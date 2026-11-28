//! First real H2/TLS 1.3 server ingress. This is not an H3 endpoint.
//! A listener, not the untrusted HTTP Host/authority, determines authorization.
use crate::{
    config::{self, Config, Inbound, ServerDocument, ServerPolicy, User},
    diagnostics::{self, Value},
    live_auth::{AuthCell, LiveAuthorization},
    protocol::{self, Address, Decoder, Direction, ErrorCode, Frame, Role, Session},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
#[cfg(test)]
use tokio::io::AsyncReadExt;
use tokio::{
    io::AsyncWriteExt,
    net::{lookup_host, TcpListener, TcpStream},
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PEM_BYTES: u64 = 1024 * 1024;
const AUTH_WINDOW: Duration = Duration::from_secs(60);
const AUTH_ATTEMPTS: u32 = 120;
const MAX_TRACKED_PEERS: usize = 4096;
const MAX_DNS_RESULTS: usize = 64;
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Fixed-window admission limiter, shared across listeners. The table never
/// grows beyond MAX_TRACKED_PEERS; a full table rejects unknown active peers.
#[derive(Default)]
struct PeerBudget {
    peers: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl PeerBudget {
    fn admit(&self, ip: IpAddr, now: Instant) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        let Ok(mut peers) = self.peers.lock() else {
            return false;
        };
        if !peers.contains_key(&ip) && peers.len() >= MAX_TRACKED_PEERS {
            peers.retain(|_, (start, _)| now.saturating_duration_since(*start) < AUTH_WINDOW);
            if peers.len() >= MAX_TRACKED_PEERS {
                return false;
            }
        }
        let entry = peers.entry(ip).or_insert((now, 0));
        if now.saturating_duration_since(entry.0) >= AUTH_WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= AUTH_ATTEMPTS {
            return false;
        }
        entry.1 += 1;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerError {
    Config,
    Io,
    TcpControllerUnavailable,
    Tls,
    Http2,
    Protocol,
    TimedOut,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::Config => "server configuration or TLS identity invalid",
            Self::Io => "server network or file operation failed",
            Self::TcpControllerUnavailable => "TCP BBR/CUBIC controller unavailable",
            Self::Tls => "TLS handshake or certificate failed",
            Self::Http2 => "HTTP/2 session closed or flow control failed",
            Self::Protocol => "SmartTheia protocol violation",
            Self::TimedOut => "server operation timed out",
        };
        f.write_str(description)
    }
}
impl std::error::Error for ServerError {}

pub(crate) const fn error_kind(error: ServerError) -> &'static str {
    match error {
        ServerError::Config => "configuration",
        ServerError::Io => "io",
        ServerError::TcpControllerUnavailable => "tcp_controller_unavailable",
        ServerError::Tls => "tls",
        ServerError::Http2 => "h2",
        ServerError::Protocol => "protocol",
        ServerError::TimedOut => "timeout",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    Unauthorized,
    Forbidden,
    Busy,
}

impl AuthFailure {
    pub fn status(self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Busy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// One listener's immutable policy. Sharing the same semaphores across all
/// contexts protects aggregate connection and user quotas across inbounds.
pub struct ServerContext {
    pub inbound_id: String,
    security_mode: crate::security_profile::SecurityMode,
    identity_routes: Option<RwLock<IdentityRoutePolicy>>,
    own_routes: Option<crate::split_http::IdentityRoutes>,
    padding: crate::descriptor::Padding,
    identity_gate: Option<Arc<RwLock<bool>>>,
    authorization: Arc<AuthCell>,
    policy: ServerPolicy,
    global_streams: Arc<Semaphore>,
    user_streams: Arc<HashMap<String, Arc<Semaphore>>>,
    connection_slots: Arc<Semaphore>,
    // Supervised file runtime: same occupancy ledger for every generation.
    // Library-only unsupervised contexts continue using fixed semaphores.
    live_quota: Option<Arc<crate::quota::Ledger>>,
    peer_budget: Arc<PeerBudget>,
}

struct IdentityRoutePolicy {
    paths: crate::split_http::IdentityRoutes,
    stream_one: bool,
    stream_up: bool,
    not_before: u64,
    not_after: u64,
    signed: Arc<str>,
    successor: Option<Arc<str>>,
    signer: [u8; 32],
    descriptor: crate::descriptor::Descriptor,
    digest: [u8; 32],
}

impl IdentityRoutePolicy {
    fn current(&self) -> bool {
        crate::reference_health::unix_now()
            .is_ok_and(|now| now >= self.not_before && now < self.not_after)
    }
}

pub struct SessionPermit {
    routing: Arc<crate::routing::exchange::Published>,
    _global: Option<OwnedSemaphorePermit>,
    _user: Option<OwnedSemaphorePermit>,
    _live: Option<crate::quota::Lease>,
}

pub(crate) struct ConnectionSlot {
    _legacy: Option<OwnedSemaphorePermit>,
    _live: Option<crate::quota::Lease>,
}

impl ServerContext {
    pub fn new(inbound: &Inbound, users: &[User], policy: &ServerPolicy) -> Self {
        let all_users = users
            .iter()
            .map(|user| {
                (
                    user.id.clone(),
                    Arc::new(Semaphore::new(policy.max_connections_per_user as usize)),
                )
            })
            .collect();
        Self::with_limits(
            inbound,
            policy,
            AuthCell::isolated(inbound, users, policy, None),
            Arc::new(Semaphore::new(policy.max_connections_total as usize)),
            Arc::new(all_users),
            Arc::new(Semaphore::new(policy.max_connections_total as usize)),
            Arc::new(PeerBudget::default()),
        )
    }

    fn with_limits(
        inbound: &Inbound,
        policy: &ServerPolicy,
        authorization: Arc<AuthCell>,
        global_streams: Arc<Semaphore>,
        user_streams: Arc<HashMap<String, Arc<Semaphore>>>,
        connection_slots: Arc<Semaphore>,
        peer_budget: Arc<PeerBudget>,
    ) -> Self {
        Self {
            inbound_id: inbound.id.clone(),
            security_mode: inbound.security_mode,
            identity_routes: None,
            padding: crate::descriptor::Padding::default(),
            own_routes: inbound
                .path_prefix
                .as_deref()
                .and_then(|prefix| crate::split_http::IdentityRoutes::new(prefix).ok()),
            identity_gate: None,
            authorization,
            policy: policy.clone(),
            global_streams,
            user_streams,
            connection_slots,
            live_quota: None,
            peer_budget,
        }
    }

    fn apply_own_tls_policy(&mut self) {
        if self.security_mode.is_plain() && self.identity_routes.is_none() {
            self.padding = crate::padding::OWN_TLS_PADDING;
        }
    }

    /// Build the identity-authenticated application context from an already
    /// independently verified document. No public listener is activated here.
    pub(crate) fn identity_fixture(
        inbound: &Inbound,
        users: &[User],
        policy: &ServerPolicy,
        value: &crate::descriptor::Verified,
        signed: Arc<str>,
    ) -> Result<Self, ServerError> {
        if !inbound.security_mode.is_plain() {
            return Err(ServerError::Config);
        }
        Self::identity_context(inbound, users, policy, value, signed)
    }

    pub(crate) fn identity_context(
        inbound: &Inbound,
        users: &[User],
        policy: &ServerPolicy,
        value: &crate::descriptor::Verified,
        signed: Arc<str>,
    ) -> Result<Self, ServerError> {
        Self::new(inbound, users, policy).with_identity(inbound, value, signed)
    }

    fn with_identity(
        mut self,
        inbound: &Inbound,
        value: &crate::descriptor::Verified,
        signed: Arc<str>,
    ) -> Result<Self, ServerError> {
        let d = value.descriptor();
        if !(inbound.security_mode.is_plain()
            || inbound.security_mode == crate::security_profile::SecurityMode::SmartReality)
            || inbound.id != d.scope.inbound
            || inbound.allowed_user_ids.is_empty()
            || value
                .check_time(crate::reference_health::unix_now().map_err(|_| ServerError::Config)?)
                .is_err()
        {
            return Err(ServerError::Config);
        }
        let paths = crate::split_http::IdentityRoutes::new(&d.path_prefix)
            .map_err(|_| ServerError::Config)?;
        let users = self
            .authorization
            .load()
            .map_err(|_| ServerError::Config)?
            .users
            .clone();
        self.authorization = AuthCell::isolated(inbound, &users, &self.policy, Some(&inbound.id));
        self.routing_publication()?;
        self.padding = d.padding.clone();
        self.identity_routes = Some(RwLock::new(IdentityRoutePolicy {
            paths,
            stream_one: d.stream_one,
            stream_up: d.stream_up,
            not_before: d.not_before,
            not_after: d.not_after,
            signed,
            successor: None,
            signer: value.signer(),
            descriptor: d.clone(),
            digest: value.payload_sha256(),
        }));
        Ok(self)
    }

    pub(crate) fn fork_identity(
        &self,
        value: &crate::descriptor::Verified,
        signed: Arc<str>,
        successor: Option<Arc<str>>,
        gate: Arc<RwLock<bool>>,
    ) -> Result<Self, ServerError> {
        let d = value.descriptor();
        if d.scope.inbound != self.inbound_id
            || value
                .check_time(crate::reference_health::unix_now().map_err(|_| ServerError::Config)?)
                .is_err()
        {
            return Err(ServerError::Config);
        }
        let paths = crate::split_http::IdentityRoutes::new(&d.path_prefix)
            .map_err(|_| ServerError::Config)?;
        Ok(Self {
            inbound_id: self.inbound_id.clone(),
            security_mode: self.security_mode,
            own_routes: None,
            padding: d.padding.clone(),
            identity_routes: Some(RwLock::new(IdentityRoutePolicy {
                paths,
                stream_one: d.stream_one,
                stream_up: d.stream_up,
                not_before: d.not_before,
                not_after: d.not_after,
                signed,
                successor,
                signer: value.signer(),
                descriptor: d.clone(),
                digest: value.payload_sha256(),
            })),
            identity_gate: Some(gate),
            authorization: self.authorization.clone(),
            policy: self.policy.clone(),
            global_streams: self.global_streams.clone(),
            user_streams: self.user_streams.clone(),
            connection_slots: self.connection_slots.clone(),
            live_quota: self.live_quota.clone(),
            peer_budget: self.peer_budget.clone(),
        })
    }

    /// Controlled loopback fixture only. Update a compatible signed
    /// descriptor on the existing shared authorization/connection budget.
    /// No transport, routes, reference, grants or key change is permitted.
    pub(crate) fn renew_identity_fixture(
        &self,
        signed: &str,
        expected: [u8; 32],
    ) -> Result<u64, ServerError> {
        let mut routes = self
            .identity_routes
            .as_ref()
            .ok_or(ServerError::Config)?
            .write()
            .map_err(|_| ServerError::Config)?;
        if routes.digest != expected || !routes.current() {
            return Err(ServerError::Config);
        }
        let previous = &routes.descriptor;
        let anchor = crate::descriptor::Anchor::new(
            previous.scope.clone(),
            routes.signer,
            previous.revision,
            crate::descriptor::ClientPolicy {
                transport: crate::config::Transport::Auto,
                xhttp_mode: crate::config::XhttpMode::Auto,
            },
        )
        .map_err(|_| ServerError::Config)?;
        let value = crate::descriptor::verify(signed, &anchor).map_err(|_| ServerError::Config)?;
        let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
        value.check_time(now).map_err(|_| ServerError::Config)?;
        let next = value.descriptor();
        if next.revision <= previous.revision
            || next.not_before < previous.not_before
            || next.not_after <= previous.not_after
        {
            return Err(ServerError::Config);
        }
        let mut compatible = previous.clone();
        compatible.revision = next.revision;
        compatible.not_before = next.not_before;
        compatible.not_after = next.not_after;
        if &compatible != next {
            return Err(ServerError::Config);
        }
        routes.not_before = next.not_before;
        routes.not_after = next.not_after;
        routes.descriptor = next.clone();
        routes.digest = value.payload_sha256();
        routes.signed = Arc::from(signed);
        Ok(next.revision)
    }

    pub(crate) fn pad_response<T>(
        &self,
        mut response: Response<T>,
    ) -> Result<Response<T>, ServerError> {
        self.padding
            .add_header(response.headers_mut())
            .map_err(|_| ServerError::Config)?;
        Ok(response)
    }

    pub(crate) fn padding_frame(&self, accepted: u32) -> Result<Option<Frame>, ServerError> {
        self.padding
            .frame(accepted)
            .map_err(|_| ServerError::Config)
    }

    pub(crate) fn split_leg<T>(&self, request: &Request<T>) -> Option<crate::split_http::Leg> {
        match &self.identity_routes {
            Some(routes) => {
                let routes = routes.read().ok()?;
                if routes.current() && routes.stream_up {
                    routes.paths.leg(request)
                } else {
                    None
                }
            }
            None => self.own_routes.as_ref()?.leg(request),
        }
    }

    /// Routing data is private to authenticated grants, including own-TLS.
    pub(crate) fn is_routing_request<T>(&self, request: &Request<T>) -> bool {
        if request.method() != Method::GET {
            return false;
        }
        match &self.identity_routes {
            Some(routes) => routes
                .read()
                .is_ok_and(|r| r.current() && request.uri().path() == r.paths.routing),
            None => self
                .own_routes
                .as_ref()
                .is_some_and(|r| request.uri().path() == r.routing),
        }
    }

    pub(crate) fn authorize_routing<T>(
        &self,
        request: &Request<T>,
        peer: IpAddr,
    ) -> Result<(SessionPermit, Arc<crate::routing::exchange::Published>), StatusCode> {
        if !self.is_routing_request(request)
            || request.uri().query().is_some()
            || request
                .headers()
                .contains_key(crate::split_http::PAIR_HEADER)
        {
            return Err(StatusCode::NOT_FOUND);
        }
        if !self.peer_budget.admit(peer, Instant::now()) {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        if request
            .headers()
            .get_all(header::AUTHORIZATION)
            .iter()
            .count()
            != 1
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let permit = self
            .authorize(
                request
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok()),
            )
            .map_err(AuthFailure::status)?;
        let publication = permit.routing.clone();
        Ok((permit, publication))
    }

    fn routing_publication(&self) -> Result<Arc<crate::routing::exchange::Published>, ServerError> {
        self.authorization
            .load()
            .map_err(|_| ServerError::Config)?
            .routing
            .get(&self.inbound_id)
            .cloned()
            .ok_or(ServerError::Config)
    }

    pub(crate) async fn routing_response(
        &self,
        publication: &crate::routing::exchange::Published,
        headers: &http::HeaderMap,
    ) -> Result<Arc<[u8]>, StatusCode> {
        crate::routing::exchange::response_data(
            publication,
            headers,
            self.policy.allow_private_ips,
            Duration::from_millis(u64::from(self.policy.connect_timeout_ms)),
        )
        .await
    }

    pub(crate) fn is_descriptor_request<T>(&self, request: &Request<T>) -> bool {
        self.identity_routes.as_ref().is_some_and(|routes| {
            routes.read().is_ok_and(|routes| {
                request.method() == Method::GET
                    && (request.uri().path() == routes.paths.descriptor
                        || request.uri().path() == routes.paths.successor)
            })
        })
    }

    /// Same grant and quota policy as a tunnel, but never dials a target.
    /// The caller must verify empty request body and complete TLS first.
    pub(crate) fn authorize_descriptor<T>(
        &self,
        request: &Request<T>,
        peer: IpAddr,
    ) -> Result<(SessionPermit, Arc<str>), StatusCode> {
        let routes = self
            .identity_routes
            .as_ref()
            .ok_or(StatusCode::NOT_FOUND)?
            .read()
            .map_err(|_| StatusCode::NOT_FOUND)?;
        if !routes.current()
            || request.method() != Method::GET
            || (request.uri().path() != routes.paths.descriptor
                && request.uri().path() != routes.paths.successor)
            || request.uri().query().is_some()
            || request
                .headers()
                .contains_key(crate::split_http::PAIR_HEADER)
        {
            return Err(StatusCode::NOT_FOUND);
        }
        if !self.peer_budget.admit(peer, Instant::now()) {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        if request
            .headers()
            .get_all(header::AUTHORIZATION)
            .iter()
            .count()
            != 1
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let permit = self
            .authorize(
                request
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
            )
            .map_err(AuthFailure::status)?;
        let signed = if request.uri().path() == routes.paths.successor {
            routes.successor.clone().ok_or(StatusCode::NOT_FOUND)?
        } else {
            routes.signed.clone()
        };
        Ok((permit, signed))
    }

    pub(crate) fn connection_slot(&self) -> Option<ConnectionSlot> {
        if let Some(ledger) = &self.live_quota {
            return Some(ConnectionSlot {
                _legacy: None,
                _live: Some(ledger.acquire_connection()?),
            });
        }
        Some(ConnectionSlot {
            _legacy: Some(self.connection_slots.clone().try_acquire_owned().ok()?),
            _live: None,
        })
    }

    pub(crate) async fn dial_target(
        &self,
        address: &Address,
        port: u16,
    ) -> Result<TcpStream, ErrorCode> {
        let routing = self
            .routing_publication()
            .map_err(|_| ErrorCode::PolicyDenied)?;
        connect_target(address, port, &self.policy, routing.snapshot.policy()).await
    }

    pub(crate) async fn dial_udp_target(
        &self,
        address: &Address,
        port: u16,
    ) -> Result<tokio::net::UdpSocket, ErrorCode> {
        let routing = self
            .routing_publication()
            .map_err(|_| ErrorCode::PolicyDenied)?;
        connect_target_with(
            address,
            port,
            &self.policy,
            routing.snapshot.policy(),
            crate::udp_relay::connect,
        )
        .await
    }

    /// Identical admission, route, content type, credential and user quota
    /// policy for H2 and H3. The listener context, never Host, chooses grants.
    pub(crate) fn authorize_request<T>(
        &self,
        request: &Request<T>,
        peer: IpAddr,
    ) -> Result<SessionPermit, StatusCode> {
        if !self.peer_budget.admit(peer, Instant::now()) {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let single_allowed = match &self.identity_routes {
            Some(routes) => routes.read().is_ok_and(|routes| {
                routes.current() && routes.stream_one && request.uri().path() == routes.paths.single
            }),
            None => {
                !self.security_mode.is_stream_up()
                    && self
                        .own_routes
                        .as_ref()
                        .is_some_and(|routes| request.uri().path() == routes.single)
            }
        };
        if !single_allowed
            || request.method() != Method::POST
            || request.uri().query().is_some()
            || request
                .headers()
                .contains_key(crate::split_http::PAIR_HEADER)
            || request
                .headers()
                .get_all(header::CONTENT_TYPE)
                .iter()
                .count()
                != 1
            || request
                .headers()
                .get(header::CONTENT_TYPE)
                .map(|value| value.as_bytes())
                != Some(b"application/octet-stream".as_slice())
        {
            return Err(StatusCode::NOT_FOUND);
        }
        if request
            .headers()
            .get_all(header::AUTHORIZATION)
            .iter()
            .count()
            != 1
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let auth = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        self.authorize(auth).map_err(AuthFailure::status)
    }

    pub(crate) fn allows_native_lab(&self) -> bool {
        self.security_mode.is_plain() && self.identity_routes.is_none()
    }

    pub(crate) fn requires_channel_binding(&self) -> bool {
        !self.security_mode.is_plain() && self.identity_routes.is_none()
    }

    pub(crate) fn stream_up(&self) -> bool {
        self.security_mode.is_stream_up()
    }

    pub(crate) fn accepts_split<T>(&self, request: &Request<T>) -> bool {
        if self.identity_routes.is_some() {
            self.split_leg(request).is_some()
        } else {
            self.stream_up() || (self.security_mode.is_plain() && self.split_leg(request).is_some())
        }
    }

    pub(crate) fn authorize_split_pair<U, D>(
        &self,
        upload: &Request<U>,
        download: &Request<D>,
        peer: IpAddr,
    ) -> Result<SessionPermit, StatusCode> {
        use crate::split_http::{self, Leg};
        if !self.peer_budget.admit(peer, Instant::now()) {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        if !(self.stream_up() || self.security_mode.is_plain() || self.identity_routes.is_some())
            || self.split_leg(upload) != Some(Leg::Upload)
            || self.split_leg(download) != Some(Leg::Download)
            || split_http::pair_id(upload).is_none()
            || split_http::pair_id(upload) != split_http::pair_id(download)
        {
            return Err(StatusCode::NOT_FOUND);
        }
        let up = upload.headers();
        let down = download.headers();
        if up.get_all(header::AUTHORIZATION).iter().count() != 1
            || down.get_all(header::AUTHORIZATION).iter().count() != 1
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let up = up
            .get(header::AUTHORIZATION)
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let down = down
            .get(header::AUTHORIZATION)
            .ok_or(StatusCode::UNAUTHORIZED)?;
        if !bool::from(up.as_bytes().ct_eq(down.as_bytes())) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        // Exactly one authorization snapshot and quota permit for both legs.
        self.authorize(up.to_str().ok())
            .map_err(AuthFailure::status)
    }

    /// Raw token digest is the SHA-256 of exactly 32 decoded bytes, not the
    /// base64url text or a 64-character hex digest presented as a credential.
    /// Check all configured hashes using constant-time comparison and never
    /// reflect token bytes, hashes or even the candidate string in errors.
    pub fn authorize(&self, authorization: Option<&str>) -> Result<SessionPermit, AuthFailure> {
        // Held through permit acquisition: a structural root replacement
        // linearizes against new logical streams on the old TLS context.
        let _identity = if let Some(gate) = &self.identity_gate {
            let held = gate.read().map_err(|_| AuthFailure::Forbidden)?;
            if !*held {
                return Err(AuthFailure::Forbidden);
            }
            Some(held)
        } else {
            None
        };
        let header = authorization.ok_or(AuthFailure::Unauthorized)?;
        let bearer = header
            .strip_prefix("Bearer ")
            .ok_or(AuthFailure::Unauthorized)?;
        if bearer.len() != 43 || bearer.contains('=') {
            return Err(AuthFailure::Unauthorized);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(bearer)
            .map_err(|_| AuthFailure::Unauthorized)?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != bearer {
            return Err(AuthFailure::Unauthorized);
        }
        let candidate = Sha256::digest(&decoded);
        // One immutable view of *all* users and grants per request. This
        // Arc is independent of the short-lived shared RwLock, so a future
        // publication cannot cut off an already admitted session.
        let snapshot = self
            .authorization
            .load()
            .map_err(|_| AuthFailure::Unauthorized)?;
        let mut matching_user: Option<&User> = None;
        for user in &snapshot.users {
            // The structural TOML validator has already confirmed lower-hex
            // digest shape; skip damaged runtime fixtures rather than trusting.
            if let Some(stored) = decode_digest(&user.token_sha256) {
                let equal = stored.ct_eq(candidate.as_slice()).unwrap_u8() == 1;
                if equal {
                    matching_user = Some(user);
                }
            }
        }
        let user = matching_user.ok_or(AuthFailure::Unauthorized)?;
        if user.disabled
            || !snapshot
                .grants
                .get(&self.inbound_id)
                .is_some_and(|grants| grants.contains(&user.id))
        {
            return Err(AuthFailure::Forbidden);
        }
        let routing = snapshot
            .routing
            .get(&self.inbound_id)
            .cloned()
            .ok_or(AuthFailure::Forbidden)?;
        // Admission and quota resize serialize through a single short
        // occupancy lock across old/new H2 and QUIC listener generations.
        if let Some(ledger) = &self.live_quota {
            let permit = ledger
                .acquire_session_checked(&user.id, || {
                    self.authorization
                        .load()
                        .is_ok_and(|current| Arc::ptr_eq(&current, &snapshot))
                })
                .ok_or(AuthFailure::Busy)?;
            return Ok(SessionPermit {
                routing,
                _global: None,
                _user: None,
                _live: Some(permit),
            });
        }
        let global = self
            .global_streams
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthFailure::Busy)?;
        let user_limit = self
            .user_streams
            .get(&user.id)
            .ok_or(AuthFailure::Forbidden)?;
        let per_user = user_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthFailure::Busy)?;
        Ok(SessionPermit {
            routing,
            _global: Some(global),
            _user: Some(per_user),
            _live: None,
        })
    }
}

fn decode_digest(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0; 32];
    for (index, pair) in raw.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        fn nibble(b: u8) -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            }
        }
        out[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

pub use crate::net::address::allowed_destination;

/// All DNS and dial attempts consume one deadline. The result list is bounded;
/// no second resolution can change the addresses checked by the policy.
async fn connect_target(
    address: &Address,
    port: u16,
    policy: &ServerPolicy,
    routing: &crate::routing::Policy,
) -> Result<TcpStream, ErrorCode> {
    connect_target_with(
        address,
        port,
        policy,
        routing,
        crate::routing::carrier_socket::connect_plain_tcp,
    )
    .await
}

async fn connect_target_with<T, F, Fut>(
    address: &Address,
    port: u16,
    policy: &ServerPolicy,
    routing: &crate::routing::Policy,
    dial: F,
) -> Result<T, ErrorCode>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let domain = match address {
        Address::Dns(name) => Some(name.as_str()),
        _ => None,
    };
    if let Some(name) = domain {
        if matches!(
            routing
                .domain_decision(name)
                .map_err(|_| ErrorCode::PolicyDenied)?,
            Some(crate::routing::Action::Direct | crate::routing::Action::Blocked)
        ) {
            return Err(ErrorCode::PolicyDenied);
        }
    }
    let duration = Duration::from_millis(u64::from(policy.connect_timeout_ms));
    let deadline = tokio::time::Instant::now() + duration;
    timeout(duration, async {
        let candidates: Vec<SocketAddr> = match address {
            Address::V4(ip) => vec![SocketAddr::from((*ip, port))],
            Address::V6(ip) => vec![SocketAddr::from((*ip, port))],
            Address::Dns(name) => lookup_host((name.as_str(), port))
                .await
                .map_err(|_| ErrorCode::DialFailed)?
                .take(MAX_DNS_RESULTS + 1)
                .collect(),
        };
        let permitted = permitted_candidates(candidates, policy.allow_private_ips)?;
        let mut routed = Vec::new();
        for candidate in permitted {
            if routing
                .matching_action(domain, Some(candidate.ip()))
                .map_err(|_| ErrorCode::PolicyDenied)?
                .unwrap_or(crate::routing::Action::Allowed)
                .permits_server_egress()
            {
                routed.push(candidate);
            }
        }
        if routed.is_empty() {
            return Err(ErrorCode::PolicyDenied);
        }
        // Pin each ACL-checked SocketAddr. Share the remaining deadline
        // between candidates so an unresponsive IPv6 route cannot starve IPv4.
        dial_candidates(&routed, deadline, dial).await
    })
    .await
    .map_err(|_| ErrorCode::DialTimeout)?
}

async fn dial_candidates<T, F, Fut>(
    candidates: &[SocketAddr],
    deadline: tokio::time::Instant,
    mut dial: F,
) -> Result<T, ErrorCode>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let mut timed_out = false;
    for (index, candidate) in candidates.iter().copied().enumerate() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(ErrorCode::DialTimeout);
        }
        // At most 64 candidates. Attempts are sequential; never establish
        // multiple competing connections to the remote target.
        let budget = remaining / (candidates.len() - index) as u32;
        match timeout(budget, dial(candidate)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(_)) => {}
            Err(_) => timed_out = true,
        }
    }
    Err(if timed_out {
        ErrorCode::DialTimeout
    } else {
        ErrorCode::DialFailed
    })
}

fn permitted_candidates(
    candidates: Vec<SocketAddr>,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, ErrorCode> {
    if candidates.len() > MAX_DNS_RESULTS {
        return Err(ErrorCode::ResourceLimit);
    }
    let mut seen = HashSet::new();
    let permitted: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| allowed_destination(candidate.ip(), allow_private))
        .filter(|candidate| seen.insert(*candidate))
        .collect();
    if permitted.is_empty() {
        return Err(ErrorCode::PolicyDenied);
    }
    Ok(permitted)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenerationPhase {
    Prepared,
    Active,
    Drain,
}

pub(crate) const GENERATION_DRAIN: Duration = Duration::from_secs(20);

pub(crate) async fn await_generation_activation(
    phase: &mut watch::Receiver<GenerationPhase>,
) -> bool {
    loop {
        let current = *phase.borrow_and_update();
        match current {
            GenerationPhase::Active => return true,
            GenerationPhase::Drain => return false,
            GenerationPhase::Prepared => {}
        }
        if phase.changed().await.is_err() {
            return false;
        }
    }
}

/// A closed controller is also a drain request. A receiver cloned after
/// publication must observe Drain even if no further notification arrives.
pub(crate) fn generation_draining(phase: &watch::Receiver<GenerationPhase>) -> bool {
    *phase.borrow() == GenerationPhase::Drain || phase.has_changed().is_err()
}

pub(crate) async fn await_generation_drain(phase: &mut watch::Receiver<GenerationPhase>) {
    while !generation_draining(phase) {
        if phase.changed().await.is_err() {
            break;
        }
    }
}

pub async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    context: Arc<ServerContext>,
) -> Result<(), ServerError> {
    let (_owner, phase) = watch::channel(GenerationPhase::Active);
    serve_generation(listener, acceptor, context, phase).await
}

pub(crate) async fn serve_generation(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    context: Arc<ServerContext>,
    phase: watch::Receiver<GenerationPhase>,
) -> Result<(), ServerError> {
    serve_generation_with_tls(listener, Arc::new(RwLock::new(acceptor)), context, phase).await
}

/// A short, per-new-TCP-socket acceptor load; active TLS sessions retain the
/// ServerConfig selected for their own handshake. The running supervisor
/// replaces only the acceptor pointer after validating the full H2+H3 set.
pub(crate) async fn serve_generation_with_tls(
    listener: TcpListener,
    acceptor: Arc<RwLock<TlsAcceptor>>,
    context: Arc<ServerContext>,
    mut phase: watch::Receiver<GenerationPhase>,
) -> Result<(), ServerError> {
    // Public library serve() callers may supply a prebound listener.
    // Apply the fixed BBR-first policy before activating it.
    crate::tcp_bbr::select(&listener).map_err(|_| ServerError::TcpControllerUnavailable)?;
    if !await_generation_activation(&mut phase).await {
        crate::diag!(Info, "server.h2", "generation_aborted_before_activation");
        return Ok(());
    }
    crate::diag!(Info, "server.h2", "listener_active");
    // JoinSet ownership makes cancellation of serve cancel all of its
    // connections, which in turn cancel all of their stream handlers.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            change = phase.changed() => {
                if change.is_err() || *phase.borrow() == GenerationPhase::Drain {
                    break;
                }
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (socket, peer) = accepted.map_err(|_| ServerError::Io)?;
                let connection_id = diagnostics::next_id();
                let Ok(controller) = crate::tcp_bbr::select(&socket) else {
                    crate::diag!(Warn, "server.h2", "tcp_controller_unavailable",
                        "connection" = Value::Count(connection_id));
                    continue;
                };
                crate::diag!(Trace, "server.h2", "tcp_controller_selected",
                    "controller" = Value::Label(controller.label()),
                    "connection" = Value::Count(connection_id));
                crate::diag!(Trace, "server.h2", "tcp_accepted",
                    "connection" = Value::Count(connection_id));
                let Some(slot) = context.connection_slot() else {
                    crate::diag!(Warn, "server.h2", "connection_quota_rejected",
                        "connection" = Value::Count(connection_id));
                    continue;
                };
                let tls_acceptor = {
                    let current = acceptor.read().map_err(|_| ServerError::Io)?;
                    current.clone()
                };
                let context = context.clone();
                connections.spawn(serve_h2_socket(socket, tls_acceptor, context, peer, slot, connection_id, phase.clone()));
            }
        }
    }
    // Stop new TCP accepts first, then give already-authenticated tunnels a
    // bounded chance to finish. Exceeding the grace aborts remaining tasks;
    // it is never advertised as hard revoke or lossless migration.
    crate::diag!(Info, "server.h2", "generation_draining");
    drop(listener);
    let _ = timeout(GENERATION_DRAIN, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}

/// Shared H2 application transport. The upstream admission adapter must
/// supply the exact original byte stream and selected identity TLS config.
pub(crate) async fn serve_h2_socket<S>(
    socket: S,
    tls_acceptor: TlsAcceptor,
    context: Arc<ServerContext>,
    peer: std::net::SocketAddr,
    slot: ConnectionSlot,
    connection_id: u64,
    mut phase: watch::Receiver<GenerationPhase>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let _slot = slot;
    let tls = match timeout(HANDSHAKE_TIMEOUT, tls_acceptor.accept(socket)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(_)) => {
            crate::diag!(
                Warn,
                "server.h2",
                "tls_handshake_failed",
                "connection" = Value::Count(connection_id)
            );
            return;
        }
        Err(_) => {
            crate::diag!(
                Warn,
                "server.h2",
                "tls_handshake_timeout",
                "connection" = Value::Count(connection_id)
            );
            return;
        }
    };
    if !crate::transport_policy::Carrier::H2.accepts_tls(
        tls.get_ref().1.protocol_version(),
        tls.get_ref().1.alpn_protocol(),
    ) {
        crate::diag!(
            Warn,
            "server.h2",
            "alpn_rejected",
            "connection" = Value::Count(connection_id)
        );
        return;
    }
    crate::diag!(
        Trace,
        "server.h2",
        "tls_verified",
        "connection" = Value::Count(connection_id)
    );
    let binding = if context.requires_channel_binding() {
        let Ok(key) = tls.get_ref().1.export_keying_material(
            [0u8; 32],
            crate::channel_binding::LABEL,
            Some(crate::channel_binding::H2),
        ) else {
            return;
        };
        Some(Arc::new(crate::channel_binding::Admission::new(
            zeroize::Zeroizing::new(key),
        )))
    } else {
        None
    };
    let builder = crate::transport_policy::Carrier::H2.h2_server();
    let Ok(Ok(mut connection)) = timeout(HANDSHAKE_TIMEOUT, builder.handshake(tls)).await else {
        crate::diag!(
            Warn,
            "server.h2",
            "h2_handshake_failed_or_timeout",
            "connection" = Value::Count(connection_id)
        );
        return;
    };
    crate::diag!(
        Debug,
        "server.h2",
        "connection_ready",
        "connection" = Value::Count(connection_id)
    );
    let mut handlers = JoinSet::new();
    let pair = Arc::new(crate::split_http::Pair::new());
    let mut draining = false;
    loop {
        let idle = handlers.is_empty();
        let accepted = tokio::select! {
            biased;
            _ = await_generation_drain(&mut phase), if !draining => {
                connection.graceful_shutdown();
                draining = true;
                continue;
            }
            _ = handlers.join_next(), if !idle => continue,
            accepted = connection.accept() => accepted,
            _ = tokio::time::sleep(AUTH_WINDOW), if idle => break,
        };
        let Some(Ok((request, mut respond))) = accepted else {
            break;
        };
        // During the initial GOAWAY/PING exchange h2 may still deliver
        // in-flight streams. Never authorize a new request after drain.
        if draining || generation_draining(&phase) {
            respond.send_reset(h2::Reason::REFUSED_STREAM);
            continue;
        }
        let context = context.clone();
        let pair = pair.clone();
        let binding = binding.clone();
        handlers.spawn(async move {
            let result = if context.is_routing_request(&request) {
                handle_routing(request, respond, &context, peer.ip(), binding.as_deref()).await
            } else if context.is_descriptor_request(&request) {
                handle_descriptor(request, respond, &context, peer.ip()).await
            } else if context.accepts_split(&request) {
                handle_split_request(
                    request,
                    respond,
                    &context,
                    peer.ip(),
                    &pair,
                    binding.as_deref(),
                )
                .await
            } else {
                handle_request(request, respond, context, peer.ip(), binding.as_deref()).await
            };
            if let Err(error) = result {
                crate::diag!(
                    Warn,
                    "server.h2",
                    "request_failed",
                    "reason" = Value::Label(error_kind(error))
                );
            }
        });
    }
}

async fn reject(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: StatusCode,
) -> Result<(), ServerError> {
    let response = Response::builder()
        .status(status)
        .body(())
        .map_err(|_| ServerError::Http2)?;
    respond
        .send_response(response, true)
        .map_err(|_| ServerError::Http2)?;
    Ok(())
}

async fn handle_descriptor(
    mut request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    context: &ServerContext,
    peer: IpAddr,
) -> Result<(), ServerError> {
    let (_permit, signed) = match context.authorize_descriptor(&request, peer) {
        Ok(value) => value,
        Err(status) => return reject(&mut respond, status).await,
    };
    let empty = timeout(HANDSHAKE_TIMEOUT, async {
        request.body_mut().data().await.is_none()
            && request
                .body_mut()
                .trailers()
                .await
                .is_ok_and(|value| value.is_none())
    })
    .await
    .unwrap_or(false);
    if !empty {
        return reject(&mut respond, StatusCode::BAD_REQUEST).await;
    }
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, signed.len().to_string())
        .body(())
        .map_err(|_| ServerError::Http2)?;
    let mut output = respond
        .send_response(context.pad_response(response)?, false)
        .map_err(|_| ServerError::Http2)?;
    timeout(CLOSE_TIMEOUT, async {
        output.reserve_capacity(signed.len());
        let mut remaining = signed.as_bytes();
        while !remaining.is_empty() {
            let credit = std::future::poll_fn(|cx| output.poll_capacity(cx))
                .await
                .ok_or(ServerError::Io)?
                .map_err(|_| ServerError::Io)?;
            if credit == 0 {
                continue;
            }
            let count = credit.min(remaining.len());
            output
                .send_data(
                    Bytes::copy_from_slice(&remaining[..count]),
                    count == remaining.len(),
                )
                .map_err(|_| ServerError::Io)?;
            remaining = &remaining[count..];
            if !remaining.is_empty() {
                output.reserve_capacity(remaining.len());
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| ServerError::Io)?
}

async fn handle_routing(
    mut request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    context: &ServerContext,
    peer: IpAddr,
    binding: Option<&crate::channel_binding::Admission>,
) -> Result<(), ServerError> {
    let (_permit, publication) = match context.authorize_routing(&request, peer) {
        Ok(value) => value,
        Err(status) => return reject(&mut respond, status).await,
    };
    if !crate::channel_binding::admit(binding, &[&request]) {
        return reject(&mut respond, StatusCode::UNAUTHORIZED).await;
    }
    let empty = timeout(HANDSHAKE_TIMEOUT, async {
        request.body_mut().data().await.is_none()
            && request
                .body_mut()
                .trailers()
                .await
                .is_ok_and(|value| value.is_none())
    })
    .await
    .unwrap_or(false);
    if !empty {
        return reject(&mut respond, StatusCode::BAD_REQUEST).await;
    }
    let signed = match context
        .routing_response(&publication, request.headers())
        .await
    {
        Ok(bytes) => bytes,
        Err(status) => return reject(&mut respond, status).await,
    };
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, signed.len().to_string())
        .body(())
        .map_err(|_| ServerError::Http2)?;
    let mut output = respond
        .send_response(context.pad_response(response)?, false)
        .map_err(|_| ServerError::Http2)?;
    timeout(crate::routing::exchange::TRANSFER_TIMEOUT, async {
        output.reserve_capacity(signed.len().min(64 * 1024));
        let mut remaining: &[u8] = &signed;
        while !remaining.is_empty() {
            let credit = std::future::poll_fn(|cx| output.poll_capacity(cx))
                .await
                .ok_or(ServerError::Io)?
                .map_err(|_| ServerError::Io)?;
            if credit == 0 {
                continue;
            }
            let count = credit.min(remaining.len()).min(64 * 1024);
            output
                .send_data(
                    Bytes::copy_from_slice(&remaining[..count]),
                    count == remaining.len(),
                )
                .map_err(|_| ServerError::Io)?;
            remaining = &remaining[count..];
            if !remaining.is_empty() {
                output.reserve_capacity(remaining.len().min(64 * 1024));
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| ServerError::Io)?
}

async fn handle_request(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    context: Arc<ServerContext>,
    peer: IpAddr,
    binding: Option<&crate::channel_binding::Admission>,
) -> Result<(), ServerError> {
    let session_id = diagnostics::next_id();
    crate::diag!(
        Trace,
        "server.h2",
        "request_received",
        "session" = Value::Count(session_id)
    );
    let permit = match context.authorize_request(&request, peer) {
        Ok(permit) => permit,
        Err(status) => {
            crate::diag!(
                Warn,
                "server.h2",
                "authorization_rejected",
                "session" = Value::Count(session_id),
                "http_status" = Value::Count(u64::from(status.as_u16()))
            );
            return reject(&mut respond, status).await;
        }
    };
    if !crate::channel_binding::admit(binding, &[&request]) {
        return reject(&mut respond, StatusCode::UNAUTHORIZED).await;
    }
    crate::diag!(
        Debug,
        "server.h2",
        "authorized",
        "session" = Value::Count(session_id)
    );
    let inbound = request.into_body();
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|_| ServerError::Http2)?;
    // HTTP 200 acknowledges transport/auth headers, NOT remote TCP OPEN.
    let outgoing = respond
        .send_response(context.pad_response(response)?, false)
        .map_err(|_| ServerError::Http2)?;
    let result = relay_request(inbound, outgoing, &context, session_id).await;
    drop(permit);
    result
}

type SplitPair =
    crate::split_http::Pair<(Request<h2::RecvStream>, h2::server::SendResponse<Bytes>)>;

async fn handle_split_request(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    context: &ServerContext,
    peer: IpAddr,
    pair: &SplitPair,
    binding: Option<&crate::channel_binding::Admission>,
) -> Result<(), ServerError> {
    let Some(leg) = context.split_leg(&request) else {
        return reject(&mut respond, StatusCode::NOT_FOUND).await;
    };
    let Some(id) = crate::split_http::pair_id(&request) else {
        return reject(&mut respond, StatusCode::BAD_REQUEST).await;
    };
    let Some(((upload, mut up), (mut download, mut down))) =
        pair.join(id, leg, (request, respond)).await
    else {
        return Ok(());
    };
    let permit = match context.authorize_split_pair(&upload, &download, peer) {
        Ok(permit) => permit,
        Err(status) => {
            let _ = reject(&mut up, status).await;
            return reject(&mut down, status).await;
        }
    };
    if !crate::channel_binding::admit(binding, &[&upload, &download]) {
        let _ = reject(&mut up, StatusCode::UNAUTHORIZED).await;
        return reject(&mut down, StatusCode::UNAUTHORIZED).await;
    }
    // GET has no request body or trailers; never dial until its EOF is proven.
    let empty = timeout(HANDSHAKE_TIMEOUT, async {
        download.body_mut().data().await.is_none()
            && download
                .body_mut()
                .trailers()
                .await
                .is_ok_and(|value| value.is_none())
    })
    .await
    .unwrap_or(false);
    if !empty {
        let _ = reject(&mut up, StatusCode::BAD_REQUEST).await;
        return reject(&mut down, StatusCode::BAD_REQUEST).await;
    }
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|_| ServerError::Http2)?;
    // POST response contains only an empty acknowledgement. All downstream
    // SmartTheia frames travel on the independent GET response.
    let upload_ack = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|_| ServerError::Http2)?;
    up.send_response(context.pad_response(upload_ack)?, true)
        .map_err(|_| ServerError::Http2)?;
    let outgoing = down
        .send_response(context.pad_response(response)?, false)
        .map_err(|_| ServerError::Http2)?;
    let result = relay_request(
        upload.into_body(),
        outgoing,
        context,
        diagnostics::next_id(),
    )
    .await;
    drop(permit);
    result
}

async fn relay_request(
    mut inbound: h2::RecvStream,
    mut outgoing: h2::SendStream<Bytes>,
    context: &ServerContext,
    session_id: u64,
) -> Result<(), ServerError> {
    // Handshake, dial, writes and inactivity have their own deadlines.
    // Do not expire an otherwise progressing TCP tunnel by session age.
    let result = handle_frames(&mut inbound, &mut outgoing, context, session_id).await;
    match &result {
        Ok(()) => crate::diag!(
            Info,
            "server.h2",
            "request_completed",
            "session" = Value::Count(session_id)
        ),
        Err(error) => crate::diag!(
            Warn,
            "server.h2",
            "request_relay_failed",
            "session" = Value::Count(session_id),
            "reason" = Value::Label(error_kind(*error))
        ),
    }
    // A timeout or transport failure can interrupt an already partially
    // written frame. Reset rather than appending an ABORT to corrupt bytes.
    if matches!(result, Err(ServerError::TimedOut | ServerError::Http2)) {
        outgoing.send_reset(h2::Reason::CANCEL);
        return Ok(());
    }
    if result.is_err() {
        let sent = timeout(
            CLOSE_TIMEOUT,
            send_frame(&mut outgoing, &Frame::Abort(ErrorCode::ProtocolError)),
        )
        .await;
        if !matches!(sent, Ok(Ok(()))) {
            outgoing.send_reset(h2::Reason::CANCEL);
            return Ok(());
        }
    }
    let _ = outgoing.send_data(Bytes::new(), true);
    Ok(())
}

async fn send_frame(
    outgoing: &mut h2::SendStream<Bytes>,
    frame: &Frame,
) -> Result<(), ServerError> {
    let mut bytes = Bytes::from(protocol::encode(frame).map_err(|_| ServerError::Protocol)?);
    while !bytes.is_empty() {
        outgoing.reserve_capacity(bytes.len());
        let capacity = if outgoing.capacity() == 0 {
            std::future::poll_fn(|cx| outgoing.poll_capacity(cx))
                .await
                .ok_or(ServerError::Http2)?
                .map_err(|_| ServerError::Http2)?
        } else {
            outgoing.capacity()
        };
        if capacity == 0 {
            continue;
        }
        outgoing
            .send_data(bytes.split_to(capacity.min(bytes.len())), false)
            .map_err(|_| ServerError::Http2)?;
    }
    Ok(())
}

#[derive(Default)]
struct IncomingFrames {
    decoder: Decoder,
    ready: VecDeque<Frame>,
}

impl IncomingFrames {
    async fn next(&mut self, incoming: &mut h2::RecvStream) -> Result<Option<Frame>, ServerError> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            let block = incoming.data().await;
            let Some(block) = block else {
                self.decoder.finish().map_err(|_| ServerError::Protocol)?;
                if incoming
                    .trailers()
                    .await
                    .map_err(|_| ServerError::Http2)?
                    .is_some()
                {
                    return Err(ServerError::Protocol);
                }
                return Ok(None);
            };
            let block = block.map_err(|_| ServerError::Http2)?;
            let size = block.len();
            let frames = self
                .decoder
                .feed(&block)
                .map_err(|_| ServerError::Protocol)?;
            self.ready.extend(frames);
            incoming
                .flow_control()
                .release_capacity(size)
                .map_err(|_| ServerError::Http2)?;
        }
    }
}

async fn handle_frames(
    incoming: &mut h2::RecvStream,
    outgoing: &mut h2::SendStream<Bytes>,
    context: &ServerContext,
    session_id: u64,
) -> Result<(), ServerError> {
    let mut decoder = IncomingFrames::default();
    let mut state = Session::new(Role::Server);
    let opened = timeout(HANDSHAKE_TIMEOUT, async {
        let hello = decoder.next(incoming).await?.ok_or(ServerError::Protocol)?;
        state
            .apply(Direction::Receive, &hello)
            .map_err(|_| ServerError::Protocol)?;
        let Frame::Hello { capabilities, .. } = hello else {
            return Err(ServerError::Protocol);
        };
        let ack = Frame::HelloAck {
            version: protocol::VERSION,
            accepted_capabilities: capabilities & protocol::CAP_PADDING,
        };
        state
            .apply(Direction::Send, &ack)
            .map_err(|_| ServerError::Protocol)?;
        send_frame(outgoing, &ack).await?;
        if let Some(padding) = context.padding_frame(capabilities & protocol::CAP_PADDING)? {
            state
                .apply(Direction::Send, &padding)
                .map_err(|_| ServerError::Protocol)?;
            send_frame(outgoing, &padding).await?;
        }
        let open = loop {
            let frame = decoder.next(incoming).await?.ok_or(ServerError::Protocol)?;
            state
                .apply(Direction::Receive, &frame)
                .map_err(|_| ServerError::Protocol)?;
            if matches!(frame, Frame::Padding(_)) {
                tokio::task::yield_now().await;
                continue;
            }
            break frame;
        };
        match open {
            Frame::OpenTcp { address, port } | Frame::OpenUdp { address, port } => {
                Ok::<_, ServerError>((address, port))
            }
            _ => Err(ServerError::Protocol),
        }
    })
    .await
    .map_err(|_| ServerError::TimedOut)??;
    let (address, port) = opened;
    crate::diag!(
        Trace,
        "server.h2",
        "hello_and_open_validated",
        "session" = Value::Count(session_id)
    );
    let udp = state.udp();
    let dial = tokio::select! {
        biased;
        next = async {
            loop {
                match decoder.next(incoming).await? {
                    Some(frame @ Frame::Padding(_)) => {
                        state.apply(Direction::Receive, &frame).map_err(|_| ServerError::Protocol)?;
                        tokio::task::yield_now().await;
                    }
                    _ => return Err::<(), ServerError>(ServerError::Protocol),
                }
            }
        } => {
            next?;
            return Err(ServerError::Protocol);
        }
        result = async {
            if udp { context.dial_udp_target(&address, port).await.map(crate::udp_relay::Target::Udp) }
            else { context.dial_target(&address, port).await.map(crate::udp_relay::Target::Tcp) }
        } => result,
        _ = std::future::poll_fn(|cx| outgoing.poll_reset(cx)) => {
            return Err(ServerError::Http2);
        }
    };
    let tcp = match dial {
        Ok(tcp) => tcp,
        Err(code) => {
            crate::diag!(
                Warn,
                "server.h2",
                "target_dial_rejected",
                "session" = Value::Count(session_id),
                "code" = Value::Count(code as u64)
            );
            let failure = Frame::OpenError(code);
            state
                .apply(Direction::Send, &failure)
                .map_err(|_| ServerError::Protocol)?;
            timeout(FRAME_IDLE_TIMEOUT, send_frame(outgoing, &failure))
                .await
                .map_err(|_| ServerError::TimedOut)??;
            return Ok(());
        }
    };
    state
        .apply(Direction::Send, &Frame::OpenOk)
        .map_err(|_| ServerError::Protocol)?;
    timeout(FRAME_IDLE_TIMEOUT, send_frame(outgoing, &Frame::OpenOk))
        .await
        .map_err(|_| ServerError::TimedOut)??;
    crate::diag!(
        Debug,
        "server.h2",
        "open_ok_sent",
        "session" = Value::Count(session_id)
    );
    match tcp {
        crate::udp_relay::Target::Tcp(tcp) => {
            relay_tcp(tcp, incoming, outgoing, decoder, state, session_id).await
        }
        crate::udp_relay::Target::Udp(udp) => {
            relay_udp(udp, incoming, outgoing, decoder, state).await
        }
    }
}

/// Drive the two TCP directions independently. In particular, lack of H2
/// response credit must never block writes to the target TCP connection.
/// Each directional FSM starts at OPEN_OK; only its own DATA/FIN transitions
/// are applied. Both tasks must finish successfully for graceful completion.
async fn relay_tcp(
    tcp: TcpStream,
    incoming: &mut h2::RecvStream,
    outgoing: &mut h2::SendStream<Bytes>,
    mut decoder: IncomingFrames,
    mut state: Session,
    session_id: u64,
) -> Result<(), ServerError> {
    let traffic = crate::traffic::enter(crate::Role::Server, false);
    let (mut read, mut write) = tcp.into_split();
    let mut rx_state = state.clone();
    let mut tx_state = state.clone();
    let activity = crate::relay_liveness::Activity::new();
    let (download_done, download_finished) = tokio::sync::oneshot::channel();
    let upload = async {
        loop {
            let frame = decoder.next(incoming).await?.ok_or(ServerError::Protocol)?;
            rx_state
                .apply(Direction::Receive, &frame)
                .map_err(|_| ServerError::Protocol)?;
            match frame {
                Frame::Padding(_) => tokio::task::yield_now().await,
                Frame::Data(data) => {
                    crate::diag!(
                        Trace,
                        "server.h2",
                        "upload_frame",
                        "session" = Value::Count(session_id),
                        "bytes" = Value::Count(data.len() as u64)
                    );
                    timeout(FRAME_IDLE_TIMEOUT, write.write_all(&data))
                        .await
                        .map_err(|_| ServerError::TimedOut)?
                        .map_err(|_| ServerError::Io)?;
                    traffic.upload(data.len());
                    activity.data(data.len());
                }
                Frame::Fin => {
                    crate::diag!(
                        Debug,
                        "server.h2",
                        "upload_fin",
                        "session" = Value::Count(session_id)
                    );
                    timeout(FRAME_IDLE_TIMEOUT, write.shutdown())
                        .await
                        .map_err(|_| ServerError::TimedOut)?
                        .map_err(|_| ServerError::Io)?;
                    activity.half_closed();
                    break;
                }
                Frame::Abort(_) => return Err(ServerError::Http2),
                _ => return Err(ServerError::Protocol),
            }
        }
        // FIN half-closes TCP upload, not the HTTP request itself. Keep
        // watching for reset, trailing frames or request EOF while downloading.
        let tail = crate::relay_liveness::receive_tail(
            async {
                loop {
                    let frame = decoder.next(incoming).await?;
                    if let Some(padding @ Frame::Padding(_)) = &frame {
                        if activity.both_finished() {
                            return Err(ServerError::Protocol);
                        }
                        rx_state
                            .apply(Direction::Receive, padding)
                            .map_err(|_| ServerError::Protocol)?;
                        tokio::task::yield_now().await;
                        continue;
                    }
                    return Ok(frame);
                }
            },
            download_finished,
            ServerError::TimedOut,
        )
        .await?;
        if tail.is_some() {
            return Err(ServerError::Protocol);
        }
        Ok::<(), ServerError>(())
    };
    let download = async {
        let mut buffer = [0u8; crate::relay_batch::MAX_BATCH];
        let mut batch = crate::relay_batch::ReadyBatch::default();
        loop {
            let size = tokio::select! {
                result = batch.read(&mut read, &mut buffer) => {
                    result.map_err(|_| ServerError::Io)?
                }
                _ = std::future::poll_fn(|cx| outgoing.poll_reset(cx)) => {
                    return Err(ServerError::Http2);
                }
            };
            let frame = if size == 0 {
                Frame::Fin
            } else {
                Frame::Data(buffer[..size].to_vec())
            };
            crate::diag!(
                Trace,
                "server.h2",
                "download_frame",
                "session" = Value::Count(session_id),
                "bytes" = Value::Count(size as u64),
                "fin" = Value::Flag(size == 0)
            );
            tx_state
                .apply(Direction::Send, &frame)
                .map_err(|_| ServerError::Protocol)?;
            timeout(FRAME_IDLE_TIMEOUT, send_frame(outgoing, &frame))
                .await
                .map_err(|_| ServerError::TimedOut)??;
            if size == 0 {
                activity.half_closed();
                let _ = download_done.send(());
                return Ok::<(), ServerError>(());
            }
            traffic.download(size);
            activity.data(size);
        }
    };

    // An error can cancel send_frame halfway through an H2 window. Reset
    // the stream instead of appending an ABORT to a partially written frame.
    activity
        .run(upload, download, ServerError::TimedOut)
        .await
        .map_err(|error| {
            // Preserve timeout diagnostics; other errors can interrupt an H2 frame.
            if matches!(error, ServerError::TimedOut) {
                error
            } else {
                ServerError::Http2
            }
        })?;
    state
        .apply(Direction::Receive, &Frame::Fin)
        .map_err(|_| ServerError::Protocol)?;
    state
        .apply(Direction::Send, &Frame::Fin)
        .map_err(|_| ServerError::Protocol)?;
    state.finish().map_err(|_| ServerError::Protocol)
}

pub(crate) fn pem_data(
    reference: &str,
    private_key: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ServerError> {
    let path = reference.strip_prefix("file:").ok_or(ServerError::Config)?;
    crate::bounded_input::read(Path::new(path), MAX_PEM_BYTES, true, private_key)
        .map_err(|_| ServerError::Config)
}

fn check_certificate_name(
    leaf: &rustls::pki_types::CertificateDer<'_>,
    name: &str,
) -> Result<(), ServerError> {
    let name = rustls::pki_types::ServerName::try_from(name.to_owned())
        .map_err(|_| ServerError::Config)?;
    let cert = rustls::server::ParsedCertificate::try_from(leaf).map_err(|_| ServerError::Tls)?;
    rustls::client::verify_server_name(&cert, &name).map_err(|_| ServerError::Tls)
}

struct TlsMaterial {
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    identity: crate::reload_preflight::IdentityHash,
}

fn tls_material(inbound: &Inbound) -> Result<TlsMaterial, ServerError> {
    if inbound.security_mode == crate::security_profile::SecurityMode::SmartReality
        || inbound.reality.is_some()
    {
        return Err(ServerError::Config);
    }
    let cert_bytes = pem_data(&inbound.tls_cert, false)?;
    let key_bytes = pem_data(&inbound.tls_key, true)?;
    tls_material_from_bytes(inbound, &cert_bytes, &key_bytes)
}

fn tls_material_from_bytes(
    inbound: &Inbound,
    cert_bytes: &[u8],
    key_bytes: &[u8],
) -> Result<TlsMaterial, ServerError> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let identity = crate::reload_preflight::IdentityHash::from_pem(cert_bytes, key_bytes);
    if inbound.security_mode == crate::security_profile::SecurityMode::SmartReality
        || inbound.reality.is_some()
    {
        return Err(ServerError::Config);
    }
    let mut cert_reader = BufReader::new(cert_bytes);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|_| ServerError::Config)?;
    let leaf = certs.first().ok_or(ServerError::Config)?;
    check_certificate_name(leaf, &inbound.server_name)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes))
        .map_err(|_| ServerError::Config)?
        .ok_or(ServerError::Config)?;
    Ok(TlsMaterial {
        certs,
        key,
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        identity,
    })
}

/// One read of each external TLS PEM file, tied to the operator's
/// independently supplied SHA-256. No private key bytes appear in IPC,
/// stderr or logs; raw buffers are zeroized when the request/snapshot drops.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) struct CapturedTls {
    pairs: Vec<CapturedMaterial>,
    fingerprint: [u8; 32],
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
enum CapturedMaterial {
    Pem(CapturedPem),
    Reality(
        Box<crate::reality_generation::Candidate>,
        crate::reload_preflight::IdentityHash,
    ),
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
struct CapturedPem {
    cert: zeroize::Zeroizing<Vec<u8>>,
    key: zeroize::Zeroizing<Vec<u8>>,
    identity: crate::reload_preflight::IdentityHash,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl CapturedTls {
    /// Domain-separated and length-delimited digest, including stable inbound
    /// IDs in document order. This prevents a reordered pair or ambiguous
    /// PEM concatenation from sharing an operator approval fingerprint.
    pub(crate) fn capture(document: &ServerDocument) -> Result<Self, ServerError> {
        let mut hash = Sha256::new();
        hash.update(b"theia-tls-pem-snapshot-v1\0");
        hash.update((document.server.inbounds.len() as u64).to_be_bytes());
        let mut pairs = Vec::with_capacity(document.server.inbounds.len());
        for inbound in &document.server.inbounds {
            if let Some(binding) = &inbound.reality {
                let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
                let candidate = crate::reality_generation::Candidate::capture(inbound, now)
                    .map_err(|_| ServerError::Config)?;
                let fingerprint = candidate.fingerprint();
                for chunk in [
                    inbound.id.as_bytes(),
                    b"Theia/REALITY/v1".as_slice(),
                    fingerprint.as_slice(),
                ] {
                    hash.update((chunk.len() as u64).to_be_bytes());
                    hash.update(chunk);
                }
                pairs.push(CapturedMaterial::Reality(
                    Box::new(candidate),
                    crate::reload_preflight::IdentityHash::reality(binding),
                ));
                continue;
            }
            let cert = pem_data(&inbound.tls_cert, false)?;
            let key = pem_data(&inbound.tls_key, true)?;
            // A successful fingerprint is proof of a usable TLS1.3 identity,
            // not simply that two arbitrary private files could be hashed.
            let material = tls_material_from_bytes(inbound, &cert, &key)?;
            let _h2 = tls_acceptor(material.certs.clone(), material.key.clone_key())?;
            let _h3 = crate::h3_server::OwnTlsConfig::new(material.certs, material.key)
                .map_err(|_| ServerError::Tls)?;
            let id = inbound.id.as_bytes();
            for chunk in [id, cert.as_slice(), key.as_slice()] {
                hash.update((chunk.len() as u64).to_be_bytes());
                hash.update(chunk);
            }
            let identity = crate::reload_preflight::IdentityHash::from_pem(&cert, &key);
            pairs.push(CapturedMaterial::Pem(CapturedPem {
                cert,
                key,
                identity,
            }));
        }
        Ok(Self {
            pairs,
            fingerprint: hash.finalize().into(),
        })
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub(crate) fn matches(&self, expected: &[u8; 32]) -> bool {
        self.fingerprint.ct_eq(expected).unwrap_u8() == 1
    }

    pub(crate) fn identities(&self) -> Vec<crate::reload_preflight::IdentityHash> {
        self.pairs
            .iter()
            .map(|pair| match pair {
                CapturedMaterial::Pem(p) => p.identity.clone(),
                CapturedMaterial::Reality(_, id) => id.clone(),
            })
            .collect()
    }

    fn material(&self, inbound: &Inbound, index: usize) -> Result<TlsMaterial, ServerError> {
        let Some(CapturedMaterial::Pem(pair)) = self.pairs.get(index) else {
            return Err(ServerError::Config);
        };
        tls_material_from_bytes(inbound, &pair.cert, &pair.key)
    }
    fn reality(&self, index: usize) -> Result<&crate::reality_generation::Candidate, ServerError> {
        let Some(CapturedMaterial::Reality(candidate, _)) = self.pairs.get(index) else {
            return Err(ServerError::Config);
        };
        Ok(candidate)
    }
}

/// Read-only local CLI tool. It reads the same bounded private PEM files that
/// the server will later capture; the resulting digest is public, NOT the key.
/// Operators must compute this fingerprint from trusted/immutable PEM paths.
pub fn tls_fingerprint_file(path: &Path) -> Result<[u8; 32], ServerError> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        let document = match config::read_file(path).map_err(|_| ServerError::Config)? {
            Config::Server(document) => document,
            _ => return Err(ServerError::Config),
        };
        Ok(CapturedTls::capture(&document)?.fingerprint)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = path;
        Err(ServerError::Config)
    }
}

fn tls_acceptor(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, ServerError> {
    let tls = crate::transport_policy::Carrier::H2
        .server_tls(certs, key)
        .map_err(|_| ServerError::Tls)?;
    Ok(TlsAcceptor::from(Arc::new(tls)))
}

/// Prepare all TCP and UDP listeners and TLS identity before launching tasks.
pub async fn run_file(config_path: &Path) -> Result<(), ServerError> {
    crate::diag!(Info, "server", "config_read_begin");
    let parsed = config::read_file(config_path).map_err(|_| ServerError::Config)?;
    let Config::Server(document) = parsed else {
        crate::diag!(Warn, "server", "config_role_mismatch");
        return Err(ServerError::Config);
    };
    crate::diag!(
        Info,
        "server",
        "config_valid",
        "inbounds" = Value::Count(document.server.inbounds.len() as u64)
    );
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        run_supervised_file(document, config_path, None).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        run_document_with_config(document, Some(config_path)).await
    }
}

/// Shared admission accounting for OLD and NEW listeners. The first online
/// cutover slice deliberately rejects changes to these limits or user IDs.
#[cfg(any(target_os = "linux", target_os = "windows"))]
struct GenerationLimits {
    global: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    per_user: Arc<HashMap<String, Arc<Semaphore>>>,
    ledger: Arc<crate::quota::Ledger>,
    peer_budget: Arc<PeerBudget>,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl GenerationLimits {
    fn new(document: &ServerDocument) -> Self {
        let policy = &document.server.policy;
        let per_user = document
            .server
            .users
            .iter()
            .map(|user| {
                (
                    user.id.clone(),
                    Arc::new(Semaphore::new(policy.max_connections_per_user as usize)),
                )
            })
            .collect();
        Self {
            global: Arc::new(Semaphore::new(policy.max_connections_total as usize)),
            connections: Arc::new(Semaphore::new(policy.max_connections_total as usize)),
            per_user: Arc::new(per_user),
            ledger: crate::quota::Ledger::new(policy, &document.server.users),
            peer_budget: Arc::new(PeerBudget::default()),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
enum ReadyListener {
    Plain(
        TcpListener,
        TlsAcceptor,
        crate::h3_server::OwnTlsEndpoint,
        Arc<ServerContext>,
        crate::h3_server::OwnTlsConfig,
    ),
    Reality(
        crate::reality_tcp::PreparedTcp,
        Option<crate::reality_quic::PreparedQuic>,
        Option<tokio::net::UdpSocket>,
        Box<crate::reality_generation::Manager>,
        Arc<crate::reality_live::Live>,
    ),
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
struct PreparedGeneration {
    listeners: Vec<ReadyListener>,
    identities: Vec<crate::reload_preflight::IdentityHash>,
    live: Arc<LiveAuthorization>,
    reality: crate::runtime_generation::RealityMap,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn prepare_generation(
    document: &ServerDocument,
    revision: u64,
    limits: &GenerationLimits,
    captured: Option<&CapturedTls>,
) -> Result<PreparedGeneration, ServerError> {
    let live = Arc::new(
        LiveAuthorization::new_at_revision(document.clone(), revision)
            .map_err(|_| ServerError::Config)?,
    );
    prepare_selected_listeners(document, limits, captured, live, None).await
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn prepare_selected_listeners(
    document: &ServerDocument,
    limits: &GenerationLimits,
    captured: Option<&CapturedTls>,
    live: Arc<LiveAuthorization>,
    only: Option<&std::collections::HashSet<String>>,
) -> Result<PreparedGeneration, ServerError> {
    prepare_selected_listeners_inner(
        document,
        limits,
        captured,
        live,
        only,
        #[cfg(test)]
        None,
    )
    .await
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn prepare_selected_listeners_inner(
    document: &ServerDocument,
    limits: &GenerationLimits,
    captured: Option<&CapturedTls>,
    live: Arc<LiveAuthorization>,
    only: Option<&std::collections::HashSet<String>>,
    #[cfg(test)] guard_start: Option<u64>,
) -> Result<PreparedGeneration, ServerError> {
    let mut listeners = Vec::with_capacity(document.server.inbounds.len());
    let mut identities = Vec::with_capacity(document.server.inbounds.len());
    let mut reality = HashMap::new();
    let config = Config::Server(document.clone());
    for (index, inbound) in document.server.inbounds.iter().enumerate() {
        if only.is_some_and(|ids| !ids.contains(&inbound.id)) {
            continue;
        }
        let tcp_addr: SocketAddr = inbound.h2_listen.parse().map_err(|_| ServerError::Config)?;
        let udp_addr: SocketAddr = inbound
            .quic_listen
            .parse()
            .map_err(|_| ServerError::Config)?;
        if let Some(binding) = &inbound.reality {
            let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
            let (manager, lease) = if let Some(snapshot) = captured {
                snapshot
                    .reality(index)?
                    .activate(inbound, now)
                    .map_err(|_| ServerError::Config)?
            } else {
                let manager =
                    crate::reality_generation::Manager::new_live(&config, &inbound.id, now)
                        .await
                        .map_err(|_| ServerError::Config)?;
                let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
                let lease = manager.refresh(now).map_err(|_| ServerError::Config)?;
                (manager, lease)
            };
            let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
            let h3 = lease.publication().active().verified().descriptor().h3;
            let mut context = ServerContext::with_limits(
                inbound,
                &document.server.policy,
                live.shared(),
                limits.global.clone(),
                limits.per_user.clone(),
                limits.connections.clone(),
                limits.peer_budget.clone(),
            );
            // The staged AuthCell may not contain a newly added inbound until CAS.
            context.live_quota = Some(limits.ledger.clone());
            #[cfg(test)]
            let carrier = if let Some(start) = guard_start {
                crate::reality_live::Live::with_guard_start(
                    Arc::new(lease),
                    Arc::new(context),
                    now,
                    start,
                )?
            } else {
                crate::reality_live::Live::new(Arc::new(lease), Arc::new(context), now)?
            };
            #[cfg(not(test))]
            let carrier = crate::reality_live::Live::new(Arc::new(lease), Arc::new(context), now)?;
            let listener = crate::tcp_bbr::bind(tcp_addr).map_err(|e| match e {
                crate::tcp_bbr::Error::Network => ServerError::Io,
                crate::tcp_bbr::Error::Unavailable => ServerError::TcpControllerUnavailable,
            })?;
            let tcp = crate::reality_tcp::PreparedTcp::from_live(listener, carrier.clone())?;
            let udp = crate::routing::carrier_socket::bind_plain_udp(udp_addr)
                .await
                .map_err(|_| ServerError::Io)?;
            let (quic, silent) = if h3 {
                (
                    Some(crate::reality_quic::PreparedQuic::from_live(
                        udp,
                        carrier.clone(),
                    )?),
                    None,
                )
            } else {
                (None, Some(udp))
            };
            identities.push(crate::reload_preflight::IdentityHash::reality(binding));
            reality.insert(
                inbound.id.clone(),
                (binding.manifest_sha256, carrier.clone()),
            );
            listeners.push(ReadyListener::Reality(
                tcp,
                quic,
                silent,
                Box::new(manager),
                carrier,
            ));
            continue;
        }
        let material = match captured {
            Some(snapshot) => snapshot.material(inbound, index)?,
            None => tls_material(inbound)?,
        };
        identities.push(material.identity);
        let acceptor = tls_acceptor(material.certs.clone(), material.key.clone_key())?;
        // Prebind BOTH transports before publishing or shutting down ANY
        // old listener. A failure drops all prepared sockets by RAII.
        let listener = crate::tcp_bbr::bind(tcp_addr).map_err(|error| match error {
            crate::tcp_bbr::Error::Network => ServerError::Io,
            crate::tcp_bbr::Error::Unavailable => ServerError::TcpControllerUnavailable,
        })?;
        let h3_config = crate::h3_server::OwnTlsConfig::new(material.certs, material.key)
            .map_err(|_| ServerError::Tls)?;
        let endpoint = crate::h3_server::OwnTlsEndpoint::bind(udp_addr, h3_config.clone())
            .map_err(|_| ServerError::Io)?;
        let mut context = ServerContext::with_limits(
            inbound,
            &document.server.policy,
            live.shared(),
            limits.global.clone(),
            limits.per_user.clone(),
            limits.connections.clone(),
            limits.peer_budget.clone(),
        );
        context.live_quota = Some(limits.ledger.clone());
        context.apply_own_tls_policy();
        listeners.push(ReadyListener::Plain(
            listener,
            acceptor,
            endpoint,
            Arc::new(context),
            h3_config,
        ));
    }
    Ok(PreparedGeneration {
        listeners,
        identities,
        live,
        reality,
    })
}

/// Exact currently bound TLS accept handles. No socket is closed or rebound
/// when the supervisor rotates the certificate for new H2/H3 handshakes.
#[cfg(any(target_os = "linux", target_os = "windows"))]
struct HotIdentity {
    id: String,
    h2: Arc<RwLock<TlsAcceptor>>,
    h3: crate::h3_server::OwnTlsEndpoint,
}

/// TLS-only candidate fully staged *before* touching either bound socket.
/// Both transport identities and BBR/ALPN parameters are validated using
/// exactly the startup configuration builders.
#[cfg(any(target_os = "linux", target_os = "windows"))]
struct PreparedSamePortTls {
    h2: Vec<TlsAcceptor>,
    h3: Vec<crate::h3_server::OwnTlsConfig>,
    identities: Vec<crate::reload_preflight::IdentityHash>,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn prepare_same_port_tls(
    document: &ServerDocument,
    captured: &CapturedTls,
) -> Result<PreparedSamePortTls, ServerError> {
    let mut h2 = Vec::with_capacity(document.server.inbounds.len());
    let mut h3 = Vec::with_capacity(document.server.inbounds.len());
    // Keep identities in document order, but compile PEM acceptors in
    // ordinary-listener order, exactly as RunningGeneration::launch does.
    let identities = captured.identities();
    for (index, inbound) in document.server.inbounds.iter().enumerate() {
        if inbound.reality.is_some() {
            continue;
        }
        let material = captured.material(inbound, index)?;
        let h2_acceptor = tls_acceptor(material.certs.clone(), material.key.clone_key())?;
        let h3_config = crate::h3_server::OwnTlsConfig::new(material.certs, material.key)
            .map_err(|_| ServerError::Tls)?;
        h2.push(h2_acceptor);
        h3.push(h3_config);
    }
    Ok(PreparedSamePortTls { h2, h3, identities })
}

/// The *previous* actual TLS identity, retained for at most five minutes
/// after ONE same-port rotation. TLS ServerConfig owns private signing keys;
/// this slot never holds raw PEM bytes and never touches disk on rollback.
#[cfg(any(target_os = "linux", target_os = "windows"))]
struct StructuralRollbackSlot {
    document: Arc<ServerDocument>,
    identities: Vec<crate::reload_preflight::IdentityHash>,
    revision: u64,
    ready_at: Instant,
    expires: Instant,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
struct RollbackSlot {
    expires: Instant,
    h2: Vec<TlsAcceptor>,
    h3: Vec<crate::h3_server::OwnTlsConfig>,
    identities: Vec<crate::reload_preflight::IdentityHash>,
    refs: Vec<(String, String)>,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
const TLS_ROLLBACK_WINDOW: Duration = Duration::from_secs(300);

#[cfg(any(target_os = "linux", target_os = "windows"))]
struct HotReality {
    id: String,
    carrier: Arc<crate::reality_live::Live>,
    manager: Arc<tokio::sync::Mutex<Arc<crate::reality_generation::Manager>>>,
    used_roots: std::collections::HashSet<[u8; 32]>,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
struct RunningGeneration {
    tasks: JoinSet<(String, Result<(), ServerError>)>,
    phases: HashMap<String, watch::Sender<GenerationPhase>>,
    draining: std::collections::HashSet<String>,
    identities: Vec<HotIdentity>,
    // Exact QUIC configs installed on the endpoints. Saved previous configs
    // support a one-shot TLS undo without reading external PEM files again.
    active_h3: Vec<crate::h3_server::OwnTlsConfig>,
    reality: Vec<HotReality>,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl RunningGeneration {
    fn launch(listeners: Vec<ReadyListener>, phase: GenerationPhase) -> Self {
        let mut running = Self {
            tasks: JoinSet::new(),
            phases: HashMap::new(),
            draining: Default::default(),
            identities: Vec::new(),
            active_h3: Vec::new(),
            reality: Vec::new(),
        };
        running.append(listeners, phase);
        running
    }
    fn append(&mut self, listeners: Vec<ReadyListener>, phase: GenerationPhase) {
        for listener in listeners {
            let id = match &listener {
                ReadyListener::Plain(_, _, _, context, _) => context.inbound_id.clone(),
                ReadyListener::Reality(_, _, _, _, carrier) => carrier.inbound_id().to_owned(),
            };
            let (sender, receiver) = watch::channel(phase);
            self.phases.insert(id.clone(), sender);
            let mut tasks = JoinSet::new();
            match listener {
                ReadyListener::Plain(tcp, acceptor, udp, context, h3_config) => {
                    let h2 = Arc::new(RwLock::new(acceptor));
                    self.identities.push(HotIdentity {
                        id: id.clone(),
                        h2: h2.clone(),
                        h3: udp.clone(),
                    });
                    self.active_h3.push(h3_config);
                    tasks.spawn(serve_generation_with_tls(
                        tcp,
                        h2,
                        context.clone(),
                        receiver.clone(),
                    ));
                    tasks.spawn(udp.serve_generation(context, receiver.clone()));
                }
                ReadyListener::Reality(tcp, quic, silent, manager, carrier) => {
                    let root = manager.root_fingerprint();
                    let manager = Arc::new(tokio::sync::Mutex::new(Arc::new(*manager)));
                    self.reality.push(HotReality {
                        id: id.clone(),
                        carrier: carrier.clone(),
                        manager: manager.clone(),
                        used_roots: std::collections::HashSet::from([root]),
                    });
                    let mut phase = receiver.clone();
                    tasks.spawn(async move {
                        if !await_generation_activation(&mut phase).await {
                            return Ok(());
                        }
                        tcp.serve_generation(phase).await
                    });
                    if let Some(quic) = quic {
                        let mut phase = receiver.clone();
                        tasks.spawn(async move {
                            if !await_generation_activation(&mut phase).await {
                                return Ok(());
                            }
                            quic.serve_generation(phase).await
                        });
                    }
                    if let Some(socket) = silent {
                        let mut phase = receiver.clone();
                        tasks.spawn(async move {
                            let _socket = socket;
                            if !await_generation_activation(&mut phase).await {
                                return Ok(());
                            }
                            while phase.changed().await.is_ok() {
                                if *phase.borrow() == GenerationPhase::Drain {
                                    break;
                                }
                            }
                            Ok(())
                        });
                    }
                    let mut phase = receiver.clone();
                    tasks.spawn(async move{
                        if !await_generation_activation(&mut phase).await{return Ok(());}
                        loop{
                            tokio::select!{
                                changed=phase.changed()=>{
                                    if changed.is_err()||*phase.borrow()==GenerationPhase::Drain{return Ok(());}
                                }
                                _=tokio::time::sleep(Duration::from_secs(5))=>{
                                    let manager=manager.lock().await;
                                    let result=tokio::select!{
                                        result=manager.maintain(&carrier)=>result,
                                        _=phase.changed()=>return Ok(()),
                                    };
                                    match result{
                                        Ok(lease)=>{
                                            if let Ok(now)=crate::reference_health::unix_now(){
                                                if carrier.publish(Arc::new(lease),now).is_ok(){continue;}
                                            }
                                            carrier.suspend();
                                        }
                                        Err(_)=>carrier.suspend(),
                                    }
                                }
                            }
                        }
                    });
                }
            }
            // Own every transport task for this inbound in a scoped group.
            // Dropping the parent cancels the entire group, including on
            // panic. An active group exiting unexpectedly is fatal.
            self.tasks.spawn(async move {
                let mut phase = receiver;
                let result = loop {
                    if *phase.borrow() == GenerationPhase::Drain {
                        break Ok(());
                    }
                    tokio::select! {
                        change=phase.changed()=>{
                            if change.is_err(){break Ok(());}
                        }
                        joined=tasks.join_next()=>{
                            if *phase.borrow()==GenerationPhase::Drain{break Ok(());}
                            break match joined{Some(Ok(Err(e)))=>Err(e),_=>Err(ServerError::Io)};
                        }
                    }
                };
                if result.is_ok() {
                    let _ = timeout(GENERATION_DRAIN + Duration::from_secs(2), async {
                        while tasks.join_next().await.is_some() {}
                    })
                    .await;
                }
                tasks.shutdown().await;
                (id, result)
            });
        }
    }
    fn is_healthy_before_activation(&mut self) -> bool {
        self.tasks.try_join_next().is_none()
    }
    fn start(&self) {
        for phase in self.phases.values() {
            phase.send_replace(GenerationPhase::Active);
        }
    }
    fn drain(&self) {
        for hot in &self.reality {
            hot.carrier.retire();
        }
        for phase in self.phases.values() {
            phase.send_replace(GenerationPhase::Drain);
        }
    }
    fn remove_inbounds(&mut self, removed: &std::collections::HashSet<String>) {
        // Revoke admissions on all removed REALITY contexts before signalling
        // GOAWAY. Existing tunnel permits and retained inbounds are unaffected.
        self.reality.retain(|hot| {
            if removed.contains(&hot.id) {
                hot.carrier.retire();
                false
            } else {
                true
            }
        });
        for id in removed {
            if let Some(phase) = self.phases.get(id) {
                self.draining.insert(id.clone());
                phase.send_replace(GenerationPhase::Drain);
            }
        }
        let old = std::mem::take(&mut self.identities);
        let configs = std::mem::take(&mut self.active_h3);
        for (hot, cfg) in old.into_iter().zip(configs) {
            if !removed.contains(&hot.id) {
                self.identities.push(hot);
                self.active_h3.push(cfg);
            }
        }
    }
    fn order_plain(&mut self, document: &ServerDocument) {
        let mut entries: Vec<_> = std::mem::take(&mut self.identities)
            .into_iter()
            .zip(std::mem::take(&mut self.active_h3))
            .collect();
        entries.sort_by_key(|(hot, _)| {
            document
                .server
                .inbounds
                .iter()
                .position(|i| i.id == hot.id)
                .unwrap_or(usize::MAX)
        });
        (self.identities, self.active_h3) = entries.into_iter().unzip();
    }
    fn has_draining(&self) -> bool {
        !self.draining.is_empty()
    }
    fn finish_draining(&mut self, id: &str) -> bool {
        if !self.draining.remove(id) {
            return false;
        }
        self.phases.remove(id);
        true
    }
}

/// Exercise the real supervisor preparation, launch and partial removal
/// path. The replay clock override is compiled only into the test harness.
#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
pub(crate) async fn registered_reality_drain_fixture(
    document: ServerDocument,
    ready: tokio::sync::oneshot::Sender<()>,
    drain: tokio::sync::oneshot::Receiver<()>,
    draining: tokio::sync::oneshot::Sender<()>,
) -> Result<(), ServerError> {
    let limits = GenerationLimits::new(&document);
    let authorization =
        Arc::new(LiveAuthorization::new(document.clone()).map_err(|_| ServerError::Config)?);
    let start = crate::reference_health::unix_now()
        .map_err(|_| ServerError::Config)?
        .saturating_sub(121);
    let prepared = prepare_selected_listeners_inner(
        &document,
        &limits,
        None,
        authorization,
        None,
        Some(start),
    )
    .await?;
    let mut running = RunningGeneration::launch(prepared.listeners, GenerationPhase::Active);
    ready.send(()).map_err(|_| ServerError::Io)?;
    tokio::select! {
        signal = drain => signal.map_err(|_| ServerError::Io)?,
        _ = running.tasks.join_next() => return Err(ServerError::Io),
    }
    let removed = document
        .server
        .inbounds
        .iter()
        .map(|inbound| inbound.id.clone())
        .collect();
    running.remove_inbounds(&removed);
    draining.send(()).map_err(|_| ServerError::Io)?;
    while let Some(result) = running.tasks.join_next().await {
        let (id, result) = result.map_err(|_| ServerError::Io)?;
        result?;
        if !running.finish_draining(&id) {
            return Err(ServerError::Io);
        }
    }
    if running.has_draining() {
        return Err(ServerError::Io);
    }
    Ok(())
}

/// Reaper is capped at one at a time. After a bounded 20-second drain, all
/// surviving connections in the previous generation are cancelled; the new
/// generation remains owned by the same supervisor.
#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn reap_previous(mut previous: RunningGeneration) {
    previous.drain();
    let _ = timeout(GENERATION_DRAIN + Duration::from_secs(2), async {
        while previous.tasks.join_next().await.is_some() {}
    })
    .await;
    previous.tasks.abort_all();
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn stage_fresh_generation(
    request: &crate::runtime_generation::RestartRequest,
    identities: &[crate::reload_preflight::IdentityHash],
    limits: &GenerationLimits,
    path: &Path,
) -> Result<
    (
        RunningGeneration,
        crate::runtime_generation::View,
        Vec<crate::reload_preflight::IdentityHash>,
        crate::runtime_generation::RealityMap,
        u64,
    ),
    (),
> {
    let active = request.previous.document.as_ref();
    let candidate = &request.candidate;
    let snapshot = request.material.as_ref().ok_or(())?;
    if !crate::restart_guard::same_shared_limits(active, candidate) {
        return Err(());
    }
    if crate::restart_guard::probe_captured(active, identities, candidate, snapshot)
        != Ok(crate::restart_guard::RestartVerdict::FreshPortsBindable)
    {
        return Err(());
    }
    let next_revision = request.expected_revision.checked_add(1).ok_or(())?;
    let prepared = prepare_generation(candidate, next_revision, limits, Some(snapshot))
        .await
        .map_err(|_| ())?;
    let next = crate::runtime_generation::View {
        document: Arc::new(candidate.clone()),
        inbounds: candidate.server.inbounds.len(),
        preflight: Arc::new(crate::reload_preflight::ReloadPreflight::new(
            path.to_owned(),
            candidate.clone(),
            prepared.identities.clone(),
        )),
        live: prepared.live,
    };
    let mut running = RunningGeneration::launch(prepared.listeners, GenerationPhase::Prepared);
    tokio::task::yield_now().await;
    if !running.is_healthy_before_activation() {
        return Err(());
    }
    Ok((
        running,
        next,
        prepared.identities,
        prepared.reality,
        next_revision,
    ))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn stage_partial_generation(
    request: &crate::runtime_generation::RestartRequest,
    loaded: &[crate::reload_preflight::IdentityHash],
    limits: &GenerationLimits,
    path: &Path,
    plan: &crate::restart_guard::PartialLayout,
) -> Result<
    (
        PreparedGeneration,
        crate::runtime_generation::View,
        crate::live_auth::StagedAuthorization,
    ),
    (),
> {
    let snapshot = request.material.as_ref().ok_or(())?;
    let candidate = &request.candidate;
    if crate::restart_guard::probe_captured(&request.previous.document, loaded, candidate, snapshot)
        != Ok(crate::restart_guard::RestartVerdict::FreshPortsBindable)
    {
        return Err(());
    }
    let (live, auth) = request
        .previous
        .live
        .prepare_tls_rebase(candidate, request.expected_revision)
        .map_err(|_| ())?;
    let live = Arc::new(live);
    let prepared = prepare_selected_listeners(
        candidate,
        limits,
        Some(snapshot),
        live.clone(),
        Some(&plan.added),
    )
    .await
    .map_err(|_| ())?;
    let view = crate::runtime_generation::View {
        document: Arc::new(candidate.clone()),
        inbounds: candidate.server.inbounds.len(),
        preflight: Arc::new(crate::reload_preflight::ReloadPreflight::new(
            path.to_owned(),
            candidate.clone(),
            snapshot.identities(),
        )),
        live,
    };
    Ok((prepared, view, auth))
}

/// Only identity material may change. All PEM/cert/key/QUIC/H2 builders
/// finish before acquiring the short CAS lock or swapping any live handles.
/// The old listener socket and both active tunnel populations remain intact.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn commit_same_port_reality(
    runtime: &crate::runtime_generation::State,
    running: &mut RunningGeneration,
    request: &crate::runtime_generation::RestartRequest,
    loaded: &[crate::reload_preflight::IdentityHash],
    path: &Path,
    root_history: &mut crate::reality_root_history::RootHistory,
) -> Result<(Vec<crate::reload_preflight::IdentityHash>, u64), ()> {
    use crate::restart_guard::{self, RestartVerdict};
    let previous = request.previous.document.as_ref();
    let candidate = &request.candidate;
    let index = restart_guard::same_port_reality_only(previous, candidate).ok_or(())?;
    let snapshot = request.material.as_ref().ok_or(())?;
    if restart_guard::probe_captured(previous, loaded, candidate, snapshot)
        != Ok(RestartVerdict::SamePortTlsReady)
    {
        return Err(());
    }
    let inbound = &candidate.server.inbounds[index];
    let binding = inbound.reality.as_ref().ok_or(())?;
    let old = previous.server.inbounds[index].reality.as_ref().ok_or(())?;
    let hot = running
        .reality
        .iter_mut()
        .find(|v| v.id == inbound.id)
        .ok_or(())?;
    if hot.used_roots.contains(&binding.identity_sha256) {
        return Err(());
    }
    // One supervisor owns the maintenance mutex. If DNS/health work is
    // in progress, refuse rather than race a stale manager publication.
    let mut manager = hot.manager.try_lock().map_err(|_| ())?;
    let now = crate::reference_health::unix_now().map_err(|_| ())?;
    let (next_manager, lease) = snapshot
        .reality(index)
        .map_err(|_| ())?
        .activate(inbound, now)
        .map_err(|_| ())?;
    manager
        .check_replacement(&lease, binding.identity_sha256)
        .map_err(|_| ())?;
    let prepared = hot
        .carrier
        .prepare_replacement(Arc::new(lease), now)
        .map_err(|_| ())?;
    let (live, auth) = request
        .previous
        .live
        .prepare_tls_rebase(candidate, request.expected_revision)
        .map_err(|_| ())?;
    let identities = snapshot.identities();
    let next = crate::runtime_generation::View {
        document: Arc::new(candidate.clone()),
        inbounds: candidate.server.inbounds.len(),
        preflight: Arc::new(crate::reload_preflight::ReloadPreflight::new(
            path.to_owned(),
            candidate.clone(),
            identities.clone(),
        )),
        live: Arc::new(live),
    };
    if request.complete.is_closed() {
        return Err(());
    }
    root_history.advance(candidate)?;
    let revision = hot.carrier.commit_replacement(prepared, |publish| {
        runtime
            .commit_reality_replacement(
                &request.previous,
                request.expected_revision,
                next,
                auth,
                (&inbound.id, old.manifest_sha256, binding.manifest_sha256),
                || {
                    publish();
                    *manager = Arc::new(next_manager);
                },
            )
            .map_err(|_| ())
    })?;
    hot.used_roots.insert(binding.identity_sha256);
    root_history.committed();
    Ok((identities, revision))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn commit_same_port_tls(
    runtime: &crate::runtime_generation::State,
    running: &mut RunningGeneration,
    request: &crate::runtime_generation::RestartRequest,
    loaded_identities: &[crate::reload_preflight::IdentityHash],
    path: &Path,
) -> Result<
    (
        Vec<crate::reload_preflight::IdentityHash>,
        u64,
        RollbackSlot,
    ),
    (),
> {
    let candidate = &request.candidate;
    let original = request.previous.document.as_ref();
    let snapshot = request.material.as_ref().ok_or(())?;
    if crate::restart_guard::probe_captured(original, loaded_identities, candidate, snapshot)
        != Ok(crate::restart_guard::RestartVerdict::SamePortTlsReady)
        || !crate::restart_guard::same_port_tls_only(original, candidate)
        || running.identities.len()
            != candidate
                .server
                .inbounds
                .iter()
                .filter(|i| i.reality.is_none())
                .count()
        || running.active_h3.len() != running.identities.len()
    {
        return Err(());
    }
    let prepared = prepare_same_port_tls(candidate, snapshot).map_err(|_| ())?;
    if prepared.h2.len() != running.identities.len()
        || prepared.h3.len() != running.identities.len()
    {
        return Err(());
    }
    let (rebased_live, staged_auth) = request
        .previous
        .live
        .prepare_tls_rebase(candidate, request.expected_revision)
        .map_err(|_| ())?;
    let next_view = crate::runtime_generation::View {
        document: Arc::new(candidate.clone()),
        inbounds: candidate.server.inbounds.len(),
        preflight: Arc::new(crate::reload_preflight::ReloadPreflight::new(
            path.to_owned(),
            candidate.clone(),
            prepared.identities.clone(),
        )),
        live: Arc::new(rebased_live),
    };

    // Before publishing ANY TLS identity, acquire all H2 acceptor locks.
    // Lock poisoning or a stale CAS aborts without touching the sockets.
    let mut held = Vec::with_capacity(running.identities.len());
    for handle in &running.identities {
        held.push(handle.h2.write().map_err(|_| ())?);
    }
    let previous_h2 = held.iter().map(|guard| (**guard).clone()).collect();
    let previous_h3 = running.active_h3.clone();
    let next_h3 = prepared.h3.clone();
    let refs = original
        .server
        .inbounds
        .iter()
        .map(|inbound| (inbound.tls_cert.clone(), inbound.tls_key.clone()))
        .collect();
    let previous_identities = loaded_identities.to_vec();
    let PreparedSamePortTls { h2, h3, identities } = prepared;
    let revision = runtime
        .commit_tls_rotation(
            &request.previous,
            request.expected_revision,
            next_view,
            staged_auth,
            || {
                for (guard, acceptor) in held.iter_mut().zip(h2) {
                    **guard = acceptor;
                }
                for (handle, config) in running.identities.iter().zip(h3) {
                    handle.h3.set_server_config(config);
                }
            },
        )
        .map_err(|_| ())?;
    running.active_h3 = next_h3;
    let slot = RollbackSlot {
        expires: Instant::now() + TLS_ROLLBACK_WINDOW,
        h2: previous_h2,
        h3: previous_h3,
        identities: previous_identities,
        refs,
    };
    Ok((identities, revision, slot))
}

/// Reinstall exactly the old *compiled* H2/H3 TLS configs after an explicit
/// operator CAS. The current authorization baseline (including quota and
/// token changes made after rotation) is preserved; only TLS identity refs
/// and loaded TLS hashes are restored. One shot, no PEM filesystem I/O.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn commit_tls_rollback(
    runtime: &crate::runtime_generation::State,
    running: &mut RunningGeneration,
    slot: &RollbackSlot,
    expected_revision: u64,
    path: &Path,
) -> Result<(Vec<crate::reload_preflight::IdentityHash>, u64), ()> {
    if Instant::now() >= slot.expires
        || slot.h2.len() != running.identities.len()
        || slot.h3.len() != running.identities.len()
        || running.active_h3.len() != running.identities.len()
    {
        return Err(());
    }
    let previous = runtime.snapshot().map_err(|_| ())?;
    if slot.refs.len() != previous.document.server.inbounds.len()
        || slot.identities.len() != previous.document.server.inbounds.len()
        || running.identities.len()
            != previous
                .document
                .server
                .inbounds
                .iter()
                .filter(|i| i.reality.is_none())
                .count()
        || previous
            .document
            .server
            .inbounds
            .iter()
            .zip(&slot.identities)
            .any(|(i, identity)| {
                i.reality
                    .as_ref()
                    .is_some_and(|b| crate::reload_preflight::IdentityHash::reality(b) != *identity)
            })
        || previous.live.revision() != Ok(expected_revision)
    {
        return Err(());
    }
    let mut target = previous.document.as_ref().clone();
    for (inbound, (cert, key)) in target.server.inbounds.iter_mut().zip(&slot.refs) {
        inbound.tls_cert.clone_from(cert);
        inbound.tls_key.clone_from(key);
    }
    if !crate::restart_guard::same_port_tls_only(&previous.document, &target) {
        return Err(());
    }
    let (rebased_live, staged_auth) = previous
        .live
        .prepare_tls_rebase(&target, expected_revision)
        .map_err(|_| ())?;
    let next = crate::runtime_generation::View {
        document: Arc::new(target.clone()),
        inbounds: target.server.inbounds.len(),
        preflight: Arc::new(crate::reload_preflight::ReloadPreflight::new(
            path.to_owned(),
            target,
            slot.identities.clone(),
        )),
        live: Arc::new(rebased_live),
    };

    // Fail BEFORE changing a single endpoint if any H2 lock is poisoned.
    let mut locks = Vec::with_capacity(running.identities.len());
    for handle in &running.identities {
        locks.push(handle.h2.write().map_err(|_| ())?);
    }
    let h2 = slot.h2.clone();
    let h3 = slot.h3.clone();
    let revision = runtime
        .commit_tls_rotation(&previous, expected_revision, next, staged_auth, || {
            for (guard, acceptor) in locks.iter_mut().zip(h2) {
                **guard = acceptor;
            }
            for (handle, config) in running.identities.iter().zip(h3) {
                handle.h3.set_server_config(config);
            }
        })
        .map_err(|_| ())?;
    running.active_h3.clone_from(&slot.h3);
    Ok((slot.identities.clone(), revision))
}

/// Quota-only CAS: nothing is rebound or restarted, and all previously
/// acquired permits remain counted by the SAME ledger across both transports.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn commit_live_quota(
    runtime: &crate::runtime_generation::State,
    request: &crate::runtime_generation::RestartRequest,
    ledger: &crate::quota::Ledger,
) -> Result<u64, ()> {
    let active = request.previous.document.as_ref();
    let candidate = &request.candidate;
    if !crate::restart_guard::quota_only(active, candidate) {
        return Err(());
    }
    let (rebased_live, staged_auth) = request
        .previous
        .live
        .prepare_tls_rebase(candidate, request.expected_revision)
        .map_err(|_| ())?;
    let next = crate::runtime_generation::View {
        document: Arc::new(candidate.clone()),
        inbounds: request.previous.inbounds,
        preflight: Arc::new(request.previous.preflight.rebased(candidate.clone())),
        live: Arc::new(rebased_live),
    };
    runtime
        .commit_quota(
            &request.previous,
            request.expected_revision,
            next,
            staged_auth,
            ledger,
        )
        .map_err(|_| ())
}

/// Supervisor-owned workers must never outlive a failed supervisor or
/// report a stale management view after a fatal persistence error.
#[cfg(any(target_os = "linux", target_os = "windows"))]
struct SupervisorTask<T>(tokio::task::JoinHandle<T>);
#[cfg(any(target_os = "linux", target_os = "windows"))]
impl<T> Drop for SupervisorTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
struct TuiServerControl {
    expected: [u8; 32],
    management_endpoint: Option<std::path::PathBuf>,
    ready: Option<tokio::sync::oneshot::Sender<usize>>,
    stop: tokio::sync::oneshot::Receiver<()>,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn saved_server_bytes(
    path: &Path,
    expected: [u8; 32],
) -> Result<zeroize::Zeroizing<Vec<u8>>, ServerError> {
    use sha2::{Digest, Sha256};
    let bytes =
        zeroize::Zeroizing::new(config::editor_bytes(path).map_err(|_| ServerError::Config)?);
    let digest: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
    if digest != expected {
        return Err(ServerError::Config);
    }
    Ok(bytes)
}

/// Explicitly owned TUI runtime. No process-wide signals, elevation or new
/// administrative ports; use the same supervisor and strict local IPC.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) async fn run_tui_file(
    path: &Path,
    expected: [u8; 32],
    ready: tokio::sync::oneshot::Sender<usize>,
    stop: tokio::sync::oneshot::Receiver<()>,
    management_endpoint: Option<std::path::PathBuf>,
) -> Result<(), ServerError> {
    let bytes = saved_server_bytes(path, expected)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| ServerError::Config)?;
    let Config::Server(document) = config::parse(text).map_err(|_| ServerError::Config)? else {
        return Err(ServerError::Config);
    };
    drop(bytes);
    if !document.server.enabled {
        return Err(ServerError::Config);
    }
    run_supervised_file(
        document,
        path,
        Some(TuiServerControl {
            expected,
            management_endpoint,
            ready: Some(ready),
            stop,
        }),
    )
    .await
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn run_supervised_file(
    document: ServerDocument,
    config_path: &Path,
    mut control: Option<TuiServerControl>,
) -> Result<(), ServerError> {
    crate::diag!(
        Info,
        "server.supervisor",
        "initial_generation_preflight_begin",
        "inbounds" = Value::Count(document.server.inbounds.len() as u64)
    );
    let mut root_history = crate::reality_root_history::RootHistory::open(config_path, &document)
        .map_err(|_| ServerError::Config)?;
    let limits = GenerationLimits::new(&document);
    let initial = if let Some(control) = &mut control {
        tokio::select! {
            biased;
            _ = &mut control.stop => return Ok(()),
            result = prepare_generation(&document, 1, &limits, None) => result?,
        }
    } else {
        prepare_generation(&document, 1, &limits, None).await?
    };
    if let Some(control) = &control {
        saved_server_bytes(config_path, control.expected)?;
    }
    root_history
        .advance(&document)
        .map_err(|_| ServerError::Config)?;
    root_history.committed();
    crate::diag!(
        Info,
        "server.supervisor",
        "initial_generation_prepared",
        "listeners" = Value::Count(initial.listeners.len() as u64)
    );
    let current_identities = initial.identities.clone();
    let runtime = Arc::new(
        crate::runtime_generation::State::new(crate::runtime_generation::View {
            document: Arc::new(document.clone()),
            inbounds: document.server.inbounds.len(),
            preflight: Arc::new(crate::reload_preflight::ReloadPreflight::new(
                config_path.to_owned(),
                document,
                initial.identities,
            )),
            live: initial.live,
        })
        .with_reality(initial.reality)
        .with_reality_ledger(limits.ledger.clone()),
    );

    // Refresh the pinned pair through a durable TOML + live policy CAS.
    let _geodata_refresh = SupervisorTask(tokio::spawn({
        let runtime = runtime.clone();
        let path = config_path.to_owned();
        async move {
            let mut next_refresh = tokio::time::Instant::now();
            let mut last_directory = None;
            loop {
                if let Ok(view) = runtime.snapshot() {
                    if let Some(settings) = view.document.server.policy.routing.clone() {
                        if let Some(directory) = settings.geodata_directory {
                            if last_directory.as_ref() != Some(&directory)
                                || tokio::time::Instant::now() >= next_refresh
                            {
                                last_directory = Some(directory.clone());
                                next_refresh = tokio::time::Instant::now()
                                    + crate::routing::geodata::REFRESH_INTERVAL;
                                let result = async {
                                    let store =
                                        crate::routing::geodata::Store::new(directory.into())
                                            .map_err(|_| ())?;
                                    let pair =
                                        store.refresh(&settings.rules).await.map_err(|_| ())?;
                                    let manifest = pair.manifest().clone();
                                    drop(pair);
                                    let prepare = runtime.clone();
                                    let path = path.clone();
                                    let stage = tokio::task::spawn_blocking(move || {
                                        prepare.prepare_geodata(&view, &path, manifest)
                                    })
                                    .await
                                    .map_err(|_| ())?
                                    .map_err(|_| ())?;
                                    match stage {
                                        Some(stage) => {
                                            runtime.activate_geodata(stage).map_err(|_| ())?;
                                            Ok(true)
                                        }
                                        None => Ok(false),
                                    }
                                }
                                .await;
                                match result {
                                    Ok(true) => crate::diag!(Info, "server", "geodata_activated"),
                                    Ok(false) => {}
                                    Err(()) => {
                                        // Retry conflicts and temporary failures without replacing pending edits.
                                        next_refresh =
                                            tokio::time::Instant::now() + Duration::from_secs(300);
                                        crate::diag!(
                                            Warn,
                                            "server",
                                            "geodata_refresh_or_apply_failed"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
    }));

    // Only the original, protected management listener survives cutover.
    // Never expose a new administrative TCP port or loosen Named Pipe DACL.
    let (requests, mut queue) =
        tokio::sync::mpsc::channel::<crate::runtime_generation::RestartRequest>(1);
    let inbounds = runtime.snapshot().map_err(|_| ServerError::Io)?.inbounds;
    let owned_endpoint = control
        .as_ref()
        .and_then(|c| c.management_endpoint.as_deref());
    // A TUI-started server binds its own private endpoint, never an unrelated
    // headless endpoint from process environment. Headless behavior is unchanged.
    #[cfg(target_os = "linux")]
    let management = match owned_endpoint {
        Some(directory) => crate::management::StatusServer::bind_in(directory, inbounds).map(Some),
        None => crate::management::StatusServer::from_environment(inbounds),
    }
    .map_err(|_| ServerError::Io)?
    .map(|service| service.with_supervisor(runtime.clone(), requests.clone()));
    #[cfg(target_os = "windows")]
    let management = match owned_endpoint {
        Some(endpoint) => crate::windows_control::WindowsServer::bind(
            endpoint.to_str().ok_or(ServerError::Io)?,
            inbounds,
        )
        .map(Some),
        None => crate::windows_control::WindowsServer::from_environment(inbounds),
    }
    .map_err(|_| ServerError::Io)?
    .map(|service| service.with_supervisor(runtime.clone(), requests.clone()));

    let mut management_task = management.map(|service| {
        SupervisorTask(tokio::spawn(async move {
            service.serve().await.map_err(|_| ServerError::Io)
        }))
    });
    let mut running = RunningGeneration::launch(initial.listeners, GenerationPhase::Active);
    if let Some(control) = &mut control {
        if let Some(ready) = control.ready.take() {
            let _ = ready.send(running.phases.len());
        }
    }
    crate::diag!(Info, "server.supervisor", "generation_active");
    let mut identities = current_identities;
    let mut retiring: Option<SupervisorTask<()>> = None;
    let mut rollback: Option<RollbackSlot> = None;
    let mut structural_rollback: Option<StructuralRollbackSlot> = None;
    // Root history is retained for the entire supervisor and persisted before
    // publishing any structural generation or independent root replacement.
    loop {
        tokio::select! {
            _ = async {
                match &mut control {
                    Some(control) => { let _ = (&mut control.stop).await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                // Close admission before shutdown, and stop accepting further
                // Apply requests. The retiring generation is already draining.
                running.drain();
                if let Some(mut service) = management_task.take() {
                    service.0.abort();
                    let _ = (&mut service.0).await;
                }
                let _ = timeout(GENERATION_DRAIN + Duration::from_secs(2), async {
                    while running.tasks.join_next().await.is_some() {}
                }).await;
                running.tasks.shutdown().await;
                if let Some(mut old) = retiring.take() {
                    let _ = (&mut old.0).await;
                }
                return Ok(());
            }
            request = queue.recv() => {
                let Some(mut request) = request else {
                    return Err(ServerError::Io);
                };
                // No unbounded retired-generation backlog and no double
                // admission during simultaneous restart attempts.
                if running.has_draining()||retiring.as_ref().is_some_and(|worker| !worker.0.is_finished()) {
                    let _ = request.complete.send(Err(()));
                    continue;
                }
                if let Some(mut worker) = retiring.take() {
                    let _ = (&mut worker.0).await;
                }
                if !runtime.still_current(&request.previous, request.expected_revision) {
                    let _ = request.complete.send(Err(()));
                    continue;
                }
                // The sender can disappear if the IPC deadline has elapsed.
                // Never start or commit a speculative restart whose operator
                // is no longer listening for its result.
                if request.complete.is_closed() {
                    continue;
                }
                let structural=request.kind==crate::runtime_generation::ChangeKind::StructuralRollback;
                if structural{
                    let Some(slot)=structural_rollback.as_ref()else{let _=request.complete.send(Err(()));continue;};
                    let now=Instant::now();
                    if slot.revision!=request.expected_revision||now<slot.ready_at||now>=slot.expires{
                        let _=request.complete.send(Err(()));continue;
                    }
                    let previous=slot.document.clone();
                    let previous_ids=slot.identities.clone();
                    let result=tokio::task::spawn_blocking(move||{
                        let material=CapturedTls::capture(&previous).map_err(|_|())?;
                        if material.identities()!=previous_ids{return Err(());}
                        Ok((previous,material))
                    }).await;
                    let Ok(Ok((previous,material)))=result else{let _=request.complete.send(Err(()));continue;};
                    if request.complete.is_closed(){continue;}
                    request.candidate=previous.as_ref().clone();
                    request.material=Some(material);
                }
                if root_history.check(&request.candidate).is_err() {
                    let _=request.complete.send(Err(()));continue;
                }
                if request.kind == crate::runtime_generation::ChangeKind::Rollback {
                    let applied = rollback.as_ref().ok_or(()).and_then(|slot| {
                        commit_tls_rollback(
                            &runtime,
                            &mut running,
                            slot,
                            request.expected_revision,
                            config_path,
                        )
                    });
                    match applied {
                        Ok((old_identities, revision)) => {
                            identities = old_identities;
                            // A rollback is one-shot, never a toggle or an
                            // unbounded cache of previous private identities.
                            rollback = None;
                            runtime.set_rollback_until(None);
                            let _ = request.complete.send(Ok(revision));
                        }
                        Err(()) => {
                            let _ = request.complete.send(Err(()));
                        }
                    }
                    continue;
                }
                if request.kind == crate::runtime_generation::ChangeKind::Quota {
                    let result = commit_live_quota(&runtime, &request, &limits.ledger);
                    let _ = request.complete.send(result);
                    continue;
                }
                if crate::restart_guard::same_port_reality_only(request.previous.document.as_ref(),&request.candidate).is_some(){
                    let result=commit_same_port_reality(&runtime,&mut running,&request,&identities,config_path,&mut root_history);
                    match result{
                        Ok((next,revision))=>{
                            identities=next;
                             // Independent enrollment is not reversible TLS
                            // rotation; never resurrect the replaced root.
                            rollback=None;structural_rollback=None;
                            runtime.set_rollback_until(None);
                            runtime.set_restart_rollback(None);
                            let _=request.complete.send(Ok(revision));
                        }
                        Err(())=>{
                            if root_history.pending() { return Err(ServerError::Io); }
                            let _=request.complete.send(Err(()));
                        }
                    }
                    continue;
                }
                if crate::restart_guard::same_port_tls_only(
                    request.previous.document.as_ref(),
                    &request.candidate,
                ) {
                    let applied = commit_same_port_tls(
                        &runtime,
                        &mut running,
                        &request,
                        &identities,
                        config_path,
                    );
                    match applied {
                        Ok((new_identities, revision, previous_tls)) => {
                            identities = new_identities;
                            runtime.set_rollback_until(Some(previous_tls.expires));
                            rollback=Some(previous_tls);
                            structural_rollback=None;
                            runtime.set_restart_rollback(None);
                            let _ = request.complete.send(Ok(revision));
                        }
                        Err(()) => {
                            let _ = request.complete.send(Err(()));
                        }
                    }
                    continue;
                }
                if let Some(snapshot)=request.material.as_ref(){
                    let next_ids=snapshot.identities();
                    if let Some(plan)=crate::restart_guard::partial_layout(request.previous.document.as_ref(),&identities,&request.candidate,&next_ids){
                        let staged=stage_partial_generation(&request,&identities,&limits,config_path,&plan).await;
                        let Ok((prepared,next_view,auth))=staged else{let _=request.complete.send(Err(()));continue;};
                        if request.complete.is_closed(){continue;}
                        if root_history.advance(&request.candidate).is_err() {
                            if root_history.pending() { return Err(ServerError::Io); }
                            let _=request.complete.send(Err(()));continue;
                        }
                        let root_changed=root_history.retiring();
                        let revision=runtime.commit_partial_layout(&request.previous,request.expected_revision,next_view,auth,&plan.removed,prepared.reality);
                        let Ok(revision)=revision else{
                            if root_history.pending() { return Err(ServerError::Io); }
                            let _=request.complete.send(Err(()));continue;
                        };
                        root_history.committed();
                        running.remove_inbounds(&plan.removed);
                        running.append(prepared.listeners,GenerationPhase::Active);
                        running.order_plain(&request.candidate);
                        rollback=None;
                        runtime.set_rollback_until(None);
                        if structural || root_changed{
                            structural_rollback=None;runtime.set_restart_rollback(None);
                        }else{
                            let now=Instant::now();
                            let ready_at=if plan.removed.is_empty(){now}else{now+GENERATION_DRAIN+Duration::from_secs(2)};
                            let expires=now+Duration::from_secs(300);
                            structural_rollback=Some(StructuralRollbackSlot{document:request.previous.document.clone(),identities:identities.clone(),revision,ready_at,expires});
                            runtime.set_restart_rollback(Some((revision,ready_at,expires)));
                        }
                        identities=next_ids;
                        let _=request.complete.send(Ok(revision));
                        continue;
                    }
                }
                let staged = stage_fresh_generation(
                    &request,
                    &identities,
                    &limits,
                    config_path,
                )
                .await;
                let Ok((next_running,next_view,next_identities,next_reality,revision))=staged else {
                    let _ = request.complete.send(Err(()));
                    continue;
                };
                // Under the same short CAS barrier used for auth-only Apply:
                // stale revisions cannot overwrite either generation.
                if request.complete.is_closed() {
                    continue;
                }
                if root_history.advance(&request.candidate).is_err() {
                    if root_history.pending() { return Err(ServerError::Io); }
                    let _=request.complete.send(Err(()));continue;
                }
                let root_changed=root_history.retiring();
                if runtime.commit_restart_with_reality(
                    &request.previous,
                    request.expected_revision,
                    next_view,next_reality,
                ).is_err() {
                    if root_history.pending() { return Err(ServerError::Io); }
                    let _ = request.complete.send(Err(()));
                    continue;
                }
                root_history.committed();
                next_running.start();
                let previous=std::mem::replace(&mut running,next_running);
                // No key or health rollback: previous own-TLS PEM digest
                // must still match, REALITY reopens its CURRENT rooted
                // publication and floor when the operator confirms.
                // An independent root replacement on the same logical endpoint
                // is not a reversible listener operation. Never offer its old root
                // as a structural rollback target.
                if structural || root_changed{
                    structural_rollback=None;
                    runtime.set_restart_rollback(None);
                }else{
                    let now=Instant::now();
                    let ready_at=now+GENERATION_DRAIN+Duration::from_secs(2);
                    let expires=now+Duration::from_secs(300);
                    structural_rollback=Some(StructuralRollbackSlot{
                        document:request.previous.document.clone(),identities:identities.clone(),
                        revision,ready_at,expires,
                    });
                    runtime.set_restart_rollback(Some((revision,ready_at,expires)));
                }
                identities=next_identities;
                rollback=None;
                runtime.set_rollback_until(None);
                retiring = Some(SupervisorTask(tokio::spawn(reap_previous(previous))));
                // This ACK is AFTER commit. Lost ACK is indeterminate:
                // operator must query status; never retry blindly.
                let _ = request.complete.send(Ok(revision));
            }
            _ = async {
                if let Some(slot) = &rollback {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(slot.expires)).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                rollback = None;
                runtime.set_rollback_until(None);
            }
            _=async{
                if let Some(slot)=&structural_rollback{
                    tokio::time::sleep_until(tokio::time::Instant::from_std(slot.expires)).await;
                }else{std::future::pending::<()>().await;}
            }=>{
                structural_rollback=None;
                runtime.set_restart_rollback(None);
            }
            result = running.tasks.join_next() => {
                // An unexpected H2/H3 accept-loop exit is fatal, not a
                // misleading healthy status from the management endpoint.
                match result{
                    Some(Ok((id,Ok(())))) if running.finish_draining(&id)=>continue,
                    Some(Ok((_,Err(error))))=>return Err(error),
                    _=>return Err(ServerError::Io),
                }
            }
            result = async {
                match &mut management_task {
                    Some(task) => Some((&mut task.0).await),
                    None => std::future::pending().await,
                }
            } => {
                let _ = result;
                return Err(ServerError::Io);
            }
        }
    }
}

fn has_reality(document: &ServerDocument) -> bool {
    document.server.inbounds.iter().any(|i| {
        i.security_mode == crate::security_profile::SecurityMode::SmartReality
            || i.reality.is_some()
    })
}

/// Prepare every inbound before accepting any traffic. REALITY material is
/// captured once for both transports, and every inbound shares accounting.
/// The current REALITY generation is immutable; ordinary own-TLS hot
/// replacement cannot mutate it. Management is status-only in this mode.
#[cfg(all(test, not(any(target_os = "linux", target_os = "windows"))))]
pub(crate) async fn run_reality_document_with_ready(
    document: ServerDocument,
    started: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<(), ServerError> {
    run_reality_document_inner(document, started, None).await
}

async fn run_reality_document_inner(
    document: ServerDocument,
    started: Option<tokio::sync::oneshot::Sender<()>>,
    config_path: Option<&Path>,
) -> Result<(), ServerError> {
    let config = Config::Server(document.clone());
    config.validate().map_err(|_| ServerError::Config)?;
    if !document.server.enabled {
        return Err(ServerError::Config);
    }
    let live = Arc::new(LiveAuthorization::new(document.clone()).map_err(|_| ServerError::Config)?);
    let policy = &document.server.policy;
    let ledger = crate::quota::Ledger::new(policy, &document.server.users);
    let global = Arc::new(Semaphore::new(policy.max_connections_total as usize));
    let connections = Arc::new(Semaphore::new(policy.max_connections_total as usize));
    let peers = Arc::new(PeerBudget::default());
    let users = Arc::new(
        document
            .server
            .users
            .iter()
            .map(|user| {
                (
                    user.id.clone(),
                    Arc::new(Semaphore::new(policy.max_connections_per_user as usize)),
                )
            })
            .collect::<HashMap<_, _>>(),
    );
    enum Ready {
        Plain(
            TcpListener,
            TlsAcceptor,
            crate::h3_server::OwnTlsEndpoint,
            Arc<ServerContext>,
        ),
        Reality(
            crate::reality_tcp::PreparedTcp,
            Option<crate::reality_quic::PreparedQuic>,
            Option<tokio::net::UdpSocket>,
            Box<crate::reality_generation::Manager>,
            Arc<crate::reality_live::Live>,
        ),
    }
    let mut ready = Vec::with_capacity(document.server.inbounds.len());
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let mut loaded_identities = Vec::new();
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let mut reality_status = HashMap::new();
    for inbound in &document.server.inbounds {
        let tcp_addr: SocketAddr = inbound.h2_listen.parse().map_err(|_| ServerError::Config)?;
        let udp_addr: SocketAddr = inbound
            .quic_listen
            .parse()
            .map_err(|_| ServerError::Config)?;
        let listener = crate::tcp_bbr::bind(tcp_addr).map_err(|error| match error {
            crate::tcp_bbr::Error::Network => ServerError::Io,
            crate::tcp_bbr::Error::Unavailable => ServerError::TcpControllerUnavailable,
        })?;
        let mut context = ServerContext::with_limits(
            inbound,
            policy,
            live.shared(),
            global.clone(),
            users.clone(),
            connections.clone(),
            peers.clone(),
        );
        context.routing_publication()?;
        context.live_quota = Some(ledger.clone());
        context.apply_own_tls_policy();
        if inbound.security_mode == crate::security_profile::SecurityMode::SmartReality {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            loaded_identities.push(crate::reload_preflight::IdentityHash::reality(
                inbound.reality.as_ref().ok_or(ServerError::Config)?,
            ));
            let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
            let manager = crate::reality_generation::Manager::new_live(&config, &inbound.id, now)
                .await
                .map_err(|_| ServerError::Config)?;
            let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
            let generation = Arc::new(manager.refresh(now).map_err(|_| ServerError::Config)?);
            let h3 = generation.publication().active().verified().descriptor().h3;
            #[cfg(test)]
            let live_generation = if started.is_some() {
                crate::reality_live::Live::with_guard_start(
                    generation,
                    Arc::new(context),
                    now,
                    now.saturating_sub(121),
                )?
            } else {
                crate::reality_live::Live::new(generation, Arc::new(context), now)?
            };
            #[cfg(not(test))]
            let live_generation =
                crate::reality_live::Live::new(generation, Arc::new(context), now)?;
            let tcp =
                crate::reality_tcp::PreparedTcp::from_live(listener, live_generation.clone())?;
            let udp = crate::routing::carrier_socket::bind_plain_udp(udp_addr)
                .await
                .map_err(|_| ServerError::Io)?;
            let (quic, silent) = if h3 {
                (
                    Some(crate::reality_quic::PreparedQuic::from_live(
                        udp,
                        live_generation.clone(),
                    )?),
                    None,
                )
            } else {
                // Keep the approved UDP port reserved; no H3 advertisement,
                // no TLS response and no speculative reference forwarding.
                (None, Some(udp))
            };
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            reality_status.insert(
                inbound.id.clone(),
                (
                    inbound
                        .reality
                        .as_ref()
                        .ok_or(ServerError::Config)?
                        .manifest_sha256,
                    live_generation.clone(),
                ),
            );
            ready.push(Ready::Reality(
                tcp,
                quic,
                silent,
                Box::new(manager),
                live_generation,
            ));
        } else {
            let material = tls_material(inbound)?;
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            loaded_identities.push(material.identity.clone());
            let acceptor = tls_acceptor(material.certs.clone(), material.key.clone_key())?;
            let endpoint = crate::h3_server::OwnTlsConfig::new(material.certs, material.key)
                .and_then(|tls| crate::h3_server::OwnTlsEndpoint::bind(udp_addr, tls))
                .map_err(|_| ServerError::Tls)?;
            ready.push(Ready::Plain(
                listener,
                acceptor,
                endpoint,
                Arc::new(context),
            ));
        }
    }
    // Same protected native CAS interface, but only auth-only mutations
    // until a structural REALITY cutover can be fully staged.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let runtime = config_path.map(|path| {
        Arc::new(
            crate::runtime_generation::State::new(crate::runtime_generation::View {
                document: Arc::new(document.clone()),
                inbounds: ready.len(),
                preflight: Arc::new(crate::reload_preflight::ReloadPreflight::new(
                    path.to_owned(),
                    document.clone(),
                    loaded_identities,
                )),
                live: live.clone(),
            })
            .with_reality(reality_status)
            .with_reality_ledger(ledger.clone()),
        )
    });
    #[cfg(target_os = "linux")]
    let management = crate::management::StatusServer::from_environment(ready.len())
        .map_err(|_| ServerError::Io)?
        .map(|server| {
            if let Some(runtime) = runtime {
                server.with_runtime(runtime)
            } else {
                server
            }
        });
    #[cfg(target_os = "windows")]
    let management = crate::windows_control::WindowsServer::from_environment(ready.len())
        .map_err(|_| ServerError::Io)?
        .map(|server| {
            if let Some(runtime) = runtime {
                server.with_runtime(runtime)
            } else {
                server
            }
        });
    let mut tasks = JoinSet::new();
    let mut silent_sockets = Vec::new();
    for item in ready {
        match item {
            Ready::Plain(listener, acceptor, endpoint, context) => {
                tasks.spawn(serve(listener, acceptor, context.clone()));
                tasks.spawn(endpoint.serve(context));
            }
            Ready::Reality(tcp, quic, silent, manager, live_generation) => {
                tasks.spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        match manager.maintain(&live_generation).await {
                            Ok(lease) => {
                                let Ok(now) = crate::reference_health::unix_now() else {
                                    live_generation.suspend();
                                    continue;
                                };
                                if live_generation.publish(Arc::new(lease), now).is_err() {
                                    live_generation.suspend();
                                }
                            }
                            Err(_) => live_generation.suspend(),
                        }
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), ServerError>(())
                });
                tasks.spawn(tcp.serve());
                if let Some(quic) = quic {
                    tasks.spawn(quic.serve());
                }
                if let Some(socket) = silent {
                    silent_sockets.push(socket);
                }
            }
        }
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    if let Some(management) = management {
        tasks.spawn(async move { management.serve().await.map_err(|_| ServerError::Io) });
    }
    if let Some(started) = started {
        let _ = started.send(());
    }
    let result = match tasks.join_next().await {
        Some(Ok(result)) => result,
        _ => Err(ServerError::Io),
    };
    drop(silent_sockets);
    result
}

pub async fn run_document(document: ServerDocument) -> Result<(), ServerError> {
    run_document_with_config(document, None).await
}

async fn run_document_with_config(
    document: ServerDocument,
    config_path: Option<&Path>,
) -> Result<(), ServerError> {
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let _ = config_path;
    if has_reality(&document) {
        return run_reality_document_inner(document, None, config_path).await;
    }
    if !document.server.enabled {
        return Err(ServerError::Config);
    }
    // One shared authorization snapshot for every H2/H3 inbound.
    // Explicit CAS Apply is accessible only via secured local IPC.
    let live_authorization =
        Arc::new(LiveAuthorization::new(document.clone()).map_err(|_| ServerError::Config)?);
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let baseline = document.clone();
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let mut loaded_identities = Vec::new();
    let policy = document.server.policy;
    let peer_budget = Arc::new(PeerBudget::default());
    let global = Arc::new(Semaphore::new(policy.max_connections_total as usize));
    let connections = Arc::new(Semaphore::new(policy.max_connections_total as usize));
    let per_user: Arc<HashMap<_, _>> = Arc::new(
        document
            .server
            .users
            .iter()
            .map(|u| {
                (
                    u.id.clone(),
                    Arc::new(Semaphore::new(policy.max_connections_per_user as usize)),
                )
            })
            .collect(),
    );
    let mut prepared = Vec::new();
    for inbound in &document.server.inbounds {
        let addr: SocketAddr = inbound.h2_listen.parse().map_err(|_| ServerError::Config)?;
        let udp_addr: SocketAddr = inbound
            .quic_listen
            .parse()
            .map_err(|_| ServerError::Config)?;
        let material = tls_material(inbound)?;
        crate::diag!(
            Debug,
            "server",
            "listener_prepare",
            "h2_port" = Value::Count(u64::from(addr.port())),
            "h3_port" = Value::Count(u64::from(udp_addr.port()))
        );
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        loaded_identities.push(material.identity.clone());
        let acceptor = tls_acceptor(material.certs.clone(), material.key.clone_key())?;
        let listener = crate::tcp_bbr::bind(addr).map_err(|error| match error {
            crate::tcp_bbr::Error::Network => ServerError::Io,
            crate::tcp_bbr::Error::Unavailable => ServerError::TcpControllerUnavailable,
        })?;
        let endpoint = crate::h3_server::OwnTlsConfig::new(material.certs, material.key)
            .and_then(|tls| crate::h3_server::OwnTlsEndpoint::bind(udp_addr, tls))
            .map_err(|error| match error {
                crate::quic_transport::QuicError::Bind => ServerError::Io,
                _ => ServerError::Tls,
            })?;
        let mut context = ServerContext::with_limits(
            inbound,
            &policy,
            live_authorization.shared(),
            global.clone(),
            per_user.clone(),
            connections.clone(),
            peer_budget.clone(),
        );
        context.routing_publication()?;
        context.apply_own_tls_policy();
        prepared.push((listener, acceptor, endpoint, Arc::new(context)));
    }
    // Both platforms require explicit private local IPC opt-in. Advertise
    // status only AFTER all TCP/UDP listeners and TLS have been prepared.
    #[cfg(target_os = "linux")]
    let management = crate::management::StatusServer::from_environment(prepared.len())
        .map_err(|_| ServerError::Io)?
        .map(|server| {
            if let Some(path) = config_path {
                server
                    .with_preflight(Arc::new(crate::reload_preflight::ReloadPreflight::new(
                        path.to_owned(),
                        baseline,
                        loaded_identities,
                    )))
                    .with_live_authorization(live_authorization.clone())
            } else {
                server
            }
        });

    #[cfg(target_os = "windows")]
    let windows_management =
        crate::windows_control::WindowsServer::from_environment(prepared.len())
            .map_err(|_| ServerError::Io)?
            .map(|server| {
                if let Some(path) = config_path {
                    server
                        .with_preflight(Arc::new(crate::reload_preflight::ReloadPreflight::new(
                            path.to_owned(),
                            baseline,
                            loaded_identities,
                        )))
                        .with_live_authorization(live_authorization.clone())
                } else {
                    server
                }
            });

    let mut tasks = JoinSet::new();
    for (listener, acceptor, endpoint, context) in prepared {
        tasks.spawn(serve(listener, acceptor, context.clone()));
        tasks.spawn(endpoint.serve(context));
    }
    #[cfg(target_os = "linux")]
    if let Some(management) = management {
        tasks.spawn(async move { management.serve().await.map_err(|_| ServerError::Io) });
    }
    #[cfg(target_os = "windows")]
    if let Some(management) = windows_management {
        tasks.spawn(async move { management.serve().await.map_err(|_| ServerError::Io) });
    }
    match tasks.join_next().await {
        Some(Ok(result)) => result,
        _ => Err(ServerError::Io),
    }
}

async fn relay_udp(
    socket: tokio::net::UdpSocket,
    incoming: &mut h2::RecvStream,
    outgoing: &mut h2::SendStream<Bytes>,
    mut decoder: IncomingFrames,
    state: Session,
) -> Result<(), ServerError> {
    let traffic = crate::traffic::enter_udp(crate::Role::Server, false, false);
    let mut rx_state = state.clone();
    let mut tx_state = state;
    let activity = crate::udp_relay::Activity::new();
    let writing = std::sync::atomic::AtomicBool::new(false);
    let upload = async {
        loop {
            let frame = decoder.next(incoming).await?.ok_or(ServerError::Protocol)?;
            rx_state
                .apply(Direction::Receive, &frame)
                .map_err(|_| ServerError::Protocol)?;
            match frame {
                Frame::Datagram(data) => {
                    crate::udp_relay::send_datagram(&socket, &data)
                        .await
                        .map_err(|_| ServerError::Io)?;
                    traffic.upload(data.len());
                    activity.touch();
                }
                Frame::Padding(_) => tokio::task::yield_now().await,
                Frame::Fin => return Ok::<(), ServerError>(()),
                _ => return Err(ServerError::Protocol),
            }
        }
    };
    let download = async {
        let mut buf = vec![0; crate::protocol::MAX_DATAGRAM + 1];
        loop {
            let n = socket.recv(&mut buf).await.map_err(|_| ServerError::Io)?;
            if n > crate::protocol::MAX_DATAGRAM {
                continue;
            }
            let frame = Frame::Datagram(buf[..n].to_vec());
            tx_state
                .apply(Direction::Send, &frame)
                .map_err(|_| ServerError::Protocol)?;
            writing.store(true, std::sync::atomic::Ordering::Relaxed);
            timeout(FRAME_IDLE_TIMEOUT, send_frame(outgoing, &frame))
                .await
                .map_err(|_| ServerError::TimedOut)??;
            writing.store(false, std::sync::atomic::Ordering::Relaxed);
            traffic.download(n);
            activity.touch();
        }
        #[allow(unreachable_code)]
        Ok::<(), ServerError>(())
    };
    // UDP FIN terminates the association (no TCP-style half close).
    let result = tokio::select! { result=upload=>result, result=download=>result, ()=activity.expire()=>Ok(()) };
    if writing.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(ServerError::TimedOut);
    }
    result?;
    let frame = Frame::Fin;
    tx_state
        .apply(Direction::Send, &frame)
        .map_err(|_| ServerError::Protocol)?;
    timeout(FRAME_IDLE_TIMEOUT, send_frame(outgoing, &frame))
        .await
        .map_err(|_| ServerError::TimedOut)??;
    Ok(())
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test]
    async fn tui_server_owns_startup_and_releases_listeners_on_confirmed_stop() {
        use std::fs;
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let directory =
            std::env::temp_dir().join(crate::tui_editor::generated_id("tui-server").unwrap());
        fs::create_dir(&directory).unwrap();
        let _cleanup = Cleanup(directory.clone());
        let path = directory.join("server.toml");
        let cert = directory.join("cert.pem");
        let key = directory.join("key.pem");
        let material = rcgen::generate_simple_self_signed(vec!["a.example.org".into()]).unwrap();
        fs::write(&cert, material.cert.pem()).unwrap();
        #[cfg(not(windows))]
        fs::write(&key, material.key_pair.serialize_pem()).unwrap();
        #[cfg(windows)]
        crate::bounded_input::write_test_private(&key, material.key_pair.serialize_pem());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let mut document = live_auth_fixture();
        document.server.inbounds.truncate(1);
        let inbound = &mut document.server.inbounds[0];
        inbound.h2_listen = tcp_addr.to_string();
        inbound.quic_listen = udp_addr.to_string();
        inbound.tls_cert = format!("file:{}", cert.display());
        inbound.tls_key = format!("file:{}", key.display());
        let contents = Config::Server(document).to_toml().unwrap();
        fs::write(&path, &contents).unwrap();
        let expected: [u8; 32] = Sha256::digest(contents.as_bytes()).into();
        let (bad_ready, _) = tokio::sync::oneshot::channel();
        let (_bad_stop, bad_rx) = tokio::sync::oneshot::channel();
        assert!(matches!(
            run_tui_file(&path, [0; 32], bad_ready, bad_rx, None).await,
            Err(ServerError::Config)
        ));
        drop(tcp);
        drop(udp);
        let (ready, ready_rx) = tokio::sync::oneshot::channel();
        let (stop, stop_rx) = tokio::sync::oneshot::channel();
        let run_path = path.clone();
        #[cfg(target_os = "linux")]
        let endpoint = {
            use std::os::unix::fs::DirBuilderExt;
            let endpoint = directory.join("ipc");
            fs::DirBuilder::new().mode(0o700).create(&endpoint).unwrap();
            endpoint
        };
        #[cfg(target_os = "windows")]
        let endpoint =
            std::path::PathBuf::from(crate::tui_editor::generated_id("tui-ipc").unwrap());
        let run_endpoint = endpoint.clone();
        let task = tokio::spawn(async move {
            run_tui_file(&run_path, expected, ready, stop_rx, Some(run_endpoint)).await
        });
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(10), ready_rx)
                .await
                .unwrap()
                .unwrap(),
            1
        );
        assert!(std::net::TcpListener::bind(tcp_addr).is_err());
        assert!(std::net::UdpSocket::bind(udp_addr).is_err());
        use crate::management::{StatusCommand, StatusReply};
        let status = crate::tui_runtime::query_endpoint(&endpoint, StatusCommand::Status)
            .await
            .unwrap();
        assert!(matches!(
            status,
            StatusReply::RunningRevision { inbounds: 1, .. }
        ));
        // Drive the actual protected management endpoint while the same
        // supervisor owns the listeners. Read-only preflights never change
        // the revision, and mutations require both the saved digest and CAS.
        let Config::Server(mut candidate) = config::parse(&contents).unwrap() else {
            panic!("server fixture");
        };
        let save = |doc: &ServerDocument| {
            let bytes = Config::Server(doc.clone()).to_toml().unwrap();
            fs::write(&path, bytes.as_bytes()).unwrap();
            <[u8; 32]>::from(Sha256::digest(bytes.as_bytes()))
        };
        let query = |command| crate::tui_runtime::query_endpoint(&endpoint, command);
        let access = |user: &str, digest| {
            let mut inbound = [0; 64];
            inbound[..6].copy_from_slice(b"edge-a");
            let mut name = [0; 64];
            name[..user.len()].copy_from_slice(user.as_bytes());
            StatusCommand::AccessStatus {
                inbound,
                user: name,
                saved_sha256: digest,
            }
        };
        assert_eq!(
            query(access("alice", expected)).await.unwrap(),
            StatusReply::AccessObserved {
                revision: 1,
                state: 3
            }
        );
        assert_eq!(
            query(access("bob", expected)).await.unwrap(),
            StatusReply::AccessObserved {
                revision: 1,
                state: 1
            }
        );
        assert!(query(access("alice", [0; 32])).await.is_err());
        assert_eq!(
            query(StatusCommand::CheckReload).await.unwrap(),
            StatusReply::Compatible
        );
        assert!(query(StatusCommand::CheckTlsRollback).await.is_err());
        assert!(query(StatusCommand::CheckRestartRollback).await.is_err());
        assert!(query(StatusCommand::CheckAuthRollback).await.is_err());
        candidate.server.policy.max_connections_total += 1;
        let digest = save(&candidate);
        assert_eq!(
            query(StatusCommand::CheckQuota).await.unwrap(),
            StatusReply::QuotaReady
        );
        assert!(query(StatusCommand::ApplyQuotaBound {
            expected_revision: 1,
            candidate_sha256: [0; 32]
        })
        .await
        .is_err());
        assert!(query(StatusCommand::ApplyQuotaBound {
            expected_revision: 2,
            candidate_sha256: digest
        })
        .await
        .is_err());
        assert_eq!(
            query(StatusCommand::ApplyQuotaBound {
                expected_revision: 1,
                candidate_sha256: digest
            })
            .await
            .unwrap(),
            StatusReply::QuotaApplied { revision: 2 }
        );
        assert!(query(StatusCommand::ApplyQuotaBound {
            expected_revision: 1,
            candidate_sha256: digest
        })
        .await
        .is_err());

        let enabled = candidate.clone();
        candidate
            .server
            .users
            .iter_mut()
            .find(|user| user.id == "alice")
            .unwrap()
            .disabled = true;
        let digest = save(&candidate);
        assert_eq!(
            query(StatusCommand::CheckReload).await.unwrap(),
            StatusReply::Compatible
        );
        assert_eq!(
            query(access("alice", digest)).await.unwrap(),
            StatusReply::AccessObserved {
                revision: 2,
                state: 3
            }
        );
        assert!(query(StatusCommand::ApplyReloadBound {
            expected_revision: 2,
            candidate_sha256: [0; 32]
        })
        .await
        .is_err());
        assert_eq!(
            query(StatusCommand::ApplyReloadBound {
                expected_revision: 2,
                candidate_sha256: digest
            })
            .await
            .unwrap(),
            StatusReply::Applied { revision: 3 }
        );
        assert_eq!(
            query(access("alice", digest)).await.unwrap(),
            StatusReply::AccessObserved {
                revision: 3,
                state: 2
            }
        );
        // Own-TLS-only deployments do not publish a REALITY auth rollback
        // slot. Restoration is a new explicit, saved and CAS-bound reload.
        assert!(query(StatusCommand::CheckAuthRollback).await.is_err());
        assert!(query(StatusCommand::ApplyAuthRollback {
            expected_revision: 2
        })
        .await
        .is_err());
        assert!(query(StatusCommand::ApplyAuthRollback {
            expected_revision: 3
        })
        .await
        .is_err());
        assert_eq!(
            query(access("alice", digest)).await.unwrap(),
            StatusReply::AccessObserved {
                revision: 3,
                state: 2
            }
        );
        candidate = enabled;
        let digest = save(&candidate);
        assert_eq!(
            query(StatusCommand::CheckReload).await.unwrap(),
            StatusReply::Compatible
        );
        assert!(query(StatusCommand::ApplyReloadBound {
            expected_revision: 2,
            candidate_sha256: digest
        })
        .await
        .is_err());
        assert_eq!(
            query(StatusCommand::ApplyReloadBound {
                expected_revision: 3,
                candidate_sha256: digest
            })
            .await
            .unwrap(),
            StatusReply::Applied { revision: 4 }
        );
        assert_eq!(
            query(access("alice", digest)).await.unwrap(),
            StatusReply::AccessObserved {
                revision: 4,
                state: 3
            }
        );

        let next_material =
            rcgen::generate_simple_self_signed(vec!["a.example.org".into()]).unwrap();
        let next_cert = directory.join("next-cert.pem");
        let next_key = directory.join("next-key.pem");
        fs::write(&next_cert, next_material.cert.pem()).unwrap();
        #[cfg(not(windows))]
        fs::write(&next_key, next_material.key_pair.serialize_pem()).unwrap();
        #[cfg(windows)]
        crate::bounded_input::write_test_private(&next_key, next_material.key_pair.serialize_pem());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&next_key, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let before_rotation = candidate.clone();
        candidate.server.inbounds[0].tls_cert = format!("file:{}", next_cert.display());
        candidate.server.inbounds[0].tls_key = format!("file:{}", next_key.display());
        let digest = save(&candidate);
        assert_eq!(
            query(StatusCommand::CheckRestart).await.unwrap(),
            StatusReply::RestartSamePortTlsReady
        );
        assert!(query(StatusCommand::CheckRestartBound {
            expected_revision: 3,
            candidate_sha256: digest
        })
        .await
        .is_err());
        let StatusReply::RestartPreview {
            same_port: true,
            material_sha256,
        } = query(StatusCommand::CheckRestartBound {
            expected_revision: 4,
            candidate_sha256: digest,
        })
        .await
        .unwrap()
        else {
            panic!("same-port preview");
        };
        assert!(query(StatusCommand::ApplyRestartBound {
            expected_revision: 4,
            candidate_sha256: digest,
            tls_sha256: [0; 32]
        })
        .await
        .is_err());
        assert_eq!(
            query(StatusCommand::ApplyRestartBound {
                expected_revision: 4,
                candidate_sha256: digest,
                tls_sha256: material_sha256
            })
            .await
            .unwrap(),
            StatusReply::RestartApplied { revision: 5 }
        );
        assert!(matches!(
            query(StatusCommand::CheckTlsRollback).await.unwrap(),
            StatusReply::TlsRollbackReady { revision: 5, .. }
        ));
        assert!(query(StatusCommand::ApplyTlsRollback {
            expected_revision: 4
        })
        .await
        .is_err());
        assert_eq!(
            query(StatusCommand::ApplyTlsRollback {
                expected_revision: 5
            })
            .await
            .unwrap(),
            StatusReply::TlsRollbackApplied { revision: 6 }
        );
        assert!(query(StatusCommand::ApplyTlsRollback {
            expected_revision: 5
        })
        .await
        .is_err());

        // A partial layout adds an independent listener pair and preserves
        // the old pair. Its one-shot structural rollback retires only that
        // pair; neither operation mutates the saved candidate.
        candidate = before_rotation;
        let mut extra = candidate.server.inbounds[0].clone();
        extra.id = "edge-c".into();
        let new_tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let new_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let extra_tcp = new_tcp.local_addr().unwrap();
        let extra_udp = new_udp.local_addr().unwrap();
        extra.h2_listen = extra_tcp.to_string();
        extra.quic_listen = extra_udp.to_string();
        candidate.server.inbounds.push(extra);
        let digest = save(&candidate);
        assert!(query(StatusCommand::CheckRestartBound {
            expected_revision: 6,
            candidate_sha256: digest
        })
        .await
        .is_err());
        drop((new_tcp, new_udp));
        let StatusReply::RestartPreview {
            same_port: false,
            material_sha256,
        } = query(StatusCommand::CheckRestartBound {
            expected_revision: 6,
            candidate_sha256: digest,
        })
        .await
        .unwrap()
        else {
            panic!("partial restart preview");
        };
        assert_eq!(
            query(StatusCommand::ApplyRestartBound {
                expected_revision: 6,
                candidate_sha256: digest,
                tls_sha256: material_sha256
            })
            .await
            .unwrap(),
            StatusReply::RestartApplied { revision: 7 }
        );
        assert_eq!(
            query(StatusCommand::Status).await.unwrap(),
            StatusReply::RunningRevision {
                inbounds: 2,
                revision: 7
            }
        );
        assert!(std::net::TcpListener::bind(extra_tcp).is_err());
        assert!(std::net::UdpSocket::bind(extra_udp).is_err());
        assert!(matches!(
            query(StatusCommand::CheckRestartRollback).await.unwrap(),
            StatusReply::RestartRollbackReady { revision: 7, .. }
        ));
        assert!(query(StatusCommand::ApplyRestartRollback {
            expected_revision: 6
        })
        .await
        .is_err());
        assert_eq!(
            query(StatusCommand::ApplyRestartRollback {
                expected_revision: 7
            })
            .await
            .unwrap(),
            StatusReply::RestartRollbackApplied { revision: 8 }
        );
        assert_eq!(
            query(StatusCommand::Status).await.unwrap(),
            StatusReply::RunningRevision {
                inbounds: 1,
                revision: 8
            }
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(fs::read(&path).unwrap())),
            digest
        );
        fs::write(&path, &contents).unwrap();
        stop.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(std::net::TcpListener::bind(tcp_addr).is_ok());
        assert!(std::net::UdpSocket::bind(udp_addr).is_ok());
        assert!(
            crate::tui_runtime::query_endpoint(&endpoint, StatusCommand::Status)
                .await
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), contents.as_bytes());
    }

    #[test]
    fn pem_reader_refuses_oversized_and_relative_inputs() {
        use std::fs;

        let name = format!("theia-pem-input-{}", std::process::id());
        let path = std::env::temp_dir().join(name);
        fs::write(&path, vec![b'x'; MAX_PEM_BYTES as usize + 1]).unwrap();
        let reference = format!("file:{}", path.display());
        assert!(pem_data(&reference, false).is_err());
        assert!(pem_data("file:relative-key.pem", true).is_err());
        fs::write(&path, b"public fixture").unwrap();
        let bytes = pem_data(&reference, false).unwrap();
        assert_eq!(bytes.as_slice(), b"public fixture");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn peer_budget_is_bounded_and_ipv4_mapped_shares_quota() {
        let budget = PeerBudget::default();
        let now = Instant::now();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        for _ in 0..AUTH_ATTEMPTS {
            assert!(budget.admit(ip, now));
        }
        assert!(!budget.admit(mapped, now));
        assert!(budget.admit(mapped, now + AUTH_WINDOW));
        for n in 1..MAX_TRACKED_PEERS {
            let peer = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, (n >> 8) as u8, n as u8));
            assert!(budget.admit(peer, now));
        }
        let other = "192.0.2.1".parse().unwrap();
        assert!(!budget.admit(other, now));
        assert_eq!(budget.peers.lock().unwrap().len(), MAX_TRACKED_PEERS);
        assert!(budget.admit(other, now + AUTH_WINDOW));
    }

    #[test]
    fn dns_candidate_filter_pins_public_ips_and_caps_results() {
        let mixed: Vec<SocketAddr> = [
            "127.0.0.1:443",
            "8.8.8.8:443",
            "8.8.8.8:443",
            "[::ffff:169.254.169.254]:443",
            "[2002:7f00:1::]:443",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        assert_eq!(
            permitted_candidates(mixed, false).unwrap(),
            vec!["8.8.8.8:443".parse().unwrap()]
        );
        let denied = vec!["127.0.0.1:443".parse().unwrap()];
        assert_eq!(
            permitted_candidates(denied, false),
            Err(ErrorCode::PolicyDenied)
        );
        let many = vec!["8.8.8.8:443".parse().unwrap(); MAX_DNS_RESULTS + 1];
        assert_eq!(
            permitted_candidates(many, false),
            Err(ErrorCode::ResourceLimit)
        );
    }

    #[tokio::test]
    async fn stalled_first_dns_candidate_does_not_starve_second() {
        let first: SocketAddr = "[::1]:443".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let result = dial_candidates(&[first, second], deadline, |candidate| async move {
            if candidate == first {
                std::future::pending::<std::io::Result<SocketAddr>>().await
            } else {
                Ok(candidate)
            }
        })
        .await;
        assert_eq!(result, Ok(second));
    }

    #[tokio::test]
    async fn generation_drain_observes_late_receivers_and_controller_loss() {
        let (owner, mut receiver) = watch::channel(GenerationPhase::Prepared);
        owner.send_replace(GenerationPhase::Active);
        assert!(!generation_draining(&receiver));
        owner.send_replace(GenerationPhase::Drain);
        let mut late = owner.subscribe();
        await_generation_drain(&mut receiver).await;
        await_generation_drain(&mut late).await;
        assert!(generation_draining(&receiver));
        assert!(generation_draining(&late));

        let (owner, mut receiver) = watch::channel(GenerationPhase::Active);
        drop(owner);
        await_generation_drain(&mut receiver).await;
        assert!(generation_draining(&receiver));
    }

    async fn production_listener_drain(h3: bool, split: bool) {
        let mut document = live_auth_fixture();
        document.server.policy.allow_private_ips = true;
        document.server.policy.max_connections_per_user = 4;
        document.server.policy.max_connections_total = 8;
        let mut context = ServerContext::new(
            &document.server.inbounds[0],
            &document.server.users,
            &document.server.policy,
        );
        context.apply_own_tls_policy();
        let context = Arc::new(context);
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = signed.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let (owner, phase) = watch::channel(GenerationPhase::Active);
        let (remote, server) = if h3 {
            let endpoint = crate::quic_transport::server_endpoint(
                "127.0.0.1:0".parse().unwrap(),
                vec![cert],
                key.into(),
            )
            .unwrap();
            let remote = endpoint.local_addr().unwrap();
            (
                remote,
                tokio::spawn(endpoint.serve_generation(context, phase)),
            )
        } else {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let remote = listener.local_addr().unwrap();
            let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key.into())
            .unwrap();
            tls.alpn_protocols = vec![b"h2".to_vec()];
            (
                remote,
                tokio::spawn(serve_generation(
                    listener,
                    TlsAcceptor::from(Arc::new(tls)),
                    context,
                    phase,
                )),
            )
        };
        let token = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let address = Address::V4([127, 0, 0, 1]);

        async fn exchange(app: &mut tokio::io::DuplexStream, data: &[u8]) {
            app.write_all(data).await.unwrap();
            let mut reply = vec![0; data.len()];
            app.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, data);
        }

        macro_rules! exercise {
            ($client:expr) => {{
                let client = $client
                    .with_own_tls_policy()
                    .unwrap()
                    .with_stream_up(split)
                    .unwrap()
                    .with_connection_pool();
                let tunnel = client.open(address.clone(), target_port).await.unwrap();
                let (mut upstream, _) = target.accept().await.unwrap();
                let echo = tokio::spawn(async move {
                    let (mut read, mut write) = upstream.split();
                    tokio::io::copy(&mut read, &mut write).await.unwrap();
                    write.shutdown().await.unwrap();
                });
                let (mut app, local) = tokio::io::duplex(4096);
                let relay = tokio::spawn(tunnel.relay(local));
                exchange(&mut app, b"before drain").await;
                owner.send_replace(GenerationPhase::Drain);
                exchange(&mut app, b"existing stream after drain").await;
                // Allow the native GOAWAY control exchange to be driven;
                // new admission must fail while the old tunnel still works.
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert!(client.open(address.clone(), target_port).await.is_err());
                assert!(timeout(Duration::from_millis(50), target.accept())
                    .await
                    .is_err());
                exchange(&mut app, b"existing stream after rejected admission").await;
                app.shutdown().await.unwrap();
                let mut tail = Vec::new();
                app.read_to_end(&mut tail).await.unwrap();
                assert!(tail.is_empty());
                relay.await.unwrap().unwrap();
                echo.await.unwrap();
                drop(client);
            }};
        }

        if h3 {
            exercise!(
                crate::h3_client::H3Client::new(remote, "localhost", &token, roots)
                    .unwrap()
                    .with_connect_timeout(Duration::from_millis(500))
                    .unwrap()
            );
        } else {
            exercise!(crate::client::H2Client::new(
                &remote.to_string(),
                "localhost",
                &token,
                roots
            )
            .unwrap());
        }
        server.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn production_generation_drain_preserves_admitted_h2_h3_tunnels() {
        timeout(Duration::from_secs(15), async {
            tokio::join!(
                production_listener_drain(false, false),
                production_listener_drain(false, true),
                production_listener_drain(true, false),
                production_listener_drain(true, true),
            );
        })
        .await
        .expect("bounded production drain matrix");
    }

    fn live_auth_fixture() -> ServerDocument {
        use crate::config::{Management, ServerSettings, Ui};
        let digest = |byte: u8| -> String {
            Sha256::digest([byte; 32])
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        ServerDocument {
            schema_version: 1,
            server: ServerSettings {
                enabled: true,
                inbounds: vec![
                    Inbound {
                        id: "edge-a".into(),
                        path_prefix: Some(crate::split_http::EXAMPLE_PREFIX.into()),
                        allowed_user_ids: vec!["alice".into()],
                        h2_listen: "127.0.0.1:9443".into(),
                        quic_listen: "127.0.0.1:9443".into(),
                        server_name: "a.example.org".into(),
                        tls_cert: "file:/tmp/theia-a.crt".into(),
                        security_mode: Default::default(),
                        reality: None,
                        tls_key: "file:/tmp/theia-a.key".into(),
                    },
                    Inbound {
                        id: "edge-b".into(),
                        path_prefix: Some(crate::split_http::EXAMPLE_PREFIX.into()),
                        allowed_user_ids: vec!["bob".into()],
                        h2_listen: "127.0.0.1:9444".into(),
                        quic_listen: "127.0.0.1:9444".into(),
                        server_name: "b.example.org".into(),
                        tls_cert: "file:/tmp/theia-b.crt".into(),
                        security_mode: Default::default(),
                        reality: None,
                        tls_key: "file:/tmp/theia-b.key".into(),
                    },
                ],
                users: vec![
                    User {
                        id: "alice".into(),
                        token_sha256: digest(7),
                        disabled: false,
                    },
                    User {
                        id: "bob".into(),
                        token_sha256: digest(9),
                        disabled: false,
                    },
                ],
                policy: ServerPolicy {
                    routing: None,
                    allow_private_ips: false,
                    max_connections_per_user: 1,
                    max_connections_total: 3,
                    connect_timeout_ms: 1000,
                },
            },
            management: Management {
                ipc: "auto".into(),
                log_level: "info".into(),
            },
            ui: Ui {
                language: "ru".into(),
            },
        }
    }

    fn live_auth_contexts(
        control: &crate::live_auth::LiveAuthorization,
        document: &ServerDocument,
    ) -> (ServerContext, ServerContext) {
        let policy = &document.server.policy;
        let total = Arc::new(Semaphore::new(policy.max_connections_total as usize));
        let users: Arc<HashMap<_, _>> = Arc::new(
            document
                .server
                .users
                .iter()
                .map(|u| {
                    (
                        u.id.clone(),
                        Arc::new(Semaphore::new(policy.max_connections_per_user as usize)),
                    )
                })
                .collect(),
        );
        let connections = Arc::new(Semaphore::new(policy.max_connections_total as usize));
        let budget = Arc::new(PeerBudget::default());
        let make = |inbound: &Inbound| {
            ServerContext::with_limits(
                inbound,
                policy,
                control.shared(),
                total.clone(),
                users.clone(),
                connections.clone(),
                budget.clone(),
            )
        };
        (
            make(&document.server.inbounds[0]),
            make(&document.server.inbounds[1]),
        )
    }

    fn live_bearer(byte: u8) -> String {
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([byte; 32]))
    }

    #[test]
    fn m4_2b1a_staged_auth_is_invisible_until_atomic_publish_to_all_inbounds() {
        use crate::live_auth::LiveAuthorization;
        let document = live_auth_fixture();
        let control = LiveAuthorization::new(document.clone()).unwrap();
        let (a, b) = live_auth_contexts(&control, &document);
        let old_alice = live_bearer(7);
        let rotated_alice = live_bearer(8);
        let bob = live_bearer(9);

        // The session already granted on edge-a must survive a future
        // credential revocation, without holding the auth snapshot lock.
        let existing = a.authorize(Some(&old_alice)).unwrap();
        let mut candidate = document.clone();
        candidate.server.users[0].token_sha256 = Sha256::digest([8u8; 32])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        candidate.server.inbounds[0].allowed_user_ids = vec!["bob".into()];
        candidate.server.inbounds[1].allowed_user_ids = vec!["alice".into()];
        let staged = control.stage(&candidate, 1).unwrap();
        assert_eq!(control.revision(), Ok(1));
        assert_eq!(a.authorize(Some(&bob)).err(), Some(AuthFailure::Forbidden));
        assert_eq!(
            b.authorize(Some(&rotated_alice)).err(),
            Some(AuthFailure::Unauthorized)
        );

        assert_eq!(control.publish(staged), Ok(2));
        assert_eq!(control.revision(), Ok(2));
        assert_eq!(
            a.authorize(Some(&old_alice)).err(),
            Some(AuthFailure::Unauthorized)
        );
        assert_eq!(b.authorize(Some(&bob)).err(), Some(AuthFailure::Forbidden));
        // New requests on BOTH listener contexts see one published snapshot.
        let bob_granted = a.authorize(Some(&bob)).unwrap();
        assert_eq!(
            b.authorize(Some(&rotated_alice)).err(),
            Some(AuthFailure::Busy),
            "prior Alice session keeps the same per-user quota occupied"
        );
        drop(existing);
        let alice_granted = b.authorize(Some(&rotated_alice)).unwrap();
        drop(bob_granted);
        drop(alice_granted);
    }

    #[test]
    fn m4_2b1a_failed_candidate_stale_cas_and_foreign_stage_never_change_revision() {
        use crate::live_auth::{LiveAuthError, LiveAuthorization};
        let document = live_auth_fixture();
        let control = LiveAuthorization::new(document.clone()).unwrap();
        let foreign = LiveAuthorization::new(document.clone()).unwrap();
        let (a, b) = live_auth_contexts(&control, &document);
        let mut invalid = document.clone();
        invalid.server.inbounds[0].allowed_user_ids = vec!["nonexistent".into()];
        assert!(matches!(
            control.stage(&invalid, 1),
            Err(LiveAuthError::InvalidCandidate)
        ));

        let mut incompatible = document.clone();
        incompatible.server.policy.max_connections_per_user = 2;
        assert!(matches!(
            control.stage(&incompatible, 1),
            Err(LiveAuthError::RequiresRestart)
        ));
        assert_eq!(control.revision(), Ok(1));

        let mut rotated = document.clone();
        rotated.server.users[1].disabled = true;
        let first = control.stage(&rotated, 1).unwrap();
        let second = control.stage(&rotated, 1).unwrap();
        let other = foreign.stage(&rotated, 1).unwrap();
        assert_eq!(control.publish(other), Err(LiveAuthError::ForeignStage));
        assert_eq!(control.revision(), Ok(1));
        assert_eq!(control.publish(first), Ok(2));
        assert_eq!(control.publish(second), Err(LiveAuthError::StaleRevision));
        assert!(matches!(
            control.stage(&document, 1),
            Err(LiveAuthError::StaleRevision)
        ));
        assert_eq!(control.revision(), Ok(2));
        assert!(a.authorize(Some(&live_bearer(7))).is_ok());
        assert_eq!(
            b.authorize(Some(&live_bearer(9))).err(),
            Some(AuthFailure::Forbidden)
        );
    }

    #[test]
    fn m4_2b1a_rotating_token_does_not_reset_per_user_quota_or_existing_permit() {
        use crate::live_auth::LiveAuthorization;
        let document = live_auth_fixture();
        let control = LiveAuthorization::new(document.clone()).unwrap();
        let (a, _) = live_auth_contexts(&control, &document);
        let existing = a.authorize(Some(&live_bearer(7))).unwrap();

        let mut candidate = document.clone();
        candidate.server.users[0].token_sha256 = Sha256::digest([8u8; 32])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let staged = control.stage(&candidate, 1).unwrap();
        assert_eq!(control.publish(staged), Ok(2));
        assert_eq!(
            a.authorize(Some(&live_bearer(8))).err(),
            Some(AuthFailure::Busy),
            "rotated credential must share existing user's permit quota"
        );
        drop(existing);
        assert!(a.authorize(Some(&live_bearer(8))).is_ok());
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn captured_pem_snapshot_survives_disk_replacement_without_tls_builder_reread() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let path = std::env::temp_dir().join(format!(
            "theia-tls-pin-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        let cert_path = path.join("cert.pem");
        let key_path = path.join("key.pem");
        let generated = rcgen::generate_simple_self_signed(vec![
            "a.example.org".into(),
            "b.example.org".into(),
        ])
        .unwrap();
        let cert_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(generated.cert.der())
        );
        let key_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(generated.key_pair.serialize_der())
        );
        std::fs::write(&cert_path, &cert_pem).unwrap();
        #[cfg(not(windows))]
        std::fs::write(&key_path, &key_pem).unwrap();
        #[cfg(windows)]
        crate::bounded_input::write_test_private(&key_path, &key_pem);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let mut doc = live_auth_fixture();
        for inbound in &mut doc.server.inbounds {
            inbound.tls_cert = format!("file:{}", cert_path.display());
            inbound.tls_key = format!("file:{}", key_path.display());
        }
        let captured = CapturedTls::capture(&doc).unwrap();
        let fingerprint = captured.fingerprint;
        assert!(captured.matches(&fingerprint));
        std::fs::write(&cert_path, "corrupted cert after snapshot").unwrap();
        std::fs::write(&key_path, "corrupted key after snapshot").unwrap();
        assert!(CapturedTls::capture(&doc).is_err());
        // Both real H2 and QUIC/BBR builders must still work exclusively
        // from the previously authorized private in-memory PEM snapshot.
        let prepared = prepare_same_port_tls(&doc, &captured).unwrap();
        assert_eq!(prepared.h2.len(), doc.server.inbounds.len());
        assert_eq!(prepared.h3.len(), doc.server.inbounds.len());
        assert!(prepared.identities == captured.identities());
        // Order of inbound identities is part of the cryptographic pin.
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        let mut reordered = doc.clone();
        reordered.server.inbounds.reverse();
        assert!(!CapturedTls::capture(&reordered)
            .unwrap()
            .matches(&fingerprint));
        std::fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn configured_name_must_match_certificate_san() {
        let cert = rcgen::generate_simple_self_signed(vec!["theia.example".into()]).unwrap();
        assert!(check_certificate_name(cert.cert.der(), "theia.example").is_ok());
        assert!(check_certificate_name(cert.cert.der(), "other.example").is_err());
    }

    /// Required native CI fixture: Python/OpenSSL+h2 and aioquic are
    /// independent implementations on both ends of the passive relay.
    /// No marker or bearer is supplied by the independent client.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "required independent reference CI installs pinned h2/aioquic"]
    async fn independent_external_reference_through_registered_reality_dispatchers() {
        use crate::reality_config::{self, Request, ServerRequest};
        use crate::reference_health::{Evidence, Plan, State, Store, Target};
        use std::{
            fs,
            path::PathBuf,
            process::{Child, Command},
            sync::atomic::{AtomicU64, Ordering},
        };
        struct Scratch(PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        struct Process(Child);
        impl Drop for Process {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let directory = Scratch(std::env::temp_dir().join(format!(
            "theia-independent-reference-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        )));
        fs::create_dir(&directory.0).unwrap();
        tokio::time::timeout(Duration::from_secs(45), async {
            let reservations = crate::shared_port::reserve_shared_port();
            let address = reservations.0.local_addr().unwrap();
            let now = crate::reference_health::unix_now().unwrap();
            let approved: SocketAddr = "93.184.216.2:443".parse().unwrap();
            let state = State::new(Plan {
                schema_version: 1,
                inbound: "independent-reference".into(),
                endpoint: address.to_string(),
                own_ips: vec![address.ip()],
                references: vec![Target {
                    server_name: "reference.example.org".into(), address: approved,
                }],
            }, vec![Evidence { h2_status: Some(200), h3_status: Some(200) }], now).unwrap();
            let health = directory.0.join("health.toml");
            Store::new(&health).unwrap().enroll(&state).unwrap();
            let bundle = directory.0.join("bundle");
            let digest = state.snapshot_sha256().unwrap();
            let record = crate::reality_provision::create(&state, digest, &bundle, now).unwrap();
            let config_path = directory.0.join("server.toml");
            fs::write(&config_path, include_str!("../../../examples/server.toml")
                .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64))).unwrap();
            let request = Request::Server(ServerRequest {
                health, bundle, health_sha256: digest,
                identity_sha256: record.identity_sha256, listen: address,
                grants: vec!["device-a".into()],
            });
            let preview = reality_config::prepare(&config_path, &request, now).unwrap();
            reality_config::apply(&config_path, &request, preview.approval_sha256(), now).unwrap();
            let Config::Server(mut document) = config::read_file(&config_path).unwrap() else { panic!() };
            document.server.inbounds.retain(|i| i.id == "independent-reference");
            let limits = GenerationLimits::new(&document);
            let auth = Arc::new(LiveAuthorization::new(document.clone()).unwrap());
            drop(reservations);
            let prepared = prepare_selected_listeners_inner(&document, &limits, None, auth, None, None)
                .await.unwrap();
            let cert = rcgen::generate_simple_self_signed(vec!["reference.example.org".into()]).unwrap();
            fs::write(directory.0.join("cert.pem"), cert.cert.pem()).unwrap();
            fs::write(directory.0.join("key.pem"), cert.key_pair.serialize_pem()).unwrap();
            let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/e2e/f18_independent_reference.py");
            let mut child = Process(Command::new("python")
                .arg(script).arg(&directory.0).arg(address.to_string()).spawn().unwrap());
            let ready = directory.0.join("reference-port");
            let fixture = loop {
                if let Ok(raw) = fs::read_to_string(&ready) {
                    let port = raw.trim().parse::<u16>().unwrap();
                    break SocketAddr::from(([127, 0, 0, 1], port));
                }
                assert!(child.0.try_wait().unwrap().is_none(), "independent reference exited before readiness");
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            let (_, carrier) = prepared.reality.get("independent-reference").unwrap();
            carrier.set_fixture_reference(approved, fixture);
            let mut running = RunningGeneration::launch(prepared.listeners, GenerationPhase::Active);
            fs::write(directory.0.join("relay-ready"), b"ready").unwrap();
            loop {
                if let Some(exit) = child.0.try_wait().unwrap() {
                    assert!(exit.success(), "independent direct/relay comparison failed");
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {},
                    result = running.tasks.join_next() => panic!("reference dispatcher exited: {result:?}"),
                }
            }
            let removed = document.server.inbounds.iter().map(|i| i.id.clone()).collect();
            running.remove_inbounds(&removed);
            while let Some(result) = running.tasks.join_next().await {
                let (id, result) = result.unwrap();
                result.unwrap();
                assert!(running.finish_draining(&id));
            }
            assert!(!running.has_draining());
        }).await.expect("bounded independent reference fixture");
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test]
    async fn supervisor_prepares_both_transports_rotates_rolls_back_and_cuts_over_shared_limits() {
        use crate::reload_preflight::ReloadPreflight;
        use crate::runtime_generation::{ChangeKind, RestartRequest, State, View};
        use std::{
            fs,
            net::{TcpListener as StdTcp, UdpSocket as StdUdp},
        };
        let directory = std::env::temp_dir().join(format!(
            "theia-supervisor-native-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&directory).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let path = directory.join("server.toml");
        let material = |name: &str| -> (String, String) {
            let generated = rcgen::generate_simple_self_signed(vec![
                "a.example.org".into(),
                "b.example.org".into(),
            ])
            .unwrap();
            let cert = directory.join(format!("{name}.pem"));
            let key = directory.join(format!("{name}.key"));
            fs::write(&cert, generated.cert.pem()).unwrap();
            #[cfg(not(windows))]
            fs::write(&key, generated.key_pair.serialize_pem()).unwrap();
            #[cfg(windows)]
            crate::bounded_input::write_test_private(&key, generated.key_pair.serialize_pem());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            }
            (
                format!("file:{}", cert.display()),
                format!("file:{}", key.display()),
            )
        };
        let addresses = |doc: &mut ServerDocument| {
            let mut tcp = Vec::new();
            let mut udp = Vec::new();
            for inbound in &mut doc.server.inbounds {
                let t = StdTcp::bind("127.0.0.1:0").unwrap();
                let u = StdUdp::bind("127.0.0.1:0").unwrap();
                inbound.h2_listen = t.local_addr().unwrap().to_string();
                inbound.quic_listen = u.local_addr().unwrap().to_string();
                tcp.push(t);
                udp.push(u);
            }
            (tcp, udp)
        };
        let (cert, key) = material("old");
        let mut initial = live_auth_fixture();
        for inbound in &mut initial.server.inbounds {
            inbound.tls_cert.clone_from(&cert);
            inbound.tls_key.clone_from(&key);
        }
        let reservations = addresses(&mut initial);
        let limits = GenerationLimits::new(&initial);
        // No generation may partially start when its TCP port is occupied.
        assert!(prepare_generation(&initial, 1, &limits, None)
            .await
            .is_err());
        drop(reservations);
        let prepared = prepare_generation(&initial, 1, &limits, None)
            .await
            .unwrap();
        let ids = prepared.identities.clone();
        let runtime = State::new(View {
            document: Arc::new(initial.clone()),
            inbounds: initial.server.inbounds.len(),
            preflight: Arc::new(ReloadPreflight::new(
                path.clone(),
                initial.clone(),
                ids.clone(),
            )),
            live: prepared.live,
        });
        let mut running = RunningGeneration::launch(prepared.listeners, GenerationPhase::Prepared);
        tokio::task::yield_now().await;
        assert!(running.is_healthy_before_activation());
        running.start();
        let request = |candidate: ServerDocument, kind, captured| {
            let previous = runtime.snapshot().unwrap();
            let expected_revision = previous.live.revision().unwrap();
            let (complete, _reply) = tokio::sync::oneshot::channel();
            RestartRequest {
                kind,
                previous,
                expected_revision,
                candidate,
                material: captured,
                complete,
            }
        };
        let (new_cert, new_key) = material("rotated");
        let mut rotation = initial.clone();
        for inbound in &mut rotation.server.inbounds {
            inbound.tls_cert.clone_from(&new_cert);
            inbound.tls_key.clone_from(&new_key);
        }
        let missing = request(rotation.clone(), ChangeKind::Restart, None);
        assert!(commit_same_port_tls(&runtime, &mut running, &missing, &ids, &path).is_err());
        let captured = CapturedTls::capture(&rotation).unwrap();
        let rotate = request(rotation.clone(), ChangeKind::Restart, Some(captured));
        let (rotated_ids, revision, mut slot) =
            commit_same_port_tls(&runtime, &mut running, &rotate, &ids, &path).unwrap();
        assert_eq!(revision, 2);
        assert!(rotated_ids != ids);
        assert_eq!(runtime.snapshot().unwrap().document.as_ref(), &rotation);
        assert!(commit_same_port_tls(&runtime, &mut running, &rotate, &ids, &path).is_err());
        assert!(commit_tls_rollback(&runtime, &mut running, &slot, 1, &path).is_err());

        let mut quota = rotation.clone();
        quota.server.policy.max_connections_total += 1;
        let occupied = limits.ledger.acquire_session("alice").unwrap();
        let invalid_quota = request(rotation.clone(), ChangeKind::Quota, None);
        assert!(commit_live_quota(&runtime, &invalid_quota, &limits.ledger).is_err());
        let quota_request = request(quota.clone(), ChangeKind::Quota, None);
        assert_eq!(
            commit_live_quota(&runtime, &quota_request, &limits.ledger),
            Ok(3)
        );
        assert!(limits.ledger.acquire_session("alice").is_none());
        drop(occupied);
        let deadline = slot.expires;
        slot.expires = Instant::now();
        assert!(commit_tls_rollback(&runtime, &mut running, &slot, 3, &path).is_err());
        slot.expires = deadline;
        let (restored, revision) =
            commit_tls_rollback(&runtime, &mut running, &slot, 3, &path).unwrap();
        assert_eq!(revision, 4);
        assert!(restored == ids);
        let current = runtime.snapshot().unwrap();
        assert_eq!(current.document.server.policy, quota.server.policy);
        assert_eq!(current.document.server.inbounds[0].tls_cert, cert);
        assert_eq!(current.document.server.inbounds[0].tls_key, key);
        // A fresh generation uses the same ledger and preserves the old
        // listener sockets until the candidate is published.
        let mut candidate = current.document.as_ref().clone();
        let fresh_reservations = addresses(&mut candidate);
        let captured = CapturedTls::capture(&candidate).unwrap();
        let fresh = request(candidate.clone(), ChangeKind::Restart, Some(captured));
        assert!(stage_fresh_generation(&fresh, &restored, &limits, &path)
            .await
            .is_err());
        drop(fresh_reservations);
        let (mut successor, next, next_ids, next_reality, revision) =
            stage_fresh_generation(&fresh, &restored, &limits, &path)
                .await
                .unwrap();
        assert_eq!(revision, 5);
        assert!(next_ids == restored);
        assert_eq!(runtime.snapshot().unwrap().live.revision(), Ok(4));
        assert!(StdTcp::bind(&initial.server.inbounds[0].h2_listen).is_err());
        assert!(StdTcp::bind(&candidate.server.inbounds[0].h2_listen).is_err());
        runtime
            .commit_restart_with_reality(
                &fresh.previous,
                fresh.expected_revision,
                next,
                next_reality,
            )
            .unwrap();
        successor.start();
        assert_eq!(runtime.snapshot().unwrap().live.revision(), Ok(5));
        let retired = fresh.previous.live.shared().load().unwrap();
        assert!(retired.grants.is_empty());
        assert!(retired.users.iter().all(|u| u.disabled));
        tokio::time::timeout(Duration::from_secs(5), reap_previous(running))
            .await
            .unwrap();
        // Partial cutover: bind only a new inbound, keep existing TCP/UDP
        // ownership and the exact shared authorization cell.
        let retained = runtime.snapshot().unwrap();
        let mut added = retained.document.as_ref().clone();
        let mut inbound = added.server.inbounds[0].clone();
        inbound.id = "edge-c".into();
        let reserve_tcp = StdTcp::bind("127.0.0.1:0").unwrap();
        let reserve_udp = StdUdp::bind("127.0.0.1:0").unwrap();
        inbound.h2_listen = reserve_tcp.local_addr().unwrap().to_string();
        inbound.quic_listen = reserve_udp.local_addr().unwrap().to_string();
        added.server.inbounds.push(inbound.clone());
        let captured = CapturedTls::capture(&added).unwrap();
        let add_ids = captured.identities();
        let plan =
            crate::restart_guard::partial_layout(&retained.document, &next_ids, &added, &add_ids)
                .unwrap();
        assert!(plan.added.contains("edge-c") && plan.removed.is_empty());
        let add = request(added.clone(), ChangeKind::Restart, Some(captured));
        assert!(
            stage_partial_generation(&add, &next_ids, &limits, &path, &plan)
                .await
                .is_err()
        );
        assert_eq!(runtime.snapshot().unwrap().live.revision(), Ok(5));
        drop((reserve_tcp, reserve_udp));
        let (prepared, view, auth) =
            stage_partial_generation(&add, &next_ids, &limits, &path, &plan)
                .await
                .unwrap();
        assert_eq!(prepared.listeners.len(), 1);
        assert_eq!(
            runtime.commit_partial_layout(
                &add.previous,
                5,
                view,
                auth,
                &plan.removed,
                prepared.reality
            ),
            Ok(6)
        );
        successor.append(prepared.listeners, GenerationPhase::Active);
        successor.order_plain(&added);
        let current = runtime.snapshot().unwrap();
        assert!(Arc::ptr_eq(&current.live.shared(), &retained.live.shared()));
        assert!(StdTcp::bind(&added.server.inbounds[0].h2_listen).is_err());
        assert!(StdUdp::bind(&added.server.inbounds[0].quic_listen).is_err());
        assert!(StdTcp::bind(&inbound.h2_listen).is_err());
        let mut removed = added.clone();
        removed.server.inbounds.retain(|i| i.id != "edge-c");
        let captured = CapturedTls::capture(&removed).unwrap();
        let remove_ids = captured.identities();
        let plan =
            crate::restart_guard::partial_layout(&added, &add_ids, &removed, &remove_ids).unwrap();
        assert!(plan.added.is_empty() && plan.removed.contains("edge-c"));
        let remove = request(removed, ChangeKind::Restart, Some(captured));
        let (prepared, view, auth) =
            stage_partial_generation(&remove, &add_ids, &limits, &path, &plan)
                .await
                .unwrap();
        assert!(prepared.listeners.is_empty());
        assert_eq!(
            runtime.commit_partial_layout(
                &remove.previous,
                6,
                view,
                auth,
                &plan.removed,
                prepared.reality
            ),
            Ok(7)
        );
        successor.remove_inbounds(&plan.removed);
        assert!(successor.has_draining());
        let (id, result) =
            tokio::time::timeout(Duration::from_secs(5), successor.tasks.join_next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert!(result.is_ok() && successor.finish_draining(&id));
        assert!(!successor.has_draining());
        assert!(StdTcp::bind(&inbound.h2_listen).is_ok());
        assert!(StdUdp::bind(&inbound.quic_listen).is_ok());
        assert!(StdTcp::bind(&added.server.inbounds[0].h2_listen).is_err());
        tokio::time::timeout(Duration::from_secs(5), reap_previous(successor))
            .await
            .unwrap();

        // Real registered bundle plus ordinary TLS. PEM rotation and its
        // rollback must not replace the REALITY route table or UDP endpoint.
        let mut mixed = initial.clone();
        let reservations = addresses(&mut mixed);
        drop(reservations);
        let (tcp, udp) = crate::shared_port::reserve_shared_port();
        let addr = tcp.local_addr().unwrap();
        let edge = &mut mixed.server.inbounds[1];
        edge.h2_listen = addr.to_string();
        edge.quic_listen = addr.to_string();
        edge.security_mode = crate::security_profile::SecurityMode::SmartReality;
        edge.path_prefix = None;
        edge.tls_cert.clear();
        edge.tls_key.clear();
        let now = crate::reference_health::unix_now().unwrap();
        let health = crate::reference_health::State::new(
            crate::reference_health::Plan {
                schema_version: 1,
                inbound: edge.id.clone(),
                endpoint: format!("{}:{}", edge.server_name, addr.port()),
                own_ips: vec![addr.ip()],
                references: vec![crate::reference_health::Target {
                    server_name: "ref.example.org".into(),
                    address: "93.184.216.2:443".parse().unwrap(),
                }],
            },
            vec![crate::reference_health::Evidence {
                h2_status: Some(200),
                h3_status: Some(200),
            }],
            now,
        )
        .unwrap();
        let health_path = directory.join("mixed-health");
        crate::reference_health::Store::new(&health_path)
            .unwrap()
            .enroll(&health)
            .unwrap();
        let bundle = directory.join("mixed-bundle");
        let digest = health.snapshot_sha256().unwrap();
        let record = crate::reality_provision::create(&health, digest, &bundle, now).unwrap();
        edge.reality = Some(crate::config::RealityBinding {
            health_store: health_path.to_string_lossy().into_owned(),
            bundle: bundle.to_string_lossy().into_owned(),
            initial_health_sha256: digest,
            identity_sha256: record.identity_sha256,
            manifest_sha256: record.manifest_sha256().unwrap(),
        });
        drop((tcp, udp));
        let captured = CapturedTls::capture(&mixed).unwrap();
        let mixed_ids = captured.identities();
        let mixed_limits = GenerationLimits::new(&mixed);
        let prepared = prepare_generation(&mixed, 1, &mixed_limits, Some(&captured))
            .await
            .unwrap();
        let state = State::new(View {
            document: Arc::new(mixed.clone()),
            inbounds: 2,
            preflight: Arc::new(ReloadPreflight::new(
                path.clone(),
                mixed.clone(),
                mixed_ids.clone(),
            )),
            live: prepared.live,
        })
        .with_reality(prepared.reality)
        .with_reality_ledger(mixed_limits.ledger.clone());
        let mut running = RunningGeneration::launch(prepared.listeners, GenerationPhase::Active);
        let live = running.reality[0].carrier.clone();
        let generation = live.current().unwrap();
        let mut rotated = mixed.clone();
        rotated.server.inbounds[0].tls_cert = new_cert;
        rotated.server.inbounds[0].tls_key = new_key;
        let (complete, _rx) = tokio::sync::oneshot::channel();
        let request = RestartRequest {
            kind: ChangeKind::Restart,
            previous: state.snapshot().unwrap(),
            expected_revision: 1,
            material: Some(CapturedTls::capture(&rotated).unwrap()),
            candidate: rotated,
            complete,
        };
        let (updated, revision, slot) =
            commit_same_port_tls(&state, &mut running, &request, &mixed_ids, &path).unwrap();
        assert_eq!(revision, 2);
        assert!(updated[0] != mixed_ids[0] && updated[1] == mixed_ids[1]);
        assert!(Arc::ptr_eq(&live, &running.reality[0].carrier));
        assert!(Arc::ptr_eq(&generation, &live.current().unwrap()));
        let (restored, revision) =
            commit_tls_rollback(&state, &mut running, &slot, 2, &path).unwrap();
        assert_eq!(revision, 3);
        assert!(restored == mixed_ids);
        assert!(Arc::ptr_eq(&generation, &live.current().unwrap()));
        assert!(StdTcp::bind(addr).is_err());
        assert!(StdUdp::bind(addr).is_err());
        // REALITY groups need not finish naturally before the drain timeout;
        // dropping the test-owned group cancels every listener task.
        running.tasks.shutdown().await;
    }
}
