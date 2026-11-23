//! First real H2/TLS 1.3 server ingress. This is not an H3 endpoint.
//! A listener, not the untrusted HTTP Host/authority, determines authorization.
use crate::{
    config::{self, Config, Inbound, ServerDocument, ServerPolicy, User},
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
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PEM_BYTES: u64 = 1024 * 1024;
const MAX_H2_STREAMS: u32 = 32;
const MAX_HEADER_BYTES: u32 = 8192;
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
            Self::Tls => "TLS handshake or certificate failed",
            Self::Http2 => "HTTP/2 session closed or flow control failed",
            Self::Protocol => "SmartTheia protocol violation",
            Self::TimedOut => "server operation timed out",
        };
        f.write_str(description)
    }
}
impl std::error::Error for ServerError {}

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
    authorization: Arc<AuthCell>,
    policy: ServerPolicy,
    global_streams: Arc<Semaphore>,
    user_streams: Arc<HashMap<String, Arc<Semaphore>>>,
    connection_slots: Arc<Semaphore>,
    peer_budget: Arc<PeerBudget>,
}

pub struct SessionPermit {
    _global: OwnedSemaphorePermit,
    _user: OwnedSemaphorePermit,
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
            AuthCell::isolated(inbound, users),
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
            authorization,
            policy: policy.clone(),
            global_streams,
            user_streams,
            connection_slots,
            peer_budget,
        }
    }

    pub(crate) fn connection_slot(&self) -> Option<OwnedSemaphorePermit> {
        self.connection_slots.clone().try_acquire_owned().ok()
    }

    pub(crate) async fn dial_target(
        &self,
        address: &Address,
        port: u16,
    ) -> Result<TcpStream, ErrorCode> {
        connect_target(address, port, &self.policy).await
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
        if request.method() != Method::POST
            || request.uri().path() != "/v1/session"
            || request.uri().query().is_some()
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

    /// Raw token digest is the SHA-256 of exactly 32 decoded bytes, not the
    /// base64url text or a 64-character hex digest presented as a credential.
    /// Check all configured hashes using constant-time comparison and never
    /// reflect token bytes, hashes or even the candidate string in errors.
    pub fn authorize(&self, authorization: Option<&str>) -> Result<SessionPermit, AuthFailure> {
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
            _global: global,
            _user: per_user,
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

/// Fail-closed address policy. IPv4-mapped IPv6 must be checked as IPv4.
/// Private/loopback, link-local, multicast, reserved and documentation ranges
/// are rejected by default; only explicit allow_private_ips permits them.
pub fn allowed_destination(ip: IpAddr, allow_private_ips: bool) -> bool {
    if let IpAddr::V6(v6) = ip {
        if let Some(mapped) = v6.to_ipv4_mapped() {
            return allowed_destination(IpAddr::V4(mapped), allow_private_ips);
        }
    }
    if allow_private_ips {
        return !ip.is_unspecified() && !ip.is_multicast();
    }
    match ip {
        IpAddr::V4(v4) => allowed_v4(v4),
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let global_unicast = (segments[0] & 0xe000) == 0x2000;
            let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
            // Reject transition/tunneling and special-use ranges rather than
            // relying on embedded IPv4 routing or future address assignments.
            let special = (segments[0] == 0x2001 && segments[1] < 0x0200)
                || segments[0] == 0x2002
                || (segments[0] == 0x3fff && segments[1] < 0x1000);
            global_unicast && !documentation && !special
        }
    }
}

fn allowed_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 0 || b == 168 || (b == 88 && c == 99)))
        || (a == 198 && ((b == 18 || b == 19) || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113)
        || (a == 192 && b == 0 && c == 2)
        || (a == 255 && b == 255 && c == 255 && d == 255))
}

/// All DNS and dial attempts consume one deadline. The result list is bounded;
/// no second resolution can change the addresses checked by the policy.
async fn connect_target(
    address: &Address,
    port: u16,
    policy: &ServerPolicy,
) -> Result<TcpStream, ErrorCode> {
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
        // Pin each ACL-checked SocketAddr. Share the remaining deadline
        // between candidates so an unresponsive IPv6 route cannot starve IPv4.
        dial_candidates(&permitted, deadline, TcpStream::connect).await
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

pub async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    context: Arc<ServerContext>,
) -> Result<(), ServerError> {
    // JoinSet ownership makes cancellation of serve cancel all of its
    // connections, which in turn cancel all of their stream handlers.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (socket, peer) = accepted.map_err(|_| ServerError::Io)?;
                let Some(slot) = context.connection_slot() else {
                    continue;
                };
                let tls_acceptor = acceptor.clone();
                let context = context.clone();
                connections.spawn(async move {
                    let _slot = slot;
                    let Ok(Ok(tls)) = timeout(HANDSHAKE_TIMEOUT, tls_acceptor.accept(socket)).await else {
                        return;
                    };
                    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                        return;
                    }
                    let mut builder = h2::server::Builder::new();
                    builder.max_concurrent_streams(MAX_H2_STREAMS);
                    builder.max_header_list_size(MAX_HEADER_BYTES);
                    let Ok(Ok(mut connection)) = timeout(HANDSHAKE_TIMEOUT, builder.handshake(tls)).await else {
                        return;
                    };
                    let mut handlers = JoinSet::new();
                    loop {
                        let accepted = if handlers.is_empty() {
                            match timeout(AUTH_WINDOW, connection.accept()).await {
                                Ok(accepted) => accepted,
                                Err(_) => break,
                            }
                        } else {
                            tokio::select! {
                                _ = handlers.join_next() => continue,
                                accepted = connection.accept() => accepted,
                            }
                        };
                        let Some(Ok((request, respond))) = accepted else {
                            break;
                        };
                        let context = context.clone();
                        handlers.spawn(async move {
                            let _ = handle_request(request, respond, context, peer.ip()).await;
                        });
                    }
                });
            }
        }
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

async fn handle_request(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    context: Arc<ServerContext>,
    peer: IpAddr,
) -> Result<(), ServerError> {
    let permit = match context.authorize_request(&request, peer) {
        Ok(permit) => permit,
        Err(status) => return reject(&mut respond, status).await,
    };
    let mut inbound = request.into_body();
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|_| ServerError::Http2)?;
    // HTTP 200 acknowledges transport/auth headers, NOT remote TCP OPEN.
    let mut outgoing = respond
        .send_response(response, false)
        .map_err(|_| ServerError::Http2)?;
    let result = timeout(
        Duration::from_secs(300),
        handle_frames(&mut inbound, &mut outgoing, &context),
    )
    .await;
    // A timeout or transport failure can interrupt an already partially
    // written frame. Reset rather than appending an ABORT to corrupt bytes.
    if matches!(
        result,
        Err(_) | Ok(Err(ServerError::TimedOut | ServerError::Http2))
    ) {
        outgoing.send_reset(h2::Reason::CANCEL);
        return Ok(());
    }
    if !matches!(result, Ok(Ok(()))) {
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
    drop(permit);
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
            let block = timeout(FRAME_IDLE_TIMEOUT, incoming.data())
                .await
                .map_err(|_| ServerError::TimedOut)?;
            let Some(block) = block else {
                self.decoder.finish().map_err(|_| ServerError::Protocol)?;
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
) -> Result<(), ServerError> {
    let mut decoder = IncomingFrames::default();
    let mut state = Session::new(Role::Server);
    let opened = timeout(HANDSHAKE_TIMEOUT, async {
        let hello = decoder.next(incoming).await?.ok_or(ServerError::Protocol)?;
        state
            .apply(Direction::Receive, &hello)
            .map_err(|_| ServerError::Protocol)?;
        send_frame(
            outgoing,
            &Frame::HelloAck {
                version: protocol::VERSION,
                accepted_capabilities: 0,
            },
        )
        .await?;
        state
            .apply(
                Direction::Send,
                &Frame::HelloAck {
                    version: protocol::VERSION,
                    accepted_capabilities: 0,
                },
            )
            .map_err(|_| ServerError::Protocol)?;
        let open = decoder.next(incoming).await?.ok_or(ServerError::Protocol)?;
        state
            .apply(Direction::Receive, &open)
            .map_err(|_| ServerError::Protocol)?;
        let Frame::OpenTcp { address, port } = open else {
            return Err(ServerError::Protocol);
        };
        Ok::<_, ServerError>((address, port))
    })
    .await
    .map_err(|_| ServerError::TimedOut)??;
    let (address, port) = opened;
    let dial = tokio::select! {
        result = context.dial_target(&address, port) => result,
        _ = std::future::poll_fn(|cx| outgoing.poll_reset(cx)) => {
            return Err(ServerError::Http2);
        }
    };
    let tcp = match dial {
        Ok(tcp) => tcp,
        Err(code) => {
            let failure = Frame::OpenError(code);
            state
                .apply(Direction::Send, &failure)
                .map_err(|_| ServerError::Protocol)?;
            send_frame(outgoing, &failure).await?;
            return Ok(());
        }
    };
    state
        .apply(Direction::Send, &Frame::OpenOk)
        .map_err(|_| ServerError::Protocol)?;
    send_frame(outgoing, &Frame::OpenOk).await?;

    relay_tcp(tcp, incoming, outgoing, decoder, state).await
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
) -> Result<(), ServerError> {
    let (mut read, mut write) = tcp.into_split();
    let mut rx_state = state.clone();
    let mut tx_state = state.clone();
    let (download_done, mut download_finished) = tokio::sync::oneshot::channel();
    let upload = async {
        loop {
            let frame = decoder.next(incoming).await?.ok_or(ServerError::Protocol)?;
            rx_state
                .apply(Direction::Receive, &frame)
                .map_err(|_| ServerError::Protocol)?;
            match frame {
                Frame::Data(data) => {
                    timeout(FRAME_IDLE_TIMEOUT, write.write_all(&data))
                        .await
                        .map_err(|_| ServerError::TimedOut)?
                        .map_err(|_| ServerError::Io)?;
                }
                Frame::Fin => {
                    timeout(FRAME_IDLE_TIMEOUT, write.shutdown())
                        .await
                        .map_err(|_| ServerError::TimedOut)?
                        .map_err(|_| ServerError::Io)?;
                    break;
                }
                Frame::Abort(_) => return Err(ServerError::Http2),
                _ => return Err(ServerError::Protocol),
            }
        }
        // FIN half-closes TCP upload, not the HTTP request itself. Keep
        // watching for reset, trailing frames or request EOF while downloading.
        let tail = tokio::select! {
            result = decoder.next(incoming) => result?,
            _ = &mut download_finished => {
                timeout(CLOSE_TIMEOUT, decoder.next(incoming))
                    .await
                    .map_err(|_| ServerError::TimedOut)??
            }
        };
        if tail.is_some() {
            return Err(ServerError::Protocol);
        }
        Ok::<(), ServerError>(())
    };
    let download = async {
        let mut buffer = [0u8; 4096];
        loop {
            let size = tokio::select! {
                result = timeout(FRAME_IDLE_TIMEOUT, read.read(&mut buffer)) => {
                    result.map_err(|_| ServerError::TimedOut)?
                        .map_err(|_| ServerError::Io)?
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
            tx_state
                .apply(Direction::Send, &frame)
                .map_err(|_| ServerError::Protocol)?;
            timeout(FRAME_IDLE_TIMEOUT, send_frame(outgoing, &frame))
                .await
                .map_err(|_| ServerError::TimedOut)??;
            if size == 0 {
                let _ = download_done.send(());
                return Ok::<(), ServerError>(());
            }
        }
    };

    // An error can cancel send_frame halfway through an H2 window. Reset
    // the stream instead of appending an ABORT to a partially written frame.
    tokio::try_join!(upload, download).map_err(|_| ServerError::Http2)?;
    state
        .apply(Direction::Receive, &Frame::Fin)
        .map_err(|_| ServerError::Protocol)?;
    state
        .apply(Direction::Send, &Frame::Fin)
        .map_err(|_| ServerError::Protocol)?;
    state.finish().map_err(|_| ServerError::Protocol)
}

pub(crate) fn pem_data(reference: &str, private_key: bool) -> Result<Vec<u8>, ServerError> {
    let path = reference.strip_prefix("file:").ok_or(ServerError::Config)?;
    let path = Path::new(path);
    let meta = std::fs::symlink_metadata(path).map_err(|_| ServerError::Config)?;
    if !meta.file_type().is_file() || meta.len() > MAX_PEM_BYTES {
        return Err(ServerError::Config);
    }
    #[cfg(unix)]
    if private_key {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(ServerError::Config);
        }
    }
    #[cfg(not(unix))]
    let _ = private_key;
    let bytes = std::fs::read(path).map_err(|_| ServerError::Config)?;
    if bytes.len() as u64 > MAX_PEM_BYTES {
        return Err(ServerError::Config);
    }
    Ok(bytes)
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
    let cert_bytes = pem_data(&inbound.tls_cert, false)?;
    let key_bytes = pem_data(&inbound.tls_key, true)?;
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let identity = crate::reload_preflight::IdentityHash::from_pem(&cert_bytes, &key_bytes);
    let mut cert_reader = BufReader::new(cert_bytes.as_slice());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|_| ServerError::Config)?;
    let leaf = certs.first().ok_or(ServerError::Config)?;
    check_certificate_name(leaf, &inbound.server_name)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
        .map_err(|_| ServerError::Config)?
        .ok_or(ServerError::Config)?;
    Ok(TlsMaterial {
        certs,
        key,
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        identity,
    })
}

fn tls_acceptor(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, ServerError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| ServerError::Tls)?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| ServerError::Tls)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    tls.max_early_data_size = 0;
    Ok(TlsAcceptor::from(Arc::new(tls)))
}

/// Prepare all TCP and UDP listeners and TLS identity before launching tasks.
pub async fn run_file(config_path: &Path) -> Result<(), ServerError> {
    let parsed = config::read_file(config_path).map_err(|_| ServerError::Config)?;
    let Config::Server(document) = parsed else {
        return Err(ServerError::Config);
    };
    run_document_with_config(document, Some(config_path)).await
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
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        loaded_identities.push(material.identity.clone());
        let acceptor = tls_acceptor(material.certs.clone(), material.key.clone_key())?;
        let listener = TcpListener::bind(addr).await.map_err(|_| ServerError::Io)?;
        let endpoint =
            crate::quic_transport::server_endpoint(udp_addr, material.certs, material.key)
                .map_err(|error| match error {
                    crate::quic_transport::QuicError::Bind => ServerError::Io,
                    _ => ServerError::Tls,
                })?;
        let context = Arc::new(ServerContext::with_limits(
            inbound,
            &policy,
            live_authorization.shared(),
            global.clone(),
            per_user.clone(),
            connections.clone(),
            peer_budget.clone(),
        ));
        prepared.push((listener, acceptor, endpoint, context));
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
        tasks.spawn(crate::h3_server::serve(endpoint, context));
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

#[cfg(test)]
mod hardening_tests {
    use super::*;

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
            let peer = IpAddr::V4(Ipv4Addr::new(10, 0, (n >> 8) as u8, n as u8));
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
                        allowed_user_ids: vec!["alice".into()],
                        h2_listen: "127.0.0.1:9443".into(),
                        quic_listen: "127.0.0.1:9443".into(),
                        server_name: "a.example.org".into(),
                        tls_cert: "file:/tmp/theia-a.crt".into(),
                        tls_key: "file:/tmp/theia-a.key".into(),
                    },
                    Inbound {
                        id: "edge-b".into(),
                        allowed_user_ids: vec!["bob".into()],
                        h2_listen: "127.0.0.1:9444".into(),
                        quic_listen: "127.0.0.1:9444".into(),
                        server_name: "b.example.org".into(),
                        tls_cert: "file:/tmp/theia-b.crt".into(),
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

    #[test]
    fn configured_name_must_match_certificate_san() {
        let cert = rcgen::generate_simple_self_signed(vec!["theia.example".into()]).unwrap();
        assert!(check_certificate_name(cert.cert.der(), "theia.example").is_ok());
        assert!(check_certificate_name(cert.cert.der(), "other.example").is_err());
    }
}
