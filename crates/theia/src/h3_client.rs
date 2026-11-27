//! Explicit H3 client core with bounded per-profile connection reuse.
use crate::{
    client::{bearer_header, ClientError},
    diagnostics::{self, Value},
    protocol::{self, Address, Decoder, Direction, Frame, Role, Session},
    quic_core::{dial, h3_adapter, handshake_udp, negotiation::VersionPolicy, wire::Version},
};
use bytes::{Buf, Bytes};
use h3::{client::RequestStream, quic};
use http::{header, HeaderValue, Request, StatusCode, Uri};
use rustls::{pki_types::ServerName, RootCertStore};
use std::{collections::VecDeque, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinHandle,
    time::timeout,
};

use crate::xhttp::session::{self, CarrierKind, FrameReader, FrameWriter, OpenAdapter, OPEN_TIMEOUT, IO_TIMEOUT};
type Tx = RequestStream<h3_adapter::SendSide, Bytes>;
type Rx = RequestStream<h3_adapter::RecvSide, Bytes>;

pub struct H3Client {
    remote: SocketAddr,
    name: String,
    uri: Uri,
    authorization: HeaderValue,
    own_trust: crate::own_tls::Trust,
    identity_quic: Option<Arc<rustls::ClientConfig>>,
    native_lab: Option<crate::quic_core::wire::Version>,
    native_pins: Option<(SocketAddr, crate::quic_core::scope::NetworkScope)>,
    identity_routes: Option<crate::split_http::IdentityRoutes>,
    padding: crate::descriptor::Padding,
    own_routes: Option<crate::split_http::IdentityRoutes>,
    connect_timeout: Duration,
    certificate_pin: Option<crate::security_profile::CertificatePin>,
    stream_up: bool,
    auto_mode: Option<crate::split_http::AutoMode>,
    pool: crate::connection_pool::Pool<H3Connection>,
    reuse_connections: bool,
}

impl H3Client {
    /// Only the configured server address is resolved by the composition
    /// root. Target DNS names remain opaque SmartTheia addresses.
    pub fn new(
        remote: SocketAddr,
        name: &str,
        token: &str,
        roots: RootCertStore,
    ) -> Result<Self, ClientError> {
        Self::new_with_trust(remote, name, token, crate::own_tls::Trust::Roots(roots))
    }

    pub(crate) fn new_with_trust(
        remote: SocketAddr,
        name: &str,
        token: &str,
        trust: crate::own_tls::Trust,
    ) -> Result<Self, ClientError> {
        if remote.port() == 0 || remote.ip().is_unspecified() || !trust.usable() {
            return Err(ClientError::Configuration);
        }
        if !matches!(ServerName::try_from(name), Ok(ServerName::DnsName(_))) {
            return Err(ClientError::Configuration);
        }
        let uri = Uri::builder()
            .scheme("https")
            .authority(name)
            .path_and_query("/v1/theia-example/session")
            .build()
            .map_err(|_| ClientError::Configuration)?;
        Ok(Self {
            remote,
            name: name.to_owned(),
            uri,
            authorization: bearer_header(token)?,
            own_trust: trust,
            identity_quic: None,
            native_lab: None,
            native_pins: None,
            identity_routes: None,
            padding: crate::descriptor::Padding::default(),
            own_routes: Some(crate::split_http::IdentityRoutes::new(
                crate::split_http::EXAMPLE_PREFIX,
            )?),
            connect_timeout: Duration::from_secs(10),
            certificate_pin: None,
            stream_up: false,
            auto_mode: None,
            pool: crate::connection_pool::Pool::default(),
            reuse_connections: false,
        })
    }

    pub(crate) fn identity_fixture(
        remote: SocketAddr,
        token: &str,
        value: &crate::descriptor::Verified,
    ) -> Result<Self, ClientError> {
        let d = value.descriptor();
        if !remote.ip().is_loopback()
            || d.scope.endpoint != remote.to_string()
            || !value.effective_modes().h3
        {
            return Err(ClientError::Configuration);
        }
        let quic = crate::identity_tls::client_tls(
            &d.scope,
            value.signer(),
            crate::identity_tls::Branch::H3,
        )
        .map_err(|_| ClientError::Tls)?;
        Self::identity_carrier(remote, "localhost", token, value, quic)
    }

    pub(crate) fn admitted_fixture(
        remote: SocketAddr,
        token: &str,
        value: &crate::descriptor::Verified,
        secret: Arc<crate::reality_admission::Secret>,
    ) -> Result<Self, ClientError> {
        let d = value.descriptor();
        if !remote.ip().is_loopback()
            || d.scope.endpoint != remote.to_string()
            || !value.effective_modes().h3
        {
            return Err(ClientError::Configuration);
        }
        let name = &d
            .references
            .get(usize::from(d.active_reference))
            .ok_or(ClientError::Configuration)?
            .server_name;
        let quic = crate::identity_tls::admitted_client_tls(
            value,
            crate::identity_tls::Branch::H3,
            secret,
        )
        .map_err(|_| ClientError::Tls)?;
        Self::identity_carrier(remote, name, token, value, quic)
    }

    pub(crate) fn admitted_runtime(
        remote: SocketAddr,
        token: &str,
        value: &crate::descriptor::Verified,
        secret: Arc<crate::reality_admission::Secret>,
    ) -> Result<Self, ClientError> {
        let d = value.descriptor();
        if remote.port() == 0 || remote.ip().is_unspecified() || !value.effective_modes().h3 {
            return Err(ClientError::Configuration);
        }
        let name = &d
            .references
            .get(usize::from(d.active_reference))
            .ok_or(ClientError::Configuration)?
            .server_name;
        let quic = crate::identity_tls::admitted_client_tls(
            value,
            crate::identity_tls::Branch::H3,
            secret,
        )
        .map_err(|_| ClientError::Tls)?;
        Self::identity_carrier(remote, name, token, value, quic)
    }

    fn identity_carrier(
        remote: SocketAddr,
        name: &str,
        token: &str,
        value: &crate::descriptor::Verified,
        quic: rustls::ClientConfig,
    ) -> Result<Self, ClientError> {
        let d = value.descriptor();
        let routes = crate::split_http::IdentityRoutes::new(&d.path_prefix)?;
        let uri = Uri::builder()
            .scheme("https")
            .authority(name)
            .path_and_query(routes.single.as_str())
            .build()
            .map_err(|_| ClientError::Configuration)?;
        let mut client = Self {
            remote,
            name: name.to_owned(),
            uri,
            authorization: bearer_header(token)?,
            own_trust: crate::own_tls::Trust::Roots(RootCertStore::empty()),
            identity_quic: Some(Arc::new(quic)),
            native_lab: None,
            native_pins: None,
            identity_routes: Some(routes),
            padding: d.padding.clone(),
            own_routes: None,
            connect_timeout: Duration::from_secs(10),
            certificate_pin: None,
            stream_up: false,
            auto_mode: None,
            pool: crate::connection_pool::Pool::with_rotation(&value.descriptor().rotation),
            reuse_connections: false,
        };
        let modes = value.effective_modes();
        client = if modes.stream_one && modes.stream_up {
            client.with_auto_stream_up(Duration::from_secs(900))?
        } else {
            client.with_stream_up(modes.stream_up)?
        };
        Ok(client)
    }

    pub(crate) async fn fetch_identity_descriptor(&self) -> Result<String, ClientError> {
        self.fetch_identity_document(false).await
    }

    pub(crate) async fn fetch_identity_document(
        &self,
        successor: bool,
    ) -> Result<String, ClientError> {
        let routes = self
            .identity_routes
            .as_ref()
            .ok_or(ClientError::Configuration)?;
        timeout(OPEN_TIMEOUT, async {
            let connection = self.connect_verified(diagnostics::next_id()).await?;
            let mut sender = connection
                .sender
                .lock()
                .map_err(|_| ClientError::Http3)?
                .clone();
            let mut parts = self.uri.clone().into_parts();
            parts.path_and_query = Some(
                (if successor {
                    &routes.successor
                } else {
                    &routes.descriptor
                })
                .parse()
                .map_err(|_| ClientError::Configuration)?,
            );
            let uri = Uri::from_parts(parts).map_err(|_| ClientError::Configuration)?;
            let request = Request::get(uri)
                .header(header::AUTHORIZATION, self.authorization.clone())
                .body(())
                .map_err(|_| ClientError::Configuration)?;
            let mut stream = sender
                .send_request(self.padding.request(request)?)
                .await
                .map_err(|_| ClientError::Http3)?;
            stream.finish().await.map_err(|_| ClientError::Http3)?;
            let response = stream
                .recv_response()
                .await
                .map_err(|_| ClientError::Http3)?;
            crate::split_http::check_status(response.status())?;
            let expected = crate::identity_data::validate_descriptor_headers(response.headers())?;
            let mut bytes = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.map_err(|_| ClientError::Http3)? {
                if chunk.remaining() > expected.saturating_sub(bytes.len()) {
                    return Err(ClientError::Protocol);
                }
                let chunk = chunk.copy_to_bytes(chunk.remaining());
                crate::identity_data::append_descriptor(&mut bytes, &chunk, expected)?;
            }
            if stream
                .recv_trailers()
                .await
                .map_err(|_| ClientError::Http3)?
                .is_some()
            {
                return Err(ClientError::Protocol);
            }
            crate::identity_data::finish_descriptor(bytes, expected)
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    /// Authenticated binary policy snapshot for this exact inbound path.
    pub(crate) async fn fetch_routing(
        &self,
        known: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, ClientError> {
        self.routing_resource(None, known).await
    }

    pub(crate) async fn resolve_routing(
        &self,
        name: &str,
        digest: [u8; 32],
    ) -> Result<Vec<std::net::IpAddr>, ClientError> {
        let bytes = self.routing_resource(Some((name,digest,false)),None).await?;
        crate::routing::exchange::decode_ips(&bytes)
    }

    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    pub(crate) async fn resolve_native_dns(&self,name:&str,digest:[u8;32])->Result<Vec<std::net::IpAddr>,ClientError> {
        let bytes=self.routing_resource(Some((name,digest,true)),None).await?;
        crate::routing::exchange::decode_ips(&bytes)
    }

    pub(crate) fn own_routing_scope(&self) -> Option<&str> {
        self.own_routes
            .as_ref()?
            .routing
            .strip_prefix("/v1/")?
            .strip_suffix("/routing")
    }

    async fn routing_resource(
        &self,
        domain: Option<(&str,[u8;32],bool)>,
        known: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, ClientError> {
        let routes = self
            .identity_routes
            .as_ref()
            .or(self.own_routes.as_ref())
            .ok_or(ClientError::Configuration)?;
        timeout(crate::routing::exchange::TRANSFER_TIMEOUT, async {
            let route = crate::network_scope::observe(self.remote);
            let reusable = self.reuse_connections && self.certificate_pin.is_none();
            let mut lease = self
                .pool
                .acquire(
                    route,
                    reusable,
                    |connection| !connection.driver.0.is_finished(),
                    self.connect_verified(diagnostics::next_id()),
                )
                .await?;
            if route.is_some() && crate::network_scope::observe(self.remote) != route {
                lease.retire();
                return Err(ClientError::Io);
            }
            if !lease.accepting_new_streams() {
                return Err(ClientError::Http3);
            }
            let connection = lease.connection();
            let mut sender = connection
                .sender
                .lock()
                .map_err(|_| ClientError::Http3)?
                .clone();
            let mut parts = self.uri.clone().into_parts();
            parts.path_and_query = Some(
                routes
                    .routing
                    .parse()
                    .map_err(|_| ClientError::Configuration)?,
            );
            let uri = Uri::from_parts(parts).map_err(|_| ClientError::Configuration)?;
            let mut request = Request::get(uri)
                .header(header::AUTHORIZATION, self.authorization.clone())
                .body(())
                .map_err(|_| ClientError::Configuration)?;
            if let Some((name,digest,native))=domain {
                crate::routing::exchange::request_domain(&mut request,name,digest)?;
                if native {request.headers_mut().insert(crate::routing::exchange::NATIVE_DNS_HEADER,http::HeaderValue::from_static("1"));}
            } else if let Some(digest) = known {
                crate::routing::exchange::request_digest(&mut request, digest)?;
            }
            let request = crate::channel_binding::attach(
                connection.binding.as_ref(),
                self.padding.request(request)?,
            )?;
            let mut stream = sender
                .send_request(request)
                .await
                .map_err(|_| ClientError::Http3)?;
            stream.finish().await.map_err(|_| ClientError::Http3)?;
            let response = stream
                .recv_response()
                .await
                .map_err(|_| ClientError::Http3)?;
            crate::split_http::check_status(response.status())?;
            let expected = crate::routing::exchange::validate_headers(response.headers())?;
            if domain.is_some() && expected > crate::routing::exchange::DNS_LIMIT {
                return Err(ClientError::Protocol);
            }
            let mut bytes = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.map_err(|_| ClientError::Http3)? {
                if chunk.remaining() > expected.saturating_sub(bytes.len()) {
                    return Err(ClientError::Protocol);
                }
                let chunk = chunk.copy_to_bytes(chunk.remaining());
                crate::routing::exchange::append(&mut bytes, &chunk, expected)?;
            }
            if stream
                .recv_trailers()
                .await
                .map_err(|_| ClientError::Http3)?
                .is_some()
            {
                return Err(ClientError::Protocol);
            }
            let bytes = crate::routing::exchange::finish(bytes, expected)?;
            lease.admitted();
            Ok(bytes)
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    /// Reuse verified own-TLS connections within this immutable profile.
    pub(crate) fn set_profile_budget(&mut self, budget: std::sync::Arc<tokio::sync::Semaphore>) {
        self.pool.set_profile_budget(budget);
    }

    pub(crate) fn profile_budget(&self) -> std::sync::Arc<tokio::sync::Semaphore> {
        self.pool.profile_budget()
    }

    pub(crate) fn with_mode_cache_ttl(mut self, ttl: Duration) -> Self {
        if let Some(mode) = self.auto_mode.as_mut() {
            mode.set_ttl(ttl);
        }
        self
    }

    pub fn with_connection_pool(mut self) -> Self {
        self.reuse_connections = true;
        self
    }

    /// Enable the common production Own-TLS padding policy. Identity
    /// carriers always keep the immutable signed descriptor policy.
    pub(crate) fn with_own_tls_policy(mut self) -> Result<Self, ClientError> {
        if self.identity_routes.is_some() || self.certificate_pin.is_some() {
            return Err(ClientError::Configuration);
        }
        self.padding = crate::padding::OWN_TLS_PADDING;
        Ok(self)
    }

    /// Set the exact configured inbound route, before admitting any session.
    pub fn with_path_prefix(mut self, prefix: &str) -> Result<Self, ClientError> {
        if self.identity_routes.is_some() {
            return Err(ClientError::Configuration);
        }
        let routes = crate::split_http::IdentityRoutes::new(prefix)?;
        let mut parts = self.uri.clone().into_parts();
        parts.path_and_query = Some(
            routes
                .single
                .parse()
                .map_err(|_| ClientError::Configuration)?,
        );
        self.uri = http::Uri::from_parts(parts).map_err(|_| ClientError::Configuration)?;
        self.own_routes = Some(routes);
        Ok(self)
    }

    pub fn with_certificate_pin(
        mut self,
        pin: Option<crate::security_profile::CertificatePin>,
    ) -> Result<Self, ClientError> {
        if pin.is_some() && self.auto_mode.is_some() {
            return Err(ClientError::Configuration);
        }
        if pin.is_none() && self.certificate_pin.is_some() {
            return Err(ClientError::Configuration);
        }
        self.certificate_pin = pin;
        Ok(self)
    }

    /// Explicit XHTTP split mode with the same TLS verification and credentials.
    pub fn with_stream_up(mut self, enabled: bool) -> Result<Self, ClientError> {
        if self.auto_mode.is_some() || (self.stream_up && !enabled) {
            return Err(ClientError::Configuration);
        }
        self.stream_up = enabled;
        Ok(self)
    }

    /// Opt-in auto XHTTP for own TLS; legacy pinned profiles remain exact.
    pub fn with_auto_stream_up(mut self, ttl: Duration) -> Result<Self, ClientError> {
        if self.certificate_pin.is_some() || self.stream_up || self.auto_mode.is_some() {
            return Err(ClientError::Configuration);
        }
        self.auto_mode = Some(crate::split_http::AutoMode::new(self.remote, ttl));
        Ok(self)
    }

    pub(crate) fn remote(&self) -> SocketAddr {
        self.remote
    }

    pub fn with_connect_timeout(mut self, duration: Duration) -> Result<Self, ClientError> {
        if !(Duration::from_millis(500)..=Duration::from_secs(15)).contains(&duration) {
            return Err(ClientError::Configuration);
        }
        self.connect_timeout = duration;
        Ok(self)
    }

    pub async fn open(&self, address: Address, port: u16) -> Result<H3Tunnel, ClientError> {
        self.open_frame(Frame::OpenTcp { address, port }).await
    }

    pub(crate) async fn open_udp(
        &self,
        address: Address,
        port: u16,
    ) -> Result<H3Tunnel, ClientError> {
        self.open_frame(Frame::OpenUdp { address, port }).await
    }

    async fn open_frame(&self, open: Frame) -> Result<H3Tunnel, ClientError> {
        session::open(self, open).await
    }

    /// A full authenticated transport handshake, shared by tunnel opens and
    /// idle-cache rechecks. No HTTP request or bearer is sent here.
    /// Explicit non-production carrier. Never used by config, Auto or REALITY.
    /// Certificate pinning cannot be bypassed by selecting this fixture.
    pub fn with_native_lab(
        mut self,
        version: crate::quic_core::wire::Version,
    ) -> Result<Self, ClientError> {
        if !self.remote.ip().is_loopback()
            || self.identity_quic.is_some()
            || self.certificate_pin.is_some()
        {
            return Err(ClientError::Configuration);
        }
        self.pool = crate::connection_pool::Pool::default();
        self.native_lab = Some(version);
        self.native_pins = None;
        Ok(self)
    }

    /// Explicit non-production pinned own-TLS carrier. Uses the identical
    /// H3/XHTTP pool and request FSM, without bypassing certificate validation.
    pub fn with_native_pinned(
        mut self,
        version: crate::quic_core::wire::Version,
        local: SocketAddr,
        scope: crate::quic_core::scope::NetworkScope,
    ) -> Result<Self, ClientError> {
        if !scope.is_pinned()
            || !scope.allows_local(local.ip())
            || !scope.allows_peer(self.remote.ip())
            || local.is_ipv4() != self.remote.is_ipv4()
            || self.identity_quic.is_some()
            || self.certificate_pin.is_some()
        {
            return Err(ClientError::Configuration);
        }
        self.pool = crate::connection_pool::Pool::default();
        self.native_lab = Some(version);
        self.native_pins = Some((local, scope));
        Ok(self)
    }

    // Box the handshake future to keep native QUIC state off the executable's
    // small Windows main stack. All paths verify the actual TLS handshake,
    // ALPN, transport parameters and optional DER pin before opening H3.
    fn native_connection(
        &self,
    ) -> impl std::future::Future<Output = Result<crate::quic_core::endpoint::LabSession, ClientError>>
           + Send
           + '_ {
        Box::pin(async move {
            let tls = match &self.identity_quic {
                Some(config) => config.clone(),
                None => Arc::new(
                    self.own_trust
                        .tls(crate::transport_policy::Carrier::H3)
                        .map_err(|_| ClientError::Tls)?,
                ),
            };
            let name =
                ServerName::try_from(self.name.clone()).map_err(|_| ClientError::Configuration)?;
            let session = if let Some(version) = self.native_lab {
                // Keep explicit test scopes; never broaden a caller's pinned
                // addresses or bypass an identity/pin using the lab selectors.
                if self.identity_quic.is_some() || self.certificate_pin.is_some() {
                    return Err(ClientError::Configuration);
                }
                timeout(self.connect_timeout, async {
                    let (_, mut session) = match self.native_pins {
                        Some((local, scope)) => {
                            handshake_udp::connect_versions_scoped(
                                local,
                                self.remote,
                                VersionPolicy::exact(version),
                                tls,
                                name,
                                scope,
                            )
                            .await
                        }
                        None => {
                            handshake_udp::connect_versions(
                                SocketAddr::new(self.remote.ip(), 0),
                                self.remote,
                                VersionPolicy::exact(version),
                                tls,
                                name,
                            )
                            .await
                        }
                    }
                    .map_err(|_| ClientError::Tls)?;
                    dial::confirm(&mut session).await.map_err(dial_error)?;
                    Ok::<_, ClientError>(session)
                })
                .await
                .map_err(|_| ClientError::Timeout)??
            } else {
                // Keep v1 for the still-compatible REALITY server. A version
                // restart for plain TLS must authenticate version_information.
                let policy = if self.identity_quic.is_some() {
                    VersionPolicy::exact(Version::V1)
                } else {
                    VersionPolicy::both()
                };
                dial::connect(self.remote, name, tls, None, policy, self.connect_timeout)
                    .await
                    .map_err(dial_error)?
                    .1
            };
            if let Some(pin) = self.certificate_pin {
                pin.verify(session.peer_leaf().ok_or(ClientError::Tls)?)?;
            }
            Ok(session)
        })
    }

    /// Check only the configured peer, PKI/identity, ALPN and optional pin.
    /// No HTTP stream, credential or application byte is sent by this probe.
    pub(crate) async fn probe(&self) -> Result<(), ClientError> {
        let session = self.native_connection().await?;
        dial::close_probe(session).await.map_err(dial_error)
    }

    pub(crate) async fn warm_carrier(&self) -> Result<(), ClientError> {
        if !self.reuse_connections || self.certificate_pin.is_some() { return Ok(()); }
        let route = crate::network_scope::observe(self.remote);
        self.pool.warm(route, |connection| !connection.driver.0.is_finished(),
            self.connect_verified(crate::diagnostics::next_id()),
            || route.is_some() && crate::network_scope::observe(self.remote) == route,
        ).await
    }

    async fn connect_verified(&self, operation: u64) -> Result<H3Connection, ClientError> {
        let session = self.native_connection().await?;
        let (transport, key) =
            h3_adapter::NativeConnection::start(session).map_err(|_| ClientError::Tls)?;
        let binding = self.certificate_pin.map(|_| key);
        #[cfg(test)]
        let test_opener = transport.test_opener();
        crate::diag!(
            Trace,
            "client.h3",
            "quic_tls_bbr_verified",
            "op" = Value::Count(operation)
        );
        let mut builder = h3::client::builder();
        builder.max_field_section_size(u64::from(crate::transport_policy::MAX_HEADER_LIST_BYTES));
        let (mut driver, sender) = builder
            .build::<_, _, Bytes>(transport)
            .await
            .map_err(|_| ClientError::Http3)?;
        // h3 closes the connection when the final SendRequest is dropped.
        // Keep a sender alive with the owned driver throughout relay.
        let keep_sender = sender.clone();
        let driver = Driver(tokio::spawn(async move {
            let _keep_sender = keep_sender;
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        }));
        Ok(H3Connection {
            sender: std::sync::Mutex::new(sender),
            driver,
            binding,
            #[cfg(test)]
            test_opener,
        })
    }

    async fn open_inner(
        &self,
        open: &Frame,
        operation: u64,
        stream_up: bool,
        stage: &mut crate::split_http::HelloOutcome,
    ) -> Result<H3Tunnel, ClientError> {
        let route = crate::network_scope::observe(self.remote);
        let reusable = self.reuse_connections && self.certificate_pin.is_none();
        let mut lease = self
            .pool
            .acquire(
                route,
                reusable,
                |connection| !connection.driver.0.is_finished(),
                self.connect_verified(operation),
            )
            .await?;
        // A network transition during a queued/dialing admission invalidates
        // reuse before any HTTP headers or bearer are sent.
        if route.is_some() && crate::network_scope::observe(self.remote) != route {
            lease.retire();
            return Err(ClientError::Io);
        }
        if !lease.accepting_new_streams() {
            return Err(ClientError::Http3);
        }
        // Only a protocol-level graceful refusal during HTTP admission can
        // retry. The lease's Drop removes the draining connection from reuse
        // while other admitted leases retain it.
        let mut admission_error = |error: h3::error::StreamError| {
            if matches!(&error, h3::error::StreamError::RemoteClosing { .. })
                || matches!(&error, h3::error::StreamError::RemoteTerminate { code, .. }
                    if *code == h3::error::Code::H3_REQUEST_REJECTED)
            {
                lease.retire();
                *stage = crate::split_http::HelloOutcome::Draining;
            }
            ClientError::Http3
        };
        let connection = lease.connection();
        let binding = connection.binding.as_ref();
        let mut sender = connection
            .sender
            .lock()
            .map_err(|_| ClientError::Http3)?
            .clone();
        let pair_id = lease.id();
        let (response, mut tx, mut rx) = if stream_up {
            use crate::split_http::{self, Leg};
            let mut download = sender
                .send_request(crate::channel_binding::attach(
                    binding,
                    self.padding.request(split_http::request_for(
                        self.identity_routes.as_ref().or(self.own_routes.as_ref()),
                        &self.uri,
                        Leg::Download,
                        &self.authorization,
                        pair_id,
                    )?)?,
                )?)
                .await
                .map_err(&mut admission_error)?;
            download.finish().await.map_err(&mut admission_error)?;
            let mut upload = sender
                .send_request(crate::channel_binding::attach(
                    binding,
                    self.padding.request(split_http::request_for(
                        self.identity_routes.as_ref().or(self.own_routes.as_ref()),
                        &self.uri,
                        Leg::Upload,
                        &self.authorization,
                        pair_id,
                    )?)?,
                )?)
                .await
                .map_err(&mut admission_error)?;
            let upload_response = upload.recv_response().await.map_err(&mut admission_error)?;
            split_http::check_status(upload_response.status())?;
            if upload
                .recv_data()
                .await
                .map_err(|_| ClientError::Http3)?
                .is_some()
                || upload
                    .recv_trailers()
                    .await
                    .map_err(|_| ClientError::Http3)?
                    .is_some()
            {
                return Err(ClientError::Protocol);
            }
            let response = download
                .recv_response()
                .await
                .map_err(&mut admission_error)?;
            let (tx, _) = upload.split();
            let (_, rx) = download.split();
            (response, tx, rx)
        } else {
            let request = Request::post(self.uri.clone())
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::AUTHORIZATION, self.authorization.clone())
                .body(())
                .map_err(|_| ClientError::Configuration)?;
            let mut stream = sender
                .send_request(crate::channel_binding::attach(
                    binding,
                    self.padding.request(request)?,
                )?)
                .await
                .map_err(&mut admission_error)?;
            let response = stream.recv_response().await.map_err(&mut admission_error)?;
            let (tx, rx) = stream.split();
            (response, tx, rx)
        };
        crate::diag!(
            Trace,
            "client.h3",
            "response_received",
            "op" = Value::Count(operation),
            "status" = Value::Count(u64::from(response.status().as_u16()))
        );
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(ClientError::Unauthorized);
            }
            other => return Err(ClientError::Rejected(other.as_u16())),
        }

        let mut decoder = Incoming::default();
        let mut state = Session::new(Role::Client);
        let hello = Frame::Hello {
            version: protocol::VERSION,
            capabilities: protocol::CAP_PADDING,
        };
        state
            .apply(Direction::Send, &hello)
            .map_err(|_| ClientError::Protocol)?;
        send(&mut tx, &hello).await?;
        let ack = if self.auto_mode.is_some() && !stream_up {
            match timeout(crate::split_http::HELLO_ACK_TIMEOUT, decoder.next(&mut rx)).await {
                Ok(result) => result?,
                Err(_) => {
                    if !decoder.eof && decoder.decoder.pending_len() == 0 {
                        *stage = crate::split_http::HelloOutcome::Silent;
                    }
                    return Err(ClientError::Timeout);
                }
            }
        } else {
            decoder.next(&mut rx).await?
        }
        .ok_or(ClientError::Protocol)?;
        state
            .apply(Direction::Receive, &ack)
            .map_err(|_| ClientError::Protocol)?;
        crate::diag!(
            Trace,
            "client.h3",
            "hello_ack_received",
            "op" = Value::Count(operation)
        );
        let Frame::HelloAck {
            accepted_capabilities,
            ..
        } = ack
        else {
            return Err(ClientError::Protocol);
        };
        *stage = crate::split_http::HelloOutcome::Acked;
        if let Some(padding) = self.padding.frame(accepted_capabilities)? {
            state
                .apply(Direction::Send, &padding)
                .map_err(|_| ClientError::Protocol)?;
            send(&mut tx, &padding).await?;
        }
        state
            .apply(Direction::Send, open)
            .map_err(|_| ClientError::Protocol)?;
        send(&mut tx, open).await?;
        let answer = loop {
            let frame = decoder.next(&mut rx).await?.ok_or(ClientError::Protocol)?;
            state
                .apply(Direction::Receive, &frame)
                .map_err(|_| ClientError::Protocol)?;
            if matches!(frame, Frame::Padding(_)) {
                // Padding must not reset the enclosing OPEN deadline or
                // monopolize the task when frames are already buffered.
                tokio::task::yield_now().await;
                continue;
            }
            break frame;
        };
        match answer {
            Frame::OpenOk if state.tunnel_open() => {
                lease.admitted();
                Ok(H3Tunnel {
                    operation,
                    stream_up,
                    tx,
                    rx,
                    decoder,
                    state,
                    _lease: lease,
                })
            }
            Frame::OpenError(code) => {
                crate::diag!(
                    Warn,
                    "client.h3",
                    "remote_open_refused",
                    "op" = Value::Count(operation),
                    "code" = Value::Count(code as u64)
                );
                Err(ClientError::Open(code))
            }
            _ => Err(ClientError::Protocol),
        }
    }
}

fn dial_error(error: dial::Error) -> ClientError {
    use crate::net::error::{EndpointUnavailable, FailureClass};
    match error.class() {
        FailureClass::Configuration => ClientError::Configuration,
        FailureClass::LocalSetup => ClientError::Io,
        FailureClass::AmbiguousTimeout => ClientError::Timeout,
        FailureClass::EndpointUnavailable(EndpointUnavailable::NoResponse) => ClientError::QuicUnreachable,
        FailureClass::EndpointUnavailable(EndpointUnavailable::Refused) => ClientError::QuicEndpointNetworkRefused,
        _ => ClientError::Tls,
    }
}

impl OpenAdapter for H3Client {
    type Tunnel = H3Tunnel;
    const KIND: CarrierKind = CarrierKind::H3;
    fn explicit_stream_up(&self) -> bool { self.stream_up }
    fn automatic_mode(&self) -> Option<&crate::split_http::AutoMode> { self.auto_mode.as_ref() }
    async fn open_attempt<'a>(&'a self, open: &'a Frame, operation: u64, stream_up: bool, stage: &'a mut crate::split_http::HelloOutcome) -> Result<H3Tunnel, ClientError> {
        self.open_inner(open, operation, stream_up, stage).await
    }
}

struct H3Connection {
    sender: std::sync::Mutex<h3::client::SendRequest<h3_adapter::Opener, Bytes>>,
    driver: Driver,
    binding: Option<crate::channel_binding::Key>,
    #[cfg(test)]
    test_opener: h3_adapter::Opener,
}

struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A tunnel retains a lease on its verified QUIC connection.
/// Its constructor is private and reachable only after valid OPEN_OK.
pub struct H3Tunnel {
    operation: u64,
    stream_up: bool,
    tx: Tx,
    rx: Rx,
    decoder: Incoming,
    state: Session,
    _lease: crate::connection_pool::Lease<H3Connection>,
}

impl H3Tunnel {
    pub(crate) async fn relay_udp(
        mut self, first: Option<Vec<u8>>, upload: tokio::sync::mpsc::Receiver<Vec<u8>>,
        download: tokio::sync::mpsc::Sender<Vec<u8>>, flow: Option<&crate::routing::flow::FlowLease>,
    ) -> Result<(), ClientError> {
        let mut reader = H3FrameReader { decoder: &mut self.decoder, stream: &mut self.rx };
        session::relay_udp(CarrierKind::H3, &self.state, &mut self.tx, &mut reader, first, upload, download, flow).await
    }

    pub(crate) fn opened_stream_up(&self) -> bool {
        self.stream_up
    }
    #[cfg(test)]
    pub(crate) async fn rebind_for_test(
        &self,
        socket: std::net::UdpSocket,
    ) -> Result<(), ClientError> {
        self._lease
            .connection()
            .test_opener
            .rebind_for_test(socket)
            .await
            .map_err(|_| ClientError::Io)
    }

    /// True when both tunnels share one verified transport connection.
    /// Does not reveal peer addresses, credentials or connection identifiers.
    pub fn shares_transport_with(&self, other: &Self) -> bool {
        self._lease.shares_connection(&other._lease)
    }

    pub async fn relay<S>(self, local: S) -> Result<(), ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.relay_guarded(local, None).await
    }

    pub(crate) async fn relay_guarded<S>(
        mut self, local: S, flow: Option<&crate::routing::flow::FlowLease>,
    ) -> Result<(), ClientError>
    where S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut reader = H3FrameReader { decoder: &mut self.decoder, stream: &mut self.rx };
        let lease = &self._lease;
        session::relay_tcp(CarrierKind::H3, self.operation, &mut self.state, &mut self.tx, &mut reader, local, flow, |bytes| lease.record_data(bytes)).await
    }
}

impl FrameWriter for Tx {
    async fn send<'a>(&'a mut self, frame: &'a Frame) -> Result<(), ClientError> {
        send(self, frame).await
    }
    async fn finish(&mut self) -> Result<(), ClientError> {
        send(self, &Frame::Fin).await?;
        timeout(IO_TIMEOUT, RequestStream::finish(self)).await.map_err(|_| ClientError::Timeout)?.map_err(|_| ClientError::Http3)
    }
}

struct H3FrameReader<'a> {
    decoder: &'a mut Incoming,
    stream: &'a mut Rx,
}
impl FrameReader for H3FrameReader<'_> {
    async fn next(&mut self) -> Result<Option<Frame>, ClientError> { self.decoder.next(self.stream).await }
}

#[derive(Default)]
struct Incoming {
    decoder: Decoder,
    ready: VecDeque<Frame>,
    eof: bool,
}

impl Incoming {
    async fn next<S: quic::RecvStream>(
        &mut self,
        stream: &mut RequestStream<S, Bytes>,
    ) -> Result<Option<Frame>, ClientError> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            let data = stream.recv_data().await.map_err(|_| ClientError::Http3)?;
            let Some(mut data) = data else {
                self.eof = true;
                self.decoder.finish().map_err(|_| ClientError::Protocol)?;
                let trailers = timeout(IO_TIMEOUT, stream.recv_trailers())
                    .await
                    .map_err(|_| ClientError::Timeout)?
                    .map_err(|_| ClientError::Http3)?;
                if trailers.is_some() {
                    return Err(ClientError::Protocol);
                }
                return Ok(None);
            };
            while data.has_remaining() {
                let n = data.remaining().min(4096);
                let bytes = data.copy_to_bytes(n);
                self.ready.extend(
                    self.decoder
                        .feed(&bytes)
                        .map_err(|_| ClientError::Protocol)?,
                );
            }
        }
    }
}

async fn send<S: quic::SendStream<Bytes>>(
    stream: &mut RequestStream<S, Bytes>,
    frame: &Frame,
) -> Result<(), ClientError> {
    let bytes = Bytes::from(protocol::encode(frame).map_err(|_| ClientError::Protocol)?);
    timeout(IO_TIMEOUT, stream.send_data(bytes))
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(|_| ClientError::Http3)
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use crate::security_profile::CertificatePin;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    async fn check_no_application_streams(server: &quinn::Endpoint) {
        let incoming = server.accept().await.unwrap();
        // A credential-free probe may close immediately after the verified
        // client handshake, before the server confirms its final flight.
        if let Ok(Ok(connection)) = timeout(Duration::from_secs(3), incoming).await {
            assert!(!matches!(
                timeout(Duration::from_millis(250), connection.accept_bi()).await,
                Ok(Ok(_))
            ));
            assert!(!matches!(
                timeout(Duration::from_millis(250), connection.accept_uni()).await,
                Ok(Ok(_))
            ));
        }
    }

    #[tokio::test]
    async fn background_probe_preserves_pki_hostname_and_pin() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server = crate::quinn_reference::server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![der.clone()],
            key.into(),
        )
        .unwrap();
        let remote = server.local_addr().unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let mut wrong_roots = RootCertStore::empty();
        wrong_roots.add(other.cert.der().clone()).unwrap();
        let token = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
        let pin = CertificatePin::from_der(der.as_ref());
        let wrong_pin = CertificatePin::from_der(other.cert.der().as_ref());
        let cases = [
            ("localhost", roots.clone(), pin, Ok(())),
            ("localhost", roots.clone(), wrong_pin, Err(ClientError::Tls)),
            ("localhost", wrong_roots, pin, Err(ClientError::Tls)),
            ("wrong.invalid", roots, pin, Err(ClientError::Tls)),
        ];
        for (name, roots, pin, expected) in cases {
            let client = H3Client::new(remote, name, &token, roots)
                .unwrap()
                .with_certificate_pin(Some(pin))
                .unwrap();
            let (result, ()) = timeout(Duration::from_secs(15), async {
                tokio::join!(client.probe(), check_no_application_streams(&server))
            })
            .await
            .expect("bounded native handshake probe");
            assert_eq!(result, expected);
        }
    }
}
