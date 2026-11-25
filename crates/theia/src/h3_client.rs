//! Explicit H3 client core with bounded per-profile connection reuse.
use crate::{
    client::{bearer_header, error_kind, ClientError},
    diagnostics::{self, Value},
    protocol::{self, Address, Decoder, Direction, Frame, Role, Session},
    quic_transport::{ObservedEndpoint, QuicError},
};
use bytes::{Buf, Bytes};
use h3::{client::RequestStream, quic};
use http::{header, HeaderValue, Request, StatusCode, Uri};
use rustls::{pki_types::ServerName, RootCertStore};
use std::{collections::VecDeque, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};

const OPEN_TIMEOUT: Duration = Duration::from_secs(60);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEADERS: u64 = 8192;
type Tx = RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type Rx = RequestStream<h3_quinn::RecvStream, Bytes>;

pub struct H3Client {
    remote: SocketAddr,
    name: String,
    uri: Uri,
    authorization: HeaderValue,
    roots: RootCertStore,
    identity_quic: Option<quinn::ClientConfig>,
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
        if remote.port() == 0 || remote.ip().is_unspecified() || roots.is_empty() {
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
            roots,
            identity_quic: None,
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
        let quic = crate::identity_tls::quic_client(&d.scope, value.signer())
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
        let quic = crate::identity_tls::admitted_quic_client(value, secret)
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
        let quic = crate::identity_tls::admitted_quic_client(value, secret)
            .map_err(|_| ClientError::Tls)?;
        Self::identity_carrier(remote, name, token, value, quic)
    }

    fn identity_carrier(
        remote: SocketAddr,
        name: &str,
        token: &str,
        value: &crate::descriptor::Verified,
        quic: quinn::ClientConfig,
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
            roots: RootCertStore::empty(),
            identity_quic: Some(quic),
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
        let operation = diagnostics::next_id();
        crate::diag!(
            Debug,
            "client.h3",
            "open_begin",
            "op" = Value::Count(operation)
        );
        let open = Frame::OpenTcp { address, port };
        protocol::encode(&open).map_err(|_| ClientError::Configuration)?;
        let result = timeout(OPEN_TIMEOUT, self.open_selected(open, operation))
            .await
            .map_err(|_| ClientError::Timeout)
            .and_then(|result| result);
        match &result {
            Ok(_) => crate::diag!(
                Debug,
                "client.h3",
                "open_confirmed",
                "op" = Value::Count(operation)
            ),
            Err(error) => crate::diag!(
                Warn,
                "client.h3",
                "open_failed",
                "op" = Value::Count(operation),
                "reason" = Value::Label(error_kind(error))
            ),
        }
        result
    }

    /// A full authenticated transport handshake, shared by tunnel opens and
    /// idle-cache rechecks. No HTTP request or bearer is sent here.
    async fn verified_connection(
        &self,
    ) -> Result<(ObservedEndpoint, quinn::Connection), ClientError> {
        let bind = if self.remote.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let endpoint = match &self.identity_quic {
            Some(config) => ObservedEndpoint::with_config(bind, config.clone()),
            None => ObservedEndpoint::new(bind, self.roots.clone()),
        }
        .map_err(quic_error)?;
        // No credential/request data until verified full handshake and BBR.
        let connection = endpoint
            .connect(self.remote, &self.name, self.connect_timeout)
            .await
            .map_err(quic_error)?;
        if let Some(pin) = self.certificate_pin {
            let chain = connection
                .peer_identity()
                .ok_or(ClientError::Tls)?
                .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .map_err(|_| ClientError::Tls)?;
            pin.verify(chain.first().ok_or(ClientError::Tls)?.as_ref())?;
        }
        Ok((endpoint, connection))
    }

    /// Check only the configured peer, PKI, ALPN, optional pin and BBR.
    /// Dropping the endpoint closes this probe; it never opens a tunnel.
    pub(crate) async fn probe(&self) -> Result<(), ClientError> {
        self.verified_connection().await.map(|_| ())
    }

    async fn open_selected(&self, open: Frame, operation: u64) -> Result<H3Tunnel, ClientError> {
        use crate::split_http::HelloOutcome;
        let mut stage = HelloOutcome::Pending;
        let Some(mode) = &self.auto_mode else {
            return self
                .open_mode(&open, operation, self.stream_up, &mut stage)
                .await;
        };
        let ticket = mode.select()?;
        let stream_up = ticket.stream_up;
        let result = self
            .open_mode(&open, operation, stream_up, &mut stage)
            .await;
        if !mode.after_attempt(ticket, stream_up, stage)? {
            return result;
        }
        // The first attempt is fully dropped and never sent OPEN_TCP.
        crate::diag!(Debug, "client.h3", "xhttp_pre_open_stream_up_retry");
        let mut stage = HelloOutcome::Pending;
        let result = self.open_mode(&open, operation, true, &mut stage).await;
        mode.after_attempt(ticket, true, stage)?;
        // The original H3 attempt already completed HTTP admission.
        // UDP silence in the second attempt must not authorize H2 fallback.
        match result {
            Err(ClientError::QuicUnreachable | ClientError::QuicEndpointNetworkRefused) => {
                Err(ClientError::Timeout)
            }
            other => other,
        }
    }

    /// At most one fresh connection after an explicit graceful GOAWAY
    /// before any HELLO/OPEN. Never replay a body or change XHTTP mode.
    async fn open_mode(
        &self,
        open: &Frame,
        operation: u64,
        stream_up: bool,
        stage: &mut crate::split_http::HelloOutcome,
    ) -> Result<H3Tunnel, ClientError> {
        use crate::split_http::HelloOutcome;
        let result = self.open_inner(open, operation, stream_up, stage).await;
        if *stage != HelloOutcome::Draining {
            return result;
        }
        *stage = HelloOutcome::Pending;
        let result = self.open_inner(open, operation, stream_up, stage).await;
        match result {
            Err(ClientError::QuicUnreachable | ClientError::QuicEndpointNetworkRefused) => {
                Err(ClientError::Timeout)
            }
            other => other,
        }
    }

    async fn connect_verified(&self, operation: u64) -> Result<H3Connection, ClientError> {
        let (endpoint, connection) = self.verified_connection().await?;
        let binding = if self.certificate_pin.is_some() {
            let mut key = zeroize::Zeroizing::new([0u8; 32]);
            connection
                .export_keying_material(
                    &mut key[..],
                    crate::channel_binding::LABEL,
                    crate::channel_binding::H3,
                )
                .map_err(|_| ClientError::Tls)?;
            Some(key)
        } else {
            None
        };
        crate::diag!(
            Trace,
            "client.h3",
            "quic_tls_bbr_verified",
            "op" = Value::Count(operation)
        );
        let mut builder = h3::client::builder();
        builder.max_field_section_size(MAX_HEADERS);
        let (mut driver, sender) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
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
            _endpoint: endpoint,
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
            if matches!(error, h3::error::StreamError::RemoteClosing { .. }) {
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

fn quic_error(error: QuicError) -> ClientError {
    match error {
        QuicError::Configuration => ClientError::Configuration,
        QuicError::Bind => ClientError::Io,
        QuicError::Timeout => ClientError::Timeout,
        QuicError::Unreachable => ClientError::QuicUnreachable,
        QuicError::EndpointNetworkRefused => ClientError::QuicEndpointNetworkRefused,
        QuicError::Handshake | QuicError::Alpn => ClientError::Tls,
        QuicError::CongestionController => ClientError::Http3,
    }
}

struct H3Connection {
    sender: std::sync::Mutex<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    driver: Driver,
    binding: Option<crate::channel_binding::Key>,
    _endpoint: ObservedEndpoint,
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
    tx: Tx,
    rx: Rx,
    decoder: Incoming,
    state: Session,
    _lease: crate::connection_pool::Lease<H3Connection>,
}

impl H3Tunnel {
    #[cfg(test)]
    pub(crate) fn rebind_for_test(&self, socket: std::net::UdpSocket) -> Result<(), ClientError> {
        self._lease
            .connection()
            ._endpoint
            .endpoint
            .rebind(socket)
            .map_err(|_| ClientError::Io)
    }

    /// True when both tunnels share one verified transport connection.
    /// Does not reveal peer addresses, credentials or connection identifiers.
    pub fn shares_transport_with(&self, other: &Self) -> bool {
        self._lease.shares_connection(&other._lease)
    }

    pub async fn relay<S>(mut self, local: S) -> Result<(), ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let operation = self.operation;
        crate::diag!(
            Debug,
            "client.h3",
            "relay_begin",
            "op" = Value::Count(operation)
        );
        let (mut read, mut write) = tokio::io::split(local);
        let tx = &mut self.tx;
        let rx = &mut self.rx;
        let decoder = &mut self.decoder;
        let mut upload_state = self.state.clone();
        let mut download_state = self.state.clone();
        let activity = crate::relay_liveness::Activity::new();
        let (upload_done, upload_finished) = tokio::sync::oneshot::channel();
        let upload = async {
            let mut buffer = [0; 4096];
            loop {
                let n = read.read(&mut buffer).await.map_err(|_| ClientError::Io)?;
                let frame = if n == 0 {
                    Frame::Fin
                } else {
                    Frame::Data(buffer[..n].to_vec())
                };
                crate::diag!(
                    Trace,
                    "client.h3",
                    "upload_frame",
                    "op" = Value::Count(operation),
                    "bytes" = Value::Count(n as u64),
                    "fin" = Value::Flag(n == 0)
                );
                upload_state
                    .apply(Direction::Send, &frame)
                    .map_err(|_| ClientError::Protocol)?;
                send(tx, &frame).await?;
                if n == 0 {
                    timeout(IO_TIMEOUT, tx.finish())
                        .await
                        .map_err(|_| ClientError::Timeout)?
                        .map_err(|_| ClientError::Http3)?;
                    activity.half_closed();
                    let _ = upload_done.send(());
                    return Ok::<(), ClientError>(());
                }
                self._lease.record_data(n);
                activity.data(n);
            }
        };
        let download = async {
            loop {
                let frame = decoder.next(rx).await?.ok_or(ClientError::Protocol)?;
                download_state
                    .apply(Direction::Receive, &frame)
                    .map_err(|_| ClientError::Protocol)?;
                match frame {
                    Frame::Padding(_) => tokio::task::yield_now().await,
                    Frame::Data(data) => {
                        crate::diag!(
                            Trace,
                            "client.h3",
                            "download_frame",
                            "op" = Value::Count(operation),
                            "bytes" = Value::Count(data.len() as u64)
                        );
                        timeout(IO_TIMEOUT, write.write_all(&data))
                            .await
                            .map_err(|_| ClientError::Timeout)?
                            .map_err(|_| ClientError::Io)?;
                        self._lease.record_data(data.len());
                        activity.data(data.len());
                    }
                    Frame::Fin => {
                        crate::diag!(
                            Debug,
                            "client.h3",
                            "download_fin",
                            "op" = Value::Count(operation)
                        );
                        timeout(IO_TIMEOUT, write.shutdown())
                            .await
                            .map_err(|_| ClientError::Timeout)?
                            .map_err(|_| ClientError::Io)?;
                        activity.half_closed();
                        break;
                    }
                    Frame::Abort(code) => return Err(ClientError::Open(code)),
                    _ => return Err(ClientError::Protocol),
                }
            }
            if crate::relay_liveness::receive_tail(
                async {
                    loop {
                        let frame = decoder.next(rx).await?;
                        if let Some(padding @ Frame::Padding(_)) = &frame {
                            if activity.both_finished() {
                                return Err(ClientError::Protocol);
                            }
                            download_state
                                .apply(Direction::Receive, padding)
                                .map_err(|_| ClientError::Protocol)?;
                            tokio::task::yield_now().await;
                            continue;
                        }
                        return Ok(frame);
                    }
                },
                upload_finished,
                ClientError::Timeout,
            )
            .await?
            .is_some()
            {
                return Err(ClientError::Protocol);
            }
            Ok::<(), ClientError>(())
        };
        if let Err(error) = activity.run(upload, download, ClientError::Timeout).await {
            crate::diag!(
                Warn,
                "client.h3",
                "relay_failed",
                "op" = Value::Count(operation),
                "reason" = Value::Label(error_kind(&error))
            );
            return Err(error);
        }
        crate::diag!(
            Debug,
            "client.h3",
            "relay_completed",
            "op" = Value::Count(operation)
        );
        self.state
            .apply(Direction::Send, &Frame::Fin)
            .map_err(|_| ClientError::Protocol)?;
        self.state
            .apply(Direction::Receive, &Frame::Fin)
            .map_err(|_| ClientError::Protocol)?;
        self.state.finish().map_err(|_| ClientError::Protocol)
    }
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
        if let Ok(connection) = incoming.await {
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
        let server = crate::quic_transport::server_endpoint(
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
