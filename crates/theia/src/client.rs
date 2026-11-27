//! Authenticated H2 client transport used by the local proxy listeners.
//! Trust anchors are supplied by the caller; this API never disables PKI.
use crate::diagnostics::{self, Value};
use crate::protocol::{self, Address, Decoder, Direction, ErrorCode, Frame, Role, Session};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use http::{header, HeaderValue, Request, StatusCode};
use rustls::{pki_types::ServerName, RootCertStore};
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::xhttp::session::{self, CarrierKind, FrameReader, FrameWriter, OpenAdapter, OPEN_TIMEOUT, IO_TIMEOUT};

// Preserve the public client error API; the implementation is transport-neutral.
pub use crate::net::error::ClientError;
pub(crate) use crate::net::error::error_kind;

pub(crate) fn bearer_header(token: &str) -> Result<HeaderValue, ClientError> {
    if token.len() != 43 || token.contains('=') {
        return Err(ClientError::Configuration);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ClientError::Configuration)?;
    if raw.len() != 32 || URL_SAFE_NO_PAD.encode(&raw) != token {
        return Err(ClientError::Configuration);
    }
    let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| ClientError::Configuration)?;
    authorization.set_sensitive(true);
    Ok(authorization)
}

#[derive(Clone, Copy)]
enum H2WireShape {
    Standard,
    /// Measured partial Chromium-like HTTP/2 features. Strict bounded
    /// credits and the library's pseudo-header order are intentionally kept.
    BrowserH2V1,
}

enum H2Tls {
    Rustls(TlsConnector),
    #[cfg(feature = "experimental-btls-h2")]
    Btls {
        server_name: String,
        trusted_ca_pem: Arc<[u8]>,
    },
}

/// One explicit H2 endpoint with independently verified TLS/H2 connections. The default backend remains rustls; an experimental
/// BoringSSL backend is only available through an explicit feature-gated API.
pub struct H2Client {
    endpoint: String,
    server_name: ServerName<'static>,
    uri: http::Uri,
    authorization: HeaderValue,
    connector: H2Tls,
    wire_shape: H2WireShape,
    certificate_pin: Option<crate::security_profile::CertificatePin>,
    identity_routes: Option<crate::split_http::IdentityRoutes>,
    padding: crate::descriptor::Padding,
    own_routes: Option<crate::split_http::IdentityRoutes>,
    stream_up: bool,
    auto_mode: Option<crate::split_http::AutoMode>,
    pool: crate::connection_pool::Pool<H2Connection>,
    reuse_connections: bool,
}

impl H2Client {
    pub fn new(
        endpoint: &str,
        name: &str,
        token: &str,
        roots: RootCertStore,
    ) -> Result<Self, ClientError> {
        Self::new_with_trust(endpoint, name, token, &crate::own_tls::Trust::Roots(roots))
    }

    pub(crate) fn new_with_trust(
        endpoint: &str,
        name: &str,
        token: &str,
        trust: &crate::own_tls::Trust,
    ) -> Result<Self, ClientError> {
        if !trust.usable() {
            return Err(ClientError::Configuration);
        }
        let tls = trust.tls(crate::transport_policy::Carrier::H2).map_err(|_| ClientError::Tls)?;
        Self::with_connector(
            endpoint,
            name,
            token,
            H2Tls::Rustls(TlsConnector::from(Arc::new(tls))),
            H2WireShape::Standard,
        )
    }

    pub(crate) fn identity_fixture(
        remote: std::net::SocketAddr,
        token: &str,
        value: &crate::descriptor::Verified,
    ) -> Result<Self, ClientError> {
        let d = value.descriptor();
        if !remote.ip().is_loopback()
            || d.scope.endpoint != remote.to_string()
            || !value.effective_modes().h2
        {
            return Err(ClientError::Configuration);
        }
        let tls = crate::identity_tls::client_tls(
            &d.scope,
            value.signer(),
            crate::identity_tls::Branch::H2,
        )
        .map_err(|_| ClientError::Tls)?;
        Self::identity_carrier(remote, "localhost", token, value, tls)
    }

    pub(crate) fn admitted_fixture(
        remote: std::net::SocketAddr,
        token: &str,
        value: &crate::descriptor::Verified,
        secret: Arc<crate::reality_admission::Secret>,
    ) -> Result<Self, ClientError> {
        let d = value.descriptor();
        if !remote.ip().is_loopback()
            || d.scope.endpoint != remote.to_string()
            || !value.effective_modes().h2
        {
            return Err(ClientError::Configuration);
        }
        let name = &d
            .references
            .get(usize::from(d.active_reference))
            .ok_or(ClientError::Configuration)?
            .server_name;
        let tls = crate::identity_tls::admitted_client_tls(
            value,
            crate::identity_tls::Branch::H2,
            secret,
        )
        .map_err(|_| ClientError::Tls)?;
        Self::identity_carrier(remote, name, token, value, tls)
    }

    pub(crate) fn admitted_runtime(
        remote: std::net::SocketAddr,
        token: &str,
        value: &crate::descriptor::Verified,
        secret: Arc<crate::reality_admission::Secret>,
    ) -> Result<Self, ClientError> {
        let d = value.descriptor();
        if remote.port() == 0 || remote.ip().is_unspecified() || !value.effective_modes().h2 {
            return Err(ClientError::Configuration);
        }
        let name = &d
            .references
            .get(usize::from(d.active_reference))
            .ok_or(ClientError::Configuration)?
            .server_name;
        let tls = crate::identity_tls::admitted_client_tls(
            value,
            crate::identity_tls::Branch::H2,
            secret,
        )
        .map_err(|_| ClientError::Tls)?;
        Self::identity_carrier(remote, name, token, value, tls)
    }

    fn identity_carrier(
        remote: std::net::SocketAddr,
        name: &str,
        token: &str,
        value: &crate::descriptor::Verified,
        tls: rustls::ClientConfig,
    ) -> Result<Self, ClientError> {
        let d = value.descriptor();
        let mut client = Self::with_connector(
            &remote.to_string(),
            name,
            token,
            H2Tls::Rustls(TlsConnector::from(Arc::new(tls))),
            H2WireShape::Standard,
        )?;
        let routes = crate::split_http::IdentityRoutes::new(&d.path_prefix)?;
        client.uri = http::Uri::builder()
            .scheme("https")
            .authority(name)
            .path_and_query(routes.single.as_str())
            .build()
            .map_err(|_| ClientError::Configuration)?;
        client.identity_routes = Some(routes);
        client.padding = d.padding.clone();
        client.own_routes = None;
        client.pool = crate::connection_pool::Pool::with_rotation(&value.descriptor().rotation);
        let modes = value.effective_modes();
        client = if modes.stream_one && modes.stream_up {
            client.with_auto_stream_up(Duration::from_secs(900))?
        } else {
            client.with_stream_up(modes.stream_up)?
        };
        Ok(client)
    }

    /// Authenticated descriptor GET; never send a bearer before the pinned
    /// identity handshake, never interpret the body as a routing command.
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
            let sender = connection
                .sender
                .lock()
                .map_err(|_| ClientError::Http2)?
                .clone();
            let mut sender = sender.ready().await.map_err(|_| ClientError::Http2)?;
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
            let uri = http::Uri::from_parts(parts).map_err(|_| ClientError::Configuration)?;
            let request = Request::get(uri)
                .header(header::AUTHORIZATION, self.authorization.clone())
                .body(())
                .map_err(|_| ClientError::Configuration)?;
            let (response, _) = sender
                .send_request(self.padding.request(request)?, true)
                .map_err(|_| ClientError::Http2)?;
            let response = response.await.map_err(|_| ClientError::Http2)?;
            crate::split_http::check_status(response.status())?;
            let expected = crate::identity_data::validate_descriptor_headers(response.headers())?;
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|_| ClientError::Http2)?;
                crate::identity_data::append_descriptor(&mut bytes, &chunk, expected)?;
                body.flow_control()
                    .release_capacity(chunk.len())
                    .map_err(|_| ClientError::Http2)?;
            }
            if body
                .trailers()
                .await
                .map_err(|_| ClientError::Http2)?
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
            let route = self
                .endpoint
                .parse()
                .ok()
                .and_then(crate::network_scope::observe);
            let reusable = self.reuse_connections
                && self.certificate_pin.is_none()
                && matches!(&self.connector, H2Tls::Rustls(_));
            let mut lease = self
                .pool
                .acquire(
                    route,
                    reusable,
                    |connection| !connection.driver.0.is_finished(),
                    self.connect_verified(diagnostics::next_id()),
                )
                .await?;
            if route.is_some()
                && self
                    .endpoint
                    .parse()
                    .ok()
                    .and_then(crate::network_scope::observe)
                    != route
            {
                lease.retire();
                return Err(ClientError::Io);
            }
            if !lease.accepting_new_streams() {
                return Err(ClientError::Http2);
            }
            let connection = lease.connection();
            let sender = connection
                .sender
                .lock()
                .map_err(|_| ClientError::Http2)?
                .clone();
            let mut sender = sender.ready().await.map_err(|_| ClientError::Http2)?;
            let mut parts = self.uri.clone().into_parts();
            parts.path_and_query = Some(
                routes
                    .routing
                    .parse()
                    .map_err(|_| ClientError::Configuration)?,
            );
            let uri = http::Uri::from_parts(parts).map_err(|_| ClientError::Configuration)?;
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
            let (response, _) = sender
                .send_request(request, true)
                .map_err(|_| ClientError::Http2)?;
            let response = response.await.map_err(|_| ClientError::Http2)?;
            crate::split_http::check_status(response.status())?;
            let expected = crate::routing::exchange::validate_headers(response.headers())?;
            if domain.is_some() && expected > crate::routing::exchange::DNS_LIMIT {
                return Err(ClientError::Protocol);
            }
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|_| ClientError::Http2)?;
                crate::routing::exchange::append(&mut bytes, &chunk, expected)?;
                body.flow_control()
                    .release_capacity(chunk.len())
                    .map_err(|_| ClientError::Http2)?;
            }
            if body
                .trailers()
                .await
                .map_err(|_| ClientError::Http2)?
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

    /// Experimental API only: build a separately verified BoringSSL connector
    /// with one explicit CA PEM. Not selected by TOML, H3 or the default CLI;
    /// never treat this as a named Chrome/browser fingerprint.
    #[cfg(feature = "experimental-btls-h2")]
    pub fn new_experimental_btls(
        endpoint: &str,
        name: &str,
        token: &str,
        trusted_ca_pem: &[u8],
    ) -> Result<Self, ClientError> {
        crate::h2_btls::validate_ca(trusted_ca_pem)?;
        Self::with_connector(
            endpoint,
            name,
            token,
            H2Tls::Btls {
                server_name: name.to_owned(),
                trusted_ca_pem: Arc::from(trusted_ca_pem),
            },
            H2WireShape::Standard,
        )
    }

    /// F-13 opt-in production H2 profile: real BoringSSL TLS1.3, GREASE,
    /// ALPS and strict CA/SNI/ALPN, plus a measured resource-bounded H2
    /// wire shape. Chromium159 parity is NOT asserted: pseudo-header order,
    /// connection window and full ClientHello cipher/extension vectors differ.
    /// H3/QUIC and auto are refused by typed configuration before startup.
    #[cfg(feature = "experimental-btls-h2")]
    pub fn new_browser_h2_v1(
        endpoint: &str,
        name: &str,
        token: &str,
        trusted_ca_pem: &[u8],
    ) -> Result<Self, ClientError> {
        crate::h2_btls::validate_ca(trusted_ca_pem)?;
        Self::with_connector(
            endpoint,
            name,
            token,
            H2Tls::Btls {
                server_name: name.to_owned(),
                trusted_ca_pem: Arc::from(trusted_ca_pem),
            },
            H2WireShape::BrowserH2V1,
        )
    }

    fn with_connector(
        endpoint: &str,
        name: &str,
        token: &str,
        connector: H2Tls,
        wire_shape: H2WireShape,
    ) -> Result<Self, ClientError> {
        let authorization = bearer_header(token)?;
        let authority: http::uri::Authority =
            endpoint.parse().map_err(|_| ClientError::Configuration)?;
        if authority.port_u16().unwrap_or(0) == 0 || authority.host().is_empty() {
            return Err(ClientError::Configuration);
        }
        let server_name =
            ServerName::try_from(name.to_owned()).map_err(|_| ClientError::Configuration)?;
        let uri = http::Uri::builder()
            .scheme("https")
            .authority(name)
            .path_and_query("/v1/theia-example/session")
            .build()
            .map_err(|_| ClientError::Configuration)?;
        Ok(Self {
            endpoint: endpoint.to_owned(),
            server_name,
            uri,
            authorization,
            connector,
            wire_shape,
            certificate_pin: None,
            identity_routes: None,
            padding: crate::descriptor::Padding::default(),
            own_routes: Some(crate::split_http::IdentityRoutes::new(
                crate::split_http::EXAMPLE_PREFIX,
            )?),
            stream_up: false,
            auto_mode: None,
            pool: crate::connection_pool::Pool::default(),
            reuse_connections: false,
        })
    }

    /// Opt in to an additional exact leaf certificate identity, retaining PKI.
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
        if pin.is_some() {
            if !matches!(&self.connector, H2Tls::Rustls(_)) {
                return Err(ClientError::Configuration);
            }
        } else if self.certificate_pin.is_some() {
            return Err(ClientError::Configuration);
        }
        self.certificate_pin = pin;
        Ok(self)
    }

    /// Explicit XHTTP split mode with the same TLS verification and credentials.
    pub fn with_stream_up(mut self, enabled: bool) -> Result<Self, ClientError> {
        if self.auto_mode.is_some()
            || (self.stream_up && !enabled)
            || (enabled && !matches!(&self.connector, H2Tls::Rustls(_)))
        {
            return Err(ClientError::Configuration);
        }
        self.stream_up = enabled;
        Ok(self)
    }

    /// Opt-in auto XHTTP for own TLS on an already resolved, pinned endpoint.
    pub fn with_auto_stream_up(mut self, ttl: Duration) -> Result<Self, ClientError> {
        if self.certificate_pin.is_some()
            || self.stream_up
            || self.auto_mode.is_some()
            || !matches!(&self.connector, H2Tls::Rustls(_))
        {
            return Err(ClientError::Configuration);
        }
        let remote = self
            .endpoint
            .parse()
            .map_err(|_| ClientError::Configuration)?;
        self.auto_mode = Some(crate::split_http::AutoMode::new(remote, ttl));
        Ok(self)
    }

    /// Resolve only the configured server endpoint. DNS target names are
    /// encoded verbatim as OPEN_TCP and are never resolved by this client.
    /// A successful return is possible only after a valid OPEN_OK.
    pub async fn open(&self, address: Address, port: u16) -> Result<Tunnel, ClientError> {
        self.open_frame(Frame::OpenTcp { address, port }).await
    }

    pub(crate) async fn open_udp(
        &self,
        address: Address,
        port: u16,
    ) -> Result<Tunnel, ClientError> {
        self.open_frame(Frame::OpenUdp { address, port }).await
    }

    async fn open_frame(&self, open: Frame) -> Result<Tunnel, ClientError> {
        session::open(self, open).await
    }

    pub(crate) async fn warm_carrier(&self) -> Result<(), ClientError> {
        let reusable = self.reuse_connections && self.certificate_pin.is_none()
            && matches!(&self.connector, H2Tls::Rustls(_));
        if !reusable { return Ok(()); }
        let route = self.endpoint.parse().ok().and_then(crate::network_scope::observe);
        self.pool.warm(route, |connection| !connection.driver.0.is_finished(),
            self.connect_verified(diagnostics::next_id()),
            || route.is_some() && self.endpoint.parse().ok().and_then(crate::network_scope::observe) == route,
        ).await
    }

    async fn connect_verified(&self, operation: u64) -> Result<H2Connection, ClientError> {
        let (socket, controller, carrier_lease) =
            crate::tcp_bbr::connect_carrier(self.endpoint.as_str())
                .await
                .map_err(|error| match error {
                    crate::tcp_bbr::Error::Network => ClientError::Io,
                    crate::tcp_bbr::Error::Unavailable => ClientError::TcpControllerUnavailable,
                })?;
        crate::diag!(
            Trace,
            "client.h2",
            "tcp_controller_selected",
            "controller" = Value::Label(controller.label()),
            "op" = Value::Count(operation)
        );
        let (sender, driver, binding) = match &self.connector {
            H2Tls::Rustls(connector) => {
                let tls = connector
                    .connect(self.server_name.clone(), socket)
                    .await
                    .map_err(|_| ClientError::Tls)?;
                if !crate::transport_policy::Carrier::H2.accepts_tls(
                    tls.get_ref().1.protocol_version(),
                    tls.get_ref().1.alpn_protocol(),
                ) {
                    return Err(ClientError::Tls);
                }
                if let Some(pin) = self.certificate_pin {
                    pin.verify(
                        tls.get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|chain| chain.first())
                            .ok_or(ClientError::Tls)?
                            .as_ref(),
                    )?;
                }
                let binding = if self.certificate_pin.is_some() {
                    Some(zeroize::Zeroizing::new(
                        tls.get_ref()
                            .1
                            .export_keying_material(
                                [0u8; 32],
                                crate::channel_binding::LABEL,
                                Some(crate::channel_binding::H2),
                            )
                            .map_err(|_| ClientError::Tls)?,
                    ))
                } else {
                    None
                };
                let (sender, driver) = start_h2(tls, self.wire_shape, carrier_lease).await?;
                (sender, driver, binding)
            }
            #[cfg(feature = "experimental-btls-h2")]
            H2Tls::Btls {
                server_name,
                trusted_ca_pem,
            } => {
                let tls = crate::h2_btls::connect(socket, server_name, trusted_ca_pem).await?;
                let (sender, driver) = start_h2(tls, self.wire_shape, carrier_lease).await?;
                (sender, driver, None)
            }
        };
        crate::diag!(
            Trace,
            "client.h2",
            "tls_and_h2_verified",
            "op" = Value::Count(operation)
        );
        Ok(H2Connection {
            sender: std::sync::Mutex::new(sender),
            driver,
            binding,
        })
    }

    async fn open_inner(
        &self,
        open: &Frame,
        operation: u64,
        stream_up: bool,
        stage: &mut crate::split_http::HelloOutcome,
    ) -> Result<Tunnel, ClientError> {
        let route = self
            .endpoint
            .parse()
            .ok()
            .and_then(crate::network_scope::observe);
        let reusable = self.reuse_connections
            && self.certificate_pin.is_none()
            && matches!(&self.connector, H2Tls::Rustls(_));
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
        if route.is_some()
            && self
                .endpoint
                .parse()
                .ok()
                .and_then(crate::network_scope::observe)
                != route
        {
            lease.retire();
            return Err(ClientError::Io);
        }
        if !lease.accepting_new_streams() {
            return Err(ClientError::Http2);
        }
        // Only a protocol-level graceful refusal during HTTP admission can
        // retry. The lease's Drop removes the draining connection from reuse
        // while other admitted leases retain it.
        let mut admission_error = |error: h2::Error| {
            if error.is_remote()
                && ((error.is_go_away() && error.reason() == Some(h2::Reason::NO_ERROR))
                    || (error.is_reset() && error.reason() == Some(h2::Reason::REFUSED_STREAM)))
            {
                lease.retire();
                *stage = crate::split_http::HelloOutcome::Draining;
            }
            ClientError::Http2
        };
        let connection = lease.connection();
        let binding = connection.binding.as_ref();
        let sender = connection
            .sender
            .lock()
            .map_err(|_| ClientError::Http2)?
            .clone();
        let mut sender = sender.ready().await.map_err(&mut admission_error)?;
        let pair_id = lease.id();
        // Bearer is sent only on a verified connection.
        let (response, mut outgoing) = if stream_up {
            use crate::split_http::{self, Leg};
            let (download, _) = sender
                .send_request(
                    crate::channel_binding::attach(
                        binding,
                        self.padding.request(split_http::request_for(
                            self.identity_routes.as_ref().or(self.own_routes.as_ref()),
                            &self.uri,
                            Leg::Download,
                            &self.authorization,
                            pair_id,
                        )?)?,
                    )?,
                    true,
                )
                .map_err(&mut admission_error)?;
            let mut sender = sender.ready().await.map_err(&mut admission_error)?;
            let (upload, tx) = sender
                .send_request(
                    crate::channel_binding::attach(
                        binding,
                        self.padding.request(split_http::request_for(
                            self.identity_routes.as_ref().or(self.own_routes.as_ref()),
                            &self.uri,
                            Leg::Upload,
                            &self.authorization,
                            pair_id,
                        )?)?,
                    )?,
                    false,
                )
                .map_err(&mut admission_error)?;
            let upload = upload.await.map_err(&mut admission_error)?;
            split_http::check_status(upload.status())?;
            let mut empty = upload.into_body();
            if empty.data().await.is_some()
                || empty
                    .trailers()
                    .await
                    .map_err(|_| ClientError::Http2)?
                    .is_some()
            {
                return Err(ClientError::Protocol);
            }
            (download.await.map_err(&mut admission_error)?, tx)
        } else {
            let request = Request::post(self.uri.clone())
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::AUTHORIZATION, self.authorization.clone())
                .body(())
                .map_err(|_| ClientError::Configuration)?;
            let (response, tx) = sender
                .send_request(
                    crate::channel_binding::attach(binding, self.padding.request(request)?)?,
                    false,
                )
                .map_err(&mut admission_error)?;
            (response.await.map_err(&mut admission_error)?, tx)
        };
        crate::diag!(
            Trace,
            "client.h2",
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
        let mut incoming = response.into_body();
        let mut decoder = IncomingFrames::default();
        let mut state = Session::new(Role::Client);
        let hello = Frame::Hello {
            version: protocol::VERSION,
            capabilities: protocol::CAP_PADDING,
        };
        state
            .apply(Direction::Send, &hello)
            .map_err(|_| ClientError::Protocol)?;
        send_frame(&mut outgoing, &hello, false).await?;
        let ack = if self.auto_mode.is_some() && !stream_up {
            match timeout(
                crate::split_http::HELLO_ACK_TIMEOUT,
                decoder.next(&mut incoming),
            )
            .await
            {
                Ok(result) => result?,
                Err(_) => {
                    if !decoder.eof && decoder.decoder.pending_len() == 0 {
                        *stage = crate::split_http::HelloOutcome::Silent;
                    }
                    return Err(ClientError::Timeout);
                }
            }
        } else {
            decoder.next(&mut incoming).await?
        }
        .ok_or(ClientError::Protocol)?;
        state
            .apply(Direction::Receive, &ack)
            .map_err(|_| ClientError::Protocol)?;
        crate::diag!(
            Trace,
            "client.h2",
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
            send_frame(&mut outgoing, &padding, false).await?;
        }
        state
            .apply(Direction::Send, open)
            .map_err(|_| ClientError::Protocol)?;
        send_frame(&mut outgoing, open, false).await?;
        let result = loop {
            let frame = decoder
                .next(&mut incoming)
                .await?
                .ok_or(ClientError::Protocol)?;
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
        match result {
            Frame::OpenOk if state.tunnel_open() => {
                lease.admitted();
                Ok(Tunnel {
                    operation,
                    stream_up,
                    incoming,
                    outgoing,
                    decoder,
                    state,
                    _lease: lease,
                })
            }
            Frame::OpenError(code) => {
                crate::diag!(
                    Warn,
                    "client.h2",
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

/// Same HTTP/2 transport engine and ownership regardless of verified TLS
/// backend. The SmartTheia HELLO/OPEN_OK state machine below is shared.
async fn start_h2<S>(
    tls: S,
    wire_shape: H2WireShape,
    carrier_lease: crate::routing::carrier_socket::Lease,
) -> Result<(h2::client::SendRequest<Bytes>, Driver), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = crate::transport_policy::Carrier::H2.h2_client();
    if matches!(wire_shape, H2WireShape::BrowserH2V1) {
        // Chromium159 advertises HPACK table 65536, 6MiB per-stream credit,
        // 256KiB max header list and ~15MiB connection receive credit.
        // Preserve the same HPACK table hint but bound receive credit to
        // 256KiB per active stream and retain the strict 8KiB header limit.
        // This is a measured *partial* HTTP fingerprint, not impersonation.
        builder.header_table_size(65_536);
        builder.initial_window_size(262_144);
    }
    let (sender, connection) = builder
        .handshake(tls)
        .await
        .map_err(|_| ClientError::Http2)?;
    let driver = Driver(tokio::spawn(async move {
        let _carrier = carrier_lease;
        let _ = connection.await;
    }));
    Ok((sender, driver))
}

impl OpenAdapter for H2Client {
    type Tunnel = Tunnel;
    const KIND: CarrierKind = CarrierKind::H2;
    fn explicit_stream_up(&self) -> bool { self.stream_up }
    fn automatic_mode(&self) -> Option<&crate::split_http::AutoMode> { self.auto_mode.as_ref() }
    async fn open_attempt<'a>(&'a self, open: &'a Frame, operation: u64, stream_up: bool, stage: &'a mut crate::split_http::HelloOutcome) -> Result<Tunnel, ClientError> {
        self.open_inner(open, operation, stream_up, stage).await
    }
}

struct H2Connection {
    sender: std::sync::Mutex<h2::client::SendRequest<Bytes>>,
    driver: Driver,
    binding: Option<crate::channel_binding::Key>,
}

struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Construction is private: a Tunnel always represents a verified OPEN_OK.
/// A lease keeps the shared verified connection alive for this tunnel.
pub struct Tunnel {
    operation: u64,
    stream_up: bool,
    incoming: h2::RecvStream,
    outgoing: h2::SendStream<Bytes>,
    decoder: IncomingFrames,
    state: Session,
    _lease: crate::connection_pool::Lease<H2Connection>,
}

impl Tunnel {
    pub(crate) async fn relay_udp(
        mut self, first: Option<Vec<u8>>, upload: tokio::sync::mpsc::Receiver<Vec<u8>>,
        download: tokio::sync::mpsc::Sender<Vec<u8>>, flow: Option<&crate::routing::flow::FlowLease>,
    ) -> Result<(), ClientError> {
        let mut reader = H2FrameReader { decoder: &mut self.decoder, stream: &mut self.incoming };
        session::relay_udp(CarrierKind::H2, &self.state, &mut self.outgoing, &mut reader, first, upload, download, flow).await
    }

    pub(crate) fn opened_stream_up(&self) -> bool {
        self.stream_up
    }
    /// True when both tunnels share one verified transport connection.
    /// Does not reveal peer addresses, credentials or connection identifiers.
    pub fn shares_transport_with(&self, other: &Self) -> bool {
        self._lease.shares_connection(&other._lease)
    }

    /// Relay a local duplex byte stream after OPEN_OK. Each direction has
    /// independent flow control, one bounded frame buffer and FIN state.
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
        let mut reader = H2FrameReader { decoder: &mut self.decoder, stream: &mut self.incoming };
        let lease = &self._lease;
        session::relay_tcp(CarrierKind::H2, self.operation, &mut self.state, &mut self.outgoing, &mut reader, local, flow, |bytes| lease.record_data(bytes)).await
    }
}

async fn send_frame(
    outgoing: &mut h2::SendStream<Bytes>,
    frame: &Frame,
    end: bool,
) -> Result<(), ClientError> {
    let mut bytes = Bytes::from(protocol::encode(frame).map_err(|_| ClientError::Protocol)?);
    while !bytes.is_empty() {
        outgoing.reserve_capacity(bytes.len());
        let capacity = if outgoing.capacity() == 0 {
            std::future::poll_fn(|cx| outgoing.poll_capacity(cx))
                .await
                .ok_or(ClientError::Http2)?
                .map_err(|_| ClientError::Http2)?
        } else {
            outgoing.capacity()
        };
        if capacity == 0 {
            continue;
        }
        let part = bytes.split_to(capacity.min(bytes.len()));
        outgoing
            .send_data(part, end && bytes.is_empty())
            .map_err(|_| ClientError::Http2)?;
    }
    Ok(())
}

impl FrameWriter for h2::SendStream<Bytes> {
    async fn send<'a>(&'a mut self, frame: &'a Frame) -> Result<(), ClientError> {
        timeout(IO_TIMEOUT, send_frame(self, frame, false)).await.map_err(|_| ClientError::Timeout)?
    }
    async fn finish(&mut self) -> Result<(), ClientError> {
        timeout(IO_TIMEOUT, send_frame(self, &Frame::Fin, true)).await.map_err(|_| ClientError::Timeout)?
    }
    fn abort(&mut self) { self.send_reset(h2::Reason::CANCEL); }
}

struct H2FrameReader<'a> {
    decoder: &'a mut IncomingFrames,
    stream: &'a mut h2::RecvStream,
}
impl FrameReader for H2FrameReader<'_> {
    async fn next(&mut self) -> Result<Option<Frame>, ClientError> { self.decoder.next(self.stream).await }
}

#[derive(Default)]
struct IncomingFrames {
    decoder: Decoder,
    ready: VecDeque<Frame>,
    eof: bool,
}

impl IncomingFrames {
    async fn next(&mut self, incoming: &mut h2::RecvStream) -> Result<Option<Frame>, ClientError> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            let chunk = incoming.data().await;
            let Some(chunk) = chunk else {
                self.eof = true;
                self.decoder.finish().map_err(|_| ClientError::Protocol)?;
                if incoming
                    .trailers()
                    .await
                    .map_err(|_| ClientError::Http2)?
                    .is_some()
                {
                    return Err(ClientError::Protocol);
                }
                return Ok(None);
            };
            let chunk = chunk.map_err(|_| ClientError::Http2)?;
            self.ready.extend(
                self.decoder
                    .feed(&chunk)
                    .map_err(|_| ClientError::Protocol)?,
            );
            incoming
                .flow_control()
                .release_capacity(chunk.len())
                .map_err(|_| ClientError::Http2)?;
        }
    }
}
