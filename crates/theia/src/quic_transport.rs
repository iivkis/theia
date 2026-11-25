//! M3.1a: QUIC/TLS composition root for both H3 peers.
//! A separately observed UDP handshake permits conservative fallback.
use quinn::udp::{RecvMeta, Transmit};
use quinn::{
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
    AsyncUdpSocket, Connection, Endpoint, EndpointConfig, Runtime, TokioRuntime, TransportConfig,
    UdpPoller, VarInt,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    RootCertStore,
};
use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::timeout;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const ALPN: &[u8] = b"h3";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicError {
    Configuration,
    Bind,
    Handshake,
    Timeout,
    Unreachable,
    EndpointNetworkRefused,
    Alpn,
    CongestionController,
}

impl fmt::Display for QuicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately omit endpoint, certificate contents and credentials.
        f.write_str(match self {
            Self::Configuration => "invalid QUIC configuration",
            Self::Bind => "UDP bind failed",
            Self::Handshake => "QUIC handshake failed",
            Self::Timeout => "QUIC handshake timed out",
            Self::Unreachable => "quic_unreachable",
            Self::EndpointNetworkRefused => "quic_endpoint_network_refused",
            Self::Alpn => "QUIC ALPN mismatch",
            Self::CongestionController => "QUIC BBR controller unavailable",
        })
    }
}
impl std::error::Error for QuicError {}

pub(crate) fn transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    // Bounded per-connection stream credit. Leave unidirectional credit for
    // HTTP/3 control and QPACK streams. These are not process RSS promises.
    config.max_concurrent_bidi_streams(VarInt::from_u32(32));
    config.max_concurrent_uni_streams(VarInt::from_u32(8));
    config.stream_receive_window(VarInt::from_u32(256 * 1024));
    config.receive_window(VarInt::from_u32(4 * 1024 * 1024));
    config.send_window(4 * 1024 * 1024);
    Arc::new(config)
}

pub fn server_endpoint(
    bind: SocketAddr,
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Endpoint, QuicError> {
    let config = server_config(certificates, key)?;
    server_endpoint_with_config(bind, config)
}

/// Preserve exactly the configuration installed on the live QUIC endpoint.
/// Rollback must not reopen a PEM path or synthesize a different identity.
pub(crate) fn server_endpoint_with_config(
    bind: SocketAddr,
    config: quinn::ServerConfig,
) -> Result<Endpoint, QuicError> {
    Endpoint::server(config, bind).map_err(|_| QuicError::Bind)
}

/// Build a complete QUIC TLS1.3/h3/BBR server configuration *without* owning
/// a UDP socket. A running Endpoint may replace its server config for NEW
/// connections while existing QUIC transport connections remain attached to
/// their already-negotiated identity.
pub(crate) fn server_config(
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, QuicError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| QuicError::Configuration)?
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .map_err(|_| QuicError::Configuration)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;
    let crypto = QuicServerConfig::try_from(tls).map_err(|_| QuicError::Configuration)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport_config());
    config.migration(false);
    Ok(config)
}

pub fn client_endpoint(bind: SocketAddr, roots: RootCertStore) -> Result<Endpoint, QuicError> {
    let config = client_config(roots)?;
    let mut endpoint = Endpoint::client(bind).map_err(|_| QuicError::Bind)?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

fn client_config(roots: RootCertStore) -> Result<quinn::ClientConfig, QuicError> {
    if roots.is_empty() {
        return Err(QuicError::Configuration);
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| QuicError::Configuration)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    let crypto = QuicClientConfig::try_from(tls).map_err(|_| QuicError::Configuration)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport_config());
    Ok(config)
}

/// Verify the actually negotiated protocol and active controller, not just
/// a config label. This guard is used before any application/auth bytes.
fn verify(connection: &Connection) -> Result<(), QuicError> {
    let metadata = connection
        .handshake_data()
        .ok_or(QuicError::Handshake)?
        .downcast::<HandshakeData>()
        .map_err(|_| QuicError::Handshake)?;
    if metadata.protocol.as_deref() != Some(ALPN) {
        return Err(QuicError::Alpn);
    }
    if connection
        .congestion_state()
        .into_any()
        .downcast::<quinn::congestion::Bbr>()
        .is_err()
    {
        return Err(QuicError::CongestionController);
    }
    Ok(())
}

fn checked(connection: Connection) -> Result<Connection, QuicError> {
    if let Err(error) = verify(&connection) {
        connection.close(VarInt::from_u32(0x102), b"transport verification failed");
        return Err(error);
    }
    Ok(connection)
}

/// Full authenticated TLS handshake; never calls into_0rtt. Errors remain
/// fail-closed and are NOT evidence for automatic H2 fallback.
pub async fn connect(
    endpoint: &Endpoint,
    remote: SocketAddr,
    name: &str,
) -> Result<Connection, QuicError> {
    if !matches!(ServerName::try_from(name), Ok(ServerName::DnsName(_))) {
        return Err(QuicError::Configuration);
    }
    let pending = endpoint
        .connect(remote, name)
        .map_err(|_| QuicError::Configuration)?;
    let connection = timeout(HANDSHAKE_TIMEOUT, pending)
        .await
        .map_err(|_| QuicError::Timeout)?
        .map_err(|_| QuicError::Handshake)?;
    checked(connection)
}

/// Accept a single incoming connection after the full handshake.
/// Connection quotas/rate limits and H3 request handlers are M3.1b.
pub async fn accept(incoming: quinn::Incoming) -> Result<Connection, QuicError> {
    let connection = timeout(HANDSHAKE_TIMEOUT, incoming)
        .await
        .map_err(|_| QuicError::Timeout)?
        .map_err(|_| QuicError::Handshake)?;
    checked(connection)
}

/// Select the already authenticated generation for this single Initial.
pub(crate) async fn accept_with(
    incoming: quinn::Incoming,
    config: Arc<quinn::ServerConfig>,
) -> Result<Connection, QuicError> {
    let pending = incoming
        .accept_with(config)
        .map_err(|_| QuicError::Handshake)?;
    let connection = timeout(HANDSHAKE_TIMEOUT, pending)
        .await
        .map_err(|_| QuicError::Timeout)?
        .map_err(|_| QuicError::Handshake)?;
    checked(connection)
}

/// A fresh socket for exactly one candidate. Any received datagram, even an
/// invalid one, disables no-response fallback. This is intentionally stricter
/// than interpreting every QUIC timeout as blocked UDP.
#[derive(Debug)]
struct Observation {
    io: Arc<dyn AsyncUdpSocket>,
    sent: AtomicBool,
    received: AtomicBool,
    remote: OnceLock<SocketAddr>,
    network_refused: AtomicBool,
}

// Only errors returned by a send to the exact pinned destination qualify.
// Never classify errors from bind, socket allocation, receive, TLS or QUIC
// protocol processing as endpoint unavailability.
fn definitive_send_error(error: io::ErrorKind) -> bool {
    matches!(
        error,
        io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::ConnectionRefused
    )
}

fn handshake_timeout_error(sent: bool, received: bool, refused: bool) -> QuicError {
    if received {
        QuicError::Timeout
    } else if refused {
        QuicError::EndpointNetworkRefused
    } else if sent {
        QuicError::Unreachable
    } else {
        QuicError::Timeout
    }
}

impl AsyncUdpSocket for Observation {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.io.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        match self.io.try_send(transmit) {
            Ok(()) => {
                self.sent.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => {
                if self.remote.get() == Some(&transmit.destination)
                    && definitive_send_error(error.kind())
                {
                    self.network_refused.store(true, Ordering::SeqCst);
                }
                Err(error)
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let result = self.io.poll_recv(cx, bufs, meta);
        if matches!(&result, Poll::Ready(Ok(n)) if *n > 0) {
            self.received.store(true, Ordering::SeqCst);
        }
        result
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.io.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.io.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.io.may_fragment()
    }
}

pub(crate) struct ObservedEndpoint {
    pub endpoint: Endpoint,
    observation: Arc<Observation>,
}

impl ObservedEndpoint {
    pub fn new(bind: SocketAddr, roots: RootCertStore) -> Result<Self, QuicError> {
        Self::with_config(bind, client_config(roots)?)
    }

    pub(crate) fn with_config(
        bind: SocketAddr,
        config: quinn::ClientConfig,
    ) -> Result<Self, QuicError> {
        let runtime = Arc::new(TokioRuntime);
        let udp = UdpSocket::bind(bind).map_err(|_| QuicError::Bind)?;
        udp.set_nonblocking(true).map_err(|_| QuicError::Bind)?;
        let io = runtime.wrap_udp_socket(udp).map_err(|_| QuicError::Bind)?;
        let observation = Arc::new(Observation {
            io,
            sent: AtomicBool::new(false),
            received: AtomicBool::new(false),
            remote: OnceLock::new(),
            network_refused: AtomicBool::new(false),
        });
        let mut endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            observation.clone(),
            runtime,
        )
        .map_err(|_| QuicError::Bind)?;
        endpoint.set_default_client_config(config);
        Ok(Self {
            endpoint,
            observation,
        })
    }

    pub async fn connect(
        &self,
        remote: SocketAddr,
        name: &str,
        deadline: Duration,
    ) -> Result<Connection, QuicError> {
        if !matches!(ServerName::try_from(name), Ok(ServerName::DnsName(_))) {
            return Err(QuicError::Configuration);
        }
        self.observation
            .remote
            .set(remote)
            .map_err(|_| QuicError::Configuration)?;
        let pending = self
            .endpoint
            .connect(remote, name)
            .map_err(|_| QuicError::Configuration)?;
        match timeout(deadline, pending).await {
            Ok(Ok(connection)) => checked(connection),
            Ok(Err(quinn::ConnectionError::TimedOut)) | Err(_) => Err(handshake_timeout_error(
                self.observation.sent.load(Ordering::SeqCst),
                self.observation.received.load(Ordering::SeqCst),
                self.observation.network_refused.load(Ordering::SeqCst),
            )),
            Ok(Err(_)) => Err(QuicError::Handshake),
        }
    }
}

impl Drop for ObservedEndpoint {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"client closed");
    }
}

#[cfg(test)]
mod observed_errors {
    use super::*;
    #[test]
    fn only_destination_send_network_errors_are_definitive() {
        use io::ErrorKind::*;
        for error in [NetworkUnreachable, HostUnreachable, ConnectionRefused] {
            assert!(definitive_send_error(error));
        }
        for error in [
            PermissionDenied,
            AddrNotAvailable,
            WouldBlock,
            Interrupted,
            OutOfMemory,
            ConnectionReset,
            TimedOut,
            Other,
            InvalidInput,
        ] {
            assert!(!definitive_send_error(error));
        }
        assert_eq!(
            handshake_timeout_error(false, false, true),
            QuicError::EndpointNetworkRefused
        );
        assert_eq!(
            handshake_timeout_error(true, true, true),
            QuicError::Timeout
        );
        assert_eq!(
            handshake_timeout_error(true, false, false),
            QuicError::Unreachable
        );
        assert_eq!(
            handshake_timeout_error(false, false, false),
            QuicError::Timeout
        );
    }
}
