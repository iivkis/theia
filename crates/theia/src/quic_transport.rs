//! M3.1a: QUIC/TLS composition root for both H3 peers.
//! Not yet wired into client/server runtime or the transport selector.
use quinn::{
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
    Connection, Endpoint, TransportConfig, VarInt,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    RootCertStore,
};
use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::timeout;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const ALPN: &[u8] = b"h3";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicError {
    Configuration,
    Bind,
    Handshake,
    Timeout,
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
            Self::Alpn => "QUIC ALPN mismatch",
            Self::CongestionController => "QUIC BBR controller unavailable",
        })
    }
}
impl std::error::Error for QuicError {}

fn transport_config() -> Arc<TransportConfig> {
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
    Endpoint::server(config, bind).map_err(|_| QuicError::Bind)
}

pub fn client_endpoint(bind: SocketAddr, roots: RootCertStore) -> Result<Endpoint, QuicError> {
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
    let mut endpoint = Endpoint::client(bind).map_err(|_| QuicError::Bind)?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
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
