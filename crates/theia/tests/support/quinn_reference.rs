//! Independent historical QUIC reference used only by tests and benchmarks.
//! Never linked into the product's normal dependency graph.
#![allow(dead_code)]
use quinn::{
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
    Connection, Endpoint, TransportConfig, VarInt,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    RootCertStore,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use theia::{quic_transport::QuicError, transport_policy as policy};
use tokio::time::timeout;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    // Bounded per-connection stream credit. Leave unidirectional credit for
    // HTTP/3 control and QPACK streams. These are not process RSS promises.
    config.max_concurrent_bidi_streams(VarInt::from_u32(policy::MAX_BIDI_STREAMS));
    config.max_concurrent_uni_streams(VarInt::from_u32(policy::MAX_QUIC_UNI_STREAMS));
    config.stream_receive_window(VarInt::from_u32(policy::QUIC_STREAM_RECEIVE_BYTES));
    config.receive_window(VarInt::from_u32(policy::QUIC_CONNECTION_RECEIVE_BYTES));
    config.send_window(policy::QUIC_SEND_WINDOW_BYTES);
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
    tls.alpn_protocols = vec![b"h3".to_vec()];
    server_from_tls(tls)
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
    tls.alpn_protocols = vec![b"h3".to_vec()];
    client_from_tls(tls)
}

/// Verify the actually negotiated protocol and active controller, not just
/// a config label. This guard is used before any application/auth bytes.
fn verify(connection: &Connection) -> Result<(), QuicError> {
    let metadata = connection
        .handshake_data()
        .ok_or(QuicError::Handshake)?
        .downcast::<HandshakeData>()
        .map_err(|_| QuicError::Handshake)?;
    if metadata.protocol.as_deref() != Some(b"h3".as_slice()) {
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

pub fn client_from_tls(tls: rustls::ClientConfig) -> Result<quinn::ClientConfig, QuicError> {
    let crypto = QuicClientConfig::try_from(tls).map_err(|_| QuicError::Configuration)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport_config());
    Ok(config)
}

pub fn server_from_tls(tls: rustls::ServerConfig) -> Result<quinn::ServerConfig, QuicError> {
    let crypto = QuicServerConfig::try_from(tls).map_err(|_| QuicError::Configuration)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport_config());
    config.migration(false);
    Ok(config)
}
