//! Native QUIC public composition boundary. The runtime has no alternate
//! QUIC backend; independent comparison fixtures live under tests/support.
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{fmt, net::SocketAddr};

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

pub fn server_endpoint(
    bind: SocketAddr,
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<crate::h3_server::OwnTlsEndpoint, QuicError> {
    crate::h3_server::OwnTlsConfig::new(certificates, key)
        .and_then(|tls| crate::h3_server::OwnTlsEndpoint::bind(bind, tls))
}
