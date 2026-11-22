//! M3.4c CI-only H2 transport feasibility over verified BoringSSL.
//!
//! This is NOT the production Theia H2 client, not a Chrome fingerprint,
//! not a complete SmartTheia session, and not an H3/QUIC adapter. The purpose
//! is to prove that the candidate TLS stream can carry concurrent H2 request
//! and response bodies without bypassing peer verification.

use crate::h2_candidate;
use btls::ssl::SslVersion;
use bytes::Bytes;
use std::{fmt, net::SocketAddr, time::Duration};
use tokio::{net::TcpStream, task::JoinHandle, time::timeout};
use tokio_btls::SslStream;

const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2CandidateError {
    InvalidTrustAnchor,
    InvalidServerName,
    Tcp,
    Tls,
    Http2,
    Timeout,
}

impl fmt::Display for H2CandidateError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not disclose server names, certificates, or TLS peer diagnostics.
        match self {
            Self::InvalidTrustAnchor => fmt.write_str("invalid H2 trust anchor"),
            Self::InvalidServerName => fmt.write_str("invalid H2 TLS name"),
            Self::Tcp => fmt.write_str("H2 TCP connection failed"),
            Self::Tls => fmt.write_str("H2 verified TLS1.3/ALPN negotiation failed"),
            Self::Http2 => fmt.write_str("H2 transport handshake failed"),
            Self::Timeout => fmt.write_str("H2 handshake deadline reached"),
        }
    }
}

impl std::error::Error for H2CandidateError {}

/// The H2 connection driver must remain polled while the request body and
/// response body are open. Dropping this proof-of-feasibility connection
/// aborts the driver instead of leaving an orphaned task behind.
pub struct VerifiedH2 {
    sender: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<()>,
}

impl VerifiedH2 {
    pub fn sender(&mut self) -> &mut h2::client::SendRequest<Bytes> {
        &mut self.sender
    }
}

impl Drop for VerifiedH2 {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Connect only after strict TLS1.3 X.509 chain/name and ALPN h2 verification.
/// The caller cannot submit HTTP headers or authorization tokens until this
/// function returns. A failed handshake returns no H2 request handle.
///
/// The endpoint is a concrete socket address for isolated loopback tests;
/// production server-name DNS, config and auth policy are out of scope.
pub async fn connect_verified_h2(
    endpoint: SocketAddr,
    server_name: &str,
    trusted_ca_pem: &[u8],
) -> Result<VerifiedH2, H2CandidateError> {
    timeout(HANDSHAKE_DEADLINE, async {
        let config =
            h2_candidate(trusted_ca_pem).map_err(|_| H2CandidateError::InvalidTrustAnchor)?;
        let ssl = config
            .into_ssl(server_name)
            .map_err(|_| H2CandidateError::InvalidServerName)?;
        let socket = TcpStream::connect(endpoint)
            .await
            .map_err(|_| H2CandidateError::Tcp)?;
        let mut tls = Box::pin(SslStream::new(ssl, socket).map_err(|_| H2CandidateError::Tls)?);
        tls.as_mut()
            .connect()
            .await
            .map_err(|_| H2CandidateError::Tls)?;
        if tls.ssl().version2() != Some(SslVersion::TLS1_3)
            || tls.ssl().selected_alpn_protocol() != Some(b"h2".as_slice())
        {
            return Err(H2CandidateError::Tls);
        }

        let mut builder = h2::client::Builder::new();
        builder.max_header_list_size(8192);
        let (sender, connection) = builder
            .handshake(tls)
            .await
            .map_err(|_| H2CandidateError::Http2)?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(VerifiedH2 { sender, driver })
    })
    .await
    .map_err(|_| H2CandidateError::Timeout)?
}
