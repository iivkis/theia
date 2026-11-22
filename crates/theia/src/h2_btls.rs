//! Explicit, feature-gated BoringSSL H2 transport for M3.4e CI verification.
//! Never used by the shipping default client or selected by TOML. This is
//! not a Chrome/JA3/JA4 profile and cannot serve QUIC/H3.
use crate::client::ClientError;
use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{store::X509StoreBuilder, X509},
};
use std::pin::Pin;
use tokio::net::TcpStream;
use tokio_btls::SslStream;

/// Restrict this experiment to one explicitly trusted CA PEM certificate.
/// No system trust override, insecure verifier, or unverified ALPN fallback.
fn tls_config(trusted_ca_pem: &[u8]) -> Result<btls::ssl::ConnectConfiguration, ClientError> {
    let certificate = X509::from_pem(trusted_ca_pem).map_err(|_| ClientError::Configuration)?;
    let mut roots = X509StoreBuilder::new().map_err(|_| ClientError::Configuration)?;
    roots
        .add_cert(certificate)
        .map_err(|_| ClientError::Configuration)?;

    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|_| ClientError::Configuration)?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|_| ClientError::Configuration)?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|_| ClientError::Configuration)?;
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_verify_cert_store(roots.build())
        .map_err(|_| ClientError::Configuration)?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder
        .set_alpn_protos(b"\x02h2\x08http/1.1")
        .map_err(|_| ClientError::Configuration)?;

    let mut config = builder
        .build()
        .configure()
        .map_err(|_| ClientError::Configuration)?;
    config.set_verify_hostname(true);
    config
        .add_application_settings(b"h2")
        .map_err(|_| ClientError::Configuration)?;
    config.set_alps_use_new_codepoint(true);
    Ok(config)
}

/// Fail early on missing/invalid trust material, before any TCP connection.
pub(crate) fn validate_ca(trusted_ca_pem: &[u8]) -> Result<(), ClientError> {
    tls_config(trusted_ca_pem).map(|_| ())
}

/// On success the returned stream has completed strict X.509 chain, hostname,
/// TLS1.3 and negotiated ALPN h2 verification. No request body or credentials
/// can be sent before this returns successfully.
pub(crate) async fn connect(
    socket: TcpStream,
    server_name: &str,
    trusted_ca_pem: &[u8],
) -> Result<Pin<Box<SslStream<TcpStream>>>, ClientError> {
    let config = tls_config(trusted_ca_pem)?;
    let ssl = config.into_ssl(server_name).map_err(|_| ClientError::Tls)?;
    let mut stream = Box::pin(SslStream::new(ssl, socket).map_err(|_| ClientError::Tls)?);
    stream
        .as_mut()
        .connect()
        .await
        .map_err(|_| ClientError::Tls)?;
    if stream.ssl().version2() != Some(SslVersion::TLS1_3)
        || stream.ssl().selected_alpn_protocol() != Some(b"h2".as_slice())
    {
        return Err(ClientError::Tls);
    }
    Ok(stream)
}
