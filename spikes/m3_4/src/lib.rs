//! M3.4b research only: BoringSSL H2 candidate with GREASE and ALPS.
//! Do not import into the production workspace until on-wire and PKI tests
//! pass on Linux and Windows, the HTTP/2 stream adapter is integrated, and
//! the independent H3/QUIC requirements are met.

use btls::{
    error::ErrorStack,
    ssl::{ConnectConfiguration, SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};

/// An explicit, strict TLS 1.3 H2 candidate. No insecure verifier, fallback,
/// custom cryptography, resumption/0-RTT or platform trust assumptions.
/// This is not a validated Chrome133 profile: only GREASE/ALPS primitives
/// have been configured. On-wire resemblance must be measured separately.
pub fn h2_candidate(trusted_ca_pem: &[u8]) -> Result<ConnectConfiguration, ErrorStack> {
    let certificate = X509::from_pem(trusted_ca_pem)?;
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_verify(SslVerifyMode::PEER);
    builder.cert_store_mut().add_cert(certificate)?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    let mut config = builder.build().configure()?;
    config.set_verify_hostname(true);
    config.add_application_settings(b"h2")?;
    config.set_alps_use_new_codepoint(true);
    Ok(config)
}
