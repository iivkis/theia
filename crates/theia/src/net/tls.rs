//! Shared verified TLS configuration primitives. Identity and trust anchors
//! are chosen by callers, never inferred from the peer or mixed between modes.
use rustls::{ClientConfig, ConfigBuilder, RootCertStore, ServerConfig, WantsVerifier};
use std::sync::Arc;

pub(crate) fn client_tls13_builder() -> Result<ConfigBuilder<ClientConfig, WantsVerifier>, rustls::Error> {
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
}

pub(crate) fn server_tls13_builder() -> Result<ConfigBuilder<ServerConfig, WantsVerifier>, rustls::Error> {
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
}

fn nonempty(roots: &RootCertStore) -> Result<(), rustls::Error> {
    if roots.is_empty() { return Err(rustls::Error::General("empty explicit trust store".into())); }
    Ok(())
}

pub(crate) fn configure_client(config: &mut ClientConfig, alpn: &[u8]) {
    config.alpn_protocols = vec![alpn.to_vec()];
    config.enable_early_data = false;
}

/// For enrolled identity, pinned anchors and probes that need a fresh
/// certificate witness: no cached session can stand in for verification.
pub(crate) fn require_full_handshake(config: &mut ClientConfig) {
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
}

pub(crate) fn roots_tls13(roots: RootCertStore, alpn: &[u8]) -> Result<ClientConfig, rustls::Error> {
    nonempty(&roots)?;
    let mut config = client_tls13_builder()?.with_root_certificates(roots).with_no_client_auth();
    configure_client(&mut config, alpn);
    Ok(config)
}

/// Explicit external HTTPS reference witness. Keep X25519 restriction
/// separate from the production carrier and ordinary application TLS.
pub(crate) fn reference_h2(roots: RootCertStore) -> Result<ClientConfig, rustls::Error> {
    nonempty(&roots)?;
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups.retain(|group| group.name() == rustls::NamedGroup::X25519);
    if provider.kx_groups.is_empty() { return Err(rustls::Error::General("X25519 unavailable".into())); }
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots).with_no_client_auth();
    configure_client(&mut config, b"h2");
    require_full_handshake(&mut config);
    Ok(config)
}

/// Ordinary authenticated application TLS probes retain the previously
/// supported TLS versions and do not inherit an XHTTP ALPN.
pub(crate) fn application_probe(roots: RootCertStore) -> Result<ClientConfig, rustls::Error> {
    nonempty(&roots)?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots).with_no_client_auth();
    require_full_handshake(&mut config);
    Ok(config)
}

pub(crate) fn native_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_trust_is_rejected_by_all_root_builders() {
        assert!(roots_tls13(RootCertStore::empty(), b"h2").is_err());
        assert!(reference_h2(RootCertStore::empty()).is_err());
        assert!(application_probe(RootCertStore::empty()).is_err());
    }
    #[test]
    fn carrier_and_application_probe_keep_distinct_alpn() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let carrier = roots_tls13(roots.clone(), b"h3").unwrap();
        let reference = reference_h2(roots.clone()).unwrap();
        let probe = application_probe(roots).unwrap();
        assert_eq!(carrier.alpn_protocols, vec![b"h3".to_vec()]);
        assert_eq!(reference.alpn_protocols, vec![b"h2".to_vec()]);
        assert!(probe.alpn_protocols.is_empty());
        assert!(!carrier.enable_early_data && !reference.enable_early_data && !probe.enable_early_data);
    }
}
