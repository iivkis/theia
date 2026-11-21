//! Pinned Go uTLS HelloChrome_133 is a reference, not browser traffic.
//! Ignored test is explicitly mandatory in Linux+Windows CI after an external
//! Go helper produces a private ClientHello. Regular cargo test lacks fixture.
use rustls::pki_types::ServerName;
use std::sync::Arc;
use theia_m0_1_feasibility::client_hello::{is_grease, parse_handshake, parse_tls_records};

fn rustls_default_h2() -> theia_m0_1_feasibility::client_hello::ClientHelloSummary {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS1.3 provider")
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let mut client = rustls::ClientConnection::new(
        Arc::new(tls), ServerName::try_from("localhost".to_owned()).unwrap(),
    ).expect("TLS client");
    let mut serialized = Vec::new();
    while client.wants_write() {
        assert!(client.write_tls(&mut serialized).unwrap() > 0);
    }
    parse_tls_records(&serialized).expect("rustls engine ClientHello")
}

#[test]
#[ignore = "requires Go uTLS v1.8.2 fixture; CI generates it and runs --ignored"]
fn go_utls_chrome133_is_a_reference_but_not_rustls_or_quic() {
    let path = std::env::var_os("THEIA_UTLS_HELLO_PATH")
        .expect("THEIA_UTLS_HELLO_PATH must point to privately generated Go uTLS fixture");
    let raw = std::fs::read(path).expect("read generated Go uTLS first-flight");
    let go = parse_handshake(&raw).expect("valid Go uTLS ClientHello handshake");
    let rust = rustls_default_h2();

    // Stable traits of pinned HelloChrome_133; never pin randomized extension
    // order or ephemeral per-run GREASE values.
    assert_eq!(go.legacy_version, 0x0303);
    assert!(go.sni_present, "Go uTLS reference must send SNI");
    assert_eq!(go.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert!(go.supported_versions.contains(&0x0304));
    assert!(go.has_grease_extension(), "uTLS Chrome133 template uses GREASE");
    assert!(go.has_alps(), "uTLS Chrome133 template uses ALPS 17613");
    assert!(go.cipher_suites.iter().any(|&v| is_grease(v)));
    assert!(go.supported_groups.iter().any(|&v| is_grease(v)));
    assert!(!go.quic_transport_parameters_present,
            "TCP uTLS hello is not a QUIC Initial reference");

    // Show exact class of mismatches without exposing SNI/random/key material.
    assert_eq!(rust.alpn, vec![b"h2".to_vec()]);
    assert!(!rust.has_grease_extension());
    assert!(!rust.has_alps());
    assert_ne!(go.cipher_suites, rust.cipher_suites);
    assert_ne!(go.supported_groups, rust.supported_groups);
    eprintln!("Go uTLS v1.8.2 Chrome133 H2 reference: GREASE={} ALPS={} cipher_count={} extension_count={} groups_count={} ALPN h2,http/1.1",
        go.has_grease_extension(), go.has_alps(), go.cipher_suites.len(),
        go.extensions_in_wire_order.len(), go.supported_groups.len());
    eprintln!("rustls default TLS/H2 engine: GREASE={} ALPS={} cipher_count={} extension_count={} groups_count={} ALPN h2",
        rust.has_grease_extension(), rust.has_alps(), rust.cipher_suites.len(),
        rust.extensions_in_wire_order.len(), rust.supported_groups.len());
    eprintln!("H3 reference available=false: Go uTLS TCP profile lacks QUIC transport parameters and Quinn crypto bridge");
}
