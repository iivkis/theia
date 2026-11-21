//! Exact evidence for the *default rustls* TLS ClientHello, not Chrome/Firefox.
//! H2 uses real TLS record serialization; H3 uses rustls's plaintext QUIC
//! handshake API, BEFORE Quinn encrypts QUIC Initial packets. They are not
//! interchangeable with actual network captures or browser reference traces.
use rustls::pki_types::ServerName;
use std::{io::Write, sync::Arc};
use theia_m0_1_feasibility::client_hello::{
    is_grease, parse_handshake, parse_tls_records, ClientHelloSummary,
};

fn client_config(alpn: &[u8]) -> Arc<rustls::ClientConfig> {
    // No TLS trust bypass or custom verifier is created. This test extracts
    // the initial ClientHello only, and never connects to an external server.
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS1.3 provider")
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    Arc::new(config)
}

fn default_tls_h2_clienthello() -> ClientHelloSummary {
    let mut conn = rustls::ClientConnection::new(
        client_config(b"h2"),
        ServerName::try_from("localhost".to_string()).unwrap(),
    )
    .expect("TLS engine");
    let mut bytes = Vec::new();
    while conn.wants_write() {
        let written = conn
            .write_tls(&mut bytes)
            .expect("emit ClientHello TLS records");
        assert!(written > 0, "TLS handshake writer must progress");
    }
    parse_tls_records(&bytes).expect("parse generated TLS ClientHello")
}

fn default_quic_h3_clienthello() -> ClientHelloSummary {
    // Transport params are intentionally empty in this *engine-only* probe.
    // A live Quinn endpoint generates real parameters; thus this cannot prove
    // on-wire QUIC packet bytes or a valid complete QUIC handshake.
    let mut conn = rustls::quic::ClientConnection::new(
        client_config(b"h3"),
        rustls::quic::Version::V1,
        ServerName::try_from("localhost".to_string()).unwrap(),
        Vec::new(),
    )
    .expect("QUIC-compatible TLS engine");
    let mut plaintext_handshake = Vec::new();
    conn.write_hs(&mut plaintext_handshake);
    assert!(
        !plaintext_handshake.is_empty(),
        "TLS client handshake CRYPTO payload"
    );
    parse_handshake(&plaintext_handshake).expect("parse plaintext QUIC ClientHello")
}

#[test]
fn default_rustls_h2_clienthello_has_tls13_sni_and_alpn() {
    let hello = default_tls_h2_clienthello();
    assert_eq!(hello.legacy_version, 0x0303);
    assert_eq!(hello.alpn, vec![b"h2".to_vec()]);
    assert!(hello.sni_present);
    assert!(
        hello.supported_versions.contains(&0x0304),
        "TLS1.3 advertised"
    );
    assert!(!hello.cipher_suites.is_empty());
    assert!(!hello.extensions_in_wire_order.is_empty());
    assert!(!hello.quic_transport_parameters_present);
    // Do not pretend any observed extension list is a named browser profile.
    eprintln!("default rustls H2 ClientHello (no host/random/secret): {hello:?}");
}

#[test]
fn default_rustls_quic_h3_clienthello_has_transport_params_and_alpn() {
    let hello = default_quic_h3_clienthello();
    assert_eq!(hello.legacy_version, 0x0303);
    assert_eq!(hello.alpn, vec![b"h3".to_vec()]);
    assert!(hello.sni_present);
    assert!(
        hello.supported_versions.contains(&0x0304),
        "QUIC must use TLS1.3"
    );
    assert!(
        hello.quic_transport_parameters_present,
        "QUIC TLS extension 57 must exist"
    );
    assert!(!hello.cipher_suites.is_empty());
    eprintln!("default rustls QUIC/H3 ClientHello (no host/random/secret): {hello:?}");
}

#[test]
fn default_h2_and_h3_clienthello_are_distinct_and_not_browser_claims() {
    let h2 = default_tls_h2_clienthello();
    let h3 = default_quic_h3_clienthello();
    assert_ne!(h2.alpn, h3.alpn);
    assert!(!h2.quic_transport_parameters_present);
    assert!(h3.quic_transport_parameters_present);
    let h2_grease = h2
        .extensions_in_wire_order
        .iter()
        .filter(|&&e| is_grease(e))
        .count();
    let h3_grease = h3
        .extensions_in_wire_order
        .iter()
        .filter(|&&e| is_grease(e))
        .count();
    // Diagnostic only, no assertion against any browser build or GREASE policy:
    eprintln!("default rustls GREASE extension counts: h2={h2_grease} h3={h3_grease}");
}


/// A version-pinned negative control: the default rustls 0.23.46 TLS/H2
/// first flight lacks GREASE and both old/new ALPS codepoints. This is
/// evidence against *claiming* a Chrome profile, not proof of matching or
/// nonmatching every browser build (real browser captures are still required).
#[test]
fn default_rustls_h2_cannot_pass_named_browser_gate() {
    let hello = default_tls_h2_clienthello();
    assert!(!hello.has_grease_extension(),
        "rustls first flight changed: update fingerprint evidence and comparison");
    assert!(!hello.has_alps(),
        "rustls ALPS support changed: update fingerprint evidence and comparison");
    assert_eq!(hello.supported_groups, vec![29, 23, 24]);
    eprintln!("named browser profile gate: BLOCKED, GREASE=false ALPS(old/new)=false; no real Chrome capture");
}
