//! M3.4a: observe the real production H2 client on a TCP socket, not an
//! engine-only rustls fixture. This is a negative browser-profile control,
//! not a claim that the application impersonates Chrome.
#[path = "../../../spikes/m0_1/src/client_hello.rs"]
mod client_hello;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use client_hello::{parse_handshake, parse_tls_records, ClientHelloSummary, ParseError};
use rustls::RootCertStore;
use std::time::Duration;
use theia::{client::H2Client, protocol::Address};
use tokio::{io::AsyncReadExt, net::TcpListener, time::timeout};

/// The TCP peer intentionally does not complete TLS. Capture only plaintext
/// handshake records, discard their bytes immediately, and verify the client
/// fails closed. No production credentials or external host is involved.
async fn capture_production_h2_hello() -> ClientHelloSummary {
    timeout(Duration::from_secs(12), async {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("ephemeral localhost certificate");
        let mut roots = RootCertStore::empty();
        roots
            .add(certificate.cert.der().clone())
            .expect("trust test-only certificate");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test-only loopback listener");
        let endpoint = listener.local_addr().unwrap().to_string();
        let token = URL_SAFE_NO_PAD.encode([0x42; 32]);
        let client = H2Client::new(&endpoint, "localhost", &token, roots)
            .expect("valid production H2 configuration");
        let opening = tokio::spawn(async move {
            client
                .open(Address::Dns("example.org".into()), 443)
                .await
                .is_err()
        });

        let (mut socket, _) = listener.accept().await.expect("accept H2 TLS client");
        let mut wire = Vec::new();
        let observed = loop {
            let mut header = [0u8; 5];
            socket
                .read_exact(&mut header)
                .await
                .expect("read TLS record header");
            assert_eq!(header[0], 22, "expected TLS handshake record");
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            assert!((1..=18_432).contains(&length), "bounded TLS record");
            assert!(wire.len() + 5 + length <= 65_536, "bounded TLS ClientHello");
            wire.extend_from_slice(&header);
            let offset = wire.len();
            wire.resize(offset + length, 0);
            socket
                .read_exact(&mut wire[offset..])
                .await
                .expect("read TLS record payload");
            match parse_tls_records(&wire) {
                Ok(summary) => break summary,
                Err(ParseError::Truncated) => continue,
                Err(other) => panic!("malformed observed TLS ClientHello: {other:?}"),
            }
        };
        drop(wire); // Never log or persist SNI, key shares, or TLS randomness.
        drop(socket);
        assert!(
            opening.await.expect("H2 client task did not panic"),
            "client must reject a peer that never completed authenticated TLS"
        );
        observed
    })
    .await
    .expect("bounded production TLS fingerprint capture")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_theia_h2_clienthello_is_not_yet_a_browser_profile() {
    let observed = capture_production_h2_hello().await;
    assert_eq!(observed.legacy_version, 0x0303);
    assert!(observed.supported_versions.contains(&0x0304));
    assert!(observed.sni_present);
    assert_eq!(observed.alpn, vec![b"h2".to_vec()]);
    assert!(!observed.quic_transport_parameters_present);
    // This is an intentionally failing release gate: the current default
    // rustls configuration does not offer the named browser-like profile.
    assert!(!observed.has_grease_extension());
    assert!(!observed.has_alps());
    eprintln!(
        "Theia real H2/TCP ClientHello: cipher_count={} extension_count={} groups_count={} GREASE=false ALPS=false (NOT Chrome)",
        observed.cipher_suites.len(),
        observed.extensions_in_wire_order.len(),
        observed.supported_groups.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "mandatory CI-only comparison; requires private Go uTLS HelloChrome_133 fixture"]
async fn live_theia_h2_vs_pinned_utls_chrome133_reference() {
    let path = std::env::var_os("THEIA_UTLS_HELLO_PATH")
        .expect("CI must generate the Go uTLS v1.8.2 HelloChrome_133 fixture");
    let raw = std::fs::read(path).expect("read ephemeral Go ClientHello");
    let reference = parse_handshake(&raw).expect("valid reference ClientHello");
    drop(raw);

    let observed = capture_production_h2_hello().await;
    assert_eq!(reference.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert!(reference.has_grease_extension());
    assert!(reference.has_alps());
    assert!(!reference.quic_transport_parameters_present);
    assert!(!observed.has_grease_extension());
    assert!(!observed.has_alps());
    assert_ne!(reference.cipher_suites, observed.cipher_suites);
    assert_ne!(reference.supported_groups, observed.supported_groups);
    eprintln!(
        "H2/TCP live Theia vs Go uTLS 1.8.2 Chrome133: cipher_count={}/{} extension_count={}/{} groups_count={}/{} GREASE=false/true ALPS=false/true; F-13 remains BLOCKED",
        observed.cipher_suites.len(),
        reference.cipher_suites.len(),
        observed.extensions_in_wire_order.len(),
        reference.extensions_in_wire_order.len(),
        observed.supported_groups.len(),
        reference.supported_groups.len()
    );
}
