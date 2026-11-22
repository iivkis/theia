//! Native Linux/Windows CI: strict, explicitly approved QUIC/H3 TLS observations.
//! Real local UDP/QUIC handshakes, never public targets or DNS.
use rcgen::generate_simple_self_signed;
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{net::SocketAddr, time::Duration};
use theia::{
    camouflage_discovery::Observation,
    camouflage_h3_probe::{probe_quic_h3, H3ProbeError},
    camouflage_probe::{ProbeApproval, ProbeRequest},
    quic_transport,
};
use tokio::time::timeout;

fn server() -> (quinn::Endpoint, SocketAddr, RootCertStore) {
    let signed = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = signed.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der());
    let server = quic_transport::server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key.into(),
    )
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let addr = server.local_addr().unwrap();
    (server, addr, roots)
}

fn request(address: SocketAddr, name: &str) -> ProbeRequest {
    ProbeRequest {
        address,
        server_name: name.to_owned(),
        deadline: Duration::from_secs(2),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_loopback_h3_requires_real_quic_tls13_ca_sni_and_alpn() {
    timeout(Duration::from_secs(8), async {
        let (server, address, roots) = server();
        let worker = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = quic_transport::accept(incoming).await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(connection);
        });
        let report = probe_quic_h3(
            request(address, "localhost"),
            roots,
            ProbeApproval::isolated_loopback_fixture(address),
        )
        .await
        .unwrap();
        assert_eq!(report.connected_ip, address.ip());
        assert_eq!(report.evidence.tls13, Observation::Verified);
        assert_eq!(report.evidence.trusted_chain, Observation::Verified);
        assert_eq!(report.evidence.sni_san_match, Observation::Verified);
        assert_eq!(report.evidence.alpn_h3, Observation::Verified);
        assert_eq!(report.evidence.alpn_h2, Observation::Unknown);
        assert_eq!(
            report.evidence.theia_fingerprint_match,
            Observation::Unknown
        );
        assert!(report.handshake_elapsed <= Duration::from_secs(2));
        worker.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_hostname_and_untrusted_ca_never_produce_positive_h3_evidence() {
    timeout(Duration::from_secs(10), async {
        let (server, address, roots) = server();
        let worker = tokio::spawn(async move {
            for _ in 0..2 {
                let incoming = server.accept().await.unwrap();
                let _ = quic_transport::accept(incoming).await;
            }
        });
        let wrong_name = probe_quic_h3(
            request(address, "wrong.example"),
            roots.clone(),
            ProbeApproval::isolated_loopback_fixture(address),
        )
        .await;
        assert!(matches!(wrong_name, Err(H3ProbeError::HandshakeRejected)));
        let wrong = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut wrong_roots = RootCertStore::empty();
        wrong_roots.add(wrong.cert.der().clone()).unwrap();
        let wrong_ca = probe_quic_h3(
            request(address, "localhost"),
            wrong_roots,
            ProbeApproval::isolated_loopback_fixture(address),
        )
        .await;
        assert!(matches!(wrong_ca, Err(H3ProbeError::HandshakeRejected)));
        worker.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn explicit_consent_and_bounds_are_enforced_before_udp_io() {
    let (_server, address, roots) = server();
    for (request, trust, approval, expected) in [
        (
            request(address, "localhost"),
            roots.clone(),
            ProbeApproval::Denied,
            H3ProbeError::NotApproved,
        ),
        (
            request(address, "localhost"),
            RootCertStore::empty(),
            ProbeApproval::isolated_loopback_fixture(address),
            H3ProbeError::NoTrustAnchors,
        ),
        (
            request(address, "127.0.0.1"),
            roots.clone(),
            ProbeApproval::isolated_loopback_fixture(address),
            H3ProbeError::InvalidServerName,
        ),
        (
            ProbeRequest {
                deadline: Duration::ZERO,
                ..request(address, "localhost")
            },
            roots.clone(),
            ProbeApproval::isolated_loopback_fixture(address),
            H3ProbeError::InvalidDeadline,
        ),
    ] {
        assert_eq!(
            probe_quic_h3(request, trust, approval).await.unwrap_err(),
            expected
        );
    }
    // Public exact-IP approval cannot be repurposed for an arbitrary port or
    // a non-public address, including an unrecognized loopback fixture.
    assert_eq!(
        probe_quic_h3(
            request(address, "localhost"),
            roots,
            ProbeApproval::public_https_ip(address.ip()),
        )
        .await
        .unwrap_err(),
        H3ProbeError::NotApproved
    );
}

#[tokio::test]
async fn silent_udp_peer_times_out_without_false_success_or_http_fallback() {
    timeout(Duration::from_secs(4), async {
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = blackhole.local_addr().unwrap();
        let signed = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(signed.cert.der().clone()).unwrap();
        let mut request = request(address, "localhost");
        request.deadline = Duration::from_millis(100);
        let result = probe_quic_h3(
            request,
            roots,
            ProbeApproval::isolated_loopback_fixture(address),
        )
        .await;
        assert!(matches!(
            result,
            Err(H3ProbeError::TimedOut) | Err(H3ProbeError::UdpUnavailable)
        ));
    })
    .await
    .unwrap();
}
