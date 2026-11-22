//! M3.5b2a: actual route-local IP discovery (no datagrams sent) and TLS1.3
//! probe of one explicitly approved pinned address. No DNS, public sweeps,
//! real REALITY camouflage, H3 probe, or user-facing scanner in this slice.
use rcgen::generate_simple_self_signed;
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{net::{IpAddr, SocketAddr}, sync::Arc, time::Duration};
use theia::camouflage_probe::{
    probe_tls_h2, route_selected_local_ip, ProbeApproval, ProbeError, ProbeRequest,
};
use theia::camouflage_discovery::{Observation, Transport};
use tokio::{net::TcpListener, time::timeout};
use tokio_rustls::TlsAcceptor;

const DEADLINE: Duration = Duration::from_secs(6);

struct Fixture {
    address: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    server: tokio::task::JoinHandle<()>,
}

async fn fixture(alpn: &[u8]) -> Fixture {
    let signed = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = signed.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der());
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key.into())
    .unwrap();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // Even rejected identities must not crash a server task.
        let _ = acceptor.accept(tcp).await;
    });
    Fixture { address, certificate: cert, server }
}

fn roots(cert: rustls::pki_types::CertificateDer<'static>) -> RootCertStore {
    let mut trust = RootCertStore::empty();
    trust.add(cert).unwrap();
    trust
}

fn request(address: SocketAddr, name: &str) -> ProbeRequest {
    ProbeRequest {
        address,
        server_name: name.to_string(),
        deadline: Duration::from_secs(3),
    }
}

#[test]
fn selected_route_ip_is_read_without_generating_a_subnet_or_egress_claim() {
    let ip = route_selected_local_ip("127.0.0.1:9".parse().unwrap()).unwrap();
    assert_eq!(ip, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_tls13_h2_observations_leave_fingerprint_unknown() {
    timeout(DEADLINE, async {
        let f = fixture(b"h2").await;
        let report = probe_tls_h2(
            request(f.address, "localhost"),
            roots(f.certificate.clone()),
            ProbeApproval::isolated_loopback_fixture(f.address),
        ).await.unwrap();
        assert_eq!(report.connected_ip, f.address.ip());
        assert_eq!(report.evidence.tls13, Observation::Verified);
        assert_eq!(report.evidence.trusted_chain, Observation::Verified);
        assert_eq!(report.evidence.sni_san_match, Observation::Verified);
        assert_eq!(report.evidence.certificate_current, Observation::Verified);
        assert_eq!(report.evidence.reachable, Observation::Verified);
        assert_eq!(report.evidence.alpn_h2, Observation::Verified);
        assert_eq!(report.evidence.alpn_h3, Observation::Unknown);
        assert_eq!(report.evidence.theia_fingerprint_match, Observation::Unknown);
        let h2 = report.evidence.suitability(Transport::H2);
        assert!(!h2.eligible, "first flight fingerprint is not verified");
        assert!(h2.score > 0 && h2.score < 100);
        assert!(!report.evidence.suitability(Transport::H3).eligible);
        f.server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unapproved_socket_fails_before_a_connection_or_dns_lookup() {
    let f = fixture(b"h2").await;
    let result = probe_tls_h2(
        request(f.address, "localhost"),
        roots(f.certificate),
        ProbeApproval::Denied,
    ).await;
    assert!(matches!(result, Err(ProbeError::NotApproved)));
    f.server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_loopback_fixture_approval_does_not_allow_another_port_or_ip() {
    let f = fixture(b"h2").await;
    let other = SocketAddr::new(f.address.ip(), f.address.port() ^ 1);
    let result = probe_tls_h2(
        request(other, "localhost"),
        roots(f.certificate),
        ProbeApproval::isolated_loopback_fixture(f.address),
    ).await;
    assert!(matches!(result, Err(ProbeError::NotApproved)));
    f.server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_ca_rejected_and_no_verified_tls_report_returned() {
    timeout(DEADLINE, async {
        let f = fixture(b"h2").await;
        let wrong = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let result = probe_tls_h2(
            request(f.address, "localhost"),
            roots(wrong.cert.der().clone()),
            ProbeApproval::isolated_loopback_fixture(f.address),
        ).await;
        assert!(matches!(result, Err(ProbeError::TlsRejected)));
        f.server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_sni_cannot_reuse_a_valid_certificate_from_another_name() {
    timeout(DEADLINE, async {
        let f = fixture(b"h2").await;
        let result = probe_tls_h2(
            request(f.address, "wrong.example"),
            roots(f.certificate),
            ProbeApproval::isolated_loopback_fixture(f.address),
        ).await;
        assert!(matches!(result, Err(ProbeError::TlsRejected)));
        f.server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_alpn_on_tcp_is_not_accepted_as_h2() {
    timeout(DEADLINE, async {
        let f = fixture(b"h3").await;
        let result = probe_tls_h2(
            request(f.address, "localhost"),
            roots(f.certificate),
            ProbeApproval::isolated_loopback_fixture(f.address),
        ).await;
        assert!(matches!(result, Err(ProbeError::TlsRejected) | Err(ProbeError::WrongAlpn)));
        f.server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_timeout_is_bounded_and_does_not_emit_success() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_tcp, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let result = timeout(
        DEADLINE,
        probe_tls_h2(
            ProbeRequest {
                address,
                server_name: "localhost".to_string(),
                deadline: Duration::from_millis(100),
            },
            RootCertStore::empty(),
            ProbeApproval::isolated_loopback_fixture(address),
        ),
    ).await.unwrap();
    assert!(matches!(result, Err(ProbeError::NoTrustAnchors)));
    // Repeat with a real trust root to reach the network deadline.
    let signed = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = second.local_addr().unwrap();
    let stall = tokio::spawn(async move {
        let (_tcp, _) = second.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let result = probe_tls_h2(
        ProbeRequest {
            address,
            server_name: "localhost".to_string(),
            deadline: Duration::from_millis(100),
        },
        roots(signed.cert.der().clone()),
        ProbeApproval::isolated_loopback_fixture(address),
    ).await;
    assert!(matches!(result, Err(ProbeError::TimedOut)));
    server.abort();
    stall.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reject_invalid_sni_and_empty_deadline_without_connecting() {
    let f = fixture(b"h2").await;
    let consent = ProbeApproval::isolated_loopback_fixture(f.address);
    let request = request(f.address, "");
    let invalid = probe_tls_h2(request, roots(f.certificate.clone()), consent).await;
    assert!(matches!(invalid, Err(ProbeError::InvalidServerName)));
    let mut request = request(f.address, "localhost");
    request.deadline = Duration::ZERO;
    let invalid = probe_tls_h2(
        request,
        roots(f.certificate),
        ProbeApproval::isolated_loopback_fixture(f.address),
    ).await;
    assert!(matches!(invalid, Err(ProbeError::InvalidDeadline)));
    f.server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_probe_scope_is_exact_ip_on_tcp_443_only() {
    let ip: IpAddr = "93.184.216.10".parse().unwrap();
    let bad = request(SocketAddr::new(ip, 8443), "example.com");
    let result = probe_tls_h2(
        bad,
        RootCertStore::empty(),
        ProbeApproval::public_https_ip(ip),
    ).await;
    assert!(matches!(result, Err(ProbeError::NotApproved)));
    let other = request("93.184.216.11:443".parse().unwrap(), "example.com");
    let result = probe_tls_h2(other, RootCertStore::empty(), ProbeApproval::public_https_ip(ip)).await;
    assert!(matches!(result, Err(ProbeError::NotApproved)));
}
