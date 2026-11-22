//! M3.5b2b3: bounded *explicitly selected* TLS/H2 probe batch.
//! No external CI calls, no DNS, no CIDR sweep or implicit target selection.
use rcgen::generate_simple_self_signed;
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{net::{IpAddr, SocketAddr}, sync::Arc, time::Duration};
use theia::{
    camouflage_batch::{
        probe_explicit_batch, BatchError, BatchTarget, MAX_EXPLICIT_BATCH,
    },
    camouflage_discovery::Observation,
    camouflage_interfaces::NativeInterfaces,
    camouflage_probe::{ProbeApproval, ProbeError, ProbeRequest},
    camouflage_workflow::{build_preview, PreviewScope},
};
use tokio::{net::TcpListener, task::JoinHandle, time::timeout};
use tokio_rustls::TlsAcceptor;

struct Fixture {
    address: SocketAddr,
    roots: RootCertStore,
    server: JoinHandle<()>,
}

async fn fixture(alpn: &[u8]) -> Fixture {
    let signed = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = signed.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key.into())
    .unwrap();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = acceptor.accept(tcp).await;
    });
    Fixture { address, roots, server }
}

fn target(address: SocketAddr, roots: RootCertStore, approval: ProbeApproval) -> BatchTarget {
    BatchTarget {
        request: ProbeRequest {
            address,
            server_name: "localhost".to_owned(),
            deadline: Duration::from_secs(2),
        },
        roots,
        approval,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicitly_approved_exact_loopback_peers_are_tested_in_stable_order() {
    timeout(Duration::from_secs(10), async {
        let a = fixture(b"h2").await;
        let b = fixture(b"h2").await;
        let preview = build_preview(&NativeInterfaces::default(), None, PreviewScope::PassiveOnly);
        let report = probe_explicit_batch(
            &preview,
            vec![
                target(a.address, a.roots, ProbeApproval::isolated_loopback_fixture(a.address)),
                target(b.address, b.roots, ProbeApproval::isolated_loopback_fixture(b.address)),
            ],
        ).await.unwrap();

        assert_eq!(report.results.len(), 2);
        assert!(report.all_handshakes_verified);
        assert_eq!(report.results[0].address, a.address);
        assert_eq!(report.results[1].address, b.address);
        for result in &report.results {
            let observed = result.result.as_ref().unwrap();
            assert_eq!(observed.evidence.alpn_h2, Observation::Verified);
            assert_eq!(observed.evidence.theia_fingerprint_match, Observation::Unknown);
        }
        a.server.await.unwrap();
        b.server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn individual_tls_failure_is_preserved_without_fake_batch_success() {
    timeout(Duration::from_secs(10), async {
        let good = fixture(b"h2").await;
        let bad = fixture(b"h3").await;
        let preview = build_preview(&NativeInterfaces::default(), None, PreviewScope::PassiveOnly);
        let report = probe_explicit_batch(
            &preview,
            vec![
                target(good.address, good.roots, ProbeApproval::isolated_loopback_fixture(good.address)),
                target(bad.address, bad.roots, ProbeApproval::isolated_loopback_fixture(bad.address)),
            ],
        ).await.unwrap();
        assert!(!report.all_handshakes_verified);
        assert!(report.results[0].result.is_ok());
        assert!(matches!(
            report.results[1].result,
            Err(ProbeError::TlsRejected) | Err(ProbeError::WrongAlpn)
        ));
        good.server.await.unwrap();
        bad.server.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn deny_missing_consent_before_tcp_or_tls() {
    let a = fixture(b"h2").await;
    let preview = build_preview(&NativeInterfaces::default(), None, PreviewScope::PassiveOnly);
    let result = probe_explicit_batch(
        &preview, vec![target(a.address, a.roots, ProbeApproval::Denied)]
    ).await;
    assert!(matches!(result, Err(BatchError::NotApproved)));
    a.server.abort();
}

#[tokio::test]
async fn no_implicit_public_targets_even_if_caller_constructs_a_valid_approval() {
    let preview = build_preview(&NativeInterfaces::default(), None, PreviewScope::PassiveOnly);
    let ip: IpAddr = "93.184.216.42".parse().unwrap();
    let request = ProbeRequest {
        address: SocketAddr::new(ip, 443),
        server_name: "example.org".into(),
        deadline: Duration::from_secs(1),
    };
    let result = probe_explicit_batch(
        &preview,
        vec![BatchTarget {
            request, roots: RootCertStore::empty(), approval: ProbeApproval::public_https_ip(ip)
        }],
    ).await;
    assert!(matches!(result, Err(BatchError::UnplannedAddress)));
}

#[tokio::test]
async fn duplicate_socket_and_oversized_or_empty_batch_fail_before_network() {
    let preview = build_preview(&NativeInterfaces::default(), None, PreviewScope::PassiveOnly);
    assert!(matches!(
        probe_explicit_batch(&preview, vec![]).await,
        Err(BatchError::Empty)
    ));
    let fixture = fixture(b"h2").await;
    let approval = ProbeApproval::isolated_loopback_fixture(fixture.address);
    let duplicate = vec![
        target(fixture.address, fixture.roots.clone(), approval),
        target(fixture.address, fixture.roots.clone(), approval),
    ];
    assert!(matches!(
        probe_explicit_batch(&preview, duplicate).await,
        Err(BatchError::DuplicateAddress)
    ));
    let overflowing = (0..MAX_EXPLICIT_BATCH+1)
        .map(|_| target(fixture.address, RootCertStore::empty(), ProbeApproval::Denied))
        .collect();
    assert!(matches!(
        probe_explicit_batch(&preview, overflowing).await,
        Err(BatchError::TooManyTargets)
    ));
    fixture.server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn individual_timeout_does_not_make_unobserved_fingerprint_eligible() {
    timeout(Duration::from_secs(8), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_tcp, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let signed = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(signed.cert.der().clone()).unwrap();
        let mut request = target(
            address, roots, ProbeApproval::isolated_loopback_fixture(address)
        );
        request.request.deadline = Duration::from_millis(80);
        let preview = build_preview(&NativeInterfaces::default(), None, PreviewScope::PassiveOnly);
        let outcome = probe_explicit_batch(&preview, vec![request]).await.unwrap();
        assert!(!outcome.all_handshakes_verified);
        assert!(matches!(outcome.results[0].result, Err(ProbeError::TimedOut)));
        server.abort();
    }).await.unwrap();
}
