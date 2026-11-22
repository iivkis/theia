//! Native CI dual-transport witness on the same exact IP, name and port.
//! Deliberately does not probe any external or unapproved Internet address.
use rcgen::generate_simple_self_signed;
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use theia::{
    camouflage_dual::{probe_dual_h2_h3, DualProbeError, DualProbeTarget},
    camouflage_h3_probe::H3ProbeError,
    camouflage_interfaces::NativeInterfaces,
    camouflage_probe::{ProbeApproval, ProbeError, ProbeRequest},
    camouflage_workflow::{build_preview, DiscoveryPreview, PreviewScope},
    quic_transport,
};
use tokio::{net::TcpListener, time::timeout};
use tokio_rustls::TlsAcceptor;

struct Loopback {
    address: SocketAddr,
    roots: RootCertStore,
    tcp_task: tokio::task::JoinHandle<()>,
    udp_task: tokio::task::JoinHandle<()>,
}

async fn fixture(both: bool) -> Loopback {
    let signed = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = signed.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key.clone_key().into())
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let tcp_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = acceptor.accept(tcp).await;
    });

    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let udp_task = if both {
        let endpoint = quic_transport::server_endpoint(address, vec![cert], key.into()).unwrap();
        tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let Ok(conn) = quic_transport::accept(incoming).await else {
                // Client intentionally rejects the certificate in the negative
                // PKI fixture; server authentication must fail closed too.
                return;
            };
            tokio::time::sleep(Duration::from_millis(120)).await;
            drop(conn);
        })
    } else {
        // Bound but nonresponsive UDP: H2 can pass, H3 must not be guessed.
        let socket = tokio::net::UdpSocket::bind(address).await.unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            drop(socket);
        })
    };
    Loopback {
        address,
        roots,
        tcp_task,
        udp_task,
    }
}

fn preview() -> DiscoveryPreview {
    build_preview(
        &NativeInterfaces::default(),
        None,
        PreviewScope::PassiveOnly,
    )
}

fn target(f: &Loopback, approval: ProbeApproval) -> DualProbeTarget {
    DualProbeTarget {
        request: ProbeRequest {
            address: f.address,
            server_name: "localhost".to_owned(),
            deadline: Duration::from_millis(900),
        },
        roots: f.roots.clone(),
        approval,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_pinned_ip_and_sni_verified_on_tcp_h2_and_udp_h3() {
    timeout(Duration::from_secs(8), async {
        let fixture = fixture(true).await;
        let report = probe_dual_h2_h3(
            &preview(),
            target(
                &fixture,
                ProbeApproval::isolated_loopback_fixture(fixture.address),
            ),
        )
        .await
        .unwrap();
        assert!(report.h2.is_ok());
        assert!(report.h3.is_ok());
        assert!(report.both_transports_verified());
        assert!(!report.reality_eligible());
        assert_eq!(report.address, fixture.address);
        fixture.tcp_task.await.unwrap();
        fixture.udp_task.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_success_and_udp_h3_failure_must_not_select_candidate() {
    timeout(Duration::from_secs(6), async {
        let fixture = fixture(false).await;
        let report = probe_dual_h2_h3(
            &preview(),
            target(
                &fixture,
                ProbeApproval::isolated_loopback_fixture(fixture.address),
            ),
        )
        .await
        .unwrap();
        assert!(report.h2.is_ok());
        assert!(matches!(
            report.h3,
            Err(H3ProbeError::TimedOut | H3ProbeError::UdpUnavailable)
        ));
        assert!(!report.both_transports_verified());
        assert!(!report.reality_eligible());
        fixture.tcp_task.await.unwrap();
        fixture.udp_task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejected_approval_and_trust_fail_before_any_network_connect() {
    let fixture = fixture(true).await;
    let rejected = probe_dual_h2_h3(&preview(), target(&fixture, ProbeApproval::Denied)).await;
    assert!(matches!(rejected, Err(DualProbeError::NotApproved)));
    let mut no_roots = target(
        &fixture,
        ProbeApproval::isolated_loopback_fixture(fixture.address),
    );
    no_roots.roots = RootCertStore::empty();
    assert!(matches!(
        probe_dual_h2_h3(&preview(), no_roots).await,
        Err(DualProbeError::NoTrustAnchors)
    ));
    let mut bad_name = target(
        &fixture,
        ProbeApproval::isolated_loopback_fixture(fixture.address),
    );
    bad_name.request.server_name = "127.0.0.1".to_owned();
    assert!(matches!(
        probe_dual_h2_h3(&preview(), bad_name).await,
        Err(DualProbeError::InvalidServerName)
    ));
    fixture.tcp_task.abort();
    fixture.udp_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_ca_and_sni_never_produce_h2_or_h3_verified_pair() {
    timeout(Duration::from_secs(8), async {
        let fixture = fixture(true).await;
        let mut wrong = target(
            &fixture,
            ProbeApproval::isolated_loopback_fixture(fixture.address),
        );
        let other = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(other.cert.der().clone()).unwrap();
        wrong.roots = roots;
        let report = probe_dual_h2_h3(&preview(), wrong).await.unwrap();
        assert!(matches!(report.h2, Err(ProbeError::TlsRejected)));
        assert!(matches!(report.h3, Err(H3ProbeError::HandshakeRejected)));
        assert!(!report.both_transports_verified());
        fixture.tcp_task.await.unwrap();
        fixture.udp_task.await.unwrap();
    })
    .await
    .unwrap();
}
