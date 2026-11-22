//! M4.5f native Linux/Windows: bounded source-aware H2+H3 candidate checks.
//! Only loopback UDP/TCP traffic, no live catalogue-domain or CIDR scans.
use rcgen::generate_simple_self_signed;
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use theia::{
    camouflage_dual::{CandidateConsent, DualProbeError, DualProbeTarget},
    camouflage_dual_batch::{probe_dual_batch, DualBatchError, DualBatchTarget, MAX_DUAL_BATCH},
    camouflage_interfaces::NativeInterfaces,
    camouflage_probe::{ProbeApproval, ProbeRequest},
    camouflage_workflow::{build_preview, PreviewScope},
    quic_transport,
};
use tokio::{net::TcpListener, time::timeout};
use tokio_rustls::TlsAcceptor;

fn preview() -> theia::camouflage_workflow::DiscoveryPreview {
    build_preview(
        &NativeInterfaces::default(),
        None,
        PreviewScope::PassiveOnly,
    )
}

fn target(
    address: SocketAddr,
    roots: RootCertStore,
    approval: ProbeApproval,
    sni: &str,
    consent: CandidateConsent,
) -> DualBatchTarget {
    DualBatchTarget {
        target: DualProbeTarget {
            request: ProbeRequest {
                address,
                server_name: sni.to_owned(),
                deadline: Duration::from_secs(2),
            },
            roots,
            approval,
        },
        consent,
    }
}

#[tokio::test]
async fn empty_duplicate_and_over_quota_batches_refuse_before_network() {
    assert!(matches!(
        probe_dual_batch(&preview(), vec![]).await,
        Err(DualBatchError::Empty)
    ));
    let address: SocketAddr = "127.0.0.1:45678".parse().unwrap();
    let unit = target(
        address,
        RootCertStore::empty(),
        ProbeApproval::Denied,
        "localhost",
        CandidateConsent::PlannedIp,
    );
    let over = vec![unit.clone(); MAX_DUAL_BATCH + 1];
    assert!(matches!(
        probe_dual_batch(&preview(), over).await,
        Err(DualBatchError::TooManyTargets)
    ));
    assert!(matches!(
        probe_dual_batch(&preview(), vec![unit.clone(), unit]).await,
        Err(DualBatchError::DuplicateTarget)
    ));
}

#[tokio::test]
async fn one_denied_second_target_blocks_entire_batch_before_any_socket() {
    let signed = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(signed.cert.der().clone()).unwrap();
    let address: SocketAddr = "127.0.0.1:49221".parse().unwrap();
    let first = target(
        address,
        roots.clone(),
        ProbeApproval::isolated_loopback_fixture(address),
        "localhost",
        CandidateConsent::PlannedIp,
    );
    let denied = target(
        SocketAddr::new(address.ip(), address.port() + 1),
        roots,
        ProbeApproval::Denied,
        "localhost",
        CandidateConsent::PlannedIp,
    );
    assert!(matches!(
        probe_dual_batch(&preview(), vec![first, denied]).await,
        Err(DualBatchError::Target(DualProbeError::NotApproved))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicitly_pinned_seed_domain_requires_both_real_tcp_h2_and_udp_h3() {
    timeout(Duration::from_secs(12), async {
        // "google.com" is a local test certificate only: absolutely no
        // traffic or DNS lookup to the real provider is made in native CI.
        let signed = generate_simple_self_signed(vec!["google.com".into()]).unwrap();
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

        // QUIC first chooses a UDP-allowed ephemeral port. Windows may deny
        // another protocol at some ports; retry a finite number of times.
        let mut pair = None;
        for _ in 0..32 {
            let endpoint = quic_transport::server_endpoint(
                "127.0.0.1:0".parse().unwrap(),
                vec![cert.clone()],
                key.clone_key().into(),
            )
            .unwrap();
            let address = endpoint.local_addr().unwrap();
            if let Ok(listener) = TcpListener::bind(address).await {
                pair = Some((endpoint, listener));
                break;
            }
        }
        let (udp, tcp) = pair.expect("shared loopback UDP/TCP port required");
        let address = udp.local_addr().unwrap();
        let tcp_worker = tokio::spawn(async move {
            let (stream, _) = tcp.accept().await.unwrap();
            acceptor.accept(stream).await.unwrap();
        });
        let udp_worker = tokio::spawn(async move {
            let incoming = udp.accept().await.unwrap();
            let connection = quic_transport::accept(incoming).await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(connection);
        });
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let ip: IpAddr = address.ip();
        let approved = CandidateConsent::PinnedDomain {
            domain: "google.com",
            pinned_ip: ip,
        };
        let result = probe_dual_batch(
            &preview(),
            vec![target(
                address,
                roots,
                ProbeApproval::isolated_loopback_fixture(address),
                "google.com",
                approved,
            )],
        )
        .await
        .unwrap();
        assert_eq!(result.results.len(), 1);
        assert!(result.results[0]
            .result
            .as_ref()
            .unwrap()
            .both_transports_verified());
        assert_eq!(result.dual_verified_count(), 1);
        assert!(!result.reality_ready());
        tcp_worker.await.unwrap();
        udp_worker.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn domain_consent_is_bound_to_selected_dns_name_and_pinned_address() {
    let ip: IpAddr = "93.184.216.10".parse().unwrap();
    let address = SocketAddr::new(ip, 443);
    let mut approved = target(
        address,
        RootCertStore::empty(),
        ProbeApproval::public_https_ip(ip),
        "google.com",
        CandidateConsent::PinnedDomain {
            domain: "github.com",
            pinned_ip: ip,
        },
    );
    assert!(matches!(
        probe_dual_batch(&preview(), vec![approved.clone()]).await,
        Err(DualBatchError::Target(DualProbeError::DomainNameMismatch))
    ));
    approved.consent = CandidateConsent::PinnedDomain {
        domain: "google.com",
        pinned_ip: "93.184.216.11".parse().unwrap(),
    };
    assert!(matches!(
        probe_dual_batch(&preview(), vec![approved]).await,
        Err(DualBatchError::Target(
            DualProbeError::DomainAddressMismatch
        ))
    ));
}
