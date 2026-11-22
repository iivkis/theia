//! M3.5b2b4: default ipify.org provider, explicit approval, local-only TLS tests.
use rcgen::generate_simple_self_signed;
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::time::Duration;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use theia::camouflage_egress::{
    default_ipify_request, observe_default_ipify, observe_public_egress, EgressApproval,
    EgressError, IpifyConsent, DEFAULT_EGRESS_SERVICE_HOST, DEFAULT_EGRESS_SERVICE_URL,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

#[test]
fn default_service_is_exact_dual_stack_ipify_org_and_plain_text() {
    assert_eq!(DEFAULT_EGRESS_SERVICE_HOST, "api64.ipify.org");
    assert_eq!(DEFAULT_EGRESS_SERVICE_URL, "https://api64.ipify.org/");
    let pinned = SocketAddr::new("93.184.216.34".parse().unwrap(), 443);
    let request = default_ipify_request(pinned);
    assert_eq!(request.address, pinned);
    assert_eq!(request.server_name, DEFAULT_EGRESS_SERVICE_HOST);
    assert_eq!(request.path, "/");
    assert!(request.deadline > Duration::ZERO);
    assert!(request.deadline <= Duration::from_secs(5));
    assert!(!format!("{request:?}").contains(DEFAULT_EGRESS_SERVICE_HOST));
}

#[tokio::test]
async fn no_consent_or_roots_never_starts_dns_or_connect() {
    assert!(matches!(
        observe_default_ipify(RootCertStore::empty(), IpifyConsent::Denied).await,
        Err(EgressError::NotApproved)
    ));
    assert!(matches!(
        observe_default_ipify(RootCertStore::empty(), IpifyConsent::Approved).await,
        Err(EgressError::NoTrustAnchors)
    ));
}

/// Real loopback TLS 1.3 verification of the *exact production preset*
/// (SNI, Host, URI path), without reaching ipify or any public endpoint.
async fn ipify_fixture(
    body: &'static [u8],
) -> (SocketAddr, RootCertStore, tokio::task::JoinHandle<()>) {
    let signed = generate_simple_self_signed(vec![DEFAULT_EGRESS_SERVICE_HOST.into()]).unwrap();
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
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 1024 {
            match tls.read_u8().await {
                Ok(b) => bytes.push(b),
                Err(_) => return,
            }
        }
        assert!(bytes.starts_with(b"GET / HTTP/1.1\r\nHost: api64.ipify.org\r\n"));
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        tls.write_all(header.as_bytes()).await.unwrap();
        tls.write_all(body).await.unwrap();
        let _ = tls.shutdown().await;
    });
    (addr, roots, task)
}

#[tokio::test]
async fn default_preset_real_tls_fixture_accepts_ipv4_and_ipv6_plain_text() {
    timeout(Duration::from_secs(10), async {
        for (text, expected) in [
            (
                &b"93.184.216.34\n"[..],
                "93.184.216.34".parse::<IpAddr>().unwrap(),
            ),
            (
                &b"2606:4700:4700::1111\n"[..],
                "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            ),
        ] {
            let (address, roots, server) = ipify_fixture(text).await;
            let report = observe_public_egress(
                default_ipify_request(address),
                roots,
                EgressApproval::isolated_loopback_fixture(address),
            )
            .await
            .unwrap();
            assert_eq!(report.ip(), expected);
            assert_eq!(report.source().server_name(), DEFAULT_EGRESS_SERVICE_HOST);
            assert_eq!(report.source().pinned_ip(), address.ip());
            server.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn default_preset_rejects_bad_witness_value_without_positive_evidence() {
    let (address, roots, server) = ipify_fixture(b"10.0.0.123").await;
    assert!(matches!(
        observe_public_egress(
            default_ipify_request(address),
            roots,
            EgressApproval::isolated_loopback_fixture(address)
        )
        .await,
        Err(EgressError::UnusableAddress)
    ));
    server.await.unwrap();
}
