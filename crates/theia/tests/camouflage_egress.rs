//! M3.5b2b2: consented, strictly verified HTTPS egress echo with no
//! external CI traffic, plus an offline preview that never infers approval.
use rcgen::generate_simple_self_signed;
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{net::{IpAddr, SocketAddr}, sync::Arc, time::Duration};
use theia::camouflage_egress::{
    observe_public_egress, EgressApproval, EgressError, EgressRequest,
};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener, task::JoinHandle, time::timeout};
use tokio_rustls::TlsAcceptor;

struct Fixture {
    address: SocketAddr,
    roots: RootCertStore,
    server: JoinHandle<()>,
}

async fn fixture(body: &'static [u8], status: &'static str, alpn: &'static [u8]) -> Fixture {
    let signed = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
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
        if let Ok(mut tls) = acceptor.accept(tcp).await {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") && request.len() < 2048 {
                match tls.read_u8().await {
                    Ok(byte) => request.push(byte),
                    Err(_) => return,
                }
            }
            if request.starts_with(b"GET /whoami HTTP/1.1\r\nHost: localhost\r\n") {
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls.write_all(body).await;
                let _ = tls.shutdown().await;
            }
        }
    });
    Fixture { address, roots, server }
}

fn request(address: SocketAddr) -> EgressRequest {
    EgressRequest {
        address,
        server_name: "localhost".to_owned(),
        path: "/whoami".to_owned(),
        deadline: Duration::from_secs(3),
    }
}

#[tokio::test]
async fn verified_pinned_https_echo_returns_only_remote_observation() {
    timeout(Duration::from_secs(8), async {
        let f = fixture(b"93.184.216.34\n", "200 OK", b"http/1.1").await;
        let report = observe_public_egress(
            request(f.address),
            f.roots,
            EgressApproval::isolated_loopback_fixture(f.address),
        )
        .await
        .unwrap();
        assert_eq!(report.ip(), "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(report.source().pinned_ip(), f.address.ip());
        assert_eq!(report.source().server_name(), "localhost");
        assert!(report.observed_at() <= std::time::SystemTime::now());
        f.server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn valid_ipv6_public_echo_is_supported_without_scanning_ipv6() {
    let f = fixture(b"2606:4700:4700::1111", "200 OK", b"http/1.1").await;
    let report = observe_public_egress(
        request(f.address), f.roots,
        EgressApproval::isolated_loopback_fixture(f.address),
    ).await.unwrap();
    assert_eq!(report.ip(), "2606:4700:4700::1111".parse().unwrap());
    f.server.await.unwrap();
}

#[tokio::test]
async fn consent_is_exact_and_prevents_tcp_connect() {
    let f = fixture(b"93.184.216.10", "200 OK", b"http/1.1").await;
    for approval in [
        EgressApproval::Denied,
        EgressApproval::public_https_ip(f.address.ip()),
        EgressApproval::isolated_loopback_fixture(
            SocketAddr::new(f.address.ip(), f.address.port() ^ 1),
        ),
    ] {
        let result = observe_public_egress(
            request(f.address), f.roots.clone(), approval,
        ).await;
        assert!(matches!(result, Err(EgressError::NotApproved)));
    }
    f.server.abort();
}

#[tokio::test]
async fn reject_empty_roots_invalid_host_and_header_injection_before_network() {
    let f = fixture(b"93.184.216.10", "200 OK", b"http/1.1").await;
    let approval = EgressApproval::isolated_loopback_fixture(f.address);
    assert!(matches!(
        observe_public_egress(request(f.address), RootCertStore::empty(), approval).await,
        Err(EgressError::NoTrustAnchors)
    ));
    let mut bad = request(f.address);
    bad.server_name = "127.0.0.1".into();
    assert!(matches!(
        observe_public_egress(bad, f.roots.clone(), approval).await,
        Err(EgressError::InvalidRequest)
    ));
    let mut bad = request(f.address);
    bad.path = "/whoami\r\nHost: attacker.example".into();
    assert!(matches!(
        observe_public_egress(bad, f.roots, approval).await,
        Err(EgressError::InvalidRequest)
    ));
    f.server.abort();
}

#[tokio::test]
async fn wrong_ca_and_hostname_fail_closed() {
    let f = fixture(b"93.184.216.10", "200 OK", b"http/1.1").await;
    let wrong = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(wrong.cert.der().clone()).unwrap();
    assert!(matches!(
        observe_public_egress(
            request(f.address), roots,
            EgressApproval::isolated_loopback_fixture(f.address)
        ).await,
        Err(EgressError::TlsRejected)
    ));
    f.server.await.unwrap();

    let f = fixture(b"93.184.216.10", "200 OK", b"http/1.1").await;
    let mut bad = request(f.address);
    bad.server_name = "wrong.example".into();
    assert!(matches!(
        observe_public_egress(
            bad, f.roots,
            EgressApproval::isolated_loopback_fixture(f.address)
        ).await,
        Err(EgressError::TlsRejected)
    ));
    f.server.await.unwrap();
}

#[tokio::test]
async fn redirects_and_private_echo_and_wrong_alpn_are_not_trusted() {
    for (body, status, alpn, error) in [
        (&b"93.184.216.10"[..], "302 Found", &b"http/1.1"[..], EgressError::InvalidResponse),
        (&b"10.9.8.7"[..], "200 OK", &b"http/1.1"[..], EgressError::UnusableAddress),
        (&b"203.0.113.1"[..], "200 OK", &b"http/1.1"[..], EgressError::UnusableAddress),
        (&b"93.184.216.10"[..], "200 OK", &b"h2"[..], EgressError::TlsRejected),
    ] {
        let f = fixture(body, status, alpn).await;
        assert_eq!(
            observe_public_egress(
                request(f.address), f.roots,
                EgressApproval::isolated_loopback_fixture(f.address)
            ).await.unwrap_err(),
            error
        );
        f.server.await.unwrap();
    }
}

#[tokio::test]
async fn timeouts_and_invalid_deadline_never_return_positive_evidence() {
    let f = fixture(b"93.184.216.10", "200 OK", b"http/1.1").await;
    let mut invalid = request(f.address);
    invalid.deadline = Duration::ZERO;
    assert!(matches!(
        observe_public_egress(
            invalid, f.roots, EgressApproval::isolated_loopback_fixture(f.address)
        ).await,
        Err(EgressError::InvalidRequest)
    ));
    f.server.abort();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stall = tokio::spawn(async move {
        let (_tcp, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut bounded = request(address);
    bounded.deadline = Duration::from_millis(50);
    assert!(matches!(
        observe_public_egress(
            bounded, roots, EgressApproval::isolated_loopback_fixture(address)
        ).await,
        Err(EgressError::TimedOut)
    ));
    stall.abort();
}
