//! Real isolated H2 and H3 application-level readiness witnesses.
//! TLS/ALPN alone cannot satisfy this check; no public host is contacted.
use crate::{
    config::{Inbound, ServerPolicy, User},
    owned_endpoint::{self, HttpWitness},
    security_profile::{CertificatePin, SecurityMode},
    server::ServerContext,
};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, task::JoinSet, time::timeout};
use tokio_rustls::TlsAcceptor;

struct Fixture {
    address: SocketAddr,
    roots: RootCertStore,
    pin: CertificatePin,
    _servers: JoinSet<Result<(), crate::server::ServerError>>,
}

async fn fixture(serve_http: bool) -> Fixture {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = generated.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
    let pin = CertificatePin::from_der(cert.as_ref());
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key.clone_key().into())
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let mut pair = None;
    for _ in 0..32 {
        let udp = crate::quic_transport::server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![cert.clone()],
            key.clone_key().into(),
        )
        .unwrap();
        let address = udp.local_addr().unwrap();
        if let Ok(tcp) = TcpListener::bind(address).await {
            pair = Some((udp, tcp, address));
            break;
        }
    }
    let (udp, tcp, address) = pair.expect("native shared loopback port");
    let inbound = Inbound {
        id: "owned".into(),
        security_mode: SecurityMode::Plain,
        reality_key: None,
        allowed_user_ids: vec!["fixture".into()],
        h2_listen: address.to_string(),
        quic_listen: address.to_string(),
        server_name: "localhost".into(),
        tls_cert: "unused".into(),
        tls_key: "unused".into(),
    };
    let user = User {
        id: "fixture".into(),
        token_sha256: "42".repeat(32),
        disabled: false,
    };
    let policy = ServerPolicy {
        allow_private_ips: false,
        max_connections_per_user: 8,
        max_connections_total: 16,
        connect_timeout_ms: 1500,
    };
    let context = Arc::new(ServerContext::new(&inbound, &[user], &policy));
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let mut servers = JoinSet::new();
    servers.spawn(crate::server::serve(tcp, acceptor, context.clone()));
    if serve_http {
        servers.spawn(crate::h3_server::serve(udp, context));
    } else {
        // Real verified QUIC ALPN but no HTTP/3 driver, requests or responses.
        servers.spawn(async move {
            let incoming = udp.accept().await.unwrap();
            let connection = crate::quic_transport::accept(incoming).await.unwrap();
            tokio::time::sleep(Duration::from_secs(6)).await;
            drop(connection);
            Ok(())
        });
    }
    Fixture {
        address,
        roots,
        pin,
        _servers: servers,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owned_readiness_requires_real_http_on_both_transports_and_exact_leaf() {
    timeout(Duration::from_secs(20), async {
        let fixture = fixture(true).await;
        // A real final HTTP response even when the route is not served.
        let witness = owned_endpoint::verify(
            fixture.address,
            "localhost",
            fixture.roots.clone(),
            fixture.pin,
        )
        .await
        .unwrap();
        assert_eq!(witness, HttpWitness { h2: 404, h3: 404 });
        let wrong = CertificatePin::from_der(b"not the reviewed leaf");
        assert!(
            owned_endpoint::verify(fixture.address, "localhost", fixture.roots.clone(), wrong)
                .await
                .is_err()
        );
        assert!(owned_endpoint::verify(
            fixture.address,
            "wrong.example",
            fixture.roots.clone(),
            fixture.pin
        )
        .await
        .is_err());
        assert!(owned_endpoint::verify(
            fixture.address,
            "localhost",
            RootCertStore::empty(),
            fixture.pin
        )
        .await
        .is_err());
        let tls_only = fixture_without_h3().await;
        assert!(owned_endpoint::verify(
            tls_only.address,
            "localhost",
            tls_only.roots.clone(),
            tls_only.pin
        )
        .await
        .is_err());
    })
    .await
    .expect("bounded real owned endpoint readiness matrix");
}

async fn fixture_without_h3() -> Fixture {
    fixture(false).await
}
