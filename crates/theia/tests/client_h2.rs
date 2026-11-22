//! Real M2.2a H2 client against the production M2.1 listener.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use theia::{
    client::{ClientError, H2Client},
    config::{Inbound, ServerPolicy, User},
    protocol::{Address, ErrorCode},
    server::{serve, ServerContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const TOKEN: [u8; 32] = [0x42; 32];

async fn listener(
    private: bool,
) -> (
    String,
    RootCertStore,
    JoinHandle<Result<(), theia::server::ServerError>>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der.clone()], key.into())
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let mut roots = RootCertStore::empty();
    roots.add(der).unwrap();
    let inbound = Inbound {
        id: "test".into(),
        allowed_user_ids: vec!["client".into()],
        h2_listen: "127.0.0.1:0".into(),
        quic_listen: "127.0.0.1:0".into(),
        server_name: "localhost".into(),
        tls_cert: "unused-test-fixture".into(),
        tls_key: "unused-test-fixture".into(),
    };
    let user = User {
        id: "client".into(),
        token_sha256: format!("{:x}", Sha256::digest(TOKEN)),
        disabled: false,
    };
    let policy = ServerPolicy {
        allow_private_ips: private,
        max_connections_per_user: 8,
        max_connections_total: 8,
        connect_timeout_ms: 1500,
    };
    let context = Arc::new(ServerContext::new(&inbound, &[user], &policy));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let task = tokio::spawn(serve(listener, acceptor, context));
    (endpoint, roots, task)
}

fn token() -> String {
    URL_SAFE_NO_PAD.encode(TOKEN)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_client_opens_dns_target_and_relays_both_fins() {
    timeout(Duration::from_secs(15), async {
        let (endpoint, roots, server) = listener(true).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut data = Vec::new();
            socket.read_to_end(&mut data).await.unwrap();
            socket.write_all(&data).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let client = H2Client::new(&endpoint, "localhost", &token(), roots).unwrap();
        let tunnel = client
            .open(Address::Dns("localhost".into()), port)
            .await
            .unwrap();
        let (mut app, local) = tokio::io::duplex(4096);
        let relay = tokio::spawn(tunnel.relay(local));
        let payload: Vec<_> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
        app.write_all(&payload).await.unwrap();
        app.shutdown().await.unwrap();
        let mut received = Vec::new();
        app.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, payload);
        relay.await.unwrap().unwrap();
        echo.await.unwrap();
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificate_auth_and_acl_failures_never_return_tunnel() {
    timeout(Duration::from_secs(15), async {
        let (endpoint, roots, server) = listener(false).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let addr = Address::Dns("localhost".into());
        let wrong_name =
            H2Client::new(&endpoint, "wrong.example", &token(), roots.clone()).unwrap();
        assert!(matches!(
            wrong_name.open(addr.clone(), port).await,
            Err(ClientError::Tls)
        ));
        let unrelated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut untrusted = RootCertStore::empty();
        untrusted.add(unrelated.cert.der().clone()).unwrap();
        let wrong_ca = H2Client::new(&endpoint, "localhost", &token(), untrusted).unwrap();
        assert!(matches!(
            wrong_ca.open(addr.clone(), port).await,
            Err(ClientError::Tls)
        ));
        let wrong_token = H2Client::new(
            &endpoint,
            "localhost",
            &URL_SAFE_NO_PAD.encode([0x43; 32]),
            roots.clone(),
        )
        .unwrap();
        assert!(matches!(
            wrong_token.open(addr.clone(), port).await,
            Err(ClientError::Unauthorized)
        ));
        let valid = H2Client::new(&endpoint, "localhost", &token(), roots).unwrap();
        assert!(matches!(
            valid.open(addr, port).await,
            Err(ClientError::Open(ErrorCode::PolicyDenied))
        ));
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        server.abort();
    })
    .await
    .unwrap();
}

#[test]
fn rejects_missing_trust_and_noncanonical_token() {
    assert!(matches!(
        H2Client::new(
            "localhost:443",
            "localhost",
            &token(),
            RootCertStore::empty()
        ),
        Err(ClientError::Configuration)
    ));
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    assert!(matches!(
        H2Client::new(
            "localhost:443",
            "localhost",
            &format!("{}=", token()),
            roots
        ),
        Err(ClientError::Configuration)
    ));
}
