//! Native Linux/Windows loopback H2/TLS 1.3 tests; no external endpoints.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use rustls::{
    pki_types::{PrivatePkcs8KeyDer, ServerName},
    RootCertStore,
};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, net::IpAddr, sync::Arc, time::Duration};
use theia::{
    config::{Inbound, ServerPolicy, User},
    protocol::{Address, Decoder, ErrorCode, Frame, VERSION},
    server::{allowed_destination, serve, AuthFailure, ServerContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const SECRET: [u8; 32] = [0x42; 32];

fn inbound() -> Inbound {
    Inbound {
        id: "public".into(),
        allowed_user_ids: vec!["device-a".into()],
        quic_listen: "127.0.0.1:0".into(),
        h2_listen: "127.0.0.1:0".into(),
        server_name: "localhost".into(),
        tls_cert: "file:/tmp/test-cert.pem".into(),
        tls_key: "file:/tmp/test-key.pem".into(),
    }
}
fn policy(allow_private_ips: bool) -> ServerPolicy {
    ServerPolicy {
        allow_private_ips,
        max_connections_per_user: 2,
        max_connections_total: 8,
        connect_timeout_ms: 1500,
    }
}
fn users() -> Vec<User> {
    let digest = Sha256::digest(SECRET);
    vec![User {
        id: "device-a".into(),
        token_sha256: format!("{digest:x}"),
        disabled: false,
    }]
}
fn bearer() -> String {
    format!("Bearer {}", URL_SAFE_NO_PAD.encode(SECRET))
}
fn context(allow_private: bool) -> ServerContext {
    ServerContext::new(&inbound(), &users(), &policy(allow_private))
}

fn tls_pair() -> (TlsAcceptor, TlsConnector) {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("test-only in-memory certificate");
    let cert = generated.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key.into())
    .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    (
        TlsAcceptor::from(Arc::new(server)),
        TlsConnector::from(Arc::new(client)),
    )
}

async fn send(
    stream: &mut h2::SendStream<Bytes>,
    frame: &Frame,
    end: bool,
) {
    let bytes = Bytes::from(theia::protocol::encode(frame).unwrap());
    stream.reserve_capacity(bytes.len());
    while stream.capacity() < bytes.len() {
        let available = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .expect("h2 stream open")
            .expect("flow control");
        assert!(available > 0);
    }
    stream.send_data(bytes, end).unwrap();
}

async fn next_frame(
    body: &mut h2::RecvStream,
    decoder: &mut Decoder,
    queued: &mut VecDeque<Frame>,
) -> Frame {
    loop {
        if let Some(frame) = queued.pop_front() {
            return frame;
        }
        let chunk = body.data().await.expect("response frame").expect("body bytes");
        let size = chunk.len();
        queued.extend(decoder.feed(&chunk).expect("valid SmartTheia"));
        body.flow_control().release_capacity(size).unwrap();
    }
}

async fn client(
    address: std::net::SocketAddr,
    connector: TlsConnector,
) -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<()>,
) {
    let socket = TcpStream::connect(address).await.unwrap();
    let tls = connector
        .connect(ServerName::try_from("localhost".to_owned()).unwrap(), socket)
        .await
        .expect("validated TLS chain + hostname");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (sender, connection) = h2::client::handshake(tls).await.expect("h2 client handshake");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, driver)
}

fn request(token: &str) -> http::Request<()> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri("https://localhost/v1/session")
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header(http::header::AUTHORIZATION, token)
        .body(())
        .unwrap()
}

#[test]
fn canonical_token_and_inbound_user_grants_are_enforced() {
    let context = context(false);
    let valid = bearer();
    assert!(context.authorize(Some(&valid)).is_ok());
    assert!(matches!(context.authorize(None), Err(AuthFailure::Unauthorized)));
    assert!(matches!(
        context.authorize(Some("Bearer secret")),
        Err(AuthFailure::Unauthorized)
    ));
    assert!(matches!(
        context.authorize(Some(&format!("{valid}="))),
        Err(AuthFailure::Unauthorized)
    ));
    assert!(matches!(
        context.authorize(Some(&format!("Bearer {}", URL_SAFE_NO_PAD.encode([0x43; 32])))),
        Err(AuthFailure::Unauthorized)
    ));

    let mut disabled = users();
    disabled[0].disabled = true;
    assert!(matches!(
        ServerContext::new(&inbound(), &disabled, &policy(false)).authorize(Some(&valid)),
        Err(AuthFailure::Forbidden)
    ));
    let mut forbidden_inbound = inbound();
    forbidden_inbound.allowed_user_ids = vec!["different-user".into()];
    assert!(matches!(
        ServerContext::new(&forbidden_inbound, &users(), &policy(false)).authorize(Some(&valid)),
        Err(AuthFailure::Forbidden)
    ));
    let mut limited = policy(false);
    limited.max_connections_per_user = 1;
    let context = ServerContext::new(&inbound(), &users(), &limited);
    let first = context.authorize(Some(&valid)).unwrap();
    assert!(matches!(context.authorize(Some(&valid)), Err(AuthFailure::Busy)));
    drop(first);
    assert!(context.authorize(Some(&valid)).is_ok());
}

#[test]
fn acl_denies_private_reserved_documentation_and_mapped_ip() {
    for address in [
        "127.0.0.1",
        "10.1.1.2",
        "172.16.0.10",
        "192.168.1.1",
        "169.254.1.2",
        "100.64.1.2",
        "198.18.0.1",
        "192.0.2.3",
        "203.0.113.2",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(
            !allowed_destination(address.parse::<IpAddr>().unwrap(), false),
            "{address}"
        );
    }
    for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
        assert!(allowed_destination(address.parse().unwrap(), false));
    }
    assert!(allowed_destination("127.0.0.1".parse().unwrap(), true));
    assert!(!allowed_destination("0.0.0.0".parse().unwrap(), true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_tls_stream_acknowledges_tcp_open_only_after_echo_dial() {
    timeout(Duration::from_secs(15), async {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut socket, _) = echo.accept().await.unwrap();
            let mut content = Vec::new();
            socket.read_to_end(&mut content).await.unwrap();
            socket.write_all(&content).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, acceptor, Arc::new(context(true))));
        let (mut sender, driver) = client(address, connector).await;
        let (response_future, mut tx) = sender.send_request(request(&bearer()), false).unwrap();

        send(&mut tx, &Frame::Hello { version: VERSION, capabilities: 0 }, false).await;
        let response = response_future.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut rx = response.into_body();
        let mut decoder = Decoder::new();
        let mut queue = VecDeque::new();
        assert_eq!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::HelloAck { version: VERSION, accepted_capabilities: 0 }
        );
        // HELLO_ACK is intentionally received before request EOF.
        send(
            &mut tx,
            &Frame::OpenTcp {
                address: Address::V4([127, 0, 0, 1]),
                port: target.port(),
            },
            false,
        ).await;
        assert_eq!(next_frame(&mut rx, &mut decoder, &mut queue).await, Frame::OpenOk);
        send(&mut tx, &Frame::Data(b"protected echo".to_vec()), false).await;
        send(&mut tx, &Frame::Fin, true).await;
        assert_eq!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::Data(b"protected echo".to_vec())
        );
        assert_eq!(next_frame(&mut rx, &mut decoder, &mut queue).await, Frame::Fin);
        while let Some(chunk) = rx.data().await {
            assert!(chunk.unwrap().is_empty(), "no DATA after terminal SmartTheia frame");
        }
        decoder.finish().unwrap();
        echo_task.await.unwrap();
        driver.abort();
        server.abort();
    }).await.expect("TLS/H2 authenticated echo timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_tls_default_policy_rejects_private_ip_without_tcp_dial() {
    timeout(Duration::from_secs(12), async {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, acceptor, Arc::new(context(false))));
        let (mut sender, driver) = client(address, connector).await;
        let (response_future, mut tx) = sender.send_request(request(&bearer()), false).unwrap();
        send(&mut tx, &Frame::Hello { version: VERSION, capabilities: 0 }, false).await;
        let response = response_future.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut rx = response.into_body();
        let mut decoder = Decoder::new();
        let mut queue = VecDeque::new();
        assert!(matches!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::HelloAck { .. }
        ));
        send(&mut tx, &Frame::OpenTcp {
            address: Address::V4([127, 0, 0, 1]),
            port: target.port(),
        }, true).await;
        assert_eq!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::OpenError(ErrorCode::PolicyDenied)
        );
        while let Some(chunk) = rx.data().await {
            assert!(chunk.unwrap().is_empty(), "no DATA after terminal SmartTheia frame");
        }
        decoder.finish().unwrap();
        assert!(timeout(Duration::from_millis(250), echo.accept()).await.is_err());
        driver.abort();
        server.abort();
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_tls_rejects_missing_bearer_before_smarttheia() {
    timeout(Duration::from_secs(10), async {
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, acceptor, Arc::new(context(true))));
        let (mut sender, driver) = client(address, connector).await;
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/v1/session")
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .body(())
            .unwrap();
        let (response_future, _) = sender.send_request(req, true).unwrap();
        let response = response_future.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        driver.abort();
        server.abort();
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_wrong_hostname_and_untrusted_ca_fail_closed() {
    timeout(Duration::from_secs(10), async {
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, acceptor, Arc::new(context(true))));
        let socket = TcpStream::connect(address).await.unwrap();
        assert!(connector.connect(
            ServerName::try_from("wrong.example".to_owned()).unwrap(),
            socket,
        ).await.is_err());

        // A distinct, valid CA must not authenticate this listener.
        let unrelated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(unrelated.cert.der().clone()).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let untrusted = TlsConnector::from(Arc::new(tls));
        let socket = TcpStream::connect(address).await.unwrap();
        assert!(untrusted.connect(
            ServerName::try_from("localhost".to_owned()).unwrap(),
            socket,
        ).await.is_err());
        server.abort();
    }).await.unwrap();
}
