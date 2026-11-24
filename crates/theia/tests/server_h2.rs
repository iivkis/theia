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
        security_mode: Default::default(),
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

async fn send(stream: &mut h2::SendStream<Bytes>, frame: &Frame, end: bool) {
    let mut bytes = Bytes::from(theia::protocol::encode(frame).unwrap());
    while !bytes.is_empty() {
        stream.reserve_capacity(bytes.len());
        let available = if stream.capacity() == 0 {
            std::future::poll_fn(|cx| stream.poll_capacity(cx))
                .await
                .expect("h2 stream open")
                .expect("flow control")
        } else {
            stream.capacity()
        };
        if available == 0 {
            continue;
        }
        let part = bytes.split_to(available.min(bytes.len()));
        stream.send_data(part, end && bytes.is_empty()).unwrap();
    }
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
        let chunk = body
            .data()
            .await
            .expect("response frame")
            .expect("body bytes");
        let size = chunk.len();
        queued.extend(decoder.feed(&chunk).expect("valid SmartTheia"));
        body.flow_control().release_capacity(size).unwrap();
    }
}

async fn client(
    address: std::net::SocketAddr,
    connector: TlsConnector,
) -> (h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>) {
    client_with_window(address, connector, 65_535).await
}

async fn client_with_window(
    address: std::net::SocketAddr,
    connector: TlsConnector,
    window: u32,
) -> (h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>) {
    let socket = TcpStream::connect(address).await.unwrap();
    let tls = connector
        .connect(
            ServerName::try_from("localhost".to_owned()).unwrap(),
            socket,
        )
        .await
        .expect("validated TLS chain + hostname");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(window);
    let (sender, connection) = builder.handshake(tls).await.expect("h2 client handshake");
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
    assert!(matches!(
        context.authorize(None),
        Err(AuthFailure::Unauthorized)
    ));
    assert!(matches!(
        context.authorize(Some("Bearer secret")),
        Err(AuthFailure::Unauthorized)
    ));
    assert!(matches!(
        context.authorize(Some(&format!("{valid}="))),
        Err(AuthFailure::Unauthorized)
    ));
    assert!(matches!(
        context.authorize(Some(&format!(
            "Bearer {}",
            URL_SAFE_NO_PAD.encode([0x43; 32])
        ))),
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
    assert!(matches!(
        context.authorize(Some(&valid)),
        Err(AuthFailure::Busy)
    ));
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

        send(
            &mut tx,
            &Frame::Hello {
                version: VERSION,
                capabilities: 0,
            },
            false,
        )
        .await;
        let response = response_future.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut rx = response.into_body();
        let mut decoder = Decoder::new();
        let mut queue = VecDeque::new();
        assert_eq!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::HelloAck {
                version: VERSION,
                accepted_capabilities: 0
            }
        );
        // HELLO_ACK is intentionally received before request EOF.
        send(
            &mut tx,
            &Frame::OpenTcp {
                address: Address::V4([127, 0, 0, 1]),
                port: target.port(),
            },
            false,
        )
        .await;
        assert_eq!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::OpenOk
        );
        send(&mut tx, &Frame::Data(b"protected echo".to_vec()), false).await;
        send(&mut tx, &Frame::Fin, true).await;
        assert_eq!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::Data(b"protected echo".to_vec())
        );
        assert_eq!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::Fin
        );
        while let Some(chunk) = rx.data().await {
            assert!(
                chunk.unwrap().is_empty(),
                "no DATA after terminal SmartTheia frame"
            );
        }
        decoder.finish().unwrap();
        echo_task.await.unwrap();
        driver.abort();
        server.abort();
    })
    .await
    .expect("TLS/H2 authenticated echo timed out");
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
        send(
            &mut tx,
            &Frame::Hello {
                version: VERSION,
                capabilities: 0,
            },
            false,
        )
        .await;
        let response = response_future.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut rx = response.into_body();
        let mut decoder = Decoder::new();
        let mut queue = VecDeque::new();
        assert!(matches!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::HelloAck { .. }
        ));
        send(
            &mut tx,
            &Frame::OpenTcp {
                address: Address::V4([127, 0, 0, 1]),
                port: target.port(),
            },
            true,
        )
        .await;
        assert_eq!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::OpenError(ErrorCode::PolicyDenied)
        );
        while let Some(chunk) = rx.data().await {
            assert!(
                chunk.unwrap().is_empty(),
                "no DATA after terminal SmartTheia frame"
            );
        }
        decoder.finish().unwrap();
        assert!(timeout(Duration::from_millis(250), echo.accept())
            .await
            .is_err());
        driver.abort();
        server.abort();
    })
    .await
    .unwrap();
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
        assert!(response.into_body().data().await.is_none());

        sender = sender.ready().await.unwrap();
        let wrong = format!("Bearer {}", URL_SAFE_NO_PAD.encode([0x7e; 32]));
        let (response_future, _) = sender.send_request(request(&wrong), true).unwrap();
        let response = response_future.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        assert!(response.into_body().data().await.is_none());

        // HTTP 200 acknowledges headers, not an OPEN_OK or TCP relay.
        sender = sender.ready().await.unwrap();
        let (response_future, _tx) = sender.send_request(request(&bearer()), false).unwrap();
        let response = response_future.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        driver.abort();
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_wrong_hostname_and_untrusted_ca_fail_closed() {
    timeout(Duration::from_secs(10), async {
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, acceptor, Arc::new(context(true))));
        let socket = TcpStream::connect(address).await.unwrap();
        assert!(connector
            .connect(
                ServerName::try_from("wrong.example".to_owned()).unwrap(),
                socket,
            )
            .await
            .is_err());

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
        assert!(untrusted
            .connect(
                ServerName::try_from("localhost".to_owned()).unwrap(),
                socket,
            )
            .await
            .is_err());
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_peer_request_budget_returns_429_on_same_connection() {
    timeout(Duration::from_secs(15), async {
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, acceptor, Arc::new(context(false))));
        let (mut sender, driver) = client(address, connector).await;
        for _ in 0..120 {
            sender = sender.ready().await.unwrap();
            let (response, _) = sender.send_request(request("invalid"), true).unwrap();
            assert_eq!(
                response.await.unwrap().status(),
                http::StatusCode::UNAUTHORIZED
            );
        }
        sender = sender.ready().await.unwrap();
        let (response, _) = sender.send_request(request(&bearer()), true).unwrap();
        assert_eq!(
            response.await.unwrap().status(),
            http::StatusCode::TOO_MANY_REQUESTS
        );
        driver.abort();
        server.abort();
        let _ = server.await;
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_listener_releases_live_tunnel_and_session_permits() {
    timeout(Duration::from_secs(12), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let context = Arc::new(context(true));
        let server = tokio::spawn(serve(listener, acceptor, context.clone()));
        let (mut sender, driver) = client(address, connector).await;
        let (response, mut tx) = sender.send_request(request(&bearer()), false).unwrap();
        send(
            &mut tx,
            &Frame::Hello {
                version: VERSION,
                capabilities: 0,
            },
            false,
        )
        .await;
        let mut rx = response.await.unwrap().into_body();
        let mut decoder = Decoder::new();
        let mut queue = VecDeque::new();
        assert!(matches!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::HelloAck { .. }
        ));
        send(
            &mut tx,
            &Frame::OpenTcp {
                address: Address::V4([127, 0, 0, 1]),
                port: destination.port(),
            },
            false,
        )
        .await;
        assert_eq!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::OpenOk
        );
        let (mut remote, _) = target.accept().await.unwrap();
        let held = context.authorize(Some(&bearer())).unwrap();
        assert!(matches!(
            context.authorize(Some(&bearer())),
            Err(AuthFailure::Busy)
        ));
        server.abort();
        let _ = server.await;
        let mut byte = [0u8; 1];
        assert_eq!(remote.read(&mut byte).await.unwrap(), 0);
        // Drop recursion in JoinSet is asynchronous; wait for child permit release.
        let recovered = timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(permit) = context.authorize(Some(&bearer())) {
                    break permit;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(recovered);
        drop(held);
        driver.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_acl_checks_server_resolved_localhost_before_dial() {
    timeout(Duration::from_secs(12), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, acceptor, Arc::new(context(false))));
        let (mut sender, driver) = client(address, connector).await;
        let (response, mut tx) = sender.send_request(request(&bearer()), false).unwrap();
        send(
            &mut tx,
            &Frame::Hello {
                version: VERSION,
                capabilities: 0,
            },
            false,
        )
        .await;
        let mut rx = response.await.unwrap().into_body();
        let mut decoder = Decoder::new();
        let mut queue = VecDeque::new();
        assert!(matches!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::HelloAck { .. }
        ));
        send(
            &mut tx,
            &Frame::OpenTcp {
                address: Address::Dns("localhost".into()),
                port: destination.port(),
            },
            true,
        )
        .await;
        assert_eq!(
            next_frame(&mut rx, &mut decoder, &mut queue).await,
            Frame::OpenError(ErrorCode::PolicyDenied)
        );
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        driver.abort();
        server.abort();
        let _ = server.await;
    })
    .await
    .unwrap();
}

async fn open_tunnel(
    sender: &mut h2::client::SendRequest<Bytes>,
    port: u16,
) -> (
    h2::SendStream<Bytes>,
    h2::RecvStream,
    Decoder,
    VecDeque<Frame>,
) {
    let (response, mut tx) = sender.send_request(request(&bearer()), false).unwrap();
    send(
        &mut tx,
        &Frame::Hello {
            version: VERSION,
            capabilities: 0,
        },
        false,
    )
    .await;
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut rx = response.into_body();
    let mut decoder = Decoder::new();
    let mut queue = VecDeque::new();
    assert!(matches!(
        next_frame(&mut rx, &mut decoder, &mut queue).await,
        Frame::HelloAck { .. }
    ));
    send(
        &mut tx,
        &Frame::OpenTcp {
            address: Address::V4([127, 0, 0, 1]),
            port,
        },
        false,
    )
    .await;
    assert_eq!(
        next_frame(&mut rx, &mut decoder, &mut queue).await,
        Frame::OpenOk
    );
    (tx, rx, decoder, queue)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_h2_response_reader_does_not_block_tcp_upload() {
    timeout(Duration::from_secs(15), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, acceptor, Arc::new(context(true))));
        let (mut sender, driver) = client_with_window(address, connector, 1024).await;
        let (mut tx, mut rx, mut decoder, mut queue) = open_tunnel(&mut sender, port).await;
        let (remote, _) = target.accept().await.unwrap();
        let (mut read, mut write) = remote.into_split();
        let payload = (0..256 * 1024).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            write.write_all(&payload).await.unwrap();
            write.shutdown().await.unwrap();
        });
        let held = rx.data().await.unwrap().unwrap();
        assert!(!held.is_empty());
        // Withhold all response window credit. The server must still accept
        // an upload while its download cannot finish even a 4 KiB frame.
        tokio::time::sleep(Duration::from_millis(100)).await;
        send(
            &mut tx,
            &Frame::Data(b"upload under backpressure".to_vec()),
            false,
        )
        .await;
        send(&mut tx, &Frame::Fin, true).await;
        let mut upload = Vec::new();
        timeout(Duration::from_secs(3), read.read_to_end(&mut upload))
            .await
            .expect("upstream must not wait for response credit")
            .unwrap();
        assert_eq!(upload, b"upload under backpressure");
        queue.extend(decoder.feed(&held).unwrap());
        rx.flow_control().release_capacity(held.len()).unwrap();

        let mut downloaded = Vec::new();
        loop {
            match next_frame(&mut rx, &mut decoder, &mut queue).await {
                Frame::Data(data) => downloaded.extend(data),
                Frame::Fin => break,
                other => panic!("unexpected response frame: {other:?}"),
            }
        }
        assert_eq!(downloaded, expected);
        assert!(queue.is_empty());
        decoder.finish().unwrap();
        while let Some(chunk) = rx.data().await {
            assert!(chunk.unwrap().is_empty());
        }
        writer.await.unwrap();
        driver.abort();
        server.abort();
        let _ = server.await;
    })
    .await
    .expect("bounded two-way transfer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_h2_tunnels_survive_one_stream_reset() {
    timeout(Duration::from_secs(20), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut limits = policy(true);
        limits.max_connections_per_user = 8;
        let context = Arc::new(ServerContext::new(&inbound(), &users(), &limits));
        let server = tokio::spawn(serve(listener, acceptor, context.clone()));
        let (mut sender, driver) = client(address, connector).await;
        let mut tunnels = Vec::new();
        let mut sockets = Vec::new();
        for _ in 0..8 {
            sender = sender.ready().await.unwrap();
            tunnels.push(open_tunnel(&mut sender, port).await);
            sockets.push(target.accept().await.unwrap().0);
        }
        assert!(matches!(
            context.authorize(Some(&bearer())),
            Err(AuthFailure::Busy)
        ));
        let (mut cancelled, _rx, _decoder, _queue) = tunnels.pop().unwrap();
        let mut cancelled_peer = sockets.pop().unwrap();
        cancelled.send_reset(h2::Reason::CANCEL);
        let mut byte = [0u8; 1];
        let closed = timeout(Duration::from_secs(3), cancelled_peer.read(&mut byte))
            .await
            .expect("reset must close upstream TCP");
        assert!(
            matches!(closed, Ok(0))
                || closed.is_err_and(|e| {
                    matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    )
                })
        );

        let mut echo_tasks = tokio::task::JoinSet::new();
        for mut socket in sockets {
            echo_tasks.spawn(async move {
                let mut content = Vec::new();
                socket.read_to_end(&mut content).await.unwrap();
                socket.write_all(&content).await.unwrap();
                socket.shutdown().await.unwrap();
            });
        }
        let mut clients = tokio::task::JoinSet::new();
        for (index, (mut tx, mut rx, mut decoder, mut queue)) in tunnels.into_iter().enumerate() {
            clients.spawn(async move {
                let payload = vec![index as u8; 32 * 1024];
                send(&mut tx, &Frame::Data(payload.clone()), false).await;
                send(&mut tx, &Frame::Fin, true).await;
                let mut received = Vec::new();
                loop {
                    match next_frame(&mut rx, &mut decoder, &mut queue).await {
                        Frame::Data(data) => received.extend(data),
                        Frame::Fin => break,
                        other => panic!("sibling stream damaged: {other:?}"),
                    }
                }
                assert_eq!(received, payload);
                assert!(queue.is_empty());
                decoder.finish().unwrap();
                while let Some(chunk) = rx.data().await {
                    assert!(chunk.unwrap().is_empty());
                }
            });
        }
        while let Some(result) = clients.join_next().await {
            result.unwrap();
        }
        while let Some(result) = echo_tasks.join_next().await {
            result.unwrap();
        }
        // Connection remains usable after all eight sessions finish.
        sender = sender.ready().await.unwrap();
        let (response, _) = sender.send_request(request("invalid"), true).unwrap();
        assert_eq!(
            response.await.unwrap().status(),
            http::StatusCode::UNAUTHORIZED
        );
        driver.abort();
        server.abort();
        let _ = server.await;
    })
    .await
    .expect("eight independent live H2 streams");
}

// H3 already refuses HTTP trailers. H2 must not interpret a trailing header
// block after SmartTheia FIN as a clean end of the byte stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_request_trailers_after_fin_reset_the_stream() {
    timeout(Duration::from_secs(10), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let (acceptor, connector) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(listener, acceptor, Arc::new(context(true))));
        let (mut sender, driver) = client(address, connector).await;
        let (mut tx, mut rx, _, _) = open_tunnel(&mut sender, port).await;
        let (mut remote, _) = target.accept().await.unwrap();
        send(&mut tx, &Frame::Fin, false).await;
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-unexpected", http::HeaderValue::from_static("1"));
        tx.send_trailers(trailers).unwrap();
        // The server may have emitted response DATA/FIN before it sees
        // the invalid trailers, but must never complete with clean EOF.
        remote.shutdown().await.unwrap();
        loop {
            match rx.data().await {
                Some(Ok(chunk)) => rx.flow_control().release_capacity(chunk.len()).unwrap(),
                Some(Err(_)) => break,
                None => panic!("H2 request trailers were accepted as clean EOF"),
            }
        }
        driver.abort();
        server.abort();
    })
    .await
    .expect("bounded trailer rejection");
}
