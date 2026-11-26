//! Real native CI H3 server regression, using a raw verified H3 client fixture.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::{Buf, Bytes};
use http::{Request, StatusCode};
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, net::SocketAddr, sync::Arc, time::Duration};
use theia::{
    client::ClientError,
    config::{Inbound, ServerPolicy, User},
    h3_client::H3Client,
    h3_server,
    protocol::{self, Address, Decoder, ErrorCode, Frame},
    quic_transport,
    server::ServerContext,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};

const TOKEN: [u8; 32] = [0x42; 32];
type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ServerTask = JoinHandle<Result<(), theia::server::ServerError>>;

fn token() -> String {
    URL_SAFE_NO_PAD.encode(TOKEN)
}

fn fixture(private: bool) -> (quinn::Endpoint, SocketAddr, ServerTask) {
    let (client, remote, task, _roots) = fixture_with_roots(private);
    (client, remote, task)
}

fn fixture_with_roots(private: bool) -> (quinn::Endpoint, SocketAddr, ServerTask, RootCertStore) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let bind = "127.0.0.1:0".parse().unwrap();
    let endpoint = quic_transport::server_endpoint(bind, vec![der.clone()], key.into()).unwrap();
    let remote = endpoint.local_addr().unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(der).unwrap();
    let client = quic_transport::client_endpoint(bind, roots.clone()).unwrap();
    let server = tokio::spawn(h3_server::serve(endpoint, context(private)));
    (client, remote, server, roots)
}

fn context(private: bool) -> Arc<ServerContext> {
    let inbound = Inbound {
        id: "test".into(),
        path_prefix: Some("/v1/theia-example".into()),
        allowed_user_ids: vec!["allowed".into()],
        h2_listen: "127.0.0.1:0".into(),
        quic_listen: "127.0.0.1:0".into(),
        server_name: "localhost".into(),
        tls_cert: "unused".into(),
        security_mode: Default::default(),
        reality: None,
        tls_key: "unused".into(),
    };
    let users = [
        User {
            id: "allowed".into(),
            token_sha256: format!("{:x}", Sha256::digest(TOKEN)),
            disabled: false,
        },
        User {
            id: "other".into(),
            token_sha256: format!("{:x}", Sha256::digest([0x43; 32])),
            disabled: false,
        },
    ];
    let policy = ServerPolicy {
        routing: None,
        allow_private_ips: private,
        max_connections_per_user: 8,
        max_connections_total: 8,
        connect_timeout_ms: 2000,
    };
    Arc::new(ServerContext::new(&inbound, &users, &policy))
}

fn request(auth: Option<&str>) -> Request<()> {
    let mut request = Request::post("https://localhost/v1/theia-example/session")
        .header("content-type", "application/octet-stream");
    if let Some(token) = auth {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    request.body(()).unwrap()
}

async fn send(stream: &mut ClientStream, frame: Frame) {
    stream
        .send_data(Bytes::from(protocol::encode(&frame).unwrap()))
        .await
        .unwrap();
}

#[derive(Default)]
struct Frames {
    decoder: Decoder,
    ready: VecDeque<Frame>,
}

impl Frames {
    async fn next(&mut self, stream: &mut ClientStream) -> Option<Frame> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Some(frame);
            }
            let Some(mut data) = stream.recv_data().await.unwrap() else {
                self.decoder.finish().unwrap();
                return None;
            };
            self.ready.extend(
                self.decoder
                    .feed(&data.copy_to_bytes(data.remaining()))
                    .unwrap(),
            );
        }
    }
}

async fn open(stream: &mut ClientStream, frames: &mut Frames, port: u16) -> Frame {
    assert_eq!(stream.recv_response().await.unwrap().status(), 200);
    send(
        stream,
        Frame::Hello {
            version: protocol::VERSION,
            capabilities: 0,
        },
    )
    .await;
    assert_eq!(
        frames.next(stream).await,
        Some(Frame::HelloAck {
            version: protocol::VERSION,
            accepted_capabilities: 0,
        })
    );
    send(
        stream,
        Frame::OpenTcp {
            address: Address::Dns("localhost".into()),
            port,
        },
    )
    .await;
    frames.next(stream).await.unwrap()
}

async fn open_with_padding(stream: &mut ClientStream, frames: &mut Frames, port: u16) -> Frame {
    assert_eq!(stream.recv_response().await.unwrap().status(), 200);
    send(
        stream,
        Frame::Hello {
            version: protocol::VERSION,
            capabilities: protocol::CAP_PADDING,
        },
    )
    .await;
    assert_eq!(
        frames.next(stream).await,
        Some(Frame::HelloAck {
            version: protocol::VERSION,
            accepted_capabilities: protocol::CAP_PADDING,
        })
    );
    send(stream, Frame::Padding(vec![0x91; 1024])).await;
    send(
        stream,
        Frame::OpenTcp {
            address: Address::Dns("localhost".into()),
            port,
        },
    )
    .await;
    frames.next(stream).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_h3_server_relays_tcp_before_request_fin_and_after_half_close() {
    timeout(Duration::from_secs(20), async {
        let (endpoint, remote, server) = fixture(true);
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut tcp, _) = target.accept().await.unwrap();
            let mut first = [0; 5];
            tcp.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"early");
            tcp.write_all(&first).await.unwrap();
            let mut rest = Vec::new();
            tcp.read_to_end(&mut rest).await.unwrap();
            tcp.write_all(&rest).await.unwrap();
            tcp.shutdown().await.unwrap();
        });
        let conn = quic_transport::connect(&endpoint, remote, "localhost")
            .await
            .unwrap();
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let mut stream = sender.send_request(request(Some(&token()))).await.unwrap();
        let mut frames = Frames::default();
        assert_eq!(
            open_with_padding(&mut stream, &mut frames, port).await,
            Frame::OpenOk
        );
        send(&mut stream, Frame::Padding(vec![0x13; 123])).await;
        send(&mut stream, Frame::Data(b"early".to_vec())).await;
        assert_eq!(
            frames.next(&mut stream).await,
            Some(Frame::Data(b"early".to_vec()))
        );
        let payload: Vec<_> = (0..128 * 1024).map(|n| (n % 251) as u8).collect();
        for chunk in payload.chunks(4096) {
            send(&mut stream, Frame::Data(chunk.to_vec())).await;
        }
        send(&mut stream, Frame::Fin).await;
        stream.finish().await.unwrap();
        let mut received = Vec::new();
        loop {
            match frames.next(&mut stream).await.unwrap() {
                Frame::Data(data) => received.extend(data),
                Frame::Fin => break,
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        assert_eq!(received, payload);
        assert!(frames.next(&mut stream).await.is_none());
        echo.await.unwrap();
        driver.abort();
        server.abort();
        endpoint.close(0u32.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_rejects_missing_wrong_and_ungranted_bearers_and_denied_tcp() {
    timeout(Duration::from_secs(20), async {
        let (endpoint, remote, server) = fixture(false);
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let conn = quic_transport::connect(&endpoint, remote, "localhost")
            .await
            .unwrap();
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let wrong = URL_SAFE_NO_PAD.encode([0x44; 32]);
        let other = URL_SAFE_NO_PAD.encode([0x43; 32]);
        for (auth, status) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some(wrong.as_str()), StatusCode::UNAUTHORIZED),
            (Some(other.as_str()), StatusCode::FORBIDDEN),
        ] {
            let mut stream = sender.send_request(request(auth)).await.unwrap();
            // Authorization must reject from request headers without waiting
            // for request EOF. Finishing the upload races the server's
            // intentional STOP_SENDING(H3_REQUEST_CANCELLED) on Windows.
            assert_eq!(stream.recv_response().await.unwrap().status(), status);
            // The server sends an HTTP denial and stops reading the rejected
            // request. Depending on the QUIC scheduler, the response body may
            // end with FIN or the expected cancellation; neither carries DATA.
            match stream.recv_data().await {
                Ok(None) => {}
                Err(h3::error::StreamError::RemoteTerminate { code, .. })
                    if code == h3::error::Code::H3_REQUEST_CANCELLED => {}
                _ => panic!("denied H3 response must have no body or unexpected reset"),
            }
        }

        let mut stream = sender.send_request(request(Some(&token()))).await.unwrap();
        let mut frames = Frames::default();
        assert_eq!(
            open(&mut stream, &mut frames, port).await,
            Frame::OpenError(ErrorCode::PolicyDenied)
        );
        assert!(frames.next(&mut stream).await.is_none());
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        driver.abort();
        server.abort();
        endpoint.close(0u32.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_h3_client_and_server_relay_exact_bytes() {
    timeout(Duration::from_secs(20), async {
        let (_endpoint, remote, server, roots) = fixture_with_roots(true);
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut tcp, _) = target.accept().await.unwrap();
            let mut early = [0; 5];
            tcp.read_exact(&mut early).await.unwrap();
            tcp.write_all(&early).await.unwrap();
            let mut rest = Vec::new();
            tcp.read_to_end(&mut rest).await.unwrap();
            tcp.write_all(&rest).await.unwrap();
            tcp.shutdown().await.unwrap();
        });
        let client = H3Client::new(remote, "localhost", &token(), roots).unwrap();
        let tunnel = client
            .open(Address::Dns("localhost".into()), port)
            .await
            .unwrap();
        let (mut app, local) = tokio::io::duplex(4096);
        let relay = tokio::spawn(tunnel.relay(local));
        app.write_all(b"early").await.unwrap();
        let mut reply = [0; 5];
        app.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"early");
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
async fn production_h3_client_rejects_tls_bearer_and_acl_failures() {
    timeout(Duration::from_secs(20), async {
        let (_endpoint, remote, server, roots) = fixture_with_roots(false);
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let address = Address::V4([127, 0, 0, 1]);
        let wrong_name = H3Client::new(remote, "wrong.example", &token(), roots.clone()).unwrap();
        assert!(matches!(
            wrong_name.open(address.clone(), port).await,
            Err(ClientError::Tls)
        ));
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut unrelated = RootCertStore::empty();
        unrelated.add(cert.cert.der().clone()).unwrap();
        let wrong_ca = H3Client::new(remote, "localhost", &token(), unrelated).unwrap();
        assert!(matches!(
            wrong_ca.open(address.clone(), port).await,
            Err(ClientError::Tls)
        ));
        let wrong_bearer = H3Client::new(
            remote,
            "localhost",
            &URL_SAFE_NO_PAD.encode([0x44; 32]),
            roots.clone(),
        )
        .unwrap();
        assert!(matches!(
            wrong_bearer.open(address.clone(), port).await,
            Err(ClientError::Unauthorized)
        ));
        let ungranted = H3Client::new(
            remote,
            "localhost",
            &URL_SAFE_NO_PAD.encode([0x43; 32]),
            roots.clone(),
        )
        .unwrap();
        assert!(matches!(
            ungranted.open(address.clone(), port).await,
            Err(ClientError::Unauthorized)
        ));
        let valid = H3Client::new(remote, "localhost", &token(), roots).unwrap();
        assert!(matches!(
            valid.open(address, port).await,
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

/// Real QUIC peers with the correct certificate but an incompatible or
/// absent application protocol must never reach SmartTheia authorization.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_h3_client_refuses_incompatible_alpn_before_application_data() {
    timeout(Duration::from_secs(25), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let mut roots = RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        for protocols in [vec![b"h2".to_vec()], Vec::new()] {
            let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key.clone_key().into())
            .unwrap();
            tls.alpn_protocols = protocols;
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
            let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            let peer = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let remote = peer.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let incoming = peer.accept().await.expect("real UDP connection");
                if let Ok(connection) = incoming.await {
                    // If the TLS implementation permits an absent ALPN,
                    // the application must still refuse before opening streams.
                    assert!(connection.accept_bi().await.is_err());
                    assert!(connection.accept_uni().await.is_err());
                }
            });
            let client = H3Client::new(remote, "localhost", &token(), roots.clone()).unwrap();
            let result = client.open(Address::V4([127, 0, 0, 1]), 443).await;
            assert!(matches!(result, Err(ClientError::Tls)));
            server.await.unwrap();
        }
    })
    .await
    .expect("bounded incompatible QUIC ALPN matrix");
}

#[test]
fn production_h3_client_rejects_invalid_configuration() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let remote = "127.0.0.1:443".parse().unwrap();
    assert!(matches!(
        H3Client::new(remote, "localhost", &token(), RootCertStore::empty()),
        Err(ClientError::Configuration)
    ));
    assert!(matches!(
        H3Client::new(remote, "localhost", &format!("{}=", token()), roots.clone()),
        Err(ClientError::Configuration)
    ));
    assert!(matches!(
        H3Client::new(remote, "127.0.0.1", &token(), roots),
        Err(ClientError::Configuration)
    ));
}

/// F-18 negative architectural evidence: the *current* conventional H3
/// listener accepts fully authenticated QUIC/TLS before knowing the bearer,
/// and an unauthorized active probe can read its HTTP 401 response. This is
/// a deliberately red readiness *claim*, not a failing CI assertion: the
/// existing server must preserve strict bearer denial and must not pretend
/// it provides REALITY-like anti-probing before TLS/HTTP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn f18_current_h3_active_probe_sees_unauthorized_response_but_no_tunnel() {
    timeout(Duration::from_secs(15), async {
        let (endpoint, remote, server) = fixture(false);
        let conn = quic_transport::connect(&endpoint, remote, "localhost")
            .await
            .expect("standard QUIC handshake is permitted without bearer");
        let mut exporter = [0u8; 32];
        conn.export_keying_material(
            &mut exporter,
            b"EXPORTER-Theia-F18-active-probe-baseline-only",
            b"this-fixture-is-NOT-REALITY",
        )
        .expect("TLS channel exists before HTTP application authentication");
        assert_ne!(exporter, [0u8; 32]);
        zeroize::Zeroize::zeroize(&mut exporter);

        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        // An observer with a valid CA can distinguish this endpoint by a
        // visible rejection on the production /v1/theia-example/session route. It cannot
        // obtain an authorized tunnel, and this is not a pre-TLS proof.
        let mut anonymous = sender.send_request(request(None)).await.unwrap();
        assert_eq!(
            anonymous.recv_response().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let mut invalid = sender
            .send_request(request(Some(&URL_SAFE_NO_PAD.encode([0x7e; 32]))))
            .await
            .unwrap();
        assert_eq!(
            invalid.recv_response().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        // Correct bearer can provoke HTTP 200 even without SmartTheia
        // HELLO/OPEN_OK; this is not authorization to relay application data.
        let valid_bearer = token();
        let mut authorized = sender
            .send_request(request(Some(&valid_bearer)))
            .await
            .unwrap();
        assert_eq!(
            authorized.recv_response().await.unwrap().status(),
            StatusCode::OK
        );

        driver_task.abort();
        server.abort();
        endpoint.close(0u32.into(), b"done");
    })
    .await
    .expect("bounded real H3 active-probing baseline completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_rejects_unnegotiated_padding_before_target_dial() {
    timeout(Duration::from_secs(10), async {
        let (endpoint, remote, server) = fixture(true);
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let conn = quic_transport::connect(&endpoint, remote, "localhost")
            .await
            .unwrap();
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let mut stream = sender.send_request(request(Some(&token()))).await.unwrap();
        assert_eq!(
            stream.recv_response().await.unwrap().status(),
            StatusCode::OK
        );
        let mut frames = Frames::default();
        send(
            &mut stream,
            Frame::Hello {
                version: protocol::VERSION,
                capabilities: 0,
            },
        )
        .await;
        assert_eq!(
            frames.next(&mut stream).await,
            Some(Frame::HelloAck {
                version: protocol::VERSION,
                accepted_capabilities: 0
            })
        );
        let mut bytes = vec![0x13, 0, 0, 0, 0, 1, 0x42];
        bytes.extend(
            protocol::encode(&Frame::OpenTcp {
                address: Address::V4([127, 0, 0, 1]),
                port,
            })
            .unwrap(),
        );
        stream.send_data(Bytes::from(bytes)).await.unwrap();
        match stream.recv_data().await {
            Err(h3::error::StreamError::RemoteTerminate { code, .. })
                if code == h3::error::Code::H3_REQUEST_CANCELLED => {}
            _ => panic!("unnegotiated PADDING must cancel the H3 stream"),
        }
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        driver.abort();
        server.abort();
        endpoint.close(0u32.into(), b"done");
    })
    .await
    .unwrap();
}

fn native_tls_fixture() -> (Arc<rustls::ServerConfig>, RootCertStore) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der.clone()], key.into())
    .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.send_tls13_tickets = 0;
    let mut roots = RootCertStore::empty();
    roots.add(der).unwrap();
    (Arc::new(tls), roots)
}

async fn native_fixture(private: bool) -> (SocketAddr, JoinHandle<()>, RootCertStore) {
    use theia::quic_core::{handshake_udp, listener::Listener};
    let (tls, roots) = native_tls_fixture();
    let mut listener = Listener::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        64,
    )
    .unwrap();
    let remote = listener.local_addr();
    let context = context(private);
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                incoming = listener.accept() => {
                    let Ok(candidate) = incoming else { break; };
                    let tls = tls.clone();
                    let context = context.clone();
                    tasks.spawn(async move {
                        if let Ok(session) = handshake_udp::accept(candidate, tls).await {
                            let _ = h3_server::run_native_lab(session, context).await;
                        }
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    (remote, task, roots)
}

async fn exact_relay_sample(client: &H3Client, payload: &[u8]) -> (Duration, Duration) {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).await.unwrap();
        socket.write_all(&bytes).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let started = std::time::Instant::now();
    let tunnel = client
        .open(Address::V4([127, 0, 0, 1]), port)
        .await
        .unwrap();
    let open = started.elapsed();
    let (mut app, local) = tokio::io::duplex(8192);
    let relay = tokio::spawn(tunnel.relay(local));
    let started = std::time::Instant::now();
    app.write_all(payload).await.unwrap();
    app.shutdown().await.unwrap();
    let mut received = Vec::new();
    app.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, payload);
    relay.await.unwrap().unwrap();
    echo.await.unwrap();
    (open, started.elapsed())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_xhttp_loopback_preserves_grants_and_both_stream_modes() {
    use theia::quic_core::wire::Version;
    timeout(Duration::from_secs(60), async {
        let (remote, server, roots) = native_fixture(true).await;
        for version in [Version::V1, Version::V2] {
            for split in [false, true] {
                let client = H3Client::new(remote, "localhost", &token(), roots.clone())
                    .unwrap()
                    .with_native_lab(version)
                    .unwrap()
                    .with_stream_up(split)
                    .unwrap();
                exact_relay_sample(&client, &vec![0x6a; 96 * 1024]).await;
            }
        }
        let wrong = URL_SAFE_NO_PAD.encode([0x44; 32]);
        let client = H3Client::new(remote, "localhost", &wrong, roots)
            .unwrap()
            .with_native_lab(Version::V2)
            .unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            client
                .open(
                    Address::V4([127, 0, 0, 1]),
                    target.local_addr().unwrap().port()
                )
                .await,
            Err(ClientError::Unauthorized)
        ));
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        server.abort();
    })
    .await
    .unwrap();
}

async fn exercise_pinned_native_endpoint(ip: std::net::IpAddr, external: bool) {
    use theia::quic_core::{scope::NetworkScope, wire::Version};
    let (tls, roots) = native_tls_fixture();
    let local = SocketAddr::new(ip, 0);
    let socket = tokio::net::UdpSocket::bind(local).await.unwrap();
    let remote = socket.local_addr().unwrap();
    let scope = NetworkScope::pinned([ip; 2], [ip; 2]).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let shutdown = async move { let _ = stopped.await; };
        if external {
            h3_server::serve_native_external(socket, tls, context(true), shutdown).await
        } else {
            h3_server::serve_native_pinned(socket, scope, tls, context(true), shutdown).await
        }
    });
    for version in [Version::V1, Version::V2] {
        let client = H3Client::new(remote, "localhost", &token(), roots.clone())
            .unwrap().with_native_pinned(version, local, scope).unwrap()
            .with_connection_pool().with_auto_stream_up(Duration::from_secs(60)).unwrap();
        let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        // Repeated opens exercise the same common connection pool and
        // per-request authorization rather than a new fixture-only relay.
        exact_relay_sample(&client, &data).await;
        exact_relay_sample(&client, b"second pooled request").await;
    }
    let wrong = URL_SAFE_NO_PAD.encode([0x44; 32]);
    let client = H3Client::new(remote, "localhost", &wrong, roots)
        .unwrap().with_native_pinned(Version::V2, local, scope).unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    assert!(matches!(client.open(Address::V4([127, 0, 0, 1]), target.local_addr().unwrap().port()).await,
        Err(ClientError::Unauthorized)));
    assert!(timeout(Duration::from_millis(250), target.accept()).await.is_err());
    drop(client);
    stop.send(()).unwrap();
    timeout(Duration::from_secs(25), server).await.unwrap().unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_native_h3_ipv4_ipv6_pool_auth_and_drain() {
    timeout(Duration::from_secs(90), async {
        exercise_pinned_native_endpoint("127.0.0.1".parse().unwrap(), false).await;
        exercise_pinned_native_endpoint("::1".parse().unwrap(), true).await;
    }).await.unwrap();
}

/// Explicitly opt in using a locally assigned, non-loopback interface.
/// This is a same-host smoke test, not a physical-network acceptance result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an explicitly provisioned network interface"]
async fn pinned_native_h3_non_loopback_interface() {
    let ip: std::net::IpAddr = std::env::var("THEIA_QUIC_TEST_LOCAL").unwrap().parse().unwrap();
    assert!(!ip.is_loopback());
    timeout(Duration::from_secs(60), exercise_pinned_native_endpoint(ip, true)).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_version_specific_probe_rejects_bad_trust_and_unapproved_endpoint() {
    use theia::{camouflage_h3_probe::{probe_quic_h3_native, H3ProbeError}, camouflage_probe::{ProbeApproval, ProbeRequest}, quic_core::wire::Version};
    let (remote, server, roots) = native_fixture(true).await;
    let request = ProbeRequest { address: remote, server_name: "localhost".into(), deadline: Duration::from_secs(5) };
    let source = remote.ip();
    let approval = ProbeApproval::isolated_loopback_fixture(remote);
    assert!(matches!(probe_quic_h3_native(request.clone(), roots.clone(), ProbeApproval::Denied, source, Version::V2).await, Err(H3ProbeError::NotApproved)));
    for version in [Version::V1, Version::V2] {
        let report = probe_quic_h3_native(request.clone(), roots.clone(), approval, source, version).await.unwrap();
        assert_eq!(report.version, version);
        assert_eq!(report.source, source);
        assert_eq!(report.transport.connected_ip, remote.ip());
    }
    let mut wrong = request.clone();
    wrong.server_name = "wrong.invalid".into();
    assert!(matches!(probe_quic_h3_native(wrong, roots, approval, source, Version::V2).await, Err(H3ProbeError::HandshakeRejected)));
    server.abort();
}

/// Manual matched loopback workload: raw samples, no performance claim.
/// Run in release mode on a quiet machine; independent network/CPU/RSS
/// measurements remain separate acceptance requirements.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual comparative loopback benchmark"]
async fn quinn_native_xhttp_comparison_samples() {
    use theia::quic_core::wire::Version;
    timeout(Duration::from_secs(240), async {
        let (_endpoint, qaddr, qserver, qroots) = fixture_with_roots(true);
        let (naddr, nserver, nroots) = native_fixture(true).await;
        let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        println!("backend,stream_up,sample,bytes,open_us,relay_us");
        for split in [false, true] {
            for sample in 0..5 {
                for (label, version) in [
                    ("quinn", None),
                    ("native-v1", Some(Version::V1)),
                    ("native-v2", Some(Version::V2)),
                ] {
                    let client = if let Some(version) = version {
                        H3Client::new(naddr, "localhost", &token(), nroots.clone())
                            .unwrap()
                            .with_native_lab(version)
                            .unwrap()
                    } else {
                        H3Client::new(qaddr, "localhost", &token(), qroots.clone()).unwrap()
                    };
                    let client = client.with_stream_up(split).unwrap();
                    let (open, relay) = exact_relay_sample(&client, &payload).await;
                    println!(
                        "{label},{split},{sample},{},{},{}",
                        payload.len(),
                        open.as_micros(),
                        relay.as_micros()
                    );
                }
            }
        }
        qserver.abort();
        nserver.abort();
    })
    .await
    .unwrap();
}
