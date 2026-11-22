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
    let inbound = Inbound {
        id: "test".into(),
        allowed_user_ids: vec!["allowed".into()],
        h2_listen: "127.0.0.1:0".into(),
        quic_listen: "127.0.0.1:0".into(),
        server_name: "localhost".into(),
        tls_cert: "unused".into(),
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
        allow_private_ips: private,
        max_connections_per_user: 8,
        max_connections_total: 8,
        connect_timeout_ms: 2000,
    };
    let context = Arc::new(ServerContext::new(&inbound, &users, &policy));
    let server = tokio::spawn(h3_server::serve(endpoint, context));
    (client, remote, server, roots)
}

fn request(auth: Option<&str>) -> Request<()> {
    let mut request = Request::post("https://localhost/v1/session")
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
        assert_eq!(open(&mut stream, &mut frames, port).await, Frame::OpenOk);
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
            stream.finish().await.unwrap();
            assert_eq!(stream.recv_response().await.unwrap().status(), status);
            assert!(stream.recv_data().await.unwrap().is_none());
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
