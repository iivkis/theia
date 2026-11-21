//! Real TCP + TLS 1.3 + ALPN h2 integration tests. Nothing is sent outside loopback.
//! A test-generated certificate is trusted via a normal RootCertStore;
//! no insecure verifier, key logging or TLS verification bypass.
use bytes::Bytes;
use rustls::{
    pki_types::{PrivatePkcs8KeyDer, ServerName},
    ProtocolVersion, RootCertStore,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const H2_ALPN: &[u8] = b"h2";

fn tls_configs(
    trust_server: bool,
    server_alpn: &[u8],
    client_alpn: &[u8],
) -> (TlsAcceptor, TlsConnector) {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("generate ephemeral test certificate");
    let server_cert = generated.cert.der().clone();
    let server_key = PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());

    let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 provider")
    .with_no_client_auth()
    .with_single_cert(vec![server_cert.clone()], server_key.into())
    .expect("test identity");
    server_tls.alpn_protocols = vec![server_alpn.into()];

    let trusted_cert = if trust_server {
        server_cert
    } else {
        // Same hostname but a different, untrusted identity.
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate another certificate")
            .cert
            .der()
            .clone()
    };
    let mut roots = RootCertStore::empty();
    roots.add(trusted_cert).expect("valid test trust anchor");
    let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 provider")
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_tls.alpn_protocols = vec![client_alpn.into()];

    (
        TlsAcceptor::from(Arc::new(server_tls)),
        TlsConnector::from(Arc::new(client_tls)),
    )
}

// Do not rely on h2::SendStream::send_data() buffering unlimited data.
// Even for tiny chunks, explicitly request flow-control capacity first.
async fn bounded_send(stream: &mut h2::SendStream<Bytes>, data: Bytes, end: bool) {
    let required = data.len();
    stream.reserve_capacity(required);
    while stream.capacity() < required {
        stream.poll_capacity_or_error().await;
    }
    stream.send_data(data, end).expect("send h2 DATA");
}

trait AwaitCapacity {
    fn poll_capacity_or_error(&mut self) -> impl std::future::Future<Output = ()>;
}

impl AwaitCapacity for h2::SendStream<Bytes> {
    async fn poll_capacity_or_error(&mut self) {
        let change = std::future::poll_fn(|cx| self.poll_capacity(cx))
            .await
            .expect("capacity stream closed")
            .expect("h2 capacity error");
        assert!(change > 0, "positive window update required");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls13_h2_full_duplex_response_before_request_eof() {
    tokio::time::timeout(Duration::from_secs(12), async {
        let (acceptor, connector) = tls_configs(true, H2_ALPN, H2_ALPN);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP");
        let addr = listener.local_addr().unwrap();
        let (client_done_tx, client_done_rx) = oneshot::channel::<()>();
        let (server_done_tx, server_done_rx) = oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("TCP accept");
            let tls = acceptor.accept(socket).await.expect("TLS server handshake");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(H2_ALPN));
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(ProtocolVersion::TLSv1_3)
            );
            let mut h2_connection = h2::server::handshake(tls).await.expect("h2 server");
            let (request, mut responder) = h2_connection
                .accept()
                .await
                .expect("h2 accepted")
                .expect("POST request");
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/v1/session");

            let handler = tokio::spawn(async move {
                let mut request_body = request.into_body();
                let first = request_body.data().await.unwrap().unwrap();
                assert_eq!(first, Bytes::from_static(b"phase-1"));
                request_body
                    .flow_control()
                    .release_capacity(first.len())
                    .unwrap();

                // Return HTTP 200 and a response body BEFORE consuming request EOF.
                let mut response_body = responder
                    .send_response(
                        http::Response::builder().status(200).body(()).unwrap(),
                        false,
                    )
                    .expect("response headers");
                bounded_send(&mut response_body, Bytes::from_static(b"reply-1"), false).await;

                let next = request_body.data().await.unwrap().unwrap();
                assert_eq!(next, Bytes::from_static(b"phase-2"));
                request_body
                    .flow_control()
                    .release_capacity(next.len())
                    .unwrap();
                assert!(
                    request_body.data().await.is_none(),
                    "request EOS after phase-2"
                );
                bounded_send(&mut response_body, Bytes::from_static(b"reply-2"), true).await;
                server_done_tx.send(()).expect("client awaiting handler");
            });

            // The h2 connection must keep being polled even while the handler runs.
            // Signal explicit completion only when the client has received response EOS.
            tokio::select! {
                _ = async { while h2_connection.accept().await.is_some() {} } => {},
                _ = client_done_rx => {},
            }
            handler.await.expect("handler completed");
        });

        let tcp = TcpStream::connect(addr)
            .await
            .expect("connect loopback TCP");
        let server_name = ServerName::try_from("localhost".to_owned()).unwrap();
        let tls = connector
            .connect(server_name, tcp)
            .await
            .expect("verified TLS client handshake");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(H2_ALPN));
        assert_eq!(
            tls.get_ref().1.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
        assert!(tls.get_ref().1.peer_certificates().is_some());

        let (mut requests, connection) = h2::client::handshake(tls).await.expect("h2 client");
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/v1/session")
            .body(())
            .unwrap();
        let (response_future, mut request_body) = requests
            .send_request(request, false)
            .expect("send HTTP/2 POST");
        bounded_send(&mut request_body, Bytes::from_static(b"phase-1"), false).await;

        // Fails by timeout if the server waits for request-body EOF.
        let response = response_future
            .await
            .expect("HTTP/2 response before request EOF");
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut response_body = response.into_body();
        let first = response_body.data().await.unwrap().unwrap();
        assert_eq!(first, Bytes::from_static(b"reply-1"));
        response_body
            .flow_control()
            .release_capacity(first.len())
            .unwrap();

        bounded_send(&mut request_body, Bytes::from_static(b"phase-2"), true).await;
        let second = response_body.data().await.unwrap().unwrap();
        assert_eq!(second, Bytes::from_static(b"reply-2"));
        response_body
            .flow_control()
            .release_capacity(second.len())
            .unwrap();
        assert!(
            response_body.data().await.is_none(),
            "response EOS after phase-2"
        );

        server_done_rx.await.expect("server processed request EOS");
        client_done_tx.send(()).expect("server waiter alive");
        server_task.await.expect("server task");
        driver.abort();
    })
    .await
    .expect("TLS/h2 full-duplex test timed out");
}

async fn handshake_must_fail(
    trust_server: bool,
    server_alpn: &[u8],
    client_alpn: &[u8],
    host: &str,
) {
    tokio::time::timeout(Duration::from_secs(8), async {
        let (acceptor, connector) = tls_configs(trust_server, server_alpn, client_alpn);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(socket).await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let host = ServerName::try_from(host.to_owned()).unwrap();
        let result = connector.connect(host, tcp).await;
        assert!(
            result.is_err(),
            "TLS identity/ALPN failure must not establish a stream"
        );
        server.await.expect("server completed handshake");
    })
    .await
    .expect("negative TLS test timed out");
}

#[tokio::test]
async fn tls13_h2_rejects_wrong_hostname() {
    handshake_must_fail(true, H2_ALPN, H2_ALPN, "wrong.example").await;
}

#[tokio::test]
async fn tls13_h2_rejects_untrusted_ca() {
    handshake_must_fail(false, H2_ALPN, H2_ALPN, "localhost").await;
}

#[tokio::test]
async fn tls13_h2_rejects_alpn_mismatch() {
    handshake_must_fail(true, H2_ALPN, b"http/1.1", "localhost").await;
}

/// More than the default HTTP/2 stream window in both directions, with explicit
/// backpressure and half-close. Not a throughput benchmark or allocator profiler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls13_h2_megabyte_flow_control_and_half_close() {
    const BLOCK: usize = 4096;
    const GATE_BYTES: usize = 15 * BLOCK; // 61,440 < default 65,535 stream window
    const REQUEST_BYTES: usize = 1024 * 1024;
    const RESPONSE_BYTES: usize = 256 * 1024;

    tokio::time::timeout(Duration::from_secs(25), async {
        let (acceptor, connector) = tls_configs(true, H2_ALPN, H2_ALPN);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP");
        let addr = listener.local_addr().unwrap();
        let (held_tx, held_rx) = oneshot::channel::<()>();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let (server_done_tx, server_done_rx) = oneshot::channel::<()>();
        let (client_done_tx, client_done_rx) = oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("TCP accept");
            let tls = acceptor.accept(socket).await.expect("TLS server");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(H2_ALPN));
            let mut connection = h2::server::handshake(tls).await.expect("h2 server");
            let (request, mut responder) = connection
                .accept()
                .await
                .expect("accept HTTP2")
                .expect("POST stream");

            let handler = tokio::spawn(async move {
                let mut request_body = request.into_body();
                let mut received = 0;
                // Intentionally withhold stream WINDOW_UPDATE while reading 60 KiB.
                while received < GATE_BYTES {
                    let data = request_body.data().await.expect("DATA").expect("chunk");
                    assert!(data.iter().all(|&b| b == 0xa5));
                    received += data.len();
                }
                assert_eq!(received, GATE_BYTES, "test depends on 4 KiB DATA frames");
                held_tx.send(()).expect("client waiting for held window");
                release_rx
                    .await
                    .expect("client observed sender capacity exhausted");
                request_body
                    .flow_control()
                    .release_capacity(received)
                    .unwrap();

                while let Some(data) = request_body.data().await {
                    let data = data.expect("valid DATA");
                    assert!(data.iter().all(|&b| b == 0xa5));
                    received += data.len();
                    request_body
                        .flow_control()
                        .release_capacity(data.len())
                        .unwrap();
                }
                assert_eq!(received, REQUEST_BYTES, "all request bytes delivered");
                // POST request body is closed; response stream remains writable.
                let mut response_body = responder
                    .send_response(
                        http::Response::builder().status(200).body(()).unwrap(),
                        false,
                    )
                    .expect("response after request FIN");
                let data = Bytes::from(vec![0x7c; BLOCK]);
                for i in 0..(RESPONSE_BYTES / BLOCK) {
                    bounded_send(
                        &mut response_body,
                        data.clone(),
                        i == RESPONSE_BYTES / BLOCK - 1,
                    )
                    .await;
                }
                server_done_tx.send(()).expect("client still waiting");
            });

            // Keep driving h2 transport while handler awaits request/response body.
            tokio::select! {
                _ = async { while connection.accept().await.is_some() {} } => {},
                _ = client_done_rx => {},
            }
            handler.await.expect("stream handler");
        });

        let tcp = TcpStream::connect(addr).await.expect("TCP connect");
        let tls = connector
            .connect(ServerName::try_from("localhost".to_owned()).unwrap(), tcp)
            .await
            .expect("verified TLS client");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(H2_ALPN));
        let (mut sender, driver) = h2::client::handshake(tls).await.expect("h2 client");
        let driver_task = tokio::spawn(async move {
            let _ = driver.await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/v1/session")
            .body(())
            .unwrap();
        let (response_future, mut outgoing) =
            sender.send_request(request, false).expect("send POST");
        let block = Bytes::from(vec![0xa5; BLOCK]);

        // Fill most of the advertised 64 KiB stream window without remote
        // release_capacity. The 16th complete 4 KiB block cannot yet be sent.
        for _ in 0..(GATE_BYTES / BLOCK) {
            bounded_send(&mut outgoing, block.clone(), false).await;
        }
        held_rx.await.expect("server withheld window");
        assert!(
            outgoing.capacity() < BLOCK,
            "a full 4 KiB sender chunk must not fit before WINDOW_UPDATE"
        );
        release_tx
            .send(())
            .expect("server waiting for window release");
        for i in (GATE_BYTES / BLOCK)..(REQUEST_BYTES / BLOCK) {
            bounded_send(&mut outgoing, block.clone(), i == REQUEST_BYTES / BLOCK - 1).await;
        }

        let response = response_future.await.expect("response after request FIN");
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut body = response.into_body();
        let mut received = 0;
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("response DATA");
            assert!(chunk.iter().all(|&b| b == 0x7c));
            received += chunk.len();
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        assert_eq!(
            received, RESPONSE_BYTES,
            "response survives request half-close"
        );
        server_done_rx.await.expect("server finished response");
        client_done_tx.send(()).expect("server still polling");
        server_task.await.expect("server task");
        driver_task.abort();
    })
    .await
    .expect("h2 megabyte/backpressure/half-close timed out");
}

/// Several HTTP/2 streams must remain open simultaneously on one verified TLS
/// connection. All request headers are accepted before *any* server response,
/// and all responses arrive before their corresponding request EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls13_h2_eight_concurrent_full_duplex_streams() {
    const STREAMS: usize = 8;
    tokio::time::timeout(Duration::from_secs(15), async {
        let (acceptor, connector) = tls_configs(true, H2_ALPN, H2_ALPN);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP");
        let address = listener.local_addr().unwrap();
        let (client_done_tx, client_done_rx) = oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept TCP");
            let tls = acceptor.accept(socket).await.expect("TLS 1.3");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(H2_ALPN));
            let mut connection = h2::server::handshake(tls).await.expect("h2 server");

            // Force eight live streams: no server handler responds until all
            // eight HEADERS have arrived, rather than testing sequential requests.
            let mut accepted = Vec::new();
            for _ in 0..STREAMS {
                let next = connection
                    .accept()
                    .await
                    .expect("h2 connection")
                    .expect("request");
                accepted.push(next);
            }
            let handlers: Vec<_> = accepted
                .into_iter()
                .map(|(request, mut responder)| {
                    tokio::spawn(async move {
                        let index = request
                            .uri()
                            .path()
                            .strip_prefix("/v1/session/")
                            .expect("expected path")
                            .parse::<u8>()
                            .expect("stream number");
                        let mut request_body = request.into_body();
                        let first = request_body
                            .data()
                            .await
                            .expect("initial DATA")
                            .expect("no reset");
                        assert_eq!(first, Bytes::from(vec![index]));
                        request_body
                            .flow_control()
                            .release_capacity(first.len())
                            .unwrap();

                        // The request body is still open at this point.
                        let mut response = responder
                            .send_response(
                                http::Response::builder().status(200).body(()).unwrap(),
                                false,
                            )
                            .expect("early response HEADERS");
                        bounded_send(&mut response, Bytes::from(vec![index]), false).await;

                        let second = request_body
                            .data()
                            .await
                            .expect("second DATA")
                            .expect("no reset");
                        assert_eq!(second, Bytes::from(vec![index.wrapping_add(1)]));
                        request_body
                            .flow_control()
                            .release_capacity(second.len())
                            .unwrap();
                        assert!(request_body.data().await.is_none(), "request half-close");
                        bounded_send(
                            &mut response,
                            Bytes::from(vec![index.wrapping_add(1)]),
                            true,
                        )
                        .await;
                    })
                })
                .collect();

            tokio::select! {
                _ = async { while connection.accept().await.is_some() {} } => {},
                _ = client_done_rx => {},
            }
            for handler in handlers {
                handler.await.expect("independent stream handler");
            }
        });

        let socket = TcpStream::connect(address).await.expect("TCP connect");
        let tls = connector
            .connect(
                ServerName::try_from("localhost".to_owned()).unwrap(),
                socket,
            )
            .await
            .expect("verified TLS");
        let (mut sender, driver) = h2::client::handshake(tls).await.expect("h2 client");
        let client_driver = tokio::spawn(async move {
            let _ = driver.await;
        });
        let mut streams = Vec::new();
        for i in 0..STREAMS {
            let req = http::Request::builder()
                .method(http::Method::POST)
                .uri(format!("https://localhost/v1/session/{i}"))
                .body(())
                .unwrap();
            let (response, mut send) = sender.send_request(req, false).expect("new stream");
            bounded_send(&mut send, Bytes::from(vec![i as u8]), false).await;
            streams.push((i as u8, response, send));
        }

        for (i, response, mut request_body) in streams {
            let response = response
                .await
                .expect("early response on independent stream");
            assert_eq!(response.status(), http::StatusCode::OK);
            let mut body = response.into_body();
            let first = body.data().await.expect("reply-1").expect("valid frame");
            assert_eq!(first, Bytes::from(vec![i]));
            body.flow_control().release_capacity(first.len()).unwrap();

            bounded_send(
                &mut request_body,
                Bytes::from(vec![i.wrapping_add(1)]),
                true,
            )
            .await;
            let second = body.data().await.expect("reply-2").expect("valid frame");
            assert_eq!(second, Bytes::from(vec![i.wrapping_add(1)]));
            body.flow_control().release_capacity(second.len()).unwrap();
            assert!(body.data().await.is_none(), "response EOS");
        }

        client_done_tx.send(()).expect("server still alive");
        server.await.expect("server task");
        client_driver.abort();
    })
    .await
    .expect("eight concurrent TLS/h2 streams timed out");
}

/// Cancel one in-flight HTTP/2 stream with RST_STREAM CANCEL; a sibling stream
/// must still be usable on the same TLS session. No sleeps or external servers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls13_h2_cancel_stream_preserves_connection() {
    tokio::time::timeout(Duration::from_secs(12), async {
        let (acceptor, connector) = tls_configs(true, H2_ALPN, H2_ALPN);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP");
        let address = listener.local_addr().unwrap();
        let (first_consumed_tx, first_consumed_rx) = oneshot::channel::<()>();
        let (reset_observed_tx, reset_observed_rx) = oneshot::channel::<()>();
        let (client_done_tx, client_done_rx) = oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("TCP");
            let tls = acceptor.accept(socket).await.expect("TLS");
            let mut connection = h2::server::handshake(tls).await.expect("h2 server");
            let (cancelled, _responder) = connection
                .accept()
                .await
                .expect("client")
                .expect("first request");
            let cancel_handler = tokio::spawn(async move {
                let mut body = cancelled.into_body();
                let first = body.data().await.expect("body").expect("first DATA");
                assert_eq!(first, Bytes::from_static(b"before-cancel"));
                body.flow_control().release_capacity(first.len()).unwrap();
                first_consumed_tx.send(()).expect("client ready");
                match body.data().await {
                    Some(Err(error)) => assert!(error.is_reset(), "expected RST_STREAM: {error:?}"),
                    other => panic!("expected stream reset after cancel, got {other:?}"),
                }
                reset_observed_tx
                    .send(())
                    .expect("client waiting for reset");
            });

            let (second, mut respond) = connection
                .accept()
                .await
                .expect("connection alive")
                .expect("second request");
            assert_eq!(second.uri().path(), "/v1/session/after-cancel");
            let second_handler = tokio::spawn(async move {
                let mut body = second.into_body();
                let data = body.data().await.expect("DATA").expect("chunk");
                assert_eq!(data, Bytes::from_static(b"still-alive"));
                body.flow_control().release_capacity(data.len()).unwrap();
                assert!(body.data().await.is_none(), "second request EOF");
                respond
                    .send_response(
                        http::Response::builder().status(204).body(()).unwrap(),
                        true,
                    )
                    .expect("successful independent stream");
            });
            tokio::select! {
                _ = async { while connection.accept().await.is_some() {} } => {},
                _ = client_done_rx => {},
            }
            cancel_handler.await.expect("RST_STREAM handler");
            second_handler.await.expect("sibling request handler");
        });

        let tcp = TcpStream::connect(address).await.expect("TCP connect");
        let tls = connector
            .connect(ServerName::try_from("localhost".to_owned()).unwrap(), tcp)
            .await
            .expect("TLS verified");
        let (mut sender, driver) = h2::client::handshake(tls).await.expect("h2 client");
        let client_driver = tokio::spawn(async move {
            let _ = driver.await;
        });

        let (old_response, mut cancelled) = sender
            .send_request(
                http::Request::builder()
                    .method(http::Method::POST)
                    .uri("https://localhost/v1/session/cancel")
                    .body(())
                    .unwrap(),
                false,
            )
            .expect("first stream");
        bounded_send(&mut cancelled, Bytes::from_static(b"before-cancel"), false).await;
        first_consumed_rx
            .await
            .expect("server consumed initial data");
        cancelled.send_reset(h2::Reason::CANCEL);
        drop(old_response);
        reset_observed_rx
            .await
            .expect("server saw request cancellation");

        let (response, mut sibling) = sender
            .send_request(
                http::Request::builder()
                    .method(http::Method::POST)
                    .uri("https://localhost/v1/session/after-cancel")
                    .body(())
                    .unwrap(),
                false,
            )
            .expect("second stream");
        bounded_send(&mut sibling, Bytes::from_static(b"still-alive"), true).await;
        assert_eq!(
            response.await.expect("sibling response").status(),
            http::StatusCode::NO_CONTENT
        );

        client_done_tx.send(()).expect("server alive");
        server.await.expect("server task");
        client_driver.abort();
    })
    .await
    .expect("TLS/h2 cancellation test timed out");
}

/// The *response* reader withholds HTTP/2 flow-control credit, forcing the
/// server's bounded SendStream to stop. After releasing capacity, a 512 KiB
/// body completes without reconnecting. No unbounded application queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls13_h2_slow_response_reader_stalls_and_recovers() {
    const BLOCK: usize = 4096;
    const HELD: usize = 15 * BLOCK; // 61,440, less than 65,535 default stream window
    const TOTAL: usize = 512 * 1024;

    tokio::time::timeout(Duration::from_secs(20), async {
        let (acceptor, connector) = tls_configs(true, H2_ALPN, H2_ALPN);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP");
        let addr = listener.local_addr().unwrap();
        let (window_held_tx, window_held_rx) = oneshot::channel::<()>();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let (client_done_tx, client_done_rx) = oneshot::channel::<()>();
        let (server_done_tx, server_done_rx) = oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("TCP accept");
            let tls = acceptor.accept(socket).await.expect("TLS handshake");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(H2_ALPN));
            let mut connection = h2::server::handshake(tls).await.expect("h2 server");
            let (request, mut responder) = connection
                .accept()
                .await
                .expect("connection")
                .expect("request");
            assert_eq!(request.uri().path(), "/v1/session/slow-reader");
            let handler = tokio::spawn(async move {
                let mut body = request.into_body();
                assert!(body.data().await.is_none(), "request is half-closed");

                let mut outgoing = responder
                    .send_response(
                        http::Response::builder().status(200).body(()).unwrap(),
                        false,
                    )
                    .expect("response HEADERS");
                let block = Bytes::from(vec![0xc3; BLOCK]);
                for _ in 0..(HELD / BLOCK) {
                    bounded_send(&mut outgoing, block.clone(), false).await;
                }
                // Response stream credit must remain unavailable until the
                // client explicitly calls release_capacity on received DATA.
                assert!(
                    outgoing.capacity() < BLOCK,
                    "slow reader has not released enough credit for another block"
                );
                window_held_tx
                    .send(())
                    .expect("client observing stalled window");
                release_rx.await.expect("client releases stream window");

                for index in (HELD / BLOCK)..(TOTAL / BLOCK) {
                    bounded_send(&mut outgoing, block.clone(), index == TOTAL / BLOCK - 1).await;
                }
                server_done_tx.send(()).expect("client still waiting");
            });
            tokio::select! {
                _ = async { while connection.accept().await.is_some() {} } => {},
                _ = client_done_rx => {},
            }
            handler.await.expect("response sender task");
        });

        let tcp = TcpStream::connect(addr).await.expect("TCP connect");
        let tls = connector
            .connect(ServerName::try_from("localhost".to_owned()).unwrap(), tcp)
            .await
            .expect("verified TLS");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(H2_ALPN));
        let (mut sender, driver) = h2::client::handshake(tls).await.expect("h2 client");
        let driver_task = tokio::spawn(async move {
            let _ = driver.await;
        });

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/v1/session/slow-reader")
            .body(())
            .unwrap();
        let (response, _finished_request) = sender
            .send_request(request, true)
            .expect("send request with EOS");
        let response = response.await.expect("response HEADERS");
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut incoming = response.into_body();
        let mut held = 0;
        while held < HELD {
            let chunk = incoming.data().await.expect("DATA").expect("frame");
            assert!(chunk.iter().all(|&x| x == 0xc3), "byte-exact payload");
            held += chunk.len();
            // Intentionally do not release credit yet.
        }
        assert_eq!(held, HELD, "expected exactly fifteen 4 KiB DATA frames");
        window_held_rx.await.expect("sender reached credit limit");
        incoming
            .flow_control()
            .release_capacity(held)
            .expect("release window");
        release_tx.send(()).expect("server ready to continue");

        let mut received = held;
        while let Some(chunk) = incoming.data().await {
            let chunk = chunk.expect("response DATA");
            assert!(chunk.iter().all(|&x| x == 0xc3), "recovered payload");
            received += chunk.len();
            incoming
                .flow_control()
                .release_capacity(chunk.len())
                .expect("bounded receiver");
        }
        assert_eq!(
            received, TOTAL,
            "complete response after slow reader resumed"
        );
        server_done_rx.await.expect("server completed response");
        client_done_tx.send(()).expect("server alive");
        server.await.expect("server handler");
        driver_task.abort();
    })
    .await
    .expect("H2/TLS slow-reader backpressure test timed out");
}
