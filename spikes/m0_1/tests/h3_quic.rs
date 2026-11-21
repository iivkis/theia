//! Network-level feasibility checks for Theia H3 over QUIC/TLS 1.3.
//! Test-only localhost credentials, ordinary hostname verification, no insecure TLS verifier.
use bytes::{Buf, Bytes};
use quinn::{
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
    Endpoint,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use theia_m0_1_feasibility::{configure_client_bbr, configure_server_bbr};

const ALPN: &[u8] = b"h3";

fn endpoints() -> (Endpoint, Endpoint, SocketAddr) {
    endpoints_with_slow_reader_limits(false)
}

/// When enabled, the QUIC receiver advertises a small per-stream window and
/// the sender has a small global write buffer, so stalled readers can exert
/// testable backpressure. Ordinary tests use their original defaults.
fn endpoints_with_slow_reader_limits(slow_reader: bool) -> (Endpoint, Endpoint, SocketAddr) {
    let key =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("generate test cert");
    let cert = key.cert.der().clone();
    let private = PrivatePkcs8KeyDer::from(key.key_pair.serialize_der());

    let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS1.3 provider")
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], private.into())
    .expect("valid test certificate");
    server_tls.alpn_protocols = vec![ALPN.into()];
    // Neither HTTP 0-RTT nor QUIC 0-RTT is enabled in this test.
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_tls).expect("QUIC TLS server config"),
    ));
    if slow_reader {
        let mut transport = theia_m0_1_feasibility::bbr_transport();
        // Maximum aggregate bytes accepted by application writers on the
        // server connection, not a measured peak-RSS limit.
        transport.send_window(48 * 1024);
        server_config.transport_config(Arc::new(transport));
    } else {
        configure_server_bbr(&mut server_config);
    }
    let server =
        Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).expect("bind UDP server");
    let address = server.local_addr().expect("bound address");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("trust generated test certificate");
    let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS1.3 provider")
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_tls.alpn_protocols = vec![ALPN.into()];
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls).expect("QUIC TLS client config"),
    ));
    if slow_reader {
        let mut transport = theia_m0_1_feasibility::bbr_transport();
        transport.stream_receive_window(quinn::VarInt::from_u32(32 * 1024));
        // Reserve credit for H3 control/QPACK streams and other traffic.
        transport.receive_window(quinn::VarInt::from_u32(256 * 1024));
        client_config.transport_config(Arc::new(transport));
    } else {
        configure_client_bbr(&mut client_config);
    }
    let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("bind UDP client");
    client.set_default_client_config(client_config);
    (server, client, address)
}

fn assert_h3_and_bbr(conn: &quinn::Connection) {
    let handshake = conn
        .handshake_data()
        .expect("handshake metadata")
        .downcast::<HandshakeData>()
        .expect("rustls handshake metadata");
    assert_eq!(handshake.protocol.as_deref(), Some(ALPN));
    assert!(
        conn.congestion_state()
            .into_any()
            .downcast::<quinn::congestion::Bbr>()
            .is_ok(),
        "actual active QUIC sender must be BBR, not CUBIC"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_quic_tls_full_duplex_and_active_bbr_on_both_sides() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (server_endpoint, client_endpoint, server_addr) = endpoints();

        let (client_done_tx, client_done_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("incoming QUIC");
            let conn = incoming.await.expect("TLS handshake");
            assert_h3_and_bbr(&conn);

            let mut h3conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
                .await
                .expect("H3 server session");
            let resolver = h3conn
                .accept()
                .await
                .expect("H3 accept")
                .expect("POST stream");
            let (request, mut stream) = resolver.resolve_request().await.expect("POST headers");
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/v1/session");
            // First DATA arrives while request body is still open.
            let mut first = stream
                .recv_data()
                .await
                .expect("request chunk")
                .expect("phase-1");
            assert_eq!(
                first.copy_to_bytes(first.remaining()),
                Bytes::from_static(b"phase-1")
            );

            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .expect("response headers before request EOF");
            stream
                .send_data(Bytes::from_static(b"reply-1"))
                .await
                .expect("response chunk");

            let mut second = stream
                .recv_data()
                .await
                .expect("second request chunk")
                .expect("phase-2");
            assert_eq!(
                second.copy_to_bytes(second.remaining()),
                Bytes::from_static(b"phase-2")
            );
            stream
                .send_data(Bytes::from_static(b"reply-2"))
                .await
                .expect("second response");
            stream.finish().await.expect("finish response");
            // Keep endpoint and the H3 connection alive until the client confirms EOF.
            client_done_rx.await.expect("client consumed response");
        });

        let conn = client_endpoint
            .connect(server_addr, "localhost")
            .expect("valid server address")
            .await
            .expect("verified QUIC TLS handshake");
        assert_h3_and_bbr(&conn);
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .expect("H3 client session");
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/v1/session")
            .body(())
            .unwrap();
        let mut stream = sender.send_request(request).await.expect("send H3 headers");
        stream
            .send_data(Bytes::from_static(b"phase-1"))
            .await
            .expect("send initial body");

        // Critical: response can be received before request.finish() / request EOF.
        let response = stream
            .recv_response()
            .await
            .expect("server response before request EOF");
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut reply = stream
            .recv_data()
            .await
            .expect("response body")
            .expect("reply-1");
        assert_eq!(
            reply.copy_to_bytes(reply.remaining()),
            Bytes::from_static(b"reply-1")
        );

        stream
            .send_data(Bytes::from_static(b"phase-2"))
            .await
            .expect("send additional body");
        stream.finish().await.expect("finish request");
        let mut second_reply = stream
            .recv_data()
            .await
            .expect("second body")
            .expect("reply-2");
        assert_eq!(
            second_reply.copy_to_bytes(second_reply.remaining()),
            Bytes::from_static(b"reply-2"),
        );
        assert!(stream.recv_data().await.expect("response EOF").is_none());
        client_done_tx.send(()).expect("server waiter alive");

        server_task.await.expect("server task");
        driver_task.abort();
        client_endpoint.close(0u32.into(), b"done");
    })
    .await
    .expect("H3/QUIC full duplex timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_quic_rejects_wrong_server_hostname() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (server_endpoint, client_endpoint, server_addr) = endpoints();
        // Server must drive the handshake even though the client rejects identity.
        let server_task = tokio::spawn(async move {
            if let Some(incoming) = server_endpoint.accept().await {
                let _ = incoming.await;
            }
        });
        let result = client_endpoint
            .connect(server_addr, "incorrect.example")
            .expect("dial allowed")
            .await;
        assert!(
            result.is_err(),
            "certificate name mismatch must fail closed"
        );
        server_task.await.expect("handshake task");
    })
    .await
    .expect("rejection test timed out");
}

/// Eight independent HTTP/3 bidirectional streams share one authenticated
/// QUIC/TLS connection. All headers arrive before the server responds on any
/// stream, proving multiplexing rather than sequential connection reuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_quic_eight_concurrent_bidirectional_streams() {
    const STREAMS: usize = 8;
    tokio::time::timeout(Duration::from_secs(15), async {
        let (server_endpoint, client_endpoint, addr) = endpoints();
        let (client_done_tx, client_done_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("QUIC connection");
            let connection = incoming.await.expect("verified TLS/QUIC");
            assert_h3_and_bbr(&connection);
            let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(connection))
                .await
                .expect("H3 session");

            let mut resolvers = Vec::new();
            for _ in 0..STREAMS {
                let resolver = h3.accept().await.expect("H3 stream").expect("request");
                resolvers.push(resolver);
            }
            let handlers: Vec<_> = resolvers
                .into_iter()
                .map(|resolver| {
                    tokio::spawn(async move {
                        let (request, mut stream) =
                            resolver.resolve_request().await.expect("POST headers");
                        let i = request
                            .uri()
                            .path()
                            .strip_prefix("/v1/session/")
                            .expect("request route")
                            .parse::<u8>()
                            .expect("stream id");
                        assert_eq!(request.method(), http::Method::POST);
                        let mut initial = stream
                            .recv_data()
                            .await
                            .expect("initial DATA")
                            .expect("nonempty body");
                        assert_eq!(
                            initial.copy_to_bytes(initial.remaining()),
                            Bytes::from(vec![i])
                        );

                        // Respond while request stream is still open.
                        stream
                            .send_response(http::Response::builder().status(200).body(()).unwrap())
                            .await
                            .expect("early H3 response");
                        stream
                            .send_data(Bytes::from(vec![i]))
                            .await
                            .expect("first reply");

                        let mut second = stream
                            .recv_data()
                            .await
                            .expect("later request DATA")
                            .expect("phase-2");
                        assert_eq!(
                            second.copy_to_bytes(second.remaining()),
                            Bytes::from(vec![i.wrapping_add(1)])
                        );
                        assert!(stream.recv_data().await.expect("request EOF").is_none());
                        stream
                            .send_data(Bytes::from(vec![i.wrapping_add(1)]))
                            .await
                            .expect("second reply");
                        stream.finish().await.expect("response FIN");
                    })
                })
                .collect();

            client_done_rx.await.expect("client read all replies");
            for handler in handlers {
                handler.await.expect("independent H3 stream handler");
            }
        });

        let connection = client_endpoint
            .connect(addr, "localhost")
            .expect("QUIC connect")
            .await
            .expect("verified certificate");
        assert_h3_and_bbr(&connection);
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .expect("H3 client");
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let mut active = Vec::new();
        for i in 0..STREAMS {
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri(format!("https://localhost/v1/session/{i}"))
                .body(())
                .unwrap();
            let mut stream = sender.send_request(request).await.expect("open H3 stream");
            stream
                .send_data(Bytes::from(vec![i as u8]))
                .await
                .expect("send phase-1 without EOF");
            active.push((i as u8, stream));
        }

        for (i, mut stream) in active {
            let response = stream
                .recv_response()
                .await
                .expect("early H3 response before request EOF");
            assert_eq!(response.status(), http::StatusCode::OK);
            let mut first = stream
                .recv_data()
                .await
                .expect("first reply")
                .expect("DATA");
            assert_eq!(first.copy_to_bytes(first.remaining()), Bytes::from(vec![i]));

            stream
                .send_data(Bytes::from(vec![i.wrapping_add(1)]))
                .await
                .expect("phase-2 while reading response");
            stream.finish().await.expect("request FIN");
            let mut second = stream
                .recv_data()
                .await
                .expect("second reply")
                .expect("DATA");
            assert_eq!(
                second.copy_to_bytes(second.remaining()),
                Bytes::from(vec![i.wrapping_add(1)])
            );
            assert!(stream.recv_data().await.expect("response EOF").is_none());
        }

        client_done_tx.send(()).expect("server alive");
        server.await.expect("server task");
        driver_task.abort();
        client_endpoint.close(0u32.into(), b"done");
    })
    .await
    .expect("eight concurrent QUIC/H3 streams timed out");
}

/// A cancelled HTTP/3 request must reset its QUIC stream, not kill the
/// authenticated QUIC connection or another HTTP/3 stream on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_quic_cancel_stream_preserves_sibling_request() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (server_endpoint, client_endpoint, addr) = endpoints();
        let (first_consumed_tx, first_consumed_rx) = tokio::sync::oneshot::channel::<()>();
        let (cancel_observed_tx, cancel_observed_rx) = tokio::sync::oneshot::channel::<()>();
        let (client_done_tx, client_done_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("QUIC");
            let connection = incoming.await.expect("TLS verified");
            assert_h3_and_bbr(&connection);
            let mut h3: h3::server::Connection<_, Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection))
                    .await
                    .expect("H3 server session");

            let first = h3
                .accept()
                .await
                .expect("accept first")
                .expect("first request");
            let cancel_handler = tokio::spawn(async move {
                let (request, mut stream) = first.resolve_request().await.expect("headers");
                assert_eq!(request.uri().path(), "/v1/session/cancel");
                let mut data = stream
                    .recv_data()
                    .await
                    .expect("first chunk")
                    .expect("DATA");
                assert_eq!(
                    data.copy_to_bytes(data.remaining()),
                    Bytes::from_static(b"before-cancel")
                );
                first_consumed_tx.send(()).expect("client waiting");
                // HTTP/3 request cancellation is QUIC RESET_STREAM on request
                // sending half; this is not a graceful request FIN.
                let next = stream.recv_data().await;
                assert!(next.is_err(), "expected H3 stream reset after cancellation");
                cancel_observed_tx
                    .send(())
                    .expect("client awaiting cancellation");
            });

            let second = h3
                .accept()
                .await
                .expect("accept sibling")
                .expect("second request");
            let sibling_handler = tokio::spawn(async move {
                let (request, mut stream) =
                    second.resolve_request().await.expect("sibling headers");
                assert_eq!(request.uri().path(), "/v1/session/after-cancel");
                let mut data = stream
                    .recv_data()
                    .await
                    .expect("sibling DATA")
                    .expect("body");
                assert_eq!(
                    data.copy_to_bytes(data.remaining()),
                    Bytes::from_static(b"still-alive")
                );
                assert!(stream.recv_data().await.expect("sibling EOF").is_none());
                stream
                    .send_response(http::Response::builder().status(204).body(()).unwrap())
                    .await
                    .expect("reply to sibling");
                stream.finish().await.expect("sibling response FIN");
            });

            client_done_rx.await.expect("client read sibling reply");
            cancel_handler.await.expect("cancel handler");
            sibling_handler.await.expect("sibling handler");
        });

        let connection = client_endpoint
            .connect(addr, "localhost")
            .expect("QUIC connect")
            .await
            .expect("TLS certificate validation");
        assert_h3_and_bbr(&connection);
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .expect("H3 client");
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/v1/session/cancel")
            .body(())
            .unwrap();
        let mut cancelled = sender.send_request(request).await.expect("first stream");
        cancelled
            .send_data(Bytes::from_static(b"before-cancel"))
            .await
            .expect("first DATA");
        first_consumed_rx.await.expect("server received DATA");
        cancelled.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        cancelled.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        drop(cancelled);
        cancel_observed_rx.await.expect("server observed H3 reset");

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/v1/session/after-cancel")
            .body(())
            .unwrap();
        let mut sibling = sender
            .send_request(request)
            .await
            .expect("independent stream");
        sibling
            .send_data(Bytes::from_static(b"still-alive"))
            .await
            .expect("sibling DATA");
        sibling.finish().await.expect("sibling request FIN");
        assert_eq!(
            sibling
                .recv_response()
                .await
                .expect("sibling response")
                .status(),
            http::StatusCode::NO_CONTENT,
        );
        assert!(sibling
            .recv_data()
            .await
            .expect("sibling response EOF")
            .is_none());

        client_done_tx.send(()).expect("server still alive");
        server.await.expect("server task");
        driver_task.abort();
        client_endpoint.close(0u32.into(), b"done");
    })
    .await
    .expect("H3 cancelled stream isolation timed out");
}


/// With QUIC send_window=48 KiB and peer stream_receive_window=32 KiB,
/// a server writing 1 MiB of H3 response DATA must stall while the client
/// ignores the body, then finish once that same reader begins draining it.
/// A success here proves transport backpressure and recovery, not peak RSS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_quic_slow_response_reader_stalls_and_recovers() {
    const BLOCK: usize = 4096;
    const TOTAL: usize = 1024 * 1024;

    tokio::time::timeout(Duration::from_secs(25), async {
        let (server_endpoint, client_endpoint, addr) =
            endpoints_with_slow_reader_limits(true);
        let (first_chunk_tx, first_chunk_rx) = tokio::sync::oneshot::channel::<()>();
        let (send_finished_tx, mut send_finished_rx) =
            tokio::sync::oneshot::channel::<()>();
        let (client_done_tx, client_done_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("incoming QUIC");
            let connection = incoming.await.expect("QUIC TLS handshake");
            assert_h3_and_bbr(&connection);
            let mut h3: h3::server::Connection<_, Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection))
                    .await.expect("H3 server");
            let resolver = h3.accept().await.expect("H3 accept").expect("request");
            let (request, mut stream) = resolver.resolve_request().await
                .expect("request headers");
            assert_eq!(request.uri().path(), "/v1/session/slow-reader");
            assert!(stream.recv_data().await.expect("request EOF").is_none());
            stream.send_response(http::Response::builder().status(200)
                .body(()).unwrap()).await.expect("early response");

            let chunk = Bytes::from(vec![0x6d; BLOCK]);
            stream.send_data(chunk.clone()).await.expect("first H3 DATA");
            first_chunk_tx.send(()).expect("client awaiting first chunk");
            for _ in 1..(TOTAL / BLOCK) {
                stream.send_data(chunk.clone()).await.expect("write under backpressure");
            }
            stream.finish().await.expect("H3 response EOF");
            send_finished_tx.send(()).expect("client awaits sender");
            client_done_rx.await.expect("reader completed response");
        });

        let connection = client_endpoint.connect(addr, "localhost")
            .expect("connect").await.expect("verified certificate");
        assert_h3_and_bbr(&connection);
        let (mut driver, mut sender) = h3::client::new(
            h3_quinn::Connection::new(connection.clone())
        ).await.expect("H3 client");
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/v1/session/slow-reader")
            .body(()).unwrap();
        let mut stream = sender.send_request(request).await.expect("H3 request");
        stream.finish().await.expect("request body EOS");
        assert_eq!(stream.recv_response().await.expect("HTTP response").status(),
                   http::StatusCode::OK);
        first_chunk_rx.await.expect("server began writing response");

        // The client has not read *any* response DATA. The producer must not
        // be able to buffer a full mebibyte behind a 48 KiB send_window.
        assert!(tokio::time::timeout(
            Duration::from_millis(100), &mut send_finished_rx
        ).await.is_err(), "H3 sender unexpectedly buffered entire 1 MiB");

        let mut received = 0usize;
        while let Some(mut buf) = stream.recv_data().await.expect("response DATA") {
            let len = buf.remaining();
            let bytes = buf.copy_to_bytes(len);
            assert!(bytes.iter().all(|&b| b == 0x6d), "byte-exact H3 body");
            received += len;
            assert!(received <= TOTAL, "response exceeded test payload budget");
        }
        assert_eq!(received, TOTAL, "full H3 body delivered after stalled reader");
        send_finished_rx.await.expect("server finished sending");
        client_done_tx.send(()).expect("server still alive");
        server.await.expect("server task");
        driver_task.abort();
        client_endpoint.close(0u32.into(), b"done");
    }).await.expect("H3/QUIC slow-reader backpressure timed out");
}
