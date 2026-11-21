//! Network-level feasibility checks for Theia H3 over QUIC/TLS 1.3.
//! Test-only localhost credentials, ordinary hostname verification, no insecure TLS verifier.
use bytes::{Buf, Bytes};
use quinn::{crypto::rustls::{QuicClientConfig, QuicServerConfig, HandshakeData}, Endpoint};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use theia_m0_1_feasibility::{configure_client_bbr, configure_server_bbr};

const ALPN: &[u8] = b"h3";

fn endpoints() -> (Endpoint, Endpoint, SocketAddr) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("generate test cert");
    let cert = key.cert.der().clone();
    let private = PrivatePkcs8KeyDer::from(key.key_pair.serialize_der());

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], private.into())
        .expect("valid test certificate");
    server_tls.alpn_protocols = vec![ALPN.into()];
    // Neither HTTP 0-RTT nor QUIC 0-RTT is enabled in this test.
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_tls).expect("QUIC TLS server config"),
    ));
    configure_server_bbr(&mut server_config);
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
        .expect("bind UDP server");
    let address = server.local_addr().expect("bound address");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("trust generated test certificate");
    let mut client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![ALPN.into()];
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls).expect("QUIC TLS client config"),
    ));
    configure_client_bbr(&mut client_config);
    let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap())
        .expect("bind UDP client");
    client.set_default_client_config(client_config);
    (server, client, address)
}

fn assert_h3_and_bbr(conn: &quinn::Connection) {
    let handshake = conn.handshake_data()
        .expect("handshake metadata")
        .downcast::<HandshakeData>()
        .expect("rustls handshake metadata");
    assert_eq!(handshake.protocol.as_deref(), Some(ALPN));
    assert!(
        conn.congestion_state().into_any()
            .downcast::<quinn::congestion::Bbr>().is_ok(),
        "actual active QUIC sender must be BBR, not CUBIC"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_quic_tls_full_duplex_and_active_bbr_on_both_sides() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (server_endpoint, client_endpoint, server_addr) = endpoints();

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.expect("incoming QUIC");
            let conn = incoming.await.expect("TLS handshake");
            assert_h3_and_bbr(&conn);

            let mut h3conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
                .await.expect("H3 server session");
            let resolver = h3conn.accept().await.expect("H3 accept").expect("POST stream");
            let (request, mut stream) = resolver.resolve_request().await.expect("POST headers");
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/v1/session");
            // First DATA arrives while request body is still open.
            let mut first = stream.recv_data().await.expect("request chunk").expect("phase-1");
            assert_eq!(first.copy_to_bytes(first.remaining()), Bytes::from_static(b"phase-1"));

            stream.send_response(http::Response::builder().status(200).body(()).unwrap())
                .await.expect("response headers before request EOF");
            stream.send_data(Bytes::from_static(b"reply-1")).await.expect("response chunk");

            let mut second = stream.recv_data().await.expect("second request chunk").expect("phase-2");
            assert_eq!(second.copy_to_bytes(second.remaining()), Bytes::from_static(b"phase-2"));
            stream.send_data(Bytes::from_static(b"reply-2")).await.expect("second response");
            stream.finish().await.expect("finish response");
            // Keep both endpoints alive until client has consumed response.
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let conn = client_endpoint.connect(server_addr, "localhost")
            .expect("valid server address").await.expect("verified QUIC TLS handshake");
        assert_h3_and_bbr(&conn);
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await.expect("H3 client session");
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/v1/session")
            .body(()).unwrap();
        let mut stream = sender.send_request(request).await.expect("send H3 headers");
        stream.send_data(Bytes::from_static(b"phase-1")).await.expect("send initial body");

        // Critical: response can be received before request.finish() / request EOF.
        let response = stream.recv_response().await.expect("server response before request EOF");
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut reply = stream.recv_data().await.expect("response body").expect("reply-1");
        assert_eq!(reply.copy_to_bytes(reply.remaining()), Bytes::from_static(b"reply-1"));

        stream.send_data(Bytes::from_static(b"phase-2")).await.expect("send additional body");
        stream.finish().await.expect("finish request");
        let mut second_reply = stream.recv_data().await.expect("second body").expect("reply-2");
        assert_eq!(
            second_reply.copy_to_bytes(second_reply.remaining()),
            Bytes::from_static(b"reply-2"),
        );
        assert!(stream.recv_data().await.expect("response EOF").is_none());

        server_task.await.expect("server task");
        driver_task.abort();
        client_endpoint.close(0u32.into(), b"done");
    }).await.expect("H3/QUIC full duplex timed out");
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
        let result = client_endpoint.connect(server_addr, "incorrect.example")
            .expect("dial allowed").await;
        assert!(result.is_err(), "certificate name mismatch must fail closed");
        server_task.await.expect("handshake task");
    }).await.expect("rejection test timed out");
}
