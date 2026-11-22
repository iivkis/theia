//! CI-only loopback proof of the production QUIC/TLS composition root.
use bytes::{Buf, Bytes};
use quinn::Endpoint;
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use std::{net::SocketAddr, time::Duration};
use theia::{
    protocol::{self, Decoder, Direction, Frame, Role, Session, VERSION},
    quic_transport::{accept, client_endpoint, connect, server_endpoint, QuicError},
};
use tokio::time::timeout;

fn endpoints() -> (Endpoint, Endpoint, SocketAddr) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let bind = "127.0.0.1:0".parse().unwrap();
    let server = server_endpoint(bind, vec![der.clone()], key.into()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(der).unwrap();
    let client = client_endpoint(bind, roots).unwrap();
    let address = server.local_addr().unwrap();
    (server, client, address)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_quic_endpoints_exchange_smarttheia_over_h3() {
    timeout(Duration::from_secs(15), async {
        let (server, client, address) = endpoints();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let conn = accept(server.accept().await.unwrap()).await.unwrap();
            let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(conn))
                .await
                .unwrap();
            let resolver = h3.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/v1/session");
            let mut decoder = Decoder::new();
            let mut session = Session::new(Role::Server);
            let hello = loop {
                let mut data = stream.recv_data().await.unwrap().unwrap();
                let frames = decoder.feed(&data.copy_to_bytes(data.remaining())).unwrap();
                if !frames.is_empty() {
                    assert_eq!(frames.len(), 1);
                    break frames[0].clone();
                }
            };
            session.apply(Direction::Receive, &hello).unwrap();
            assert!(matches!(hello, Frame::Hello { .. }));
            let ack = Frame::HelloAck {
                version: VERSION,
                accepted_capabilities: 0,
            };
            session.apply(Direction::Send, &ack).unwrap();
            stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            stream
                .send_data(Bytes::from(protocol::encode(&ack).unwrap()))
                .await
                .unwrap();
            // Client closes request only after ACK is received: no EOF gating.
            assert!(stream.recv_data().await.unwrap().is_none());
            decoder.finish().unwrap();
            stream.finish().await.unwrap();
            done_rx.await.unwrap();
        });
        let conn = connect(&client, address, "localhost").await.unwrap();
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let request = http::Request::post("https://localhost/v1/session")
            .body(())
            .unwrap();
        let mut stream = sender.send_request(request).await.unwrap();
        let mut state = Session::new(Role::Client);
        let hello = Frame::Hello {
            version: VERSION,
            capabilities: 0,
        };
        state.apply(Direction::Send, &hello).unwrap();
        stream
            .send_data(Bytes::from(protocol::encode(&hello).unwrap()))
            .await
            .unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        let mut decoder = Decoder::new();
        let ack = loop {
            let mut data = stream.recv_data().await.unwrap().unwrap();
            let frames = decoder.feed(&data.copy_to_bytes(data.remaining())).unwrap();
            if !frames.is_empty() {
                assert_eq!(frames.len(), 1);
                break frames[0].clone();
            }
        };
        state.apply(Direction::Receive, &ack).unwrap();
        assert!(matches!(ack, Frame::HelloAck { .. }));
        // This is a handshake test, not a completed SmartTheia TCP tunnel.
        assert!(!state.tunnel_open());
        stream.finish().await.unwrap();
        assert!(stream.recv_data().await.unwrap().is_none());
        decoder.finish().unwrap();
        done_tx.send(()).unwrap();
        task.await.unwrap();
        driver_task.abort();
        client.close(0u32.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn production_quic_rejects_wrong_name_and_untrusted_ca() {
    timeout(Duration::from_secs(15), async {
        let (server, client, address) = endpoints();
        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let incoming = server.accept().await.unwrap();
                assert!(accept(incoming).await.is_err());
            }
        });
        assert!(matches!(
            connect(&client, address, "wrong.example").await,
            Err(QuicError::Handshake)
        ));
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let wrong_ca = client_endpoint("127.0.0.1:0".parse().unwrap(), roots).unwrap();
        assert!(matches!(
            connect(&wrong_ca, address, "localhost").await,
            Err(QuicError::Handshake)
        ));
        server_task.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn production_quic_empty_trust_fails_before_binding() {
    assert!(matches!(
        client_endpoint("127.0.0.1:0".parse().unwrap(), RootCertStore::empty()),
        Err(QuicError::Configuration)
    ));
}
