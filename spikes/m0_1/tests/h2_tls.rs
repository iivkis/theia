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
