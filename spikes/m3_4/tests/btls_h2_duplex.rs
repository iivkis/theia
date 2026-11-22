//! M3.4c on-wire CI proof of BoringSSL -> h2 0.4.19 full duplex.
//! Tests use loopback and ephemeral PKI, never production user certificates.
//! The transport adapter is research-only; no browser-profile claims.
use bytes::Bytes;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::{future::poll_fn, sync::Arc, time::Duration};
use theia_m3_4_btls_feasibility::h2_transport::{
    connect_verified_h2, H2CandidateError,
};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};
use tokio_rustls::TlsAcceptor;

const DEADLINE: Duration = Duration::from_secs(25);

fn tls_fixture(server_alpn: &'static [u8]) -> (TlsAcceptor, String, String) {
    let mut ca_params = CertificateParams::new(vec!["test-ca.invalid".into()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "theia-m3-4c-fixture-root");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "theia-m3-4c-fixture-server");
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf_cert.der().clone(), ca_cert.der().clone()],
        PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![server_alpn.to_vec()];
    let alien_ca = rcgen::generate_simple_self_signed(vec!["unrelated.example".into()])
        .unwrap()
        .cert
        .pem();
    (TlsAcceptor::from(Arc::new(tls)), ca_cert.pem(), alien_ca)
}

/// The h2 send window may be lower than a caller's payload. Never buffer
/// unbounded request or response DATA while waiting for peer WINDOW_UPDATE.
async fn bounded_send(stream: &mut h2::SendStream<Bytes>, data: Bytes, end: bool) {
    let size = data.len();
    stream.reserve_capacity(size);
    while stream.capacity() < size {
        let granted = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .expect("open H2 stream")
            .expect("H2 flow control");
        assert!(granted > 0, "peer must make capacity available");
    }
    stream.send_data(data, end).expect("bounded H2 DATA");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn btls_h2_full_duplex_response_before_request_end_stream() {
    timeout(DEADLINE, async {
        let (acceptor, trusted_ca, _) = tls_fixture(b"h2");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (client_done_tx, client_done_rx) = oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(socket).await.expect("strict TLS server");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            let mut h2 = h2::server::handshake(tls).await.expect("server H2 handshake");
            let (request, mut responder) = h2
                .accept()
                .await
                .expect("open H2 connection")
                .expect("POST stream");
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/v1/session");
            assert_eq!(request.uri().authority().unwrap().as_str(), "localhost");

            let handler = tokio::spawn(async move {
                let mut incoming = request.into_body();
                let first = incoming.data().await.unwrap().unwrap();
                assert_eq!(first, Bytes::from_static(b"client-first"));
                incoming.flow_control().release_capacity(first.len()).unwrap();

                // Send response without request END_STREAM: proves full duplex.
                let mut outgoing = responder
                    .send_response(http::Response::builder().status(200).body(()).unwrap(), false)
                    .expect("response headers while request body remains open");
                bounded_send(&mut outgoing, Bytes::from_static(b"server-first"), false).await;

                let second = incoming.data().await.unwrap().unwrap();
                assert_eq!(second, Bytes::from_static(b"client-second"));
                incoming.flow_control().release_capacity(second.len()).unwrap();
                assert!(incoming.data().await.is_none(), "request half-close");
                bounded_send(&mut outgoing, Bytes::from_static(b"server-second"), true).await;
            });

            // Keep the H2 connection polled during the application handler.
            tokio::select! {
                _ = async { while h2.accept().await.is_some() {} } => {},
                _ = client_done_rx => {},
            }
            handler.await.expect("full duplex server handler");
        });

        let mut client = connect_verified_h2(endpoint, "localhost", trusted_ca.as_bytes())
            .await
            .expect("verified BoringSSL TLS13 + ALPN h2 + HTTP2");
        let request = http::Request::post("https://localhost/v1/session")
            .body(())
            .unwrap();
        let (response, mut upload) = client
            .sender()
            .send_request(request, false)
            .expect("request with open body");
        bounded_send(&mut upload, Bytes::from_static(b"client-first"), false).await;

        let reply = response
            .await
            .expect("early response without upload END_STREAM");
        assert_eq!(reply.status(), http::StatusCode::OK);
        let mut download = reply.into_body();
        let first = download.data().await.unwrap().unwrap();
        assert_eq!(first, Bytes::from_static(b"server-first"));
        download.flow_control().release_capacity(first.len()).unwrap();

        // The request remains writable after response HEADERS and DATA.
        bounded_send(&mut upload, Bytes::from_static(b"client-second"), true).await;
        let second = download.data().await.unwrap().unwrap();
        assert_eq!(second, Bytes::from_static(b"server-second"));
        download.flow_control().release_capacity(second.len()).unwrap();
        assert!(download.data().await.is_none(), "response half-close");
        client_done_tx.send(()).expect("server driver still alive");
        server.await.expect("server completed");
    })
    .await
    .expect("bounded full-duplex TLS/H2 test timeout");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn btls_h2_rejects_wrong_name_untrusted_ca_and_downgraded_alpn() {
    timeout(DEADLINE, async {
        for (alpn, name, trust_ok) in [
            (b"h2".as_slice(), "wrong.example", true),
            (b"h2".as_slice(), "localhost", false),
            (b"http/1.1".as_slice(), "localhost", true),
        ] {
            let (acceptor, trusted_ca, alien_ca) = tls_fixture(alpn);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                // No HTTP/2 server is started: security rejection must occur
                // before an H2 sender/request handle is returned to the caller.
                acceptor.accept(socket).await.is_ok()
            });

            let pem = if trust_ok { &trusted_ca } else { &alien_ca };
            let result = connect_verified_h2(endpoint, name, pem.as_bytes()).await;
            assert!(
                matches!(result, Err(H2CandidateError::Tls)),
                "TLS identity, trust or ALPN failure must not create an H2 sender"
            );
            let server_accepted = server.await.unwrap();
            assert_eq!(server_accepted, alpn == b"http/1.1");
        }
    })
    .await
    .expect("TLS negative matrix deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn btls_h2_forbidden_response_arrives_before_request_eof() {
    timeout(DEADLINE, async {
        let (acceptor, trusted_ca, _) = tls_fixture(b"h2");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (done_tx, done_rx) = oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(socket).await.unwrap();
            let mut h2 = h2::server::handshake(tls).await.unwrap();
            let (request, mut responder) = h2.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::POST);
            let handler = tokio::spawn(async move {
                // Simulate an auth rejection based only on request headers.
                // Do not await request data or EOF before returning 403.
                responder
                    .send_response(
                        http::Response::builder().status(403).body(()).unwrap(),
                        true,
                    )
                    .expect("reject without waiting for request EOF");
            });
            tokio::select! {
                _ = async { while h2.accept().await.is_some() {} } => {},
                _ = done_rx => {},
            }
            handler.await.unwrap();
        });

        let mut client = connect_verified_h2(endpoint, "localhost", trusted_ca.as_bytes())
            .await
            .expect("verified H2");
        let (reply, _open_upload) = client
            .sender()
            .send_request(
                http::Request::post("https://localhost/v1/session")
                    .body(())
                    .unwrap(),
                false,
            )
            .expect("POST without request EOF");
        assert_eq!(
            reply.await.expect("early HTTP denial").status(),
            http::StatusCode::FORBIDDEN
        );
        // No tunnel success or synthetic OPEN_OK is inferred from HTTP 403.
        done_tx.send(()).unwrap();
        server.await.unwrap();
    })
    .await
    .expect("bounded auth-denial H2 test timeout");
}
