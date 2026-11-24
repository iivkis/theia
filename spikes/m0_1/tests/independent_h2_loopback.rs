//! Independent Python/OpenSSL TLS 1.3/H2 interoperability and PKI tests.
//! Test-only loopback, not a browser fingerprint reference.
use rustls::{pki_types::PrivatePkcs8KeyDer, ProtocolVersion};
use std::{process::Command, sync::Arc, time::Duration};
use tokio::{io::AsyncReadExt, net::TcpListener, sync::oneshot};
use tokio_rustls::TlsAcceptor;

fn tls_server() -> (TlsAcceptor, String) {
    let keypair = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("ephemeral certificate");
    let cert_der = keypair.cert.der().clone();
    let cert_pem = keypair.cert.pem();
    let private = PrivatePkcs8KeyDer::from(keypair.key_pair.serialize_der());
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], private.into())
    .expect("ephemeral TLS identity");
    config.alpn_protocols = vec![b"h2".to_vec()];
    (TlsAcceptor::from(Arc::new(config)), cert_pem)
}

async fn exercise_independent_tls(mode: &'static str) {
    tokio::time::timeout(Duration::from_secs(45), async {
        let (acceptor, trusted_pem) = tls_server();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listen address");
        let (reader_done_tx, reader_done_rx) = oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("independent TCP connection");
            if mode == "ok" {
                let tls = acceptor.accept(socket).await.expect("TLS server handshake");
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
                assert_eq!(
                    tls.get_ref().1.protocol_version(),
                    Some(ProtocolVersion::TLSv1_3)
                );

                let mut h2 = h2::server::handshake(tls).await.expect("real H2 server");
                let (request, mut responder) = h2
                    .accept()
                    .await
                    .expect("H2 connection still running")
                    .expect("GET over independent TLS session");
                assert_eq!(request.method(), http::Method::GET);
                assert_eq!(request.uri().path(), "/");
                let mut body = request.into_body();
                assert!(body.data().await.is_none(), "GET body EOF");
                responder
                    .send_response(
                        http::Response::builder().status(204).body(()).unwrap(),
                        true,
                    )
                    .expect("H2 status 204 HEADERS");

                // Poll the h2 connection to drive its IO while the independent client
                // receives HEADERS; merely constructing a responder is not IO.
                tokio::select! {
                    _ = async { while h2.accept().await.is_some() {} } => {},
                    _ = reader_done_rx => {},
                }
            } else {
                // The client must reject the certificate BEFORE any H2 DATA.
                // Server accept can succeed or fail depending on alert timing.
                if let Ok(mut tls) = acceptor.accept(socket).await {
                    let mut byte = [0u8; 1];
                    match tokio::time::timeout(Duration::from_secs(8), tls.read(&mut byte)).await {
                        Ok(Ok(0)) | Ok(Err(_)) => {}
                        Ok(Ok(_)) => panic!("invalid-cert independent client sent HTTP/2 data"),
                        Err(_) => panic!("rejected independent TLS connection did not close"),
                    }
                }
            }
        });

        // The probe uses only Python's standard library and OpenSSL.
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/independent-h2-probe.py");
        let output = Command::new("python")
            .arg(script)
            .arg(address.to_string())
            .arg(mode)
            .env("THEIA_TEST_ROOT_PEM", trusted_pem)
            .output()
            .expect("launch independent TLS client probe");
        let _ = reader_done_tx.send(());
        assert!(
            output.status.success(),
            "independent TLS probe {mode} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        match mode {
            "ok" => assert!(stdout.contains("TLS1.3 h2 GET -> 204"), "{stdout}"),
            "wrong-name" => assert!(stdout.contains("rejected wrong hostname"), "{stdout}"),
            "untrusted-ca" => assert!(stdout.contains("rejected untrusted CA"), "{stdout}"),
            _ => unreachable!(),
        }
        server_task.await.expect("Rust TLS server task");
    })
    .await
    .expect("OpenSSL/Rust H2 loopback test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "mandatory native CI supplies Python 3.12"]
async fn independent_tls13_h2_request_with_verified_identity() {
    exercise_independent_tls("ok").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "mandatory native CI supplies Python 3.12"]
async fn independent_tls13_rejects_wrong_hostname_before_h2() {
    exercise_independent_tls("wrong-name").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "mandatory native CI supplies Python 3.12"]
async fn independent_tls13_rejects_untrusted_ca_before_h2() {
    exercise_independent_tls("untrusted-ca").await;
}
