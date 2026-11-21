//! Test-only E2E between the actual Go uTLS Chrome133 TLS client and the
//! pinned Rust h2 0.4.19 server. The Go binary is built separately by CI.
//!
//! This proves real TCP ClientHello fields and strict TLS identity checks,
//! NOT a Rust client impersonating Chrome or any HTTP/3/QUIC profile.
use rustls::{pki_types::PrivatePkcs8KeyDer, ProtocolVersion};
use std::{process::Command, sync::Arc, time::Duration};
use theia_m0_1_feasibility::client_hello::{parse_tls_records, ClientHelloSummary};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
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

/// Observe the actual first TCP TLS record before rustls consumes it.
/// SNI, key shares, client random and raw handshake are never logged or saved.
async fn inspect_real_wire_client_hello(socket: &TcpStream) -> ClientHelloSummary {
    tokio::time::timeout(Duration::from_secs(12), async {
        let mut raw = [0u8; 16 * 1024];
        loop {
            let n = socket
                .peek(&mut raw)
                .await
                .expect("peek Go uTLS first flight");
            if n >= 5 {
                assert_eq!(raw[0], 22, "TLS handshake record");
                let length = usize::from(u16::from_be_bytes([raw[3], raw[4]]));
                assert!(length > 0 && length <= raw.len() - 5, "bounded TLS record");
                if n >= 5 + length {
                    let observed = parse_tls_records(&raw[..5 + length])
                        .expect("valid network TLS ClientHello");
                    return observed;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("capture test first flight timed out")
}

async fn exercise_go_utls(mode: &'static str) {
    tokio::time::timeout(Duration::from_secs(45), async {
        let binary = std::env::var_os("THEIA_UTLS_H2_PROBE")
            .expect("CI must build test-only Go uTLS h2_probe binary");
        let (acceptor, trusted_pem) = tls_server();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("listen address");
        let (reader_done_tx, reader_done_rx) = oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("Go TCP connection");
            let first_flight = inspect_real_wire_client_hello(&socket).await;
            assert_eq!(first_flight.legacy_version, 0x0303);
            assert_eq!(
                first_flight.alpn,
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                "actual on-socket ALPN matches Chrome133 uTLS profile"
            );
            assert!(
                first_flight.has_grease_extension(),
                "Go uTLS ClientHello on TCP must contain GREASE"
            );
            assert!(
                first_flight.has_alps(),
                "Go uTLS ClientHello on TCP must contain ALPS"
            );
            assert!(first_flight.sni_present, "Go TLS sent SNI");
            assert!(
                !first_flight.quic_transport_parameters_present,
                "TCP TLS cannot claim to be QUIC"
            );

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
                    .expect("GET over uTLS session");
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

                // Poll the h2 connection to drive its IO while the Go client
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
                        Ok(Ok(_)) => panic!("invalid-cert uTLS client sent HTTP/2 data"),
                        Err(_) => panic!("rejected Go uTLS connection did not close"),
                    }
                }
            }
            eprintln!("actual Go uTLS TLS ClientHello observed on loopback: GREASE=true ALPS=true");
        });

        // CI builds the binary before this ignored test, so this blocks only
        // one worker while other Tokio workers drive the Rust TLS/H2 server.
        let output = Command::new(binary)
            .arg(address.to_string())
            .arg(mode)
            .env("THEIA_TEST_ROOT_PEM", trusted_pem)
            .output()
            .expect("launch Go uTLS client probe");
        let _ = reader_done_tx.send(());
        assert!(
            output.status.success(),
            "Go uTLS probe {mode} failed: {}",
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
    .expect("Go uTLS/Rust H2 loopback test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "CI builds Go uTLS helper and runs these network tests explicitly"]
async fn utls_chrome133_real_tcp_tls13_h2_request_with_verified_identity() {
    exercise_go_utls("ok").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "CI builds Go uTLS helper and runs these network tests explicitly"]
async fn utls_chrome133_real_tcp_rejects_wrong_hostname_before_h2() {
    exercise_go_utls("wrong-name").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "CI builds Go uTLS helper and runs these network tests explicitly"]
async fn utls_chrome133_real_tcp_rejects_untrusted_ca_before_h2() {
    exercise_go_utls("untrusted-ca").await;
}
