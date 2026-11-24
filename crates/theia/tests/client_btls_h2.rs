//! M3.4e: real production SmartTheia H2Client state machine over optional
//! verified BoringSSL TCP/TLS1.3. Mandatory Linux/Windows CI feature test.
//! The default binary and H3 transport never select this experiment.
#![cfg(feature = "experimental-btls-h2")]

#[path = "../../../spikes/m0_1/src/client_hello.rs"]
mod client_hello;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use client_hello::{parse_tls_records, ParseError};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use theia::{
    client::{ClientError, H2Client},
    config::{Inbound, ServerPolicy, User},
    protocol::{Address, ErrorCode},
    server::{serve, ServerContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const TOKEN: [u8; 32] = [0x42; 32];
const TEST_DEADLINE: Duration = Duration::from_secs(25);

type ServerTask = JoinHandle<Result<(), theia::server::ServerError>>;

fn token() -> String {
    URL_SAFE_NO_PAD.encode(TOKEN)
}

/// Test CA and leaf have distinct subjects: otherwise BoringSSL may treat
/// the leaf as a self-signed certificate despite an explicit trusted root.
fn tls_fixture(alpn: &[u8]) -> (TlsAcceptor, String) {
    let mut ca_params = CertificateParams::new(vec!["test-root.invalid".into()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "theia-m3-4e-root");
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "theia-m3-4e-server");
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone(), ca.der().clone()],
        PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
    )
    .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    (TlsAcceptor::from(Arc::new(config)), ca.pem())
}

async fn production_listener(allow_private: bool, alpn: &[u8]) -> (String, String, ServerTask) {
    let (acceptor, pem) = tls_fixture(alpn);
    let inbound = Inbound {
        id: "test".into(),
        allowed_user_ids: vec!["client".into()],
        h2_listen: "127.0.0.1:0".into(),
        quic_listen: "127.0.0.1:0".into(),
        server_name: "localhost".into(),
        tls_cert: "ephemeral-test-only".into(),
        security_mode: Default::default(),
        reality_key: None,
        tls_key: "ephemeral-test-only".into(),
    };
    let user = User {
        id: "client".into(),
        token_sha256: format!("{:x}", Sha256::digest(TOKEN)),
        disabled: false,
    };
    let policy = ServerPolicy {
        allow_private_ips: allow_private,
        max_connections_per_user: 8,
        max_connections_total: 8,
        connect_timeout_ms: 1500,
    };
    let context = Arc::new(ServerContext::new(&inbound, &[user], &policy));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(serve(listener, acceptor, context));
    (endpoint, pem, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn experimental_btls_opens_production_smarttheia_and_relays_both_fins() {
    timeout(TEST_DEADLINE, async {
        let (endpoint, pem, server) = production_listener(true, b"h2").await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut received = Vec::new();
            socket.read_to_end(&mut received).await.unwrap();
            socket.write_all(&received).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let client =
            H2Client::new_experimental_btls(&endpoint, "localhost", &token(), pem.as_bytes())
                .unwrap();
        // This returns only AFTER HTTP auth, HELLO_ACK and actual OPEN_OK.
        let tunnel = client
            .open(Address::Dns("localhost".into()), port)
            .await
            .expect("strict TLS + authenticated SmartTheia OPEN_OK");
        let (mut app, local) = tokio::io::duplex(4096);
        let relay = tokio::spawn(tunnel.relay(local));
        let payload: Vec<_> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
        app.write_all(&payload).await.unwrap();
        app.shutdown().await.unwrap();
        let mut output = Vec::new();
        app.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, payload, "byte exact duplex relay and both FINs");
        relay.await.unwrap().unwrap();
        echo.await.unwrap();
        server.abort();
    })
    .await
    .expect("bounded production BoringSSL SmartTheia E2E");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn experimental_btls_never_opens_after_wrong_ca_name_auth_or_acl() {
    timeout(TEST_DEADLINE, async {
        let (endpoint, pem, server) = production_listener(false, b"h2").await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let address = Address::Dns("localhost".into());

        let wrong_name =
            H2Client::new_experimental_btls(&endpoint, "wrong.example", &token(), pem.as_bytes())
                .unwrap();
        assert!(matches!(
            wrong_name.open(address.clone(), port).await,
            Err(ClientError::Tls)
        ));
        let (_, unrelated) = tls_fixture(b"h2");
        let wrong_ca =
            H2Client::new_experimental_btls(&endpoint, "localhost", &token(), unrelated.as_bytes())
                .unwrap();
        assert!(matches!(
            wrong_ca.open(address.clone(), port).await,
            Err(ClientError::Tls)
        ));

        let wrong_token = H2Client::new_experimental_btls(
            &endpoint,
            "localhost",
            &URL_SAFE_NO_PAD.encode([0x43; 32]),
            pem.as_bytes(),
        )
        .unwrap();
        assert!(matches!(
            wrong_token.open(address.clone(), port).await,
            Err(ClientError::Unauthorized)
        ));

        let correct =
            H2Client::new_experimental_btls(&endpoint, "localhost", &token(), pem.as_bytes())
                .unwrap();
        assert!(matches!(
            correct.open(address, port).await,
            Err(ClientError::Open(ErrorCode::PolicyDenied))
        ));
        assert!(
            timeout(Duration::from_millis(250), target.accept())
                .await
                .is_err(),
            "no unauthorized or ACL-denied remote dial"
        );
        server.abort();
    })
    .await
    .expect("bounded BoringSSL negative PKI/auth/ACL matrix");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn experimental_btls_rejects_non_h2_alpn_and_invalid_trust_at_construction() {
    timeout(TEST_DEADLINE, async {
        let (endpoint, pem, server) = production_listener(true, b"http/1.1").await;
        let client =
            H2Client::new_experimental_btls(&endpoint, "localhost", &token(), pem.as_bytes())
                .unwrap();
        assert!(matches!(
            client.open(Address::Dns("localhost".into()), 443).await,
            Err(ClientError::Tls)
        ));
        server.abort();
        assert!(matches!(
            H2Client::new_experimental_btls(&endpoint, "localhost", &token(), b""),
            Err(ClientError::Configuration)
        ));
        assert!(matches!(
            H2Client::new_experimental_btls(&endpoint, "localhost", &token(), b"not a CA"),
            Err(ClientError::Configuration)
        ));
    })
    .await
    .expect("BoringSSL must reject ALPN downgrade and missing CA");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn experimental_production_btls_clienthello_has_real_grease_alps_and_fails_closed() {
    timeout(Duration::from_secs(15), async {
        let (_, pem) = tls_fixture(b"h2");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let client =
            H2Client::new_experimental_btls(&endpoint, "localhost", &token(), pem.as_bytes())
                .unwrap();
        let opening = tokio::spawn(async move {
            client
                .open(Address::Dns("example.org".into()), 443)
                .await
                .is_err()
        });
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut wire = Vec::new();
        let hello = loop {
            let mut header = [0u8; 5];
            socket.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 22, "actual TLS handshake record");
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            assert!((1..=18_432).contains(&length), "bounded TLS record");
            assert!(wire.len() + 5 + length <= 65_536, "bounded TLS ClientHello");
            wire.extend_from_slice(&header);
            let start = wire.len();
            wire.resize(start + length, 0);
            socket.read_exact(&mut wire[start..]).await.unwrap();
            match parse_tls_records(&wire) {
                Ok(summary) => break summary,
                Err(ParseError::Truncated) => continue,
                Err(other) => panic!("malformed TLS ClientHello: {other:?}"),
            }
        };
        drop(wire); // Never emit SNI/random/key shares/raw TLS bytes in CI logs.
        drop(socket);
        assert!(opening.await.unwrap(), "unverified peer cannot open a tunnel");

        assert_eq!(hello.legacy_version, 0x0303);
        assert!(hello.supported_versions.contains(&0x0304));
        assert!(hello.sni_present);
        assert_eq!(hello.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert!(hello.has_grease_extension());
        assert!(hello.has_alps());
        assert!(hello.extensions_in_wire_order.contains(&17_613));
        assert!(!hello.quic_transport_parameters_present);
        eprintln!(
            "Experimental production H2Client BoringSSL first-flight: GREASE=yes ALPS_17613=yes cipher_count={} extension_count={} (NOT Chrome fidelity)",
            hello.cipher_suites.len(),
            hello.extensions_in_wire_order.len()
        );
    })
    .await
    .expect("bounded production-path first-flight observation");
}
