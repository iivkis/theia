//! CI-only feasibility: BoringSSL real TCP/TLS first flight and strict PKI.
//! This crate is not part of the shipping Rust Theia binary.
#[path = "../../m0_1/src/client_hello.rs"]
mod client_hello;

use btls::ssl::SslVersion;
use client_hello::{parse_handshake, parse_tls_records, ParseError};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::{sync::Arc, time::Duration};
use theia_m3_4_btls_feasibility::h2_candidate;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_btls::SslStream;
use tokio_rustls::TlsAcceptor;

const MAX_CLIENT_HELLO: usize = 65_536;

fn certificate_fixture() -> (String, String, rustls::ServerConfig) {
    let mut ca_params = CertificateParams::new(vec!["theia-test-ca".into()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // rcgen's default CN is identical for both certificates. If unchanged,
    // BoringSSL sees the leaf Subject == Issuer and rejects it as self-signed.
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "theia-fixture-root");
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "theia-fixture-leaf");
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    assert_ne!(
        leaf.params().distinguished_name,
        ca.params().distinguished_name,
        "distinct CA and leaf subjects are required for X.509 chain fixture"
    );

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
    config.alpn_protocols = vec![b"h2".to_vec()];
    let unrelated = rcgen::generate_simple_self_signed(vec!["unrelated.example".into()])
        .unwrap()
        .cert
        .pem();
    (ca.pem(), unrelated, config)
}

async fn connect(
    address: std::net::SocketAddr,
    name: &str,
    trusted_ca: &[u8],
) -> Result<(), &'static str> {
    let config = h2_candidate(trusted_ca).map_err(|_| "invalid strict TLS configuration")?;
    let ssl = config.into_ssl(name).map_err(|_| "invalid target name")?;
    let socket = TcpStream::connect(address).await.map_err(|_| "connect")?;
    let mut stream = Box::pin(SslStream::new(ssl, socket).map_err(|_| "TLS setup")?);
    if let Err(error) = stream.as_mut().connect().await {
        // Safe test-only diagnostic: never print SNI, peer cert, key material,
        // TLS record bytes, error stacks or credential contents.
        eprintln!(
            "BoringSSL handshake rejected: ssl_code={:?}, x509_verify={:?}",
            error.code(),
            stream.ssl().verify_result()
        );
        return Err("verified TLS handshake failed");
    }
    if stream.ssl().version2() != Some(SslVersion::TLS1_3)
        || stream.ssl().selected_alpn_protocol() != Some(b"h2".as_slice())
    {
        return Err("TLS version / ALPN mismatch");
    }
    Ok(())
}

async fn capture_hello() -> client_hello::ClientHelloSummary {
    timeout(Duration::from_secs(15), async {
        let (pem, _, _) = certificate_fixture();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let attempt =
            tokio::spawn(
                async move { connect(address, "localhost", pem.as_bytes()).await.is_err() },
            );
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut raw = Vec::new();
        let observed = loop {
            let mut record = [0u8; 5];
            socket.read_exact(&mut record).await.unwrap();
            assert_eq!(record[0], 22, "TLS handshake record only");
            let length = usize::from(u16::from_be_bytes([record[3], record[4]]));
            assert!((1..=18_432).contains(&length), "bounded TLS record");
            assert!(raw.len() + record.len() + length <= MAX_CLIENT_HELLO);
            raw.extend_from_slice(&record);
            let at = raw.len();
            raw.resize(at + length, 0);
            socket.read_exact(&mut raw[at..]).await.unwrap();
            match parse_tls_records(&raw) {
                Ok(summary) => break summary,
                Err(ParseError::Truncated) => continue,
                Err(other) => panic!("malformed BoringSSL ClientHello: {other:?}"),
            }
        };
        drop(raw); // Never log SNI, randomness, key shares or raw ClientHello.
        drop(socket);
        assert!(attempt.await.unwrap(), "unverified peer must be rejected");
        observed
    })
    .await
    .expect("first-flight and fail-closed deadline")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn btls_candidate_emits_real_grease_and_new_alps_over_tcp() {
    let hello = capture_hello().await;
    assert!(hello.sni_present);
    assert_eq!(hello.legacy_version, 0x0303);
    assert!(hello.supported_versions.contains(&0x0304));
    assert_eq!(hello.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert!(
        hello.has_grease_extension(),
        "actual TCP flight needs GREASE"
    );
    assert!(hello.has_alps(), "actual TCP flight needs ALPS");
    assert!(
        hello.extensions_in_wire_order.contains(&17_613),
        "new ALPS codepoint"
    );
    assert!(!hello.quic_transport_parameters_present);
    eprintln!(
        "BoringSSL H2 candidate actual first flight: GREASE=yes ALPS_17613=yes, ciphers={} extensions={} groups={}; no Chrome match claimed",
        hello.cipher_suites.len(),
        hello.extensions_in_wire_order.len(),
        hello.supported_groups.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn btls_candidate_validates_chain_name_and_tls13_h2() {
    timeout(Duration::from_secs(20), async {
        let (pem, unrelated, server_config) = certificate_fixture();
        for (name, roots, accepted) in [
            ("localhost", pem.as_bytes(), true),
            ("wrong.example", pem.as_bytes(), false),
            ("localhost", unrelated.as_bytes(), false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(server_config.clone()));
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                acceptor.accept(socket).await.is_ok()
            });
            let result = connect(address, name, roots).await;
            // The client may abort a rejected handshake, but success is
            // always reflected on the server for the accepted case.
            let server_result = server.await.unwrap();
            assert_eq!(
                result.is_ok(),
                accepted,
                "strict certificate/name gate: {result:?}, server_accepted={server_result}"
            );
            if accepted {
                assert!(server_result, "verified TLS peer must finish handshake");
            }
        }
    })
    .await
    .expect("bounded loopback certificate matrix");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "mandatory CI-only Go uTLS reference fixture"]
async fn btls_live_h2_compares_to_pinned_utls_chrome133() {
    let path = std::env::var_os("THEIA_UTLS_HELLO_PATH")
        .expect("mandatory Linux/Windows CI generates pinned Go reference");
    let raw = std::fs::read(path).expect("read private ephemeral TLS reference");
    let reference = parse_handshake(&raw).expect("valid Go reference ClientHello");
    drop(raw);
    let candidate = capture_hello().await;
    assert!(reference.has_grease_extension() && reference.has_alps());
    assert_eq!(reference.alpn, candidate.alpn);
    assert!(candidate.has_grease_extension() && candidate.has_alps());
    assert!(candidate.extensions_in_wire_order.contains(&17_613));
    // These are separate stacks; no byte-for-byte profile fidelity is claimed.
    eprintln!(
        "Go uTLS Chrome133 vs BoringSSL candidate on TCP: GREASE=yes/yes ALPS=yes/yes; cipher counts {}/{} extension counts {}/{}; F-13 still BLOCKED",
        reference.cipher_suites.len(),
        candidate.cipher_suites.len(),
        reference.extensions_in_wire_order.len(),
        candidate.extensions_in_wire_order.len()
    );
}
