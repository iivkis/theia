//! M3.5a CI-only feasibility controls for a future authenticated camouflage
//! mode. This is NOT REALITY, a wire implementation, a scanner, or a defense
//! against DPI / encapsulated TLS fingerprints.
//!
//! Observations: rustls 0.23.46 supports TLS 1.3 exporter binding after strict
//! certificate verification on TCP/H2, but it does NOT authenticate a separate
//! REALITY-style server identity or reproduce a target site's TLS transcript.
//! Production TOML v1 and invitation v1 must reject new security/shaping flags
//! until an audited, versioned protocol actually exists.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rcgen::generate_simple_self_signed;
use rustls::{
    pki_types::{PrivatePkcs8KeyDer, ServerName},
    RootCertStore,
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use theia::{
    config::{self, Config},
    invite::Invitation,
    quic_transport::{
        accept as accept_quic, client_endpoint, connect as connect_quic, server_endpoint,
    },
};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroize;

const EXPORTER_LABEL: &[u8] = b"EXPORTER-Theia-M3.5a-feasibility-only";
const CONTEXT: &[u8] = b"test-only-domain-separated-channel-binding";
const DEADLINE: Duration = Duration::from_secs(12);

fn checked_server_fixture() -> Config {
    let example = include_str!("../../../examples/server.toml");
    let example = example.replace(
        "REPLACE_WITH_64_LOWERCASE_HEX",
        &format!("{:x}", Sha256::digest([0x42u8; 32])),
    );
    config::parse(&example).expect("valid server example after digest replacement")
}

#[test]
fn v1_toml_refuses_unsupported_server_security_and_shaping_fields() {
    let cfg = checked_server_fixture();
    assert!(cfg.validate().is_ok());
    let baseline = cfg.to_toml().unwrap();
    let anchor = "server_name = \"edge.example.org\"\n";
    assert!(baseline.contains(anchor));
    for proposed in [
        "security_mode = \"smart-reality-v1\"\n",
        "reality_private_key = \"file:/private/server-key\"\n",
        "flow_shaping = \"required\"\n",
        "camouflage_target = \"example.net\"\n",
        "insecure_skip_verify = true\n",
    ] {
        let changed = baseline.replacen(anchor, &format!("{anchor}{proposed}"), 1);
        assert!(
            config::parse(&changed).is_err(),
            "unknown server mode must not silently enable camouflage"
        );
    }
}

#[test]
fn v1_toml_refuses_unsupported_client_modes_even_if_supplied_as_profile() {
    let document = config::parse(include_str!("../../../examples/client.toml")).unwrap();
    let baseline = document.to_toml().unwrap();
    let anchor = "tls_profile = \"default\"\n";
    assert!(baseline.contains(anchor));
    for unsupported in ["smart-reality-v1", "reality", "chrome133", "insecure"] {
        let changed = baseline.replacen(anchor, &format!("tls_profile = \"{unsupported}\"\n"), 1);
        assert!(
            config::parse(&changed).is_err(),
            "unimplemented named TLS/security mode must fail closed"
        );
    }
    for extra in [
        "server_public_key = \"test-only-not-an-identity\"\n",
        "security_mode = \"smart-reality-v1\"\n",
        "flow_shaping = \"required\"\n",
        "disable_certificate_verification = true\n",
    ] {
        assert!(config::parse(&baseline.replacen(anchor, &format!("{anchor}{extra}"), 1)).is_err());
    }
}

#[test]
fn v1_invite_rejects_new_mode_and_identity_injection_without_a_version_bump() {
    let cfg = checked_server_fixture();
    let public = Invitation::public_from_server(&cfg, "public").unwrap();
    assert!(!public.has_token());
    let v1 = public.encode().unwrap();
    assert!(Invitation::decode(&v1).is_ok());
    assert!(Invitation::decode(&v1.replacen("theia://v1/", "theia://v2/", 1)).is_err());
    let wire = URL_SAFE_NO_PAD
        .decode(v1.strip_prefix("theia://v1/").unwrap())
        .unwrap();
    let text = std::str::from_utf8(&wire).unwrap();
    for candidate in [
        text.replace(
            "tls_profile = \"default\"",
            "tls_profile = \"smart-reality-v1\"",
        ),
        text.replace("version = 1", "version = 2"),
        format!("{text}server_public_key = \"test-only-key\"\n"),
        format!("{text}flow_shaping = \"required\"\n"),
        format!("{text}insecure_skip_verify = true\n"),
    ] {
        let link = format!(
            "theia://v1/{}",
            URL_SAFE_NO_PAD.encode(candidate.as_bytes())
        );
        assert!(
            Invitation::decode(&link).is_err(),
            "v1 must reject new trust and anti-DPI fields"
        );
    }
}

/// TLS exporter is a channel-binding PRIMITIVE. Its feasibility is useful,
/// but it does NOT give Theia a REALITY-compatible handshake, a server-key
/// signature or any immunity to active probing. No server keys logged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_h2_tls_exporter_is_identical_on_peers_and_context_separated() {
    timeout(DEADLINE, async {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let chain = vec![cert.cert.der().clone()];
        let private_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain.clone(), private_key.into())
        .unwrap();
        server_tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_tls));

        let mut roots = RootCertStore::empty();
        roots.add(chain[0].clone()).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_tls));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(socket).await.unwrap();
            let connection = stream.get_ref().1;
            assert_eq!(connection.alpn_protocol(), Some(&b"h2"[..]));
            assert_eq!(
                connection.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            let same = connection
                .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(CONTEXT))
                .unwrap();
            let distinct = connection
                .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(b"other context"))
                .unwrap();
            (same, distinct)
        });
        let socket = TcpStream::connect(addr).await.unwrap();
        let tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), socket)
            .await
            .unwrap();
        let connection = tls.get_ref().1;
        assert_eq!(connection.alpn_protocol(), Some(&b"h2"[..]));
        assert_eq!(
            connection.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let mut same = connection
            .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(CONTEXT))
            .unwrap();
        let mut distinct = connection
            .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(b"other context"))
            .unwrap();
        let (mut server_same, mut server_distinct) = server.await.unwrap();
        assert_eq!(
            same, server_same,
            "exporter binds to the authenticated TLS session"
        );
        assert_eq!(
            distinct, server_distinct,
            "both sides use identical context"
        );
        assert_ne!(
            same, distinct,
            "context must domain-separate different uses"
        );
        same.zeroize();
        distinct.zeroize();
        server_same.zeroize();
        server_distinct.zeroize();
    })
    .await
    .expect("test-only TLS exporter handshake completed within deadline");
}

/// QUIC has its own exporter API and network fingerprint. A successful
/// exporter probe is not evidence that REALITY's modified handshake can be
/// carried over QUIC/H3, only that ordinary verified QUIC TLS1.3 can be
/// bound to a session-specific context.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_h3_quic_exporter_matches_both_peers_with_domain_separation() {
    timeout(DEADLINE, async {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server = server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![der.clone()],
            key.into(),
        )
        .unwrap();
        let remote = server.local_addr().unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(der).unwrap();
        let client = client_endpoint("127.0.0.1:0".parse().unwrap(), roots).unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = accept_quic(incoming).await.unwrap();
            let mut derived = [0u8; 32];
            let mut other = [0u8; 32];
            connection
                .export_keying_material(&mut derived, EXPORTER_LABEL, CONTEXT)
                .unwrap();
            connection
                .export_keying_material(&mut other, EXPORTER_LABEL, b"other context")
                .unwrap();
            done_rx.await.unwrap();
            connection.close(0u32.into(), b"finished");
            (derived, other)
        });
        let connection = connect_quic(&client, remote, "localhost").await.unwrap();
        let mut derived = [0u8; 32];
        let mut other = [0u8; 32];
        connection
            .export_keying_material(&mut derived, EXPORTER_LABEL, CONTEXT)
            .unwrap();
        connection
            .export_keying_material(&mut other, EXPORTER_LABEL, b"other context")
            .unwrap();
        done_tx.send(()).unwrap();
        let (mut server_derived, mut server_other) = server_task.await.unwrap();
        assert_eq!(derived, server_derived);
        assert_eq!(other, server_other);
        assert_ne!(derived, other);
        derived.zeroize();
        other.zeroize();
        server_derived.zeroize();
        server_other.zeroize();
        client.close(0u32.into(), b"done");
    })
    .await
    .expect("test-only QUIC exporter completed within deadline");
}

/// Independently prove that an exporter's existence cannot justify bypassing
/// certificate checks: a peer with a trusted name but a different CA is
/// rejected before any application export or SmartTheia bytes are sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_exporter_is_unavailable_for_untrusted_certificates() {
    timeout(DEADLINE, async {
        let legit = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other_ca = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![legit.cert.der().clone()],
            PrivatePkcs8KeyDer::from(legit.key_pair.serialize_der()).into(),
        )
        .unwrap();
        server_tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_tls));

        let mut roots = RootCertStore::empty();
        roots.add(other_ca.cert.der().clone()).unwrap();
        let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            assert!(
                acceptor.accept(socket).await.is_err(),
                "server should observe TLS failure, not an authenticated session"
            );
        });
        let client = TcpStream::connect(addr).await.unwrap();
        assert!(
            connector
                .connect(ServerName::try_from("localhost").unwrap(), client)
                .await
                .is_err(),
            "untrusted peer must fail before exporter or application handshake"
        );
        server.await.unwrap();
    })
    .await
    .expect("test-only negative handshake completed within deadline");
}
