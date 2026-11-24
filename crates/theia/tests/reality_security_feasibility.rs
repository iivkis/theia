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

#[path = "support/f18_research_identity.rs"]
mod f18_identity_lab;

#[test]
fn h3_identity_proof_must_be_signed_for_its_own_branch_not_replayed_from_h2() {
    use f18_identity_lab::{Branch, Failure, ReplayWindow, Transcript};
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let signer = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pinned: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
    // These fixed bytes are *not* the entropy test. This checks that the
    // H3-only branch is encoded and signed separately, not silently treated
    // as an H2 proof. Verified QUIC exporters are exercised below.
    let h2 = Transcript::new(
        Branch::H2,
        "localhost",
        443,
        [1; 32],
        [2; 32],
        [3; 32],
        10_000,
    )
    .unwrap();
    let h3 = Transcript::new(
        Branch::H3,
        "localhost",
        443,
        [1; 32],
        [2; 32],
        [3; 32],
        10_000,
    )
    .unwrap();
    let h2_signature = signer.sign(&h2.encode());
    let h3_signature = signer.sign(&h3.encode());
    let mut replay = ReplayWindow::new(4).unwrap();
    assert_eq!(
        replay.accept(&pinned, &h3, h2_signature.as_ref(), 10_000),
        Err(Failure::InvalidProof)
    );
    assert_eq!(
        replay.accept(&pinned, &h3, h3_signature.as_ref(), 10_000),
        Ok(())
    );
    assert_eq!(
        replay.accept(&pinned, &h3, h3_signature.as_ref(), 10_001),
        Err(Failure::Replay)
    );
}

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

/// M3.5a1 *research* application flight over a real, strictly verified
/// TLS1.3/H2-ALPN channel. This does NOT modify TLS ClientHello, QUIC Initial,
/// the production wire, existing bearer grants or active-probing behavior.
/// Proof/signature and client challenge travel on this private loopback fixture
/// only. The signed transcript contains the actual post-verification exporter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_tls_h2_channel_supports_independent_pinned_ed25519_identity_proof() {
    use f18_identity_lab::{Branch, ReplayWindow, Transcript};
    use ring::{
        rand::{SecureRandom, SystemRandom},
        signature::{Ed25519KeyPair, KeyPair},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    timeout(DEADLINE, async {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pinned: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
        let mut signing_key = pkcs8.as_ref().to_vec();
        let mut client_nonce = [0u8; 32];
        rng.fill(&mut client_nonce).unwrap();

        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let chain = vec![cert.cert.der().clone()];
        let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            chain.clone(),
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        server_tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(socket).await.unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            let mut received_nonce = [0u8; 32];
            tls.read_exact(&mut received_nonce).await.unwrap();
            let mut exporter = tls
                .get_ref()
                .1
                .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(CONTEXT))
                .unwrap();
            let mut server_nonce = [0u8; 32];
            SystemRandom::new().fill(&mut server_nonce).unwrap();
            let transcript = Transcript::new(
                Branch::H2,
                "localhost",
                443,
                received_nonce,
                server_nonce,
                exporter,
                10_000,
            )
            .unwrap();
            let signature = Ed25519KeyPair::from_pkcs8(&signing_key)
                .unwrap()
                .sign(&transcript.encode());
            tls.write_all(&server_nonce).await.unwrap();
            tls.write_all(signature.as_ref()).await.unwrap();
            tls.flush().await.unwrap();
            signing_key.zeroize();
            exporter.zeroize();
        });

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
        let socket = TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), socket)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        tls.write_all(&client_nonce).await.unwrap();
        tls.flush().await.unwrap();
        let mut server_nonce = [0u8; 32];
        let mut signature = [0u8; 64];
        tls.read_exact(&mut server_nonce).await.unwrap();
        tls.read_exact(&mut signature).await.unwrap();
        let mut exporter = tls
            .get_ref()
            .1
            .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(CONTEXT))
            .unwrap();
        let transcript = Transcript::new(
            Branch::H2,
            "localhost",
            443,
            client_nonce,
            server_nonce,
            exporter,
            10_000,
        )
        .unwrap();
        let mut seen = ReplayWindow::new(8).unwrap();
        assert_eq!(
            seen.accept(&pinned, &transcript, &signature, 10_000),
            Ok(())
        );
        assert_eq!(
            seen.accept(&pinned, &transcript, &signature, 10_001),
            Err(f18_identity_lab::Failure::Replay)
        );
        exporter.zeroize();
        signature.zeroize();
        server_task.await.unwrap();
    })
    .await
    .expect("research-only independent TLS exporter identity proof bounded by deadline");
}

/// Two actual verified QUIC connections to the same listener must not share
/// exporter-bound proofs, even when the research replay cache is recreated.
/// This checks channel binding, not persistent or distributed replay storage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_identity_proof_is_bound_to_live_connection_after_cache_reset() {
    use f18_identity_lab::{Branch, Failure, ReplayWindow, Transcript};
    use ring::{
        rand::{SecureRandom, SystemRandom},
        signature::{Ed25519KeyPair, KeyPair},
    };

    timeout(DEADLINE, async {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pinned: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
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

        let mut exporters = [[0u8; 32]; 2];
        for exporter in &mut exporters {
            // A fresh endpoint deliberately avoids session-ticket reuse.
            let mut roots = RootCertStore::empty();
            roots.add(der.clone()).unwrap();
            let client = client_endpoint("127.0.0.1:0".parse().unwrap(), roots).unwrap();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
            let (mut server_exporter, ()) = tokio::join!(
                async {
                    let incoming = server.accept().await.unwrap();
                    let connection = accept_quic(incoming).await.unwrap();
                    let mut derived = [0u8; 32];
                    connection
                        .export_keying_material(&mut derived, EXPORTER_LABEL, CONTEXT)
                        .unwrap();
                    done_rx.await.unwrap();
                    connection.close(0u32.into(), b"finished");
                    derived
                },
                async {
                    let connection = connect_quic(&client, remote, "localhost").await.unwrap();
                    connection
                        .export_keying_material(exporter, EXPORTER_LABEL, CONTEXT)
                        .unwrap();
                    done_tx.send(()).unwrap();
                }
            );
            assert!(*exporter == server_exporter, "peer exporter mismatch");
            server_exporter.zeroize();
            client.close(0u32.into(), b"done");
        }
        assert!(
            exporters[0] != exporters[1],
            "independent verified sessions must have distinct exporters"
        );

        let mut client_nonce = [0u8; 32];
        let mut server_nonce = [0u8; 32];
        rng.fill(&mut client_nonce).unwrap();
        rng.fill(&mut server_nonce).unwrap();
        let mut original = Transcript::new(
            Branch::H3,
            "localhost",
            remote.port(),
            client_nonce,
            server_nonce,
            exporters[0],
            10_000,
        )
        .unwrap();
        let original_signature = signer.sign(&original.encode());
        let mut seen = ReplayWindow::new(1).unwrap();
        assert_eq!(
            seen.accept(&pinned, &original, original_signature.as_ref(), 10_000),
            Ok(())
        );
        assert_eq!(
            seen.accept(&pinned, &original, original_signature.as_ref(), 10_001),
            Err(Failure::Replay)
        );

        // Keep every other signed field identical to isolate the channel
        // binding. The verifier uses the new connection's local exporter,
        // not a value supplied by an untrusted peer.
        let mut rebound = original.clone();
        rebound.exporter = exporters[1];
        let mut reset = ReplayWindow::new(1).unwrap();
        assert_eq!(
            reset.accept(&pinned, &rebound, original_signature.as_ref(), 10_001),
            Err(Failure::InvalidProof)
        );
        // An invalid proof must not consume the sole replay-cache slot.
        let new_signature = signer.sign(&rebound.encode());
        assert_eq!(
            reset.accept(&pinned, &rebound, new_signature.as_ref(), 10_001),
            Ok(())
        );
        assert_eq!(
            reset.accept(&pinned, &rebound, new_signature.as_ref(), 10_002),
            Err(Failure::Replay)
        );
        original.exporter.zeroize();
        rebound.exporter.zeroize();
        exporters.zeroize();
        client_nonce.zeroize();
        server_nonce.zeroize();
        server.close(0u32.into(), b"done");
    })
    .await
    .expect("research-only reconnect proof completed within deadline");
}
