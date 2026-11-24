//! Native real TLS/QUIC pinned identity and mutually exclusive HTTP routes.
//! No third-party endpoints; each peer uses isolated loopback certificates.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use http::{HeaderValue, Request, StatusCode};
use ring::hmac;
use rustls::{pki_types::PrivatePkcs8KeyDer, RootCertStore};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use theia::{
    client::{ClientError, H2Client},
    config::{self, Config, Inbound, ServerPolicy, Transport, User},
    h3_client::H3Client,
    invite::Invitation,
    protocol::Address,
    reality_identity::PublicIdentity,
    security_profile::{CertificatePin, SecurityMode},
    server::{self, ServerContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const TOKEN: [u8; 32] = [0x42; 32];

struct Fixture {
    h2: SocketAddr,
    h3: SocketAddr,
    roots: RootCertStore,
    pin: CertificatePin,
    other_pin: CertificatePin,
    stream_up: bool,
    identity: Option<PublicIdentity>,
    _servers: JoinSet<Result<(), server::ServerError>>,
}

impl Fixture {
    async fn start(mode: SecurityMode) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = cert.key_pair.serialize_der();
        let pin = CertificatePin::from_der(der.as_ref());
        let other_pin = CertificatePin::from_der(other.cert.der().as_ref());
        let mut roots = RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        // Both leaf identities have valid chain and SAN with these roots;
        // the pin alone distinguishes the two trusted certificates.
        roots.add(other.cert.der().clone()).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivatePkcs8KeyDer::from(key.clone()).into(),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let h2 = tcp.local_addr().unwrap();
        let udp = theia::quic_transport::server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![der],
            PrivatePkcs8KeyDer::from(key).into(),
        )
        .unwrap();
        let h3 = udp.local_addr().unwrap();
        let (identity, reality_key, key_path) = if mode.is_reality() {
            use ring::{rand::SystemRandom, signature::{Ed25519KeyPair, KeyPair}};
            use std::io::Write;
            let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let pair = Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
            let profile = format!("smart-reality-v1:{}", URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()));
            let identity = PublicIdentity::parse_profile(&profile).unwrap();
            let path = std::env::temp_dir().join(format!("theia-reality-{}-{}.der", std::process::id(), URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&path).unwrap();
            file.write_all(der.as_ref()).unwrap();
            drop(file);
            (Some(identity), Some(format!("file:{}", path.display())), Some(path))
        } else {
            (None, None, None)
        };
        let inbound = Inbound {
            id: "test".into(),
            security_mode: mode,
            reality_key,
            allowed_user_ids: vec!["client".into()],
            h2_listen: h2.to_string(),
            quic_listen: h3.to_string(),
            server_name: "localhost".into(),
            tls_cert: "unused".into(),
            tls_key: "unused".into(),
        };
        let user = User {
            id: "client".into(),
            token_sha256: format!("{:x}", Sha256::digest(TOKEN)),
            disabled: false,
        };
        let policy = ServerPolicy {
            allow_private_ips: true,
            max_connections_per_user: 8,
            max_connections_total: 8,
            connect_timeout_ms: 2000,
        };
        let context = Arc::new(ServerContext::new(&inbound, &[user], &policy));
        if let Some(path) = key_path {
            std::fs::remove_file(path).unwrap();
        }
        let mut servers = JoinSet::new();
        servers.spawn(server::serve(
            tcp,
            TlsAcceptor::from(Arc::new(tls)),
            context.clone(),
        ));
        servers.spawn(theia::h3_server::serve(udp, context));
        Self {
            h2,
            h3,
            roots,
            pin,
            other_pin,
            stream_up: mode == SecurityMode::PinnedCertStreamUpV1 || mode.is_reality(),
            identity,
            _servers: servers,
        }
    }

    fn h2(&self, pin: Option<CertificatePin>, name: &str, token: &[u8; 32]) -> H2Client {
        H2Client::new(
            &self.h2.to_string(),
            name,
            &URL_SAFE_NO_PAD.encode(token),
            self.roots.clone(),
        )
        .unwrap()
        .with_certificate_pin(pin)
        .unwrap()
        .with_stream_up(self.stream_up)
        .unwrap()
    }

    fn h3(&self, pin: Option<CertificatePin>, name: &str, token: &[u8; 32]) -> H3Client {
        H3Client::new(
            self.h3,
            name,
            &URL_SAFE_NO_PAD.encode(token),
            self.roots.clone(),
        )
        .unwrap()
        .with_certificate_pin(pin)
        .unwrap()
        .with_stream_up(self.stream_up)
        .unwrap()
    }

    async fn errors(
        &self,
        pin: Option<CertificatePin>,
        name: &str,
        token: &[u8; 32],
        port: u16,
        expected: ClientError,
    ) {
        let address = Address::V4([127, 0, 0, 1]);
        assert_eq!(
            self.h2(pin, name, token)
                .open(address.clone(), port)
                .await
                .err(),
            Some(expected)
        );
        assert_eq!(
            self.h3(pin, name, token).open(address, port).await.err(),
            Some(expected)
        );
    }

    async fn transfer(&self, pin: Option<CertificatePin>, target: &TcpListener) {
        let port = target.local_addr().unwrap().port();
        let address = Address::V4([127, 0, 0, 1]);
        for h3 in [false, true] {
            // Derive the actual runtime mode/pin from the portable invite,
            // not the fixture's original configuration after the roundtrip.
            let Config::Client(doc) =
                config::parse(include_str!("../../../examples/client.toml")).unwrap()
            else {
                panic!("client fixture");
            };
            let mut profile = doc.client.profiles[0].clone();
            profile.server = if h3 { self.h3 } else { self.h2 }.to_string();
            profile.server_name = "localhost".into();
            profile.transport = if h3 { Transport::H3 } else { Transport::H2 };
            profile.tls_profile = pin.map_or_else(
                || "default".into(),
                |pin| {
                    if self.stream_up {
                        pin.stream_up_profile()
                    } else {
                        pin.profile()
                    }
                },
            );
            if let Some(identity) = self.identity {
                profile.tls_profile = identity.profile();
            }
            let invite = Invitation::public_from_profile(&profile)
                .unwrap()
                .encode()
                .unwrap();
            let received = Invitation::decode(&invite)
                .unwrap()
                .to_profile("env:TEST_TOKEN", None)
                .unwrap();
            assert_eq!(received.tls_profile, profile.tls_profile);
            assert_eq!(received.transport, profile.transport);
            let imported_pin = CertificatePin::parse_profile(&received.tls_profile);
            let identity = PublicIdentity::parse_profile(&received.tls_profile);
            let stream_up = identity.is_some() || CertificatePin::is_stream_up_profile(&received.tls_profile);
            let token = URL_SAFE_NO_PAD.encode(TOKEN);
            let (mut app, local) = tokio::io::duplex(4096);
            let relay = if received.transport == Transport::H3 {
                let tunnel = H3Client::new(
                    received.server.parse().unwrap(),
                    &received.server_name,
                    &token,
                    self.roots.clone(),
                )
                .unwrap()
                .with_certificate_pin(imported_pin)
                .unwrap()
                .with_server_identity(identity)
                .unwrap()
                .with_stream_up(stream_up)
                .unwrap()
                .open(address.clone(), port)
                .await
                .unwrap();
                tokio::spawn(tunnel.relay(local))
            } else {
                let tunnel = H2Client::new(
                    &received.server,
                    &received.server_name,
                    &token,
                    self.roots.clone(),
                )
                .unwrap()
                .with_certificate_pin(imported_pin)
                .unwrap()
                .with_server_identity(identity)
                .unwrap()
                .with_stream_up(stream_up)
                .unwrap()
                .open(address.clone(), port)
                .await
                .unwrap();
                tokio::spawn(tunnel.relay(local))
            };
            let (mut remote, _) = target.accept().await.unwrap();
            // Full duplex before either FIN, and payload beyond one flow window.
            let payload: Vec<_> = (0..128 * 1024).map(|n| (n % 251) as u8).collect();
            let mut data = vec![0; payload.len()];
            tokio::try_join!(app.write_all(&payload), remote.read_exact(&mut data)).unwrap();
            assert_eq!(data, payload);
            let mut reply = vec![0; payload.len()];
            tokio::try_join!(remote.write_all(&data), app.read_exact(&mut reply)).unwrap();
            assert_eq!(reply, payload);
            app.shutdown().await.unwrap();
            let mut tail = Vec::new();
            remote.read_to_end(&mut tail).await.unwrap();
            assert!(tail.is_empty());
            remote.shutdown().await.unwrap();
            app.read_to_end(&mut tail).await.unwrap();
            assert!(tail.is_empty());
            relay.await.unwrap().unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_h3_pinned_identity_and_mode_are_fail_closed() {
    timeout(Duration::from_secs(30), async {
        let pinned = Fixture::start(SecurityMode::PinnedCertV1).await;
        let plain = Fixture::start(SecurityMode::Plain).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();

        // Trusted certificate with wrong pin, wrong hostname with right
        // pin, bad bearer, and both directions of mode mismatch.
        pinned
            .errors(
                Some(pinned.other_pin),
                "localhost",
                &TOKEN,
                port,
                ClientError::Tls,
            )
            .await;
        // H3 may categorize an ordinary chain/SAN error as its own
        // transport handshake error; it must not return a usable tunnel.
        assert!(pinned
            .h2(Some(pinned.pin), "wrong.example", &TOKEN)
            .open(Address::V4([127, 0, 0, 1]), port)
            .await
            .is_err());
        assert!(pinned
            .h3(Some(pinned.pin), "wrong.example", &TOKEN)
            .open(Address::V4([127, 0, 0, 1]), port)
            .await
            .is_err());
        pinned
            .errors(
                Some(pinned.pin),
                "localhost",
                &[0x43; 32],
                port,
                ClientError::Unauthorized,
            )
            .await;
        pinned
            .errors(None, "localhost", &TOKEN, port, ClientError::Rejected(404))
            .await;
        plain
            .errors(
                Some(plain.pin),
                "localhost",
                &TOKEN,
                port,
                ClientError::Rejected(404),
            )
            .await;
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());

        pinned.transfer(Some(pinned.pin), &target).await;
        plain.transfer(None, &target).await;
    })
    .await
    .expect("bounded H2/H3 identity and mode matrix");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_h3_stream_up_separate_http_legs_and_identity() {
    timeout(Duration::from_secs(40), async {
        let split = Fixture::start(SecurityMode::PinnedCertStreamUpV1).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        split
            .errors(
                Some(split.other_pin),
                "localhost",
                &TOKEN,
                port,
                ClientError::Tls,
            )
            .await;
        split
            .errors(
                Some(split.pin),
                "localhost",
                &[0x43; 32],
                port,
                ClientError::Unauthorized,
            )
            .await;
        let address = Address::V4([127, 0, 0, 1]);
        let token = URL_SAFE_NO_PAD.encode(TOKEN);
        let legacy = H2Client::new(
            &split.h2.to_string(),
            "localhost",
            &token,
            split.roots.clone(),
        )
        .unwrap()
        .with_certificate_pin(Some(split.pin))
        .unwrap();
        assert_eq!(
            legacy.open(address.clone(), port).await.err(),
            Some(ClientError::Rejected(404))
        );
        let legacy = H3Client::new(split.h3, "localhost", &token, split.roots.clone())
            .unwrap()
            .with_certificate_pin(Some(split.pin))
            .unwrap();
        assert_eq!(
            legacy.open(address, port).await.err(),
            Some(ClientError::Rejected(404))
        );
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        split.transfer(Some(split.pin), &target).await;
    })
    .await
    .expect("bounded real H2/H3 split transport matrix");
}

// Independent wire witness, not a call to the production proof helper.
fn raw_pinned_request(proof: Option<&HeaderValue>) -> Request<()> {
    let mut request = Request::post("https://localhost/v1/pinned-session")
        .header("content-type", "application/octet-stream")
        .header(
            "authorization",
            format!("Bearer {}", URL_SAFE_NO_PAD.encode(TOKEN)),
        )
        .body(())
        .unwrap();
    if let Some(proof) = proof {
        request
            .headers_mut()
            .insert("theia-channel-proof", proof.clone());
    }
    request
}

fn witness(key: &[u8; 32]) -> HeaderValue {
    let request = raw_pinned_request(None);
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut data = b"SmartTheia/XHTTP/admission/v1\0".to_vec();
    for part in [
        b"POST".as_slice(),
        b"/v1/pinned-session".as_slice(),
        request.headers()["authorization"].as_bytes(),
    ] {
        data.extend_from_slice(&(part.len() as u32).to_be_bytes());
        data.extend_from_slice(part);
    }
    let tag = hmac::sign(&signing_key, &data);
    let mut header = HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(tag.as_ref())).unwrap();
    header.set_sensitive(true);
    header
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_exporter_proof_replay_is_refused_on_same_and_fresh_connection() {
    timeout(Duration::from_secs(20), async {
        let fixture = Fixture::start(SecurityMode::PinnedCertV1).await;
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(fixture.roots.clone())
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let mut old = None;
        for _ in 0..2 {
            let socket = tokio::net::TcpStream::connect(fixture.h2).await.unwrap();
            let tls = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    socket,
                )
                .await
                .unwrap();
            let key = zeroize::Zeroizing::new(
                tls.get_ref()
                    .1
                    .export_keying_material(
                        [0u8; 32],
                        b"EXPORTER-SmartTheia-XHTTP-Admission-v1",
                        Some(b"h2"),
                    )
                    .unwrap(),
            );
            let current = witness(&key);
            let (mut sender, connection) = h2::client::handshake(tls).await.unwrap();
            let driver = tokio::spawn(connection);
            for (proof, expected) in [
                (None, StatusCode::UNAUTHORIZED),
                (old.as_ref(), StatusCode::UNAUTHORIZED),
                (Some(&current), StatusCode::OK),
                (Some(&current), StatusCode::UNAUTHORIZED),
            ] {
                sender = sender.ready().await.unwrap();
                let (response, _body) = sender
                    .send_request(raw_pinned_request(proof), true)
                    .unwrap();
                assert_eq!(response.await.unwrap().status(), expected);
            }
            old = Some(current);
            driver.abort();
        }
    })
    .await
    .expect("bounded native H2 exporter admission");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_exporter_proof_replay_is_refused_on_same_and_fresh_connection() {
    timeout(Duration::from_secs(20), async {
        let fixture = Fixture::start(SecurityMode::PinnedCertV1).await;
        let endpoint = theia::quic_transport::client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            fixture.roots.clone(),
        )
        .unwrap();
        let mut old = None;
        for _ in 0..2 {
            let connection = theia::quic_transport::connect(&endpoint, fixture.h3, "localhost")
                .await
                .unwrap();
            let mut key = zeroize::Zeroizing::new([0u8; 32]);
            connection
                .export_keying_material(
                    &mut key[..],
                    b"EXPORTER-SmartTheia-XHTTP-Admission-v1",
                    b"h3",
                )
                .unwrap();
            let current = witness(&key);
            let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            let driver_task = tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });
            for (proof, expected) in [
                (None, StatusCode::UNAUTHORIZED),
                (old.as_ref(), StatusCode::UNAUTHORIZED),
                (Some(&current), StatusCode::OK),
                (Some(&current), StatusCode::UNAUTHORIZED),
            ] {
                let mut stream: h3::client::RequestStream<_, Bytes> = sender
                    .send_request(raw_pinned_request(proof))
                    .await
                    .unwrap();
                // Receiving headers requires no HELLO or OPEN; 200 is only
                // admission. The test never requests an external target.
                assert_eq!(stream.recv_response().await.unwrap().status(), expected);
            }
            old = Some(current);
            driver_task.abort();
        }
    })
    .await
    .expect("bounded native H3 exporter admission");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reality_independent_identity_h2_h3_and_wrong_key_refusal() {
    timeout(Duration::from_secs(40), async {
        let fixture = Fixture::start(SecurityMode::SmartRealityV1).await;
        let other = Fixture::start(SecurityMode::SmartRealityV1).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let address = Address::V4([127, 0, 0, 1]);
        let token = URL_SAFE_NO_PAD.encode(TOKEN);
        let wrong = other.identity.unwrap();
        assert_ne!(Some(wrong), fixture.identity);
        let h2 = H2Client::new(&fixture.h2.to_string(), "localhost", &token, fixture.roots.clone())
            .unwrap().with_server_identity(Some(wrong)).unwrap();
        let h3 = H3Client::new(fixture.h3, "localhost", &token, fixture.roots.clone())
            .unwrap().with_server_identity(Some(wrong)).unwrap();
        assert_eq!(h2.open(address.clone(), port).await.err(), Some(ClientError::Tls));
        assert_eq!(h3.open(address.clone(), port).await.err(), Some(ClientError::Tls));

        // The ordinary pinned stream-up client must not silently enter the
        // independent-identity mode even with valid PKI, pin and bearer.
        let h2 = fixture.h2(Some(fixture.pin), "localhost", &TOKEN);
        let h3 = fixture.h3(Some(fixture.pin), "localhost", &TOKEN);
        assert!(h2.open(address.clone(), port).await.is_err());
        assert!(h3.open(address, port).await.is_err());
        assert!(timeout(Duration::from_millis(250), target.accept()).await.is_err());
        fixture.transfer(None, &target).await;
    }).await.expect("bounded independent identity H2/H3 matrix");
}
