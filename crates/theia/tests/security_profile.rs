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
    silent_h2_hello: Arc<std::sync::atomic::AtomicBool>,
    _servers: JoinSet<Result<(), server::ServerError>>,
}

impl Fixture {
    async fn start(mode: SecurityMode) -> Self {
        Self::start_with_silent_h2(mode, false).await
    }

    async fn start_with_silent_h2(mode: SecurityMode, silent: bool) -> Self {
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
        let inbound = Inbound {
            id: "test".into(),
        path_prefix: Some("/v1/theia-example".into()),
            security_mode: mode,
            reality: None,
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
        let mut servers = JoinSet::new();
        let silent_h2_hello = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let witness = silent_h2_hello.clone();
        let h2_context = context.clone();
        servers.spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(tls));
            if silent {
                // Independently admit stream-one and deliberately hold back
                // HELLO_ACK. Inspect every received frame until cancellation.
                // The production listener takes the next TLS connection.
                let (socket, _) = tcp.accept().await.unwrap();
                let tls = acceptor.accept(socket).await.unwrap();
                let mut connection = h2::server::handshake(tls).await.unwrap();
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                assert_eq!(request.uri().path(), "/v1/theia-example/session");
                let mut body = request.into_body();
                let _outgoing = respond
                    .send_response(
                        http::Response::builder().status(200).body(()).unwrap(),
                        false,
                    )
                    .unwrap();
                let observe = async {
                    let mut decoder = theia::protocol::Decoder::new();
                    let mut seen = false;
                    while let Some(Ok(chunk)) = body.data().await {
                        for frame in decoder.feed(&chunk).unwrap() {
                            assert!(matches!(frame, theia::protocol::Frame::Hello { .. }));
                            assert!(!seen);
                            seen = true;
                        }
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                    }
                    assert!(seen);
                    assert_eq!(decoder.pending_len(), 0);
                };
                let drive = async {
                    assert!(!matches!(connection.accept().await, Some(Ok(_))));
                };
                tokio::join!(observe, drive);
                witness.store(true, std::sync::atomic::Ordering::Release);
            }
            server::serve(tcp, acceptor, h2_context).await
        });
        servers.spawn(theia::h3_server::serve(udp, context));
        Self {
            h2,
            h3,
            roots,
            pin,
            other_pin,
            stream_up: mode == SecurityMode::PinnedCertStreamUpV1,
            silent_h2_hello,
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
            if pin.is_none() {
                profile.xhttp_mode = Some(if self.stream_up {
                    config::XhttpMode::StreamUp
                } else {
                    config::XhttpMode::StreamOne
                });
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
            assert_eq!(
                received.effective_xhttp_mode(),
                profile.effective_xhttp_mode()
            );
            let stream_up = received.effective_xhttp_mode() == config::XhttpMode::StreamUp;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_tls_accepts_both_xhttp_modes_with_identical_grants() {
    timeout(Duration::from_secs(40), async {
        let mut plain = Fixture::start(SecurityMode::Plain).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        plain.transfer(None, &target).await;
        plain.stream_up = true;
        plain
            .errors(
                None,
                "localhost",
                &[0x43; 32],
                port,
                ClientError::Unauthorized,
            )
            .await;
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        plain.transfer(None, &target).await;
    })
    .await
    .expect("own TLS H2/H3 stream-one and stream-up byte-exact matrix");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_tls_h2_auto_retries_silence_only_before_open() {
    timeout(Duration::from_secs(35), async {
        let fixture = Fixture::start_with_silent_h2(SecurityMode::Plain, true).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let client = fixture
            .h2(None, "localhost", &TOKEN)
            .with_auto_stream_up(Duration::from_secs(900))
            .unwrap();
        let tunnel = client
            .open(Address::V4([127, 0, 0, 1]), port)
            .await
            .unwrap();
        let (remote, _) = target.accept().await.unwrap();
        assert!(fixture
            .silent_h2_hello
            .load(std::sync::atomic::Ordering::Acquire));
        drop(tunnel);
        drop(remote);
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
    })
    .await
    .expect("admitted HELLO silence can retry once; first attempt sends no OPEN");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_tls_auto_h2_h3_rejects_auth_and_accepts_normal_stream_one() {
    timeout(Duration::from_secs(30), async {
        let fixture = Fixture::start(SecurityMode::Plain).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let addr = Address::V4([127, 0, 0, 1]);
        let ttl = Duration::from_secs(900);
        let h2 = fixture
            .h2(None, "localhost", &[0x43; 32])
            .with_auto_stream_up(ttl)
            .unwrap();
        let h3 = fixture
            .h3(None, "localhost", &[0x43; 32])
            .with_auto_stream_up(ttl)
            .unwrap();
        assert_eq!(
            h2.open(addr.clone(), port).await.err(),
            Some(ClientError::Unauthorized)
        );
        assert_eq!(
            h3.open(addr.clone(), port).await.err(),
            Some(ClientError::Unauthorized)
        );
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        let h2 = fixture
            .h2(None, "localhost", &TOKEN)
            .with_auto_stream_up(ttl)
            .unwrap();
        let h3 = fixture
            .h3(None, "localhost", &TOKEN)
            .with_auto_stream_up(ttl)
            .unwrap();
        let tunnel = h2.open(addr.clone(), port).await.unwrap();
        let (remote, _) = target.accept().await.unwrap();
        drop(tunnel);
        drop(remote);
        let tunnel = h3.open(addr, port).await.unwrap();
        let (remote, _) = target.accept().await.unwrap();
        drop(tunnel);
        drop(remote);
    })
    .await
    .expect("own TLS auto modes preserve H2/H3 auth and OPEN semantics");
}

// Independent wire witness, not a call to the production proof helper.
fn raw_pinned_request(proof: Option<&HeaderValue>) -> Request<()> {
    let mut request = Request::post("https://localhost/v1/theia-example/session")
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
        b"/v1/theia-example/session".as_slice(),
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
async fn pooled_own_tls_h2_h3_keep_parallel_tunnels_independent() {
    timeout(Duration::from_secs(30), async {
        let fixture = Fixture::start(SecurityMode::Plain).await;
        for split in [false, true] {
            for h3 in [false, true] {
                let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = target.local_addr().unwrap().port();
                let address = Address::V4([127, 0, 0, 1]);
                let token = URL_SAFE_NO_PAD.encode(TOKEN);
                let (mut left, left_local) = tokio::io::duplex(4096);
                let (mut right, right_local) = tokio::io::duplex(4096);
                let (a, b) = if h3 {
                    let client =
                        H3Client::new(fixture.h3, "localhost", &token, fixture.roots.clone())
                            .unwrap()
                            .with_stream_up(split)
                            .unwrap()
                            .with_connection_pool();
                    let a = client.open(address.clone(), port).await.unwrap();
                    let b = client.open(address.clone(), port).await.unwrap();
                    assert!(
                        a.shares_transport_with(&b),
                        "both tunnels must use the same verified carrier"
                    );
                    (
                        tokio::spawn(a.relay(left_local)),
                        tokio::spawn(b.relay(right_local)),
                    )
                } else {
                    let client = H2Client::new(
                        &fixture.h2.to_string(),
                        "localhost",
                        &token,
                        fixture.roots.clone(),
                    )
                    .unwrap()
                    .with_stream_up(split)
                    .unwrap()
                    .with_connection_pool();
                    let a = client.open(address.clone(), port).await.unwrap();
                    let b = client.open(address.clone(), port).await.unwrap();
                    assert!(
                        a.shares_transport_with(&b),
                        "both tunnels must use the same verified carrier"
                    );
                    (
                        tokio::spawn(a.relay(left_local)),
                        tokio::spawn(b.relay(right_local)),
                    )
                };
                let (mut first, _) = target.accept().await.unwrap();
                let (mut second, _) = target.accept().await.unwrap();
                left.write_all(b"left").await.unwrap();
                right.write_all(b"right").await.unwrap();
                let mut l = [0; 4];
                let mut r = [0; 5];
                first.read_exact(&mut l).await.unwrap();
                second.read_exact(&mut r).await.unwrap();
                assert_eq!(&l, b"left");
                assert_eq!(&r, b"right");
                // Dropping one tunnel must not close the other's HTTP driver.
                a.abort();
                let _ = a.await;
                second.write_all(b"alive").await.unwrap();
                right.read_exact(&mut r).await.unwrap();
                assert_eq!(&r, b"alive");
                right.shutdown().await.unwrap();
                second.read_to_end(&mut Vec::new()).await.unwrap();
                second.shutdown().await.unwrap();
                right.read_to_end(&mut Vec::new()).await.unwrap();
                b.await.unwrap().unwrap();
            }
        }
    })
    .await
    .unwrap();
}
