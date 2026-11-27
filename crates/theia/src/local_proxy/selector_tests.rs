#![cfg(test)]

use super::*;

#[cfg(test)]
async fn udp_revoked_fallback_fixture(client: &ProxyClient) {
    use crate::udp_relay::{self, Tunnel, QUEUE};
    use tokio::sync::mpsc;
    let local_origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let verified = crate::routing::dpi::VerifiedUdp::disabled_fixture(
        udp_relay::connect(local_origin.local_addr().unwrap())
            .await
            .unwrap(),
    );
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let authorization = verified.fallback_policy();
    let ProxyClient::Direct(client) = client else {
        panic!("own TLS fixture");
    };
    let carrier = client.carrier.clone();
    let fallback = Box::pin(async move {
        // A successful OPEN is insufficient if the local routing lease
        // was revoked before the application datagram could be sent.
        let tunnel = carrier.open_udp(Address::V4([127, 0, 0, 1]), port).await?;
        authorization.revoke_fixture();
        Ok(tunnel)
    });
    let (up, rx) = mpsc::channel(QUEUE);
    let (down, _responses) = mpsc::channel(QUEUE);
    up.send(b"must not escape".to_vec()).await.unwrap();
    let result = timeout(
        Duration::from_secs(5),
        Tunnel::VerifiedLocal(Box::new(verified), fallback).relay(rx, down),
    )
    .await
    .unwrap();
    assert!(matches!(
        result,
        Err(ClientError::Open(ErrorCode::PolicyDenied))
    ));
    let mut buf = [0; 32];
    assert!(
        timeout(Duration::from_millis(50), local_origin.recv_from(&mut buf))
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(50), target.recv_from(&mut buf))
            .await
            .is_err()
    );
}

#[cfg(test)]
async fn udp_prewrite_fallback_fixture(client: &ProxyClient) {
    use crate::udp_relay::{self, Tunnel, QUEUE};
    use tokio::sync::mpsc;
    let local_origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let verified = crate::routing::dpi::VerifiedUdp::disabled_fixture(
        udp_relay::connect(local_origin.local_addr().unwrap())
            .await
            .unwrap(),
    );
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let ProxyClient::Direct(client) = client else {
        panic!("own TLS fixture");
    };
    let carrier = client.carrier.clone();
    let fallback =
        Box::pin(async move { carrier.open_udp(Address::V4([127, 0, 0, 1]), port).await });
    let (up, rx) = mpsc::channel(QUEUE);
    let (down, mut responses) = mpsc::channel(QUEUE);
    up.send(b"first".to_vec()).await.unwrap();
    up.send(Vec::new()).await.unwrap();
    let task = tokio::spawn(Tunnel::VerifiedLocal(Box::new(verified), fallback).relay(rx, down));
    let mut buf = [0; 32];
    for data in [b"first".as_slice(), b"".as_slice()] {
        let (n, source) = timeout(Duration::from_secs(3), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], data);
        target.send_to(data, source).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), responses.recv())
                .await
                .unwrap()
                .unwrap(),
            data
        );
    }
    assert!(
        timeout(Duration::from_millis(50), local_origin.recv_from(&mut buf))
            .await
            .is_err()
    );
    drop(up);
    task.await.unwrap().unwrap();
}

#[cfg(test)]
async fn udp_socks_fixture(client: &ProxyClient) {
    use crate::udp_relay::{encode_socks, parse_socks};
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    // Keep the UDP client endpoint alive until the SOCKS control session
    // closes. Dropping it with pending QUIC replies can generate an ICMP
    // port-unreachable and a Winsock UDP reset on the proxy socket.
    let app = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let app_port = app.local_addr().unwrap().port();
    let (mut control, local) = paired().await;
    let client = (*client).clone();
    assert!(matches!(
        client
            .open_udp(
                Address::Dns("blocked.invalid".into()),
                443,
                &crate::routing::dpi::udp::Candidate::Other,
                b"",
            )
            .await,
        Err(ClientError::Open(ErrorCode::PolicyDenied))
    ));
    let task = tokio::spawn(async move { handle(local, false, &client, 1).await });
    let mut greeting = vec![5, 1, 0, 5, 3, 0, 1, 127, 0, 0, 1];
    greeting.extend(app_port.to_be_bytes());
    control.write_all(&greeting).await.unwrap();
    let mut reply = [0; 12];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..6], &[5, 0, 5, 0, 0, 1]);
    let relay = SocketAddr::from((
        [reply[6], reply[7], reply[8], reply[9]],
        u16::from_be_bytes([reply[10], reply[11]]),
    ));
    let address = Address::V4([127, 0, 0, 1]);
    let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    attacker
        .send_to(
            &encode_socks(&address, port, b"wrong source").unwrap(),
            relay,
        )
        .await
        .unwrap();
    let mut buf = vec![0; 65536];
    assert!(
        timeout(Duration::from_millis(40), target.recv_from(&mut buf))
            .await
            .is_err()
    );
    let mut stun = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    stun.extend([7; 12]);
    let hello = crate::routing::dpi::test_hello();
    let quic = crate::reality_quic_wire::test_initial(crate::reality_quic_wire::V1, &hello[5..]);
    for (index, data) in [stun, quic, vec![], b"last".to_vec()]
        .into_iter()
        .enumerate()
    {
        let packet = encode_socks(&address, port, &data).unwrap();
        app.send_to(&packet, relay).await.unwrap();
        let (n, peer) = timeout(Duration::from_secs(3), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], data);
        let response = if index == 0 {
            // Minimal Binding success with the observed VPS source.
            let mut response = data.clone();
            response[0] = 1;
            response[3] = 12;
            response.extend([0, 0x20, 0, 8, 0, 1]);
            response.extend((peer.port() ^ 0x2112).to_be_bytes());
            let IpAddr::V4(ip) = peer.ip() else {
                panic!("fixture IPv4")
            };
            response.extend(
                ip.octets()
                    .into_iter()
                    .zip([0x21, 0x12, 0xa4, 0x42])
                    .map(|(a, b)| a ^ b),
            );
            response
        } else {
            data
        };
        target.send_to(&response, peer).await.unwrap();
        let (n, source) = timeout(Duration::from_secs(3), app.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, relay);
        assert_eq!(
            parse_socks(&buf[..n]),
            Some((address.clone(), port, response.as_slice()))
        );
    }
    udp_quic_fixture(app.clone(), relay).await;
    control.shutdown().await.unwrap();
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[cfg(test)]
async fn udp_quic_fixture(app: Arc<tokio::net::UdpSocket>, relay: SocketAddr) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let origin = crate::quinn_reference::server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        vec![der],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
    )
    .unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let endpoint =
        crate::quinn_reference::client_endpoint("127.0.0.1:0".parse().unwrap(), roots).unwrap();
    let client_addr = endpoint.local_addr().unwrap();
    let bridge_addr = app.local_addr().unwrap();
    let bridge = tokio::spawn(async move {
        let target = Address::V4([127, 0, 0, 1]);
        let mut buf = vec![0; 65536];
        loop {
            let (n, source) = app.recv_from(&mut buf).await.unwrap();
            if source == client_addr {
                if let Some(wire) = crate::udp_relay::encode_socks(&target, origin_port, &buf[..n])
                {
                    app.send_to(&wire, relay).await.unwrap();
                }
            } else if source == relay {
                if let Some((address, port, data)) = crate::udp_relay::parse_socks(&buf[..n]) {
                    if address == target && port == origin_port {
                        app.send_to(data, client_addr).await.unwrap();
                    }
                }
            }
        }
    });
    let server = async {
        let connection = crate::quinn_reference::accept(origin.accept().await.unwrap())
            .await
            .unwrap();
        let (mut tx, mut rx) = connection.accept_bi().await.unwrap();
        let bytes = rx.read_to_end(64).await.unwrap();
        assert_eq!(bytes, b"nested quic");
        tx.write_all(&bytes).await.unwrap();
        tx.finish().unwrap();
        connection
    };
    let client = async {
        let connection = crate::quinn_reference::connect(&endpoint, bridge_addr, "localhost")
            .await
            .unwrap();
        let (mut tx, mut rx) = connection.open_bi().await.unwrap();
        tx.write_all(b"nested quic").await.unwrap();
        tx.finish().unwrap();
        assert_eq!(rx.read_to_end(64).await.unwrap(), b"nested quic");
        connection
    };
    let (_server, _client) = timeout(Duration::from_secs(10), async {
        tokio::join!(server, client)
    })
    .await
    .unwrap();
    bridge.abort();
    let _ = bridge.await;
}

// The public-address reference evidence is synthetic and deliberately
// not used by the admitted test branch. All application I/O is loopback;
// this does not assert external reference parity.
// Match the production runtime's bounded stack reserve for the large
// multi-carrier integration fixtures, including the thread doing block_on.
fn run_proxy_fixture<F, Fut>(make: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()>,
{
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(8 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(make()));
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn registered_reality_live_rotation_keeps_native_connect_and_socks5_open() {
    run_proxy_fixture(|| registered_reality_scenario(false));
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
fn registered_reality_production_drain_preserves_h2_h3_both_xhttp_modes() {
    run_proxy_fixture(|| registered_reality_scenario(true));
}

async fn registered_reality_scenario(drain_only: bool) {
    use crate::{
        descriptor::ClientPolicy,
        reality_bootstrap as bootstrap,
        reality_config::{self, ClientRequest, Request, ServerRequest},
        reality_generation::Manager,
        reference_health::{self, Evidence, Plan, State, Store, Target},
    };
    use sha2::{Digest, Sha256};
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let dir = Scratch(std::env::temp_dir().join(format!(
        "theia-reality-native-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )));
    std::fs::create_dir(&dir.0).unwrap();
    timeout(Duration::from_secs(59), async {
        let reservations = crate::shared_port::reserve_shared_port();
        let remote = reservations.0.local_addr().unwrap();
        let now = reference_health::unix_now()
            .unwrap()
            .saturating_sub(if drain_only { 0 } else { 3700 });
        let state = State::new(
            Plan {
                schema_version: 1,
                inbound: "reality-native".into(),
                endpoint: remote.to_string(),
                own_ips: vec![remote.ip()],
                references: vec![
                    Target {
                        server_name: "ref.example.org".into(),
                        address: "93.184.216.2:443".parse().unwrap(),
                    },
                    Target {
                        server_name: "reserve.example.org".into(),
                        address: "93.184.216.3:443".parse().unwrap(),
                    },
                ],
            },
            vec![
                Evidence {
                    h2_status: Some(200),
                    h3_status: Some(200)
                };
                2
            ],
            now,
        )
        .unwrap();
        let health = dir.0.join("health.toml");
        Store::new(&health).unwrap().enroll(&state).unwrap();
        let bundle = dir.0.join("bundle");
        let digest = state.snapshot_sha256().unwrap();
        let record = crate::reality_provision::create(&state, digest, &bundle, now).unwrap();
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        let initial_publication = std::fs::read(bundle.join("publication.toml")).unwrap();
        let token = [42u8; 32];
        let server_path = dir.0.join("server.toml");
        let source = include_str!("../../../../examples/server.toml").replace(
            "REPLACE_WITH_64_LOWERCASE_HEX",
            &format!("{:x}", Sha256::digest(token)),
        );
        std::fs::write(&server_path, source).unwrap();
        let request = Request::Server(ServerRequest {
            health: health.clone(),
            bundle: bundle.clone(),
            health_sha256: digest,
            identity_sha256: record.identity_sha256,
            listen: remote,
            grants: vec!["device-a".into()],
        });
        let preview = reality_config::prepare(&server_path, &request, now).unwrap();
        reality_config::apply(&server_path, &request, preview.approval_sha256(), now).unwrap();
        let Config::Server(mut server_doc) = config::read_file(&server_path).unwrap() else {
            panic!()
        };
        // The template own-TLS inbound has placeholder PEM paths.
        // Test the registered REALITY branch, not an invalid template.
        server_doc
            .server
            .inbounds
            .retain(|i| i.id == "reality-native");
        server_doc.server.policy.allow_private_ips = true;
        let config = Config::Server(server_doc.clone());
        let lease = Manager::new(&config, "reality-native", now)
            .unwrap()
            .refresh(now)
            .unwrap();
        let material = lease.publication().active();
        let old_signer = material.verified().signer();
        let successor =
            crate::identity_tls::Identity::generate(material.identity().scope().clone()).unwrap();
        let successor_path = dir.0.join("successor.key");
        successor.save_new(&successor_path).unwrap();
        let invite =
            bootstrap::Invitation::public(material.identity(), material.signed(), now).unwrap();
        let uri = invite.encode().unwrap();
        let client_path = dir.0.join("client.toml");
        let mut bearer = crate::client_import::PrivateBearer::create(&client_path, &token).unwrap();
        let reference = bearer.reference().unwrap();
        bearer.commit();
        std::fs::write(
            &client_path,
            include_str!("../../../../examples/client.toml"),
        )
        .unwrap();
        for (id, transport, mode) in [
            ("native-h2", Transport::H2, XhttpMode::StreamOne),
            ("native-h3", Transport::H3, XhttpMode::StreamOne),
            ("split-h2", Transport::H2, XhttpMode::StreamUp),
            ("split-h3", Transport::H3, XhttpMode::StreamUp),
        ] {
            // Stream-up profiles remain offline during the live rotation.
            let enrollment = dir.0.join(format!("{id}.toml"));
            let trust = dir.0.join(format!("{id}-trust.toml"));
            bootstrap::import(
                &uri,
                bootstrap::ImportApproval {
                    document_sha256: bootstrap::digest(&uri),
                    identity_sha256: invite.fingerprint(),
                },
                &enrollment,
                &trust,
                bootstrap::EnrollmentMaterial {
                    admission_path: &bundle.join("admission.key"),
                    expected_admission: None,
                    external_token: Some(&reference),
                },
                ClientPolicy {
                    transport,
                    xhttp_mode: mode,
                },
                now,
            )
            .unwrap();
            let request = Request::Client(ClientRequest {
                enrollment,
                identity_sha256: invite.fingerprint(),
                id: id.into(),
            });
            let preview = reality_config::prepare(&client_path, &request, now).unwrap();
            reality_config::apply(&client_path, &request, preview.approval_sha256(), now).unwrap();
        }
        // A single signed snapshot is the source of both native carriers.
        drop(lease);
        // Production listener preparation binds both protocols itself.
        // Keep the fixture reservation through all preceding file work.
        drop(reservations);
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        if drain_only {
            let (started, ready) = tokio::sync::oneshot::channel();
            let (drain, stop) = tokio::sync::oneshot::channel();
            let (draining, acknowledged) = tokio::sync::oneshot::channel();
            let mut server = JoinSet::new();
            server.spawn(crate::server::registered_reality_drain_fixture(
                server_doc, started, stop, draining,
            ));
            ready.await.unwrap();
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_port = target.local_addr().unwrap().port();
            let Config::Client(client_doc) = config::read_file(&client_path).unwrap() else {
                panic!("client fixture");
            };
            let mut clients = Vec::new();
            let mut apps = Vec::new();
            let mut relays = JoinSet::new();
            let mut echoes = JoinSet::new();
            let address = Address::V4([127, 0, 0, 1]);
            async fn exchange(app: &mut TcpStream, data: &[u8]) {
                app.write_all(data).await.unwrap();
                let mut got = vec![0; data.len()];
                app.read_exact(&mut got).await.unwrap();
                assert_eq!(got, data);
            }
            for id in ["native-h2", "native-h3", "split-h2", "split-h3"] {
                let profile = client_doc
                    .client
                    .profiles
                    .iter()
                    .find(|p| p.id == id)
                    .unwrap();
                let client = load_client(profile).await.unwrap();
                // Real marker/identity admission and OPEN_OK through the
                // registered production TCP/UDP listeners.
                let tunnel = client.open(address.clone(), target_port).await.unwrap();
                let (mut upstream, _) = target.accept().await.unwrap();
                echoes.spawn(async move {
                    let (mut read, mut write) = upstream.split();
                    tokio::io::copy(&mut read, &mut write).await.unwrap();
                    write.shutdown().await.unwrap();
                });
                let (mut app, local) = paired().await;
                relays.spawn(tunnel.relay(local));
                exchange(&mut app, id.as_bytes()).await;
                clients.push(client);
                apps.push(app);
            }
            drain.send(()).unwrap();
            acknowledged.await.unwrap();
            for app in &mut apps {
                exchange(app, b"old OPEN_OK tunnel after drain").await;
            }
            // Exercise all four modes concurrently within the production
            // drain deadline. No new upstream dial is permitted.
            let mut refusals = JoinSet::new();
            for client in clients {
                let address = address.clone();
                refusals.spawn(async move {
                    let refusal =
                        timeout(Duration::from_secs(5), client.open(address, target_port)).await;
                    assert!(matches!(refusal, Ok(Err(_))));
                });
            }
            while let Some(result) = refusals.join_next().await {
                result.unwrap();
            }
            assert!(timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err());
            for mut app in apps {
                exchange(&mut app, b"still alive after refused admission").await;
                app.shutdown().await.unwrap();
                let mut tail = Vec::new();
                app.read_to_end(&mut tail).await.unwrap();
                assert!(tail.is_empty());
            }
            while let Some(result) = relays.join_next().await {
                result.unwrap().unwrap();
            }
            while let Some(result) = echoes.join_next().await {
                result.unwrap();
            }
            server.join_next().await.unwrap().unwrap().unwrap();
            // The supervisor has released both sockets after drain.
            let tcp = TcpListener::bind(remote).await.unwrap();
            let udp = tokio::net::UdpSocket::bind(remote).await.unwrap();
            drop((tcp, udp));
            return;
        }
        let (started, ready) = tokio::sync::oneshot::channel();
        let mut server = JoinSet::new();
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        let (drain, stop) = tokio::sync::oneshot::channel();
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        let (draining, acknowledged) = tokio::sync::oneshot::channel();
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        server.spawn(crate::server::registered_reality_drain_fixture(
            server_doc.clone(),
            started,
            stop,
            draining,
        ));
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        server.spawn(crate::server::run_reality_document_with_ready(
            server_doc,
            Some(started),
        ));
        ready.await.unwrap();
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let mut echo_tasks = JoinSet::new();
        echo_tasks.spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                let (mut stream, _) = echo.accept().await.unwrap();
                sessions.spawn(async move {
                    let mut bytes = [0; 4];
                    while stream.read_exact(&mut bytes).await.is_ok() {
                        stream.write_all(&bytes).await.unwrap();
                    }
                });
            }
        });
        let Config::Client(mut client_doc) = config::read_file(&client_path).unwrap() else {
            panic!()
        };
        let mut established = Vec::new();
        let mut proxies = Vec::new();
        let mut managed_clients = Vec::new();
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        let mut headless = None;
        for (id, socks_mode) in [("native-h2", false), ("native-h3", true)] {
            client_doc.client.active_profile = id.into();
            let profile = client_doc
                .client
                .profiles
                .iter()
                .find(|p| p.id == id)
                .unwrap();
            let client = load_client(profile).await.unwrap();
            let ProxyClient::Reality(managed) = &client else {
                panic!("wrong security mode")
            };
            let current = managed.generation().await.unwrap();
            let report = managed.runtime_report().await;
            assert!(report.contains("Сохранённое доверие: совпадает"));
            assert!(report.contains(
                "последнее подтверждённое соединение: пока нет подтверждённого соединения"
            ));
            assert!(report.contains(if socks_mode {
                "Режим передачи: h3"
            } else {
                "Режим передачи: h2"
            }));
            managed_clients.push(managed.clone());
            if let Carrier::H3(h3) = &current.carrier {
                // Use the production dispatcher and a real OPEN_OK
                // tunnel. Rebind the same Quinn endpoint, not a new
                // connection or a new admission handshake.
                let tunnel = h3
                    .open(crate::protocol::Address::V4([127, 0, 0, 1]), target.port())
                    .await
                    .unwrap();
                let (mut local, remote) = tokio::io::duplex(4096);
                let rebind = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                rebind.set_nonblocking(true).unwrap();
                tunnel.rebind_for_test(rebind).await.unwrap();
                let task = tokio::spawn(tunnel.relay(remote));
                local.write_all(b"move").await.unwrap();
                let mut bytes = [0; 4];
                timeout(Duration::from_secs(10), local.read_exact(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&bytes, b"move");
                local.write_all(b"stay").await.unwrap();
                timeout(Duration::from_secs(10), local.read_exact(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&bytes, b"stay");
                drop(local);
                task.abort();
                let _ = task.await;
            }
            assert!(matches!(
                (&current.carrier, socks_mode),
                (Carrier::H2(_), false) | (Carrier::H3(_), true)
            ));
            let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listen = if socks_mode {
                socks.local_addr().unwrap()
            } else {
                http.local_addr().unwrap()
            };
            let mut proxy = JoinSet::new();
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            if !socks_mode {
                let raw = Config::Client(client_doc.clone()).to_toml().unwrap();
                std::fs::write(&client_path, &raw).unwrap();
                let digest = Sha256::digest(raw.as_bytes()).into();
                let runtime =
                    ClientRuntime::new(client_path.clone(), client_doc.clone(), digest, client);
                headless = Some((runtime.clone(), listen));
                proxy.spawn(serve_managed_proxy(http, socks, runtime));
            } else {
                proxy.spawn(serve_proxy(http, socks, client));
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            proxy.spawn(serve_proxy(http, socks, client));
            let mut stream = TcpStream::connect(listen).await.unwrap();
            if socks_mode {
                stream.write_all(&[5, 1, 0]).await.unwrap();
                let mut response = [0; 2];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(response, [5, 0]);
                let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
                request.extend_from_slice(&target.port().to_be_bytes());
                stream.write_all(&request).await.unwrap();
                let mut response = [0; 10];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(&response[..2], &[5, 0]);
            } else {
                stream
                    .write_all(
                        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                let mut response = vec![0; HTTP_OK.len()];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(response, HTTP_OK);
            }
            stream.write_all(b"ping").await.unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            let report = managed_clients.last().unwrap().runtime_report().await;
            assert!(report.contains(if socks_mode {
                "последнее подтверждённое соединение: H3"
            } else {
                "последнее подтверждённое соединение: H2"
            }));
            established.push(stream);
            proxies.push(proxy);
        }
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            use crate::management::{StatusCommand as C, StatusReply as R};
            async fn ipc(
                runtime: Arc<ClientRuntime>,
                command: C,
            ) -> Result<R, crate::management::ManagementError> {
                let (caller, handler) = tokio::io::duplex(1024);
                let task = tokio::spawn(crate::management::handle_client(handler, runtime));
                let result = crate::management::exchange(caller, command).await;
                task.await.unwrap().unwrap();
                result
            }
            let (runtime, listen) = headless.unwrap();
            let raw = Config::Client(client_doc.clone()).to_toml().unwrap();
            std::fs::write(&client_path, &raw).unwrap();
            let digest: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
            assert!(ipc(
                runtime.clone(),
                C::ClientApply {
                    expected_revision: 1,
                    candidate_sha256: [0; 32]
                }
            )
            .await
            .is_err());
            assert_eq!(
                ipc(
                    runtime.clone(),
                    C::ClientPreview {
                        expected_revision: 1,
                        candidate_sha256: digest
                    }
                )
                .await
                .unwrap(),
                R::ClientReady { revision: 1 }
            );
            assert_eq!(runtime.status().await.0, 1);
            assert_eq!(
                ipc(
                    runtime.clone(),
                    C::ClientApply {
                        expected_revision: 1,
                        candidate_sha256: digest
                    }
                )
                .await
                .unwrap(),
                R::ClientApplied { revision: 2 }
            );
            assert!(ipc(
                runtime.clone(),
                C::ClientApply {
                    expected_revision: 1,
                    candidate_sha256: digest
                }
            )
            .await
            .is_err());
            let mut stream = TcpStream::connect(listen).await.unwrap();
            stream
                .write_all(
                    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut response = vec![0; HTTP_OK.len()];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, HTTP_OK);
            stream.write_all(b"swap").await.unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"swap");
            assert!(matches!(
                ipc(runtime.clone(), C::ClientStatus).await.unwrap(),
                R::ClientRunning {
                    revision: 2,
                    transport: 3,
                    ..
                }
            ));
            // Profile switch retires old local policy leases, including
            // idle established flows; server auth-only Apply is separate.
            let mut old = [0; 1];
            assert!(matches!(
                timeout(Duration::from_secs(3), established[0].read(&mut old)).await,
                Ok(Ok(0) | Err(_))
            ));
            assert!(matches!(
                managed_clients[0]
                    .open(Address::V4([127, 0, 0, 1]), target.port())
                    .await,
                Err(ClientError::Open(ErrorCode::PolicyDenied))
            ));
            // Exercise signer rotation on a fresh independent H2 owner
            // instead of asking the retired runtime to admit new flows.
            let h2_profile = client_doc
                .client
                .profiles
                .iter()
                .find(|profile| profile.id == "native-h2")
                .unwrap();
            let ProxyClient::Reality(fresh_h2) = load_client(h2_profile).await.unwrap() else {
                panic!("wrong security mode");
            };
            // Open a separate H2 flow under a fresh independent runtime
            // so the subsequent H2/H3 rotation regression remains intact.
            let (http, socks) = (
                TcpListener::bind("127.0.0.1:0").await.unwrap(),
                TcpListener::bind("127.0.0.1:0").await.unwrap(),
            );
            let address = http.local_addr().unwrap();
            proxies[0].spawn(serve_proxy(
                http,
                socks,
                ProxyClient::Reality(fresh_h2.clone()),
            ));
            let mut fresh_stream = TcpStream::connect(address).await.unwrap();
            fresh_stream
                .write_all(
                    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut reply = vec![0; HTTP_OK.len()];
            fresh_stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, HTTP_OK);
            established[0] = fresh_stream;
            managed_clients[0] = fresh_h2;
            for stream in &mut established {
                stream.write_all(b"keep").await.unwrap();
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"keep");
            }
        }
        let publication =
            crate::identity_publication::Publication::new(&bundle.join("publication.toml"))
                .unwrap();
        let now = reference_health::unix_now().unwrap();
        let store = Store::new(&health).unwrap();
        let good = Evidence {
            h2_status: Some(200),
            h3_status: Some(200),
        };
        store
            .fixture_record(vec![Evidence::default(), good], now - 301)
            .unwrap();
        store
            .fixture_record(vec![Evidence::default(), good], now - 1)
            .unwrap();
        // The maintenance worker, not the test, performs the failover.
        // Both clients retain the original signed SNI until refresh.
        for managed in &managed_clients {
            for _ in 0..20 {
                let generation = managed.generation().await.unwrap();
                if generation.value.descriptor().active_reference == 1 {
                    break;
                }
                let _ = managed.refresh(&generation).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            assert_eq!(
                managed
                    .generation()
                    .await
                    .unwrap()
                    .value
                    .descriptor()
                    .active_reference,
                1
            );
        }
        for stream in &mut established {
            stream.write_all(b"fail").await.unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"fail");
        }
        let now = reference_health::unix_now().unwrap();
        let status = publication.inspect(now).unwrap();
        assert_eq!(status.active_reference, 1);
        publication
            .begin_rotation(
                &successor_path,
                status.snapshot_sha256,
                bootstrap::fingerprint(successor.public_key()),
                now,
            )
            .unwrap();
        for managed in &managed_clients {
            // Wait for the owner-scoped live publication poll, then
            // explicitly drive the same authenticated promotion path
            // that the background client worker uses.
            for _ in 0..20 {
                let generation = managed.generation().await.unwrap();
                if generation.value.signer() == successor.public_key() {
                    break;
                }
                assert_eq!(generation.value.signer(), old_signer);
                let _ = managed.refresh(&generation).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let new = managed.generation().await.unwrap();
            assert_eq!(new.value.signer(), successor.public_key());
            // An actual new tunnel must complete on the new signer.
            let tunnel = managed
                .open(Address::V4([127, 0, 0, 1]), target.port())
                .await
                .unwrap();
            drop(tunnel);
        }
        // Both already-established application tunnels still carry
        // bytes after the two transport pools have changed identity.
        for mut stream in established {
            stream.write_all(b"pong").await.unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"pong");
        }
        for mut proxy in proxies {
            proxy.shutdown().await;
        }
        drop(managed_clients);
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        server.shutdown().await;
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            drain.send(()).unwrap();
            acknowledged.await.unwrap();
            server.join_next().await.unwrap().unwrap().unwrap();
            // A fresh supervisor must reject a previously valid but
            // superseded publication, even after the old process exits.
            let path = bundle.join("publication.toml");
            let latest = std::fs::read(&path).unwrap();
            assert_ne!(initial_publication, latest);
            std::fs::write(&path, &initial_publication).unwrap();
            let (started, _ready) = tokio::sync::oneshot::channel();
            let (_drain, stop) = tokio::sync::oneshot::channel();
            let (draining, _acknowledged) = tokio::sync::oneshot::channel();
            let rejected = timeout(
                Duration::from_secs(3),
                crate::server::registered_reality_drain_fixture(
                    server_doc.clone(),
                    started,
                    stop,
                    draining,
                ),
            )
            .await;
            std::fs::write(&path, latest).unwrap();
            assert!(matches!(
                rejected,
                Ok(Err(crate::server::ServerError::Config))
            ));

            // Restart using the exact durable health and publication
            // state. The two unopened profiles still pin revision 1.
            let (started, ready) = tokio::sync::oneshot::channel();
            let (drain, stop) = tokio::sync::oneshot::channel();
            let (draining, acknowledged) = tokio::sync::oneshot::channel();
            server.spawn(crate::server::registered_reality_drain_fixture(
                server_doc, started, stop, draining,
            ));
            ready.await.unwrap();
            for id in ["split-h2", "split-h3"] {
                let profile = client_doc
                    .client
                    .profiles
                    .iter()
                    .find(|profile| profile.id == id)
                    .unwrap();
                let client = load_client(profile).await.unwrap();
                let ProxyClient::Reality(managed) = &client else {
                    panic!("wrong security mode");
                };
                let old = managed.generation().await.unwrap();
                assert_eq!(old.value.descriptor().revision, 1);
                assert_eq!(old.value.descriptor().active_reference, 0);
                assert_eq!(old.value.signer(), old_signer);
                // Authenticate the old signer, fetch the latest
                // announcement and verify successor TLS before CAS.
                managed.refresh(&old).await.unwrap();
                let current = managed.generation().await.unwrap();
                assert_eq!(current.value.signer(), successor.public_key());
                assert_eq!(current.value.descriptor().active_reference, 1);
                assert!(current.value.descriptor().revision > 1);
                let tunnel = client
                    .open(Address::V4([127, 0, 0, 1]), target.port())
                    .await
                    .unwrap();
                let (mut app, local) = paired().await;
                let relay = tokio::spawn(tunnel.relay(local));
                app.write_all(b"back").await.unwrap();
                let mut bytes = [0; 4];
                app.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"back");
                app.shutdown().await.unwrap();
                let mut tail = Vec::new();
                app.read_to_end(&mut tail).await.unwrap();
                assert!(tail.is_empty());
                relay.await.unwrap().unwrap();
            }
            drain.send(()).unwrap();
            acknowledged.await.unwrap();
            server.join_next().await.unwrap().unwrap().unwrap();
        }
        echo_tasks.shutdown().await;
    })
    .await
    .unwrap();
}

#[test]
fn runtime_file_reference_refuses_non_native_or_oversized_input() {
    use std::fs;

    let name = format!("theia-runtime-input-{}", std::process::id());
    let path = std::env::temp_dir().join(name);
    fs::write(&path, [b'x'; 44]).unwrap();
    let reference = format!("file:{}", path.display());
    assert!(load_file(&reference, 43, true).is_err());
    assert!(load_file("file:relative-token", 43, true).is_err());
    assert!(load_file("https://example.invalid/ca", CA_LIMIT, false).is_err());
    #[cfg(windows)]
    assert!(load_file(r"file:\\server\share\token", 43, true).is_err());
    fs::remove_file(path).unwrap();
}

#[test]
fn negative_cache_expires_and_zero_ttl_disables_it() {
    let mut cache = NegativeCache::default();
    let route = Some("192.0.2.1:0".parse().unwrap());
    let now = Instant::now();
    let ttl = Duration::from_secs(5);
    let (generation, cached) = cache.observe(route, now);
    assert!(!cached);
    assert!(cache.record(generation, now, ttl));
    assert!(cache.observe(route, now + Duration::from_secs(4)).1);
    let (next, cached) = cache.observe(route, now + ttl);
    assert_ne!(next, generation);
    assert!(!cached);
    assert!(!cache.record(next, now + ttl, Duration::ZERO));
    assert!(!cache.observe(route, now + ttl).1);
}

#[test]
fn recheck_deadline_is_not_extended_and_only_one_generation_can_claim_it() {
    let mut cache = NegativeCache::default();
    let route = Some("192.0.2.1:0".parse().unwrap());
    let now = Instant::now();
    let ttl = Duration::from_secs(5);
    let deadline = now + ttl;
    let (generation, _) = cache.observe(route, now);
    assert!(cache.record(generation, now, ttl));
    assert!(!cache.record(generation, now + Duration::from_secs(1), ttl));
    assert_eq!(cache.expires, Some(deadline));
    assert_eq!(cache.begin_recheck(generation, deadline, route, now), None);
    let next = cache
        .begin_recheck(generation, deadline, route, deadline)
        .unwrap();
    assert_ne!(generation, next);
    assert_eq!(
        cache.begin_recheck(generation, deadline, route, deadline),
        None
    );
    assert!(!cache.record(generation, deadline, ttl));
    assert!(cache.record(next, deadline, ttl));
    let other = Some("198.51.100.1:0".parse().unwrap());
    assert_eq!(
        cache.begin_recheck(next, deadline + ttl, other, deadline + ttl),
        None
    );
    assert!(cache.expires.is_none());
}

#[tokio::test]
async fn auto_retries_only_two_silent_pre_authentication_attempts() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let token = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
    let auto = AutoClient::new(
        Arc::new(H2Client::new(&remote.to_string(), "localhost", &token, roots.clone()).unwrap()),
        Arc::new(H3Client::new(remote, "localhost", &token, roots).unwrap()),
        Duration::from_secs(900),
    );
    for error in [
        ClientError::Tls,
        ClientError::Unauthorized,
        ClientError::Protocol,
        ClientError::Timeout,
        ClientError::Io,
        ClientError::Http3,
        ClientError::Rejected(429),
    ] {
        let (generation, _) = auto.observe().unwrap();
        let mut calls = 0;
        let result = auto
            .attempt_h3(generation, || {
                calls += 1;
                std::future::ready(Err::<(), _>(error))
            })
            .await;
        assert!(matches!(result, Err(actual) if actual == error));
        assert_eq!(calls, 1);
        assert!(!auto.observe().unwrap().1);
    }
    let (generation, _) = auto.observe().unwrap();
    let mut calls = 0;
    let result = auto
        .attempt_h3(generation, || {
            calls += 1;
            std::future::ready(Err::<(), _>(ClientError::QuicUnreachable))
        })
        .await;
    assert!(matches!(result, Ok(None)));
    assert_eq!(calls, AUTO_QUIC_ATTEMPTS);
    assert!(auto.observe().unwrap().1);
    auto.complete(generation, false).unwrap();
    let (generation, _) = auto.observe().unwrap();
    let mut calls = 0;
    let result = auto
        .attempt_h3(generation, || {
            calls += 1;
            std::future::ready(Err::<(), _>(ClientError::QuicEndpointNetworkRefused))
        })
        .await;
    assert!(matches!(result, Ok(None)));
    assert_eq!(calls, 1);
    assert!(auto.observe().unwrap().1);
}

#[tokio::test]
async fn idle_profile_rechecks_quic_without_opening_an_application_tunnel() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server = crate::quinn_reference::server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.cert.der().clone()],
        key.into(),
    )
    .unwrap();
    let remote = server.local_addr().unwrap();
    let token = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
    let auto = AutoClient::new(
        Arc::new(H2Client::new(&remote.to_string(), "localhost", &token, roots.clone()).unwrap()),
        Arc::new(H3Client::new(remote, "localhost", &token, roots).unwrap()),
        Duration::from_millis(100),
    );
    let (generation, _) = auto.observe().unwrap();
    assert!(auto.complete(generation, true).unwrap());
    let witness = async {
        // No local CONNECT or SOCKS request is made. Only maintenance
        // can initiate this connection.
        let incoming = server.accept().await.unwrap();
        let _ = incoming.await;
        loop {
            {
                let cache = auto.negative.lock().unwrap();
                if cache.generation != generation.wrapping_add(1) && cache.expires.is_none() {
                    assert_ne!(cache.generation, generation);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    timeout(Duration::from_secs(15), async {
        tokio::select! {
            result = auto.maintain() => panic!("maintenance exited: {result:?}"),
            () = witness => {}
        }
    })
    .await
    .expect("idle profile must recheck its expired negative cache");
}

#[test]
fn route_change_rejects_stale_results_and_unknown_route_disables_cache() {
    let mut cache = NegativeCache::default();
    let now = Instant::now();
    let ttl = Duration::from_secs(900);
    let a = Some("192.0.2.1:0".parse().unwrap());
    let b = Some("198.51.100.1:0".parse().unwrap());
    let (old, _) = cache.observe(a, now);
    cache.record(old, now, ttl);
    assert!(cache.observe(a, now).1);
    let (new, cached) = cache.observe(b, now);
    assert_ne!(old, new);
    assert!(!cached);
    cache.record(old, now, ttl);
    assert!(!cache.observe(b, now).1);
    cache.record(new, now, ttl);
    assert!(cache.observe(b, now).1);
    let (unknown, cached) = cache.observe(None, now);
    assert!(!cached);
    cache.record(unknown, now, ttl);
    assert!(!cache.observe(None, now).1);
    assert!(!cache.observe(b, now).1);
}

#[test]
fn same_ip_network_epoch_invalidates_quic_failure() {
    let mut cache = NegativeCache::default();
    let now = Instant::now();
    let source = "192.0.2.1:0".parse().unwrap();
    let a = Some(crate::network_scope::Scope::fixture(source, 1));
    let b = Some(crate::network_scope::Scope::fixture(source, 2));
    let (old, _) = cache.observe(a, now);
    assert!(cache.record(old, now, Duration::from_secs(900)));
    let (new, cached) = cache.observe(b, now);
    assert_ne!(old, new);
    assert!(!cached);
    assert!(!cache.record(old, now, Duration::from_secs(900)));
}

#[test]
fn successful_or_terminal_probe_invalidates_prior_failure_generation() {
    let mut cache = NegativeCache::default();
    let now = Instant::now();
    let route = Some("127.0.0.1:0".parse().unwrap());
    let (old, _) = cache.observe(route, now);
    cache.invalidate();
    cache.record(old, now, Duration::from_secs(900));
    assert!(!cache.observe(route, now).1);
}

#[test]
fn route_source_uses_os_loopback_route_without_application_traffic() {
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_nonblocking(true).unwrap();
    let remote = peer.local_addr().unwrap();
    assert_eq!(route_source(remote), Some("127.0.0.1:0".parse().unwrap()));
    assert_eq!(
        peer.recv_from(&mut [0; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

pub(super) async fn paired() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (left, right) = tokio::join!(TcpStream::connect(address), listener.accept());
    (left.unwrap(), right.unwrap().0)
}

#[tokio::test]
async fn http_connect_validation_preserves_pipelined_bytes_and_rejects_ambiguous_requests() {
    let (mut client, mut proxy) = paired().await;
    client
        .write_all(b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\nsentinel")
        .await
        .unwrap();
    assert_eq!(
        http_target(&mut proxy).await.unwrap(),
        HttpRequest::Connect(Address::V6(Ipv6Addr::LOCALHOST.octets()), 443)
    );
    let mut trailing = [0; 8];
    proxy.read_exact(&mut trailing).await.unwrap();
    assert_eq!(&trailing, b"sentinel");
    let cases: &[(&[u8], &[u8])] = &[
            (b"GET example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n",HTTP_METHOD),
            (b"CONNECT example.org:443 HTTP/1.1\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.1\r\nHost: other.org:443\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nHost: example.org:443\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nContent-Length: 0\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nTransfer-Encoding: chunked\r\n\r\n",HTTP_BAD),
            (b"CONNECT [bad]:443 HTTP/1.0\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:0 HTTP/1.0\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:65536 HTTP/1.0\r\n\r\n",HTTP_BAD),
            (b"CONNECT invalid HTTP/1.0\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/2\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.1\r\nHost: \xff\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.0\r\nbroken\r\n\r\n",HTTP_BAD),
        ];
    for (request, error) in cases {
        let (mut client, mut proxy) = paired().await;
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(http_target(&mut proxy).await, Err(*error));
    }
    let (mut client, mut proxy) = paired().await;
    client.write_all(&[b'x'; HEADER_LIMIT]).await.unwrap();
    assert_eq!(http_target(&mut proxy).await, Err(HTTP_BAD));
}

#[tokio::test]
async fn absolute_http_rewrites_and_never_relays_a_second_request() {
    let (mut app, mut proxy) = paired().await;
    app.write_all(b"POST http://Example.org/a?q=1 HTTP/1.1\r\nHost: example.org:80\r\nProxy-Authorization: Basic secret\r\nConnection: X-Private, keep-alive\r\nX-Private: discard\r\nContent-Length: 3\r\nX-Test: yes\r\n\r\nabcGET http://other.org/ HTTP/1.1\r\nHost: other.org\r\n\r\n").await.unwrap();
    let HttpRequest::Plain(address, port, request) = http_target(&mut proxy).await.unwrap() else {
        panic!("expected plain HTTP");
    };
    assert_eq!((address, port), (Address::Dns("example.org".into()), 80));
    let rewritten = std::str::from_utf8(&request).unwrap();
    assert!(rewritten.starts_with("POST /a?q=1 HTTP/1.1\r\n"));
    assert!(rewritten
        .to_ascii_lowercase()
        .contains("\r\nhost: example.org\r\n"));
    assert!(
        rewritten.contains("\r\nConnection: close\r\nContent-Length: 3\r\nx-test: yes\r\n\r\nabc")
    );
    assert!(!rewritten.contains("secret"));
    assert!(!rewritten.contains("discard"));
    let mut once = HttpOnce {
        socket: proxy,
        request: request.clone().into(),
    };
    let mut relayed = Vec::new();
    once.read_to_end(&mut relayed).await.unwrap();
    assert_eq!(relayed, request);
    once.write_all(b"response").await.unwrap();
    let mut response = [0; 8];
    app.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"response");
    once.flush().await.unwrap();
    once.shutdown().await.unwrap();
    assert_eq!(
        app.read_u8().await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn absolute_http_rejects_ambiguous_authority_and_framing() {
    let cases = [
            "GET http://example.org/ HTTP/1.1\r\nHost: other.org\r\n\r\n",
            "GET http://example.org/ HTTP/1.1\r\n\r\n",
            "GET http://user@example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
            "GET http://example.org/#fragment HTTP/1.1\r\nHost: example.org\r\n\r\n",
            "GET http://example.org:81/ HTTP/1.1\r\nHost: example.org\r\n\r\n",
            "GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\nHost: example.org\r\n\r\n",
            "POST http://example.org/ HTTP/1.1\r\nHost: example.org\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
            "POST http://example.org/ HTTP/1.1\r\nHost: example.org\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST http://example.org/ HTTP/1.1\r\nHost: example.org\r\nContent-Length: 1048577\r\n\r\n",
            "POST http://example.org/ HTTP/1.1\r\nHost: example.org\r\nContent-Length: 2\r\n\r\na",
            "GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\nConnection: host\r\n\r\n",
            "GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\nUpgrade: websocket\r\n\r\n",
            "POST http://example.org/ HTTP/1.1\r\nHost: example.org\r\nExpect: 100-continue\r\n\r\n",
        ];
    for request in cases {
        let (mut app, mut proxy) = paired().await;
        app.write_all(request.as_bytes()).await.unwrap();
        app.shutdown().await.unwrap();
        assert_eq!(http_target(&mut proxy).await, Err(HTTP_BAD), "{request:?}");
    }
    let (mut app, mut proxy) = paired().await;
    app.write_all(b"GET http://[::1]:8080/ HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n")
        .await
        .unwrap();
    assert!(matches!(
        http_target(&mut proxy).await.unwrap(),
        HttpRequest::Plain(Address::V6(_), 8080, _)
    ));
}

#[tokio::test]
async fn socks_connect_rejects_bad_methods_addresses_commands_and_truncation() {
    let (mut client, mut proxy) = paired().await;
    client.write_all(&[5, 1, 2]).await.unwrap();
    assert_eq!(socks_target(&mut proxy).await, Err(ClientError::Protocol));
    let mut response = [0; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 255]);
    for (request, reply) in [
        (vec![4, 1, 0, 1], 1),
        (vec![5, 1, 1, 1], 1),
        (vec![5, 2, 0, 1], 7),
        (vec![5, 1, 0, 9], 8),
        (vec![5, 1, 0, 3, 1, 255], 8),
        (vec![5, 1, 0, 1, 127, 0, 0, 1, 0, 0], 8),
    ] {
        let (mut client, mut proxy) = paired().await;
        client.write_all(&[5, 1, 0]).await.unwrap();
        client.write_all(&request).await.unwrap();
        assert_eq!(socks_target(&mut proxy).await, Err(ClientError::Protocol));
        let mut response = [0; 12];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response[..2], &[5, 0]);
        assert_eq!(&response[2..], &[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
    let mut v6 = vec![5, 1, 0, 5, 1, 0, 4];
    v6.extend(Ipv6Addr::LOCALHOST.octets());
    v6.extend(443u16.to_be_bytes());
    v6.extend(b"tail");
    let (mut client, mut proxy) = paired().await;
    client.write_all(&v6).await.unwrap();
    assert_eq!(
        socks_target(&mut proxy).await.unwrap(),
        (Address::V6(Ipv6Addr::LOCALHOST.octets()), 443)
    );
    let mut tail = [0; 4];
    proxy.read_exact(&mut tail).await.unwrap();
    assert_eq!(&tail, b"tail");
    for prefix in [
        vec![4, 0],
        vec![5, 0],
        vec![5, 1, 0, 5, 1, 0, 1, 127],
        vec![5, 1, 0, 5, 1, 0, 4, 0],
        vec![5, 1, 0, 5, 1, 0, 3, 4, b'a'],
    ] {
        let (mut client, mut proxy) = paired().await;
        client.write_all(&prefix).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(socks_target(&mut proxy).await.is_err());
    }
}

#[test]
fn real_local_proxy_modes_validate_credentials_and_relay_over_both_transports() {
    run_proxy_fixture(real_local_proxy_modes_fixture);
}

async fn real_local_proxy_modes_fixture() {
    use crate::{
        config::{Inbound, ServerPolicy, User},
        server::ServerContext,
    };
    use sha2::{Digest, Sha256};
    let directory = std::env::temp_dir().join(format!(
        "theia-local-proxy-modes-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = directory.join("ca.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    let token = [42; 32];
    let secret =
        crate::client_import::PrivateBearer::create(&directory.join("client.toml"), &token)
            .unwrap();
    let Config::Client(doc) =
        config::parse(include_str!("../../../../examples/client.toml")).unwrap()
    else {
        panic!("client fixture");
    };
    let mut profile = doc.client.profiles[0].clone();
    profile.auth_token = secret.reference().unwrap();
    profile.server_name = "localhost".into();
    profile.tls_ca = Some(format!("file:{}", cert_path.display()));
    profile.transport = Transport::H2;
    profile.server = "127.0.0.1:443".into();
    profile.xhttp_mode = Some(XhttpMode::StreamOne);
    let mut invalid = profile.clone();
    invalid.tls_ca = None;
    assert!(load_client(&invalid).await.is_err());
    invalid = profile.clone();
    invalid.auth_token = "file:relative".into();
    assert!(load_client(&invalid).await.is_err());
    invalid = profile.clone();
    invalid.security_mode = SecurityMode::SmartReality;
    assert!(load_client(&invalid).await.is_err());
    invalid = profile.clone();
    invalid.security_mode = SecurityMode::PinnedCertV1;
    assert!(load_client(&invalid).await.is_err());
    invalid.xhttp_mode = None;
    invalid.transport = Transport::H3;
    assert!(load_client(&invalid).await.is_err());
    invalid.transport = Transport::H2;
    assert!(load_client(&invalid).await.is_err());
    let mut pinned = profile.clone();
    pinned.xhttp_mode = None;
    pinned.security_mode = SecurityMode::PinnedCertStreamUpV1;
    assert!(load_client(&pinned).await.is_err());
    let mut automatic_mode = profile.clone();
    automatic_mode.xhttp_mode = Some(XhttpMode::Auto);
    assert!(matches!(
        load_client(&automatic_mode).await,
        Ok(ProxyClient::Direct(d)) if matches!(&d.carrier, Carrier::H2(_))
    ));
    automatic_mode.transport = Transport::Auto;
    assert!(matches!(
        load_client(&automatic_mode).await,
        Ok(ProxyClient::Direct(d)) if matches!(&d.carrier, Carrier::Auto(_))
    ));

    let inbound = Inbound {
        id: "edge".into(),
        path_prefix: Some(crate::split_http::EXAMPLE_PREFIX.into()),
        allowed_user_ids: vec!["client".into()],
        h2_listen: "127.0.0.1:0".into(),
        quic_listen: "127.0.0.1:0".into(),
        server_name: "localhost".into(),
        tls_cert: "unused".into(),
        tls_key: "unused".into(),
        security_mode: Default::default(),
        reality: None,
    };
    let user = User {
        id: "client".into(),
        token_sha256: format!("{:x}", Sha256::digest(token)),
        disabled: false,
    };
    let policy = ServerPolicy {
        routing: Some(crate::routing::Settings {
            revision: 2,
            geodata_directory: None,
            diagnostic_domains: crate::routing::snapshot::default_diagnostic_domains(),
            datasets: None,
            rules: vec![
                crate::routing::Rule {
                    name: "local direct".into(),
                    action: Action::Direct,
                    domains: vec!["full:localhost".into()],
                    ips: vec![],
                    applications: vec![],
                },
                crate::routing::Rule {
                    name: "blocked".into(),
                    action: Action::Blocked,
                    domains: vec!["full:blocked.invalid".into()],
                    ips: vec![],
                    applications: vec![],
                },
                crate::routing::Rule {
                    name: "dpi fallback".into(),
                    action: Action::DirectDpi,
                    domains: vec![],
                    ips: vec!["127.0.0.1/32".into()],
                    applications: vec![],
                },
            ],
        }),
        allow_private_ips: true,
        max_connections_per_user: 8,
        max_connections_total: 8,
        connect_timeout_ms: 1500,
    };
    let context = Arc::new(ServerContext::new(
        &inbound,
        std::slice::from_ref(&user),
        &policy,
    ));
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let h2 = tokio::spawn(crate::server::serve(
        tcp,
        tokio_rustls::TlsAcceptor::from(Arc::new(tls.clone())),
        context.clone(),
    ));
    let quic = crate::quic_transport::server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
    )
    .unwrap();
    let quic_addr = quic.local_addr().unwrap();
    let h3 = tokio::spawn(crate::h3_server::serve(quic, context));

    timeout(Duration::from_secs(50), async {
            for (transport, remote, http) in [
                (Transport::H2, tcp_addr, true),
                (Transport::H3, quic_addr, false),
                (Transport::Auto, quic_addr, true),
            ] {
                profile.transport = transport;
                profile.server = remote.to_string();

                // The exact same production H2/H3 clients now consume
                // compact key trust without opening a PEM file.
                let anchor = crate::own_tls::Anchor::from_bytes(Sha256::digest(cert.cert.der()).into());
                let mut key_profile = profile.clone();
                key_profile.tls_ca = Some(anchor.reference());
                let key_client = load_client(&key_profile).await.unwrap();
                assert_eq!(key_client.routing_policy().await.unwrap().manifest().revision, 2);
                drop(key_client);

                key_profile.tls_ca = Some(crate::own_tls::Anchor::from_bytes([0x99; 32]).reference());
                let wrong = load_client(&key_profile).await.unwrap();
                assert!(wrong.routing_policy().await.is_err(), "wrong anchor must reject the authenticated exchange");
                drop(wrong);

                let proxy_client = load_client(&profile).await.unwrap();
                let snapshot = proxy_client.routing_policy().await.unwrap();
                assert_eq!(snapshot.manifest().revision, 2);

                // The same production request handler, not a parser-only
                // fixture, must route absolute-form over H2/H3 and Pass.
                for host in ["127.0.0.1", "localhost"] {
                    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let port = origin.local_addr().unwrap().port();
                    let (mut app, local) = paired().await;
                    let proxy = proxy_client.clone();
                    let exchange = tokio::spawn(async move {
                        handle(local, true, &proxy, 0).await
                    });
                    app.write_all(format!(
                        "POST http://{host}:{port}/path?q=1 HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: Basic not-for-origin\r\nContent-Length: 3\r\n\r\nabc"
                    ).as_bytes()).await.unwrap();
                    let (mut peer, _) = origin.accept().await.unwrap();
                    let mut wire = Vec::new();
                    peer.read_to_end(&mut wire).await.unwrap();
                    assert_eq!(wire, format!(
                        "POST /path?q=1 HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: 3\r\n\r\nabc"
                    ).into_bytes());
                    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                    peer.write_all(response).await.unwrap();
                    peer.shutdown().await.unwrap();
                    let mut actual = Vec::new();
                    app.read_to_end(&mut actual).await.unwrap();
                    assert_eq!(actual, response);
                    exchange.await.unwrap().unwrap();
                }

                let (mut app, local) = paired().await;
                let proxy = proxy_client.clone();
                let denied = tokio::spawn(async move { handle(local, true, &proxy, 0).await });
                app.write_all(b"GET http://blocked.invalid/ HTTP/1.1\r\nHost: blocked.invalid\r\n\r\n").await.unwrap();
                let mut reply = Vec::new();
                app.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, HTTP_DENIED);
                assert!(matches!(denied.await.unwrap(), Err(ClientError::Open(ErrorCode::PolicyDenied))));
                assert_eq!(
                    snapshot
                        .policy()
                        .matching_action(None, Some("127.0.0.1".parse().unwrap()))
                        .unwrap(),
                    Some(Action::DirectDpi)
                );
                let dpi_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let dpi_port = dpi_listener.local_addr().unwrap().port();
                let dpi_tunnel = proxy_client
                    .open(Address::V4([127, 0, 0, 1]), dpi_port)
                    .await
                    .unwrap();
                assert!(matches!(
                    dpi_tunnel.tunnel,
                    ProxyTunnel::H2(_) | ProxyTunnel::H3(_)
                ));
                let _dpi_accepted = dpi_listener.accept().await.unwrap();
                drop(dpi_tunnel);
                drop(_dpi_accepted);
                // Exercise deferred fallback on both carriers without making
                // any public connections or weakening production IP checks.
                let fallback = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let fallback_port = fallback.local_addr().unwrap().port();
                let (origin, mut observer) = paired().await;
                let (mut app, local) = paired().await;
                let ProxyClient::Direct(client) = &proxy_client else {
                    panic!("expected own TLS")
                };
                let route = ProxyTunnel::Dpi(Box::new(DpiRoute {
                    tunnel: crate::routing::dpi::Tunnel::fixture(origin, "example.org"),
                    observed: Some(client.last_open.clone()),
                    carrier: client.carrier.clone(),
                    address: Address::V4([127, 0, 0, 1]),
                    port: fallback_port,
                }));
                let task = tokio::spawn(route.relay(local));
                app.write_all(b"not TLS, exact prefix").await.unwrap();
                app.shutdown().await.unwrap();
                let (mut destination, _) = fallback.accept().await.unwrap();
                let mut bytes = Vec::new();
                destination.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"not TLS, exact prefix");
                destination.write_all(b"ok").await.unwrap();
                destination.shutdown().await.unwrap();
                let mut reply = Vec::new();
                app.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"ok");
                task.await.unwrap().unwrap();
                let mut leaked = Vec::new();
                observer.read_to_end(&mut leaked).await.unwrap();
                assert!(leaked.is_empty());
                assert!(matches!(
                    proxy_client
                        .open(Address::Dns("blocked.invalid".into()), 443)
                        .await,
                    Err(ClientError::Open(ErrorCode::PolicyDenied))
                ));
                let direct_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let direct_port = direct_listener.local_addr().unwrap().port();
                let tunnel = proxy_client
                    .open(Address::Dns("localhost".into()), direct_port)
                    .await
                    .unwrap();
                assert!(matches!(tunnel.tunnel, ProxyTunnel::Direct(_)));
                let _accepted = direct_listener.accept().await.unwrap();
                if let ProxyClient::Direct(client) = &proxy_client {
                    assert!(matches!(
                        client
                            .carrier
                            .open(Address::Dns("localhost".into()), direct_port)
                            .await,
                        Err(ClientError::Open(ErrorCode::PolicyDenied))
                    ));
                }
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                if transport == Transport::H2 {
                    use crate::routing::{
                        packet::{FlowKey, Transport as PacketTransport},
                        PacketAction,
                    };
                    // Native packets have unknown domain evidence. Use an
                    // independent authenticated policy, not earlier IP rules
                    // that would prevent the ordinary proxy's domain decision
                    // before DNS resolution, or earlier domain rules that
                    // would prevent native IP-only authorization.
                    let mut native_policy = policy.clone();
                    native_policy.routing.as_mut().unwrap().rules = vec![
                        crate::routing::Rule {
                            name: "native test pass".into(),
                            action: Action::Direct,
                            domains: vec![],
                            ips: vec!["192.0.2.0/24".into()],
                            applications: vec![],
                        },
                        crate::routing::Rule {
                            name: "native test redirect".into(),
                            action: Action::Allowed,
                            domains: vec![],
                            ips: vec!["198.51.100.0/24".into()],
                            applications: vec![],
                        },
                        crate::routing::Rule {
                            name: "native test drop".into(),
                            action: Action::Blocked,
                            domains: vec![],
                            ips: vec!["203.0.113.0/24".into()],
                            applications: vec![],
                        },
                    ];
                    let native_context = Arc::new(ServerContext::new(
                        &inbound,
                        std::slice::from_ref(&user),
                        &native_policy,
                    ));
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let native_remote = listener.local_addr().unwrap();
                    let native_server = tokio::spawn(crate::server::serve(
                        listener,
                        tokio_rustls::TlsAcceptor::from(Arc::new(tls.clone())),
                        native_context,
                    ));
                    let path = directory.join("native.toml");
                    let mut native = doc.clone();
                    native.client.active_profile = profile.id.clone();
                    native.client.profiles = vec![profile.clone()];
                    native.client.profiles[0].server = native_remote.to_string();
                    config::atomic_write(&path, &Config::Client(native)).unwrap();
                    let ingress = NativeIngress::prepare(&path).await.unwrap();
                    assert_eq!(ingress.runtime.capture_state.reported(), 1);
                    assert!(
                        NativeIngress::prepare(&path).await.is_err(),
                        "exclusive native owner"
                    );
                    ingress.runtime.capture_state.ready().unwrap();
                    assert!(ingress.ensure_running().is_ok());
                    let source = "10.0.0.2:40001".parse().unwrap();
                    let key = |destination: &str, transport| FlowKey {
                        source,
                        destination: destination.parse().unwrap(),
                        transport,
                        interface: 7,
                    };
                    for destination in [
                        "127.0.0.1:443",
                        "0.0.0.0:443",
                        "224.0.0.1:443",
                        "192.0.2.1:0",
                        "10.0.0.2:40001",
                        "192.0.2.1:443",
                        "203.0.113.1:443",
                    ] {
                        assert!(
                            matches!(
                                ingress
                                    .redirect(key(destination, PacketTransport::Tcp))
                                    .await,
                                Err(ClientError::Open(ErrorCode::PolicyDenied))
                            ),
                            "{destination}"
                        );
                    }
                    let (_, flow, address) = ingress
                        .redirect(key("198.51.100.1:443", PacketTransport::Tcp))
                        .await
                        .unwrap();
                    assert_eq!(address, Address::V4([198, 51, 100, 1]));
                    assert!(flow.commit(PacketAction::Redirect).is_ok());
                    drop(flow);
                    let (_, local) = paired().await;
                    assert!(matches!(
                        ingress
                            .relay_terminated_tcp(
                                key("198.51.100.1:443", PacketTransport::Udp),
                                local
                            )
                            .await,
                        Err(ClientError::Protocol)
                    ));
                    let (_tx, up) = tokio::sync::mpsc::channel(1);
                    let (down, _rx) = tokio::sync::mpsc::channel(1);
                    assert!(matches!(
                        ingress
                            .relay_terminated_udp(
                                key("198.51.100.1:443", PacketTransport::Tcp),
                                up,
                                down
                            )
                            .await,
                        Err(ClientError::Protocol)
                    ));
                    #[cfg(target_os = "linux")]
                    {
                        use crate::routing::packet::PacketMeta;
                        let meta = |destination, transport, tcp_flags| PacketMeta {
                            flow: key(destination, transport),
                            payload_len: 0,
                            tcp_flags,
                        };
                        let first = meta("192.0.2.1:443", PacketTransport::Tcp, Some(0x10));
                        assert_eq!(ingress.raw_verdict(first).await, PacketAction::Drop);
                        let syn = PacketMeta {
                            tcp_flags: Some(2),
                            ..first
                        };
                        assert_eq!(ingress.raw_verdict(syn).await, PacketAction::Pass);
                        assert_eq!(ingress.raw_verdict(first).await, PacketAction::Pass);
                        // A tagged packet cannot inherit an ordinary flow,
                        // even with the same exact tuple and fresh policy.
                        assert_eq!(ingress.raw_verdict_bound(first,Some(91)).await,PacketAction::Drop);
                        assert_eq!(ingress.raw_verdict(first).await,PacketAction::Drop);
                        let tagged=meta("192.0.2.1:8443",PacketTransport::Tcp,Some(2));
                        assert_eq!(ingress.raw_verdict_bound(tagged,Some(92)).await,PacketAction::Pass);
                        assert_eq!(ingress.raw_verdict_bound(tagged,Some(92)).await,PacketAction::Pass);
                        assert_eq!(ingress.raw_verdict_bound(tagged,Some(93)).await,PacketAction::Drop);
                        assert_eq!(ingress.raw_verdict_bound(tagged,Some(92)).await,PacketAction::Drop);
                        assert_eq!(
                            ingress
                                .raw_verdict(meta("192.0.2.2:53", PacketTransport::Udp, None))
                                .await,
                            PacketAction::Drop
                        );
                        for destination in [
                            "0.0.0.0:443",
                            "224.0.0.1:443",
                            "198.51.100.1:443",
                            "203.0.113.1:443",
                        ] {
                            assert_eq!(
                                ingress
                                    .raw_verdict(meta(destination, PacketTransport::Tcp, Some(2)))
                                    .await,
                                PacketAction::Drop
                            );
                        }
                        ingress.unified_redirect_regression_fixture(meta("198.51.100.1:8443", PacketTransport::Tcp, Some(2))).await;
                        assert!(ingress
                            .prepare_stun_lab(
                                key("192.0.2.1:3478", PacketTransport::Tcp),
                                "example.org"
                            )
                            .await
                            .is_err());
                    }
                    ingress.shutdown();
                    assert_eq!(ingress.runtime.capture_state.reported(), 3);
                    assert!(ingress.ensure_running().is_err());
                    ingress.stopped().await;
                    let (_tx, up) = tokio::sync::mpsc::channel(1);
                    let (down, _rx) = tokio::sync::mpsc::channel(1);
                    assert!(matches!(
                        ingress
                            .relay_terminated_udp(
                                key("198.51.100.1:443", PacketTransport::Udp),
                                up,
                                down
                            )
                            .await,
                        Err(ClientError::Open(ErrorCode::PolicyDenied))
                    ));
                    drop(ingress);
                    // A failed preflight releases the exclusive owner.
                    assert!(NativeIngress::prepare(&directory.join("missing.toml"))
                        .await
                        .is_err());
                    let owner = NativeOwner::acquire().unwrap();
                    drop(owner);
                    native_server.abort();
                }
                udp_prewrite_fallback_fixture(&proxy_client).await;
                udp_revoked_fallback_fixture(&proxy_client).await;
                udp_socks_fixture(&proxy_client).await;
                let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = target.local_addr().unwrap().port();
                let echo = tokio::spawn(async move {
                    let (mut stream, _) = target.accept().await.unwrap();
                    let mut bytes = Vec::new();
                    stream.read_to_end(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"byte-exact proxy");
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
                let (mut app, local) = paired().await;
                let proxy =
                    tokio::spawn(async move { handle(local, http, &proxy_client, 1).await });
                if http {
                    app.write_all(
                        format!(
                            "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                    let mut reply = vec![0; HTTP_OK.len()];
                    app.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply, HTTP_OK);
                } else {
                    let mut request = vec![5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1];
                    request.extend(port.to_be_bytes());
                    app.write_all(&request).await.unwrap();
                    let mut reply = [0; 12];
                    app.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                }
                app.write_all(b"byte-exact proxy").await.unwrap();
                app.shutdown().await.unwrap();
                let mut result = Vec::new();
                app.read_to_end(&mut result).await.unwrap();
                assert_eq!(&result, b"byte-exact proxy");
                proxy.await.unwrap().unwrap();
                echo.await.unwrap();
            }
        })
        .await
        .unwrap();
    h2.abort();
    h3.abort();
}
