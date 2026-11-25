//! Native H2/H3 application-plane regressions. These are controlled
//! loopback fixtures, not evidence for the public REALITY admission relay.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use theia::{
    client::ClientError,
    config::{Inbound, ServerPolicy, Transport, User, XhttpMode},
    descriptor::{
        self, Anchor, ClientPolicy, Descriptor, Padding, Reference, Rotation, Scope, SecurityMode,
        Store,
    },
    identity_data::{FixtureClient, ManagedFixtureClient, PreparedFixture},
    identity_tls::{Branch, Identity},
    protocol::{Address, ErrorCode},
    reference_health,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

const TOKEN: [u8; 32] = [42; 32];
const OTHER: [u8; 32] = [43; 32];
const DEADLINE: Duration = Duration::from_secs(25);

fn policy(allow_private_ips: bool) -> ServerPolicy {
    ServerPolicy {
        allow_private_ips,
        max_connections_per_user: 8,
        max_connections_total: 8,
        connect_timeout_ms: 1500,
    }
}

fn config(remote: SocketAddr) -> (Inbound, Vec<User>) {
    let inbound = Inbound {
        id: "edge".into(),
        security_mode: Default::default(),
        reality: None,
        allowed_user_ids: vec!["allowed".into()],
        quic_listen: remote.to_string(),
        h2_listen: remote.to_string(),
        server_name: "localhost".into(),
        tls_cert: "unused".into(),
        tls_key: "unused".into(),
    };
    let users = vec![
        User {
            id: "allowed".into(),
            token_sha256: format!("{:x}", Sha256::digest(TOKEN)),
            disabled: false,
        },
        User {
            id: "other".into(),
            token_sha256: format!("{:x}", Sha256::digest(OTHER)),
            disabled: false,
        },
    ];
    (inbound, users)
}

fn value(scope: Scope, h3: bool, now: u64) -> Descriptor {
    Descriptor {
        schema_version: 1,
        wire_version: 1,
        security_mode: SecurityMode::SmartReality,
        revision: 1,
        not_before: now.saturating_sub(1),
        not_after: now + 600,
        active_reference: 0,
        h3,
        stream_one: true,
        stream_up: true,
        path_prefix: "/v1/fixture-prefix".into(),
        next_identity: None,
        scope,
        padding: Padding {
            header_min: 0,
            header_max: 128,
            frame_min: 0,
            frame_max: 512,
        },
        rotation: Rotation {
            lifetime_min_s: 10,
            lifetime_max_s: 60,
            volume_min_bytes: 1024,
            volume_max_bytes: 4096,
        },
        references: vec![Reference {
            server_name: "reference.example.org".into(),
            port: 443,
            h3,
        }],
    }
}

fn anchor(identity: &Identity, mode: XhttpMode) -> Anchor {
    Anchor::new(
        identity.scope().clone(),
        identity.public_key(),
        1,
        ClientPolicy {
            transport: Transport::Auto,
            xhttp_mode: mode,
        },
    )
    .unwrap()
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "theia-identity-data-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn bind() -> TcpListener {
    // TCP/UDP port availability is not identical on all native platforms.
    for _ in 0..16 {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        if let Ok(udp) = std::net::UdpSocket::bind(tcp.local_addr().unwrap()) {
            drop(udp);
            return tcp;
        }
    }
    panic!("unable to reserve a loopback fixture port");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_identity_relay_and_descriptor_update_on_h2_and_h3() {
    timeout(DEADLINE, async {
        let tcp = bind().await;
        let remote = tcp.local_addr().unwrap();
        let scope = Scope {
            inbound: "edge".into(),
            endpoint: remote.to_string(),
        };
        let identity = Identity::generate(scope.clone()).unwrap();
        let now = reference_health::unix_now().unwrap();
        let first = value(scope, true, now);
        let first_raw = identity.sign_descriptor(&first).unwrap();
        let mut second = first.clone();
        second.revision = 2;
        let second_raw = identity.sign_descriptor(&second).unwrap();
        let (inbound, users) = config(remote);
        let server =
            PreparedFixture::new(tcp, &identity, &second_raw, &inbound, &users, &policy(true))
                .unwrap();
        let server = tokio::spawn(server.serve());
        let scratch = Scratch::new();
        for (branch, mode) in [
            (Branch::H2, XhttpMode::StreamOne),
            (Branch::H2, XhttpMode::StreamUp),
            (Branch::H3, XhttpMode::StreamOne),
            (Branch::H3, XhttpMode::StreamUp),
        ] {
            let anchor = anchor(&identity, mode);
            let verified = descriptor::verify(&first_raw, &anchor).unwrap();
            let client =
                FixtureClient::new(remote, &URL_SAFE_NO_PAD.encode(TOKEN), verified, branch)
                    .unwrap();
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = target.local_addr().unwrap().port();
            let echo = tokio::spawn(async move {
                let (mut socket, _) = target.accept().await.unwrap();
                let mut bytes = Vec::new();
                socket.read_to_end(&mut bytes).await.unwrap();
                socket.write_all(&bytes).await.unwrap();
                socket.shutdown().await.unwrap();
            });
            let tunnel = client
                .open(Address::Dns("localhost".into()), port)
                .await
                .unwrap();
            let (mut app, local) = tokio::io::duplex(4096);
            let relay = tokio::spawn(tunnel.relay(local));
            let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
            app.write_all(&payload).await.unwrap();
            app.shutdown().await.unwrap();
            let mut returned = Vec::new();
            app.read_to_end(&mut returned).await.unwrap();
            assert_eq!(returned, payload);
            relay.await.unwrap().unwrap();
            echo.await.unwrap();

            let path = scratch.0.join(format!("{branch:?}-{mode:?}.toml"));
            let store = Store::new(&path, anchor.clone()).unwrap();
            store.initialize(&first_raw, now).unwrap();
            assert_eq!(
                client.refresh(&store).await.unwrap(),
                descriptor::Change::Advanced
            );
            let reopened = Store::new(&path, anchor).unwrap();
            assert_eq!(
                reopened
                    .load(reference_health::unix_now().unwrap())
                    .unwrap()
                    .descriptor()
                    .revision,
                2
            );
            // A client holding the old immutable snapshot cannot overwrite a
            // newer snapshot. It must reopen the verified store first.
            assert!(client.refresh(&reopened).await.is_err());
        }
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_identity_wrong_grant_and_wrong_route_never_dial_target() {
    timeout(DEADLINE, async {
        let tcp = bind().await;
        let remote = tcp.local_addr().unwrap();
        let scope = Scope {
            inbound: "edge".into(),
            endpoint: remote.to_string(),
        };
        let identity = Identity::generate(scope.clone()).unwrap();
        let unrelated = Identity::generate(scope.clone()).unwrap();
        let now = reference_health::unix_now().unwrap();
        let mut descriptor = value(scope, true, now);
        let raw = identity.sign_descriptor(&descriptor).unwrap();
        let bad_key_raw = unrelated.sign_descriptor(&descriptor).unwrap();
        descriptor.path_prefix = "/v1/different-prefix".into();
        let bad_route_raw = identity.sign_descriptor(&descriptor).unwrap();
        let (inbound, users) = config(remote);
        let server =
            PreparedFixture::new(tcp, &identity, &raw, &inbound, &users, &policy(true)).unwrap();
        let server = tokio::spawn(server.serve());
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let addr = Address::Dns("localhost".into());
        for branch in [Branch::H2, Branch::H3] {
            let valid_anchor = anchor(&identity, XhttpMode::StreamOne);
            let wrong_anchor = anchor(&unrelated, XhttpMode::StreamOne);
            let wrong = descriptor::verify(&bad_key_raw, &wrong_anchor).unwrap();
            let client =
                FixtureClient::new(remote, &URL_SAFE_NO_PAD.encode(TOKEN), wrong, branch).unwrap();
            assert!(matches!(
                client.open(addr.clone(), port).await,
                Err(ClientError::Tls)
            ));
            let wrong_grant = descriptor::verify(&raw, &valid_anchor).unwrap();
            let client =
                FixtureClient::new(remote, &URL_SAFE_NO_PAD.encode(OTHER), wrong_grant, branch)
                    .unwrap();
            assert!(matches!(
                client.open(addr.clone(), port).await,
                Err(ClientError::Unauthorized)
            ));
            let wrong_route = descriptor::verify(&bad_route_raw, &valid_anchor).unwrap();
            let client =
                FixtureClient::new(remote, &URL_SAFE_NO_PAD.encode(TOKEN), wrong_route, branch)
                    .unwrap();
            assert!(matches!(
                client.open(addr.clone(), port).await,
                Err(ClientError::Rejected(404))
            ));
        }
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_only_descriptor_refuses_h3_and_private_target_acl_remains_effective() {
    timeout(DEADLINE, async {
        let tcp = bind().await;
        let remote = tcp.local_addr().unwrap();
        let scope = Scope {
            inbound: "edge".into(),
            endpoint: remote.to_string(),
        };
        let identity = Identity::generate(scope.clone()).unwrap();
        let now = reference_health::unix_now().unwrap();
        let d = value(scope, false, now);
        let raw = identity.sign_descriptor(&d).unwrap();
        let anchor = anchor(&identity, XhttpMode::StreamOne);
        let verified = descriptor::verify(&raw, &anchor).unwrap();
        assert!(
            FixtureClient::new(remote, &URL_SAFE_NO_PAD.encode(TOKEN), verified, Branch::H3)
                .is_err()
        );
        let (inbound, users) = config(remote);
        let server =
            PreparedFixture::new(tcp, &identity, &raw, &inbound, &users, &policy(false)).unwrap();
        let server = tokio::spawn(server.serve());
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let client = FixtureClient::new(
            remote,
            &URL_SAFE_NO_PAD.encode(TOKEN),
            descriptor::verify(&raw, &anchor).unwrap(),
            Branch::H2,
        )
        .unwrap();
        assert!(matches!(
            client.open(Address::Dns("localhost".into()), port).await,
            Err(ClientError::Open(ErrorCode::PolicyDenied))
        ));
        assert!(timeout(Duration::from_millis(250), target.accept())
            .await
            .is_err());
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_generations_refresh_persistent_revision_without_reusing_old_pool() {
    timeout(DEADLINE, async {
        let tcp = bind().await;
        let remote = tcp.local_addr().unwrap();
        let scope = Scope {
            inbound: "edge".into(),
            endpoint: remote.to_string(),
        };
        let identity = Identity::generate(scope.clone()).unwrap();
        let now = reference_health::unix_now().unwrap();
        let first = value(scope, true, now);
        let initial = identity.sign_descriptor(&first).unwrap();
        let mut second = first.clone();
        second.revision = 2;
        let latest = identity.sign_descriptor(&second).unwrap();
        let (inbound, users) = config(remote);
        let server = tokio::spawn(
            PreparedFixture::new(tcp, &identity, &latest, &inbound, &users, &policy(true))
                .unwrap()
                .serve(),
        );
        let scratch = Scratch::new();
        for branch in [Branch::H2, Branch::H3] {
            let path = scratch.0.join(format!("managed-{branch:?}.toml"));
            let anchor = anchor(&identity, XhttpMode::StreamOne);
            let store = Store::new(&path, anchor.clone()).unwrap();
            store.initialize(&initial, now).unwrap();
            let manager =
                ManagedFixtureClient::new(remote, branch, &URL_SAFE_NO_PAD.encode(TOKEN), store)
                    .unwrap();
            assert_eq!(manager.revision().await.unwrap(), 1);
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = target.local_addr().unwrap().port();
            let address = Address::V4([127, 0, 0, 1]);
            let old = manager.open(address.clone(), port).await.unwrap();
            let (mut old_remote, _) = target.accept().await.unwrap();
            assert_eq!(
                manager.refresh().await.unwrap(),
                descriptor::Change::Advanced
            );
            assert_eq!(manager.revision().await.unwrap(), 2);
            let new = manager.open(address, port).await.unwrap();
            let (mut new_remote, _) = target.accept().await.unwrap();
            match (&old, &new) {
                (
                    theia::identity_data::FixtureTunnel::H2(a),
                    theia::identity_data::FixtureTunnel::H2(b),
                ) => assert!(!a.shares_transport_with(b)),
                (
                    theia::identity_data::FixtureTunnel::H3(a),
                    theia::identity_data::FixtureTunnel::H3(b),
                ) => assert!(!a.shares_transport_with(b)),
                _ => panic!("branch changed"),
            }
            // Old and new tunnels remain independently usable.
            for (tunnel, socket) in [(old, &mut old_remote), (new, &mut new_remote)] {
                let (mut app, local) = tokio::io::duplex(1024);
                let relay = tokio::spawn(tunnel.relay(local));
                app.write_all(b"generation").await.unwrap();
                let mut bytes = [0; 10];
                socket.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"generation");
                socket.write_all(&bytes).await.unwrap();
                app.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"generation");
                app.shutdown().await.unwrap();
                socket.shutdown().await.unwrap();
                relay.await.unwrap().unwrap();
            }
            let reopened = Store::new(&path, anchor).unwrap();
            assert_eq!(
                reopened
                    .load(reference_health::unix_now().unwrap())
                    .unwrap()
                    .descriptor()
                    .revision,
                2
            );
            assert!(reopened
                .update(&initial, reference_health::unix_now().unwrap())
                .is_err());
            // An unreadable trust file never falls back to an in-memory pool.
            std::fs::write(&path, b"invalid").unwrap();
            assert!(matches!(manager.revision().await, Err(ClientError::Tls)));
        }
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_compatible_publication_renewal_preserves_h2_h3_tunnels() {
    timeout(DEADLINE, async {
        let tcp = bind().await;
        let remote = tcp.local_addr().unwrap();
        let identity = Identity::generate(Scope {
            inbound: "edge".into(),
            endpoint: remote.to_string(),
        })
        .unwrap();
        let now = reference_health::unix_now().unwrap();
        let first = value(identity.scope().clone(), true, now);
        let initial = identity.sign_descriptor(&first).unwrap();
        let root = anchor(&identity, XhttpMode::StreamOne);
        let digest = descriptor::verify(&initial, &root)
            .unwrap()
            .payload_sha256();
        let (inbound, users) = config(remote);
        let prepared =
            PreparedFixture::new(tcp, &identity, &initial, &inbound, &users, &policy(true))
                .unwrap();
        let control = prepared.control();
        let server = tokio::spawn(prepared.serve());
        let scratch = Scratch::new();
        let mut leases = Vec::new();
        for branch in [Branch::H2, Branch::H3] {
            let store =
                Store::new(&scratch.0.join(format!("live-{branch:?}")), root.clone()).unwrap();
            store.initialize(&initial, now).unwrap();
            let client = FixtureClient::new(
                remote,
                &URL_SAFE_NO_PAD.encode(TOKEN),
                store.load(now).unwrap(),
                branch,
            )
            .unwrap();
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tunnel = client
                .open(
                    Address::V4([127, 0, 0, 1]),
                    target.local_addr().unwrap().port(),
                )
                .await
                .unwrap();
            let (socket, _) = target.accept().await.unwrap();
            let (app, local) = tokio::io::duplex(1024);
            let task = tokio::spawn(tunnel.relay(local));
            leases.push((client, store, app, socket, task));
        }
        let mut next = first.clone();
        next.revision = 2;
        next.not_after += 600;
        let renewed = identity.sign_descriptor(&next).unwrap();
        let mut incompatible = next.clone();
        incompatible.path_prefix = "/v1/changed".into();
        assert!(control
            .renew(&identity.sign_descriptor(&incompatible).unwrap(), digest)
            .is_err());
        let wrong = Identity::generate(identity.scope().clone()).unwrap();
        assert!(control
            .renew(&wrong.sign_descriptor(&next).unwrap(), digest)
            .is_err());
        assert!(control.renew(&renewed, [0; 32]).is_err());
        assert_eq!(control.renew(&renewed, digest).unwrap(), 2);
        assert!(control.renew(&initial, digest).is_err());
        for (client, store, mut app, mut socket, task) in leases {
            assert_eq!(
                client.refresh(&store).await.unwrap(),
                descriptor::Change::Advanced
            );
            assert_eq!(
                store
                    .load(reference_health::unix_now().unwrap())
                    .unwrap()
                    .descriptor()
                    .revision,
                2
            );
            app.write_all(b"still open").await.unwrap();
            let mut bytes = [0; 10];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"still open");
            socket.write_all(&bytes).await.unwrap();
            app.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"still open");
            app.shutdown().await.unwrap();
            socket.shutdown().await.unwrap();
            task.await.unwrap().unwrap();
        }
        server.abort();
    })
    .await
    .unwrap();
}

// Actual TLS and QUIC handshakes using the same callback that produces the
// final transcript bytes. Controlled reference DNS names are used as SNI
// only; no third-party DNS resolution or reference network access occurs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_admission_callbacks_complete_full_tls_and_quic_before_application_data() {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;
    use theia::{
        identity_tls,
        reality_admission::{ReplayGuard, Secret},
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    timeout(DEADLINE, async {
        let tcp = bind().await;
        let remote = tcp.local_addr().unwrap();
        let scope = Scope {
            inbound: "edge".into(),
            endpoint: remote.to_string(),
        };
        let identity = Identity::generate(scope.clone()).unwrap();
        let now = reference_health::unix_now().unwrap();
        let d = value(scope.clone(), true, now);
        let signed = identity.sign_descriptor(&d).unwrap();
        let v = descriptor::verify(&signed, &anchor(&identity, XhttpMode::StreamOne)).unwrap();
        let name = d.references[0].server_name.as_str();
        let secret = Arc::new(Secret::generate().unwrap());
        let wrong = Arc::new(Secret::generate().unwrap());
        // Explicitly old startup time for this controlled test; production
        // restart retains the guard's conservative acceptance window.
        let guard = Arc::new(ReplayGuard::new(32, now - 121).unwrap());

        let acceptor = TlsAcceptor::from(Arc::new(
            identity_tls::checked_server_tls(
                &identity,
                &v,
                Branch::H2,
                secret.clone(),
                guard.clone(),
            )
            .unwrap(),
        ));
        let server = tokio::spawn(async move {
            for expected in [false, false, true] {
                let (stream, _) = tcp.accept().await.unwrap();
                let handshake = acceptor.accept(stream).await;
                assert_eq!(handshake.is_ok(), expected);
                if let Ok(mut tls) = handshake {
                    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                    let mut data = [0; 4];
                    tls.read_exact(&mut data).await.unwrap();
                    assert_eq!(&data, b"ping");
                    tls.write_all(b"pong").await.unwrap();
                    tls.shutdown().await.unwrap();
                }
            }
        });
        let plain = identity_tls::client_tls(&scope, identity.public_key(), Branch::H2).unwrap();
        let bad = identity_tls::admitted_client_tls(&v, Branch::H2, wrong.clone()).unwrap();
        let good = identity_tls::admitted_client_tls(&v, Branch::H2, secret.clone()).unwrap();
        for (tls, expected) in [(plain, false), (bad, false), (good, true)] {
            let socket = tokio::net::TcpStream::connect(remote).await.unwrap();
            let result = TlsConnector::from(Arc::new(tls))
                .connect(ServerName::try_from(name.to_owned()).unwrap(), socket)
                .await;
            assert_eq!(result.is_ok(), expected);
            if let Ok(mut stream) = result {
                stream.write_all(b"ping").await.unwrap();
                let mut data = [0; 4];
                stream.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"pong");
            }
        }
        server.await.unwrap();

        let server = quinn::Endpoint::server(
            identity_tls::checked_quic_server(&identity, &v, secret.clone(), guard.clone())
                .unwrap(),
            remote,
        )
        .unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let cases = [
            (
                identity_tls::quic_client(&scope, identity.public_key()).unwrap(),
                false,
            ),
            (
                identity_tls::admitted_quic_client(&v, wrong).unwrap(),
                false,
            ),
            (
                identity_tls::admitted_quic_client(&v, secret).unwrap(),
                true,
            ),
        ];
        let server_task = tokio::spawn(async move {
            for expected in [false, false, true] {
                let attempt = server.accept().await.unwrap().await;
                assert_eq!(attempt.is_ok(), expected);
                if let Ok(conn) = attempt {
                    let (mut tx, mut rx) = conn.accept_bi().await.unwrap();
                    let mut data = [0; 4];
                    rx.read_exact(&mut data).await.unwrap();
                    assert_eq!(&data, b"ping");
                    tx.write_all(b"pong").await.unwrap();
                    tx.finish().unwrap();
                    tx.stopped().await.unwrap();
                }
            }
        });
        for (config, expected) in cases {
            client.set_default_client_config(config);
            let result = client.connect(remote, name).unwrap().await;
            assert_eq!(result.is_ok(), expected);
            if let Ok(conn) = result {
                let (mut tx, mut rx) = conn.open_bi().await.unwrap();
                tx.write_all(b"ping").await.unwrap();
                tx.finish().unwrap();
                let mut data = [0; 4];
                rx.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"pong");
                assert_eq!(rx.read_to_end(16).await.unwrap(), Vec::<u8>::new());
            }
        }
        server_task.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admitted_native_application_carriers_and_descriptor_refresh() {
    timeout(DEADLINE, async {
        let tcp = bind().await;
        let remote = tcp.local_addr().unwrap();
        let scope = Scope {
            inbound: "edge".into(),
            endpoint: remote.to_string(),
        };
        let identity = Identity::generate(scope.clone()).unwrap();
        let now = reference_health::unix_now().unwrap();
        let first = value(scope, true, now);
        let first_raw = identity.sign_descriptor(&first).unwrap();
        let mut second = first.clone();
        second.revision = 2;
        let second_raw = identity.sign_descriptor(&second).unwrap();
        let (inbound, users) = config(remote);
        let secret = std::sync::Arc::new(theia::reality_admission::Secret::generate().unwrap());
        let guard = std::sync::Arc::new(
            theia::reality_admission::ReplayGuard::new(65536, now.saturating_sub(121)).unwrap(),
        );
        let server = PreparedFixture::new_admitted(
            tcp,
            &identity,
            &second_raw,
            &inbound,
            &users,
            &policy(true),
            (secret.clone(), guard),
        )
        .unwrap();
        let server = tokio::spawn(server.serve());
        let scratch = Scratch::new();
        for (branch, mode) in [
            (Branch::H2, XhttpMode::StreamOne),
            (Branch::H2, XhttpMode::StreamUp),
            (Branch::H3, XhttpMode::StreamOne),
            (Branch::H3, XhttpMode::StreamUp),
        ] {
            let anchor = anchor(&identity, mode);
            let verified = descriptor::verify(&first_raw, &anchor).unwrap();
            let client = FixtureClient::new_admitted(
                remote,
                &URL_SAFE_NO_PAD.encode(TOKEN),
                verified,
                branch,
                secret.clone(),
            )
            .unwrap();
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = target.local_addr().unwrap().port();
            let echo = tokio::spawn(async move {
                let (mut socket, _) = target.accept().await.unwrap();
                let mut bytes = Vec::new();
                socket.read_to_end(&mut bytes).await.unwrap();
                socket.write_all(&bytes).await.unwrap();
                socket.shutdown().await.unwrap();
            });
            let tunnel = client
                .open(Address::Dns("localhost".into()), port)
                .await
                .unwrap();
            let (mut app, local) = tokio::io::duplex(4096);
            let relay = tokio::spawn(tunnel.relay(local));
            let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
            app.write_all(&payload).await.unwrap();
            app.shutdown().await.unwrap();
            let mut returned = Vec::new();
            app.read_to_end(&mut returned).await.unwrap();
            assert_eq!(returned, payload);
            relay.await.unwrap().unwrap();
            echo.await.unwrap();

            let path = scratch.0.join(format!("{branch:?}-{mode:?}.toml"));
            let store = Store::new(&path, anchor.clone()).unwrap();
            store.initialize(&first_raw, now).unwrap();
            assert_eq!(
                client.refresh(&store).await.unwrap(),
                descriptor::Change::Advanced
            );
            let reopened = Store::new(&path, anchor).unwrap();
            assert_eq!(
                reopened
                    .load(reference_health::unix_now().unwrap())
                    .unwrap()
                    .descriptor()
                    .revision,
                2
            );
            // A client holding the old immutable snapshot cannot overwrite a
            // newer snapshot. It must reopen the verified store first.
            assert!(client.refresh(&reopened).await.is_err());
        }
        server.abort();
    })
    .await
    .unwrap();
}
