//! M4.2b1b: compiled Linux server, real H2 + H3 and private IPC Apply.
//! No public network, TUI Apply or system proxy modifications.
#![cfg(target_os = "linux")]
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{TcpListener as StdTcp, UdpSocket},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use theia::{
    client::{ClientError, H2Client},
    config::{Config, Inbound, Management, ServerDocument, ServerPolicy, ServerSettings, Ui, User},
    h3_client::H3Client,
    management::{query_in, ManagementError, StatusCommand, StatusReply},
    protocol::Address,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{sleep, timeout},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn port(tcp: bool) -> u16 {
    if tcp {
        StdTcp::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    } else {
        UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }
}
fn save(path: &Path, doc: &ServerDocument) {
    fs::write(path, Config::Server(doc.clone()).to_toml().unwrap()).unwrap();
}
fn token(byte: u8) -> String { URL_SAFE_NO_PAD.encode([byte; 32]) }
fn hash(byte: u8) -> String { format!("{:x}", Sha256::digest([byte; 32])) }
async fn echo_one(tcp: tokio::net::TcpStream) {
    let (mut input, mut output) = tcp.into_split();
    let _ = tokio::io::copy(&mut input, &mut output).await;
    let _ = output.shutdown().await;
}
fn cli(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_theia"))
        .args(args)
        .env("THEIA_CONTROL_DIR", dir)
        .output()
        .unwrap()
}
async fn has_revision(dir: &Path, revision: u64) {
    assert_eq!(
        query_in(dir, StatusCommand::Status).await,
        Ok(StatusReply::RunningRevision { inbounds: 1, revision })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn atomic_apply_rotates_h2_and_h3_without_dropping_open_tunnels_or_quotas() {
    timeout(Duration::from_secs(35), async {
        let dir = std::env::temp_dir().join(format!("theia-apply-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let toml = dir.join("server.toml");
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(generated.cert.der()));
        let key = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(generated.key_pair.serialize_der()));
        fs::write(&cert_path, &cert).unwrap();
        fs::write(&key_path, &key).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(generated.cert.der().clone()).unwrap();
        let tcp = port(true);
        let udp = port(false);
        let mut doc = ServerDocument {
            schema_version: 1,
            server: ServerSettings {
                enabled: true,
                inbounds: vec![Inbound {
                    id: "edge".into(),
                    allowed_user_ids: vec!["device-a".into()],
                    h2_listen: format!("127.0.0.1:{tcp}"),
                    quic_listen: format!("127.0.0.1:{udp}"),
                    server_name: "localhost".into(),
                    tls_cert: format!("file:{}", cert_path.display()),
                    tls_key: format!("file:{}", key_path.display()),
                }],
                users: vec![User {
                    id: "device-a".into(),
                    token_sha256: hash(0x42),
                    disabled: false,
                }],
                policy: ServerPolicy {
                    allow_private_ips: true,
                    max_connections_per_user: 5,
                    max_connections_total: 12,
                    connect_timeout_ms: 1500,
                },
            },
            management: Management {
                ipc: "auto".into(), log_level: "info".into(),
            },
            ui: Ui { language: "ru".into() },
        };
        save(&toml, &doc);
        let mut server = Running(Command::new(env!("CARGO_BIN_EXE_theia"))
            .args(["server", "run", "--config"]).arg(&toml)
            .env("THEIA_CONTROL_DIR", &dir)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().unwrap());
        timeout(Duration::from_secs(8), async {
            loop {
                if query_in(&dir, StatusCommand::Status).await ==
                    Ok(StatusReply::RunningRevision { inbounds: 1, revision: 1 }) { break; }
                assert!(server.0.try_wait().unwrap().is_none(), "server exited");
                sleep(Duration::from_millis(25)).await;
            }
        }).await.unwrap();
        has_revision(&dir, 1).await;

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = target.accept().await else { break; };
                tokio::spawn(echo_one(tcp));
            }
        });
        let addr = Address::V4([127, 0, 0, 1]);
        let h2old = H2Client::new(&format!("127.0.0.1:{tcp}"), "localhost", &token(0x42), roots.clone()).unwrap();
        let h3old = H3Client::new(format!("127.0.0.1:{udp}").parse().unwrap(), "localhost", &token(0x42), roots.clone()).unwrap();
        let h2_open = h2old.open(addr.clone(), target_port).await.unwrap();
        let h3_open = h3old.open(addr.clone(), target_port).await.unwrap();

        // Stage is a safe read-only preview, not an implicit commit.
        doc.server.users[0].token_sha256 = hash(0x43);
        save(&toml, &doc);
        assert_eq!(query_in(&dir, StatusCommand::CheckReload).await, Ok(StatusReply::Compatible));
        has_revision(&dir, 1).await;

        assert_eq!(
            query_in(&dir, StatusCommand::ApplyReload { expected_revision: 1 }).await,
            Ok(StatusReply::Applied { revision: 2 })
        );
        has_revision(&dir, 2).await;
        assert_eq!(query_in(&dir, StatusCommand::ApplyReload { expected_revision: 1 }).await,
            Err(ManagementError::CandidateRejected), "stale CAS must not apply twice");
        let old_h2 = h2old.open(addr.clone(), target_port).await.err();
        let old_h3 = h3old.open(addr.clone(), target_port).await.err();
        assert_eq!(old_h2, Some(ClientError::Unauthorized));
        assert_eq!(old_h3, Some(ClientError::Unauthorized));
        let h2new = H2Client::new(&format!("127.0.0.1:{tcp}"), "localhost", &token(0x43), roots.clone()).unwrap();
        let h3new = H3Client::new(format!("127.0.0.1:{udp}").parse().unwrap(), "localhost", &token(0x43), roots.clone()).unwrap();
        assert!(h2new.open(addr.clone(), target_port).await.is_ok());
        assert!(h3new.open(addr.clone(), target_port).await.is_ok());

        // Pre-commit H2/H3 streams still echo after the token is revoked.
        for old in [0u8, 1u8] {
            let (mut app, local) = tokio::io::duplex(256);
            let relay = if old == 0 {
                tokio::spawn(async move { h2_open.relay(local).await.map_err(|e| format!("{e}")) })
            } else {
                tokio::spawn(async move { h3_open.relay(local).await.map_err(|e| format!("{e}")) })
            };
            app.write_all(b"still-open").await.unwrap();
            let mut reply = [0; 10];
            app.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"still-open");
            app.shutdown().await.unwrap();
            relay.await.unwrap().unwrap();
        }

        // Saved candidate is invalid: no revision increment, no changed auth.
        let stable = doc.clone();
        doc.server.policy.max_connections_total += 1;
        save(&toml, &doc);
        assert_eq!(
            query_in(&dir, StatusCommand::ApplyReload { expected_revision: 2 }).await,
            Err(ManagementError::CandidateRejected)
        );
        has_revision(&dir, 2).await;
        doc = stable;
        save(&toml, &doc);
        fs::write(&cert_path, b"swapped PEM").unwrap();
        assert_eq!(
            query_in(&dir, StatusCommand::ApplyReload { expected_revision: 2 }).await,
            Err(ManagementError::CandidateRejected)
        );
        has_revision(&dir, 2).await;
        fs::write(&cert_path, &cert).unwrap();

        let rejected = tokio::task::spawn_blocking({
            let dir = dir.clone();
            move || cli(&dir, &["server", "reload", "--expected-revision", "1"])
        }).await.unwrap();
        assert!(!rejected.status.success());
        assert!(!String::from_utf8_lossy(&rejected.stderr).contains(&token(0x43)));
        let status = tokio::task::spawn_blocking({
            let dir = dir.clone();
            move || cli(&dir, &["server", "status"])
        }).await.unwrap();
        assert!(status.status.success());
        assert!(String::from_utf8_lossy(&status.stdout).contains("revision=2"));

        echo_task.abort();
        drop(server);
        fs::remove_dir_all(dir).unwrap();
    }).await.expect("H2/H3 apply E2E must stay bounded");
}
