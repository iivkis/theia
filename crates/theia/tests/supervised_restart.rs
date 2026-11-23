//! M4.2h: compiled server, actual H2 TLS + H3 QUIC across a supervised
//! two-generation fresh-port cutover. Native Linux private Unix management
//! socket or Windows user-SID protected Named Pipe; no mock IPC or listeners.
#![cfg(any(target_os = "linux", target_os = "windows"))]

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write as _,
    net::{TcpListener as StdTcp, UdpSocket as StdUdp},
    path::Path,
    process::{Child, Command, Output, Stdio},
    time::Duration,
};
use theia::{
    client::H2Client,
    config::{Config, Inbound, Management, ServerDocument, ServerPolicy, ServerSettings, Ui, User},
    h3_client::H3Client,
    protocol::Address,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{sleep, timeout},
};

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Temp(std::path::PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn port(tcp: bool) -> u16 {
    if tcp {
        StdTcp::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    } else {
        StdUdp::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}

fn credential(byte: u8) -> String {
    URL_SAFE_NO_PAD.encode([byte; 32])
}

fn digest(byte: u8) -> String {
    format!("{:x}", Sha256::digest([byte; 32]))
}

fn save(path: &Path, document: &ServerDocument) -> String {
    let bytes = Config::Server(document.clone()).to_toml().unwrap();
    fs::write(path, &bytes).unwrap();
    format!("{:x}", Sha256::digest(bytes.as_bytes()))
}

fn cli(env_key: &str, endpoint: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_theia"))
        .args(args)
        .env(env_key, endpoint)
        .output()
        .expect("native theia CLI")
}

fn revision(env_key: &str, endpoint: &str, value: u64) -> bool {
    let output = cli(env_key, endpoint, &["server", "status"]);
    output.status.success()
        && String::from_utf8_lossy(&output.stdout)
            .contains(&format!("authorization revision={value}"))
}

fn apply(env_key: &str, endpoint: &str, expected: u64, hex: &str, should_succeed: bool) {
    let output = cli(
        env_key,
        endpoint,
        &[
            "server",
            "restart",
            "--apply",
            "--expected-revision",
            &expected.to_string(),
            "--sha256",
            hex,
            "--confirm",
        ],
    );
    assert_eq!(
        output.status.success(),
        should_succeed,
        "unexpected supervised restart result: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if should_succeed {
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains("supervised fresh-port restart applied"));
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(&format!("revision={}", expected + 1))
        );
    }
}

fn write_identity(cert: &Path, key: &Path, generated: &rcgen::CertifiedKey) {
    fs::write(
        cert,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(generated.cert.der())
        ),
    )
    .unwrap();
    fs::write(
        key,
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(generated.key_pair.serialize_der())
        ),
    )
    .unwrap();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(key, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

async fn echo_one(tcp: tokio::net::TcpStream) {
    let (mut input, mut output) = tcp.into_split();
    let _ = tokio::io::copy(&mut input, &mut output).await;
    let _ = output.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_supervisor_prepares_then_switches_h2_h3_and_drains_old_sessions() {
    timeout(Duration::from_secs(55), async {
        let base = std::env::temp_dir().join(format!(
            "theia-supervised-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir(&base).unwrap();
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let _temp = Temp(base.clone());
        let old_cert = base.join("old-cert.pem");
        let old_key = base.join("old-key.pem");
        let new_cert = base.join("new-cert.pem");
        let new_key = base.join("new-key.pem");
        let config_path = base.join("server.toml");
        let old_identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let new_identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        write_identity(&old_cert, &old_key, &old_identity);
        write_identity(&new_cert, &new_key, &new_identity);
        let mut roots = RootCertStore::empty();
        roots.add(old_identity.cert.der().clone()).unwrap();
        roots.add(new_identity.cert.der().clone()).unwrap();

        let old_tcp = port(true);
        let old_udp = port(false);
        let mut document = ServerDocument {
            schema_version: 1,
            server: ServerSettings {
                enabled: true,
                inbounds: vec![Inbound {
                    id: "edge".into(),
                    allowed_user_ids: vec!["device-a".into()],
                    h2_listen: format!("127.0.0.1:{old_tcp}"),
                    quic_listen: format!("127.0.0.1:{old_udp}"),
                    server_name: "localhost".into(),
                    tls_cert: format!("file:{}", old_cert.display()),
                    tls_key: format!("file:{}", old_key.display()),
                }],
                users: vec![User {
                    id: "device-a".into(),
                    token_sha256: digest(0x42),
                    disabled: false,
                }],
                policy: ServerPolicy {
                    allow_private_ips: true,
                    max_connections_per_user: 6,
                    max_connections_total: 16,
                    connect_timeout_ms: 2000,
                },
            },
            management: Management {
                ipc: "auto".into(),
                log_level: "info".into(),
            },
            ui: Ui {
                language: "ru".into(),
            },
        };
        save(&config_path, &document);
        #[cfg(target_os = "linux")]
        let (env_key, endpoint) = ("THEIA_CONTROL_DIR", base.to_string_lossy().into_owned());
        #[cfg(target_os = "windows")]
        let (env_key, endpoint) = (
            "THEIA_CONTROL_PIPE",
            format!("m42h{}{}", std::process::id(), old_tcp),
        );
        let mut server = Running(
            Command::new(env!("CARGO_BIN_EXE_theia"))
                .args(["server", "run", "--config"])
                .arg(&config_path)
                .env(env_key, &endpoint)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        timeout(Duration::from_secs(12), async {
            loop {
                if revision(env_key, &endpoint, 1) {
                    break;
                }
                assert!(server.0.try_wait().unwrap().is_none(), "server exited");
                sleep(Duration::from_millis(35)).await;
            }
        })
        .await
        .expect("compiled server must become healthy at revision 1");

        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            while let Ok((socket, _)) = echo.accept().await {
                tokio::spawn(echo_one(socket));
            }
        });
        let address = Address::V4([127, 0, 0, 1]);
        let old_h2 = H2Client::new(
            &format!("127.0.0.1:{old_tcp}"),
            "localhost",
            &credential(0x42),
            roots.clone(),
        )
        .unwrap();
        let old_h3 = H3Client::new(
            format!("127.0.0.1:{old_udp}").parse().unwrap(),
            "localhost",
            &credential(0x42),
            roots.clone(),
        )
        .unwrap();
        // Keep actual authenticated H2 and H3 tunnels alive through cutover.
        let h2_tunnel = old_h2.open(address.clone(), echo_port).await.unwrap();
        let h3_tunnel = old_h3.open(address.clone(), echo_port).await.unwrap();

        let mut next = document.clone();
        let next_tcp = port(true);
        let next_udp = port(false);
        next.server.inbounds[0].h2_listen = format!("127.0.0.1:{next_tcp}");
        next.server.inbounds[0].quic_listen = format!("127.0.0.1:{next_udp}");
        next.server.inbounds[0].tls_cert = format!("file:{}", new_cert.display());
        next.server.inbounds[0].tls_key = format!("file:{}", new_key.display());
        let next_sha = save(&config_path, &next);

        apply(env_key, &endpoint, 1, &"0".repeat(64), false);
        assert!(revision(env_key, &endpoint, 1));

        let occupied_tcp = StdTcp::bind("127.0.0.1:0").unwrap();
        let mut busy = next.clone();
        busy.server.inbounds[0].h2_listen = occupied_tcp.local_addr().unwrap().to_string();
        let hash = save(&config_path, &busy);
        apply(env_key, &endpoint, 1, &hash, false);
        drop(occupied_tcp);
        assert!(revision(env_key, &endpoint, 1));

        let occupied_udp = StdUdp::bind("127.0.0.1:0").unwrap();
        busy = next.clone();
        busy.server.inbounds[0].quic_listen = occupied_udp.local_addr().unwrap().to_string();
        let hash = save(&config_path, &busy);
        apply(env_key, &endpoint, 1, &hash, false);
        drop(occupied_udp);
        assert!(revision(env_key, &endpoint, 1));

        let mut quota_changed = next.clone();
        quota_changed.server.policy.max_connections_total += 1;
        let hash = save(&config_path, &quota_changed);
        apply(env_key, &endpoint, 1, &hash, false);
        assert!(revision(env_key, &endpoint, 1));

        let mut same_port = next.clone();
        same_port.server.inbounds[0].h2_listen = document.server.inbounds[0].h2_listen.clone();
        let hash = save(&config_path, &same_port);
        apply(env_key, &endpoint, 1, &hash, false);
        assert!(revision(env_key, &endpoint, 1));

        // Hash computed BEFORE an external writer modifies the file must
        // fail content binding, not accidentally load another candidate.
        save(&config_path, &next);
        fs::OpenOptions::new()
            .append(true)
            .open(&config_path)
            .unwrap()
            .write_all(b"\n# concurrent operator edit\n")
            .unwrap();
        apply(env_key, &endpoint, 1, &next_sha, false);
        assert!(revision(env_key, &endpoint, 1));

        let hash = save(&config_path, &next);
        apply(env_key, &endpoint, 1, &hash, true);
        assert!(revision(env_key, &endpoint, 2));
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "supervisor died after cutover"
        );
        apply(env_key, &endpoint, 1, &hash, false);
        assert!(revision(env_key, &endpoint, 2));

        let new_h2 = H2Client::new(
            &format!("127.0.0.1:{next_tcp}"),
            "localhost",
            &credential(0x42),
            roots.clone(),
        )
        .unwrap();
        let new_h3 = H3Client::new(
            format!("127.0.0.1:{next_udp}").parse().unwrap(),
            "localhost",
            &credential(0x42),
            roots.clone(),
        )
        .unwrap();
        assert!(new_h2.open(address.clone(), echo_port).await.is_ok());
        assert!(new_h3.open(address.clone(), echo_port).await.is_ok());

        // Previous authenticated tunnels can finish within bounded drain.
        let (mut h2_app, h2_local) = tokio::io::duplex(256);
        let h2_relay = tokio::spawn(async move { h2_tunnel.relay(h2_local).await });
        h2_app.write_all(b"old-alive!").await.unwrap();
        let mut h2_reply = [0u8; 10];
        h2_app.read_exact(&mut h2_reply).await.unwrap();
        assert_eq!(&h2_reply, b"old-alive!");
        h2_app.shutdown().await.unwrap();
        h2_relay.await.unwrap().unwrap();
        let (mut h3_app, h3_local) = tokio::io::duplex(256);
        let h3_relay = tokio::spawn(async move { h3_tunnel.relay(h3_local).await });
        h3_app.write_all(b"old-alive!").await.unwrap();
        let mut h3_reply = [0u8; 10];
        h3_app.read_exact(&mut h3_reply).await.unwrap();
        assert_eq!(&h3_reply, b"old-alive!");
        h3_app.shutdown().await.unwrap();
        h3_relay.await.unwrap().unwrap();

        // Neither accepting NEW old connections nor approving NEW requests
        // over existing old connections is allowed after commit.
        assert!(old_h2.open(address.clone(), echo_port).await.is_err());
        assert!(old_h3.open(address.clone(), echo_port).await.is_err());

        // The protected IPC preflight and CAS controller must now belong to
        // generation 2, so ordinary auth-only Apply continues working.
        document = next;
        document.server.users[0].token_sha256 = digest(0x43);
        save(&config_path, &document);
        let auth_apply = cli(
            env_key,
            &endpoint,
            &["server", "reload", "--expected-revision", "2"],
        );
        assert!(
            auth_apply.status.success(),
            "post-cutover authorization CAS must work: {}",
            String::from_utf8_lossy(&auth_apply.stderr)
        );
        assert!(revision(env_key, &endpoint, 3));
        let rotated_h2 = H2Client::new(
            &format!("127.0.0.1:{next_tcp}"),
            "localhost",
            &credential(0x43),
            roots.clone(),
        )
        .unwrap();
        let rotated_h3 = H3Client::new(
            format!("127.0.0.1:{next_udp}").parse().unwrap(),
            "localhost",
            &credential(0x43),
            roots,
        )
        .unwrap();
        assert!(rotated_h2.open(address.clone(), echo_port).await.is_ok());
        assert!(rotated_h3.open(address, echo_port).await.is_ok());
        echo_task.abort();
        drop(server);
    })
    .await
    .expect("native supervised H2/H3 cutover must finish without hanging");
}
