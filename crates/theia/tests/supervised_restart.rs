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

/// Read-only operator fingerprint. Returns only the domain-separated digest,
/// never a certificate, private key, or bearer in stdout.
fn material_fingerprint(config: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_theia"))
        .args(["server", "tls", "fingerprint", "--config"])
        .arg(config)
        .output()
        .unwrap();
    if !output.status.success() {
        // Invalid TLS candidates must still be sent to the native manager
        // for explicit fail-closed validation, with no valid key exposure.
        return "0".repeat(64);
    }
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    stdout
        .strip_prefix("theia-tls-pem-v1 sha256=")
        .and_then(|value| value.strip_suffix('\n'))
        .expect("read-only fingerprint output format")
        .to_owned()
}

fn apply_with_pin(
    env_key: &str,
    endpoint: &str,
    expected: u64,
    hex: &str,
    material_sha: &str,
    should_succeed: bool,
) {
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
            "--tls-sha256",
            material_sha,
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
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("supervised H2/H3 restart applied")
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(&format!("revision={}", expected + 1))
        );
    }
}

fn apply(
    env_key: &str,
    endpoint: &str,
    expected: u64,
    hex: &str,
    should_succeed: bool,
    config: &Path,
) {
    let material_sha = material_fingerprint(config);
    apply_with_pin(
        env_key,
        endpoint,
        expected,
        hex,
        &material_sha,
        should_succeed,
    );
}

fn rollback(env_key: &str, endpoint: &str, expected: u64, succeeds: bool) {
    let output = cli(
        env_key,
        endpoint,
        &[
            "server",
            "tls",
            "rollback",
            "--apply",
            "--expected-revision",
            &expected.to_string(),
            "--confirm",
        ],
    );
    assert_eq!(
        output.status.success(),
        succeeds,
        "rollback CAS: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    if succeeds {
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains("previous same-port H2/H3 TLS identity restored from memory"));
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(&format!("revision={}", expected + 1))
        );
    }
}

fn check_rollback(env_key: &str, endpoint: &str, revision: u64) -> bool {
    let output = cli(env_key, endpoint, &["server", "tls", "rollback", "--check"]);
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.contains(&format!("revision={revision}"))
        && text.contains("remaining_seconds=")
        && text.contains("no change applied")
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
                    security_mode: Default::default(),
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
        assert!(!check_rollback(env_key, &endpoint, 1));
        rollback(env_key, &endpoint, 1, false);

        let mut next = document.clone();
        let next_tcp = port(true);
        let next_udp = port(false);
        next.server.inbounds[0].h2_listen = format!("127.0.0.1:{next_tcp}");
        next.server.inbounds[0].quic_listen = format!("127.0.0.1:{next_udp}");
        next.server.inbounds[0].tls_cert = format!("file:{}", new_cert.display());
        next.server.inbounds[0].tls_key = format!("file:{}", new_key.display());
        let next_sha = save(&config_path, &next);

        apply(env_key, &endpoint, 1, &"0".repeat(64), false, &config_path);
        assert!(revision(env_key, &endpoint, 1));

        let occupied_tcp = StdTcp::bind("127.0.0.1:0").unwrap();
        let mut busy = next.clone();
        busy.server.inbounds[0].h2_listen = occupied_tcp.local_addr().unwrap().to_string();
        let hash = save(&config_path, &busy);
        apply(env_key, &endpoint, 1, &hash, false, &config_path);
        drop(occupied_tcp);
        assert!(revision(env_key, &endpoint, 1));

        let occupied_udp = StdUdp::bind("127.0.0.1:0").unwrap();
        busy = next.clone();
        busy.server.inbounds[0].quic_listen = occupied_udp.local_addr().unwrap().to_string();
        let hash = save(&config_path, &busy);
        apply(env_key, &endpoint, 1, &hash, false, &config_path);
        drop(occupied_udp);
        assert!(revision(env_key, &endpoint, 1));

        let mut quota_changed = next.clone();
        quota_changed.server.policy.max_connections_total += 1;
        let hash = save(&config_path, &quota_changed);
        apply(env_key, &endpoint, 1, &hash, false, &config_path);
        assert!(revision(env_key, &endpoint, 1));

        let mut same_port = next.clone();
        same_port.server.inbounds[0].h2_listen = document.server.inbounds[0].h2_listen.clone();
        let hash = save(&config_path, &same_port);
        apply(env_key, &endpoint, 1, &hash, false, &config_path);
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
        apply(env_key, &endpoint, 1, &next_sha, false, &config_path);
        assert!(revision(env_key, &endpoint, 1));

        let hash = save(&config_path, &next);
        apply(env_key, &endpoint, 1, &hash, true, &config_path);
        assert!(revision(env_key, &endpoint, 2));
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "supervisor died after cutover"
        );
        apply(env_key, &endpoint, 1, &hash, false, &config_path);
        assert!(revision(env_key, &endpoint, 2));
        assert!(!check_rollback(env_key, &endpoint, 2));
        rollback(env_key, &endpoint, 2, false);

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

/// M4.2i: rotate strict TLS1.3 identity on the SAME H2/TCP and H3/QUIC
/// ports without rebinding either listener or aborting authenticated tunnels.
/// The revision must advance only after both fresh TLS configs are staged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_port_tls_identity_rotation_preserves_h2_h3_and_rejects_invalid_candidate() {
    timeout(Duration::from_secs(50), async {
        let base = std::env::temp_dir().join(format!(
            "theia-tls-rotate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
        let next_cert = base.join("new-cert.pem");
        let next_key = base.join("new-key.pem");
        let malformed_cert = base.join("broken-cert.pem");
        let config_path = base.join("server.toml");
        let old_identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let next_identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        write_identity(&old_cert, &old_key, &old_identity);
        write_identity(&next_cert, &next_key, &next_identity);
        fs::write(&malformed_cert, "not a certificate").unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(old_identity.cert.der().clone()).unwrap();
        roots.add(next_identity.cert.der().clone()).unwrap();
        let tcp_port = port(true);
        let udp_port = port(false);
        let mut document = ServerDocument {
            schema_version: 1,
            server: ServerSettings {
                enabled: true,
                inbounds: vec![Inbound {
                    id: "edge".into(),
                    allowed_user_ids: vec!["device-a".into()],
                    h2_listen: format!("127.0.0.1:{tcp_port}"),
                    quic_listen: format!("127.0.0.1:{udp_port}"),
                    server_name: "localhost".into(),
                    tls_cert: format!("file:{}", old_cert.display()),
                    security_mode: Default::default(),
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
            format!("m42i{}{}", std::process::id(), tcp_port),
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
        .unwrap();
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            while let Ok((socket, _)) = echo.accept().await {
                tokio::spawn(echo_one(socket));
            }
        });
        let address = Address::V4([127, 0, 0, 1]);
        let previous_h2 = H2Client::new(
            &format!("127.0.0.1:{tcp_port}"),
            "localhost",
            &credential(0x42),
            roots.clone(),
        )
        .unwrap();
        let previous_h3 = H3Client::new(
            format!("127.0.0.1:{udp_port}").parse().unwrap(),
            "localhost",
            &credential(0x42),
            roots.clone(),
        )
        .unwrap();
        let h2_tunnel = previous_h2.open(address.clone(), echo_port).await.unwrap();
        let h3_tunnel = previous_h3.open(address.clone(), echo_port).await.unwrap();
        assert!(!check_rollback(env_key, &endpoint, 1));
        rollback(env_key, &endpoint, 1, false);

        let mut candidate = document.clone();
        candidate.server.inbounds[0].tls_cert = format!("file:{}", next_cert.display());
        candidate.server.inbounds[0].tls_key = format!("file:{}", next_key.display());
        let hash = save(&config_path, &candidate);
        let check = cli(env_key, &endpoint, &["server", "restart", "--check"]);
        assert!(
            check.status.success()
                && String::from_utf8_lossy(&check.stdout).contains("same-port TLS"),
            "same-port identity rotation must have an explicit ready classification: {}",
            String::from_utf8_lossy(&check.stdout),
        );
        // TOML is unchanged, yet both PEM files have been replaced with
        // ANOTHER valid TLS identity after the operator inspected them.
        // A SHA of TOML alone would accept this unauthorized identity.
        let operator_tls_pin = material_fingerprint(&config_path);
        let substituted = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        write_identity(&next_cert, &next_key, &substituted);
        assert_ne!(material_fingerprint(&config_path), operator_tls_pin);
        apply_with_pin(env_key, &endpoint, 1, &hash, &operator_tls_pin, false);
        assert!(revision(env_key, &endpoint, 1));
        assert!(server.0.try_wait().unwrap().is_none());
        write_identity(&next_cert, &next_key, &next_identity);
        assert_eq!(material_fingerprint(&config_path), operator_tls_pin);

        // Candidate content and expected revision must be exact.
        apply(env_key, &endpoint, 1, &"0".repeat(64), false, &config_path);
        assert!(revision(env_key, &endpoint, 1));
        let mut invalid = candidate.clone();
        invalid.server.inbounds[0].tls_cert = format!("file:{}", malformed_cert.display());
        let bad_hash = save(&config_path, &invalid);
        apply(env_key, &endpoint, 1, &bad_hash, false, &config_path);
        assert!(revision(env_key, &endpoint, 1));
        let mut quota = candidate.clone();
        quota.server.policy.max_connections_per_user += 1;
        let quota_hash = save(&config_path, &quota);
        apply(env_key, &endpoint, 1, &quota_hash, false, &config_path);
        assert!(revision(env_key, &endpoint, 1));
        // Fresh-port path is NOT invoked: both existing TCP and UDP bind
        // addresses remain the same throughout this confirmed rotation.
        let real_hash = save(&config_path, &candidate);
        assert_eq!(real_hash, hash);
        apply(env_key, &endpoint, 1, &real_hash, true, &config_path);
        assert!(revision(env_key, &endpoint, 2));
        assert!(check_rollback(env_key, &endpoint, 2));
        assert!(server.0.try_wait().unwrap().is_none());
        apply(env_key, &endpoint, 1, &real_hash, false, &config_path);
        assert!(revision(env_key, &endpoint, 2));

        // A client trusting ONLY the new CA must see the NEW certificate on
        // BOTH original TCP and UDP addresses, not a newly bound port.
        let mut new_roots = RootCertStore::empty();
        new_roots.add(next_identity.cert.der().clone()).unwrap();
        let new_h2 = H2Client::new(
            &format!("127.0.0.1:{tcp_port}"),
            "localhost",
            &credential(0x42),
            new_roots.clone(),
        )
        .unwrap();
        let new_h3 = H3Client::new(
            format!("127.0.0.1:{udp_port}").parse().unwrap(),
            "localhost",
            &credential(0x42),
            new_roots,
        )
        .unwrap();
        assert!(new_h2.open(address.clone(), echo_port).await.is_ok());
        assert!(new_h3.open(address.clone(), echo_port).await.is_ok());

        // Previously authenticated streams remain alive across the same-port
        // TLS swap. This is NEW handshakes-only, not hard revoke/migration.
        let mut h2_open = Some(h2_tunnel);
        let mut h3_open = Some(h3_tunnel);
        for old in [0u8, 1u8] {
            let (mut app, local) = tokio::io::duplex(256);
            let relay = if old == 0 {
                let tunnel = h2_open.take().unwrap();
                tokio::spawn(async move {
                    tunnel
                        .relay(local)
                        .await
                        .map_err(|error| format!("{error}"))
                })
            } else {
                let tunnel = h3_open.take().unwrap();
                tokio::spawn(async move {
                    tunnel
                        .relay(local)
                        .await
                        .map_err(|error| format!("{error}"))
                })
            };
            app.write_all(b"still-live").await.unwrap();
            let mut response = [0u8; 10];
            app.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"still-live");
            app.shutdown().await.unwrap();
            relay.await.unwrap().unwrap();
        }

        // Existing auth-only CAS is immediately usable after the rotation.
        document = candidate;
        document.server.users[0].token_sha256 = digest(0x43);
        save(&config_path, &document);
        let reloaded = cli(
            env_key,
            &endpoint,
            &["server", "reload", "--expected-revision", "2"],
        );
        assert!(
            reloaded.status.success(),
            "post-rotation CAS must use the current TLS baseline: {}",
            String::from_utf8_lossy(&reloaded.stderr)
        );
        assert!(revision(env_key, &endpoint, 3));
        assert!(check_rollback(env_key, &endpoint, 3));
        rollback(env_key, &endpoint, 2, false);
        assert!(revision(env_key, &endpoint, 3));

        // Repeating the SAME-port rotation after an auth-only CAS must use
        // its newest user/token baseline. This protects against stale View
        // documents that would falsely classify valid PEM-only candidates as
        // an unauthorized user mutation.
        let mut rotate_again = document.clone();
        rotate_again.server.inbounds[0].tls_cert = format!("file:{}", old_cert.display());
        rotate_again.server.inbounds[0].tls_key = format!("file:{}", old_key.display());
        let again_hash = save(&config_path, &rotate_again);
        apply(env_key, &endpoint, 3, &again_hash, true, &config_path);
        assert!(revision(env_key, &endpoint, 4));
        let mut restored_ca = RootCertStore::empty();
        restored_ca.add(old_identity.cert.der().clone()).unwrap();
        let restored_h2 = H2Client::new(
            &format!("127.0.0.1:{tcp_port}"),
            "localhost",
            &credential(0x43),
            restored_ca.clone(),
        )
        .unwrap();
        let restored_h3 = H3Client::new(
            format!("127.0.0.1:{udp_port}").parse().unwrap(),
            "localhost",
            &credential(0x43),
            restored_ca,
        )
        .unwrap();
        // Keep open authenticated tunnels on the identity about to be
        // retired by rollback. Neither H2 nor QUIC sessions are migrated
        // or aborted just because new handshakes switch certificates.
        let still_h2 = restored_h2.open(address.clone(), echo_port).await.unwrap();
        let still_h3 = restored_h3.open(address.clone(), echo_port).await.unwrap();

        // The second same-port TLS rotation supersedes the older undo.
        // Corrupt the previous certificate on disk AFTER the CAS. Rollback
        // must use retained production TLS configs and preserve the
        // authorization token changed between those two rotations.
        assert!(check_rollback(env_key, &endpoint, 4));
        fs::write(&next_cert, "corrupted disk certificate").unwrap();
        fs::write(&next_key, "corrupted disk private key").unwrap();
        rollback(env_key, &endpoint, 3, false);
        assert!(revision(env_key, &endpoint, 4));
        rollback(env_key, &endpoint, 4, true);
        assert!(revision(env_key, &endpoint, 5));
        assert!(!check_rollback(env_key, &endpoint, 5));
        rollback(env_key, &endpoint, 5, false);
        assert!(revision(env_key, &endpoint, 5));

        let mut previous_only = RootCertStore::empty();
        previous_only.add(next_identity.cert.der().clone()).unwrap();
        let recovered_h2 = H2Client::new(
            &format!("127.0.0.1:{tcp_port}"),
            "localhost",
            &credential(0x43),
            previous_only.clone(),
        )
        .unwrap();
        let recovered_h3 = H3Client::new(
            format!("127.0.0.1:{udp_port}").parse().unwrap(),
            "localhost",
            &credential(0x43),
            previous_only,
        )
        .unwrap();
        assert!(recovered_h2.open(address.clone(), echo_port).await.is_ok());
        assert!(recovered_h3.open(address.clone(), echo_port).await.is_ok());
        let (mut h2_app, h2_local) = tokio::io::duplex(128);
        let h2_task = tokio::spawn(async move { still_h2.relay(h2_local).await });
        h2_app.write_all(b"old-alive!").await.unwrap();
        let mut from_h2 = [0u8; 10];
        h2_app.read_exact(&mut from_h2).await.unwrap();
        assert_eq!(&from_h2, b"old-alive!");
        h2_app.shutdown().await.unwrap();
        h2_task.await.unwrap().unwrap();

        let (mut h3_app, h3_local) = tokio::io::duplex(128);
        let h3_task = tokio::spawn(async move { still_h3.relay(h3_local).await });
        h3_app.write_all(b"old-alive!").await.unwrap();
        let mut from_h3 = [0u8; 10];
        h3_app.read_exact(&mut from_h3).await.unwrap();
        assert_eq!(&from_h3, b"old-alive!");
        h3_app.shutdown().await.unwrap();
        h3_task.await.unwrap().unwrap();
        assert!(server.0.try_wait().unwrap().is_none());
        echo_task.abort();
    })
    .await
    .expect("native H2+H3 same-port TLS identity rotation must complete");
}

fn quota_apply(env_key: &str, endpoint: &str, expected: u64, sha: &str, succeeds: bool) {
    let output = cli(
        env_key,
        endpoint,
        &[
            "server",
            "quota",
            "--apply",
            "--expected-revision",
            &expected.to_string(),
            "--sha256",
            sha,
            "--confirm",
        ],
    );
    assert_eq!(
        output.status.success(),
        succeeds,
        "quota CAS: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if succeeds {
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("quota caps applied live"),
            "a successful quota update must acknowledge real occupancy resize"
        );
    }
}

/// M4.2j: The OS-level H2/TLS and H3/QUIC servers retain REAL authenticated
/// streams, and shrinking BOTH caps below occupancy must NOT cut them off or
/// allow new sessions. Growing beyond startup caps must actually admit more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_live_quota_contraction_and_growth_hold_h2_h3_session_permits() {
    timeout(Duration::from_secs(65), async {
        let base = std::env::temp_dir().join(format!(
            "theia-quota-{}-{}",
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
        let cert = base.join("cert.pem");
        let key = base.join("key.pem");
        let config = base.join("server.toml");
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        write_identity(&cert, &key, &identity);
        let mut roots = RootCertStore::empty();
        roots.add(identity.cert.der().clone()).unwrap();
        let tcp_port = port(true);
        let udp_port = port(false);
        let mut document = ServerDocument {
            schema_version: 1,
            server: ServerSettings {
                enabled: true,
                inbounds: vec![Inbound {
                    id: "edge".into(),
                    allowed_user_ids: vec!["device-a".into()],
                    h2_listen: format!("127.0.0.1:{tcp_port}"),
                    quic_listen: format!("127.0.0.1:{udp_port}"),
                    server_name: "localhost".into(),
                    tls_cert: format!("file:{}", cert.display()),
                    security_mode: Default::default(),
                    tls_key: format!("file:{}", key.display()),
                }],
                users: vec![User {
                    id: "device-a".into(),
                    token_sha256: digest(0x42),
                    disabled: false,
                }],
                policy: ServerPolicy {
                    allow_private_ips: true,
                    max_connections_per_user: 2,
                    max_connections_total: 2,
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
        save(&config, &document);
        #[cfg(target_os = "linux")]
        let (env_key, endpoint) = ("THEIA_CONTROL_DIR", base.to_string_lossy().into_owned());
        #[cfg(target_os = "windows")]
        let (env_key, endpoint) = (
            "THEIA_CONTROL_PIPE",
            format!("m42j{}{}", std::process::id(), tcp_port),
        );
        let mut server = Running(
            Command::new(env!("CARGO_BIN_EXE_theia"))
                .args(["server", "run", "--config"])
                .arg(&config)
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
        .expect("compiled server must publish a native control endpoint");
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            while let Ok((socket, _)) = echo.accept().await {
                tokio::spawn(echo_one(socket));
            }
        });
        let address = Address::V4([127, 0, 0, 1]);
        let old_h2 = H2Client::new(
            &format!("127.0.0.1:{tcp_port}"),
            "localhost",
            &credential(0x42),
            roots.clone(),
        )
        .unwrap();
        let old_h3 = H3Client::new(
            format!("127.0.0.1:{udp_port}").parse().unwrap(),
            "localhost",
            &credential(0x42),
            roots.clone(),
        )
        .unwrap();
        let old_tunnel_h2 = old_h2.open(address.clone(), echo_port).await.unwrap();
        let old_tunnel_h3 = old_h3.open(address.clone(), echo_port).await.unwrap();

        // Wrong SHA, invalid limit, and non-quota changes fail without
        // changing either bound listener, revision or held tunnel.
        let mut shrink = document.clone();
        shrink.server.policy.max_connections_total = 1;
        shrink.server.policy.max_connections_per_user = 1;
        let sha = save(&config, &shrink);
        let advisory = cli(env_key, &endpoint, &["server", "quota", "--check"]);
        assert!(
            advisory.status.success()
                && String::from_utf8_lossy(&advisory.stdout).contains("quota-only candidate ready"),
            "quota check must be non-mutating: {}",
            String::from_utf8_lossy(&advisory.stderr),
        );
        assert!(revision(env_key, &endpoint, 1));
        quota_apply(env_key, &endpoint, 1, &"0".repeat(64), false);

        let mut mixed = shrink.clone();
        mixed.server.policy.allow_private_ips = false;
        quota_apply(env_key, &endpoint, 1, &save(&config, &mixed), false);
        // The typed serializer correctly refuses invalid caps; create an
        // intentionally malformed-on-disk candidate to exercise the native
        // manager's own structural validator, not the test helper.
        let invalid_toml = Config::Server(shrink.clone()).to_toml().unwrap().replace(
            "max_connections_per_user = 1",
            "max_connections_per_user = 3",
        );
        assert!(invalid_toml.contains("max_connections_per_user = 3"));
        fs::write(&config, &invalid_toml).unwrap();
        let invalid_hash = format!("{:x}", Sha256::digest(invalid_toml.as_bytes()));
        quota_apply(env_key, &endpoint, 1, &invalid_hash, false);
        assert!(revision(env_key, &endpoint, 1));

        let actual_sha = save(&config, &shrink);
        assert_eq!(sha, actual_sha);
        quota_apply(env_key, &endpoint, 1, &actual_sha, true);
        assert!(revision(env_key, &endpoint, 2));
        quota_apply(env_key, &endpoint, 1, &actual_sha, false);
        assert!(revision(env_key, &endpoint, 2));

        // Two existing transport connections and two fully authenticated
        // streams are still held while the new configured cap is ONE.
        let try_h2 = old_h2.open(address.clone(), echo_port);
        assert!(
            timeout(Duration::from_secs(3), try_h2)
                .await
                .map_or(true, |attempt| attempt.is_err()),
            "H2 admission must fail while existing occupancy exceeds cap"
        );
        let try_h3 = old_h3.open(address.clone(), echo_port);
        assert!(
            timeout(Duration::from_secs(3), try_h3)
                .await
                .map_or(true, |attempt| attempt.is_err()),
            "H3 admission must fail while existing occupancy exceeds cap"
        );
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "quota shrink stopped server"
        );
        assert!(revision(env_key, &endpoint, 2));

        // Growth beyond the ORIGINAL cap of 2 must use the same ledger,
        // not an old fixed-size semaphore silently throttling new sessions.
        let mut grown = shrink.clone();
        grown.server.policy.max_connections_per_user = 4;
        grown.server.policy.max_connections_total = 4;
        let grown_sha = save(&config, &grown);
        quota_apply(env_key, &endpoint, 2, &grown_sha, true);
        assert!(revision(env_key, &endpoint, 3));
        let more_h2 = old_h2.open(address.clone(), echo_port).await.unwrap();
        let more_h3 = old_h3.open(address.clone(), echo_port).await.unwrap();

        // Every pre-quota-change authenticated tunnel still relays bytes.
        let (mut old_h2_app, old_h2_local) = tokio::io::duplex(256);
        let h2_task = tokio::spawn(async move { old_tunnel_h2.relay(old_h2_local).await });
        old_h2_app.write_all(b"still-live").await.unwrap();
        let mut h2_echo = [0u8; 10];
        old_h2_app.read_exact(&mut h2_echo).await.unwrap();
        assert_eq!(&h2_echo, b"still-live");
        old_h2_app.shutdown().await.unwrap();
        h2_task.await.unwrap().unwrap();

        let (mut old_h3_app, old_h3_local) = tokio::io::duplex(256);
        let h3_task = tokio::spawn(async move { old_tunnel_h3.relay(old_h3_local).await });
        old_h3_app.write_all(b"still-live").await.unwrap();
        let mut h3_echo = [0u8; 10];
        old_h3_app.read_exact(&mut h3_echo).await.unwrap();
        assert_eq!(&h3_echo, b"still-live");
        old_h3_app.shutdown().await.unwrap();
        h3_task.await.unwrap().unwrap();
        drop((more_h2, more_h3));

        // The snapshot must have been rebased to the quota-adjusted policy,
        // so ordinary auth-only CAS remains compatible.
        document = grown;
        document.server.users[0].token_sha256 = digest(0x43);
        save(&config, &document);
        let auth = cli(
            env_key,
            &endpoint,
            &["server", "reload", "--expected-revision", "3"],
        );
        assert!(
            auth.status.success(),
            "auth-only CAS after quotas must succeed: {}",
            String::from_utf8_lossy(&auth.stderr)
        );
        assert!(revision(env_key, &endpoint, 4));
        let new_h2 = H2Client::new(
            &format!("127.0.0.1:{tcp_port}"),
            "localhost",
            &credential(0x43),
            roots.clone(),
        )
        .unwrap();
        let new_h3 = H3Client::new(
            format!("127.0.0.1:{udp_port}").parse().unwrap(),
            "localhost",
            &credential(0x43),
            roots,
        )
        .unwrap();
        assert!(new_h2.open(address.clone(), echo_port).await.is_ok());
        assert!(new_h3.open(address, echo_port).await.is_ok());
        echo_task.abort();
    })
    .await
    .expect("live quota resize native E2E must finish without hanging");
}
