//! M4.2f: real binary server + actual Linux PTY / Windows ConPTY TUI CAS E2E.
//! The Python helper ONLY drives OS terminal keystrokes, and compiled CLI
//! status confirms real shared H2/H3 auth publication (not fake TUI receipts).
#![cfg(any(target_os = "linux", target_os = "windows"))]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{TcpListener, UdpSocket},
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
use theia::config::{
    Config, Inbound, Management, ServerDocument, ServerPolicy, ServerSettings, Ui, User,
};
use tokio::time::{sleep, timeout};

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port(tcp: bool) -> u16 {
    if tcp {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    } else {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}

fn digest(byte: u8) -> String {
    format!("{:x}", Sha256::digest([byte; 32]))
}

fn save(path: &Path, doc: &ServerDocument) {
    fs::write(path, Config::Server(doc.clone()).to_toml().unwrap()).unwrap();
}

fn cli_status(binary: &str, env_key: &str, endpoint: &str, revision: u64) -> bool {
    let output = Command::new(binary)
        .args(["server", "status"])
        .env(env_key, endpoint)
        .output()
        .expect("compiled server status CLI must start");
    output.status.success()
        && String::from_utf8_lossy(&output.stdout)
            .contains(&format!("authorization revision={revision}"))
}

async fn drive_terminal(
    binary: &str,
    env_key: &str,
    endpoint: &str,
    config: &Path,
    scenario: &str,
    revision: u64,
) {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/tui-real-terminal-e2e.py");
    let interpreter = if cfg!(target_os = "windows") {
        "python"
    } else {
        "python3"
    };
    let binary = binary.to_owned();
    let env_key = env_key.to_owned();
    let endpoint = endpoint.to_owned();
    let config = config.to_path_buf();
    let scenario = scenario.to_owned();
    let output = timeout(
        Duration::from_secs(78),
        tokio::task::spawn_blocking(move || {
            Command::new(interpreter)
                .arg(script)
                .arg("--binary")
                .arg(binary)
                .arg("--config")
                .arg(config)
                .arg("--scenario")
                .arg(&scenario)
                .arg("--revision")
                .arg(revision.to_string())
                .env(&env_key, endpoint)
                .output()
        }),
    )
    .await
    .expect("actual terminal E2E timed out")
    .expect("terminal test worker panicked")
    .expect("could not run terminal E2E");
    assert!(
        output.status.success(),
        "{scenario} real PTY/ConPTY regression failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains(&format!("REAL_TUI_PTY_E2E_OK: {scenario}")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compiled_tui_real_terminal_needs_y_and_obeys_content_bound_cas() {
    let base = std::env::temp_dir().join(format!(
        "theia-real-tui-{}-{}",
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
    let _cleanup = TempDir(base.clone());
    let cert_path = base.join("cert.pem");
    let key_path = base.join("key.pem");
    let server_file = base.join("server.toml");
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    fs::write(
        &cert_path,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(generated.cert.der())
        ),
    )
    .unwrap();
    fs::write(
        &key_path,
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(generated.key_pair.serialize_der())
        ),
    )
    .unwrap();
    let tcp = free_port(true);
    let udp = free_port(false);
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
                token_sha256: digest(0x42),
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
            ipc: "auto".into(),
            log_level: "info".into(),
        },
        ui: Ui {
            language: "ru".into(),
        },
    };
    save(&server_file, &doc);
    let binary = env!("CARGO_BIN_EXE_theia");
    #[cfg(target_os = "linux")]
    let (env_key, endpoint) = ("THEIA_CONTROL_DIR", base.to_string_lossy().into_owned());
    #[cfg(target_os = "windows")]
    let (env_key, endpoint) = (
        "THEIA_CONTROL_PIPE",
        format!("m42f{}{}", std::process::id(), tcp),
    );
    let mut running = Running(
        Command::new(binary)
            .args(["server", "run", "--config"])
            .arg(&server_file)
            .env(env_key, &endpoint)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("compiled H2/H3 server must start"),
    );
    timeout(Duration::from_secs(12), async {
        loop {
            if cli_status(binary, env_key, &endpoint, 1) {
                break;
            }
            assert!(
                running.0.try_wait().unwrap().is_none(),
                "server exited before IPC"
            );
            sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .expect("real server revision 1 must become available");
    // The TUI loads an auth-only updated TOML. Ctrl+R is only a preview until y.
    doc.server.users[0].token_sha256 = digest(0x43);
    save(&server_file, &doc);
    drive_terminal(binary, env_key, &endpoint, &server_file, "apply", 1).await;
    assert!(
        cli_status(binary, env_key, &endpoint, 2),
        "TUI y must really CAS publish"
    );
    // Modify TOML on disk AFTER TUI read, to fail exact saved-content digest.
    drive_terminal(binary, env_key, &endpoint, &server_file, "reject", 2).await;
    assert!(
        cli_status(binary, env_key, &endpoint, 2),
        "external TOML edit must fail closed"
    );
    drive_terminal(binary, env_key, &endpoint, &server_file, "dirty", 2).await;
    assert!(
        cli_status(binary, env_key, &endpoint, 2),
        "dirty draft must never apply"
    );
    drive_terminal(binary, env_key, &endpoint, &server_file, "readonly", 2).await;
    assert!(
        cli_status(binary, env_key, &endpoint, 2),
        "status-only must never apply"
    );
    drive_terminal(
        binary,
        env_key,
        &endpoint,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/client.toml"),
        "client",
        2,
    )
    .await;
    assert!(
        cli_status(binary, env_key, &endpoint, 2),
        "client TUI must never apply"
    );
    drop(running);
}

// Test-only cleanup: server Child must be dropped before directory.
struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
