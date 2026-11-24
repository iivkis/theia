//! M4.2b0: real compiled Linux server/management socket, no public network.
//! Dry-run preflight is never Apply. The server must survive all rejections.
#![cfg(target_os = "linux")]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{
    fs,
    net::{TcpListener, UdpSocket},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use theia::{
    config::{Config, Inbound, Management, ServerDocument, ServerPolicy, ServerSettings, Ui, User},
    management::{query_in, ManagementError, StatusCommand, StatusReply},
};
use tokio::time::{sleep, timeout};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct ServerChild(Child);
impl Drop for ServerChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_config(path: &Path, doc: &ServerDocument) {
    fs::write(path, Config::Server(doc.clone()).to_toml().unwrap()).unwrap();
}

fn fresh_port(tcp: bool) -> u16 {
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

#[tokio::test]
async fn live_binary_preflight_accepts_safe_delta_rejects_identity_drift_and_never_applies() {
    let directory = std::env::temp_dir().join(format!(
        "theia-b0-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let cert_path = directory.join("cert.pem");
    let key_path = directory.join("key.pem");
    let config_path = directory.join("server.toml");
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(generated.cert.der())
    );
    let key = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(generated.key_pair.serialize_der())
    );
    fs::write(&cert_path, &cert).unwrap();
    fs::write(&key_path, &key).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

    let h2 = fresh_port(true);
    let h3 = fresh_port(false);
    let mut doc = ServerDocument {
        schema_version: 1,
        server: ServerSettings {
            enabled: true,
            inbounds: vec![Inbound {
                id: "edge".into(),
                allowed_user_ids: vec!["device-a".into()],
                h2_listen: format!("127.0.0.1:{h2}"),
                quic_listen: format!("127.0.0.1:{h3}"),
                server_name: "localhost".into(),
                tls_cert: format!("file:{}", cert_path.display()),
                security_mode: Default::default(),
                tls_key: format!("file:{}", key_path.display()),
            }],
            users: vec![User {
                id: "device-a".into(),
                token_sha256: "a".repeat(64),
                disabled: false,
            }],
            policy: ServerPolicy {
                allow_private_ips: true,
                max_connections_per_user: 2,
                max_connections_total: 8,
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
    write_config(&config_path, &doc);
    let child = Command::new(env!("CARGO_BIN_EXE_theia"))
        .args(["server", "run", "--config"])
        .arg(&config_path)
        .env("THEIA_CONTROL_DIR", &directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = ServerChild(child);
    timeout(Duration::from_secs(8), async {
        loop {
            if let Ok(StatusReply::RunningRevision {
                inbounds: 1,
                revision: 1,
            }) = query_in(&directory, StatusCommand::Status).await
            {
                break;
            }
            assert!(server.0.try_wait().unwrap().is_none(), "test server quit");
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("server status socket must become available");

    assert_eq!(
        query_in(&directory, StatusCommand::CheckReload).await,
        Ok(StatusReply::Compatible)
    );
    let cli_dir = directory.clone();
    let accepted = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_theia"))
            .args(["server", "reload", "--check"])
            .env("THEIA_CONTROL_DIR", cli_dir)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(accepted.status.success(), "{:?}", accepted.stderr);
    assert_eq!(
        accepted.stdout,
        b"candidate compatible with running listener; runtime UNCHANGED\n"
    );

    // This update is only a saved candidate, not applied: the status
    // endpoint stays read-only and no reload acknowledgement is emitted.
    doc.server.users[0].token_sha256 = "b".repeat(64);
    write_config(&config_path, &doc);
    assert_eq!(
        query_in(&directory, StatusCommand::CheckReload).await,
        Ok(StatusReply::Compatible)
    );
    assert_eq!(
        query_in(&directory, StatusCommand::Reload).await,
        Ok(StatusReply::Unsupported)
    );

    // Same-path PEM replacement is a hidden TLS identity change and must
    // be rejected, even though the TOML fields have not changed.
    fs::write(&cert_path, b"replacement PEM").unwrap();
    assert_eq!(
        query_in(&directory, StatusCommand::CheckReload).await,
        Err(ManagementError::CandidateRejected)
    );
    fs::write(&cert_path, &cert).unwrap();

    doc.server.inbounds[0].h2_listen = format!("127.0.0.1:{}", fresh_port(true));
    write_config(&config_path, &doc);
    assert_eq!(
        query_in(&directory, StatusCommand::CheckReload).await,
        Err(ManagementError::CandidateRejected)
    );

    let denied_dir = directory.clone();
    let rejected = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_theia"))
            .args(["server", "reload", "--check"])
            .env("THEIA_CONTROL_DIR", denied_dir)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!rejected.status.success(), "rejection cannot exit zero");
    assert!(!String::from_utf8_lossy(&rejected.stderr).contains("private key"));
    assert_eq!(
        query_in(&directory, StatusCommand::Status).await,
        Ok(StatusReply::RunningRevision {
            inbounds: 1,
            revision: 1
        })
    );
    drop(server);
    fs::remove_dir_all(&directory).unwrap();
}
