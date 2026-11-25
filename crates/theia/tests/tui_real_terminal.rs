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

#[path = "support/private_pem.rs"]
mod private_pem;

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn reserve_ports() -> (TcpListener, UdpSocket) {
    (
        TcpListener::bind("127.0.0.1:0").unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    )
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

fn assert_restart_check(binary: &str, env_key: &str, endpoint: &str, expected: &str, ok: bool) {
    let result = Command::new(binary)
        .args(["server", "restart", "--check"])
        .env(env_key, endpoint)
        .output()
        .expect("compiled restart checker must start");
    assert_eq!(
        result.status.success(),
        ok,
        "restart check exit mismatch; stdout={}; stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let observed = if ok { &result.stdout } else { &result.stderr };
    assert!(
        String::from_utf8_lossy(observed).contains(expected),
        "restart check did not classify read-only preflight: {}",
        String::from_utf8_lossy(observed)
    );
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
    let scenario_for_child = scenario.clone();
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
                .arg(&scenario_for_child)
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
    private_pem::write_new_key(
        &key_path,
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(generated.key_pair.serialize_der())
        ),
    );
    let reservations = reserve_ports();
    let tcp = reservations.0.local_addr().unwrap().port();
    let udp = reservations.1.local_addr().unwrap().port();
    let mut doc = ServerDocument {
        schema_version: 1,
        server: ServerSettings {
            enabled: true,
            inbounds: vec![Inbound {
                id: "edge".into(),
                path_prefix: Some("/v1/theia-example".into()),
                allowed_user_ids: vec!["device-a".into()],
                h2_listen: format!("127.0.0.1:{tcp}"),
                quic_listen: format!("127.0.0.1:{udp}"),
                server_name: "localhost".into(),
                tls_cert: format!("file:{}", cert_path.display()),
                security_mode: Default::default(),
                reality: None,
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
    assert!(
        theia::server::tls_fingerprint_file(&server_file).is_ok(),
        "TUI fixture must pass protected PEM validation and production TLS builders"
    );
    let binary = env!("CARGO_BIN_EXE_theia");
    #[cfg(target_os = "linux")]
    let (env_key, endpoint) = ("THEIA_CONTROL_DIR", base.to_string_lossy().into_owned());
    #[cfg(target_os = "windows")]
    let (env_key, endpoint) = (
        "THEIA_CONTROL_PIPE",
        format!("m42f{}{}", std::process::id(), tcp),
    );
    drop(reservations);
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
            if let Some(status) = running.0.try_wait().unwrap() {
                panic!("TUI server exited before management readiness: {status}");
            }
            sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .expect("real server revision 1 must become available");
    // M4.2g: native CLI checks run via the SAME protected IPC of this real
    // server, not a separate parser/unit mock. All verdicts MUST keep the
    // original H2+H3 listeners and live authorization revision 1 untouched.
    assert_restart_check(binary, env_key, &endpoint, "restart not needed", true);

    let old_doc = doc.clone();
    let mut moved = doc.clone();
    let reservations = reserve_ports();
    moved.server.inbounds[0].h2_listen = reservations.0.local_addr().unwrap().to_string();
    moved.server.inbounds[0].quic_listen = reservations.1.local_addr().unwrap().to_string();
    save(&server_file, &moved);
    drop(reservations);
    assert_restart_check(
        binary,
        env_key,
        &endpoint,
        "temporarily bound then released",
        true,
    );
    assert!(cli_status(binary, env_key, &endpoint, 1));

    let occupied_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut busy = moved.clone();
    busy.server.inbounds[0].h2_listen = occupied_tcp.local_addr().unwrap().to_string();
    save(&server_file, &busy);
    assert_restart_check(
        binary,
        env_key,
        &endpoint,
        "candidate or expected revision rejected",
        false,
    );
    drop(occupied_tcp);
    assert!(cli_status(binary, env_key, &endpoint, 1));

    let occupied_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    busy = moved.clone();
    busy.server.inbounds[0].quic_listen = occupied_udp.local_addr().unwrap().to_string();
    save(&server_file, &busy);
    assert_restart_check(
        binary,
        env_key,
        &endpoint,
        "candidate or expected revision rejected",
        false,
    );
    drop(occupied_udp);
    assert!(cli_status(binary, env_key, &endpoint, 1));

    // Same-port TLS/policy changes cannot honestly be prebound with this
    // runtime; report maintenance, not a fake zero-downtime restart.
    let mut maintenance = old_doc.clone();
    maintenance.server.policy.max_connections_total += 1;
    save(&server_file, &maintenance);
    assert_restart_check(
        binary,
        env_key,
        &endpoint,
        "requires controlled maintenance",
        true,
    );
    assert!(cli_status(binary, env_key, &endpoint, 1));

    // A wrong SAN must be rejected by the REAL rustls TLS1.3 identity
    // builder, even when the proposed next-generation ports are free.
    let alien = rcgen::generate_simple_self_signed(vec!["other.example.org".into()]).unwrap();
    let other_cert = base.join("other-cert.pem");
    let other_key = base.join("other-key.pem");
    fs::write(
        &other_cert,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(alien.cert.der())
        ),
    )
    .unwrap();
    private_pem::write_new_key(
        &other_key,
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(alien.key_pair.serialize_der())
        ),
    );
    let mut bad_identity = moved;
    bad_identity.server.inbounds[0].tls_cert = format!("file:{}", other_cert.display());
    bad_identity.server.inbounds[0].tls_key = format!("file:{}", other_key.display());
    save(&server_file, &bad_identity);
    assert_restart_check(
        binary,
        env_key,
        &endpoint,
        "candidate or expected revision rejected",
        false,
    );
    assert!(cli_status(binary, env_key, &endpoint, 1));

    doc = old_doc;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compiled_dual_mode_tui_invitation_import_apply_and_rollback() {
    use theia::{
        client_import::PrivateBearer,
        reality_config::{self, Request, ServerRequest},
        reference_health::{self, Evidence, Plan, State, Store, Target},
    };
    let base = std::env::temp_dir().join(format!("theia-dual-ui-{}", std::process::id()));
    fs::create_dir(&base).unwrap();
    let _cleanup = TempDir(base.clone());
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let cert = base.join("cert.pem");
    let key = base.join("key.pem");
    let server_file = base.join("server.toml");
    let client_file = base.join("client.toml");
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    fs::write(&cert, generated.cert.pem()).unwrap();
    private_pem::write_new_key(&key, generated.key_pair.serialize_pem());
    let localhost = tokio::net::lookup_host(("localhost", 0)).await.unwrap().next().unwrap().ip();
    let reserve = |ip| {
        (0..16).find_map(|_| {
            let tcp = TcpListener::bind(std::net::SocketAddr::new(ip, 0)).ok()?;
            let udp = UdpSocket::bind(tcp.local_addr().ok()?).ok()?;
            Some((tcp, udp))
        }).unwrap()
    };
    let own = reserve(localhost);
    let smart = reserve(std::net::Ipv4Addr::LOCALHOST.into());
    let own_addr = own.0.local_addr().unwrap();
    let smart_addr = smart.0.local_addr().unwrap();
    let Config::Server(mut document) = theia::config::parse(&include_str!("../../../examples/server.toml")
        .replace("REPLACE_WITH_64_LOWERCASE_HEX", &digest(42))).unwrap() else { panic!("server"); };
    let inbound = &mut document.server.inbounds[0];
    inbound.h2_listen = own_addr.to_string();
    inbound.quic_listen = own_addr.to_string();
    inbound.server_name = "localhost".into();
    inbound.tls_cert = format!("file:{}", cert.display());
    inbound.tls_key = format!("file:{}", key.display());
    document.server.policy.allow_private_ips = true;
    save(&server_file, &document);
    let now = reference_health::unix_now().unwrap();
    let state = State::new(Plan {
        schema_version: 1, inbound: "reality".into(), endpoint: smart_addr.to_string(),
        own_ips: vec![smart_addr.ip()], references: vec![Target {
            server_name: "reference.example.org".into(), address: "93.184.216.2:443".parse().unwrap(),
        }],
    }, vec![Evidence {h2_status: Some(200), h3_status: Some(200)}], now).unwrap();
    let health = base.join("health.toml");
    Store::new(&health).unwrap().enroll(&state).unwrap();
    let bundle = base.join("bundle");
    let health_sha256 = state.snapshot_sha256().unwrap();
    let record = theia::reality_provision::create(&state, health_sha256, &bundle, now).unwrap();
    let request = Request::Server(ServerRequest {
        health, bundle: bundle.clone(), health_sha256, identity_sha256: record.identity_sha256,
        listen: smart_addr, grants: vec!["device-a".into()],
    });
    let review = reality_config::prepare(&server_file, &request, now).unwrap();
    reality_config::apply(&server_file, &request, review.approval_sha256(), now).unwrap();
    let fingerprint = record.identity_sha256.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let Config::Client(mut client) = theia::config::parse(include_str!("../../../examples/client.toml")).unwrap() else { panic!("client"); };
    let mut credential = PrivateBearer::create(&client_file, &[42;32]).unwrap();
    let profile = &mut client.client.profiles[0];
    profile.server = own_addr.to_string();
    profile.server_name = "localhost".into();
    profile.tls_ca = Some(format!("file:{}", cert.display()));
    profile.auth_token = credential.reference().unwrap();
    let http = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = http.local_addr().unwrap().port();
    let socks_port = socks.local_addr().unwrap().port();
    client.client.proxy.http_listen = format!("127.0.0.1:{http_port}");
    client.client.proxy.socks5_listen = format!("127.0.0.1:{socks_port}");
    fs::write(&client_file, Config::Client(client).to_toml().unwrap()).unwrap();
    credential.commit();
    let binary = env!("CARGO_BIN_EXE_theia");
    #[cfg(target_os = "linux")]
    let (env_key, endpoint) = ("THEIA_CONTROL_DIR", base.to_string_lossy().into_owned());
    #[cfg(target_os = "windows")]
    let (env_key, endpoint) = ("THEIA_CONTROL_PIPE", format!("dual-ui-{}-{}",std::process::id(),own_addr.port()));
    drop((own, smart, http, socks));
    let mut running = Running(Command::new(binary).args(["server","run","--config"]).arg(&server_file)
        .env(env_key, &endpoint).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    timeout(Duration::from_secs(8), async {
        loop {
            if cli_status(binary, env_key, &endpoint, 1) { break; }
            assert!(running.0.try_wait().unwrap().is_none());
            sleep(Duration::from_millis(25)).await;
        }
    }).await.unwrap();
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        while let Ok((socket,_)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = socket.into_split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/tui-real-terminal-e2e.py");
    let interpreter = if cfg!(target_os = "windows") { "python" } else { "python3" };
    let output = timeout(Duration::from_secs(50), tokio::task::spawn_blocking(move || {
        Command::new(interpreter).arg(script).args(["--binary",binary,"--scenario","dual-product","--revision","1"])
            .arg("--config").arg(server_file).arg("--client").arg(client_file)
            .arg("--cert").arg(cert).arg("--admission").arg(bundle.join("admission.key"))
            .arg("--fingerprint").arg(fingerprint)
            .arg("--http-port").arg(http_port.to_string()).arg("--socks-port").arg(socks_port.to_string())
            .arg("--echo-port").arg(echo_port.to_string()).env(env_key, endpoint).output()
    })).await.expect("dual-mode PTY/ConPTY deadline").unwrap().unwrap();
    echo_task.abort();
    assert!(output.status.success(), "dual-mode terminal scenario failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("REAL_TUI_PTY_E2E_OK: dual-product"));
}

// Test-only cleanup: server Child must be dropped before directory.
struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disposable Windows CI only: actual ConPTY changes per-user WinINet"]
async fn compiled_client_proxy_conpty_lifecycle() {
    use theia::client_import::PrivateBearer;
    use tokio::net::TcpListener as AsyncListener;

    assert_eq!(
        std::env::var("THEIA_WINDOWS_PROXY_E2E_ALLOWED").as_deref(),
        Ok("yes")
    );
    let base =
        std::env::temp_dir().join(format!("theia-client-proxy-conpty-{}", std::process::id()));
    fs::create_dir(&base).unwrap();
    let _cleanup = TempDir(base.clone());
    let cert_path = base.join("cert.pem");
    let key_path = base.join("key.pem");
    let server_file = base.join("server.toml");
    let client_file = base.join("client.toml");
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    fs::write(&cert_path, generated.cert.pem()).unwrap();
    private_pem::write_new_key(
        &key_path,
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(generated.key_pair.serialize_der())
        ),
    );

    let reservations = reserve_ports();
    let tcp = reservations.0.local_addr().unwrap().port();
    let udp = reservations.1.local_addr().unwrap().port();
    let server = ServerDocument {
        schema_version: 1,
        server: ServerSettings {
            enabled: true,
            inbounds: vec![Inbound {
                id: "edge".into(),
                path_prefix: Some("/v1/theia-example".into()),
                allowed_user_ids: vec!["device-a".into()],
                h2_listen: format!("127.0.0.1:{tcp}"),
                quic_listen: format!("127.0.0.1:{udp}"),
                server_name: "localhost".into(),
                tls_cert: format!("file:{}", cert_path.display()),
                security_mode: Default::default(),
                reality: None,
                tls_key: format!("file:{}", key_path.display()),
            }],
            users: vec![User {
                id: "device-a".into(),
                token_sha256: digest(42),
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
    save(&server_file, &server);
    assert!(
        theia::server::tls_fingerprint_file(&server_file).is_ok(),
        "ConPTY fixture must pass protected PEM validation and production TLS builders"
    );
    let binary = env!("CARGO_BIN_EXE_theia");
    let pipe = format!("proxyconpty{}", std::process::id());
    drop(reservations);
    let mut running = Running(
        Command::new(binary)
            .args(["server", "run", "--config"])
            .arg(&server_file)
            .env("THEIA_CONTROL_PIPE", &pipe)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    timeout(Duration::from_secs(12), async {
        loop {
            if cli_status(binary, "THEIA_CONTROL_PIPE", &pipe, 1) {
                break;
            }
            if let Some(status) = running.0.try_wait().unwrap() {
                panic!("ConPTY server exited before management readiness: {status}");
            }
            sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .unwrap();

    let echo = AsyncListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        while let Ok((socket, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = socket.into_split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });

    let bearer = PrivateBearer::create(&client_file, &[42; 32]).unwrap();
    let Config::Client(mut client) =
        theia::config::parse(include_str!("../../../examples/client.toml")).unwrap()
    else {
        panic!("client template");
    };
    let profile = &mut client.client.profiles[0];
    profile.server = format!("127.0.0.1:{tcp}");
    profile.server_name = "localhost".into();
    profile.transport = theia::config::Transport::H2;
    profile.tls_ca = Some(format!("file:{}", cert_path.display()));
    profile.auth_token = bearer.reference().unwrap();
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = first.local_addr().unwrap().port();
    let socks_port = second.local_addr().unwrap().port();
    client.client.proxy.http_listen = format!("127.0.0.1:{http_port}");
    client.client.proxy.socks5_listen = format!("127.0.0.1:{socks_port}");
    client.client.proxy.system_proxy = theia::config::SystemProxy::Manual;
    fs::write(&client_file, Config::Client(client).to_toml().unwrap()).unwrap();
    drop(first);
    drop(second);

    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/tui-real-terminal-e2e.py");
    let output = timeout(
        Duration::from_secs(150),
        tokio::task::spawn_blocking(move || {
            Command::new("python")
                .arg(script)
                .arg("--binary")
                .arg(binary)
                .arg("--config")
                .arg(client_file)
                .args(["--scenario", "client-proxy", "--revision", "1"])
                .arg("--http-port")
                .arg(http_port.to_string())
                .arg("--socks-port")
                .arg(socks_port.to_string())
                .arg("--echo-port")
                .arg(echo_port.to_string())
                .output()
        }),
    )
    .await
    .expect("compiled client ConPTY timed out")
    .unwrap()
    .unwrap();
    echo_task.abort();
    assert!(
        output.status.success(),
        "client ConPTY failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("REAL_TUI_PTY_E2E_OK: client-proxy"));
    drop(running);
    drop(bearer);
}
