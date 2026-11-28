//! Black-box CLI regression tests. Run natively on Linux and Windows.
use std::process::{Command, Output};

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_theia"))
        .args(args)
        .output()
        .expect("theia executable must exist")
}

#[test]
fn help_and_version_exit_successfully() {
    let help = invoke(&["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("H2 server inbound"));
    assert!(
        help.stderr.is_empty(),
        "successful --help must not emit diagnostics warnings: {}",
        String::from_utf8_lossy(&help.stderr)
    );

    let version = invoke(&["--version"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("theia 0.1.0"));
}

#[test]
fn accepted_runtime_commands_fail_closed() {
    let result = invoke(&["tui", "--role", "client"]);
    // Non-interactive CI process must fail before raw mode, network or OS changes.
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("interactive terminal required"));
}

#[test]
fn tui_editor_non_tty_rejects_before_opening_config() {
    for args in [
        vec!["tui", "--role", "server", "--config", "does-not-exist.toml"],
        vec!["tui", "--role", "client", "--config", "does-not-exist.toml"],
    ] {
        let output = invoke(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("interactive terminal required"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("does-not-exist"));
    }
}

#[test]
fn validates_client_toml_and_rejects_unknown_fields() {
    let path = std::env::temp_dir().join(format!("theia-m12-cli-{}.toml", std::process::id()));
    let valid = include_str!("../../../examples/client.toml");
    std::fs::write(&path, valid).unwrap();
    let path_str = path.to_str().unwrap();
    let output = invoke(&["config", "validate", "--config", path_str]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("structurally valid"));
    std::fs::write(
        &path,
        valid.replace(
            "ingress_mode = \"system_proxy\"",
            "ingress_mode = \"packet\"",
        ),
    )
    .unwrap();
    let output = invoke(&["config", "validate", "--config", path_str]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("THEIA_AUTH_TOKEN"));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn server_run_missing_config_fails_before_binding() {
    let result = invoke(&["server", "run", "--config", "not-present-m21.toml"]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("server failed"));
}

#[test]
fn rejected_arguments_cannot_start_a_runtime() {
    for args in [
        vec!["tui", "--role", "administrator"],
        vec!["server", "run", "--config", "--version"],
        vec!["client", "run", "--config"],
        vec!["garbage"],
    ] {
        let result = invoke(&args);
        assert_eq!(result.status.code(), Some(2), "{args:?}");
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn errors_do_not_echo_argument_content() {
    let secret = "secret-token-DO-NOT-LOG";
    let result = invoke(&["client", "run", "--config", secret]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(secret));
}

#[test]
fn client_run_missing_config_fails_before_binding() {
    let result = invoke(&["client", "run", "--config", "missing-m22.toml"]);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("client failed"));
    assert!(result.stdout.is_empty());
}

// An unsupported OS command still fails closed with its original exit code.
#[cfg(not(windows))]
#[test]
fn windows_proxy_commands_fail_closed_on_other_platforms() {
    for args in [
        vec!["client", "proxy", "--status"],
        vec!["client", "proxy", "--recover", "--confirm"],
        vec![
            "client",
            "run",
            "--config",
            "missing.toml",
            "--system-proxy",
            "--confirm",
        ],
    ] {
        let result = invoke(&args);
        assert_eq!(result.status.code(), Some(3));
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("Windows user proxy"));
    }
}

#[test]
fn profile_consent_is_local_and_ingress_selection_is_not_activation() {
    use theia::config::{self, Config, IngressMode};
    let fixture = include_str!("../../../examples/client.toml");
    let Config::Client(mut doc) = config::parse(fixture).unwrap() else {
        panic!("client template");
    };
    assert_eq!(doc.client.ingress_mode, IngressMode::SystemProxy);
    assert!(!doc.client.profiles[0].direct_dpi.unwrap_or(false));
    let mut other = doc.client.profiles[0].clone();
    other.id = "other".into();
    doc.client.profiles[0].direct_dpi = Some(true);
    doc.client.profiles[0].direct_dpi_stun = Some(true);
    doc.client.profiles.push(other);
    doc.client.active_profile = "other".into();
    let source = Config::Client(doc.clone()).to_toml().unwrap();
    let Config::Client(round_trip) = config::parse(&source).unwrap() else {
        panic!("client template");
    };
    assert_eq!(round_trip, doc);
    let active = round_trip
        .client
        .profiles
        .iter()
        .find(|p| p.id == round_trip.client.active_profile)
        .unwrap();
    assert!(!active.direct_dpi.unwrap_or(false));
    assert!(!active.direct_dpi_stun.unwrap_or(false));
    for field in [
        "system_proxy = \"manual\"",
        "direct_dpi = true",
        "direct_dpi_stun = true",
    ] {
        let legacy = fixture.replace("[client.proxy]", &format!("[client.proxy]\n{field}"));
        assert!(config::parse(&legacy).is_err());
    }
    for mode in ["tun", "packet"] {
        let unsupported = fixture.replace(
            "ingress_mode = \"system_proxy\"",
            &format!("ingress_mode = \"{mode}\""),
        );
        assert!(config::parse(&unsupported).is_err());
    }
}

// The binary's management dispatcher must never confuse missing IPC, rejected
// CAS or an unrecognized receipt with a successful operation.
fn isolated_management_command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_theia"));
    command.args(args);
    for name in [
        "THEIA_CONTROL_DIR",
        "THEIA_CONTROL_PIPE",
        "THEIA_CLIENT_CONTROL_DIR",
        "THEIA_CLIENT_CONTROL_PIPE",
    ] {
        command.env_remove(name);
    }
    command
}

#[test]
fn management_commands_without_owner_never_report_success() {
    let digest = "12".repeat(32);
    let nonce = "34".repeat(32);
    for args in [
        vec!["server", "status"],
        vec!["server", "reload", "--check"],
        vec!["server", "restart", "--check"],
        vec!["server", "quota", "--check"],
        vec!["server", "auth", "rollback", "--check"],
        vec!["server", "tls", "rollback", "--check"],
        vec!["server", "restart", "rollback", "--check"],
        vec!["server", "reload", "--expected-revision", "7"],
        vec![
            "server",
            "reload",
            "--apply",
            "--expected-revision",
            "7",
            "--sha256",
            &digest,
            "--confirm",
        ],
        vec![
            "server",
            "quota",
            "--apply",
            "--expected-revision",
            "7",
            "--sha256",
            &digest,
            "--confirm",
        ],
        vec![
            "server",
            "restart",
            "--apply",
            "--expected-revision",
            "7",
            "--sha256",
            &digest,
            "--tls-sha256",
            &nonce,
            "--confirm",
        ],
        vec![
            "server",
            "auth",
            "rollback",
            "--apply",
            "--expected-revision",
            "7",
            "--confirm",
        ],
        vec![
            "server",
            "tls",
            "rollback",
            "--apply",
            "--expected-revision",
            "7",
            "--confirm",
        ],
        vec![
            "server",
            "restart",
            "rollback",
            "--apply",
            "--expected-revision",
            "7",
            "--confirm",
        ],
        vec!["client", "status"],
        vec!["client", "lifecycle"],
        vec![
            "client",
            "reload",
            "--check",
            "--expected-revision",
            "7",
            "--sha256",
            &digest,
        ],
        vec![
            "client",
            "reload",
            "--apply",
            "--expected-revision",
            "7",
            "--sha256",
            &digest,
            "--confirm",
        ],
        vec![
            "client",
            "disconnect",
            "--expected-revision",
            "7",
            "--sha256",
            &digest,
            "--instance",
            &nonce,
            "--confirm",
        ],
    ] {
        let out = isolated_management_command(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("management status unavailable"),
            "{args:?}: {stderr}"
        );
        assert!(!stderr.contains(digest.as_str()));
        assert!(!stderr.contains(nonce.as_str()));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn native_cli_management_receipts_are_bound_and_never_overstate_lifecycle() {
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::{fs::DirBuilderExt, net::UnixListener},
        time::{Duration, Instant},
    };
    let dir = std::env::temp_dir().join(format!("theia-cli-receipts-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let path = dir.join("theia-server.sock");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let digest = "12".repeat(32);
    let nonce = "34".repeat(32);
    let run = |args: &[&str], wire: &str, reply: &str, expected: Option<&str>| {
        let mut child = isolated_management_command(args)
            .env("THEIA_CONTROL_DIR", &dir)
            .env("THEIA_CLIENT_CONTROL_DIR", &dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => {
                    let _ = child.kill();
                    let out = child.wait_with_output().unwrap();
                    panic!(
                        "no CLI request for {args:?}: {error}: {}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        assert_eq!(request, wire, "{args:?}");
        stream.write_all(reply.as_bytes()).unwrap();
        drop(stream);
        let out = child.wait_with_output().unwrap();
        if let Some(expected) = expected {
            assert!(
                out.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains(expected), "{args:?}: {stdout}");
        } else {
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            assert!(out.stdout.is_empty(), "{args:?}");
            assert!(String::from_utf8_lossy(&out.stderr).contains("management status unavailable"));
        }
    };
    for (reply, expected) in [
        (
            "theia-status-v1 running inbounds=2\n",
            "reload not available",
        ),
        (
            "theia-status-v2 running inbounds=2 revision=7\n",
            "authorization revision=7",
        ),
    ] {
        run(&["server", "status"], "status\n", reply, Some(expected));
    }
    run(
        &["server", "status"],
        "status\n",
        "theia-status-v2 running inbounds=2 revision=0\n",
        None,
    );
    run(
        &["server", "reload", "--check"],
        "check-reload\n",
        "theia-check-v1 compatible\n",
        Some("runtime UNCHANGED"),
    );
    run(
        &["server", "reload", "--check"],
        "check-reload\n",
        "theia-check-v1 rejected\n",
        None,
    );
    run(
        &["server", "quota", "--check"],
        "check-quota\n",
        "theia-quota-v1 ready\n",
        Some("nothing applied"),
    );
    for (reply, expected) in [
        ("auth-only", "runtime UNCHANGED"),
        ("same-port-tls", "same-port TLS rotation ready"),
        ("maintenance", "controlled maintenance"),
        ("ports-bindable", "NOT reserved or applied"),
    ] {
        run(
            &["server", "restart", "--check"],
            "check-restart\n",
            &format!("theia-restart-v1 {reply}\n"),
            Some(expected),
        );
    }
    for (kind, expected) in [
        ("auth", "authorization rollback ready"),
        ("tls", "same-port TLS identity rollback ready"),
        ("restart", "structural rollback ready"),
    ] {
        let check = ["server", kind, "rollback", "--check"];
        let wire = format!("{kind}-rollback-check\n");
        run(
            &check,
            &wire,
            &format!("theia-{kind}-rollback-v1 ready revision=7 seconds=300\n"),
            Some(expected),
        );
        run(
            &check,
            &wire,
            &format!("theia-{kind}-rollback-v1 ready revision=7 seconds=301\n"),
            None,
        );
        let apply = [
            "server",
            kind,
            "rollback",
            "--apply",
            "--expected-revision",
            "7",
            "--confirm",
        ];
        let wire = format!("{kind}-rollback-apply rev=7\n");
        run(
            &apply,
            &wire,
            &format!("theia-{kind}-rollback-v1 applied revision=8\n"),
            Some("revision=8"),
        );
        run(
            &apply,
            &wire,
            &format!("theia-{kind}-rollback-v1 applied revision=7\n"),
            None,
        );
    }
    let reload = [
        "server",
        "reload",
        "--apply",
        "--expected-revision",
        "7",
        "--sha256",
        &digest,
        "--confirm",
    ];
    let wire = format!("apply-reload rev=7 sha256={digest}\n");
    run(
        &reload,
        &wire,
        "theia-apply-v1 applied revision=8\n",
        Some("existing tunnels retained"),
    );
    run(&reload, &wire, "theia-apply-v1 applied revision=9\n", None);
    run(
        &["server", "reload", "--expected-revision", "7"],
        "apply-reload rev=7\n",
        "theia-apply-v1 applied revision=8\n",
        Some("revision=8"),
    );
    let quota = [
        "server",
        "quota",
        "--apply",
        "--expected-revision",
        "7",
        "--sha256",
        &digest,
        "--confirm",
    ];
    let wire = format!("quota-apply rev=7 sha256={digest}\n");
    run(
        &quota,
        &wire,
        "theia-quota-v1 applied revision=8\n",
        Some("cap contraction blocks new admission"),
    );
    run(&quota, &wire, "theia-quota-v1 rejected\n", None);
    let restart = [
        "server",
        "restart",
        "--apply",
        "--expected-revision",
        "7",
        "--sha256",
        &digest,
        "--tls-sha256",
        &nonce,
        "--confirm",
    ];
    let wire = format!("restart-apply rev=7 sha256={digest} tls-sha256={nonce}\n");
    run(
        &restart,
        &wire,
        "theia-restart-v1 applied revision=8\n",
        Some("no automatic rollback"),
    );
    run(
        &restart,
        &wire,
        "theia-restart-v1 applied revision=9\n",
        None,
    );
    let counters = ["0"; 38].join(",");
    for (capture, expected) in [
        (0, "inactive"),
        (1, "preparing"),
        (2, "isolated_lab"),
        (3, "recovery_required"),
    ] {
        run(&["client", "status"], "client-status\n", &format!("theia-client-v1 r=7 sha256={digest} d=0 t=2 x=1 f=0 rr=1 rs=1 rt={counters} fs=unknown cap={capture}\n"), Some(&format!("packet_interception={expected}")));
    }
    for (phase, listeners, applied, expected) in [
        (0, 0, 0, "inactive"),
        (1, 0, 0, "preparing"),
        (2, 1, 1, "connected"),
        (3, 0, 1, "stopping"),
        (4, 0, 2, "recovery_required"),
    ] {
        run(&["client", "lifecycle"], "client-lifecycle\n", &format!("theia-client-v1 lifecycle r=7 sha256={digest} instance={nonce} phase={phase} listeners={listeners} applied={applied}\n"), Some(&format!("lifecycle={expected}")));
    }
    run(&["client", "lifecycle"], "client-lifecycle\n", &format!("theia-client-v1 lifecycle r=7 sha256={digest} instance={nonce} phase=2 listeners=0 applied=1\n"), None);
    let preview = [
        "client",
        "reload",
        "--check",
        "--expected-revision",
        "7",
        "--sha256",
        &digest,
    ];
    run(
        &preview,
        &format!("client-preview rev=7 sha256={digest}\n"),
        "theia-client-v1 ready r=7\n",
        Some("nothing applied"),
    );
    let apply = [
        "client",
        "reload",
        "--apply",
        "--expected-revision",
        "7",
        "--sha256",
        &digest,
        "--confirm",
    ];
    let wire = format!("client-apply rev=7 sha256={digest}\n");
    run(
        &apply,
        &wire,
        "theia-client-v1 applied r=8\n",
        Some("previous routing generation retired"),
    );
    run(&apply, &wire, "theia-client-v1 applied r=7\n", None);
    let disconnect = [
        "client",
        "disconnect",
        "--expected-revision",
        "7",
        "--sha256",
        &digest,
        "--instance",
        &nonce,
        "--confirm",
    ];
    let wire = format!("client-disconnect rev=7 sha256={digest} instance={nonce}\n");
    run(
        &disconnect,
        &wire,
        &format!("theia-client-v1 disconnect-accepted r=7 instance={nonce}\n"),
        Some("restoration not yet confirmed"),
    );
    run(
        &disconnect,
        &wire,
        &format!("theia-client-v1 disconnect-accepted r=7 instance={digest}\n"),
        None,
    );
}
