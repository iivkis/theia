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
        valid.replace("ingress_mode = \"system_proxy\"", "ingress_mode = \"packet\""),
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
    let active = round_trip.client.profiles.iter()
        .find(|p| p.id == round_trip.client.active_profile).unwrap();
    assert!(!active.direct_dpi.unwrap_or(false));
    assert!(!active.direct_dpi_stun.unwrap_or(false));
    for field in ["system_proxy = \"manual\"", "direct_dpi = true", "direct_dpi_stun = true"] {
        let legacy = fixture.replace("[client.proxy]", &format!("[client.proxy]\n{field}"));
        assert!(config::parse(&legacy).is_err());
    }
    for mode in ["tun", "packet"] {
        let unsupported = fixture.replace("ingress_mode = \"system_proxy\"", &format!("ingress_mode = \"{mode}\""));
        assert!(config::parse(&unsupported).is_err());
    }
}
