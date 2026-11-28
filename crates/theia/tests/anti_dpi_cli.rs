//! F-20 offline CLI and role separation. No network or OS changes.
use std::process::Command;

#[test]
fn standalone_validation_and_preflight_are_offline_and_role_specific() {
    let path = std::env::temp_dir().join(format!(
        "theia-f20-cli-{}.toml", std::process::id()
    ));
    let path_str = path.to_str().unwrap();
    let invoke = |role: &str, command: &str| {
        Command::new(env!("CARGO_BIN_EXE_theia"))
            .args([role, command, "--config", path_str])
            .output()
            .unwrap()
    };
    let example = include_str!("../../../examples/anti-dpi.toml");
    std::fs::write(&path, example).unwrap();
    assert!(invoke("anti-dpi", "validate").status.success());
    let preflight = invoke("anti-dpi", "preflight");
    assert!(preflight.status.success());
    assert!(String::from_utf8_lossy(&preflight.stdout).contains("runtime readiness not checked"));
    assert_eq!(invoke("config", "validate").status.code(), Some(2));
    std::fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
    assert_eq!(invoke("anti-dpi", "validate").status.code(), Some(2));
    std::fs::write(&path, example.replace("system_proxy", "packet")).unwrap();
    assert_eq!(invoke("anti-dpi", "preflight").status.code(), Some(2));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn catalogue_cli_is_offline_and_reports_historical_sources() {
    let result = Command::new(env!("CARGO_BIN_EXE_theia"))
        .args(["anti-dpi", "catalog"]).output().unwrap();
    assert!(result.status.success());
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("built-in=60"));
    assert!(output.contains("No network checks performed"));
    assert!(output.contains("discord.com"));
    assert!(output.contains("web.telegram.org"));
    assert!(output.contains("www.instagram.com"));
    assert!(!output.contains("meduza.io"));
    assert!(output.contains("scope=Service"));
    assert!(output.contains("sha256="));
}

#[test]
fn diagnostic_preview_is_offline_and_confirmation_is_exact() {
    let path = std::env::temp_dir().join(format!("theia-f20-preview-{}.toml", std::process::id()));
    let example = include_str!("../../../examples/anti-dpi.toml");
    std::fs::write(&path, format!("{example}\n[anti_dpi.resolver]\nhostname='dns.example.com'\nbootstrap=['1.1.1.1']\n")).unwrap();
    let path = path.to_str().unwrap();
    let args = ["anti-dpi", "diagnose", "--config", path, "--domains", "discord.com"];
    let result = Command::new(env!("CARGO_BIN_EXE_theia")).args(args).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("Diagnostic preview (no network requests)"));
    assert!(output.contains("discord.com"));
    assert!(output.contains("dns.example.com"));
    assert!(output.contains("AwaitingAcceptance"));
    assert!(output.contains("Confirm exact plan with SHA256="));
    let result = Command::new(env!("CARGO_BIN_EXE_theia")).args(args)
        .args(["--confirm", &"00".repeat(32)]).output().unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("review again"));
    let invalid = Command::new(env!("CARGO_BIN_EXE_theia")).args(args)
        .arg("--anonymous").output().unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn standalone_apply_is_explicit_and_connect_preview_is_offline() {
    let dir = std::env::temp_dir().join(format!("theia-f20-apply-cli-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("anti-dpi.toml");
    std::fs::write(&path, include_str!("../../../examples/anti-dpi.toml")).unwrap();
    let run = |operation: &str, digest: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_theia"));
        command.args(["anti-dpi", operation, "--config"]).arg(&path);
        if let Some(digest) = digest { command.args(["--confirm", digest]); }
        command.output().unwrap()
    };
    let preview = run("enroll", None);
    assert!(preview.status.success());
    let text = String::from_utf8(preview.stdout).unwrap();
    let digest = text.split("Confirm policy SHA256=").last().unwrap().trim();
    assert_eq!(digest.len(), 64);
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    assert!(!run("apply", Some(digest)).status.success());
    assert!(!run("enroll", Some(&"00".repeat(32))).status.success());
    assert!(run("enroll", Some(digest)).status.success());
    assert!(run("apply", Some(digest)).status.success());
    let connect = run("connect", None);
    assert!(connect.status.success());
    let text = String::from_utf8(connect.stdout).unwrap();
    assert!(text.contains("Pass/Drop only"));
    assert!(text.contains("Modify is denied"));
    std::fs::remove_dir_all(dir).unwrap();
}
