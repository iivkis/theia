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
