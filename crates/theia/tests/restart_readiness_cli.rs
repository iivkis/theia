//! M4.2g: restart preflight must exist as an explicit, safe IPC command.
//! A missing server must fail via private IPC, not argument parser fallback.
use std::process::Command;

#[test]
fn restart_check_is_a_recognized_explicit_management_command() {
    let binary = env!("CARGO_BIN_EXE_theia");
    let output = Command::new(binary)
        .args(["server", "restart", "--check"])
        .env_remove("THEIA_CONTROL_DIR")
        .env_remove("THEIA_CONTROL_PIPE")
        .output()
        .expect("compiled binary");
    assert!(!output.status.success(), "no manager must never be reported ready");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("management status unavailable"),
        "restart check must use native IPC rather than parser rejection"
    );
    assert!(
        !stderr.contains("invalid arguments"),
        "explicit restart check command is part of the CLI contract"
    );
}
