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
    assert!(String::from_utf8_lossy(&help.stdout).contains("no proxy runtime"));
    assert!(help.stderr.is_empty());

    let version = invoke(&["--version"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("theia 0.1.0"));
}

#[test]
fn accepted_runtime_commands_fail_closed() {
    for args in [
        vec!["tui", "--role", "client"],
        vec!["server", "run", "--config", "missing.toml"],
        vec!["client", "run", "--config", "missing.toml"],
        vec!["config", "validate", "--config", "missing.toml"],
    ] {
        let result = invoke(&args);
        assert_eq!(result.status.code(), Some(3), "{args:?}");
        assert!(result.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("not implemented"),
            "{args:?}"
        );
    }
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
    assert_eq!(result.status.code(), Some(3));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(secret));
}
