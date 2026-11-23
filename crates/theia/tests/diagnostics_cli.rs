//! Black-box diagnostics regressions, exercised by native Linux/Windows CI.
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn isolated_dir() -> PathBuf {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("theia-trace-cli-{}-{stamp}", std::process::id()))
}

fn invoke(dir: &PathBuf, args: &[&str], disabled: bool) -> std::process::Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_theia"));
    process.args(args).env("THEIA_TRACE_DIR", dir);
    if disabled {
        process.env("THEIA_TRACE_OFF", "1");
    } else {
        process.env_remove("THEIA_TRACE_OFF");
    }
    process.output().expect("CLI binary must launch")
}

#[test]
fn cli_writes_trace_by_default_without_leaking_arguments_or_credentials() {
    let dir = isolated_dir();
    let secret = "secret-token-DO-NOT-LOG";
    let failed = invoke(&dir, &["client", "run", "--config", secret], false);
    assert_eq!(failed.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&failed.stderr).contains(secret));
    let ok = invoke(&dir, &["--help"], false);
    assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
    let files: Vec<_> = fs::read_dir(&dir).unwrap().map(|entry| entry.unwrap().path()).collect();
    assert_eq!(files.len(), 2, "each process owns an isolated trace");
    let mut combined = String::new();
    for file in files {
        let size = fs::metadata(&file).unwrap().len();
        assert!(size > 0);
        assert!(size <= theia::diagnostics::MAX_LOG_BYTES / 2);
        combined.push_str(&fs::read_to_string(file).unwrap());
    }
    assert!(combined.contains("component=process event=started"));
    assert!(combined.contains("component=process event=failed"));
    assert!(combined.contains("component=process event=completed"));
    assert!(combined.contains("at=") && combined.contains("main.rs:"));
    assert!(!combined.contains(secret));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn explicitly_disabled_trace_creates_no_log_directory() {
    let dir = isolated_dir();
    let result = invoke(&dir, &["--version"], true);
    assert!(result.status.success());
    assert!(!dir.exists());
}

#[cfg(unix)]
#[test]
fn trace_files_are_readable_only_by_the_owner() {
    use std::os::unix::fs::PermissionsExt;

    let dir = isolated_dir();
    let result = invoke(&dir, &["--version"], false);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let log = fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
    assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(log).unwrap().permissions().mode() & 0o777, 0o600);
    fs::remove_dir_all(dir).unwrap();
}
