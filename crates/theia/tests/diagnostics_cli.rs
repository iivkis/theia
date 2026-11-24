//! Black-box diagnostics regressions, exercised by native Linux/Windows CI.
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn isolated_dir() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("theia-trace-cli-{}-{stamp}", std::process::id()))
}

fn invoke(dir: &PathBuf, args: &[&str], disabled: bool) -> std::process::Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_theia"));
    process
        .args(args)
        .env("THEIA_TRACE_DIR", dir)
        .env_remove("THEIA_TRACE_LEVEL")
        .env("TOKIO_WORKER_THREADS", "2");
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
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
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
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let log = fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(log).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn concurrent_cli_startup_shares_new_private_directory_without_stderr() {
    let root = isolated_dir();
    let dir = root.join("new").join("logs");
    assert!(!root.exists());
    let children: Vec<_> = (0..12)
        .map(|_| {
            Command::new(env!("CARGO_BIN_EXE_theia"))
                .arg("--help")
                .env("THEIA_TRACE_DIR", &dir)
                .env_remove("THEIA_TRACE_OFF")
                .env_remove("THEIA_TRACE_LEVEL")
                .env("TOKIO_WORKER_THREADS", "2")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn concurrent CLI")
        })
        .collect();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let traces: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(traces.len(), 12);
    for path in traces {
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("component=process event=started"));
        assert!(content.contains("component=process event=completed"));
    }
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn insecure_existing_trace_directory_warns_without_mutating_it() {
    use std::os::unix::fs::PermissionsExt;

    let dir = isolated_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let output = invoke(&dir, &["--help"], false);
    assert!(output.status.success());
    let warning = String::from_utf8_lossy(&output.stderr);
    assert!(warning.contains("file trace unavailable"));
    assert!(!warning.contains(dir.to_str().unwrap()));
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o755
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn quiet_trace_keeps_failures_and_off_overrides_detailed_mode() {
    let dir = isolated_dir();
    let failed = Command::new(env!("CARGO_BIN_EXE_theia"))
        .arg("--unknown")
        .env("THEIA_TRACE_DIR", &dir)
        .env("THEIA_TRACE_LEVEL", "warn")
        .env_remove("THEIA_TRACE_OFF")
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(2));
    let log = fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
    let content = fs::read_to_string(log).unwrap();
    assert!(content.contains("level=ERROR component=process event=failed"));
    assert!(!content.contains("level=INFO"));
    assert!(!content.contains("level=DEBUG"));
    assert!(!content.contains("level=TRACE"));
    fs::remove_dir_all(&dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_theia"))
        .arg("--version")
        .env("THEIA_TRACE_DIR", &dir)
        .env("THEIA_TRACE_LEVEL", "trace")
        .env("THEIA_TRACE_OFF", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!dir.exists());
}
