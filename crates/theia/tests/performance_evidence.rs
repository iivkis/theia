//! Native-binary benchmark smoke. The independent Python witness records
//! only aggregate counts and timing from its own loopback fixtures.
//! Same-binary A/A trials deliberately cannot become release evidence.
#[path = "support/private_pem.rs"]
mod private_pem;

use std::{fs, path::PathBuf, process::Command};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "mandatory native browser-e2e job supplies psutil and an exact tested SHA"]
fn native_binary_performance_evidence_smoke() {
    let sha = std::env::var("THEIA_PERF_TESTED_SHA").expect("exact tested SHA");
    let output = PathBuf::from(std::env::var_os("THEIA_PERF_OUTPUT").expect("evidence path"));
    let directory = std::env::temp_dir().join(format!("theia-perf-fixture-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let scratch = Scratch(directory);
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = scratch.0.join("cert.pem");
    let key = scratch.0.join("key.pem");
    fs::write(&cert, certificate.cert.pem()).unwrap();
    private_pem::write_new_key(&key, certificate.key_pair.serialize_pem());
    let binary = env!("CARGO_BIN_EXE_theia");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/benchmark/run_loopback_performance.py");
    let mut command = Command::new("python");
    command.arg(script)
        .args(["--baseline", binary, "--candidate", binary])
        .args(["--baseline-revision", &sha, "--candidate-revision", &sha])
        .arg("--cert").arg(cert).arg("--key").arg(key)
        .arg("--output").arg(output);
    let result = command.output().expect("native measurement harness");
    assert!(result.status.success(), "controlled benchmark failed: {}",
            String::from_utf8_lossy(&result.stderr));
}
