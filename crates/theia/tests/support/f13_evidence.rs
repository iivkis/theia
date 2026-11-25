//! Test-only sanitized measurements; never write capture bytes or credentials.
use std::{fs::OpenOptions, io::Write, path::PathBuf};

pub fn emit(name: &str, json: &str) {
    if let Some(directory) = std::env::var_os("THEIA_F13_EVIDENCE_DIR") {
        let path = PathBuf::from(directory).join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("create fresh bounded F-13 observation");
        file.write_all(json.as_bytes())
            .expect("write sanitized F-13 observation");
        file.sync_all().expect("flush sanitized F-13 observation");
    }
}
