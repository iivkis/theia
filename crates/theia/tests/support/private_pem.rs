//! Write a new TLS test key using the exact production private-file constructor.
//! Every fixture lives under a test-owned fresh directory. Never weaken the
//! runtime reader to accommodate a test's inherited Windows DACL.
use std::{io::Write, path::Path};

pub fn write_new_key(path: &Path, bytes: impl AsRef<[u8]>) {
    let mut file =
        theia::client_import::create_private_file(path).expect("create protected TLS test key");
    file.write_all(bytes.as_ref()).unwrap();
    file.sync_all().unwrap();
}
