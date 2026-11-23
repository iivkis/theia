//! M4.2b0: a strict, read-only compatibility preflight for a future reload.
//!
//! No runtime swap occurs here. This intentionally permits only changes to
//! existing users' token digests/disabled flags and existing inbound grants.
//! Listener/TLS identity, quota policy and user inventory remain immutable.
//! Real reload/rollback and Windows management IPC are separate milestones.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
use crate::config;
use crate::config::{Config, ServerDocument};
use std::fmt;

#[cfg(any(target_os = "linux", target_os = "windows", test))]
use sha2::{Digest, Sha256};
#[cfg(any(target_os = "linux", target_os = "windows", test))]
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadCheckError {
    InvalidConfig,
    RequiresRestart,
    IdentityDrift,
}

impl fmt::Display for ReloadCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("candidate config invalid"),
            Self::RequiresRestart => f.write_str("candidate changes restart-only fields"),
            Self::IdentityDrift => f.write_str("TLS identity files changed or cannot be verified"),
        }
    }
}
impl std::error::Error for ReloadCheckError {}

/// Structural compatibility is deliberately narrower than an eventual
/// transactional hot reload. It does not read PEM files or publish a new
/// snapshot, and its success is never an 'applied' receipt.
pub fn assess_reload(
    running: &ServerDocument,
    candidate: &ServerDocument,
) -> Result<(), ReloadCheckError> {
    Config::Server(candidate.clone())
        .validate()
        .map_err(|_| ReloadCheckError::InvalidConfig)?;
    if !candidate.server.enabled
        || candidate.schema_version != running.schema_version
        || candidate.management != running.management
        || candidate.ui != running.ui
        || candidate.server.policy != running.server.policy
        || candidate.server.inbounds.len() != running.server.inbounds.len()
        || candidate.server.users.len() != running.server.users.len()
    {
        return Err(ReloadCheckError::RequiresRestart);
    }
    for (before, after) in running
        .server
        .inbounds
        .iter()
        .zip(&candidate.server.inbounds)
    {
        if before.id != after.id
            || before.quic_listen != after.quic_listen
            || before.h2_listen != after.h2_listen
            || before.server_name != after.server_name
            || before.tls_cert != after.tls_cert
            || before.tls_key != after.tls_key
        {
            return Err(ReloadCheckError::RequiresRestart);
        }
    }
    if running
        .server
        .users
        .iter()
        .zip(&candidate.server.users)
        .any(|(before, after)| before.id != after.id)
    {
        return Err(ReloadCheckError::RequiresRestart);
    }
    Ok(())
}

/// Digest of *loaded* PEM bytes, not the paths in TOML. Never log these
/// digests: the private key itself is not captured in this snapshot.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
#[derive(Clone)]
pub(crate) struct IdentityHash {
    cert: [u8; 32],
    key: [u8; 32],
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
impl IdentityHash {
    pub(crate) fn from_pem(cert: &[u8], key: &[u8]) -> Self {
        Self {
            cert: Sha256::digest(cert).into(),
            key: Sha256::digest(key).into(),
        }
    }

    pub(crate) fn matches(&self, cert: &[u8], key: &[u8]) -> bool {
        let expected = Self::from_pem(cert, key);
        self.cert == expected.cert && self.key == expected.key
    }
}

/// Safe, bounded validation against the exact active server document and the
/// PEM bytes used when constructing the actual TLS acceptors. A successful
/// check never authorizes reloading or changes an existing connection.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub(crate) struct ReloadPreflight {
    config_path: PathBuf,
    active: ServerDocument,
    identities: Vec<IdentityHash>,
    restart_probe_lock: std::sync::Mutex<()>,
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
impl ReloadPreflight {
    pub(crate) fn new(
        config_path: PathBuf,
        active: ServerDocument,
        identities: Vec<IdentityHash>,
    ) -> Self {
        Self {
            config_path,
            active,
            identities,
            restart_probe_lock: std::sync::Mutex::new(()),
        }
    }

    /// Read the candidate exactly once and verify every restart-only
    /// field and the actual PEM bytes loaded by the live listeners. The owned
    /// returned document is the only one later staged/published: no second
    /// read of TOML after validation.
    pub(crate) fn load_candidate(&self) -> Result<ServerDocument, ReloadCheckError> {
        let candidate = match config::read_file(&self.config_path) {
            Ok(Config::Server(document)) => document,
            _ => return Err(ReloadCheckError::InvalidConfig),
        };
        self.validate_candidate(candidate)
    }

    /// The TUI can only apply the *exact bytes* of its last saved document.
    /// Read the live server's file ONCE and compare its digest before parsing.
    /// This rejects a mismatched path, out-of-band edits and a stale preview;
    /// the file worker is still purely read-only and cancellation-safe.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn load_candidate_bound(
        &self,
        expected_sha256: [u8; 32],
    ) -> Result<ServerDocument, ReloadCheckError> {
        use std::io::Read;
        let file =
            std::fs::File::open(&self.config_path).map_err(|_| ReloadCheckError::InvalidConfig)?;
        let mut contents = zeroize::Zeroizing::new(Vec::new());
        file.take(1024 * 1024 + 1)
            .read_to_end(&mut contents)
            .map_err(|_| ReloadCheckError::InvalidConfig)?;
        if contents.len() > 1024 * 1024 {
            return Err(ReloadCheckError::InvalidConfig);
        }
        let observed: [u8; 32] = Sha256::digest(contents.as_slice()).into();
        if observed != expected_sha256 {
            return Err(ReloadCheckError::InvalidConfig);
        }
        let source = std::str::from_utf8(&contents).map_err(|_| ReloadCheckError::InvalidConfig)?;
        let candidate = match config::parse(source) {
            Ok(Config::Server(document)) => document,
            _ => return Err(ReloadCheckError::InvalidConfig),
        };
        self.validate_candidate(candidate)
    }

    fn validate_candidate(
        &self,
        candidate: ServerDocument,
    ) -> Result<ServerDocument, ReloadCheckError> {
        assess_reload(&self.active, &candidate)?;
        if self.identities.len() != candidate.server.inbounds.len() {
            return Err(ReloadCheckError::IdentityDrift);
        }
        for (inbound, identity) in candidate.server.inbounds.iter().zip(&self.identities) {
            let cert = crate::server::pem_data(&inbound.tls_cert, false)
                .map_err(|_| ReloadCheckError::IdentityDrift)?;
            let key = crate::server::pem_data(&inbound.tls_key, true)
                .map_err(|_| ReloadCheckError::IdentityDrift)?;
            if !identity.matches(&cert, &key) {
                return Err(ReloadCheckError::IdentityDrift);
            }
        }
        Ok(candidate)
    }

    /// Restart-only planning: read one bounded candidate, verify real TLS
    /// identities and temporarily probe all fresh OS listener addresses.
    /// Never publishes auth, stops old listeners or reserves ports for later.
    pub(crate) fn check_restart_file(
        &self,
    ) -> Result<crate::restart_guard::RestartVerdict, crate::restart_guard::RestartError> {
        // Failed/cancelled IPC handlers cannot launch a growing backlog of
        // slow filesystem operations or hold candidate ports indefinitely.
        // The guard stays owned by the worker even after its client times out.
        let _single_flight = self.restart_probe_lock.try_lock().map_err(|_| {
            crate::restart_guard::RestartError::ProbeBusy
        })?;
        let candidate = match config::read_file(&self.config_path) {
            Ok(Config::Server(document)) => document,
            _ => return Err(crate::restart_guard::RestartError::InvalidConfig),
        };
        crate::restart_guard::probe(&self.active, &self.identities, &candidate)
    }

    /// Still a read-only check, never an implicit Apply.
    pub(crate) fn check_file(&self) -> Result<(), ReloadCheckError> {
        self.load_candidate().map(|_| ())
    }

    #[cfg(test)]
    fn check_document_identity(
        &self,
        candidate: &ServerDocument,
        certs: &[(&[u8], &[u8])],
    ) -> Result<(), ReloadCheckError> {
        assess_reload(&self.active, candidate)?;
        if self.identities.len() != certs.len() {
            return Err(ReloadCheckError::IdentityDrift);
        }
        if self
            .identities
            .iter()
            .zip(certs)
            .all(|(hash, (cert, key))| hash.matches(cert, key))
        {
            Ok(())
        } else {
            Err(ReloadCheckError::IdentityDrift)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Inbound, Management, ServerPolicy, ServerSettings, Ui, User};

    fn document() -> ServerDocument {
        ServerDocument {
            schema_version: 1,
            server: ServerSettings {
                enabled: true,
                inbounds: vec![Inbound {
                    id: "edge".into(),
                    allowed_user_ids: vec!["user".into()],
                    quic_listen: "127.0.0.1:9443".into(),
                    h2_listen: "127.0.0.1:9443".into(),
                    server_name: "edge.example.org".into(),
                    tls_cert: "file:/tmp/theia-cert.pem".into(),
                    tls_key: "file:/tmp/theia-key.pem".into(),
                }],
                users: vec![User {
                    id: "user".into(),
                    token_sha256: "b".repeat(64),
                    disabled: false,
                }],
                policy: ServerPolicy {
                    allow_private_ips: false,
                    max_connections_per_user: 2,
                    max_connections_total: 8,
                    connect_timeout_ms: 1500,
                },
            },
            management: Management {
                ipc: "auto".into(),
                log_level: "info".into(),
            },
            ui: Ui {
                language: "ru".into(),
            },
        }
    }

    #[test]
    fn tls_content_change_is_rejected_even_if_reference_paths_match() {
        let doc = document();
        let snapshot = ReloadPreflight::new(
            std::path::Path::new("/tmp/nonexistent").to_owned(),
            doc.clone(),
            vec![IdentityHash::from_pem(b"original cert", b"original key")],
        );
        assert_eq!(
            snapshot.check_document_identity(&doc, &[(b"original cert", b"original key")]),
            Ok(())
        );
        assert_eq!(
            snapshot.check_document_identity(&doc, &[(b"replacement cert", b"original key")]),
            Err(ReloadCheckError::IdentityDrift)
        );
        assert_eq!(
            snapshot.check_document_identity(&doc, &[(b"original cert", b"replacement key")]),
            Err(ReloadCheckError::IdentityDrift)
        );
        assert_eq!(
            snapshot.check_document_identity(&doc, &[]),
            Err(ReloadCheckError::IdentityDrift)
        );
    }

    #[test]
    fn missing_candidate_file_is_invalid_not_applied() {
        let doc = document();
        let snapshot = ReloadPreflight::new(
            std::path::Path::new("/definitely-not-a-theia-config-file").to_owned(),
            doc,
            vec![IdentityHash::from_pem(b"original", b"key")],
        );
        assert_eq!(snapshot.check_file(), Err(ReloadCheckError::InvalidConfig));
    }
    #[test]
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn on_disk_preflight_detects_pem_drift_without_writing_or_publishing() {
        use std::fs;
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!(
            "theia-preflight-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let cert = directory.join("cert.pem");
        let key = directory.join("key.pem");
        let config_file = directory.join("server.toml");
        let cert_bytes = b"certificate bytes captured when listener started";
        let key_bytes = b"private key bytes captured when listener started";
        fs::write(&cert, cert_bytes).unwrap();
        fs::write(&key, key_bytes).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let mut active = document();
        active.server.inbounds[0].tls_cert = format!("file:{}", cert.display());
        active.server.inbounds[0].tls_key = format!("file:{}", key.display());
        fs::write(
            &config_file,
            Config::Server(active.clone()).to_toml().unwrap(),
        )
        .unwrap();
        let snapshot = ReloadPreflight::new(
            config_file.clone(),
            active.clone(),
            vec![IdentityHash::from_pem(cert_bytes, key_bytes)],
        );
        assert_eq!(snapshot.check_file(), Ok(()));
        let mut candidate = active;
        candidate.server.users[0].token_sha256 = "c".repeat(64);
        fs::write(
            &config_file,
            Config::Server(candidate.clone()).to_toml().unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot.check_file(), Ok(()), "candidate is not committed");

        fs::write(&cert, b"swapped certificate").unwrap();
        assert_eq!(snapshot.check_file(), Err(ReloadCheckError::IdentityDrift));
        fs::write(&cert, cert_bytes).unwrap();
        fs::write(&key, b"swapped key").unwrap();
        assert_eq!(snapshot.check_file(), Err(ReloadCheckError::IdentityDrift));
        fs::write(&key, key_bytes).unwrap();
        candidate.server.inbounds[0].h2_listen = "127.0.0.1:9555".into();
        fs::write(&config_file, Config::Server(candidate).to_toml().unwrap()).unwrap();
        assert_eq!(
            snapshot.check_file(),
            Err(ReloadCheckError::RequiresRestart)
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
