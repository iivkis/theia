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
            || before.security_mode != after.security_mode
            || before.reality != after.reality
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
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct IdentityHash {
    cert: [u8; 32],
    key: [u8; 32],
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
impl IdentityHash {
    pub(crate) fn reality(binding:&crate::config::RealityBinding)->Self {
        Self{cert:binding.manifest_sha256,key:binding.identity_sha256}
    }

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

    /// Preserve the cert/key digests actually loaded by listeners while
    /// rebasing the candidate snapshot after an authorization-only CAS.
    pub(crate) fn rebased(&self, candidate: ServerDocument) -> Self {
        Self::new(self.config_path.clone(), candidate, self.identities.clone())
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
        let contents = crate::bounded_input::read(&self.config_path, 1024 * 1024, false, false)
            .map_err(|_| ReloadCheckError::InvalidConfig)?;
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

    pub(crate) fn preview_restart_bound(&self,digest:[u8;32])->Result<(bool,[u8;32]),crate::restart_guard::RestartError>{
        use crate::restart_guard::{RestartError,RestartVerdict};
        let _probe=self.restart_probe_lock.try_lock().map_err(|_|RestartError::ProbeBusy)?;
        let candidate=self.load_restart_candidate_bound(digest)?;
        if !crate::restart_guard::same_shared_limits(&self.active,&candidate){return Err(RestartError::InvalidConfig);}
        let material=crate::server::CapturedTls::capture(&candidate).map_err(|_|RestartError::InvalidTlsIdentity)?;
        let verdict=crate::restart_guard::probe_captured(&self.active,&self.identities,&candidate,&material)?;
        let same_port=match verdict{
            RestartVerdict::SamePortTlsReady=>true,
            RestartVerdict::FreshPortsBindable=>false,
            _=>return Err(RestartError::InvalidConfig),
        };
        Ok((same_port,material.fingerprint()))
    }

    /// Content-bound restart candidate, read ONCE by a cancel-safe worker.
    /// Unlike auth-only Apply this deliberately allows changed listeners/TLS,
    /// but still never commits or opens a production socket on the worker.
    pub(crate) fn load_restart_candidate_bound(
        &self,
        expected_sha256: [u8; 32],
    ) -> Result<ServerDocument, crate::restart_guard::RestartError> {
        let contents = crate::bounded_input::read(&self.config_path, 1024 * 1024, false, false)
            .map_err(|_| crate::restart_guard::RestartError::InvalidConfig)?;
        let observed: [u8; 32] = Sha256::digest(contents.as_slice()).into();
        if observed != expected_sha256 {
            return Err(crate::restart_guard::RestartError::InvalidConfig);
        }
        let source = std::str::from_utf8(&contents)
            .map_err(|_| crate::restart_guard::RestartError::InvalidConfig)?;
        let candidate = match config::parse(source) {
            Ok(Config::Server(document)) => document,
            _ => return Err(crate::restart_guard::RestartError::InvalidConfig),
        };
        Config::Server(candidate.clone())
            .validate()
            .map_err(|_| crate::restart_guard::RestartError::InvalidConfig)?;
        if !candidate.server.enabled {
            return Err(crate::restart_guard::RestartError::InvalidConfig);
        }
        Ok(candidate)
    }

    pub(crate) fn validate_candidate(
        &self,
        candidate: ServerDocument,
    ) -> Result<ServerDocument, ReloadCheckError> {
        assess_reload(&self.active, &candidate)?;
        if self.identities.len() != candidate.server.inbounds.len() {
            return Err(ReloadCheckError::IdentityDrift);
        }
        for (inbound, identity) in candidate.server.inbounds.iter().zip(&self.identities) {
            if let Some(binding)=&inbound.reality {
                if *identity!=IdentityHash::reality(binding){return Err(ReloadCheckError::IdentityDrift);}
                let addr:std::net::SocketAddr=inbound.h2_listen.parse().map_err(|_|ReloadCheckError::IdentityDrift)?;
                let scope=crate::descriptor::Scope{inbound:inbound.id.clone(),endpoint:format!("{}:{}",inbound.server_name,addr.port())};
                let state=crate::reference_health::Store::new(std::path::Path::new(&binding.health_store))
                    .and_then(|store|store.inspect()).map_err(|_|ReloadCheckError::IdentityDrift)?;
                let now=crate::reference_health::unix_now().map_err(|_|ReloadCheckError::IdentityDrift)?;
                crate::reality_provision::inspect_registered(std::path::Path::new(&binding.bundle),binding,&state,&scope,now)
                    .map_err(|_|ReloadCheckError::IdentityDrift)?;
                continue;
            }
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

    /// The quota transaction MUST NOT smuggle a TLS file update via an
    /// unchanged file: reference; actual loaded PEM bytes remain authoritative.
    pub(crate) fn loaded_tls_unchanged(&self, candidate: &ServerDocument) -> bool {
        let mut normalized=candidate.clone();
        normalized.server.policy=self.active.server.policy.clone();
        self.validate_candidate(normalized).is_ok()
    }

    /// Bound and typed TOML is the ONE candidate the native supervisor sees.
    /// This operation can never publish a quota update from a timed-out IPC
    /// worker, and never exposes cert paths or tokens in its response.
    pub(crate) fn load_quota_candidate_bound(
        &self,
        expected_sha256: [u8; 32],
    ) -> Result<ServerDocument, crate::restart_guard::RestartError> {
        let candidate = self.load_restart_candidate_bound(expected_sha256)?;
        if !crate::restart_guard::quota_only(&self.active, &candidate) {
            return Err(crate::restart_guard::RestartError::InvalidConfig);
        }
        if !self.loaded_tls_unchanged(&candidate) {
            return Err(crate::restart_guard::RestartError::InvalidTlsIdentity);
        }
        Ok(candidate)
    }

    /// Advisory only. Actual admission accounting must be checked under
    /// the single quota mutex at CAS, not here during filesystem I/O.
    pub(crate) fn check_quota_file(&self) -> Result<(), crate::restart_guard::RestartError> {
        let _single_flight = self
            .restart_probe_lock
            .try_lock()
            .map_err(|_| crate::restart_guard::RestartError::ProbeBusy)?;
        let candidate = match config::read_file(&self.config_path) {
            Ok(Config::Server(document)) => document,
            _ => return Err(crate::restart_guard::RestartError::InvalidConfig),
        };
        Config::Server(candidate.clone())
            .validate()
            .map_err(|_| crate::restart_guard::RestartError::InvalidConfig)?;
        if !crate::restart_guard::quota_only(&self.active, &candidate) {
            return Err(crate::restart_guard::RestartError::InvalidConfig);
        }
        if !self.loaded_tls_unchanged(&candidate) {
            return Err(crate::restart_guard::RestartError::InvalidTlsIdentity);
        }
        Ok(())
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
        let _single_flight = self
            .restart_probe_lock
            .try_lock()
            .map_err(|_| crate::restart_guard::RestartError::ProbeBusy)?;
        let candidate = match config::read_file(&self.config_path) {
            Ok(Config::Server(document)) => document,
            _ => return Err(crate::restart_guard::RestartError::InvalidConfig),
        };
        crate::restart_guard::probe(&self.active,&self.identities,&candidate)
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
                    security_mode: Default::default(),
                    reality: None,
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
    fn restart_readiness_probe_is_single_flight_even_if_original_ipc_times_out() {
        let snapshot = ReloadPreflight::new(
            std::path::PathBuf::from("nonexistent-theia-restart-preflight.toml"),
            document(),
            Vec::new(),
        );
        let held = snapshot.restart_probe_lock.lock().unwrap();
        assert!(matches!(
            snapshot.check_restart_file(),
            Err(crate::restart_guard::RestartError::ProbeBusy)
        ));
        drop(held);
        assert!(matches!(
            snapshot.check_restart_file(),
            Err(crate::restart_guard::RestartError::InvalidConfig)
        ));
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

    #[test]
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn bound_preflight_rejects_stale_documents_and_tls_drift_and_probes_real_ports() {
        use crate::restart_guard::{RestartError, RestartVerdict};
        use std::{
            fs,
            net::{TcpListener, UdpSocket},
        };
        let directory = std::env::temp_dir().join(format!(
            "theia-bound-preflight-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&directory).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let cert = directory.join("cert.pem");
        let key = directory.join("key.pem");
        let config_path = directory.join("server.toml");
        let mut active = document();
        let generated =
            rcgen::generate_simple_self_signed(vec![active.server.inbounds[0].server_name.clone()])
                .unwrap();
        let cert_pem = generated.cert.pem();
        let key_pem = generated.key_pair.serialize_pem();
        fs::write(&cert, &cert_pem).unwrap();
        fs::write(&key, &key_pem).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        }
        active.server.inbounds[0].tls_cert = format!("file:{}", cert.display());
        active.server.inbounds[0].tls_key = format!("file:{}", key.display());
        let tcp_active = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp_active = UdpSocket::bind("127.0.0.1:0").unwrap();
        active.server.inbounds[0].h2_listen = tcp_active.local_addr().unwrap().to_string();
        active.server.inbounds[0].quic_listen = udp_active.local_addr().unwrap().to_string();
        let snapshot = ReloadPreflight::new(
            config_path.clone(),
            active.clone(),
            vec![IdentityHash::from_pem(
                cert_pem.as_bytes(),
                key_pem.as_bytes(),
            )],
        );
        let write = |doc: &ServerDocument| -> [u8; 32] {
            let raw = Config::Server(doc.clone()).to_toml().unwrap();
            fs::write(&config_path, &raw).unwrap();
            Sha256::digest(raw.as_bytes()).into()
        };
        let digest = write(&active);
        assert_eq!(snapshot.load_candidate_bound(digest).unwrap(), active);
        assert!(snapshot.load_candidate_bound([0; 32]).is_err());
        assert_eq!(
            snapshot.check_restart_file(),
            Ok(RestartVerdict::AuthorizationOnly)
        );
        assert_eq!(
            snapshot.check_quota_file(),
            Err(RestartError::InvalidConfig)
        );
        let mut candidate = active.clone();
        candidate.server.policy.max_connections_total += 1;
        let digest = write(&candidate);
        assert_eq!(
            snapshot.load_quota_candidate_bound(digest).unwrap(),
            candidate
        );
        assert_eq!(snapshot.check_quota_file(), Ok(()));
        assert!(snapshot.load_candidate_bound(digest).is_err());
        assert!(snapshot.load_quota_candidate_bound([0; 32]).is_err());
        assert!(!crate::restart_guard::same_shared_limits(
            &active, &candidate
        ));
        fs::write(&key, b"changed key bytes").unwrap();
        assert_eq!(
            snapshot.check_quota_file(),
            Err(RestartError::InvalidTlsIdentity)
        );
        assert!(matches!(
            snapshot.load_quota_candidate_bound(digest),
            Err(RestartError::InvalidTlsIdentity)
        ));
        fs::write(&key, &key_pem).unwrap();
        let held = snapshot.restart_probe_lock.lock().unwrap();
        assert_eq!(snapshot.check_quota_file(), Err(RestartError::ProbeBusy));
        drop(held);

        let rotated =
            rcgen::generate_simple_self_signed(vec![active.server.inbounds[0].server_name.clone()])
                .unwrap();
        fs::write(&cert, rotated.cert.pem()).unwrap();
        fs::write(&key, rotated.key_pair.serialize_pem()).unwrap();
        write(&active);
        assert_eq!(
            snapshot.check_restart_file(),
            Ok(RestartVerdict::SamePortTlsReady)
        );
        fs::write(&cert, &cert_pem).unwrap();
        fs::write(&key, &key_pem).unwrap();

        candidate = active.clone();
        let fresh_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let fresh_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        candidate.server.inbounds[0].h2_listen = fresh_tcp.local_addr().unwrap().to_string();
        candidate.server.inbounds[0].quic_listen = fresh_udp.local_addr().unwrap().to_string();
        assert!(crate::restart_guard::same_shared_limits(
            &active, &candidate
        ));
        let digest = write(&candidate);
        assert_eq!(
            snapshot.load_restart_candidate_bound(digest).unwrap(),
            candidate
        );
        assert_eq!(
            snapshot.check_restart_file(),
            Err(RestartError::PortUnavailable)
        );
        drop(fresh_tcp);
        assert_eq!(
            snapshot.check_restart_file(),
            Err(RestartError::PortUnavailable)
        );
        drop(fresh_udp);
        assert_eq!(
            snapshot.check_restart_file(),
            Ok(RestartVerdict::FreshPortsBindable)
        );
        // The successful probe is advisory: both fresh ports are released.
        let tcp = TcpListener::bind(&candidate.server.inbounds[0].h2_listen).unwrap();
        let udp = UdpSocket::bind(&candidate.server.inbounds[0].quic_listen).unwrap();
        drop((tcp, udp));
        candidate.server.inbounds[0].h2_listen = active.server.inbounds[0].h2_listen.clone();
        write(&candidate);
        assert_eq!(
            snapshot.check_restart_file(),
            Ok(RestartVerdict::RequiresMaintenance)
        );
        assert!(tcp_active.local_addr().is_ok());
        assert!(udp_active.local_addr().is_ok());
        fs::write(&cert, b"not a PEM certificate").unwrap();
        assert_eq!(
            snapshot.check_restart_file(),
            Err(RestartError::InvalidTlsIdentity)
        );
        fs::write(&config_path, b"invalid TOML").unwrap();
        let digest: [u8; 32] = Sha256::digest(b"invalid TOML").into();
        assert!(snapshot.load_candidate_bound(digest).is_err());
        assert!(snapshot.load_restart_candidate_bound(digest).is_err());
        assert_eq!(
            snapshot.check_restart_file(),
            Err(RestartError::InvalidConfig)
        );
    }
}
