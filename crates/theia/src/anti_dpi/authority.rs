//! Durable standalone policy publication. Saving a document is not Apply.
//! No server snapshot, profile, or credentials participate in this namespace.
use super::{invalid, Document, PreparedPolicy};
use crate::config::{self, ConfigError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Floor {
    schema_version: u32,
    id: String,
    revision: u64,
    digest: [u8; 32],
}

/// Resolve only a regular, non-reparse leaf. Canonicalizing the existing
/// object collapses case/short-name aliases before deriving the floor name.
/// Parent directories must still be trusted (see bounded_input).
pub(crate) fn canonical_config_path(path: &Path) -> Result<PathBuf, ConfigError> {
    let path = std::path::absolute(path)
        .map_err(|_| invalid("anti_dpi", "cannot locate configuration"))?;
    if !crate::bounded_input::explicit_file_path(&path) ||
        !std::fs::symlink_metadata(&path).is_ok_and(|m| crate::bounded_input::regular_file(&m)) {
        return Err(invalid("anti_dpi", "unsafe configuration path"));
    }
    let canonical = std::fs::canonicalize(&path)
        .map_err(|_| invalid("anti_dpi", "cannot resolve configuration path"))?;
    if !crate::bounded_input::explicit_file_path(&canonical) {
        return Err(invalid("anti_dpi", "unsafe canonical path"));
    }
    Ok(canonical)
}

fn floor_path(path: &Path) -> Result<PathBuf, ConfigError> {
    let name = path.file_name().ok_or_else(|| invalid("anti_dpi.floor", "configuration filename missing"))?;
    let mut hash = Sha256::new();
    hash.update(b"theia/standalone/floor/v1\0");
    hash.update(name.as_encoded_bytes());
    let digest = hash.finalize();
    let mut hex = String::new();
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    Ok(path.with_file_name(format!(".anti-dpi-floor-{hex}.toml")))
}

fn load_floor(path: &Path) -> Result<Option<Vec<u8>>, ConfigError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => crate::bounded_input::read(path, 4096, true, true)
            .map(|b| Some(b.to_vec()))
            .map_err(|_| invalid("anti_dpi.floor", "unsafe or unreadable revision floor")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(invalid("anti_dpi.floor", "cannot inspect revision floor")),
    }
}

fn decode(bytes: &[u8]) -> Result<Floor, ConfigError> {
    let value: Floor = toml::from_str(std::str::from_utf8(bytes)
        .map_err(|_| invalid("anti_dpi.floor", "invalid revision floor"))?)
        .map_err(|_| invalid("anti_dpi.floor", "invalid revision floor"))?;
    if value.schema_version != 1 || !config::valid_id(&value.id) || value.revision == 0 {
        return Err(invalid("anti_dpi.floor", "invalid revision floor"));
    }
    Ok(value)
}

fn checkpoint(policy: &PreparedPolicy) -> Floor {
    Floor {
        schema_version: 1,
        id: policy.id().to_owned(),
        revision: policy.revision(),
        digest: policy.digest(),
    }
}

fn accepts(previous: &Floor, next: &Floor) -> Result<(), ConfigError> {
    if previous.id != next.id || next.revision < previous.revision ||
        (next.revision == previous.revision && next.digest != previous.digest)
    {
        return Err(invalid("anti_dpi.floor", "identity mismatch, rollback or same-revision equivocation"));
    }
    Ok(())
}

pub struct Candidate {
    path: PathBuf,
    bytes: Vec<u8>,
    document: Document,
    policy: PreparedPolicy,
}

impl Candidate {
    pub fn read(path: &Path) -> Result<Self, ConfigError> {
        let path = canonical_config_path(path)?;
        let bytes = config::editor_bytes(&path)?;
        let document = Document::parse(std::str::from_utf8(&bytes)
            .map_err(|_| invalid("anti_dpi", "configuration is not UTF-8"))?)?;
        let policy = document.prepare()?;
        Ok(Self { path, bytes, document, policy })
    }

    pub fn document(&self) -> &Document { &self.document }

    #[cfg(windows)]
    pub(crate) fn path(&self) -> &Path { &self.path }

    pub fn digest(&self) -> [u8; 32] { self.policy.digest() }

    pub fn preview(&self) -> String {
        let mut text = String::new();
        use std::fmt::Write as _;
        let _ = writeln!(text, "Standalone policy: revision {}, {} rules",
            self.policy.revision(), self.document.anti_dpi.rules.len());
        let _ = writeln!(text, "Default: Pass only if all rules are NoMatch; Modify never falls back to Pass.");
        for (index, rule) in self.document.anti_dpi.rules.iter().enumerate() {
            let _ = writeln!(text, "{}. {}: {:?}; domains={:?}; ips={:?}; apps={:?}",
                index + 1, rule.name, rule.action, rule.domains, rule.ips, rule.applications);
        }
        let _ = writeln!(text, "Direct egress consent: {}; Anti-DPI consent: {}",
            self.document.anti_dpi.consent.direct_egress, self.document.anti_dpi.consent.direct_dpi);
        let _ = writeln!(text, "Apply publishes only the durable local policy. No network or OS proxy changes.");
        text.push_str("Confirm policy SHA256=");
        for byte in self.digest() { let _ = write!(text, "{byte:02x}"); }
        text
    }

    pub fn connect_preview(&self) -> String {
        let config = &self.document.anti_dpi;
        let mut text = self.preview();
        use std::fmt::Write as _;
        let _ = writeln!(text, "\nWindows System Proxy development mode: Pass/Drop only; Modify is denied.");
        let _ = writeln!(text, "HTTP: {}; SOCKS5: {}", config.proxy.http_listen, config.proxy.socks5_listen);
        if let Some(resolver) = &config.resolver {
            let _ = writeln!(text, "DoH: https://{}/dns-query; explicit bootstrap {:?}", resolver.hostname, resolver.bootstrap);
        } else {
            text.push_str("Resolver not configured; connection will be refused.\n");
        }
        text.push_str("Local egress discloses your IP. Only WinINet proxy settings are changed; this is not TUN or host-wide protection. Ctrl+C requests conditional restoration. A saved and explicitly applied revision is required.\n");
        text
    }

    fn assert_saved(&self) -> Result<(), ConfigError> {
        if config::editor_bytes(&self.path).is_ok_and(|bytes| bytes == self.bytes) {
            Ok(())
        } else {
            Err(invalid("anti_dpi", "saved configuration changed; review again"))
        }
    }

    /// Explicit first enrollment. A missing floor is not silently recreated
    /// by Apply or Connect. Resetting trust requires a separate reviewed flow.
    pub fn enroll(&self, expected: [u8; 32]) -> Result<(), ConfigError> {
        self.publish(expected, true, None)
    }

    pub fn apply(&self, expected: [u8; 32]) -> Result<(), ConfigError> {
        self.publish(expected, false, None)
    }

    #[cfg(windows)]
    pub(crate) fn apply_over(&self, expected: [u8; 32], active: &Active) -> Result<(), ConfigError> {
        if self.path != active.candidate.path {
            return Err(invalid("anti_dpi.floor", "wrong active configuration"));
        }
        self.publish(expected, false, Some(&active.floor_bytes))
    }

    fn publish(&self, expected: [u8; 32], enroll: bool, active_floor: Option<&[u8]>) -> Result<(), ConfigError> {
        if self.digest() != expected {
            return Err(invalid("anti_dpi", "confirmation does not match policy"));
        }
        let _config_lock = config::editor_lock(&self.path)?;
        self.assert_saved()?;
        let path = floor_path(&self.path)?;
        let previous = load_floor(&path)?;
        if active_floor.is_some_and(|expected| previous.as_deref() != Some(expected)) {
            return Err(invalid("anti_dpi.floor", "active revision floor changed; review or recover"));
        }
        let next = checkpoint(&self.policy);
        match &previous {
            Some(raw) => {
                if enroll {
                    return Err(invalid("anti_dpi.floor", "already enrolled; use Apply"));
                }
                let old = decode(raw)?;
                accepts(&old, &next)?;
                if old == next {
                    return config::guarded_trust_assert(&path, raw);
                }
            }
            None if !enroll => return Err(invalid("anti_dpi.floor", "missing floor; explicit enrollment required")),
            None => {}
        }
        let value = toml::to_string(&next)
            .map_err(|_| invalid("anti_dpi.floor", "cannot encode revision floor"))?;
        config::guarded_trust_write(&path, &value, previous.as_deref())
            .map_err(|error| match error {
                config::WriteFailure::BeforeReplace(e) => e,
                config::WriteFailure::AfterReplace(_) => invalid("anti_dpi.floor", "publication uncertain; inspect saved floor before continuing"),
            })
    }

    pub(crate) fn activate(self) -> Result<Active, ConfigError> {
        self.assert_saved()?;
        let floor = floor_path(&self.path)?;
        let bytes = load_floor(&floor)?.ok_or_else(|| invalid("anti_dpi.floor", "policy not enrolled/applied"))?;
        if decode(&bytes)? != checkpoint(&self.policy) {
            return Err(invalid("anti_dpi.floor", "saved policy is not the applied revision"));
        }
        let active = Active { candidate: self, floor, floor_bytes: bytes, revoked: AtomicBool::new(false),
            #[cfg(windows)]
            evidence: crate::routing::dpi::StandaloneEvidence::new(),
        };
        if !active.live() {
            return Err(invalid("anti_dpi.floor", "policy changed during activation"));
        }
        Ok(active)
    }
}

/// One immutable publication. Observed file/floor loss is latched so
/// restoring bytes cannot revive a previously revoked flow or generation.
pub(crate) struct Active {
    candidate: Candidate,
    floor: PathBuf,
    floor_bytes: Vec<u8>,
    revoked: AtomicBool,
    #[cfg(windows)]
    pub(crate) evidence: crate::routing::dpi::StandaloneEvidence,
}

impl Active {
    pub(crate) fn document(&self) -> &Document { &self.candidate.document }
    pub(crate) fn policy(&self) -> &PreparedPolicy { &self.candidate.policy }

    #[cfg(windows)]
    pub(crate) fn matches_path(&self, path: &Path) -> bool { self.candidate.path == path }

    pub(crate) fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    pub(crate) fn live(&self) -> bool {
        if self.revoked.load(Ordering::Acquire) {
            return false;
        }
        // Save is not Apply. A change to saved bytes is conservatively
        // treated as loss of the reviewed configuration, not as permission
        // to use a new rule set. Reconnect after explicit Apply.
        if self.candidate.assert_saved().is_err() ||
            !load_floor(&self.floor).is_ok_and(|bytes| bytes.as_deref() == Some(self.floor_bytes.as_slice()))
        {
            self.revoke();
        }
        !self.revoked.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("theia-f20-authority-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir(&path).unwrap();
            let config = path.join("anti-dpi.toml");
            std::fs::write(&config, include_str!("../../../../examples/anti-dpi.toml")).unwrap();
            Self(config)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(self.0.parent().unwrap()); }
    }

    #[test]
    fn enrollment_apply_rollback_equivocation_and_latched_revoke() {
        let fixture = Fixture::new();
        let path = &fixture.0;
        let first = Candidate::read(path).unwrap();
        let digest = first.digest();
        assert!(first.apply(digest).is_err());
        assert!(first.enroll([0; 32]).is_err());
        first.enroll(digest).unwrap();
        assert!(first.enroll(digest).is_err());
        first.apply(digest).unwrap();
        let active = first.activate().unwrap();
        assert!(active.live());
        let original = std::fs::read(path).unwrap();

        let mut changed = Document::read(path).unwrap();
        changed.anti_dpi.consent.direct_egress = true;
        std::fs::write(path, changed.to_toml().unwrap()).unwrap();
        let equivocation = Candidate::read(path).unwrap();
        assert!(equivocation.apply(equivocation.digest()).is_err());
        assert!(!active.live());
        std::fs::write(path, &original).unwrap();
        assert!(!active.live());

        changed.anti_dpi.revision += 1;
        std::fs::write(path, changed.to_toml().unwrap()).unwrap();
        let newer = Candidate::read(path).unwrap();
        newer.apply(newer.digest()).unwrap();
        let newer = newer.activate().unwrap();
        assert!(newer.live());
        std::fs::write(path, &original).unwrap();
        let rollback = Candidate::read(path).unwrap();
        assert!(rollback.apply(digest).is_err());
        assert!(rollback.activate().is_err());
        assert!(!newer.live());
    }

    #[test]
    fn floor_with_untrusted_permissions_is_not_accepted() {
        let fixture = Fixture::new();
        let candidate = Candidate::read(&fixture.0).unwrap();
        candidate.enroll(candidate.digest()).unwrap();
        let floor = floor_path(&candidate.path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&floor, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_floor(&floor).is_err());
        }
        #[cfg(windows)]
        {
            let bytes = std::fs::read(&floor).unwrap();
            std::fs::remove_file(&floor).unwrap();
            std::fs::write(&floor, &bytes).unwrap();
            assert!(load_floor(&floor).is_err());
        }
        #[cfg(any(unix, windows))]
        assert!(candidate.activate().is_err());
    }

    #[test]
    fn floor_loss_revokes_and_normal_apply_cannot_recreate_it() {
        let fixture = Fixture::new();
        let first = Candidate::read(&fixture.0).unwrap();
        first.enroll(first.digest()).unwrap();
        let active = first.activate().unwrap();
        let path = floor_path(&canonical_config_path(&fixture.0).unwrap()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(!active.live());
        let candidate = Candidate::read(&fixture.0).unwrap();
        assert!(candidate.apply(candidate.digest()).is_err());
        assert!(candidate.activate().is_err());
        #[cfg(windows)]
        crate::bounded_input::write_test_private(&path, bytes);
        #[cfg(not(windows))]
        {
            std::fs::write(&path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        assert!(!active.live());
    }
}
