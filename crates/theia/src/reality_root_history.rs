//! Per-server durable independent-root retirement history.
//! Removal does not forget an inbound's last root. Replacing it, including
//! across a maintenance restart, permanently denies the former root in this
//! configuration lineage. An owner who deletes/rolls back the whole protected
//! state or uses a different config path is outside this local threat model.
#![forbid(unsafe_code)]
use crate::config::{self, ServerDocument, WriteFailure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
};

const MAX_ROOTS: usize = 4096;
const MAX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    schema_version: u16,
    last: BTreeMap<String, [u8; 32]>,
    retired: BTreeSet<[u8; 32]>,
}
impl Default for History {
    fn default() -> Self {
        Self { schema_version: 1, last: BTreeMap::new(), retired: BTreeSet::new() }
    }
}
impl History {
    fn validate(&self) -> Result<(), ()> {
        if self.schema_version != 1
            || self.last.len().saturating_add(self.retired.len()) > MAX_ROOTS
            || self.retired.contains(&[0; 32])
            || self.last.iter().any(|(id, root)| {
                id.is_empty() || id.len() > 64
                    || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    || *root == [0; 32] || self.retired.contains(root)
            })
            || self.last.values().collect::<BTreeSet<_>>().len() != self.last.len()
        {
            return Err(());
        }
        Ok(())
    }

    fn next(&self, document: &ServerDocument) -> Result<Self, ()> {
        self.validate()?;
        let mut next = self.clone();
        for inbound in &document.server.inbounds {
            let new = inbound.reality.as_ref().map(|b| b.identity_sha256);
            if let Some(old) = next.last.get(&inbound.id).copied() {
                if Some(old) != new {
                    next.last.remove(&inbound.id);
                    next.retired.insert(old);
                }
            }
            if let Some(root) = new {
                if next.retired.contains(&root) {
                    return Err(());
                }
                next.last.insert(inbound.id.clone(), root);
            }
        }
        // Never erase history just because an inbound was removed.
        next.validate()?;
        Ok(next)
    }

    fn encode(&self) -> Result<String, ()> {
        self.validate()?;
        let raw = toml::to_string(self).map_err(|_| ())?;
        if raw.len() > MAX_BYTES { return Err(()); }
        Ok(raw)
    }
}

pub(crate) struct RootHistory {
    path: PathBuf,
    owner: Option<File>,
    current: History,
    raw: Option<String>,
    // The durable write precedes in-memory publication. If it may have
    // succeeded but publication fails, the supervisor MUST exit rather
    // than continue admitting traffic under a potentially retired root.
    pending: bool,
    retiring: bool,
}
impl RootHistory {
    fn path_for(config_path: &Path) -> Result<PathBuf, ()> {
        let path = fs::canonicalize(config_path).map_err(|_| ())?;
        let mut name = path.as_os_str().to_os_string();
        name.push(".reality-roots.toml");
        Ok(PathBuf::from(name))
    }

    pub(crate) fn open(config_path: &Path, document: &ServerDocument) -> Result<Self, ()> {
        let mut history = Self {
            path: Self::path_for(config_path)?,
            owner: None,
            current: History::default(),
            raw: None,
            pending: false,
            retiring: false,
        };
        let exists = history.exists()?;
        if exists || document.server.inbounds.iter().any(|i| i.reality.is_some()) {
            history.acquire()?;
            history.load()?;
        }
        history.check(document)?;
        Ok(history)
    }

    fn exists(&self) -> Result<bool, ()> {
        Self::exists_at(&self.path)
    }

    fn exists_at(path: &Path) -> Result<bool, ()> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => Ok(true),
            Ok(_) => Err(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(_) => Err(()),
        }
    }

    fn acquire(&mut self) -> Result<(), ()> {
        if self.owner.is_none() {
            let mut name = self.path.as_os_str().to_os_string();
            name.push(".supervisor");
            self.owner = Some(config::editor_lock(Path::new(&name)).map_err(|_| ())?);
        }
        Ok(())
    }

    fn read(path: &Path) -> Result<(String, History), ()> {
        let raw = crate::reality_bootstrap::read_text(path, MAX_BYTES, true).map_err(|_| ())?;
        let current: History = toml::from_str(&raw).map_err(|_| ())?;
        current.validate()?;
        Ok((raw.to_string(), current))
    }

    fn load(&mut self) -> Result<(), ()> {
        if self.exists()? {
            let (raw, current) = Self::read(&self.path)?;
            self.current = current;
            self.raw = Some(raw);
        }
        Ok(())
    }

    /// Read-only planning. Do not take the supervisor's lifetime lock or
    /// create a sidecar from a preview. A running REALITY root must already
    /// be recorded exactly; concurrent publication is rejected by the
    /// caller's revision CAS and the supervisor's exact-byte disk CAS.
    pub(crate) fn preview(
        config_path: &Path, active: &ServerDocument, candidate: &ServerDocument,
    ) -> Result<(), ()> {
        let path = Self::path_for(config_path)?;
        let history = if Self::exists_at(&path)? {
            Self::read(&path)?.1
        } else {
            History::default()
        };
        if active.server.inbounds.iter().any(|inbound| {
            inbound.reality.as_ref().is_some_and(|binding|
                history.last.get(&inbound.id) != Some(&binding.identity_sha256)
            )
        }) {
            return Err(());
        }
        history.next(candidate).map(|_| ())
    }

    pub(crate) fn check(&self, document: &ServerDocument) -> Result<(), ()> {
        self.current.next(document).map(|_| ())
    }

    /// Validate and durably advance only after candidate resources have
    /// been prepared. Unchanged state still uses the exact-byte disk CAS.
    pub(crate) fn advance(&mut self, document: &ServerDocument) -> Result<(), ()> {
        if self.pending { return Err(()); }
        let next = self.current.next(document)?;
        if self.raw.is_none() && next == History::default() {
            return Ok(());
        }
        self.acquire()?;
        if next == self.current {
            let raw = self.raw.as_ref().ok_or(())?;
            return config::guarded_trust_assert(&self.path, raw.as_bytes()).map_err(|_| ());
        }
        let encoded = next.encode()?;
        let retiring = next.retired != self.current.retired;
        match config::guarded_trust_write(&self.path, &encoded, self.raw.as_deref().map(str::as_bytes)) {
            Ok(()) => {
                self.current = next;
                self.raw = Some(encoded);
                self.pending = true;
                self.retiring = retiring;
                Ok(())
            }
            Err(WriteFailure::BeforeReplace(_)) => Err(()),
            Err(WriteFailure::AfterReplace(_)) => {
                self.pending = true;
                Err(())
            }
        }
    }

    pub(crate) fn pending(&self) -> bool { self.pending }
    pub(crate) fn retiring(&self) -> bool { self.retiring }
    pub(crate) fn committed(&mut self) { self.pending = false; self.retiring = false; }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RealityBinding};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn document(root: Option<u8>) -> ServerDocument {
        let raw = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        let Config::Server(mut doc) = config::parse(&raw).unwrap() else { panic!() };
        doc.server.inbounds[0].reality = root.map(|value| RealityBinding {
            health_store: "health".into(), bundle: "bundle".into(),
            initial_health_sha256: [1; 32], identity_sha256: [value; 32],
            manifest_sha256: [value; 32],
        });
        doc
    }

    #[test]
    fn restart_remove_readd_and_stale_root_are_not_rollbacks() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("theia-root-history-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("server.toml");
        fs::write(&path, b"fixture").unwrap();
        let a = document(Some(1));
        let b = document(Some(2));
        let mut history = RootHistory::open(&path, &a).unwrap();
        history.advance(&a).unwrap();
        assert!(history.pending());
        history.committed();
        assert!(RootHistory::open(&path, &a).is_err());
        let mut removed = a.clone();
        removed.server.inbounds.clear();
        history.advance(&removed).unwrap();
        assert!(!history.pending());
        history.advance(&b).unwrap();
        assert!(history.pending());
        // Simulate process loss BEFORE the memory commit.
        drop(history);
        assert!(RootHistory::open(&path, &a).is_err());
        let mut recovered = RootHistory::open(&path, &b).unwrap();
        recovered.advance(&b).unwrap();
        assert!(!recovered.pending());
        assert!(recovered.check(&a).is_err());
        assert!(RootHistory::preview(&path, &b, &a).is_err());
        assert!(RootHistory::preview(&path, &b, &b).is_ok());
        assert!(RootHistory::preview(&path, &a, &b).is_err());
        let plain = document(None);
        recovered.advance(&plain).unwrap();
        recovered.committed();
        drop(recovered);
        assert!(RootHistory::open(&path, &b).is_err());
        let mut recovered = RootHistory::open(&path, &plain).unwrap();
        let c = document(Some(3));
        recovered.advance(&c).unwrap();
        recovered.committed();
        let raw = fs::read(&recovered.path).unwrap();
        let mut stale = raw.clone();
        stale.push(b'\n');
        fs::write(&recovered.path, &stale).unwrap();
        assert!(recovered.advance(&c).is_err());
        assert!(!recovered.pending());
        drop(recovered);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn history_rejects_duplicate_roots_and_capacity() {
        let a = document(Some(1));
        let first = History::default().next(&a).unwrap();
        let mut duplicate = a.clone();
        let mut inbound = duplicate.server.inbounds[0].clone();
        inbound.id = "another".into();
        duplicate.server.inbounds.push(inbound);
        assert!(first.next(&duplicate).is_err());
        let mut full = first;
        for n in 0..MAX_ROOTS {
            let mut root = [255; 32];
            root[..8].copy_from_slice(&(n as u64).to_be_bytes());
            full.retired.insert(root);
        }
        assert!(full.validate().is_err());
    }
}
