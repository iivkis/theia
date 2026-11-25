//! Owner-only, create-new material transaction. No cleanup of user-supplied
//! directories or previously registered material. Keep ambiguous publications.
use crate::{config, reality_bootstrap::Error};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub(crate) struct StagedMaterial {
    root: PathBuf,
    config: PathBuf,
    source: Option<[u8; 32]>,
    armed: bool,
}
impl StagedMaterial {
    pub(crate) fn create(root: &Path, config: &Path, source: [u8; 32]) -> Result<Self, Error> {
        Self::create_for(root, config, Some(source))
    }
    pub(crate) fn create_for_new_config(root: &Path, config: &Path) -> Result<Self, Error> {
        Self::create_for(root, config, None)
    }
    fn create_for(root: &Path, config: &Path, source: Option<[u8; 32]>) -> Result<Self, Error> {
        if !crate::bounded_input::explicit_file_path(config)
            || !crate::bounded_input::explicit_file_path(root) || root.parent() != config.parent() {
            return Err(Error::Storage);
        }
        if !Self::unchanged(config, source) {
            return Err(Error::Approval);
        }
        crate::client_import::new_private_directory(root).map_err(|_| Error::Storage)?;
        Ok(Self {
            root: root.to_owned(),
            config: config.to_owned(),
            source,
            armed: true,
        })
    }
    fn unchanged(path: &Path, source: Option<[u8; 32]>) -> bool {
        match source {
            Some(source) => config::editor_bytes(path)
                .is_ok_and(|raw| <[u8; 32]>::from(Sha256::digest(raw)) == source),
            None => matches!(std::fs::symlink_metadata(path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound),
        }
    }
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn preserve(&mut self) {
        self.armed = false;
    }
    pub(crate) fn refuse(&mut self) {
        self.armed = true;
    }
    pub(crate) fn cleanup(&mut self) -> Result<(), Error> {
        if !self.armed {
            return Ok(());
        }
        // Disarm before deletion: an ambiguous or failed cleanup must never
        // be retried against a path that may have been reused.
        self.armed = false;
        let _lock = config::editor_lock(&self.config).map_err(|_| Error::Indeterminate)?;
        if !Self::unchanged(&self.config, self.source) {
            return Err(Error::Indeterminate);
        }
        let meta = std::fs::symlink_metadata(&self.root).map_err(|_| Error::Storage)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(Error::Storage);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(Error::Storage);
            }
        }
        std::fs::remove_dir_all(&self.root).map_err(|_| Error::Storage)
    }
}
impl Drop for StagedMaterial {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_owns_only_created_root_and_preserves_changed_or_committed_material() {
        let dir = std::env::temp_dir().join(crate::tui_editor::generated_id("stage-test").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let config = dir.join("server.toml");
        std::fs::write(&config, include_str!("../../../examples/server.toml")).unwrap();
        let source = Sha256::digest(std::fs::read(&config).unwrap()).into();
        let unrelated = dir.join("unrelated");
        std::fs::create_dir(&unrelated).unwrap();
        assert!(StagedMaterial::create(&unrelated, &config, source).is_err());
        let root = dir.join("new-material");
        let mut guard = StagedMaterial::create(&root, &config, source).unwrap();
        std::fs::write(root.join("partial"), b"data").unwrap();
        guard.cleanup().unwrap();
        assert!(!root.exists() && unrelated.exists());
        let mut guard = StagedMaterial::create(&root, &config, source).unwrap();
        guard.preserve();
        drop(guard);
        assert!(root.exists());
        std::fs::remove_dir(&root).unwrap();
        let mut guard = StagedMaterial::create(&root, &config, source).unwrap();
        std::fs::write(&config, b"changed").unwrap();
        assert_eq!(guard.cleanup(), Err(Error::Indeterminate));
        assert!(root.exists());
        std::fs::write(&config, include_str!("../../../examples/server.toml")).unwrap();
        std::fs::remove_dir(&root).unwrap();
        let mut guard = StagedMaterial::create(&root, &config, source).unwrap();
        let lock = config::editor_lock(&config).unwrap();
        assert_eq!(guard.cleanup(), Err(Error::Indeterminate));
        drop(lock);
        assert!(root.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
