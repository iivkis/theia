//! Shared bounded input for configuration, certificates and credentials.
//! Never log paths, input bytes or operating-system errors.
use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

// Reject ambiguous path forms before touching the filesystem. A drive
// letter is not proof that a volume is physically local (mapped drives
// and mounted filesystems are outside this lexical check).
pub(crate) fn explicit_file_path(path: &Path) -> bool {
    use std::path::Component;

    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return false;
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        let mut parts = path.components();
        if !matches!(
            parts.next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        ) {
            return false;
        }
        // Alternate data streams and device syntax are not invitation files.
        if parts.any(|part| match part {
            Component::Normal(name) => name.to_string_lossy().contains(':'),
            _ => false,
        }) {
            return false;
        }
    }
    true
}

pub(crate) fn regular_file(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return false;
        }
    }
    metadata.is_file()
}

pub(crate) fn no_follow(options: &mut OpenOptions) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = options;
}

fn acceptable(metadata: &fs::Metadata, limit: u64, private: bool) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && metadata.permissions().mode() & 0o077 != 0 {
            return false;
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    regular_file(metadata) && metadata.len() <= limit
}

/// Relative paths remain available to explicit config CLI callers only.
/// Validate both the path and opened handle; use bounded reads even if the
/// file grows after metadata inspection. Trusted parent paths are required.
pub(crate) fn read(
    path: &Path,
    limit: u64,
    absolute: bool,
    private: bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "unsafe or oversized input");
    if absolute && !explicit_file_path(path) {
        return Err(invalid());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !acceptable(&metadata, limit, private) {
        return Err(invalid());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    no_follow(&mut options);
    let file = options.open(path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !acceptable(&metadata, limit, private) {
        return Err(invalid());
    }
    let mut contents = Zeroizing::new(Vec::new());
    file.take(limit.checked_add(1).ok_or_else(invalid)?)
        .read_to_end(&mut contents)
        .map_err(|_| invalid())?;
    if contents.len() as u64 > limit {
        return Err(invalid());
    }
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "theia-bounded-input-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn exact_limit_regular_file_and_missing_or_directory_refusal() {
        let dir = Scratch::new();
        let path = dir.0.join("input");
        fs::write(&path, b"abcd").unwrap();
        assert_eq!(read(&path, 4, true, false).unwrap().as_slice(), b"abcd");
        assert!(read(&path, 3, true, false).is_err());
        assert!(read(&dir.0, 4, true, false).is_err());
        assert!(read(&dir.0.join("missing"), 4, true, false).is_err());
        assert!(read(Path::new("relative"), 4, true, false).is_err());
        assert!(!explicit_file_path(&dir.0.join("sub/../input")));
    }

    #[cfg(unix)]
    #[test]
    fn private_permission_requirement_applies_to_the_opened_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = Scratch::new();
        let path = dir.0.join("secret");
        fs::write(&path, b"abcd").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read(&path, 4, true, true).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&path, 4, true, true).is_err());
        assert!(read(&path, 4, true, false).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn symlink_refused_even_for_nonprivate_input() {
        use std::os::unix::fs::symlink;

        let dir = Scratch::new();
        let target = dir.0.join("target");
        let link = dir.0.join("link");
        fs::write(&target, b"abcd").unwrap();
        symlink(&target, &link).unwrap();
        assert!(read(&link, 4, true, false).is_err());
        assert!(read(&link, 4, false, false).is_err());
    }
}
