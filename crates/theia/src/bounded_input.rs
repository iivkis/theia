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
    #[cfg(windows)]
    if private && !private_windows::check(&file) {
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

#[cfg(all(test, windows))]
pub(crate) fn write_test_private(path: &Path, data: impl AsRef<[u8]>) {
    use std::io::Write;
    let mut file = crate::client_import::new_private_file(path).unwrap();
    file.write_all(data.as_ref()).unwrap();
}

// Inspect the opened handle, not the path: path-based ACL checks could
// otherwise validate a different object from the bytes about to be read.
// The accepted policy is deliberately narrow: protected DACL, only current
// process user and LocalSystem, with no inherited or object-specific ACEs.
// Administrators with privilege to bypass ACLs are outside this threat model.
#[cfg(windows)]
mod private_windows {
    use std::{ffi::c_void, fs::File, os::windows::io::AsRawHandle, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT},
            EqualSid, GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACL,
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        },
    };

    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by a Win32 LocalAlloc-returning API.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn sid(text: &str) -> Option<Local> {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let mut raw = null_mut();
        // SAFETY: NUL-terminated SID string and writable out pointer.
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw) } == 0 || raw.is_null() {
            return None;
        }
        Some(Local(raw))
    }

    pub(super) fn check(file: &File) -> bool {
        let Ok(current) = crate::windows_control::current_user_sid() else {
            return false;
        };
        let Some(user) = sid(&current) else {
            return false;
        };
        let Some(system) = sid("S-1-5-18") else {
            return false;
        };
        let mut owner = null_mut();
        let mut acl: *mut ACL = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: file handle is borrowed for the duration of this call;
        // output pointers point to live stack variables.
        let result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        };
        let descriptor = Local(descriptor);
        if result != 0 || descriptor.0.is_null() || acl.is_null() || owner.is_null() {
            return false;
        }
        // SAFETY: successful GetSecurityInfo populated pointers into descriptor.
        if unsafe { EqualSid(owner, user.0) == 0 && EqualSid(owner, system.0) == 0 } {
            return false;
        }
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: descriptor and output variables are live.
        if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return false;
        }
        // SAFETY: ACL points into the live kernel-validated descriptor.
        let count = unsafe { (*acl).AceCount };
        if count != 2 && !(count == 1 && current == "S-1-5-18") {
            return false;
        }
        let mut seen_user = false;
        let mut seen_system = false;
        for index in 0..u32::from(count) {
            let mut raw = null_mut();
            // SAFETY: index is within the ACL's ACE count.
            if unsafe { GetAce(acl, index, &mut raw) } == 0 || raw.is_null() {
                return false;
            }
            let ace = raw.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: all ACEs begin with ACE_HEADER. Check the type before
            // accessing the ACCESS_ALLOWED_ACE-specific SID field.
            let header = unsafe { (*ace).Header };
            if header.AceType != 0 || header.AceFlags != 0 {
                return false;
            }
            // SAFETY: kernel-validated ACCESS_ALLOWED_ACE in live descriptor.
            let actual = unsafe { std::ptr::addr_of_mut!((*ace).SidStart).cast::<c_void>() };
            let is_user = unsafe { EqualSid(actual, user.0) } != 0;
            let is_system = unsafe { EqualSid(actual, system.0) } != 0;
            if !is_user && !is_system {
                return false;
            }
            seen_user |= is_user;
            seen_system |= is_system;
        }
        seen_user && seen_system
    }
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

    #[cfg(windows)]
    #[test]
    fn private_windows_file_is_checked_on_open_handle() {
        use std::io::Write;
        let dir = Scratch::new();
        let path = dir.0.join("protected");
        let mut file = crate::client_import::new_private_file(&path).unwrap();
        file.write_all(b"abcd").unwrap();
        drop(file);
        assert_eq!(read(&path, 4, true, true).unwrap().as_slice(), b"abcd");
        let broad = dir.0.join("broad");
        crate::client_import::test_broad_file(&broad).unwrap();
        assert!(read(&broad, 4, true, false).is_ok());
        assert!(read(&broad, 4, true, true).is_err());
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
