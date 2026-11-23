//! F-14 client import: local-only invitation input and a private, create-new
//! bearer file. No network, account activation or Windows proxy operations.
//! A caller must perform strict typed TOML validation and guarded commit.
use crate::invite::{Invitation, InviteError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_URI: u64 = 4096;
const RANDOM_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    InvalidSource,
    UnsafeStorage,
    InvalidCredential,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never echo input, source paths, token or TOML parse fragments.
        fmt.write_str("Theia invitation import was refused")
    }
}

impl std::error::Error for ImportError {}

/// The TUI accepts an explicit pasted theia://v1 URI or an absolute local
/// text-file path. Never treat a path as a URL or fetch over the network.
/// The original source is not displayed in the preview.
pub fn read_source(raw: &str) -> Result<Invitation, ImportError> {
    if raw.len() > MAX_URI as usize || raw.is_empty() {
        return Err(ImportError::InvalidSource);
    }
    if raw.starts_with("theia://") {
        return Invitation::decode(raw).map_err(|_| ImportError::InvalidSource);
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(ImportError::InvalidSource);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ImportError::InvalidSource)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_URI {
        return Err(ImportError::InvalidSource);
    }
    let mut contents = Zeroizing::new(Vec::new());
    File::open(path)
        .map_err(|_| ImportError::InvalidSource)?
        .take(MAX_URI + 1)
        .read_to_end(&mut contents)
        .map_err(|_| ImportError::InvalidSource)?;
    if contents.len() as u64 > MAX_URI {
        return Err(ImportError::InvalidSource);
    }
    let value = std::str::from_utf8(&contents).map_err(|_| ImportError::InvalidSource)?;
    Invitation::decode(value.trim_end_matches(['\r', '\n']))
        .map_err(|_| ImportError::InvalidSource)
}

pub fn valid_explicit_reference(raw: &str) -> bool {
    raw.starts_with("env:")
        && raw
            .strip_prefix("env:")
            .is_some_and(|name| {
                let bytes = name.as_bytes();
                !bytes.is_empty()
                    && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
                    && bytes[1..]
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
            })
}

/// Untrusted URI cannot add, bypass, replace or select CA anchors. The CA
/// reference comes from an independently typed absolute file path only;
/// verify the cert encoding now and let runtime verify hostname/chain later.
pub fn checked_ca_ref(raw: Option<&str>) -> Result<Option<String>, ImportError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let path = raw.strip_prefix("file:").ok_or(ImportError::InvalidSource)?;
    let path = Path::new(path);
    if !path.is_absolute() || path.components().any(|part| matches!(part, std::path::Component::ParentDir)) {
        return Err(ImportError::InvalidSource);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ImportError::InvalidSource)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err(ImportError::InvalidSource);
    }
    let mut contents = Vec::new();
    File::open(path)
        .map_err(|_| ImportError::InvalidSource)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut contents)
        .map_err(|_| ImportError::InvalidSource)?;
    if contents.len() > 1024 * 1024 {
        return Err(ImportError::InvalidSource);
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(contents.as_slice())) {
        roots
            .add(cert.map_err(|_| ImportError::InvalidSource)?)
            .map_err(|_| ImportError::InvalidSource)?;
    }
    if roots.is_empty() {
        return Err(ImportError::InvalidSource);
    }
    Ok(Some(raw.to_owned()))
}

/// The directory and bearer file are new, owner-only NT/Unix objects.
/// If TOML save fails before the replace commit point, Drop rolls back both.
/// A post-rename fsync error is handled by the caller by inspecting the exact
/// on-disk TOML before deciding whether this file may safely be removed.
pub struct PrivateBearer {
    directory: PathBuf,
    file: PathBuf,
    committed: bool,
}

impl PrivateBearer {
    pub fn create(config_path: &Path, bytes: &[u8; 32]) -> Result<Self, ImportError> {
        let parent = config_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = fs::canonicalize(parent).map_err(|_| ImportError::UnsafeStorage)?;
        if !parent.is_dir() {
            return Err(ImportError::UnsafeStorage);
        }
        let mut random = Zeroizing::new([0u8; RANDOM_BYTES]);
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut random[..])
            .map_err(|_| ImportError::UnsafeStorage)?;
        let mut suffix = String::with_capacity(RANDOM_BYTES * 2);
        for byte in random.iter() {
            use std::fmt::Write as _;
            write!(&mut suffix, "{byte:02x}").map_err(|_| ImportError::UnsafeStorage)?;
        }
        let directory = parent.join(format!(".theia-bearer-{suffix}"));
        new_private_directory(&directory).map_err(|_| ImportError::UnsafeStorage)?;
        let file = directory.join("token");
        let mut guard = Self {
            directory,
            file,
            committed: false,
        };
        let result = (|| -> io::Result<()> {
            let mut writer = new_private_file(&guard.file)?;
            let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes));
            writer.write_all(encoded.as_bytes())?;
            writer.sync_all()?;
            drop(writer);
            #[cfg(unix)]
            File::open(&guard.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            return Err(ImportError::UnsafeStorage);
        }
        Ok(guard)
    }

    pub fn reference(&self) -> Result<String, ImportError> {
        let filename = self.file.to_str().ok_or(ImportError::UnsafeStorage)?;
        Ok(format!("file:{filename}"))
    }

    pub fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PrivateBearer {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.file);
            let _ = fs::remove_dir(&self.directory);
        }
    }
}

#[cfg(unix)]
fn new_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}
#[cfg(unix)]
fn new_private_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

#[cfg(windows)]
mod private_windows {
    use super::*;
    use std::{ffi::c_void, mem::size_of, os::windows::{ffi::OsStrExt, io::FromRawHandle}, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::{LocalFree, INVALID_HANDLE_VALUE},
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{CreateDirectoryW, CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL},
    };

    struct Descriptor(*mut c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: returned by Windows ConvertStringSecurityDescriptor...
            unsafe { LocalFree(self.0) };
        }
    }
    fn security_descriptor() -> io::Result<Descriptor> {
        let sid = crate::windows_control::current_user_sid()
            .map_err(|_| io::Error::other("private user SID unavailable"))?;
        let sddl = format!("D:P(A;;FA;;;{sid})(A;;FA;;;SY)");
        let wide = sddl.encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>();
        let mut ptr = null_mut();
        // SAFETY: NUL-terminated SDDL, out-pointer valid and LocalAlloc owned.
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), 1, &mut ptr, null_mut()) } == 0 || ptr.is_null() {
            return Err(io::Error::other("cannot create protected DACL"));
        }
        Ok(Descriptor(ptr))
    }
    fn attrs(descriptor: &Descriptor) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        }
    }
    fn path_wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }
    pub(super) fn directory(path: &Path) -> io::Result<()> {
        let descriptor = security_descriptor()?;
        let attrs = attrs(&descriptor);
        // SAFETY: protected DACL and absolute NUL-terminated path live during syscall.
        if unsafe { CreateDirectoryW(path_wide(path).as_ptr(), &attrs) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub(super) fn file(path: &Path) -> io::Result<File> {
        let descriptor = security_descriptor()?;
        let attrs = attrs(&descriptor);
        // SAFETY: CREATE_NEW refuses existing targets, including symlink/reparse
        // objects. Security attributes are explicit and protected, not inherited.
        let handle = unsafe {
            CreateFileW(path_wide(path).as_ptr(), 0x4000_0000, 0, &attrs, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, null_mut())
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: owns a valid, freshly created Win32 file handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }
}

#[cfg(windows)]
fn new_private_directory(path: &Path) -> io::Result<()> { private_windows::directory(path) }
#[cfg(windows)]
fn new_private_file(path: &Path) -> io::Result<File> { private_windows::file(path) }

#[cfg(not(any(unix, windows)))]
fn new_private_directory(_: &Path) -> io::Result<()> { Err(io::Error::other("unsupported platform")) }
#[cfg(not(any(unix, windows)))]
fn new_private_file(_: &Path) -> io::Result<File> { Err(io::Error::other("unsupported platform")) }

pub fn read_token_ref(reference: &str) -> Result<Zeroizing<String>, ImportError> {
    let path = reference.strip_prefix("file:").ok_or(ImportError::InvalidCredential)?;
    let bytes = fs::read(path).map_err(|_| ImportError::InvalidCredential)?;
    if bytes.len() != 43 {
        return Err(ImportError::InvalidCredential);
    }
    let value = String::from_utf8(bytes).map_err(|_| ImportError::InvalidCredential)?;
    Ok(Zeroizing::new(value))
}

pub fn _type_contract(_: Result<Invitation, InviteError>) {}
