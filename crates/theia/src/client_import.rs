//! F-14 client import: local-only invitation input and a private, create-new
//! bearer file. No network, account activation or Windows proxy operations.
//! A caller must perform strict typed TOML validation and guarded commit.
use crate::invite::Invitation;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_URI: u64 = 4096;
const MAX_CA: u64 = 1024 * 1024;
const RANDOM_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    InvalidSource,
    UnsafeStorage,
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
    let contents = read_local_file(Path::new(raw), MAX_URI)?;
    let value = std::str::from_utf8(&contents).map_err(|_| ImportError::InvalidSource)?;
    Invitation::decode(value.trim_end_matches(['\r', '\n'])).map_err(|_| ImportError::InvalidSource)
}

fn read_local_file(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    crate::bounded_input::read(path, limit, true, false).map_err(|_| ImportError::InvalidSource)
}

pub fn valid_explicit_reference(raw: &str) -> bool {
    raw.starts_with("env:")
        && raw.strip_prefix("env:").is_some_and(|name| {
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
    let path = raw
        .strip_prefix("file:")
        .ok_or(ImportError::InvalidSource)?;
    let contents = read_local_file(Path::new(path), MAX_CA)?;
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
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes));
        Self::create_payload(config_path, "bearer", "token", encoded.as_bytes())
    }

    pub(crate) fn create_payload(
        config_path: &Path,
        kind: &str,
        filename: &str,
        payload: &[u8],
    ) -> Result<Self, ImportError> {
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
        let directory = parent.join(format!(".theia-{kind}-{suffix}"));
        new_private_directory(&directory).map_err(|_| ImportError::UnsafeStorage)?;
        let file = directory.join(filename);
        let guard = Self {
            directory,
            file,
            committed: false,
        };
        let result = (|| -> io::Result<()> {
            let mut writer = new_private_file(&guard.file)?;
            writer.write_all(payload)?;
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

/// Confidential export is called only after a separate user confirmation.
/// A fresh protected directory and create-new file avoid overwrite. The
/// caller owns the returned credential file and is responsible for transfer.
pub(crate) fn export_invitation_file(
    config_path: &Path,
    invite: &Invitation,
) -> Result<PathBuf, ImportError> {
    if !invite.has_token() {
        return Err(ImportError::InvalidSource);
    }
    let encoded = Zeroizing::new(invite.encode().map_err(|_| ImportError::InvalidSource)?);
    let mut output = PrivateBearer::create_payload(
        config_path,
        "export",
        "invitation.theia",
        encoded.as_bytes(),
    )?;
    let path = output.file.clone();
    output.commit();
    Ok(path)
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
pub(crate) fn new_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}
/// Create a fresh private file at an explicit absolute path. The caller must
/// supply a trusted parent directory. Existing files are never overwritten.
/// Uses mode 0600 on Unix and an explicit protected user/System DACL on Windows.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    if !crate::bounded_input::explicit_file_path(path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid private file path",
        ));
    }
    new_private_file(path)
}

#[cfg(unix)]
fn new_private_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(windows)]
mod private_windows {
    use super::*;
    use std::{
        ffi::c_void,
        mem::size_of,
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        ptr::null_mut,
    };
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
        let sddl = format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)");
        descriptor_from_sddl(&sddl)
    }
    fn descriptor_from_sddl(sddl: &str) -> io::Result<Descriptor> {
        let wide = sddl
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut ptr = null_mut();
        // SAFETY: NUL-terminated SDDL, out-pointer valid and LocalAlloc owned.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut ptr,
                null_mut(),
            )
        } == 0
            || ptr.is_null()
        {
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
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
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
        file_with_descriptor(path, security_descriptor()?)
    }
    #[cfg(test)]
    pub(super) fn broad_file(path: &Path) -> io::Result<File> {
        let sid = crate::windows_control::current_user_sid()
            .map_err(|_| io::Error::other("private user SID unavailable"))?;
        file_with_descriptor(
            path,
            descriptor_from_sddl(&format!(
                "O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FR;;;WD)"
            ))?,
        )
    }
    fn file_with_descriptor(path: &Path, descriptor: Descriptor) -> io::Result<File> {
        let attrs = attrs(&descriptor);
        // SAFETY: CREATE_NEW refuses existing targets, including symlink/reparse
        // objects. Security attributes are explicit and protected, not inherited.
        let handle = unsafe {
            CreateFileW(
                path_wide(path).as_ptr(),
                0x4000_0000,
                0,
                &attrs,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: owns a valid, freshly created Win32 file handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }
}

#[cfg(all(test, windows))]
pub(crate) fn test_broad_file(path: &Path) -> io::Result<File> {
    private_windows::broad_file(path)
}

#[cfg(windows)]
pub(crate) fn new_private_directory(path: &Path) -> io::Result<()> {
    private_windows::directory(path)
}
#[cfg(windows)]
pub(crate) fn new_private_file(path: &Path) -> io::Result<File> {
    private_windows::file(path)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn new_private_directory(_: &Path) -> io::Result<()> {
    Err(io::Error::other("unsupported platform"))
}
#[cfg(not(any(unix, windows)))]
fn new_private_file(_: &Path) -> io::Result<File> {
    Err(io::Error::other("unsupported platform"))
}

#[cfg(all(test, windows))]
mod windows_acl_tests {
    use super::*;
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
            EqualSid, GetAce, ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION,
        },
    };

    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: Win32 LocalAlloc allocation owned by this wrapper.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn sid(raw: &str) -> Local {
        let wide = raw
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut sid: *mut c_void = null_mut();
        // SAFETY: NUL-terminated Windows SID string and out pointer.
        assert_ne!(
            unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) },
            0
        );
        assert!(!sid.is_null());
        Local(sid)
    }

    pub(super) fn assert_exact_private_dacl(path: &Path) {
        let mut wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut acl: *mut ACL = null_mut();
        let mut descriptor: *mut c_void = null_mut();
        // SAFETY: path points to a live owned object; output pointers valid.
        assert_eq!(
            unsafe {
                GetNamedSecurityInfoW(
                    wide.as_mut_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    &mut acl,
                    null_mut(),
                    &mut descriptor,
                )
            },
            0
        );
        assert!(!acl.is_null(), "NULL DACL would allow everyone access");
        let _descriptor = Local(descriptor);
        let user = sid(&crate::windows_control::current_user_sid().unwrap());
        let system = sid("S-1-5-18");
        // SAFETY: ACL comes from a live kernel security descriptor.
        let count = unsafe { (*acl).AceCount };
        assert_eq!(count, 2, "only owner and LocalSystem may access token");
        let mut seen_user = false;
        let mut seen_system = false;
        for index in 0..u32::from(count) {
            let mut ace: *mut c_void = null_mut();
            // SAFETY: index below the exact ACE count.
            assert_ne!(unsafe { GetAce(acl, index, &mut ace) }, 0);
            assert!(!ace.is_null());
            let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: GetAce returned an ACCESS_ALLOWED_ACE pointer.
            let header = unsafe { (*ace).Header };
            assert_eq!(header.AceType, 0u8);
            assert_eq!(header.AceFlags, 0u8, "must not inherit broad ACEs");
            let actual = unsafe { std::ptr::addr_of_mut!((*ace).SidStart).cast::<c_void>() };
            // SAFETY: both SID allocations and security descriptor are live.
            if unsafe { EqualSid(actual, user.0) } != 0 {
                assert!(!seen_user);
                seen_user = true;
            } else if unsafe { EqualSid(actual, system.0) } != 0 {
                assert!(!seen_system);
                seen_system = true;
            } else {
                panic!("unexpected Windows principal in bearer ACL");
            }
        }
        assert!(seen_user && seen_system);
    }

    #[test]
    fn imported_bearer_file_and_directory_have_only_user_and_system_acl() {
        let parent = std::env::temp_dir().join(format!("theia-import-acl-{}", std::process::id()));
        fs::create_dir(&parent).unwrap();
        let credential = PrivateBearer::create(&parent.join("client.toml"), &[0x42; 32])
            .expect("must create protected directory and token file");
        assert_exact_private_dacl(&credential.directory);
        assert_exact_private_dacl(&credential.file);
        drop(credential);
        fs::remove_dir(&parent).unwrap();
    }
}

#[cfg(all(test, any(unix, windows)))]
mod storage_tests {
    use super::*;
    use crate::bounded_input::explicit_file_path;
    use sha2::Digest;
    use std::{process::Command, sync::Barrier, thread};

    const CHILD_PARENT: &str = "THEIA_TEST_PRIVATE_BEARER_CHILD_PARENT";
    const CHILD_EXIT: i32 = 73;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let mut random = [0u8; 16];
            rustls::crypto::ring::default_provider()
                .secure_random
                .fill(&mut random)
                .unwrap();
            let name = format!("theia-storage-test-{}", URL_SAFE_NO_PAD.encode(random));
            let path = std::env::temp_dir().join(name);
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn assert_private(path: &Path, directory: bool) {
        assert_eq!(fs::metadata(path).unwrap().is_dir(), directory);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, if directory { 0o700 } else { 0o600 });
        }
        #[cfg(windows)]
        super::windows_acl_tests::assert_exact_private_dacl(path);
    }

    fn fixture_invite() -> String {
        let source = include_str!("../../../examples/client.toml");
        let document = crate::config::parse(source).unwrap();
        let crate::config::Config::Client(document) = document else {
            panic!("client");
        };
        Invitation::public_from_profile(&document.client.profiles[0])
            .unwrap()
            .encode()
            .unwrap()
    }

    #[test]
    fn explicit_local_import_and_ca_have_bounded_regular_file_contract() {
        let scratch = Scratch::new();
        let uri = fixture_invite();
        let path = scratch.0.join("invite.txt");
        fs::write(&path, format!("{uri}\r\n")).unwrap();
        assert!(!read_source(path.to_str().unwrap()).unwrap().has_token());
        assert!(!read_source(&uri).unwrap().has_token());
        let ca = scratch.0.join("ca.pem");
        let names = vec!["edge.example.org".to_owned()];
        let cert = rcgen::generate_simple_self_signed(names).unwrap();
        fs::write(&ca, cert.cert.pem()).unwrap();
        let ca_ref = format!("file:{}", ca.display());
        let selected = checked_ca_ref(Some(&ca_ref)).unwrap();
        assert_eq!(selected, Some(ca_ref.clone()));
        for bytes in [
            vec![0xff, 0xfe],
            vec![b'x'; MAX_URI as usize + 1],
            b"not an invitation".to_vec(),
        ] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(
                read_source(path.to_str().unwrap()).unwrap_err(),
                ImportError::InvalidSource
            );
        }
        for bytes in [
            Vec::new(),
            b"not a certificate".to_vec(),
            vec![b'x'; MAX_CA as usize + 1],
        ] {
            fs::write(&ca, bytes).unwrap();
            let result = checked_ca_ref(Some(&ca_ref));
            assert_eq!(result, Err(ImportError::InvalidSource));
        }
        assert!(read_source(scratch.0.to_str().unwrap()).is_err());
        assert!(read_source("relative.txt").is_err());
        assert!(read_source("https://example.invalid/invite").is_err());
        let parent_path = scratch.0.join("sub/../invite.txt");
        assert!(!explicit_file_path(&parent_path));
        assert!(read_source(parent_path.to_str().unwrap()).is_err());
    }

    #[test]
    fn bounded_reader_checks_exact_boundary() {
        let scratch = Scratch::new();
        let path = scratch.0.join("data");
        fs::write(&path, b"abcd").unwrap();
        let contents = read_local_file(&path, 4).unwrap();
        assert_eq!(contents.as_slice(), b"abcd");
        assert!(read_local_file(&path, 3).is_err());
        assert!(read_local_file(&scratch.0.join("missing"), 4).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_import_rejects_final_symlinks_for_both_input_types() {
        use std::os::unix::fs::symlink;

        let scratch = Scratch::new();
        let invite = scratch.0.join("invite.txt");
        fs::write(&invite, fixture_invite()).unwrap();
        let link = scratch.0.join("link.txt");
        symlink(&invite, &link).unwrap();
        assert!(read_source(link.to_str().unwrap()).is_err());
        let ca = scratch.0.join("ca.pem");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(&ca, cert.cert.pem()).unwrap();
        let ca_link = scratch.0.join("ca-link.pem");
        symlink(&ca, &ca_link).unwrap();
        let reference = format!("file:{}", ca_link.display());
        assert!(checked_ca_ref(Some(&reference)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_remote_device_and_alternate_stream_paths_are_rejected_lexically() {
        for raw in [
            r"\\server\share\invite.txt",
            r"\\?\UNC\server\share\invite.txt",
            r"\\.\PhysicalDrive0",
            r"C:\data\invite.txt:stream",
            r"C:\data\..\invite.txt",
            r"C:invite.txt",
        ] {
            assert!(!explicit_file_path(Path::new(raw)));
        }
        assert!(explicit_file_path(Path::new(r"C:\data\invite.txt")));
        assert!(explicit_file_path(Path::new(r"\\?\C:\data\invite.txt")));
    }

    #[test]
    fn confidential_export_uses_private_distinct_create_new_files() {
        let scratch = Scratch::new();
        let path = scratch.0.join("server.toml");
        let source = include_str!("../../../examples/server.toml").replace(
            "REPLACE_WITH_64_LOWERCASE_HEX",
            &format!("{:x}", sha2::Sha256::digest([0x42; 32])),
        );
        let server = crate::config::parse(&source).unwrap();
        let public = Invitation::public_from_server(&server, "public").unwrap();
        assert!(export_invitation_file(&path, &public).is_err());
        let invite =
            Invitation::issued_from_server(&server, "public", "device-a", &[0x42; 32]).unwrap();
        let first = export_invitation_file(&path, &invite).unwrap();
        let second = export_invitation_file(&path, &invite).unwrap();
        assert_ne!(first, second);
        for file in [&first, &second] {
            assert_private(file, false);
            assert_private(file.parent().unwrap(), true);
            let decoded = read_source(file.to_str().unwrap()).unwrap();
            assert_eq!(decoded.token_bytes(), Some([0x42; 32]));
        }
    }

    #[test]
    fn private_creation_collisions_preserve_existing_data() {
        let scratch = Scratch::new();
        let directory = scratch.0.join("private");
        new_private_directory(&directory).unwrap();
        assert!(new_private_directory(&directory).is_err());
        assert_private(&directory, true);

        let path = directory.join("credential");
        let mut file = new_private_file(&path).unwrap();
        file.write_all(b"original fixture").unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(new_private_file(&path).is_err());
        assert_eq!(fs::read(&path).unwrap().as_slice(), b"original fixture");
        assert_private(&path, false);
    }

    #[test]
    fn concurrent_create_new_has_one_winner_and_no_overwrite() {
        let scratch = Scratch::new();
        let path = scratch.0.join("credential");
        let barrier = Barrier::new(2);
        let results = thread::scope(|scope| {
            let workers = (*b"AB").map(|byte| {
                let barrier = &barrier;
                let path = &path;
                scope.spawn(move || {
                    barrier.wait();
                    let Ok(mut file) = new_private_file(path) else {
                        return None;
                    };
                    file.write_all(&[byte]).unwrap();
                    file.sync_all().unwrap();
                    Some(byte)
                })
            });
            workers.map(|worker| worker.join().unwrap())
        });
        let winners: Vec<_> = results.into_iter().flatten().collect();
        assert_eq!(winners.len(), 1);
        assert_eq!(fs::read(&path).unwrap(), winners);
        assert_private(&path, false);
    }

    #[test]
    fn credential_guard_rolls_back_only_its_own_uncommitted_files() {
        let scratch = Scratch::new();
        let config = scratch.0.join("client.toml");
        let mut kept = PrivateBearer::create(&config, &[0x11; 32]).unwrap();
        let discarded = PrivateBearer::create(&config, &[0x22; 32]).unwrap();
        let kept_path = kept.file.clone();
        let discarded_path = discarded.file.clone();
        assert_ne!(kept_path, discarded_path);
        assert_private(&kept.directory, true);
        assert_private(&kept_path, false);
        assert_private(&discarded.directory, true);
        assert_private(&discarded_path, false);

        kept.commit();
        drop(kept);
        drop(discarded);
        assert!(!discarded_path.exists());
        assert!(!discarded_path.parent().unwrap().exists());
        assert_eq!(
            fs::read_to_string(&kept_path).unwrap(),
            URL_SAFE_NO_PAD.encode([0x11; 32])
        );
        assert!(!config.exists());
    }

    // This exact test is invoked by the parent in a fresh process. Exit
    // bypasses Rust Drop; ordinary test runs do not enter the fixture.
    #[test]
    fn child_exits_before_bearer_commit() {
        let Some(parent) = std::env::var_os(CHILD_PARENT) else {
            return;
        };
        let path = PathBuf::from(parent).join("client.toml");
        let _pending = PrivateBearer::create(&path, &[0x33; 32]).unwrap();
        std::process::exit(CHILD_EXIT);
    }

    #[test]
    fn process_exit_before_commit_leaves_only_private_unreferenced_bearer() {
        let scratch = Scratch::new();
        let config = scratch.0.join("client.toml");
        let baseline = include_str!("../../../examples/client.toml");
        fs::write(&config, baseline).unwrap();

        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "client_import::storage_tests::child_exits_before_bearer_commit",
            ])
            .env(CHILD_PARENT, &scratch.0)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(CHILD_EXIT));
        assert_eq!(fs::read_to_string(&config).unwrap(), baseline);

        let directories: Vec<_> = fs::read_dir(&scratch.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_dir())
            .collect();
        assert_eq!(directories.len(), 1);
        let orphan = directories[0].join("token");
        assert_private(&directories[0], true);
        assert_private(&orphan, false);
        assert_eq!(
            fs::read_to_string(&orphan).unwrap(),
            URL_SAFE_NO_PAD.encode([0x33; 32])
        );

        // A separate creation must not adopt or overwrite the orphan.
        let next = PrivateBearer::create(&config, &[0x44; 32]).unwrap();
        assert_ne!(next.file, orphan);
        drop(next);
        assert!(orphan.exists());
        assert_eq!(fs::read_to_string(&config).unwrap(), baseline);
    }
}
