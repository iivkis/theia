//! M4.3 / F-07: explicit per-user WinINet proxy ownership with a durable
//! fail-closed recovery journal. Never used by the headless server.
//!
//! A named user-SID mutex is held for the *entire* client proxy lifetime.
//! A crashed owner leaves a journal but releases the OS mutex. Recovery only
//! restores if all current WinINet fields still equal our exact applied state.
//! No force flag exists. External edits, group policy and ambiguous WinINet
//! results are never silently overwritten.
#![cfg(windows)]

use crate::windows_control::current_user_sid;
use serde::{Deserialize, Serialize};
use std::{
    ffi::c_void,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, LocalFree, ERROR_FILE_NOT_FOUND, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
    },
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
            GetSecurityInfo, SE_KERNEL_OBJECT, SE_REGISTRY_KEY,
        },
        EqualSid, GetAce, ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
    },
    System::{
        Registry::{
            RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegFlushKey, RegOpenKeyExW,
            RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
            KEY_ALL_ACCESS, KEY_QUERY_VALUE, KEY_READ, REG_BINARY, REG_DWORD,
        },
        Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
    },
};

const JOURNAL_KEY: &str = "Software\\Theia\\WinInetProxyRecoveryV1";
const JOURNAL_NAME: &str = "OwnerTransactionV1";
const SCOPE_POLICY_KEY: &str =
    "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
const SCOPE_POLICY_VALUE: &str = "ProxySettingsPerUser";
const MAX_JOURNAL: usize = 12 * 1024;
const MAX_TEXT: usize = 2048;
const INTERNET_OPTION_PER_CONNECTION_OPTION: u32 = 75;
const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
const INTERNET_OPTION_REFRESH: u32 = 37;
const INTERNET_PER_CONN_FLAGS: u32 = 1;
const INTERNET_PER_CONN_PROXY_SERVER: u32 = 2;
const INTERNET_PER_CONN_PROXY_BYPASS: u32 = 3;
const INTERNET_PER_CONN_AUTOCONFIG_URL: u32 = 4;
const INTERNET_PER_CONN_FLAGS_UI: u32 = 10;
const PROXY_TYPE_DIRECT: u32 = 1;
const PROXY_TYPE_PROXY: u32 = 2;
const VALID_PROXY_FLAGS: u32 = 0x0f;

#[link(name = "wininet")]
unsafe extern "system" {
    fn InternetQueryOptionW(
        handle: *mut c_void,
        option: u32,
        buffer: *mut c_void,
        length: *mut u32,
    ) -> i32;
    fn InternetSetOptionW(
        handle: *mut c_void,
        option: u32,
        buffer: *mut c_void,
        length: u32,
    ) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    Unavailable,
    Busy,
    RecoveryRequired,
    Conflict,
    InvalidSettings,
    PolicyManaged,
    Journal,
}
impl std::fmt::Display for ProxyError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No proxy URLs, SIDs, PAC credentials, registry data or paths.
        fmt.write_str(match self {
            Self::Unavailable => "Windows user proxy API unavailable",
            Self::Busy => "another Theia client owns system proxy management",
            Self::RecoveryRequired => "previous Theia proxy journal requires explicit recovery",
            Self::Conflict => "Windows user proxy changed; refusing to overwrite another owner",
            Self::InvalidSettings => "Windows proxy configuration could not be safely managed",
            Self::PolicyManaged => "Windows proxy scope not confirmed per-user; write refused",
            Self::Journal => "cannot safely read or durably update proxy recovery journal",
        })
    }
}
impl std::error::Error for ProxyError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    flags: u32,
    server: String,
    bypass: String,
    auto_url: String,
}
impl Snapshot {
    fn validate(&self) -> Result<(), ProxyError> {
        if self.flags == 0
            || self.flags & !VALID_PROXY_FLAGS != 0
            || [&self.server, &self.bypass, &self.auto_url]
                .iter()
                .any(|s| s.len() > MAX_TEXT || s.contains('\0') || s.contains(['\r', '\n']))
        {
            return Err(ProxyError::InvalidSettings);
        }
        Ok(())
    }

    fn for_loopback(&self, bind: SocketAddr) -> Result<Self, ProxyError> {
        if !matches!(
            bind.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST) | IpAddr::V6(Ipv6Addr::LOCALHOST)
        ) || bind.port() == 0
        {
            return Err(ProxyError::InvalidSettings);
        }
        // WinINet is an HTTP(S) proxy, not SOCKS/TUN, and uses a single
        // loopback HTTP CONNECT port for both HTTP and HTTPS URLs.
        let result = Self {
            flags: PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY,
            server: format!("http={bind};https={bind}"),
            bypass: "<local>;localhost;127.0.0.1;[::1]".into(),
            auto_url: self.auto_url.clone(),
        };
        result.validate()?;
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    user_sid: String,
    before: Snapshot,
    applied: Snapshot,
}
impl Journal {
    fn validate(&self) -> Result<(), ProxyError> {
        if self.version != 1
            || self.user_sid != current_user_sid().map_err(|_| ProxyError::Journal)?
        {
            return Err(ProxyError::Journal);
        }
        self.before.validate()?;
        self.applied.validate()?;
        let bind: SocketAddr = self
            .applied
            .server
            .strip_prefix("http=")
            .and_then(|value| value.split_once(";https="))
            .and_then(|(http, https)| (http == https).then_some(http))
            .and_then(|value| value.parse().ok())
            .ok_or(ProxyError::Journal)?;
        let expected = self
            .before
            .for_loopback(bind)
            .map_err(|_| ProxyError::Journal)?;
        if expected != self.applied || self.before == self.applied {
            return Err(ProxyError::Journal);
        }
        Ok(())
    }
}

#[repr(C)]
union OptionValue {
    number: u32,
    text: *mut u16,
}
#[repr(C)]
struct PerConnectionOption {
    id: u32,
    value: OptionValue,
}
#[repr(C)]
struct PerConnectionList {
    size: u32,
    connection: *mut u16,
    option_count: u32,
    option_error: u32,
    options: *mut PerConnectionOption,
}
fn option(id: u32) -> PerConnectionOption {
    PerConnectionOption {
        id,
        value: OptionValue { text: null_mut() },
    }
}
fn list(options: &mut [PerConnectionOption; 4]) -> PerConnectionList {
    PerConnectionList {
        size: size_of::<PerConnectionList>() as u32,
        connection: null_mut(),
        option_count: 4,
        option_error: 0,
        options: options.as_mut_ptr(),
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
fn read_wide(ptr: *mut u16) -> Result<String, ProxyError> {
    if ptr.is_null() {
        return Ok(String::new());
    }
    // SAFETY: on successful WinINet query, this is an API-owned terminated
    // GlobalAlloc UTF-16 string. A hard scan bound limits decoded content.
    let mut len = 0usize;
    while len <= MAX_TEXT {
        if unsafe { *ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    if len > MAX_TEXT {
        return Err(ProxyError::InvalidSettings);
    }
    // SAFETY: non-null WinINet result remains live until GlobalFree.
    String::from_utf16(unsafe { std::slice::from_raw_parts(ptr, len) })
        .map_err(|_| ProxyError::InvalidSettings)
}
fn query_with_flags(flag_id: u32) -> Result<Snapshot, ProxyError> {
    let mut fields = [
        option(flag_id),
        option(INTERNET_PER_CONN_PROXY_SERVER),
        option(INTERNET_PER_CONN_PROXY_BYPASS),
        option(INTERNET_PER_CONN_AUTOCONFIG_URL),
    ];
    let mut args = list(&mut fields);
    let mut bytes = size_of::<PerConnectionList>() as u32;
    // SAFETY: null handle targets the current user's default LAN settings;
    // options and list are correctly aligned C-compatible objects.
    let result = unsafe {
        InternetQueryOptionW(
            null_mut(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&mut args as *mut PerConnectionList).cast(),
            &mut bytes,
        )
    };
    let observed = if result == 0 || args.option_error != 0 {
        Err(ProxyError::Unavailable)
    } else {
        (|| {
            // SAFETY: union fields are selected by the matching option IDs.
            let flags = unsafe { fields[0].value.number };
            let server = read_wide(unsafe { fields[1].value.text })?;
            let bypass = read_wide(unsafe { fields[2].value.text })?;
            let auto_url = read_wide(unsafe { fields[3].value.text })?;
            let state = Snapshot {
                flags,
                server,
                bypass,
                auto_url,
            };
            state.validate()?;
            Ok(state)
        })()
    };
    // WinINet owns output GlobalAlloc UTF-16 fields even if decode fails.
    // SAFETY: fields 1..=3 are string options, not the numeric FLAGS union.
    for field in &fields[1..] {
        let ptr = unsafe { field.value.text };
        if !ptr.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::GlobalFree(ptr.cast());
            }
        }
    }
    observed
}
fn query() -> Result<Snapshot, ProxyError> {
    require_per_user_scope()?;
    let observed = match query_with_flags(INTERNET_PER_CONN_FLAGS_UI) {
        Err(ProxyError::Unavailable) => query_with_flags(INTERNET_PER_CONN_FLAGS),
        result => result,
    }?;
    require_per_user_scope()?;
    Ok(observed)
}
fn set(state: &Snapshot) -> Result<(), ProxyError> {
    state.validate()?;
    require_per_user_scope()?;
    let mut strings = [
        wide(&state.server),
        wide(&state.bypass),
        wide(&state.auto_url),
    ];
    let mut fields = [
        PerConnectionOption {
            id: INTERNET_PER_CONN_FLAGS,
            value: OptionValue {
                number: state.flags,
            },
        },
        PerConnectionOption {
            id: INTERNET_PER_CONN_PROXY_SERVER,
            value: OptionValue {
                text: strings[0].as_mut_ptr(),
            },
        },
        PerConnectionOption {
            id: INTERNET_PER_CONN_PROXY_BYPASS,
            value: OptionValue {
                text: strings[1].as_mut_ptr(),
            },
        },
        PerConnectionOption {
            id: INTERNET_PER_CONN_AUTOCONFIG_URL,
            value: OptionValue {
                text: strings[2].as_mut_ptr(),
            },
        },
    ];
    let mut args = list(&mut fields);
    // SAFETY: each pointer lives through synchronous InternetSetOptionW.
    if unsafe {
        InternetSetOptionW(
            null_mut(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&mut args as *mut PerConnectionList).cast(),
            size_of::<PerConnectionList>() as u32,
        )
    } == 0
        || args.option_error != 0
    {
        return Err(ProxyError::Unavailable);
    }
    for id in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        // SAFETY: documented process-global WinINet refresh notification.
        if unsafe { InternetSetOptionW(null_mut(), id, null_mut(), 0) } == 0 {
            return Err(ProxyError::Unavailable);
        }
    }
    require_per_user_scope()
}

// The journal is HKCU-wide, so current binaries must serialize across
// terminal sessions as well as within the session used by older binaries.
struct Mutex {
    _legacy: MutexHandle,
    _global: MutexHandle,
}

impl Mutex {
    fn acquire() -> Result<Self, ProxyError> {
        let sid = current_user_sid().map_err(|_| ProxyError::Unavailable)?;
        if sid == "S-1-5-18" {
            return Err(ProxyError::Unavailable);
        }
        let global_name = format!("Global\\Theia-WinInet-Proxy-{sid}");
        let local_name = format!("Local\\Theia-WinInet-Proxy-{sid}");
        let global = MutexHandle::acquire(&global_name, Some(&sid))?;
        let legacy = MutexHandle::acquire(&local_name, None)?;
        Ok(Self {
            _legacy: legacy,
            _global: global,
        })
    }
}

struct MutexHandle(HANDLE);
impl MutexHandle {
    fn acquire(name: &str, protected_sid: Option<&str>) -> Result<Self, ProxyError> {
        let security = protected_sid
            .map(|sid| security_descriptor(&format!("O:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)")))
            .transpose()?;
        let attrs = security.as_ref().map(|security| SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.0,
            bInheritHandle: 0,
        });
        let attributes = attrs.as_ref().map_or(null(), |attrs| attrs as *const _);
        // SAFETY: terminated name and optional live security descriptor.
        let handle = unsafe { CreateMutexW(attributes, 0, wide(name).as_ptr()) };
        if handle.is_null() {
            return Err(ProxyError::Unavailable);
        }
        if protected_sid.is_some() && check_mutex_security(handle).is_err() {
            unsafe { CloseHandle(handle) };
            return Err(ProxyError::Unavailable);
        }
        // SAFETY: valid mutex handle, nonblocking wait.
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
            unsafe { CloseHandle(handle) };
            return Err(ProxyError::Busy);
        }
        Ok(Self(handle))
    }
}
impl Drop for MutexHandle {
    fn drop(&mut self) {
        // SAFETY: this handle was acquired on the current native thread.
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
use std::ptr::null;

struct Security(*mut c_void);
impl Drop for Security {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}
fn private_security() -> Result<Security, ProxyError> {
    let sid = current_user_sid().map_err(|_| ProxyError::Journal)?;
    security_descriptor(&format!("D:P(A;;KA;;;{sid})(A;;KA;;;SY)"))
}

fn security_descriptor(sddl: &str) -> Result<Security, ProxyError> {
    let descriptor = wide(sddl);
    let mut pointer = null_mut();
    // SAFETY: terminated SDDL with protected user and SYSTEM only.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor.as_ptr(),
            1,
            &mut pointer,
            null_mut(),
        )
    } == 0
        || pointer.is_null()
    {
        return Err(ProxyError::Journal);
    }
    Ok(Security(pointer))
}
struct Sid(*mut c_void);
impl Drop for Sid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}
fn parsed_sid(raw: &str) -> Result<Sid, ProxyError> {
    let mut sid = null_mut();
    if unsafe { ConvertStringSidToSidW(wide(raw).as_ptr(), &mut sid) } == 0 || sid.is_null() {
        return Err(ProxyError::Journal);
    }
    Ok(Sid(sid))
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
// Only absent policy or an explicit DWORD 1 permits per-user WinINet.
// Never modify policy and never assume access denied means not configured.
fn require_per_user_scope_at(root: HKEY, path: &str) -> Result<(), ProxyError> {
    let mut key = null_mut();
    let result = unsafe { RegOpenKeyExW(root, wide(path).as_ptr(), 0, KEY_QUERY_VALUE, &mut key) };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    if result != 0 {
        return Err(ProxyError::PolicyManaged);
    }
    let key = Key(key);
    let mut kind = 0;
    let mut bytes = [0u8; 4];
    let mut length = bytes.len() as u32;
    let result = unsafe {
        RegQueryValueExW(
            key.0,
            wide(SCOPE_POLICY_VALUE).as_ptr(),
            null(),
            &mut kind,
            bytes.as_mut_ptr(),
            &mut length,
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    if result != 0 || kind != REG_DWORD || length != 4 || u32::from_le_bytes(bytes) != 1 {
        return Err(ProxyError::PolicyManaged);
    }
    Ok(())
}

fn require_per_user_scope() -> Result<(), ProxyError> {
    require_per_user_scope_at(HKEY_LOCAL_MACHINE, SCOPE_POLICY_KEY)
}

fn check_acl(key: HKEY) -> Result<(), ProxyError> {
    let mut acl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: live registry key handle and owned descriptor output.
    if unsafe {
        GetSecurityInfo(
            key as _,
            SE_REGISTRY_KEY,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    } != 0
        || acl.is_null()
    {
        return Err(ProxyError::Journal);
    }
    let _descriptor = Security(descriptor);
    let user = parsed_sid(&current_user_sid().map_err(|_| ProxyError::Journal)?)?;
    let system = parsed_sid("S-1-5-18")?;
    check_sid_acl(acl, &user, &system)
}

fn check_mutex_security(handle: HANDLE) -> Result<(), ProxyError> {
    let mut acl: *mut ACL = null_mut();
    let mut owner = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: live mutex handle and owned descriptor outputs.
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    let _descriptor = Security(descriptor);
    if result != 0 || acl.is_null() || owner.is_null() {
        return Err(ProxyError::Unavailable);
    }
    let user = parsed_sid(&current_user_sid().map_err(|_| ProxyError::Unavailable)?)?;
    let system = parsed_sid("S-1-5-18")?;
    if unsafe { EqualSid(owner, user.0) } == 0 && unsafe { EqualSid(owner, system.0) } == 0 {
        return Err(ProxyError::Unavailable);
    }
    check_sid_acl(acl, &user, &system).map_err(|_| ProxyError::Unavailable)
}

// SAFETY invariant: callers retain the GetSecurityInfo descriptor and
// supply its non-null ACL for the entire validation.
fn check_sid_acl(acl: *mut ACL, user: &Sid, system: &Sid) -> Result<(), ProxyError> {
    let count = unsafe { (*acl).AceCount };
    if count != 2 {
        return Err(ProxyError::Journal);
    }
    let mut found_user = false;
    let mut found_system = false;
    for i in 0..u32::from(count) {
        let mut raw = null_mut();
        if unsafe { GetAce(acl, i, &mut raw) } == 0 || raw.is_null() {
            return Err(ProxyError::Journal);
        }
        let ace = raw.cast::<ACCESS_ALLOWED_ACE>();
        let header = unsafe { (*ace).Header };
        if header.AceType != 0 || header.AceFlags != 0 {
            return Err(ProxyError::Journal);
        }
        let found = unsafe { std::ptr::addr_of_mut!((*ace).SidStart).cast::<c_void>() };
        if unsafe { EqualSid(found, user.0) } != 0 {
            if found_user {
                return Err(ProxyError::Journal);
            }
            found_user = true;
        } else if unsafe { EqualSid(found, system.0) } != 0 {
            if found_system {
                return Err(ProxyError::Journal);
            }
            found_system = true;
        } else {
            return Err(ProxyError::Journal);
        }
    }
    if !found_user || !found_system {
        return Err(ProxyError::Journal);
    }
    Ok(())
}
fn open_key(create: bool) -> Result<Option<Key>, ProxyError> {
    let mut key = null_mut();
    let path = wide(JOURNAL_KEY);
    if create {
        let security = private_security()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.0,
            bInheritHandle: 0,
        };
        let mut disposition = 0;
        // SAFETY: HKCU scope, protected DACL and live out handles.
        if unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                null_mut(),
                0,
                KEY_ALL_ACCESS,
                &attributes,
                &mut key,
                &mut disposition,
            )
        } != 0
        {
            return Err(ProxyError::Journal);
        }
    } else {
        // SAFETY: open read-only private HKCU recovery journal, never create.
        let result =
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_READ, &mut key) };
        if result == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if result != 0 {
            return Err(ProxyError::Journal);
        }
    }
    let guard = Key(key);
    check_acl(guard.0)?;
    Ok(Some(guard))
}
fn read_journal() -> Result<Option<Journal>, ProxyError> {
    let Some(key) = open_key(false)? else {
        return Ok(None);
    };
    let mut kind = 0;
    let mut length = 0u32;
    let name = wide(JOURNAL_NAME);
    // SAFETY: probe the owned HKCU registry value length with no output buffer.
    let result = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            &mut kind,
            null_mut(),
            &mut length,
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if result != 0 || kind != REG_BINARY || length == 0 || length as usize > MAX_JOURNAL {
        return Err(ProxyError::Journal);
    }
    let mut bytes = vec![0u8; length as usize];
    // SAFETY: bounded destination and live key; registry API writes length bytes.
    if unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            &mut kind,
            bytes.as_mut_ptr(),
            &mut length,
        )
    } != 0
        || kind != REG_BINARY
        || length as usize != bytes.len()
    {
        return Err(ProxyError::Journal);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ProxyError::Journal)?;
    let record: Journal = toml::from_str(text).map_err(|_| ProxyError::Journal)?;
    record.validate()?;
    Ok(Some(record))
}
fn save_journal(value: &Journal) -> Result<(), ProxyError> {
    value.validate()?;
    let encoded = toml::to_string(value).map_err(|_| ProxyError::Journal)?;
    if encoded.len() > MAX_JOURNAL {
        return Err(ProxyError::Journal);
    }
    let key = open_key(true)?.ok_or(ProxyError::Journal)?;
    // Never silently replace a recovery record, even with an identical one.
    if read_journal()?.is_some() {
        return Err(ProxyError::RecoveryRequired);
    }
    let bytes = encoded.as_bytes();
    let name = wide(JOURNAL_NAME);
    // SAFETY: bounded immutable serialized journal and live HKCU key.
    if unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            REG_BINARY,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    } != 0
        || unsafe { RegFlushKey(key.0) } != 0
    {
        return Err(ProxyError::Journal);
    }
    Ok(())
}
fn delete_journal() -> Result<(), ProxyError> {
    let key = open_key(true)?.ok_or(ProxyError::Journal)?;
    // SAFETY: specific bounded registry value, not the parent/user key.
    if unsafe { RegDeleteValueW(key.0, wide(JOURNAL_NAME).as_ptr()) } != 0
        || unsafe { RegFlushKey(key.0) } != 0
    {
        return Err(ProxyError::Journal);
    }
    Ok(())
}

fn recover_locked() -> Result<Recovery, ProxyError> {
    let Some(journal) = read_journal()? else {
        return Ok(Recovery::NothingPending);
    };
    restore_journal(&journal, None)
}

fn require_journal(journal: &Journal) -> Result<(), ProxyError> {
    if read_journal()?.as_ref() != Some(journal) {
        return Err(ProxyError::Conflict);
    }
    Ok(())
}

fn restore_journal(journal: &Journal, expected: Option<&Snapshot>) -> Result<Recovery, ProxyError> {
    require_journal(journal)?;
    let current = query()?;
    if expected.is_some_and(|expected| expected != &current) {
        return Err(ProxyError::Conflict);
    }
    if current == journal.before {
        // Process crashed before WinINet commit or another actor restored the
        // *exact* old state. Clear the stale journal without touching WinINet.
        require_journal(journal)?;
        delete_journal()?;
        return Ok(Recovery::AlreadyRestored);
    }
    if current != journal.applied {
        // Never stomp a new VPN, PAC URL, browser or another local proxy.
        return Err(ProxyError::Conflict);
    }
    require_journal(journal)?;
    if query()? != current {
        return Err(ProxyError::Conflict);
    }
    set(&journal.before)?;
    if query()? != journal.before {
        return Err(ProxyError::Conflict);
    }
    require_journal(journal)?;
    delete_journal()?;
    Ok(Recovery::Restored)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    NothingPending,
    AlreadyRestored,
    Restored,
}
pub fn recover_explicit() -> Result<Recovery, ProxyError> {
    let _lock = Mutex::acquire()?;
    recover_locked()
}

/// Redacted observation for TUI. A matching journal is not proof that this
/// process owns the mutex; only its own live lease can establish ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservedProxy {
    Direct,
    External,
    Journal(ProxyStatus),
}

pub(crate) fn observed_proxy() -> Result<ObservedProxy, ProxyError> {
    let state = status()?;
    if state != ProxyStatus::NoJournal {
        return Ok(ObservedProxy::Journal(state));
    }
    let current = query()?;
    Ok(if current.flags == PROXY_TYPE_DIRECT {
        ObservedProxy::Direct
    } else {
        ObservedProxy::External
    })
}

/// Opaque exact snapshot retained in memory only. Never format its strings.
pub(crate) struct ApplyReview(Snapshot);

impl ApplyReview {
    pub(crate) fn description(&self) -> &'static str {
        if self.0.flags == PROXY_TYPE_DIRECT {
            "Текущие параметры: прямое подключение."
        } else {
            "Текущие параметры: внешний прокси/PAC/автоопределение."
        }
    }
}

pub(crate) fn review_apply(bind: SocketAddr) -> Result<ApplyReview, ProxyError> {
    let _lock = Mutex::acquire()?;
    if read_journal()?.is_some() {
        return Err(ProxyError::RecoveryRequired);
    }
    let before = query()?;
    if before.for_loopback(bind)? == before {
        return Err(ProxyError::InvalidSettings);
    }
    Ok(ApplyReview(before))
}

/// Bind the recovery consent to one exact journal and observed OS state.
pub(crate) struct RecoveryReview {
    journal: Journal,
    current: Snapshot,
}

pub(crate) fn review_recovery() -> Result<RecoveryReview, ProxyError> {
    let _lock = Mutex::acquire()?;
    let journal = read_journal()?.ok_or(ProxyError::RecoveryRequired)?;
    let current = query()?;
    if current != journal.before && current != journal.applied {
        return Err(ProxyError::Conflict);
    }
    Ok(RecoveryReview { journal, current })
}

pub(crate) fn recover_reviewed(review: RecoveryReview) -> Result<Recovery, ProxyError> {
    let _lock = Mutex::acquire()?;
    restore_journal(&review.journal, Some(&review.current))
}

/// The Windows mutex is **thread-owned**, not task-owned. A Tokio task can
/// resume on another OS thread after any await; therefore the mutex, WinINet
/// apply and every CAS restore are pinned to this dedicated native thread.
struct NativeOwner {
    _lock: Mutex,
    journal: Journal,
    active: bool,
}

impl NativeOwner {
    fn apply_locked(lock: Mutex, bind: SocketAddr, review: Option<ApplyReview>) -> Result<Self, ProxyError> {
        if read_journal()?.is_some() {
            return Err(ProxyError::RecoveryRequired);
        }
        let before = query()?;
        if review.is_some_and(|review| review.0 != before) {
            return Err(ProxyError::Conflict);
        }
        let applied = before.for_loopback(bind)?;
        if applied == before {
            return Err(ProxyError::InvalidSettings);
        }
        let journal = Journal {
            version: 1,
            user_sid: current_user_sid().map_err(|_| ProxyError::Journal)?,
            before,
            applied,
        };
        save_journal(&journal)?;
        // Compare-before-write. Other applications do not honor this mutex:
        // a subsequent foreign edit cannot be overwritten during restore.
        require_journal(&journal)?;
        if query()? != journal.before {
            return Err(ProxyError::Conflict);
        }
        // Construct the owner before the first potentially mutating call.
        // On an uncertain apply Drop performs only exact-state CAS; partial
        // or foreign states retain the journal for explicit recovery.
        let owner = Self { _lock: lock, journal, active: true };
        set(&owner.journal.applied)?;
        if query()? != owner.journal.applied {
            return Err(ProxyError::Conflict);
        }
        require_journal(&owner.journal)?;
        Ok(owner)
    }

    fn restore(&mut self) -> Result<Recovery, ProxyError> {
        if !self.active {
            return Ok(Recovery::NothingPending);
        }
        let outcome = restore_journal(&self.journal, None)?;
        self.active = false;
        Ok(outcome)
    }
}

impl Drop for NativeOwner {
    fn drop(&mut self) {
        // Only the same native thread that acquired the Windows mutex
        // can release it. A failed CAS preserves a private recovery journal.
        let _ = self.restore();
    }
}

type RestoreReply = std::sync::mpsc::SyncSender<Result<Recovery, ProxyError>>;
type ApplyRequest = (SocketAddr, Option<ApplyReview>);

/// The SID-scoped owner is reserved before DNS, credential preflight or bind.
/// The native thread retains both mutexes while the async controller prepares.
pub(crate) struct ReservedProxy {
    start: Option<std::sync::mpsc::SyncSender<ApplyRequest>>,
    ready: std::sync::mpsc::Receiver<Result<Journal, ProxyError>>,
    commands: Option<std::sync::mpsc::Sender<RestoreReply>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ReservedProxy {
    pub(crate) fn acquire() -> Result<Self, ProxyError> {
        let (reserved_tx, reserved_rx) = std::sync::mpsc::sync_channel(1);
        let (start_tx, start_rx) = std::sync::mpsc::sync_channel::<ApplyRequest>(1);
        let (ready_tx, ready) = std::sync::mpsc::sync_channel(1);
        let (commands, commands_rx) = std::sync::mpsc::channel::<RestoreReply>();
        let thread = std::thread::Builder::new()
            .name("theia-wininet-owner".into())
            .spawn(move || {
                let reservation = (|| {
                    let lock = Mutex::acquire()?;
                    if read_journal()?.is_some() {
                        return Err(ProxyError::RecoveryRequired);
                    }
                    // Validate per-user scope before any network preflight.
                    query()?;
                    Ok(lock)
                })();
                let lock = match reservation {
                    Ok(lock) => lock,
                    Err(error) => {
                        let _ = reserved_tx.send(Err(error));
                        return;
                    }
                };
                if reserved_tx.send(Ok(())).is_err() { return; }
                let Ok((bind, review)) = start_rx.recv() else { return };
                let mut owner = match NativeOwner::apply_locked(lock, bind, review) {
                    Ok(owner) => owner,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                if ready_tx.send(Ok(owner.journal.clone())).is_err() { return; }
                while let Ok(reply) = commands_rx.recv() {
                    let outcome = owner.restore();
                    let done = outcome.is_ok();
                    let _ = reply.send(outcome);
                    if done { break; }
                }
            })
            .map_err(|_| ProxyError::Unavailable)?;
        match reserved_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                start: Some(start_tx), ready, commands: Some(commands), thread: Some(thread),
            }),
            result => {
                let _ = thread.join();
                Err(match result { Ok(Err(error)) => error, _ => ProxyError::Unavailable })
            }
        }
    }

    pub(crate) fn apply(mut self, bind: SocketAddr, review: Option<ApplyReview>) -> Result<OwnedProxy, ProxyError> {
        self.start.take().ok_or(ProxyError::Unavailable)?
            .send((bind, review)).map_err(|_| ProxyError::Unavailable)?;
        let journal = self.ready.recv().map_err(|_| ProxyError::Unavailable)??;
        Ok(OwnedProxy {
            commands: self.commands.take(),
            thread: self.thread.take(),
            active: true,
            journal,
        })
    }
}

impl Drop for ReservedProxy {
    fn drop(&mut self) {
        self.start.take();
        self.commands.take();
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

pub struct OwnedProxy {
    commands: Option<std::sync::mpsc::Sender<RestoreReply>>,
    thread: Option<std::thread::JoinHandle<()>>,
    active: bool,
    journal: Journal,
}

impl OwnedProxy {
    /// Explicit confirmed transaction for already-prepared callers.
    /// The product controller reserves before preparation.
    pub fn apply(bind: SocketAddr) -> Result<Self, ProxyError> {
        ReservedProxy::acquire()?.apply(bind, None)
    }

    #[cfg(test)]
    pub(crate) fn apply_reviewed(bind: SocketAddr, review: ApplyReview) -> Result<Self, ProxyError> {
        ReservedProxy::acquire()?.apply(bind, Some(review))
    }

    /// A matching current snapshot alone does not establish journal ownership.
    pub(crate) fn verify(&self) -> Result<(), ProxyError> {
        if !self.active || self.thread.as_ref().is_none_or(|thread| thread.is_finished()) {
            return Err(ProxyError::Unavailable);
        }
        require_journal(&self.journal)?;
        if query()? != self.journal.applied { return Err(ProxyError::Conflict); }
        require_journal(&self.journal)
    }

    /// Synchronous conditional restore on the same OS thread that owns
    /// WinINet mutex; safe across async task migration or Ctrl+C callbacks.
    pub fn restore(&mut self) -> Result<Recovery, ProxyError> {
        if !self.active {
            return Ok(Recovery::NothingPending);
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.commands
            .as_ref()
            .ok_or(ProxyError::Unavailable)?
            .send(tx)
            .map_err(|_| ProxyError::Unavailable)?;
        let outcome = rx.recv().map_err(|_| ProxyError::Unavailable)??;
        self.active = false;
        self.commands.take();
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| ProxyError::Unavailable)?;
        }
        Ok(outcome)
    }
}

impl Drop for OwnedProxy {
    fn drop(&mut self) {
        // Graceful client shutdown always requests CAS, never forced restore.
        let _ = self.restore();
        // Release channel even after a foreign-write conflict, allowing the
        // native worker to finish and release its *own thread's* Win32 mutex.
        self.commands.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyStatus {
    NoJournal,
    PendingOwned,
    PendingConflict,
    PendingAlreadyRestored,
}
pub fn status() -> Result<ProxyStatus, ProxyError> {
    let Some(journal) = read_journal()? else {
        return Ok(ProxyStatus::NoJournal);
    };
    let current = query()?;
    Ok(if current == journal.applied {
        ProxyStatus::PendingOwned
    } else if current == journal.before {
        ProxyStatus::PendingAlreadyRestored
    } else {
        ProxyStatus::PendingConflict
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_or_foreign_proxy_settings_and_public_binds() {
        let base = Snapshot {
            flags: PROXY_TYPE_DIRECT,
            server: String::new(),
            bypass: String::new(),
            auto_url: String::new(),
        };
        assert!(base.for_loopback("0.0.0.0:7890".parse().unwrap()).is_err());
        assert!(base
            .for_loopback("192.0.2.1:7890".parse().unwrap())
            .is_err());
        assert!(base.for_loopback("127.0.0.1:0".parse().unwrap()).is_err());
        assert_eq!(
            base.for_loopback("127.0.0.1:7890".parse().unwrap())
                .unwrap()
                .server,
            "http=127.0.0.1:7890;https=127.0.0.1:7890"
        );
        let mut invalid = base.clone();
        invalid.flags = 0x100;
        assert_eq!(invalid.validate(), Err(ProxyError::InvalidSettings));
        invalid.flags = PROXY_TYPE_DIRECT;
        invalid.bypass = "malicious\nvalue".into();
        assert_eq!(invalid.validate(), Err(ProxyError::InvalidSettings));
    }
    #[test]
    fn journal_is_bound_to_version_and_user_and_never_allows_forced_recovery() {
        let before = Snapshot {
            flags: PROXY_TYPE_DIRECT,
            server: "old.proxy:8888".into(),
            bypass: "example.invalid".into(),
            auto_url: String::new(),
        };
        let applied = before
            .for_loopback("127.0.0.1:7890".parse().unwrap())
            .unwrap();
        let mut journal = Journal {
            version: 1,
            user_sid: current_user_sid().unwrap(),
            before,
            applied,
        };
        journal.validate().unwrap();
        let valid = journal.applied.clone();
        journal.applied.server = "http=192.0.2.1:7890;https=192.0.2.1:7890".into();
        assert_eq!(journal.validate(), Err(ProxyError::Journal));
        journal.applied = valid.clone();
        journal.applied.bypass.push_str(";foreign.invalid");
        assert_eq!(journal.validate(), Err(ProxyError::Journal));
        journal.applied = valid.clone();
        journal.applied.server = "http=127.0.0.1:7890;https=127.0.0.1:7891".into();
        assert_eq!(journal.validate(), Err(ProxyError::Journal));
        journal.applied = valid;
        journal.version = 2;
        assert_eq!(journal.validate(), Err(ProxyError::Journal));
        journal.version = 1;
        journal.user_sid = "S-1-5-18".into();
        assert_eq!(journal.validate(), Err(ProxyError::Journal));
    }
    // The previous v1 writer used exactly these fields. A strict upgrade
    // must still accept all valid legacy snapshots without rewriting them.
    fn read_legacy_journal(journal: &Journal) -> Journal {
        let encoded = toml::to_string(journal).unwrap();
        toml::from_str(&encoded).unwrap()
    }

    #[test]
    fn native_scope_policy_reader_refuses_machine_and_malformed_values() {
        use windows_sys::Win32::System::Registry::{RegDeleteKeyW, REG_OPTION_VOLATILE};

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = format!(
            "Software\\TheiaProxyPolicyTest-{}-{stamp}",
            std::process::id()
        );
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, wide(&self.0).as_ptr()) };
            }
        }
        assert_eq!(require_per_user_scope_at(HKEY_CURRENT_USER, &path), Ok(()));
        let mut handle = null_mut();
        let mut disposition = 0;
        assert_eq!(
            unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    wide(&path).as_ptr(),
                    0,
                    null_mut(),
                    REG_OPTION_VOLATILE,
                    KEY_ALL_ACCESS,
                    null(),
                    &mut handle,
                    &mut disposition,
                )
            },
            0
        );
        let _cleanup = Cleanup(path.clone());
        let key = Key(handle);
        assert_eq!(require_per_user_scope_at(HKEY_CURRENT_USER, &path), Ok(()));
        for (kind, bytes, expected) in [
            (REG_DWORD, 1u32.to_le_bytes(), Ok(())),
            (
                REG_DWORD,
                0u32.to_le_bytes(),
                Err(ProxyError::PolicyManaged),
            ),
            (
                REG_DWORD,
                2u32.to_le_bytes(),
                Err(ProxyError::PolicyManaged),
            ),
            (
                REG_BINARY,
                1u32.to_le_bytes(),
                Err(ProxyError::PolicyManaged),
            ),
        ] {
            assert_eq!(
                unsafe {
                    RegSetValueExW(
                        key.0,
                        wide(SCOPE_POLICY_VALUE).as_ptr(),
                        0,
                        kind,
                        bytes.as_ptr(),
                        bytes.len() as u32,
                    )
                },
                0
            );
            assert_eq!(
                require_per_user_scope_at(HKEY_CURRENT_USER, &path),
                expected
            );
        }
        assert_eq!(
            unsafe { RegDeleteValueW(key.0, wide(SCOPE_POLICY_VALUE).as_ptr()) },
            0
        );
        assert_eq!(require_per_user_scope_at(HKEY_CURRENT_USER, &path), Ok(()));
    }

    #[test]
    fn legacy_v1_journal_preserves_proxy_pac_and_autodetect_fields() {
        let sid = current_user_sid().unwrap();
        let legacy = format!(
            r#"version = 1
user_sid = "{sid}"

[before]
flags = 15
server = "http=old.invalid:8080;https=old.invalid:8443"
bypass = "<local>;internal.invalid"
auto_url = "https://pac.invalid/proxy.pac"

[applied]
flags = 3
server = "http=127.0.0.1:7890;https=127.0.0.1:7890"
bypass = "<local>;localhost;127.0.0.1;[::1]"
auto_url = "https://pac.invalid/proxy.pac"
"#
        );
        let journal: Journal = toml::from_str(&legacy).unwrap();
        journal.validate().unwrap();
        assert_eq!(journal.before.flags, 15);
        assert_eq!(journal.before.bypass, "<local>;internal.invalid");
        assert_eq!(journal.before.auto_url, journal.applied.auto_url);
        assert_eq!(read_legacy_journal(&journal), journal);
        for flags in 1..=VALID_PROXY_FLAGS {
            let mut before = journal.before.clone();
            before.flags = flags;
            let applied = before.for_loopback("[::1]:7890".parse().unwrap()).unwrap();
            let candidate = Journal {
                version: 1,
                user_sid: sid.clone(),
                before,
                applied,
            };
            candidate.validate().unwrap();
            assert_eq!(read_legacy_journal(&candidate), candidate);
        }
        let unknown = legacy.replace("version = 1", "version = 2");
        let record: Journal = toml::from_str(&unknown).unwrap();
        assert_eq!(record.validate(), Err(ProxyError::Journal));
    }

    /// Opt-in native OS settings test, ONLY on a disposable CI Windows user
    /// and only when THEIA_WINDOWS_PROXY_E2E_ALLOWED is set. Never auto-run on
    /// developer machines. This temporarily changes the *current user's*
    /// default LAN WinINet HTTP(S) proxy.
    #[test]
    #[ignore = "disposable Windows CI only: temporarily mutates WinINet per-user proxy"]
    fn native_wininet_cas_recovery_and_foreign_override() {
        if std::env::var("THEIA_WINDOWS_PROXY_E2E_ALLOWED").as_deref() != Ok("yes") {
            panic!("explicit disposable Windows runner consent required");
        }
        if std::env::var("THEIA_PROXY_CRASH_CHILD").as_deref() == Ok("yes") {
            // An actual second process uses a real WinINet mutation and a
            // real OS process exit that bypasses Drop. Its mutex is released
            // by the Windows kernel while the durable journal remains.
            let _lease = OwnedProxy::apply("127.0.0.1:45992".parse().unwrap()).unwrap();
            assert_eq!(status().unwrap(), ProxyStatus::PendingOwned);
            std::process::exit(73);
        }
        // Current clients serialize on the global SID mutex and also honor
        // a legacy session-local owner. Exercise both with native threads.
        let sid = current_user_sid().unwrap();
        let global_name = format!("Global\\Theia-WinInet-Proxy-{sid}");
        let legacy_name = format!("Local\\Theia-WinInet-Proxy-{sid}");
        let global = MutexHandle::acquire(&global_name, Some(&sid)).unwrap();
        assert_eq!(
            std::thread::spawn(|| Mutex::acquire().map(|_| ()))
                .join()
                .unwrap(),
            Err(ProxyError::Busy)
        );
        drop(global);
        let legacy = MutexHandle::acquire(&legacy_name, None).unwrap();
        assert_eq!(
            std::thread::spawn(|| Mutex::acquire().map(|_| ()))
                .join()
                .unwrap(),
            Err(ProxyError::Busy)
        );
        drop(legacy);
        drop(Mutex::acquire().unwrap());

        let original = query().unwrap();
        assert_eq!(status().unwrap(), ProxyStatus::NoJournal);
        // Reservation serializes the whole preflight, without OS mutation.
        let reservation = ReservedProxy::acquire().unwrap();
        assert!(matches!(ReservedProxy::acquire(), Err(ProxyError::Busy)));
        assert_eq!(recover_explicit(), Err(ProxyError::Busy));
        assert_eq!(query().unwrap(), original);
        assert_eq!(status().unwrap(), ProxyStatus::NoJournal);
        drop(reservation);
        let bind = "127.0.0.1:45991".parse().unwrap();
        let review = review_apply(bind).unwrap();
        let mut changed = original.clone();
        changed.bypass = "review-drift.invalid".into();
        set(&changed).unwrap();
        let changed = query().unwrap();
        assert_ne!(changed, original);
        assert_eq!(changed.bypass, "review-drift.invalid");
        assert!(matches!(
            OwnedProxy::apply_reviewed(bind, review),
            Err(ProxyError::Conflict)
        ));
        assert_eq!(query().unwrap(), changed);
        assert_eq!(status().unwrap(), ProxyStatus::NoJournal);
        set(&original).unwrap();
        let review = review_apply(bind).unwrap();
        let mut proxy = OwnedProxy::apply_reviewed(bind, review).unwrap();
        proxy.verify().unwrap();
        let applied = query().unwrap();
        assert_eq!(applied.server, "http=127.0.0.1:45991;https=127.0.0.1:45991");
        assert_eq!(status().unwrap(), ProxyStatus::PendingOwned);
        assert_eq!(
            recover_explicit(),
            Err(ProxyError::Busy),
            "running owner is protected by mutex"
        );
        // A live owner cannot restore from a missing or replaced journal,
        // even if the currently applied WinINet snapshot still matches.
        let journal = read_journal().unwrap().unwrap();
        delete_journal().unwrap();
        assert_eq!(proxy.restore(), Err(ProxyError::Conflict));
        assert_eq!(query().unwrap(), applied);
        let mut replacement = read_legacy_journal(&journal);
        replacement.before.bypass.push_str(";replacement.invalid");
        save_journal(&replacement).unwrap();
        assert_eq!(proxy.restore(), Err(ProxyError::Conflict));
        assert_eq!(query().unwrap(), applied);
        assert_eq!(read_journal().unwrap(), Some(replacement));
        delete_journal().unwrap();
        save_journal(&journal).unwrap();
        // Make a foreign WinINet edit and verify CAS refuses to erase it.
        let mut foreign = applied.clone();
        foreign.bypass.push_str(";example.org");
        set(&foreign).unwrap();
        assert_eq!(proxy.verify(), Err(ProxyError::Conflict));
        assert_eq!(proxy.restore(), Err(ProxyError::Conflict));
        assert_eq!(status().unwrap(), ProxyStatus::PendingConflict);
        // Return to the state the original owner last wrote, then restore.
        set(&applied).unwrap();
        assert_eq!(proxy.restore(), Ok(Recovery::Restored));
        assert_eq!(query().unwrap(), original);
        assert_eq!(status().unwrap(), ProxyStatus::NoJournal);
        drop(proxy);
        // Real crash subprocess regression: a fresh process recovers a
        // previous instance that exited *without* Rust destructors.
        let crash = || {
            let self_executable = std::env::current_exe().unwrap();
            let result = std::process::Command::new(self_executable)
                .arg(
                    "windows_system_proxy::tests::native_wininet_cas_recovery_and_foreign_override",
                )
                .arg("--exact")
                .arg("--ignored")
                .env("THEIA_PROXY_CRASH_CHILD", "yes")
                .status()
                .unwrap();
            assert_eq!(
                result.code(),
                Some(73),
                "child must simulate hard exit after apply"
            );
            assert_eq!(status().unwrap(), ProxyStatus::PendingOwned);
        };
        crash();
        assert_eq!(recover_explicit(), Ok(Recovery::Restored));
        assert_eq!(query().unwrap(), original);
        assert_eq!(status().unwrap(), ProxyStatus::NoJournal);
        assert_eq!(recover_explicit(), Ok(Recovery::NothingPending));
        assert_eq!(query().unwrap(), original);

        // A v1 record can survive a process exit before apply or an external
        // restoration. Clear only the record, with the exact original intact.
        crash();
        set(&original).unwrap();
        assert_eq!(status().unwrap(), ProxyStatus::PendingAlreadyRestored);
        let review = review_recovery().unwrap();
        assert_eq!(recover_reviewed(review), Ok(Recovery::AlreadyRestored));
        assert_eq!(query().unwrap(), original);
        assert_eq!(status().unwrap(), ProxyStatus::NoJournal);

        // Recovery consent also expires when the journal itself is replaced.
        crash();
        let review = review_recovery().unwrap();
        let record = read_journal().unwrap().unwrap();
        let applied = query().unwrap();
        let mut replacement = read_legacy_journal(&record);
        replacement.before.bypass = "replacement.invalid".into();
        delete_journal().unwrap();
        save_journal(&replacement).unwrap();
        assert_eq!(recover_reviewed(review), Err(ProxyError::Conflict));
        assert_eq!(query().unwrap(), applied);
        assert_eq!(read_journal().unwrap(), Some(replacement));
        delete_journal().unwrap();
        save_journal(&record).unwrap();
        assert_eq!(recover_explicit(), Ok(Recovery::Restored));
        assert_eq!(query().unwrap(), original);
        assert_eq!(status().unwrap(), ProxyStatus::NoJournal);

        crash();
        let review = review_recovery().unwrap();
        let applied = query().unwrap();
        let mut changed = applied.clone();
        changed.bypass = "recovery-drift.invalid".into();
        set(&changed).unwrap();
        let changed = query().unwrap();
        assert_ne!(changed, applied);
        assert_eq!(changed.bypass, "recovery-drift.invalid");
        assert_eq!(recover_reviewed(review), Err(ProxyError::Conflict));
        assert_eq!(query().unwrap(), changed);
        assert_eq!(status().unwrap(), ProxyStatus::PendingConflict);
        set(&applied).unwrap();
        let review = review_recovery().unwrap();
        assert_eq!(recover_reviewed(review), Ok(Recovery::Restored));
        assert_eq!(query().unwrap(), original);
        assert_eq!(status().unwrap(), ProxyStatus::NoJournal);

        crate::tui_system_proxy::tests::native_lifecycle(
            || {
                assert_eq!(query().unwrap(), original);
                assert_eq!(status().unwrap(), ProxyStatus::NoJournal);
            },
            crash,
        );

        // No test leaves the disposable CI user's WinINet settings modified.
        assert_eq!(query().unwrap(), original);
        assert_eq!(status().unwrap(), ProxyStatus::NoJournal);
    }
}
