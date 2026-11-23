//! M4.2d: Windows Named Pipe management bound to the current process user
//! SID with an explicit protected DACL. No default pipe ACL, no admin TCP.
#![cfg(target_os = "windows")]

use crate::{
    live_auth::LiveAuthorization,
    management::{self, ManagementError, StatusCommand, StatusReply},
    reload_preflight::ReloadPreflight,
};
use std::{ffi::c_void, mem::size_of, ptr::null_mut, sync::Arc, time::Duration};
use tokio::{
    net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions},
    sync::Semaphore,
    task::JoinSet,
    time::{sleep, timeout},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, ERROR_PIPE_BUSY, HANDLE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

fn valid_identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 48
        && id
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-')
}

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: owns handle acquired via OpenProcessToken.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct Descriptor(*mut c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocation returned by ConvertStringSecurityDescriptor.
            unsafe { LocalFree(self.0) };
        }
    }
}

pub fn current_user_sid() -> Result<String, ManagementError> {
    let mut handle: HANDLE = null_mut();
    // SAFETY: valid pseudo-handle and writable out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
        return Err(ManagementError::UnsafeEndpoint);
    }
    let token = Token(handle);
    let mut size = 0u32;
    // SAFETY: documented first-call size probe.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size) };
    if size < size_of::<TOKEN_USER>() as u32 || size > 4096 {
        return Err(ManagementError::UnsafeEndpoint);
    }
    // Aligned buffer: TOKEN_USER contains a SID pointer.
    let mut buffer = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    // SAFETY: aligned buffer with at least the reported byte capacity.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(ManagementError::UnsafeEndpoint);
    }
    // SAFETY: successful TokenUser call populated the aligned TOKEN_USER.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    if sid.is_null() {
        return Err(ManagementError::UnsafeEndpoint);
    }
    let mut text: *mut u16 = null_mut();
    // SAFETY: SID points into the live token information buffer.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err(ManagementError::UnsafeEndpoint);
    }
    let result = (|| {
        let mut count = 0usize;
        // SAFETY: returned SID string is NUL terminated. A hard cap rejects
        // unrealistic results before unbounded allocation or scanning.
        while count < 192 && unsafe { *text.add(count) } != 0 {
            count += 1;
        }
        if count == 192 {
            return Err(ManagementError::UnsafeEndpoint);
        }
        // SAFETY: at least count+1 units were allocated by the conversion.
        let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, count) })
            .map_err(|_| ManagementError::UnsafeEndpoint)?;
        if !value.starts_with("S-1-")
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
        {
            return Err(ManagementError::UnsafeEndpoint);
        }
        Ok(value)
    })();
    // SAFETY: exactly the LocalAlloc pointer returned by the SID converter.
    unsafe { LocalFree(text.cast()) };
    result
}

pub fn pipe_name(id: &str) -> Result<String, ManagementError> {
    if !valid_identifier(id) {
        return Err(ManagementError::UnsafeEndpoint);
    }
    Ok(format!(
        r"\\.\pipe\theia-control-{}-{id}",
        current_user_sid()?
    ))
}

fn descriptor() -> Result<Descriptor, ManagementError> {
    let sddl = format!("D:P(A;;GA;;;{})(A;;GA;;;SY)", current_user_sid()?);
    let wide = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut security: *mut c_void = null_mut();
    // SAFETY: NUL-terminated SDDL and writable output descriptor pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            1,
            &mut security,
            null_mut(),
        )
    } == 0
        || security.is_null()
    {
        return Err(ManagementError::UnsafeEndpoint);
    }
    Ok(Descriptor(security))
}

fn create_instance(name: &str, first: bool) -> Result<NamedPipeServer, ManagementError> {
    let descriptor = descriptor()?;
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    // Set pipe mode first; enforce remote rejection last. Never create with
    // a null security descriptor or inherited anonymous access.
    options.max_instances(management::MAX_CLIENTS + 1);
    options.first_pipe_instance(first);
    options.reject_remote_clients(true);
    // SAFETY: attrs and descriptor remain valid for this synchronous call.
    unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attrs as *mut SECURITY_ATTRIBUTES).cast(),
        )
    }
    .map_err(|_| ManagementError::SocketUnavailable)
}

/// Bind only after TCP/UDP/TLS listener preparation, so failed server starts
/// cannot advertise a valid status or allow preflight Apply.
pub struct WindowsServer {
    name: String,
    current: NamedPipeServer,
    inbounds: usize,
    preflight: Option<Arc<ReloadPreflight>>,
    live: Option<Arc<LiveAuthorization>>,
}

impl WindowsServer {
    pub fn bind(id: &str, inbounds: usize) -> Result<Self, ManagementError> {
        if inbounds == 0 || inbounds > 65535 {
            return Err(ManagementError::UnsafeEndpoint);
        }
        let name = pipe_name(id)?;
        let current = create_instance(&name, true)?;
        Ok(Self {
            name,
            current,
            inbounds,
            preflight: None,
            live: None,
        })
    }

    pub fn from_environment(inbounds: usize) -> Result<Option<Self>, ManagementError> {
        let Some(raw) = std::env::var_os("THEIA_CONTROL_PIPE") else {
            return Ok(None);
        };
        let id = raw
            .into_string()
            .map_err(|_| ManagementError::UnsafeEndpoint)?;
        Self::bind(&id, inbounds).map(Some)
    }

    pub(crate) fn with_preflight(mut self, preflight: Arc<ReloadPreflight>) -> Self {
        self.preflight = Some(preflight);
        self
    }

    pub(crate) fn with_live_authorization(mut self, live: Arc<LiveAuthorization>) -> Self {
        self.live = Some(live);
        self
    }

    pub async fn serve(mut self) -> Result<(), ManagementError> {
        let permits = Arc::new(Semaphore::new(management::MAX_CLIENTS));
        let mut tasks = JoinSet::new();
        loop {
            self.current
                .connect()
                .await
                .map_err(|_| ManagementError::Io)?;
            // Eight active handlers plus one pending socket maximum.
            let permit = permits
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| ManagementError::Io)?;
            let fresh = create_instance(&self.name, false)?;
            let stream = std::mem::replace(&mut self.current, fresh);
            let inbounds = self.inbounds;
            let preflight = self.preflight.clone();
            let live = self.live.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let _ = timeout(
                    management::IO_TIMEOUT,
                    management::handle(stream, inbounds, preflight, live),
                )
                .await;
            });
            while tasks.try_join_next().is_some() {}
        }
    }
}

pub async fn query_pipe(id: &str, command: StatusCommand) -> Result<StatusReply, ManagementError> {
    let name = pipe_name(id)?;
    timeout(management::IO_TIMEOUT, async {
        loop {
            match ClientOptions::new().open(&name) {
                Ok(stream) => return management::exchange(stream, command).await,
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    sleep(Duration::from_millis(15)).await;
                }
                Err(_) => return Err(ManagementError::SocketUnavailable),
            }
        }
    })
    .await
    .map_err(|_| ManagementError::TimedOut)?
}

pub async fn query_environment(command: StatusCommand) -> Result<StatusReply, ManagementError> {
    let id = std::env::var_os("THEIA_CONTROL_PIPE")
        .ok_or(ManagementError::NotConfigured)?
        .into_string()
        .map_err(|_| ManagementError::UnsafeEndpoint)?;
    query_pipe(&id, command).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn id() -> String {
        format!(
            "p{}x{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }
    #[test]
    fn id_is_canonical_and_derived_from_process_sid() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-"));
        let endpoint = pipe_name("m42d").unwrap();
        assert!(endpoint.contains(&sid));
        assert!(endpoint.ends_with("-m42d"));
        for raw in ["", ".", "..", " a", "a/b", "a\\b", "a:b", "a\nb", "ü"] {
            assert!(pipe_name(raw).is_err());
        }
        assert!(pipe_name(&"a".repeat(49)).is_err());
    }

    #[tokio::test]
    async fn named_pipe_kernel_dacl_contains_only_current_sid_and_system() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
                SE_KERNEL_OBJECT,
            },
            DACL_SECURITY_INFORMATION,
        };
        let pipe = WindowsServer::bind(&id(), 1).unwrap();
        let mut security: *mut c_void = null_mut();
        // SAFETY: owned live server kernel handle and valid output pointer.
        let result = unsafe {
            GetSecurityInfo(
                pipe.current.as_raw_handle() as _,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut security,
            )
        };
        assert_eq!(result, 0, "must inspect the actual NT object ACL");
        let _security = Descriptor(security);
        let mut text: *mut u16 = null_mut();
        // SAFETY: descriptor is live and obtained directly from the pipe.
        assert_ne!(
            unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    security,
                    1,
                    DACL_SECURITY_INFORMATION,
                    &mut text,
                    null_mut(),
                )
            },
            0
        );
        let mut length = 0usize;
        // SAFETY: ConvertSecurityDescriptor... returns NUL-terminated LocalAlloc UTF16.
        while length < 1024 && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        assert!(length < 1024);
        // SAFETY: allocation remains valid until LocalFree below.
        let observed =
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).unwrap();
        // SAFETY: free exactly the text allocated by the NT converter.
        unsafe { LocalFree(text.cast()) };
        let sid = current_user_sid().unwrap();
        assert!(observed.starts_with("D:P"), "DACL must block inheritance");
        assert!(observed.contains(&format!(";;;{sid})")));
        assert!(observed.contains(";;;SY)"));
        assert_eq!(observed.matches("(A;").count(), 2, "exactly two allow ACEs");
        for banned in [";;;WD)", ";;;AN)", ";;;AU)", ";;;BU)", ";;;BA)"] {
            assert!(
                !observed.contains(banned),
                "default Everyone/anonymous/broad ACL leaked"
            );
        }
    }

    #[tokio::test]
    async fn private_named_pipe_is_first_instance_and_standalone_has_no_apply() {
        let id = id();
        let server = WindowsServer::bind(&id, 2).unwrap();
        assert!(
            WindowsServer::bind(&id, 2).is_err(),
            "must reject competing first instance"
        );
        let task = tokio::spawn(server.serve());
        assert_eq!(
            query_pipe(&id, StatusCommand::Status).await,
            Ok(StatusReply::Running { inbounds: 2 })
        );
        assert_eq!(
            query_pipe(
                &id,
                StatusCommand::ApplyReload {
                    expected_revision: 1
                }
            )
            .await,
            Err(ManagementError::Unsupported)
        );
        assert_eq!(
            query_pipe(
                &id,
                StatusCommand::ApplyReloadBound {
                    expected_revision: 1,
                    candidate_sha256: [1u8; 32],
                }
            )
            .await,
            Err(ManagementError::Unsupported)
        );
        task.abort();
    }
}
