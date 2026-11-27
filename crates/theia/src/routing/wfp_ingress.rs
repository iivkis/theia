//! Windows user-mode WFP redirect adapter. Requires a separate installed
//! ALE_CONNECT_REDIRECT callout driver and secure session provisioning.
//! No WFP filters or driver installation are performed here.
use super::{packet::FlowKey, wfp_context};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    io,
    net::SocketAddr,
    os::windows::io::{AsRawHandle, AsRawSocket, FromRawHandle, OwnedHandle},
    ptr,
};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use windows_sys::Win32::Networking::WinSock::{
    WSAGetLastError, WSAIoctl, SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE,
    SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
};
use zeroize::Zeroizing;

const QUERY_RECORDS: u32 = SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS;
const QUERY_CONTEXT: u32 = SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT;
const MAX_RECORDS: usize = 4096;

fn query(stream: &impl AsRawSocket, code: u32, buffer: &mut [u8]) -> io::Result<usize> {
    let mut returned = 0u32;
    // SAFETY: socket is owned by the caller, output memory is valid for
    // the synchronous call; no overlapped pointer or callback is retained.
    let rc = unsafe {
        WSAIoctl(
            stream.as_raw_socket() as usize,
            code,
            ptr::null(),
            0,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut returned,
            ptr::null_mut(),
            None,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    let n = returned as usize;
    if n == 0 || n > buffer.len() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(n)
}

/// One privileged laboratory driver session. The driver accepts exactly
/// one configuration for its lifetime and disables redirect on cleanup.
/// No BFE filters are installed, and no unsigned driver is loaded here.
pub struct WfpLabSession {
    handle: OwnedHandle,
    token: Zeroizing<[u8; 32]>,
    compartment: u32,
    port: u16,
    retired: AtomicBool,
}

const CONFIGURE: u32 = (0x22 << 16) | (2 << 14) | (0x800 << 2);
const AUTHORIZE_ENDPOINT: u32 = (0x22 << 16) | (2 << 14) | (0x801 << 2);
const STATUS: u32 = (0x22 << 16) | (2 << 14) | (0x802 << 2);
const STOP: u32 = (0x22 << 16) | (2 << 14) | (0x803 << 2);
const QUERY_ENDPOINT: u32 = SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE;

fn ioctl(handle: &OwnedHandle, code: u32, bytes: &[u8]) -> io::Result<()> {
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let mut returned = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle.as_raw_handle().cast(),
            code,
            bytes.as_ptr().cast(),
            bytes.len() as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if returned != 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(())
}

impl WfpLabSession {
    /// Requires a SYSTEM-owned service, an already installed laboratory
    /// driver and a non-default test compartment. The caller must bind the
    /// listener and arrange isolated BFE filters before admitting traffic.
    pub fn open(compartment: u32, port: u16) -> io::Result<Self> {
        use windows_sys::Win32::{
            Foundation::INVALID_HANDLE_VALUE,
            Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING},
        };
        if compartment <= 1 || port == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        if unsafe {
            windows_sys::Win32::NetworkManagement::IpHelper::GetCurrentThreadCompartmentId()
        } != compartment
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let name: Vec<u16> = r"\\.\TheiaWfpLab".encode_utf16().chain([0]).collect();
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                0x4000_0000,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        let mut token = Zeroizing::new([0u8; 32]);
        SystemRandom::new()
            .fill(&mut *token)
            .map_err(|_| io::Error::other("session entropy unavailable"))?;
        let mut request = Zeroizing::new([0u8; 40]);
        request[..4].copy_from_slice(&compartment.to_be_bytes());
        request[4..6].copy_from_slice(&port.to_be_bytes());
        request[8..].copy_from_slice(token.as_ref());
        ioctl(&handle, CONFIGURE, request.as_ref())?;
        let session = Self {
            handle,
            token,
            compartment,
            port,
            retired: AtomicBool::new(false),
        };
        session.check()?;
        Ok(session)
    }

    fn scope_request(&self) -> Zeroizing<[u8; 40]> {
        let mut bytes = Zeroizing::new([0u8; 40]);
        bytes[..4].copy_from_slice(&self.compartment.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.port.to_be_bytes());
        bytes[8..].copy_from_slice(self.token.as_ref());
        bytes
    }

    /// Check the live kernel session on the same compartment worker.
    pub(crate) fn check(&self) -> io::Result<()> {
        if self.retired.load(Ordering::Acquire)
            || unsafe {
                windows_sys::Win32::NetworkManagement::IpHelper::GetCurrentThreadCompartmentId()
            } != self.compartment
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let bytes = self.scope_request();
        ioctl(&self.handle, STATUS, bytes.as_ref())?;
        if self.retired.load(Ordering::Acquire) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }

    /// Stop is explicit and irreversible for this driver session. The
    /// persistent filters are NOT removed; signed-driver recovery is separate.
    pub(crate) fn deactivate(&self) -> io::Result<()> {
        if self.retired.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let bytes = self.scope_request();
        ioctl(&self.handle, STOP, bytes.as_ref())
    }

    /// Register the actual ALE endpoint handle before the TCP connect.
    /// The kernel consumes one exact (process, endpoint, target) permit.
    /// It is not a process-wide exemption.
    pub fn authorize_tcp_carrier(
        &self,
        socket: &tokio::net::TcpSocket,
        target: SocketAddr,
    ) -> io::Result<()> {
        self.authorize_carrier(socket, target, 6)
    }

    fn authorize_carrier(
        &self,
        socket: &impl AsRawSocket,
        target: SocketAddr,
        protocol: u8,
    ) -> io::Result<()> {
        self.check()?;
        if !matches!(protocol, 6 | 17) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if target.port() == 0
            || target.ip().is_unspecified()
            || target.ip().is_multicast()
            || matches!(target, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.ip().to_ipv4_mapped().is_some() || v6.ip().is_unicast_link_local())
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let mut endpoint = [0u8; 8];
        if query(socket, QUERY_ENDPOINT, &mut endpoint)? != 8 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let endpoint = u64::from_ne_bytes(endpoint);
        if endpoint == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let mut request = [0u8; 28];
        request[..8].copy_from_slice(&endpoint.to_be_bytes());
        request[8] = if target.is_ipv4() { 4 } else { 6 };
        request[9] = protocol;
        request[10..12].copy_from_slice(&target.port().to_be_bytes());
        match target.ip() {
            std::net::IpAddr::V4(ip) => request[12..16].copy_from_slice(&ip.octets()),
            std::net::IpAddr::V6(ip) => request[12..28].copy_from_slice(&ip.octets()),
        }
        ioctl(&self.handle, AUTHORIZE_ENDPOINT, &request)?;
        self.check()
    }

    pub(super) fn udp_context(
        &self,
        context: &[u8],
        peer: SocketAddr,
        local: SocketAddr,
    ) -> io::Result<FlowKey> {
        self.check()?;
        if local.port() != self.port {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let key = wfp_context::decode_transport(
            context,
            &self.token,
            peer,
            local,
            super::packet::Transport::Udp,
        )
        .ok_or(io::ErrorKind::PermissionDenied)?;
        if key.interface != self.compartment {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.check()?;
        Ok(key)
    }

    pub(crate) fn original_tcp(&self, stream: &TcpStream) -> io::Result<FlowKey> {
        self.check()?;
        if stream.local_addr()?.port() != self.port {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let key = original_tcp(stream, &self.token)?;
        if key.interface != self.compartment {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        self.check()?;
        Ok(key)
    }
}

fn original_tcp(stream: &TcpStream, token: &[u8; 32]) -> io::Result<FlowKey> {
    // The existing H2/H3 carrier is not a new direct socket to the original
    // destination. It still requires independently proven carrier exclusion.
    // Redirect records are queried to reject ordinary local TCP connections;
    // do not copy opaque records to an unrelated multiplexed carrier.
    let mut records = [0u8; MAX_RECORDS];
    query(stream, QUERY_RECORDS, &mut records)?;
    let mut context = [0u8; wfp_context::SIZE];
    let len = query(stream, QUERY_CONTEXT, &mut context)?;
    wfp_context::decode(
        &context[..len],
        token,
        stream.peer_addr()?,
        stream.local_addr()?,
    )
    .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))
}

impl super::carrier_socket::Registrar for WfpLabSession {
    fn tcp(
        &self,
        socket: &tokio::net::TcpSocket,
        peer: SocketAddr,
    ) -> io::Result<super::carrier_socket::Lease> {
        self.authorize_tcp_carrier(socket, peer)?;
        Ok(super::carrier_socket::Lease::default())
    }
    fn udp(
        &self,
        socket: &tokio::net::UdpSocket,
        peer: SocketAddr,
    ) -> io::Result<super::carrier_socket::Lease> {
        // A connected, pinned H3 socket uses one ALE admission before
        // any datagram; no user UDP or process-wide permit is granted.
        if socket.peer_addr().is_ok() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.authorize_carrier(socket, peer, 17)?;
        Ok(super::carrier_socket::Lease::default())
    }
}

/// Exclusive dual-stack listeners, bound before enabling the companion
/// driver. This does not install filters or change the thread compartment.
pub(crate) fn bind_tcp_listeners(compartment: u32, port: u16) -> io::Result<[TcpListener; 2]> {
    use windows_sys::Win32::Networking::WinSock::{
        getsockopt, setsockopt, IPPROTO_IPV6, IPV6_V6ONLY, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
    };
    if compartment <= 1
        || port == 0
        || unsafe {
            windows_sys::Win32::NetworkManagement::IpHelper::GetCurrentThreadCompartmentId()
        } != compartment
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    fn set_one(socket: &TcpSocket, level: i32, option: i32) -> io::Result<()> {
        let value = 1i32;
        let mut readback = 0i32;
        let mut len = std::mem::size_of::<i32>() as i32;
        let raw = socket.as_raw_socket() as usize;
        if unsafe { setsockopt(raw, level, option, (&value as *const i32).cast(), len) } != 0
            || unsafe {
                getsockopt(
                    raw,
                    level,
                    option,
                    (&mut readback as *mut i32).cast(),
                    &mut len,
                )
            } != 0
        {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        if readback != 1 || len != std::mem::size_of::<i32>() as i32 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    let v4 = TcpSocket::new_v4()?;
    let v6 = TcpSocket::new_v6()?;
    for socket in [&v4, &v6] {
        set_one(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE)?;
    }
    set_one(&v6, IPPROTO_IPV6, IPV6_V6ONLY)?;
    v4.bind(SocketAddr::from(([0, 0, 0, 0], port)))?;
    v6.bind(SocketAddr::new(
        std::net::Ipv6Addr::UNSPECIFIED.into(),
        port,
    ))?;
    Ok([v4.listen(128)?, v6.listen(128)?])
}

/// A pinned read-only BFE inspector from the exact approved driver build.
/// Keep the executable open without write/delete sharing while invoking
/// it; the caller must supply an administrator-owned local directory.
/// A foreign administrator racing directory replacement is out of scope.
pub(crate) struct BfeInspector {
    path: std::path::PathBuf,
    _file: std::fs::File,
    compartment: u32,
}
impl BfeInspector {
    pub(crate) fn open(
        path: &std::path::Path,
        expected: [u8; 32],
        compartment: u32,
    ) -> io::Result<Self> {
        use sha2::{Digest, Sha256};
        use std::{io::Read, os::windows::fs::OpenOptionsExt};
        use subtle::ConstantTimeEq;
        if compartment <= 1 || expected == [0; 32] || !path.is_absolute() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let path = std::fs::canonicalize(path)?;
        if path
            .extension()
            .and_then(|v| v.to_str())
            .is_none_or(|v| !v.eq_ignore_ascii_case("exe"))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || !(1..=16 * 1024 * 1024).contains(&metadata.len()) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 32 * 1024];
        let mut total = 0u64;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > metadata.len() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            hash.update(&buffer[..count]);
        }
        let actual: [u8; 32] = hash.finalize().into();
        if total != metadata.len() || !bool::from(actual.ct_eq(&expected)) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(Self {
            path,
            _file: file,
            compartment,
        })
    }

    /// The helper performs one read-only BFE transaction; timeout, failure,
    /// or an unconfirmed exit never means capture-ready. No recovery command
    /// is available through this runtime helper.
    pub(crate) async fn inspect(self: &std::sync::Arc<Self>) -> io::Result<()> {
        let owner = self.clone();
        tokio::task::spawn_blocking(move || {
            use std::{
                process::{Command, Stdio},
                time::{Duration, Instant},
            };
            let mut child = Command::new(&owner.path)
                .arg("inspect")
                .arg(owner.compartment.to_string())
                .arg("--isolated-lab-confirm")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        return if status.success() {
                            Ok(())
                        } else {
                            Err(io::ErrorKind::PermissionDenied.into())
                        }
                    }
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    result => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(result
                            .err()
                            .unwrap_or_else(|| io::ErrorKind::TimedOut.into()));
                    }
                }
            }
        })
        .await
        .map_err(|_| io::Error::other("BFE inspection worker failed"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_default_compartment_and_unapproved_inspector_before_open() {
        assert!(WfpLabSession::open(1, 18080).is_err());
        assert!(WfpLabSession::open(2, 0).is_err());
        assert!(bind_tcp_listeners(1, 18080).is_err());
        assert!(bind_tcp_listeners(2, 0).is_err());
        assert!(BfeInspector::open(std::path::Path::new("not-approved.exe"), [1; 32], 2).is_err());
        assert!(BfeInspector::open(std::path::Path::new("not-approved.exe"), [0; 32], 2).is_err());
    }
}
