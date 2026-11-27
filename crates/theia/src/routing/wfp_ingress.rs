//! Windows user-mode WFP redirect adapter. Requires a separate installed
//! ALE_CONNECT_REDIRECT callout driver and secure session provisioning.
//! No WFP filters or driver installation are performed here.
use super::{packet::FlowKey, wfp_context};
use std::{io, net::SocketAddr, os::windows::io::{AsRawHandle, AsRawSocket, FromRawHandle, OwnedHandle}, ptr};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;
use tokio::net::TcpStream;
use windows_sys::Win32::Networking::WinSock::{WSAGetLastError, WSAIoctl, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE};

const QUERY_RECORDS: u32 = SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS;
const QUERY_CONTEXT: u32 = SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT;
const MAX_RECORDS: usize = 4096;

fn query(stream: &impl AsRawSocket, code: u32, buffer: &mut [u8]) -> io::Result<usize> {
    let mut returned = 0u32;
    // SAFETY: socket is owned by the caller, output memory is valid for
    // the synchronous call; no overlapped pointer or callback is retained.
    let rc = unsafe {
        WSAIoctl(stream.as_raw_socket() as usize, code, ptr::null(), 0,
            buffer.as_mut_ptr().cast(), buffer.len() as u32, &mut returned,
            ptr::null_mut(), None)
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
}

const CONFIGURE: u32 = (0x22 << 16) | (2 << 14) | (0x800 << 2);
const AUTHORIZE_ENDPOINT: u32 = (0x22 << 16) | (2 << 14) | (0x801 << 2);
const QUERY_ENDPOINT: u32 = SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE;

fn ioctl(handle: &OwnedHandle, code: u32, bytes: &[u8]) -> io::Result<()> {
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let mut returned = 0;
    let ok = unsafe { DeviceIoControl(handle.as_raw_handle().cast(), code,
        bytes.as_ptr().cast(), bytes.len() as u32, ptr::null_mut(), 0, &mut returned, ptr::null_mut()) };
    if ok == 0 { return Err(io::Error::last_os_error()); }
    if returned != 0 { return Err(io::Error::from(io::ErrorKind::InvalidData)); }
    Ok(())
}

impl WfpLabSession {
    /// Requires a SYSTEM-owned service, an already installed laboratory
    /// driver and a non-default test compartment. The caller must bind the
    /// listener and arrange isolated BFE filters before admitting traffic.
    pub fn open(compartment: u32, port: u16) -> io::Result<Self> {
        use windows_sys::Win32::{Foundation::INVALID_HANDLE_VALUE, Storage::FileSystem::{CreateFileW, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL}};
        if compartment <= 1 || port == 0 { return Err(io::Error::from(io::ErrorKind::InvalidInput)); }
        let name: Vec<u16> = r"\\.\TheiaWfpLab".encode_utf16().chain([0]).collect();
        let raw = unsafe { CreateFileW(name.as_ptr(), 0x4000_0000, 0, ptr::null(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, ptr::null_mut()) };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() { return Err(io::Error::last_os_error()); }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        let mut token = Zeroizing::new([0u8;32]);
        SystemRandom::new().fill(&mut *token).map_err(|_| io::Error::other("session entropy unavailable"))?;
        let mut request = Zeroizing::new([0u8;40]);
        request[..4].copy_from_slice(&compartment.to_be_bytes());
        request[4..6].copy_from_slice(&port.to_be_bytes());
        request[8..].copy_from_slice(token.as_ref());
        ioctl(&handle, CONFIGURE, request.as_ref())?;
        Ok(Self { handle, token, compartment, port })
    }

    /// Register the actual ALE endpoint handle before the TCP connect.
    /// The kernel consumes one exact (process, endpoint, target) permit.
    /// It is not a process-wide exemption. H3 and production carrier
    /// construction are not connected to this experimental API yet.
    pub fn authorize_tcp_carrier(&self, socket: &tokio::net::TcpSocket, target: SocketAddr) -> io::Result<()> {
        if target.port() == 0 || target.ip().is_unspecified() || target.ip().is_multicast()
            || matches!(target, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.ip().to_ipv4_mapped().is_some() || v6.ip().is_unicast_link_local()) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let mut endpoint = [0u8;8];
        if query(socket, QUERY_ENDPOINT, &mut endpoint)? != 8 { return Err(io::Error::from(io::ErrorKind::InvalidData)); }
        let endpoint = u64::from_ne_bytes(endpoint);
        if endpoint == 0 { return Err(io::Error::from(io::ErrorKind::InvalidData)); }
        let mut request = [0u8;28];
        request[..8].copy_from_slice(&endpoint.to_be_bytes());
        request[8] = if target.is_ipv4() { 4 } else { 6 };
        request[10..12].copy_from_slice(&target.port().to_be_bytes());
        match target.ip() {
            std::net::IpAddr::V4(ip) => request[12..16].copy_from_slice(&ip.octets()),
            std::net::IpAddr::V6(ip) => request[12..28].copy_from_slice(&ip.octets()),
        }
        ioctl(&self.handle, AUTHORIZE_ENDPOINT, &request)
    }

    pub(super) fn udp_context(&self, context: &[u8], peer: SocketAddr, local: SocketAddr) -> io::Result<FlowKey> {
        if local.port() != self.port { return Err(io::ErrorKind::PermissionDenied.into()); }
        let key = wfp_context::decode_transport(context, &self.token, peer, local, super::packet::Transport::Udp)
            .ok_or(io::ErrorKind::PermissionDenied)?;
        if key.interface != self.compartment { return Err(io::ErrorKind::PermissionDenied.into()); }
        Ok(key)
    }

    pub(crate) fn original_tcp(&self, stream: &TcpStream) -> io::Result<FlowKey> {
        if stream.local_addr()?.port() != self.port { return Err(io::Error::from(io::ErrorKind::PermissionDenied)); }
        let key = original_tcp(stream, &self.token)?;
        if key.interface != self.compartment { return Err(io::Error::from(io::ErrorKind::PermissionDenied)); }
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
    wfp_context::decode(&context[..len], token, stream.peer_addr()?, stream.local_addr()?)
        .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))
}


impl super::carrier_socket::Registrar for WfpLabSession {
    fn tcp(&self, socket: &tokio::net::TcpSocket, peer: SocketAddr) -> io::Result<super::carrier_socket::Lease> {
        self.authorize_tcp_carrier(socket, peer)?;
        Ok(super::carrier_socket::Lease::default())
    }
    fn udp(&self, _: &tokio::net::UdpSocket, _: SocketAddr) -> io::Result<super::carrier_socket::Lease> {
        // No Windows UDP carrier exemption is proven yet. A local
        // policy failure must not look like network unreachability.
        Err(io::ErrorKind::PermissionDenied.into())
    }
}
