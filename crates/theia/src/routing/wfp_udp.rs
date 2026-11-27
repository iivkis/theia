//! Windows UDP ancillary-data receive adapter, first redirected datagram
//! only. The driver deliberately still blocks UDP: a tested reverse
//! transport injection path and connected-UDP handling are prerequisites.
//! No ordinary UDP packet, client header or guessed tuple is admitted.
use super::{packet::FlowKey, wfp_ingress::WfpLabSession};
use std::{io, mem, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, os::windows::io::AsRawSocket, ptr, sync::Arc};
use tokio::net::UdpSocket;
use windows_sys::Win32::Networking::WinSock::*;

const MAX_CONTROL: usize = 8192;
const MAX_RECORDS: usize = 4096;
fn invalid() -> io::Error { io::ErrorKind::InvalidData.into() }
fn denied() -> io::Error { io::ErrorKind::PermissionDenied.into() }
fn error() -> io::Error { io::Error::from_raw_os_error(unsafe { WSAGetLastError() }) }
fn aligned(n: usize) -> Option<usize> {
    let a = mem::size_of::<usize>();
    n.checked_add(a-1).map(|n| n & !(a-1))
}
fn address(data: &[u8]) -> io::Result<SocketAddr> {
    if data.len() < 4 { return Err(invalid()); }
    let family = u16::from_ne_bytes(data[..2].try_into().map_err(|_| invalid())?);
    let port = u16::from_be_bytes(data[2..4].try_into().map_err(|_| invalid())?);
    let ip = match family {
        AF_INET if data.len() == 16 => IpAddr::V4(Ipv4Addr::from(<[u8;4]>::try_from(&data[4..8]).map_err(|_| invalid())?)),
        AF_INET6 if data.len() == 28 && data[24..28] == [0;4] => {
            let ip = Ipv6Addr::from(<[u8;16]>::try_from(&data[8..24]).map_err(|_| invalid())?);
            if ip.to_ipv4_mapped().is_some() || ip.is_unicast_link_local() { return Err(denied()); }
            IpAddr::V6(ip)
        }
        _ => return Err(invalid()),
    };
    if port == 0 || ip.is_unspecified() || ip.is_multicast() { return Err(denied()); }
    Ok(SocketAddr::new(ip, port))
}
fn controls(mut data: &[u8], ipv4: bool) -> io::Result<(&[u8], &[u8])> {
    let header = aligned(mem::size_of::<WSACMSGHDR>()).ok_or_else(invalid)?;
    let (level, records, context) = if ipv4 {
        (IPPROTO_IP as i32, IP_WFP_REDIRECT_RECORDS as i32, IP_WFP_REDIRECT_CONTEXT as i32)
    } else {
        (IPPROTO_IPV6 as i32, IPV6_WFP_REDIRECT_RECORDS as i32, IPV6_WFP_REDIRECT_CONTEXT as i32)
    };
    let (mut r, mut c) = (None,None);
    while !data.is_empty() {
        if data.len() < header { return Err(invalid()); }
        let h = unsafe { ptr::read_unaligned(data.as_ptr().cast::<WSACMSGHDR>()) };
        let len = h.cmsg_len;
        if len < header || len > data.len() { return Err(invalid()); }
        let value = &data[header..len];
        if h.cmsg_level == level && h.cmsg_type == records {
            if r.is_some() || value.is_empty() || value.len() > MAX_RECORDS { return Err(invalid()); }
            r = Some(value);
        } else if h.cmsg_level == level && h.cmsg_type == context {
            if c.is_some() || value.len() != super::wfp_context::SIZE { return Err(invalid()); }
            c = Some(value);
        }
        let next = aligned(len).ok_or_else(invalid)?;
        if len == data.len() { break; }
        if next > data.len() { return Err(invalid()); }
        data = &data[next..];
    }
    Ok((r.ok_or_else(denied)?,c.ok_or_else(denied)?))
}
fn recv_extension(socket: &UdpSocket) -> io::Result<LPFN_WSARECVMSG> {
    let mut callback: LPFN_WSARECVMSG = None;
    let mut count = 0;
    let guid = WSAID_WSARECVMSG;
    let rc = unsafe {
        WSAIoctl(socket.as_raw_socket() as usize, SIO_GET_EXTENSION_FUNCTION_POINTER,
            (&guid as *const windows_sys::core::GUID).cast(), mem::size_of_val(&guid) as u32,
            (&mut callback as *mut LPFN_WSARECVMSG).cast(), mem::size_of_val(&callback) as u32,
            &mut count, ptr::null_mut(), None)
    };
    if rc != 0 { return Err(error()); }
    if count as usize != mem::size_of_val(&callback) || callback.is_none() { return Err(invalid()); }
    Ok(callback)
}

/// An exact first packet with the driver's private context. Redirect record
/// remains opaque and is never copied onto an unrelated multiplexed carrier.
pub struct FirstDatagram {
    key: FlowKey,
    payload: Vec<u8>,
    records: Vec<u8>,
}
impl FirstDatagram {
    pub fn key(&self) -> FlowKey { self.key }
    pub fn payload(&self) -> &[u8] { &self.payload }
    pub fn redirect_records(&self) -> &[u8] { &self.records }
}
pub struct WfpUdpCapture {
    socket: UdpSocket,
    session: Arc<WfpLabSession>,
    receive: LPFN_WSARECVMSG,
}
impl WfpUdpCapture {
    pub fn from_bound_socket(socket: UdpSocket, session: Arc<WfpLabSession>) -> io::Result<Self> {
        let receive = recv_extension(&socket)?;
        Ok(Self { socket, session, receive })
    }
    pub async fn receive_first(&self) -> io::Result<FirstDatagram> {
        loop {
            self.socket.readable().await?;
            match self.socket.try_io(tokio::io::Interest::READABLE, || self.receive_one()) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }
    fn receive_one(&self) -> io::Result<FirstDatagram> {
        let mut payload = vec![0u8; crate::protocol::MAX_DATAGRAM+1];
        let mut control = [0usize; MAX_CONTROL/mem::size_of::<usize>()];
        let mut peer: SOCKADDR_STORAGE = unsafe { mem::zeroed() };
        let mut buffer = WSABUF { len: payload.len() as u32, buf: payload.as_mut_ptr() };
        let mut message = WSAMSG {
            name: (&mut peer as *mut SOCKADDR_STORAGE).cast(),
            namelen: mem::size_of_val(&peer) as i32,
            lpBuffers: &mut buffer, dwBufferCount: 1,
            Control: WSABUF { len: MAX_CONTROL as u32, buf: control.as_mut_ptr().cast() },
            dwFlags: 0,
        };
        let mut read = 0;
        let receive = self.receive.ok_or_else(invalid)?;
        let rc = unsafe { receive(self.socket.as_raw_socket() as usize, &mut message, &mut read, ptr::null_mut(), None) };
        if rc != 0 { return Err(error()); }
        if message.dwFlags & (MSG_TRUNC as u32 | MSG_CTRUNC as u32) != 0
            || read as usize > crate::protocol::MAX_DATAGRAM || message.namelen < 0
            || message.namelen as usize > mem::size_of_val(&peer) || message.Control.len as usize > MAX_CONTROL { return Err(invalid()); }
        let peer = address(unsafe { std::slice::from_raw_parts((&peer as *const SOCKADDR_STORAGE).cast::<u8>(), message.namelen as usize) })?;
        let local = self.socket.local_addr()?;
        if local.is_ipv4() != peer.is_ipv4() { return Err(denied()); }
        let (records, context) = controls(unsafe { std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), message.Control.len as usize) }, peer.is_ipv4())?;
        let key = self.session.udp_context(context, peer, local)?;
        payload.truncate(read as usize);
        Ok(FirstDatagram { key, payload, records: records.to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_or_truncated_control_never_authorizes_udp() {
        assert!(controls(&[], true).is_err());
        assert!(controls(&[0;3], false).is_err());
        assert!(address(&[0;16]).is_err());
    }

    fn control(kind: i32, data: &[u8]) -> Vec<u8> {
        let header = aligned(mem::size_of::<WSACMSGHDR>()).unwrap();
        let size = header + data.len();
        let mut bytes = vec![0u8; aligned(size).unwrap()];
        let h = WSACMSGHDR { cmsg_len: size, cmsg_level: IPPROTO_IP as i32, cmsg_type: kind };
        unsafe { ptr::write_unaligned(bytes.as_mut_ptr().cast::<WSACMSGHDR>(), h); }
        bytes[header..size].copy_from_slice(data);
        bytes
    }

    #[test]
    fn exact_ancillary_pair_rejects_duplicate_wrong_family_and_trailing_fragment() {
        let records = control(IP_WFP_REDIRECT_RECORDS as i32, &[1, 2, 3]);
        let context = control(IP_WFP_REDIRECT_CONTEXT as i32, &[0; super::super::wfp_context::SIZE]);
        let valid = [records.as_slice(), context.as_slice()].concat();
        assert_eq!(controls(&valid, true).unwrap().0, &[1, 2, 3]);
        assert!(controls(&valid, false).is_err());
        assert!(controls(&[valid.as_slice(), records.as_slice()].concat(), true).is_err());
        assert!(controls(&[valid.as_slice(), &[1]].concat(), true).is_err());
        let header = aligned(mem::size_of::<WSACMSGHDR>()).unwrap();
        let truncated = [context.as_slice(), &records[..header + 4]].concat();
        assert!(controls(&truncated, true).is_err());
    }
}
