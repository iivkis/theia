//! Kernel-supplied original destination for already NAT-redirected TCP.
//! No nftables rules or socket exemptions are installed by this module.
use super::packet::{FlowKey, Transport};
use std::{
    io,
    mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use tokio::{io::unix::AsyncFd, net::TcpStream};

const SO_ORIGINAL_DST: libc::c_int = 80;

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

/// Query conntrack on the accepted socket itself. Never trust a client
/// header, local address or an externally supplied original destination.
pub(crate) fn original_tcp(stream: &TcpStream) -> io::Result<FlowKey> {
    let local = stream.local_addr()?;
    let source = stream.peer_addr()?;
    let destination = if local.is_ipv4() {
        let mut raw: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: the initialized storage and length match the kernel ABI.
        let rc = unsafe {
            libc::getsockopt(stream.as_raw_fd(), libc::SOL_IP, SO_ORIGINAL_DST,
                (&mut raw as *mut libc::sockaddr_in).cast(), &mut len)
        };
        if rc != 0 { return Err(io::Error::last_os_error()); }
        if len as usize != mem::size_of::<libc::sockaddr_in>() || raw.sin_family != libc::AF_INET as libc::sa_family_t {
            return Err(invalid());
        }
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes()), u16::from_be(raw.sin_port)))
    } else {
        let mut raw: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        // SAFETY: the initialized storage and length match the kernel ABI.
        let rc = unsafe {
            libc::getsockopt(stream.as_raw_fd(), libc::SOL_IPV6, SO_ORIGINAL_DST,
                (&mut raw as *mut libc::sockaddr_in6).cast(), &mut len)
        };
        if rc != 0 { return Err(io::Error::last_os_error()); }
        if len as usize != mem::size_of::<libc::sockaddr_in6>() || raw.sin6_family != libc::AF_INET6 as libc::sa_family_t {
            return Err(invalid());
        }
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(raw.sin6_addr.s6_addr), u16::from_be(raw.sin6_port), 0, raw.sin6_scope_id))
    };
    validate_redirect(local, source, destination)
}

fn validate_redirect(local: SocketAddr, source: SocketAddr, destination: SocketAddr) -> io::Result<FlowKey> {
    if destination == local || destination == source || destination.port() == 0
        || source.port() == 0 || destination.ip().is_unspecified()
        || destination.ip().is_multicast() || destination.ip().is_loopback()
        || matches!(destination, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.ip().is_unicast_link_local() || v6.ip().to_ipv4_mapped().is_some())
        || source.is_ipv4() != destination.is_ipv4()
    {
        return Err(invalid());
    }
    Ok(FlowKey { source, destination, transport: Transport::Tcp, interface: 0 })
}

/// One datagram and its original destination, as supplied by Linux ancillary
/// data. No domain or application identity is inferred from this tuple.
pub struct CapturedDatagram {
    pub(crate) key: FlowKey,
    pub(crate) payload: Vec<u8>,
}
impl CapturedDatagram {
    pub fn key(&self) -> FlowKey { self.key }
    pub fn payload(&self) -> &[u8] { &self.payload }
}

/// Receiver for an already provisioned transparent UDP listener. It does
/// not install policy routing. Reverse-path routing and carrier socket
/// isolation remain the responsibility of the isolated platform owner.
pub struct UdpCapture {
    socket: AsyncFd<std::net::UdpSocket>,
}

const IP_ORIGDSTADDR: libc::c_int = 20;
const IPV6_ORIGDSTADDR: libc::c_int = 74;

fn sockopt_int(socket: &std::net::UdpSocket, level: libc::c_int, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut value = 0;
    let mut len = mem::size_of_val(&value) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(socket.as_raw_fd(), level, option, (&mut value as *mut libc::c_int).cast(), &mut len)
    };
    if result != 0 { return Err(io::Error::last_os_error()); }
    if len as usize != mem::size_of_val(&value) { return Err(invalid()); }
    Ok(value)
}

impl UdpCapture {
    pub fn from_bound_socket(socket: std::net::UdpSocket) -> io::Result<Self> {
        let local = socket.local_addr()?;
        // Never conflate v4-mapped addresses and native IPv6 ancillary data.
        if local.is_ipv6() && sockopt_int(&socket, libc::SOL_IPV6, libc::IPV6_V6ONLY)? != 1 {
            return Err(invalid());
        }
        let (level, option, transparent) = if local.is_ipv4() {
            (libc::SOL_IP, IP_ORIGDSTADDR, 19) // IP_TRANSPARENT
        } else {
            (libc::SOL_IPV6, IPV6_ORIGDSTADDR, 75) // IPV6_TRANSPARENT
        };
        if sockopt_int(&socket, level, transparent)? != 1 {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let enabled: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(socket.as_raw_fd(), level, option, (&enabled as *const libc::c_int).cast(),
                mem::size_of_val(&enabled) as libc::socklen_t)
        };
        if result != 0 { return Err(io::Error::last_os_error()); }
        socket.set_nonblocking(true)?;
        Ok(Self { socket: AsyncFd::new(socket)? })
    }

    pub async fn receive(&self) -> io::Result<CapturedDatagram> {
        loop {
            let mut ready = self.socket.readable().await?;
            match ready.try_io(|inner| receive_udp(inner.get_ref())) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }
}

fn read_address(bytes: &[u8]) -> io::Result<SocketAddr> {
    let family = u16::from_ne_bytes(bytes.get(..2).ok_or_else(invalid)?.try_into().map_err(|_| invalid())?);
    match family as libc::c_int {
        libc::AF_INET if bytes.len() == mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: exact checked length; ancillary storage may be unaligned.
            let raw = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::sockaddr_in>()) };
            Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes()), u16::from_be(raw.sin_port))))
        }
        libc::AF_INET6 if bytes.len() == mem::size_of::<libc::sockaddr_in6>() => {
            let raw = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::sockaddr_in6>()) };
            Ok(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(raw.sin6_addr.s6_addr), u16::from_be(raw.sin6_port), 0, raw.sin6_scope_id)))
        }
        _ => Err(invalid()),
    }
}

fn align_cmsg(n: usize) -> Option<usize> {
    let a = mem::size_of::<usize>();
    n.checked_add(a - 1).map(|n| n & !(a - 1))
}

fn original_ancillary(mut bytes: &[u8], ipv4: bool) -> io::Result<SocketAddr> {
    let header = align_cmsg(mem::size_of::<libc::cmsghdr>()).ok_or_else(invalid)?;
    let mut destination = None;
    while !bytes.is_empty() {
        if bytes.len() < header { return Err(invalid()); }
        let cmsg = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::cmsghdr>()) };
        let len = cmsg.cmsg_len as usize;
        if len < header || len > bytes.len() { return Err(invalid()); }
        let expected = if ipv4 {
            (libc::SOL_IP, IP_ORIGDSTADDR)
        } else {
            (libc::SOL_IPV6, IPV6_ORIGDSTADDR)
        };
        if (cmsg.cmsg_level, cmsg.cmsg_type) == expected {
            if destination.is_some() { return Err(invalid()); }
            let address = read_address(&bytes[header..len])?;
            if address.is_ipv4() != ipv4 { return Err(invalid()); }
            destination = Some(address);
        } else if matches!((cmsg.cmsg_level, cmsg.cmsg_type), (libc::SOL_IP, IP_ORIGDSTADDR) | (libc::SOL_IPV6, IPV6_ORIGDSTADDR)) {
            return Err(invalid());
        }
        let aligned = align_cmsg(len).ok_or_else(invalid)?;
        if aligned >= bytes.len() { break; }
        bytes = &bytes[aligned..];
    }
    destination.ok_or_else(invalid)
}

fn receive_udp(socket: &std::net::UdpSocket) -> io::Result<CapturedDatagram> {
    let mut data = vec![0u8; crate::protocol::MAX_DATAGRAM + 1];
    let mut source: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut control = [0usize; 32];
    let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: data.len() };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = (&mut source as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = mem::size_of_val(&source) as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = mem::size_of_val(&control) as _;
    // SAFETY: all output buffers are initialized, live and bounded.
    let read = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
    if read < 0 { return Err(io::Error::last_os_error()); }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || read as usize > crate::protocol::MAX_DATAGRAM
        || msg.msg_namelen as usize > mem::size_of_val(&source)
        || msg.msg_controllen as usize > mem::size_of_val(&control) {
        return Err(invalid());
    }
    let source_bytes = unsafe { std::slice::from_raw_parts((&source as *const libc::sockaddr_storage).cast::<u8>(), msg.msg_namelen as usize) };
    let control_bytes = unsafe { std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), msg.msg_controllen as usize) };
    let source = read_address(source_bytes)?;
    let local = socket.local_addr()?;
    let destination = original_ancillary(control_bytes, local.is_ipv4())?;
    // Ordinary datagrams sent to the listener port cannot become relay
    // requests. Conservatively refuse this port even on a wildcard bind.
    if destination.port() == local.port() { return Err(invalid()); }
    let mut key = validate_redirect(local, source, destination)?;
    key.transport = Transport::Udp;
    data.truncate(read as usize);
    Ok(CapturedDatagram { key, payload: data })
}

/// Return path for one kernel-captured UDP flow only. No raw packet
/// injection, wildcard peer, arbitrary send_to or source override.
pub(crate) struct UdpReply {
    socket: tokio::net::UdpSocket,
    key: FlowKey,
}

fn set_int(fd: &OwnedFd, level: libc::c_int, option: libc::c_int) -> io::Result<()> {
    let value: libc::c_int = 1;
    let rc = unsafe { libc::setsockopt(fd.as_raw_fd(), level, option, (&value as *const libc::c_int).cast(), mem::size_of_val(&value) as libc::socklen_t) };
    if rc != 0 { return Err(io::Error::last_os_error()); }
    Ok(())
}

fn is_local_ip(ip: std::net::IpAddr) -> io::Result<bool> {
    let mut list = std::ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut list) };
    if rc != 0 { return Err(io::Error::last_os_error()); }
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) { unsafe { libc::freeifaddrs(self.0); } }
    }
    let guard = Addresses(list);
    let mut p = guard.0;
    for _ in 0..4096 {
        if p.is_null() { return Ok(false); }
        let item = unsafe { &*p };
        if !item.ifa_addr.is_null() {
            let addr = match unsafe { (*item.ifa_addr).sa_family } as libc::c_int {
                libc::AF_INET => {
                    let a = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_in>() };
                    Some(std::net::IpAddr::V4(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes())))
                }
                libc::AF_INET6 => {
                    let a = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_in6>() };
                    Some(std::net::IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)))
                }
                _ => None,
            };
            if addr == Some(ip) { return Ok(true); }
        }
        p = item.ifa_next;
    }
    Err(invalid())
}

fn bind_reply(fd: &OwnedFd, address: SocketAddr) -> io::Result<()> {
    let rc = match address {
        SocketAddr::V4(v4) => {
            let mut raw: libc::sockaddr_in = unsafe { mem::zeroed() };
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = v4.port().to_be();
            raw.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            unsafe { libc::bind(fd.as_raw_fd(), (&raw as *const libc::sockaddr_in).cast(), mem::size_of_val(&raw) as libc::socklen_t) }
        }
        SocketAddr::V6(v6) => {
            let mut raw: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = v6.port().to_be();
            raw.sin6_addr.s6_addr = v6.ip().octets();
            unsafe { libc::bind(fd.as_raw_fd(), (&raw as *const libc::sockaddr_in6).cast(), mem::size_of_val(&raw) as libc::socklen_t) }
        }
    };
    if rc != 0 { return Err(io::Error::last_os_error()); }
    Ok(())
}

impl UdpReply {
    pub(crate) fn open(first: &CapturedDatagram) -> io::Result<Self> {
        let key = first.key;
        if key.transport != Transport::Udp || key.source.is_ipv4() != key.destination.is_ipv4()
            || key.source.ip().is_unspecified() || key.source.ip().is_multicast()
            || key.source.port() == 0 || key.destination.port() == 0
            || matches!(key.source, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.ip().is_unicast_link_local() || v6.ip().to_ipv4_mapped().is_some())
            || !is_local_ip(key.source.ip())? {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let family = if key.source.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        let raw = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 { return Err(io::Error::last_os_error()); }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if key.source.is_ipv4() {
            set_int(&fd, libc::SOL_IP, 19)?; // IP_TRANSPARENT
        } else {
            set_int(&fd, libc::SOL_IPV6, libc::IPV6_V6ONLY)?;
            set_int(&fd, libc::SOL_IPV6, 75)?; // IPV6_TRANSPARENT
        }
        // Do not enable SO_REUSEADDR/SO_REUSEPORT: conflicts are refusal.
        bind_reply(&fd, key.destination)?;
        let socket = std::net::UdpSocket::from(fd);
        socket.connect(key.source)?;
        if socket.local_addr()? != key.destination || socket.peer_addr()? != key.source { return Err(invalid()); }
        Ok(Self { socket: tokio::net::UdpSocket::from_std(socket)?, key })
    }

    pub(crate) fn admit_reply(&self, registrar: &dyn super::carrier_socket::Registrar) -> io::Result<super::carrier_socket::Lease> {
        // Only this connected reverse-path socket and original local peer.
        registrar.udp(&self.socket, self.key.source)
    }

    pub(crate) async fn send(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > crate::protocol::MAX_DATAGRAM || self.socket.local_addr()? != self.key.destination
            || self.socket.peer_addr()? != self.key.source {
            return Err(invalid());
        }
        let n = self.socket.send(bytes).await?;
        if n != bytes.len() { return Err(io::Error::from(io::ErrorKind::WriteZero)); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cmsg4() -> Vec<u8> {
        let header = align_cmsg(mem::size_of::<libc::cmsghdr>()).unwrap();
        let size = mem::size_of::<libc::sockaddr_in>();
        let len = header + size;
        let mut bytes = vec![0u8; align_cmsg(len).unwrap()];
        let cmsg = libc::cmsghdr { cmsg_len: len as _, cmsg_level: libc::SOL_IP, cmsg_type: IP_ORIGDSTADDR };
        let mut address: libc::sockaddr_in = unsafe { mem::zeroed() };
        address.sin_family = libc::AF_INET as libc::sa_family_t;
        address.sin_port = 53u16.to_be();
        address.sin_addr.s_addr = u32::from_ne_bytes([192, 0, 2, 1]);
        unsafe {
            std::ptr::write_unaligned(bytes.as_mut_ptr().cast::<libc::cmsghdr>(), cmsg);
            std::ptr::write_unaligned(bytes.as_mut_ptr().add(header).cast::<libc::sockaddr_in>(), address);
        }
        bytes
    }

    #[test]
    fn local_peer_address_is_checked_against_kernel_interfaces() {
        assert!(is_local_ip("127.0.0.1".parse().unwrap()).unwrap());
        assert!(!is_local_ip("0.0.0.0".parse().unwrap()).unwrap());
    }

    #[test]
    fn original_udp_ancillary_is_exact_and_unambiguous() {
        let bytes = cmsg4();
        assert_eq!(original_ancillary(&bytes, true).unwrap(), "192.0.2.1:53".parse().unwrap());
        assert!(original_ancillary(&bytes, false).is_err());
        assert!(original_ancillary(&bytes[..mem::size_of::<libc::cmsghdr>()], true).is_err());
        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&bytes);
        assert!(original_ancillary(&duplicate, true).is_err());
    }

    #[test]
    fn rejects_nonredirected_and_recursive_destinations() {
        let local = "127.0.0.1:10000".parse().unwrap();
        let source = "127.0.0.1:20000".parse().unwrap();
        assert!(validate_redirect(local, source, local).is_err());
        assert!(validate_redirect(local, source, source).is_err());
        assert!(validate_redirect(local, source, "127.0.0.2:443".parse().unwrap()).is_err());
        assert_eq!(validate_redirect(local, source, "198.51.100.4:443".parse().unwrap()).unwrap().destination, "198.51.100.4:443".parse().unwrap());
    }
}
