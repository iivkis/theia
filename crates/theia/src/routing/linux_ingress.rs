//! Kernel-supplied original destination for already NAT-redirected TCP.
//! No nftables rules or socket exemptions are installed by this module.
use super::packet::{FlowKey, Transport};
use std::{
    io, mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use tokio::{
    io::unix::AsyncFd,
    net::{TcpListener, TcpStream},
};

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
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                (&mut raw as *mut libc::sockaddr_in).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != mem::size_of::<libc::sockaddr_in>()
            || raw.sin_family != libc::AF_INET as libc::sa_family_t
        {
            return Err(invalid());
        }
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes()),
            u16::from_be(raw.sin_port),
        ))
    } else {
        let mut raw: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        // SAFETY: the initialized storage and length match the kernel ABI.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_IPV6,
                SO_ORIGINAL_DST,
                (&mut raw as *mut libc::sockaddr_in6).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != mem::size_of::<libc::sockaddr_in6>()
            || raw.sin6_family != libc::AF_INET6 as libc::sa_family_t
        {
            return Err(invalid());
        }
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(raw.sin6_addr.s6_addr),
            u16::from_be(raw.sin6_port),
            0,
            raw.sin6_scope_id,
        ))
    };
    validate_redirect(local, source, destination)
}

fn validate_redirect(
    local: SocketAddr,
    source: SocketAddr,
    destination: SocketAddr,
) -> io::Result<FlowKey> {
    if destination == local
        || destination == source
        || destination.port() == 0
        || source.port() == 0
        || local.port() == 0
        || source.ip().is_unspecified()
        || source.ip().is_multicast()
        || local.is_ipv4() != source.is_ipv4()
        || matches!(source, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.ip().is_unicast_link_local() || v6.ip().to_ipv4_mapped().is_some())
        || destination.ip().is_unspecified()
        || destination.ip().is_multicast()
        || destination.ip().is_loopback()
        || matches!(destination, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.ip().is_unicast_link_local() || v6.ip().to_ipv4_mapped().is_some())
        || source.is_ipv4() != destination.is_ipv4()
    {
        return Err(invalid());
    }
    Ok(FlowKey {
        source,
        destination,
        transport: Transport::Tcp,
        interface: 0,
    })
}

/// TCP socket accepted by an owned IP_TRANSPARENT listener. The original
/// destination is its kernel local endpoint, not a user-provided address.
pub(crate) struct TransparentTcp {
    pub(crate) stream: TcpStream,
    pub(crate) key: FlowKey,
}

/// The four ingress listeners are prepared as one resource. Dropping
/// any failed preparation closes every socket; this does not install
/// TPROXY or policy routing and does not authorize the host namespace.
pub struct RedirectListeners {
    pub(crate) tcp4: TcpListener,
    pub(crate) tcp6: TcpListener,
    pub(crate) udp4: UdpCapture,
    pub(crate) udp6: UdpCapture,
    port: u16,
}

impl RedirectListeners {
    /// Bind an isolated, dual-stack transparent ingress before installing
    /// rules. The caller must be on the dedicated namespace worker.
    pub fn bind(host_namespace: &std::fs::File, port: u16) -> io::Result<Self> {
        Self::bind_mode(host_namespace, port, false)
    }
    pub(crate) fn bind_mode(
        host_namespace: &std::fs::File,
        port: u16,
        host_mode: bool,
    ) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        if host_mode {
            super::linux_rules::verify_host_scope(host_namespace)?;
        }
        let host = host_namespace.metadata()?;
        let current = std::fs::metadata("/proc/thread-self/ns/net")?;
        if port == 0
            || (!host_mode && (host.dev(), host.ino()) == (current.dev(), current.ino()))
            || unsafe { libc::ioctl(host_namespace.as_raw_fd(), 0xb703 as _) } != libc::CLONE_NEWNET
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let tcp = |ipv4| -> io::Result<TcpListener> {
            let fd = transparent_bound(ipv4, libc::SOCK_STREAM, port)?;
            if unsafe { libc::listen(fd.as_raw_fd(), 128) } != 0 {
                return Err(io::Error::last_os_error());
            }
            TcpListener::from_std(std::net::TcpListener::from(fd))
        };
        let udp = |ipv4| -> io::Result<UdpCapture> {
            UdpCapture::from_bound_socket(std::net::UdpSocket::from(transparent_bound(
                ipv4,
                libc::SOCK_DGRAM,
                port,
            )?))
        };
        Ok(Self {
            tcp4: tcp(true)?,
            tcp6: tcp(false)?,
            udp4: udp(true)?,
            udp6: udp(false)?,
            port,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

fn transparent_bound(ipv4: bool, kind: libc::c_int, port: u16) -> io::Result<OwnedFd> {
    let family = if ipv4 { libc::AF_INET } else { libc::AF_INET6 };
    let raw = unsafe { libc::socket(family, kind | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let address = if ipv4 {
        set_int(&fd, libc::SOL_IP, 19)?; // IP_TRANSPARENT
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port)
    } else {
        set_int(&fd, libc::SOL_IPV6, libc::IPV6_V6ONLY)?;
        set_int(&fd, libc::SOL_IPV6, 75)?; // IPV6_TRANSPARENT
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)
    };
    bind_reply(&fd, address)?;
    Ok(fd)
}

/// Accept only a TCP endpoint selected by a transparent listener. An
/// ordinary connection to a local service/listener is never interpreted
/// as an original remote destination. The caller must own the rules.
pub(crate) async fn accept_transparent(listener: &TcpListener) -> io::Result<TransparentTcp> {
    let (stream, peer) = listener.accept().await?;
    let local = listener.local_addr()?;
    let target = stream.local_addr()?;
    let (level, opt) = if local.is_ipv4() {
        (libc::SOL_IP, 19)
    } else {
        (libc::SOL_IPV6, 75)
    };
    if stream.peer_addr()? != peer
        || sockopt_int(listener, level, opt)? != 1
        || sockopt_int(&stream, level, opt)? != 1
        || !is_local_ip(peer.ip())?
        || is_local_ip(target.ip())?
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let key = validate_redirect(local, peer, target)?;
    Ok(TransparentTcp { stream, key })
}

/// One datagram and its original destination, as supplied by Linux ancillary
/// data. No domain or application identity is inferred from this tuple.
pub struct CapturedDatagram {
    pub(crate) key: FlowKey,
    pub(crate) payload: Vec<u8>,
}
impl CapturedDatagram {
    pub fn key(&self) -> FlowKey {
        self.key
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Receiver for an already provisioned transparent UDP listener. It does
/// not install policy routing. Reverse-path routing and carrier socket
/// isolation remain the responsibility of the isolated platform owner.
pub struct UdpCapture {
    socket: AsyncFd<std::net::UdpSocket>,
}

const IP_ORIGDSTADDR: libc::c_int = 20;
const IPV6_ORIGDSTADDR: libc::c_int = 74;

fn sockopt_int(
    socket: &impl AsRawFd,
    level: libc::c_int,
    option: libc::c_int,
) -> io::Result<libc::c_int> {
    let mut value = 0;
    let mut len = mem::size_of_val(&value) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != mem::size_of_val(&value) {
        return Err(invalid());
    }
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
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&enabled as *const libc::c_int).cast(),
                mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: AsyncFd::new(socket)?,
        })
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.get_ref().local_addr()
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
    let family = u16::from_ne_bytes(
        bytes
            .get(..2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    );
    match family as libc::c_int {
        libc::AF_INET if bytes.len() == mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: exact checked length; ancillary storage may be unaligned.
            let raw =
                unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::sockaddr_in>()) };
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(raw.sin_port),
            )))
        }
        libc::AF_INET6 if bytes.len() == mem::size_of::<libc::sockaddr_in6>() => {
            let raw =
                unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::sockaddr_in6>()) };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(raw.sin6_addr.s6_addr),
                u16::from_be(raw.sin6_port),
                0,
                raw.sin6_scope_id,
            )))
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
        if bytes.len() < header {
            return Err(invalid());
        }
        let cmsg = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::cmsghdr>()) };
        let len = cmsg.cmsg_len as usize;
        if len < header || len > bytes.len() {
            return Err(invalid());
        }
        let expected = if ipv4 {
            (libc::SOL_IP, IP_ORIGDSTADDR)
        } else {
            (libc::SOL_IPV6, IPV6_ORIGDSTADDR)
        };
        if (cmsg.cmsg_level, cmsg.cmsg_type) == expected {
            if destination.is_some() {
                return Err(invalid());
            }
            let address = read_address(&bytes[header..len])?;
            if address.is_ipv4() != ipv4 {
                return Err(invalid());
            }
            destination = Some(address);
        } else if matches!(
            (cmsg.cmsg_level, cmsg.cmsg_type),
            (libc::SOL_IP, IP_ORIGDSTADDR) | (libc::SOL_IPV6, IPV6_ORIGDSTADDR)
        ) {
            return Err(invalid());
        }
        let aligned = align_cmsg(len).ok_or_else(invalid)?;
        if len == bytes.len() {
            break;
        }
        if aligned > bytes.len() {
            return Err(invalid());
        }
        bytes = &bytes[aligned..];
    }
    destination.ok_or_else(invalid)
}

fn receive_udp(socket: &std::net::UdpSocket) -> io::Result<CapturedDatagram> {
    let mut data = vec![0u8; crate::protocol::MAX_DATAGRAM + 1];
    let mut source: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut control = [0usize; 32];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = (&mut source as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = mem::size_of_val(&source) as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = mem::size_of_val(&control) as _;
    // SAFETY: all output buffers are initialized, live and bounded.
    let read = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || read as usize > crate::protocol::MAX_DATAGRAM
        || msg.msg_namelen as usize > mem::size_of_val(&source)
        || msg.msg_controllen as usize > mem::size_of_val(&control)
    {
        return Err(invalid());
    }
    let source_bytes = unsafe {
        std::slice::from_raw_parts(
            (&source as *const libc::sockaddr_storage).cast::<u8>(),
            msg.msg_namelen as usize,
        )
    };
    let control_bytes = unsafe {
        std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), msg.msg_controllen as usize)
    };
    let source = read_address(source_bytes)?;
    let local = socket.local_addr()?;
    let destination = original_ancillary(control_bytes, local.is_ipv4())?;
    // Ordinary datagrams sent to the listener port cannot become relay
    // requests. Conservatively refuse this port even on a wildcard bind.
    if destination.port() == local.port()
        || !is_local_ip(source.ip())?
        || is_local_ip(destination.ip())?
    {
        return Err(invalid());
    }
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
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_int).cast(),
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn is_local_ip(ip: std::net::IpAddr) -> io::Result<bool> {
    let mut list = std::ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut list) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
    let guard = Addresses(list);
    let mut p = guard.0;
    for _ in 0..4096 {
        if p.is_null() {
            return Ok(false);
        }
        let item = unsafe { &*p };
        if !item.ifa_addr.is_null() {
            let addr = match unsafe { (*item.ifa_addr).sa_family } as libc::c_int {
                libc::AF_INET => {
                    let a = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_in>() };
                    Some(std::net::IpAddr::V4(Ipv4Addr::from(
                        a.sin_addr.s_addr.to_ne_bytes(),
                    )))
                }
                libc::AF_INET6 => {
                    let a = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_in6>() };
                    Some(std::net::IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)))
                }
                _ => None,
            };
            if addr == Some(ip) {
                return Ok(true);
            }
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
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&raw as *const libc::sockaddr_in).cast(),
                    mem::size_of_val(&raw) as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let mut raw: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = v6.port().to_be();
            raw.sin6_addr.s6_addr = v6.ip().octets();
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&raw as *const libc::sockaddr_in6).cast(),
                    mem::size_of_val(&raw) as libc::socklen_t,
                )
            }
        }
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl UdpReply {
    pub(crate) fn open(first: &CapturedDatagram) -> io::Result<Self> {
        let key = first.key;
        if key.transport != Transport::Udp
            || key.source.is_ipv4() != key.destination.is_ipv4()
            || key.source.ip().is_unspecified()
            || key.source.ip().is_multicast()
            || key.source.port() == 0
            || key.destination.port() == 0
            || matches!(key.source, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.ip().is_unicast_link_local() || v6.ip().to_ipv4_mapped().is_some())
            || !is_local_ip(key.source.ip())?
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let family = if key.source.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let raw = unsafe {
            libc::socket(
                family,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
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
        if socket.local_addr()? != key.destination || socket.peer_addr()? != key.source {
            return Err(invalid());
        }
        Ok(Self {
            socket: tokio::net::UdpSocket::from_std(socket)?,
            key,
        })
    }

    pub(crate) fn admit_reply(
        &self,
        registrar: &dyn super::carrier_socket::Registrar,
    ) -> io::Result<super::carrier_socket::Lease> {
        // Only this connected reverse-path socket and original local peer.
        registrar.udp_reply(&self.socket, self.key.source)
    }

    pub(crate) async fn send(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > crate::protocol::MAX_DATAGRAM
            || self.socket.local_addr()? != self.key.destination
            || self.socket.peer_addr()? != self.key.source
        {
            return Err(invalid());
        }
        let n = self.socket.send(bytes).await?;
        if n != bytes.len() {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
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
        let cmsg = libc::cmsghdr {
            cmsg_len: len as _,
            cmsg_level: libc::SOL_IP,
            cmsg_type: IP_ORIGDSTADDR,
        };
        let mut address: libc::sockaddr_in = unsafe { mem::zeroed() };
        address.sin_family = libc::AF_INET as libc::sa_family_t;
        address.sin_port = 53u16.to_be();
        address.sin_addr.s_addr = u32::from_ne_bytes([192, 0, 2, 1]);
        unsafe {
            std::ptr::write_unaligned(bytes.as_mut_ptr().cast::<libc::cmsghdr>(), cmsg);
            std::ptr::write_unaligned(
                bytes.as_mut_ptr().add(header).cast::<libc::sockaddr_in>(),
                address,
            );
        }
        bytes
    }

    /// Exercise the actual journaled guard, policy routing, TPROXY,
    /// carrier exception/revocation and reverse UDP in a disposable
    /// namespace. No manual target-specific nft rules.
    #[test]
    #[ignore = "requires isolated Linux namespace, nftables, iproute2 and CAP_NET_ADMIN"]
    fn kernel_dual_stack_transparent_redirect_and_reply() {
        std::thread::spawn(|| {
            use crate::routing::{
                carrier_socket::Registrar,
                linux_rules::{self, LabRegistrar, LabRules},
            };
            use ring::rand::{SecureRandom, SystemRandom};
            use std::{
                os::unix::fs::DirBuilderExt,
                process::Command,
                sync::{Arc, Mutex},
                time::{Duration, Instant},
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let host = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
            let ip = |args: &[&str]| {
                assert!(
                    Command::new("ip").args(args).status().unwrap().success(),
                    "{args:?}"
                );
            };
            ip(&["link", "set", "lo", "up"]);
            ip(&[
                "link",
                "add",
                "theiatest0",
                "type",
                "veth",
                "peer",
                "name",
                "theiawire0",
            ]);
            ip(&["link", "set", "theiawire0", "address", "02:00:00:00:01:02"]);
            ip(&["link", "set", "theiawire0", "up"]);
            ip(&["link", "set", "theiatest0", "up"]);
            ip(&["addr", "add", "192.0.2.1/24", "dev", "theiatest0"]);
            ip(&[
                "-6",
                "addr",
                "add",
                "2001:db8:1::1/64",
                "dev",
                "theiatest0",
                "nodad",
            ]);
            ip(&[
                "route",
                "add",
                "198.51.100.2/32",
                "dev",
                "theiatest0",
                "src",
                "192.0.2.1",
            ]);
            ip(&[
                "-6",
                "route",
                "add",
                "2001:db8:2::2/128",
                "dev",
                "theiatest0",
                "src",
                "2001:db8:1::1",
            ]);
            ip(&[
                "route",
                "add",
                "203.0.113.2/32",
                "dev",
                "theiatest0",
                "src",
                "192.0.2.1",
            ]);
            ip(&[
                "-6",
                "route",
                "add",
                "2001:db8:3::2/128",
                "dev",
                "theiatest0",
                "src",
                "2001:db8:1::1",
            ]);
            for address in ["198.51.100.2", "203.0.113.2"] {
                ip(&[
                    "neigh",
                    "replace",
                    address,
                    "lladdr",
                    "02:00:00:00:01:02",
                    "nud",
                    "permanent",
                    "dev",
                    "theiatest0",
                ]);
            }

            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let listeners = RedirectListeners::bind(&host, 49001).unwrap();
                let mut nonce = [0u8; 16];
                SystemRandom::new().fill(&mut nonce).unwrap();
                let suffix = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
                let directory = std::env::temp_dir().join(format!("theia-all-redirect-{suffix}"));
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&directory)
                    .unwrap();
                let journal = directory.join("guard.toml");
                let policy_routes =
                    linux_rules::PolicyRoutes::install(&host, &journal, false).unwrap();
                assert!(policy_routes.current().unwrap());
                let rules = Arc::new(Mutex::new(
                    LabRules::install_redirect(&host, &journal, listeners.port()).unwrap(),
                ));
                let registrar = LabRegistrar::new(rules.clone(), host.try_clone().unwrap());
                assert!(rules
                    .lock()
                    .unwrap()
                    .redirect_ready(listeners.port())
                    .unwrap());
                // Independent wire observation on the peer veth. No
                // reliance on send() success or listener silence alone.
                let raw = unsafe {
                    libc::socket(
                        libc::AF_PACKET,
                        libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                        i32::from(0x0800u16.to_be()),
                    )
                };
                assert!(raw >= 0);
                let wire = unsafe { OwnedFd::from_raw_fd(raw) };
                let mut link: libc::sockaddr_ll = unsafe { mem::zeroed() };
                link.sll_family = libc::AF_PACKET as u16;
                link.sll_protocol = 0x0800u16.to_be();
                link.sll_ifindex = unsafe { libc::if_nametoindex(c"theiawire0".as_ptr()) } as i32;
                assert!(link.sll_ifindex > 0);
                assert_eq!(
                    unsafe {
                        libc::bind(
                            wire.as_raw_fd(),
                            (&link as *const libc::sockaddr_ll).cast(),
                            mem::size_of_val(&link) as libc::socklen_t,
                        )
                    },
                    0
                );
                let seen = |sentinel: &[u8], wait: Duration| {
                    let end = Instant::now() + wait;
                    let mut data = [0u8; 65536];
                    loop {
                        let n = unsafe {
                            libc::recv(wire.as_raw_fd(), data.as_mut_ptr().cast(), data.len(), 0)
                        };
                        if n >= 0 {
                            if data[..n as usize]
                                .windows(sentinel.len())
                                .any(|part| part == sentinel)
                            {
                                return true;
                            }
                        } else {
                            assert_eq!(
                                io::Error::last_os_error().kind(),
                                io::ErrorKind::WouldBlock
                            );
                        }
                        if Instant::now() >= end {
                            return false;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                };

                for (tcp, udp, source, target) in [
                    (
                        &listeners.tcp4,
                        &listeners.udp4,
                        "192.0.2.1:0",
                        "198.51.100.2:443",
                    ),
                    (
                        &listeners.tcp4,
                        &listeners.udp4,
                        "192.0.2.1:0",
                        "203.0.113.2:853",
                    ),
                    (
                        &listeners.tcp6,
                        &listeners.udp6,
                        "[2001:db8:1::1]:0",
                        "[2001:db8:2::2]:443",
                    ),
                    (
                        &listeners.tcp6,
                        &listeners.udp6,
                        "[2001:db8:1::1]:0",
                        "[2001:db8:3::2]:853",
                    ),
                ] {
                    let source: SocketAddr = source.parse().unwrap();
                    let target: SocketAddr = target.parse().unwrap();
                    let tcp_client = async {
                        let socket = if source.is_ipv4() {
                            tokio::net::TcpSocket::new_v4().unwrap()
                        } else {
                            tokio::net::TcpSocket::new_v6().unwrap()
                        };
                        socket.bind(source).unwrap();
                        let mut stream = socket.connect(target).await.unwrap();
                        assert_eq!(stream.peer_addr().unwrap(), target);
                        stream.write_all(b"tcp").await.unwrap();
                        let mut reply = [0; 3];
                        stream.read_exact(&mut reply).await.unwrap();
                        assert_eq!(&reply, b"ack");
                    };
                    let tcp_proxy = async {
                        let captured = accept_transparent(tcp).await.unwrap();
                        assert_eq!(captured.key.destination, target);
                        assert_eq!(captured.key.source.ip(), source.ip());
                        let mut stream = captured.stream;
                        let mut bytes = [0; 3];
                        stream.read_exact(&mut bytes).await.unwrap();
                        assert_eq!(&bytes, b"tcp");
                        stream.write_all(b"ack").await.unwrap();
                    };
                    tokio::time::timeout(Duration::from_secs(5), async {
                        tokio::join!(tcp_client, tcp_proxy);
                    })
                    .await
                    .unwrap();

                    let client = tokio::net::UdpSocket::bind(source).await.unwrap();
                    client.connect(target).await.unwrap();
                    client.send(b"udp").await.unwrap();
                    let captured = tokio::time::timeout(Duration::from_secs(5), udp.receive())
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(captured.key().destination, target);
                    assert_eq!(captured.key().source, client.local_addr().unwrap());
                    assert_eq!(captured.payload(), b"udp");
                    let reverse = UdpReply::open(&captured).unwrap();
                    reverse.send(b"ack").await.unwrap();
                    let mut reply = [0; 3];
                    let (n, from) =
                        tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut reply))
                            .await
                            .unwrap()
                            .unwrap();
                    assert_eq!(from, target);
                    assert_eq!(&reply[..n], b"ack");
                }
                let peer: SocketAddr = "198.51.100.2:443".parse().unwrap();
                let carrier = tokio::net::UdpSocket::bind("192.0.2.1:0").await.unwrap();
                let lease = registrar.udp(&carrier, peer).unwrap();
                carrier.connect(peer).await.unwrap();
                carrier.send(b"theia-carrier-positive").await.unwrap();
                assert!(seen(b"theia-carrier-positive", Duration::from_secs(2)));
                let competitor = tokio::net::UdpSocket::bind("192.0.2.1:0").await.unwrap();
                competitor.connect(peer).await.unwrap();
                competitor.send(b"theia-ordinary-negative").await.unwrap();
                let captured =
                    tokio::time::timeout(Duration::from_secs(2), listeners.udp4.receive())
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(captured.payload(), b"theia-ordinary-negative");
                assert!(!seen(
                    b"theia-ordinary-negative",
                    Duration::from_millis(150)
                ));
                drop(lease);
                carrier.send(b"theia-revoked-negative").await.unwrap();
                let captured =
                    tokio::time::timeout(Duration::from_secs(2), listeners.udp4.receive())
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(captured.key().source, carrier.local_addr().unwrap());
                assert_eq!(captured.payload(), b"theia-revoked-negative");
                assert!(!seen(b"theia-revoked-negative", Duration::from_millis(150)));
                assert!(registrar.udp(&carrier, peer).is_err());
                // Listener death does not restore direct egress.
                drop(listeners);
                let _ = competitor.send(b"theia-no-listener-negative").await;
                assert!(!seen(
                    b"theia-no-listener-negative",
                    Duration::from_millis(150)
                ));
                // Even if the marked local route disappears, the actual
                // physical postrouting guard must reject the reroute.
                ip(&[
                    "rule", "del", "priority", "21577", "fwmark", "0x5449", "lookup", "21577",
                ]);
                assert!(!policy_routes.current().unwrap());
                assert!(!rules.lock().unwrap().redirect_ready(49001).unwrap());
                let _ = competitor.send(b"theia-no-route-negative").await;
                assert!(!seen(
                    b"theia-no-route-negative",
                    Duration::from_millis(150)
                ));
                registrar.retire().unwrap();
                assert!(rules.lock().unwrap().current().unwrap());
                drop(registrar);
                drop(rules);
                let _ = competitor.send(b"theia-no-owner-negative").await;
                assert!(!seen(
                    b"theia-no-owner-negative",
                    Duration::from_millis(150)
                ));
                drop(policy_routes);
                linux_rules::recover(&host, &journal).unwrap();
                // Positive control proves the same wire and route can
                // actually emit the packet after explicit owned recovery.
                let positive = tokio::net::UdpSocket::bind("192.0.2.1:0").await.unwrap();
                positive.connect(peer).await.unwrap();
                positive.send(b"theia-restored-positive").await.unwrap();
                assert!(seen(b"theia-restored-positive", Duration::from_secs(2)));
                std::fs::remove_dir_all(directory).unwrap();
            });
        })
        .join()
        .unwrap();
    }

    #[test]
    fn local_peer_address_is_checked_against_kernel_interfaces() {
        assert!(is_local_ip("127.0.0.1".parse().unwrap()).unwrap());
        assert!(!is_local_ip("0.0.0.0".parse().unwrap()).unwrap());
    }

    #[tokio::test]
    async fn ordinary_loopback_sockets_never_become_transparent_ingress() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let socket = std::net::UdpSocket::bind(address).unwrap();
            let local = socket.local_addr().unwrap();
            let peer = std::net::UdpSocket::bind(address).unwrap();
            // The real socket is not transparent. Do not grant capture or
            // turn an ordinary datagram into a redirected original flow.
            assert!(UdpCapture::from_bound_socket(socket.try_clone().unwrap()).is_err());
            assert!(matches!(receive_udp(&socket), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
            peer.send_to(b"ordinary", local).unwrap();
            // Use a bounded readiness wait instead of a scheduling assumption.
            socket.set_nonblocking(true).unwrap();
            let socket = tokio::io::unix::AsyncFd::new(socket).unwrap();
            let mut ready = tokio::time::timeout(std::time::Duration::from_secs(2), socket.readable()).await.unwrap().unwrap();
            assert!(matches!(ready.try_io(|inner| receive_udp(inner.get_ref())), Ok(Err(_))));
            let listener = TcpListener::bind(address).await.unwrap();
            let peer = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            let (accepted, _) = listener.accept().await.unwrap();
            assert!(original_tcp(&accepted).is_err());
            drop(peer);
        }
    }

    #[test]
    fn ipv6_original_destination_control_message_is_bounded_and_exact() {
        let header = align_cmsg(mem::size_of::<libc::cmsghdr>()).unwrap();
        let size = mem::size_of::<libc::sockaddr_in6>();
        let len = header + size;
        let mut bytes = vec![0u8; align_cmsg(len).unwrap()];
        let cmsg = libc::cmsghdr {
            cmsg_len: len as _,
            cmsg_level: libc::SOL_IPV6,
            cmsg_type: IPV6_ORIGDSTADDR,
        };
        let mut address: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        address.sin6_port = 443u16.to_be();
        address.sin6_addr.s6_addr = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        unsafe {
            std::ptr::write_unaligned(bytes.as_mut_ptr().cast::<libc::cmsghdr>(), cmsg);
            std::ptr::write_unaligned(bytes.as_mut_ptr().add(header).cast::<libc::sockaddr_in6>(), address);
        }
        let target = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(original_ancillary(&bytes, false).unwrap(), target);
        assert!(original_ancillary(&bytes, true).is_err());
        assert!(original_ancillary(&bytes[..len - 1], false).is_err());
        assert!(read_address(&[0]).is_err());
        assert!(align_cmsg(usize::MAX).is_none());
        let local = "[::1]:10000".parse().unwrap();
        let source = "[::1]:20000".parse().unwrap();
        assert_eq!(validate_redirect(local, source, target).unwrap().destination, target);
        for bad in ["[::]:443", "[ff02::1]:443", "[fe80::1]:443", "[::ffff:192.0.2.1]:443", "[2001:db8::1]:0"] {
            assert!(validate_redirect(local, source, bad.parse().unwrap()).is_err());
        }
    }

    #[test]
    fn original_udp_ancillary_is_exact_and_unambiguous() {
        let bytes = cmsg4();
        assert_eq!(
            original_ancillary(&bytes, true).unwrap(),
            "192.0.2.1:53".parse().unwrap()
        );
        assert!(original_ancillary(&bytes, false).is_err());
        assert!(original_ancillary(&bytes[..mem::size_of::<libc::cmsghdr>()], true).is_err());
        let mut duplicate = bytes.clone();
        duplicate.extend_from_slice(&bytes);
        assert!(original_ancillary(&duplicate, true).is_err());
        assert!(original_ancillary(&[bytes.as_slice(), &[0]].concat(), true).is_err());

        // An unknown final control with an incomplete alignment gap must
        // not turn a malformed receive into a valid original destination.
        let header = align_cmsg(mem::size_of::<libc::cmsghdr>()).unwrap();
        let mut partial = vec![0u8; header + 2];
        let control = libc::cmsghdr {
            cmsg_len: (header + 1) as _,
            cmsg_level: libc::SOL_SOCKET,
            cmsg_type: 0,
        };
        unsafe {
            std::ptr::write_unaligned(partial.as_mut_ptr().cast::<libc::cmsghdr>(), control);
        }
        assert!(original_ancillary(&[bytes.as_slice(), &partial].concat(), true).is_err());
    }

    #[test]
    fn rejects_nonredirected_and_recursive_destinations() {
        let local = "127.0.0.1:10000".parse().unwrap();
        let source = "127.0.0.1:20000".parse().unwrap();
        assert!(validate_redirect(local, source, local).is_err());
        assert!(validate_redirect(local, source, source).is_err());
        assert!(validate_redirect(local, source, "127.0.0.2:443".parse().unwrap()).is_err());
        let target = "198.51.100.4:443".parse().unwrap();
        for bad in [
            "0.0.0.0:20000",
            "224.0.0.1:20000",
            "[::ffff:127.0.0.1]:20000",
        ] {
            assert!(validate_redirect(local, bad.parse().unwrap(), target).is_err());
        }
        assert!(validate_redirect("[::1]:10000".parse().unwrap(), source, target).is_err());
        assert_eq!(
            validate_redirect(local, source, "198.51.100.4:443".parse().unwrap())
                .unwrap()
                .destination,
            "198.51.100.4:443".parse().unwrap()
        );
    }
}
