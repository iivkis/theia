//! Small OS boundary for native QUIC. The protocol core stays safe Rust.
//! On unsupported platforms do not claim DF/ECN support. No global settings.
use crate::quic_core::ecn::Mark;
use std::{io, net::SocketAddr};
use tokio::net::UdpSocket;

#[derive(Clone, Copy, Default)]
pub(crate) struct Options {
    pub(crate) df: bool,
    pub(crate) ecn: bool,
    pub(crate) pktinfo: bool,
    #[cfg(target_os = "windows")]
    recvmsg: windows_sys::Win32::Networking::WinSock::LPFN_WSARECVMSG,
}

impl Options {
    pub(crate) fn configure(socket: &UdpSocket) -> Self {
        #[cfg(target_os = "linux")]
        {
            linux::configure(socket)
        }
        #[cfg(target_os = "windows")]
        {
            windows::configure(socket)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = socket;
            Self::default()
        }
    }

    pub(crate) async fn receive(
        self,
        socket: &UdpSocket,
        out: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Mark)> {
        let (n, peer, _, mark) = self.receive_to(socket, out).await?;
        Ok((n, peer, mark))
    }

    /// Preserve the actual destination on wildcard sockets. Missing
    /// ancillary metadata must never be replaced with a guessed route.
    pub(crate) async fn receive_to(
        self,
        socket: &UdpSocket,
        out: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, SocketAddr, Mark)> {
        let bound = socket.local_addr()?;
        #[cfg(target_os = "linux")]
        if self.ecn || self.pktinfo {
            let (n, peer, destination, mark) = linux::receive(socket, out).await?;
            return Ok((n, peer, local_destination(bound, destination)?, mark));
        }
        #[cfg(target_os = "windows")]
        if self.recvmsg.is_some() {
            let (n, peer, destination, mark) = windows::receive(socket, self.recvmsg, out).await?;
            return Ok((n, peer, local_destination(bound, destination)?, mark));
        }
        let _ = self;
        if bound.ip().is_unspecified() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let (n, peer) = socket.recv_from(out).await?;
        Ok((n, peer, bound, Mark::NotEct))
    }

    pub(crate) async fn send(
        self,
        socket: &UdpSocket,
        data: &[u8],
        peer: SocketAddr,
        ect: bool,
    ) -> io::Result<(usize, Mark)> {
        self.send_from(socket, data, peer, socket.local_addr()?, ect).await
    }

    pub(crate) async fn send_from(
        self,
        socket: &UdpSocket,
        data: &[u8],
        peer: SocketAddr,
        local: SocketAddr,
        ect: bool,
    ) -> io::Result<(usize, Mark)> {
        let bound = socket.local_addr()?;
        let source = if bound.ip().is_unspecified() {
            if !self.pktinfo || local.ip().is_unspecified() || local.port() != bound.port()
                || local.is_ipv4() != bound.is_ipv4() || local.is_ipv4() != peer.is_ipv4() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            Some(local.ip())
        } else {
            if bound != local {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            None
        };
        let ect = ect && self.ecn;
        #[cfg(target_os = "linux")]
        if ect || source.is_some() {
            match linux::send(socket, data, peer, source, ect).await {
                Ok(n) => return Ok((n, if ect { Mark::Ect0 } else { Mark::NotEct })),
                Err(e) if ect && matches!(e.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOPROTOOPT | libc::EOPNOTSUPP)) => {
                    if source.is_some() {
                        return linux::send(socket, data, peer, source, false).await.map(|n| (n, Mark::NotEct));
                    }
                }
                Err(e) => return Err(e),
            }
        }
        #[cfg(target_os = "windows")]
        if ect || source.is_some() {
            match windows::send(socket, data, peer, source, ect).await {
                Ok(n) => return Ok((n, if ect { Mark::Ect0 } else { Mark::NotEct })),
                Err(e) if ect && matches!(e.raw_os_error(), Some(10022 | 10042 | 10045)) => {
                    if source.is_some() {
                        return windows::send(socket, data, peer, source, false).await.map(|n| (n, Mark::NotEct));
                    }
                }
                Err(e) => return Err(e),
            }
        }
        let _ = (self, ect);
        if source.is_some() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        Ok((socket.send_to(data, peer).await?, Mark::NotEct))
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn local_destination(bound: SocketAddr, destination: Option<std::net::IpAddr>) -> io::Result<SocketAddr> {
    if !bound.ip().is_unspecified() {
        return Ok(bound);
    }
    let ip = destination.ok_or(io::ErrorKind::InvalidData)?;
    if ip.is_unspecified() || ip.is_multicast() || ip.is_ipv4() != bound.is_ipv4() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(SocketAddr::new(ip, bound.port()))

}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        mem::{self, size_of},
        net::{Ipv4Addr, Ipv6Addr, SocketAddrV6},
        os::fd::AsRawFd,
        ptr,
    };
    use tokio::io::Interest;

    fn set(
        socket: &UdpSocket,
        level: libc::c_int,
        option: libc::c_int,
        value: libc::c_int,
    ) -> bool {
        // SAFETY: fd is borrowed from a live socket, value points to an
        // initialized integer of the exact size expected by these options.
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&value as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            ) == 0
        }
    }

    pub(super) fn configure(socket: &UdpSocket) -> Options {
        let Ok(local) = socket.local_addr() else {
            return Options::default();
        };
        if local.is_ipv4() {
            Options {
                df: set(
                    socket,
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    libc::IP_PMTUDISC_DO,
                ),
                ecn: set(socket, libc::IPPROTO_IP, libc::IP_RECVTOS, 1),
                pktinfo: set(socket, libc::IPPROTO_IP, libc::IP_PKTINFO, 1),
            }
        } else {
            Options {
                df: set(
                    socket,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    libc::IP_PMTUDISC_DO,
                ),
                ecn: set(socket, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, 1),
                pktinfo: set(socket, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1),
            }
        }
    }

    fn mark(bits: u8) -> Mark {
        match bits & 3 {
            1 => Mark::Ect1,
            2 => Mark::Ect0,
            3 => Mark::Ce,
            _ => Mark::NotEct,
        }
    }

    fn receive_now(socket: &UdpSocket, out: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<std::net::IpAddr>, Mark)> {
        // SAFETY: zero is a valid initial representation for these C structs.
        // The aligned control buffer, address and iovec remain live for recvmsg.
        let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut control = [0usize; 16];
        let mut iov = libc::iovec {
            iov_base: out.as_mut_ptr().cast(),
            iov_len: out.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = (&mut addr as *mut libc::sockaddr_storage).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of_val(&control);
        let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || n as usize > out.len() {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        let peer = match i32::from(addr.ss_family) {
            libc::AF_INET if msg.msg_namelen as usize >= size_of::<libc::sockaddr_in>() => {
                // SAFETY: kernel returned this family and sufficient length;
                // sockaddr_storage is aligned for both concrete address types.
                let a = unsafe {
                    &*(&addr as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()
                };
                SocketAddr::new(
                    Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()).into(),
                    u16::from_be(a.sin_port),
                )
            }
            libc::AF_INET6 if msg.msg_namelen as usize >= size_of::<libc::sockaddr_in6>() => {
                let a = unsafe {
                    &*(&addr as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
                };
                SocketAddrV6::new(
                    Ipv6Addr::from(a.sin6_addr.s6_addr),
                    u16::from_be(a.sin6_port),
                    u32::from_be(a.sin6_flowinfo),
                    a.sin6_scope_id,
                )
                .into()
            }
            _ => return Err(io::Error::from(io::ErrorKind::InvalidData)),
        };
        let mut ecn = Mark::NotEct;
        let mut destination = None;
        if msg.msg_controllen > mem::size_of_val(&control) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // SAFETY: the kernel filled the aligned ancillary buffer. Validate
        // each header length and remaining extent before reading its data.
        unsafe {
            let begin = control.as_ptr() as usize;
            let end = begin + msg.msg_controllen;
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                let start = c as usize;
                if start < begin || start.saturating_add(size_of::<libc::cmsghdr>()) > end {
                    break;
                }
                let header = &*c;
                let minimum = libc::CMSG_LEN(0) as usize;
                if header.cmsg_len < minimum || start.saturating_add(header.cmsg_len) > end {
                    break;
                }
                let data = libc::CMSG_DATA(c);
                if header.cmsg_level == libc::IPPROTO_IP
                    && header.cmsg_type == libc::IP_TOS
                    && header.cmsg_len >= libc::CMSG_LEN(1) as usize
                {
                    ecn = mark(*data);
                } else if header.cmsg_level == libc::IPPROTO_IPV6
                    && header.cmsg_type == libc::IPV6_TCLASS
                    && header.cmsg_len >= libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize
                {
                    ecn = mark(ptr::read_unaligned(data.cast::<libc::c_int>()) as u8);
                }
                if header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == libc::IP_PKTINFO
                    && header.cmsg_len >= libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as u32) as usize {
                    let info = ptr::read_unaligned(data.cast::<libc::in_pktinfo>());
                    destination = Some(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()).into());
                } else if header.cmsg_level == libc::IPPROTO_IPV6 && header.cmsg_type == libc::IPV6_PKTINFO
                    && header.cmsg_len >= libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as u32) as usize {
                    let info = ptr::read_unaligned(data.cast::<libc::in6_pktinfo>());
                    destination = Some(Ipv6Addr::from(info.ipi6_addr.s6_addr).into());
                }
                let next = libc::CMSG_NXTHDR(&msg, c);
                if !next.is_null() && next as usize <= start {
                    break;
                }
                c = next;
            }
        }
        Ok((n as usize, peer, destination, ecn))
    }

    pub(super) async fn receive(
        socket: &UdpSocket,
        out: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<std::net::IpAddr>, Mark)> {
        loop {
            socket.readable().await?;
            match socket.try_io(Interest::READABLE, || receive_now(socket, out)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }

    fn send_now(socket: &UdpSocket, data: &[u8], peer: SocketAddr, source: Option<std::net::IpAddr>, ect: bool) -> io::Result<usize> {
        let mut v4: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut v6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        let (addr, len, level, kind) = match peer {
            SocketAddr::V4(a) => {
                v4.sin_family = libc::AF_INET as libc::sa_family_t;
                v4.sin_port = a.port().to_be();
                v4.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
                (
                    (&mut v4 as *mut libc::sockaddr_in).cast::<libc::c_void>(),
                    size_of::<libc::sockaddr_in>(),
                    libc::IPPROTO_IP,
                    libc::IP_TOS,
                )
            }
            SocketAddr::V6(a) => {
                v6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                v6.sin6_port = a.port().to_be();
                v6.sin6_addr.s6_addr = a.ip().octets();
                v6.sin6_scope_id = a.scope_id();
                v6.sin6_flowinfo = a.flowinfo().to_be();
                (
                    (&mut v6 as *mut libc::sockaddr_in6).cast::<libc::c_void>(),
                    size_of::<libc::sockaddr_in6>(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_TCLASS,
                )
            }
        };
        let mut control = [0usize; 16];
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = addr;
        msg.msg_namelen = len as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        // SAFETY: one aligned, bounded integer cmsg, all sendmsg buffers
        // remain alive; the syscall only reads the payload and address.
        unsafe {
            let mut used = 0usize;
            // Each CMSG_SPACE includes alignment for the next header.
            let mut append = |level, kind, value: *const u8, len: usize| {
                let space = libc::CMSG_SPACE(len as u32) as usize;
                if used + space > mem::size_of_val(&control) {
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                }
                let c = control.as_mut_ptr().cast::<u8>().add(used).cast::<libc::cmsghdr>();
                (*c).cmsg_len = libc::CMSG_LEN(len as u32) as usize;
                (*c).cmsg_level = level;
                (*c).cmsg_type = kind;
                ptr::copy_nonoverlapping(value, libc::CMSG_DATA(c), len);
                used += space;
                Ok(())
            };
            match source {
                Some(std::net::IpAddr::V4(ip)) => {
                    let mut info: libc::in_pktinfo = mem::zeroed();
                    info.ipi_spec_dst.s_addr = u32::from_ne_bytes(ip.octets());
                    append(libc::IPPROTO_IP, libc::IP_PKTINFO, (&info as *const libc::in_pktinfo).cast(), size_of::<libc::in_pktinfo>())?;
                }
                Some(std::net::IpAddr::V6(ip)) => {
                    let mut info: libc::in6_pktinfo = mem::zeroed();
                    info.ipi6_addr.s6_addr = ip.octets();
                    append(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, (&info as *const libc::in6_pktinfo).cast(), size_of::<libc::in6_pktinfo>())?;
                }
                None => {}
            }
            if ect {
                let value = 2 as libc::c_int;
                append(level, kind, (&value as *const libc::c_int).cast(), size_of::<libc::c_int>())?;
            }
            msg.msg_controllen = used;
            let n = libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_DONTWAIT);
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    pub(super) async fn send(
        socket: &UdpSocket,
        data: &[u8],
        peer: SocketAddr,
        source: Option<std::net::IpAddr>,
        ect: bool,
    ) -> io::Result<usize> {
        loop {
            socket.writable().await?;
            match socket.try_io(Interest::WRITABLE, || send_now(socket, data, peer, source, ect)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::{
        mem::{size_of, size_of_val},
        net::{Ipv4Addr, Ipv6Addr, SocketAddrV6},
        os::windows::io::AsRawSocket,
        ptr,
    };
    use tokio::io::Interest;
    use windows_sys::Win32::Networking::WinSock::{
        getsockopt, setsockopt, WSAGetLastError, WSAIoctl, WSASendMsg, AF_INET, AF_INET6,
        IPPROTO_IP, IPPROTO_IPV6, IPV6_ECN, IPV6_MTU_DISCOVER, IPV6_RECVECN, IP_ECN,
        IP_MTU_DISCOVER, IP_PMTUDISC_DO, IP_RECVECN, LPFN_WSARECVMSG, IP_PKTINFO, IPV6_PKTINFO,
        SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKADDR, SOCKET, WSABUF, WSAID_WSARECVMSG, WSAMSG,
    };

    // WSA_CMSG_* are C macros, not exported functions. Align the header
    // and payload to SIZE_T exactly as the Winsock ABI does.
    #[repr(C)]
    struct Header {
        len: usize,
        level: i32,
        kind: i32,
    }
    const fn align(n: usize) -> usize {
        n.div_ceil(size_of::<usize>()) * size_of::<usize>()
    }
    const HEAD: usize = align(size_of::<Header>());

    fn raw(socket: &UdpSocket) -> SOCKET {
        socket.as_raw_socket() as SOCKET
    }

    fn set_verified(socket: &UdpSocket, level: i32, option: i32, value: i32) -> bool {
        let mut readback = 0i32;
        let mut len = size_of::<i32>() as i32;
        // SAFETY: socket is live, both option buffers are exact DWORD sizes.
        unsafe {
            setsockopt(
                raw(socket),
                level,
                option,
                (&value as *const i32).cast(),
                len,
            ) == 0
                && getsockopt(
                    raw(socket),
                    level,
                    option,
                    (&mut readback as *mut i32).cast(),
                    &mut len,
                ) == 0
                && len == size_of::<i32>() as i32
                && value == readback
        }
    }

    pub(super) fn configure(socket: &UdpSocket) -> Options {
        let Ok(local) = socket.local_addr() else {
            return Options::default();
        };
        let (level, mtu, ecn) = if local.is_ipv4() {
            (IPPROTO_IP, IP_MTU_DISCOVER, IP_RECVECN)
        } else {
            (IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_RECVECN)
        };
        let df = set_verified(socket, level, mtu, IP_PMTUDISC_DO);
        let mut recvmsg: LPFN_WSARECVMSG = None;
        let mut written = 0u32;
        // SAFETY: query this socket's provider for the documented function
        // pointer. No overlapped operation is pending after this call.
        let result = unsafe {
            WSAIoctl(
                raw(socket),
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&WSAID_WSARECVMSG as *const windows_sys::core::GUID).cast(),
                size_of_val(&WSAID_WSARECVMSG) as u32,
                (&mut recvmsg as *mut LPFN_WSARECVMSG).cast(),
                size_of::<LPFN_WSARECVMSG>() as u32,
                &mut written,
                ptr::null_mut(),
                None,
            )
        };
        let available = result == 0 && written as usize == size_of::<LPFN_WSARECVMSG>() && recvmsg.is_some();
        let enabled = available && set_verified(socket, level, ecn, 1);
        let pktinfo = available && set_verified(socket, level, if local.is_ipv4() { IP_PKTINFO } else { IPV6_PKTINFO }, 1);
        Options {
            df,
            ecn: enabled,
            pktinfo,
            recvmsg: if enabled || pktinfo { recvmsg } else { None },
        }
    }

    // Aligned storage, initialized before use. Encode only documented
    // SOCKADDR_IN / SOCKADDR_IN6 fields; no pointer escapes a syscall.
    #[repr(C, align(8))]
    struct Address([u8; 128]);

    impl Address {
        fn from_peer(peer: SocketAddr) -> (Self, i32, i32, i32) {
            let mut addr = Self([0; 128]);
            addr.0[2..4].copy_from_slice(&peer.port().to_be_bytes());
            match peer {
                SocketAddr::V4(a) => {
                    addr.0[..2].copy_from_slice(&AF_INET.to_ne_bytes());
                    addr.0[4..8].copy_from_slice(&a.ip().octets());
                    (addr, 16, IPPROTO_IP, IP_ECN)
                }
                SocketAddr::V6(a) => {
                    addr.0[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
                    addr.0[4..8].copy_from_slice(&a.flowinfo().to_be_bytes());
                    addr.0[8..24].copy_from_slice(&a.ip().octets());
                    addr.0[24..28].copy_from_slice(&a.scope_id().to_ne_bytes());
                    (addr, 28, IPPROTO_IPV6, IPV6_ECN)
                }
            }
        }
        fn peer(&self, len: i32) -> io::Result<SocketAddr> {
            let family = u16::from_ne_bytes(self.0[..2].try_into().unwrap());
            let port = u16::from_be_bytes(self.0[2..4].try_into().unwrap());
            match family {
                AF_INET if len >= 16 => Ok(SocketAddr::new(
                    Ipv4Addr::from(<[u8; 4]>::try_from(&self.0[4..8]).unwrap()).into(),
                    port,
                )),
                AF_INET6 if len >= 28 => Ok(SocketAddrV6::new(
                    Ipv6Addr::from(<[u8; 16]>::try_from(&self.0[8..24]).unwrap()),
                    port,
                    u32::from_be_bytes(self.0[4..8].try_into().unwrap()),
                    u32::from_ne_bytes(self.0[24..28].try_into().unwrap()),
                )
                .into()),
                _ => Err(io::ErrorKind::InvalidData.into()),
            }
        }
    }

    fn last_error() -> io::Error {
        // SAFETY: retrieves the thread-local Winsock error immediately.
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    fn decode_control(control: &[usize], length: usize) -> io::Result<(Option<std::net::IpAddr>, Mark)> {
        if length > size_of_val(control) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut offset = 0usize;
        let mut mark = Mark::NotEct;
        let mut destination = None;
        while length.saturating_sub(offset) >= HEAD {
            // SAFETY: offset aligned, length bounded by initialized storage.
            let p = unsafe { control.as_ptr().cast::<u8>().add(offset) };
            let header = unsafe { &*p.cast::<Header>() };
            if header.len < HEAD || header.len > length - offset {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if ((header.level == IPPROTO_IP && header.kind == IP_ECN)
                || (header.level == IPPROTO_IPV6 && header.kind == IPV6_ECN))
                && header.len >= HEAD + size_of::<i32>()
            {
                // SAFETY: checked complete integer inside this header.
                let value = unsafe { ptr::read_unaligned(p.add(HEAD).cast::<i32>()) };
                mark = match value {
                    0 => Mark::NotEct,
                    1 => Mark::Ect1,
                    2 => Mark::Ect0,
                    3 => Mark::Ce,
                    _ => return Err(io::ErrorKind::InvalidData.into()),
                };
            } else if header.level == IPPROTO_IP && header.kind == IP_PKTINFO && header.len >= HEAD + 8 {
                let address = unsafe { ptr::read_unaligned(p.add(HEAD).cast::<[u8; 4]>()) };
                destination = Some(Ipv4Addr::from(address).into());
            } else if header.level == IPPROTO_IPV6 && header.kind == IPV6_PKTINFO && header.len >= HEAD + 20 {
                let address = unsafe { ptr::read_unaligned(p.add(HEAD).cast::<[u8; 16]>()) };
                destination = Some(Ipv6Addr::from(address).into());
            }
            offset += align(header.len);
        }
        Ok((destination, mark))
    }

    fn receive_now(
        socket: &UdpSocket,
        recvmsg: LPFN_WSARECVMSG,
        out: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<std::net::IpAddr>, Mark)> {
        let recvmsg = recvmsg.ok_or(io::ErrorKind::Unsupported)?;
        let mut addr = Address([0; 128]);
        let mut control = [0usize; 16];
        let mut buffer = WSABUF {
            len: out.len() as u32,
            buf: out.as_mut_ptr(),
        };
        let mut msg = WSAMSG {
            name: addr.0.as_mut_ptr().cast::<SOCKADDR>(),
            namelen: addr.0.len() as i32,
            lpBuffers: &mut buffer,
            dwBufferCount: 1,
            Control: WSABUF {
                len: size_of_val(&control) as u32,
                buf: control.as_mut_ptr().cast(),
            },
            dwFlags: 0,
        };
        let mut n = 0;
        // SAFETY: nonblocking socket and initialized live buffers, no overlapped I/O.
        if unsafe { recvmsg(raw(socket), &mut msg, &mut n, ptr::null_mut(), None) } != 0 {
            return Err(last_error());
        }
        // MSG_TRUNC=0x100, MSG_CTRUNC=0x200 in Winsock.
        if msg.dwFlags & 0x300 != 0 || n as usize > out.len() {
            return Err(io::Error::from_raw_os_error(10040));
        }
        let (destination, mark) = decode_control(&control, msg.Control.len as usize)?;
        Ok((n as usize, addr.peer(msg.namelen)?, destination, mark))
    }

    pub(super) async fn receive(
        socket: &UdpSocket,
        recvmsg: LPFN_WSARECVMSG,
        out: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<std::net::IpAddr>, Mark)> {
        loop {
            socket.readable().await?;
            match socket.try_io(Interest::READABLE, || receive_now(socket, recvmsg, out)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }

    fn send_now(socket: &UdpSocket, data: &[u8], peer: SocketAddr, source: Option<std::net::IpAddr>, ect: bool) -> io::Result<usize> {
        let (mut addr, len, level, kind) = Address::from_peer(peer);
        let mut control = [0usize; 16];
        let mut used = 0usize;
        let mut append = |level, kind, bytes: &[u8]| -> io::Result<()> {
            let len = HEAD + bytes.len();
            let space = align(len);
            if used + space > size_of_val(&control) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            // SAFETY: aligned, initialized storage; both extents checked.
            unsafe {
                let p = control.as_mut_ptr().cast::<u8>().add(used);
                ptr::write(p.cast::<Header>(), Header { len, level, kind });
                ptr::copy_nonoverlapping(bytes.as_ptr(), p.add(HEAD), bytes.len());
            }
            used += space;
            Ok(())
        };
        match source {
            Some(std::net::IpAddr::V4(ip)) => {
                let mut info = [0u8; 8];
                info[..4].copy_from_slice(&ip.octets());
                append(IPPROTO_IP, IP_PKTINFO, &info)?;
            }
            Some(std::net::IpAddr::V6(ip)) => {
                let mut info = [0u8; 20];
                info[..16].copy_from_slice(&ip.octets());
                append(IPPROTO_IPV6, IPV6_PKTINFO, &info)?;
            }
            None => {}
        }
        if ect {
            append(level, kind, &2i32.to_ne_bytes())?;
        }
        let mut buffer = WSABUF {
            len: data.len() as u32,
            buf: data.as_ptr().cast_mut(),
        };
        let msg = WSAMSG {
            name: addr.0.as_mut_ptr().cast::<SOCKADDR>(),
            namelen: len,
            lpBuffers: &mut buffer,
            dwBufferCount: 1,
            Control: WSABUF {
                len: used as u32,
                buf: control.as_mut_ptr().cast(),
            },
            dwFlags: 0,
        };
        let mut n = 0;
        // SAFETY: synchronous nonblocking send, all buffers live throughout;
        // Winsock reads the payload. No pending overlapped operation.
        if unsafe { WSASendMsg(raw(socket), &msg, 0, &mut n, ptr::null_mut(), None) } != 0 {
            return Err(last_error());
        }
        Ok(n as usize)
    }

    pub(super) async fn send(
        socket: &UdpSocket,
        data: &[u8],
        peer: SocketAddr,
        source: Option<std::net::IpAddr>,
        ect: bool,
    ) -> io::Result<usize> {
        loop {
            socket.writable().await?;
            match socket.try_io(Interest::WRITABLE, || send_now(socket, data, peer, source, ect)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
mod tests {
    use super::*;
    use std::time::Duration;
    #[tokio::test]
    async fn wildcard_reply_preserves_destination_on_both_families() {
        for (bind, target, client) in [
            #[cfg(target_os = "linux")]
            ("0.0.0.0:0", "127.0.0.2:0", "127.0.0.1:0"),
            #[cfg(target_os = "windows")]
            ("0.0.0.0:0", "127.0.0.1:0", "127.0.0.1:0"),
            ("[::]:0", "[::1]:0", "[::1]:0"),
        ] {
            let server = UdpSocket::bind(bind).await.unwrap();
            let client = UdpSocket::bind(client).await.unwrap();
            let options = Options::configure(&server);
            assert!(options.pktinfo);
            let mut target: SocketAddr = target.parse().unwrap();
            target.set_port(server.local_addr().unwrap().port());
            client.send_to(b"request", target).await.unwrap();
            let mut buffer = [0; 32];
            let (n, peer, local, _) = tokio::time::timeout(Duration::from_secs(2), options.receive_to(&server, &mut buffer)).await.unwrap().unwrap();
            assert_eq!((n, local), (7, target));
            options.send_from(&server, b"reply", peer, local, false).await.unwrap();
            let (n, from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer)).await.unwrap().unwrap();
            assert_eq!((n, from), (5, target));
        }
    }

    #[tokio::test]
    async fn actual_udp_ect_and_notect_on_both_ip_families() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let a = UdpSocket::bind(bind).await.unwrap();
            let b = UdpSocket::bind(bind).await.unwrap();
            let tx = Options::configure(&a);
            let rx = Options::configure(&b);
            assert!(tx.df && rx.df && tx.ecn && rx.ecn);
            for (ect, mark) in [(true, Mark::Ect0), (false, Mark::NotEct)] {
                assert_eq!(
                    tx.send(&a, b"test", b.local_addr().unwrap(), ect)
                        .await
                        .unwrap(),
                    (4, mark)
                );
                let mut out = [0; 8];
                let (n, peer, observed) =
                    tokio::time::timeout(Duration::from_secs(2), rx.receive(&b, &mut out))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!((n, peer, observed), (4, a.local_addr().unwrap(), mark));
                assert_eq!(&out[..n], b"test");
            }
        }
    }
}
