//! Small OS boundary for native QUIC. The protocol core stays safe Rust.
//! On unsupported platforms do not claim DF/ECN support. No global settings.
use crate::quic_core::ecn::Mark;
use std::{io, net::SocketAddr};
use tokio::net::UdpSocket;

#[derive(Clone, Copy, Default)]
pub(crate) struct Options {
    pub(crate) df: bool,
    pub(crate) ecn: bool,
}

impl Options {
    pub(crate) fn configure(socket: &UdpSocket) -> Self {
        #[cfg(target_os = "linux")]
        { linux::configure(socket) }
        #[cfg(not(target_os = "linux"))]
        { let _ = socket; Self::default() }
    }

    pub(crate) async fn receive(self, socket: &UdpSocket, out: &mut [u8]) -> io::Result<(usize, SocketAddr, Mark)> {
        #[cfg(target_os = "linux")]
        if self.ecn {
            return linux::receive(socket, out).await;
        }
        let _ = self;
        let (n, peer) = socket.recv_from(out).await?;
        Ok((n, peer, Mark::NotEct))
    }

    pub(crate) async fn send(self, socket: &UdpSocket, data: &[u8], peer: SocketAddr, ect: bool) -> io::Result<(usize, Mark)> {
        #[cfg(target_os = "linux")]
        if self.ecn && ect {
            match linux::send(socket, data, peer).await {
                Ok(n) => return Ok((n, Mark::Ect0)),
                // These errors reject the syscall without transmission.
                // Other failures are not retried as they may be ambiguous.
                Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOPROTOOPT | libc::EOPNOTSUPP)) => {},
                Err(e) => return Err(e),
            }
        }
        let _ = (self, ect);
        Ok((socket.send_to(data, peer).await?, Mark::NotEct))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{mem::{self, size_of}, net::{Ipv4Addr, Ipv6Addr, SocketAddrV6}, os::fd::AsRawFd, ptr};
    use tokio::io::Interest;

    fn set(socket: &UdpSocket, level: libc::c_int, option: libc::c_int, value: libc::c_int) -> bool {
        // SAFETY: fd is borrowed from a live socket, value points to an
        // initialized integer of the exact size expected by these options.
        unsafe { libc::setsockopt(socket.as_raw_fd(), level, option, (&value as *const libc::c_int).cast(), size_of::<libc::c_int>() as libc::socklen_t) == 0 }
    }

    pub(super) fn configure(socket: &UdpSocket) -> Options {
        let Ok(local) = socket.local_addr() else { return Options::default(); };
        if local.is_ipv4() {
            Options {
                df: set(socket, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, libc::IP_PMTUDISC_DO),
                ecn: set(socket, libc::IPPROTO_IP, libc::IP_RECVTOS, 1),
            }
        } else {
            Options {
                df: set(socket, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, libc::IP_PMTUDISC_DO),
                ecn: set(socket, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, 1),
            }
        }
    }

    fn mark(bits: u8) -> Mark {
        match bits & 3 { 1 => Mark::Ect1, 2 => Mark::Ect0, 3 => Mark::Ce, _ => Mark::NotEct }
    }

    fn receive_now(socket: &UdpSocket, out: &mut [u8]) -> io::Result<(usize, SocketAddr, Mark)> {
        // SAFETY: zero is a valid initial representation for these C structs.
        // The aligned control buffer, address and iovec remain live for recvmsg.
        let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut control = [0usize; 16];
        let mut iov = libc::iovec { iov_base: out.as_mut_ptr().cast(), iov_len: out.len() };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = (&mut addr as *mut libc::sockaddr_storage).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of_val(&control);
        let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
        if n < 0 { return Err(io::Error::last_os_error()); }
        if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || n as usize > out.len() {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        let peer = match i32::from(addr.ss_family) {
            libc::AF_INET if msg.msg_namelen as usize >= size_of::<libc::sockaddr_in>() => {
                // SAFETY: kernel returned this family and sufficient length;
                // sockaddr_storage is aligned for both concrete address types.
                let a = unsafe { &*(&addr as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
                SocketAddr::new(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()).into(), u16::from_be(a.sin_port))
            }
            libc::AF_INET6 if msg.msg_namelen as usize >= size_of::<libc::sockaddr_in6>() => {
                let a = unsafe { &*(&addr as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
                SocketAddrV6::new(Ipv6Addr::from(a.sin6_addr.s6_addr), u16::from_be(a.sin6_port), u32::from_be(a.sin6_flowinfo), a.sin6_scope_id).into()
            }
            _ => return Err(io::Error::from(io::ErrorKind::InvalidData)),
        };
        let mut ecn = Mark::NotEct;
        if msg.msg_controllen > mem::size_of_val(&control) { return Err(io::ErrorKind::InvalidData.into()); }
        // SAFETY: the kernel filled the aligned ancillary buffer. Validate
        // each header length and remaining extent before reading its data.
        unsafe {
            let begin = control.as_ptr() as usize;
            let end = begin + msg.msg_controllen;
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                let start = c as usize;
                if start < begin || start.saturating_add(size_of::<libc::cmsghdr>()) > end { break; }
                let header = &*c;
                let minimum = libc::CMSG_LEN(0) as usize;
                if header.cmsg_len < minimum || start.saturating_add(header.cmsg_len) > end { break; }
                let data = libc::CMSG_DATA(c);
                if header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == libc::IP_TOS
                    && header.cmsg_len >= libc::CMSG_LEN(1) as usize {
                    ecn = mark(*data);
                } else if header.cmsg_level == libc::IPPROTO_IPV6 && header.cmsg_type == libc::IPV6_TCLASS
                    && header.cmsg_len >= libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize {
                    ecn = mark(ptr::read_unaligned(data.cast::<libc::c_int>()) as u8);
                }
                let next = libc::CMSG_NXTHDR(&msg, c);
                if !next.is_null() && next as usize <= start { break; }
                c = next;
            }
        }
        Ok((n as usize, peer, ecn))
    }

    pub(super) async fn receive(socket: &UdpSocket, out: &mut [u8]) -> io::Result<(usize, SocketAddr, Mark)> {
        loop {
            socket.readable().await?;
            match socket.try_io(Interest::READABLE, || receive_now(socket, out)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }

    fn send_now(socket: &UdpSocket, data: &[u8], peer: SocketAddr) -> io::Result<usize> {
        let mut v4: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut v6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        let (addr, len, level, kind) = match peer {
            SocketAddr::V4(a) => {
                v4.sin_family = libc::AF_INET as libc::sa_family_t;
                v4.sin_port = a.port().to_be();
                v4.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
                ((&mut v4 as *mut libc::sockaddr_in).cast::<libc::c_void>(), size_of::<libc::sockaddr_in>(), libc::IPPROTO_IP, libc::IP_TOS)
            }
            SocketAddr::V6(a) => {
                v6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                v6.sin6_port = a.port().to_be();
                v6.sin6_addr.s6_addr = a.ip().octets();
                v6.sin6_scope_id = a.scope_id();
                v6.sin6_flowinfo = a.flowinfo().to_be();
                ((&mut v6 as *mut libc::sockaddr_in6).cast::<libc::c_void>(), size_of::<libc::sockaddr_in6>(), libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
            }
        };
        let mut control = [0usize; 8];
        let mut iov = libc::iovec { iov_base: data.as_ptr().cast_mut().cast(), iov_len: data.len() };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = addr;
        msg.msg_namelen = len as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        // SAFETY: one aligned, bounded integer cmsg, all sendmsg buffers
        // remain alive; the syscall only reads the payload and address.
        unsafe {
            msg.msg_controllen = libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) as usize;
            if msg.msg_controllen > mem::size_of_val(&control) { return Err(io::ErrorKind::InvalidInput.into()); }
            let c = libc::CMSG_FIRSTHDR(&msg);
            if c.is_null() { return Err(io::ErrorKind::InvalidInput.into()); }
            (*c).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;
            (*c).cmsg_level = level;
            (*c).cmsg_type = kind;
            ptr::write_unaligned(libc::CMSG_DATA(c).cast::<libc::c_int>(), 2);
            let n = libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_DONTWAIT);
            if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
        }
    }

    pub(super) async fn send(socket: &UdpSocket, data: &[u8], peer: SocketAddr) -> io::Result<usize> {
        loop {
            socket.writable().await?;
            match socket.try_io(Interest::WRITABLE, || send_now(socket, data, peer)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::time::Duration;
    #[tokio::test]
    async fn actual_udp_ect_and_notect_on_both_ip_families() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let a = UdpSocket::bind(bind).await.unwrap();
            let b = UdpSocket::bind(bind).await.unwrap();
            let tx = Options::configure(&a);
            let rx = Options::configure(&b);
            assert!(tx.df && rx.df && tx.ecn && rx.ecn);
            for (ect, mark) in [(true, Mark::Ect0), (false, Mark::NotEct)] {
                assert_eq!(tx.send(&a, b"test", b.local_addr().unwrap(), ect).await.unwrap(), (4, mark));
                let mut out = [0; 8];
                let (n, peer, observed) = tokio::time::timeout(Duration::from_secs(2), rx.receive(&b, &mut out)).await.unwrap().unwrap();
                assert_eq!((n, peer, observed), (4, a.local_addr().unwrap(), mark));
                assert_eq!(&out[..n], b"test");
            }
        }
    }
}
