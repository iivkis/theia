//! Laboratory socket exemption lease. Kernel socket mark is set only on
//! the exact connected descriptor, and nftables also matches its complete
//! TCP/UDP tuple. The caller must own the socket and trust other privileged
//! processes in the isolated network namespace. No blanket process bypass.
use super::{
    linux_attribution::socket_cookie,
    packet::{FlowKey, Transport},
};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    fs::File,
    io, mem,
    net::{SocketAddr, TcpStream, UdpSocket},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
};

fn denied() -> io::Error {
    io::Error::from(io::ErrorKind::PermissionDenied)
}
fn opt_u64(fd: &impl AsRawFd, option: libc::c_int) -> io::Result<u64> {
    let mut value = 0u64;
    let mut len = mem::size_of_val(&value) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut u64).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != mem::size_of_val(&value) || value == 0 {
        return Err(denied());
    }
    Ok(value)
}
fn verify_descriptor(socket:&impl AsRawFd,transport:Transport)->io::Result<()> {
    // All factory sockets and all retained duplicates must be
    // close-on-exec. This does not prevent deliberate descriptor passing
    // or a privileged fork; such sharing remains outside the lab scope.
    let flags=unsafe {libc::fcntl(socket.as_raw_fd(),libc::F_GETFD)};
    if flags<0 {return Err(io::Error::last_os_error());}
    if flags&libc::FD_CLOEXEC==0 {return Err(denied());}
    for (option,expected) in [
        (libc::SO_TYPE,if transport==Transport::Tcp {libc::SOCK_STREAM}else{libc::SOCK_DGRAM}),
        (libc::SO_PROTOCOL,if transport==Transport::Tcp {libc::IPPROTO_TCP}else{libc::IPPROTO_UDP}),
    ] {
        let mut value=0i32;
        let mut len=mem::size_of_val(&value) as libc::socklen_t;
        if unsafe {libc::getsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,option,
            (&mut value as *mut i32).cast(),&mut len)}!=0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize!=mem::size_of_val(&value) || value!=expected {return Err(denied());}
    }
    Ok(())
}
fn get_mark(fd: &OwnedFd) -> io::Result<u32> {
    let mut value = 0u32;
    let mut len = mem::size_of_val(&value) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mut value as *mut u32).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != mem::size_of_val(&value) {
        return Err(denied());
    }
    Ok(value)
}
fn set_mark(fd: &OwnedFd, value: u32) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&value as *const u32).cast(),
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if get_mark(fd)? != value {
        return Err(denied());
    }
    Ok(())
}
fn current_namespace() -> io::Result<(u64, u64)> {
    let meta = std::fs::metadata("/proc/thread-self/ns/net")?;
    Ok((meta.dev(), meta.ino()))
}
fn check_scope(host: &File) -> io::Result<(u64, u64)> {
    let host_meta = host.metadata()?;
    let current = current_namespace()?;
    if current == (host_meta.dev(), host_meta.ino())
        || unsafe { libc::ioctl(host.as_raw_fd(), 0xb703 as _) } != libc::CLONE_NEWNET
    {
        return Err(denied());
    }
    Ok(current)
}
fn valid(key: FlowKey) -> bool {
    [key.source, key.destination].iter().all(|a| a.port() != 0 && !a.ip().is_unspecified() && !a.ip().is_multicast()
        && !matches!(a, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.ip().to_ipv4_mapped().is_some() || v6.ip().is_unicast_link_local()))
        && key.source != key.destination && key.source.is_ipv4() == key.destination.is_ipv4()
}

pub struct LabCarrierSocket {
    fd: OwnedFd,
    key: FlowKey,
    cookie: u64,
    mark: u32,
    namespace: (u64, u64),
    pending: bool,
}
impl LabCarrierSocket {
    /// Only call with a socket already authenticated by the client and
    /// owned exclusively by the trusted service. The FD is duplicated to
    /// retain the kernel object until the rules lease is dropped.
    pub fn tcp(socket: &TcpStream, host_namespace: &File) -> io::Result<Self> {
        verify_descriptor(socket,Transport::Tcp)?;
        let key = FlowKey {
            source: socket.local_addr()?,
            destination: socket.peer_addr()?,
            transport: Transport::Tcp,
            interface: 0,
        };
        Self::claim(socket.try_clone()?.into(), key, host_namespace, false)
    }
    pub fn udp(socket: &UdpSocket, host_namespace: &File) -> io::Result<Self> {
        verify_descriptor(socket,Transport::Udp)?;
        let key = FlowKey {
            source: socket.local_addr()?,
            destination: socket.peer_addr()?,
            transport: Transport::Udp,
            interface: 0,
        };
        Self::claim(socket.try_clone()?.into(), key, host_namespace, false)
    }
    pub(super) fn pending_tcp(
        socket: &tokio::net::TcpSocket,
        peer: SocketAddr,
        host: &File,
    ) -> io::Result<Self> {
        Self::pending(socket, socket.local_addr()?, peer, Transport::Tcp, host)
    }
    pub(super) fn pending_udp(
        socket: &tokio::net::UdpSocket,
        peer: SocketAddr,
        host: &File,
    ) -> io::Result<Self> {
        Self::pending(socket, socket.local_addr()?, peer, Transport::Udp, host)
    }
    fn pending(
        socket: &impl AsRawFd,
        source: SocketAddr,
        destination: SocketAddr,
        transport: Transport,
        host: &File,
    ) -> io::Result<Self> {
        verify_descriptor(socket,transport)?;
        let fd = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self::claim(
            fd,
            FlowKey {
                source,
                destination,
                transport,
                interface: 0,
            },
            host,
            true,
        )
    }
    fn claim(fd: OwnedFd, key: FlowKey, host_namespace: &File, pending: bool) -> io::Result<Self> {
        verify_descriptor(&fd,key.transport)?;
        let namespace = check_scope(host_namespace)?;
        if !valid(key) || get_mark(&fd)? != 0 {
            return Err(denied());
        }
        let probe = UdpSocket::bind("0.0.0.0:0")?;
        if opt_u64(&fd, 71)? != opt_u64(&probe, 71)? {
            return Err(denied());
        } // SO_NETNS_COOKIE
        let cookie = socket_cookie(&fd)?;
        let mut bytes = [0u8; 4];
        SystemRandom::new().fill(&mut bytes).map_err(|_| denied())?;
        let mark = u32::from_ne_bytes(bytes);
        if mark == 0 || mark==super::linux_rules::REDIRECT_MARK {
            return Err(denied());
        }
        let lease = Self {
            fd,
            key,
            cookie,
            mark,
            namespace,
            pending,
        };
        set_mark(&lease.fd, mark)?;
        lease.verify()?;
        Ok(lease)
    }
    pub(super) fn verify(&self) -> io::Result<()> {
        verify_descriptor(&self.fd,self.key.transport)?;
        if current_namespace()? != self.namespace
            || socket_cookie(&self.fd)? != self.cookie
            || get_mark(&self.fd)? != self.mark
        {
            return Err(denied());
        }
        // Verify current connected tuple through a fresh duplicate of the
        // actual kernel socket. UDP reconnects must not inherit permission.
        let fd = self.fd.try_clone()?;
        let (source, destination) = match self.key.transport {
            Transport::Tcp => {
                let s = TcpStream::from(fd);
                (s.local_addr()?, s.peer_addr())
            }
            Transport::Udp => {
                let s = UdpSocket::from(fd);
                (s.local_addr()?, s.peer_addr())
            }
        };
        if source != self.key.source {
            return Err(denied());
        }
        match destination {
            Ok(peer) if peer == self.key.destination => (),
            Err(error) if self.pending && error.kind() == io::ErrorKind::NotConnected => (),
            _ => return Err(denied()),
        }
        Ok(())
    }
    pub(super) fn clear_mark(&self) -> io::Result<()> {
        if socket_cookie(&self.fd)? != self.cookie {
            return Err(denied());
        }
        match get_mark(&self.fd)? {
            0 => Ok(()),
            mark if mark == self.mark => set_mark(&self.fd, 0),
            _ => Err(denied()),
        }
    }
    pub(super) fn key(&self) -> FlowKey {
        self.key
    }
    pub(super) fn cookie(&self) -> u64 {
        self.cookie
    }
    pub(super) fn mark(&self) -> u32 {
        self.mark
    }
}
impl Drop for LabCarrierSocket {
    fn drop(&mut self) {
        // Only our descriptor, and only if its mark is still ours. A
        // failed reset is not a permission to remove the capture rules.
        if socket_cookie(&self.fd).ok() == Some(self.cookie)
            && get_mark(&self.fd).ok() == Some(self.mark)
        {
            let _ = set_mark(&self.fd, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_checks_reject_wrong_protocol_and_inheritable_fd() {
        let socket=UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(verify_descriptor(&socket,Transport::Udp).is_ok());
        assert!(verify_descriptor(&socket,Transport::Tcp).is_err());
        let raw=unsafe {libc::fcntl(socket.as_raw_fd(),libc::F_DUPFD,0)};
        assert!(raw>=0);
        let fd=unsafe {OwnedFd::from_raw_fd(raw)};
        assert!(verify_descriptor(&fd,Transport::Udp).is_err());
        assert_eq!(unsafe {libc::fcntl(fd.as_raw_fd(),libc::F_SETFD,libc::FD_CLOEXEC)},0);
        assert!(verify_descriptor(&fd,Transport::Udp).is_ok());
    }
    #[test]
    fn never_marks_a_socket_in_the_host_namespace() {
        let host = File::open("/proc/thread-self/ns/net").unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(peer.local_addr().unwrap()).unwrap();
        assert!(LabCarrierSocket::udp(&socket, &host).is_err());
    }
}
