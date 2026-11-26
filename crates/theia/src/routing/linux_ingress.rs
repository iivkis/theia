//! Kernel-supplied original destination for already NAT-redirected TCP.
//! No nftables rules or socket exemptions are installed by this module.
use super::packet::{FlowKey, Transport};
use std::{
    io,
    mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::AsRawFd,
};
use tokio::net::TcpStream;

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

#[cfg(test)]
mod tests {
    use super::*;
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
