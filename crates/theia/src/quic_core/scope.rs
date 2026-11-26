//! Explicit socket scope for controlled non-loopback QUIC trials. There is
//! deliberately no wildcard or arbitrary peer mode before production parity.
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkScope {
    pins: Option<([IpAddr; 2], [IpAddr; 2])>,
}

impl NetworkScope {
    pub(crate) const fn loopback() -> Self {
        Self { pins: None }
    }

    /// The caller explicitly authorizes one or two local and peer addresses.
    /// Repeat an address when there is no secondary path. A socket is always
    /// bound to one concrete address and a single IP family.
    pub fn pinned(local: [IpAddr; 2], peer: [IpAddr; 2]) -> Option<Self> {
        if local.iter().chain(peer.iter()).any(|ip| !unicast(*ip))
            || local.iter().chain(peer.iter()).any(|ip| ip.is_ipv4() != local[0].is_ipv4())
        {
            return None;
        }
        Some(Self { pins: Some((local, peer)) })
    }

    pub(crate) fn is_pinned(self) -> bool {
        self.pins.is_some()
    }

    pub(crate) fn allows_local(self, ip: IpAddr) -> bool {
        self.pins.map_or_else(|| ip.is_loopback(), |(local, _)| local.contains(&ip))
    }

    pub(crate) fn allows_peer(self, ip: IpAddr) -> bool {
        self.pins.map_or_else(|| ip.is_loopback(), |(_, peer)| peer.contains(&ip))
    }

    pub(crate) fn permits(self, local: SocketAddr, peer: SocketAddr) -> bool {
        self.allows_local(local.ip()) && self.allows_peer(peer.ip())
            && local.is_ipv4() == peer.is_ipv4()
            && local.port() != 0 && peer.port() != 0 && local != peer
    }
}

fn unicast(ip: IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_multicast() { return false; }
    match ip {
        IpAddr::V4(ip) => !ip.is_broadcast() && !ip.is_link_local(),
        IpAddr::V6(ip) => !ip.is_unicast_link_local() && ip.to_ipv4_mapped().is_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_dual_path_scope_rejects_wildcards_and_unapproved_peers() {
        let local: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        let peer: IpAddr = "198.51.100.1".parse().unwrap();
        let next: IpAddr = "198.51.100.2".parse().unwrap();
        let scope = NetworkScope::pinned([local, other], [peer, next]).unwrap();
        assert!(scope.permits(SocketAddr::new(local, 10), SocketAddr::new(peer, 20)));
        assert!(scope.permits(SocketAddr::new(other, 11), SocketAddr::new(next, 21)));
        assert!(!scope.permits(SocketAddr::new(local, 10), "203.0.113.1:20".parse().unwrap()));
        assert!(!scope.permits(SocketAddr::new(local, 10), SocketAddr::new(peer, 0)));
        assert!(NetworkScope::pinned(["0.0.0.0".parse().unwrap(), other], [peer, next]).is_none());
        assert!(NetworkScope::pinned([local, other], [peer, "::1".parse().unwrap()]).is_none());
        let v6 = "::1".parse().unwrap();
        assert!(NetworkScope::pinned([v6; 2], [v6; 2]).unwrap()
            .permits("[::1]:1000".parse().unwrap(), "[::1]:1001".parse().unwrap()));
        assert!(!NetworkScope::loopback().permits("127.0.0.1:1000".parse().unwrap(), "[::1]:1001".parse().unwrap()));
    }
}
