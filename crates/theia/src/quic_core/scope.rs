//! Explicit socket scope. A server may accept unpinned unicast peers only
//! through the explicit own-TLS server entry point, on a concrete local IP.
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkScope {
    pins: Option<([IpAddr; 2], [IpAddr; 2])>,
    server: Option<IpAddr>,
}

impl NetworkScope {
    pub(crate) const fn loopback() -> Self {
        Self {
            pins: None,
            server: None,
        }
    }

    /// The caller explicitly authorizes one or two local and peer addresses.
    /// Repeat an address when there is no secondary path. A socket is always
    /// bound to one concrete address and a single IP family.
    pub fn pinned(local: [IpAddr; 2], peer: [IpAddr; 2]) -> Option<Self> {
        if local.iter().chain(peer.iter()).any(|ip| !unicast(*ip))
            || local
                .iter()
                .chain(peer.iter())
                .any(|ip| ip.is_ipv4() != local[0].is_ipv4())
        {
            return None;
        }
        Some(Self {
            pins: Some((local, peer)),
            server: None,
        })
    }

    pub(crate) fn external_server(local: IpAddr) -> Option<Self> {
        unicast(local).then_some(Self {
            pins: None,
            server: Some(local),
        })
    }

    /// A wildcard authorizes only the concrete unicast destination supplied
    /// by the kernel on receive. It never authorizes an unspecified source.
    pub(crate) fn listener(bind: IpAddr) -> Option<Self> {
        if bind.is_unspecified() {
            Some(Self {
                pins: None,
                server: Some(bind),
            })
        } else {
            Self::external_server(bind)
        }
    }

    pub(crate) fn allows_bind(self, ip: IpAddr) -> bool {
        self.server == Some(ip) || self.allows_local(ip)
    }

    pub(crate) fn is_external_server(self) -> bool {
        self.server.is_some()
    }

    pub(crate) fn is_pinned(self) -> bool {
        self.pins.is_some()
    }

    pub(crate) fn allows_local(self, ip: IpAddr) -> bool {
        if let Some(local) = self.server {
            return if local.is_unspecified() {
                unicast(ip) && ip.is_ipv4() == local.is_ipv4()
            } else {
                ip == local
            };
        }
        self.pins
            .map_or_else(|| ip.is_loopback(), |(local, _)| local.contains(&ip))
    }

    pub(crate) fn allows_peer(self, ip: IpAddr) -> bool {
        if let Some(local) = self.server {
            return unicast(ip) && ip.is_ipv4() == local.is_ipv4();
        }
        self.pins
            .map_or_else(|| ip.is_loopback(), |(_, peer)| peer.contains(&ip))
    }

    pub(crate) fn permits(self, local: SocketAddr, peer: SocketAddr) -> bool {
        self.allows_local(local.ip())
            && self.allows_peer(peer.ip())
            && local.is_ipv4() == peer.is_ipv4()
            && local.port() != 0
            && peer.port() != 0
            && local != peer
    }
}

fn unicast(ip: IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => !ip.is_broadcast() && !ip.is_link_local(),
        IpAddr::V6(ip) => !ip.is_unicast_link_local() && ip.to_ipv4_mapped().is_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_server_scope_has_one_local_ip_and_rejects_nonunicast() {
        let local = "192.0.2.1:443".parse::<SocketAddr>().unwrap();
        let scope = NetworkScope::external_server(local.ip()).unwrap();
        assert!(scope.is_external_server());
        assert!(!scope.is_pinned());
        assert!(scope.permits(local, "198.51.100.10:2000".parse().unwrap()));
        assert!(scope.permits(local, "203.0.113.11:3000".parse().unwrap()));
        assert!(!scope.permits(local, "224.0.0.1:2000".parse().unwrap()));
        assert!(!scope.permits(local, "0.0.0.0:2000".parse().unwrap()));
        assert!(!scope.permits(local, "[::1]:2000".parse().unwrap()));
        assert!(!scope.permits(
            "192.0.2.2:443".parse().unwrap(),
            "198.51.100.10:2000".parse().unwrap()
        ));
        assert!(NetworkScope::external_server("0.0.0.0".parse().unwrap()).is_none());
    }

    #[test]
    fn wildcard_requires_concrete_same_family_destination() {
        for (bind, local, peer) in [
            ("0.0.0.0:443", "127.0.0.2:443", "127.0.0.1:1234"),
            ("[::]:443", "[::1]:443", "[::1]:1234"),
        ] {
            let bind: SocketAddr = bind.parse().unwrap();
            let scope = NetworkScope::listener(bind.ip()).unwrap();
            assert!(scope.allows_bind(bind.ip()));
            assert!(!scope.allows_local(bind.ip()));
            assert!(scope.permits(local.parse().unwrap(), peer.parse().unwrap()));
            assert!(!scope.permits(bind, peer.parse().unwrap()));
        }
    }

    #[test]
    fn exact_dual_path_scope_rejects_wildcards_and_unapproved_peers() {
        let local: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        let peer: IpAddr = "198.51.100.1".parse().unwrap();
        let next: IpAddr = "198.51.100.2".parse().unwrap();
        let scope = NetworkScope::pinned([local, other], [peer, next]).unwrap();
        assert!(scope.permits(SocketAddr::new(local, 10), SocketAddr::new(peer, 20)));
        assert!(scope.permits(SocketAddr::new(other, 11), SocketAddr::new(next, 21)));
        assert!(!scope.permits(
            SocketAddr::new(local, 10),
            "203.0.113.1:20".parse().unwrap()
        ));
        assert!(!scope.permits(SocketAddr::new(local, 10), SocketAddr::new(peer, 0)));
        assert!(NetworkScope::pinned(["0.0.0.0".parse().unwrap(), other], [peer, next]).is_none());
        assert!(NetworkScope::pinned([local, other], [peer, "::1".parse().unwrap()]).is_none());
        let v6 = "::1".parse().unwrap();
        assert!(NetworkScope::pinned([v6; 2], [v6; 2])
            .unwrap()
            .permits("[::1]:1000".parse().unwrap(), "[::1]:1001".parse().unwrap()));
        assert!(!NetworkScope::loopback().permits(
            "127.0.0.1:1000".parse().unwrap(),
            "[::1]:1001".parse().unwrap()
        ));
    }
}
