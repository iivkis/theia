//! Common destination ACL for server and standalone local egress.
use std::net::{IpAddr, Ipv4Addr};

/// Fail-closed address policy. IPv4-mapped IPv6 must be checked as IPv4.
/// Private/loopback, link-local, multicast, reserved and documentation ranges
/// are rejected by default; only explicit allow_private_ips permits them.
pub fn allowed_destination(ip: IpAddr, allow_private_ips: bool) -> bool {
    if let IpAddr::V6(v6) = ip {
        if let Some(mapped) = v6.to_ipv4_mapped() {
            return allowed_destination(IpAddr::V4(mapped), allow_private_ips);
        }
    }
    if allow_private_ips {
        return !ip.is_unspecified() && !ip.is_multicast();
    }
    match ip {
        IpAddr::V4(v4) => allowed_v4(v4),
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let global_unicast = (segments[0] & 0xe000) == 0x2000;
            let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
            // Reject transition/tunneling and special-use ranges rather than
            // relying on embedded IPv4 routing or future address assignments.
            let special = (segments[0] == 0x2001 && segments[1] < 0x0200)
                || segments[0] == 0x2002
                || (segments[0] == 0x3fff && segments[1] < 0x1000);
            global_unicast && !documentation && !special
        }
    }
}

fn allowed_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 0 || b == 168 || (b == 88 && c == 99)))
        || (a == 198 && ((b == 18 || b == 19) || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113)
        || (a == 192 && b == 0 && c == 2)
        || (a == 255 && b == 255 && c == 255 && d == 255))
}
