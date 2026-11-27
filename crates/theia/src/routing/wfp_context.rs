//! Fixed, versioned companion-driver redirect context. Parsing only;
//! the private session token must be installed via a protected driver channel.
use super::packet::{FlowKey, Transport};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use subtle::ConstantTimeEq;

pub(super) const SIZE: usize = 84;
const MAGIC: &[u8; 8] = b"THWFP001";

pub(super) fn decode(bytes: &[u8], token: &[u8; 32], peer: SocketAddr, local: SocketAddr) -> Option<FlowKey> {
    decode_transport(bytes, token, peer, local, Transport::Tcp)
}

pub(super) fn decode_transport(bytes: &[u8], token: &[u8; 32], peer: SocketAddr, local: SocketAddr, transport: Transport) -> Option<FlowKey> {
    let protocol = match transport { Transport::Tcp => 6, Transport::Udp => 17 };
    if bytes.len() != SIZE || &bytes[..8] != MAGIC || *token == [0; 32]
        || !bool::from(bytes[8..40].ct_eq(token.as_slice()))
        || bytes[41] != protocol || bytes[42..44] != [0, 0] {
        return None;
    }
    let compartment = u32::from_be_bytes(bytes[44..48].try_into().ok()?);
    if compartment == 0 { return None; }
    let source_port = u16::from_be_bytes(bytes[48..50].try_into().ok()?);
    let destination_port = u16::from_be_bytes(bytes[50..52].try_into().ok()?);
    let ip = |raw: &[u8]| match bytes[40] {
        4 if raw[4..] == [0; 12] => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&raw[..4]).ok()?))),
        6 => {
            let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(raw).ok()?);
            if v6.to_ipv4_mapped().is_some() || v6.is_unicast_link_local() { None } else { Some(IpAddr::V6(v6)) }
        }
        _ => None,
    };
    let source = SocketAddr::new(ip(&bytes[52..68])?, source_port);
    let destination = SocketAddr::new(ip(&bytes[68..84])?, destination_port);
    if source != peer || source_port == 0 || destination_port == 0
        || source.ip().is_unspecified() || source.ip().is_multicast()
        || !(local.ip().is_loopback() || local.ip() == source.ip()) || destination == local || destination == source
        || destination.ip().is_loopback() || destination.ip().is_multicast() || destination.ip().is_unspecified() {
        return None;
    }
    Some(FlowKey { source, destination, transport, interface: compartment })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_private_context_rejects_mismatch_and_truncation() {
        let mut bytes = [0; SIZE];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..40].copy_from_slice(&[7; 32]);
        bytes[40] = 4;
        bytes[41] = 6;
        bytes[44..48].copy_from_slice(&1u32.to_be_bytes());
        bytes[48..50].copy_from_slice(&1234u16.to_be_bytes());
        bytes[50..52].copy_from_slice(&443u16.to_be_bytes());
        bytes[52..56].copy_from_slice(&[127, 0, 0, 1]);
        bytes[68..72].copy_from_slice(&[192, 0, 2, 1]);
        let peer = "127.0.0.1:1234".parse().unwrap();
        let local = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(decode(&bytes, &[7; 32], peer, local).unwrap().destination, "192.0.2.1:443".parse().unwrap());
        assert!(decode(&bytes, &[8; 32], peer, local).is_none());
        assert!(decode(&bytes, &[7; 32], "127.0.0.1:1235".parse().unwrap(), local).is_none());
        for len in 0..SIZE { assert!(decode(&bytes[..len], &[7; 32], peer, local).is_none()); }
        bytes[41] = 17;
        assert!(decode(&bytes, &[7; 32], peer, local).is_none());
        assert_eq!(decode_transport(&bytes, &[7; 32], peer, local, Transport::Udp).unwrap().transport, Transport::Udp);
    }
}
