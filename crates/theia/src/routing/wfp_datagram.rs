//! Fixed ABI for datagrams captured by the isolated kernel WFP adapter.
//! The generation is opaque; reverse requests never serialize an address.
use super::packet::{FlowKey, Transport};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub(crate) const HEADER: usize = 56;
pub(crate) const MAX_FRAME: usize = HEADER + crate::protocol::MAX_DATAGRAM;

#[derive(Debug)]
pub(crate) struct Datagram {
    pub(crate) generation: u64,
    pub(crate) key: FlowKey,
    pub(crate) payload: Vec<u8>,
}
impl Datagram {
    pub(crate) fn decode(bytes: &[u8], compartment: u32) -> Option<Self> {
        if bytes.len() < HEADER || bytes.len() > MAX_FRAME
            || bytes[9] != 17 || bytes[10..12] != [0; 2]
            || compartment <= 1
            || u32::from_be_bytes(bytes[12..16].try_into().ok()?) != compartment
        {
            return None;
        }
        let generation = u64::from_be_bytes(bytes[..8].try_into().ok()?);
        let len = u32::from_be_bytes(bytes[52..56].try_into().ok()?) as usize;
        if generation == 0 || len != bytes.len() - HEADER {
            return None;
        }
        let address = |raw: &[u8], port| {
            let ip = match bytes[8] {
                4 if raw[4..] == [0; 12] => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&raw[..4]).ok()?)),
                6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(raw).ok()?)),
                _ => return None,
            };
            if port == 0 || ip.is_unspecified() || ip.is_multicast() || ip.is_loopback()
                || matches!(ip, IpAddr::V4(v4) if v4.octets()[0] >= 224)
                || matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() || v6.is_unicast_link_local())
            {
                return None;
            }
            Some(SocketAddr::new(ip, port))
        };
        let source = address(&bytes[20..36], u16::from_be_bytes(bytes[16..18].try_into().ok()?))?;
        let destination = address(&bytes[36..52], u16::from_be_bytes(bytes[18..20].try_into().ok()?))?;
        if source.ip() == destination.ip() { return None; }
        Some(Self {
            generation,
            key: FlowKey { source, destination, transport: Transport::Udp, interface: compartment },
            payload: bytes[HEADER..].to_vec(),
        })
    }
}

/// Reverse request contains the session token, opaque generation and
/// payload only. The driver resolves every addressing field itself.
pub(crate) fn reply_request(token: &[u8; 32], generation: u64, data: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    if *token == [0; 32] || generation == 0 || data.len() > crate::protocol::MAX_DATAGRAM {
        return None;
    }
    let mut request = zeroize::Zeroizing::new(Vec::with_capacity(40 + data.len()));
    request.extend_from_slice(token);
    request.extend_from_slice(&generation.to_be_bytes());
    request.extend_from_slice(data);
    Some(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(v6: bool, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0; HEADER];
        b[..8].copy_from_slice(&7u64.to_be_bytes());
        b[8] = if v6 { 6 } else { 4 };
        b[9] = 17;
        b[12..16].copy_from_slice(&2u32.to_be_bytes());
        b[16..18].copy_from_slice(&1234u16.to_be_bytes());
        b[18..20].copy_from_slice(&443u16.to_be_bytes());
        if v6 {
            b[20..36].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
            b[36..52].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        } else {
            b[20..24].copy_from_slice(&[192,0,2,1]);
            b[36..40].copy_from_slice(&[198,51,100,2]);
        }
        b[52..56].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        b.extend_from_slice(payload);
        b
    }
    #[test]
    fn exact_dual_stack_capture_and_no_address_in_reply() {
        for v6 in [false, true] {
            for data in [vec![], vec![7; 5], vec![9; crate::protocol::MAX_DATAGRAM]] {
                let b = frame(v6, &data);
                let d = Datagram::decode(&b, 2).unwrap();
                assert_eq!(d.generation, 7);
                assert_eq!(d.payload, data);
                assert_eq!(d.key.source.port(), 1234);
                assert_eq!(d.key.destination.port(), 443);
                assert_eq!(d.key.source.is_ipv6(), v6);
                let request = reply_request(&[1; 32], d.generation, &d.payload).unwrap();
                assert_eq!(&request[..32], &[1; 32]);
                assert_eq!(&request[32..40], &7u64.to_be_bytes());
                assert_eq!(&request[40..], data);
                assert!(Datagram::decode(&b, 3).is_none());
                assert!(Datagram::decode(&b[..b.len()-1], 2).is_none());
            }
        }
        assert!(reply_request(&[1; 32], 0, &[]).is_none());
        assert!(reply_request(&[0; 32], 1, &[]).is_none());
    }
    #[test]
    fn malformed_identity_or_length_is_denied() {
        let b = frame(false, &[1,2,3]);
        for len in 0..b.len() { assert!(Datagram::decode(&b[..len], 2).is_none()); }
        for (index, value) in [(7,0),(8,5),(9,6),(10,1),(24,1),(16,0),(52,1)] {
            let mut altered = b.clone();
            altered[index] = value;
            if index == 16 { altered[17] = 0; }
            assert!(Datagram::decode(&altered, 2).is_none(), "{index}");
        }
        let mut oversized = b;
        oversized.resize(MAX_FRAME+1, 0);
        assert!(Datagram::decode(&oversized, 2).is_none());
    }
}
