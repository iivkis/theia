//! Experimental pure packet transformation; no strategy is approved for
//! production native egress until independently measured and policy-bound.
//! This narrow STUN variant changes a real credential-free Binding packet,
//! never a probe, and recomputes IPv4/IPv6 transport lengths and checksums.
use super::{dpi::udp::{prepare_binding, BindingStrategy}, packet::{PacketMeta, Transport}};
use std::borrow::Cow;

fn words(bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    let sum = chunks.by_ref().map(|p| u32::from(u16::from_be_bytes([p[0], p[1]]))).sum::<u32>();
    sum + chunks.remainder().first().map_or(0, |b| u32::from(*b) << 8)
}
fn checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}
fn udp_checksum(packet: &[u8], offset: usize) -> u16 {
    let len = (packet.len() - offset) as u32;
    let pseudo = if offset == 20 {
        words(&packet[12..20]) + 17 + len
    } else {
        words(&packet[8..40]) + 17 + (len >> 16) + (len & 0xffff)
    };
    checksum(pseudo + words(&packet[offset..]))
}

/// Only complete non-offloaded UDP packets with no IP options/extensions.
/// The caller must establish that offload is absent and the actual strategy
/// is permitted for this flow. None means no modification; never count it as
/// successful Modify or substitute ordinary local Pass.
pub fn stun_fingerprint(packet: &[u8]) -> Option<Vec<u8>> {
    let meta = PacketMeta::parse(packet, 0).ok()?;
    if meta.flow.transport != Transport::Udp || meta.flow.destination.port() != 3478
        || meta.flow.destination.ip().is_multicast() || meta.flow.destination.ip().is_unspecified() {
        return None;
    }
    let offset = match packet[0] >> 4 {
        4 if packet[0] == 0x45 && packet[9] == 17 && checksum(words(&packet[..20])) == 0 => 20,
        6 if packet[6] == 17 => 40,
        _ => return None,
    };
    let existing = u16::from_be_bytes(packet[offset+6..offset+8].try_into().ok()?);
    if existing == 0 {
        if offset == 40 { return None; }
    } else if udp_checksum(packet, offset) != 0 {
        return None;
    }
    let Cow::Owned(data) = prepare_binding(&packet[offset+8..], BindingStrategy::Fingerprint)? else {
        return None;
    };
    let mut out = packet[..offset+8].to_vec();
    out.extend_from_slice(&data);
    let udp_len = u16::try_from(out.len() - offset).ok()?;
    out[offset+4..offset+6].copy_from_slice(&udp_len.to_be_bytes());
    out[offset+6..offset+8].fill(0);
    if offset == 20 {
        let total = u16::try_from(out.len()).ok()?;
        out[2..4].copy_from_slice(&total.to_be_bytes());
        out[10..12].fill(0);
        let sum = checksum(words(&out[..20]));
        out[10..12].copy_from_slice(&sum.to_be_bytes());
    } else {
        out[4..6].copy_from_slice(&udp_len.to_be_bytes());
    }
    let sum = udp_checksum(&out, offset);
    let sum = if sum == 0 { u16::MAX } else { sum };
    out[offset+6..offset+8].copy_from_slice(&sum.to_be_bytes());
    let changed = PacketMeta::parse(&out, 0).ok()?;
    if changed.flow != meta.flow || changed.payload_len != meta.payload_len + 8 { return None; }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(v6: bool) -> Vec<u8> {
        let offset = if v6 { 40 } else { 20 };
        let mut b = vec![0u8; offset + 28];
        if v6 {
            b[0] = 0x60;
            b[4..6].copy_from_slice(&28u16.to_be_bytes());
            b[6] = 17;
            b[8..24].copy_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
            b[24..40].copy_from_slice(&"2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        } else {
            b[0] = 0x45;
            b[2..4].copy_from_slice(&48u16.to_be_bytes());
            b[8] = 64;
            b[9] = 17;
            b[12..16].copy_from_slice(&[192, 0, 2, 1]);
            b[16..20].copy_from_slice(&[198, 51, 100, 2]);
            let sum = checksum(words(&b[..20]));
            b[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        b[offset..offset+2].copy_from_slice(&1234u16.to_be_bytes());
        b[offset+2..offset+4].copy_from_slice(&3478u16.to_be_bytes());
        b[offset+4..offset+6].copy_from_slice(&28u16.to_be_bytes());
        b[offset+8..offset+16].copy_from_slice(&[0,1,0,0,0x21,0x12,0xa4,0x42]);
        b[offset+16..offset+28].fill(7);
        let sum = udp_checksum(&b, offset);
        b[offset+6..offset+8].copy_from_slice(&(if sum == 0 { u16::MAX } else { sum }).to_be_bytes());
        b
    }
    #[test]
    fn dual_stack_binding_transform_preserves_tuple_and_integrity() {
        for v6 in [false, true] {
            let offset = if v6 { 40 } else { 20 };
            let original = packet(v6);
            let changed = stun_fingerprint(&original).unwrap();
            assert_eq!(changed.len(), original.len()+8);
            assert_eq!(udp_checksum(&changed, offset), 0);
            if !v6 { assert_eq!(checksum(words(&changed[..20])), 0); }
            assert_eq!(&changed[offset+16..offset+28], &original[offset+16..offset+28]);
            assert!(super::super::dpi::udp::plain_binding(&changed[offset+8..]).is_some());
            assert!(stun_fingerprint(&changed).is_none());
            let mut corrupt = original.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(stun_fingerprint(&corrupt).is_none());
            for n in 0..original.len() { assert!(stun_fingerprint(&original[..n]).is_none()); }
        }
    }
}
