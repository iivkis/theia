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

/// Candidate TCP/TLS segmentation. Does not change the TLS byte stream,
/// ACK number or window; PSH stays on the last segment. A real backend must
/// own both emissions, retransmission and cancellation before enabling it.
/// IPv4 DF and no IP/TCP options, IPv6 without extension headers only.
/// Never use the expected name as proof of the application's identity.
pub fn tcp_tls_segments(packet: &[u8], expected_name: &str) -> Option<[Vec<u8>; 2]> {
    let name = super::domain_name(expected_name).ok()?;
    let meta = PacketMeta::parse(packet, 0).ok()?;
    if meta.flow.transport != Transport::Tcp || meta.flow.destination.port() != 443
        || meta.flow.destination.ip().is_multicast() || meta.flow.destination.ip().is_unspecified()
        || !matches!(meta.tcp_flags, Some(0x10 | 0x18)) { return None; }
    let off = match packet[0] >> 4 {
        4 if packet[0] == 0x45 && packet[9] == 6
            && packet[6..8] == [0x40,0] && checksum(words(&packet[..20])) == 0 => 20,
        6 if packet[6] == 6 => 40,
        _ => return None,
    };
    if packet[off+12] != 0x50 || tcp_checksum(packet, off) != 0 { return None; }
    let payload = &packet[off+20..];
    if payload.len() <= 5 || !super::dpi::complete_packet_hello(payload, &name) { return None; }
    let seq = u32::from_be_bytes(packet[off+4..off+8].try_into().ok()?);
    let mut first = packet[..off+20].to_vec();
    first.extend_from_slice(&payload[..5]);
    first[off+13] &= !0x08; // PSH only on last segment
    let mut second = packet[..off+20].to_vec();
    second.extend_from_slice(&payload[5..]);
    second[off+4..off+8].copy_from_slice(&seq.wrapping_add(5).to_be_bytes());
    for out in [&mut first, &mut second] {
        let len = out.len();
        if off == 20 {
            out[2..4].copy_from_slice(&u16::try_from(len).ok()?.to_be_bytes());
            out[10..12].fill(0);
            let sum = checksum(words(&out[..20]));
            out[10..12].copy_from_slice(&sum.to_be_bytes());
        } else {
            out[4..6].copy_from_slice(&u16::try_from(len-40).ok()?.to_be_bytes());
        }
        out[off+16..off+18].fill(0);
        let sum = tcp_checksum(out, off);
        out[off+16..off+18].copy_from_slice(&sum.to_be_bytes());
        if PacketMeta::parse(out, 0).ok()?.flow != meta.flow || tcp_checksum(out, off) != 0 { return None; }
    }
    Some([first,second])
}
fn tcp_checksum(packet: &[u8], off: usize) -> u16 {
    let len = (packet.len()-off) as u32;
    let pseudo = if off == 20 { words(&packet[12..20])+6+len }
        else { words(&packet[8..40])+6+(len>>16)+(len&0xffff) };
    checksum(pseudo+words(&packet[off..]))
}

/// Candidate QUIC v1/v2 datagram de-coalescing. Authenticated Initial
/// packet and opaque subsequent long-header packets are kept byte-for-byte.
/// No packet number/nonce reuse, re-encryption, fake packet, or change to
/// CRYPTO stream bytes. Each resulting Initial remains at least 1200 bytes.
/// The actual UDP egress must own all outputs; this is not a verdict API.
pub fn quic_initial_datagrams(data: &[u8], expected_name: &str) -> Option<Vec<Vec<u8>>> {
    use crate::reality_quic_wire::{self as wire, Flight, Inspection, Kind};
    if data.len() > wire::MAX_DATAGRAM || !wire::coherent_datagram(data) { return None; }
    let first = wire::long(data)?;
    if first.kind != Kind::Initial || first.end < wire::MIN_INITIAL || first.end == data.len() { return None; }
    let expected = super::domain_name(expected_name).ok()?;
    let mut flight = Flight::new(&first)?;
    if !matches!(flight.inspect(&data[..first.end]), Inspection::Hello(message) if super::dpi::packet_quic_hello(&message, &expected)) { return None; }
    let mut result = vec![data[..first.end].to_vec()];
    let mut offset = first.end;
    let mut zero_rtt = false;
    let mut handshake = false;
    while offset < data.len() {
        let next = wire::long(&data[offset..])?;
        if next.version != first.version || next.dcid != first.dcid || next.scid != first.scid { return None; }
        match next.kind {
            Kind::ZeroRtt if !zero_rtt && !handshake => zero_rtt = true,
            Kind::Handshake if !handshake => handshake = true,
            _ => return None,
        }
        let end = offset.checked_add(next.end)?;
        result.push(data[offset..end].to_vec());
        offset = end;
    }
    (result.len() > 1).then_some(result)
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
    fn tcp_segment_candidates_preserve_stream_sequence_and_checksums() {
        let hello = super::super::dpi::packet_test_hello("example.org");
        for ipv6 in [false,true] {
            let off = if ipv6 { 40 } else { 20 };
            let mut original = vec![0u8;off+20];
            if ipv6 {
                original[0] = 0x60; original[6] = 6;
                original[8..24].copy_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
                original[24..40].copy_from_slice(&"2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
                original[4..6].copy_from_slice(&((20+hello.len()) as u16).to_be_bytes());
            } else {
                original[0] = 0x45; original[9] = 6; original[8] = 64;
                original[2..4].copy_from_slice(&((40+hello.len()) as u16).to_be_bytes());
                original[6..8].copy_from_slice(&[0x40,0]);
                original[12..16].copy_from_slice(&[192,0,2,1]);
                original[16..20].copy_from_slice(&[198,51,100,2]);
                let sum = checksum(words(&original[..20]));
                original[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            original[off..off+2].copy_from_slice(&1234u16.to_be_bytes());
            original[off+2..off+4].copy_from_slice(&443u16.to_be_bytes());
            original[off+4..off+8].copy_from_slice(&(u32::MAX-2).to_be_bytes());
            original[off+12] = 0x50; original[off+13] = 0x18;
            original.extend_from_slice(&hello);
            let sum = tcp_checksum(&original,off);
            original[off+16..off+18].copy_from_slice(&sum.to_be_bytes());
            let [a,b] = tcp_tls_segments(&original,"example.org").unwrap();
            assert_eq!([&a[off+20..], &b[off+20..]].concat(),hello);
            assert_eq!(a[off+13],0x10); assert_eq!(b[off+13],0x18);
            assert_eq!(u32::from_be_bytes(b[off+4..off+8].try_into().unwrap()),2);
            assert_eq!(tcp_checksum(&a,off),0); assert_eq!(tcp_checksum(&b,off),0);
            assert!(tcp_tls_segments(&original,"other.example").is_none());
        }
    }

    #[test]
    fn quic_candidate_never_splits_unauthenticated_or_short_initial() {
        use crate::reality_quic_wire as wire;
        for version in [wire::V1,wire::V2] {
            let initial = wire::test_initial(version, &super::super::dpi::packet_test_hello("example.org")[5..]);
            assert!(quic_initial_datagrams(&initial,"example.org").is_none());
            let mut data = initial.clone();
            let header = wire::long(&initial).unwrap();
            // Opaque structurally valid subsequent Handshake packet, not
            // interpreted as an authenticated transport/control frame.
            let mut tail = vec![if version == wire::V1 {0xe0} else {0xf0}];
            tail.extend_from_slice(&version.to_be_bytes());
            tail.push(header.dcid.len() as u8); tail.extend_from_slice(header.dcid);
            tail.push(header.scid.len() as u8); tail.extend_from_slice(header.scid);
            tail.push(20); tail.extend([7;20]);
            data.extend_from_slice(&tail);
            let split = quic_initial_datagrams(&data,"example.org").unwrap();
            assert_eq!(split,vec![initial,tail]);
            assert_eq!(split.concat(),data);
            data[100] ^= 1;
            assert!(quic_initial_datagrams(&data,"example.org").is_none());
        }
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
