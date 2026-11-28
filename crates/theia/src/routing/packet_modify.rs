//! Experimental pure packet transformation; no strategy is approved for
//! production native egress until independently measured and policy-bound.
//! This narrow STUN variant changes a real credential-free Binding packet,
//! never a probe, and recomputes IPv4/IPv6 transport lengths and checksums.
use super::{
    dpi::udp::{prepare_binding, BindingStrategy},
    packet::{PacketMeta, Transport},
};
use std::borrow::Cow;

fn words(bytes: &[u8]) -> u32 {
    let (chunks, tail) = bytes.as_chunks::<2>();
    let sum = chunks
        .iter()
        .map(|p| u32::from(u16::from_be_bytes(*p)))
        .sum::<u32>();
    sum + tail.first().map_or(0, |b| u32::from(*b) << 8)
}
fn checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
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
    if meta.flow.transport != Transport::Udp
        || meta.flow.destination.port() != 3478
        || meta.flow.destination.ip().is_multicast()
        || meta.flow.destination.ip().is_unspecified()
    {
        return None;
    }
    let offset = match packet[0] >> 4 {
        4 if packet[0] == 0x45 && packet[9] == 17 && checksum(words(&packet[..20])) == 0 => 20,
        6 if packet[6] == 17 => 40,
        _ => return None,
    };
    let existing = u16::from_be_bytes(packet[offset + 6..offset + 8].try_into().ok()?);
    if existing == 0 {
        if offset == 40 {
            return None;
        }
    } else if udp_checksum(packet, offset) != 0 {
        return None;
    }
    let Cow::Owned(data) = prepare_binding(&packet[offset + 8..], BindingStrategy::Fingerprint)?
    else {
        return None;
    };
    let mut out = packet[..offset + 8].to_vec();
    out.extend_from_slice(&data);
    let udp_len = u16::try_from(out.len() - offset).ok()?;
    out[offset + 4..offset + 6].copy_from_slice(&udp_len.to_be_bytes());
    out[offset + 6..offset + 8].fill(0);
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
    out[offset + 6..offset + 8].copy_from_slice(&sum.to_be_bytes());
    let changed = PacketMeta::parse(&out, 0).ok()?;
    if changed.flow != meta.flow || changed.payload_len != meta.payload_len + 8 {
        return None;
    }
    Some(out)
}

/// Complete TCP packets with only the options whose semantics survive
/// copying onto both contiguous segments. In particular, never split
/// authenticated TCP (MD5/AO), MPTCP, SACK blocks or unknown options.
fn tcp_view(packet: &[u8]) -> Option<(PacketMeta, usize, usize)> {
    let meta = PacketMeta::parse(packet, 0).ok()?;
    if meta.flow.transport != Transport::Tcp || !matches!(meta.tcp_flags, Some(0x10 | 0x18)) {
        return None;
    }
    let off = match packet[0] >> 4 {
        4 if packet[0] == 0x45
            && packet[9] == 6
            && packet[6..8] == [0x40, 0]
            && checksum(words(&packet[..20])) == 0 =>
        {
            20
        }
        6 if packet[6] == 6 => 40,
        _ => return None,
    };
    if packet[off + 12] & 0x0f != 0 || tcp_checksum(packet, off) != 0 {
        return None;
    }
    let end = off + usize::from(packet[off + 12] >> 4) * 4;
    let mut options = packet.get(off + 20..end)?;
    let mut timestamp = false;
    while let Some(&kind) = options.first() {
        match kind {
            0 if options.iter().all(|&b| b == 0) => break,
            1 => options = &options[1..],
            8 if !timestamp && options.get(1) == Some(&10) && options.len() >= 10 => {
                timestamp = true;
                options = &options[10..];
            }
            _ => return None,
        }
    }
    Some((meta, off, end))
}

fn fix_tcp_lengths_and_checksums(packet: &mut [u8], off: usize) -> Option<()> {
    let len = packet.len();
    if off == 20 {
        packet[2..4].copy_from_slice(&u16::try_from(len).ok()?.to_be_bytes());
        packet[10..12].fill(0);
        let sum = checksum(words(&packet[..20]));
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
    } else {
        packet[4..6].copy_from_slice(&u16::try_from(len.checked_sub(40)?).ok()?.to_be_bytes());
    }
    packet[off + 16..off + 18].fill(0);
    let sum = tcp_checksum(packet, off);
    packet[off + 16..off + 18].copy_from_slice(&sum.to_be_bytes());
    Some(())
}

fn split_tcp(
    packet: &[u8],
    meta: PacketMeta,
    off: usize,
    end: usize,
    boundary: usize,
) -> Option<[Vec<u8>; 2]> {
    let payload = packet.get(end..)?;
    if boundary == 0 || boundary >= payload.len() {
        return None;
    }
    let seq = u32::from_be_bytes(packet[off + 4..off + 8].try_into().ok()?);
    let mut first = packet[..end].to_vec();
    first.extend_from_slice(&payload[..boundary]);
    first[off + 13] &= !0x08; // PSH only on last segment
    let mut second = packet[..end].to_vec();
    second.extend_from_slice(&payload[boundary..]);
    second[off + 4..off + 8].copy_from_slice(
        &seq.wrapping_add(u32::try_from(boundary).ok()?)
            .to_be_bytes(),
    );
    for out in [&mut first, &mut second] {
        fix_tcp_lengths_and_checksums(out, off)?;
        if tcp_view(out)?.0.flow != meta.flow {
            return None;
        }
    }
    Some([first, second])
}

/// Candidate TCP/TLS segmentation. Does not change the TLS byte stream,
/// ACK number or window; PSH stays on the last segment. A real backend must
/// own both emissions, retransmission and cancellation before enabling it.
/// IPv4 DF, IPv6 without extensions, TCP timestamp/NOP/padding options only.
/// Never use the expected name as proof of the application's identity.
pub fn tcp_tls_segments(packet: &[u8], expected_name: &str) -> Option<[Vec<u8>; 2]> {
    let name = super::domain_name(expected_name).ok()?;
    let (meta, off, end) = tcp_view(packet)?;
    if meta.flow.destination.port() != 443
        || meta.flow.destination.ip().is_multicast()
        || meta.flow.destination.ip().is_unspecified()
    {
        return None;
    }
    let payload = &packet[end..];
    if payload.len() <= 5 || !super::dpi::complete_packet_hello(payload, &name) {
        return None;
    }
    split_tcp(packet, meta, off, end, 5)
}

/// Bounded retransmission plan for one already-authorized split flight.
/// The owner must bind it to a live, unique kernel socket/flow generation.
/// It is not a raw sender, policy credential, or permission to replay data.
/// Retransmitted bytes must agree with the exact original sequence interval;
/// an observed cumulative ACK can only advance, and retirement is terminal.
pub struct TcpSplitPlan {
    key: super::packet::FlowKey,
    sequence: u32,
    payload: Vec<u8>,
    acknowledged: usize,
}

impl TcpSplitPlan {
    pub fn begin(packet: &[u8], expected_name: &str) -> Option<(Self, [Vec<u8>; 2])> {
        let (plan, outputs) = Self::begin_flight(&[packet], expected_name)?;
        Some((plan, outputs.try_into().ok()?))
    }

    /// Build a byte-exact split/retransmission plan from a complete,
    /// ordered, bounded first TLS flight captured before any payload send.
    /// The backend must own the live socket generation, hold all original
    /// packets, verify policy and commit once before emission. This method
    /// never transmits or authorizes packets, and rejects gaps/overlaps.
    pub fn begin_flight(packets: &[&[u8]], expected_name: &str) -> Option<(Self, Vec<Vec<u8>>)> {
        const MAX_PACKETS: usize = 32;
        const BOUNDARY: usize = 5;
        if packets.is_empty() || packets.len() > MAX_PACKETS {
            return None;
        }
        let name = super::domain_name(expected_name).ok()?;
        let (first, off, _) = tcp_view(packets[0])?;
        if first.flow.destination.port() != 443
            || first.flow.destination.ip().is_multicast()
            || first.flow.destination.ip().is_unspecified()
        {
            return None;
        }
        let sequence = u32::from_be_bytes(packets[0][off + 4..off + 8].try_into().ok()?);
        let mut payload = Vec::new();
        let mut boundary_packet = None;
        for (index, packet) in packets.iter().enumerate() {
            let (meta, off, end) = tcp_view(packet)?;
            let bytes = packet.get(end..)?;
            let start = payload.len();
            let limit = start.checked_add(bytes.len())?;
            if meta.flow != first.flow
                || bytes.is_empty()
                || limit > crate::reality_admission::MAX_HELLO
                || u32::from_be_bytes(packet[off + 4..off + 8].try_into().ok()?)
                    != sequence.wrapping_add(u32::try_from(start).ok()?)
            {
                return None;
            }
            if start < BOUNDARY && limit > BOUNDARY {
                boundary_packet = Some((index, BOUNDARY - start));
            }
            payload.extend_from_slice(bytes);
        }
        if !super::dpi::complete_packet_hello(&payload, &name) {
            return None;
        }
        // Already split at exactly this boundary is a no-op, not Modify.
        let (index, boundary) = boundary_packet?;
        let (meta, off, end) = tcp_view(packets[index])?;
        let [a, b] = split_tcp(packets[index], meta, off, end, boundary)?;
        let mut outputs = Vec::with_capacity(packets.len() + 1);
        for packet in &packets[..index] {
            outputs.push(packet.to_vec());
        }
        outputs.extend([a, b]);
        for packet in &packets[index + 1..] {
            outputs.push(packet.to_vec());
        }
        Some((
            Self {
                key: first.flow,
                sequence,
                payload,
                acknowledged: 0,
            },
            outputs,
        ))
    }

    /// Called only on a retransmission captured from the owning connection.
    /// No proactive retransmission timer: the native TCP stack owns RTO,
    /// congestion control, sequence allocation and retransmit scheduling.
    pub fn retransmission(&self, packet: &[u8]) -> Option<Vec<Vec<u8>>> {
        if self.acknowledged == self.payload.len() {
            return None;
        }
        let (meta, off, end) = tcp_view(packet)?;
        if meta.flow != self.key || meta.payload_len == 0 {
            return None;
        }
        let sequence = u32::from_be_bytes(packet[off + 4..off + 8].try_into().ok()?);
        let offset = sequence.wrapping_sub(self.sequence) as usize;
        let limit = offset.checked_add(meta.payload_len)?;
        if self.payload.get(offset..limit)? != packet.get(end..)? {
            return None;
        }
        // A retransmission crossing the original boundary must be split
        // there again. An already-segmented range remains byte exact.
        if offset < 5 && limit > 5 {
            Some(
                split_tcp(packet, meta, off, end, 5 - offset)?
                    .into_iter()
                    .collect(),
            )
        } else {
            Some(vec![packet.to_vec()])
        }
    }

    /// Observe an exact reverse-flow ACK after kernel-side corroboration.
    /// Wire checksum alone never authenticates the peer. Future ACKs outside
    /// the sent interval, wrong tuples and malformed headers cannot retire it.
    pub fn acknowledge(&mut self, packet: &[u8]) -> Option<bool> {
        let (meta, off, _) = tcp_view(packet)?;
        if meta.flow.source != self.key.destination
            || meta.flow.destination != self.key.source
            || meta.flow.transport != Transport::Tcp
        {
            return None;
        }
        let ack = u32::from_be_bytes(packet[off + 8..off + 12].try_into().ok()?);
        let progress = ack.wrapping_sub(self.sequence) as usize;
        if progress > self.payload.len() {
            return None;
        }
        self.acknowledged = self.acknowledged.max(progress);
        Some(self.acknowledged == self.payload.len())
    }
}
/// One-way execution state for a bounded, already policy-authorized raw
/// TCP split. The caller must exclusively own the capture generation and
/// packet sender, discard the held originals before the first send and
/// bind ACK/retransmission observations to the same kernel socket. This
/// type cannot establish any of those platform credentials by itself.
///
/// An unsuccessful send attempt (even of the first segment) is terminal.
/// There is no API for replaying the initial batch or choosing fallback
/// once the sender has been invoked.
#[cfg(test)]
pub(crate) struct TcpSplitExecution {
    plan: TcpSplitPlan,
    initial: Option<Vec<Vec<u8>>>,
    state: SplitState,
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum SplitState {
    Pending,
    Active,
    Complete,
    Failed,
}
#[cfg(test)]
impl TcpSplitExecution {
    pub(crate) fn prepare(packets: &[&[u8]], name: &str) -> Option<Self> {
        let (plan, initial) = TcpSplitPlan::begin_flight(packets, name)?;
        Some(Self {
            plan,
            initial: Some(initial),
            state: SplitState::Pending,
        })
    }

    /// The commit callback must irreversibly authorize Modify for the
    /// exact native flow before the first writer invocation. A denial is
    /// terminal for this execution (no original packet is returned).
    pub(crate) fn emit_initial(
        &mut self,
        commit: impl FnOnce() -> std::io::Result<()>,
        mut emit: impl FnMut(&[u8]) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        if self.state != SplitState::Pending {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        // Default to terminal before invoking any callback, including on
        // panic or partial write. Active is published only on full return.
        self.state = SplitState::Failed;
        let initial = self.initial.take().ok_or(std::io::ErrorKind::InvalidData)?;
        commit()?;
        for part in &initial {
            emit(part)?;
        }
        self.state = SplitState::Active;
        Ok(())
    }

    pub(crate) fn emit_retransmission(
        &mut self,
        packet: &[u8],
        mut emit: impl FnMut(&[u8]) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        if self.state != SplitState::Active {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        self.state = SplitState::Failed;
        let outputs = self
            .plan
            .retransmission(packet)
            .ok_or(std::io::ErrorKind::InvalidData)?;
        for part in &outputs {
            emit(part)?;
        }
        self.state = SplitState::Active;
        Ok(())
    }

    pub(crate) fn acknowledge(&mut self, packet: &[u8]) -> Option<bool> {
        if self.state != SplitState::Active {
            return None;
        }
        let complete = self.plan.acknowledge(packet)?;
        if complete {
            self.state = SplitState::Complete;
        }
        Some(complete)
    }
}

fn tcp_checksum(packet: &[u8], off: usize) -> u16 {
    let len = (packet.len() - off) as u32;
    let pseudo = if off == 20 {
        words(&packet[12..20]) + 6 + len
    } else {
        words(&packet[8..40]) + 6 + (len >> 16) + (len & 0xffff)
    };
    checksum(pseudo + words(&packet[off..]))
}

/// Candidate QUIC v1/v2 datagram de-coalescing. Authenticated Initial
/// packet and opaque subsequent long-header packets are kept byte-for-byte.
/// No packet number/nonce reuse, re-encryption, fake packet, or change to
/// CRYPTO stream bytes. Each resulting Initial remains at least 1200 bytes.
/// The actual UDP egress must own all outputs; this is not a verdict API.
pub fn quic_initial_datagrams(data: &[u8], expected_name: &str) -> Option<Vec<Vec<u8>>> {
    use crate::reality_quic_wire::{self as wire, Flight, Inspection, Kind};
    if data.len() > wire::MAX_DATAGRAM || !wire::coherent_datagram(data) {
        return None;
    }
    let first = wire::long(data)?;
    if first.kind != Kind::Initial || first.end < wire::MIN_INITIAL || first.end == data.len() {
        return None;
    }
    let expected = super::domain_name(expected_name).ok()?;
    let mut flight = Flight::new(&first)?;
    if !matches!(flight.inspect(&data[..first.end]), Inspection::Hello(message) if super::dpi::packet_quic_hello(&message, &expected))
    {
        return None;
    }
    let mut result = vec![data[..first.end].to_vec()];
    let mut offset = first.end;
    let mut zero_rtt = false;
    let mut handshake = false;
    while offset < data.len() {
        let next = wire::long(&data[offset..])?;
        if next.version != first.version || next.dcid != first.dcid || next.scid != first.scid {
            return None;
        }
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

/// Alternative for a fresh, single client Initial: split the original
/// CRYPTO frame into two offset-preserving frames inside the same packet.
/// Only public Initial keys are used; no TLS transcript, packet number,
/// CID, version, token, length or application bytes are changed. The
/// original ciphertext must never also be sent to the destination.
/// Other Initial layouts, Retry and coalesced packets fail closed here.
pub(crate) fn quic_initial_crypto_split(data: &[u8], expected_name: &str) -> Option<Vec<u8>> {
    use crate::{
        quic_core::{initial::crypto_frame, packet::Reader, wire::varint},
        reality_quic_wire::{self as wire, Flight, Inspection, Kind},
    };
    use rustls::{crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256, quic, Side};
    if !(wire::MIN_INITIAL..=wire::MAX_DATAGRAM).contains(&data.len()) {
        return None;
    }
    let long = wire::long(data)?;
    if long.kind != Kind::Initial
        || long.end != data.len()
        || !long.token.is_empty()
        || !(8..=20).contains(&long.dcid.len())
    {
        return None;
    }
    let name = super::domain_name(expected_name).ok()?;
    let mut flight = Flight::new(&long)?;
    let Inspection::Hello(hello) = flight.inspect(data) else {
        return None;
    };
    if !super::dpi::packet_quic_hello(&hello, &name) {
        return None;
    }
    let suite = TLS13_AES_128_GCM_SHA256.tls13()?.quic_suite()?;
    let version = match long.version {
        wire::V1 => quic::Version::V1,
        wire::V2 => quic::Version::V2,
        _ => return None,
    };
    let pn_offset = long.packet_number_offset();
    let mut reader = Reader::new(suite.keys(long.dcid, Side::Client, version).local);
    let opened = reader.open(data, pn_offset).ok()?;
    // Only one complete CRYPTO frame plus padding. In particular do not
    // rewrite ACKs, connection-close, Retry or unknown frame semantics.
    let mut at = 0;
    let mut crypto = None;
    while at < opened.payload.len() {
        match varint(&opened.payload, &mut at)? {
            0 => {}
            6 if crypto.is_none() => {
                if varint(&opened.payload, &mut at)? != 0 {
                    return None;
                }
                let length = usize::try_from(varint(&opened.payload, &mut at)?).ok()?;
                let end = at.checked_add(length)?;
                crypto = Some(opened.payload.get(at..end)?);
                at = end;
            }
            _ => return None,
        }
    }
    let crypto = crypto?;
    if crypto != hello.as_slice() || crypto.len() < 2 {
        return None;
    }
    let middle = crypto.len() / 2;
    let mut payload = crypto_frame(0, &crypto[..middle]).ok()?;
    payload.extend(crypto_frame(middle as u64, &crypto[middle..]).ok()?);
    if payload.len() > opened.payload.len() {
        return None;
    }
    payload.resize(opened.payload.len(), 0);
    if payload == opened.payload {
        return None;
    }
    let keys = suite.keys(long.dcid, Side::Client, version).local;
    let mut out = opened.header;
    let tag = keys.packet.encrypt_in_place(opened.number, &out, &mut payload).ok()?;
    out.extend(payload);
    out.extend_from_slice(tag.as_ref());
    let sample_start = pn_offset.checked_add(4)?;
    let sample_end = sample_start.checked_add(keys.header.sample_len())?;
    if sample_end > out.len() {
        return None;
    }
    let (prefix, suffix) = out.split_at_mut(sample_start);
    let (first, rest) = prefix.split_first_mut()?;
    keys.header.encrypt_in_place(
        &suffix[..sample_end - sample_start],
        first,
        &mut rest[pn_offset - 1..],
    ).ok()?;
    if out.len() != data.len() || out == data {
        return None;
    }
    // Round-trip the rewritten wire image before giving it to a socket.
    let new_header = wire::long(&out)?;
    let mut verify = Flight::new(&new_header)?;
    if !matches!(verify.inspect(&out), Inspection::Hello(bytes) if bytes == hello) {
        return None;
    }
    Some(out)
}

/// A shared proxy/diagnostic transformation. Prefer byte-exact datagram
/// de-coalescing; fresh standalone Initials use the CRYPTO-frame alternative.
pub(crate) fn quic_initial_transform(data: &[u8], name: &str) -> Option<Vec<Vec<u8>>> {
    quic_initial_datagrams(data, name).or_else(|| {
        quic_initial_crypto_split(data, name).map(|packet| vec![packet])
    })
}

/// An untrusted probe hint, never a domain identity. The lab accepts
/// complete v1/v2 H3 Initials only if an actual transformation is possible.
/// The caller must independently verify the exact version, not downgrade.
#[cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64")
))]
pub(crate) fn unified_quic_hint(data: &[u8]) -> Option<(String, crate::quic_core::wire::Version)> {
    use super::dpi::udp::{Candidate, Observer};
    use crate::quic_core::wire::Version;
    let (name, version) = match Observer::default().outgoing(data) {
        Candidate::QuicH3(name) => (name, Version::V1),
        Candidate::QuicV2H3(name) => (name, Version::V2),
        _ => return None,
    };
    quic_initial_datagrams(data, &name)?;
    Some((name, version))
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
            b[8..24].copy_from_slice(
                &"2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
            b[24..40].copy_from_slice(
                &"2001:db8::2"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
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
        b[offset..offset + 2].copy_from_slice(&1234u16.to_be_bytes());
        b[offset + 2..offset + 4].copy_from_slice(&3478u16.to_be_bytes());
        b[offset + 4..offset + 6].copy_from_slice(&28u16.to_be_bytes());
        b[offset + 8..offset + 16].copy_from_slice(&[0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
        b[offset + 16..offset + 28].fill(7);
        let sum = udp_checksum(&b, offset);
        b[offset + 6..offset + 8]
            .copy_from_slice(&(if sum == 0 { u16::MAX } else { sum }).to_be_bytes());
        b
    }
    #[test]
    fn tcp_segment_candidates_preserve_stream_sequence_and_checksums() {
        let hello = super::super::dpi::packet_test_hello("example.org");
        for ipv6 in [false, true] {
            let off = if ipv6 { 40 } else { 20 };
            let mut original = vec![0u8; off + 20];
            if ipv6 {
                original[0] = 0x60;
                original[6] = 6;
                original[8..24].copy_from_slice(
                    &"2001:db8::1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
                original[24..40].copy_from_slice(
                    &"2001:db8::2"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
                original[4..6].copy_from_slice(&((20 + hello.len()) as u16).to_be_bytes());
            } else {
                original[0] = 0x45;
                original[9] = 6;
                original[8] = 64;
                original[2..4].copy_from_slice(&((40 + hello.len()) as u16).to_be_bytes());
                original[6..8].copy_from_slice(&[0x40, 0]);
                original[12..16].copy_from_slice(&[192, 0, 2, 1]);
                original[16..20].copy_from_slice(&[198, 51, 100, 2]);
                let sum = checksum(words(&original[..20]));
                original[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            original[off..off + 2].copy_from_slice(&1234u16.to_be_bytes());
            original[off + 2..off + 4].copy_from_slice(&443u16.to_be_bytes());
            original[off + 4..off + 8].copy_from_slice(&(u32::MAX - 2).to_be_bytes());
            original[off + 12] = 0x50;
            original[off + 13] = 0x18;
            original.extend_from_slice(&hello);
            let sum = tcp_checksum(&original, off);
            original[off + 16..off + 18].copy_from_slice(&sum.to_be_bytes());
            // A complete ClientHello can span several captured TCP segments.
            let (meta, _, end) = tcp_view(&original).unwrap();
            let [prefix, tail] = split_tcp(&original, meta, off, end, 2).unwrap();
            let (tail_meta, _, tail_end) = tcp_view(&tail).unwrap();
            let [middle, last] = split_tcp(&tail, tail_meta, off, tail_end, 10).unwrap();
            let (flight, outputs) =
                TcpSplitPlan::begin_flight(&[&prefix, &middle, &last], "example.org").unwrap();
            assert_eq!(outputs.len(), 4);
            let restored: Vec<u8> = outputs
                .iter()
                .flat_map(|packet| {
                    let (_, _, end) = tcp_view(packet).unwrap();
                    packet[end..].iter().copied()
                })
                .collect();
            assert_eq!(restored, hello);
            assert_eq!(flight.retransmission(&middle).unwrap(), outputs[1..3]);
            assert!(TcpSplitPlan::begin_flight(&[&prefix, &last], "example.org").is_none());
            assert!(
                TcpSplitPlan::begin_flight(&[&prefix, &prefix, &middle, &last], "example.org")
                    .is_none()
            );
            assert!(
                TcpSplitPlan::begin_flight(&[&prefix, &middle, &last], "wrong.invalid").is_none()
            );
            // A partial injection or commit denial permanently consumes
            // the batch. Neither retry nor kernel retransmission is valid
            // after the writer itself reports an ambiguous failure.
            let mut execution =
                TcpSplitExecution::prepare(&[&prefix, &middle, &last], "example.org").unwrap();
            let mut writes = 0;
            assert!(execution
                .emit_initial(
                    || Ok(()),
                    |_| {
                        writes += 1;
                        if writes == 2 {
                            Err(std::io::ErrorKind::BrokenPipe.into())
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err());
            assert_eq!(writes, 2);
            assert!(execution
                .emit_initial(
                    || panic!("must not recommit"),
                    |_| panic!("must not replay")
                )
                .is_err());
            assert!(execution
                .emit_retransmission(&middle, |_| panic!("must not inject"))
                .is_err());
            let mut denied =
                TcpSplitExecution::prepare(&[&prefix, &middle, &last], "example.org").unwrap();
            assert!(denied
                .emit_initial(
                    || Err(std::io::ErrorKind::PermissionDenied.into()),
                    |_| panic!("commit denied")
                )
                .is_err());
            assert!(denied
                .emit_initial(|| Ok(()), |_| panic!("must not replay"))
                .is_err());

            let (mut plan, [a, b]) = TcpSplitPlan::begin(&original, "example.org").unwrap();
            assert!(TcpSplitPlan::begin_flight(&[&a, &b], "example.org").is_none());
            assert_eq!([&a[off + 20..], &b[off + 20..]].concat(), hello);
            assert_eq!(a[off + 13], 0x10);
            assert_eq!(b[off + 13], 0x18);
            assert_eq!(
                u32::from_be_bytes(b[off + 4..off + 8].try_into().unwrap()),
                2
            );
            assert_eq!(tcp_checksum(&a, off), 0);
            assert_eq!(tcp_checksum(&b, off), 0);
            assert!(tcp_tls_segments(&original, "other.example").is_none());
            assert_eq!(
                plan.retransmission(&original).unwrap(),
                vec![a.clone(), b.clone()]
            );
            assert_eq!(plan.retransmission(&b).unwrap(), vec![b.clone()]);
            let mut altered = b.clone();
            *altered.last_mut().unwrap() ^= 1;
            fix_tcp_lengths_and_checksums(&mut altered, off).unwrap();
            assert!(plan.retransmission(&altered).is_none());
            let mut ack = original[..off + 20].to_vec();
            if ipv6 {
                let src = ack[8..24].to_vec();
                ack.copy_within(24..40, 8);
                ack[24..40].copy_from_slice(&src);
            } else {
                let src = ack[12..16].to_vec();
                ack.copy_within(16..20, 12);
                ack[16..20].copy_from_slice(&src);
            }
            ack[off..off + 2].copy_from_slice(&443u16.to_be_bytes());
            ack[off + 2..off + 4].copy_from_slice(&1234u16.to_be_bytes());
            ack[off + 13] = 0x10;
            let base = u32::MAX - 2;
            ack[off + 8..off + 12].copy_from_slice(&base.wrapping_add(5).to_be_bytes());
            fix_tcp_lengths_and_checksums(&mut ack, off).unwrap();
            assert_eq!(plan.acknowledge(&ack), Some(false));
            assert_eq!(plan.acknowledged, 5);
            ack[off + 8..off + 12].copy_from_slice(&base.wrapping_add(1).to_be_bytes());
            fix_tcp_lengths_and_checksums(&mut ack, off).unwrap();
            assert_eq!(plan.acknowledge(&ack), Some(false));
            assert_eq!(plan.acknowledged, 5);
            ack[off + 8..off + 12]
                .copy_from_slice(&base.wrapping_add(hello.len() as u32 + 1).to_be_bytes());
            fix_tcp_lengths_and_checksums(&mut ack, off).unwrap();
            assert_eq!(plan.acknowledge(&ack), None);
            ack[off + 8..off + 12]
                .copy_from_slice(&base.wrapping_add(hello.len() as u32).to_be_bytes());
            fix_tcp_lengths_and_checksums(&mut ack, off).unwrap();
            assert_eq!(plan.acknowledge(&ack), Some(true));
            assert!(plan.retransmission(&original).is_none());
            let mut active =
                TcpSplitExecution::prepare(&[&prefix, &middle, &last], "example.org").unwrap();
            let mut written = Vec::new();
            active
                .emit_initial(
                    || Ok(()),
                    |part| {
                        written.push(part.to_vec());
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(written, outputs);
            assert!(active
                .emit_initial(
                    || panic!("must not recommit"),
                    |_| panic!("must not replay")
                )
                .is_err());
            assert_eq!(active.acknowledge(&ack), Some(true));
            assert!(active
                .emit_retransmission(&middle, |_| panic!("already acknowledged"))
                .is_err());
        }
    }

    /// Actual kernel emission and reception of the two transformed IPv4
    /// packets, on disposable loopback only. No raw egress API is exported
    /// to the product. This proves packet boundaries, not live TCP state,
    /// retransmission, NFQUEUE reinjection or independent DPI effectiveness.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires isolated Linux network namespace, CAP_NET_RAW and iproute2"]
    fn kernel_tcp_split_emits_two_real_ipv4_packets() {
        std::thread::spawn(|| {
            use std::{
                io, mem,
                os::fd::{AsRawFd, FromRawFd, OwnedFd},
                os::unix::fs::MetadataExt,
                process::Command,
            };
            let before = std::fs::metadata("/proc/thread-self/ns/net").unwrap();
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
            let after = std::fs::metadata("/proc/thread-self/ns/net").unwrap();
            assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert!(Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .unwrap()
                .success());
            fn raw(protocol: libc::c_int) -> OwnedFd {
                let fd = unsafe {
                    libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocol)
                };
                assert!(fd >= 0, "raw socket: {}", io::Error::last_os_error());
                unsafe { OwnedFd::from_raw_fd(fd) }
            }
            fn addr(ip: [u8; 4]) -> libc::sockaddr_in {
                assert_eq!(ip[0], 127); // strictly isolated local fixture
                let mut a: libc::sockaddr_in = unsafe { mem::zeroed() };
                a.sin_family = libc::AF_INET as libc::sa_family_t;
                a.sin_addr.s_addr = u32::from_ne_bytes(ip);
                a
            }
            let target = addr([127, 0, 0, 2]);
            let source = addr([127, 0, 0, 1]);
            let receiver = raw(libc::IPPROTO_TCP);
            let sender = raw(libc::IPPROTO_RAW); // IP_HDRINCL, send-only
            for (fd, address) in [(&receiver, &target), (&sender, &source)] {
                assert_eq!(
                    unsafe {
                        libc::bind(
                            fd.as_raw_fd(),
                            (address as *const libc::sockaddr_in).cast(),
                            mem::size_of_val(address) as libc::socklen_t,
                        )
                    },
                    0
                );
            }
            let wait = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        receiver.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        (&wait as *const libc::timeval).cast(),
                        mem::size_of_val(&wait) as libc::socklen_t,
                    )
                },
                0
            );
            let hello = super::super::dpi::packet_test_hello("example.org");
            let mut original = vec![0u8; 40];
            original[0] = 0x45;
            original[2..4].copy_from_slice(&((40 + hello.len()) as u16).to_be_bytes());
            original[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
            original[6..8].copy_from_slice(&[0x40, 0]);
            original[8] = 64;
            original[9] = 6;
            original[12..16].copy_from_slice(&[127, 0, 0, 1]);
            original[16..20].copy_from_slice(&[127, 0, 0, 2]);
            let sum = checksum(words(&original[..20]));
            original[10..12].copy_from_slice(&sum.to_be_bytes());
            original[20..22].copy_from_slice(&1234u16.to_be_bytes());
            original[22..24].copy_from_slice(&443u16.to_be_bytes());
            original[24..28].copy_from_slice(&100u32.to_be_bytes());
            original[32] = 0x50;
            original[33] = 0x18;
            original.extend_from_slice(&hello);
            let sum = tcp_checksum(&original, 20);
            original[36..38].copy_from_slice(&sum.to_be_bytes());
            let pair = tcp_tls_segments(&original, "example.org").unwrap();
            for part in &pair {
                let written = unsafe {
                    libc::sendto(
                        sender.as_raw_fd(),
                        part.as_ptr().cast(),
                        part.len(),
                        0,
                        (&target as *const libc::sockaddr_in).cast(),
                        mem::size_of_val(&target) as libc::socklen_t,
                    )
                };
                assert_eq!(
                    written,
                    part.len() as isize,
                    "raw send: {}",
                    io::Error::last_os_error()
                );
            }
            let mut seen = Vec::new();
            for expected in &pair {
                let mut bytes = vec![0u8; 65535];
                let read = unsafe {
                    libc::recv(
                        receiver.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        0,
                    )
                };
                assert!(read >= 40, "raw receive: {}", io::Error::last_os_error());
                bytes.truncate(read as usize);
                assert_eq!(bytes, *expected);
                assert_eq!(tcp_checksum(&bytes, 20), 0);
                seen.extend_from_slice(&bytes[40..]);
            }
            assert_eq!(seen, hello);
        })
        .join()
        .unwrap();
    }

    /// Exercise an established Linux TCP connection, not a synthetic raw
    /// four-tuple. Suppress the real first payload in NFQUEUE, emit only the
    /// first transformed segment and require the native stack to retransmit.
    /// The test uses an isolated loopback namespace and test-only raw sender;
    /// no production socket mark or unrestricted packet API is installed.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires isolated Linux namespace, nftables, CAP_NET_ADMIN/CAP_NET_RAW"]
    fn kernel_live_tcp_split_retransmission_and_ack() {
        std::thread::spawn(|| {
            use crate::routing::{nfqueue::Queue, PacketAction};
            use std::{io::{self,Read,Write}, mem, net::{TcpListener,TcpStream}, os::fd::{AsRawFd,FromRawFd,OwnedFd}, os::unix::fs::MetadataExt, process::{Command,Stdio},time::{Duration,Instant}};
            let host = std::fs::metadata("/proc/thread-self/ns/net").unwrap();
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) },0);
            let current = std::fs::metadata("/proc/thread-self/ns/net").unwrap();
            assert_ne!((host.dev(),host.ino()),(current.dev(),current.ino()));
            assert!(Command::new("ip").args(["link","set","lo","up"]).status().unwrap().success());

            let listener = TcpListener::bind("127.0.0.2:443").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            client.set_nodelay(true).unwrap();
            let (mut peer,remote) = listener.accept().unwrap();
            assert_eq!(remote,client.local_addr().unwrap());
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let client_port = remote.port();

            // The namespace contains only this fixture. A single raw socket
            // with a test-only mark avoids re-capture of the emitted segments.
            let mark = 0x54484941i32;
            let raw = unsafe { libc::socket(libc::AF_INET,libc::SOCK_RAW | libc::SOCK_CLOEXEC,libc::IPPROTO_RAW) };
            assert!(raw >= 0);
            let sender = unsafe { OwnedFd::from_raw_fd(raw) };
            assert_eq!(unsafe { libc::setsockopt(raw,libc::SOL_SOCKET,libc::SO_MARK,(&mark as *const i32).cast(),mem::size_of_val(&mark) as libc::socklen_t) },0);
            let mut target: libc::sockaddr_in = unsafe { mem::zeroed() };
            target.sin_family = libc::AF_INET as libc::sa_family_t;
            target.sin_addr.s_addr = u32::from_ne_bytes([127,0,0,2]);
            let emit = |part: &[u8]| {
                assert_eq!(part[12..20],[127,0,0,1,127,0,0,2]);
                let sent = unsafe { libc::sendto(sender.as_raw_fd(),part.as_ptr().cast(),part.len(),0,
                    (&target as *const libc::sockaddr_in).cast(),mem::size_of_val(&target) as libc::socklen_t) };
                assert_eq!(sent,part.len() as isize,"raw send: {}",io::Error::last_os_error());
            };
            let mut queue = Queue::bind(49012,128).unwrap();
            let mut nft = Command::new("nft").args(["-f","-"]).stdin(Stdio::piped()).spawn().unwrap();
            {
                let mut stdin = nft.stdin.take().unwrap();
                writeln!(stdin,"add table inet theia_tcp_live_lab").unwrap();
                writeln!(stdin,"add chain inet theia_tcp_live_lab output {{ type filter hook output priority -150; policy accept; }}").unwrap();
                writeln!(stdin,"add rule inet theia_tcp_live_lab output ip saddr 127.0.0.1 ip daddr 127.0.0.2 tcp sport {client_port} tcp dport 443 meta mark != {mark} queue num 49012").unwrap();
                writeln!(stdin,"add rule inet theia_tcp_live_lab output ip saddr 127.0.0.2 ip daddr 127.0.0.1 tcp sport 443 tcp dport {client_port} queue num 49012").unwrap();
            }
            assert!(nft.wait().unwrap().success());
            let hello = super::super::dpi::packet_test_hello("example.org");
            // Force two distinct native sends by waiting for the first
            // kernel capture before submitting the remaining bytes.
            client.write_all(&hello[..2]).unwrap();
            let deadline = Instant::now()+Duration::from_secs(12);
            let mut initial_packets = Vec::<Vec<u8>>::new();
            let mut plan: Option<TcpSplitExecution> = None;
            let mut retransmitted = false;
            let mut complete = false;
            while Instant::now() < deadline {
                let packet = match queue.receive() {
                    Ok(packet)=>packet,
                    Err(error) if matches!(error.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::TimedOut|io::ErrorKind::Interrupted)=>continue,
                    Err(error)=>panic!("NFQUEUE: {error}"),
                };
                assert!(packet.local_output());
                let meta = packet.metadata().expect("complete non-GSO TCP packet");
                let mut bytes = packet.bytes().to_vec();
                // LOCAL_OUT may carry partial checksums before software or
                // device offload. Normalize ONLY inside this owned test.
                // The production candidate still requires verified checksum.
                assert_eq!(bytes[0],0x45);
                if packet.checksum_pending() {
                    fix_tcp_lengths_and_checksums(&mut bytes,20).unwrap();
                }
                if meta.flow.source == client.local_addr().unwrap() && meta.payload_len != 0 {
                    packet.finish(PacketAction::Drop).unwrap();
                    if let Some(plan) = &mut plan {
                        plan.emit_retransmission(&bytes,|part|{emit(part);Ok(())})
                            .expect("native retransmission must match original sequence bytes");
                        retransmitted = true;
                    } else {
                        if initial_packets.is_empty() {
                            assert_eq!(meta.payload_len, 2);
                            initial_packets.push(bytes);
                            client.write_all(&hello[2..]).unwrap();
                            continue;
                        }
                        assert_eq!(initial_packets.len(), 1);
                        assert_eq!(meta.payload_len, hello.len() - 2);
                        initial_packets.push(bytes);
                        let inputs: Vec<&[u8]> = initial_packets.iter().map(Vec::as_slice).collect();
                        let mut new=TcpSplitExecution::prepare(&inputs,"example.org")
                            .expect("real multi-packet TLS payload split");
                        let mut count=0;
                        // This isolated fixture already owns the exact socket
                        // and raw sender. Simulate a network drop of the last
                        // emitted segment, not a local sender error.
                        new.emit_initial(||Ok(()),|part|{
                            count+=1;
                            if count<=2 {emit(part);}
                            Ok(())
                        }).unwrap();
                        assert_eq!(count, 3);
                        plan = Some(new);
                    }
                } else {
                    if meta.flow.source == peer.local_addr().unwrap() {
                        if let Some(plan) = &mut plan {
                            complete = plan.acknowledge(&bytes).unwrap_or(false);
                        }
                    }
                    assert_eq!(packet.finish(PacketAction::Pass).unwrap(),PacketAction::Pass);
                    if complete { break; }
                }
            }
            assert_eq!(initial_packets.len(), 2, "must observe multiple original kernel packets");
            assert!(retransmitted,"native TCP did not retransmit the lost sequence range");
            assert!(complete,"peer did not acknowledge the entire split payload");
            let mut received = vec![0;hello.len()];
            peer.read_exact(&mut received).unwrap();
            assert_eq!(received,hello);
            peer.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
            let mut extra = [0;1];
            let error = peer.read(&mut extra).unwrap_err();
            assert!(matches!(error.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::TimedOut),"duplicate application bytes");
            // Closing the queue cannot bypass its non-bypass rule; the
            // disposable namespace and all its rules vanish on thread exit.
        }).join().unwrap();
    }

    #[test]
    fn fresh_quic_initial_crypto_split_preserves_packet_and_transcript() {
        use crate::reality_quic_wire::{self as wire, Flight, Inspection};
        for version in [wire::V1, wire::V2] {
            let hello = super::super::dpi::packet_test_quic_hello("example.org");
            let input = wire::test_initial(version, &hello);
            let output = quic_initial_crypto_split(&input, "example.org").unwrap();
            assert_ne!(input, output);
            assert_eq!(input.len(), output.len());
            let a = wire::long(&input).unwrap();
            let b = wire::long(&output).unwrap();
            assert_eq!((a.version, a.dcid, a.scid, a.token), (b.version, b.dcid, b.scid, b.token));
            let mut observed = Flight::new(&b).unwrap();
            assert!(matches!(observed.inspect(&output), Inspection::Hello(bytes) if bytes == hello));
            assert!(quic_initial_crypto_split(&output, "example.org").is_none());
            assert!(quic_initial_crypto_split(&input, "wrong.example").is_none());
            let mut damaged = input.clone();
            damaged[100] ^= 1;
            assert!(quic_initial_crypto_split(&damaged, "example.org").is_none());
            assert_eq!(quic_initial_transform(&input, "example.org"), Some(vec![output]));
        }
    }

    #[test]
    fn quic_candidate_never_splits_unauthenticated_or_short_initial() {
        use crate::reality_quic_wire as wire;
        for version in [wire::V1, wire::V2] {
            let initial = wire::test_initial(
                version,
                &super::super::dpi::packet_test_quic_hello("example.org"),
            );
            assert!(quic_initial_datagrams(&initial, "example.org").is_none());
            let mut data = initial.clone();
            let header = wire::long(&initial).unwrap();
            // Opaque structurally valid subsequent Handshake packet, not
            // interpreted as an authenticated transport/control frame.
            let mut tail = vec![if version == wire::V1 { 0xe0 } else { 0xf0 }];
            tail.extend_from_slice(&version.to_be_bytes());
            tail.push(header.dcid.len() as u8);
            tail.extend_from_slice(header.dcid);
            tail.push(header.scid.len() as u8);
            tail.extend_from_slice(header.scid);
            tail.push(20);
            tail.extend([7; 20]);
            data.extend_from_slice(&tail);
            let split = quic_initial_datagrams(&data, "example.org").unwrap();
            #[cfg(target_os = "linux")]
            {
                assert!(unified_quic_hint(&initial).is_none());
                assert_eq!(
                    unified_quic_hint(&data),
                    Some((
                        "example.org".to_owned(),
                        crate::quic_core::wire::Version::from_wire(version).unwrap()
                    ))
                );
            }
            assert_eq!(split, vec![initial, tail]);
            assert_eq!(split.concat(), data);
            data[100] ^= 1;
            assert!(quic_initial_datagrams(&data, "example.org").is_none());
            #[cfg(any(
                target_os = "linux",
                all(target_os = "windows", target_arch = "x86_64")
            ))]
            assert!(unified_quic_hint(&data).is_none());
        }
    }

    /// Independently decrypt the emitted Initial using pinned aioquic.
    /// The opaque following packet is a structural fixture, not a live
    /// handshake or evidence of bypass effectiveness.
    #[test]
    #[ignore = "requires pinned aioquic from browser-e2e CI"]
    fn independent_aioquic_initial_modify_v1_v2() {
        use crate::reality_quic_wire as wire;
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        for version in [wire::V1, wire::V2] {
            let hello = super::super::dpi::packet_test_quic_hello("example.org");
            let initial = wire::test_initial(version, &hello);
            let header = wire::long(&initial).unwrap();
            let mut tail = vec![if version == wire::V1 { 0xe0 } else { 0xf0 }];
            tail.extend_from_slice(&version.to_be_bytes());
            tail.push(header.dcid.len() as u8);
            tail.extend_from_slice(header.dcid);
            tail.push(header.scid.len() as u8);
            tail.extend_from_slice(header.scid);
            tail.push(20);
            tail.extend([7; 20]);
            let input = [initial.as_slice(), tail.as_slice()].concat();
            let outputs = quic_initial_datagrams(&input, "example.org").unwrap();
            assert_eq!(outputs.len(), 2);
            assert_eq!(outputs.concat(), input);
            assert!(quic_initial_datagrams(&input, "wrong.example").is_none());
            let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/e2e/independent_quic_modify.py");
            let mut peer = Command::new("python")
                .arg(script)
                .arg(version.to_string())
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            {
                let mut stdin = peer.stdin.take().unwrap();
                let rewritten = quic_initial_crypto_split(&initial, "example.org").unwrap();
                for data in [&input, &outputs[0], &outputs[1], &hello, &rewritten] {
                    stdin.write_all(&(data.len() as u32).to_be_bytes()).unwrap();
                    stdin.write_all(data).unwrap();
                }
            }
            assert!(
                peer.wait().unwrap().success(),
                "independent Initial verification failed"
            );
        }
    }

    #[test]
    fn dual_stack_binding_transform_preserves_tuple_and_integrity() {
        for v6 in [false, true] {
            let offset = if v6 { 40 } else { 20 };
            let original = packet(v6);
            let changed = stun_fingerprint(&original).unwrap();
            assert_eq!(changed.len(), original.len() + 8);
            assert_eq!(udp_checksum(&changed, offset), 0);
            if !v6 {
                assert_eq!(checksum(words(&changed[..20])), 0);
            }
            assert_eq!(
                &changed[offset + 16..offset + 28],
                &original[offset + 16..offset + 28]
            );
            assert!(super::super::dpi::udp::plain_binding(&changed[offset + 8..]).is_some());
            assert!(stun_fingerprint(&changed).is_none());
            let mut corrupt = original.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(stun_fingerprint(&corrupt).is_none());
            for n in 0..original.len() {
                assert!(stun_fingerprint(&original[..n]).is_none());
            }
        }
    }
}
