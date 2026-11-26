//! Protected Initial packet writer for QUIC v1/v2 using rustls' RFC keys.
//! This is a bounded packet codec, not a network endpoint or TLS identity
//! proof. Initial secrets are public; no application data is allowed here.
use super::wire::{encode_varint, Version};
use rustls::{crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256, quic, Side};

pub const MIN_DATAGRAM: usize = 1200;
pub const MAX_DATAGRAM: usize = 65527;
const MAX_TOKEN: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    Limit,
    InvalidCid,
    InvalidToken,
    Crypto,
}

fn append_number(out: &mut Vec<u8>, value: u64) -> Result<(), PacketError> {
    let mut bytes = [0; 8];
    out.extend_from_slice(encode_varint(value, &mut bytes).ok_or(PacketError::Limit)?);
    Ok(())
}

/// CRYPTO frame serialization for Initial/Handshake bytes, not application data.
pub fn crypto_frame(offset: u64, data: &[u8]) -> Result<Vec<u8>, PacketError> {
    if data.len() > MAX_DATAGRAM
        || offset.checked_add(data.len() as u64).is_none_or(|n| n > super::wire::MAX_VARINT)
    {
        return Err(PacketError::Limit);
    }
    let mut out = vec![6];
    append_number(&mut out, offset)?;
    append_number(&mut out, data.len() as u64)?;
    if out.len() + data.len() > MAX_DATAGRAM {
        return Err(PacketError::Limit);
    }
    out.extend_from_slice(data);
    Ok(out)
}

/// Own one packet-number sequence for the Initial key generation. A
/// connection must never reset this writer on retransmission. Retry and
/// generation transitions remain the responsibility of the future endpoint.
pub struct Writer {
    version: Version,
    server: bool,
    keys: quic::DirectionalKeys,
    next: u64,
}

impl Writer {
    pub fn new(version: Version, initial_dcid: &[u8], side: Side) -> Result<Self, PacketError> {
        if !(8..=20).contains(&initial_dcid.len()) {
            return Err(PacketError::InvalidCid);
        }
        let suite = TLS13_AES_128_GCM_SHA256.tls13()
            .and_then(|s| s.quic_suite()).ok_or(PacketError::Crypto)?;
        let version_tls = match version {
            Version::V1 => quic::Version::V1,
            Version::V2 => quic::Version::V2,
        };
        let server = matches!(side, Side::Server);
        let keys = suite.keys(initial_dcid, side, version_tls).local;
        Ok(Self { version, server, keys, next: 0 })
    }

    /// Serialize one complete, padded Initial datagram. The caller supplies
    /// only frames legal in the Initial packet space. No UDP send occurs.
    pub fn seal(&mut self, dcid: &[u8], scid: &[u8], token: &[u8], frames: &[u8])
        -> Result<Vec<u8>, PacketError>
    {
        if dcid.len() > 20 || scid.len() > 20 || (!self.server && dcid.len() < 8) {
            return Err(PacketError::InvalidCid);
        }
        if token.len() > MAX_TOKEN || (self.server && !token.is_empty()) {
            return Err(PacketError::InvalidToken);
        }
        // Four-byte packet numbers; no truncated wrap within this foundation.
        if self.next > u64::from(u32::MAX) || frames.len() > MAX_DATAGRAM {
            return Err(PacketError::Limit);
        }
        let mut out = vec![match self.version { Version::V1 => 0xc3, Version::V2 => 0xd3 }];
        out.extend_from_slice(&self.version.wire().to_be_bytes());
        out.push(dcid.len() as u8);
        out.extend_from_slice(dcid);
        out.push(scid.len() as u8);
        out.extend_from_slice(scid);
        append_number(&mut out, token.len() as u64)?;
        out.extend_from_slice(token);
        let tag_len = self.keys.packet.tag_len();
        let sample_len = self.keys.header.sample_len();
        let mut payload_len = frames.len().max(sample_len.saturating_sub(tag_len));
        loop {
            let length = 4 + payload_len + tag_len;
            let mut encoded = [0; 8];
            let len_field = encode_varint(length as u64, &mut encoded).ok_or(PacketError::Limit)?;
            let total = out.len() + len_field.len() + length;
            if total < MIN_DATAGRAM {
                payload_len += MIN_DATAGRAM - total;
                continue;
            }
            if total > MAX_DATAGRAM {
                return Err(PacketError::Limit);
            }
            out.reserve(len_field.len() + length);
            out.extend_from_slice(len_field);
            break;
        }
        let pn_offset = out.len();
        let pn = self.next;
        // A failed sealing attempt must never allow reuse of its packet number.
        self.next += 1;
        out.extend_from_slice(&(pn as u32).to_be_bytes());
        let payload_offset = out.len();
        out.extend_from_slice(frames);
        out.resize(payload_offset + payload_len, 0);
        let (header, payload) = out.split_at_mut(payload_offset);
        let tag = self.keys.packet.encrypt_in_place(pn, header, payload)
            .map_err(|_| PacketError::Crypto)?;
        out.extend_from_slice(tag.as_ref());
        let (header, ciphertext) = out.split_at_mut(payload_offset);
        let sample = ciphertext.get(..sample_len).ok_or(PacketError::Crypto)?;
        let (first, rest) = header.split_first_mut().ok_or(PacketError::Crypto)?;
        self.keys.header.encrypt_in_place(sample, first, &mut rest[pn_offset - 1..])
            .map_err(|_| PacketError::Crypto)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality_quic_wire::{self, Flight, Inspection, Kind};

    #[test]
    fn protected_v1_v2_interoperate_with_existing_ring_observer() {
        let cid = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut hello = vec![1, 0, 0, 34];
        hello.resize(38, 0);
        for v in [Version::V1, Version::V2] {
            let mut writer = Writer::new(v, &cid, Side::Client).unwrap();
            let first = writer.seal(&cid, &[9], &[], &crypto_frame(0, &hello[..16]).unwrap()).unwrap();
            let second = writer.seal(&cid, &[9], &[], &crypto_frame(16, &hello[16..]).unwrap()).unwrap();
            assert!(first.len() >= MIN_DATAGRAM);
            assert!(second.len() >= MIN_DATAGRAM);
            let header = reality_quic_wire::long(&first).unwrap();
            assert_eq!(header.version, v.wire());
            assert_eq!(header.kind, Kind::Initial);
            assert_eq!(header.end, first.len());
            let mut flight = Flight::new(&header).unwrap();
            assert!(matches!(flight.inspect(&first), Inspection::Pending));
            assert!(matches!(flight.inspect(&second), Inspection::Hello(data) if data == hello));
            let mut changed = second.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert!(matches!(flight.inspect(&changed), Inspection::Invalid));
        }
    }

    #[test]
    fn writer_bounds_and_server_token() {
        let cid = [0; 8];
        assert!(matches!(Writer::new(Version::V1, &[], Side::Client), Err(PacketError::InvalidCid)));
        let mut writer = Writer::new(Version::V2, &cid, Side::Server).unwrap();
        assert_eq!(writer.seal(&[], &cid, &[1], &[]), Err(PacketError::InvalidToken));
        assert_eq!(writer.seal(&[0; 21], &cid, &[], &[]), Err(PacketError::InvalidCid));
        assert_eq!(writer.seal(&[], &cid, &[], &vec![0; MAX_DATAGRAM]), Err(PacketError::Limit));
        assert_eq!(crypto_frame(super::super::wire::MAX_VARINT, &[1]), Err(PacketError::Limit));
        let result = writer.seal(&[], &cid, &[], &[1]).unwrap();
        assert!(result.len() >= MIN_DATAGRAM);
        writer.next = u64::from(u32::MAX) + 1;
        assert_eq!(writer.seal(&[], &cid, &[], &[1]), Err(PacketError::Limit));
    }
}
