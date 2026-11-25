//! QUIC v1/v2 public-header and Initial inspection. RFC 9000/9001/9369.
//! Initial keys are public; successful decryption is NOT address or identity
//! authentication. Never rewrite a datagram that is passed to the reference.
#![forbid(unsafe_code)]

use ring::{aead, hkdf};

pub(crate) type Cid = Vec<u8>;
pub(crate) const MAX_DATAGRAM: usize = 65527;
pub(crate) const MIN_INITIAL: usize = 1200;
pub(crate) const V1: u32 = 1;
pub(crate) const V2: u32 = 0x6b3343cf;
const MAX_CRYPTO: usize = crate::reality_admission::MAX_HELLO;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
}

#[derive(Debug)]
pub(crate) struct Long<'a> {
    pub kind: Kind,
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    pub token: &'a [u8],
    pn: usize,
    pub end: usize,
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(n)?;
    let value = bytes.get(*pos..end)?;
    *pos = end;
    Some(value)
}
fn varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *take(bytes, pos, 1)?.first()?;
    let n = 1usize << (first >> 6);
    let mut value = u64::from(first & 63);
    for &b in take(bytes, pos, n - 1)? {
        value = (value << 8) | u64::from(b);
    }
    Some(value)
}
fn cid<'a>(bytes: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = usize::from(*take(bytes, pos, 1)?.first()?);
    if len > 20 {
        return None;
    }
    take(bytes, pos, len)
}

/// Length is packet-relative, not datagram-relative. Retry and VN consume
/// the rest of the datagram and cannot be coalesced with subsequent packets.
pub(crate) fn long(bytes: &[u8]) -> Option<Long<'_>> {
    let first = *bytes.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let mut pos = 1;
    let version = u32::from_be_bytes(take(bytes, &mut pos, 4)?.try_into().ok()?);
    let dcid = cid(bytes, &mut pos)?;
    let scid = cid(bytes, &mut pos)?;
    if version == 0 {
        let rest = bytes.len().checked_sub(pos)?;
        if rest == 0 || rest % 4 != 0 {
            return None;
        }
        return Some(Long {
            kind: Kind::VersionNegotiation,
            version,
            dcid,
            scid,
            token: &[],
            pn: 0,
            end: bytes.len(),
        });
    }
    if !matches!(version, V1 | V2) {
        return None;
    }
    // RFC 9287 permits greasing the fixed bit after negotiation (including
    // remembered parameters). This is an observer parser, not an endpoint
    // accepting packets: no inference of negotiated transport parameters.
    let ty = (first >> 4) & 3;
    let kind = match (version, ty) {
        (V1, 0) | (V2, 1) => Kind::Initial,
        (V1, 1) | (V2, 2) => Kind::ZeroRtt,
        (V1, 2) | (V2, 3) => Kind::Handshake,
        _ => Kind::Retry,
    };
    if kind == Kind::Retry {
        let end = bytes.len().checked_sub(16)?;
        let token = bytes.get(pos..end)?;
        if token.is_empty() {
            return None;
        }
        return Some(Long {
            kind,
            version,
            dcid,
            scid,
            token,
            pn: 0,
            end: bytes.len(),
        });
    }
    let token = if kind == Kind::Initial {
        let n = usize::try_from(varint(bytes, &mut pos)?).ok()?;
        take(bytes, &mut pos, n)?
    } else {
        &[]
    };
    let n = usize::try_from(varint(bytes, &mut pos)?).ok()?;
    let end = pos.checked_add(n)?;
    if n < 17 || end > bytes.len() {
        return None;
    }
    Some(Long {
        kind,
        version,
        dcid,
        scid,
        token,
        pn: pos,
        end,
    })
}

/// Every packet in a coalesced datagram must have the same destination
/// CID. A trailing short header consumes the rest. No encrypted packet is
/// interpreted as an authenticated control frame. Retry/VN are standalone.
pub(crate) fn coherent_datagram(bytes: &[u8]) -> bool {
    let Some(first) = long(bytes) else {
        return false;
    };
    if matches!(first.kind, Kind::Retry | Kind::VersionNegotiation) {
        return true;
    }
    let mut offset = first.end;
    let mut packets = 1;
    while offset < bytes.len() {
        packets += 1;
        if packets > 64 {
            return false;
        }
        let tail = &bytes[offset..];
        if tail[0] & 0x80 == 0 {
            return tail.len() >= 1 + first.dcid.len() + 17
                && tail.get(1..1 + first.dcid.len()) == Some(first.dcid);
        }
        let Some(next) = long(tail) else {
            return false;
        };
        if next.dcid != first.dcid
            || next.version != first.version
            || matches!(next.kind, Kind::Retry | Kind::VersionNegotiation)
        {
            return false;
        }
        offset += next.end;
    }
    true
}

pub(crate) fn short_matches(bytes: &[u8], cid: &[u8]) -> bool {
    !cid.is_empty()
        && bytes.first().is_some_and(|b| b & 0x80 == 0)
        && bytes.len() >= 1 + cid.len() + 17
        && bytes.get(1..1 + cid.len()) == Some(cid)
}

/// Retry integrity is a public consistency check, not proof of the client's
/// address or of the reference's TLS identity. Token bytes remain opaque.
pub(crate) fn retry_valid(bytes: &[u8], original: &[u8]) -> bool {
    const KEY: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    const NONCE: [u8; 12] = [
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
    ];
    let Some(header) = long(bytes) else {
        return false;
    };
    if original.len() > 20 || header.kind != Kind::Retry {
        return false;
    }
    let (key, nonce) = match header.version {
        V1 => (KEY, NONCE),
        V2 => (
            [
                0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c,
                0xcc, 0x92,
            ],
            [
                0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
            ],
        ),
        _ => return false,
    };
    let split = bytes.len() - 16;
    let mut aad = Vec::with_capacity(1 + original.len() + split);
    aad.push(original.len() as u8);
    aad.extend_from_slice(original);
    aad.extend_from_slice(&bytes[..split]);
    let Ok(key) = aead::UnboundKey::new(&aead::AES_128_GCM, &key) else {
        return false;
    };
    let mut tag = bytes[split..].to_vec();
    aead::LessSafeKey::new(key)
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut tag,
        )
        .is_ok()
}

struct Size(usize);
impl hkdf::KeyType for Size {
    fn len(&self) -> usize {
        self.0
    }
}
fn expand<const N: usize>(key: &hkdf::Prk, label: &[u8]) -> Option<[u8; N]> {
    let mut info = Vec::with_capacity(10 + label.len());
    info.extend_from_slice(&(N as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    let parts = [info.as_slice()];
    let mut result = [0; N];
    key.expand(&parts, Size(N)).ok()?.fill(&mut result).ok()?;
    Some(result)
}
struct InitialKeys {
    hp: aead::quic::HeaderProtectionKey,
    packet: aead::LessSafeKey,
    iv: [u8; 12],
}
impl InitialKeys {
    fn client(dcid: &[u8], version: u32) -> Option<Self> {
        const SALT: [u8; 20] = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];
        const SALT_V2: [u8; 20] = [
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
            0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
        ];
        let (salt, key_label, iv_label, hp_label): (&[u8], &[u8], &[u8], &[u8]) = match version {
            V1 => (&SALT, b"quic key", b"quic iv", b"quic hp"),
            V2 => (&SALT_V2, b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
            _ => return None,
        };
        let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
        let secret = expand::<32>(&initial, b"client in")?;
        let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &secret);
        let hp = aead::quic::HeaderProtectionKey::new(
            &aead::quic::AES_128,
            &expand::<16>(&prk, hp_label)?,
        )
        .ok()?;
        let packet = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &expand::<16>(&prk, key_label)?).ok()?,
        );
        Some(Self {
            hp,
            packet,
            iv: expand::<12>(&prk, iv_label)?,
        })
    }

    fn open(
        &self,
        bytes: &[u8],
        header: &Long<'_>,
        largest: Option<u64>,
    ) -> Option<(u64, Vec<u8>)> {
        let mut packet = bytes.get(..header.end)?.to_vec();
        let sample = packet.get(header.pn + 4..header.pn + 20)?;
        let mask = self.hp.new_mask(sample).ok()?;
        packet[0] ^= mask[0] & 0x0f;
        if packet[0] & 0x0c != 0 {
            return None;
        }
        let len = usize::from(packet[0] & 3) + 1;
        let mut truncated = 0u64;
        for i in 0..len {
            let byte = packet.get_mut(header.pn + i)?;
            *byte ^= mask[i + 1];
            truncated = (truncated << 8) | u64::from(*byte);
        }
        let pn = decode_number(truncated, len, largest)?;
        let mut nonce = self.iv;
        for (a, b) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
            *a ^= b;
        }
        let (aad, ciphertext) = packet.split_at_mut(header.pn + len);
        let plain = self
            .packet
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&*aad),
                ciphertext,
            )
            .ok()?;
        Some((pn, plain.to_vec()))
    }
}
fn decode_number(truncated: u64, len: usize, largest: Option<u64>) -> Option<u64> {
    let expected = largest.map_or(0, |n| n + 1);
    let window = 1u64 << (len * 8);
    let half = window / 2;
    let mut candidate = (expected & !(window - 1)) | truncated;
    if candidate + half <= expected && candidate < (1u64 << 62) - window {
        candidate += window;
    } else if candidate > expected + half && candidate >= window {
        candidate -= window;
    }
    (candidate < (1u64 << 62)).then_some(candidate)
}

pub(crate) enum Inspection {
    Pending,
    Hello(Vec<u8>),
    Invalid,
}

/// A bounded reassembler for a single client Initial packet-number space.
/// Overlapping CRYPTO data must agree byte for byte; never fill gaps by
/// guessing. Retransmissions are harmless and do not grow memory.
pub(crate) struct Flight {
    keys: InitialKeys,
    version: u32,
    dcid: Cid,
    scid: Cid,
    largest: Option<u64>,
    crypto: Vec<Option<u8>>,
    contiguous: usize,
}
impl Flight {
    pub fn new(header: &Long<'_>) -> Option<Self> {
        if header.kind != Kind::Initial || header.dcid.len() < 8 {
            return None;
        }
        Some(Self {
            keys: InitialKeys::client(header.dcid, header.version)?,
            version: header.version,
            dcid: header.dcid.to_vec(),
            scid: header.scid.to_vec(),
            largest: None,
            crypto: vec![None; MAX_CRYPTO],
            contiguous: 0,
        })
    }
    pub fn inspect(&mut self, datagram: &[u8]) -> Inspection {
        if datagram.len() < MIN_INITIAL || !coherent_datagram(datagram) {
            return Inspection::Invalid;
        }
        let mut offset = 0;
        let mut seen = false;
        while offset < datagram.len() {
            let Some(header) = long(&datagram[offset..]) else {
                break;
            };
            if header.kind == Kind::Initial {
                if header.version != self.version
                    || header.dcid != self.dcid
                    || header.scid != self.scid
                {
                    return Inspection::Invalid;
                }
                let Some((pn, plain)) = self.keys.open(&datagram[offset..], &header, self.largest)
                else {
                    return Inspection::Invalid;
                };
                self.largest = Some(self.largest.map_or(pn, |n| n.max(pn)));
                if self.frames(&plain).is_none() {
                    return Inspection::Invalid;
                }
                seen = true;
            }
            offset += header.end;
        }
        if !seen {
            return Inspection::Invalid;
        }
        while self.contiguous < self.crypto.len() && self.crypto[self.contiguous].is_some() {
            self.contiguous += 1;
        }
        if self.contiguous == 0 {
            return Inspection::Pending;
        }
        if self.crypto[0] != Some(1) {
            return Inspection::Invalid;
        }
        if self.contiguous < 4 {
            return Inspection::Pending;
        }
        let total = 4
            + (usize::from(self.crypto[1].unwrap_or(0)) << 16)
            + (usize::from(self.crypto[2].unwrap_or(0)) << 8)
            + usize::from(self.crypto[3].unwrap_or(0));
        if !(38..=MAX_CRYPTO).contains(&total) {
            return Inspection::Invalid;
        }
        if self.contiguous < total {
            return Inspection::Pending;
        }
        Inspection::Hello(
            self.crypto[..total]
                .iter()
                .map(|b| b.unwrap_or(0))
                .collect(),
        )
    }

    fn frames(&mut self, bytes: &[u8]) -> Option<()> {
        let mut pos = 0;
        while pos < bytes.len() {
            match varint(bytes, &mut pos)? {
                0 | 1 => {} // PADDING, PING
                kind @ (2 | 3) => {
                    let mut low = varint(bytes, &mut pos)?;
                    varint(bytes, &mut pos)?; // ACK delay
                    let count = varint(bytes, &mut pos)?;
                    low = low.checked_sub(varint(bytes, &mut pos)?)?;
                    if count > 256 {
                        return None;
                    }
                    for _ in 0..count {
                        low = low.checked_sub(varint(bytes, &mut pos)?.checked_add(2)?)?;
                        low = low.checked_sub(varint(bytes, &mut pos)?)?;
                    }
                    if kind == 3 {
                        for _ in 0..3 {
                            varint(bytes, &mut pos)?;
                        }
                    }
                }
                6 => {
                    let start = usize::try_from(varint(bytes, &mut pos)?).ok()?;
                    let len = usize::try_from(varint(bytes, &mut pos)?).ok()?;
                    let data = take(bytes, &mut pos, len)?;
                    let slots = self.crypto.get_mut(start..start.checked_add(len)?)?;
                    for (slot, &byte) in slots.iter_mut().zip(data) {
                        if slot.is_some_and(|old| old != byte) {
                            return None;
                        }
                        *slot = Some(byte);
                    }
                }
                0x1c => {
                    varint(bytes, &mut pos)?;
                    varint(bytes, &mut pos)?;
                    let len = usize::try_from(varint(bytes, &mut pos)?).ok()?;
                    take(bytes, &mut pos, len)?;
                }
                _ => return None,
            }
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn rfc9001_retry_vector_and_mutations() {
        let dcid = hex("8394c8f03e515708");
        let retry = hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        assert!(retry_valid(&retry, &dcid));
        let mut bad = retry.clone();
        bad[20] ^= 1;
        assert!(!retry_valid(&bad, &dcid));
        assert!(!retry_valid(&retry, &[0; 8]));
        for n in 0..retry.len() {
            assert!(!retry_valid(&retry[..n], &dcid));
        }
    }
    #[test]
    fn rfc9001_client_key_derivation() {
        let dcid = hex("8394c8f03e515708");
        let keys = InitialKeys::client(&dcid, V1).unwrap();
        assert_eq!(keys.iv.as_slice(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(
            keys.hp
                .new_mask(&hex("d1b1c98dd7689fb8ec11d242b123dc9b"))
                .unwrap()
                .as_slice(),
            hex("437b9aec36")
        );
        assert_eq!(decode_number(0, 1, Some(255)), Some(256));
        assert_eq!(decode_number(255, 1, Some(256)), Some(255));
    }
    #[test]
    fn rfc9369_retry_and_initial_key_vectors() {
        let dcid = hex("8394c8f03e515708");
        let retry = hex("cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6");
        assert_eq!(long(&retry).unwrap().version, V2);
        assert!(retry_valid(&retry, &dcid));
        let mut bad = retry.clone();
        bad[20] ^= 1;
        assert!(!retry_valid(&bad, &dcid));
        assert!(!retry_valid(&retry, &[0; 8]));
        let keys = InitialKeys::client(&dcid, V2).unwrap();
        assert_eq!(keys.iv.as_slice(), hex("91f73e2351d8fa91660e909f"));
        assert!(InitialKeys::client(&dcid, 0).is_none());
    }
    #[test]
    fn reassembly_rejects_conflicting_overlap_and_limits() {
        let raw = [
            0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 9, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let h = long(&raw).unwrap();
        let mut flight = Flight::new(&h).unwrap();
        assert!(flight.frames(&[6, 2, 2, 0, 34]).is_some());
        assert!(flight.frames(&[6, 0, 2, 1, 0]).is_some());
        assert!(flight.frames(&[6, 2, 2, 0, 34]).is_some());
        assert!(flight.frames(&[6, 2, 1, 1]).is_none());
        // 32767 is encoded as a four-byte QUIC varint; one byte fits, two do not.
        assert!(flight.frames(&[6, 0x80, 0, 0x7f, 0xff, 1, 0]).is_some());
        assert!(flight.frames(&[6, 0x80, 0, 0x7f, 0xff, 2, 0, 0]).is_none());
        for n in 0..raw.len() {
            assert!(long(&raw[..n]).is_none());
        }
    }

    fn initial_packet(pn: u16, frames: &[u8], version: u32) -> Vec<u8> {
        let dcid = [1, 2, 3, 4, 5, 6, 7, 8];
        let keys = InitialKeys::client(&dcid, version).unwrap();
        let mut packet = vec![if version == V1 { 0xc1 } else { 0xd1 }];
        packet.extend_from_slice(&version.to_be_bytes());
        packet.push(8);
        packet.extend_from_slice(&dcid);
        packet.extend_from_slice(&[8, 9, 10, 11, 12, 13, 14, 15, 16, 0]);
        // Two-byte length, two-byte packet number, 16-byte tag.
        let payload_len = MIN_INITIAL - packet.len() - 2 - 2 - 16;
        let length = (payload_len + 2 + 16) as u16 | 0x4000;
        packet.extend_from_slice(&length.to_be_bytes());
        let offset = packet.len();
        packet.extend_from_slice(&pn.to_be_bytes());
        let mut plain = frames.to_vec();
        plain.resize(payload_len, 0);
        let mut nonce = keys.iv;
        for (a, b) in nonce[4..].iter_mut().zip(u64::from(pn).to_be_bytes()) {
            *a ^= b;
        }
        keys.packet
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(packet.as_slice()),
                &mut plain,
            )
            .unwrap();
        packet.extend_from_slice(&plain);
        let mask = keys.hp.new_mask(&packet[offset + 4..offset + 20]).unwrap();
        packet[0] ^= mask[0] & 15;
        packet[offset] ^= mask[1];
        packet[offset + 1] ^= mask[2];
        assert_eq!(packet.len(), MIN_INITIAL);
        packet
    }

    #[test]
    fn encrypted_initials_reassemble_out_of_order_without_modifying_datagrams() {
        let mut hello = vec![1, 0, 0, 34];
        hello.extend_from_slice(&[7; 34]);
        let mut tail = vec![6, 12, 26];
        tail.extend_from_slice(&hello[12..]);
        let mut head = vec![6, 0, 12];
        head.extend_from_slice(&hello[..12]);
        let second = initial_packet(1, &tail, V1);
        let first = initial_packet(0, &head, V1);
        let mut flight = Flight::new(&long(&second).unwrap()).unwrap();
        assert!(matches!(flight.inspect(&second), Inspection::Pending));
        assert!(matches!(flight.inspect(&second), Inspection::Pending));
        assert!(matches!(flight.inspect(&first), Inspection::Hello(value) if value == hello));
        let v2 = initial_packet(0, &head, V2);
        let v2_tail = initial_packet(1, &tail, V2);
        let mut flight = Flight::new(&long(&v2).unwrap()).unwrap();
        assert!(matches!(flight.inspect(&v2), Inspection::Pending));
        assert!(matches!(flight.inspect(&v2_tail),Inspection::Hello(value) if value==hello));
        assert!(matches!(
            Flight::new(&long(&v2).unwrap()).unwrap().inspect(&first),
            Inspection::Invalid
        ));
        let mut forged = first.clone();
        forged[1199] ^= 1;
        assert!(matches!(
            Flight::new(&long(&forged).unwrap())
                .unwrap()
                .inspect(&forged),
            Inspection::Invalid
        ));
    }
}
