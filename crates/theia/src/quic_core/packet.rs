//! Packet protection using rustls keys. Each Reader/Writer belongs to
//! exactly one packet-number space and key generation. This codec is not
//! an endpoint; CID/version routing, key updates and TLS admission are external.
use super::wire::{decode_number, MAX_VARINT};
use rustls::quic::DirectionalKeys;

const MAX_PACKET: usize = 65527;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Header,
    Limit,
    Crypto,
    Duplicate,
    TooOld,
    Reserved,
}

#[derive(Default)]
pub struct ReplayWindow {
    largest: Option<u64>,
    bits: u128,
}

impl ReplayWindow {
    pub fn largest(&self) -> Option<u64> { self.largest }

    /// Call only after successful packet protection verification.
    pub fn accept(&mut self, number: u64) -> Result<(), Error> {
        if number > MAX_VARINT { return Err(Error::Limit); }
        match self.largest {
            None => { self.largest = Some(number); self.bits = 1; }
            Some(old) if number > old => {
                let shift = number - old;
                self.bits = if shift >= 128 { 1 } else { (self.bits << shift) | 1 };
                self.largest = Some(number);
            }
            Some(old) => {
                let age = old - number;
                if age >= 128 { return Err(Error::TooOld); }
                let mask = 1u128 << age;
                if self.bits & mask != 0 { return Err(Error::Duplicate); }
                self.bits |= mask;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Opened {
    pub number: u64,
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
}

pub struct Reader {
    keys: DirectionalKeys,
    replay: ReplayWindow,
    failures: u64,
}

impl Reader {
    pub fn new(keys: DirectionalKeys) -> Self {
        Self { keys, replay: ReplayWindow::default(), failures: 0 }
    }

    /// pn_offset and packet boundaries must be obtained from a validated
    /// outer header. Initial keys are public, so their AEAD does not
    /// authenticate the peer. No short-header key update is performed here.
    pub fn open(&mut self, packet: &[u8], pn_offset: usize) -> Result<Opened, Error> {
        if self.failures >= self.keys.packet.integrity_limit() { return Err(Error::Limit); }
        if packet.len() > MAX_PACKET || pn_offset == 0 { return Err(Error::Header); }
        let sample_start = pn_offset.checked_add(4).ok_or(Error::Header)?;
        let sample_end = sample_start.checked_add(self.keys.header.sample_len()).ok_or(Error::Header)?;
        if sample_end > packet.len() { return Err(Error::Header); }
        let mut data = packet.to_vec();
        {
            let (prefix, suffix) = data.split_at_mut(sample_start);
            let (first, rest) = prefix.split_first_mut().ok_or(Error::Header)?;
            self.keys.header.decrypt_in_place(
                &suffix[..sample_end - sample_start], first, &mut rest[pn_offset - 1..],
            ).map_err(|_| Error::Crypto)?;
        }
        let first = data[0];
        let pn_len = usize::from(first & 3) + 1;
        let payload_start = pn_offset + pn_len;
        let number = data[pn_offset..payload_start].iter().fold(0u64, |n, b| (n << 8) | u64::from(*b));
        let number = decode_number(number, pn_len, self.replay.largest()).ok_or(Error::Header)?;
        if data.len() - payload_start < self.keys.packet.tag_len() { return Err(Error::Header); }
        let (header, ciphertext) = data.split_at_mut(payload_start);
        let plain = match self.keys.packet.decrypt_in_place(number, header, ciphertext) {
            Ok(plain) => plain,
            Err(_) => { self.failures = self.failures.saturating_add(1); return Err(Error::Crypto); }
        };
        // Reserved bits are checked only after AEAD succeeds.
        let reserved = if first & 0x80 != 0 { 0x0c } else { 0x18 };
        if first & reserved != 0 { return Err(Error::Reserved); }
        self.replay.accept(number)?;
        Ok(Opened { number, header: header.to_vec(), payload: plain.to_vec() })
    }
}

/// Monotonic packet-number allocation and protection for a single space.
/// The supplied header must already contain a correct packet length, where
/// applicable, and a 4-byte packet-number field at its end.
pub struct Writer {
    keys: DirectionalKeys,
    next: u64,
}

impl Writer {
    pub fn new(keys: DirectionalKeys) -> Self { Self { keys, next: 0 } }

    pub fn seal(&mut self, header: &[u8], payload: &[u8]) -> Result<(u64, Vec<u8>), Error> {
        if header.len() < 5 || header[0] & 3 != 3 { return Err(Error::Header); }
        let reserved = if header[0] & 0x80 != 0 { 0x0c } else { 0x18 };
        if header[0] & reserved != 0 { return Err(Error::Reserved); }
        let total = header.len().checked_add(payload.len()).and_then(|n| n.checked_add(self.keys.packet.tag_len())).ok_or(Error::Limit)?;
        if total > MAX_PACKET || self.next > u64::from(u32::MAX)
            || self.next >= self.keys.packet.confidentiality_limit() { return Err(Error::Limit); }
        if payload.len().saturating_add(self.keys.packet.tag_len()) < self.keys.header.sample_len() {
            return Err(Error::Header);
        }
        let number = self.next;
        self.next += 1;
        let pn_offset = header.len() - 4;
        let mut data = Vec::with_capacity(total);
        data.extend_from_slice(&header[..pn_offset]);
        data.extend_from_slice(&(number as u32).to_be_bytes());
        data.extend_from_slice(payload);
        let (prefix, plain) = data.split_at_mut(header.len());
        let tag = self.keys.packet.encrypt_in_place(number, prefix, plain).map_err(|_| Error::Crypto)?;
        data.extend_from_slice(tag.as_ref());
        let (prefix, suffix) = data.split_at_mut(header.len());
        let (first, rest) = prefix.split_first_mut().ok_or(Error::Header)?;
        self.keys.header.encrypt_in_place(&suffix[..self.keys.header.sample_len()], first, &mut rest[pn_offset - 1..])
            .map_err(|_| Error::Crypto)?;
        Ok((number, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256, quic, Side};

    #[test]
    fn replay_window_reordering_and_bounds() {
        let mut r = ReplayWindow::default();
        assert_eq!(r.accept(0), Ok(()));
        assert_eq!(r.accept(2), Ok(()));
        assert_eq!(r.accept(1), Ok(()));
        assert_eq!(r.accept(1), Err(Error::Duplicate));
        assert_eq!(r.accept(130), Ok(()));
        assert_eq!(r.accept(2), Err(Error::TooOld));
        assert_eq!(r.accept(129), Ok(()));
        assert_eq!(r.accept(u64::MAX), Err(Error::Limit));
    }

    #[test]
    fn packet_protection_tamper_reorder_and_replay() {
        let suite = TLS13_AES_128_GCM_SHA256.tls13().unwrap().quic_suite().unwrap();
        for version in [quic::Version::V1, quic::Version::V2] {
            let cid = [1; 8];
            let c = suite.keys(&cid, Side::Client, version);
            let s = suite.keys(&cid, Side::Server, version);
            // Use a short-header-shaped fixture with public test keys only.
            let mut writer = Writer::new(c.local);
            let mut reader = Reader::new(s.remote);
            let header = [0x43, 1, 2, 3, 4, 0, 0, 0, 0];
            let (_, a) = writer.seal(&header, b"first").unwrap();
            let (_, b) = writer.seal(&header, b"second").unwrap();
            let mut bad = b.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert_eq!(reader.open(&bad, 5), Err(Error::Crypto));
            assert_eq!(reader.open(&b, 5).unwrap().number, 1);
            assert_eq!(reader.open(&a, 5).unwrap().payload, b"first");
            assert_eq!(reader.open(&a, 5), Err(Error::Duplicate));
            assert_eq!(reader.open(&[], usize::MAX), Err(Error::Header));
        }
    }
}
