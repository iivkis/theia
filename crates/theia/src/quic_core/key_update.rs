//! Independent 1-RTT key-phase codec. The endpoint must supply authenticated
//! ACKs, handshake confirmation and the old-key retirement deadline.
//! Used by the isolated loopback endpoint; not a production key lifecycle.
use super::{packet::{Error, Opened, ReplayWindow}, wire::decode_number};
use rustls::quic::{DirectionalKeys, HeaderProtectionKey, PacketKey, Secrets};
use std::time::Instant;

const MAX_PACKET: usize = 65527;

pub struct Sender {
    keys: DirectionalKeys,
    secrets: Secrets,
    next: u64,
    first: u64,
    phase: bool,
    acknowledged: bool,
    generation: u64,
}

impl Sender {
    pub fn new(keys: DirectionalKeys, secrets: Secrets) -> Self {
        Self { keys, secrets, next: 0, first: 0, phase: false, acknowledged: false, generation: 0 }
    }

    /// The caller must validate the ACK against its sent-packet ledger.
    pub fn acknowledged(&mut self, number: u64) {
        if number >= self.first && number < self.next { self.acknowledged = true; }
    }

    pub fn update(&mut self, handshake_confirmed: bool) -> Result<(), Error> {
        if !handshake_confirmed || !self.acknowledged { return Err(Error::Crypto); }
        self.advance()
    }

    /// The caller obtained generation from an authenticated receive-key
    /// transition. A response is not a new locally initiated update.
    pub(crate) fn respond(&mut self, generation: u64) -> Result<(), Error> {
        if generation <= self.generation { return Ok(()); }
        if self.generation.checked_add(1) != Some(generation) { return Err(Error::Crypto); }
        self.advance()
    }

    fn advance(&mut self) -> Result<(), Error> {
        self.generation = self.generation.checked_add(1).ok_or(Error::Limit)?;
        self.keys.packet = self.secrets.next_packet_keys().local;
        self.first = self.next;
        self.phase = !self.phase;
        self.acknowledged = false;
        Ok(())
    }

    /// Fixed four-byte packet number encoding, short header only.
    /// The header-protection key is intentionally not changed.
    pub fn seal(&mut self, cid: &[u8], payload: &[u8]) -> Result<(u64, Vec<u8>), Error> {
        if cid.is_empty() || cid.len() > 20 || payload.is_empty() { return Err(Error::Header); }
        let tag_len = self.keys.packet.tag_len();
        let sample_len = self.keys.header.sample_len();
        let size = 1 + cid.len() + 4 + tag_len;
        if payload.len() > MAX_PACKET - size || payload.len().saturating_add(tag_len) < sample_len
            || self.next > u64::from(u32::MAX)
            || self.next - self.first >= self.keys.packet.confidentiality_limit() {
            return Err(Error::Limit);
        }
        let pn = self.next;
        self.next += 1;
        let mut bytes = Vec::with_capacity(size + payload.len());
        bytes.push(0x43 | if self.phase { 0x04 } else { 0 });
        bytes.extend_from_slice(cid);
        bytes.extend_from_slice(&(pn as u32).to_be_bytes());
        let offset = bytes.len();
        bytes.extend_from_slice(payload);
        let (header, plain) = bytes.split_at_mut(offset);
        let tag = self.keys.packet.encrypt_in_place(pn, header, plain).map_err(|_| Error::Crypto)?;
        bytes.extend_from_slice(tag.as_ref());
        let (header, suffix) = bytes.split_at_mut(offset);
        let (first, rest) = header.split_first_mut().ok_or(Error::Header)?;
        self.keys.header.encrypt_in_place(&suffix[..sample_len], first, &mut rest[cid.len()..])
            .map_err(|_| Error::Crypto)?;
        Ok((pn, bytes))
    }
}

struct Previous {
    key: Box<dyn PacketKey>,
    expires: Instant,
}

pub struct Receiver {
    header: Box<dyn HeaderProtectionKey>,
    current: Box<dyn PacketKey>,
    next: Box<dyn PacketKey>,
    secrets: Secrets,
    previous: Option<Previous>,
    phase: bool,
    first_current: u64,
    replay: ReplayWindow,
    failures: u64,
    generation: u64,
}

impl Receiver {
    pub fn new(keys: DirectionalKeys, mut secrets: Secrets) -> Self {
        let next = secrets.next_packet_keys().remote;
        Self { header: keys.header, current: keys.packet, next, secrets, previous: None,
            phase: false, first_current: 0, replay: ReplayWindow::default(), failures: 0, generation: 0 }
    }

    pub fn generation(&self) -> u64 { self.generation }

    pub fn retirement_deadline(&self) -> Option<Instant> { self.previous.as_ref().map(|p| p.expires) }

    pub fn expire(&mut self, now: Instant) {
        if self.previous.as_ref().is_some_and(|p| now >= p.expires) {
            self.previous = None;
        }
    }

    /// A valid packet in the next phase advances the receive generation.
    /// A reordered previous-phase packet remains eligible only below the
    /// first accepted packet number of the new phase, until retirement.
    /// A failed AEAD never advances the phase or replay state.
    pub fn open(&mut self, cid: &[u8], packet: &[u8], now: Instant,
                old_key_deadline: Instant, handshake_confirmed: bool) -> Result<Opened, Error> {
        self.expire(now);
        if packet.len() > MAX_PACKET || cid.is_empty() || cid.len() > 20
            || packet.first().is_none_or(|b| b & 0xc0 != 0x40)
            || packet.get(1..1 + cid.len()) != Some(cid) {
            return Err(Error::Header);
        }
        if self.failures >= self.current.integrity_limit() { return Err(Error::Limit); }
        let pn_offset = 1 + cid.len();
        let sample_start = pn_offset + 4;
        let sample_len = self.header.sample_len();
        if packet.len() < sample_start + sample_len { return Err(Error::Header); }
        let mut bytes = packet.to_vec();
        let (prefix, suffix) = bytes.split_at_mut(sample_start);
        let (first, rest) = prefix.split_first_mut().ok_or(Error::Header)?;
        self.header.decrypt_in_place(&suffix[..sample_len], first, &mut rest[cid.len()..])
            .map_err(|_| Error::Crypto)?;
        let first = bytes[0];
        let pn_len = usize::from(first & 3) + 1;
        let end = pn_offset + pn_len;
        let truncated = bytes[pn_offset..end].iter().fold(0u64, |n, b| (n << 8) | u64::from(*b));
        let pn = decode_number(truncated, pn_len, self.replay.largest()).ok_or(Error::Header)?;
        let phase = first & 4 != 0;
        let is_next = phase != self.phase && pn >= self.first_current
            && self.replay.largest().is_none_or(|largest| pn > largest);
        let key = if phase == self.phase {
            &self.current
        } else if pn < self.first_current {
            &self.previous.as_ref().ok_or(Error::TooOld)?.key
        } else if is_next && handshake_confirmed && old_key_deadline > now {
            &self.next
        } else {
            return Err(Error::Crypto);
        };
        let (header, ciphertext) = bytes.split_at_mut(end);
        let plain = match key.decrypt_in_place(pn, header, ciphertext) {
            Ok(plain) => plain.to_vec(),
            Err(_) => {
                self.failures = self.failures.saturating_add(1);
                return Err(Error::Crypto);
            }
        };
        if first & 0x18 != 0 { return Err(Error::Reserved); }
        self.replay.accept(pn)?;
        if is_next {
            self.generation = self.generation.checked_add(1).ok_or(Error::Limit)?;
            let next = self.secrets.next_packet_keys().remote;
            let old = std::mem::replace(&mut self.current, std::mem::replace(&mut self.next, next));
            self.previous = Some(Previous { key: old, expires: old_key_deadline });
            self.phase = phase;
            self.first_current = pn;
        } else if phase == self.phase && pn < self.first_current {
            // The first received packet may not be the first sent in the
            // generation. Successful decryption establishes the lower bound.
            self.first_current = pn;
        }
        Ok(Opened { number: pn, header: header.to_vec(), payload: plain })
    }
}
