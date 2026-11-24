//! F-18 v1 admission candidate. The marker authenticates an exact TLS
//! ClientHello before normal TLS authentication. A backend must call seal
//! BEFORE the TLS transcript is committed; rewriting emitted TLS bytes
//! is not supported. No listener or client backend is enabled here.
#![forbid(unsafe_code)]

use crate::{config, descriptor::Scope, identity_tls::Branch};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use std::{collections::{HashMap, HashSet}, sync::Mutex};
use zeroize::Zeroizing;

pub const MAX_HELLO: usize = 32 * 1024;
const RANDOM_START: usize = 6;
const RANDOM_END: usize = 38;
const WINDOW: u64 = 120;
const NONCE_LEN: usize = 12;
const DOMAIN: &[u8] = b"Theia/SmartReality/admission/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Format,
    Scope,
    Crypto,
    Clock,
    Replay,
    Capacity,
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < count {
            return Err(Error::Format);
        }
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<usize, Error> {
        Ok(usize::from(self.take(1)?[0]))
    }
    fn u16(&mut self) -> Result<usize, Error> {
        let raw = self.take(2)?;
        Ok(usize::from(u16::from_be_bytes([raw[0], raw[1]])))
    }
    fn vector8(&mut self) -> Result<&'a [u8], Error> {
        let size = self.u8()?;
        self.take(size)
    }
    fn vector16(&mut self) -> Result<&'a [u8], Error> {
        let size = self.u16()?;
        self.take(size)
    }
    fn finish(self) -> Result<(), Error> {
        if self.0.is_empty() { Ok(()) } else { Err(Error::Format) }
    }
}

fn alpn(branch: Branch) -> &'static [u8] {
    match branch { Branch::H2 => b"h2", Branch::H3 => b"h3" }
}

/// Inspect the complete first TLS handshake message, not TLS records or
/// QUIC packets. The transport adapter is responsible for bounded reassembly.
fn validate_hello(hello: &[u8], name: &str, branch: Branch) -> Result<(), Error> {
    if hello.len() < RANDOM_END || hello.len() > MAX_HELLO
        || hello[0] != 1
        || ((usize::from(hello[1]) << 16) | (usize::from(hello[2]) << 8) | usize::from(hello[3])) != hello.len() - 4
        || !config::valid_dns(name)
    {
        return Err(Error::Format);
    }
    let mut c = Cursor(&hello[4..]);
    if c.take(2)? != [3, 3] {
        return Err(Error::Format);
    }
    c.take(32)?;
    let session = c.vector8()?;
    if session.len() > 32 || (branch == Branch::H3 && !session.is_empty()) {
        return Err(Error::Format);
    }
    let suites = c.vector16()?;
    if suites.is_empty() || suites.len() % 2 != 0 || c.vector8()? != [0] {
        return Err(Error::Format);
    }
    let mut extensions = Cursor(c.vector16()?);
    c.finish()?;
    let mut types = HashSet::new();
    let (mut sni, mut protocol, mut tls13, mut x25519) = (false, false, false, false);
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vector16()?;
        if !types.insert(kind) {
            return Err(Error::Format);
        }
        let mut field = Cursor(data);
        match kind {
            0 => {
                let mut names = Cursor(field.vector16()?);
                field.finish()?;
                if names.u8()? != 0 || names.vector16()? != name.as_bytes() {
                    return Err(Error::Scope);
                }
                names.finish()?;
                sni = true;
            }
            16 => {
                let mut protocols = Cursor(field.vector16()?);
                field.finish()?;
                while !protocols.0.is_empty() {
                    let value = protocols.vector8()?;
                    if value.is_empty() { return Err(Error::Format); }
                    protocol |= value == alpn(branch);
                }
            }
            43 => {
                let versions = field.vector8()?;
                field.finish()?;
                if versions.is_empty() || versions.len() % 2 != 0 {
                    return Err(Error::Format);
                }
                tls13 = versions.chunks_exact(2).any(|pair| pair == [3, 4]);
            }
            51 => {
                let mut shares = Cursor(field.vector16()?);
                field.finish()?;
                let mut groups = HashSet::new();
                while !shares.0.is_empty() {
                    let group = shares.u16()?;
                    let public = shares.vector16()?;
                    if public.is_empty() || !groups.insert(group) { return Err(Error::Format); }
                    if group == 29 {
                        if public.len() != 32 || public.iter().all(|byte| *byte == 0) {
                            return Err(Error::Format);
                        }
                        x25519 = true;
                    }
                }
            }
            // PSK and early_data forbidden for this contract.
            41 | 42 => return Err(Error::Format),
            _ => {}
        }
    }
    if sni && protocol && tls13 && x25519 {
        Ok(())
    } else {
        Err(Error::Format)
    }
}

/// Dedicated per-inbound random secret, independently provisioned.
/// Possession grants handshake admission only; the pinned identity and
/// per-tunnel bearer/grants still apply. No key material in Debug/logs.
pub struct Secret(Zeroizing<[u8; 32]>);
impl Secret {
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        SystemRandom::new().fill(bytes.as_mut()).map_err(|_| Error::Crypto)?;
        Self::new(*bytes)
    }
    pub fn new(bytes: [u8; 32]) -> Result<Self, Error> {
        if bytes == [0; 32] { return Err(Error::Crypto); }
        Ok(Self(Zeroizing::new(bytes)))
    }
    fn key(&self) -> Result<LessSafeKey, Error> {
        UnboundKey::new(&aead::CHACHA20_POLY1305, self.0.as_ref())
            .map(LessSafeKey::new).map_err(|_| Error::Crypto)
    }
}

pub struct Context<'a> {
    pub scope: &'a Scope,
    pub identity: [u8; 32],
    pub reference: &'a str,
    pub branch: Branch,
}

impl Context<'_> {
    fn aad(&self, hello: &[u8]) -> Result<Vec<u8>, Error> {
        if !config::valid_id(&self.scope.inbound)
            || !config::valid_remote(&self.scope.endpoint)
            || self.identity == [0; 32]
        {
            return Err(Error::Scope);
        }
        validate_hello(hello, self.reference, self.branch)?;
        let mut aad = Vec::with_capacity(DOMAIN.len() + 32 + hello.len() + 512);
        aad.extend_from_slice(DOMAIN);
        for field in [
            self.scope.inbound.as_bytes(),
            self.scope.endpoint.as_bytes(),
            self.identity.as_slice(),
            self.reference.as_bytes(),
            alpn(self.branch),
        ] {
            let len = u16::try_from(field.len()).map_err(|_| Error::Scope)?;
            aad.extend_from_slice(&len.to_be_bytes());
            aad.extend_from_slice(field);
        }
        aad.extend_from_slice(&hello[..RANDOM_START]);
        aad.extend_from_slice(&[0; 32]);
        aad.extend_from_slice(&hello[RANDOM_END..]);
        Ok(aad)
    }
}

/// Seal before transcript hashing. Wire field: random 96-bit nonce,
/// AEAD ciphertext of a 32-bit Unix timestamp, 128-bit authentication tag.
/// The timestamp is encrypted; both transports share the same field layout.
/// The entire remaining ClientHello (including the ephemeral key share),
/// scope, signer, reference and branch are authenticated associated data.
pub fn seal(secret: &Secret, context: &Context<'_>, hello: &mut [u8], now: u64) -> Result<(), Error> {
    let timestamp = u32::try_from(now).map_err(|_| Error::Clock)?;
    let aad = context.aad(hello)?;
    let mut nonce = [0; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).map_err(|_| Error::Crypto)?;
    let mut payload = timestamp.to_be_bytes();
    let tag = secret.key()?.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut payload,
    ).map_err(|_| Error::Crypto)?;
    let random = &mut hello[RANDOM_START..RANDOM_END];
    random[..NONCE_LEN].copy_from_slice(&nonce);
    random[NONCE_LEN..NONCE_LEN + payload.len()].copy_from_slice(&payload);
    random[NONCE_LEN + payload.len()..].copy_from_slice(tag.as_ref());
    Ok(())
}

struct ReplayState {
    seen: HashMap<[u8; NONCE_LEN], u64>,
    clock_floor: u64,
}

/// One guard per admission secret, shared by TCP and QUIC and all
/// concurrent accept tasks. Never evict a still-live nonce to make room.
/// With no durable replay journal, a newly started process rejects all
/// timestamps that could have been accepted before its startup, including
/// the future-skew allowance. This intentionally trades availability for
/// restart replay safety until a durable journal is designed.
pub struct ReplayGuard {
    capacity: usize,
    startup_cutoff: u64,
    state: Mutex<ReplayState>,
}

impl ReplayGuard {
    pub fn new(capacity: usize, started_at: u64) -> Result<Self, Error> {
        if !(1..=65536).contains(&capacity) { return Err(Error::Capacity); }
        Ok(Self {
            capacity,
            startup_cutoff: started_at.checked_add(WINDOW).ok_or(Error::Clock)?,
            state: Mutex::new(ReplayState { seen: HashMap::new(), clock_floor: started_at }),
        })
    }

    pub fn admit(&self, secret: &Secret, context: &Context<'_>, hello: &[u8], now: u64) -> Result<(), Error> {
        let aad = context.aad(hello)?;
        let random = &hello[RANDOM_START..RANDOM_END];
        let nonce: [u8; NONCE_LEN] = random[..NONCE_LEN].try_into().map_err(|_| Error::Format)?;
        let mut payload = Zeroizing::new([0; 20]);
        payload.copy_from_slice(&random[NONCE_LEN..]);
        let plain = secret.key()?.open_in_place(
            Nonce::assume_unique_for_key(nonce), Aad::from(aad), payload.as_mut(),
        ).map_err(|_| Error::Crypto)?;
        let timestamp = u64::from(u32::from_be_bytes(plain.try_into().map_err(|_| Error::Format)?));
        if timestamp <= self.startup_cutoff || timestamp.abs_diff(now) > WINDOW {
            return Err(Error::Clock);
        }
        let mut state = self.state.lock().map_err(|_| Error::Replay)?;
        if now < state.clock_floor { return Err(Error::Clock); }
        state.clock_floor = now;
        state.seen.retain(|_, expiry| *expiry >= now);
        if state.seen.contains_key(&nonce) { return Err(Error::Replay); }
        if state.seen.len() == self.capacity { return Err(Error::Capacity); }
        state.seen.insert(nonce, timestamp.saturating_add(WINDOW));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector(bytes: &mut Vec<u8>, value: &[u8]) {
        bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    fn extension(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
        bytes.extend_from_slice(&kind.to_be_bytes());
        vector(bytes, value);
    }
    fn hello(name: &str, branch: Branch) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        vector(&mut body, &[0x13, 1]);
        body.extend_from_slice(&[1, 0]);
        let mut extensions = Vec::new();
        let mut entry = vec![0];
        vector(&mut entry, name.as_bytes());
        let mut list = Vec::new();
        vector(&mut list, &entry);
        extension(&mut extensions, 0, &list);
        let mut protocols = Vec::new();
        let mut protocol = vec![2];
        protocol.extend_from_slice(alpn(branch));
        vector(&mut protocols, &protocol);
        extension(&mut extensions, 16, &protocols);
        extension(&mut extensions, 43, &[2, 3, 4]);
        let mut share = vec![0, 29];
        vector(&mut share, &[7; 32]);
        let mut shares = Vec::new();
        vector(&mut shares, &share);
        extension(&mut extensions, 51, &shares);
        vector(&mut body, &extensions);
        let mut result = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        result.extend_from_slice(&body);
        result
    }
    fn scope() -> Scope {
        Scope { inbound: "edge".into(), endpoint: "edge.example.org:443".into() }
    }
    #[test]
    fn admission_is_scope_branch_and_exact_hello_bound_and_one_use() {
        let scope = scope();
        let context = Context { scope: &scope, identity: [3; 32], reference: "ref.example.org", branch: Branch::H2 };
        let secret = Secret::new([4; 32]).unwrap();
        let mut message = hello(context.reference, context.branch);
        let now = 2000;
        seal(&secret, &context, &mut message, now).unwrap();
        let guard = ReplayGuard::new(2, 1000).unwrap();
        let wrong = Secret::new([5; 32]).unwrap();
        assert!(guard.admit(&wrong, &context, &message, now).is_err());
        let mut changed = message.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(guard.admit(&secret, &context, &changed, now).is_err());
        let foreign = Context { identity: [8; 32], ..context };
        assert!(guard.admit(&secret, &foreign, &message, now).is_err());
        let h3 = Context { branch: Branch::H3, ..context };
        assert!(guard.admit(&secret, &h3, &message, now).is_err());
        assert_eq!(guard.admit(&secret, &context, &message, now), Ok(()));
        assert_eq!(guard.admit(&secret, &context, &message, now), Err(Error::Replay));
        let restarted = ReplayGuard::new(2, now).unwrap();
        assert_eq!(restarted.admit(&secret, &context, &message, now), Err(Error::Clock));
    }
    #[test]
    fn cache_never_evicts_live_entries_and_time_window_is_bounded() {
        let scope = scope();
        let context = Context { scope: &scope, identity: [3; 32], reference: "ref.example.org", branch: Branch::H3 };
        let secret = Secret::new([4; 32]).unwrap();
        let guard = ReplayGuard::new(1, 1000).unwrap();
        let mut first = hello(context.reference, context.branch);
        let mut second = first.clone();
        seal(&secret, &context, &mut first, 2000).unwrap();
        seal(&secret, &context, &mut second, 2001).unwrap();
        assert_eq!(guard.admit(&secret, &context, &first, 2000), Ok(()));
        assert_eq!(guard.admit(&secret, &context, &second, 2001), Err(Error::Capacity));
        assert_eq!(guard.admit(&secret, &context, &first, 2001), Err(Error::Replay));
        assert_eq!(guard.admit(&secret, &context, &second, 2121), Ok(()));
        assert_eq!(guard.admit(&secret, &context, &second, 2122), Err(Error::Clock));
        assert!(guard.admit(&secret, &context, &second, 2119).is_err());
    }
    #[test]
    fn malformed_hello_and_wrong_reference_are_refused() {
        let scope = scope();
        let context = Context { scope: &scope, identity: [3; 32], reference: "ref.example.org", branch: Branch::H2 };
        let secret = Secret::new([4; 32]).unwrap();
        let mut wrong = hello("other.example.org", Branch::H2);
        assert!(seal(&secret, &context, &mut wrong, 2000).is_err());
        let valid = hello(context.reference, Branch::H2);
        for end in 0..valid.len() {
            let mut truncated = valid[..end].to_vec();
            assert!(seal(&secret, &context, &mut truncated, 2000).is_err());
        }
    }
}
