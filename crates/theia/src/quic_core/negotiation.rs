//! Retry address-validation tokens and conservative Version Negotiation
//! inspection. Neither public Retry integrity nor VN authenticates a peer.
//! The caller must enforce connection history and never reuse TLS/PN state
//! when starting a new connection. No automatic version downgrade.
use super::wire::Version;
use crate::reality_quic_wire::{long, retry_valid, Kind};
use ring::{hmac, rand::{SecureRandom, SystemRandom}};
use std::net::{IpAddr, SocketAddr};

const CID_LEN: usize = 8;
const TAG_LEN: usize = 32;
const MAX_TTL: u64 = 30;
const BODY_LEN: usize = 8 + 4 + CID_LEN * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { Random, Invalid, Expired, Context }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    pub version: Version,
    pub original: [u8; CID_LEN],
    pub retry: [u8; CID_LEN],
}

pub struct Tokens {
    key: hmac::Key,
}

impl Tokens {
    pub fn new() -> Result<Self, Error> {
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new()).map_err(|_| Error::Random)?;
        Ok(Self { key })
    }

    fn authenticate_input(peer: SocketAddr, body: &[u8]) -> Vec<u8> {
        let mut data = b"theia-quic-retry-v1".to_vec();
        match peer.ip() {
            IpAddr::V4(ip) => { data.push(4); data.extend(ip.octets()); }
            IpAddr::V6(ip) => { data.push(6); data.extend(ip.octets()); }
        }
        // Scope matters for link-local IPv6, although the production
        // listener still enforces its own address policy.
        let scope = match peer { SocketAddr::V6(v6) => v6.scope_id(), _ => 0 };
        data.extend(scope.to_be_bytes());
        data.extend(peer.port().to_be_bytes());
        data.extend(body);
        data
    }

    /// The caller supplies seconds from the same clock for issue and verify.
    /// This token validates address and CID binding, not admission. Replay
    /// within TTL requires separate listener CID/session deduplication.
    pub fn issue(&self, peer: SocketAddr, binding: Binding, now_secs: u64) -> Result<Vec<u8>, Error> {
        if peer.port() == 0 || binding.original == binding.retry { return Err(Error::Context); }
        let mut body = Vec::with_capacity(BODY_LEN + TAG_LEN);
        body.extend(now_secs.to_be_bytes());
        body.extend(binding.version.wire().to_be_bytes());
        body.extend(binding.original);
        body.extend(binding.retry);
        let tag = hmac::sign(&self.key, &Self::authenticate_input(peer, &body));
        body.extend(tag.as_ref());
        Ok(body)
    }

    pub fn verify(&self, token: &[u8], peer: SocketAddr, expected_version: Version,
                  expected_retry: [u8; CID_LEN], now_secs: u64) -> Result<Binding, Error> {
        if token.len() != BODY_LEN + TAG_LEN || peer.port() == 0 { return Err(Error::Invalid); }
        let (body, tag) = token.split_at(BODY_LEN);
        hmac::verify(&self.key, &Self::authenticate_input(peer, body), tag).map_err(|_| Error::Invalid)?;
        let issued = u64::from_be_bytes(body[..8].try_into().map_err(|_| Error::Invalid)?);
        if now_secs.checked_sub(issued).is_none_or(|age| age > MAX_TTL) { return Err(Error::Expired); }
        let version = Version::from_wire(u32::from_be_bytes(body[8..12].try_into().map_err(|_| Error::Invalid)?))
            .ok_or(Error::Invalid)?;
        let original = body[12..20].try_into().map_err(|_| Error::Invalid)?;
        let retry = body[20..28].try_into().map_err(|_| Error::Invalid)?;
        if version != expected_version || retry != expected_retry || original == retry { return Err(Error::Context); }
        Ok(Binding { version, original, retry })
    }
}

/// Validate public Retry integrity and client-side connection context.
/// The token remains opaque. After one Retry or any accepted server
/// Initial/Handshake, subsequent Retry packets must be ignored.
pub fn retry_token<'a>(packet: &'a [u8], version: Version, client_cid: &[u8],
                       original: &[u8], already_retried: bool, peer_progress: bool)
    -> Result<(&'a [u8], &'a [u8]), Error> {
    if already_retried || peer_progress { return Err(Error::Context); }
    let h = long(packet).ok_or(Error::Invalid)?;
    if h.kind != Kind::Retry || h.version != version.wire()
        || h.dcid != client_cid || h.scid.is_empty() || h.scid == original
        || h.token.len() > 4096 || !retry_valid(packet, original) {
        return Err(Error::Invalid);
    }
    Ok((h.scid, h.token))
}

/// Return advertised supported candidates only. VN is unauthenticated;
/// the active connection is not modified and selection requires an
/// explicit local policy and subsequent authenticated version validation.
pub fn version_candidates(packet: &[u8], offered: Version, local: &[u8],
                          original: &[u8], peer_progress: bool) -> Result<Vec<Version>, Error> {
    if peer_progress { return Err(Error::Context); }
    let h = long(packet).ok_or(Error::Invalid)?;
    if h.kind != Kind::VersionNegotiation || h.dcid != local || h.scid != original { return Err(Error::Invalid); }
    let start = 7 + local.len() + original.len();
    let versions = packet.get(start..).ok_or(Error::Invalid)?;
    if versions.len() > 256 { return Err(Error::Invalid); }
    let mut result = Vec::new();
    for bytes in versions.chunks_exact(4) {
        let number = u32::from_be_bytes(bytes.try_into().map_err(|_| Error::Invalid)?);
        if number == offered.wire() { return Err(Error::Context); }
        if let Some(version) = Version::from_wire(number) {
            if !result.contains(&version) { result.push(version); }
        }
    }
    Ok(result)
}

/// Generate unpredictable fixed-length CIDs. The listener must register
/// them atomically and retry on collision, never overwrite a route.
pub fn random_cid() -> Result<[u8; CID_LEN], Error> {
    let mut cid = [0; CID_LEN];
    SystemRandom::new().fill(&mut cid).map_err(|_| Error::Random)?;
    Ok(cid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_bind_address_version_cids_and_lifetime() {
        let t = Tokens::new().unwrap();
        let peer = "127.0.0.1:2345".parse().unwrap();
        let other = "127.0.0.1:2346".parse().unwrap();
        for version in [Version::V1, Version::V2] {
            let b = Binding { version, original: [1; 8], retry: [2; 8] };
            let token = t.issue(peer, b, 100).unwrap();
            assert_eq!(t.verify(&token, peer, version, b.retry, 130), Ok(b));
            assert_eq!(t.verify(&token, peer, version, b.retry, 131), Err(Error::Expired));
            assert_eq!(t.verify(&token, peer, version, b.retry, 99), Err(Error::Expired));
            assert_eq!(t.verify(&token, other, version, b.retry, 101), Err(Error::Invalid));
            assert_eq!(t.verify(&token, peer, version, [3; 8], 101), Err(Error::Context));
            let mut altered = token.clone();
            altered[15] ^= 1;
            assert_eq!(t.verify(&altered, peer, version, b.retry, 101), Err(Error::Invalid));
            assert_eq!(t.verify(&token[..20], peer, version, b.retry, 101), Err(Error::Invalid));
        }
    }

    #[test]
    fn negotiation_is_context_bound_and_never_chooses_current() {
        let local = [1; 8];
        let original = [2; 8];
        let mut p = vec![0x80, 0, 0, 0, 0, 8];
        p.extend(local);
        p.push(8);
        p.extend(original);
        p.extend(Version::V2.wire().to_be_bytes());
        assert_eq!(version_candidates(&p, Version::V1, &local, &original, false), Ok(vec![Version::V2]));
        assert_eq!(version_candidates(&p, Version::V2, &local, &original, false), Err(Error::Context));
        assert_eq!(version_candidates(&p, Version::V1, &original, &local, false), Err(Error::Invalid));
        assert_eq!(version_candidates(&p, Version::V1, &local, &original, true), Err(Error::Context));
    }

    #[test]
    fn rfc9001_retry_context() {
        let packet = [0xff,0,0,0,1,0,8,0xf0,0x67,0xa5,0x50,0x2a,0x42,0x62,0xb5,
            0x74,0x6f,0x6b,0x65,0x6e,0x04,0xa2,0x65,0xba,0x2e,0xff,0x4d,0x82,
            0x90,0x58,0xfb,0x3f,0x0f,0x24,0x96,0xba];
        let original = [0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08];
        assert_eq!(retry_token(&packet, Version::V1, &[], &original, false, false).unwrap().1, b"token");
        assert_eq!(retry_token(&packet, Version::V1, &[], &original, true, false), Err(Error::Context));
        assert_eq!(retry_token(&packet, Version::V1, &[], &original, false, true), Err(Error::Context));
    }
}
