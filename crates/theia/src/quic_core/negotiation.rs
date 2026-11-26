//! Retry address-validation tokens and conservative Version Negotiation
//! inspection. Neither public Retry integrity nor VN authenticates a peer.
//! The caller must enforce connection history and never reuse TLS/PN state
//! when starting a new connection. No automatic version downgrade.
use super::wire::Version;
use crate::reality_quic_wire::{long, retry_valid, Kind};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use std::net::{IpAddr, SocketAddr};

const CID_LEN: usize = 8;
const TAG_LEN: usize = 32;
const MAX_TTL: u64 = 30;
pub const TOKEN_TTL: u64 = MAX_TTL;
const MIN_BODY_LEN: usize = 8 + 4 + CID_LEN + 1 + 8 + 1;
const MAX_BODY_LEN: usize = 8 + 4 + CID_LEN + 1 + 20 + 1 + 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Random,
    Invalid,
    Expired,
    Context,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    pub version: Version,
    pub original: Vec<u8>,
    pub retry: [u8; CID_LEN],
    pub client: Vec<u8>,
}

/// Explicit, ordered local version policy. A restart is a fresh TLS/QUIC
/// connection and its selected version must survive authenticated TP checks.
#[derive(Clone, Debug)]
pub struct VersionPolicy(Vec<Version>);

impl VersionPolicy {
    pub fn new(versions: &[Version]) -> Result<Self, Error> {
        if versions.is_empty() || versions.len() > 2 || (versions.len() == 2 && versions[0] == versions[1]) {
            return Err(Error::Context);
        }
        Ok(Self(versions.to_vec()))
    }

    pub fn both() -> Self { Self(vec![Version::V1, Version::V2]) }
    pub fn exact(version: Version) -> Self { Self(vec![version]) }
    pub fn preferred(&self) -> Version { self.0[0] }
    pub fn supports(&self, version: Version) -> bool { self.0.contains(&version) }
    pub fn versions(&self) -> &[Version] { &self.0 }
    pub fn choose(&self, offered: &[Version]) -> Option<Version> {
        self.0.iter().copied().find(|v| offered.contains(v))
    }

    /// RFC 9368: client advertises only the chosen version to disable
    /// compatible in-place negotiation; server lists fully deployed versions.
    pub(crate) fn information(&self, chosen: Version, server: bool) -> Vec<u8> {
        let mut out = chosen.wire().to_be_bytes().to_vec();
        let available = if server { self.versions() } else { std::slice::from_ref(&chosen) };
        for version in available { out.extend_from_slice(&version.wire().to_be_bytes()); }
        out
    }

    /// Validate the authenticated version_information TP, not just public
    /// VN bytes. A missing TP is never accepted after a native VN restart.
    pub(crate) fn validate_information(&self, bytes: Option<&[u8]>, chosen: Version,
        peer_server: bool, restarted: bool) -> Result<(), Error> {
        let Some(bytes) = bytes else { return if restarted { Err(Error::Context) } else { Ok(()) }; };
        let (words, tail) = bytes.as_chunks::<4>();
        if words.is_empty() || !tail.is_empty() || words.len() > 65 { return Err(Error::Invalid); }
        let mut numbers = words.iter().map(|word| u32::from_be_bytes(*word));
        if numbers.next() != Some(chosen.wire()) { return Err(Error::Context); }
        let available: Vec<_> = numbers.collect();
        if available.contains(&0) || (!peer_server && !available.contains(&chosen.wire())) {
            return Err(Error::Invalid);
        }
        if peer_server && restarted {
            if available.is_empty() { return Err(Error::Context); }
            let mut candidates: Vec<_> = available.into_iter().filter_map(Version::from_wire).collect();
            candidates.push(chosen);
            if self.choose(&candidates) != Some(chosen) { return Err(Error::Context); }
        }
        Ok(())
    }
}

pub struct Tokens {
    key: hmac::Key,
}

impl Tokens {
    pub fn new() -> Result<Self, Error> {
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new())
            .map_err(|_| Error::Random)?;
        Ok(Self { key })
    }

    fn authenticate_input(peer: SocketAddr, body: &[u8]) -> Vec<u8> {
        let mut data = b"theia-quic-retry-v1".to_vec();
        match peer.ip() {
            IpAddr::V4(ip) => {
                data.push(4);
                data.extend(ip.octets());
            }
            IpAddr::V6(ip) => {
                data.push(6);
                data.extend(ip.octets());
            }
        }
        // Scope matters for link-local IPv6, although the production
        // listener still enforces its own address policy.
        let scope = match peer {
            SocketAddr::V6(v6) => v6.scope_id(),
            _ => 0,
        };
        data.extend(scope.to_be_bytes());
        data.extend(peer.port().to_be_bytes());
        data.extend(body);
        data
    }

    /// The caller supplies seconds from the same clock for issue and verify.
    /// This token validates address and CID binding, not admission. Replay
    /// within TTL requires separate listener CID/session deduplication.
    pub fn issue(
        &self,
        peer: SocketAddr,
        binding: &Binding,
        now_secs: u64,
    ) -> Result<Vec<u8>, Error> {
        if peer.port() == 0
            || !(8..=20).contains(&binding.original.len())
            || binding.client.len() > 20
            || binding.original.as_slice() == binding.retry.as_slice()
        {
            return Err(Error::Context);
        }
        let mut body = Vec::with_capacity(MAX_BODY_LEN + TAG_LEN);
        body.extend(now_secs.to_be_bytes());
        body.extend(binding.version.wire().to_be_bytes());
        body.extend(binding.retry);
        body.push(binding.original.len() as u8);
        body.extend_from_slice(&binding.original);
        body.push(binding.client.len() as u8);
        body.extend_from_slice(&binding.client);
        let tag = hmac::sign(&self.key, &Self::authenticate_input(peer, &body));
        body.extend(tag.as_ref());
        Ok(body)
    }

    pub fn verify(
        &self,
        token: &[u8],
        peer: SocketAddr,
        expected_version: Version,
        expected_retry: [u8; CID_LEN],
        expected_client: &[u8],
        now_secs: u64,
    ) -> Result<Binding, Error> {
        if !(MIN_BODY_LEN + TAG_LEN..=MAX_BODY_LEN + TAG_LEN).contains(&token.len())
            || peer.port() == 0
            || expected_client.len() > 20
        {
            return Err(Error::Invalid);
        }
        let (body, tag) = token.split_at(token.len() - TAG_LEN);
        hmac::verify(&self.key, &Self::authenticate_input(peer, body), tag)
            .map_err(|_| Error::Invalid)?;
        let issued = u64::from_be_bytes(body[..8].try_into().map_err(|_| Error::Invalid)?);
        if now_secs.checked_sub(issued).is_none_or(|age| age > MAX_TTL) {
            return Err(Error::Expired);
        }
        let version = Version::from_wire(u32::from_be_bytes(
            body[8..12].try_into().map_err(|_| Error::Invalid)?,
        ))
        .ok_or(Error::Invalid)?;
        let retry: [u8; CID_LEN] = body[12..20].try_into().map_err(|_| Error::Invalid)?;
        let original_len = usize::from(body[20]);
        if !(8..=20).contains(&original_len) {
            return Err(Error::Invalid);
        }
        let original_end = 21 + original_len;
        let original = body.get(21..original_end).ok_or(Error::Invalid)?;
        let client_len = usize::from(*body.get(original_end).ok_or(Error::Invalid)?);
        let client = body.get(original_end + 1..).ok_or(Error::Invalid)?;
        if client_len != client.len() || client_len > 20 {
            return Err(Error::Invalid);
        }
        if version != expected_version
            || retry != expected_retry
            || original == retry.as_slice()
            || client != expected_client
        {
            return Err(Error::Context);
        }
        Ok(Binding {
            version,
            original: original.to_vec(),
            retry,
            client: client.to_vec(),
        })
    }
}

/// Validate public Retry integrity and client-side connection context.
/// The token remains opaque. After one Retry or any accepted server
/// Initial/Handshake, subsequent Retry packets must be ignored.
pub fn retry_token<'a>(
    packet: &'a [u8],
    version: Version,
    client_cid: &[u8],
    original: &[u8],
    already_retried: bool,
    peer_progress: bool,
) -> Result<(&'a [u8], &'a [u8]), Error> {
    if already_retried || peer_progress {
        return Err(Error::Context);
    }
    let h = long(packet).ok_or(Error::Invalid)?;
    if h.kind != Kind::Retry
        || h.version != version.wire()
        || h.dcid != client_cid
        || h.scid.is_empty()
        || h.scid == original
        || h.token.len() > 4096
        || !retry_valid(packet, original)
    {
        return Err(Error::Invalid);
    }
    Ok((h.scid, h.token))
}

/// Return advertised supported candidates only. VN is unauthenticated;
/// the active connection is not modified and selection requires an
/// explicit local policy and subsequent authenticated version validation.
pub fn version_candidates(
    packet: &[u8],
    offered: Version,
    local: &[u8],
    original: &[u8],
    peer_progress: bool,
) -> Result<Vec<Version>, Error> {
    if peer_progress {
        return Err(Error::Context);
    }
    let h = long(packet).ok_or(Error::Invalid)?;
    if h.kind != Kind::VersionNegotiation || h.dcid != local || h.scid != original {
        return Err(Error::Invalid);
    }
    let start = 7 + local.len() + original.len();
    let versions = packet.get(start..).ok_or(Error::Invalid)?;
    if versions.is_empty() || versions.len() > 256 || versions.len() % 4 != 0 {
        return Err(Error::Invalid);
    }
    let mut result = Vec::new();
    for bytes in versions.as_chunks::<4>().0 {
        let number = u32::from_be_bytes(*bytes);
        if number == offered.wire() {
            return Err(Error::Context);
        }
        if let Some(version) = Version::from_wire(number) {
            if !result.contains(&version) {
                result.push(version);
            }
        }
    }
    Ok(result)
}

/// Generate unpredictable fixed-length CIDs. The listener must register
/// them atomically and retry on collision, never overwrite a route.
pub fn random_cid() -> Result<[u8; CID_LEN], Error> {
    let mut cid = [0; CID_LEN];
    SystemRandom::new()
        .fill(&mut cid)
        .map_err(|_| Error::Random)?;
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
            let b = Binding {
                version,
                original: vec![1; 12],
                retry: [2; 8],
                client: vec![4; 10],
            };
            let token = t.issue(peer, &b, 100).unwrap();
            assert_eq!(
                t.verify(&token, peer, version, b.retry, &b.client, 130),
                Ok(b.clone())
            );
            assert_eq!(
                t.verify(&token, peer, version, b.retry, &b.client, 131),
                Err(Error::Expired)
            );
            assert_eq!(
                t.verify(&token, peer, version, b.retry, &b.client, 99),
                Err(Error::Expired)
            );
            assert_eq!(
                t.verify(&token, other, version, b.retry, &b.client, 101),
                Err(Error::Invalid)
            );
            assert_eq!(
                t.verify(&token, peer, version, [3; 8], &b.client, 101),
                Err(Error::Context)
            );
            assert_eq!(
                t.verify(&token, peer, version, b.retry, &[9; 10], 101),
                Err(Error::Context)
            );
            let mut altered = token.clone();
            altered[15] ^= 1;
            assert_eq!(
                t.verify(&altered, peer, version, b.retry, &b.client, 101),
                Err(Error::Invalid)
            );
            assert_eq!(
                t.verify(&token[..20], peer, version, b.retry, &b.client, 101),
                Err(Error::Invalid)
            );
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
        assert_eq!(
            version_candidates(&p, Version::V1, &local, &original, false),
            Ok(vec![Version::V2])
        );
        assert_eq!(
            version_candidates(&p, Version::V2, &local, &original, false),
            Err(Error::Context)
        );
        assert_eq!(
            version_candidates(&p, Version::V1, &original, &local, false),
            Err(Error::Invalid)
        );
        assert_eq!(
            version_candidates(&p, Version::V1, &local, &original, true),
            Err(Error::Context)
        );
    }

    #[test]
    fn rfc9001_retry_context() {
        let packet = [
            0xff, 0, 0, 0, 1, 0, 8, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74, 0x6f,
            0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb,
            0x3f, 0x0f, 0x24, 0x96, 0xba,
        ];
        let original = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        assert_eq!(
            retry_token(&packet, Version::V1, &[], &original, false, false)
                .unwrap()
                .1,
            b"token"
        );
        assert_eq!(
            retry_token(&packet, Version::V1, &[], &original, true, false),
            Err(Error::Context)
        );
        assert_eq!(
            retry_token(&packet, Version::V1, &[], &original, false, true),
            Err(Error::Context)
        );
    }
}

#[cfg(test)]
mod version_policy_tests {
    use super::*;
    #[test]
    fn restart_requires_authenticated_server_support_and_rejects_downgrade() {
        let preferred = VersionPolicy::new(&[Version::V2, Version::V1]).unwrap();
        let v1 = VersionPolicy::exact(Version::V1);
        assert_eq!(preferred.choose(&[Version::V1]), Some(Version::V1));
        assert_eq!(preferred.validate_information(Some(&v1.information(Version::V1, true)), Version::V1, true, true), Ok(()));
        assert_eq!(preferred.validate_information(Some(&preferred.information(Version::V1, true)), Version::V1, true, true), Err(Error::Context));
        assert_eq!(preferred.validate_information(None, Version::V1, true, true), Err(Error::Context));
        assert!(preferred.validate_information(Some(&[0; 8]), Version::V1, false, false).is_err());
        assert!(VersionPolicy::new(&[Version::V1, Version::V1]).is_err());
    }
}
