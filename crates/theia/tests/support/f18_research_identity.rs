//! Test-only M3.5a1 candidate for a *secondary* server identity proof.
//! Strict CA/SAN/ALPN TLS authentication MUST happen before this could run.
//! Not a REALITY handshake, anti-probing mechanism or production protocol.
//! Keys, nonces and exporters must never enter a trace, CLI or TOML v1.
#![forbid(unsafe_code)]

use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Deliberately distinct from current SmartTheia v1 and the M3.5a0 exporter.
/// Not a negotiated wire label. Changing it invalidates all lab proofs.
const DOMAIN: &[u8] = b"Theia/M3.5a1/RESEARCH-ONLY/server-identity/v1\0";
pub const WINDOW_MS: u64 = 60_000;
const FUTURE_SKEW_MS: u64 = 2_000;
const MAX_LAB_CAPACITY: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Branch {
    H2 = 2,
    H3 = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    InvalidTranscript,
    InvalidProof,
    Future,
    Expired,
    ClockRollback,
    Replay,
    Capacity,
}

/// Canonical fixed-length typed fields; no free-form HTTP header or client
/// target address is admitted. This remains unapproved lab-only material.
#[derive(Clone)]
pub struct Transcript {
    pub branch: Branch,
    pub server_name: String,
    pub port: u16,
    pub client_nonce: [u8; 32],
    pub server_nonce: [u8; 32],
    pub exporter: [u8; 32],
    pub issued_ms: u64,
}

impl Transcript {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        branch: Branch,
        server_name: &str,
        port: u16,
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        exporter: [u8; 32],
        issued_ms: u64,
    ) -> Result<Self, Failure> {
        let candidate = Self {
            branch,
            server_name: server_name.to_owned(),
            port,
            client_nonce,
            server_nonce,
            exporter,
            issued_ms,
        };
        if !candidate.valid() {
            return Err(Failure::InvalidTranscript);
        }
        Ok(candidate)
    }

    fn valid(&self) -> bool {
        let name = self.server_name.as_bytes();
        if self.port == 0
            || name.is_empty()
            || name.len() > 253
            || self.client_nonce.iter().all(|&b| b == 0)
            || self.server_nonce.iter().all(|&b| b == 0)
            || self.exporter.iter().all(|&b| b == 0)
        {
            return false;
        }
        // For this lab, require a canonical lower-case ASCII DNS hostname.
        // IP literals, IDNA normalization and aliases require a separate ADR.
        name.split(|&byte| byte == b'.').all(|label| {
            label.len() <= 63
                && !label.is_empty()
                && label[0] != b'-'
                && label[label.len() - 1] != b'-'
                && label
                    .iter()
                    .all(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let name = self.server_name.as_bytes();
        let mut encoded = Vec::with_capacity(DOMAIN.len() + 1 + 1 + name.len() + 2 + 8 + 96);
        encoded.extend_from_slice(DOMAIN);
        encoded.push(self.branch as u8);
        encoded.push(name.len() as u8);
        encoded.extend_from_slice(name);
        encoded.extend_from_slice(&self.port.to_be_bytes());
        encoded.extend_from_slice(&self.issued_ms.to_be_bytes());
        encoded.extend_from_slice(&self.client_nonce);
        encoded.extend_from_slice(&self.server_nonce);
        encoded.extend_from_slice(&self.exporter);
        encoded
    }
}

/// Bounded model only. Production must use monotonic time, distributed replay
/// handling where required and an audited client-auth/probing policy.
pub struct ReplayWindow {
    entries: HashMap<[u8; 32], u64>,
    max: usize,
    last_observed_ms: Option<u64>,
}

impl ReplayWindow {
    pub fn new(max: usize) -> Result<Self, Failure> {
        if max == 0 || max > MAX_LAB_CAPACITY {
            return Err(Failure::Capacity);
        }
        Ok(Self {
            entries: HashMap::with_capacity(max),
            max,
            last_observed_ms: None,
        })
    }

    /// Checks the pinned Ed25519 identity in addition to an already verified
    /// TLS channel. A valid proof admits nothing to server OPEN/relay.
    pub fn accept(
        &mut self,
        pinned_key: &[u8; 32],
        transcript: &Transcript,
        signature: &[u8],
        now_ms: u64,
    ) -> Result<(), Failure> {
        if self
            .last_observed_ms
            .is_some_and(|previous| now_ms < previous)
        {
            return Err(Failure::ClockRollback);
        }
        if !transcript.valid() {
            return Err(Failure::InvalidTranscript);
        }
        if transcript.issued_ms > now_ms.saturating_add(FUTURE_SKEW_MS) {
            return Err(Failure::Future);
        }
        let expires_at = transcript.issued_ms.saturating_add(WINDOW_MS);
        if now_ms >= expires_at {
            return Err(Failure::Expired);
        }

        let encoded = transcript.encode();
        UnparsedPublicKey::new(&ED25519, pinned_key)
            .verify(&encoded, signature)
            .map_err(|_| Failure::InvalidProof)?;

        self.entries.retain(|_, &mut expiry| now_ms < expiry);
        let id: [u8; 32] = Sha256::digest(&encoded).into();
        if self.entries.contains_key(&id) {
            return Err(Failure::Replay);
        }
        // Fail closed under adversarial pressure, never evict a live nonce.
        if self.entries.len() >= self.max {
            return Err(Failure::Capacity);
        }
        self.entries.insert(id, expires_at);
        self.last_observed_ms = Some(now_ms);
        Ok(())
    }
}
