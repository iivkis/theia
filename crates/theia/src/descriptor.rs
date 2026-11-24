//! Offline candidate for the signed inbound-descriptor v1 contract.
//! This module does not enable REALITY, authorize a relay target, authenticate
//! TLS, perform network I/O, or activate a successor identity. Its encoding
//! and integration require security review before production use.
#![forbid(unsafe_code)]
use crate::config::{self, WriteFailure};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, path::Path};

pub const MAX_DOCUMENT: usize = 16 * 1024;
const MAX_PAYLOAD: usize = 8 * 1024;
const SIGN_DOMAIN: &[u8] = b"SmartTheia/inbound-descriptor/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Format,
    Scope,
    Signature,
    Validity,
    Rollback,
    Equivocation,
    Storage,
    Indeterminate,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not reflect untrusted documents, endpoints, paths or key bytes.
        f.write_str(match self {
            Self::Format => "invalid descriptor format",
            Self::Scope => "descriptor outside pinned scope",
            Self::Signature => "descriptor signature rejected",
            Self::Validity => "descriptor outside validity interval",
            Self::Rollback => "descriptor revision rollback",
            Self::Equivocation => "conflicting content at one descriptor revision",
            Self::Storage => "trust snapshot storage refused",
            Self::Indeterminate => "trust snapshot publication uncertain; reopen before retry",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub inbound: String,
    pub endpoint: String,
}
impl Scope {
    fn valid(&self) -> bool {
        config::valid_id(&self.inbound) && config::valid_remote(&self.endpoint)
    }
}

/// Must come from an independently authenticated enrollment, never from the
/// descriptor itself. A minimum revision may be pinned during enrollment.
#[derive(Clone)]
pub struct Anchor {
    scope: Scope,
    public_key: [u8; 32],
    minimum_revision: u64,
}
impl Anchor {
    pub fn new(scope: Scope, public_key: [u8; 32], minimum_revision: u64) -> Result<Self, Error> {
        if !scope.valid() || public_key == [0; 32] || minimum_revision == 0 {
            return Err(Error::Format);
        }
        Ok(Self { scope, public_key, minimum_revision })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityMode {
    SmartReality,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub server_name: String,
    pub port: u16,
    pub h3: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Padding {
    pub header_min: u16,
    pub header_max: u16,
    pub frame_min: u32,
    pub frame_max: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    pub lifetime_min_s: u32,
    pub lifetime_max_s: u32,
    pub volume_min_bytes: u64,
    pub volume_max_bytes: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub schema_version: u16,
    pub wire_version: u16,
    pub security_mode: SecurityMode,
    pub revision: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub active_reference: u8,
    pub h3: bool,
    pub stream_one: bool,
    pub stream_up: bool,
    pub path_prefix: String,
    /// Signed public metadata, NOT permission to replace the trust anchor.
    pub next_identity: Option<String>,
    pub scope: Scope,
    pub padding: Padding,
    pub rotation: Rotation,
    pub references: Vec<Reference>,
}

fn canonical_base64<const N: usize>(raw: &str) -> Result<[u8; N], Error> {
    let decoded = URL_SAFE_NO_PAD.decode(raw).map_err(|_| Error::Format)?;
    let bytes: [u8; N] = decoded.try_into().map_err(|_| Error::Format)?;
    if URL_SAFE_NO_PAD.encode(bytes) != raw {
        return Err(Error::Format);
    }
    Ok(bytes)
}

impl Descriptor {
    fn validate(&self) -> Result<(), Error> {
        let prefix = self.path_prefix.strip_prefix("/v1/").ok_or(Error::Format)?;
        if self.schema_version != 1 || self.wire_version != 1
            || self.revision == 0 || self.not_before >= self.not_after
            || !self.scope.valid() || !(1..=3).contains(&self.references.len())
            || usize::from(self.active_reference) >= self.references.len()
            || !(self.stream_one || self.stream_up)
            || prefix.is_empty() || prefix.len() > 64
            || !prefix.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || self.padding.header_min > self.padding.header_max
            || self.padding.header_max > 8192
            || self.padding.frame_min > self.padding.frame_max
            || self.padding.frame_max > crate::protocol::MAX_PAYLOAD as u32
            || self.rotation.lifetime_min_s == 0
            || self.rotation.lifetime_min_s > self.rotation.lifetime_max_s
            || self.rotation.volume_min_bytes == 0
            || self.rotation.volume_min_bytes > self.rotation.volume_max_bytes
        {
            return Err(Error::Format);
        }
        for (i, reference) in self.references.iter().enumerate() {
            if !config::valid_dns(&reference.server_name) || reference.port == 0
                || reference.server_name != reference.server_name.to_ascii_lowercase()
                || self.references[..i].iter().any(|old|
                    old.server_name == reference.server_name && old.port == reference.port)
            {
                return Err(Error::Format);
            }
        }
        if self.h3 && !self.references[usize::from(self.active_reference)].h3 {
            return Err(Error::Format);
        }
        if let Some(key) = &self.next_identity {
            if canonical_base64::<32>(key)? == [0; 32] {
                return Err(Error::Format);
            }
        }
        Ok(())
    }

    fn payload(&self) -> Result<String, Error> {
        self.validate()?;
        let payload = toml::to_string(self).map_err(|_| Error::Format)?;
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::Format);
        }
        Ok(payload)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    signature: String,
}
fn signing_input(payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGN_DOMAIN.len() + payload.len());
    input.extend_from_slice(SIGN_DOMAIN);
    input.extend_from_slice(payload);
    input
}

/// Sign the exact canonical payload using the existing audited library
/// primitive. This does NOT sign a TLS transcript or prove session identity.
pub fn sign(descriptor: &Descriptor, key: &Ed25519KeyPair) -> Result<String, Error> {
    let payload = descriptor.payload()?;
    if let Some(next) = &descriptor.next_identity {
        if canonical_base64::<32>(next)?.as_slice() == key.public_key().as_ref() {
            return Err(Error::Format);
        }
    }
    let signature = key.sign(&signing_input(payload.as_bytes()));
    let envelope = Envelope {
        payload: URL_SAFE_NO_PAD.encode(payload.as_bytes()),
        signature: URL_SAFE_NO_PAD.encode(signature.as_ref()),
    };
    toml::to_string(&envelope).map_err(|_| Error::Format)
}

pub struct Verified {
    descriptor: Descriptor,
    digest: [u8; 32],
    signer: [u8; 32],
}
impl Verified {
    pub fn descriptor(&self) -> &Descriptor { &self.descriptor }
    pub fn check_time(&self, now: u64) -> Result<(), Error> {
        if now < self.descriptor.not_before || now >= self.descriptor.not_after {
            return Err(Error::Validity);
        }
        Ok(())
    }
    pub fn compare(&self, next: &Self) -> Result<Change, Error> {
        if self.descriptor.scope != next.descriptor.scope || self.signer != next.signer {
            return Err(Error::Scope);
        }
        match next.descriptor.revision.cmp(&self.descriptor.revision) {
            std::cmp::Ordering::Less => Err(Error::Rollback),
            std::cmp::Ordering::Equal if self.digest != next.digest => Err(Error::Equivocation),
            std::cmp::Ordering::Equal => Ok(Change::Unchanged),
            std::cmp::Ordering::Greater => Ok(Change::Advanced),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change { Unchanged, Advanced }

/// Verify signature BEFORE parsing the signed payload. Only exact typed,
/// canonical TOML is accepted, with no extra, duplicate or unknown fields.
/// Time is checked separately so an expired authenticated disk snapshot can
/// still retain its revision floor for replacement after an offline interval.
pub fn verify(document: &str, anchor: &Anchor) -> Result<Verified, Error> {
    if document.len() > MAX_DOCUMENT {
        return Err(Error::Format);
    }
    let envelope: Envelope = toml::from_str(document).map_err(|_| Error::Format)?;
    let payload = URL_SAFE_NO_PAD.decode(&envelope.payload).map_err(|_| Error::Format)?;
    if payload.len() > MAX_PAYLOAD || URL_SAFE_NO_PAD.encode(&payload) != envelope.payload {
        return Err(Error::Format);
    }
    let signature = canonical_base64::<64>(&envelope.signature)?;
    UnparsedPublicKey::new(&ED25519, anchor.public_key)
        .verify(&signing_input(&payload), &signature).map_err(|_| Error::Signature)?;
    let text = std::str::from_utf8(&payload).map_err(|_| Error::Format)?;
    let descriptor: Descriptor = toml::from_str(text).map_err(|_| Error::Format)?;
    if descriptor.payload()? != text {
        return Err(Error::Format);
    }
    if descriptor.scope != anchor.scope {
        return Err(Error::Scope);
    }
    if descriptor.revision < anchor.minimum_revision {
        return Err(Error::Rollback);
    }
    if let Some(next) = &descriptor.next_identity {
        if canonical_base64::<32>(next)? == anchor.public_key {
            return Err(Error::Format);
        }
    }
    Ok(Verified { descriptor, digest: Sha256::digest(payload).into(), signer: anchor.public_key })
}

/// Local-only store. The path must be absolute and its directory trusted.
/// The independently pinned Anchor must survive restart outside this file.
/// Local filesystem rollback by a privileged actor is not covered.
pub struct Store {
    anchor: Anchor,
    path: std::path::PathBuf,
}
impl Store {
    pub fn new(path: &Path, anchor: Anchor) -> Result<Self, Error> {
        if !crate::bounded_input::explicit_file_path(path) {
            return Err(Error::Storage);
        }
        Ok(Self { anchor, path: path.to_owned() })
    }

    fn snapshot(&self) -> Result<(String, Verified), Error> {
        let bytes = crate::bounded_input::read(&self.path, MAX_DOCUMENT as u64, true, true)
            .map_err(|_| Error::Storage)?;
        let document = std::str::from_utf8(&bytes).map_err(|_| Error::Format)?;
        let verified = verify(document, &self.anchor)?;
        Ok((document.to_owned(), verified))
    }

    pub fn load(&self, now: u64) -> Result<Verified, Error> {
        let (_, verified) = self.snapshot()?;
        verified.check_time(now)?;
        Ok(verified)
    }

    /// Explicit enrollment only; never invoked as a recovery from a missing
    /// or corrupt existing store. Creation cannot clobber an existing file.
    pub fn initialize(&self, document: &str, now: u64) -> Result<(), Error> {
        let next = verify(document, &self.anchor)?;
        next.check_time(now)?;
        config::guarded_trust_write(&self.path, document, None).map_err(storage_error)
    }

    /// Read/verify old and new, then CAS the entire signed snapshot. No
    /// active runtime state is changed by this offline component.
    pub fn update(&self, document: &str, now: u64) -> Result<Change, Error> {
        let (old, previous) = self.snapshot()?;
        let next = verify(document, &self.anchor)?;
        next.check_time(now)?;
        let change = previous.compare(&next)?;
        // Even idempotent updates check CAS, so concurrent advancement is
        // not reported as an accepted stale state.
        config::guarded_trust_write(&self.path, document, Some(old.as_bytes()))
            .map_err(storage_error)?;
        Ok(change)
    }
}
fn storage_error(error: WriteFailure) -> Error {
    match error {
        WriteFailure::BeforeReplace(_) => Error::Storage,
        WriteFailure::AfterReplace(_) => Error::Indeterminate,
    }
}
