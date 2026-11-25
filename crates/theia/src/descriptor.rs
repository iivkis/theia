//! Offline candidate for the signed inbound-descriptor v1 contract.
//! This module does not enable REALITY, authorize a relay target, authenticate
//! TLS, perform network I/O, or activate a successor identity. Its encoding
//! and integration require security review before production use.
#![forbid(unsafe_code)]
use crate::config::{self, Transport, WriteFailure, XhttpMode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, path::Path};

pub const MAX_DOCUMENT: usize = 16 * 1024;
const MAX_PAYLOAD: usize = 8 * 1024;
/// Provisional local trust-history bounds, not negotiated wire parameters.
const MAX_TRANSITIONS: usize = 8;
const MAX_SNAPSHOT: usize = 512 * 1024;
const SIGN_DOMAIN: &[u8] = b"SmartTheia/inbound-descriptor/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Format,
    Scope,
    Policy,
    Signature,
    Validity,
    Rollback,
    Equivocation,
    Rotation,
    ReenrollmentRequired,
    Storage,
    Indeterminate,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not reflect untrusted documents, endpoints, paths or key bytes.
        f.write_str(match self {
            Self::Format => "invalid descriptor format",
            Self::Scope => "descriptor outside pinned scope",
            Self::Policy => "descriptor conflicts with explicit local transport or XHTTP policy",
            Self::Signature => "descriptor signature rejected",
            Self::Validity => "descriptor outside validity interval",
            Self::Rollback => "descriptor revision rollback",
            Self::Equivocation => "conflicting content at one descriptor revision",
            Self::Rotation => "identity transition refused",
            Self::ReenrollmentRequired => "independent enrollment required",
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

/// Explicit, independently stored operator restrictions. The signed server
/// descriptor may narrow the offered modes, never override these restrictions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientPolicy {
    pub transport: Transport,
    pub xhttp_mode: XhttpMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectiveModes {
    pub h2: bool,
    pub h3: bool,
    pub stream_one: bool,
    pub stream_up: bool,
}

impl ClientPolicy {
    pub fn intersect(self, descriptor: &Descriptor) -> Result<EffectiveModes, Error> {
        let modes = EffectiveModes {
            h2: self.transport != Transport::H3,
            h3: self.transport != Transport::H2 && descriptor.h3,
            stream_one: self.xhttp_mode != XhttpMode::StreamUp && descriptor.stream_one,
            stream_up: self.xhttp_mode != XhttpMode::StreamOne && descriptor.stream_up,
        };
        if !(modes.h2 || modes.h3) || !(modes.stream_one || modes.stream_up) {
            return Err(Error::Policy);
        }
        Ok(modes)
    }
}

/// Must come from an independently authenticated enrollment, never from the
/// descriptor itself. A minimum revision and local policy are pinned here.
#[derive(Clone)]
pub struct Anchor {
    scope: Scope,
    public_key: [u8; 32],
    minimum_revision: u64,
    policy: ClientPolicy,
}
impl Anchor {
    pub fn new(
        scope: Scope,
        public_key: [u8; 32],
        minimum_revision: u64,
        policy: ClientPolicy,
    ) -> Result<Self, Error> {
        if !scope.valid() || public_key == [0; 32] || minimum_revision == 0 {
            return Err(Error::Format);
        }
        Ok(Self {
            scope,
            public_key,
            minimum_revision,
            policy,
        })
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
        if self.schema_version != 1
            || self.wire_version != 1
            || self.revision == 0
            || self.not_before >= self.not_after
            || !self.scope.valid()
            || !(1..=3).contains(&self.references.len())
            || usize::from(self.active_reference) >= self.references.len()
            || !(self.stream_one || self.stream_up)
            || prefix.is_empty()
            || prefix.len() > 64
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
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
        // Reject the obvious self-reference even before resolution. DNS
        // aliases and actual local addresses require a separate runtime check.
        let endpoint_host = self.scope.endpoint.rsplit_once(':').ok_or(Error::Format)?.0;
        for (i, reference) in self.references.iter().enumerate() {
            if reference.server_name.eq_ignore_ascii_case(endpoint_host)
                || !config::valid_dns(&reference.server_name)
                || reference.port == 0
                || reference.server_name != reference.server_name.to_ascii_lowercase()
                || self.references[..i].iter().any(|old| {
                    old.server_name == reference.server_name && old.port == reference.port
                })
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
    effective_modes: EffectiveModes,
}
impl Verified {
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn signer(&self) -> [u8; 32] {
        self.signer
    }
    pub fn payload_sha256(&self) -> [u8; 32] {
        self.digest
    }
    pub fn effective_modes(&self) -> EffectiveModes {
        self.effective_modes
    }
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
pub enum Change {
    Unchanged,
    Advanced,
}

/// Verify signature BEFORE parsing the signed payload. Only exact typed,
/// canonical TOML is accepted, with no extra, duplicate or unknown fields.
/// Time is checked separately so an expired authenticated disk snapshot can
/// still retain its revision floor for replacement after an offline interval.
pub fn verify(document: &str, anchor: &Anchor) -> Result<Verified, Error> {
    if document.len() > MAX_DOCUMENT {
        return Err(Error::Format);
    }
    let envelope: Envelope = toml::from_str(document).map_err(|_| Error::Format)?;
    let payload = URL_SAFE_NO_PAD
        .decode(&envelope.payload)
        .map_err(|_| Error::Format)?;
    if payload.len() > MAX_PAYLOAD || URL_SAFE_NO_PAD.encode(&payload) != envelope.payload {
        return Err(Error::Format);
    }
    let signature = canonical_base64::<64>(&envelope.signature)?;
    UnparsedPublicKey::new(&ED25519, anchor.public_key)
        .verify(&signing_input(&payload), &signature)
        .map_err(|_| Error::Signature)?;
    let text = std::str::from_utf8(&payload).map_err(|_| Error::Format)?;
    let descriptor: Descriptor = toml::from_str(text).map_err(|_| Error::Format)?;
    if descriptor.payload()? != text
        || toml::to_string(&envelope).map_err(|_| Error::Format)? != document
    {
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
    let effective_modes = anchor.policy.intersect(&descriptor)?;
    Ok(Verified {
        descriptor,
        digest: Sha256::digest(payload).into(),
        signer: anchor.public_key,
        effective_modes,
    })
}

/// Each explicit transition retains both signed documents. History is
/// validated from the independent enrollment root on EVERY reopen. No
/// unsigned current-key field is trusted and retired keys are never reused.
/// The local acceptance timestamp is not a remotely authenticated timestamp.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    announcement: String,
    successor: String,
    accepted_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u16,
    last_accepted_at: u64,
    current: String,
    transitions: Vec<Transition>,
}

struct History {
    anchor: Anchor,
    retired: Vec<[u8; 32]>,
    last_transition: u64,
    floor: Option<Verified>,
}

impl History {
    fn new(anchor: &Anchor) -> Self {
        Self {
            anchor: anchor.clone(),
            retired: Vec::new(),
            last_transition: 0,
            floor: None,
        }
    }

    fn check_clock(&self, now: u64) -> Result<(), Error> {
        if now < self.last_transition {
            return Err(Error::Validity);
        }
        Ok(())
    }

    fn check_retired(&self, verified: &Verified) -> Result<(), Error> {
        if let Some(raw) = &verified.descriptor.next_identity {
            let next = canonical_base64::<32>(raw)?;
            if self.retired.contains(&next) {
                return Err(Error::Rotation);
            }
        }
        Ok(())
    }

    fn verify_current(&self, document: &str) -> Result<Verified, Error> {
        let current = verify(document, &self.anchor)?;
        if let Some(floor) = &self.floor {
            floor.compare(&current)?;
        }
        self.check_retired(&current)?;
        Ok(current)
    }

    fn advance(
        &mut self,
        announcement: &Verified,
        successor: &str,
        expected_key: [u8; 32],
        now: u64,
    ) -> Result<Verified, Error> {
        if self.retired.len() >= MAX_TRANSITIONS {
            return Err(Error::ReenrollmentRequired);
        }
        self.check_clock(now)?;
        if announcement.signer != self.anchor.public_key
            || announcement.descriptor.scope != self.anchor.scope
        {
            return Err(Error::Scope);
        }
        if let Some(floor) = &self.floor {
            floor.compare(announcement)?;
        }
        // The current identity must still be valid at the transition.
        // A client that missed overlap cannot recover through an expired
        // announcement or a key supplied by the untrusted successor alone.
        announcement
            .check_time(now)
            .map_err(|_| Error::ReenrollmentRequired)?;
        let raw = announcement
            .descriptor
            .next_identity
            .as_ref()
            .ok_or(Error::Rotation)?;
        let next_key = canonical_base64::<32>(raw)?;
        if next_key != expected_key
            || next_key == self.anchor.public_key
            || self.retired.contains(&next_key)
        {
            return Err(Error::Rotation);
        }
        let minimum = announcement
            .descriptor
            .revision
            .checked_add(1)
            .ok_or(Error::ReenrollmentRequired)?;
        let new_anchor = Anchor::new(
            self.anchor.scope.clone(),
            next_key,
            minimum,
            self.anchor.policy,
        )?;
        let next = verify(successor, &new_anchor)?;
        next.check_time(now)?;
        if let Some(raw) = &next.descriptor.next_identity {
            let proposed = canonical_base64::<32>(raw)?;
            if proposed == self.anchor.public_key || self.retired.contains(&proposed) {
                return Err(Error::Rotation);
            }
        }
        self.retired.push(self.anchor.public_key);
        self.anchor = new_anchor;
        self.last_transition = now;
        Ok(next)
    }
}

impl Snapshot {
    fn encode(&self) -> Result<String, Error> {
        let encoded = toml::to_string(self).map_err(|_| Error::Format)?;
        if encoded.len() > MAX_SNAPSHOT {
            return Err(Error::Format);
        }
        Ok(encoded)
    }

    fn validate(&self, root: &Anchor) -> Result<(History, Verified), Error> {
        if self.schema_version != 1 || self.transitions.len() > MAX_TRANSITIONS {
            return Err(Error::Format);
        }
        let mut history = History::new(root);
        for transition in &self.transitions {
            let announcement = history.verify_current(&transition.announcement)?;
            let raw = announcement
                .descriptor
                .next_identity
                .as_ref()
                .ok_or(Error::Rotation)?;
            let key = canonical_base64::<32>(raw)?;
            let next = history.advance(
                &announcement,
                &transition.successor,
                key,
                transition.accepted_at,
            )?;
            history.floor = Some(next);
        }
        let current = history.verify_current(&self.current)?;
        history.check_clock(self.last_accepted_at)?;
        current.check_time(self.last_accepted_at)?;
        history.last_transition = self.last_accepted_at;
        Ok((history, current))
    }
}

/// Local-only store. The path must be absolute and its directory trusted.
/// The independently pinned Anchor must survive restart outside this file.
/// Local filesystem rollback or timestamp manipulation by a privileged actor
/// is not covered. This is a candidate for review, not a live trust adapter.
pub struct Store {
    anchor: Anchor,
    path: std::path::PathBuf,
}
impl Store {
    pub fn new(path: &Path, anchor: Anchor) -> Result<Self, Error> {
        if !crate::bounded_input::explicit_file_path(path) {
            return Err(Error::Storage);
        }
        Ok(Self {
            anchor,
            path: path.to_owned(),
        })
    }

    fn snapshot(&self) -> Result<(String, Snapshot, History, Verified), Error> {
        let bytes = crate::bounded_input::read(&self.path, MAX_SNAPSHOT as u64, true, true)
            .map_err(|_| Error::Storage)?;
        let raw = std::str::from_utf8(&bytes).map_err(|_| Error::Format)?;
        let snapshot: Snapshot = toml::from_str(raw).map_err(|_| Error::Format)?;
        let (history, verified) = snapshot.validate(&self.anchor)?;
        Ok((raw.to_owned(), snapshot, history, verified))
    }

    /// Authenticated local snapshot for offline review. Expiration does
    /// not erase the revision floor; callers must display validity separately.
    pub fn inspect(&self, now: u64) -> Result<Verified, Error> {
        self.inspect_bound(now).map(|(_, value)| value)
    }

    pub(crate) fn inspect_bound(&self, now: u64) -> Result<([u8;32], Verified), Error> {
        let (raw, _, history, verified) = self.snapshot()?;
        history.check_clock(now)?;
        Ok((Sha256::digest(raw.as_bytes()).into(), verified))
    }

    /// Independent re-enrollment must not resurrect a key this trust
    /// history already retired, or disguise ordinary renewal as a reset.
    pub(crate) fn inspect_replacement(&self, proposed: [u8;32], now: u64) -> Result<([u8;32], Verified), Error> {
        let (raw, _, history, verified) = self.snapshot()?;
        history.check_clock(now)?;
        if proposed == self.anchor.public_key || proposed == verified.signer()
            || history.retired.contains(&proposed) {
            return Err(Error::Rotation);
        }
        Ok((Sha256::digest(raw.as_bytes()).into(), verified))
    }

    pub fn preview_update(&self, document: &str, now: u64) -> Result<(u64, Verified), Error> {
        let (_, previous, next) = self.preview_update_bound(document, now)?;
        Ok((previous.descriptor.revision, next))
    }

    /// The entire trust history, including accepted timestamps and the
    /// old signed payload, is bound to the offline confirmation.
    pub fn preview_update_bound(&self, document: &str, now: u64) -> Result<([u8;32], Verified, Verified), Error> {
        let (raw, _, history, previous) = self.snapshot()?;
        history.check_clock(now)?;
        let next = history.verify_current(document)?;
        next.check_time(now)?;
        previous.compare(&next)?;
        Ok((Sha256::digest(raw.as_bytes()).into(), previous, next))
    }

    /// Bind an explicit trust transition to the complete current persistent
    /// snapshot, not merely its revision (including the accepted history).
    pub fn preview_promotion_bound(
        &self,
        document: &str,
        now: u64,
    ) -> Result<([u8; 32], Verified, Verified), Error> {
        let (raw, _, mut history, previous) = self.snapshot()?;
        let next_key = canonical_base64::<32>(
            previous.descriptor.next_identity.as_deref().ok_or(Error::Rotation)?,
        )?;
        let next = history.advance(&previous, document, next_key, now)?;
        Ok((Sha256::digest(raw.as_bytes()).into(), previous, next))
    }

    pub fn preview_promotion(
        &self,
        document: &str,
        expected_key: [u8; 32],
        now: u64,
    ) -> Result<(u64, Verified), Error> {
        let (_, _, mut history, previous) = self.snapshot()?;
        let next = history.advance(&previous, document, expected_key, now)?;
        Ok((previous.descriptor.revision, next))
    }

    pub fn load(&self, now: u64) -> Result<Verified, Error> {
        let (_, _, history, verified) = self.snapshot()?;
        history.check_clock(now)?;
        verified.check_time(now)?;
        Ok(verified)
    }

    /// Explicit enrollment only; never invoked as a recovery from a missing
    /// or corrupt existing store. Creation cannot clobber an existing file.
    pub fn initialize(&self, document: &str, now: u64) -> Result<(), Error> {
        let next = verify(document, &self.anchor)?;
        next.check_time(now)?;
        let snapshot = Snapshot {
            schema_version: 1,
            last_accepted_at: now,
            current: document.to_owned(),
            transitions: Vec::new(),
        };
        config::guarded_trust_write(&self.path, &snapshot.encode()?, None).map_err(storage_error)
    }

    /// Ordinary updates cannot change identity. Read/verify old and new,
    /// then CAS the entire signed snapshot, including the immutable history.
    pub fn update(&self, document: &str, now: u64) -> Result<Change, Error> {
        self.update_inner(document, None, None, None, now)
    }

    /// Guarded offline operator update; the revision check is inside the
    /// same snapshot read that supplies the atomic CAS expected bytes.
    pub fn update_at(
        &self,
        document: &str,
        expected_revision: u64,
        now: u64,
    ) -> Result<Change, Error> {
        self.update_inner(document, Some(expected_revision), None, None, now)
    }

    /// Bind an authenticated download to the exact descriptor used for its
    /// connection, including signer, scope, revision and signed digest.
    pub fn update_matching(
        &self,
        document: &str,
        expected: &Verified,
        now: u64,
    ) -> Result<Change, Error> {
        self.update_inner(document, Some(expected.descriptor.revision), Some(expected), None, now)
    }

    /// Offline recovery can replace an expired document, but never a
    /// different trust snapshot from the one the operator confirmed.
    pub fn update_bound(
        &self, document: &str, expected_revision: u64, expected_snapshot: [u8;32], now: u64,
    ) -> Result<Change, Error> {
        self.update_inner(document, Some(expected_revision), None, Some(expected_snapshot), now)
    }

    fn update_inner(
        &self,
        document: &str,
        expected_revision: Option<u64>,
        expected: Option<&Verified>,
        expected_snapshot: Option<[u8;32]>,
        now: u64,
    ) -> Result<Change, Error> {
        let (old, mut snapshot, history, previous) = self.snapshot()?;
        let digest: [u8;32] = Sha256::digest(old.as_bytes()).into();
        if expected_snapshot.is_some_and(|expected| expected != digest) {
            return Err(Error::Rollback);
        }
        if expected_revision.is_some_and(|rev| rev != previous.descriptor.revision) {
            return Err(Error::Rollback);
        }
        if let Some(expected) = expected {
            if expected.compare(&previous)? != Change::Unchanged {
                return Err(Error::Rollback);
            }
            expected.check_time(now)?;
        }
        history.check_clock(now)?;
        let next = history.verify_current(document)?;
        next.check_time(now)?;
        let change = previous.compare(&next)?;
        snapshot.current = document.to_owned();
        snapshot.last_accepted_at = now;
        snapshot.validate(&self.anchor)?;
        config::guarded_trust_write(&self.path, &snapshot.encode()?, Some(old.as_bytes()))
            .map_err(storage_error)?;
        Ok(change)
    }

    /// Revision-guarded normal rotation, NOT compromise recovery.
    /// Caller must independently confirm the intended key and current
    /// revision, or establish continuity through the authenticated live
    /// successor protocol (announcement + successor handshake + bound CAS).
    /// A raw automatic descriptor download alone is insufficient.
    /// Both signatures and both validity intervals must be verified before
    /// publication. The current signer is retired only at the CAS commit.
    pub fn promote(
        &self,
        successor: &str,
        expected_revision: u64,
        expected_key: [u8; 32],
        now: u64,
    ) -> Result<Change, Error> {
        self.promote_inner(successor, expected_revision, expected_key, None, now)
    }

    pub fn promote_bound(
        &self,
        successor: &str,
        expected_revision: u64,
        expected_key: [u8; 32],
        expected_snapshot: [u8; 32],
        now: u64,
    ) -> Result<Change, Error> {
        self.promote_inner(successor, expected_revision, expected_key, Some(expected_snapshot), now)
    }

    fn promote_inner(
        &self,
        successor: &str,
        expected_revision: u64,
        expected_key: [u8; 32],
        expected_snapshot: Option<[u8; 32]>,
        now: u64,
    ) -> Result<Change, Error> {
        let (old, mut snapshot, mut history, previous) = self.snapshot()?;
        let actual: [u8; 32] = Sha256::digest(old.as_bytes()).into();
        if previous.descriptor.revision != expected_revision
            || expected_snapshot.is_some_and(|expected| expected != actual)
        {
            return Err(Error::Rotation);
        }
        history.advance(&previous, successor, expected_key, now)?;
        snapshot.transitions.push(Transition {
            announcement: std::mem::replace(&mut snapshot.current, successor.to_owned()),
            successor: successor.to_owned(),
            accepted_at: now,
        });
        snapshot.last_accepted_at = now;
        // Re-verify the exact candidate from the independent root before CAS.
        snapshot.validate(&self.anchor)?;
        config::guarded_trust_write(&self.path, &snapshot.encode()?, Some(old.as_bytes()))
            .map_err(storage_error)?;
        Ok(Change::Advanced)
    }
}
fn storage_error(error: WriteFailure) -> Error {
    match error {
        WriteFailure::BeforeReplace(_) => Error::Storage,
        WriteFailure::AfterReplace(_) => Error::Indeterminate,
    }
}
