//! Persistent server-side signed descriptor publication and explicit identity
//! rotation. The local record is an operator-owned candidate, never a live
//! listener or a replacement for independent client trust.
//!
//! The active and pending private keys are in separate owner-only files.
//! Every read re-verifies the signed documents and actual referenced keys.
//! No automatic switch, key deletion or compromise recovery.
#![forbid(unsafe_code)]

use crate::{
    config::{self, WriteFailure},
    descriptor::{self, Anchor, Scope, Verified},
    identity_tls::Identity,
    reality_bootstrap::{self as bootstrap, Error, VALIDITY},
    reference_health,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_BYTES: usize = 128 * 1024;
const OVERLAP: u64 = 7 * 24 * 60 * 60;
// Provisional dev cooldown; any intervening publication resets it
// conservatively. This prevents immediate back-and-forth switches.
const FAILOVER_COOLDOWN: u64 = 60 * 60;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    key_file: String,
    started_at: u64,
    ends_at: u64,
    announcement: String,
    successor: String,
}

/// Retain both signed documents after old key retirement. A list of old
/// key names alone is not proof of an authorized identity transition.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedRotation {
    started_at: u64,
    ends_at: u64,
    retired_at: u64,
    announcement: String,
    successor: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u16,
    scope: Scope,
    generation: u64,
    clock_floor: u64,
    // Exact approved plan, including IP pins and declared server addresses.
    plan_sha256: [u8; 32],
    root_public: String,
    initial_document: String,
    active_key: String,
    active_document: String,
    retired: Vec<String>,
    transitions: Vec<CompletedRotation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<Pending>,
}

struct Checked {
    active: Identity,
    current: Verified,
    next: Option<(Identity, Verified)>,
}

fn file(path: &str) -> Result<&Path, Error> {
    let path = Path::new(path);
    if !crate::bounded_input::explicit_file_path(path) {
        return Err(Error::Storage);
    }
    Ok(path)
}

fn public_key(identity: &Identity) -> String {
    URL_SAFE_NO_PAD.encode(identity.public_key())
}

fn verified(identity: &Identity, signed: &str, minimum: u64) -> Result<Verified, Error> {
    verify_public(identity.scope(), identity.public_key(), signed, minimum)
}

fn decode_public(raw: &str) -> Result<[u8; 32], Error> {
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| Error::Format)?;
    let public: [u8; 32] = bytes.try_into().map_err(|_| Error::Format)?;
    if public == [0; 32] || URL_SAFE_NO_PAD.encode(public) != raw {
        return Err(Error::Format);
    }
    Ok(public)
}

fn verify_public(scope: &Scope, public: [u8; 32], signed: &str, minimum: u64) -> Result<Verified, Error> {
    let anchor = Anchor::new(
        scope.clone(),
        public,
        minimum,
        bootstrap::auto_policy(),
    )
    .map_err(|_| Error::Descriptor)?;
    descriptor::verify(signed, &anchor).map_err(|_| Error::Descriptor)
}

fn key_at(path: &str, scope: &Scope) -> Result<Identity, Error> {
    Identity::load(file(path)?, scope).map_err(|_| Error::Identity)
}

fn check_rotation_pair(announcement: &Verified, successor: &Verified, started: u64, ends: u64) -> Result<(), Error> {
    announcement.check_time(started).map_err(|_| Error::Descriptor)?;
    successor.check_time(started).map_err(|_| Error::Descriptor)?;
    let a = announcement.descriptor();
    let b = successor.descriptor();
    if b.revision != a.revision.checked_add(1).ok_or(Error::Descriptor)?
        || a.next_identity.as_deref() != Some(URL_SAFE_NO_PAD.encode(successor.signer()).as_str())
        || b.next_identity.is_some()
        || ends != started.checked_add(OVERLAP).ok_or(Error::Clock)?
        || a.not_after != ends || a.not_before != started
        || b.not_before != started || b.not_after <= ends
        || a.scope != b.scope || a.active_reference != b.active_reference
        || a.references != b.references || a.h3 != b.h3
        || a.stream_one != b.stream_one || a.stream_up != b.stream_up
        || a.path_prefix != b.path_prefix || a.padding != b.padding || a.rotation != b.rotation {
        return Err(Error::Descriptor);
    }
    Ok(())
}

impl Record {
    /// Verify the whole completed server rotation lineage without reading
    /// retired private keys. Retirement occurs after overlap; verify the
    /// signed pair at its original start, and the successor at retirement.
    fn lineage(&self) -> Result<([u8;32], Verified, Verified), Error> {
        if self.transitions.len() != self.retired.len() || self.transitions.len() > 64 {
            return Err(Error::Format);
        }
        let root = decode_public(&self.root_public)?;
        let initial = verify_public(&self.scope, root, &self.initial_document, 1)?;
        if initial.descriptor().revision != 1 || initial.descriptor().next_identity.is_some() {
            return Err(Error::Descriptor);
        }
        let mut floor = verify_public(&self.scope, root, &self.initial_document, 1)?;
        let mut clock = floor.descriptor().not_before;
        let mut seen = std::collections::HashSet::from([root]);
        for (transition, retired) in self.transitions.iter().zip(&self.retired) {
            if transition.started_at < clock || transition.retired_at < transition.ends_at
                || transition.retired_at > self.clock_floor || decode_public(retired)? != floor.signer() {
                return Err(Error::Clock);
            }
            let announcement = verify_public(&self.scope, floor.signer(), &transition.announcement,
                floor.descriptor().revision)?;
            if floor.compare(&announcement).map_err(|_| Error::Descriptor)? != descriptor::Change::Advanced {
                return Err(Error::Descriptor);
            }
            let next_key = decode_public(announcement.descriptor().next_identity.as_deref().ok_or(Error::Identity)?)?;
            if !seen.insert(next_key) { return Err(Error::Identity); }
            let minimum = announcement.descriptor().revision.checked_add(1).ok_or(Error::Descriptor)?;
            let successor = verify_public(&self.scope, next_key, &transition.successor, minimum)?;
            check_rotation_pair(&announcement, &successor, transition.started_at, transition.ends_at)?;
            successor.check_time(transition.retired_at).map_err(|_| Error::Descriptor)?;
            floor = successor;
            clock = transition.retired_at;
        }
        let current = verify_public(&self.scope, floor.signer(), &self.active_document, floor.descriptor().revision)?;
        floor.compare(&current).map_err(|_| Error::Descriptor)?;
        if self.clock_floor < clock || self.generation != current.descriptor().revision {
            return Err(Error::Descriptor);
        }
        Ok((root, initial, current))
    }

    fn validate(&self) -> Result<Checked, Error> {
        if self.schema_version != 1
            || self.generation == 0
            || self.clock_floor == 0
            || self.plan_sha256 == [0; 32]
            || self.retired.len() > 64
        {
            return Err(Error::Format);
        }
        let mut retired = std::collections::HashSet::new();
        for raw in &self.retired {
            let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| Error::Format)?;
            if bytes.len() != 32
                || bytes.iter().all(|byte| *byte == 0)
                || URL_SAFE_NO_PAD.encode(&bytes) != *raw
                || !retired.insert(raw)
            {
                return Err(Error::Format);
            }
        }
        let active = key_at(&self.active_key, &self.scope)?;
        if self.retired.contains(&public_key(&active)) {
            return Err(Error::Identity);
        }
        let (_, _, current) = self.lineage()?;
        if current.signer() != active.public_key() { return Err(Error::Identity); }
        current
            .check_time(self.clock_floor)
            .map_err(|_| Error::Descriptor)?;
        let next = if let Some(pending) = &self.pending {
            if pending.key_file == self.active_key
                || pending.started_at > self.clock_floor
                || pending.ends_at
                    != pending
                        .started_at
                        .checked_add(OVERLAP)
                        .ok_or(Error::Clock)?
                || self.active_document != pending.announcement
            {
                return Err(Error::Format);
            }
            let successor_key = key_at(&pending.key_file, &self.scope)?;
            let encoded = public_key(&successor_key);
            if self.retired.contains(&encoded)
                || active.public_key() == successor_key.public_key()
                || current.descriptor().next_identity.as_deref() != Some(encoded.as_str())
            {
                return Err(Error::Identity);
            }
            let minimum = current
                .descriptor()
                .revision
                .checked_add(1)
                .ok_or(Error::Descriptor)?;
            let successor = verified(&successor_key, &pending.successor, minimum)?;
            check_rotation_pair(&current, &successor, pending.started_at, pending.ends_at)?;
            Some((successor_key, successor))
        } else {
            if current.descriptor().next_identity.is_some() {
                return Err(Error::Descriptor);
            }
            None
        };
        Ok(Checked {
            active,
            current,
            next,
        })
    }

    fn encode(&self) -> Result<String, Error> {
        self.validate()?;
        let raw = toml::to_string(self).map_err(|_| Error::Format)?;
        if raw.len() > MAX_BYTES {
            return Err(Error::Format);
        }
        Ok(raw)
    }

    fn check_clock(&self, now: u64) -> Result<(), Error> {
        if now < self.clock_floor {
            Err(Error::Clock)
        } else {
            Ok(())
        }
    }

    fn advance(&mut self, now: u64) -> Result<(), Error> {
        self.check_clock(now)?;
        self.clock_floor = now;
        self.generation = self.generation.checked_add(1).ok_or(Error::Descriptor)?;
        Ok(())
    }
}

/// Immutable verified publication material. Preparing it reads the exact
/// owner-approved record and keys once. No network listener or grant changes
/// occur; caller must still enforce transport admission and fresh DNS pins.
pub struct CapturedPublication {
    generation: u64,
    snapshot_sha256: [u8; 32],
    plan_sha256: [u8; 32],
    captured_at: u64,
    active: PublishedIdentity,
    next: Option<PublishedIdentity>,
}

pub struct PublishedIdentity {
    identity: Identity,
    verified: Verified,
    signed: String,
}

impl PublishedIdentity {
    pub fn identity(&self) -> &Identity { &self.identity }
    pub fn verified(&self) -> &Verified { &self.verified }
    pub fn signed(&self) -> &str { &self.signed }
}

impl CapturedPublication {
    pub fn generation(&self) -> u64 { self.generation }
    pub fn snapshot_sha256(&self) -> [u8; 32] { self.snapshot_sha256 }
    pub fn plan_sha256(&self) -> [u8; 32] { self.plan_sha256 }
    pub fn active(&self) -> &PublishedIdentity { &self.active }
    pub fn next(&self) -> Option<&PublishedIdentity> { self.next.as_ref() }

    /// Selection uses the exact independently authenticated public identity.
    /// Old admission cannot select the next signer, or vice versa.
    pub fn select(&self, public: [u8; 32], now: u64) -> Result<&PublishedIdentity, Error> {
        if now < self.captured_at { return Err(Error::Clock); }
        let selected = if self.active.identity.public_key() == public {
            &self.active
        } else {
            self.next.as_ref().filter(|entry| entry.identity.public_key() == public)
                .ok_or(Error::Identity)?
        };
        selected.verified.check_time(now).map_err(|_| Error::Descriptor)?;
        Ok(selected)
    }
}

pub struct Publication {
    path: PathBuf,
}

impl Publication {
    pub fn new(path: &Path) -> Result<Self, Error> {
        if !crate::bounded_input::explicit_file_path(path) {
            return Err(Error::Storage);
        }
        Ok(Self {
            path: path.to_owned(),
        })
    }

    fn snapshot(&self) -> Result<(String, Record, Checked), Error> {
        let raw = bootstrap::read_text(&self.path, MAX_BYTES, true)?;
        let record: Record = toml::from_str(&raw).map_err(|_| Error::Format)?;
        let checked = record.validate()?;
        Ok((raw.to_string(), record, checked))
    }

    fn write(&self, record: &Record, old: Option<&str>) -> Result<(), Error> {
        config::guarded_trust_write(&self.path, &record.encode()?, old.map(str::as_bytes)).map_err(
            |error| match error {
                WriteFailure::BeforeReplace(_) => Error::Storage,
                WriteFailure::AfterReplace(_) => Error::Indeterminate,
            },
        )
    }

    /// Single create-only publication, preventing two revision-one candidates
    /// from accidentally becoming authoritative for the same local record.
    pub fn initialize(
        &self,
        state: &reference_health::State,
        key_path: &Path,
        now: u64,
    ) -> Result<(), Error> {
        let scope = Scope {
            inbound: state.plan().inbound.clone(),
            endpoint: state.plan().endpoint.clone(),
        };
        let key_file = key_path.to_str().ok_or(Error::Storage)?.to_owned();
        let identity = key_at(&key_file, &scope)?;
        let active_document = bootstrap::initial_descriptor(state, &identity, now)?;
        self.write(
            &Record {
                schema_version: 1,
                scope,
                generation: 1,
                clock_floor: now,
                plan_sha256: state.plan().digest().map_err(|_| Error::Health)?,
                root_public: public_key(&identity),
                initial_document: active_document.clone(),
                active_key: key_file,
                active_document,
                retired: Vec::new(),
                transitions: Vec::new(),
                pending: None,
            },
            None,
        )
    }

    /// Public output only. Revision and exact snapshot digest are a CAS
    /// guard, not permission to load a different key file or change scope.
    pub fn inspect(&self, now: u64) -> Result<Status, Error> {
        let (raw, record, checked) = self.snapshot()?;
        record.check_clock(now)?;
        Ok(Status {
            generation: record.generation,
            plan_sha256: record.plan_sha256,
            snapshot_sha256: bootstrap::digest(&raw),
            revision: checked.current.descriptor().revision,
            active_reference: checked.current.descriptor().active_reference,
            active_fingerprint: bootstrap::fingerprint(checked.active.public_key()),
            valid_now: checked.current.check_time(now).is_ok(),
            not_after: checked.current.descriptor().not_after,
            next_fingerprint: checked
                .next
                .as_ref()
                .map(|(key, _)| bootstrap::fingerprint(key.public_key())),
            overlap_ends_at: record.pending.as_ref().map(|pending| pending.ends_at),
        })
    }

    /// Read-only descriptor inspection tied to the exact approved publication.
    /// Expiry does not remove the last authenticated configuration.
    pub fn inspect_descriptor(&self, expected: [u8; 32], now: u64) -> Result<Verified, Error> {
        let (raw, record, checked) = self.snapshot()?;
        record.check_clock(now)?;
        if bootstrap::digest(&raw) != expected { return Err(Error::Approval); }
        Ok(checked.current)
    }

    fn check_root(record: &Record, scope: &Scope, expected_root: [u8; 32],
        expected_initial: [u8; 32], expected_plan: [u8; 32]) -> Result<(), Error> {
        let (root, initial, _) = record.lineage()?;
        if &record.scope != scope || bootstrap::fingerprint(root) != expected_root
            || initial.payload_sha256() != expected_initial || record.plan_sha256 != expected_plan {
            return Err(Error::Approval);
        }
        Ok(())
    }

    /// Reopen the current signed publication only when its complete
    /// lineage matches the independently pinned initial receipt. The
    /// returned status is local and does not authorize activation.
    pub fn inspect_rooted(
        &self, scope: &Scope, expected_root: [u8; 32], expected_initial: [u8; 32],
        expected_plan: [u8; 32], now: u64,
    ) -> Result<Verified, Error> {
        self.inspect_rooted_snapshot(scope, expected_root, expected_initial, expected_plan, now)
            .map(|(value, _, _)| value)
    }

    pub(crate) fn inspect_rooted_snapshot(
        &self, scope: &Scope, expected_root: [u8; 32], expected_initial: [u8; 32],
        expected_plan: [u8; 32], now: u64,
    ) -> Result<(Verified, u64, [u8; 32]), Error> {
        let (raw, record, checked) = self.snapshot()?;
        record.check_clock(now)?;
        Self::check_root(&record, scope, expected_root, expected_initial, expected_plan)?;
        Ok((checked.current, record.generation, bootstrap::digest(&raw)))
    }

    /// Capture both signing generations from the same verified file
    /// snapshot, matching a separately approved health inventory. Failed
    /// refresh never silently substitutes an arbitrary key or reference.
    pub fn capture(
        &self,
        state: &reference_health::State,
        expected_snapshot: [u8; 32],
        now: u64,
    ) -> Result<CapturedPublication, Error> {
        let (raw, record, checked) = self.snapshot()?;
        if bootstrap::digest(&raw) != expected_snapshot {
            return Err(Error::Approval);
        }
        Self::capture_checked(record, checked, expected_snapshot, state, now)
    }

    /// Validate the independent root and capture both key generations from
    /// the SAME file read. Never use a separately inspected snapshot to
    /// authorize keys from a later, potentially replaced publication.
    pub(crate) fn capture_rooted(
        &self, state: &reference_health::State, scope: &Scope,
        expected_root: [u8; 32], expected_initial: [u8; 32], now: u64,
    ) -> Result<CapturedPublication, Error> {
        let (raw, record, checked) = self.snapshot()?;
        Self::check_root(&record, scope, expected_root, expected_initial,
            state.plan().digest().map_err(|_| Error::Health)?)?;
        Self::capture_checked(record, checked, bootstrap::digest(&raw), state, now)
    }

    fn capture_checked(
        record: Record, checked: Checked, expected_snapshot: [u8; 32],
        state: &reference_health::State, now: u64,
    ) -> Result<CapturedPublication, Error> {
        record.check_clock(now)?;
        if state.plan().digest().map_err(|_| Error::Health)? != record.plan_sha256 {
            return Err(Error::Approval);
        }
        checked.current.check_time(now).map_err(|_| Error::Descriptor)?;
        state.validate_active(checked.current.descriptor(), now).map_err(|_| Error::Health)?;
        let next = match (checked.next, record.pending) {
            (Some((identity, verified)), Some(pending)) => {
                verified.check_time(now).map_err(|_| Error::Descriptor)?;
                state.validate_active(verified.descriptor(), now).map_err(|_| Error::Health)?;
                Some(PublishedIdentity { identity, verified, signed: pending.successor })
            }
            (None, None) => None,
            _ => return Err(Error::Descriptor),
        };
        Ok(CapturedPublication {
            generation: record.generation,
            snapshot_sha256: expected_snapshot,
            plan_sha256: record.plan_sha256,
            captured_at: now,
            active: PublishedIdentity {
                identity: checked.active, verified: checked.current, signed: record.active_document
            },
            next,
        })
    }

    pub fn documents(&self, now: u64) -> Result<(String, Option<String>), Error> {
        let (_, record, checked) = self.snapshot()?;
        record.check_clock(now)?;
        checked
            .current
            .check_time(now)
            .map_err(|_| Error::Descriptor)?;
        if let Some((_, next)) = &checked.next {
            next.check_time(now).map_err(|_| Error::Descriptor)?;
        }
        Ok((
            record.active_document,
            record.pending.map(|pending| pending.successor),
        ))
    }

    pub fn refresh(
        &self,
        state: &reference_health::State,
        expected: [u8; 32],
        now: u64,
    ) -> Result<(), Error> {
        let (old, mut record, checked) = self.snapshot()?;
        if bootstrap::digest(&old) != expected || record.pending.is_some() {
            return Err(Error::Approval);
        }
        record.check_clock(now)?;
        if state.plan().digest().map_err(|_| Error::Health)? != record.plan_sha256 {
            return Err(Error::Approval);
        }
        record.active_document =
            bootstrap::refresh_descriptor(state, &checked.active, &record.active_document, now)?;
        record.advance(now)?;
        self.write(&record, Some(&old))
    }

    fn reference_change(
        state: &reference_health::State,
        record: &Record,
        checked: &Checked,
        now: u64,
    ) -> Result<u8, Error> {
        record.check_clock(now)?;
        if record.pending.is_some()
            || state.plan().digest().map_err(|_| Error::Health)? != record.plan_sha256
        {
            return Err(Error::Approval);
        }
        if now.saturating_sub(record.clock_floor) < FAILOVER_COOLDOWN {
            return Err(Error::Health);
        }
        let index = state
            .failover_candidate(checked.current.descriptor(), now)
            .map_err(|_| Error::Health)?;
        u8::try_from(index).map_err(|_| Error::Health)
    }

    /// Read-only exact preview. Local publication is not a runtime Apply.
    pub fn preview_failover(
        &self,
        state: &reference_health::State,
        now: u64,
    ) -> Result<FailoverPreview, Error> {
        let (old, record, checked) = self.snapshot()?;
        let selected = Self::reference_change(state, &record, &checked, now)?;
        Ok(FailoverPreview {
            publication_sha256: bootstrap::digest(&old),
            health_sha256: state.snapshot_sha256().map_err(|_| Error::Health)?,
            current_reference: checked.current.descriptor().active_reference,
            selected_reference: selected,
            next_revision: checked
                .current
                .descriptor()
                .revision
                .checked_add(1)
                .ok_or(Error::Descriptor)?,
        })
    }

    /// Explicit offline publication after a separately confirmed client
    /// recovery plan. The caller must distribute the new signed descriptor
    /// through the authenticated recovery path; this changes no listeners.
    /// The exact evidence is still required to be fresh at commit time.
    pub fn apply_failover(
        &self,
        state: &reference_health::State,
        approval: FailoverApproval,
        now: u64,
    ) -> Result<(), Error> {
        let (old, mut record, checked) = self.snapshot()?;
        if bootstrap::digest(&old) != approval.publication_sha256
            || state.snapshot_sha256().map_err(|_| Error::Health)? != approval.health_sha256
        {
            return Err(Error::Approval);
        }
        let selected = Self::reference_change(state, &record, &checked, now)?;
        if selected != approval.selected_reference {
            return Err(Error::Approval);
        }
        let mut next = checked.current.descriptor().clone();
        next.active_reference = selected;
        next.revision = next.revision.checked_add(1).ok_or(Error::Descriptor)?;
        next.not_before = now;
        next.not_after = now.checked_add(VALIDITY).ok_or(Error::Clock)?;
        state
            .validate_active(&next, now)
            .map_err(|_| Error::Health)?;
        record.active_document = checked
            .active
            .sign_descriptor(&next)
            .map_err(|_| Error::Descriptor)?;
        record.advance(now)?;
        self.write(&record, Some(&old))
    }

    /// Stage a previously generated independent successor key. Both
    /// documents are signed before publication. Overlap is seven days,
    /// during which clients can explicitly promote their persistent anchor.
    /// No listener is changed and no old key is deleted.
    pub fn begin_rotation(
        &self,
        successor_path: &Path,
        expected: [u8; 32],
        expected_next: [u8; 32],
        now: u64,
    ) -> Result<(), Error> {
        let (old, mut record, checked) = self.snapshot()?;
        if bootstrap::digest(&old) != expected
            || record.pending.is_some()
            || record.retired.len() >= 64
        {
            return Err(Error::Approval);
        }
        record.check_clock(now)?;
        checked
            .current
            .check_time(now)
            .map_err(|_| Error::Descriptor)?;
        let key_file = successor_path.to_str().ok_or(Error::Storage)?.to_owned();
        let next = key_at(&key_file, &record.scope)?;
        let encoded = public_key(&next);
        if bootstrap::fingerprint(next.public_key()) != expected_next
            || next.public_key() == checked.active.public_key()
            || record.retired.contains(&encoded)
        {
            return Err(Error::Identity);
        }
        let ends_at = now.checked_add(OVERLAP).ok_or(Error::Clock)?;
        let mut announcement = checked.current.descriptor().clone();
        announcement.revision = announcement
            .revision
            .checked_add(1)
            .ok_or(Error::Descriptor)?;
        announcement.not_before = now;
        announcement.not_after = ends_at;
        announcement.next_identity = Some(encoded);
        let signed_announcement = checked
            .active
            .sign_descriptor(&announcement)
            .map_err(|_| Error::Descriptor)?;
        let mut successor = announcement.clone();
        successor.revision = successor.revision.checked_add(1).ok_or(Error::Descriptor)?;
        successor.not_after = ends_at.checked_add(VALIDITY).ok_or(Error::Clock)?;
        successor.next_identity = None;
        let signed_successor = next
            .sign_descriptor(&successor)
            .map_err(|_| Error::Descriptor)?;
        record.active_document = signed_announcement.clone();
        record.pending = Some(Pending {
            key_file,
            started_at: now,
            ends_at,
            announcement: signed_announcement,
            successor: signed_successor,
        });
        record.advance(now)?;
        self.write(&record, Some(&old))
    }

    /// Explicitly retire the previous signer only after the entire overlap.
    /// Offline clients which missed it must use independent re-enrollment.
    /// A revoked or compromised key is never used to authorize recovery.
    pub fn promote(
        &self,
        expected: [u8; 32],
        expected_next: [u8; 32],
        now: u64,
    ) -> Result<(), Error> {
        let (old, mut record, checked) = self.snapshot()?;
        if bootstrap::digest(&old) != expected {
            return Err(Error::Approval);
        }
        record.check_clock(now)?;
        let pending = record.pending.take().ok_or(Error::Identity)?;
        let (next_key, next) = checked.next.ok_or(Error::Identity)?;
        if now < pending.ends_at || bootstrap::fingerprint(next_key.public_key()) != expected_next {
            return Err(Error::Approval);
        }
        next.check_time(now).map_err(|_| Error::Descriptor)?;
        record.retired.push(public_key(&checked.active));
        record.transitions.push(CompletedRotation {
            started_at: pending.started_at, ends_at: pending.ends_at, retired_at: now,
            announcement: pending.announcement, successor: pending.successor.clone(),
        });
        record.active_key = pending.key_file;
        record.active_document = pending.successor;
        record.advance(now)?;
        self.write(&record, Some(&old))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct FailoverPreview {
    pub publication_sha256: [u8; 32],
    pub health_sha256: [u8; 32],
    pub current_reference: u8,
    pub selected_reference: u8,
    pub next_revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailoverApproval {
    pub publication_sha256: [u8; 32],
    pub health_sha256: [u8; 32],
    pub selected_reference: u8,
}

pub struct Status {
    pub generation: u64,
    pub plan_sha256: [u8; 32],
    pub snapshot_sha256: [u8; 32],
    pub revision: u64,
    pub active_reference: u8,
    pub active_fingerprint: [u8; 32],
    pub valid_now: bool,
    pub not_after: u64,
    pub next_fingerprint: Option<[u8; 32]>,
    pub overlap_ends_at: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Transport, XhttpMode};
    use crate::descriptor::ClientPolicy;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "theia-publication-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn guarded_failover_keeps_identity_routes_and_transport_and_refuses_stale_evidence() {
        let now = 1000;
        let dir = Scratch::new();
        let plan = reference_health::Plan {
            schema_version: 1,
            inbound: "edge".into(),
            endpoint: "edge.example.org:443".into(),
            own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: (2..=4)
                .map(|i| reference_health::Target {
                    server_name: format!("ref{i}.example.org"),
                    address: format!("93.184.216.{i}:443").parse().unwrap(),
                })
                .collect(),
        };
        let h3 = reference_health::Evidence {
            h2_status: Some(200),
            h3_status: Some(200),
        };
        let h2 = reference_health::Evidence {
            h2_status: Some(200),
            h3_status: None,
        };
        let state = reference_health::State::new(plan, vec![h3, h2, h3], now).unwrap();
        let scope = Scope {
            inbound: state.plan().inbound.clone(),
            endpoint: state.plan().endpoint.clone(),
        };
        let identity = Identity::generate(scope.clone()).unwrap();
        let key = dir.0.join("active.key");
        identity.save_new(&key).unwrap();
        let publication = Publication::new(&dir.0.join("publication.toml")).unwrap();
        publication.initialize(&state, &key, now).unwrap();
        let original = publication.documents(now).unwrap().0;
        let anchor =
            Anchor::new(scope, identity.public_key(), 1, bootstrap::auto_policy()).unwrap();
        let old = descriptor::verify(&original, &anchor).unwrap();
        let time = now + FAILOVER_COOLDOWN + 10;
        let failed = vec![reference_health::Evidence::default(), h2, h3];
        let once = state.record(failed.clone(), time - 10).unwrap();
        assert!(publication.preview_failover(&once, time).is_err());
        let twice = once.record(failed, time).unwrap();
        let preview = publication.preview_failover(&twice, time).unwrap();
        assert_eq!(preview.selected_reference, 2);
        assert_eq!(preview.next_revision, 2);
        assert!(publication.preview_failover(&twice, time + 61).is_err());
        let approval = FailoverApproval {
            publication_sha256: preview.publication_sha256,
            health_sha256: preview.health_sha256,
            selected_reference: 2,
        };
        assert!(publication
            .apply_failover(
                &twice,
                FailoverApproval {
                    selected_reference: 1,
                    ..approval
                },
                time
            )
            .is_err());
        assert!(publication
            .apply_failover(
                &twice,
                FailoverApproval {
                    health_sha256: [0; 32],
                    ..approval
                },
                time
            )
            .is_err());
        publication.apply_failover(&twice, approval, time).unwrap();
        let status = publication.inspect(time).unwrap();
        assert_eq!(status.active_reference, 2);
        assert_eq!(
            status.active_fingerprint,
            bootstrap::fingerprint(identity.public_key())
        );
        let next = descriptor::verify(&publication.documents(time).unwrap().0, &anchor).unwrap();
        assert_eq!(next.descriptor().path_prefix, old.descriptor().path_prefix);
        assert!(next.descriptor().references == old.descriptor().references);
        assert!(next.descriptor().h3);
        assert!(publication.apply_failover(&twice, approval, time).is_err());
        // Refresh after the first reference failed is valid for the now
        // active reference; new invitations can carry the updated snapshot.
        publication
            .refresh(&twice, status.snapshot_sha256, time + 1)
            .unwrap();
        assert_eq!(publication.inspect(time + 1).unwrap().revision, 3);
    }

    #[test]
    fn publication_rotation_survives_restart_and_enforces_full_overlap_and_cas() {
        let now = 1000;
        let dir = Scratch::new();
        let plan = reference_health::Plan {
            schema_version: 1,
            inbound: "edge".into(),
            endpoint: "edge.example.org:443".into(),
            own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: vec![reference_health::Target {
                server_name: "reference.example.org".into(),
                address: "93.184.216.2:443".parse().unwrap(),
            }],
        };
        let state = reference_health::State::new(
            plan,
            vec![reference_health::Evidence {
                h2_status: Some(200),
                h3_status: None,
            }],
            now,
        )
        .unwrap();
        let scope = Scope {
            inbound: state.plan().inbound.clone(),
            endpoint: state.plan().endpoint.clone(),
        };
        let active = Identity::generate(scope.clone()).unwrap();
        let next = Identity::generate(scope.clone()).unwrap();
        let old_key = dir.0.join("old.key");
        let next_key = dir.0.join("next.key");
        active.save_new(&old_key).unwrap();
        next.save_new(&next_key).unwrap();
        let path = dir.0.join("publication.toml");
        let publication = Publication::new(&path).unwrap();
        publication.initialize(&state, &old_key, now).unwrap();
        assert!(publication.initialize(&state, &old_key, now).is_err());
        let start = publication.inspect(now).unwrap();
        let initial = publication.documents(now).unwrap().0;
        let initial_anchor = Anchor::new(scope.clone(), active.public_key(), 1, bootstrap::auto_policy()).unwrap();
        let initial_digest = descriptor::verify(&initial, &initial_anchor).unwrap().payload_sha256();
        assert!(publication.inspect_rooted(&scope, bootstrap::fingerprint(active.public_key()), initial_digest, start.plan_sha256, now).is_ok());
        let mut substituted = state.plan().clone();
        substituted.references[0].address = "93.184.216.3:443".parse().unwrap();
        let substituted = reference_health::State::new(
            substituted,
            vec![reference_health::Evidence {
                h2_status: Some(200),
                h3_status: None,
            }],
            now,
        )
        .unwrap();
        assert!(matches!(
            publication.refresh(&substituted, start.snapshot_sha256, now + 1),
            Err(Error::Approval)
        ));
        assert_eq!(
            publication.inspect(now + 1).unwrap().snapshot_sha256,
            start.snapshot_sha256
        );
        assert_eq!(start.plan_sha256, state.plan().digest().unwrap());
        let fingerprint = bootstrap::fingerprint(next.public_key());
        assert!(publication
            .begin_rotation(&next_key, [0; 32], fingerprint, now + 1)
            .is_err());
        assert!(publication
            .begin_rotation(&next_key, start.snapshot_sha256, [0; 32], now + 1)
            .is_err());
        publication
            .begin_rotation(&next_key, start.snapshot_sha256, fingerprint, now + 1)
            .unwrap();
        let publication = Publication::new(&path).unwrap();
        let overlap = publication.inspect(now + 1).unwrap();
        assert_eq!(overlap.revision, 2);
        assert_eq!(overlap.next_fingerprint, Some(fingerprint));
        let (announcement, successor) = publication.documents(now + 1).unwrap();
        let successor = successor.unwrap();
        assert!(publication.capture(&state, start.snapshot_sha256, now + 1).is_err());
        assert!(publication.capture(&substituted, overlap.snapshot_sha256, now + 1).is_err());
        let captured = publication.capture(&state, overlap.snapshot_sha256, now + 1).unwrap();
        assert_eq!(captured.generation(), overlap.generation);
        assert_eq!(captured.snapshot_sha256(), overlap.snapshot_sha256);
        assert_eq!(captured.plan_sha256(), overlap.plan_sha256);
        let old_material = captured.select(active.public_key(), now + 1).unwrap();
        let new_material = captured.select(next.public_key(), now + 1).unwrap();
        assert_eq!(old_material.signed(), announcement);
        assert_eq!(new_material.signed(), successor);
        assert_eq!(old_material.identity().public_key(), old_material.verified().signer());
        assert_eq!(new_material.identity().public_key(), new_material.verified().signer());
        assert!(captured.select([0; 32], now + 1).is_err());
        assert!(captured.select(active.public_key(), overlap.overlap_ends_at.unwrap()).is_err());

        // A separate client already enrolled at revision one can consume
        // the old-signed announcement and explicitly promote to the next.
        let anchor = Anchor::new(
            scope.clone(),
            active.public_key(),
            1,
            ClientPolicy {
                transport: Transport::Auto,
                xhttp_mode: XhttpMode::Auto,
            },
        )
        .unwrap();
        let client_path = dir.0.join("client.toml");
        let store = descriptor::Store::new(&client_path, anchor).unwrap();
        store.initialize(&initial, now).unwrap();
        store.update_at(&announcement, 1, now + 1).unwrap();
        store
            .promote(&successor, 2, next.public_key(), now + 1)
            .unwrap();
        assert_eq!(store.load(now + 1).unwrap().signer(), next.public_key());

        let ends = overlap.overlap_ends_at.unwrap();
        assert!(publication
            .promote(overlap.snapshot_sha256, fingerprint, ends - 1)
            .is_err());
        publication
            .promote(overlap.snapshot_sha256, fingerprint, ends)
            .unwrap();
        let final_state = publication.inspect(ends).unwrap();
        assert_eq!(final_state.revision, 3);
        assert_eq!(final_state.active_fingerprint, fingerprint);
        assert_eq!(final_state.next_fingerprint, None);
        assert!(old_key.exists() && next_key.exists());
        assert_eq!(publication.inspect_rooted(&scope, bootstrap::fingerprint(active.public_key()), initial_digest, start.plan_sha256, ends).unwrap().signer(), next.public_key());
        assert!(publication.inspect_rooted(&scope, fingerprint, initial_digest, start.plan_sha256, ends).is_err());
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut forged: Record = toml::from_str(&raw).unwrap();
        forged.transitions.clear();
        std::fs::write(&path, toml::to_string(&forged).unwrap()).unwrap();
        assert!(publication.inspect(ends).is_err());
        std::fs::write(&path, &raw).unwrap();
        assert!(publication.inspect(ends).is_ok());
        assert!(publication
            .begin_rotation(
                &old_key,
                final_state.snapshot_sha256,
                bootstrap::fingerprint(active.public_key()),
                ends + 1
            )
            .is_err());
    }
}
