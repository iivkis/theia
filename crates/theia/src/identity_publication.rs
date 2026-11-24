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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    key_file: String,
    started_at: u64,
    ends_at: u64,
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
    active_key: String,
    active_document: String,
    retired: Vec<String>,
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
    let anchor = Anchor::new(
        identity.scope().clone(),
        identity.public_key(),
        minimum,
        bootstrap::auto_policy(),
    )
    .map_err(|_| Error::Descriptor)?;
    descriptor::verify(signed, &anchor).map_err(|_| Error::Descriptor)
}

fn key_at(path: &str, scope: &Scope) -> Result<Identity, Error> {
    Identity::load(file(path)?, scope).map_err(|_| Error::Identity)
}

impl Record {
    fn validate(&self) -> Result<Checked, Error> {
        if self.schema_version != 1
            || self.generation == 0
            || self.clock_floor == 0
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
        let current = verified(&active, &self.active_document, 1)?;
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
            current
                .check_time(pending.started_at)
                .map_err(|_| Error::Descriptor)?;
            successor
                .check_time(pending.started_at)
                .map_err(|_| Error::Descriptor)?;
            let a = current.descriptor();
            let b = successor.descriptor();
            // The next document must change only the signing identity,
            // revision and validity. No route/transport/grant change rides
            // along with key rotation.
            if b.revision != minimum
                || b.next_identity.is_some()
                || a.not_after != pending.ends_at
                || a.not_before != pending.started_at
                || b.not_before != pending.started_at
                || b.not_after <= pending.ends_at
                || a.active_reference != b.active_reference
                || a.references != b.references
                || a.h3 != b.h3
                || a.stream_one != b.stream_one
                || a.stream_up != b.stream_up
                || a.path_prefix != b.path_prefix
                || a.padding != b.padding
                || a.rotation != b.rotation
            {
                return Err(Error::Descriptor);
            }
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
                active_key: key_file,
                active_document,
                retired: Vec::new(),
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
            snapshot_sha256: bootstrap::digest(&raw),
            revision: checked.current.descriptor().revision,
            active_fingerprint: bootstrap::fingerprint(checked.active.public_key()),
            valid_now: checked.current.check_time(now).is_ok(),
            next_fingerprint: checked
                .next
                .as_ref()
                .map(|(key, _)| bootstrap::fingerprint(key.public_key())),
            overlap_ends_at: record.pending.as_ref().map(|pending| pending.ends_at),
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
        record.active_document =
            bootstrap::refresh_descriptor(state, &checked.active, &record.active_document, now)?;
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
        record.active_key = pending.key_file;
        record.active_document = pending.successor;
        record.advance(now)?;
        self.write(&record, Some(&old))
    }
}

pub struct Status {
    pub generation: u64,
    pub snapshot_sha256: [u8; 32],
    pub revision: u64,
    pub active_fingerprint: [u8; 32],
    pub valid_now: bool,
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

        // A separate client already enrolled at revision one can consume
        // the old-signed announcement and explicitly promote to the next.
        let anchor = Anchor::new(
            scope,
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
