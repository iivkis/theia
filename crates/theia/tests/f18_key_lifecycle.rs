//! F-18 key-lifecycle policy experiment. Local, pre-authorized trust
//! snapshots only: no network negotiation, production key store or wire API.
#![forbid(unsafe_code)]

#[path = "support/f18_research_identity.rs"]
mod lab;

use lab::{Branch, Failure, ReplayWindow, Transcript};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{Barrier, Mutex},
    thread,
};

const MAX_PINS: usize = 2;
const MAX_RETIRED: usize = 4;
const START: u64 = 10_000;
const ROTATE: u64 = 20_000;
const RETIRE: u64 = 30_000;
const END: u64 = 40_000;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Scope {
    inbound: &'static str,
    host: &'static str,
    port: u16,
}

const EDGE: Scope = Scope {
    inbound: "edge-a",
    host: "edge.example.org",
    port: 443,
};

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    key: [u8; 32],
    valid_from: u64,
    valid_until: u64,
}

struct Policy {
    scope: Scope,
    generation: u64,
    pins: Vec<Pin>,
}

impl Policy {
    fn valid(&self) -> bool {
        self.generation != 0
            && !self.scope.inbound.is_empty()
            && !self.scope.host.is_empty()
            && self.scope.port != 0
            && self.pins.len() <= MAX_PINS
            && self.pins.iter().enumerate().all(|(index, pin)| {
                pin.key != [0; 32]
                    && pin.valid_from < pin.valid_until
                    && !self.pins[..index].iter().any(|other| other.key == pin.key)
            })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Rejection {
    Policy,
    Generation,
    Scope,
    Key,
    Downgrade,
    Clock,
    RetiredCapacity,
    Proof(Failure),
}

#[derive(Clone, Copy)]
enum Mode {
    Pinned,
    Plain,
}

#[derive(Clone, Copy)]
struct Expected {
    scope: Scope,
    branch: Branch,
    mode: Mode,
}

// An already authorized local policy is a prerequisite. This model does
// not authenticate a policy update or prove crash-safe persistence.
struct Trust {
    policy: Policy,
    retired: Vec<[u8; 32]>,
    replay: ReplayWindow,
    last_ms: u64,
}

impl Trust {
    fn new(policy: Policy, now_ms: u64) -> Result<Self, Rejection> {
        if !policy.valid() {
            return Err(Rejection::Policy);
        }
        Ok(Self {
            policy,
            retired: Vec::new(),
            replay: ReplayWindow::new(8).map_err(Rejection::Proof)?,
            last_ms: now_ms,
        })
    }

    fn replace(&mut self, next: Policy, now_ms: u64) -> Result<(), Rejection> {
        if now_ms < self.last_ms {
            return Err(Rejection::Clock);
        }
        if !next.valid() {
            return Err(Rejection::Policy);
        }
        if next.scope != self.policy.scope {
            return Err(Rejection::Scope);
        }
        if self.policy.generation.checked_add(1) != Some(next.generation) {
            return Err(Rejection::Generation);
        }
        for pin in &next.pins {
            if self.retired.contains(&pin.key) {
                return Err(Rejection::Key);
            }
            if self.policy.pins.iter().any(|old| {
                old.key == pin.key
                    && (pin.valid_from < old.valid_from || pin.valid_until > old.valid_until)
            }) {
                return Err(Rejection::Key);
            }
        }
        let mut retired = self.retired.clone();
        for pin in &self.policy.pins {
            if !next.pins.iter().any(|candidate| candidate.key == pin.key) {
                if retired.len() == MAX_RETIRED {
                    return Err(Rejection::RetiredCapacity);
                }
                retired.push(pin.key);
            }
        }
        // No state change until all validation succeeds.
        self.retired = retired;
        self.policy = next;
        self.last_ms = now_ms;
        Ok(())
    }

    fn verify(
        &mut self,
        expected: Expected,
        key: &[u8; 32],
        transcript: &Transcript,
        signature: &[u8],
        now_ms: u64,
    ) -> Result<(), Rejection> {
        if !matches!(expected.mode, Mode::Pinned) {
            return Err(Rejection::Downgrade);
        }
        if now_ms < self.last_ms {
            return Err(Rejection::Clock);
        }
        if expected.scope != self.policy.scope
            || expected.branch != transcript.branch
            || transcript.server_name != expected.scope.host
            || transcript.port != expected.scope.port
        {
            return Err(Rejection::Scope);
        }
        let pin = self
            .policy
            .pins
            .iter()
            .find(|pin| &pin.key == key)
            .ok_or(Rejection::Key)?;
        if now_ms < pin.valid_from
            || now_ms >= pin.valid_until
            || transcript.issued_ms < pin.valid_from
            || transcript.issued_ms >= pin.valid_until
        {
            return Err(Rejection::Key);
        }
        self.replay
            .accept(key, transcript, signature, now_ms)
            .map_err(Rejection::Proof)?;
        self.last_ms = now_ms;
        Ok(())
    }
}

fn keypair() -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn pin(key: &Ed25519KeyPair, valid_from: u64, valid_until: u64) -> Pin {
    Pin {
        key: key.public_key().as_ref().try_into().unwrap(),
        valid_from,
        valid_until,
    }
}

fn policy(generation: u64, pins: Vec<Pin>) -> Policy {
    Policy {
        scope: EDGE,
        generation,
        pins,
    }
}

fn expected(branch: Branch) -> Expected {
    Expected {
        scope: EDGE,
        branch,
        mode: Mode::Pinned,
    }
}

// Deterministic synthetic session inputs. Real TLS exporter and DATA
// evidence lives in the separate M3.5a4/a5 network tests.
fn transcript(branch: Branch, issued_ms: u64, seed: u8) -> Transcript {
    Transcript::new(
        branch, EDGE.host, EDGE.port, [seed; 32], [2; 32], [3; 32], issued_ms,
    )
    .unwrap()
}

fn verify(
    trust: &mut Trust,
    expected: Expected,
    key: &Ed25519KeyPair,
    proof: &Transcript,
    now_ms: u64,
) -> Result<(), Rejection> {
    let signature = key.sign(&proof.encode());
    let public = key.public_key().as_ref().try_into().unwrap();
    trust.verify(expected, public, proof, signature.as_ref(), now_ms)
}

#[test]
fn rotation_overlap_expiry_revocation_and_replay_are_fail_closed_on_both_branches() {
    for branch in [Branch::H2, Branch::H3] {
        let old = keypair();
        let new = keypair();
        let old_pin = pin(&old, START, RETIRE);
        let new_pin = pin(&new, ROTATE, END);
        let mut trust = Trust::new(policy(1, vec![old_pin]), START).unwrap();
        let first = transcript(branch, START, 1);
        assert_eq!(
            verify(&mut trust, expected(branch), &old, &first, START),
            Ok(())
        );
        assert_eq!(
            verify(&mut trust, expected(branch), &new, &first, START),
            Err(Rejection::Key)
        );

        trust
            .replace(policy(2, vec![old_pin, new_pin]), ROTATE - 1)
            .unwrap();
        assert_eq!(
            verify(&mut trust, expected(branch), &new, &first, ROTATE - 1),
            Err(Rejection::Key)
        );
        assert_eq!(
            verify(&mut trust, expected(branch), &old, &first, ROTATE),
            Err(Rejection::Proof(Failure::Replay))
        );
        let old_overlap = transcript(branch, ROTATE, 4);
        let new_overlap = transcript(branch, ROTATE, 5);
        assert_eq!(
            verify(&mut trust, expected(branch), &old, &old_overlap, ROTATE),
            Ok(())
        );
        assert_eq!(
            verify(&mut trust, expected(branch), &new, &new_overlap, ROTATE),
            Ok(())
        );

        // A proof issued before a key becomes trusted stays invalid.
        let backdated = transcript(branch, ROTATE - 1, 6);
        assert_eq!(
            verify(&mut trust, expected(branch), &new, &backdated, ROTATE),
            Err(Rejection::Key)
        );
        assert_eq!(
            verify(&mut trust, expected(branch), &old, &old_overlap, RETIRE),
            Err(Rejection::Key)
        );
        // An explicit revocation retires the key permanently in this model.
        trust.replace(policy(3, vec![new_pin]), RETIRE).unwrap();
        assert_eq!(
            trust.replace(policy(4, vec![old_pin, new_pin]), RETIRE),
            Err(Rejection::Key)
        );
        let current = transcript(branch, RETIRE, 7);
        assert_eq!(
            verify(&mut trust, expected(branch), &old, &current, RETIRE),
            Err(Rejection::Key)
        );
        assert_eq!(
            verify(&mut trust, expected(branch), &new, &current, RETIRE),
            Ok(())
        );
        assert_eq!(
            verify(&mut trust, expected(branch), &new, &current, END),
            Err(Rejection::Key)
        );
    }
}

#[test]
fn scope_mode_pin_and_generation_mismatch_never_enable_plain_tls() {
    let key = keypair();
    let other = keypair();
    let current_pin = pin(&key, START, END);
    let mut trust = Trust::new(policy(3, vec![current_pin]), START).unwrap();
    let proof = transcript(Branch::H2, START, 1);
    let context = expected(Branch::H2);
    let mut wrong = context;
    wrong.scope.inbound = "edge-b";
    assert_eq!(
        verify(&mut trust, wrong, &key, &proof, START),
        Err(Rejection::Scope)
    );
    wrong = context;
    wrong.scope.host = "other.example.org";
    assert_eq!(
        verify(&mut trust, wrong, &key, &proof, START),
        Err(Rejection::Scope)
    );
    wrong = context;
    wrong.scope.port = 8443;
    assert_eq!(
        verify(&mut trust, wrong, &key, &proof, START),
        Err(Rejection::Scope)
    );
    assert_eq!(
        verify(&mut trust, expected(Branch::H3), &key, &proof, START),
        Err(Rejection::Scope)
    );
    wrong = context;
    wrong.mode = Mode::Plain;
    assert_eq!(
        verify(&mut trust, wrong, &key, &proof, START),
        Err(Rejection::Downgrade)
    );
    assert_eq!(
        verify(&mut trust, context, &other, &proof, START),
        Err(Rejection::Key)
    );
    assert_eq!(
        trust.replace(policy(2, vec![current_pin]), START),
        Err(Rejection::Generation)
    );
    assert_eq!(
        trust.replace(policy(5, vec![current_pin]), START),
        Err(Rejection::Generation)
    );
    assert_eq!(
        trust.replace(policy(4, vec![current_pin, current_pin]), START),
        Err(Rejection::Policy)
    );
    assert_eq!(
        trust.replace(policy(4, vec![pin(&key, START, END + 1)]), START),
        Err(Rejection::Key)
    );
    let mut foreign = policy(4, vec![current_pin]);
    foreign.scope.inbound = "edge-b";
    assert_eq!(trust.replace(foreign, START), Err(Rejection::Scope));
    assert_eq!(
        trust.replace(policy(4, vec![current_pin]), START - 1),
        Err(Rejection::Clock)
    );
    // Failed updates and proofs must not poison the valid policy or replay.
    assert_eq!(verify(&mut trust, context, &key, &proof, START), Ok(()));
    trust.replace(policy(4, vec![current_pin]), ROTATE).unwrap();
    assert_eq!(
        verify(&mut trust, context, &key, &proof, START),
        Err(Rejection::Clock)
    );
}

#[test]
fn retired_key_history_is_bounded_without_eviction_or_partial_update() {
    let keys: Vec<_> = (0..=MAX_RETIRED + 1).map(|_| keypair()).collect();
    let initial = policy(1, vec![pin(&keys[0], START, END)]);
    let mut trust = Trust::new(initial, START).unwrap();
    for (index, key) in keys.iter().enumerate().take(MAX_RETIRED + 1).skip(1) {
        trust
            .replace(policy(index as u64 + 1, vec![pin(key, START, END)]), START)
            .unwrap();
    }
    let next = policy(
        MAX_RETIRED as u64 + 2,
        vec![pin(&keys[MAX_RETIRED + 1], START, END)],
    );
    assert_eq!(trust.replace(next, START), Err(Rejection::RetiredCapacity));
    let proof = transcript(Branch::H3, START, 1);
    assert_eq!(
        verify(&mut trust, expected(Branch::H3), &keys[0], &proof, START),
        Err(Rejection::Key)
    );
    assert_eq!(
        verify(
            &mut trust,
            expected(Branch::H3),
            &keys[MAX_RETIRED],
            &proof,
            START
        ),
        Ok(())
    );
}

#[test]
fn emergency_deny_all_retires_unexpired_pins_and_requires_new_trust() {
    for branch in [Branch::H2, Branch::H3] {
        let old = keypair();
        let replacement = keypair();
        let old_pin = pin(&old, START, END);
        let new_pin = pin(&replacement, ROTATE, END);
        let mut trust = Trust::new(policy(1, vec![old_pin]), START).unwrap();
        let initial = transcript(branch, START, 1);
        assert_eq!(
            verify(&mut trust, expected(branch), &old, &initial, START),
            Ok(())
        );

        // Explicit empty authorized snapshot means no trusted identity.
        // The retired key is still cryptographically valid and unexpired.
        trust.replace(policy(2, vec![]), ROTATE).unwrap();
        let fresh = transcript(branch, ROTATE, 4);
        assert_eq!(
            verify(&mut trust, expected(branch), &old, &fresh, ROTATE),
            Err(Rejection::Key)
        );
        assert_eq!(
            trust.replace(policy(3, vec![old_pin]), ROTATE),
            Err(Rejection::Key)
        );
        trust.replace(policy(3, vec![new_pin]), ROTATE).unwrap();
        assert_eq!(
            verify(&mut trust, expected(branch), &old, &fresh, ROTATE),
            Err(Rejection::Key)
        );
        let bad_signature = old.sign(&fresh.encode());
        assert_eq!(
            trust.verify(
                expected(branch),
                &new_pin.key,
                &fresh,
                bad_signature.as_ref(),
                ROTATE
            ),
            Err(Rejection::Proof(Failure::InvalidProof))
        );
        assert_eq!(
            verify(&mut trust, expected(branch), &replacement, &fresh, ROTATE),
            Ok(())
        );
    }
}

// This is a research checkpoint for public trust metadata, not a production
// persistence format. The expected digest must come from a separately
// trusted, non-rollbackable source; storing it beside the file is insufficient.
const MAX_CHECKPOINT_BYTES: usize = 16 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u32,
    inbound: String,
    host: String,
    port: u16,
    generation: u64,
    pins: Vec<Pin>,
    retired: Vec<[u8; 32]>,
    last_ms: u64,
}

struct Anchor {
    generation: u64,
    digest: [u8; 32],
}

fn checkpoint(trust: &Trust) -> Checkpoint {
    Checkpoint {
        version: 1,
        inbound: trust.policy.scope.inbound.into(),
        host: trust.policy.scope.host.into(),
        port: trust.policy.scope.port,
        generation: trust.policy.generation,
        pins: trust.policy.pins.clone(),
        retired: trust.retired.clone(),
        last_ms: trust.last_ms,
    }
}

fn encode_checkpoint(value: &Checkpoint) -> String {
    toml::to_string(value).unwrap()
}

// Test fixture for an independently authorized external anchor, NOT a
// trust-on-first-use function. Never derive this from an untrusted file.
fn authorize_fixture(value: &Checkpoint, text: &str) -> Anchor {
    Anchor {
        generation: value.generation,
        digest: Sha256::digest(text.as_bytes()).into(),
    }
}

fn restore(text: &str, anchor: &Anchor, scope: Scope, now_ms: u64) -> Result<Trust, Rejection> {
    if text.len() > MAX_CHECKPOINT_BYTES {
        return Err(Rejection::Policy);
    }
    let digest: [u8; 32] = Sha256::digest(text.as_bytes()).into();
    if digest != anchor.digest {
        return Err(Rejection::Policy);
    }
    let saved: Checkpoint = toml::from_str(text).map_err(|_| Rejection::Policy)?;
    if saved.version != 1 || saved.generation != anchor.generation {
        return Err(Rejection::Generation);
    }
    if saved.inbound != scope.inbound || saved.host != scope.host || saved.port != scope.port {
        return Err(Rejection::Scope);
    }
    if now_ms < saved.last_ms {
        return Err(Rejection::Clock);
    }
    if saved.retired.len() > MAX_RETIRED {
        return Err(Rejection::RetiredCapacity);
    }
    for (index, key) in saved.retired.iter().enumerate() {
        if *key == [0; 32]
            || saved.retired[..index].contains(key)
            || saved.pins.iter().any(|pin| pin.key == *key)
        {
            return Err(Rejection::Key);
        }
    }
    let policy = Policy {
        scope,
        generation: saved.generation,
        pins: saved.pins,
    };
    let mut trust = Trust::new(policy, now_ms)?;
    trust.retired = saved.retired;
    // Replay is deliberately NOT restored. The separate channel-binding
    // evidence requires a fresh verified connection after restart.
    Ok(trust)
}

#[test]
fn checkpoint_restore_keeps_retired_keys_and_rejects_rollback() {
    for branch in [Branch::H2, Branch::H3] {
        let old = keypair();
        let new = keypair();
        let old_pin = pin(&old, START, END);
        let new_pin = pin(&new, ROTATE, END);
        let mut trust = Trust::new(policy(1, vec![old_pin]), START).unwrap();
        let previous = encode_checkpoint(&checkpoint(&trust));
        trust.replace(policy(2, vec![new_pin]), ROTATE).unwrap();

        let saved = checkpoint(&trust);
        let text = encode_checkpoint(&saved);
        let anchor = authorize_fixture(&saved, &text);
        drop(trust);

        // A prior valid snapshot cannot be used against the latest anchor.
        assert!(matches!(
            restore(&previous, &anchor, EDGE, ROTATE),
            Err(Rejection::Policy)
        ));
        assert!(matches!(
            restore(&text, &anchor, EDGE, ROTATE - 1),
            Err(Rejection::Clock)
        ));
        let mut foreign = EDGE;
        foreign.inbound = "edge-b";
        assert!(matches!(
            restore(&text, &anchor, foreign, ROTATE),
            Err(Rejection::Scope)
        ));
        let mut restored = restore(&text, &anchor, EDGE, ROTATE).unwrap();
        assert_eq!(
            restored.replace(policy(3, vec![old_pin]), ROTATE),
            Err(Rejection::Key)
        );
        let proof = transcript(branch, ROTATE, 7);
        assert_eq!(
            verify(&mut restored, expected(branch), &old, &proof, ROTATE),
            Err(Rejection::Key)
        );
        assert_eq!(
            verify(&mut restored, expected(branch), &new, &proof, ROTATE),
            Ok(())
        );
    }
}

#[test]
fn checkpoint_rejects_tamper_truncation_unknown_fields_and_bad_anchors() {
    let key = keypair();
    let trust = Trust::new(policy(1, vec![pin(&key, START, END)]), START).unwrap();
    let saved = checkpoint(&trust);
    let text = encode_checkpoint(&saved);
    let anchor = authorize_fixture(&saved, &text);
    for bad in [
        String::new(),
        text[..text.len() / 2].to_owned(),
        format!("{text}# changed\n"),
        "x".repeat(MAX_CHECKPOINT_BYTES + 1),
    ] {
        assert!(matches!(
            restore(&bad, &anchor, EDGE, START),
            Err(Rejection::Policy)
        ));
    }

    // Even independently authorized malformed snapshots must fail validation.
    let unknown = format!("unknown = true\n{text}");
    let unknown_anchor = authorize_fixture(&saved, &unknown);
    assert!(matches!(
        restore(&unknown, &unknown_anchor, EDGE, START),
        Err(Rejection::Policy)
    ));
    let wrong_generation = Anchor {
        generation: 2,
        digest: anchor.digest,
    };
    assert!(matches!(
        restore(&text, &wrong_generation, EDGE, START),
        Err(Rejection::Generation)
    ));
}

#[test]
fn checkpoint_rejects_invalid_retired_history_and_restores_explicit_deny_all() {
    let key = keypair();
    let old_pin = pin(&key, START, END);
    let mut trust = Trust::new(policy(1, vec![old_pin]), START).unwrap();
    let mut saved = checkpoint(&trust);
    saved.retired.push(old_pin.key);
    let overlapping = encode_checkpoint(&saved);
    let anchor = authorize_fixture(&saved, &overlapping);
    assert!(matches!(
        restore(&overlapping, &anchor, EDGE, START),
        Err(Rejection::Key)
    ));

    trust.replace(policy(2, vec![]), ROTATE).unwrap();
    let mut saved = checkpoint(&trust);
    let text = encode_checkpoint(&saved);
    let anchor = authorize_fixture(&saved, &text);
    let mut restored = restore(&text, &anchor, EDGE, ROTATE).unwrap();
    assert!(restored.policy.pins.is_empty());
    assert_eq!(
        restored.replace(policy(3, vec![old_pin]), ROTATE),
        Err(Rejection::Key)
    );

    saved.retired.push(old_pin.key);
    let duplicate = encode_checkpoint(&saved);
    let anchor = authorize_fixture(&saved, &duplicate);
    assert!(matches!(
        restore(&duplicate, &anchor, EDGE, ROTATE),
        Err(Rejection::Key)
    ));
    saved.retired = vec![[1; 32]; MAX_RETIRED + 1];
    let oversized = encode_checkpoint(&saved);
    let anchor = authorize_fixture(&saved, &oversized);
    assert!(matches!(
        restore(&oversized, &anchor, EDGE, ROTATE),
        Err(Rejection::RetiredCapacity)
    ));
}

// File fixtures use a unique, isolated test directory. They do not model
// concurrent hostile filesystem mutation, ACL provisioning or power loss.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let mut nonce = [0; 8];
        SystemRandom::new().fill(&mut nonce).unwrap();
        let name = format!("theia-f18-checkpoint-{:016x}", u64::from_be_bytes(nonce));
        let path = std::env::temp_dir().join(name);
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_fixture(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn restore_file(path: &Path, anchor: &Anchor, now_ms: u64) -> Result<Trust, Rejection> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Rejection::Policy)?;
    if !metadata.is_file() || metadata.len() > MAX_CHECKPOINT_BYTES as u64 {
        return Err(Rejection::Policy);
    }
    let file = File::open(path).map_err(|_| Rejection::Policy)?;
    let mut bytes = Vec::new();
    file.take(MAX_CHECKPOINT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Rejection::Policy)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Rejection::Policy)?;
    restore(text, anchor, EDGE, now_ms)
}

#[test]
fn file_checkpoint_recovery_rejects_partial_stale_and_missing_commits() {
    let dir = Scratch::new();
    let old = keypair();
    let new = keypair();
    let old_pin = pin(&old, START, END);
    let new_pin = pin(&new, ROTATE, END);
    let mut trust = Trust::new(policy(1, vec![old_pin]), START).unwrap();
    let old_text = encode_checkpoint(&checkpoint(&trust));
    let previous = dir.0.join("previous.toml");
    write_fixture(&previous, old_text.as_bytes());

    trust.replace(policy(2, vec![new_pin]), ROTATE).unwrap();
    let saved = checkpoint(&trust);
    let text = encode_checkpoint(&saved);
    let anchor = authorize_fixture(&saved, &text);
    drop(trust);

    let committed = dir.0.join("committed.toml");
    let partial = dir.0.join("partial.tmp");
    write_fixture(&partial, &text.as_bytes()[..text.len() / 2]);

    // A selected commit that is absent must not fall back to any older
    // complete snapshot or an incomplete temporary file.
    for path in [&committed, &previous, &partial, &dir.0] {
        assert!(matches!(
            restore_file(path, &anchor, ROTATE),
            Err(Rejection::Policy)
        ));
    }

    let staged = dir.0.join("staged.tmp");
    write_fixture(&staged, text.as_bytes());
    // Same-directory rename into an absent destination. This is a
    // controlled publication test, not a replacement or durability claim.
    fs::rename(&staged, &committed).unwrap();
    assert!(!staged.exists());
    let mut restored = restore_file(&committed, &anchor, ROTATE).unwrap();
    assert_eq!(
        restored.replace(policy(3, vec![old_pin]), ROTATE),
        Err(Rejection::Key)
    );
    let proof = transcript(Branch::H2, ROTATE, 6);
    assert_eq!(
        verify(&mut restored, expected(Branch::H2), &old, &proof, ROTATE),
        Err(Rejection::Key)
    );
    assert_eq!(
        verify(&mut restored, expected(Branch::H2), &new, &proof, ROTATE),
        Ok(())
    );

    // A damaged committed file must fail closed even when an older
    // complete snapshot remains available in the same directory.
    fs::write(&committed, [0xff, 0xfe]).unwrap();
    assert!(matches!(
        restore_file(&committed, &anchor, ROTATE),
        Err(Rejection::Policy)
    ));
    fs::write(&committed, vec![b'x'; MAX_CHECKPOINT_BYTES + 1]).unwrap();
    assert!(matches!(
        restore_file(&committed, &anchor, ROTATE),
        Err(Rejection::Policy)
    ));
    assert!(matches!(
        restore_file(&previous, &anchor, ROTATE),
        Err(Rejection::Policy)
    ));
}

#[test]
fn independently_anchored_checkpoint_must_still_have_valid_policy() {
    let key = keypair();
    let good = pin(&key, START, END);
    let trust = Trust::new(policy(1, vec![good]), START).unwrap();
    let mut saved = checkpoint(&trust);

    saved.version = 2;
    let text = encode_checkpoint(&saved);
    let anchor = authorize_fixture(&saved, &text);
    assert!(matches!(
        restore(&text, &anchor, EDGE, START),
        Err(Rejection::Generation)
    ));
    saved.version = 1;
    saved.generation = 0;
    let text = encode_checkpoint(&saved);
    let anchor = authorize_fixture(&saved, &text);
    assert!(matches!(
        restore(&text, &anchor, EDGE, START),
        Err(Rejection::Policy)
    ));
    saved.generation = 1;
    for pins in [
        vec![good, good],
        vec![good; MAX_PINS + 1],
        vec![pin(&key, END, START)],
        vec![Pin {
            key: [0; 32],
            ..good
        }],
    ] {
        saved.pins = pins;
        let text = encode_checkpoint(&saved);
        let anchor = authorize_fixture(&saved, &text);
        assert!(matches!(
            restore(&text, &anchor, EDGE, START),
            Err(Rejection::Policy)
        ));
    }

    saved.pins = vec![good];
    saved.retired = vec![[0; 32]];
    let text = encode_checkpoint(&saved);
    let anchor = authorize_fixture(&saved, &text);
    assert!(matches!(
        restore(&text, &anchor, EDGE, START),
        Err(Rejection::Key)
    ));
}

const CHECKPOINT_CHILD_ROOT: &str = "THEIA_TEST_CHECKPOINT_CHILD_ROOT";
const CHECKPOINT_CHILD_PHASE: &str = "THEIA_TEST_CHECKPOINT_CHILD_PHASE";
const CHECKPOINT_CHILD_EXIT: i32 = 74;

#[test]
fn checkpoint_child_exits_at_publication_boundary() {
    let Some(root) = std::env::var_os(CHECKPOINT_CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let phase = std::env::var(CHECKPOINT_CHILD_PHASE).unwrap();
    let text = fs::read(root.join("authorized-fixture.toml")).unwrap();
    let staged = root.join("pending.tmp");
    match phase.as_str() {
        "partial" => write_fixture(&staged, &text[..text.len() / 2]),
        "staged" => write_fixture(&staged, &text),
        "published" => {
            write_fixture(&staged, &text);
            fs::rename(staged, root.join("committed.toml")).unwrap();
        }
        _ => panic!("unknown fixture phase"),
    }
    std::process::exit(CHECKPOINT_CHILD_EXIT);
}

#[test]
fn process_exit_around_checkpoint_publication_never_selects_staging_or_old_state() {
    let old = keypair();
    let new = keypair();
    let old_pin = pin(&old, START, END);
    let new_pin = pin(&new, ROTATE, END);
    let mut trust = Trust::new(policy(1, vec![old_pin]), START).unwrap();
    let previous = encode_checkpoint(&checkpoint(&trust));
    trust.replace(policy(2, vec![new_pin]), ROTATE).unwrap();
    let saved = checkpoint(&trust);
    let text = encode_checkpoint(&saved);
    let anchor = authorize_fixture(&saved, &text);
    drop(trust);

    for phase in ["partial", "staged", "published"] {
        let dir = Scratch::new();
        let old_file = dir.0.join("previous.toml");
        let pending = dir.0.join("pending.tmp");
        let committed = dir.0.join("committed.toml");
        let source = dir.0.join("authorized-fixture.toml");
        write_fixture(&old_file, previous.as_bytes());
        write_fixture(&source, text.as_bytes());

        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "checkpoint_child_exits_at_publication_boundary"])
            .env(CHECKPOINT_CHILD_ROOT, &dir.0)
            .env(CHECKPOINT_CHILD_PHASE, phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(CHECKPOINT_CHILD_EXIT));
        assert!(matches!(
            restore_file(&old_file, &anchor, ROTATE),
            Err(Rejection::Policy)
        ));
        if phase == "published" {
            assert!(!pending.exists());
            let mut restored = restore_file(&committed, &anchor, ROTATE).unwrap();
            assert_eq!(
                restored.replace(policy(3, vec![old_pin]), ROTATE),
                Err(Rejection::Key)
            );
            let proof = transcript(Branch::H3, ROTATE, 6);
            assert_eq!(
                verify(&mut restored, expected(Branch::H3), &new, &proof, ROTATE),
                Ok(())
            );
        } else {
            assert!(pending.exists());
            assert!(matches!(
                restore_file(&committed, &anchor, ROTATE),
                Err(Rejection::Policy)
            ));
            assert!(!committed.exists());
        }
    }
}

#[test]
fn concurrent_policy_updates_from_same_generation_have_only_one_winner() {
    let old = keypair();
    let first = keypair();
    let second = keypair();
    let old_pin = pin(&old, START, END);
    let candidates = [pin(&first, ROTATE, END), pin(&second, ROTATE, END)];
    let trust = Mutex::new(Trust::new(policy(1, vec![old_pin]), START).unwrap());
    let barrier = Barrier::new(2);
    let outcomes = thread::scope(|scope| {
        let workers = candidates.map(|candidate| {
            let trust = &trust;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                trust
                    .lock()
                    .unwrap()
                    .replace(policy(2, vec![candidate]), ROTATE)
            })
        });
        workers.map(|worker| worker.join().unwrap())
    });
    let mut trust = trust.into_inner().unwrap();
    assert_eq!(trust.policy.generation, 2);
    assert_eq!(trust.policy.pins.len(), 1);
    assert_eq!(trust.retired, vec![old_pin.key]);
    let winner = if outcomes[0].is_ok() { 0 } else { 1 };
    assert_eq!(outcomes[winner], Ok(()));
    assert_eq!(outcomes[1 - winner], Err(Rejection::Generation));
    assert_eq!(trust.policy.pins[0].key, candidates[winner].key);

    for (index, key) in [&first, &second].into_iter().enumerate() {
        let proof = transcript(Branch::H2, ROTATE, 5);
        let outcome = verify(&mut trust, expected(Branch::H2), key, &proof, ROTATE);
        assert_eq!(
            outcome,
            if index == winner {
                Ok(())
            } else {
                Err(Rejection::Key)
            }
        );
    }
    let proof = transcript(Branch::H2, ROTATE, 6);
    assert_eq!(
        verify(&mut trust, expected(Branch::H2), &old, &proof, ROTATE),
        Err(Rejection::Key)
    );
}

#[test]
fn concurrent_identical_proofs_consume_only_one_replay_slot() {
    for branch in [Branch::H2, Branch::H3] {
        let signer = keypair();
        let public = pin(&signer, START, END).key;
        let trust = Trust::new(policy(1, vec![pin(&signer, START, END)]), START);
        let trust = Mutex::new(trust.unwrap());
        let proof = transcript(branch, START, 1);
        let signature = signer.sign(&proof.encode());
        let barrier = Barrier::new(2);
        let outcomes = thread::scope(|scope| {
            let workers = [0, 1].map(|_| {
                let trust = &trust;
                let proof = &proof;
                let signature = signature.as_ref();
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    trust
                        .lock()
                        .unwrap()
                        .verify(expected(branch), &public, proof, signature, START)
                })
            });
            workers.map(|worker| worker.join().unwrap())
        });
        let winner = if outcomes[0].is_ok() { 0 } else { 1 };
        assert_eq!(outcomes[winner], Ok(()));
        assert_eq!(outcomes[1 - winner], Err(Rejection::Proof(Failure::Replay)));
        let mut trust = trust.into_inner().unwrap();
        for seed in 2..=8 {
            let fresh = transcript(branch, START, seed);
            assert_eq!(
                verify(&mut trust, expected(branch), &signer, &fresh, START),
                Ok(())
            );
        }
        let excess = transcript(branch, START, 9);
        assert_eq!(
            verify(&mut trust, expected(branch), &signer, &excess, START),
            Err(Rejection::Proof(Failure::Capacity))
        );
    }
}

#[test]
fn distinct_inbound_pins_and_checkpoint_anchors_are_isolated() {
    let first = keypair();
    let second = keypair();
    let first_pin = pin(&first, START, END);
    let second_pin = pin(&second, START, END);
    let other = Scope {
        inbound: "edge-b",
        ..EDGE
    };
    let left = Trust::new(policy(1, vec![first_pin]), START).unwrap();
    let right_policy = Policy {
        scope: other,
        generation: 1,
        pins: vec![second_pin],
    };
    let right = Trust::new(right_policy, START).unwrap();
    let left_saved = checkpoint(&left);
    let right_saved = checkpoint(&right);
    let left_text = encode_checkpoint(&left_saved);
    let right_text = encode_checkpoint(&right_saved);
    let left_anchor = authorize_fixture(&left_saved, &left_text);
    let right_anchor = authorize_fixture(&right_saved, &right_text);
    assert!(matches!(
        restore(&left_text, &right_anchor, other, START),
        Err(Rejection::Policy)
    ));
    assert!(matches!(
        restore(&left_text, &left_anchor, other, START),
        Err(Rejection::Scope)
    ));
    assert!(matches!(
        restore(&right_text, &right_anchor, EDGE, START),
        Err(Rejection::Scope)
    ));
    let mut left = restore(&left_text, &left_anchor, EDGE, START).unwrap();
    let mut right = restore(&right_text, &right_anchor, other, START).unwrap();
    let branch = Branch::H3;
    let proof = transcript(branch, START, 1);
    let mut right_expected = expected(branch);
    right_expected.scope = other;
    assert_eq!(
        verify(&mut right, right_expected, &first, &proof, START),
        Err(Rejection::Key)
    );
    assert_eq!(
        verify(&mut left, expected(branch), &second, &proof, START),
        Err(Rejection::Key)
    );
    assert_eq!(
        verify(&mut right, right_expected, &second, &proof, START),
        Ok(())
    );
    assert_eq!(
        verify(&mut left, expected(branch), &first, &proof, START),
        Ok(())
    );

    left.replace(policy(2, vec![]), ROTATE).unwrap();
    let fresh = transcript(branch, ROTATE, 2);
    assert_eq!(
        verify(&mut left, expected(branch), &first, &fresh, ROTATE),
        Err(Rejection::Key)
    );
    assert_eq!(
        verify(&mut right, right_expected, &second, &fresh, ROTATE),
        Ok(())
    );
}
