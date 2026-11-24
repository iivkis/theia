//! F-18 key-lifecycle policy experiment. Local, pre-authorized trust
//! snapshots only: no network negotiation, production key store or wire API.
#![forbid(unsafe_code)]

#[path = "support/f18_research_identity.rs"]
mod lab;

use lab::{Branch, Failure, ReplayWindow, Transcript};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
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

#[derive(Clone, Copy)]
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
        branch,
        EDGE.host,
        EDGE.port,
        [seed; 32],
        [2; 32],
        [3; 32],
        issued_ms,
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
    trust
        .replace(policy(4, vec![current_pin]), ROTATE)
        .unwrap();
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
