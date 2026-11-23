//! F-18 / M3.5a1 research-only tests: a candidate *additional* server
//! identity proof bound to a verified TLS exporter. NOT a wire protocol,
//! REALITY handshake, anti-probing protection or production security mode.
#![forbid(unsafe_code)]

#[path = "support/f18_research_identity.rs"]
mod lab;

use lab::{Branch, Failure, ReplayWindow, Transcript, WINDOW_MS};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};

fn keypair() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn nonce() -> [u8; 32] {
    let mut result = [0u8; 32];
    SystemRandom::new().fill(&mut result).unwrap();
    result
}

fn fixture(branch: Branch) -> Transcript {
    Transcript::new(
        branch,
        "edge.example.org",
        443,
        nonce(),
        nonce(),
        nonce(), // test-only stand-in; real TLS exporters are separately exercised in CI
        10_000,
    )
    .unwrap()
}

fn pinned_key(key: &Ed25519KeyPair) -> [u8; 32] {
    key.public_key().as_ref().try_into().unwrap()
}

#[test]
fn signed_session_and_server_identity_are_bound_and_a_replay_is_rejected() {
    let key = keypair();
    let transcript = fixture(Branch::H2);
    let signature = key.sign(&transcript.encode());
    let mut seen = ReplayWindow::new(8).unwrap();
    let pin = pinned_key(&key);

    assert_eq!(
        seen.accept(&pin, &transcript, signature.as_ref(), 10_000),
        Ok(())
    );
    assert_eq!(
        seen.accept(&pin, &transcript, signature.as_ref(), 10_001),
        Err(Failure::Replay)
    );
}

#[test]
fn independent_pinned_key_is_required_even_with_a_valid_tls_exporter() {
    let trusted = keypair();
    let attacker = keypair();
    let transcript = fixture(Branch::H2);
    let signed_by_attacker = attacker.sign(&transcript.encode());
    let mut seen = ReplayWindow::new(8).unwrap();

    assert_eq!(
        seen.accept(
            &pinned_key(&trusted),
            &transcript,
            signed_by_attacker.as_ref(),
            10_000,
        ),
        Err(Failure::InvalidProof)
    );
    // Failed authentication must not poison replay state.
    let correct = trusted.sign(&transcript.encode());
    assert_eq!(
        seen.accept(&pinned_key(&trusted), &transcript, correct.as_ref(), 10_000),
        Ok(())
    );
}

#[test]
fn any_changed_transport_endpoint_nonce_exporter_or_freshness_invalidates_proof() {
    let key = keypair();
    let original = fixture(Branch::H2);
    let signature = key.sign(&original.encode());
    let pin = pinned_key(&key);

    let mut changed = original.clone();
    changed.branch = Branch::H3;
    let mut alternatives = vec![changed];

    let mut changed = original.clone();
    changed.server_name = "other.example.org".to_owned();
    alternatives.push(changed);

    let mut changed = original.clone();
    changed.port = 8443;
    alternatives.push(changed);

    let mut changed = original.clone();
    changed.client_nonce = nonce();
    alternatives.push(changed);

    let mut changed = original.clone();
    changed.server_nonce = nonce();
    alternatives.push(changed);

    let mut changed = original.clone();
    changed.exporter = nonce();
    alternatives.push(changed);

    let mut changed = original.clone();
    changed.issued_ms += 1;
    alternatives.push(changed);

    for changed in alternatives {
        let mut seen = ReplayWindow::new(8).unwrap();
        assert_eq!(
            seen.accept(&pin, &changed, signature.as_ref(), 10_000),
            Err(Failure::InvalidProof),
            "identity proof must be transcript-exact"
        );
    }
    // H3 is independently signed; a H2 proof is not silently reused for QUIC.
    let h3 = fixture(Branch::H3);
    let signature = key.sign(&h3.encode());
    assert_eq!(
        ReplayWindow::new(8).unwrap().accept(&pin, &h3, signature.as_ref(), 10_000),
        Ok(())
    );
}

#[test]
fn stale_future_and_backwards_clock_fail_closed() {
    let key = keypair();
    let proof = fixture(Branch::H2);
    let signature = key.sign(&proof.encode());
    let pin = pinned_key(&key);
    let mut seen = ReplayWindow::new(8).unwrap();

    assert_eq!(
        seen.accept(&pin, &proof, signature.as_ref(), 7_999),
        Err(Failure::Future)
    );
    assert_eq!(
        seen.accept(&pin, &proof, signature.as_ref(), 10_000 + WINDOW_MS),
        Err(Failure::Expired)
    );
    assert_eq!(
        seen.accept(&pin, &proof, signature.as_ref(), 10_000 + WINDOW_MS - 1),
        Ok(())
    );
    assert_eq!(
        seen.accept(&pin, &proof, signature.as_ref(), 10_100),
        Err(Failure::ClockRollback)
    );
}

#[test]
fn cache_capacity_never_evicts_live_challenges_and_expires_at_signed_deadline() {
    let key = keypair();
    let pin = pinned_key(&key);
    let mut seen = ReplayWindow::new(2).unwrap();

    let first = fixture(Branch::H2);
    let second = fixture(Branch::H2);
    let third = fixture(Branch::H2);
    for proof in [&first, &second] {
        assert_eq!(
            seen.accept(&pin, proof, key.sign(&proof.encode()).as_ref(), 10_000),
            Ok(())
        );
    }
    assert_eq!(
        seen.accept(&pin, &third, key.sign(&third.encode()).as_ref(), 10_000),
        Err(Failure::Capacity)
    );
    assert_eq!(
        seen.accept(&pin, &first, key.sign(&first.encode()).as_ref(), 10_001),
        Err(Failure::Replay)
    );
    assert_eq!(ReplayWindow::new(0).err(), Some(Failure::Capacity));
    assert_eq!(ReplayWindow::new(4_097).err(), Some(Failure::Capacity));

    let refreshed = Transcript::new(
        Branch::H3,
        "edge.example.org",
        443,
        nonce(),
        nonce(),
        nonce(),
        10_000 + WINDOW_MS,
    )
    .unwrap();
    assert_eq!(
        seen.accept(
            &pin,
            &refreshed,
            key.sign(&refreshed.encode()).as_ref(),
            10_000 + WINDOW_MS,
        ),
        Ok(())
    );
}

#[test]
fn noncanonical_names_zero_entropy_and_bad_ports_are_rejected() {
    for name in [
        "",
        "Edge.example.org",
        "edge.example.org.",
        "edge..example.org",
        "-edge.example.org",
        "edge-.example.org",
        "edge.example.org:443",
        "éxample.org",
    ] {
        assert_eq!(
            Transcript::new(Branch::H2, name, 443, nonce(), nonce(), nonce(), 10_000).err(),
            Some(Failure::InvalidTranscript)
        );
    }
    assert_eq!(
        Transcript::new(
            Branch::H2, "edge.example.org", 0, nonce(), nonce(), nonce(), 10_000,
        )
        .err(),
        Some(Failure::InvalidTranscript)
    );
    assert_eq!(
        Transcript::new(
            Branch::H2, "edge.example.org", 443, [0u8; 32], nonce(), nonce(), 10_000,
        )
        .err(),
        Some(Failure::InvalidTranscript)
    );
    assert_eq!(
        Transcript::new(
            Branch::H2, "edge.example.org", 443, nonce(), [0u8; 32], nonce(), 10_000,
        )
        .err(),
        Some(Failure::InvalidTranscript)
    );
    assert_eq!(
        Transcript::new(
            Branch::H2, "edge.example.org", 443, nonce(), nonce(), [0u8; 32], 10_000,
        )
        .err(),
        Some(Failure::InvalidTranscript)
    );
}
