//! Offline candidate tests; not evidence of REALITY TLS admission.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use theia::{
    config::{Transport, XhttpMode},
    descriptor::{
        self, Anchor, Change, ClientPolicy, Descriptor, Error, Padding, Reference, Rotation, Scope,
        SecurityMode, Store,
    },
};

fn key() -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}
fn auto_policy() -> ClientPolicy {
    ClientPolicy {
        transport: Transport::Auto,
        xhttp_mode: XhttpMode::Auto,
    }
}

fn anchor(d: &Descriptor, key: &Ed25519KeyPair) -> Anchor {
    policy_anchor(d, key, auto_policy())
}

fn policy_anchor(d: &Descriptor, key: &Ed25519KeyPair, policy: ClientPolicy) -> Anchor {
    Anchor::new(
        d.scope.clone(),
        key.public_key().as_ref().try_into().unwrap(),
        1,
        policy,
    )
    .unwrap()
}
fn fixture(revision: u64) -> Descriptor {
    Descriptor {
        schema_version: 1,
        wire_version: 1,
        security_mode: SecurityMode::SmartReality,
        revision,
        not_before: 100,
        not_after: 200,
        scope: Scope {
            inbound: "edge".into(),
            endpoint: "edge.example.org:443".into(),
        },
        active_reference: 0,
        references: vec![Reference {
            server_name: "reference.example.org".into(),
            port: 443,
            h3: true,
        }],
        h3: true,
        stream_one: true,
        stream_up: true,
        path_prefix: "/v1/fixture".into(),
        padding: Padding {
            header_min: 0,
            header_max: 100,
            frame_min: 0,
            frame_max: 512,
        },
        rotation: Rotation {
            lifetime_min_s: 10,
            lifetime_max_s: 60,
            volume_min_bytes: 1024,
            volume_max_bytes: 2048,
        },
        next_identity: None,
    }
}
fn assert_error<T>(result: Result<T, Error>, expected: Error) {
    assert_eq!(result.err(), Some(expected));
}

#[test]
fn signed_descriptor_binds_every_field_to_independent_anchor() {
    let key = key();
    let other = self::key();
    let d = fixture(1);
    let a = anchor(&d, &key);
    let raw = descriptor::sign(&d, &key).unwrap();
    let verified = descriptor::verify(&raw, &a).unwrap();
    assert_eq!(verified.descriptor().revision, 1);
    assert_error(verified.check_time(99), Error::Validity);
    verified.check_time(100).unwrap();
    assert_error(verified.check_time(200), Error::Validity);
    assert_error(
        descriptor::verify(&raw, &anchor(&d, &other)),
        Error::Signature,
    );
    let foreign =
        descriptor::verify(&descriptor::sign(&d, &other).unwrap(), &anchor(&d, &other)).unwrap();
    assert_error(verified.compare(&foreign), Error::Scope);
    let floor = Anchor::new(
        d.scope.clone(),
        key.public_key().as_ref().try_into().unwrap(),
        2,
        auto_policy(),
    )
    .unwrap();
    assert_error(descriptor::verify(&raw, &floor), Error::Rollback);
    let mut wrong = d.clone();
    wrong.scope.inbound = "other".into();
    assert_error(
        descriptor::verify(&descriptor::sign(&wrong, &key).unwrap(), &a),
        Error::Scope,
    );
    wrong = d.clone();
    wrong.scope.endpoint = "other.example.org:443".into();
    assert_error(
        descriptor::verify(&descriptor::sign(&wrong, &key).unwrap(), &a),
        Error::Scope,
    );
    let mut envelope: toml::Table = toml::from_str(&raw).unwrap();
    let payload = envelope["payload"].as_str().unwrap();
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    let edited = payload.replace("revision = 1", "revision = 2");
    envelope.insert(
        "payload".into(),
        toml::Value::String(URL_SAFE_NO_PAD.encode(edited)),
    );
    assert_error(
        descriptor::verify(&toml::to_string(&envelope).unwrap(), &a),
        Error::Signature,
    );
    assert_error(
        descriptor::verify(&format!("{raw}\nunknown = 1"), &a),
        Error::Format,
    );
    assert_error(
        descriptor::verify(&"x".repeat(descriptor::MAX_DOCUMENT + 1), &a),
        Error::Format,
    );
}

#[test]
fn signed_invalid_fields_and_unsupported_contract_are_refused() {
    let key = key();
    let d = fixture(1);
    let a = anchor(&d, &key);
    let raw = descriptor::sign(&d, &key).unwrap();
    let original: toml::Table = toml::from_str(&raw).unwrap();
    let payload = String::from_utf8(
        URL_SAFE_NO_PAD
            .decode(original["payload"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    for bad in [
        format!("unknown = 1\n{payload}"),
        format!("revision = 1\n{payload}"),
        payload.replace("wire_version = 1", "wire_version = 2"),
        payload.replace(
            "security_mode = \"smart-reality\"",
            "security_mode = \"own-tls\"",
        ),
    ] {
        let mut input = b"SmartTheia/inbound-descriptor/v1\0".to_vec();
        input.extend_from_slice(bad.as_bytes());
        let sig = key.sign(&input);
        let mut envelope = original.clone();
        envelope.insert(
            "payload".into(),
            toml::Value::String(URL_SAFE_NO_PAD.encode(bad)),
        );
        envelope.insert(
            "signature".into(),
            toml::Value::String(URL_SAFE_NO_PAD.encode(sig.as_ref())),
        );
        assert_error(
            descriptor::verify(&toml::to_string(&envelope).unwrap(), &a),
            Error::Format,
        );
    }
    let mut bad = d.clone();
    bad.references[0].h3 = false;
    assert_error(descriptor::sign(&bad, &key), Error::Format);
    bad = d.clone();
    bad.path_prefix = "/v1/../x".into();
    assert_error(descriptor::sign(&bad, &key), Error::Format);
    bad = d.clone();
    bad.padding.frame_max = 65_537;
    assert_error(descriptor::sign(&bad, &key), Error::Format);
    bad = d.clone();
    bad.references[0].server_name = "edge.example.org".into();
    assert_error(descriptor::sign(&bad, &key), Error::Format);
    bad = d.clone();
    bad.scope.endpoint = "EDGE.example.org:8443".into();
    bad.references[0].server_name = "edge.example.org".into();
    assert_error(descriptor::sign(&bad, &key), Error::Format);
}

#[test]
fn valid_signature_does_not_make_noncanonical_envelope_acceptable() {
    let key = key();
    let d = fixture(1);
    let a = anchor(&d, &key);
    let raw = descriptor::sign(&d, &key).unwrap();
    assert!(descriptor::verify(&raw, &a).is_ok());
    assert_error(
        descriptor::verify(&format!("# extra envelope text\n{raw}"), &a),
        Error::Format,
    );
    assert_error(descriptor::verify(&format!("{raw}\n"), &a), Error::Format);
}

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "theia-descriptor-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn durable_revision_floor_rejects_rollback_equivocation_and_key_substitution_after_restart() {
    let temp = Scratch::new();
    let path = temp.0.join("trust.toml");
    let key = key();
    let successor = self::key();
    let mut first = fixture(1);
    first.next_identity = Some(URL_SAFE_NO_PAD.encode(successor.public_key().as_ref()));
    let a = anchor(&first, &key);
    let first_raw = descriptor::sign(&first, &key).unwrap();
    let store = Store::new(&path, a.clone()).unwrap();
    assert_error(store.update(&first_raw, 120), Error::Storage);
    store.initialize(&first_raw, 120).unwrap();
    assert_error(store.initialize(&first_raw, 120), Error::Storage);
    assert_eq!(store.update(&first_raw, 120).unwrap(), Change::Unchanged);
    let mut second = first.clone();
    second.revision = 7;
    second.not_before = 200;
    second.not_after = 300;
    let next = descriptor::sign(&second, &key).unwrap();
    assert_error(store.update(&next, 199), Error::Validity);
    drop(store);
    let reopened = Store::new(&path, a.clone()).unwrap();
    assert_error(reopened.load(220), Error::Validity);
    assert_eq!(reopened.update(&next, 220).unwrap(), Change::Advanced);
    drop(reopened);
    let reopened = Store::new(&path, a).unwrap();
    assert_eq!(reopened.load(220).unwrap().descriptor().revision, 7);
    let mut rollback = second.clone();
    rollback.revision = 6;
    assert_error(
        reopened.update(&descriptor::sign(&rollback, &key).unwrap(), 220),
        Error::Rollback,
    );
    let mut conflicting = second.clone();
    conflicting.path_prefix = "/v1/other".into();
    assert_error(
        reopened.update(&descriptor::sign(&conflicting, &key).unwrap(), 220),
        Error::Equivocation,
    );
    let mut substituted = second.clone();
    substituted.revision = 8;
    substituted.next_identity = None;
    assert_error(
        reopened.update(&descriptor::sign(&substituted, &successor).unwrap(), 220),
        Error::Signature,
    );
    let saved: toml::Table = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(saved["current"].as_str(), Some(next.as_str()));
    assert_eq!(saved["transitions"].as_array().unwrap().len(), 0);
}

#[test]
fn concurrent_signed_updates_never_publish_a_lower_revision_over_a_higher_one() {
    use std::{sync::Barrier, thread};
    let temp = Scratch::new();
    let path = temp.0.join("trust.toml");
    let key = key();
    let first = fixture(1);
    let anchor = anchor(&first, &key);
    let store = Store::new(&path, anchor.clone()).unwrap();
    store
        .initialize(&descriptor::sign(&first, &key).unwrap(), 120)
        .unwrap();
    let second = descriptor::sign(&fixture(2), &key).unwrap();
    let third = descriptor::sign(&fixture(3), &key).unwrap();
    let barrier = Barrier::new(2);
    let (a, b) = thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            store.update(&second, 120)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            store.update(&third, 120)
        });
        (a.join().unwrap(), b.join().unwrap())
    });
    assert!(a.is_ok() || b.is_ok());
    let revision = store.load(120).unwrap().descriptor().revision;
    if b.is_ok() {
        assert_eq!(revision, 3);
    }
    if a.is_ok() {
        assert!(revision >= 2);
    }
    // A failed writer retries only after re-reading the signed snapshot.
    if revision == 2 {
        assert_eq!(store.update(&third, 120).unwrap(), Change::Advanced);
    }
    assert_error(store.update(&second, 120), Error::Rollback);
    let saved: toml::Table = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(saved["current"].as_str(), Some(third.as_str()));
}

#[test]
fn initialization_never_overwrites_corrupt_or_unrelated_local_state() {
    let temp = Scratch::new();
    let path = temp.0.join("trust.toml");
    fs::write(&path, b"unrelated").unwrap();
    let key = key();
    let first = fixture(1);
    let store = Store::new(&path, anchor(&first, &key)).unwrap();
    let signed = descriptor::sign(&first, &key).unwrap();
    assert_error(store.initialize(&signed, 120), Error::Storage);
    assert!(store.update(&signed, 120).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"unrelated");
}

fn public(key: &Ed25519KeyPair) -> [u8; 32] {
    key.public_key().as_ref().try_into().unwrap()
}

#[test]
fn explicit_rotation_survives_restart_and_retires_previous_signers() {
    let temp = Scratch::new();
    let path = temp.0.join("trust.toml");
    let root = key();
    let next = key();
    let third = key();
    let mut initial = fixture(1);
    initial.next_identity = Some(URL_SAFE_NO_PAD.encode(public(&next)));
    let pinned = anchor(&initial, &root);
    let store = Store::new(&path, pinned.clone()).unwrap();
    store
        .initialize(&descriptor::sign(&initial, &root).unwrap(), 120)
        .unwrap();
    let mut second = fixture(2);
    second.next_identity = Some(URL_SAFE_NO_PAD.encode(public(&third)));
    let signed = descriptor::sign(&second, &next).unwrap();
    let before = fs::read(&path).unwrap();
    assert_error(store.update(&signed, 120), Error::Signature);
    assert_error(
        store.promote(&signed, 2, public(&next), 120),
        Error::Rotation,
    );
    assert_error(
        store.promote(&signed, 1, public(&third), 120),
        Error::Rotation,
    );
    assert_error(
        store.promote(
            &descriptor::sign(&second, &root).unwrap(),
            1,
            public(&next),
            120,
        ),
        Error::Signature,
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(
        store.promote(&signed, 1, public(&next), 120).unwrap(),
        Change::Advanced
    );
    drop(store);
    let reopened = Store::new(&path, pinned.clone()).unwrap();
    assert_eq!(reopened.load(120).unwrap().signer(), public(&next));
    assert_error(reopened.load(119), Error::Validity);
    assert_error(
        reopened.update(&descriptor::sign(&fixture(3), &root).unwrap(), 130),
        Error::Signature,
    );
    let mut retired = fixture(3);
    retired.next_identity = Some(URL_SAFE_NO_PAD.encode(public(&root)));
    assert_error(
        reopened.update(&descriptor::sign(&retired, &next).unwrap(), 130),
        Error::Rotation,
    );
    let final_signed = descriptor::sign(&fixture(4), &third).unwrap();
    assert_eq!(
        reopened
            .promote(&final_signed, 2, public(&third), 130)
            .unwrap(),
        Change::Advanced
    );
    drop(reopened);
    let reopened = Store::new(&path, pinned).unwrap();
    let current = reopened.load(130).unwrap();
    assert_eq!(current.signer(), public(&third));
    assert_eq!(current.descriptor().revision, 4);
    assert_error(
        reopened.update(&descriptor::sign(&fixture(5), &next).unwrap(), 130),
        Error::Signature,
    );
}

#[test]
fn missed_overlap_requires_independent_enrollment_and_preserves_snapshot() {
    let temp = Scratch::new();
    let path = temp.0.join("trust.toml");
    let root = key();
    let next = key();
    let mut first = fixture(1);
    first.next_identity = Some(URL_SAFE_NO_PAD.encode(public(&next)));
    let store = Store::new(&path, anchor(&first, &root)).unwrap();
    store
        .initialize(&descriptor::sign(&first, &root).unwrap(), 120)
        .unwrap();
    let before = fs::read(&path).unwrap();
    let mut second = fixture(2);
    second.not_before = 200;
    second.not_after = 300;
    let successor = descriptor::sign(&second, &next).unwrap();
    assert_error(
        store.promote(&successor, 1, public(&next), 199),
        Error::Validity,
    );
    assert_error(
        store.promote(&successor, 1, public(&next), 200),
        Error::ReenrollmentRequired,
    );
    assert_error(store.load(200), Error::Validity);
    assert_eq!(fs::read(&path).unwrap(), before);
    // Recovery must independently pin a new key, in a fresh store.
    let fresh = Store::new(&temp.0.join("reenrolled.toml"), anchor(&second, &next)).unwrap();
    fresh.initialize(&successor, 220).unwrap();
    assert_eq!(fresh.load(220).unwrap().signer(), public(&next));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn persisted_transition_tampering_is_rejected_without_partial_update() {
    let temp = Scratch::new();
    let path = temp.0.join("trust.toml");
    let root = key();
    let next = key();
    let unrelated = key();
    let mut initial = fixture(1);
    initial.next_identity = Some(URL_SAFE_NO_PAD.encode(public(&next)));
    let pinned = anchor(&initial, &root);
    let store = Store::new(&path, pinned.clone()).unwrap();
    store
        .initialize(&descriptor::sign(&initial, &root).unwrap(), 120)
        .unwrap();
    let signed = descriptor::sign(&fixture(2), &next).unwrap();
    store.promote(&signed, 1, public(&next), 120).unwrap();
    let saved = fs::read_to_string(&path).unwrap();
    let mut forged: toml::Table = toml::from_str(&saved).unwrap();
    let transitions = forged
        .get_mut("transitions")
        .unwrap()
        .as_array_mut()
        .unwrap();
    transitions[0].as_table_mut().unwrap().insert(
        "successor".into(),
        toml::Value::String(descriptor::sign(&fixture(2), &unrelated).unwrap()),
    );
    // Deliberately corrupt an already private fixture, not the product store.
    fs::write(&path, toml::to_string(&forged).unwrap()).unwrap();
    assert_error(
        Store::new(&path, pinned).unwrap().load(120),
        Error::Signature,
    );
    let corrupt = fs::read(&path).unwrap();
    assert_error(
        store.update(&descriptor::sign(&fixture(3), &next).unwrap(), 130),
        Error::Signature,
    );
    assert_eq!(fs::read(&path).unwrap(), corrupt);
}

#[test]
fn bounded_history_requires_reenrollment_instead_of_forgetting_retired_keys() {
    let temp = Scratch::new();
    let path = temp.0.join("trust.toml");
    let keys: Vec<_> = (0..10).map(|_| key()).collect();
    let mut initial = fixture(1);
    initial.next_identity = Some(URL_SAFE_NO_PAD.encode(public(&keys[1])));
    let root = anchor(&initial, &keys[0]);
    let store = Store::new(&path, root.clone()).unwrap();
    store
        .initialize(&descriptor::sign(&initial, &keys[0]).unwrap(), 120)
        .unwrap();
    for i in 1..=8 {
        let mut next = fixture(i as u64 + 1);
        next.next_identity = Some(URL_SAFE_NO_PAD.encode(public(&keys[i + 1])));
        let signed = descriptor::sign(&next, &keys[i]).unwrap();
        assert_eq!(
            store
                .promote(&signed, i as u64, public(&keys[i]), 120)
                .unwrap(),
            Change::Advanced
        );
    }
    let saved = fs::read(&path).unwrap();
    let latest = descriptor::sign(&fixture(10), &keys[9]).unwrap();
    let reopened = Store::new(&path, root).unwrap();
    assert_eq!(reopened.load(120).unwrap().descriptor().revision, 9);
    assert_error(
        reopened.promote(&latest, 9, public(&keys[9]), 120),
        Error::ReenrollmentRequired,
    );
    assert_eq!(fs::read(&path).unwrap(), saved);
    // Ordinary same-key updates remain possible even at the history ceiling.
    assert_eq!(
        reopened
            .update(&descriptor::sign(&fixture(10), &keys[8]).unwrap(), 120)
            .unwrap(),
        Change::Advanced
    );
}

#[test]
fn competing_promotion_and_old_key_update_have_one_revision_guard() {
    use std::{sync::Barrier, thread};
    let temp = Scratch::new();
    let path = temp.0.join("trust.toml");
    let old = key();
    let successor = key();
    let mut first = fixture(1);
    first.next_identity = Some(URL_SAFE_NO_PAD.encode(public(&successor)));
    let root = anchor(&first, &old);
    let store = Store::new(&path, root.clone()).unwrap();
    store
        .initialize(&descriptor::sign(&first, &old).unwrap(), 120)
        .unwrap();
    let replacement = descriptor::sign(&fixture(2), &successor).unwrap();
    let old_update = descriptor::sign(&fixture(3), &old).unwrap();
    let barrier = Barrier::new(2);
    let (a, b) = thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            store.promote(&replacement, 1, public(&successor), 120)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            store.update(&old_update, 120)
        });
        (a.join().unwrap(), b.join().unwrap())
    });
    assert_ne!(a.is_ok(), b.is_ok());
    let reopened = Store::new(&path, root).unwrap();
    let current = reopened.load(120).unwrap();
    if a.is_ok() {
        assert_eq!(current.signer(), public(&successor));
        assert_eq!(current.descriptor().revision, 2);
        assert_error(reopened.update(&old_update, 120), Error::Signature);
    } else {
        assert_eq!(current.signer(), public(&old));
        assert_eq!(current.descriptor().revision, 3);
        assert_error(
            reopened.promote(&replacement, 1, public(&successor), 120),
            Error::Rotation,
        );
    }
}

#[test]
fn offline_cli_requires_exact_preview_digest_and_guarded_revision() {
    use sha2::{Digest, Sha256};
    use std::{
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };
    let scratch = Scratch::new();
    let root = key();
    let successor = key();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut first = fixture(1);
    first.not_before = now - 1;
    first.not_after = now + 3600;
    first.next_identity = Some(URL_SAFE_NO_PAD.encode(public(&successor)));
    let anchor_path = scratch.0.join("anchor.toml");
    let store = scratch.0.join("store.toml");
    let document = scratch.0.join("descriptor.toml");
    let anchor_text = format!("schema_version = 1\ninbound = \"edge\"\nendpoint = \"edge.example.org:443\"\npublic_key = \"{}\"\nminimum_revision = 1\ntransport = \"auto\"\nxhttp_mode = \"auto\"\n", URL_SAFE_NO_PAD.encode(public(&root)));
    use std::io::Write;
    {
        let mut anchor = theia::client_import::create_private_file(&anchor_path)
            .expect("create protected independent trust anchor");
        anchor.write_all(anchor_text.as_bytes()).unwrap();
        anchor.sync_all().unwrap();
    }
    let raw = descriptor::sign(&first, &root).unwrap();
    fs::write(&document, &raw).unwrap();
    let a = anchor_path.to_str().unwrap();
    let s = store.to_str().unwrap();
    let d = document.to_str().unwrap();
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_theia"))
            .args(args)
            .output()
            .unwrap()
    };
    let hash = |raw: &str| format!("{:x}", Sha256::digest(raw.as_bytes()));
    let preview = invoke(&["trust", "verify", "--anchor", a, "--document", d]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let verified_text = String::from_utf8_lossy(&preview.stdout);
    assert!(verified_text.contains(&hash(&raw)));
    assert!(verified_text.contains("effective_h2=true"));
    assert!(verified_text.contains("effective_h3=true"));
    assert!(verified_text.contains("effective_stream_one=true"));
    assert!(verified_text.contains("effective_stream_up=true"));
    assert!(!store.exists());
    let bad_hash = "00".repeat(32);
    assert!(!invoke(&[
        "trust",
        "enroll",
        "--anchor",
        a,
        "--store",
        s,
        "--document",
        d,
        "--sha256",
        &bad_hash,
        "--confirm"
    ])
    .status
    .success());
    assert!(!store.exists());
    assert!(!invoke(&[
        "trust",
        "enroll",
        "--anchor",
        a,
        "--store",
        s,
        "--document",
        d,
        "--sha256",
        &hash(&raw)
    ])
    .status
    .success());
    assert!(invoke(&[
        "trust",
        "enroll",
        "--anchor",
        a,
        "--store",
        s,
        "--document",
        d,
        "--sha256",
        &hash(&raw),
        "--confirm"
    ])
    .status
    .success());
    let mut second = first.clone();
    second.revision = 2;
    let update = descriptor::sign(&second, &root).unwrap();
    fs::write(&document, &update).unwrap();
    let before = fs::read(&store).unwrap();
    let preview = invoke(&[
        "trust",
        "preview-update",
        "--anchor",
        a,
        "--store",
        s,
        "--document",
        d,
    ]);
    assert!(preview.status.success());
    assert!(String::from_utf8_lossy(&preview.stdout).contains("expected_revision=1"));
    assert_eq!(fs::read(&store).unwrap(), before);
    assert!(!invoke(&[
        "trust",
        "update",
        "--anchor",
        a,
        "--store",
        s,
        "--document",
        d,
        "--expected-revision",
        "2",
        "--sha256",
        &hash(&update),
        "--confirm"
    ])
    .status
    .success());
    assert_eq!(fs::read(&store).unwrap(), before);
    assert!(invoke(&[
        "trust",
        "update",
        "--anchor",
        a,
        "--store",
        s,
        "--document",
        d,
        "--expected-revision",
        "1",
        "--sha256",
        &hash(&update),
        "--confirm"
    ])
    .status
    .success());
    let mut third = first;
    third.revision = 3;
    third.next_identity = None;
    let rotation = descriptor::sign(&third, &successor).unwrap();
    fs::write(&document, &rotation).unwrap();
    let next = URL_SAFE_NO_PAD.encode(public(&successor));
    let preview = invoke(&[
        "trust",
        "preview-rotation",
        "--anchor",
        a,
        "--store",
        s,
        "--document",
        d,
        "--next-key",
        &next,
    ]);
    assert!(preview.status.success());
    assert!(String::from_utf8_lossy(&preview.stdout).contains("expected_revision=2"));
    assert!(invoke(&[
        "trust",
        "rotate",
        "--anchor",
        a,
        "--store",
        s,
        "--document",
        d,
        "--next-key",
        &next,
        "--expected-revision",
        "2",
        "--sha256",
        &hash(&rotation),
        "--confirm"
    ])
    .status
    .success());
    let inspected = invoke(&["trust", "inspect", "--anchor", a, "--store", s]);
    assert!(inspected.status.success());
    let text = String::from_utf8_lossy(&inspected.stdout);
    assert!(text.contains("revision=3"));
    assert!(text.contains("runtime UNCHANGED"));
    assert!(!text.contains("edge.example.org"));
}

#[test]
fn persisted_acceptance_time_prevents_ordinary_clock_rollback() {
    let temp = Scratch::new();
    let root = key();
    let first = fixture(1);
    let path = temp.0.join("trust.toml");
    let pinned = anchor(&first, &root);
    let store = Store::new(&path, pinned.clone()).unwrap();
    store
        .initialize(&descriptor::sign(&first, &root).unwrap(), 120)
        .unwrap();
    let second = descriptor::sign(&fixture(2), &root).unwrap();
    store.update_at(&second, 1, 150).unwrap();
    let reopened = Store::new(&path, pinned).unwrap();
    let saved = fs::read(&path).unwrap();
    assert_error(reopened.inspect(149), Error::Validity);
    assert_error(
        reopened.update(&descriptor::sign(&fixture(3), &root).unwrap(), 149),
        Error::Validity,
    );
    assert_eq!(fs::read(&path).unwrap(), saved);
    assert_eq!(reopened.load(150).unwrap().descriptor().revision, 2);
}

#[test]
fn local_policy_intersects_offers_without_overriding_explicit_modes() {
    let mut descriptor = fixture(1);
    for (transport, h2, h3) in [
        (Transport::Auto, true, true),
        (Transport::H2, true, false),
        (Transport::H3, false, true),
    ] {
        for (xhttp_mode, stream_one, stream_up) in [
            (XhttpMode::Auto, true, true),
            (XhttpMode::StreamOne, true, false),
            (XhttpMode::StreamUp, false, true),
        ] {
            let modes = ClientPolicy {
                transport,
                xhttp_mode,
            }
            .intersect(&descriptor)
            .unwrap();
            assert_eq!((modes.h2, modes.h3), (h2, h3));
            assert_eq!((modes.stream_one, modes.stream_up), (stream_one, stream_up));
        }
    }
    descriptor.h3 = false;
    descriptor.stream_up = false;
    let modes = auto_policy().intersect(&descriptor).unwrap();
    assert!(modes.h2 && modes.stream_one);
    assert!(!modes.h3 && !modes.stream_up);
    for policy in [
        ClientPolicy {
            transport: Transport::H3,
            xhttp_mode: XhttpMode::Auto,
        },
        ClientPolicy {
            transport: Transport::Auto,
            xhttp_mode: XhttpMode::StreamUp,
        },
    ] {
        assert_error(policy.intersect(&descriptor), Error::Policy);
    }
}

#[test]
fn incompatible_signed_update_cannot_replace_working_snapshot() {
    let scratch = Scratch::new();
    let path = scratch.0.join("store.toml");
    let root = key();
    let first = fixture(1);
    let policy = ClientPolicy {
        transport: Transport::H3,
        xhttp_mode: XhttpMode::StreamUp,
    };
    let anchor = policy_anchor(&first, &root, policy);
    let store = Store::new(&path, anchor.clone()).unwrap();
    let raw = descriptor::sign(&first, &root).unwrap();
    store.initialize(&raw, 120).unwrap();
    let before = fs::read(&path).unwrap();
    for remove_h3 in [true, false] {
        let mut next = fixture(2);
        if remove_h3 {
            next.h3 = false;
        } else {
            next.stream_up = false;
        }
        let signed = descriptor::sign(&next, &root).unwrap();
        assert_error(store.preview_update(&signed, 121), Error::Policy);
        assert_error(store.update_at(&signed, 1, 121), Error::Policy);
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    let reopened = Store::new(&path, anchor).unwrap();
    let verified = reopened.load(122).unwrap();
    assert_eq!(verified.descriptor().revision, 1);
    let modes = verified.effective_modes();
    assert!(modes.h3 && modes.stream_up);
    assert!(!modes.h2 && !modes.stream_one);
}

#[test]
fn incompatible_successor_cannot_bypass_local_policy_during_rotation() {
    let scratch = Scratch::new();
    let path = scratch.0.join("store.toml");
    let root = key();
    let successor = key();
    let mut first = fixture(1);
    first.next_identity = Some(URL_SAFE_NO_PAD.encode(public(&successor)));
    let policy = ClientPolicy {
        transport: Transport::H3,
        xhttp_mode: XhttpMode::StreamOne,
    };
    let anchor = policy_anchor(&first, &root, policy);
    let store = Store::new(&path, anchor.clone()).unwrap();
    store
        .initialize(&descriptor::sign(&first, &root).unwrap(), 120)
        .unwrap();
    let before = fs::read(&path).unwrap();
    let mut next = fixture(2);
    next.h3 = false;
    let signed = descriptor::sign(&next, &successor).unwrap();
    assert_error(
        store.preview_promotion(&signed, public(&successor), 121),
        Error::Policy,
    );
    assert_error(
        store.promote(&signed, 1, public(&successor), 121),
        Error::Policy,
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    next.h3 = true;
    let signed = descriptor::sign(&next, &successor).unwrap();
    assert_eq!(
        store.promote(&signed, 1, public(&successor), 121).unwrap(),
        Change::Advanced
    );
    let reopened = Store::new(&path, anchor).unwrap();
    let effective = reopened.load(122).unwrap().effective_modes();
    assert!(effective.h3 && effective.stream_one);
    assert!(!effective.h2 && !effective.stream_up);
}
