//! Guarded registration of independently provisioned REALITY material in
//! the shared server/client TOML schema. This is persistence, NOT activation.
//! A REALITY record can never be reinterpreted as an ordinary TLS profile.
#![forbid(unsafe_code)]

use crate::{
    config::{self, Config, Inbound, Profile, RealityBinding, RealityClientBinding, WriteFailure},
    reality_bootstrap::{self as bootstrap, Error},
    reference_health,
    security_profile::SecurityMode,
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::{Path, PathBuf}};
use subtle::ConstantTimeEq;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerRequest {
    pub health: PathBuf,
    pub bundle: PathBuf,
    pub health_sha256: [u8; 32],
    pub identity_sha256: [u8; 32],
    pub listen: SocketAddr,
    pub grants: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRequest {
    pub enrollment: PathBuf,
    pub identity_sha256: [u8; 32],
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Server(ServerRequest),
    Client(ClientRequest),
    /// Explicit independent re-enrollment, never an automatic trust transition.
    Reenroll(ClientRequest),
}

pub struct Prepared {
    original: Vec<u8>,
    candidate: Config,
    approval_sha256: [u8; 32],
    report: String,
}

impl Prepared {
    pub fn approval_sha256(&self) -> [u8; 32] { self.approval_sha256 }
    pub(crate) fn source_sha256(&self) -> [u8; 32] { Sha256::digest(&self.original).into() }
    pub fn report(&self) -> &str { &self.report }
    pub fn candidate(&self) -> &Config { &self.candidate }
}

fn path_string(path: &Path) -> Result<String, Error> {
    if !crate::bounded_input::explicit_file_path(path) {
        return Err(Error::Storage);
    }
    path.to_str().filter(|p| !p.chars().any(char::is_control))
        .map(str::to_owned).ok_or(Error::Storage)
}

fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(64);
    for byte in bytes { let _ = write!(out, "{byte:02x}"); }
    out
}

fn approval(original: &[u8], next: &str, evidence: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"Theia/REALITY-config-registration/v1\0");
    for part in [original, next.as_bytes(), evidence.as_slice()] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

/// Read and validate exactly one config snapshot plus the corresponding
/// independent enrollment or complete initial server receipt. The returned
/// config is immutable; no listener, proxy, grant runtime or file is changed.
pub fn prepare(path: &Path, request: &Request, now: u64) -> Result<Prepared, Error> {
    path_string(path)?;
    let original = config::editor_bytes(path).map_err(|_| Error::Storage)?;
    let mut candidate = config::parse(std::str::from_utf8(&original).map_err(|_| Error::Format)?)
        .map_err(|_| Error::Format)?;
    let (report, evidence) = match (&mut candidate, request) {
        (Config::Server(document), Request::Server(r)) => {
            if r.listen.port() == 0 || r.grants.is_empty() || r.grants.len() > 256 {
                return Err(Error::Grant);
            }
            // Require explicit enabled user grants at initial registration.
            if r.grants.iter().any(|id| !document.server.users.iter().any(|u| &u.id == id && !u.disabled)) {
                return Err(Error::Grant);
            }
            let state = reference_health::Store::new(&r.health).map_err(|_| Error::Health)?
                .inspect().map_err(|_| Error::Health)?;
            let record = crate::reality_provision::inspect_initial(&state, r.health_sha256,
                r.identity_sha256, &r.bundle, now)?;
            let (host, port) = record.scope.endpoint.rsplit_once(':').ok_or(Error::Scope)?;
            if port.parse::<u16>().ok() != Some(r.listen.port()) {
                return Err(Error::Scope);
            }
            if document.server.inbounds.iter().any(|i| i.id == record.scope.inbound) {
                return Err(Error::Scope);
            }
            document.server.inbounds.push(Inbound {
                id: record.scope.inbound.clone(),
                security_mode: SecurityMode::SmartReality,
                reality: Some(RealityBinding {
                    health_store: path_string(&r.health)?,
                    bundle: path_string(&r.bundle)?,
                    initial_health_sha256: r.health_sha256,
                    identity_sha256: r.identity_sha256,
                    manifest_sha256: record.manifest_sha256()?,
                }),
                allowed_user_ids: r.grants.clone(),
                h2_listen: r.listen.to_string(),
                quic_listen: r.listen.to_string(),
                server_name: host.to_owned(),
                tls_cert: String::new(), tls_key: String::new(),
            });
            let report = format!("Register REALITY inbound (saved configuration only)\ninbound={}\nendpoint={}\nlisten={}\ngrants={}\nidentity_sha256={}\n{}\nExisting runtime remains unchanged. Startup uses the registered generation; live changes require a separate supported activation operation.",
                record.scope.inbound, record.scope.endpoint, r.listen, r.grants.join(","),
                hex(record.identity_sha256), state.report(now).map_err(|_| Error::Health)?);
            (report, record.publication_sha256)
        }
        (Config::Client(document), Request::Client(r)) => {
            if !config::valid_id(&r.id) || document.client.profiles.iter().any(|p| p.id == r.id) {
                return Err(Error::Scope);
            }
            let (profile, enrollment_sha256) = bootstrap::Profile::read_snapshot(&r.enrollment)?;
            if !bool::from(profile.enrollment_identity()?.ct_eq(&r.identity_sha256)) {
                return Err(Error::Approval);
            }
            let value = profile.load(now)?;
            let policy = profile.policy();
            let host = profile.endpoint().rsplit_once(':').ok_or(Error::Scope)?.0;
            document.client.profiles.push(Profile {
                id: r.id.clone(), server: profile.endpoint().to_owned(), server_name: host.to_owned(),
                auth_token: profile.credential_reference().to_owned(),
                tls_profile: "smart-reality".into(),
                reality_profile: Some(RealityClientBinding {
                    enrollment: path_string(&r.enrollment)?,
                    enrollment_sha256,
                    identity_sha256: r.identity_sha256,
                }),
                xhttp_mode: Some(policy.xhttp_mode), tls_ca: None, transport: policy.transport,
                quic_connect_timeout_ms: 1600, quic_negative_cache_ttl_s: 900,
            });
            let modes = value.effective_modes();
            let report = format!("Register REALITY profile (saved configuration only)\nprofile={}\nendpoint={}\nidentity_sha256={}\nrevision={}\nh2={}\nh3={}\nstream_one={}\nstream_up={}\nActive profile and proxy remain unchanged. Selected profile can be started after preflight; the current process is unchanged.",
                r.id, profile.endpoint(), hex(bootstrap::fingerprint(value.signer())), value.descriptor().revision,
                modes.h2, modes.h3, modes.stream_one, modes.stream_up);
            (report, value.payload_sha256())
        }
        (Config::Client(document), Request::Reenroll(r)) => {
            let entry = document.client.profiles.iter_mut().find(|p| p.id == r.id).ok_or(Error::Scope)?;
            let old = pinned_client(entry)?;
            let binding = entry.reality_profile.as_ref().ok_or(Error::Format)?;
            let new_path = path_string(&r.enrollment)?;
            if new_path == binding.enrollment { return Err(Error::Approval); }
            let (replacement, enrollment_sha256) = bootstrap::Profile::read_snapshot(&r.enrollment)?;
            if !bool::from(replacement.enrollment_identity()?.ct_eq(&r.identity_sha256)) {
                return Err(Error::Approval);
            }
            let (new_snapshot, value) = replacement.store()?.inspect_bound(now).map_err(|_| Error::Descriptor)?;
            value.check_time(now).map_err(|_| Error::Descriptor)?;
            // This is a freshly and independently enrolled root, not a
            // successor inferred from untrusted data or a historical key.
            if bootstrap::fingerprint(value.signer()) != r.identity_sha256 {
                return Err(Error::Identity);
            }
            let (old_snapshot, previous) = old.store()?.inspect_replacement(value.signer(), now)
                .map_err(|_| Error::Descriptor)?;
            if previous.descriptor().scope != value.descriptor().scope
                || old.endpoint() != replacement.endpoint()
                || old.policy().transport != replacement.policy().transport
                || old.policy().xhttp_mode != replacement.policy().xhttp_mode {
                return Err(Error::Scope);
            }
            let credential_changed = entry.auth_token != replacement.credential_reference();
            entry.auth_token = replacement.credential_reference().to_owned();
            entry.reality_profile = Some(RealityClientBinding {
                enrollment: new_path, enrollment_sha256, identity_sha256: r.identity_sha256,
            });
            // Keep the old files untouched for investigation. The normal
            // config CAS is the only publication point of the replacement.
            let mut hash = Sha256::new();
            hash.update(b"Theia/independent-reenrollment/v1\0");
            hash.update(old_snapshot);
            hash.update(new_snapshot);
            let evidence = hash.finalize().into();
            let report = format!("Independent REALITY re-enrollment; saved configuration only\nprofile={}\nendpoint={}\nold_identity_sha256={}\nnew_identity_sha256={}\nold_revision={}\nnew_revision={}\nold_valid_now={}\ncredential_reference_changed={}\nConfirm new identity independently. Not an automatic trust transition. Old enrollment and trust files retained. Active profile, transport policy and proxy unchanged; no runtime activation.",
                r.id, old.endpoint(), hex(bootstrap::fingerprint(previous.signer())), hex(r.identity_sha256),
                previous.descriptor().revision, value.descriptor().revision, previous.check_time(now).is_ok(), credential_changed);
            (report, evidence)
        }
        _ => return Err(Error::Format),
    };
    // The normal typed validator enforces unique IDs, non-overlapping bind
    // addresses, explicit grants and mutually exclusive trust modes.
    let next = candidate.to_toml().map_err(|_| Error::Format)?;
    let approval_sha256 = approval(&original, &next, evidence);
    Ok(Prepared { original, candidate, approval_sha256, report })
}

/// Repeat all material checks at Apply. The config CAS operates on the
/// original bytes, not a serialization of a stale cached document.
pub fn apply(path: &Path, request: &Request, expected: [u8; 32], now: u64) -> Result<(), Error> {
    let prepared = prepare(path, request, now)?;
    if !bool::from(prepared.approval_sha256.ct_eq(&expected)) {
        return Err(Error::Approval);
    }
    config::guarded_write(path, &prepared.candidate, &prepared.original)
        .map(|_| ()).map_err(|error| match error {
            WriteFailure::BeforeReplace(_) => Error::Storage,
            WriteFailure::AfterReplace(_) => Error::Indeterminate,
        })
}

/// Validate the immutable enrollment pinned by the shared config before
/// interpreting mutable trust history. A copied/replaced profile, changed
/// bearer ref or independently edited mode must not silently take effect.
pub(crate) fn pinned_client(profile: &Profile) -> Result<bootstrap::Profile, Error> {
    if profile.tls_profile != "smart-reality" || profile.tls_ca.is_some() {
        return Err(Error::Format);
    }
    let binding = profile.reality_profile.as_ref().ok_or(Error::Format)?;
    let (enrollment, digest) = bootstrap::Profile::read_snapshot(Path::new(&binding.enrollment))?;
    if !bool::from(digest.ct_eq(&binding.enrollment_sha256))
        || !bool::from(enrollment.enrollment_identity()?.ct_eq(&binding.identity_sha256))
        || enrollment.endpoint() != profile.server
        || enrollment.credential_reference() != profile.auth_token
        || enrollment.policy().transport != profile.transport
        || enrollment.policy().xhttp_mode != profile.effective_xhttp_mode() {
        return Err(Error::Approval);
    }
    Ok(enrollment)
}

pub fn validate_client(profile: &Profile, now: u64) -> Result<crate::descriptor::Verified, Error> {
    pinned_client(profile)?.load(now)
}

/// Read-only status for a saved REALITY record. Distinguish valid trust,
/// stale/unavailable reference evidence and runtime backend availability.
pub fn registered_status(path: &Path, id: &str, now: u64) -> Result<String, Error> {
    path_string(path)?;
    let document = config::read_file(path).map_err(|_| Error::Format)?;
    status_document(&document, id, now)
}

/// Render from the exact saved configuration bytes selected by the editor.
/// Never use a second file read that may inspect a different record.
pub(crate) fn status_expected(path: &Path, expected: [u8; 32], id: &str, now: u64) -> Result<String, Error> {
    path_string(path)?;
    let raw = config::editor_bytes(path).map_err(|_| Error::Storage)?;
    let actual: [u8; 32] = Sha256::digest(&raw).into();
    if actual != expected { return Err(Error::Approval); }
    let document = config::parse(std::str::from_utf8(&raw).map_err(|_| Error::Format)?)
        .map_err(|_| Error::Format)?;
    status_document(&document, id, now)
}

fn status_document(document: &Config, id: &str, now: u64) -> Result<String, Error> {
    match document {
        Config::Server(doc) => {
            let inbound = doc.server.inbounds.iter().find(|i| i.id == id).ok_or(Error::Scope)?;
            if inbound.security_mode != SecurityMode::SmartReality { return Err(Error::Format); }
            let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
            let listen: SocketAddr = inbound.h2_listen.parse().map_err(|_| Error::Scope)?;
            let scope = crate::descriptor::Scope {
                inbound: id.to_owned(), endpoint: format!("{}:{}", inbound.server_name, listen.port()),
            };
            let state = reference_health::Store::new(Path::new(&binding.health_store)).map_err(|_| Error::Health)?
                .inspect().map_err(|_| Error::Health)?;
            let value = crate::reality_provision::inspect_registered(Path::new(&binding.bundle), binding, &state, &scope, now)?;
            let (health, reserve) = state.active_status(value.descriptor(), now).map_err(|_| Error::Health)?;
            let signed = value.descriptor();
            Ok(format!("Saved REALITY inbound; live state not inspected\ninbound={id}\nendpoint={}\nrevision={}\nidentity_sha256={}\nvalid_now={}\nactive_reference={}\nactive_status={health:?}\nreserve_candidate={}\nlast_checked_at={}\nnext_check_at={}\nh3={}\nbackend_available=true",
                scope.endpoint, signed.revision, hex(bootstrap::fingerprint(value.signer())),
                value.check_time(now).is_ok(), signed.references[usize::from(signed.active_reference)].server_name,
                reserve.map_or("none".into(), |i| i.to_string()), state.last_checked_at(),
                state.next_active_check_at(signed, now).map_err(|_| Error::Health)?, signed.h3))
        }
        Config::Client(doc) => {
            let profile = doc.client.profiles.iter().find(|p| p.id == id).ok_or(Error::Scope)?;
            let enrollment = pinned_client(profile)?;
            let value = enrollment.store()?.inspect(now).map_err(|_| Error::Descriptor)?;
            let modes = value.effective_modes();
            let valid = value.check_time(now).is_ok();
            Ok(format!("Saved REALITY profile; live state not inspected\nprofile={id}\nactive_profile={}\nrevision={}\nidentity_sha256={}\nvalid_now={valid}\nrequired_action={}\nh2={}\nh3={}\nstream_one={}\nstream_up={}\nbackend_available=true",
                doc.client.active_profile == id, value.descriptor().revision, hex(bootstrap::fingerprint(value.signer())),
                if valid { "ready-for-startup-preflight" } else { "authenticated-offline-recovery" },
                modes.h2, modes.h3, modes.stream_one, modes.stream_up))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{descriptor::Scope, identity_tls::Identity, reality_admission::Secret,
        reference_health::{Evidence, Plan, State, Store, Target}};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!("theia-reality-config-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

    fn health() -> State {
        State::new(Plan { schema_version: 1, inbound: "reality-edge".into(),
            endpoint: "edge.example.org:9443".into(), own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: vec![Target { server_name: "ref.example.org".into(), address: "93.184.216.2:443".parse().unwrap() }] },
            vec![Evidence { h2_status: Some(200), h3_status: None }], 1000).unwrap()
    }

    #[test]
    fn server_registration_requires_exact_grants_material_and_nonoverlapping_bind() {
        let dir = Scratch::new();
        let state = health();
        let health_path = dir.0.join("health");
        let bundle = dir.0.join("bundle");
        Store::new(&health_path).unwrap().enroll(&state).unwrap();
        let digest = state.snapshot_sha256().unwrap();
        let record = crate::reality_provision::create(&state, digest, &bundle, 1000).unwrap();
        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        let path = dir.0.join("server.toml");
        std::fs::write(&path, &source).unwrap();
        let mut r = ServerRequest { health: health_path, bundle, health_sha256: digest,
            identity_sha256: record.identity_sha256, listen: "127.0.0.1:9443".parse().unwrap(), grants: vec!["device-a".into()] };
        let req = Request::Server(r.clone());
        let preview = prepare(&path, &req, 1000).unwrap();
        assert!(preview.report().contains("ref"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
        assert_eq!(apply(&path, &req, [0; 32], 1000), Err(Error::Approval));
        r.grants = vec!["missing".into()];
        assert!(matches!(prepare(&path, &Request::Server(r.clone()), 1000), Err(Error::Grant)));
        r.grants = vec!["device-a".into(), "device-a".into()];
        assert!(prepare(&path, &Request::Server(r.clone()), 1000).is_err());
        r.grants.pop();
        r.listen.set_port(443);
        assert!(matches!(prepare(&path, &Request::Server(r), 1000), Err(Error::Scope)));
        std::fs::write(&path, format!("{source}\n# changed")).unwrap();
        assert_eq!(apply(&path, &req, preview.approval_sha256(), 1000), Err(Error::Approval));
        std::fs::write(&path, source).unwrap();
        apply(&path, &req, preview.approval_sha256(), 1000).unwrap();
        let Config::Server(saved) = config::read_file(&path).unwrap() else { panic!() };
        let inbound = saved.server.inbounds.last().unwrap();
        assert_eq!(inbound.security_mode, SecurityMode::SmartReality);
        assert!(inbound.tls_cert.is_empty() && inbound.tls_key.is_empty());
        assert_eq!(inbound.allowed_user_ids, vec!["device-a"]);
        assert!(prepare(&path, &req, 1000).is_err());
        let status = registered_status(&path, "reality-edge", 1000).unwrap();
        let saved_digest: [u8; 32] = Sha256::digest(std::fs::read(&path).unwrap()).into();
        assert_eq!(status_expected(&path, saved_digest, "reality-edge", 1000).unwrap(), status);
        assert_eq!(status_expected(&path, [0;32], "reality-edge", 1000), Err(Error::Approval));
        assert!(status.contains("backend_available=true"));
        assert!(status.contains("active_reference=ref.example.org"));
        // Compatible renewal advances publication without rewriting the
        // independently pinned initial receipt or the config record.
        let binding = inbound.reality.as_ref().unwrap();
        let publication = crate::identity_publication::Publication::new(&Path::new(&binding.bundle).join("publication.toml")).unwrap();
        let snapshot = publication.inspect(1001).unwrap();
        publication.refresh(&state, snapshot.snapshot_sha256, 1001).unwrap();
        assert!(registered_status(&path, "reality-edge", 1001).unwrap().contains("revision=2"));
        let mut mixed = saved;
        mixed.server.inbounds.last_mut().unwrap().tls_cert = "file:/tmp/foreign.pem".into();
        assert!(Config::Server(mixed).validate().is_err());
    }

    #[test]
    fn independent_reenrollment_replaces_only_selected_binding_and_requires_fresh_confirmation() {
        let dir = Scratch::new();
        let state = health();
        let scope = Scope { inbound: state.plan().inbound.clone(), endpoint: state.plan().endpoint.clone() };
        let old = Identity::generate(scope.clone()).unwrap();
        let next = Identity::generate(scope).unwrap();
        let enroll = |identity: &Identity, state: &State, name: &str, now: u64| {
            let signed = bootstrap::initial_descriptor(state, identity, now).unwrap();
            let invitation = bootstrap::Invitation::public(identity, &signed, now).unwrap();
            let uri = invitation.encode().unwrap();
            let admission = dir.0.join(format!("{name}-admission"));
            Secret::generate().unwrap().save_new(identity.scope(), &admission).unwrap();
            let enrollment = dir.0.join(format!("{name}-enrollment"));
            let trust = dir.0.join(format!("{name}-trust"));
            let pin = invitation.fingerprint();
            bootstrap::import(&uri, bootstrap::ImportApproval { document_sha256: bootstrap::digest(&uri), identity_sha256: pin },
                &enrollment, &trust, bootstrap::EnrollmentMaterial { admission_path: &admission,
                    expected_admission: None, external_token: Some("env:THEIA_TEST") }, bootstrap::auto_policy(), now).unwrap();
            (enrollment, trust, pin, signed)
        };
        let (old_path, old_trust, old_pin, _) = enroll(&old, &state, "old", 1000);
        let cfg = dir.0.join("client.toml");
        std::fs::write(&cfg, include_str!("../../../examples/client.toml")).unwrap();
        let initial = Request::Client(ClientRequest { enrollment: old_path.clone(), identity_sha256: old_pin, id: "recovery".into() });
        let preview = prepare(&cfg, &initial, 1000).unwrap();
        apply(&cfg, &initial, preview.approval_sha256(), 1000).unwrap();
        let Config::Client(before) = config::read_file(&cfg).unwrap() else { panic!() };
        let expired = validate_client(before.client.profiles.last().unwrap(), 1000).unwrap().descriptor().not_after;
        let fresh = State::new(state.plan().clone(), vec![Evidence { h2_status: Some(200), h3_status: None }], expired).unwrap();
        let (new_path, new_trust, new_pin, signed) = enroll(&next, &fresh, "new", expired);
        let req = ClientRequest { enrollment: new_path.clone(), identity_sha256: new_pin, id: "recovery".into() };
        let old_bytes = std::fs::read(&old_trust).unwrap();
        let before_bytes = std::fs::read(&cfg).unwrap();
        assert!(prepare(&cfg, &Request::Reenroll(ClientRequest { identity_sha256: old_pin, ..req.clone() }), expired).is_err());
        assert!(prepare(&cfg, &Request::Reenroll(ClientRequest { enrollment: old_path.clone(), identity_sha256: old_pin, id: req.id.clone() }), expired).is_err());
        let request = Request::Reenroll(req);
        let preview = prepare(&cfg, &request, expired).unwrap();
        assert!(preview.report().contains("old_valid_now=false"));
        assert!(!preview.report().contains("THEIA_TEST"));
        assert_eq!(std::fs::read(&cfg).unwrap(), before_bytes);
        assert_eq!(apply(&cfg, &request, [0;32], expired), Err(Error::Approval));
        bootstrap::Profile::read(&new_path).unwrap().store().unwrap().update(&signed, expired + 1).unwrap();
        assert_eq!(apply(&cfg, &request, preview.approval_sha256(), expired + 1), Err(Error::Approval));
        let preview = prepare(&cfg, &request, expired + 1).unwrap();
        apply(&cfg, &request, preview.approval_sha256(), expired + 1).unwrap();
        let Config::Client(after) = config::read_file(&cfg).unwrap() else { panic!() };
        assert_eq!(after.client.active_profile, before.client.active_profile);
        assert_eq!(after.client.proxy, before.client.proxy);
        assert_eq!(after.client.profiles.len(), before.client.profiles.len());
        assert_eq!(validate_client(after.client.profiles.last().unwrap(), expired + 1).unwrap().signer(), next.public_key());
        assert_eq!(std::fs::read(&old_trust).unwrap(), old_bytes);
        assert!(old_path.exists() && new_trust.exists());
        assert!(prepare(&cfg, &request, expired + 1).is_err());
    }

    #[test]
    fn client_registration_pins_enrollment_and_preserves_active_proxy() {
        let dir = Scratch::new();
        let state = health();
        let identity = Identity::generate(Scope { inbound: state.plan().inbound.clone(), endpoint: state.plan().endpoint.clone() }).unwrap();
        let document = bootstrap::initial_descriptor(&state, &identity, 1000).unwrap();
        let invite = bootstrap::Invitation::public(&identity, &document, 1000).unwrap();
        let uri = invite.encode().unwrap();
        let admission = dir.0.join("admission");
        Secret::generate().unwrap().save_new(identity.scope(), &admission).unwrap();
        let enrollment = dir.0.join("enrollment");
        let trust = dir.0.join("trust");
        let pin = invite.fingerprint();
        bootstrap::import(&uri, bootstrap::ImportApproval { document_sha256: bootstrap::digest(&uri), identity_sha256: pin },
            &enrollment, &trust, bootstrap::EnrollmentMaterial { admission_path: &admission,
                expected_admission: None, external_token: Some("env:THEIA_TEST") }, bootstrap::auto_policy(), 1000).unwrap();
        let path = dir.0.join("client.toml");
        let source = include_str!("../../../examples/client.toml");
        std::fs::write(&path, source).unwrap();
        let Config::Client(original) = config::parse(source).unwrap() else { panic!() };
        let req = Request::Client(ClientRequest { enrollment: enrollment.clone(), identity_sha256: pin, id: "reality-client".into() });
        let preview = prepare(&path, &req, 1000).unwrap();
        assert!(!preview.report().contains("THEIA_TEST"));
        apply(&path, &req, preview.approval_sha256(), 1000).unwrap();
        let Config::Client(saved) = config::read_file(&path).unwrap() else { panic!() };
        assert_eq!(saved.client.active_profile, original.client.active_profile);
        assert_eq!(saved.client.proxy, original.client.proxy);
        let mut new = saved.client.profiles.last().unwrap().clone();
        assert!(validate_client(&new, 1000).is_ok());
        assert!(registered_status(&path, "reality-client", 1000).unwrap().contains("active_profile=false"));
        let expired = validate_client(&new, 1000).unwrap().descriptor().not_after;
        assert!(validate_client(&new, expired).is_err());
        let offline = registered_status(&path, "reality-client", expired).unwrap();
        assert!(offline.contains("valid_now=false"));
        assert!(offline.contains("required_action=authenticated-offline-recovery"));
        new.auth_token = "env:OTHER".into();
        assert!(matches!(validate_client(&new, 1000), Err(Error::Approval)));
        let mut replacement = std::fs::read_to_string(&enrollment).unwrap();
        replacement.push_str("\n# changed");
        std::fs::write(&enrollment, replacement).unwrap();
        assert!(matches!(validate_client(saved.client.profiles.last().unwrap(), 1000), Err(Error::Approval)));
    }
}
