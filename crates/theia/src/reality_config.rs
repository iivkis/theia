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
}

pub struct Prepared {
    original: Vec<u8>,
    candidate: Config,
    approval_sha256: [u8; 32],
    report: String,
}

impl Prepared {
    pub fn approval_sha256(&self) -> [u8; 32] { self.approval_sha256 }
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
                }),
                allowed_user_ids: r.grants.clone(),
                h2_listen: r.listen.to_string(),
                quic_listen: r.listen.to_string(),
                server_name: host.to_owned(),
                tls_cert: String::new(), tls_key: String::new(),
            });
            let report = format!("Register REALITY inbound (saved configuration only)\ninbound={}\nendpoint={}\nlisten={}\ngrants={}\nidentity_sha256={}\n{}\nExisting runtime remains unchanged. Current backend refuses REALITY activation; do not restart into this record until backend support exists.",
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
            let report = format!("Register REALITY profile (saved configuration only)\nprofile={}\nendpoint={}\nidentity_sha256={}\nrevision={}\nh2={}\nh3={}\nstream_one={}\nstream_up={}\nActive profile and proxy remain unchanged. Current backend refuses REALITY activation.",
                r.id, profile.endpoint(), hex(bootstrap::fingerprint(value.signer())), value.descriptor().revision,
                modes.h2, modes.h3, modes.stream_one, modes.stream_up);
            (report, value.payload_sha256())
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
pub fn validate_client(profile: &Profile, now: u64) -> Result<crate::descriptor::Verified, Error> {
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
    enrollment.load(now)
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
        let mut mixed = saved;
        mixed.server.inbounds.last_mut().unwrap().tls_cert = "file:/tmp/foreign.pem".into();
        assert!(Config::Server(mixed).validate().is_err());
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
        new.auth_token = "env:OTHER".into();
        assert!(matches!(validate_client(&new, 1000), Err(Error::Approval)));
        let mut replacement = std::fs::read_to_string(&enrollment).unwrap();
        replacement.push_str("\n# changed");
        std::fs::write(&enrollment, replacement).unwrap();
        assert!(matches!(validate_client(saved.client.profiles.last().unwrap(), 1000), Err(Error::Approval)));
    }
}
