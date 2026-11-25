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
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
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
pub struct ServerReplacement {
    pub id: String,
    pub health: PathBuf,
    pub bundle: PathBuf,
    pub health_sha256: [u8; 32],
    pub identity_sha256: [u8; 32],
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
    ReplaceServer(ServerReplacement),
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
    pub fn approval_sha256(&self) -> [u8; 32] {
        self.approval_sha256
    }
    pub(crate) fn source_sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.original).into()
    }
    pub fn report(&self) -> &str {
        &self.report
    }
    pub fn candidate(&self) -> &Config {
        &self.candidate
    }
}

fn path_string(path: &Path) -> Result<String, Error> {
    if !crate::bounded_input::explicit_file_path(path) {
        return Err(Error::Storage);
    }
    path.to_str()
        .filter(|p| !p.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or(Error::Storage)
}

fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
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

/// Same verified binding builder for registration and first-run creation.
fn approved_server_inbound(
    r: &ServerRequest,
    now: u64,
) -> Result<
    (
        Inbound,
        reference_health::State,
        crate::reality_provision::Record,
    ),
    Error,
> {
    if r.listen.port() == 0 || r.grants.is_empty() || r.grants.len() > 256 {
        return Err(Error::Grant);
    }
    let state = reference_health::Store::new(&r.health)
        .map_err(|_| Error::Health)?
        .inspect()
        .map_err(|_| Error::Health)?;
    let record = crate::reality_provision::inspect_initial(
        &state,
        r.health_sha256,
        r.identity_sha256,
        &r.bundle,
        now,
    )?;
    let (host, port) = record.scope.endpoint.rsplit_once(':').ok_or(Error::Scope)?;
    if port.parse::<u16>().ok() != Some(r.listen.port()) {
        return Err(Error::Scope);
    }
    let inbound = Inbound {
        id: record.scope.inbound.clone(),
        path_prefix: None,
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
        tls_cert: String::new(),
        tls_key: String::new(),
    };
    Ok((inbound, state, record))
}

/// First configuration: no placeholder Own-TLS or usable default credential.
pub(crate) fn first_server_candidate(r: &ServerRequest, now: u64) -> Result<Config, Error> {
    use zeroize::Zeroizing;
    if r.grants.len() != 1 || !config::valid_id(&r.grants[0]) {
        return Err(Error::Grant);
    }
    let (inbound, _, _) = approved_server_inbound(r, now)?;
    let mut random = Zeroizing::new([0u8; 32]);
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut random[..])
        .map_err(|_| Error::Storage)?;
    let candidate = Config::Server(config::ServerDocument {
        schema_version: 1,
        management: config::Management {
            ipc: "auto".into(),
            log_level: "info".into(),
        },
        ui: config::Ui {
            language: "ru".into(),
        },
        server: config::ServerSettings {
            enabled: true,
            inbounds: vec![inbound],
            users: vec![config::User {
                id: r.grants[0].clone(),
                token_sha256: format!("{:x}", Sha256::digest(&random[..])),
                disabled: true,
            }],
            policy: config::ServerPolicy {
                allow_private_ips: false,
                max_connections_per_user: 64,
                max_connections_total: 1024,
                connect_timeout_ms: 10000,
            },
        },
    });
    candidate.validate().map_err(|_| Error::Format)?;
    Ok(candidate)
}

fn approved_client_profile(
    r: &ClientRequest,
    now: u64,
) -> Result<(Profile, crate::descriptor::Verified), Error> {
    if !config::valid_id(&r.id) {
        return Err(Error::Scope);
    }
    let (profile, enrollment_sha256) = bootstrap::Profile::read_snapshot(&r.enrollment)?;
    if !bool::from(profile.enrollment_identity()?.ct_eq(&r.identity_sha256)) {
        return Err(Error::Approval);
    }
    let value = profile.load(now)?;
    let policy = profile.policy();
    let host = profile.endpoint().rsplit_once(':').ok_or(Error::Scope)?.0;
    let entry = Profile {
        id: r.id.clone(),
        path_prefix: None,
        server: profile.endpoint().to_owned(),
        server_name: host.to_owned(),
        auth_token: profile.credential_reference().to_owned(),
        security_mode: SecurityMode::SmartReality,
        reality_profile: Some(RealityClientBinding {
            enrollment: path_string(&r.enrollment)?,
            enrollment_sha256,
            identity_sha256: r.identity_sha256,
        }),
        xhttp_mode: Some(policy.xhttp_mode),
        tls_ca: None,
        transport: policy.transport,
        quic_connect_timeout_ms: 1600,
        quic_negative_cache_ttl_s: 900,
    };
    Ok((entry, value))
}

pub(crate) fn first_client_candidate(r: &ClientRequest, now: u64) -> Result<Config, Error> {
    let (profile, _) = approved_client_profile(r, now)?;
    let candidate = Config::Client(config::ClientDocument {
        schema_version: 1,
        management: config::Management {
            ipc: "auto".into(),
            log_level: "info".into(),
        },
        ui: config::Ui {
            language: "ru".into(),
        },
        client: config::ClientSettings {
            active_profile: r.id.clone(),
            profiles: vec![profile],
            proxy: config::LocalProxy {
                http_listen: "127.0.0.1:7890".into(),
                socks5_listen: "127.0.0.1:7891".into(),
                system_proxy: config::SystemProxy::Off,
            },
        },
    });
    candidate.validate().map_err(|_| Error::Format)?;
    Ok(candidate)
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
            if r.grants.iter().any(|id| {
                !document
                    .server
                    .users
                    .iter()
                    .any(|u| &u.id == id && !u.disabled)
            }) {
                return Err(Error::Grant);
            }
            let (inbound, state, record) = approved_server_inbound(r, now)?;
            if document.server.inbounds.iter().any(|i| i.id == inbound.id) {
                return Err(Error::Scope);
            }
            document.server.inbounds.push(inbound);
            let report = format!("Register REALITY inbound (saved configuration only)\ninbound={}\nendpoint={}\nlisten={}\ngrants={}\nidentity_sha256={}\n{}\nExisting runtime remains unchanged. Startup uses the registered generation; live changes require a separate supported activation operation.",
                record.scope.inbound, record.scope.endpoint, r.listen, r.grants.join(","),
                hex(record.identity_sha256), state.report(now).map_err(|_| Error::Health)?);
            (report, record.publication_sha256)
        }
        (Config::Server(document), Request::ReplaceServer(r)) => {
            let entry = document
                .server
                .inbounds
                .iter_mut()
                .find(|i| i.id == r.id)
                .ok_or(Error::Scope)?;
            if entry.security_mode != SecurityMode::SmartReality {
                return Err(Error::Format);
            }
            let old = entry.reality.as_ref().ok_or(Error::Format)?;
            let state = reference_health::Store::new(&r.health)
                .and_then(|s| s.inspect())
                .map_err(|_| Error::Health)?;
            let record = crate::reality_provision::inspect_initial(
                &state,
                r.health_sha256,
                r.identity_sha256,
                &r.bundle,
                now,
            )?;
            let addr: SocketAddr = entry.h2_listen.parse().map_err(|_| Error::Scope)?;
            if record.scope.inbound != entry.id
                || record.scope.endpoint != format!("{}:{}", entry.server_name, addr.port())
            {
                return Err(Error::Scope);
            }
            let binding = RealityBinding {
                health_store: path_string(&r.health)?,
                bundle: path_string(&r.bundle)?,
                initial_health_sha256: r.health_sha256,
                identity_sha256: r.identity_sha256,
                manifest_sha256: record.manifest_sha256()?,
            };
            if old.identity_sha256 == binding.identity_sha256
                || old.bundle == binding.bundle
                || old.manifest_sha256 == binding.manifest_sha256
            {
                return Err(Error::Approval);
            }
            let report=format!("Independent REALITY server replacement (saved config only)\ninbound={}\nendpoint={}\nold_identity_sha256={}\nnew_identity_sha256={}\nExisting bind, grants and policy retained. Confirm new identity independently; clients require new enrollment. Old bundle is retained but must not be reactivated as rollback.\n{}",
                entry.id,record.scope.endpoint,hex(old.identity_sha256),hex(binding.identity_sha256),
                state.report(now).map_err(|_|Error::Health)?);
            entry.reality = Some(binding);
            (report, record.publication_sha256)
        }
        (Config::Client(document), Request::Client(r)) => {
            if !config::valid_id(&r.id) || document.client.profiles.iter().any(|p| p.id == r.id) {
                return Err(Error::Scope);
            }
            let (profile, value) = approved_client_profile(r, now)?;
            let endpoint = profile.server.clone();
            document.client.profiles.push(profile);
            let modes = value.effective_modes();
            let report = format!("Register REALITY profile (saved configuration only)\nprofile={}\nendpoint={}\nidentity_sha256={}\nrevision={}\nh2={}\nh3={}\nstream_one={}\nstream_up={}\nActive profile and proxy remain unchanged. Selected profile can be started after preflight; the current process is unchanged.",
                r.id, endpoint, hex(bootstrap::fingerprint(value.signer())), value.descriptor().revision,
                modes.h2, modes.h3, modes.stream_one, modes.stream_up);
            (report, value.payload_sha256())
        }
        (Config::Client(document), Request::Reenroll(r)) => {
            let entry = document
                .client
                .profiles
                .iter_mut()
                .find(|p| p.id == r.id)
                .ok_or(Error::Scope)?;
            let old = pinned_client(entry)?;
            let binding = entry.reality_profile.as_ref().ok_or(Error::Format)?;
            let new_path = path_string(&r.enrollment)?;
            if new_path == binding.enrollment {
                return Err(Error::Approval);
            }
            let (replacement, enrollment_sha256) =
                bootstrap::Profile::read_snapshot(&r.enrollment)?;
            if !bool::from(replacement.enrollment_identity()?.ct_eq(&r.identity_sha256)) {
                return Err(Error::Approval);
            }
            let (new_snapshot, value) = replacement
                .store()?
                .inspect_bound(now)
                .map_err(|_| Error::Descriptor)?;
            value.check_time(now).map_err(|_| Error::Descriptor)?;
            // This is a freshly and independently enrolled root, not a
            // successor inferred from untrusted data or a historical key.
            if bootstrap::fingerprint(value.signer()) != r.identity_sha256 {
                return Err(Error::Identity);
            }
            let (old_snapshot, previous) = old
                .store()?
                .inspect_replacement(value.signer(), now)
                .map_err(|_| Error::Descriptor)?;
            if previous.descriptor().scope != value.descriptor().scope
                || old.endpoint() != replacement.endpoint()
                || old.policy().transport != replacement.policy().transport
                || old.policy().xhttp_mode != replacement.policy().xhttp_mode
            {
                return Err(Error::Scope);
            }
            let credential_changed = entry.auth_token != replacement.credential_reference();
            entry.auth_token = replacement.credential_reference().to_owned();
            entry.reality_profile = Some(RealityClientBinding {
                enrollment: new_path,
                enrollment_sha256,
                identity_sha256: r.identity_sha256,
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
    Ok(Prepared {
        original,
        candidate,
        approval_sha256,
        report,
    })
}

/// Repeat all material checks at Apply. The config CAS operates on the
/// original bytes, not a serialization of a stale cached document.
pub fn apply(path: &Path, request: &Request, expected: [u8; 32], now: u64) -> Result<(), Error> {
    let prepared = prepare(path, request, now)?;
    if !bool::from(prepared.approval_sha256.ct_eq(&expected)) {
        return Err(Error::Approval);
    }
    config::guarded_write(path, &prepared.candidate, &prepared.original)
        .map(|_| ())
        .map_err(|error| match error {
            WriteFailure::BeforeReplace(_) => Error::Storage,
            WriteFailure::AfterReplace(_) => Error::Indeterminate,
        })
}

/// Validate the immutable enrollment pinned by the shared config before
/// interpreting mutable trust history. A copied/replaced profile, changed
/// bearer ref or independently edited mode must not silently take effect.
pub(crate) fn pinned_client(profile: &Profile) -> Result<bootstrap::Profile, Error> {
    if profile.security_mode != SecurityMode::SmartReality || profile.tls_ca.is_some() {
        return Err(Error::Format);
    }
    let binding = profile.reality_profile.as_ref().ok_or(Error::Format)?;
    let (enrollment, digest) = bootstrap::Profile::read_snapshot(Path::new(&binding.enrollment))?;
    if !bool::from(digest.ct_eq(&binding.enrollment_sha256))
        || !bool::from(
            enrollment
                .enrollment_identity()?
                .ct_eq(&binding.identity_sha256),
        )
        || enrollment.endpoint() != profile.server
        || enrollment.credential_reference() != profile.auth_token
        || enrollment.policy().transport != profile.transport
        || enrollment.policy().xhttp_mode != profile.effective_xhttp_mode()
    {
        return Err(Error::Approval);
    }
    Ok(enrollment)
}

/// A credential refresh stages new private files; the config CAS is the
/// publication point. Neither the original enrollment nor trust is rewritten.
struct CredentialPrepared {
    original: Vec<u8>,
    candidate: Config,
    enrollment: bootstrap::Profile,
    bearer: zeroize::Zeroizing<[u8; 32]>,
    trust_snapshot: [u8; 32],
    approval: [u8; 32],
    revision: u64,
}

fn prepare_credential(
    path: &Path,
    id: &str,
    source: &Path,
    now: u64,
) -> Result<CredentialPrepared, Error> {
    path_string(path)?;
    path_string(source)?;
    let original = config::editor_bytes(path).map_err(|_| Error::Storage)?;
    let candidate = config::parse(std::str::from_utf8(&original).map_err(|_| Error::Format)?)
        .map_err(|_| Error::Format)?;
    let Config::Client(doc) = &candidate else {
        return Err(Error::Format);
    };
    let profile = doc
        .client
        .profiles
        .iter()
        .find(|p| p.id == id)
        .ok_or(Error::Scope)?;
    let enrollment = pinned_client(profile)?;
    let uri = bootstrap::read_text(source, bootstrap::MAX_URI, true)?;
    let (trust_snapshot, bearer, revision) = enrollment.credential_material(&uri, now)?;
    let mut h = Sha256::new();
    h.update(b"Theia/REALITY-credential-refresh/v1\0");
    for part in [
        original.as_slice(),
        id.as_bytes(),
        uri.as_bytes(),
        trust_snapshot.as_slice(),
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    Ok(CredentialPrepared {
        original,
        candidate,
        enrollment,
        bearer,
        trust_snapshot,
        approval: h.finalize().into(),
        revision,
    })
}

pub(crate) fn preview_credential_refresh(
    path: &Path,
    id: &str,
    source: &Path,
    now: u64,
) -> Result<([u8; 32], u64), Error> {
    let p = prepare_credential(path, id, source, now)?;
    Ok((p.approval, p.revision))
}

pub(crate) fn preview_credential_refresh_for_editor(
    path: &Path,
    digest: [u8; 32],
    id: &str,
    source: &Path,
    now: u64,
) -> Result<([u8; 32], u64), Error> {
    let p = prepare_credential(path, id, source, now)?;
    if <[u8; 32]>::from(Sha256::digest(&p.original)) != digest {
        return Err(Error::Approval);
    }
    Ok((p.approval, p.revision))
}

pub(crate) fn save_credential_refresh(
    path: &Path,
    id: &str,
    source: &Path,
    expected: [u8; 32],
    now: u64,
) -> Result<(), Error> {
    let mut p = prepare_credential(path, id, source, now)?;
    if !bool::from(p.approval.ct_eq(&expected)) {
        return Err(Error::Approval);
    }
    let mut bearer =
        crate::client_import::PrivateBearer::create(path, &p.bearer).map_err(|_| Error::Storage)?;
    let reference = bearer.reference().map_err(|_| Error::Storage)?;
    let raw = p.enrollment.credential_enrollment(&reference)?;
    let mut enrollment = crate::client_import::PrivateBearer::create_payload(
        path,
        "enrollment",
        "profile.toml",
        raw.as_bytes(),
    )
    .map_err(|_| Error::Storage)?;
    let enrollment_ref = enrollment.reference().map_err(|_| Error::Storage)?;
    let enrollment_path = enrollment_ref.strip_prefix("file:").ok_or(Error::Storage)?;
    let Config::Client(doc) = &mut p.candidate else {
        return Err(Error::Format);
    };
    let profile = doc
        .client
        .profiles
        .iter_mut()
        .find(|x| x.id == id)
        .ok_or(Error::Scope)?;
    let binding = profile.reality_profile.as_mut().ok_or(Error::Format)?;
    binding.enrollment = enrollment_path.to_owned();
    binding.enrollment_sha256 = bootstrap::digest(&raw);
    profile.auth_token = reference;
    // Check the trust snapshot again before publishing. Later legitimate
    // trust updates use the same store and retain its monotonic floor.
    let (snapshot, _) = p
        .enrollment
        .store()?
        .inspect_bound(now)
        .map_err(|_| Error::Descriptor)?;
    if snapshot != p.trust_snapshot {
        return Err(Error::Approval);
    }
    let updated = pinned_client(profile)?;
    if !p.enrollment.same_trust_as(&updated) {
        return Err(Error::Approval);
    }
    match config::guarded_write(path, &p.candidate, &p.original) {
        Ok(_) => {
            bearer.commit();
            enrollment.commit();
            Ok(())
        }
        Err(WriteFailure::AfterReplace(_)) => {
            bearer.commit();
            enrollment.commit();
            Err(Error::Indeterminate)
        }
        Err(WriteFailure::BeforeReplace(_)) => Err(Error::Storage),
    }
}

/// Runtime Apply may accept a replacement enrollment only if every
/// trust-bearing field stays equal and the selected credential changes.
pub(crate) fn credential_only_change(old: &Profile, new: &Profile) -> bool {
    if old.auth_token == new.auth_token {
        return false;
    }
    match (pinned_client(old), pinned_client(new)) {
        (Ok(a), Ok(b)) => a.same_trust_as(&b),
        _ => false,
    }
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
pub(crate) fn status_expected(
    path: &Path,
    expected: [u8; 32],
    id: &str,
    now: u64,
) -> Result<String, Error> {
    path_string(path)?;
    let raw = config::editor_bytes(path).map_err(|_| Error::Storage)?;
    let actual: [u8; 32] = Sha256::digest(&raw).into();
    if actual != expected {
        return Err(Error::Approval);
    }
    let document = config::parse(std::str::from_utf8(&raw).map_err(|_| Error::Format)?)
        .map_err(|_| Error::Format)?;
    status_document(&document, id, now)
}

fn exact_client_record(path: &Path, expected: [u8; 32], id: &str) -> Result<Profile, Error> {
    path_string(path)?;
    let raw = config::editor_bytes(path).map_err(|_| Error::Storage)?;
    let digest: [u8; 32] = Sha256::digest(&raw).into();
    if digest != expected {
        return Err(Error::Approval);
    }
    let Config::Client(doc) = config::parse(std::str::from_utf8(&raw).map_err(|_| Error::Format)?)
        .map_err(|_| Error::Format)?
    else {
        return Err(Error::Format);
    };
    doc.client
        .profiles
        .into_iter()
        .find(|p| p.id == id && p.security_mode == SecurityMode::SmartReality)
        .ok_or(Error::Scope)
}

enum TrustApproval {
    Recover(bootstrap::RecoveryApproval),
    Promote(bootstrap::PromotionApproval),
}
pub(crate) struct TrustReview {
    source: PathBuf,
    approval: TrustApproval,
    report: String,
}
impl TrustReview {
    pub(crate) fn report(&self) -> &str {
        &self.report
    }
    pub(crate) fn prepare(
        path: &Path,
        digest: [u8; 32],
        id: &str,
        source: &Path,
        promote: bool,
        now: u64,
    ) -> Result<Self, Error> {
        path_string(source)?;
        let profile = exact_client_record(path, digest, id)?;
        let enrollment = pinned_client(&profile)?;
        let raw = bootstrap::read_text(source, crate::descriptor::MAX_DOCUMENT, false)?;
        let (approval, report) = if promote {
            let p = enrollment.preview_promotion(&raw, now)?;
            (TrustApproval::Promote(bootstrap::PromotionApproval{
                expected_revision:p.expected_revision,snapshot_sha256:p.snapshot_sha256,
                document_sha256:p.document_sha256,next_identity_sha256:p.next_identity_sha256,
            }),format!("Плановый переход identity\nrevision {} -> {}\nТекущий fingerprint={}\nСледующий fingerprint={}\nOverlap ends={}\nСверьте новый fingerprint по доверенному каналу. Это не recovery после компрометации; удалённое владение ключом будет проверено до bearer при подключении.",
                p.expected_revision,p.next_revision,hex(p.current_identity_sha256),hex(p.next_identity_sha256),p.overlap_ends_at))
        } else {
            let p = enrollment.preview_recovery(&raw, now)?;
            (TrustApproval::Recover(bootstrap::RecoveryApproval{
                expected_revision:p.expected_revision,snapshot_sha256:p.snapshot_sha256,
                document_sha256:p.document_sha256,identity_sha256:p.identity_sha256,
            }),format!("Восстановление дескриптора под текущим закреплённым ключом\nrevision {} -> {}\nFingerprint={}\nИстёк={}; reference changed={}\nСмена identity запрещена.",
                p.expected_revision,p.next_revision,hex(p.identity_sha256),p.current_expired,p.reference_changed))
        };
        Ok(Self {
            source: source.to_owned(),
            approval,
            report,
        })
    }
    pub(crate) fn apply(
        self,
        path: &Path,
        digest: [u8; 32],
        id: &str,
        now: u64,
    ) -> Result<String, Error> {
        let profile = exact_client_record(path, digest, id)?;
        let enrollment = pinned_client(&profile)?;
        let raw = bootstrap::read_text(&self.source, crate::descriptor::MAX_DOCUMENT, false)?;
        match self.approval {
            TrustApproval::Recover(approval) => enrollment.recover(&raw, approval, now)?,
            TrustApproval::Promote(approval) => enrollment.promote(&raw, approval, now)?,
        }
        Ok("Trust store обновлён с CAS. TOML, bearer и OS proxy не изменены. Для проверки удалённого соединения запустите runtime отдельно.".into())
    }
}

fn exact_server_record(path: &Path, expected: [u8; 32], id: &str) -> Result<Inbound, Error> {
    path_string(path)?;
    let bytes = config::editor_bytes(path).map_err(|_| Error::Storage)?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != expected {
        return Err(Error::Approval);
    }
    let Config::Server(doc) =
        config::parse(std::str::from_utf8(&bytes).map_err(|_| Error::Format)?)
            .map_err(|_| Error::Format)?
    else {
        return Err(Error::Format);
    };
    let inbound = doc
        .server
        .inbounds
        .into_iter()
        .find(|i| i.id == id)
        .ok_or(Error::Scope)?;
    if inbound.security_mode != SecurityMode::SmartReality || inbound.reality.is_none() {
        return Err(Error::Format);
    }
    Ok(inbound)
}

pub(crate) fn runtime_status_command(
    path: &Path,
    expected: [u8; 32],
    id: &str,
) -> Result<crate::management::StatusCommand, Error> {
    let inbound = exact_server_record(path, expected, id)?;
    crate::management::StatusCommand::reality_status(
        id,
        inbound.reality.ok_or(Error::Format)?.manifest_sha256,
    )
    .map_err(|_| Error::Format)
}

/// Issue from the registered, rooted publication, never from an arbitrary
/// supplied signing key or unregistered bundle. This is a local operation.
pub(crate) fn registered_invitation(
    document: &config::ServerDocument,
    id: &str,
    credential: Option<(&str, &[u8; 32])>,
    now: u64,
) -> Result<bootstrap::Invitation, Error> {
    let inbound = document
        .server
        .inbounds
        .iter()
        .find(|i| i.id == id)
        .ok_or(Error::Scope)?;
    if !document.server.enabled || inbound.security_mode != SecurityMode::SmartReality {
        return Err(Error::Grant);
    }
    let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
    let listen: SocketAddr = inbound.h2_listen.parse().map_err(|_| Error::Scope)?;
    let scope = crate::descriptor::Scope {
        inbound: id.into(),
        endpoint: format!("{}:{}", inbound.server_name, listen.port()),
    };
    let state = reference_health::Store::new(Path::new(&binding.health_store))
        .and_then(|s| s.inspect())
        .map_err(|_| Error::Health)?;
    let (publication, admission) = crate::reality_provision::capture_registered(
        Path::new(&binding.bundle),
        binding,
        &state,
        &scope,
        now,
    )?;
    // Prefer the active signer while it remains valid. The successor can
    // be used after expiration, but its fingerprint must be verified
    // independently by a new client just like any other enrollment.
    let active = publication.active();
    let material = if active.verified().check_time(now).is_ok() {
        active
    } else {
        publication.next().ok_or(Error::Descriptor)?
    };
    match credential {
        Some((user, bearer)) => bootstrap::Invitation::issued(
            material.identity(),
            material.signed(),
            document,
            user,
            bearer,
            &admission,
            now,
        ),
        None => bootstrap::Invitation::public(material.identity(), material.signed(), now),
    }
}

fn rotation_snapshot(
    path: &Path,
    expected: [u8; 32],
    id: &str,
    now: u64,
) -> Result<
    (
        PathBuf,
        crate::descriptor::Scope,
        crate::identity_publication::Status,
    ),
    Error,
> {
    let inbound = exact_server_record(path, expected, id)?;
    let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
    let addr: SocketAddr = inbound.h2_listen.parse().map_err(|_| Error::Scope)?;
    let scope = crate::descriptor::Scope {
        inbound: id.to_owned(),
        endpoint: format!("{}:{}", inbound.server_name, addr.port()),
    };
    let state = reference_health::Store::new(Path::new(&binding.health_store))
        .and_then(|s| s.inspect())
        .map_err(|_| Error::Health)?;
    let directory = PathBuf::from(&binding.bundle);
    let (value, stamp) = crate::reality_provision::inspect_registered_snapshot(
        &directory, binding, &state, &scope, now,
    )?;
    state
        .validate_active(value.descriptor(), now)
        .map_err(|_| Error::Health)?;
    let publication =
        crate::identity_publication::Publication::new(&directory.join("publication.toml"))?;
    let status = publication.inspect(now)?;
    if status.snapshot_sha256 != stamp.publication {
        return Err(Error::Approval);
    }
    Ok((directory, scope, status))
}

pub(crate) struct ExpiryReview {
    approval: crate::identity_publication::ExpiredRecovery,
    directory: PathBuf,
    report: String,
}
impl ExpiryReview {
    pub(crate) fn report(&self) -> &str {
        &self.report
    }
    fn snapshot(
        path: &Path,
        digest: [u8; 32],
        id: &str,
        now: u64,
    ) -> Result<
        (
            PathBuf,
            reference_health::State,
            crate::reality_checkpoint::Stamp,
        ),
        Error,
    > {
        let inbound = exact_server_record(path, digest, id)?;
        let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
        let addr: SocketAddr = inbound.h2_listen.parse().map_err(|_| Error::Scope)?;
        let scope = crate::descriptor::Scope {
            inbound: id.to_owned(),
            endpoint: format!("{}:{}", inbound.server_name, addr.port()),
        };
        let state = reference_health::Store::new(Path::new(&binding.health_store))
            .and_then(|s| s.inspect())
            .map_err(|_| Error::Health)?;
        let directory = PathBuf::from(&binding.bundle);
        let (_, stamp) = crate::reality_provision::inspect_registered_snapshot(
            &directory, binding, &state, &scope, now,
        )?;
        Ok((directory, state, stamp))
    }
    pub(crate) fn prepare(
        path: &Path,
        digest: [u8; 32],
        id: &str,
        now: u64,
    ) -> Result<Self, Error> {
        let (directory, state, stamp) = Self::snapshot(path, digest, id, now)?;
        let publication =
            crate::identity_publication::Publication::new(&directory.join("publication.toml"))?;
        let approval = publication.preview_expired(&state, now)?;
        if approval.publication_sha256 != stamp.publication
            || approval.health_sha256 != stamp.health
        {
            return Err(Error::Approval);
        }
        let report=format!("Восстановление истёкшей identity без смены ключа\nFingerprint={}\nrevision {} -> {}\nТребуется свежая проверка одобренного reference (до 60 с). Сверьте fingerprint. Старый signer не активируется. Клиенты с истёкшим descriptor требуют offline recovery; компрометация требует независимого enrollment.",
            hex(approval.identity_sha256),approval.previous_revision,approval.next_revision);
        Ok(Self {
            approval,
            directory,
            report,
        })
    }
    pub(crate) fn apply(
        self,
        path: &Path,
        digest: [u8; 32],
        id: &str,
        now: u64,
    ) -> Result<String, Error> {
        let (directory, state, stamp) = Self::snapshot(path, digest, id, now)?;
        if directory != self.directory
            || stamp.publication != self.approval.publication_sha256
            || stamp.health != self.approval.health_sha256
        {
            return Err(Error::Approval);
        }
        let publication =
            crate::identity_publication::Publication::new(&directory.join("publication.toml"))?;
        crate::reality_checkpoint::accept(&directory, stamp, now)?;
        publication.recover_expired(&state, self.approval, now)?;
        Ok("Новый дескриптор опубликован под тем же ключом. Runtime проверит новое поколение; истёкшие клиенты восстанавливаются отдельно.".into())
    }
}

pub(crate) struct RotationReview {
    directory: PathBuf,
    expected: [u8; 32],
    fingerprint: [u8; 32],
    identity: Option<crate::identity_tls::Identity>,
    report: String,
}
impl RotationReview {
    pub(crate) fn report(&self) -> &str {
        &self.report
    }
    pub(crate) fn prepare(
        path: &Path,
        digest: [u8; 32],
        id: &str,
        retire: bool,
        now: u64,
    ) -> Result<Self, Error> {
        let (directory, scope, status) = rotation_snapshot(path, digest, id, now)?;
        let (fingerprint, identity, report) = if retire {
            let ends = status.overlap_ends_at.ok_or(Error::Identity)?;
            let fingerprint = status.next_fingerprint.ok_or(Error::Identity)?;
            if now < ends {
                return Err(Error::Approval);
            }
            (fingerprint,None,format!("Отозвать старую identity после overlap.\nСтарый fingerprint={}\nНовый fingerprint={}\nОткрытые туннели не закрываются; пропустившие overlap клиенты требуют независимого enrollment.",
                hex(status.active_fingerprint),hex(fingerprint)))
        } else {
            if !status.valid_now || status.next_fingerprint.is_some() {
                return Err(Error::Approval);
            }
            let key =
                crate::identity_tls::Identity::generate(scope).map_err(|_| Error::Identity)?;
            let fingerprint = bootstrap::fingerprint(key.public_key());
            (fingerprint,Some(key),format!("Начать плановую ротацию identity (7 суток).\nТекущий fingerprint={}\nСледующий fingerprint={}\nОба ключа действуют в overlap; новый ключ пока только в памяти.",
                hex(status.active_fingerprint),hex(fingerprint)))
        };
        Ok(Self {
            directory,
            expected: status.snapshot_sha256,
            fingerprint,
            identity,
            report,
        })
    }
    pub(crate) fn apply(
        self,
        path: &Path,
        digest: [u8; 32],
        id: &str,
        now: u64,
    ) -> Result<String, Error> {
        let (directory, scope, status) = rotation_snapshot(path, digest, id, now)?;
        if directory != self.directory || status.snapshot_sha256 != self.expected {
            return Err(Error::Approval);
        }
        let publication =
            crate::identity_publication::Publication::new(&directory.join("publication.toml"))?;
        if let Some(identity) = self.identity {
            if identity.scope() != &scope || !status.valid_now || status.next_fingerprint.is_some()
            {
                return Err(Error::Approval);
            }
            let key_path = directory.join(format!("identity-{}.key", hex(self.fingerprint)));
            identity.save_new(&key_path).map_err(|e| match e {
                crate::identity_tls::Error::Indeterminate => Error::Indeterminate,
                _ => Error::Storage,
            })?;
            if let Err(error) =
                publication.begin_rotation(&key_path, self.expected, self.fingerprint, now)
            {
                // Definite failure: delete only the exact key created by
                // this operation. An uncertain publication keeps material.
                if error != Error::Indeterminate
                    && crate::identity_tls::Identity::load(&key_path, &scope)
                        .is_ok_and(|k| k.public_key() == identity.public_key())
                {
                    let _ = std::fs::remove_file(&key_path);
                }
                return Err(error);
            }
            Ok(
                "Ротация опубликована. Live worker перечитает bundle; проверьте runtime отдельно."
                    .into(),
            )
        } else {
            if status.next_fingerprint != Some(self.fingerprint) {
                return Err(Error::Approval);
            }
            publication.promote(self.expected, self.fingerprint, now)?;
            Ok("Старая identity отозвана в публикации; live worker применит новое поколение. Проверьте runtime.".into())
        }
    }
}

fn status_document(document: &Config, id: &str, now: u64) -> Result<String, Error> {
    match document {
        Config::Server(doc) => {
            let inbound = doc
                .server
                .inbounds
                .iter()
                .find(|i| i.id == id)
                .ok_or(Error::Scope)?;
            if inbound.security_mode != SecurityMode::SmartReality {
                return Err(Error::Format);
            }
            let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
            let listen: SocketAddr = inbound.h2_listen.parse().map_err(|_| Error::Scope)?;
            let scope = crate::descriptor::Scope {
                inbound: id.to_owned(),
                endpoint: format!("{}:{}", inbound.server_name, listen.port()),
            };
            let state = reference_health::Store::new(Path::new(&binding.health_store))
                .map_err(|_| Error::Health)?
                .inspect()
                .map_err(|_| Error::Health)?;
            let value = crate::reality_provision::inspect_registered(
                Path::new(&binding.bundle),
                binding,
                &state,
                &scope,
                now,
            )?;
            let (health, reserve) = state
                .active_status(value.descriptor(), now)
                .map_err(|_| Error::Health)?;
            let signed = value.descriptor();
            Ok(format!("Saved REALITY inbound; live state not inspected\ninbound={id}\nendpoint={}\nrevision={}\nidentity_sha256={}\nvalid_now={}\nactive_reference={}\nactive_status={health:?}\nreserve_candidate={}\nlast_checked_at={}\nnext_check_at={}\nh3={}\nbackend_available=true",
                scope.endpoint, signed.revision, hex(bootstrap::fingerprint(value.signer())),
                value.check_time(now).is_ok(), signed.references[usize::from(signed.active_reference)].server_name,
                reserve.map_or("none".into(), |i| i.to_string()), state.last_checked_at(),
                state.next_active_check_at(signed, now).map_err(|_| Error::Health)?, signed.h3))
        }
        Config::Client(doc) => {
            let profile = doc
                .client
                .profiles
                .iter()
                .find(|p| p.id == id)
                .ok_or(Error::Scope)?;
            let enrollment = pinned_client(profile)?;
            let value = enrollment
                .store()?
                .inspect(now)
                .map_err(|_| Error::Descriptor)?;
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
    use crate::{
        descriptor::Scope,
        identity_tls::Identity,
        reality_admission::Secret,
        reference_health::{Evidence, Plan, State, Store, Target},
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "theia-reality-config-{}-{}",
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

    fn health() -> State {
        State::new(
            Plan {
                schema_version: 1,
                inbound: "reality-edge".into(),
                endpoint: "edge.example.org:9443".into(),
                own_ips: vec!["93.184.216.1".parse().unwrap()],
                references: vec![Target {
                    server_name: "ref.example.org".into(),
                    address: "93.184.216.2:443".parse().unwrap(),
                }],
            },
            vec![Evidence {
                h2_status: Some(200),
                h3_status: None,
            }],
            1000,
        )
        .unwrap()
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
        let mut r = ServerRequest {
            health: health_path,
            bundle,
            health_sha256: digest,
            identity_sha256: record.identity_sha256,
            listen: "127.0.0.1:9443".parse().unwrap(),
            grants: vec!["device-a".into()],
        };
        let req = Request::Server(r.clone());
        let preview = prepare(&path, &req, 1000).unwrap();
        assert!(preview.report().contains("ref"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
        assert_eq!(apply(&path, &req, [0; 32], 1000), Err(Error::Approval));
        r.grants = vec!["missing".into()];
        assert!(matches!(
            prepare(&path, &Request::Server(r.clone()), 1000),
            Err(Error::Grant)
        ));
        r.grants = vec!["device-a".into(), "device-a".into()];
        assert!(prepare(&path, &Request::Server(r.clone()), 1000).is_err());
        r.grants.pop();
        r.listen.set_port(443);
        assert!(matches!(
            prepare(&path, &Request::Server(r), 1000),
            Err(Error::Scope)
        ));
        std::fs::write(&path, format!("{source}\n# changed")).unwrap();
        assert_eq!(
            apply(&path, &req, preview.approval_sha256(), 1000),
            Err(Error::Approval)
        );
        std::fs::write(&path, source).unwrap();
        apply(&path, &req, preview.approval_sha256(), 1000).unwrap();
        let Config::Server(saved) = config::read_file(&path).unwrap() else {
            panic!()
        };
        let inbound = saved.server.inbounds.last().unwrap();
        assert_eq!(inbound.security_mode, SecurityMode::SmartReality);
        assert!(inbound.tls_cert.is_empty() && inbound.tls_key.is_empty());
        assert_eq!(inbound.allowed_user_ids, vec!["device-a"]);
        assert!(prepare(&path, &req, 1000).is_err());
        let status = registered_status(&path, "reality-edge", 1000).unwrap();
        let saved_digest: [u8; 32] = Sha256::digest(std::fs::read(&path).unwrap()).into();
        assert_eq!(
            status_expected(&path, saved_digest, "reality-edge", 1000).unwrap(),
            status
        );
        assert_eq!(
            status_expected(&path, [0; 32], "reality-edge", 1000),
            Err(Error::Approval)
        );
        assert!(status.contains("backend_available=true"));
        assert!(status.contains("active_reference=ref.example.org"));
        // Compatible renewal advances publication without rewriting the
        // independently pinned initial receipt or the config record.
        let binding = inbound.reality.as_ref().unwrap();
        let publication = crate::identity_publication::Publication::new(
            &Path::new(&binding.bundle).join("publication.toml"),
        )
        .unwrap();
        let snapshot = publication.inspect(1001).unwrap();
        publication
            .refresh(&state, snapshot.snapshot_sha256, 1001)
            .unwrap();
        assert!(registered_status(&path, "reality-edge", 1001)
            .unwrap()
            .contains("revision=2"));
        let replacement_health = dir.0.join("replacement-health");
        let replacement_bundle = dir.0.join("replacement-bundle");
        Store::new(&replacement_health)
            .unwrap()
            .enroll(&state)
            .unwrap();
        let replacement =
            crate::reality_provision::create(&state, digest, &replacement_bundle, 1001).unwrap();
        let req = Request::ReplaceServer(ServerReplacement {
            id: "reality-edge".into(),
            health: replacement_health,
            bundle: replacement_bundle,
            health_sha256: digest,
            identity_sha256: replacement.identity_sha256,
        });
        let preview = prepare(&path, &req, 1001).unwrap();
        assert!(apply(&path, &req, [0; 32], 1001).is_err());
        apply(&path, &req, preview.approval_sha256(), 1001).unwrap();
        let Config::Server(after) = config::read_file(&path).unwrap() else {
            panic!()
        };
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        assert_eq!(
            crate::restart_guard::same_port_reality_only(&saved, &after),
            Some(saved.server.inbounds.len() - 1)
        );
        assert_eq!(
            after.server.inbounds.last().unwrap().allowed_user_ids,
            inbound.allowed_user_ids
        );
        assert_eq!(
            after.server.inbounds.last().unwrap().h2_listen,
            inbound.h2_listen
        );
        assert!(prepare(&path, &req, 1001).is_err());
        let mut mixed = saved;
        mixed.server.inbounds.last_mut().unwrap().tls_cert = "file:/tmp/foreign.pem".into();
        assert!(Config::Server(mixed).validate().is_err());
    }

    #[test]
    fn independent_reenrollment_replaces_only_selected_binding_and_requires_fresh_confirmation() {
        let dir = Scratch::new();
        let state = health();
        let scope = Scope {
            inbound: state.plan().inbound.clone(),
            endpoint: state.plan().endpoint.clone(),
        };
        let old = Identity::generate(scope.clone()).unwrap();
        let next = Identity::generate(scope).unwrap();
        let enroll = |identity: &Identity, state: &State, name: &str, now: u64| {
            let signed = bootstrap::initial_descriptor(state, identity, now).unwrap();
            let invitation = bootstrap::Invitation::public(identity, &signed, now).unwrap();
            let uri = invitation.encode().unwrap();
            let admission = dir.0.join(format!("{name}-admission"));
            Secret::generate()
                .unwrap()
                .save_new(identity.scope(), &admission)
                .unwrap();
            let enrollment = dir.0.join(format!("{name}-enrollment"));
            let trust = dir.0.join(format!("{name}-trust"));
            let pin = invitation.fingerprint();
            bootstrap::import(
                &uri,
                bootstrap::ImportApproval {
                    document_sha256: bootstrap::digest(&uri),
                    identity_sha256: pin,
                },
                &enrollment,
                &trust,
                bootstrap::EnrollmentMaterial {
                    admission_path: &admission,
                    expected_admission: None,
                    external_token: Some("env:THEIA_TEST"),
                },
                bootstrap::auto_policy(),
                now,
            )
            .unwrap();
            (enrollment, trust, pin, signed)
        };
        let (old_path, old_trust, old_pin, _) = enroll(&old, &state, "old", 1000);
        let cfg = dir.0.join("client.toml");
        std::fs::write(&cfg, include_str!("../../../examples/client.toml")).unwrap();
        let initial = Request::Client(ClientRequest {
            enrollment: old_path.clone(),
            identity_sha256: old_pin,
            id: "recovery".into(),
        });
        let preview = prepare(&cfg, &initial, 1000).unwrap();
        apply(&cfg, &initial, preview.approval_sha256(), 1000).unwrap();
        let Config::Client(before) = config::read_file(&cfg).unwrap() else {
            panic!()
        };
        let expired = validate_client(before.client.profiles.last().unwrap(), 1000)
            .unwrap()
            .descriptor()
            .not_after;
        let fresh = State::new(
            state.plan().clone(),
            vec![Evidence {
                h2_status: Some(200),
                h3_status: None,
            }],
            expired,
        )
        .unwrap();
        let (new_path, new_trust, new_pin, signed) = enroll(&next, &fresh, "new", expired);
        let req = ClientRequest {
            enrollment: new_path.clone(),
            identity_sha256: new_pin,
            id: "recovery".into(),
        };
        let old_bytes = std::fs::read(&old_trust).unwrap();
        let before_bytes = std::fs::read(&cfg).unwrap();
        assert!(prepare(
            &cfg,
            &Request::Reenroll(ClientRequest {
                identity_sha256: old_pin,
                ..req.clone()
            }),
            expired
        )
        .is_err());
        assert!(prepare(
            &cfg,
            &Request::Reenroll(ClientRequest {
                enrollment: old_path.clone(),
                identity_sha256: old_pin,
                id: req.id.clone()
            }),
            expired
        )
        .is_err());
        let request = Request::Reenroll(req);
        let preview = prepare(&cfg, &request, expired).unwrap();
        assert!(preview.report().contains("old_valid_now=false"));
        assert!(!preview.report().contains("THEIA_TEST"));
        assert_eq!(std::fs::read(&cfg).unwrap(), before_bytes);
        assert_eq!(
            apply(&cfg, &request, [0; 32], expired),
            Err(Error::Approval)
        );
        bootstrap::Profile::read(&new_path)
            .unwrap()
            .store()
            .unwrap()
            .update(&signed, expired + 1)
            .unwrap();
        assert_eq!(
            apply(&cfg, &request, preview.approval_sha256(), expired + 1),
            Err(Error::Approval)
        );
        let preview = prepare(&cfg, &request, expired + 1).unwrap();
        apply(&cfg, &request, preview.approval_sha256(), expired + 1).unwrap();
        let Config::Client(after) = config::read_file(&cfg).unwrap() else {
            panic!()
        };
        assert_eq!(after.client.active_profile, before.client.active_profile);
        assert_eq!(after.client.proxy, before.client.proxy);
        assert_eq!(after.client.profiles.len(), before.client.profiles.len());
        assert_eq!(
            validate_client(after.client.profiles.last().unwrap(), expired + 1)
                .unwrap()
                .signer(),
            next.public_key()
        );
        assert_eq!(std::fs::read(&old_trust).unwrap(), old_bytes);
        assert!(old_path.exists() && new_trust.exists());
        assert!(prepare(&cfg, &request, expired + 1).is_err());
    }

    #[test]
    fn credential_refresh_binds_current_trust_and_preserves_active_profile() {
        let dir = Scratch::new();
        let state = health();
        let scope = Scope {
            inbound: state.plan().inbound.clone(),
            endpoint: state.plan().endpoint.clone(),
        };
        let identity = Identity::generate(scope.clone()).unwrap();
        let signed = bootstrap::initial_descriptor(&state, &identity, 1000).unwrap();
        let public = bootstrap::Invitation::public(&identity, &signed, 1000).unwrap();
        let uri = public.encode().unwrap();
        let admission = dir.0.join("admission");
        Secret::generate()
            .unwrap()
            .save_new(&scope, &admission)
            .unwrap();
        let enrollment = dir.0.join("enrollment");
        let trust = dir.0.join("trust");
        let pin = public.fingerprint();
        bootstrap::import(
            &uri,
            bootstrap::ImportApproval {
                document_sha256: bootstrap::digest(&uri),
                identity_sha256: pin,
            },
            &enrollment,
            &trust,
            bootstrap::EnrollmentMaterial {
                admission_path: &admission,
                expected_admission: None,
                external_token: Some("env:THEIA_TEST"),
            },
            bootstrap::auto_policy(),
            1000,
        )
        .unwrap();
        let client = dir.0.join("client.toml");
        std::fs::write(&client, include_str!("../../../examples/client.toml")).unwrap();
        let req = Request::Client(ClientRequest {
            enrollment: enrollment.clone(),
            identity_sha256: pin,
            id: "reality-client".into(),
        });
        let approval = prepare(&client, &req, 1000).unwrap().approval_sha256();
        apply(&client, &req, approval, 1000).unwrap();
        let Config::Client(old) = config::read_file(&client).unwrap() else {
            panic!()
        };
        let before = std::fs::read(&client).unwrap();
        let old_enrollment = std::fs::read(&enrollment).unwrap();
        let before_trust = std::fs::read(&trust).unwrap();
        let invite_path = dir.0.join("invite");
        bootstrap::create_text(&invite_path, &uri).unwrap();
        assert!(preview_credential_refresh(&client, "reality-client", &invite_path, 1000).is_err());
        let token = [71u8; 32];
        let server_source = include_str!("../../../examples/server.toml").replace(
            "REPLACE_WITH_64_LOWERCASE_HEX",
            &format!("{:x}", Sha256::digest(token)),
        );
        let Config::Server(mut server) = config::parse(&server_source).unwrap() else {
            panic!()
        };
        server.server.enabled = true;
        server.server.inbounds[0].id = scope.inbound.clone();
        server.server.inbounds[0].server_name = "edge.example.org".into();
        server.server.inbounds[0].h2_listen = "127.0.0.1:9443".into();
        server.server.inbounds[0].quic_listen = "127.0.0.1:9443".into();
        let user = server.server.users[0].id.clone();
        server.server.users[0].disabled = false;
        server.server.inbounds[0].allowed_user_ids = vec![user.clone()];
        let issued =
            bootstrap::Invitation::issued(&identity, &signed, &server, &user, &token,
                &Secret::load(&scope, &admission).unwrap(), 1000)
                .unwrap();
        std::fs::write(&invite_path, issued.encode().unwrap().as_bytes()).unwrap();
        let (approval, revision) =
            preview_credential_refresh(&client, "reality-client", &invite_path, 1000).unwrap();
        assert_eq!(revision, 1);
        assert!(
            save_credential_refresh(&client, "reality-client", &invite_path, [0; 32], 1000)
                .is_err()
        );
        assert_eq!(std::fs::read(&client).unwrap(), before);
        std::fs::write(&client, [before.as_slice(), b"\n# changed"].concat()).unwrap();
        assert!(
            save_credential_refresh(&client, "reality-client", &invite_path, approval, 1000)
                .is_err()
        );
        std::fs::write(&client, &before).unwrap();
        save_credential_refresh(&client, "reality-client", &invite_path, approval, 1000).unwrap();
        let Config::Client(new) = config::read_file(&client).unwrap() else {
            panic!()
        };
        assert_eq!(old.client.active_profile, new.client.active_profile);
        assert_eq!(old.client.proxy, new.client.proxy);
        let old_p = old.client.profiles.last().unwrap();
        let new_p = new.client.profiles.last().unwrap();
        assert!(credential_only_change(old_p, new_p));
        assert!(validate_client(new_p, 1000).is_ok());
        assert!(!credential_only_change(new_p, new_p));
        let mut tampered = new_p.clone();
        tampered.reality_profile.as_mut().unwrap().identity_sha256 = [5; 32];
        assert!(!credential_only_change(old_p, &tampered));
        assert_eq!(std::fs::read(&enrollment).unwrap(), old_enrollment);
        assert_eq!(std::fs::read(&trust).unwrap(), before_trust);
        assert!(
            save_credential_refresh(&client, "reality-client", &invite_path, approval, 1000)
                .is_err()
        );
    }

    #[test]
    fn client_registration_pins_enrollment_and_preserves_active_proxy() {
        let dir = Scratch::new();
        let state = health();
        let identity = Identity::generate(Scope {
            inbound: state.plan().inbound.clone(),
            endpoint: state.plan().endpoint.clone(),
        })
        .unwrap();
        let document = bootstrap::initial_descriptor(&state, &identity, 1000).unwrap();
        let invite = bootstrap::Invitation::public(&identity, &document, 1000).unwrap();
        let uri = invite.encode().unwrap();
        let admission = dir.0.join("admission");
        Secret::generate()
            .unwrap()
            .save_new(identity.scope(), &admission)
            .unwrap();
        let enrollment = dir.0.join("enrollment");
        let trust = dir.0.join("trust");
        let pin = invite.fingerprint();
        bootstrap::import(
            &uri,
            bootstrap::ImportApproval {
                document_sha256: bootstrap::digest(&uri),
                identity_sha256: pin,
            },
            &enrollment,
            &trust,
            bootstrap::EnrollmentMaterial {
                admission_path: &admission,
                expected_admission: None,
                external_token: Some("env:THEIA_TEST"),
            },
            bootstrap::auto_policy(),
            1000,
        )
        .unwrap();
        let path = dir.0.join("client.toml");
        let source = include_str!("../../../examples/client.toml");
        std::fs::write(&path, source).unwrap();
        let Config::Client(original) = config::parse(source).unwrap() else {
            panic!()
        };
        let req = Request::Client(ClientRequest {
            enrollment: enrollment.clone(),
            identity_sha256: pin,
            id: "reality-client".into(),
        });
        let preview = prepare(&path, &req, 1000).unwrap();
        assert!(!preview.report().contains("THEIA_TEST"));
        apply(&path, &req, preview.approval_sha256(), 1000).unwrap();
        let Config::Client(saved) = config::read_file(&path).unwrap() else {
            panic!()
        };
        assert_eq!(saved.client.active_profile, original.client.active_profile);
        assert_eq!(saved.client.proxy, original.client.proxy);
        let mut new = saved.client.profiles.last().unwrap().clone();
        assert!(validate_client(&new, 1000).is_ok());
        assert!(registered_status(&path, "reality-client", 1000)
            .unwrap()
            .contains("active_profile=false"));
        let expired = validate_client(&new, 1000).unwrap().descriptor().not_after;
        assert!(validate_client(&new, expired).is_err());
        let offline = registered_status(&path, "reality-client", expired).unwrap();
        assert!(offline.contains("valid_now=false"));
        assert!(offline.contains("required_action=authenticated-offline-recovery"));
        let fresh = State::new(
            state.plan().clone(),
            vec![Evidence {
                h2_status: Some(200),
                h3_status: None,
            }],
            expired,
        )
        .unwrap();
        let recovered =
            bootstrap::refresh_descriptor(&fresh, &identity, &document, expired).unwrap();
        let descriptor = dir.0.join("recovered");
        bootstrap::create_text(&descriptor, &recovered).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let preview =
            TrustReview::prepare(&path, digest, "reality-client", &descriptor, false, expired)
                .unwrap();
        assert!(!preview.report().contains("THEIA_TEST"));
        assert!(TrustReview::prepare(
            &path,
            [0; 32],
            "reality-client",
            &descriptor,
            false,
            expired
        )
        .is_err());
        assert!(
            TrustReview::prepare(&path, digest, "reality-client", &descriptor, true, expired)
                .is_err()
        );
        std::fs::write(&descriptor, &document).unwrap();
        assert!(preview
            .apply(&path, digest, "reality-client", expired)
            .is_err());
        std::fs::write(&descriptor, &recovered).unwrap();
        let preview =
            TrustReview::prepare(&path, digest, "reality-client", &descriptor, false, expired)
                .unwrap();
        preview
            .apply(&path, digest, "reality-client", expired)
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            validate_client(&new, expired)
                .unwrap()
                .descriptor()
                .revision,
            2
        );
        new.auth_token = "env:OTHER".into();
        assert!(matches!(validate_client(&new, 1000), Err(Error::Approval)));
        let mut replacement = std::fs::read_to_string(&enrollment).unwrap();
        replacement.push_str("\n# changed");
        std::fs::write(&enrollment, replacement).unwrap();
        assert!(matches!(
            validate_client(saved.client.profiles.last().unwrap(), 1000),
            Err(Error::Approval)
        ));
    }

    #[test]
    fn registered_rotation_preview_apply_and_stale_digest_are_guarded() {
        let dir = Scratch::new();
        let state = health();
        let health_path = dir.0.join("health");
        let bundle = dir.0.join("bundle");
        Store::new(&health_path).unwrap().enroll(&state).unwrap();
        let digest = state.snapshot_sha256().unwrap();
        let record = crate::reality_provision::create(&state, digest, &bundle, 1000).unwrap();
        let path = dir.0.join("server.toml");
        std::fs::write(
            &path,
            include_str!("../../../examples/server.toml")
                .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64)),
        )
        .unwrap();
        let req = Request::Server(ServerRequest {
            health: health_path.clone(),
            bundle: bundle.clone(),
            health_sha256: digest,
            identity_sha256: record.identity_sha256,
            listen: "127.0.0.1:9443".parse().unwrap(),
            grants: vec!["device-a".into()],
        });
        let prepared = prepare(&path, &req, 1000).unwrap();
        let original: [u8; 32] = Sha256::digest(std::fs::read(&path).unwrap()).into();
        assert_eq!(prepared.source_sha256(), original);
        assert!(matches!(prepared.candidate(), Config::Server(_)));
        apply(&path, &req, prepared.approval_sha256(), 1000).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let saved: [u8; 32] = Sha256::digest(&bytes).into();
        let id = "reality-edge";
        assert!(runtime_status_command(&path, saved, id).is_ok());
        assert!(runtime_status_command(&path, [0; 32], id).is_err());
        assert!(runtime_status_command(&path, saved, "missing").is_err());
        assert!(RotationReview::prepare(&path, saved, id, true, 1001).is_err());
        assert!(ExpiryReview::prepare(&path, saved, id, 1001).is_err());
        let preview = RotationReview::prepare(&path, saved, id, false, 1001).unwrap();
        assert!(preview.report().contains("fingerprint"));
        let publication =
            crate::identity_publication::Publication::new(&bundle.join("publication.toml"))
                .unwrap();
        let before = publication.inspect(1001).unwrap();
        assert!(before.next_fingerprint.is_none());
        assert!(preview.apply(&path, [0; 32], id, 1001).is_err());
        assert_eq!(
            publication.inspect(1001).unwrap().snapshot_sha256,
            before.snapshot_sha256
        );
        let preview = RotationReview::prepare(&path, saved, id, false, 1001).unwrap();
        let stale = RotationReview::prepare(&path, saved, id, false, 1001).unwrap();
        assert!(preview
            .apply(&path, saved, id, 1001)
            .unwrap()
            .contains("Ротация опубликована"));
        assert!(stale.apply(&path, saved, id, 1001).is_err());
        let after = publication.inspect(1001).unwrap();
        assert_eq!(after.revision, 2);
        assert!(after.next_fingerprint.is_some());
        assert!(RotationReview::prepare(&path, saved, id, false, 1001).is_err());
        assert!(RotationReview::prepare(&path, saved, id, true, 1001).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}
