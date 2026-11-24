//! Create-only local initial provisioning transaction. The manifest is
//! published last. Incomplete directories must never be treated as ready.
//! No live listener, grant, system proxy, or network setting is changed.
#![forbid(unsafe_code)]

use crate::{
    descriptor::Scope,
    identity_publication::Publication,
    identity_tls::Identity,
    reality_admission::Secret,
    reality_bootstrap::{self as bootstrap, Error},
    reference_health::State,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const MANIFEST: &str = "provision.toml";
const IDENTITY: &str = "identity.key";
const ADMISSION: &str = "admission.key";
const PUBLICATION: &str = "publication.toml";

#[derive(Debug, PartialEq, Eq)]
pub struct Preview {
    pub health_sha256: [u8; 32],
    pub plan_sha256: [u8; 32],
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    schema_version: u16,
    pub scope: Scope,
    pub health_sha256: [u8; 32],
    pub plan_sha256: [u8; 32],
    pub identity_sha256: [u8; 32],
    pub publication_sha256: [u8; 32],
    pub initial_payload_sha256: [u8; 32],
    admission_commitment: [u8; 32],
}

impl Record {
    pub(crate) fn manifest_sha256(&self) -> Result<[u8; 32], Error> {
        let raw = toml::to_string(self).map_err(|_| Error::Format)?;
        Ok(bootstrap::digest(&raw))
    }
}

pub fn preview(state: &State, now: u64) -> Result<Preview, Error> {
    state.provisioning_ready(now).map_err(|_| Error::Health)?;
    Ok(Preview {
        health_sha256: state.snapshot_sha256().map_err(|_| Error::Health)?,
        plan_sha256: state.plan().digest().map_err(|_| Error::Health)?,
    })
}

/// The directory must not exist. On any failure after directory creation,
/// leave it private and incomplete, rather than deleting possibly observed
/// key material. Retry only into a different new directory. A completed
/// manifest is an initial provisioning receipt, not a live configuration.
pub fn create(
    state: &State,
    expected_health: [u8; 32],
    output: &Path,
    now: u64,
) -> Result<Record, Error> {
    let approved = preview(state, now)?;
    if approved.health_sha256 != expected_health {
        return Err(Error::Approval);
    }
    if !crate::bounded_input::explicit_file_path(output) || output.file_name().is_none() {
        return Err(Error::Storage);
    }
    crate::client_import::new_private_directory(output).map_err(|_| Error::Storage)?;
    let scope = Scope {
        inbound: state.plan().inbound.clone(),
        endpoint: state.plan().endpoint.clone(),
    };
    let identity = Identity::generate(scope.clone()).map_err(|_| Error::Identity)?;
    identity.save_new(&output.join(IDENTITY)).map_err(|error| match error {
        crate::identity_tls::Error::Indeterminate => Error::Indeterminate,
        _ => Error::Storage,
    })?;
    let secret = Secret::generate().map_err(|_| Error::Identity)?;
    secret.save_new(&scope, &output.join(ADMISSION)).map_err(|error| match error {
            crate::reality_admission::Error::Indeterminate => Error::Indeterminate,
            _ => Error::Storage,
        })?;
    let publication = Publication::new(&output.join(PUBLICATION))?;
    publication.initialize(state, &output.join(IDENTITY), now)?;
    let status = publication.inspect(now)?;
    let initial = publication.inspect_descriptor(status.snapshot_sha256, now)?;
    let record = Record {
        schema_version: 1,
        scope,
        health_sha256: approved.health_sha256,
        plan_sha256: approved.plan_sha256,
        identity_sha256: bootstrap::fingerprint(identity.public_key()),
        publication_sha256: status.snapshot_sha256,
        initial_payload_sha256: initial.payload_sha256(),
        admission_commitment: secret.commitment(),
    };
    if !status.valid_now || status.active_fingerprint != record.identity_sha256
        || status.plan_sha256 != record.plan_sha256 || status.generation != 1
        || status.next_fingerprint.is_some() {
        return Err(Error::Descriptor);
    }
    let raw = toml::to_string(&record).map_err(|_| Error::Format)?;
    bootstrap::create_text(&output.join(MANIFEST), &raw)?;
    Ok(record)
}

fn read_manifest(directory: &Path) -> Result<Record, Error> {
    if !crate::bounded_input::explicit_file_path(directory) || directory.file_name().is_none() {
        return Err(Error::Storage);
    }
    let metadata = std::fs::symlink_metadata(directory).map_err(|_| Error::Storage)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() { return Err(Error::Storage); }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::Storage);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 { return Err(Error::Storage); }
    }
    let raw = bootstrap::read_text(&directory.join(MANIFEST), 8192, true)?;
    let record: Record = toml::from_str(&raw).map_err(|_| Error::Format)?;
    if record.schema_version != 1 { return Err(Error::Format); }
    Ok(record)
}

/// Reopen registered materials after compatible refresh or planned rotation.
/// The manifest's canonical commitment and independent root are stored in
/// the ordinary config, outside the mutable publication.
pub fn inspect_registered(
    directory: &Path,
    binding: &crate::config::RealityBinding,
    state: &State,
    scope: &Scope,
    now: u64,
) -> Result<crate::descriptor::Verified, Error> {
    let (record, _admission) = registered_material(directory, binding, state, scope)?;
    Publication::new(&directory.join(PUBLICATION))?.inspect_rooted(scope,
        binding.identity_sha256, record.initial_payload_sha256, record.plan_sha256, now)
}

fn registered_material(
    directory: &Path, binding: &crate::config::RealityBinding, state: &State, scope: &Scope,
) -> Result<(Record, Secret), Error> {
    use subtle::ConstantTimeEq;
    let record = read_manifest(directory)?;
    if &record.scope != scope || record.health_sha256 != binding.initial_health_sha256
        || record.identity_sha256 != binding.identity_sha256
        || !bool::from(record.manifest_sha256()?.ct_eq(&binding.manifest_sha256))
        || record.plan_sha256 != state.plan().digest().map_err(|_| Error::Health)? {
        return Err(Error::Approval);
    }
    let admission = Secret::load(scope, &directory.join(ADMISSION)).map_err(|_| Error::Credential)?;
    if !bool::from(admission.commitment().ct_eq(&record.admission_commitment)) {
        return Err(Error::Credential);
    }
    Ok((record, admission))
}

/// Root and material are validated together before a new local candidate
/// generation is constructed. This does not bind a socket or enable a backend.
pub(crate) fn capture_registered(
    directory: &Path, binding: &crate::config::RealityBinding, state: &State,
    scope: &Scope, now: u64,
) -> Result<(crate::identity_publication::CapturedPublication, Secret), Error> {
    let (record, admission) = registered_material(directory, binding, state, scope)?;
    let captured = Publication::new(&directory.join(PUBLICATION))?.capture_rooted(
        state, scope, binding.identity_sha256, record.initial_payload_sha256, now)?;
    Ok((captured, admission))
}

/// Reopen an initial, unmodified provisioning receipt. An independent
/// identity fingerprint and exact health approval are required, rather
/// than trusting metadata merely because it resides in the directory.
/// This is *not* a current-publication loader after refresh or rotation.
pub fn inspect_initial(
    state: &State,
    expected_health: [u8; 32],
    expected_identity: [u8; 32],
    directory: &Path,
    now: u64,
) -> Result<Record, Error> {
    use subtle::ConstantTimeEq;
    let record = read_manifest(directory)?;
    if record.schema_version != 1
        || record.scope.inbound != state.plan().inbound
        || record.scope.endpoint != state.plan().endpoint
        || record.plan_sha256 != state.plan().digest().map_err(|_| Error::Health)?
        || record.health_sha256 != state.snapshot_sha256().map_err(|_| Error::Health)?
        || record.health_sha256 != expected_health
        || record.identity_sha256 != expected_identity {
        return Err(Error::Approval);
    }
    let identity = Identity::load(&directory.join(IDENTITY), &record.scope).map_err(|_| Error::Identity)?;
    if !bool::from(bootstrap::fingerprint(identity.public_key()).ct_eq(&expected_identity)) {
        return Err(Error::Identity);
    }
    let admission = Secret::load(&record.scope, &directory.join(ADMISSION)).map_err(|_| Error::Credential)?;
    if !bool::from(admission.commitment().ct_eq(&record.admission_commitment)) {
        return Err(Error::Credential);
    }
    let publication = Publication::new(&directory.join(PUBLICATION))?;
    let status = publication.inspect(now)?;
    if status.generation != 1 || status.revision != 1 || status.next_fingerprint.is_some()
        || status.snapshot_sha256 != record.publication_sha256 || status.plan_sha256 != record.plan_sha256 {
        return Err(Error::Descriptor);
    }
    let captured = publication.capture(state, record.publication_sha256, now)?;
    let active = captured.select(identity.public_key(), now)?;
    if active.verified().descriptor().scope != record.scope
        || active.verified().payload_sha256() != record.initial_payload_sha256 { return Err(Error::Scope); }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_health::{Evidence, Plan, Target};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn provisioning_is_fresh_digest_bound_and_create_only() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir().join(format!("theia-provision-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&parent).unwrap();
        let output = parent.join("new");
        let state = State::new(Plan {
            schema_version: 1,
            inbound: "edge".into(),
            endpoint: "edge.example.org:443".into(),
            own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: vec![Target { server_name: "reference.example.org".into(), address: "93.184.216.2:443".parse().unwrap() }],
        }, vec![Evidence { h2_status: Some(200), h3_status: None }], 1000).unwrap();
        let approval = preview(&state, 1000).unwrap();
        assert!(preview(&state, 999).is_err());
        assert!(preview(&state, 1061).is_err());
        assert!(matches!(create(&state, [0; 32], &output, 1000), Err(Error::Approval)));
        assert!(!output.exists());
        let record = create(&state, approval.health_sha256, &output, 1060).unwrap();
        let identity = Identity::load(&output.join(IDENTITY), &record.scope).unwrap();
        assert_eq!(bootstrap::fingerprint(identity.public_key()), record.identity_sha256);
        assert!(Secret::load(&record.scope, &output.join(ADMISSION)).is_ok());
        assert!(inspect_initial(&state, approval.health_sha256, record.identity_sha256, &output, 1060).is_ok());
        assert!(inspect_initial(&state, approval.health_sha256, [0; 32], &output, 1060).is_err());
        assert!(inspect_initial(&state, [0; 32], record.identity_sha256, &output, 1060).is_err());
        let incomplete = parent.join("incomplete");
        crate::client_import::new_private_directory(&incomplete).unwrap();
        assert!(inspect_initial(&state, approval.health_sha256, record.identity_sha256, &incomplete, 1060).is_err());
        let secret_path = output.join(ADMISSION);
        std::fs::remove_file(&secret_path).unwrap();
        Secret::generate().unwrap().save_new(&record.scope, &secret_path).unwrap();
        assert!(matches!(inspect_initial(&state, approval.health_sha256, record.identity_sha256, &output, 1060), Err(Error::Credential)));
        let status = Publication::new(&output.join(PUBLICATION)).unwrap().inspect(1060).unwrap();
        assert_eq!(status.snapshot_sha256, record.publication_sha256);
        let raw = bootstrap::read_text(&output.join(MANIFEST), 8192, true).unwrap();
        assert!(toml::from_str::<Record>(&raw).unwrap() == record);
        assert!(matches!(create(&state, approval.health_sha256, &output, 1060), Err(Error::Storage)));
        assert_eq!(&*bootstrap::read_text(&output.join(MANIFEST), 8192, true).unwrap(), &*raw);
        std::fs::remove_dir_all(parent).unwrap();
    }
}
