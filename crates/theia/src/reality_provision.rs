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
    Secret::generate().map_err(|_| Error::Identity)?
        .save_new(&scope, &output.join(ADMISSION)).map_err(|error| match error {
            crate::reality_admission::Error::Indeterminate => Error::Indeterminate,
            _ => Error::Storage,
        })?;
    let publication = Publication::new(&output.join(PUBLICATION))?;
    publication.initialize(state, &output.join(IDENTITY), now)?;
    let status = publication.inspect(now)?;
    let record = Record {
        schema_version: 1,
        scope,
        health_sha256: approved.health_sha256,
        plan_sha256: approved.plan_sha256,
        identity_sha256: bootstrap::fingerprint(identity.public_key()),
        publication_sha256: status.snapshot_sha256,
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
        let status = Publication::new(&output.join(PUBLICATION)).unwrap().inspect(1060).unwrap();
        assert_eq!(status.snapshot_sha256, record.publication_sha256);
        let raw = bootstrap::read_text(&output.join(MANIFEST), 8192, true).unwrap();
        assert!(toml::from_str::<Record>(&raw).unwrap() == record);
        assert!(matches!(create(&state, approval.health_sha256, &output, 1060), Err(Error::Storage)));
        assert_eq!(&*bootstrap::read_text(&output.join(MANIFEST), 8192, true).unwrap(), &*raw);
        std::fs::remove_dir_all(parent).unwrap();
    }
}
