//! Local generation lifecycle for registered REALITY material. It does not
//! activate a carrier. The owner-approved configuration is immutable for
//! the lifetime of the manager; a change requires a new supervisor action.
#![forbid(unsafe_code)]

use crate::{
    config::{Config, Inbound},
    reality_checkpoint::{self, Stamp},
    descriptor::Scope,
    identity_publication::CapturedPublication,
    reality_admission::Secret,
    reality_bootstrap::Error,
    reference_health::{State, Store},
    security_profile::SecurityMode,
};
use std::{net::SocketAddr, path::Path, sync::{Arc, Mutex}};

struct Generation {
    publication: CapturedPublication,
    // Keep the protected material owned by this generation; it is never
    // returned by status, debug formatting or this local lifecycle API.
    admission: Arc<Secret>,
    health: State,
    health_revision: u64,
    health_digest: [u8; 32],
}

impl Generation {
    fn load(inbound: &Inbound, scope: &Scope, now: u64) -> Result<Self, Error> {
        let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
        let health = Store::new(Path::new(&binding.health_store)).map_err(|_| Error::Health)?
            .inspect().map_err(|_| Error::Health)?;
        Self::from_health(inbound, scope, &health, now)
    }

    fn from_health(inbound: &Inbound, scope: &Scope, health: &State, now: u64) -> Result<Self, Error> {
        let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
        let (publication, admission) = crate::reality_provision::capture_registered(
            Path::new(&binding.bundle), binding, health, scope, now)?;
        Ok(Self {
            publication, admission: Arc::new(admission), health: health.clone(), health_revision: health.revision(),
            health_digest: health.snapshot_sha256().map_err(|_| Error::Health)?,
        })
    }

    fn stamp(&self, inbound: &Inbound) -> Result<Stamp, Error> {
        Ok(Stamp {
            manifest: inbound.reality.as_ref().ok_or(Error::Format)?.manifest_sha256,
            generation: self.publication.generation(),
            publication: self.publication.snapshot_sha256(),
            health_revision: self.health_revision, health: self.health_digest,
        })
    }

    fn compare(&self, next: &Self) -> Result<(), Error> {
        let old = &self.publication;
        let new = &next.publication;
        if new.generation() < old.generation()
            || next.health_revision < self.health_revision
            || (new.generation() == old.generation() && new.snapshot_sha256() != old.snapshot_sha256())
            || (next.health_revision == self.health_revision && next.health_digest != self.health_digest)
            || new.plan_sha256() != old.plan_sha256() {
            return Err(Error::Approval);
        }
        Ok(())
    }
}

struct Slot {
    // Retain the last accepted floor even after a failed refresh; never
    // reset monotonicity merely because the disk temporarily disappeared.
    last: Arc<Generation>,
    last_checked_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub generation: u64,
    pub revision: u64,
    pub health_revision: u64,
    pub active_reference: u8,
    pub overlap: bool,
    pub active_usable: bool,
    pub successor_usable: bool,
}

/// An immutable local candidate snapshot, not a handshake authorization.
/// No signing key or bearer is exposed. Existing owners can retain a lease
/// for accounting without preventing the next generation from being loaded.
pub struct Lease(Arc<Generation>, u64);

impl Lease {
    pub(crate) fn publication(&self) -> &CapturedPublication { &self.0.publication }
    pub(crate) fn admission(&self) -> Arc<Secret> { self.0.admission.clone() }
    pub(crate) fn health(&self) -> &State { &self.0.health }

    pub fn status(&self) -> Status {
        let generation = &self.0;
        let publication = &generation.publication;
        let active = publication.active().verified();
        let active_usable = active.check_time(self.1).is_ok();
        let successor_usable = publication.next().is_some_and(|entry| entry.verified().check_time(self.1).is_ok());
        Status { generation: publication.generation(), revision: active.descriptor().revision,
            health_revision: generation.health_revision, active_reference: active.descriptor().active_reference,
            overlap: active_usable && successor_usable, active_usable, successor_usable }
    }
}

pub struct Manager {
    inbound: Inbound,
    scope: Scope,
    slot: Mutex<Slot>,
}

impl Manager {
    /// Construct only from a validated shared server config. There is no
    /// fallback to own TLS, no listener activation, and no grant mutation.
    pub fn new(config: &Config, inbound_id: &str, now: u64) -> Result<Self, Error> {
        config.validate().map_err(|_| Error::Format)?;
        let Config::Server(doc) = config else { return Err(Error::Format); };
        if !doc.server.enabled { return Err(Error::Format); }
        let inbound = doc.server.inbounds.iter().find(|i| i.id == inbound_id).ok_or(Error::Scope)?;
        if inbound.security_mode != SecurityMode::SmartReality || inbound.reality.is_none() {
            return Err(Error::Format);
        }
        let listen: SocketAddr = inbound.h2_listen.parse().map_err(|_| Error::Scope)?;
        let scope = Scope { inbound: inbound.id.clone(), endpoint: format!("{}:{}", inbound.server_name, listen.port()) };
        let first = Arc::new(Generation::load(inbound, &scope, now)?);
        let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
        reality_checkpoint::accept(Path::new(&binding.bundle), first.stamp(inbound)?, now)?;
        Ok(Self { inbound: inbound.clone(), scope, slot: Mutex::new(Slot { last: first, last_checked_at: now }) })
    }

    /// Serialize candidate changes, revalidate private materials on each
    /// refresh, and refuse stale, equivocated or unhealthy generations.
    /// Never hand out the prior candidate on failure. The lock is intended
    /// for a local maintenance worker, not an async network event loop.
    pub fn refresh(&self, now: u64) -> Result<Lease, Error> {
        let mut slot = self.slot.lock().map_err(|_| Error::Storage)?;
        if now < slot.last_checked_at { return Err(Error::Clock); }
        // A failed refresh must not make an earlier clock acceptable again.
        slot.last_checked_at = now;
        let candidate = Generation::load(&self.inbound, &self.scope, now)?;
        slot.last.compare(&candidate)?;
        let binding = self.inbound.reality.as_ref().ok_or(Error::Format)?;
        reality_checkpoint::accept(Path::new(&binding.bundle), candidate.stamp(&self.inbound)?, now)?;
        if candidate.publication.snapshot_sha256() != slot.last.publication.snapshot_sha256()
            || candidate.health_digest != slot.last.health_digest {
            slot.last = Arc::new(candidate);
        }
        Ok(Lease(Arc::clone(&slot.last), now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config, reality_config::{self, Request, ServerRequest},
        reference_health::{Evidence, Plan, Target}};
    use std::{path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!("theia-generation-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

    #[test]
    fn generation_rejects_rollback_and_retains_existing_lease() {
        let dir = Scratch::new();
        let now = 1000;
        let state = State::new(Plan { schema_version: 1, inbound: "edge".into(),
            endpoint: "edge.example.org:9443".into(), own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: vec![Target { server_name: "ref.example.org".into(), address: "93.184.216.2:443".parse().unwrap() }] },
            vec![Evidence { h2_status: Some(200), h3_status: None }], now).unwrap();
        let health = dir.0.join("health");
        Store::new(&health).unwrap().enroll(&state).unwrap();
        let bundle = dir.0.join("bundle");
        let digest = state.snapshot_sha256().unwrap();
        let record = crate::reality_provision::create(&state, digest, &bundle, now).unwrap();
        let cfg = dir.0.join("server.toml");
        std::fs::write(&cfg, include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64))).unwrap();
        let request = Request::Server(ServerRequest { health, bundle: bundle.clone(), health_sha256: digest,
            identity_sha256: record.identity_sha256, listen: "127.0.0.1:9443".parse().unwrap(),
            grants: vec!["device-a".into()] });
        let preview = reality_config::prepare(&cfg, &request, now).unwrap();
        reality_config::apply(&cfg, &request, preview.approval_sha256(), now).unwrap();
        let doc = config::read_file(&cfg).unwrap();
        let manager = Manager::new(&doc, "edge", now).unwrap();
        let old = manager.refresh(now).unwrap();
        let path = bundle.join("publication.toml");
        let original = std::fs::read(&path).unwrap();
        let publication = crate::identity_publication::Publication::new(&path).unwrap();
        let status = publication.inspect(now).unwrap();
        publication.refresh(&state, status.snapshot_sha256, now + 1).unwrap();
        let new = manager.refresh(now + 1).unwrap();
        assert_eq!(old.status().revision, 1);
        assert_eq!(new.status().revision, 2);
        assert!(matches!(manager.refresh(now), Err(Error::Clock)));
        let updated = std::fs::read(&path).unwrap();
        std::fs::write(&path, original).unwrap();
        assert!(matches!(manager.refresh(now + 2), Err(Error::Approval)));
        // The generation floor is independent of the mutable publication;
        // even a completely new manager must reject this older snapshot.
        assert!(matches!(Manager::new(&doc, "edge", now + 2), Err(Error::Approval)));
        std::fs::write(&path, updated).unwrap();
        assert_eq!(manager.refresh(now + 2).unwrap().status().revision, 2);
        let reopened = Manager::new(&doc, "edge", now + 2).unwrap();
        assert_eq!(reopened.refresh(now + 2).unwrap().status().revision, 2);
        let floor = bundle.join("generation-floor.toml");
        let floor_raw = std::fs::read(&floor).unwrap();
        std::fs::remove_file(&floor).unwrap();
        assert!(matches!(Manager::new(&doc, "edge", now + 2), Err(Error::Storage)));
        assert!(matches!(manager.refresh(now + 2), Err(Error::Storage)));
        crate::reality_bootstrap::create_text(&floor, std::str::from_utf8(&floor_raw).unwrap()).unwrap();
        let secret = bundle.join("admission.key");
        std::fs::remove_file(&secret).unwrap();
        assert!(matches!(manager.refresh(now + 3), Err(Error::Credential)));
        assert_eq!(old.status().revision, 1);
    }
}
