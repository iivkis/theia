//! Local generation lifecycle for registered REALITY material. It does not
//! activate a carrier. The owner-approved configuration is immutable for
//! the lifetime of the manager; a change requires a new supervisor action.
#![forbid(unsafe_code)]

use crate::{
    config::{Config, Inbound},
    descriptor::Scope,
    identity_publication::CapturedPublication,
    reality_admission::Secret,
    reality_bootstrap::Error,
    reality_checkpoint::{self, Stamp},
    reference_health::{State, Store},
    security_profile::SecurityMode,
};
use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
};

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
        let health = Store::new(Path::new(&binding.health_store))
            .map_err(|_| Error::Health)?
            .inspect()
            .map_err(|_| Error::Health)?;
        Self::from_health(inbound, scope, &health, now)
    }

    fn from_health(
        inbound: &Inbound,
        scope: &Scope,
        health: &State,
        now: u64,
    ) -> Result<Self, Error> {
        let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
        let (publication, admission) = crate::reality_provision::capture_registered(
            Path::new(&binding.bundle),
            binding,
            health,
            scope,
            now,
        )?;
        Ok(Self {
            publication,
            admission: Arc::new(admission),
            health: health.clone(),
            health_revision: health.revision(),
            health_digest: health.snapshot_sha256().map_err(|_| Error::Health)?,
        })
    }

    fn stamp(&self, inbound: &Inbound) -> Result<Stamp, Error> {
        Ok(Stamp {
            manifest: inbound
                .reality
                .as_ref()
                .ok_or(Error::Format)?
                .manifest_sha256,
            generation: self.publication.generation(),
            publication: self.publication.snapshot_sha256(),
            health_revision: self.health_revision,
            health: self.health_digest,
        })
    }

    fn compare(&self, next: &Self) -> Result<(), Error> {
        let old = &self.publication;
        let new = &next.publication;
        if new.generation() < old.generation()
            || next.health_revision < self.health_revision
            || (new.generation() == old.generation()
                && new.snapshot_sha256() != old.snapshot_sha256())
            || (next.health_revision == self.health_revision
                && next.health_digest != self.health_digest)
            || new.plan_sha256() != old.plan_sha256()
        {
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
    pub(crate) fn publication(&self) -> &CapturedPublication {
        &self.0.publication
    }
    pub(crate) fn admission(&self) -> Arc<Secret> {
        self.0.admission.clone()
    }
    pub(crate) fn health(&self) -> &State {
        &self.0.health
    }

    pub fn status(&self) -> Status {
        let generation = &self.0;
        let publication = &generation.publication;
        let active = publication.active().verified();
        let active_usable = active.check_time(self.1).is_ok();
        let successor_usable = publication
            .next()
            .is_some_and(|entry| entry.verified().check_time(self.1).is_ok());
        let effective = if !active_usable {
            publication.next().map(|v| v.verified()).unwrap_or(active)
        } else {
            active
        };
        Status {
            generation: publication.generation(),
            revision: effective.descriptor().revision,
            health_revision: generation.health_revision,
            active_reference: effective.descriptor().active_reference,
            overlap: active_usable && successor_usable,
            active_usable,
            successor_usable,
        }
    }
}

/// Read-only capture for content-bound structural Apply. Its immutable
/// generation is exactly the one later used to construct both transports.
pub(crate) struct Candidate {
    inbound: Inbound,
    scope: Scope,
    generation: Arc<Generation>,
    stamp: Stamp,
}
impl Candidate {
    pub(crate) fn capture(inbound: &Inbound, now: u64) -> Result<Self, Error> {
        let addr: SocketAddr = inbound.h2_listen.parse().map_err(|_| Error::Scope)?;
        let scope = Scope {
            inbound: inbound.id.clone(),
            endpoint: format!("{}:{}", inbound.server_name, addr.port()),
        };
        let generation = Arc::new(Generation::load(inbound, &scope, now)?);
        let stamp = generation.stamp(inbound)?;
        let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
        reality_checkpoint::verify(Path::new(&binding.bundle), stamp, now)?;
        Ok(Self {
            inbound: inbound.clone(),
            scope,
            generation,
            stamp,
        })
    }
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"Theia/REALITY/restart-material/v1\0");
        hash.update(self.stamp.manifest);
        hash.update(self.stamp.publication);
        hash.update(self.stamp.health);
        hash.finalize().into()
    }
    pub(crate) fn activate(&self, inbound: &Inbound, now: u64) -> Result<(Manager, Lease), Error> {
        if &self.inbound != inbound {
            return Err(Error::Approval);
        }
        let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
        // Re-read only the verified stamp, not the accepted key objects.
        // If maintenance changed health or publication after the preview,
        // reject the stale candidate and require a new explicit approval.
        let observed = Store::new(Path::new(&binding.health_store))
            .and_then(|s| s.inspect())
            .map_err(|_| Error::Health)?;
        let (_, stamp) = crate::reality_provision::inspect_registered_snapshot(
            Path::new(&binding.bundle),
            binding,
            &observed,
            &self.scope,
            now,
        )?;
        if stamp != self.stamp {
            return Err(Error::Approval);
        }
        let lease = Lease(self.generation.clone(), now);
        if crate::reality_live::relay_value(&lease, now).is_none() {
            return Err(Error::Health);
        }
        reality_checkpoint::accept(Path::new(&binding.bundle), stamp, now)?;
        Ok((
            Manager {
                inbound: inbound.clone(),
                scope: self.scope.clone(),
                slot: Mutex::new(Slot {
                    last: self.generation.clone(),
                    last_checked_at: now,
                }),
            },
            lease,
        ))
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
        let Config::Server(doc) = config else {
            return Err(Error::Format);
        };
        if !doc.server.enabled {
            return Err(Error::Format);
        }
        let inbound = doc
            .server
            .inbounds
            .iter()
            .find(|i| i.id == inbound_id)
            .ok_or(Error::Scope)?;
        if inbound.security_mode != SecurityMode::SmartReality || inbound.reality.is_none() {
            return Err(Error::Format);
        }
        let listen: SocketAddr = inbound.h2_listen.parse().map_err(|_| Error::Scope)?;
        let scope = Scope {
            inbound: inbound.id.clone(),
            endpoint: format!("{}:{}", inbound.server_name, listen.port()),
        };
        let first = Arc::new(Generation::load(inbound, &scope, now)?);
        let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
        reality_checkpoint::accept(Path::new(&binding.bundle), first.stamp(inbound)?, now)?;
        Ok(Self {
            inbound: inbound.clone(),
            scope,
            slot: Mutex::new(Slot {
                last: first,
                last_checked_at: now,
            }),
        })
    }

    /// Startup may encounter persisted degradation from a previous process.
    /// Before binding listeners, perform only a due bounded recheck and
    /// the same approved failover CAS. Missing or invalid private material,
    /// floor rollback, expired trust and unavailable reserves fail closed.
    pub(crate) async fn new_live(
        config: &Config,
        inbound_id: &str,
        now: u64,
    ) -> Result<Self, Error> {
        if let Ok(manager) = Self::new(config, inbound_id, now) {
            return Ok(manager);
        }
        config.validate().map_err(|_| Error::Format)?;
        let Config::Server(doc) = config else {
            return Err(Error::Format);
        };
        if !doc.server.enabled {
            return Err(Error::Format);
        }
        let inbound = doc
            .server
            .inbounds
            .iter()
            .find(|i| i.id == inbound_id)
            .ok_or(Error::Scope)?;
        if inbound.security_mode != SecurityMode::SmartReality {
            return Err(Error::Format);
        }
        let binding = inbound.reality.as_ref().ok_or(Error::Format)?;
        let listen: SocketAddr = inbound.h2_listen.parse().map_err(|_| Error::Scope)?;
        let scope = Scope {
            inbound: inbound.id.clone(),
            endpoint: format!("{}:{}", inbound.server_name, listen.port()),
        };
        let directory = Path::new(&binding.bundle);
        let store = Store::new(Path::new(&binding.health_store)).map_err(|_| Error::Health)?;
        let publication =
            crate::identity_publication::Publication::new(&directory.join("publication.toml"))?;
        let snapshot = |time: u64| -> Result<(State, crate::descriptor::Verified, Stamp), Error> {
            let health = store.inspect().map_err(|_| Error::Health)?;
            let (value, stamp) = crate::reality_provision::inspect_registered_snapshot(
                directory, binding, &health, &scope, time,
            )?;
            reality_checkpoint::accept(directory, stamp, time)?;
            Ok((health, value, stamp))
        };
        let (mut health, mut value, mut stamp) = snapshot(now)?;
        let approved = health.plan().digest().map_err(|_| Error::Health)?;
        let mut time = now;
        if now
            >= health
                .next_active_check_at(value.descriptor(), now)
                .map_err(|_| Error::Health)?
        {
            store
                .recheck(health.revision(), approved)
                .await
                .map_err(|_| Error::Health)?;
            time = crate::reference_health::unix_now().map_err(|_| Error::Clock)?;
            (health, value, stamp) = snapshot(time)?;
        }
        let status = publication.inspect(time)?;
        if status.snapshot_sha256 != stamp.publication || status.plan_sha256 != approved {
            return Err(Error::Approval);
        }
        if status.valid_now
            && health
                .active_status(value.descriptor(), time)
                .map_err(|_| Error::Health)?
                .0
                == crate::reference_health::PrimaryStatus::Degraded
        {
            let preview = publication.preview_failover(&health, time)?;
            if preview.publication_sha256 != stamp.publication
                || preview.health_sha256 != stamp.health
                || snapshot(time)?.2 != stamp
            {
                return Err(Error::Approval);
            }
            publication.apply_failover(
                &health,
                crate::identity_publication::FailoverApproval {
                    publication_sha256: stamp.publication,
                    health_sha256: stamp.health,
                    selected_reference: preview.selected_reference,
                },
                time,
            )?;
        }
        Self::new(config, inbound_id, time)
    }

    /// Independently root both files even while the active reference is
    /// degraded. Advance the durable floor before further probes or writes:
    /// a failed capture must not make stale healthy evidence acceptable.
    fn maintenance_snapshot(
        &self,
        now: u64,
    ) -> Result<(State, crate::descriptor::Verified, Stamp), Error> {
        let binding = self.inbound.reality.as_ref().ok_or(Error::Format)?;
        let health = Store::new(Path::new(&binding.health_store))
            .map_err(|_| Error::Health)?
            .inspect()
            .map_err(|_| Error::Health)?;
        let (value, stamp) = crate::reality_provision::inspect_registered_snapshot(
            Path::new(&binding.bundle),
            binding,
            &health,
            &self.scope,
            now,
        )?;
        reality_checkpoint::accept(Path::new(&binding.bundle), stamp, now)?;
        Ok((health, value, stamp))
    }

    /// One owner-scoped maintenance cycle. Only the immutable enrolled plan
    /// may be probed. The publication has its own exact-byte CAS, and the
    /// health digest is re-read immediately before each publication change.
    /// A changed/expired trust chain is never replaced with an unrooted one.
    pub(crate) async fn maintain(&self, live: &crate::reality_live::Live) -> Result<Lease, Error> {
        use crate::{
            identity_publication::{FailoverApproval, Publication},
            reference_health::{self, PrimaryStatus},
        };
        let binding = self.inbound.reality.as_ref().ok_or(Error::Format)?;
        let store = Store::new(Path::new(&binding.health_store)).map_err(|_| Error::Health)?;
        let publication = Publication::new(&Path::new(&binding.bundle).join("publication.toml"))?;
        let mut now = reference_health::unix_now().map_err(|_| Error::Clock)?;
        let (mut health, mut value, mut stamp) = self.maintenance_snapshot(now)?;
        let approved = health.plan().digest().map_err(|_| Error::Health)?;
        let due = health
            .next_active_check_at(value.descriptor(), now)
            .map_err(|_| Error::Health)?;
        let status = publication.inspect(now)?;
        if status.snapshot_sha256 != stamp.publication || status.plan_sha256 != approved {
            return Err(Error::Approval);
        }
        let expiry_due = status.valid_now
            && (status.next_fingerprint.is_none()
                || status.overlap_ends_at.is_some_and(|end| now >= end))
            && status.not_after.saturating_sub(now) <= 24 * 60 * 60;
        let (active, _) = health
            .active_status(value.descriptor(), now)
            .map_err(|_| Error::Health)?;
        // A suspect/unavailable reference stops new admissions; previously
        // accepted connections and relay sockets retain their own leases.
        if active != PrimaryStatus::Healthy {
            live.suspend();
        }
        let fresh = now.saturating_sub(health.last_checked_at()) <= 60;
        if now >= due || (expiry_due && !fresh) {
            store
                .recheck(health.revision(), approved)
                .await
                .map_err(|_| Error::Health)?;
            now = reference_health::unix_now().map_err(|_| Error::Clock)?;
            (health, value, stamp) = self.maintenance_snapshot(now)?;
        }
        let (active, reserve) = health
            .active_status(value.descriptor(), now)
            .map_err(|_| Error::Health)?;
        if active != PrimaryStatus::Healthy {
            live.suspend();
        }
        let status = publication.inspect(now)?;
        if status.snapshot_sha256 != stamp.publication || status.plan_sha256 != approved {
            return Err(Error::Approval);
        }
        let fresh = now.saturating_sub(health.last_checked_at()) <= 60;
        if active == PrimaryStatus::Degraded && reserve.is_some() && fresh && status.valid_now {
            // Existing clients can bootstrap using any signed reference
            // alias at the same pinned endpoint, but only after admission
            // and independent identity verification. No relay alias.
            if let Ok(preview) = publication.preview_failover(&health, now) {
                if preview.publication_sha256 != stamp.publication
                    || preview.health_sha256 != stamp.health
                    || Some(usize::from(preview.selected_reference)) != reserve
                {
                    return Err(Error::Approval);
                }
                let (_, _, exact) = self.maintenance_snapshot(now)?;
                if exact != stamp {
                    return Err(Error::Approval);
                }
                publication.apply_failover(
                    &health,
                    FailoverApproval {
                        publication_sha256: preview.publication_sha256,
                        health_sha256: preview.health_sha256,
                        selected_reference: preview.selected_reference,
                    },
                    now,
                )?;
                crate::diag!(Info, "server.reality", "approved_reference_switched");
            }
        } else if active == PrimaryStatus::Healthy
            && fresh
            && status.valid_now
            && (status.next_fingerprint.is_none()
                || status.overlap_ends_at.is_some_and(|end| now >= end))
            && status.not_after.saturating_sub(now) <= 24 * 60 * 60
        {
            let (_, _, exact) = self.maintenance_snapshot(now)?;
            if exact != stamp {
                return Err(Error::Approval);
            }
            publication.refresh(&health, stamp.publication, now)?;
        }
        self.refresh(reference_health::unix_now().map_err(|_| Error::Clock)?)
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn root_fingerprint(&self) -> [u8; 32] {
        self.inbound
            .reality
            .as_ref()
            .expect("registered manager")
            .identity_sha256
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn check_replacement(&self, next: &Lease, root: [u8; 32]) -> Result<(), Error> {
        let slot = self.slot.lock().map_err(|_| Error::Storage)?;
        let old = &slot.last;
        let p = next.publication();
        let value = p.active().verified();
        if p.generation() != 1
            || p.next().is_some()
            || value.descriptor().revision != 1
            || value.descriptor().scope != self.scope
            || crate::reality_bootstrap::fingerprint(value.signer()) != root
            || root == self.root_fingerprint()
            || old.admission.commitment() == next.admission().commitment()
            || old.publication.active().verified().signer() == value.signer()
            || old
                .publication
                .next()
                .is_some_and(|m| m.verified().signer() == value.signer())
        {
            return Err(Error::Approval);
        }
        Ok(())
    }

    /// Serialize candidate changes, revalidate private materials on each
    /// refresh, and refuse stale, equivocated or unhealthy generations.
    /// Never hand out the prior candidate on failure. The lock is intended
    /// for a local maintenance worker, not an async network event loop.
    pub fn refresh(&self, now: u64) -> Result<Lease, Error> {
        let mut slot = self.slot.lock().map_err(|_| Error::Storage)?;
        if now < slot.last_checked_at {
            return Err(Error::Clock);
        }
        // A failed refresh must not make an earlier clock acceptable again.
        slot.last_checked_at = now;
        let candidate = Generation::load(&self.inbound, &self.scope, now)?;
        slot.last.compare(&candidate)?;
        let binding = self.inbound.reality.as_ref().ok_or(Error::Format)?;
        reality_checkpoint::accept(
            Path::new(&binding.bundle),
            candidate.stamp(&self.inbound)?,
            now,
        )?;
        if candidate.publication.snapshot_sha256() != slot.last.publication.snapshot_sha256()
            || candidate.health_digest != slot.last.health_digest
        {
            slot.last = Arc::new(candidate);
        }
        Ok(Lease(Arc::clone(&slot.last), now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config,
        reality_config::{self, Request, ServerRequest},
        reference_health::{Evidence, Plan, Target},
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "theia-generation-{}-{}",
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

    #[tokio::test]
    async fn startup_recovery_switches_only_to_fresh_approved_reserve_and_keeps_floor() {
        let dir = Scratch::new();
        let now = crate::reference_health::unix_now().unwrap();
        let initial = now - 3700;
        let good = Evidence {
            h2_status: Some(200),
            h3_status: Some(200),
        };
        let state = State::new(
            Plan {
                schema_version: 1,
                inbound: "edge".into(),
                endpoint: "edge.example.org:9443".into(),
                own_ips: vec!["93.184.216.1".parse().unwrap()],
                references: vec![
                    Target {
                        server_name: "ref.example.org".into(),
                        address: "93.184.216.2:443".parse().unwrap(),
                    },
                    Target {
                        server_name: "reserve.example.org".into(),
                        address: "93.184.216.3:443".parse().unwrap(),
                    },
                ],
            },
            vec![good.clone(), good.clone()],
            initial,
        )
        .unwrap();
        let health = dir.0.join("health");
        let store = Store::new(&health).unwrap();
        store.enroll(&state).unwrap();
        let old = std::fs::read(&health).unwrap();
        let bundle = dir.0.join("bundle");
        let digest = state.snapshot_sha256().unwrap();
        let record = crate::reality_provision::create(&state, digest, &bundle, initial).unwrap();
        let cfg = dir.0.join("server.toml");
        std::fs::write(
            &cfg,
            include_str!("../../../examples/server.toml")
                .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64)),
        )
        .unwrap();
        let request = Request::Server(ServerRequest {
            health: health.clone(),
            bundle: bundle.clone(),
            health_sha256: digest,
            identity_sha256: record.identity_sha256,
            listen: "127.0.0.1:9443".parse().unwrap(),
            grants: vec!["device-a".into()],
        });
        let preview = reality_config::prepare(&cfg, &request, initial).unwrap();
        reality_config::apply(&cfg, &request, preview.approval_sha256(), initial).unwrap();
        let doc = config::read_file(&cfg).unwrap();
        store
            .fixture_record(vec![Evidence::default(), good.clone()], now - 301)
            .unwrap();
        store
            .fixture_record(vec![Evidence::default(), good], now - 1)
            .unwrap();
        assert!(Manager::new(&doc, "edge", now).is_err());
        let manager = Manager::new_live(&doc, "edge", now).await.unwrap();
        let lease = manager.refresh(now).unwrap();
        assert_eq!(lease.status().active_reference, 1);
        assert_eq!(lease.status().revision, 2);
        assert_eq!(lease.status().health_revision, 3);
        // A stale healthy snapshot cannot resurrect the old primary.
        std::fs::write(&health, old).unwrap();
        assert!(Manager::new(&doc, "edge", now).is_err());
    }

    #[test]
    fn generation_rejects_rollback_and_retains_existing_lease() {
        let dir = Scratch::new();
        let now = 1000;
        let state = State::new(
            Plan {
                schema_version: 1,
                inbound: "edge".into(),
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
            now,
        )
        .unwrap();
        let health = dir.0.join("health");
        Store::new(&health).unwrap().enroll(&state).unwrap();
        let bundle = dir.0.join("bundle");
        let digest = state.snapshot_sha256().unwrap();
        let record = crate::reality_provision::create(&state, digest, &bundle, now).unwrap();
        let cfg = dir.0.join("server.toml");
        std::fs::write(
            &cfg,
            include_str!("../../../examples/server.toml")
                .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64)),
        )
        .unwrap();
        let request = Request::Server(ServerRequest {
            health,
            bundle: bundle.clone(),
            health_sha256: digest,
            identity_sha256: record.identity_sha256,
            listen: "127.0.0.1:9443".parse().unwrap(),
            grants: vec!["device-a".into()],
        });
        let preview = reality_config::prepare(&cfg, &request, now).unwrap();
        reality_config::apply(&cfg, &request, preview.approval_sha256(), now).unwrap();
        let doc = config::read_file(&cfg).unwrap();
        let Config::Server(server) = &doc else {
            panic!("server fixture")
        };
        let inbound = server
            .server
            .inbounds
            .iter()
            .find(|i| i.id == "edge")
            .unwrap();
        let captured = Candidate::capture(inbound, now).unwrap();
        let (_, lease) = captured.activate(inbound, now).unwrap();
        assert_eq!(lease.status().revision, 1);
        let manager = Manager::new(&doc, "edge", now).unwrap();
        let old = manager.refresh(now).unwrap();
        let path = bundle.join("publication.toml");
        let original = std::fs::read(&path).unwrap();
        let publication = crate::identity_publication::Publication::new(&path).unwrap();
        let status = publication.inspect(now).unwrap();
        publication
            .refresh(&state, status.snapshot_sha256, now + 1)
            .unwrap();
        assert!(captured.activate(inbound, now + 1).is_err());
        let new = manager.refresh(now + 1).unwrap();
        assert_eq!(old.status().revision, 1);
        assert_eq!(new.status().revision, 2);
        assert!(matches!(manager.refresh(now), Err(Error::Clock)));
        let updated = std::fs::read(&path).unwrap();
        std::fs::write(&path, original).unwrap();
        assert!(matches!(manager.refresh(now + 2), Err(Error::Approval)));
        // The generation floor is independent of the mutable publication;
        // even a completely new manager must reject this older snapshot.
        assert!(matches!(
            Manager::new(&doc, "edge", now + 2),
            Err(Error::Approval)
        ));
        std::fs::write(&path, updated).unwrap();
        assert_eq!(manager.refresh(now + 2).unwrap().status().revision, 2);
        let reopened = Manager::new(&doc, "edge", now + 2).unwrap();
        assert_eq!(reopened.refresh(now + 2).unwrap().status().revision, 2);
        let floor = bundle.join("generation-floor.toml");
        let floor_raw = std::fs::read(&floor).unwrap();
        std::fs::remove_file(&floor).unwrap();
        assert!(matches!(
            Manager::new(&doc, "edge", now + 2),
            Err(Error::Storage)
        ));
        assert!(matches!(manager.refresh(now + 2), Err(Error::Storage)));
        crate::reality_bootstrap::create_text(&floor, std::str::from_utf8(&floor_raw).unwrap())
            .unwrap();
        let secret = bundle.join("admission.key");
        std::fs::remove_file(&secret).unwrap();
        assert!(matches!(manager.refresh(now + 3), Err(Error::Credential)));
        assert_eq!(old.status().revision, 1);
    }
}
