//! Bounded maintenance for a separately approved reference inventory and
//! local signed publication. Does not activate listeners or change grants.
//! Compatible expiry renewal only; switching reference/identity remains
//! a separate guarded operation until a live recovery path is available.
#![forbid(unsafe_code)]

use crate::{
    identity_publication::{Publication, Status},
    reality_bootstrap,
    reference_health::{self as health, Error, PrimaryStatus, State, Store},
};
use std::time::Duration;

const RENEW_BEFORE: u64 = 24 * 60 * 60;
const FRESH_SECONDS: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Wait,
    Check,
    Renew,
    RecoveryRequired,
    RotationPending,
    ReferenceDegraded,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Observation {
    pub health_revision: u64,
    pub descriptor_revision: u64,
    pub active_reference: u8,
    pub active_status: PrimaryStatus,
    pub reserve_candidate: Option<usize>,
    pub next_check_at: u64,
    pub not_after: u64,
    pub action: Action,
    publication_sha256: [u8; 32],
    health_sha256: [u8; 32],
}

impl Observation {
    pub fn report(&self) -> String {
        format!("Publication maintenance; runtime UNCHANGED\nhealth_revision={}\ndescriptor_revision={}\nactive_reference={}\nactive_status={:?}\nreserve_candidate={}\nnext_check_at={}\nnot_after={}\naction={:?}",
            self.health_revision, self.descriptor_revision, self.active_reference,
            self.active_status, self.reserve_candidate.map_or("none".into(), |n| n.to_string()),
            self.next_check_at, self.not_after, self.action)
    }
}

fn publication_error(error: reality_bootstrap::Error) -> Error {
    match error {
        reality_bootstrap::Error::Approval => Error::Approval,
        reality_bootstrap::Error::Clock => Error::Clock,
        reality_bootstrap::Error::Indeterminate => Error::Indeterminate,
        reality_bootstrap::Error::Storage => Error::Storage,
        _ => Error::NotEligible,
    }
}

fn observe(
    state: &State,
    publication: &Publication,
    approved: [u8; 32],
    now: u64,
) -> Result<Observation, Error> {
    let status = publication.inspect(now).map_err(publication_error)?;
    if state.plan().digest()? != approved || status.plan_sha256 != approved {
        return Err(Error::Approval);
    }
    let verified = publication
        .inspect_descriptor(status.snapshot_sha256, now)
        .map_err(publication_error)?;
    let (active_status, reserve_candidate) = state.active_status(verified.descriptor(), now)?;
    let next_check_at = state.next_active_check_at(verified.descriptor(), now)?;
    let fresh = now
        .checked_sub(state.last_checked_at())
        .ok_or(Error::Clock)?
        <= FRESH_SECONDS;
    let action = decide(&status, active_status, next_check_at, fresh, now);
    Ok(Observation {
        health_revision: state.revision(),
        descriptor_revision: status.revision,
        active_reference: status.active_reference,
        active_status,
        reserve_candidate,
        next_check_at,
        not_after: status.not_after,
        action,
        publication_sha256: status.snapshot_sha256,
        health_sha256: state.snapshot_sha256()?,
    })
}

fn decide(
    status: &Status,
    active_status: PrimaryStatus,
    due: u64,
    fresh: bool,
    now: u64,
) -> Action {
    // Health observations may continue even if the publication expired
    // or is rotating. Never renew an expired trust chain automatically.
    if now >= due {
        return Action::Check;
    }
    if !status.valid_now {
        return Action::RecoveryRequired;
    }
    if status.next_fingerprint.is_some() {
        return Action::RotationPending;
    }
    if active_status != PrimaryStatus::Healthy {
        return Action::ReferenceDegraded;
    }
    if status.not_after.saturating_sub(now) <= RENEW_BEFORE && fresh {
        return Action::Renew;
    }
    Action::Wait
}

pub fn inspect(
    store: &Store,
    publication: &Publication,
    approved: [u8; 32],
    now: u64,
) -> Result<Observation, Error> {
    observe(&store.inspect()?, publication, approved, now)
}

/// A new health snapshot and publication are re-read for the renewal.
/// This preserves the current identity, reference, routes and transport
/// modes. Exact publication CAS protects against concurrent edits.
fn renew(
    store: &Store,
    publication: &Publication,
    approved: [u8; 32],
    expected: &Observation,
    now: u64,
) -> Result<(), Error> {
    let state = store.inspect()?;
    let current = observe(&state, publication, approved, now)?;
    if current.action != Action::Renew
        || current.health_sha256 != expected.health_sha256
        || current.publication_sha256 != expected.publication_sha256
    {
        return Err(Error::Conflict);
    }
    publication
        .refresh(&state, current.publication_sha256, now)
        .map_err(publication_error)
}

/// Foreground operator service, Ctrl+C cancels outstanding probes. A CAS,
/// DNS safety or storage error exits rather than silently retrying writes.
pub async fn monitor(
    store: &Store,
    publication: &Publication,
    approved: [u8; 32],
) -> Result<String, Error> {
    let work = async {
        let mut previous = None;
        loop {
            let now = health::unix_now()?;
            let observation = inspect(store, publication, approved, now)?;
            if previous.as_ref() != Some(&observation) {
                println!("{}", observation.report());
            }
            match observation.action {
                Action::Check => {
                    store.recheck(observation.health_revision, approved).await?;
                }
                Action::Renew => {
                    renew(
                        store,
                        publication,
                        approved,
                        &observation,
                        health::unix_now()?,
                    )?;
                }
                _ => {
                    tokio::time::sleep(Duration::from_secs(
                        observation.next_check_at.saturating_sub(now).clamp(1, 60),
                    ))
                    .await;
                }
            }
            previous = Some(observation);
        }
    };
    tokio::select! {
        biased;
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|_| Error::Storage)?;
            Ok("Publication monitor stopped; runtime UNCHANGED".into())
        }
        result = work => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        descriptor::Scope,
        identity_tls::Identity,
        reference_health::{Evidence, Plan, Target},
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "theia-maintenance-{}-{}",
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

    #[test]
    fn same_reference_renewal_preserves_signed_operational_parameters_and_refuses_stale_cas() {
        let dir = Scratch::new();
        let start = 1000;
        let plan = Plan {
            schema_version: 1,
            inbound: "edge".into(),
            endpoint: "edge.example.org:443".into(),
            own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: vec![Target {
                server_name: "reference.example.org".into(),
                address: "93.184.216.2:443".parse().unwrap(),
            }],
        };
        let good = Evidence {
            h2_status: Some(200),
            h3_status: Some(200),
        };
        let state = State::new(plan, vec![good], start).unwrap();
        let approved = state.plan().digest().unwrap();
        let key = Identity::generate(Scope {
            inbound: state.plan().inbound.clone(),
            endpoint: state.plan().endpoint.clone(),
        })
        .unwrap();
        let key_path = dir.0.join("key");
        key.save_new(&key_path).unwrap();
        let publication = Publication::new(&dir.0.join("publication")).unwrap();
        publication.initialize(&state, &key_path, start).unwrap();
        let status = publication.inspect(start).unwrap();
        let before = publication
            .inspect_descriptor(status.snapshot_sha256, start)
            .unwrap();
        assert_eq!(
            observe(&state, &publication, approved, start)
                .unwrap()
                .action,
            Action::Wait
        );
        assert!(matches!(
            observe(&state, &publication, [0; 32], start),
            Err(Error::Approval)
        ));
        let now = status.not_after - RENEW_BEFORE + 1;
        // A new independent health measurement is required at renewal time.
        assert_eq!(
            observe(&state, &publication, approved, now).unwrap().action,
            Action::Check
        );
        let state_path = dir.0.join("health");
        let store = Store::new(&state_path).unwrap();
        let fresh = State::new(state.plan().clone(), vec![good], now).unwrap();
        store.enroll(&fresh).unwrap();
        let observation = inspect(&store, &publication, approved, now).unwrap();
        assert_eq!(observation.action, Action::Renew);
        renew(&store, &publication, approved, &observation, now).unwrap();
        assert_eq!(
            renew(&store, &publication, approved, &observation, now),
            Err(Error::Conflict)
        );
        let after_status = publication.inspect(now).unwrap();
        let after = publication
            .inspect_descriptor(after_status.snapshot_sha256, now)
            .unwrap();
        let a = before.descriptor();
        let b = after.descriptor();
        assert_eq!(b.revision, a.revision + 1);
        assert_eq!(before.signer(), after.signer());
        assert_eq!(a.active_reference, b.active_reference);
        assert_eq!(a.path_prefix, b.path_prefix);
        assert!(a.references == b.references && a.padding == b.padding && a.rotation == b.rotation);
        assert_eq!(a.h3, b.h3);
        assert_eq!(
            inspect(&store, &publication, approved, now).unwrap().action,
            Action::Wait
        );
        let lost = fresh.record(vec![Evidence::default()], now + 1).unwrap();
        assert_eq!(
            observe(&lost, &publication, approved, now + 1)
                .unwrap()
                .action,
            Action::ReferenceDegraded
        );
        assert_eq!(
            observe(&lost, &publication, approved, now + 301)
                .unwrap()
                .action,
            Action::Check
        );
    }

    #[test]
    fn expired_or_rotating_publication_is_never_renewed_implicitly() {
        let mut status = Status {
            generation: 1,
            plan_sha256: [1; 32],
            snapshot_sha256: [2; 32],
            revision: 1,
            active_reference: 0,
            active_fingerprint: [3; 32],
            valid_now: false,
            not_after: 100,
            next_fingerprint: None,
            overlap_ends_at: None,
        };
        assert_eq!(
            decide(&status, PrimaryStatus::Healthy, 200, true, 100),
            Action::RecoveryRequired
        );
        status.valid_now = true;
        status.next_fingerprint = Some([4; 32]);
        assert_eq!(
            decide(&status, PrimaryStatus::Healthy, 200, true, 100),
            Action::RotationPending
        );
        status.next_fingerprint = None;
        status.not_after = 101;
        assert_eq!(
            decide(&status, PrimaryStatus::Healthy, 200, false, 100),
            Action::Wait
        );
        assert_eq!(
            decide(&status, PrimaryStatus::Unavailable, 200, true, 100),
            Action::ReferenceDegraded
        );
    }
}
