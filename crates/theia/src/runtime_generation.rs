//! M4.2h: guarded swap of ONE live runtime view.
//!
//! The management endpoint stays owned by the same process and protected by
//! the same Unix permissions / Windows SID DACL across listener generations.
//! A short read/write lock is ONLY held during in-memory CAS publication;
//! disk, PEM, network and the async supervisor are never run under this lock.
use crate::{
    config::ServerDocument,
    live_auth::{LiveAuthError, LiveAuthorization, StagedAuthorization},
    reload_preflight::ReloadPreflight,
};
use std::{
    sync::{Arc, RwLock},
    time::Instant,
};
use tokio::sync::oneshot;

pub(crate) struct View {
    pub(crate) document: Arc<ServerDocument>,
    pub(crate) inbounds: usize,
    pub(crate) preflight: Arc<ReloadPreflight>,
    pub(crate) live: Arc<LiveAuthorization>,
}

pub(crate) type RealityMap =
    std::collections::HashMap<String, ([u8; 32], Arc<crate::reality_live::Live>)>;

pub(crate) struct State {
    current: RwLock<Arc<View>>,
    // Only advisory metadata crosses IPC; the actual previous TLS private
    // configs live exclusively in the single supervisor, never in replies.
    rollback_until: RwLock<Option<Instant>>,
    restart_rollback: RwLock<Option<(u64, Instant, Instant)>>,
    auth_rollback: RwLock<Option<AuthRollback>>,
    reality: RwLock<RealityMap>,
    reality_ledger: Option<Arc<crate::quota::Ledger>>,
}

struct AuthRollback {
    document: Arc<ServerDocument>,
    revision: u64,
    until: Instant,
}

impl State {
    pub(crate) fn new(initial: View) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
            rollback_until: RwLock::new(None),
            restart_rollback: RwLock::new(None),
            auth_rollback: RwLock::new(None),
            reality: RwLock::new(RealityMap::new()),
            reality_ledger: None,
        }
    }

    pub(crate) fn with_reality(mut self, entries: RealityMap) -> Self {
        self.reality = RwLock::new(entries);
        self
    }
    pub(crate) fn with_reality_ledger(mut self, ledger: Arc<crate::quota::Ledger>) -> Self {
        self.reality_ledger = Some(ledger);
        self
    }
    pub(crate) fn has_reality_ledger(&self) -> bool {
        self.reality_ledger.is_some()
    }
    pub(crate) fn apply_reality_quota(
        &self,
        previous: &Arc<View>,
        expected: u64,
        candidate: &ServerDocument,
    ) -> Result<u64, LiveAuthError> {
        let ledger = self
            .reality_ledger
            .as_ref()
            .ok_or(LiveAuthError::Unavailable)?;
        if !crate::restart_guard::quota_only(previous.document.as_ref(), candidate) {
            return Err(LiveAuthError::RequiresRestart);
        }
        let (live, stage) = previous.live.prepare_tls_rebase(candidate, expected)?;
        let next = View {
            document: Arc::new(candidate.clone()),
            inbounds: previous.inbounds,
            preflight: Arc::new(previous.preflight.rebased(candidate.clone())),
            live: Arc::new(live),
        };
        self.commit_quota(previous, expected, next, stage, ledger)
    }
    pub(crate) fn reality_status(
        &self,
        id: &str,
        manifest: [u8; 32],
    ) -> Option<Option<crate::reality_generation::Status>> {
        let (view, live) = {
            let view = self.current.read().ok()?.clone();
            let map = self.reality.read().ok()?;
            let (expected, live) = map.get(id)?;
            if *expected != manifest {
                return None;
            }
            (view, live.clone())
        };
        // Never hold the runtime lock while reading the route table:
        // same-port Apply acquires these locks in the opposite order.
        let status = live.status();
        let current = self.current.read().ok()?;
        if !Arc::ptr_eq(&current, &view) {
            return None;
        }
        Some(status)
    }

    /// Advisory rollback readiness. Never returns certificates, keys or
    /// fingerprints; a fresh CAS recheck is mandatory on Apply.
    pub(crate) fn rollback_status(&self) -> Option<(u64, u64)> {
        let view = self.current.read().ok()?;
        let until = (*self.rollback_until.read().ok()?)?;
        let remaining = until.checked_duration_since(Instant::now())?;
        let revision = view.live.revision().ok()?;
        Some((revision, remaining.as_secs().saturating_add(1)))
    }

    pub(crate) fn set_restart_rollback(&self, slot: Option<(u64, Instant, Instant)>) {
        if let Ok(mut guard) = self.restart_rollback.write() {
            *guard = slot;
        }
    }
    pub(crate) fn restart_rollback_status(&self) -> Option<(u64, u64)> {
        let view = self.current.read().ok()?;
        let revision = view.live.revision().ok()?;
        let mut slot = self.restart_rollback.write().ok()?;
        let (expected, ready, until) = (*slot)?;
        let now = Instant::now();
        if expected != revision || now >= until {
            *slot = None;
            return None;
        }
        if now < ready {
            return None;
        }
        Some((
            revision,
            until
                .saturating_duration_since(now)
                .as_secs()
                .saturating_add(1)
                .min(300),
        ))
    }
    pub(crate) fn set_rollback_until(&self, deadline: Option<Instant>) {
        if let Ok(mut slot) = self.rollback_until.write() {
            *slot = deadline;
        }
    }

    pub(crate) fn snapshot(&self) -> Result<Arc<View>, LiveAuthError> {
        self.current
            .read()
            .map(|guard| Arc::clone(&guard))
            .map_err(|_| LiveAuthError::Unavailable)
    }

    pub(crate) fn still_current(&self, view: &Arc<View>, revision: u64) -> bool {
        let Ok(guard) = self.current.read() else {
            return false;
        };
        Arc::ptr_eq(&guard, view) && view.live.revision() == Ok(revision)
    }

    /// No stale in-flight IPC Apply can publish into an old generation and
    /// receive a false success response after a listener cutover.
    pub(crate) fn apply_auth(
        &self,
        view: &Arc<View>,
        candidate: &ServerDocument,
        expected: u64,
    ) -> Result<u64, LiveAuthError> {
        let mut guard = self
            .current
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        if !Arc::ptr_eq(&guard, view) {
            return Err(LiveAuthError::StaleRevision);
        }
        let mut rollback = self
            .auth_rollback
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        let revision = self.publish_managed_auth(view, candidate, expected)?;
        *rollback = if view
            .document
            .server
            .inbounds
            .iter()
            .any(|i| i.reality.is_some())
        {
            Some(AuthRollback {
                document: view.document.clone(),
                revision,
                until: Instant::now() + std::time::Duration::from_secs(300),
            })
        } else {
            None
        };
        // The running TLS sockets, quotas and AuthCell remain the same.
        // Rebase the management snapshot so a later TLS-only rotation
        // compares against the MOST RECENT auth state, not startup TOML.
        *guard = Arc::new(View {
            document: Arc::new(candidate.clone()),
            inbounds: view.inbounds,
            preflight: Arc::new(view.preflight.rebased(candidate.clone())),
            live: Arc::new(view.live.with_new_baseline(candidate.clone())),
        });
        Ok(revision)
    }

    // Caller owns the runtime writer lock. No live auth or quota change
    // occurs until the entire candidate and occupancy transition are staged.
    fn publish_managed_auth(
        &self,
        view: &Arc<View>,
        candidate: &ServerDocument,
        expected: u64,
    ) -> Result<u64, LiveAuthError> {
        if let Some(ledger) = &self.reality_ledger {
            crate::reload_preflight::assess_managed_reload(&view.document, candidate)
                .map_err(|_| LiveAuthError::RequiresRestart)?;
            let (_, stage) = view.live.prepare_tls_rebase(candidate, expected)?;
            let roster = ledger
                .prepare_roster(&candidate.server.users)
                .map_err(|_| LiveAuthError::Unavailable)?;
            let revision = view.live.publish(stage)?;
            roster.commit();
            Ok(revision)
        } else {
            view.live
                .stage(candidate, expected)
                .and_then(|stage| view.live.publish(stage))
        }
    }

    pub(crate) fn auth_rollback_status(&self) -> Option<(u64, u64)> {
        let current = self.current.read().ok()?;
        let mut slot = self.auth_rollback.write().ok()?;
        let revision = current.live.revision().ok()?;
        let remaining = slot.as_ref().and_then(|item| {
            (item.revision == revision)
                .then(|| item.until.checked_duration_since(Instant::now()))
                .flatten()
        });
        if let Some(remaining) = remaining {
            Some((revision, remaining.as_secs().saturating_add(1).min(300)))
        } else {
            *slot = None;
            None
        }
    }

    /// Clone only the previous authorization document, not TLS or trust
    /// snapshots. Revalidation runs outside the commit locks.
    pub(crate) fn auth_rollback_candidate(
        &self,
        view: &Arc<View>,
        expected: u64,
    ) -> Option<Arc<ServerDocument>> {
        let current = self.current.read().ok()?;
        if !Arc::ptr_eq(&current, view) || view.live.revision() != Ok(expected) {
            return None;
        }
        let slot = self.auth_rollback.read().ok()?;
        let item = slot.as_ref()?;
        if item.revision != expected || item.until <= Instant::now() {
            return None;
        }
        Some(item.document.clone())
    }

    /// One-shot rollback is a NEW auth revision. Never restore a previous
    /// publication, health, admission key or quota. Saved TOML is untouched.
    pub(crate) fn rollback_auth(
        &self,
        view: &Arc<View>,
        candidate: &Arc<ServerDocument>,
        expected: u64,
    ) -> Result<u64, LiveAuthError> {
        let mut current = self
            .current
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        if !Arc::ptr_eq(&current, view) || view.live.revision() != Ok(expected) {
            return Err(LiveAuthError::StaleRevision);
        }
        let mut slot = self
            .auth_rollback
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        let Some(item) = slot.as_ref() else {
            return Err(LiveAuthError::StaleRevision);
        };
        if item.revision != expected
            || item.until <= Instant::now()
            || !Arc::ptr_eq(&item.document, candidate)
        {
            return Err(LiveAuthError::StaleRevision);
        }
        let next = self.publish_managed_auth(view, candidate, expected)?;
        *current = Arc::new(View {
            document: candidate.clone(),
            inbounds: view.inbounds,
            preflight: Arc::new(view.preflight.rebased(candidate.as_ref().clone())),
            live: Arc::new(view.live.with_new_baseline(candidate.as_ref().clone())),
        });
        *slot = None;
        Ok(next)
    }

    /// Same-port identity rotation: one short writer CAS for the persisted
    /// management snapshot and a staged authorization revision. The caller
    /// has pre-built BOTH H2+H3 configs and already acquired all H2 locks,
    /// so the final transport swap itself is infallible and synchronous.
    ///
    /// Old tunnels keep their negotiated TLS and shared authorization cell.
    /// Rejected stale/foreign snapshots do not invoke the swap closure.
    pub(crate) fn commit_tls_rotation(
        &self,
        previous: &Arc<View>,
        expected: u64,
        next: View,
        authorization: StagedAuthorization,
        swap_new_tls: impl FnOnce(),
    ) -> Result<u64, LiveAuthError> {
        let mut guard = self
            .current
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        if !Arc::ptr_eq(&guard, previous) || previous.live.revision()? != expected {
            return Err(LiveAuthError::StaleRevision);
        }
        let next_revision = expected
            .checked_add(1)
            .ok_or(LiveAuthError::RevisionExhausted)?;
        let actual = previous.live.publish(authorization)?;
        if actual != next_revision {
            return Err(LiveAuthError::StaleRevision);
        }
        swap_new_tls();
        *guard = Arc::new(next);
        Ok(actual)
    }

    /// Same listener set, different independently enrolled REALITY root.
    /// The supervisor holds the route and previous admission gate locks.
    /// Only one changed manifest is installed; no old root rollback slot.
    pub(crate) fn commit_reality_replacement(
        &self,
        previous: &Arc<View>,
        expected: u64,
        next: View,
        authorization: StagedAuthorization,
        replacement: (&str, [u8; 32], [u8; 32]),
        swap: impl FnOnce(),
    ) -> Result<u64, LiveAuthError> {
        let mut guard = self
            .current
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        if !Arc::ptr_eq(&guard, previous) || previous.live.revision()? != expected {
            return Err(LiveAuthError::StaleRevision);
        }
        let mut reality = self
            .reality
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        let (id, old_manifest, new_manifest) = replacement;
        let entry = reality.get_mut(id).ok_or(LiveAuthError::Unavailable)?;
        if entry.0 != old_manifest || old_manifest == new_manifest {
            return Err(LiveAuthError::StaleRevision);
        }
        let mut rollback = self
            .auth_rollback
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        let revision = previous.live.publish(authorization)?;
        swap();
        entry.0 = new_manifest;
        *rollback = None;
        *guard = Arc::new(next);
        Ok(revision)
    }

    /// M4.2j: one guarded quota limit/revision publication. The shared
    /// ledger counts ALL held H2+H3 permits, including those created before
    /// cutover. A cap smaller than occupancy creates admission debt; no
    /// currently authenticated stream or transport is forcibly revoked.
    pub(crate) fn commit_quota(
        &self,
        previous: &Arc<View>,
        expected: u64,
        next: View,
        authorization: StagedAuthorization,
        ledger: &crate::quota::Ledger,
    ) -> Result<u64, LiveAuthError> {
        let mut guard = self
            .current
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        if !Arc::ptr_eq(&guard, previous) || previous.live.revision()? != expected {
            return Err(LiveAuthError::StaleRevision);
        }
        let expected_next = expected
            .checked_add(1)
            .ok_or(LiveAuthError::RevisionExhausted)?;
        let mut rollback = self
            .auth_rollback
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        let held = ledger
            .prepare_resize(&next.document.server.policy)
            .map_err(|_| LiveAuthError::Unavailable)?;
        // No fallible quota action after revision publication: held.commit
        // sets two small integers under the already acquired ledger lock.
        let revision = previous.live.publish(authorization)?;
        debug_assert_eq!(revision, expected_next);
        held.commit();
        *rollback = None;
        *guard = Arc::new(next);
        Ok(revision)
    }

    /// Partial listener edit: retained contexts keep the same AuthCell
    /// and ledger; removed grants disappear at the same revision. New
    /// listeners were fully bound before this method, but are not serving.
    pub(crate) fn commit_partial_layout(
        &self,
        previous: &Arc<View>,
        expected: u64,
        next: View,
        auth: StagedAuthorization,
        removed: &std::collections::HashSet<String>,
        added: RealityMap,
    ) -> Result<u64, LiveAuthError> {
        let mut current = self
            .current
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        if !Arc::ptr_eq(&current, previous) || previous.live.revision()? != expected {
            return Err(LiveAuthError::StaleRevision);
        }
        let mut reality = self
            .reality
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        if added.keys().any(|id| reality.contains_key(id)) {
            return Err(LiveAuthError::RequiresRestart);
        }
        let mut rollback = self
            .auth_rollback
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        let revision = previous.live.publish(auth)?;
        reality.retain(|id, (_, carrier)| {
            if removed.contains(id) {
                carrier.retire();
                false
            } else {
                true
            }
        });
        reality.extend(added);
        *rollback = None;
        *current = Arc::new(next);
        Ok(revision)
    }

    /// Linearization point for a prepared fresh-port listener generation.
    /// In-flight and future requests on the former generation are denied
    /// NEW admission before the protected IPC view points to the successor.
    #[cfg(test)]
    pub(crate) fn commit_restart(
        &self,
        previous: &Arc<View>,
        expected: u64,
        next: View,
    ) -> Result<(), LiveAuthError> {
        self.commit_restart_with_reality(previous, expected, next, RealityMap::new())
    }

    pub(crate) fn commit_restart_with_reality(
        &self,
        previous: &Arc<View>,
        expected: u64,
        next: View,
        reality: RealityMap,
    ) -> Result<(), LiveAuthError> {
        let mut guard = self
            .current
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        if !Arc::ptr_eq(&guard, previous) || previous.live.revision()? != expected {
            return Err(LiveAuthError::StaleRevision);
        }
        if next.live.revision()?
            != expected
                .checked_add(1)
                .ok_or(LiveAuthError::RevisionExhausted)?
        {
            return Err(LiveAuthError::StaleRevision);
        }
        let mut old_reality = self
            .reality
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        let mut rollback = self
            .auth_rollback
            .write()
            .map_err(|_| LiveAuthError::Unavailable)?;
        previous.live.close_new_admission()?;
        for (_, carrier) in old_reality.values() {
            carrier.retire();
        }
        *old_reality = reality;
        *rollback = None;
        *guard = Arc::new(next);
        Ok(())
    }
}

/// The request contains an owned, validated, content-bound document. No
/// restart work runs on a blocking IPC thread after that handler is cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChangeKind {
    Restart,
    Quota,
    Rollback,
    StructuralRollback,
}

pub(crate) struct RestartRequest {
    pub(crate) kind: ChangeKind,
    pub(crate) previous: Arc<View>,
    pub(crate) expected_revision: u64,
    pub(crate) candidate: ServerDocument,
    /// The one verified candidate PEM snapshot, required for any restart.
    /// Quota-only requests carry None and never touch TLS identities.
    pub(crate) material: Option<crate::server::CapturedTls>,
    pub(crate) complete: oneshot::Sender<Result<u64, ()>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_auth_rollback_is_single_use_and_monotonic() {
        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        let crate::config::Config::Server(mut doc) = crate::config::parse(&source).unwrap() else {
            panic!()
        };
        let inbound = &mut doc.server.inbounds[0];
        inbound.security_mode = crate::security_profile::SecurityMode::SmartReality;
        inbound.path_prefix = None;
        inbound.tls_cert.clear();
        inbound.tls_key.clear();
        let base = std::env::temp_dir();
        inbound.reality = Some(crate::config::RealityBinding {
            health_store: base.join("health").to_string_lossy().into_owned(),
            bundle: base.join("bundle").to_string_lossy().into_owned(),
            initial_health_sha256: [1; 32],
            identity_sha256: [2; 32],
            manifest_sha256: [3; 32],
        });
        let live = Arc::new(LiveAuthorization::new(doc.clone()).unwrap());
        let state = State::new(View {
            document: Arc::new(doc.clone()),
            inbounds: 1,
            preflight: Arc::new(ReloadPreflight::new(
                base.join("server.toml"),
                doc.clone(),
                Vec::new(),
            )),
            live,
        });
        let original = state.snapshot().unwrap();
        let mut updated = doc.clone();
        updated.server.users[0].disabled = true;
        assert_eq!(state.apply_auth(&original, &updated, 1), Ok(2));
        let current = state.snapshot().unwrap();
        assert_eq!(state.auth_rollback_status().unwrap().0, 2);
        assert!(state.auth_rollback_candidate(&current, 1).is_none());
        let previous = state.auth_rollback_candidate(&current, 2).unwrap();
        assert_eq!(state.rollback_auth(&current, &previous, 2), Ok(3));
        assert!(state.auth_rollback_status().is_none());
        assert_eq!(state.snapshot().unwrap().document.as_ref(), &doc);
        assert!(state.rollback_auth(&current, &previous, 2).is_err());
    }

    #[test]
    fn managed_roster_apply_rejects_stale_and_keeps_deleted_id_occupancy() {
        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        let crate::config::Config::Server(mut doc) = crate::config::parse(&source).unwrap() else {
            panic!()
        };
        doc.server.policy.max_connections_per_user = 1;
        let user = doc.server.users[0].clone();
        let mut other = user.clone();
        other.id = "new-device".into();
        other.token_sha256 = "b".repeat(64);
        doc.server.users.push(other.clone());
        doc.server.inbounds[0]
            .allowed_user_ids
            .push(other.id.clone());
        let ledger = crate::quota::Ledger::new(&doc.server.policy, &doc.server.users);
        let live = Arc::new(LiveAuthorization::new(doc.clone()).unwrap());
        let state = State::new(View {
            document: Arc::new(doc.clone()),
            inbounds: doc.server.inbounds.len(),
            preflight: Arc::new(ReloadPreflight::new(
                std::env::temp_dir().join("unused.toml"),
                doc.clone(),
                Vec::new(),
            )),
            live,
        })
        .with_reality_ledger(ledger.clone());
        let held = ledger.acquire_session(&user.id).unwrap();
        let original = state.snapshot().unwrap();
        let mut removed = doc.clone();
        removed.server.users.retain(|u| u.id != user.id);
        for inbound in &mut removed.server.inbounds {
            inbound.allowed_user_ids.retain(|id| id != &user.id);
        }
        assert_eq!(state.apply_auth(&original, &removed, 1), Ok(2));
        assert!(ledger.acquire_session(&user.id).is_none());
        assert!(state.apply_auth(&original, &doc, 1).is_err());
        let current = state.snapshot().unwrap();
        assert_eq!(state.apply_auth(&current, &doc, 2), Ok(3));
        assert!(ledger.acquire_session(&user.id).is_none());
        drop(held);
        assert!(ledger.acquire_session(&user.id).is_some());
        let mut invalid = doc.clone();
        invalid.server.inbounds[0].tls_cert = "file:replacement.pem".into();
        let current = state.snapshot().unwrap();
        assert!(state.apply_auth(&current, &invalid, 3).is_err());
        assert_eq!(state.snapshot().unwrap().live.revision(), Ok(3));
    }

    #[test]
    fn rollback_readiness_is_bounded_and_never_exposes_secret_material() {
        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        let crate::config::Config::Server(document) = crate::config::parse(&source).unwrap() else {
            panic!("server fixture");
        };
        let state = State::new(View {
            document: Arc::new(document.clone()),
            inbounds: document.server.inbounds.len(),
            preflight: Arc::new(ReloadPreflight::new(
                std::path::PathBuf::from("/nonexistent"),
                document.clone(),
                Vec::new(),
            )),
            live: Arc::new(LiveAuthorization::new(document).unwrap()),
        });
        assert!(state.rollback_status().is_none());
        state.set_rollback_until(Some(Instant::now() + std::time::Duration::from_secs(300)));
        let (revision, remaining) = state.rollback_status().unwrap();
        assert_eq!(revision, 1);
        assert!((1..=301).contains(&remaining));
        state.set_rollback_until(Some(Instant::now() - std::time::Duration::from_secs(1)));
        assert!(state.rollback_status().is_none());
        state.set_rollback_until(None);
        assert!(state.rollback_status().is_none());
    }

    #[test]
    fn auth_only_cas_updates_tls_rotation_baseline_and_rejects_old_generation() {
        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        let crate::config::Config::Server(active) = crate::config::parse(&source).unwrap() else {
            panic!("server config fixture must parse");
        };
        let live = Arc::new(LiveAuthorization::new(active.clone()).unwrap());
        let preflight = Arc::new(ReloadPreflight::new(
            std::path::PathBuf::from("/nonexistent"),
            active.clone(),
            Vec::new(),
        ));
        let state = State::new(View {
            document: Arc::new(active.clone()),
            inbounds: active.server.inbounds.len(),
            preflight,
            live,
        });
        let old = state.snapshot().unwrap();
        let mut updated = active.clone();
        updated.server.users[0].token_sha256 = "b".repeat(64);
        assert_eq!(state.apply_auth(&old, &updated, 1), Ok(2));
        let current = state.snapshot().unwrap();
        assert_eq!(current.live.revision(), Ok(2));
        assert_eq!(current.document.as_ref(), &updated);
        assert!(!Arc::ptr_eq(&old, &current));
        assert!(matches!(
            state.apply_auth(&old, &updated, 2),
            Err(LiveAuthError::StaleRevision)
        ));
        let mut next_identity = updated.clone();
        next_identity.server.inbounds[0].tls_cert = "file:rotated-cert.pem".to_owned();
        assert!(
            crate::restart_guard::same_port_tls_only(&current.document, &next_identity),
            "TLS rotation after auth CAS must compare the newest auth user state"
        );
    }

    #[test]
    fn restart_rejects_foreign_and_stale_snapshots_without_any_publication() {
        let raw = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        let crate::config::Config::Server(active) = crate::config::parse(&raw).unwrap() else {
            panic!("example server config must be valid");
        };
        let a = Arc::new(LiveAuthorization::new(active.clone()).unwrap());
        let b = Arc::new(LiveAuthorization::new(active.clone()).unwrap());
        let preflight = || {
            Arc::new(ReloadPreflight::new(
                std::path::PathBuf::from("/nonexistent"),
                active.clone(),
                Vec::new(),
            ))
        };
        let state = State::new(View {
            document: Arc::new(active.clone()),
            inbounds: 1,
            preflight: preflight(),
            live: a.clone(),
        });
        let before = state.snapshot().unwrap();
        let invalid = View {
            document: Arc::new(active.clone()),
            inbounds: 1,
            preflight: preflight(),
            live: b.clone(),
        };
        assert!(state.commit_restart(&before, 2, invalid).is_err());
        assert_eq!(state.snapshot().unwrap().live.revision(), Ok(1));
        let foreign = Arc::new(View {
            document: Arc::new(active.clone()),
            inbounds: 1,
            preflight: preflight(),
            live: a,
        });
        let invalid = View {
            document: Arc::new(active.clone()),
            inbounds: 1,
            preflight: preflight(),
            live: b,
        };
        assert!(state.commit_restart(&foreign, 1, invalid).is_err());
        assert!(Arc::ptr_eq(&state.snapshot().unwrap(), &before));
    }

    #[test]
    fn quota_tls_and_restart_commits_publish_one_monotonic_generation() {
        let raw = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        let crate::config::Config::Server(active) = crate::config::parse(&raw).unwrap() else {
            panic!("server fixture");
        };
        let make_view = |doc: &ServerDocument, live: LiveAuthorization| View {
            document: Arc::new(doc.clone()),
            inbounds: doc.server.inbounds.len(),
            preflight: Arc::new(ReloadPreflight::new(
                std::path::PathBuf::from("/nonexistent"),
                doc.clone(),
                Vec::new(),
            )),
            live: Arc::new(live),
        };
        let state = State::new(make_view(
            &active,
            LiveAuthorization::new(active.clone()).unwrap(),
        ));
        let before = state.snapshot().unwrap();
        assert!(state.still_current(&before, 1));
        assert!(!state.still_current(&before, 2));
        let ledger = crate::quota::Ledger::new(&active.server.policy, &active.server.users);
        let user = &active.server.users[0].id;
        let occupied = ledger.acquire_session(user).unwrap();
        let mut quota = active.clone();
        quota.server.policy.max_connections_per_user = 1;
        quota.server.policy.max_connections_total = 1;
        let (rebased, stage) = before.live.prepare_tls_rebase(&quota, 1).unwrap();
        assert_eq!(
            state.commit_quota(&before, 1, make_view(&quota, rebased), stage, &ledger),
            Ok(2)
        );
        assert!(ledger.acquire_session(user).is_none());
        drop(occupied);
        assert!(ledger.acquire_session(user).is_some());
        assert!(!state.still_current(&before, 1));
        let current = state.snapshot().unwrap();
        assert!(state.still_current(&current, 2));
        let mut rotation = quota.clone();
        rotation.server.inbounds[0].tls_cert = "file:/tmp/rotated-cert.pem".into();
        let (rebased, stage) = current.live.prepare_tls_rebase(&rotation, 2).unwrap();
        let called = std::cell::Cell::new(false);
        assert_eq!(
            state.commit_tls_rotation(&current, 2, make_view(&rotation, rebased), stage, || called
                .set(true)),
            Ok(3)
        );
        assert!(called.get());
        let rotated = state.snapshot().unwrap();
        assert_eq!(rotated.document.as_ref(), &rotation);
        assert!(state.still_current(&rotated, 3));
        let (rebased, stage) = rotated.live.prepare_tls_rebase(&rotation, 3).unwrap();
        assert_eq!(
            state.commit_tls_rotation(
                &current,
                2,
                make_view(&rotation, rebased),
                stage,
                || panic!("stale TLS swap")
            ),
            Err(LiveAuthError::StaleRevision)
        );
        let mut fresh = rotation.clone();
        fresh.server.inbounds[0].h2_listen = "127.0.0.1:39991".into();
        assert_eq!(
            state.commit_restart(
                &rotated,
                3,
                make_view(
                    &fresh,
                    LiveAuthorization::new_at_revision(fresh.clone(), 3).unwrap()
                )
            ),
            Err(LiveAuthError::StaleRevision)
        );
        state
            .commit_restart(
                &rotated,
                3,
                make_view(
                    &fresh,
                    LiveAuthorization::new_at_revision(fresh.clone(), 4).unwrap(),
                ),
            )
            .unwrap();
        let successor = state.snapshot().unwrap();
        assert!(state.still_current(&successor, 4));
        assert_eq!(successor.document.as_ref(), &fresh);
        assert!(!state.still_current(&rotated, 3));
        assert_eq!(rotated.live.revision(), Ok(3));
    }
}
