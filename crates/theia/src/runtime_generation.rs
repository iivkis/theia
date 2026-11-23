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
use std::{sync::{Arc, RwLock}, time::Instant};
use tokio::sync::oneshot;

pub(crate) struct View {
    pub(crate) document: Arc<ServerDocument>,
    pub(crate) inbounds: usize,
    pub(crate) preflight: Arc<ReloadPreflight>,
    pub(crate) live: Arc<LiveAuthorization>,
}

pub(crate) struct State {
    current: RwLock<Arc<View>>,
    // Only advisory metadata crosses IPC; the actual previous TLS private
    // configs live exclusively in the single supervisor, never in replies.
    rollback_until: RwLock<Option<Instant>>,
}

impl State {
    pub(crate) fn new(initial: View) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
            rollback_until: RwLock::new(None),
        }
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
        let staged = view.live.stage(candidate, expected)?;
        let revision = view.live.publish(staged)?;
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
        let held = ledger
            .prepare_resize(&next.document.server.policy)
            .map_err(|_| LiveAuthError::Unavailable)?;
        // No fallible quota action after revision publication: held.commit
        // sets two small integers under the already acquired ledger lock.
        let revision = previous.live.publish(authorization)?;
        debug_assert_eq!(revision, expected_next);
        held.commit();
        *guard = Arc::new(next);
        Ok(revision)
    }

    /// Linearization point for a prepared fresh-port listener generation.
    /// In-flight and future requests on the former generation are denied
    /// NEW admission before the protected IPC view points to the successor.
    pub(crate) fn commit_restart(
        &self,
        previous: &Arc<View>,
        expected: u64,
        next: View,
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
        previous.live.close_new_admission()?;
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
    fn rollback_readiness_is_bounded_and_never_exposes_secret_material() {
        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        let crate::config::Config::Server(document) = crate::config::parse(&source).unwrap()
        else { panic!("server fixture"); };
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
}
