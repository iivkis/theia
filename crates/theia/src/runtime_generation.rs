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
use std::sync::{Arc, RwLock};
use tokio::sync::oneshot;

pub(crate) struct View {
    pub(crate) document: Arc<ServerDocument>,
    pub(crate) inbounds: usize,
    pub(crate) preflight: Arc<ReloadPreflight>,
    pub(crate) live: Arc<LiveAuthorization>,
}

pub(crate) struct State {
    current: RwLock<Arc<View>>,
}

impl State {
    pub(crate) fn new(initial: View) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
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
        let guard = self
            .current
            .read()
            .map_err(|_| LiveAuthError::Unavailable)?;
        if !Arc::ptr_eq(&guard, view) {
            return Err(LiveAuthError::StaleRevision);
        }
        view.live
            .stage(candidate, expected)
            .and_then(|staged| view.live.publish(staged))
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
pub(crate) struct RestartRequest {
    pub(crate) previous: Arc<View>,
    pub(crate) expected_revision: u64,
    pub(crate) candidate: ServerDocument,
    pub(crate) complete: oneshot::Sender<Result<u64, ()>>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
