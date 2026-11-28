//! Runtime-owned policy publication and consent, independent of any egress.
use super::client_state::LocalPolicy;
use crate::client::ClientError;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

pub(crate) fn stale_policy() -> ClientError {
    crate::traffic::dpi_policy_stale();
    ClientError::Open(crate::protocol::ErrorCode::PolicyDenied)
}

#[cfg(windows)]
struct LocalAuthority {
    digest: [u8; 32],
    live: Arc<dyn Fn() -> bool + Send + Sync>,
}

#[derive(Default)]
pub(crate) struct PolicyState {
    enabled: AtomicBool,
    retired: AtomicBool,
    stun_enabled: AtomicBool,
    policy: std::sync::Mutex<Option<LocalPolicy>>,
    policy_epoch: AtomicU64,
    #[cfg(windows)]
    local: Option<LocalAuthority>,
}

impl PolicyState {
    /// A standalone authority is not a server snapshot. Its immutable
    /// guard owns the exact local publication, DNS pins and session scope.
    #[cfg(windows)]
    pub(crate) fn standalone(digest: [u8; 32], live: Arc<dyn Fn() -> bool + Send + Sync>, stun: bool) -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(true),
            stun_enabled: AtomicBool::new(stun),
            policy_epoch: AtomicU64::new(1),
            local: Some(LocalAuthority { digest, live }),
            ..Self::default()
        })
    }

    pub(crate) fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub(crate) fn set_stun_enabled(&self, enabled: bool) {
        self.stun_enabled.store(enabled, Ordering::Relaxed);
    }

    pub(crate) fn stun_enabled(&self) -> bool {
        self.enabled() && self.stun_enabled.load(Ordering::Relaxed)
    }

    pub(super) fn authorize_policy(&self, lease: Option<LocalPolicy>) {
        #[cfg(windows)]
        if self.local.is_some() { return; }
        if let Ok(mut policy) = self.policy.lock() {
            let next = if self.retired() { None } else { lease };
            let continuous = match (&*policy, &next) {
                (Some(old), Some(new)) => old.continues(new),
                (None, None) => true,
                _ => false,
            };
            if !continuous {
                self.policy_epoch.fetch_add(1, Ordering::AcqRel);
            }
            *policy = next;
        }
    }

    pub(crate) fn retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    /// Retired client generations cannot authorize any more user payload.
    /// Server auth-only Apply is a separate admission contract.
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        self.authorize_policy(None);
    }

    pub(crate) fn policy_current(&self, digest: [u8; 32]) -> bool {
        self.current_epoch(digest).is_some()
    }

    fn current_epoch(&self, digest: [u8; 32]) -> Option<u64> {
        #[cfg(windows)]
        if let Some(local) = &self.local {
            if self.retired() { return None; }
            if !(local.live)() {
                self.retired.store(true, Ordering::Release);
                return None;
            }
            return (local.digest == digest).then_some(1);
        }
        let mut policy = self.policy.lock().ok()?;
        if self.retired() {
            return None;
        }
        if policy.as_ref().is_some_and(|lease| !lease.valid_current()) {
            *policy = None;
            self.policy_epoch.fetch_add(1, Ordering::AcqRel);
            return None;
        }
        policy
            .as_ref()
            .filter(|lease| lease.matches_digest(digest))?;
        Some(self.policy_epoch.load(Ordering::Acquire))
    }

    pub(crate) fn policy_epoch(&self, digest: [u8; 32]) -> Result<u64, ClientError> {
        self.current_epoch(digest).ok_or_else(stale_policy)
    }

    pub(crate) fn check_policy(&self, digest: [u8; 32]) -> Result<(), ClientError> {
        if self.policy_current(digest) {
            Ok(())
        } else {
            Err(stale_policy())
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub(crate) fn pin(self: &Arc<Self>, digest: [u8; 32]) -> Result<PolicyLease, ClientError> {
        Ok(PolicyLease {
            state: self.clone(),
            digest,
            epoch: self.policy_epoch(digest)?,
        })
    }
}

/// The exact accepted publication, not merely a digest that may reappear.
#[derive(Clone)]
pub(crate) struct PolicyLease {
    state: Arc<PolicyState>,
    digest: [u8; 32],
    epoch: u64,
}
impl PolicyLease {
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn check_owner(&self, owner: &Arc<PolicyState>) -> Result<(), ClientError> {
        if !Arc::ptr_eq(&self.state, owner) {
            return Err(stale_policy());
        }
        self.check()
    }
    pub(crate) fn check(&self) -> Result<(), ClientError> {
        if self.state.policy_epoch(self.digest)? != self.epoch {
            return Err(stale_policy());
        }
        Ok(())
    }
    pub(crate) fn modify_enabled(&self) -> bool {
        self.state.enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn standalone_revocation_is_irreversible_and_digest_bound() {
        let alive = Arc::new(AtomicBool::new(true));
        let check = alive.clone();
        let authority = PolicyState::standalone([8; 32], Arc::new(move || check.load(Ordering::Acquire)), false);
        assert!(authority.pin([7; 32]).is_err());
        let lease = authority.pin([8; 32]).unwrap();
        assert!(lease.check().is_ok());
        assert!(!authority.stun_enabled());
        alive.store(false, Ordering::Release);
        assert!(lease.check().is_err());
        alive.store(true, Ordering::Release);
        assert!(authority.pin([8; 32]).is_err());
    }

    #[test]
    fn revocation_and_republication_cannot_revive_a_lease() {
        let authority = Arc::new(PolicyState::default());
        let digest = [7; 32];
        authority.authorize_policy(Some(LocalPolicy::fixture(digest)));
        let lease = authority.pin(digest).unwrap();
        authority.set_enabled(false);
        assert!(lease.check().is_ok());
        assert!(!lease.modify_enabled());
        authority.authorize_policy(None);
        authority.authorize_policy(Some(LocalPolicy::fixture(digest)));
        assert!(lease.check().is_err());
        let fresh = authority.pin(digest).unwrap();
        authority.retire();
        assert!(fresh.check().is_err());
        authority.authorize_policy(Some(LocalPolicy::fixture(digest)));
        assert!(authority.pin(digest).is_err());
    }
}
