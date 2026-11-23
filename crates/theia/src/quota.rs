//! Dynamic quota ledger. The same ledger must outlive every H2/H3 listener
//! generation and account for all held permits during limit contraction.
//! No async I/O or allocations on the successful admission critical section.
use crate::config::{ServerPolicy, User};

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// All active stream/user and transport occupancies are counted under ONE
/// short lock. Resizing below occupancy creates admission debt, not a
/// semaphore replacement that would forget already-open sessions.
#[derive(Debug)]
pub(crate) struct Ledger {
    usage: Mutex<Usage>,
}

#[derive(Debug)]
struct Usage {
    per_user_limit: usize,
    total_limit: usize,
    sessions: usize,
    connections: usize,
    per_user: HashMap<String, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuotaError {
    InvalidLimit,
    Unavailable,
}

pub(crate) struct Lease {
    ledger: Arc<Ledger>,
    kind: LeaseKind,
}

enum LeaseKind {
    Session(String),
    Connection,
}

impl Drop for Lease {
    fn drop(&mut self) {
        // A poisoned lock must never cause a panic from Drop; it must
        // fail closed for future admissions instead of over-admitting.
        if let Ok(mut usage) = self.ledger.usage.lock() {
            match &self.kind {
                LeaseKind::Session(user) => {
                    usage.sessions -= 1;
                    if let Some(count) = usage.per_user.get_mut(user) {
                        *count -= 1;
                    }
                }
                LeaseKind::Connection => usage.connections -= 1,
            }
        }
    }
}

impl Ledger {
    pub(crate) fn new(policy: &ServerPolicy, users: &[User]) -> Arc<Self> {
        Arc::new(Self {
            usage: Mutex::new(Usage {
                per_user_limit: policy.max_connections_per_user as usize,
                total_limit: policy.max_connections_total as usize,
                sessions: 0,
                connections: 0,
                per_user: users.iter().map(|user| (user.id.clone(), 0)).collect(),
            }),
        })
    }

    /// Admission is a single non-async decision across both transports and
    /// ALL inbounds. No new slot can sneak in while a quota cap is resized.
    pub(crate) fn acquire_session(self: &Arc<Self>, user: &str) -> Option<Lease> {
        let mut usage = self.usage.lock().ok()?;
        if usage.sessions >= usage.total_limit
            || *usage.per_user.get(user)? >= usage.per_user_limit
        {
            return None;
        }
        usage.sessions += 1;
        *usage.per_user.get_mut(user)? += 1;
        drop(usage);
        Some(Lease {
            ledger: Arc::clone(self),
            kind: LeaseKind::Session(user.to_owned()),
        })
    }

    pub(crate) fn acquire_connection(self: &Arc<Self>) -> Option<Lease> {
        let mut usage = self.usage.lock().ok()?;
        if usage.connections >= usage.total_limit {
            return None;
        }
        usage.connections += 1;
        drop(usage);
        Some(Lease {
            ledger: Arc::clone(self),
            kind: LeaseKind::Connection,
        })
    }

    fn validate_limits(policy: &ServerPolicy) -> Result<(), QuotaError> {
        if policy.max_connections_per_user == 0
            || policy.max_connections_total == 0
            || policy.max_connections_per_user > policy.max_connections_total
        {
            return Err(QuotaError::InvalidLimit);
        }
        Ok(())
    }

    pub(crate) fn resize(&self, policy: &ServerPolicy) -> Result<(), QuotaError> {
        Self::validate_limits(policy)?;
        let mut usage = self.usage.lock().map_err(|_| QuotaError::Unavailable)?;
        usage.per_user_limit = policy.max_connections_per_user as usize;
        usage.total_limit = policy.max_connections_total as usize;
        Ok(())
    }

    /// Acquire before CAS; only commit new caps AFTER authorization revision
    /// successfully publishes. The guard is held across publication so
    /// admission cannot race into the old free permits during a shrink.
    pub(crate) fn prepare_resize(
        &self,
        policy: &ServerPolicy,
    ) -> Result<PreparedResize<'_>, QuotaError> {
        Self::validate_limits(policy)?;
        let guard = self.usage.lock().map_err(|_| QuotaError::Unavailable)?;
        Ok(PreparedResize {
            guard,
            per_user_limit: policy.max_connections_per_user as usize,
            total_limit: policy.max_connections_total as usize,
        })
    }

    #[cfg(test)]
    fn occupancy(&self) -> Result<(usize, usize), QuotaError> {
        let usage = self.usage.lock().map_err(|_| QuotaError::Unavailable)?;
        Ok((usage.sessions, usage.connections))
    }
}

pub(crate) struct PreparedResize<'a> {
    guard: std::sync::MutexGuard<'a, Usage>,
    per_user_limit: usize,
    total_limit: usize,
}

impl PreparedResize<'_> {
    pub(crate) fn commit(mut self) {
        self.guard.per_user_limit = self.per_user_limit;
        self.guard.total_limit = self.total_limit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(per_user: u32, total: u32) -> ServerPolicy {
        ServerPolicy {
            allow_private_ips: true,
            max_connections_per_user: per_user,
            max_connections_total: total,
            connect_timeout_ms: 2000,
        }
    }
    fn people() -> Vec<User> {
        ["alice", "bob"]
            .iter()
            .map(|id| User {
                id: (*id).into(),
                token_sha256: "a".repeat(64),
                disabled: false,
            })
            .collect()
    }

    #[test]
    fn shrinking_below_existing_occupancy_never_revokes_or_over_admits() {
        let ledger = Ledger::new(&policy(3, 3), &people());
        let a = ledger.acquire_session("alice").unwrap();
        let b = ledger.acquire_session("alice").unwrap();
        let c = ledger.acquire_session("alice").unwrap();
        assert!(ledger.acquire_session("bob").is_none());
        ledger.resize(&policy(1, 1)).unwrap();
        assert!(ledger.acquire_session("bob").is_none());
        drop(a);
        assert!(ledger.acquire_session("alice").is_none());
        drop(b);
        assert!(ledger.acquire_session("bob").is_none());
        drop(c);
        let resumed = ledger.acquire_session("bob").expect("debt repaid");
        assert!(ledger.acquire_session("alice").is_none());
        drop(resumed);
        assert!(ledger.acquire_session("alice").is_some());
    }

    #[test]
    fn increasing_beyond_initial_caps_preserves_one_global_and_per_user_limit() {
        let ledger = Ledger::new(&policy(1, 1), &people());
        let old = ledger.acquire_session("alice").unwrap();
        ledger.resize(&policy(3, 4)).unwrap();
        let a2 = ledger.acquire_session("alice").unwrap();
        let a3 = ledger.acquire_session("alice").unwrap();
        assert!(ledger.acquire_session("alice").is_none());
        let b = ledger.acquire_session("bob").unwrap();
        assert!(ledger.acquire_session("bob").is_none());
        assert!(ledger.acquire_session("unknown").is_none());
        drop((old, a2, a3, b));
        for _ in 0..4 {
            // Released slots are reusable, never permanently forgotten.
            assert!(ledger.acquire_session("alice").is_some());
        }
    }

    #[test]
    fn transport_connections_are_not_revoked_during_contraction() {
        let ledger = Ledger::new(&policy(4, 4), &people());
        let a = ledger.acquire_connection().unwrap();
        let b = ledger.acquire_connection().unwrap();
        let c = ledger.acquire_connection().unwrap();
        ledger.resize(&policy(1, 1)).unwrap();
        assert!(ledger.acquire_connection().is_none());
        drop(a);
        assert!(ledger.acquire_connection().is_none());
        drop(b);
        assert!(ledger.acquire_connection().is_none());
        drop(c);
        let new_connection = ledger.acquire_connection().unwrap();
        assert!(ledger.acquire_connection().is_none());
        drop(new_connection);
        assert!(ledger.acquire_connection().is_some());
    }

    #[test]
    fn concurrent_admission_and_resize_are_serialized_under_one_lock() {
        let ledger = Ledger::new(&policy(8, 8), &people());
        std::thread::scope(|threads| {
            for thread in 0..8 {
                let shared = ledger.clone();
                threads.spawn(move || {
                    for iteration in 0..200 {
                        let _held = shared.acquire_session(if thread % 2 == 0 {
                            "alice"
                        } else {
                            "bob"
                        });
                        if iteration % 17 == 0 {
                            let cap = if iteration % 34 == 0 { 2 } else { 8 };
                            shared.resize(&policy(cap, cap)).unwrap();
                        }
                    }
                });
            }
        });
        let (streams, connections) = ledger.occupancy().unwrap();
        assert_eq!((streams, connections), (0, 0));
        ledger.resize(&policy(1, 1)).unwrap();
        let _one = ledger.acquire_session("alice").unwrap();
        assert!(ledger.acquire_session("bob").is_none());
    }
}
