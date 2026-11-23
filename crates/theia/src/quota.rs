//! Dynamic quota ledger. The same ledger must outlive every H2/H3 listener
//! generation and account for all held permits during limit contraction.
//! No async I/O or allocations on the successful admission critical section.
use crate::config::{ServerPolicy, User};

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
