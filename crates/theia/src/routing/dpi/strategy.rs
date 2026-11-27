//! Bounded evidence scoped to profile, policy, network and exact destination.
use crate::network_scope;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
const CACHE_LIMIT: usize = 128;
const POSITIVE_TTL: Duration = Duration::from_secs(60);
const NEGATIVE_TTL: Duration = Duration::from_secs(20);
const HISTORY_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Strategy {
    Header,
    Middle,
    Balanced,
}

impl Strategy {
    pub(super) const ALL: [Self; 3] = [Self::Header, Self::Middle, Self::Balanced];
    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Key {
    pub(super) name: String,
    pub(super) address: SocketAddr,
    pub(super) policy: [u8; 32],
    pub(super) epoch: u64,
    pub(super) network: network_scope::Scope,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    Verified(Strategy),
    Unavailable,
    Avoid { strategy: Strategy, until: Instant },
}
// A lease identifies one publication, not just a strategy or a key. Holding
// it prevents ABA even after eviction, expiry or re-publication.
#[derive(Clone, Debug)]
pub(super) struct Lease(Arc<()>);

impl Lease {
    pub(super) fn new() -> Self {
        Self(Arc::new(()))
    }

    pub(super) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

struct Entry {
    key: Key,
    lease: Lease,
    verdict: Verdict,
    expires: Instant,
}

#[derive(Clone, Copy)]
struct Sample {
    millis: u32,
    failures: u32,
}
impl Default for Sample {
    fn default() -> Self {
        Self {
            millis: 1000,
            failures: 0,
        }
    }
}
struct History {
    key: Key,
    samples: [Sample; 3],
    expires: Instant,
}
#[derive(Default)]
pub(super) struct Cache(Mutex<VecDeque<Entry>>, Mutex<VecDeque<History>>);
impl Cache {
    pub(super) fn ranked(&self, key: &Key) -> [Strategy; 3] {
        let mut order = Strategy::ALL;
        if let Ok(mut history) = self.1.lock() {
            history.retain(|entry| entry.expires > Instant::now());
            if let Some(entry) = history.iter().find(|entry| &entry.key == key) {
                order.sort_by_key(|strategy| {
                    let sample = entry.samples[strategy.index()];
                    sample
                        .failures
                        .saturating_mul(2000)
                        .saturating_add(sample.millis)
                });
            }
        }
        order
    }
    pub(super) fn observe(&self, key: &Key, strategy: Strategy, good: bool, elapsed: Duration) {
        if network_scope::observe(key.address) == Some(key.network) {
            self.sample(key, strategy, good, elapsed);
        }
    }
    fn sample(&self, key: &Key, strategy: Strategy, good: bool, elapsed: Duration) {
        let Ok(mut history) = self.1.lock() else {
            return;
        };
        let now = Instant::now();
        history.retain(|entry| entry.expires > now);
        let mut entry = match history.iter().position(|entry| &entry.key == key) {
            Some(index) => history.remove(index).expect("position exists"),
            None => History {
                key: key.clone(),
                samples: [Sample::default(); 3],
                expires: now + HISTORY_TTL,
            },
        };
        let sample = &mut entry.samples[strategy.index()];
        if good {
            sample.failures = sample.failures.saturating_sub(1);
            let millis = elapsed.as_millis().clamp(1, 2000) as u32;
            sample.millis = (sample.millis * 3 + millis) / 4;
        } else {
            sample.failures = sample.failures.saturating_add(1).min(8);
        }
        entry.expires = now + HISTORY_TTL;
        if history.len() >= CACHE_LIMIT {
            history.pop_front();
        }
        history.push_back(entry);
    }
    #[cfg(test)]
    fn cached(&self, key: &Key) -> Option<Verdict> {
        self.evidence(key).map(|(verdict, _)| verdict)
    }

    pub(super) fn evidence(&self, key: &Key) -> Option<(Verdict, Lease)> {
        let mut cache = self.0.lock().ok()?;
        let now = Instant::now();
        cache.retain(|entry| entry.expires > now);
        cache.iter().find(|entry| &entry.key == key).map(|entry| {
            let verdict = match entry.verdict {
                Verdict::Avoid { until, .. } if until > now => Verdict::Unavailable,
                other => other,
            };
            (verdict, entry.lease.clone())
        })
    }

    pub(super) fn current(&self, key: &Key, strategy: Strategy, lease: &Lease) -> bool {
        self.evidence(key).is_some_and(|(verdict, current)| {
            verdict == Verdict::Verified(strategy) && current.same(lease)
        })
    }

    pub(super) fn remember(&self, key: &Key, verdict: Verdict) -> Option<Lease> {
        // A network change or loss of OS evidence prevents reuse/publication.
        if network_scope::observe(key.address) != Some(key.network) {
            return None;
        }
        self.insert(key, verdict)
    }

    fn insert(&self, key: &Key, verdict: Verdict) -> Option<Lease> {
        let mut cache = self.0.lock().ok()?;
        let now = Instant::now();
        cache.retain(|entry| entry.expires > now && &entry.key != key);
        if cache.len() >= CACHE_LIMIT {
            cache.pop_front();
        }
        let ttl = match verdict {
            Verdict::Verified(_) | Verdict::Avoid { .. } => POSITIVE_TTL,
            Verdict::Unavailable => NEGATIVE_TTL,
        };
        let lease = Lease::new();
        cache.push_back(Entry {
            key: key.clone(),
            lease: lease.clone(),
            verdict,
            expires: now + ttl,
        });
        Some(lease)
    }

    pub(super) fn failed(&self, key: &Key, strategy: Strategy, lease: &Lease) {
        if network_scope::observe(key.address) != Some(key.network) {
            return;
        }
        self.record_outcome(key, strategy, lease, false, Duration::ZERO);
    }

    pub(super) fn succeeded(
        &self,
        key: &Key,
        strategy: Strategy,
        lease: &Lease,
        elapsed: Duration,
    ) {
        if network_scope::observe(key.address) == Some(key.network) {
            self.record_outcome(key, strategy, lease, true, elapsed);
        }
    }

    fn record_outcome(
        &self,
        key: &Key,
        strategy: Strategy,
        lease: &Lease,
        good: bool,
        elapsed: Duration,
    ) {
        let Ok(mut cache) = self.0.lock() else {
            return;
        };
        let now = Instant::now();
        cache.retain(|entry| entry.expires > now);
        if let Some(entry) = cache.iter_mut().find(|entry| {
            &entry.key == key
                && entry.verdict == Verdict::Verified(strategy)
                && entry.lease.same(lease)
        }) {
            // Keep the generation check and the history update under the
            // same cache lock. The lock order is cache -> history; no
            // history operation holds its lock while acquiring the cache.
            self.sample(key, strategy, good, elapsed);
            if !good {
                entry.verdict = Verdict::Avoid {
                    strategy,
                    until: now + NEGATIVE_TTL,
                };
                entry.expires = now + POSITIVE_TTL;
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranking_uses_scoped_observed_latency_and_failures() {
        let cache = Cache::default();
        let address = "127.0.0.1:443".parse().unwrap();
        let mut key = Key {
            name: "example.org".into(),
            address,
            policy: [1; 32],
            epoch: 1,
            network: network_scope::Scope::fixture(address, 0),
        };
        cache.sample(&key, Strategy::Header, false, Duration::ZERO);
        cache.sample(&key, Strategy::Balanced, true, Duration::from_millis(50));
        assert_eq!(
            cache.ranked(&key),
            [Strategy::Balanced, Strategy::Middle, Strategy::Header]
        );
        key.policy = [2; 32];
        assert_eq!(cache.ranked(&key), Strategy::ALL);
    }

    #[test]
    fn late_failure_preserves_other_strategy_and_original_cooldown() {
        let cache = Cache::default();
        let address = "127.0.0.1:443".parse().unwrap();
        let key = Key {
            name: "example.org".into(),
            address,
            policy: [1; 32],
            epoch: 1,
            network: network_scope::Scope::fixture(address, 0),
        };
        let lease = cache.insert(&key, Verdict::Verified(Strategy::Middle)).unwrap();
        cache.record_outcome(&key, Strategy::Header, &lease, false, Duration::ZERO);
        assert!(matches!(
            cache.cached(&key),
            Some(Verdict::Verified(Strategy::Middle))
        ));
        cache.record_outcome(&key, Strategy::Middle, &lease, false, Duration::ZERO);
        let first = cache.0.lock().unwrap().front().unwrap().verdict;
        assert!(matches!(cache.cached(&key), Some(Verdict::Unavailable)));
        cache.record_outcome(&key, Strategy::Middle, &lease, false, Duration::ZERO);
        assert!(cache.0.lock().unwrap().front().unwrap().verdict == first);
    }

    #[test]
    fn stale_same_strategy_cannot_revoke_or_reweight_new_evidence() {
        let cache = Cache::default();
        let address = "127.0.0.1:443".parse().unwrap();
        let key = Key {
            name: "example.org".into(),
            address,
            policy: [1; 32],
            epoch: 1,
            network: network_scope::Scope::fixture(address, 0),
        };
        let old = cache.insert(&key, Verdict::Verified(Strategy::Header)).unwrap();
        let fresh = cache.insert(&key, Verdict::Verified(Strategy::Header)).unwrap();
        assert!(!cache.current(&key, Strategy::Header, &old));
        assert!(cache.current(&key, Strategy::Header, &fresh));
        cache.record_outcome(&key, Strategy::Header, &old, false, Duration::ZERO);
        cache.record_outcome(&key, Strategy::Header, &old, true, Duration::from_millis(1));
        assert!(cache.current(&key, Strategy::Header, &fresh));
        assert!(cache.1.lock().unwrap().is_empty());

        cache.record_outcome(&key, Strategy::Header, &fresh, false, Duration::ZERO);
        assert!(matches!(cache.cached(&key), Some(Verdict::Unavailable)));
        assert_eq!(cache.1.lock().unwrap().front().unwrap().samples[0].failures, 1);
        // Repeated reports from the same failed lease cannot extend cooldown.
        let original = cache.0.lock().unwrap().front().unwrap().verdict;
        cache.record_outcome(&key, Strategy::Header, &fresh, false, Duration::ZERO);
        assert!(cache.0.lock().unwrap().front().unwrap().verdict == original);
        assert_eq!(cache.1.lock().unwrap().front().unwrap().samples[0].failures, 1);

        // A retained lease cannot become current after expiry/eviction.
        cache.0.lock().unwrap().clear();
        let newest = cache.insert(&key, Verdict::Verified(Strategy::Header)).unwrap();
        assert!(!cache.current(&key, Strategy::Header, &fresh));
        assert!(cache.current(&key, Strategy::Header, &newest));
    }

    #[test]
    fn cache_scope_capacity_and_expiry() {
        let cache = Cache::default();
        let address = "127.0.0.1:443".parse().unwrap();
        let mut key = Key {
            name: "example.org".into(),
            address,
            policy: [1; 32],
            epoch: 1,
            network: network_scope::Scope::fixture(address, 1),
        };
        let _ = cache.insert(&key, Verdict::Verified(Strategy::Header));
        assert!(matches!(
            cache.cached(&key),
            Some(Verdict::Verified(Strategy::Header))
        ));
        key.policy = [2; 32];
        assert!(cache.cached(&key).is_none());
        key.policy = [1; 32];
        key.epoch = 2;
        assert!(cache.cached(&key).is_none());
        assert_eq!(cache.ranked(&key), Strategy::ALL);
        key.epoch = 1;
        key.network = network_scope::Scope::fixture(address, 2);
        assert!(cache.cached(&key).is_none());
        key.network = network_scope::Scope::fixture(address, 1);
        let _ = cache.insert(
            &key,
            Verdict::Avoid {
                strategy: Strategy::Header,
                until: Instant::now() + NEGATIVE_TTL,
            },
        );
        assert!(matches!(cache.cached(&key), Some(Verdict::Unavailable)));
        let _ = cache.insert(
            &key,
            Verdict::Avoid {
                strategy: Strategy::Header,
                until: Instant::now(),
            },
        );
        assert!(matches!(
            cache.cached(&key),
            Some(Verdict::Avoid {
                strategy: Strategy::Header,
                ..
            })
        ));
        for i in 0..=CACHE_LIMIT {
            key.name = format!("{i}.example.org");
            let _ = cache.insert(&key, Verdict::Unavailable);
        }
        assert_eq!(cache.0.lock().unwrap().len(), CACHE_LIMIT);
        cache
            .0
            .lock()
            .unwrap()
            .iter_mut()
            .for_each(|e| e.expires = Instant::now() - Duration::from_secs(1));
        assert!(cache.cached(&key).is_none());
    }
}
