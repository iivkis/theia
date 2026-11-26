//! Bounded evidence scoped to profile, policy, network and exact destination.
use crate::network_scope;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::Mutex,
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
    pub(super) network: network_scope::Scope,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    Verified(Strategy),
    Unavailable,
    Avoid { strategy: Strategy, until: Instant },
}
struct Entry {
    key: Key,
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
    pub(super) fn cached(&self, key: &Key) -> Option<Verdict> {
        let mut cache = self.0.lock().ok()?;
        let now = Instant::now();
        cache.retain(|entry| entry.expires > now);
        cache
            .iter()
            .find(|entry| &entry.key == key)
            .map(|entry| match entry.verdict {
                Verdict::Avoid { until, .. } if until > now => Verdict::Unavailable,
                other => other,
            })
    }

    pub(super) fn remember(&self, key: &Key, verdict: Verdict) {
        // A network change or loss of OS evidence prevents reuse/publication.
        if network_scope::observe(key.address) != Some(key.network) {
            return;
        }
        self.insert(key, verdict);
    }

    pub(super) fn insert(&self, key: &Key, verdict: Verdict) {
        if let Ok(mut cache) = self.0.lock() {
            let now = Instant::now();
            cache.retain(|entry| entry.expires > now && &entry.key != key);
            if cache.len() >= CACHE_LIMIT {
                cache.pop_front();
            }
            let ttl = match verdict {
                Verdict::Verified(_) | Verdict::Avoid { .. } => POSITIVE_TTL,
                Verdict::Unavailable => NEGATIVE_TTL,
            };
            cache.push_back(Entry {
                key: key.clone(),
                verdict,
                expires: now + ttl,
            });
        }
    }

    pub(super) fn failed(&self, key: &Key, strategy: Strategy) {
        if network_scope::observe(key.address) != Some(key.network) {
            return;
        }
        self.sample(key, strategy, false, Duration::ZERO);
        self.invalidate_strategy(key, strategy);
    }

    fn invalidate_strategy(&self, key: &Key, strategy: Strategy) {
        let Ok(mut cache) = self.0.lock() else {
            return;
        };
        let now = Instant::now();
        cache.retain(|entry| entry.expires > now);
        if let Some(entry) = cache.iter_mut().find(|entry| &entry.key == key) {
            // Late results from a previous stream must not invalidate an
            // independently verified different strategy or extend a cooldown.
            if entry.verdict == Verdict::Verified(strategy) {
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
            network: network_scope::Scope::fixture(address, 0),
        };
        cache.insert(&key, Verdict::Verified(Strategy::Middle));
        cache.invalidate_strategy(&key, Strategy::Header);
        assert!(matches!(
            cache.cached(&key),
            Some(Verdict::Verified(Strategy::Middle))
        ));
        cache.invalidate_strategy(&key, Strategy::Middle);
        let first = cache.0.lock().unwrap().front().unwrap().verdict;
        assert!(matches!(cache.cached(&key), Some(Verdict::Unavailable)));
        cache.invalidate_strategy(&key, Strategy::Middle);
        assert!(cache.0.lock().unwrap().front().unwrap().verdict == first);
    }

    #[test]
    fn cache_scope_capacity_and_expiry() {
        let cache = Cache::default();
        let address = "127.0.0.1:443".parse().unwrap();
        let mut key = Key {
            name: "example.org".into(),
            address,
            policy: [1; 32],
            network: network_scope::Scope::fixture(address, 1),
        };
        cache.insert(&key, Verdict::Verified(Strategy::Header));
        assert!(matches!(
            cache.cached(&key),
            Some(Verdict::Verified(Strategy::Header))
        ));
        key.policy = [2; 32];
        assert!(cache.cached(&key).is_none());
        key.policy = [1; 32];
        key.network = network_scope::Scope::fixture(address, 2);
        assert!(cache.cached(&key).is_none());
        key.network = network_scope::Scope::fixture(address, 1);
        cache.insert(
            &key,
            Verdict::Avoid {
                strategy: Strategy::Header,
                until: Instant::now() + NEGATIVE_TTL,
            },
        );
        assert!(matches!(cache.cached(&key), Some(Verdict::Unavailable)));
        cache.insert(
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
            cache.insert(&key, Verdict::Unavailable);
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
