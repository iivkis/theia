//! Bounded evidence scoped to profile, policy, network and exact destination.
use crate::network_scope;
use std::{collections::VecDeque, net::SocketAddr, sync::Mutex, time::{Duration,Instant}};
const CACHE_LIMIT: usize = 128;
const POSITIVE_TTL: Duration = Duration::from_secs(60);
const NEGATIVE_TTL: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Strategy {
    Header,
    Middle,
}

impl Strategy {
    pub(super) const ALL: [Self; 2] = [Self::Header, Self::Middle];
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

#[derive(Default)]
pub(super) struct Cache(Mutex<VecDeque<Entry>>);
impl Cache {
    pub(super) fn cached(&self, key: &Key) -> Option<Verdict> {
        let mut cache = self.0.lock().ok()?;
        let now = Instant::now();
        cache.retain(|entry| entry.expires > now);
        cache.iter().find(|entry| &entry.key == key).map(|entry| match entry.verdict {
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
        self.remember(key, Verdict::Avoid { strategy, until: Instant::now()+NEGATIVE_TTL });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_scope_capacity_and_expiry() {
        let cache = Cache::default();
        let address = "127.0.0.1:443".parse().unwrap();
        let mut key = Key { name:"example.org".into(), address, policy:[1;32], network:network_scope::Scope::fixture(address,1) };
        cache.insert(&key,Verdict::Verified(Strategy::Header));
        assert!(matches!(cache.cached(&key),Some(Verdict::Verified(Strategy::Header))));
        key.policy=[2;32];
        assert!(cache.cached(&key).is_none());
        key.policy=[1;32];
        key.network=network_scope::Scope::fixture(address,2);
        assert!(cache.cached(&key).is_none());
        key.network=network_scope::Scope::fixture(address,1);
        cache.insert(&key,Verdict::Avoid { strategy:Strategy::Header, until:Instant::now()+NEGATIVE_TTL });
        assert!(matches!(cache.cached(&key),Some(Verdict::Unavailable)));
        cache.insert(&key,Verdict::Avoid { strategy:Strategy::Header, until:Instant::now() });
        assert!(matches!(cache.cached(&key),Some(Verdict::Avoid { strategy:Strategy::Header,.. })));
        for i in 0..=CACHE_LIMIT {
            key.name=format!("{i}.example.org");
            cache.insert(&key,Verdict::Unavailable);
        }
        assert_eq!(cache.0.lock().unwrap().len(),CACHE_LIMIT);
        cache.0.lock().unwrap().iter_mut().for_each(|e| e.expires=Instant::now()-Duration::from_secs(1));
        assert!(cache.cached(&key).is_none());
    }
}
