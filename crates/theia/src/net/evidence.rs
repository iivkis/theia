//! Shared publication identity, deadline and bounded-cache primitives.
//! Consumers keep separate policy/profile/endpoint/protocol namespaces.
use std::{collections::VecDeque, sync::Arc, time::{Duration, Instant}};

pub(crate) fn live(expires: Instant, now: Instant) -> bool { expires > now }

pub(crate) fn deadline(now: Instant, ttl: Duration) -> Option<Instant> {
    if ttl.is_zero() { None } else { now.checked_add(ttl) }
}

pub(crate) fn expiry(now: Instant, ttl: Duration) -> Instant {
    // Overflow or a zero TTL must fail closed, not become infinite evidence.
    deadline(now, ttl).unwrap_or(now)
}

pub(crate) fn push_bounded<T>(items: &mut VecDeque<T>, item: T, capacity: usize) {
    if capacity == 0 { return; }
    while items.len() >= capacity { items.pop_front(); }
    items.push_back(item);
}

// A lease identifies one publication, not just a strategy or a key. Holding
// it prevents ABA even after eviction, expiry or re-publication.
#[derive(Clone, Debug)]
pub(crate) struct Publication(Arc<()>);

impl Publication {
    pub(crate) fn new() -> Self {
        Self(Arc::new(()))
    }

    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}


/// A single transport/mode decision scoped to the network. The owner
/// decides the meaning of a positive publication; this is not a shared verdict.
#[derive(Default)]
pub(crate) struct ScopedDecision {
    pub(crate) route: Option<crate::network_scope::Scope>,
    pub(crate) generation: u64,
    pub(crate) expires: Option<Instant>,
}

impl ScopedDecision {
    pub(crate) fn observe(&mut self, route: Option<crate::network_scope::Scope>, now: Instant) -> (u64, bool) {
        if route.is_none() || self.route != route {
            self.route = route;
            self.invalidate();
        }
        if self.expires.is_some_and(|until| !live(until, now)) {
            // A foreground request may win the expiry race. Retire the
            // previous generation so a sleeping maintenance task cannot
            // publish evidence for it later.
            self.invalidate();
        }
        (self.generation, self.expires.is_some())
    }

    pub(crate) fn current(&self, generation: u64) -> bool {
        self.route.is_some() && self.generation == generation
    }

    pub(crate) fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.expires = None;
    }

    pub(crate) fn record(&mut self, generation: u64, now: Instant, ttl: Duration) -> bool {
        if self.generation != generation
            || self.route.is_none()
            || ttl.is_zero()
            || self.expires.is_some()
        {
            return false;
        }
        // Concurrent failures must not push the first recheck further away.
        self.expires = deadline(now, ttl);
        self.expires.is_some()
    }

    pub(crate) fn begin_recheck(
        &mut self,
        generation: u64,
        deadline: Instant,
        route: Option<crate::network_scope::Scope>,
        now: Instant,
    ) -> Option<u64> {
        if self.generation != generation || self.expires != Some(deadline) || now < deadline {
            return None;
        }
        if route.is_none() || self.route != route {
            self.route = route;
            self.invalidate();
            return None;
        }
        self.invalidate();
        Some(self.generation)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn separate_publications_are_never_equivalent() {
        let first = Publication::new();
        assert!(first.same(&first.clone()));
        assert!(!first.same(&Publication::new()));
    }
    #[test]
    fn scoped_decisions_expire_and_reject_late_publication() {
        let now = Instant::now();
        let ttl = Duration::from_secs(2);
        let scope = Some(crate::network_scope::Scope::fixture("127.0.0.1:0".parse().unwrap(), 1));
        let mut cache = ScopedDecision::default();
        let (generation, _) = cache.observe(scope, now);
        assert!(cache.record(generation, now, ttl));
        assert!(!cache.record(generation, now + Duration::from_secs(1), ttl));
        let (next, cached) = cache.observe(scope, now + ttl);
        assert!(!cached);
        assert_ne!(generation, next);
        assert!(!cache.record(generation, now + ttl, ttl));
        assert!(cache.record(next, now + ttl, ttl));
    }
    #[test]
    fn bounds_and_deadlines() {
        let now = Instant::now();
        assert!(!live(expiry(now, Duration::ZERO), now));
        let mut values = VecDeque::new();
        for n in 0..5 { push_bounded(&mut values, n, 2); }
        assert_eq!(values.into_iter().collect::<Vec<_>>(), vec![3,4]);
    }
}
