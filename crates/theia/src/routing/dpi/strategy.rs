//! Bounded evidence scoped to profile, policy, network and exact destination.
use super::UdpProbe;
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
pub(crate) enum Strategy {
    Header,
    Middle,
    Balanced,
}

impl Strategy {
    pub(crate) const ALL: [Self; 3] = [Self::Header, Self::Middle, Self::Balanced];

    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::Header => "tcp_header",
            Self::Middle => "tcp_middle",
            Self::Balanced => "tcp_balanced",
        }
    }

    /// Separate role acceptance, not inherited from the SmartTheia path.
    /// Enable only after independent exact-revision F-20 evidence.
    pub(crate) fn accepted_for_standalone(self) -> bool {
        const ACCEPTED: &[Strategy] = &[];
        ACCEPTED.contains(&self)
    }
    pub(crate) fn available_for_standalone(self) -> bool {
        self.accepted_for_standalone() || super::STANDALONE_EXPERIMENTAL
    }

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
    UdpVerified,
    Denied,
    Unavailable,
    Avoid { strategy: Strategy, until: Instant },
}
pub(super) use crate::net::evidence::Publication as Lease;
use crate::net::evidence::{expiry, live, push_bounded};

struct Entry {
    key: Key,
    probe: Option<UdpProbe>,
    lease: Lease,
    verdict: Verdict,
    expires: Instant,
    last_use: Option<Instant>,
    refresh_attempt: Option<Instant>,
}

#[derive(Clone, Copy)]
struct Sample {
    millis: u32,
    deviation: u32,
    observed: bool,
    rtt: Option<(u32, u32)>,
    failures: u32,
}
impl Default for Sample {
    fn default() -> Self {
        Self {
            millis: 1000,
            deviation: 0,
            observed: false,
            rtt: None,
            failures: 0,
        }
    }
}
struct History {
    key: Key,
    samples: [Sample; 6],
    expires: Instant,
}
#[derive(Default)]
pub(super) struct Cache(Mutex<VecDeque<Entry>>, Mutex<VecDeque<History>>);
impl Cache {
    pub(super) fn ranked(&self, key: &Key) -> [Strategy; 3] {
        let mut order = Strategy::ALL;
        if let Ok(mut history) = self.1.lock() {
            history.retain(|entry| live(entry.expires, Instant::now()));
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
    /// Measured handshake latency AND independent round-trip estimates.
    /// EWMA + variation and a conservative margin; failures back off,
    /// never exceed the established per-protocol hard deadline.
    fn budget(&self, key: &Key, index: usize, cap: Duration) -> Duration {
        let sample = self
            .1
            .lock()
            .ok()
            .and_then(|mut history| {
                history.retain(|entry| live(entry.expires, Instant::now()));
                history
                    .iter()
                    .find(|entry| &entry.key == key)
                    .map(|entry| entry.samples[index])
            })
            .unwrap_or_default();
        if !sample.observed {
            return cap;
        }
        let ceiling = cap.as_millis().min(u128::from(u32::MAX)) as u32;
        let handshake = sample
            .millis
            .saturating_mul(2)
            .saturating_add(sample.deviation.saturating_mul(4));
        let network = sample.rtt.map_or(0, |(rtt, variation)| {
            rtt.saturating_mul(3)
                .saturating_add(variation.saturating_mul(4))
        });
        let predicted = handshake
            .max(network)
            .saturating_add(100)
            .saturating_mul(1 + sample.failures.min(3));
        Duration::from_millis(u64::from(predicted.clamp(350.min(ceiling), ceiling)))
    }

    pub(super) fn tcp_budget(&self, key: &Key, strategy: Strategy, cap: Duration) -> Duration {
        self.budget(key, strategy.index(), cap)
    }

    pub(super) fn udp_budget(&self, key: &Key, probe: UdpProbe, cap: Duration) -> Duration {
        self.budget(key, probe.index(), cap)
    }

    /// Only actual foreground commitment marks a target recently used.
    pub(super) fn touch_tcp(&self, key: &Key, lease: &Lease) {
        let Ok(mut entries) = self.0.lock() else {
            return;
        };
        let now = Instant::now();
        if let Some(entry) = entries.iter_mut().find(|e| {
            &e.key == key
                && e.probe.is_none()
                && live(e.expires, now)
                && e.lease.same(lease)
                && matches!(e.verdict, Verdict::Verified(_))
        }) {
            entry.last_use = Some(now);
        }
    }

    /// At most one background candidate per tick. No speculative targets,
    /// no indefinite refresh without new application traffic.
    pub(super) fn due_tcp(&self) -> Option<(Key, Strategy, Lease)> {
        let mut entries = self.0.lock().ok()?;
        let now = Instant::now();
        let entry = entries
            .iter_mut()
            .filter(|e| {
                e.probe.is_none()
                    && live(e.expires, now)
                    && e.expires.saturating_duration_since(now) <= Duration::from_secs(12)
                    && e.last_use
                        .is_some_and(|t| now.duration_since(t) <= Duration::from_secs(90))
                    && e.refresh_attempt
                        .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(15))
                    && matches!(e.verdict, Verdict::Verified(_))
            })
            .min_by_key(|e| e.expires)?;
        let Verdict::Verified(strategy) = entry.verdict else {
            return None;
        };
        entry.refresh_attempt = Some(now);
        Some((entry.key.clone(), strategy, entry.lease.clone()))
    }

    pub(super) fn denied_tcp(&self, key: &Key) -> bool {
        self.evidence(key)
            .is_some_and(|(verdict, _)| verdict == Verdict::Denied)
    }

    pub(super) fn deny_tcp(&self, key: &Key, lease: &Lease) {
        let Ok(mut entries) = self.0.lock() else {
            return;
        };
        let now = Instant::now();
        if let Some(entry) = entries.iter_mut().find(|e| {
            &e.key == key
                && e.probe.is_none()
                && live(e.expires, now)
                && e.lease.same(lease)
                && matches!(e.verdict, Verdict::Verified(_))
        }) {
            entry.verdict = Verdict::Denied;
            entry.expires = expiry(now, NEGATIVE_TTL);
        }
    }

    /// Compare-and-refresh a positive publication. A stale background
    /// result cannot overwrite a foreground outcome, and keeps last_use.
    pub(super) fn renew_tcp(&self, key: &Key, strategy: Strategy, lease: &Lease) -> bool {
        let Ok(mut entries) = self.0.lock() else {
            return false;
        };
        let now = Instant::now();
        let Some(entry) = entries.iter_mut().find(|e| {
            &e.key == key
                && e.probe.is_none()
                && live(e.expires, now)
                && e.lease.same(lease)
                && e.verdict == Verdict::Verified(strategy)
        }) else {
            return false;
        };
        // Same immutable strategy and scope; do not invalidate a pending
        // flow solely because its evidence was independently refreshed.
        entry.expires = expiry(now, POSITIVE_TTL);
        true
    }

    pub(super) fn observe(
        &self,
        key: &Key,
        strategy: Strategy,
        good: bool,
        elapsed: Duration,
        rtt: Option<Duration>,
    ) {
        if network_scope::observe(key.address) == Some(key.network) {
            self.sample_timing(key, strategy.index(), good, elapsed, rtt);
        }
    }
    fn sample(&self, key: &Key, strategy: Strategy, good: bool, elapsed: Duration) {
        self.sample_index(key, strategy.index(), good, elapsed);
    }

    fn sample_index(&self, key: &Key, index: usize, good: bool, elapsed: Duration) {
        self.sample_timing(key, index, good, elapsed, None);
    }

    fn sample_timing(
        &self,
        key: &Key,
        index: usize,
        good: bool,
        elapsed: Duration,
        rtt: Option<Duration>,
    ) {
        let Ok(mut history) = self.1.lock() else {
            return;
        };
        let now = Instant::now();
        history.retain(|entry| live(entry.expires, now));
        let mut entry = match history.iter().position(|entry| &entry.key == key) {
            Some(index) => history.remove(index).expect("position exists"),
            None => History {
                key: key.clone(),
                samples: [Sample::default(); 6],
                expires: expiry(now, HISTORY_TTL),
            },
        };
        let sample = &mut entry.samples[index];
        if good {
            sample.failures = sample.failures.saturating_sub(1);
            let millis = elapsed.as_millis().clamp(1, 2000) as u32;
            if sample.observed {
                sample.deviation = (sample.deviation * 3 + sample.millis.abs_diff(millis)) / 4;
                sample.millis = (sample.millis * 3 + millis) / 4;
            } else {
                sample.millis = millis;
                sample.deviation = millis / 2;
                sample.observed = true;
            }
            // No RTT sample from a failed, canceled or unauthenticated probe.
            if let Some(rtt) = rtt {
                let value = rtt.as_millis().clamp(1, 2000) as u32;
                sample.rtt = Some(match sample.rtt {
                    Some((old, variation)) => (
                        (old * 7 + value) / 8,
                        (variation * 3 + old.abs_diff(value)) / 4,
                    ),
                    None => (value, value / 2),
                });
            }
        } else {
            sample.failures = sample.failures.saturating_add(1).min(8);
        }
        entry.expires = expiry(now, HISTORY_TTL);
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
        self.evidence_kind(key, None)
    }

    fn evidence_kind(&self, key: &Key, probe: Option<UdpProbe>) -> Option<(Verdict, Lease)> {
        let mut cache = self.0.lock().ok()?;
        let now = Instant::now();
        cache.retain(|entry| live(entry.expires, now));
        cache
            .iter()
            .find(|entry| &entry.key == key && entry.probe == probe)
            .map(|entry| {
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
        self.insert_kind(key, None, verdict)
    }

    fn insert_kind(&self, key: &Key, probe: Option<UdpProbe>, verdict: Verdict) -> Option<Lease> {
        let mut cache = self.0.lock().ok()?;
        let now = Instant::now();
        cache.retain(|entry| {
            live(entry.expires, now) && (&entry.key != key || entry.probe != probe)
        });
        let ttl = match verdict {
            Verdict::Verified(_) | Verdict::UdpVerified | Verdict::Avoid { .. } => POSITIVE_TTL,
            Verdict::Unavailable | Verdict::Denied => NEGATIVE_TTL,
        };
        let lease = Lease::new();
        push_bounded(
            &mut cache,
            Entry {
                key: key.clone(),
                probe,
                lease: lease.clone(),
                verdict,
                expires: expiry(now, ttl),
                last_use: None,
                refresh_attempt: None,
            },
            CACHE_LIMIT,
        );
        Some(lease)
    }

    pub(super) fn udp_evidence(&self, key: &Key, probe: UdpProbe) -> Option<(bool, Lease)> {
        self.evidence_kind(key, Some(probe))
            .map(|(verdict, lease)| (verdict == Verdict::UdpVerified, lease))
    }

    pub(super) fn remember_udp(&self, key: &Key, probe: UdpProbe, good: bool) -> Option<Lease> {
        if network_scope::observe(key.address) != Some(key.network) {
            return None;
        }
        self.insert_kind(
            key,
            Some(probe),
            if good {
                Verdict::UdpVerified
            } else {
                Verdict::Unavailable
            },
        )
    }

    pub(super) fn observe_udp(
        &self,
        key: &Key,
        probe: UdpProbe,
        good: bool,
        elapsed: Duration,
        rtt: Option<Duration>,
    ) {
        if network_scope::observe(key.address) == Some(key.network) {
            self.sample_timing(key, probe.index(), good, elapsed, rtt);
        }
    }

    pub(super) fn udp_score(&self, key: &Key, probe: UdpProbe) -> u32 {
        let sample = self
            .1
            .lock()
            .ok()
            .and_then(|mut history| {
                history.retain(|entry| live(entry.expires, Instant::now()));
                history
                    .iter()
                    .find(|entry| &entry.key == key)
                    .map(|entry| entry.samples[probe.index()])
            })
            .unwrap_or_default();
        sample
            .failures
            .saturating_mul(2000)
            .saturating_add(sample.millis)
    }

    pub(super) fn fail_udp(&self, key: &Key, probe: UdpProbe, lease: &Lease) {
        if network_scope::observe(key.address) != Some(key.network) {
            return;
        }
        let Ok(mut cache) = self.0.lock() else { return };
        let now = Instant::now();
        cache.retain(|entry| live(entry.expires, now));
        if let Some(entry) = cache.iter_mut().find(|entry| {
            &entry.key == key
                && entry.probe == Some(probe)
                && entry.verdict == Verdict::UdpVerified
                && entry.lease.same(lease)
        }) {
            self.sample_index(key, probe.index(), false, Duration::ZERO);
            entry.verdict = Verdict::Unavailable;
            entry.expires = expiry(now, NEGATIVE_TTL);
        }
    }

    #[cfg(test)]
    pub(super) fn fixture_udp(&self, key: &Key, probe: UdpProbe, good: bool) -> Lease {
        self.insert_kind(
            key,
            Some(probe),
            if good {
                Verdict::UdpVerified
            } else {
                Verdict::Unavailable
            },
        )
        .unwrap()
    }

    #[cfg(test)]
    pub(super) fn fixture_size(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    #[cfg(test)]
    pub(super) fn fixture_expire(&self) {
        for entry in self.0.lock().unwrap().iter_mut() {
            entry.expires = Instant::now();
        }
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
        cache.retain(|entry| live(entry.expires, now));
        if let Some(entry) = cache.iter_mut().find(|entry| {
            &entry.key == key
                && entry.probe.is_none()
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
                    until: expiry(now, NEGATIVE_TTL),
                };
                entry.expires = expiry(now, POSITIVE_TTL);
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
    fn adaptive_budget_uses_successful_round_trip_and_latency_only() {
        let cache = Cache::default();
        let address = "127.0.0.1:443".parse().unwrap();
        let mut key = Key {
            name: "example.org".into(),
            address,
            policy: [1; 32],
            epoch: 1,
            network: network_scope::Scope::fixture(address, 0),
        };
        let cap = Duration::from_secs(2);
        let index = Strategy::Header.index();
        assert_eq!(cache.tcp_budget(&key, Strategy::Header, cap), cap);
        cache.sample_timing(
            &key,
            index,
            true,
            Duration::from_millis(70),
            Some(Duration::from_millis(30)),
        );
        let fast = cache.tcp_budget(&key, Strategy::Header, cap);
        assert!(fast >= Duration::from_millis(350) && fast < cap);
        cache.sample_timing(
            &key,
            index,
            false,
            Duration::ZERO,
            Some(Duration::from_millis(1)),
        );
        assert!(cache.tcp_budget(&key, Strategy::Header, cap) > fast);
        for _ in 0..8 {
            cache.sample_timing(
                &key,
                index,
                true,
                Duration::from_millis(900),
                Some(Duration::from_millis(700)),
            );
        }
        assert_eq!(cache.tcp_budget(&key, Strategy::Header, cap), cap);
        key.epoch += 1;
        assert_eq!(cache.tcp_budget(&key, Strategy::Header, cap), cap);
    }

    #[test]
    fn refresh_requires_real_recent_use_and_exact_live_publication() {
        let cache = Cache::default();
        let address = "127.0.0.1:443".parse().unwrap();
        let key = Key {
            name: "example.org".into(),
            address,
            policy: [1; 32],
            epoch: 1,
            network: network_scope::Scope::fixture(address, 0),
        };
        let strategy = Strategy::Header;
        let old = cache.insert(&key, Verdict::Verified(strategy)).unwrap();
        cache.0.lock().unwrap()[0].expires = Instant::now() + Duration::from_secs(8);
        assert!(
            cache.due_tcp().is_none(),
            "probe alone must not schedule background traffic"
        );
        cache.touch_tcp(&key, &old);
        let (_, chosen, due) = cache.due_tcp().unwrap();
        assert_eq!(chosen, strategy);
        assert!(due.same(&old));
        assert!(
            cache.due_tcp().is_none(),
            "refresh must be single flight/rate limited"
        );
        assert!(cache.renew_tcp(&key, strategy, &old));
        assert!(cache.current(&key, strategy, &old));
        let fresh = cache.insert(&key, Verdict::Verified(strategy)).unwrap();
        assert!(!cache.renew_tcp(&key, strategy, &old));
        cache.deny_tcp(&key, &old);
        assert!(cache.current(&key, strategy, &fresh));
        cache.deny_tcp(&key, &fresh);
        assert!(cache.denied_tcp(&key));
        assert!(!cache.renew_tcp(&key, strategy, &fresh));
    }

    #[test]
    fn unified_evidence_and_rankings_never_cross_tcp_udp_or_quic_versions() {
        use crate::quic_core::wire::Version;
        let cache = Cache::default();
        let address = "127.0.0.1:443".parse().unwrap();
        let mut key = Key {
            name: "example.org".into(),
            address,
            policy: [1; 32],
            epoch: 1,
            network: network_scope::Scope::fixture(address, 0),
        };
        let tcp = cache
            .insert(&key, Verdict::Verified(Strategy::Header))
            .unwrap();
        let v1 = UdpProbe::Quic(Version::V1);
        let v2 = UdpProbe::Quic(Version::V2);
        let old = cache.fixture_udp(&key, v1, true);
        let fresh = cache.fixture_udp(&key, v1, true);
        cache.fixture_udp(&key, v2, false);
        assert!(cache.current(&key, Strategy::Header, &tcp));
        assert!(cache.udp_evidence(&key, v1).unwrap().1.same(&fresh));
        assert!(!cache.udp_evidence(&key, v1).unwrap().1.same(&old));
        assert!(!cache.udp_evidence(&key, v2).unwrap().0);
        assert!(cache.udp_evidence(&key, UdpProbe::Stun).is_none());
        cache.sample_index(&key, v1.index(), false, Duration::ZERO);
        cache.sample_index(&key, v2.index(), true, Duration::from_millis(50));
        assert!(cache.udp_score(&key, v2) < cache.udp_score(&key, v1));
        assert_eq!(cache.ranked(&key), Strategy::ALL);
        key.epoch += 1;
        assert!(cache.evidence(&key).is_none());
        assert!(cache.udp_evidence(&key, v1).is_none());
        assert_eq!(cache.udp_score(&key, v1), 1000);
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
        let lease = cache
            .insert(&key, Verdict::Verified(Strategy::Middle))
            .unwrap();
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
        let old = cache
            .insert(&key, Verdict::Verified(Strategy::Header))
            .unwrap();
        let fresh = cache
            .insert(&key, Verdict::Verified(Strategy::Header))
            .unwrap();
        assert!(!cache.current(&key, Strategy::Header, &old));
        assert!(cache.current(&key, Strategy::Header, &fresh));
        cache.record_outcome(&key, Strategy::Header, &old, false, Duration::ZERO);
        cache.record_outcome(&key, Strategy::Header, &old, true, Duration::from_millis(1));
        assert!(cache.current(&key, Strategy::Header, &fresh));
        assert!(cache.1.lock().unwrap().is_empty());

        cache.record_outcome(&key, Strategy::Header, &fresh, false, Duration::ZERO);
        assert!(matches!(cache.cached(&key), Some(Verdict::Unavailable)));
        assert_eq!(
            cache.1.lock().unwrap().front().unwrap().samples[0].failures,
            1
        );
        // Repeated reports from the same failed lease cannot extend cooldown.
        let original = cache.0.lock().unwrap().front().unwrap().verdict;
        cache.record_outcome(&key, Strategy::Header, &fresh, false, Duration::ZERO);
        assert!(cache.0.lock().unwrap().front().unwrap().verdict == original);
        assert_eq!(
            cache.1.lock().unwrap().front().unwrap().samples[0].failures,
            1
        );

        // A retained lease cannot become current after expiry/eviction.
        cache.0.lock().unwrap().clear();
        let newest = cache
            .insert(&key, Verdict::Verified(Strategy::Header))
            .unwrap();
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
