//! Bounded correlation of a resolver's claimed request link with a
//! corroborated OS flow and an authenticated DNS pin set. This deliberately
//! produces a candidate observation, NOT Evidence::Known: the production
//! resolver event provenance and capture-side cookie binding remain open.
use super::{linux_events::CorroboratedFlow, packet::FlowKey, RoutingError};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::{Duration, Instant},
};

const MAX_ENTRIES: usize = 4096;
const TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverLink {
    pub key: FlowKey,
    pub cookie: u64,
    pub process_start: u64,
    pub request_id: [u8; 16],
    pub domain: String,
}
struct Entry {
    flow: CorroboratedFlow,
    digest: [u8; 32],
    request_id: [u8; 16],
    domain: String,
    deadline: Instant,
    ambiguous: bool,
}
#[derive(Default)]
pub struct DnsCandidates {
    entries: HashMap<FlowKey, Entry>,
    // Request IDs survive flow retirement for the bounded collector epoch.
    // A replay on a different socket cannot gain a fresh deadline.
    used_requests: HashSet<[u8; 16]>,
}
impl DnsCandidates {
    /// Returns false for missing/ambiguous association, stale/different flow
    /// or quota failure. The protected resolver response must be fetched
    /// for the exact policy digest and requested domain by the caller.
    /// A caller-provided monotonic observation deadline is mandatory.
    /// The current protected DNS wire format carries no authoritative TTL;
    /// this limit is not proof of DNS freshness or sender identity.
    pub fn record(
        &mut self,
        flow: CorroboratedFlow,
        link: &ResolverLink,
        digest: [u8; 32],
        protected_ips: &[IpAddr],
        observation_deadline: Instant,
    ) -> Result<bool, RoutingError> {
        self.record_at(
            flow,
            link,
            digest,
            protected_ips,
            observation_deadline,
            Instant::now(),
        )
    }

    fn record_at(
        &mut self,
        flow: CorroboratedFlow,
        link: &ResolverLink,
        digest: [u8; 32],
        protected_ips: &[IpAddr],
        observation_deadline: Instant,
        now: Instant,
    ) -> Result<bool, RoutingError> {
        // Retain expired entries as bounded tombstones until the owning
        // flow is explicitly forgotten. An old request must not gain a
        // fresh deadline just because its diagnostic observation expired.
        // On exhaustion refuse new observations; never evict a tombstone
        // to make room for an uncorroborated request.
        let name = match super::domain_name(&link.domain) {
            Ok(name) => name,
            Err(error) => {
                self.poison_key(flow.key);
                return Err(error);
            }
        };
        if link.key != flow.key
            || link.cookie != flow.cookie
            || link.process_start != flow.process_start
            || flow.cookie == 0
            || flow.process_start == 0
            || observation_deadline <= now
            || link.request_id == [0; 16]
            || digest == [0; 32]
            || protected_ips.len() > 64
            || !protected_ips.contains(&flow.key.destination.ip())
        {
            self.poison_key(flow.key);
            return Ok(false);
        }
        // A request identifier is scoped to one exact flow. A conflicting
        // observation must revoke BOTH candidates, not authorize the
        // latest caller or leave the original observation usable.
        let mut reused = false;
        for (key, entry) in &mut self.entries {
            if *key != flow.key && entry.request_id == link.request_id {
                entry.ambiguous = true;
                reused = true;
            }
        }
        if reused {
            self.poison_key(flow.key);
            return Ok(false);
        }
        if let Some(entry) = self.entries.get_mut(&flow.key) {
            if entry.deadline <= now {
                return Ok(false);
            }
            if entry.flow != flow
                || entry.digest != digest
                || entry.domain != name
                || entry.request_id != link.request_id
            {
                entry.ambiguous = true;
            }
            // Re-observation must not extend an existing candidate or
            // outlive the shortest accepted observation deadline.
            entry.deadline = entry.deadline.min(observation_deadline);
            return Ok(!entry.ambiguous);
        }
        if self.entries.len() >= MAX_ENTRIES || self.used_requests.len() >= MAX_ENTRIES
            || !self.used_requests.insert(link.request_id) {
            return Ok(false);
        }
        self.entries.insert(
            flow.key,
            Entry {
                flow,
                digest,
                request_id: link.request_id,
                domain: name,
                deadline: now
                    .checked_add(TTL)
                    .unwrap_or(now)
                    .min(observation_deadline),
                ambiguous: false,
            },
        );
        Ok(true)
    }

    /// The exact flow observation and policy generation are mandatory.
    /// No reverse DNS, destination-only lookup or ambiguous fallback.
    pub fn candidate(&self, flow: CorroboratedFlow, digest: [u8; 32]) -> Option<&str> {
        self.candidate_at(flow, digest, Instant::now())
    }

    fn candidate_at(&self, flow: CorroboratedFlow, digest: [u8; 32], now: Instant) -> Option<&str> {
        let entry = self.entries.get(&flow.key)?;
        (entry.flow == flow && entry.digest == digest && !entry.ambiguous && entry.deadline > now)
            .then_some(entry.domain.as_str())
    }
    fn poison_key(&mut self, key: FlowKey) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.ambiguous = true;
        }
    }

    /// Poison rather than delete after an uncertain source check. Removing
    /// a failed candidate would allow the same request to create a fresh TTL.
    pub(crate) fn invalidate(&mut self, flow: CorroboratedFlow) {
        self.poison_key(flow.key);
    }

    pub fn forget(&mut self, flow: CorroboratedFlow) {
        if self
            .entries
            .get(&flow.key)
            .is_some_and(|entry| entry.flow == flow)
        {
            self.entries.remove(&flow.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{packet::Transport, ApplicationId};
    #[test]
    fn dns_link_never_crosses_socket_generation_or_ambiguous_request() {
        let flow = CorroboratedFlow {
            key: FlowKey {
                source: "192.0.2.2:1234".parse().unwrap(),
                destination: "198.51.100.1:443".parse().unwrap(),
                transport: Transport::Tcp,
                interface: 0,
            },
            cookie: 7,
            process_start: 8,
            application: ApplicationId::from_sha256([1; 32]),
        };
        let mut link = ResolverLink {
            key: flow.key,
            cookie: 7,
            process_start: 8,
            request_id: [3; 16],
            domain: "example.org".into(),
        };
        let mut table = DnsCandidates::default();
        let deadline = Instant::now() + TTL;
        assert!(!table.record(flow, &link, [1; 32], &[], deadline).unwrap());
        let ips = [flow.key.destination.ip()];
        assert!(table.record(flow, &link, [1; 32], &ips, deadline).unwrap());
        assert_eq!(table.candidate(flow, [1; 32]), Some("example.org"));
        assert!(table.candidate(flow, [2; 32]).is_none());
        assert!(table
            .candidate(CorroboratedFlow { cookie: 9, ..flow }, [1; 32])
            .is_none());
        table.invalidate(flow);
        assert!(table.candidate(flow, [1; 32]).is_none());
        assert!(!table.record(flow, &link, [1; 32], &ips, deadline).unwrap());
        link.domain = "other.example".into();
        link.request_id = [4; 16];
        assert!(!table.record(flow, &link, [1; 32], &ips, deadline).unwrap());
        assert!(table.candidate(flow, [1; 32]).is_none());
        table.forget(flow);
        assert!(table.candidate(flow, [1; 32]).is_none());
        // Retiring the exact socket never re-arms a previously used ID.
        link.domain = "example.org".into();
        link.request_id = [3; 16];
        assert!(!table.record(flow, &link, [1; 32], &ips, deadline).unwrap());
        let mut other=flow;
        other.key.source.set_port(1235);
        other.cookie=9;
        link.key=other.key;
        link.cookie=other.cookie;
        assert!(!table.record(other,&link,[1;32],&ips,deadline).unwrap());
    }

    #[test]
    fn conflicting_requests_and_invalid_observations_revoke_candidates() {
        let flow = CorroboratedFlow {
            key: FlowKey {
                source: "192.0.2.2:1234".parse().unwrap(),
                destination: "198.51.100.1:443".parse().unwrap(),
                transport: Transport::Udp,
                interface: 0,
            },
            cookie: 7,
            process_start: 8,
            application: ApplicationId::from_sha256([1; 32]),
        };
        let link = ResolverLink {
            key: flow.key,
            cookie: flow.cookie,
            process_start: flow.process_start,
            request_id: [3; 16],
            domain: "example.org".into(),
        };
        let ips = [flow.key.destination.ip()];
        let deadline = Instant::now() + TTL;
        let mut table = DnsCandidates::default();
        assert!(table.record(flow, &link, [1; 32], &ips, deadline).unwrap());
        let mut other = flow;
        other.key.source.set_port(1235);
        other.cookie = 9;
        let mut copied = link.clone();
        copied.key = other.key;
        copied.cookie = other.cookie;
        assert!(!table.record(other, &copied, [1; 32], &ips, deadline).unwrap());
        assert!(table.candidate(flow, [1; 32]).is_none());
        assert!(table.candidate(other, [1; 32]).is_none());
        let mut table = DnsCandidates::default();
        assert!(table.record(flow, &link, [1; 32], &ips, deadline).unwrap());
        assert!(!table.record(flow, &link, [1; 32], &[], deadline).unwrap());
        assert!(table.candidate(flow, [1; 32]).is_none());
        assert!(!table.record(flow, &link, [1; 32], &ips, deadline).unwrap());
    }

    #[test]
    fn candidate_never_outlives_observation_or_refreshes_by_replay() {
        let flow = CorroboratedFlow {
            key: FlowKey {
                source: "192.0.2.2:1234".parse().unwrap(),
                destination: "198.51.100.1:443".parse().unwrap(),
                transport: Transport::Udp,
                interface: 0,
            },
            cookie: 7,
            process_start: 8,
            application: ApplicationId::from_sha256([1; 32]),
        };
        let link = ResolverLink {
            key: flow.key,
            cookie: 7,
            process_start: 8,
            request_id: [3; 16],
            domain: "example.org".into(),
        };
        let ips = [flow.key.destination.ip()];
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        let mut table = DnsCandidates::default();
        assert!(!table
            .record_at(flow, &link, [1; 32], &ips, now, now)
            .unwrap());
        assert!(table
            .record_at(flow, &link, [1; 32], &ips, deadline, now)
            .unwrap());
        assert!(table
            .record_at(
                flow,
                &link,
                [1; 32],
                &ips,
                now + TTL,
                now + Duration::from_secs(1)
            )
            .unwrap());
        assert_eq!(
            table.candidate_at(flow, [1; 32], now + Duration::from_secs(4)),
            Some("example.org")
        );
        assert!(table.candidate_at(flow, [1; 32], deadline).is_none());
        assert!(!table
            .record_at(flow, &link, [1; 32], &ips, deadline, deadline)
            .unwrap());
        // A new protected DNS exchange alone does not establish a fresh
        // resolver event or prove a different sender on the same socket.
        assert!(!table
            .record_at(flow, &link, [1; 32], &ips, deadline + TTL, deadline)
            .unwrap());
        let mut changed = link.clone();
        changed.request_id = [5; 16];
        assert!(!table
            .record_at(flow, &changed, [1; 32], &ips, deadline + TTL, deadline)
            .unwrap());
        assert!(table.candidate_at(flow, [1; 32], deadline).is_none());
    }
}
