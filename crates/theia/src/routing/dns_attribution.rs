//! Bounded correlation of a resolver's claimed request link with a
//! corroborated OS flow and an authenticated DNS pin set. This deliberately
//! produces a candidate observation, NOT Evidence::Known: the production
//! resolver event provenance and capture-side cookie binding remain open.
use super::{linux_events::CorroboratedFlow, packet::FlowKey, RoutingError};
use std::{collections::HashMap, net::IpAddr, time::{Duration, Instant}};

const MAX_ENTRIES: usize = 4096;
const TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverLink {
    pub key: FlowKey,
    pub cookie: u64,
    pub process_start: u64,
    pub request_id: [u8;16],
    pub domain: String,
}
struct Entry {
    flow: CorroboratedFlow,
    digest: [u8;32],
    request_id: [u8;16],
    domain: String,
    deadline: Instant,
    ambiguous: bool,
}
#[derive(Default)]
pub struct DnsCandidates {
    entries: HashMap<FlowKey, Entry>,
}
impl DnsCandidates {
    /// Returns false for missing/ambiguous association, stale/different flow
    /// or quota failure. The protected resolver response must be fetched
    /// for the exact policy digest and requested domain by the caller.
    pub fn record(&mut self, flow: CorroboratedFlow, link: &ResolverLink,
        digest: [u8;32], protected_ips: &[IpAddr]) -> Result<bool, RoutingError> {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.deadline > now);
        let name = super::domain_name(&link.domain)?;
        if link.key != flow.key || link.cookie != flow.cookie || link.process_start != flow.process_start
            || link.request_id == [0;16] || digest == [0;32] || protected_ips.len() > 64
            || !protected_ips.contains(&flow.key.destination.ip()) {
            return Ok(false);
        }
        if let Some(entry) = self.entries.get_mut(&flow.key) {
            if entry.flow != flow || entry.digest != digest || entry.domain != name || entry.request_id != link.request_id {
                entry.ambiguous = true;
            }
            return Ok(!entry.ambiguous);
        }
        if self.entries.len() >= MAX_ENTRIES { return Ok(false); }
        self.entries.insert(flow.key, Entry {
            flow, digest, request_id: link.request_id, domain: name,
            deadline: now + TTL, ambiguous: false,
        });
        Ok(true)
    }

    /// The exact flow observation and policy generation are mandatory.
    /// No reverse DNS, destination-only lookup or ambiguous fallback.
    pub fn candidate(&self, flow: CorroboratedFlow, digest: [u8;32]) -> Option<&str> {
        let entry = self.entries.get(&flow.key)?;
        (entry.flow == flow && entry.digest == digest && !entry.ambiguous && entry.deadline > Instant::now())
            .then_some(entry.domain.as_str())
    }
    pub fn forget(&mut self, flow: CorroboratedFlow) {
        if self.entries.get(&flow.key).is_some_and(|entry| entry.flow == flow) {
            self.entries.remove(&flow.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{ApplicationId, packet::Transport};
    #[test]
    fn dns_link_never_crosses_socket_generation_or_ambiguous_request() {
        let flow = CorroboratedFlow {
            key: FlowKey { source: "192.0.2.2:1234".parse().unwrap(), destination: "198.51.100.1:443".parse().unwrap(), transport: Transport::Tcp, interface: 0 },
            cookie: 7, process_start: 8, application: ApplicationId::from_sha256([1;32]),
        };
        let mut link = ResolverLink { key: flow.key, cookie: 7, process_start: 8, request_id: [3;16], domain: "example.org".into() };
        let mut table = DnsCandidates::default();
        assert!(!table.record(flow, &link, [1;32], &[]).unwrap());
        let ips = [flow.key.destination.ip()];
        assert!(table.record(flow, &link, [1;32], &ips).unwrap());
        assert_eq!(table.candidate(flow,[1;32]), Some("example.org"));
        assert!(table.candidate(flow,[2;32]).is_none());
        assert!(table.candidate(CorroboratedFlow { cookie: 9, ..flow },[1;32]).is_none());
        link.domain = "other.example".into();
        link.request_id = [4;16];
        assert!(!table.record(flow, &link,[1;32], &ips).unwrap());
        assert!(table.candidate(flow,[1;32]).is_none());
        table.forget(flow);
        assert!(table.candidate(flow,[1;32]).is_none());
    }
}
