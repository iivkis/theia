//! Bounded DNS wire adapter. No DNSSEC assertion or flow attribution.
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

/// A bounded diagnostic hint for selecting a STUN probe. This is NOT a
/// DNS cache, a request-to-application link, or trusted domain evidence.
/// A fresh authenticated lookup and an independently conclusive Unknown
/// policy are mandatory before any egress based on this hint.
#[derive(Default)]
pub(crate) struct ProbeHints {
    entries: HashMap<(IpAddr, IpAddr, [u8; 32]), Hint>,
}
struct Hint {
    name: String,
    deadline: Instant,
    ambiguous: bool,
}
impl ProbeHints {
    const CAPACITY: usize = 4096;
    const WINDOW: Duration = Duration::from_secs(5);

    pub(crate) fn record(&mut self, source: IpAddr, digest: [u8; 32], name: &str, ips: &[IpAddr]) {
        self.record_at(source, digest, name, ips, Instant::now());
    }

    fn record_at(
        &mut self,
        source: IpAddr,
        digest: [u8; 32],
        name: &str,
        ips: &[IpAddr],
        now: Instant,
    ) {
        self.entries.retain(|_, entry| entry.deadline > now);
        for &ip in ips {
            let key = (source, ip, digest);
            if let Some(entry) = self.entries.get_mut(&key) {
                if entry.name != name {
                    entry.ambiguous = true;
                }
                // Do not renew an existing observation.
            } else if self.entries.len() < Self::CAPACITY {
                self.entries.insert(
                    key,
                    Hint {
                        name: name.to_owned(),
                        deadline: now + Self::WINDOW,
                        ambiguous: false,
                    },
                );
            }
        }
    }

    pub(crate) fn get(&self, source: IpAddr, ip: IpAddr, digest: [u8; 32]) -> Option<String> {
        self.get_at(source, ip, digest, Instant::now())
    }

    fn get_at(&self, source: IpAddr, ip: IpAddr, digest: [u8; 32], now: Instant) -> Option<String> {
        let entry = self.entries.get(&(source, ip, digest))?;
        (!entry.ambiguous && entry.deadline > now).then(|| entry.name.clone())
    }
}

/// Per-flow, one-shot commitments to actual NFQUEUE UDP DNS payloads.
/// Created only by the owned policy queue before the TPROXY verdict;
/// consumed by the local resolver on exact delivery. The commitment is
/// not a PID, socket cookie or application identity. Any loss, reorder,
/// mismatch or timeout retires the flow instead of guessing provenance.
#[cfg(target_os = "linux")]
#[derive(Default)]
pub(crate) struct CapturedQueries {
    pending: std::collections::VecDeque<([u8; 32], Instant)>,
    retired: bool,
}
#[cfg(target_os = "linux")]
impl CapturedQueries {
    const LIMIT: usize = 64;
    const WINDOW: Duration = Duration::from_secs(10);

    fn digest(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).into()
    }
    pub(crate) fn record(&mut self, bytes: &[u8]) -> bool {
        self.record_at(bytes, Instant::now())
    }
    fn record_at(&mut self, bytes: &[u8], now: Instant) -> bool {
        if self.retired
            || self.pending.len() >= Self::LIMIT
            || Question::parse(bytes).is_none()
            || self
                .pending
                .front()
                .is_some_and(|(_, deadline)| *deadline <= now)
        {
            self.retire();
            return false;
        }
        self.pending
            .push_back((Self::digest(bytes), now + Self::WINDOW));
        true
    }
    pub(crate) fn consume(&mut self, bytes: &[u8]) -> bool {
        self.consume_at(bytes, Instant::now())
    }
    fn consume_at(&mut self, bytes: &[u8], now: Instant) -> bool {
        if self.retired
            || !self
                .pending
                .pop_front()
                .is_some_and(|(digest, deadline)| deadline > now && digest == Self::digest(bytes))
        {
            self.retire();
            return false;
        }
        true
    }
    pub(crate) fn retire(&mut self) {
        self.retired = true;
        self.pending.clear();
    }
}

pub(crate) const MAX_QUERY: usize = 4096;
const MAX_UDP: usize = 1232;
const MAX_TCP: usize = 4096;
pub(crate) struct Question {
    id: [u8; 2],
    rd: u16,
    name: String,
    wire: Vec<u8>,
    kind: u16,
    limit: usize,
    edns: bool,
}
fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}
impl Question {
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        if !(12..=MAX_QUERY).contains(&bytes.len())
            || word(bytes, 4) != Some(1)
            || word(bytes, 6) != Some(0)
            || word(bytes, 8) != Some(0)
        {
            return None;
        }
        let flags = word(bytes, 2)?;
        if flags & !0x0100 != 0 {
            return None;
        }
        let mut offset = 12usize;
        let mut labels = Vec::new();
        loop {
            let len = usize::from(*bytes.get(offset)?);
            offset += 1;
            if len == 0 {
                break;
            }
            if len > 63 || offset.checked_add(len)? - 12 > 254 {
                return None;
            }
            let label = std::str::from_utf8(bytes.get(offset..offset + len)?).ok()?;
            if label.contains('.') {
                return None;
            }
            labels.push(label);
            offset += len;
        }
        let name = super::domain_name(&labels.join(".")).ok()?;
        let kind = word(bytes, offset)?;
        if ![1, 28].contains(&kind) || word(bytes, offset + 2) != Some(1) {
            return None;
        }
        offset += 4;
        let (edns, limit) = match word(bytes, 10)? {
            0 if offset == bytes.len() => (false, 512),
            1 if bytes.len() == offset + 11
                && bytes[offset] == 0
                && word(bytes, offset + 1) == Some(41)
                && bytes[offset + 5..offset + 11] == [0; 6] =>
            {
                (
                    true,
                    usize::from(word(bytes, offset + 3)?).clamp(512, MAX_UDP),
                )
            }
            _ => return None,
        };
        Some(Self {
            id: bytes[..2].try_into().ok()?,
            rd: flags,
            name,
            wire: bytes[12..offset].to_vec(),
            kind,
            limit,
            edns,
        })
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    /// Only addresses actually present in a non-truncated answer can
    /// be used as diagnostic hints. They carry no authoritative TTL.
    pub(crate) fn hint_ips(&self, answer: &[u8], ips: &[IpAddr]) -> Vec<IpAddr> {
        if word(answer, 2).is_none_or(|flags| flags & 0x020f != 0) || word(answer, 6) == Some(0) {
            return Vec::new();
        }
        ips.iter()
            .copied()
            .filter(|ip| {
                if self.kind == 1 {
                    ip.is_ipv4()
                } else {
                    ip.is_ipv6()
                }
            })
            .collect()
    }
    fn header(&self, flags: u16, count: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&(0x8080 | self.rd | flags).to_be_bytes());
        for v in [1u16, count, 0, u16::from(self.edns)] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out.extend_from_slice(&self.wire);
        out
    }
    fn opt(&self, out: &mut Vec<u8>) {
        if self.edns {
            out.extend_from_slice(&[0, 0, 41]);
            out.extend_from_slice(&(self.limit as u16).to_be_bytes());
            out.extend_from_slice(&[0; 6]);
        }
    }
    pub(crate) fn failure(&self) -> Vec<u8> {
        let mut out = self.header(2, 0); // SERVFAIL; never synthesize NXDOMAIN
        self.opt(&mut out);
        out
    }
    pub(crate) fn answer(&self, ips: &[IpAddr], tcp: bool) -> Vec<u8> {
        if ips.len() > 64 {
            return self.failure();
        }
        let addresses = ips
            .iter()
            .filter(|ip| {
                if self.kind == 1 {
                    ip.is_ipv4()
                } else {
                    ip.is_ipv6()
                }
            })
            .collect::<Vec<_>>();
        let mut out = self.header(0, addresses.len() as u16);
        for ip in addresses {
            let bytes = match ip {
                IpAddr::V4(v) => v.octets().to_vec(),
                IpAddr::V6(v) => v.octets().to_vec(),
            };
            out.extend_from_slice(&[0xc0, 0x0c]);
            out.extend_from_slice(&self.kind.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes()); // no authoritative TTL
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        self.opt(&mut out);
        if out.len() > (if tcp { MAX_TCP } else { self.limit }) {
            out = self.header(0x0200, 0);
            self.opt(&mut out);
        }
        out
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07Example\x03org\x00\x00\x01\x00\x01");
        q
    }
    #[test]
    fn probe_hint_is_scoped_ambiguous_and_nonrenewable() {
        let source = "192.0.2.1".parse().unwrap();
        let other = "192.0.2.2".parse().unwrap();
        let ip = "198.51.100.1".parse().unwrap();
        let now = Instant::now();
        let mut hints = ProbeHints::default();
        hints.record_at(source, [1; 32], "one.example", &[ip], now);
        assert_eq!(
            hints.get_at(source, ip, [1; 32], now).as_deref(),
            Some("one.example")
        );
        assert!(hints.get_at(other, ip, [1; 32], now).is_none());
        assert!(hints.get_at(source, ip, [2; 32], now).is_none());
        hints.record_at(
            source,
            [1; 32],
            "one.example",
            &[ip],
            now + Duration::from_secs(4),
        );
        assert!(hints
            .get_at(source, ip, [1; 32], now + Duration::from_secs(5))
            .is_none());
        hints.record_at(
            source,
            [1; 32],
            "two.example",
            &[ip],
            now + Duration::from_secs(4),
        );
        assert!(hints
            .get_at(source, ip, [1; 32], now + Duration::from_secs(4))
            .is_none());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn captured_dns_is_exact_one_shot_ordered_and_bounded() {
        let q = query();
        let mut other = q.clone();
        other[0] ^= 1; // same name, different transaction
        let now = Instant::now();
        let mut capture = CapturedQueries::default();
        assert!(capture.record_at(&q, now));
        assert!(capture.record_at(&other, now));
        assert!(capture.consume_at(&q, now));
        assert!(capture.consume_at(&other, now));
        assert!(!capture.consume_at(&other, now)); // replay
        assert!(!capture.record_at(&q, now));
        let mut capture = CapturedQueries::default();
        assert!(capture.record_at(&q, now));
        assert!(!capture.consume_at(&other, now)); // reordered/forged
        assert!(!capture.consume_at(&q, now));
        let mut capture = CapturedQueries::default();
        assert!(capture.record_at(&q, now));
        assert!(!capture.consume_at(&q, now + CapturedQueries::WINDOW));
        let mut capture = CapturedQueries::default();
        for _ in 0..CapturedQueries::LIMIT {
            assert!(capture.record_at(&q, now));
        }
        assert!(!capture.record_at(&q, now));
        assert!(!capture.consume_at(&q, now));
    }
    #[test]
    fn exact_question_zero_ttl_family_and_truncation() {
        let raw = query();
        let q = Question::parse(&raw).unwrap();
        assert_eq!(q.name(), "example.org");
        let answer = q.answer(
            &["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            false,
        );
        assert_eq!(&answer[..2], &raw[..2]);
        assert_eq!(word(&answer, 6), Some(1));
        assert_eq!(&answer[12..raw.len()], &raw[12..]);
        assert_eq!(&answer[raw.len() + 6..raw.len() + 10], &[0; 4]);
        let ips = (1..=64)
            .map(|n| IpAddr::from([192, 0, 2, n]))
            .collect::<Vec<_>>();
        let short = q.answer(&ips, false);
        assert_eq!(word(&short, 2).unwrap() & 0x0200, 0x0200);
        assert_eq!(word(&short, 6), Some(0));
        assert_eq!(word(&q.answer(&ips, true), 6), Some(64));
        assert_eq!(word(&q.failure(), 2).unwrap() & 15, 2);
    }
    #[test]
    fn rejects_compression_multiple_questions_and_unsupported_edns() {
        let raw = query();
        for end in 0..raw.len() {
            assert!(Question::parse(&raw[..end]).is_none());
        }
        let mut q = raw.clone();
        q[12] = 0xc0;
        assert!(Question::parse(&q).is_none());
        let mut q = raw.clone();
        q[5] = 2;
        assert!(Question::parse(&q).is_none());
        let mut q = raw;
        q[11] = 1;
        q.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        assert!(Question::parse(&q).is_some());
        let n = q.len();
        q[n - 4] = 0x80;
        assert!(Question::parse(&q).is_none());
    }
}
