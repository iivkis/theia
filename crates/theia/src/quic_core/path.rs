//! Connection-ID lifecycle and candidate-path validation state. No network
//! routing is performed here. Only authenticated packets may call the
//! receive/challenge methods; Initial AEAD alone is not authentication.
use super::recovery::PathBudget;
use subtle::ConstantTimeEq;
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

const MAX_CIDS: usize = 8;
const CHALLENGE_TTL: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    Conflict,
    Invalid,
    Random,
    Path,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionId {
    pub sequence: u64,
    pub cid: Vec<u8>,
    pub reset_token: [u8; 16],
}

pub struct PeerIds {
    entries: BTreeMap<u64, ConnectionId>,
    floor: u64,
    limit: usize,
    initial: Option<(Vec<u8>, Option<[u8; 16]>)>,
}

impl PeerIds {
    pub fn new(limit: usize) -> Result<Self, Error> {
        if !(2..=MAX_CIDS).contains(&limit) {
            return Err(Error::Limit);
        }
        Ok(Self {
            entries: BTreeMap::new(),
            floor: 0,
            limit,
            initial: None,
        })
    }

    /// Seed sequence zero from the authenticated handshake. An absent
    /// reset token is not replaced with a guessed or synthetic token.
    pub(crate) fn with_initial(cid: &[u8], token: Option<[u8; 16]>, limit: usize) -> Result<Self, Error> {
        if cid.is_empty() || cid.len() > 20 { return Err(Error::Invalid); }
        let mut ids = Self::new(limit)?;
        ids.initial = Some((cid.to_vec(), token));
        Ok(ids)
    }

    pub(crate) fn current(&self) -> Option<&[u8]> {
        if let Some((cid, _)) = &self.initial { return Some(cid); }
        self.entries.first_key_value().map(|(_, id)| id.cid.as_slice())
    }

    pub(crate) fn has_spare(&self) -> bool {
        self.entries.len() + usize::from(self.initial.is_some()) > 1
    }

    /// Select the lowest unused CID and retire the previous sequence. The
    /// monotone floor prevents a retransmitted NEW_CONNECTION_ID from
    /// resurrecting a CID already used on a different physical path.
    pub(crate) fn rotate(&mut self) -> Option<u64> {
        if !self.has_spare() { return None; }
        let retired = if self.initial.take().is_some() { 0 } else {
            self.entries.pop_first()?.0
        };
        self.floor = *self.entries.first_key_value()?.0;
        Some(retired)
    }

    /// Constant-time comparison of the trailing token against live peer
    /// CIDs. Caller must first rule out successful packet protection.
    pub(crate) fn matches_reset(&self, packet: &[u8]) -> bool {
        if packet.len() < 21 || packet[0] & 0x80 != 0 { return false; }
        let tail = &packet[packet.len()-16..];
        let mut matched = subtle::Choice::from(0);
        if let Some((_, Some(token))) = &self.initial { matched |= token.as_slice().ct_eq(tail); }
        for id in self.entries.values() { matched |= id.reset_token.as_slice().ct_eq(tail); }
        bool::from(matched)
    }

    /// Accept one authenticated NEW_CONNECTION_ID. Return sequences that
    /// the caller must acknowledge with RETIRE_CONNECTION_ID. No mutation
    /// on invalid input or excessive active count.
    pub fn insert(&mut self, id: ConnectionId, retire_prior_to: u64) -> Result<Vec<u64>, Error> {
        if id.cid.is_empty()
            || id.cid.len() > 20
            || id.sequence > super::wire::MAX_VARINT
            || retire_prior_to > id.sequence
        {
            return Err(Error::Invalid);
        }
        if let Some((initial, token)) = &mut self.initial {
            if id.sequence == 0 {
                if *initial != id.cid || token.is_some_and(|old| old != id.reset_token) {
                    return Err(Error::Conflict);
                }
                *token = Some(id.reset_token);
                return Ok(Vec::new());
            }
            if *initial == id.cid || token.is_some_and(|old| old == id.reset_token) {
                return Err(Error::Conflict);
            }
        }
        if let Some(old) = self.entries.get(&id.sequence) {
            if old != &id {
                return Err(Error::Conflict);
            }
        }
        if self.entries.values().any(|old| {
            old.sequence != id.sequence && (old.cid == id.cid || old.reset_token == id.reset_token)
        }) {
            return Err(Error::Conflict);
        }
        let floor = self.floor.max(retire_prior_to);
        if id.sequence < floor {
            return Ok(vec![id.sequence]);
        }
        let count = self.entries.keys().filter(|&&n| n >= floor).count()
            + usize::from(!self.entries.contains_key(&id.sequence))
            + usize::from(self.initial.is_some() && floor == 0);
        if count > self.limit {
            return Err(Error::Limit);
        }
        let mut retired: Vec<u64> = self
            .entries
            .keys()
            .copied()
            .filter(|n| *n < floor)
            .collect();
        if floor > 0 && self.initial.take().is_some() { retired.insert(0, 0); }
        self.entries.retain(|n, _| *n >= floor);
        self.floor = floor;
        self.entries.insert(id.sequence, id);
        Ok(retired)
    }

    pub fn get(&self, sequence: u64) -> Option<&ConnectionId> {
        self.entries.get(&sequence)
    }
}

struct Candidate {
    address: SocketAddr,
    challenge: [u8; 8],
    expires: Instant,
    budget: PathBudget,
    last_challenge: Option<Instant>,
}

/// One already validated active path and one bounded candidate. A valid
/// PATH_RESPONSE must match both the challenge and the candidate address.
/// Migration does not change authorization or recreate user admission.
pub struct Paths {
    active: SocketAddr,
    candidate: Option<Candidate>,
}

impl Paths {
    pub fn new_validated(active: SocketAddr) -> Self {
        Self {
            active,
            candidate: None,
        }
    }
    pub fn active(&self) -> SocketAddr {
        self.active
    }

    /// Start a candidate after an authenticated packet on a new address.
    /// Existing unexpired candidates cannot be replaced by another path.
    pub fn begin(
        &mut self,
        address: SocketAddr,
        received: u64,
        now: Instant,
    ) -> Result<[u8; 8], Error> {
        if address == self.active || address.port() == 0 || received == 0 {
            return Err(Error::Path);
        }
        if let Some(c) = self.candidate.as_mut() {
            if now < c.expires {
                if address != c.address {
                    return Err(Error::Path);
                }
                c.budget.received(received);
                return Ok(c.challenge);
            }
        }
        let mut challenge = [0; 8];
        SystemRandom::new()
            .fill(&mut challenge)
            .map_err(|_| Error::Random)?;
        let expires = now.checked_add(CHALLENGE_TTL).ok_or(Error::Limit)?;
        let mut budget = PathBudget::default();
        budget.received(received);
        self.candidate = Some(Candidate {
            address,
            challenge,
            expires,
            budget,
            last_challenge: None,
        });
        Ok(challenge)
    }

    pub fn reserve_candidate_send(
        &mut self,
        address: SocketAddr,
        bytes: u64,
        now: Instant,
    ) -> bool {
        self.candidate.as_mut().is_some_and(|c| {
            address == c.address && now < c.expires && c.budget.reserve_send(bytes)
        })
    }

    pub fn reserve_challenge(
        &mut self,
        address: SocketAddr,
        bytes: u64,
        now: Instant,
        interval: Duration,
    ) -> bool {
        let Some(c) = self.candidate.as_mut() else {
            return false;
        };
        if c.address != address
            || now >= c.expires
            || c.last_challenge
                .is_some_and(|sent| now.saturating_duration_since(sent) < interval)
            || !c.budget.reserve_send(bytes)
        {
            return false;
        }
        c.last_challenge = Some(now);
        true
    }

    /// Return a timer only while a retry fits the candidate amplification budget.
    pub fn challenge_deadline(&self, bytes: u64, interval: Duration) -> Option<Instant> {
        let c = self.candidate.as_ref()?;
        if !c.budget.can_send(bytes) {
            return None;
        }
        let at = match c.last_challenge {
            Some(sent) => sent.checked_add(interval.max(Duration::from_millis(1)))?,
            None => c.expires.checked_sub(CHALLENGE_TTL)?,
        };
        (at < c.expires).then_some(at)
    }

    pub fn due_challenge(
        &self,
        bytes: u64,
        now: Instant,
        interval: Duration,
    ) -> Option<(SocketAddr, [u8; 8])> {
        let c = self.candidate.as_ref()?;
        if now >= c.expires || now < self.challenge_deadline(bytes, interval)? {
            return None;
        }
        Some((c.address, c.challenge))
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.candidate.as_ref().map(|c| c.expires)
    }

    pub fn expire(&mut self, now: Instant) {
        if self.deadline().is_some_and(|at| now >= at) {
            self.candidate = None;
        }
    }

    pub fn response(&mut self, address: SocketAddr, response: [u8; 8], now: Instant) -> bool {
        if !self.candidate.as_ref().is_some_and(|c| {
            address == c.address
                && now < c.expires
                && c.last_challenge.is_some()
                && response == c.challenge
        }) {
            return false;
        }
        self.active = address;
        self.candidate = None;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(n: u64) -> ConnectionId {
        ConnectionId {
            sequence: n,
            cid: vec![n as u8; 8],
            reset_token: [n as u8; 16],
        }
    }

    #[test]
    fn cid_retirement_and_conflicts() {
        let mut ids = PeerIds::new(2).unwrap();
        ids.insert(cid(0), 0).unwrap();
        ids.insert(cid(1), 0).unwrap();
        assert_eq!(ids.insert(cid(2), 0), Err(Error::Limit));
        let mut conflict = cid(1);
        conflict.reset_token = [4; 16];
        assert_eq!(ids.insert(conflict, 0), Err(Error::Conflict));
        assert_eq!(ids.insert(cid(2), 1), Ok(vec![0]));
        assert!(ids.get(0).is_none());
        assert_eq!(ids.insert(cid(0), 0), Ok(vec![0]));
        assert_eq!(ids.get(2), Some(&cid(2)));
    }

    #[test]
    fn live_reset_tokens_and_cid_rotation() {
        let mut ids = PeerIds::with_initial(&[9; 8], Some([9; 16]), 2).unwrap();
        assert_eq!(ids.current(), Some([9; 8].as_slice()));
        let mut reset = vec![0x40; 21];
        reset[5..].fill(9);
        assert!(ids.matches_reset(&reset));
        assert!(!ids.matches_reset(&reset[1..]));
        ids.insert(cid(1), 0).unwrap();
        assert_eq!(ids.insert(cid(2), 0), Err(Error::Limit));
        assert_eq!(ids.rotate(), Some(0));
        assert_eq!(ids.current(), Some([1; 8].as_slice()));
        assert!(!ids.matches_reset(&reset));
        reset[5..].fill(1);
        assert!(ids.matches_reset(&reset));
        assert_eq!(ids.insert(cid(0), 0), Ok(vec![0]));
        assert_eq!(ids.rotate(), None);
        assert_eq!(ids.insert(cid(2), 2), Ok(vec![1]));
        assert_eq!(ids.current(), Some([2; 8].as_slice()));
    }

    #[test]
    fn lost_challenge_retries_until_amplification_budget_exhausted() {
        let active = "127.0.0.1:1000".parse().unwrap();
        let next = "127.0.0.1:1001".parse().unwrap();
        let now = Instant::now();
        let pto = Duration::from_millis(100);
        let mut paths = Paths::new_validated(active);
        let challenge = paths.begin(next, 1200, now).unwrap();
        assert!(paths.reserve_challenge(next, 1200, now, pto));
        assert_eq!(paths.challenge_deadline(1200, pto), Some(now + pto));
        assert_eq!(paths.due_challenge(1200, now, pto), None);
        for at in [now + pto, now + 2 * pto] {
            assert_eq!(paths.due_challenge(1200, at, pto), Some((next, challenge)));
            assert!(paths.reserve_challenge(next, 1200, at, pto));
        }
        assert_eq!(paths.challenge_deadline(1200, pto), None);
        assert!(!paths.reserve_challenge(next, 1200, now + 3 * pto, pto));
        assert_eq!(paths.active(), active);
        assert!(paths.response(next, challenge, now + 3 * pto));
        assert_eq!(paths.active(), next);
    }

    #[test]
    fn challenge_is_bound_to_address_and_budget() {
        let active = "127.0.0.1:1000".parse().unwrap();
        let next = "127.0.0.1:1001".parse().unwrap();
        let other = "127.0.0.1:1002".parse().unwrap();
        let now = Instant::now();
        let mut paths = Paths::new_validated(active);
        let challenge = paths.begin(next, 100, now).unwrap();
        assert!(!paths.response(next, challenge, now));
        assert!(paths.reserve_challenge(next, 300, now, Duration::from_secs(1)));
        assert!(!paths.reserve_challenge(next, 1, now, Duration::from_secs(1)));
        assert!(!paths.reserve_candidate_send(next, 1, now));
        assert_eq!(paths.begin(other, 100, now), Err(Error::Path));
        assert!(!paths.response(other, challenge, now));
        assert!(!paths.response(next, challenge, now + CHALLENGE_TTL));
        assert_eq!(paths.active(), active);
        let challenge = paths.begin(next, 100, now + CHALLENGE_TTL).unwrap();
        assert!(!paths.response(next, challenge, now + CHALLENGE_TTL));
        assert!(paths.reserve_challenge(next, 300, now + CHALLENGE_TTL, Duration::from_secs(1)));
        assert!(paths.response(next, challenge, now + CHALLENGE_TTL));
        assert_eq!(paths.active(), next);
        assert!(!paths.response(next, challenge, now + CHALLENGE_TTL));
    }
}
