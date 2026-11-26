//! Bounded receive-side connection and stream flow accounting. This is
//! not the send-side flow controller or a complete QUIC stream lifecycle.
use super::{
    stream::{ReceiveBuffer, ReceiveError, MAX_WINDOW},
    wire::MAX_VARINT,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

const MAX_STREAMS: u64 = 64;
const MAX_STREAM_COUNT: u64 = 1 << 60;
const RECENT_CLOSED: usize = 64;
const MAX_TOTAL_WINDOW: usize = 8 * 1024 * 1024;
const MAX_ADAPTIVE_STREAM: usize = 256 * 1024;
const MAX_ADAPTIVE_CONNECTION: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    StreamId,
    Receive(ReceiveError),
}

pub struct ReceiveFlow {
    peer_bit: u64,
    max_bidi: u64,
    max_uni: u64,
    max_local_bidi: u64,
    stream_limit: u64,
    window: usize,
    max_data: u64,
    used: u64,
    adaptive_cap: Option<usize>,
    connection_window: u64,
    consumed: u64,
    tune_epoch: Option<(Instant, u64)>,
    streams: BTreeMap<u64, ReceiveBuffer>,
    // Exclusive high-water mark by stream type. Every lower ID is either
    // active or closed, never reopened. Peer IDs are opened implicitly.
    opened: [u64; 4],
    recent_closed: BTreeMap<u64, ReceiveBuffer>,
}

impl ReceiveFlow {
    /// Only peer-initiated receive directions are admitted by this stage.
    pub fn new(
        local_server: bool,
        max_bidi: u64,
        max_uni: u64,
        stream_limit: u64,
        window: usize,
        max_data: u64,
    ) -> Result<Self, Error> {
        let count = max_bidi.checked_add(max_uni).ok_or(Error::Limit)?;
        if count > MAX_STREAMS
            || window == 0
            || window > MAX_WINDOW
            || (count as usize).saturating_mul(window) > MAX_TOTAL_WINDOW
            || stream_limit > MAX_VARINT
            || max_data > MAX_VARINT
        {
            return Err(Error::Limit);
        }
        Ok(Self {
            peer_bit: u64::from(!local_server),
            max_bidi,
            max_uni,
            max_local_bidi: 0,
            stream_limit,
            window,
            max_data,
            used: 0,
            adaptive_cap: None,
            connection_window: max_data,
            consumed: 0,
            tune_epoch: None,
            streams: BTreeMap::new(),
            opened: [0; 4],
            recent_closed: BTreeMap::new(),
        })
    }

    pub fn enable_local_bidi(&mut self, limit: u64) -> Result<(), Error> {
        let count = self
            .max_bidi
            .checked_add(self.max_uni)
            .and_then(|n| n.checked_add(limit))
            .ok_or(Error::Limit)?;
        if count > MAX_STREAMS
            || (count as usize).saturating_mul(self.window) > MAX_TOTAL_WINDOW
            || self.adaptive_cap.is_some()
            || limit < self.max_local_bidi
        {
            return Err(Error::Limit);
        }
        self.max_local_bidi = limit;
        Ok(())
    }

    /// Called once, before any stream opens, after the TLS handshake.
    /// Each active receive direction has a fixed maximum allocation, even
    /// when cumulative MAX_STREAMS grows over the life of the connection.
    pub(crate) fn enable_autotune(&mut self) -> Result<(), Error> {
        if self.adaptive_cap.is_some()
            || !self.streams.is_empty()
            || self.stream_limit != self.window as u64
            || self.max_data > MAX_ADAPTIVE_CONNECTION
        {
            return Err(Error::Limit);
        }
        let count = (self.max_bidi + self.max_uni + self.max_local_bidi).max(1) as usize;
        let cap = (MAX_TOTAL_WINDOW / count).min(MAX_ADAPTIVE_STREAM);
        if cap < self.window {
            return Err(Error::Limit);
        }
        self.adaptive_cap = Some(cap);
        Ok(())
    }

    pub(crate) fn can_open_local_bidi(&self) -> bool {
        self.streams
            .keys()
            .filter(|id| **id & 1 != self.peer_bit)
            .count()
            < self.max_local_bidi as usize
    }

    pub fn register_local_bidi(&mut self, id: u64) -> Result<(), Error> {
        if id > MAX_VARINT
            || id & 2 != 0
            || id & 1 == self.peer_bit
            || id / 4 != self.opened[(id & 3) as usize]
        {
            return Err(Error::StreamId);
        }
        if !self.streams.contains_key(&id) {
            if !self.can_open_local_bidi() {
                return Err(Error::Limit);
            }
            let buffer =
                ReceiveBuffer::new(self.window, self.stream_limit).map_err(Error::Receive)?;
            self.streams.insert(id, buffer);
            self.opened[(id & 3) as usize] += 1;
        }
        Ok(())
    }

    fn check_id(&self, id: u64) -> Result<(), Error> {
        if id <= MAX_VARINT
            && id & 1 != self.peer_bit
            && id & 2 == 0
            && id / 4 < self.opened[(id & 3) as usize]
        {
            return Ok(());
        }
        let limit = if id & 2 == 0 {
            self.max_bidi
        } else {
            self.max_uni
        };
        if id > MAX_VARINT || id & 1 != self.peer_bit || id / 4 >= limit {
            Err(Error::StreamId)
        } else {
            Ok(())
        }
    }

    pub fn extend_connection_limit(&mut self, limit: u64) -> Result<(), Error> {
        if limit < self.max_data || limit > MAX_VARINT {
            return Err(Error::Limit);
        }
        self.max_data = limit;
        Ok(())
    }

    pub fn used(&self) -> u64 {
        self.used
    }

    pub(crate) fn peer_streams(&self) -> Vec<u64> {
        self.streams
            .keys()
            .copied()
            .filter(|id| id & 1 == self.peer_bit)
            .collect()
    }

    /// Receiving a higher peer stream ID implicitly opens all lower IDs
    /// of that type. Allocate only after the actual frame was validated.
    pub(crate) fn register_implicit(&mut self, id: u64) -> Result<(), Error> {
        self.check_id(id)?;
        if id & 1 != self.peer_bit {
            return Ok(());
        }
        let kind = (id & 3) as usize;
        let end = id / 4 + 1;
        // Work is bounded by the advertised concurrent stream allowance,
        // not by the connection's cumulative stream number.
        for n in self.opened[kind]..end {
            let prior = n * 4 + kind as u64;
            if let std::collections::btree_map::Entry::Vacant(slot) = self.streams.entry(prior) {
                slot.insert(
                    ReceiveBuffer::new(self.window, self.stream_limit).map_err(Error::Receive)?,
                );
            }
        }
        self.opened[kind] = self.opened[kind].max(end);
        Ok(())
    }

    pub(crate) fn is_closed(&self, id: u64) -> bool {
        id <= MAX_VARINT
            && id / 4 < self.opened[(id & 3) as usize]
            && !self.streams.contains_key(&id)
    }

    /// Charge the increase in highest offset, including gaps, once only.
    /// Failed insertions never change the aggregate credit or create streams.
    pub fn insert(&mut self, id: u64, offset: u64, data: &[u8], fin: bool) -> Result<(), Error> {
        self.check_id(id)?;
        if self.is_closed(id) {
            // RFC 9000 permits forgetting final size after stream closure.
            // Keep a bounded recent cache for stricter duplicate checks.
            return match self.recent_closed.get_mut(&id) {
                Some(stream) => stream.insert(offset, data, fin).map_err(Error::Receive),
                None => Ok(()),
            };
        }
        let end = offset.checked_add(data.len() as u64).ok_or(Error::Limit)?;
        let old = self
            .streams
            .get(&id)
            .map_or(0, ReceiveBuffer::highest_offset);
        let used = self
            .used
            .checked_add(end.saturating_sub(old))
            .ok_or(Error::Limit)?;
        if used > self.max_data {
            return Err(Error::Limit);
        }
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.insert(offset, data, fin).map_err(Error::Receive)?;
        } else {
            let mut stream =
                ReceiveBuffer::new(self.window, self.stream_limit).map_err(Error::Receive)?;
            stream.insert(offset, data, fin).map_err(Error::Receive)?;
            self.streams.insert(id, stream);
        }
        self.used = used;
        self.register_implicit(id)
    }

    pub fn reset(&mut self, id: u64, final_size: u64, code: u64) -> Result<(), Error> {
        self.check_id(id)?;
        if self.is_closed(id) {
            return match self.recent_closed.get_mut(&id) {
                Some(stream) => stream.reset(final_size, code).map_err(Error::Receive),
                None => Ok(()),
            };
        }
        let old = self
            .streams
            .get(&id)
            .map_or(0, ReceiveBuffer::highest_offset);
        let used = self
            .used
            .checked_add(final_size.saturating_sub(old))
            .ok_or(Error::Limit)?;
        if used > self.max_data {
            return Err(Error::Limit);
        }
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.reset(final_size, code).map_err(Error::Receive)?;
        } else {
            let mut stream =
                ReceiveBuffer::new(self.window, self.stream_limit).map_err(Error::Receive)?;
            stream.reset(final_size, code).map_err(Error::Receive)?;
            self.streams.insert(id, stream);
        }
        self.used = used;
        self.register_implicit(id)
    }

    pub fn check_stop(&self, id: u64) -> Result<(), Error> {
        self.check_id(id)
    }

    pub(crate) fn abandon(&mut self, id: u64) -> Result<(), Error> {
        self.streams.get_mut(&id).ok_or(Error::StreamId)?.abandon();
        Ok(())
    }

    pub fn read(&mut self, id: u64, output: &mut [u8]) -> Result<usize, Error> {
        let stream = self.streams.get_mut(&id).ok_or(Error::StreamId)?;
        if let Some(code) = stream.reset_code() {
            return Err(Error::Receive(ReceiveError::Reset(code)));
        }
        Ok(stream.read(output))
    }

    /// Read and replenish only the consumed absolute credit. The caller must
    /// queue both MAX_DATA and MAX_STREAM_DATA before exposing the new limits
    /// to the peer. Neither duplicate nor out-of-order bytes grant credit.
    pub fn read_replenish(
        &mut self,
        id: u64,
        output: &mut [u8],
    ) -> Result<(usize, u64, u64), Error> {
        self.read_replenish_at(id, output, Instant::now(), Duration::ZERO)
    }

    pub(crate) fn read_replenish_at(
        &mut self,
        id: u64,
        output: &mut [u8],
        now: Instant,
        rtt: Duration,
    ) -> Result<(usize, u64, u64), Error> {
        let stream = self.streams.get_mut(&id).ok_or(Error::StreamId)?;
        if let Some(code) = stream.reset_code() {
            return Err(Error::Receive(ReceiveError::Reset(code)));
        }
        let n = stream.read(output);
        let extra = self
            .adaptive_cap
            .map_or(0, |cap| stream.tune_window(n, now, rtt, cap));
        let limit = stream
            .limit()
            .saturating_add(n as u64)
            .saturating_add(extra as u64)
            .min(MAX_VARINT);
        stream.extend_limit(limit).map_err(Error::Receive)?;
        let before = self.consumed;
        self.consumed = self.consumed.saturating_add(n as u64);
        let mut growth = 0;
        if self.adaptive_cap.is_some() && n != 0 && !rtt.is_zero() {
            let (start, offset) = *self.tune_epoch.get_or_insert((now, before));
            if now.saturating_duration_since(start) > rtt.saturating_mul(2) {
                self.tune_epoch = Some((now, before));
            } else if self.consumed.saturating_sub(offset) >= (self.connection_window / 2).max(1) {
                let old = self.connection_window;
                self.connection_window = old.saturating_mul(2).min(MAX_ADAPTIVE_CONNECTION);
                growth = self.connection_window - old;
                self.tune_epoch = Some((now, self.consumed));
            }
        }
        self.max_data = self
            .max_data
            .saturating_add(n as u64)
            .saturating_add(growth)
            .min(MAX_VARINT);
        Ok((n, self.max_data, limit))
    }

    /// Return cumulative peer stream credit and connection credit only once,
    /// after the application has released a terminal receive direction.
    /// Active allocation stays bounded while cumulative IDs grow to the
    /// protocol maximum. Closed streams cannot be reopened by late frames.
    pub(crate) fn retire(&mut self, id: u64) -> Option<(Option<u64>, Option<u64>)> {
        let released = self.streams.get_mut(&id)?.release_terminal()?;
        let terminal = self.streams.remove(&id)?;
        self.recent_closed.insert(id, terminal);
        if self.recent_closed.len() > RECENT_CLOSED {
            self.recent_closed.pop_first();
        }
        self.max_data = self.max_data.saturating_add(released).min(MAX_VARINT);
        let grant = if id & 1 == self.peer_bit {
            let limit = if id & 2 == 0 {
                &mut self.max_bidi
            } else {
                &mut self.max_uni
            };
            if *limit < MAX_STREAM_COUNT {
                *limit += 1;
                Some(*limit)
            } else {
                None
            }
        } else {
            None
        };
        Some((grant, (released != 0).then_some(self.max_data)))
    }

    pub fn finished(&self, id: u64) -> bool {
        self.streams.get(&id).is_some_and(ReceiveBuffer::finished)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_consumption_grows_windows_but_retirement_does_not_multiply_budget() {
        let now = Instant::now();
        let rtt = Duration::from_millis(10);
        let mut f = ReceiveFlow::new(true, 1, 1, 64, 64, 64).unwrap();
        f.enable_autotune().unwrap();
        f.insert(0, 0, &[7; 32], false).unwrap();
        assert_eq!(
            f.read_replenish_at(0, &mut [0; 32], now, rtt),
            Ok((32, 160, 160))
        );
        assert_eq!(
            f.read_replenish_at(0, &mut [0; 32], now, rtt),
            Ok((0, 160, 160))
        );
        f.insert(0, 32, &[9; 64], false).unwrap();
        assert_eq!(
            f.read_replenish_at(0, &mut [0; 64], now + rtt, rtt),
            Ok((64, 352, 352))
        );
        let cap = f.adaptive_cap.unwrap();
        assert!(cap <= MAX_ADAPTIVE_STREAM);
        f.insert(0, 96, &[], true).unwrap();
        assert!(f.retire(0).is_some());
        // New streams start at the negotiated initial limit, not the
        // previous stream's enlarged absolute limit.
        assert_eq!(
            f.insert(4, 64, b"x", false),
            Err(Error::Receive(ReceiveError::Limit))
        );
        f.insert(4, 0, &[1; 16], false).unwrap();
        let slow = now + Duration::from_secs(1);
        assert_eq!(
            f.read_replenish_at(4, &mut [0; 16], slow, rtt),
            Ok((16, 368, 80))
        );
        f.insert(4, 16, &[1; 16], false).unwrap();
        assert_eq!(
            f.read_replenish_at(4, &mut [0; 16], slow + rtt * 3, rtt),
            Ok((16, 384, 96))
        );
    }

    #[test]
    fn connection_credit_counts_gaps_and_duplicates_once() {
        let mut f = ReceiveFlow::new(true, 2, 1, 16, 16, 8).unwrap();
        f.insert(0, 3, b"de", true).unwrap();
        assert_eq!(f.used(), 5);
        f.insert(0, 0, b"abc", false).unwrap();
        assert_eq!(f.used(), 5);
        assert_eq!(f.insert(4, 0, b"abcd", false), Err(Error::Limit));
        assert_eq!(f.used(), 5);
        f.insert(4, 0, b"abc", false).unwrap();
        assert_eq!(f.used(), 8);
        let mut data = [0; 5];
        assert_eq!(f.read(0, &mut data), Ok(5));
        assert_eq!(&data, b"abcde");
        assert!(f.finished(0));
        assert_eq!(f.used(), 8);
        f.extend_connection_limit(10).unwrap();
        assert_eq!(f.insert(1, 0, b"x", false), Err(Error::StreamId));
        assert_eq!(f.insert(8, 0, b"x", false), Err(Error::StreamId));
        assert_eq!(f.insert(6, 0, b"x", false), Err(Error::StreamId));
        f.insert(2, 0, b"x", false).unwrap();
        assert_eq!(f.used(), 9);
        assert_eq!(f.extend_connection_limit(8), Err(Error::Limit));
        assert!(ReceiveFlow::new(false, 64, 1, 16, 16, 8).is_err());
    }
    #[test]
    fn retirement_grants_credit_once_and_preserves_final_size() {
        let mut f = ReceiveFlow::new(true, 1, 1, 16, 16, 16).unwrap();
        f.insert(2, 0, b"abc", true).unwrap();
        assert_eq!(f.retire(2), None);
        assert_eq!(f.read(2, &mut [0; 3]), Ok(3));
        assert_eq!(f.retire(2), Some((Some(2), None)));
        assert_eq!(f.retire(2), None);
        assert!(f.insert(2, 3, b"x", false).is_err());
        f.reset(6, 8, 7).unwrap();
        assert_eq!(f.retire(6), Some((Some(3), Some(24))));
        assert_eq!(f.retire(6), None);
        assert!(f.peer_streams().is_empty());
        f.insert(10, 0, b"x", false).unwrap();
        f.abandon(10).unwrap();
        assert_eq!(f.retire(10), None);
        f.insert(10, 3, b"z", true).unwrap();
        assert_eq!(f.retire(10), Some((Some(4), Some(28))));
    }
    #[test]
    fn cumulative_stream_credit_reuses_memory_not_identifiers() {
        let mut f = ReceiveFlow::new(true, 1, 2, 16, 16, 16).unwrap();
        // Keep the first uni stream open (as H3 control streams do).
        f.insert(2, 0, b"", false).unwrap();
        for n in 1..=1024u64 {
            let id = n * 4 + 2;
            f.reset(id, 1, 7).unwrap();
            assert_eq!(f.retire(id).unwrap().0, Some(n + 2));
            assert_eq!(f.streams.len(), 1);
            assert!(f.recent_closed.len() <= RECENT_CLOSED);
        }
        let used = f.used();
        f.insert(6, 0, b"x", true).unwrap();
        f.reset(6, 1, 7).unwrap();
        assert_eq!(f.used(), used);
        assert!(f.is_closed(6));
        assert_eq!(f.peer_streams(), vec![2]);
        assert!(f.insert(4 * 1026 + 2, 0, b"x", false).is_err());
    }

    #[test]
    fn reset_charges_final_size_once_and_discards_buffer() {
        let mut f = ReceiveFlow::new(true, 1, 1, 16, 8, 12).unwrap();
        f.insert(0, 0, b"abc", false).unwrap();
        assert_eq!(
            f.reset(0, 2, 7),
            Err(Error::Receive(ReceiveError::FinalSize))
        );
        assert_eq!(f.reset(0, 13, 7), Err(Error::Limit));
        assert_eq!(f.used(), 3);
        f.reset(0, 10, 7).unwrap();
        assert_eq!(f.used(), 10);
        f.reset(0, 10, 8).unwrap();
        f.insert(0, 9, b"x", true).unwrap();
        assert_eq!(f.used(), 10);
        assert_eq!(
            f.read(0, &mut [0; 4]),
            Err(Error::Receive(ReceiveError::Reset(7)))
        );
        assert!(!f.finished(0));
        assert_eq!(
            f.insert(0, 10, b"x", false),
            Err(Error::Receive(ReceiveError::FinalSize))
        );
        assert_eq!(f.reset(2, 3, 0), Err(Error::Limit));
        assert_eq!(f.used(), 10);
    }
}
