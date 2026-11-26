//! Bounded receive-side connection and stream flow accounting. This is
//! not the send-side flow controller or a complete QUIC stream lifecycle.
use super::{stream::{ReceiveBuffer, ReceiveError, MAX_WINDOW}, wire::MAX_VARINT};
use std::collections::BTreeMap;

const MAX_STREAMS: u64 = 64;
const MAX_TOTAL_WINDOW: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { Limit, StreamId, Receive(ReceiveError) }

pub struct ReceiveFlow {
    peer_bit: u64,
    max_bidi: u64,
    max_uni: u64,
    max_local_bidi: u64,
    stream_limit: u64,
    window: usize,
    max_data: u64,
    used: u64,
    streams: BTreeMap<u64, ReceiveBuffer>,
}

impl ReceiveFlow {
    /// Only peer-initiated receive directions are admitted by this stage.
    pub fn new(local_server: bool, max_bidi: u64, max_uni: u64,
               stream_limit: u64, window: usize, max_data: u64) -> Result<Self, Error> {
        let count = max_bidi.checked_add(max_uni).ok_or(Error::Limit)?;
        if count > MAX_STREAMS || window == 0 || window > MAX_WINDOW
            || (count as usize).saturating_mul(window) > MAX_TOTAL_WINDOW
            || stream_limit > MAX_VARINT || max_data > MAX_VARINT { return Err(Error::Limit); }
        Ok(Self { peer_bit: u64::from(!local_server), max_bidi, max_uni, max_local_bidi: 0,
            stream_limit, window, max_data, used: 0, streams: BTreeMap::new() })
    }

    pub fn enable_local_bidi(&mut self, limit: u64) -> Result<(), Error> {
        let count = self.max_bidi.checked_add(self.max_uni).and_then(|n| n.checked_add(limit)).ok_or(Error::Limit)?;
        if count > MAX_STREAMS || (count as usize).saturating_mul(self.window) > MAX_TOTAL_WINDOW
            || limit < self.max_local_bidi { return Err(Error::Limit); }
        self.max_local_bidi = limit;
        Ok(())
    }

    pub fn register_local_bidi(&mut self, id: u64) -> Result<(), Error> {
        if id > MAX_VARINT || id & 2 != 0 || id & 1 == self.peer_bit || id / 4 >= self.max_local_bidi {
            return Err(Error::StreamId);
        }
        if !self.streams.contains_key(&id) {
            let buffer = ReceiveBuffer::new(self.window, self.stream_limit).map_err(Error::Receive)?;
            self.streams.insert(id, buffer);
        }
        Ok(())
    }

    fn check_id(&self, id: u64) -> Result<(), Error> {
        if id & 1 != self.peer_bit && id & 2 == 0 && self.streams.contains_key(&id) {
            return Ok(());
        }
        let limit = if id & 2 == 0 { self.max_bidi } else { self.max_uni };
        if id > MAX_VARINT || id & 1 != self.peer_bit || id / 4 >= limit {
            Err(Error::StreamId)
        } else { Ok(()) }
    }

    pub fn extend_connection_limit(&mut self, limit: u64) -> Result<(), Error> {
        if limit < self.max_data || limit > MAX_VARINT { return Err(Error::Limit); }
        self.max_data = limit;
        Ok(())
    }

    pub fn used(&self) -> u64 { self.used }

    /// Charge the increase in highest offset, including gaps, once only.
    /// Failed insertions never change the aggregate credit or create streams.
    pub fn insert(&mut self, id: u64, offset: u64, data: &[u8], fin: bool) -> Result<(), Error> {
        self.check_id(id)?;
        let end = offset.checked_add(data.len() as u64).ok_or(Error::Limit)?;
        let old = self.streams.get(&id).map_or(0, ReceiveBuffer::highest_offset);
        let used = self.used.checked_add(end.saturating_sub(old)).ok_or(Error::Limit)?;
        if used > self.max_data { return Err(Error::Limit); }
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.insert(offset, data, fin).map_err(Error::Receive)?;
        } else {
            let mut stream = ReceiveBuffer::new(self.window, self.stream_limit).map_err(Error::Receive)?;
            stream.insert(offset, data, fin).map_err(Error::Receive)?;
            self.streams.insert(id, stream);
        }
        self.used = used;
        Ok(())
    }

    pub fn reset(&mut self, id: u64, final_size: u64, code: u64) -> Result<(), Error> {
        self.check_id(id)?;
        let old = self.streams.get(&id).map_or(0, ReceiveBuffer::highest_offset);
        let used = self.used.checked_add(final_size.saturating_sub(old)).ok_or(Error::Limit)?;
        if used > self.max_data { return Err(Error::Limit); }
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.reset(final_size, code).map_err(Error::Receive)?;
        } else {
            let mut stream = ReceiveBuffer::new(self.window, self.stream_limit).map_err(Error::Receive)?;
            stream.reset(final_size, code).map_err(Error::Receive)?;
            self.streams.insert(id, stream);
        }
        self.used = used;
        Ok(())
    }

    pub fn check_stop(&self, id: u64) -> Result<(), Error> { self.check_id(id) }

    pub fn read(&mut self, id: u64, output: &mut [u8]) -> Result<usize, Error> {
        let stream = self.streams.get_mut(&id).ok_or(Error::StreamId)?;
        if let Some(code) = stream.reset_code() { return Err(Error::Receive(ReceiveError::Reset(code))); }
        Ok(stream.read(output))
    }

    /// Read and replenish only the consumed absolute credit. The caller must
    /// queue both MAX_DATA and MAX_STREAM_DATA before exposing the new limits
    /// to the peer. Neither duplicate nor out-of-order bytes grant credit.
    pub fn read_replenish(&mut self, id: u64, output: &mut [u8]) -> Result<(usize, u64, u64), Error> {
        let stream = self.streams.get_mut(&id).ok_or(Error::StreamId)?;
        if let Some(code) = stream.reset_code() { return Err(Error::Receive(ReceiveError::Reset(code))); }
        let n = stream.read(output);
        let limit = stream.limit().saturating_add(n as u64).min(MAX_VARINT);
        stream.extend_limit(limit).map_err(Error::Receive)?;
        self.max_data = self.max_data.saturating_add(n as u64).min(MAX_VARINT);
        Ok((n, self.max_data, limit))
    }

    pub fn finished(&self, id: u64) -> bool {
        self.streams.get(&id).is_some_and(ReceiveBuffer::finished)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn reset_charges_final_size_once_and_discards_buffer() {
        let mut f = ReceiveFlow::new(true, 1, 1, 16, 8, 12).unwrap();
        f.insert(0, 0, b"abc", false).unwrap();
        assert_eq!(f.reset(0, 2, 7), Err(Error::Receive(ReceiveError::FinalSize)));
        assert_eq!(f.reset(0, 13, 7), Err(Error::Limit));
        assert_eq!(f.used(), 3);
        f.reset(0, 10, 7).unwrap();
        assert_eq!(f.used(), 10);
        f.reset(0, 10, 8).unwrap();
        f.insert(0, 9, b"x", true).unwrap();
        assert_eq!(f.used(), 10);
        assert_eq!(f.read(0, &mut [0; 4]), Err(Error::Receive(ReceiveError::Reset(7))));
        assert!(!f.finished(0));
        assert_eq!(f.insert(0, 10, b"x", false), Err(Error::Receive(ReceiveError::FinalSize)));
        assert_eq!(f.reset(2, 3, 0), Err(Error::Limit));
        assert_eq!(f.used(), 10);
    }

}
