//! Bounded send-side credit for locally opened unidirectional streams.
//! Retransmissions use existing frame references and never reserve credit again.
use super::wire::{encode_varint, MAX_VARINT};
use std::collections::BTreeMap;

const MAX_STREAM_COUNT: u64 = 1 << 60;
const MAX_ACTIVE_PER_TYPE: usize = 64;
pub const MAX_CHUNK: usize = 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    Stream,
    Finished,
}

struct Stream {
    offset: u64,
    limit: u64,
    fin: bool,
    reset: Option<u64>,
}

pub struct SendFlow {
    local_bit: u64,
    max_streams: u64,
    max_bidi: u64,
    peer_bidi: u64,
    next_uni: u64,
    next_bidi: u64,
    peer_opened: u64,
    initial_limit: u64,
    local_bidi_limit: u64,
    peer_bidi_limit: u64,
    max_data: u64,
    used: u64,
    streams: BTreeMap<u64, Stream>,
}

impl SendFlow {
    pub fn new(
        server: bool,
        max_streams: u64,
        stream_limit: u64,
        max_data: u64,
    ) -> Result<Self, Error> {
        if max_streams > (1 << 60) || stream_limit > MAX_VARINT || max_data > MAX_VARINT {
            return Err(Error::Limit);
        }
        Ok(Self {
            local_bit: u64::from(server),
            max_streams,
            max_bidi: 0,
            peer_bidi: 0,
            next_uni: 0,
            next_bidi: 0,
            peer_opened: 0,
            initial_limit: stream_limit,
            local_bidi_limit: stream_limit,
            peer_bidi_limit: stream_limit,
            max_data,
            used: 0,
            streams: BTreeMap::new(),
        })
    }

    /// Authenticated peer limits apply before the first stream is opened.
    /// A peer-local bidi stream is remote-initiated from our perspective.
    pub(crate) fn from_peer(
        server: bool,
        limits: super::parameters::Limits,
        peer_bidi: u64,
    ) -> Result<Self, Error> {
        let mut flow = Self::new(
            server,
            limits.max_streams_uni,
            limits.initial_uni,
            limits.max_data,
        )?;
        flow.enable_bidi(limits.max_streams_bidi, peer_bidi)?;
        flow.local_bidi_limit = limits.initial_bidi_remote;
        flow.peer_bidi_limit = limits.initial_bidi_local;
        Ok(flow)
    }

    pub fn open(&mut self) -> Result<u64, Error> {
        let n = self.next_uni;
        if n >= self.max_streams || self.active_type(2 + self.local_bit) >= MAX_ACTIVE_PER_TYPE {
            return Err(Error::Limit);
        }
        let id = n * 4 + 2 + self.local_bit;
        self.streams.insert(
            id,
            Stream {
                offset: 0,
                limit: self.initial_limit,
                fin: false,
                reset: None,
            },
        );
        self.next_uni += 1;
        Ok(id)
    }

    fn active_type(&self, kind: u64) -> usize {
        self.streams.keys().filter(|id| **id & 3 == kind).count()
    }

    /// Cumulative peer credit is independent of the local active cap.
    pub fn enable_bidi(&mut self, local: u64, peer: u64) -> Result<(), Error> {
        if local > MAX_STREAM_COUNT
            || peer > MAX_STREAM_COUNT
            || local < self.next_bidi
            || peer < self.peer_bidi
        {
            return Err(Error::Limit);
        }
        self.max_bidi = local;
        self.peer_bidi = peer;
        Ok(())
    }

    pub fn open_bidi(&mut self) -> Result<u64, Error> {
        if self.next_bidi >= self.max_bidi
            || self.active_type(self.local_bit) >= MAX_ACTIVE_PER_TYPE
        {
            return Err(Error::Limit);
        }
        let id = self.next_bidi * 4 + self.local_bit;
        self.streams.insert(
            id,
            Stream {
                offset: 0,
                limit: self.local_bidi_limit,
                fin: false,
                reset: None,
            },
        );
        self.next_bidi += 1;
        Ok(id)
    }

    /// The receive side must first validate that the peer opened this stream.
    pub fn register_peer_bidi(&mut self, id: u64) -> Result<(), Error> {
        if id > MAX_VARINT || id & 2 != 0 || id & 1 == self.local_bit || id / 4 >= self.peer_bidi {
            return Err(Error::Stream);
        }
        if id / 4 < self.peer_opened {
            return Ok(());
        }
        if id / 4 != self.peer_opened || self.active_type(1 - self.local_bit) >= MAX_ACTIVE_PER_TYPE
        {
            return Err(Error::Limit);
        }
        self.peer_opened += 1;
        self.streams.entry(id).or_insert(Stream {
            offset: 0,
            limit: self.peer_bidi_limit,
            fin: false,
            reset: None,
        });
        Ok(())
    }

    pub(crate) fn grant_peer_bidi(&mut self, value: u64) {
        self.peer_bidi = self.peer_bidi.max(value.min(MAX_STREAM_COUNT));
    }

    pub(crate) fn terminal(&self, id: u64) -> bool {
        self.streams.get(&id).is_some_and(|stream| stream.fin)
    }

    pub(crate) fn lifetime_exhausted(&self, bidi: bool) -> bool {
        (if bidi { self.next_bidi } else { self.next_uni }) >= MAX_STREAM_COUNT
    }

    pub(crate) fn retire(&mut self, id: u64) {
        self.streams.remove(&id);
    }

    pub(crate) fn is_closed(&self, id: u64) -> bool {
        if id > MAX_VARINT || self.streams.contains_key(&id) {
            return false;
        }
        let next = match (id & 1 == self.local_bit, id & 2 == 0) {
            (true, true) => self.next_bidi,
            (true, false) => self.next_uni,
            (false, true) => self.peer_opened,
            (false, false) => 0,
        };
        id / 4 < next
    }

    pub fn max_bidi(&mut self, value: u64) -> Result<(), Error> {
        if value > (1 << 60) {
            return Err(Error::Limit);
        }
        self.max_bidi = self.max_bidi.max(value);
        Ok(())
    }

    pub(crate) fn available(&self, id: u64) -> usize {
        self.streams.get(&id).filter(|s| !s.fin).map_or(0, |s| {
            s.limit
                .saturating_sub(s.offset)
                .min(self.max_data.saturating_sub(self.used))
                .min(MAX_CHUNK as u64) as usize
        })
    }

    pub fn max_data(&mut self, value: u64) -> Result<(), Error> {
        if value > MAX_VARINT {
            return Err(Error::Limit);
        }
        self.max_data = self.max_data.max(value);
        Ok(())
    }

    pub fn max_streams(&mut self, value: u64) -> Result<(), Error> {
        if value > (1 << 60) {
            return Err(Error::Limit);
        }
        self.max_streams = self.max_streams.max(value);
        Ok(())
    }

    pub fn max_stream_data(&mut self, id: u64, value: u64) -> Result<(), Error> {
        if value > MAX_VARINT {
            return Err(Error::Limit);
        }
        if self.is_closed(id) {
            return Ok(());
        }
        let stream = self.streams.get_mut(&id).ok_or(Error::Stream)?;
        stream.limit = stream.limit.max(value);
        Ok(())
    }

    /// STOP_SENDING or a local reset terminates the send direction. The
    /// final offset includes all bytes already committed to send credit.
    /// The caller cancels queued STREAM frames and reliably sends RESET.
    pub(crate) fn reset_code(&self, id: u64) -> Option<u64> {
        self.streams.get(&id).and_then(|stream| stream.reset)
    }

    pub fn reset(&mut self, id: u64, code: u64) -> Result<Option<Vec<u8>>, Error> {
        if self.is_closed(id) {
            return Ok(None);
        }
        let stream = self.streams.get_mut(&id).ok_or(Error::Stream)?;
        if code > MAX_VARINT {
            return Err(Error::Limit);
        }
        if stream.reset.is_some() {
            return Ok(None);
        }
        let mut frame = vec![4];
        for value in [id, code, stream.offset] {
            let mut scratch = [0; 8];
            frame.extend_from_slice(encode_varint(value, &mut scratch).ok_or(Error::Limit)?);
        }
        stream.reset = Some(code);
        stream.fin = true;
        Ok(Some(frame))
    }

    /// Encode one STREAM frame and commit newly sent byte offsets. The caller
    /// must reserve queue capacity first; failed encoding leaves credit intact.
    pub fn encode(&mut self, id: u64, bytes: &[u8], fin: bool) -> Result<Vec<u8>, Error> {
        let stream = self.streams.get_mut(&id).ok_or(Error::Stream)?;
        if stream.fin {
            return Err(Error::Finished);
        }
        if bytes.len() > MAX_CHUNK || (bytes.is_empty() && !fin) {
            return Err(Error::Limit);
        }
        let n = bytes.len() as u64;
        let end = stream.offset.checked_add(n).ok_or(Error::Limit)?;
        let total = self.used.checked_add(n).ok_or(Error::Limit)?;
        if end > stream.limit || total > self.max_data {
            return Err(Error::Limit);
        }
        let mut out = vec![0x0e | u8::from(fin)];
        for value in [id, stream.offset, n] {
            let mut scratch = [0; 8];
            out.extend_from_slice(encode_varint(value, &mut scratch).ok_or(Error::Limit)?);
        }
        out.extend_from_slice(bytes);
        stream.offset = end;
        stream.fin = fin;
        self.used = total;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_core::{
        frames::{decode, Frame},
        spaces::Space,
    };

    #[test]
    fn authenticated_asymmetric_credit_uses_peer_direction() {
        let limits = super::super::parameters::Limits {
            max_udp_payload: 1400,
            max_data: 30,
            initial_bidi_local: 3,
            initial_bidi_remote: 5,
            initial_uni: 7,
            max_streams_bidi: 1,
            max_streams_uni: 1,
            ack_delay_exponent: 3,
            max_ack_delay_ms: 25,
            active_cid_limit: 2,
        };
        let mut flow = SendFlow::from_peer(false, limits, 8).unwrap();
        let uni = flow.open().unwrap();
        let bidi = flow.open_bidi().unwrap();
        flow.register_peer_bidi(1).unwrap();
        assert_eq!(
            (flow.available(uni), flow.available(bidi), flow.available(1)),
            (7, 5, 3)
        );
        assert_eq!(flow.open_bidi(), Err(Error::Limit));
    }

    #[test]
    fn send_metadata_is_bounded_across_many_streams() {
        let mut f = SendFlow::new(false, 1024, 8, 8).unwrap();
        let control = f.open().unwrap();
        for n in 1..1024 {
            let id = f.open().unwrap();
            assert_eq!(id, 4 * n + 2);
            f.encode(id, b"", true).unwrap();
            f.retire(id);
            assert!(f.is_closed(id));
            assert_eq!(f.max_stream_data(id, 8), Ok(()));
            assert_eq!(f.reset(id, 7), Ok(None));
        }
        assert_eq!(f.streams.len(), 1);
        assert!(!f.is_closed(control));
        assert_eq!(f.open(), Err(Error::Limit));
        f.max_streams(1025).unwrap();
        assert_eq!(f.open().unwrap(), 4098);
    }

    #[test]
    fn credit_and_fin() {
        let mut f = SendFlow::new(false, 1, 3, 4).unwrap();
        let id = f.open().unwrap();
        assert_eq!(id, 2);
        assert_eq!(f.open(), Err(Error::Limit));
        assert_eq!(f.encode(id, b"abcd", false), Err(Error::Limit));
        assert_eq!(f.available(id), 3);
        let bytes = f.encode(id, b"ab", false).unwrap();
        assert_eq!(f.available(id), 1);
        assert_eq!(
            decode(&bytes, Space::Application).unwrap(),
            [Frame::Stream {
                id,
                offset: 0,
                data: b"ab",
                fin: false
            }]
        );
        f.max_stream_data(id, 4).unwrap();
        f.max_stream_data(id, 1).unwrap();
        f.encode(id, b"cd", true).unwrap();
        assert_eq!(f.encode(id, b"", true), Err(Error::Finished));
        f.max_streams(2).unwrap();
        let second = f.open().unwrap();
        assert_eq!(f.encode(second, b"x", false), Err(Error::Limit));
        f.max_data(5).unwrap();
        f.encode(second, b"x", true).unwrap();
    }
    #[test]
    fn reset_serializes_committed_offset_and_is_idempotent() {
        let mut f = SendFlow::new(false, 1, 8, 8).unwrap();
        let id = f.open().unwrap();
        f.encode(id, b"abc", false).unwrap();
        let frame = f.reset(id, 17).unwrap().unwrap();
        assert_eq!(
            decode(&frame, Space::Application).unwrap(),
            [Frame::ResetStream {
                id,
                code: 17,
                final_size: 3
            }]
        );
        assert_eq!(f.reset(id, 17), Ok(None));
        assert_eq!(f.encode(id, b"x", false), Err(Error::Finished));
    }
}
