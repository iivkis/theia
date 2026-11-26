//! Bounded receive-side byte reassembly for future CRYPTO/STREAM users.
//! This is not a connection-level flow controller or a complete stream FSM.
use super::wire::MAX_VARINT;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

pub const MAX_WINDOW: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveError {
    Limit,
    FinalSize,
    Conflict,
    Reset(u64),
}

pub struct ReceiveBuffer {
    window: usize,
    limit: u64,
    read_offset: u64,
    highest: u64,
    final_size: Option<u64>,
    reset_code: Option<u64>,
    abandoned: bool,
    bytes: VecDeque<Option<u8>>,
    tune_epoch: Option<(Instant, u64)>,
}

impl ReceiveBuffer {
    pub fn new(window: usize, limit: u64) -> Result<Self, ReceiveError> {
        if window == 0 || window > MAX_WINDOW || limit > MAX_VARINT {
            return Err(ReceiveError::Limit);
        }
        Ok(Self {
            window,
            limit,
            read_offset: 0,
            highest: 0,
            final_size: None,
            reset_code: None,
            abandoned: false,
            bytes: VecDeque::new(),
            tune_epoch: None,
        })
    }

    /// Increase (never decrease) the absolute flow-control limit.
    pub fn extend_limit(&mut self, limit: u64) -> Result<(), ReceiveError> {
        if limit < self.limit || limit > MAX_VARINT {
            return Err(ReceiveError::Limit);
        }
        self.limit = limit;
        Ok(())
    }

    /// Insert out-of-order data atomically. Already consumed bytes are ignored;
    /// overlapping buffered bytes must agree. FIN fixes the final offset.
    pub fn insert(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<(), ReceiveError> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(ReceiveError::Limit)?;
        if end > self.limit {
            return Err(ReceiveError::Limit);
        }
        if self
            .final_size
            .is_some_and(|size| end > size || (fin && end != size))
            || (fin && end < self.highest)
        {
            return Err(ReceiveError::FinalSize);
        }
        if self.reset_code.is_some() {
            return Ok(());
        }
        if self.abandoned {
            self.highest = self.highest.max(end);
            if fin {
                self.final_size = Some(end);
            }
            return Ok(());
        }
        if end.saturating_sub(self.read_offset) > self.window as u64 {
            return Err(ReceiveError::Limit);
        }

        let skip = self
            .read_offset
            .saturating_sub(offset)
            .min(data.len() as u64) as usize;
        let remaining = &data[skip..];
        let start = offset.saturating_sub(self.read_offset) as usize;
        for (i, &byte) in remaining.iter().enumerate() {
            if let Some(Some(previous)) = self.bytes.get(start + i) {
                if *previous != byte {
                    return Err(ReceiveError::Conflict);
                }
            }
        }
        if !remaining.is_empty() {
            let required = start + remaining.len();
            if self.bytes.len() < required {
                self.bytes.resize(required, None);
            }
            for (i, &byte) in remaining.iter().enumerate() {
                self.bytes[start + i] = Some(byte);
            }
        }
        self.highest = self.highest.max(end);
        if fin {
            self.final_size = Some(end);
        }
        Ok(())
    }

    /// RESET_STREAM fixes final size even if bytes are missing. Credit is
    /// checked by the owner before this mutation; do not allocate gaps.
    pub fn reset(&mut self, final_size: u64, code: u64) -> Result<(), ReceiveError> {
        if final_size > self.limit || code > MAX_VARINT {
            return Err(ReceiveError::Limit);
        }
        if final_size < self.highest || self.final_size.is_some_and(|size| size != final_size) {
            return Err(ReceiveError::FinalSize);
        }
        // Already fully consumed FIN wins; late RESET cannot revoke it.
        if self.finished() {
            return Ok(());
        }
        self.final_size = Some(final_size);
        self.highest = final_size;
        self.reset_code.get_or_insert(code);
        self.bytes.clear();
        Ok(())
    }

    /// Terminal metadata remains available to validate late duplicates, but
    /// the reassembly allocation and unread reset credit can be released.
    pub(crate) fn abandon(&mut self) {
        self.abandoned = true;
        self.bytes = VecDeque::new();
    }

    pub(crate) fn release_terminal(&mut self) -> Option<u64> {
        let terminal = self.finished()
            || self.reset_code.is_some()
            || (self.abandoned && self.final_size.is_some());
        if !terminal {
            return None;
        }
        let released = self.highest.saturating_sub(self.read_offset);
        self.read_offset = self.highest;
        self.bytes = VecDeque::new();
        Some(released)
    }

    pub fn reset_code(&self) -> Option<u64> {
        self.reset_code
    }

    pub fn read(&mut self, output: &mut [u8]) -> usize {
        let mut written = 0;
        for slot in output {
            let Some(Some(byte)) = self.bytes.front().copied() else {
                break;
            };
            self.bytes.pop_front();
            *slot = byte;
            written += 1;
        }
        self.read_offset += written as u64;
        written
    }

    /// Grow only when the application actually consumes at least half the
    /// receive window within two measured RTTs. Never grant more memory
    /// than the connection's fixed per-stream allocation budget.
    pub(crate) fn tune_window(
        &mut self,
        consumed: usize,
        now: Instant,
        rtt: Duration,
        cap: usize,
    ) -> usize {
        if consumed == 0
            || rtt.is_zero()
            || self.final_size.is_some()
            || self.abandoned
            || self.window >= cap
        {
            return 0;
        }
        let before = self.read_offset.saturating_sub(consumed as u64);
        let (start, offset) = *self.tune_epoch.get_or_insert((now, before));
        if now.saturating_duration_since(start) > rtt.saturating_mul(2) {
            self.tune_epoch = Some((now, before));
            return 0;
        }
        if self.read_offset.saturating_sub(offset) < (self.window / 2).max(1) as u64 {
            return 0;
        }
        let old = self.window;
        self.window = old.saturating_mul(2).min(cap).min(MAX_WINDOW);
        self.tune_epoch = Some((now, self.read_offset));
        self.window - old
    }

    pub fn finished(&self) -> bool {
        self.reset_code.is_none() && self.final_size == Some(self.read_offset)
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub(crate) fn consumed_offset(&self) -> u64 {
        self.read_offset
    }

    pub fn highest_offset(&self) -> u64 {
        self.highest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorder_duplicate_and_final_size() {
        let mut rx = ReceiveBuffer::new(8, 8).unwrap();
        let mut out = [0; 8];
        rx.insert(3, b"def", true).unwrap();
        assert_eq!(rx.read(&mut out), 0);
        rx.insert(2, b"cd", false).unwrap();
        assert_eq!(rx.insert(0, b"abX", false), Err(ReceiveError::Conflict));
        assert_eq!(rx.read(&mut out), 0);
        rx.insert(0, b"abc", false).unwrap();
        assert_eq!(rx.highest_offset(), 6);
        assert_eq!(rx.insert(6, b"x", false), Err(ReceiveError::FinalSize));
        assert_eq!(rx.insert(0, b"abc", true), Err(ReceiveError::FinalSize));
        assert_eq!(rx.read(&mut out[..2]), 2);
        assert!(!rx.finished());
        rx.insert(0, b"abcdef", true).unwrap();
        assert_eq!(rx.read(&mut out[2..]), 4);
        assert_eq!(&out[..6], b"abcdef");
        assert!(rx.finished());
    }

    #[test]
    fn bounded_window_and_monotonic_flow_limit() {
        assert!(ReceiveBuffer::new(0, 8).is_err());
        assert!(ReceiveBuffer::new(MAX_WINDOW + 1, 8).is_err());
        assert!(ReceiveBuffer::new(4, MAX_VARINT + 1).is_err());
        let mut rx = ReceiveBuffer::new(4, 4).unwrap();
        assert_eq!(rx.insert(u64::MAX, b"x", false), Err(ReceiveError::Limit));
        assert_eq!(rx.insert(4, b"x", false), Err(ReceiveError::Limit));
        assert_eq!(rx.extend_limit(3), Err(ReceiveError::Limit));
        assert_eq!(rx.extend_limit(MAX_VARINT + 1), Err(ReceiveError::Limit));
        rx.extend_limit(10).unwrap();
        assert_eq!(rx.insert(4, b"x", false), Err(ReceiveError::Limit));
        rx.insert(0, b"abcd", false).unwrap();
        assert_eq!(rx.insert(1, b"", true), Err(ReceiveError::FinalSize));
        assert_eq!(rx.read(&mut [0; 4]), 4);
        rx.insert(4, b"ef", false).unwrap();
        rx.insert(6, b"", true).unwrap();
        assert_eq!(rx.read(&mut [0; 4]), 2);
        assert!(rx.finished());
    }
}
