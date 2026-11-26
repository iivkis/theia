//! Bounded receive-side byte reassembly for future CRYPTO/STREAM users.
//! This is not a connection-level flow controller or a complete stream FSM.
use super::wire::MAX_VARINT;
use std::collections::VecDeque;

pub const MAX_WINDOW: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveError {
    Limit,
    FinalSize,
    Conflict,
}

pub struct ReceiveBuffer {
    window: usize,
    limit: u64,
    read_offset: u64,
    highest: u64,
    final_size: Option<u64>,
    bytes: VecDeque<Option<u8>>,
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
            bytes: VecDeque::new(),
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
        let end = offset.checked_add(data.len() as u64).ok_or(ReceiveError::Limit)?;
        if end > self.limit {
            return Err(ReceiveError::Limit);
        }
        if self.final_size.is_some_and(|size| end > size || (fin && end != size))
            || (fin && end < self.highest)
        {
            return Err(ReceiveError::FinalSize);
        }
        if end.saturating_sub(self.read_offset) > self.window as u64 {
            return Err(ReceiveError::Limit);
        }

        let skip = self.read_offset.saturating_sub(offset).min(data.len() as u64) as usize;
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

    pub fn finished(&self) -> bool {
        self.final_size == Some(self.read_offset)
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
