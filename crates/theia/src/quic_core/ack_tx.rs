//! Bounded ACK history and serialization. Only insert successfully opened
//! packets. ACK-only packets do not trigger an ACK on their own.
use super::{
    ack::Range,
    wire::{encode_varint, MAX_VARINT},
};
use std::collections::BTreeSet;

const WINDOW: u64 = 128;

#[derive(Default)]
pub struct History {
    numbers: BTreeSet<u64>,
    largest: Option<u64>,
    pending: bool,
}

impl History {
    pub fn record(&mut self, number: u64, eliciting: bool) -> bool {
        if number > MAX_VARINT
            || self
                .largest
                .is_some_and(|n| n.saturating_sub(number) >= WINDOW)
        {
            return false;
        }
        self.largest = Some(self.largest.map_or(number, |n| n.max(number)));
        let floor = self.largest.unwrap_or(0).saturating_sub(WINDOW - 1);
        self.numbers.retain(|n| *n >= floor);
        let fresh = self.numbers.insert(number);
        self.pending |= eliciting;
        fresh
    }

    pub fn pending(&self) -> bool {
        self.pending
    }

    /// Immediate ACK, zero encoded delay; caller clears pending only after
    /// packet sealing. The bounded history is retained for subsequent ACKs.
    pub fn encode(&self) -> Option<Vec<u8>> {
        if !self.pending {
            return None;
        }
        let mut ranges: Vec<Range> = Vec::new();
        for &number in self.numbers.iter().rev() {
            if let Some(last) = ranges.last_mut() {
                if number + 1 == last.first {
                    last.first = number;
                    continue;
                }
            }
            ranges.push(Range {
                first: number,
                last: number,
            });
        }
        let first = ranges.first()?;
        let mut out = vec![2];
        let mut add = |value| {
            let mut scratch = [0; 8];
            out.extend_from_slice(encode_varint(value, &mut scratch).expect("bounded ACK value"));
        };
        add(first.last);
        add(0);
        add((ranges.len() - 1) as u64);
        add(first.last - first.first);
        for pair in ranges.windows(2) {
            add(pair[0].first - pair[1].last - 2);
            add(pair[1].last - pair[1].first);
        }
        Some(out)
    }

    pub fn sent(&mut self) {
        self.pending = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_core::ack::Ack;

    #[test]
    fn gaps_reorder_and_ack_only() {
        let mut h = History::default();
        assert!(h.record(4, false));
        assert!(h.encode().is_none());
        assert!(h.record(0, true));
        assert!(h.record(1, true));
        assert!(!h.record(1, true));
        let data = h.encode().unwrap();
        let mut at = 1;
        let a = Ack::decode(&data, &mut at, false).unwrap();
        assert_eq!(
            a.ranges,
            [Range { first: 4, last: 4 }, Range { first: 0, last: 1 }]
        );
        assert_eq!(at, data.len());
        h.sent();
        assert!(h.encode().is_none());
        assert!(h.record(132, true));
        assert!(!h.record(4, true));
        let data = h.encode().unwrap();
        assert_eq!(
            Ack::decode(&data, &mut { 1usize }, false).unwrap().ranges,
            [Range {
                first: 132,
                last: 132
            }]
        );
    }
}
