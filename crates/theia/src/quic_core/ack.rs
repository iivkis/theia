//! Bounded ACK range decoding, shared with the existing Initial observer.
//! An endpoint must still reject ACKs for unsent packets in the relevant
//! packet-number space; syntax alone never authenticates a peer.
use super::wire::varint;

pub const MAX_ACK_RANGES: u64 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Range {
    pub first: u64,
    pub last: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Ack {
    pub delay: u64,
    pub ranges: Vec<Range>,
    pub ecn: Option<[u64; 3]>,
}

impl Ack {
    /// Decode the ACK payload after type 0x02/0x03, atomically advancing
    /// the caller's cursor only after all ranges and ECN counters validate.
    pub fn decode(bytes: &[u8], pos: &mut usize, with_ecn: bool) -> Option<Self> {
        let mut at = *pos;
        let largest = varint(bytes, &mut at)?;
        let delay = varint(bytes, &mut at)?;
        let count = varint(bytes, &mut at)?;
        if count > MAX_ACK_RANGES {
            return None;
        }
        // Each additional range consumes at least two bytes.
        let first = largest.checked_sub(varint(bytes, &mut at)?)?;
        if count > bytes.len().saturating_sub(at) as u64 / 2 {
            return None;
        }
        let mut ranges = Vec::with_capacity(count as usize + 1);
        ranges.push(Range { first, last: largest });
        let mut low = first;
        for _ in 0..count {
            let last = low.checked_sub(varint(bytes, &mut at)?.checked_add(2)?)?;
            let first = last.checked_sub(varint(bytes, &mut at)?)?;
            ranges.push(Range { first, last });
            low = first;
        }
        let ecn = if with_ecn {
            Some([varint(bytes, &mut at)?, varint(bytes, &mut at)?, varint(bytes, &mut at)?])
        } else {
            None
        };
        *pos = at;
        Some(Self { delay, ranges, ecn })
    }

    pub fn acknowledges(&self, number: u64) -> bool {
        self.ranges.iter().any(|range| (range.first..=range.last).contains(&number))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_ranges_and_ecn_are_exact() {
        let data = [99, 10, 2, 1, 2, 1, 1, 3, 4, 5, 99];
        let mut pos = 1;
        let a = Ack::decode(&data, &mut pos, true).unwrap();
        assert_eq!(a.delay, 2);
        assert_eq!(a.ranges, [Range { first: 8, last: 10 }, Range { first: 4, last: 5 }]);
        assert_eq!(a.ecn, Some([3, 4, 5]));
        assert_eq!(pos, 10);
        assert!(a.acknowledges(4));
        assert!(a.acknowledges(10));
        assert!(!a.acknowledges(6));
        assert!(!a.acknowledges(11));
        let mut pos = 1;
        assert!(Ack::decode(&data, &mut pos, false).unwrap().ecn.is_none());
        assert_eq!(pos, 7);
        for cut in 1..10 {
            let mut pos = 1;
            assert!(Ack::decode(&data[..cut], &mut pos, true).is_none());
            assert_eq!(pos, 1);
        }
    }

    #[test]
    fn rejects_underflow_and_excessive_range_count() {
        for bytes in [&[1, 0, 0, 2][..], &[2, 0, 1, 1, 0, 0], &[2, 0, 1, 0, 0, 1], &[0, 0, 0x41, 1, 0]] {
            let mut pos = 0;
            assert!(Ack::decode(bytes, &mut pos, false).is_none());
            assert_eq!(pos, 0);
        }
    }
}
