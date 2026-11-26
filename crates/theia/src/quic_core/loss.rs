//! Bounded RFC 9002-style packet loss bookkeeping for one number space.
//! ACKs must come from an authenticated packet in that space. Returned
//! frame descriptors are candidates for retransmission, not a send queue:
//! the owner must suppress frames already acknowledged by another packet.
use super::{ack::Ack, wire::MAX_VARINT};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

const MAX_OUTSTANDING: usize = 4096;
const MAX_FRAMES: usize = 32;
const PACKET_THRESHOLD: u64 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameRef {
    Crypto {
        offset: u64,
        len: u32,
    },
    Stream {
        id: u64,
        offset: u64,
        len: u32,
        fin: bool,
    },
    Control(u64),
}

#[derive(Debug)]
pub struct Sent {
    pub number: u64,
    pub at: Instant,
    pub bytes: u32,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    pub frames: Vec<FrameRef>,
}

#[derive(Default, Debug)]
pub struct Outcome {
    pub acknowledged: Vec<Sent>,
    pub lost: Vec<Sent>,
    pub acknowledged_bytes: u64,
    pub lost_bytes: u64,
    pub rtt_sample: Option<Duration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    Sequence,
    Ack,
    Clock,
}

#[derive(Default)]
pub struct Ledger {
    next: u64,
    sent: VecDeque<Sent>,
    last_send: Option<Instant>,
    largest_ack: Option<u64>,
    bytes_in_flight: u64,
}

impl Ledger {
    /// Retry resets recovery, but never the packet-number sequence.
    pub(crate) fn with_next(next: u64) -> Self {
        Self {
            next,
            ..Self::default()
        }
    }

    /// This stage requires contiguous attempted packet numbers. If sealing
    /// burns a number before transmission, the future owner must account for
    /// it explicitly instead of treating it as successfully sent.
    pub fn record(&mut self, packet: Sent) -> Result<(), Error> {
        if packet.number != self.next || packet.number > MAX_VARINT {
            return Err(Error::Sequence);
        }
        if packet.bytes == 0
            || packet.bytes > 65527
            || packet.frames.len() > MAX_FRAMES
            || (packet.in_flight && self.sent.len() == MAX_OUTSTANDING)
            || (!packet.in_flight && packet.ack_eliciting)
        {
            return Err(Error::Limit);
        }
        if self.last_send.is_some_and(|last| packet.at < last) {
            return Err(Error::Clock);
        }
        if packet.in_flight {
            self.bytes_in_flight = self
                .bytes_in_flight
                .checked_add(u64::from(packet.bytes))
                .ok_or(Error::Limit)?;
        }
        self.next += 1;
        self.last_send = Some(packet.at);
        // ACK-only packets still consume packet numbers, but do not need
        // retention in the loss ledger.
        if packet.in_flight {
            self.sent.push_back(packet);
        }
        Ok(())
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Apply an ACK atomically after validating its descending, disjoint
    /// ranges and that it cannot acknowledge unsent packet numbers.
    pub fn acknowledge(
        &mut self,
        ack: &Ack,
        now: Instant,
        loss_delay: Duration,
    ) -> Result<Outcome, Error> {
        let first = ack.ranges.first().ok_or(Error::Ack)?;
        if ack.ranges.len() > super::ack::MAX_ACK_RANGES as usize + 1 || first.last >= self.next {
            return Err(Error::Ack);
        }
        let mut previous: Option<u64> = None;
        for r in &ack.ranges {
            if r.first > r.last
                || r.last >= self.next
                || previous.is_some_and(|low| low.checked_sub(2).is_none_or(|bound| r.last > bound))
            {
                return Err(Error::Ack);
            }
            previous = Some(r.first);
        }
        if self.last_send.is_some_and(|at| now < at) {
            return Err(Error::Clock);
        }
        self.largest_ack = Some(
            self.largest_ack
                .map_or(first.last, |old| old.max(first.last)),
        );
        let mut result = Outcome::default();
        let mut pending = VecDeque::with_capacity(self.sent.len());
        while let Some(p) = self.sent.pop_front() {
            if ack.acknowledges(p.number) {
                if p.number == first.last && p.ack_eliciting {
                    result.rtt_sample = Some(now.duration_since(p.at));
                }
                if p.in_flight {
                    let bytes = u64::from(p.bytes);
                    self.bytes_in_flight -= bytes;
                    result.acknowledged_bytes += bytes;
                }
                result.acknowledged.push(p);
            } else {
                pending.push_back(p);
            }
        }
        self.sent = pending;
        self.detect(now, loss_delay, &mut result);
        Ok(result)
    }

    pub fn on_loss_timer(&mut self, now: Instant, loss_delay: Duration) -> Result<Outcome, Error> {
        if self.last_send.is_some_and(|at| now < at) {
            return Err(Error::Clock);
        }
        let mut result = Outcome::default();
        self.detect(now, loss_delay, &mut result);
        Ok(result)
    }

    fn detect(&mut self, now: Instant, delay: Duration, out: &mut Outcome) {
        let Some(largest) = self.largest_ack else {
            return;
        };
        let mut pending = VecDeque::with_capacity(self.sent.len());
        while let Some(p) = self.sent.pop_front() {
            let lost = p.number < largest
                && (largest - p.number >= PACKET_THRESHOLD || now.duration_since(p.at) >= delay);
            if lost {
                if p.in_flight {
                    let bytes = u64::from(p.bytes);
                    self.bytes_in_flight -= bytes;
                    out.lost_bytes += bytes;
                }
                out.lost.push(p);
            } else {
                pending.push_back(p);
            }
        }
        self.sent = pending;
    }

    /// Earliest time-threshold deadline; PTO for the no-ACK case belongs to
    /// connection-level recovery and is intentionally not synthesized here.
    pub fn loss_deadline(&self, delay: Duration) -> Option<Instant> {
        let largest = self.largest_ack?;
        self.sent
            .iter()
            .filter(|p| p.number < largest)
            .filter_map(|p| p.at.checked_add(delay))
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_core::ack::Range;

    fn packet(number: u64, at: Instant) -> Sent {
        Sent {
            number,
            at,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            frames: vec![FrameRef::Crypto {
                offset: number,
                len: 1,
            }],
        }
    }
    fn ack(number: u64) -> Ack {
        Ack {
            delay: 0,
            ranges: vec![Range {
                first: number,
                last: number,
            }],
            ecn: None,
        }
    }

    #[test]
    fn packet_and_time_loss_with_retransmission_candidates() {
        let now = Instant::now();
        let mut l = Ledger::default();
        for n in 0..4 {
            l.record(packet(n, now)).unwrap();
        }
        let result = l
            .acknowledge(&ack(3), now, Duration::from_millis(20))
            .unwrap();
        assert_eq!(result.acknowledged_bytes, 1200);
        assert_eq!(result.lost_bytes, 1200);
        assert_eq!(result.lost[0].number, 0);
        assert_eq!(
            result.lost[0].frames,
            [FrameRef::Crypto { offset: 0, len: 1 }]
        );
        assert_eq!(l.bytes_in_flight(), 2400);
        assert_eq!(
            l.loss_deadline(Duration::from_millis(20)),
            Some(now + Duration::from_millis(20))
        );
        let out = l
            .on_loss_timer(now + Duration::from_millis(20), Duration::from_millis(20))
            .unwrap();
        assert_eq!(out.lost_bytes, 2400);
        assert_eq!(l.bytes_in_flight(), 0);
        assert!(l
            .acknowledge(&ack(3), now, Duration::ZERO)
            .unwrap()
            .acknowledged
            .is_empty());
    }

    #[test]
    fn invalid_ack_and_sequences_do_not_mutate() {
        let now = Instant::now();
        let mut l = Ledger::default();
        assert_eq!(l.record(packet(1, now)), Err(Error::Sequence));
        l.record(packet(0, now)).unwrap();
        assert_eq!(
            l.acknowledge(&ack(1), now, Duration::ZERO).unwrap_err(),
            Error::Ack
        );
        let bad = Ack {
            delay: 0,
            ranges: vec![Range { first: 1, last: 0 }],
            ecn: None,
        };
        assert_eq!(
            l.acknowledge(&bad, now, Duration::ZERO).unwrap_err(),
            Error::Ack
        );
        assert_eq!(l.bytes_in_flight(), 1200);
        assert!(l
            .on_loss_timer(now, Duration::ZERO)
            .unwrap()
            .lost
            .is_empty());
        assert_eq!(
            l.acknowledge(&ack(0), now, Duration::ZERO)
                .unwrap()
                .rtt_sample,
            Some(Duration::ZERO)
        );
        assert_eq!(l.bytes_in_flight(), 0);
    }
}
