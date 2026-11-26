//! Bounded RFC 9002-style packet loss bookkeeping for one number space.
//! ACKs must come from an authenticated packet in that space. Returned
//! frame descriptors are candidates for retransmission, not a send queue:
//! the owner must suppress frames already acknowledged by another packet.
use super::{ack::Ack, wire::MAX_VARINT};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
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
    MtuProbe,
    PaddingOnly,
}

#[derive(Clone, Debug)]
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
    /// Late ACKs carry delivery evidence, but no remaining flight credit.
    pub late_acknowledged: Vec<Sent>,
    pub acknowledged_bytes: u64,
    pub lost_bytes: u64,
    pub rtt_sample: Option<Duration>,
    pub newly_acked_eliciting: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    Sequence,
    Ack,
    Clock,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Status { Pending, Acked, Lost, Neutral }

#[derive(Default)]
pub struct Ledger {
    next: u64,
    sent: VecDeque<Sent>,
    last_send: Option<Instant>,
    largest_ack: Option<u64>,
    bytes_in_flight: u64,
    congestion_history: BTreeMap<u64, (Instant, Status)>,
    ack_only: BTreeMap<u64, Instant>,
    recent_lost: BTreeMap<u64, Sent>,
    burned: BTreeSet<u64>,
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
        if packet.ack_eliciting {
            self.congestion_history.insert(packet.number, (packet.at, Status::Pending));
            if self.congestion_history.len() > MAX_OUTSTANDING * 2 {
                self.congestion_history.pop_first();
            }
        } else {
            self.ack_only.insert(packet.number, packet.at);
            if self.ack_only.len() > MAX_OUTSTANDING {
                self.ack_only.pop_first();
            }
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

    /// Abandon flight accounting for the old physical path, but never
    /// reset the connection-wide packet number or permit ACKs of unsent PN.
    pub(crate) fn restart_path(&mut self) {
        self.sent.clear();
        self.bytes_in_flight = 0;
        self.largest_ack = None;
        self.congestion_history.clear();
        self.ack_only.clear();
        self.recent_lost.clear();
    }

    /// A definitive local EMSGSIZE means this number was never transmitted.
    /// Keep a bounded set for ACK validation; fail closed rather than forget.
    pub(crate) fn burn(&mut self, number: u64, now: Instant) -> Result<(), Error> {
        if number != self.next || number > MAX_VARINT { return Err(Error::Sequence); }
        if self.burned.len() >= MAX_OUTSTANDING { return Err(Error::Limit); }
        if self.last_send.is_some_and(|last| now < last) { return Err(Error::Clock); }
        self.burned.insert(number);
        self.next += 1;
        self.last_send = Some(now);
        Ok(())
    }

    pub(crate) fn has_eliciting_flight(&self) -> bool {
        self.sent.iter().any(|packet| packet.ack_eliciting)
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
        self.acknowledge_with_delay(ack, now, |_| loss_delay)
    }

    /// The RFC 9002 ACK handler updates RTT before time-threshold loss detection.
    pub(crate) fn acknowledge_with_delay(
        &mut self,
        ack: &Ack,
        now: Instant,
        delay: impl FnOnce(Option<Duration>) -> Duration,
    ) -> Result<Outcome, Error> {
        let first = ack.ranges.first().ok_or(Error::Ack)?;
        if ack.ranges.len() > super::ack::MAX_ACK_RANGES as usize + 1 || first.last >= self.next {
            return Err(Error::Ack);
        }
        let mut previous: Option<u64> = None;
        for r in &ack.ranges {
            if r.first > r.last
                || r.last >= self.next
                || self.burned.range(r.first..=r.last).next().is_some()
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
        // RFC 9002 section 5.1: sample the largest newly acknowledged
        // packet, provided at least one newly ACKed packet is eliciting.
        // The largest itself can be ACK-only. Old-path timestamps were
        // cleared on migration, and an ACK can never sample twice.
        let largest_at = self.congestion_history.get(&first.last)
            .filter(|(_, status)| *status != Status::Acked)
            .map(|(at, _)| *at)
            .or_else(|| self.ack_only.get(&first.last).copied());
        let mut result = Outcome::default();
        for range in &ack.ranges {
            for (_, (_, status)) in self.congestion_history.range_mut(range.first..=range.last) {
                result.newly_acked_eliciting |= *status != Status::Acked;
                *status = Status::Acked;
            }
        }
        self.ack_only.retain(|number, _| !ack.acknowledges(*number));
        self.recent_lost.retain(|number, packet| {
            if ack.acknowledges(*number) {
                result.late_acknowledged.push(packet.clone());
                false
            } else { true }
        });
        let mut pending = VecDeque::with_capacity(self.sent.len());
        while let Some(p) = self.sent.pop_front() {
            if ack.acknowledges(p.number) {
                result.newly_acked_eliciting |= p.ack_eliciting;
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
        if result.newly_acked_eliciting {
            result.rtt_sample = largest_at.map(|at| now.duration_since(at));
        }
        let loss_delay = delay(result.rtt_sample);
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
                if let Some((_, status)) = self.congestion_history.get_mut(&p.number) {
                    *status = if p.frames.contains(&FrameRef::MtuProbe) { Status::Neutral } else { Status::Lost };
                }
                self.recent_lost.insert(p.number, p.clone());
                if self.recent_lost.len() > MAX_OUTSTANDING {
                    self.recent_lost.pop_first();
                }
                out.lost.push(p);
            } else {
                pending.push_back(p);
            }
        }
        self.sent = pending;
    }

    /// RFC 9002 persistent congestion can span multiple ACK/loss events.
    /// An unresolved or ACKed ack-eliciting packet breaks the run; ignored
    /// ACK-only numbers do not. Bounded history eviction is conservative.
    pub(crate) fn persistent_end(&self, first_rtt: Instant, threshold: Duration) -> Option<Instant> {
        let mut start = None;
        let mut end = None;
        for &(at, status) in self.congestion_history.values() {
            if status != Status::Lost || at < first_rtt {
                start = None;
                continue;
            }
            let begin = *start.get_or_insert(at);
            if at.saturating_duration_since(begin) >= threshold {
                end = Some(at);
            }
        }
        end
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
    fn persistent_congestion_spans_events_but_late_ack_breaks_interval() {
        let now = Instant::now();
        let tick = Duration::from_millis(10);
        let mut l = Ledger::default();
        l.record(packet(0, now)).unwrap();
        let mut ack_only = packet(1, now + tick);
        ack_only.ack_eliciting = false;
        ack_only.in_flight = false;
        l.record(ack_only).unwrap();
        l.record(packet(2, now + tick * 2)).unwrap();
        l.record(packet(3, now + tick * 3)).unwrap();
        l.record(packet(4, now + tick * 4)).unwrap();
        let at = now + tick * 4;
        // Packet 0 is lost by packet threshold; 2 and 3 remain pending.
        l.acknowledge(&ack(4), at, tick * 4).unwrap();
        assert_eq!(l.persistent_end(now, tick * 2), None);
        l.on_loss_timer(at + tick * 4, tick * 4).unwrap();
        assert_eq!(l.persistent_end(now, tick * 2), Some(now + tick * 3));
        // A late ACK splits the run, including across an ACK-only number.
        l.acknowledge(&ack(2), at + tick * 4, tick * 4).unwrap();
        assert_eq!(l.persistent_end(now, tick * 2), None);
        l.restart_path();
        assert_eq!(l.persistent_end(now, tick), None);
    }

    #[test]
    fn updated_rtt_controls_time_threshold_in_same_ack() {
        let now = Instant::now();
        let mut l = Ledger::default();
        l.record(packet(0, now)).unwrap();
        l.record(packet(1, now + Duration::from_millis(20))).unwrap();
        let out = l.acknowledge_with_delay(&ack(1), now + Duration::from_millis(30), |sample| {
            assert_eq!(sample, Some(Duration::from_millis(10)));
            Duration::from_millis(12)
        }).unwrap();
        assert_eq!(out.lost.len(), 1);
    }

    #[test]
    fn burned_packet_numbers_never_become_acknowledgeable_after_migration() {
        let now = Instant::now();
        let mut l = Ledger::default();
        l.record(packet(0, now)).unwrap();
        l.burn(1, now).unwrap();
        l.record(packet(2, now)).unwrap();
        let a = Ack { delay: 0, ranges: vec![Range { first: 0, last: 2 }], ecn: None };
        assert_eq!(l.acknowledge(&a, now, Duration::ZERO).unwrap_err(), Error::Ack);
        assert_eq!(l.bytes_in_flight(), 2400);
        l.restart_path();
        assert_eq!(l.acknowledge(&ack(1), now, Duration::ZERO).unwrap_err(), Error::Ack);
        l.record(packet(3, now)).unwrap();
    }

    #[test]
    fn sample_largest_ack_only_when_new_eliciting_packet_is_acknowledged() {
        let start = Instant::now();
        let delta = Duration::from_millis(10);
        let mut l = Ledger::default();
        l.record(packet(0, start)).unwrap();
        let mut pure = packet(1, start + delta);
        pure.ack_eliciting = false;
        pure.in_flight = false;
        l.record(pure).unwrap();
        let both = Ack { delay: 0, ranges: vec![Range { first: 0, last: 1 }], ecn: None };
        let outcome = l.acknowledge(&both, start + delta * 3, delta * 4).unwrap();
        assert_eq!(outcome.rtt_sample, Some(delta * 2));
        assert!(outcome.newly_acked_eliciting);
        assert_eq!(outcome.acknowledged_bytes, 1200);
        let duplicate = l.acknowledge(&both, start + delta * 4, delta).unwrap();
        assert!(!duplicate.newly_acked_eliciting);
        assert_eq!(duplicate.rtt_sample, None);
        let mut pure = packet(2, start + delta * 4);
        pure.ack_eliciting = false;
        pure.in_flight = false;
        l.record(pure).unwrap();
        assert_eq!(l.acknowledge(&ack(2), start + delta * 5, delta).unwrap().rtt_sample, None);
    }

    #[test]
    fn late_ack_preserves_delivery_metadata_without_releasing_flight_twice() {
        let start = Instant::now();
        let delta = Duration::from_millis(10);
        let mut l = Ledger::default();
        for n in 0..4 { l.record(packet(n, start)).unwrap(); }
        let first = l.acknowledge(&ack(3), start + delta, delta * 2).unwrap();
        assert_eq!(first.lost[0].number, 0);
        let flight = l.bytes_in_flight();
        let late = l.acknowledge(&ack(0), start + delta, delta * 2).unwrap();
        assert_eq!(late.late_acknowledged.len(), 1);
        assert_eq!(late.late_acknowledged[0].bytes, 1200);
        assert_eq!(late.acknowledged_bytes, 0);
        assert_eq!(l.bytes_in_flight(), flight);
        assert!(l.acknowledge(&ack(0), start + delta, delta * 2).unwrap().late_acknowledged.is_empty());
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
