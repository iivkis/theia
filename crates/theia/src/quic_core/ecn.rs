//! RFC 9000 section 13.4.2 ECN counter validation, independent of socket I/O.
//! An owner must supply actual sent IP marks and authenticated, ledger-checked
//! ACKs. Do not enable ECN until the platform can send and receive codepoints.
use super::{ack::Ack, wire::MAX_VARINT};
use std::{collections::BTreeMap, time::{Duration, Instant}};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Mark {
    #[default]
    NotEct,
    Ect0,
    Ect1,
    Ce,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts([u64; 3]);

impl Counts {
    pub fn record(&mut self, mark: Mark) {
        let index = match mark {
            Mark::NotEct => return,
            Mark::Ect0 => 0,
            Mark::Ect1 => 1,
            Mark::Ce => 2,
        };
        self.0[index] = self.0[index].saturating_add(1).min(MAX_VARINT);
    }

    pub fn reported(self) -> Option<[u64; 3]> {
        (self.0 != [0; 3]).then_some(self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum State {
    #[default]
    Testing,
    Capable,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Feedback {
    Ignored,
    Valid { ce_increase: u64 },
    Failed,
}

/// One packet number space on a single path. Migration needs a new path
/// validation state and the connection-wide counter baseline, not a reset
/// of the wire counters. The caller must not mix different path epochs.
#[derive(Default)]
pub struct Validator {
    state: State,
    sent: [u64; 2],
    reported: [u64; 3],
    largest: Option<u64>,
}

impl Validator {
    pub fn state(&self) -> State {
        self.state
    }

    /// Count only packets actually transmitted with the indicated codepoint.
    pub fn sent(&mut self, mark: Mark) {
        let index = match mark {
            Mark::NotEct | Mark::Ce => return,
            Mark::Ect0 => 0,
            Mark::Ect1 => 1,
        };
        self.sent[index] = self.sent[index].saturating_add(1).min(MAX_VARINT);
    }

    pub fn fail(&mut self) {
        self.state = State::Failed;
    }

    /// newly_marked counts distinct ECT(0), ECT(1) packets newly ACKed by
    /// the authenticated sent ledger. ACK reordering cannot disable ECN.
    pub fn acknowledge(
        &mut self,
        largest: u64,
        newly_marked: [u64; 2],
        counts: Option<[u64; 3]>,
    ) -> Feedback {
        if self.state == State::Failed {
            return Feedback::Failed;
        }
        if self.largest.is_some_and(|old| largest <= old) {
            return Feedback::Ignored;
        }
        self.largest = Some(largest);
        let Some(counts) = counts else {
            if newly_marked != [0; 2] {
                self.fail();
                return Feedback::Failed;
            }
            return Feedback::Ignored;
        };
        let invalid = counts
            .iter()
            .zip(self.reported)
            .any(|(&n, old)| n < old || n > MAX_VARINT)
            || counts[0] > self.sent[0]
            || counts[1] > self.sent[1]
            || counts.iter().map(|&n| u128::from(n)).sum::<u128>()
                > self.sent.iter().map(|&n| u128::from(n)).sum::<u128>();
        if invalid {
            self.fail();
            return Feedback::Failed;
        }
        let delta = [
            counts[0] - self.reported[0],
            counts[1] - self.reported[1],
            counts[2] - self.reported[2],
        ];
        if delta[0] + delta[2] < newly_marked[0]
            || delta[1] + delta[2] < newly_marked[1]
            || delta.iter().map(|&n| u128::from(n)).sum::<u128>()
                < newly_marked.iter().map(|&n| u128::from(n)).sum::<u128>()
        {
            self.fail();
            return Feedback::Failed;
        }
        self.reported = counts;
        if newly_marked != [0; 2] {
            self.state = State::Capable;
        }
        Feedback::Valid {
            ce_increase: delta[2],
        }
    }
}

/// Bounded application-space ECN experiment. Marks are registered only
/// after successful kernel send and authenticated ledger insertion. On
/// migration or exhausted evidence, fall back to Not-ECT for this session.
#[derive(Default)]
pub(crate) struct PathEcn {
    enabled: bool,
    validator: Validator,
    pending: BTreeMap<u64, Instant>,
    testing_sent: u8,
    first: Option<Instant>,
}

impl PathEcn {
    pub(crate) fn enable(&mut self, supported: bool) { self.enabled = supported; }
    pub(crate) fn disable(&mut self) {
        self.enabled = false;
        self.pending.clear();
        self.validator.fail();
    }
    pub(crate) fn should_mark(&self) -> bool {
        self.enabled && match self.validator.state() {
            State::Testing => self.testing_sent < 10,
            State::Capable => true,
            State::Failed => false,
        }
    }
    pub(crate) fn sent(&mut self, pn: u64, mark: Mark, now: Instant) {
        if !self.enabled { return; }
        if mark != Mark::Ect0 || self.pending.len() >= 8192 {
            self.disable();
            return;
        }
        self.validator.sent(mark);
        self.pending.insert(pn, now);
        self.first.get_or_insert(now);
        self.testing_sent = self.testing_sent.saturating_add(1);
    }
    pub(crate) fn tick(&mut self, now: Instant, pto: Duration) {
        if self.enabled && self.validator.state() == State::Testing
            && self.first.is_some_and(|at| now.saturating_duration_since(at) >= pto.saturating_mul(3)) {
            self.disable();
        }
    }
    pub(crate) fn acknowledge(&mut self, ack: &Ack) -> Option<Instant> {
        if !self.enabled { return None; }
        let largest = ack.ranges.first()?.last;
        let mut newly = 0u64;
        let mut newest = None;
        self.pending.retain(|pn, at| {
            if ack.acknowledges(*pn) {
                newly += 1;
                newest = Some(newest.map_or(*at, |old: Instant| old.max(*at)));
                false
            } else { true }
        });
        match self.validator.acknowledge(largest, [newly, 0], ack.ecn) {
            Feedback::Failed => { self.disable(); None },
            Feedback::Valid { ce_increase } if ce_increase != 0 => newest,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_marked_packet_history_requires_valid_feedback_and_disables_on_migration() {
        use crate::quic_core::ack::Range;
        let now = Instant::now();
        let mut p = PathEcn::default();
        p.enable(true);
        assert!(p.should_mark());
        p.sent(1, Mark::Ect0, now);
        let ack = Ack { delay: 0, ranges: vec![Range { first: 1, last: 1 }], ecn: Some([0, 0, 1]) };
        assert_eq!(p.acknowledge(&ack), Some(now));
        assert!(p.should_mark());
        p.disable();
        assert!(!p.should_mark());
        let mut p = PathEcn::default();
        p.enable(true);
        p.sent(2, Mark::NotEct, now);
        assert!(!p.should_mark());
    }

    #[test]
    fn validates_counter_deltas_and_ignores_reordered_ack() {
        let mut v = Validator::default();
        for mark in [Mark::Ect0, Mark::Ect0, Mark::Ect1] {
            v.sent(mark);
        }
        assert_eq!(v.acknowledge(0, [0, 0], None), Feedback::Ignored);
        assert_eq!(v.state(), State::Testing);
        assert_eq!(
            v.acknowledge(1, [1, 0], Some([1, 0, 0])),
            Feedback::Valid { ce_increase: 0 }
        );
        assert_eq!(v.state(), State::Capable);
        assert_eq!(
            v.acknowledge(3, [1, 1], Some([1, 1, 1])),
            Feedback::Valid { ce_increase: 1 }
        );
        assert_eq!(v.acknowledge(2, [1, 0], None), Feedback::Ignored);
        assert_eq!(
            v.acknowledge(4, [0, 0], Some([1, 1, 1])),
            Feedback::Valid { ce_increase: 0 }
        );
        assert_eq!(v.acknowledge(5, [0, 0], Some([0, 1, 1])), Feedback::Failed);
        assert_eq!(v.state(), State::Failed);
        assert_eq!(v.acknowledge(6, [0, 0], Some([1, 1, 1])), Feedback::Failed);
    }

    #[test]
    fn detects_missing_bleached_and_fabricated_marks() {
        let mut extreme = Validator::default();
        assert_eq!(
            extreme.acknowledge(1, [u64::MAX; 2], Some([0; 3])),
            Feedback::Failed
        );
        for counters in [None, Some([0, 0, 0]), Some([0, 1, 0]), Some([2, 0, 0])] {
            let mut v = Validator::default();
            v.sent(Mark::Ect0);
            assert_eq!(v.acknowledge(1, [1, 0], counters), Feedback::Failed);
        }
        let mut v = Validator::default();
        v.sent(Mark::Ect0);
        v.sent(Mark::Ect1);
        assert_eq!(v.acknowledge(1, [1, 1], Some([0, 0, 1])), Feedback::Failed);
        let mut v = Validator::default();
        v.sent(Mark::NotEct);
        v.sent(Mark::Ce);
        assert_eq!(v.acknowledge(0, [0, 0], Some([0, 0, 1])), Feedback::Failed);
    }
}
