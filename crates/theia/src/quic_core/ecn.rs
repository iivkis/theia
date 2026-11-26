//! RFC 9000 section 13.4.2 ECN counter validation, independent of socket I/O.
//! An owner must supply actual sent IP marks and authenticated, ledger-checked
//! ACKs. Do not enable ECN until the platform can send and receive codepoints.
use super::wire::MAX_VARINT;

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

#[cfg(test)]
mod tests {
    use super::*;

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
