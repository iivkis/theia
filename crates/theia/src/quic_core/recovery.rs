//! RFC 9002 RTT/PTO math and per-path anti-amplification accounting.
//! The caller must authenticate ACKs and manage packet-number spaces,
//! sent packets, loss detection, timers and congestion control.
use std::time::Duration;

const INITIAL_RTT: Duration = Duration::from_millis(333);
const GRANULARITY: Duration = Duration::from_millis(1);

#[derive(Clone, Debug)]
pub struct Rtt {
    latest: Duration,
    minimum: Option<Duration>,
    smoothed: Duration,
    variation: Duration,
}

impl Default for Rtt {
    fn default() -> Self {
        Self {
            latest: INITIAL_RTT,
            minimum: None,
            smoothed: INITIAL_RTT,
            variation: INITIAL_RTT / 2,
        }
    }
}

impl Rtt {
    /// ACK delay may only be subtracted after handshake confirmation.
    pub fn update(
        &mut self,
        measured: Duration,
        ack_delay: Duration,
        max_ack_delay: Duration,
        handshake_confirmed: bool,
    ) {
        self.latest = measured;
        let Some(previous_min) = self.minimum else {
            self.minimum = Some(measured);
            self.smoothed = measured;
            self.variation = measured / 2;
            return;
        };
        let minimum = previous_min.min(measured);
        self.minimum = Some(minimum);
        let delay = if handshake_confirmed {
            ack_delay.min(max_ack_delay)
        } else {
            Duration::ZERO
        };
        let adjusted = if measured.saturating_sub(minimum) >= delay {
            measured.saturating_sub(delay)
        } else {
            measured
        };
        let difference = self.smoothed.abs_diff(adjusted);
        self.variation = (self.variation - self.variation / 4).saturating_add(difference / 4);
        self.smoothed = (self.smoothed - self.smoothed / 8).saturating_add(adjusted / 8);
    }

    pub fn smoothed(&self) -> Duration {
        self.smoothed
    }

    pub fn minimum(&self) -> Option<Duration> {
        self.minimum
    }

    pub fn loss_delay(&self) -> Duration {
        let base = self.latest.max(self.smoothed);
        base.saturating_add(base / 8).max(GRANULARITY)
    }

    /// For Initial/Handshake pass zero for max_ack_delay.
    pub fn pto(&self, max_ack_delay: Duration, count: u32) -> Duration {
        self.smoothed
            .saturating_add(self.variation.saturating_mul(4).max(GRANULARITY))
            .saturating_add(max_ack_delay)
            .saturating_mul(2u32.saturating_pow(count))
    }
}

/// One unvalidated server path; count accepted input and actual attempted
/// output bytes. Validation must come from the endpoint's authenticated
/// path/address validation, never from parsing a public Initial.
#[derive(Default, Debug)]
pub struct PathBudget {
    received: u64,
    sent: u64,
    validated: bool,
}

impl PathBudget {
    pub fn received(&mut self, bytes: u64) {
        self.received = self.received.saturating_add(bytes);
    }

    pub fn can_send(&self, bytes: u64) -> bool {
        self.sent
            .checked_add(bytes)
            .is_some_and(|total| self.validated || total <= self.received.saturating_mul(3))
    }

    pub fn reserve_send(&mut self, bytes: u64) -> bool {
        let Some(total) = self.sent.checked_add(bytes) else {
            return false;
        };
        if !self.validated && total > self.received.saturating_mul(3) {
            return false;
        }
        self.sent = total;
        true
    }

    pub fn validate(&mut self) {
        self.validated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn rtt_minimum_and_pto_backoff() {
        let mut rtt = Rtt::default();
        assert_eq!(rtt.pto(Duration::ZERO, 0), ms(999));
        rtt.update(ms(80), ms(40), ms(25), false);
        assert_eq!(rtt.minimum(), Some(ms(80)));
        assert_eq!(rtt.smoothed(), ms(80));
        assert_eq!(rtt.pto(Duration::ZERO, 0), ms(240));
        rtt.update(ms(100), ms(40), ms(25), true);
        assert_eq!(rtt.smoothed(), ms(82) + Duration::from_micros(500));
        assert_eq!(rtt.loss_delay(), ms(112) + Duration::from_micros(500));
        assert_eq!(rtt.pto(ms(25), 1), rtt.pto(ms(25), 0) * 2);
        rtt.update(ms(60), ms(25), ms(25), true);
        assert_eq!(rtt.minimum(), Some(ms(60)));
    }

    #[test]
    fn path_budget_is_independent_and_fail_closed() {
        let mut path = PathBudget::default();
        assert!(!path.reserve_send(1));
        path.received(1200);
        assert!(path.reserve_send(3600));
        assert!(!path.reserve_send(1));
        path.received(100);
        assert!(path.reserve_send(300));
        let mut other = PathBudget::default();
        assert!(!other.reserve_send(1));
        path.validate();
        assert!(path.reserve_send(10000));
        assert!(!path.reserve_send(u64::MAX));
        other.received(u64::MAX);
        assert!(other.reserve_send(u64::MAX));
        assert!(!other.reserve_send(1));
    }
}
