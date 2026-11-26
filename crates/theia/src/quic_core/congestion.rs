//! QUIC CUBIC window controller, following RFC 9438 with RFC 9002
//! recovery and an RFC 9406-style conservative slow-start extension.
//! Independent conformance and cross-space integration remain required.
use std::time::{Duration, Instant};

const MAX_CWND: u64 = 64 * 1024 * 1024;
const BETA: f64 = 0.7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    Accounting,
}

/// RFC 9438 cubic target in packets. This function does not grant send credit
/// or implement the TCP-friendly region, pacing or recovery transitions.
pub fn cubic_target(w_max: f64, w_epoch: f64, elapsed: Duration) -> Option<f64> {
    if !w_max.is_finite() || !w_epoch.is_finite() || w_max < 0.0 || w_epoch < 0.0 {
        return None;
    }
    let k = ((w_max - w_epoch) / 0.4).cbrt();
    let w = 0.4 * (elapsed.as_secs_f64() - k).powi(3) + w_max;
    w.is_finite().then_some(w.max(0.0))
}

// Packet-timed rounds: sample at least eight RTTs in each round before
// comparing its minimum to the preceding round. No ACK-count growth.
#[derive(Default)]
struct SlowStart {
    end: Option<u64>,
    minimum: Option<Duration>,
    previous: Option<Duration>,
    samples: u32,
    css_baseline: Option<Duration>,
    css_rounds: u8,
}

impl SlowStart {
    fn sample(&mut self, pn: u64, last_sent: u64, rtt: Duration) -> bool {
        if self.end.is_some_and(|end| pn > end) {
            if let Some(baseline) = self.css_baseline {
                if self.samples >= 8 {
                    if self.minimum.is_some_and(|rtt| rtt < baseline) {
                        self.css_baseline = None;
                        self.css_rounds = 0;
                    } else {
                        self.css_rounds = self.css_rounds.saturating_add(1);
                        if self.css_rounds >= 5 { return true; }
                    }
                }
            }
            self.previous = self.minimum.filter(|_| self.samples >= 8);
            self.minimum = None;
            self.samples = 0;
            self.end = Some(last_sent);
        }
        self.end.get_or_insert(last_sent);
        self.minimum = Some(self.minimum.map_or(rtt, |old| old.min(rtt)));
        self.samples = self.samples.saturating_add(1);
        if self.samples >= 8 && self.css_baseline.is_none() {
            if let (Some(previous), Some(current)) = (self.previous, self.minimum) {
                let threshold = (previous / 8).clamp(Duration::from_millis(4), Duration::from_millis(16));
                if current >= previous.saturating_add(threshold) {
                    self.css_baseline = Some(current);
                    self.css_rounds = 0;
                }
            }
        }
        false
    }
}

/// Congestion response checkpoint, excluding authoritative flight bytes.
pub(crate) struct Undo {
    cwnd: u64,
    ssthresh: u64,
    last_max: f64,
    prior_cwnd: f64,
    friendly: f64,
    recovery: Option<Instant>,
}

pub struct Window {
    mtu: u64,
    cwnd: u64,
    in_flight: u64,
    recovery: Option<Instant>,
    ssthresh: u64,
    last_max: f64,
    prior_cwnd: f64,
    epoch: Option<(Instant, f64)>,
    growth_credit: f64,
    friendly: f64,
    slow: SlowStart,
    idle_since: Option<Instant>,
    ecn_backoff: u8,
    last_ecn: Option<Instant>,
}

impl Window {
    pub fn new(mtu: u64) -> Result<Self, Error> {
        if !(1200..=65527).contains(&mtu) {
            return Err(Error::Limit);
        }
        let cwnd = (10 * mtu).min((2 * mtu).max(14720));
        Ok(Self {
            mtu,
            cwnd,
            in_flight: 0,
            recovery: None,
            ssthresh: MAX_CWND,
            last_max: 0.0,
            prior_cwnd: 0.0,
            epoch: None,
            growth_credit: 0.0,
            friendly: 0.0,
            slow: SlowStart::default(),
            idle_since: None,
            ecn_backoff: 0,
            last_ecn: None,
        })
    }

    pub(crate) fn set_mtu(&mut self, mtu: u64) {
        debug_assert!((1200..=super::mtu::MAX_UDP_PAYLOAD as u64).contains(&mtu));
        let scale = self.mtu as f64 / mtu as f64;
        self.last_max *= scale;
        self.prior_cwnd *= scale;
        self.friendly *= scale;
        self.mtu = mtu;
        self.cwnd = self.cwnd.max(2 * mtu);
        self.ssthresh = self.ssthresh.max(2 * mtu);
        self.epoch = None;
        self.growth_credit = 0.0;
        self.slow = SlowStart::default();
    }

    pub(crate) fn can_reserve_size(&self, bytes: u64) -> bool {
        bytes != 0 && bytes <= super::mtu::MAX_UDP_PAYLOAD as u64
            && self.in_flight.checked_add(bytes).is_some_and(|n| n <= self.cwnd)
    }

    pub(crate) fn reserve_discovery(&mut self, bytes: u64) -> Result<(), Error> {
        if !self.can_reserve_size(bytes) { return Err(Error::Limit); }
        self.in_flight += bytes;
        Ok(())
    }

    pub(crate) fn checkpoint(&self) -> Undo {
        Undo {
            cwnd: self.cwnd, ssthresh: self.ssthresh, last_max: self.last_max,
            prior_cwnd: self.prior_cwnd, friendly: self.friendly, recovery: self.recovery,
        }
    }

    pub(crate) fn undo_loss(&mut self, prior: Undo) {
        if self.cwnd >= prior.cwnd { return; }
        self.cwnd = prior.cwnd;
        self.ssthresh = prior.ssthresh;
        self.last_max = prior.last_max;
        self.prior_cwnd = prior.prior_cwnd;
        self.friendly = prior.friendly;
        self.recovery = prior.recovery;
        // Never accumulate cubic wall time while the reduced window was active.
        self.epoch = None;
        self.growth_credit = 0.0;
    }

    pub fn cwnd(&self) -> u64 {
        self.cwnd
    }
    pub fn in_flight(&self) -> u64 {
        self.in_flight
    }

    /// Ordinary in-flight packets only. RFC PTO probes require a separate
    /// bounded exception and anti-amplification check, not this method.
    pub fn reserve(&mut self, bytes: u64) -> Result<(), Error> {
        let next = self.in_flight.checked_add(bytes).ok_or(Error::Limit)?;
        if bytes == 0 || bytes > self.mtu || next > self.cwnd {
            return Err(Error::Limit);
        }
        self.in_flight = next;
        Ok(())
    }

    /// At most one MTU per PTO probe; caller enforces timer and probe count.
    pub fn reserve_probe(&mut self, bytes: u64) -> Result<(), Error> {
        if bytes == 0 || bytes > self.mtu {
            return Err(Error::Limit);
        }
        self.in_flight = self.in_flight.checked_add(bytes).ok_or(Error::Limit)?;
        Ok(())
    }

    pub fn retire(&mut self, bytes: u64) -> Result<(), Error> {
        self.in_flight = self.in_flight.checked_sub(bytes).ok_or(Error::Accounting)?;
        Ok(())
    }

    /// Apply a single congestion event per recovery boundary (beta=0.7).
    pub fn loss(&mut self, sent: Instant, now: Instant) -> Result<bool, Error> {
        if sent > now {
            return Err(Error::Accounting);
        }
        if self.recovery.is_some_and(|start| sent <= start) {
            return Ok(false);
        }
        self.recovery = Some(now);
        let packets = self.cwnd as f64 / self.mtu as f64;
        self.prior_cwnd = packets;
        // Fast convergence: when another flow joins, reduce the remembered
        // maximum more aggressively than the actual window reduction.
        self.last_max = if packets < self.last_max {
            packets * (1.0 + BETA) / 2.0
        } else {
            packets
        };
        self.cwnd = (self.cwnd.saturating_mul(7) / 10).max(2 * self.mtu);
        self.ssthresh = self.cwnd;
        self.epoch = None;
        self.growth_credit = 0.0;
        self.slow = SlowStart::default();
        self.idle_since = None;
        Ok(true)
    }

    /// Collapse the window on verified persistent congestion. Preserve
    /// accounting for packets that have not yet been acknowledged/lost.
    pub fn persistent_congestion(&mut self, now: Instant) {
        self.recovery = Some(now);
        let previous = self.cwnd;
        self.prior_cwnd = previous as f64 / self.mtu as f64;
        self.cwnd = 2 * self.mtu;
        self.ssthresh = (previous.saturating_mul(7) / 10).max(self.cwnd);
        self.last_max = 0.0;
        self.slow = SlowStart::default();
        self.idle_since = None;
        self.epoch = None;
        self.growth_credit = 0.0;
    }

    pub(crate) fn application_limited(&mut self) {
        // Conservative rebase on idle/flow-control limit: no wall-clock
        // windfall on the next ACK. Keep the remembered saturation point.
        self.epoch = None;
        self.growth_credit = 0.0;
        self.idle_since = None;
    }

    pub(crate) fn mark_idle(&mut self, now: Instant) {
        self.idle_since.get_or_insert(now);
    }

    pub(crate) fn resume(&mut self, now: Instant) {
        if let Some(idle) = self.idle_since.take() {
            if let Some((epoch, initial)) = self.epoch {
                self.epoch = epoch.checked_add(now.saturating_duration_since(idle)).map(|at| (at, initial));
            }
        }
    }

    pub(crate) fn rtt_sample(&mut self, pn: u64, last_sent: u64, rtt: Duration) {
        if self.cwnd < self.ssthresh && self.slow.sample(pn, last_sent, rtt) {
            self.ssthresh = self.cwnd;
            self.prior_cwnd = self.cwnd as f64 / self.mtu as f64;
            self.last_max = self.prior_cwnd;
            self.epoch = None;
            self.growth_credit = 0.0;
        }
    }

    pub(crate) fn ecn(&mut self, sent: Instant, now: Instant) -> Result<(), Error> {
        if self.loss(sent, now)? && self.cwnd == 2 * self.mtu {
            // QUIC minimum window remains two packets. Further CE reduces
            // the pacing rate, rather than violating the minimum cwnd.
            self.ecn_backoff = self.ecn_backoff.saturating_add(1).min(8);
            self.last_ecn = Some(now);
        }
        Ok(())
    }

    pub(crate) fn clean_ecn_ack(&mut self, now: Instant, rtt: Duration) {
        if self.ecn_backoff != 0 && self.last_ecn.is_some_and(|at| now.saturating_duration_since(at) >= rtt.max(Duration::from_millis(1))) {
            self.ecn_backoff -= 1;
            self.last_ecn = Some(now);
        }
    }

    pub(crate) fn pacing_interval(&self, bytes: u64, rtt: Duration) -> Duration {
        let factor = f64::from(1u32 << self.ecn_backoff);
        rtt.mul_f64(factor * bytes as f64 / self.cwnd as f64)
            .max(Duration::from_micros(1))
    }

    /// Called only for newly acknowledged in-flight bytes. Avoid growth
    /// on app-limited ACKs or packets sent before a congestion event.
    /// The future production scheduler must track cwnd-limited periods
    /// more precisely across all packet-number spaces.
    pub fn on_ack(
        &mut self,
        sent: Instant,
        now: Instant,
        bytes: u64,
        rtt: Duration,
        cwnd_limited: bool,
    ) -> Result<(), Error> {
        if sent > now || bytes == 0 || bytes > self.mtu.max(super::mtu::MAX_UDP_PAYLOAD as u64) {
            return Err(Error::Accounting);
        }
        if self.recovery.is_some_and(|start| sent <= start) {
            return Ok(());
        }
        if !cwnd_limited {
            self.application_limited();
            return Ok(());
        }
        if self.cwnd < self.ssthresh {
            let growth = if self.slow.css_baseline.is_some() {
                self.growth_credit += bytes as f64 / 4.0;
                let whole = self.growth_credit.floor() as u64;
                self.growth_credit -= whole as f64;
                whole
            } else { bytes };
            self.cwnd = self
                .cwnd
                .saturating_add(growth)
                .min(self.ssthresh)
                .min(MAX_CWND);
            return Ok(());
        }
        let current = self.cwnd as f64 / self.mtu as f64;
        if self.epoch.is_none() {
            self.epoch = Some((now, current));
            self.friendly = current;
        }
        let (start, initial) = self.epoch.ok_or(Error::Accounting)?;
        let elapsed = now.checked_duration_since(start).ok_or(Error::Accounting)?;
        let rtt = rtt.max(Duration::from_micros(1));
        let w_max = self.last_max.max(initial);
        let cubic =
            cubic_target(w_max, initial, elapsed.saturating_add(rtt)).ok_or(Error::Accounting)?;
        // TCP-friendly growth is driven by newly acknowledged bytes, not
        // merely wall time (an ACK after an idle period must not grant a burst).
        // RFC 9438 section 4.3: use the Reno increment after W_est reaches
        // the pre-congestion window. The denominator is the current cwnd.
        let alpha = if self.friendly >= self.prior_cwnd {
            1.0
        } else {
            3.0 * (1.0 - BETA) / (1.0 + BETA)
        };
        self.friendly += alpha * (bytes as f64 / self.mtu as f64) / current.max(1.0);
        let cubic_now = cubic_target(w_max, initial, elapsed).ok_or(Error::Accounting)?;
        // Reno-friendly growth updates the estimate directly rather than
        // integrating the difference a second time. Otherwise grow toward
        // the next-RTT cubic target, bounded by the slow-start rate.
        let increase = if cubic_now < self.friendly {
            ((self.friendly - current).max(0.0) * self.mtu as f64).min(bytes as f64)
        } else {
            let target = cubic.clamp(current, current * 1.5);
            ((target - current) / current) * bytes as f64
        };
        self.growth_credit += increase;
        let whole = self.growth_credit.floor() as u64;
        self.growth_credit -= whole as f64;
        self.cwnd = self.cwnd.saturating_add(whole).min(MAX_CWND);
        Ok(())
    }

    /// The future scheduler chooses a validated controller's target.
    /// This window only bounds the size and preserves in-flight accounting.
    pub fn set_target(&mut self, bytes: u64) -> Result<(), Error> {
        if bytes < 2 * self.mtu || bytes > MAX_CWND {
            return Err(Error::Limit);
        }
        self.cwnd = bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_delay_increase_enters_css_then_avoidance() {
        let mut w = Window::new(1200).unwrap();
        let base = Duration::from_millis(40);
        let elevated = Duration::from_millis(50);
        for round in 0..7u64 {
            for n in 0..8 {
                w.rtt_sample(round * 8 + n, round * 8 + 7, if round == 0 { base } else { elevated });
            }
        }
        assert_eq!(w.ssthresh, w.cwnd());
        let mut s = SlowStart::default();
        for n in 0..8 { assert!(!s.sample(n, 7, base)); }
        for n in 8..16 { assert!(!s.sample(n, 15, elevated)); }
        assert!(s.css_baseline.is_some());
        for n in 16..24 { assert!(!s.sample(n, 23, base)); }
        assert!(!s.sample(24, 31, base));
        assert!(s.css_baseline.is_none());
    }

    #[test]
    fn minimum_window_ecn_reduces_pacing_without_losing_accounting() {
        let now = Instant::now();
        let rtt = Duration::from_millis(50);
        let mut w = Window::new(1200).unwrap();
        w.persistent_congestion(now);
        let original = w.pacing_interval(1200, rtt);
        w.ecn(now + rtt, now + rtt * 2).unwrap();
        assert_eq!(w.cwnd(), 2400);
        assert!(w.pacing_interval(1200, rtt) > original);
        let rate = w.pacing_interval(1200, rtt);
        w.ecn(now + rtt, now + rtt * 2).unwrap();
        assert_eq!(w.pacing_interval(1200, rtt), rate);
        w.clean_ecn_ack(now + rtt * 3, rtt);
        assert_eq!(w.pacing_interval(1200, rtt), original);
    }

    #[test]
    fn cubic_curve_and_window_recovery() {
        assert!((cubic_target(100.0, 70.0, Duration::ZERO).unwrap() - 70.0).abs() < 0.000001);
        assert!(cubic_target(100.0, 70.0, Duration::from_secs(10)).unwrap() > 100.0);
        assert!(cubic_target(f64::NAN, 70.0, Duration::ZERO).is_none());
        let mut w = Window::new(1200).unwrap();
        assert_eq!(w.cwnd(), 12000);
        for _ in 0..10 {
            w.reserve(1200).unwrap();
        }
        assert_eq!(w.reserve(1), Err(Error::Limit));
        let now = Instant::now();
        assert!(w.loss(now, now).unwrap());
        assert_eq!(w.cwnd(), 8400);
        assert!(!w.loss(now, now).unwrap());
        assert_eq!(w.in_flight(), 12000);
        w.retire(4800).unwrap();
        w.reserve(1200).unwrap();
        assert_eq!(w.in_flight(), 8400);
        assert_eq!(w.retire(8401), Err(Error::Accounting));
        assert_eq!(w.set_target(1), Err(Error::Limit));
        w.set_target(12000).unwrap();
        assert_eq!(w.cwnd(), 12000);
    }
    #[test]
    fn reno_friendly_growth_is_ack_driven_and_idle_rebases_epoch() {
        let now = Instant::now();
        let rtt = Duration::from_millis(10);
        let mut w = Window::new(1200).unwrap();
        w.loss(now, now).unwrap();
        let initial = w.cwnd();
        let sent = now + rtt;
        w.on_ack(sent, sent + rtt, 1200, rtt, true).unwrap();
        assert!(w.cwnd() > initial);
        let after = w.cwnd();
        w.application_limited();
        w.on_ack(sent, sent + Duration::from_secs(60), 1200, rtt, true)
            .unwrap();
        assert!(w.cwnd() <= after + 1200);
    }

    #[test]
    fn slow_start_then_cubic_growth_ignores_app_limited_and_old_packets() {
        let start = Instant::now();
        let rtt = Duration::from_millis(100);
        let mut w = Window::new(1200).unwrap();
        w.on_ack(start, start + rtt, 1200, rtt, false).unwrap();
        assert_eq!(w.cwnd(), 12000);
        w.on_ack(start, start + rtt, 1200, rtt, true).unwrap();
        assert_eq!(w.cwnd(), 13200);
        let lost = start + rtt;
        w.loss(start, lost).unwrap();
        let reduced = w.cwnd();
        assert_eq!(reduced, 9240);
        w.on_ack(start, lost + rtt, 1200, rtt, true).unwrap();
        assert_eq!(w.cwnd(), reduced);
        let later = lost + Duration::from_millis(1);
        for n in 1..=20 {
            let at = later + rtt * n;
            w.on_ack(later, at, 1200, rtt, true).unwrap();
        }
        assert!(w.cwnd() > reduced);
        assert!(w.cwnd() <= MAX_CWND);
    }
}
