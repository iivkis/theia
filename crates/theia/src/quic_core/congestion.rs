//! Congestion-control building blocks for the future connection scheduler.
//! CUBIC window growth, slow start and recovery for the isolated session.
//! This remains a development controller: ECN, HyStart++, complete
//! persistent-congestion evidence and full idle handling remain open.
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

pub struct Window {
    mtu: u64,
    cwnd: u64,
    in_flight: u64,
    recovery: Option<Instant>,
    ssthresh: u64,
    last_max: f64,
    epoch: Option<(Instant, f64)>,
    growth_credit: f64,
    friendly: f64,
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
            epoch: None,
            growth_credit: 0.0,
            friendly: 0.0,
        })
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

    /// Apply a single congestion event for packets sent before the same
    /// recovery boundary. Uses CUBIC's beta=0.7, not a full controller.
    pub fn loss(&mut self, sent: Instant, now: Instant) -> Result<bool, Error> {
        if sent > now {
            return Err(Error::Accounting);
        }
        if self.recovery.is_some_and(|start| sent <= start) {
            return Ok(false);
        }
        self.recovery = Some(now);
        let packets = self.cwnd as f64 / self.mtu as f64;
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
        Ok(true)
    }

    /// Collapse the window on verified persistent congestion. Preserve
    /// accounting for packets that have not yet been acknowledged/lost.
    pub fn persistent_congestion(&mut self, now: Instant) {
        self.recovery = Some(now);
        self.last_max = self.cwnd as f64 / self.mtu as f64;
        self.cwnd = 2 * self.mtu;
        self.ssthresh = self.cwnd;
        self.epoch = None;
        self.growth_credit = 0.0;
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
        if sent > now || bytes == 0 || bytes > self.mtu {
            return Err(Error::Accounting);
        }
        if !cwnd_limited {
            self.epoch = None;
            self.growth_credit = 0.0;
            return Ok(());
        }
        if self.recovery.is_some_and(|start| sent <= start) {
            return Ok(());
        }
        if self.cwnd < self.ssthresh {
            self.cwnd = self
                .cwnd
                .saturating_add(bytes)
                .min(self.ssthresh)
                .min(MAX_CWND);
            return Ok(());
        }
        let current = self.cwnd as f64 / self.mtu as f64;
        if self.epoch.is_none() { self.epoch = Some((now, current)); self.friendly = current; }
        let (start, initial) = self.epoch.ok_or(Error::Accounting)?;
        let elapsed = now.checked_duration_since(start).ok_or(Error::Accounting)?;
        let rtt = rtt.max(Duration::from_micros(1));
        let w_max = self.last_max.max(initial);
        let cubic =
            cubic_target(w_max, initial, elapsed.saturating_add(rtt)).ok_or(Error::Accounting)?;
        // TCP-friendly growth is driven by newly acknowledged bytes, not
        // merely wall time (an ACK after an idle period must not grant a burst).
        self.friendly += (3.0 * (1.0 - BETA) / (1.0 + BETA)) * (bytes as f64 / self.mtu as f64) / self.friendly.max(1.0);
        let friendly = self.friendly;
        // Limit ACK-driven growth to a bounded target; use fractional byte
        // credit rather than rounding every small ACK up to a whole MTU.
        let target = cubic.max(friendly).min(current * 1.5);
        let increase = ((target - current).max(0.0) / current) * bytes as f64;
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
