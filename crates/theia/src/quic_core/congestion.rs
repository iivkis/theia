//! Congestion-control building blocks for the future connection scheduler.
//! CUBIC target and conservative congestion-window bookkeeping, not a
//! complete RFC 9438 controller. BBR needs a delivery-rate sampler, pacing
//! and a validated state machine; it is not implemented here.
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { Limit, Accounting }

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
}

impl Window {
    pub fn new(mtu: u64) -> Result<Self, Error> {
        if !(1200..=65527).contains(&mtu) { return Err(Error::Limit); }
        let cwnd = (10 * mtu).min((2 * mtu).max(14720));
        Ok(Self { mtu, cwnd, in_flight: 0, recovery: None })
    }

    pub fn cwnd(&self) -> u64 { self.cwnd }
    pub fn in_flight(&self) -> u64 { self.in_flight }

    /// Ordinary in-flight packets only. RFC PTO probes require a separate
    /// bounded exception and anti-amplification check, not this method.
    pub fn reserve(&mut self, bytes: u64) -> Result<(), Error> {
        let next = self.in_flight.checked_add(bytes).ok_or(Error::Limit)?;
        if bytes == 0 || bytes > self.mtu || next > self.cwnd { return Err(Error::Limit); }
        self.in_flight = next;
        Ok(())
    }

    pub fn retire(&mut self, bytes: u64) -> Result<(), Error> {
        self.in_flight = self.in_flight.checked_sub(bytes).ok_or(Error::Accounting)?;
        Ok(())
    }

    /// Apply a single congestion event for packets sent before the same
    /// recovery boundary. Uses CUBIC's beta=0.7, not a full controller.
    pub fn loss(&mut self, sent: Instant, now: Instant) -> Result<bool, Error> {
        if sent > now { return Err(Error::Accounting); }
        if self.recovery.is_some_and(|start| sent <= start) { return Ok(false); }
        self.recovery = Some(now);
        self.cwnd = (self.cwnd.saturating_mul(7) / 10).max(2 * self.mtu);
        Ok(true)
    }

    /// The future scheduler chooses a validated controller's target.
    /// This window only bounds the size and preserves in-flight accounting.
    pub fn set_target(&mut self, bytes: u64) -> Result<(), Error> {
        if bytes < 2 * self.mtu || bytes > 64 * 1024 * 1024 { return Err(Error::Limit); }
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
        for _ in 0..10 { w.reserve(1200).unwrap(); }
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
}
