//! Bounded packetization-layer MTU discovery for authenticated QUIC paths.
//! The base 1200-byte packet size is always usable for retransmission.
use super::loss::{FrameRef, Outcome};
use std::time::{Duration, Instant};

pub const BASE: usize = 1200;
pub const MAX_UDP_PAYLOAD: usize = 1452;
const INTERVAL: Duration = Duration::from_secs(1);
const STEP: usize = 16;

pub(crate) struct Discovery {
    peer_cap: usize,
    current: usize,
    upper: usize,
    next: Option<Instant>,
    pending: Option<(u64, usize)>,
    failed: Option<usize>,
    large_losses: u8,
}

impl Default for Discovery {
    fn default() -> Self {
        Self { peer_cap: BASE, current: BASE, upper: BASE, next: None, pending: None, failed: None, large_losses: 0 }
    }
}

impl Discovery {
    pub(crate) fn new(peer_cap: u64, now: Instant) -> Self {
        let cap = peer_cap.clamp(BASE as u64, MAX_UDP_PAYLOAD as u64) as usize;
        Self { peer_cap: cap, upper: cap, next: now.checked_add(INTERVAL), ..Self::default() }
    }

    pub(crate) fn current(&self) -> usize { self.current }

    pub(crate) fn candidate(&self) -> Option<usize> {
        if self.pending.is_some() || self.upper.saturating_sub(self.current) < STEP { return None; }
        Some(self.failed.unwrap_or_else(|| self.current + (self.upper - self.current).div_ceil(2)))
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.candidate()?;
        self.next
    }

    pub(crate) fn sent(&mut self, number: u64, size: usize) {
        self.pending = Some((number, size));
        self.next = None;
    }

    pub(crate) fn reset_path(&mut self, now: Instant) {
        *self = Self::new(self.peer_cap as u64, now);
    }

    /// The kernel rejected this datagram before transmission. The caller
    /// burns its packet number; reliable frames remain queued at base size.
    pub(crate) fn local_reject(&mut self, size: usize, now: Instant) {
        self.upper = self.upper.min(size.saturating_sub(1)).max(BASE);
        if self.current > self.upper { self.current = BASE; }
        self.pending = None;
        self.failed = None;
        self.large_losses = 0;
        self.next = now.checked_add(INTERVAL);
    }

    pub(crate) fn feedback(&mut self, outcome: &Outcome, now: Instant) {
        if let Some((number, size)) = self.pending {
            if outcome.acknowledged.iter().any(|p| p.number == number) {
                self.current = size;
                self.failed = None;
                self.pending = None;
                self.next = now.checked_add(INTERVAL);
            } else if outcome.lost.iter().any(|p| p.number == number) {
                self.pending = None;
                if self.failed == Some(size) {
                    self.upper = self.upper.min(size - 1);
                    self.failed = None;
                } else {
                    self.failed = Some(size);
                }
                self.next = now.checked_add(INTERVAL);
            }
        }
        // Loss of probe-only packets is not congestion. Detect a possible
        // black hole only with actual larger data loss and a surviving base
        // packet; retransmit the original small frame descriptors.
        if self.current > BASE {
            for packet in &outcome.lost {
                if packet.bytes as usize > BASE && !packet.frames.contains(&FrameRef::MtuProbe) {
                    self.large_losses = self.large_losses.saturating_add(1);
                }
            }
            if outcome.acknowledged.iter().any(|p| p.bytes as usize > BASE) {
                self.large_losses = 0;
            } else if self.large_losses >= 3 && outcome.acknowledged.iter().any(|p| p.bytes as usize <= BASE) {
                let old = self.current;
                self.local_reject(old, now);
            }
        }
    }
}

pub(crate) fn message_too_large(error: &std::io::Error) -> bool {
    #[cfg(target_os = "linux")]
    { error.raw_os_error() == Some(libc::EMSGSIZE) }
    #[cfg(target_os = "windows")]
    { error.raw_os_error() == Some(10040) }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    { let _ = error; false }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_core::loss::Sent;
    fn packet(number: u64, size: usize, now: Instant, probe: bool) -> Sent {
        Sent { number, at: now, bytes: size as u32, ack_eliciting: true, in_flight: true,
            frames: if probe { vec![FrameRef::MtuProbe] } else { vec![FrameRef::Control(number)] } }
    }

    #[test]
    fn only_authenticated_probe_ack_raises_mtu_and_loss_bounds_search() {
        let now = Instant::now();
        let mut d = Discovery::new(65527, now);
        let size = d.candidate().unwrap();
        assert_eq!(size, 1326);
        d.sent(1, size);
        d.feedback(&Outcome { acknowledged: vec![packet(2, BASE, now, false)], ..Outcome::default() }, now);
        assert_eq!(d.current(), BASE);
        d.feedback(&Outcome { acknowledged: vec![packet(1, size, now, true)], ..Outcome::default() }, now);
        assert_eq!(d.current(), size);
        let next = d.candidate().unwrap();
        for n in [3, 4] {
            d.sent(n, next);
            d.feedback(&Outcome { lost: vec![packet(n, next, now, true)], ..Outcome::default() }, now);
        }
        assert!(d.candidate().unwrap() < next);
        d.local_reject(size, now);
        assert_eq!(d.current(), BASE);
        d.reset_path(now);
        assert_eq!(d.candidate(), Some(size));
        assert!(Discovery::new(BASE as u64, now).candidate().is_none());
    }

    #[test]
    fn larger_data_blackhole_falls_back_to_base() {
        let now = Instant::now();
        let mut d = Discovery::new(1452, now);
        let size = d.candidate().unwrap();
        d.sent(1, size);
        d.feedback(&Outcome { acknowledged: vec![packet(1, size, now, true)], ..Outcome::default() }, now);
        d.feedback(&Outcome { lost: (2..5).map(|n| packet(n, size, now, false)).collect(), acknowledged: vec![packet(5, BASE, now, false)], ..Outcome::default() }, now);
        assert_eq!(d.current(), BASE);
    }
}
