//! Development application-space scheduler. Stable frame IDs allow late
//! ACKs of a lost transmission to cancel queued retransmissions. No
//! handshake-space timers, multipath, key updates or production admission.
use super::{ack::Ack, bbr::Bbr, congestion::Window, loss::{self, FrameRef, Ledger, Sent}, recovery::Rtt};
use std::{collections::{BTreeMap, VecDeque}, time::{Duration, Instant}};

const MAX_FRAMES: usize = 128;
const MAX_ALIASES: usize = 4096;
const MAX_PTO: u32 = 8;
const MTU: u64 = 1200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { Limit, Ledger, Window, Timeout }

struct Pending {
    bytes: Vec<u8>,
    queued: bool,
}

pub struct Scheduler {
    ledger: Ledger,
    window: Window,
    bbr: Option<Bbr>,
    rtt: Rtt,
    frames: BTreeMap<u64, Pending>,
    queue: VecDeque<u64>,
    aliases: BTreeMap<u64, u64>,
    next_id: u64,
    last_eliciting: Option<Instant>,
    pto_count: u32,
    next_send: Option<Instant>,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self {
            ledger: Ledger::default(), window: Window::new(MTU).expect("valid MTU"), bbr: None,
            rtt: Rtt::default(), frames: BTreeMap::new(), queue: VecDeque::new(),
            aliases: BTreeMap::new(), next_id: 0, last_eliciting: None,
            pto_count: 0, next_send: None,
        }
    }
}

impl Scheduler {
    pub fn with_bbr(now: Instant) -> Self {
        Self { bbr: Some(Bbr::new(MTU, now).expect("valid MTU")), ..Self::default() }
    }

    pub fn can_queue(&self) -> bool { self.can_queue_n(1) }

    pub fn can_queue_n(&self, n: usize) -> bool {
        n <= MAX_FRAMES.saturating_sub(self.frames.len()) && (n as u64) <= u64::MAX - self.next_id
    }

    pub fn enqueue(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        if !self.can_queue() || bytes.is_empty() || bytes.len() > 1100 { return Err(Error::Limit); }
        let id = self.next_id;
        self.next_id += 1;
        self.frames.insert(id, Pending { bytes, queued: true });
        self.queue.push_back(id);
        Ok(())
    }

    pub fn pending(&self) -> usize { self.frames.len() }

    /// Cancel only STREAM data for the reset direction. Keep sent-packet
    /// accounting until ACK/loss so bytes-in-flight never disappear early.
    pub fn cancel_stream(&mut self, stream: u64) {
        use super::{frames::{decode, Frame}, spaces::Space};
        self.frames.retain(|_, pending| {
            !matches!(decode(&pending.bytes, Space::Application).as_deref(),
                Ok([Frame::Stream { id, .. }]) if *id == stream)
        });
        self.aliases.retain(|_, id| self.frames.contains_key(id));
        self.queue.retain(|id| self.frames.contains_key(id));
        if self.frames.is_empty() { self.last_eliciting = None; }
    }

    /// One frame per packet. PTO may send a single probe over the current
    /// congestion window; ordinary sends remain paced and window-limited.
    pub fn candidate(&mut self, now: Instant) -> Result<Option<(u64, Vec<u8>, bool)>, Error> {
        self.queue.retain(|id| self.frames.contains_key(id));
        let probe_due = !self.frames.is_empty() && self.pto_deadline().is_some_and(|at| now >= at);
        if probe_due {
            if self.pto_count >= MAX_PTO { return Err(Error::Timeout); }
            if self.aliases.len() >= MAX_ALIASES { return Err(Error::Limit); }
            if let Some((&id, f)) = self.frames.first_key_value() {
                return Ok(Some((id, f.bytes.clone(), true)));
            }
        }
        if self.next_send.is_some_and(|at| now < at)
            || self.window.in_flight().saturating_add(MTU) > self.window.cwnd() { return Ok(None); }
        if self.aliases.len() >= MAX_ALIASES { return Err(Error::Limit); }
        Ok(self.queue.front().and_then(|id| self.frames.get(id).map(|f| (*id, f.bytes.clone(), false))))
    }

    /// Called once after successful packet sealing. If the I/O attempt fails,
    /// the owner must terminate rather than reuse packet numbers.
    pub fn record(&mut self, number: u64, bytes: usize, frame: Option<(u64, bool)>, now: Instant) -> Result<(), Error> {
        if bytes == 0 || bytes > MTU as usize { return Err(Error::Limit); }
        if let Some((id, probe)) = frame {
            if !self.frames.contains_key(&id) || self.aliases.len() >= MAX_ALIASES { return Err(Error::Limit); }
            let before = self.window.in_flight();
            let app_limited = probe || (self.queue.iter().all(|queued| *queued == id)
                && before.saturating_add(2 * MTU) <= self.window.cwnd());
            if probe {
                self.window.reserve_probe(bytes as u64).map_err(|_| Error::Window)?;
            } else {
                self.window.reserve(bytes as u64).map_err(|_| Error::Window)?;
            }
            if let Err(_e) = self.ledger.record(Sent { number, at: now, bytes: bytes as u32, ack_eliciting: true,
                in_flight: true, frames: vec![FrameRef::Control(id)] }) {
                self.window.retire(bytes as u64).map_err(|_| Error::Window)?;
                return Err(Error::Ledger);
            }
            if let Some(bbr) = self.bbr.as_mut() {
                bbr.sent(number, bytes as u64, now, before, app_limited).map_err(|_| Error::Window)?;
            }
            self.aliases.insert(number, id);
            self.queue.retain(|queued| *queued != id);
            if let Some(f) = self.frames.get_mut(&id) { f.queued = false; }
            if probe { self.pto_count += 1; }
            self.last_eliciting = Some(now);
            let spacing = if let Some(bbr) = &self.bbr {
                bbr.pacing_interval(bytes as u64)
            } else {
                self.rtt.smoothed().mul_f64(bytes as f64 / self.window.cwnd() as f64)
                    .max(Duration::from_micros(1))
            };
            self.next_send = now.checked_add(spacing);
        } else {
            self.ledger.record(Sent { number, at: now, bytes: bytes as u32,
                ack_eliciting: false, in_flight: false, frames: vec![] }).map_err(|_| Error::Ledger)?;
        }
        Ok(())
    }

    pub fn acknowledge(&mut self, ack: &Ack, now: Instant) -> Result<(), Error> {
        let outcome = self.ledger.acknowledge(ack, now, self.rtt.loss_delay()).map_err(|_| Error::Ledger)?;
        // Retain aliases for declared-lost packets until any copy is ACKed.
        let completed: Vec<u64> = self.aliases.iter().filter_map(|(n, id)| ack.acknowledges(*n).then_some(*id)).collect();
        for id in completed {
            self.frames.remove(&id);
            self.aliases.retain(|_, value| *value != id);
        }
        self.queue.retain(|id| self.frames.contains_key(id));
        if self.frames.is_empty() { self.last_eliciting = None; }
        if outcome.acknowledged.iter().any(|p| p.ack_eliciting) {
            self.pto_count = 0;
        }
        if let Some(sample) = outcome.rtt_sample { self.rtt.update(sample, Duration::ZERO, Duration::ZERO, true); }
        self.apply_loss(outcome, now)
    }

    fn apply_loss(&mut self, outcome: loss::Outcome, now: Instant) -> Result<(), Error> {
        let limited = self.window.in_flight().saturating_add(MTU) > self.window.cwnd();
        self.window.retire(outcome.acknowledged_bytes + outcome.lost_bytes).map_err(|_| Error::Window)?;
        // BBR uses the same authoritative in-flight ledger, but does not
        // apply CUBIC's multiplicative decrease/growth to its model.
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.feedback(&outcome, now, self.window.in_flight()).map_err(|_| Error::Window)?;
            self.window.set_target(bbr.cwnd()).map_err(|_| Error::Window)?;
        } else if persistent_loss(&outcome, self.base_pto().saturating_mul(3)) {
            self.window.persistent_congestion(now);
        }
        // Apply loss before growth, so an ACK for a packet sent before
        // the new recovery boundary cannot undo the congestion event.
        for p in outcome.lost {
            if p.in_flight && self.bbr.is_none() { self.window.loss(p.at, now).map_err(|_| Error::Window)?; }
            for f in p.frames {
                if let FrameRef::Control(id) = f {
                    if let Some(pending) = self.frames.get_mut(&id) {
                        if !pending.queued {
                            pending.queued = true;
                            self.queue.push_back(id);
                        }
                    }
                }
            }
        }
        for p in outcome.acknowledged {
            if p.in_flight && self.bbr.is_none() {
                self.window.on_ack(p.at, now, u64::from(p.bytes), self.rtt.smoothed(), limited)
                    .map_err(|_| Error::Window)?;
            }
        }
        Ok(())
    }

    pub fn on_timer(&mut self, now: Instant) -> Result<(), Error> {
        let result = self.ledger.on_loss_timer(now, self.rtt.loss_delay()).map_err(|_| Error::Ledger)?;
        self.apply_loss(result, now)
    }

    pub fn base_pto(&self) -> Duration { self.rtt.pto(Duration::ZERO, 0) }

    fn pto_deadline(&self) -> Option<Instant> {
        if self.frames.is_empty() { return None; }
        self.last_eliciting?.checked_add(self.rtt.pto(Duration::ZERO, self.pto_count))
    }

    pub fn deadline(&self) -> Option<Instant> {
        let loss = self.ledger.loss_deadline(self.rtt.loss_delay());
        let pto = self.pto_deadline();
        let pace = if !self.queue.is_empty() && self.window.in_flight().saturating_add(MTU) <= self.window.cwnd() {
            self.next_send
        } else { None };
        [loss, pto, pace].into_iter().flatten().min()
    }
}

/// Conservative persistent-congestion evidence: only one contiguous run
/// of lost ACK-eliciting packets in the same authenticated loss outcome.
/// Cross-event tracking remains a production recovery requirement.
fn persistent_loss(outcome: &loss::Outcome, threshold: Duration) -> bool {
    let mut start: Option<Instant> = None;
    let mut last: Option<u64> = None;
    for packet in &outcome.lost {
        if !packet.in_flight || !packet.ack_eliciting {
            start = None;
            last = None;
            continue;
        }
        if last.and_then(|n| n.checked_add(1)) != Some(packet.number) { start = Some(packet.at); }
        last = Some(packet.number);
        if start.is_some_and(|at| packet.at.saturating_duration_since(at) >= threshold) { return true; }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_core::ack::Range;

    fn ack(n: u64) -> Ack { Ack { delay: 0, ranges: vec![Range { first: n, last: n }], ecn: None } }

    #[test]
    fn pto_retransmission_and_late_ack_cancel() {
        let now = Instant::now();
        let mut s = Scheduler::default();
        s.enqueue(vec![1]).unwrap();
        let (id, data, probe) = s.candidate(now).unwrap().unwrap();
        assert_eq!(data, [1]);
        assert!(!probe);
        s.record(0, 100, Some((id, false)), now).unwrap();
        assert!(s.candidate(now).unwrap().is_none());
        let later = now + Duration::from_secs(1);
        let (again, data, probe) = s.candidate(later).unwrap().unwrap();
        assert_eq!(again, id);
        assert_eq!(data, [1]);
        assert!(probe);
        s.record(1, 100, Some((id, true)), later).unwrap();
        s.acknowledge(&ack(0), later).unwrap();
        assert_eq!(s.pending(), 0);
        assert!(s.candidate(later).unwrap().is_none());
        s.acknowledge(&ack(1), later).unwrap();
        assert_eq!(s.window.in_flight(), 0);
    }

    #[test]
    fn ack_only_packets_do_not_consume_loss_queue() {
        let now = Instant::now();
        let mut s = Scheduler::default();
        for number in 0..5000 { s.record(number, 30, None, now).unwrap(); }
        assert_eq!(s.window.in_flight(), 0);
        assert_eq!(s.acknowledge(&ack(5000), now), Err(Error::Ledger));
    }
    #[test]
    fn bbr_scheduler_uses_same_packet_ledger_and_releases_credit() {
        let now = Instant::now();
        let mut s = Scheduler::with_bbr(now);
        s.enqueue(vec![1]).unwrap();
        let (id, _, probe) = s.candidate(now).unwrap().unwrap();
        s.record(0, 100, Some((id, probe)), now).unwrap();
        assert_eq!(s.window.in_flight(), 100);
        s.acknowledge(&ack(0), now + Duration::from_millis(20)).unwrap();
        assert_eq!(s.window.in_flight(), 0);
        assert_eq!(s.pending(), 0);
        assert_eq!(s.bbr.as_ref().unwrap().bandwidth(), 5000);
    }

    #[test]
    fn cancel_does_not_remove_in_flight_accounting() {
        let now = Instant::now();
        let mut s = Scheduler::default();
        s.enqueue(vec![0x0a, 2, 1, 42]).unwrap();
        s.enqueue(vec![0x0a, 6, 1, 42]).unwrap();
        let (id, _, _) = s.candidate(now).unwrap().unwrap();
        s.record(0, 100, Some((id, false)), now).unwrap();
        s.cancel_stream(2);
        assert_eq!(s.pending(), 1);
        assert_eq!(s.window.in_flight(), 100);
        s.acknowledge(&ack(0), now).unwrap();
        assert_eq!(s.window.in_flight(), 0);
        assert_eq!(s.pending(), 1);
    }

}
