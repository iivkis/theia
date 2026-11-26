//! Development application-space scheduler. Stable frame IDs allow late
//! ACKs of a lost transmission to cancel queued retransmissions. No
//! handshake-space timers, multipath, key updates or production admission.
use super::{
    ack::Ack,
    bbr::Bbr,
    congestion::Window,
    loss::{self, FrameRef, Ledger, Sent},
    recovery::Rtt,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::{Duration, Instant},
};

const MAX_FRAMES: usize = 128;
const MAX_ALIASES: usize = 4096;
const MAX_PTO: u32 = 8;
const MTU: u64 = 1200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    Ledger,
    Window,
    Timeout,
}

struct Pending {
    bytes: Vec<u8>,
    queued: bool,
}

pub struct Scheduler {
    ledger: Ledger,
    window: Window,
    bbr: Option<Bbr>,
    rtt: Rtt,
    ack_delay_exponent: u32,
    max_ack_delay: Duration,
    confirmed: bool,
    frames: BTreeMap<u64, Pending>,
    queue: VecDeque<u64>,
    aliases: BTreeMap<u64, u64>,
    next_id: u64,
    last_eliciting: Option<Instant>,
    pto_count: u32,
    next_send: Option<Instant>,
    cwnd_limited: BTreeSet<u64>,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self {
            ledger: Ledger::default(),
            window: Window::new(MTU).expect("valid MTU"),
            bbr: None,
            rtt: Rtt::default(),
            ack_delay_exponent: 0,
            max_ack_delay: Duration::ZERO,
            confirmed: false,
            frames: BTreeMap::new(),
            queue: VecDeque::new(),
            aliases: BTreeMap::new(),
            next_id: 0,
            last_eliciting: None,
            pto_count: 0,
            next_send: None,
            cwnd_limited: BTreeSet::new(),
        }
    }
}

impl Scheduler {
    pub(crate) fn after_retry(next: u64) -> Self {
        Self {
            ledger: Ledger::with_next(next),
            ..Self::default()
        }
    }

    pub fn with_bbr(now: Instant) -> Self {
        Self {
            bbr: Some(Bbr::new(MTU, now).expect("valid MTU")),
            ..Self::default()
        }
    }

    /// Cross-IP migration resets RTT, congestion and pacing. Reliable
    /// frames are queued again; retained aliases still recognize a late
    /// ACK from the old path without adding old-path RTT or delivery samples.
    pub(crate) fn restart_path(&mut self, now: Instant) {
        self.ledger.restart_path();
        self.window = Window::new(MTU).expect("valid MTU");
        if self.bbr.is_some() {
            self.bbr = Some(Bbr::new(MTU, now).expect("valid MTU"));
        }
        self.rtt = Rtt::default();
        self.queue.clear();
        for (&id, frame) in &mut self.frames {
            frame.queued = true;
            self.queue.push_back(id);
        }
        self.cwnd_limited.clear();
        self.last_eliciting = None;
        self.pto_count = 0;
        self.next_send = None;
    }

    pub fn can_queue(&self) -> bool {
        self.can_queue_n(1)
    }

    pub fn can_queue_n(&self, n: usize) -> bool {
        n <= MAX_FRAMES.saturating_sub(self.frames.len()) && (n as u64) <= u64::MAX - self.next_id
    }

    pub fn enqueue(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        if !self.can_queue() || bytes.is_empty() || bytes.len() > 1100 {
            return Err(Error::Limit);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.frames.insert(
            id,
            Pending {
                bytes,
                queued: true,
            },
        );
        self.queue.push_back(id);
        Ok(())
    }

    pub(crate) fn stream_pending(&self, stream: u64) -> bool {
        use super::{
            frames::{decode, Frame},
            spaces::Space,
        };
        self.frames.values().any(|pending| {
            matches!(decode(&pending.bytes, Space::Application).as_deref(),
            Ok([Frame::Stream { id, .. } | Frame::ResetStream { id, .. }]) if *id == stream)
        })
    }

    pub(crate) fn has_queued(&self) -> bool {
        self.frames.values().any(|frame| frame.queued)
    }

    pub fn pending(&self) -> usize {
        self.frames.len()
    }

    /// Cancel only STREAM data for the reset direction. Keep sent-packet
    /// accounting until ACK/loss so bytes-in-flight never disappear early.
    pub fn cancel_stream(&mut self, stream: u64) {
        use super::{
            frames::{decode, Frame},
            spaces::Space,
        };
        self.frames.retain(|_, pending| {
            !matches!(decode(&pending.bytes, Space::Application).as_deref(),
                Ok([Frame::Stream { id, .. }]) if *id == stream)
        });
        self.aliases.retain(|_, id| self.frames.contains_key(id));
        self.queue.retain(|id| self.frames.contains_key(id));
        if self.frames.is_empty() && self.ledger.bytes_in_flight() == 0 {
            self.last_eliciting = None;
        }
    }

    /// One frame per packet. PTO may send a single probe over the current
    /// congestion window; ordinary sends remain paced and window-limited.
    pub fn candidate(&mut self, now: Instant) -> Result<Option<(u64, Vec<u8>, bool)>, Error> {
        self.queue.retain(|id| self.frames.contains_key(id));
        let probe_due = self.pto_deadline().is_some_and(|at| now >= at);
        if probe_due {
            if self.pto_count >= MAX_PTO {
                return Err(Error::Timeout);
            }
            if self.aliases.len() >= MAX_ALIASES {
                return Err(Error::Limit);
            }
            // A PATH probe or canceled STREAM can leave flight bytes but
            // no retransmittable frame. PTO still needs an eliciting probe.
            if self.frames.is_empty() {
                self.enqueue(vec![1])?;
            }
            if let Some((&id, f)) = self.frames.first_key_value() {
                return Ok(Some((id, f.bytes.clone(), true)));
            }
        }
        if self.next_send.is_some_and(|at| now < at)
            || self.window.in_flight().saturating_add(MTU) > self.window.cwnd()
        {
            return Ok(None);
        }
        if self.aliases.len() >= MAX_ALIASES {
            return Err(Error::Limit);
        }
        Ok(self
            .queue
            .front()
            .and_then(|id| self.frames.get(id).map(|f| (*id, f.bytes.clone(), false))))
    }

    /// Called once after successful packet sealing. If the I/O attempt fails,
    /// the owner must terminate rather than reuse packet numbers.
    pub fn record(
        &mut self,
        number: u64,
        bytes: usize,
        frame: Option<(u64, bool)>,
        now: Instant,
    ) -> Result<(), Error> {
        if bytes == 0 || bytes > MTU as usize {
            return Err(Error::Limit);
        }
        if let Some((id, probe)) = frame {
            if !self.frames.contains_key(&id) || self.aliases.len() >= MAX_ALIASES {
                return Err(Error::Limit);
            }
            let before = self.window.in_flight();
            if before == 0 && self.bbr.is_none() {
                self.window.application_limited();
            }
            let app_limited = probe
                || (self.queue.iter().all(|queued| *queued == id)
                    && before.saturating_add(2 * MTU) <= self.window.cwnd());
            if probe {
                self.window
                    .reserve_probe(bytes as u64)
                    .map_err(|_| Error::Window)?;
            } else {
                self.window
                    .reserve(bytes as u64)
                    .map_err(|_| Error::Window)?;
            }
            if let Err(_e) = self.ledger.record(Sent {
                number,
                at: now,
                bytes: bytes as u32,
                ack_eliciting: true,
                in_flight: true,
                frames: vec![FrameRef::Control(id)],
            }) {
                self.window
                    .retire(bytes as u64)
                    .map_err(|_| Error::Window)?;
                return Err(Error::Ledger);
            }
            if let Some(bbr) = self.bbr.as_mut() {
                bbr.sent(number, bytes as u64, now, before, app_limited)
                    .map_err(|_| Error::Window)?;
            }
            if !app_limited && self.bbr.is_none() {
                self.cwnd_limited.insert(number);
            }
            self.aliases.insert(number, id);
            self.queue.retain(|queued| *queued != id);
            if let Some(f) = self.frames.get_mut(&id) {
                f.queued = false;
            }
            if probe {
                self.pto_count += 1;
            }
            self.last_eliciting = Some(now);
            let spacing = if let Some(bbr) = &self.bbr {
                bbr.pacing_interval(bytes as u64)
            } else {
                self.rtt
                    .smoothed()
                    .mul_f64(bytes as f64 / self.window.cwnd() as f64)
                    .max(Duration::from_micros(1))
            };
            self.next_send = now.checked_add(spacing);
        } else {
            self.ledger
                .record(Sent {
                    number,
                    at: now,
                    bytes: bytes as u32,
                    ack_eliciting: false,
                    in_flight: false,
                    frames: vec![],
                })
                .map_err(|_| Error::Ledger)?;
        }
        Ok(())
    }

    /// One path probe is charged to the normal flight window and ledger.
    /// No generic STREAM retransmission is created for PATH_* frames.
    /// The path owner decides whether and where a later probe may be sent.
    pub fn can_send_path(&self) -> bool {
        self.window.in_flight().saturating_add(MTU) <= self.window.cwnd()
    }

    pub fn record_path(&mut self, number: u64, bytes: usize, now: Instant) -> Result<(), Error> {
        if bytes != MTU as usize || !self.can_send_path() {
            return Err(Error::Window);
        }
        let before = self.window.in_flight();
        self.window
            .reserve(bytes as u64)
            .map_err(|_| Error::Window)?;
        if self
            .ledger
            .record(Sent {
                number,
                at: now,
                bytes: bytes as u32,
                ack_eliciting: true,
                in_flight: true,
                frames: vec![],
            })
            .is_err()
        {
            self.window
                .retire(bytes as u64)
                .map_err(|_| Error::Window)?;
            return Err(Error::Ledger);
        }
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.sent(number, bytes as u64, now, before, true)
                .map_err(|_| Error::Window)?;
        }
        self.last_eliciting = Some(now);
        Ok(())
    }

    /// Only application-space schedulers receive negotiated ACK timing.
    pub(crate) fn application_ack_timing(
        &mut self,
        exponent: u64,
        max_delay_ms: u64,
        confirmed: bool,
    ) {
        self.ack_delay_exponent = exponent.min(20) as u32;
        self.max_ack_delay = Duration::from_millis(max_delay_ms.min((1 << 14) - 1));
        self.confirmed = confirmed;
    }

    pub(crate) fn confirm_handshake(&mut self) {
        self.confirmed = true;
    }

    fn ack_delay_limit(&self) -> Duration {
        if self.confirmed {
            self.max_ack_delay
        } else {
            Duration::ZERO
        }
    }

    pub fn acknowledge(&mut self, ack: &Ack, now: Instant) -> Result<(), Error> {
        let outcome = self
            .ledger
            .acknowledge(ack, now, self.rtt.loss_delay())
            .map_err(|_| Error::Ledger)?;
        // Retain aliases for declared-lost packets until any copy is ACKed.
        let completed: Vec<u64> = self
            .aliases
            .iter()
            .filter_map(|(n, id)| ack.acknowledges(*n).then_some(*id))
            .collect();
        for id in completed {
            self.frames.remove(&id);
            self.aliases.retain(|_, value| *value != id);
        }
        self.queue.retain(|id| self.frames.contains_key(id));
        if self.frames.is_empty() && self.ledger.bytes_in_flight() == 0 {
            self.last_eliciting = None;
        }
        if outcome.acknowledged.iter().any(|p| p.ack_eliciting) {
            self.pto_count = 0;
        }
        if let Some(sample) = outcome.rtt_sample {
            let delay =
                Duration::from_micros(ack.delay.saturating_mul(1u64 << self.ack_delay_exponent));
            let limit = self.ack_delay_limit();
            self.rtt.update(sample, delay, limit, self.confirmed);
        }
        self.apply_loss(outcome, now)
    }

    fn apply_loss(&mut self, outcome: loss::Outcome, now: Instant) -> Result<(), Error> {
        self.window
            .retire(outcome.acknowledged_bytes + outcome.lost_bytes)
            .map_err(|_| Error::Window)?;
        // BBR uses the same authoritative in-flight ledger, but does not
        // apply CUBIC's multiplicative decrease/growth to its model.
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.feedback(&outcome, now, self.window.in_flight())
                .map_err(|_| Error::Window)?;
            self.window
                .set_target(bbr.cwnd())
                .map_err(|_| Error::Window)?;
        } else if self.rtt.minimum().is_some()
            && persistent_loss(&outcome, self.base_pto().saturating_mul(3))
        {
            self.window.persistent_congestion(now);
        }
        // Apply loss before growth, so an ACK for a packet sent before
        // the new recovery boundary cannot undo the congestion event.
        for p in outcome.lost {
            self.cwnd_limited.remove(&p.number);
            if p.in_flight && self.bbr.is_none() {
                self.window.loss(p.at, now).map_err(|_| Error::Window)?;
            }
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
            let limited = self.cwnd_limited.remove(&p.number);
            if p.in_flight && self.bbr.is_none() {
                self.window
                    .on_ack(p.at, now, u64::from(p.bytes), self.rtt.smoothed(), limited)
                    .map_err(|_| Error::Window)?;
            }
        }
        Ok(())
    }

    pub fn on_timer(&mut self, now: Instant) -> Result<(), Error> {
        let result = self
            .ledger
            .on_loss_timer(now, self.rtt.loss_delay())
            .map_err(|_| Error::Ledger)?;
        self.apply_loss(result, now)
    }

    pub fn base_pto(&self) -> Duration {
        self.rtt.pto(self.ack_delay_limit(), 0)
    }

    fn pto_deadline(&self) -> Option<Instant> {
        if self.ledger.bytes_in_flight() == 0 {
            return None;
        }
        self.last_eliciting?
            .checked_add(self.rtt.pto(self.ack_delay_limit(), self.pto_count))
    }

    pub fn deadline(&self) -> Option<Instant> {
        let loss = self.ledger.loss_deadline(self.rtt.loss_delay());
        let pto = self.pto_deadline();
        let pace = if !self.queue.is_empty()
            && self.window.in_flight().saturating_add(MTU) <= self.window.cwnd()
        {
            self.next_send
        } else {
            None
        };
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
        if last.and_then(|n| n.checked_add(1)) != Some(packet.number) {
            start = Some(packet.at);
        }
        last = Some(packet.number);
        if start.is_some_and(|at| packet.at.saturating_duration_since(at) >= threshold) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_core::ack::Range;

    fn ack(n: u64) -> Ack {
        Ack {
            delay: 0,
            ranges: vec![Range { first: n, last: n }],
            ecn: None,
        }
    }

    #[test]
    fn negotiated_ack_delay_applies_only_after_confirmation() {
        let now = Instant::now();
        let mut s = Scheduler::default();
        let initial_pto = s.base_pto();
        s.application_ack_timing(3, 25, false);
        assert_eq!(s.base_pto(), initial_pto);
        s.confirm_handshake();
        assert_eq!(s.base_pto(), initial_pto + Duration::from_millis(25));
        s.rtt.update(
            Duration::from_millis(100),
            Duration::ZERO,
            Duration::ZERO,
            true,
        );
        s.enqueue(vec![1]).unwrap();
        s.record(0, 100, Some((0, false)), now).unwrap();
        let mut a = ack(0);
        a.delay = 2500; // 20ms at exponent 3
        s.acknowledge(&a, now + Duration::from_millis(150)).unwrap();
        assert_eq!(s.rtt.smoothed(), Duration::from_micros(103750));
    }

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
    fn migration_requeues_reliable_data_without_reusing_packet_numbers() {
        for bbr in [false, true] {
            let now = Instant::now();
            let mut s = if bbr {
                Scheduler::with_bbr(now)
            } else {
                Scheduler::default()
            };
            s.enqueue(vec![1]).unwrap();
            let (id, _, _) = s.candidate(now).unwrap().unwrap();
            s.record(0, 100, Some((id, false)), now).unwrap();
            let next = now + Duration::from_millis(50);
            s.restart_path(next);
            assert_eq!(s.window.in_flight(), 0);
            assert!(s.rtt.minimum().is_none());
            assert_eq!(s.candidate(next).unwrap().unwrap().0, id);
            s.record(1, 100, Some((id, false)), next).unwrap();
            s.acknowledge(&ack(0), next).unwrap();
            assert_eq!(s.pending(), 0);
            assert!(s.rtt.minimum().is_none());
            assert_eq!(s.window.in_flight(), 100);
            s.acknowledge(&ack(1), next + Duration::from_millis(5))
                .unwrap();
            assert_eq!(s.window.in_flight(), 0);
            assert_eq!(s.rtt.minimum(), Some(Duration::from_millis(5)));
        }
    }

    #[test]
    fn ack_only_packets_do_not_consume_loss_queue() {
        let now = Instant::now();
        let mut s = Scheduler::default();
        for number in 0..5000 {
            s.record(number, 30, None, now).unwrap();
        }
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
        s.acknowledge(&ack(0), now + Duration::from_millis(20))
            .unwrap();
        assert_eq!(s.window.in_flight(), 0);
        assert_eq!(s.pending(), 0);
        assert_eq!(s.bbr.as_ref().unwrap().bandwidth(), 5000);
    }

    #[test]
    fn path_packets_share_flight_accounting_without_stream_aliases() {
        let now = Instant::now();
        let mut s = Scheduler::with_bbr(now);
        assert!(s.can_send_path());
        s.record_path(0, 1200, now).unwrap();
        assert_eq!(s.window.in_flight(), 1200);
        assert_eq!(s.pending(), 0);
        s.acknowledge(&ack(0), now + Duration::from_millis(10))
            .unwrap();
        assert_eq!(s.window.in_flight(), 0);
    }

    #[test]
    fn path_only_flight_arms_pto_and_ping_releases_lost_probe() {
        let now = Instant::now();
        let mut s = Scheduler::default();
        s.record_path(0, 1200, now).unwrap();
        let at = s.deadline().unwrap();
        let (id, bytes, probe) = s.candidate(at).unwrap().unwrap();
        assert_eq!(bytes, [1]);
        assert!(probe);
        s.record(1, 32, Some((id, probe)), at).unwrap();
        s.acknowledge(&ack(1), at + Duration::from_millis(10))
            .unwrap();
        assert_eq!(s.window.in_flight(), 0);
        assert_eq!(s.pending(), 0);
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
