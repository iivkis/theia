//! Per-PN-space loss/retransmission ledgers sharing one physical-path
//! congestion controller, RTT estimator, pacing clock and PTO backoff.
use super::{
    ack::Ack,
    bbr::Bbr,
    congestion::Window,
    loss::{self, FrameRef, Ledger, Sent},
    mtu::Discovery,
    recovery::Rtt,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_FRAMES: usize = 128;
// Count encoded bytes conservatively at their maximum per frame.
const APPLICATION_FRAMES: usize = crate::transport_policy::QUIC_SEND_WINDOW_BYTES as usize / 1100;
const MAX_ALIASES: usize = 4096;
const MAX_PTO: u32 = 8;
const MAX_HISTORY: usize = 8192;
const MTU: u64 = 1200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    Ledger,
    Window,
    Timeout,
}

type Batch = (Vec<u64>, Vec<u8>, bool);

struct Pending {
    bytes: Vec<u8>,
    queued: bool,
}

// A single owner drives the connection. The lock protects synchronous
// state transitions only; it is never held across I/O or an await.
struct LossUndo {
    cubic: super::congestion::Undo,
    bbr: Option<super::bbr::Undo>,
    pending: BTreeSet<u64>,
    boundary: u64,
    expires: Instant,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TxState {
    Pending,
    Acked,
    Lost,
    Neutral,
}

struct TxHistory {
    at: Instant,
    space: u64,
    state: TxState,
}

struct PathControl {
    window: Window,
    bbr: Option<Bbr>,
    rtt: Rtt,
    pto_count: u32,
    next_send: Option<Instant>,
    first_rtt_at: Option<Instant>,
    persistent_reported: Option<Instant>,
    next_tx: u64,
    last_tx: Option<u64>,
    next_space: u64,
    history: BTreeMap<u64, TxHistory>,
    application_max_ack_delay: Duration,
    undo: Option<LossUndo>,
}

impl PathControl {
    fn new(bbr: Option<Bbr>) -> Self {
        Self {
            window: Window::new(MTU).expect("valid MTU"),
            bbr,
            rtt: Rtt::default(),
            pto_count: 0,
            next_send: None,
            first_rtt_at: None,
            persistent_reported: None,
            next_tx: 0,
            last_tx: None,
            next_space: 1,
            history: BTreeMap::new(),
            application_max_ack_delay: Duration::ZERO,
            undo: None,
        }
    }

    fn allocate(&mut self, space: u64, now: Instant, eliciting: bool) -> Result<u64, Error> {
        let id = self.next_tx;
        self.next_tx = id.checked_add(1).ok_or(Error::Limit)?;
        self.last_tx = Some(id);
        if eliciting {
            self.history.insert(
                id,
                TxHistory {
                    at: now,
                    space,
                    state: TxState::Pending,
                },
            );
            if self.history.len() > MAX_HISTORY {
                self.history.pop_first();
            }
        }
        Ok(id)
    }

    fn persistent_end(&self, first: Instant, threshold: Duration) -> Option<Instant> {
        let mut start = None;
        let mut end = None;
        for entry in self.history.values() {
            if entry.at < first || entry.state != TxState::Lost {
                start = None;
                continue;
            }
            let begin = *start.get_or_insert(entry.at);
            if entry.at.saturating_duration_since(begin) >= threshold {
                end = Some(entry.at);
            }
        }
        end
    }

    fn state(&mut self, tx: u64, state: TxState) {
        if let Some(entry) = self.history.get_mut(&tx) {
            entry.state = state;
        }
    }
}

type SharedPath = Arc<Mutex<PathControl>>;

pub struct Scheduler {
    ledger: Ledger,
    path: SharedPath,
    space: u64,
    // Wire packet numbers overlap across spaces; BBR and HyStart use a
    // monotone connection-local transmission ID instead.
    active_tx: BTreeMap<u64, u64>,
    lost_tx: BTreeMap<u64, u64>,
    ack_delay_exponent: u32,
    max_ack_delay: Duration,
    confirmed: bool,
    frames: BTreeMap<u64, Pending>,
    frame_limit: usize,
    queue: VecDeque<u64>,
    aliases: BTreeMap<u64, Vec<u64>>,
    next_id: u64,
    last_eliciting: Option<Instant>,
    cwnd_limited: BTreeSet<u64>,
    mtu: Discovery,
    ecn: super::ecn::PathEcn,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new(Arc::new(Mutex::new(PathControl::new(None))), 0)
    }
}

impl Scheduler {
    fn new(path: SharedPath, space: u64) -> Self {
        Self {
            ledger: Ledger::default(),
            path,
            space,
            active_tx: BTreeMap::new(),
            lost_tx: BTreeMap::new(),
            ack_delay_exponent: 0,
            max_ack_delay: Duration::ZERO,
            confirmed: false,
            frames: BTreeMap::new(),
            frame_limit: MAX_FRAMES,
            queue: VecDeque::new(),
            aliases: BTreeMap::new(),
            next_id: 0,
            last_eliciting: None,
            cwnd_limited: BTreeSet::new(),
            mtu: Discovery::default(),
            ecn: super::ecn::PathEcn::default(),
        }
    }

    pub fn with_bbr(now: Instant) -> Self {
        Self::new(
            Arc::new(Mutex::new(PathControl::new(Some(
                Bbr::new(MTU, now).expect("valid MTU"),
            )))),
            0,
        )
    }

    pub(crate) fn fork_space(&self) -> Self {
        let mut path = self.path.lock().expect("path lock");
        let space = path.next_space;
        path.next_space = path
            .next_space
            .checked_add(1)
            .expect("bounded packet spaces");
        Self::new(self.path.clone(), space)
    }

    pub(crate) fn after_retry(mut self, next: u64, now: Instant) -> Self {
        // Retry is possible only before Handshake keys. Reset path model,
        // retain the shared handle and never restart the wire PN sequence.
        self.restart_path(now);
        let mut next_space = self.fork_space();
        next_space.ledger = Ledger::with_next(next);
        next_space
    }

    /// Check actual coalesced flight bytes before allocating any wire PN.
    /// PTO is an explicitly bounded exception, not ordinary send credit.
    pub(crate) fn permits_flight(&self, ordinary: u64, probe: u64, now: Instant) -> bool {
        let path = self.path.lock().expect("path lock");
        probe <= MTU
            && (ordinary == 0
                || (path.next_send.is_none_or(|at| now >= at)
                    && path
                        .window
                        .in_flight()
                        .saturating_add(ordinary)
                        .saturating_add(probe)
                        <= path.window.cwnd()))
    }

    /// Cross-IP migration occurs only after Handshake discard. Reset model
    /// and flight but never the wire PN or the connection-local TX sequence.
    pub(crate) fn restart_path(&mut self, now: Instant) {
        let mut path = self.path.lock().expect("path lock");
        debug_assert_eq!(path.window.in_flight(), self.ledger.bytes_in_flight());
        let next_tx = path.next_tx;
        let next_space = path.next_space;
        let app_delay = path.application_max_ack_delay;
        let bbr = path
            .bbr
            .as_ref()
            .map(|_| Bbr::new(MTU, now).expect("valid MTU"));
        *path = PathControl::new(bbr);
        path.next_tx = next_tx;
        path.next_space = next_space;
        path.application_max_ack_delay = app_delay;
        self.ledger.restart_path();
        self.active_tx.clear();
        self.lost_tx.clear();
        self.mtu.reset_path(now);
        self.ecn.disable();
        self.queue.clear();
        for (&id, frame) in &mut self.frames {
            frame.queued = true;
            self.queue.push_back(id);
        }
        self.cwnd_limited.clear();
        self.last_eliciting = None;
    }

    pub(crate) fn enable_application_buffer(&mut self) {
        self.frame_limit = APPLICATION_FRAMES;
    }

    pub fn can_queue(&self) -> bool {
        self.can_queue_n(1)
    }

    pub fn can_queue_n(&self, n: usize) -> bool {
        n <= self.frame_limit.saturating_sub(self.frames.len())
            && (n as u64) <= u64::MAX - self.next_id
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
        self.aliases.retain(|_, ids| {
            ids.retain(|id| self.frames.contains_key(id));
            !ids.is_empty()
        });
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
            if self.path.lock().expect("path lock").pto_count >= MAX_PTO {
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
        if !self.permits_flight(self.mtu.current() as u64, 0, now) {
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

    /// Coalesce length-delimited reliable application frames into the
    /// discovered packet size. Each original frame retains its own alias;
    /// after a path MTU reduction they can be retransmitted individually.
    pub(crate) fn candidate_batch(
        &mut self,
        now: Instant,
        capacity: usize,
    ) -> Result<Option<Batch>, Error> {
        let Some((id, mut bytes, probe)) = self.candidate(now)? else {
            return Ok(None);
        };
        if bytes.len() > capacity {
            return Err(Error::Limit);
        }
        let mut ids = vec![id];
        if !probe
            && !bytes
                .first()
                .is_some_and(|ty| (8..=15).contains(ty) && ty & 2 == 0)
        {
            for &next in &self.queue {
                if next == id {
                    continue;
                }
                let Some(frame) = self.frames.get(&next) else {
                    continue;
                };
                if ids.len() == 32 || bytes.len() + frame.bytes.len() > capacity {
                    break;
                }
                // A STREAM without LEN consumes the remaining packet. Our
                // send encoder always writes LEN; preserve this invariant.
                if frame
                    .bytes
                    .first()
                    .is_some_and(|ty| (8..=15).contains(ty) && ty & 2 == 0)
                {
                    break;
                }
                bytes.extend_from_slice(&frame.bytes);
                ids.push(next);
            }
        }
        Ok(Some((ids, bytes, probe)))
    }

    pub(crate) fn enable_mtu(&mut self, peer_cap: u64, now: Instant) {
        self.mtu = Discovery::new(peer_cap, now);
    }

    pub(crate) fn current_mtu(&self) -> usize {
        self.mtu.current()
    }

    pub(crate) fn reset_mtu(&mut self, now: Instant) {
        self.ecn.disable();
        self.path.lock().expect("path lock").undo = None;
        let before = self.mtu.current();
        self.mtu.reset_path(now);
        self.apply_mtu(before);
    }

    pub(crate) fn disable_mtu(&mut self) {
        let before = self.mtu.current();
        self.mtu = Discovery::default();
        self.apply_mtu(before);
    }

    pub(crate) fn enable_ecn(&mut self, supported: bool) {
        self.ecn.enable(supported);
    }
    pub(crate) fn should_mark_ecn(&self) -> bool {
        self.ecn.should_mark()
    }
    pub(crate) fn record_ecn(&mut self, number: u64, mark: super::ecn::Mark, now: Instant) {
        self.ecn.sent(number, mark, now);
    }

    fn mtu_deadline(&self) -> Option<Instant> {
        let size = self.mtu.candidate()?;
        (self.confirmed
            && self
                .path
                .lock()
                .expect("path lock")
                .window
                .can_reserve_size(size as u64))
        .then_some(())?;
        self.mtu.deadline()
    }

    pub(crate) fn mtu_probe(&self, now: Instant) -> Option<usize> {
        (now >= self.mtu_deadline()?)
            .then(|| self.mtu.candidate())
            .flatten()
    }

    fn apply_mtu(&mut self, before: usize) {
        let mtu = self.mtu.current();
        if before != mtu {
            let mut path = self.path.lock().expect("path lock");
            path.undo = None;
            path.window.set_mtu(mtu as u64);
            if let Some(bbr) = path.bbr.as_mut() {
                bbr.set_mtu(mtu as u64);
                let target = bbr.cwnd();
                path.window.set_target(target).expect("bounded BBR window");
            }
        }
    }

    pub(crate) fn burn_unsent(&mut self, number: u64, now: Instant) -> Result<(), Error> {
        self.ledger.burn(number, now).map_err(|_| Error::Ledger)
    }

    pub(crate) fn reject_mtu(
        &mut self,
        number: u64,
        size: usize,
        now: Instant,
    ) -> Result<(), Error> {
        self.burn_unsent(number, now)?;
        let before = self.mtu.current();
        self.mtu.local_reject(size, now);
        self.apply_mtu(before);
        Ok(())
    }

    pub(crate) fn record_mtu_probe(
        &mut self,
        number: u64,
        bytes: usize,
        now: Instant,
    ) -> Result<(), Error> {
        if self.mtu_probe(now) != Some(bytes) {
            return Err(Error::Window);
        }
        self.record_unreliable(number, bytes, now, Some(FrameRef::MtuProbe))?;
        self.mtu.sent(number, bytes);
        Ok(())
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
        match frame {
            Some((id, probe)) => self.record_batch(number, bytes, &[id], probe, now),
            None => self.record_batch(number, bytes, &[], false, now),
        }
    }

    pub(crate) fn record_batch(
        &mut self,
        number: u64,
        bytes: usize,
        ids: &[u64],
        probe: bool,
        now: Instant,
    ) -> Result<(), Error> {
        if bytes == 0 || bytes > self.mtu.current() || ids.len() > 32 {
            return Err(Error::Limit);
        }
        if !ids.is_empty() {
            if ids.iter().any(|id| !self.frames.contains_key(id))
                || self.aliases.len() >= MAX_ALIASES
            {
                return Err(Error::Limit);
            }
            let mut path = self.path.lock().expect("path lock");
            let before = path.window.in_flight();
            if before == 0 && path.bbr.is_none() {
                path.window.resume(now);
            }
            let app_limited = probe
                || (self.queue.iter().all(|queued| ids.contains(queued))
                    && before.saturating_add(2 * self.mtu.current() as u64) <= path.window.cwnd());
            if probe {
                path.window
                    .reserve_probe(bytes as u64)
                    .map_err(|_| Error::Window)?;
            } else {
                path.window
                    .reserve(bytes as u64)
                    .map_err(|_| Error::Window)?;
            }
            if let Err(_e) = self.ledger.record(Sent {
                number,
                at: now,
                bytes: bytes as u32,
                ack_eliciting: true,
                in_flight: true,
                frames: ids.iter().map(|&id| FrameRef::Control(id)).collect(),
            }) {
                path.window
                    .retire(bytes as u64)
                    .map_err(|_| Error::Window)?;
                return Err(Error::Ledger);
            }
            let tx = path.allocate(self.space, now, true)?;
            self.active_tx.insert(number, tx);
            if let Some(bbr) = path.bbr.as_mut() {
                bbr.sent(tx, bytes as u64, now, before, app_limited)
                    .map_err(|_| Error::Window)?;
            }
            if !app_limited && path.bbr.is_none() {
                self.cwnd_limited.insert(number);
            }
            self.aliases.insert(number, ids.to_vec());
            self.queue.retain(|queued| !ids.contains(queued));
            for id in ids {
                if let Some(f) = self.frames.get_mut(id) {
                    f.queued = false;
                }
            }
            if probe {
                path.pto_count += 1;
            }
            self.last_eliciting = Some(now);
            let spacing = if let Some(bbr) = &path.bbr {
                bbr.pacing_interval(bytes as u64)
            } else {
                path.window
                    .pacing_interval(bytes as u64, path.rtt.smoothed())
            };
            path.next_send = path.next_send.unwrap_or(now).max(now).checked_add(spacing);
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
        let path = self.path.lock().expect("path lock");
        path.window.in_flight().saturating_add(MTU) <= path.window.cwnd()
    }

    pub fn record_path(&mut self, number: u64, bytes: usize, now: Instant) -> Result<(), Error> {
        if bytes == 0 || bytes > MTU as usize || !self.can_send_path() {
            return Err(Error::Window);
        }
        self.record_unreliable(number, bytes, now, None)
    }

    pub(crate) fn record_padded_ack(
        &mut self,
        number: u64,
        bytes: usize,
        now: Instant,
    ) -> Result<(), Error> {
        self.record_unreliable(number, bytes, now, Some(FrameRef::PaddingOnly))
    }

    fn record_unreliable(
        &mut self,
        number: u64,
        bytes: usize,
        now: Instant,
        marker: Option<FrameRef>,
    ) -> Result<(), Error> {
        let mut path = self.path.lock().expect("path lock");
        let before = path.window.in_flight();
        let eliciting = marker != Some(FrameRef::PaddingOnly);
        path.window
            .reserve_discovery(bytes as u64)
            .map_err(|_| Error::Window)?;
        if self
            .ledger
            .record(Sent {
                number,
                at: now,
                bytes: bytes as u32,
                ack_eliciting: eliciting,
                in_flight: true,
                frames: marker.into_iter().collect(),
            })
            .is_err()
        {
            path.window
                .retire(bytes as u64)
                .map_err(|_| Error::Window)?;
            return Err(Error::Ledger);
        }
        let tx = path.allocate(self.space, now, eliciting)?;
        self.active_tx.insert(number, tx);
        if let Some(bbr) = path.bbr.as_mut() {
            bbr.sent(tx, bytes as u64, now, before, true)
                .map_err(|_| Error::Window)?;
        }
        if eliciting {
            self.last_eliciting = Some(now);
        }
        let spacing = if let Some(bbr) = &path.bbr {
            bbr.pacing_interval(bytes as u64)
        } else {
            path.window
                .pacing_interval(bytes as u64, path.rtt.smoothed())
        };
        path.next_send = path.next_send.unwrap_or(now).max(now).checked_add(spacing);
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
        self.path
            .lock()
            .expect("path lock")
            .application_max_ack_delay = self.max_ack_delay;
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
        let delay =
            Duration::from_micros(ack.delay.saturating_mul(1u64 << self.ack_delay_exponent));
        let limit = self.ack_delay_limit();
        let confirmed = self.confirmed;
        let largest_sent_at = ack.ranges.first().and_then(|range| self.ledger.sent_at(range.last));
        let outcome = {
            let mut path = self.path.lock().expect("path lock");
            self.ledger
                .acknowledge_with_delay(ack, now, |sample| {
                    if let Some(sample) = sample {
                        path.first_rtt_at.get_or_insert(now);
                        path.rtt.update(sample, delay, limit, confirmed);
                    }
                    path.rtt.loss_delay()
                })
                .map_err(|_| Error::Ledger)?
        };
        // Retain aliases for declared-lost packets until any copy is ACKed.
        let completed: BTreeSet<u64> = self
            .aliases
            .iter()
            .filter(|(n, _)| ack.acknowledges(**n))
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();
        for id in &completed {
            self.frames.remove(id);
        }
        self.aliases.retain(|_, ids| {
            ids.retain(|id| !completed.contains(id));
            !ids.is_empty()
        });
        self.queue.retain(|id| self.frames.contains_key(id));
        if self.frames.is_empty() && self.ledger.bytes_in_flight() == 0 {
            self.last_eliciting = None;
        }
        {
            let mut path = self.path.lock().expect("path lock");
            if outcome.newly_acked_eliciting {
                path.pto_count = 0;
            }
            if path.bbr.is_none() && outcome.lost_bytes == 0 {
                if let (Some(sample), Some(last)) = (outcome.rtt_sample, path.last_tx) {
                    if let Some(tx) = outcome
                        .acknowledged
                        .iter()
                        .filter(|p| self.cwnd_limited.contains(&p.number))
                        .filter_map(|p| self.active_tx.get(&p.number).copied())
                        .max()
                    {
                        path.window.rtt_sample(tx, last, sample);
                    }
                }
            }
        }
        let new_delivery = outcome.newly_acked_eliciting;
        let ce = self.ecn.acknowledge(ack, largest_sent_at, now);
        if ce.is_some() {
            self.path.lock().expect("path lock").undo = None;
        }
        self.apply_loss(outcome, now)?;
        let mut path = self.path.lock().expect("path lock");
        if let Some(at) = ce {
            path.undo = None;
            if let Some(bbr) = path.bbr.as_mut() {
                bbr.ecn_congestion(now);
                let target = bbr.cwnd();
                path.window.set_target(target).map_err(|_| Error::Window)?;
            } else {
                path.window.ecn(at, now).map_err(|_| Error::Window)?;
            }
        } else if new_delivery && path.bbr.is_none() {
            let rtt = path.rtt.smoothed();
            path.window.clean_ecn_ack(now, rtt);
        }
        Ok(())
    }

    fn apply_loss(&mut self, outcome: loss::Outcome, now: Instant) -> Result<(), Error> {
        self.path
            .lock()
            .expect("path lock")
            .window
            .retire(outcome.acknowledged_bytes + outcome.lost_bytes)
            .map_err(|_| Error::Window)?;
        let before = self.mtu.current();
        self.mtu.feedback(&outcome, now);
        self.apply_mtu(before);
        // Keep wire aliases/MTU feedback in their own number space. Only
        // controller feedback uses connection-local transmission IDs.
        let mut model = loss::Outcome {
            acknowledged_bytes: outcome.acknowledged_bytes,
            lost_bytes: outcome.lost_bytes,
            rtt_sample: outcome.rtt_sample,
            newly_acked_eliciting: outcome.newly_acked_eliciting,
            ..loss::Outcome::default()
        };
        for packet in &outcome.acknowledged {
            let mut p = packet.clone();
            p.number = self.active_tx.remove(&packet.number).ok_or(Error::Ledger)?;
            model.acknowledged.push(p);
        }
        for packet in &outcome.lost {
            let mut p = packet.clone();
            p.number = self.active_tx.remove(&packet.number).ok_or(Error::Ledger)?;
            self.lost_tx.insert(packet.number, p.number);
            if self.lost_tx.len() > MAX_ALIASES {
                self.lost_tx.pop_first();
            }
            model.lost.push(p);
        }
        for packet in &outcome.late_acknowledged {
            if let Some(tx) = self.lost_tx.remove(&packet.number) {
                let mut p = packet.clone();
                p.number = tx;
                model.late_acknowledged.push(p);
            }
        }
        let mut path = self.path.lock().expect("path lock");
        let pto = path.rtt.pto(path.application_max_ack_delay, 0);
        for p in &model.acknowledged {
            path.state(p.number, TxState::Acked);
        }
        for p in &model.late_acknowledged {
            path.state(p.number, TxState::Acked);
        }
        for p in &model.lost {
            path.state(
                p.number,
                if p.frames.contains(&FrameRef::MtuProbe) {
                    TxState::Neutral
                } else {
                    TxState::Lost
                },
            );
        }
        let persistent = path
            .first_rtt_at
            .filter(|_| !outcome.lost.is_empty())
            .and_then(|first| path.persistent_end(first, pto.saturating_mul(3)))
            .filter(|end| path.persistent_reported.is_none_or(|old| *end > old));
        // Undo is intentionally stricter than a heuristic: only a complete
        // set of late original-PN ACKs proves the loss event spurious.
        // Later loss, CE, path/MTU change, discard or expiry invalidates it.
        if path.undo.as_ref().is_some_and(|undo| now >= undo.expires) {
            path.undo = None;
        }
        let congestion: BTreeSet<_> = model
            .lost
            .iter()
            .filter(|p| p.in_flight && !p.frames.contains(&FrameRef::MtuProbe))
            .map(|p| p.number)
            .collect();
        if persistent.is_some() {
            path.undo = None;
        } else if !congestion.is_empty() {
            let same_episode = path.undo.as_ref().is_some_and(|undo| {
                congestion.last().is_some_and(|tx| *tx <= undo.boundary)
                    && undo.pending.len().saturating_add(congestion.len()) <= MAX_HISTORY
            });
            if same_episode {
                if let Some(undo) = path.undo.as_mut() {
                    undo.pending.extend(congestion);
                }
            } else {
                path.undo = Some(LossUndo {
                    cubic: path.window.checkpoint(),
                    bbr: path.bbr.as_ref().map(Bbr::checkpoint),
                    pending: congestion,
                    boundary: path.last_tx.unwrap_or(0),
                    expires: now
                        .checked_add(pto.saturating_mul(3).min(Duration::from_secs(30)))
                        .ok_or(Error::Limit)?,
                });
            }
        }
        if let Some(undo) = path.undo.as_mut() {
            for packet in &model.late_acknowledged {
                undo.pending.remove(&packet.number);
            }
        }
        let in_flight = path.window.in_flight();
        if let Some(bbr) = path.bbr.as_mut() {
            bbr.feedback(&model, now, in_flight)
                .map_err(|_| Error::Window)?;
            if persistent.is_some() {
                bbr.persistent_congestion(now);
            }
            let target = bbr.cwnd();
            path.window.set_target(target).map_err(|_| Error::Window)?;
        } else if persistent.is_some() {
            path.window.persistent_congestion(now);
        }
        if persistent.is_some() {
            path.persistent_reported = persistent;
        }
        for p in outcome.lost {
            self.cwnd_limited.remove(&p.number);
            if p.in_flight
                && path.bbr.is_none()
                && persistent.is_none()
                && !p.frames.contains(&FrameRef::MtuProbe)
            {
                path.window.loss(p.at, now).map_err(|_| Error::Window)?;
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
        let smoothed = path.rtt.smoothed();
        for p in outcome.acknowledged {
            let limited = self.cwnd_limited.remove(&p.number);
            if p.in_flight && path.bbr.is_none() && persistent.is_none() {
                path.window
                    .on_ack(p.at, now, u64::from(p.bytes), smoothed, limited)
                    .map_err(|_| Error::Window)?;
            }
        }
        if path
            .undo
            .as_ref()
            .is_some_and(|undo| undo.pending.is_empty())
        {
            let undo = path.undo.take().expect("checked undo");
            if let (Some(bbr), Some(old)) = (path.bbr.as_mut(), undo.bbr) {
                bbr.undo_loss(old, now);
                let target = bbr.cwnd();
                path.window.set_target(target).map_err(|_| Error::Window)?;
            } else if path.bbr.is_none() {
                path.window.undo_loss(undo.cubic);
            }
        }
        if path.window.in_flight() == 0 && path.bbr.is_none() {
            path.window.mark_idle(now);
        }
        Ok(())
    }

    pub fn on_timer(&mut self, now: Instant) -> Result<(), Error> {
        let pto = self.base_pto();
        self.ecn.tick(now, pto);
        let delay = self.path.lock().expect("path lock").rtt.loss_delay();
        let result = self
            .ledger
            .on_loss_timer(now, delay)
            .map_err(|_| Error::Ledger)?;
        self.apply_loss(result, now)
    }

    pub(crate) fn measured_rtt(&self) -> Option<Duration> {
        let path = self.path.lock().expect("path lock");
        path.rtt.minimum().map(|_| path.rtt.smoothed())
    }

    pub fn base_pto(&self) -> Duration {
        self.path
            .lock()
            .expect("path lock")
            .rtt
            .pto(self.ack_delay_limit(), 0)
    }

    pub(crate) fn pto_deadline(&self) -> Option<Instant> {
        if !self.ledger.has_eliciting_flight() {
            return None;
        }
        let path = self.path.lock().expect("path lock");
        self.last_eliciting?
            .checked_add(path.rtt.pto(self.ack_delay_limit(), path.pto_count))
    }

    pub(crate) fn pacing_deadline(&self) -> Option<Instant> {
        let path = self.path.lock().expect("path lock");
        (path.window.in_flight().saturating_add(MTU) <= path.window.cwnd())
            .then_some(path.next_send)
            .flatten()
    }

    pub fn deadline(&self) -> Option<Instant> {
        let (loss, pace) = {
            let path = self.path.lock().expect("path lock");
            let loss = self.ledger.loss_deadline(path.rtt.loss_delay());
            let pace = if !self.queue.is_empty()
                && path
                    .window
                    .in_flight()
                    .saturating_add(self.mtu.current() as u64)
                    <= path.window.cwnd()
            {
                path.next_send
            } else {
                None
            };
            (loss, pace)
        };
        [loss, self.pto_deadline(), pace, self.mtu_deadline()]
            .into_iter()
            .flatten()
            .min()
    }
}

// Key discard releases only the abandoned space. It is not congestion,
// delivery, or an RTT sample. Other spaces retain their model and flight.
impl Drop for Scheduler {
    fn drop(&mut self) {
        let Ok(mut path) = self.path.lock() else {
            return;
        };
        if path
            .undo
            .as_ref()
            .is_some_and(|undo| self.lost_tx.values().any(|id| undo.pending.contains(id)))
        {
            path.undo = None;
        }
        // A discarded space can no longer prove delivery of its packets.
        // Keep a neutral barrier instead of joining loss intervals across it.
        for entry in path
            .history
            .values_mut()
            .filter(|entry| entry.space == self.space)
        {
            entry.state = TxState::Neutral;
        }
        path.pto_count = 0;
        let _ = path.window.retire(self.ledger.bytes_in_flight());
        if let Some(bbr) = path.bbr.as_mut() {
            for id in self.active_tx.values().chain(self.lost_tx.values()) {
                bbr.discard(*id);
            }
        }
    }
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
    fn persistent_congestion_is_connection_wide_and_ack_is_a_barrier() {
        let now = Instant::now();
        let delta = Duration::from_millis(100);
        let mut path = PathControl::new(None);
        let a = path.allocate(0, now, true).unwrap();
        let b = path.allocate(1, now + delta, true).unwrap();
        let c = path.allocate(2, now + delta * 3, true).unwrap();
        path.state(a, TxState::Lost);
        path.state(b, TxState::Lost);
        path.state(c, TxState::Lost);
        assert_eq!(path.persistent_end(now, delta * 3), Some(now + delta * 3));
        path.state(b, TxState::Acked);
        assert_eq!(path.persistent_end(now, delta * 3), None);
        path.state(b, TxState::Neutral);
        assert_eq!(path.persistent_end(now, delta * 3), None);
    }

    #[test]
    fn proven_spurious_loss_undoes_window_but_not_flight() {
        let now = Instant::now();
        for use_bbr in [false, true] {
            let mut s = if use_bbr {
                Scheduler::with_bbr(now)
            } else {
                Scheduler::default()
            };
            for n in 0..4 {
                s.enqueue(vec![1]).unwrap();
                s.record(n, 1200, Some((n, false)), now).unwrap();
            }
            let old = s.path.lock().unwrap().window.cwnd();
            let at = now + Duration::from_millis(100);
            s.acknowledge(&ack(3), at).unwrap();
            let reduced = s.path.lock().unwrap().window.cwnd();
            assert!(s.path.lock().unwrap().undo.is_some());
            let flight = s.path.lock().unwrap().window.in_flight();
            s.acknowledge(&ack(0), at).unwrap();
            assert_eq!(s.path.lock().unwrap().window.in_flight(), flight);
            assert!(s.path.lock().unwrap().undo.is_none());
            assert!(s.path.lock().unwrap().window.cwnd() >= reduced);
            assert!(s.path.lock().unwrap().window.cwnd() >= old);
            let restored = s.path.lock().unwrap().window.cwnd();
            s.acknowledge(&ack(0), at).unwrap();
            assert_eq!(s.path.lock().unwrap().window.cwnd(), restored);
        }
    }

    #[test]
    fn one_loss_episode_can_span_spaces_but_new_ce_invalidates_undo() {
        let start = Instant::now();
        let delta = Duration::from_millis(100);
        let mut initial = Scheduler::default();
        let mut handshake = initial.fork_space();
        for n in 0..4 {
            initial.enqueue(vec![1]).unwrap();
            initial.record(n, 1200, Some((n, false)), start).unwrap();
            handshake.enqueue(vec![1]).unwrap();
            handshake.record(n, 1200, Some((n, false)), start).unwrap();
        }
        let at = start + delta;
        initial.acknowledge(&ack(3), at).unwrap();
        handshake.acknowledge(&ack(3), at).unwrap();
        assert_eq!(
            initial
                .path
                .lock()
                .unwrap()
                .undo
                .as_ref()
                .unwrap()
                .pending
                .len(),
            2
        );
        initial.acknowledge(&ack(0), at).unwrap();
        assert_eq!(
            initial
                .path
                .lock()
                .unwrap()
                .undo
                .as_ref()
                .unwrap()
                .pending
                .len(),
            1
        );
        // CE is validated by the per-space ECN validator before the shared
        // controller sees it. Exercise that same invalidation boundary.
        {
            let mut path = initial.path.lock().unwrap();
            path.undo = None;
            path.window.ecn(at, at + delta).unwrap();
        }
        let before = initial.path.lock().unwrap().window.cwnd();
        handshake.acknowledge(&ack(0), at).unwrap();
        assert_eq!(initial.path.lock().unwrap().window.cwnd(), before);
        assert!(initial.path.lock().unwrap().undo.is_none());
    }

    #[test]
    fn padded_ack_consumes_shared_window_but_does_not_arm_pto() {
        let now = Instant::now();
        let mut initial = Scheduler::with_bbr(now);
        let app = initial.fork_space();
        initial.record_padded_ack(0, 1200, now).unwrap();
        assert_eq!(app.path.lock().unwrap().window.in_flight(), 1200);
        assert!(initial.pto_deadline().is_none());
        initial
            .acknowledge(&ack(0), now + Duration::from_millis(50))
            .unwrap();
        assert_eq!(app.path.lock().unwrap().window.in_flight(), 0);
        assert!(app.measured_rtt().is_none());
    }

    #[test]
    fn overlapping_spaces_share_window_rtt_pacing_and_discard() {
        let now = Instant::now();
        for bbr in [false, true] {
            let mut initial = if bbr {
                Scheduler::with_bbr(now)
            } else {
                Scheduler::default()
            };
            let mut handshake = initial.fork_space();
            let mut application = initial.fork_space();
            initial.enqueue(vec![1]).unwrap();
            handshake.enqueue(vec![1]).unwrap();
            application.enqueue(vec![1]).unwrap();
            initial.record(0, 1200, Some((0, false)), now).unwrap();
            assert!(handshake.candidate(now).unwrap().is_none());
            let later = now + Duration::from_secs(1);
            handshake.record(0, 1000, Some((0, false)), later).unwrap();
            assert_eq!(application.path.lock().unwrap().window.in_flight(), 2200);
            assert_ne!(initial.active_tx[&0], handshake.active_tx[&0]);
            initial.acknowledge(&ack(0), later).unwrap();
            assert_eq!(
                application.path.lock().unwrap().rtt.minimum(),
                Some(Duration::from_secs(1))
            );
            assert_eq!(application.path.lock().unwrap().window.in_flight(), 1000);
            application.record(0, 500, Some((0, false)), later).unwrap();
            drop(handshake);
            assert_eq!(application.path.lock().unwrap().window.in_flight(), 500);
            application
                .acknowledge(&ack(0), later + Duration::from_millis(10))
                .unwrap();
            assert_eq!(application.path.lock().unwrap().window.in_flight(), 0);
            assert_eq!(
                application.path.lock().unwrap().rtt.minimum(),
                Some(Duration::from_millis(10))
            );
        }
    }

    #[derive(Clone, Copy)]
    struct SimAck {
        flow: usize,
        pn: u64,
        frame: u64,
    }

    fn shared_bottleneck(
        algorithms: [bool; 2],
        rtt_ms: [u64; 2],
        seconds: u64,
        periodic_loss: bool,
    ) -> ([u64; 2], u64) {
        let start = Instant::now();
        let mut flows = algorithms.map(|bbr| {
            if bbr {
                Scheduler::with_bbr(start)
            } else {
                Scheduler::default()
            }
        });
        let mut numbers = [0u64; 2];
        let mut completed = [BTreeSet::new(), BTreeSet::new()];
        let mut ack_events: BTreeMap<u64, Vec<SimAck>> = BTreeMap::new();
        // One 1200-byte packet per ms (9.6 Mbit/s), FIFO of 24
        // packets, no artificial per-flow service reservation.
        let mut link_free = 0u64;
        let mut dropped = 0u64;
        for tick in 0..seconds * 1000 {
            let now = start + Duration::from_millis(tick);
            for ack_event in ack_events.remove(&tick).unwrap_or_default() {
                flows[ack_event.flow]
                    .acknowledge(&ack(ack_event.pn), now)
                    .unwrap();
                completed[ack_event.flow].insert(ack_event.frame);
            }
            // Alternate iteration order to avoid a fixed equal-time tie bias.
            for k in 0..2 {
                let i = (k + tick as usize) % 2;
                let flow = &mut flows[i];
                flow.on_timer(now).unwrap();
                while flow.can_queue() {
                    flow.enqueue(vec![1]).unwrap();
                }
                if let Some((id, _, probe)) = flow.candidate(now).unwrap() {
                    let number = numbers[i];
                    numbers[i] += 1;
                    flow.record(number, 1200, Some((id, probe)), now).unwrap();
                    let queue = link_free.saturating_sub(tick);
                    if queue >= 24 || (periodic_loss && number % 97 == 13) {
                        dropped += 1;
                    } else {
                        link_free = link_free.max(tick) + 1;
                        // Deterministic occasional reordering, independent of controller.
                        let reorder = if periodic_loss && number % 131 == 19 {
                            12
                        } else {
                            0
                        };
                        let due = link_free + rtt_ms[i] + reorder;
                        ack_events.entry(due).or_default().push(SimAck {
                            flow: i,
                            pn: number,
                            frame: id,
                        });
                    }
                }
                let path = flow.path.lock().unwrap();
                assert_eq!(path.window.in_flight(), flow.ledger.bytes_in_flight());
                assert!(path.window.cwnd() >= 2400);
                assert!(path.window.cwnd() <= 64 * 1024 * 1024);
            }
        }
        (completed.map(|frames| frames.len() as u64 * 1200), dropped)
    }

    #[test]
    fn both_controllers_make_progress_on_a_shared_bounded_link() {
        let (bytes, _) = shared_bottleneck([false, true], [30, 30], 2, false);
        assert!(bytes.iter().all(|n| *n > 0));
    }

    /// Diagnostic rather than a fairness gate. Report nominal unique-frame
    /// delivery, not actual H3 goodput. Probe jitter is intentionally real.
    #[test]
    #[ignore = "extended virtual-time congestion diagnostics"]
    fn competing_congestion_models_diagnostic() {
        println!(
            "controller_a,controller_b,rtt_a_ms,rtt_b_ms,loss_reorder,bytes_a,bytes_b,dropped,jain"
        );
        for algorithms in [[false, false], [true, true], [false, true], [true, false]] {
            for rtt in [[30, 30], [20, 80]] {
                for loss in [false, true] {
                    let (bytes, dropped) = shared_bottleneck(algorithms, rtt, 30, loss);
                    let a = bytes[0] as f64;
                    let b = bytes[1] as f64;
                    assert!(a > 0.0 && b > 0.0);
                    let jain = (a + b).powi(2) / (2.0 * (a * a + b * b));
                    let name = |bbr| if bbr { "bbr" } else { "cubic" };
                    println!(
                        "{},{},{},{},{},{},{},{},{:.6}",
                        name(algorithms[0]),
                        name(algorithms[1]),
                        rtt[0],
                        rtt[1],
                        loss,
                        bytes[0],
                        bytes[1],
                        dropped,
                        jain
                    );
                }
            }
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
        s.path.lock().unwrap().rtt.update(
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
        assert_eq!(
            s.path.lock().unwrap().rtt.smoothed(),
            Duration::from_micros(103750)
        );
    }

    #[test]
    fn discovery_uses_real_packet_ack_and_batch_retransmission_aliases() {
        let now = Instant::now();
        let mut s = Scheduler::default();
        s.confirm_handshake();
        s.enable_mtu(1452, now);
        let at = s.deadline().unwrap();
        let size = s.mtu_probe(at).unwrap();
        s.record_mtu_probe(0, size, at).unwrap();
        assert_eq!(s.current_mtu(), 1200);
        s.acknowledge(&ack(0), at + Duration::from_millis(10))
            .unwrap();
        assert_eq!(s.current_mtu(), size);
        s.enqueue(vec![1]).unwrap();
        s.enqueue(vec![1]).unwrap();
        let later = s
            .path
            .lock()
            .unwrap()
            .next_send
            .unwrap()
            .max(at + Duration::from_millis(10));
        let (ids, bytes, probe) = s.candidate_batch(later, size - 29).unwrap().unwrap();
        assert_eq!(bytes, [1, 1]);
        assert_eq!(ids.len(), 2);
        s.record_batch(1, 31, &ids, probe, later).unwrap();
        s.acknowledge(&ack(1), later).unwrap();
        assert_eq!(s.pending(), 0);
        s.reject_mtu(2, size, later).unwrap();
        assert_eq!(s.current_mtu(), 1200);
        assert_eq!(s.acknowledge(&ack(2), later), Err(Error::Ledger));
    }

    #[test]
    fn retransmission_after_mtu_reduction_keeps_individual_frame_aliases() {
        let now = Instant::now();
        let mut s = Scheduler::default();
        s.enqueue(vec![1; 700]).unwrap();
        s.enqueue(vec![1; 590]).unwrap();
        let (ids, _, _) = s.candidate_batch(now, 1400).unwrap().unwrap();
        assert_eq!(ids.len(), 2);
        // Model the initial batched transmission on a discovered path.
        s.confirm_handshake();
        s.enable_mtu(1452, now);
        let at = s.mtu_deadline().unwrap();
        let probe = s.mtu_probe(at).unwrap();
        s.record_mtu_probe(0, probe, at).unwrap();
        s.acknowledge(&ack(0), at + Duration::from_millis(10))
            .unwrap();
        let at = at + Duration::from_millis(10);
        s.record_batch(1, 1319, &ids, false, at).unwrap();
        s.restart_path(at);
        let (one, bytes, _) = s.candidate_batch(at, 1171).unwrap().unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(bytes.len(), 700);
        s.record_batch(2, 729, &one, false, at).unwrap();
        s.acknowledge(&ack(1), at).unwrap();
        assert_eq!(s.pending(), 0);
        assert_eq!(s.path.lock().unwrap().window.in_flight(), 729);
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
        assert_eq!(s.path.lock().unwrap().window.in_flight(), 0);
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
            assert_eq!(s.path.lock().unwrap().window.in_flight(), 0);
            assert!(s.path.lock().unwrap().rtt.minimum().is_none());
            assert_eq!(s.candidate(next).unwrap().unwrap().0, id);
            s.record(1, 100, Some((id, false)), next).unwrap();
            s.acknowledge(&ack(0), next).unwrap();
            assert_eq!(s.pending(), 0);
            assert!(s.path.lock().unwrap().rtt.minimum().is_none());
            assert_eq!(s.path.lock().unwrap().window.in_flight(), 100);
            s.acknowledge(&ack(1), next + Duration::from_millis(5))
                .unwrap();
            assert_eq!(s.path.lock().unwrap().window.in_flight(), 0);
            assert_eq!(
                s.path.lock().unwrap().rtt.minimum(),
                Some(Duration::from_millis(5))
            );
        }
    }

    #[test]
    fn ack_only_packets_do_not_consume_loss_queue() {
        let now = Instant::now();
        let mut s = Scheduler::default();
        for number in 0..5000 {
            s.record(number, 30, None, now).unwrap();
        }
        assert_eq!(s.path.lock().unwrap().window.in_flight(), 0);
        assert_eq!(s.acknowledge(&ack(5000), now), Err(Error::Ledger));
    }
    #[test]
    fn bbr_scheduler_uses_same_packet_ledger_and_releases_credit() {
        let now = Instant::now();
        let mut s = Scheduler::with_bbr(now);
        s.enqueue(vec![1]).unwrap();
        let (id, _, probe) = s.candidate(now).unwrap().unwrap();
        s.record(0, 100, Some((id, probe)), now).unwrap();
        assert_eq!(s.path.lock().unwrap().window.in_flight(), 100);
        s.acknowledge(&ack(0), now + Duration::from_millis(20))
            .unwrap();
        assert_eq!(s.path.lock().unwrap().window.in_flight(), 0);
        assert_eq!(s.pending(), 0);
        assert_eq!(
            s.path.lock().unwrap().bbr.as_ref().unwrap().bandwidth(),
            5000
        );
    }

    #[test]
    fn path_packets_share_flight_accounting_without_stream_aliases() {
        let now = Instant::now();
        let mut s = Scheduler::with_bbr(now);
        assert!(s.can_send_path());
        s.record_path(0, 1200, now).unwrap();
        assert_eq!(s.path.lock().unwrap().window.in_flight(), 1200);
        assert_eq!(s.pending(), 0);
        s.acknowledge(&ack(0), now + Duration::from_millis(10))
            .unwrap();
        assert_eq!(s.path.lock().unwrap().window.in_flight(), 0);
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
        assert_eq!(s.path.lock().unwrap().window.in_flight(), 0);
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
        assert_eq!(s.path.lock().unwrap().window.in_flight(), 100);
        s.acknowledge(&ack(0), now).unwrap();
        assert_eq!(s.path.lock().unwrap().window.in_flight(), 0);
        assert_eq!(s.pending(), 1);
    }
}
