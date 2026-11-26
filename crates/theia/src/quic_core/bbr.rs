//! Native QUIC BBR controller targeting draft-ietf-ccwg-bbr-07.
//! Delivery-rate sampling, a bounded bandwidth filter, min RTT, startup,
//! drain, bandwidth probing, RTT probing, pacing and packet conservation.
//! This is not a claim of conformance to the evolving IETF BBR draft (v3),
//! fairness, performance superiority or readiness for production.
use super::loss::Outcome;
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

const MAX_CWND: u64 = 64 * 1024 * 1024;
const MAX_RATE: u64 = 100_000_000_000; // bytes/s, arithmetic/resource bound
const MAX_SAMPLES: usize = 4096;
const INITIAL_RTT: Duration = Duration::from_millis(333);
const MIN_RTT_TTL: Duration = Duration::from_secs(10);
const PROBE_RTT_TIME: Duration = Duration::from_millis(200);
const HIGH_GAIN: f64 = 2.77;
const DRAIN_GAIN: f64 = 0.5;
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(5);
// Four-phase bandwidth probing, following the phase structure in
// draft-ietf-ccwg-bbr-07. The conservative bounded transitions below
// are intentionally not a complete implementation of that draft.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbePhase { Down, Cruise, Refill, Up }

impl ProbePhase {
    fn gain(self) -> f64 {
        match self { Self::Down => 0.90, Self::Cruise | Self::Refill => 1.0, Self::Up => 1.25 }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    Clock,
    Accounting,
}

#[derive(Clone, Copy)]
struct Sample {
    delivered: u64,
    delivered_at: Instant,
    first_sent_at: Instant,
    sent_at: Instant,
    app_limited: bool,
    tx_in_flight: u64,
    probing: bool,
}

pub struct Bbr {
    mtu: u64,
    cwnd: u64,
    mode: Mode,
    delivered: u64,
    delivered_at: Instant,
    first_sent_at: Instant,
    last_sent: Option<u64>,
    app_limited_until: u64,
    samples: BTreeMap<u64, Sample>,
    lost_samples: BTreeMap<u64, Sample>,
    bandwidth: VecDeque<(u64, u64)>,
    round: u64,
    next_round: u64,
    min_rtt: Option<Duration>,
    min_stamp: Instant,
    full_bw: u64,
    plateau: u8,
    full_pipe: bool,
    phase: ProbePhase,
    phase_at: Instant,
    phase_round: u64,
    cycle: u64,
    cycle_nonlimited: bool,
    probe_full_bw: u64,
    probe_plateau: u8,
    probe_wait: Duration,
    bandwidth_cap: Option<u64>,
    inflight_longterm: Option<u64>,
    bw_latest: u64,
    inflight_latest: u64,
    probe_up_rounds: u8,
    probe_up_acked: u64,
    probe_rtt_stamp: Instant,
    prior_cwnd: u64,
    ack_epoch: Instant,
    ack_epoch_bytes: u64,
    extra_acked: VecDeque<(u64, u64)>,
    idle_restart: bool,
    probe_done: Option<(Instant, u64)>,
    probe_min: Option<Duration>,
    recovery_until: Option<u64>,
    loss_ceiling: Option<u64>,
    round_acked: u64,
    round_lost: u64,
    last_ecn_round: Option<u64>,
}

impl Bbr {
    pub fn new(mtu: u64, now: Instant) -> Result<Self, Error> {
        if !(1200..=65527).contains(&mtu) {
            return Err(Error::Limit);
        }
        let cwnd = (10 * mtu).min((2 * mtu).max(14720)).max(4 * mtu);
        Ok(Self {
            mtu,
            cwnd,
            mode: Mode::Startup,
            delivered: 0,
            delivered_at: now,
            first_sent_at: now,
            last_sent: None,
            app_limited_until: 0,
            samples: BTreeMap::new(),
            lost_samples: BTreeMap::new(),
            bandwidth: VecDeque::new(),
            round: 0,
            next_round: 0,
            min_rtt: None,
            min_stamp: now,
            full_bw: 0,
            plateau: 0,
            full_pipe: false,
            phase: ProbePhase::Down,
            phase_at: now,
            phase_round: 0,
            cycle: 0,
            cycle_nonlimited: false,
            probe_full_bw: 0,
            probe_plateau: 0,
            probe_wait: Duration::from_secs(2),
            bandwidth_cap: None,
            inflight_longterm: None,
            bw_latest: 0,
            inflight_latest: 0,
            probe_up_rounds: 0,
            probe_up_acked: 0,
            probe_rtt_stamp: now,
            prior_cwnd: cwnd,
            ack_epoch: now,
            ack_epoch_bytes: 0,
            extra_acked: VecDeque::new(),
            idle_restart: false,
            probe_done: None,
            probe_min: None,
            recovery_until: None,
            loss_ceiling: None,
            round_acked: 0,
            round_lost: 0,
            last_ecn_round: None,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub(crate) fn set_mtu(&mut self, mtu: u64) {
        self.mtu = mtu;
        self.cwnd = self.cwnd.max(4 * mtu);
        self.loss_ceiling = self.loss_ceiling.map(|limit| limit.max(4 * mtu));
        self.inflight_longterm = self.inflight_longterm.map(|limit| limit.max(4 * mtu));
    }

    /// Conservative CE response, at most once per packet-timed round.
    /// This does not claim BBRv3 ECN/L4S conformance.
    pub(crate) fn persistent_congestion(&mut self, now: Instant) {
        let floor = 4 * self.mtu;
        self.cwnd = floor;
        self.loss_ceiling = Some(floor);
        self.inflight_longterm = Some(floor);
        self.prior_cwnd = floor;
        self.bound_bandwidth();
        self.full_pipe = true;
        self.recovery_until = self.last_sent;
        self.mode = Mode::ProbeBw;
        self.set_phase(ProbePhase::Down, now);
    }

    pub(crate) fn ecn_congestion(&mut self, now: Instant) {
        if self.last_ecn_round == Some(self.round) { return; }
        self.last_ecn_round = Some(self.round);
        let bound = (self.cwnd.saturating_mul(7) / 10).max(4 * self.mtu);
        if self.is_probing() {
            self.inflight_longterm = Some(self.inflight_longterm.map_or(bound, |old| old.min(bound)));
        }
        self.loss_ceiling = Some(self.loss_ceiling.map_or(bound, |old| old.min(bound)));
        self.cwnd = self.cwnd.min(bound);
        self.bound_bandwidth();
        if self.mode == Mode::ProbeBw { self.set_phase(ProbePhase::Down, now); }
        if self.mode == Mode::Startup {
            self.full_pipe = true;
            self.mode = Mode::Drain;
        }
    }

    pub fn cwnd(&self) -> u64 {
        self.cwnd
    }
    pub fn bandwidth(&self) -> u64 {
        self.bandwidth
            .iter()
            .map(|(_, rate)| *rate)
            .max()
            .unwrap_or(0)
    }
    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }
    fn rtt(&self) -> Duration {
        self.min_rtt
            .unwrap_or(INITIAL_RTT)
            .max(Duration::from_micros(1))
    }

    fn phase_cycle(&self) -> u64 { self.cycle }

    fn is_probing(&self) -> bool {
        self.mode == Mode::Startup || (self.mode == Mode::ProbeBw && matches!(self.phase, ProbePhase::Refill | ProbePhase::Up))
    }

    fn effective_bw(&self) -> u64 {
        let bw = self.bandwidth();
        if self.is_probing() { bw } else { bw.min(self.bandwidth_cap.unwrap_or(MAX_RATE)) }
    }

    fn bdp(&self) -> u64 {
        let bw = self.effective_bw();
        if bw == 0 {
            return self.cwnd;
        }
        ((u128::from(bw) * self.rtt().as_nanos()) / 1_000_000_000).min(u128::from(MAX_CWND)) as u64
    }

    fn gain(&self) -> f64 {
        match self.mode {
            Mode::Startup => HIGH_GAIN,
            Mode::Drain => DRAIN_GAIN,
            Mode::ProbeBw => self.phase.gain(),
            Mode::ProbeRtt => 1.0,
        }
    }

    pub fn pacing_rate(&self) -> u64 {
        let bw = self.effective_bw();
        let base = if bw == 0 {
            rate(self.cwnd, self.rtt())
        } else {
            bw
        };
        let gain = if self.idle_restart && self.mode == Mode::ProbeBw { 1.0 } else { self.gain() };
        ((base as f64 * gain * 0.99) as u64).clamp(1, MAX_RATE)
    }

    pub fn pacing_interval(&self, bytes: u64) -> Duration {
        let nanos = (u128::from(bytes) * 1_000_000_000).div_ceil(u128::from(self.pacing_rate()));
        Duration::from_nanos(nanos.clamp(1_000, u128::from(u64::MAX)) as u64)
    }

    /// The scheduler supplies actual newly attempted in-flight packets and
    /// the pre-send flight size. ACK-only packets do not enter the model.
    pub fn sent(
        &mut self,
        number: u64,
        bytes: u64,
        now: Instant,
        before: u64,
        app_limited: bool,
    ) -> Result<(), Error> {
        if bytes == 0
            || bytes > self.mtu.max(super::mtu::MAX_UDP_PAYLOAD as u64)
            || self.samples.len() >= MAX_SAMPLES
            || self.last_sent.is_some_and(|last| number <= last)
        {
            return Err(Error::Accounting);
        }
        if now < self.delivered_at || now < self.first_sent_at {
            return Err(Error::Clock);
        }
        if before == 0 {
            self.idle_restart = app_limited;
            self.first_sent_at = now;
            self.delivered_at = now;
            self.ack_epoch = now;
            self.ack_epoch_bytes = 0;
        }
        if app_limited {
            self.app_limited_until = self
                .app_limited_until
                .max(self.delivered.saturating_add(before).saturating_add(bytes));
        }
        self.samples.insert(
            number,
            Sample {
                delivered: self.delivered,
                delivered_at: self.delivered_at,
                first_sent_at: self.first_sent_at,
                sent_at: now,
                app_limited: self.delivered < self.app_limited_until || self.mode == Mode::ProbeRtt,
                tx_in_flight: before.saturating_add(bytes),
                probing: self.is_probing(),
            },
        );
        self.last_sent = Some(number);
        Ok(())
    }

    /// Feedback comes only from the authenticated ACK/loss ledger. Sample
    /// rate uses the greater of send and ACK elapsed times, mitigating ACK
    /// compression; app-limited samples cannot lower the bandwidth filter.
    pub fn feedback(
        &mut self,
        outcome: &Outcome,
        now: Instant,
        in_flight: u64,
    ) -> Result<(), Error> {
        if now < self.delivered_at {
            return Err(Error::Clock);
        }
        if outcome.acknowledged.is_empty() && outcome.lost.is_empty() && outcome.late_acknowledged.is_empty() { return Ok(()); }
        let mut sample: Option<Sample> = None;
        let mut highest = None;
        let mut delivered_bytes = outcome.acknowledged_bytes;
        for packet in &outcome.acknowledged {
            if !packet.in_flight {
                continue;
            }
            let value = self
                .samples
                .remove(&packet.number)
                .ok_or(Error::Accounting)?;
            if now < value.sent_at {
                return Err(Error::Clock);
            }
            if sample
                .is_none_or(|old| (value.delivered, value.sent_at) > (old.delivered, old.sent_at))
            {
                sample = Some(value);
            }
            highest = Some(highest.map_or(packet.number, |old: u64| old.max(packet.number)));
        }
        // A late ACK is evidence of delivery, not a second release of
        // flight credit or an instruction to grow the congestion window.
        for packet in &outcome.late_acknowledged {
            if let Some(value) = self.lost_samples.remove(&packet.number) {
                if now < value.sent_at { return Err(Error::Clock); }
                delivered_bytes = delivered_bytes.saturating_add(u64::from(packet.bytes));
                if sample.is_none_or(|old| (value.delivered, value.sent_at) > (old.delivered, old.sent_at)) {
                    sample = Some(value);
                }
                highest = Some(highest.map_or(packet.number, |old: u64| old.max(packet.number)));
            }
        }
        let mut probe_flight = None;
        for packet in &outcome.lost {
            if packet.in_flight {
                let lost = self.samples.remove(&packet.number).ok_or(Error::Accounting)?;
                self.lost_samples.insert(packet.number, lost);
                if self.lost_samples.len() > MAX_SAMPLES { self.lost_samples.pop_first(); }
                if lost.probing && !lost.app_limited && !packet.frames.contains(&super::loss::FrameRef::MtuProbe) {
                    probe_flight = Some(probe_flight.map_or(lost.tx_in_flight, |old: u64| old.min(lost.tx_in_flight)));
                }
            }
        }
        if outcome.acknowledged_bytes != 0 && sample.is_none() {
            return Err(Error::Accounting);
        }
        let mut round_start = false;
        let mut nonlimited_rate = None;
        let mut measured_rate = 0;
        let mut delivered_sample = 0;
        if let Some(sample) = sample {
            self.delivered = self
                .delivered
                .checked_add(delivered_bytes)
                .ok_or(Error::Limit)?;
            self.delivered_at = now;
            self.idle_restart = false;
            self.first_sent_at = self.first_sent_at.max(sample.sent_at);
            if sample.delivered >= self.next_round {
                self.round = self.round.checked_add(1).ok_or(Error::Limit)?;
                self.next_round = self.delivered;
                round_start = true;
            }
            // Keep the max filter bounded; cycle aging occurs at ProbeBW_DOWN.
            self.extra_acked.retain(|(round, _)| self.round.saturating_sub(*round) < 10);
            let elapsed = now
                .duration_since(sample.delivered_at)
                .max(sample.sent_at.duration_since(sample.first_sent_at));
            if !elapsed.is_zero() && self.min_rtt.is_none_or(|minimum| elapsed >= minimum) {
                let delivered = self
                    .delivered
                    .checked_sub(sample.delivered)
                    .ok_or(Error::Accounting)?;
                let measured = rate(delivered, elapsed);
                measured_rate = measured;
                delivered_sample = delivered;
                if !sample.app_limited || measured >= self.bandwidth() {
                    let cycle = self.phase_cycle();
                    if let Some((round, best)) = self.bandwidth.back_mut() {
                        if *round == cycle {
                            *best = (*best).max(measured);
                        } else {
                            self.bandwidth.push_back((cycle, measured));
                        }
                    } else {
                        self.bandwidth.push_back((cycle, measured));
                    }
                }
                if !sample.app_limited {
                    self.cycle_nonlimited = true;
                    nonlimited_rate = Some(measured);
                }
            }
        }
        let probe_lost = outcome.lost.iter().filter(|p| p.frames.contains(&super::loss::FrameRef::MtuProbe)).map(|p| u64::from(p.bytes)).sum::<u64>();
        let congestion_lost = outcome.lost_bytes.saturating_sub(probe_lost);
        let floor = 4 * self.mtu;
        self.bw_latest = self.bw_latest.max(measured_rate);
        self.inflight_latest = self.inflight_latest.max(delivered_sample);
        self.round_acked = self.round_acked.saturating_add(delivered_bytes);
        self.round_lost = self.round_lost.saturating_add(congestion_lost);
        let observed = self.round_acked.saturating_add(self.round_lost);
        let excessive = observed >= floor && u128::from(self.round_lost) * 50 > u128::from(observed);
        if excessive && self.is_probing() {
            if let Some(flight) = probe_flight {
                let bound = flight.max(self.bdp().saturating_mul(7) / 10).max(floor);
                self.inflight_longterm = Some(self.inflight_longterm.map_or(bound, |old| old.min(bound)));
                if self.mode == Mode::Startup {
                    self.full_pipe = true;
                    self.mode = Mode::Drain;
                } else {
                    self.set_phase(ProbePhase::Down, now);
                }
            }
        }
        // Short-term estimates adapt on a completed loss round, not once per
        // lost packet. Independent long-term limits survive REFILL.
        if round_start {
            if self.round_lost != 0 && !self.is_probing() {
                let old = self.loss_ceiling.unwrap_or(self.cwnd);
                self.loss_ceiling = Some((old.saturating_mul(7) / 10).max(self.inflight_latest).clamp(floor, MAX_CWND));
                self.bound_bandwidth();
            }
            self.round_acked = 0;
            self.round_lost = 0;
            self.bw_latest = measured_rate;
            self.inflight_latest = delivered_sample;
        }
        self.update_ack_aggregation(now, delivered_bytes);
        let expired = now.saturating_duration_since(self.probe_rtt_stamp) >= PROBE_RTT_INTERVAL;
        if let Some(rtt) = outcome.rtt_sample.map(|r| r.max(Duration::from_micros(1))) {
            if self.min_rtt.is_none_or(|old| rtt <= old) {
                self.min_rtt = Some(rtt);
                self.min_stamp = now;
                self.probe_rtt_stamp = now;
            } else if now.saturating_duration_since(self.min_stamp) >= MIN_RTT_TTL && self.mode != Mode::ProbeRtt {
                // Retain the old minimum until a low-inflight probe validates a new one.
                self.probe_rtt_stamp = self.min_stamp;
            }
            if self.mode == Mode::ProbeRtt && self.probe_done.is_some() {
                self.probe_min = Some(self.probe_min.map_or(rtt, |old| old.min(rtt)));
            }
        }
        if round_start && self.mode == Mode::Startup {
            if let Some(measured) = nonlimited_rate {
                if self.full_bw == 0 || u128::from(measured) * 4 >= u128::from(self.full_bw) * 5 {
                    self.full_bw = measured;
                    self.plateau = 0;
                } else {
                    self.plateau = self.plateau.saturating_add(1);
                    if self.plateau >= 3 {
                        self.full_pipe = true;
                        self.mode = Mode::Drain;
                    }
                }
            }
        }
        if self.mode == Mode::Drain && in_flight <= self.bdp() {
            self.enter_probe_bw(now);
        } else if self.mode == Mode::ProbeBw {
            if self.phase == ProbePhase::Up {
                self.probe_up_acked = self.probe_up_acked.saturating_add(outcome.acknowledged_bytes);
                if round_start {
                    if let Some(measured) = nonlimited_rate {
                        if self.probe_full_bw == 0 || u128::from(measured) * 4 >= u128::from(self.probe_full_bw) * 5 {
                            self.probe_full_bw = measured;
                            self.probe_plateau = 0;
                        } else {
                            self.probe_plateau = self.probe_plateau.saturating_add(1);
                        }
                    }
                }
            }
            self.advance_probe(now, in_flight, round_start, congestion_lost != 0);
        }
        if expired && self.probe_rtt_stamp != now && sample.is_some() && self.mode != Mode::ProbeRtt {
            self.prior_cwnd = self.cwnd;
            self.mode = Mode::ProbeRtt;
            self.probe_done = None;
            self.probe_min = None;
        }
        let floor = 4 * self.mtu;
        if self.mode == Mode::ProbeRtt {
            if in_flight <= self.probe_rtt_cwnd() && self.probe_done.is_none() {
                self.probe_min = None;
                self.probe_done = Some((
                    now.checked_add(PROBE_RTT_TIME).ok_or(Error::Clock)?,
                    self.round,
                ));
            }
            if let Some((end, round)) = self.probe_done {
                if now >= end && self.round > round && self.probe_min.is_some() {
                    self.min_rtt = self.probe_min.take();
                    self.min_stamp = now;
                    self.probe_rtt_stamp = now;
                    self.cwnd = self.cwnd.max(self.prior_cwnd);
                    self.probe_done = None;
                    if self.full_pipe {
                        self.enter_probe_bw(now);
                    } else {
                        self.mode = Mode::Startup;
                    }
                }
            }
        }
        if self
            .recovery_until
            .is_some_and(|boundary| highest.is_some_and(|n| n > boundary))
        {
            self.recovery_until = None;
        }
        if congestion_lost != 0 {
            self.recovery_until = self.last_sent;
            self.cwnd = self.cwnd.saturating_sub(congestion_lost).max(floor);
        }
        let target = self.target_cwnd();
        self.cwnd = if self.mode == Mode::ProbeRtt {
            self.probe_rtt_cwnd().min(target)
        } else if self.full_pipe {
            self.cwnd
                .saturating_add(outcome.acknowledged_bytes)
                .min(target)
                .max(floor)
        } else if self.cwnd < target {
            self.cwnd
                .saturating_add(outcome.acknowledged_bytes)
                .min(MAX_CWND)
        } else {
            self.cwnd
        };
        if self.full_pipe { self.cwnd = self.cwnd.min(target); }
        if self.recovery_until.is_some() && self.mode != Mode::ProbeRtt {
            // Packet conservation during recovery, within the model's
            // independently computed bounds; PTO remains a separate exception.
            self.cwnd = self.cwnd.max(in_flight.saturating_add(outcome.acknowledged_bytes).max(floor)).min(target);
        }
        Ok(())
    }

    fn probe_rtt_cwnd(&self) -> u64 { (self.bdp() / 2).clamp(4 * self.mtu, MAX_CWND) }

    fn longterm_limit(&self) -> u64 {
        let bound = self.inflight_longterm.unwrap_or(MAX_CWND);
        if self.mode == Mode::ProbeRtt || (self.mode == Mode::ProbeBw && self.phase == ProbePhase::Cruise) {
            if self.inflight_longterm.is_some() { return (bound.saturating_mul(85) / 100).max(4 * self.mtu); }
        }
        bound
    }

    fn target_cwnd(&self) -> u64 {
        let bdp = self.bdp();
        let base = if self.mode == Mode::ProbeBw && self.phase == ProbePhase::Up {
            bdp.saturating_mul(9) / 4
        } else if self.mode == Mode::ProbeRtt { bdp / 2 } else { bdp.saturating_mul(2) };
        let extra = if self.mode == Mode::ProbeRtt { 0 } else { self.extra_acked.iter().map(|(_, v)| *v).max().unwrap_or(0) };
        let short = if self.is_probing() { MAX_CWND } else { self.loss_ceiling.unwrap_or(MAX_CWND) };
        base.saturating_add(extra).max(4 * self.mtu)
            .min(self.longterm_limit()).min(short).clamp(4 * self.mtu, MAX_CWND)
    }

    fn update_ack_aggregation(&mut self, now: Instant, acked: u64) {
        if acked == 0 || self.effective_bw() == 0 { return; }
        let expected = (u128::from(self.effective_bw()) * now.saturating_duration_since(self.ack_epoch).as_nanos() / 1_000_000_000).min(u128::from(u64::MAX)) as u64;
        if self.ack_epoch_bytes <= expected {
            self.ack_epoch = now;
            self.ack_epoch_bytes = acked;
        } else {
            self.ack_epoch_bytes = self.ack_epoch_bytes.saturating_add(acked);
        }
        let expected = if self.ack_epoch == now { 0 } else { expected };
        let extra = self.ack_epoch_bytes.saturating_sub(expected).min(self.cwnd).min(self.bandwidth() / 10);
        if let Some((round, value)) = self.extra_acked.back_mut() {
            if *round == self.round { *value = (*value).max(extra); return; }
        }
        self.extra_acked.push_back((self.round, extra));
    }

    fn bound_bandwidth(&mut self) {
        let bw = self.bandwidth();
        if bw != 0 {
            let old = self.bandwidth_cap.unwrap_or(bw);
            self.bandwidth_cap = Some((old.saturating_mul(7) / 10).max(self.bw_latest).max(1).min(bw));
        }
    }

    fn set_phase(&mut self, phase: ProbePhase, now: Instant) {
        if self.phase == ProbePhase::Up && phase == ProbePhase::Down && self.cycle_nonlimited {
            self.cycle = self.cycle.saturating_add(1);
            let cycle = self.cycle;
            self.bandwidth.retain(|(old, _)| cycle.saturating_sub(*old) < 2);
            self.cycle_nonlimited = false;
        }
        self.phase = phase;
        self.phase_at = now;
        self.phase_round = self.round;
        if phase == ProbePhase::Down {
            // Randomize the next probe wait across flows without relying on
            // a global clock, with a conservative bounded RNG failure value.
            use ring::rand::{SecureRandom, SystemRandom};
            let mut random = [0; 2];
            let jitter = if SystemRandom::new().fill(&mut random).is_ok() {
                u16::from_ne_bytes(random) as u64 % 1001
            } else { 500 };
            self.probe_wait = Duration::from_millis(2000 + jitter);
        }
        if phase == ProbePhase::Refill {
            self.bandwidth_cap = None;
            self.loss_ceiling = None;
        }
        if phase == ProbePhase::Up {
            self.probe_up_rounds = 0;
            self.probe_up_acked = 0;
            self.probe_full_bw = self.bandwidth();
            self.probe_plateau = 0;
        }
    }

    fn advance_probe(&mut self, now: Instant, in_flight: u64, round_start: bool, lost: bool) {
        let elapsed = now.saturating_duration_since(self.phase_at);
        let new_round = round_start && self.round > self.phase_round;
        if self.phase == ProbePhase::Up && !lost {
            if let Some(limit) = self.inflight_longterm.as_mut() {
                let divisor = 1u64 << self.probe_up_rounds.min(16);
                let step = (self.cwnd / divisor).max(self.mtu);
                let count = self.probe_up_acked / step;
                self.probe_up_acked %= step;
                *limit = limit.saturating_add(count.saturating_mul(self.mtu)).min(MAX_CWND);
            }
            if new_round { self.probe_up_rounds = self.probe_up_rounds.saturating_add(1); }
        }
        let headroom = self.inflight_longterm.map_or(MAX_CWND, |v| (v * 85 / 100).max(4 * self.mtu));
        match self.phase {
            ProbePhase::Down if in_flight <= self.bdp() && in_flight <= headroom => self.set_phase(ProbePhase::Cruise, now),
            ProbePhase::Cruise if new_round && !lost && (elapsed >= self.probe_wait || self.round.saturating_sub(self.phase_round) >= (self.bdp() / self.mtu).clamp(2, 63)) => self.set_phase(ProbePhase::Refill, now),
            ProbePhase::Refill if lost => self.set_phase(ProbePhase::Down, now),
            ProbePhase::Refill if new_round => self.set_phase(ProbePhase::Up, now),
            ProbePhase::Up if lost || self.probe_plateau >= 3 || (new_round && elapsed >= self.rtt() && in_flight >= self.bdp().saturating_mul(5) / 4) => self.set_phase(ProbePhase::Down, now),
            _ => {}
        }
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.set_phase(ProbePhase::Down, now);
    }
}

fn rate(bytes: u64, elapsed: Duration) -> u64 {
    ((u128::from(bytes) * 1_000_000_000) / elapsed.as_nanos().max(1)).min(u128::from(MAX_RATE))
        as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_core::loss::Sent;

    fn packet(number: u64, at: Instant) -> Sent {
        Sent {
            number,
            at,
            bytes: 1200,
            ack_eliciting: true,
            in_flight: true,
            frames: vec![],
        }
    }
    fn ack(bbr: &mut Bbr, number: u64, at: Instant, elapsed: Duration, app_limited: bool) {
        bbr.sent(number, 1200, at, 0, app_limited).unwrap();
        let outcome = Outcome {
            acknowledged: vec![packet(number, at)],
            acknowledged_bytes: 1200,
            rtt_sample: Some(elapsed),
            ..Outcome::default()
        };
        bbr.feedback(&outcome, at + elapsed, 0).unwrap();
    }

    #[test]
    fn delivery_rate_startup_drain_and_app_limited_filter() {
        let start = Instant::now();
        let rtt = Duration::from_millis(100);
        let mut bbr = Bbr::new(1200, start).unwrap();
        assert_eq!(bbr.mode(), Mode::Startup);
        assert!(bbr.pacing_rate() > 0);
        for n in 0..4 {
            ack(&mut bbr, n, start + rtt * (n as u32 * 2), rtt, false);
        }
        assert_eq!(bbr.bandwidth(), 12_000);
        assert_eq!(bbr.min_rtt(), Some(rtt));
        assert_eq!(bbr.mode(), Mode::ProbeBw);
        ack(&mut bbr, 4, start + Duration::from_secs(1), rtt * 2, true);
        assert_eq!(bbr.bandwidth(), 12_000);
        assert!(bbr.cwnd() >= 4800);
        assert!(bbr.pacing_interval(1200) > Duration::ZERO);
    }

    #[test]
    fn four_probe_phases_and_ecn_bound_pacing_once_per_round() {
        let now = Instant::now();
        let mut b = Bbr::new(1200, now).unwrap();
        b.full_pipe = true;
        b.bandwidth.push_back((0, 120_000));
        b.min_rtt = Some(Duration::from_millis(100));
        b.enter_probe_bw(now);
        assert_eq!(b.phase, ProbePhase::Down);
        b.advance_probe(now, 0, false, false);
        assert_eq!(b.phase, ProbePhase::Cruise);
        let refill = now + b.probe_wait;
        b.round += 1;
        b.advance_probe(refill, 0, true, false);
        assert_eq!(b.phase, ProbePhase::Refill);
        b.round += 1;
        b.advance_probe(refill + Duration::from_millis(100), 0, true, false);
        assert_eq!(b.phase, ProbePhase::Up);
        let rate = b.pacing_rate();
        b.ecn_congestion(refill + Duration::from_millis(200));
        assert_eq!(b.phase, ProbePhase::Down);
        assert!(b.pacing_rate() < rate);
        let cwnd = b.cwnd();
        b.ecn_congestion(refill + Duration::from_millis(201));
        assert_eq!(b.cwnd(), cwnd);
        b.persistent_congestion(refill + Duration::from_secs(1));
        assert_eq!(b.cwnd(), 4800);
        assert_eq!(b.loss_ceiling, Some(4800));
    }

    #[test]
    fn application_limited_probe_does_not_age_out_bandwidth() {
        let now = Instant::now();
        let mut b = Bbr::new(1200, now).unwrap();
        b.bandwidth.push_back((0, 100_000));
        b.mode = Mode::ProbeBw;
        for _ in 0..4 {
            b.set_phase(ProbePhase::Up, now);
            b.set_phase(ProbePhase::Down, now);
        }
        assert_eq!(b.bandwidth(), 100_000);
        assert_eq!(b.cycle, 0);
        b.set_phase(ProbePhase::Up, now);
        b.cycle_nonlimited = true;
        b.probe_plateau = 3;
        b.advance_probe(now, 0, false, false);
        assert_eq!(b.phase, ProbePhase::Down);
        assert_eq!(b.cycle, 1);
    }

    #[test]
    fn late_ack_counts_delivery_once_without_resurrecting_flight() {
        let now = Instant::now();
        let mut b = Bbr::new(1200, now).unwrap();
        let rtt = Duration::from_millis(100);
        b.sent(0, 1200, now, 0, false).unwrap();
        b.feedback(&Outcome { lost: vec![packet(0, now)], lost_bytes: 1200, ..Outcome::default() }, now + rtt, 0).unwrap();
        assert_eq!(b.delivered, 0);
        let late = Outcome { late_acknowledged: vec![packet(0, now)], ..Outcome::default() };
        b.feedback(&late, now + rtt * 2, 0).unwrap();
        assert_eq!(b.delivered, 1200);
        assert!(b.lost_samples.is_empty());
        b.feedback(&late, now + rtt * 3, 0).unwrap();
        assert_eq!(b.delivered, 1200);
    }

    #[test]
    fn short_term_bounds_reset_on_refill_but_long_term_and_headroom_remain() {
        let now = Instant::now();
        let mut b = Bbr::new(1200, now).unwrap();
        b.full_pipe = true;
        b.bandwidth.push_back((0, 1_200_000));
        b.min_rtt = Some(Duration::from_millis(100));
        b.mode = Mode::ProbeBw;
        b.phase = ProbePhase::Cruise;
        b.bandwidth_cap = Some(600_000);
        b.loss_ceiling = Some(40_000);
        b.inflight_longterm = Some(80_000);
        assert_eq!(b.effective_bw(), 600_000);
        assert_eq!(b.target_cwnd(), 40_000);
        b.set_phase(ProbePhase::Refill, now);
        assert_eq!(b.effective_bw(), 1_200_000);
        assert_eq!(b.loss_ceiling, None);
        assert_eq!(b.target_cwnd(), 80_000);
        b.set_phase(ProbePhase::Cruise, now);
        assert_eq!(b.target_cwnd(), 68_000);
        assert_eq!(b.probe_rtt_cwnd(), 60_000);
    }

    #[test]
    fn loss_does_not_inflate_delivery_and_probe_rtt_completes() {
        let start = Instant::now();
        let rtt = Duration::from_millis(100);
        let mut bbr = Bbr::new(1200, start).unwrap();
        ack(&mut bbr, 0, start, rtt, false);
        let lost_at = start + rtt * 2;
        bbr.sent(1, 1200, lost_at, 0, false).unwrap();
        let outcome = Outcome {
            lost: vec![packet(1, lost_at)],
            lost_bytes: 1200,
            ..Outcome::default()
        };
        bbr.feedback(&outcome, lost_at + rtt, 0).unwrap();
        assert_eq!(bbr.delivered, 1200);
        assert!(bbr.samples.is_empty());
        let probe = start + Duration::from_secs(11);
        ack(&mut bbr, 2, probe, rtt * 2, false);
        assert_eq!(bbr.mode(), Mode::ProbeRtt);
        assert_eq!(bbr.cwnd(), 4800);
        ack(&mut bbr, 3, probe + rtt * 3, rtt * 2, false);
        assert_ne!(bbr.mode(), Mode::ProbeRtt);
        assert_eq!(bbr.min_rtt(), Some(rtt * 2));
    }
}
