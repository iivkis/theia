//! Experimental BBR-family controller for the native QUIC laboratory.
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
const HIGH_GAIN: f64 = 2.885;
const BW_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

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
    bandwidth: VecDeque<(u64, u64)>,
    round: u64,
    next_round: u64,
    min_rtt: Option<Duration>,
    min_stamp: Instant,
    full_bw: u64,
    plateau: u8,
    full_pipe: bool,
    cycle: usize,
    cycle_at: Instant,
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
            bandwidth: VecDeque::new(),
            round: 0,
            next_round: 0,
            min_rtt: None,
            min_stamp: now,
            full_bw: 0,
            plateau: 0,
            full_pipe: false,
            cycle: 0,
            cycle_at: now,
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
    }

    /// Conservative CE response, at most once per packet-timed round.
    /// This does not claim BBRv3 ECN/L4S conformance.
    pub(crate) fn ecn_congestion(&mut self) {
        if self.last_ecn_round == Some(self.round) { return; }
        self.last_ecn_round = Some(self.round);
        let bound = (self.cwnd.saturating_mul(7) / 10).max(4 * self.mtu);
        self.loss_ceiling = Some(self.loss_ceiling.map_or(bound, |old| old.min(bound)));
        self.cwnd = self.cwnd.min(bound);
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

    fn bdp(&self) -> u64 {
        let bw = self.bandwidth();
        if bw == 0 {
            return self.cwnd;
        }
        ((u128::from(bw) * self.rtt().as_nanos()) / 1_000_000_000).min(u128::from(MAX_CWND)) as u64
    }

    fn gain(&self) -> f64 {
        match self.mode {
            Mode::Startup => HIGH_GAIN,
            Mode::Drain => 1.0 / HIGH_GAIN,
            Mode::ProbeBw => BW_GAINS[self.cycle],
            Mode::ProbeRtt => 1.0,
        }
    }

    pub fn pacing_rate(&self) -> u64 {
        let bw = self.bandwidth();
        let base = if bw == 0 {
            rate(self.cwnd, self.rtt())
        } else {
            bw
        };
        ((base as f64 * self.gain()) as u64).clamp(1, MAX_RATE)
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
            self.first_sent_at = now;
            self.delivered_at = now;
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
                app_limited: self.delivered < self.app_limited_until,
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
        let mut sample: Option<Sample> = None;
        let mut highest = None;
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
        for packet in &outcome.lost {
            if packet.in_flight && self.samples.remove(&packet.number).is_none() {
                return Err(Error::Accounting);
            }
        }
        if outcome.acknowledged_bytes != 0 && sample.is_none() {
            return Err(Error::Accounting);
        }
        let mut round_start = false;
        let mut nonlimited_rate = None;
        if let Some(sample) = sample {
            self.delivered = self
                .delivered
                .checked_add(outcome.acknowledged_bytes)
                .ok_or(Error::Limit)?;
            self.delivered_at = now;
            if sample.delivered >= self.next_round {
                self.round = self.round.checked_add(1).ok_or(Error::Limit)?;
                self.next_round = self.delivered;
                round_start = true;
            }
            self.bandwidth
                .retain(|(round, _)| self.round.saturating_sub(*round) < 10);
            let elapsed = now
                .duration_since(sample.delivered_at)
                .max(sample.sent_at.duration_since(sample.first_sent_at));
            if !elapsed.is_zero() {
                let delivered = self
                    .delivered
                    .checked_sub(sample.delivered)
                    .ok_or(Error::Accounting)?;
                let measured = rate(delivered, elapsed);
                if !sample.app_limited || measured >= self.bandwidth() {
                    if let Some((round, best)) = self.bandwidth.back_mut() {
                        if *round == self.round {
                            *best = (*best).max(measured);
                        } else {
                            self.bandwidth.push_back((self.round, measured));
                        }
                    } else {
                        self.bandwidth.push_back((self.round, measured));
                    }
                }
                if !sample.app_limited {
                    nonlimited_rate = Some(measured);
                }
            }
        }
        let probe_lost = outcome.lost.iter().filter(|p| p.frames.contains(&super::loss::FrameRef::MtuProbe)).map(|p| u64::from(p.bytes)).sum::<u64>();
        let congestion_lost = outcome.lost_bytes.saturating_sub(probe_lost);
        // A bounded loss signal complements the delivery-rate estimate. It is
        // deliberately conservative and does not claim the full v3 model.
        self.round_acked = self.round_acked.saturating_add(outcome.acknowledged_bytes);
        self.round_lost = self.round_lost.saturating_add(congestion_lost);
        let floor = 4 * self.mtu;
        let observed = self.round_acked.saturating_add(self.round_lost);
        if observed >= 4 * self.mtu && u128::from(self.round_lost) * 50 > u128::from(observed) {
            let bound = (self.cwnd.saturating_mul(7) / 10).max(floor);
            self.loss_ceiling = Some(self.loss_ceiling.map_or(bound, |old| old.min(bound)));
            if self.mode == Mode::Startup {
                self.full_pipe = true;
                self.mode = Mode::Drain;
            }
            self.round_acked = 0;
            self.round_lost = 0;
        } else if round_start {
            if self.round_lost == 0 {
                if let Some(old) = self.loss_ceiling {
                    self.loss_ceiling = Some(old.saturating_add(self.mtu).min(MAX_CWND));
                }
            }
            self.round_acked = 0;
            self.round_lost = 0;
        }
        let expired = now.saturating_duration_since(self.min_stamp) >= MIN_RTT_TTL;
        if let Some(rtt) = outcome.rtt_sample.map(|r| r.max(Duration::from_micros(1))) {
            if self.min_rtt.is_none_or(|old| rtt <= old) {
                self.min_rtt = Some(rtt);
                self.min_stamp = now;
            }
            if self.mode == Mode::ProbeRtt {
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
        } else if self.mode == Mode::ProbeBw
            && round_start
            && now.saturating_duration_since(self.cycle_at) >= self.rtt()
        {
            self.cycle = (self.cycle + 1) % BW_GAINS.len();
            self.cycle_at = now;
        }
        if expired && self.min_stamp != now && sample.is_some() && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.probe_done = None;
            self.probe_min = None;
        }
        let floor = 4 * self.mtu;
        if self.mode == Mode::ProbeRtt {
            if in_flight <= floor && self.probe_done.is_none() {
                self.probe_done = Some((
                    now.checked_add(PROBE_RTT_TIME).ok_or(Error::Clock)?,
                    self.round,
                ));
            }
            if let Some((end, round)) = self.probe_done {
                if now >= end && self.round > round && self.probe_min.is_some() {
                    self.min_rtt = self.probe_min.take();
                    self.min_stamp = now;
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
        let target = self
            .bdp()
            .saturating_mul(2)
            .clamp(floor, MAX_CWND)
            .min(self.loss_ceiling.unwrap_or(MAX_CWND));
        self.cwnd = if self.mode == Mode::ProbeRtt {
            floor
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
        if self.recovery_until.is_some() {
            self.cwnd = self.cwnd.min(
                in_flight
                    .saturating_add(outcome.acknowledged_bytes)
                    .max(floor),
            );
        }
        Ok(())
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        // Start in neutral cruise. A future production controller should
        // randomize the probe epoch and implement the current v3 loss bounds.
        self.cycle = 2;
        self.cycle_at = now;
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
