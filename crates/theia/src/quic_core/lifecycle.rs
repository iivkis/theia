//! Fail-closed transport lifecycle for the future endpoint. TLS completion,
//! transport parameter validation and Theia admission are distinct events.
//! This state object does not itself establish identity or validate a path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase { Handshaking, TransportReady, Admitted, Closing, Draining, Closed }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { State, Validation }

pub struct Lifecycle {
    phase: Phase,
    handshake_confirmed: bool,
}

impl Default for Lifecycle {
    fn default() -> Self { Self { phase: Phase::Handshaking, handshake_confirmed: false } }
}

impl Lifecycle {
    pub fn phase(&self) -> Phase { self.phase }

    /// Called by the TLS/transport owner only after real TLS completion,
    /// validated peer parameters and the required ALPN/identity checks.
    pub fn transport_ready(&mut self, tls_complete: bool, parameters_valid: bool,
                           identity_valid: bool, alpn_valid: bool) -> Result<(), Error> {
        if self.phase != Phase::Handshaking { return Err(Error::State); }
        if !(tls_complete && parameters_valid && identity_valid && alpn_valid) {
            self.phase = Phase::Closing;
            return Err(Error::Validation);
        }
        self.phase = Phase::TransportReady;
        Ok(())
    }

    pub fn confirm_handshake(&mut self) -> Result<(), Error> {
        if !matches!(self.phase, Phase::TransportReady | Phase::Admitted) { return Err(Error::State); }
        self.handshake_confirmed = true;
        Ok(())
    }

    /// Theia admission/grants are checked by the existing application layer;
    /// transport readiness cannot alone grant a user tunnel.
    pub fn admit(&mut self, authorized: bool) -> Result<(), Error> {
        if self.phase != Phase::TransportReady { return Err(Error::State); }
        if !authorized { self.phase = Phase::Closing; return Err(Error::Validation); }
        self.phase = Phase::Admitted;
        Ok(())
    }

    pub fn can_relay(&self) -> bool { self.phase == Phase::Admitted }
    pub fn handshake_confirmed(&self) -> bool { self.handshake_confirmed }

    pub fn close(&mut self) {
        if matches!(self.phase, Phase::Handshaking | Phase::TransportReady | Phase::Admitted) {
            self.phase = Phase::Closing;
        }
    }

    pub fn peer_closed(&mut self) {
        if self.phase != Phase::Closed { self.phase = Phase::Draining; }
    }

    /// The endpoint owner must enforce the closing/draining deadline.
    pub fn expire(&mut self) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Closing | Phase::Draining) { return Err(Error::State); }
        self.phase = Phase::Closed;
        Ok(())
    }
}

/// Connection shutdown timer for a connection whose application packet
/// keys are installed. Retain the route for at least three base PTOs.
/// Peer close enters silent draining and cannot extend the original timer.
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ShutdownPhase { #[default] Open, Closing, Draining, Closed }

#[derive(Default)]
pub struct Shutdown {
    phase: ShutdownPhase,
    deadline: Option<Instant>,
    next_send: Option<Instant>,
    pending: bool,
    code: u64,
}

impl Shutdown {
    pub fn phase(&self) -> ShutdownPhase { self.phase }
    pub fn deadline(&self) -> Option<Instant> { self.deadline }
    pub fn is_open(&self) -> bool { self.phase == ShutdownPhase::Open }

    fn duration(pto: Duration) -> Duration {
        pto.max(Duration::from_millis(1)).saturating_mul(3)
    }

    pub fn local(&mut self, now: Instant, pto: Duration, code: u64) -> Result<(), Error> {
        if code > super::wire::MAX_VARINT { return Err(Error::Validation); }
        if self.phase != ShutdownPhase::Open { return Err(Error::State); }
        self.deadline = Some(now.checked_add(Self::duration(pto)).ok_or(Error::State)?);
        self.phase = ShutdownPhase::Closing;
        self.pending = true;
        self.code = code;
        Ok(())
    }

    pub fn peer(&mut self, now: Instant, pto: Duration) -> Result<(), Error> {
        match self.phase {
            ShutdownPhase::Open => {
                self.deadline = Some(now.checked_add(Self::duration(pto)).ok_or(Error::State)?);
            }
            ShutdownPhase::Closing => {}
            ShutdownPhase::Draining | ShutdownPhase::Closed => return Ok(()),
        }
        self.phase = ShutdownPhase::Draining;
        self.pending = false;
        self.next_send = None;
        Ok(())
    }

    /// The caller has successfully authenticated a packet, not just parsed
    /// its CID. Limit retransmission of CONNECTION_CLOSE to one per PTO.
    pub fn authenticated_packet(&mut self, now: Instant) {
        if self.phase == ShutdownPhase::Closing
            && self.deadline.is_some_and(|end| now < end)
            && self.next_send.is_none_or(|next| now >= next) {
            self.pending = true;
        }
    }

    pub fn take_close(&mut self, now: Instant, pto: Duration) -> Option<u64> {
        if self.expire(now) || self.phase != ShutdownPhase::Closing || !self.pending {
            return None;
        }
        self.pending = false;
        self.next_send = now.checked_add(pto.max(Duration::from_millis(1)));
        Some(self.code)
    }

    pub fn expire(&mut self, now: Instant) -> bool {
        if self.deadline.is_some_and(|end| now >= end) { self.abort(); }
        self.phase == ShutdownPhase::Closed
    }

    pub fn abort(&mut self) {
        self.phase = ShutdownPhase::Closed;
        self.deadline = None;
        self.next_send = None;
        self.pending = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_draining_and_rate_limited_retransmission() {
        let start = Instant::now();
        let pto = Duration::from_millis(100);
        let mut state = Shutdown::default();
        assert_eq!(state.phase(), ShutdownPhase::Open);
        state.local(start, pto, 42).unwrap();
        assert_eq!(state.deadline(), Some(start + pto * 3));
        assert_eq!(state.take_close(start, pto), Some(42));
        state.authenticated_packet(start + Duration::from_millis(99));
        assert_eq!(state.take_close(start + Duration::from_millis(99), pto), None);
        state.authenticated_packet(start + pto);
        assert_eq!(state.take_close(start + pto, pto), Some(42));
        assert_eq!(state.local(start + pto, pto, 7), Err(Error::State));
        state.peer(start + pto * 2, pto).unwrap();
        assert_eq!(state.phase(), ShutdownPhase::Draining);
        state.authenticated_packet(start + pto * 2);
        assert_eq!(state.take_close(start + pto * 2, pto), None);
        assert!(!state.expire(start + pto * 2));
        assert!(state.expire(start + pto * 3));
        assert_eq!(state.phase(), ShutdownPhase::Closed);
        state.peer(start + pto * 4, pto).unwrap();
        assert_eq!(state.phase(), ShutdownPhase::Closed);
    }

    #[test]
    fn transport_readiness_does_not_grant_admission() {
        let mut l = Lifecycle::default();
        assert!(!l.can_relay());
        assert_eq!(l.admit(true), Err(Error::State));
        assert_eq!(l.confirm_handshake(), Err(Error::State));
        l.transport_ready(true, true, true, true).unwrap();
        assert!(!l.can_relay());
        l.confirm_handshake().unwrap();
        assert!(l.handshake_confirmed());
        l.admit(true).unwrap();
        assert!(l.can_relay());
        l.close();
        assert!(!l.can_relay());
        assert_eq!(l.admit(true), Err(Error::State));
        l.peer_closed();
        l.expire().unwrap();
        l.peer_closed();
        assert_eq!(l.phase(), Phase::Closed);
    }

    #[test]
    fn failures_are_terminal() {
        for values in [(false,true,true,true),(true,false,true,true),(true,true,false,true),(true,true,true,false)] {
            let mut l = Lifecycle::default();
            assert_eq!(l.transport_ready(values.0, values.1, values.2, values.3), Err(Error::Validation));
            assert_eq!(l.transport_ready(true,true,true,true), Err(Error::State));
            assert_eq!(l.phase(), Phase::Closing);
        }
        let mut l = Lifecycle::default();
        l.transport_ready(true,true,true,true).unwrap();
        assert_eq!(l.admit(false), Err(Error::Validation));
        assert!(!l.can_relay());
    }
}
