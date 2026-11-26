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

#[cfg(test)]
mod tests {
    use super::*;

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
