//! Bounded QUIC Initial observation, never rewrites ciphertext.
use crate::reality_quic_wire::{self as wire, Flight, Inspection, Kind};
pub(super) enum Result {
    Pending,
    Hello {
        name: String,
        version: u32,
        h3: bool,
    },
    Unsupported,
}
#[derive(Default)]
pub(super) struct Observer {
    flight: Option<Flight>,
    done: bool,
    count: usize,
    bytes: usize,
}
impl Observer {
    pub(super) fn observe(&mut self, data: &[u8]) -> Result {
        if self.done {
            return Result::Unsupported;
        }
        self.count += 1;
        self.bytes = self.bytes.saturating_add(data.len());
        if self.count > 8
            || self.bytes > 64 * 1024
            || data.len() < wire::MIN_INITIAL
            || data.len() > wire::MAX_DATAGRAM
        {
            self.done = true;
            self.flight = None;
            return Result::Unsupported;
        }
        let Some(header) = wire::long(data) else {
            self.done = true;
            self.flight = None;
            return Result::Unsupported;
        };
        if header.kind != Kind::Initial || !wire::coherent_datagram(data) {
            self.done = true;
            self.flight = None;
            return Result::Unsupported;
        }
        if self.flight.is_none() {
            self.flight = Flight::new(&header);
        }
        let Some(flight) = self.flight.as_mut() else {
            self.done = true;
            return Result::Unsupported;
        };
        match flight.inspect(data) {
            Inspection::Pending => Result::Pending,
            Inspection::Hello(message) => {
                self.done = true;
                self.flight = None;
                match super::tls::hello_metadata(&message) {
                    Some((name, h3)) => Result::Hello {
                        name,
                        version: header.version,
                        h3,
                    },
                    None => Result::Unsupported,
                }
            }
            Inspection::Invalid => {
                self.done = true;
                self.flight = None;
                Result::Unsupported
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_initial_v1_v2_and_tampering() {
        for version in [wire::V1, wire::V2] {
            let packet =
                wire::test_initial(version, &super::super::tls::fixture("example.org")[5..]);
            let mut observer = Observer::default();
            assert!(
                matches!(observer.observe(&packet), Result::Hello { version: v, .. } if v == version)
            );
            assert!(matches!(observer.observe(&packet), Result::Unsupported));
            let mut bad = packet;
            *bad.last_mut().unwrap() ^= 1;
            assert!(matches!(
                Observer::default().observe(&bad),
                Result::Unsupported
            ));
        }
    }
}
