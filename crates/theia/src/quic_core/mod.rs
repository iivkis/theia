//! Native QUIC foundation. Not a selectable endpoint until interoperability,
//! security and performance gates pass. Existing H3 remains on Quinn.
#![forbid(unsafe_code)]

pub mod ack;
pub mod ack_tx;
pub mod bbr;
pub mod congestion;
pub mod datagram;
pub mod ecn;
pub mod endpoint;
pub mod flow;
pub mod frames;
pub mod h3_adapter;
pub mod handshake;
pub mod handshake_udp;
pub mod ingress;
pub mod initial;
pub mod key_update;
pub mod lifecycle;
pub mod listener;
pub mod loss;
pub mod negotiation;
pub mod packet;
pub mod parameters;
pub mod path;
pub mod recovery;
pub mod scheduler;
pub mod send_flow;
pub mod spaces;
pub mod stream;
pub mod tls;
pub mod wire;

#[cfg(test)]
mod mutation_tests {
    //! Deterministic parser mutation regressions in the ordinary native test
    //! suite. This is a bounded smoke corpus, not continuous coverage-guided fuzzing.
    use super::{
        ack::Ack,
        datagram, frames,
        ingress::{Action, Ingress},
        initial::Writer,
        parameters::Parameters,
        spaces::Space,
        wire::{self, Version},
    };
    use rustls::Side;

    fn exercise(bytes: &[u8], ingress: &mut Ingress, tick: u64) {
        for space in [Space::Initial, Space::Handshake, Space::Application] {
            let _ = frames::decode(bytes, space);
        }
        for with_ecn in [false, true] {
            let mut pos = 0;
            if Ack::decode(bytes, &mut pos, with_ecn).is_some() {
                assert!(pos <= bytes.len());
            } else {
                assert_eq!(pos, 0);
            }
        }
        if let Ok(parts) = datagram::split(bytes) {
            let consumed = parts.iter().map(|p| p.bytes.len()).sum::<usize>();
            assert!(consumed <= bytes.len());
            assert!(bytes[consumed..].iter().all(|&b| b == 0));
            if consumed < bytes.len() {
                assert_eq!(parts[0].kind, datagram::PacketKind::Initial);
            }
            assert!(parts.iter().all(|p| p.destination == parts[0].destination));
        }
        if let Ok(params) = Parameters::parse(bytes) {
            for id in 0..=0x11 {
                let _ = params.integer(id);
            }
        }
        let mut pos = 0;
        while wire::varint(bytes, &mut pos).is_some() {
            assert!(pos <= bytes.len());
        }
        let peer = "127.0.0.1:12345".parse().unwrap();
        if let Ok(Action::Reply(reply)) = ingress.process(peer, bytes, tick) {
            assert!(!reply.is_empty() && reply.len() <= bytes.len());
        }
    }

    fn next(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    #[test]
    fn bounded_native_parser_corpus() {
        let mut ingress = Ingress::new(8).unwrap();
        let mut seed = 0xd3a5_71c0_9182_55f1;
        let mut corpus = vec![
            vec![0x02, 0, 0, 0, 0],
            vec![0x03, 0, 0, 0, 0, 1, 0, 1],
            vec![0x0f, 4, 0, 2, 9, 8],
            vec![0x18, 1, 0, 8],
            vec![0xff; 64],
            vec![0; 1200],
            vec![1; 257],
        ];
        for version in [Version::V1, Version::V2] {
            let dcid = [3; 8];
            let scid = [4; 8];
            let packet = Writer::new(version, &dcid, Side::Client)
                .unwrap()
                .seal(&dcid, &scid, &[], &[1])
                .unwrap();
            corpus.push(packet);
        }
        let mut tick = 0;
        for original in &corpus {
            for n in 0..=original.len() {
                exercise(&original[..n], &mut ingress, tick);
                tick += 1;
            }
            for i in 0..original.len() {
                let mut mutated = original.clone();
                mutated[i] ^= 0x80;
                exercise(&mutated, &mut ingress, tick);
                tick += 1;
            }
        }
        for _ in 0..4096 {
            let size = (next(&mut seed) % 1400) as usize;
            let bytes: Vec<_> = (0..size).map(|_| next(&mut seed) as u8).collect();
            exercise(&bytes, &mut ingress, tick);
            tick += 1;
        }
    }
}

/// The experimental native transport must never become an externally reachable
/// carrier before independent admission and interoperability acceptance.
pub(crate) fn loopback_pair(local: std::net::SocketAddr, peer: std::net::SocketAddr) -> bool {
    local.ip().is_loopback() && peer.ip().is_loopback() && peer.port() != 0 && local != peer
}

#[cfg(test)]
mod scope_tests {
    use super::loopback_pair;
    #[test]
    fn laboratory_scope_rejects_external_and_invalid_peers() {
        let local = "127.0.0.1:1234".parse().unwrap();
        let peer = "127.0.0.1:4321".parse().unwrap();
        assert!(loopback_pair(local, peer));
        assert!(!loopback_pair(local, local));
        assert!(!loopback_pair(local, "127.0.0.1:0".parse().unwrap()));
        assert!(!loopback_pair(local, "192.0.2.1:443".parse().unwrap()));
        assert!(!loopback_pair("0.0.0.0:1234".parse().unwrap(), peer));
        assert!(loopback_pair(
            "[::1]:1234".parse().unwrap(),
            "[::1]:4321".parse().unwrap()
        ));
    }
}
