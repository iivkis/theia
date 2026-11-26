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
        assert_eq!(
            parts.iter().map(|p| p.bytes.len()).sum::<usize>(),
            bytes.len()
        );
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
