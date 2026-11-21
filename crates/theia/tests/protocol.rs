use theia::protocol::{
    decode, encode, Address, Decoder, Direction, ErrorCode, Frame, ProtocolError, Role, Session,
    HEADER_LEN, MAX_PAYLOAD, VERSION,
};

fn hello() -> Frame {
    Frame::Hello {
        version: VERSION,
        capabilities: 0,
    }
}
fn ack() -> Frame {
    Frame::HelloAck {
        version: VERSION,
        accepted_capabilities: 0,
    }
}
fn open() -> Frame {
    Frame::OpenTcp {
        address: Address::Dns("xn--e1afmkfd.example".to_owned()),
        port: 443,
    }
}
fn establish() -> (Session, Session) {
    let mut client = Session::new(Role::Client);
    let mut server = Session::new(Role::Server);
    for (direction, frame) in [
        (Direction::Send, hello()),
        (Direction::Receive, ack()),
        (Direction::Send, open()),
        (Direction::Receive, Frame::OpenOk),
    ] {
        client.apply(direction, &frame).unwrap();
        server
            .apply(
                match direction {
                    Direction::Send => Direction::Receive,
                    Direction::Receive => Direction::Send,
                },
                &frame,
            )
            .unwrap();
    }
    (client, server)
}

#[test]
fn documented_golden_vectors_are_exact() {
    let fixtures: [(Frame, &[u8]); 4] = [
        (hello(), &[0x01, 0, 0, 0, 0, 6, 0, 1, 0, 0, 0, 0]),
        (ack(), &[0x02, 0, 0, 0, 0, 6, 0, 1, 0, 0, 0, 0]),
        (Frame::Fin, &[0x11, 0, 0, 0, 0, 0]),
        (
            Frame::OpenError(ErrorCode::PolicyDenied),
            &[0x05, 0, 0, 0, 0, 2, 0, 3],
        ),
    ];
    for (frame, bytes) in fixtures {
        assert_eq!(encode(&frame).unwrap(), bytes);
        assert_eq!(decode(bytes).unwrap(), frame);
    }
}

#[test]
fn all_frame_variants_round_trip_and_big_endian_address_length() {
    let frames = [
        hello(),
        ack(),
        open(),
        Frame::OpenTcp {
            address: Address::V4([127, 0, 0, 1]),
            port: 65535,
        },
        Frame::OpenTcp {
            address: Address::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            port: 1,
        },
        Frame::OpenOk,
        Frame::OpenError(ErrorCode::DialTimeout),
        Frame::Data(vec![]),
        Frame::Data(b"hello".to_vec()),
        Frame::Fin,
        Frame::Abort(ErrorCode::ResourceLimit),
    ];
    for frame in frames {
        let wire = encode(&frame).unwrap();
        assert_eq!(decode(&wire).unwrap(), frame);
        assert_eq!(wire[1], 0);
        assert_eq!(
            u32::from_be_bytes([wire[2], wire[3], wire[4], wire[5]]) as usize,
            wire.len() - HEADER_LEN
        );
    }
    let wire = encode(&Frame::OpenTcp {
        address: Address::V4([1, 2, 3, 4]),
        port: 443,
    })
    .unwrap();
    assert_eq!(&wire[HEADER_LEN..], &[1, 0, 4, 1, 2, 3, 4, 1, 187]);
}

#[test]
fn size_boundaries_are_enforced_before_buffering() {
    let small = Frame::Data(Vec::new());
    let maximum = Frame::Data(vec![0x72; MAX_PAYLOAD]);
    assert_eq!(decode(&encode(&small).unwrap()).unwrap(), small);
    let large = encode(&maximum).unwrap();
    assert_eq!(large.len(), MAX_PAYLOAD + HEADER_LEN);
    assert_eq!(decode(&large).unwrap(), maximum);
    assert_eq!(
        encode(&Frame::Data(vec![0; MAX_PAYLOAD + 1])),
        Err(ProtocolError::FrameTooLarge)
    );
    let oversized = [0x10, 0, 0, 1, 0, 1];
    assert_eq!(decode(&oversized), Err(ProtocolError::FrameTooLarge));
    let mut decoder = Decoder::new();
    assert_eq!(decoder.feed(&oversized), Err(ProtocolError::FrameTooLarge));
    assert_eq!(decoder.pending_len(), HEADER_LEN);
}

#[test]
fn stream_decoder_accepts_every_split_and_multiple_coalesced_frames() {
    let frames = [
        hello(),
        ack(),
        open(),
        Frame::OpenOk,
        Frame::Data(vec![8; 1024]),
        Frame::Fin,
    ];
    let mut wire = Vec::new();
    for frame in &frames {
        wire.extend(encode(frame).unwrap());
    }
    for split in 0..=wire.len() {
        let mut dec = Decoder::new();
        let mut received = dec.feed(&wire[..split]).unwrap();
        received.extend(dec.feed(&wire[split..]).unwrap());
        dec.finish().unwrap();
        assert_eq!(received, frames, "split at {split}");
    }
    let mut one_byte_at_a_time = Decoder::new();
    let mut frames_seen = Vec::new();
    for chunk in wire.chunks(1) {
        one_byte_at_a_time
            .feed_each(chunk, |f| {
                frames_seen.push(f);
                Ok(())
            })
            .unwrap();
        assert!(one_byte_at_a_time.pending_len() <= MAX_PAYLOAD + HEADER_LEN);
    }
    one_byte_at_a_time.finish().unwrap();
    assert_eq!(frames_seen, frames);
}

#[test]
fn malformed_payloads_flags_version_and_types_are_rejected() {
    let bad: [(Vec<u8>, ProtocolError); 13] = [
        (
            vec![0x01, 1, 0, 0, 0, 6, 0, 1, 0, 0, 0, 0],
            ProtocolError::InvalidFlags,
        ),
        (vec![0xff, 0, 0, 0, 0, 0], ProtocolError::UnknownType),
        (
            vec![0x01, 0, 0, 0, 0, 6, 0, 2, 0, 0, 0, 0],
            ProtocolError::UnsupportedVersion,
        ),
        (
            vec![0x02, 0, 0, 0, 0, 6, 0, 1, 0, 0, 0, 1],
            ProtocolError::UnsupportedCapabilities,
        ),
        (
            vec![0x01, 0, 0, 0, 0, 5, 0, 1, 0, 0, 0],
            ProtocolError::InvalidLength,
        ),
        (vec![0x04, 0, 0, 0, 0, 1, 0], ProtocolError::InvalidLength),
        (vec![0x05, 0, 0, 0, 0, 2, 0, 0], ProtocolError::InvalidCode),
        (vec![0x11, 0, 0, 0, 0, 1, 0], ProtocolError::InvalidLength),
        (
            vec![0x03, 0, 0, 0, 0, 5, 1, 0, 0, 0, 80],
            ProtocolError::InvalidAddress,
        ),
        (
            vec![0x03, 0, 0, 0, 0, 6, 3, 0, 1, 0xff, 0, 80],
            ProtocolError::InvalidAddress,
        ),
        (
            vec![0x03, 0, 0, 0, 0, 6, 3, 0, 1, b'a', 0, 0],
            ProtocolError::InvalidAddress,
        ),
        (vec![0x10, 0, 0, 0, 0, 2, 0], ProtocolError::Truncated),
        (vec![0x11, 0, 0, 0, 0, 0, 0], ProtocolError::TrailingBytes),
    ];
    for (wire, expected) in bad {
        assert_eq!(decode(&wire), Err(expected), "{wire:?}");
    }
    for name in [
        "",
        "bad..example",
        "-bad.com",
        "bad-.com",
        "example/path",
        "💀.com",
    ] {
        assert_eq!(
            encode(&Frame::OpenTcp {
                address: Address::Dns(name.into()),
                port: 443,
            }),
            Err(ProtocolError::InvalidAddress),
            "{name}"
        );
    }
    assert_eq!(decode(&[0x01]), Err(ProtocolError::Truncated));
}

#[test]
fn eof_in_partial_frame_or_handshake_is_truncated() {
    let mut dec = Decoder::new();
    dec.feed(&[0x01, 0, 0]).unwrap();
    assert_eq!(dec.finish(), Err(ProtocolError::Truncated));
    let mut initial = Session::new(Role::Client);
    assert_eq!(initial.finish(), Err(ProtocolError::Truncated));
    initial.apply(Direction::Send, &hello()).unwrap();
    assert_eq!(initial.finish(), Err(ProtocolError::Truncated));
}

#[test]
fn local_success_is_gated_on_open_ok_not_http_or_hello_ack() {
    let mut client = Session::new(Role::Client);
    let mut server = Session::new(Role::Server);
    assert!(!client.tunnel_open());
    assert_eq!(
        client.apply(Direction::Receive, &Frame::OpenOk),
        Err(ProtocolError::InvalidTransition)
    );
    client.apply(Direction::Send, &hello()).unwrap();
    server.apply(Direction::Receive, &hello()).unwrap();
    server.apply(Direction::Send, &ack()).unwrap();
    client.apply(Direction::Receive, &ack()).unwrap();
    assert!(!client.tunnel_open());
    assert_eq!(
        client.apply(Direction::Receive, &Frame::Data(vec![1])),
        Err(ProtocolError::InvalidTransition)
    );
    client.apply(Direction::Send, &open()).unwrap();
    server.apply(Direction::Receive, &open()).unwrap();
    assert!(!client.tunnel_open());
    server.apply(Direction::Send, &Frame::OpenOk).unwrap();
    client.apply(Direction::Receive, &Frame::OpenOk).unwrap();
    assert!(client.tunnel_open());
    assert!(server.tunnel_open());
}

#[test]
fn full_duplex_half_close_then_both_fin_and_drain() {
    let (mut client, mut server) = establish();
    client.apply(Direction::Send, &Frame::Fin).unwrap();
    server.apply(Direction::Receive, &Frame::Fin).unwrap();
    assert!(client.tunnel_open());
    assert_eq!(
        client.apply(Direction::Send, &Frame::Data(vec![3])),
        Err(ProtocolError::InvalidTransition)
    );
    assert_eq!(
        client.apply(Direction::Send, &Frame::Fin),
        Err(ProtocolError::InvalidTransition)
    );
    client
        .apply(Direction::Receive, &Frame::Data(vec![4]))
        .unwrap();
    server
        .apply(Direction::Send, &Frame::Data(vec![4]))
        .unwrap();
    server.apply(Direction::Send, &Frame::Fin).unwrap();
    client.apply(Direction::Receive, &Frame::Fin).unwrap();
    assert!(client.is_closed());
    assert!(server.is_closed());
    assert_eq!(client.finish(), Ok(()));
    assert_eq!(server.finish(), Ok(()));
    assert_eq!(
        client.apply(Direction::Receive, &Frame::Data(vec![])),
        Err(ProtocolError::InvalidTransition)
    );
}

#[test]
fn open_error_and_abort_are_terminal_and_never_open_tunnel() {
    let mut client = Session::new(Role::Client);
    client.apply(Direction::Send, &hello()).unwrap();
    client.apply(Direction::Receive, &ack()).unwrap();
    client.apply(Direction::Send, &open()).unwrap();
    client
        .apply(
            Direction::Receive,
            &Frame::OpenError(ErrorCode::PolicyDenied),
        )
        .unwrap();
    assert!(!client.tunnel_open());
    assert!(client.is_closed());
    assert!(client.finish().is_ok());
    assert_eq!(
        client.apply(Direction::Receive, &Frame::OpenOk),
        Err(ProtocolError::InvalidTransition)
    );
    let (mut client, mut server) = establish();
    client
        .apply(Direction::Send, &Frame::Abort(ErrorCode::General))
        .unwrap();
    server
        .apply(Direction::Receive, &Frame::Abort(ErrorCode::General))
        .unwrap();
    assert!(client.is_closed() && server.is_closed());
    assert_eq!(
        client.apply(Direction::Send, &Frame::Abort(ErrorCode::General)),
        Err(ProtocolError::InvalidTransition)
    );
}

#[test]
fn invalid_transitions_do_not_advance_session() {
    let mut client = Session::new(Role::Client);
    assert_eq!(
        client.apply(Direction::Send, &Frame::Data(vec![1])),
        Err(ProtocolError::InvalidTransition)
    );
    client.apply(Direction::Send, &hello()).unwrap();
    assert_eq!(
        client.apply(Direction::Send, &hello()),
        Err(ProtocolError::InvalidTransition)
    );
    client.apply(Direction::Receive, &ack()).unwrap();
    assert_eq!(
        client.apply(Direction::Receive, &Frame::OpenOk),
        Err(ProtocolError::InvalidTransition)
    );
    client.apply(Direction::Send, &open()).unwrap();
    assert_eq!(
        client.apply(Direction::Send, &open()),
        Err(ProtocolError::InvalidTransition)
    );
    client.apply(Direction::Receive, &Frame::OpenOk).unwrap();
    assert!(client.tunnel_open());
}

#[test]
fn deterministic_random_chunks_never_panic_and_bound_partial_memory() {
    let mut seed: u64 = 0x06e1_02d9_8baf_41c3;
    for _ in 0..512 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let size = ((seed >> 21) % 90_000) as usize;
        let mut bytes = Vec::with_capacity(size);
        for _ in 0..size {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes.push((seed >> 32) as u8);
        }
        let _ = decode(&bytes);
        let mut decoder = Decoder::new();
        for chunk in bytes.chunks(137) {
            if decoder.feed_each(chunk, |_| Ok(())).is_err() {
                break;
            }
            assert!(decoder.pending_len() <= HEADER_LEN + MAX_PAYLOAD);
        }
    }
}
