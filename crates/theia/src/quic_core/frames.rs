//! Bounded frame decoder for the native QUIC core. Unknown/unsupported
//! frame types fail closed. The endpoint must validate and apply the
//! decoded frames only after packet protection and connection routing.
use super::{
    ack::Ack,
    spaces::Space,
    wire::{varint, MAX_VARINT},
};

const MAX_FRAMES: usize = 256;
const MAX_PACKET: usize = 65527;

#[derive(Debug, Eq, PartialEq)]
pub enum Frame<'a> {
    Padding,
    Ping,
    Ack(Ack),
    Crypto {
        offset: u64,
        data: &'a [u8],
    },
    Stream {
        id: u64,
        offset: u64,
        data: &'a [u8],
        fin: bool,
    },
    ResetStream {
        id: u64,
        code: u64,
        final_size: u64,
    },
    StopSending {
        id: u64,
        code: u64,
    },
    NewToken(&'a [u8]),
    DataBlocked(u64),
    StreamDataBlocked {
        id: u64,
        limit: u64,
    },
    StreamsBlocked {
        bidi: bool,
        limit: u64,
    },
    MaxData(u64),
    MaxStreamData {
        id: u64,
        limit: u64,
    },
    MaxStreams {
        bidi: bool,
        limit: u64,
    },
    Close {
        application: bool,
        code: u64,
        trigger: Option<u64>,
        reason: &'a [u8],
    },
    NewConnectionId {
        sequence: u64,
        retire_prior_to: u64,
        cid: &'a [u8],
        reset_token: [u8; 16],
    },
    RetireConnectionId(u64),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    HandshakeDone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Limit,
    Invalid,
    WrongSpace,
    Unsupported,
}

fn number(bytes: &[u8], at: &mut usize) -> Result<u64, Error> {
    varint(bytes, at).ok_or(Error::Truncated)
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, len: u64) -> Result<&'a [u8], Error> {
    let len = usize::try_from(len).map_err(|_| Error::Limit)?;
    let end = at.checked_add(len).ok_or(Error::Limit)?;
    let result = bytes.get(*at..end).ok_or(Error::Truncated)?;
    *at = end;
    Ok(result)
}

fn data<'a>(bytes: &'a [u8], at: &mut usize, offset: u64, len: u64) -> Result<&'a [u8], Error> {
    if offset.checked_add(len).is_none_or(|end| end > MAX_VARINT) {
        return Err(Error::Limit);
    }
    take(bytes, at, len)
}

pub fn decode(bytes: &[u8], space: Space) -> Result<Vec<Frame<'_>>, Error> {
    if bytes.is_empty() || bytes.len() > MAX_PACKET {
        return Err(Error::Limit);
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if out.len() == MAX_FRAMES {
            return Err(Error::Limit);
        }
        let start = at;
        let ty = number(bytes, &mut at)?;
        // RFC 9000 requires minimal encoding of frame types.
        let minimal = match ty {
            0..=63 => 1,
            64..=16383 => 2,
            16384..=1073741823 => 4,
            _ => 8,
        };
        if at - start != minimal {
            return Err(Error::Invalid);
        }
        if space != Space::Application && !matches!(ty, 0 | 1 | 2 | 3 | 6 | 0x1c) {
            return Err(Error::WrongSpace);
        }
        let frame = match ty {
            0 => {
                while bytes.get(at) == Some(&0) {
                    at += 1;
                }
                Frame::Padding
            }
            1 => Frame::Ping,
            2 | 3 => Frame::Ack(Ack::decode(bytes, &mut at, ty == 3).ok_or(Error::Invalid)?),
            4 => Frame::ResetStream {
                id: number(bytes, &mut at)?,
                code: number(bytes, &mut at)?,
                final_size: number(bytes, &mut at)?,
            },
            5 => Frame::StopSending {
                id: number(bytes, &mut at)?,
                code: number(bytes, &mut at)?,
            },
            6 => {
                let offset = number(bytes, &mut at)?;
                let len = number(bytes, &mut at)?;
                Frame::Crypto {
                    offset,
                    data: data(bytes, &mut at, offset, len)?,
                }
            }
            7 => {
                let len = number(bytes, &mut at)?;
                if len == 0 {
                    return Err(Error::Invalid);
                }
                Frame::NewToken(take(bytes, &mut at, len)?)
            }
            8..=15 => {
                let id = number(bytes, &mut at)?;
                let offset = if ty & 4 != 0 {
                    number(bytes, &mut at)?
                } else {
                    0
                };
                let len = if ty & 2 != 0 {
                    number(bytes, &mut at)?
                } else {
                    (bytes.len() - at) as u64
                };
                Frame::Stream {
                    id,
                    offset,
                    data: data(bytes, &mut at, offset, len)?,
                    fin: ty & 1 != 0,
                }
            }
            0x10 => Frame::MaxData(number(bytes, &mut at)?),
            0x11 => Frame::MaxStreamData {
                id: number(bytes, &mut at)?,
                limit: number(bytes, &mut at)?,
            },
            0x12 | 0x13 => {
                let limit = number(bytes, &mut at)?;
                if limit > 1 << 60 {
                    return Err(Error::Limit);
                }
                Frame::MaxStreams {
                    bidi: ty == 0x12,
                    limit,
                }
            }
            0x14 => Frame::DataBlocked(number(bytes, &mut at)?),
            0x15 => Frame::StreamDataBlocked {
                id: number(bytes, &mut at)?,
                limit: number(bytes, &mut at)?,
            },
            0x16 | 0x17 => {
                let limit = number(bytes, &mut at)?;
                if limit > 1 << 60 {
                    return Err(Error::Limit);
                }
                Frame::StreamsBlocked {
                    bidi: ty == 0x16,
                    limit,
                }
            }
            0x18 => {
                let sequence = number(bytes, &mut at)?;
                let retire_prior_to = number(bytes, &mut at)?;
                if retire_prior_to > sequence {
                    return Err(Error::Invalid);
                }
                let len = u64::from(*take(bytes, &mut at, 1)?.first().ok_or(Error::Truncated)?);
                if !(1..=20).contains(&len) {
                    return Err(Error::Invalid);
                }
                let cid = take(bytes, &mut at, len)?;
                let reset_token = take(bytes, &mut at, 16)?
                    .try_into()
                    .map_err(|_| Error::Truncated)?;
                Frame::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    cid,
                    reset_token,
                }
            }
            0x19 => Frame::RetireConnectionId(number(bytes, &mut at)?),
            0x1a => Frame::PathChallenge(
                take(bytes, &mut at, 8)?
                    .try_into()
                    .map_err(|_| Error::Truncated)?,
            ),
            0x1b => Frame::PathResponse(
                take(bytes, &mut at, 8)?
                    .try_into()
                    .map_err(|_| Error::Truncated)?,
            ),
            0x1c | 0x1d => {
                let code = number(bytes, &mut at)?;
                let trigger = if ty == 0x1c {
                    Some(number(bytes, &mut at)?)
                } else {
                    None
                };
                let len = number(bytes, &mut at)?;
                Frame::Close {
                    application: ty == 0x1d,
                    code,
                    trigger,
                    reason: take(bytes, &mut at, len)?,
                }
            }
            0x1e => Frame::HandshakeDone,
            _ => return Err(Error::Unsupported),
        };
        out.push(frame);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_crypto_and_padding() {
        let bytes = [0, 0, 1, 6, 3, 2, 8, 9, 0, 0];
        assert_eq!(
            decode(&bytes, Space::Initial).unwrap(),
            [
                Frame::Padding,
                Frame::Ping,
                Frame::Crypto {
                    offset: 3,
                    data: &[8, 9]
                },
                Frame::Padding,
            ]
        );
        assert_eq!(
            decode(&[0x0a, 0, 1, 42], Space::Initial),
            Err(Error::WrongSpace)
        );
        assert_eq!(decode(&[0x1e], Space::Handshake), Err(Error::WrongSpace));
        assert_eq!(decode(&[0x40, 1], Space::Initial), Err(Error::Invalid));
    }

    #[test]
    fn stream_and_flow_control() {
        let bytes = [0x0f, 4, 2, 2, 9, 8, 0x10, 10, 0x11, 4, 12, 0x13, 2];
        assert_eq!(
            decode(&bytes, Space::Application).unwrap(),
            [
                Frame::Stream {
                    id: 4,
                    offset: 2,
                    data: &[9, 8],
                    fin: true
                },
                Frame::MaxData(10),
                Frame::MaxStreamData { id: 4, limit: 12 },
                Frame::MaxStreams {
                    bidi: false,
                    limit: 2
                },
            ]
        );
        assert_eq!(
            decode(&[8, 0, 1, 2], Space::Application).unwrap(),
            [Frame::Stream {
                id: 0,
                offset: 0,
                data: &[1, 2],
                fin: false
            }]
        );
        assert_eq!(
            decode(&[0x0a, 0, 2, 1], Space::Application),
            Err(Error::Truncated)
        );
        assert_eq!(decode(&[0xff], Space::Application), Err(Error::Truncated));
        assert_eq!(decode(&[0x1f], Space::Application), Err(Error::Unsupported));
        assert_eq!(
            decode(&vec![1; MAX_FRAMES + 1], Space::Application),
            Err(Error::Limit)
        );
    }
    #[test]
    fn token_and_blocked_hints_are_bounded_and_application_only() {
        let wire = [7, 2, 9, 8, 0x14, 3, 0x15, 4, 5, 0x16, 6, 0x17, 7];
        assert_eq!(
            decode(&wire, Space::Application).unwrap(),
            [
                Frame::NewToken(&[9, 8]),
                Frame::DataBlocked(3),
                Frame::StreamDataBlocked { id: 4, limit: 5 },
                Frame::StreamsBlocked {
                    bidi: true,
                    limit: 6
                },
                Frame::StreamsBlocked {
                    bidi: false,
                    limit: 7
                },
            ]
        );
        assert_eq!(decode(&[7, 0], Space::Application), Err(Error::Invalid));
        assert_eq!(
            decode(&[7, 2, 1], Space::Application),
            Err(Error::Truncated)
        );
        assert_eq!(decode(&[0x14, 0], Space::Handshake), Err(Error::WrongSpace));
        assert_eq!(
            decode(
                &[0x16, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                Space::Application
            ),
            Err(Error::Limit)
        );
    }

    #[test]
    fn cid_and_path_frames() {
        let mut bytes = vec![0x18, 2, 1, 1, 9];
        bytes.extend([4; 16]);
        bytes.extend([0x19, 0, 0x1a]);
        bytes.extend([5; 8]);
        bytes.push(0x1b);
        bytes.extend([6; 8]);
        assert_eq!(
            decode(&bytes, Space::Application).unwrap(),
            [
                Frame::NewConnectionId {
                    sequence: 2,
                    retire_prior_to: 1,
                    cid: &[9],
                    reset_token: [4; 16]
                },
                Frame::RetireConnectionId(0),
                Frame::PathChallenge([5; 8]),
                Frame::PathResponse([6; 8]),
            ]
        );
        assert_eq!(
            decode(&[0x18, 0, 1, 1], Space::Application),
            Err(Error::Invalid)
        );
        assert_eq!(
            decode(&[0x1a, 0], Space::Application),
            Err(Error::Truncated)
        );
        assert_eq!(decode(&[0x1b], Space::Handshake), Err(Error::WrongSpace));
    }
}
