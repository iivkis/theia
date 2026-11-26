//! SmartTheia v1 framing and per-HTTP-stream state machine.
//! Pure Rust: no network, TLS, async runtime, or global mutable state.
//! One HTTP/2 or HTTP/3 stream carries one independent TCP or UDP tunnel.
use std::net::IpAddr;

pub const HEADER_LEN: usize = 6;
pub const MAX_PAYLOAD: usize = 65_536;
pub const VERSION: u16 = 1;
pub const CAP_PADDING: u32 = 0x1;
pub const MAX_DATAGRAM: usize = 65_507;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    Truncated,
    FrameTooLarge,
    TrailingBytes,
    InvalidFlags,
    UnknownType,
    UnsupportedVersion,
    UnsupportedCapabilities,
    InvalidLength,
    InvalidAddress,
    InvalidCode,
    InvalidTransition,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    General = 1,
    AddressInvalid = 2,
    PolicyDenied = 3,
    DialTimeout = 4,
    DialFailed = 5,
    ResourceLimit = 6,
    UnsupportedVersion = 7,
    ProtocolError = 8,
    Truncated = 9,
}

impl TryFrom<u16> for ErrorCode {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::General,
            2 => Self::AddressInvalid,
            3 => Self::PolicyDenied,
            4 => Self::DialTimeout,
            5 => Self::DialFailed,
            6 => Self::ResourceLimit,
            7 => Self::UnsupportedVersion,
            8 => Self::ProtocolError,
            9 => Self::Truncated,
            _ => return Err(ProtocolError::InvalidCode),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    V4([u8; 4]),
    Dns(String),
    V6([u8; 16]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello {
        version: u16,
        capabilities: u32,
    },
    HelloAck {
        version: u16,
        accepted_capabilities: u32,
    },
    OpenTcp {
        address: Address,
        port: u16,
    },
    OpenUdp {
        address: Address,
        port: u16,
    },
    OpenOk,
    OpenError(ErrorCode),
    Data(Vec<u8>),
    Datagram(Vec<u8>),
    Fin,
    Abort(ErrorCode),
    Padding(Vec<u8>),
}

pub(crate) fn valid_dns(host: &str) -> bool {
    host.len() <= 253
        && !host.is_empty()
        && host.is_ascii()
        && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn validate(frame: &Frame) -> Result<(), ProtocolError> {
    match frame {
        Frame::Hello {
            version,
            capabilities,
        } => {
            if *version != VERSION {
                return Err(ProtocolError::UnsupportedVersion);
            }
            if *capabilities & !CAP_PADDING != 0 {
                return Err(ProtocolError::UnsupportedCapabilities);
            }
        }
        Frame::HelloAck {
            version,
            accepted_capabilities,
        } => {
            if *version != VERSION {
                return Err(ProtocolError::UnsupportedVersion);
            }
            if *accepted_capabilities & !CAP_PADDING != 0 {
                return Err(ProtocolError::UnsupportedCapabilities);
            }
        }
        Frame::OpenTcp { address, port } | Frame::OpenUdp { address, port } => {
            if *port == 0 {
                return Err(ProtocolError::InvalidAddress);
            }
            if let Address::Dns(host) = address {
                if !valid_dns(host) {
                    return Err(ProtocolError::InvalidAddress);
                }
            }
        }
        Frame::Datagram(data) if data.len() > MAX_DATAGRAM => {
            return Err(ProtocolError::FrameTooLarge)
        }
        Frame::Data(data) | Frame::Padding(data) if data.len() > MAX_PAYLOAD => {
            return Err(ProtocolError::FrameTooLarge);
        }
        _ => {}
    }
    Ok(())
}

/// Encode a complete frame, rejecting invalid typed values before any output.
pub fn encode(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
    validate(frame)?;
    let (kind, payload) = match frame {
        Frame::Hello {
            version,
            capabilities,
        } => {
            let mut p = Vec::with_capacity(6);
            p.extend_from_slice(&version.to_be_bytes());
            p.extend_from_slice(&capabilities.to_be_bytes());
            (0x01, p)
        }
        Frame::HelloAck {
            version,
            accepted_capabilities,
        } => {
            let mut p = Vec::with_capacity(6);
            p.extend_from_slice(&version.to_be_bytes());
            p.extend_from_slice(&accepted_capabilities.to_be_bytes());
            (0x02, p)
        }
        Frame::OpenTcp { address, port } | Frame::OpenUdp { address, port } => {
            let mut p = Vec::new();
            let bytes: &[u8] = match address {
                Address::V4(ip) => {
                    p.push(0x01);
                    ip
                }
                Address::Dns(name) => {
                    p.push(0x03);
                    name.as_bytes()
                }
                Address::V6(ip) => {
                    p.push(0x04);
                    ip
                }
            };
            p.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            p.extend_from_slice(bytes);
            p.extend_from_slice(&port.to_be_bytes());
            (
                if matches!(frame, Frame::OpenUdp { .. }) {
                    0x06
                } else {
                    0x03
                },
                p,
            )
        }
        Frame::OpenOk => (0x04, Vec::new()),
        Frame::OpenError(code) => (0x05, (*code as u16).to_be_bytes().to_vec()),
        Frame::Data(bytes) => (0x10, bytes.clone()),
        Frame::Datagram(bytes) => (0x14, bytes.clone()),
        Frame::Fin => (0x11, Vec::new()),
        Frame::Abort(code) => (0x12, (*code as u16).to_be_bytes().to_vec()),
        Frame::Padding(bytes) => (0x13, bytes.clone()),
    };
    if payload.len() > MAX_PAYLOAD {
        return Err(ProtocolError::FrameTooLarge);
    }
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(kind);
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

fn frame_type(kind: u8) -> Result<(), ProtocolError> {
    match kind {
        0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x10 | 0x11 | 0x12 | 0x13 | 0x14 => Ok(()),
        _ => Err(ProtocolError::UnknownType),
    }
}

fn checked_header(header: &[u8]) -> Result<usize, ProtocolError> {
    if header.len() < HEADER_LEN {
        return Err(ProtocolError::Truncated);
    }
    let length = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if length > MAX_PAYLOAD || (header[0] == 0x14 && length > MAX_DATAGRAM) {
        return Err(ProtocolError::FrameTooLarge);
    }
    if header[1] != 0 {
        return Err(ProtocolError::InvalidFlags);
    }
    frame_type(header[0])?;
    Ok(length)
}

/// Decode exactly one complete frame; arbitrary HTTP chunk boundaries belong
/// to the incremental `Decoder`.
pub fn decode(bytes: &[u8]) -> Result<Frame, ProtocolError> {
    let length = checked_header(bytes)?;
    let total = HEADER_LEN + length;
    if bytes.len() < total {
        return Err(ProtocolError::Truncated);
    }
    if bytes.len() > total {
        return Err(ProtocolError::TrailingBytes);
    }
    let p = &bytes[HEADER_LEN..];
    let frame = match bytes[0] {
        0x01 | 0x02 => {
            if p.len() != 6 {
                return Err(ProtocolError::InvalidLength);
            }
            let version = u16::from_be_bytes([p[0], p[1]]);
            let bits = u32::from_be_bytes([p[2], p[3], p[4], p[5]]);
            if bytes[0] == 0x01 {
                Frame::Hello {
                    version,
                    capabilities: bits,
                }
            } else {
                Frame::HelloAck {
                    version,
                    accepted_capabilities: bits,
                }
            }
        }
        0x03 | 0x06 => {
            if p.len() < 5 {
                return Err(ProtocolError::InvalidLength);
            }
            let address_length = u16::from_be_bytes([p[1], p[2]]) as usize;
            if address_length + 5 != p.len() {
                return Err(ProtocolError::InvalidLength);
            }
            let raw = &p[3..3 + address_length];
            let address = match p[0] {
                0x01 if raw.len() == 4 => {
                    let mut ip = [0; 4];
                    ip.copy_from_slice(raw);
                    Address::V4(ip)
                }
                0x03 => {
                    let host =
                        std::str::from_utf8(raw).map_err(|_| ProtocolError::InvalidAddress)?;
                    Address::Dns(host.to_owned())
                }
                0x04 if raw.len() == 16 => {
                    let mut ip = [0; 16];
                    ip.copy_from_slice(raw);
                    Address::V6(ip)
                }
                _ => return Err(ProtocolError::InvalidAddress),
            };
            let port = u16::from_be_bytes([p[p.len() - 2], p[p.len() - 1]]);
            if bytes[0] == 0x06 {
                Frame::OpenUdp { address, port }
            } else {
                Frame::OpenTcp { address, port }
            }
        }
        0x04 => {
            if !p.is_empty() {
                return Err(ProtocolError::InvalidLength);
            }
            Frame::OpenOk
        }
        0x05 | 0x12 => {
            if p.len() != 2 {
                return Err(ProtocolError::InvalidLength);
            }
            let code = ErrorCode::try_from(u16::from_be_bytes([p[0], p[1]]))?;
            if bytes[0] == 0x05 {
                Frame::OpenError(code)
            } else {
                Frame::Abort(code)
            }
        }
        0x10 => Frame::Data(p.to_vec()),
        0x14 => Frame::Datagram(p.to_vec()),
        0x13 => Frame::Padding(p.to_vec()),
        0x11 => {
            if !p.is_empty() {
                return Err(ProtocolError::InvalidLength);
            }
            Frame::Fin
        }
        _ => return Err(ProtocolError::UnknownType),
    };
    validate(&frame)?;
    Ok(frame)
}

/// Keeps at most one partial frame (65,542 bytes); a caller can stream frames
/// directly to an application callback rather than collecting an unbounded
/// number of decoded frames from one large HTTP body chunk.
#[derive(Debug, Default)]
pub struct Decoder {
    partial: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending_len(&self) -> usize {
        self.partial.len()
    }

    pub fn feed_each(
        &mut self,
        mut input: &[u8],
        mut accept: impl FnMut(Frame) -> Result<(), ProtocolError>,
    ) -> Result<(), ProtocolError> {
        while !input.is_empty() {
            let target = if self.partial.len() < HEADER_LEN {
                HEADER_LEN
            } else {
                HEADER_LEN + checked_header(&self.partial)?
            };
            let take = (target - self.partial.len()).min(input.len());
            self.partial.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.partial.len() >= HEADER_LEN {
                let body_len = checked_header(&self.partial)?;
                if self.partial.len() == HEADER_LEN + body_len {
                    let frame = decode(&self.partial)?;
                    self.partial.clear();
                    accept(frame)?;
                }
            }
        }
        Ok(())
    }

    pub fn feed(&mut self, input: &[u8]) -> Result<Vec<Frame>, ProtocolError> {
        let mut frames = Vec::new();
        self.feed_each(input, |frame| {
            frames.push(frame);
            Ok(())
        })?;
        Ok(frames)
    }

    pub fn finish(&self) -> Result<(), ProtocolError> {
        if self.partial.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::Truncated)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Send,
    Receive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Initial,
    NeedHelloAck,
    NeedOpen,
    NeedOpenResult,
    Open,
    Closed,
}

/// One protocol session per HTTP stream. Moving to `Open` is the ONLY
/// authorization for a local proxy to acknowledge a successfully opened TCP
/// tunnel. HTTP 200 or HELLO_ACK alone must never be treated as OPEN_OK.
#[derive(Debug, Clone)]
pub struct Session {
    role: Role,
    phase: Phase,
    offered_capabilities: u32,
    accepted_capabilities: u32,
    sent_fin: bool,
    received_fin: bool,
    udp: bool,
}

impl Session {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            phase: Phase::Initial,
            offered_capabilities: 0,
            accepted_capabilities: 0,
            sent_fin: false,
            received_fin: false,
            udp: false,
        }
    }

    pub fn tunnel_open(&self) -> bool {
        self.phase == Phase::Open
    }

    pub(crate) fn udp(&self) -> bool {
        self.udp
    }

    pub fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }

    pub fn apply(&mut self, direction: Direction, frame: &Frame) -> Result<(), ProtocolError> {
        validate(frame)?;
        if self.is_closed() {
            return Err(ProtocolError::InvalidTransition);
        }
        if matches!(frame, Frame::Padding(_)) {
            return if self.accepted_capabilities & CAP_PADDING != 0 {
                Ok(())
            } else {
                Err(ProtocolError::UnsupportedCapabilities)
            };
        }
        if matches!(frame, Frame::Abort(_)) {
            self.phase = Phase::Closed;
            return Ok(());
        }
        match (self.role, self.phase, direction, frame) {
            (Role::Client, Phase::Initial, Direction::Send, Frame::Hello { capabilities, .. })
            | (
                Role::Server,
                Phase::Initial,
                Direction::Receive,
                Frame::Hello { capabilities, .. },
            ) => {
                self.offered_capabilities = *capabilities;
                self.phase = Phase::NeedHelloAck;
            }
            (
                Role::Client,
                Phase::NeedHelloAck,
                Direction::Receive,
                Frame::HelloAck {
                    accepted_capabilities,
                    ..
                },
            )
            | (
                Role::Server,
                Phase::NeedHelloAck,
                Direction::Send,
                Frame::HelloAck {
                    accepted_capabilities,
                    ..
                },
            ) => {
                if *accepted_capabilities & !self.offered_capabilities != 0 {
                    return Err(ProtocolError::UnsupportedCapabilities);
                }
                self.accepted_capabilities = *accepted_capabilities;
                self.phase = Phase::NeedOpen;
            }
            (
                Role::Client,
                Phase::NeedOpen,
                Direction::Send,
                Frame::OpenTcp { .. } | Frame::OpenUdp { .. },
            )
            | (
                Role::Server,
                Phase::NeedOpen,
                Direction::Receive,
                Frame::OpenTcp { .. } | Frame::OpenUdp { .. },
            ) => {
                self.udp = matches!(frame, Frame::OpenUdp { .. });
                self.phase = Phase::NeedOpenResult;
            }
            (Role::Client, Phase::NeedOpenResult, Direction::Receive, Frame::OpenOk)
            | (Role::Server, Phase::NeedOpenResult, Direction::Send, Frame::OpenOk) => {
                self.phase = Phase::Open;
            }
            (Role::Client, Phase::NeedOpenResult, Direction::Receive, Frame::OpenError(_))
            | (Role::Server, Phase::NeedOpenResult, Direction::Send, Frame::OpenError(_)) => {
                self.phase = Phase::Closed;
            }
            (_, Phase::Open, Direction::Send, Frame::Data(_)) if !self.udp && !self.sent_fin => {}
            (_, Phase::Open, Direction::Receive, Frame::Data(_))
                if !self.udp && !self.received_fin => {}
            (_, Phase::Open, Direction::Send, Frame::Datagram(_)) if self.udp && !self.sent_fin => {
            }
            (_, Phase::Open, Direction::Receive, Frame::Datagram(_))
                if self.udp && !self.received_fin => {}
            (_, Phase::Open, Direction::Send, Frame::Fin) if !self.sent_fin => {
                self.sent_fin = true;
            }
            (_, Phase::Open, Direction::Receive, Frame::Fin) if !self.received_fin => {
                self.received_fin = true;
            }
            _ => return Err(ProtocolError::InvalidTransition),
        }
        if self.sent_fin && self.received_fin {
            self.phase = Phase::Closed;
        }
        Ok(())
    }

    /// Transport EOF is valid only after both FINs or a terminal
    /// OPEN_ERROR/ABORT; a mid-handshake or half-closed EOF is truncated.
    pub fn finish(&self) -> Result<(), ProtocolError> {
        if self.is_closed() {
            Ok(())
        } else {
            Err(ProtocolError::Truncated)
        }
    }
}

#[cfg(test)]
mod udp_tests {
    use super::*;
    #[test]
    fn udp_wire_and_fsm_are_distinct() {
        let open = Frame::OpenUdp {
            address: Address::Dns("example.org".into()),
            port: 443,
        };
        for frame in [
            open.clone(),
            Frame::Datagram(vec![]),
            Frame::Datagram(vec![1; MAX_DATAGRAM]),
        ] {
            assert_eq!(decode(&encode(&frame).unwrap()).unwrap(), frame);
        }
        assert!(encode(&Frame::Datagram(vec![0; MAX_DATAGRAM + 1])).is_err());
        for (role, hello, ack, send, recv) in [
            (
                Role::Client,
                Direction::Send,
                Direction::Receive,
                Direction::Send,
                Direction::Receive,
            ),
            (
                Role::Server,
                Direction::Receive,
                Direction::Send,
                Direction::Receive,
                Direction::Send,
            ),
        ] {
            let mut s = Session::new(role);
            s.apply(
                hello,
                &Frame::Hello {
                    version: VERSION,
                    capabilities: 0,
                },
            )
            .unwrap();
            s.apply(
                ack,
                &Frame::HelloAck {
                    version: VERSION,
                    accepted_capabilities: 0,
                },
            )
            .unwrap();
            s.apply(send, &open).unwrap();
            assert!(s.apply(send, &Frame::Datagram(vec![1])).is_err());
            s.apply(recv, &Frame::OpenOk).unwrap();
            assert!(s.udp());
            assert!(s.apply(send, &Frame::Data(vec![1])).is_err());
            s.apply(send, &Frame::Datagram(vec![1])).unwrap();
            s.apply(recv, &Frame::Datagram(vec![])).unwrap();
            s.apply(send, &Frame::Fin).unwrap();
            assert!(s.apply(send, &Frame::Datagram(vec![])).is_err());
            s.apply(recv, &Frame::Fin).unwrap();
            s.finish().unwrap();
            let mut tcp = Session::new(role);
            tcp.apply(
                hello,
                &Frame::Hello {
                    version: VERSION,
                    capabilities: 0,
                },
            )
            .unwrap();
            tcp.apply(
                ack,
                &Frame::HelloAck {
                    version: VERSION,
                    accepted_capabilities: 0,
                },
            )
            .unwrap();
            tcp.apply(
                send,
                &Frame::OpenTcp {
                    address: Address::V4([127, 0, 0, 1]),
                    port: 443,
                },
            )
            .unwrap();
            tcp.apply(recv, &Frame::OpenOk).unwrap();
            assert!(tcp.apply(send, &Frame::Datagram(vec![1])).is_err());
        }
    }
}
