//! Isolated development UDP session for exercising application-space
//! packet protection, STREAM, ACK and retransmission. Loopback only,
//! pre-established TLS keys, fixed CID and peer; NOT a QUIC handshake
//! endpoint, interoperable H3 backend or an admitted Theia user tunnel.
use super::{ack_tx::History, flow::ReceiveFlow, frames::{self, Frame}, packet::{self, Reader, Writer},
    scheduler::Scheduler, send_flow::SendFlow, spaces::Space};
use rustls::quic::Keys;
use std::{io, net::SocketAddr, time::{Duration, Instant}};
use tokio::net::UdpSocket;

const CID_LEN: usize = 8;
const MTU: usize = 1200;
const MAX_STREAMS: u64 = 8;
const FLOW_LIMIT: u64 = 64 * 1024;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Scope,
    Protocol,
    Closed,
    Packet(packet::Error),
    Send(super::send_flow::Error),
    Receive(super::flow::Error),
    Schedule(super::scheduler::Error),
}

pub struct LabSession {
    socket: UdpSocket,
    local_cid: [u8; CID_LEN],
    remote_cid: [u8; CID_LEN],
    reader: Reader,
    writer: Writer,
    acknowledgments: History,
    send: SendFlow,
    receive: ReceiveFlow,
    scheduler: Scheduler,
    closed: bool,
}

impl LabSession {
    /// Accept only explicitly provided application keys from a completed TLS
    /// session in a controlled fixture. This function does not verify TLS
    /// completion or identity, so it must not be used for product admission.
    pub async fn connect(socket: UdpSocket, peer: SocketAddr, server: bool,
                         local_cid: [u8; CID_LEN], remote_cid: [u8; CID_LEN],
                         keys: Keys) -> Result<Self, Error> {
        let local = socket.local_addr().map_err(Error::Io)?;
        if !local.ip().is_loopback() || !peer.ip().is_loopback() || peer.port() == 0
            || local == peer || local_cid == remote_cid || local_cid == [0; CID_LEN]
            || remote_cid == [0; CID_LEN] { return Err(Error::Scope); }
        socket.connect(peer).await.map_err(Error::Io)?;
        Ok(Self { socket, local_cid, remote_cid, reader: Reader::new(keys.remote),
            writer: Writer::new(keys.local), acknowledgments: History::default(),
            send: SendFlow::new(server, MAX_STREAMS, FLOW_LIMIT, FLOW_LIMIT).map_err(Error::Send)?,
            receive: ReceiveFlow::new(server, 0, MAX_STREAMS, FLOW_LIMIT, FLOW_LIMIT as usize, FLOW_LIMIT).map_err(Error::Receive)?,
            scheduler: Scheduler::default(), closed: false })
    }

    pub fn open_uni(&mut self) -> Result<u64, Error> {
        if self.closed { return Err(Error::Closed); }
        self.send.open().map_err(Error::Send)
    }

    pub fn queue(&mut self, id: u64, bytes: &[u8], fin: bool) -> Result<(), Error> {
        if self.closed { return Err(Error::Closed); }
        if !self.scheduler.can_queue() { return Err(Error::Schedule(super::scheduler::Error::Limit)); }
        let frame = self.send.encode(id, bytes, fin).map_err(Error::Send)?;
        self.scheduler.enqueue(frame).map_err(Error::Schedule)
    }

    pub fn pending(&self) -> usize { self.scheduler.pending() }

    pub fn read(&mut self, id: u64, bytes: &mut [u8]) -> Result<usize, Error> {
        if self.closed { return Err(Error::Closed); }
        self.receive.read(id, bytes).map_err(Error::Receive)
    }

    pub fn finished(&self, id: u64) -> bool { !self.closed && self.receive.finished(id) }

    pub fn deadline(&self) -> Option<Instant> { self.scheduler.deadline() }

    /// Send at most one datagram per call, ACKs first. The caller owns the
    /// drive loop and timer. Any uncertain send outcome is terminal.
    pub async fn flush(&mut self, now: Instant) -> Result<bool, Error> {
        if self.closed { return Err(Error::Closed); }
        let result = self.flush_inner(now).await;
        if result.is_err() { self.closed = true; }
        result
    }

    async fn flush_inner(&mut self, now: Instant) -> Result<bool, Error> {
        self.scheduler.on_timer(now).map_err(Error::Schedule)?;
        let ack = self.acknowledgments.encode();
        let (payload, frame) = if let Some(ack) = ack {
            (ack, None)
        } else if let Some((id, frame, probe)) = self.scheduler.candidate(now).map_err(Error::Schedule)? {
            (frame, Some((id, probe)))
        } else { return Ok(false); };
        let mut header = vec![0x43];
        header.extend_from_slice(&self.remote_cid);
        header.extend_from_slice(&[0; 4]);
        let (number, packet) = self.writer.seal(&header, &payload).map_err(Error::Packet)?;
        self.scheduler.record(number, packet.len(), frame, now).map_err(Error::Schedule)?;
        if self.socket.send(&packet).await.map_err(Error::Io)? != packet.len() {
            return Err(Error::Protocol);
        }
        if frame.is_none() { self.acknowledgments.sent(); }
        Ok(true)
    }

    /// Read at most one datagram. Malformed unauthenticated packets are
    /// dropped; authenticated protocol errors terminate this lab session.
    pub async fn recv(&mut self, wait: Duration) -> Result<bool, Error> {
        if self.closed { return Err(Error::Closed); }
        let result = self.recv_inner(wait).await;
        if result.is_err() { self.closed = true; }
        result
    }

    async fn recv_inner(&mut self, wait: Duration) -> Result<bool, Error> {
        let mut buf = [0; MTU + 1];
        let n = match tokio::time::timeout(wait, self.socket.recv(&mut buf)).await {
            Ok(result) => result.map_err(Error::Io)?,
            Err(_) => return Ok(false),
        };
        if n > MTU || n < 1 + CID_LEN + 4 + 16 || buf[0] & 0xc0 != 0x40
            || buf[1..1 + CID_LEN] != self.local_cid { return Ok(false); }
        let opened = match self.reader.open(&buf[..n], 1 + CID_LEN) {
            Ok(p) => p,
            Err(packet::Error::Reserved | packet::Error::Limit) => return Err(Error::Protocol),
            Err(_) => return Ok(false),
        };
        // No key phase changes or negotiated fixed-bit greasing in this fixture.
        if opened.header[0] & 0x04 != 0 { return Err(Error::Protocol); }
        let parsed = frames::decode(&opened.payload, Space::Application).map_err(|_| Error::Protocol)?;
        let eliciting = parsed.iter().any(|f| !matches!(f, Frame::Ack(_) | Frame::Padding | Frame::Close { .. }));
        let now = Instant::now();
        for frame in parsed {
            match frame {
                Frame::Padding | Frame::Ping => {}
                Frame::Ack(ack) => self.scheduler.acknowledge(&ack, now).map_err(Error::Schedule)?,
                Frame::Stream { id, offset, data, fin } if id & 2 != 0 =>
                    self.receive.insert(id, offset, data, fin).map_err(Error::Receive)?,
                Frame::MaxData(n) => self.send.max_data(n).map_err(Error::Send)?,
                Frame::MaxStreamData { id, limit } => self.send.max_stream_data(id, limit).map_err(Error::Send)?,
                Frame::MaxStreams { bidi: false, limit } => self.send.max_streams(limit).map_err(Error::Send)?,
                Frame::Close { .. } => { self.closed = true; return Ok(true); }
                _ => return Err(Error::Protocol),
            }
        }
        self.acknowledgments.record(opened.number, eliciting);
        Ok(true)
    }
}
