//! Isolated development UDP session for exercising application-space
//! packet protection, STREAM, ACK and retransmission. Loopback only,
//! pre-established TLS keys, fixed CID and peer; NOT a QUIC handshake
//! endpoint, interoperable H3 backend or an admitted Theia user tunnel.
use super::{ack_tx::History, flow::ReceiveFlow, frames::{self, Frame}, packet::{self, Reader, Writer},
    scheduler::Scheduler, send_flow::SendFlow, spaces::Space};
use rustls::quic::{Keys, Secrets};
use super::key_update;
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

enum Protection {
    Fixed { reader: Reader, writer: Writer },
    Rotating { reader: key_update::Receiver, writer: key_update::Sender },
}

pub struct LabSession {
    socket: UdpSocket,
    local_cid: [u8; CID_LEN],
    remote_cid: [u8; CID_LEN],
    protection: Protection,
    acknowledgments: History,
    send: SendFlow,
    receive: ReceiveFlow,
    scheduler: Scheduler,
    closed: bool,
    server: bool,
    confirmed: bool,
}

impl LabSession {
    /// Accept only explicitly provided application keys from a completed TLS
    /// session in a controlled fixture. This function does not verify TLS
    /// completion or identity, so it must not be used for product admission.
    pub async fn connect(socket: UdpSocket, peer: SocketAddr, server: bool,
                         local_cid: [u8; CID_LEN], remote_cid: [u8; CID_LEN],
                         keys: Keys) -> Result<Self, Error> {
        Self::connect_inner(socket, peer, server, local_cid, remote_cid,
            Protection::Fixed { reader: Reader::new(keys.remote), writer: Writer::new(keys.local) }, false).await
    }

    /// Only the UDP handshake driver can construct this session. Server
    /// TLS completion confirms its handshake; the client waits for the
    /// authenticated HANDSHAKE_DONE frame.
    pub(crate) async fn after_handshake(socket: UdpSocket, peer: SocketAddr, server: bool,
                         local_cid: [u8; CID_LEN], remote_cid: [u8; CID_LEN],
                         keys: Keys, secrets: Secrets) -> Result<Self, Error> {
        let mut session = Self::connect_inner(socket, peer, server, local_cid, remote_cid,
            Protection::Rotating { reader: key_update::Receiver::new(keys.remote, secrets.clone()),
                writer: key_update::Sender::new(keys.local, secrets) }, server).await?;
        if server { session.scheduler.enqueue(vec![0x1e]).map_err(Error::Schedule)?; }
        Ok(session)
    }

    async fn connect_inner(socket: UdpSocket, peer: SocketAddr, server: bool,
                         local_cid: [u8; CID_LEN], remote_cid: [u8; CID_LEN],
                         protection: Protection, confirmed: bool) -> Result<Self, Error> {
        let local = socket.local_addr().map_err(Error::Io)?;
        if !local.ip().is_loopback() || !peer.ip().is_loopback() || peer.port() == 0
            || local == peer || local_cid == remote_cid || local_cid == [0; CID_LEN]
            || remote_cid == [0; CID_LEN] { return Err(Error::Scope); }
        socket.connect(peer).await.map_err(Error::Io)?;
        let mut send = SendFlow::new(server, MAX_STREAMS, FLOW_LIMIT, FLOW_LIMIT).map_err(Error::Send)?;
        send.enable_bidi(MAX_STREAMS, MAX_STREAMS).map_err(Error::Send)?;
        let mut receive = ReceiveFlow::new(server, MAX_STREAMS, MAX_STREAMS, FLOW_LIMIT,
            FLOW_LIMIT as usize, FLOW_LIMIT).map_err(Error::Receive)?;
        receive.enable_local_bidi(MAX_STREAMS).map_err(Error::Receive)?;
        Ok(Self { socket, local_cid, remote_cid, protection, acknowledgments: History::default(),
            send, receive,
            scheduler: Scheduler::default(), closed: false, server, confirmed })
    }

    pub fn handshake_confirmed(&self) -> bool { self.confirmed }

    pub fn update_keys(&mut self) -> Result<(), Error> {
        if self.closed { return Err(Error::Closed); }
        match &mut self.protection {
            Protection::Rotating { writer, .. } => writer.update(self.confirmed).map_err(Error::Packet),
            Protection::Fixed { .. } => Err(Error::Protocol),
        }
    }

    pub fn open_uni(&mut self) -> Result<u64, Error> {
        if self.closed { return Err(Error::Closed); }
        self.send.open().map_err(Error::Send)
    }

    pub fn open_bidi(&mut self) -> Result<u64, Error> {
        if self.closed { return Err(Error::Closed); }
        let id = self.send.open_bidi().map_err(Error::Send)?;
        if let Err(e) = self.receive.register_local_bidi(id) {
            self.closed = true;
            return Err(Error::Receive(e));
        }
        Ok(id)
    }

    pub fn queue(&mut self, id: u64, bytes: &[u8], fin: bool) -> Result<(), Error> {
        if self.closed { return Err(Error::Closed); }
        if !self.scheduler.can_queue() { return Err(Error::Schedule(super::scheduler::Error::Limit)); }
        let frame = self.send.encode(id, bytes, fin).map_err(Error::Send)?;
        self.scheduler.enqueue(frame).map_err(Error::Schedule)
    }

    pub fn reset_stream(&mut self, id: u64, code: u64) -> Result<(), Error> {
        if self.closed { return Err(Error::Closed); }
        if !self.scheduler.can_queue() { return Err(Error::Schedule(super::scheduler::Error::Limit)); }
        if let Some(frame) = self.send.reset(id, code).map_err(Error::Send)? {
            self.scheduler.cancel_stream(id);
            if let Err(e) = self.scheduler.enqueue(frame) {
                self.closed = true;
                return Err(Error::Schedule(e));
            }
        }
        Ok(())
    }

    pub fn stop_sending(&mut self, id: u64, code: u64) -> Result<(), Error> {
        if self.closed { return Err(Error::Closed); }
        self.receive.check_stop(id).map_err(Error::Receive)?;
        let mut frame = vec![5];
        for value in [id, code] {
            let mut scratch = [0; 8];
            frame.extend_from_slice(super::wire::encode_varint(value, &mut scratch).ok_or(Error::Protocol)?);
        }
        self.scheduler.enqueue(frame).map_err(Error::Schedule)
    }

    pub fn pending(&self) -> usize { self.scheduler.pending() }

    pub fn read(&mut self, id: u64, bytes: &mut [u8]) -> Result<usize, Error> {
        if self.closed { return Err(Error::Closed); }
        self.receive.read(id, bytes).map_err(Error::Receive)
    }

    /// Explicit window replenishment for streaming fixtures. Reserving queue
    /// capacity first prevents granting credit without its reliable update.
    pub fn read_replenish(&mut self, id: u64, bytes: &mut [u8]) -> Result<usize, Error> {
        if self.closed { return Err(Error::Closed); }
        if !self.scheduler.can_queue_n(2) { return Err(Error::Schedule(super::scheduler::Error::Limit)); }
        let (n, connection, stream) = self.receive.read_replenish(id, bytes).map_err(Error::Receive)?;
        if n != 0 {
            for (ty, numbers) in [(0x10, vec![connection]), (0x11, vec![id, stream])] {
                let mut frame = vec![ty];
                for value in numbers {
                    let mut scratch = [0; 8];
                    frame.extend_from_slice(super::wire::encode_varint(value, &mut scratch).ok_or(Error::Protocol)?);
                }
                if let Err(e) = self.scheduler.enqueue(frame) {
                    self.closed = true;
                    return Err(Error::Schedule(e));
                }
            }
        }
        Ok(n)
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
        let (number, packet) = match &mut self.protection {
            Protection::Fixed { writer, .. } => writer.seal(&header, &payload),
            Protection::Rotating { writer, .. } => writer.seal(&self.remote_cid, &payload),
        }.map_err(Error::Packet)?;
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
        let now = Instant::now();
        let old_key_deadline = now.checked_add(self.scheduler.base_pto().saturating_mul(3)).ok_or(Error::Protocol)?;
        let result = match &mut self.protection {
            Protection::Fixed { reader, .. } => reader.open(&buf[..n], 1 + CID_LEN),
            Protection::Rotating { reader, writer } => {
                match reader.open(&self.local_cid, &buf[..n], now, old_key_deadline, self.confirmed) {
                    Ok(packet) => {
                        writer.respond(reader.generation()).map_err(Error::Packet)?;
                        Ok(packet)
                    }
                    Err(e) => Err(e),
                }
            }
        };
        let opened = match result {
            Ok(p) => p,
            Err(packet::Error::Reserved | packet::Error::Limit) => return Err(Error::Protocol),
            Err(_) => return Ok(false),
        };
        if matches!(&self.protection, Protection::Fixed { .. }) && opened.header[0] & 0x04 != 0 { return Err(Error::Protocol); }
        let parsed = frames::decode(&opened.payload, Space::Application).map_err(|_| Error::Protocol)?;
        let eliciting = parsed.iter().any(|f| !matches!(f, Frame::Ack(_) | Frame::Padding | Frame::Close { .. }));
        let now = Instant::now();
        for frame in parsed {
            match frame {
                Frame::Padding | Frame::Ping => {}
                Frame::Ack(ack) => {
                    self.scheduler.acknowledge(&ack, now).map_err(Error::Schedule)?;
                    if let Protection::Rotating { writer, .. } = &mut self.protection {
                        if let Some(range) = ack.ranges.first() { writer.acknowledged(range.last); }
                    }
                }
                Frame::HandshakeDone if !self.server && matches!(&self.protection, Protection::Rotating { .. }) => {
                    self.confirmed = true;
                }
                Frame::Stream { id, offset, data, fin } => {
                    self.receive.insert(id, offset, data, fin).map_err(Error::Receive)?;
                    if id & 2 == 0 && id & 1 != u64::from(self.server) {
                        self.send.register_peer_bidi(id).map_err(Error::Send)?;
                    }
                }
                Frame::ResetStream { id, code, final_size } => {
                    self.receive.reset(id, final_size, code).map_err(Error::Receive)?;
                    if id & 2 == 0 && id & 1 != u64::from(self.server) {
                        self.send.register_peer_bidi(id).map_err(Error::Send)?;
                    }
                }
                Frame::StopSending { id, code } => self.reset_stream(id, code)?,
                Frame::MaxData(n) => self.send.max_data(n).map_err(Error::Send)?,
                Frame::MaxStreamData { id, limit } => self.send.max_stream_data(id, limit).map_err(Error::Send)?,
                Frame::MaxStreams { bidi: false, limit } => self.send.max_streams(limit.min(MAX_STREAMS)).map_err(Error::Send)?,
                Frame::MaxStreams { bidi: true, limit } => self.send.max_bidi(limit.min(MAX_STREAMS)).map_err(Error::Send)?,
                Frame::Close { .. } => { self.closed = true; return Ok(true); }
                _ => return Err(Error::Protocol),
            }
        }
        self.acknowledgments.record(opened.number, eliciting);
        Ok(true)
    }
}
