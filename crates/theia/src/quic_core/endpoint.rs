//! Isolated development UDP session for exercising application-space
//! packet protection, STREAM, ACK and retransmission. Loopback only,
//! pre-established TLS keys, fixed CID, bounded same-IP rebinding; NOT a QUIC handshake
//! endpoint, interoperable H3 backend or an admitted Theia user tunnel.
use super::{ack_tx::History, flow::ReceiveFlow, frames::{self, Frame}, packet::{self, Reader, Writer},
    scheduler::Scheduler, send_flow::SendFlow, spaces::Space};
use rustls::quic::{Keys, Secrets};
use super::{key_update, lifecycle::{Shutdown, ShutdownPhase}, path::Paths};
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
    paths: Paths,
    local_cid: [u8; CID_LEN],
    remote_cid: [u8; CID_LEN],
    protection: Option<Protection>,
    acknowledgments: History,
    send: SendFlow,
    receive: ReceiveFlow,
    scheduler: Scheduler,
    closed: bool,
    shutdown: Shutdown,
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
            Protection::Fixed { reader: Reader::new(keys.remote), writer: Writer::new(keys.local) }, false)
    }

    /// Only the UDP handshake driver can construct this session. Server
    /// TLS completion confirms its handshake; the client waits for the
    /// authenticated HANDSHAKE_DONE frame.
    pub(crate) async fn after_handshake(socket: UdpSocket, peer: SocketAddr, server: bool,
                         local_cid: [u8; CID_LEN], remote_cid: [u8; CID_LEN],
                         keys: Keys, secrets: Secrets) -> Result<Self, Error> {
        let mut session = Self::connect_inner(socket, peer, server, local_cid, remote_cid,
            Protection::Rotating { reader: key_update::Receiver::new(keys.remote, secrets.clone()),
                writer: key_update::Sender::new(keys.local, secrets) }, server)?;
        // Application-space native laboratory defaults to BBR; the
        // fixed-key codec fixture keeps the CUBIC scheduler for comparison.
        session.scheduler = Scheduler::with_bbr(Instant::now());
        if server { session.scheduler.enqueue(vec![0x1e]).map_err(Error::Schedule)?; }
        Ok(session)
    }

    fn connect_inner(socket: UdpSocket, peer: SocketAddr, server: bool,
                         local_cid: [u8; CID_LEN], remote_cid: [u8; CID_LEN],
                         protection: Protection, confirmed: bool) -> Result<Self, Error> {
        let local = socket.local_addr().map_err(Error::Io)?;
        if !local.ip().is_loopback() || !peer.ip().is_loopback() || peer.port() == 0
            || local == peer || local_cid == remote_cid || local_cid == [0; CID_LEN]
            || remote_cid == [0; CID_LEN] { return Err(Error::Scope); }
        if socket.peer_addr().is_ok() { return Err(Error::Scope); }
        let mut send = SendFlow::new(server, MAX_STREAMS, FLOW_LIMIT, FLOW_LIMIT).map_err(Error::Send)?;
        send.enable_bidi(MAX_STREAMS, MAX_STREAMS).map_err(Error::Send)?;
        let mut receive = ReceiveFlow::new(server, MAX_STREAMS, MAX_STREAMS, FLOW_LIMIT,
            FLOW_LIMIT as usize, FLOW_LIMIT).map_err(Error::Receive)?;
        receive.enable_local_bidi(MAX_STREAMS).map_err(Error::Receive)?;
        Ok(Self { socket, paths: Paths::new_validated(peer), local_cid, remote_cid, protection: Some(protection), acknowledgments: History::default(),
            send, receive,
            scheduler: Scheduler::default(), closed: false, shutdown: Shutdown::default(), server, confirmed })
    }

    pub fn handshake_confirmed(&self) -> bool { self.confirmed }

    pub fn peer_addr(&self) -> SocketAddr { self.paths.active() }

    /// Controlled NAT-rebinding fixture: replace only the client's UDP
    /// port on the same loopback IP. No CID rotation or cross-IP migration.
    /// Existing streams and cryptographic packet numbers remain intact.
    pub async fn rebind(&mut self, socket: UdpSocket, now: Instant) -> Result<(), Error> {
        if self.server || !self.confirmed || !self.active() { return Err(Error::Scope); }
        let previous = self.socket.local_addr().map_err(Error::Io)?;
        let next = socket.local_addr().map_err(Error::Io)?;
        if !next.ip().is_loopback() || next.ip() != previous.ip()
            || next == previous || next == self.paths.active() || socket.peer_addr().is_ok()
            || !self.scheduler.can_send_path() { return Err(Error::Scope); }
        self.socket = socket;
        let peer = self.paths.active();
        if let Err(e) = self.send_path(peer, &[1], now).await {
            self.abort();
            return Err(e);
        }
        Ok(())
    }

    async fn send_path(&mut self, peer: SocketAddr, frame: &[u8], now: Instant) -> Result<(), Error> {
        if !self.scheduler.can_send_path() { return Err(Error::Protocol); }
        let mut payload = frame.to_vec();
        // Fixed four-byte PN and the 16-byte AEAD tag used by this fixture.
        payload.resize(MTU - 1 - CID_LEN - 4 - 16, 0);
        let (number, packet) = self.seal(&payload)?;
        self.scheduler.record_path(number, packet.len(), now).map_err(Error::Schedule)?;
        if self.socket.send_to(&packet, peer).await.map_err(Error::Io)? != packet.len() {
            return Err(Error::Protocol);
        }
        Ok(())
    }

    pub fn update_keys(&mut self) -> Result<(), Error> {
        if !self.active() { return Err(Error::Closed); }
        match self.protection.as_mut().ok_or(Error::Closed)? {
            Protection::Rotating { writer, .. } => writer.update(self.confirmed).map_err(Error::Packet),
            Protection::Fixed { .. } => Err(Error::Protocol),
        }
    }

    pub fn open_uni(&mut self) -> Result<u64, Error> {
        if !self.active() { return Err(Error::Closed); }
        self.send.open().map_err(Error::Send)
    }

    pub fn open_bidi(&mut self) -> Result<u64, Error> {
        if !self.active() { return Err(Error::Closed); }
        let id = self.send.open_bidi().map_err(Error::Send)?;
        if let Err(e) = self.receive.register_local_bidi(id) {
            self.abort();
            return Err(Error::Receive(e));
        }
        Ok(id)
    }

    pub fn queue(&mut self, id: u64, bytes: &[u8], fin: bool) -> Result<(), Error> {
        if !self.active() { return Err(Error::Closed); }
        if !self.scheduler.can_queue() { return Err(Error::Schedule(super::scheduler::Error::Limit)); }
        let frame = self.send.encode(id, bytes, fin).map_err(Error::Send)?;
        self.scheduler.enqueue(frame).map_err(Error::Schedule)
    }

    pub fn reset_stream(&mut self, id: u64, code: u64) -> Result<(), Error> {
        if !self.active() { return Err(Error::Closed); }
        if !self.scheduler.can_queue() { return Err(Error::Schedule(super::scheduler::Error::Limit)); }
        if let Some(frame) = self.send.reset(id, code).map_err(Error::Send)? {
            self.scheduler.cancel_stream(id);
            if let Err(e) = self.scheduler.enqueue(frame) {
                self.abort();
                return Err(Error::Schedule(e));
            }
        }
        Ok(())
    }

    pub fn stop_sending(&mut self, id: u64, code: u64) -> Result<(), Error> {
        if !self.active() { return Err(Error::Closed); }
        self.receive.check_stop(id).map_err(Error::Receive)?;
        let mut frame = vec![5];
        for value in [id, code] {
            let mut scratch = [0; 8];
            frame.extend_from_slice(super::wire::encode_varint(value, &mut scratch).ok_or(Error::Protocol)?);
        }
        self.scheduler.enqueue(frame).map_err(Error::Schedule)
    }

    pub fn pending(&self) -> usize { if self.active() { self.scheduler.pending() } else { 0 } }

    pub fn read(&mut self, id: u64, bytes: &mut [u8]) -> Result<usize, Error> {
        if !self.active() { return Err(Error::Closed); }
        self.receive.read(id, bytes).map_err(Error::Receive)
    }

    /// Explicit window replenishment for streaming fixtures. Reserving queue
    /// capacity first prevents granting credit without its reliable update.
    pub fn read_replenish(&mut self, id: u64, bytes: &mut [u8]) -> Result<usize, Error> {
        if !self.active() { return Err(Error::Closed); }
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
                    self.abort();
                    return Err(Error::Schedule(e));
                }
            }
        }
        Ok(n)
    }

    pub fn finished(&self, id: u64) -> bool { self.active() && self.receive.finished(id) }

    fn active(&self) -> bool { !self.closed && self.shutdown.is_open() }

    fn abort(&mut self) {
        self.closed = true;
        self.shutdown.abort();
        self.protection = None;
    }

    /// No new streams, data or key changes after local closing begins.
    pub fn close(&mut self, code: u64, now: Instant) -> Result<(), Error> {
        if !self.active() { return Err(Error::Closed); }
        self.shutdown.local(now, self.scheduler.base_pto(), code).map_err(|_| Error::Protocol)
    }

    pub fn shutdown_phase(&self) -> ShutdownPhase { self.shutdown.phase() }

    fn tick(&mut self, now: Instant) {
        self.paths.expire(now);
        if self.shutdown.expire(now) {
            self.abort();
        } else if let Some(Protection::Rotating { reader, .. }) = &mut self.protection {
            reader.expire(now);
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        let old_keys = match &self.protection {
            Some(Protection::Rotating { reader, .. }) => reader.retirement_deadline(),
            _ => None,
        };
        let recovery = if self.active() { self.scheduler.deadline() } else { None };
        [self.shutdown.deadline(), old_keys, recovery, self.paths.deadline()].into_iter().flatten().min()
    }

    /// Send at most one datagram per call, ACKs first. The caller owns the
    /// drive loop and timer. Any uncertain send outcome is terminal.
    pub async fn flush(&mut self, now: Instant) -> Result<bool, Error> {
        if self.closed { return Err(Error::Closed); }
        self.tick(now);
        if self.closed || self.shutdown.phase() == ShutdownPhase::Draining { return Ok(false); }
        let result = if self.shutdown.phase() == ShutdownPhase::Closing {
            self.flush_close(now).await
        } else {
            self.flush_inner(now).await
        };
        if result.is_err() { self.abort(); }
        result
    }

    async fn flush_close(&mut self, now: Instant) -> Result<bool, Error> {
        let Some(code) = self.shutdown.take_close(now, self.scheduler.base_pto()) else { return Ok(false); };
        let mut payload = vec![0x1d];
        let mut scratch = [0; 8];
        payload.extend_from_slice(super::wire::encode_varint(code, &mut scratch).ok_or(Error::Protocol)?);
        payload.push(0); // empty reason
        // CONNECTION_CLOSE is not ACK-eliciting. Once closing, no normal
        // recovery or application frames are driven, but PN never resets.
        let (_, packet) = self.seal(&payload)?;
        if self.socket.send_to(&packet, self.paths.active()).await.map_err(Error::Io)? != packet.len() { return Err(Error::Protocol); }
        Ok(true)
    }

    fn seal(&mut self, payload: &[u8]) -> Result<(u64, Vec<u8>), Error> {
        let mut header = vec![0x43];
        header.extend_from_slice(&self.remote_cid);
        header.extend_from_slice(&[0; 4]);
        match self.protection.as_mut().ok_or(Error::Closed)? {
            Protection::Fixed { writer, .. } => writer.seal(&header, payload),
            Protection::Rotating { writer, .. } => writer.seal(&self.remote_cid, payload),
        }.map_err(Error::Packet)
    }

    async fn flush_inner(&mut self, now: Instant) -> Result<bool, Error> {
        self.scheduler.on_timer(now).map_err(Error::Schedule)?;
        let ack = self.acknowledgments.encode();
        let (payload, frame) = if let Some(ack) = ack {
            (ack, None)
        } else if let Some((id, frame, probe)) = self.scheduler.candidate(now).map_err(Error::Schedule)? {
            (frame, Some((id, probe)))
        } else { return Ok(false); };
        let (number, packet) = self.seal(&payload)?;
        self.scheduler.record(number, packet.len(), frame, now).map_err(Error::Schedule)?;
        if self.socket.send_to(&packet, self.paths.active()).await.map_err(Error::Io)? != packet.len() {
            return Err(Error::Protocol);
        }
        if frame.is_none() { self.acknowledgments.sent(); }
        Ok(true)
    }

    /// Read at most one datagram. Malformed unauthenticated packets are
    /// dropped; authenticated protocol errors terminate this lab session.
    pub async fn recv(&mut self, wait: Duration) -> Result<bool, Error> {
        if self.closed { return Err(Error::Closed); }
        let now = Instant::now();
        self.tick(now);
        if self.closed { return Ok(false); }
        let wait = self.shutdown.deadline().map_or(wait, |at| wait.min(at.saturating_duration_since(now)));
        let result = self.recv_inner(wait).await;
        if result.is_err() { self.abort(); } else { self.tick(Instant::now()); }
        result
    }

    async fn recv_inner(&mut self, wait: Duration) -> Result<bool, Error> {
        let mut buf = [0; MTU + 1];
        let (n, source) = match tokio::time::timeout(wait, self.socket.recv_from(&mut buf)).await {
            Ok(result) => result.map_err(Error::Io)?,
            Err(_) => return Ok(false),
        };
        if self.shutdown.phase() == ShutdownPhase::Draining { return Ok(false); }
        let new_path = source != self.paths.active();
        if new_path && (!self.server || !self.confirmed || !self.active()
            || source.ip() != self.paths.active().ip()) { return Ok(false); }
        if n > MTU || n < 1 + CID_LEN + 4 + 16 || buf[0] & 0xc0 != 0x40
            || buf[1..1 + CID_LEN] != self.local_cid { return Ok(false); }
        let now = Instant::now();
        let old_key_deadline = now.checked_add(self.scheduler.base_pto().saturating_mul(3)).ok_or(Error::Protocol)?;
        let result = match self.protection.as_mut().ok_or(Error::Closed)? {
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
        if matches!(&self.protection, Some(Protection::Fixed { .. })) && opened.header[0] & 0x04 != 0 { return Err(Error::Protocol); }
        let parsed = frames::decode(&opened.payload, Space::Application).map_err(|_| Error::Protocol)?;
        if new_path {
            // Only authenticated 1-RTT packets can establish a candidate.
            // Never apply stream data, ACKs or close from an unvalidated path.
            let Ok(challenge) = self.paths.begin(source, n as u64, now) else { return Ok(false); };
            let probing = parsed.iter().all(|f| matches!(f, Frame::Padding | Frame::Ping
                | Frame::PathChallenge(_) | Frame::PathResponse(_)));
            if !probing || !parsed.iter().any(|f| matches!(f, Frame::PathResponse(value)
                if self.paths.response(source, *value, now))) {
                if self.scheduler.can_send_path() && self.paths.reserve_challenge(
                    source, MTU as u64, now, self.scheduler.base_pto()) {
                    let mut frame = vec![0x1a];
                    frame.extend_from_slice(&challenge);
                    self.send_path(source, &frame, now).await?;
                }
                return Ok(false);
            }
            // Same-IP NAT rebinding may retain congestion and RTT state.
            // Cross-IP path changes require independent recovery state.
        }
        if parsed.iter().any(|frame| matches!(frame, Frame::Close { .. })) {
            self.shutdown.peer(now, self.scheduler.base_pto()).map_err(|_| Error::Protocol)?;
            // Draining is silent. Drop keys now; retain the connection
            // object/route until the shutdown deadline.
            self.protection = None;
            return Ok(true);
        }
        if self.shutdown.phase() == ShutdownPhase::Closing {
            self.shutdown.authenticated_packet(now);
            return Ok(true);
        }
        let eliciting = parsed.iter().any(|f| !matches!(f, Frame::Ack(_) | Frame::Padding | Frame::Close { .. }));
        let now = Instant::now();
        for frame in parsed {
            match frame {
                Frame::Padding | Frame::Ping | Frame::PathResponse(_) => {}
                Frame::PathChallenge(value) if self.confirmed => {
                    if self.scheduler.can_send_path() {
                        let mut response = vec![0x1b];
                        response.extend_from_slice(&value);
                        self.send_path(source, &response, now).await?;
                    }
                }
                Frame::Ack(ack) => {
                    self.scheduler.acknowledge(&ack, now).map_err(Error::Schedule)?;
                    if let Some(Protection::Rotating { writer, .. }) = &mut self.protection {
                        if let Some(range) = ack.ranges.first() { writer.acknowledged(range.last); }
                    }
                }
                Frame::HandshakeDone if !self.server && matches!(&self.protection, Some(Protection::Rotating { .. })) => {
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
                _ => return Err(Error::Protocol),
            }
        }
        self.acknowledgments.record(opened.number, eliciting);
        Ok(true)
    }
}
