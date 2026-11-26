//! Isolated development UDP session for exercising application-space
//! packet protection, STREAM, ACK and retransmission. Loopback only,
//! bounded CID rotation and candidate-path validation; not an external
//! QUIC endpoint, interoperable H3 backend or an admitted Theia user tunnel.
use super::listener::SessionIo;
use super::{
    ack_tx::History,
    flow::ReceiveFlow,
    frames::{self, Frame},
    packet::{self, Reader, Writer},
    scheduler::Scheduler,
    send_flow::SendFlow,
    spaces::Space,
};
use super::{
    key_update,
    lifecycle::{Idle, Shutdown, ShutdownPhase},
    path::{ConnectionId, Paths, PeerIds},
};
use rustls::quic::{Keys, Secrets};
use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};
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
    Fixed {
        reader: Reader,
        writer: Writer,
    },
    Rotating {
        reader: Box<key_update::Receiver>,
        writer: key_update::Sender,
    },
}

pub(crate) struct Established {
    pub keys: Keys,
    pub secrets: Secrets,
    pub idle_timeout: Duration,
    pub binding: zeroize::Zeroizing<[u8; 32]>,
    pub peer_limits: super::parameters::Limits,
    pub peer_reset_token: Option<[u8; 16]>,
}

pub struct LabSession {
    socket: SessionIo,
    paths: Paths,
    local_ids: BTreeMap<u64, [u8; CID_LEN]>,
    next_local_sequence: u64,
    peer_cid_limit: usize,
    peer_ids: PeerIds,
    protection: Option<Protection>,
    acknowledgments: History,
    send: SendFlow,
    receive: ReceiveFlow,
    scheduler: Scheduler,
    closed: bool,
    shutdown: Shutdown,
    server: bool,
    confirmed: bool,
    idle: Idle,
    binding: Option<zeroize::Zeroizing<[u8; 32]>>,
    peer_application_close: Option<u64>,
}

impl LabSession {
    /// Accept only explicitly provided application keys from a completed TLS
    /// session in a controlled fixture. This function does not verify TLS
    /// completion or identity, so it must not be used for product admission.
    pub async fn connect(
        socket: UdpSocket,
        peer: SocketAddr,
        server: bool,
        local_cid: [u8; CID_LEN],
        remote_cid: [u8; CID_LEN],
        keys: Keys,
    ) -> Result<Self, Error> {
        Self::connect_inner(
            socket.into(),
            peer,
            server,
            local_cid,
            remote_cid,
            Protection::Fixed {
                reader: Reader::new(keys.remote),
                writer: Writer::new(keys.local),
            },
            false,
        )
    }

    /// Only the UDP handshake driver can construct this session. Server
    /// TLS completion confirms its handshake; the client waits for the
    /// authenticated HANDSHAKE_DONE frame.
    pub(crate) async fn after_handshake(
        socket: SessionIo,
        peer: SocketAddr,
        server: bool,
        local_cid: [u8; CID_LEN],
        remote_cid: [u8; CID_LEN],
        established: Established,
    ) -> Result<Self, Error> {
        let Established {
            keys,
            secrets,
            idle_timeout,
            binding,
            peer_limits,
            peer_reset_token,
        } = established;
        let mut session = Self::connect_inner(
            socket,
            peer,
            server,
            local_cid,
            remote_cid,
            Protection::Rotating {
                reader: Box::new(key_update::Receiver::new(keys.remote, secrets.clone())),
                writer: key_update::Sender::new(keys.local, secrets),
            },
            server,
        )?;
        // Application-space native laboratory defaults to BBR; the
        // fixed-key codec fixture keeps the CUBIC scheduler for comparison.
        session.peer_ids = PeerIds::with_initial(&remote_cid, peer_reset_token, 2).map_err(|_| Error::Protocol)?;
        session.peer_cid_limit = peer_limits.active_cid_limit.min(8) as usize;
        session.send = SendFlow::from_peer(server, peer_limits, MAX_STREAMS).map_err(Error::Send)?;
        session.scheduler = Scheduler::with_bbr(Instant::now());
        session.idle = Idle::new(Instant::now(), idle_timeout);
        session.binding = Some(binding);
        if server {
            session
                .scheduler
                .enqueue(vec![0x1e])
                .map_err(Error::Schedule)?;
        }
        Ok(session)
    }

    fn connect_inner(
        socket: SessionIo,
        peer: SocketAddr,
        server: bool,
        local_cid: [u8; CID_LEN],
        remote_cid: [u8; CID_LEN],
        protection: Protection,
        confirmed: bool,
    ) -> Result<Self, Error> {
        let local = socket.local_addr().map_err(Error::Io)?;
        if !super::loopback_pair(local, peer)
            || local_cid == remote_cid
            || local_cid == [0; CID_LEN]
            || remote_cid == [0; CID_LEN]
        {
            return Err(Error::Scope);
        }
        if socket.peer_addr().is_ok() {
            return Err(Error::Scope);
        }
        let mut send =
            SendFlow::new(server, MAX_STREAMS, FLOW_LIMIT, FLOW_LIMIT).map_err(Error::Send)?;
        send.enable_bidi(MAX_STREAMS, MAX_STREAMS)
            .map_err(Error::Send)?;
        let mut receive = ReceiveFlow::new(
            server,
            MAX_STREAMS,
            MAX_STREAMS,
            FLOW_LIMIT,
            FLOW_LIMIT as usize,
            FLOW_LIMIT,
        )
        .map_err(Error::Receive)?;
        receive
            .enable_local_bidi(MAX_STREAMS)
            .map_err(Error::Receive)?;
        Ok(Self {
            socket,
            paths: Paths::new_validated(peer),
            local_ids: BTreeMap::from([(0, local_cid)]),
            next_local_sequence: 1,
            peer_cid_limit: 2,
            peer_ids: PeerIds::with_initial(&remote_cid, None, 2).map_err(|_| Error::Protocol)?,
            protection: Some(protection),
            acknowledgments: History::default(),
            send,
            receive,
            scheduler: Scheduler::default(),
            closed: false,
            shutdown: Shutdown::default(),
            server,
            confirmed,
            idle: Idle::new(Instant::now(), Duration::from_secs(30)),
            binding: None,
            peer_application_close: None,
        })
    }

    pub fn handshake_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Only TLS-established laboratory sessions have exporter material.
    /// Taking it is not an admission decision; the HTTP layer must verify it.
    pub(crate) fn take_channel_binding(&mut self) -> Option<zeroize::Zeroizing<[u8; 32]>> {
        if self.active() {
            self.binding.take()
        } else {
            None
        }
    }

    pub(crate) fn peer_application_close(&self) -> Option<u64> {
        self.peer_application_close
    }

    pub(crate) fn peer_streams(&self) -> Vec<u64> {
        self.receive.peer_streams()
    }

    pub(crate) fn send_reset_code(&self, id: u64) -> Option<u64> {
        self.send.reset_code(id)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.paths.active()
    }

    /// Advertise one fresh, registered local CID over authenticated 1-RTT.
    /// Registration precedes transmission; never advertise an unroutable alias.
    /// This is still a laboratory operation, not production admission.
    pub async fn advertise_connection_id(&mut self) -> Result<u64, Error> {
        if !self.confirmed || !self.active() || self.local_ids.len() >= self.peer_cid_limit
            || !self.scheduler.can_queue() || self.next_local_sequence > super::wire::MAX_VARINT {
            return Err(Error::Scope);
        }
        let (cid, token) = self.socket.issue_cid().await.map_err(Error::Io)?;
        if cid == [0; CID_LEN] || self.local_ids.values().any(|old| *old == cid) { return Err(Error::Protocol); }
        let sequence = self.next_local_sequence;
        let mut frame = vec![0x18];
        let mut scratch = [0; 8];
        frame.extend_from_slice(super::wire::encode_varint(sequence, &mut scratch).ok_or(Error::Protocol)?);
        frame.extend_from_slice(&[0, CID_LEN as u8]);
        frame.extend_from_slice(&cid);
        frame.extend_from_slice(&token);
        self.scheduler.enqueue(frame).map_err(Error::Schedule)?;
        self.local_ids.insert(sequence, cid);
        self.next_local_sequence += 1;
        Ok(sequence)
    }

    fn queue_retire_cid(&mut self, sequence: u64) -> Result<(), Error> {
        let mut frame = vec![0x19];
        let mut scratch = [0; 8];
        frame.extend_from_slice(super::wire::encode_varint(sequence, &mut scratch).ok_or(Error::Protocol)?);
        self.scheduler.enqueue(frame).map_err(Error::Schedule)
    }

    /// Controlled rebinding: a different loopback IP requires a fresh peer
    /// CID and recovery reset. This does not enable public addresses.
    /// Existing streams and cryptographic packet numbers remain intact.
    pub async fn rebind(&mut self, socket: UdpSocket, now: Instant) -> Result<(), Error> {
        if self.server || !self.confirmed || !self.active() {
            return Err(Error::Scope);
        }
        let previous = self.socket.local_addr().map_err(Error::Io)?;
        let next = socket.local_addr().map_err(Error::Io)?;
        let cross_ip = next.ip() != previous.ip();
        let rotate = self.peer_ids.has_spare();
        if !next.ip().is_loopback()
            || next.is_ipv4() != self.paths.active().is_ipv4()
            || (cross_ip && !rotate)
            || (rotate && !self.scheduler.can_queue())
            || next == previous
            || next == self.paths.active()
            || socket.peer_addr().is_ok()
            || !self.scheduler.can_send_path()
        {
            return Err(Error::Scope);
        }
        if rotate {
            let retired = self.peer_ids.rotate().ok_or(Error::Protocol)?;
            self.queue_retire_cid(retired)?;
        }
        if cross_ip { self.scheduler.restart_path(now); }
        self.socket = socket.into();
        let peer = self.paths.active();
        if let Err(e) = self.send_path(peer, &[1], now).await {
            self.abort();
            return Err(e);
        }
        Ok(())
    }

    async fn send_path(
        &mut self,
        peer: SocketAddr,
        frame: &[u8],
        now: Instant,
    ) -> Result<(), Error> {
        if !self.scheduler.can_send_path() {
            return Err(Error::Protocol);
        }
        let mut payload = frame.to_vec();
        // Fixed four-byte PN and the 16-byte AEAD tag used by this fixture.
        let cid_len = self.peer_ids.current().ok_or(Error::Protocol)?.len();
        payload.resize(MTU - 1 - cid_len - 4 - 16, 0);
        let (number, packet) = self.seal(&payload)?;
        self.scheduler
            .record_path(number, packet.len(), now)
            .map_err(Error::Schedule)?;
        if self
            .socket
            .send_to(&packet, peer)
            .await
            .map_err(Error::Io)?
            != packet.len()
        {
            return Err(Error::Protocol);
        }
        self.idle.sent(now);
        Ok(())
    }

    pub fn update_keys(&mut self) -> Result<(), Error> {
        if !self.active() {
            return Err(Error::Closed);
        }
        match self.protection.as_mut().ok_or(Error::Closed)? {
            Protection::Rotating { writer, .. } => {
                writer.update(self.confirmed).map_err(Error::Packet)
            }
            Protection::Fixed { .. } => Err(Error::Protocol),
        }
    }

    pub fn open_uni(&mut self) -> Result<u64, Error> {
        if !self.active() {
            return Err(Error::Closed);
        }
        self.send.open().map_err(Error::Send)
    }

    pub fn open_bidi(&mut self) -> Result<u64, Error> {
        if !self.active() {
            return Err(Error::Closed);
        }
        if !self.receive.can_open_local_bidi() { return Err(Error::Send(super::send_flow::Error::Limit)); }
        let id = self.send.open_bidi().map_err(Error::Send)?;
        if let Err(e) = self.receive.register_local_bidi(id) {
            self.abort();
            return Err(Error::Receive(e));
        }
        Ok(id)
    }

    pub fn queue(&mut self, id: u64, bytes: &[u8], fin: bool) -> Result<(), Error> {
        if !self.active() {
            return Err(Error::Closed);
        }
        if !self.scheduler.can_queue() {
            return Err(Error::Schedule(super::scheduler::Error::Limit));
        }
        let frame = self.send.encode(id, bytes, fin).map_err(Error::Send)?;
        self.scheduler.enqueue(frame).map_err(Error::Schedule)
    }

    pub fn reset_stream(&mut self, id: u64, code: u64) -> Result<(), Error> {
        if !self.active() {
            return Err(Error::Closed);
        }
        if !self.scheduler.can_queue() {
            return Err(Error::Schedule(super::scheduler::Error::Limit));
        }
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
        if !self.active() {
            return Err(Error::Closed);
        }
        self.receive.check_stop(id).map_err(Error::Receive)?;
        let mut frame = vec![5];
        for value in [id, code] {
            let mut scratch = [0; 8];
            frame.extend_from_slice(
                super::wire::encode_varint(value, &mut scratch).ok_or(Error::Protocol)?,
            );
        }
        self.scheduler.enqueue(frame).map_err(Error::Schedule)?;
        self.receive.abandon(id).map_err(Error::Receive)
    }

    pub(crate) fn send_capacity(&self, id: u64) -> usize { self.send.available(id) }

    pub(crate) fn lifetime_exhausted(&self, bidi: bool) -> bool { self.send.lifetime_exhausted(bidi) }

    /// A peer stream earns a new stream ID only after both relevant halves
    /// terminate and reliable STREAM/RESET frames are acknowledged.
    pub(crate) fn retire_stream(&mut self, id: u64, tx: bool, rx: bool) -> Result<bool, Error> {
        if tx && (!self.send.terminal(id) || self.scheduler.stream_pending(id)) { return Ok(false); }
        if !rx { return Ok(true); }
        if !self.scheduler.can_queue_n(2) { return Ok(false); }
        let Some((grant, data)) = self.receive.retire(id) else { return Ok(false); };
        if let Some(limit) = grant {
            let bidi = id & 2 == 0;
            if bidi { self.send.grant_peer_bidi(limit); }
            self.queue_credit(if bidi { 0x12 } else { 0x13 }, limit)?;
        }
        if let Some(limit) = data { self.queue_credit(0x10, limit)?; }
        Ok(true)
    }

    fn queue_credit(&mut self, ty: u8, limit: u64) -> Result<(), Error> {
        let mut frame = vec![ty];
        let mut scratch = [0; 8];
        frame.extend_from_slice(super::wire::encode_varint(limit, &mut scratch).ok_or(Error::Protocol)?);
        self.scheduler.enqueue(frame).map_err(Error::Schedule)
    }

    pub fn pending(&self) -> usize {
        if self.active() {
            self.scheduler.pending()
        } else {
            0
        }
    }

    pub fn read(&mut self, id: u64, bytes: &mut [u8]) -> Result<usize, Error> {
        if !self.active() {
            return Err(Error::Closed);
        }
        self.receive.read(id, bytes).map_err(Error::Receive)
    }

    /// Explicit window replenishment for streaming fixtures. Reserving queue
    /// capacity first prevents granting credit without its reliable update.
    pub fn read_replenish(&mut self, id: u64, bytes: &mut [u8]) -> Result<usize, Error> {
        if !self.active() {
            return Err(Error::Closed);
        }
        if !self.scheduler.can_queue_n(2) {
            return Err(Error::Schedule(super::scheduler::Error::Limit));
        }
        let (n, connection, stream) = self
            .receive
            .read_replenish(id, bytes)
            .map_err(Error::Receive)?;
        if n != 0 {
            for (ty, numbers) in [(0x10, vec![connection]), (0x11, vec![id, stream])] {
                let mut frame = vec![ty];
                for value in numbers {
                    let mut scratch = [0; 8];
                    frame.extend_from_slice(
                        super::wire::encode_varint(value, &mut scratch).ok_or(Error::Protocol)?,
                    );
                }
                if let Err(e) = self.scheduler.enqueue(frame) {
                    self.abort();
                    return Err(Error::Schedule(e));
                }
            }
        }
        Ok(n)
    }

    pub fn finished(&self, id: u64) -> bool {
        self.active() && self.receive.finished(id)
    }

    fn register_implicit(&mut self, id: u64) -> Result<(), Error> {
        self.receive.register_implicit(id).map_err(Error::Receive)?;
        if id & 2 == 0 && id & 1 != u64::from(self.server) {
            for prior in ((id & 3)..=id).step_by(4) {
                self.send.register_peer_bidi(prior).map_err(Error::Send)?;
            }
        }
        Ok(())
    }

    fn active(&self) -> bool {
        !self.closed && self.shutdown.is_open()
    }

    fn abort(&mut self) {
        self.closed = true;
        self.shutdown.abort();
        self.protection = None;
        self.binding = None;
    }

    /// No new streams, data or key changes after local closing begins.
    pub fn close(&mut self, code: u64, now: Instant) -> Result<(), Error> {
        if !self.active() {
            return Err(Error::Closed);
        }
        self.shutdown
            .local(now, self.scheduler.base_pto(), code)
            .map_err(|_| Error::Protocol)
    }

    pub fn shutdown_phase(&self) -> ShutdownPhase {
        self.shutdown.phase()
    }

    fn tick(&mut self, now: Instant) {
        self.paths.expire(now);
        if self.active()
            && self
                .idle
                .deadline(self.scheduler.base_pto())
                .is_some_and(|at| now >= at)
        {
            self.abort();
            return;
        }
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
        let recovery = if self.active() {
            self.scheduler.deadline()
        } else {
            None
        };
        let idle = if self.active() {
            self.idle.deadline(self.scheduler.base_pto())
        } else {
            None
        };
        let path_retry = if self.active() && self.scheduler.can_send_path() {
            self.paths
                .challenge_deadline(MTU as u64, self.scheduler.base_pto())
        } else {
            None
        };
        [
            self.shutdown.deadline(),
            old_keys,
            recovery,
            self.paths.deadline(),
            idle,
            path_retry,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Send at most one datagram per call, ACKs first. The caller owns the
    /// drive loop and timer. Any uncertain send outcome is terminal.
    pub async fn flush(&mut self, now: Instant) -> Result<bool, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        self.tick(now);
        if self.closed || self.shutdown.phase() == ShutdownPhase::Draining {
            return Ok(false);
        }
        let result = if self.shutdown.phase() == ShutdownPhase::Closing {
            self.flush_close(now).await
        } else {
            self.flush_inner(now).await
        };
        if result.is_err() {
            self.abort();
        }
        result
    }

    async fn flush_close(&mut self, now: Instant) -> Result<bool, Error> {
        let Some(code) = self.shutdown.take_close(now, self.scheduler.base_pto()) else {
            return Ok(false);
        };
        let mut payload = vec![0x1d];
        let mut scratch = [0; 8];
        payload.extend_from_slice(
            super::wire::encode_varint(code, &mut scratch).ok_or(Error::Protocol)?,
        );
        payload.push(0); // empty reason
                         // CONNECTION_CLOSE is not ACK-eliciting. Once closing, no normal
                         // recovery or application frames are driven, but PN never resets.
        let (_, packet) = self.seal(&payload)?;
        if self
            .socket
            .send_to(&packet, self.paths.active())
            .await
            .map_err(Error::Io)?
            != packet.len()
        {
            return Err(Error::Protocol);
        }
        Ok(true)
    }

    fn seal(&mut self, payload: &[u8]) -> Result<(u64, Vec<u8>), Error> {
        let mut header = vec![0x43];
        let remote_cid = self.peer_ids.current().ok_or(Error::Protocol)?;
        header.extend_from_slice(remote_cid);
        header.extend_from_slice(&[0; 4]);
        match self.protection.as_mut().ok_or(Error::Closed)? {
            Protection::Fixed { writer, .. } => writer.seal(&header, payload),
            Protection::Rotating { writer, .. } => writer.seal(remote_cid, payload),
        }
        .map_err(Error::Packet)
    }

    async fn flush_inner(&mut self, now: Instant) -> Result<bool, Error> {
        self.scheduler.on_timer(now).map_err(Error::Schedule)?;
        if self.scheduler.can_send_path() {
            let pto = self.scheduler.base_pto();
            if let Some((peer, challenge)) = self.paths.due_challenge(MTU as u64, now, pto) {
                if self.paths.reserve_challenge(peer, MTU as u64, now, pto) {
                    let mut frame = vec![0x1a];
                    frame.extend_from_slice(&challenge);
                    self.send_path(peer, &frame, now).await?;
                    return Ok(true);
                }
            }
        }
        let ack = self.acknowledgments.encode();
        let (payload, frame) = if let Some(ack) = ack {
            (ack, None)
        } else if let Some((id, frame, probe)) =
            self.scheduler.candidate(now).map_err(Error::Schedule)?
        {
            (frame, Some((id, probe)))
        } else {
            return Ok(false);
        };
        let (number, packet) = self.seal(&payload)?;
        self.scheduler
            .record(number, packet.len(), frame, now)
            .map_err(Error::Schedule)?;
        if self
            .socket
            .send_to(&packet, self.paths.active())
            .await
            .map_err(Error::Io)?
            != packet.len()
        {
            return Err(Error::Protocol);
        }
        if frame.is_none() {
            self.acknowledgments.sent();
        } else {
            self.idle.sent(now);
        }
        Ok(true)
    }

    /// Read at most one datagram. Malformed unauthenticated packets are
    /// dropped; authenticated protocol errors terminate this lab session.
    pub async fn recv(&mut self, wait: Duration) -> Result<bool, Error> {
        self.recv_with_wake(wait, None).await
    }

    /// Wake only while waiting for UDP, never cancel an authenticated packet
    /// handler after it has consumed a datagram or reserved a packet number.
    pub(crate) async fn recv_with_wake(&mut self, wait: Duration, wake: Option<&tokio::sync::Notify>) -> Result<bool, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        let now = Instant::now();
        self.tick(now);
        if self.closed {
            return Ok(false);
        }
        let idle = if self.active() {
            self.idle.deadline(self.scheduler.base_pto())
        } else {
            None
        };
        let wait = [self.shutdown.deadline(), idle]
            .into_iter()
            .flatten()
            .fold(wait, |wait, at| wait.min(at.saturating_duration_since(now)));
        let result = self.recv_inner(wait, wake).await;
        if result.is_err() {
            self.abort();
        } else {
            self.tick(Instant::now());
        }
        result
    }

    fn receive_stateless_reset(&mut self, packet: &[u8], source: SocketAddr, now: Instant) -> Result<bool, Error> {
        if source != self.paths.active() || packet.len() > MTU || !self.peer_ids.matches_reset(packet) { return Ok(false); }
        self.shutdown.peer(now, self.scheduler.base_pto()).map_err(|_| Error::Protocol)?;
        self.protection = None;
        self.binding = None;
        Ok(true)
    }

    async fn recv_inner(&mut self, wait: Duration, wake: Option<&tokio::sync::Notify>) -> Result<bool, Error> {
        let mut buf = [0; MTU + 1];
        let incoming = tokio::time::timeout(wait, self.socket.recv_from(&mut buf));
        let received = if let Some(wake) = wake {
            tokio::select! { biased; packet = incoming => packet, _ = wake.notified() => return Ok(false) }
        } else { incoming.await };
        let (n, source) = match received {
            Ok(result) => result.map_err(Error::Io)?,
            Err(_) => return Ok(false),
        };
        if self.shutdown.phase() == ShutdownPhase::Draining {
            return Ok(false);
        }
        let new_path = source != self.paths.active();
        if new_path
            && (!self.server
                || !self.confirmed
                || !self.active()
                || !source.ip().is_loopback())
        {
            return Ok(false);
        }
        let destination = if (1 + CID_LEN + 4 + 16..=MTU).contains(&n) && buf[0] & 0xc0 == 0x40 {
            self.local_ids.iter().find_map(|(&seq, cid)| (buf[1..1+CID_LEN] == *cid).then_some((seq, *cid)))
        } else { None };
        let Some((destination_sequence, destination_cid)) = destination else {
            return self.receive_stateless_reset(&buf[..n], source, Instant::now());
        };
        let now = Instant::now();
        let old_key_deadline = now
            .checked_add(self.scheduler.base_pto().saturating_mul(3))
            .ok_or(Error::Protocol)?;
        let result = match self.protection.as_mut().ok_or(Error::Closed)? {
            Protection::Fixed { reader, .. } => reader.open(&buf[..n], 1 + CID_LEN),
            Protection::Rotating { reader, writer } => {
                match reader.open(
                    &destination_cid,
                    &buf[..n],
                    now,
                    old_key_deadline,
                    self.confirmed,
                ) {
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
            Err(packet::Error::Crypto | packet::Error::Header | packet::Error::TooOld) => return self.receive_stateless_reset(&buf[..n], source, now),
            Err(_) => return Ok(false),
        };
        if matches!(&self.protection, Some(Protection::Fixed { .. }))
            && opened.header[0] & 0x04 != 0
        {
            return Err(Error::Protocol);
        }
        let parsed =
            frames::decode(&opened.payload, Space::Application).map_err(|_| Error::Protocol)?;
        if new_path {
            // Only authenticated 1-RTT packets can establish a candidate.
            // Never apply stream data, ACKs or close from an unvalidated path.
            let old_ip = self.paths.active().ip();
            let Ok(challenge) = self.paths.begin(source, n as u64, now) else {
                return Ok(false);
            };
            let probing = parsed.iter().all(|f| {
                matches!(
                    f,
                    Frame::Padding | Frame::Ping | Frame::PathChallenge(_) | Frame::PathResponse(_)
                )
            });
            if !probing
                || !parsed.iter().any(|f| {
                    matches!(f, Frame::PathResponse(value)
                if self.paths.response(source, *value, now))
                })
            {
                if self.scheduler.can_send_path()
                    && self.paths.reserve_challenge(
                        source,
                        MTU as u64,
                        now,
                        self.scheduler.base_pto(),
                    )
                {
                    let mut frame = vec![0x1a];
                    frame.extend_from_slice(&challenge);
                    self.send_path(source, &frame, now).await?;
                }
                return Ok(false);
            }
            // A validated cross-IP path starts a fresh congestion/RTT model;
            // same-IP NAT rebinding may preserve the old estimates.
            if old_ip != source.ip() { self.scheduler.restart_path(now); }
        }
        self.idle.received(now);
        if let Some(Frame::Close {
            application, code, ..
        }) = parsed
            .iter()
            .find(|frame| matches!(frame, Frame::Close { .. }))
        {
            if *application {
                self.peer_application_close = Some(*code);
            }
            self.shutdown
                .peer(now, self.scheduler.base_pto())
                .map_err(|_| Error::Protocol)?;
            // Draining is silent. Drop keys now; retain the connection
            // object/route until the shutdown deadline.
            self.protection = None;
            self.binding = None;
            return Ok(true);
        }
        if self.shutdown.phase() == ShutdownPhase::Closing {
            self.shutdown.authenticated_packet(now);
            return Ok(true);
        }
        let eliciting = parsed
            .iter()
            .any(|f| !matches!(f, Frame::Ack(_) | Frame::Padding | Frame::Close { .. }));
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
                Frame::NewConnectionId { sequence, retire_prior_to, cid, reset_token } => {
                    let retired = self.peer_ids.insert(ConnectionId { sequence, cid: cid.to_vec(), reset_token }, retire_prior_to).map_err(|_| Error::Protocol)?;
                    if !self.scheduler.can_queue_n(retired.len()) { return Err(Error::Protocol); }
                    for sequence in retired { self.queue_retire_cid(sequence)?; }
                }
                Frame::RetireConnectionId(sequence) => {
                    if sequence >= self.next_local_sequence || sequence == destination_sequence { return Err(Error::Protocol); }
                    if let Some(cid) = self.local_ids.get(&sequence).copied() {
                        if self.local_ids.len() <= 1 { return Err(Error::Protocol); }
                        self.socket.retire_cid(cid).await.map_err(Error::Io)?;
                        self.local_ids.remove(&sequence);
                    }
                }
                Frame::Ack(ack) => {
                    self.scheduler
                        .acknowledge(&ack, now)
                        .map_err(Error::Schedule)?;
                    if let Some(Protection::Rotating { writer, .. }) = &mut self.protection {
                        if let Some(range) = ack.ranges.first() {
                            writer.acknowledged(range.last);
                        }
                    }
                }
                Frame::HandshakeDone
                    if !self.server
                        && matches!(&self.protection, Some(Protection::Rotating { .. })) =>
                {
                    self.confirmed = true;
                }
                Frame::Stream {
                    id,
                    offset,
                    data,
                    fin,
                } => {
                    self.receive
                        .insert(id, offset, data, fin)
                        .map_err(Error::Receive)?;
                    self.register_implicit(id)?;
                }
                Frame::ResetStream {
                    id,
                    code,
                    final_size,
                } => {
                    self.receive
                        .reset(id, final_size, code)
                        .map_err(Error::Receive)?;
                    self.register_implicit(id)?;
                }
                Frame::StopSending { id, code } => self.reset_stream(id, code)?,
                Frame::MaxData(n) => self.send.max_data(n).map_err(Error::Send)?,
                Frame::MaxStreamData { id, limit } => {
                    self.send.max_stream_data(id, limit).map_err(Error::Send)?
                }
                Frame::MaxStreams { bidi: false, limit } => self
                    .send
                    .max_streams(limit)
                    .map_err(Error::Send)?,
                Frame::MaxStreams { bidi: true, limit } => self
                    .send
                    .max_bidi(limit)
                    .map_err(Error::Send)?,
                _ => return Err(Error::Protocol),
            }
        }
        self.acknowledgments.record(opened.number, eliciting);
        Ok(true)
    }
}
