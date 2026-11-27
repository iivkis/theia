//! Loopback-only QUIC v1/v2 handshake experiment over UDP. TLS messages
//! travel exclusively in protected Initial and Handshake packets. Retry and
//! shared listener support remain loopback-only; no VN restart, resumption or H3.
//! This is not a production listener or Theia admission.
use super::listener::{Candidate, SessionIo};
use super::{
    ack_tx::History,
    endpoint::LabSession,
    frames::{self, Frame},
    handshake::{Driver, Level},
    initial::crypto_frame,
    negotiation::VersionPolicy,
    packet::{self, Reader, Writer},
    parameters::{self, Parameters, PeerContext},
    recovery::PathBudget,
    scheduler::Scheduler,
    spaces::Space,
    tls,
    wire::{encode_varint, varint, Version},
};
use rustls::{
    crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    pki_types::ServerName,
    quic::{self, KeyChange, Keys, Secrets},
    ClientConfig, ServerConfig, Side,
};
use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

const MTU: usize = 1200;
const CHUNK: usize = 900;
const MAX_RETRY_TOKEN: usize = 512;
const DEADLINE: Duration = Duration::from_secs(8);
const CID_LEN: usize = 8;
use crate::transport_policy as policy;

#[derive(Debug)]
pub enum Error {
    Scope,
    Protocol,
    Timeout,
    VersionNegotiation(Version),
    Io(io::Error),
    Tls(rustls::Error),
    Driver(super::handshake::Error),
    Packet(packet::Error),
    Schedule(super::scheduler::Error),
    Endpoint(super::endpoint::Error),
}

/// Explicit controller selection for interoperability and benchmark trials.
/// Existing native entry points retain their BBR default; production
/// configuration and the accepted Quinn backend are not changed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Congestion {
    Cubic,
    #[default]
    Bbr,
}

pub enum Config {
    Client {
        tls: Arc<ClientConfig>,
        name: ServerName<'static>,
    },
    Server(Arc<ServerConfig>),
}

struct Epoch {
    reader: Reader,
    writer: Writer,
    ack: History,
    schedule: Scheduler,
}

impl Epoch {
    #[cfg(test)]
    fn new(keys: Keys) -> Self {
        Self::with_schedule(keys, Scheduler::default())
    }

    fn with_schedule(keys: Keys, schedule: Scheduler) -> Self {
        Self {
            reader: Reader::new(keys.remote),
            writer: Writer::new(keys.local),
            ack: History::default(),
            schedule,
        }
    }
}

fn params(
    server: bool,
    version: Version,
    versions: &VersionPolicy,
    local: &[u8; CID_LEN],
    original: &[u8],
    retry: Option<&[u8]>,
    initial_reset: Option<[u8; 16]>,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    parameters::append(&mut out, 0x11, &versions.information(version, server))
        .map_err(|_| Error::Protocol)?;
    parameters::append(&mut out, 0x0f, local).map_err(|_| Error::Protocol)?;
    if server {
        parameters::append(&mut out, 0x00, original).map_err(|_| Error::Protocol)?;
        if let Some(token) = initial_reset {
            parameters::append(&mut out, 0x02, &token).map_err(|_| Error::Protocol)?;
        }
    }
    if server {
        if let Some(cid) = retry {
            parameters::append(&mut out, 0x10, cid).map_err(|_| Error::Protocol)?;
        }
    }
    for (id, value) in [
        (0x01, 30_000),
        (0x03, super::mtu::MAX_UDP_PAYLOAD as u64),
        (0x04, u64::from(policy::QUIC_CONNECTION_RECEIVE_BYTES)),
        (0x05, u64::from(policy::QUIC_STREAM_RECEIVE_BYTES)),
        (0x06, u64::from(policy::QUIC_STREAM_RECEIVE_BYTES)),
        (0x07, u64::from(policy::QUIC_STREAM_RECEIVE_BYTES)),
        (0x08, u64::from(policy::MAX_BIDI_STREAMS)),
        (0x09, u64::from(policy::MAX_QUIC_UNI_STREAMS)),
    ] {
        let mut scratch = [0; 8];
        let value = encode_varint(value, &mut scratch).ok_or(Error::Protocol)?;
        parameters::append(&mut out, id, value).map_err(|_| Error::Protocol)?;
    }
    Ok(out)
}

fn header_type(version: Version, index: usize) -> u8 {
    match (version, index) {
        (Version::V1, 0) => 0xc3,
        (Version::V2, 0) => 0xd3,
        (Version::V1, _) => 0xe3,
        (Version::V2, _) => 0xf3,
    }
}

/// Four-byte packet number and two-byte length. Initial padding is inside
/// AEAD and sized against the entire datagram, including coalesced packets.
fn header(
    version: Version,
    index: usize,
    local: &[u8; CID_LEN],
    remote: &[u8],
    token: &[u8],
    payload: &mut Vec<u8>,
    minimum: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = vec![header_type(version, index)];
    out.extend_from_slice(&version.wire().to_be_bytes());
    if remote.is_empty() || remote.len() > 20 {
        return Err(Error::Protocol);
    }
    out.push(remote.len() as u8);
    out.extend_from_slice(remote);
    out.push(CID_LEN as u8);
    out.extend_from_slice(local);
    if index == 0 {
        let mut scratch = [0; 8];
        out.extend_from_slice(
            encode_varint(token.len() as u64, &mut scratch).ok_or(Error::Protocol)?,
        );
        out.extend_from_slice(token);
    }
    let overhead = out.len() + 2 + 4 + 16;
    if payload.is_empty() || overhead + payload.len() > MTU {
        return Err(Error::Protocol);
    }
    if index == 0 && minimum > overhead + payload.len() {
        if minimum > MTU {
            return Err(Error::Protocol);
        }
        payload.resize(minimum - overhead, 0);
    }
    let len = (4 + 16 + payload.len()) as u16;
    out.extend_from_slice(&(len | 0x4000).to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    Ok(out)
}

fn parse_header(
    packet: &[u8],
    version: Version,
    local: &[u8],
    remote: &[u8],
    expected_token: &[u8],
) -> Option<(usize, usize)> {
    let ty = *packet.first()? & 0xf0;
    let index = if ty == header_type(version, 0) & 0xf0 {
        0
    } else if ty == header_type(version, 1) & 0xf0 {
        1
    } else {
        return None;
    };
    let end = 6 + local.len();
    if packet.get(1..5)? != version.wire().to_be_bytes()
        || usize::from(*packet.get(5)?) != local.len()
        || packet.get(6..end)? != local
        || usize::from(*packet.get(end)?) != remote.len()
        || packet.get(end + 1..end + 1 + remote.len())? != remote
    {
        return None;
    }
    let mut at = end + 1 + remote.len();
    if index == 0 {
        let len = usize::try_from(varint(packet, &mut at)?).ok()?;
        let end = at.checked_add(len)?;
        if packet.get(at..end)? != expected_token {
            return None;
        }
        at = end;
    }
    let length = usize::try_from(varint(packet, &mut at)?).ok()?;
    if length < 20 || at.checked_add(length)? != packet.len() {
        return None;
    }
    Some((index, at))
}

/// Client-side Handshake packet-number space retained after TLS completion.
/// A lost final Handshake ACK must not prevent 1-RTT or HANDSHAKE_DONE.
/// Only the client retains this state; the server discards it on TLS confirmation.
pub(crate) struct HandshakeTail {
    epoch: Epoch,
    version: Version,
    local: [u8; CID_LEN],
    remote: Vec<u8>,
    consumed: u64,
    expires: Instant,
}

pub(crate) enum TailEvent {
    Ignored,
    Authenticated,
    Close,
}

impl HandshakeTail {
    pub(crate) fn deadline(&self) -> Instant {
        self.epoch
            .schedule
            .deadline()
            .map_or(self.expires, |at| at.min(self.expires))
    }

    /// Some indicates a sent Handshake packet; the boolean says whether
    /// it is ACK-eliciting. Retransmissions allocate new packet numbers.
    pub(crate) async fn flush(
        &mut self,
        socket: &SessionIo,
        peer: SocketAddr,
        now: Instant,
    ) -> Result<Option<bool>, Error> {
        if now >= self.expires {
            return Err(Error::Timeout);
        }
        self.epoch.schedule.on_timer(now).map_err(Error::Schedule)?;
        let (mut payload, frame) = if let Some(ack) = self.epoch.ack.encode() {
            (ack, None)
        } else if let Some((id, data, probe)) = self
            .epoch
            .schedule
            .candidate(now)
            .map_err(Error::Schedule)?
        {
            (data, Some((id, probe)))
        } else {
            return Ok(None);
        };
        let header = header(
            self.version,
            1,
            &self.local,
            &self.remote,
            &[],
            &mut payload,
            0,
        )?;
        let (number, packet) = self
            .epoch
            .writer
            .seal(&header, &payload)
            .map_err(Error::Packet)?;
        self.epoch
            .schedule
            .record(number, packet.len(), frame, now)
            .map_err(Error::Schedule)?;
        if socket.send_to(&packet, peer).await.map_err(Error::Io)? != packet.len() {
            return Err(Error::Protocol);
        }
        if frame.is_none() {
            self.epoch.ack.sent();
        }
        Ok(Some(frame.is_some()))
    }

    pub(crate) fn receive(&mut self, packet: &[u8], now: Instant) -> Result<TailEvent, Error> {
        if now >= self.expires {
            return Err(Error::Timeout);
        }
        let Some((1, at)) = parse_header(packet, self.version, &self.local, &self.remote, &[])
        else {
            return Ok(TailEvent::Ignored);
        };
        let opened = match self.epoch.reader.open(packet, at) {
            Ok(packet) => packet,
            Err(packet::Error::Reserved | packet::Error::Limit) => return Err(Error::Protocol),
            Err(_) => return Ok(TailEvent::Ignored),
        };
        let parsed =
            frames::decode(&opened.payload, Space::Handshake).map_err(|_| Error::Protocol)?;
        if parsed
            .iter()
            .any(|frame| matches!(frame, Frame::Close { .. }))
        {
            return Ok(TailEvent::Close);
        }
        let mut eliciting = false;
        for frame in parsed {
            match frame {
                Frame::Padding => {}
                Frame::Ping => eliciting = true,
                Frame::Ack(ack) => self
                    .epoch
                    .schedule
                    .acknowledge(&ack, now)
                    .map_err(Error::Schedule)?,
                Frame::Crypto { offset, data } => {
                    // TLS is complete. Already consumed CRYPTO may be
                    // retransmitted, but no new handshake bytes are accepted.
                    if offset
                        .checked_add(data.len() as u64)
                        .is_none_or(|end| end > self.consumed)
                    {
                        return Err(Error::Protocol);
                    }
                    eliciting = true;
                }
                _ => return Err(Error::Protocol),
            }
        }
        self.epoch.ack.record(opened.number, eliciting);
        Ok(TailEvent::Authenticated)
    }
}

struct FlightPacket {
    index: usize,
    padded_ack: bool,
    header: Vec<u8>,
    payload: Vec<u8>,
    frame: Option<(u64, bool)>,
}
impl FlightPacket {
    fn size(&self) -> usize {
        self.header.len() + self.payload.len() + 16
    }
}

struct Handshake {
    driver: Driver,
    epochs: [Option<Epoch>; 2],
    application_schedule: Scheduler,
    application: Option<(Keys, Secrets)>,
    budget: PathBudget,
    server: bool,
    version: Version,
    local: [u8; CID_LEN],
    remote: Vec<u8>,
    original: Vec<u8>,
    retry: Option<Vec<u8>>,
    token: Vec<u8>,
    peer_progress: bool,
    initial_frames: Vec<Vec<u8>>,
    early_application: Vec<Vec<u8>>,
    versions: VersionPolicy,
    restarted: bool,
}

impl Handshake {
    fn collect(&mut self) -> Result<(), Error> {
        while let Some(flight) = self.driver.poll_output().map_err(Error::Driver)? {
            let index = flight.level as usize;
            // Tickets and other post-handshake CRYPTO are not supported by
            // this fixture. Do not silently drop bytes or reuse app keys.
            if index >= 2 && !flight.data.is_empty() {
                return Err(Error::Protocol);
            }
            for (i, chunk) in flight.data.chunks(CHUNK).enumerate() {
                let frame = crypto_frame(flight.offset + (i * CHUNK) as u64, chunk)
                    .map_err(|_| Error::Protocol)?;
                if !self.server && index == 0 && !self.peer_progress && self.retry.is_none() {
                    self.initial_frames.push(frame.clone());
                }
                self.epochs[index]
                    .as_mut()
                    .ok_or(Error::Protocol)?
                    .schedule
                    .enqueue(frame)
                    .map_err(Error::Schedule)?;
            }
            match flight.keys {
                Some(KeyChange::Handshake { keys }) if self.epochs[1].is_none() => {
                    self.epochs[1] = Some(Epoch::with_schedule(
                        keys,
                        self.application_schedule.fork_space(),
                    ))
                }
                Some(KeyChange::OneRtt { keys, next }) if self.application.is_none() => {
                    self.application = Some((keys, next))
                }
                Some(_) => return Err(Error::Protocol),
                None => {}
            }
        }
        Ok(())
    }

    /// Emit one datagram with up to two independently protected packets.
    /// No PN is allocated until the complete amplification charge succeeds.
    async fn emit(
        &mut self,
        socket: &SessionIo,
        peer: SocketAddr,
        packets: Vec<FlightPacket>,
        now: Instant,
    ) -> Result<bool, Error> {
        let total: usize = packets.iter().map(FlightPacket::size).sum();
        if total > MTU || total == 0 {
            return Err(Error::Protocol);
        }
        let ordinary: u64 = packets
            .iter()
            .filter(|p| p.padded_ack || p.frame.is_some_and(|(_, probe)| !probe))
            .map(|p| p.size() as u64)
            .sum();
        let probes: u64 = packets
            .iter()
            .filter(|p| p.frame.is_some_and(|(_, probe)| probe))
            .map(|p| p.size() as u64)
            .sum();
        let stale_probe = packets.iter().any(|p| {
            p.frame.is_some_and(|(_, probe)| probe)
                && self.epochs[p.index]
                    .as_ref()
                    .is_none_or(|epoch| epoch.schedule.pto_deadline().is_none_or(|at| now < at))
        });
        if stale_probe
            || packets
                .iter()
                .filter(|p| p.frame.is_some_and(|(_, probe)| probe))
                .count()
                > 1
            || !self
                .application_schedule
                .permits_flight(ordinary, probes, now)
        {
            return Ok(false);
        }
        if self.server && !self.budget.reserve_send(total as u64) {
            return Ok(false);
        }
        let mut datagram = Vec::with_capacity(total);
        let mut discard_initial = false;
        for packet in packets {
            let epoch = self.epochs[packet.index].as_mut().ok_or(Error::Protocol)?;
            let (number, protected) = epoch
                .writer
                .seal(&packet.header, &packet.payload)
                .map_err(Error::Packet)?;
            if packet.padded_ack {
                epoch
                    .schedule
                    .record_padded_ack(number, protected.len(), now)
                    .map_err(Error::Schedule)?;
            } else {
                epoch
                    .schedule
                    .record(number, protected.len(), packet.frame, now)
                    .map_err(Error::Schedule)?;
            }
            datagram.extend_from_slice(&protected);
            if packet.frame.is_none() {
                epoch.ack.sent();
            }
            discard_initial |= !self.server && packet.index == 1;
        }
        if socket.send_to(&datagram, peer).await.map_err(Error::Io)? != datagram.len() {
            return Err(Error::Protocol);
        }
        if discard_initial {
            self.epochs[0] = None;
        }
        Ok(true)
    }

    fn pad_initial(&self, packet: &mut FlightPacket, minimum: usize) -> Result<(), Error> {
        if packet.index != 0 || (self.server && packet.frame.is_none()) {
            return Ok(());
        }
        let token = if self.server {
            &[][..]
        } else {
            self.token.as_slice()
        };
        let original_len = packet.payload.len();
        packet.header = header(
            self.version,
            0,
            &self.local,
            &self.remote,
            token,
            &mut packet.payload,
            minimum,
        )?;
        packet.padded_ack |= packet.frame.is_none() && packet.payload.len() > original_len;
        Ok(())
    }

    async fn flush(&mut self, socket: &SessionIo, peer: SocketAddr) -> Result<bool, Error> {
        let now = Instant::now();
        let mut packets = Vec::with_capacity(2);
        for (index, epoch) in self.epochs.iter_mut().enumerate() {
            let Some(epoch) = epoch else {
                continue;
            };
            epoch.schedule.on_timer(now).map_err(Error::Schedule)?;
            let (mut payload, frame) = if let Some(ack) = epoch.ack.encode() {
                (ack, None)
            } else if let Some((id, data, probe)) =
                epoch.schedule.candidate(now).map_err(Error::Schedule)?
            {
                (data, Some((id, probe)))
            } else {
                continue;
            };
            let token = if self.server {
                &[][..]
            } else {
                self.token.as_slice()
            };
            let header = header(
                self.version,
                index,
                &self.local,
                &self.remote,
                token,
                &mut payload,
                0,
            )?;
            packets.push(FlightPacket {
                index,
                padded_ack: false,
                header,
                payload,
                frame,
            });
        }
        if packets
            .iter()
            .filter(|p| p.frame.is_some_and(|(_, probe)| probe))
            .count()
            > 1
        {
            let first = packets
                .iter()
                .filter(|p| p.frame.is_some_and(|(_, probe)| probe))
                .min_by_key(|p| {
                    self.epochs[p.index]
                        .as_ref()
                        .and_then(|epoch| epoch.schedule.pto_deadline())
                })
                .map(|p| p.index)
                .ok_or(Error::Protocol)?;
            packets.retain(|p| !p.frame.is_some_and(|(_, probe)| probe) || p.index == first);
        }
        if packets.len() == 2 && packets.iter().map(FlightPacket::size).sum::<usize>() <= MTU {
            let initial_size = MTU - packets[1].size();
            self.pad_initial(&mut packets[0], initial_size)?;
            // Coalescing is opportunistic; if unvalidated budget is smaller
            // than a padded Initial, a standalone Handshake may still fit.
            if !self.server || self.budget.can_send(MTU as u64) {
                let ordinary = packets
                    .iter()
                    .filter(|p| p.padded_ack || p.frame.is_some_and(|(_, probe)| !probe))
                    .map(|p| p.size() as u64)
                    .sum();
                let probes = packets
                    .iter()
                    .filter(|p| p.frame.is_some_and(|(_, probe)| probe))
                    .map(|p| p.size() as u64)
                    .sum();
                if packets
                    .iter()
                    .filter(|p| p.frame.is_some_and(|(_, probe)| probe))
                    .count()
                    <= 1
                    && self
                        .application_schedule
                        .permits_flight(ordinary, probes, now)
                {
                    return self.emit(socket, peer, packets, now).await;
                }
            }
        }
        let mut sent = false;
        for mut packet in packets {
            self.pad_initial(&mut packet, MTU)?;
            sent |= self.emit(socket, peer, vec![packet], now).await?;
        }
        Ok(sent)
    }

    fn wait(&self, now: Instant, sent: bool) -> Duration {
        if sent {
            return Duration::ZERO;
        }
        self.epochs
            .iter()
            .flatten()
            .filter_map(|epoch| {
                let deadline = epoch.schedule.deadline();
                // Client Initial ACK-only packets require padding and can
                // be deferred by the shared pacing window.
                let ack_pace = (!self.server && epoch.ack.pending())
                    .then(|| epoch.schedule.pacing_deadline())
                    .flatten();
                [deadline, ack_pace].into_iter().flatten().min()
            })
            .filter(|at| *at > now || !self.server || self.budget.can_send(MTU as u64))
            .min()
            .map_or(DEADLINE, |at| {
                at.saturating_duration_since(now).min(DEADLINE)
            })
    }

    fn apply_retry(&mut self, packet: &[u8]) -> Result<(), Error> {
        if self.server {
            return Ok(());
        }
        let Ok((cid, token)) = super::negotiation::retry_token(
            packet,
            self.version,
            &self.local,
            &self.original,
            self.retry.is_some(),
            self.peer_progress,
        ) else {
            return Ok(());
        };
        if cid.is_empty() || cid.len() > 20 {
            return Ok(());
        }
        // Bound the opaque token to leave room for the original CRYPTO chunks.
        if cid == self.local.as_slice() || token.is_empty() || token.len() > MAX_RETRY_TOKEN {
            return Ok(());
        }
        let next = self.epochs[0]
            .as_ref()
            .ok_or(Error::Protocol)?
            .writer
            .next();
        // Keep TLS and CRYPTO offsets; only Initial protection and recovery
        // are reset. The packet number MUST continue across Retry.
        let keys = initial_keys(self.version, cid, false)?;
        let old = self.epochs[0].take().ok_or(Error::Protocol)?;
        let mut epoch = Epoch {
            reader: Reader::new(keys.remote),
            writer: Writer::with_next(keys.local, next),
            ack: History::default(),
            schedule: old.schedule.after_retry(next, Instant::now()),
        };
        // A larger opaque Retry token consumes Initial payload space.
        // Re-fragment the original CRYPTO without changing TLS offsets.
        let chunk = CHUNK.min(MTU - 80 - token.len());
        for frame in self.initial_frames.drain(..) {
            let parsed = frames::decode(&frame, Space::Initial).map_err(|_| Error::Protocol)?;
            for item in parsed {
                let Frame::Crypto { offset, data } = item else {
                    return Err(Error::Protocol);
                };
                for (i, part) in data.chunks(chunk).enumerate() {
                    let frame = crypto_frame(offset + (i * chunk) as u64, part)
                        .map_err(|_| Error::Protocol)?;
                    epoch.schedule.enqueue(frame).map_err(Error::Schedule)?;
                }
            }
        }
        self.epochs[0] = Some(epoch);
        self.remote = cid.to_vec();
        self.retry = Some(cid.to_vec());
        self.token = token.to_vec();
        Ok(())
    }

    fn receive_datagram(&mut self, datagram: &[u8]) -> Result<(), Error> {
        let Ok(packets) = super::datagram::split(datagram) else {
            return Ok(());
        };
        for packet in packets {
            if packet.kind == super::datagram::PacketKind::VersionNegotiation {
                if !self.server && !self.restarted && self.retry.is_none() {
                    if let Ok(offered) = super::negotiation::version_candidates(
                        packet.bytes,
                        self.version,
                        &self.local,
                        &self.original,
                        self.peer_progress,
                    ) {
                        if let Some(version) = self.versions.choose(&offered) {
                            return Err(Error::VersionNegotiation(version));
                        }
                    }
                }
                continue;
            }
            if packet.kind == super::datagram::PacketKind::Retry {
                self.apply_retry(packet.bytes)?;
                continue;
            }
            if packet.kind == super::datagram::PacketKind::Application {
                // Only ciphertext is buffered, with a fixed per-connection
                // bound. Never apply 1-RTT until TLS and transport parameters pass.
                if packet.destination == self.local.as_slice() && self.early_application.len() < 16
                {
                    self.early_application.push(packet.bytes.to_vec());
                }
                continue;
            }
            if !matches!(
                packet.kind,
                super::datagram::PacketKind::Initial | super::datagram::PacketKind::Handshake
            ) {
                continue;
            }
            self.receive(packet.bytes)?;
            // A preceding Initial can install Handshake keys needed for
            // the next packet in the same datagram.
            self.collect()?;
        }
        Ok(())
    }

    fn receive(&mut self, packet: &[u8]) -> Result<(), Error> {
        let token = if self.server {
            self.token.as_slice()
        } else {
            &[][..]
        };
        // A server chooses its own SCID in its first Initial, including
        // after Retry. The Initial AEAD uses ODCID/Retry keys, not this SCID.
        // TLS transport parameters subsequently authenticate the selection.
        let proposed = if !self.server && !self.peer_progress {
            crate::reality_quic_wire::long(packet)
                .filter(|h| h.kind == crate::reality_quic_wire::Kind::Initial)
                .map(|h| h.scid)
                .filter(|cid| !cid.is_empty() && cid.len() <= 20 && *cid != self.local.as_slice())
        } else {
            None
        };
        let remote = proposed.unwrap_or(self.remote.as_slice());
        let header = parse_header(packet, self.version, &self.local, remote, token)
            .or_else(|| {
                // REALITY preadmission does not validate the path and does
                // not issue Retry. Original DCID is an Initial-only alias.
                if self.server && self.retry.is_none() {
                    parse_header(packet, self.version, &self.original, remote, token)
                        .filter(|(index, _)| *index == 0)
                } else { None }
            });
        let Some((index, at)) = header else { return Ok(()); };
        let Some(epoch) = self.epochs[index].as_mut() else {
            return Ok(());
        };
        let opened = match epoch.reader.open(packet, at) {
            Ok(p) => p,
            Err(packet::Error::Reserved | packet::Error::Limit) if index == 1 => {
                return Err(Error::Protocol)
            }
            Err(_) => return Ok(()),
        };
        if let Some(cid) = proposed {
            self.remote = cid.to_vec();
        }
        self.peer_progress = true;
        self.initial_frames.clear();
        let space = if index == 0 {
            Space::Initial
        } else {
            Space::Handshake
        };
        let level = if index == 0 {
            Level::Initial
        } else {
            Level::Handshake
        };
        let parsed = frames::decode(&opened.payload, space).map_err(|_| Error::Protocol)?;
        if self.server {
            self.budget.received(packet.len() as u64);
            // Only Handshake packet protection, never Initial, validates
            // the fixed client's address in this experiment.
            if index == 1 {
                self.budget.validate();
            }
        }
        let mut eliciting = false;
        for frame in parsed {
            match frame {
                Frame::Padding => {}
                Frame::Ping => eliciting = true,
                Frame::Ack(ack) => epoch
                    .schedule
                    .acknowledge(&ack, Instant::now())
                    .map_err(Error::Schedule)?,
                Frame::Crypto { offset, data } => {
                    self.driver
                        .receive(level, offset, data)
                        .map_err(Error::Driver)?;
                    eliciting = true;
                }
                _ => return Err(Error::Protocol),
            }
        }
        epoch.ack.record(opened.number, eliciting);
        // Server discards Initial on its first authenticated Handshake
        // packet, not on public Initial decryption.
        if self.server && index == 1 {
            self.epochs[0] = None;
        }
        Ok(())
    }

    fn done(&self) -> bool {
        self.driver.tls_complete()
            && self.application.is_some()
            && (self.server
                || self
                    .epochs
                    .iter()
                    .flatten()
                    .all(|epoch| !epoch.schedule.has_queued() && !epoch.ack.pending()))
    }
}

/// Complete TLS via actual UDP Initial/Handshake datagrams, then hand the
/// unused 1-RTT keys to the existing isolated session. Both peers must be
/// driven concurrently. Timeout/uncertain I/O drops the socket and keys.
/// The client retains Handshake recovery until authenticated HANDSHAKE_DONE.
/// Server confirmation does not depend on a final Handshake ACK.
pub async fn establish(
    socket: UdpSocket,
    peer: SocketAddr,
    version: Version,
    local: [u8; CID_LEN],
    remote: [u8; CID_LEN],
    config: Config,
) -> Result<LabSession, Error> {
    let address = socket.local_addr().map_err(Error::Io)?;
    if !super::loopback_pair(address, peer)
        || local == remote
        || local == [0; CID_LEN]
        || remote == [0; CID_LEN]
    {
        return Err(Error::Scope);
    }
    let server = matches!(&config, Config::Server(_));
    let original = if server { local } else { remote };
    establish_inner(
        socket.into(),
        peer,
        InitialRoute {
            version,
            local,
            remote: remote.to_vec(),
            original: original.to_vec(),
            retry: None,
            initial_reset: None,
            token: Vec::new(),
            versions: if server {
                VersionPolicy::both()
            } else {
                VersionPolicy::exact(version)
            },
            restarted: false,
        },
        config,
        Congestion::Bbr,
        None,
    )
    .await
}

/// Client with fresh unpredictable CIDs, for the shared loopback listener.
pub async fn connect(
    socket: UdpSocket,
    peer: SocketAddr,
    version: Version,
    tls: Arc<ClientConfig>,
    name: ServerName<'static>,
) -> Result<LabSession, Error> {
    let local = super::negotiation::random_cid().map_err(|_| Error::Protocol)?;
    let original = super::negotiation::random_cid().map_err(|_| Error::Protocol)?;
    establish(
        socket,
        peer,
        version,
        local,
        original,
        Config::Client { tls, name },
    )
    .await
}

/// Explicit version preference, one fresh retry only after a context-valid VN.
/// The second attempt authenticates server version information before exporter
/// material is returned. TLS failures and ordinary timeouts never select another version.
pub async fn connect_versions(
    local: SocketAddr,
    peer: SocketAddr,
    versions: VersionPolicy,
    tls: Arc<ClientConfig>,
    name: ServerName<'static>,
) -> Result<(Version, LabSession), Error> {
    connect_versions_scoped(
        local,
        peer,
        versions,
        tls,
        name,
        super::scope::NetworkScope::loopback(),
    )
    .await
}

/// Explicit pinned-interface client for controlled non-loopback acceptance.
pub async fn connect_versions_scoped(
    local: SocketAddr,
    peer: SocketAddr,
    versions: VersionPolicy,
    tls: Arc<ClientConfig>,
    name: ServerName<'static>,
    scope: super::scope::NetworkScope,
) -> Result<(Version, LabSession), Error> {
    connect_versions_scoped_with_congestion(
        local,
        peer,
        versions,
        tls,
        name,
        scope,
        Congestion::Bbr,
    )
    .await
}

pub async fn connect_versions_scoped_with_congestion(
    local: SocketAddr,
    peer: SocketAddr,
    versions: VersionPolicy,
    tls: Arc<ClientConfig>,
    name: ServerName<'static>,
    scope: super::scope::NetworkScope,
    congestion: Congestion,
) -> Result<(Version, LabSession), Error> {
    connect_scoped(local, peer, versions, tls, name, scope, (congestion, None)).await
}

/// Keep the same observation across version negotiation and the caller's deadline.
pub(crate) async fn connect_versions_observed(
    local: SocketAddr,
    peer: SocketAddr,
    versions: VersionPolicy,
    tls: Arc<ClientConfig>,
    name: ServerName<'static>,
    scope: super::scope::NetworkScope,
    observation: &super::dial::Observation,
) -> Result<(Version, LabSession), Error> {
    connect_scoped(local, peer, versions, tls, name, scope, (Congestion::Bbr, Some(observation))).await
}

async fn connect_scoped(
    local: SocketAddr,
    peer: SocketAddr,
    versions: VersionPolicy,
    tls: Arc<ClientConfig>,
    name: ServerName<'static>,
    scope: super::scope::NetworkScope,
    options: (Congestion, Option<&super::dial::Observation>),
) -> Result<(Version, LabSession), Error> {
    let (congestion, observation) = options;
    let mut version = versions.preferred();
    for restarted in [false, true] {
        let socket = UdpSocket::bind(local).await.map_err(Error::Io)?;
        if !scope.permits(socket.local_addr().map_err(Error::Io)?, peer) {
            return Err(Error::Scope);
        }
        let carrier_lease = crate::routing::carrier_socket::udp(&socket, peer).map_err(|_| Error::Scope)?;
        let pinned = if crate::routing::carrier_socket::active() {
            socket.connect(peer).await.map_err(|_| Error::Scope)?;
            if socket.peer_addr().ok() != Some(peer) { return Err(Error::Scope); }
            Some(peer)
        } else { None };
        let cid = super::negotiation::random_cid().map_err(|_| Error::Protocol)?;
        let original = super::negotiation::random_cid().map_err(|_| Error::Protocol)?;
        if cid == original || cid == [0; CID_LEN] || original == [0; CID_LEN] {
            return Err(Error::Protocol);
        }
        let route = InitialRoute {
            version,
            local: cid,
            remote: original.to_vec(),
            original: original.to_vec(),
            retry: None,
            initial_reset: None,
            token: Vec::new(),
            versions: versions.clone(),
            restarted,
        };
        match establish_inner(
            SessionIo::direct_carrier(socket, scope, carrier_lease, pinned),
            peer,
            route,
            Config::Client {
                tls: tls.clone(),
                name: name.clone(),
            },
            congestion,
            observation,
        )
        .await
        {
            Ok(session) => return Ok((version, session)),
            Err(Error::VersionNegotiation(next))
                if !restarted && next != version && versions.supports(next) =>
            {
                version = next
            }
            Err(error) => return Err(error),
        }
    }
    Err(Error::Protocol)
}

/// The candidate is created exclusively after the listener validates Retry.
/// TLS and CID parameters must still authenticate before returning a session.
pub async fn accept(candidate: Candidate, tls: Arc<ServerConfig>) -> Result<LabSession, Error> {
    accept_with_congestion(candidate, tls, Congestion::Bbr).await
}

pub async fn accept_with_congestion(
    candidate: Candidate,
    tls: Arc<ServerConfig>,
    congestion: Congestion,
) -> Result<LabSession, Error> {
    let (socket, peer, binding, token, initial_reset, versions, retry_validated) = candidate.into_parts();
    let original = binding.original;
    let remote = binding.client;
    if !(8..=20).contains(&original.len())
        || remote.is_empty()
        || remote.len() > 20
        || remote.as_slice() == binding.retry.as_slice()
        || remote.iter().all(|b| *b == 0)
        || original.iter().all(|b| *b == 0)
    {
        return Err(Error::Scope);
    }
    establish_inner(
        socket,
        peer,
        InitialRoute {
            version: binding.version,
            local: binding.retry,
            remote,
            original,
            retry: retry_validated.then(|| binding.retry.to_vec()),
            initial_reset: Some(initial_reset),
            token,
            versions,
            restarted: false,
        },
        Config::Server(tls),
        congestion,
        None,
    )
    .await
}

fn initial_keys(version: Version, destination: &[u8], server: bool) -> Result<Keys, Error> {
    let suite = TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(|s| s.quic_suite())
        .ok_or(Error::Protocol)?;
    let version_tls = match version {
        Version::V1 => quic::Version::V1,
        Version::V2 => quic::Version::V2,
    };
    Ok(suite.keys(
        destination,
        if server { Side::Server } else { Side::Client },
        version_tls,
    ))
}

struct InitialRoute {
    version: Version,
    local: [u8; CID_LEN],
    remote: Vec<u8>,
    original: Vec<u8>,
    retry: Option<Vec<u8>>,
    initial_reset: Option<[u8; 16]>,
    token: Vec<u8>,
    versions: VersionPolicy,
    restarted: bool,
}

async fn establish_inner(
    mut socket: SessionIo,
    peer: SocketAddr,
    route: InitialRoute,
    config: Config,
    congestion: Congestion,
    observation: Option<&super::dial::Observation>,
) -> Result<LabSession, Error> {
    let InitialRoute {
        version,
        local,
        remote,
        original,
        retry,
        initial_reset,
        token,
        versions,
        restarted,
    } = route;
    if !socket
        .scope()
        .permits(socket.local_addr().map_err(Error::Io)?, peer)
    {
        return Err(Error::Scope);
    }
    let server = matches!(&config, Config::Server(_));
    let parameters = params(
        server,
        version,
        &versions,
        &local,
        &original,
        retry.as_deref(),
        initial_reset,
    )?;
    let connection = match config {
        Config::Client { tls: config, name } => tls::client(config, version, name, parameters),
        Config::Server(config) => {
            if config.send_tls13_tickets != 0 {
                return Err(Error::Protocol);
            }
            tls::server(config, version, parameters)
        }
    }
    .map_err(Error::Tls)?;
    let destination = retry.as_deref().unwrap_or(&original);
    let keys = initial_keys(version, destination, server)?;
    let initial = match congestion {
        Congestion::Bbr => Scheduler::with_bbr(Instant::now()),
        Congestion::Cubic => Scheduler::default(),
    };
    let mut application_schedule = initial.fork_space();
    application_schedule.enable_application_buffer();
    let mut handshake = Handshake {
        driver: Driver::new(connection),
        epochs: [Some(Epoch::with_schedule(keys, initial)), None],
        application_schedule,
        application: None,
        budget: PathBudget::default(),
        server,
        version,
        local,
        remote,
        original,
        retry,
        token,
        peer_progress: false,
        initial_frames: Vec::new(),
        early_application: Vec::new(),
        versions,
        restarted,
    };
    if server && handshake.retry.is_some() {
        handshake.budget.validate();
    }
    if socket.peer_addr().is_ok() {
        return Err(Error::Scope);
    }
    tokio::time::timeout(DEADLINE, async {
        let mut buffer = [0; super::mtu::MAX_UDP_PAYLOAD + 1];
        loop {
            handshake.collect()?;
            let sent = match handshake.flush(&socket, peer).await {
                Ok(sent) => {
                    if let Some(observation) = observation.filter(|_| sent) {
                        observation.sent();
                    }
                    sent
                }
                Err(error) => {
                    if let (Some(observation), Error::Io(io)) = (observation, &error) {
                        // flush's only I/O is send_to the exact peer.
                        observation.send_error(io.kind());
                    }
                    return Err(error);
                }
            };
            if handshake.done() {
                break;
            }
            let wait = handshake.wait(Instant::now(), sent);
            if sent {
                tokio::task::yield_now().await;
            }
            match tokio::time::timeout(wait, socket.recv_from(&mut buffer)).await {
                Ok(Ok((n, source, _mark))) => {
                    // Even malformed, oversized or wrong-source UDP is
                    // evidence against a no-response fallback on this socket.
                    if let Some(observation) = observation {
                        observation.received();
                    }
                    if source == peer && n <= super::mtu::MAX_UDP_PAYLOAD {
                        handshake.receive_datagram(&buffer[..n])?;
                    }
                }
                Err(_) => {}
                Ok(Err(e)) if super::mtu::message_too_large(&e) => {
                    if let Some(observation) = observation {
                        observation.received();
                    }
                }
                Ok(Err(e)) => return Err(Error::Io(e)),
            }
        }
        Ok::<(), Error>(())
    })
    .await
    .map_err(|_| Error::Timeout)??;
    if handshake.driver.negotiated_alpn() != Some(b"h3".as_slice()) {
        return Err(Error::Protocol);
    }
    let peer_params = Parameters::parse(handshake.driver.peer_parameters().ok_or(Error::Protocol)?)
        .map_err(|_| Error::Protocol)?;
    handshake
        .versions
        .validate_information(peer_params.get(0x11), version, !server, restarted)
        .map_err(|_| Error::Protocol)?;
    let limits = peer_params
        .validate(PeerContext {
            server: !server,
            initial_source: &handshake.remote,
            original_destination: &handshake.original,
            retry_source: if server {
                None
            } else {
                handshake.retry.as_deref()
            },
        })
        .map_err(|_| Error::Protocol)?;
    // Keep our local receive and MTU bounds; honor the authenticated peer's independent send credits.
    let peer_idle = peer_params
        .integer(0x01)
        .map_err(|_| Error::Protocol)?
        .unwrap_or(0);
    let idle_timeout = Duration::from_millis(if peer_idle == 0 {
        30_000
    } else {
        peer_idle.min(30_000)
    });
    let peer_reset_token = peer_params
        .get(0x02)
        .and_then(|token| token.try_into().ok());
    let binding = handshake.driver.channel_binding().map_err(Error::Driver)?;
    let peer_leaf = handshake.driver.peer_leaf();
    let tail = if server {
        None
    } else {
        Some(HandshakeTail {
            epoch: handshake.epochs[1].take().ok_or(Error::Protocol)?,
            version,
            local,
            remote: handshake.remote.clone(),
            consumed: handshake.driver.consumed_handshake(),
            expires: Instant::now()
                .checked_add(DEADLINE)
                .ok_or(Error::Protocol)?,
        })
    };
    // Key discard releases the Initial and (server) Handshake flight.
    handshake.epochs = [None, None];
    let (keys, secrets) = handshake.application.take().ok_or(Error::Protocol)?;
    LabSession::after_handshake(
        socket,
        peer,
        server,
        local,
        &handshake.remote,
        super::endpoint::Established {
            keys,
            secrets,
            idle_timeout,
            binding,
            peer_leaf,
            peer_limits: limits,
            peer_reset_token,
            peer_disable_migration: peer_params.get(0x0c).is_some(),
            tail,
            scheduler: handshake.application_schedule,
            early_application: handshake.early_application,
        },
    )
    .await
    .map_err(Error::Endpoint)
}

#[cfg(test)]
mod coalescing_tests {
    use super::*;
    #[tokio::test]
    async fn retained_handshake_space_retransmits_without_reusing_packet_numbers() {
        for version in [Version::V1, Version::V2] {
            let client = [1; CID_LEN];
            let server = [2; CID_LEN];
            // Use independently derived matching fixture keys for this
            // packet-space test; the real TLS integration tests use TLS keys.
            let client_keys = initial_keys(version, &server, false).unwrap();
            let server_keys = initial_keys(version, &server, true).unwrap();
            let mut reader = Reader::new(server_keys.remote);
            let mut writer = Writer::new(server_keys.local);
            let now = Instant::now();
            let mut tail = HandshakeTail {
                epoch: Epoch::new(client_keys),
                version,
                local: client,
                remote: server.to_vec(),
                consumed: 8,
                expires: now + DEADLINE,
            };
            tail.epoch
                .schedule
                .enqueue(crypto_frame(0, b"finished").unwrap())
                .unwrap();
            let socket = SessionIo::from(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = peer.local_addr().unwrap();
            let mut buf = [0; MTU];
            for (pn, at) in [(0, now), (1, now + Duration::from_secs(2))] {
                assert_eq!(tail.flush(&socket, addr, at).await.unwrap(), Some(true));
                let (n, _) = tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                let (index, offset) =
                    parse_header(&buf[..n], version, &server, &client, &[]).unwrap();
                assert_eq!(index, 1);
                let opened = reader.open(&buf[..n], offset).unwrap();
                assert_eq!(opened.number, pn);
                let parsed = frames::decode(&opened.payload, Space::Handshake).unwrap();
                assert!(
                    matches!(parsed.as_slice(), [Frame::Crypto { offset: 0, data }] if *data == b"finished")
                );
                // Deliberately omit the ACK of the first transmission.
            }
            let mut ack = vec![2, 1, 0, 0, 0];
            let h = header(version, 1, &server, &client, &[], &mut ack, 0).unwrap();
            let (_, ack) = writer.seal(&h, &ack).unwrap();
            let at = now + Duration::from_secs(2) + Duration::from_millis(1);
            assert!(matches!(
                tail.receive(&ack, at),
                Ok(TailEvent::Authenticated)
            ));
            assert_eq!(tail.epoch.schedule.pending(), 0);
            let mut retransmitted = crypto_frame(0, b"finished").unwrap();
            let h = header(version, 1, &server, &client, &[], &mut retransmitted, 0).unwrap();
            let (_, retransmitted) = writer.seal(&h, &retransmitted).unwrap();
            assert!(matches!(
                tail.receive(&retransmitted, at),
                Ok(TailEvent::Authenticated)
            ));
            assert_eq!(tail.flush(&socket, addr, at).await.unwrap(), Some(false));
            let mut extra = crypto_frame(8, b"x").unwrap();
            let h = header(version, 1, &server, &client, &[], &mut extra, 0).unwrap();
            let (_, extra) = writer.seal(&h, &extra).unwrap();
            assert!(matches!(tail.receive(&extra, at), Err(Error::Protocol)));
        }
    }

    #[test]
    fn long_headers_accept_independent_peer_cid_lengths() {
        for version in [Version::V1, Version::V2] {
            for len in [1, 8, 12, 20] {
                let local = [1; CID_LEN];
                let remote = vec![2; len];
                let mut payload = vec![1];
                let h = header(version, 1, &local, &remote, &[], &mut payload, 0).unwrap();
                let mut packet = h.clone();
                packet.extend_from_slice(&payload);
                packet.extend([0; 16]);
                // Receiver local CID remains eight bytes; verify the inverse
                // direction with the variable peer source CID.
                let mut inbound = vec![header_type(version, 1)];
                inbound.extend(version.wire().to_be_bytes());
                inbound.push(CID_LEN as u8);
                inbound.extend(local);
                inbound.push(len as u8);
                inbound.extend(&remote);
                inbound.extend_from_slice(&(21u16 | 0x4000).to_be_bytes());
                inbound.extend([0; 21]);
                assert_eq!(
                    parse_header(&inbound, version, &local, &remote, &[]),
                    Some((1, 17 + len))
                );
                assert!(parse_header(&inbound, version, &local, &[3; 8], &[]).is_none());
                assert_eq!(packet[5] as usize, len);
            }
        }
    }

    #[test]
    fn initial_padding_counts_coalesced_handshake_bytes() {
        for version in [Version::V1, Version::V2] {
            let local = [1; CID_LEN];
            let remote = [2; CID_LEN];
            let mut handshake = vec![1];
            let h = header(version, 1, &local, &remote, &[], &mut handshake, 0).unwrap();
            let (_, second) = Writer::new(initial_keys(version, &remote, false).unwrap().local)
                .seal(&h, &handshake)
                .unwrap();
            let mut initial = vec![1];
            let h = header(
                version,
                0,
                &local,
                &remote,
                &[],
                &mut initial,
                MTU - second.len(),
            )
            .unwrap();
            let (_, mut first) = Writer::new(initial_keys(version, &remote, false).unwrap().local)
                .seal(&h, &initial)
                .unwrap();
            let first_len = first.len();
            first.extend_from_slice(&second);
            assert_eq!(first.len(), MTU);
            let packets = super::super::datagram::split(&first).unwrap();
            assert_eq!(packets.len(), 2);
            assert_eq!(packets[0].bytes.len(), first_len);
            assert_eq!(packets[1].bytes, second.as_slice());
        }
    }
}
