//! Loopback-only QUIC v1/v2 handshake experiment over UDP. TLS messages
//! travel exclusively in protected Initial and Handshake packets. Fixed
//! pre-arranged CIDs, no Retry/VN, no resumption, no H3.
//! This is not a production listener or Theia admission.
use super::{
    ack_tx::History, endpoint::LabSession, frames::{self, Frame},
    handshake::{Driver, Level}, initial::crypto_frame, packet::{self, Reader, Writer},
    parameters::{self, Parameters, PeerContext}, recovery::PathBudget,
    scheduler::Scheduler, spaces::Space, tls, wire::{encode_varint, varint, Version},
};
use rustls::{crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256, pki_types::ServerName,
    quic::{self, KeyChange, Keys, Secrets}, ClientConfig, ServerConfig, Side};
use std::{io, net::SocketAddr, sync::Arc, time::{Duration, Instant}};
use tokio::net::UdpSocket;

const MTU: usize = 1200;
const CHUNK: usize = 900;
const DEADLINE: Duration = Duration::from_secs(8);
const CID_LEN: usize = 8;
const CREDIT: u64 = 64 * 1024;
const STREAMS: u64 = 8;

#[derive(Debug)]
pub enum Error {
    Scope,
    Protocol,
    Timeout,
    Io(io::Error),
    Tls(rustls::Error),
    Driver(super::handshake::Error),
    Packet(packet::Error),
    Schedule(super::scheduler::Error),
    Endpoint(super::endpoint::Error),
}

pub enum Config {
    Client { tls: Arc<ClientConfig>, name: ServerName<'static> },
    Server(Arc<ServerConfig>),
}

struct Epoch {
    reader: Reader,
    writer: Writer,
    ack: History,
    schedule: Scheduler,
}

impl Epoch {
    fn new(keys: Keys) -> Self {
        Self { reader: Reader::new(keys.remote), writer: Writer::new(keys.local),
            ack: History::default(), schedule: Scheduler::default() }
    }
}

fn params(server: bool, local: &[u8; CID_LEN], original: &[u8; CID_LEN]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    parameters::append(&mut out, 0x0f, local).map_err(|_| Error::Protocol)?;
    if server { parameters::append(&mut out, 0x00, original).map_err(|_| Error::Protocol)?; }
    for (id, value) in [(0x03, MTU as u64), (0x04, CREDIT), (0x05, CREDIT), (0x06, CREDIT), (0x07, CREDIT), (0x08, STREAMS), (0x09, STREAMS)] {
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

/// Four-byte packet number and two-byte length, with padding INSIDE
/// Initial AEAD. Exactly one long-header packet per datagram.
fn header(version: Version, index: usize, local: &[u8; CID_LEN],
          remote: &[u8; CID_LEN], payload: &mut Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut out = vec![header_type(version, index)];
    out.extend_from_slice(&version.wire().to_be_bytes());
    out.push(CID_LEN as u8);
    out.extend_from_slice(remote);
    out.push(CID_LEN as u8);
    out.extend_from_slice(local);
    if index == 0 { out.push(0); }
    let overhead = out.len() + 2 + 4 + 16;
    if payload.is_empty() || overhead + payload.len() > MTU { return Err(Error::Protocol); }
    if index == 0 { payload.resize(MTU - overhead, 0); }
    let len = (4 + 16 + payload.len()) as u16;
    out.extend_from_slice(&(len | 0x4000).to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    Ok(out)
}

fn parse_header(packet: &[u8], version: Version, local: &[u8; CID_LEN],
                remote: &[u8; CID_LEN]) -> Option<(usize, usize)> {
    let ty = *packet.first()? & 0xf0;
    let index = if ty == header_type(version, 0) & 0xf0 { 0 }
        else if ty == header_type(version, 1) & 0xf0 { 1 } else { return None; };
    if packet.get(1..5)? != version.wire()
        || *packet.get(5)? != CID_LEN as u8 || packet.get(6..14)? != local
        || *packet.get(14)? != CID_LEN as u8 || packet.get(15..23)? != remote {
        return None;
    }
    let mut at = 23;
    if index == 0 && varint(packet, &mut at)? != 0 { return None; }
    let length = usize::try_from(varint(packet, &mut at)?).ok()?;
    if length < 20 || at.checked_add(length)? != packet.len() { return None; }
    Some((index, at))
}

struct Handshake {
    driver: Driver,
    epochs: [Option<Epoch>; 2],
    application: Option<(Keys, Secrets)>,
    budget: PathBudget,
    server: bool,
    version: Version,
    local: [u8; CID_LEN],
    remote: [u8; CID_LEN],
}

impl Handshake {
    fn collect(&mut self) -> Result<(), Error> {
        while let Some(flight) = self.driver.poll_output().map_err(Error::Driver)? {
            let index = flight.level as usize;
            // Tickets and other post-handshake CRYPTO are not supported by
            // this fixture. Do not silently drop bytes or reuse app keys.
            if index >= 2 && !flight.data.is_empty() { return Err(Error::Protocol); }
            for (i, chunk) in flight.data.chunks(CHUNK).enumerate() {
                let frame = crypto_frame(flight.offset + (i * CHUNK) as u64, chunk).map_err(|_| Error::Protocol)?;
                self.epochs[index].as_mut().ok_or(Error::Protocol)?.schedule.enqueue(frame).map_err(Error::Schedule)?;
            }
            match flight.keys {
                Some(KeyChange::Handshake { keys }) if self.epochs[1].is_none() => self.epochs[1] = Some(Epoch::new(keys)),
                Some(KeyChange::OneRtt { keys, next }) if self.application.is_none() => self.application = Some((keys, next)),
                Some(_) => return Err(Error::Protocol),
                None => {}
            }
        }
        Ok(())
    }

    async fn flush(&mut self, socket: &UdpSocket) -> Result<(), Error> {
        for (index, epoch) in self.epochs.iter_mut().enumerate() {
            let Some(epoch) = epoch else { continue; };
            let now = Instant::now();
            epoch.schedule.on_timer(now).map_err(Error::Schedule)?;
            let (mut payload, frame) = if let Some(ack) = epoch.ack.encode() {
                (ack, None)
            } else if let Some((id, data, probe)) = epoch.schedule.candidate(now).map_err(Error::Schedule)? {
                (data, Some((id, probe)))
            } else { continue; };
            let h = header(self.version, index, &self.local, &self.remote, &mut payload)?;
            let expected = h.len() + payload.len() + 16;
            if self.server && !self.budget.reserve_send(expected as u64) { continue; }
            let (number, packet) = epoch.writer.seal(&h, &payload).map_err(Error::Packet)?;
            epoch.schedule.record(number, packet.len(), frame, now).map_err(Error::Schedule)?;
            if socket.send(&packet).await.map_err(Error::Io)? != packet.len() { return Err(Error::Protocol); }
            if frame.is_none() { epoch.ack.sent(); }
        }
        Ok(())
    }

    fn receive_datagram(&mut self, datagram: &[u8]) -> Result<(), Error> {
        let Ok(packets) = super::datagram::split(datagram) else { return Ok(()); };
        for packet in packets {
            if !matches!(packet.kind, super::datagram::PacketKind::Initial | super::datagram::PacketKind::Handshake) {
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
        let Some((index, at)) = parse_header(packet, self.version, &self.local, &self.remote) else { return Ok(()); };
        let Some(epoch) = self.epochs[index].as_mut() else { return Ok(()); };
        let opened = match epoch.reader.open(packet, at) {
            Ok(p) => p,
            Err(packet::Error::Reserved | packet::Error::Limit) if index == 1 => return Err(Error::Protocol),
            Err(_) => return Ok(()),
        };
        let space = if index == 0 { Space::Initial } else { Space::Handshake };
        let level = if index == 0 { Level::Initial } else { Level::Handshake };
        let parsed = frames::decode(&opened.payload, space).map_err(|_| Error::Protocol)?;
        if self.server {
            self.budget.received(packet.len() as u64);
            // Only Handshake packet protection, never Initial, validates
            // the fixed client's address in this experiment.
            if index == 1 { self.budget.validate(); }
        }
        let mut eliciting = false;
        for frame in parsed {
            match frame {
                Frame::Padding => {}
                Frame::Ping => eliciting = true,
                Frame::Ack(ack) => epoch.schedule.acknowledge(&ack, Instant::now()).map_err(Error::Schedule)?,
                Frame::Crypto { offset, data } => {
                    self.driver.receive(level, offset, data).map_err(Error::Driver)?;
                    eliciting = true;
                }
                _ => return Err(Error::Protocol),
            }
        }
        epoch.ack.record(opened.number, eliciting);
        Ok(())
    }

    fn done(&self) -> bool {
        self.driver.tls_complete() && self.application.is_some()
            && self.epochs.iter().flatten().all(|epoch| epoch.schedule.pending() == 0 && !epoch.ack.pending())
    }
}

/// Complete TLS via actual UDP Initial/Handshake datagrams, then hand the
/// unused 1-RTT keys to the existing isolated session. Both peers must be
/// driven concurrently. Timeout/uncertain I/O drops the socket and keys.
/// A lost final ACK may time out; full QUIC draining is not implemented.
pub async fn establish(socket: UdpSocket, peer: SocketAddr, version: Version,
                       local: [u8; CID_LEN], remote: [u8; CID_LEN], config: Config) -> Result<LabSession, Error> {
    let address = socket.local_addr().map_err(Error::Io)?;
    if !address.ip().is_loopback() || !peer.ip().is_loopback() || peer.port() == 0
        || address == peer || local == remote || local == [0; CID_LEN] || remote == [0; CID_LEN] {
        return Err(Error::Scope);
    }
    let server = matches!(&config, Config::Server(_));
    let original = if server { local } else { remote };
    let parameters = params(server, &local, &original)?;
    let connection = match config {
        Config::Client { tls: config, name } => tls::client(config, version, name, parameters),
        Config::Server(config) => {
            if config.send_tls13_tickets != 0 { return Err(Error::Protocol); }
            tls::server(config, version, parameters)
        }
    }.map_err(Error::Tls)?;
    let suite = TLS13_AES_128_GCM_SHA256.tls13().and_then(|s| s.quic_suite()).ok_or(Error::Protocol)?;
    let version_tls = match version { Version::V1 => quic::Version::V1, Version::V2 => quic::Version::V2 };
    let keys = suite.keys(&original, if server { Side::Server } else { Side::Client }, version_tls);
    let mut handshake = Handshake { driver: Driver::new(connection), epochs: [Some(Epoch::new(keys)), None],
        application: None, budget: PathBudget::default(), server, version, local, remote };
    socket.connect(peer).await.map_err(Error::Io)?;
    tokio::time::timeout(DEADLINE, async {
        let mut buffer = [0; MTU + 1];
        loop {
            handshake.collect()?;
            handshake.flush(&socket).await?;
            if handshake.done() { break; }
            match tokio::time::timeout(Duration::from_millis(2), socket.recv(&mut buffer)).await {
                Ok(Ok(n)) if n <= MTU => handshake.receive_datagram(&buffer[..n])?,
                Ok(Ok(_)) | Err(_) => {}
                Ok(Err(e)) => return Err(Error::Io(e)),
            }
        }
        Ok::<(), Error>(())
    }).await.map_err(|_| Error::Timeout)??;
    if handshake.driver.negotiated_alpn() != Some(b"h3".as_slice()) { return Err(Error::Protocol); }
    let peer_params = Parameters::parse(handshake.driver.peer_parameters().ok_or(Error::Protocol)?)
        .map_err(|_| Error::Protocol)?;
    let limits = peer_params.validate(PeerContext { server: !server, initial_source: &remote,
        original_destination: &original, retry_source: None }).map_err(|_| Error::Protocol)?;
    if limits.max_data != CREDIT || limits.max_streams_uni != STREAMS
        || limits.max_streams_bidi != STREAMS || limits.max_udp_payload != MTU as u64
        || [0x05, 0x06, 0x07].into_iter().any(|id| peer_params.integer(id) != Ok(Some(CREDIT))) {
        return Err(Error::Protocol);
    }
    let (keys, secrets) = handshake.application.take().ok_or(Error::Protocol)?;
    LabSession::after_handshake(socket, peer, server, local, remote, keys, secrets)
        .await.map_err(Error::Endpoint)
}
