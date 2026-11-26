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
const DEADLINE: Duration = Duration::from_secs(8);
const CID_LEN: usize = 8;
const CREDIT: u64 = 64 * 1024;
const STREAMS: u64 = 8;

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
    fn new(keys: Keys) -> Self {
        Self {
            reader: Reader::new(keys.remote),
            writer: Writer::new(keys.local),
            ack: History::default(),
            schedule: Scheduler::default(),
        }
    }
}

fn params(
    server: bool,
    version: Version,
    versions: &VersionPolicy,
    local: &[u8; CID_LEN],
    original: &[u8; CID_LEN],
    retry: Option<&[u8; CID_LEN]>,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    parameters::append(&mut out, 0x11, &versions.information(version, server)).map_err(|_| Error::Protocol)?;
    parameters::append(&mut out, 0x0f, local).map_err(|_| Error::Protocol)?;
    if server {
        parameters::append(&mut out, 0x00, original).map_err(|_| Error::Protocol)?;
    }
    if server {
        if let Some(cid) = retry {
            parameters::append(&mut out, 0x10, cid).map_err(|_| Error::Protocol)?;
        }
    }
    for (id, value) in [
        (0x01, 30_000),
        (0x03, MTU as u64),
        (0x04, CREDIT),
        (0x05, CREDIT),
        (0x06, CREDIT),
        (0x07, CREDIT),
        (0x08, STREAMS),
        (0x09, STREAMS),
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

/// Four-byte packet number and two-byte length, with padding INSIDE
/// Initial AEAD. Exactly one long-header packet per datagram.
fn header(
    version: Version,
    index: usize,
    local: &[u8; CID_LEN],
    remote: &[u8; CID_LEN],
    token: &[u8],
    payload: &mut Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let mut out = vec![header_type(version, index)];
    out.extend_from_slice(&version.wire().to_be_bytes());
    out.push(CID_LEN as u8);
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
    if index == 0 {
        payload.resize(MTU - overhead, 0);
    }
    let len = (4 + 16 + payload.len()) as u16;
    out.extend_from_slice(&(len | 0x4000).to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    Ok(out)
}

fn parse_header(
    packet: &[u8],
    version: Version,
    local: &[u8; CID_LEN],
    remote: &[u8; CID_LEN],
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
    if packet.get(1..5)? != version.wire().to_be_bytes()
        || *packet.get(5)? != CID_LEN as u8
        || packet.get(6..14)? != local
        || *packet.get(14)? != CID_LEN as u8
        || packet.get(15..23)? != remote
    {
        return None;
    }
    let mut at = 23;
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

struct Handshake {
    driver: Driver,
    epochs: [Option<Epoch>; 2],
    application: Option<(Keys, Secrets)>,
    budget: PathBudget,
    server: bool,
    version: Version,
    local: [u8; CID_LEN],
    remote: [u8; CID_LEN],
    original: [u8; CID_LEN],
    retry: Option<[u8; CID_LEN]>,
    token: Vec<u8>,
    peer_progress: bool,
    initial_frames: Vec<Vec<u8>>,
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
                    self.epochs[1] = Some(Epoch::new(keys))
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

    async fn flush(&mut self, socket: &SessionIo, peer: SocketAddr) -> Result<(), Error> {
        let mut discard_initial = false;
        for (index, epoch) in self.epochs.iter_mut().enumerate() {
            let Some(epoch) = epoch else {
                continue;
            };
            let now = Instant::now();
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
            let h = header(
                self.version,
                index,
                &self.local,
                &self.remote,
                token,
                &mut payload,
            )?;
            let expected = h.len() + payload.len() + 16;
            if self.server && !self.budget.reserve_send(expected as u64) {
                continue;
            }
            let (number, packet) = epoch.writer.seal(&h, &payload).map_err(Error::Packet)?;
            epoch
                .schedule
                .record(number, packet.len(), frame, now)
                .map_err(Error::Schedule)?;
            if socket.send_to(&packet, peer).await.map_err(Error::Io)? != packet.len() {
                return Err(Error::Protocol);
            }
            if frame.is_none() {
                epoch.ack.sent();
            }
            // Client discards Initial only after actually sending a
            // protected Handshake packet (RFC 9001 section 4.9.1).
            if !self.server && index == 1 {
                discard_initial = true;
            }
        }
        if discard_initial {
            self.epochs[0] = None;
        }
        Ok(())
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
        let Ok(cid) = <[u8; CID_LEN]>::try_from(cid) else {
            return Ok(());
        };
        // Bound the opaque token to leave room for the original CRYPTO chunks.
        if cid == self.local || token.is_empty() || token.len() > 200 {
            return Ok(());
        }
        let next = self.epochs[0]
            .as_ref()
            .ok_or(Error::Protocol)?
            .writer
            .next();
        let keys = initial_keys(self.version, &cid, false)?;
        let mut epoch = Epoch::new(keys);
        // Keep TLS and CRYPTO offsets; only Initial protection and recovery
        // are reset. The packet number MUST continue across Retry.
        let keys = initial_keys(self.version, &cid, false)?;
        epoch.writer = Writer::with_next(keys.local, next);
        epoch.schedule = Scheduler::after_retry(next);
        for frame in self.initial_frames.drain(..) {
            epoch.schedule.enqueue(frame).map_err(Error::Schedule)?;
        }
        self.epochs[0] = Some(epoch);
        self.remote = cid;
        self.retry = Some(cid);
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
                    if let Ok(offered) = super::negotiation::version_candidates(packet.bytes, self.version, &self.local, &self.original, self.peer_progress) {
                        if let Some(version) = self.versions.choose(&offered) { return Err(Error::VersionNegotiation(version)); }
                    }
                }
                continue;
            }
            if packet.kind == super::datagram::PacketKind::Retry {
                self.apply_retry(packet.bytes)?;
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
        let Some((index, at)) =
            parse_header(packet, self.version, &self.local, &self.remote, token)
        else {
            return Ok(());
        };
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
            && self
                .epochs
                .iter()
                .flatten()
                .all(|epoch| epoch.schedule.pending() == 0 && !epoch.ack.pending())
    }
}

/// Complete TLS via actual UDP Initial/Handshake datagrams, then hand the
/// unused 1-RTT keys to the existing isolated session. Both peers must be
/// driven concurrently. Timeout/uncertain I/O drops the socket and keys.
/// A lost final ACK may time out; full QUIC draining is not implemented.
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
            remote,
            original,
            retry: None,
            token: Vec::new(),
            versions: if server { VersionPolicy::both() } else { VersionPolicy::exact(version) },
            restarted: false,
        },
        config,
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
pub async fn connect_versions(local: SocketAddr, peer: SocketAddr, versions: VersionPolicy,
    tls: Arc<ClientConfig>, name: ServerName<'static>) -> Result<(Version, LabSession), Error> {
    let mut version = versions.preferred();
    for restarted in [false, true] {
        let socket = UdpSocket::bind(local).await.map_err(Error::Io)?;
        if !super::loopback_pair(socket.local_addr().map_err(Error::Io)?, peer) { return Err(Error::Scope); }
        let cid = super::negotiation::random_cid().map_err(|_| Error::Protocol)?;
        let original = super::negotiation::random_cid().map_err(|_| Error::Protocol)?;
        if cid == original || cid == [0; CID_LEN] || original == [0; CID_LEN] { return Err(Error::Protocol); }
        let route = InitialRoute { version, local: cid, remote: original, original, retry: None,
            token: Vec::new(), versions: versions.clone(), restarted };
        match establish_inner(socket.into(), peer, route, Config::Client { tls: tls.clone(), name: name.clone() }).await {
            Ok(session) => return Ok((version, session)),
            Err(Error::VersionNegotiation(next)) if !restarted && next != version && versions.supports(next) => version = next,
            Err(error) => return Err(error),
        }
    }
    Err(Error::Protocol)
}

/// The candidate is created exclusively after the listener validates Retry.
/// TLS and CID parameters must still authenticate before returning a session.
pub async fn accept(candidate: Candidate, tls: Arc<ServerConfig>) -> Result<LabSession, Error> {
    let (socket, peer, binding, token, versions) = candidate.into_parts();
    let original =
        <[u8; CID_LEN]>::try_from(binding.original.as_slice()).map_err(|_| Error::Protocol)?;
    let remote =
        <[u8; CID_LEN]>::try_from(binding.client.as_slice()).map_err(|_| Error::Protocol)?;
    if remote == binding.retry || remote == [0; CID_LEN] || original == [0; CID_LEN] {
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
            retry: Some(binding.retry),
            token,
            versions,
            restarted: false,
        },
        Config::Server(tls),
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
    remote: [u8; CID_LEN],
    original: [u8; CID_LEN],
    retry: Option<[u8; CID_LEN]>,
    token: Vec<u8>,
    versions: VersionPolicy,
    restarted: bool,
}

async fn establish_inner(
    mut socket: SessionIo,
    peer: SocketAddr,
    route: InitialRoute,
    config: Config,
) -> Result<LabSession, Error> {
    let InitialRoute {
        version,
        local,
        remote,
        original,
        retry,
        token,
        versions,
        restarted,
    } = route;
    let server = matches!(&config, Config::Server(_));
    let parameters = params(server, version, &versions, &local, &original, retry.as_ref())?;
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
    let destination = retry.as_ref().unwrap_or(&original);
    let keys = initial_keys(version, destination, server)?;
    let mut handshake = Handshake {
        driver: Driver::new(connection),
        epochs: [Some(Epoch::new(keys)), None],
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
        versions,
        restarted,
    };
    if server && retry.is_some() {
        handshake.budget.validate();
    }
    if socket.peer_addr().is_ok() {
        return Err(Error::Scope);
    }
    tokio::time::timeout(DEADLINE, async {
        let mut buffer = [0; MTU + 1];
        loop {
            handshake.collect()?;
            handshake.flush(&socket, peer).await?;
            if handshake.done() {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(2), socket.recv_from(&mut buffer))
                .await
            {
                Ok(Ok((n, source))) if source == peer && n <= MTU => {
                    handshake.receive_datagram(&buffer[..n])?
                }
                Ok(Ok(_)) | Err(_) => {}
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
    handshake.versions.validate_information(peer_params.get(0x11), version, !server, restarted).map_err(|_| Error::Protocol)?;
    let limits = peer_params
        .validate(PeerContext {
            server: !server,
            initial_source: &handshake.remote,
            original_destination: &original,
            retry_source: if server {
                None
            } else {
                handshake.retry.as_ref().map(|cid| cid.as_slice())
            },
        })
        .map_err(|_| Error::Protocol)?;
    if limits.max_data != CREDIT
        || limits.max_streams_uni != STREAMS
        || limits.max_streams_bidi != STREAMS
        || limits.max_udp_payload != MTU as u64
        || [0x05, 0x06, 0x07]
            .into_iter()
            .any(|id| peer_params.integer(id) != Ok(Some(CREDIT)))
    {
        return Err(Error::Protocol);
    }
    let peer_idle = peer_params
        .integer(0x01)
        .map_err(|_| Error::Protocol)?
        .unwrap_or(0);
    let idle_timeout = Duration::from_millis(if peer_idle == 0 {
        30_000
    } else {
        peer_idle.min(30_000)
    });
    let binding = handshake.driver.channel_binding().map_err(Error::Driver)?;
    let (keys, secrets) = handshake.application.take().ok_or(Error::Protocol)?;
    LabSession::after_handshake(
        socket,
        peer,
        server,
        local,
        handshake.remote,
        super::endpoint::Established {
            keys,
            secrets,
            idle_timeout,
            binding,
        },
    )
    .await
    .map_err(Error::Endpoint)
}
