//! External QUIC v1/v2 reference relay for a prepared REALITY generation.
//! The relay never terminates reference TLS or rewrites datagrams. Admission
//! is decided before opening a reference socket. A valid marker is handed
//! exclusively to the local QUIC endpoint via a bounded virtual UDP socket.
//! Startup supplies one immutable, independently approved generation.
#![forbid(unsafe_code)]

use crate::{
    config::Config,
    identity_tls::Branch,
    reality_generation::{Lease, Manager},
    reality_live::{Live, Route},
    reality_quic_wire::{self as wire, Cid, Flight, Inspection, Kind},
    server::{self, ServerContext, ServerError},
};
use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, ConnectionId, ConnectionIdGenerator, Endpoint, EndpointConfig, TokioRuntime,
    UdpPoller,
};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch, Semaphore},
    task::JoinSet,
    time::{timeout, Instant},
};
use zeroize::Zeroizing;

const SESSIONS: usize = 64;
const RETIRED_LIMIT: usize = 256;
const RETIRED_TTL: Duration = Duration::from_secs(60);
const PATHS: usize = 4;
const CIDS: usize = 8;
const QUEUE: usize = 16;
const LOCAL_MAX: usize = 1472;
const LOCAL_CID_LEN: usize = 20;
const MAX_FIRST_BYTES: usize = 64 * 1024;
const FIRST_DEADLINE: Duration = Duration::from_secs(3);
const LIFETIME: Duration = Duration::from_secs(60);
const IDLE: Duration = Duration::from_secs(15);
const BYTES: usize = 8 * 1024 * 1024;
const DNS_DEADLINE: Duration = Duration::from_secs(5);
type SessionId = u64;

#[derive(Default)]
struct Budget {
    received: usize,
    sent: usize,
}
impl Budget {
    fn credit(&mut self, n: usize) {
        self.received = self.received.saturating_add(n);
    }
    fn allows(&self, n: usize) -> bool {
        self.sent.saturating_add(n) <= self.received.saturating_mul(3)
    }
    fn debit(&mut self, n: usize) {
        self.sent = self.sent.saturating_add(n);
    }
}

struct Path {
    queue: mpsc::Sender<Vec<u8>>,
    budget: Budget,
    last: Instant,
}
struct Retry {
    cid: Cid,
    token: Vec<u8>,
}
struct Session {
    original: Cid,
    client: Cid,
    original_version: u32,
    negotiated_version: Option<u32>,
    server: HashSet<Cid>,
    retry: Option<Retry>,
    retry_echoed: bool,
    server_initial: bool,
    initial_server_cid: Option<Cid>,
    first_peer: SocketAddr,
    paths: HashMap<SocketAddr, Path>,
    deadline: Instant,
    last: Instant,
    remaining: usize,
    paths_opened: usize,
    closed_paths: HashSet<SocketAddr>,
    generation: Option<Arc<Lease>>,
    reference_signer: Option<[u8; 32]>,
}
impl Session {
    fn new(peer: SocketAddr, original: Cid, client: Cid, version: u32, now: Instant) -> Self {
        Self {
            original,
            client,
            original_version: version,
            negotiated_version: None,
            server: HashSet::new(),
            retry: None,
            retry_echoed: false,
            server_initial: false,
            initial_server_cid: None,
            first_peer: peer,
            paths: HashMap::new(),
            deadline: now + LIFETIME,
            last: now,
            remaining: BYTES,
            paths_opened: 0,
            closed_paths: HashSet::new(),
            generation: None,
            reference_signer: None,
        }
    }
    fn expired(&self, now: Instant) -> bool {
        now >= self.deadline
            || now.saturating_duration_since(self.last) >= IDLE
            || self.remaining == 0
    }
    fn prune_paths(&mut self, now: Instant) {
        self.paths.retain(|peer, path| {
            let keep = !path.queue.is_closed() && now.saturating_duration_since(path.last) < IDLE;
            if !keep {
                self.closed_paths.insert(*peer);
            }
            keep
        });
    }
    fn known(&self, datagram: &[u8]) -> bool {
        if let Some(h) = wire::long(datagram) {
            h.kind != Kind::Retry
                && h.kind != Kind::VersionNegotiation
                && (h.dcid == self.original || self.server.contains(h.dcid))
                && (h.kind != Kind::Initial || h.scid == self.client)
        } else {
            self.initial_server_cid
                .as_ref()
                .is_some_and(|cid| wire::short_matches(datagram, cid))
        }
    }
    fn allows_client(&self, peer: SocketAddr, datagram: &[u8]) -> bool {
        if let Some(h) = wire::long(datagram) {
            if !wire::coherent_datagram(datagram) {
                return false;
            }
            if peer != self.first_peer {
                return false;
            }
            let version = self.negotiated_version.unwrap_or(self.original_version);
            if h.version != version {
                return false;
            }
            if h.kind == Kind::Initial {
                if datagram.len() < wire::MIN_INITIAL || h.scid != self.client {
                    return false;
                }
                if let Some(retry) = &self.retry {
                    // The first post-Retry Initial must echo the exact
                    // token on the original path. Do not accept another
                    // server CID as a replacement before that exchange.
                    return peer == self.first_peer
                        && h.token == retry.token
                        && (h.dcid == retry.cid
                            || (self.retry_echoed
                                && self.server_initial
                                && self.server.contains(h.dcid)));
                }
            }
            self.known(datagram)
                || self
                    .initial_server_cid
                    .as_deref()
                    .is_some_and(|cid| cid.is_empty() && h.dcid.is_empty())
        } else {
            self.server_initial
                && datagram.len() >= 18
                && datagram.first().is_some_and(|b| b & 0x80 == 0)
                && (self.paths.contains_key(&peer) || self.known(datagram))
        }
    }

    // Accept only public CIDs learned from the connected reference socket.
    // NEW_CONNECTION_ID / RETIRE_CONNECTION_ID are encrypted, so a passive
    // relay cannot learn them from 1-RTT packets. Never guess a new CID length.
    fn observe_reference(&mut self, peer: SocketAddr, packet: &[u8]) -> bool {
        if let Some(h) = wire::long(packet) {
            if !wire::coherent_datagram(packet) {
                return false;
            }
            if h.dcid != self.client {
                return false;
            }
            if h.kind == Kind::VersionNegotiation {
                // VN is advisory, never a path validation or CID update.
                return peer == self.first_peer
                    && self.retry.is_none()
                    && !self.server_initial
                    && h.scid == self.original;
            }
            if h.kind == Kind::Retry {
                if h.version != self.original_version
                    || peer != self.first_peer
                    || self.server_initial
                    || h.scid.is_empty()
                    || h.scid == self.original
                    || !wire::retry_valid(packet, &self.original)
                {
                    return false;
                }
                if let Some(old) = &self.retry {
                    return old.cid == h.scid && old.token == h.token;
                }
                if !self.server.is_empty() {
                    return false;
                }
                self.retry = Some(Retry {
                    cid: h.scid.to_vec(),
                    token: h.token.to_vec(),
                });
            } else if h.kind != Kind::Initial && h.kind != Kind::Handshake {
                return false;
            } else {
                if self.retry.is_some() && !self.retry_echoed {
                    return false;
                }
                // Compatible v1/v2 negotiation may change version on the
                // first server Initial, never on Retry or a later packet.
                if let Some(version) = self.negotiated_version {
                    if h.version != version {
                        return false;
                    }
                } else {
                    if peer != self.first_peer || h.kind != Kind::Initial {
                        return false;
                    }
                    self.negotiated_version = Some(h.version);
                }
                if let Some(cid) = &self.initial_server_cid {
                    if h.scid != cid.as_slice() {
                        return false;
                    }
                } else {
                    if h.kind != Kind::Initial || peer != self.first_peer {
                        return false;
                    }
                    self.initial_server_cid = Some(h.scid.to_vec());
                }
                if h.kind == Kind::Initial {
                    self.server_initial = true;
                }
            }
            if !h.scid.is_empty() && !self.server.contains(h.scid) {
                if self.server.len() == CIDS {
                    return false;
                }
                self.server.insert(h.scid.to_vec());
            }
            true
        } else {
            self.server_initial
                && packet.len() >= 18
                && packet.first().is_some_and(|b| b & 0x80 == 0)
                && self.paths.contains_key(&peer)
        }
    }

    fn enqueue(&mut self, peer: SocketAddr, data: Vec<u8>, now: Instant) {
        let n = data.len();
        if n > self.remaining {
            return;
        }
        let echoed = peer == self.first_peer
            && self.retry.as_ref().is_some_and(|retry| {
                wire::long(&data).is_some_and(|h| {
                    h.kind == Kind::Initial
                        && h.dcid == retry.cid
                        && h.token == retry.token
                        && h.scid == self.client
                })
            });
        let Some(path) = self.paths.get_mut(&peer) else {
            return;
        };
        if now.saturating_duration_since(path.last) >= IDLE || path.queue.is_closed() {
            return;
        }
        if path.queue.try_send(data).is_ok() {
            self.remaining -= n;
            path.budget.credit(n);
            path.last = now;
            self.last = now;
            self.retry_echoed |= echoed;
        }
    }
    fn can_reply(&self, peer: SocketAddr, n: usize) -> bool {
        n <= self.remaining
            && self.paths.get(&peer).is_some_and(|p| {
                !p.queue.is_closed()
                    && p.budget.allows(n)
                    && Instant::now().saturating_duration_since(p.last) < IDLE
            })
    }
    fn sent(&mut self, peer: SocketAddr, n: usize, now: Instant) {
        if let Some(path) = self.paths.get_mut(&peer) {
            path.budget.debit(n);
            path.last = now;
            self.remaining -= n;
            self.last = now;
        }
    }
}

/// Bounded cooldown retains public routing identifiers, not packets or
/// sockets. A retired Initial cannot instantly recreate the same quota
/// window. Reserve one retirement slot for every active relay session.
struct Retired {
    original: Cid,
    client: Cid,
    server: HashSet<Cid>,
    peers: HashSet<SocketAddr>,
    until: Instant,
}
impl Retired {
    fn from_session(session: Session, now: Instant) -> Self {
        let mut peers = session.closed_paths;
        peers.extend(session.paths.keys().copied());
        peers.insert(session.first_peer);
        Self {
            original: session.original,
            client: session.client,
            server: session.server,
            peers,
            until: now + RETIRED_TTL,
        }
    }
    fn blocks(&self, peer: SocketAddr, bytes: &[u8], now: Instant) -> bool {
        if now >= self.until {
            return false;
        }
        if let Some(h) = wire::long(bytes) {
            return (self.peers.contains(&peer)
                && h.dcid == self.original
                && h.scid == self.client)
                || self.server.contains(h.dcid);
        }
        self.server
            .iter()
            .any(|cid| wire::short_matches(bytes, cid))
    }
}

struct Pending {
    flight: Flight,
    client: Cid,
    version: u32,
    datagrams: Vec<Vec<u8>>,
    bytes: usize,
    deadline: Instant,
}
impl Pending {
    fn add(&mut self, data: Vec<u8>) -> Option<Inspection> {
        let h = wire::long(&data)?;
        if h.kind != Kind::Initial || h.version != self.version || h.scid != self.client.as_slice()
        {
            return None;
        }
        let total = self.bytes.checked_add(data.len())?;
        if total > MAX_FIRST_BYTES || self.datagrams.len() >= QUEUE {
            return None;
        }
        let decision = self.flight.inspect(&data);
        self.datagrams.push(data);
        self.bytes = total;
        Some(decision)
    }
}

struct Reply {
    id: SessionId,
    peer: SocketAddr,
    data: Vec<u8>,
}
fn wildcard(ip: IpAddr) -> SocketAddr {
    match ip {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

/// Each physical client path has its own connected upstream socket. A CID
/// seen from a second address does not redirect or validate the old path.
/// Responses return only to the physical peer owning this socket.
async fn reference_path(
    generation: Arc<Lease>,
    signer: [u8; 32],
    id: SessionId,
    peer: SocketAddr,
    deadline: Instant,
    incoming: mpsc::Receiver<Vec<u8>>,
    replies: mpsc::Sender<Reply>,
) {
    let publication = generation.publication();
    let Ok(now) = crate::reference_health::unix_now() else {
        return;
    };
    // A session pins the signer/reference selected at its creation. When
    // overlap expires, a new path cannot silently switch to the successor's
    // reference; if this exact descriptor is no longer valid, close the path.
    let Ok(material) = publication.select(signer, now) else {
        return;
    };
    let value = material.verified();
    let Ok(Ok(lease)) = timeout(
        DNS_DEADLINE,
        generation
            .health()
            .relay_lease(value, publication.plan_sha256()),
    )
    .await
    else {
        return;
    };
    let Ok(address) = lease.address() else {
        return;
    };
    let Ok(socket) = UdpSocket::bind(wildcard(address.ip())).await else {
        return;
    };
    if socket.connect(address).await.is_err() || lease.address().ok() != Some(address) {
        return;
    }
    pump_path(socket, id, peer, deadline, incoming, replies, || {
        lease.address().is_ok()
    })
    .await;
}

async fn pump_path(
    socket: UdpSocket,
    id: SessionId,
    peer: SocketAddr,
    deadline: Instant,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    replies: mpsc::Sender<Reply>,
    eligible: impl Fn() -> bool,
) {
    let mut buf = vec![0; wire::MAX_DATAGRAM + 1];
    loop {
        if incoming.is_closed() || !eligible() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return,
            data = incoming.recv() => {
                let Some(data) = data else { return; };
                if incoming.is_closed() || !eligible() { return; }
                if !matches!(timeout(Duration::from_secs(1), socket.send(&data)).await,
                    Ok(Ok(n)) if n == data.len()) { return; }
            }
            result = socket.recv(&mut buf) => {
                let Ok(n) = result else { return; };
                if incoming.is_closed() || !eligible() { return; }
                if n > 0 && n <= wire::MAX_DATAGRAM {
                    let _ = replies.try_send(Reply { id, peer, data: buf[..n].to_vec() });
                }
            }
        }
    }
}

fn unique<I: Iterator<Item = SessionId>>(mut ids: I) -> Option<SessionId> {
    let first = ids.next()?;
    ids.next().is_none().then_some(first)
}
fn route(
    sessions: &HashMap<SessionId, Session>,
    peer: SocketAddr,
    bytes: &[u8],
    admitted_peer: bool,
) -> Option<SessionId> {
    let known = || sessions.iter().filter(|(_, s)| s.known(bytes));
    let mut global = known();
    if let Some((&id, session)) = global.next() {
        // Even on an existing tuple, prefix collisions are ambiguous.
        // A tuple is not proof of association with one of several CIDs.
        if global.next().is_some() {
            return None;
        }
        return (session.paths.contains_key(&peer) || bytes[0] & 0x80 == 0).then_some(id);
    }
    if wire::long(bytes).is_some_and(|h| h.dcid.is_empty() && h.kind == Kind::Handshake) {
        return unique(
            sessions
                .iter()
                .filter(|(_, s)| {
                    s.first_peer == peer && s.initial_server_cid.as_deref() == Some(&[])
                })
                .map(|(&id, _)| id),
        );
    }
    // On an existing, unambiguous physical tuple the reference can decrypt
    // packets carrying an encrypted, newly issued CID. Do not learn it from
    // unauthenticated bytes or guess which of several connections owns it.
    if admitted_peer || bytes.len() < 18 || !bytes.first().is_some_and(|b| b & 0x80 == 0) {
        return None;
    }
    unique(
        sessions
            .iter()
            .filter(|(_, s)| s.paths.contains_key(&peer))
            .map(|(&id, _)| id),
    )
}

// A generation-specific authenticated CID namespace permits routing all
// native Quinn-issued CIDs, including encrypted NEW_CONNECTION_ID frames.
// It does not authenticate packets, grant admission, or validate a path.
// The pseudorandom prefix hides the counter and the independent tag avoids
// a visible generation identifier. Quinn owns connection/retirement state.
struct LocalCidKey {
    key: hmac::Key,
    sequence: AtomicU64,
}
impl LocalCidKey {
    fn fresh() -> Result<Self, ServerError> {
        let mut secret = Zeroizing::new([0u8; 32]);
        SystemRandom::new()
            .fill(&mut secret[..])
            .map_err(|_| ServerError::Tls)?;
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &secret[..]),
            sequence: AtomicU64::new(0),
        })
    }
    fn tag(&self, prefix: &[u8]) -> hmac::Tag {
        let mut mac = hmac::Context::with_key(&self.key);
        mac.update(b"Theia/QUIC/local-cid/tag/v1");
        mac.update(prefix);
        mac.sign()
    }
    fn matches(&self, cid: &[u8]) -> bool {
        if cid.len() != LOCAL_CID_LEN {
            return false;
        }
        let tag = self.tag(&cid[..10]);
        bool::from(cid[10..].ct_eq(&tag.as_ref()[..10]))
    }
    fn next(&self) -> [u8; LOCAL_CID_LEN] {
        let counter = self.sequence.fetch_add(1, Ordering::Relaxed);
        let mut mac = hmac::Context::with_key(&self.key);
        mac.update(b"Theia/QUIC/local-cid/prefix/v1");
        mac.update(&counter.to_be_bytes());
        let prefix = mac.sign();
        let mut cid = [0; LOCAL_CID_LEN];
        cid[..10].copy_from_slice(&prefix.as_ref()[..10]);
        let tag = self.tag(&cid[..10]);
        cid[10..].copy_from_slice(&tag.as_ref()[..10]);
        cid
    }
}
struct NativeCids(Arc<LocalCidKey>);
impl ConnectionIdGenerator for NativeCids {
    fn generate_cid(&mut self) -> ConnectionId {
        ConnectionId::new(&self.0.next())
    }
    fn cid_len(&self) -> usize {
        LOCAL_CID_LEN
    }
    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

// Quinn receives the original physical source address, not a loopback proxy
// address. Its own authenticated path validation and amplification rules
// therefore remain applicable. No extra listener can bypass admission.
// When a bounded queue or OS send buffer fills, UDP may drop a datagram.
struct LocalSocket {
    socket: Arc<UdpSocket>,
    receive: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
}
impl fmt::Debug for LocalSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RealityQuicSocket(<redacted>)")
    }
}
#[derive(Debug)]
struct Ready;
impl UdpPoller for Ready {
    fn poll_writable(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncUdpSocket for LocalSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Ready)
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // GSO is not advertised; no packet splitting or byte rewriting.
        if transmit.segment_size.is_some() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let result = self
            .socket
            .try_send_to(transmit.contents, transmit.destination);
        match result {
            Ok(n) if n == transmit.contents.len() => Ok(()),
            Ok(_) => Err(io::ErrorKind::WriteZero.into()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }
    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut receiver = self
            .receive
            .lock()
            .map_err(|_| io::Error::other("QUIC receive lock"))?;
        match receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Some((addr, bytes))) => {
                if bytes.len() > bufs[0].len() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                bufs[0][..bytes.len()].copy_from_slice(&bytes);
                meta[0] = RecvMeta {
                    addr,
                    len: bytes.len(),
                    stride: bytes.len(),
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    fn may_fragment(&self) -> bool {
        true
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// Actual UDP composition for a single prepared generation. No wildcard
/// reference destinations, caller-supplied routing addresses, or detached
/// workers. The normal REALITY startup shares its captured generation.
pub struct PreparedQuic {
    socket: Arc<UdpSocket>,
    endpoint: Endpoint,
    local: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    local_cids: Arc<LocalCidKey>,
    path_slots: Arc<Semaphore>,
    live: Arc<Live>,
    tickets: Arc<Mutex<HashMap<(SocketAddr, Cid), Ticket>>>,
}
struct Ticket {
    route: Arc<Route>,
    until: Instant,
}
impl PreparedQuic {
    pub fn prepare(
        socket: UdpSocket,
        document: &Config,
        inbound_id: &str,
    ) -> Result<Self, ServerError> {
        let Config::Server(doc) = document else {
            return Err(ServerError::Config);
        };
        let inbound = doc
            .server
            .inbounds
            .iter()
            .find(|i| i.id == inbound_id)
            .ok_or(ServerError::Config)?;
        let expected: SocketAddr = inbound
            .quic_listen
            .parse()
            .map_err(|_| ServerError::Config)?;
        if socket.local_addr().map_err(|_| ServerError::Io)? != expected {
            return Err(ServerError::Config);
        }
        let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
        let manager = Manager::new(document, inbound_id, now).map_err(|_| ServerError::Config)?;
        let generation = Arc::new(manager.refresh(now).map_err(|_| ServerError::Config)?);
        let context = Arc::new(ServerContext::new(
            inbound,
            &doc.server.users,
            &doc.server.policy,
        ));
        Self::from_shared(socket, generation, context, now)
    }

    pub(crate) fn from_shared(
        socket: UdpSocket,
        generation: Arc<Lease>,
        context: Arc<ServerContext>,
        now: u64,
    ) -> Result<Self, ServerError> {
        Self::from_live(socket, Live::new(generation, context, now)?)
    }

    pub(crate) fn from_live(socket: UdpSocket, live: Arc<Live>) -> Result<Self, ServerError> {
        let server = live
            .current()
            .and_then(|g| g.default_quic())
            .ok_or(ServerError::Config)?;
        let socket = Arc::new(socket);
        let (local, rx) = mpsc::channel(SESSIONS * 2);
        let local_cids = Arc::new(LocalCidKey::fresh()?);
        let mut endpoint_config = EndpointConfig::default();
        let cid_key = local_cids.clone();
        endpoint_config.cid_generator(move || Box::new(NativeCids(cid_key.clone())));
        endpoint_config
            .max_udp_payload_size(LOCAL_MAX as u16)
            .map_err(|_| ServerError::Config)?;
        let virtual_socket = Arc::new(LocalSocket {
            socket: socket.clone(),
            receive: Mutex::new(rx),
        });
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server),
            virtual_socket,
            Arc::new(TokioRuntime),
        )
        .map_err(|_| ServerError::Io)?;
        Ok(Self {
            socket,
            endpoint,
            local,
            local_cids,
            live,
            tickets: Arc::new(Mutex::new(HashMap::new())),
            path_slots: Arc::new(Semaphore::new(SESSIONS * PATHS)),
        })
    }

    pub async fn serve(self) -> Result<(), ServerError> {
        let (_owner, phase) = watch::channel(server::GenerationPhase::Active);
        self.serve_generation(phase).await
    }

    pub(crate) async fn serve_generation(
        self,
        phase: watch::Receiver<server::GenerationPhase>,
    ) -> Result<(), ServerError> {
        let endpoint = self.endpoint.clone();
        let result = tokio::select! {
            result = self.accept_native(phase.clone()) => result,
            result = self.dispatch(phase) => result,
        };
        endpoint.close(0u32.into(), b"backend closed");
        result
    }

    async fn accept_native(
        &self,
        mut phase: watch::Receiver<server::GenerationPhase>,
    ) -> Result<(), ServerError> {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _=server::await_generation_drain(&mut phase)=>break,
                _=tasks.join_next(),if !tasks.is_empty()=>{},
                incoming=self.endpoint.accept()=>{
                    let Some(incoming)=incoming else{return Err(ServerError::Io);};
                    let key=(incoming.remote_address(),incoming.orig_dst_cid().to_vec());
                    let ticket=self.tickets.lock().map_err(|_|ServerError::Io)?.remove(&key);
                    let Some(ticket)=ticket else{incoming.ignore();continue;};
                    let Ok(now)=crate::reference_health::unix_now() else{incoming.ignore();continue;};
                    let still_current=self.live.current().is_some_and(|g|
                        (g.lease.publication().snapshot_sha256(),g.lease.status().health_revision)==ticket.route.generation_id());
                    if ticket.until<=Instant::now() || !still_current || !ticket.route.current(now) {
                        incoming.ignore();continue;
                    }
                    let Some(config)=ticket.route.quic.clone() else{incoming.ignore();continue;};
                    let context=ticket.route.context.clone();
                    let Some(slot)=context.connection_slot() else{incoming.refuse();continue;};
                    let connection_phase=phase.clone();
                    tasks.spawn(async move{
                        let _slot=slot;
                        if let Ok(connection)=crate::quic_transport::accept_with(incoming,config).await{
                            crate::h3_server::run_connection(connection,context,connection_phase).await;
                        }
                    });
                }
            }
        }
        // The dispatcher remains alive in serve_generation while native
        // streams drain; new unclassified sessions are no longer admitted.
        let _ = timeout(server::GENERATION_DRAIN, async {
            while !tasks.is_empty() {
                tokio::select! {
                    _=tasks.join_next()=>{},
                    incoming=self.endpoint.accept()=> {
                        if let Some(incoming)=incoming { incoming.refuse(); } else { break; }
                    }
                }
            }
        })
        .await;
        Ok(())
    }

    fn open_path(
        &self,
        workers: &mut JoinSet<()>,
        replies: &mpsc::Sender<Reply>,
        id: SessionId,
        session: &mut Session,
        peer: SocketAddr,
    ) -> bool {
        if let Some(path) = session.paths.get(&peer) {
            return !path.queue.is_closed();
        }
        if session.closed_paths.contains(&peer) || session.paths_opened >= PATHS {
            return false;
        }
        let Ok(slot) = self.path_slots.clone().try_acquire_owned() else {
            return false;
        };
        let (tx, rx) = mpsc::channel(QUEUE);
        session.paths.insert(
            peer,
            Path {
                queue: tx,
                budget: Budget::default(),
                last: Instant::now(),
            },
        );
        session.paths_opened += 1;
        let (Some(generation), Some(signer)) =
            (session.generation.clone(), session.reference_signer)
        else {
            session.paths.remove(&peer);
            return false;
        };
        let deadline = session.deadline;
        let replies = replies.clone();
        workers.spawn(async move {
            let _slot = slot;
            reference_path(generation, signer, id, peer, deadline, rx, replies).await;
        });
        true
    }

    async fn dispatch(
        &self,
        phase: watch::Receiver<server::GenerationPhase>,
    ) -> Result<(), ServerError> {
        let mut pending: HashMap<(SocketAddr, Cid), Pending> = HashMap::new();
        let mut sessions: HashMap<SessionId, Session> = HashMap::new();
        let mut retired: Vec<Retired> = Vec::new();
        // Admitted Initial retransmits retain the same decision. Unknown
        // Initials, even from an already admitted tuple, must be classified.
        let mut admitted: HashMap<(SocketAddr, Cid), (Cid, Instant)> = HashMap::new();
        let mut sequence = 0u64;
        let mut workers = JoinSet::new();
        let (reply_tx, mut replies) = mpsc::channel::<Reply>(SESSIONS * 2);
        let mut buf = vec![0; wire::MAX_DATAGRAM + 1];
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let now = Instant::now();
                    pending.retain(|_, p| p.deadline > now);
                    retired.retain(|s| s.until > now);
                    let expired: Vec<_> = sessions.iter_mut().filter_map(|(&id,s)| {
                        s.prune_paths(now);
                        (s.expired(now) || s.paths.is_empty()).then_some(id)
                    }).collect();
                    for id in expired {
                        if let Some(s) = sessions.remove(&id) { retired.push(Retired::from_session(s,now)); }
                    }
                    admitted.retain(|_, (_, until)| *until > now);
                    self.tickets.lock().map_err(|_|ServerError::Io)?.retain(|_,ticket|ticket.until>now);
                }
                _ = workers.join_next(), if !workers.is_empty() => {}
                reply = replies.recv() => {
                    let Some(reply) = reply else { return Err(ServerError::Io); };
                    let now = Instant::now();
                    let Some(s) = sessions.get_mut(&reply.id) else { continue; };
                    if s.expired(now) || !s.can_reply(reply.peer, reply.data.len())
                        || !s.observe_reference(reply.peer, &reply.data) { continue; }
                    if matches!(self.socket.try_send_to(&reply.data, reply.peer), Ok(n) if n == reply.data.len()) {
                        s.sent(reply.peer, reply.data.len(), now);
                    }
                }
                recv = self.socket.recv_from(&mut buf) => {
                    let (n, peer) = recv.map_err(|_| ServerError::Io)?;
                    if n == 0 || n > wire::MAX_DATAGRAM { continue; }
                    let now = Instant::now();
                    let data = &buf[..n];
                    let header = wire::long(data);
                    let short = data[0] & 0x80 == 0;
                    if short && n<18{continue;}
                    if !short && (header.is_none()||!wire::coherent_datagram(data)){continue;}
                    let local_peer = admitted.keys().any(|(addr, _)| *addr == peer);
                    let local_known = if short {
                        data.get(1..1 + LOCAL_CID_LEN).is_some_and(|cid| self.local_cids.matches(cid))
                    } else {
                        header.as_ref().is_some_and(|h| self.local_cids.matches(h.dcid))
                    };
                    let is_initial = header.as_ref().is_some_and(|h| h.kind == Kind::Initial);
                    let existing_local = header.as_ref().is_some_and(|h| {
                        admitted.get(&(peer, h.dcid.to_vec())).is_some_and(|(scid, until)| *until > now && h.scid == scid.as_slice())
                    });
                    if !local_known && !existing_local && retired.iter().any(|s| s.blocks(peer, data, now)) {
                        continue;
                    }
                    // An opaque CID from an old connection could otherwise
                    // be delivered to a new session on a reused tuple.
                    // Known CIDs still work; tuple-only fallback is quarantined.
                    let retired_tuple=short&&retired.iter().any(|s|s.until>now&&s.peers.contains(&peer));
                    let relay=route(&sessions,peer,data,local_peer||local_known||retired_tuple);
                    if (local_known || existing_local) && (relay.is_some() || sessions.values().any(|s|s.known(data))) { continue; }
                    if local_known || existing_local {
                        if header.as_ref().is_some_and(|h|h.version!=wire::V1){continue;}
                        // An issued local CID alone is not authorization to
                        // create a fresh connection. Only a previously
                        // classified client Initial may reach TLS on it.
                        let initial_continuation = header.as_ref().is_some_and(|h|
                            admitted.iter().any(|((addr, _), (scid, until))|
                                *addr == peer && *until > now && h.scid == scid.as_slice()));
                        // A continuation belongs to the already selected
                        // handshake. Native TLS validates its own immutable
                        // ticket; a fresh Initial cannot get a ticket here.
                        let initial_current = !is_initial || existing_local || initial_continuation;
                        if n <= LOCAL_MAX && initial_current && (!is_initial || existing_local || initial_continuation) {
                            let _ = self.local.try_send((peer, data.to_vec()));
                        }
                        continue;
                    }
                    if let Some(id) = relay {
                        let Some(s) = sessions.get_mut(&id) else { continue; };
                        if !s.expired(now) && s.allows_client(peer, data)
                            && self.open_path(&mut workers, &reply_tx, id, s, peer) {
                            s.enqueue(peer, data.to_vec(), now);
                        }
                        continue;
                    }
                    if short || server::generation_draining(&phase) { continue; }
                    let Some(h) = header else { continue; };
                    if h.kind != Kind::Initial || n < wire::MIN_INITIAL || h.dcid.len() < 8 { continue; }
                    // A known but ambiguous long-header CID must not
                    // silently allocate a second reference session.
                    if sessions.values().any(|s| s.known(data)) { continue; }
                    let key = (peer, h.dcid.to_vec());
                    if !pending.contains_key(&key) {
                        if pending.len() + sessions.len() >= SESSIONS { continue; }
                        let Some(flight) = Flight::new(&h) else { continue; };
                        pending.insert(key.clone(), Pending { flight, client: h.scid.to_vec(), version:h.version,datagrams: Vec::new(), bytes: 0, deadline: now + FIRST_DEADLINE });
                    }
                    // Do not let an unrelated version/SCID invalidate an
                    // already pending flight or consume its reassembly slot.
                    if pending.get(&key).is_some_and(|p|p.version!=h.version||p.client.as_slice()!=h.scid){continue;}
                    let decision = pending.get_mut(&key).and_then(|p| {
                        if now >= p.deadline { None } else { p.add(data.to_vec()) }
                    });
                    if matches!(decision, Some(Inspection::Pending)) { continue; }
                    let Some(p) = pending.remove(&key) else { continue; };
                    let Some(decision) = decision else { continue; };
                    let Ok(wall) = crate::reference_health::unix_now() else { continue; };
                    let Some(generation)=self.live.current() else {continue;};
                    let selected=match decision{
                        Inspection::Hello(hello)=>generation.select(&self.live.guard,Branch::H3,&hello,wall),
                        Inspection::Invalid=>None,
                        Inspection::Pending=>continue,
                    };
                    if let Some(route)=selected{
                        // The native Quinn contract currently supports v1 only.
                        // A valid v2 marker must never be sent to the reference.
                        if h.version!=wire::V1{continue;}
                        if admitted.len()>=SESSIONS || p.datagrams.iter().any(|packet|packet.len()>LOCAL_MAX){continue;}
                        {
                            let mut tickets=self.tickets.lock().map_err(|_|ServerError::Io)?;
                            if tickets.len()>=SESSIONS || tickets.contains_key(&key){continue;}
                            tickets.insert(key.clone(),Ticket{route,until:now+FIRST_DEADLINE});
                        }
                        admitted.insert(key,(p.client,now+LIFETIME));
                        for packet in p.datagrams{let _=self.local.try_send((peer,packet));}
                    }else{
                        let Some(value)=generation.relay_value(wall) else{continue;};
                        let signer=value.signer();
                        if sessions.len() + retired.len() >= RETIRED_LIMIT { continue; }
                        let Some(next) = sequence.checked_add(1) else { return Err(ServerError::Io); };
                        sequence = next;
                        let mut s = Session::new(peer, h.dcid.to_vec(), p.client, p.version,now);
                        s.generation=Some(generation.lease.clone());
                        s.reference_signer=Some(signer);
                        if !self.open_path(&mut workers, &reply_tx, sequence, &mut s, peer) { continue; }
                        for packet in p.datagrams { s.enqueue(peer, packet, now); }
                        sessions.insert(sequence, s);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }
    fn session(p: SocketAddr, server: &[u8]) -> Session {
        let mut s = Session::new(p, vec![1; 8], vec![2; 8], wire::V1, Instant::now());
        s.server.insert(server.to_vec());
        s.server_initial = true;
        s.initial_server_cid = Some(server.to_vec());
        s.negotiated_version = Some(wire::V1);
        let (queue, _rx) = mpsc::channel(1);
        s.paths.insert(
            p,
            Path {
                queue,
                budget: Budget::default(),
                last: Instant::now(),
            },
        );
        s
    }
    #[test]
    fn amplification_is_per_path_and_never_promoted_by_cid_or_retry() {
        let mut s = session(peer(1), &[3; 8]);
        let (first_queue, _first_rx) = mpsc::channel(1);
        s.paths.get_mut(&peer(1)).unwrap().queue = first_queue;
        let (queue, _rx) = mpsc::channel(1);
        s.paths.insert(
            peer(2),
            Path {
                queue,
                budget: Budget::default(),
                last: Instant::now(),
            },
        );
        s.paths.get_mut(&peer(1)).unwrap().budget.credit(1200);
        assert!(s.can_reply(peer(1), 3600));
        assert!(!s.can_reply(peer(1), 3601));
        assert!(!s.can_reply(peer(2), 1));
        s.sent(peer(1), 3600, Instant::now());
        assert!(!s.can_reply(peer(1), 1));
        s.paths.get_mut(&peer(2)).unwrap().budget.credit(20);
        assert!(s.can_reply(peer(2), 60));
        assert!(!s.can_reply(peer(2), 61));
    }
    #[test]
    fn known_cid_rebinding_and_unknown_rotation_are_unambiguous() {
        let old = peer(1);
        let new = peer(2);
        let mut table = HashMap::new();
        table.insert(1, session(old, &[3; 8]));
        let known = [
            0x40, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let rotated = [
            0x40, 4, 4, 4, 4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(route(&table, new, &known, false), Some(1));
        assert_eq!(route(&table, old, &rotated, false), Some(1));
        assert_eq!(route(&table, new, &rotated, false), None);
        let mut greased = known;
        greased[0] = 0;
        assert_eq!(route(&table, new, &greased, false), Some(1));
        let mut greased_unknown = rotated;
        greased_unknown[0] = 0;
        assert_eq!(route(&table, old, &greased_unknown, false), Some(1));
        assert_eq!(route(&table, new, &greased_unknown, false), None);
        assert_eq!(route(&table, old, &rotated, true), None);
        table.insert(2, session(old, &[5; 8]));
        assert_eq!(route(&table, old, &rotated, false), None);
        table.insert(3, session(peer(3), &[3; 8]));
        assert_eq!(route(&table, new, &known, false), None);
        assert_eq!(route(&table, old, &known, false), None);
    }
    #[test]
    fn first_flight_is_version_and_client_cid_bound() {
        let mut initial = vec![0xc0, 0, 0, 0, 1, 8];
        initial.extend_from_slice(&[1; 8]);
        initial.push(8);
        initial.extend_from_slice(&[2; 8]);
        initial.extend_from_slice(&[0, 0x44, 0x96]);
        initial.resize(1200, 0);
        let h = wire::long(&initial).unwrap();
        let mut pending = Pending {
            flight: Flight::new(&h).unwrap(),
            client: h.scid.to_vec(),
            version: h.version,
            datagrams: Vec::new(),
            bytes: 0,
            deadline: Instant::now() + FIRST_DEADLINE,
        };
        let mut other = initial.clone();
        other[0] = 0xd0;
        other[1..5].copy_from_slice(&wire::V2.to_be_bytes());
        assert!(pending.add(other).is_none());
        let mut other = initial.clone();
        other[15] ^= 1;
        assert!(pending.add(other).is_none());
        assert!(pending.datagrams.is_empty() && pending.bytes == 0);
    }

    #[test]
    fn zero_cid_and_retry_cid_cannot_authorize_migration() {
        let p = peer(1);
        let mut s = session(p, &[3; 8]);
        s.initial_server_cid = Some(Vec::new());
        s.server.insert(vec![9; 8]); // historical Retry CID, not a 1-RTT CID
        let mut short = vec![0x40];
        short.extend_from_slice(&[9; 8]);
        short.extend_from_slice(&[0; 24]);
        let mut table = HashMap::from([(1, s)]);
        assert_eq!(route(&table, peer(2), &short, false), None);
        assert_eq!(route(&table, p, &short, false), Some(1));
        let mut handshake = vec![0xe0, 0, 0, 0, 1, 0, 8];
        handshake.extend_from_slice(&[2; 8]);
        handshake.push(20);
        handshake.extend_from_slice(&[0; 20]);
        assert_eq!(route(&table, p, &handshake, false), Some(1));
        assert!(table[&1].allows_client(p, &handshake));
        assert_eq!(route(&table, peer(2), &handshake, false), None);
        table.insert(2, session(p, &[4; 8]));
        assert_eq!(route(&table, p, &short, false), None);
    }

    #[test]
    fn opaque_cid_new_address_is_not_connection_or_validation_evidence() {
        let mut table = HashMap::new();
        table.insert(1, session(peer(1), &[1; 8]));
        table.insert(2, session(peer(2), &[2; 8]));
        // Either reference-side connection could have received this
        // newly issued, encrypted CID. The observer sees identical bytes.
        let mut opaque = vec![0x40];
        opaque.extend_from_slice(&[9; 8]);
        opaque.extend_from_slice(&[0; 24]);
        assert_eq!(route(&table, peer(3), &opaque, false), None);
        for s in table.values() {
            assert!(!s.can_reply(peer(3), 1));
            assert!(!s.allows_client(peer(3), &opaque));
        }
        assert_eq!(route(&table, peer(1), &opaque, true), None);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn quotas_expiry_and_queue_failure_do_not_create_credit() {
        let p = peer(1);
        let mut s = session(p, &[3; 8]);
        let now = Instant::now();
        s.enqueue(p, vec![0; 1200], now);
        assert!(!s.can_reply(p, 1)); // receiver was dropped
        assert_eq!(s.remaining, BYTES);
        assert!(s.expired(now + LIFETIME));
        assert!(s.expired(now + IDLE));
        let (queue, mut rx) = mpsc::channel(1);
        s.paths.insert(
            p,
            Path {
                queue,
                budget: Budget::default(),
                last: Instant::now(),
            },
        );
        let bytes = vec![0; 1200];
        s.enqueue(p, bytes.clone(), now);
        s.enqueue(p, bytes.clone(), now);
        assert_eq!(s.remaining, BYTES - 1200);
        assert_eq!(rx.try_recv().unwrap(), bytes);
        assert!(s.can_reply(p, 3600));
        assert!(!s.can_reply(p, 3601));
    }

    #[test]
    fn local_cids_are_generation_bound_and_not_a_visible_prefix() {
        let a = LocalCidKey::fresh().unwrap();
        let b = LocalCidKey::fresh().unwrap();
        let first = a.next();
        let second = a.next();
        assert_ne!(first, second);
        assert!(a.matches(&first) && a.matches(&second));
        assert!(!b.matches(&first));
        for i in 0..first.len() {
            let mut bad = first;
            bad[i] ^= 1;
            assert!(!a.matches(&bad));
        }
        assert!(!a.matches(&first[..19]));
    }

    // Real separate TLS/QUIC endpoint forces Retry. The relay has no
    // TLS keys and does not terminate the connection; only the fixture's
    // socket setup bypasses production public-DNS eligibility.
    #[tokio::test]
    async fn external_quic_retry_then_authenticated_stream_through_relay() {
        let cert = rcgen::generate_simple_self_signed(vec!["reference.example".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
        let reference =
            crate::quic_transport::server_endpoint(peer(0), vec![cert.cert.der().clone()], key)
                .unwrap();
        let target = reference.local_addr().unwrap();
        let listener = UdpSocket::bind(peer(0)).await.unwrap();
        let relay_addr = listener.local_addr().unwrap();
        let client = crate::quic_transport::client_endpoint(peer(0), roots).unwrap();
        let physical = client.local_addr().unwrap();
        let upstream = UdpSocket::bind(peer(0)).await.unwrap();
        upstream.connect(target).await.unwrap();
        let (tx, rx) = mpsc::channel(QUEUE);
        let (rtx, mut rrx) = mpsc::channel(QUEUE);
        let deadline = Instant::now() + Duration::from_secs(15);
        let pump = tokio::spawn(pump_path(upstream, 1, physical, deadline, rx, rtx, || true));
        let relay = tokio::spawn(async move {
            let mut buf = vec![0; wire::MAX_DATAGRAM + 1];
            let mut state: Option<Session> = None;
            loop {
                tokio::select! {
                    _=tokio::time::sleep_until(deadline)=>break,
                    result=listener.recv_from(&mut buf)=>{
                        let (n,peer)=result.unwrap();
                        if peer!=physical||n==0||n>wire::MAX_DATAGRAM{continue;}
                        let data=&buf[..n];
                        if state.is_none(){
                            let Some(h)=wire::long(data)else{continue;};
                            if h.kind!=Kind::Initial||n<wire::MIN_INITIAL{continue;}
                            let mut s=Session::new(peer,h.dcid.to_vec(),h.scid.to_vec(),h.version,Instant::now());
                            s.paths.insert(peer,Path{queue:tx.clone(),budget:Budget::default(),last:Instant::now()});
                            state=Some(s);
                        }
                        let s=state.as_mut().unwrap();
                        if s.allows_client(peer,data){s.enqueue(peer,data.to_vec(),Instant::now());}
                    }
                    reply=rrx.recv()=>{
                        let Some(reply)=reply else{break;};
                        let Some(s)=state.as_mut()else{continue;};
                        if s.can_reply(reply.peer,reply.data.len())&&s.observe_reference(reply.peer,&reply.data){
                            let n=listener.send_to(&reply.data,reply.peer).await.unwrap();
                            assert_eq!(n,reply.data.len());
                            s.sent(reply.peer,n,Instant::now());
                            let budget=&s.paths[&physical].budget;
                            assert!(budget.sent<=budget.received*3);
                        }
                    }
                }
            }
        });
        let server = tokio::spawn(async move {
            let initial = reference.accept().await.unwrap();
            assert!(!initial.remote_address_validated());
            initial.retry().unwrap();
            let next = reference.accept().await.unwrap();
            assert!(next.remote_address_validated());
            let conn = crate::quic_transport::accept(next).await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            assert_eq!(recv.read_to_end(1024).await.unwrap(), b"external");
            send.write_all(b"reference").await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
        });
        let result = timeout(Duration::from_secs(12), async {
            let conn = crate::quic_transport::connect(&client, relay_addr, "reference.example")
                .await
                .unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(b"external").await.unwrap();
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(1024).await.unwrap(), b"reference");
            conn.close(0u32.into(), b"done");
        })
        .await;
        relay.abort();
        pump.abort();
        server.abort();
        result.unwrap();
    }

    #[tokio::test]
    async fn actual_udp_pump_preserves_datagrams_and_isolates_paths() {
        let reference = UdpSocket::bind(peer(0)).await.unwrap();
        let upstream_a = UdpSocket::bind(peer(0)).await.unwrap();
        let upstream_b = UdpSocket::bind(peer(0)).await.unwrap();
        let rogue = UdpSocket::bind(peer(0)).await.unwrap();
        let target = reference.local_addr().unwrap();
        upstream_a.connect(target).await.unwrap();
        upstream_b.connect(target).await.unwrap();
        let addr_a = upstream_a.local_addr().unwrap();
        let addr_b = upstream_b.local_addr().unwrap();
        let (a_tx, a_rx) = mpsc::channel(4);
        let (b_tx, b_rx) = mpsc::channel(4);
        let (reply_tx, mut reply_rx) = mpsc::channel(4);
        let deadline = Instant::now() + Duration::from_secs(3);
        let a = tokio::spawn(pump_path(
            upstream_a,
            1,
            peer(100),
            deadline,
            a_rx,
            reply_tx.clone(),
            || true,
        ));
        let b = tokio::spawn(pump_path(
            upstream_b,
            1,
            peer(200),
            deadline,
            b_rx,
            reply_tx,
            || true,
        ));
        let first = vec![0xc0; 1200];
        let second = vec![0x40; 49];
        a_tx.send(first.clone()).await.unwrap();
        b_tx.send(second.clone()).await.unwrap();
        let mut buf = [0u8; 2048];
        let mut seen = HashMap::new();
        for _ in 0..2 {
            let (n, addr) = timeout(Duration::from_secs(1), reference.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            seen.insert(addr, buf[..n].to_vec());
        }
        assert_eq!(seen.get(&addr_a), Some(&first));
        assert_eq!(seen.get(&addr_b), Some(&second));
        rogue.send_to(b"rogue", addr_a).await.unwrap();
        reference.send_to(b"old-path", addr_a).await.unwrap();
        reference.send_to(b"new-path", addr_b).await.unwrap();
        let mut replies = HashMap::new();
        for _ in 0..2 {
            let reply = timeout(Duration::from_secs(1), reply_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.id, 1);
            replies.insert(reply.peer, reply.data);
        }
        assert_eq!(
            replies.get(&peer(100)).map(Vec::as_slice),
            Some(b"old-path".as_slice())
        );
        assert_eq!(
            replies.get(&peer(200)).map(Vec::as_slice),
            Some(b"new-path".as_slice())
        );
        drop(a_tx);
        drop(b_tx);
        timeout(Duration::from_secs(1), a).await.unwrap().unwrap();
        timeout(Duration::from_secs(1), b).await.unwrap().unwrap();
    }

    #[test]
    fn coalesced_packets_cannot_cross_connection_boundaries() {
        fn packet(dcid: u8) -> Vec<u8> {
            let mut p = vec![0xe0, 0, 0, 0, 1, 8];
            p.extend_from_slice(&[dcid; 8]);
            p.push(8);
            p.extend_from_slice(&[2; 8]);
            p.push(17);
            p.extend_from_slice(&[0; 17]);
            p
        }
        let mut bytes = packet(3);
        bytes.extend(packet(3));
        assert!(wire::coherent_datagram(&bytes));
        bytes.extend(packet(4));
        assert!(!wire::coherent_datagram(&bytes));
        let mut bytes = packet(3);
        bytes.extend([0x40]);
        bytes.extend([3; 8]);
        bytes.extend([0; 17]);
        assert!(wire::coherent_datagram(&bytes));
        let last = packet(3).len() + 1;
        bytes[last] = 4;
        assert!(!wire::coherent_datagram(&bytes));
    }

    #[test]
    fn retirement_is_bounded_and_dead_path_cannot_reset_credit() {
        let p = peer(10);
        let mut s = session(p, &[3; 8]);
        let now = Instant::now();
        s.prune_paths(now);
        assert!(s.paths.is_empty());
        assert!(s.closed_paths.contains(&p));
        let retired = Retired::from_session(s, now);
        let known = [
            0x40, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(retired.blocks(p, &known, now));
        assert!(retired.blocks(peer(20), &known, now));
        assert!(!retired.blocks(p, &known, now + RETIRED_TTL));
    }

    #[test]
    fn retry_token_never_transfers_to_another_path_or_grants_credit() {
        let p = peer(10);
        let mut s = session(p, &[3; 8]);
        s.server_initial = false;
        s.negotiated_version = None;
        s.initial_server_cid = None;
        s.retry = Some(Retry {
            cid: vec![3; 8],
            token: vec![9],
        });
        let (tx, _rx) = mpsc::channel(2);
        s.paths.get_mut(&p).unwrap().queue = tx;
        let mut packet = vec![0xc0, 0, 0, 0, 1, 8];
        packet.extend_from_slice(&[3; 8]);
        packet.push(8);
        packet.extend_from_slice(&[2; 8]);
        packet.extend_from_slice(&[1, 9, 0x44, 0x95]); // 1173 bytes
        packet.resize(1200, 0);
        // The packet length field must cover a whole initial packet.
        assert!(wire::long(&packet).is_some());
        assert!(s.allows_client(p, &packet));
        assert!(!s.allows_client(peer(11), &packet));
        let mut forged = packet.clone();
        forged[24] ^= 1;
        assert!(!s.allows_client(p, &forged));
        assert!(!s.can_reply(p, 1));
        s.enqueue(p, packet, Instant::now());
        assert!(s.retry_echoed);
        assert!(s.can_reply(p, 3600));
        assert!(!s.can_reply(p, 3601));
    }
}
