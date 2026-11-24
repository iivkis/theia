//! External QUIC v1 reference relay for a prepared REALITY generation.
//! The relay never terminates reference TLS or rewrites datagrams. Admission
//! is decided before opening a reference socket. A valid marker is handed
//! exclusively to the local QUIC endpoint via a bounded virtual UDP socket.
//! Production startup remains a separate explicit integration decision.
#![forbid(unsafe_code)]

use crate::{
    config::Config,
    identity_tls::Branch,
    reality_admission::{Context, ReplayGuard},
    reality_generation::{Lease, Manager},
    reality_quic_wire::{self as wire, Cid, Flight, Inspection, Kind},
    server::{ServerContext, ServerError},
};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, TokioRuntime, UdpPoller, udp::{RecvMeta, Transmit}};
use std::{
    collections::{HashMap, HashSet},
    fmt, io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinSet, time::{Instant, timeout}};

const SESSIONS: usize = 64;
const PATHS: usize = 4;
const CIDS: usize = 8;
const QUEUE: usize = 16;
const MAX_FIRST_BYTES: usize = 64 * 1024;
const FIRST_DEADLINE: Duration = Duration::from_secs(3);
const LIFETIME: Duration = Duration::from_secs(60);
const IDLE: Duration = Duration::from_secs(15);
const BYTES: usize = 8 * 1024 * 1024;
const DNS_DEADLINE: Duration = Duration::from_secs(5);
type SessionId = u64;

#[derive(Default)]
struct Budget { received: usize, sent: usize }
impl Budget {
    fn credit(&mut self, n: usize) { self.received = self.received.saturating_add(n); }
    fn allows(&self, n: usize) -> bool { self.sent.saturating_add(n) <= self.received.saturating_mul(3) }
    fn debit(&mut self, n: usize) { self.sent = self.sent.saturating_add(n); }
}

struct Path {
    queue: mpsc::Sender<Vec<u8>>,
    budget: Budget,
}
struct Retry { cid: Cid, token: Vec<u8> }
struct Session {
    original: Cid,
    client: Cid,
    server: HashSet<Cid>,
    retry: Option<Retry>,
    first_peer: SocketAddr,
    paths: HashMap<SocketAddr, Path>,
    deadline: Instant,
    last: Instant,
    remaining: usize,
    paths_opened: usize,
}
impl Session {
    fn new(peer: SocketAddr, original: Cid, client: Cid, now: Instant) -> Self {
        Self { original, client, server: HashSet::new(), retry: None, first_peer: peer,
            paths: HashMap::new(), deadline: now + LIFETIME, last: now, remaining: BYTES, paths_opened: 0 }
    }
    fn expired(&self, now: Instant) -> bool {
        now >= self.deadline || now.saturating_duration_since(self.last) >= IDLE || self.remaining == 0
    }
    fn known(&self, datagram: &[u8]) -> bool {
        if let Some(h) = wire::long(datagram) {
            h.kind != Kind::Retry && h.kind != Kind::VersionNegotiation
                && (h.dcid == self.original || self.server.contains(h.dcid))
                && (h.kind != Kind::Initial || h.scid == self.client)
        } else {
            self.server.iter().any(|cid| wire::short_matches(datagram, cid))
        }
    }
    fn allows_client(&self, peer: SocketAddr, datagram: &[u8]) -> bool {
        if let Some(h) = wire::long(datagram) {
            if peer != self.first_peer && !self.paths.contains_key(&peer) { return false; }
            if h.kind == Kind::Initial {
                if datagram.len() < wire::MIN_INITIAL || h.scid != self.client { return false; }
                if let Some(retry) = &self.retry {
                    return h.dcid == retry.cid && h.token == retry.token
                        || (self.server.contains(h.dcid) && h.dcid != retry.cid);
                }
            }
            self.known(datagram)
        } else {
            datagram.first().is_some_and(|b| b & 0x80 == 0) &&
                (self.paths.contains_key(&peer) || self.known(datagram))
        }
    }

    // Accept only public CIDs learned from the connected reference socket.
    // NEW_CONNECTION_ID / RETIRE_CONNECTION_ID are encrypted, so a passive
    // relay cannot learn them from 1-RTT packets. Never guess a new CID length.
    fn observe_reference(&mut self, peer: SocketAddr, packet: &[u8]) -> bool {
        if let Some(h) = wire::long(packet) {
            if h.dcid != self.client { return false; }
            if h.kind == Kind::VersionNegotiation {
                return self.retry.is_none() && h.scid == self.original;
            }
            if h.kind == Kind::Retry {
                if peer != self.first_peer || h.scid.is_empty() || h.scid == self.original
                    || !wire::retry_valid(packet, &self.original) { return false; }
                if let Some(old) = &self.retry { return old.cid == h.scid && old.token == h.token; }
                if !self.server.is_empty() { return false; }
                self.retry = Some(Retry { cid: h.scid.to_vec(), token: h.token.to_vec() });
            } else if h.kind != Kind::Initial && h.kind != Kind::Handshake {
                return false;
            }
            if !h.scid.is_empty() && !self.server.contains(h.scid) {
                if self.server.len() == CIDS { return false; }
                self.server.insert(h.scid.to_vec());
            }
            true
        } else {
            packet.first().is_some_and(|b| b & 0x80 == 0) &&
                (self.client.is_empty() || wire::short_matches(packet, &self.client)
                    || self.paths.contains_key(&peer))
        }
    }

    fn enqueue(&mut self, peer: SocketAddr, data: Vec<u8>, now: Instant) {
        let n = data.len();
        if n > self.remaining { return; }
        let Some(path) = self.paths.get_mut(&peer) else { return; };
        if path.queue.try_send(data).is_ok() {
            self.remaining -= n;
            path.budget.credit(n);
            self.last = now;
        }
    }
    fn can_reply(&self, peer: SocketAddr, n: usize) -> bool {
        n <= self.remaining && self.paths.get(&peer).is_some_and(|p| p.budget.allows(n))
    }
    fn sent(&mut self, peer: SocketAddr, n: usize, now: Instant) {
        if let Some(path) = self.paths.get_mut(&peer) {
            path.budget.debit(n);
            self.remaining -= n;
            self.last = now;
        }
    }
}

struct Pending {
    flight: Flight,
    datagrams: Vec<Vec<u8>>,
    bytes: usize,
    deadline: Instant,
}
impl Pending {
    fn add(&mut self, data: Vec<u8>) -> Option<Inspection> {
        let total = self.bytes.checked_add(data.len())?;
        if total > MAX_FIRST_BYTES || self.datagrams.len() >= QUEUE { return None; }
        let decision = self.flight.inspect(&data);
        self.datagrams.push(data);
        self.bytes = total;
        Some(decision)
    }
}

struct Reply { id: SessionId, peer: SocketAddr, data: Vec<u8> }
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
    generation: Arc<Lease>, id: SessionId, peer: SocketAddr, deadline: Instant,
    mut incoming: mpsc::Receiver<Vec<u8>>, replies: mpsc::Sender<Reply>,
) {
    let publication = generation.publication();
    let value = publication.active().verified();
    let Ok(Ok(lease)) = timeout(DNS_DEADLINE,
        generation.health().relay_lease(value, publication.plan_sha256())).await else { return; };
    let Ok(address) = lease.address() else { return; };
    let Ok(socket) = UdpSocket::bind(wildcard(address.ip())).await else { return; };
    if socket.connect(address).await.is_err() || lease.address().ok() != Some(address) { return; }
    let mut buf = vec![0; wire::MAX_DATAGRAM + 1];
    loop {
        if lease.address().is_err() { return; }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return,
            data = incoming.recv() => {
                let Some(data) = data else { return; };
                if lease.address().is_err() { return; }
                if !matches!(timeout(Duration::from_secs(1), socket.send(&data)).await,
                    Ok(Ok(n)) if n == data.len()) { return; }
            }
            result = socket.recv(&mut buf) => {
                let Ok(n) = result else { return; };
                if lease.address().is_err() { return; }
                if n > 0 && n <= wire::MAX_DATAGRAM {
                    let _ = replies.try_send(Reply { id, peer, data: buf[..n].to_vec() });
                }
            }
        }
    }
}

fn unique<I: Iterator<Item=SessionId>>(mut ids: I) -> Option<SessionId> {
    let first = ids.next()?;
    ids.next().is_none().then_some(first)
}
fn route(sessions: &HashMap<SessionId, Session>, peer: SocketAddr, bytes: &[u8], admitted_peer: bool) -> Option<SessionId> {
    let known = || sessions.iter().filter(|(_, s)| s.known(bytes));
    let mut matches = known().filter(|(_, s)| s.paths.contains_key(&peer));
    if let Some((&id, _)) = matches.next() {
        return matches.next().is_none().then_some(id);
    }
    let mut global = known();
    if let Some((&id, _)) = global.next() {
        // A client-selected Initial DCID is not sufficient to attach a
        // different source address. Only observed short-header CIDs migrate.
        return (global.next().is_none() && bytes[0] & 0x80 == 0).then_some(id);
    }
    // On an existing, unambiguous physical tuple the reference can decrypt
    // packets carrying an encrypted, newly issued CID. Do not learn it from
    // unauthenticated bytes or guess which of several connections owns it.
    if admitted_peer || !bytes.first().is_some_and(|b| b & 0x80 == 0) { return None; }
    unique(sessions.iter().filter(|(_, s)| s.paths.contains_key(&peer)).map(|(&id, _)| id))
}

// Quinn receives the original physical source address, not a loopback proxy
// address. Its own authenticated path validation and amplification rules
// therefore remain applicable. No extra listener can bypass admission.
// When a bounded queue or OS send buffer fills, UDP may drop a datagram.
struct LocalSocket {
    socket: Arc<UdpSocket>,
    receive: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    cids: Arc<Mutex<HashMap<Cid, Instant>>>,
}
impl fmt::Debug for LocalSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("RealityQuicSocket(<redacted>)") }
}
#[derive(Debug)]
struct Ready;
impl UdpPoller for Ready {
    fn poll_writable(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncUdpSocket for LocalSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> { Box::pin(Ready) }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // GSO is not advertised; no packet splitting or byte rewriting.
        if transmit.segment_size.is_some() { return Err(io::ErrorKind::InvalidInput.into()); }
        let result = self.socket.try_send_to(transmit.contents, transmit.destination);
        match result {
            Ok(n) if n == transmit.contents.len() => {
                if let Some(h) = wire::long(transmit.contents) {
                    if !h.scid.is_empty() && h.kind != Kind::VersionNegotiation {
                        if let Ok(mut cids) = self.cids.lock() {
                            let now = Instant::now();
                            cids.retain(|_, deadline| *deadline > now);
                            if cids.len() < SESSIONS * CIDS || cids.contains_key(h.scid) {
                                cids.insert(h.scid.to_vec(), now + LIFETIME);
                            }
                        }
                    }
                }
                Ok(())
            }
            Ok(_) => Err(io::ErrorKind::WriteZero.into()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }
    fn poll_recv(&self, cx: &mut TaskContext<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() { return Poll::Ready(Ok(0)); }
        let mut receiver = self.receive.lock().map_err(|_| io::Error::other("QUIC receive lock"))?;
        match receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Some((addr, bytes))) => {
                if bytes.len() > bufs[0].len() { return Poll::Ready(Err(io::ErrorKind::InvalidData.into())); }
                bufs[0][..bytes.len()].copy_from_slice(&bytes);
                meta[0] = RecvMeta { addr, len: bytes.len(), stride: bytes.len(), ecn: None, dst_ip: None };
                Poll::Ready(Ok(1))
            }
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> { self.socket.local_addr() }
    fn may_fragment(&self) -> bool { true }
    fn max_transmit_segments(&self) -> usize { 1 }
    fn max_receive_segments(&self) -> usize { 1 }
}

/// Actual UDP composition for a single prepared generation. No wildcard
/// reference destinations, caller-supplied routing addresses, or detached
/// workers. The normal server startup does not yet activate this candidate.
pub struct PreparedQuic {
    socket: Arc<UdpSocket>,
    endpoint: Endpoint,
    local: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    local_cids: Arc<Mutex<HashMap<Cid, Instant>>>,
    context: Arc<ServerContext>,
    generation: Arc<Lease>,
    guard: ReplayGuard,
}
impl PreparedQuic {
    pub fn prepare(socket: UdpSocket, document: &Config, inbound_id: &str) -> Result<Self, ServerError> {
        let Config::Server(doc) = document else { return Err(ServerError::Config); };
        let inbound = doc.server.inbounds.iter().find(|i| i.id == inbound_id).ok_or(ServerError::Config)?;
        let expected: SocketAddr = inbound.quic_listen.parse().map_err(|_| ServerError::Config)?;
        if socket.local_addr().map_err(|_| ServerError::Io)? != expected { return Err(ServerError::Config); }
        let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
        let manager = Manager::new(document, inbound_id, now).map_err(|_| ServerError::Config)?;
        let generation = Arc::new(manager.refresh(now).map_err(|_| ServerError::Config)?);
        let publication = generation.publication();
        if publication.next().is_some() { return Err(ServerError::Config); }
        let material = publication.active();
        let value = material.verified();
        if !value.effective_modes().h3 { return Err(ServerError::Config); }
        let d = value.descriptor();
        let reference = d.references.get(usize::from(d.active_reference)).ok_or(ServerError::Config)?;
        let mut tls = material.identity().server_tls(&reference.server_name, Branch::H3).map_err(|_| ServerError::Tls)?;
        tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| ServerError::Tls)?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server.transport_config(crate::quic_transport::transport_config());
        server.migration(false);
        let context = Arc::new(ServerContext::identity_context(inbound, &doc.server.users,
            &doc.server.policy, value, Arc::from(material.signed()))?);
        let socket = Arc::new(socket);
        let (local, rx) = mpsc::channel(SESSIONS * 2);
        let local_cids = Arc::new(Mutex::new(HashMap::new()));
        let virtual_socket = Arc::new(LocalSocket { socket: socket.clone(), receive: Mutex::new(rx), cids: local_cids.clone() });
        let endpoint = Endpoint::new_with_abstract_socket(EndpointConfig::default(), Some(server),
            virtual_socket, Arc::new(TokioRuntime)).map_err(|_| ServerError::Io)?;
        let guard = ReplayGuard::new(65536, now).map_err(|_| ServerError::Config)?;
        Ok(Self { socket, endpoint, local, local_cids, context, generation, guard })
    }

    pub async fn serve(self) -> Result<(), ServerError> {
        let endpoint = self.endpoint.clone();
        let result = tokio::select! {
            result = crate::h3_server::serve(endpoint.clone(), self.context.clone()) => result,
            result = self.dispatch() => result,
        };
        endpoint.close(0u32.into(), b"backend closed");
        result
    }

    fn open_path(&self, workers: &mut JoinSet<()>, replies: &mpsc::Sender<Reply>, id: SessionId,
        session: &mut Session, peer: SocketAddr) -> bool {
        if session.paths.contains_key(&peer) { return true; }
        if session.paths_opened >= PATHS { return false; }
        let (tx, rx) = mpsc::channel(QUEUE);
        session.paths.insert(peer, Path { queue: tx, budget: Budget::default() });
        session.paths_opened += 1;
        workers.spawn(reference_path(self.generation.clone(), id, peer, session.deadline, rx, replies.clone()));
        true
    }

    async fn dispatch(&self) -> Result<(), ServerError> {
        let mut pending: HashMap<(SocketAddr, Cid), Pending> = HashMap::new();
        let mut sessions: HashMap<SessionId, Session> = HashMap::new();
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
                    sessions.retain(|_, s| !s.expired(now));
                    admitted.retain(|_, (_, until)| *until > now);
                    if let Ok(mut cids) = self.local_cids.lock() { cids.retain(|_, until| *until > now); }
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
                    let local_peer = admitted.keys().any(|(addr, _)| *addr == peer);
                    let local_known = self.local_cids.lock().map(|cids| cids.iter().any(|(cid, deadline)| {
                        *deadline > now && if short { wire::short_matches(data, cid) }
                            else { header.as_ref().is_some_and(|h| h.dcid == cid.as_slice()) }
                    })).unwrap_or(false);
                    let existing_local = header.as_ref().is_some_and(|h| {
                        admitted.get(&(peer, h.dcid.to_vec())).is_some_and(|(scid, until)| *until > now && h.scid == scid.as_slice())
                    });
                    let relay = route(&sessions, peer, data, local_peer || local_known);
                    if (local_known || existing_local) && relay.is_some() { continue; }
                    if local_known || existing_local {
                        let _ = self.local.try_send((peer, data.to_vec()));
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
                    if short {
                        // Unknown short CID on a known admitted tuple can
                        // be a legitimate CID rotation. Quinn authenticates
                        // it; a tuple shared with a relay is ambiguous.
                        if local_peer && !sessions.values().any(|s| s.paths.contains_key(&peer)) {
                            let _ = self.local.try_send((peer, data.to_vec()));
                        }
                        continue;
                    }
                    let Some(h) = header else { continue; };
                    if h.kind != Kind::Initial || n < wire::MIN_INITIAL || h.dcid.len() < 8 { continue; }
                    let key = (peer, h.dcid.to_vec());
                    if !pending.contains_key(&key) {
                        if pending.len() + sessions.len() >= SESSIONS || admitted.len() >= SESSIONS { continue; }
                        let Some(flight) = Flight::new(&h) else { continue; };
                        pending.insert(key.clone(), Pending { flight, datagrams: Vec::new(), bytes: 0, deadline: now + FIRST_DEADLINE });
                    }
                    let decision = pending.get_mut(&key).and_then(|p| {
                        if now >= p.deadline { None } else { p.add(data.to_vec()) }
                    });
                    if matches!(decision, Some(Inspection::Pending)) { continue; }
                    let Some(p) = pending.remove(&key) else { continue; };
                    let Some(decision) = decision else { continue; };
                    let Ok(wall) = crate::reference_health::unix_now() else { continue; };
                    let publication = self.generation.publication();
                    let value = publication.active().verified();
                    if value.check_time(wall).is_err() { continue; }
                    let d = value.descriptor();
                    let Some(reference) = d.references.get(usize::from(d.active_reference)) else { continue; };
                    let secret = self.generation.admission();
                    let context = Context { scope: &d.scope, identity: value.signer(), reference: &reference.server_name, branch: Branch::H3 };
                    let allowed = match decision {
                        Inspection::Hello(hello) => self.guard.admit(&secret, &context, &hello, wall).is_ok(),
                        Inspection::Invalid => false,
                        Inspection::Pending => continue,
                    };
                    if allowed {
                        if admitted.len() >= SESSIONS { continue; }
                        admitted.insert(key, (h.scid.to_vec(), now + LIFETIME));
                        for packet in p.datagrams { let _ = self.local.try_send((peer, packet)); }
                    } else {
                        let Some(next) = sequence.checked_add(1) else { return Err(ServerError::Io); };
                        sequence = next;
                        let mut s = Session::new(peer, h.dcid.to_vec(), h.scid.to_vec(), now);
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
    fn peer(port: u16) -> SocketAddr { SocketAddr::from(([127,0,0,1], port)) }
    fn session(p: SocketAddr, server: &[u8]) -> Session {
        let mut s = Session::new(p, vec![1;8], vec![2;8], Instant::now());
        s.server.insert(server.to_vec());
        let (queue, _rx) = mpsc::channel(1);
        s.paths.insert(p, Path { queue, budget: Budget::default() });
        s
    }
    #[test]
    fn amplification_is_per_path_and_never_promoted_by_cid_or_retry() {
        let mut s = session(peer(1), &[3;8]);
        let (queue, _rx) = mpsc::channel(1);
        s.paths.insert(peer(2), Path { queue, budget: Budget::default() });
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
        let old = peer(1); let new = peer(2);
        let mut table = HashMap::new();
        table.insert(1, session(old, &[3;8]));
        let known = [0x40,3,3,3,3,3,3,3,3,0];
        let rotated = [0x40,4,4,4,4,4,4,4,4,0];
        assert_eq!(route(&table, new, &known, false), Some(1));
        assert_eq!(route(&table, old, &rotated, false), Some(1));
        assert_eq!(route(&table, new, &rotated, false), None);
        assert_eq!(route(&table, old, &rotated, true), None);
        table.insert(2, session(old, &[5;8]));
        assert_eq!(route(&table, old, &rotated, false), None);
        table.insert(3, session(peer(3), &[3;8]));
        assert_eq!(route(&table, new, &known, false), None);
        assert_eq!(route(&table, old, &known, false), Some(1));
    }
    #[test]
    fn quotas_expiry_and_queue_failure_do_not_create_credit() {
        let p = peer(1);
        let mut s = session(p, &[3;8]);
        let now = Instant::now();
        s.enqueue(p, vec![0;1200], now);
        assert!(!s.can_reply(p, 1)); // receiver was dropped
        assert_eq!(s.remaining, BYTES);
        assert!(s.expired(now + LIFETIME));
        assert!(s.expired(now + IDLE));
        let (queue, mut rx) = mpsc::channel(1);
        s.paths.insert(p, Path { queue, budget: Budget::default() });
        let bytes = vec![0;1200];
        s.enqueue(p, bytes.clone(), now);
        s.enqueue(p, bytes.clone(), now);
        assert_eq!(s.remaining, BYTES - 1200);
        assert_eq!(rx.try_recv().unwrap(), bytes);
        assert!(s.can_reply(p, 3600));
        assert!(!s.can_reply(p, 3601));
    }
}
