//! Shared, bounded loopback UDP listener for native QUIC integration tests.
//! Address validation is NOT TLS identity or Theia admission. The listener
//! owns CID routes, not application authorization. A full production
//! connection driver and external acceptance remain mandatory.
use super::{
    ingress::{Action, Ingress},
    negotiation::{Binding, VersionPolicy},
    scope::NetworkScope,
};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

type Cid = [u8; 8];
type IssuedCid = (Cid, [u8; 16]);
pub(crate) enum RouteCommand {
    StopAccepting { reply: oneshot::Sender<()> },
    Issue {
        owner: u64,
        reply: oneshot::Sender<io::Result<IssuedCid>>,
    },
    Retire {
        owner: u64,
        cid: Cid,
        reply: oneshot::Sender<io::Result<()>>,
    },
}

const MTU: usize = 1200;
const MAX_CONNECTIONS: usize = 128;
const MAILBOX: usize = 16;
type Datagram = (Vec<u8>, SocketAddr);

pub(crate) enum SessionIo {
    Direct { socket: UdpSocket, scope: NetworkScope },
    Routed {
        socket: Arc<UdpSocket>,
        scope: NetworkScope,
        incoming: mpsc::Receiver<Datagram>,
        owner: u64,
        commands: mpsc::Sender<RouteCommand>,
    },
}

impl From<UdpSocket> for SessionIo {
    fn from(socket: UdpSocket) -> Self {
        Self::direct(socket, NetworkScope::loopback())
    }
}

impl SessionIo {
    pub(crate) fn direct(socket: UdpSocket, scope: NetworkScope) -> Self {
        Self::Direct { socket, scope }
    }

    pub(crate) fn scope(&self) -> NetworkScope {
        match self { Self::Direct { scope, .. } | Self::Routed { scope, .. } => *scope }
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Direct { socket: s, .. } => s.local_addr(),
            Self::Routed { socket, .. } => socket.local_addr(),
        }
    }

    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Direct { socket: s, .. } => s.peer_addr(),
            Self::Routed { .. } => Err(io::Error::from(io::ErrorKind::NotConnected)),
        }
    }

    pub(crate) async fn issue_cid(&self) -> io::Result<IssuedCid> {
        match self {
            Self::Direct { .. } => {
                let cid = super::negotiation::random_cid().map_err(|_| io::ErrorKind::Other)?;
                let mut token = [0; 16];
                SystemRandom::new()
                    .fill(&mut token)
                    .map_err(|_| io::ErrorKind::Other)?;
                Ok((cid, token))
            }
            Self::Routed {
                owner, commands, ..
            } => {
                let (reply, result) = oneshot::channel();
                commands
                    .send(RouteCommand::Issue {
                        owner: *owner,
                        reply,
                    })
                    .await
                    .map_err(|_| io::ErrorKind::BrokenPipe)?;
                result.await.map_err(|_| io::ErrorKind::BrokenPipe)?
            }
        }
    }

    pub(crate) async fn retire_cid(&self, cid: Cid) -> io::Result<()> {
        match self {
            Self::Direct { .. } => Ok(()),
            Self::Routed {
                owner, commands, ..
            } => {
                let (reply, result) = oneshot::channel();
                commands
                    .send(RouteCommand::Retire {
                        owner: *owner,
                        cid,
                        reply,
                    })
                    .await
                    .map_err(|_| io::ErrorKind::BrokenPipe)?;
                result.await.map_err(|_| io::ErrorKind::BrokenPipe)?
            }
        }
    }

    pub(crate) async fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Direct { socket: s, .. } => s.send_to(bytes, peer).await,
            Self::Routed {
                socket, incoming, ..
            } => {
                if incoming.is_closed() {
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                }
                socket.send_to(bytes, peer).await
            }
        }
    }

    pub(crate) async fn recv_from(&mut self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::Direct { socket: s, .. } => s.recv_from(out).await,
            Self::Routed { incoming, .. } => {
                let (bytes, peer) = incoming.recv().await.ok_or(io::ErrorKind::BrokenPipe)?;
                let n = bytes.len().min(out.len());
                out[..n].copy_from_slice(&bytes[..n]);
                Ok((n, peer))
            }
        }
    }
}

/// A Retry-validated candidate, not an authenticated user. Dropping it
/// closes its mailbox and the listener retires the CID without reuse.
pub struct Candidate {
    io: SessionIo,
    peer: SocketAddr,
    binding: Binding,
    token: Vec<u8>,
    initial_reset: [u8; 16],
    versions: VersionPolicy,
}

impl Candidate {
    pub(crate) fn into_parts(self) -> (SessionIo, SocketAddr, Binding, Vec<u8>, [u8; 16], VersionPolicy) {
        (self.io, self.peer, self.binding, self.token, self.initial_reset, self.versions)
    }
}

pub struct Listener {
    local: SocketAddr,
    candidates: mpsc::Receiver<Candidate>,
    worker: JoinHandle<io::Result<()>>,
    commands: mpsc::Sender<RouteCommand>,
}

impl Listener {
    pub fn new(socket: UdpSocket, limit: usize) -> io::Result<Self> {
        Self::with_versions(socket, limit, VersionPolicy::both())
    }

    pub fn with_versions(
        socket: UdpSocket,
        limit: usize,
        versions: VersionPolicy,
    ) -> io::Result<Self> {
        Self::with_scope(socket, limit, versions, NetworkScope::loopback())
    }

    pub fn with_scope(socket: UdpSocket, limit: usize, versions: VersionPolicy, scope: NetworkScope) -> io::Result<Self> {
        let local = socket.local_addr()?;
        if !scope.allows_local(local.ip())
            || socket.peer_addr().is_ok()
            || !(1..=MAX_CONNECTIONS).contains(&limit)
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let ingress = Ingress::for_listener(limit, versions.clone())
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        let (tx, candidates) = mpsc::channel(limit);
        let (commands, requests) = mpsc::channel(limit);
        let worker = tokio::spawn(run(
            Arc::new(socket),
            ingress,
            tx,
            versions,
            commands.clone(),
            requests,
            scope,
        ));
        Ok(Self {
            local,
            candidates,
            worker,
            commands,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub(crate) async fn stop_accepting(&self) -> io::Result<()> {
        let (reply, result) = oneshot::channel();
        self.commands.send(RouteCommand::StopAccepting { reply }).await.map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.await.map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    pub async fn accept(&mut self) -> io::Result<Candidate> {
        self.candidates
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

async fn run(
    socket: Arc<UdpSocket>,
    mut ingress: Ingress,
    accepts: mpsc::Sender<Candidate>,
    versions: VersionPolicy,
    commands: mpsc::Sender<RouteCommand>,
    mut requests: mpsc::Receiver<RouteCommand>,
    scope: NetworkScope,
) -> io::Result<()> {
    let local = socket.local_addr()?;
    let clock = Instant::now();
    let mut routes: BTreeMap<u64, mpsc::Sender<Datagram>> = BTreeMap::new();
    let mut buffer = [0; MTU + 1];
    let mut sweep = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            _ = accepts.closed() => return Ok(()),
            _ = sweep.tick() => {
                let expired: Vec<_> = routes.iter().filter_map(|(&id, tx)| tx.is_closed().then_some(id)).collect();
                for owner in expired {
                    routes.remove(&owner);
                    ingress.close(owner, clock.elapsed().as_secs()).map_err(|_| io::ErrorKind::InvalidData)?;
                }
            }
            Some(command) = requests.recv() => {
                let now = clock.elapsed().as_secs();
                match command {
                    RouteCommand::StopAccepting { reply } => {
                        ingress.stop_accepting();
                        let _ = reply.send(());
                    }
                    RouteCommand::Issue { owner, reply } => {
                        if reply.is_closed() { continue; }
                        let issued = ingress.issue_local_cid(owner, now).map(|cid| (cid, ingress.reset_token(cid)))
                            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock));
                        if let Err(Ok((cid, _))) = reply.send(issued) {
                            let _ = ingress.retire_local_cid(owner, cid, now);
                        }
                    }
                    RouteCommand::Retire { owner, cid, reply } => {
                        let result = ingress.retire_local_cid(owner, cid, now).map_err(|_| io::Error::from(io::ErrorKind::InvalidData));
                        let _ = reply.send(result);
                    }
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let (n, peer) = match received {
                    Ok(value) => value,
                    // Windows can surface ICMP Port Unreachable on an
                    // unconnected UDP socket. It is not a listener failure.
                    Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused) || (cfg!(windows) && e.raw_os_error() == Some(10040)) => continue,
                    Err(e) => return Err(e),
                };
                if !scope.permits(local, peer) || n > MTU { continue; }
                let bytes = &buffer[..n];
                let now = clock.elapsed().as_secs();
                let action = match ingress.process(peer, bytes, now) {
                    Ok(action) => action,
                    // A saturated route table or failed CID allocation is
                    // not permission to stop unrelated established sessions.
                    Err(super::ingress::Error::Limit | super::ingress::Error::Random) => continue,
                    Err(_) => return Err(io::Error::from(io::ErrorKind::InvalidData)),
                };
                match action {
                    Action::Drop => {}
                    Action::Reply(reply) => {
                        if reply.len() <= n {
                            match socket.send_to(&reply, peer).await {
                                Ok(written) if written == reply.len() => {},
                                Ok(_) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                                Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused | io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable) => {},
                                Err(e) => return Err(e),
                            }
                        }
                    }
                    Action::Existing(owner) => {
                        if let Some(tx) = routes.get(&owner) {
                            // Drop on mailbox saturation; never block unrelated CIDs.
                            if let Ok(permit) = tx.try_reserve() { permit.send((bytes.to_vec(), peer)); }
                        }
                    }
                    Action::Accepted { owner, binding } => {
                        let token = crate::reality_quic_wire::long(bytes).map(|h| h.token.to_vec());
                        if let (Some(token), Ok(permit)) = (token, accepts.try_reserve()) {
                            let (tx, incoming) = mpsc::channel(MAILBOX);
                            tx.try_send((bytes.to_vec(), peer)).map_err(|_| io::ErrorKind::InvalidData)?;
                            let initial_reset = ingress.initial_reset(owner, binding.retry).map_err(|_| io::ErrorKind::InvalidData)?;
                            routes.insert(owner, tx);
                            permit.send(Candidate { io: SessionIo::Routed { socket: socket.clone(), scope, incoming, owner, commands: commands.clone() },
                                peer, binding, token, initial_reset, versions: versions.clone() });
                        } else {
                            ingress.close(owner, now).map_err(|_| io::ErrorKind::InvalidData)?;
                        }
                    }
                }
            }
        }
    }
}
