//! Standalone local egress, sharing the SmartTheia negotiation and WinINet
//! owner. This development slice supports Pass and Drop; unaccepted Modify
//! fails closed. It must not be reported as a complete F-20 release.
use super::{ingress::{self, HttpOnce, Request}, LOCAL_LIMIT, REPLY_TIMEOUT};
use crate::{
    anti_dpi::{authority::{Active, Candidate}, dns, Decision},
    client::ClientError,
    net::guarded_io::{revoked, GuardedIo},
    network_scope,
    protocol::{Address, ErrorCode},
    routing::{self, carrier_socket},
    udp_relay,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, Semaphore},
    task::JoinSet,
    time::{timeout, Instant},
};

fn denied() -> ClientError { ClientError::Open(ErrorCode::PolicyDenied) }

struct Runtime {
    active: Active,
    epoch: u64,
    roots: rustls::RootCertStore,
    resolver_slots: Semaphore,
}

impl Runtime {
    fn live(&self) -> bool {
        if network_scope::generation() != Some(self.epoch) {
            self.active.revoke();
        }
        self.active.live()
    }

    async fn target(&self, address: &Address, port: u16) -> Result<Target, ClientError> {
        if !self.live() || !self.active.document().anti_dpi.consent.direct_egress || port == 0 {
            return Err(denied());
        }
        let policy = self.active.policy();
        let pins = match address {
            Address::Dns(name) => {
                let name = routing::domain_name(name).map_err(|_| ClientError::Protocol)?;
                // Reject conclusive Drop or unaccepted Modify before DNS.
                match policy.classify_domain(&name) {
                    Decision::Drop | Decision::Modify => return Err(denied()),
                    _ => {}
                }
                let _permit = self.resolver_slots.try_acquire()
                    .map_err(|_| ClientError::Open(ErrorCode::ResourceLimit))?;
                let live = || self.live();
                let result = dns::resolve(
                    self.active.document().anti_dpi.resolver.as_ref(),
                    policy, &name, &self.roots, &live,
                    Instant::now() + Duration::from_secs(6),
                ).await.map_err(|error| match error {
                    dns::DnsError::PolicyDenied | dns::DnsError::Cancelled => denied(),
                    dns::DnsError::Tls => ClientError::Tls,
                    dns::DnsError::Timeout => ClientError::Timeout,
                    _ => ClientError::Open(ErrorCode::DialFailed),
                })?;
                if result.decision() != Decision::Pass || !result.current() {
                    return Err(denied());
                }
                Some(result)
            }
            Address::V4(_) | Address::V6(_) => None,
        };
        let ip = match (address, &pins) {
            (_, Some(pins)) => *pins.addresses().first().ok_or_else(denied)?,
            (Address::V4(bytes), None) => IpAddr::from(*bytes),
            (Address::V6(bytes), None) => IpAddr::from(*bytes),
            _ => return Err(denied()),
        };
        let ip = crate::anti_dpi::canonical_ip(ip);
        if pins.is_none() && policy.classify_literal(ip) != Decision::Pass {
            return Err(denied());
        }
        let peer = SocketAddr::new(ip, port);
        let scope = network_scope::observe(peer).ok_or_else(denied)?;
        let target = Target { peer, scope, pins };
        if !target.live(self) {
            return Err(denied());
        }
        Ok(target)
    }
}

struct Target {
    peer: SocketAddr,
    scope: network_scope::Scope,
    pins: Option<dns::Pins>,
}

impl Target {
    fn live(&self, runtime: &Runtime) -> bool {
        runtime.live() && self.pins.as_ref().is_none_or(dns::Pins::current)
            && network_scope::observe(self.peer) == Some(self.scope)
    }
}

async fn tcp(
    runtime: &Runtime, socket: &mut TcpStream, is_http: bool,
    address: &Address, port: u16,
) -> Result<(TcpStream, Target), ClientError> {
    let result = async {
        let target = runtime.target(address, port).await?;
        let live = || target.live(runtime);
        let origin = tokio::select! {
            biased;
            _ = revoked(&live) => return Err(denied()),
            result = timeout(Duration::from_secs(6), carrier_socket::connect_plain_tcp(target.peer)) =>
                result.map_err(|_| ClientError::Timeout)?
                    .map_err(|e| if e.kind() == std::io::ErrorKind::PermissionDenied {
                        denied()
                    } else { ClientError::Open(ErrorCode::DialFailed) })?,
        };
        if !target.live(runtime) || !origin.local_addr().is_ok_and(|a| target.scope.matches_local(a)) {
            return Err(denied());
        }
        Ok((origin, target))
    }.await;
    if let Err(error) = &result {
        ingress::failure(socket, is_http, error).await;
    }
    result
}

async fn handle(runtime: Arc<Runtime>, mut socket: TcpStream, is_http: bool) -> Result<(), ClientError> {
    let live = || runtime.live();
    let request = tokio::select! {
        biased;
        _ = revoked(&live) => return Err(denied()),
        result = ingress::negotiate(&mut socket, is_http) => result?,
    };
    let (address, port, plain) = match request {
        Request::Tcp { address, port, plain } => (address, port, plain),
        Request::Udp { address, port } => return association(runtime.clone(), socket, address, port).await,
    };
    let (origin, target) = tcp(&runtime, &mut socket, is_http, &address, port).await?;
    let live = || target.live(&runtime);
    if !live() {
        return Err(denied());
    }
    // Both directions are guarded. In particular a server-first protocol
    // cannot deliver payload following a policy or DNS-pin revocation.
    let mut origin = GuardedIo::new(origin, &live);
    let operation = async {
        if let Some(request) = plain {
            // Share the existing single-request absolute-form HTTP adapter.
            let local = HttpOnce { socket, request: request.into() };
            let mut local = GuardedIo::new(local, &live);
            tokio::io::copy_bidirectional(&mut local, &mut origin).await
                .map_err(|_| ClientError::Io)?;
        } else {
            if !live() { return Err(denied()); }
            tokio::select! {
                biased;
                _ = revoked(&live) => return Err(denied()),
                result = ingress::success(&mut socket, is_http) => result?,
            }
            let mut local = GuardedIo::new(socket, &live);
            tokio::io::copy_bidirectional(&mut local, &mut origin).await
                .map_err(|_| ClientError::Io)?;
        }
        Ok(())
    };
    tokio::select! {
        biased;
        _ = revoked(&live) => Err(denied()),
        // Conservative bound for this initial standalone relay; domain pins
        // usually expire earlier. Never extend a lease silently.
        result = timeout(Duration::from_secs(60), operation) =>
            result.map_err(|_| ClientError::Timeout)?,
    }
}

/// Recheck after readiness and immediately before each actual datagram
/// syscall. WouldBlock is not a successful send and never queues a retry
/// after a datagram has been emitted.
async fn send_udp(
    socket: &UdpSocket,
    bytes: &[u8],
    destination: Option<SocketAddr>,
    live: &(dyn Fn() -> bool + Sync),
) -> Result<(), ClientError> {
    if bytes.len() > crate::protocol::MAX_DATAGRAM {
        return Err(ClientError::Protocol);
    }
    let send = async {
        loop {
            socket.writable().await.map_err(|_| ClientError::Io)?;
            if !live() {
                return Err(denied());
            }
            let result = if let Some(destination) = destination {
                socket.try_send_to(bytes, destination)
            } else {
                socket.try_send(bytes)
            };
            match result {
                Ok(n) if n == bytes.len() => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                _ => return Err(ClientError::Io),
            }
        }
    };
    tokio::select! {
        biased;
        _ = revoked(live) => Err(denied()),
        result = timeout(REPLY_TIMEOUT, send) => result.map_err(|_| ClientError::Timeout)?,
    }
}

async fn udp_flow(
    runtime: Arc<Runtime>, socket: Arc<UdpSocket>, source: SocketAddr,
    address: Address, port: u16, mut queued: mpsc::Receiver<Vec<u8>>,
) -> Result<(), ClientError> {
    let target = runtime.target(&address, port).await?;
    let live = || target.live(&runtime);
    let origin = tokio::select! {
        biased;
        _ = revoked(&live) => return Err(denied()),
        result = timeout(Duration::from_secs(6), udp_relay::connect(target.peer)) =>
            result.map_err(|_| ClientError::Timeout)?.map_err(|_| ClientError::Io)?,
    };
    if !live() || !origin.local_addr().is_ok_and(|a| target.scope.matches_local(a)) {
        return Err(denied());
    }
    let activity = udp_relay::Activity::new();
    let mut buffer = vec![0; 65536];
    let mut packet = Vec::new();
    loop {
        tokio::select! {
            biased;
            _ = revoked(&live) => return Err(denied()),
            _ = activity.expire() => return Ok(()),
            outgoing = queued.recv() => {
                let Some(data) = outgoing else { return Ok(()) };
                if !live() { return Err(denied()); }
                send_udp(&origin, &data, None, &live).await?;
                activity.touch();
            }
            received = origin.recv(&mut buffer) => {
                let count = received.map_err(|_| ClientError::Io)?;
                if !live() { return Err(denied()); }
                if !udp_relay::encode_socks_into(&mut packet, &address, port, &buffer[..count]) {
                    continue;
                }
                send_udp(&socket, &packet, Some(source), &live).await?;
                activity.touch();
            }
        }
    }
}

async fn association(runtime: Arc<Runtime>, mut control: TcpStream, requested: Address, port: u16)
    -> Result<(), ClientError>
{
    let peer = control.peer_addr().map_err(|_| ClientError::Io)?;
    let local = control.local_addr().map_err(|_| ClientError::Io)?;
    if !runtime.live() || !runtime.active.document().anti_dpi.consent.direct_egress
        || !peer.ip().is_loopback() || !local.ip().is_loopback()
        || !udp_relay::valid_associate(&requested, peer.ip())
    {
        ingress::failure(&mut control, false, &denied()).await;
        return Err(denied());
    }
    let socket = Arc::new(carrier_socket::bind_plain_udp(SocketAddr::new(local.ip(), 0))
        .await.map_err(|_| ClientError::Io)?);
    let bound = socket.local_addr().map_err(|_| ClientError::Io)?;
    let mut pinned = (port != 0).then(|| SocketAddr::new(peer.ip(), port));
    let live = || runtime.live();
    if !live() { return Err(denied()); }
    timeout(REPLY_TIMEOUT, control.write_all(&udp_relay::associate_reply(bound)))
        .await.map_err(|_| ClientError::Timeout)?.map_err(|_| ClientError::Io)?;
    let mut flows = HashMap::<(Address, u16), mpsc::Sender<Vec<u8>>>::new();
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0; 65536];
    let mut control_byte = [0; 1];
    let result = loop {
        tokio::select! {
            biased;
            _ = revoked(&live) => break Err(denied()),
            read = control.read(&mut control_byte) => break match read {
                Ok(0) => Ok(()), _ => Err(ClientError::Protocol),
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {
                flows.retain(|_, queue| !queue.is_closed());
            }
            received = socket.recv_from(&mut buffer) => {
                let (count, source) = match received {
                    Ok(value) => value, Err(_) => break Err(ClientError::Io),
                };
                if !live() { break Err(denied()); }
                if source.ip() != peer.ip() || pinned.is_some_and(|p| p != source) {
                    continue;
                }
                let Some((address, port, data)) = udp_relay::parse_socks(&buffer[..count]) else { continue };
                pinned.get_or_insert(source);
                let key = (address, port);
                flows.retain(|_, queue| !queue.is_closed());
                if let Some(queue) = flows.get(&key) {
                    // Congestion drops this datagram, never retries it.
                    let _ = queue.try_send(data.to_vec());
                    continue;
                }
                if tasks.len() >= udp_relay::MAX_FLOWS { continue; }
                let (queue, receiver) = mpsc::channel(udp_relay::QUEUE);
                if queue.try_send(data.to_vec()).is_err() { continue; }
                flows.insert(key.clone(), queue);
                tasks.spawn(udp_flow(runtime.clone(), socket.clone(), source, key.0, key.1, receiver));
            }
        }
    };
    tasks.shutdown().await;
    result
}

async fn serve(runtime: Arc<Runtime>, http: &TcpListener, socks: &TcpListener) -> Result<(), ClientError> {
    let slots = Arc::new(Semaphore::new(LOCAL_LIMIT));
    let mut tasks = JoinSet::new();
    let live = || runtime.live();
    let result = loop {
        let (socket, is_http) = tokio::select! {
            biased;
            _ = revoked(&live) => break Err(denied()),
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
            result = http.accept() => match result {
                Ok((s, _)) => (s, true), Err(_) => break Err(ClientError::Io),
            },
            result = socks.accept() => match result {
                Ok((s, _)) => (s, false), Err(_) => break Err(ClientError::Io),
            },
        };
        if !live() { break Err(denied()); }
        if let Ok(slot) = slots.clone().try_acquire_owned() {
            let runtime = runtime.clone();
            tasks.spawn(async move {
                let _slot = slot;
                let _ = handle(runtime, socket, is_http).await;
            });
        }
    };
    // Revocation lets nested associations drain their owned workers rather
    // than aborting the parent while an inner JoinSet still owns sockets.
    runtime.active.revoke();
    while tasks.join_next().await.is_some() {}
    result
}

/// Windows WinINet lifecycle. The two listeners are reserved before apply,
/// both retained through CAS restore, and bounded flow cleanup precedes
/// release of the shared owner. No fake SmartTheia profile or carrier.
pub(crate) async fn run(candidate: Candidate, expected: [u8; 32]) -> Result<(), ClientError> {
    if candidate.digest() != expected {
        return Err(ClientError::Configuration);
    }
    let reservation = crate::windows_system_proxy::ReservedProxy::acquire()
        .map_err(|_| ClientError::SystemProxy)?;
    let active = candidate.activate().map_err(|_| ClientError::Configuration)?;
    if !active.document().anti_dpi.consent.direct_egress || active.document().anti_dpi.resolver.is_none() {
        return Err(ClientError::Configuration);
    }
    let epoch = network_scope::generation().ok_or_else(denied)?;
    let roots = crate::net::tls::native_roots();
    if roots.is_empty() { return Err(ClientError::Tls); }
    let runtime = Arc::new(Runtime { active, epoch, roots, resolver_slots: Semaphore::new(4) });
    let config = &runtime.active.document().anti_dpi.proxy;
    let http = super::bind_proxy_listener(&config.http_listen).await?;
    let socks = super::bind_proxy_listener(&config.socks5_listen).await?;
    if !runtime.live() { return Err(denied()); }
    let bind = http.local_addr().map_err(|_| ClientError::Io)?;
    let mut owner = reservation.apply(bind, None).map_err(|_| ClientError::SystemProxy)?;
    if owner.verify().is_err() {
        return Err(ClientError::SystemProxy);
    }
    eprintln!("Windows System Proxy readback confirmed. Development Pass/Drop only; Anti-DPI Modify unavailable. Ctrl+C disconnects.");
    let (restored, outcome, cleanup) = {
        let serving = serve(runtime.clone(), &http, &socks);
        tokio::pin!(serving);
        let (outcome, ended) = loop {
            tokio::select! {
                biased;
                signal = tokio::signal::ctrl_c() =>
                    break (signal.map_err(|_| ClientError::Io), false),
                result = &mut serving => break (result, true),
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                    if !runtime.live() || owner.verify().is_err() {
                        break (Err(ClientError::SystemProxy), false);
                    }
                }
            }
        };
        runtime.active.revoke();
        let restored = owner.restore_held().map_err(|_| ClientError::SystemProxy);
        let cleanup = if ended { Ok(()) } else {
            timeout(Duration::from_secs(2), &mut serving).await
                .map(|_| ()).map_err(|_| ClientError::Timeout)
        };
        (restored, outcome, cleanup)
    };
    drop(http);
    drop(socks);
    if restored.is_err() { owner.abandon_after_conflict(); } else { drop(owner); }
    restored.and(outcome).and(cleanup)
}
