//! Standalone local egress, sharing the SmartTheia negotiation and WinINet
//! owner. This development slice supports Pass and Drop; unaccepted Modify
//! fails closed. It must not be reported as a complete F-20 release.
use super::{
    ingress::{self, HttpOnce, Request},
    LOCAL_LIMIT, REPLY_TIMEOUT,
};
use crate::{
    anti_dpi::{
        authority::{Active, Candidate},
        diagnostic::RunContext,
        dns,
        session::{Command, Control, DiagnosticUpdate, Job, Phase},
        Decision,
    },
    client::ClientError,
    net::guarded_io::{revoked, GuardedIo},
    network_scope,
    protocol::{Address, ErrorCode},
    routing::{
        self, carrier_socket,
        dpi::{self, Engine, Strategy, UdpStrategy},
        flow::{FlowTable, Protocol},
        policy_lease::{PolicyLease, PolicyState},
        PacketAction,
    },
    udp_relay,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{atomic::Ordering, Arc, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, Semaphore},
    task::JoinSet,
    time::{timeout, Instant},
};

fn denied() -> ClientError {
    ClientError::Open(ErrorCode::PolicyDenied)
}

struct Runtime {
    active: RwLock<Arc<Active>>,
    epoch: u64,
    roots: rustls::RootCertStore,
    resolver_slots: crate::net::probe::PriorityBudget,
    flows: Arc<FlowTable>,
    control: Arc<Control>,
}

impl Runtime {
    fn live(&self) -> bool {
        if network_scope::generation() != Some(self.epoch) {
            self.revoke();
            return false;
        }
        self.control.ready()
    }

    fn snapshot(&self) -> Result<Arc<Active>, ClientError> {
        self.active
            .read()
            .map(|active| active.clone())
            .map_err(|_| denied())
    }

    fn revoke(&self) {
        if let Ok(active) = self.snapshot() {
            active.revoke();
        }
    }

    fn publication_status(&self) {
        if let Ok(active) = self.snapshot() {
            self.control.publication(
                active.policy().revision(),
                active.policy().digest(),
                self.live() && active.live() && active.document().anti_dpi.consent.direct_egress,
            );
        }
    }

    fn apply(&self, candidate: Candidate, expected: [u8; 32]) -> Result<(), String> {
        let old = self.snapshot().map_err(|error| error.to_string())?;
        if !self.live()
            || !old.matches_path(candidate.path())
            || old.document().anti_dpi.id != candidate.document().anti_dpi.id
            || old.document().anti_dpi.proxy != candidate.document().anti_dpi.proxy
        {
            return Err("Wrong owner/configuration or listener changes require Disconnect".into());
        }
        // The disk floor is the durable CAS authority. Old flows must never
        // survive a publication; a failed/uncertain activation is fail closed.
        candidate
            .apply_over(expected, &old)
            .map_err(|error| error.to_string())?;
        old.revoke();
        let next = candidate.activate().map_err(|error| error.to_string())?;
        *self
            .active
            .write()
            .map_err(|_| "publication lock poisoned".to_owned())? = Arc::new(next);
        self.publication_status();
        Ok(())
    }

    async fn target(
        &self,
        active: &Arc<Active>,
        address: &Address,
        port: u16,
        allow_modify: bool,
    ) -> Result<Target, ClientError> {
        if !self.live()
            || !active.live()
            || !active.document().anti_dpi.consent.direct_egress
            || port == 0
        {
            return Err(denied());
        }
        let policy = active.policy();
        let allow_modify = allow_modify && active.document().anti_dpi.consent.direct_dpi;
        let pins = match address {
            Address::Dns(name) => {
                let name = routing::domain_name(name).map_err(|_| ClientError::Protocol)?;
                // Reject conclusive Drop or unaccepted Modify before DNS.
                match policy.classify_domain(&name) {
                    Decision::Drop => return Err(denied()),
                    Decision::Modify if !allow_modify => return Err(denied()),
                    _ => {}
                }
                let live = || self.live() && active.live();
                let _permit = tokio::select! {
                    biased;
                    _ = revoked(&live) => return Err(denied()),
                    result = timeout(Duration::from_secs(6), self.resolver_slots.production(1)) =>
                        result.map_err(|_| ClientError::Timeout)?
                            .map_err(|_| ClientError::Open(ErrorCode::ResourceLimit))?,
                };
                let result = dns::resolve(
                    active.document().anti_dpi.resolver.as_ref(),
                    policy,
                    &name,
                    &self.roots,
                    &live,
                    Instant::now() + Duration::from_secs(6),
                )
                .await
                .map_err(|error| match error {
                    dns::DnsError::PolicyDenied | dns::DnsError::Cancelled => denied(),
                    dns::DnsError::Tls => ClientError::Tls,
                    dns::DnsError::Timeout => ClientError::Timeout,
                    _ => ClientError::Open(ErrorCode::DialFailed),
                })?;
                if !(result.decision() == Decision::Pass
                    || (allow_modify && result.decision() == Decision::Modify))
                    || !result.current()
                {
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
        let decision = pins.as_ref().map_or(Decision::Pass, dns::Pins::decision);
        let target = Target {
            peer,
            scope,
            pins,
            decision,
            active: active.clone(),
        };
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
    decision: Decision,
    active: Arc<Active>,
}

impl Target {
    fn live(&self, runtime: &Runtime) -> bool {
        runtime.live()
            && self.active.live()
            && self.pins.as_ref().is_none_or(dns::Pins::current)
            && network_scope::observe(self.peer) == Some(self.scope)
    }
}

async fn tcp(runtime: &Runtime, target: &Target) -> Result<TcpStream, ClientError> {
    {
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
        if !target.live(runtime)
            || !origin
                .local_addr()
                .is_ok_and(|a| target.scope.matches_local(a))
        {
            return Err(denied());
        }
        Ok(origin)
    }
}

fn modify_engine(
    runtime: &Arc<Runtime>,
    target: &Arc<Target>,
) -> Result<(Arc<Engine>, PolicyLease), ClientError> {
    let digest = target.active.policy().digest();
    let stun = target.active.document().anti_dpi.consent.direct_dpi_stun;
    let runtime = runtime.clone();
    let evidence_target = target.clone();
    let target = target.clone();
    let authority = PolicyState::standalone(
        digest,
        Arc::new(move || {
            target.live(&runtime) && target.active.document().anti_dpi.consent.direct_dpi
        }),
        stun,
    );
    let pin = authority.pin(digest)?;
    Ok((
        Arc::new(Engine::new_standalone(
            authority,
            &evidence_target.active.evidence,
        )),
        pin,
    ))
}

async fn modify_tcp(
    runtime: Arc<Runtime>,
    target: Arc<Target>,
    mut socket: TcpStream,
    is_http: bool,
    address: Address,
    port: u16,
) -> Result<(), ClientError> {
    let live = || target.live(&runtime);
    let opened = async {
        let Address::Dns(name) = &address else {
            return Err(denied());
        };
        let (engine, pin) = modify_engine(&runtime, &target)?;
        let flow = runtime.flows.begin_pinned(
            pin.clone(),
            Protocol::Tcp,
            address.clone(),
            port,
            PacketAction::Modify,
        )?;
        let _permit = timeout(Duration::from_secs(6), runtime.resolver_slots.production(2))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|_| denied())?;
        let tunnel = engine
            .open_checked_pinned(name, port, &[target.peer.ip()], &pin)
            .await?
            .ok_or_else(denied)?;
        flow.check_pending()?;
        Ok::<_, ClientError>((tunnel, flow))
    };
    let (tunnel, flow) = match tokio::select! {
        biased;
        _ = revoked(&live) => Err(denied()),
        result = opened => result,
    } {
        Ok(value) => value,
        Err(error) => {
            ingress::failure(&mut socket, is_http, &error).await;
            return Err(error);
        }
    };
    tokio::select! {
        biased;
        _ = revoked(&live) => return Err(denied()),
        result = ingress::success(&mut socket, is_http) => result?,
    }
    tokio::select! {
        biased;
        _ = revoked(&live) => Err(denied()),
        result = tunnel.relay_guarded(socket, Some(&flow)) => match result? {
            dpi::RelayOutcome::Finished => Ok(()),
            dpi::RelayOutcome::Fallback { .. } => Err(denied()),
        },
    }
}

async fn handle(
    runtime: Arc<Runtime>,
    mut socket: TcpStream,
    is_http: bool,
) -> Result<(), ClientError> {
    let active = runtime.snapshot()?;
    let live = || runtime.live() && active.live();
    if !live() {
        return Err(denied());
    }
    let request = tokio::select! {
        biased;
        _ = revoked(&live) => return Err(denied()),
        result = ingress::negotiate(&mut socket, is_http) => result?,
    };
    let (address, port, plain) = match request {
        Request::Tcp {
            address,
            port,
            plain,
        } => (address, port, plain),
        Request::Udp { address, port } => {
            return association(runtime.clone(), active.clone(), socket, address, port).await
        }
    };
    let allow_modify = plain.is_none()
        && matches!(port, 443 | 8443)
        && Strategy::ALL
            .into_iter()
            .any(Strategy::available_for_standalone);
    let target = match runtime.target(&active, &address, port, allow_modify).await {
        Ok(target) => target,
        Err(error) => {
            ingress::failure(&mut socket, is_http, &error).await;
            return Err(error);
        }
    };
    if target.decision == Decision::Modify {
        return modify_tcp(
            runtime.clone(),
            Arc::new(target),
            socket,
            is_http,
            address,
            port,
        )
        .await;
    }
    let origin = match tcp(&runtime, &target).await {
        Ok(origin) => origin,
        Err(error) => {
            ingress::failure(&mut socket, is_http, &error).await;
            return Err(error);
        }
    };
    let live = || target.live(&runtime);
    if !live() {
        return Err(denied());
    }
    // Both directions are guarded. In particular a server-first protocol
    // cannot deliver payload following a policy or DNS-pin revocation.
    let mut origin = GuardedIo::new(origin, &live).counted(&runtime.control.uploaded);
    let operation = async {
        if let Some(request) = plain {
            // Share the existing single-request absolute-form HTTP adapter.
            let local = HttpOnce {
                socket,
                request: request.into(),
            };
            let mut local = GuardedIo::new(local, &live).counted(&runtime.control.downloaded);
            tokio::io::copy_bidirectional(&mut local, &mut origin)
                .await
                .map_err(|_| ClientError::Io)?;
        } else {
            if !live() {
                return Err(denied());
            }
            tokio::select! {
                biased;
                _ = revoked(&live) => return Err(denied()),
                result = ingress::success(&mut socket, is_http) => result?,
            }
            let mut local = GuardedIo::new(socket, &live).counted(&runtime.control.downloaded);
            tokio::io::copy_bidirectional(&mut local, &mut origin)
                .await
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
    runtime: Arc<Runtime>,
    active: Arc<Active>,
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    address: Address,
    port: u16,
    mut queued: mpsc::Receiver<Vec<u8>>,
) -> Result<(), ClientError> {
    let current = || runtime.live() && active.live();
    let first = tokio::select! {
        biased;
        _ = revoked(&current) => return Err(denied()),
        first = queued.recv() => match first { Some(first) => first, None => return Ok(()) },
    };
    let mut observer = dpi::udp::Observer::default();
    let strategy = super::egress::udp_strategy_standalone(
        &address,
        port,
        &observer.outgoing(&first),
        &first,
        active.document().anti_dpi.consent.direct_dpi_stun,
    )
    .filter(|s| s.available_for_standalone());
    let target = runtime
        .target(&active, &address, port, strategy.is_some())
        .await?;
    if target.decision == Decision::Modify {
        return modify_udp(
            runtime.clone(),
            Arc::new(target),
            socket,
            source,
            address,
            port,
            strategy.ok_or_else(denied)?,
            first,
            queued,
        )
        .await;
    }
    let live = || target.live(&runtime);
    let origin = tokio::select! {
        biased;
        _ = revoked(&live) => return Err(denied()),
        result = timeout(Duration::from_secs(6), udp_relay::connect(target.peer)) =>
            result.map_err(|_| ClientError::Timeout)?.map_err(|_| ClientError::Io)?,
    };
    if !live()
        || !origin
            .local_addr()
            .is_ok_and(|a| target.scope.matches_local(a))
    {
        return Err(denied());
    }
    let activity = udp_relay::Activity::new();
    let mut buffer = vec![0; 65536];
    let mut packet = Vec::new();
    send_udp(&origin, &first, None, &live).await?;
    runtime
        .control
        .uploaded
        .fetch_add(first.len() as u64, Ordering::Relaxed);
    activity.touch();
    loop {
        tokio::select! {
            biased;
            _ = revoked(&live) => return Err(denied()),
            _ = activity.expire() => return Ok(()),
            outgoing = queued.recv() => {
                let Some(data) = outgoing else { return Ok(()) };
                if !live() { return Err(denied()); }
                send_udp(&origin, &data, None, &live).await?;
                runtime.control.uploaded.fetch_add(data.len() as u64, Ordering::Relaxed);
                activity.touch();
            }
            received = origin.recv(&mut buffer) => {
                let count = received.map_err(|_| ClientError::Io)?;
                if !live() { return Err(denied()); }
                if !udp_relay::encode_socks_into(&mut packet, &address, port, &buffer[..count]) {
                    continue;
                }
                send_udp(&socket, &packet, Some(source), &live).await?;
                runtime.control.downloaded.fetch_add(count as u64, Ordering::Relaxed);
                activity.touch();
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn modify_udp(
    runtime: Arc<Runtime>,
    target: Arc<Target>,
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    address: Address,
    port: u16,
    strategy: UdpStrategy,
    first: Vec<u8>,
    queued: mpsc::Receiver<Vec<u8>>,
) -> Result<(), ClientError> {
    let Address::Dns(name) = &address else {
        return Err(denied());
    };
    let live = || target.live(&runtime);
    let (engine, pin) = modify_engine(&runtime, &target)?;
    let flow = runtime.flows.begin_pinned(
        pin.clone(),
        Protocol::Udp,
        address.clone(),
        port,
        PacketAction::Modify,
    )?;
    let verified = tokio::select! {
        biased;
        _ = revoked(&live) => return Err(denied()),
        result = async {
            let _permit = timeout(Duration::from_secs(6), runtime.resolver_slots.production(1))
                .await.map_err(|_| ClientError::Timeout)?.map_err(|_| denied())?;
            engine.open_standalone_udp(name, port, &[target.peer.ip()], &pin, strategy).await
        } => result?.ok_or_else(denied)?,
    };
    let delivery = verified.fallback_policy();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(udp_relay::QUEUE);
    let down = async {
        let mut packet = Vec::new();
        while let Some(data) = rx.recv().await {
            if !live() {
                return Err(denied());
            }
            delivery.check()?;
            flow.check_live(PacketAction::Modify)?;
            if udp_relay::encode_socks_into(&mut packet, &address, port, &data) {
                send_udp(&socket, &packet, Some(source), &|| {
                    live()
                        && delivery.check().is_ok()
                        && flow.check_live(PacketAction::Modify).is_ok()
                })
                .await?;
            }
        }
        Ok(())
    };
    tokio::select! {
        biased;
        _ = revoked(&live) => Err(denied()),
        result = async {
            tokio::try_join!(udp_relay::relay_standalone_verified(Box::new(verified), first, queued, tx, &flow), down)?;
            Ok(())
        } => result,
    }
}

async fn association(
    runtime: Arc<Runtime>,
    active: Arc<Active>,
    mut control: TcpStream,
    requested: Address,
    port: u16,
) -> Result<(), ClientError> {
    let peer = control.peer_addr().map_err(|_| ClientError::Io)?;
    let local = control.local_addr().map_err(|_| ClientError::Io)?;
    if !runtime.live()
        || !active.live()
        || !active.document().anti_dpi.consent.direct_egress
        || !peer.ip().is_loopback()
        || !local.ip().is_loopback()
        || !udp_relay::valid_associate(&requested, peer.ip())
    {
        ingress::failure(&mut control, false, &denied()).await;
        return Err(denied());
    }
    let socket = Arc::new(
        carrier_socket::bind_plain_udp(SocketAddr::new(local.ip(), 0))
            .await
            .map_err(|_| ClientError::Io)?,
    );
    let bound = socket.local_addr().map_err(|_| ClientError::Io)?;
    let mut pinned = (port != 0).then(|| SocketAddr::new(peer.ip(), port));
    let live = || runtime.live() && active.live();
    if !live() {
        return Err(denied());
    }
    timeout(
        REPLY_TIMEOUT,
        control.write_all(&udp_relay::associate_reply(bound)),
    )
    .await
    .map_err(|_| ClientError::Timeout)?
    .map_err(|_| ClientError::Io)?;
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
                tasks.spawn(crate::traffic::STANDALONE_METER.scope(runtime.control.modify_meter.clone(),
                    udp_flow(runtime.clone(), active.clone(), socket.clone(), source, key.0, key.1, receiver)));
            }
        }
    };
    tasks.shutdown().await;
    result
}

async fn serve(
    runtime: Arc<Runtime>,
    http: &TcpListener,
    socks: &TcpListener,
) -> Result<(), ClientError> {
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
        if !live() {
            break Err(denied());
        }
        if let Ok(slot) = slots.clone().try_acquire_owned() {
            let runtime = runtime.clone();
            tasks.spawn(async move {
                let _slot = slot;
                let counter = runtime.control.enter();
                if crate::traffic::STANDALONE_METER
                    .scope(
                        runtime.control.modify_meter.clone(),
                        handle(runtime.clone(), socket, is_http),
                    )
                    .await
                    .is_err()
                {
                    counter.failure();
                }
            });
        }
    };
    // Revocation lets nested associations drain their owned workers rather
    // than aborting the parent while an inner JoinSet still owns sockets.
    runtime.revoke();
    while tasks.join_next().await.is_some() {}
    result
}

/// Windows WinINet lifecycle. The two listeners are reserved before apply,
/// both retained through CAS restore, and bounded flow cleanup precedes
/// release of the shared owner. No fake SmartTheia profile or carrier.
pub(crate) async fn run(candidate: Candidate, expected: [u8; 32]) -> Result<(), ClientError> {
    let (control, commands) = Control::channel().map_err(|_| ClientError::Configuration)?;
    run_controlled(candidate, expected, control, commands, None).await
}

pub(crate) async fn run_controlled(
    candidate: Candidate,
    expected: [u8; 32],
    control: Arc<Control>,
    commands: mpsc::Receiver<Command>,
    review: Option<crate::windows_system_proxy::ApplyReview>,
) -> Result<(), ClientError> {
    let outcome = run_inner(candidate, expected, control.clone(), commands, review).await;
    control.set_phase(if outcome.is_ok() {
        Phase::Stopped
    } else {
        Phase::Failed
    });
    outcome
}

async fn diagnostic(runtime: Arc<Runtime>, job: Job) {
    let active = match runtime.snapshot() {
        Ok(active) => active,
        Err(error) => {
            let _ = job
                .updates
                .send(DiagnosticUpdate::Done(Err(error.to_string())));
            return;
        }
    };
    let ready = || runtime.live() && active.live();
    let result = job
        .plan
        .run_owned(
            job.confirmation,
            RunContext {
                active: &active,
                epoch: runtime.epoch,
                roots: &runtime.roots,
                cancel: &job.cancel,
                ready: &ready,
                permits: Some(&runtime.resolver_slots),
            },
            |cells| {
                let _ = job.updates.send(DiagnosticUpdate::Cells(cells.to_vec()));
            },
        )
        .await
        .map_err(|error| error.to_string());
    let _ = job.updates.send(DiagnosticUpdate::Done(result));
}

async fn run_inner(
    candidate: Candidate,
    expected: [u8; 32],
    control: Arc<Control>,
    mut commands: mpsc::Receiver<Command>,
    review: Option<crate::windows_system_proxy::ApplyReview>,
) -> Result<(), ClientError> {
    if candidate.digest() != expected {
        return Err(ClientError::Configuration);
    }
    let reservation = crate::windows_system_proxy::ReservedProxy::acquire()
        .map_err(|_| ClientError::SystemProxy)?;
    let control_path = candidate.path().to_path_buf();
    let active = candidate
        .activate()
        .map_err(|_| ClientError::Configuration)?;
    if !active.document().anti_dpi.consent.direct_egress
        || active.document().anti_dpi.resolver.is_none()
    {
        return Err(ClientError::Configuration);
    }
    let epoch = network_scope::generation().ok_or_else(denied)?;
    let roots = crate::net::tls::native_roots();
    if roots.is_empty() {
        return Err(ClientError::Tls);
    }
    let active = Arc::new(active);
    let runtime = Arc::new(Runtime {
        active: RwLock::new(active.clone()),
        epoch,
        roots,
        resolver_slots: crate::net::probe::PriorityBudget::new(),
        flows: FlowTable::standalone(),
        control: control.clone(),
    });
    let config = &active.document().anti_dpi.proxy;
    let http = super::bind_proxy_listener(&config.http_listen).await?;
    let socks = super::bind_proxy_listener(&config.socks5_listen).await?;
    if !active.live() || control.stop.load(Ordering::Acquire) {
        return Err(denied());
    }
    let bind = http.local_addr().map_err(|_| ClientError::Io)?;
    let ipc = crate::windows_control::WindowsServer::bind_standalone(control_path, control.clone())
        .map_err(|_| ClientError::Configuration)?;
    let mut owner = reservation
        .apply(bind, review)
        .map_err(|_| ClientError::SystemProxy)?;
    if owner.verify().is_err() {
        return Err(ClientError::SystemProxy);
    }
    control.set_phase(Phase::Connected);
    runtime.publication_status();
    let mut jobs = JoinSet::new();
    let ipc_serving = ipc.serve();
    tokio::pin!(ipc_serving);
    let (restored, outcome, cleanup) = {
        let serving = serve(runtime.clone(), &http, &socks);
        tokio::pin!(serving);
        let not_stopped = || !control.stop.load(Ordering::Acquire);
        let (outcome, ended) = loop {
            tokio::select! {
                biased;
                signal = tokio::signal::ctrl_c() =>
                    break (signal.map_err(|_| ClientError::Io), false),
                _ = revoked(&not_stopped) => break (Ok(()), false),
                result = &mut serving => break (if control.stop.load(Ordering::Acquire) { Ok(()) } else { result }, true),
                _ = jobs.join_next(), if !jobs.is_empty() => {},
                _ = &mut ipc_serving => break (Err(ClientError::SystemProxy), false),
                Some(command) = commands.recv() => match command {
                    Command::Diagnose(job) => {
                        if jobs.is_empty() && runtime.live() && owner.verify().is_ok() {
                            jobs.spawn(diagnostic(runtime.clone(), job));
                        } else {
                            let _ = job.updates.send(DiagnosticUpdate::Done(Err("Diagnostic already active or proxy owner unavailable".into())));
                        }
                    }
                    Command::Apply { prior, candidate, expected, reply } => {
                        let result = if owner.verify().is_ok() && runtime.live() && control.matches(prior) {
                            runtime.apply(candidate, expected)
                        } else { Err("Proxy ownership lost".into()) };
                        let _ = reply.send(result);
                    }
                    Command::Disconnect { prior, reply, ack } => {
                        if owner.verify().is_ok() && control.matches(prior) {
                            control.disconnect();
                            let _ = reply.send(Ok(()));
                            // Admission is closed immediately. Wait briefly for the
                            // protected IPC response, never for a remote peer.
                            let _ = timeout(Duration::from_secs(1), ack).await;
                            break (Ok(()), false);
                        }
                        let _ = reply.send(Err("Proxy ownership or instance changed".into()));
                    }
                },
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                    runtime.publication_status();
                    if !runtime.live() || owner.verify().is_err() {
                        break (Err(ClientError::SystemProxy), false);
                    }
                }
            }
        };
        control.set_phase(Phase::Stopping);
        runtime.revoke();
        commands.close();
        while let Ok(command) = commands.try_recv() {
            match command {
                Command::Diagnose(job) => {
                    let _ = job
                        .updates
                        .send(DiagnosticUpdate::Done(Err("Proxy session stopped".into())));
                }
                Command::Apply { reply, .. } | Command::Disconnect { reply, .. } => {
                    let _ = reply.send(Err("Proxy session stopped".into()));
                }
            }
        }
        let restored = owner.restore_held().map_err(|_| ClientError::SystemProxy);
        let cleanup = if ended {
            Ok(())
        } else {
            timeout(Duration::from_secs(2), &mut serving)
                .await
                .map(|_| ())
                .map_err(|_| ClientError::Timeout)
        };
        (restored, outcome, cleanup)
    };
    let job_cleanup = timeout(Duration::from_secs(2), async {
        while jobs.join_next().await.is_some() {}
    })
    .await;
    if job_cleanup.is_err() {
        jobs.shutdown().await;
    }
    drop(http);
    drop(socks);
    if restored.is_err() {
        owner.abandon_after_conflict();
    } else {
        drop(owner);
    }
    restored
        .and(outcome)
        .and(cleanup)
        .and(job_cleanup.map_err(|_| ClientError::Timeout))
}
