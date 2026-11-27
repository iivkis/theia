//! Native proxy-based Anti-DPI coordinator. All processing is on owned
//! TCP streams; no raw packets, drivers or platform-specific DPI modules.
mod quic;
mod strategy;
mod tcp;
mod tls;
pub(crate) mod udp;

pub(super) fn complete_packet_hello(bytes: &[u8], expected: &str) -> bool {
    matches!(tls::inspect(bytes), tls::Flight::Complete { consumed, name, .. } if consumed == bytes.len() && name == expected)
}
pub(super) fn packet_quic_hello(message: &[u8], expected: &str) -> bool {
    tls::hello_metadata(message).is_some_and(|(name, h3)| h3 && name == expected)
}
#[cfg(test)]
pub(super) fn packet_test_hello(name: &str) -> Vec<u8> {
    tls::fixture(name)
}
#[cfg(test)]
pub(super) fn packet_test_quic_hello(name: &str) -> Vec<u8> {
    let mut record = tls::fixture(name);
    // Fixture has no session ID, one cipher and one compression method.
    // Append ALPN h3 and update the extension/handshake/record lengths.
    let extension_len = u16::from_be_bytes(record[50..52].try_into().unwrap());
    record.extend([0, 16, 0, 5, 0, 3, 2, b'h', b'3']);
    record[50..52].copy_from_slice(&(extension_len + 9).to_be_bytes());
    let body_len = (record.len() - 9) as u32;
    record[6..9].copy_from_slice(&body_len.to_be_bytes()[1..]);
    let record_len = (record.len() - 5) as u16;
    record[3..5].copy_from_slice(&record_len.to_be_bytes());
    assert!(packet_quic_hello(&record[5..], name));
    record[5..].to_vec()
}

use crate::{client::ClientError, network_scope};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use strategy::{Key, Lease, Strategy, Verdict};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Semaphore, time::timeout};

const ATTEMPT: Duration = Duration::from_secs(2);
const OPEN_BUDGET: Duration = Duration::from_secs(6);
const FIRST_FLIGHT: Duration = Duration::from_secs(5);

pub(crate) fn stale_policy() -> ClientError {
    crate::traffic::dpi_policy_stale();
    ClientError::Open(crate::protocol::ErrorCode::PolicyDenied)
}

/// Profile-local, bounded strategy evidence. No state on disk or in logs.
/// Consent is local configuration, not a command in the server snapshot.
pub(crate) struct Engine {
    enabled: AtomicBool,
    retired: AtomicBool,
    stun_enabled: AtomicBool,
    policy: std::sync::Mutex<Option<super::client_state::LocalPolicy>>,
    policy_epoch: AtomicU64,
    cache: strategy::Cache,
    udp_cache: std::sync::Mutex<std::collections::VecDeque<UdpEvidence>>,
    probes: Semaphore,
    // Bounded lock stripes coalesce simultaneous probes without an unbounded map.
    probe_slots: [tokio::sync::Mutex<()>; 32],
}

struct UdpEvidence {
    key: Key,
    probe: UdpProbe,
    good: bool,
    expiry: std::time::Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UdpProbe {
    Quic(crate::quic_core::wire::Version),
    Stun,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpStrategy {
    Quic(crate::quic_core::wire::Version),
    StunBinding(udp::BindingStrategy),
}

impl UdpStrategy {
    fn probe(self) -> UdpProbe {
        match self {
            Self::Quic(version) => UdpProbe::Quic(version),
            Self::StunBinding(_) => UdpProbe::Stun,
        }
    }
}

pub(crate) struct VerifiedUdp {
    pub(crate) socket: tokio::net::UdpSocket,
    pub(crate) strategy: UdpStrategy,
    engine: Arc<Engine>,
    key: Key,
    _admission: super::carrier_socket::Lease,
}
impl VerifiedUdp {
    pub(crate) fn check_policy(&self) -> Result<(), ClientError> {
        self.engine.check_key_policy(&self.key)
    }

    pub(crate) fn fallback_policy(&self) -> FallbackPolicy {
        FallbackPolicy {
            engine: self.engine.clone(),
            digest: self.key.policy,
            epoch: self.key.epoch,
        }
    }

    pub(crate) fn admissible(&self) -> Result<bool, ClientError> {
        self.check_policy()?;
        Ok(self.engine.enabled()
            && (!matches!(self.strategy, UdpStrategy::StunBinding(_))
                || self.engine.stun_enabled())
            && network_scope::observe(self.key.address) == Some(self.key.network)
            && self
                .socket
                .local_addr()
                .is_ok_and(|local| self.key.network.matches_local(local))
            && self.engine.cached_udp(&self.key, self.strategy.probe()) == Some(true))
    }
    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    pub(crate) fn quic_batch(&self, first: &[u8]) -> Option<Vec<Vec<u8>>> {
        let UdpStrategy::Quic(version) = self.strategy else {
            return None;
        };
        if crate::reality_quic_wire::long(first)?.version != version.wire() {
            return None;
        }
        super::packet_modify::quic_initial_datagrams(first, &self.key.name)
    }

    pub(crate) fn failed(&self) {
        self.engine
            .remember_udp(self.key.clone(), self.strategy.probe(), false);
    }

    #[cfg(test)]
    pub(crate) fn disabled_fixture(socket: tokio::net::UdpSocket) -> Self {
        let address = socket.peer_addr().unwrap();
        let engine = Arc::new(Engine::default());
        engine.authorize_policy(Some(super::client_state::LocalPolicy::fixture([1; 32])));
        Self {
            socket,
            strategy: UdpStrategy::Quic(crate::quic_core::wire::Version::V1),
            _admission: Default::default(),
            engine,
            key: Key {
                name: "example.org".into(),
                address,
                policy: [1; 32],
                epoch: 1,
                network: network_scope::Scope::fixture(address, 0),
            },
        }
    }
}

async fn scoped_udp(
    address: SocketAddr,
    scope: network_scope::Scope,
) -> Option<(tokio::net::UdpSocket, super::carrier_socket::Lease)> {
    let socket = super::carrier_socket::bind_udp(scope.bind_address()).await.ok()?;
    // The local bind is concrete before registering the exact endpoint.
    // No STUN probe or user datagram may precede the owned lease.
    let admission = super::carrier_socket::udp(&socket, address).ok()?;
    socket.connect(address).await.ok()?;
    (socket.peer_addr().ok()? == address && scope.matches_local(socket.local_addr().ok()?))
        .then_some((socket, admission))
}

impl Default for Engine {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            stun_enabled: AtomicBool::new(false),
            policy: std::sync::Mutex::new(None),
            policy_epoch: AtomicU64::new(0),
            cache: strategy::Cache::default(),
            udp_cache: std::sync::Mutex::new(std::collections::VecDeque::new()),
            probes: Semaphore::new(4),
            probe_slots: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
        }
    }
}

impl Engine {
    pub(crate) fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub(crate) fn set_stun_enabled(&self, enabled: bool) {
        self.stun_enabled.store(enabled, Ordering::Relaxed);
    }

    pub(crate) fn stun_enabled(&self) -> bool {
        self.enabled() && self.stun_enabled.load(Ordering::Relaxed)
    }

    pub(super) fn authorize_policy(&self, lease: Option<super::client_state::LocalPolicy>) {
        if let Ok(mut policy) = self.policy.lock() {
            let next = if self.retired() { None } else { lease };
            let continuous = match (&*policy, &next) {
                (Some(old), Some(new)) => old.continues(new),
                (None, None) => true,
                _ => false,
            };
            if !continuous {
                self.policy_epoch.fetch_add(1, Ordering::AcqRel);
            }
            *policy = next;
        }
    }

    pub(crate) fn retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    /// Retired client generations cannot authorize any more user payload.
    /// Server auth-only Apply is a separate admission contract.
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        self.authorize_policy(None);
    }

    pub(crate) fn policy_current(&self, digest: [u8; 32]) -> bool {
        self.policy.lock().ok().is_some_and(|policy| {
            !self.retired() && policy.as_ref().is_some_and(|lease| lease.valid(digest))
        })
    }

    pub(super) fn policy_epoch(&self, digest: [u8; 32]) -> Result<u64, ClientError> {
        let policy = self.policy.lock().map_err(|_| stale_policy())?;
        if self.retired() || !policy.as_ref().is_some_and(|lease| lease.valid(digest)) {
            return Err(stale_policy());
        }
        Ok(self.policy_epoch.load(Ordering::Acquire))
    }

    pub(crate) fn check_policy(&self, digest: [u8; 32]) -> Result<(), ClientError> {
        if self.policy_current(digest) {
            Ok(())
        } else {
            Err(stale_policy())
        }
    }

    fn check_key_policy(&self, key: &Key) -> Result<(), ClientError> {
        if self.policy_epoch(key.policy)? == key.epoch { Ok(()) } else { Err(stale_policy()) }
    }

    fn key_live(&self, key: &Key) -> bool {
        self.enabled()
            && self.check_key_policy(key).is_ok()
            && network_scope::observe(key.address) == Some(key.network)
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn probe_slot(&self, name: &str, address: SocketAddr, policy: [u8; 32]) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        (name, address, policy).hash(&mut hash);
        (hash.finish() as usize) % self.probe_slots.len()
    }

    fn cached_udp(&self, key: &Key, probe: UdpProbe) -> Option<bool> {
        let mut cache = self.udp_cache.lock().ok()?;
        cache.retain(|entry| entry.expiry > std::time::Instant::now());
        cache
            .iter()
            .find(|entry| &entry.key == key && entry.probe == probe)
            .map(|entry| entry.good)
    }

    fn remember_udp(&self, key: Key, probe: UdpProbe, good: bool) {
        if !self.key_live(&key) {
            return;
        }
        if let Ok(mut cache) = self.udp_cache.lock() {
            cache.retain(|entry| {
                (entry.key != key || entry.probe != probe)
                    && entry.expiry > std::time::Instant::now()
            });
            if cache.len() >= 128 {
                cache.pop_front();
            }
            cache.push_back(UdpEvidence {
                key,
                probe,
                good,
                expiry: std::time::Instant::now() + Duration::from_secs(if good { 60 } else { 20 }),
            });
        }
    }

    /// Local reachability strategy; not a ciphertext transformation. Fail
    /// closed to the authenticated VPS before the first application datagram.
    #[cfg(test)]
    pub(crate) async fn open_quic_udp(
        self: &Arc<Self>,
        name: &str,
        port: u16,
        ips: &[IpAddr],
        policy: [u8; 32],
    ) -> Option<VerifiedUdp> {
        self.open_quic_udp_version(name, port, ips, policy, crate::quic_core::wire::Version::V1)
            .await
    }

    pub(crate) async fn open_quic_udp_version(
        self: &Arc<Self>,
        name: &str,
        port: u16,
        ips: &[IpAddr],
        policy: [u8; 32],
        version: crate::quic_core::wire::Version,
    ) -> Option<VerifiedUdp> {
        let probe = UdpProbe::Quic(version);
        if !self.enabled()
            || !self.policy_current(policy)
            || port != 443
            || ips.is_empty()
            || ips.len() > 64
            || !ips
                .iter()
                .all(|ip| crate::server::allowed_destination(*ip, false))
        {
            return None;
        }
        let epoch = self.policy_epoch(policy).ok()?;
        let name = super::domain_name(name).ok()?;
        timeout(OPEN_BUDGET, async {
            for ip in ips.iter().take(2) {
                let address = SocketAddr::new(*ip, port);
                let Some(network) = network_scope::observe(address) else {
                    continue;
                };
                let key = Key {
                    name: name.clone(),
                    address,
                    policy,
                    epoch,
                    network,
                };
                let slot = self.probe_slot(&name, address, policy);
                let guard = self.probe_slots[slot].lock().await;
                if !self.key_live(&key) {
                    continue;
                }
                let good = if let Some(good) = self.cached_udp(&key, probe) {
                    crate::traffic::dpi_cache_hit();
                    good
                } else {
                    let _permit = self.probes.try_acquire().ok()?;
                    let config = tokio::task::spawn_blocking(tls::native_config)
                        .await
                        .ok()??;
                    let good = timeout(
                        ATTEMPT,
                        udp::probe_quic(&name, address, Some(network), config, version),
                    )
                    .await
                    .ok()
                    .flatten()
                    .is_some();
                    crate::traffic::dpi_probe(good);
                    self.remember_udp(key.clone(), probe, good);
                    good
                };
                drop(guard);
                if !good || !self.key_live(&key) {
                    continue;
                }
                if let Some((socket, admission)) = scoped_udp(address, network).await {
                    if self.key_live(&key)
                        && socket
                            .local_addr()
                            .is_ok_and(|local| network.matches_local(local))
                    {
                        return Some(VerifiedUdp {
                            socket,
                            strategy: UdpStrategy::Quic(version),
                            _admission: admission,
                            engine: self.clone(),
                            key,
                        });
                    }
                }
                self.remember_udp(key, probe, false);
            }
            None
        })
        .await
        .ok()
        .flatten()
    }

    /// Opt-in, credential-free STUN Binding reachability. The probe uses a
    /// separate socket; no probe response can enter the application relay.
    /// No positive result is reused to skip probing another flow.
    pub(crate) async fn open_stun_udp(
        self: &Arc<Self>,
        name: &str,
        port: u16,
        ips: &[IpAddr],
        policy: [u8; 32],
    ) -> Option<VerifiedUdp> {
        if !self.stun_enabled()
            || !self.policy_current(policy)
            || port != 3478
            || ips.is_empty()
            || ips.len() > 64
            || !ips
                .iter()
                .all(|ip| crate::server::allowed_destination(*ip, false))
        {
            return None;
        }
        let epoch = self.policy_epoch(policy).ok()?;
        let name = super::domain_name(name).ok()?;
        timeout(OPEN_BUDGET, async {
            for ip in ips.iter().take(2) {
                let address = SocketAddr::new(*ip, port);
                let Some(network) = network_scope::observe(address) else {
                    continue;
                };
                let key = Key {
                    name: name.clone(),
                    address,
                    policy,
                    epoch,
                    network,
                };
                let _guard = self.probe_slots[self.probe_slot(&name, address, policy)]
                    .lock()
                    .await;
                if !self.stun_enabled() || !self.key_live(&key) {
                    continue;
                }
                if self.cached_udp(&key, UdpProbe::Stun) == Some(false) {
                    continue;
                }
                let _permit = self.probes.try_acquire().ok()?;
                let mut selected = None;
                for strategy in [
                    udp::BindingStrategy::Fingerprint,
                    udp::BindingStrategy::Plain,
                ] {
                    let good = timeout(Duration::from_millis(1200), async {
                        let (socket, _admission) = scoped_udp(address, network).await?;
                        if !self.stun_enabled() || !self.key_live(&key) {
                            return None;
                        }
                        udp::probe_stun(&socket, strategy).await
                    })
                    .await
                    .ok()
                    .flatten()
                    .is_some();
                    if !self.stun_enabled() || !self.key_live(&key) {
                        break;
                    }
                    crate::traffic::udp_stun_probe(good);
                    if good {
                        selected = Some(strategy);
                        break;
                    }
                }
                if !self.stun_enabled() || !self.key_live(&key) {
                    continue;
                }
                self.remember_udp(key.clone(), UdpProbe::Stun, selected.is_some());
                let Some(strategy) = selected else {
                    continue;
                };
                if let Some((socket, admission)) = scoped_udp(address, network).await {
                    if self.stun_enabled() && self.key_live(&key) {
                        return Some(VerifiedUdp {
                            socket,
                            strategy: UdpStrategy::StunBinding(strategy),
                            _admission: admission,
                            engine: self.clone(),
                            key,
                        });
                    }
                }
            }
            None
        })
        .await
        .ok()
        .flatten()
    }

    pub(crate) async fn open(
        self: &Arc<Self>,
        name: &str,
        port: u16,
        ips: &[IpAddr],
        policy: [u8; 32],
    ) -> Option<Tunnel> {
        if !self.enabled()
            || !self.policy_current(policy)
            || !matches!(port, 443 | 8443)
            || ips.is_empty()
            || ips.len() > 64
            || !ips
                .iter()
                .all(|ip| crate::server::allowed_destination(*ip, false))
        {
            return None;
        }
        let epoch = self.policy_epoch(policy).ok()?;
        let name = super::domain_name(name).ok()?;
        let deadline = tokio::time::Instant::now() + OPEN_BUDGET;
        timeout(OPEN_BUDGET, async {
            for ip in ips.iter().take(2) {
                let address = SocketAddr::new(*ip, port);
                let Some(network) = network_scope::observe(address) else { continue };
                let key = Key { name: name.clone(), address, policy, epoch, network };
                let slot = self.probe_slot(&key.name, address, policy);
                let guard = self.probe_slots[slot].lock().await;
                if !self.key_live(&key) { continue; }
                let (strategy, lease) = match self.cache.evidence(&key) {
                    Some((Verdict::Verified(strategy), lease)) => {
                        crate::traffic::dpi_cache_hit();
                        (strategy, lease)
                    }
                    Some((Verdict::Unavailable, _)) => continue,
                    previous => {
                        let _permit = self.probes.try_acquire().ok()?;
                        let config = tokio::task::spawn_blocking(tls::native_config).await.ok()??;
                        let mut verified = None;
                        let mut attempted = 0;
                        let mut order = self.cache.ranked(&key);
                        // A recently failed strategy is last, not permanently
                        // excluded. A new complete round can rehabilitate it.
                        if let Some((Verdict::Avoid { strategy: failed, .. }, _)) = previous {
                            order.sort_by_key(|strategy| *strategy == failed);
                        }
                        for strategy in order {
                            if !self.key_live(&key) { break; }
                            // Reserve a real application TCP dial before
                            // starting another independent probe. Never
                            // record overall budget exhaustion as peer failure.
                            if deadline.saturating_duration_since(tokio::time::Instant::now())
                                < ATTEMPT + ATTEMPT {
                                break;
                            }
                            let started = std::time::Instant::now();
                            let good = timeout(ATTEMPT, tls::probe_guarded(
                                &name, address, Some(network), strategy, config.clone(),
                                || self.key_live(&key),
                            )).await.ok().flatten().is_some();
                            if !self.key_live(&key) { break; }
                            attempted += 1;
                            self.cache.observe(&key, strategy, good, started.elapsed());
                            crate::traffic::dpi_probe(good);
                            if good {
                                verified = Some(strategy);
                                break;
                            }
                        }
                        if !self.key_live(&key) { continue; }
                        let Some(strategy) = verified else {
                            // Only a complete, still-authorized strategy round
                            // may publish negative evidence.
                            if attempted == Strategy::ALL.len() {
                                let _ = self.cache.remember(&key, Verdict::Unavailable);
                            }
                            continue;
                        };
                        let Some(lease) = self.cache.remember(&key, Verdict::Verified(strategy)) else {
                            continue;
                        };
                        (strategy, lease)
                    }
                };
                drop(guard);
                if !self.key_live(&key) || !self.cache.current(&key, strategy, &lease) {
                    continue;
                }
                if let Ok(Ok((target, admission))) = timeout(ATTEMPT, tcp::connect(address)).await {
                    if self.key_live(&key)
                        && self.cache.current(&key, strategy, &lease)
                        && target.local_addr().is_ok_and(|local| network.matches_local(local)) {
                        return Some(Tunnel {
                            target, _admission: admission, strategy, lease,
                            engine: self.clone(), key,
                        });
                    }
                }
                // A failed plain TCP dial is not a failed TLS strategy.
            }
            None
        }).await.ok().flatten()
    }
}

pub(crate) struct Tunnel {
    target: TcpStream,
    _admission: super::carrier_socket::Lease,
    strategy: Strategy,
    lease: Lease,
    engine: Arc<Engine>,
    key: Key,
}

/// Fallback is legal only before the first write to the selected origin.
/// The prefix belongs exclusively to the application and is sent once.
pub(crate) enum RelayOutcome {
    Finished,
    Fallback { client: TcpStream, prefix: Vec<u8> },
}

pub(crate) struct FallbackPolicy {
    engine: Arc<Engine>,
    digest: [u8; 32],
    epoch: u64,
}
impl FallbackPolicy {
    pub(crate) fn check(&self) -> Result<(), ClientError> {
        if self.engine.policy_epoch(self.digest)? == self.epoch { Ok(()) } else { Err(stale_policy()) }
    }

    #[cfg(test)]
    pub(crate) fn revoke_fixture(&self) {
        self.engine.authorize_policy(None);
    }
}

/// Consume only the bounded initial flight. The name is a probe hint,
/// never authenticated domain evidence. Preserve partial bytes on timeout.
pub(crate) async fn read_tcp_hint(client: &mut TcpStream) -> Result<(Vec<u8>, Option<String>), ClientError> {
    let mut prefix = Vec::new();
    let ready = match timeout(FIRST_FLIGHT, tcp::read_hello(client, &mut prefix)).await {
        Ok(Ok(ready)) => ready,
        Ok(Err(error)) => return Err(error),
        Err(_) => false,
    };
    let name = if ready {
        match tls::inspect(&prefix) {
            tls::Flight::Complete { name, .. } => Some(name),
            _ => None,
        }
    } else { None };
    Ok((prefix, name))
}

impl Tunnel {
    pub(crate) fn fallback_policy(&self) -> FallbackPolicy {
        FallbackPolicy {
            engine: self.engine.clone(),
            digest: self.key.policy,
            epoch: self.key.epoch,
        }
    }

    pub(crate) async fn relay_guarded(
        self,
        mut client: TcpStream,
        flow: Option<&super::flow::FlowLease>,
    ) -> Result<RelayOutcome, ClientError> {
        let (prefix, name) = read_tcp_hint(&mut client).await?;
        self.relay_prefix(client, prefix, name.is_some(), flow).await
    }

    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    pub(crate) fn matches_native_target(&self, key: super::packet::FlowKey, source: IpAddr) -> bool {
        self.target.peer_addr().ok() == Some(key.destination)
            && self.target.local_addr().is_ok_and(|a| a.ip() == source)
    }

    pub(crate) async fn relay_prefix(
        mut self,
        mut client: TcpStream,
        prefix: Vec<u8>,
        ready: bool,
        flow: Option<&super::flow::FlowLease>,
    ) -> Result<RelayOutcome, ClientError> {
        // A superseded/expired policy is not permission for VPS fallback.
        self.engine.check_key_policy(&self.key)?;
        let transformed = if ready {
            tls::transform(&prefix, &self.key.name, self.strategy)
        } else {
            None
        };
        let Some(transformed) = transformed.filter(|bytes| bytes != &prefix) else {
            // Unsupported protocol, ECH, SNI mismatch, partial input or
            // timeout: no origin application bytes have left this process.
            return Ok(RelayOutcome::Fallback { client, prefix });
        };
        if !self.engine.enabled()
            || network_scope::observe(self.key.address) != Some(self.key.network)
            || !self
                .target
                .local_addr()
                .is_ok_and(|local| self.key.network.matches_local(local))
            || !self.engine.cache.current(&self.key, self.strategy, &self.lease)
        {
            return Ok(RelayOutcome::Fallback { client, prefix });
        }
        self.engine.check_key_policy(&self.key)?;
        if let Some(flow) = flow {
            flow.commit(super::PacketAction::Modify)?;
        }
        // From the first attempted write onward, even a partial write or
        // timeout is terminal for this stream. Never replay it over the VPS.
        let started = std::time::Instant::now();
        let response = timeout(FIRST_FLIGHT, async {
            self.target
                .write_all(&transformed)
                .await
                .map_err(|_| ClientError::Io)?;
            tcp::read_server_hello(&mut self.target).await
        })
        .await;
        let response = match response {
            Ok(Ok(tcp::ServerFlight::Hello(response))) => response,
            Ok(Ok(tcp::ServerFlight::Alert(alert))) => {
                self.engine.cache.failed(&self.key, self.strategy, &self.lease);
                crate::traffic::dpi_first_failure();
                crate::traffic::dpi_tls_alert();
                // Forward the genuine alert; do not retry or manufacture a
                // replacement response on a different connection.
                if let Some(flow)=flow {flow.check_live(super::PacketAction::Modify)?;}
                timeout(FIRST_FLIGHT, client.write_all(&alert))
                    .await
                    .map_err(|_| ClientError::Timeout)?
                    .map_err(|_| ClientError::Io)?;
                return Err(ClientError::Tls);
            }
            Ok(Err(error)) => {
                self.engine.cache.failed(&self.key, self.strategy, &self.lease);
                crate::traffic::dpi_first_failure();
                return Err(error);
            }
            Err(_) => {
                self.engine.cache.failed(&self.key, self.strategy, &self.lease);
                crate::traffic::dpi_first_failure();
                crate::traffic::dpi_timeout();
                return Err(ClientError::Timeout);
            }
        };
        if let Some(flow)=flow {flow.check_live(super::PacketAction::Modify)?;}
        timeout(FIRST_FLIGHT, client.write_all(&response))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|_| ClientError::Io)?;
        let hello_elapsed = started.elapsed();
        crate::traffic::dpi_first_response();
        let (result, exchanged, peer_failure) = super::client_state::relay_direct_after_first(
            client,
            self.target,
            prefix.len(),
            response.len(),
            flow,
        )
        .await;
        // A ServerHello alone is insufficient evidence of usable application
        // traffic. Do not penalize a clean early application disconnect.
        if peer_failure {
            self.engine.cache.failed(&self.key, self.strategy, &self.lease);
            crate::traffic::dpi_post_hello_failure();
        } else if exchanged && result.is_ok() {
            self.engine
                .cache
                .succeeded(&self.key, self.strategy, &self.lease, hello_elapsed);
        }
        result?;
        Ok(RelayOutcome::Finished)
    }

    #[cfg(test)]
    pub(crate) fn fixture(target: TcpStream, name: &str) -> Self {
        let address = target.peer_addr().unwrap();
        let engine = Arc::new(Engine::default());
        engine.authorize_policy(Some(super::client_state::LocalPolicy::fixture([1; 32])));
        Self {
            target,
            _admission: Default::default(),
            strategy: Strategy::Header,
            lease: Lease::new(),
            engine,
            key: Key {
                name: name.into(),
                address,
                policy: [1; 32],
                epoch: 1,
                network: network_scope::Scope::fixture(address, 0),
            },
        }
    }
}

#[cfg(test)]
mod native_admission_tests {
    use super::*;
    use crate::routing::carrier_socket::{self, Registrar};
    use std::io;
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpSocket, UdpSocket}};

    struct Refuse;
    impl Registrar for Refuse {
        fn tcp(&self, _: &TcpSocket, _: SocketAddr) -> io::Result<carrier_socket::Lease> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
        fn udp(&self, _: &UdpSocket, _: SocketAddr) -> io::Result<carrier_socket::Lease> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
        fn retire(&self) -> io::Result<()> { Ok(()) }
    }

    #[tokio::test]
    async fn native_probe_cannot_dial_without_admission() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        carrier_socket::scope(Some(Arc::new(Refuse)), async {
            assert!(tcp::connect(target).await.is_err());
            if let Some(scope) = network_scope::observe(target) {
                assert!(scoped_udp(target, scope).await.is_none());
            }
        }).await;
        assert!(timeout(Duration::from_millis(50), listener.accept()).await.is_err());
    }

    #[cfg(any(target_os="linux",all(target_os="windows",target_arch="x86_64")))]
    #[tokio::test]
    async fn native_udp_socket_retains_exact_preconnect_lease() {
        use std::sync::atomic::{AtomicUsize,Ordering as AtomicOrdering};
        struct Count(Arc<AtomicUsize>);
        impl Drop for Count {
            fn drop(&mut self) {self.0.fetch_sub(1,AtomicOrdering::SeqCst);}
        }
        struct Admit {
            count:Arc<AtomicUsize>,
            peer:SocketAddr,
        }
        impl Registrar for Admit {
            fn tcp(&self,_:&TcpSocket,_:SocketAddr)->io::Result<carrier_socket::Lease> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
            fn udp(&self,socket:&UdpSocket,peer:SocketAddr)->io::Result<carrier_socket::Lease> {
                assert_eq!(peer,self.peer);
                assert!(socket.peer_addr().is_err());
                assert_eq!(socket.local_addr().unwrap().ip(),peer.ip());
                assert_ne!(socket.local_addr().unwrap().port(),0);
                self.count.fetch_add(1,AtomicOrdering::SeqCst);
                Ok(carrier_socket::Lease::retain(Count(self.count.clone())))
            }
            fn retire(&self)->io::Result<()> {Ok(())}
        }
        let receiver=UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer=receiver.local_addr().unwrap();
        let network=network_scope::Scope::fixture(peer,0);
        let count=Arc::new(AtomicUsize::new(0));
        let owner=Arc::new(Admit{count:count.clone(),peer});
        let (socket,lease)=carrier_socket::scope(Some(owner),scoped_udp(peer,network)).await.unwrap();
        assert_eq!(socket.peer_addr().unwrap(),peer);
        assert_eq!(count.load(AtomicOrdering::SeqCst),1);
        drop(socket);
        drop(lease);
        assert_eq!(count.load(AtomicOrdering::SeqCst),0);
    }

    #[tokio::test]
    async fn native_tcp_hint_preserves_exact_consumed_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (sender, receiver) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()), listener.accept()
        );
        let mut sender = sender.unwrap();
        let (mut receiver, _) = receiver.unwrap();
        let hello = tls::fixture("example.org");
        sender.write_all(&hello).await.unwrap();
        sender.write_all(b"following bytes").await.unwrap();
        let (prefix, name) = read_tcp_hint(&mut receiver).await.unwrap();
        assert_eq!(prefix, hello);
        assert_eq!(name.as_deref(), Some("example.org"));
        let mut following = [0; 15];
        receiver.read_exact(&mut following).await.unwrap();
        assert_eq!(&following, b"following bytes");
    }
}

#[cfg(test)]
pub(crate) fn test_hello() -> Vec<u8> {
    tls::fixture("example.org")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deferred_fallback_cannot_reuse_revoked_policy() {
        let engine = Arc::new(Engine::default());
        let digest = [1; 32];
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture(
            digest,
        )));
        let authorization = FallbackPolicy {
            engine: engine.clone(),
            digest,
            epoch: engine.policy_epoch(digest).unwrap(),
        };
        assert!(authorization.check().is_ok());
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture(
            [2; 32],
        )));
        assert!(authorization.check().is_err());
        engine.authorize_policy(None);
        assert!(authorization.check().is_err());
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture(digest)));
        assert!(authorization.check().is_err(), "same digest must not revive fallback");
    }

    #[test]
    fn udp_evidence_does_not_cross_protocol_versions() {
        use crate::quic_core::wire::Version;
        let engine = Engine::default();
        let address = "192.0.2.1:443".parse().unwrap();
        let key = Key {
            name: "example.org".into(),
            address,
            policy: [1; 32],
            epoch: 1,
            network: network_scope::Scope::fixture(address, 1),
        };
        let expiry = std::time::Instant::now() + Duration::from_secs(60);
        engine.udp_cache.lock().unwrap().push_back(UdpEvidence {
            key: key.clone(),
            probe: UdpProbe::Quic(Version::V1),
            good: true,
            expiry,
        });
        assert_eq!(
            engine.cached_udp(&key, UdpProbe::Quic(Version::V1)),
            Some(true)
        );
        assert_eq!(engine.cached_udp(&key, UdpProbe::Quic(Version::V2)), None);
        assert_eq!(engine.cached_udp(&key, UdpProbe::Stun), None);
        engine.udp_cache.lock().unwrap().push_back(UdpEvidence {
            key: key.clone(),
            probe: UdpProbe::Quic(Version::V2),
            good: false,
            expiry,
        });
        assert_eq!(
            engine.cached_udp(&key, UdpProbe::Quic(Version::V2)),
            Some(false)
        );
        assert_eq!(
            engine.cached_udp(&key, UdpProbe::Quic(Version::V1)),
            Some(true)
        );
    }

    #[tokio::test]
    async fn disabled_or_private_targets_never_probe() {
        let engine = Arc::new(Engine::default());
        assert!(engine
            .open("example.org", 443, &["8.8.8.8".parse().unwrap()], [1; 32])
            .await
            .is_none());
        assert!(engine
            .open_quic_udp("example.org", 443, &["8.8.8.8".parse().unwrap()], [1; 32])
            .await
            .is_none());
        engine.set_enabled(true);
        assert!(engine
            .open_quic_udp("localhost", 443, &["127.0.0.1".parse().unwrap()], [1; 32])
            .await
            .is_none());
        assert!(engine
            .open_quic_udp("example.org", 53, &["8.8.8.8".parse().unwrap()], [1; 32])
            .await
            .is_none());
        assert!(engine
            .open_quic_udp("example.org", 443, &[], [1; 32])
            .await
            .is_none());
        assert!(engine
            .open("localhost", 443, &["127.0.0.1".parse().unwrap()], [1; 32])
            .await
            .is_none());
        assert!(engine
            .open("example.org", 80, &["8.8.8.8".parse().unwrap()], [1; 32])
            .await
            .is_none());
        assert!(engine
            .open("example.org", 443, &[], [1; 32])
            .await
            .is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test]
    async fn udp_evidence_requires_live_scope_consent_and_policy_and_is_bounded() {
        use crate::quic_core::wire::Version;
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let network = (0..16)
            .find_map(|_| network_scope::observe(address))
            .unwrap();
        let engine = Arc::new(Engine::default());
        let policy = [1; 32];
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture(
            policy,
        )));
        engine.set_enabled(true);
        engine.set_stun_enabled(true);
        let key = Key {
            name: "example.org".into(),
            address,
            policy,
            epoch: engine.policy_epoch(policy).unwrap(),
            network,
        };
        let (socket, admission) = scoped_udp(address, network).await.unwrap();
        let verified = VerifiedUdp {
            socket,
            _admission: admission,
            strategy: UdpStrategy::StunBinding(udp::BindingStrategy::Fingerprint),
            engine: engine.clone(),
            key: key.clone(),
        };
        assert!(!verified.admissible().unwrap());
        engine.remember_udp(key.clone(), UdpProbe::Stun, true);
        assert!(verified.admissible().unwrap());
        engine.set_stun_enabled(false);
        assert!(!verified.admissible().unwrap());
        engine.set_stun_enabled(true);
        verified.failed();
        assert_eq!(engine.cached_udp(&key, UdpProbe::Stun), Some(false));
        assert!(!verified.admissible().unwrap());
        engine.remember_udp(key.clone(), UdpProbe::Quic(Version::V2), true);
        assert_eq!(engine.cached_udp(&key, UdpProbe::Quic(Version::V1)), None);
        for i in 0..129 {
            let mut other = key.clone();
            other.name = format!("host{i}.example.org");
            engine.remember_udp(other, UdpProbe::Stun, true);
        }
        assert_eq!(engine.udp_cache.lock().unwrap().len(), 128);
        assert_eq!(engine.cached_udp(&key, UdpProbe::Stun), None);
        for item in engine.udp_cache.lock().unwrap().iter_mut() {
            item.expiry = std::time::Instant::now();
        }
        assert_eq!(engine.cached_udp(&key, UdpProbe::Stun), None);
        assert!(engine.udp_cache.lock().unwrap().is_empty());
        let fallback = verified.fallback_policy();
        engine.retire();
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture(
            policy,
        )));
        assert!(verified.admissible().is_err());
        assert!(fallback.check().is_err());
        assert!(
            peer.try_recv_from(&mut [0; 1]).is_err(),
            "scope/cache checks must not send"
        );
    }

    #[tokio::test]
    async fn authorized_engine_rejects_invalid_scope_before_network_io() {
        let engine = Arc::new(Engine::default());
        let policy = [1; 32];
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture(
            policy,
        )));
        engine.set_enabled(true);
        engine.set_stun_enabled(true);
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        for (name, ips) in [
            ("invalid/name", vec![public]),
            ("example.org", vec![]),
            ("example.org", vec![public, local]),
            ("example.org", vec![public; 65]),
        ] {
            assert!(engine.open(name, 443, &ips, policy).await.is_none());
            assert!(engine
                .open_quic_udp(name, 443, &ips, policy)
                .await
                .is_none());
            assert!(engine
                .open_stun_udp(name, 3478, &ips, policy)
                .await
                .is_none());
        }
        assert!(engine
            .open("example.org", 80, &[public], policy)
            .await
            .is_none());
        assert!(engine
            .open_quic_udp("example.org", 80, &[public], policy)
            .await
            .is_none());
        assert!(engine
            .open_stun_udp("example.org", 443, &[public], policy)
            .await
            .is_none());
        engine.retire();
        assert!(engine
            .open_stun_udp("example.org", 3478, &[public], policy)
            .await
            .is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test]
    async fn guarded_relay_preserves_exact_first_flight_and_never_replays_after_alert() {
        use tokio::io::AsyncReadExt;
        async fn pair() -> (TcpStream, TcpStream) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (a, b) = tokio::join!(
                TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept()
            );
            (a.unwrap(), b.unwrap().0)
        }
        for alert in [true, false] {
            timeout(Duration::from_secs(8), async {
                let (app, client) = pair().await;
                let (target, mut origin) = pair().await;
                let mut tunnel = Tunnel::fixture(target, "example.org");
                tunnel.key.network = (0..16)
                    .find_map(|_| network_scope::observe(tunnel.key.address))
                    .unwrap();
                tunnel.engine.set_enabled(true);
                tunnel.lease = tunnel
                    .engine
                    .cache
                    .remember(&tunnel.key, Verdict::Verified(Strategy::Header))
                    .unwrap();
                let expected = tls::transform(
                    &tls::fixture("example.org"),
                    "example.org",
                    Strategy::Header,
                )
                .unwrap();
                let mut app = app;
                app.write_all(&tls::fixture("example.org")).await.unwrap();
                let wire = if alert {
                    vec![21, 3, 3, 0, 2, 2, 40]
                } else {
                    let mut message = vec![2, 0, 0, 38, 3, 3];
                    message.extend([1; 32]);
                    message.extend([0, 0x13, 1, 0]);
                    let mut wire = vec![22, 3, 3, 0, message.len() as u8];
                    wire.extend(message);
                    wire
                };
                let io = async {
                    let mut got = vec![0; expected.len()];
                    origin.read_exact(&mut got).await.unwrap();
                    assert_eq!(got, expected);
                    origin.write_all(&wire).await.unwrap();
                    let mut actual = vec![0; wire.len()];
                    app.read_exact(&mut actual).await.unwrap();
                    assert_eq!(actual, wire);
                    if !alert {
                        app.write_all(b"upload").await.unwrap();
                        let mut up = [0; 6];
                        origin.read_exact(&mut up).await.unwrap();
                        assert_eq!(&up, b"upload");
                        origin.write_all(b"download").await.unwrap();
                        let mut down = [0; 8];
                        app.read_exact(&mut down).await.unwrap();
                        assert_eq!(&down, b"download");
                        app.shutdown().await.unwrap();
                        origin.shutdown().await.unwrap();
                    }
                };
                let (result, ()) = tokio::join!(tunnel.relay_guarded(client, None), io);
                if alert {
                    assert!(matches!(result, Err(ClientError::Tls)));
                } else {
                    assert!(matches!(result, Ok(RelayOutcome::Finished)));
                }
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn real_tls_peer_accepts_native_record_strategies_and_rejects_wrong_name() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.cert.der().clone();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let config = tls::tls_config(roots).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        timeout(Duration::from_secs(10), async {
            for (name, strategy, expected) in [
                ("localhost", Strategy::Header, true),
                ("localhost", Strategy::Middle, true),
                ("localhost", Strategy::Balanced, true),
                ("wrong.invalid", Strategy::Header, false),
            ] {
                let server = async {
                    let (socket, _) = listener.accept().await.unwrap();
                    acceptor.accept(socket).await.is_ok()
                };
                let client = tls::probe(name, address, None, strategy, config.clone());
                let (server_ok, client_ok) = tokio::join!(server, client);
                assert_eq!(client_ok.is_some(), expected);
                assert_eq!(server_ok, expected);
            }
        })
        .await
        .unwrap();
    }
}
