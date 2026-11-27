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
pub(super) fn packet_test_hello(name: &str) -> Vec<u8> { tls::fixture(name) }
#[cfg(test)]
pub(super) fn packet_test_quic_hello(name: &str) -> Vec<u8> {
    let mut record = tls::fixture(name);
    // Fixture has no session ID, one cipher and one compression method.
    // Append ALPN h3 and update the extension/handshake/record lengths.
    let extension_len = u16::from_be_bytes(record[50..52].try_into().unwrap());
    record.extend([0,16,0,5,0,3,2,b'h',b'3']);
    record[50..52].copy_from_slice(&(extension_len+9).to_be_bytes());
    let body_len = (record.len()-9) as u32;
    record[6..9].copy_from_slice(&body_len.to_be_bytes()[1..]);
    let record_len = (record.len()-5) as u16;
    record[3..5].copy_from_slice(&record_len.to_be_bytes());
    assert!(packet_quic_hello(&record[5..],name));
    record[5..].to_vec()
}

use crate::{client::ClientError, network_scope};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use strategy::{Key, Strategy, Verdict};
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
        match self { Self::Quic(version) => UdpProbe::Quic(version), Self::StunBinding(_) => UdpProbe::Stun }
    }
}

pub(crate) struct VerifiedUdp {
    pub(crate) socket: tokio::net::UdpSocket,
    pub(crate) strategy: UdpStrategy,
    engine: Arc<Engine>,
    key: Key,
}
impl VerifiedUdp {
    pub(crate) fn check_policy(&self) -> Result<(), ClientError> {
        self.engine.check_policy(self.key.policy)
    }

    pub(crate) fn fallback_policy(&self) -> FallbackPolicy {
        FallbackPolicy {
            engine: self.engine.clone(),
            digest: self.key.policy,
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
    #[cfg(target_os = "linux")]
    pub(crate) fn quic_batch(&self, first: &[u8]) -> Option<Vec<Vec<u8>>> {
        let UdpStrategy::Quic(version) = self.strategy else { return None; };
        if crate::reality_quic_wire::long(first)?.version != version.wire() { return None; }
        super::packet_modify::quic_initial_datagrams(first, &self.key.name)
    }

    pub(crate) fn failed(&self) {
        self.engine.remember_udp(self.key.clone(), self.strategy.probe(), false);
    }

    #[cfg(test)]
    pub(crate) fn disabled_fixture(socket: tokio::net::UdpSocket) -> Self {
        let address = socket.peer_addr().unwrap();
        let engine = Arc::new(Engine::default());
        engine.authorize_policy(Some(super::client_state::LocalPolicy::fixture([1; 32])));
        Self {
            socket,
            strategy: UdpStrategy::Quic(crate::quic_core::wire::Version::V1),
            engine,
            key: Key {
                name: "example.org".into(),
                address,
                policy: [1; 32],
                network: network_scope::Scope::fixture(address, 0),
            },
        }
    }
}

async fn scoped_udp(
    address: SocketAddr,
    scope: network_scope::Scope,
) -> Option<tokio::net::UdpSocket> {
    let socket = tokio::net::UdpSocket::bind(scope.bind_address())
        .await
        .ok()?;
    socket.connect(address).await.ok()?;
    (socket.peer_addr().ok()? == address && scope.matches_local(socket.local_addr().ok()?))
        .then_some(socket)
}

impl Default for Engine {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            stun_enabled: AtomicBool::new(false),
            policy: std::sync::Mutex::new(None),
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
            *policy = if self.retired() { None } else { lease };
        }
    }

    pub(crate) fn retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    /// Retired runtime generations may drain committed flows, but cannot
    /// authorize a new first send or refresh their old policy lease.
    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        self.authorize_policy(None);
    }

    pub(crate) fn policy_current(&self, digest: [u8; 32]) -> bool {
        self.policy
            .lock()
            .ok()
            .is_some_and(|policy| !self.retired() && policy.as_ref().is_some_and(|lease| lease.valid(digest)))
    }

    pub(crate) fn check_policy(&self, digest: [u8; 32]) -> Result<(), ClientError> {
        if self.policy_current(digest) {
            Ok(())
        } else {
            Err(stale_policy())
        }
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
        if network_scope::observe(key.address) != Some(key.network) {
            return;
        }
        if let Ok(mut cache) = self.udp_cache.lock() {
            cache.retain(|entry| (entry.key != key || entry.probe != probe) && entry.expiry > std::time::Instant::now());
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
    pub(crate) async fn open_quic_udp(
        self: &Arc<Self>,
        name: &str,
        port: u16,
        ips: &[IpAddr],
        policy: [u8; 32],
    ) -> Option<VerifiedUdp> {
        self.open_quic_udp_version(name, port, ips, policy, crate::quic_core::wire::Version::V1).await
    }

    pub(crate) async fn open_quic_udp_version(
        self: &Arc<Self>,
        name: &str,
        port: u16,
        ips: &[IpAddr],
        policy: [u8;32],
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
                    network,
                };
                let slot = self.probe_slot(&name, address, policy);
                let guard = self.probe_slots[slot].lock().await;
                if !self.enabled()
                    || !self.policy_current(policy)
                    || network_scope::observe(address) != Some(network)
                {
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
                if !good
                    || !self.enabled()
                    || !self.policy_current(policy)
                    || network_scope::observe(address) != Some(network)
                {
                    continue;
                }
                if let Ok(socket) = crate::udp_relay::connect(address).await {
                    if self.enabled()
                        && self.policy_current(policy)
                        && network_scope::observe(address) == Some(network)
                        && socket
                            .local_addr()
                            .is_ok_and(|local| network.matches_local(local))
                    {
                        return Some(VerifiedUdp {
                            socket,
                            strategy: UdpStrategy::Quic(version),
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
                    network,
                };
                let _guard = self.probe_slots[self.probe_slot(&name, address, policy)]
                    .lock()
                    .await;
                if !self.stun_enabled()
                    || !self.policy_current(policy)
                    || network_scope::observe(address) != Some(network)
                {
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
                        let socket = scoped_udp(address, network).await?;
                        if !self.stun_enabled()
                            || !self.policy_current(policy)
                            || network_scope::observe(address) != Some(network)
                        {
                            return None;
                        }
                        udp::probe_stun(&socket, strategy).await
                    })
                    .await
                    .ok()
                    .flatten()
                    .is_some();
                    if !self.stun_enabled()
                        || !self.policy_current(policy)
                        || network_scope::observe(address) != Some(network)
                    {
                        break;
                    }
                    crate::traffic::udp_stun_probe(good);
                    if good {
                        selected = Some(strategy);
                        break;
                    }
                }
                if !self.stun_enabled()
                    || !self.policy_current(policy)
                    || network_scope::observe(address) != Some(network)
                {
                    continue;
                }
                self.remember_udp(key.clone(), UdpProbe::Stun, selected.is_some());
                let Some(strategy) = selected else {
                    continue;
                };
                if let Some(socket) = scoped_udp(address, network).await {
                    if self.stun_enabled()
                        && self.policy_current(policy)
                        && network_scope::observe(address) == Some(network)
                    {
                        return Some(VerifiedUdp {
                            socket,
                            strategy: UdpStrategy::StunBinding(strategy),
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
        let name = super::domain_name(name).ok()?;
        timeout(OPEN_BUDGET, async {
            for ip in ips.iter().take(2) {
                let address = SocketAddr::new(*ip, port);
                let Some(network) = network_scope::observe(address) else {
                    continue;
                };
                let key = Key { name: name.clone(), address, policy, network };
                let slot = self.probe_slot(&key.name, address, policy);
                let guard = self.probe_slots[slot].lock().await;
                if !self.enabled() || !self.policy_current(policy) || network_scope::observe(address) != Some(network) { continue; }
                let strategy = match self.cache.cached(&key) {
                    Some(Verdict::Verified(strategy)) => { crate::traffic::dpi_cache_hit(); strategy },
                    Some(Verdict::Unavailable) => continue,
                    previous => {
                        let _permit = self.probes.try_acquire().ok()?;
                        let config = tokio::task::spawn_blocking(tls::native_config).await.ok()??;
                        let mut verified = None;
                        for strategy in self.cache.ranked(&key) {
                            if !self.enabled() || !self.policy_current(policy) || network_scope::observe(address) != Some(network) { break; }
                            if matches!(previous, Some(Verdict::Avoid { strategy: failed, .. }) if failed == strategy) { continue; }
                            let started = std::time::Instant::now();
                            let good = timeout(ATTEMPT, tls::probe(&name, address, Some(network), strategy, config.clone()))
                                .await.ok().flatten().is_some();
                            self.cache.observe(&key, strategy, good, started.elapsed());
                            crate::traffic::dpi_probe(good);
                            if good {
                                verified = Some(strategy);
                                break;
                            }
                        }
                        let Some(strategy) = verified else {
                            self.cache.remember(&key, Verdict::Unavailable);
                            continue;
                        };
                        self.cache.remember(&key, Verdict::Verified(strategy));
                        strategy
                    }
                };
                drop(guard);
                if !self.enabled() || !self.policy_current(policy) || network_scope::observe(address) != Some(network) {
                    continue;
                }
                match timeout(ATTEMPT, tcp::connect(address)).await {
                    Ok(Ok(target)) if self.enabled() && self.policy_current(policy)
                        && network_scope::observe(address) == Some(network)
                        && target.local_addr().is_ok_and(|local| network.matches_local(local)) => {
                        return Some(Tunnel {
                            target,
                            strategy,
                            engine: self.clone(),
                            key,
                        });
                    }
                    Ok(Ok(_)) => {
                        // Local scope/consent changed, not evidence against
                        // the peer or a strategy on the previous network.
                    }
                    _ if self.enabled() && self.policy_current(policy) => {
                        self.cache.failed(&key, strategy);
                    }
                    _ => {}

                }
            }
            None
        })
        .await
        .ok()
        .flatten()
    }
}

pub(crate) struct Tunnel {
    target: TcpStream,
    strategy: Strategy,
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
}
impl FallbackPolicy {
    pub(crate) fn check(&self) -> Result<(), ClientError> {
        self.engine.check_policy(self.digest)
    }

    #[cfg(test)]
    pub(crate) fn revoke_fixture(&self) {
        self.engine.authorize_policy(None);
    }
}

impl Tunnel {
    pub(crate) fn fallback_policy(&self) -> FallbackPolicy {
        FallbackPolicy {
            engine: self.engine.clone(),
            digest: self.key.policy,
        }
    }

    pub(crate) async fn relay_guarded(
        mut self,
        mut client: TcpStream,
        flow: Option<&super::flow::FlowLease>,
    ) -> Result<RelayOutcome, ClientError> {
        let mut prefix = Vec::new();
        let ready = match timeout(FIRST_FLIGHT, tcp::read_hello(&mut client, &mut prefix)).await {
            Ok(Ok(ready)) => ready,
            Ok(Err(error)) => return Err(error),
            Err(_) => false,
        };
        // A superseded/expired policy is not permission for VPS fallback.
        if !self.engine.policy_current(self.key.policy) {
            return Err(stale_policy());
        }
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
            || self.engine.cache.cached(&self.key) != Some(Verdict::Verified(self.strategy))
        {
            return Ok(RelayOutcome::Fallback { client, prefix });
        }
        self.engine.check_policy(self.key.policy)?;
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
                self.engine.cache.failed(&self.key, self.strategy);
                crate::traffic::dpi_first_failure();
                crate::traffic::dpi_tls_alert();
                // Forward the genuine alert; do not retry or manufacture a
                // replacement response on a different connection.
                timeout(FIRST_FLIGHT, client.write_all(&alert))
                    .await
                    .map_err(|_| ClientError::Timeout)?
                    .map_err(|_| ClientError::Io)?;
                return Err(ClientError::Tls);
            }
            Ok(Err(error)) => {
                self.engine.cache.failed(&self.key, self.strategy);
                crate::traffic::dpi_first_failure();
                return Err(error);
            }
            Err(_) => {
                self.engine.cache.failed(&self.key, self.strategy);
                crate::traffic::dpi_first_failure();
                crate::traffic::dpi_timeout();
                return Err(ClientError::Timeout);
            }
        };
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
        )
        .await;
        // A ServerHello alone is insufficient evidence of usable application
        // traffic. Do not penalize a clean early application disconnect.
        if peer_failure {
            self.engine.cache.failed(&self.key, self.strategy);
            crate::traffic::dpi_post_hello_failure();
        } else if exchanged && result.is_ok() {
            self.engine
                .cache
                .observe(&self.key, self.strategy, true, hello_elapsed);
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
            strategy: Strategy::Header,
            engine,
            key: Key {
                name: name.into(),
                address,
                policy: [1; 32],
                network: network_scope::Scope::fixture(address, 0),
            },
        }
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
        };
        assert!(authorization.check().is_ok());
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture(
            [2; 32],
        )));
        assert!(authorization.check().is_err());
        engine.authorize_policy(None);
        assert!(authorization.check().is_err());
    }

    #[test]
    fn udp_evidence_does_not_cross_protocol_versions() {
        use crate::quic_core::wire::Version;
        let engine = Engine::default();
        let address = "192.0.2.1:443".parse().unwrap();
        let key = Key { name: "example.org".into(), address, policy: [1;32], network: network_scope::Scope::fixture(address, 1) };
        let expiry = std::time::Instant::now() + Duration::from_secs(60);
        engine.udp_cache.lock().unwrap().push_back(UdpEvidence {
            key: key.clone(), probe: UdpProbe::Quic(Version::V1), good: true, expiry,
        });
        assert_eq!(engine.cached_udp(&key, UdpProbe::Quic(Version::V1)), Some(true));
        assert_eq!(engine.cached_udp(&key, UdpProbe::Quic(Version::V2)), None);
        assert_eq!(engine.cached_udp(&key, UdpProbe::Stun), None);
        engine.udp_cache.lock().unwrap().push_back(UdpEvidence {
            key: key.clone(), probe: UdpProbe::Quic(Version::V2), good: false, expiry,
        });
        assert_eq!(engine.cached_udp(&key, UdpProbe::Quic(Version::V2)), Some(false));
        assert_eq!(engine.cached_udp(&key, UdpProbe::Quic(Version::V1)), Some(true));
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
