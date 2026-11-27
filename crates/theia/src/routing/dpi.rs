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
    sync::Arc,
    time::Duration,
};
use strategy::{Key, Lease, Strategy, Verdict};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Semaphore, time::timeout};

const ATTEMPT: Duration = Duration::from_secs(2);
const PROBE_WAVE: usize = 2;
const OPEN_BUDGET: Duration = Duration::from_secs(6);
const FIRST_FLIGHT: Duration = Duration::from_secs(5);

pub(crate) use super::policy_lease::stale_policy;
use super::policy_lease::{PolicyLease, PolicyState};

/// Profile-local, bounded strategy evidence. No state on disk or in logs.
/// Consent is local configuration, not a command in the server snapshot.
pub(crate) struct Engine {
    policy: Arc<PolicyState>,
    cache: strategy::Cache,
    probes: Semaphore,
    // Bounded lock stripes coalesce simultaneous probes without an unbounded map.
    probe_slots: [tokio::sync::Mutex<()>; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UdpProbe {
    Quic(crate::quic_core::wire::Version),
    Stun,
}

impl UdpProbe {
    fn index(self) -> usize {
        use crate::quic_core::wire::Version;
        match self { Self::Quic(Version::V1) => 3, Self::Quic(Version::V2) => 4, Self::Stun => 5 }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpStrategy {
    Quic(crate::quic_core::wire::Version),
    StunBinding(udp::BindingStrategy),
}

impl UdpStrategy {
    /// Product activation is a reviewed source-level gate, not a user
    /// configuration switch or a successful reachability probe. Populate
    /// only after independent, exact-revision F-15 acceptance.
    pub(crate) fn accepted_for_proxy(self) -> bool {
        const ACCEPTED: &[UdpStrategy] = &[];
        !matches!(self, Self::StunBinding(udp::BindingStrategy::Plain)) && ACCEPTED.contains(&self)
    }

    pub(crate) fn capability_summary() -> String {
        use crate::quic_core::wire::Version;
        let status = |strategy: Self| if strategy.accepted_for_proxy() { "принят" } else { "ожидает приёмки" };
        format!("QUIC v1: {}; QUIC v2: {}; STUN: {}",
            status(Self::Quic(Version::V1)), status(Self::Quic(Version::V2)),
            status(Self::StunBinding(udp::BindingStrategy::Fingerprint)))
    }

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
    lease: Lease,
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
            scope: self.engine.enabled().then_some((self.key.address, self.key.network)),
            require_stun: matches!(self.strategy, UdpStrategy::StunBinding(_)),
            tcp_evidence: None,
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
            && self.engine.udp_current(&self.key, self.strategy.probe(), &self.lease))
    }
    pub(crate) fn quic_batch(&self, first: &[u8]) -> Option<Vec<Vec<u8>>> {
        let UdpStrategy::Quic(version) = self.strategy else {
            return None;
        };
        if crate::reality_quic_wire::long(first)?.version != version.wire() {
            return None;
        }
        super::packet_modify::quic_initial_datagrams(first, &self.key.name)
    }

    /// Once the real flow is selected, cache expiry is not a reason to
    /// change egress. The exact policy, consent and route remain mandatory.
    pub(crate) fn check_live(&self) -> Result<(), ClientError> {
        self.check_policy()?;
        if !self.engine.key_live(&self.key)
            || (matches!(self.strategy, UdpStrategy::StunBinding(_)) && !self.engine.stun_enabled())
            || self.socket.peer_addr().ok() != Some(self.key.address)
            || !self.socket.local_addr().is_ok_and(|local| self.key.network.matches_local(local))
        { return Err(stale_policy()); }
        Ok(())
    }

    pub(crate) async fn wait_revoked(&self) -> Result<(), ClientError> {
        loop {
            self.check_live()?;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub(crate) fn failed(&self) {
        self.engine
            .fail_udp(&self.key, self.strategy.probe(), &self.lease);
    }

    #[cfg(test)]
    pub(crate) fn active_fixture(
        socket: tokio::net::UdpSocket, strategy: UdpStrategy, name: &str,
    ) -> (Self, super::flow::FlowLease) {
        let address = socket.peer_addr().unwrap();
        let network = (0..16).find_map(|_| network_scope::observe(address)).unwrap();
        let engine = Arc::new(Engine::default());
        let policy = [1; 32];
        engine.authorize_policy(Some(super::client_state::LocalPolicy::fixture(policy)));
        engine.set_enabled(true);
        engine.set_stun_enabled(true);
        let key = Key { name: name.into(), address, policy, epoch: engine.policy_epoch(policy).unwrap(), network };
        let lease = engine.remember_udp(key.clone(), strategy.probe(), true).unwrap();
        let flow = super::flow::FlowTable::shared().begin(
            engine.policy.clone(), super::flow::Protocol::Udp,
            crate::protocol::Address::Dns(name.into()), address.port(), policy, super::PacketAction::Modify,
        ).unwrap();
        (Self { socket, strategy, engine, key, lease, _admission: Default::default() }, flow)
    }

    #[cfg(test)]
    pub(crate) fn disabled_fixture(socket: tokio::net::UdpSocket) -> Self {
        let address = socket.peer_addr().unwrap();
        let engine = Arc::new(Engine::default());
        engine.authorize_policy(Some(super::client_state::LocalPolicy::fixture([1; 32])));
        Self {
            socket,
            strategy: UdpStrategy::Quic(crate::quic_core::wire::Version::V1),
            lease: Lease::new(),
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

#[cfg(test)]
async fn scoped_udp(
    address: SocketAddr,
    scope: network_scope::Scope,
) -> Option<(tokio::net::UdpSocket, super::carrier_socket::Lease)> {
    scoped_udp_checked(address, scope).await.ok().flatten()
}

async fn scoped_udp_checked(
    address: SocketAddr, scope: network_scope::Scope,
) -> Result<Option<(tokio::net::UdpSocket, super::carrier_socket::Lease)>, ClientError> {
    fn network_error(error: std::io::Error) -> Result<Option<()>, ClientError> {
        if error.kind() == std::io::ErrorKind::PermissionDenied { Err(stale_policy()) }
        else { Ok(None) }
    }
    let (socket, admission) = match super::carrier_socket::dial_udp(scope.bind_address(), address, true, |local| scope.matches_local(local)).await {
        Ok(value) => value,
        Err(error) => { network_error(error.into_io())?; return Ok(None); }
    };
    if !socket.local_addr().is_ok_and(|local| scope.matches_local(local)) { return Err(stale_policy()); }
    Ok(Some((socket, admission)))
}

impl Default for Engine {
    fn default() -> Self { Self::new(Arc::new(PolicyState::default())) }
}

impl Engine {
    pub(crate) fn new(policy: Arc<PolicyState>) -> Self {
        Self {
            policy,
            cache: strategy::Cache::default(),
            probes: Semaphore::new(4),
            probe_slots: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
        }
    }
    pub(crate) fn set_enabled(&self, enabled: bool) { self.policy.set_enabled(enabled); }
    pub(crate) fn set_stun_enabled(&self, enabled: bool) { self.policy.set_stun_enabled(enabled); }
    pub(crate) fn stun_enabled(&self) -> bool { self.policy.stun_enabled() }
    #[cfg(test)]
    pub(super) fn authorize_policy(&self, lease: Option<super::client_state::LocalPolicy>) { self.policy.authorize_policy(lease); }
    pub(crate) fn retired(&self) -> bool { self.policy.retired() }
    #[cfg(test)]
    pub(crate) fn retire(&self) { self.policy.retire(); }
    pub(super) fn policy_epoch(&self, digest: [u8; 32]) -> Result<u64, ClientError> { self.policy.policy_epoch(digest) }

    fn check_key_policy(&self, key: &Key) -> Result<(), ClientError> {
        if self.policy_epoch(key.policy)? == key.epoch { Ok(()) } else { Err(stale_policy()) }
    }

    fn key_live(&self, key: &Key) -> bool {
        self.enabled()
            && self.check_key_policy(key).is_ok()
            && network_scope::observe(key.address) == Some(key.network)
    }

    pub(crate) fn enabled(&self) -> bool { self.policy.enabled() }

    fn probe_slot(&self, name: &str, address: SocketAddr, policy: [u8; 32]) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        (name, address, policy).hash(&mut hash);
        (hash.finish() as usize) % self.probe_slots.len()
    }

    fn udp_evidence(&self, key: &Key, probe: UdpProbe) -> Option<(bool, Lease)> {
        self.cache.udp_evidence(key, probe)
    }

    #[cfg(test)]
    fn cached_udp(&self, key: &Key, probe: UdpProbe) -> Option<bool> {
        self.udp_evidence(key, probe).map(|(good, _)| good)
    }

    fn udp_current(&self, key: &Key, probe: UdpProbe, lease: &Lease) -> bool {
        self.udp_evidence(key, probe).is_some_and(|(good, current)| good && current.same(lease))
    }

    fn remember_udp(&self, key: Key, probe: UdpProbe, good: bool) -> Option<Lease> {
        if !self.key_live(&key) { return None; }
        self.cache.remember_udp(&key, probe, good)
    }

    fn fail_udp(&self, key: &Key, probe: UdpProbe, lease: &Lease) {
        if self.key_live(key) { self.cache.fail_udp(key, probe, lease); }
    }

    fn ranked_udp_keys(&self, name: &str, port: u16, ips: &[IpAddr], policy: [u8; 32],
        epoch: u64, probe: UdpProbe) -> Vec<Key> {
        let mut keys: Vec<_> = ips.iter().take(2).filter_map(|ip| {
            let address = SocketAddr::new(*ip, port);
            let network = network_scope::observe(address)?;
            Some(Key { name: name.to_owned(), address, policy, epoch, network })
        }).collect();
        keys.sort_by_key(|key| self.cache.udp_score(key, probe));
        keys
    }

    #[cfg(test)]
    pub(crate) async fn open_quic_udp(
        self: &Arc<Self>, name: &str, port: u16, ips: &[IpAddr], policy: [u8; 32],
    ) -> Option<VerifiedUdp> {
        self.open_quic_udp_version(name, port, ips, policy, crate::quic_core::wire::Version::V1).await
    }

    // Native lab callers intentionally retain their fail-closed Option API.
    pub(crate) async fn open_quic_udp_version(
        self: &Arc<Self>, name: &str, port: u16, ips: &[IpAddr], policy: [u8; 32],
        version: crate::quic_core::wire::Version,
    ) -> Option<VerifiedUdp> {
        self.open_udp_checked(name, port, ips, policy, UdpStrategy::Quic(version)).await.ok().flatten()
    }

    pub(crate) async fn open_stun_udp(
        self: &Arc<Self>, name: &str, port: u16, ips: &[IpAddr], policy: [u8; 32],
    ) -> Option<VerifiedUdp> {
        self.open_udp_checked(name, port, ips, policy, UdpStrategy::StunBinding(udp::BindingStrategy::Fingerprint)).await.ok().flatten()
    }

    /// Product selection must not confuse ordinary QUIC reachability
    /// with a verified active de-coalescing probe. The current native
    /// dialer disables tickets/0-RTT and uses MTU 1200, so it cannot produce
    /// the required independently originated coalesced first flight.
    #[cfg(test)]
    pub(crate) async fn open_proxy_udp_checked(
        self: &Arc<Self>, name: &str, port: u16, ips: &[IpAddr], policy: [u8;32],
        strategy: UdpStrategy,
    ) -> Result<Option<VerifiedUdp>, ClientError> {
        let pin = self.policy.pin(policy)?;
        self.open_proxy_udp_pinned(name, port, ips, &pin, strategy).await
    }

    pub(crate) async fn open_proxy_udp_pinned(
        self: &Arc<Self>, name: &str, port: u16, ips: &[IpAddr], pin: &PolicyLease,
        strategy: UdpStrategy,
    ) -> Result<Option<VerifiedUdp>, ClientError> {
        pin.check_owner(&self.policy)?;
        if matches!(strategy, UdpStrategy::Quic(_)) {
            // Fail closed to an authorized pre-send XHTTP fallback, without
            // probing the target or reusing lab-only reachability evidence.
            if ips.len() > 64 || !ips.iter().all(|ip| crate::server::allowed_destination(*ip, false)) {
                return Err(stale_policy());
            }
            pin.check()?;
            return Ok(None);
        }
        self.open_udp_pinned(name, port, ips, pin, strategy).await
    }

    /// Ok(None) is a safe pre-user-write fallback. Err is a protective
    /// refusal. Probe evidence authenticates QUIC reachability only; the
    /// product route must separately require accepted active transformation.
    pub(crate) async fn open_udp_checked(
        self: &Arc<Self>, name: &str, port: u16, ips: &[IpAddr], policy: [u8; 32],
        strategy: UdpStrategy,
    ) -> Result<Option<VerifiedUdp>, ClientError> {
        let pin = self.policy.pin(policy)?;
        self.open_udp_pinned(name, port, ips, &pin, strategy).await
    }

    async fn open_udp_pinned(
        self: &Arc<Self>, name: &str, port: u16, ips: &[IpAddr], pin: &PolicyLease,
        strategy: UdpStrategy,
    ) -> Result<Option<VerifiedUdp>, ClientError> {
        pin.check_owner(&self.policy)?;
        let policy = pin.digest();
        let stun = match strategy {
            UdpStrategy::Quic(_) if port == 443 => false,
            UdpStrategy::StunBinding(udp::BindingStrategy::Fingerprint) if port == 3478 => true,
            _ => return Ok(None),
        };
        if !self.enabled() || (stun && !self.stun_enabled()) || ips.is_empty() { return Ok(None); }
        if ips.len() > 64 || !ips.iter().all(|ip| crate::server::allowed_destination(*ip, false)) {
            return Err(ClientError::Open(crate::protocol::ErrorCode::PolicyDenied));
        }
        let name = super::domain_name(name).map_err(|_| ClientError::Protocol)?;
        let probe = strategy.probe();
        let deadline = tokio::time::Instant::now() + OPEN_BUDGET;
        let keys = self.ranked_udp_keys(&name, port, ips, policy, pin.epoch(), probe);
        let probe_key = |key: Key| {
            let name = &name;
            async move {
                let address = key.address;
                let live = || self.key_live(&key) && (!stun || self.stun_enabled());
                let slot = &self.probe_slots[self.probe_slot(&name, address, policy)];
                // Contention before a probe is a safe budget fallback, not
                // a negative strategy result or an ambiguous handshake.
                let Ok(_guard) = timeout(Duration::from_millis(250), slot.lock()).await else { return Ok(None) };
                if !live() { return Err(stale_policy()); }
                let cached = self.udp_evidence(&key, probe);
                let lease = match cached {
                    Some((false, _)) => return Ok(None),
                    Some((true, lease)) if !stun => {
                        crate::traffic::dpi_cache_hit();
                        lease
                    }
                    _ => {
                        let Ok(_permit) = self.probes.try_acquire() else { return Ok(None) };
                        let ceiling = if stun { Duration::from_millis(1200) } else { ATTEMPT };
                        let budget = self.cache.udp_budget(&key, probe, ceiling);
                        if deadline.saturating_duration_since(tokio::time::Instant::now()) < budget + ATTEMPT {
                            return Ok(None);
                        }
                        let started = std::time::Instant::now();
                        let result = match strategy {
                            UdpStrategy::Quic(version) => {
                                let Ok(Some(config)) = tokio::task::spawn_blocking(tls::native_config).await else { return Ok(None) };
                                if !live() { return Err(stale_policy()); }
                                // A shorter outer budget must not mask a
                                // received but unauthenticated QUIC handshake.
                                if deadline.saturating_duration_since(tokio::time::Instant::now()) < budget + ATTEMPT { return Ok(None); }
                                let revoked = async {
                                    loop {
                                        if !live() { return Err(stale_policy()); }
                                        tokio::time::sleep(Duration::from_millis(50)).await;
                                    }
                                };
                                tokio::select! {
                                    biased;
                                    result = revoked => result?,
                                    result = udp::probe_quic_checked(&name, address, Some(key.network), config, version, budget) => result?,
                                }
                            }
                            UdpStrategy::StunBinding(binding) => {
                                let Some((socket, _admission)) = scoped_udp_checked(address, key.network).await? else { return Ok(None) };
                                if !live() { return Err(stale_policy()); }
                                match timeout(budget, udp::probe_stun_checked(&socket, binding, &live)).await {
                                    Ok(result) => result?,
                                    Err(_) => None,
                                }
                            }
                        };
                        if !live() { return Err(stale_policy()); }
                        let good = result.is_some();
                        self.cache.observe_udp(&key, probe, good, started.elapsed(), result.and_then(|sample| sample.rtt));
                        if stun { crate::traffic::udp_stun_probe(good); } else { crate::traffic::dpi_probe(good); }
                        let Some(lease) = self.remember_udp(key.clone(), probe, good) else { return Err(stale_policy()) };
                        if !good { return Ok(None); }
                        lease
                    }
                };
                if !live() { return Err(stale_policy()); }
                if !self.udp_current(&key, probe, &lease) { return Ok(None); }
                let Some((socket, admission)) = scoped_udp_checked(address, key.network).await? else { return Ok(None) };
                if !live() { return Err(stale_policy()); }
                if self.udp_current(&key, probe, &lease) {
                    return Ok(Some(VerifiedUdp {
                        socket, strategy, lease, _admission: admission, engine: self.clone(), key,
                    }));
                }
                Ok(None)
            }
        };
        let result = timeout(OPEN_BUDGET, async {
            let mut keys = keys.into_iter();
            let Some(first) = keys.next() else { return Ok(None) };
            let second = keys.next();
            let (left, right) = tokio::join!(
                probe_key(first),
                async { match second { Some(key) => probe_key(key).await, None => Ok(None) } }
            );
            // Never use a positive peer to mask an identity or policy error
            // from the other completed probe. Both share the global cap.
            let left = left?;
            let right = right?;
            Ok(left.or(right))
        }).await;
        pin.check()?;
        if !self.enabled() || (stun && !self.stun_enabled()) { return Err(stale_policy()); }
        // An unknown outcome of an in-progress probe is not a fallback.
        result.unwrap_or_else(|_| Err(ClientError::Timeout))
    }

    #[cfg(test)]
    async fn open(self: &Arc<Self>, name: &str, port: u16, ips: &[IpAddr], policy: [u8; 32]) -> Option<Tunnel> {
        self.open_checked(name, port, ips, policy).await.ok().flatten()
    }

    pub(crate) async fn open_checked(
        self: &Arc<Self>,
        name: &str,
        port: u16,
        ips: &[IpAddr],
        policy: [u8; 32],
    ) -> Result<Option<Tunnel>, ClientError> {
        let pin = self.policy.pin(policy)?;
        self.open_checked_pinned(name, port, ips, &pin).await
    }

    pub(crate) async fn open_checked_pinned(
        self: &Arc<Self>, name: &str, port: u16, ips: &[IpAddr], pin: &PolicyLease,
    ) -> Result<Option<Tunnel>, ClientError> {
        pin.check_owner(&self.policy)?;
        let policy = pin.digest();
        if !self.enabled() || !matches!(port, 443 | 8443) || ips.is_empty() {
            return Ok(None);
        }
        if ips.len() > 64 || !ips.iter().all(|ip| crate::server::allowed_destination(*ip, false)) {
            return Err(ClientError::Open(crate::protocol::ErrorCode::PolicyDenied));
        }
        let epoch = pin.epoch();
        let name = super::domain_name(name).map_err(|_| ClientError::Protocol)?;
        let deadline = tokio::time::Instant::now() + OPEN_BUDGET;
        let result = timeout(OPEN_BUDGET, async {
            for ip in ips.iter().take(2) {
                let address = SocketAddr::new(*ip, port);
                let Some(network) = network_scope::observe(address) else { continue };
                let key = Key { name: name.clone(), address, policy, epoch, network };
                let slot = self.probe_slot(&key.name, address, policy);
                let Ok(guard) = timeout(Duration::from_millis(250), self.probe_slots[slot].lock()).await else { return Ok(None) };
                if !self.key_live(&key) { return Err(stale_policy()); }
                let (strategy, lease) = match self.cache.evidence(&key) {
                    Some((Verdict::Verified(strategy), lease)) => {
                        crate::traffic::dpi_cache_hit();
                        (strategy, lease)
                    }
                    Some((Verdict::Unavailable, _)) => continue,
                    Some((Verdict::Denied, _)) => return Err(stale_policy()),
                    previous => {
                        let Ok(Some(config)) = tokio::task::spawn_blocking(tls::native_config).await else { return Ok(None) };
                        let mut verified = None;
                        let mut attempted = 0;
                        let mut order = self.cache.ranked(&key);
                        if let Some((Verdict::Avoid { strategy: failed, .. }, _)) = previous {
                            order.sort_by_key(|strategy| *strategy == failed);
                        }
                        // Parallel bounded waves. Collect both completed
                        // outcomes before selection so a protective refusal
                        // cannot be hidden behind a faster positive probe.
                        for wave in order.chunks(PROBE_WAVE) {
                            if !self.key_live(&key) { return Err(stale_policy()); }
                            let probe = |strategy: Strategy| {
                                let key = &key;
                                let name = &name;
                                let config = config.clone();
                                async move {
                                    let budget = self.cache.tcp_budget(key, strategy, ATTEMPT);
                                    if deadline.saturating_duration_since(tokio::time::Instant::now()) < budget + ATTEMPT {
                                        return None;
                                    }
                                    let _permit = self.probes.try_acquire().ok()?;
                                    let started = std::time::Instant::now();
                                    let mut rtt = None;
                                    let verdict = tls::probe_measured(
                                        name, address, Some(network), strategy, config, budget,
                                        || self.key_live(key), &mut rtt,
                                    ).await;
                                    Some((strategy, verdict, started.elapsed(), rtt))
                                }
                            };
                            let (first, second) = tokio::join!(
                                probe(wave[0]),
                                async { match wave.get(1) { Some(&strategy) => probe(strategy).await, None => None } }
                            );
                            if !self.key_live(&key) { return Err(stale_policy()); }
                            use tls::ProbeVerdict::*;
                            let outcomes = [first, second];
                            for (_, verdict, _, _) in outcomes.iter().flatten() {
                                use crate::net::error::FailureClass;
                                match verdict.failure() {
                                    Some(FailureClass::IdentityRejected) => return Err(ClientError::Tls),
                                    Some(FailureClass::PolicyDenied) => return Err(stale_policy()),
                                    _ => {}
                                }
                            }
                            let mut best = None;
                            for (strategy, verdict, elapsed, rtt) in outcomes.into_iter().flatten() {
                                if matches!(verdict, Verified | StrategyFailed) {
                                    let good = verdict == Verified;
                                    attempted += 1;
                                    self.cache.observe(&key, strategy, good, elapsed, rtt);
                                    crate::traffic::dpi_probe(good);
                                    if good && best.is_none_or(|(_, prior)| elapsed < prior) {
                                        best = Some((strategy, elapsed));
                                    }
                                }
                            }
                            if let Some((strategy, _)) = best {
                                verified = Some(strategy);
                                break;
                            }
                        }
                        if !self.key_live(&key) { return Err(stale_policy()); }
                        let Some(strategy) = verified else {
                            if attempted == Strategy::ALL.len() {
                                let _ = self.cache.remember(&key, Verdict::Unavailable);
                            }
                            continue;
                        };
                        let Some(lease) = self.cache.remember(&key, Verdict::Verified(strategy)) else {
                            return Err(stale_policy());
                        };
                        (strategy, lease)
                    }
                };
                drop(guard);
                if !self.key_live(&key) { return Err(stale_policy()); }
                if self.cache.denied_tcp(&key) { return Err(stale_policy()); }
                if !self.cache.current(&key, strategy, &lease) { continue; }
                match timeout(ATTEMPT, tcp::connect(address)).await {
                    Ok(Ok((target, admission))) => {
                        if !self.key_live(&key)
                            || !target.local_addr().is_ok_and(|local| network.matches_local(local)) {
                            return Err(stale_policy());
                        }
                        if self.cache.current(&key, strategy, &lease) {
                            return Ok(Some(Tunnel {
                                target, _admission: admission, strategy, lease,
                                engine: self.clone(), key,
                            }));
                        }
                    }
                    Ok(Err(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                        return Err(ClientError::Open(crate::protocol::ErrorCode::PolicyDenied));
                    }
                    _ => {}
                }
                if !self.key_live(&key) { return Err(stale_policy()); }
            }
            Ok(None)
        }).await;
        pin.check()?;
        if !self.enabled() { return Err(stale_policy()); }
        result.unwrap_or(Ok(None))
    }

    pub(crate) fn due_tcp_refresh(&self) -> Option<RefreshTarget> {
        if !self.enabled() || self.retired() { return None; }
        let (key, strategy, lease) = self.cache.due_tcp()?;
        self.key_live(&key).then_some(RefreshTarget { key, strategy, lease })
    }

    /// Caller must freshly resolve protected DNS and classify all pins
    /// against the current snapshot before invoking this background probe.
    pub(crate) fn invalidate_refresh(&self, target: RefreshTarget) {
        if self.key_live(&target.key) { self.cache.deny_tcp(&target.key, &target.lease); }
    }

    pub(crate) async fn refresh_tcp(&self, target: RefreshTarget) {
        let RefreshTarget { key, strategy, lease } = target;
        if !self.key_live(&key) { return; }
        let slot = &self.probe_slots[self.probe_slot(&key.name, key.address, key.policy)];
        let Ok(_guard) = slot.try_lock() else { return };
        let Ok(_permit) = self.probes.try_acquire() else { return };
        if !self.key_live(&key) || !self.cache.current(&key, strategy, &lease) { return; }
        let Ok(Some(config)) = tokio::task::spawn_blocking(tls::native_config).await else { return };
        let budget = self.cache.tcp_budget(&key, strategy, ATTEMPT);
        let started = std::time::Instant::now();
        let mut rtt = None;
        let verdict = tls::probe_measured(&key.name, key.address, Some(key.network), strategy,
            config, budget, || self.key_live(&key) && self.cache.current(&key, strategy, &lease), &mut rtt).await;
        if !self.key_live(&key) || !self.cache.current(&key, strategy, &lease) { return; }
        match verdict {
            tls::ProbeVerdict::Verified => {
                if self.cache.renew_tcp(&key, strategy, &lease) {
                    self.cache.observe(&key, strategy, true, started.elapsed(), rtt);
                    crate::traffic::dpi_probe(true);
                }
            }
            tls::ProbeVerdict::StrategyFailed => {
                self.cache.failed(&key, strategy, &lease);
                crate::traffic::dpi_probe(false);
            }
            // Never convert a protective refusal to a cached fallback.
            // Expire the original evidence, forcing fresh foreground validation.
            tls::ProbeVerdict::IdentityRejected | tls::ProbeVerdict::Denied =>
                self.cache.deny_tcp(&key, &lease),
            tls::ProbeVerdict::Unavailable => {}
        }
    }

}

pub(crate) struct RefreshTarget {
    key: Key,
    strategy: Strategy,
    lease: Lease,
}
impl RefreshTarget {
    pub(crate) fn name(&self) -> &str { &self.key.name }
    pub(crate) fn address(&self) -> SocketAddr { self.key.address }
    pub(crate) fn digest(&self) -> [u8;32] { self.key.policy }
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
    scope: Option<(SocketAddr, network_scope::Scope)>,
    require_stun: bool,
    tcp_evidence: Option<Key>,
}
impl FallbackPolicy {
    pub(crate) fn check(&self) -> Result<(), ClientError> {
        if self.engine.policy_epoch(self.digest)? != self.epoch { return Err(stale_policy()); }
        if self.require_stun && !self.engine.stun_enabled() { return Err(stale_policy()); }
        if self.tcp_evidence.as_ref().is_some_and(|key| self.engine.cache.denied_tcp(key)) {
            return Err(stale_policy());
        }
        if self.scope.is_some_and(|(address, scope)| !self.engine.enabled() || network_scope::observe(address) != Some(scope)) {
            return Err(stale_policy());
        }
        Ok(())
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
            scope: self.engine.enabled().then_some((self.key.address, self.key.network)),
            require_stun: false,
            tcp_evidence: Some(self.key.clone()),
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
        if flow.is_some() && !self.engine.key_live(&self.key) { return Err(stale_policy()); }
        if self.engine.cache.denied_tcp(&self.key) { return Err(stale_policy()); }
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
        let engine = &self.engine;
        let key = &self.key;
        let check_scope = || {
            if engine.key_live(key) {
                if let Some(flow) = flow { flow.check_live(super::PacketAction::Modify)?; }
                Ok(())
            } else {
                Err(stale_policy())
            }
        };
        check_scope()?;
        if !self.target.local_addr().is_ok_and(|local| self.key.network.matches_local(local)) {
            return Err(stale_policy());
        }
        if self.engine.cache.denied_tcp(&self.key) { return Err(stale_policy()); }
        if !self.engine.cache.current(&self.key, self.strategy, &self.lease) {
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
            let mut pending = transformed.as_slice();
            while !pending.is_empty() {
                check_scope()?;
                let count = self.target.write(pending).await.map_err(|_| ClientError::Io)?;
                if count == 0 { return Err(ClientError::Io); }
                pending = &pending[count..];
            }
            tcp::read_server_hello(&mut self.target).await
        })
        .await;
        check_scope()?;
        let response = match response {
            Ok(Ok(tcp::ServerFlight::Hello(response))) => response,
            Ok(Ok(tcp::ServerFlight::Alert(alert))) => {
                self.engine.cache.failed(&self.key, self.strategy, &self.lease);
                crate::traffic::dpi_first_failure();
                crate::traffic::dpi_tls_alert();
                // Forward the genuine alert; do not retry or manufacture a
                // replacement response on a different connection.
                check_scope()?;
                timeout(FIRST_FLIGHT, tcp::write_checked(&mut client, &alert, &check_scope))
                    .await
                    .map_err(|_| ClientError::Timeout)??;
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
        check_scope()?;
        timeout(FIRST_FLIGHT, tcp::write_checked(&mut client, &response, &check_scope))
            .await.map_err(|_| ClientError::Timeout)??;
        let hello_elapsed = started.elapsed();
        if flow.is_some() { self.engine.cache.touch_tcp(&self.key, &self.lease); }
        crate::traffic::dpi_first_response();
        let (result, exchanged, peer_failure) = super::client_state::relay_direct_after_first(
            client,
            self.target,
            prefix.len(),
            response.len(),
            flow,
            &check_scope,
        )
        .await;
        // A ServerHello alone is insufficient evidence of usable application
        // traffic. Do not penalize a clean early application disconnect.
        if peer_failure && check_scope().is_ok() {
            self.engine.cache.failed(&self.key, self.strategy, &self.lease);
            crate::traffic::dpi_post_hello_failure();
        } else if exchanged && result.is_ok() && check_scope().is_ok() {
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
            scope: None,
            require_stun: false,
            tcp_evidence: None,
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
        let _ = engine.cache.fixture_udp(&key, UdpProbe::Quic(Version::V1), true);
        assert_eq!(
            engine.cached_udp(&key, UdpProbe::Quic(Version::V1)),
            Some(true)
        );
        assert_eq!(engine.cached_udp(&key, UdpProbe::Quic(Version::V2)), None);
        assert_eq!(engine.cached_udp(&key, UdpProbe::Stun), None);
        let _ = engine.cache.fixture_udp(&key, UdpProbe::Quic(Version::V2), false);
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
    async fn product_quic_requires_active_probe_not_reachability_cache() {
        let engine = Arc::new(Engine::default());
        let policy = [1; 32];
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture(policy)));
        engine.set_enabled(true);
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        for version in [crate::quic_core::wire::Version::V1, crate::quic_core::wire::Version::V2] {
            // The product path must exit before any local target network I/O
            // while native active first-flight generation is unavailable.
            assert!(matches!(engine.open_proxy_udp_checked(
                "example.org", 443, &[public], policy, UdpStrategy::Quic(version)
            ).await, Ok(None)));
        }
        let private: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(matches!(engine.open_proxy_udp_checked("localhost", 443, &[private], policy,
            UdpStrategy::Quic(crate::quic_core::wire::Version::V1)).await,
            Err(ClientError::Open(crate::protocol::ErrorCode::PolicyDenied))));
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
        let mut verified = VerifiedUdp {
            socket,
            lease: Lease::new(),
            _admission: admission,
            strategy: UdpStrategy::StunBinding(udp::BindingStrategy::Fingerprint),
            engine: engine.clone(),
            key: key.clone(),
        };
        assert!(!verified.admissible().unwrap());
        verified.lease = engine.remember_udp(key.clone(), UdpProbe::Stun, true).unwrap();
        assert!(verified.admissible().unwrap());
        engine.set_stun_enabled(false);
        assert!(!verified.admissible().unwrap());
        engine.set_stun_enabled(true);
        let old = verified.lease.clone();
        verified.lease = engine.remember_udp(key.clone(), UdpProbe::Stun, true).unwrap();
        engine.fail_udp(&key, UdpProbe::Stun, &old);
        assert!(verified.admissible().unwrap(), "late failure must not invalidate fresh UDP evidence");
        verified.failed();
        assert_eq!(engine.cached_udp(&key, UdpProbe::Stun), Some(false));
        assert!(!verified.admissible().unwrap());
        let _ = engine.remember_udp(key.clone(), UdpProbe::Quic(Version::V2), true);
        assert_eq!(engine.cached_udp(&key, UdpProbe::Quic(Version::V1)), None);
        for i in 0..129 {
            let mut other = key.clone();
            other.name = format!("host{i}.example.org");
            let _ = engine.remember_udp(other, UdpProbe::Stun, true);
        }
        assert_eq!(engine.cache.fixture_size(), 128);
        assert_eq!(engine.cached_udp(&key, UdpProbe::Stun), None);
        engine.cache.fixture_expire();
        assert_eq!(engine.cached_udp(&key, UdpProbe::Stun), None);
        assert_eq!(engine.cache.fixture_size(), 0);
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
        assert!(matches!(engine.open_checked("localhost", 443, &["127.0.0.1".parse().unwrap()], policy).await,
            Err(ClientError::Open(crate::protocol::ErrorCode::PolicyDenied))));
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        let v2 = UdpStrategy::Quic(crate::quic_core::wire::Version::V2);
        assert!(matches!(engine.open_udp_checked("example.org", 443, &[local], policy, v2).await,
            Err(ClientError::Open(crate::protocol::ErrorCode::PolicyDenied))));
        assert!(matches!(engine.open_udp_checked("example.org", 80, &[public], policy, v2).await, Ok(None)));
        assert!(!UdpStrategy::StunBinding(udp::BindingStrategy::Plain).accepted_for_proxy());
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
        assert!(matches!(engine.open_udp_checked("example.org", 443, &[public], policy, v2).await,
            Err(ClientError::Open(crate::protocol::ErrorCode::PolicyDenied))));
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
    /// The peer is an independent Python/OpenSSL TLS implementation with a
    /// deliberately narrow synthetic record filter. This exercises the
    /// actual Rust probe AND actual proxy relay, not the transform helper
    /// in isolation. No real network or public-IP exception is required.
    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    #[tokio::test]
    async fn independent_openssl_record_filter_and_application_exchange() {
        use std::{io::{BufRead, BufReader}, process::{Child, Command, Stdio}};
        use tokio::io::AsyncReadExt;
        const PING: &[u8] = b"theia-dpi-ping";
        const PONG: &[u8] = b"theia-dpi-pong";
        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        struct FixtureDir(std::path::PathBuf);
        impl Drop for FixtureDir {
            fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
        }
        use ring::rand::{SecureRandom, SystemRandom};
        let mut random = [0; 16];
        SystemRandom::new().fill(&mut random).unwrap();
        let unique: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let directory = FixtureDir(std::env::temp_dir().join(format!("theia-dpi-{unique}")));
        std::fs::create_dir(&directory.0).unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = directory.0.join("cert.pem");
        let key_path = directory.0.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let config = tls::tls_config(roots).unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/anti-dpi-tls-peer.py");
        let python = std::env::var_os("THEIA_DPI_PYTHON").unwrap_or_else(||
            if cfg!(windows) { "python".into() } else { "python3".into() });
        let mut peer = ChildGuard(Command::new(python).arg(script)
            .arg("--cert").arg(&cert_path).arg("--key").arg(&key_path)
            .stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap());
        let stdout = peer.0.stdout.take().unwrap();
        let (events, incoming) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if events.send(line).is_err() { break; }
            }
        });
        let ready = incoming.recv_timeout(Duration::from_secs(10)).unwrap();
        let port: u16 = ready.strip_prefix("READY ").unwrap().parse().unwrap();
        let address: SocketAddr = ([127, 0, 0, 1], port).into();

        async fn application(
            socket: TcpStream, config: Arc<rustls::ClientConfig>,
        ) -> std::io::Result<()> {
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut tls = tokio_rustls::TlsConnector::from(config).connect(name, socket).await?;
            tls.write_all(PING).await?;
            let mut reply = [0; PONG.len()];
            tls.read_exact(&mut reply).await?;
            assert_eq!(reply.as_slice(), PONG);
            tls.shutdown().await?;
            let mut tail = Vec::new();
            tls.read_to_end(&mut tail).await?;
            assert!(tail.is_empty());
            Ok(())
        }

        // Ordinary TLS reaches the peer without the filter, and the same
        // ordinary TLS fails once the synthetic filter is enabled.
        timeout(Duration::from_secs(10), application(TcpStream::connect(address).await.unwrap(), config.clone()))
            .await.unwrap().unwrap();
        let blocked = timeout(Duration::from_secs(10), application(TcpStream::connect(address).await.unwrap(), config.clone()))
            .await.unwrap();
        assert!(blocked.is_err(), "unmodified control must fail");

        for strategy in Strategy::ALL {
            let verdict = tls::probe_guarded("localhost", address, None, strategy, config.clone(),
                ATTEMPT, || true).await;
            assert_eq!(verdict, tls::ProbeVerdict::Verified);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (app, accepted) = tokio::join!(TcpStream::connect(listener.local_addr().unwrap()), listener.accept());
            let app = app.unwrap();
            let local = accepted.unwrap().0;
            let target = TcpStream::connect(address).await.unwrap();
            let mut tunnel = Tunnel::fixture(target, "localhost");
            tunnel.strategy = strategy;
            tunnel.key.network = (0..16).find_map(|_| network_scope::observe(address)).unwrap();
            tunnel.engine.set_enabled(true);
            tunnel.lease = tunnel.engine.cache.remember(&tunnel.key, Verdict::Verified(strategy)).unwrap();
            let flow = super::super::flow::FlowTable::shared().begin(
                tunnel.engine.policy.clone(), super::super::flow::Protocol::Tcp,
                crate::protocol::Address::Dns("localhost".into()), port, tunnel.key.policy,
                super::super::PacketAction::Modify,
            ).unwrap();
            let (relay, application_result) = timeout(Duration::from_secs(10), async {
                tokio::join!(tunnel.relay_guarded(local, Some(&flow)), application(app, config.clone()))
            }).await.unwrap();
            assert!(matches!(relay, Ok(RelayOutcome::Finished)));
            application_result.unwrap();
            assert!(flow.committed(super::super::PacketAction::Modify));
        }

        for expected in [
            "PASS baseline records=1 handshake=1 exchange=1",
            "PASS blocked records=1 handshake=0 exchange=0",
            "PASS header-probe records=2 handshake=1 exchange=0",
            "PASS header records=2 handshake=1 exchange=1",
            "PASS middle-probe records=2 handshake=1 exchange=0",
            "PASS middle records=2 handshake=1 exchange=1",
            "PASS balanced-probe records=4 handshake=1 exchange=0",
            "PASS balanced records=4 handshake=1 exchange=1",
        ] {
            let actual = incoming.recv_timeout(Duration::from_secs(10)).unwrap();
            assert_eq!(actual, expected);
            println!("{actual}");
        }
        let version = incoming.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(version.starts_with("OPENSSL "));
        println!("{version}");
        assert!(peer.0.wait().unwrap().success());
        reader.join().unwrap();
    }

}
