//! Local loopback-only HTTP and SOCKS5 listeners for H2, H3 or conservative QUIC-first auto mode.
//! Local direct destinations use bounded DNS only after explicit routing authorization.

mod auto;
mod egress;
pub(crate) mod profile_diagnostics;
mod ingress;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod runtime;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) use runtime::ClientRuntime;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod native;
#[cfg(windows)]
mod system_proxy;
#[cfg(target_os = "linux")]
pub use native::LabStunPermit;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use native::NativeIngress;
#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
use native::NativeOwner;
#[cfg(windows)]
pub(crate) use system_proxy::SystemProxySession;

use crate::{
    client::{error_kind, ClientError, H2Client, Tunnel},
    config::{self, Config, Profile, Transport, XhttpMode},
    diagnostics::{self, Value},
    h3_client::{H3Client, H3Tunnel},
    protocol::{Address, ErrorCode},
    routing::{
        client_state::{self, Cache},
        snapshot::Snapshot,
        Action,
    },
    security_profile::SecurityMode,
};
use rustls::RootCertStore;
#[cfg(test)]
use std::net::UdpSocket;
use std::{
    io::BufReader,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, Semaphore},
    task::JoinSet,
    time::timeout,
};

const LOCAL_LIMIT: usize = 64;
const NEGOTIATE_TIMEOUT: Duration = Duration::from_secs(10);
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);
const CA_LIMIT: usize = 1024 * 1024;

fn load_file(
    reference: &str,
    limit: usize,
    secret: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ClientError> {
    let path = reference
        .strip_prefix("file:")
        .ok_or(ClientError::Configuration)?;
    crate::bounded_input::read(Path::new(path), limit as u64, true, secret)
        .map_err(|_| ClientError::Configuration)
}

fn read_token(profile: &Profile) -> Result<zeroize::Zeroizing<String>, ClientError> {
    let token = if let Some(name) = profile.auth_token.strip_prefix("env:") {
        zeroize::Zeroizing::new(std::env::var(name).map_err(|_| ClientError::Configuration)?)
    } else {
        let bytes = load_file(&profile.auth_token, 43, true)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| ClientError::Configuration)?;
        zeroize::Zeroizing::new(text.to_owned())
    };
    if token.len() != 43 {
        return Err(ClientError::Configuration);
    }
    Ok(token)
}

#[cfg(test)]
async fn load_client(profile: &Profile) -> Result<ProxyClient, ClientError> {
    load_client_with_budget(profile, crate::connection_pool::profile_budget(), None).await
}

async fn load_client_with_budget(
    profile: &Profile,
    budget: Arc<Semaphore>,
    config_path: Option<&Path>,
) -> Result<ProxyClient, ClientError> {
    match profile.security_mode {
        SecurityMode::SmartReality
            if profile.reality_profile.is_some() && profile.tls_ca.is_none() =>
        {
            let identity = profile
                .reality_profile
                .as_ref()
                .ok_or(ClientError::Configuration)?
                .identity_sha256;
            let checkpoint = client_state::checkpoint_path(config_path, profile, identity)?;
            return RealityClient::prepare_with_budget(profile, budget, checkpoint)
                .await
                .map(Arc::new)
                .map(ProxyClient::Reality);
        }
        SecurityMode::Plain if profile.reality_profile.is_none() => {}
        _ => return Err(ClientError::Configuration),
    }
    let prefix = profile
        .path_prefix
        .as_deref()
        .ok_or(ClientError::Configuration)?;
    let reference = profile
        .tls_ca
        .as_deref()
        .ok_or(ClientError::Configuration)?;
    let (trust, identity) = if let Some(anchor) = crate::own_tls::Anchor::parse(reference) {
        (crate::own_tls::Trust::Pinned(anchor), anchor.bytes())
    } else {
        let cert = load_file(reference, CA_LIMIT, false)?;
        use sha2::{Digest, Sha256};
        let identity = Sha256::digest(cert.as_slice()).into();
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut BufReader::new(cert.as_slice())) {
            roots
                .add(cert.map_err(|_| ClientError::Configuration)?)
                .map_err(|_| ClientError::Configuration)?;
        }
        (crate::own_tls::Trust::Roots(roots), identity)
    };
    let checkpoint = client_state::checkpoint_path(config_path, profile, identity)?;
    let token = read_token(profile)?;
    if !trust.usable() {
        return Err(ClientError::Configuration);
    }
    let mode = profile.effective_xhttp_mode();
    let stream_up = mode == XhttpMode::StreamUp;
    let auto_xhttp = mode == XhttpMode::Auto;
    let ttl = Duration::from_secs(u64::from(profile.quic_negative_cache_ttl_s));
    match profile.transport {
        Transport::H2 => {
            let endpoint = resolve_server(profile).await?.to_string();
            let client = H2Client::new_with_trust(&endpoint, &profile.server_name, &token, &trust)?
                .with_path_prefix(prefix)?
                .with_own_tls_policy()?
                .with_stream_up(stream_up)?;
            let client = if auto_xhttp {
                client.with_auto_stream_up(ttl)?
            } else {
                client
            };
            Ok(ProxyClient::direct_with_checkpoint(
                Carrier::from_options(
                    Some(Arc::new(client.with_connection_pool())),
                    None,
                    ttl,
                    budget,
                )?,
                checkpoint,
            ))
        }
        Transport::H3 | Transport::Auto => {
            // Resolve the configured server only, never the requested target.
            let remote = resolve_server(profile).await?;
            let h3 = H3Client::new_with_trust(remote, &profile.server_name, &token, trust.clone())?
                .with_path_prefix(prefix)?
                .with_own_tls_policy()?
                .with_stream_up(stream_up)?
                .with_connect_timeout(Duration::from_millis(u64::from(
                    profile.quic_connect_timeout_ms,
                )))?;
            let h3 = h3.with_connection_pool();
            let h3 = Arc::new(if auto_xhttp {
                h3.with_auto_stream_up(ttl)?
            } else {
                h3
            });
            if profile.transport == Transport::H3 {
                return Ok(ProxyClient::direct_with_checkpoint(
                    Carrier::from_options(None, Some(h3), ttl, budget)?,
                    checkpoint,
                ));
            }
            // Both carriers use the same resolved endpoint. Do not resolve
            // the hostname again during fallback; retain the configured SNI,
            // trust anchors, certificate pin and authorization unchanged.
            let h2 = H2Client::new_with_trust(
                &remote.to_string(),
                &profile.server_name,
                &token,
                &trust,
            )?
            .with_path_prefix(prefix)?
            .with_own_tls_policy()?
            .with_stream_up(stream_up)?;
            let h2 = h2.with_connection_pool();
            let h2 = Arc::new(if auto_xhttp {
                h2.with_auto_stream_up(ttl)?
            } else {
                h2
            });
            Ok(ProxyClient::direct_with_checkpoint(
                Carrier::from_options(Some(h2), Some(h3), ttl, budget)?,
                checkpoint,
            ))
        }
    }
}

async fn resolve_server(profile: &Profile) -> Result<SocketAddr, ClientError> {
    // Bootstrap must not invoke the ordinary system resolver while the
    // native owner is preparing or controlling DNS. A literal pinned
    // carrier endpoint is mandatory until protected bootstrap exists.
    if crate::routing::carrier_socket::active() {
        return profile
            .server
            .parse::<SocketAddr>()
            .map_err(|_| ClientError::Configuration);
    }
    timeout(NEGOTIATE_TIMEOUT, tokio::net::lookup_host(&profile.server))
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(|_| ClientError::Io)?
        .next()
        .ok_or(ClientError::Io)
}

#[derive(Clone)]
enum ProxyClient {
    Direct(Arc<DirectClient>),
    Reality(Arc<RealityClient>),
}

/// A pinned endpoint and trust-store generation for the production proxy.
/// New logical tunnels re-read the persistent trust floor. A changed
/// descriptor creates new carrier pools and an independent fallback cache;
/// established tunnels retain their own transport leases.
#[derive(Clone)]
enum Carrier {
    H2(Arc<H2Client>),
    H3(Arc<H3Client>),
    Auto(Arc<AutoClient>),
}
struct DirectClient {
    carrier: Carrier,
    routing: Cache,
    last_open: Arc<std::sync::atomic::AtomicU8>,
}
impl DirectClient {
    fn fallback(&self) -> bool {
        match &self.carrier {
            Carrier::Auto(a) => a.negative.lock().ok().is_some_and(|c| {
                c.route.is_some()
                    && c.route == crate::network_scope::observe(a.h3.remote())
                    && c.expires.is_some_and(|t| t > Instant::now())
            }),
            _ => false,
        }
    }
    fn last_xhttp(&self) -> u8 {
        self.last_open.load(std::sync::atomic::Ordering::Relaxed) & 3
    }
    fn last_transport(&self) -> u8 {
        self.last_open.load(std::sync::atomic::Ordering::Relaxed) >> 2
    }
}
struct RealityGeneration {
    value: crate::descriptor::Verified,
    carrier: Carrier,
    credential_digest: [u8; 32],
    last_open: Arc<std::sync::atomic::AtomicU8>,
    last_refresh: std::sync::atomic::AtomicU8,
}
pub(crate) struct RealityClient {
    profile: Profile,
    remote: SocketAddr,
    budget: Arc<Semaphore>,
    current: tokio::sync::Mutex<Arc<RealityGeneration>>,
    routing: Cache,
    changed: Notify,
}
impl RealityClient {
    fn now() -> Result<u64, ClientError> {
        crate::reference_health::unix_now().map_err(|_| ClientError::Tls)
    }
    async fn prepare_with_budget(
        profile: &Profile,
        budget: Arc<Semaphore>,
        checkpoint: Option<std::path::PathBuf>,
    ) -> Result<Self, ClientError> {
        // No DNS/credential use before the enrollment and independent trust
        // anchor have been checked.
        let enrollment = crate::reality_config::pinned_client(profile)
            .map_err(|_| ClientError::Configuration)?;
        let value = enrollment
            .load(Self::now()?)
            .map_err(|_| ClientError::Tls)?;
        let remote = resolve_server(profile).await?;
        let first = Self::build(profile, remote, &enrollment, value, None, budget.clone())?;
        let routing = Cache::new(first.value.descriptor().scope.inbound.clone(), checkpoint);
        Ok(Self {
            profile: profile.clone(),
            remote,
            budget,
            current: tokio::sync::Mutex::new(Arc::new(first)),
            routing,
            changed: Notify::new(),
        })
    }
    fn build(
        profile: &Profile,
        remote: SocketAddr,
        enrollment: &crate::reality_bootstrap::Profile,
        value: crate::descriptor::Verified,
        expected_credential: Option<[u8; 32]>,
        budget: Arc<Semaphore>,
    ) -> Result<RealityGeneration, ClientError> {
        if value.descriptor().scope.endpoint != profile.server {
            return Err(ClientError::Configuration);
        }
        let secret = Arc::new(enrollment.admission().map_err(|_| ClientError::Tls)?);
        let token = read_token(profile)?;
        use sha2::{Digest, Sha256};
        let credential_digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if expected_credential.is_some_and(|expected| expected != credential_digest) {
            return Err(ClientError::Configuration);
        }
        let modes = value.effective_modes();
        let ttl = Duration::from_secs(u64::from(profile.quic_negative_cache_ttl_s));
        let timeout = Duration::from_millis(u64::from(profile.quic_connect_timeout_ms));
        let h2 = if modes.h2 {
            Some(Arc::new(
                H2Client::admitted_runtime(remote, &token, &value, secret.clone())?
                    .with_mode_cache_ttl(ttl)
                    .with_connection_pool(),
            ))
        } else {
            None
        };
        let h3 = if modes.h3 {
            Some(Arc::new(
                H3Client::admitted_runtime(remote, &token, &value, secret)?
                    .with_mode_cache_ttl(ttl)
                    .with_connect_timeout(timeout)?
                    .with_connection_pool(),
            ))
        } else {
            None
        };
        let carrier = Carrier::from_options(h2, h3, ttl, budget)?;
        Ok(RealityGeneration {
            value,
            carrier,
            credential_digest,
            last_open: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            last_refresh: std::sync::atomic::AtomicU8::new(0),
        })
    }
    async fn generation(&self) -> Result<Arc<RealityGeneration>, ClientError> {
        let mut slot = self.current.lock().await;
        let enrollment = crate::reality_config::pinned_client(&self.profile)
            .map_err(|_| ClientError::Configuration)?;
        let value = enrollment
            .load(Self::now()?)
            .map_err(|_| ClientError::Tls)?;
        use sha2::{Digest, Sha256};
        let credential_digest: [u8; 32] =
            Sha256::digest(read_token(&self.profile)?.as_bytes()).into();
        if credential_digest != slot.credential_digest {
            return Err(ClientError::Configuration);
        }
        let old = &slot.value;
        if old.descriptor().scope != value.descriptor().scope
            || value.descriptor().revision < old.descriptor().revision
        {
            return Err(ClientError::Tls);
        }
        if old.signer() == value.signer() {
            if old.compare(&value).map_err(|_| ClientError::Tls)?
                == crate::descriptor::Change::Unchanged
            {
                return Ok(slot.clone());
            }
        } else if value.descriptor().revision <= old.descriptor().revision {
            return Err(ClientError::Tls);
        }
        let next = Arc::new(Self::build(
            &self.profile,
            self.remote,
            &enrollment,
            value,
            Some(slot.credential_digest),
            self.budget.clone(),
        )?);
        *slot = next.clone();
        self.changed.notify_one();
        Ok(next)
    }
    #[cfg(test)]
    async fn open(&self, address: Address, port: u16) -> Result<RoutedTcp, ClientError> {
        self.open_for(address, port, true).await
    }

    async fn open_for(
        &self,
        address: Address,
        port: u16,
        allow_dpi: bool,
    ) -> Result<RoutedTcp, ClientError> {
        let generation = self.generation().await?;
        let mut result =
            routed_open(&generation.carrier, &self.routing, address, port, allow_dpi).await;
        if let Ok(tunnel) = &mut result {
            if let ProxyTunnel::Dpi(route) = &mut tunnel.tunnel {
                route.observed = Some(generation.last_open.clone());
            }
            if tunnel.open_code() != 0 {
                generation
                    .last_open
                    .store(tunnel.open_code(), std::sync::atomic::Ordering::Relaxed);
            }
        }
        result
    }

    pub(crate) async fn runtime_report(&self) -> String {
        use std::sync::atomic::Ordering;
        let generation = self.current.lock().await.clone();
        let value = &generation.value;
        let valid = Self::now().is_ok_and(|now| value.check_time(now).is_ok());
        let policy = match &generation.carrier {
            Carrier::H2(_) => "h2",
            Carrier::H3(_) => "h3",
            Carrier::Auto(_) => "auto",
        };
        let fallback = match &generation.carrier {
            Carrier::Auto(auto) => auto.negative.lock().ok().map(|cache| {
                cache.route.is_some()
                    && cache.route == crate::network_scope::observe(auto.h3.remote())
                    && cache.expires.is_some_and(|until| until > Instant::now())
            }),
            _ => None,
        };
        let observed = generation.last_open.load(Ordering::Relaxed);
        let transport = match observed >> 2 {
            2 => "H2",
            3 => "H3",
            _ => "пока нет подтверждённого соединения",
        };
        let refresh = match generation.last_refresh.load(Ordering::Relaxed) {
            1 => "успешно",
            2 => "отклонено/недоступно",
            _ => "ещё не выполнялось",
        };
        // Read the pinned durable state without refreshing or changing it.
        let profile = self.profile.clone();
        let trust = tokio::task::spawn_blocking(move || {
            crate::reality_config::pinned_client(&profile)
                .ok()
                .and_then(|p| p.load(Self::now().ok()?).ok())
        })
        .await
        .ok()
        .flatten();
        let trust_state = match trust {
            Some(v) if v.payload_sha256() == value.payload_sha256() => "совпадает",
            Some(_) => "изменилось, новые запросы перепроверят",
            None => "не подтверждено, новые запросы могут быть отклонены",
        };
        format!("Локальный прокси работает. Это не подтверждает связь с сервером.\nВерсия описания: {} · номер референса: {} · актуально: {}\nРежим передачи: {} · последнее подтверждённое соединение: {transport}; XHTTP: {}\nВременный переход с H3: {}\nОбновление описания сервера: {refresh}\nСохранённое доверие: {trust_state}",
            value.descriptor().revision,value.descriptor().active_reference, if valid { "да" } else { "нет" },
            if policy == "auto" { "автоматически" } else { policy }, xhttp_observation(observed & 3),
            fallback.map_or("не применяется",|v|if v{"активен: временная сетевая недоступность QUIC"}else{"не активен"}))
    }
    async fn refresh(&self, generation: &RealityGeneration) -> Result<(), ClientError> {
        let enrollment = crate::reality_config::pinned_client(&self.profile)
            .map_err(|_| ClientError::Configuration)?;
        let store = enrollment.store().map_err(|_| ClientError::Tls)?;
        let signed = generation.carrier.fetch_identity_document(false).await?;
        store
            .update_matching(&signed, &generation.value, Self::now()?)
            .map_err(|_| ClientError::Tls)?;
        let current = store.load(Self::now()?).map_err(|_| ClientError::Tls)?;
        if current.descriptor().next_identity.is_some() {
            // Read the successor only on the still-authenticated old
            // identity. Its key must match the signed announcement and
            // its operational parameters must match exactly.
            let successor = generation.carrier.fetch_identity_document(true).await?;
            let now = Self::now()?;
            let preview = enrollment
                .preview_promotion(&successor, now)
                .map_err(|_| ClientError::Tls)?;
            if preview.expected_revision != current.descriptor().revision
                || preview.current_identity_sha256
                    != crate::reality_bootstrap::fingerprint(current.signer())
            {
                return Err(ClientError::Tls);
            }
            // Prepare a carrier for the proposed signer before committing
            // the CAS. Verify actual successor TLS identity on a new
            // connection; possession is not inferred from a signed file.
            let (_, _, candidate) = store
                .preview_promotion_bound(&successor, now)
                .map_err(|_| ClientError::Tls)?;
            let next = Self::build(
                &self.profile,
                self.remote,
                &enrollment,
                candidate,
                Some(generation.credential_digest),
                self.budget.clone(),
            )?;
            let seen = next.carrier.fetch_identity_document(false).await?;
            if seen != successor {
                return Err(ClientError::Tls);
            }
            enrollment
                .promote(
                    &successor,
                    crate::reality_bootstrap::PromotionApproval {
                        expected_revision: preview.expected_revision,
                        snapshot_sha256: preview.snapshot_sha256,
                        document_sha256: preview.document_sha256,
                        next_identity_sha256: preview.next_identity_sha256,
                    },
                    Self::now()?,
                )
                .map_err(|_| ClientError::Tls)?;
        }
        Ok(())
    }
    async fn maintain(&self) -> Result<(), ClientError> {
        loop {
            let generation = match self.generation().await {
                Ok(value) => value,
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
            };
            let refresh = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    // CAS binds refresh to the generation used for the GET.
                    let ok = self.refresh(&generation).await.is_ok();
                    generation
                        .last_refresh
                        .store(if ok { 1 } else { 2 }, std::sync::atomic::Ordering::Relaxed);
                    match self.generation().await {
                        Ok(current) if Arc::ptr_eq(&current, &generation) => {}
                        _ => break,
                    }
                }
            };
            tokio::select! {
                _ = self.changed.notified() => {},
                _ = refresh => {},
                result = generation.carrier.maintain() => return result,
            }
        }
    }
}

/// Preserve the established route observation contract for existing callers.
pub(crate) fn route_source(remote: SocketAddr) -> Option<SocketAddr> {
    let mut local = crate::routing::carrier_socket::selected_source(remote).ok()?;
    if local.ip().is_unspecified() {
        return None;
    }
    local.set_port(0);
    Some(local)
}

#[cfg(target_os = "windows")]
pub(crate) use crate::routing::carrier_socket::windows_route_binding;

#[cfg(test)]
use crate::net::evidence::ScopedDecision as NegativeCache;
use auto::AutoClient;
#[cfg(test)]
use auto::AUTO_QUIC_ATTEMPTS;

enum ProxyTunnel {
    Direct(TcpStream),
    Dpi(Box<DpiRoute>),
    H2(Box<Tunnel>),
    H3(Box<H3Tunnel>),
}

struct RoutedTcp {
    tunnel: ProxyTunnel,
    flow: crate::routing::flow::FlowLease,
}
impl RoutedTcp {
    fn open_code(&self) -> u8 {
        self.tunnel.open_code()
    }
    async fn relay(self, socket: TcpStream) -> Result<(), ClientError> {
        tokio::select! {
            biased;
            result = self.flow.wait_revoked() => result,
            result = self.tunnel.relay_guarded(socket, Some(&self.flow)) => result,
        }
    }

    async fn relay_http(self, socket: TcpStream, request: Vec<u8>) -> Result<(), ClientError> {
        // A single absolute-form request owns this stream. No subsequent
        // request can reuse the selected destination or bypass policy.
        let local = HttpOnce {
            socket,
            request: request.into(),
        };
        let flow = Some(&self.flow);
        let relay = async {
            match self.tunnel {
                ProxyTunnel::Direct(target) => {
                    client_state::relay_http_direct_guarded(local, target, flow).await
                }
                ProxyTunnel::H2(tunnel) => tunnel.relay_guarded(local, flow).await,
                ProxyTunnel::H3(tunnel) => tunnel.relay_guarded(local, flow).await,
                // Plain HTTP is known not to be a TLS ClientHello before OPEN.
                ProxyTunnel::Dpi(_) => Err(ClientError::Protocol),
            }
        };
        tokio::select! {
            biased;
            result = self.flow.wait_revoked() => result,
            result = relay => result,
        }
    }
}

struct RoutedUdp {
    tunnel: crate::udp_relay::Tunnel,
    flow: crate::routing::flow::FlowLease,
}
impl RoutedUdp {
    fn record_transport(&self, observed: &std::sync::atomic::AtomicU8) {
        self.tunnel.record_transport(observed);
    }
}

struct DpiRoute {
    tunnel: crate::routing::dpi::Tunnel,
    observed: Option<Arc<std::sync::atomic::AtomicU8>>,
    carrier: Carrier,
    address: Address,
    port: u16,
}

impl Carrier {
    async fn warm_carrier(&self) -> Result<(), ClientError> {
        match self {
            Self::H2(client) => client.warm_carrier().await,
            Self::H3(client) => client.warm_carrier().await,
            Self::Auto(client) => {
                // Speculation never publishes negative evidence and cannot
                // authorize an H3->H2 transition. Follow a live prior decision.
                let scope = crate::network_scope::observe(client.h3.remote());
                let cached = client.negative.lock().ok().is_some_and(|cache| {
                    scope.is_some()
                        && cache.route == scope
                        && cache.expires.is_some_and(|t| t > Instant::now())
                });
                if cached {
                    client.h2.warm_carrier().await
                } else {
                    client.h3.warm_carrier().await
                }
            }
        }
    }

    async fn warm_during<T>(&self, work: impl std::future::Future<Output = T>) -> T {
        tokio::pin!(work);
        tokio::select! {
            biased;
            result = &mut work => result,
            _ = self.warm_carrier() => work.await,
        }
    }

    async fn refresh_recent_tcp(&self, cache: &Cache, snapshot: &Snapshot) {
        let Some(target) = cache.dpi.due_tcp_refresh() else {
            return;
        };
        if target.digest() != snapshot.digest() {
            return;
        }
        let name = target.name();
        let policy = snapshot.policy();
        let address = target.address();
        let digest = target.digest();
        let Ok(pin) = cache.policy.pin(digest) else {
            return;
        };
        // Refresh never trusts old DNS pins. Bound control-plane delay,
        // refuse any mixed rules or non-public IPs, and keep the exact IP.
        let Ok(Ok(ips)) = timeout(Duration::from_secs(2), self.resolve_routing(name, digest)).await
        else {
            cache.dpi.invalidate_refresh(target);
            return;
        };
        if pin.check().is_err()
            || ips.is_empty()
            || ips.len() > 64
            || !ips.contains(&address.ip())
            || !ips.iter().all(|ip| {
                crate::server::allowed_destination(*ip, false)
                    && policy.classify(
                        crate::routing::Evidence::Known(name),
                        crate::routing::Evidence::Known(*ip),
                    ) == Ok(crate::routing::Classification::Matched(Action::DirectDpi))
            })
        {
            cache.dpi.invalidate_refresh(target);
            return;
        }
        cache.dpi.refresh_tcp(target).await;
    }

    fn own_routing_scope(&self) -> Option<&str> {
        match self {
            Self::H2(c) => c.own_routing_scope(),
            Self::H3(c) => c.own_routing_scope(),
            Self::Auto(c) => c.h2.own_routing_scope(),
        }
    }
    async fn fetch_routing(&self, known: Option<[u8; 32]>) -> Result<Vec<u8>, ClientError> {
        match self {
            Self::H2(c) => Box::pin(c.fetch_routing(known)).await,
            Self::H3(c) => Box::pin(c.fetch_routing(known)).await,
            Self::Auto(c) => Box::pin(c.fetch_routing(known)).await,
        }
    }
    async fn resolve_routing(
        &self,
        name: &str,
        digest: [u8; 32],
    ) -> Result<Vec<IpAddr>, ClientError> {
        match self {
            Self::H2(c) => c.resolve_routing(name, digest).await,
            Self::H3(c) => c.resolve_routing(name, digest).await,
            Self::Auto(c) => c.resolve_routing(name, digest).await,
        }
    }
    #[cfg(any(
        target_os = "linux",
        all(target_os = "windows", target_arch = "x86_64")
    ))]
    async fn resolve_native_dns(
        &self,
        name: &str,
        digest: [u8; 32],
    ) -> Result<Vec<IpAddr>, ClientError> {
        match self {
            Self::H2(c) => c.resolve_native_dns(name, digest).await,
            Self::H3(c) => c.resolve_native_dns(name, digest).await,
            Self::Auto(c) => c.resolve_native_dns(name, digest).await,
        }
    }
    fn profile_budget(&self) -> Arc<Semaphore> {
        match self {
            Self::H2(client) => client.profile_budget(),
            Self::H3(client) => client.profile_budget(),
            Self::Auto(client) => client.h2.profile_budget(),
        }
    }

    fn from_options(
        mut h2: Option<Arc<H2Client>>,
        mut h3: Option<Arc<H3Client>>,
        ttl: Duration,
        budget: Arc<Semaphore>,
    ) -> Result<Self, ClientError> {
        if let Some(client) = h2.as_mut() {
            Arc::get_mut(client)
                .ok_or(ClientError::Configuration)?
                .set_profile_budget(budget.clone());
        }
        if let Some(client) = h3.as_mut() {
            Arc::get_mut(client)
                .ok_or(ClientError::Configuration)?
                .set_profile_budget(budget);
        }
        match (h2, h3) {
            (Some(h2), Some(h3)) => Ok(Self::Auto(Arc::new(AutoClient::new(h2, h3, ttl)))),
            (Some(h2), None) => Ok(Self::H2(h2)),
            (None, Some(h3)) => Ok(Self::H3(h3)),
            _ => Err(ClientError::Configuration),
        }
    }

    async fn open_udp(
        &self,
        address: Address,
        port: u16,
    ) -> Result<crate::udp_relay::Tunnel, ClientError> {
        match self {
            Self::H2(c) => c
                .open_udp(address, port)
                .await
                .map(Box::new)
                .map(crate::udp_relay::Tunnel::H2),
            Self::H3(c) => c
                .open_udp(address, port)
                .await
                .map(Box::new)
                .map(crate::udp_relay::Tunnel::H3),
            Self::Auto(c) => c.open_udp(address, port).await,
        }
    }

    async fn open(&self, address: Address, port: u16) -> Result<ProxyTunnel, ClientError> {
        match self {
            Self::H2(client) => client
                .open(address, port)
                .await
                .map(Box::new)
                .map(ProxyTunnel::H2),
            Self::H3(client) => client
                .open(address, port)
                .await
                .map(Box::new)
                .map(ProxyTunnel::H3),
            Self::Auto(client) => client.open(address, port).await,
        }
    }

    async fn fetch_identity_document(&self, successor: bool) -> Result<String, ClientError> {
        match self {
            Self::H2(client) => client.fetch_identity_document(successor).await,
            Self::H3(client) => client.fetch_identity_document(successor).await,
            Self::Auto(client) => client.fetch_identity_document(successor).await,
        }
    }

    async fn maintain(&self) -> Result<(), ClientError> {
        match self {
            Self::Auto(client) => client.maintain().await,
            _ => std::future::pending().await,
        }
    }
}

use egress::{routed_open, routed_udp};

impl ProxyClient {
    fn direct(carrier: Carrier) -> Self {
        Self::direct_with_checkpoint(carrier, None)
    }
    fn direct_with_checkpoint(carrier: Carrier, checkpoint: Option<std::path::PathBuf>) -> Self {
        let routing = Cache::new(
            carrier.own_routing_scope().unwrap_or("").to_owned(),
            checkpoint,
        );
        Self::Direct(Arc::new(DirectClient {
            carrier,
            routing,
            last_open: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        }))
    }

    async fn runtime_report(&self) -> String {
        let report = match self {
            Self::Reality(r) => r.runtime_report().await,
            Self::Direct(d) => {
                let policy = match &d.carrier {
                    Carrier::H2(_) => "H2",
                    Carrier::H3(_) => "H3",
                    Carrier::Auto(_) => "auto",
                };
                let opened = match d.last_transport() {
                    2 => "H2",
                    3 => "H3",
                    _ => "пока нет подтверждённого соединения",
                };
                format!("Локальный прокси работает. Это не подтверждает связь с сервером.\nРежим передачи: {} · последнее подтверждённое соединение: {opened}; XHTTP: {}\nВременный переход с H3: {}", if policy == "auto" { "автоматически" } else { policy }, xhttp_observation(d.last_xhttp()), if d.fallback() { "активен: временная сетевая недоступность QUIC" } else { "не активен" })
            }
        };
        format!(
            "{report}\nСистемный перехват: не активирован (backend не готов)\n{}\n{}\nЛокальный Anti-DPI: {}\nUDP Modify: {}; непринятые стратегии используют VPS\n{}",
            crate::routing::flow::summary(self.routing_cache().flows.counts()),
            self.routing_cache().report(),
            if self.routing_cache().dpi.enabled() {
                "разрешён (экспериментальный TCP/TLS)"
            } else {
                "выключен; резерв VPS"
            },
            crate::routing::dpi::UdpStrategy::capability_summary(),
            crate::traffic::routing_summary()
        )
    }

    fn routing_cache(&self) -> &Cache {
        match self {
            Self::Direct(c) => &c.routing,
            Self::Reality(c) => &c.routing,
        }
    }
    async fn routing_policy(&self) -> Result<Arc<Snapshot>, ClientError> {
        match self {
            Self::Direct(c) => c.routing.get(|known| c.carrier.fetch_routing(known)).await,
            Self::Reality(c) => {
                let generation = c.generation().await?;
                c.routing
                    .get(|known| generation.carrier.fetch_routing(known))
                    .await
            }
        }
    }

    async fn refresh_routing_policy(&self) -> Result<Arc<Snapshot>, ClientError> {
        match self {
            Self::Direct(c) => {
                c.routing
                    .refresh(|known| c.carrier.fetch_routing(known))
                    .await
            }
            Self::Reality(c) => {
                let generation = c.generation().await?;
                c.routing
                    .refresh(|known| generation.carrier.fetch_routing(known))
                    .await
            }
        }
    }

    async fn open_udp(
        &self,
        address: Address,
        port: u16,
        candidate: &crate::routing::dpi::udp::Candidate,
        first: &[u8],
    ) -> Result<RoutedUdp, ClientError> {
        match self {
            Self::Direct(c) => {
                let tunnel = routed_udp(
                    &c.carrier,
                    &c.routing,
                    address,
                    port,
                    candidate,
                    first,
                    &c.last_open,
                )
                .await?;
                tunnel.record_transport(&c.last_open);
                Ok(tunnel)
            }
            Self::Reality(c) => {
                let generation = c.generation().await?;
                let tunnel = routed_udp(
                    &generation.carrier,
                    &c.routing,
                    address,
                    port,
                    candidate,
                    first,
                    &generation.last_open,
                )
                .await?;
                tunnel.record_transport(&generation.last_open);
                Ok(tunnel)
            }
        }
    }

    fn profile_budget(&self) -> Arc<Semaphore> {
        match self {
            Self::Direct(client) => client.carrier.profile_budget(),
            Self::Reality(client) => client.budget.clone(),
        }
    }

    async fn open(&self, address: Address, port: u16) -> Result<RoutedTcp, ClientError> {
        self.open_for(address, port, true).await
    }

    async fn open_for(
        &self,
        address: Address,
        port: u16,
        allow_dpi: bool,
    ) -> Result<RoutedTcp, ClientError> {
        match self {
            Self::Direct(client) => {
                let mut tunnel =
                    routed_open(&client.carrier, &client.routing, address, port, allow_dpi).await?;
                if let ProxyTunnel::Dpi(route) = &mut tunnel.tunnel {
                    route.observed = Some(client.last_open.clone());
                }
                if tunnel.open_code() != 0 {
                    client
                        .last_open
                        .store(tunnel.open_code(), std::sync::atomic::Ordering::Relaxed);
                }
                Ok(tunnel)
            }
            Self::Reality(client) => client.open_for(address, port, allow_dpi).await,
        }
    }
    async fn maintain(&self) -> Result<(), ClientError> {
        let carrier = async {
            match self {
                Self::Direct(client) => client.carrier.maintain().await,
                Self::Reality(client) => client.maintain().await,
            }
        };
        let routing = async {
            loop {
                if let Ok(snapshot) = self.refresh_routing_policy().await {
                    // No speculative native capture traffic. Proxy runtime
                    // owns this future; generation change cancels it.
                    if !crate::routing::carrier_socket::active() {
                        match self {
                            Self::Direct(client) => {
                                client
                                    .carrier
                                    .refresh_recent_tcp(&client.routing, &snapshot)
                                    .await
                            }
                            Self::Reality(client) => {
                                if let Ok(generation) = client.generation().await {
                                    generation
                                        .carrier
                                        .refresh_recent_tcp(&client.routing, &snapshot)
                                        .await;
                                }
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        };
        tokio::select! { result = carrier => result, result = routing => result }
    }
}

pub(crate) fn xhttp_observation(code: u8) -> &'static str {
    match code {
        1 => "stream-one",
        2 => "stream-up",
        _ => "не подтверждён",
    }
}

impl ProxyTunnel {
    fn open_code(&self) -> u8 {
        let (transport, up) = match self {
            Self::Direct(_) | Self::Dpi(_) => return 0,
            Self::H2(t) => (2, t.opened_stream_up()),
            Self::H3(t) => (3, t.opened_stream_up()),
        };
        (transport << 2) | if up { 2 } else { 1 }
    }

    #[cfg(test)]
    async fn relay(self, socket: TcpStream) -> Result<(), ClientError> {
        self.relay_guarded(socket, None).await
    }

    async fn relay_guarded(
        self,
        socket: TcpStream,
        flow: Option<&crate::routing::flow::FlowLease>,
    ) -> Result<(), ClientError> {
        match self {
            Self::Direct(target) => client_state::relay_direct_guarded(socket, target, flow).await,
            Self::Dpi(route) => {
                let DpiRoute {
                    tunnel,
                    observed,
                    carrier,
                    address,
                    port,
                } = *route;
                let authorization = tunnel.fallback_policy();
                match tunnel.relay_guarded(socket, flow).await? {
                    crate::routing::dpi::RelayOutcome::Finished => Ok(()),
                    crate::routing::dpi::RelayOutcome::Fallback { client, prefix } => {
                        // The origin received no application bytes. The carrier
                        // repeats server admission/ACL for the original target.
                        authorization.check()?;
                        if let Some(flow) = flow {
                            flow.check_pending()?;
                        }
                        let tunnel = carrier.open(address, port).await?;
                        authorization.check()?;
                        if let Some(flow) = flow {
                            flow.check_pending()?;
                        }
                        if let Some(observed) = observed {
                            observed
                                .store(tunnel.open_code(), std::sync::atomic::Ordering::Relaxed);
                        }
                        let local = crate::reality_tcp::Prefixed::new(client, prefix.into());
                        crate::traffic::dpi_fallback_open();
                        match tunnel {
                            Self::H2(tunnel) => tunnel.relay_guarded(local, flow).await,
                            Self::H3(tunnel) => tunnel.relay_guarded(local, flow).await,
                            _ => Err(ClientError::Protocol),
                        }
                    }
                }
            }
            Self::H2(tunnel) => tunnel.relay_guarded(socket, flow).await,
            Self::H3(tunnel) => tunnel.relay_guarded(socket, flow).await,
        }
    }
}

pub async fn run_file(config_path: &Path) -> Result<(), ClientError> {
    Box::pin(run_file_inner(config_path)).await
}

/// Windows-only, explicitly confirmed user WinINet proxy operation. The
/// settings are touched ONLY after strict client/TLS preflight and BOTH local
/// loopback TCP listeners are bound, never on plain client run or server run.
#[cfg(windows)]
pub async fn run_file_with_system_proxy(config_path: &Path) -> Result<(), ClientError> {
    use sha2::{Digest, Sha256};
    let raw = zeroize::Zeroizing::new(
        config::editor_bytes(config_path).map_err(|_| ClientError::Configuration)?,
    );
    let digest = Sha256::digest(raw.as_slice()).into();
    let mut session = SystemProxySession::connect(config_path, digest, None).await?;
    tokio::select! {
        result = session.ended() => result,
        signal = tokio::signal::ctrl_c() => {
            let result = session.disconnect().await;
            signal.map_err(|_| ClientError::Io)?;
            result
        }
    }
}

async fn run_file_inner(config_path: &Path) -> Result<(), ClientError> {
    crate::diag!(Info, "client.proxy", "config_read_begin");
    let raw = zeroize::Zeroizing::new(
        config::editor_bytes(config_path).map_err(|_| ClientError::Configuration)?,
    );
    let Config::Client(document) =
        config::parse(std::str::from_utf8(&raw).map_err(|_| ClientError::Configuration)?)
            .map_err(|_| ClientError::Configuration)?
    else {
        return Err(ClientError::Configuration);
    };
    let (http, socks, client) = Box::pin(prepare_proxy(&document, config_path)).await?;
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let managed = {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(raw.as_slice()).into();
        saved_client_bytes(config_path, digest)?;
        ClientRuntime::new(
            std::path::absolute(config_path).map_err(|_| ClientError::Configuration)?,
            document.clone(),
            digest,
            client.clone(),
        )
    };
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let control = crate::management::client_server(managed.clone())
        .map_err(|_| ClientError::Configuration)?;
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    let serving = async move {
        let management = async move {
            match control {
                Some(server) => server.serve().await.map_err(|_| ClientError::Io),
                None => std::future::pending::<Result<(), ClientError>>().await,
            }
        };
        tokio::select! {
            result=serve_managed_proxy(http,socks,managed)=>result,
            result=management=>result,
        }
    };
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let serving = serve_proxy(http, socks, client);
    serving.await
}

#[cfg(windows)]
async fn bind_proxy_listener(address: &str) -> Result<TcpListener, ClientError> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::{
        Foundation::{SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT},
        Networking::WinSock::{setsockopt, SOL_SOCKET, SO_EXCLUSIVEADDRUSE},
    };
    let address: SocketAddr = address.parse().map_err(|_| ClientError::Configuration)?;
    if !matches!(
        address.ip(),
        IpAddr::V4(Ipv4Addr::LOCALHOST) | IpAddr::V6(Ipv6Addr::LOCALHOST)
    ) {
        return Err(ClientError::Configuration);
    }
    let socket = crate::routing::carrier_socket::new_tcp(address).map_err(|_| ClientError::Io)?;
    let raw = socket.as_raw_socket() as usize;
    let enabled: i32 = 1;
    // SAFETY: socket is uniquely owned; the option is a live i32 for
    // synchronous Winsock, and the handle is valid for this lifetime.
    if unsafe {
        setsockopt(
            raw,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            4,
        )
    } != 0
        || unsafe { SetHandleInformation(raw as HANDLE, HANDLE_FLAG_INHERIT, 0) } == 0
    {
        return Err(ClientError::Io);
    }
    crate::routing::carrier_socket::listen_tcp(socket, address, 128).map_err(|_| ClientError::Io)
}

#[cfg(not(windows))]
async fn bind_proxy_listener(address: &str) -> Result<TcpListener, ClientError> {
    TcpListener::bind(address)
        .await
        .map_err(|_| ClientError::Io)
}

#[cfg(all(test, windows))]
#[tokio::test]
async fn product_proxy_listener_is_exclusive_and_loopback_only() {
    let owned = bind_proxy_listener("127.0.0.1:0").await.unwrap();
    let address = owned.local_addr().unwrap();
    let foreign = tokio::net::TcpSocket::new_v4().unwrap();
    foreign.set_reuseaddr(true).unwrap();
    assert!(foreign.bind(address).is_err());
    assert!(bind_proxy_listener("0.0.0.0:0").await.is_err());
    drop(owned);
    let replacement = bind_proxy_listener(&address.to_string()).await.unwrap();
    assert_eq!(replacement.local_addr().unwrap(), address);
}

/// Shared startup preflight: never changes the OS proxy or claims an
/// authenticated remote tunnel merely because the listeners bind.
async fn prepare_proxy(
    document: &config::ClientDocument,
    path: &Path,
) -> Result<(TcpListener, TcpListener, ProxyClient), ClientError> {
    let client = prepare_client(document, path).await?;
    // All startup validation and both binds must succeed before accepting.
    let http = bind_proxy_listener(&document.client.proxy.http_listen).await?;
    let socks = bind_proxy_listener(&document.client.proxy.socks5_listen).await?;
    crate::diag!(
        Info,
        "client.proxy",
        "listeners_bound",
        "count" = Value::Count(2)
    );
    Ok((http, socks, client))
}

async fn prepare_client(
    document: &config::ClientDocument,
    path: &Path,
) -> Result<ProxyClient, ClientError> {
    let profile = document
        .client
        .profiles
        .iter()
        .find(|p| p.id == document.client.active_profile)
        .ok_or(ClientError::Configuration)?;
    crate::diag!(
        Debug,
        "client.proxy",
        "config_valid",
        "profiles" = Value::Count(document.client.profiles.len() as u64)
    );
    let client = load_client_with_budget(
        profile,
        crate::connection_pool::profile_budget(),
        Some(path),
    )
    .await?;
    client
        .routing_cache()
        .dpi
        .set_enabled(profile.direct_dpi.unwrap_or(false));
    client
        .routing_cache()
        .dpi
        .set_stun_enabled(profile.direct_dpi_stun.unwrap_or(false));
    client.routing_policy().await?;
    crate::diag!(Info, "client.proxy", "transport_preflight_passed");
    Ok(client)
}

/// A Windows TUI starts the local client independently of OS proxy consent.
/// The exact saved TOML is parsed once; subsequent activation must still
/// match that editor revision. No credential or source text leaves this API.
pub(crate) struct PreparedLocalProxy {
    http: TcpListener,
    socks: TcpListener,
    client: ProxyClient,
}

impl PreparedLocalProxy {
    pub(crate) async fn start_selected(
        path: &Path,
        expected: [u8; 32],
        id: &str,
    ) -> Result<Self, ClientError> {
        let bytes = saved_client_bytes(path, expected)?;
        let Config::Client(document) =
            config::parse(std::str::from_utf8(&bytes).map_err(|_| ClientError::Configuration)?)
                .map_err(|_| ClientError::Configuration)?
        else {
            return Err(ClientError::Configuration);
        };
        if document.client.active_profile != id
            || !document.client.profiles.iter().any(|p| p.id == id)
        {
            return Err(ClientError::Configuration);
        }
        let (http, socks, client) = prepare_proxy(&document, path).await?;
        // Detect edits during DNS/bind preflight before accepting traffic.
        saved_client_bytes(path, expected)?;
        Ok(Self {
            http,
            socks,
            client,
        })
    }

    pub(crate) async fn serve_selected_observed(
        self,
        mut stop: tokio::sync::oneshot::Receiver<()>,
        report: Arc<Mutex<String>>,
    ) -> Result<(), ClientError> {
        let client = self.client.clone();
        let monitor = async move {
            loop {
                let status = client.runtime_report().await;
                if let Ok(mut slot) = report.lock() {
                    *slot = status;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        };
        tokio::select! {
            result=serve_proxy(self.http,self.socks,self.client)=>result,
            _=monitor=>Ok(()),
            _=&mut stop=>Ok(()),
        }
    }
}

pub(crate) fn saved_client_bytes(
    path: &Path,
    expected: [u8; 32],
) -> Result<zeroize::Zeroizing<Vec<u8>>, ClientError> {
    use sha2::{Digest, Sha256};
    let bytes = zeroize::Zeroizing::new(
        config::editor_bytes(path).map_err(|_| ClientError::Configuration)?,
    );
    let actual: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
    if actual != expected {
        return Err(ClientError::Configuration);
    }
    Ok(bytes)
}

pub async fn serve(
    http: TcpListener,
    socks: TcpListener,
    client: Arc<H2Client>,
) -> Result<(), ClientError> {
    serve_proxy(http, socks, ProxyClient::direct(Carrier::H2(client))).await
}

async fn serve_proxy(
    http: TcpListener,
    socks: TcpListener,
    client: ProxyClient,
) -> Result<(), ClientError> {
    let maintenance = async { client.maintain().await };
    serve_proxy_loop(http, socks, || Some(client.clone()), maintenance).await
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn serve_managed_proxy(
    http: TcpListener,
    socks: TcpListener,
    runtime: Arc<ClientRuntime>,
) -> Result<(), ClientError> {
    serve_proxy_loop(
        http,
        socks,
        || {
            runtime
                .admitting()
                .then(|| runtime.slot.borrow().client.clone())
        },
        runtime.maintain(),
    )
    .await
}

async fn serve_proxy_loop(
    http: TcpListener,
    socks: TcpListener,
    current: impl Fn() -> Option<ProxyClient>,
    maintenance: impl std::future::Future<Output = Result<(), ClientError>>,
) -> Result<(), ClientError> {
    // Preserve the boundary even for callers bypassing TOML validation.
    for listener in [&http, &socks] {
        let addr = listener.local_addr().map_err(|_| ClientError::Io)?;
        if !matches!(
            addr.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST) | IpAddr::V6(Ipv6Addr::LOCALHOST)
        ) {
            return Err(ClientError::Configuration);
        }
    }
    crate::diag!(
        Info,
        "client.proxy",
        "accept_loop_started",
        "max_sessions" = Value::Count(LOCAL_LIMIT as u64)
    );
    let slots = Arc::new(Semaphore::new(LOCAL_LIMIT));
    let mut tasks = JoinSet::new();
    // Tied to this accept loop: shutdown or cancellation drops maintenance,
    // including any in-flight QUIC probe, before releasing the profile.
    tokio::pin!(maintenance);
    loop {
        let (socket, is_http) = tokio::select! {
            biased;
            result = &mut maintenance => {
                tasks.shutdown().await;
                return result;
            },
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
            accepted = http.accept() => match accepted {
                Ok((socket, _)) => (socket, true),
                Err(_) => { tasks.shutdown().await; return Err(ClientError::Io); }
            },
            accepted = socks.accept() => match accepted {
                Ok((socket, _)) => (socket, false),
                Err(_) => { tasks.shutdown().await; return Err(ClientError::Io); }
            },
        };
        let session_id = diagnostics::next_id();
        crate::diag!(
            Trace,
            "client.proxy",
            "local_accepted",
            "session" = Value::Count(session_id),
            "http_connect" = Value::Flag(is_http)
        );
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            crate::diag!(
                Warn,
                "client.proxy",
                "session_quota_rejected",
                "session" = Value::Count(session_id)
            );
            continue;
        };
        let Some(client) = current() else { continue };
        tasks.spawn(async move {
            let _slot = slot;
            let result = handle(socket, is_http, &client, session_id).await;
            match result {
                Ok(()) => crate::diag!(
                    Info,
                    "client.proxy",
                    "session_completed",
                    "session" = Value::Count(session_id)
                ),
                Err(error) => crate::diag!(
                    Warn,
                    "client.proxy",
                    "session_failed",
                    "session" = Value::Count(session_id),
                    "reason" = Value::Label(error_kind(&error))
                ),
            }
        });
    }
}

use ingress::{handle, HttpOnce};
#[cfg(test)]
use ingress::{
    http_target, socks_target, HttpRequest, HEADER_LIMIT, HTTP_BAD, HTTP_DENIED, HTTP_METHOD,
    HTTP_OK,
};

mod selector_tests;
