//! Local loopback-only CONNECT and SOCKS5 listeners for H2, H3 or conservative QUIC-first auto mode.
//! Local direct destinations use bounded DNS only after explicit routing authorization.
use crate::{
    client::{error_kind, ClientError, H2Client, Tunnel},
    config::{self, Config, Profile, Transport, XhttpMode},
    diagnostics::{self, Value},
    h3_client::{H3Client, H3Tunnel},
    protocol::{self, Address, ErrorCode, Frame},
    routing::{
        client_state::{self, Cache},
        snapshot::Snapshot,
        Action,
    },
    security_profile::SecurityMode,
};
use rustls::RootCertStore;
use std::{
    io::BufReader,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
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
const HEADER_LIMIT: usize = 8192;
const NEGOTIATE_TIMEOUT: Duration = Duration::from_secs(10);
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);
const CA_LIMIT: usize = 1024 * 1024;
const AUTO_QUIC_ATTEMPTS: usize = 2;

const HTTP_OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const HTTP_BAD: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const HTTP_METHOD: &[u8] =
    b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const HTTP_DENIED: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const HTTP_FAILED: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const HTTP_TIMEOUT: &[u8] =
    b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

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
    let reference = profile.tls_ca.as_deref().ok_or(ClientError::Configuration)?;
    let (trust, identity) = if let Some(anchor) = crate::own_tls::Anchor::parse(reference) {
        (crate::own_tls::Trust::Pinned(anchor), anchor.bytes())
    } else {
        let cert = load_file(reference, CA_LIMIT, false)?;
        use sha2::{Digest, Sha256};
        let identity = Sha256::digest(cert.as_slice()).into();
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut BufReader::new(cert.as_slice())) {
            roots.add(cert.map_err(|_| ClientError::Configuration)?)
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
            let h2 = H2Client::new_with_trust(&remote.to_string(), &profile.server_name, &token, &trust)?
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
    async fn open(&self, address: Address, port: u16) -> Result<RoutedTcp, ClientError> {
        let generation = self.generation().await?;
        let mut result = routed_open(&generation.carrier, &self.routing, address, port).await;
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

/// The OS chooses the UDP source address for the pinned server. Connecting
/// this temporary socket sends no application datagram and performs no DNS.
/// Preserve IPv6 scope, discard the ephemeral local port. A failed observation
/// must never authorize reuse of an earlier negative cache entry.
pub(crate) fn route_source(remote: SocketAddr) -> Option<SocketAddr> {
    #[cfg(target_os = "windows")]
    if crate::routing::carrier_socket::active() {
        return windows_route_source(remote);
    }
    let bind = if remote.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(remote).ok()?;
    let mut local = socket.local_addr().ok()?;
    if local.ip().is_unspecified() {
        return None;
    }
    local.set_port(0);
    Some(local)
}

// Read-only route query, not a throwaway UDP connect (which would itself
// require WFP ALE permission while capture is active).
#[cfg(target_os = "windows")]
fn windows_route_source(remote: SocketAddr) -> Option<SocketAddr> {
    use std::{mem, ptr};
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{GetBestInterfaceEx, GetBestRoute2, MIB_IPFORWARD_ROW2},
        Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET},
    };
    if remote.ip().is_unspecified() || remote.ip().is_multicast() {
        return None;
    }
    let mut dst: SOCKADDR_INET = unsafe { mem::zeroed() };
    let mut source: SOCKADDR_INET = unsafe { mem::zeroed() };
    if mem::size_of::<SOCKADDR_INET>() != 28 {
        return None;
    }
    let raw = unsafe {
        std::slice::from_raw_parts_mut((&mut dst as *mut SOCKADDR_INET).cast::<u8>(), 28)
    };
    match remote {
        SocketAddr::V4(v4) => {
            raw[..2].copy_from_slice(&AF_INET.to_ne_bytes());
            raw[4..8].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            if v6.scope_id() != 0 || v6.ip().to_ipv4_mapped().is_some() {
                return None;
            }
            raw[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            raw[8..24].copy_from_slice(&v6.ip().octets());
        }
    }
    let mut interface = 0u32;
    if unsafe { GetBestInterfaceEx((&mut dst as *mut SOCKADDR_INET).cast(), &mut interface) } != 0
        || interface == 0
    {
        return None;
    }
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { mem::zeroed() };
    if unsafe {
        GetBestRoute2(
            ptr::null(),
            interface,
            ptr::null(),
            &dst,
            0,
            &mut route,
            &mut source,
        )
    } != 0
    {
        return None;
    }
    let raw =
        unsafe { std::slice::from_raw_parts((&source as *const SOCKADDR_INET).cast::<u8>(), 28) };
    let family = u16::from_ne_bytes(raw[..2].try_into().ok()?);
    let ip = match (remote, family) {
        (SocketAddr::V4(_), AF_INET) => {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&raw[4..8]).ok()?))
        }
        (SocketAddr::V6(_), AF_INET6) if raw[24..28] == [0; 4] => {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).ok()?))
        }
        _ => return None,
    };
    (!ip.is_unspecified() && !ip.is_multicast()).then_some(SocketAddr::new(ip, 0))
}

#[derive(Default)]
struct NegativeCache {
    route: Option<crate::network_scope::Scope>,
    generation: u64,
    expires: Option<Instant>,
}

impl NegativeCache {
    fn observe(&mut self, route: Option<crate::network_scope::Scope>, now: Instant) -> (u64, bool) {
        if route.is_none() || self.route != route {
            self.route = route;
            self.invalidate();
        }
        if self.expires.is_some_and(|until| now >= until) {
            // A foreground request may win the expiry race. Retire the
            // previous generation so a sleeping maintenance task cannot
            // publish evidence for it later.
            self.invalidate();
        }
        (self.generation, self.expires.is_some())
    }

    fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.expires = None;
    }

    fn record(&mut self, generation: u64, now: Instant, ttl: Duration) -> bool {
        if self.generation != generation
            || self.route.is_none()
            || ttl.is_zero()
            || self.expires.is_some()
        {
            return false;
        }
        // Concurrent failures must not push the first recheck further away.
        self.expires = now.checked_add(ttl);
        self.expires.is_some()
    }

    fn begin_recheck(
        &mut self,
        generation: u64,
        deadline: Instant,
        route: Option<crate::network_scope::Scope>,
        now: Instant,
    ) -> Option<u64> {
        if self.generation != generation || self.expires != Some(deadline) || now < deadline {
            return None;
        }
        if route.is_none() || self.route != route {
            self.route = route;
            self.invalidate();
            return None;
        }
        self.invalidate();
        Some(self.generation)
    }
}

struct AutoClient {
    h2: Arc<H2Client>,
    h3: Arc<H3Client>,
    ttl: Duration,
    negative: Mutex<NegativeCache>,
    cache_changed: Notify,
    recheck_gate: tokio::sync::Mutex<()>,
}

impl AutoClient {
    fn observe(&self) -> Result<(u64, bool), ClientError> {
        let mut cache = self
            .negative
            .lock()
            .map_err(|_| ClientError::Configuration)?;
        let previous = cache.generation;
        let observed = cache.observe(
            crate::network_scope::observe(self.h3.remote()),
            Instant::now(),
        );
        if previous != cache.generation {
            self.cache_changed.notify_one();
        }
        Ok(observed)
    }

    fn complete(&self, generation: u64, unreachable: bool) -> Result<bool, ClientError> {
        let mut cache = self
            .negative
            .lock()
            .map_err(|_| ClientError::Configuration)?;
        let current = crate::network_scope::observe(self.h3.remote());
        // Unknown routing is never cached. A known changed route must not
        // inherit a fallback decision obtained on the previous network.
        if current != cache.route {
            cache.route = current;
            cache.invalidate();
            self.cache_changed.notify_one();
        }
        if !unreachable {
            if cache.generation == generation {
                cache.invalidate();
                self.cache_changed.notify_one();
            }
            return Ok(false);
        }
        if cache.generation != generation || current.is_none() {
            return Ok(false);
        }
        if cache.record(generation, Instant::now(), self.ttl) {
            self.cache_changed.notify_one();
        }
        Ok(true)
    }

    /// Check the generation without consuming a due recheck. Both
    /// foreground and maintenance use this before taking another step.
    fn same_scope(&self, generation: u64) -> Result<bool, ClientError> {
        let mut cache = self
            .negative
            .lock()
            .map_err(|_| ClientError::Configuration)?;
        let scope = crate::network_scope::observe(self.h3.remote());
        if scope != cache.route || scope.is_none() {
            cache.route = scope;
            cache.invalidate();
            self.cache_changed.notify_one();
            return Ok(false);
        }
        Ok(cache.generation == generation)
    }

    /// The single fallback decision for tunnel, descriptor and background
    /// probe operations. Only a pre-authenticated QuicUnreachable result
    /// can reach the retry branch. Every other error remains terminal.
    async fn attempt_h3<T, F, Fut>(
        &self,
        generation: u64,
        mut attempt: F,
    ) -> Result<Option<T>, ClientError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, ClientError>>,
    {
        for index in 0..AUTO_QUIC_ATTEMPTS {
            // Unknown network scope disables reuse and fallback, not a
            // first authenticated H3 connection attempt.
            if index > 0 && !self.same_scope(generation)? {
                return Err(ClientError::QuicUnreachable);
            }
            match attempt().await {
                Ok(value) => {
                    self.complete(generation, false)?;
                    return Ok(Some(value));
                }
                Err(ClientError::QuicUnreachable) if index + 1 < AUTO_QUIC_ATTEMPTS => {}
                Err(ClientError::QuicUnreachable | ClientError::QuicEndpointNetworkRefused) => {
                    if self.complete(generation, true)? {
                        return Ok(None);
                    }
                    crate::diag!(
                        Warn,
                        "client.auto",
                        "stale_quic_probe_rejected",
                        "generation" = Value::Count(generation)
                    );
                    return Err(ClientError::QuicUnreachable);
                }
                Err(error) => {
                    self.complete(generation, false)?;
                    crate::diag!(
                        Warn,
                        "client.auto",
                        "terminal_h3_failure_no_fallback",
                        "generation" = Value::Count(generation),
                        "reason" = Value::Label(error_kind(&error))
                    );
                    return Err(error);
                }
            }
        }
        Err(ClientError::Configuration)
    }

    /// A due negative-cache expiry has exactly one owner, whether a new
    /// tunnel or the maintenance timer arrives first. Keep the async gate
    /// only for that bounded credential-free probe, not for application OPEN.
    /// Cancellation discards evidence and releases the gate; no fallback
    /// can be published by a canceled probe.
    async fn prepare(&self) -> Result<(u64, bool), ClientError> {
        let _gate = self.recheck_gate.lock().await;
        let recheck = {
            let mut cache = self
                .negative
                .lock()
                .map_err(|_| ClientError::Configuration)?;
            let now = Instant::now();
            let scope = crate::network_scope::observe(self.h3.remote());
            match cache.expires {
                Some(deadline) if now >= deadline => {
                    let generation = cache.generation;
                    cache.begin_recheck(generation, deadline, scope, now)
                }
                _ => None,
            }
        };
        if let Some(generation) = recheck {
            match self.attempt_h3(generation, || self.h3.probe()).await {
                Ok(Some(())) => crate::diag!(Debug, "client.auto", "background_h3_verified"),
                Ok(None) => {}
                Err(error) => {
                    crate::diag!(
                        Warn,
                        "client.auto",
                        "background_h3_terminal_failure",
                        "reason" = Value::Label(error_kind(&error))
                    );
                    return Err(error);
                }
            }
        }
        self.observe()
    }

    /// One maintenance future per immutable carrier generation. Foreground
    /// requests use the exact same expiry gate. No detached probe survives
    /// runtime shutdown or a security/credential generation replacement.
    async fn maintain(&self) -> Result<(), ClientError> {
        loop {
            let pending = self
                .negative
                .lock()
                .map_err(|_| ClientError::Configuration)?
                .expires;
            let Some(deadline) = pending else {
                self.cache_changed.notified().await;
                continue;
            };
            tokio::select! {
                _ = self.cache_changed.notified() => continue,
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
            }
            // Terminal remote errors invalidate evidence, not the running
            // local listener. The next request still verifies independently.
            let _ = self.prepare().await;
        }
    }

    async fn fetch_routing(&self, known: Option<[u8; 32]>) -> Result<Vec<u8>, ClientError> {
        let (generation, cached) = self.prepare().await?;
        if !cached {
            if let Some(value) = self
                .attempt_h3(generation, || self.h3.fetch_routing(known))
                .await?
            {
                return Ok(value);
            }
        }
        if !self.same_scope(generation)? {
            return Err(ClientError::QuicUnreachable);
        }
        self.h2.fetch_routing(known).await
    }

    async fn resolve_routing(
        &self,
        name: &str,
        digest: [u8; 32],
    ) -> Result<Vec<IpAddr>, ClientError> {
        let (generation, cached) = self.prepare().await?;
        if !cached {
            if let Some(value) = self
                .attempt_h3(generation, || self.h3.resolve_routing(name, digest))
                .await?
            {
                return Ok(value);
            }
        }
        if !self.same_scope(generation)? {
            return Err(ClientError::QuicUnreachable);
        }
        self.h2.resolve_routing(name, digest).await
    }

    async fn fetch_identity_document(&self, successor: bool) -> Result<String, ClientError> {
        let (generation, cached) = self.prepare().await?;
        if !cached {
            if let Some(value) = self
                .attempt_h3(generation, || self.h3.fetch_identity_document(successor))
                .await?
            {
                return Ok(value);
            }
        }
        if !self.same_scope(generation)? {
            return Err(ClientError::QuicUnreachable);
        }
        self.h2.fetch_identity_document(successor).await
    }

    async fn open_udp(
        &self,
        address: Address,
        port: u16,
    ) -> Result<crate::udp_relay::Tunnel, ClientError> {
        let (generation, cached) = self.prepare().await?;
        if !cached {
            if let Some(tunnel) = self
                .attempt_h3(generation, || self.h3.open_udp(address.clone(), port))
                .await?
            {
                return Ok(crate::udp_relay::Tunnel::H3(Box::new(tunnel)));
            }
        }
        if !self.same_scope(generation)? {
            return Err(ClientError::QuicUnreachable);
        }
        self.h2
            .open_udp(address, port)
            .await
            .map(Box::new)
            .map(crate::udp_relay::Tunnel::H2)
    }

    async fn open(&self, address: Address, port: u16) -> Result<ProxyTunnel, ClientError> {
        let (generation, cached) = self.prepare().await?;
        crate::diag!(
            Debug,
            "client.auto",
            "transport_select",
            "generation" = Value::Count(generation),
            "negative_cache_hit" = Value::Flag(cached)
        );
        // XHTTP caches remain carrier-local; only the configured mode
        // restriction crosses the transport boundary.
        if !cached {
            if let Some(tunnel) = self
                .attempt_h3(generation, || self.h3.open(address.clone(), port))
                .await?
            {
                crate::diag!(
                    Debug,
                    "client.auto",
                    "selected_h3",
                    "generation" = Value::Count(generation)
                );
                eprintln!("transport=h3");
                return Ok(ProxyTunnel::H3(Box::new(tunnel)));
            }
            crate::diag!(
                Warn,
                "client.auto",
                "h3_udp_silent_fallback_h2",
                "generation" = Value::Count(generation)
            );
            eprintln!("transport=h2 reason=quic_unreachable");
        } else {
            crate::diag!(
                Debug,
                "client.auto",
                "negative_cache_fallback_h2",
                "generation" = Value::Count(generation)
            );
            eprintln!("transport=h2 reason=quic_negative_cache");
        }
        if !self.same_scope(generation)? {
            return Err(ClientError::QuicUnreachable);
        }
        self.h2
            .open(address, port)
            .await
            .map(Box::new)
            .map(ProxyTunnel::H2)
    }
}

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
        self.tunnel.relay_guarded(socket, Some(&self.flow)).await
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
    async fn relay(
        self,
        upload: tokio::sync::mpsc::Receiver<Vec<u8>>,
        download: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Result<(), ClientError> {
        self.tunnel
            .relay_guarded(upload, download, Some(&self.flow))
            .await
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
            (Some(h2), Some(h3)) => Ok(Self::Auto(Arc::new(AutoClient {
                h2,
                h3,
                ttl,
                negative: Mutex::new(NegativeCache::default()),
                cache_changed: Notify::new(),
                recheck_gate: tokio::sync::Mutex::new(()),
            }))),
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

async fn route_decision(
    carrier: &Carrier,
    cache: &Cache,
    address: &Address,
) -> Result<(Arc<Snapshot>, Action, Option<Vec<IpAddr>>), ClientError> {
    let snapshot = cache.get(|known| carrier.fetch_routing(known)).await?;
    let policy = snapshot.policy();
    let denied = || ClientError::Open(ErrorCode::PolicyDenied);
    use crate::routing::Evidence;
    let mut pinned = None;
    let action = match address {
        Address::V4(ip) => policy
            .classify(
                Evidence::Absent,
                Evidence::Known(IpAddr::V4(Ipv4Addr::from(*ip))),
            )
            .map_err(|_| denied())?
            .action()
            .ok_or_else(denied)?,
        Address::V6(ip) => policy
            .classify(
                Evidence::Absent,
                Evidence::Known(IpAddr::V6(Ipv6Addr::from(*ip))),
            )
            .map_err(|_| denied())?
            .action()
            .ok_or_else(denied)?,
        Address::Dns(name) => match policy
            .classify(Evidence::Known(name), Evidence::Unknown)
            .map_err(|_| denied())?
            .action()
        {
            Some(action) => action,
            None => {
                // Resolve only over the verified control channel when an IP
                // rule can precede the domain decision. Never locally resolve
                // a potentially proxied hostname.
                let ips = carrier.resolve_routing(name, snapshot.digest()).await?;
                let mut action = None;
                for ip in &ips {
                    let selected = policy
                        .classify(Evidence::Known(name), Evidence::Known(*ip))
                        .map_err(|_| denied())?
                        .action()
                        .ok_or_else(denied)?;
                    if action.is_some_and(|old| old != selected) {
                        // Mixed route decisions are ambiguous; do not silently
                        // downgrade to direct or proxy one of the blocked IPs.
                        action = Some(Action::Blocked);
                        break;
                    }
                    action = Some(selected);
                }
                pinned = Some(ips);
                action.ok_or_else(denied)?
            }
        },
    };
    // DNS preflight may have awaited network I/O; never return a superseded
    // policy as authorization to initiate an egress.
    cache.dpi.check_policy(snapshot.digest())?;
    Ok((snapshot, action, pinned))
}

async fn routed_open(
    carrier: &Carrier,
    cache: &Cache,
    address: Address,
    port: u16,
) -> Result<RoutedTcp, ClientError> {
    let (snapshot, action, pinned) = route_decision(carrier, cache, &address).await?;
    if action.packet_action() == crate::routing::PacketAction::Drop {
        crate::traffic::blocked();
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    let flow = cache.flows.begin(
        cache.dpi.clone(),
        crate::routing::flow::Protocol::Tcp,
        address.clone(),
        port,
        snapshot.digest(),
        action.packet_action(),
    )?;
    let tunnel =
        routed_open_selected(carrier, cache, address, port, snapshot, action, pinned).await?;
    Ok(RoutedTcp { tunnel, flow })
}

async fn routed_open_selected(
    carrier: &Carrier,
    cache: &Cache,
    address: Address,
    port: u16,
    snapshot: Arc<Snapshot>,
    action: Action,
    pinned: Option<Vec<IpAddr>>,
) -> Result<ProxyTunnel, ClientError> {
    let policy = snapshot.policy();
    let denied = || ClientError::Open(ErrorCode::PolicyDenied);
    match action.packet_action() {
        crate::routing::PacketAction::Drop => {
            crate::traffic::blocked();
            Err(denied())
        }
        crate::routing::PacketAction::Redirect => {
            cache.dpi.check_policy(snapshot.digest())?;
            let tunnel = carrier.open(address, port).await?;
            cache.dpi.check_policy(snapshot.digest())?;
            Ok(tunnel)
        }
        crate::routing::PacketAction::Modify => {
            // Initial native backend supports domain HTTPS TCP only. Resolve
            // via the authenticated policy endpoint, never the local resolver.
            if cache.dpi.enabled() && matches!(port, 443 | 8443) {
                if let Address::Dns(name) = &address {
                    let ips = match pinned {
                        Some(ips) => ips,
                        None => match carrier.resolve_routing(name, snapshot.digest()).await {
                            Ok(ips) => ips,
                            // Only a conclusive domain rule can fall back on a
                            // transient DNS server error. Auth/policy/digest
                            // errors must not be hidden by a fallback.
                            Err(ClientError::Rejected(502 | 504)) => Vec::new(),
                            Err(error) => return Err(error),
                        },
                    };
                    let permitted = !ips.is_empty()
                        && ips.iter().all(|ip| {
                            policy.classify(
                                crate::routing::Evidence::Known(name),
                                crate::routing::Evidence::Known(*ip),
                            ) == Ok(crate::routing::Classification::Matched(Action::DirectDpi))
                        });
                    if !ips.is_empty() && !permitted {
                        return Err(denied());
                    }
                    if permitted {
                        if let Some(tunnel) =
                            cache.dpi.open(name, port, &ips, snapshot.digest()).await
                        {
                            return Ok(ProxyTunnel::Dpi(Box::new(DpiRoute {
                                tunnel,
                                observed: None,
                                carrier: carrier.clone(),
                                address,
                                port,
                            })));
                        }
                    }
                }
            }
            // A changed local policy does not authorize an older fallback.
            if !cache.dpi.policy_current(snapshot.digest()) {
                return Err(crate::routing::dpi::stale_policy());
            }
            // Failed local probe/dial or unsupported traffic uses the same
            // authenticated VPS carrier. No silent unprotected direct route.
            let tunnel = carrier.open(address, port).await?;
            cache.dpi.check_policy(snapshot.digest())?;
            crate::traffic::dpi_fallback_open();
            Ok(tunnel)
        }
        crate::routing::PacketAction::Pass => {
            cache.dpi.check_policy(snapshot.digest())?;
            let target = client_state::dial_direct(address, port, pinned).await?;
            cache.dpi.check_policy(snapshot.digest())?;
            Ok(ProxyTunnel::Direct(target))
        }
    }
}

async fn routed_udp(
    carrier: &Carrier,
    cache: &Cache,
    address: Address,
    port: u16,
    candidate: &crate::routing::dpi::udp::Candidate,
    observed: &Arc<std::sync::atomic::AtomicU8>,
) -> Result<RoutedUdp, ClientError> {
    let (snapshot, action, pinned) = route_decision(carrier, cache, &address).await?;
    if action.packet_action() == crate::routing::PacketAction::Drop {
        crate::traffic::blocked();
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    let flow = cache.flows.begin(
        cache.dpi.clone(),
        crate::routing::flow::Protocol::Udp,
        address.clone(),
        port,
        snapshot.digest(),
        action.packet_action(),
    )?;
    let tunnel = routed_udp_selected(
        carrier, cache, address, port, candidate, observed, snapshot, action, pinned,
    )
    .await?;
    Ok(RoutedUdp { tunnel, flow })
}

#[allow(clippy::too_many_arguments)]
async fn routed_udp_selected(
    carrier: &Carrier,
    cache: &Cache,
    address: Address,
    port: u16,
    candidate: &crate::routing::dpi::udp::Candidate,
    observed: &Arc<std::sync::atomic::AtomicU8>,
    snapshot: Arc<Snapshot>,
    action: Action,
    pinned: Option<Vec<IpAddr>>,
) -> Result<crate::udp_relay::Tunnel, ClientError> {
    match action.packet_action() {
        crate::routing::PacketAction::Drop => {
            crate::traffic::blocked();
            Err(ClientError::Open(ErrorCode::PolicyDenied))
        }
        crate::routing::PacketAction::Pass => {
            cache.dpi.check_policy(snapshot.digest())?;
            let target = crate::udp_relay::direct(address, port, pinned).await?;
            cache.dpi.check_policy(snapshot.digest())?;
            Ok(crate::udp_relay::Tunnel::Direct(target))
        }
        crate::routing::PacketAction::Redirect => {
            cache.dpi.check_policy(snapshot.digest())?;
            let tunnel = carrier.open_udp(address, port).await?;
            cache.dpi.check_policy(snapshot.digest())?;
            Ok(tunnel)
        }
        crate::routing::PacketAction::Modify => {
            use crate::routing::dpi::udp::Candidate;
            // The locked Quinn backend cannot authenticate QUIC v2.
            // Never treat a v1 handshake as evidence for v2.
            let stun = matches!(candidate, Candidate::StunBinding);
            let local_candidate = match (&address, candidate) {
                (Address::Dns(name), Candidate::QuicH3(sni))
                    if port == 443 && cache.dpi.enabled() =>
                {
                    crate::routing::domain_name(name).as_deref() == Ok(sni.as_str())
                }
                (Address::Dns(_), Candidate::StunBinding)
                    if port == 3478 && cache.dpi.stun_enabled() =>
                {
                    true
                }
                _ => false,
            };
            if local_candidate {
                if let Address::Dns(name) = &address {
                    let ips = match pinned {
                        Some(ips) => ips,
                        None => match carrier.resolve_routing(name, snapshot.digest()).await {
                            Ok(ips) => ips,
                            Err(ClientError::Rejected(502 | 504)) => Vec::new(),
                            Err(error) => return Err(error),
                        },
                    };
                    let permitted = ips.iter().all(|ip| {
                        snapshot.policy().classify(
                            crate::routing::Evidence::Known(name),
                            crate::routing::Evidence::Known(*ip),
                        ) == Ok(crate::routing::Classification::Matched(Action::DirectDpi))
                    });
                    if !permitted {
                        return Err(ClientError::Open(ErrorCode::PolicyDenied));
                    }
                    if !ips.is_empty() {
                        let verified = if stun {
                            cache
                                .dpi
                                .open_stun_udp(name, port, &ips, snapshot.digest())
                                .await
                        } else {
                            cache
                                .dpi
                                .open_quic_udp(name, port, &ips, snapshot.digest())
                                .await
                        };
                        if let Some(verified) = verified {
                            let carrier = carrier.clone();
                            let target = address.clone();
                            let observed = observed.clone();
                            let fallback = Box::pin(async move {
                                let tunnel = carrier.open_udp(target, port).await?;
                                tunnel.record_transport(&observed);
                                crate::traffic::udp_dpi_fallback();
                                if stun {
                                    crate::traffic::udp_stun_fallback();
                                }
                                Ok(tunnel)
                            });
                            return Ok(crate::udp_relay::Tunnel::VerifiedLocal(
                                Box::new(verified),
                                fallback,
                            ));
                        }
                    }
                }
            }
            if !cache.dpi.policy_current(snapshot.digest()) {
                return Err(crate::routing::dpi::stale_policy());
            }
            let tunnel = carrier.open_udp(address, port).await?;
            cache.dpi.check_policy(snapshot.digest())?;
            crate::traffic::udp_dpi_fallback();
            if matches!(candidate, Candidate::Stun | Candidate::StunBinding) {
                crate::traffic::udp_stun_fallback();
            }
            if matches!(candidate, Candidate::QuicV2H3(_)) {
                crate::traffic::udp_quic_v2_fallback();
            }
            Ok(tunnel)
        }
    }
}

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
            "{report}\nСистемный перехват: не активирован (backend не готов)\n{}\n{}\nЛокальный Anti-DPI: {}\n{}",
            crate::routing::flow::summary(self.routing_cache().flows.counts()),
            self.routing_cache().report(),
            if self.routing_cache().dpi.enabled() {
                "разрешён (экспериментальный TCP/TLS)"
            } else {
                "выключен; резерв VPS"
            },
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

    async fn open_udp(
        &self,
        address: Address,
        port: u16,
        candidate: &crate::routing::dpi::udp::Candidate,
    ) -> Result<RoutedUdp, ClientError> {
        match self {
            Self::Direct(c) => {
                let tunnel = routed_udp(
                    &c.carrier,
                    &c.routing,
                    address,
                    port,
                    candidate,
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
        match self {
            Self::Direct(client) => {
                let mut tunnel =
                    routed_open(&client.carrier, &client.routing, address, port).await?;
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
            Self::Reality(client) => client.open(address, port).await,
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
                let _ = self.routing_policy().await;
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
                        let tunnel = carrier.open(address, port).await?;
                        authorization.check()?;
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
    Box::pin(run_file_inner(config_path, false)).await
}

/// Windows-only, explicitly confirmed user WinINet proxy operation. The
/// settings are touched ONLY after strict client/TLS preflight and BOTH local
/// loopback TCP listeners are bound, never on plain client run or server run.
#[cfg(windows)]
pub async fn run_file_with_system_proxy(config_path: &Path) -> Result<(), ClientError> {
    Box::pin(run_file_inner(config_path, true)).await
}

// The process-level generation owns the exact saved config. Old accepted
// sockets retain their carrier clone; only new accepts use the new snapshot.
#[cfg(any(target_os = "linux", target_os = "windows"))]
struct ClientView {
    document: config::ClientDocument,
    digest: [u8; 32],
    revision: u64,
    client: ProxyClient,
}
// One atomic lifecycle: a concurrent Stop must never be overwritten by
// preparation or a backend's final readiness publication. State 4 is an
// internal terminal state for runtimes that never owned native capture.
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[derive(Default)]
struct CaptureLifecycle(std::sync::atomic::AtomicU8);

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl CaptureLifecycle {
    fn idle(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire) == 0
    }

    fn running(&self) -> bool {
        matches!(self.0.load(std::sync::atomic::Ordering::Acquire), 1 | 2)
    }

    fn accepting(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire) == 2
    }

    fn begin(&self) -> Result<(), ClientError> {
        self.transition(0, 1)
    }

    fn ready(&self) -> Result<(), ClientError> {
        self.transition(1, 2)
    }

    fn transition(&self, from: u8, to: u8) -> Result<(), ClientError> {
        use std::sync::atomic::Ordering;
        self.0
            .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ClientError::Configuration)
    }

    fn stop(&self) {
        use std::sync::atomic::Ordering;
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            let next = match state {
                0 => 4,
                1 | 2 => 3,
                _ => return,
            };
            match self
                .0
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(observed) => state = observed,
            }
        }
    }

    fn reported(&self) -> u8 {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            4 => 0,
            state => state,
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
mod capture_lifecycle_tests {
    use super::CaptureLifecycle;

    #[test]
    fn stopped_before_preparation_cannot_publish_capture() {
        let state = CaptureLifecycle::default();
        assert!(state.idle());
        state.stop();
        assert_eq!(state.reported(), 0);
        assert!(!state.idle());
        assert!(!state.running());
        assert!(state.begin().is_err());
        assert!(state.ready().is_err());
        state.stop();
        assert_eq!(state.reported(), 0);
    }

    #[test]
    fn interrupted_preparation_is_recovery_required() {
        let state = CaptureLifecycle::default();
        assert!(state.ready().is_err());
        state.begin().unwrap();
        assert_eq!(state.reported(), 1);
        assert!(state.running());
        assert!(!state.accepting());
        assert!(state.begin().is_err());
        state.stop();
        assert_eq!(state.reported(), 3);
        assert!(state.ready().is_err());
        assert!(state.begin().is_err());
        assert!(!state.running());
        state.stop();
        assert_eq!(state.reported(), 3);
    }

    #[test]
    fn ready_then_stop_is_terminal() {
        let state = CaptureLifecycle::default();
        state.begin().unwrap();
        state.ready().unwrap();
        assert_eq!(state.reported(), 2);
        assert!(state.accepting());
        assert!(state.ready().is_err());
        assert!(state.running());
        state.stop();
        assert_eq!(state.reported(), 3);
        assert!(!state.running());
        assert!(!state.accepting());
        assert!(state.ready().is_err());
    }

    #[test]
    fn concurrent_ready_and_stop_cannot_resurrect_capture() {
        let state = CaptureLifecycle::default();
        state.begin().unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                let _ = state.ready();
            });
            barrier.wait();
            state.stop();
        });
        assert_eq!(state.reported(), 3);
        assert!(!state.running());
        assert!(state.ready().is_err());
    }

    #[test]
    fn concurrent_prepare_and_stop_never_leaves_a_live_state() {
        let state = CaptureLifecycle::default();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                let _ = state.begin();
            });
            barrier.wait();
            state.stop();
        });
        assert!(matches!(state.reported(), 0 | 3));
        assert!(!state.running());
        assert!(!state.idle());
        assert!(state.begin().is_err());
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) struct ClientRuntime {
    path: std::path::PathBuf,
    slot: tokio::sync::watch::Sender<Arc<ClientView>>,
    // Bound one staging operation per process, with no commit on cancellation.
    stage: tokio::sync::Mutex<()>,
    capture_state: CaptureLifecycle,
    stopped: tokio::sync::watch::Sender<bool>,
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
impl ClientRuntime {
    fn new(
        path: std::path::PathBuf,
        document: config::ClientDocument,
        digest: [u8; 32],
        client: ProxyClient,
    ) -> Arc<Self> {
        let (slot, _) = tokio::sync::watch::channel(Arc::new(ClientView {
            document,
            digest,
            revision: 1,
            client,
        }));
        let (stopped, _) = tokio::sync::watch::channel(false);
        Arc::new(Self {
            path,
            slot,
            stage: tokio::sync::Mutex::new(()),
            capture_state: CaptureLifecycle::default(),
            stopped,
        })
    }
    /// Pin exactly the published client generation for native capture.
    /// A structural or profile update needs explicit stop/recovery until
    /// carrier and rule changes can be committed in one platform transaction.
    async fn attach_native(
        self: &Arc<Self>,
        owner: Arc<NativeOwner>,
        registrar: Option<Arc<dyn crate::routing::carrier_socket::Registrar>>,
    ) -> Result<NativeIngress, ClientError> {
        let _stage = self
            .stage
            .try_lock()
            .map_err(|_| ClientError::Configuration)?;
        if *self.stopped.borrow() || !self.capture_state.idle() {
            return Err(ClientError::Configuration);
        }
        let view = self.slot.borrow().clone();
        saved_client_bytes(&self.path, view.digest)?;
        crate::routing::carrier_socket::scope(registrar.clone(), view.client.routing_policy())
            .await?;
        saved_client_bytes(&self.path, view.digest)?;
        if *self.stopped.borrow() {
            return Err(ClientError::Configuration);
        }
        self.capture_state.begin()?;
        Ok(NativeIngress {
            runtime: self.clone(),
            client: view.client.clone(),
            revision: view.revision,
            registrar: Mutex::new(registrar),
            verdict_gate: Mutex::new(()),
            #[cfg(target_os = "linux")]
            raw: Mutex::new(std::collections::HashMap::new()),
            #[cfg(target_os = "linux")]
            udp_consumer: std::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            tcp_consumer: std::sync::atomic::AtomicBool::new(false),
            _owner: owner,
        })
    }

    fn stop(&self) {
        // Capture rules may remain after the queue stops. Never publish
        // inactive/connected until the owner has finished recovery.
        self.capture_state.stop();
        self.stopped.send_replace(true);
        self.slot.borrow().client.routing_cache().dpi.retire();
    }

    async fn stopped(&self) {
        let mut stop = self.stopped.subscribe();
        if !*stop.borrow() {
            let _ = stop.wait_for(|stopped| *stopped).await;
        }
    }

    pub(crate) async fn status(
        &self,
    ) -> (
        u64,
        [u8; 32],
        u64,
        u8,
        u8,
        bool,
        (u64, u8),
        [u64; 38],
        Option<[u16; 4]>,
        u8,
    ) {
        let view = self.slot.borrow().clone();
        let (desc, observed, fallback) = match &view.client {
            ProxyClient::Reality(r) => {
                let g = r.current.lock().await.clone();
                let fallback = match &g.carrier {
                    Carrier::Auto(a) => a.negative.lock().ok().is_some_and(|c| {
                        c.route.is_some()
                            && c.route == crate::network_scope::observe(a.h3.remote())
                            && c.expires.is_some_and(|t| t > Instant::now())
                    }),
                    _ => false,
                };
                (
                    g.value.descriptor().revision,
                    g.last_open.load(std::sync::atomic::Ordering::Relaxed),
                    fallback,
                )
            }
            ProxyClient::Direct(d) => (
                0,
                d.last_open.load(std::sync::atomic::Ordering::Relaxed),
                d.fallback(),
            ),
        };
        (
            view.revision,
            view.digest,
            desc,
            observed >> 2,
            observed & 3,
            fallback,
            view.client.routing_cache().observation(),
            crate::traffic::routing_totals(),
            view.client.routing_cache().flows.counts(),
            self.capture_state.reported(),
        )
    }
    async fn candidate(
        &self,
        previous: &ClientView,
        digest: [u8; 32],
    ) -> Result<(config::ClientDocument, ProxyClient), ClientError> {
        let raw = saved_client_bytes(&self.path, digest)?;
        let Config::Client(candidate) =
            config::parse(std::str::from_utf8(&raw).map_err(|_| ClientError::Configuration)?)
                .map_err(|_| ClientError::Configuration)?
        else {
            return Err(ClientError::Configuration);
        };
        // Structural loopback and OS proxy changes require explicit stop/start.
        if candidate.client.proxy != previous.document.client.proxy
            || candidate.management != previous.document.management
        {
            return Err(ClientError::Configuration);
        }
        let old = previous
            .document
            .client
            .profiles
            .iter()
            .find(|p| p.id == previous.document.client.active_profile)
            .ok_or(ClientError::Configuration)?;
        let next = candidate
            .client
            .profiles
            .iter()
            .find(|p| p.id == candidate.client.active_profile)
            .ok_or(ClientError::Configuration)?;
        // No in-place replacement of any existing independently enrolled root.
        for prior in &previous.document.client.profiles {
            if let Some(new) = candidate.client.profiles.iter().find(|p| p.id == prior.id) {
                if prior.security_mode != new.security_mode
                    || (prior.reality_profile != new.reality_profile
                        && !crate::reality_config::credential_only_change(prior, new))
                {
                    return Err(ClientError::Configuration);
                }
            }
        }
        if old.security_mode != next.security_mode {
            return Err(ClientError::Configuration);
        }
        let client = if old.id == next.id {
            load_client_with_budget(next, previous.client.profile_budget(), Some(&self.path))
                .await?
        } else {
            load_client_with_budget(
                next,
                crate::connection_pool::profile_budget(),
                Some(&self.path),
            )
            .await?
        };
        client
            .routing_cache()
            .dpi
            .set_enabled(candidate.client.proxy.direct_dpi.unwrap_or(false));
        client
            .routing_cache()
            .dpi
            .set_stun_enabled(candidate.client.proxy.direct_dpi_stun.unwrap_or(false));
        Box::pin(client.routing_policy()).await?;
        saved_client_bytes(&self.path, digest)?;
        Ok((candidate, client))
    }
    pub(crate) async fn change(
        &self,
        expected: u64,
        digest: [u8; 32],
        apply: bool,
    ) -> Result<u64, ClientError> {
        let _stage = self
            .stage
            .try_lock()
            .map_err(|_| ClientError::Configuration)?;
        if *self.stopped.borrow() || !self.capture_state.idle() {
            return Err(ClientError::Configuration);
        }
        let previous = self.slot.borrow().clone();
        if previous.revision != expected || previous.digest == digest {
            return Err(ClientError::Configuration);
        }
        let (document, client) = self.candidate(&previous, digest).await?;
        if !apply {
            return Ok(expected);
        }
        let revision = expected.checked_add(1).ok_or(ClientError::Configuration)?;
        // No await between final exact-byte recheck and publication.
        saved_client_bytes(&self.path, digest)?;
        if *self.stopped.borrow() {
            return Err(ClientError::Configuration);
        }
        previous.client.routing_cache().dpi.retire();
        self.slot.send_replace(Arc::new(ClientView {
            document,
            digest,
            revision,
            client,
        }));
        Ok(revision)
    }
    async fn maintain(&self) -> Result<(), ClientError> {
        let mut changes = self.slot.subscribe();
        loop {
            let view = changes.borrow_and_update().clone();
            let maintenance = async { view.client.maintain().await };
            tokio::select! {
                biased;
                ()=self.stopped()=>return Ok(()),
                result=maintenance=>return result,
                result=changes.changed()=>if result.is_err(){return Err(ClientError::Io);},
            }
        }
    }
}

async fn run_file_inner(config_path: &Path, enable_system_proxy: bool) -> Result<(), ClientError> {
    crate::diag!(
        Info,
        "client.proxy",
        "config_read_begin",
        "system_proxy_requested" = Value::Flag(enable_system_proxy)
    );
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
    #[cfg(windows)]
    let http_bound = http.local_addr().map_err(|_| ClientError::Io)?;
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
    #[cfg(windows)]
    if enable_system_proxy {
        // A config declaration is insufficient by itself: this branch
        // requires the *additional CLI* --system-proxy --confirm.
        if document.client.proxy.system_proxy != config::SystemProxy::Manual {
            return Err(ClientError::SystemProxy);
        }
        let mut lease = crate::windows_system_proxy::OwnedProxy::apply(http_bound)
            .map_err(|_| ClientError::SystemProxy)?;
        // Ctrl+C is the normal scoped exit. A killed process cannot execute
        // destructors; persistent registry journal permits explicit recovery
        // on the next invocation, without overwriting a foreign proxy change.
        let result = tokio::select! {
            result = serving => result,
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|_| ClientError::SystemProxy)
            }
        };
        lease.restore().map_err(|_| ClientError::SystemProxy)?;
        return result;
    }
    #[cfg(not(windows))]
    if enable_system_proxy {
        return Err(ClientError::SystemProxy);
    }
    serving.await
}

/// Experimental native-ingress adapter for an already isolated platform
/// harness. It uses the same authenticated client, classifier, shared flow
/// table and H2/H3 carrier as explicit proxy ingress. It does NOT install
/// system rules, assert capture readiness, or provide an egress exemption.
/// A production backend must own those operations before calling it.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub struct NativeIngress {
    runtime: Arc<ClientRuntime>,
    client: ProxyClient,
    revision: u64,
    registrar: Mutex<Option<Arc<dyn crate::routing::carrier_socket::Registrar>>>,
    verdict_gate: Mutex<()>,
    #[cfg(target_os = "linux")]
    raw: Mutex<std::collections::HashMap<crate::routing::packet::FlowKey, RawLease>>,
    #[cfg(target_os = "linux")]
    udp_consumer: std::sync::atomic::AtomicBool,
    #[cfg(target_os = "linux")]
    tcp_consumer: std::sync::atomic::AtomicBool,
    _owner: Arc<NativeOwner>,
}

/// A single experimental packet strategy bound to a specific native flow.
/// The caller must prepare it before activating isolated queue rules.
/// It is not a DNS/application attribution credential.
#[cfg(target_os = "linux")]
pub struct LabStunPermit {
    key: crate::routing::packet::FlowKey,
    flow: crate::routing::flow::FlowLease,
    engine: Arc<crate::routing::dpi::Engine>,
    verified: crate::routing::dpi::VerifiedUdp,
    failed: bool,
}

#[cfg(target_os = "linux")]
struct RawLease {
    flow: crate::routing::flow::FlowLease,
    digest: [u8; 32],
    last: Instant,
    denied: bool,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
static NATIVE_OWNER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// Field destruction is ordered: release the kernel scope handle before
// allowing another owner in this process to try to acquire it.
#[cfg(any(target_os = "linux", target_os = "windows"))]
struct ProcessOwner;

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Drop for ProcessOwner {
    fn drop(&mut self) {
        NATIVE_OWNER.store(false, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
struct NativeOwner {
    #[cfg(target_os = "linux")]
    _scope: std::os::unix::net::UnixDatagram,
    #[cfg(target_os = "windows")]
    _scope: std::os::windows::io::OwnedHandle,
    _process: ProcessOwner,
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
impl NativeOwner {
    fn acquire() -> Result<Self, ClientError> {
        NATIVE_OWNER
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map_err(|_| ClientError::Configuration)?;
        match Self::scope() {
            Ok(owner) => Ok(owner),
            Err(error) => {
                NATIVE_OWNER.store(false, std::sync::atomic::Ordering::Release);
                Err(error)
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn scope() -> Result<Self, ClientError> {
        use std::os::linux::net::SocketAddrExt;
        // Abstract Unix socket names are scoped to the network namespace.
        // Kernel closes the ownership handle on crash; no stale PID file.
        let address =
            std::os::unix::net::SocketAddr::from_abstract_name(b"theia-native-ingress-v1")
                .map_err(|_| ClientError::Configuration)?;
        let socket = std::os::unix::net::UnixDatagram::bind_addr(&address)
            .map_err(|_| ClientError::Configuration)?;
        Ok(Self { _scope: socket, _process: ProcessOwner })
    }

    #[cfg(target_os = "windows")]
    fn scope() -> Result<Self, ClientError> {
        use std::{
            os::windows::io::{FromRawHandle, OwnedHandle},
            ptr,
        };
        use windows_sys::Win32::{
            Foundation::{GetLastError, ERROR_ALREADY_EXISTS},
            System::Threading::CreateEventW,
        };
        // An event is a lifetime handle, not a thread-affine mutex. We
        // reject an existing object instead of sharing or stealing it.
        let name: Vec<u16> = "Global\\Theia.NativeIngress.v1"
            .encode_utf16()
            .chain([0])
            .collect();
        let raw = unsafe { CreateEventW(ptr::null(), 1, 0, name.as_ptr()) };
        if raw.is_null() {
            return Err(ClientError::Configuration);
        }
        let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        // SAFETY: CreateEventW returned one owned non-null kernel handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        if existed {
            return Err(ClientError::Configuration);
        }
        Ok(Self { _scope: handle, _process: ProcessOwner })
    }
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
impl NativeIngress {
    /// Preflight only; the caller owns an isolated network namespace/rule
    /// transaction. No new CLI or second system interception mode.
    pub async fn prepare(path: &Path) -> Result<Self, ClientError> {
        let owner = Arc::new(NativeOwner::acquire()?);
        let raw = zeroize::Zeroizing::new(
            config::editor_bytes(path).map_err(|_| ClientError::Configuration)?,
        );
        let Config::Client(document) =
            config::parse(std::str::from_utf8(&raw).map_err(|_| ClientError::Configuration)?)
                .map_err(|_| ClientError::Configuration)?
        else {
            return Err(ClientError::Configuration);
        };
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(raw.as_slice()).into();
        let client = prepare_client(&document, path).await?;
        saved_client_bytes(path, digest)?;
        let runtime = ClientRuntime::new(
            std::path::absolute(path).map_err(|_| ClientError::Configuration)?,
            document,
            digest,
            client,
        );
        runtime.attach_native(owner, None).await
    }

    /// Cancels all native relay operations, retires the policy lease and
    /// leaves the externally owned OS capture rules untouched. The platform
    /// owner must perform its own authenticated CAS restoration on explicit Stop.
    pub fn shutdown(&self) {
        let _gate = self.verdict_gate.lock();
        self.runtime.stop();
        self.client.routing_cache().dpi.retire();
        if let Ok(mut registrar) = self.registrar.lock() {
            drop(registrar.take());
        }
        #[cfg(target_os = "linux")]
        if let Ok(mut raw) = self.raw.lock() {
            raw.clear();
        }
    }

    async fn stopped(&self) {
        self.runtime.stopped().await;
    }

    fn registrar(
        &self,
    ) -> Result<Option<Arc<dyn crate::routing::carrier_socket::Registrar>>, ClientError> {
        self.registrar
            .lock()
            .map(|r| r.clone())
            .map_err(|_| ClientError::Configuration)
    }

    fn ensure_running(&self) -> Result<(), ClientError> {
        if !self.runtime.capture_state.running()
            || *self.runtime.stopped.borrow()
            || self.runtime.slot.borrow().revision != self.revision
        {
            Err(ClientError::Open(ErrorCode::PolicyDenied))
        } else {
            Ok(())
        }
    }

    fn ensure_accepting(&self) -> Result<(), ClientError> {
        self.ensure_running()?;
        if !self.runtime.capture_state.accepting() {
            return Err(ClientError::Open(ErrorCode::PolicyDenied));
        }
        Ok(())
    }

    /// Own the actual queue consumer and the current runtime's maintenance
    /// for the entire isolated capture lifetime. No production activation:
    /// rules and queue must have been provisioned in the same namespace.
    /// Cancellation or any fatal error retires the runtime and closes the
    /// queue; the journal remains for explicit CAS recovery.
    #[cfg(target_os = "linux")]
    pub async fn serve_linux_queue(
        &self,
        queue: crate::routing::nfqueue::Queue,
        rules: crate::routing::linux_rules::LabRules,
        host_namespace: std::fs::File,
    ) -> Result<(), ClientError> {
        self.ensure_running()?;
        if !rules.owns_queue(&queue).map_err(|_| ClientError::Io)? {
            return Err(ClientError::Configuration);
        }
        let rules = Arc::new(Mutex::new(rules));
        let registrar: Arc<dyn crate::routing::carrier_socket::Registrar> = Arc::new(
            crate::routing::linux_rules::LabRegistrar::new(rules.clone(), host_namespace),
        );
        {
            let mut slot = self
                .registrar
                .lock()
                .map_err(|_| ClientError::Configuration)?;
            if slot.is_some() {
                return Err(ClientError::Configuration);
            }
            *slot = Some(registrar.clone());
        }
        self.serve_linux_shared(queue, rules, registrar).await
    }

    #[cfg(target_os = "linux")]
    async fn serve_linux_shared(
        &self,
        queue: crate::routing::nfqueue::Queue,
        rules: Arc<Mutex<crate::routing::linux_rules::LabRules>>,
        registrar: Arc<dyn crate::routing::carrier_socket::Registrar>,
    ) -> Result<(), ClientError> {
        struct StopOnDrop<'a>(&'a NativeIngress);
        impl Drop for StopOnDrop<'_> {
            fn drop(&mut self) {
                self.0.shutdown();
            }
        }
        let _stop = StopOnDrop(self);
        self.ensure_running()?;
        if !rules
            .lock()
            .map_err(|_| ClientError::Configuration)?
            .owns_queue(&queue)
            .map_err(|_| ClientError::Io)?
        {
            return Err(ClientError::Configuration);
        }
        let mut queue = queue.into_async().map_err(|_| ClientError::Io)?;
        self.runtime.capture_state.ready()?;
        let consume = async {
            let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let packet = tokio::select! {
                    biased;
                    _ = heartbeat.tick() => {
                        if !rules.lock().map_err(|_| ClientError::Configuration)?.current().map_err(|_| ClientError::Io)? {
                            return Err(ClientError::Open(ErrorCode::PolicyDenied));
                        }
                        continue;
                    }
                    packet=queue.next()=>packet.map_err(|_| ClientError::Io)?,
                };
                if !rules
                    .lock()
                    .map_err(|_| ClientError::Configuration)?
                    .owns_packet(&packet)
                    .map_err(|_| ClientError::Io)?
                {
                    return Err(ClientError::Open(ErrorCode::PolicyDenied));
                }
                self.verdict(&rules, packet)
                    .await
                    .map_err(|_| ClientError::Io)?;
            }
        };
        tokio::select! {
            biased;
            result=crate::routing::carrier_socket::scope(Some(registrar.clone()), consume)=>result,
            result=crate::routing::carrier_socket::scope(Some(registrar), self.runtime.maintain())=>result,
            ()=self.stopped()=>Ok(()),
        }
    }

    /// End-to-end managed startup for a dedicated Linux laboratory
    /// namespace. This is intentionally not exposed as the product's
    /// Connect action: transparent Redirect and attribution are incomplete.
    /// No preflight carrier is opened before the registrar is in scope.
    /// A failed or cancelled run leaves the fail-closed table and durable
    /// journal intact. Only an explicit successful Stop may restore rules.
    #[cfg(target_os = "linux")]
    pub async fn run_linux_lab(
        path: &Path,
        host_namespace: std::fs::File,
        journal: &Path,
        queue_number: u16,
        stop: impl std::future::Future<Output = std::io::Result<()>>,
    ) -> Result<(), ClientError> {
        use crate::routing::{
            carrier_socket,
            linux_rules::{self, LabRegistrar, LabRules},
            nfqueue::Queue,
        };
        use sha2::{Digest, Sha256};
        // Namespace ownership must not move between executor threads.
        if tokio::runtime::Handle::current().runtime_flavor()
            != tokio::runtime::RuntimeFlavor::CurrentThread
        {
            return Err(ClientError::Configuration);
        }
        let owner = Arc::new(NativeOwner::acquire()?);
        let path = std::path::absolute(path).map_err(|_| ClientError::Configuration)?;
        let raw = zeroize::Zeroizing::new(
            config::editor_bytes(&path).map_err(|_| ClientError::Configuration)?,
        );
        let Config::Client(document) =
            config::parse(std::str::from_utf8(&raw).map_err(|_| ClientError::Configuration)?)
                .map_err(|_| ClientError::Configuration)?
        else {
            return Err(ClientError::Configuration);
        };
        let digest: [u8; 32] = Sha256::digest(raw.as_slice()).into();
        saved_client_bytes(&path, digest)?;
        let queue = Queue::bind(queue_number, 256).map_err(|_| ClientError::Io)?;
        let rules = Arc::new(Mutex::new(
            LabRules::install(&queue, &host_namespace, journal).map_err(|_| ClientError::Io)?,
        ));
        let registrar: Arc<dyn carrier_socket::Registrar> = Arc::new(LabRegistrar::new(
            rules.clone(),
            host_namespace.try_clone().map_err(|_| ClientError::Io)?,
        ));
        let client =
            carrier_socket::scope(Some(registrar.clone()), prepare_client(&document, &path))
                .await?;
        saved_client_bytes(&path, digest)?;
        let runtime = ClientRuntime::new(path, document, digest, client);
        // Keep the process/namespace owner alive across the entire explicit
        // recovery transaction, not just across the packet consumer.
        let ingress = runtime
            .attach_native(owner.clone(), Some(registrar.clone()))
            .await?;
        let control = crate::management::client_server(runtime.clone())
            .map_err(|_| ClientError::Configuration)?;
        let management = async move {
            match control {
                Some(server) => server.serve().await.map_err(|_| ClientError::Io),
                None => std::future::pending::<Result<(), ClientError>>().await,
            }
        };
        let explicit = tokio::select! {
            biased;
            result=ingress.serve_linux_shared(queue,rules.clone(),registrar.clone())=>{
                result?;
                Err(ClientError::Io) // unexpected consumer exit, never auto restore
            },
            result=management=>{ result?; Err(ClientError::Io) },
            // When a failure and explicit stop are already ready together,
            // do not reinterpret a failed consumer as a clean shutdown.
            result=stop=>result.map_err(|_| ClientError::Io),
        };
        ingress.shutdown();
        drop(ingress);
        drop(runtime);
        drop(registrar);
        explicit?;
        // Connection drivers may release their socket leases asynchronously
        // after abort. Never restore while a live carrier retains our rules.
        timeout(Duration::from_secs(3), async {
            while Arc::strong_count(&rules) != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)?;
        drop(rules);
        let recovered = linux_rules::recover(&host_namespace, journal).map_err(|_| ClientError::Io);
        drop(owner);
        recovered
    }

    /// Managed Windows TCP Redirect laboratory. Requires a disposable
    /// non-default compartment, signed installed driver and already-owned
    /// BFE filters, provisioned outside this process. No production Connect,
    /// user UDP or auto recovery is enabled by this entry point.
    #[cfg(target_os = "windows")]
    pub async fn run_windows_lab(
        path: &Path,
        compartment: u32,
        port: u16,
        controller: &Path,
        controller_sha256: [u8; 32],
        stop: impl std::future::Future<Output = std::io::Result<()>>,
    ) -> Result<(), ClientError> {
        use crate::routing::{
            carrier_socket,
            wfp_ingress::{bind_tcp_listeners, BfeInspector, WfpLabSession},
        };
        use sha2::{Digest, Sha256};
        if tokio::runtime::Handle::current().runtime_flavor()
            != tokio::runtime::RuntimeFlavor::CurrentThread
        {
            return Err(ClientError::Configuration);
        }
        let owner = Arc::new(NativeOwner::acquire()?);
        let path = std::path::absolute(path).map_err(|_| ClientError::Configuration)?;
        let raw = zeroize::Zeroizing::new(
            config::editor_bytes(&path).map_err(|_| ClientError::Configuration)?,
        );
        let Config::Client(document) =
            config::parse(std::str::from_utf8(&raw).map_err(|_| ClientError::Configuration)?)
                .map_err(|_| ClientError::Configuration)?
        else {
            return Err(ClientError::Configuration);
        };
        let digest: [u8; 32] = Sha256::digest(raw.as_slice()).into();
        saved_client_bytes(&path, digest)?;
        let proof = Arc::new(
            BfeInspector::open(controller, controller_sha256, compartment)
                .map_err(|_| ClientError::Configuration)?,
        );
        proof
            .inspect()
            .await
            .map_err(|_| ClientError::Configuration)?;
        let [v4, v6] = bind_tcp_listeners(compartment, port).map_err(|_| ClientError::Io)?;
        let session =
            Arc::new(WfpLabSession::open(compartment, port).map_err(|_| ClientError::Io)?);
        // Even if preflight or the owning future is cancelled, retire the
        // kernel session before releasing listeners. Persistent filters stay.
        struct StopDriver(Arc<WfpLabSession>);
        impl Drop for StopDriver {
            fn drop(&mut self) {
                let _ = self.0.deactivate();
            }
        }
        let _stop_driver = StopDriver(session.clone());
        let registrar: Arc<dyn carrier_socket::Registrar> = session.clone();
        let client =
            carrier_socket::scope(Some(registrar.clone()), prepare_client(&document, &path))
                .await?;
        saved_client_bytes(&path, digest)?;
        let runtime = ClientRuntime::new(path, document, digest, client);
        let ingress = Arc::new(
            runtime
                .attach_native(owner.clone(), Some(registrar.clone()))
                .await?,
        );
        let control = crate::management::client_server(runtime.clone())
            .map_err(|_| ClientError::Configuration)?;
        let management = async move {
            match control {
                Some(server) => server.serve().await.map_err(|_| ClientError::Io),
                None => std::future::pending::<Result<(), ClientError>>().await,
            }
        };
        proof
            .inspect()
            .await
            .map_err(|_| ClientError::Configuration)?;
        session.check().map_err(|_| ClientError::Io)?;
        ingress.runtime.capture_state.ready()?;
        let mut relays = JoinSet::new();
        let result = {
            let consume = async {
                let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
                heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    let stream = tokio::select! {
                        biased;
                        _ = heartbeat.tick() => {
                            session.check().map_err(|_| ClientError::Io)?;
                            proof.inspect().await.map_err(|_| ClientError::Io)?;
                            session.check().map_err(|_| ClientError::Io)?;
                            continue;
                        }
                        finished = relays.join_next(), if !relays.is_empty() => {
                            // Individual denial/transport failure closes that
                            // flow; a panicked relay is a supervisor failure.
                            if finished.is_some_and(|r| r.is_err()) { return Err(ClientError::Io); }
                            continue;
                        }
                        result = v4.accept() => result.map_err(|_| ClientError::Io)?.0,
                        result = v6.accept() => result.map_err(|_| ClientError::Io)?.0,
                    };
                    session.check().map_err(|_| ClientError::Io)?;
                    if relays.len() >= LOCAL_LIMIT {
                        drop(stream);
                        continue;
                    }
                    let ingress = ingress.clone();
                    let session = session.clone();
                    // The current-thread runtime keeps these socket operations
                    // in the verified compartment; no detached worker owns a
                    // listener or receives a process-wide exemption.
                    relays.spawn(async move { ingress.relay_windows_tcp(stream, session).await });
                }
            };
            tokio::select! {
                biased;
                result = consume => result,
                result = carrier_socket::scope(Some(registrar.clone()),runtime.maintain()) => {
                    result?;
                    Err(ClientError::Io)
                },
                result = management => { result?; Err(ClientError::Io) },
                result = stop => result.map_err(|_| ClientError::Io),
            }
        };
        let retired = session.deactivate();
        ingress.shutdown();
        relays.shutdown().await;
        drop(v4);
        drop(v6);
        drop(ingress);
        drop(runtime);
        drop(registrar);
        result?;
        retired.map_err(|_| ClientError::Io)?;
        // A successful explicit stop proves driver retirement, not BFE
        // restoration. Require the persistent filters to still be exact;
        // the administrator must unload/recover them using signed tooling.
        proof.inspect().await.map_err(|_| ClientError::Io)?;
        drop(owner);
        Ok(())
    }

    /// Correlate an actual private collector/queue observation with
    /// authenticated DNS, rechecking it before publication. The resolver
    /// link is still a claimed link, not trusted evidence of the original
    /// application request. No native route is authorized by this API.
    #[cfg(all(target_os = "linux", feature = "linux-ebpf-lab"))]
    pub async fn corroborate_dns_captured_lab(
        &self,
        observation: &crate::routing::linux_bpf_loader::CapturedObservation<'_, '_>,
        link: &crate::routing::dns_attribution::ResolverLink,
        candidates: &mut crate::routing::dns_attribution::DnsCandidates,
    ) -> Result<bool, ClientError> {
        self.ensure_accepting()?;
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        let flow = observation.flow();
        if observation.revalidate().is_err() {
            candidates.invalidate(flow);
            return Err(denied());
        }
        // Never allow an older, already published candidate to survive
        // a failed attempt to revalidate its source.
        let result = self.corroborate_dns_inner(flow, link, candidates, || {
            self.ensure_accepting()?;
            observation.revalidate().map_err(|_| denied())?;
            Ok(())
        }).await;
        if !matches!(&result, Ok(true)) {
            candidates.invalidate(flow);
        }
        result
    }

    /// Correlate a laboratory resolver link with protected DNS from the
    /// exact active policy generation. This does not grant routing
    /// authorization: neither the BPF reader nor resolver event source
    /// has yet been integrated into the production native backend.
    #[cfg(target_os = "linux")]
    pub async fn corroborate_dns_lab(
        &self,
        flow: crate::routing::linux_events::CorroboratedFlow,
        link: &crate::routing::dns_attribution::ResolverLink,
        candidates: &mut crate::routing::dns_attribution::DnsCandidates,
    ) -> Result<bool, ClientError> {
        self.corroborate_dns_inner(flow, link, candidates, || Ok(())).await
    }

    #[cfg(target_os = "linux")]
    async fn corroborate_dns_inner(
        &self,
        flow: crate::routing::linux_events::CorroboratedFlow,
        link: &crate::routing::dns_attribution::ResolverLink,
        candidates: &mut crate::routing::dns_attribution::DnsCandidates,
        validate_source: impl FnOnce() -> Result<(), ClientError>,
    ) -> Result<bool, ClientError> {
        self.ensure_running()?;
        if flow.key() != link.key
            || flow.cookie() != link.cookie
            || flow.process_start() != link.process_start
        {
            return Ok(false);
        }
        let registrar = self
            .registrar()?
            .ok_or(ClientError::Open(ErrorCode::PolicyDenied))?;
        crate::routing::carrier_socket::scope(Some(registrar), async {
            let (carrier, cache) = match &self.client {
                ProxyClient::Direct(c) => (c.carrier.clone(), &c.routing),
                ProxyClient::Reality(c) => (c.generation().await?.carrier.clone(), &c.routing),
            };
            let snapshot = cache.get(|known| carrier.fetch_routing(known)).await?;
            let digest = snapshot.digest();
            let name =
                crate::routing::domain_name(&link.domain).map_err(|_| ClientError::Protocol)?;
            // The current wire response contains addresses, not authoritative
            // DNS TTLs. Bound this diagnostic to the original policy lease and
            // a short window beginning BEFORE the authenticated request.
            let original_deadline = cache.observation_deadline(digest)?;
            let requested = Instant::now();
            let ips = carrier.resolve_routing(&name, digest).await?;
            let deadline = original_deadline
                .min(cache.observation_deadline(digest)?)
                .min(requested + Duration::from_secs(30));
            self.ensure_running()?;
            validate_source()?;
            cache.dpi.check_policy(digest)?;
            candidates
                .record(flow, link, digest, &ips, deadline)
                .map_err(|_| ClientError::Protocol)
        })
        .await
    }

    /// Prepare a narrowly scoped laboratory Modify permit. The route must
    /// be conclusive even with unknown application/domain evidence; the
    /// supplied name is only an authenticated DNS/reachability probe hint,
    /// never evidence of which name the application actually requested.
    /// No probe is run on the captured application socket or packet.
    #[cfg(target_os = "linux")]
    pub async fn prepare_stun_lab(
        &self,
        key: crate::routing::packet::FlowKey,
        domain: &str,
    ) -> Result<LabStunPermit, ClientError> {
        use crate::routing::{
            dpi::{udp::BindingStrategy, UdpStrategy},
            packet::Transport,
            Evidence, PacketAction,
        };
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        self.ensure_running()?;
        if key.transport != Transport::Udp
            || key.destination.port() != 3478
            || key.source.port() == 0
            || key.source.is_ipv4() != key.destination.is_ipv4()
            || !crate::server::allowed_destination(key.destination.ip(), false)
        {
            return Err(denied());
        }
        let (carrier, cache) = match &self.client {
            ProxyClient::Direct(c) => (c.carrier.clone(), &c.routing),
            ProxyClient::Reality(c) => (c.generation().await?.carrier.clone(), &c.routing),
        };
        let snapshot = cache.get(|known| carrier.fetch_routing(known)).await?;
        let digest = snapshot.digest();
        let name = crate::routing::domain_name(domain).map_err(|_| denied())?;
        let policy = snapshot.policy();
        for evidence in [Evidence::Unknown, Evidence::Known(name.as_str())] {
            if policy
                .classify_with_application(
                    evidence,
                    Evidence::Known(key.destination.ip()),
                    Evidence::Unknown,
                )
                .map_err(|_| denied())?
                .action()
                != Some(Action::DirectDpi)
            {
                return Err(denied());
            }
        }
        if !cache.dpi.stun_enabled() {
            return Err(denied());
        }
        let ips = carrier.resolve_routing(&name, digest).await?;
        if !ips.contains(&key.destination.ip()) {
            return Err(denied());
        }
        let verified = cache
            .dpi
            .open_stun_udp(&name, 3478, &[key.destination.ip()], digest)
            .await
            .ok_or_else(denied)?;
        if verified.strategy != UdpStrategy::StunBinding(BindingStrategy::Fingerprint)
            || verified.socket.peer_addr().ok() != Some(key.destination)
            || !verified
                .socket
                .local_addr()
                .is_ok_and(|a| a.ip() == key.source.ip())
            || !verified.admissible()?
        {
            return Err(denied());
        }
        self.ensure_running()?;
        let flow =
            cache
                .flows
                .begin_native(cache.dpi.clone(), key, digest, PacketAction::Modify)?;
        Ok(LabStunPermit {
            key,
            flow,
            engine: cache.dpi.clone(),
            verified,
            failed: false,
        })
    }

    /// The actual NFQUEUE replacement is available only under an owned
    /// isolated lab rules lease. Unsupported packets, stale evidence,
    /// shutdown and all mismatches are terminal for this permit.
    #[cfg(target_os = "linux")]
    pub fn verdict_stun_lab(
        &self,
        rules: &crate::routing::linux_rules::LabRules,
        permit: &mut LabStunPermit,
        packet: crate::routing::nfqueue::Packet<'_>,
    ) -> std::io::Result<crate::routing::PacketAction> {
        use crate::routing::PacketAction;
        let gate = self.verdict_gate.lock();
        let acceptable = gate.is_ok()
            && !permit.failed
            && self.ensure_accepting().is_ok()
            && Arc::ptr_eq(&permit.engine, &self.client.routing_cache().dpi)
            && packet.local_output()
            && !packet.checksum_pending()
            && packet
                .metadata()
                .is_some_and(|meta| meta.flow == permit.key)
            && rules.owns_packet(&packet).unwrap_or(false)
            && permit.verified.admissible().unwrap_or(false);
        if acceptable {
            if let Some(changed) = crate::routing::packet_modify::stun_fingerprint(packet.bytes()) {
                // Commit before the kernel verdict, never retry another egress.
                if permit.flow.commit(PacketAction::Modify).is_ok() {
                    let result = packet.finish_stun_lab(&changed);
                    if !matches!(&result, Ok(PacketAction::Modify)) {
                        permit.failed = true;
                    }
                    return result;
                }
            }
        }
        permit.failed = true;
        packet.finish(PacketAction::Drop)
    }

    /// Deliver only a conclusive early Pass to NFQUEUE. Unknown domain/app,
    /// Modify, Redirect and all errors fail closed on raw packet ingress.
    /// No raw TCP connection is moved to the carrier after its SYN.
    #[cfg(target_os = "linux")]
    pub async fn verdict(
        &self,
        rules: &Mutex<crate::routing::linux_rules::LabRules>,
        packet: crate::routing::nfqueue::Packet<'_>,
    ) -> std::io::Result<crate::routing::PacketAction> {
        use crate::routing::PacketAction;
        // Check before doing any async policy work; a standalone queue
        // without the exact owned rule set must not authorize native Pass.
        if !rules
            .lock()
            .map_err(|_| std::io::ErrorKind::PermissionDenied)?
            .owns_packet(&packet)?
        {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let meta = packet.metadata();
        let action = if packet.local_output() {
            match meta {
                Some(meta) => self.raw_verdict(meta).await,
                None => PacketAction::Drop,
            }
        } else {
            PacketAction::Drop
        };
        let gate = self.verdict_gate.lock();
        // Recheck AFTER the asynchronous policy fetch. Hold the rule mutex
        // through the actual verdict so our own dynamic lease transaction
        // cannot race this check. A foreign change is a terminal error.
        let owned = rules
            .lock()
            .map_err(|_| std::io::ErrorKind::PermissionDenied)?;
        if !owned.owns_packet(&packet)? {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let mut action = if gate.is_ok() && self.ensure_accepting().is_ok() {
            action
        } else {
            PacketAction::Drop
        };
        if action == PacketAction::Pass {
            let current = meta
                .and_then(|m| {
                    let key = crate::routing::packet::FlowKey {
                        interface: 0,
                        ..m.flow
                    };
                    let mut raw = self.raw.lock().ok()?;
                    let entry = raw.get_mut(&key)?;
                    if self
                        .client
                        .routing_cache()
                        .dpi
                        .check_policy(entry.digest)
                        .is_err()
                    {
                        entry.denied = true;
                    }
                    Some(!entry.denied)
                })
                .unwrap_or(false);
            if !current {
                action = PacketAction::Drop;
            }
        }
        let result = packet.finish(action);
        drop(owned);
        result
    }

    #[cfg(target_os = "linux")]
    async fn raw_verdict(
        &self,
        mut meta: crate::routing::packet::PacketMeta,
    ) -> crate::routing::PacketAction {
        use crate::routing::{packet::Transport, Evidence, PacketAction};
        meta.flow.interface = 0;
        if [meta.flow.source.ip(), meta.flow.destination.ip()].iter().any(|ip| ip.is_unspecified() || ip.is_multicast() || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local() || v6.to_ipv4_mapped().is_some())) {
            return PacketAction::Drop;
        }
        if self.ensure_accepting().is_err() {
            return PacketAction::Drop;
        }
        let snapshot = match timeout(Duration::from_millis(250), self.client.routing_policy()).await
        {
            Ok(Ok(snapshot)) => snapshot,
            _ => {
                if let Ok(mut raw) = self.raw.lock() {
                    if let Some(entry) = raw.get_mut(&meta.flow) {
                        entry.denied = true;
                        entry.last = Instant::now();
                    }
                }
                return PacketAction::Drop;
            }
        };
        let cache = self.client.routing_cache();
        let digest = snapshot.digest();
        let matched = meta
            .classify(snapshot.policy(), Evidence::Unknown, Evidence::Unknown)
            .ok()
            .and_then(|c| c.action())
            .map(Action::packet_action);
        let Ok(mut raw) = self.raw.lock() else {
            return PacketAction::Drop;
        };
        if self.ensure_accepting().is_err() {
            return PacketAction::Drop;
        }
        let now = Instant::now();
        raw.retain(|_, entry| now.duration_since(entry.last) < Duration::from_secs(60));
        let current = matched == Some(PacketAction::Pass) && cache.dpi.check_policy(digest).is_ok();
        if let Some(entry) = raw.get_mut(&meta.flow) {
            entry.last = now;
            if !current || entry.digest != digest {
                entry.denied = true;
            }
            return if !entry.denied && entry.flow.commit(PacketAction::Pass).is_ok() {
                PacketAction::Pass
            } else {
                PacketAction::Drop
            };
        }
        // TCP must start from a SYN without ACK/RST/FIN. A lost or expired
        // flow is never silently recreated from a middle-of-stream packet.
        if !current
            || (meta.flow.transport == Transport::Tcp
                && !meta.tcp_flags.is_some_and(|f| f & 0x17 == 0x02))
        {
            return PacketAction::Drop;
        }
        let Ok(flow) =
            cache
                .flows
                .begin_native(cache.dpi.clone(), meta.flow, digest, PacketAction::Pass)
        else {
            return PacketAction::Drop;
        };
        if flow.commit(PacketAction::Pass).is_err() {
            return PacketAction::Drop;
        }
        raw.insert(
            meta.flow,
            RawLease {
                flow,
                digest,
                last: now,
                denied: false,
            },
        );
        PacketAction::Pass
    }

    /// Terminate an already redirected TCP connection using the original
    /// target from conntrack. Native domain/application are Unknown.
    /// Only carrier Redirect (or legal pre-payload Modify fallback) is
    /// supported here: local Pass must use a separate proven egress path.
    #[cfg(target_os = "linux")]
    pub async fn relay_linux_tcp(&self, stream: TcpStream) -> Result<(), ClientError> {
        self.ensure_accepting()?;
        if self.registrar()?.is_none() {
            return Err(ClientError::Open(ErrorCode::PolicyDenied));
        }
        let key = crate::routing::linux_ingress::original_tcp(&stream)
            .map_err(|_| ClientError::Open(ErrorCode::PolicyDenied))?;
        self.relay_terminated_tcp(key, stream).await
    }

    /// WFP companion driver must supply the original target in a context
    /// bound to the current private driver/service session. This entry
    /// point does not install callouts or trust a client-supplied header.
    #[cfg(target_os = "windows")]
    pub async fn relay_windows_tcp(
        &self,
        stream: TcpStream,
        session: Arc<crate::routing::wfp_ingress::WfpLabSession>,
    ) -> Result<(), ClientError> {
        self.ensure_accepting()?;
        let expected = self
            .registrar()?
            .ok_or(ClientError::Open(ErrorCode::PolicyDenied))?;
        let registrar: Arc<dyn crate::routing::carrier_socket::Registrar> = session.clone();
        if !Arc::ptr_eq(&expected, &registrar) {
            return Err(ClientError::Open(ErrorCode::PolicyDenied));
        }
        let key = session
            .original_tcp(&stream)
            .map_err(|_| ClientError::Open(ErrorCode::PolicyDenied))?;
        crate::routing::carrier_socket::scope(
            Some(registrar),
            self.relay_terminated_tcp(key, stream),
        )
        .await
    }

    async fn relay_terminated_tcp(
        &self,
        key: crate::routing::packet::FlowKey,
        stream: TcpStream,
    ) -> Result<(), ClientError> {
        if key.transport != crate::routing::packet::Transport::Tcp {
            return Err(ClientError::Protocol);
        }
        tokio::select! {
            biased;
            () = self.stopped() => Err(ClientError::Open(ErrorCode::PolicyDenied)),
            result = async {
                let (carrier, flow, address) = self.redirect(key).await?;
                let tunnel = crate::routing::carrier_socket::scope(self.registrar()?, carrier.open(address, key.destination.port())).await?;
                tunnel.relay_guarded(stream, Some(&flow)).await
            } => result,
        }
    }

    /// Serve both TCP and UDP terminated adapters with the same native
    /// runtime/flow table. This is only usable after the existing owned
    /// queue is ready and the caller has provisioned compatible TPROXY,
    /// reverse-path and policy-routing rules in the isolated namespace.
    /// No production ready state or system rule activation is implied.
    #[cfg(target_os = "linux")]
    pub async fn serve_linux_redirect_capture(
        self: &Arc<Self>,
        listeners: crate::routing::linux_ingress::RedirectListeners,
    ) -> Result<(), ClientError> {
        self.ensure_accepting()?;
        let crate::routing::linux_ingress::RedirectListeners { tcp4, tcp6, udp4, udp6, .. } = listeners;
        tokio::try_join!(
            self.serve_linux_tcp_capture(tcp4, tcp6),
            self.serve_linux_udp_capture(udp4, udp6),
        ).map(|_| ())
    }

    #[cfg(target_os = "linux")]
    async fn serve_linux_tcp_capture(
        self: &Arc<Self>,
        v4: TcpListener,
        v6: TcpListener,
    ) -> Result<(), ClientError> {
        use std::sync::atomic::Ordering;
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        self.ensure_accepting()?;
        let a = v4.local_addr().map_err(|_| ClientError::Io)?;
        let b = v6.local_addr().map_err(|_| ClientError::Io)?;
        if !a.is_ipv4() || !b.is_ipv6() || a.port() == 0 || a.port() != b.port()
            || self.registrar()?.is_none()
            || self.tcp_consumer.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            return Err(denied());
        }
        struct StopOnDrop<'a>(&'a NativeIngress);
        impl Drop for StopOnDrop<'_> {
            fn drop(&mut self) {
                self.0.shutdown();
            }
        }
        let _stop = StopOnDrop(self);
        let mut tasks = JoinSet::new();
        let result = loop {
            if self.ensure_accepting().is_err() {
                break Err(denied());
            }
            let accepted = tokio::select! {
                () = self.stopped() => break Ok(()),
                finished = tasks.join_next(), if !tasks.is_empty() => {
                    if finished.is_some_and(|result| result.is_err()) {
                        break Err(ClientError::Io);
                    }
                    continue;
                }
                accepted = crate::routing::linux_ingress::accept_transparent(&v4) => accepted,
                accepted = crate::routing::linux_ingress::accept_transparent(&v6) => accepted,
            };
            let captured = match accepted {
                Ok(captured) => captured,
                Err(error) if matches!(error.kind(), std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidData) => continue,
                Err(_) => break Err(ClientError::Io),
            };
            if tasks.len() >= LOCAL_LIMIT {
                drop(captured);
                continue;
            }
            let ingress = self.clone();
            tasks.spawn(async move {
                // A failed per-flow authorization closes only its stream.
                // All forwarding still uses the shared native policy lease.
                let _ = ingress.relay_terminated_tcp(captured.key, captured.stream).await;
            });
        };
        self.shutdown();
        tasks.shutdown().await;
        result
    }

    /// Supervise both transparent UDP listeners under the already ready
    /// isolated native owner. The caller must provision the kernel redirect
    /// and reverse path rules; this cannot create or publish capture itself.
    /// No tuple can be recycled while its former relay still owns replies.
    #[cfg(target_os = "linux")]
    pub async fn serve_linux_udp_capture(
        self: &Arc<Self>,
        v4: crate::routing::linux_ingress::UdpCapture,
        v6: crate::routing::linux_ingress::UdpCapture,
    ) -> Result<(), ClientError> {
        use std::sync::atomic::Ordering;
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        self.ensure_accepting()?;
        let a = v4.local_addr().map_err(|_| ClientError::Io)?;
        let b = v6.local_addr().map_err(|_| ClientError::Io)?;
        if !a.is_ipv4() || !b.is_ipv6() || a.port() == 0 || a.port() != b.port()
            || self.registrar()?.is_none()
            || self.udp_consumer.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            return Err(denied());
        }
        // A listener failure or cancellation retires the entire native
        // runtime, not merely one address family. Never silently degrade.
        struct StopOnDrop<'a>(&'a NativeIngress);
        impl Drop for StopOnDrop<'_> {
            fn drop(&mut self) {
                self.0.shutdown();
            }
        }
        let _stop = StopOnDrop(self);
        let mut flows = NativeUdpDispatch::default();
        let mut tasks = JoinSet::new();
        let result = loop {
            if self.ensure_accepting().is_err() {
                break Err(denied());
            }
            let packet = tokio::select! {
                () = self.stopped() => break Ok(()),
                finished = tasks.join_next(), if !tasks.is_empty() => {
                    match finished {
                        Some(Ok(key)) if flows.complete(key) => continue,
                        _ => break Err(ClientError::Io),
                    }
                }
                packet = v4.receive() => packet,
                packet = v6.receive() => packet,
            };
            let packet = match packet {
                Ok(packet) => packet,
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    crate::traffic::udp_queue_drop();
                    continue;
                }
                Err(_) => break Err(ClientError::Io),
            };
            if let Some((first, subsequent)) = flows.admit(packet) {
                let key = first.key();
                let ingress = self.clone();
                tasks.spawn(async move {
                    // Individual authenticated relay failure closes only
                    // this flow. A panic or inconsistent ownership is fatal.
                    let _ = ingress.relay_linux_udp(first, subsequent).await;
                    key
                });
            }
        };
        self.shutdown();
        tasks.shutdown().await;
        result
    }

    /// One terminated Linux UDP flow from UdpCapture. The platform owner
    /// demultiplexes subsequent captured datagrams by the exact key. The
    /// connected reply socket uses the original remote address as source
    /// and refuses nonlocal peers. Requires isolated, correctly provisioned
    /// reverse-path routing; does not exempt sockets from system capture.
    #[cfg(target_os = "linux")]
    pub async fn relay_linux_udp(
        &self,
        first: crate::routing::linux_ingress::CapturedDatagram,
        mut subsequent: tokio::sync::mpsc::Receiver<
            crate::routing::linux_ingress::CapturedDatagram,
        >,
    ) -> Result<(), ClientError> {
        use crate::routing::PacketAction;
        self.ensure_accepting()?;
        let registrar = self.registrar()?.ok_or(ClientError::Open(ErrorCode::PolicyDenied))?;
        let key = first.key;
        if subsequent.max_capacity() > crate::udp_relay::QUEUE {
            return Err(ClientError::Protocol);
        }
        tokio::select! {
            biased;
            () = self.stopped() => Err(ClientError::Open(ErrorCode::PolicyDenied)),
            result = async {
                let (carrier, flow, address) = self.redirect(key).await?;
                let tunnel = crate::routing::carrier_socket::scope(self.registrar()?, carrier.open_udp(address, key.destination.port())).await?;
                let reply = crate::routing::linux_ingress::UdpReply::open(&first).map_err(|_| ClientError::Io)?;
                let _reply_admission = reply.admit_reply(registrar.as_ref()).map_err(|_| ClientError::Io)?;
                let (tx, up) = tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
                let (down, mut rx) = tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
                tx.send(first.payload).await.map_err(|_| ClientError::Io)?;
                let relay = tunnel.relay_guarded(up, down, Some(&flow));
                let feed = async move {
                    while let Some(datagram) = subsequent.recv().await {
                        if datagram.key != key || datagram.payload.len() > crate::protocol::MAX_DATAGRAM {
                            return Err(ClientError::Protocol);
                        }
                        tx.send(datagram.payload).await.map_err(|_| ClientError::Io)?;
                    }
                    Ok::<(), ClientError>(())
                };
                let replies = async {
                    while let Some(bytes) = rx.recv().await {
                        if !flow.committed(PacketAction::Redirect) {
                            return Err(ClientError::Open(ErrorCode::PolicyDenied));
                        }
                        reply.send(&bytes).await.map_err(|_| ClientError::Io)?;
                    }
                    Ok::<(), ClientError>(())
                };
                supervise_native_udp(relay, feed, replies).await
            } => result,
        }
    }

    /// Actual multi-datagram QUIC Modify in the isolated Linux lab.
    /// The caller supplies only kernel-captured UDP and an untrusted
    /// probe-name hint. Domain and application evidence remain Unknown;
    /// the authenticated policy must conclusively authorize Modify without
    /// that hint. No ordinary proxy or production native activation.
    #[cfg(target_os = "linux")]
    pub async fn relay_linux_quic_lab(
        &self,
        first: crate::routing::linux_ingress::CapturedDatagram,
        mut subsequent: tokio::sync::mpsc::Receiver<
            crate::routing::linux_ingress::CapturedDatagram,
        >,
        domain: &str,
    ) -> Result<(), ClientError> {
        use crate::routing::{carrier_socket, packet::Transport, Evidence, PacketAction};
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        let key = first.key;
        if key.transport != Transport::Udp
            || key.destination.port() != 443
            || subsequent.max_capacity() > crate::udp_relay::QUEUE
            || !crate::server::allowed_destination(key.destination.ip(), false)
        {
            return Err(denied());
        }
        let registrar = self.registrar()?.ok_or_else(denied)?;
        tokio::select! {
            biased;
            () = self.stopped() => Err(denied()),
            result = carrier_socket::scope(Some(registrar.clone()), async {
                self.ensure_accepting()?;
                let name = crate::routing::domain_name(domain).map_err(|_| denied())?;
                if crate::routing::packet_modify::quic_initial_datagrams(&first.payload, &name).is_none() {
                    return Err(denied());
                }
                let (carrier, cache) = match &self.client {
                    ProxyClient::Direct(c) => (c.carrier.clone(), &c.routing),
                    ProxyClient::Reality(c) => (c.generation().await?.carrier.clone(), &c.routing),
                };
                let snapshot = cache.get(|known| carrier.fetch_routing(known)).await?;
                let digest = snapshot.digest();
                for evidence in [Evidence::Unknown, Evidence::Known(name.as_str())] {
                    if snapshot.policy().classify_with_application(evidence,Evidence::Known(key.destination.ip()),Evidence::Unknown)
                        .map_err(|_| denied())?.action() != Some(Action::DirectDpi) { return Err(denied()); }
                }
                let ips = carrier.resolve_routing(&name,digest).await?;
                if !ips.contains(&key.destination.ip()) { return Err(denied()); }
                let version = crate::reality_quic_wire::long(&first.payload)
                    .and_then(|header| crate::quic_core::wire::Version::from_wire(header.version))
                    .ok_or_else(denied)?;
                let verified = cache.dpi.open_quic_udp_version(&name,443,&[key.destination.ip()],digest,version).await.ok_or_else(denied)?;
                if verified.quic_batch(&first.payload).is_none() || verified.socket.peer_addr().ok() != Some(key.destination)
                    || !verified.socket.local_addr().is_ok_and(|a| a.ip() == key.source.ip())
                    || !verified.admissible()? { return Err(denied()); }
                let flow = cache.flows.begin_native(cache.dpi.clone(),key,digest,PacketAction::Modify)?;
                let _local_admission = registrar.udp(&verified.socket,key.destination).map_err(|_| denied())?;
                let reply = crate::routing::linux_ingress::UdpReply::open(&first).map_err(|_| ClientError::Io)?;
                let _reply_admission = reply.admit_reply(registrar.as_ref()).map_err(|_| denied())?;
                let (tx,up) = tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
                let (down,mut rx) = tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
                let relay = crate::udp_relay::relay_quic_lab(&verified,first.payload,up,down,&flow);
                let feed = async move {
                    while let Some(datagram) = subsequent.recv().await {
                        if datagram.key != key || datagram.payload.len() > crate::protocol::MAX_DATAGRAM {
                            return Err(ClientError::Protocol);
                        }
                        tx.send(datagram.payload).await.map_err(|_| ClientError::Io)?;
                    }
                    Ok::<(),ClientError>(())
                };
                let replies = async {
                    while let Some(bytes) = rx.recv().await {
                        if !flow.committed(PacketAction::Modify) { return Err(denied()); }
                        reply.send(&bytes).await.map_err(|_| ClientError::Io)?;
                    }
                    Ok::<(),ClientError>(())
                };
                supervise_native_udp(relay, feed, replies).await
            }) => result,
        }
    }

    /// Common UDP handoff for a trusted platform adapter with a terminated
    /// datagram flow. The OS-specific receiver/response routing is owned
    /// by the platform adapter; use relay_linux_udp on Linux.
    pub async fn relay_terminated_udp(
        &self,
        key: crate::routing::packet::FlowKey,
        upload: tokio::sync::mpsc::Receiver<Vec<u8>>,
        download: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Result<(), ClientError> {
        if key.transport != crate::routing::packet::Transport::Udp
            || upload.max_capacity() > crate::udp_relay::QUEUE
            || download.max_capacity() > crate::udp_relay::QUEUE
        {
            return Err(ClientError::Protocol);
        }
        tokio::select! {
            biased;
            () = self.stopped() => Err(ClientError::Open(ErrorCode::PolicyDenied)),
            result = async {
                let (carrier, flow, address) = self.redirect(key).await?;
                let tunnel = crate::routing::carrier_socket::scope(self.registrar()?, carrier.open_udp(address, key.destination.port())).await?;
                tunnel.relay_guarded(upload, download, Some(&flow)).await
            } => result,
        }
    }

    async fn redirect(
        &self,
        key: crate::routing::packet::FlowKey,
    ) -> Result<(Carrier, crate::routing::flow::FlowLease, Address), ClientError> {
        use crate::routing::{Evidence, PacketAction};
        self.ensure_accepting()?;
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        if key.destination.port() == 0
            || key.source.port() == 0
            || key.destination.ip().is_loopback()
            || key.destination.ip().is_unspecified()
            || key.destination.ip().is_multicast()
            || key.destination == key.source
            || matches!(key.destination, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.ip().is_unicast_link_local() || v6.ip().to_ipv4_mapped().is_some())
        {
            return Err(denied());
        }
        let (carrier, cache) = match &self.client {
            ProxyClient::Direct(c) => (c.carrier.clone(), &c.routing),
            ProxyClient::Reality(c) => (c.generation().await?.carrier.clone(), &c.routing),
        };
        let snapshot = crate::routing::carrier_socket::scope(
            self.registrar()?,
            cache.get(|known| carrier.fetch_routing(known)),
        )
        .await?;
        let configured = snapshot
            .policy()
            .classify_with_application(
                Evidence::Unknown,
                Evidence::Known(key.destination.ip()),
                Evidence::Unknown,
            )
            .map_err(|_| denied())?
            .action()
            .ok_or_else(denied)?
            .packet_action();
        if !matches!(configured, PacketAction::Redirect | PacketAction::Modify) {
            return Err(denied());
        }
        self.ensure_accepting()?;
        let flow =
            cache
                .flows
                .begin_native(cache.dpi.clone(), key, snapshot.digest(), configured)?;
        let address = match key.destination.ip() {
            IpAddr::V4(ip) => Address::V4(ip.octets()),
            IpAddr::V6(ip) => Address::V6(ip.octets()),
        };
        Ok((carrier, flow, address))
    }
}

/// Exact tuple dispatch shared by both Linux UDP listeners. The common
/// FlowTable still owns egress authorization and process-wide flow quota.
#[cfg(target_os = "linux")]
#[derive(Default)]
struct NativeUdpDispatch {
    flows: std::collections::HashMap<
        crate::routing::packet::FlowKey,
        tokio::sync::mpsc::Sender<crate::routing::linux_ingress::CapturedDatagram>,
    >,
}

#[cfg(target_os = "linux")]
impl NativeUdpDispatch {
    fn admit(
        &mut self,
        packet: crate::routing::linux_ingress::CapturedDatagram,
    ) -> Option<(
        crate::routing::linux_ingress::CapturedDatagram,
        tokio::sync::mpsc::Receiver<crate::routing::linux_ingress::CapturedDatagram>,
    )> {
        let key = packet.key();
        if let Some(tx) = self.flows.get(&key) {
            // Closed and full both drop. Only the joined relay task may
            // release the tuple, after its response drain and lease drop.
            if tx.try_send(packet).is_err() {
                crate::traffic::udp_queue_drop();
            }
            return None;
        }
        if self.flows.len() >= LOCAL_LIMIT {
            crate::traffic::udp_queue_drop();
            return None;
        }
        let (tx, rx) = tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
        self.flows.insert(key, tx);
        Some((packet, rx))
    }

    fn complete(&mut self, key: crate::routing::packet::FlowKey) -> bool {
        self.flows.remove(&key).is_some()
    }
}

/// A clean relay EOF must not cancel accepted reverse datagrams. Keep the
/// flow lease and reply socket until a bounded drain finishes. Feed EOF is
/// not relay EOF; dropping the upload sender lets the carrier send FIN.
/// Errors and outer runtime cancellation still terminate immediately.
#[cfg(target_os = "linux")]
async fn supervise_native_udp(
    relay: impl std::future::Future<Output = Result<(), ClientError>>,
    feed: impl std::future::Future<Output = Result<(), ClientError>>,
    replies: impl std::future::Future<Output = Result<(), ClientError>>,
) -> Result<(), ClientError> {
    tokio::pin!(relay, feed, replies);
    let mut fed = false;
    let mut replied = false;
    loop {
        tokio::select! {
            biased;
            result = &mut relay => {
                result?;
                if !replied {
                    timeout(Duration::from_secs(2), &mut replies)
                        .await.map_err(|_| ClientError::Timeout)??;
                }
                return Ok(());
            }
            result = &mut feed, if !fed => { result?; fed = true; }
            result = &mut replies, if !replied => { result?; replied = true; }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod native_udp_lifecycle_tests {
    use super::*;

    #[test]
    fn native_udp_tuple_not_reused_before_task_join_and_queues_are_bounded() {
        use crate::routing::{linux_ingress::CapturedDatagram, packet::{FlowKey, Transport}};
        let key = FlowKey {
            source: "192.0.2.1:1234".parse().unwrap(),
            destination: "198.51.100.1:443".parse().unwrap(),
            transport: Transport::Udp,
            interface: 0,
        };
        let packet = |key, n| CapturedDatagram { key, payload: vec![n] };
        let mut dispatch = NativeUdpDispatch::default();
        let (first, mut rx) = dispatch.admit(packet(key, 0)).unwrap();
        assert_eq!(first.payload(), &[0]);
        for n in 1..=crate::udp_relay::QUEUE + 1 {
            assert!(dispatch.admit(packet(key, n as u8)).is_none());
        }
        for n in 1..=crate::udp_relay::QUEUE {
            assert_eq!(rx.try_recv().unwrap().payload(), &[n as u8]);
        }
        assert!(rx.try_recv().is_err());
        drop(rx);
        assert!(dispatch.admit(packet(key, 99)).is_none());
        assert!(dispatch.complete(key));
        assert!(!dispatch.complete(key));
        let (_, _new) = dispatch.admit(packet(key, 100)).unwrap();
        // Keep receivers live to make the capacity test independent of EOF.
        let mut receivers = Vec::new();
        for n in 1..LOCAL_LIMIT {
            let other = FlowKey { source: SocketAddr::new(key.source.ip(), 2000 + n as u16), ..key };
            receivers.push(dispatch.admit(packet(other, 1)).unwrap().1);
        }
        let overflow = FlowKey { source: "192.0.2.1:65000".parse().unwrap(), ..key };
        assert!(dispatch.admit(packet(overflow, 1)).is_none());
        assert_eq!(dispatch.flows.len(), LOCAL_LIMIT);
    }

    #[tokio::test]
    async fn relay_completion_drains_accepted_replies_after_upload_eof() {
        let (up, mut upload) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let (down, mut download) = tokio::sync::mpsc::channel::<Vec<u8>>(2);
        let feed = async move {
            up.send(vec![1]).await.unwrap();
            Ok(())
        };
        let relay = async move {
            assert_eq!(upload.recv().await, Some(vec![1]));
            assert!(upload.recv().await.is_none());
            down.send(vec![2]).await.unwrap();
            down.send(vec![3]).await.unwrap();
            Ok(())
        };
        let mut observed = Vec::new();
        let replies = async {
            while let Some(bytes) = download.recv().await {
                tokio::task::yield_now().await;
                observed.push(bytes);
            }
            Ok(())
        };
        supervise_native_udp(relay, feed, replies).await.unwrap();
        assert_eq!(observed, [vec![2], vec![3]]);
    }

    #[tokio::test]
    async fn failed_relay_does_not_drain_or_wait_for_upload() {
        let result = supervise_native_udp(
            async { Err(ClientError::Protocol) },
            std::future::pending(),
            std::future::pending(),
        ).await;
        assert!(matches!(result, Err(ClientError::Protocol)));
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Drop for NativeIngress {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Shared startup preflight: never changes the OS proxy or claims an
/// authenticated remote tunnel merely because the listeners bind.
async fn prepare_proxy(
    document: &config::ClientDocument,
    path: &Path,
) -> Result<(TcpListener, TcpListener, ProxyClient), ClientError> {
    let client = prepare_client(document, path).await?;
    // All startup validation and both binds must succeed before accepting.
    let http = TcpListener::bind(&document.client.proxy.http_listen)
        .await
        .map_err(|_| ClientError::Io)?;
    let socks = TcpListener::bind(&document.client.proxy.socks5_listen)
        .await
        .map_err(|_| ClientError::Io)?;
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
        .set_enabled(document.client.proxy.direct_dpi.unwrap_or(false));
    client
        .routing_cache()
        .dpi
        .set_stun_enabled(document.client.proxy.direct_dpi_stun.unwrap_or(false));
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
    #[cfg(windows)]
    pub(crate) manual: bool,
}

impl PreparedLocalProxy {
    #[cfg(windows)]
    pub(crate) async fn start(path: &Path, expected: [u8; 32]) -> Result<Self, ClientError> {
        let bytes = saved_client_bytes(path, expected)?;
        let source = std::str::from_utf8(&bytes).map_err(|_| ClientError::Configuration)?;
        let Config::Client(document) =
            config::parse(source).map_err(|_| ClientError::Configuration)?
        else {
            return Err(ClientError::Configuration);
        };
        let (http, socks, client) = prepare_proxy(&document, path).await?;
        Ok(Self {
            http,
            socks,
            client,
            manual: document.client.proxy.system_proxy == config::SystemProxy::Manual,
        })
    }

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
            #[cfg(windows)]
            manual: document.client.proxy.system_proxy == config::SystemProxy::Manual,
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

    #[cfg(windows)]
    pub(crate) fn reality_monitor(&self) -> Option<Arc<RealityClient>> {
        match &self.client {
            ProxyClient::Reality(r) => Some(r.clone()),
            _ => None,
        }
    }
    #[cfg(windows)]
    pub(crate) fn http_address(&self) -> Result<SocketAddr, ClientError> {
        self.http.local_addr().map_err(|_| ClientError::Io)
    }

    #[cfg(windows)]
    pub(crate) async fn serve(self) -> Result<(), ClientError> {
        serve_proxy(self.http, self.socks, self.client).await
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
    serve_proxy_loop(http, socks, || client.clone(), maintenance).await
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
        || runtime.slot.borrow().client.clone(),
        runtime.maintain(),
    )
    .await
}

async fn serve_proxy_loop(
    http: TcpListener,
    socks: TcpListener,
    current: impl Fn() -> ProxyClient,
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
            result = &mut maintenance => return result,
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
            accepted = http.accept() => (accepted.map_err(|_| ClientError::Io)?.0, true),
            accepted = socks.accept() => (accepted.map_err(|_| ClientError::Io)?.0, false),
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
        let client = current();
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

fn validate_target(address: Address, port: u16) -> Result<(Address, u16), ClientError> {
    protocol::encode(&Frame::OpenTcp {
        address: address.clone(),
        port,
    })
    .map_err(|_| ClientError::Protocol)?;
    Ok((address, port))
}

fn parse_authority(raw: &str) -> Result<(Address, u16), ClientError> {
    let (host, port) = raw.rsplit_once(':').ok_or(ClientError::Protocol)?;
    let port = port.parse::<u16>().map_err(|_| ClientError::Protocol)?;
    let address = if let Some(host) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        Address::V6(
            host.parse::<Ipv6Addr>()
                .map_err(|_| ClientError::Protocol)?
                .octets(),
        )
    } else if let Ok(ip) = host.parse::<Ipv4Addr>() {
        Address::V4(ip.octets())
    } else {
        Address::Dns(host.to_owned())
    };
    validate_target(address, port)
}

async fn http_target(socket: &mut TcpStream) -> Result<(Address, u16), &'static [u8]> {
    // Read exactly through the header terminator without consuming the
    // first bytes of a pipelined TLS/application stream.
    let mut head = Vec::with_capacity(1024);
    while head.len() < HEADER_LIMIT {
        let byte = socket.read_u8().await.map_err(|_| HTTP_BAD)?;
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !head.ends_with(b"\r\n\r\n") {
        return Err(HTTP_BAD);
    }
    let text = std::str::from_utf8(&head[..head.len() - 4]).map_err(|_| HTTP_BAD)?;
    let mut lines = text.split("\r\n");
    let mut line = lines.next().ok_or(HTTP_BAD)?.split(' ');
    let method = line.next().ok_or(HTTP_BAD)?;
    let authority = line.next().ok_or(HTTP_BAD)?;
    let version = line.next().ok_or(HTTP_BAD)?;
    if line.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(HTTP_BAD);
    }
    if method != "CONNECT" {
        return Err(HTTP_METHOD);
    }
    let target = parse_authority(authority).map_err(|_| HTTP_BAD)?;
    let mut host_seen = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(HTTP_BAD)?;
        let name = http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| HTTP_BAD)?;
        let value = value.trim_matches([' ', '\t']);
        http::HeaderValue::from_str(value).map_err(|_| HTTP_BAD)?;
        if name == http::header::TRANSFER_ENCODING || name == http::header::CONTENT_LENGTH {
            return Err(HTTP_BAD);
        }
        if name == http::header::HOST {
            if host_seen || !value.eq_ignore_ascii_case(authority) {
                return Err(HTTP_BAD);
            }
            host_seen = true;
        }
    }
    if version == "HTTP/1.1" && !host_seen {
        return Err(HTTP_BAD);
    }
    Ok(target)
}

async fn socks_reply(socket: &mut TcpStream, code: u8) -> Result<(), ClientError> {
    // BND.ADDR/BND.PORT are unspecified in this proxy protocol slice.
    socket
        .write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|_| ClientError::Io)
}

enum SocksRequest {
    Connect(Address, u16),
    Associate(Address, u16),
}

async fn socks_request(socket: &mut TcpStream) -> Result<SocksRequest, ClientError> {
    let mut greeting = [0; 2];
    socket
        .read_exact(&mut greeting)
        .await
        .map_err(|_| ClientError::Io)?;
    if greeting[0] != 5 || greeting[1] == 0 {
        return Err(ClientError::Protocol);
    }
    let mut methods = vec![0; usize::from(greeting[1])];
    socket
        .read_exact(&mut methods)
        .await
        .map_err(|_| ClientError::Io)?;
    if !methods.contains(&0) {
        socket
            .write_all(&[5, 0xff])
            .await
            .map_err(|_| ClientError::Io)?;
        return Err(ClientError::Protocol);
    }
    // Local no-auth is allowed only on loopback. Remote auth is mandatory.
    socket
        .write_all(&[5, 0])
        .await
        .map_err(|_| ClientError::Io)?;
    let mut request = [0; 4];
    socket
        .read_exact(&mut request)
        .await
        .map_err(|_| ClientError::Io)?;
    if request[0] != 5 || request[2] != 0 {
        socks_reply(socket, 1).await?;
        return Err(ClientError::Protocol);
    }
    if !matches!(request[1], 1 | 3) {
        socks_reply(socket, 7).await?;
        return Err(ClientError::Protocol);
    }
    let address = match request[3] {
        1 => {
            let mut addr = [0; 4];
            socket
                .read_exact(&mut addr)
                .await
                .map_err(|_| ClientError::Io)?;
            Address::V4(addr)
        }
        4 => {
            let mut addr = [0; 16];
            socket
                .read_exact(&mut addr)
                .await
                .map_err(|_| ClientError::Io)?;
            Address::V6(addr)
        }
        3 => {
            let len = socket.read_u8().await.map_err(|_| ClientError::Io)?;
            let mut name = vec![0; usize::from(len)];
            socket
                .read_exact(&mut name)
                .await
                .map_err(|_| ClientError::Io)?;
            match String::from_utf8(name) {
                Ok(name) => Address::Dns(name),
                Err(_) => {
                    socks_reply(socket, 8).await?;
                    return Err(ClientError::Protocol);
                }
            }
        }
        _ => {
            socks_reply(socket, 8).await?;
            return Err(ClientError::Protocol);
        }
    };
    let port = socket.read_u16().await.map_err(|_| ClientError::Io)?;
    if request[1] == 3 {
        return Ok(SocksRequest::Associate(address, port));
    }
    match validate_target(address, port) {
        Ok((address, port)) => Ok(SocksRequest::Connect(address, port)),
        Err(error) => {
            socks_reply(socket, 8).await?;
            Err(error)
        }
    }
}

async fn handle(
    mut socket: TcpStream,
    is_http: bool,
    client: &ProxyClient,
    session_id: u64,
) -> Result<(), ClientError> {
    crate::diag!(
        Trace,
        "client.proxy",
        "negotiation_started",
        "session" = Value::Count(session_id)
    );
    let (address, port) = if is_http {
        match timeout(NEGOTIATE_TIMEOUT, http_target(&mut socket)).await {
            Ok(Ok(target)) => target,
            Ok(Err(reply)) => {
                let _ = timeout(REPLY_TIMEOUT, socket.write_all(reply)).await;
                crate::diag!(
                    Warn,
                    "client.proxy",
                    "http_connect_parse_failed",
                    "session" = Value::Count(session_id)
                );
                return Err(ClientError::Protocol);
            }
            Err(_) => return Err(ClientError::Timeout),
        }
    } else {
        match timeout(NEGOTIATE_TIMEOUT, socks_request(&mut socket))
            .await
            .map_err(|_| ClientError::Timeout)??
        {
            SocksRequest::Connect(address, port) => (address, port),
            SocksRequest::Associate(address, port) => {
                return udp_association(socket, client, address, port).await
            }
        }
    };
    crate::diag!(
        Debug,
        "client.proxy",
        "negotiation_validated",
        "session" = Value::Count(session_id)
    );
    match client.open(address, port).await {
        Ok(tunnel) => {
            if tunnel.open_code() == 0 {
                crate::diag!(
                    Debug,
                    "client.proxy",
                    "direct_open_ok",
                    "session" = Value::Count(session_id)
                );
            } else {
                crate::diag!(
                    Debug,
                    "client.proxy",
                    "remote_open_ok",
                    "session" = Value::Count(session_id)
                );
            }
            // A direct socket is already connected; proxied routes verified OPEN_OK.
            if is_http {
                timeout(REPLY_TIMEOUT, socket.write_all(HTTP_OK))
                    .await
                    .map_err(|_| ClientError::Timeout)?
                    .map_err(|_| ClientError::Io)?;
            } else {
                timeout(REPLY_TIMEOUT, socks_reply(&mut socket, 0))
                    .await
                    .map_err(|_| ClientError::Timeout)??;
            }
            tunnel.relay(socket).await
        }
        Err(error) => {
            crate::diag!(
                Warn,
                "client.proxy",
                "remote_open_failed",
                "session" = Value::Count(session_id),
                "reason" = Value::Label(error_kind(&error))
            );
            if is_http {
                let reply = match error {
                    ClientError::Open(ErrorCode::PolicyDenied) | ClientError::Unauthorized => {
                        HTTP_DENIED
                    }
                    ClientError::Timeout
                    | ClientError::QuicUnreachable
                    | ClientError::QuicEndpointNetworkRefused
                    | ClientError::Open(ErrorCode::DialTimeout) => HTTP_TIMEOUT,
                    _ => HTTP_FAILED,
                };
                let _ = timeout(REPLY_TIMEOUT, socket.write_all(reply)).await;
            } else {
                let code = match error {
                    ClientError::Open(ErrorCode::PolicyDenied) | ClientError::Unauthorized => 2,
                    ClientError::Open(ErrorCode::DialFailed) => 4,
                    ClientError::Open(ErrorCode::AddressInvalid) => 8,
                    ClientError::Timeout | ClientError::Open(ErrorCode::DialTimeout) => 6,
                    _ => 1,
                };
                let _ = timeout(REPLY_TIMEOUT, socks_reply(&mut socket, code)).await;
            }
            // Send an orderly FIN after the terminal denial. Never reopen a
            // tunnel or retry the rejected remote request.
            let _ = timeout(REPLY_TIMEOUT, socket.shutdown()).await;
            Err(error)
        }
    }
}

#[cfg(test)]
async fn socks_target(socket: &mut TcpStream) -> Result<(Address, u16), ClientError> {
    match socks_request(socket).await? {
        SocksRequest::Connect(a, p) => Ok((a, p)),
        _ => Err(ClientError::Protocol),
    }
}

async fn udp_association(
    mut control: TcpStream,
    client: &ProxyClient,
    requested: Address,
    port: u16,
) -> Result<(), ClientError> {
    use crate::udp_relay::{self, MAX_FLOWS, QUEUE};
    use tokio::sync::mpsc;
    let peer = control.peer_addr().map_err(|_| ClientError::Io)?;
    let local = control.local_addr().map_err(|_| ClientError::Io)?;
    if !peer.ip().is_loopback()
        || !local.ip().is_loopback()
        || !udp_relay::valid_associate(&requested, peer.ip())
    {
        socks_reply(&mut control, 2).await?;
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    let socket = Arc::new(
        tokio::net::UdpSocket::bind(SocketAddr::new(local.ip(), 0))
            .await
            .map_err(|_| ClientError::Io)?,
    );
    let bound = socket.local_addr().map_err(|_| ClientError::Io)?;
    timeout(
        REPLY_TIMEOUT,
        control.write_all(&udp_relay::associate_reply(bound)),
    )
    .await
    .map_err(|_| ClientError::Timeout)?
    .map_err(|_| ClientError::Io)?;
    let mut pinned = if port == 0 {
        None
    } else {
        Some(SocketAddr::new(peer.ip(), port))
    };
    use crate::routing::dpi::udp::{self, Candidate};
    type Observer = Arc<std::sync::Mutex<udp::Observer>>;
    struct Flow {
        tx: mpsc::Sender<Vec<u8>>,
        observer: Observer,
        classification: tokio::sync::watch::Sender<Candidate>,
        finished: Arc<std::sync::atomic::AtomicBool>,
    }
    struct Completion(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Completion {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }
    let mut flows = std::collections::HashMap::<(Address, u16), Flow>::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut buf = vec![0; 65536];
    let mut control_byte = [0; 1];
    loop {
        tokio::select! {
            result=control.read(&mut control_byte)=>{
                return match result { Ok(0)=>Ok(()), Ok(_)=>Err(ClientError::Protocol), Err(_)=>Err(ClientError::Io) };
            }
            _=tasks.join_next(), if !tasks.is_empty()=>{ flows.retain(|_,flow|!flow.finished.load(std::sync::atomic::Ordering::Acquire)); }
            result=socket.recv_from(&mut buf)=>{
                let (n,source)=result.map_err(|_|ClientError::Io)?;
                if source.ip()!=peer.ip() || pinned.is_some_and(|old|old!=source) { continue; }
                let Some((address,port,data))=udp_relay::parse_socks(&buf[..n]) else { continue; };
                if pinned.is_none() { pinned=Some(source); }
                let key=(address,port);
                flows.retain(|_,flow|!flow.finished.load(std::sync::atomic::Ordering::Acquire));
                if let Some(flow)=flows.get(&key) {
                    // Full queue drops the datagram, never replays it.
                    if !flow.tx.is_closed() {
                        match flow.tx.try_reserve() {
                            Ok(permit) => {
                                let next=flow.observer.lock().unwrap_or_else(|e|e.into_inner()).outgoing(data);
                                // Publish only after this datagram is admitted.
                                permit.send(data.to_vec());
                                if next != Candidate::Pending {
                                    flow.classification.send_if_modified(|current| {
                                        if *current == Candidate::Pending { *current=next; true } else { false }
                                    });
                                }
                            }
                            Err(_) => crate::traffic::udp_queue_drop(),
                        }
                    } else {
                        // The previous flow still owns the downstream queue.
                        crate::traffic::udp_queue_drop();
                    }
                    continue;
                }
                if tasks.len()>=MAX_FLOWS { crate::traffic::udp_queue_drop(); continue; }
                let (tx,rx)=mpsc::channel(QUEUE);
                let _=tx.try_send(data.to_vec());
                let observer=Arc::new(std::sync::Mutex::new(udp::Observer::default()));
                let (candidate, deadline) = {
                    let mut observer = observer.lock().unwrap_or_else(|e| e.into_inner());
                    let candidate = observer.outgoing(data);
                    (candidate, observer.classification_deadline())
                };
                let (classification,classified)=tokio::sync::watch::channel(candidate);
                let finished=Arc::new(std::sync::atomic::AtomicBool::new(false));
                let completion=Completion(finished.clone());
                flows.insert(key.clone(),Flow { tx, observer: observer.clone(), classification, finished });
                let socket=socket.clone();
                let proxy=(*client).clone();
                tasks.spawn(async move {
                    let _completion=completion;
                    let (address,port)=key;
                    let candidate=udp::await_candidate(classified, deadline).await;
                    let tunnel=proxy.open_udp(address.clone(),port,&candidate).await?;
                    let (down_tx,mut down_rx)=mpsc::channel(QUEUE);
                    let relay=tunnel.relay(rx,down_tx);
                    let deliver=async {
                        let mut packet = Vec::new();
                        while let Some(data)=down_rx.recv().await {
                            observer.lock().unwrap_or_else(|e|e.into_inner()).incoming(&data);
                            if !udp_relay::encode_socks_into(&mut packet, &address, port, &data) {
                                // SOCKS framing may exceed the UDP maximum;
                                // this is not queue congestion.
                                continue;
                            }
                            let n=timeout(REPLY_TIMEOUT,socket.send_to(&packet,source)).await
                                .map_err(|_|ClientError::Timeout)?.map_err(|_|ClientError::Io)?;
                            if n!=packet.len(){return Err(ClientError::Io);}
                        }
                        Ok::<(),ClientError>(())
                    };
                    // On clean termination drain accepted responses instead
                    // of cancelling the downstream queue when relay returns.
                    tokio::try_join!(relay, deliver).map(|_| ())
                });
            }
        }
    }
}

#[cfg(test)]
async fn udp_revoked_fallback_fixture(client: &ProxyClient) {
    use crate::udp_relay::{self, Tunnel, QUEUE};
    use tokio::sync::mpsc;
    let local_origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let verified = crate::routing::dpi::VerifiedUdp::disabled_fixture(
        udp_relay::connect(local_origin.local_addr().unwrap())
            .await
            .unwrap(),
    );
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let authorization = verified.fallback_policy();
    let ProxyClient::Direct(client) = client else {
        panic!("own TLS fixture");
    };
    let carrier = client.carrier.clone();
    let fallback = Box::pin(async move {
        // A successful OPEN is insufficient if the local routing lease
        // was revoked before the application datagram could be sent.
        let tunnel = carrier.open_udp(Address::V4([127, 0, 0, 1]), port).await?;
        authorization.revoke_fixture();
        Ok(tunnel)
    });
    let (up, rx) = mpsc::channel(QUEUE);
    let (down, _responses) = mpsc::channel(QUEUE);
    up.send(b"must not escape".to_vec()).await.unwrap();
    let result = timeout(
        Duration::from_secs(5),
        Tunnel::VerifiedLocal(Box::new(verified), fallback).relay(rx, down),
    )
    .await
    .unwrap();
    assert!(matches!(
        result,
        Err(ClientError::Open(ErrorCode::PolicyDenied))
    ));
    let mut buf = [0; 32];
    assert!(
        timeout(Duration::from_millis(50), local_origin.recv_from(&mut buf))
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(50), target.recv_from(&mut buf))
            .await
            .is_err()
    );
}

#[cfg(test)]
async fn udp_prewrite_fallback_fixture(client: &ProxyClient) {
    use crate::udp_relay::{self, Tunnel, QUEUE};
    use tokio::sync::mpsc;
    let local_origin = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let verified = crate::routing::dpi::VerifiedUdp::disabled_fixture(
        udp_relay::connect(local_origin.local_addr().unwrap())
            .await
            .unwrap(),
    );
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let ProxyClient::Direct(client) = client else {
        panic!("own TLS fixture");
    };
    let carrier = client.carrier.clone();
    let fallback =
        Box::pin(async move { carrier.open_udp(Address::V4([127, 0, 0, 1]), port).await });
    let (up, rx) = mpsc::channel(QUEUE);
    let (down, mut responses) = mpsc::channel(QUEUE);
    up.send(b"first".to_vec()).await.unwrap();
    up.send(Vec::new()).await.unwrap();
    let task = tokio::spawn(Tunnel::VerifiedLocal(Box::new(verified), fallback).relay(rx, down));
    let mut buf = [0; 32];
    for data in [b"first".as_slice(), b"".as_slice()] {
        let (n, source) = timeout(Duration::from_secs(3), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], data);
        target.send_to(data, source).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), responses.recv())
                .await
                .unwrap()
                .unwrap(),
            data
        );
    }
    assert!(
        timeout(Duration::from_millis(50), local_origin.recv_from(&mut buf))
            .await
            .is_err()
    );
    drop(up);
    task.await.unwrap().unwrap();
}

#[cfg(test)]
async fn udp_socks_fixture(client: &ProxyClient) {
    use crate::udp_relay::{encode_socks, parse_socks};
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let app = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let app_port = app.local_addr().unwrap().port();
    let (mut control, local) = selector_tests::paired().await;
    let client = (*client).clone();
    assert!(matches!(
        client
            .open_udp(
                Address::Dns("blocked.invalid".into()),
                443,
                &crate::routing::dpi::udp::Candidate::Other
            )
            .await,
        Err(ClientError::Open(ErrorCode::PolicyDenied))
    ));
    let task = tokio::spawn(async move { handle(local, false, &client, 1).await });
    let mut greeting = vec![5, 1, 0, 5, 3, 0, 1, 127, 0, 0, 1];
    greeting.extend(app_port.to_be_bytes());
    control.write_all(&greeting).await.unwrap();
    let mut reply = [0; 12];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..6], &[5, 0, 5, 0, 0, 1]);
    let relay = SocketAddr::from((
        [reply[6], reply[7], reply[8], reply[9]],
        u16::from_be_bytes([reply[10], reply[11]]),
    ));
    let address = Address::V4([127, 0, 0, 1]);
    let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    attacker
        .send_to(
            &encode_socks(&address, port, b"wrong source").unwrap(),
            relay,
        )
        .await
        .unwrap();
    let mut buf = vec![0; 65536];
    assert!(
        timeout(Duration::from_millis(40), target.recv_from(&mut buf))
            .await
            .is_err()
    );
    let mut stun = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    stun.extend([7; 12]);
    let hello = crate::routing::dpi::test_hello();
    let quic = crate::reality_quic_wire::test_initial(crate::reality_quic_wire::V1, &hello[5..]);
    for (index, data) in [stun, quic, vec![], b"last".to_vec()]
        .into_iter()
        .enumerate()
    {
        let packet = encode_socks(&address, port, &data).unwrap();
        app.send_to(&packet, relay).await.unwrap();
        let (n, peer) = timeout(Duration::from_secs(3), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], data);
        let response = if index == 0 {
            // Minimal Binding success with the observed VPS source.
            let mut response = data.clone();
            response[0] = 1;
            response[3] = 12;
            response.extend([0, 0x20, 0, 8, 0, 1]);
            response.extend((peer.port() ^ 0x2112).to_be_bytes());
            let IpAddr::V4(ip) = peer.ip() else {
                panic!("fixture IPv4")
            };
            response.extend(
                ip.octets()
                    .into_iter()
                    .zip([0x21, 0x12, 0xa4, 0x42])
                    .map(|(a, b)| a ^ b),
            );
            response
        } else {
            data
        };
        target.send_to(&response, peer).await.unwrap();
        let (n, source) = timeout(Duration::from_secs(3), app.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, relay);
        assert_eq!(
            parse_socks(&buf[..n]),
            Some((address.clone(), port, response.as_slice()))
        );
    }
    udp_quic_fixture(app, relay).await;
    control.shutdown().await.unwrap();
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[cfg(test)]
async fn udp_quic_fixture(app: tokio::net::UdpSocket, relay: SocketAddr) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let origin = crate::quinn_reference::server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        vec![der],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
    )
    .unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let endpoint =
        crate::quinn_reference::client_endpoint("127.0.0.1:0".parse().unwrap(), roots).unwrap();
    let client_addr = endpoint.local_addr().unwrap();
    let bridge_addr = app.local_addr().unwrap();
    let bridge = tokio::spawn(async move {
        let target = Address::V4([127, 0, 0, 1]);
        let mut buf = vec![0; 65536];
        loop {
            let (n, source) = app.recv_from(&mut buf).await.unwrap();
            if source == client_addr {
                if let Some(wire) = crate::udp_relay::encode_socks(&target, origin_port, &buf[..n])
                {
                    app.send_to(&wire, relay).await.unwrap();
                }
            } else if source == relay {
                if let Some((address, port, data)) = crate::udp_relay::parse_socks(&buf[..n]) {
                    if address == target && port == origin_port {
                        app.send_to(data, client_addr).await.unwrap();
                    }
                }
            }
        }
    });
    let server = async {
        let connection = crate::quinn_reference::accept(origin.accept().await.unwrap())
            .await
            .unwrap();
        let (mut tx, mut rx) = connection.accept_bi().await.unwrap();
        let bytes = rx.read_to_end(64).await.unwrap();
        assert_eq!(bytes, b"nested quic");
        tx.write_all(&bytes).await.unwrap();
        tx.finish().unwrap();
        connection
    };
    let client = async {
        let connection = crate::quinn_reference::connect(&endpoint, bridge_addr, "localhost")
            .await
            .unwrap();
        let (mut tx, mut rx) = connection.open_bi().await.unwrap();
        tx.write_all(b"nested quic").await.unwrap();
        tx.finish().unwrap();
        assert_eq!(rx.read_to_end(64).await.unwrap(), b"nested quic");
        connection
    };
    let (_server, _client) = timeout(Duration::from_secs(10), async {
        tokio::join!(server, client)
    })
    .await
    .unwrap();
    bridge.abort();
    let _ = bridge.await;
}

#[cfg(test)]
mod selector_tests {
    use super::*;

    // The public-address reference evidence is synthetic and deliberately
    // not used by the admitted test branch. All application I/O is loopback;
    // this does not assert external reference parity.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn registered_reality_live_rotation_keeps_native_connect_and_socks5_open() {
        registered_reality_scenario(false).await;
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn registered_reality_production_drain_preserves_h2_h3_both_xhttp_modes() {
        registered_reality_scenario(true).await;
    }

    async fn registered_reality_scenario(drain_only: bool) {
        use crate::{
            descriptor::ClientPolicy,
            reality_bootstrap as bootstrap,
            reality_config::{self, ClientRequest, Request, ServerRequest},
            reality_generation::Manager,
            reference_health::{self, Evidence, Plan, State, Store, Target},
        };
        use sha2::{Digest, Sha256};
        use std::{
            path::PathBuf,
            sync::atomic::{AtomicU64, Ordering},
        };
        struct Scratch(PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let dir = Scratch(std::env::temp_dir().join(format!(
            "theia-reality-native-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )));
        std::fs::create_dir(&dir.0).unwrap();
        timeout(Duration::from_secs(59), async {
            let reservations = crate::shared_port::reserve_shared_port();
            let remote = reservations.0.local_addr().unwrap();
            let now = reference_health::unix_now()
                .unwrap()
                .saturating_sub(if drain_only { 0 } else { 3700 });
            let state = State::new(
                Plan {
                    schema_version: 1,
                    inbound: "reality-native".into(),
                    endpoint: remote.to_string(),
                    own_ips: vec![remote.ip()],
                    references: vec![
                        Target {
                            server_name: "ref.example.org".into(),
                            address: "93.184.216.2:443".parse().unwrap(),
                        },
                        Target {
                            server_name: "reserve.example.org".into(),
                            address: "93.184.216.3:443".parse().unwrap(),
                        },
                    ],
                },
                vec![
                    Evidence {
                        h2_status: Some(200),
                        h3_status: Some(200)
                    };
                    2
                ],
                now,
            )
            .unwrap();
            let health = dir.0.join("health.toml");
            Store::new(&health).unwrap().enroll(&state).unwrap();
            let bundle = dir.0.join("bundle");
            let digest = state.snapshot_sha256().unwrap();
            let record = crate::reality_provision::create(&state, digest, &bundle, now).unwrap();
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let initial_publication = std::fs::read(bundle.join("publication.toml")).unwrap();
            let token = [42u8; 32];
            let server_path = dir.0.join("server.toml");
            let source = include_str!("../../../examples/server.toml").replace(
                "REPLACE_WITH_64_LOWERCASE_HEX",
                &format!("{:x}", Sha256::digest(token)),
            );
            std::fs::write(&server_path, source).unwrap();
            let request = Request::Server(ServerRequest {
                health: health.clone(),
                bundle: bundle.clone(),
                health_sha256: digest,
                identity_sha256: record.identity_sha256,
                listen: remote,
                grants: vec!["device-a".into()],
            });
            let preview = reality_config::prepare(&server_path, &request, now).unwrap();
            reality_config::apply(&server_path, &request, preview.approval_sha256(), now).unwrap();
            let Config::Server(mut server_doc) = config::read_file(&server_path).unwrap() else {
                panic!()
            };
            // The template own-TLS inbound has placeholder PEM paths.
            // Test the registered REALITY branch, not an invalid template.
            server_doc
                .server
                .inbounds
                .retain(|i| i.id == "reality-native");
            server_doc.server.policy.allow_private_ips = true;
            let config = Config::Server(server_doc.clone());
            let lease = Manager::new(&config, "reality-native", now)
                .unwrap()
                .refresh(now)
                .unwrap();
            let material = lease.publication().active();
            let old_signer = material.verified().signer();
            let successor =
                crate::identity_tls::Identity::generate(material.identity().scope().clone())
                    .unwrap();
            let successor_path = dir.0.join("successor.key");
            successor.save_new(&successor_path).unwrap();
            let invite =
                bootstrap::Invitation::public(material.identity(), material.signed(), now).unwrap();
            let uri = invite.encode().unwrap();
            let client_path = dir.0.join("client.toml");
            let mut bearer =
                crate::client_import::PrivateBearer::create(&client_path, &token).unwrap();
            let reference = bearer.reference().unwrap();
            bearer.commit();
            std::fs::write(&client_path, include_str!("../../../examples/client.toml")).unwrap();
            for (id, transport, mode) in [
                ("native-h2", Transport::H2, XhttpMode::StreamOne),
                ("native-h3", Transport::H3, XhttpMode::StreamOne),
                ("split-h2", Transport::H2, XhttpMode::StreamUp),
                ("split-h3", Transport::H3, XhttpMode::StreamUp),
            ] {
                // Stream-up profiles remain offline during the live rotation.
                let enrollment = dir.0.join(format!("{id}.toml"));
                let trust = dir.0.join(format!("{id}-trust.toml"));
                bootstrap::import(
                    &uri,
                    bootstrap::ImportApproval {
                        document_sha256: bootstrap::digest(&uri),
                        identity_sha256: invite.fingerprint(),
                    },
                    &enrollment,
                    &trust,
                    bootstrap::EnrollmentMaterial {
                        admission_path: &bundle.join("admission.key"),
                        expected_admission: None,
                        external_token: Some(&reference),
                    },
                    ClientPolicy {
                        transport,
                        xhttp_mode: mode,
                    },
                    now,
                )
                .unwrap();
                let request = Request::Client(ClientRequest {
                    enrollment,
                    identity_sha256: invite.fingerprint(),
                    id: id.into(),
                });
                let preview = reality_config::prepare(&client_path, &request, now).unwrap();
                reality_config::apply(&client_path, &request, preview.approval_sha256(), now)
                    .unwrap();
            }
            // A single signed snapshot is the source of both native carriers.
            drop(lease);
            // Production listener preparation binds both protocols itself.
            // Keep the fixture reservation through all preceding file work.
            drop(reservations);
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            if drain_only {
                let (started, ready) = tokio::sync::oneshot::channel();
                let (drain, stop) = tokio::sync::oneshot::channel();
                let (draining, acknowledged) = tokio::sync::oneshot::channel();
                let mut server = JoinSet::new();
                server.spawn(crate::server::registered_reality_drain_fixture(
                    server_doc, started, stop, draining,
                ));
                ready.await.unwrap();
                let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let target_port = target.local_addr().unwrap().port();
                let Config::Client(client_doc) = config::read_file(&client_path).unwrap() else {
                    panic!("client fixture");
                };
                let mut clients = Vec::new();
                let mut apps = Vec::new();
                let mut relays = JoinSet::new();
                let mut echoes = JoinSet::new();
                let address = Address::V4([127, 0, 0, 1]);
                async fn exchange(app: &mut TcpStream, data: &[u8]) {
                    app.write_all(data).await.unwrap();
                    let mut got = vec![0; data.len()];
                    app.read_exact(&mut got).await.unwrap();
                    assert_eq!(got, data);
                }
                for id in ["native-h2", "native-h3", "split-h2", "split-h3"] {
                    let profile = client_doc
                        .client
                        .profiles
                        .iter()
                        .find(|p| p.id == id)
                        .unwrap();
                    let client = load_client(profile).await.unwrap();
                    // Real marker/identity admission and OPEN_OK through the
                    // registered production TCP/UDP listeners.
                    let tunnel = client.open(address.clone(), target_port).await.unwrap();
                    let (mut upstream, _) = target.accept().await.unwrap();
                    echoes.spawn(async move {
                        let (mut read, mut write) = upstream.split();
                        tokio::io::copy(&mut read, &mut write).await.unwrap();
                        write.shutdown().await.unwrap();
                    });
                    let (mut app, local) = paired().await;
                    relays.spawn(tunnel.relay(local));
                    exchange(&mut app, id.as_bytes()).await;
                    clients.push(client);
                    apps.push(app);
                }
                drain.send(()).unwrap();
                acknowledged.await.unwrap();
                for app in &mut apps {
                    exchange(app, b"old OPEN_OK tunnel after drain").await;
                }
                // Exercise all four modes concurrently within the production
                // drain deadline. No new upstream dial is permitted.
                let mut refusals = JoinSet::new();
                for client in clients {
                    let address = address.clone();
                    refusals.spawn(async move {
                        let refusal =
                            timeout(Duration::from_secs(5), client.open(address, target_port))
                                .await;
                        assert!(matches!(refusal, Ok(Err(_))));
                    });
                }
                while let Some(result) = refusals.join_next().await {
                    result.unwrap();
                }
                assert!(timeout(Duration::from_millis(100), target.accept())
                    .await
                    .is_err());
                for mut app in apps {
                    exchange(&mut app, b"still alive after refused admission").await;
                    app.shutdown().await.unwrap();
                    let mut tail = Vec::new();
                    app.read_to_end(&mut tail).await.unwrap();
                    assert!(tail.is_empty());
                }
                while let Some(result) = relays.join_next().await {
                    result.unwrap().unwrap();
                }
                while let Some(result) = echoes.join_next().await {
                    result.unwrap();
                }
                server.join_next().await.unwrap().unwrap().unwrap();
                // The supervisor has released both sockets after drain.
                let tcp = TcpListener::bind(remote).await.unwrap();
                let udp = tokio::net::UdpSocket::bind(remote).await.unwrap();
                drop((tcp, udp));
                return;
            }
            let (started, ready) = tokio::sync::oneshot::channel();
            let mut server = JoinSet::new();
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let (drain, stop) = tokio::sync::oneshot::channel();
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let (draining, acknowledged) = tokio::sync::oneshot::channel();
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            server.spawn(crate::server::registered_reality_drain_fixture(
                server_doc.clone(),
                started,
                stop,
                draining,
            ));
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            server.spawn(crate::server::run_reality_document_with_ready(
                server_doc,
                Some(started),
            ));
            ready.await.unwrap();
            let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = echo.local_addr().unwrap();
            let mut echo_tasks = JoinSet::new();
            echo_tasks.spawn(async move {
                let mut sessions = JoinSet::new();
                loop {
                    let (mut stream, _) = echo.accept().await.unwrap();
                    sessions.spawn(async move {
                        let mut bytes = [0; 4];
                        while stream.read_exact(&mut bytes).await.is_ok() {
                            stream.write_all(&bytes).await.unwrap();
                        }
                    });
                }
            });
            let Config::Client(mut client_doc) = config::read_file(&client_path).unwrap() else {
                panic!()
            };
            let mut established = Vec::new();
            let mut proxies = Vec::new();
            let mut managed_clients = Vec::new();
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let mut headless = None;
            for (id, socks_mode) in [("native-h2", false), ("native-h3", true)] {
                client_doc.client.active_profile = id.into();
                let profile = client_doc
                    .client
                    .profiles
                    .iter()
                    .find(|p| p.id == id)
                    .unwrap();
                let client = load_client(profile).await.unwrap();
                let ProxyClient::Reality(managed) = &client else {
                    panic!("wrong security mode")
                };
                let current = managed.generation().await.unwrap();
                let report = managed.runtime_report().await;
                assert!(report.contains("Сохранённое доверие: совпадает"));
                assert!(report.contains(
                    "последнее подтверждённое соединение: пока нет подтверждённого соединения"
                ));
                assert!(report.contains(if socks_mode {
                    "Режим передачи: h3"
                } else {
                    "Режим передачи: h2"
                }));
                managed_clients.push(managed.clone());
                if let Carrier::H3(h3) = &current.carrier {
                    // Use the production dispatcher and a real OPEN_OK
                    // tunnel. Rebind the same Quinn endpoint, not a new
                    // connection or a new admission handshake.
                    let tunnel = h3
                        .open(crate::protocol::Address::V4([127, 0, 0, 1]), target.port())
                        .await
                        .unwrap();
                    let (mut local, remote) = tokio::io::duplex(4096);
                    let rebind = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                    rebind.set_nonblocking(true).unwrap();
                    tunnel.rebind_for_test(rebind).await.unwrap();
                    let task = tokio::spawn(tunnel.relay(remote));
                    local.write_all(b"move").await.unwrap();
                    let mut bytes = [0; 4];
                    timeout(Duration::from_secs(10), local.read_exact(&mut bytes))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(&bytes, b"move");
                    local.write_all(b"stay").await.unwrap();
                    timeout(Duration::from_secs(10), local.read_exact(&mut bytes))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(&bytes, b"stay");
                    drop(local);
                    task.abort();
                    let _ = task.await;
                }
                assert!(matches!(
                    (&current.carrier, socks_mode),
                    (Carrier::H2(_), false) | (Carrier::H3(_), true)
                ));
                let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let listen = if socks_mode {
                    socks.local_addr().unwrap()
                } else {
                    http.local_addr().unwrap()
                };
                let mut proxy = JoinSet::new();
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                if !socks_mode {
                    let raw = Config::Client(client_doc.clone()).to_toml().unwrap();
                    std::fs::write(&client_path, &raw).unwrap();
                    let digest = Sha256::digest(raw.as_bytes()).into();
                    let runtime =
                        ClientRuntime::new(client_path.clone(), client_doc.clone(), digest, client);
                    headless = Some((runtime.clone(), listen));
                    proxy.spawn(serve_managed_proxy(http, socks, runtime));
                } else {
                    proxy.spawn(serve_proxy(http, socks, client));
                }
                #[cfg(not(any(target_os = "linux", target_os = "windows")))]
                proxy.spawn(serve_proxy(http, socks, client));
                let mut stream = TcpStream::connect(listen).await.unwrap();
                if socks_mode {
                    stream.write_all(&[5, 1, 0]).await.unwrap();
                    let mut response = [0; 2];
                    stream.read_exact(&mut response).await.unwrap();
                    assert_eq!(response, [5, 0]);
                    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
                    request.extend_from_slice(&target.port().to_be_bytes());
                    stream.write_all(&request).await.unwrap();
                    let mut response = [0; 10];
                    stream.read_exact(&mut response).await.unwrap();
                    assert_eq!(&response[..2], &[5, 0]);
                } else {
                    stream
                        .write_all(
                            format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n")
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                    let mut response = vec![0; HTTP_OK.len()];
                    stream.read_exact(&mut response).await.unwrap();
                    assert_eq!(response, HTTP_OK);
                }
                stream.write_all(b"ping").await.unwrap();
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"ping");
                let report = managed_clients.last().unwrap().runtime_report().await;
                assert!(report.contains(if socks_mode {
                    "последнее подтверждённое соединение: H3"
                } else {
                    "последнее подтверждённое соединение: H2"
                }));
                established.push(stream);
                proxies.push(proxy);
            }
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            {
                use crate::management::{StatusCommand as C, StatusReply as R};
                async fn ipc(
                    runtime: Arc<ClientRuntime>,
                    command: C,
                ) -> Result<R, crate::management::ManagementError> {
                    let (caller, handler) = tokio::io::duplex(1024);
                    let task = tokio::spawn(crate::management::handle_client(handler, runtime));
                    let result = crate::management::exchange(caller, command).await;
                    task.await.unwrap().unwrap();
                    result
                }
                let (runtime, listen) = headless.unwrap();
                let raw = Config::Client(client_doc.clone()).to_toml().unwrap();
                std::fs::write(&client_path, &raw).unwrap();
                let digest: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
                assert!(ipc(
                    runtime.clone(),
                    C::ClientApply {
                        expected_revision: 1,
                        candidate_sha256: [0; 32]
                    }
                )
                .await
                .is_err());
                assert_eq!(
                    ipc(
                        runtime.clone(),
                        C::ClientPreview {
                            expected_revision: 1,
                            candidate_sha256: digest
                        }
                    )
                    .await
                    .unwrap(),
                    R::ClientReady { revision: 1 }
                );
                assert_eq!(runtime.status().await.0, 1);
                assert_eq!(
                    ipc(
                        runtime.clone(),
                        C::ClientApply {
                            expected_revision: 1,
                            candidate_sha256: digest
                        }
                    )
                    .await
                    .unwrap(),
                    R::ClientApplied { revision: 2 }
                );
                assert!(ipc(
                    runtime.clone(),
                    C::ClientApply {
                        expected_revision: 1,
                        candidate_sha256: digest
                    }
                )
                .await
                .is_err());
                let mut stream = TcpStream::connect(listen).await.unwrap();
                stream
                    .write_all(
                        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                let mut response = vec![0; HTTP_OK.len()];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(response, HTTP_OK);
                stream.write_all(b"swap").await.unwrap();
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"swap");
                assert!(matches!(
                    ipc(runtime.clone(), C::ClientStatus).await.unwrap(),
                    R::ClientRunning {
                        revision: 2,
                        transport: 3,
                        ..
                    }
                ));
                // Apply deliberately retires the old client's policy lease.
                // Its established flows may finish, but new OPEN must fail.
                assert!(matches!(
                    managed_clients[0]
                        .open(Address::V4([127, 0, 0, 1]), target.port())
                        .await,
                    Err(ClientError::Open(ErrorCode::PolicyDenied))
                ));
                // Exercise signer rotation on a fresh independent H2 owner
                // instead of asking the retired runtime to admit new flows.
                let h2_profile = client_doc
                    .client
                    .profiles
                    .iter()
                    .find(|profile| profile.id == "native-h2")
                    .unwrap();
                let ProxyClient::Reality(fresh_h2) = load_client(h2_profile).await.unwrap() else {
                    panic!("wrong security mode");
                };
                managed_clients[0] = fresh_h2;
                for stream in &mut established {
                    stream.write_all(b"keep").await.unwrap();
                    stream.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"keep");
                }
            }
            let publication =
                crate::identity_publication::Publication::new(&bundle.join("publication.toml"))
                    .unwrap();
            let now = reference_health::unix_now().unwrap();
            let store = Store::new(&health).unwrap();
            let good = Evidence {
                h2_status: Some(200),
                h3_status: Some(200),
            };
            store
                .fixture_record(vec![Evidence::default(), good], now - 301)
                .unwrap();
            store
                .fixture_record(vec![Evidence::default(), good], now - 1)
                .unwrap();
            // The maintenance worker, not the test, performs the failover.
            // Both clients retain the original signed SNI until refresh.
            for managed in &managed_clients {
                for _ in 0..20 {
                    let generation = managed.generation().await.unwrap();
                    if generation.value.descriptor().active_reference == 1 {
                        break;
                    }
                    let _ = managed.refresh(&generation).await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                assert_eq!(
                    managed
                        .generation()
                        .await
                        .unwrap()
                        .value
                        .descriptor()
                        .active_reference,
                    1
                );
            }
            for stream in &mut established {
                stream.write_all(b"fail").await.unwrap();
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"fail");
            }
            let now = reference_health::unix_now().unwrap();
            let status = publication.inspect(now).unwrap();
            assert_eq!(status.active_reference, 1);
            publication
                .begin_rotation(
                    &successor_path,
                    status.snapshot_sha256,
                    bootstrap::fingerprint(successor.public_key()),
                    now,
                )
                .unwrap();
            for managed in &managed_clients {
                // Wait for the owner-scoped live publication poll, then
                // explicitly drive the same authenticated promotion path
                // that the background client worker uses.
                for _ in 0..20 {
                    let generation = managed.generation().await.unwrap();
                    if generation.value.signer() == successor.public_key() {
                        break;
                    }
                    assert_eq!(generation.value.signer(), old_signer);
                    let _ = managed.refresh(&generation).await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                let new = managed.generation().await.unwrap();
                assert_eq!(new.value.signer(), successor.public_key());
                // An actual new tunnel must complete on the new signer.
                let tunnel = managed
                    .open(Address::V4([127, 0, 0, 1]), target.port())
                    .await
                    .unwrap();
                drop(tunnel);
            }
            // Both already-established application tunnels still carry
            // bytes after the two transport pools have changed identity.
            for mut stream in established {
                stream.write_all(b"pong").await.unwrap();
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"pong");
            }
            for mut proxy in proxies {
                proxy.shutdown().await;
            }
            drop(managed_clients);
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            server.shutdown().await;
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            {
                drain.send(()).unwrap();
                acknowledged.await.unwrap();
                server.join_next().await.unwrap().unwrap().unwrap();
                // A fresh supervisor must reject a previously valid but
                // superseded publication, even after the old process exits.
                let path = bundle.join("publication.toml");
                let latest = std::fs::read(&path).unwrap();
                assert_ne!(initial_publication, latest);
                std::fs::write(&path, &initial_publication).unwrap();
                let (started, _ready) = tokio::sync::oneshot::channel();
                let (_drain, stop) = tokio::sync::oneshot::channel();
                let (draining, _acknowledged) = tokio::sync::oneshot::channel();
                let rejected = timeout(
                    Duration::from_secs(3),
                    crate::server::registered_reality_drain_fixture(
                        server_doc.clone(),
                        started,
                        stop,
                        draining,
                    ),
                )
                .await;
                std::fs::write(&path, latest).unwrap();
                assert!(matches!(
                    rejected,
                    Ok(Err(crate::server::ServerError::Config))
                ));

                // Restart using the exact durable health and publication
                // state. The two unopened profiles still pin revision 1.
                let (started, ready) = tokio::sync::oneshot::channel();
                let (drain, stop) = tokio::sync::oneshot::channel();
                let (draining, acknowledged) = tokio::sync::oneshot::channel();
                server.spawn(crate::server::registered_reality_drain_fixture(
                    server_doc, started, stop, draining,
                ));
                ready.await.unwrap();
                for id in ["split-h2", "split-h3"] {
                    let profile = client_doc
                        .client
                        .profiles
                        .iter()
                        .find(|profile| profile.id == id)
                        .unwrap();
                    let client = load_client(profile).await.unwrap();
                    let ProxyClient::Reality(managed) = &client else {
                        panic!("wrong security mode");
                    };
                    let old = managed.generation().await.unwrap();
                    assert_eq!(old.value.descriptor().revision, 1);
                    assert_eq!(old.value.descriptor().active_reference, 0);
                    assert_eq!(old.value.signer(), old_signer);
                    // Authenticate the old signer, fetch the latest
                    // announcement and verify successor TLS before CAS.
                    managed.refresh(&old).await.unwrap();
                    let current = managed.generation().await.unwrap();
                    assert_eq!(current.value.signer(), successor.public_key());
                    assert_eq!(current.value.descriptor().active_reference, 1);
                    assert!(current.value.descriptor().revision > 1);
                    let tunnel = client
                        .open(Address::V4([127, 0, 0, 1]), target.port())
                        .await
                        .unwrap();
                    let (mut app, local) = paired().await;
                    let relay = tokio::spawn(tunnel.relay(local));
                    app.write_all(b"back").await.unwrap();
                    let mut bytes = [0; 4];
                    app.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"back");
                    app.shutdown().await.unwrap();
                    let mut tail = Vec::new();
                    app.read_to_end(&mut tail).await.unwrap();
                    assert!(tail.is_empty());
                    relay.await.unwrap().unwrap();
                }
                drain.send(()).unwrap();
                acknowledged.await.unwrap();
                server.join_next().await.unwrap().unwrap().unwrap();
            }
            echo_tasks.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[test]
    fn runtime_file_reference_refuses_non_native_or_oversized_input() {
        use std::fs;

        let name = format!("theia-runtime-input-{}", std::process::id());
        let path = std::env::temp_dir().join(name);
        fs::write(&path, [b'x'; 44]).unwrap();
        let reference = format!("file:{}", path.display());
        assert!(load_file(&reference, 43, true).is_err());
        assert!(load_file("file:relative-token", 43, true).is_err());
        assert!(load_file("https://example.invalid/ca", CA_LIMIT, false).is_err());
        #[cfg(windows)]
        assert!(load_file(r"file:\\server\share\token", 43, true).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn negative_cache_expires_and_zero_ttl_disables_it() {
        let mut cache = NegativeCache::default();
        let route = Some("192.0.2.1:0".parse().unwrap());
        let now = Instant::now();
        let ttl = Duration::from_secs(5);
        let (generation, cached) = cache.observe(route, now);
        assert!(!cached);
        assert!(cache.record(generation, now, ttl));
        assert!(cache.observe(route, now + Duration::from_secs(4)).1);
        let (next, cached) = cache.observe(route, now + ttl);
        assert_ne!(next, generation);
        assert!(!cached);
        assert!(!cache.record(next, now + ttl, Duration::ZERO));
        assert!(!cache.observe(route, now + ttl).1);
    }

    #[test]
    fn recheck_deadline_is_not_extended_and_only_one_generation_can_claim_it() {
        let mut cache = NegativeCache::default();
        let route = Some("192.0.2.1:0".parse().unwrap());
        let now = Instant::now();
        let ttl = Duration::from_secs(5);
        let deadline = now + ttl;
        let (generation, _) = cache.observe(route, now);
        assert!(cache.record(generation, now, ttl));
        assert!(!cache.record(generation, now + Duration::from_secs(1), ttl));
        assert_eq!(cache.expires, Some(deadline));
        assert_eq!(cache.begin_recheck(generation, deadline, route, now), None);
        let next = cache
            .begin_recheck(generation, deadline, route, deadline)
            .unwrap();
        assert_ne!(generation, next);
        assert_eq!(
            cache.begin_recheck(generation, deadline, route, deadline),
            None
        );
        assert!(!cache.record(generation, deadline, ttl));
        assert!(cache.record(next, deadline, ttl));
        let other = Some("198.51.100.1:0".parse().unwrap());
        assert_eq!(
            cache.begin_recheck(next, deadline + ttl, other, deadline + ttl),
            None
        );
        assert!(cache.expires.is_none());
    }

    #[tokio::test]
    async fn auto_retries_only_two_silent_pre_authentication_attempts() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let token = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
        let auto = AutoClient {
            h2: Arc::new(
                H2Client::new(&remote.to_string(), "localhost", &token, roots.clone()).unwrap(),
            ),
            h3: Arc::new(H3Client::new(remote, "localhost", &token, roots).unwrap()),
            ttl: Duration::from_secs(900),
            negative: Mutex::new(NegativeCache::default()),
            cache_changed: Notify::new(),
            recheck_gate: tokio::sync::Mutex::new(()),
        };
        for error in [
            ClientError::Tls,
            ClientError::Unauthorized,
            ClientError::Protocol,
            ClientError::Timeout,
            ClientError::Io,
            ClientError::Http3,
            ClientError::Rejected(429),
        ] {
            let (generation, _) = auto.observe().unwrap();
            let mut calls = 0;
            let result = auto
                .attempt_h3(generation, || {
                    calls += 1;
                    std::future::ready(Err::<(), _>(error))
                })
                .await;
            assert!(matches!(result, Err(actual) if actual == error));
            assert_eq!(calls, 1);
            assert!(!auto.observe().unwrap().1);
        }
        let (generation, _) = auto.observe().unwrap();
        let mut calls = 0;
        let result = auto
            .attempt_h3(generation, || {
                calls += 1;
                std::future::ready(Err::<(), _>(ClientError::QuicUnreachable))
            })
            .await;
        assert!(matches!(result, Ok(None)));
        assert_eq!(calls, AUTO_QUIC_ATTEMPTS);
        assert!(auto.observe().unwrap().1);
        auto.complete(generation, false).unwrap();
        let (generation, _) = auto.observe().unwrap();
        let mut calls = 0;
        let result = auto
            .attempt_h3(generation, || {
                calls += 1;
                std::future::ready(Err::<(), _>(ClientError::QuicEndpointNetworkRefused))
            })
            .await;
        assert!(matches!(result, Ok(None)));
        assert_eq!(calls, 1);
        assert!(auto.observe().unwrap().1);
    }

    #[tokio::test]
    async fn idle_profile_rechecks_quic_without_opening_an_application_tunnel() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server = crate::quinn_reference::server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![cert.cert.der().clone()],
            key.into(),
        )
        .unwrap();
        let remote = server.local_addr().unwrap();
        let token = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
        let auto = AutoClient {
            h2: Arc::new(
                H2Client::new(&remote.to_string(), "localhost", &token, roots.clone()).unwrap(),
            ),
            h3: Arc::new(H3Client::new(remote, "localhost", &token, roots).unwrap()),
            ttl: Duration::from_millis(100),
            negative: Mutex::new(NegativeCache::default()),
            cache_changed: Notify::new(),
            recheck_gate: tokio::sync::Mutex::new(()),
        };
        let (generation, _) = auto.observe().unwrap();
        assert!(auto.complete(generation, true).unwrap());
        let witness = async {
            // No local CONNECT or SOCKS request is made. Only maintenance
            // can initiate this connection.
            let incoming = server.accept().await.unwrap();
            let _ = incoming.await;
            loop {
                {
                    let cache = auto.negative.lock().unwrap();
                    if cache.generation != generation.wrapping_add(1) && cache.expires.is_none() {
                        assert_ne!(cache.generation, generation);
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        timeout(Duration::from_secs(15), async {
            tokio::select! {
                result = auto.maintain() => panic!("maintenance exited: {result:?}"),
                () = witness => {}
            }
        })
        .await
        .expect("idle profile must recheck its expired negative cache");
    }

    #[test]
    fn route_change_rejects_stale_results_and_unknown_route_disables_cache() {
        let mut cache = NegativeCache::default();
        let now = Instant::now();
        let ttl = Duration::from_secs(900);
        let a = Some("192.0.2.1:0".parse().unwrap());
        let b = Some("198.51.100.1:0".parse().unwrap());
        let (old, _) = cache.observe(a, now);
        cache.record(old, now, ttl);
        assert!(cache.observe(a, now).1);
        let (new, cached) = cache.observe(b, now);
        assert_ne!(old, new);
        assert!(!cached);
        cache.record(old, now, ttl);
        assert!(!cache.observe(b, now).1);
        cache.record(new, now, ttl);
        assert!(cache.observe(b, now).1);
        let (unknown, cached) = cache.observe(None, now);
        assert!(!cached);
        cache.record(unknown, now, ttl);
        assert!(!cache.observe(None, now).1);
        assert!(!cache.observe(b, now).1);
    }

    #[test]
    fn same_ip_network_epoch_invalidates_quic_failure() {
        let mut cache = NegativeCache::default();
        let now = Instant::now();
        let source = "192.0.2.1:0".parse().unwrap();
        let a = Some(crate::network_scope::Scope::fixture(source, 1));
        let b = Some(crate::network_scope::Scope::fixture(source, 2));
        let (old, _) = cache.observe(a, now);
        assert!(cache.record(old, now, Duration::from_secs(900)));
        let (new, cached) = cache.observe(b, now);
        assert_ne!(old, new);
        assert!(!cached);
        assert!(!cache.record(old, now, Duration::from_secs(900)));
    }

    #[test]
    fn successful_or_terminal_probe_invalidates_prior_failure_generation() {
        let mut cache = NegativeCache::default();
        let now = Instant::now();
        let route = Some("127.0.0.1:0".parse().unwrap());
        let (old, _) = cache.observe(route, now);
        cache.invalidate();
        cache.record(old, now, Duration::from_secs(900));
        assert!(!cache.observe(route, now).1);
    }

    #[test]
    fn route_source_uses_os_loopback_route_without_application_traffic() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_nonblocking(true).unwrap();
        let remote = peer.local_addr().unwrap();
        assert_eq!(route_source(remote), Some("127.0.0.1:0".parse().unwrap()));
        assert_eq!(
            peer.recv_from(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    pub(super) async fn paired() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (left, right) = tokio::join!(TcpStream::connect(address), listener.accept());
        (left.unwrap(), right.unwrap().0)
    }

    #[tokio::test]
    async fn http_connect_validation_preserves_pipelined_bytes_and_rejects_ambiguous_requests() {
        let (mut client, mut proxy) = paired().await;
        client
            .write_all(b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\nsentinel")
            .await
            .unwrap();
        assert_eq!(
            http_target(&mut proxy).await.unwrap(),
            (Address::V6(Ipv6Addr::LOCALHOST.octets()), 443)
        );
        let mut trailing = [0; 8];
        proxy.read_exact(&mut trailing).await.unwrap();
        assert_eq!(&trailing, b"sentinel");
        let cases: &[(&[u8], &[u8])] = &[
            (b"GET example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n",HTTP_METHOD),
            (b"CONNECT example.org:443 HTTP/1.1\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.1\r\nHost: other.org:443\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nHost: example.org:443\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nContent-Length: 0\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nTransfer-Encoding: chunked\r\n\r\n",HTTP_BAD),
            (b"CONNECT [bad]:443 HTTP/1.0\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:0 HTTP/1.0\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:65536 HTTP/1.0\r\n\r\n",HTTP_BAD),
            (b"CONNECT invalid HTTP/1.0\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/2\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.1\r\nHost: \xff\r\n\r\n",HTTP_BAD),
            (b"CONNECT example.org:443 HTTP/1.0\r\nbroken\r\n\r\n",HTTP_BAD),
        ];
        for (request, error) in cases {
            let (mut client, mut proxy) = paired().await;
            client.write_all(request).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(http_target(&mut proxy).await, Err(*error));
        }
        let (mut client, mut proxy) = paired().await;
        client.write_all(&[b'x'; HEADER_LIMIT]).await.unwrap();
        assert_eq!(http_target(&mut proxy).await, Err(HTTP_BAD));
    }

    #[tokio::test]
    async fn socks_connect_rejects_bad_methods_addresses_commands_and_truncation() {
        let (mut client, mut proxy) = paired().await;
        client.write_all(&[5, 1, 2]).await.unwrap();
        assert_eq!(socks_target(&mut proxy).await, Err(ClientError::Protocol));
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [5, 255]);
        for (request, reply) in [
            (vec![4, 1, 0, 1], 1),
            (vec![5, 1, 1, 1], 1),
            (vec![5, 2, 0, 1], 7),
            (vec![5, 1, 0, 9], 8),
            (vec![5, 1, 0, 3, 1, 255], 8),
            (vec![5, 1, 0, 1, 127, 0, 0, 1, 0, 0], 8),
        ] {
            let (mut client, mut proxy) = paired().await;
            client.write_all(&[5, 1, 0]).await.unwrap();
            client.write_all(&request).await.unwrap();
            assert_eq!(socks_target(&mut proxy).await, Err(ClientError::Protocol));
            let mut response = [0; 12];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..2], &[5, 0]);
            assert_eq!(&response[2..], &[5, reply, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
        let mut v6 = vec![5, 1, 0, 5, 1, 0, 4];
        v6.extend(Ipv6Addr::LOCALHOST.octets());
        v6.extend(443u16.to_be_bytes());
        v6.extend(b"tail");
        let (mut client, mut proxy) = paired().await;
        client.write_all(&v6).await.unwrap();
        assert_eq!(
            socks_target(&mut proxy).await.unwrap(),
            (Address::V6(Ipv6Addr::LOCALHOST.octets()), 443)
        );
        let mut tail = [0; 4];
        proxy.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"tail");
        for prefix in [
            vec![4, 0],
            vec![5, 0],
            vec![5, 1, 0, 5, 1, 0, 1, 127],
            vec![5, 1, 0, 5, 1, 0, 4, 0],
            vec![5, 1, 0, 5, 1, 0, 3, 4, b'a'],
        ] {
            let (mut client, mut proxy) = paired().await;
            client.write_all(&prefix).await.unwrap();
            client.shutdown().await.unwrap();
            assert!(socks_target(&mut proxy).await.is_err());
        }
    }

    #[tokio::test]
    async fn real_local_proxy_modes_validate_credentials_and_relay_over_both_transports() {
        use crate::{
            config::{Inbound, ServerPolicy, User},
            server::ServerContext,
        };
        use sha2::{Digest, Sha256};
        let directory = std::env::temp_dir().join(format!(
            "theia-local-proxy-modes-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = directory.join("ca.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        let token = [42; 32];
        let secret =
            crate::client_import::PrivateBearer::create(&directory.join("client.toml"), &token)
                .unwrap();
        let Config::Client(doc) =
            config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client fixture");
        };
        let mut profile = doc.client.profiles[0].clone();
        profile.auth_token = secret.reference().unwrap();
        profile.server_name = "localhost".into();
        profile.tls_ca = Some(format!("file:{}", cert_path.display()));
        profile.transport = Transport::H2;
        profile.server = "127.0.0.1:443".into();
        profile.xhttp_mode = Some(XhttpMode::StreamOne);
        let mut invalid = profile.clone();
        invalid.tls_ca = None;
        assert!(load_client(&invalid).await.is_err());
        invalid = profile.clone();
        invalid.auth_token = "file:relative".into();
        assert!(load_client(&invalid).await.is_err());
        invalid = profile.clone();
        invalid.security_mode = SecurityMode::SmartReality;
        assert!(load_client(&invalid).await.is_err());
        invalid = profile.clone();
        invalid.security_mode = SecurityMode::PinnedCertV1;
        assert!(load_client(&invalid).await.is_err());
        invalid.xhttp_mode = None;
        invalid.transport = Transport::H3;
        assert!(load_client(&invalid).await.is_err());
        invalid.transport = Transport::H2;
        assert!(load_client(&invalid).await.is_err());
        let mut pinned = profile.clone();
        pinned.xhttp_mode = None;
        pinned.security_mode = SecurityMode::PinnedCertStreamUpV1;
        assert!(load_client(&pinned).await.is_err());
        let mut automatic_mode = profile.clone();
        automatic_mode.xhttp_mode = Some(XhttpMode::Auto);
        assert!(matches!(
            load_client(&automatic_mode).await,
            Ok(ProxyClient::Direct(d)) if matches!(&d.carrier, Carrier::H2(_))
        ));
        automatic_mode.transport = Transport::Auto;
        assert!(matches!(
            load_client(&automatic_mode).await,
            Ok(ProxyClient::Direct(d)) if matches!(&d.carrier, Carrier::Auto(_))
        ));

        let inbound = Inbound {
            id: "edge".into(),
            path_prefix: Some(crate::split_http::EXAMPLE_PREFIX.into()),
            allowed_user_ids: vec!["client".into()],
            h2_listen: "127.0.0.1:0".into(),
            quic_listen: "127.0.0.1:0".into(),
            server_name: "localhost".into(),
            tls_cert: "unused".into(),
            tls_key: "unused".into(),
            security_mode: Default::default(),
            reality: None,
        };
        let user = User {
            id: "client".into(),
            token_sha256: format!("{:x}", Sha256::digest(token)),
            disabled: false,
        };
        let policy = ServerPolicy {
            routing: Some(crate::routing::Settings {
                revision: 2,
                geodata_directory: None,
                datasets: None,
                rules: vec![
                    crate::routing::Rule {
                        name: "local direct".into(),
                        action: Action::Direct,
                        domains: vec!["full:localhost".into()],
                        ips: vec![],
                        applications: vec![],
                    },
                    crate::routing::Rule {
                        name: "blocked".into(),
                        action: Action::Blocked,
                        domains: vec!["full:blocked.invalid".into()],
                        ips: vec![],
                        applications: vec![],
                    },
                    crate::routing::Rule {
                        name: "dpi fallback".into(),
                        action: Action::DirectDpi,
                        domains: vec![],
                        ips: vec!["127.0.0.1/32".into()],
                        applications: vec![],
                    },
                ],
            }),
            allow_private_ips: true,
            max_connections_per_user: 8,
            max_connections_total: 8,
            connect_timeout_ms: 1500,
        };
        let context = Arc::new(ServerContext::new(
            &inbound,
            std::slice::from_ref(&user),
            &policy,
        ));
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        let h2 = tokio::spawn(crate::server::serve(
            tcp,
            tokio_rustls::TlsAcceptor::from(Arc::new(tls.clone())),
            context.clone(),
        ));
        let quic = crate::quic_transport::server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        let quic_addr = quic.local_addr().unwrap();
        let h3 = tokio::spawn(crate::h3_server::serve(quic, context));

        timeout(Duration::from_secs(50), async {
            for (transport, remote, http) in [
                (Transport::H2, tcp_addr, true),
                (Transport::H3, quic_addr, false),
                (Transport::Auto, quic_addr, true),
            ] {
                profile.transport = transport;
                profile.server = remote.to_string();

                // The exact same production H2/H3 clients now consume
                // compact key trust without opening a PEM file.
                let anchor = crate::own_tls::Anchor::from_bytes(Sha256::digest(cert.cert.der()).into());
                let mut key_profile = profile.clone();
                key_profile.tls_ca = Some(anchor.reference());
                let key_client = load_client(&key_profile).await.unwrap();
                assert_eq!(key_client.routing_policy().await.unwrap().manifest().revision, 2);
                drop(key_client);

                key_profile.tls_ca = Some(crate::own_tls::Anchor::from_bytes([0x99; 32]).reference());
                let wrong = load_client(&key_profile).await.unwrap();
                assert!(wrong.routing_policy().await.is_err(), "wrong anchor must reject the authenticated exchange");
                drop(wrong);

                let proxy_client = load_client(&profile).await.unwrap();
                let snapshot = proxy_client.routing_policy().await.unwrap();
                assert_eq!(snapshot.manifest().revision, 2);
                assert_eq!(
                    snapshot
                        .policy()
                        .matching_action(None, Some("127.0.0.1".parse().unwrap()))
                        .unwrap(),
                    Some(Action::DirectDpi)
                );
                let dpi_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let dpi_port = dpi_listener.local_addr().unwrap().port();
                let dpi_tunnel = proxy_client
                    .open(Address::V4([127, 0, 0, 1]), dpi_port)
                    .await
                    .unwrap();
                assert!(matches!(
                    dpi_tunnel.tunnel,
                    ProxyTunnel::H2(_) | ProxyTunnel::H3(_)
                ));
                let _dpi_accepted = dpi_listener.accept().await.unwrap();
                drop(dpi_tunnel);
                drop(_dpi_accepted);
                // Exercise deferred fallback on both carriers without making
                // any public connections or weakening production IP checks.
                let fallback = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let fallback_port = fallback.local_addr().unwrap().port();
                let (origin, mut observer) = paired().await;
                let (mut app, local) = paired().await;
                let ProxyClient::Direct(client) = &proxy_client else {
                    panic!("expected own TLS")
                };
                let route = ProxyTunnel::Dpi(Box::new(DpiRoute {
                    tunnel: crate::routing::dpi::Tunnel::fixture(origin, "example.org"),
                    observed: Some(client.last_open.clone()),
                    carrier: client.carrier.clone(),
                    address: Address::V4([127, 0, 0, 1]),
                    port: fallback_port,
                }));
                let task = tokio::spawn(route.relay(local));
                app.write_all(b"not TLS, exact prefix").await.unwrap();
                app.shutdown().await.unwrap();
                let (mut destination, _) = fallback.accept().await.unwrap();
                let mut bytes = Vec::new();
                destination.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"not TLS, exact prefix");
                destination.write_all(b"ok").await.unwrap();
                destination.shutdown().await.unwrap();
                let mut reply = Vec::new();
                app.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"ok");
                task.await.unwrap().unwrap();
                let mut leaked = Vec::new();
                observer.read_to_end(&mut leaked).await.unwrap();
                assert!(leaked.is_empty());
                assert!(matches!(
                    proxy_client
                        .open(Address::Dns("blocked.invalid".into()), 443)
                        .await,
                    Err(ClientError::Open(ErrorCode::PolicyDenied))
                ));
                let direct_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let direct_port = direct_listener.local_addr().unwrap().port();
                let tunnel = proxy_client
                    .open(Address::Dns("localhost".into()), direct_port)
                    .await
                    .unwrap();
                assert!(matches!(tunnel.tunnel, ProxyTunnel::Direct(_)));
                let _accepted = direct_listener.accept().await.unwrap();
                if let ProxyClient::Direct(client) = &proxy_client {
                    assert!(matches!(
                        client
                            .carrier
                            .open(Address::Dns("localhost".into()), direct_port)
                            .await,
                        Err(ClientError::Open(ErrorCode::PolicyDenied))
                    ));
                }
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                if transport == Transport::H2 {
                    use crate::routing::{
                        packet::{FlowKey, Transport as PacketTransport},
                        PacketAction,
                    };
                    // Native packets have unknown domain evidence. Use an
                    // independent authenticated policy, not earlier IP rules
                    // that would prevent the ordinary proxy's domain decision
                    // before DNS resolution, or earlier domain rules that
                    // would prevent native IP-only authorization.
                    let mut native_policy = policy.clone();
                    native_policy.routing.as_mut().unwrap().rules = vec![
                        crate::routing::Rule {
                            name: "native test pass".into(),
                            action: Action::Direct,
                            domains: vec![],
                            ips: vec!["192.0.2.0/24".into()],
                            applications: vec![],
                        },
                        crate::routing::Rule {
                            name: "native test redirect".into(),
                            action: Action::Allowed,
                            domains: vec![],
                            ips: vec!["198.51.100.0/24".into()],
                            applications: vec![],
                        },
                        crate::routing::Rule {
                            name: "native test drop".into(),
                            action: Action::Blocked,
                            domains: vec![],
                            ips: vec!["203.0.113.0/24".into()],
                            applications: vec![],
                        },
                    ];
                    let native_context = Arc::new(ServerContext::new(
                        &inbound,
                        std::slice::from_ref(&user),
                        &native_policy,
                    ));
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let native_remote = listener.local_addr().unwrap();
                    let native_server = tokio::spawn(crate::server::serve(
                        listener,
                        tokio_rustls::TlsAcceptor::from(Arc::new(tls.clone())),
                        native_context,
                    ));
                    let path = directory.join("native.toml");
                    let mut native = doc.clone();
                    native.client.active_profile = profile.id.clone();
                    native.client.profiles = vec![profile.clone()];
                    native.client.profiles[0].server = native_remote.to_string();
                    config::atomic_write(&path, &Config::Client(native)).unwrap();
                    let ingress = NativeIngress::prepare(&path).await.unwrap();
                    assert_eq!(ingress.runtime.capture_state.reported(), 1);
                    assert!(
                        NativeIngress::prepare(&path).await.is_err(),
                        "exclusive native owner"
                    );
                    ingress.runtime.capture_state.ready().unwrap();
                    assert!(ingress.ensure_running().is_ok());
                    let source = "10.0.0.2:40001".parse().unwrap();
                    let key = |destination: &str, transport| FlowKey {
                        source,
                        destination: destination.parse().unwrap(),
                        transport,
                        interface: 7,
                    };
                    for destination in [
                        "127.0.0.1:443",
                        "0.0.0.0:443",
                        "224.0.0.1:443",
                        "192.0.2.1:0",
                        "10.0.0.2:40001",
                        "192.0.2.1:443",
                        "203.0.113.1:443",
                    ] {
                        assert!(
                            matches!(
                                ingress
                                    .redirect(key(destination, PacketTransport::Tcp))
                                    .await,
                                Err(ClientError::Open(ErrorCode::PolicyDenied))
                            ),
                            "{destination}"
                        );
                    }
                    let (_, flow, address) = ingress
                        .redirect(key("198.51.100.1:443", PacketTransport::Tcp))
                        .await
                        .unwrap();
                    assert_eq!(address, Address::V4([198, 51, 100, 1]));
                    assert!(flow.commit(PacketAction::Redirect).is_ok());
                    drop(flow);
                    let (_, local) = paired().await;
                    assert!(matches!(
                        ingress
                            .relay_terminated_tcp(
                                key("198.51.100.1:443", PacketTransport::Udp),
                                local
                            )
                            .await,
                        Err(ClientError::Protocol)
                    ));
                    let (_tx, up) = tokio::sync::mpsc::channel(1);
                    let (down, _rx) = tokio::sync::mpsc::channel(1);
                    assert!(matches!(
                        ingress
                            .relay_terminated_udp(
                                key("198.51.100.1:443", PacketTransport::Tcp),
                                up,
                                down
                            )
                            .await,
                        Err(ClientError::Protocol)
                    ));
                    #[cfg(target_os = "linux")]
                    {
                        use crate::routing::packet::PacketMeta;
                        let meta = |destination, transport, tcp_flags| PacketMeta {
                            flow: key(destination, transport),
                            payload_len: 0,
                            tcp_flags,
                        };
                        let first = meta("192.0.2.1:443", PacketTransport::Tcp, Some(0x10));
                        assert_eq!(ingress.raw_verdict(first).await, PacketAction::Drop);
                        let syn = PacketMeta {
                            tcp_flags: Some(2),
                            ..first
                        };
                        assert_eq!(ingress.raw_verdict(syn).await, PacketAction::Pass);
                        assert_eq!(ingress.raw_verdict(first).await, PacketAction::Pass);
                        assert_eq!(
                            ingress
                                .raw_verdict(meta("192.0.2.2:53", PacketTransport::Udp, None))
                                .await,
                            PacketAction::Pass
                        );
                        for destination in [
                            "0.0.0.0:443",
                            "224.0.0.1:443",
                            "198.51.100.1:443",
                            "203.0.113.1:443",
                        ] {
                            assert_eq!(
                                ingress
                                    .raw_verdict(meta(destination, PacketTransport::Tcp, Some(2)))
                                    .await,
                                PacketAction::Drop
                            );
                        }
                        assert!(ingress
                            .prepare_stun_lab(
                                key("192.0.2.1:3478", PacketTransport::Tcp),
                                "example.org"
                            )
                            .await
                            .is_err());
                    }
                    ingress.shutdown();
                    assert_eq!(ingress.runtime.capture_state.reported(), 3);
                    assert!(ingress.ensure_running().is_err());
                    ingress.stopped().await;
                    let (_tx, up) = tokio::sync::mpsc::channel(1);
                    let (down, _rx) = tokio::sync::mpsc::channel(1);
                    assert!(matches!(
                        ingress
                            .relay_terminated_udp(
                                key("198.51.100.1:443", PacketTransport::Udp),
                                up,
                                down
                            )
                            .await,
                        Err(ClientError::Open(ErrorCode::PolicyDenied))
                    ));
                    drop(ingress);
                    // A failed preflight releases the exclusive owner.
                    assert!(NativeIngress::prepare(&directory.join("missing.toml"))
                        .await
                        .is_err());
                    let owner = NativeOwner::acquire().unwrap();
                    drop(owner);
                    native_server.abort();
                }
                udp_prewrite_fallback_fixture(&proxy_client).await;
                udp_revoked_fallback_fixture(&proxy_client).await;
                udp_socks_fixture(&proxy_client).await;
                let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = target.local_addr().unwrap().port();
                let echo = tokio::spawn(async move {
                    let (mut stream, _) = target.accept().await.unwrap();
                    let mut bytes = Vec::new();
                    stream.read_to_end(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"byte-exact proxy");
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
                let (mut app, local) = paired().await;
                let proxy =
                    tokio::spawn(async move { handle(local, http, &proxy_client, 1).await });
                if http {
                    app.write_all(
                        format!(
                            "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                    let mut reply = vec![0; HTTP_OK.len()];
                    app.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply, HTTP_OK);
                } else {
                    let mut request = vec![5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1];
                    request.extend(port.to_be_bytes());
                    app.write_all(&request).await.unwrap();
                    let mut reply = [0; 12];
                    app.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                }
                app.write_all(b"byte-exact proxy").await.unwrap();
                app.shutdown().await.unwrap();
                let mut result = Vec::new();
                app.read_to_end(&mut result).await.unwrap();
                assert_eq!(&result, b"byte-exact proxy");
                proxy.await.unwrap().unwrap();
                echo.await.unwrap();
            }
        })
        .await
        .unwrap();
        h2.abort();
        h3.abort();
    }
}
