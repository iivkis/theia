//! Local loopback-only CONNECT and SOCKS5 listeners for H2, H3 or conservative QUIC-first auto mode.
//! No system proxy changes, destination DNS lookups or live tunnel migration.
use crate::{
    client::{error_kind, ClientError, H2Client, Tunnel},
    config::{self, Config, Profile, Transport, XhttpMode},
    diagnostics::{self, Value},
    h3_client::{H3Client, H3Tunnel},
    protocol::{self, Address, ErrorCode, Frame},
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

async fn load_client(profile: &Profile) -> Result<ProxyClient, ClientError> {
    load_client_with_budget(profile, crate::connection_pool::profile_budget()).await
}

async fn load_client_with_budget(
    profile: &Profile,
    budget: Arc<Semaphore>,
) -> Result<ProxyClient, ClientError> {
    match profile.security_mode {
        SecurityMode::SmartReality
            if profile.reality_profile.is_some() && profile.tls_ca.is_none() =>
        {
            return RealityClient::prepare_with_budget(profile, budget)
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
    let cert = load_file(
        profile
            .tls_ca
            .as_deref()
            .ok_or(ClientError::Configuration)?,
        CA_LIMIT,
        false,
    )?;
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(cert.as_slice())) {
        roots
            .add(cert.map_err(|_| ClientError::Configuration)?)
            .map_err(|_| ClientError::Configuration)?;
    }
    let token = read_token(profile)?;
    if roots.is_empty() {
        return Err(ClientError::Configuration);
    }
    let mode = profile.effective_xhttp_mode();
    let stream_up = mode == XhttpMode::StreamUp;
    let auto_xhttp = mode == XhttpMode::Auto;
    let ttl = Duration::from_secs(u64::from(profile.quic_negative_cache_ttl_s));
    match profile.transport {
        Transport::H2 => {
            let endpoint = resolve_server(profile).await?.to_string();
            let client = H2Client::new(&endpoint, &profile.server_name, &token, roots)?
                .with_path_prefix(prefix)?
                .with_own_tls_policy()?
                .with_stream_up(stream_up)?;
            let client = if auto_xhttp {
                client.with_auto_stream_up(ttl)?
            } else {
                client
            };
            Ok(ProxyClient::direct(Carrier::from_options(
                Some(Arc::new(client.with_connection_pool())),
                None,
                ttl,
                budget,
            )?))
        }
        Transport::H3 | Transport::Auto => {
            // Resolve the configured server only, never the requested target.
            let remote = resolve_server(profile).await?;
            let h3 = H3Client::new(remote, &profile.server_name, &token, roots.clone())?
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
                return Ok(ProxyClient::direct(Carrier::from_options(
                    None,
                    Some(h3),
                    ttl,
                    budget,
                )?));
            }
            // Both carriers use the same resolved endpoint. Do not resolve
            // the hostname again during fallback; retain the configured SNI,
            // trust anchors, certificate pin and authorization unchanged.
            let h2 = H2Client::new(&remote.to_string(), &profile.server_name, &token, roots)?
                .with_path_prefix(prefix)?
                .with_own_tls_policy()?
                .with_stream_up(stream_up)?;
            let h2 = h2.with_connection_pool();
            let h2 = Arc::new(if auto_xhttp {
                h2.with_auto_stream_up(ttl)?
            } else {
                h2
            });
            Ok(ProxyClient::direct(Carrier::from_options(
                Some(h2),
                Some(h3),
                ttl,
                budget,
            )?))
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
    last_open: std::sync::atomic::AtomicU8,
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
    last_open: std::sync::atomic::AtomicU8,
    last_refresh: std::sync::atomic::AtomicU8,
}
pub(crate) struct RealityClient {
    profile: Profile,
    remote: SocketAddr,
    budget: Arc<Semaphore>,
    current: tokio::sync::Mutex<Arc<RealityGeneration>>,
    changed: Notify,
}
impl RealityClient {
    fn now() -> Result<u64, ClientError> {
        crate::reference_health::unix_now().map_err(|_| ClientError::Tls)
    }
    async fn prepare_with_budget(
        profile: &Profile,
        budget: Arc<Semaphore>,
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
        Ok(Self {
            profile: profile.clone(),
            remote,
            budget,
            current: tokio::sync::Mutex::new(Arc::new(first)),
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
            last_open: std::sync::atomic::AtomicU8::new(0),
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
    async fn open(&self, address: Address, port: u16) -> Result<ProxyTunnel, ClientError> {
        let generation = self.generation().await?;
        let result = generation.carrier.open(address, port).await;
        if let Ok(tunnel) = &result {
            generation
                .last_open
                .store(tunnel.open_code(), std::sync::atomic::Ordering::Relaxed);
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
    H2(Box<Tunnel>),
    H3(Box<H3Tunnel>),
}

impl Carrier {
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

impl ProxyClient {
    fn direct(carrier: Carrier) -> Self {
        Self::Direct(Arc::new(DirectClient {
            carrier,
            last_open: std::sync::atomic::AtomicU8::new(0),
        }))
    }

    async fn runtime_report(&self) -> String {
        match self {
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
        }
    }

    fn profile_budget(&self) -> Arc<Semaphore> {
        match self {
            Self::Direct(client) => client.carrier.profile_budget(),
            Self::Reality(client) => client.budget.clone(),
        }
    }

    async fn open(&self, address: Address, port: u16) -> Result<ProxyTunnel, ClientError> {
        match self {
            Self::Direct(client) => {
                let tunnel = client.carrier.open(address, port).await?;
                client
                    .last_open
                    .store(tunnel.open_code(), std::sync::atomic::Ordering::Relaxed);
                Ok(tunnel)
            }
            Self::Reality(client) => client.open(address, port).await,
        }
    }
    async fn maintain(&self) -> Result<(), ClientError> {
        match self {
            Self::Direct(client) => client.carrier.maintain().await,
            Self::Reality(client) => client.maintain().await,
        }
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
            Self::H2(t) => (2, t.opened_stream_up()),
            Self::H3(t) => (3, t.opened_stream_up()),
        };
        (transport << 2) | if up { 2 } else { 1 }
    }

    async fn relay(self, socket: TcpStream) -> Result<(), ClientError> {
        match self {
            Self::H2(tunnel) => tunnel.relay(socket).await,
            Self::H3(tunnel) => tunnel.relay(socket).await,
        }
    }
}

pub async fn run_file(config_path: &Path) -> Result<(), ClientError> {
    run_file_inner(config_path, false).await
}

/// Windows-only, explicitly confirmed user WinINet proxy operation. The
/// settings are touched ONLY after strict client/TLS preflight and BOTH local
/// loopback TCP listeners are bound, never on plain client run or server run.
#[cfg(windows)]
pub async fn run_file_with_system_proxy(config_path: &Path) -> Result<(), ClientError> {
    run_file_inner(config_path, true).await
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
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) struct ClientRuntime {
    path: std::path::PathBuf,
    slot: tokio::sync::watch::Sender<Arc<ClientView>>,
    // Bound one staging operation per process, with no commit on cancellation.
    stage: tokio::sync::Mutex<()>,
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
        Arc::new(Self {
            path,
            slot,
            stage: tokio::sync::Mutex::new(()),
        })
    }
    pub(crate) async fn status(&self) -> (u64, [u8; 32], u64, u8, u8, bool) {
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
            load_client_with_budget(next, previous.client.profile_budget()).await?
        } else {
            load_client(next).await?
        };
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
    let (http, socks, client) = prepare_proxy(&document).await?;
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

/// Shared startup preflight: never changes the OS proxy or claims an
/// authenticated remote tunnel merely because the listeners bind.
async fn prepare_proxy(
    document: &config::ClientDocument,
) -> Result<(TcpListener, TcpListener, ProxyClient), ClientError> {
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
    let client = load_client(profile).await?;
    crate::diag!(Info, "client.proxy", "transport_preflight_passed");
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
        let (http, socks, client) = prepare_proxy(&document).await?;
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
        let (http, socks, client) = prepare_proxy(&document).await?;
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

async fn socks_target(socket: &mut TcpStream) -> Result<(Address, u16), ClientError> {
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
    if request[1] != 1 {
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
    match validate_target(address, port) {
        Ok(target) => Ok(target),
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
        timeout(NEGOTIATE_TIMEOUT, socks_target(&mut socket))
            .await
            .map_err(|_| ClientError::Timeout)??
    };
    crate::diag!(
        Debug,
        "client.proxy",
        "negotiation_validated",
        "session" = Value::Count(session_id)
    );
    match client.open(address, port).await {
        Ok(tunnel) => {
            crate::diag!(
                Debug,
                "client.proxy",
                "remote_open_ok",
                "session" = Value::Count(session_id)
            );
            // This is the only success path; open() already verified OPEN_OK.
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
                    tunnel.rebind_for_test(rebind).unwrap();
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
        let server = crate::quic_transport::server_endpoint(
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

    async fn paired() -> (TcpStream, TcpStream) {
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
            routing: None,
            allow_private_ips: true,
            max_connections_per_user: 8,
            max_connections_total: 8,
            connect_timeout_ms: 1500,
        };
        let context = Arc::new(ServerContext::new(&inbound, &[user], &policy));
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
            tokio_rustls::TlsAcceptor::from(Arc::new(tls)),
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

        timeout(Duration::from_secs(25), async {
            for (transport, remote, http) in [
                (Transport::H2, tcp_addr, true),
                (Transport::H3, quic_addr, false),
                (Transport::Auto, quic_addr, true),
            ] {
                profile.transport = transport;
                profile.server = remote.to_string();
                let proxy_client = load_client(&profile).await.unwrap();
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
