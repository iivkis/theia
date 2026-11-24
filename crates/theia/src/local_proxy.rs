//! Local loopback-only CONNECT and SOCKS5 listeners for H2, H3 or conservative QUIC-first auto mode.
//! No system proxy changes, destination DNS lookups or live tunnel migration.
use crate::{
    client::{error_kind, ClientError, H2Client, Tunnel},
    config::{self, Config, Profile, Transport, XhttpMode},
    diagnostics::{self, Value},
    h3_client::{H3Client, H3Tunnel},
    protocol::{self, Address, ErrorCode, Frame},
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

async fn load_client(profile: &Profile) -> Result<ProxyClient, ClientError> {
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
    let token = if let Some(name) = profile.auth_token.strip_prefix("env:") {
        zeroize::Zeroizing::new(std::env::var(name).map_err(|_| ClientError::Configuration)?)
    } else {
        let bytes = load_file(&profile.auth_token, 43, true)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| ClientError::Configuration)?;
        zeroize::Zeroizing::new(text.to_owned())
    };
    if token.len() != 43 || roots.is_empty() {
        return Err(ClientError::Configuration);
    }
    // F-13: runtime selection must match strict typed TOML validation even
    // if a direct library caller bypasses document parsing. Never downgrade
    // a named browser-style profile to rustls or apply it to QUIC/H3/auto.
    if profile.xhttp_mode.is_some() && profile.tls_profile != "default" {
        return Err(ClientError::Configuration);
    }
    if profile.tls_profile == "browser-h2-btls-v1" {
        if profile.transport != Transport::H2 {
            return Err(ClientError::Configuration);
        }
        #[cfg(feature = "experimental-btls-h2")]
        {
            return H2Client::new_browser_h2_v1(
                &profile.server,
                &profile.server_name,
                &token,
                &cert,
            )
            .map(Arc::new)
            .map(ProxyClient::H2);
        }
        #[cfg(not(feature = "experimental-btls-h2"))]
        {
            return Err(ClientError::Configuration);
        }
    }
    let certificate_pin = if profile.tls_profile == "default" {
        None
    } else {
        Some(
            crate::security_profile::CertificatePin::parse_profile(&profile.tls_profile)
                .ok_or(ClientError::Configuration)?,
        )
    };
    let mode = profile.effective_xhttp_mode();
    let stream_up = mode == XhttpMode::StreamUp;
    let auto_xhttp = mode == XhttpMode::Auto;
    let ttl = Duration::from_secs(u64::from(profile.quic_negative_cache_ttl_s));
    match profile.transport {
        Transport::H2 => {
            let endpoint = if certificate_pin.is_none() {
                resolve_server(profile).await?.to_string()
            } else {
                profile.server.clone()
            };
            let client = H2Client::new(&endpoint, &profile.server_name, &token, roots)?
                .with_certificate_pin(certificate_pin)?
                .with_stream_up(stream_up)?;
            let client = if auto_xhttp {
                client.with_auto_stream_up(ttl)?
            } else {
                client
            };
            Ok(ProxyClient::H2(Arc::new(client.with_connection_pool())))
        }
        Transport::H3 | Transport::Auto => {
            // Resolve the configured server only, never the requested target.
            let remote = resolve_server(profile).await?;
            let h3 = H3Client::new(remote, &profile.server_name, &token, roots.clone())?
                .with_certificate_pin(certificate_pin)?
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
                return Ok(ProxyClient::H3(h3));
            }
            // Both carriers use the same resolved endpoint. Do not resolve
            // the hostname again during fallback; retain the configured SNI,
            // trust anchors, certificate pin and authorization unchanged.
            let h2 = H2Client::new(&remote.to_string(), &profile.server_name, &token, roots)?
                .with_certificate_pin(certificate_pin)?
                .with_stream_up(stream_up)?;
            let h2 = h2.with_connection_pool();
            let h2 = Arc::new(if auto_xhttp {
                h2.with_auto_stream_up(ttl)?
            } else {
                h2
            });
            Ok(ProxyClient::Auto(Arc::new(AutoClient {
                h2,
                h3,
                ttl,
                negative: Mutex::new(NegativeCache::default()),
                cache_changed: Notify::new(),
            })))
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
    H2(Arc<H2Client>),
    H3(Arc<H3Client>),
    Auto(Arc<AutoClient>),
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
    route: Option<SocketAddr>,
    generation: u64,
    expires: Option<Instant>,
}

impl NegativeCache {
    fn observe(&mut self, route: Option<SocketAddr>, now: Instant) -> (u64, bool) {
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
        route: Option<SocketAddr>,
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
}

impl AutoClient {
    fn observe(&self) -> Result<(u64, bool), ClientError> {
        let mut cache = self
            .negative
            .lock()
            .map_err(|_| ClientError::Configuration)?;
        let previous = cache.generation;
        let observed = cache.observe(route_source(self.h3.remote()), Instant::now());
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
        let current = route_source(self.h3.remote());
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
        if cache.generation != generation {
            return Ok(false);
        }
        if cache.record(generation, Instant::now(), self.ttl) {
            self.cache_changed.notify_one();
        }
        Ok(true)
    }

    /// One scoped maintenance future per running auto profile. No detached
    /// task or application credentials, and no mutex held across an await.
    async fn maintain(&self) -> Result<(), ClientError> {
        loop {
            let pending = {
                let cache = self
                    .negative
                    .lock()
                    .map_err(|_| ClientError::Configuration)?;
                cache.expires.map(|deadline| (cache.generation, deadline))
            };
            let Some((generation, deadline)) = pending else {
                self.cache_changed.notified().await;
                continue;
            };
            tokio::select! {
                _ = self.cache_changed.notified() => continue,
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
            }
            let generation = {
                let mut cache = self
                    .negative
                    .lock()
                    .map_err(|_| ClientError::Configuration)?;
                cache.begin_recheck(
                    generation,
                    deadline,
                    route_source(self.h3.remote()),
                    Instant::now(),
                )
            };
            let Some(generation) = generation else {
                continue;
            };
            for attempt in 0..AUTO_QUIC_ATTEMPTS {
                match self.h3.probe().await {
                    Err(ClientError::QuicUnreachable) if attempt + 1 < AUTO_QUIC_ATTEMPTS => {
                        if self.observe()?.0 != generation {
                            break;
                        }
                    }
                    Err(ClientError::QuicUnreachable) => {
                        self.complete(generation, true)?;
                        break;
                    }
                    result => {
                        // Verified success or a terminal failure clears the
                        // negative cache; a new tunnel must verify its own
                        // connection. Never authorize H2 on a TLS error.
                        self.complete(generation, false)?;
                        match result {
                            Ok(()) => crate::diag!(Debug, "client.auto", "background_h3_verified"),
                            Err(error) => crate::diag!(
                                Warn,
                                "client.auto",
                                "background_h3_terminal_failure",
                                "reason" = Value::Label(error_kind(&error))
                            ),
                        }
                        break;
                    }
                }
            }
        }
    }

    async fn open(&self, address: Address, port: u16) -> Result<ProxyTunnel, ClientError> {
        let (generation, cached) = self.observe()?;
        crate::diag!(
            Debug,
            "client.auto",
            "transport_select",
            "generation" = Value::Count(generation),
            "negative_cache_hit" = Value::Flag(cached)
        );
        // Keep the actual initial XHTTP mode across a fresh H3-to-H2
        // fallback. Cached H2-only requests may use their own carrier cache.
        let preferred = if cached {
            None
        } else {
            Some(self.h3.preferred_stream_up()?)
        };
        if !cached {
            for attempt in 0..AUTO_QUIC_ATTEMPTS {
                match self
                    .h3
                    .open_preferred(address.clone(), port, preferred)
                    .await
                {
                    Ok(tunnel) => {
                        self.complete(generation, false)?;
                        crate::diag!(
                            Debug,
                            "client.auto",
                            "selected_h3",
                            "generation" = Value::Count(generation)
                        );
                        eprintln!("transport=h3");
                        return Ok(ProxyTunnel::H3(Box::new(tunnel)));
                    }
                    Err(ClientError::QuicUnreachable) if attempt + 1 < AUTO_QUIC_ATTEMPTS => {
                        // Retry only a pre-authentication handshake with observed
                        // UDP silence, and never carry evidence across a route change.
                        if self.observe()?.0 != generation {
                            return Err(ClientError::QuicUnreachable);
                        }
                    }
                    Err(ClientError::QuicUnreachable) => {
                        if !self.complete(generation, true)? {
                            crate::diag!(
                                Warn,
                                "client.auto",
                                "stale_quic_probe_rejected",
                                "generation" = Value::Count(generation)
                            );
                            return Err(ClientError::QuicUnreachable);
                        }
                        crate::diag!(
                            Warn,
                            "client.auto",
                            "h3_udp_silent_fallback_h2",
                            "generation" = Value::Count(generation)
                        );
                        eprintln!("transport=h2 reason=quic_unreachable");
                        break;
                    }
                    Err(error) => {
                        // All errors except observed UDP silence remain terminal.
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
        } else {
            crate::diag!(
                Debug,
                "client.auto",
                "negative_cache_fallback_h2",
                "generation" = Value::Count(generation)
            );
            eprintln!("transport=h2 reason=quic_negative_cache");
        }
        self.h2
            .open_preferred(address, port, preferred)
            .await
            .map(Box::new)
            .map(ProxyTunnel::H2)
    }
}

enum ProxyTunnel {
    H2(Box<Tunnel>),
    H3(Box<H3Tunnel>),
}

impl ProxyClient {
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
}

impl ProxyTunnel {
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

async fn run_file_inner(config_path: &Path, enable_system_proxy: bool) -> Result<(), ClientError> {
    crate::diag!(
        Info,
        "client.proxy",
        "config_read_begin",
        "system_proxy_requested" = Value::Flag(enable_system_proxy)
    );
    let Config::Client(document) =
        config::read_file(config_path).map_err(|_| ClientError::Configuration)?
    else {
        return Err(ClientError::Configuration);
    };
    let (http, socks, client) = prepare_proxy(&document).await?;
    #[cfg(windows)]
    if enable_system_proxy {
        // A config declaration is insufficient by itself: this branch
        // requires the *additional CLI* --system-proxy --confirm.
        if document.client.proxy.system_proxy != config::SystemProxy::Manual {
            return Err(ClientError::SystemProxy);
        }
        let bound = http.local_addr().map_err(|_| ClientError::Io)?;
        let mut lease = crate::windows_system_proxy::OwnedProxy::apply(bound)
            .map_err(|_| ClientError::SystemProxy)?;
        // Ctrl+C is the normal scoped exit. A killed process cannot execute
        // destructors; persistent registry journal permits explicit recovery
        // on the next invocation, without overwriting a foreign proxy change.
        let result = tokio::select! {
            result = serve_proxy(http, socks, client) => result,
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
    serve_proxy(http, socks, client).await
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
#[cfg(windows)]
pub(crate) struct PreparedLocalProxy {
    http: TcpListener,
    socks: TcpListener,
    client: ProxyClient,
    pub(crate) manual: bool,
}

#[cfg(windows)]
impl PreparedLocalProxy {
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

    pub(crate) fn http_address(&self) -> Result<SocketAddr, ClientError> {
        self.http.local_addr().map_err(|_| ClientError::Io)
    }

    pub(crate) async fn serve(self) -> Result<(), ClientError> {
        serve_proxy(self.http, self.socks, self.client).await
    }
}

#[cfg(windows)]
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
    serve_proxy(http, socks, ProxyClient::H2(client)).await
}

async fn serve_proxy(
    http: TcpListener,
    socks: TcpListener,
    client: ProxyClient,
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
    let maintenance = async {
        match &client {
            ProxyClient::Auto(auto) => auto.maintain().await,
            _ => std::future::pending::<Result<(), ClientError>>().await,
        }
    };
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
        let client = client.clone();
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
            Err(error)
        }
    }
}

#[cfg(test)]
mod selector_tests {
    use super::*;

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
        invalid.tls_profile = "unknown".into();
        assert!(load_client(&invalid).await.is_err());
        invalid = profile.clone();
        invalid.tls_profile = "browser-h2-btls-v1".into();
        assert!(load_client(&invalid).await.is_err());
        invalid.xhttp_mode = None;
        invalid.transport = Transport::H3;
        assert!(load_client(&invalid).await.is_err());
        #[cfg(feature = "experimental-btls-h2")]
        {
            invalid.transport = Transport::H2;
            assert!(matches!(
                load_client(&invalid).await,
                Ok(ProxyClient::H2(_))
            ));
        }
        let mut pinned = profile.clone();
        pinned.xhttp_mode = None;
        pinned.tls_profile =
            crate::security_profile::CertificatePin::from_der(cert.cert.der().as_ref()).profile();
        assert!(matches!(load_client(&pinned).await, Ok(ProxyClient::H2(_))));
        let mut automatic_mode = profile.clone();
        automatic_mode.xhttp_mode = Some(XhttpMode::Auto);
        assert!(matches!(
            load_client(&automatic_mode).await,
            Ok(ProxyClient::H2(_))
        ));
        automatic_mode.transport = Transport::Auto;
        assert!(matches!(
            load_client(&automatic_mode).await,
            Ok(ProxyClient::Auto(_))
        ));

        let inbound = Inbound {
            id: "edge".into(),
            allowed_user_ids: vec!["client".into()],
            h2_listen: "127.0.0.1:0".into(),
            quic_listen: "127.0.0.1:0".into(),
            server_name: "localhost".into(),
            tls_cert: "unused".into(),
            tls_key: "unused".into(),
            security_mode: Default::default(),
        };
        let user = User {
            id: "client".into(),
            token_sha256: format!("{:x}", Sha256::digest(token)),
            disabled: false,
        };
        let policy = ServerPolicy {
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
