//! Local loopback-only CONNECT and SOCKS5 listeners for H2, H3 or conservative QUIC-first auto mode.
//! No system proxy changes, destination DNS lookups or live tunnel migration.
use crate::{
    client::{error_kind, ClientError, H2Client, Tunnel},
    config::{self, Config, Profile, Transport},
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
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

const LOCAL_LIMIT: usize = 64;
const HEADER_LIMIT: usize = 8192;
const NEGOTIATE_TIMEOUT: Duration = Duration::from_secs(10);
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);
const CA_LIMIT: usize = 1024 * 1024;

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
    if profile.tls_profile != "default" {
        return Err(ClientError::Configuration);
    }
    match profile.transport {
        Transport::H2 => H2Client::new(&profile.server, &profile.server_name, &token, roots)
            .map(Arc::new)
            .map(ProxyClient::H2),
        Transport::H3 | Transport::Auto => {
            // Resolve the configured server only, never the requested target.
            let remote = timeout(NEGOTIATE_TIMEOUT, tokio::net::lookup_host(&profile.server))
                .await
                .map_err(|_| ClientError::Timeout)?
                .map_err(|_| ClientError::Io)?
                .next()
                .ok_or(ClientError::Io)?;
            let h3 = Arc::new(
                H3Client::new(remote, &profile.server_name, &token, roots.clone())?
                    .with_connect_timeout(Duration::from_millis(u64::from(
                        profile.quic_connect_timeout_ms,
                    )))?,
            );
            if profile.transport == Transport::H3 {
                return Ok(ProxyClient::H3(h3));
            }
            let h2 = Arc::new(H2Client::new(
                &profile.server,
                &profile.server_name,
                &token,
                roots,
            )?);
            Ok(ProxyClient::Auto(Arc::new(AutoClient {
                h2,
                h3,
                ttl: Duration::from_secs(u64::from(profile.quic_negative_cache_ttl_s)),
                negative: Mutex::new(NegativeCache::default()),
            })))
        }
    }
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
fn route_source(remote: SocketAddr) -> Option<SocketAddr> {
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
            self.expires = None;
        }
        (self.generation, self.expires.is_some())
    }

    fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.expires = None;
    }

    fn record(&mut self, generation: u64, now: Instant, ttl: Duration) {
        if self.generation == generation && self.route.is_some() && !ttl.is_zero() {
            self.expires = now.checked_add(ttl);
        }
    }
}

struct AutoClient {
    h2: Arc<H2Client>,
    h3: Arc<H3Client>,
    ttl: Duration,
    negative: Mutex<NegativeCache>,
}

impl AutoClient {
    fn observe(&self) -> Result<(u64, bool), ClientError> {
        let mut cache = self
            .negative
            .lock()
            .map_err(|_| ClientError::Configuration)?;
        Ok(cache.observe(route_source(self.h3.remote()), Instant::now()))
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
        }
        if !unreachable {
            if cache.generation == generation {
                cache.invalidate();
            }
            return Ok(false);
        }
        if cache.generation != generation {
            return Ok(false);
        }
        cache.record(generation, Instant::now(), self.ttl);
        Ok(true)
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
        if !cached {
            match self.h3.open(address.clone(), port).await {
                Ok(tunnel) => {
                    self.complete(generation, false)?;
                    crate::diag!(
                        Info,
                        "client.auto",
                        "selected_h3",
                        "generation" = Value::Count(generation)
                    );
                    eprintln!("transport=h3");
                    return Ok(ProxyTunnel::H3(Box::new(tunnel)));
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
        let Config::Client(document) =
            config::parse(std::str::from_utf8(&bytes).map_err(|_| ClientError::Configuration)?)
                .map_err(|_| ClientError::Configuration)?
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
    loop {
        let (socket, is_http) = tokio::select! {
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
                Info,
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
        cache.record(generation, now, ttl);
        assert!(cache.observe(route, now + Duration::from_secs(4)).1);
        assert!(!cache.observe(route, now + ttl).1);
        cache.record(generation, now, Duration::ZERO);
        assert!(!cache.observe(route, now).1);
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
}
