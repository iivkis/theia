//! Local loopback-only CONNECT and SOCKS5 listeners for explicit H2 or H3 mode.
//! No system proxy changes, destination DNS lookups or protocol fallback.
use crate::{
    client::{ClientError, H2Client, Tunnel},
    config::{self, Config, Profile, Transport},
    h3_client::{H3Client, H3Tunnel},
    protocol::{self, Address, ErrorCode, Frame},
};
use rustls::RootCertStore;
use std::{
    io::{BufReader, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::Arc,
    time::Duration,
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

fn load_file(reference: &str, limit: usize, secret: bool) -> Result<Vec<u8>, ClientError> {
    let path = Path::new(
        reference
            .strip_prefix("file:")
            .ok_or(ClientError::Configuration)?,
    );
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ClientError::Configuration)?;
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err(ClientError::Configuration);
    }
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ClientError::Configuration);
        }
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut data = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| ClientError::Configuration)?
        .take((limit + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|_| ClientError::Configuration)?;
    if data.len() > limit {
        return Err(ClientError::Configuration);
    }
    Ok(data)
}

async fn load_client(profile: &Profile) -> Result<ProxyClient, ClientError> {
    // Auto remains fail-closed pending explicit fallback classification.
    if profile.transport == Transport::Auto {
        return Err(ClientError::Configuration);
    }
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
        std::env::var(name).map_err(|_| ClientError::Configuration)?
    } else {
        let token = load_file(&profile.auth_token, 43, true)?;
        String::from_utf8(token).map_err(|_| ClientError::Configuration)?
    };
    match profile.transport {
        Transport::H2 => H2Client::new(&profile.server, &profile.server_name, &token, roots)
            .map(Arc::new)
            .map(ProxyClient::H2),
        Transport::H3 => {
            // Resolve the configured server only, never the requested target.
            let remote = timeout(NEGOTIATE_TIMEOUT, tokio::net::lookup_host(&profile.server))
                .await
                .map_err(|_| ClientError::Timeout)?
                .map_err(|_| ClientError::Io)?
                .next()
                .ok_or(ClientError::Io)?;
            H3Client::new(remote, &profile.server_name, &token, roots)
                .map(Arc::new)
                .map(ProxyClient::H3)
        }
        Transport::Auto => Err(ClientError::Configuration),
    }
}

#[derive(Clone)]
enum ProxyClient {
    H2(Arc<H2Client>),
    H3(Arc<H3Client>),
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
    let Config::Client(document) =
        config::read_file(config_path).map_err(|_| ClientError::Configuration)?
    else {
        return Err(ClientError::Configuration);
    };
    let profile = document
        .client
        .profiles
        .iter()
        .find(|p| p.id == document.client.active_profile)
        .ok_or(ClientError::Configuration)?;
    let client = load_client(profile).await?;
    // All startup validation and both binds must succeed before accepting.
    let http = TcpListener::bind(&document.client.proxy.http_listen)
        .await
        .map_err(|_| ClientError::Io)?;
    let socks = TcpListener::bind(&document.client.proxy.socks5_listen)
        .await
        .map_err(|_| ClientError::Io)?;
    serve_proxy(http, socks, client).await
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
    let slots = Arc::new(Semaphore::new(LOCAL_LIMIT));
    let mut tasks = JoinSet::new();
    loop {
        let (socket, is_http) = tokio::select! {
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
            accepted = http.accept() => (accepted.map_err(|_| ClientError::Io)?.0, true),
            accepted = socks.accept() => (accepted.map_err(|_| ClientError::Io)?.0, false),
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let client = client.clone();
        tasks.spawn(async move {
            let _slot = slot;
            let _ = handle(socket, is_http, &client).await;
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
) -> Result<(), ClientError> {
    let (address, port) = if is_http {
        match timeout(NEGOTIATE_TIMEOUT, http_target(&mut socket)).await {
            Ok(Ok(target)) => target,
            Ok(Err(reply)) => {
                let _ = timeout(REPLY_TIMEOUT, socket.write_all(reply)).await;
                return Err(ClientError::Protocol);
            }
            Err(_) => return Err(ClientError::Timeout),
        }
    } else {
        timeout(NEGOTIATE_TIMEOUT, socks_target(&mut socket))
            .await
            .map_err(|_| ClientError::Timeout)??
    };
    match client.open(address, port).await {
        Ok(tunnel) => {
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
            if is_http {
                let reply = match error {
                    ClientError::Open(ErrorCode::PolicyDenied) | ClientError::Unauthorized => {
                        HTTP_DENIED
                    }
                    ClientError::Timeout | ClientError::Open(ErrorCode::DialTimeout) => {
                        HTTP_TIMEOUT
                    }
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
