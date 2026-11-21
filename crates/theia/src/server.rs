//! First real H2/TLS 1.3 server ingress. This is not an H3 endpoint.
//! A listener, not the untrusted HTTP Host/authority, determines authorization.
use crate::{
    config::{self, Config, Inbound, ServerDocument, ServerPolicy, User},
    protocol::{self, Address, Decoder, Direction, ErrorCode, Frame, Role, Session},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PEM_BYTES: u64 = 1024 * 1024;
const MAX_H2_STREAMS: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerError {
    Config,
    Io,
    Tls,
    Http2,
    Protocol,
    TimedOut,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::Config => "server configuration or TLS identity invalid",
            Self::Io => "server network or file operation failed",
            Self::Tls => "TLS handshake or certificate failed",
            Self::Http2 => "HTTP/2 session closed or flow control failed",
            Self::Protocol => "SmartTheia protocol violation",
            Self::TimedOut => "server operation timed out",
        };
        f.write_str(description)
    }
}
impl std::error::Error for ServerError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    Unauthorized,
    Forbidden,
    Busy,
}

impl AuthFailure {
    pub fn status(self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Busy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// One listener's immutable policy. Sharing the same semaphores across all
/// contexts protects aggregate connection and user quotas across inbounds.
pub struct ServerContext {
    pub inbound_id: String,
    allowed_users: HashSet<String>,
    users: Vec<User>,
    policy: ServerPolicy,
    global_streams: Arc<Semaphore>,
    user_streams: Arc<HashMap<String, Arc<Semaphore>>>,
    connection_slots: Arc<Semaphore>,
}

pub struct SessionPermit {
    _global: OwnedSemaphorePermit,
    _user: OwnedSemaphorePermit,
}

impl ServerContext {
    pub fn new(inbound: &Inbound, users: &[User], policy: &ServerPolicy) -> Self {
        let all_users = users
            .iter()
            .map(|user| {
                (
                    user.id.clone(),
                    Arc::new(Semaphore::new(policy.max_connections_per_user as usize)),
                )
            })
            .collect();
        Self::with_limits(
            inbound,
            users,
            policy,
            Arc::new(Semaphore::new(policy.max_connections_total as usize)),
            Arc::new(all_users),
            Arc::new(Semaphore::new(policy.max_connections_total as usize)),
        )
    }

    fn with_limits(
        inbound: &Inbound,
        users: &[User],
        policy: &ServerPolicy,
        global_streams: Arc<Semaphore>,
        user_streams: Arc<HashMap<String, Arc<Semaphore>>>,
        connection_slots: Arc<Semaphore>,
    ) -> Self {
        Self {
            inbound_id: inbound.id.clone(),
            allowed_users: inbound.allowed_user_ids.iter().cloned().collect(),
            users: users.to_vec(),
            policy: policy.clone(),
            global_streams,
            user_streams,
            connection_slots,
        }
    }

    /// Raw token digest is the SHA-256 of exactly 32 decoded bytes, not the
    /// base64url text or a 64-character hex digest presented as a credential.
    /// Check all configured hashes using constant-time comparison and never
    /// reflect token bytes, hashes or even the candidate string in errors.
    pub fn authorize(&self, authorization: Option<&str>) -> Result<SessionPermit, AuthFailure> {
        let header = authorization.ok_or(AuthFailure::Unauthorized)?;
        let bearer = header.strip_prefix("Bearer ").ok_or(AuthFailure::Unauthorized)?;
        if bearer.len() != 43 || bearer.contains('=') {
            return Err(AuthFailure::Unauthorized);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(bearer)
            .map_err(|_| AuthFailure::Unauthorized)?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != bearer {
            return Err(AuthFailure::Unauthorized);
        }
        let candidate = Sha256::digest(&decoded);
        let mut matching_user: Option<&User> = None;
        for user in &self.users {
            // The structural TOML validator has already confirmed lower-hex
            // digest shape; skip damaged runtime fixtures rather than trusting.
            if let Some(stored) = decode_digest(&user.token_sha256) {
                let equal = stored.ct_eq(candidate.as_slice()).unwrap_u8() == 1;
                if equal {
                    matching_user = Some(user);
                }
            }
        }
        let user = matching_user.ok_or(AuthFailure::Unauthorized)?;
        if user.disabled || !self.allowed_users.contains(&user.id) {
            return Err(AuthFailure::Forbidden);
        }
        let global = self
            .global_streams
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthFailure::Busy)?;
        let user_limit = self.user_streams.get(&user.id).ok_or(AuthFailure::Forbidden)?;
        let per_user = user_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthFailure::Busy)?;
        Ok(SessionPermit {
            _global: global,
            _user: per_user,
        })
    }
}

fn decode_digest(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0; 32];
    for (index, pair) in raw.as_bytes().chunks_exact(2).enumerate() {
        fn nibble(b: u8) -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            }
        }
        out[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// Fail-closed address policy. IPv4-mapped IPv6 must be checked as IPv4.
/// Private/loopback, link-local, multicast, reserved and documentation ranges
/// are rejected by default; only explicit allow_private_ips permits them.
pub fn allowed_destination(ip: IpAddr, allow_private_ips: bool) -> bool {
    if allow_private_ips {
        return !ip.is_unspecified() && !ip.is_multicast();
    }
    match ip {
        IpAddr::V4(v4) => allowed_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return allowed_v4(mapped);
            }
            let segments = v6.segments();
            let global_unicast = (segments[0] & 0xe000) == 0x2000;
            let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
            let special = segments[0] == 0x2001 && segments[1] == 0;
            global_unicast && !documentation && !special
        }
    }
}

fn allowed_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !(
        a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 0 || b == 168 || (b == 88 && c == 99)))
        || (a == 198 && ((b == 18 || b == 19) || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113)
        || (a == 192 && b == 0 && c == 2)
        || (a == 255 && b == 255 && c == 255 && d == 255)
    )
}

async fn connect_target(
    address: &Address,
    port: u16,
    policy: &ServerPolicy,
) -> Result<TcpStream, ErrorCode> {
    let duration = Duration::from_millis(u64::from(policy.connect_timeout_ms));
    let candidates: Vec<SocketAddr> = match address {
        Address::V4(ip) => vec![SocketAddr::from((*ip, port))],
        Address::V6(ip) => vec![SocketAddr::from((*ip, port))],
        Address::Dns(name) => {
            let resolved = timeout(duration, lookup_host((name.as_str(), port)))
                .await
                .map_err(|_| ErrorCode::DialTimeout)?
                .map_err(|_| ErrorCode::DialFailed)?;
            resolved.collect()
        }
    };
    let permitted: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| allowed_destination(candidate.ip(), policy.allow_private_ips))
        .collect();
    if permitted.is_empty() {
        return Err(ErrorCode::PolicyDenied);
    }
    for candidate in permitted {
        // Pin the ACL-checked SocketAddr. Never resolve the hostname again.
        match timeout(duration, TcpStream::connect(candidate)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(_)) => continue,
            Err(_) => return Err(ErrorCode::DialTimeout),
        }
    }
    Err(ErrorCode::DialFailed)
}

pub async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    context: Arc<ServerContext>,
) -> Result<(), ServerError> {
    loop {
        let (socket, _) = listener.accept().await.map_err(|_| ServerError::Io)?;
        let Ok(slot) = context.connection_slots.clone().try_acquire_owned() else {
            continue;
        };
        let tls_acceptor = acceptor.clone();
        let context = context.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let Ok(Ok(tls)) = timeout(HANDSHAKE_TIMEOUT, tls_acceptor.accept(socket)).await else {
                return;
            };
            if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                return;
            }
            let Ok(mut connection) = h2::server::Builder::new()
                .max_concurrent_streams(MAX_H2_STREAMS)
                .handshake(tls)
                .await
            else {
                return;
            };
            while let Some(result) = connection.accept().await {
                let Ok((request, respond)) = result else {
                    break;
                };
                let context = context.clone();
                tokio::spawn(async move {
                    let _ = handle_request(request, respond, context).await;
                });
            }
        });
    }
}

async fn reject(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: StatusCode,
) -> Result<(), ServerError> {
    let response = Response::builder()
        .status(status)
        .body(())
        .map_err(|_| ServerError::Http2)?;
    respond
        .send_response(response, true)
        .map_err(|_| ServerError::Http2)?;
    Ok(())
}

async fn handle_request(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    context: Arc<ServerContext>,
) -> Result<(), ServerError> {
    if request.method() != Method::POST
        || request.uri().path() != "/v1/session"
        || request.uri().query().is_some()
        || request.headers().get(header::CONTENT_TYPE).map(|value| value.as_bytes())
            != Some(b"application/octet-stream".as_slice())
    {
        reject(&mut respond, StatusCode::NOT_FOUND).await?;
        return Ok(());
    }
    if request.headers().get_all(header::AUTHORIZATION).iter().count() != 1 {
        reject(&mut respond, StatusCode::UNAUTHORIZED).await?;
        return Ok(());
    }
    let auth = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let permit = match context.authorize(auth) {
        Ok(permit) => permit,
        Err(failure) => {
            reject(&mut respond, failure.status()).await?;
            return Ok(());
        }
    };
    let mut inbound = request.into_body();
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|_| ServerError::Http2)?;
    // HTTP 200 acknowledges transport/auth headers, NOT remote TCP OPEN.
    let mut outgoing = respond
        .send_response(response, false)
        .map_err(|_| ServerError::Http2)?;
    let result = timeout(
        Duration::from_secs(300),
        handle_frames(&mut inbound, &mut outgoing, &context),
    )
    .await;
    if !matches!(result, Ok(Ok(()))) {
        let _ = send_frame(
            &mut outgoing,
            &Frame::Abort(ErrorCode::ProtocolError),
        )
        .await;
    }
    let _ = outgoing.send_data(Bytes::new(), true);
    drop(permit);
    Ok(())
}

async fn send_frame(
    outgoing: &mut h2::SendStream<Bytes>,
    frame: &Frame,
) -> Result<(), ServerError> {
    let mut bytes = Bytes::from(protocol::encode(frame).map_err(|_| ServerError::Protocol)?);
    while !bytes.is_empty() {
        outgoing.reserve_capacity(bytes.len());
        let capacity = if outgoing.capacity() == 0 {
            std::future::poll_fn(|cx| outgoing.poll_capacity(cx))
                .await
                .ok_or(ServerError::Http2)?
                .map_err(|_| ServerError::Http2)?
        } else {
            outgoing.capacity()
        };
        if capacity == 0 {
            continue;
        }
        outgoing
            .send_data(bytes.split_to(capacity.min(bytes.len())), false)
            .map_err(|_| ServerError::Http2)?;
    }
    Ok(())
}

#[derive(Default)]
struct IncomingFrames {
    decoder: Decoder,
    ready: VecDeque<Frame>,
}

impl IncomingFrames {
    async fn next(
        &mut self,
        incoming: &mut h2::RecvStream,
    ) -> Result<Option<Frame>, ServerError> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            let block = timeout(FRAME_IDLE_TIMEOUT, incoming.data())
                .await
                .map_err(|_| ServerError::TimedOut)?;
            let Some(block) = block else {
                self.decoder.finish().map_err(|_| ServerError::Protocol)?;
                return Ok(None);
            };
            let block = block.map_err(|_| ServerError::Http2)?;
            let size = block.len();
            let frames = self.decoder.feed(&block).map_err(|_| ServerError::Protocol)?;
            self.ready.extend(frames);
            incoming.flow_control().release_capacity(size).map_err(|_| ServerError::Http2)?;
        }
    }
}

async fn handle_frames(
    incoming: &mut h2::RecvStream,
    outgoing: &mut h2::SendStream<Bytes>,
    context: &ServerContext,
) -> Result<(), ServerError> {
    let mut decoder = IncomingFrames::default();
    let mut state = Session::new(Role::Server);
    let opened = timeout(HANDSHAKE_TIMEOUT, async {
        let hello = decoder.next(incoming).await?.ok_or(ServerError::Protocol)?;
        state.apply(Direction::Receive, &hello).map_err(|_| ServerError::Protocol)?;
        send_frame(
            outgoing,
            &Frame::HelloAck {
                version: protocol::VERSION,
                accepted_capabilities: 0,
            },
        )
        .await?;
        state.apply(
            Direction::Send,
            &Frame::HelloAck {
                version: protocol::VERSION,
                accepted_capabilities: 0,
            },
        )
        .map_err(|_| ServerError::Protocol)?;
        let open = decoder.next(incoming).await?.ok_or(ServerError::Protocol)?;
        state.apply(Direction::Receive, &open).map_err(|_| ServerError::Protocol)?;
        let Frame::OpenTcp { address, port } = open else {
            return Err(ServerError::Protocol);
        };
        Ok::<_, ServerError>((address, port))
    })
    .await
    .map_err(|_| ServerError::TimedOut)??;
    let (address, port) = opened;
    let mut tcp = match connect_target(&address, port, &context.policy).await {
        Ok(tcp) => tcp,
        Err(code) => {
            let failure = Frame::OpenError(code);
            state.apply(Direction::Send, &failure).map_err(|_| ServerError::Protocol)?;
            send_frame(outgoing, &failure).await?;
            return Ok(());
        }
    };
    state.apply(Direction::Send, &Frame::OpenOk).map_err(|_| ServerError::Protocol)?;
    send_frame(outgoing, &Frame::OpenOk).await?;

    let mut buffer = [0_u8; 4096];
    let mut inbound_eof = false;
    let mut remote_eof = false;
    let mut received_fin = false;
    loop {
        if state.is_closed() {
            return Ok(());
        }
        tokio::select! {
            message = decoder.next(incoming), if !inbound_eof => {
                match message? {
                    Some(Frame::Data(data)) => {
                        state.apply(Direction::Receive, &Frame::Data(data.clone()))
                            .map_err(|_| ServerError::Protocol)?;
                        timeout(FRAME_IDLE_TIMEOUT, tcp.write_all(&data))
                            .await.map_err(|_| ServerError::TimedOut)?
                            .map_err(|_| ServerError::Io)?;
                    }
                    Some(Frame::Fin) => {
                        state.apply(Direction::Receive, &Frame::Fin)
                            .map_err(|_| ServerError::Protocol)?;
                        received_fin = true;
                        tcp.shutdown().await.map_err(|_| ServerError::Io)?;
                    }
                    Some(Frame::Abort(code)) => {
                        state.apply(Direction::Receive, &Frame::Abort(code))
                            .map_err(|_| ServerError::Protocol)?;
                        return Ok(());
                    }
                    Some(_) => return Err(ServerError::Protocol),
                    None => {
                        if !received_fin {
                            return Err(ServerError::Protocol);
                        }
                        inbound_eof = true;
                    }
                }
            }
            count = timeout(FRAME_IDLE_TIMEOUT, tcp.read(&mut buffer)), if !remote_eof => {
                let size = count.map_err(|_| ServerError::TimedOut)?.map_err(|_| ServerError::Io)?;
                if size == 0 {
                    state.apply(Direction::Send, &Frame::Fin)
                        .map_err(|_| ServerError::Protocol)?;
                    send_frame(outgoing, &Frame::Fin).await?;
                    remote_eof = true;
                } else {
                    let frame = Frame::Data(buffer[..size].to_vec());
                    state.apply(Direction::Send, &frame).map_err(|_| ServerError::Protocol)?;
                    send_frame(outgoing, &frame).await?;
                }
            }
        }
    }
}

fn pem_data(reference: &str, private_key: bool) -> Result<Vec<u8>, ServerError> {
    let path = reference.strip_prefix("file:").ok_or(ServerError::Config)?;
    let path = Path::new(path);
    let meta = std::fs::symlink_metadata(path).map_err(|_| ServerError::Config)?;
    if !meta.file_type().is_file() || meta.len() > MAX_PEM_BYTES {
        return Err(ServerError::Config);
    }
    #[cfg(unix)]
    if private_key {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(ServerError::Config);
        }
    }
    let bytes = std::fs::read(path).map_err(|_| ServerError::Config)?;
    if bytes.len() as u64 > MAX_PEM_BYTES {
        return Err(ServerError::Config);
    }
    Ok(bytes)
}

fn tls_acceptor(inbound: &Inbound) -> Result<TlsAcceptor, ServerError> {
    let cert_bytes = pem_data(&inbound.tls_cert, false)?;
    let key_bytes = pem_data(&inbound.tls_key, true)?;
    let mut cert_reader = BufReader::new(cert_bytes.as_slice());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|_| ServerError::Config)?;
    if certs.is_empty() {
        return Err(ServerError::Config);
    }
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
        .map_err(|_| ServerError::Config)?
        .ok_or(ServerError::Config)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| ServerError::Tls)?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| ServerError::Tls)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(tls)))
}

/// Bind and prepare all H2 listeners before launching tasks. H3 remains an
/// explicit missing milestone; this function does not claim QUIC readiness.
pub async fn run_file(config_path: &Path) -> Result<(), ServerError> {
    let parsed = config::read_file(config_path).map_err(|_| ServerError::Config)?;
    let Config::Server(document) = parsed else {
        return Err(ServerError::Config);
    };
    run_document(document).await
}

pub async fn run_document(document: ServerDocument) -> Result<(), ServerError> {
    if !document.server.enabled {
        return Err(ServerError::Config);
    }
    let policy = document.server.policy;
    let global = Arc::new(Semaphore::new(policy.max_connections_total as usize));
    let connections = Arc::new(Semaphore::new(policy.max_connections_total as usize));
    let per_user: Arc<HashMap<_, _>> = Arc::new(
        document
            .server
            .users
            .iter()
            .map(|u| {
                (
                    u.id.clone(),
                    Arc::new(Semaphore::new(policy.max_connections_per_user as usize)),
                )
            })
            .collect(),
    );
    let mut prepared = Vec::new();
    for inbound in &document.server.inbounds {
        let addr: SocketAddr = inbound.h2_listen.parse().map_err(|_| ServerError::Config)?;
        let acceptor = tls_acceptor(inbound)?;
        let listener = TcpListener::bind(addr).await.map_err(|_| ServerError::Io)?;
        let context = Arc::new(ServerContext::with_limits(
            inbound,
            &document.server.users,
            &policy,
            global.clone(),
            per_user.clone(),
            connections.clone(),
        ));
        prepared.push((listener, acceptor, context));
    }
    let mut tasks = JoinSet::new();
    for (listener, acceptor, context) in prepared {
        tasks.spawn(serve(listener, acceptor, context));
    }
    match tasks.join_next().await {
        Some(Ok(result)) => result,
        _ => Err(ServerError::Io),
    }
}
