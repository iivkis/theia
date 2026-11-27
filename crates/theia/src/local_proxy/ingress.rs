//! Explicit loopback HTTP/SOCKS5 ingress, framing and association lifecycle.
use super::{ProxyClient, RoutedUdp, NEGOTIATE_TIMEOUT, REPLY_TIMEOUT};
use crate::{
    client::{error_kind, ClientError},
    diagnostics::Value,
    protocol::{self, Address, ErrorCode, Frame},
};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinSet,
    time::timeout,
};

pub(super) const HEADER_LIMIT: usize = 8192;
const HTTP_BODY_LIMIT: usize = 1024 * 1024;

pub(super) const HTTP_OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
pub(super) const HTTP_BAD: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
pub(super) const HTTP_METHOD: &[u8] =
    b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
pub(super) const HTTP_DENIED: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const HTTP_FAILED: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const HTTP_TIMEOUT: &[u8] =
    b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

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

#[derive(Debug, PartialEq, Eq)]
pub(super) enum HttpRequest {
    Connect(Address, u16),
    Plain(Address, u16, Vec<u8>),
}

/// Never read application bytes beyond this request. The complete bounded
/// body is buffered before opening any egress; the response remains streamed.
pub(super) struct HttpOnce {
    pub(super) socket: TcpStream,
    pub(super) request: bytes::Bytes,
}
impl tokio::io::AsyncRead for HttpOnce {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let n = out.remaining().min(self.request.len());
        out.put_slice(&self.request.split_to(n));
        std::task::Poll::Ready(Ok(()))
    }
}
impl tokio::io::AsyncWrite for HttpOnce {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.socket), cx, data)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.socket), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.socket), cx)
    }
}

fn http_authority(raw: &str) -> Result<(Address, u16), &'static [u8]> {
    if raw.contains('@') || raw.contains('%') {
        return Err(HTTP_BAD);
    }
    let authority = raw.parse::<http::uri::Authority>().map_err(|_| HTTP_BAD)?;
    let target = if authority.port().is_some() {
        parse_authority(raw)
    } else {
        parse_authority(&format!("{raw}:80"))
    };
    let (mut address, port) = target.map_err(|_| HTTP_BAD)?;
    if let Address::Dns(name) = &mut address {
        name.make_ascii_lowercase();
    }
    Ok((address, port))
}

async fn plain_http<'a>(
    socket: &mut TcpStream,
    method: &str,
    raw_uri: &str,
    version: &str,
    lines: impl Iterator<Item = &'a str>,
) -> Result<HttpRequest, &'static [u8]> {
    if !raw_uri.starts_with("http://") {
        return Err(HTTP_METHOD);
    }
    if raw_uri.contains('#') || method.eq_ignore_ascii_case("CONNECT") {
        return Err(HTTP_BAD);
    }
    http::Method::from_bytes(method.as_bytes()).map_err(|_| HTTP_BAD)?;
    let uri: http::Uri = raw_uri.parse().map_err(|_| HTTP_BAD)?;
    let authority = uri.authority().ok_or(HTTP_BAD)?.as_str();
    let (address, port) = http_authority(authority)?;
    let origin = uri.path_and_query().map_or("/", |path| path.as_str());
    let origin = if origin.starts_with('?') {
        format!("/{origin}")
    } else {
        origin.to_owned()
    };
    if !origin.starts_with('/') {
        return Err(HTTP_BAD);
    }

    let mut headers = Vec::new();
    let mut nominated = std::collections::HashSet::new();
    let mut host_seen = false;
    let mut length = None;
    for line in lines {
        let (raw_name, raw_value) = line.split_once(':').ok_or(HTTP_BAD)?;
        let name =
            http::header::HeaderName::from_bytes(raw_name.as_bytes()).map_err(|_| HTTP_BAD)?;
        let value = raw_value.trim_matches([' ', '\t']);
        http::HeaderValue::from_str(value).map_err(|_| HTTP_BAD)?;
        match name.as_str() {
            "host" => {
                if host_seen || http_authority(value)? != (address.clone(), port) {
                    return Err(HTTP_BAD);
                }
                host_seen = true;
            }
            "content-length" => {
                if length.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(HTTP_BAD);
                }
                let n = value.parse::<usize>().map_err(|_| HTTP_BAD)?;
                if n > HTTP_BODY_LIMIT {
                    return Err(HTTP_BAD);
                }
                length = Some(n);
            }
            // No ambiguous framing, upgrades or 100-continue handshake.
            "transfer-encoding" | "upgrade" | "expect" | "trailer" => return Err(HTTP_BAD),
            "connection" | "proxy-connection" => {
                for token in value.split(',') {
                    let token = token.trim_matches([' ', '\t']);
                    let field = http::header::HeaderName::from_bytes(token.as_bytes())
                        .map_err(|_| HTTP_BAD)?;
                    if matches!(
                        field.as_str(),
                        "host" | "content-length" | "transfer-encoding" | "upgrade"
                    ) {
                        return Err(HTTP_BAD);
                    }
                    nominated.insert(field);
                }
            }
            "proxy-authorization" | "proxy-authenticate" | "keep-alive" | "te" => {}
            _ => headers.push((name, value)),
        }
    }
    if version == "HTTP/1.1" && !host_seen {
        return Err(HTTP_BAD);
    }

    let mut request =
        format!("{method} {origin} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n")
            .into_bytes();
    if let Some(n) = length {
        request.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
    }
    for (name, value) in headers {
        if !nominated.contains(&name) {
            request.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
    }
    request.extend_from_slice(b"\r\n");
    if request.len() > HEADER_LIMIT {
        return Err(HTTP_BAD);
    }
    let head_len = request.len();
    request.resize(head_len + length.unwrap_or(0), 0);
    socket
        .read_exact(&mut request[head_len..])
        .await
        .map_err(|_| HTTP_BAD)?;
    Ok(HttpRequest::Plain(address, port, request))
}

pub(super) async fn http_target(socket: &mut TcpStream) -> Result<HttpRequest, &'static [u8]> {
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
        return plain_http(socket, method, authority, version, lines).await;
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
    Ok(HttpRequest::Connect(target.0, target.1))
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

pub(super) async fn handle(
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
    if !socket
        .peer_addr()
        .map_err(|_| ClientError::Io)?
        .ip()
        .is_loopback()
    {
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    let mut plain = None;
    let (address, port) = if is_http {
        match timeout(NEGOTIATE_TIMEOUT, http_target(&mut socket)).await {
            Ok(Ok(HttpRequest::Connect(address, port))) => (address, port),
            Ok(Ok(HttpRequest::Plain(address, port, request))) => {
                plain = Some(request);
                (address, port)
            }
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
    let opened = if plain.is_some() {
        client.open_for(address, port, false).await
    } else {
        client.open(address, port).await
    };
    let opened = opened.and_then(|tunnel| {
        tunnel.flow.check_pending()?;
        Ok(tunnel)
    });
    match opened {
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
            // Plain HTTP receives the actual origin response, never a CONNECT 200.
            if let Some(request) = plain {
                return tunnel.relay_http(socket, request).await;
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
pub(super) async fn socks_target(socket: &mut TcpStream) -> Result<(Address, u16), ClientError> {
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
        crate::routing::carrier_socket::bind_plain_udp(SocketAddr::new(local.ip(), 0))
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
                let first = data.to_vec(); // parse_socks already bounds the datagram
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
                    let RoutedUdp { tunnel, flow }=proxy.open_udp(address.clone(),port,&candidate,&first).await?;
                    drop(first);
                    let local_guard = tunnel.local_delivery_guard();
                    let (down_tx,mut down_rx)=mpsc::channel(QUEUE);
                    let relay=tunnel.relay_guarded(rx,down_tx,Some(&flow));
                    let deliver=async {
                        let mut packet = Vec::new();
                        while let Some(data)=down_rx.recv().await {
                            observer.lock().unwrap_or_else(|e|e.into_inner()).incoming(&data);
                            if !udp_relay::encode_socks_into(&mut packet, &address, port, &data) {
                                // SOCKS framing may exceed the UDP maximum;
                                // this is not queue congestion.
                                continue;
                            }
                            flow.check_delivery()?;
                            if flow.actual_action()? == Some(crate::routing::PacketAction::Modify) {
                                if let Some(guard) = &local_guard { guard.check()?; }
                            }
                            let n=timeout(REPLY_TIMEOUT,socket.send_to(&packet,source)).await
                                .map_err(|_|ClientError::Timeout)?.map_err(|_|ClientError::Io)?;
                            if n!=packet.len(){return Err(ClientError::Io);}
                        }
                        Ok::<(),ClientError>(())
                    };
                    // On clean termination drain accepted responses instead
                    // of cancelling the downstream queue when relay returns.
                    tokio::select! {
                        biased;
                        result=flow.wait_revoked()=>result,
                        result=async { tokio::try_join!(relay, deliver).map(|_| ()) }=>result,
                    }
                });
            }
        }
    }
}
