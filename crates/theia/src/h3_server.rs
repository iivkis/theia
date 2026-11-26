//! Authenticated production H3 request handling.
//! Reuses H2's inbound context, admission, authorization, quota and DNS ACL.
use crate::{
    diagnostics::{self, Value},
    protocol::{self, Decoder, Direction, Frame, Role, Session},
    quic_transport,
    server::{self, GenerationPhase, ServerContext, ServerError},
};
use bytes::{Buf, Bytes};
use h3::{error::Code, quic, server::RequestStream};
use http::{Request, Response, StatusCode};
use std::{collections::VecDeque, net::IpAddr, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::watch, task::JoinSet, time::timeout};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HANDLERS: usize = crate::transport_policy::MAX_BIDI_STREAMS as usize;

type Stream<S> = RequestStream<S, Bytes>;

// Both carriers must enter the very same request handlers; the native lab
// does not get its own less restrictive authorization path.
trait CarrierStream: quic::BidiStream<Bytes> + quic::RecvStream<Buf = Bytes> + Send + 'static {}
impl<S: quic::BidiStream<Bytes> + quic::RecvStream<Buf = Bytes> + Send + 'static> CarrierStream
    for S
{
}

struct ConnectionGuard(quinn::Connection);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"session closed");
    }
}

struct EndpointGuard(quinn::Endpoint);

impl Drop for EndpointGuard {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"listener closed");
    }
}

/// Own the listener, handshake tasks, connections and stream handlers.
/// No detached tasks survive a cancelled listener. Reuse a ServerContext
/// across transports when wiring the CLI, so their quotas cannot diverge.
pub async fn serve(
    endpoint: quinn::Endpoint,
    context: Arc<ServerContext>,
) -> Result<(), ServerError> {
    let (_owner, phase) = watch::channel(GenerationPhase::Active);
    serve_generation(endpoint, context, phase).await
}

pub(crate) async fn serve_generation(
    endpoint: quinn::Endpoint,
    context: Arc<ServerContext>,
    mut phase: watch::Receiver<GenerationPhase>,
) -> Result<(), ServerError> {
    if !server::await_generation_activation(&mut phase).await {
        crate::diag!(Info, "server.h3", "generation_aborted_before_activation");
        return Ok(());
    }
    crate::diag!(Info, "server.h3", "listener_active");
    let endpoint = EndpointGuard(endpoint);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            change = phase.changed() => {
                if change.is_err() || *phase.borrow() == GenerationPhase::Drain {
                    break;
                }
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
            incoming = endpoint.0.accept() => {
                let Some(incoming) = incoming else {
                    return Err(ServerError::Io);
                };
                let connection_id = diagnostics::next_id();
                crate::diag!(Trace, "server.h3", "quic_incoming",
                    "connection" = Value::Count(connection_id));
                let Some(slot) = context.connection_slot() else {
                    crate::diag!(Warn, "server.h3", "connection_quota_rejected",
                        "connection" = Value::Count(connection_id));
                    incoming.refuse();
                    continue;
                };
                let context = context.clone();
                let connection_phase = phase.clone();
                connections.spawn(async move {
                    let _slot = slot;
                    let Ok(connection) = quic_transport::accept(incoming).await else {
                        crate::diag!(Warn, "server.h3", "quic_tls_handshake_rejected",
                            "connection" = Value::Count(connection_id));
                        return;
                    };
                    crate::diag!(Debug, "server.h3", "quic_verified",
                        "connection" = Value::Count(connection_id));
                    run_connection(connection, context, connection_phase).await;
                });
            }
        }
    }
    // Quinn does not expose a portable accept-only half-close on Endpoint:
    // while existing streams drain, refuse all NEW datagrams/connection
    // attempts. EndpointGuard closes everything after the bounded window.
    crate::diag!(Info, "server.h3", "generation_draining");
    let _ = timeout(server::GENERATION_DRAIN, async {
        while !connections.is_empty() {
            tokio::select! {
                _ = connections.join_next() => {}
                incoming = endpoint.0.accept() => {
                    if let Some(incoming) = incoming {
                        incoming.refuse();
                    } else {
                        break;
                    }
                }
            }
        }
    })
    .await;
    Ok(())
}

pub(crate) async fn run_connection(
    connection: quinn::Connection,
    context: Arc<ServerContext>,
    phase: watch::Receiver<GenerationPhase>,
) {
    let guard = ConnectionGuard(connection);
    let peer = guard.0.remote_address().ip();
    let binding = if context.requires_channel_binding() {
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        if guard
            .0
            .export_keying_material(
                &mut key[..],
                crate::channel_binding::LABEL,
                crate::channel_binding::H3,
            )
            .is_err()
        {
            return;
        }
        Some(Arc::new(crate::channel_binding::Admission::new(key)))
    } else {
        None
    };
    let transport = h3_quinn::Connection::new(guard.0.clone());
    run_h3(transport, context, phase, peer, binding, async {
        let _ = guard.0.closed().await;
    })
    .await;
}

/// Experimental loopback entry point; no external listener or configuration
/// switch. Requires TLS exporter material even for own-TLS; raw fixed-key
/// sessions cannot enter the shared admission/relay handlers.
pub async fn run_native_lab(
    session: crate::quic_core::endpoint::LabSession,
    context: Arc<ServerContext>,
) -> Result<(), ServerError> {
    let peer = session.peer_addr().ip();
    // REALITY dispatch and pinned-identity admission are not yet integrated.
    if !peer.is_loopback() || !context.allows_native_lab() {
        return Err(ServerError::Io);
    }
    let _slot = context.connection_slot().ok_or(ServerError::Io)?;
    let (_owner, phase) = watch::channel(GenerationPhase::Active);
    run_native_session(session, context, phase).await
}

/// Explicit pinned-address own-TLS trial, not wired to runtime selection.
/// The common context enforces connection and request quotas before relay.
/// On shutdown refuse new connections and drain existing H3 streams.
pub async fn serve_native_pinned<F>(
    socket: tokio::net::UdpSocket,
    scope: crate::quic_core::scope::NetworkScope,
    tls: Arc<rustls::ServerConfig>,
    context: Arc<ServerContext>,
    shutdown: F,
) -> Result<(), ServerError>
where F: std::future::Future<Output = ()> + Send,
{
    if !scope.is_pinned() { return Err(ServerError::Io); }
    serve_native_scoped(socket, scope, tls, context, shutdown).await
}

/// Explicit own-TLS external listener, bound to one concrete IP. Clients
/// are not restricted to a predeclared IP. This is not yet a runtime
/// backend selector; callers must opt in and perform independent acceptance.
pub async fn serve_native_external<F>(
    socket: tokio::net::UdpSocket,
    tls: Arc<rustls::ServerConfig>,
    context: Arc<ServerContext>,
    shutdown: F,
) -> Result<(), ServerError>
where F: std::future::Future<Output = ()> + Send,
{
    let local = socket.local_addr().map_err(|_| ServerError::Io)?;
    let scope = crate::quic_core::scope::NetworkScope::external_server(local.ip()).ok_or(ServerError::Io)?;
    serve_native_scoped(socket, scope, tls, context, shutdown).await
}

async fn serve_native_scoped<F>(
    socket: tokio::net::UdpSocket,
    scope: crate::quic_core::scope::NetworkScope,
    tls: Arc<rustls::ServerConfig>,
    context: Arc<ServerContext>,
    shutdown: F,
) -> Result<(), ServerError>
where F: std::future::Future<Output = ()> + Send,
{
    use crate::quic_core::{handshake_udp, listener::Listener, negotiation::VersionPolicy};
    if !context.allows_native_lab() || tls.send_tls13_tickets != 0 || tls.max_early_data_size != 0 {
        return Err(ServerError::Io);
    }
    let mut listener = Listener::with_scope(socket, 128, VersionPolicy::both(), scope).map_err(|_| ServerError::Io)?;
    let (owner, phase) = watch::channel(GenerationPhase::Active);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = connections.join_next(), if !connections.is_empty() => {},
            incoming = listener.accept() => {
                let candidate = incoming.map_err(|_| ServerError::Io)?;
                let Some(slot) = context.connection_slot() else { continue; };
                let context = context.clone();
                let tls = tls.clone();
                let phase = phase.clone();
                connections.spawn(async move {
                    let _slot = slot;
                    if let Ok(session) = handshake_udp::accept(candidate, tls).await {
                        let _ = run_native_session(session, context, phase).await;
                    }
                });
            }
        }
    }
    listener.stop_accepting().await.map_err(|_| ServerError::Io)?;
    let _ = owner.send(GenerationPhase::Drain);
    let _ = timeout(server::GENERATION_DRAIN, async {
        while !connections.is_empty() {
            tokio::select! {
                _ = connections.join_next() => {},
                incoming = listener.accept() => { if incoming.is_err() { break; } }
            }
        }
    }).await;
    Ok(())
}

async fn run_native_session(
    session: crate::quic_core::endpoint::LabSession,
    context: Arc<ServerContext>,
    phase: watch::Receiver<GenerationPhase>,
) -> Result<(), ServerError> {
    let peer = session.peer_addr().ip();
    let (transport, _key) = crate::quic_core::h3_adapter::NativeConnection::start(session)
        .map_err(|_| ServerError::Io)?;
    let mut closed = transport.closed_signal();
    let mut drained = closed.clone();
    let binding = None;
    run_h3(
        transport,
        context,
        phase,
        peer,
        binding,
        async move { let _ = closed.changed().await; },
    )
    .await;
    // Keep the connection quota and listener ownership during the native
    // driver's closing/draining period, not merely until H3 drops.
    let _ = timeout(server::GENERATION_DRAIN, drained.changed()).await;
    Ok(())
}

async fn run_h3<C, F>(
    transport: C,
    context: Arc<ServerContext>,
    mut phase: watch::Receiver<GenerationPhase>,
    peer: IpAddr,
    binding: Option<Arc<crate::channel_binding::Admission>>,
    closed: F,
) where
    C: quic::Connection<Bytes> + 'static,
    C::BidiStream: CarrierStream,
    <C::BidiStream as quic::BidiStream<Bytes>>::SendStream: Send + 'static,
    <C::BidiStream as quic::BidiStream<Bytes>>::RecvStream:
        quic::RecvStream<Buf = Bytes> + Send + 'static,
    F: std::future::Future<Output = ()>,
{
    tokio::pin!(closed);
    let mut builder = h3::server::builder();
    builder.max_field_section_size(u64::from(crate::transport_policy::MAX_HEADER_LIST_BYTES));
    let Ok(Ok(mut h3)) = timeout(HANDSHAKE_TIMEOUT, builder.build::<_, Bytes>(transport)).await
    else {
        crate::diag!(Warn, "server.h3", "h3_handshake_failed_or_timeout");
        return;
    };
    crate::diag!(Trace, "server.h3", "h3_connection_ready");
    let mut handlers = JoinSet::new();
    let pair = Arc::new(crate::split_http::Pair::new());
    let mut draining = false;
    loop {
        // Keep driving the control stream after GOAWAY. Existing admitted
        // streams have their own handlers and retain their context.
        let idle = handlers.is_empty();
        let request = tokio::select! {
            biased;
            _ = server::await_generation_drain(&mut phase), if !draining => {
                if !matches!(timeout(CLOSE_TIMEOUT, h3.shutdown(0)).await, Ok(Ok(()))) {
                    break;
                }
                draining = true;
                continue;
            }
            _ = handlers.join_next(), if !idle => continue,
            request = h3.accept(), if handlers.len() < MAX_HANDLERS => request,
            _ = &mut closed => break,
            _ = tokio::time::sleep(IDLE_TIMEOUT), if idle => break,
        };
        let resolver = match request {
            Ok(Some(resolver)) => resolver,
            Ok(None) if draining => {
                // Do not drop already-admitted streams when the H3 accept
                // side reports no further requests. Quinn drives DATA/FIN.
                while handlers.join_next().await.is_some() {}
                let _ = timeout(CLOSE_TIMEOUT, &mut closed).await;
                break;
            }
            _ => break,
        };
        if draining || server::generation_draining(&phase) {
            // Resolve only to reject the HTTP stream; no bearer or OPEN.
            if let Ok(Ok((_, mut stream))) =
                timeout(CLOSE_TIMEOUT, resolver.resolve_request()).await
            {
                stream.stop_stream(Code::H3_REQUEST_REJECTED);
                stream.stop_sending(Code::H3_REQUEST_REJECTED);
            }
            continue;
        }
        let context = context.clone();
        let pair = pair.clone();
        let binding = binding.clone();
        handlers.spawn(async move {
            let Ok(Ok((request, stream))) =
                timeout(HANDSHAKE_TIMEOUT, resolver.resolve_request()).await
            else {
                crate::diag!(Warn, "server.h3", "request_headers_failed_or_timeout");
                return;
            };
            if context.is_routing_request(&request) {
                handle_routing(request, stream, &context, peer, binding.as_deref()).await;
            } else if context.is_descriptor_request(&request) {
                handle_descriptor(request, stream, &context, peer).await;
            } else if context.accepts_split(&request) {
                handle_split_request(request, stream, &context, peer, &pair, binding.as_deref())
                    .await;
            } else {
                handle_request(request, stream, &context, peer, binding.as_deref()).await;
            }
        });
    }
}

async fn handle_descriptor<S: CarrierStream>(
    request: Request<()>,
    mut stream: Stream<S>,
    context: &ServerContext,
    peer: IpAddr,
) {
    let (_permit, signed) = match context.authorize_descriptor(&request, peer) {
        Ok(value) => value,
        Err(status) => {
            reject_split(&mut stream, status).await;
            return;
        }
    };
    let empty = timeout(HANDSHAKE_TIMEOUT, async {
        stream.recv_data().await.is_ok_and(|data| data.is_none())
            && stream
                .recv_trailers()
                .await
                .is_ok_and(|trailers| trailers.is_none())
    })
    .await
    .unwrap_or(false);
    if !empty {
        reject_split(&mut stream, StatusCode::BAD_REQUEST).await;
        return;
    }
    let Ok(response) = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header(http::header::CONTENT_LENGTH, signed.len().to_string())
        .body(())
    else {
        return;
    };
    if !matches!(
        timeout(CLOSE_TIMEOUT, async {
            stream
                .send_response(context.pad_response(response)?)
                .await
                .map_err(|_| ServerError::Io)?;
            stream
                .send_data(Bytes::copy_from_slice(signed.as_bytes()))
                .await
                .map_err(|_| ServerError::Io)?;
            stream.finish().await.map_err(|_| ServerError::Io)
        })
        .await,
        Ok(Ok(()))
    ) {
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        stream.stop_sending(Code::H3_REQUEST_CANCELLED);
    }
}

async fn handle_routing<S: CarrierStream>(
    request: Request<()>,
    mut stream: Stream<S>,
    context: &ServerContext,
    peer: IpAddr,
    binding: Option<&crate::channel_binding::Admission>,
) {
    let (_permit, publication) = match context.authorize_routing(&request, peer) {
        Ok(value) => value,
        Err(status) => {
            reject_split(&mut stream, status).await;
            return;
        }
    };
    if !crate::channel_binding::admit(binding, &[&request]) {
        reject_split(&mut stream, StatusCode::UNAUTHORIZED).await;
        return;
    }
    let empty = timeout(HANDSHAKE_TIMEOUT, async {
        stream.recv_data().await.is_ok_and(|data| data.is_none())
            && stream
                .recv_trailers()
                .await
                .is_ok_and(|trailers| trailers.is_none())
    })
    .await
    .unwrap_or(false);
    if !empty {
        reject_split(&mut stream, StatusCode::BAD_REQUEST).await;
        return;
    }
    let signed = match context
        .routing_response(&publication, request.headers())
        .await
    {
        Ok(bytes) => bytes,
        Err(status) => {
            reject_split(&mut stream, status).await;
            return;
        }
    };
    let Ok(response) = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header(http::header::CONTENT_LENGTH, signed.len().to_string())
        .body(())
    else {
        return;
    };
    if !matches!(
        timeout(crate::routing::exchange::TRANSFER_TIMEOUT, async {
            stream
                .send_response(context.pad_response(response)?)
                .await
                .map_err(|_| ServerError::Io)?;
            for chunk in signed.chunks(64 * 1024) {
                stream
                    .send_data(Bytes::copy_from_slice(chunk))
                    .await
                    .map_err(|_| ServerError::Io)?;
            }
            stream.finish().await.map_err(|_| ServerError::Io)
        })
        .await,
        Ok(Ok(()))
    ) {
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        stream.stop_sending(Code::H3_REQUEST_CANCELLED);
    }
}

async fn handle_request<S: CarrierStream>(
    request: Request<()>,
    mut stream: Stream<S>,
    context: &ServerContext,
    peer: IpAddr,
    binding: Option<&crate::channel_binding::Admission>,
) {
    let session_id = diagnostics::next_id();
    crate::diag!(
        Trace,
        "server.h3",
        "request_received",
        "session" = Value::Count(session_id)
    );
    let permit = match context.authorize_request(&request, peer) {
        Ok(permit) => permit,
        Err(status) => {
            crate::diag!(
                Warn,
                "server.h3",
                "authorization_rejected",
                "session" = Value::Count(session_id),
                "http_status" = Value::Count(u64::from(status.as_u16()))
            );
            let _ = timeout(CLOSE_TIMEOUT, respond(&mut stream, status)).await;
            let _ = timeout(CLOSE_TIMEOUT, stream.finish()).await;
            // Refuse further body bytes without accepting a tunnel.
            stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            return;
        }
    };
    if !crate::channel_binding::admit(binding, &[&request]) {
        reject_split(&mut stream, StatusCode::UNAUTHORIZED).await;
        return;
    }
    crate::diag!(
        Debug,
        "server.h3",
        "authorized",
        "session" = Value::Count(session_id)
    );
    if !matches!(
        timeout(CLOSE_TIMEOUT, respond_admitted(&mut stream, context)).await,
        Ok(Ok(()))
    ) {
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        return;
    }

    let (tx, rx) = stream.split();
    relay_request(tx, rx, context, session_id).await;
    drop(permit);
}

type SplitPair<S> = crate::split_http::Pair<(Request<()>, Stream<S>)>;

async fn reject_split<S: CarrierStream>(stream: &mut Stream<S>, status: StatusCode) {
    let _ = timeout(CLOSE_TIMEOUT, respond(stream, status)).await;
    let _ = timeout(CLOSE_TIMEOUT, stream.finish()).await;
    stream.stop_sending(Code::H3_REQUEST_CANCELLED);
}

async fn handle_split_request<S: CarrierStream>(
    request: Request<()>,
    mut stream: Stream<S>,
    context: &ServerContext,
    peer: IpAddr,
    pair: &SplitPair<S>,
    binding: Option<&crate::channel_binding::Admission>,
) {
    let Some(leg) = context.split_leg(&request) else {
        reject_split(&mut stream, StatusCode::NOT_FOUND).await;
        return;
    };
    let Some(id) = crate::split_http::pair_id(&request) else {
        reject_split(&mut stream, StatusCode::BAD_REQUEST).await;
        return;
    };
    let Some(((upload, mut up), (download, mut down))) =
        pair.join(id, leg, (request, stream)).await
    else {
        return;
    };
    let permit = match context.authorize_split_pair(&upload, &download, peer) {
        Ok(permit) => permit,
        Err(status) => {
            reject_split(&mut up, status).await;
            reject_split(&mut down, status).await;
            return;
        }
    };
    if !crate::channel_binding::admit(binding, &[&upload, &download]) {
        reject_split(&mut up, StatusCode::UNAUTHORIZED).await;
        reject_split(&mut down, StatusCode::UNAUTHORIZED).await;
        return;
    }
    let empty = timeout(HANDSHAKE_TIMEOUT, async {
        down.recv_data().await.is_ok_and(|value| value.is_none())
            && down
                .recv_trailers()
                .await
                .is_ok_and(|value| value.is_none())
    })
    .await
    .unwrap_or(false);
    if !empty {
        reject_split(&mut up, StatusCode::BAD_REQUEST).await;
        reject_split(&mut down, StatusCode::BAD_REQUEST).await;
        return;
    }
    if !matches!(
        timeout(CLOSE_TIMEOUT, async {
            respond_admitted(&mut up, context).await?;
            up.finish().await.map_err(|_| ServerError::Io)?;
            respond_admitted(&mut down, context).await
        })
        .await,
        Ok(Ok(()))
    ) {
        up.stop_stream(Code::H3_REQUEST_CANCELLED);
        up.stop_sending(Code::H3_REQUEST_CANCELLED);
        down.stop_stream(Code::H3_REQUEST_CANCELLED);
        return;
    }
    let (_, rx) = up.split();
    let (tx, _) = down.split();
    relay_request(tx, rx, context, diagnostics::next_id()).await;
    drop(permit);
}

async fn relay_request<T: quic::SendStream<Bytes>, R: quic::RecvStream>(
    mut tx: RequestStream<T, Bytes>,
    mut rx: RequestStream<R, Bytes>,
    context: &ServerContext,
    session_id: u64,
) {
    // The bounded handshake, dial, send and shared idle deadlines remain.
    // A progressing relay has no absolute session-age limit.
    let result = handle_frames(&mut tx, &mut rx, context, session_id).await;
    match &result {
        Ok(()) => crate::diag!(
            Info,
            "server.h3",
            "request_completed",
            "session" = Value::Count(session_id)
        ),
        Err(error) => crate::diag!(
            Warn,
            "server.h3",
            "request_relay_failed",
            "session" = Value::Count(session_id),
            "reason" = Value::Label(server::error_kind(*error))
        ),
    }
    if result.is_ok() {
        if !matches!(timeout(CLOSE_TIMEOUT, tx.finish()).await, Ok(Ok(()))) {
            tx.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
        rx.stop_sending(Code::H3_NO_ERROR);
    } else {
        // A cancelled/partial frame must never be followed by new wire bytes.
        tx.stop_stream(Code::H3_REQUEST_CANCELLED);
        rx.stop_sending(Code::H3_REQUEST_CANCELLED);
    }
}

async fn respond_admitted<S: CarrierStream>(
    stream: &mut Stream<S>,
    context: &ServerContext,
) -> Result<(), ServerError> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|_| ServerError::Protocol)?;
    stream
        .send_response(context.pad_response(response)?)
        .await
        .map_err(|_| ServerError::Io)
}

async fn respond<S: CarrierStream>(
    stream: &mut Stream<S>,
    status: StatusCode,
) -> Result<(), ServerError> {
    let response = Response::builder()
        .status(status)
        .body(())
        .map_err(|_| ServerError::Protocol)?;
    stream
        .send_response(response)
        .await
        .map_err(|_| ServerError::Io)
}

#[derive(Default)]
struct Incoming {
    decoder: Decoder,
    ready: VecDeque<Frame>,
}

impl Incoming {
    async fn next<S: quic::RecvStream>(
        &mut self,
        stream: &mut RequestStream<S, Bytes>,
    ) -> Result<Option<Frame>, ServerError> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            let data = stream.recv_data().await.map_err(|_| ServerError::Io)?;
            let Some(mut data) = data else {
                self.decoder.finish().map_err(|_| ServerError::Protocol)?;
                // SmartTheia has no HTTP trailers.
                let trailers = timeout(CLOSE_TIMEOUT, stream.recv_trailers())
                    .await
                    .map_err(|_| ServerError::TimedOut)?
                    .map_err(|_| ServerError::Io)?;
                if trailers.is_some() {
                    return Err(ServerError::Protocol);
                }
                return Ok(None);
            };
            // Bound the application decoder feed even if a transport buffer
            // contains a large number of coalesced frames.
            while data.has_remaining() {
                let n = data.remaining().min(4096);
                let bytes = data.copy_to_bytes(n);
                self.ready.extend(
                    self.decoder
                        .feed(&bytes)
                        .map_err(|_| ServerError::Protocol)?,
                );
            }
        }
    }
}

async fn send<S: quic::SendStream<Bytes>>(
    stream: &mut RequestStream<S, Bytes>,
    frame: &Frame,
) -> Result<(), ServerError> {
    let bytes = Bytes::from(protocol::encode(frame).map_err(|_| ServerError::Protocol)?);
    timeout(IDLE_TIMEOUT, stream.send_data(bytes))
        .await
        .map_err(|_| ServerError::TimedOut)?
        .map_err(|_| ServerError::Io)
}

async fn handle_frames<T: quic::SendStream<Bytes>, R: quic::RecvStream>(
    tx: &mut RequestStream<T, Bytes>,
    rx: &mut RequestStream<R, Bytes>,
    context: &ServerContext,
    session_id: u64,
) -> Result<(), ServerError> {
    let mut incoming = Incoming::default();
    let mut state = Session::new(Role::Server);
    let (address, port) = timeout(HANDSHAKE_TIMEOUT, async {
        let hello = incoming.next(rx).await?.ok_or(ServerError::Protocol)?;
        state
            .apply(Direction::Receive, &hello)
            .map_err(|_| ServerError::Protocol)?;
        let Frame::Hello { capabilities, .. } = hello else {
            return Err(ServerError::Protocol);
        };
        let ack = Frame::HelloAck {
            version: protocol::VERSION,
            accepted_capabilities: capabilities & protocol::CAP_PADDING,
        };
        state
            .apply(Direction::Send, &ack)
            .map_err(|_| ServerError::Protocol)?;
        send(tx, &ack).await?;
        if let Some(padding) = context.padding_frame(capabilities & protocol::CAP_PADDING)? {
            state
                .apply(Direction::Send, &padding)
                .map_err(|_| ServerError::Protocol)?;
            send(tx, &padding).await?;
        }
        let open = loop {
            let frame = incoming.next(rx).await?.ok_or(ServerError::Protocol)?;
            state
                .apply(Direction::Receive, &frame)
                .map_err(|_| ServerError::Protocol)?;
            if matches!(frame, Frame::Padding(_)) {
                tokio::task::yield_now().await;
                continue;
            }
            break frame;
        };
        match open {
            Frame::OpenTcp { address, port } | Frame::OpenUdp { address, port } => {
                Ok::<_, ServerError>((address, port))
            }
            _ => Err(ServerError::Protocol),
        }
    })
    .await
    .map_err(|_| ServerError::TimedOut)??;

    crate::diag!(
        Trace,
        "server.h3",
        "hello_and_open_validated",
        "session" = Value::Count(session_id)
    );
    // Dial only a shared-policy vetted address. Detect early body/EOF/reset
    // while connecting; a client is not allowed to send DATA before OPEN_OK.
    let udp = state.udp();
    let dial = tokio::select! {
        biased;
        next = async {
            loop {
                match incoming.next(rx).await? {
                    Some(frame @ Frame::Padding(_)) => {
                        state.apply(Direction::Receive, &frame).map_err(|_| ServerError::Protocol)?;
                        tokio::task::yield_now().await;
                    }
                    _ => return Err::<(), ServerError>(ServerError::Protocol),
                }
            }
        } => {
            next?;
            return Err(ServerError::Protocol);
        }
        result = async {
            if udp { context.dial_udp_target(&address, port).await.map(crate::udp_relay::Target::Udp) }
            else { context.dial_target(&address, port).await.map(crate::udp_relay::Target::Tcp) }
        } => result,
    };
    let tcp = match dial {
        Ok(tcp) => tcp,
        Err(code) => {
            crate::diag!(
                Warn,
                "server.h3",
                "target_dial_rejected",
                "session" = Value::Count(session_id),
                "code" = Value::Count(code as u64)
            );
            let failure = Frame::OpenError(code);
            state
                .apply(Direction::Send, &failure)
                .map_err(|_| ServerError::Protocol)?;
            return send(tx, &failure).await;
        }
    };
    state
        .apply(Direction::Send, &Frame::OpenOk)
        .map_err(|_| ServerError::Protocol)?;
    send(tx, &Frame::OpenOk).await?;
    crate::diag!(
        Debug,
        "server.h3",
        "open_ok_sent",
        "session" = Value::Count(session_id)
    );
    match tcp {
        crate::udp_relay::Target::Tcp(tcp) => relay(tcp, tx, rx, incoming, state, session_id).await,
        crate::udp_relay::Target::Udp(udp) => relay_udp(udp, tx, rx, incoming, state).await,
    }
}

async fn relay<T: quic::SendStream<Bytes>, R: quic::RecvStream>(
    tcp: TcpStream,
    tx: &mut RequestStream<T, Bytes>,
    rx: &mut RequestStream<R, Bytes>,
    mut incoming: Incoming,
    mut state: Session,
    session_id: u64,
) -> Result<(), ServerError> {
    let traffic = crate::traffic::enter(crate::Role::Server, true);
    let (mut read, mut write) = tcp.into_split();
    let mut upload_state = state.clone();
    let mut download_state = state.clone();
    let activity = crate::relay_liveness::Activity::new();
    let (download_done, download_finished) = tokio::sync::oneshot::channel();
    let upload = async {
        loop {
            let frame = incoming.next(rx).await?.ok_or(ServerError::Protocol)?;
            upload_state
                .apply(Direction::Receive, &frame)
                .map_err(|_| ServerError::Protocol)?;
            match frame {
                Frame::Padding(_) => tokio::task::yield_now().await,
                Frame::Data(data) => {
                    crate::diag!(
                        Trace,
                        "server.h3",
                        "upload_frame",
                        "session" = Value::Count(session_id),
                        "bytes" = Value::Count(data.len() as u64)
                    );
                    timeout(IDLE_TIMEOUT, write.write_all(&data))
                        .await
                        .map_err(|_| ServerError::TimedOut)?
                        .map_err(|_| ServerError::Io)?;
                    traffic.upload(data.len());
                    activity.data(data.len());
                }
                Frame::Fin => {
                    crate::diag!(
                        Debug,
                        "server.h3",
                        "upload_fin",
                        "session" = Value::Count(session_id)
                    );
                    timeout(IDLE_TIMEOUT, write.shutdown())
                        .await
                        .map_err(|_| ServerError::TimedOut)?
                        .map_err(|_| ServerError::Io)?;
                    activity.half_closed();
                    break;
                }
                _ => return Err(ServerError::Protocol),
            }
        }
        if crate::relay_liveness::receive_tail(
            async {
                loop {
                    let frame = incoming.next(rx).await?;
                    if let Some(padding @ Frame::Padding(_)) = &frame {
                        if activity.both_finished() {
                            return Err(ServerError::Protocol);
                        }
                        upload_state
                            .apply(Direction::Receive, padding)
                            .map_err(|_| ServerError::Protocol)?;
                        tokio::task::yield_now().await;
                        continue;
                    }
                    return Ok(frame);
                }
            },
            download_finished,
            ServerError::TimedOut,
        )
        .await?
        .is_some()
        {
            return Err(ServerError::Protocol);
        }
        Ok::<(), ServerError>(())
    };
    let download = async {
        let mut buffer = [0; crate::relay_batch::MAX_BATCH];
        let mut batch = crate::relay_batch::ReadyBatch::default();
        loop {
            let n = batch
                .read(&mut read, &mut buffer)
                .await
                .map_err(|_| ServerError::Io)?;
            let frame = if n == 0 {
                Frame::Fin
            } else {
                Frame::Data(buffer[..n].to_vec())
            };
            crate::diag!(
                Trace,
                "server.h3",
                "download_frame",
                "session" = Value::Count(session_id),
                "bytes" = Value::Count(n as u64),
                "fin" = Value::Flag(n == 0)
            );
            download_state
                .apply(Direction::Send, &frame)
                .map_err(|_| ServerError::Protocol)?;
            send(tx, &frame).await?;
            if n == 0 {
                activity.half_closed();
                let _ = download_done.send(());
                return Ok::<(), ServerError>(());
            }
            traffic.download(n);
            activity.data(n);
        }
    };
    activity
        .run(upload, download, ServerError::TimedOut)
        .await?;
    state
        .apply(Direction::Receive, &Frame::Fin)
        .map_err(|_| ServerError::Protocol)?;
    state
        .apply(Direction::Send, &Frame::Fin)
        .map_err(|_| ServerError::Protocol)?;
    state.finish().map_err(|_| ServerError::Protocol)
}

async fn relay_udp<T: quic::SendStream<Bytes>, R: quic::RecvStream>(
    socket: tokio::net::UdpSocket,
    tx: &mut RequestStream<T, Bytes>,
    rx: &mut RequestStream<R, Bytes>,
    mut decoder: Incoming,
    state: Session,
) -> Result<(), ServerError> {
    let traffic = crate::traffic::enter_udp(crate::Role::Server, true, false);
    let mut rx_state = state.clone();
    let mut tx_state = state;
    let activity = crate::udp_relay::Activity::new();
    let writing = std::sync::atomic::AtomicBool::new(false);
    let upload = async {
        loop {
            let frame = decoder.next(rx).await?.ok_or(ServerError::Protocol)?;
            rx_state
                .apply(Direction::Receive, &frame)
                .map_err(|_| ServerError::Protocol)?;
            match frame {
                Frame::Datagram(data) => {
                    crate::udp_relay::send_datagram(&socket, &data)
                        .await
                        .map_err(|_| ServerError::Io)?;
                    traffic.upload(data.len());
                    activity.touch();
                }
                Frame::Padding(_) => tokio::task::yield_now().await,
                Frame::Fin => return Ok::<(), ServerError>(()),
                _ => return Err(ServerError::Protocol),
            }
        }
    };
    let download = async {
        let mut buf = vec![0; crate::protocol::MAX_DATAGRAM + 1];
        loop {
            let n = socket.recv(&mut buf).await.map_err(|_| ServerError::Io)?;
            if n > crate::protocol::MAX_DATAGRAM {
                continue;
            }
            let frame = Frame::Datagram(buf[..n].to_vec());
            tx_state
                .apply(Direction::Send, &frame)
                .map_err(|_| ServerError::Protocol)?;
            writing.store(true, std::sync::atomic::Ordering::Relaxed);
            send(tx, &frame).await?;
            writing.store(false, std::sync::atomic::Ordering::Relaxed);
            traffic.download(n);
            activity.touch();
        }
        #[allow(unreachable_code)]
        Ok::<(), ServerError>(())
    };
    // UDP FIN terminates the association (no TCP-style half close).
    let result = tokio::select! { result=upload=>result, result=download=>result, ()=activity.expire()=>Ok(()) };
    if writing.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(ServerError::TimedOut);
    }
    result?;
    let frame = Frame::Fin;
    tx_state
        .apply(Direction::Send, &frame)
        .map_err(|_| ServerError::Protocol)?;
    send(tx, &frame).await?;
    Ok(())
}
