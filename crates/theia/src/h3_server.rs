//! M3.1b: authenticated H3 request handling, not yet bound by server CLI.
//! Reuses H2's inbound context, admission, authorization, quota and DNS ACL.
use crate::{
    protocol::{self, Decoder, Direction, Frame, Role, Session},
    quic_transport,
    server::{ServerContext, ServerError},
};
use bytes::{Buf, Bytes};
use h3::{error::Code, quic, server::RequestStream};
use http::{Request, Response, StatusCode};
use std::{collections::VecDeque, net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinSet,
    time::timeout,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HANDLERS: usize = 32;
const MAX_HEADERS: u64 = 8192;

type Stream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

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
    let endpoint = EndpointGuard(endpoint);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = connections.join_next(), if !connections.is_empty() => {}
            incoming = endpoint.0.accept() => {
                let Some(incoming) = incoming else {
                    return Err(ServerError::Io);
                };
                let Some(slot) = context.connection_slot() else {
                    incoming.refuse();
                    continue;
                };
                let context = context.clone();
                connections.spawn(async move {
                    let _slot = slot;
                    let Ok(connection) = quic_transport::accept(incoming).await else {
                        return;
                    };
                    run_connection(connection, context).await;
                });
            }
        }
    }
}

async fn run_connection(connection: quinn::Connection, context: Arc<ServerContext>) {
    let guard = ConnectionGuard(connection);
    let peer = guard.0.remote_address().ip();
    let mut builder = h3::server::builder();
    builder.max_field_section_size(MAX_HEADERS);
    let Ok(Ok(mut h3)) = timeout(
        HANDSHAKE_TIMEOUT,
        builder.build::<_, Bytes>(h3_quinn::Connection::new(guard.0.clone())),
    )
    .await
    else {
        return;
    };
    let mut handlers = JoinSet::new();
    loop {
        // Do not accumulate unresolved header readers indefinitely.
        if handlers.len() >= MAX_HANDLERS {
            tokio::select! {
                _ = handlers.join_next() => continue,
                _ = guard.0.closed() => break,
            }
        }
        let request = if handlers.is_empty() {
            match timeout(IDLE_TIMEOUT, h3.accept()).await {
                Ok(request) => request,
                Err(_) => break,
            }
        } else {
            tokio::select! {
                _ = handlers.join_next() => continue,
                request = h3.accept() => request,
                _ = guard.0.closed() => break,
            }
        };
        let Ok(Some(resolver)) = request else {
            break;
        };
        let context = context.clone();
        handlers.spawn(async move {
            let Ok(Ok((request, stream))) =
                timeout(HANDSHAKE_TIMEOUT, resolver.resolve_request()).await
            else {
                return;
            };
            handle_request(request, stream, &context, peer).await;
        });
    }
}

async fn handle_request(
    request: Request<()>,
    mut stream: Stream,
    context: &ServerContext,
    peer: IpAddr,
) {
    let permit = match context.authorize_request(&request, peer) {
        Ok(permit) => permit,
        Err(status) => {
            let _ = timeout(CLOSE_TIMEOUT, respond(&mut stream, status)).await;
            let _ = timeout(CLOSE_TIMEOUT, stream.finish()).await;
            // Refuse further body bytes without accepting a tunnel.
            stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            return;
        }
    };
    if !matches!(
        timeout(CLOSE_TIMEOUT, respond(&mut stream, StatusCode::OK)).await,
        Ok(Ok(()))
    ) {
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        return;
    }

    let (mut tx, mut rx) = stream.split();
    let result = timeout(SESSION_TIMEOUT, handle_frames(&mut tx, &mut rx, context)).await;
    if matches!(result, Ok(Ok(()))) {
        if !matches!(timeout(CLOSE_TIMEOUT, tx.finish()).await, Ok(Ok(()))) {
            tx.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
        rx.stop_sending(Code::H3_NO_ERROR);
    } else {
        // A cancelled/partial frame must never be followed by new wire bytes.
        tx.stop_stream(Code::H3_REQUEST_CANCELLED);
        rx.stop_sending(Code::H3_REQUEST_CANCELLED);
    }
    drop(permit);
}

async fn respond(stream: &mut Stream, status: StatusCode) -> Result<(), ServerError> {
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
            let data = timeout(IDLE_TIMEOUT, stream.recv_data())
                .await
                .map_err(|_| ServerError::TimedOut)?
                .map_err(|_| ServerError::Io)?;
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

async fn handle_frames(
    tx: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    rx: &mut RequestStream<h3_quinn::RecvStream, Bytes>,
    context: &ServerContext,
) -> Result<(), ServerError> {
    let mut incoming = Incoming::default();
    let mut state = Session::new(Role::Server);
    let (address, port) = timeout(HANDSHAKE_TIMEOUT, async {
        let hello = incoming.next(rx).await?.ok_or(ServerError::Protocol)?;
        state
            .apply(Direction::Receive, &hello)
            .map_err(|_| ServerError::Protocol)?;
        let ack = Frame::HelloAck {
            version: protocol::VERSION,
            accepted_capabilities: 0,
        };
        state
            .apply(Direction::Send, &ack)
            .map_err(|_| ServerError::Protocol)?;
        send(tx, &ack).await?;
        let open = incoming.next(rx).await?.ok_or(ServerError::Protocol)?;
        state
            .apply(Direction::Receive, &open)
            .map_err(|_| ServerError::Protocol)?;
        let Frame::OpenTcp { address, port } = open else {
            return Err(ServerError::Protocol);
        };
        Ok::<_, ServerError>((address, port))
    })
    .await
    .map_err(|_| ServerError::TimedOut)??;

    // Dial only a shared-policy vetted address. Detect early body/EOF/reset
    // while connecting; a client is not allowed to send DATA before OPEN_OK.
    let dial = tokio::select! {
        biased;
        next = incoming.next(rx) => {
            let _ = next?;
            return Err(ServerError::Protocol);
        }
        result = context.dial_target(&address, port) => result,
    };
    let tcp = match dial {
        Ok(tcp) => tcp,
        Err(code) => {
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
    relay(tcp, tx, rx, incoming, state).await
}

async fn relay(
    tcp: TcpStream,
    tx: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    rx: &mut RequestStream<h3_quinn::RecvStream, Bytes>,
    mut incoming: Incoming,
    mut state: Session,
) -> Result<(), ServerError> {
    let (mut read, mut write) = tcp.into_split();
    let mut upload_state = state.clone();
    let mut download_state = state.clone();
    let upload = async {
        loop {
            let frame = incoming.next(rx).await?.ok_or(ServerError::Protocol)?;
            upload_state
                .apply(Direction::Receive, &frame)
                .map_err(|_| ServerError::Protocol)?;
            match frame {
                Frame::Data(data) => {
                    timeout(IDLE_TIMEOUT, write.write_all(&data))
                        .await
                        .map_err(|_| ServerError::TimedOut)?
                        .map_err(|_| ServerError::Io)?;
                }
                Frame::Fin => {
                    timeout(IDLE_TIMEOUT, write.shutdown())
                        .await
                        .map_err(|_| ServerError::TimedOut)?
                        .map_err(|_| ServerError::Io)?;
                    break;
                }
                _ => return Err(ServerError::Protocol),
            }
        }
        if timeout(IDLE_TIMEOUT, incoming.next(rx))
            .await
            .map_err(|_| ServerError::TimedOut)??
            .is_some()
        {
            return Err(ServerError::Protocol);
        }
        Ok::<(), ServerError>(())
    };
    let download = async {
        let mut buffer = [0; 4096];
        loop {
            let n = timeout(IDLE_TIMEOUT, read.read(&mut buffer))
                .await
                .map_err(|_| ServerError::TimedOut)?
                .map_err(|_| ServerError::Io)?;
            let frame = if n == 0 {
                Frame::Fin
            } else {
                Frame::Data(buffer[..n].to_vec())
            };
            download_state
                .apply(Direction::Send, &frame)
                .map_err(|_| ServerError::Protocol)?;
            send(tx, &frame).await?;
            if n == 0 {
                return Ok::<(), ServerError>(());
            }
        }
    };
    tokio::try_join!(upload, download)?;
    state
        .apply(Direction::Receive, &Frame::Fin)
        .map_err(|_| ServerError::Protocol)?;
    state
        .apply(Direction::Send, &Frame::Fin)
        .map_err(|_| ServerError::Protocol)?;
    state.finish().map_err(|_| ServerError::Protocol)
}
