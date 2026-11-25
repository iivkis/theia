//! Bounded TCP first-flight classification and exact-byte relay primitives.
//! No network listener is created here. The admitted branch must still
//! complete standard TLS 1.3 and independent identity authentication.
#![forbid(unsafe_code)]

use crate::{
    config::Config,
    identity_tls::Branch,
    reality_admission::{self, Context, ReplayGuard, Secret},
    reality_generation::Manager,
    reference_health::RelayLease,
    server::{self, ServerContext, ServerError},
};
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
    task::JoinSet,
    time::{timeout, timeout_at, Instant},
};

const MAX_RECORD: usize = 16 * 1024;
const MAX_WIRE: usize = 64 * 1024;
const FIRST_FLIGHT: Duration = Duration::from_secs(3);
const CONNECT: Duration = Duration::from_secs(5);
const RELAY_LIFETIME: Duration = Duration::from_secs(60);
const RELAY_BYTES: usize = 8 * 1024 * 1024;
const RELAY_CONNECTIONS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Io,
    Deadline,
    Limit,
    Reference,
}

/// Preserve every byte consumed by first-flight inspection, including
/// incomplete records, data beyond the first handshake and malformed TLS.
/// Normal TLS or the relay sees the original byte stream exactly once.
pub struct Prefixed<T> {
    inner: T,
    prefix: bytes::Bytes,
}

impl<T: AsyncRead + Unpin> AsyncRead for Prefixed<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let count = out.remaining().min(self.prefix.len());
            out.put_slice(&self.prefix.split_to(count));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Prefixed<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, input)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct Inspected<T> {
    io: Prefixed<T>,
    hello: Option<Vec<u8>>,
}

impl<T> Inspected<T> {
    /// Only a verified and consumed marker enters the admitted branch.
    /// All other observations collapse to Relay, including replay and
    /// cache exhaustion. No diagnostic is exposed on the network.
    pub fn classify(
        self,
        guard: &ReplayGuard,
        secret: &Secret,
        context: &Context<'_>,
        now: u64,
    ) -> Decision<T> {
        if self
            .hello
            .as_ref()
            .is_some_and(|hello| guard.admit(secret, context, hello, now).is_ok())
        {
            Decision::Admitted(self.io)
        } else {
            Decision::Relay(self.io)
        }
    }
}

pub enum Decision<T> {
    Admitted(Prefixed<T>),
    Relay(Prefixed<T>),
}

async fn fill<T: AsyncRead + Unpin>(
    io: &mut T,
    raw: &mut Vec<u8>,
    end: usize,
    deadline: Instant,
) -> Result<bool, Error> {
    if end > MAX_WIRE {
        return Ok(false);
    }
    let mut block = [0; 4096];
    while raw.len() < end {
        let count = (end - raw.len()).min(block.len());
        let n = match timeout_at(deadline, io.read(&mut block[..count])).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Err(Error::Io),
            Err(_) => return Ok(false),
        };
        if n == 0 {
            return Ok(false);
        }
        raw.extend_from_slice(&block[..n]);
    }
    Ok(true)
}

/// Collect the first TLS handshake across arbitrary TCP fragmentation and
/// TLS record fragmentation, with an absolute deadline and independent
/// wire/handshake bounds. Non-TLS inputs and partial reads are preserved.
pub async fn inspect<T: AsyncRead + Unpin>(mut io: T) -> Result<Inspected<T>, Error> {
    let deadline = Instant::now() + FIRST_FLIGHT;
    let mut raw = Vec::new();
    let mut hello = Vec::new();
    let mut complete = false;
    loop {
        let start = raw.len();
        if !fill(&mut io, &mut raw, start + 5, deadline).await? {
            break;
        }
        let header = &raw[start..start + 5];
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if header[0] != 22
            || header[1] != 3
            || !(1..=3).contains(&header[2])
            || !(1..=MAX_RECORD).contains(&length)
        {
            break;
        }
        if !fill(&mut io, &mut raw, start + 5 + length, deadline).await? {
            break;
        }
        let record = &raw[start + 5..];
        if hello.len() + record.len() > reality_admission::MAX_HELLO + MAX_RECORD {
            break;
        }
        hello.extend_from_slice(record);
        if hello.first() != Some(&1) {
            break;
        }
        if hello.len() >= 4 {
            let expected = 4
                + ((usize::from(hello[1]) << 16)
                    | (usize::from(hello[2]) << 8)
                    | usize::from(hello[3]));
            if !(38..=reality_admission::MAX_HELLO).contains(&expected) {
                break;
            }
            if hello.len() >= expected {
                hello.truncate(expected);
                complete = true;
                break;
            }
        }
    }
    Ok(Inspected {
        io: Prefixed {
            inner: io,
            prefix: raw.into(),
        },
        hello: complete.then_some(hello),
    })
}

async fn transfer<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    remaining: &AtomicUsize,
) -> Result<(), Error> {
    let mut buffer = [0; 8192];
    loop {
        let count = reader.read(&mut buffer).await.map_err(|_| Error::Io)?;
        if count == 0 {
            writer.shutdown().await.map_err(|_| Error::Io)?;
            return Ok(());
        }
        remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(count)
            })
            .map_err(|_| Error::Limit)?;
        writer
            .write_all(&buffer[..count])
            .await
            .map_err(|_| Error::Io)?;
    }
}

/// Single shared byte cap across directions; partial reads are never
/// expanded or rewritten. Cancellation closes both streams and releases
/// all permits. The timeout is total duration, not reset by traffic.
async fn relay_io<A, B>(
    client: A,
    upstream: B,
    limit: usize,
    lifetime: Duration,
) -> Result<(), Error>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let remaining = AtomicUsize::new(limit);
    timeout(lifetime, async {
        tokio::try_join!(
            transfer(client_read, upstream_write, &remaining),
            transfer(upstream_read, client_write, &remaining),
        )?;
        Ok(())
    })
    .await
    .map_err(|_| Error::Deadline)?
}

/// One gate per runtime inbound; callers must acquire a slot before
/// opening a reference connection. There is no caller-supplied address.
pub struct RelayGate {
    slots: Arc<Semaphore>,
}

impl Default for RelayGate {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(RELAY_CONNECTIONS)),
        }
    }
}

impl RelayGate {
    pub async fn relay<T>(&self, client: Prefixed<T>, lease: &RelayLease) -> Result<(), Error>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let _slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Limit)?;
        let address = lease.address().map_err(|_| Error::Reference)?;
        let upstream = timeout(CONNECT, TcpStream::connect(address))
            .await
            .map_err(|_| Error::Deadline)?
            .map_err(|_| Error::Io)?;
        if upstream.peer_addr().map_err(|_| Error::Io)? != address
            || lease.address().map_err(|_| Error::Reference)? != address
        {
            return Err(Error::Reference);
        }
        relay_io(client, upstream, RELAY_BYTES, RELAY_LIFETIME).await
    }
}

/// Prepared single-generation TCP backend. The construction requires the
/// exact registered bundle and durable generation floor. Startup can share
/// one immutable lease and application context with the QUIC backend.
/// Both accepted and reference paths are bounded; all sockets are owned
/// by this task's JoinSet and cancelled on shutdown.
pub struct PreparedTcp {
    listener: TcpListener,
    live: Arc<crate::reality_live::Live>,
    relay: Arc<RelayGate>,
    inspection_slots: Arc<Semaphore>,
}

impl PreparedTcp {
    pub fn prepare(
        listener: TcpListener,
        document: &Config,
        inbound_id: &str,
    ) -> Result<Self, ServerError> {
        let Config::Server(doc) = document else {
            return Err(ServerError::Config);
        };
        let inbound = doc
            .server
            .inbounds
            .iter()
            .find(|i| i.id == inbound_id)
            .ok_or(ServerError::Config)?;
        let expected: std::net::SocketAddr =
            inbound.h2_listen.parse().map_err(|_| ServerError::Config)?;
        if listener.local_addr().map_err(|_| ServerError::Io)? != expected {
            return Err(ServerError::Config);
        }
        let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
        let manager = Manager::new(document, inbound_id, now).map_err(|_| ServerError::Config)?;
        let lease = Arc::new(manager.refresh(now).map_err(|_| ServerError::Config)?);
        let context = Arc::new(ServerContext::new(
            inbound,
            &doc.server.users,
            &doc.server.policy,
        ));
        Self::from_shared(listener, lease, context, now)
    }

    pub(crate) fn from_shared(
        listener: TcpListener,
        lease: Arc<crate::reality_generation::Lease>,
        context: Arc<ServerContext>,
        now: u64,
    ) -> Result<Self, ServerError> {
        Self::from_live(
            listener,
            crate::reality_live::Live::new(lease, context, now)?,
        )
    }

    pub(crate) fn from_live(
        listener: TcpListener,
        live: Arc<crate::reality_live::Live>,
    ) -> Result<Self, ServerError> {
        Ok(Self {
            listener,
            live,
            relay: Arc::new(RelayGate::default()),
            inspection_slots: Arc::new(Semaphore::new(64)),
        })
    }

    pub async fn serve(self) -> Result<(), ServerError> {
        let (_owner, phase) = watch::channel(server::GenerationPhase::Active);
        self.serve_generation(phase).await
    }

    pub(crate) async fn serve_generation(self, mut phase: watch::Receiver<server::GenerationPhase>) -> Result<(), ServerError> {
        crate::tcp_bbr::select(&self.listener)
            .map_err(|_| ServerError::TcpControllerUnavailable)?;
        let Self { listener, live, relay, inspection_slots } = self;
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = server::await_generation_drain(&mut phase) => break,
                _ = tasks.join_next(), if !tasks.is_empty() => {}
                result = listener.accept() => {
                    let (socket, peer) = result.map_err(|_| ServerError::Io)?;
                    let Ok(slot) = inspection_slots.clone().try_acquire_owned() else { continue; };
                    if crate::tcp_bbr::select(&socket).is_err() { continue; }
                    let live = live.clone();
                    let relay = relay.clone();
                    let connection_phase = phase.clone();
                    tasks.spawn(async move {
                        let Ok(inspected) = inspect(socket).await else { return; };
                        if server::generation_draining(&connection_phase) { return; }
                        let Ok(now) = crate::reference_health::unix_now() else { return; };
                        let Some(generation)=live.current() else { return; };
                        let selected=inspected.hello.as_ref().and_then(|hello|
                            generation.select(&live.guard,Branch::H2,hello,now));
                        if let Some(route)=selected {
                            let Some(connection)=route.context.connection_slot() else { return; };
                            drop(slot);
                            server::serve_h2_socket(inspected.io,route.tcp.clone(),route.context.clone(),
                                peer,connection,crate::diagnostics::next_id(),connection_phase).await;
                        } else {
                            let Some(value)=generation.relay_value(now) else { return; };
                            let Ok(lease)=generation.lease.health().relay_lease(value,generation.lease.publication().plan_sha256()).await else { return; };
                            let _=relay.relay(inspected.io,&lease).await;
                            drop(slot);
                        }
                    });
                }
            }
        }
        drop(listener);
        let _ = timeout(server::GENERATION_DRAIN, async {
            while tasks.join_next().await.is_some() {}
        }).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(data: &[u8]) -> Vec<u8> {
        let mut result = vec![22, 3, 3];
        result.extend_from_slice(&(data.len() as u16).to_be_bytes());
        result.extend_from_slice(data);
        result
    }

    #[tokio::test]
    async fn first_flight_preserves_fragmentation_and_trailing_bytes() {
        let mut hello = vec![1, 0, 0, 34];
        hello.extend_from_slice(&[8; 34]);
        let mut raw = record(&hello[..2]);
        let mut final_record = hello[2..].to_vec();
        final_record.extend_from_slice(b"extra");
        raw.extend_from_slice(&record(&final_record));
        raw.extend_from_slice(b"later");
        let (mut writer, reader) = tokio::io::duplex(1024);
        let original = raw.clone();
        let producer = tokio::spawn(async move {
            for byte in original {
                writer.write_all(&[byte]).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });
        let mut inspected = inspect(reader).await.unwrap();
        assert_eq!(inspected.hello, Some(hello));
        let mut seen = Vec::new();
        inspected.io.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, raw);
        producer.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_and_partial_inputs_are_not_lost() {
        for raw in [
            b"GET / HTTP/1.1\r\n".as_slice(),
            &[22, 3, 3, 0, 12, 1, 0],
            &[22, 3],
        ] {
            let (mut writer, reader) = tokio::io::duplex(1024);
            writer.write_all(raw).await.unwrap();
            writer.shutdown().await.unwrap();
            let mut inspected = inspect(reader).await.unwrap();
            assert!(inspected.hello.is_none());
            let mut seen = Vec::new();
            inspected.io.read_to_end(&mut seen).await.unwrap();
            assert_eq!(seen, raw);
        }
    }

    #[tokio::test]
    async fn relay_preserves_both_directions_and_half_close() {
        let (mut client, relay_client) = tokio::io::duplex(1024);
        let (relay_reference, mut reference) = tokio::io::duplex(1024);
        let task = tokio::spawn(relay_io(
            relay_client,
            relay_reference,
            100,
            Duration::from_secs(2),
        ));
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut seen = Vec::new();
        reference.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"request");
        reference.write_all(b"response").await.unwrap();
        reference.shutdown().await.unwrap();
        seen.clear();
        client.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"response");
        assert_eq!(task.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn relay_total_cap_and_deadline_are_enforced() {
        let (mut client, relay_client) = tokio::io::duplex(1024);
        let (relay_reference, mut reference) = tokio::io::duplex(1024);
        let task = tokio::spawn(relay_io(
            relay_client,
            relay_reference,
            5,
            Duration::from_secs(2),
        ));
        client.write_all(b"1234").await.unwrap();
        let mut first = [0; 4];
        reference.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"1234");
        reference.write_all(b"ab").await.unwrap();
        assert_eq!(task.await.unwrap(), Err(Error::Limit));
        let (client, _writer) = tokio::io::duplex(16);
        let (reference, _reader) = tokio::io::duplex(16);
        assert_eq!(
            relay_io(client, reference, 16, Duration::from_millis(10)).await,
            Err(Error::Deadline)
        );
    }
}
