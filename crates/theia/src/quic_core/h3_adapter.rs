//! h3 0.0.8 transport bridge, using only TLS-established native sessions.
//! Runtime admission remains at the common H3 application boundary.
//! The worker serializes all packet/stream state. Synchronous trait calls
//! never hold the state mutex across UDP I/O. Each direction has one bounded
//! handoff slot and one waker. There is no task per stream or per datagram.
use super::{
    endpoint::{Error as NativeError, LabSession},
    flow,
    lifecycle::ShutdownPhase,
    scheduler, send_flow,
    stream::ReceiveError,
};
use bytes::{Buf, Bytes};
use h3::{
    error::Code,
    quic::{self, ConnectionErrorIncoming as CE, StreamErrorIncoming as SE, StreamId, WriteBuf},
};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch, Notify};

// Include HTTP/3 framing overhead for a 64 KiB application write.
const SLOT_LIMIT: usize = 128 * 1024;
const OPEN_LIMIT: usize = crate::transport_policy::MAX_BIDI_STREAMS as usize + crate::transport_policy::MAX_QUIC_UNI_STREAMS as usize;
const MAX_BURST: usize = 32;
const IDLE_WAIT: Duration = Duration::from_secs(60);
const CANCEL: u64 = 0x10c;

fn internal() -> CE {
    CE::InternalError("native QUIC bridge closed".into())
}
fn connection(error: CE) -> SE {
    SE::ConnectionErrorIncoming {
        connection_error: error,
    }
}
fn invalid() -> SE {
    connection(CE::InternalError(
        "native QUIC bridge state or bound".into(),
    ))
}
fn terminated(code: u64) -> SE {
    SE::StreamTerminated { error_code: code }
}

struct Bridge {
    state: Mutex<State>,
    ready: Arc<Notify>,
}
impl std::ops::Deref for Bridge {
    type Target = Mutex<State>;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.ready.notify_one();
    }
}
type Shared = Arc<Bridge>;
type OpenResult = Result<u64, CE>;
struct OpenRequest {
    bidi: bool,
    result: oneshot::Sender<OpenResult>,
}

#[derive(Default)]
struct StreamState {
    tx: bool,
    rx: bool,
    outgoing: Option<Bytes>,
    incoming: Option<Bytes>,
    finish: bool,
    fin_queued: bool,
    eof: bool,
    reset: Option<u64>,
    reset_sent: bool,
    peer_reset: Option<u64>,
    send_interrupted: bool,
    stop: Option<u64>,
    stop_sent: bool,
    recv_reset: Option<u64>,
    send_dropped: bool,
    recv_dropped: bool,
    send_waker: Option<Waker>,
    recv_waker: Option<Waker>,
}

impl StreamState {
    fn new(tx: bool, rx: bool) -> Self {
        Self {
            tx,
            rx,
            ..Self::default()
        }
    }

    fn peer_stopped(&mut self, code: u64) {
        if self.reset.is_none() {
            self.peer_reset = Some(code);
            self.send_interrupted = self.outgoing.is_some();
        }
        self.outgoing = None;
        self.reset_sent = true;
    }
}

#[cfg(test)]
type RebindRequest = (tokio::net::UdpSocket, oneshot::Sender<Result<(), NativeError>>);

#[derive(Default)]
struct State {
    streams: BTreeMap<u64, StreamState>,
    open: VecDeque<OpenRequest>,
    accept_uni: VecDeque<u64>,
    accept_bidi: VecDeque<u64>,
    uni_waker: Option<Waker>,
    bidi_waker: Option<Waker>,
    error: Option<CE>,
    close: Option<u64>,
    cursor: Option<u64>,
    #[cfg(test)]
    rebind: Option<RebindRequest>,
}

fn wake(slot: &mut Option<Waker>, wakes: &mut Vec<Waker>) {
    if let Some(waker) = slot.take() {
        wakes.push(waker);
    }
}
fn notify(wakes: Vec<Waker>) {
    for waker in wakes {
        waker.wake();
    }
}

impl State {
    fn fail(&mut self, error: CE, wakes: &mut Vec<Waker>) {
        if self.error.is_some() {
            return;
        }
        self.error = Some(error.clone());
        #[cfg(test)]
        if let Some((_, reply)) = self.rebind.take() {
            let _ = reply.send(Err(NativeError::Scope));
        }
        for request in self.open.drain(..) {
            let _ = request.result.send(Err(error.clone()));
        }
        wake(&mut self.uni_waker, wakes);
        wake(&mut self.bidi_waker, wakes);
        self.accept_bidi.clear();
        self.accept_uni.clear();
        for stream in self.streams.values_mut() {
            stream.incoming = None;
            stream.outgoing = None;
            wake(&mut stream.send_waker, wakes);
            wake(&mut stream.recv_waker, wakes);
        }
    }

    fn discover(&mut self, session: &LabSession, wakes: &mut Vec<Waker>) {
        for id in session.peer_streams() {
            if self.streams.contains_key(&id) {
                continue;
            }
            let bidi = id & 2 == 0;
            self.streams.insert(id, StreamState::new(bidi, true));
            if bidi {
                self.accept_bidi.push_back(id);
                wake(&mut self.bidi_waker, wakes);
            } else {
                self.accept_uni.push_back(id);
                wake(&mut self.uni_waker, wakes);
            }
        }
    }
}

fn blocked(error: &NativeError) -> bool {
    matches!(
        error,
        NativeError::Send(send_flow::Error::Limit) | NativeError::Schedule(scheduler::Error::Limit)
    )
}

fn progress(
    session: &mut LabSession,
    state: &mut State,
    wakes: &mut Vec<Waker>,
    ready: &Notify,
) -> Result<(), NativeError> {
    state.discover(session, wakes);
    // Visit each queued open once: a blocked bidi must not starve uni.
    for _ in 0..state.open.len() {
        let Some(request) = state.open.pop_front() else {
            break;
        };
        if request.result.is_closed() {
            continue;
        }
        match if request.bidi {
            session.open_bidi()
        } else {
            session.open_uni()
        } {
            Ok(id) => {
                let mut stream = StreamState::new(true, request.bidi);
                if request.result.send(Ok(id)).is_err() {
                    stream.reset = Some(CANCEL);
                    stream.send_dropped = true;
                    if request.bidi {
                        stream.stop = Some(CANCEL);
                        stream.recv_dropped = true;
                    }
                }
                state.streams.insert(id, stream);
            }
            Err(NativeError::Send(send_flow::Error::Limit))
                if !session.lifetime_exhausted(request.bidi) =>
            {
                state.open.push_back(request);
            }
            Err(_) => {
                // Only exhaustion of the protocol ID space is permanent.
                let _ = request
                    .result
                    .send(Err(CE::InternalError("native stream limit".into())));
            }
        }
    }
    let mut ids: Vec<_> = state.streams.keys().copied().collect();
    if let Some(cursor) = state.cursor {
        let pivot = ids.partition_point(|id| *id <= cursor);
        ids.rotate_left(pivot);
    }
    state.cursor = ids.first().copied();
    for id in ids {
        let s = state.streams.get_mut(&id).expect("known stream");
        if s.tx && !s.reset_sent {
            if let Some(code) = session.send_reset_code(id) {
                s.peer_stopped(code);
                wake(&mut s.send_waker, wakes);
            } else if let Some(code) = s.reset {
                match session.reset_stream(id, code) {
                    Ok(()) => {
                        s.reset_sent = true;
                        s.outgoing = None;
                        wake(&mut s.send_waker, wakes);
                    }
                    Err(e) if blocked(&e) => {}
                    Err(e) => return Err(e),
                }
            } else if let Some(data) = s.outgoing.as_mut() {
                let n = data.len().min(session.send_capacity(id));
                if n != 0 {
                    match session.queue(id, &data[..n], false) {
                        Ok(()) => {
                            data.advance(n);
                            if data.is_empty() {
                                s.outgoing = None;
                                wake(&mut s.send_waker, wakes);
                            }
                        }
                        Err(e) if blocked(&e) => {}
                        Err(e) => return Err(e),
                    }
                }
            } else if s.finish && !s.fin_queued {
                match session.queue(id, &[], true) {
                    Ok(()) => {
                        s.fin_queued = true;
                        wake(&mut s.send_waker, wakes);
                    }
                    Err(e) if blocked(&e) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        if s.rx && !s.eof {
            if let Some(code) = s.stop {
                if !s.stop_sent {
                    match session.stop_sending(id, code) {
                        Ok(()) => {
                            s.stop_sent = true;
                            s.incoming = None;
                            s.eof = true;
                            wake(&mut s.recv_waker, wakes);
                        }
                        Err(e) if blocked(&e) => {}
                        Err(e) => return Err(e),
                    }
                }
            } else if s.incoming.is_none() {
                let mut data = [0; send_flow::MAX_CHUNK];
                match session.read_replenish(id, &mut data) {
                    Ok(n) => {
                        if n != 0 {
                            s.incoming = Some(Bytes::copy_from_slice(&data[..n]));
                        }
                        s.eof = session.finished(id);
                        if n != 0 || s.eof {
                            wake(&mut s.recv_waker, wakes);
                        }
                    }
                    Err(NativeError::Receive(flow::Error::Receive(ReceiveError::Reset(code)))) => {
                        s.recv_reset = Some(code);
                        s.eof = true;
                        wake(&mut s.recv_waker, wakes);
                    }
                    Err(e) if blocked(&e) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        if (!s.tx || s.send_dropped)
            && (!s.rx || s.recv_dropped)
            && session.retire_stream(id, s.tx, s.rx)?
        {
            state.streams.remove(&id);
            ready.notify_one();
        }
    }
    Ok(())
}

fn fail(weak: &Weak<Bridge>, error: CE) {
    if let Some(shared) = weak.upgrade() {
        let mut wakes = Vec::new();
        shared.lock().expect("bridge mutex").fail(error, &mut wakes);
        notify(wakes);
    }
}

async fn drive(mut session: LabSession, weak: Weak<Bridge>, ready: Arc<Notify>) {
    let mut burst = 0;
    loop {
        #[cfg(test)]
        {
            // The test command runs on the sole session owner, never while
            // the frontend state mutex is held across asynchronous UDP I/O.
            let request = weak.upgrade().and_then(|shared| {
                shared.lock().expect("bridge mutex").rebind.take()
            });
            if let Some((socket, reply)) = request {
                let result = session.rebind(socket, Instant::now()).await;
                let _ = reply.send(result);
            }
        }
        let mut wakes = Vec::new();
        let phase = session.shutdown_phase();
        let result = if let Some(shared) = weak.upgrade() {
            let mut state = shared.lock().expect("bridge mutex");
            if phase == ShutdownPhase::Open {
                if let Some(code) = state.close.take() {
                    session.close(code, Instant::now())
                } else if state.error.is_none() {
                    progress(&mut session, &mut state, &mut wakes, &ready)
                } else {
                    Ok(())
                }
            } else {
                let error = session
                    .peer_application_close()
                    .map_or_else(internal, |error_code| CE::ApplicationClose { error_code });
                state.fail(error, &mut wakes);
                Ok(())
            }
        } else {
            // Last frontend dropped. Close the transport, keeping the route
            // until the normal shutdown timer, even without frontend state.
            if phase == ShutdownPhase::Open {
                session.close(0x100, Instant::now())
            } else {
                Ok(())
            }
        };
        notify(wakes);
        if result.is_err() {
            fail(&weak, internal());
            return;
        }
        if session.shutdown_phase() == ShutdownPhase::Closed {
            fail(&weak, internal());
            return;
        }
        let sent = match session.flush(Instant::now()).await {
            Ok(sent) => sent,
            Err(_) => {
                fail(&weak, internal());
                return;
            }
        };
        if session.shutdown_phase() == ShutdownPhase::Closed {
            fail(&weak, internal());
            return;
        }
        // Bound immediate sends so a full socket cannot starve ingress or other connections.
        if sent && burst < MAX_BURST {
            burst += 1;
            continue;
        }
        let wait = if sent {
            tokio::task::yield_now().await;
            Duration::ZERO
        } else {
            session.deadline().map_or(IDLE_WAIT, |at| {
                at.saturating_duration_since(Instant::now()).min(IDLE_WAIT)
            })
        };
        burst = 0;
        if session.recv_with_wake(wait, Some(&ready)).await.is_err() {
            fail(&weak, internal());
            return;
        }
    }
}

pub struct NativeConnection {
    opener: Opener,
    closed: watch::Receiver<()>,
    driver: tokio::task::AbortHandle,
}

/// Server generation owns this guard even after H3 consumes the connection.
/// Cancellation of a generation cannot leave a detached UDP session alive.
pub(crate) struct DriverGuard(tokio::task::AbortHandle);

impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl NativeConnection {
    /// Returns exporter material separately so admission remains the
    /// existing caller's responsibility. The raw fixed-key fixture cannot
    /// enter this API. The caller retains the existing admission policy.
    pub fn start(mut session: LabSession) -> Result<(Self, zeroize::Zeroizing<[u8; 32]>), CE> {
        let key = session.take_channel_binding().ok_or_else(internal)?;
        session.enable_auto_cids();
        let ready = Arc::new(Notify::new());
        let shared = Arc::new(Bridge {
            state: Mutex::new(State::default()),
            ready: ready.clone(),
        });
        let (done, closed) = watch::channel(());
        let weak = Arc::downgrade(&shared);
        let driver = tokio::spawn(async move {
            drive(session, weak, ready).await;
            drop(done);
        }).abort_handle();
        Ok((
            Self {
                opener: Opener::new(shared),
                closed,
                driver,
            },
            key,
        ))
    }

    #[cfg(test)]
    pub(crate) fn test_opener(&self) -> Opener {
        self.opener.clone()
    }

    pub(crate) fn driver_guard(&self) -> DriverGuard {
        DriverGuard(self.driver.clone())
    }

    pub(crate) fn closed_signal(&self) -> watch::Receiver<()> {
        self.closed.clone()
    }

    fn accept(&self, cx: &mut Context<'_>, bidi: bool) -> Poll<Result<u64, CE>> {
        let mut s = self.opener.shared.lock().expect("bridge mutex");
        if let Some(error) = &s.error {
            return Poll::Ready(Err(error.clone()));
        }
        let id = if bidi {
            s.accept_bidi.pop_front()
        } else {
            s.accept_uni.pop_front()
        };
        if let Some(id) = id {
            return Poll::Ready(Ok(id));
        }
        if bidi {
            s.bidi_waker = Some(cx.waker().clone());
        } else {
            s.uni_waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

pub struct Opener {
    shared: Shared,
    uni: Option<oneshot::Receiver<OpenResult>>,
    bidi: Option<oneshot::Receiver<OpenResult>>,
}

impl Clone for Opener {
    fn clone(&self) -> Self {
        Self::new(self.shared.clone())
    }
}

impl Drop for Opener {
    fn drop(&mut self) {
        // If a completed open was never polled by its caller, ownership
        // never reached a stream handle. Cancel that stream exactly once.
        for pending in [&mut self.uni, &mut self.bidi] {
            if let Some(mut pending) = pending.take() {
                pending.close();
                if let Ok(Ok(id)) = pending.try_recv() {
                    if let Some(s) = self
                        .shared
                        .lock()
                        .expect("bridge mutex")
                        .streams
                        .get_mut(&id)
                    {
                        s.reset = Some(CANCEL);
                        s.send_dropped = true;
                        if s.rx {
                            s.stop = Some(CANCEL);
                            s.recv_dropped = true;
                        }
                    }
                }
            }
        }
        self.shared.ready.notify_one();
    }
}

impl Opener {
    #[cfg(test)]
    pub(crate) async fn rebind_for_test(&self, socket: std::net::UdpSocket) -> Result<(), NativeError> {
        let socket = tokio::net::UdpSocket::from_std(socket).map_err(NativeError::Io)?;
        let (reply, result) = oneshot::channel();
        {
            let mut state = self.shared.lock().expect("bridge mutex");
            if state.error.is_some() || state.close.is_some() || state.rebind.is_some() {
                return Err(NativeError::Scope);
            }
            state.rebind = Some((socket, reply));
        }
        self.shared.ready.notify_one();
        result.await.map_err(|_| NativeError::Scope)?
    }

    fn new(shared: Shared) -> Self {
        Self {
            shared,
            uni: None,
            bidi: None,
        }
    }

    fn open(&mut self, cx: &mut Context<'_>, bidi: bool) -> Poll<Result<u64, SE>> {
        let slot = if bidi { &mut self.bidi } else { &mut self.uni };
        if slot.is_none() {
            let mut state = self.shared.lock().expect("bridge mutex");
            if let Some(e) = &state.error {
                return Poll::Ready(Err(connection(e.clone())));
            }
            if state.open.len() >= OPEN_LIMIT {
                return Poll::Ready(Err(invalid()));
            }
            let (result, rx) = oneshot::channel();
            state.open.push_back(OpenRequest { bidi, result });
            self.shared.ready.notify_one();
            *slot = Some(rx);
        }
        match Pin::new(slot.as_mut().expect("pending open")).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                *slot = None;
                Poll::Ready(
                    result
                        .unwrap_or_else(|_| Err(internal()))
                        .map_err(connection),
                )
            }
        }
    }

    fn close_inner(&self, code: Code) {
        let mut wakes = Vec::new();
        {
            let mut state = self.shared.lock().expect("bridge mutex");
            if state.error.is_none() {
                let code = code.value();
                state.close = Some(code);
                state.fail(CE::ApplicationClose { error_code: code }, &mut wakes);
            }
        }
        self.shared.ready.notify_one();
        notify(wakes);
    }
}

impl quic::OpenStreams<Bytes> for Opener {
    type BidiStream = Bidi;
    type SendStream = SendSide;
    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bidi, SE>> {
        self.open(cx, true)
            .map(|r| r.map(|id| Bidi::new(self.shared.clone(), id)))
    }
    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<SendSide, SE>> {
        self.open(cx, false)
            .map(|r| r.map(|id| SendSide::new(self.shared.clone(), id)))
    }
    fn close(&mut self, code: Code, _: &[u8]) {
        self.close_inner(code);
    }
}

impl quic::OpenStreams<Bytes> for NativeConnection {
    type BidiStream = Bidi;
    type SendStream = SendSide;
    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bidi, SE>> {
        quic::OpenStreams::poll_open_bidi(&mut self.opener, cx)
    }
    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<SendSide, SE>> {
        quic::OpenStreams::poll_open_send(&mut self.opener, cx)
    }
    fn close(&mut self, code: Code, _: &[u8]) {
        self.opener.close_inner(code);
    }
}

impl quic::Connection<Bytes> for NativeConnection {
    type RecvStream = RecvSide;
    type OpenStreams = Opener;
    fn poll_accept_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<RecvSide, CE>> {
        self.accept(cx, false)
            .map(|r| r.map(|id| RecvSide::new(self.opener.shared.clone(), id)))
    }
    fn poll_accept_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bidi, CE>> {
        self.accept(cx, true)
            .map(|r| r.map(|id| Bidi::new(self.opener.shared.clone(), id)))
    }
    fn opener(&self) -> Opener {
        Opener::new(self.opener.shared.clone())
    }
}

pub struct SendSide {
    shared: Shared,
    id: u64,
}
impl SendSide {
    fn new(shared: Shared, id: u64) -> Self {
        Self { shared, id }
    }

    fn put(&mut self, bytes: Bytes) -> Result<(), SE> {
        let mut state = self.shared.lock().expect("bridge mutex");
        if let Some(error) = &state.error {
            return Err(connection(error.clone()));
        }
        let s = state.streams.get_mut(&self.id).ok_or_else(invalid)?;
        if let Some(code) = s.peer_reset {
            return Err(terminated(code));
        }
        if bytes.len() > SLOT_LIMIT || s.outgoing.is_some() || s.finish || s.reset.is_some() {
            return Err(invalid());
        }
        if !bytes.is_empty() {
            s.outgoing = Some(bytes);
            self.shared.ready.notify_one();
        }
        Ok(())
    }

    fn cancel(&self, code: u64) {
        let mut state = self.shared.lock().expect("bridge mutex");
        if let Some(s) = state.streams.get_mut(&self.id) {
            if !s.fin_queued && !s.reset_sent && s.reset.is_none() {
                s.reset = Some(code);
                s.outgoing = None;
                self.shared.ready.notify_one();
            }
        }
    }
}
impl Drop for SendSide {
    fn drop(&mut self) {
        self.cancel(CANCEL);
        if let Some(s) = self
            .shared
            .lock()
            .expect("bridge mutex")
            .streams
            .get_mut(&self.id)
        {
            s.send_dropped = true;
        }
        self.shared.ready.notify_one();
    }
}

impl quic::SendStream<Bytes> for SendSide {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SE>> {
        let mut state = self.shared.lock().expect("bridge mutex");
        if let Some(error) = &state.error {
            return Poll::Ready(Err(connection(error.clone())));
        }
        let Some(s) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(invalid()));
        };
        // A peer may reject a request immediately after receiving its headers.
        // Do not turn a completed handoff into a failed write: H3 must be
        // able to read the response on the independent receive half.
        // New writes and unfinished handoffs still fail after STOP_SENDING.
        if let Some(code) = s.peer_reset.filter(|_| s.send_interrupted) {
            return Poll::Ready(Err(terminated(code)));
        }
        if s.reset.is_some() {
            return Poll::Ready(Err(invalid()));
        }
        if s.outgoing.is_none() {
            return Poll::Ready(Ok(()));
        }
        s.send_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), SE> {
        let mut data = data.into();
        let n = data.remaining();
        if n > SLOT_LIMIT {
            return Err(invalid());
        }
        self.put(data.copy_to_bytes(n))
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SE>> {
        let mut state = self.shared.lock().expect("bridge mutex");
        if let Some(error) = &state.error {
            return Poll::Ready(Err(connection(error.clone())));
        }
        let Some(s) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(invalid()));
        };
        if let Some(code) = s.peer_reset {
            return Poll::Ready(Err(terminated(code)));
        }
        if s.reset.is_some() {
            return Poll::Ready(Err(invalid()));
        }
        if s.fin_queued {
            return Poll::Ready(Ok(()));
        }
        s.finish = true;
        self.shared.ready.notify_one();
        s.send_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn reset(&mut self, code: u64) {
        self.cancel(code);
    }
    fn send_id(&self) -> StreamId {
        StreamId::try_from(self.id).expect("native stream ID")
    }
}

impl quic::SendStreamUnframed<Bytes> for SendSide {
    fn poll_send<D: Buf>(&mut self, cx: &mut Context<'_>, buf: &mut D) -> Poll<Result<usize, SE>> {
        match quic::SendStream::poll_ready(self, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let n = buf.remaining().min(send_flow::MAX_CHUNK);
                Poll::Ready(self.put(buf.copy_to_bytes(n)).map(|_| n))
            }
        }
    }
}

pub struct RecvSide {
    shared: Shared,
    id: u64,
}
impl RecvSide {
    fn new(shared: Shared, id: u64) -> Self {
        Self { shared, id }
    }
    fn stop(&self, code: u64) {
        let mut state = self.shared.lock().expect("bridge mutex");
        if let Some(s) = state.streams.get_mut(&self.id) {
            if !s.eof && s.stop.is_none() {
                s.stop = Some(code);
                s.incoming = None;
                self.shared.ready.notify_one();
            }
        }
    }
}
impl Drop for RecvSide {
    fn drop(&mut self) {
        self.stop(CANCEL);
        if let Some(s) = self
            .shared
            .lock()
            .expect("bridge mutex")
            .streams
            .get_mut(&self.id)
        {
            s.recv_dropped = true;
        }
        self.shared.ready.notify_one();
    }
}
impl quic::RecvStream for RecvSide {
    type Buf = Bytes;
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, SE>> {
        let mut state = self.shared.lock().expect("bridge mutex");
        if let Some(error) = &state.error {
            return Poll::Ready(Err(connection(error.clone())));
        }
        let Some(s) = state.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(invalid()));
        };
        if let Some(code) = s.recv_reset {
            return Poll::Ready(Err(terminated(code)));
        }
        if let Some(data) = s.incoming.take() {
            self.shared.ready.notify_one();
            return Poll::Ready(Ok(Some(data)));
        }
        if s.eof || s.stop.is_some() {
            return Poll::Ready(Ok(None));
        }
        s.recv_waker = Some(cx.waker().clone());
        Poll::Pending
    }
    fn stop_sending(&mut self, code: u64) {
        self.stop(code);
    }
    fn recv_id(&self) -> StreamId {
        StreamId::try_from(self.id).expect("native stream ID")
    }
}

pub struct Bidi {
    send: SendSide,
    recv: RecvSide,
}
impl Bidi {
    fn new(shared: Shared, id: u64) -> Self {
        Self {
            send: SendSide::new(shared.clone(), id),
            recv: RecvSide::new(shared, id),
        }
    }
}
impl quic::SendStream<Bytes> for Bidi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SE>> {
        quic::SendStream::poll_ready(&mut self.send, cx)
    }
    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), SE> {
        quic::SendStream::send_data(&mut self.send, data)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SE>> {
        quic::SendStream::poll_finish(&mut self.send, cx)
    }
    fn reset(&mut self, code: u64) {
        quic::SendStream::reset(&mut self.send, code);
    }
    fn send_id(&self) -> StreamId {
        quic::SendStream::send_id(&self.send)
    }
}
impl quic::RecvStream for Bidi {
    type Buf = Bytes;
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, SE>> {
        quic::RecvStream::poll_data(&mut self.recv, cx)
    }
    fn stop_sending(&mut self, code: u64) {
        quic::RecvStream::stop_sending(&mut self.recv, code);
    }
    fn recv_id(&self) -> StreamId {
        quic::RecvStream::recv_id(&self.recv)
    }
}
impl quic::BidiStream<Bytes> for Bidi {
    type SendStream = SendSide;
    type RecvStream = RecvSide;
    fn split(self) -> (SendSide, RecvSide) {
        (self.send, self.recv)
    }
}
impl quic::SendStreamUnframed<Bytes> for Bidi {
    fn poll_send<D: Buf>(&mut self, cx: &mut Context<'_>, buf: &mut D) -> Poll<Result<usize, SE>> {
        quic::SendStreamUnframed::poll_send(&mut self.send, cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_stop_preserves_completed_handoff_and_rejects_interrupted_write() {
        for handed_off in [false, true] {
            let shared = Arc::new(Bridge {
                state: Mutex::new(State::default()),
                ready: Arc::new(Notify::new()),
            });
            shared
                .lock()
                .unwrap()
                .streams
                .insert(0, StreamState::new(true, true));
            let mut send = SendSide::new(shared.clone(), 0);
            let mut recv = RecvSide::new(shared.clone(), 0);
            let mut cx = Context::from_waker(Waker::noop());
            send.put(Bytes::from_static(b"headers")).unwrap();
            assert!(quic::SendStream::poll_ready(&mut send, &mut cx).is_pending());

            {
                let mut state = shared.lock().unwrap();
                let stream = state.streams.get_mut(&0).unwrap();
                if handed_off {
                    stream.outgoing = None;
                }
                stream.peer_stopped(CANCEL);
                stream.incoming = Some(Bytes::from_static(b"response"));
                stream.eof = true;
            }

            let ready = quic::SendStream::poll_ready(&mut send, &mut cx);
            if handed_off {
                assert!(matches!(ready, Poll::Ready(Ok(()))));
            } else {
                assert!(matches!(
                    ready,
                    Poll::Ready(Err(SE::StreamTerminated { error_code: CANCEL }))
                ));
            }
            assert!(matches!(
                send.put(Bytes::from_static(b"body")),
                Err(SE::StreamTerminated { error_code: CANCEL })
            ));
            assert!(matches!(
                quic::SendStream::poll_finish(&mut send, &mut cx),
                Poll::Ready(Err(SE::StreamTerminated { error_code: CANCEL }))
            ));
            assert!(matches!(
                quic::RecvStream::poll_data(&mut recv, &mut cx),
                Poll::Ready(Ok(Some(bytes))) if bytes == Bytes::from_static(b"response")
            ));
            assert!(matches!(
                quic::RecvStream::poll_data(&mut recv, &mut cx),
                Poll::Ready(Ok(None))
            ));
        }
    }
}
