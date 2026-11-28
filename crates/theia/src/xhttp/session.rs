//! One client session/relay state machine for H2 and H3. HTTP stream
//! creation, framing I/O and authenticated transport remain in adapters.
use crate::{
    diagnostics::{self, Level, Value},
    net::error::{endpoint_unavailable, error_kind, ClientError},
    protocol::{self, Direction, Frame, Session},
    routing::{
        flow::{FirstSend, FlowLease},
        PacketAction,
    },
    split_http::{AutoMode, HelloOutcome},
};
use std::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    time::timeout,
};

pub(crate) const OPEN_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub(crate) enum CarrierKind {
    H2,
    H3,
}
impl CarrierKind {
    fn h3(self) -> bool {
        matches!(self, Self::H3)
    }
    fn component(self) -> &'static str {
        match self {
            Self::H2 => "client.h2",
            Self::H3 => "client.h3",
        }
    }
    fn event(self, level: Level, event: &'static str, fields: &[(&'static str, Value)]) {
        diagnostics::emit(level, self.component(), event, fields, file!(), line!());
    }
}

pub(crate) trait OpenAdapter: Sync {
    type Tunnel: Send;
    const KIND: CarrierKind;
    fn explicit_stream_up(&self) -> bool;
    fn automatic_mode(&self) -> Option<&AutoMode>;
    fn open_attempt<'a>(
        &'a self,
        open: &'a Frame,
        operation: u64,
        stream_up: bool,
        stage: &'a mut HelloOutcome,
    ) -> impl Future<Output = Result<Self::Tunnel, ClientError>> + Send + 'a;
}

pub(crate) async fn open<A: OpenAdapter>(
    adapter: &A,
    frame: Frame,
) -> Result<A::Tunnel, ClientError> {
    let operation = diagnostics::next_id();
    A::KIND.event(
        Level::Debug,
        "open_begin",
        &[("op", Value::Count(operation))],
    );
    protocol::encode(&frame).map_err(|_| ClientError::Configuration)?;
    let result = timeout(OPEN_TIMEOUT, open_selected(adapter, &frame, operation))
        .await
        .map_err(|_| ClientError::Timeout)
        .and_then(|result| result);
    match &result {
        Ok(_) => A::KIND.event(
            Level::Debug,
            "open_confirmed",
            &[("op", Value::Count(operation))],
        ),
        Err(error) => A::KIND.event(
            Level::Warn,
            "open_failed",
            &[
                ("op", Value::Count(operation)),
                ("reason", Value::Label(error_kind(error))),
            ],
        ),
    }
    result
}

/// A prior admitted carrier is no longer negative availability evidence.
/// An interrupted retry must not authorize H3->H2 fallback.
fn retry_result<T>(kind: CarrierKind, result: Result<T, ClientError>) -> Result<T, ClientError> {
    match result {
        Err(error) if kind.h3() && endpoint_unavailable(error).is_some() => {
            Err(ClientError::Timeout)
        }
        other => other,
    }
}

async fn open_selected<A: OpenAdapter>(
    adapter: &A,
    open: &Frame,
    operation: u64,
) -> Result<A::Tunnel, ClientError> {
    let mut stage = HelloOutcome::Pending;
    let Some(mode) = adapter.automatic_mode() else {
        return open_mode(
            adapter,
            open,
            operation,
            adapter.explicit_stream_up(),
            &mut stage,
        )
        .await;
    };
    let ticket = mode.select()?;
    let stream_up = ticket.stream_up;
    let result = open_mode(adapter, open, operation, stream_up, &mut stage).await;
    if !mode.after_attempt(ticket, stream_up, stage)? {
        return result;
    }
    // The failed admitted session has been dropped, before any OPEN.
    A::KIND.event(Level::Debug, "xhttp_pre_open_stream_up_retry", &[]);
    let mut stage = HelloOutcome::Pending;
    let result = open_mode(adapter, open, operation, true, &mut stage).await;
    mode.after_attempt(ticket, true, stage)?;
    retry_result(A::KIND, result)
}

/// One retry only for explicit graceful drain before HELLO/OPEN.
async fn open_mode<A: OpenAdapter>(
    adapter: &A,
    open: &Frame,
    operation: u64,
    stream_up: bool,
    stage: &mut HelloOutcome,
) -> Result<A::Tunnel, ClientError> {
    let result = adapter
        .open_attempt(open, operation, stream_up, stage)
        .await;
    if *stage != HelloOutcome::Draining {
        return result;
    }
    *stage = HelloOutcome::Pending;
    let result = adapter
        .open_attempt(open, operation, stream_up, stage)
        .await;
    retry_result(A::KIND, result)
}

pub(crate) trait FrameWriter: Send {
    /// Write one complete frame with the carrier's flow control and deadline.
    fn send<'a>(
        &'a mut self,
        frame: &'a Frame,
    ) -> impl Future<Output = Result<(), ClientError>> + Send + 'a;
    /// Write FIN and finish the HTTP request body, preserving end semantics.
    fn finish(&mut self) -> impl Future<Output = Result<(), ClientError>> + Send;
    /// Never append a FIN to an interrupted frame. H3 drops its request.
    fn abort(&mut self) {}
}
pub(crate) trait FrameReader: Send {
    fn next(&mut self) -> impl Future<Output = Result<Option<Frame>, ClientError>> + Send;
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_udp(
    kind: CarrierKind,
    state: &Session,
    writer: &mut impl FrameWriter,
    reader: &mut impl FrameReader,
    mut first: Option<Vec<u8>>,
    mut upload: mpsc::Receiver<Vec<u8>>,
    download: mpsc::Sender<Vec<u8>>,
    flow: Option<&FlowLease>,
) -> Result<(), ClientError> {
    if !state.udp() {
        return Err(ClientError::Protocol);
    }
    let traffic = crate::traffic::enter_udp(crate::Role::Client, kind.h3(), false);
    let mut tx_state = state.clone();
    let mut rx_state = state.clone();
    let activity = crate::udp_relay::Activity::new();
    let writing = AtomicBool::new(false);
    let send_loop = async {
        let mut first_send = FirstSend::new(flow, PacketAction::Redirect);
        while let Some(data) = crate::udp_relay::next_datagram(&mut first, &mut upload).await {
            let size = data.len();
            let frame = Frame::Datagram(data);
            tx_state
                .apply(Direction::Send, &frame)
                .map_err(|_| ClientError::Protocol)?;
            first_send.attempt()?;
            writing.store(true, Ordering::Relaxed);
            writer.send(&frame).await?;
            writing.store(false, Ordering::Relaxed);
            traffic.upload(size);
            activity.touch();
        }
        Ok::<(), ClientError>(())
    };
    let receive_loop = async {
        loop {
            let frame = reader.next().await?.ok_or(ClientError::Protocol)?;
            rx_state
                .apply(Direction::Receive, &frame)
                .map_err(|_| ClientError::Protocol)?;
            match frame {
                Frame::Datagram(data) => {
                    if let Some(flow) = flow {
                        flow.commit(PacketAction::Redirect)?;
                    }
                    let size = data.len();
                    if crate::udp_relay::deliver(&download, || data)? {
                        traffic.download(size);
                        activity.touch();
                    }
                }
                Frame::Padding(_) => tokio::task::yield_now().await,
                Frame::Fin => return Ok::<(), ClientError>(()),
                Frame::Abort(code) => return Err(ClientError::Open(code)),
                _ => return Err(ClientError::Protocol),
            }
        }
    };
    let result = tokio::select! {
        result = send_loop => result,
        result = receive_loop => result,
        () = activity.expire() => Ok(()),
    };
    if writing.load(Ordering::Relaxed) || result.is_err() {
        writer.abort();
        return result.and(Err(ClientError::Timeout));
    }
    writer.finish().await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp<S: AsyncRead + AsyncWrite + Unpin>(
    kind: CarrierKind,
    operation: u64,
    state: &mut Session,
    writer: &mut impl FrameWriter,
    reader: &mut impl FrameReader,
    local: S,
    flow: Option<&FlowLease>,
    record_data: impl Fn(usize) + Sync,
) -> Result<(), ClientError> {
    if state.udp() {
        return Err(ClientError::Protocol);
    }
    let traffic = crate::traffic::enter(crate::Role::Client, kind.h3());
    kind.event(
        Level::Debug,
        "relay_begin",
        &[("op", Value::Count(operation))],
    );
    let (mut read, mut write) = tokio::io::split(local);
    let mut upload_state = state.clone();
    let mut download_state = state.clone();
    let activity = crate::relay_liveness::Activity::new();
    let (upload_done, upload_finished) = tokio::sync::oneshot::channel();
    let upload = async {
        let mut buffer = [0; crate::relay_batch::MAX_BATCH];
        let mut batch = crate::relay_batch::ReadyBatch::default();
        let mut first_send = FirstSend::new(flow, PacketAction::Redirect);
        loop {
            let size = batch
                .read(&mut read, &mut buffer)
                .await
                .map_err(|_| ClientError::Io)?;
            let frame = if size == 0 {
                Frame::Fin
            } else {
                Frame::Data(buffer[..size].to_vec())
            };
            kind.event(
                Level::Trace,
                "upload_frame",
                &[
                    ("op", Value::Count(operation)),
                    ("bytes", Value::Count(size as u64)),
                    ("fin", Value::Flag(size == 0)),
                ],
            );
            upload_state
                .apply(Direction::Send, &frame)
                .map_err(|_| ClientError::Protocol)?;
            if size == 0 {
                writer.finish().await?;
                activity.half_closed();
                let _ = upload_done.send(());
                return Ok::<(), ClientError>(());
            }
            first_send.attempt()?;
            writer.send(&frame).await?;
            record_data(size);
            traffic.upload(size);
            activity.data(size);
        }
    };
    let download = async {
        loop {
            let frame = reader.next().await?.ok_or(ClientError::Protocol)?;
            download_state
                .apply(Direction::Receive, &frame)
                .map_err(|_| ClientError::Protocol)?;
            match frame {
                Frame::Padding(_) => tokio::task::yield_now().await,
                Frame::Data(data) => {
                    if let Some(flow) = flow {
                        flow.commit(PacketAction::Redirect)?;
                    }
                    kind.event(
                        Level::Trace,
                        "download_frame",
                        &[
                            ("op", Value::Count(operation)),
                            ("bytes", Value::Count(data.len() as u64)),
                        ],
                    );
                    timeout(IO_TIMEOUT, write.write_all(&data))
                        .await
                        .map_err(|_| ClientError::Timeout)?
                        .map_err(|_| ClientError::Io)?;
                    record_data(data.len());
                    traffic.download(data.len());
                    activity.data(data.len());
                }
                Frame::Fin => {
                    kind.event(
                        Level::Debug,
                        "download_fin",
                        &[("op", Value::Count(operation))],
                    );
                    timeout(IO_TIMEOUT, write.shutdown())
                        .await
                        .map_err(|_| ClientError::Timeout)?
                        .map_err(|_| ClientError::Io)?;
                    activity.half_closed();
                    break;
                }
                Frame::Abort(code) => return Err(ClientError::Open(code)),
                _ => return Err(ClientError::Protocol),
            }
        }
        if crate::relay_liveness::receive_tail(
            async {
                loop {
                    let frame = reader.next().await?;
                    if let Some(padding @ Frame::Padding(_)) = &frame {
                        if activity.both_finished() {
                            return Err(ClientError::Protocol);
                        }
                        download_state
                            .apply(Direction::Receive, padding)
                            .map_err(|_| ClientError::Protocol)?;
                        tokio::task::yield_now().await;
                        continue;
                    }
                    return Ok(frame);
                }
            },
            upload_finished,
            ClientError::Timeout,
        )
        .await?
        .is_some()
        {
            return Err(ClientError::Protocol);
        }
        Ok::<(), ClientError>(())
    };
    if let Err(error) = activity.run(upload, download, ClientError::Timeout).await {
        kind.event(
            Level::Warn,
            "relay_failed",
            &[
                ("op", Value::Count(operation)),
                ("reason", Value::Label(error_kind(&error))),
            ],
        );
        return Err(error);
    }
    kind.event(
        Level::Debug,
        "relay_completed",
        &[("op", Value::Count(operation))],
    );
    state
        .apply(Direction::Send, &Frame::Fin)
        .map_err(|_| ClientError::Protocol)?;
    state
        .apply(Direction::Receive, &Frame::Fin)
        .map_err(|_| ClientError::Protocol)?;
    state.finish().map_err(|_| ClientError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    struct Mock<const H3: bool>(Mutex<VecDeque<(HelloOutcome, Result<(), ClientError>)>>);
    impl<const H3: bool> OpenAdapter for Mock<H3> {
        type Tunnel = ();
        const KIND: CarrierKind = if H3 { CarrierKind::H3 } else { CarrierKind::H2 };
        fn explicit_stream_up(&self) -> bool {
            false
        }
        fn automatic_mode(&self) -> Option<&AutoMode> {
            None
        }
        async fn open_attempt<'a>(
            &'a self,
            _open: &'a Frame,
            _operation: u64,
            _up: bool,
            stage: &'a mut HelloOutcome,
        ) -> Result<(), ClientError> {
            let (outcome, result) = self.0.lock().unwrap().pop_front().unwrap();
            *stage = outcome;
            result
        }
    }

    #[tokio::test]
    async fn admitted_h3_drain_retry_cannot_publish_new_unavailability() {
        let mock = Mock::<true>(Mutex::new(VecDeque::from([
            (HelloOutcome::Draining, Err(ClientError::Http3)),
            (HelloOutcome::Pending, Err(ClientError::QuicUnreachable)),
        ])));
        assert_eq!(
            open_selected(&mock, &Frame::Fin, 1).await,
            Err(ClientError::Timeout)
        );
        assert!(mock.0.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn single_preopen_drain_retry_and_terminal_failure() {
        let mock = Mock::<false>(Mutex::new(VecDeque::from([
            (HelloOutcome::Draining, Err(ClientError::Http2)),
            (HelloOutcome::Draining, Err(ClientError::Http2)),
            (HelloOutcome::Acked, Ok(())),
        ])));
        assert_eq!(
            open_selected(&mock, &Frame::Fin, 1).await,
            Err(ClientError::Http2)
        );
        assert_eq!(mock.0.lock().unwrap().len(), 1);
        let denied = Mock::<true>(Mutex::new(VecDeque::from([
            (HelloOutcome::Pending, Err(ClientError::Tls)),
            (HelloOutcome::Acked, Ok(())),
        ])));
        assert_eq!(
            open_selected(&denied, &Frame::Fin, 1).await,
            Err(ClientError::Tls)
        );
        assert_eq!(denied.0.lock().unwrap().len(), 1);
    }
}
