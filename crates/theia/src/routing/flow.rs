//! Shared client flow lifetime and irreversible first-payload authorization.
//! Compatibility ingress uses synthetic IDs; native backends must bind their
//! platform flow identities to this same table before forwarding any payload.
use super::{dpi::Engine, PacketAction};
use crate::{client::ClientError, protocol::{Address, ErrorCode}};
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_FLOWS: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, PartialEq, Eq)]
struct Identity {
    protocol: Protocol,
    target: Address,
    port: u16,
    digest: [u8; 32],
    configured: PacketAction,
}

struct Entry {
    identity: Identity,
    committed: Option<PacketAction>,
}

#[derive(Default)]
struct State {
    next: u64,
    entries: HashMap<u64, Entry>,
}

/// One bounded table for the client process, including retained generations.
/// Never evict an active flow to make room for a new one.
pub(crate) struct FlowTable {
    state: Mutex<State>,
    capacity: usize,
}

impl FlowTable {
    fn new(capacity: usize) -> Self {
        Self { state: Mutex::new(State::default()), capacity }
    }

    pub(crate) fn shared() -> Arc<Self> {
        static TABLE: OnceLock<Arc<FlowTable>> = OnceLock::new();
        TABLE.get_or_init(|| Arc::new(Self::new(MAX_FLOWS))).clone()
    }

    pub(crate) fn begin(
        self: &Arc<Self>,
        engine: Arc<Engine>,
        protocol: Protocol,
        target: Address,
        port: u16,
        digest: [u8; 32],
        configured: PacketAction,
    ) -> Result<FlowLease, ClientError> {
        if port == 0 || configured == PacketAction::Drop {
            return Err(denied());
        }
        engine.check_policy(digest)?;
        let identity = Identity { protocol, target, port, digest, configured };
        let mut state = self.state.lock().map_err(|_| denied())?;
        if state.entries.len() >= self.capacity {
            return Err(ClientError::Open(ErrorCode::ResourceLimit));
        }
        let id = state.next.checked_add(1).ok_or(ClientError::Open(ErrorCode::ResourceLimit))?;
        state.next = id;
        state.entries.insert(id, Entry { identity: identity.clone(), committed: None });
        Ok(FlowLease { table: self.clone(), id, identity, engine })
    }
}

fn denied() -> ClientError {
    ClientError::Open(ErrorCode::PolicyDenied)
}

/// Kept by the actual relay until completion, error or cancellation.
pub(crate) struct FlowLease {
    table: Arc<FlowTable>,
    id: u64,
    identity: Identity,
    engine: Arc<Engine>,
}

impl FlowLease {
    /// Called immediately before the first attempted payload write, not
    /// after a successful write. A partial write is never permission to retry.
    pub(crate) fn commit(&self, action: PacketAction) -> Result<(), ClientError> {
        let mut state = self.table.state.lock().map_err(|_| denied())?;
        let entry = state.entries.get_mut(&self.id).ok_or_else(denied)?;
        if entry.identity != self.identity {
            return Err(denied());
        }
        if let Some(committed) = entry.committed {
            return if committed == action { Ok(()) } else { Err(denied()) };
        }
        if action == PacketAction::Drop
            || (action != self.identity.configured
                && !(self.identity.configured == PacketAction::Modify && action == PacketAction::Redirect))
        {
            return Err(denied());
        }
        self.engine.check_policy(self.identity.digest)?;
        if action == PacketAction::Modify && !self.engine.enabled() {
            return Err(denied());
        }
        entry.committed = Some(action);
        Ok(())
    }
}

impl Drop for FlowLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.table.state.lock() {
            state.entries.remove(&self.id);
        }
    }
}

/// Gates the first nonempty application read before its bytes can be handed
/// to an egress writer. Subsequent reads stay on the committed egress.
pub(crate) struct GuardedIo<'a, S> {
    inner: S,
    flow: Option<&'a FlowLease>,
    action: PacketAction,
    started: bool,
}

impl<'a, S> GuardedIo<'a, S> {
    pub(crate) fn new(inner: S, flow: Option<&'a FlowLease>, action: PacketAction) -> Self {
        Self { inner, flow, action, started: false }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for GuardedIo<'_, S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before && !self.started {
            if let Some(flow) = self.flow {
                if flow.commit(self.action).is_err() {
                    buf.set_filled(before);
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
                }
            }
            self.started = true;
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GuardedIo<'_, S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn setup() -> (Arc<FlowTable>, Arc<Engine>) {
        let table = Arc::new(FlowTable::new(1));
        let engine = Arc::new(Engine::default());
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture([1; 32])));
        engine.set_enabled(true);
        (table, engine)
    }

    fn begin(table: &Arc<FlowTable>, engine: &Arc<Engine>, action: PacketAction) -> Result<FlowLease, ClientError> {
        table.begin(engine.clone(), Protocol::Tcp, Address::V4([192, 0, 2, 1]), 443, [1; 32], action)
    }

    #[test]
    fn bounded_table_and_irreversible_commit() {
        let (table, engine) = setup();
        let flow = begin(&table, &engine, PacketAction::Modify).unwrap();
        assert!(matches!(begin(&table, &engine, PacketAction::Pass), Err(ClientError::Open(ErrorCode::ResourceLimit))));
        assert!(flow.commit(PacketAction::Pass).is_err());
        flow.commit(PacketAction::Modify).unwrap();
        assert!(flow.commit(PacketAction::Redirect).is_err());
        engine.authorize_policy(None);
        assert!(flow.commit(PacketAction::Modify).is_ok());
        drop(flow);
        assert!(begin(&table, &engine, PacketAction::Pass).is_err());
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture([1; 32])));
        let flow = begin(&table, &engine, PacketAction::Modify).unwrap();
        flow.commit(PacketAction::Redirect).unwrap();
        assert!(flow.commit(PacketAction::Modify).is_err());
    }

    #[tokio::test]
    async fn revoked_policy_never_releases_first_payload() {
        let (table, engine) = setup();
        let flow = begin(&table, &engine, PacketAction::Redirect).unwrap();
        let (mut writer, reader) = tokio::io::duplex(16);
        let mut guarded = GuardedIo::new(reader, Some(&flow), PacketAction::Redirect);
        writer.write_all(b"secret").await.unwrap();
        engine.authorize_policy(None);
        let mut bytes = Vec::new();
        assert_eq!(guarded.read_buf(&mut bytes).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(bytes.is_empty());
    }
}
