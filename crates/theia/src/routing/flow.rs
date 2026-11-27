//! Shared client flow lifetime and irreversible first-payload authorization.
//! Compatibility ingress uses synthetic IDs; native backends must bind their
//! platform flow identities to this same table before forwarding any payload.
use super::{dpi::Engine, packet::FlowKey, PacketAction};
use crate::{client::ClientError, protocol::{Address, ErrorCode}};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

pub(crate) const MAX_FLOWS: usize = 4096;

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
    native: Option<FlowKey>,
}

struct Entry {
    identity: Identity,
    committed: Option<PacketAction>,
}

#[derive(Default)]
struct State {
    next: u64,
    entries: HashMap<u64, Entry>,
    native: HashMap<FlowKey, u64>,
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

    /// Active relay counts in pending/Pass/Modify/Redirect order. No
    /// endpoint, process identity or payload leaves the table.
    pub(crate) fn counts(&self) -> Option<[u16; 4]> {
        let state = self.state.lock().ok()?;
        let mut counts = [0u16; 4];
        for entry in state.entries.values() {
            let index = match entry.committed {
                None => 0,
                Some(PacketAction::Pass) => 1,
                Some(PacketAction::Modify) => 2,
                Some(PacketAction::Redirect) => 3,
                Some(PacketAction::Drop) => return None,
            };
            counts[index] = counts[index].checked_add(1)?;
        }
        Some(counts)
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
        self.begin_inner(engine, protocol, target, port, digest, configured, None)
    }

    pub(crate) fn begin_native(
        self: &Arc<Self>,
        engine: Arc<Engine>,
        mut key: FlowKey,
        digest: [u8; 32],
        configured: PacketAction,
    ) -> Result<FlowLease, ClientError> {
        // Single native owner in one isolated namespace/compartment. A
        // missing interface on an accepted socket must not create another
        // owner for the exact same transport tuple. Scoped IPv6 is rejected
        // at native ingress, so this is deliberately conservative.
        key.interface = 0;
        use super::packet::Transport;
        let protocol = match key.transport {
            Transport::Tcp => Protocol::Tcp,
            Transport::Udp => Protocol::Udp,
        };
        let target = match key.destination.ip() {
            std::net::IpAddr::V4(ip) => Address::V4(ip.octets()),
            std::net::IpAddr::V6(ip) => Address::V6(ip.octets()),
        };
        self.begin_inner(engine, protocol, target, key.destination.port(), digest, configured, Some(key))
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_inner(
        self: &Arc<Self>,
        engine: Arc<Engine>,
        protocol: Protocol,
        target: Address,
        port: u16,
        digest: [u8; 32],
        configured: PacketAction,
        native: Option<FlowKey>,
    ) -> Result<FlowLease, ClientError> {
        if port == 0 || configured == PacketAction::Drop {
            return Err(denied());
        }
        engine.check_policy(digest)?;
        let identity = Identity { protocol, target, port, digest, configured, native };
        let mut state = self.state.lock().map_err(|_| denied())?;
        if state.entries.len() >= self.capacity {
            return Err(ClientError::Open(ErrorCode::ResourceLimit));
        }
        if native.is_some_and(|key| state.native.contains_key(&key)) {
            return Err(denied());
        }
        let id = state.next.checked_add(1).ok_or(ClientError::Open(ErrorCode::ResourceLimit))?;
        state.next = id;
        state.entries.insert(id, Entry { identity: identity.clone(), committed: None });
        if let Some(key) = native { state.native.insert(key, id); }
        Ok(FlowLease { table: self.clone(), id, identity, engine })
    }
}

pub(crate) fn summary(counts: Option<[u16; 4]>) -> String {
    match counts {
        Some([pending, pass, modify, redirect]) => format!("Потоки: ожидают {pending} · Pass {pass} · Modify {modify} · Redirect {redirect}"),
        None => "Состояние потоков не подтверждено".into(),
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
    #[cfg(target_os = "linux")]
    pub(crate) fn committed(&self, action: PacketAction) -> bool {
        self.table.state.lock().ok().and_then(|state| state.entries.get(&self.id).map(|entry| entry.identity == self.identity && entry.committed == Some(action))).unwrap_or(false)
    }

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
            if let Some(key) = self.identity.native {
                if state.native.get(&key) == Some(&self.id) { state.native.remove(&key); }
            }
        }
    }
}

/// A cheap local latch, used directly at the actual egress writer.
/// Only the first send acquires the shared table lock.
pub(crate) struct FirstSend<'a> {
    flow: Option<&'a FlowLease>,
    action: PacketAction,
    started: bool,
}
impl<'a> FirstSend<'a> {
    pub(crate) fn new(flow: Option<&'a FlowLease>, action: PacketAction) -> Self {
        Self { flow, action, started: false }
    }
    pub(crate) fn attempt(&mut self) -> Result<(), ClientError> {
        if !self.started {
            if let Some(flow) = self.flow {
                flow.commit(self.action)?;
            }
            self.started = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(table.counts(), Some([1, 0, 0, 0]));
        assert!(flow.commit(PacketAction::Pass).is_err());
        flow.commit(PacketAction::Modify).unwrap();
        assert_eq!(table.counts(), Some([0, 0, 1, 0]));
        assert!(flow.commit(PacketAction::Redirect).is_err());
        engine.authorize_policy(None);
        assert!(flow.commit(PacketAction::Modify).is_ok());
        drop(flow);
        assert_eq!(table.counts(), Some([0, 0, 0, 0]));
        assert!(begin(&table, &engine, PacketAction::Pass).is_err());
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture([1; 32])));
        let flow = begin(&table, &engine, PacketAction::Modify).unwrap();
        flow.commit(PacketAction::Redirect).unwrap();
        assert!(flow.commit(PacketAction::Modify).is_err());
    }

    #[test]
    fn native_tuple_shares_quota_and_cannot_be_owned_twice() {
        let (table, engine) = setup();
        let key = FlowKey {
            source: "192.0.2.1:1234".parse().unwrap(),
            destination: "198.51.100.1:443".parse().unwrap(),
            transport: super::super::packet::Transport::Tcp,
            interface: 1,
        };
        let flow = table.begin_native(engine.clone(), key, [1; 32], PacketAction::Redirect).unwrap();
        assert!(table.begin_native(engine.clone(), FlowKey { interface: 99, ..key }, [1; 32], PacketAction::Pass).is_err());
        assert!(begin(&table, &engine, PacketAction::Pass).is_err());
        flow.commit(PacketAction::Redirect).unwrap();
        assert!(flow.commit(PacketAction::Pass).is_err());
        drop(flow);
        assert!(table.begin_native(engine, key, [1; 32], PacketAction::Redirect).is_ok());
    }

    #[test]
    fn retired_generation_cannot_commit_first_payload() {
        let (table, engine) = setup();
        let flow = begin(&table, &engine, PacketAction::Redirect).unwrap();
        let mut send = FirstSend::new(Some(&flow), PacketAction::Redirect);
        engine.retire();
        engine.authorize_policy(Some(super::super::client_state::LocalPolicy::fixture([1; 32])));
        assert_eq!(send.attempt(), Err(denied()));
        assert!(begin(&table, &engine, PacketAction::Pass).is_err());
    }

    #[test]
    fn committed_flow_keeps_egress_after_retirement() {
        let (table, engine) = setup();
        let flow = begin(&table, &engine, PacketAction::Pass).unwrap();
        let mut send = FirstSend::new(Some(&flow), PacketAction::Pass);
        send.attempt().unwrap();
        engine.retire();
        send.attempt().unwrap();
        assert_eq!(flow.commit(PacketAction::Redirect), Err(denied()));
    }
}
