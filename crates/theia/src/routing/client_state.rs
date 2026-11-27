//! Profile-scoped routing freshness and durable rollback floor.
//! A stale/unavailable policy never permits direct or proxy traffic.
use super::snapshot::{Checkpoint, Snapshot};
use crate::{
    client::ClientError,
    config::Profile,
    protocol::{Address, ErrorCode},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

const TTL: Duration = Duration::from_secs(60);
const REFRESH_MARGIN: Duration = Duration::from_secs(10);
const RETRY: Duration = Duration::from_secs(3);
const DIAL: Duration = Duration::from_secs(15);

pub(crate) fn checkpoint_path(
    config: Option<&Path>,
    profile: &Profile,
    trust: [u8; 32],
) -> Result<Option<PathBuf>, ClientError> {
    let Some(config) = config else {
        return Ok(None);
    };
    let config = std::fs::canonicalize(config).map_err(|_| ClientError::Configuration)?;
    let parent = config.parent().ok_or(ClientError::Configuration)?;
    let mut hash = Sha256::new();
    for value in [
        config
            .file_name()
            .ok_or(ClientError::Configuration)?
            .as_encoded_bytes(),
        profile.id.as_bytes(),
        profile.server.as_bytes(),
        profile.server_name.as_bytes(),
        profile.path_prefix.as_deref().unwrap_or("").as_bytes(),
        if profile.reality_profile.is_some() {
            b"reality".as_slice()
        } else {
            b"own-tls".as_slice()
        },
        trust.as_slice(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    let digest = hash
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok(Some(parent.join(format!(".routing-{digest}.toml"))))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Floor {
    scope: String,
    checkpoint: Checkpoint,
}

/// Local route permission is scoped to the exact accepted checkpoint and
/// deadline. A changed/deleted durable floor invalidates outstanding opens.
pub(super) struct LocalPolicy {
    checkpoint: Checkpoint,
    deadline: Instant,
    floor: Option<(PathBuf, String)>,
}

impl LocalPolicy {
    pub(super) fn continues(&self, next: &Self) -> bool {
        self.checkpoint == next.checkpoint
            && self.floor == next.floor
            && Instant::now() < self.deadline
    }

    pub(super) fn matches_digest(&self, digest: [u8; 32]) -> bool {
        self.checkpoint.digest == digest
    }

    #[cfg(test)]
    pub(super) fn valid(&self, digest: [u8; 32]) -> bool {
        self.matches_digest(digest) && self.valid_current()
    }

    pub(super) fn valid_current(&self) -> bool {
        if Instant::now() >= self.deadline {
            return false;
        }
        match &self.floor {
            None => true,
            Some((path, scope)) => floor_bytes(path)
                .ok()
                .flatten()
                .and_then(|bytes| read_floor(&bytes, scope).ok())
                .is_some_and(|floor| floor.checkpoint == self.checkpoint),
        }
    }

    #[cfg(test)]
    pub(super) fn fixture(digest: [u8; 32]) -> Self {
        Self {
            checkpoint: Checkpoint {
                revision: 1,
                digest,
            },
            deadline: Instant::now() + TTL,
            floor: None,
        }
    }
}

struct State {
    snapshot: Option<Arc<Snapshot>>,
    expires: Option<Instant>,
    retry: Option<Instant>,
}
pub(crate) struct Cache {
    scope: String,
    checkpoint: Option<PathBuf>,
    state: tokio::sync::Mutex<State>,
    pub(crate) policy: Arc<super::policy_lease::PolicyState>,
    pub(crate) dpi: Arc<super::dpi::Engine>,
    pub(crate) flows: Arc<super::flow::FlowTable>,
}

fn floor_bytes(path: &Path) -> Result<Option<Vec<u8>>, ClientError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => crate::bounded_input::read(path, 4096, true, true)
            .map(|b| Some(b.to_vec()))
            .map_err(|_| ClientError::Configuration),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ClientError::Configuration),
    }
}
fn read_floor(bytes: &[u8], scope: &str) -> Result<Floor, ClientError> {
    let value: Floor =
        toml::from_str(std::str::from_utf8(bytes).map_err(|_| ClientError::Configuration)?)
            .map_err(|_| ClientError::Configuration)?;
    if value.scope != scope || value.checkpoint.revision == 0 {
        return Err(ClientError::Configuration);
    }
    Ok(value)
}

impl Cache {
    pub(crate) fn new(scope: String, checkpoint: Option<PathBuf>) -> Self {
        let policy = Arc::new(super::policy_lease::PolicyState::default());
        Self {
            scope,
            checkpoint,
            dpi: Arc::new(super::dpi::Engine::new(policy.clone())),
            policy,
            flows: super::flow::FlowTable::shared(),
            state: tokio::sync::Mutex::new(State {
                snapshot: None,
                expires: None,
                retry: None,
            }),
        }
    }

    fn persist(&self, snapshot: &Snapshot, previous: Option<&Snapshot>) -> Result<(), ClientError> {
        if let Some(previous) = previous {
            previous
                .checkpoint()
                .accepts(snapshot)
                .map_err(|_| ClientError::Protocol)?;
        }
        let Some(path) = &self.checkpoint else {
            return Ok(());
        };
        let bytes = floor_bytes(path)?;
        if let Some(raw) = &bytes {
            let floor = read_floor(raw, &self.scope)?;
            floor
                .checkpoint
                .accepts(snapshot)
                .map_err(|_| ClientError::Protocol)?;
            if floor.checkpoint == snapshot.checkpoint() {
                return crate::config::guarded_trust_assert(path, raw)
                    .map_err(|_| ClientError::Configuration);
            }
        } else if previous.is_some() {
            // A running instance must not recreate a deleted trust floor.
            return Err(ClientError::Configuration);
        }
        let floor = Floor {
            scope: self.scope.clone(),
            checkpoint: snapshot.checkpoint(),
        };
        let text = toml::to_string(&floor).map_err(|_| ClientError::Configuration)?;
        crate::config::guarded_trust_write(path, &text, bytes.as_deref())
            .map_err(|_| ClientError::Configuration)
    }

    fn authorize_local(&self, snapshot: &Snapshot, deadline: Instant) {
        self.policy.authorize_policy(Some(LocalPolicy {
            checkpoint: snapshot.checkpoint(),
            deadline,
            floor: self
                .checkpoint
                .clone()
                .map(|path| (path, self.scope.clone())),
        }));
    }

    pub(crate) async fn get<F, Fut>(&self, fetch: F) -> Result<Arc<Snapshot>, ClientError>
    where
        F: FnOnce(Option<[u8; 32]>) -> Fut,
        Fut: Future<Output = Result<Vec<u8>, ClientError>>,
    {
        self.get_inner(fetch, false).await
    }

    pub(crate) async fn refresh<F, Fut>(&self, fetch: F) -> Result<Arc<Snapshot>, ClientError>
    where
        F: FnOnce(Option<[u8; 32]>) -> Fut,
        Fut: Future<Output = Result<Vec<u8>, ClientError>>,
    {
        self.get_inner(fetch, true).await
    }

    async fn get_inner<F, Fut>(
        &self,
        fetch: F,
        proactive: bool,
    ) -> Result<Arc<Snapshot>, ClientError>
    where
        F: FnOnce(Option<[u8; 32]>) -> Fut,
        Fut: Future<Output = Result<Vec<u8>, ClientError>>,
    {
        let mut state = self.state.lock().await;
        if self.policy.retired() {
            return Err(super::policy_lease::stale_policy());
        }
        let now = Instant::now();
        let mut keep_lease = false;
        if let (Some(deadline), Some(snapshot)) = (
            state.expires.filter(|until| now < *until),
            state.snapshot.as_ref(),
        ) {
            let result = if let Some(path) = &self.checkpoint {
                floor_bytes(path)
                    .and_then(|bytes| bytes.ok_or(ClientError::Configuration))
                    .and_then(|bytes| read_floor(&bytes, &self.scope))
                    .map(|floor| floor.checkpoint == snapshot.checkpoint())
            } else {
                Ok(true)
            };
            match result {
                Ok(true) => {
                    self.authorize_local(snapshot, deadline);
                    if !proactive || deadline.saturating_duration_since(now) > REFRESH_MARGIN {
                        return Ok(snapshot.clone());
                    }
                    keep_lease = true;
                }
                Ok(false) => {}
                Err(error) => {
                    self.policy.authorize_policy(None);
                    return Err(error);
                }
            }
        }
        // A proactive unchanged refresh may retain the unexpired lease
        // while in flight. Expired, mismatched and failed refreshes revoke it.
        if !keep_lease {
            self.policy.authorize_policy(None);
        }
        if state.retry.is_some_and(|until| now < until) {
            return Err(ClientError::Open(ErrorCode::PolicyDenied));
        }
        state.expires = None;
        state.retry = Some(now + RETRY);
        let refreshed = async {
            let previous = state.snapshot.as_ref();
            let wire = fetch(previous.map(|s| s.digest())).await?;
            let snapshot = if let Some(previous) = previous.filter(|s| {
                wire.as_slice() == super::exchange::unchanged_receipt(s.digest()).as_slice()
            }) {
                previous.clone()
            } else {
                let scope = self.scope.clone();
                Arc::new(
                    tokio::task::spawn_blocking(move || Snapshot::decode(&wire, &scope))
                        .await
                        .map_err(|_| ClientError::Protocol)?
                        .map_err(|_| ClientError::Protocol)?,
                )
            };
            if self.policy.retired() {
                return Err(super::policy_lease::stale_policy());
            }
            self.persist(&snapshot, state.snapshot.as_deref())?;
            Ok::<_, ClientError>(snapshot)
        }
        .await;
        let snapshot = match refreshed {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.policy.authorize_policy(None);
                return Err(error);
            }
        };
        state.snapshot = Some(snapshot.clone());
        let deadline = Instant::now() + TTL;
        state.expires = Some(deadline);
        self.authorize_local(&snapshot, deadline);
        if self.policy.retired() {
            return Err(super::policy_lease::stale_policy());
        }
        state.retry = None;
        Ok(snapshot)
    }
    /// Exact current policy lease for a diagnostic observation. Do not
    /// start a new refresh here: an in-flight DNS request must not inherit
    /// a later deadline merely because the same digest was republished.
    #[cfg(target_os = "linux")]
    pub(crate) fn observation_deadline(&self, digest: [u8; 32]) -> Result<Instant, ClientError> {
        let state = self
            .state
            .try_lock()
            .map_err(|_| super::policy_lease::stale_policy())?;
        let deadline = state
            .expires
            .filter(|deadline| *deadline > Instant::now())
            .ok_or_else(super::policy_lease::stale_policy)?;
        if !state
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.digest() == digest)
        {
            return Err(super::policy_lease::stale_policy());
        }
        self.policy.check_policy(digest)?;
        Ok(deadline)
    }

    /// (revision, state): 0 unknown, 1 fresh, 2 expired, 3 synchronizing.
    pub(crate) fn observation(&self) -> (u64, u8) {
        let Ok(state) = self.state.try_lock() else {
            return (0, 3);
        };
        match state.snapshot.as_ref() {
            Some(s) => (
                s.manifest().revision,
                if state.expires.is_some_and(|t| Instant::now() < t) {
                    1
                } else {
                    2
                },
            ),
            None => (0, 0),
        }
    }

    pub(crate) fn report(&self) -> String {
        let Ok(state) = self.state.try_lock() else {
            return "Правила маршрутизации: обновляются".into();
        };
        let revision = state.snapshot.as_ref().map(|s| s.manifest().revision);
        match (revision, state.expires.is_some_and(|t| Instant::now() < t)) {
            (Some(rev), true) => format!("Правила маршрутизации: версия {rev}, актуальны"),
            (Some(rev), false) => format!(
                "Правила маршрутизации: версия {rev} просрочена, новые соединения ждут проверки"
            ),
            (None, _) => "Правила маршрутизации: ещё не подтверждены".into(),
        }
    }
}

pub(crate) async fn dial_direct(
    address: Address,
    port: u16,
    pinned: Option<Vec<IpAddr>>,
) -> Result<TcpStream, ClientError> {
    if port == 0 {
        return Err(ClientError::Protocol);
    }
    tokio::time::timeout(DIAL, async {
        let candidates = if let Some(ips) = pinned {
            ips.into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect::<Vec<_>>()
        } else {
            match address {
                Address::V4(ip) => vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)],
                Address::V6(ip) => vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)],
                Address::Dns(name) => tokio::net::lookup_host((name.as_str(), port))
                    .await
                    .map_err(|_| ClientError::Open(ErrorCode::DialFailed))?
                    .take(65)
                    .collect(),
            }
        };
        if candidates.len() > 64 {
            return Err(ClientError::Open(ErrorCode::ResourceLimit));
        }
        for addr in candidates {
            if addr.ip().is_unspecified() || addr.ip().is_multicast() {
                continue;
            }
            if let Ok(socket) = super::carrier_socket::connect_plain_tcp(addr).await {
                return Ok(socket);
            }
        }
        Err(ClientError::Open(ErrorCode::DialFailed))
    })
    .await
    .map_err(|_| ClientError::Open(ErrorCode::DialTimeout))?
}

struct ExchangeEvidence(std::sync::atomic::AtomicU8);
impl ExchangeEvidence {
    fn wrote(&self, upload: bool) {
        use std::sync::atomic::Ordering;
        let bit = if upload { 1 } else { 2 };
        let previous = self.0.fetch_or(bit, Ordering::Relaxed);
        if previous != 3 && (previous | bit) == 3 {
            crate::traffic::dpi_bidirectional();
        }
    }
}

struct DirectRelayError {
    error: ClientError,
    peer: bool,
}
impl DirectRelayError {
    fn io(peer: bool) -> Self {
        Self {
            error: ClientError::Io,
            peer,
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn copy_direction(
    mut input: impl AsyncRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
    activity: &crate::relay_liveness::Activity,
    meter: &crate::traffic::Relay<'_>,
    upload: bool,
    evidence: Option<&ExchangeEvidence>,
    flow: Option<&super::flow::FlowLease>,
    action: super::PacketAction,
    scope: Option<&(dyn Fn() -> Result<(), ClientError> + Sync)>,
) -> Result<(), DirectRelayError> {
    let mut first_send = super::flow::FirstSend::new(flow, action);
    let mut bytes = [0u8; 16 * 1024];
    loop {
        let count = input
            .read(&mut bytes)
            .await
            .map_err(|_| DirectRelayError::io(!upload))?;
        if count == 0 {
            output
                .shutdown()
                .await
                .map_err(|_| DirectRelayError::io(upload))?;
            activity.half_closed();
            return Ok(());
        }
        // Either direction may be first (server-first protocols).
        let mut pending = &bytes[..count];
        while !pending.is_empty() {
            if let Some(check) = scope {
                check().map_err(|error| DirectRelayError { error, peer: false })?;
            }
            first_send
                .attempt()
                .map_err(|error| DirectRelayError { error, peer: false })?;
            let n = output
                .write(pending)
                .await
                .map_err(|_| DirectRelayError::io(upload))?;
            if n == 0 {
                return Err(DirectRelayError::io(upload));
            }
            pending = &pending[n..];
        }
        activity.data(count);
        if let Some(evidence) = evidence {
            evidence.wrote(upload);
        }
        if upload {
            meter.upload(count);
        } else {
            meter.download(count);
        }
    }
}

#[cfg(test)]
pub(crate) async fn relay_direct(client: TcpStream, target: TcpStream) -> Result<(), ClientError> {
    relay_direct_guarded(client, target, None).await
}

pub(crate) async fn relay_direct_guarded(
    client: TcpStream,
    target: TcpStream,
    flow: Option<&super::flow::FlowLease>,
) -> Result<(), ClientError> {
    relay_direct_inner(client, target, 0, 0, flow, super::PacketAction::Pass, None)
        .await
        .0
}

pub(crate) async fn relay_direct_after_first(
    client: TcpStream,
    target: TcpStream,
    upload: usize,
    download: usize,
    flow: Option<&super::flow::FlowLease>,
    scope: &(dyn Fn() -> Result<(), ClientError> + Sync),
) -> (Result<(), ClientError>, bool, bool) {
    relay_direct_inner(
        client,
        target,
        upload,
        download,
        flow,
        super::PacketAction::Modify,
        Some(scope),
    )
    .await
}

async fn relay_direct_inner(
    client: TcpStream,
    target: TcpStream,
    upload: usize,
    download: usize,
    flow: Option<&super::flow::FlowLease>,
    action: super::PacketAction,
    scope: Option<&(dyn Fn() -> Result<(), ClientError> + Sync)>,
) -> (Result<(), ClientError>, bool, bool) {
    relay_direct_parts(
        client.into_split(),
        target,
        upload,
        download,
        flow,
        action,
        scope,
    )
    .await
}

/// Plain HTTP exposes one bounded request rather than the underlying socket
/// as upload input. Keep the existing owned TCP split for opaque tunnels.
pub(crate) async fn relay_http_direct_guarded(
    client: impl AsyncRead + AsyncWrite + Unpin,
    target: TcpStream,
    flow: Option<&super::flow::FlowLease>,
) -> Result<(), ClientError> {
    relay_direct_parts(
        tokio::io::split(client),
        target,
        0,
        0,
        flow,
        super::PacketAction::Pass,
        None,
    )
    .await
    .0
}

async fn relay_direct_parts(
    (cr, cw): (impl AsyncRead + Unpin, impl AsyncWrite + Unpin),
    target: TcpStream,
    upload: usize,
    download: usize,
    flow: Option<&super::flow::FlowLease>,
    action: super::PacketAction,
    scope: Option<&(dyn Fn() -> Result<(), ClientError> + Sync)>,
) -> (Result<(), ClientError>, bool, bool) {
    let meter = crate::traffic::enter_direct();
    meter.upload(upload);
    meter.download(download);
    let activity = crate::relay_liveness::Activity::new();
    let evidence = (upload != 0 && download != 0)
        .then(|| ExchangeEvidence(std::sync::atomic::AtomicU8::new(0)));
    let (tr, tw) = target.into_split();
    let relay = activity.run(
        copy_direction(
            cr,
            tw,
            &activity,
            &meter,
            true,
            evidence.as_ref(),
            flow,
            action,
            scope,
        ),
        copy_direction(
            tr,
            cw,
            &activity,
            &meter,
            false,
            evidence.as_ref(),
            flow,
            action,
            scope,
        ),
        DirectRelayError {
            error: ClientError::Timeout,
            peer: false,
        },
    );
    let watchdog = async {
        if let Some(check) = scope {
            loop {
                if let Err(error) = check() {
                    break DirectRelayError { error, peer: false };
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        } else {
            std::future::pending::<DirectRelayError>().await
        }
    };
    let result = tokio::select! {
        biased;
        error = watchdog => Err(error),
        result = relay => result,
    };
    let exchanged =
        evidence.is_some_and(|value| value.0.load(std::sync::atomic::Ordering::Relaxed) == 3);
    let peer_failure = result.as_ref().is_err_and(|error| error.peer);
    (result.map_err(|error| error.error), exchanged, peer_failure)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn local_policy_lease_fails_closed_on_expiry_refresh_and_digest_change() {
        let cache = Cache::new("scope".into(), None);
        let (_, wire) = Snapshot::build("scope", 1, &[], &[], &[]).unwrap();
        let first = cache.get(|_| async { Ok(wire) }).await.unwrap();
        let digest = first.digest();
        assert!(cache.policy.policy_current(digest));
        assert!(!cache.policy.policy_current([0; 32]));
        cache.state.lock().await.expires = None;
        assert!(cache.get(|_| async { Err(ClientError::Io) }).await.is_err());
        assert!(!cache.policy.policy_current(digest));
        cache.state.lock().await.retry = None;
        let (_, wire) = Snapshot::build("scope", 2, &[], &[], &[]).unwrap();
        let second = cache.get(|_| async { Ok(wire) }).await.unwrap();
        assert!(!cache.policy.policy_current(digest));
        assert!(cache.policy.policy_current(second.digest()));
        let expired = LocalPolicy {
            checkpoint: second.checkpoint(),
            deadline: Instant::now(),
            floor: None,
        };
        assert!(!expired.valid(second.digest()));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn diagnostic_deadline_rejects_wrong_digest_refresh_and_retirement() {
        let cache = Cache::new("scope".into(), None);
        let (_, wire) = Snapshot::build("scope", 1, &[], &[], &[]).unwrap();
        let snapshot = cache.get(|_| async { Ok(wire) }).await.unwrap();
        let digest = snapshot.digest();
        let original = cache.observation_deadline(digest).unwrap();
        assert!(original > Instant::now());
        assert!(cache.observation_deadline([0; 32]).is_err());
        {
            let mut state = cache.state.lock().await;
            assert!(cache.observation_deadline(digest).is_err());
            state.expires = Some(Instant::now());
        }
        assert!(cache.observation_deadline(digest).is_err());
        cache
            .get(|_| async { Ok(super::super::exchange::unchanged_receipt(digest).to_vec()) })
            .await
            .unwrap();
        assert!(cache.observation_deadline(digest).unwrap() >= original);
        cache.policy.retire();
        assert!(cache.observation_deadline(digest).is_err());
    }

    #[tokio::test]
    async fn proactive_refresh_continues_current_epoch_but_failed_refresh_revokes() {
        use super::super::{flow::Protocol, PacketAction};
        let cache = Cache::new("scope".into(), None);
        let (_, wire) = Snapshot::build("scope", 1, &[], &[], &[]).unwrap();
        let snapshot = cache.get(|_| async { Ok(wire) }).await.unwrap();
        let digest = snapshot.digest();
        let flow = cache
            .flows
            .begin(
                cache.policy.clone(),
                Protocol::Tcp,
                crate::protocol::Address::V4([192, 0, 2, 1]),
                443,
                digest,
                PacketAction::Redirect,
            )
            .unwrap();
        flow.commit(PacketAction::Redirect).unwrap();
        cache.state.lock().await.expires = Some(Instant::now() + Duration::from_secs(5));
        cache
            .refresh(|known| async {
                assert_eq!(known, Some(digest));
                assert!(flow.check_delivery().is_ok());
                Ok(super::super::exchange::unchanged_receipt(digest).to_vec())
            })
            .await
            .unwrap();
        assert!(flow.check_delivery().is_ok());
        cache.state.lock().await.expires = Some(Instant::now() + Duration::from_secs(5));
        assert!(cache
            .refresh(|_| async { Err(ClientError::Io) })
            .await
            .is_err());
        assert!(flow.check_delivery().is_err());
        cache.state.lock().await.retry = None;
        cache
            .get(|_| async { Ok(super::super::exchange::unchanged_receipt(digest).to_vec()) })
            .await
            .unwrap();
        assert!(flow.check_delivery().is_err());
    }

    #[tokio::test]
    async fn cache_rejects_rollback_and_equivocation() {
        let cache = Cache::new("scope".into(), None);
        let (_, bytes) = Snapshot::build("scope", 2, &[], &[], &[]).unwrap();
        let accepted = cache.get(|_| async { Ok(bytes) }).await.unwrap();
        assert_eq!(accepted.manifest().revision, 2);
        assert!(cache
            .get(|_| async { panic!("fresh cache must not fetch") })
            .await
            .is_ok());
        cache.state.lock().await.expires = None;
        let (_, bytes) = Snapshot::build("scope", 1, &[], &[], &[]).unwrap();
        assert!(cache.get(|_| async { Ok(bytes) }).await.is_err());
        assert!(cache
            .get(|_| async { panic!("retry throttled") })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn conditional_refresh_reuses_only_the_exact_verified_snapshot() {
        let cache = Cache::new("scope".into(), None);
        let (snapshot, wire) = Snapshot::build("scope", 2, &[], &[], &[]).unwrap();
        let digest = snapshot.digest();
        let old = cache
            .get(|known| async move {
                assert!(known.is_none());
                Ok(wire)
            })
            .await
            .unwrap();
        cache.state.lock().await.expires = None;
        let fresh = cache
            .get(|known| async move {
                assert_eq!(known, Some(digest));
                Ok(super::super::exchange::unchanged_receipt(digest).to_vec())
            })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&old, &fresh));
        assert_eq!(cache.observation(), (2, 1));
        cache.state.lock().await.expires = None;
        assert!(cache
            .get(|_| async { Ok(super::super::exchange::unchanged_receipt([0; 32]).to_vec()) })
            .await
            .is_err());
        assert_eq!(cache.observation(), (2, 2));
        let empty = Cache::new("scope".into(), None);
        assert!(empty
            .get(|_| async { Ok(super::super::exchange::unchanged_receipt(digest).to_vec()) })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn durable_floor_is_scope_bound_and_fails_closed_after_deletion() {
        let dir =
            std::env::temp_dir().join(crate::tui_editor::generated_id("routing-floor").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("floor.toml");
        let cache = Cache::new("scope".into(), Some(path.clone()));
        assert_eq!(cache.observation(), (0, 0));
        assert!(cache.report().contains("не подтверждены"));
        let (_, bytes) = Snapshot::build("scope", 2, &[], &[], &[]).unwrap();
        cache.get(|_| async { Ok(bytes.clone()) }).await.unwrap();
        assert_eq!(cache.observation(), (2, 1));
        assert!(cache.report().contains("актуальны"));
        cache
            .get(|_| async { panic!("fresh floor must not fetch") })
            .await
            .unwrap();
        let restarted = Cache::new("scope".into(), Some(path.clone()));
        let (_, old) = Snapshot::build("scope", 1, &[], &[], &[]).unwrap();
        assert!(restarted.get(|_| async { Ok(old) }).await.is_err());
        let other = Cache::new("other".into(), Some(path.clone()));
        let (_, wrong) = Snapshot::build("other", 3, &[], &[], &[]).unwrap();
        assert!(other.get(|_| async { Ok(wrong) }).await.is_err());
        let advanced = Cache::new("scope".into(), Some(path.clone()));
        let (_, next) = Snapshot::build("scope", 3, &[], &[], &[]).unwrap();
        advanced.get(|_| async { Ok(next.clone()) }).await.unwrap();
        assert_eq!(
            cache
                .get(|_| async { Ok(next) })
                .await
                .unwrap()
                .manifest()
                .revision,
            3
        );
        cache.state.lock().await.expires = None;
        assert_eq!(cache.observation(), (3, 2));
        assert!(cache.report().contains("просрочена"));
        std::fs::remove_file(&path).unwrap();
        let (_, newer) = Snapshot::build("scope", 4, &[], &[], &[]).unwrap();
        assert!(cache.get(|_| async { Ok(newer) }).await.is_err());
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn direct_dial_rejects_invalid_ports_and_unusable_addresses() {
        assert!(dial_direct(Address::V4([127, 0, 0, 1]), 0, None)
            .await
            .is_err());
        assert!(dial_direct(
            Address::Dns("unused.invalid".into()),
            1,
            Some(vec![
                "0.0.0.0".parse().unwrap(),
                "224.0.0.1".parse().unwrap()
            ])
        )
        .await
        .is_err());
        assert!(dial_direct(
            Address::V4([127, 0, 0, 1]),
            1,
            Some(vec!["127.0.0.1".parse().unwrap(); 65])
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn direct_dial_and_relay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connected = dial_direct(Address::V4([127, 0, 0, 1]), port, None)
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let local = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (client, _) = local.accept().await.unwrap();
        let task = tokio::spawn(relay_direct(client, connected));
        peer.write_all(b"hello").await.unwrap();
        let mut received = [0; 5];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"hello");
        server.write_all(b"world").await.unwrap();
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"world");
        peer.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
        assert!(task.await.unwrap().is_ok());
    }
}
