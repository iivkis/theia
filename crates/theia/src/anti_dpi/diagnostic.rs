//! Standalone diagnostic plan, single-job reservation and typed report.
//! No server session, production evidence, listener or OS proxy mutation.
use super::{
    catalog::{Catalog, Overlay, VERSION},
    dns::{self, DnsError},
    invalid, Decision, Document, PreparedPolicy,
};
use crate::{
    config::{self, ConfigError},
    network_scope,
    routing::dpi::{
        diagnostic::{self as tcp_probe, Failure, Observation},
        Strategy, UdpStrategy,
    },
};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::time::Instant;

const CELL_BUDGET: Duration = Duration::from_secs(6);
const JOB_BUDGET: Duration = Duration::from_secs(600);
const CONCURRENCY: usize = 4;

/// Borrowed, exact runtime context; owned jobs must provide the shared budget.
pub(crate) struct RunContext<'a> {
    pub active: &'a super::authority::Active,
    pub epoch: u64,
    pub roots: &'a rustls::RootCertStore,
    pub cancel: &'a AtomicBool,
    pub ready: &'a (dyn Fn() -> bool + Sync),
    pub permits: Option<&'a crate::net::probe::PriorityBudget>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    TcpHttps,
    QuicV1,
    QuicV2,
    Stun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellStatus {
    Available,
    Redirect,
    HttpError,
    Unavailable,
    DnsError,
    SecurityError,
    PolicyDenied,
    Unsupported,
    NotApplicable,
    NotChecked,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    NotRun,
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    None,
    AwaitingAcceptance,
    MissingEndpointMetadata,
    Budget,
    Cancelled,
    ContextChanged,
    Dns(DnsError),
    Timeout,
    Network,
    Tls,
    Protocol,
    NoTransformation,
    ProtectiveDenial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellResult {
    pub domain: String,
    pub protocol: Protocol,
    pub strategy_id: &'static str,
    pub status: CellStatus,
    pub network: Stage,
    pub tls: Stage,
    pub application: Stage,
    pub reason: Reason,
    pub actual_modification: Option<bool>,
    pub http_status: Option<u16>,
    pub duration_ms: u128,
    pub attempts: u8,
    pub endpoint: Option<SocketAddr>,
    pub source: Option<IpAddr>,
    pub policy_action: Option<Decision>,
    pub stale: bool,
}

#[derive(Clone, Copy)]
enum Column {
    Tcp(Option<Strategy>),
    Udp(UdpStrategy, Protocol),
}

impl Column {
    fn protocol(self) -> Protocol {
        match self {
            Self::Tcp(_) => Protocol::TcpHttps,
            Self::Udp(_, protocol) => protocol,
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::Tcp(None) => "direct",
            Self::Tcp(Some(strategy)) => strategy.id(),
            Self::Udp(strategy, _) => strategy.id(),
        }
    }

    fn unavailable(self) -> Option<Reason> {
        match self {
            Self::Tcp(None) => None,
            Self::Tcp(Some(strategy)) => {
                (!strategy.accepted_for_standalone()).then_some(Reason::AwaitingAcceptance)
            }
            Self::Udp(strategy, _) if !strategy.accepted_for_standalone() => {
                Some(Reason::AwaitingAcceptance)
            }
            // A plain hostname does not advertise an authenticated QUIC or
            // credential-free STUN endpoint. Never guess protocol/port.
            Self::Udp(_, _) => Some(Reason::MissingEndpointMetadata),
        }
    }

    fn cell(self, domain: &str) -> CellResult {
        let reason = self.unavailable().unwrap_or(Reason::None);
        CellResult {
            domain: domain.to_owned(),
            protocol: self.protocol(),
            strategy_id: self.id(),
            status: if reason == Reason::AwaitingAcceptance {
                CellStatus::Unsupported
            } else {
                CellStatus::NotChecked
            },
            network: Stage::NotRun,
            tls: Stage::NotRun,
            application: Stage::NotRun,
            reason,
            actual_modification: None,
            http_status: None,
            duration_ms: 0,
            attempts: 0,
            endpoint: None,
            source: None,
            policy_action: None,
            stale: false,
        }
    }
}

fn columns() -> Vec<Column> {
    use crate::{quic_core::wire::Version, routing::dpi::udp::BindingStrategy};
    std::iter::once(Column::Tcp(None))
        .chain(
            Strategy::ALL
                .into_iter()
                .map(|strategy| Column::Tcp(Some(strategy))),
        )
        .chain([
            Column::Udp(UdpStrategy::Quic(Version::V1), Protocol::QuicV1),
            Column::Udp(UdpStrategy::Quic(Version::V2), Protocol::QuicV2),
            Column::Udp(
                UdpStrategy::StunBinding(BindingStrategy::Fingerprint),
                Protocol::Stun,
            ),
        ])
        .collect()
}

/// Canonical diagnostic columns are shared by all presentations.
pub fn strategy_columns() -> Vec<&'static str> {
    columns().into_iter().map(Column::id).collect()
}

pub(crate) fn strategy_unavailable(id: &str) -> Option<Reason> {
    columns()
        .into_iter()
        .find(|column| column.id() == id)
        .and_then(Column::unavailable)
}

#[derive(Debug)]
struct Saved {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl Saved {
    fn read(path: &Path) -> Result<Self, ConfigError> {
        // Do not canonicalize a symlink into an apparently safe regular file.
        // The shared no-follow reader must inspect the original pathname.
        let path = std::path::absolute(path)
            .map_err(|_| invalid("diagnostic", "cannot locate saved document"))?;
        let bytes = config::editor_bytes(&path)?;
        Ok(Self { path, bytes })
    }

    fn text(&self) -> Result<&str, ConfigError> {
        std::str::from_utf8(&self.bytes)
            .map_err(|_| invalid("diagnostic", "saved document is not UTF-8"))
    }

    fn current(&self) -> bool {
        config::editor_bytes(&self.path).is_ok_and(|bytes| bytes == self.bytes)
    }

    fn hash(&self, hash: &mut Sha256) {
        field(hash, self.path.as_os_str().as_encoded_bytes());
        field(hash, &self.bytes);
    }
}

fn field(hash: &mut Sha256, data: &[u8]) {
    hash.update((data.len() as u64).to_be_bytes());
    hash.update(data);
}

fn hex(digest: [u8; 32]) -> String {
    let mut result = String::new();
    for byte in digest {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

/// An offline plan. Confirmation binds the exact saved configuration,
/// catalog/overlay, selected hostnames, protocol and strategy registry.
/// The actual one-shot execution additionally binds a live network epoch.
pub struct Plan {
    saved: Saved,
    overlay: Option<Saved>,
    document: Document,
    policy: PreparedPolicy,
    hosts: Vec<String>,
    digest: [u8; 32],
}

impl Plan {
    pub fn prepare(
        config_path: &Path,
        overlay_path: Option<&Path>,
        hosts: &[String],
    ) -> Result<Self, ConfigError> {
        let saved = Saved::read(&super::authority::canonical_config_path(config_path)?)?;
        let document = Document::parse(saved.text()?)?;
        let policy = document.prepare()?;
        if document.anti_dpi.resolver.is_none() {
            return Err(invalid(
                "diagnostic.resolver",
                "explicit DoH resolver required",
            ));
        }
        let overlay = overlay_path.map(Saved::read).transpose()?;
        let choices = overlay
            .as_ref()
            .map(|saved| Overlay::parse(saved.text()?))
            .transpose()?
            .unwrap_or_default();
        let catalog = Catalog::build(&choices)?;
        let selected = if hosts.len() == 1 && hosts[0] == "all" {
            catalog
                .entries()
                .iter()
                .filter(|entry| !entry.excluded)
                .map(|entry| entry.hostname.clone())
                .collect::<Vec<_>>()
        } else {
            hosts.to_vec()
        };
        let columns = columns();
        let hosts = catalog
            .select(&selected, columns.len())?
            .into_iter()
            .map(|entry| entry.hostname.clone())
            .collect::<Vec<_>>();
        let mut hash = Sha256::new();
        field(&mut hash, b"theia/standalone/diagnostic/v1");
        saved.hash(&mut hash);
        if let Some(overlay) = &overlay {
            field(&mut hash, b"overlay");
            overlay.hash(&mut hash);
        } else {
            field(&mut hash, b"no-overlay");
        }
        field(&mut hash, VERSION.as_bytes());
        field(&mut hash, &Catalog::builtin_digest());
        field(&mut hash, &policy.digest());
        field(
            &mut hash,
            b"https:443 HEAD / HTTP/1.1; doh:443 GET /dns-query",
        );
        for host in &hosts {
            field(&mut hash, host.as_bytes());
        }
        for column in columns {
            field(&mut hash, column.id().as_bytes());
            field(
                &mut hash,
                format!("{:?}:{:?}", column.protocol(), column.unavailable()).as_bytes(),
            );
        }
        Ok(Self {
            saved,
            overlay,
            document,
            policy,
            hosts,
            digest: hash.finalize().into(),
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn planned_cells(&self) -> usize {
        self.hosts.len() * columns().len()
    }

    /// Maximum number of runnable target probes, excluding DNS preparation.
    pub(crate) fn runnable_cells(&self) -> usize {
        self.hosts.len()
            * columns().iter().filter(|column| column.unavailable().is_none()).count()
    }

    fn files_current(&self) -> bool {
        self.saved.current() && self.overlay.as_ref().is_none_or(Saved::current)
    }

    pub fn preview(&self) -> String {
        let mut result = format!(
            "Diagnostic preview (no network requests)\nCatalogue: {VERSION}, SHA256={}\nPolicy revision: {}\nTargets ({}):\n",
            hex(Catalog::builtin_digest()), self.policy.revision(), self.hosts.len(),
        );
        for host in &self.hosts {
            let _ = writeln!(result, "  {host}");
        }
        if let Some(resolver) = &self.document.anti_dpi.resolver {
            let _ = writeln!(
                result,
                "Resolver: https://{}/dns-query, bootstrap {}",
                resolver.hostname, resolver.bootstrap[0]
            );
        }
        let mut runnable = 0;
        for column in columns() {
            if column.unavailable().is_none() {
                runnable += 1;
            }
            let _ = writeln!(
                result,
                "{:?} {}: {:?}",
                column.protocol(),
                column.id(),
                column.unavailable()
            );
        }
        let _ = writeln!(result,
            "At most {} DNS/HTTPS attempts; 4 concurrent, 6 s per cell, 600 s per job.\nLocal public IP and selected names are disclosed to the resolver/targets. No VPS, no redirect following or OS proxy changes.\nConfirm exact plan with SHA256={}",
            self.hosts.len() * (dns::MAX_DNS_REQUESTS + runnable), hex(self.digest),
        );
        result
    }

    /// Localized, typed presentation of the exact reviewed plan. The CLI
    /// keeps its stable technical representation separately.
    pub(crate) fn ui_preview(&self, owned: bool) -> String {
        let mut result = String::new();
        let runnable = self.runnable_cells();
        let skipped = self.planned_cells() - runnable;
        let _ = writeln!(result, "Проверить {} сайт(ов)?\nЗапланировано сетевых проверок сайтов: {runnable}. Недоступных ячеек: {skipped}.", self.hosts.len());
        if runnable == self.hosts.len() {
            let _ = writeln!(result, "Сейчас доступна только прямая HTTPS-проверка. Anti-DPI не будет проверен.");
        }
        let _ = writeln!(result, "\n←/→ — выбрать «Запустить проверку», Enter — подтвердить. Esc — отменить.\nДо подтверждения запросов нет. DNS и сайты получат ваш публичный IP.\nПрокси Windows, правила и разрешения рабочего трафика не изменятся.");
        let _ = writeln!(result, "\nСпособы проверки:");
        for column in columns() {
            let name = match column.id() {
                "direct" => "TCP HTTPS — напрямую (контроль)",
                "tcp_header" => "TCP HTTPS — Header",
                "tcp_middle" => "TCP HTTPS — Middle",
                "tcp_balanced" => "TCP HTTPS — Balanced",
                "quic_v1_initial_split" => "QUIC v1",
                "quic_v2_initial_split" => "QUIC v2",
                "stun_fingerprint" => "STUN",
                other => other,
            };
            let state = match column.unavailable() {
                None => "будет проверено",
                Some(Reason::AwaitingAcceptance) => "пока недоступно",
                Some(Reason::MissingEndpointMetadata) => "нет данных о совместимом сервере",
                Some(_) => "не будет запущено",
            };
            let _ = writeln!(result, "  {name}: {state}");
        }
        let _ = writeln!(
            result,
            "\nЛимиты: не более {} DNS/HTTPS операций, {} параллельно; 6 с на ячейку, 10 мин на задание.",
            self.hosts.len() * dns::MAX_DNS_REQUESTS + runnable,
            if owned { 2 } else { 4 }
        );
        if let Some(resolver) = &self.document.anti_dpi.resolver {
            let _ = writeln!(
                result,
                "DNS: HTTPS https://{}/dns-query · bootstrap {}",
                resolver.hostname,
                resolver.bootstrap.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            );
        }
        let _ = writeln!(result, "Перенаправления не выполняются. Доступность не доказывает обход DPI.");
        let _ = writeln!(result, "\nТочные цели (HEAD /, HTTPS 443):");
        for host in &self.hosts {
            let _ = writeln!(result, "  {host}");
        }
        let _ = writeln!(result, "\nТехнические сведения: ревизия {} · каталог {VERSION}\nSHA256 плана: {}", self.policy.revision(), hex(self.digest));
        result
    }

    /// Requires explicit confirmation of this exact plan. No persistent
    /// consent or production strategy evidence is created.
    pub async fn run(
        self,
        confirmation: [u8; 32],
        cancel: &AtomicBool,
    ) -> Result<Report, ConfigError> {
        self.run_with_progress(confirmation, cancel, |_| {}).await
    }

    /// The callback sees only finished cells (including typed unsupported
    /// and cancelled outcomes); no production evidence or shared cache.
    pub async fn run_with_progress(
        self,
        confirmation: [u8; 32],
        cancel: &AtomicBool,
        mut progress: impl FnMut(&[CellResult]),
    ) -> Result<Report, ConfigError> {
        if self.digest != confirmation || !self.files_current() {
            return Err(invalid(
                "diagnostic",
                "confirmation or saved document changed; review again",
            ));
        }
        // This is the existing per-user System Proxy owner reservation.
        // No apply() call: diagnostics must not change any OS settings.
        #[cfg(windows)]
        let _owner = reserve()?;
        #[cfg(not(windows))]
        reserve()?;
        let candidate = super::authority::Candidate::read(&self.saved.path)?;
        if candidate.digest() != self.policy.digest() || !self.files_current() {
            return Err(invalid(
                "diagnostic",
                "applied policy changed; review again",
            ));
        }
        let active = candidate.activate()?;
        let epoch = network_scope::generation()
            .ok_or_else(|| invalid("diagnostic", "network generation unavailable"))?;
        let roots = crate::net::tls::native_roots();
        if roots.is_empty() {
            return Err(invalid("diagnostic", "native trust roots unavailable"));
        }
        self.run_context(
            RunContext {
                active: &active,
                epoch,
                roots: &roots,
                cancel,
                ready: &|| true,
                permits: None,
            },
            &mut progress,
        )
        .await
    }

    /// The caller is the actual runtime that holds the Windows proxy owner.
    /// No second reservation, no OS mutation, and no externally asserted owner.
    #[cfg(windows)]
    pub(crate) async fn run_owned(
        self,
        confirmation: [u8; 32],
        context: RunContext<'_>,
        mut progress: impl FnMut(&[CellResult]),
    ) -> Result<Report, ConfigError> {
        if self.digest != confirmation
            || !self.files_current()
            || !context.active.matches_path(&self.saved.path)
            || context.active.policy().digest() != self.policy.digest()
            || !context.active.live()
            || !(context.ready)()
            || context.permits.is_none()
        {
            return Err(invalid(
                "diagnostic.owner",
                "owned policy or connection changed; review again",
            ));
        }
        self.run_context(context, &mut progress).await
    }

    async fn run_context(
        self,
        context: RunContext<'_>,
        progress: &mut (impl FnMut(&[CellResult]) + ?Sized),
    ) -> Result<Report, ConfigError> {
        let RunContext {
            active,
            epoch,
            roots,
            cancel,
            ready,
            permits,
        } = context;
        let state = State {
            plan: &self,
            active,
            epoch,
            cancel,
            ready,
            permits,
            stale: AtomicBool::new(false),
            deadline: Instant::now() + JOB_BUDGET,
        };
        let mut cells = Vec::new();
        // Keep at least two of the four shared permits available for production.
        // Pre-connect diagnostics still use four independent rows.
        let concurrency = if permits.is_some() { 2 } else { CONCURRENCY };
        for group in self.hosts.chunks(concurrency) {
            // Fixed-size batches of borrowed futures: no detached tasks.
            // Dropping the job drops every active socket before owner release.
            let (a, b, c, d) = tokio::join!(
                optional_row(&state, group.first(), roots),
                optional_row(&state, group.get(1), roots),
                optional_row(&state, group.get(2), roots),
                optional_row(&state, group.get(3), roots),
            );
            for row in [a, b, c, d] {
                if !row.is_empty() {
                    progress(&row);
                    cells.extend(row);
                }
            }
        }
        if !state.context_current() {
            for cell in &mut cells {
                cell.stale = true;
            }
        }
        Ok(Report {
            catalog_version: VERSION,
            catalog_digest: Catalog::builtin_digest(),
            plan_digest: self.digest,
            cells,
        })
    }
}

#[cfg(windows)]
fn reserve() -> Result<crate::windows_system_proxy::ReservedProxy, ConfigError> {
    crate::windows_system_proxy::ReservedProxy::acquire().map_err(|_| {
        invalid(
            "diagnostic.owner",
            "proxy owner conflict or recovery required",
        )
    })
}

#[cfg(not(windows))]
fn reserve() -> Result<(), ConfigError> {
    Err(invalid(
        "diagnostic",
        "live standalone System Proxy diagnostics require Windows",
    ))
}

struct State<'a> {
    plan: &'a Plan,
    active: &'a super::authority::Active,
    epoch: u64,
    cancel: &'a AtomicBool,
    ready: &'a (dyn Fn() -> bool + Sync),
    permits: Option<&'a crate::net::probe::PriorityBudget>,
    stale: AtomicBool,
    deadline: Instant,
}

impl State<'_> {
    fn context_current(&self) -> bool {
        if self.stale.load(Ordering::Acquire) {
            return false;
        }
        if !(self.ready)()
            || network_scope::generation() != Some(self.epoch)
            || !self.plan.files_current()
            || !self.active.live()
        {
            self.stale.store(true, Ordering::Release);
            return false;
        }
        !self.stale.load(Ordering::Acquire)
    }

    fn live(&self) -> bool {
        !self.cancel.load(Ordering::Acquire)
            && self.context_current()
            && Instant::now() < self.deadline
    }

    fn stop_reason(&self) -> Option<Reason> {
        if !self.context_current() {
            Some(Reason::ContextChanged)
        } else if self.cancel.load(Ordering::Acquire) {
            Some(Reason::Cancelled)
        } else if Instant::now() >= self.deadline {
            Some(Reason::Budget)
        } else {
            None
        }
    }
}

fn stopped(cell: &mut CellResult, reason: Reason) {
    cell.reason = reason;
    cell.status = if reason == Reason::Cancelled {
        CellStatus::Cancelled
    } else {
        CellStatus::NotChecked
    };
    cell.stale = reason == Reason::ContextChanged;
}

fn dns_failed(cell: &mut CellResult, error: DnsError) {
    cell.reason = Reason::Dns(error);
    cell.status = match error {
        DnsError::PolicyDenied => CellStatus::PolicyDenied,
        DnsError::Tls => CellStatus::SecurityError,
        DnsError::Cancelled => CellStatus::Cancelled,
        _ => CellStatus::DnsError,
    };
}

fn apply_observation(cell: &mut CellResult, observation: Observation, modify: bool) {
    cell.network = if observation.connected {
        Stage::Passed
    } else {
        Stage::Failed
    };
    cell.tls = if observation.verified_tls {
        Stage::Passed
    } else if observation.connected {
        Stage::Failed
    } else {
        Stage::NotRun
    };
    cell.actual_modification = Some(observation.transformed);
    match observation.result {
        Ok(code) if !modify || observation.transformed => {
            cell.http_status = Some(code);
            cell.application = Stage::Passed;
            cell.status = match code {
                200..=299 => CellStatus::Available,
                300..=399 => CellStatus::Redirect,
                _ => CellStatus::HttpError,
            };
        }
        Ok(_) | Err(Failure::Unavailable) => {
            cell.status = CellStatus::NotChecked;
            cell.reason = Reason::NoTransformation;
        }
        Err(error) => {
            cell.application = if observation.verified_tls {
                Stage::Failed
            } else {
                Stage::NotRun
            };
            (cell.status, cell.reason) = match error {
                Failure::Timeout => (CellStatus::Unavailable, Reason::Timeout),
                Failure::Denied => (CellStatus::PolicyDenied, Reason::ProtectiveDenial),
                Failure::Network => (CellStatus::Unavailable, Reason::Network),
                Failure::Tls => (CellStatus::SecurityError, Reason::Tls),
                Failure::Protocol => (CellStatus::Unavailable, Reason::Protocol),
                Failure::Unavailable => unreachable!(),
            };
        }
    }
}

async fn optional_row(
    state: &State<'_>,
    host: Option<&String>,
    roots: &rustls::RootCertStore,
) -> Vec<CellResult> {
    match host {
        Some(host) => row(state, host, roots).await,
        None => Vec::new(),
    }
}

async fn row(state: &State<'_>, host: &str, roots: &rustls::RootCertStore) -> Vec<CellResult> {
    let columns = columns();
    let mut cells = columns
        .iter()
        .map(|column| column.cell(host))
        .collect::<Vec<_>>();
    let started = Instant::now();
    if let Some(reason) = state.stop_reason() {
        for (column, cell) in columns.iter().zip(&mut cells) {
            if column.unavailable().is_none() {
                stopped(cell, reason);
            }
        }
        return cells;
    }
    let live = || state.live();
    let dns_deadline = (started + CELL_BUDGET).min(state.deadline);
    let _permit = if let Some(permits) = state.permits {
        let acquired = tokio::select! {
            biased;
            _ = crate::net::guarded_io::revoked(&live) => None,
            result = permits.diagnostic(dns_deadline) => result,
        };
        match acquired {
            Some(permit) => Some(permit),
            None => {
                let reason = state.stop_reason().unwrap_or(Reason::Budget);
                for (column, cell) in columns.iter().zip(&mut cells) {
                    if column.unavailable().is_none() {
                        stopped(cell, reason);
                    }
                }
                return cells;
            }
        }
    } else {
        None
    };
    let result = dns::resolve(
        state.active.document().anti_dpi.resolver.as_ref(),
        state.active.policy(),
        host,
        roots,
        &live,
        dns_deadline,
    )
    .await;
    let dns_elapsed = started.elapsed();
    let pins = match result {
        Ok(pins) => pins,
        Err(error) => {
            for (column, cell) in columns.iter().zip(&mut cells) {
                if column.unavailable().is_none() {
                    if let Some(reason) = state.stop_reason() {
                        stopped(cell, reason);
                    } else {
                        dns_failed(cell, error);
                    }
                    cell.duration_ms = dns_elapsed.as_millis();
                }
            }
            return cells;
        }
    };
    let peer = SocketAddr::new(pins.addresses()[0], 443);
    let Some(scope) = network_scope::observe(peer) else {
        for (column, cell) in columns.iter().zip(&mut cells) {
            if column.unavailable().is_none() {
                stopped(cell, Reason::ContextChanged);
            }
        }
        return cells;
    };
    let mut attempted = false;
    let mut protective = false;
    for (column, cell) in columns.iter().zip(&mut cells) {
        if column.unavailable().is_some() {
            continue;
        }
        let Column::Tcp(strategy) = *column else {
            continue;
        };
        if let Some(reason) = state.stop_reason() {
            stopped(cell, reason);
            continue;
        }
        if protective {
            stopped(cell, Reason::ProtectiveDenial);
            continue;
        }
        if !pins.current()
            || (pins.single_use() && attempted)
            || network_scope::observe(peer) != Some(scope)
        {
            stopped(cell, Reason::ContextChanged);
            continue;
        }
        let budget = CELL_BUDGET.saturating_sub(dns_elapsed);
        if budget.is_zero() {
            stopped(cell, Reason::Budget);
            continue;
        }
        attempted = true;
        cell.attempts = 1;
        cell.endpoint = Some(peer);
        cell.source = Some(scope.bind_address().ip());
        cell.policy_action = Some(pins.decision());
        let started = Instant::now();
        let permitted =
            || state.live() && pins.current() && network_scope::observe(peer) == Some(scope);
        let observation = tcp_probe::https(
            host,
            peer,
            scope,
            strategy,
            roots,
            &permitted,
            (started + budget).min(state.deadline),
        )
        .await;
        cell.duration_ms = (started.elapsed() + dns_elapsed).as_millis();
        apply_observation(cell, observation, strategy.is_some());
        if let Some(reason) = state.stop_reason() {
            if observation.result.is_err() {
                stopped(cell, reason);
            }
            cell.stale |= reason == Reason::ContextChanged;
        }
        protective = matches!(
            cell.status,
            CellStatus::SecurityError | CellStatus::PolicyDenied
        );
    }
    if (!pins.current() && !pins.single_use()) || network_scope::observe(peer) != Some(scope) {
        for cell in &mut cells {
            cell.stale = true;
        }
    }
    cells
}

/// Select the fastest successful, actually modified TCP observation only
/// against a comparable failed direct control. Does not publish evidence.
pub(crate) fn recommend_tcp<'a>(
    direct: &CellResult,
    candidates: impl IntoIterator<Item = &'a CellResult>,
) -> Option<&'a CellResult> {
    if direct.stale
        || direct.protocol != Protocol::TcpHttps
        || direct.strategy_id != "direct"
        || direct.status != CellStatus::Unavailable
        || !matches!(direct.reason, Reason::Timeout | Reason::Network | Reason::Protocol)
        || direct.actual_modification != Some(false)
        || direct.attempts != 1
        || direct.endpoint.is_none()
        || direct.source.is_none()
        || !matches!(direct.policy_action, Some(Decision::Pass | Decision::Modify))
    {
        return None;
    }
    candidates
        .into_iter()
        .filter(|cell| {
            cell.domain == direct.domain
                && cell.protocol == direct.protocol
                && Strategy::ALL.iter().any(|strategy| strategy.id() == cell.strategy_id)
                && cell.status == CellStatus::Available
                && cell.reason == Reason::None
                && cell.actual_modification == Some(true)
                && cell.network == Stage::Passed
                && cell.tls == Stage::Passed
                && cell.application == Stage::Passed
                && cell.http_status.is_some_and(|code| (200..=299).contains(&code))
                && cell.attempts == 1
                && !cell.stale
                && cell.endpoint == direct.endpoint
                && cell.source == direct.source
                && cell.policy_action == direct.policy_action
        })
        .min_by_key(|cell| (cell.duration_ms, cell.strategy_id))
}

#[derive(Debug)]
pub struct Report {
    pub catalog_version: &'static str,
    pub catalog_digest: [u8; 32],
    pub plan_digest: [u8; 32],
    pub cells: Vec<CellResult>,
}

impl Report {
    pub fn render(&self) -> String {
        let mut result = format!(
            "Diagnostic report: catalogue={} SHA256={}\nExact tested HTTPS endpoint only; observations do not prove DPI causality.\n",
            self.catalog_version, hex(self.catalog_digest),
        );
        for cell in &self.cells {
            let _ = writeln!(result,
                "{}\t{:?}\t{}\t{:?}\tDNS/route={:?}\tnetwork={:?}\tTLS={:?}\tapp={:?}\tHTTP={:?}\tmodified={:?}\t{}ms\tattempts={}\t{:?}\tstale={}",
                cell.domain, cell.protocol, cell.strategy_id, cell.status, cell.policy_action,
                cell.network, cell.tls, cell.application, cell.http_status, cell.actual_modification,
                cell.duration_ms, cell.attempts, cell.reason, cell.stale,
            );
        }
        result
    }

    /// Aggregate only. Never include a target, IP, source, plan digest or
    /// configuration/profile identifier in an anonymous export.
    pub fn anonymous_summary(&self) -> String {
        let mut counts = std::collections::BTreeMap::new();
        for cell in &self.cells {
            let key = format!(
                "{:?}\t{}\t{:?}\t{:?}\tstale={}",
                cell.protocol, cell.strategy_id, cell.status, cell.reason, cell.stale
            );
            let entry = counts.entry(key).or_insert((0usize, 0u128));
            entry.0 += 1;
            entry.1 += cell.duration_ms;
        }
        let mut result = format!(
            "{} SHA256={}\n",
            self.catalog_version,
            hex(self.catalog_digest)
        );
        for (key, (count, duration)) in counts {
            let _ = writeln!(result, "{key}\tcount={count}\ttotal_ms={duration}");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_status_and_noop_modification_are_not_false_successes() {
        let column = Column::Tcp(None);
        for (code, status) in [
            (200, CellStatus::Available),
            (302, CellStatus::Redirect),
            (403, CellStatus::HttpError),
            (429, CellStatus::HttpError),
            (451, CellStatus::HttpError),
            (503, CellStatus::HttpError),
        ] {
            let mut cell = column.cell("example.com");
            apply_observation(
                &mut cell,
                Observation {
                    connected: true,
                    verified_tls: true,
                    transformed: false,
                    result: Ok(code),
                },
                false,
            );
            assert_eq!(cell.status, status);
            assert_eq!(cell.http_status, Some(code));
            apply_observation(
                &mut cell,
                Observation {
                    connected: true,
                    verified_tls: true,
                    transformed: false,
                    result: Ok(code),
                },
                true,
            );
            assert_eq!(cell.status, CellStatus::NotChecked);
        }
    }

    #[test]
    fn unsupported_strategies_and_cancelled_rows_are_not_failures() {
        let columns = columns();
        assert_eq!(columns.len(), 7);
        let mut cell = columns[0].cell("example.com");
        stopped(&mut cell, Reason::Cancelled);
        assert_eq!(cell.status, CellStatus::Cancelled);
        assert!(!cell.stale);
        stopped(&mut cell, Reason::ContextChanged);
        assert!(cell.stale);
        assert_eq!(
            columns[1].cell("example.com").status,
            CellStatus::Unsupported
        );
    }

    #[test]
    fn recommendations_require_comparable_verified_modified_success() {
        let mut direct = Column::Tcp(None).cell("example.com");
        direct.status = CellStatus::Unavailable;
        direct.reason = Reason::Timeout;
        direct.actual_modification = Some(false);
        direct.attempts = 1;
        direct.endpoint = Some("1.1.1.1:443".parse().unwrap());
        direct.source = Some("192.0.2.1".parse().unwrap());
        direct.policy_action = Some(Decision::Pass);
        let mut header = direct.clone();
        header.strategy_id = "tcp_header";
        header.reason = Reason::None;
        header.status = CellStatus::Available;
        header.actual_modification = Some(true);
        header.network = Stage::Passed;
        header.tls = Stage::Passed;
        header.application = Stage::Passed;
        header.http_status = Some(200);
        header.duration_ms = 80;
        let mut middle = header.clone();
        middle.strategy_id = "tcp_middle";
        middle.duration_ms = 40;
        assert_eq!(recommend_tcp(&direct, [&header, &middle]), Some(&middle));
        middle.stale = true;
        assert_eq!(recommend_tcp(&direct, [&header, &middle]), Some(&header));
        header.actual_modification = Some(false);
        assert!(recommend_tcp(&direct, [&header, &middle]).is_none());
        header.actual_modification = Some(true);
        header.endpoint = Some("1.0.0.1:443".parse().unwrap());
        assert!(recommend_tcp(&direct, [&header]).is_none());
        header.endpoint = direct.endpoint;
        direct.status = CellStatus::SecurityError;
        assert!(recommend_tcp(&direct, [&header]).is_none());
        direct.status = CellStatus::Available;
        assert!(recommend_tcp(&direct, [&header]).is_none());
    }

    #[test]
    fn anonymous_summary_never_contains_endpoints_or_plan_digest() {
        let mut cell = Column::Tcp(None).cell("private.example.com");
        cell.endpoint = Some("1.1.1.1:443".parse().unwrap());
        cell.source = Some("10.2.3.4".parse().unwrap());
        let report = Report {
            catalog_version: VERSION,
            catalog_digest: [1; 32],
            plan_digest: [2; 32],
            cells: vec![cell],
        };
        let text = report.anonymous_summary();
        assert!(!text.contains("private.example.com"));
        assert!(!text.contains("1.1.1.1"));
        assert!(!text.contains("10.2.3.4"));
        assert!(!text.contains(&hex([2; 32])));
    }
}
