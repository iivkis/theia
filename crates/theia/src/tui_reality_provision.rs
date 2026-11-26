//! Explicit local provisioning wizard. Uses the existing approved health
//! inventory and exact digest. No live server configuration or grants are
//! modified. All filesystem operations are off the terminal event loop.
use crate::{reality_bootstrap::Error, reality_provision, reference_health};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, TryRecvError},
};

const LIMIT: usize = 1024;

struct CheckedPlan {
    source_digest: [u8; 32],
    state: reference_health::State,
}

struct Review {
    digest: [u8; 32],
    body: String,
    checked: Option<Box<CheckedPlan>>,
}

struct PlanReview {
    digest: [u8; 32],
    body: String,
}

enum Stage {
    Input,
    Loading(Receiver<Result<Review, Error>>),
    LoadingPlan(Receiver<Result<PlanReview, Error>>),
    ConfirmPlan(PlanReview),
    Checking {
        result: Receiver<Result<Review, Error>>,
        cancel: tokio::sync::oneshot::Sender<()>,
    },
    Confirm(Review),
    Applying(Receiver<Result<String, Error>>),
    Done(String),
}

pub(crate) struct ProvisionPanel {
    fields: [String; 3],
    focus: usize,
    stage: Stage,
    error: Option<String>,
    wizard: Option<Wizard>,
}

fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validate_paths(health: &Path, output: &Path) -> Result<(), Error> {
    if !crate::bounded_input::explicit_file_path(health)
        || !crate::bounded_input::explicit_file_path(output)
        || health == output
        || output.file_name().is_none()
    {
        return Err(Error::Storage);
    }
    match std::fs::symlink_metadata(output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(Error::Storage),
    }
}

fn read_state(path: &Path) -> Result<reference_health::State, Error> {
    reference_health::Store::new(path)
        .map_err(|_| Error::Storage)?
        .inspect()
        .map_err(|_| Error::Health)
}

fn preview(health: &Path, output: &Path, now: u64) -> Result<Review, Error> {
    validate_paths(health, output)?;
    let state = read_state(health)?;
    render_review(&state, output, now, None)
}

fn render_review(
    state: &reference_health::State,
    output: &Path,
    now: u64,
    checked: Option<Box<CheckedPlan>>,
) -> Result<Review, Error> {
    let review = reality_provision::preview(state, now)?;
    let body = format!("ПРЕДПРОСМОТР: только локальный комплект, не live Apply.\n{}\n{}\nhealth_sha256={}\nplan_sha256={}\nКаталог: {}\nIdentity, admission и descriptor создаются автоматически.\nПрава пользователей и runtime не меняются.\ny: создать новый комплект; Esc/n: отменить.",
        state.plan().preview().map_err(|_| Error::Health)?,
        state.report(now).map_err(|_| Error::Health)?,
        hex(review.health_sha256), hex(review.plan_sha256), output.display());
    Ok(Review {
        digest: review.health_sha256,
        body,
        checked,
    })
}

fn apply(health: &Path, output: &Path, approved: [u8; 32], now: u64) -> Result<String, Error> {
    validate_paths(health, output)?;
    let state = read_state(health)?;
    let record = reality_provision::create(&state, approved, output, now)?;
    Ok(format!("Комплект сохранён. Runtime НЕ изменён.\nidentity_sha256={}\npublication_sha256={}\nEsc: закрыть.",
        hex(record.identity_sha256), hex(record.publication_sha256)))
}

fn read_plan(path: &Path) -> Result<(reference_health::Plan, [u8; 32]), Error> {
    let raw = crate::bounded_input::read(path, reference_health::MAX_PLAN as u64, true, false)
        .map_err(|_| Error::Storage)?;
    let raw = std::str::from_utf8(&raw).map_err(|_| Error::Format)?;
    let plan = reference_health::Plan::parse(raw).map_err(|_| Error::Format)?;
    Ok((plan, reference_health::digest(raw)))
}

fn new_health_path(health: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(health) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(Error::Storage),
    }
}

fn plan_preview(plan_path: &Path, health: &Path, output: &Path) -> Result<PlanReview, Error> {
    validate_paths(health, output)?;
    new_health_path(health)?;
    let (plan, digest) = read_plan(plan_path)?;
    let body = format!("СОГЛАСИЕ НА ПРОВЕРКУ: только перечисленные цели.\n{}\nplan_document_sha256={}\nПри проверке используются указанные DNS и точные IP, два HTTPS HEAD для H2/H3, без bearer и редиректов. Никакой записи до следующего подтверждения.\ny: проверить; n/Esc: отменить.", plan.preview().map_err(|_| Error::Health)?, hex(digest));
    Ok(PlanReview { digest, body })
}

fn check_plan(
    plan_path: &Path,
    health: &Path,
    output: &Path,
    expected: [u8; 32],
    cancel: tokio::sync::oneshot::Receiver<()>,
) -> Result<Review, Error> {
    validate_paths(health, output)?;
    new_health_path(health)?;
    let (plan, actual) = read_plan(plan_path)?;
    if actual != expected {
        return Err(Error::Approval);
    }
    let approved = plan.digest().map_err(|_| Error::Health)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::Storage)?;
    let evidence = runtime.block_on(async {
        tokio::select! {
            biased;
            _ = cancel => Err(Error::Health),
            evidence = reference_health::check(&plan, approved) => evidence.map_err(|_| Error::Health),
        }
    })?;
    let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
    let state = reference_health::State::new(plan, evidence, now).map_err(|_| Error::Health)?;
    let mut review = render_review(&state, output, now, None)?;
    review.checked = Some(Box::new(CheckedPlan {
        source_digest: expected,
        state,
    }));
    review.body.push_str("\nПосле подтверждения сохраняется новый health store и новый комплект. При отмене ничего не записывается.");
    Ok(review)
}

fn apply_checked(
    plan_path: &Path,
    health: &Path,
    output: &Path,
    review: Review,
    now: u64,
) -> Result<String, Error> {
    let Some(checked) = review.checked else {
        return apply(health, output, review.digest, now);
    };
    validate_paths(health, output)?;
    new_health_path(health)?;
    let (_, digest) = read_plan(plan_path)?;
    if digest != checked.source_digest {
        return Err(Error::Approval);
    }
    let fresh = reality_provision::preview(&checked.state, now)?;
    if fresh.health_sha256 != review.digest {
        return Err(Error::Approval);
    }
    reference_health::Store::new(health)
        .map_err(|_| Error::Storage)?
        .enroll(&checked.state)
        .map_err(|error| match error {
            reference_health::Error::Indeterminate => Error::Indeterminate,
            _ => Error::Storage,
        })?;
    // The health evidence is durable even if later provisioning fails.
    // It is not a configuration or proof of listener activation.
    let record = reality_provision::create(&checked.state, review.digest, output, now)?;
    Ok(format!("Health store и комплект сохранены. Runtime НЕ изменён.\nidentity_sha256={}\npublication_sha256={}\nEsc: закрыть.",
        hex(record.identity_sha256), hex(record.publication_sha256)))
}

use crate::{
    config::{self, Config},
    reality_config::{self, ServerRequest},
    tui_editor::Editor,
    tui_reality_register::RegistrationPanel,
    Role,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
const MAX_DOMAIN_SEEDS: usize = 80;
const MAX_RANGE_IPS: usize = 32;
const MAX_RANGES: usize = 4;
const DNS_PARALLELISM: usize = 6;
const WIZARD_LABELS: [&str; 8] = [
    "ID inbound",
    "TCP/UDP bind",
    "Публичный endpoint host (без порта)",
    "Собственные IP через запятую",
    "Домены: catalog или domain=IP",
    "Grants (ID через запятую)",
    "Выбор: auto / manual",
    "Разрешённые CIDR (необязательно)",
];

#[derive(Clone)]
struct WizardInput {
    config: PathBuf,
    source: Option<[u8; 32]>,
    id: String,
    listen: SocketAddr,
    endpoint: String,
    own_ips: Vec<IpAddr>,
    candidates: Vec<(String, Option<IpAddr>)>,
    range_spec: String,
    range_targets: Vec<(IpAddr, Option<String>)>,
    grants: Vec<String>,
    automatic: bool,
    health: PathBuf,
    bundle: PathBuf,
}
impl WizardInput {
    fn check_source(&self) -> Result<(), Error> {
        if range_targets(&self.range_spec, &self.own_ips)? != self.range_targets {
            return Err(Error::Scope);
        }
        use sha2::{Digest, Sha256};
        if self.source.is_none() {
            if self.grants.len() != 1 || !config::valid_id(&self.grants[0]) {
                return Err(Error::Grant);
            }
            new_health_path(&self.config)?;
            if !self.config.parent().is_some_and(Path::is_dir)
                || self.health.parent().is_none_or(|p| p.exists())
            {
                return Err(Error::Storage);
            }
            validate_paths(&self.health, &self.bundle)?;
            return new_health_path(&self.health);
        }
        let raw = config::editor_bytes(&self.config).map_err(|_| Error::Storage)?;
        let actual: [u8; 32] = Sha256::digest(&raw).into();
        if Some(actual) != self.source {
            return Err(Error::Approval);
        }
        let Config::Server(doc) =
            config::parse(std::str::from_utf8(&raw).map_err(|_| Error::Format)?)
                .map_err(|_| Error::Format)?
        else {
            return Err(Error::Format);
        };
        if doc.server.inbounds.iter().any(|i| i.id == self.id)
            || self.grants.is_empty()
            || self
                .grants
                .iter()
                .any(|id| !doc.server.users.iter().any(|u| u.id == *id && !u.disabled))
        {
            return Err(Error::Grant);
        }
        // Reject collisions with saved listeners before any consented work
        // or material creation. Wildcards may overlap both address families.
        for inbound in &doc.server.inbounds {
            for address in [&inbound.h2_listen, &inbound.quic_listen] {
                let existing: SocketAddr = address.parse().map_err(|_| Error::Scope)?;
                if existing.port() == self.listen.port()
                    && (existing.ip() == self.listen.ip()
                        || existing.ip().is_unspecified()
                        || self.listen.ip().is_unspecified())
                {
                    return Err(Error::Scope);
                }
            }
        }
        if self.health.parent().is_none_or(|p| p.exists()) {
            return Err(Error::Storage);
        }
        validate_paths(&self.health, &self.bundle)?;
        new_health_path(&self.health)?;
        Ok(())
    }
    fn parse(
        config: PathBuf,
        source: Option<[u8; 32]>,
        fields: &[String; 8],
    ) -> Result<Self, Error> {
        if !config::valid_id(&fields[0]) {
            return Err(Error::Scope);
        }
        let listen: SocketAddr = match fields[1].parse::<u16>() {
            Ok(port) => SocketAddr::from(([0, 0, 0, 0], port)),
            Err(_) => fields[1].parse().map_err(|_| Error::Scope)?,
        };
        if listen.port() == 0 {
            return Err(Error::Scope);
        }
        let endpoint = format!("{}:{}", fields[2], listen.port());
        if !config::valid_remote(&endpoint) {
            return Err(Error::Scope);
        }
        let own_ips = fields[3]
            .split(',')
            .map(|s| s.trim().parse::<IpAddr>().map_err(|_| Error::Scope))
            .collect::<Result<Vec<_>, _>>()?;
        if own_ips.is_empty() || own_ips.len() > 64 {
            return Err(Error::Scope);
        }
        let automatic = match fields[6].as_str() {
            "auto" => true,
            "manual" => false,
            _ => return Err(Error::Format),
        };
        let mut candidates = Vec::new();
        let mut add = |name: &str, address: Option<IpAddr>| -> Result<(), Error> {
            crate::camouflage_domain_dns::validate_manual_dns_request(
                name,
                crate::camouflage_domain_dns::DnsConsent::Approved,
            )
            .map_err(|_| Error::Scope)?;
            if candidates
                .iter()
                .any(|(prior, _): &(String, Option<IpAddr>)| prior == name)
            {
                return Err(Error::Scope);
            }
            candidates.push((name.to_owned(), address));
            Ok(())
        };
        if !fields[4].trim().is_empty() {
            for item in fields[4].split(',').map(str::trim) {
                if item == "catalog" {
                    if !automatic {
                        return Err(Error::Scope);
                    }
                    for domain in crate::camouflage_discovery::POPULAR_HTTPS_DOMAINS {
                        add(domain, None)?;
                    }
                    continue;
                }
                let (name, address) = if let Some((name, ip)) = item.split_once('=') {
                    (name, Some(ip.parse::<IpAddr>().map_err(|_| Error::Scope)?))
                } else {
                    (item, None)
                };
                add(name, address)?;
            }
        }
        let range_spec = fields[7].trim().to_owned();
        let range_targets = range_targets(&range_spec, &own_ips)?;
        if candidates.len() > MAX_DOMAIN_SEEDS
            || candidates.len() + range_targets.len() > reference_health::MAX_SEARCH_TARGETS
            || (candidates.is_empty() && range_targets.is_empty())
            || (!automatic && (candidates.len() > 3 || !range_targets.is_empty()))
        {
            return Err(Error::Scope);
        }
        let grants: Vec<String> = fields[5].split(',').map(|v| v.trim().to_owned()).collect();
        if grants.len() > 256
            || grants.iter().any(|v| !config::valid_id(v))
            || grants
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != grants.len()
        {
            return Err(Error::Grant);
        }
        let parent = config.parent().ok_or(Error::Storage)?;
        let root = parent.join(format!(".theia-{}-material", fields[0]));
        let health = root.join("health.toml");
        let bundle = root.join("bundle");
        let input = Self {
            config,
            source,
            id: fields[0].clone(),
            listen,
            endpoint,
            own_ips,
            candidates,
            range_spec,
            range_targets,
            grants,
            automatic,
            health,
            bundle,
        };
        input.check_source()?;
        Ok(input)
    }
    fn plan_document(&self, references: Vec<reference_health::Target>) -> reference_health::Plan {
        reference_health::Plan {
            schema_version: 1,
            inbound: self.id.clone(),
            endpoint: self.endpoint.clone(),
            own_ips: self.own_ips.clone(),
            references,
        }
    }

    fn plan(
        &self,
        references: Vec<reference_health::Target>,
    ) -> Result<reference_health::Plan, Error> {
        let plan = self.plan_document(references);
        plan.digest().map_err(|_| Error::Health)?;
        Ok(plan)
    }

    fn search_plan(
        &self,
        targets: Vec<reference_health::Target>,
    ) -> Result<reference_health::SearchPlan, Error> {
        reference_health::SearchPlan::new(self.plan_document(targets)).map_err(|_| Error::Health)
    }

    fn seed_count(&self) -> usize {
        self.candidates.len() + self.range_targets.len()
    }

    async fn resolve(&self, progress: &AtomicUsize) -> Result<ResolvedSearch, Error> {
        let seeds: Vec<_> = self
            .candidates
            .iter()
            .cloned()
            .map(|(name, ip)| SearchSeed::Domain(name, ip))
            .chain(
                self.range_targets
                    .iter()
                    .cloned()
                    .map(|(ip, name)| SearchSeed::Range(ip, name)),
            )
            .collect();
        let mut references = Vec::new();
        let mut unresolved = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for group in seeds.chunks(DNS_PARALLELISM) {
            let mut tasks = tokio::task::JoinSet::new();
            for (index, seed) in group.iter().cloned().enumerate() {
                tasks.spawn(async move { (index, resolve_seed(seed).await) });
            }
            let mut completed = Vec::new();
            while let Some(result) = tasks.join_next().await {
                completed.push(result.map_err(|_| Error::Health)?);
                progress.fetch_add(1, Ordering::Relaxed);
            }
            completed.sort_by_key(|(index, _)| *index);
            for (_, result) in completed {
                let (name, mut ips, address) = result;
                ips.sort();
                let target = ips
                    .into_iter()
                    .map(|ip| reference_health::Target {
                        server_name: name.clone(),
                        address: SocketAddr::new(ip, 443),
                    })
                    .find(|target| self.search_plan(vec![target.clone()]).is_ok());
                if let Some(target) = target {
                    if seen.insert((target.server_name.clone(), target.address)) {
                        references.push(target);
                    }
                } else {
                    unresolved.push(crate::tui_widgets::ReferenceRow {
                        name,
                        address,
                        score: 0,
                        h2: false,
                        h3: false,
                        selected: None,
                    });
                }
            }
        }
        let plan = if references.is_empty() {
            None
        } else {
            Some(self.search_plan(references)?)
        };
        Ok(ResolvedSearch { plan, unresolved })
    }
}

type RangeTargets = Vec<(IpAddr, Option<String>)>;

fn range_targets(raw: &str, own_ips: &[IpAddr]) -> Result<RangeTargets, Error> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let native =
        crate::camouflage_interfaces::collect_assigned_interfaces().map_err(|_| Error::Scope)?;
    range_targets_for_snapshot(raw, own_ips, &native.server_snapshot())
}

// Offline expansion reuses the existing assigned-interface scope gate.
// No implied permission from provider prefix, public egress or DNS answers.
fn range_targets_for_snapshot(
    raw: &str,
    own_ips: &[IpAddr],
    snapshot: &crate::camouflage_discovery::ServerSnapshot,
) -> Result<RangeTargets, Error> {
    use crate::camouflage_discovery::{
        build_plan, CandidateHost, CandidateSource, NetworkPrefix, Warning,
    };
    let mut targets: RangeTargets = Vec::new();
    if raw.split(',').count() > MAX_RANGES {
        return Err(Error::Scope);
    }
    for item in raw.split(',').map(str::trim) {
        let (name, prefix) = if let Some((name, prefix)) = item.split_once('@') {
            crate::camouflage_domain_dns::validate_manual_dns_request(
                name,
                crate::camouflage_domain_dns::DnsConsent::Approved,
            )
            .map_err(|_| Error::Scope)?;
            (Some(name.to_owned()), prefix)
        } else {
            (None, item)
        };
        let prefix: NetworkPrefix = prefix.parse().map_err(|_| Error::Scope)?;
        let plan = build_plan(snapshot, &[prefix]);
        if plan.warnings.iter().any(|warning| {
            matches!(
                warning,
                Warning::RangeNotOnServer
                    | Warning::RangeTooBroad
                    | Warning::RangeExceedsAssignedPrefix
                    | Warning::Ipv6EnumerationUnsupported
                    | Warning::CandidateLimitReached
            )
        }) {
            return Err(Error::Scope);
        }
        let mut found = false;
        for candidate in plan.candidates {
            if candidate.source != CandidateSource::AuthorizedSubnet {
                continue;
            }
            let CandidateHost::Ip(ip) = candidate.host else {
                continue;
            };
            if own_ips.contains(&ip) {
                continue;
            }
            found = true;
            if let Some((_, previous)) = targets.iter().find(|(address, _)| *address == ip) {
                if previous != &name {
                    return Err(Error::Scope);
                }
                continue;
            }
            targets.push((ip, name.clone()));
            if targets.len() > MAX_RANGE_IPS {
                return Err(Error::Scope);
            }
        }
        if !found {
            return Err(Error::Scope);
        }
    }
    Ok(targets)
}

#[derive(Clone)]
enum SearchSeed {
    Domain(String, Option<IpAddr>),
    Range(IpAddr, Option<String>),
}

struct ResolvedSearch {
    plan: Option<reference_health::SearchPlan>,
    unresolved: Vec<crate::tui_widgets::ReferenceRow>,
}

async fn resolve_seed(seed: SearchSeed) -> (String, Vec<IpAddr>, String) {
    use crate::camouflage_domain_dns::{resolve_manual_domain, DnsConsent};
    match seed {
        SearchSeed::Domain(name, Some(ip)) => (name, vec![ip], ip.to_string()),
        SearchSeed::Domain(name, None) => {
            let ips = resolve_manual_domain(&name, DnsConsent::Approved)
                .await
                .unwrap_or_default();
            (name, ips, "DNS не подтверждён".into())
        }
        SearchSeed::Range(ip, name) => {
            let name = match name {
                Some(name) => Some(name),
                None => crate::camouflage_interfaces::reverse_reference_name(ip).await,
            };
            let Some(name) = name else {
                return ("PTR/SNI не найден".into(), Vec::new(), ip.to_string());
            };
            // A reverse name is only a hint. No TLS connection is scheduled
            // unless the same public IP is present in the forward DNS result.
            let ips = resolve_manual_domain(&name, DnsConsent::Approved)
                .await
                .ok()
                .filter(|ips| ips.contains(&ip))
                .map(|_| vec![ip])
                .unwrap_or_default();
            (name, ips, ip.to_string())
        }
    }
}
/// Publish a first-run configuration only after an explicit reviewed save.
fn create_first_server(
    input: WizardInput,
    state: reference_health::State,
) -> Result<Editor, Error> {
    input.check_source()?;
    let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
    let preview = reality_provision::preview(&state, now)?;
    let mut owned = crate::tui_staged_material::StagedMaterial::create_for_new_config(
        input.health.parent().ok_or(Error::Storage)?,
        &input.config,
    )?;
    let enrolled = reference_health::Store::new(&input.health).and_then(|s| s.enroll(&state));
    if let Err(error) = enrolled {
        if matches!(error, reference_health::Error::Indeterminate) {
            owned.preserve();
            return Err(Error::Indeterminate);
        }
        owned.cleanup()?;
        return Err(Error::Storage);
    }
    let record = match reality_provision::create(&state, preview.health_sha256, &input.bundle, now)
    {
        Ok(record) => record,
        Err(Error::Indeterminate) => {
            owned.preserve();
            return Err(Error::Indeterminate);
        }
        Err(error) => {
            owned.cleanup()?;
            return Err(error);
        }
    };
    let request = ServerRequest {
        health: input.health,
        bundle: input.bundle,
        health_sha256: preview.health_sha256,
        identity_sha256: record.identity_sha256,
        listen: input.listen,
        grants: input.grants,
    };
    let candidate = match reality_config::first_server_candidate(&request, now) {
        Ok(candidate) => candidate,
        Err(error) => {
            owned.cleanup()?;
            return Err(error);
        }
    };
    match config::guarded_create(&input.config, &candidate) {
        Ok(()) => owned.preserve(),
        Err(config::WriteFailure::BeforeReplace(_)) => {
            owned.cleanup()?;
            return Err(Error::Storage);
        }
        Err(config::WriteFailure::AfterReplace(_)) => {
            owned.preserve();
            return Err(Error::Indeterminate);
        }
    }
    Editor::load(Role::Server, &input.config).map_err(|_| Error::Indeterminate)
}

#[derive(Clone)]
struct RankedReview {
    text: String,
    rows: Vec<crate::tui_widgets::ReferenceRow>,
}

fn rank_checked(
    input: &WizardInput,
    targets: Vec<reference_health::Target>,
    evidence: Vec<reference_health::Evidence>,
    now: u64,
    mut unresolved: Vec<crate::tui_widgets::ReferenceRow>,
) -> Result<(Option<reference_health::State>, RankedReview), Error> {
    if targets.len() != evidence.len() {
        return Err(Error::Health);
    }
    let mut entries: Vec<_> = targets.into_iter().zip(evidence).collect();
    let mut rows: Vec<_> = entries
        .iter()
        .map(|(target, item)| crate::tui_widgets::ReferenceRow {
            name: target.server_name.clone(),
            address: target.address.to_string(),
            score: item.score(),
            h2: item.eligible(),
            h3: item.h3(),
            selected: None,
        })
        .collect();
    let unresolved_count = unresolved.len();
    rows.append(&mut unresolved);
    let mut chosen = Vec::new();
    let mut observations = Vec::new();
    if input.automatic {
        entries.sort_by_key(|(_, item)| std::cmp::Reverse(item.score()));
        for (target, item) in entries {
            if !item.eligible() {
                continue;
            }
            let mut trial = chosen.clone();
            trial.push(target);
            // The persistent contract retains only 3 distinct names and pins.
            if input.plan(trial.clone()).is_ok() {
                chosen = trial;
                observations.push(item);
            }
            if chosen.len() == 3 {
                break;
            }
        }
    } else if unresolved_count == 0 && entries.iter().all(|(_, item)| item.eligible()) {
        (chosen, observations) = entries.into_iter().unzip();
    }
    let state = if chosen.is_empty() {
        None
    } else {
        input
            .plan(chosen)
            .ok()
            .and_then(|plan| reference_health::State::new(plan, observations, now).ok())
    };
    let mut report = format!(
        "Кандидатов: {} · DNS/PTR не подтверждено: {}.\nОценки: 100 = стабильные H2+H3, 80 = стабильный H2, 0 = отказ.\n",
        rows.len(), unresolved_count,
    );
    if let Some(state) = &state {
        for (index, target) in state.plan().references.iter().enumerate() {
            if let Some(row) = rows.iter_mut().find(|row| {
                row.name == target.server_name && row.address == target.address.to_string()
            }) {
                row.selected = Some(index);
            }
        }
    }
    rows.sort_by_key(|row| {
        (
            row.selected.unwrap_or(usize::MAX),
            std::cmp::Reverse(row.score),
        )
    });
    for row in &rows {
        report.push_str(&format!(
            "{} {} · H2={} H3={} · {}\n",
            row.name, row.address, row.h2, row.h3, row.score
        ));
    }
    if state.is_some() {
        report.push_str(&format!("\nСервер: {}\nПорт: {}\nПользователи: {}\nСоздать защищённые материалы? Сервер не будет запущен.\ny: создать; n/Esc: назад.",
            input.endpoint, input.listen.port(), input.grants.join(", ")));
    } else {
        report.push_str("\nНет допустимого набора референсов. Ничего не сохранено. Esc: изменить источники и повторить.");
    }
    Ok((state, RankedReview { text: report, rows }))
}

/// Replace provisional measurements only for the exact pins rechecked in the
/// final small batch. Other candidates are screening observations, never
/// silently promoted after that batch.
fn merge_rechecked(screen: &mut RankedReview, fresh: RankedReview) {
    for row in &mut screen.rows {
        row.selected = None;
        if let Some(rechecked) = fresh
            .rows
            .iter()
            .find(|fresh| fresh.name == row.name && fresh.address == row.address)
        {
            *row = rechecked.clone();
        }
    }
    screen.rows.sort_by_key(|row| {
        (
            row.selected.unwrap_or(usize::MAX),
            std::cmp::Reverse(row.score),
        )
    });
    screen.text = format!("Общий поиск: {} кандидатов. Повторно проверены выбранные точные адреса. Остальные оценки предварительные.\n", screen.rows.len());
    for row in &screen.rows {
        screen.text.push_str(&format!(
            "{} {} · H2={} H3={} · {}\n",
            row.name, row.address, row.h2, row.h3, row.score
        ));
    }
    screen.text.push_str(&fresh.text);
}

async fn screen_and_recheck(
    input: &WizardInput,
    resolved: ResolvedSearch,
    progress: &AtomicUsize,
    recheck_done: &AtomicUsize,
    recheck_total: &AtomicUsize,
) -> Result<(Option<reference_health::State>, RankedReview), Error> {
    let plan = resolved.plan.ok_or(Error::Health)?;
    let approved = plan.digest().map_err(|_| Error::Health)?;
    let evidence = reference_health::check_search(&plan, approved, progress)
        .await
        .map_err(|_| Error::Health)?;
    let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
    let (screen_state, mut report) = rank_checked(
        input,
        plan.into_targets(),
        evidence,
        now,
        resolved.unresolved,
    )?;
    let Some(screen_state) = screen_state else {
        return Ok((None, report));
    };
    // Screening may take minutes. Its earliest observations must not be
    // stamped with the end time of the full search for provisioning.
    let selected = screen_state.plan().references.clone();
    let final_plan = input.search_plan(selected.clone())?;
    let approved = final_plan.digest().map_err(|_| Error::Health)?;
    let started = reference_health::unix_now().map_err(|_| Error::Clock)?;
    recheck_total.store(selected.len(), Ordering::Relaxed);
    let evidence = tokio::time::timeout(
        std::time::Duration::from_secs(55),
        reference_health::check_search(&final_plan, approved, recheck_done),
    )
    .await
    .map_err(|_| Error::Health)?
    .map_err(|_| Error::Health)?;
    let (state, fresh) = rank_checked(input, selected, evidence, started, Vec::new())?;
    merge_rechecked(&mut report, fresh);
    let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
    if let Some(state) = &state {
        state.provisioning_ready(now).map_err(|_| Error::Health)?;
    }
    Ok((state, report))
}

type CheckResult = Result<(WizardInput, Option<reference_health::State>, RankedReview), Error>;

enum WizardStage {
    Input,
    DnsConfirm(Box<WizardInput>),
    Resolving(
        Receiver<Result<(WizardInput, ResolvedSearch), Error>>,
        tokio::sync::oneshot::Sender<()>,
    ),
    ProbeConfirm(Box<(WizardInput, ResolvedSearch)>),
    Checking(Receiver<CheckResult>, tokio::sync::oneshot::Sender<()>),
    CreateConfirm(Box<(WizardInput, reference_health::State, RankedReview)>),
    NoEligible(RankedReview),
    Saving(Receiver<Result<RegistrationPanel, Error>>, PathBuf),
    SavingInitial(Receiver<Result<Editor, Error>>, PathBuf),
    SaveFailed {
        root: PathBuf,
        message: String,
        retry: bool,
        inspected: bool,
    },
    Success,
}
fn path_observation(path: &Path) -> &'static str {
    match std::fs::symlink_metadata(path) {
        Ok(_) => "существует; содержимое не проверено",
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "не найден",
        Err(_) => "не удалось проверить",
    }
}

fn save_failed(root: PathBuf, error: Option<Error>) -> WizardStage {
    let retry = error
        .as_ref()
        .is_some_and(|error| !matches!(error, Error::Indeterminate | Error::Approval));
    let message = if retry {
        "Не удалось сохранить настройки. Проверьте права на папку и свободное место. Повтор возможен только после проверки исходного файла и отсутствия незавершённых материалов."
    } else if matches!(error, Some(Error::Approval)) {
        "Исходная конфигурация изменилась. Откройте её заново перед новой попыткой."
    } else {
        "Запись не подтверждена. Проверьте файлы, затем откройте конфигурацию заново. Автоматический повтор запрещён."
    };
    WizardStage::SaveFailed {
        root,
        message: message.into(),
        retry,
        inspected: false,
    }
}

fn progress_text(label: &str, done: usize, total: usize) -> String {
    let done = done.min(total);
    let filled = done.saturating_mul(24).checked_div(total).unwrap_or(0);
    let percent = done.saturating_mul(100).checked_div(total).unwrap_or(0);
    format!(
        "{label}\n[{}{}] {percent}% · {done} из {total}\nНастройки не изменяются.",
        "█".repeat(filled),
        "░".repeat(24 - filled)
    )
}

struct DomainDraft {
    rows: Vec<String>,
    focus: usize,
    error: String,
}

impl DomainDraft {
    fn new(value: &str) -> Self {
        let mut rows: Vec<_> = value.split(',').map(str::to_owned).collect();
        if rows.is_empty() {
            rows.push(String::new());
        }
        Self {
            rows,
            focus: 0,
            error: String::new(),
        }
    }
    fn value(&self) -> String {
        self.rows
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(",")
    }
    fn paste(&mut self, text: &str) {
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        if normalized.chars().any(|ch| ch.is_control() && ch != '\n') {
            return;
        }
        let mut next = self.rows.clone();
        let mut focus = self.focus;
        for (i, line) in normalized.split([',', '\n']).enumerate() {
            if i == 0 {
                next[focus].push_str(line.trim());
            } else {
                focus += 1;
                next.insert(focus, line.trim().to_owned());
            }
        }
        if next.len() <= 80 && next.join(",").len() <= LIMIT {
            self.rows = next;
            self.focus = focus;
            self.error.clear();
        } else {
            self.error = "Слишком длинный список: до 80 строк и 1024 байт.".into();
        }
    }
}

struct GrantPicker {
    selected: Vec<bool>,
    focus: usize,
}

struct Wizard {
    config: PathBuf,
    source: Option<[u8; 32]>,
    fields: [String; 8],
    focus: usize,
    advanced: bool,
    sources: bool,
    catalogue: bool,
    custom_enabled: bool,
    ranges_enabled: bool,
    dns_details: bool,
    tls_details: bool,
    result_details: bool,
    recheck_done: Arc<AtomicUsize>,
    recheck_total: Arc<AtomicUsize>,
    suggested_ip: Option<String>,
    users: String,
    available_users: Vec<String>,
    grant_picker: Option<GrantPicker>,
    domain_draft: Option<DomainDraft>,
    progress: Arc<AtomicUsize>,
    total: usize,
    stage: WizardStage,
    error: String,
    registration: Option<RegistrationPanel>,
}
impl Wizard {
    fn new(editor: &Editor) -> Result<Self, &'static str> {
        editor.require_clean_records()?;
        if editor.role() != Role::Server {
            return Err("Требуется серверная конфигурация.");
        }
        let config =
            std::path::absolute(editor.saved_path()).map_err(|_| "Недопустимый путь TOML.")?;
        let id = crate::tui_editor::generated_id("inbound")?;
        Ok(Self {
            config,
            source: Some(editor.saved_sha256()),
            fields: [
                id,
                "443".into(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                "auto".into(),
                String::new(),
            ],
            focus: 2,
            advanced: false,
            sources: false,
            catalogue: true,
            custom_enabled: false,
            ranges_enabled: false,
            dns_details: false,
            tls_details: false,
            result_details: false,
            recheck_done: Arc::new(AtomicUsize::new(0)),
            recheck_total: Arc::new(AtomicUsize::new(0)),
            suggested_ip: None,
            users: editor
                .record_user_catalog(crate::tui_editor::RecordAction::NewInbound)
                .unwrap_or_default(),
            available_users: editor
                .workspace_users()
                .into_iter()
                .filter_map(|(id, disabled, _)| (!disabled).then_some(id))
                .collect(),
            grant_picker: None,
            domain_draft: None,
            progress: Arc::new(AtomicUsize::new(0)),
            total: 0,
            stage: WizardStage::Input,
            error: String::new(),
            registration: None,
        })
    }
    fn first(path: PathBuf) -> Result<Self, &'static str> {
        let config = std::path::absolute(path).map_err(|_| "Недопустимый путь TOML.")?;
        if !crate::bounded_input::explicit_file_path(&config)
            || new_health_path(&config).is_err()
            || !config.parent().is_some_and(Path::is_dir)
        {
            return Err("Укажите новый TOML в существующем каталоге.");
        }
        Ok(Self {
            config,
            source: None,
            fields: [
                crate::tui_editor::generated_id("inbound")?,
                "443".into(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                "auto".into(),
                String::new(),
            ],
            focus: 2,
            advanced: false,
            sources: false,
            catalogue: true,
            custom_enabled: false,
            ranges_enabled: false,
            dns_details: false,
            tls_details: false,
            result_details: false,
            recheck_done: Arc::new(AtomicUsize::new(0)),
            recheck_total: Arc::new(AtomicUsize::new(0)),
            suggested_ip: None,
            users: "Введите ID первого пользователя. Он будет отключён до явного выпуска токена."
                .into(),
            available_users: Vec::new(),
            grant_picker: None,
            domain_draft: None,
            progress: Arc::new(AtomicUsize::new(0)),
            total: 0,
            stage: WizardStage::Input,
            error: String::new(),
            registration: None,
        })
    }
    // A literal endpoint can be copied to the own-address field. Never
    // infer public ownership from a local interface or provider range.
    fn suggest_own_ip(&mut self) {
        let still_suggested = self
            .suggested_ip
            .as_ref()
            .is_some_and(|value| value == &self.fields[3]);
        if self.fields[3].trim().is_empty() || still_suggested {
            self.suggested_ip = self.fields[2]
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .ok()
                .map(|ip| ip.to_string());
            self.fields[3] = self.suggested_ip.clone().unwrap_or_default();
        }
    }

    fn catalogue_enabled(&self) -> bool {
        self.catalogue
    }

    fn custom_domains(&self) -> String {
        self.fields[4].clone()
    }

    fn effective_fields(&self) -> [String; 8] {
        let mut fields = self.fields.clone();
        if !self.custom_enabled {
            fields[4].clear();
        }
        if self.catalogue {
            fields[4] = if fields[4].is_empty() {
                "catalog".into()
            } else {
                format!("catalog,{}", fields[4])
            };
        }
        if !self.ranges_enabled {
            fields[7].clear();
        }
        fields
    }

    fn endpoint_is_ip(&self) -> bool {
        self.fields[2]
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok()
    }

    fn display_value(&self, id: usize) -> String {
        match id {
            8 => format!(
                "Сайтов в каталоге: {} · рекомендуется",
                crate::camouflage_discovery::POPULAR_HTTPS_DOMAINS.len()
            ),
            9 => "Дополнительные имена сайтов".into(),
            10 => "Только сети, которые разрешено проверять".into(),
            4 => self.custom_domains(),
            6 => {
                if self.fields[6] == "auto" {
                    "Автоматически (рекомендуется)".into()
                } else {
                    "Ручной порядок".into()
                }
            }
            5 if self.source.is_some() && self.available_users.is_empty() => {
                "Нет активных пользователей".into()
            }
            5 if self.source.is_some() && self.fields[5].is_empty() => {
                "Никто не выбран · открыть список".into()
            }
            5 if self.source.is_some() => format!("{} · изменить выбор", self.fields[5]),
            _ => self.fields[id].clone(),
        }
    }

    fn editable(&self) -> bool {
        self.focus < self.fields.len()
            && self.focus != 6
            && !(self.focus == 5 && self.source.is_some())
    }

    fn edit_value(&self) -> String {
        if self.focus == 4 {
            self.custom_domains()
        } else {
            self.fields[self.focus].clone()
        }
    }

    fn put_value(&mut self, value: String) {
        if self.focus == 3 {
            self.suggested_ip = None;
        }
        self.fields[self.focus] = value;
        self.error.clear();
    }

    fn open_grants(&mut self) {
        if !self.available_users.is_empty() {
            self.grant_picker = Some(GrantPicker {
                selected: self
                    .available_users
                    .iter()
                    .map(|id| self.fields[5].split(',').any(|s| s.trim() == id))
                    .collect(),
                focus: 0,
            });
        }
    }

    fn source_error(&self) -> Option<(usize, &'static str)> {
        let fields = self.effective_fields();
        if self.custom_enabled && self.custom_domains().trim().is_empty() {
            return Some((
                4,
                "Введите хотя бы одно имя сайта или выключите этот источник.",
            ));
        }
        if self.custom_enabled && self.fields[4].split(',').any(|v| v.trim() == "catalog") {
            return Some((
                4,
                "Введите настоящее имя сайта. Готовый каталог включается отдельным переключателем.",
            ));
        }
        if self.ranges_enabled && fields[7].trim().is_empty() {
            return Some((
                7,
                "Введите разрешённый диапазон или выключите этот источник.",
            ));
        }
        if fields[4].trim().is_empty() && fields[7].trim().is_empty() {
            return Some((8, "Выберите хотя бы один источник: каталог, свои домены или разрешённые IP-диапазоны."));
        }
        if fields[6] == "manual"
            && (self.catalogue_enabled()
                || !fields[7].trim().is_empty()
                || fields[4].split(',').count() > 3)
        {
            return Some((6, "Ручной порядок: только 1–3 своих домена без каталога и IP-диапазонов. Выберите автоматический подбор."));
        }
        for item in fields[4]
            .split(',')
            .filter(|s| !s.trim().is_empty() && s.trim() != "catalog")
        {
            let item = item.trim();
            let (name, pin) = item
                .split_once('=')
                .map_or((item, None), |(name, pin)| (name, Some(pin)));
            if crate::camouflage_domain_dns::validate_manual_dns_request(
                name,
                crate::camouflage_domain_dns::DnsConsent::Approved,
            )
            .is_err()
                || pin.is_some_and(|pin| pin.parse::<IpAddr>().is_err())
            {
                return Some((4, "Введите имя сайта без https://, пути и порта. Несколько имён разделяйте запятыми."));
            }
        }
        if !fields[7].trim().is_empty() {
            let own: Vec<IpAddr> = self.fields[3]
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if range_targets(&fields[7], &own).is_err() {
                return Some((7, "Диапазон не принят. Укажите разрешённую назначенную публичную IPv4-подсеть (до 32 дополнительных IP) или оставьте поле пустым."));
            }
        }
        None
    }

    fn explain_error(error: Error) -> &'static str {
        match error {
            Error::Format => "Проверьте формат параметров.",
            Error::Scope => "Проверьте адрес, порт, имена сайтов и разрешённые диапазоны. Порт не должен пересекаться с другим подключением.",
            Error::Approval => "Конфигурация изменилась. Закройте мастер, откройте сохранённую конфигурацию и повторите.",
            Error::Grant => "Выберите действующего пользователя. Для первого сервера укажите имя нового пользователя.",
            Error::Health => "Не удалось завершить проверку сайтов. Проверьте доступ сервера к интернету, DNS и HTTPS.",
            Error::Clock => "Проверьте дату и время сервера.",
            Error::Storage => "Не удалось подготовить файлы. Проверьте права, путь и свободное место.",
            Error::Indeterminate => "Результат записи неизвестен. Проверьте файлы и конфигурацию перед повтором.",
            _ => "Проверка безопасности не пройдена. Настройки не применены.",
        }
    }

    /// Explain common form mistakes before the shared validator; never replace it.
    fn basic_error(&self) -> Option<(usize, &'static str)> {
        let port = self.fields[1]
            .parse::<u16>()
            .ok()
            .or_else(|| self.fields[1].parse::<SocketAddr>().ok().map(|a| a.port()));
        if port.is_none_or(|p| p == 0) {
            return Some((1, "Укажите порт от 1 до 65535. Обычно подходит 443."));
        }
        let endpoint = format!("{}:{}", self.fields[2], port.unwrap_or(443));
        if !config::valid_remote(&endpoint) {
            return Some((2, "Введите публичный IP или домен вашего сервера без https:// и без порта. Для IPv6 используйте квадратные скобки."));
        }
        if self.fields[3]
            .split(',')
            .any(|v| v.trim().parse::<IpAddr>().is_err())
        {
            return Some((3, "Введите IP вашего сервера. Если их несколько, разделите запятыми. Не вводите домены или адреса сторонних сайтов."));
        }
        let own: Vec<IpAddr> = self.fields[3]
            .split(',')
            .filter_map(|v| v.trim().parse().ok())
            .collect();
        if let Ok(ip) = self.fields[2].trim_matches(['[', ']']).parse::<IpAddr>() {
            if !own.contains(&ip) {
                return Some((
                    3,
                    "Добавьте IP из адреса для клиентов в список собственных IP сервера.",
                ));
            }
        }
        if own.len() != own.iter().collect::<std::collections::HashSet<_>>().len() {
            return Some((3, "Один IP указан несколько раз. Удалите повторения."));
        }
        if self.fields[5].trim().is_empty() {
            return Some((
                5,
                if self.source.is_none() {
                    "Придумайте имя первого пользователя, например phone. Доступ появится только после выдачи приглашения."
                } else {
                    "Выберите хотя бы одного активного пользователя. Enter на поле открывает список. Если пользователей нет, создайте пользователя отдельно."
                },
            ));
        }
        if self.source.is_some() && self.available_users.is_empty() {
            return Some((5, "Нет активных пользователей. Вернитесь к списку пользователей и создайте или восстановите доступ."));
        }
        if self.source.is_none() && !config::valid_id(&self.fields[5]) {
            return Some((5,"Имя первого пользователя должно быть одним допустимым ID, например phone или laptop."));
        }
        None
    }

    fn visible_fields(&self) -> Vec<usize> {
        if !self.sources {
            let mut fields = vec![2, 1];
            if self.advanced || !self.endpoint_is_ip() && !self.fields[2].is_empty() {
                fields.push(3);
            }
            fields.push(5);
            if self.advanced {
                fields.push(0);
            }
            return fields;
        }
        let mut fields = vec![8, 9];
        if self.custom_enabled {
            fields.push(4);
        }
        fields.push(10);
        if self.ranges_enabled {
            fields.push(7);
        }
        if self.advanced {
            fields.push(6);
        }
        fields
    }
    fn toggle_source(&mut self) {
        match self.focus {
            8 => self.catalogue = !self.catalogue,
            9 => self.custom_enabled = !self.custom_enabled,
            10 => self.ranges_enabled = !self.ranges_enabled,
            _ => return,
        }
        self.error.clear();
    }

    fn move_focus(&mut self, forward: bool) {
        if self.focus == 2 {
            self.suggest_own_ip();
        }
        let fields = self.visible_fields();
        let index = fields
            .iter()
            .position(|field| *field == self.focus)
            .unwrap_or(0);
        self.focus = fields[(index + if forward { 1 } else { fields.len() - 1 }) % fields.len()];
    }
    fn paste(&mut self, text: &str) {
        if let Some(draft) = self.domain_draft.as_mut() {
            draft.paste(text);
            return;
        }
        if let Some(panel) = self.registration.as_mut() {
            panel.paste(text);
            return;
        }
        if self.grant_picker.is_none()
            && matches!(self.stage, WizardStage::Input)
            && self.editable()
        {
            let mut field = self.edit_value();
            let value = text.trim_end_matches(['\r', '\n']);
            if !value.chars().any(char::is_control)
                && field.len().saturating_add(value.len()) <= LIMIT
            {
                field.push_str(value);
                self.put_value(field);
            }
        }
    }
    fn key(&mut self, key: KeyEvent) -> bool {
        if let Some(mut draft) = self.domain_draft.take() {
            match key.code {
                KeyCode::Esc => return false,
                KeyCode::F(4) => {
                    self.fields[4] = draft.value();
                    self.error.clear();
                    return false;
                }
                KeyCode::Up | KeyCode::BackTab => draft.focus = draft.focus.saturating_sub(1),
                KeyCode::Down | KeyCode::Tab => {
                    draft.focus = (draft.focus + 1).min(draft.rows.len() - 1)
                }
                KeyCode::Enter if draft.rows.len() < 80 && draft.rows.join(",").len() < LIMIT => {
                    draft.focus += 1;
                    draft.rows.insert(draft.focus, String::new());
                }
                KeyCode::Delete if draft.rows.len() > 1 => {
                    draft.rows.remove(draft.focus);
                    draft.focus = draft.focus.min(draft.rows.len() - 1);
                }
                KeyCode::Backspace => {
                    draft.rows[draft.focus].pop();
                }
                KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                    draft.rows[draft.focus].clear()
                }
                KeyCode::Char(ch)
                    if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                        && !ch.is_control() =>
                {
                    draft.paste(&ch.to_string());
                }
                _ => {}
            }
            self.domain_draft = Some(draft);
            return false;
        }
        if let Some(panel) = self.registration.as_mut() {
            return panel.key(key);
        }
        if let Some(mut picker) = self.grant_picker.take() {
            let count = picker.selected.len();
            match key.code {
                KeyCode::Esc => return false,
                KeyCode::Enter => {
                    self.fields[5] = self
                        .available_users
                        .iter()
                        .zip(&picker.selected)
                        .filter_map(|(id, chosen)| chosen.then_some(id.as_str()))
                        .collect::<Vec<_>>()
                        .join(",");
                    self.error.clear();
                    return false;
                }
                KeyCode::Up | KeyCode::BackTab => picker.focus = (picker.focus + count - 1) % count,
                KeyCode::Down | KeyCode::Tab => picker.focus = (picker.focus + 1) % count,
                KeyCode::Home => picker.focus = 0,
                KeyCode::End => picker.focus = count - 1,
                KeyCode::Char(' ') => {
                    picker.selected[picker.focus] = !picker.selected[picker.focus]
                }
                _ => {}
            }
            self.grant_picker = Some(picker);
            return false;
        }
        let old = std::mem::replace(&mut self.stage, WizardStage::Input);
        self.stage = match old {
            WizardStage::Input => {
                match key.code {
                    KeyCode::Esc if self.sources => {
                        self.sources = false;
                        self.focus = 5;
                        self.error.clear();
                    }
                    KeyCode::Esc => return true,
                    KeyCode::F(2) => {
                        self.advanced = !self.advanced;
                        if !self.visible_fields().contains(&self.focus) {
                            self.focus = self.visible_fields()[0];
                        }
                    }
                    KeyCode::F(3) if self.focus == 3 => {
                        self.suggest_own_ip();
                        if self.fields[3].is_empty() {
                            self.error = "Укажите IP из панели хостинга.".into();
                        } else {
                            self.error.clear();
                        }
                    }
                    KeyCode::F(4) if self.sources && self.custom_enabled => {
                        self.focus = 4;
                        self.domain_draft = Some(DomainDraft::new(&self.fields[4]));
                    }
                    KeyCode::F(6) if !self.sources && self.focus == 5 => self.open_grants(),
                    KeyCode::Tab | KeyCode::Down => self.move_focus(true),
                    KeyCode::BackTab | KeyCode::Up => self.move_focus(false),
                    KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
                        if matches!(self.focus, 8..=10) =>
                    {
                        self.toggle_source()
                    }
                    KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right if self.focus == 6 => {
                        self.fields[6] = if self.fields[6] == "auto" {
                            "manual".into()
                        } else {
                            "auto".into()
                        };
                        self.error.clear();
                    }
                    KeyCode::Char(' ')
                        if !self.sources && self.focus == 5 && self.source.is_some() =>
                    {
                        self.open_grants()
                    }
                    KeyCode::Backspace if self.editable() => {
                        let mut value = self.edit_value();
                        value.pop();
                        self.put_value(value);
                    }
                    KeyCode::Char('u')
                        if key.modifiers == KeyModifiers::CONTROL && self.editable() =>
                    {
                        self.put_value(String::new())
                    }
                    KeyCode::Enter => {
                        self.suggest_own_ip();
                        if !self.sources
                            && self.focus == 5
                            && self.source.is_some()
                            && !self.available_users.is_empty()
                            && self.fields[5].is_empty()
                        {
                            self.open_grants();
                            return false;
                        }
                        if let Some((field, message)) = self.basic_error() {
                            self.sources = false;
                            self.focus = field;
                            if field == 3 {
                                self.advanced = true;
                            }
                            self.error = message.into();
                            return false;
                        }
                        if !self.sources {
                            self.sources = true;
                            self.focus = 8;
                            self.error.clear();
                            return false;
                        }
                        if let Some((field, message)) = self.source_error() {
                            self.focus = field;
                            if field == 6 {
                                self.advanced = true;
                            }
                            self.error = message.into();
                            return false;
                        }
                        match WizardInput::parse(
                            self.config.clone(),
                            self.source,
                            &self.effective_fields(),
                        ) {
                            Ok(input) => {
                                self.error.clear();
                                self.dns_details = false;
                                self.stage = WizardStage::DnsConfirm(Box::new(input));
                                return false;
                            }
                            Err(error) => self.error = Self::explain_error(error).into(),
                        }
                    }
                    KeyCode::Char(ch)
                        if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                            && !ch.is_control()
                            && self.editable() =>
                    {
                        let mut value = self.edit_value();
                        if value.len() + ch.len_utf8() <= LIMIT {
                            value.push(ch);
                            self.put_value(value);
                        }
                    }
                    _ => {}
                }
                WizardStage::Input
            }
            WizardStage::DnsConfirm(input) if key.code == KeyCode::F(2) => {
                self.dns_details = !self.dns_details;
                WizardStage::DnsConfirm(input)
            }
            WizardStage::DnsConfirm(input)
                if self.dns_details
                    && matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('n')) =>
            {
                self.dns_details = false;
                WizardStage::DnsConfirm(input)
            }
            WizardStage::DnsConfirm(input)
                if !self.dns_details
                    && key.code == KeyCode::Char('y')
                    && key.modifiers.is_empty() =>
            {
                let input = *input;
                self.total = input.seed_count();
                self.progress = Arc::new(AtomicUsize::new(0));
                let progress = Arc::clone(&self.progress);
                let (tx, rx) = mpsc::channel();
                let (cancel, cancelled) = tokio::sync::oneshot::channel();
                let _worker = std::thread::spawn(move || {
                    let result = input.check_source().and_then(|()| {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .map_err(|_| Error::Storage)?;
                        let plan = rt.block_on(async {
                            tokio::select! {
                                biased;
                                _ = cancelled => Err(Error::Health),
                                result = input.resolve(&progress) => result,
                            }
                        })?;
                        Ok((input, plan))
                    });
                    let _ = tx.send(result);
                });
                WizardStage::Resolving(rx, cancel)
            }
            WizardStage::ProbeConfirm(value) if key.code == KeyCode::F(2) => {
                self.tls_details = !self.tls_details;
                WizardStage::ProbeConfirm(value)
            }
            WizardStage::ProbeConfirm(value)
                if self.tls_details
                    && matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('n')) =>
            {
                self.tls_details = false;
                WizardStage::ProbeConfirm(value)
            }
            WizardStage::ProbeConfirm(value)
                if !self.tls_details
                    && key.code == KeyCode::Char('y')
                    && key.modifiers.is_empty() =>
            {
                let (input, resolved) = *value;
                self.total = resolved
                    .plan
                    .as_ref()
                    .map_or(0, |plan| plan.targets().len());
                self.progress = Arc::new(AtomicUsize::new(0));
                self.recheck_done = Arc::new(AtomicUsize::new(0));
                self.recheck_total = Arc::new(AtomicUsize::new(0));
                let recheck_done = Arc::clone(&self.recheck_done);
                let recheck_total = Arc::clone(&self.recheck_total);
                let progress = Arc::clone(&self.progress);
                let (tx, rx) = mpsc::channel();
                let (cancel, cancelled) = tokio::sync::oneshot::channel();
                let _worker = std::thread::spawn(move || {
                    let result = input.check_source().and_then(|()| {
                        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Error::Storage)?;
                        let (state, report) = rt.block_on(async { tokio::select! {
                            biased;
                            _ = cancelled => Err(Error::Health),
                            value = screen_and_recheck(&input, resolved, &progress, &recheck_done, &recheck_total) => value,
                        } })?;
                        Ok((input, state, report))
                    });
                    let _ = tx.send(result);
                });
                WizardStage::Checking(rx, cancel)
            }
            WizardStage::CreateConfirm(value) if key.code == KeyCode::F(2) => {
                self.result_details = !self.result_details;
                WizardStage::CreateConfirm(value)
            }
            WizardStage::CreateConfirm(value)
                if self.result_details
                    && matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('n')) =>
            {
                self.result_details = false;
                WizardStage::CreateConfirm(value)
            }
            WizardStage::NoEligible(report) if key.code == KeyCode::F(2) => {
                self.result_details = !self.result_details;
                WizardStage::NoEligible(report)
            }
            WizardStage::NoEligible(report)
                if self.result_details && matches!(key.code, KeyCode::Esc | KeyCode::Enter) =>
            {
                self.result_details = false;
                WizardStage::NoEligible(report)
            }
            WizardStage::CreateConfirm(value)
                if !self.result_details
                    && key.code == KeyCode::Char('y')
                    && key.modifiers.is_empty() =>
            {
                let (input, state, _) = *value;
                // Long review/scrolling must not turn stale evidence into a
                // save. Ask again for the same exact pins, without resuming
                // the broad discovery or modifying the saved configuration.
                let fresh = reference_health::unix_now()
                    .and_then(|now| state.provisioning_ready(now))
                    .is_ok();
                if !fresh {
                    match input.search_plan(state.plan().references.clone()) {
                        Ok(plan) => {
                            self.tls_details = false;
                            self.stage = WizardStage::ProbeConfirm(Box::new((
                                input,
                                ResolvedSearch {
                                    plan: Some(plan),
                                    unresolved: Vec::new(),
                                },
                            )));
                        }
                        Err(_) => {
                            self.error = "Результаты устарели. Повторите проверку.".into();
                            self.stage = WizardStage::Input;
                        }
                    }
                    return false;
                }
                let root = input
                    .health
                    .parent()
                    .map(Path::to_owned)
                    .unwrap_or_default();
                if input.source.is_none() {
                    let (tx, rx) = mpsc::channel();
                    let _worker = std::thread::spawn(move || {
                        let _ = tx.send(create_first_server(input, state));
                    });
                    self.stage = WizardStage::SavingInitial(rx, root);
                    return false;
                }
                let (tx, rx) = mpsc::channel();
                let _worker = std::thread::spawn(move || {
                    let result = (|| {
                        let source = input.source.ok_or(Error::Approval)?;
                        input.check_source()?;
                        let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
                        let preview = reality_provision::preview(&state, now)?;
                        let mut owned = crate::tui_staged_material::StagedMaterial::create(
                            input.health.parent().ok_or(Error::Storage)?,
                            &input.config,
                            source,
                        )?;
                        // No external reference can exist before registration.
                        // Keep an uncertain write for explicit inspection.
                        let enrolled = reference_health::Store::new(&input.health)
                            .and_then(|s| s.enroll(&state));
                        if let Err(error) = enrolled {
                            if matches!(error, reference_health::Error::Indeterminate) {
                                owned.preserve();
                                return Err(Error::Indeterminate);
                            }
                            owned.cleanup()?;
                            return Err(Error::Storage);
                        }
                        let record = match reality_provision::create(
                            &state,
                            preview.health_sha256,
                            &input.bundle,
                            now,
                        ) {
                            Ok(record) => record,
                            Err(Error::Indeterminate) => {
                                owned.preserve();
                                return Err(Error::Indeterminate);
                            }
                            Err(error) => {
                                owned.cleanup()?;
                                return Err(error);
                            }
                        };
                        let request = ServerRequest {
                            health: input.health,
                            bundle: input.bundle,
                            health_sha256: preview.health_sha256,
                            identity_sha256: record.identity_sha256,
                            listen: input.listen,
                            grants: input.grants,
                        };
                        // Validate the exact saved TOML and prepared material
                        // again before presenting a separate registration.
                        reality_config::prepare(
                            &input.config,
                            &reality_config::Request::Server(request.clone()),
                            now,
                        )?;
                        RegistrationPanel::from_provision(input.config, source, request)
                            .map(|panel| panel.own_material(owned))
                    })();
                    let _ = tx.send(result);
                });
                WizardStage::Saving(rx, root)
            }
            WizardStage::DnsConfirm(_)
            | WizardStage::ProbeConfirm(_)
            | WizardStage::CreateConfirm(_)
            | WizardStage::NoEligible(_)
                if matches!(key.code, KeyCode::Esc | KeyCode::Char('n')) =>
            {
                WizardStage::Input
            }
            WizardStage::NoEligible(_) if key.code == KeyCode::Enter => WizardStage::Input,
            WizardStage::Checking(_, cancel) if key.code == KeyCode::Esc => {
                let _ = cancel.send(());
                WizardStage::Input
            }
            WizardStage::Resolving(_, cancel) if key.code == KeyCode::Esc => {
                let _ = cancel.send(());
                WizardStage::Input
            }
            WizardStage::SaveFailed {
                root,
                message,
                retry,
                inspected,
            } => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('n') => return true,
                    KeyCode::F(2) if !inspected => {
                        // Inspection never writes, deletes or changes the saved config.
                        let config = path_observation(&self.config);
                        let material = path_observation(&root);
                        WizardStage::SaveFailed { root, message: format!("{message}\nФайл конфигурации: {config}\nКаталог материалов: {material}"), retry, inspected: true }
                    }
                    KeyCode::Char('y') if retry && key.modifiers.is_empty() => {
                        // Reconstruct the exact approved scope using the existing
                        // source/path guard. No save, DNS or TLS is triggered.
                        match WizardInput::parse(self.config.clone(), self.source, &self.effective_fields()) {
                            Ok(input) if input.health.parent() == Some(root.as_path()) => {
                                self.error.clear();
                                self.sources = true;
                                self.focus = 8;
                                WizardStage::Input
                            }
                            _ => WizardStage::SaveFailed { root, message: "Повтор заблокирован: файл, каталог или параметры изменились. Откройте конфигурацию заново.".into(), retry: false, inspected: false },
                        }
                    }
                    _ => WizardStage::SaveFailed {
                        root,
                        message,
                        retry,
                        inspected,
                    },
                }
            }
            WizardStage::Success
                if matches!(
                    key.code,
                    KeyCode::Enter | KeyCode::Esc | KeyCode::Char('y' | 'n')
                ) =>
            {
                return true
            }
            other => other,
        };
        false
    }
    fn poll(&mut self) -> Option<Editor> {
        if let Some(panel) = self.registration.as_mut() {
            if let Some(editor) = panel.poll() {
                self.registration = None;
                self.stage = WizardStage::Success;
                return Some(editor);
            }
            if let Some((root, error, saved_reload_failed)) = panel.take_wizard_failure() {
                self.registration = None;
                self.stage = if saved_reload_failed {
                    WizardStage::SaveFailed { root, message: "Настройки записаны, но открыть их не удалось. Откройте файл заново. Не повторяйте запись.".into(), retry: false, inspected: false }
                } else {
                    save_failed(root, error)
                };
            }
            return None;
        }
        let result = match &self.stage {
            WizardStage::Resolving(rx, _) => match rx.try_recv() {
                Ok(value) => value.map(|(input, resolved)| {
                    if resolved.plan.is_some() {
                        self.tls_details = false;
                        WizardStage::ProbeConfirm(Box::new((input, resolved)))
                    } else {
                        self.result_details = false;
                        WizardStage::NoEligible(RankedReview {
                            text: "DNS/PTR не подтвердил ни одного кандидата. TLS не выполнялся. Esc: назад.".into(),
                            rows: resolved.unresolved,
                        })
                    }
                }),
                Err(TryRecvError::Empty) => return None, Err(TryRecvError::Disconnected) => Err(Error::Health),
            },
            WizardStage::Checking(rx, _) => match rx.try_recv() {
                Ok(value) => value.map(|(input, state, report)| { self.result_details = false; match state {
                    Some(state) => WizardStage::CreateConfirm(Box::new((input, state, report))),
                    None => WizardStage::NoEligible(report),
                } }),
                Err(TryRecvError::Empty) => return None, Err(TryRecvError::Disconnected) => Err(Error::Health),
            },
            WizardStage::SavingInitial(rx, root) => match rx.try_recv() {
                Ok(Ok(editor)) => { self.stage = WizardStage::Success; return Some(editor); }
                Ok(Err(error)) => Ok(save_failed(root.clone(), Some(error))),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Ok(save_failed(root.clone(), None)),
            },
            WizardStage::Saving(rx, root) => match rx.try_recv() {
                Ok(Ok(panel)) => { self.registration = Some(panel); return None; }
                Ok(Err(error)) => Ok(save_failed(root.clone(), Some(error))),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Ok(save_failed(root.clone(), None)),
            },
            _ => return None,
        };
        self.stage = match result {
            Ok(stage) => stage,
            Err(error) => {
                self.error = Self::explain_error(error).into();
                WizardStage::Input
            }
        };
        None
    }
    fn body(&self) -> String {
        if let Some(panel) = &self.registration {
            return panel.body();
        }
        match &self.stage {
            WizardStage::Input => {
                let mut out = if self.sources { "ИСТОЧНИКИ ПОИСКА\n".to_owned() } else { "НАСТРОЙКА СЕРВЕРА\n".to_owned() };
                for id in self.visible_fields() {
                    let label = match id {
                        8 => "Готовый каталог сайтов",
                        9 => "Добавить свои сайты",
                        10 => "Проверить разрешённые IP-диапазоны",
                        1 => "Порт подключения",
                        2 => "Адрес сервера для клиентов",
                        3 => "IP-адреса вашего сервера",
                        4 => "Свои домены (необязательно)",
                        5 if self.source.is_none() => "Имя первого пользователя",
                        5 => "Пользователи с доступом",
                        7 => "Разрешённые IP-диапазоны",
                        _ => WIZARD_LABELS[id],
                    };
                    out.push_str(&format!("{} {label}: {}\n", if id == self.focus { ">" } else { " " }, self.display_value(id)));
                }
                if self.sources {
                    out.push_str("Готовый каталог рекомендуется. Enter: продолжить; Esc: настройки сервера.\n");
                } else {
                    out.push_str("Адрес и IP возьмите из панели хостинга. Порт обычно 443. Enter: выбрать источники.\n");
                    out.push_str(&self.users);
                }
                out.push_str("\nF2: расширенные параметры.\n");
                out.push_str(&self.error);
                out
            }
            WizardStage::DnsConfirm(input) => {
                let mut body = format!("Theia узнает сетевые адреса выбранных сайтов.\n\nСайтов: {} · IP из разрешённых диапазонов: {}\nАдрес сервера: {}\nСобственные IP (не проверяются как сайты): {}\nПроверьте, что указаны все публичные IP сервера, включая NAT.\n\nНастройки не изменятся. Соединения с сайтами и запуск сервера — позже, отдельно.", input.candidates.len(), input.range_targets.len(), input.endpoint, input.own_ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));
                if !self.dns_details {
                    body.push_str("\n\nF2: Показать полный список целей.\nВыберите «Найти адреса» для разрешения только DNS/PTR.");
                    if !input.range_targets.is_empty() {
                        body.push_str("\nПодтверждайте только диапазоны, которые разрешено проверять.");
                    }
                    return body;
                }
                body.push_str("\n\nПолный список целей DNS/PTR · F2 / Enter / Esc: свернуть.\n\nДОМЕНЫ\n");
                for (name, ip) in &input.candidates {
                    body.push_str(&format!("{name}: {}\n", ip.map_or("DNS".into(), |ip| ip.to_string())));
                }
                if !input.range_targets.is_empty() {
                    body.push_str("\nРАЗРЕШЁННЫЕ IP\n");
                    for (ip, name) in &input.range_targets {
                        body.push_str(&format!("{ip}: {}\n", name.as_deref().unwrap_or("PTR → DNS")));
                    }
                }
                body
            }
            WizardStage::Resolving(_, _) => progress_text("Фаза 1/3: поиск сетевых адресов", self.progress.load(Ordering::Relaxed), self.total),
            WizardStage::ProbeConfirm(value) => {
                let targets = value.1.plan.as_ref().map(|p| p.targets()).unwrap_or_default();
                let mut text = format!("Theia проверит защищённые соединения с выбранными сайтами.\n\nАдресов для проверки: {} · не удалось найти адрес: {}\nТолько перечисленные IP и имена, порт 443, TLS 1.3, HTTP/2 и HTTP/3.\nСверка DNS сервера и сайтов; по две проверки HTTPS HEAD без перенаправлений, ключей и тела запроса.\nНастройки не записываются. Лучшие сайты будут перепроверены.", targets.len(), value.1.unresolved.len());
                if self.tls_details {
                    text.push_str("\n\nТочные цели проверки\n");
                    for target in targets {
                        text.push_str(&format!("{} · {}\n", target.server_name, target.address));
                    }
                } else {
                    text.push_str("\n\nF2: Показать полный список адресов.");
                }
                text
            }
            WizardStage::Checking(_, _) => {
                let done = self.progress.load(Ordering::Relaxed);
                let total = self.recheck_total.load(Ordering::Relaxed);
                if total > 0 {
                    format!("✓ Адреса найдены · ✓ Первичная проверка завершена\n{}", progress_text("Фаза 3/3: повторная проверка выбранных сайтов", self.recheck_done.load(Ordering::Relaxed), total))
                } else if done >= self.total {
                    "Подбираем лучшие сайты для повторной проверки.\nНастройки не изменяются.".into()
                } else {
                    format!("✓ Адреса найдены\n{}", progress_text("Фаза 2/3: проверка защищённых соединений", done, self.total))
                }
            },
            WizardStage::NoEligible(report) => report.text.clone(),
            WizardStage::CreateConfirm(value) => {
                if value.0.source.is_none() {
                    format!("{}\nПервый TOML: {}\nПервый пользователь: {} (отключён).\ny: создать материалы и сохранить новый TOML; n/Esc: назад.", value.2.text, value.0.config.display(), value.0.grants.join(", "))
                } else {
                    value.2.text.clone()
                }
            },
            WizardStage::Saving(_, _) | WizardStage::SavingInitial(_, _) => { let phase = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() / 180 % 4) as usize; format!("{} Сохраняем защищённые файлы и настройки…\nРаботающий сервер не изменяется. Дождитесь подтверждения.", ["⠋", "⠙", "⠹", "⠸"][phase]) },
            WizardStage::SaveFailed { root, message, retry, inspected } => {
                let mut body = format!("{}\n{}\n\nСервер не запущен этой операцией.", if *retry { "Ошибка сохранения" } else { "ВНИМАНИЕ: запись не подтверждена или требуется повторное открытие" }, message);
                if *inspected { body.push_str(&format!("\n\nФайл: {}\nКаталог: {}\nПроверено только наличие, не целостность.", self.config.display(), root.display())); }
                else { body.push_str("\nF2: Проверить наличие файлов и показать пути."); }
                if *retry { body.push_str("\nПовторить настройку — вернуться к источникам без записи."); }
                else { body.push_str("\nПовтор недоступен. Откройте конфигурацию заново."); }
                body
            },
            WizardStage::Success => format!("✓ Подключение REALITY создано.\n\nАдрес: {} · Порт: {}\nПользователи: {}\nНастройки: сохранены и открыты.\nСервер: не запущен этой операцией.\n\n{}", self.fields[2], self.fields[1], self.fields[5], if self.source.is_none() { "Первый пользователь отключён до выпуска ключа.\nОткройте выпуск ключа, затем отдельно запустите сервер и импортируйте ключ в клиент." } else { "Действующие ключи не изменены. Откройте пользователей для управления доступом." }),
        }
    }
}

impl ProvisionPanel {
    pub(crate) fn new() -> Self {
        Self {
            fields: std::array::from_fn(|_| String::new()),
            focus: 0,
            stage: Stage::Input,
            error: None,
            wizard: None,
        }
    }

    pub(crate) fn first(path: PathBuf) -> Result<Self, &'static str> {
        let mut panel = Self::new();
        panel.wizard = Some(Wizard::first(path)?);
        Ok(panel)
    }

    pub(crate) fn bound(editor: &Editor) -> Result<Self, &'static str> {
        let mut panel = Self::new();
        panel.wizard = Some(Wizard::new(editor)?);
        Ok(panel)
    }

    fn paths(&self) -> (PathBuf, PathBuf, PathBuf) {
        (
            PathBuf::from(&self.fields[0]),
            PathBuf::from(&self.fields[1]),
            PathBuf::from(&self.fields[2]),
        )
    }

    pub(crate) fn paste(&mut self, text: &str) {
        if let Some(wizard) = self.wizard.as_mut() {
            wizard.paste(text);
            return;
        }
        if !matches!(self.stage, Stage::Input) {
            return;
        }
        let value = text.trim_end_matches(['\r', '\n']);
        let field = &mut self.fields[self.focus];
        if !value.chars().any(char::is_control) && field.len().saturating_add(value.len()) <= LIMIT
        {
            field.push_str(value);
        }
    }

    pub(crate) fn confirmation_choice(&self) -> Option<(char, &'static str)> {
        if let Some(wizard) = &self.wizard {
            if let Some(panel) = &wizard.registration {
                return panel.confirmation_choice();
            }
            if wizard.grant_picker.is_some() {
                return None;
            }
            return match wizard.stage {
                WizardStage::DnsConfirm(_) if !wizard.dns_details => Some(('y', "Найти адреса")),
                WizardStage::ProbeConfirm(_) if !wizard.tls_details => {
                    Some(('y', "Проверить сайты"))
                }
                WizardStage::CreateConfirm(_) if !wizard.result_details => Some(('y', "Сохранить")),
                WizardStage::SaveFailed { retry: true, .. } => Some(('y', "Повторить настройку")),
                WizardStage::Success => Some((
                    'y',
                    if wizard.source.is_none() {
                        "Выпустить ключ доступа"
                    } else {
                        "Открыть пользователей"
                    },
                )),
                _ => None,
            };
        }
        match self.stage {
            Stage::ConfirmPlan(_) => Some(('y', "Начать проверку")),
            Stage::Confirm(_) => Some(('y', "Сохранить")),
            _ => None,
        }
    }

    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        if let Some(wizard) = self.wizard.as_mut() {
            return wizard.key(key);
        }
        match &self.stage {
            Stage::Loading(_) | Stage::LoadingPlan(_) | Stage::Applying(_) => return false,
            Stage::Checking { .. } => {
                if key.code == KeyCode::Esc {
                    if let Stage::Checking { cancel, .. } =
                        std::mem::replace(&mut self.stage, Stage::Input)
                    {
                        let _ = cancel.send(());
                    }
                }
                return false;
            }
            Stage::Done(_) => return key.code == KeyCode::Esc,
            Stage::ConfirmPlan(review) => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('n') => self.stage = Stage::Input,
                    KeyCode::Char('y') if key.modifiers.is_empty() => {
                        let expected = review.digest;
                        let (health, output, plan) = self.paths();
                        let (tx, result) = mpsc::channel();
                        let (cancel, cancel_rx) = tokio::sync::oneshot::channel();
                        self.stage = Stage::Checking { result, cancel };
                        let _worker = std::thread::spawn(move || {
                            let _ =
                                tx.send(check_plan(&plan, &health, &output, expected, cancel_rx));
                        });
                    }
                    _ => {}
                }
                return false;
            }
            Stage::Confirm(_) => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('n') => {
                        self.stage = Stage::Input;
                    }
                    KeyCode::Char('y') if key.modifiers.is_empty() => {
                        let (health, output, plan) = self.paths();
                        let Stage::Confirm(review) =
                            std::mem::replace(&mut self.stage, Stage::Input)
                        else {
                            return false;
                        };
                        let (tx, rx) = mpsc::channel();
                        self.stage = Stage::Applying(rx);
                        let _worker = std::thread::spawn(move || {
                            let result = reference_health::unix_now()
                                .map_err(|_| Error::Clock)
                                .and_then(|now| {
                                    apply_checked(&plan, &health, &output, review, now)
                                });
                            let _ = tx.send(result);
                        });
                    }
                    _ => {}
                }
                return false;
            }
            Stage::Input => {}
        }
        match key.code {
            KeyCode::Esc => return true,
            KeyCode::Tab => self.focus = (self.focus + 1) % self.fields.len(),
            KeyCode::BackTab => {
                self.focus = (self.focus + self.fields.len() - 1) % self.fields.len()
            }
            KeyCode::Backspace => {
                self.fields[self.focus].pop();
            }
            KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                self.fields[self.focus].clear()
            }
            KeyCode::Enter => {
                let (health, output, plan) = self.paths();
                self.error = None;
                if plan.as_os_str().is_empty() {
                    let (tx, rx) = mpsc::channel();
                    self.stage = Stage::Loading(rx);
                    let _worker = std::thread::spawn(move || {
                        let result = reference_health::unix_now()
                            .map_err(|_| Error::Clock)
                            .and_then(|now| preview(&health, &output, now));
                        let _ = tx.send(result);
                    });
                } else {
                    let (tx, rx) = mpsc::channel();
                    self.stage = Stage::LoadingPlan(rx);
                    let _worker = std::thread::spawn(move || {
                        let _ = tx.send(plan_preview(&plan, &health, &output));
                    });
                }
            }
            KeyCode::Char(ch)
                if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                    && !ch.is_control()
                    && self.fields[self.focus].len() + ch.len_utf8() <= LIMIT =>
            {
                self.fields[self.focus].push(ch);
            }
            _ => {}
        }
        false
    }

    pub(crate) fn poll(&mut self) -> Option<Editor> {
        if let Some(wizard) = self.wizard.as_mut() {
            return wizard.poll();
        }
        let result = match &self.stage {
            Stage::Loading(rx) => match rx.try_recv() {
                Ok(result) => result.map(Stage::Confirm),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Err(Error::Storage),
            },
            Stage::LoadingPlan(rx) => match rx.try_recv() {
                Ok(result) => result.map(Stage::ConfirmPlan),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Err(Error::Storage),
            },
            Stage::Checking { result, .. } => match result.try_recv() {
                Ok(result) => result.map(Stage::Confirm),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Err(Error::Health),
            },
            Stage::Applying(rx) => match rx.try_recv() {
                Ok(result) => result.map(Stage::Done),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Err(Error::Indeterminate),
            },
            _ => return None,
        };
        match result {
            Ok(stage) => self.stage = stage,
            Err(error) => {
                let message = format!("ОТКАЗ: {error}. При частичной записи проверьте каталог; автоматическое удаление запрещено.");
                self.stage = Stage::Input;
                self.error = Some(message);
            }
        }
        None
    }

    pub(crate) fn success_first_user(&self) -> Option<&str> {
        self.wizard
            .as_ref()
            .filter(|w| matches!(w.stage, WizardStage::Success) && w.source.is_none())
            .map(|w| w.fields[5].as_str())
    }

    pub(crate) fn succeeded(&self) -> bool {
        self.wizard
            .as_ref()
            .is_some_and(|w| matches!(w.stage, WizardStage::Success))
    }

    pub(crate) fn form(&self) -> Option<crate::tui_widgets::Form> {
        use crate::tui_widgets::{Field, Form};
        let wizard = self.wizard.as_ref()?;
        if let Some(panel) = &wizard.registration {
            return panel.form();
        }
        if !matches!(wizard.stage, WizardStage::Input) {
            return None;
        }
        if let Some(draft) = &wizard.domain_draft {
            return Some(Form {
                fields: draft.rows.iter().enumerate().map(|(id, value)| Field { id, label: "Сайт", value: value.clone(), hint: "Один сайт на строку. Можно вставить список. Enter — добавить строку, Delete — удалить, F4 — принять черновик." }).collect(),
                selected: draft.focus, lead: format!("Строк: {} из 80 · Вставьте имена сайтов, по одному на строку", draft.rows.len()), error: draft.error.clone(),
            });
        }
        if let Some(picker) = &wizard.grant_picker {
            let count = picker.selected.iter().filter(|chosen| **chosen).count();
            return Some(Form {
                fields: wizard
                    .available_users
                    .iter()
                    .enumerate()
                    .map(|(id, name)| Field {
                        id,
                        label: if picker.selected[id] {
                            "[x] Доступ выбран"
                        } else {
                            "[ ] Нет доступа"
                        },
                        value: name.clone(),
                        hint: "Пробел изменить выбор · Enter перенести в черновик · Esc отменить",
                    })
                    .collect(),
                selected: picker.focus,
                lead: format!(
                    "Выбрано: {count} из {} · только активные пользователи",
                    picker.selected.len()
                ),
                error: String::new(),
            });
        }
        let first = wizard.source.is_none();
        let labels = [
            ("ID подключения", "Уникальное имя, создаётся автоматически."),
            ("Порт подключения", "Обычно 443. Порт должен быть доступен на сервере."),
            ("Адрес сервера для клиентов", "Пример: vpn.example.org · IP или домен из панели хостинга, без https:// и порта."),
            ("Все IP вашего сервера", "Пример: 203.0.113.10 · Укажите реальные IP сервера, включая публичные/NAT. Несколько через запятую."),
            ("Свои сайты", "Пример: example.org · F4 открыть многострочный редактор. Можно вставить список имён через запятую; допустимо имя=IP."),
            (if first { "Имя первого пользователя" } else { "› Пользователи с доступом" },
             if first { "Пример: user · Придумайте имя. После создания выдайте личный ключ через «Восстановить доступ»." } else { "Пробел или F6 — открыть список. Если никто не выбран, Enter откроет его. Доступ не выдаётся автоматически." }),
            ("› Порядок выбора", "Пробел — изменить. Автоматический подбор рекомендуется."),
            ("Разрешённые IP-диапазоны", "Пример: 203.0.113.8/29 · Укажите реальную назначенную публичную подсеть с разрешением. Формат CIDR или имя@CIDR."),
            (if wizard.catalogue_enabled() { "[x] Готовый каталог сайтов" } else { "[ ] Готовый каталог сайтов" }, "Пробел или ←/→ — включить или выключить. Сеть только после подтверждения."),
            (if wizard.custom_enabled { "[x] Добавить свои сайты" } else { "[ ] Добавить свои сайты" }, "Пробел или ←/→ — включить или выключить дополнительный источник."),
            (if wizard.ranges_enabled { "[x] Проверить IP-диапазоны" } else { "[ ] Проверить IP-диапазоны" }, "Пробел или ←/→ — включить или выключить. Только с разрешением."),
        ];
        Some(Form {
            fields: wizard
                .visible_fields()
                .iter()
                .map(|&id| Field {
                    id,
                    label: labels[id].0,
                    hint: labels[id].1,
                    value: wizard.display_value(id),
                })
                .collect(),
            selected: wizard.focus,
            lead: if wizard.sources {
                "Для обычной настройки достаточно готового каталога. Дополнительные источники — по желанию.".into()
            } else {
                "Введите адрес из панели хостинга. Все дополнительные IP сервера укажите в расширенных настройках.".into()
            },
            error: wizard.error.clone(),
        })
    }

    pub(crate) fn select_field(&mut self, id: usize) {
        if let Some(wizard) = self.wizard.as_mut() {
            if let Some(panel) = wizard.registration.as_mut() {
                panel.select_field(id);
                return;
            }
            if let Some(draft) = wizard.domain_draft.as_mut() {
                if id < draft.rows.len() {
                    draft.focus = id;
                }
                return;
            }
            if let Some(picker) = wizard.grant_picker.as_mut() {
                if id < picker.selected.len() {
                    picker.focus = id;
                }
                return;
            }
            if wizard.registration.is_none()
                && matches!(wizard.stage, WizardStage::Input)
                && wizard.visible_fields().contains(&id)
            {
                if wizard.focus == 2 {
                    wizard.suggest_own_ip();
                }
                wizard.focus = id;
            }
        }
    }

    pub(crate) fn reference_review(&self) -> Option<crate::tui_widgets::ReferenceReview> {
        let wizard = self.wizard.as_ref()?;
        if wizard.registration.is_some() {
            return None;
        }
        if let WizardStage::NoEligible(report) = &wizard.stage {
            return Some(crate::tui_widgets::ReferenceReview {
                rows: report.rows.clone(),
                details: Vec::new(),
                note: if report.rows.iter().all(|row| row.address.parse::<SocketAddr>().is_err()) {
                    "Не найдено подтверждённых адресов. Проверьте DNS и имена сайтов. TLS-проверка не выполнялась. Ничего не сохранено."
                } else {
                    "Подходящих сайтов не найдено. Проверьте доступ сервера к HTTPS и правильность времени; затем измените источники. Ничего не сохранено."
                }.into(),
                expanded: wizard.result_details,
            });
        }
        let WizardStage::CreateConfirm(value) = &wizard.stage else {
            return None;
        };
        let (input, _, review) = value.as_ref();
        let first = input.source.is_none();
        let details = vec![
            ("Адрес сервера", input.endpoint.clone()),
            ("Адрес прослушивания", input.listen.to_string()),
            (
                "Пользователи",
                if first {
                    format!("{} (отключён до выпуска ключа)", input.grants.join(", "))
                } else {
                    input.grants.join(", ")
                },
            ),
            ("Файл настроек", input.config.display().to_string()),
        ];
        let mut note = if first {
            "Сохранение создаст защищённые файлы и настройки, но не запустит сервер.".to_owned()
        } else {
            "Сначала создаются защищённые файлы. Запись настроек подтверждается отдельно; сервер не запускается.".to_owned()
        };
        note.push_str("\nВыбранные сайты перепроверены; остальные оценки предварительные.");
        if input
            .endpoint
            .parse::<SocketAddr>()
            .is_ok_and(|address| match address.ip() {
                IpAddr::V4(ip) => ip.is_documentation(),
                IpAddr::V6(ip) => ip.segments()[..2] == [0x2001, 0xdb8],
            })
        {
            note.push_str("\nВнимание: адрес из диапазона для документации, не публичный адрес вашего VPS. Вернитесь назад и замените его перед реальным использованием.");
        }
        Some(crate::tui_widgets::ReferenceReview {
            rows: review.rows.clone(),
            details,
            note,
            expanded: wizard.result_details,
        })
    }

    pub(crate) fn guide(&self) -> Option<(usize, usize, &'static str, &'static str)> {
        let wizard = self.wizard.as_ref()?;
        if wizard.registration.is_some() {
            return Some((
                6,
                6,
                "Сохранение TOML",
                "Enter предпросмотр · Y подтвердить · Esc назад",
            ));
        }
        if wizard.domain_draft.is_some() {
            return Some((
                2,
                6,
                "Редактор списка сайтов",
                "↑↓ строка · Enter добавить · Delete удалить · F4 готово · Esc отменить",
            ));
        }
        if wizard.grant_picker.is_some() {
            return Some((
                1,
                6,
                "Выбор пользователей",
                "↑↓ пользователь · Пробел отметить · Enter готово · Esc отменить",
            ));
        }
        Some(match &wizard.stage {
            WizardStage::Input if wizard.sources => (2, 6, "Источники поиска", "↑↓ поле · Пробел выбрать · Enter продолжить · F4 список сайтов · F2 расширенные · Esc назад"),
            WizardStage::Input => (1, 6, "Настройка сервера", "↑↓ поле · Enter продолжить · F2 расширенные · Esc назад"),
            WizardStage::DnsConfirm(_) if wizard.dns_details => (3, 6, "Полный список целей", "PgUp/PgDn прокрутка · F2 / Enter / Esc свернуть"),
            WizardStage::DnsConfirm(_) => {
                (3, 6, "Поиск адресов сайтов", "F2 список целей · Y найти адреса · N / Esc назад")
            }
            WizardStage::Resolving(_, _) => (3, 6, "Получение адресов", "Esc отменить"),
            WizardStage::ProbeConfirm(_) if wizard.tls_details => (4, 6, "Точные адреса проверки", "PgUp/PgDn прокрутка · F2 / Enter / Esc свернуть"),
            WizardStage::ProbeConfirm(_) => (
                4,
                6,
                "Проверка сайтов",
                "Y проверить перечисленные адреса · N / Esc назад",
            ),
            WizardStage::Checking(_, _) => (4, 6, "Проверка сайтов", "Esc отменить"),
            WizardStage::NoEligible(_) | WizardStage::CreateConfirm(_) if wizard.result_details => (5, 6, "Полный отчёт", "PgUp/PgDn прокрутка · F2 / Enter / Esc свернуть"),
            WizardStage::NoEligible(_) => (5, 6, "Нет подходящих сайтов", "F2 отчёт · Enter / Esc изменить источники"),
            WizardStage::CreateConfirm(value) => (
                5,
                6,
                "Результат подбора",
                if value.0.source.is_none() {
                    "Y создать TOML · N / Esc назад"
                } else {
                    "Y создать материалы · N / Esc назад"
                },
            ),
            WizardStage::Saving(_, _) | WizardStage::SavingInitial(_, _) => {
                (6, 6, "Сохранение", "")
            }
            WizardStage::SaveFailed { inspected: true, .. } => (6, 6, "Результат проверки файлов", "Esc закрыть"),
            WizardStage::SaveFailed { .. } => (6, 6, "Сохранение не подтверждено", "F2 проверить файлы · Esc закрыть"),
            WizardStage::Success => (6, 6, "REALITY создан", "Enter продолжить · Esc к обзору"),
        })
    }

    pub(crate) fn body(&self) -> String {
        if let Some(wizard) = &self.wizard {
            return wizard.body();
        }
        match &self.stage {
            Stage::Input => format!("Абсолютные пути. Для новой проверки задайте Plan и новый Health; для ранее согласованного Health оставьте Plan пустым.\n{} Health: {}\n{} Каталог: {}\n{} Plan TOML: {}\nEnter: локальный предпросмотр; Tab: поле; Esc: отменить.\nСеть только после отдельного согласия.\n{}",
                if self.focus == 0 { ">" } else { " " }, self.fields[0],
                if self.focus == 1 { ">" } else { " " }, self.fields[1],
                if self.focus == 2 { ">" } else { " " }, self.fields[2],
                self.error.as_deref().unwrap_or("")),
            Stage::Loading(_) => "Чтение и проверка локальных данных; запись не начата.".into(),
            Stage::LoadingPlan(_) => "Чтение согласуемого плана; сеть и запись не используются.".into(),
            Stage::ConfirmPlan(review) => review.body.clone(),
            Stage::Checking { .. } => "Ограниченная проверка согласованных целей. Esc: отменить без записи.".into(),
            Stage::Confirm(review) => review.body.clone(),
            Stage::Applying(_) => "Создание нового защищённого комплекта. Runtime не изменяется.".into(),
            Stage::Done(message) => message.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wizard_catalogue_search_is_not_the_three_reference_persistence_limit() {
        let dir =
            std::env::temp_dir().join(crate::tui_editor::generated_id("wizard-search").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.toml");
        let mut wizard = Wizard::first(path.clone()).unwrap();
        wizard.fields[2] = "edge.example.org".into();
        wizard.fields[3] = "93.184.216.1".into();
        wizard.fields[5] = "owner".into();
        let input = WizardInput::parse(path.clone(), None, &wizard.effective_fields()).unwrap();
        assert_eq!(
            input.candidates.len(),
            crate::camouflage_discovery::POPULAR_HTTPS_DOMAINS.len()
        );
        let targets: Vec<_> = (2..=7)
            .map(|n| reference_health::Target {
                server_name: format!("host{n}.example.org"),
                address: format!("93.184.216.{n}:443").parse().unwrap(),
            })
            .collect();
        assert!(input.search_plan(targets.clone()).is_ok());
        assert!(input.plan(targets.clone()).is_err());
        let mut evidence = vec![
            reference_health::Evidence {
                h2_status: Some(200),
                h3_status: None
            };
            targets.len()
        ];
        evidence[4].h3_status = Some(200);
        evidence[5] = reference_health::Evidence::default();
        let (state, report) =
            rank_checked(&input, targets.clone(), evidence, 1000, Vec::new()).unwrap();
        let state = state.unwrap();
        assert_eq!(state.plan().references.len(), 3);
        assert_eq!(state.plan().references[0].server_name, "host6.example.org");
        assert_eq!(report.rows.len(), 6);
        assert_eq!(report.rows[0].score, 100);
        assert_eq!(report.rows[5].score, 0);
        let (state, report) = rank_checked(
            &input,
            targets.clone(),
            vec![reference_health::Evidence::default(); targets.len()],
            1000,
            Vec::new(),
        )
        .unwrap();
        assert!(state.is_none());
        assert_eq!(report.rows.len(), 6);
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recheck_never_promotes_an_unobserved_backup() {
        let row = |name: &str, score, selected| crate::tui_widgets::ReferenceRow {
            name: name.into(),
            address: format!("{name}:443"),
            score,
            h2: score > 0,
            h3: score == 100,
            selected,
        };
        let mut screening = RankedReview {
            text: String::new(),
            rows: vec![
                row("first", 100, Some(0)),
                row("other", 100, None),
                row("backup", 80, Some(1)),
            ],
        };
        let fresh = RankedReview {
            text: "fresh".into(),
            rows: vec![row("backup", 80, Some(0)), row("first", 0, None)],
        };
        merge_rechecked(&mut screening, fresh);
        assert_eq!(screening.rows[0].name, "backup");
        assert_eq!(screening.rows[0].selected, Some(0));
        assert_eq!(screening.rows[1].name, "other");
        assert_eq!(screening.rows[1].selected, None);
        assert_eq!(screening.rows[2].score, 0);
    }

    #[test]
    fn range_sources_are_bounded_and_require_assigned_scope_before_dns() {
        use crate::camouflage_discovery::{InterfaceAddress, ServerSnapshot};
        let snapshot = ServerSnapshot {
            interfaces: vec![InterfaceAddress {
                address: "93.184.216.10".parse().unwrap(),
                prefix_len: 24,
            }],
            ..ServerSnapshot::default()
        };
        let own = ["93.184.216.10".parse().unwrap()];
        let targets = range_targets_for_snapshot("93.184.216.8/29", &own, &snapshot).unwrap();
        assert_eq!(targets.len(), 5);
        assert!(targets
            .iter()
            .all(|(ip, name)| !own.contains(ip) && name.is_none()));
        let explicit =
            range_targets_for_snapshot("reference.example.org@93.184.216.8/29", &own, &snapshot)
                .unwrap();
        assert!(explicit
            .iter()
            .all(|(_, name)| name.as_deref() == Some("reference.example.org")));
        for raw in [
            "93.184.217.0/29",
            "93.184.216.0/24",
            "10.0.0.0/29",
            "0.0.0.0/0",
            "93.184.216.8/29,other.example.org@93.184.216.8/29",
        ] {
            assert!(
                range_targets_for_snapshot(raw, &own, &snapshot).is_err(),
                "{raw}"
            );
        }
        let narrow = ServerSnapshot {
            interfaces: vec![InterfaceAddress {
                address: own[0],
                prefix_len: 32,
            }],
            ..ServerSnapshot::default()
        };
        assert!(range_targets_for_snapshot("93.184.216.8/29", &own, &narrow).is_err());
    }

    #[test]
    fn novice_setup_and_source_choices_do_not_start_network_or_write() {
        let dir =
            std::env::temp_dir().join(crate::tui_editor::generated_id("wizard-novice").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.toml");
        let mut wizard = Wizard::first(path.clone()).unwrap();
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert_eq!(wizard.focus, 2);
        assert!(!wizard.visible_fields().contains(&8));
        wizard.paste("93.184.216.1");
        wizard.key(press(KeyCode::Tab));
        assert_eq!(wizard.fields[3], "93.184.216.1");
        assert!(!wizard.visible_fields().contains(&3));
        wizard.fields[2] = "93.184.216.2".into();
        wizard.suggest_own_ip();
        assert_eq!(wizard.fields[3], "93.184.216.2");
        wizard.fields[5] = "phone".into();
        wizard.key(press(KeyCode::Enter));
        assert!(wizard.sources && matches!(wizard.stage, WizardStage::Input));
        assert_eq!(wizard.focus, 8);
        wizard.key(press(KeyCode::Char(' ')));
        assert!(!wizard.catalogue_enabled());
        wizard.key(press(KeyCode::Enter));
        assert!(wizard.error.contains("хотя бы один"));
        wizard.key(press(KeyCode::Char(' ')));
        wizard.key(press(KeyCode::Down));
        assert_eq!(wizard.focus, 9);
        assert!(!wizard.visible_fields().contains(&4));
        wizard.key(press(KeyCode::Char(' ')));
        wizard.key(press(KeyCode::Down));
        assert_eq!(wizard.focus, 4);
        wizard.paste("example.org");
        assert_eq!(wizard.custom_domains(), "example.org");
        assert!(wizard.catalogue_enabled());
        wizard.focus = 8;
        wizard.key(press(KeyCode::Char(' ')));
        wizard.focus = 4;
        wizard.fields[4] = "catalog".into();
        assert!(!wizard.catalogue_enabled());
        assert_eq!(wizard.source_error().map(|(field, _)| field), Some(4));
        wizard.fields[4] = "example.org".into();
        wizard.focus = 8;
        wizard.key(press(KeyCode::Char(' ')));
        wizard.focus = 9;
        wizard.key(press(KeyCode::Char(' ')));
        assert!(!wizard.visible_fields().contains(&4));
        assert_eq!(wizard.effective_fields()[4], "catalog");
        assert_eq!(wizard.custom_domains(), "example.org");
        wizard.key(press(KeyCode::Char(' ')));
        assert_eq!(wizard.effective_fields()[4], "catalog,example.org");
        wizard.fields[7] = "203.0.113.8/29".into();
        assert!(wizard.effective_fields()[7].is_empty());
        wizard.focus = 10;
        wizard.key(press(KeyCode::Char(' ')));
        assert!(wizard.visible_fields().contains(&7));
        assert_eq!(wizard.effective_fields()[7], "203.0.113.8/29");
        wizard.key(press(KeyCode::Char(' ')));
        assert!(wizard.effective_fields()[7].is_empty());
        assert!(!wizard.visible_fields().contains(&7));
        wizard.key(press(KeyCode::Esc));
        assert!(!wizard.sources);
        assert_eq!(wizard.fields[5], "phone");
        wizard.key(press(KeyCode::Enter));
        wizard.key(press(KeyCode::Enter));
        assert!(matches!(wizard.stage, WizardStage::DnsConfirm(_)));
        assert!(!wizard.body().contains("google.com"));
        wizard.key(press(KeyCode::F(2)));
        assert!(wizard.dns_details && wizard.body().contains("google.com"));
        wizard.key(press(KeyCode::Char('y')));
        assert!(matches!(wizard.stage, WizardStage::DnsConfirm(_)));
        wizard.key(press(KeyCode::Esc));
        assert!(!wizard.dns_details && matches!(wizard.stage, WizardStage::DnsConfirm(_)));
        wizard.key(press(KeyCode::Esc));
        assert!(wizard.sources);
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn multiline_domain_draft_preserves_cancel_and_bounds() {
        let mut draft = DomainDraft::new("example.org");
        draft.focus = 0;
        draft.paste(",example.net\r\nexample.com");
        assert_eq!(draft.value(), "example.org,example.net,example.com");
        assert_eq!(draft.rows.len(), 3);
        let before = draft.value();
        draft.paste(&"x".repeat(LIMIT));
        assert_eq!(draft.value(), before);
        assert!(!draft.error.is_empty());
        let dir = std::env::temp_dir()
            .join(crate::tui_editor::generated_id("wizard-domain-draft").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.toml");
        let mut wizard = Wizard::first(path.clone()).unwrap();
        wizard.sources = true;
        wizard.custom_enabled = true;
        wizard.fields[4] = "example.org".into();
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        wizard.key(press(KeyCode::F(4)));
        wizard.key(press(KeyCode::Enter));
        wizard.paste("example.net");
        wizard.key(press(KeyCode::Esc));
        assert_eq!(wizard.fields[4], "example.org");
        wizard.key(press(KeyCode::F(4)));
        wizard.key(press(KeyCode::Enter));
        wizard.paste("example.net");
        wizard.key(press(KeyCode::F(4)));
        assert_eq!(wizard.fields[4], "example.org,example.net");
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn save_recovery_does_not_retry_uncertain_or_changed_paths() {
        let dir =
            std::env::temp_dir().join(crate::tui_editor::generated_id("wizard-recovery").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.toml");
        let mut wizard = Wizard::first(path.clone()).unwrap();
        wizard.fields[2] = "93.184.216.1".into();
        wizard.suggest_own_ip();
        wizard.fields[5] = "phone".into();
        let input = WizardInput::parse(path.clone(), None, &wizard.effective_fields()).unwrap();
        let root = input.health.parent().unwrap().to_owned();
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        wizard.stage = save_failed(root.clone(), None);
        wizard.key(press(KeyCode::Char('y')));
        assert!(matches!(
            wizard.stage,
            WizardStage::SaveFailed { retry: false, .. }
        ));
        wizard.key(press(KeyCode::F(2)));
        assert!(matches!(
            wizard.stage,
            WizardStage::SaveFailed {
                inspected: true,
                ..
            }
        ));
        assert!(!path.exists() && !root.exists());
        wizard.stage = save_failed(root.clone(), Some(Error::Storage));
        wizard.key(press(KeyCode::F(2)));
        wizard.key(press(KeyCode::Char('y')));
        assert!(matches!(wizard.stage, WizardStage::Input));
        assert!(wizard.sources && !path.exists() && !root.exists());
        std::fs::create_dir(&root).unwrap();
        wizard.stage = save_failed(root.clone(), Some(Error::Storage));
        wizard.key(press(KeyCode::Char('y')));
        assert!(matches!(
            wizard.stage,
            WizardStage::SaveFailed { retry: false, .. }
        ));
        assert!(root.is_dir() && !path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn expanded_tls_and_result_views_never_approve_and_progress_is_bounded() {
        let dir =
            std::env::temp_dir().join(crate::tui_editor::generated_id("wizard-details").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.toml");
        let mut panel = ProvisionPanel::first(path.clone()).unwrap();
        let wizard = panel.wizard.as_mut().unwrap();
        wizard.fields[2] = "93.184.216.1".into();
        wizard.suggest_own_ip();
        wizard.fields[5] = "phone".into();
        let input = WizardInput::parse(path.clone(), None, &wizard.effective_fields()).unwrap();
        let target = Target {
            server_name: "reference.example.org".into(),
            address: "93.184.216.2:443".parse().unwrap(),
        };
        wizard.stage = WizardStage::ProbeConfirm(Box::new((
            input.clone(),
            ResolvedSearch {
                plan: Some(input.search_plan(vec![target.clone()]).unwrap()),
                unresolved: Vec::new(),
            },
        )));
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        panel.key(press(KeyCode::F(2)));
        assert!(panel.confirmation_choice().is_none());
        assert!(panel.body().contains("reference.example.org"));
        panel.key(press(KeyCode::Char('y')));
        assert!(panel.confirmation_choice().is_none());
        panel.key(press(KeyCode::Enter));
        assert!(panel.confirmation_choice().is_some());
        let (state, review) = rank_checked(
            &input,
            vec![target],
            vec![Evidence {
                h2_status: Some(200),
                h3_status: None,
            }],
            reference_health::unix_now().unwrap(),
            Vec::new(),
        )
        .unwrap();
        panel.wizard.as_mut().unwrap().stage =
            WizardStage::CreateConfirm(Box::new((input, state.unwrap(), review)));
        panel.key(press(KeyCode::F(2)));
        assert!(panel.reference_review().unwrap().expanded);
        panel.key(press(KeyCode::Char('y')));
        assert!(panel.confirmation_choice().is_none());
        panel.key(press(KeyCode::Esc));
        assert!(panel.confirmation_choice().is_some());
        assert!(progress_text("Проверка", 3, 6).contains("50%"));
        assert!(progress_text("Проверка", 8, 6).contains("100%"));
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn novice_errors_focus_the_missing_field_without_creating_files() {
        let dir =
            std::env::temp_dir().join(crate::tui_editor::generated_id("wizard-errors").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let mut wizard = Wizard::first(dir.join("server.toml")).unwrap();
        let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        wizard.key(enter);
        assert_eq!(wizard.focus, 2);
        wizard.fields[2] = "edge.example.org".into();
        wizard.key(enter);
        assert_eq!(wizard.focus, 3);
        wizard.fields[3] = "192.0.2.10".into();
        wizard.key(enter);
        assert_eq!(wizard.focus, 5);
        assert!(matches!(wizard.stage, WizardStage::Input));
        assert!(!wizard.config.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn grant_picker_is_explicit_and_cancel_restores_previous_draft() {
        let dir =
            std::env::temp_dir().join(crate::tui_editor::generated_id("grant-picker").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let mut wizard = Wizard::first(dir.join("server.toml")).unwrap();
        wizard.available_users = vec!["alice".into(), "bob".into()];
        wizard.focus = 5;
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        wizard.key(press(KeyCode::F(6)));
        wizard.key(press(KeyCode::Char(' ')));
        wizard.key(press(KeyCode::Down));
        wizard.key(press(KeyCode::Char(' ')));
        assert!(wizard.fields[5].is_empty());
        wizard.key(press(KeyCode::Esc));
        assert!(wizard.fields[5].is_empty());
        wizard.key(press(KeyCode::F(6)));
        wizard.key(press(KeyCode::Char(' ')));
        wizard.key(press(KeyCode::Down));
        wizard.key(press(KeyCode::Char(' ')));
        wizard.key(press(KeyCode::Enter));
        assert_eq!(wizard.fields[5], "alice,bob");
        assert!(!wizard.config.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn first_server_wizard_publishes_only_after_review_and_never_overwrites() {
        let dir = std::env::temp_dir()
            .join(crate::tui_editor::generated_id("first-reality-server").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.toml");
        let mut wizard = Wizard::first(path.clone()).unwrap();
        wizard.fields[2] = "edge.example.org".into();
        wizard.fields[3] = "93.184.216.1".into();
        wizard.fields[4] = "reference.example.org=93.184.216.2".into();
        wizard.fields[5] = "owner".into();
        let input = WizardInput::parse(path.clone(), None, &wizard.fields).unwrap();
        let plan = input
            .plan(vec![Target {
                server_name: "reference.example.org".into(),
                address: "93.184.216.2:443".parse().unwrap(),
            }])
            .unwrap();
        let now = reference_health::unix_now().unwrap();
        let (state, report) = rank_checked(
            &input,
            plan.references,
            vec![Evidence {
                h2_status: Some(200),
                h3_status: None,
            }],
            now,
            Vec::new(),
        )
        .unwrap();
        let state = state.unwrap();
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        wizard.stage =
            WizardStage::CreateConfirm(Box::new((input.clone(), state.clone(), report.clone())));
        assert!(!path.exists() && !input.bundle.exists());
        assert!(!wizard.key(press(KeyCode::Esc)));
        assert!(matches!(wizard.stage, WizardStage::Input));
        assert!(!path.exists() && !input.health.exists());
        wizard.stage = WizardStage::CreateConfirm(Box::new((input.clone(), state.clone(), report)));
        assert!(!wizard.key(press(KeyCode::Char('y'))));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let editor = loop {
            if let Some(editor) = wizard.poll() {
                break editor;
            }
            assert!(std::time::Instant::now() < deadline, "{}", wizard.body());
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(editor.selected_reality());
        assert!(matches!(wizard.stage, WizardStage::Success));
        assert!(wizard.body().contains("Подключение REALITY создано"));
        let before = std::fs::read(&path).unwrap();
        let Config::Server(doc) = config::parse(std::str::from_utf8(&before).unwrap()).unwrap()
        else {
            panic!("server expected");
        };
        assert_eq!(doc.server.inbounds.len(), 1);
        assert_eq!(doc.server.users.len(), 1);
        assert!(doc.server.users[0].disabled);
        assert_eq!(doc.server.inbounds[0].allowed_user_ids, vec!["owner"]);
        assert!(doc.server.inbounds[0].tls_cert.is_empty());
        assert!(doc.server.inbounds[0].tls_key.is_empty());
        assert!(input.bundle.exists() && input.health.exists());
        assert!(create_first_server(input, state).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bound_wizard_keeps_dns_probe_creation_and_registration_separate() {
        let dir = std::env::temp_dir().join(format!("theia-typed-wizard-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.toml");
        std::fs::write(
            &path,
            include_str!("../../../examples/server.toml")
                .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64)),
        )
        .unwrap();
        let editor = Editor::load(Role::Server, &path).unwrap();
        let mut wizard = Wizard::new(&editor).unwrap();
        assert_eq!(wizard.fields[1], "443");
        assert!(!wizard.body().contains("Выбор: auto / manual"));
        wizard.sources = true;
        wizard.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert!(wizard.body().contains("Выбор: auto / manual"));
        wizard.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert!(!wizard.body().contains("Выбор: auto / manual"));
        wizard.sources = false;
        wizard.fields[1] = "127.0.0.1:9443".into();
        wizard.fields[2] = "127.0.0.1".into();
        wizard.fields[3] = "127.0.0.1".into();
        wizard.fields[4] = "first.example.org=93.184.216.2,second.example.org=93.184.216.3".into();
        wizard.custom_enabled = true;
        wizard.catalogue = false;
        wizard.fields[5] = "device-a".into();
        let input =
            WizardInput::parse(path.clone(), Some(editor.saved_sha256()), &wizard.fields).unwrap();
        let plan = input
            .plan(vec![
                reference_health::Target {
                    server_name: "first.example.org".into(),
                    address: "93.184.216.2:443".parse().unwrap(),
                },
                reference_health::Target {
                    server_name: "second.example.org".into(),
                    address: "93.184.216.3:443".parse().unwrap(),
                },
            ])
            .unwrap();
        let evidence = vec![
            reference_health::Evidence {
                h2_status: Some(200),
                h3_status: None,
            },
            reference_health::Evidence {
                h2_status: Some(200),
                h3_status: Some(200),
            },
        ];
        let now = reference_health::unix_now().unwrap();
        let (state, report) = rank_checked(
            &input,
            plan.references.clone(),
            evidence.clone(),
            now,
            Vec::new(),
        )
        .unwrap();
        let state = state.unwrap();
        let mut manual = input.clone();
        manual.automatic = false;
        let (ordered, _) = rank_checked(
            &manual,
            plan.references.clone(),
            evidence.clone(),
            now,
            Vec::new(),
        )
        .unwrap();
        let ordered = ordered.unwrap();
        assert_eq!(
            ordered.plan().references[0].server_name,
            "first.example.org"
        );
        let mut failed = evidence.clone();
        failed[0] = Evidence {
            h2_status: None,
            h3_status: None,
        };
        assert!(rank_checked(
            &manual,
            plan.references.clone(),
            failed.clone(),
            now,
            Vec::new()
        )
        .unwrap()
        .0
        .is_none());
        let (filtered, filtered_review) =
            rank_checked(&input, plan.references.clone(), failed, now, Vec::new()).unwrap();
        let filtered = filtered.unwrap();
        assert_eq!(filtered_review.rows.len(), 2);
        assert_eq!(filtered_review.rows[1].selected, None);
        assert_eq!(filtered_review.rows[1].score, 0);
        assert_eq!(filtered.plan().references.len(), 1);
        assert!(
            rank_checked(&input, plan.references.clone(), Vec::new(), now, Vec::new()).is_err()
        );
        let resolved = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(input.resolve(&AtomicUsize::new(0)))
            .unwrap();
        assert!(resolved.plan.unwrap().targets() == plan.references.as_slice());
        assert_eq!(state.plan().references[0].server_name, "second.example.org");
        assert!(report.text.contains("100") && report.text.contains("80"));
        assert_eq!(report.rows[0].selected, Some(0));
        assert_eq!(report.rows[0].score, 100);
        assert_eq!(report.rows[1].selected, Some(1));
        assert!(!input.bundle.exists() && !input.health.exists());
        wizard.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(wizard.sources && matches!(wizard.stage, WizardStage::Input));
        wizard.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(wizard.stage, WizardStage::DnsConfirm(_)));
        wizard.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(wizard.stage, WizardStage::Input));
        assert!(!input.bundle.exists() && !input.health.exists());
        let original = std::fs::read(&path).unwrap();
        // Cancel the registration after local creation, then repeat the same
        // operation: only our new root is removed and TOML stays byte-exact.
        wizard.stage =
            WizardStage::CreateConfirm(Box::new((input.clone(), state.clone(), report.clone())));
        wizard.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while wizard.registration.is_none() {
            let _ = wizard.poll();
            assert!(std::time::Instant::now() < deadline, "{}", wizard.body());
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(wizard.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(!input.health.parent().unwrap().exists());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        wizard.registration = None;
        wizard.stage = WizardStage::CreateConfirm(Box::new((input.clone(), state, report)));
        assert!(!wizard.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while wizard.registration.is_none() {
            let _ = wizard.poll();
            assert!(std::time::Instant::now() < deadline, "{}", wizard.body());
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(input.bundle.exists() && input.health.exists());
        wizard.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        while !wizard.body().contains("Сохранить только TOML?") {
            let _ = wizard.poll();
            assert!(std::time::Instant::now() < deadline, "{}", wizard.body());
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(std::fs::read(&path).unwrap(), original);
        wizard.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        let registered = loop {
            if let Some(editor) = wizard.poll() {
                break editor;
            }
            assert!(std::time::Instant::now() < deadline, "{}", wizard.body());
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(registered.selected_reality());
        assert_eq!(registered.selected_record_id(), input.id);
        std::fs::write(&path, "stale").unwrap();
        assert_eq!(input.check_source(), Err(Error::Approval));
        std::fs::remove_dir_all(dir).unwrap();
    }

    use crate::reference_health::{Evidence, Plan, State, Store, Target};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn exact_preview_rejects_changed_health_and_existing_output() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "theia-provision-ui-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let health = dir.join("health");
        let output = dir.join("output");
        let state = State::new(
            Plan {
                schema_version: 1,
                inbound: "edge".into(),
                endpoint: "edge.example.org:443".into(),
                own_ips: vec!["93.184.216.1".parse().unwrap()],
                references: vec![Target {
                    server_name: "reference.example.org".into(),
                    address: "93.184.216.2:443".parse().unwrap(),
                }],
            },
            vec![Evidence {
                h2_status: Some(200),
                h3_status: None,
            }],
            1000,
        )
        .unwrap();
        Store::new(&health).unwrap().enroll(&state).unwrap();
        let review = preview(&health, &output, 1000).unwrap();
        assert!(review.body.contains("reference.example.org"));
        assert!(!output.exists());
        assert!(matches!(
            apply(&health, &output, [0; 32], 1000),
            Err(Error::Approval)
        ));
        assert!(matches!(
            apply(&health, &output, review.digest, 1061),
            Err(Error::Health)
        ));
        assert!(!output.exists());
        let message = apply(&health, &output, review.digest, 1001).unwrap();
        assert!(message.contains("Runtime НЕ изменён"));
        assert!(preview(&health, &output, 1001).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn plan_preview_is_offline_and_checked_state_is_guarded_before_storage() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "theia-plan-ui-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let plan_path = dir.join("plan");
        let health = dir.join("health");
        let output = dir.join("bundle");
        let plan = Plan {
            schema_version: 1,
            inbound: "edge".into(),
            endpoint: "edge.example.org:443".into(),
            own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: vec![Target {
                server_name: "reference.example.org".into(),
                address: "93.184.216.2:443".parse().unwrap(),
            }],
        };
        let raw = toml::to_string(&plan).unwrap();
        std::fs::write(&plan_path, &raw).unwrap();
        let approval = plan_preview(&plan_path, &health, &output).unwrap();
        assert!(approval.body.contains("reference.example.org"));
        assert!(!health.exists() && !output.exists());
        let (_tx, rx) = tokio::sync::oneshot::channel();
        assert!(matches!(
            check_plan(&plan_path, &health, &output, [0; 32], rx),
            Err(Error::Approval)
        ));
        let state = State::new(
            plan,
            vec![Evidence {
                h2_status: Some(200),
                h3_status: None,
            }],
            1000,
        )
        .unwrap();
        let make_review = || {
            render_review(
                &state,
                &output,
                1000,
                Some(Box::new(CheckedPlan {
                    source_digest: approval.digest,
                    state: state.clone(),
                })),
            )
            .unwrap()
        };
        std::fs::write(&plan_path, format!("{raw}\n# changed")).unwrap();
        assert!(matches!(
            apply_checked(&plan_path, &health, &output, make_review(), 1000),
            Err(Error::Approval)
        ));
        assert!(!health.exists() && !output.exists());
        std::fs::write(&plan_path, raw).unwrap();
        assert!(matches!(
            apply_checked(&plan_path, &health, &output, make_review(), 1061),
            Err(Error::Health)
        ));
        assert!(!health.exists() && !output.exists());
        assert!(
            apply_checked(&plan_path, &health, &output, make_review(), 1001)
                .unwrap()
                .contains("Runtime НЕ изменён")
        );
        assert!(Store::new(&health).unwrap().inspect().is_ok());
        assert!(output.join("provision.toml").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn panel_does_not_write_or_enter_apply_without_confirmation() {
        let mut panel = ProvisionPanel::new();
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        panel.paste("relative");
        panel.key(key(KeyCode::Tab));
        panel.paste("relative");
        assert!(matches!(panel.stage, Stage::Input));
        panel.stage = Stage::Confirm(Review {
            digest: [1; 32],
            body: "review".into(),
            checked: None,
        });
        panel.key(key(KeyCode::Char('n')));
        assert!(matches!(panel.stage, Stage::Input));
        assert!(panel.key(key(KeyCode::Esc)));
    }

    #[test]
    fn existing_health_panel_requires_confirmation_and_persists_bundle() {
        let dir =
            std::env::temp_dir().join(format!("theia-provision-panel-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let health = dir.join("health");
        let output = dir.join("bundle");
        let now = reference_health::unix_now().unwrap();
        let state = State::new(
            Plan {
                schema_version: 1,
                inbound: "edge".into(),
                endpoint: "edge.example.org:443".into(),
                own_ips: vec!["93.184.216.1".parse().unwrap()],
                references: vec![Target {
                    server_name: "reference.example.org".into(),
                    address: "93.184.216.2:443".parse().unwrap(),
                }],
            },
            vec![Evidence {
                h2_status: Some(200),
                h3_status: None,
            }],
            now,
        )
        .unwrap();
        Store::new(&health).unwrap().enroll(&state).unwrap();
        let mut p = ProvisionPanel::new();
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        p.paste(health.to_str().unwrap());
        p.key(key(KeyCode::Tab));
        p.paste(output.to_str().unwrap());
        p.key(key(KeyCode::Char('x')));
        p.key(key(KeyCode::Backspace));
        p.key(key(KeyCode::BackTab));
        p.key(key(KeyCode::Tab));
        assert!(p.body().contains("Plan TOML"));
        p.key(key(KeyCode::Enter));
        assert!(matches!(p.stage, Stage::Loading(_)));
        assert!(!p.key(key(KeyCode::Esc)));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while matches!(p.stage, Stage::Loading(_)) {
            let _ = p.poll();
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(matches!(p.stage, Stage::Confirm(_)));
        assert!(p.body().contains("не live Apply"));
        assert!(!output.exists());
        p.key(key(KeyCode::Char('y')));
        assert!(matches!(p.stage, Stage::Applying(_)));
        assert!(p.body().contains("Runtime не изменяется"));
        while matches!(p.stage, Stage::Applying(_)) {
            let _ = p.poll();
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(matches!(p.stage, Stage::Done(_)), "{}", p.body());
        assert!(output.join("provision.toml").exists());
        assert!(p.key(key(KeyCode::Esc)));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn worker_failures_and_network_cancellation_never_report_saved() {
        let mut p = ProvisionPanel::new();
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        p.key(key(KeyCode::Char('a')));
        p.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert!(p.fields[0].is_empty());
        let (tx, rx) = mpsc::channel();
        p.stage = Stage::LoadingPlan(rx);
        assert!(p.body().contains("согласуемого плана"));
        let _ = p.poll();
        tx.send(Ok(PlanReview {
            digest: [1; 32],
            body: "consent".into(),
        }))
        .unwrap();
        let _ = p.poll();
        assert_eq!(p.body(), "consent");
        p.key(key(KeyCode::Char('n')));
        assert!(matches!(p.stage, Stage::Input));
        let (tx, result) = mpsc::channel();
        let (cancel, mut cancelled) = tokio::sync::oneshot::channel();
        p.stage = Stage::Checking { result, cancel };
        assert!(p.body().contains("отменить без записи"));
        p.key(key(KeyCode::Esc));
        assert_eq!(cancelled.try_recv(), Ok(()));
        assert!(matches!(p.stage, Stage::Input));
        drop(tx);
        let (tx, rx) = mpsc::channel();
        p.stage = Stage::Applying(rx);
        drop(tx);
        let _ = p.poll();
        assert!(p.body().contains("ОТКАЗ"));
        assert!(matches!(p.stage, Stage::Input));
    }
}
