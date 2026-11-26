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
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
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
            ).map_err(|_| Error::Scope)?;
            if candidates.iter().any(|(prior, _): &(String, Option<IpAddr>)| prior == name) {
                return Err(Error::Scope);
            }
            candidates.push((name.to_owned(), address));
            Ok(())
        };
        if !fields[4].trim().is_empty() {
            for item in fields[4].split(',').map(str::trim) {
                if item == "catalog" {
                    if !automatic { return Err(Error::Scope); }
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

    fn search_plan(&self, targets: Vec<reference_health::Target>) -> Result<reference_health::SearchPlan, Error> {
        reference_health::SearchPlan::new(self.plan_document(targets)).map_err(|_| Error::Health)
    }

    fn seed_count(&self) -> usize {
        self.candidates.len() + self.range_targets.len()
    }

    async fn resolve(&self, progress: &AtomicUsize) -> Result<ResolvedSearch, Error> {
        let seeds: Vec<_> = self.candidates.iter().cloned().map(|(name, ip)| SearchSeed::Domain(name, ip))
            .chain(self.range_targets.iter().cloned().map(|(ip, name)| SearchSeed::Range(ip, name)))
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
                let target = ips.into_iter()
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
        let plan = if references.is_empty() { None } else { Some(self.search_plan(references)?) };
        Ok(ResolvedSearch { plan, unresolved })
    }
}

type RangeTargets = Vec<(IpAddr, Option<String>)>;

fn range_targets(raw: &str, own_ips: &[IpAddr]) -> Result<RangeTargets, Error> {
    if raw.trim().is_empty() { return Ok(Vec::new()); }
    let native = crate::camouflage_interfaces::collect_assigned_interfaces().map_err(|_| Error::Scope)?;
    range_targets_for_snapshot(raw, own_ips, &native.server_snapshot())
}

// Offline expansion reuses the existing assigned-interface scope gate.
// No implied permission from provider prefix, public egress or DNS answers.
fn range_targets_for_snapshot(
    raw: &str,
    own_ips: &[IpAddr],
    snapshot: &crate::camouflage_discovery::ServerSnapshot,
) -> Result<RangeTargets, Error> {
    use crate::camouflage_discovery::{build_plan, CandidateHost, CandidateSource, NetworkPrefix, Warning};
    let mut targets: RangeTargets = Vec::new();
    if raw.split(',').count() > MAX_RANGES { return Err(Error::Scope); }
    for item in raw.split(',').map(str::trim) {
        let (name, prefix) = if let Some((name, prefix)) = item.split_once('@') {
            crate::camouflage_domain_dns::validate_manual_dns_request(
                name, crate::camouflage_domain_dns::DnsConsent::Approved,
            ).map_err(|_| Error::Scope)?;
            (Some(name.to_owned()), prefix)
        } else {
            (None, item)
        };
        let prefix: NetworkPrefix = prefix.parse().map_err(|_| Error::Scope)?;
        let plan = build_plan(snapshot, &[prefix]);
        if plan.warnings.iter().any(|warning| matches!(warning,
            Warning::RangeNotOnServer | Warning::RangeTooBroad | Warning::RangeExceedsAssignedPrefix |
            Warning::Ipv6EnumerationUnsupported | Warning::CandidateLimitReached)) {
            return Err(Error::Scope);
        }
        let mut found = false;
        for candidate in plan.candidates {
            if candidate.source != CandidateSource::AuthorizedSubnet { continue; }
            let CandidateHost::Ip(ip) = candidate.host else { continue };
            if own_ips.contains(&ip) { continue; }
            found = true;
            if let Some((_, previous)) = targets.iter().find(|(address, _)| *address == ip) {
                if previous != &name { return Err(Error::Scope); }
                continue;
            }
            targets.push((ip, name.clone()));
            if targets.len() > MAX_RANGE_IPS { return Err(Error::Scope); }
        }
        if !found { return Err(Error::Scope); }
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
            let ips = resolve_manual_domain(&name, DnsConsent::Approved).await.unwrap_or_default();
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
            let ips = resolve_manual_domain(&name, DnsConsent::Approved).await
                .ok().filter(|ips| ips.contains(&ip)).map(|_| vec![ip]).unwrap_or_default();
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
    if targets.len() != evidence.len() { return Err(Error::Health); }
    let mut entries: Vec<_> = targets.into_iter().zip(evidence).collect();
    let mut rows: Vec<_> = entries.iter().map(|(target, item)| crate::tui_widgets::ReferenceRow {
        name: target.server_name.clone(),
        address: target.address.to_string(),
        score: item.score(),
        h2: item.eligible(),
        h3: item.h3(),
        selected: None,
    }).collect();
    let unresolved_count = unresolved.len();
    rows.append(&mut unresolved);
    let mut chosen = Vec::new();
    let mut observations = Vec::new();
    if input.automatic {
        entries.sort_by_key(|(_, item)| std::cmp::Reverse(item.score()));
        for (target, item) in entries {
            if !item.eligible() { continue; }
            let mut trial = chosen.clone();
            trial.push(target);
            // The persistent contract retains only 3 distinct names and pins.
            if input.plan(trial.clone()).is_ok() {
                chosen = trial;
                observations.push(item);
            }
            if chosen.len() == 3 { break; }
        }
    } else if unresolved_count == 0 && entries.iter().all(|(_, item)| item.eligible()) {
        (chosen, observations) = entries.into_iter().unzip();
    }
    let state = if chosen.is_empty() {
        None
    } else {
        input.plan(chosen).ok().and_then(|plan| reference_health::State::new(plan, observations, now).ok())
    };
    let mut report = format!(
        "Кандидатов: {} · DNS/PTR не подтверждено: {}.\nОценки: 100 = стабильные H2+H3, 80 = стабильный H2, 0 = отказ.\n",
        rows.len(), unresolved_count,
    );
    if let Some(state) = &state {
        for (index, target) in state.plan().references.iter().enumerate() {
            if let Some(row) = rows.iter_mut().find(|row| row.name == target.server_name && row.address == target.address.to_string()) {
                row.selected = Some(index);
            }
        }
    }
    rows.sort_by_key(|row| (row.selected.unwrap_or(usize::MAX), std::cmp::Reverse(row.score)));
    for row in &rows {
        report.push_str(&format!("{} {} · H2={} H3={} · {}\n", row.name, row.address, row.h2, row.h3, row.score));
    }
    if state.is_some() {
        report.push_str(&format!("\nСервер: {}\nПорт: {}\nПользователи: {}\nСоздать защищённые материалы? Сервер не будет запущен.\ny: создать; n/Esc: назад.",
            input.endpoint, input.listen.port(), input.grants.join(", ")));
    } else {
        report.push_str("\nНет допустимого набора референсов. Ничего не сохранено. Esc: изменить источники и повторить.");
    }
    Ok((state, RankedReview { text: report, rows }))
}

enum WizardStage {
    Input,
    DnsConfirm(Box<WizardInput>),
    Resolving(
        Receiver<Result<(WizardInput, ResolvedSearch), Error>>,
        tokio::sync::oneshot::Sender<()>,
    ),
    ProbeConfirm(Box<(WizardInput, ResolvedSearch)>),
    Checking(
        Receiver<Result<(WizardInput, Option<reference_health::State>, RankedReview), Error>>,
        tokio::sync::oneshot::Sender<()>,
    ),
    CreateConfirm(Box<(WizardInput, reference_health::State, RankedReview)>),
    NoEligible(RankedReview),
    Saving(Receiver<Result<RegistrationPanel, Error>>, PathBuf),
    SavingInitial(Receiver<Result<Editor, Error>>, PathBuf),
    Done(String),
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
    users: String,
    available_users: Vec<String>,
    grant_picker: Option<GrantPicker>,
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
                "catalog".into(),
                String::new(),
                "auto".into(),
                String::new(),
            ],
            focus: 1,
            advanced: false,
            users: editor
                .record_user_catalog(crate::tui_editor::RecordAction::NewInbound)
                .unwrap_or_default(),
            available_users: editor
                .workspace_users()
                .into_iter()
                .filter_map(|(id, disabled, _)| (!disabled).then_some(id))
                .collect(),
            grant_picker: None,
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
                "catalog".into(),
                String::new(),
                "auto".into(),
                String::new(),
            ],
            focus: 1,
            advanced: false,
            users: "Введите ID первого пользователя. Он будет отключён до явного выпуска токена."
                .into(),
            available_users: Vec::new(),
            grant_picker: None,
            progress: Arc::new(AtomicUsize::new(0)),
            total: 0,
            stage: WizardStage::Input,
            error: String::new(),
            registration: None,
        })
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
        if self.fields[5].trim().is_empty() {
            return Some((
                5,
                if self.source.is_none() {
                    "Придумайте имя первого пользователя, например phone. Доступ появится только после выдачи приглашения."
                } else {
                    "Выберите хотя бы одного активного пользователя с помощью F6. Если их нет, создайте пользователя отдельно."
                },
            ));
        }
        if self.source.is_none() && !config::valid_id(&self.fields[5]) {
            return Some((5,"Имя первого пользователя должно быть одним допустимым ID, например phone или laptop."));
        }
        None
    }

    fn visible_fields(&self) -> &[usize] {
        if self.advanced {
            &[0, 1, 2, 3, 4, 5, 6, 7]
        } else {
            &[1, 2, 3, 5, 4, 7]
        }
    }
    fn move_focus(&mut self, forward: bool) {
        let fields = self.visible_fields();
        let index = fields
            .iter()
            .position(|field| *field == self.focus)
            .unwrap_or(0);
        self.focus = fields[(index + if forward { 1 } else { fields.len() - 1 }) % fields.len()];
    }
    fn paste(&mut self, text: &str) {
        if let Some(panel) = self.registration.as_mut() {
            panel.paste(text);
            return;
        }
        if self.grant_picker.is_none() && matches!(self.stage, WizardStage::Input) {
            let field = &mut self.fields[self.focus];
            let value = text.trim_end_matches(['\r', '\n']);
            if !value.chars().any(char::is_control)
                && field.len().saturating_add(value.len()) <= LIMIT
            {
                field.push_str(value);
            }
        }
    }
    fn key(&mut self, key: KeyEvent) -> bool {
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
                    KeyCode::Esc => return true,
                    KeyCode::F(2) => {
                        self.advanced = !self.advanced;
                        if !self.visible_fields().contains(&self.focus) {
                            self.focus = 1;
                        }
                    }
                    KeyCode::F(3) if self.focus == 3 && self.fields[3].is_empty() => {
                        if let Ok(ip) = self.fields[2].trim_matches(['[', ']']).parse::<IpAddr>() {
                            self.fields[3] = ip.to_string();
                            self.error.clear();
                        } else {
                            self.error="Адрес для клиентов не является IP. Укажите все IP своего сервера вручную.".into();
                        }
                    }
                    KeyCode::F(6) if self.focus == 5 && !self.available_users.is_empty() => {
                        self.grant_picker = Some(GrantPicker {
                            selected: self
                                .available_users
                                .iter()
                                .map(|id| self.fields[5].split(',').any(|s| s.trim() == id))
                                .collect(),
                            focus: 0,
                        });
                    }
                    KeyCode::Tab | KeyCode::Down => self.move_focus(true),
                    KeyCode::BackTab | KeyCode::Up => self.move_focus(false),
                    KeyCode::Backspace => {
                        self.fields[self.focus].pop();
                        self.error.clear();
                    }
                    KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                        self.fields[self.focus].clear();
                        self.error.clear();
                    }
                    KeyCode::Enter => {
                        if let Some((field, message)) = self.basic_error() {
                            self.focus = field;
                            self.error = message.into();
                            self.stage = WizardStage::Input;
                            return false;
                        }
                        match WizardInput::parse(self.config.clone(), self.source, &self.fields) {
                            Ok(input) => {
                                self.error.clear();
                                self.stage = WizardStage::DnsConfirm(Box::new(input));
                                return false;
                            }
                            Err(error) => self.error = format!("ОТКАЗ: {error}"),
                        }
                    }
                    KeyCode::Char(ch)
                        if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                            && !ch.is_control()
                            && self.fields[self.focus].len() + ch.len_utf8() <= LIMIT =>
                    {
                        self.fields[self.focus].push(ch)
                    }
                    _ => {}
                }
                WizardStage::Input
            }
            WizardStage::DnsConfirm(input)
                if key.code == KeyCode::Char('y') && key.modifiers.is_empty() =>
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
            WizardStage::ProbeConfirm(value)
                if key.code == KeyCode::Char('y') && key.modifiers.is_empty() =>
            {
                let (input, resolved) = *value;
                self.total = resolved.plan.as_ref().map_or(0, |plan| plan.targets().len());
                self.progress = Arc::new(AtomicUsize::new(0));
                let progress = Arc::clone(&self.progress);
                let (tx, rx) = mpsc::channel();
                let (cancel, cancelled) = tokio::sync::oneshot::channel();
                let _worker = std::thread::spawn(move || {
                    let result = input.check_source().and_then(|()| {
                        let plan = resolved.plan.ok_or(Error::Health)?;
                        let approved = plan.digest().map_err(|_| Error::Health)?;
                        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Error::Storage)?;
                        let evidence = rt.block_on(async { tokio::select! {
                            biased;
                            _ = cancelled => Err(Error::Health),
                            value = reference_health::check_search(&plan, approved, &progress) => value.map_err(|_| Error::Health),
                        } })?;
                        let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
                        let (state, report) = rank_checked(&input, plan.into_targets(), evidence, now, resolved.unresolved)?;
                        Ok((input, state, report))
                    });
                    let _ = tx.send(result);
                });
                WizardStage::Checking(rx, cancel)
            }
            WizardStage::CreateConfirm(value)
                if key.code == KeyCode::Char('y') && key.modifiers.is_empty() =>
            {
                let (input, state, _) = *value;
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
            WizardStage::Checking(_, cancel) if key.code == KeyCode::Esc => {
                let _ = cancel.send(());
                WizardStage::Input
            }
            WizardStage::Resolving(_, cancel) if key.code == KeyCode::Esc => {
                let _ = cancel.send(());
                WizardStage::Input
            }
            WizardStage::Done(_) if key.code == KeyCode::Esc => return true,
            other => other,
        };
        false
    }
    fn poll(&mut self) -> Option<Editor> {
        if let Some(panel) = self.registration.as_mut() {
            return panel.poll();
        }
        let result = match &self.stage {
            WizardStage::Resolving(rx, _) => match rx.try_recv() {
                Ok(value) => value.map(|(input, resolved)| {
                    if resolved.plan.is_some() {
                        WizardStage::ProbeConfirm(Box::new((input, resolved)))
                    } else {
                        WizardStage::NoEligible(RankedReview {
                            text: "DNS/PTR не подтвердил ни одного кандидата. TLS не выполнялся. Esc: назад.".into(),
                            rows: resolved.unresolved,
                        })
                    }
                }),
                Err(TryRecvError::Empty) => return None, Err(TryRecvError::Disconnected) => Err(Error::Health),
            },
            WizardStage::Checking(rx, _) => match rx.try_recv() {
                Ok(value) => value.map(|(input, state, report)| match state {
                    Some(state) => WizardStage::CreateConfirm(Box::new((input, state, report))),
                    None => WizardStage::NoEligible(report),
                }),
                Err(TryRecvError::Empty) => return None, Err(TryRecvError::Disconnected) => Err(Error::Health),
            },
            WizardStage::SavingInitial(rx, root) => match rx.try_recv() {
                Ok(Ok(editor)) => return Some(editor),
                Ok(Err(error)) => Ok(WizardStage::Done(format!("Не удалось сохранить первый TOML: {error}. При неопределённой записи проверьте {root:?}. Сервер не запущен."))),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Ok(WizardStage::Done(format!("Запись не подтверждена. Проверьте TOML и {root:?}; не повторяйте вслепую."))),
            },
            WizardStage::Saving(rx, root) => match rx.try_recv() {
                Ok(Ok(panel)) => { self.registration = Some(panel); return None; }
                Ok(Err(error)) => Ok(WizardStage::Done(format!("ОТКАЗ: {error}. При неопределённой записи проверьте каталог {root:?}; для целых материалов доступна регистрация M. Runtime не изменён. Esc: закрыть."))),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Ok(WizardStage::Done(format!("Неопределённая запись материалов в {root:?}. Не повторяйте вслепую. Esc: закрыть."))),
            },
            _ => return None,
        };
        self.stage = match result {
            Ok(stage) => stage,
            Err(error) => {
                self.error = format!("ОТКАЗ: {error}");
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
                let mut out = String::from("СЕТЬ · без собственного TLS-сертификата\n\n");
                for &i in self.visible_fields() {
                    if i == 5 { out.push_str("\nДОСТУП\n"); }
                    let label = match i {
                        1 if !self.advanced => "Порт TCP/UDP",
                        2 => "Адрес сервера для клиентов (домен/IP без порта)",
                        3 => "Собственные IP сервера (через запятую)",
                        5 if self.source.is_none() => "ID первого пользователя",
                        5 => "Пользователи с доступом (ID через запятую)",
                        _ => WIZARD_LABELS[i],
                    };
                    let value = if self.fields[i].is_empty() { "[введите значение]" } else { self.fields[i].as_str() };
                    out.push_str(&format!("{} {label}: {value}\n", if i == self.focus { ">" } else { " " }));
                }
                out.push_str(if self.advanced { "auto: подобрать по оценкам; manual: сохранить порядок.\nF2: скрыть расширенные.\n" } else { "ID создаётся автоматически; референсы подбираются из каталога.\nУкажите все собственные IP, включая публичный/NAT: это обязательная защита от self-reference.\nF2: расширенные (ID, домены/IP, manual).\n" });
                out.push_str(&self.users);
                if !self.available_users.is_empty() {
                    out.push_str("\nF6 на поле доступа: выбрать пользователей из списка.");
                }
                out.push_str("\nEnter: проверить и подобрать; ↑↓ / Tab: поле; Ctrl+U: очистить; Esc: отменить.\n");
                out.push_str(&self.error); out
            }
            WizardStage::DnsConfirm(input) => {
                let mut body = format!("Поиск: {} доменов, {} IP из разрешённых CIDR.\nDNS и обратный DNS; без TLS и записи. Только адреса с подтверждённым SNI попадут в следующий этап.\nCIDR: подтверждайте только адреса, на проверку которых у вас есть разрешение.\ny: разрешить DNS; n/Esc: отменить.\n\nДОМЕНЫ\n", input.candidates.len(), input.range_targets.len());
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
            WizardStage::Resolving(_, _) => format!("Получение DNS/PTR: {} / {}.\nEsc: отменить, без TLS и записи.", self.progress.load(Ordering::Relaxed), self.total),
            WizardStage::ProbeConfirm(value) => {
                let search = value.1.plan.as_ref().map_or_else(String::new, |plan| plan.preview());
                format!("Проверить {} согласованных IP:443 и SNI (public PKI, TLS 1.3, H2/H3 HEAD).\nDNS/PTR исключено: {}. Никаких иных адресов, портов, bearer или записи.\nDNS будет повторно сверён, включая endpoint.\ny: проверить; n/Esc: отменить.\n\n{}", value.1.plan.as_ref().map_or(0, |plan| plan.targets().len()), value.1.unresolved.len(), search)
            }
            WizardStage::Checking(_, _) => format!("Проверка TLS / QUIC: {} / {}.\nEsc: отменить без записи.", self.progress.load(Ordering::Relaxed), self.total),
            WizardStage::NoEligible(report) => report.text.clone(),
            WizardStage::CreateConfirm(value) => {
                if value.0.source.is_none() {
                    format!("{}\nПервый TOML: {}\nПервый пользователь: {} (отключён).\ny: создать материалы и сохранить новый TOML; n/Esc: назад.", value.2.text, value.0.config.display(), value.0.grants.join(", "))
                } else {
                    value.2.text.clone()
                }
            },
            WizardStage::Saving(_, _) | WizardStage::SavingInitial(_, _) => "Создание локальных материалов; не закрывайте экран. Runtime не меняется.".into(),
            WizardStage::Done(message) => message.clone(),
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
            if let Some(panel) = &wizard.registration { return panel.confirmation_choice(); }
            if wizard.grant_picker.is_some() { return None; }
            return match wizard.stage {
                WizardStage::DnsConfirm(_) => Some(('y', "Разрешить DNS")),
                WizardStage::ProbeConfirm(_) => Some(('y', "Проверить адреса")),
                WizardStage::CreateConfirm(_) => Some(('y', "Сохранить")),
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

    pub(crate) fn form(&self) -> Option<crate::tui_widgets::Form> {
        use crate::tui_widgets::{Field, Form};
        let wizard = self.wizard.as_ref()?;
        if let Some(panel) = &wizard.registration {
            return panel.form();
        }
        if !matches!(wizard.stage, WizardStage::Input) {
            return None;
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
            ("ID подключения", "Уникальное имя подключения, создаётся автоматически."),
            ("Порт TCP/UDP", "Оставьте 443, если не знаете, зачем менять. Порт должен быть доступен на сервере."),
            ("Адрес сервера для клиентов", "Введите IP или домен VPS из панели хостинга, без https:// и порта. Не адрес стороннего сайта."),
            ("IP-адреса вашего сервера", "IP указаны в панели хостинга. F3 — перенести IP из поля выше. Если IP несколько, перечислите их через запятую."),
            ("Поиск по доменам", "catalog — весь каталог; свои домены или домен=IP через запятую. Можно очистить для поиска только по CIDR."),
            (if first { "Имя первого пользователя" } else { "Пользователи с доступом (F6)" },
             if first { "Придумайте имя, например phone. После создания выдайте личный ключ через «Восстановить доступ» на обзоре." } else { "Нажмите F6 и отметьте нужных пользователей. Никому не выдаётся доступ автоматически." }),
            ("Режим подбора", "auto — лучшие 3; manual — до трёх явных доменов в заданном порядке."),
            ("Разрешённые CIDR", "Необязательно: CIDR или SNI@CIDR, до 32 IP в назначенной подсети. PTR и прямой DNS обязательны; только с разрешением."),
        ];
        Some(Form {
            fields: wizard
                .visible_fields()
                .iter()
                .map(|&id| Field {
                    id,
                    label: labels[id].0,
                    hint: labels[id].1,
                    value: wizard.fields[id].clone(),
                })
                .collect(),
            selected: wizard.focus,
            lead: if wizard.advanced {
                "Расширенные параметры · F2 скрыть".into()
            } else {
                "Данные сервера возьмите из панели хостинга. Порт обычно 443. Выберите пользователя. F2 — расширенные настройки.".into()
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
                note: "Нет допустимого набора. Ничего не сохранено. Esc: вернуться к источникам.".into(),
            });
        }
        let WizardStage::CreateConfirm(value) = &wizard.stage else { return None; };
        let (input, _, review) = value.as_ref();
        let first = input.source.is_none();
        let details = vec![
            ("Адрес сервера", input.endpoint.clone()),
            ("TCP/UDP bind", input.listen.to_string()),
            (
                "Пользователи",
                if first {
                    format!("{} (отключён до выпуска токена)", input.grants.join(", "))
                } else {
                    input.grants.join(", ")
                },
            ),
            ("TOML", input.config.display().to_string()),
        ];
        let mut note = if first {
            "Создание защищённых материалов и нового TOML. Сервер не запускается.".to_owned()
        } else {
            "Создание защищённых материалов. TOML сохраняется после отдельного подтверждения; сервер не запускается.".to_owned()
        };
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
        })
    }

    pub(crate) fn guide(&self) -> Option<(usize, usize, &'static str, &'static str)> {
        let wizard = self.wizard.as_ref()?;
        if wizard.registration.is_some() {
            return Some((
                5,
                5,
                "Сохранение TOML",
                "Enter предпросмотр · Y подтвердить · Esc назад",
            ));
        }
        if wizard.grant_picker.is_some() {
            return Some((
                1,
                5,
                "Выбор пользователей",
                "↑↓ пользователь · Пробел отметить · Enter готово · Esc отменить",
            ));
        }
        Some(match &wizard.stage {
            WizardStage::Input => (
                1,
                5,
                "Настройка сервера",
                "↑↓ поле · Enter проверить и подобрать · F2 расширенные · Esc назад",
            ),
            WizardStage::DnsConfirm(_) => {
                (2, 5, "Разрешение DNS", "Y разрешить DNS · N / Esc назад")
            }
            WizardStage::Resolving(_, _) => (2, 5, "Получение адресов", "Esc отменить"),
            WizardStage::ProbeConfirm(_) => (
                3,
                5,
                "Проверка референсов",
                "Y проверить перечисленные адреса · N / Esc назад",
            ),
            WizardStage::Checking(_, _) => (3, 5, "Проверка TLS / QUIC", "Esc отменить"),
            WizardStage::NoEligible(_) => (4, 5, "Нет подходящих референсов", "Esc изменить источники"),
            WizardStage::CreateConfirm(value) => (
                4,
                5,
                "Результат подбора",
                if value.0.source.is_none() {
                    "Y создать TOML · N / Esc назад"
                } else {
                    "Y создать материалы · N / Esc назад"
                },
            ),
            WizardStage::Saving(_, _) | WizardStage::SavingInitial(_, _) => {
                (5, 5, "Сохранение", "Идёт запись; сервер не запускается")
            }
            WizardStage::Done(_) => (5, 5, "Результат записи", "Esc закрыть"),
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
        let dir = std::env::temp_dir().join(crate::tui_editor::generated_id("wizard-search").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.toml");
        let mut wizard = Wizard::first(path.clone()).unwrap();
        wizard.fields[2] = "edge.example.org".into();
        wizard.fields[3] = "93.184.216.1".into();
        wizard.fields[5] = "owner".into();
        let input = WizardInput::parse(path.clone(), None, &wizard.fields).unwrap();
        assert_eq!(input.candidates.len(), crate::camouflage_discovery::POPULAR_HTTPS_DOMAINS.len());
        let targets: Vec<_> = (2..=7).map(|n| reference_health::Target {
            server_name: format!("host{n}.example.org"),
            address: format!("93.184.216.{n}:443").parse().unwrap(),
        }).collect();
        assert!(input.search_plan(targets.clone()).is_ok());
        assert!(input.plan(targets.clone()).is_err());
        let mut evidence = vec![reference_health::Evidence { h2_status: Some(200), h3_status: None }; targets.len()];
        evidence[4].h3_status = Some(200);
        evidence[5] = reference_health::Evidence::default();
        let (state, report) = rank_checked(&input, targets.clone(), evidence, 1000, Vec::new()).unwrap();
        let state = state.unwrap();
        assert_eq!(state.plan().references.len(), 3);
        assert_eq!(state.plan().references[0].server_name, "host6.example.org");
        assert_eq!(report.rows.len(), 6);
        assert_eq!(report.rows[0].score, 100);
        assert_eq!(report.rows[5].score, 0);
        let (state, report) = rank_checked(&input, targets.clone(), vec![reference_health::Evidence::default(); targets.len()], 1000, Vec::new()).unwrap();
        assert!(state.is_none());
        assert_eq!(report.rows.len(), 6);
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn range_sources_are_bounded_and_require_assigned_scope_before_dns() {
        use crate::camouflage_discovery::{InterfaceAddress, ServerSnapshot};
        let snapshot = ServerSnapshot {
            interfaces: vec![InterfaceAddress { address: "93.184.216.10".parse().unwrap(), prefix_len: 24 }],
            ..ServerSnapshot::default()
        };
        let own = ["93.184.216.10".parse().unwrap()];
        let targets = range_targets_for_snapshot("93.184.216.8/29", &own, &snapshot).unwrap();
        assert_eq!(targets.len(), 5);
        assert!(targets.iter().all(|(ip, name)| !own.contains(ip) && name.is_none()));
        let explicit = range_targets_for_snapshot("reference.example.org@93.184.216.8/29", &own, &snapshot).unwrap();
        assert!(explicit.iter().all(|(_, name)| name.as_deref() == Some("reference.example.org")));
        for raw in ["93.184.217.0/29", "93.184.216.0/24", "10.0.0.0/29", "0.0.0.0/0", "93.184.216.8/29,other.example.org@93.184.216.8/29"] {
            assert!(range_targets_for_snapshot(raw, &own, &snapshot).is_err(), "{raw}");
        }
        let narrow = ServerSnapshot {
            interfaces: vec![InterfaceAddress { address: own[0], prefix_len: 32 }],
            ..ServerSnapshot::default()
        };
        assert!(range_targets_for_snapshot("93.184.216.8/29", &own, &narrow).is_err());
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
        wizard.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert!(wizard.body().contains("Выбор: auto / manual"));
        wizard.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert!(!wizard.body().contains("Выбор: auto / manual"));
        wizard.fields[1] = "127.0.0.1:9443".into();
        wizard.fields[2] = "127.0.0.1".into();
        wizard.fields[3] = "127.0.0.1".into();
        wizard.fields[4] = "first.example.org=93.184.216.2,second.example.org=93.184.216.3".into();
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
        let (state, report) = rank_checked(&input, plan.references.clone(), evidence.clone(), now, Vec::new()).unwrap();
        let state = state.unwrap();
        let mut manual = input.clone();
        manual.automatic = false;
        let (ordered, _) = rank_checked(&manual, plan.references.clone(), evidence.clone(), now, Vec::new()).unwrap();
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
        assert!(rank_checked(&manual, plan.references.clone(), failed.clone(), now, Vec::new()).unwrap().0.is_none());
        let (filtered, filtered_review) = rank_checked(&input, plan.references.clone(), failed, now, Vec::new()).unwrap();
        let filtered = filtered.unwrap();
        assert_eq!(filtered_review.rows.len(), 2);
        assert_eq!(filtered_review.rows[1].selected, None);
        assert_eq!(filtered_review.rows[1].score, 0);
        assert_eq!(filtered.plan().references.len(), 1);
        assert!(rank_checked(&input, plan.references.clone(), Vec::new(), now, Vec::new()).is_err());
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
