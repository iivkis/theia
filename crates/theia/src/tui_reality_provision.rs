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


use crate::{config::{self, Config}, reality_config::{self, ServerRequest}, tui_editor::Editor, tui_reality_register::RegistrationPanel, Role};
use std::net::{IpAddr, SocketAddr};
const WIZARD_LABELS: [&str; 7] = [
    "ID inbound", "TCP/UDP bind", "Публичный endpoint host (без порта)",
    "Собственные IP через запятую", "Домены (до 3) или domain=IP",
    "Grants (ID через запятую)", "Выбор: auto / manual",
];

#[derive(Clone)]
struct WizardInput {
    config: PathBuf,
    source: [u8; 32],
    id: String,
    listen: SocketAddr,
    endpoint: String,
    own_ips: Vec<IpAddr>,
    candidates: Vec<(String, Option<IpAddr>)>,
    grants: Vec<String>,
    automatic: bool,
    health: PathBuf,
    bundle: PathBuf,
}
impl WizardInput {
    fn check_source(&self) -> Result<(), Error> {
        use sha2::{Digest, Sha256};
        let raw = config::editor_bytes(&self.config).map_err(|_| Error::Storage)?;
        let actual: [u8; 32] = Sha256::digest(&raw).into();
        if actual != self.source { return Err(Error::Approval); }
        let Config::Server(doc) = config::parse(std::str::from_utf8(&raw).map_err(|_| Error::Format)?).map_err(|_| Error::Format)? else { return Err(Error::Format); };
        if doc.server.inbounds.iter().any(|i| i.id == self.id)
            || self.grants.is_empty()
            || self.grants.iter().any(|id| !doc.server.users.iter().any(|u| u.id == *id && !u.disabled))
        { return Err(Error::Grant); }
        // Reject collisions with saved listeners before any consented work
        // or material creation. Wildcards may overlap both address families.
        for inbound in &doc.server.inbounds {
            for address in [&inbound.h2_listen, &inbound.quic_listen] {
                let existing: SocketAddr = address.parse().map_err(|_| Error::Scope)?;
                if existing.port() == self.listen.port()
                    && (existing.ip() == self.listen.ip() || existing.ip().is_unspecified() || self.listen.ip().is_unspecified())
                {
                    return Err(Error::Scope);
                }
            }
        }
        validate_paths(&self.health, &self.bundle)?;
        new_health_path(&self.health)?;
        Ok(())
    }
    fn parse(config: PathBuf, source: [u8; 32], fields: &[String; 7]) -> Result<Self, Error> {
        if !config::valid_id(&fields[0]) { return Err(Error::Scope); }
        let listen: SocketAddr = fields[1].parse().map_err(|_| Error::Scope)?;
        if listen.port() == 0 { return Err(Error::Scope); }
        let endpoint = format!("{}:{}", fields[2], listen.port());
        if !config::valid_remote(&endpoint) { return Err(Error::Scope); }
        let own_ips = fields[3].split(',').map(|s| s.trim().parse::<IpAddr>().map_err(|_| Error::Scope)).collect::<Result<Vec<_>, _>>()?;
        if own_ips.is_empty() || own_ips.len() > 64 { return Err(Error::Scope); }
        let mut candidates = Vec::new();
        for item in fields[4].split(',').map(str::trim) {
            let (name, address) = if let Some((name, ip)) = item.split_once('=') {
                (name, Some(ip.parse::<IpAddr>().map_err(|_| Error::Scope)?))
            } else { (item, None) };
            crate::camouflage_domain_dns::validate_manual_dns_request(name, crate::camouflage_domain_dns::DnsConsent::Approved).map_err(|_| Error::Scope)?;
            if candidates.iter().any(|(prior, _)| prior == name) { return Err(Error::Scope); }
            candidates.push((name.to_owned(), address));
        }
        if candidates.is_empty() || candidates.len() > 3 { return Err(Error::Scope); }
        let grants: Vec<String> = fields[5].split(',').map(|v| v.trim().to_owned()).collect();
        if grants.len() > 256 || grants.iter().any(|v| !config::valid_id(v)) || grants.iter().collect::<std::collections::HashSet<_>>().len() != grants.len() { return Err(Error::Grant); }
        let automatic = match fields[6].as_str() { "auto" => true, "manual" => false, _ => return Err(Error::Format) };
        let parent = config.parent().ok_or(Error::Storage)?;
        let health = parent.join(format!("{}.health.toml", fields[0]));
        let bundle = parent.join(format!("{}.reality", fields[0]));
        let input = Self { config, source, id: fields[0].clone(), listen, endpoint, own_ips, candidates, grants, automatic, health, bundle };
        input.check_source()?;
        Ok(input)
    }
    fn plan(&self, references: Vec<reference_health::Target>) -> Result<reference_health::Plan, Error> {
        let plan = reference_health::Plan { schema_version: 1, inbound: self.id.clone(), endpoint: self.endpoint.clone(), own_ips: self.own_ips.clone(), references };
        plan.digest().map_err(|_| Error::Health)?;
        Ok(plan)
    }
    async fn resolve(&self) -> Result<reference_health::Plan, Error> {
        let mut references = Vec::new();
        for (name, pinned) in &self.candidates {
            let ip = match pinned {
                Some(ip) => *ip,
                None => {
                    let mut addresses = crate::camouflage_domain_dns::resolve_manual_domain(name, crate::camouflage_domain_dns::DnsConsent::Approved).await.map_err(|_| Error::Health)?;
                    addresses.sort();
                    addresses.into_iter().find(|ip| !self.own_ips.contains(ip)).ok_or(Error::Health)?
                }
            };
            references.push(reference_health::Target { server_name: name.clone(), address: SocketAddr::new(ip, 443) });
        }
        self.plan(references)
    }
}
fn rank_checked(input: &WizardInput, plan: reference_health::Plan, evidence: Vec<reference_health::Evidence>, now: u64) -> Result<(reference_health::State, String), Error> {
    if plan.references.len() != evidence.len() { return Err(Error::Health); }
    let mut entries: Vec<_> = plan.references.into_iter().zip(evidence).collect();
    let mut report = String::from("Оценки: 100 = стабильные H2+H3, 80 = стабильный H2, 0 = отказ.\n");
    for (target, item) in &entries { report.push_str(&format!("{} {}: {}\n", target.server_name, target.address, item.score())); }
    if input.automatic {
        entries.retain(|(_, item)| item.eligible());
        entries.sort_by_key(|(_, item)| std::cmp::Reverse(item.score()));
    }
    // Manual mode preserves the exact operator order and refuses any
    // failed reference. Auto may only remove/reorder approved pins.
    let (targets, observed): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
    let plan = input.plan(targets)?;
    let state = reference_health::State::new(plan, observed, now).map_err(|_| Error::Health)?;
    report.push_str(&state.plan().preview().map_err(|_| Error::Health)?);
    report.push_str("\nОсновной — первый; остальные — резервы. Создать health и private bundle? Runtime не меняется.\ny: создать; n/Esc: отменить.");
    Ok((state, report))
}

enum WizardStage {
    Input,
    DnsConfirm(Box<WizardInput>),
    Resolving(Receiver<Result<(WizardInput, reference_health::Plan), Error>>),
    ProbeConfirm(Box<(WizardInput, reference_health::Plan)>),
    Checking(Receiver<Result<(WizardInput, reference_health::State, String), Error>>, tokio::sync::oneshot::Sender<()>),
    CreateConfirm(Box<(WizardInput, reference_health::State, String)>),
    Saving(Receiver<Result<RegistrationPanel, Error>>),
    Done(String),
}
struct Wizard {
    config: PathBuf,
    source: [u8; 32],
    fields: [String; 7],
    focus: usize,
    stage: WizardStage,
    error: String,
    registration: Option<RegistrationPanel>,
}
impl Wizard {
    fn new(editor: &Editor) -> Result<Self, &'static str> {
        editor.require_clean_records()?;
        if editor.role() != Role::Server { return Err("Требуется серверная конфигурация."); }
        let config = std::path::absolute(editor.saved_path()).map_err(|_| "Недопустимый путь TOML.")?;
        let id = crate::tui_editor::generated_id("inbound")?;
        Ok(Self { config, source: editor.saved_sha256(), fields: [
            id, "0.0.0.0:443".into(), String::new(), String::new(),
            crate::camouflage_discovery::POPULAR_HTTPS_DOMAINS[..3].join(","),
            String::new(), "auto".into(),
        ], focus: 1, stage: WizardStage::Input, error: String::new(), registration: None })
    }
    fn paste(&mut self, text: &str) {
        if let Some(panel) = self.registration.as_mut() { panel.paste(text); return; }
        if matches!(self.stage, WizardStage::Input) {
            let field = &mut self.fields[self.focus];
            let value = text.trim_end_matches(['\r','\n']);
            if !value.chars().any(char::is_control) && field.len().saturating_add(value.len()) <= LIMIT { field.push_str(value); }
        }
    }
    fn key(&mut self, key: KeyEvent) -> bool {
        if let Some(panel) = self.registration.as_mut() { return panel.key(key); }
        let old = std::mem::replace(&mut self.stage, WizardStage::Input);
        self.stage = match old {
            WizardStage::Input => {
                match key.code {
                    KeyCode::Esc => return true,
                    KeyCode::Tab => self.focus = (self.focus + 1) % self.fields.len(),
                    KeyCode::BackTab => self.focus = (self.focus + self.fields.len() - 1) % self.fields.len(),
                    KeyCode::Backspace => { self.fields[self.focus].pop(); }
                    KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => self.fields[self.focus].clear(),
                    KeyCode::Enter => {
                        match WizardInput::parse(self.config.clone(), self.source, &self.fields) {
                            Ok(input) => { self.error.clear(); self.stage = WizardStage::DnsConfirm(Box::new(input)); return false; }
                            Err(error) => self.error = format!("ОТКАЗ: {error}"),
                        }
                    }
                    KeyCode::Char(ch) if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT) && !ch.is_control() && self.fields[self.focus].len() + ch.len_utf8() <= LIMIT => self.fields[self.focus].push(ch),
                    _ => {}
                }
                WizardStage::Input
            }
            WizardStage::DnsConfirm(input) if key.code == KeyCode::Char('y') && key.modifiers.is_empty() => {
                let input = *input;
                let (tx, rx) = mpsc::channel();
                let _worker = std::thread::spawn(move || {
                    let result = input.check_source().and_then(|()| {
                        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Error::Storage)?;
                        let plan = rt.block_on(input.resolve())?;
                        Ok((input, plan))
                    });
                    let _ = tx.send(result);
                });
                WizardStage::Resolving(rx)
            }
            WizardStage::ProbeConfirm(value) if key.code == KeyCode::Char('y') && key.modifiers.is_empty() => {
                let (input, plan) = *value;
                let (tx, rx) = mpsc::channel();
                let (cancel, cancelled) = tokio::sync::oneshot::channel();
                let _worker = std::thread::spawn(move || {
                    let result = input.check_source().and_then(|()| {
                        let approved = plan.digest().map_err(|_| Error::Health)?;
                        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Error::Storage)?;
                        let evidence = rt.block_on(async { tokio::select! {
                            biased;
                            _ = cancelled => Err(Error::Health),
                            value = reference_health::check(&plan, approved) => value.map_err(|_| Error::Health),
                        } })?;
                        let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
                        let (state, report) = rank_checked(&input, plan, evidence, now)?;
                        Ok((input, state, report))
                    });
                    let _ = tx.send(result);
                });
                WizardStage::Checking(rx, cancel)
            }
            WizardStage::CreateConfirm(value) if key.code == KeyCode::Char('y') && key.modifiers.is_empty() => {
                let (input, state, _) = *value;
                let (tx, rx) = mpsc::channel();
                let _worker = std::thread::spawn(move || {
                    let result = (|| {
                        input.check_source()?;
                        let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
                        let preview = reality_provision::preview(&state, now)?;
                        reference_health::Store::new(&input.health).and_then(|s| s.enroll(&state)).map_err(|_| Error::Storage)?;
                        let record = reality_provision::create(&state, preview.health_sha256, &input.bundle, now)?;
                        let request = ServerRequest {
                            health: input.health, bundle: input.bundle, health_sha256: preview.health_sha256,
                            identity_sha256: record.identity_sha256, listen: input.listen, grants: input.grants,
                        };
                        // Validate the exact saved TOML and prepared material
                        // again before presenting a separate registration.
                        reality_config::prepare(&input.config, &reality_config::Request::Server(request.clone()), now)?;
                        RegistrationPanel::from_provision(input.config, input.source, request)
                    })();
                    let _ = tx.send(result);
                });
                WizardStage::Saving(rx)
            }
            WizardStage::DnsConfirm(_) | WizardStage::ProbeConfirm(_) | WizardStage::CreateConfirm(_) if matches!(key.code, KeyCode::Esc | KeyCode::Char('n')) => WizardStage::Input,
            WizardStage::Checking(_, cancel) if key.code == KeyCode::Esc => { let _ = cancel.send(()); WizardStage::Input }
            WizardStage::Resolving(_) if key.code == KeyCode::Esc => WizardStage::Input,
            WizardStage::Done(_) if key.code == KeyCode::Esc => return true,
            other => other,
        };
        false
    }
    fn poll(&mut self) -> Option<Editor> {
        if let Some(panel) = self.registration.as_mut() { return panel.poll(); }
        let result = match &self.stage {
            WizardStage::Resolving(rx) => match rx.try_recv() {
                Ok(value) => value.map(|v| WizardStage::ProbeConfirm(Box::new(v))),
                Err(TryRecvError::Empty) => return None, Err(TryRecvError::Disconnected) => Err(Error::Health),
            },
            WizardStage::Checking(rx, _) => match rx.try_recv() {
                Ok(value) => value.map(|v| WizardStage::CreateConfirm(Box::new(v))),
                Err(TryRecvError::Empty) => return None, Err(TryRecvError::Disconnected) => Err(Error::Health),
            },
            WizardStage::Saving(rx) => match rx.try_recv() {
                Ok(Ok(panel)) => { self.registration = Some(panel); return None; }
                Ok(Err(error)) => Ok(WizardStage::Done(format!("ОТКАЗ: {error}. Возможно сохранены локальные материалы; проверьте их вручную. Runtime не изменён. Esc: закрыть."))),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Ok(WizardStage::Done("Неопределённая запись материалов. Не повторяйте вслепую. Esc: закрыть.".into())),
            },
            _ => return None,
        };
        self.stage = match result { Ok(stage) => stage, Err(error) => { self.error = format!("ОТКАЗ: {error}"); WizardStage::Input } };
        None
    }
    fn body(&self) -> String {
        if let Some(panel) = &self.registration { return panel.body(); }
        match &self.stage {
            WizardStage::Input => {
                let mut out = String::from("Новый REALITY inbound. Без TLS cert/key.\n");
                for (i, (label, value)) in WIZARD_LABELS.iter().zip(&self.fields).enumerate() { out.push_str(&format!("{} {label}: {value}\n", if i == self.focus { ">" } else { " " })); }
                out.push_str("auto: подобрать по оценкам; manual: сохранить порядок.\nEnter: проверить поля; Tab: поле; Ctrl+U: очистить; Esc: отменить.\n");
                out.push_str(&self.error); out
            }
            WizardStage::DnsConfirm(input) => format!("DNS: только перечисленные домены без заданного IP.\n{}\nНет TLS/QUIC соединений. y: DNS; n/Esc: отменить.", input.candidates.iter().map(|(name, ip)| format!("{name}: {}", ip.map_or("DNS".into(), |ip| ip.to_string()))).collect::<Vec<_>>().join("\n")),
            WizardStage::Resolving(_) => "Ограниченный DNS. Esc: отменить ожидание, без TLS/записи.".into(),
            WizardStage::ProbeConfirm(value) => format!("Проверить только эти IP:443 и SNI (public PKI, H2/H3 HEAD):\n{}\ny: проверить; n/Esc: отменить.", value.1.preview().unwrap_or_else(|_| "Неверный план".into())),
            WizardStage::Checking(_, _) => "Проверка согласованных IP; Esc: отменить без записи.".into(),
            WizardStage::CreateConfirm(value) => value.2.clone(),
            WizardStage::Saving(_) => "Создание локальных материалов; не закрывайте экран. Runtime не меняется.".into(),
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
        if let Some(wizard) = self.wizard.as_mut() { wizard.paste(text); return; }
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

    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        if let Some(wizard) = self.wizard.as_mut() { return wizard.key(key); }
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
        if let Some(wizard) = self.wizard.as_mut() { return wizard.poll(); }
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

    pub(crate) fn body(&self) -> String {
        if let Some(wizard) = &self.wizard { return wizard.body(); }
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
    fn bound_wizard_keeps_dns_probe_creation_and_registration_separate() {
        let dir = std::env::temp_dir().join(format!("theia-typed-wizard-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.toml");
        std::fs::write(&path, include_str!("../../../examples/server.toml").replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64))).unwrap();
        let editor = Editor::load(Role::Server, &path).unwrap();
        let mut wizard = Wizard::new(&editor).unwrap();
        wizard.fields[1] = "127.0.0.1:9443".into();
        wizard.fields[2] = "127.0.0.1".into();
        wizard.fields[3] = "127.0.0.1".into();
        wizard.fields[4] = "first.example.org=93.184.216.2,second.example.org=93.184.216.3".into();
        wizard.fields[5] = "device-a".into();
        let input = WizardInput::parse(path.clone(), editor.saved_sha256(), &wizard.fields).unwrap();
        let plan = input.plan(vec![
            reference_health::Target { server_name: "first.example.org".into(), address: "93.184.216.2:443".parse().unwrap() },
            reference_health::Target { server_name: "second.example.org".into(), address: "93.184.216.3:443".parse().unwrap() },
        ]).unwrap();
        let evidence = vec![reference_health::Evidence { h2_status: Some(200), h3_status: None }, reference_health::Evidence { h2_status: Some(200), h3_status: Some(200) }];
        let now = reference_health::unix_now().unwrap();
        let (state, report) = rank_checked(&input, plan.clone(), evidence.clone(), now).unwrap();
        let mut manual = input.clone();
        manual.automatic = false;
        let (ordered, _) = rank_checked(&manual, plan.clone(), evidence.clone(), now).unwrap();
        assert_eq!(ordered.plan().references[0].server_name, "first.example.org");
        let mut failed = evidence.clone();
        failed[0] = Evidence { h2_status: None, h3_status: None };
        assert!(rank_checked(&manual, plan.clone(), failed.clone(), now).is_err());
        let (filtered, _) = rank_checked(&input, plan.clone(), failed, now).unwrap();
        assert_eq!(filtered.plan().references.len(), 1);
        assert!(rank_checked(&input, plan.clone(), Vec::new(), now).is_err());
        let resolved = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
            .block_on(input.resolve()).unwrap();
        assert_eq!(resolved.digest().unwrap(), plan.digest().unwrap());
        assert_eq!(state.plan().references[0].server_name, "second.example.org");
        assert!(report.contains("100") && report.contains("80"));
        assert!(!input.bundle.exists() && !input.health.exists());
        wizard.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(wizard.stage, WizardStage::DnsConfirm(_)));
        wizard.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(wizard.stage, WizardStage::Input));
        assert!(!input.bundle.exists() && !input.health.exists());
        let original = std::fs::read(&path).unwrap();
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
            if let Some(editor) = wizard.poll() { break editor; }
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
