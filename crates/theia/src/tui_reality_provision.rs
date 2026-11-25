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

impl ProvisionPanel {
    pub(crate) fn new() -> Self {
        Self {
            fields: std::array::from_fn(|_| String::new()),
            focus: 0,
            stage: Stage::Input,
            error: None,
        }
    }

    fn paths(&self) -> (PathBuf, PathBuf, PathBuf) {
        (
            PathBuf::from(&self.fields[0]),
            PathBuf::from(&self.fields[1]),
            PathBuf::from(&self.fields[2]),
        )
    }

    pub(crate) fn paste(&mut self, text: &str) {
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

    pub(crate) fn poll(&mut self) {
        let result = match &self.stage {
            Stage::Loading(rx) => match rx.try_recv() {
                Ok(result) => result.map(Stage::Confirm),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => Err(Error::Storage),
            },
            Stage::LoadingPlan(rx) => match rx.try_recv() {
                Ok(result) => result.map(Stage::ConfirmPlan),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => Err(Error::Storage),
            },
            Stage::Checking { result, .. } => match result.try_recv() {
                Ok(result) => result.map(Stage::Confirm),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => Err(Error::Health),
            },
            Stage::Applying(rx) => match rx.try_recv() {
                Ok(result) => result.map(Stage::Done),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => Err(Error::Indeterminate),
            },
            _ => return,
        };
        match result {
            Ok(stage) => self.stage = stage,
            Err(error) => {
                let message = format!("ОТКАЗ: {error}. При частичной записи проверьте каталог; автоматическое удаление запрещено.");
                self.stage = Stage::Input;
                self.error = Some(message);
            }
        }
    }

    pub(crate) fn body(&self) -> String {
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
            p.poll();
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
            p.poll();
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
        p.poll();
        tx.send(Ok(PlanReview {
            digest: [1; 32],
            body: "consent".into(),
        }))
        .unwrap();
        p.poll();
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
        p.poll();
        assert!(p.body().contains("ОТКАЗ"));
        assert!(matches!(p.stage, Stage::Input));
    }
}
