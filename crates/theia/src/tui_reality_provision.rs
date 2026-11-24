//! Explicit local provisioning wizard. Uses the existing approved health
//! inventory and exact digest. No live server configuration or grants are
//! modified. All filesystem operations are off the terminal event loop.
use crate::{reality_bootstrap::Error, reality_provision, reference_health};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{path::{Path, PathBuf}, sync::mpsc::{self, Receiver, TryRecvError}};

const LIMIT: usize = 1024;

struct Review {
    digest: [u8; 32],
    body: String,
}

enum Stage {
    Input,
    Loading(Receiver<Result<Review, Error>>),
    Confirm(Review),
    Applying(Receiver<Result<String, Error>>),
    Done(String),
}

pub(crate) struct ProvisionPanel {
    fields: [String; 2],
    focus: usize,
    stage: Stage,
    error: Option<String>,
}

fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(64);
    for byte in bytes { let _ = write!(output, "{byte:02x}"); }
    output
}

fn validate_paths(health: &Path, output: &Path) -> Result<(), Error> {
    if !crate::bounded_input::explicit_file_path(health)
        || !crate::bounded_input::explicit_file_path(output)
        || health == output || output.file_name().is_none() {
        return Err(Error::Storage);
    }
    match std::fs::symlink_metadata(output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(Error::Storage),
    }
}

fn read_state(path: &Path) -> Result<reference_health::State, Error> {
    reference_health::Store::new(path).map_err(|_| Error::Storage)?
        .inspect().map_err(|_| Error::Health)
}

fn preview(health: &Path, output: &Path, now: u64) -> Result<Review, Error> {
    validate_paths(health, output)?;
    let state = read_state(health)?;
    let review = reality_provision::preview(&state, now)?;
    let body = format!("ПРЕДПРОСМОТР: только локальный комплект, не live Apply.\n{}\n{}\nhealth_sha256={}\nplan_sha256={}\nКаталог: {}\nIdentity, admission и descriptor создаются автоматически.\nПрава пользователей и runtime не меняются.\ny: создать новый комплект; Esc/n: отменить.",
        state.plan().preview().map_err(|_| Error::Health)?,
        state.report(now).map_err(|_| Error::Health)?,
        hex(review.health_sha256), hex(review.plan_sha256), output.display());
    Ok(Review { digest: review.health_sha256, body })
}

fn apply(health: &Path, output: &Path, approved: [u8; 32], now: u64) -> Result<String, Error> {
    validate_paths(health, output)?;
    let state = read_state(health)?;
    let record = reality_provision::create(&state, approved, output, now)?;
    Ok(format!("Комплект сохранён. Runtime НЕ изменён.\nidentity_sha256={}\npublication_sha256={}\nEsc: закрыть.",
        hex(record.identity_sha256), hex(record.publication_sha256)))
}

impl ProvisionPanel {
    pub(crate) fn new() -> Self {
        Self { fields: [String::new(), String::new()], focus: 0, stage: Stage::Input, error: None }
    }

    fn paths(&self) -> (PathBuf, PathBuf) {
        (PathBuf::from(&self.fields[0]), PathBuf::from(&self.fields[1]))
    }

    pub(crate) fn paste(&mut self, text: &str) {
        if !matches!(self.stage, Stage::Input) { return; }
        let value = text.trim_end_matches(['\r', '\n']);
        let field = &mut self.fields[self.focus];
        if !value.chars().any(char::is_control) && field.len().saturating_add(value.len()) <= LIMIT {
            field.push_str(value);
        }
    }

    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        match &self.stage {
            Stage::Loading(_) | Stage::Applying(_) => return false,
            Stage::Done(_) => return key.code == KeyCode::Esc,
            Stage::Confirm(review) => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('n') => { self.stage = Stage::Input; }
                    KeyCode::Char('y') if key.modifiers.is_empty() => {
                        let digest = review.digest;
                        let (health, output) = self.paths();
                        let (tx, rx) = mpsc::channel();
                        self.stage = Stage::Applying(rx);
                        let _worker = std::thread::spawn(move || {
                            let result = reference_health::unix_now().map_err(|_| Error::Clock)
                                .and_then(|now| apply(&health, &output, digest, now));
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
            KeyCode::Tab | KeyCode::BackTab => self.focus = 1 - self.focus,
            KeyCode::Backspace => { self.fields[self.focus].pop(); }
            KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => self.fields[self.focus].clear(),
            KeyCode::Enter => {
                let (health, output) = self.paths();
                let (tx, rx) = mpsc::channel();
                self.error = None;
                self.stage = Stage::Loading(rx);
                let _worker = std::thread::spawn(move || {
                    let result = reference_health::unix_now().map_err(|_| Error::Clock)
                        .and_then(|now| preview(&health, &output, now));
                    let _ = tx.send(result);
                });
            }
            KeyCode::Char(ch) if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT) && !ch.is_control() => {
                if self.fields[self.focus].len() + ch.len_utf8() <= LIMIT { self.fields[self.focus].push(ch); }
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
            Stage::Input => format!("Укажите абсолютный путь к свежему, ранее согласованному reference health store и новый каталог.\n{} Health: {}\n{} Каталог: {}\nEnter: локальный предпросмотр; Tab: поле; Esc: отменить.\nСеть не используется. Для новой проверки используйте reference enroll/recheck.\n{}",
                if self.focus == 0 { ">" } else { " " }, self.fields[0],
                if self.focus == 1 { ">" } else { " " }, self.fields[1],
                self.error.as_deref().unwrap_or("")),
            Stage::Loading(_) => "Чтение и проверка локальных данных; запись не начата.".into(),
            Stage::Confirm(review) => review.body.clone(),
            Stage::Applying(_) => "Создание нового защищённого комплекта. Runtime не изменяется.".into(),
            Stage::Done(message) => message.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_health::{Evidence, Plan, Target, State, Store};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn exact_preview_rejects_changed_health_and_existing_output() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("theia-provision-ui-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&dir).unwrap();
        let health = dir.join("health");
        let output = dir.join("output");
        let state = State::new(Plan { schema_version: 1, inbound: "edge".into(), endpoint: "edge.example.org:443".into(),
            own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: vec![Target { server_name: "reference.example.org".into(), address: "93.184.216.2:443".parse().unwrap() }] },
            vec![Evidence { h2_status: Some(200), h3_status: None }], 1000).unwrap();
        Store::new(&health).unwrap().enroll(&state).unwrap();
        let review = preview(&health, &output, 1000).unwrap();
        assert!(review.body.contains("reference.example.org"));
        assert!(!output.exists());
        assert!(matches!(apply(&health, &output, [0; 32], 1000), Err(Error::Approval)));
        assert!(matches!(apply(&health, &output, review.digest, 1061), Err(Error::Health)));
        assert!(!output.exists());
        let message = apply(&health, &output, review.digest, 1001).unwrap();
        assert!(message.contains("Runtime НЕ изменён"));
        assert!(preview(&health, &output, 1001).is_err());
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
        panel.stage = Stage::Confirm(Review { digest: [1;32], body: "review".into() });
        panel.key(key(KeyCode::Char('n')));
        assert!(matches!(panel.stage, Stage::Input));
        assert!(panel.key(key(KeyCode::Esc)));
    }
}
