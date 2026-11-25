//! Register the already verified local materials in the ordinary typed
//! editor. Preview and save are separate; a dirty or externally changed
//! config never gets silently replaced. No live Apply is implied.
use crate::{
    config,
    reality_bootstrap::Error,
    reality_config::{self, ClientRequest, Request, ServerReplacement, ServerRequest},
    reference_health,
    tui_editor::Editor,
    Role,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, TryRecvError},
};

const SERVER_FIELDS: [&str; 6] = [
    "Health store",
    "Каталог комплекта",
    "Health SHA-256",
    "Identity SHA-256 (независимое подтверждение)",
    "TCP/UDP bind",
    "Разрешённые ID через запятую",
];
const CLIENT_FIELDS: [&str; 3] = [
    "Файл enrollment",
    "Identity SHA-256 (независимое подтверждение)",
    "Новый ID профиля",
];
const REENROLL_FIELDS: [&str; 2] = [
    "Новый отдельно импортированный enrollment",
    "Новый identity SHA-256 из независимого канала",
];
const REPLACE_SERVER_FIELDS: [&str; 4] = [
    "Новый health store",
    "Новый bundle",
    "Health SHA-256",
    "Новый fingerprint из независимого канала",
];
const MAX_FIELD: usize = 1024;

struct Review {
    request: Request,
    approval: [u8; 32],
    body: String,
}
enum Stage {
    Input,
    Preview(Receiver<Result<Review, Error>>),
    Confirm(Review),
    Saving(Receiver<Result<Editor, SaveError>>),
    Done(String),
}
enum SaveError {
    Refused(Error),
    SavedReloadFailed,
}

pub(crate) struct RegistrationPanel {
    role: Role,
    reenroll_id: Option<String>,
    config: PathBuf,
    original: [u8; 32],
    fields: Vec<String>,
    focus: usize,
    stage: Stage,
    error: Option<String>,
}

fn labels(role: Role) -> &'static [&'static str] {
    match role {
        Role::Server => &SERVER_FIELDS,
        Role::Client => &CLIENT_FIELDS,
    }
}

fn hash(value: &str) -> Result<[u8; 32], Error> {
    crate::parse_restart_digest(value).ok_or(Error::Approval)
}

fn build_request(role: Role, fields: &[String]) -> Result<Request, Error> {
    if fields.len() != labels(role).len() {
        return Err(Error::Format);
    }
    match role {
        Role::Server => {
            let listen: std::net::SocketAddr = fields[4].parse().map_err(|_| Error::Scope)?;
            let grants: Vec<String> = fields[5]
                .split(',')
                .map(str::trim)
                .map(str::to_owned)
                .collect();
            if listen.port() == 0
                || grants.len() > 256
                || grants.iter().any(|id| !config::valid_id(id))
            {
                return Err(Error::Grant);
            }
            Ok(Request::Server(ServerRequest {
                health: fields[0].as_str().into(),
                bundle: fields[1].as_str().into(),
                health_sha256: hash(&fields[2])?,
                identity_sha256: hash(&fields[3])?,
                listen,
                grants,
            }))
        }
        Role::Client => {
            if !config::valid_id(&fields[2]) {
                return Err(Error::Scope);
            }
            Ok(Request::Client(ClientRequest {
                enrollment: fields[0].as_str().into(),
                identity_sha256: hash(&fields[1])?,
                id: fields[2].clone(),
            }))
        }
    }
}

fn build_reenroll(id: &str, fields: &[String]) -> Result<Request, Error> {
    if fields.len() != REENROLL_FIELDS.len() || !config::valid_id(id) {
        return Err(Error::Format);
    }
    Ok(Request::Reenroll(ClientRequest {
        enrollment: fields[0].as_str().into(),
        identity_sha256: hash(&fields[1])?,
        id: id.to_owned(),
    }))
}

fn preview(path: &Path, original: [u8; 32], request: Request, now: u64) -> Result<Review, Error> {
    let prepared = reality_config::prepare(path, &request, now)?;
    if prepared.source_sha256() != original {
        return Err(Error::Approval);
    }
    let consent = if matches!(&request, Request::Reenroll(_) | Request::ReplaceServer(_)) {
        "Y (Shift+Y): подтвердить независимую замену identity; n/Esc: отменить."
    } else {
        "y: сохранить; n/Esc: отменить."
    };
    Ok(Review { request, approval: prepared.approval_sha256(),
        body: format!("{}\n\nСохранить только TOML? {consent}\nРаботающие listener/системный proxy не меняются.", prepared.report()) })
}

impl RegistrationPanel {
    pub(crate) fn new(editor: &Editor) -> Result<Self, &'static str> {
        let config = std::path::absolute(editor.saved_path())
            .map_err(|_| "Нужен абсолютный путь к конфигурации.")?;
        if !crate::bounded_input::explicit_file_path(&config) {
            return Err("Недопустимый путь конфигурации.");
        }
        let role = editor.role();
        let mut fields = vec![String::new(); labels(role).len()];
        if role == Role::Server {
            fields[4] = "0.0.0.0:443".into();
        }
        Ok(Self {
            role,
            reenroll_id: None,
            config,
            original: editor.saved_sha256(),
            fields,
            focus: 0,
            stage: Stage::Input,
            error: None,
        })
    }

    pub(crate) fn from_enrollment(
        config: PathBuf,
        original: [u8; 32],
        enrollment: &std::path::Path,
        identity: [u8; 32],
    ) -> Result<Self, Error> {
        if !crate::bounded_input::explicit_file_path(&config) {
            return Err(Error::Storage);
        }
        let fields = vec![
            enrollment.to_str().ok_or(Error::Storage)?.to_owned(),
            identity
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            String::new(),
        ];
        Ok(Self {
            role: Role::Client,
            reenroll_id: None,
            config,
            original,
            fields,
            focus: 2,
            stage: Stage::Input,
            error: None,
        })
    }

    pub(crate) fn reenroll(editor: &Editor) -> Result<Self, &'static str> {
        if !editor.selected_reality() {
            return Err("Выберите зарегистрированный REALITY-профиль.");
        }
        let mut panel = Self::new(editor)?;
        panel.reenroll_id = Some(editor.selected_record_id().to_owned());
        panel.fields = vec![
            String::new();
            if editor.role() == Role::Server {
                REPLACE_SERVER_FIELDS.len()
            } else {
                REENROLL_FIELDS.len()
            }
        ];
        Ok(panel)
    }

    fn request(&self) -> Result<Request, Error> {
        if let Some(id) = &self.reenroll_id {
            if self.role == Role::Server {
                if self.fields.len() != REPLACE_SERVER_FIELDS.len() {
                    return Err(Error::Format);
                }
                Ok(Request::ReplaceServer(ServerReplacement {
                    id: id.clone(),
                    health: self.fields[0].as_str().into(),
                    bundle: self.fields[1].as_str().into(),
                    health_sha256: hash(&self.fields[2])?,
                    identity_sha256: hash(&self.fields[3])?,
                }))
            } else {
                build_reenroll(id, &self.fields)
            }
        } else {
            build_request(self.role, &self.fields)
        }
    }

    pub(crate) fn paste(&mut self, text: &str) {
        if !matches!(self.stage, Stage::Input) {
            return;
        }
        let value = text.trim_end_matches(['\r', '\n']);
        let field = &mut self.fields[self.focus];
        if !value.chars().any(char::is_control)
            && field.len().saturating_add(value.len()) <= MAX_FIELD
        {
            field.push_str(value);
        }
    }

    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        match &self.stage {
            Stage::Preview(_) | Stage::Saving(_) => return false,
            Stage::Done(_) => return key.code == KeyCode::Esc,
            Stage::Confirm(_) => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('n') => self.stage = Stage::Input,
                    KeyCode::Char('y')
                        if self.reenroll_id.is_none() && key.modifiers.is_empty() =>
                    {
                        self.save_confirmed();
                    }
                    KeyCode::Char('Y')
                        if self.reenroll_id.is_some()
                            && (key.modifiers.is_empty()
                                || key.modifiers == KeyModifiers::SHIFT) =>
                    {
                        self.save_confirmed();
                    }
                    _ => {}
                }
                return false;
            }
            Stage::Input => {}
        }
        self.input_key(key)
    }

    fn save_confirmed(&mut self) {
        let role = self.role;
        let Stage::Confirm(review) = std::mem::replace(&mut self.stage, Stage::Input) else {
            return;
        };
        let path = self.config.clone();
        let (tx, rx) = mpsc::channel();
        self.stage = Stage::Saving(rx);
        let _worker = std::thread::spawn(move || {
            let result = reference_health::unix_now()
                .map_err(|_| Error::Clock)
                .and_then(|now| reality_config::apply(&path, &review.request, review.approval, now))
                .map_err(SaveError::Refused)
                .and_then(|()| Editor::load(role, &path).map_err(|_| SaveError::SavedReloadFailed));
            let _ = tx.send(result);
        });
    }

    fn input_key(&mut self, key: KeyEvent) -> bool {
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
            KeyCode::Enter => match self.request() {
                Ok(request) => {
                    let path = self.config.clone();
                    let original = self.original;
                    let (tx, rx) = mpsc::channel();
                    self.error = None;
                    self.stage = Stage::Preview(rx);
                    let _worker = std::thread::spawn(move || {
                        let result = reference_health::unix_now()
                            .map_err(|_| Error::Clock)
                            .and_then(|now| preview(&path, original, request, now));
                        let _ = tx.send(result);
                    });
                }
                Err(error) => self.error = Some(error.to_string()),
            },
            KeyCode::Char(ch)
                if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                    && !ch.is_control()
                    && self.fields[self.focus].len() + ch.len_utf8() <= MAX_FIELD =>
            {
                self.fields[self.focus].push(ch);
            }
            _ => {}
        }
        false
    }

    pub(crate) fn poll(&mut self) -> Option<Editor> {
        match &self.stage {
            Stage::Preview(rx) => match rx.try_recv() {
                Ok(Ok(review)) => self.stage = Stage::Confirm(review),
                Ok(Err(error)) => {
                    self.error = Some(format!("ОТКАЗ: {error}"));
                    self.stage = Stage::Input;
                }
                Err(TryRecvError::Disconnected) => {
                    self.error = Some("Проверка прервана.".into());
                    self.stage = Stage::Input;
                }
                Err(TryRecvError::Empty) => {}
            },
            Stage::Saving(rx) => {
                match rx.try_recv() {
                    Ok(Ok(editor)) => {
                        self.stage = Stage::Done("Запись сохранена, редактор перечитан. Runtime НЕ изменён.\nEsc: закрыть.".into());
                        return Some(editor);
                    }
                    Ok(Err(SaveError::Refused(Error::Indeterminate)))
                    | Err(TryRecvError::Disconnected) => {
                        self.stage = Stage::Done("Неопределённая запись. Проверьте файл и заново откройте редактор, не повторяйте автоматически.\nEsc: закрыть.".into());
                    }
                    Ok(Err(SaveError::SavedReloadFailed)) => {
                        self.stage = Stage::Done("TOML сохранён, перечитать редактор не удалось. Откройте заново; runtime не изменён.\nEsc: закрыть.".into());
                    }
                    Ok(Err(SaveError::Refused(error))) => {
                        self.error = Some(format!("ОТКАЗ: {error}"));
                        self.stage = Stage::Input;
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }
            _ => {}
        }
        None
    }

    pub(crate) fn body(&self) -> String {
        match &self.stage {
            Stage::Input => {
                let (mut out, labels) = if let Some(id) = &self.reenroll_id {
                    if self.role == Role::Server {
                        (format!("Независимая замена bundle выбранного inbound {id}. Сначала подготовьте новый комплект. Не штатная ротация.\n"),REPLACE_SERVER_FIELDS.as_slice())
                    } else {
                        (format!("Независимый повторный enrollment выбранного профиля {id}. Не штатная ротация. Сначала импортируйте новое приглашение через I.\n"),REENROLL_FIELDS.as_slice())
                    }
                } else {
                    (String::from("Регистрация уже подготовленных материалов. Только сохранение, не запуск.\n"), labels(self.role))
                };
                for (i, label) in labels.iter().enumerate() {
                    // No private keys, bearer or paths need to be rendered.
                    let value = if self.role == Role::Server && i >= 4
                        || self.role == Role::Client && i == 2
                    {
                        self.fields[i].as_str()
                    } else if self.fields[i].is_empty() {
                        "[пусто]"
                    } else {
                        "[введено]"
                    };
                    out.push_str(&format!(
                        "{} {label}: {value}\n",
                        if self.focus == i { ">" } else { " " }
                    ));
                }
                out.push_str("Enter: проверить; Tab: поле; Ctrl+U: очистить; Esc: отменить.\n");
                out.push_str(self.error.as_deref().unwrap_or(""));
                out
            }
            Stage::Preview(_) => {
                "Локальная проверка конфигурации и доверия. Запись не выполняется.".into()
            }
            Stage::Confirm(review) => review.body.clone(),
            Stage::Saving(_) => "Атомарное сохранение с повторной проверкой материалов.".into(),
            Stage::Done(message) => message.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reenrollment_request_cannot_change_selected_id() {
        let fields = vec!["/local/new".into(), "11".repeat(32)];
        let Request::Reenroll(req) = build_reenroll("selected", &fields).unwrap() else {
            panic!()
        };
        assert_eq!(req.id, "selected");
        assert!(build_reenroll("selected", &fields[..1]).is_err());
    }

    #[test]
    fn grants_and_hashes_are_required_before_preview() {
        let mut fields = vec![String::new(); SERVER_FIELDS.len()];
        fields[0] = "/local/health".into();
        fields[1] = "/local/bundle".into();
        fields[2] = "11".repeat(32);
        fields[3] = "22".repeat(32);
        fields[4] = "127.0.0.1:443".into();
        assert!(matches!(
            build_request(Role::Server, &fields),
            Err(Error::Grant)
        ));
        fields[5] = "device-a, device-b".into();
        let Request::Server(req) = build_request(Role::Server, &fields).unwrap() else {
            panic!()
        };
        assert_eq!(req.grants, vec!["device-a", "device-b"]);
        fields[3] = "invalid".into();
        assert!(matches!(
            build_request(Role::Server, &fields),
            Err(Error::Approval)
        ));
    }
}
