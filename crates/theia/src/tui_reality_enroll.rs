//! Client enrollment UI for the independently pinned REALITY trust store.
//! Reads explicit protected local files, never starts a proxy or changes
//! the active own-TLS profile. All file operations run outside terminal I/O.
use crate::{
    reality_bootstrap::{self as bootstrap, EnrollmentMaterial, Error, ImportApproval, Invitation},
    reference_health,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, TryRecvError},
};
use zeroize::Zeroizing;

const LIMIT: usize = 1024;
const LABELS: [&str; 6] = [
    "Приглашение (ссылка или файл)",
    "Файл допуска (admission)",
    "Новый файл профиля",
    "Хранилище доверия",
    "Отпечаток сервера (Fingerprint)",
    "Ссылка на токен (если его нет в приглашении)",
];

struct Input {
    source: PathBuf,
    inline: Option<Zeroizing<String>>,
    admission: PathBuf,
    profile: PathBuf,
    trust: PathBuf,
    identity: [u8; 32],
    token: Option<Zeroizing<String>>,
}

struct Review {
    approval: ImportApproval,
    admission: [u8; 32],
    body: String,
}

fn source_uri(input: &Input) -> Result<Zeroizing<String>, Error> {
    if let Some(uri) = &input.inline {
        if uri.len() > bootstrap::MAX_URI || !uri.starts_with(crate::invite::PREFIX) {
            return Err(Error::Format);
        }
        return Ok(uri.clone());
    }
    if !crate::bounded_input::explicit_file_path(&input.source) {
        return Err(Error::Storage);
    }
    bootstrap::read_text(&input.source, bootstrap::MAX_URI, true)
}

fn inspect(input: &Input, now: u64) -> Result<Review, Error> {
    for path in [&input.admission, &input.profile, &input.trust] {
        if !crate::bounded_input::explicit_file_path(path) {
            return Err(Error::Storage);
        }
    }
    if input.profile == input.trust {
        return Err(Error::Storage);
    }
    for path in [&input.profile, &input.trust] {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(Error::Storage),
        }
    }
    let uri = source_uri(input)?;
    let invitation = Invitation::decode(&uri, now)?;
    if invitation.fingerprint() != input.identity {
        return Err(Error::Approval);
    }
    if invitation.has_token() == input.token.is_some() {
        return Err(Error::Credential);
    }
    if let Some(token) = &input.token {
        if !crate::config::valid_secret_ref(token) {
            return Err(Error::Credential);
        }
    }
    let admission = invitation.admission_preview(&input.admission)?;
    let approval = ImportApproval {
        document_sha256: bootstrap::digest(&uri),
        identity_sha256: input.identity,
    };
    let body = format!("ПРЕДПРОСМОТР: fingerprint совпал с введённым значением.\n{}\nAdmission-файл проверен; секрет будет скопирован в защищённое хранилище.\nTransport/XHTTP: auto. CA не требуется.\nСохранение отдельного профиля не меняет active profile, proxy или runtime.\ny: сохранить; n/Esc: отменить.",
        invitation.preview(now)?);
    Ok(Review {
        approval,
        admission,
        body,
    })
}

fn apply(input: &Input, review: Review, now: u64) -> Result<String, Error> {
    let uri = source_uri(input)?;
    bootstrap::import(
        &uri,
        review.approval,
        &input.profile,
        &input.trust,
        EnrollmentMaterial {
            admission_path: &input.admission,
            expected_admission: Some(review.admission),
            external_token: input.token.as_ref().map(|value| value.as_str()),
        },
        bootstrap::auto_policy(),
        now,
    )?;
    Ok("Профиль REALITY и доверие сохранены. Runtime НЕ изменён.\nEsc: закрыть.".into())
}

fn create_first_client(
    path: &Path,
    input: &Input,
    review: Review,
    now: u64,
) -> Result<crate::tui_editor::Editor, Error> {
    use crate::{config, reality_config, Role};
    let mut owned = crate::tui_staged_material::StagedMaterial::create_for_new_config(
        input.profile.parent().ok_or(Error::Storage)?,
        path,
    )?;
    match apply(input, review, now) {
        Ok(_) => {}
        Err(Error::Indeterminate) => {
            owned.preserve();
            return Err(Error::Indeterminate);
        }
        Err(error) => {
            owned.cleanup()?;
            return Err(error);
        }
    }
    let request = reality_config::ClientRequest {
        enrollment: input.profile.clone(),
        identity_sha256: input.identity,
        id: crate::tui_editor::generated_id("profile").map_err(|_| Error::Storage)?,
    };
    let candidate = match reality_config::first_client_candidate(&request, now) {
        Ok(candidate) => candidate,
        Err(error) => {
            owned.cleanup()?;
            return Err(error);
        }
    };
    match config::guarded_create(path, &candidate) {
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
    crate::tui_editor::Editor::load(Role::Client, path).map_err(|_| Error::Indeterminate)
}

enum Stage {
    Input,
    Loading(Receiver<Result<Review, Error>>),
    Confirm(Review),
    Applying(Receiver<Result<(String, Option<crate::tui_staged_material::StagedMaterial>), Error>>),
    Creating(Receiver<Result<crate::tui_editor::Editor, Error>>),
    Done(String),
}

pub(crate) struct EnrollmentPanel {
    fields: [Zeroizing<String>; 6],
    focus: usize,
    stage: Stage,
    error: Option<String>,
    config: Option<(PathBuf, [u8; 32])>,
    new_config: Option<PathBuf>,
    registration: Option<crate::tui_reality_register::RegistrationPanel>,
    owned: Option<crate::tui_staged_material::StagedMaterial>,
    browser: Option<crate::tui_menu::FileBrowser>,
}

impl EnrollmentPanel {
    pub(crate) fn new() -> Self {
        Self {
            fields: std::array::from_fn(|_| Zeroizing::new(String::new())),
            focus: 0,
            stage: Stage::Input,
            error: None,
            config: None,
            new_config: None,
            registration: None,
            owned: None,
            browser: None,
        }
    }

    pub(crate) fn first(path: PathBuf) -> Result<Self, &'static str> {
        let path = std::path::absolute(path).map_err(|_| "Недопустимый путь TOML")?;
        if !crate::bounded_input::explicit_file_path(&path)
            || !matches!(std::fs::symlink_metadata(&path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
            || !path.parent().is_some_and(Path::is_dir)
        {
            return Err("Укажите новый клиентский TOML в существующем каталоге.");
        }
        let root = path
            .parent()
            .ok_or("Недопустимый путь TOML")?
            .join(crate::tui_editor::generated_id(".theia-enroll")?);
        let mut panel = Self::new();
        panel.fields[2] = Zeroizing::new(
            root.join("profile.toml")
                .to_str()
                .ok_or("Недопустимый путь")?
                .to_owned(),
        );
        panel.fields[3] = Zeroizing::new(
            root.join("trust.toml")
                .to_str()
                .ok_or("Недопустимый путь")?
                .to_owned(),
        );
        panel.new_config = Some(path);
        Ok(panel)
    }

    pub(crate) fn first_from_source(
        path: PathBuf,
        source: Zeroizing<String>,
    ) -> Result<Self, &'static str> {
        if source.len() > bootstrap::MAX_URI {
            return Err("Приглашение превышает лимит v1.");
        }
        let mut panel = Self::first(path)?;
        panel.fields[0] = source;
        panel.focus = 1;
        Ok(panel)
    }

    fn managed_paths(&self) -> bool {
        self.config.is_some() || self.new_config.is_some()
    }

    pub(crate) fn bound(editor: &crate::tui_editor::Editor) -> Result<Self, &'static str> {
        editor.require_clean_records()?;
        let mut panel = Self::new();
        let path =
            std::path::absolute(editor.saved_path()).map_err(|_| "Недопустимый путь TOML")?;
        let root = path
            .parent()
            .ok_or("Недопустимый путь TOML")?
            .join(crate::tui_editor::generated_id(".theia-enroll")?);
        panel.fields[2] = Zeroizing::new(
            root.join("profile.toml")
                .to_str()
                .ok_or("Недопустимый путь")?
                .to_owned(),
        );
        panel.fields[3] = Zeroizing::new(
            root.join("trust.toml")
                .to_str()
                .ok_or("Недопустимый путь")?
                .to_owned(),
        );
        panel.config = Some((path, editor.saved_sha256()));
        Ok(panel)
    }

    pub(crate) fn from_source(
        editor: &crate::tui_editor::Editor,
        source: Zeroizing<String>,
    ) -> Result<Self, &'static str> {
        if source.len() > bootstrap::MAX_URI {
            return Err("Приглашение превышает лимит v1.");
        }
        let mut panel = Self::bound(editor)?;
        panel.fields[0] = source;
        panel.focus = 1;
        Ok(panel)
    }

    fn limit(&self) -> usize {
        if self.focus == 0 {
            bootstrap::MAX_URI
        } else {
            LIMIT
        }
    }

    fn input(&self) -> Result<Input, Error> {
        let path = |i: usize| PathBuf::from(self.fields[i].as_str());
        let identity = crate::parse_restart_digest(&self.fields[4]).ok_or(Error::Approval)?;
        let token = (!self.fields[5].is_empty()).then(|| self.fields[5].clone());
        Ok(Input {
            source: if self.fields[0].starts_with("theia://") {
                PathBuf::new()
            } else {
                path(0)
            },
            inline: self.fields[0]
                .starts_with("theia://")
                .then(|| self.fields[0].clone()),
            admission: path(1),
            profile: path(2),
            trust: path(3),
            identity,
            token,
        })
    }

    pub(crate) fn paste(&mut self, value: &str) {
        if self.browser.is_some() {
            return;
        }
        if let Some(panel) = self.registration.as_mut() {
            panel.paste(value);
            return;
        }
        if !matches!(self.stage, Stage::Input) {
            return;
        }
        if self.managed_paths() && matches!(self.focus, 2 | 3) {
            return;
        }
        let value = value.trim_end_matches(['\r', '\n']);
        let limit = self.limit();
        let field = &mut self.fields[self.focus];
        if !value.chars().any(char::is_control) && field.len().saturating_add(value.len()) <= limit
        {
            field.push_str(value);
        }
    }

    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        if let Some(browser) = self.browser.as_mut() {
            if key.code == KeyCode::Esc {
                self.browser = None;
                return false;
            }
            if let Some(path) = browser.key(key.code, "") {
                if let Some(path) = path.to_str().filter(|s| !s.chars().any(char::is_control)) {
                    let limit = if self.focus == 0 {
                        bootstrap::MAX_URI
                    } else {
                        LIMIT
                    };
                    if path.len() <= limit {
                        self.fields[self.focus] = Zeroizing::new(path.to_owned());
                        self.error = None;
                    } else {
                        self.error = Some("Путь слишком длинный. Выберите другой файл.".into());
                    }
                }
                self.browser = None;
            }
            return false;
        }
        if let Some(panel) = self.registration.as_mut() {
            return panel.key(key);
        }
        match &self.stage {
            Stage::Loading(_) | Stage::Applying(_) | Stage::Creating(_) => return false,
            Stage::Done(_) => {
                if key.code == KeyCode::Char('g') && (self.config.is_none() || self.owned.is_some())
                {
                    if let (Some((path, digest)), Ok(input)) = (&self.config, self.input()) {
                        match crate::tui_reality_register::RegistrationPanel::from_enrollment(
                            path.clone(),
                            *digest,
                            &input.profile,
                            input.identity,
                        ) {
                            Ok(panel) => {
                                self.registration = Some(match self.owned.take() {
                                    Some(owned) => panel.own_material(owned),
                                    None => panel,
                                })
                            }
                            Err(error) => self.error = Some(error.to_string()),
                        }
                    }
                }
                if key.code == KeyCode::Esc {
                    if let Some(mut owned) = self.owned.take() {
                        if owned.cleanup().is_err() {
                            self.stage = Stage::Done(format!("Очистка не подтверждена; проверьте каталог {:?}. Для полного enrollment используйте M после независимой проверки. Esc: закрыть.", owned.root()));
                            return false;
                        }
                    }
                    return true;
                }
                return false;
            }
            Stage::Confirm(_) => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('n') => self.stage = Stage::Input,
                    KeyCode::Char('y') if key.modifiers.is_empty() => {
                        let Ok(input) = self.input() else {
                            self.stage = Stage::Input;
                            return false;
                        };
                        let Stage::Confirm(review) =
                            std::mem::replace(&mut self.stage, Stage::Input)
                        else {
                            return false;
                        };
                        if let Some(path) = self.new_config.clone() {
                            let (tx, rx) = mpsc::channel();
                            self.stage = Stage::Creating(rx);
                            let _worker = std::thread::spawn(move || {
                                let result = reference_health::unix_now()
                                    .map_err(|_| Error::Clock)
                                    .and_then(|now| {
                                        create_first_client(&path, &input, review, now)
                                    });
                                let _ = tx.send(result);
                            });
                            return false;
                        }
                        let (tx, rx) = mpsc::channel();
                        self.stage = Stage::Applying(rx);
                        let config = self.config.clone();
                        let _worker = std::thread::spawn(move || {
                            let result = (|| {
                                let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
                                let mut owned = config
                                    .as_ref()
                                    .map(|(path, digest)| {
                                        crate::tui_staged_material::StagedMaterial::create(
                                            input.profile.parent().ok_or(Error::Storage)?,
                                            path,
                                            *digest,
                                        )
                                    })
                                    .transpose()?;
                                match apply(&input, review, now) {
                                    Ok(message) => Ok((message, owned)),
                                    Err(Error::Indeterminate) => {
                                        if let Some(guard) = &mut owned {
                                            guard.preserve();
                                        }
                                        Err(Error::Indeterminate)
                                    }
                                    Err(error) => {
                                        if let Some(guard) = &mut owned {
                                            guard.cleanup()?;
                                        }
                                        Err(error)
                                    }
                                }
                            })();
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
            KeyCode::F(6) if self.focus <= 1 => {
                self.browser = Some(crate::tui_menu::FileBrowser::files(
                    self.fields[self.focus].as_str(),
                ));
            }
            KeyCode::F(8) => {
                self.focus = if self.focus < 4 { 4 } else { 0 };
            }
            KeyCode::Tab | KeyCode::Down => {
                self.focus = (self.focus + 1) % LABELS.len();
                if self.managed_paths() && self.focus == 2 {
                    self.focus = 4;
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = (self.focus + LABELS.len() - 1) % LABELS.len();
                if self.managed_paths() && self.focus == 3 {
                    self.focus = 1;
                }
            }
            KeyCode::Backspace => {
                self.fields[self.focus].pop();
                self.error = None;
            }
            KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                self.fields[self.focus] = Zeroizing::new(String::new());
                self.error = None;
            }
            KeyCode::Enter
                if self.managed_paths()
                    && self.focus < 4
                    && !self.fields[0].is_empty()
                    && !self.fields[1].is_empty()
                    && self.fields[4].is_empty() =>
            {
                self.focus = 4;
                self.error = None;
            }
            KeyCode::Enter if self.fields[0].is_empty() => {
                self.focus = 0;
                self.error = Some(
                    "Нет приглашения. Вставьте ссылку или выберите присланный файл (F6).".into(),
                );
            }
            KeyCode::Enter if self.fields[1].is_empty() => {
                self.focus = 1;
                self.error = Some(
                    "Нет файла допуска. Попросите его у администратора и выберите через F6.".into(),
                );
            }
            KeyCode::Enter if crate::parse_restart_digest(&self.fields[4]).is_none() => {
                self.focus = 4;
                self.error=Some("Отпечаток должен состоять из 64 шестнадцатеричных символов. Сверьте его с администратором отдельно от приглашения.".into());
            }
            KeyCode::Enter => match self.input() {
                Ok(input) => {
                    let (tx, rx) = mpsc::channel();
                    self.error = None;
                    self.stage = Stage::Loading(rx);
                    let _worker = std::thread::spawn(move || {
                        let result = reference_health::unix_now()
                            .map_err(|_| Error::Clock)
                            .and_then(|now| inspect(&input, now));
                        let _ = tx.send(result);
                    });
                }
                Err(error) => self.error = Some(error.to_string()),
            },
            KeyCode::Char(ch)
                if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                    && !ch.is_control()
                    && self.fields[self.focus].len() + ch.len_utf8() <= self.limit() =>
            {
                self.fields[self.focus].push(ch);
            }
            _ => {}
        }
        false
    }

    pub(crate) fn poll(&mut self) -> Option<crate::tui_editor::Editor> {
        if let Some(panel) = self.registration.as_mut() {
            return panel.poll();
        }
        let result = match &self.stage {
            Stage::Loading(rx) => match rx.try_recv() {
                Ok(result) => result.map(Stage::Confirm),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Err(Error::Storage),
            },
            Stage::Creating(rx) => match rx.try_recv() {
                Ok(Ok(editor)) => return Some(editor),
                Ok(Err(error)) => Err(error),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Err(Error::Indeterminate),
            },
            Stage::Applying(rx) => match rx.try_recv() {
                Ok(result) => result.map(|(message, owned)| {
                    self.owned = owned;
                    Stage::Done(message)
                }),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Err(Error::Indeterminate),
            },
            _ => return None,
        };
        match result {
            Ok(stage) => {
                self.stage = stage;
                if matches!(&self.stage, Stage::Done(_)) && self.owned.is_some() {
                    if let (Some((path, digest)), Ok(input)) = (&self.config, self.input()) {
                        match crate::tui_reality_register::RegistrationPanel::from_enrollment(
                            path.clone(),
                            *digest,
                            &input.profile,
                            input.identity,
                        ) {
                            Ok(panel) => {
                                if let Some(owned) = self.owned.take() {
                                    self.registration = Some(panel.own_material(owned));
                                }
                            }
                            Err(error) => self.error = Some(error.to_string()),
                        }
                    }
                }
            }
            Err(error) => {
                self.error = Some(format!(
                    "ОТКАЗ: {error}. При неопределённой записи проверьте файлы перед повтором."
                ));
                self.stage = if error == Error::Indeterminate {
                    Stage::Done(format!("ОТКАЗ: неопределённая запись. Проверьте подготовленный профиль {:?}; повтор заблокирован.", Path::new(self.fields[2].as_str())))
                } else {
                    Stage::Input
                };
            }
        }
        None
    }

    pub(crate) fn form(&self) -> Option<crate::tui_widgets::Form> {
        use crate::tui_widgets::{Field, Form};
        if let Some(browser) = &self.browser {
            return Some(browser.form());
        }
        if let Some(panel) = &self.registration {
            return panel.form();
        }
        if !matches!(self.stage, Stage::Input) {
            return None;
        }
        let hints = [
            "Вставьте ссылку theia:// или нажмите F6, чтобы выбрать присланный файл приглашения.",
            "Попросите администратора прислать файл допуска отдельно от ссылки. F6 — выбрать этот файл.",
            "Абсолютный путь нового файла профиля.",
            "Абсолютный путь нового хранилища доверия.",
            "Сверьте отпечаток (64 шестнадцатеричных символа) с администратором по другому доверенному каналу.",
            "Только env:/file: ссылка, если в приглашении нет токена.",
        ];
        Some(Form {
            fields: LABELS
                .iter()
                .enumerate()
                .filter(|(id, _)| {
                    !self.managed_paths() || (if self.focus < 4 { *id < 2 } else { *id >= 4 })
                })
                .map(|(id, label)| Field {
                    id,
                    label,
                    hint: hints[id],
                    value: if self.fields[id].is_empty() {
                        String::new()
                    } else {
                        format!("Скрыто · {} байт", self.fields[id].len())
                    },
                })
                .collect(),
            selected: self.focus,
            lead: if self.managed_paths() && self.focus < 4 {
                "1. Получите приглашение и отдельный файл допуска у администратора. Далее — проверка отпечатка (F8 или Tab).".into()
            } else {
                "Отпечаток сверяется независимо от приглашения. Ссылка на токен нужна только при его отсутствии в приглашении. Значения скрыты.".into()
            },
            error: self.error.clone().unwrap_or_default(),
        })
    }

    pub(crate) fn select_field(&mut self, id: usize) {
        if let Some(browser) = self.browser.as_mut() {
            browser.select_field(id);
            return;
        }
        if let Some(panel) = self.registration.as_mut() {
            panel.select_field(id);
            return;
        }
        if matches!(self.stage, Stage::Input)
            && id < LABELS.len()
            && (!self.managed_paths() || !matches!(id, 2 | 3))
        {
            self.focus = id;
        }
    }

    pub(crate) fn guide(&self) -> (usize, usize, &'static str, &'static str) {
        let total = if self.managed_paths() { 5 } else { 3 };
        if self.browser.is_some() {
            return (
                1,
                total,
                "Выбор локального файла",
                "↑↓ выбрать · Enter выбрать путь · Esc назад",
            );
        }
        if self.registration.is_some() {
            return (
                4,
                total,
                "Сохранение профиля",
                "Enter предпросмотр · y сохранить · Esc отменить",
            );
        }
        match &self.stage {
            Stage::Input if self.managed_paths() && self.focus < 4 => (
                2,
                5,
                "REALITY · приглашение и файл допуска",
                "↑↓ поле · F6 файл · F8 далее · Enter продолжить · Esc назад",
            ),
            Stage::Input if self.managed_paths() => (
                3,
                5,
                "Проверка доверия и ключа",
                "↑↓ поле · F8 назад · Enter проверить · Ctrl+U очистить · Esc отменить",
            ),
            Stage::Input => (
                1,
                3,
                "Приглашение и доверие",
                "↑↓ поле · F8 раздел · Enter проверить · Ctrl+U очистить · Esc назад",
            ),
            Stage::Loading(_) => (
                if self.managed_paths() { 3 } else { total - 1 },
                total,
                "Проверка приглашения",
                "Идёт локальная проверка",
            ),
            Stage::Confirm(_) => (
                if self.managed_paths() { 3 } else { total - 1 },
                total,
                "Подтверждение доверия",
                "Y сохранить · N / Esc назад",
            ),
            Stage::Applying(_) | Stage::Creating(_) => (
                if self.managed_paths() { 4 } else { total },
                total,
                "Сохранение",
                "Идёт запись; подключения нет",
            ),
            Stage::Done(_) => (
                total,
                total,
                "Результат",
                "G зарегистрировать, если доступно · Esc назад",
            ),
        }
    }

    pub(crate) fn body(&self) -> String {
        if let Some(panel) = &self.registration {
            return panel.body();
        }
        match &self.stage {
            Stage::Input => {
                let mut out = String::from("ШАГ 1 · Приглашение и доверие\n\nЛокальные абсолютные пути; значения скрыты.\n");
                for (i, label) in LABELS.iter().enumerate() {
                    if self.managed_paths() && matches!(i, 2 | 3) {
                        continue;
                    }
                    out.push_str(&format!(
                        "{} {label}: {} ({} bytes)\n",
                        if i == self.focus { ">" } else { " " },
                        if self.fields[i].is_empty() {
                            "[пусто]"
                        } else {
                            "[скрыто]"
                        },
                        self.fields[i].len()
                    ));
                }
                out.push_str("\nFingerprint введите из отдельного доверенного канала. Bearer: только env:/file: ссылка, не значение.\nEnter: предпросмотр; Tab: поле; Ctrl+U: очистить; Esc: отменить.\n");
                out.push_str(self.error.as_deref().unwrap_or(""));
                out
            }
            Stage::Loading(_) => {
                "Проверка локального приглашения и admission; без сети и записи.".into()
            }
            Stage::Confirm(review) => {
                if let Some(path) = &self.new_config {
                    format!("{}\n\nПервый TOML: {}\nНовый профиль станет активным в TOML. Системный прокси выключен.\ny: создать TOML и enrollment; n/Esc: назад.", review.body, path.display())
                } else {
                    review.body.clone()
                }
            }
            Stage::Applying(_) | Stage::Creating(_) => {
                "Сохранение защищённого профиля; runtime не меняется.".into()
            }
            Stage::Done(body) => {
                if self.config.is_some() && self.owned.is_some() {
                    format!("{body}\nСледующий шаг: g — зарегистрировать созданный enrollment в сохранённом TOML (отдельный preview/confirm).\n{}",self.error.as_deref().unwrap_or(""))
                } else {
                    body.clone()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        descriptor::Scope,
        identity_tls::Identity,
        reality_admission::Secret,
        reference_health::{Evidence, Plan, State, Target},
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn preview_binds_independent_identity_and_admission_without_exposing_secret() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "theia-enroll-ui-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
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
        let identity = Identity::generate(Scope {
            inbound: "edge".into(),
            endpoint: "edge.example.org:443".into(),
        })
        .unwrap();
        let document = bootstrap::initial_descriptor(&state, &identity, 1000).unwrap();
        let invite = Invitation::public(&identity, &document, 1000).unwrap();
        let uri = invite.encode().unwrap();
        let mut input = Input {
            source: dir.join("invitation"),
            inline: None,
            admission: dir.join("admission"),
            profile: dir.join("profile"),
            trust: dir.join("trust"),
            identity: [0; 32],
            token: Some(Zeroizing::new("env:TEST_BEARER".into())),
        };
        bootstrap::create_text(&input.source, &uri).unwrap();
        Secret::generate()
            .unwrap()
            .save_new(identity.scope(), &input.admission)
            .unwrap();
        assert!(matches!(inspect(&input, 1000), Err(Error::Approval)));
        input.identity = invite.fingerprint();
        let review = inspect(&input, 1000).unwrap();
        assert!(!review.body.contains(uri.as_str()));
        input.inline = Some(uri.clone());
        let inline = inspect(&input, 1000).unwrap();
        assert_eq!(
            inline.approval.document_sha256,
            review.approval.document_sha256
        );
        assert_eq!(inline.admission, review.admission);
        input.inline = None;
        assert!(!review.body.contains("env:TEST_BEARER"));
        assert!(!input.profile.exists() && !input.trust.exists());
        std::fs::remove_file(&input.admission).unwrap();
        Secret::generate()
            .unwrap()
            .save_new(identity.scope(), &input.admission)
            .unwrap();
        assert_eq!(apply(&input, review, 1000), Err(Error::Approval));
        assert!(!input.profile.exists() && !input.trust.exists());
        let review = inspect(&input, 1000).unwrap();
        assert!(apply(&input, review, 1000)
            .unwrap()
            .contains("Runtime НЕ изменён"));
        let profile = bootstrap::Profile::read(&input.profile).unwrap();
        assert!(profile.admission().is_ok());
        assert!(profile.load(1000).is_ok());

        // Fresh configuration uses the same independent verification and
        // does not require an existing or placeholder Own-TLS profile.
        let cfg = dir.join("client.toml");
        let root = dir.join("first-material");
        input.profile = root.join("profile.toml");
        input.trust = root.join("trust.toml");
        let review = inspect(&input, 1000).unwrap();
        assert!(!cfg.exists() && !root.exists());
        let editor = create_first_client(&cfg, &input, review, 1000).unwrap();
        assert!(editor.selected_reality());
        let bytes = std::fs::read(&cfg).unwrap();
        let crate::config::Config::Client(doc) =
            crate::config::parse(std::str::from_utf8(&bytes).unwrap()).unwrap()
        else {
            panic!("client expected");
        };
        assert_eq!(doc.client.profiles.len(), 1);
        assert_eq!(doc.client.active_profile, doc.client.profiles[0].id);
        assert_eq!(
            doc.client.proxy.system_proxy,
            crate::config::SystemProxy::Off
        );
        assert!(!String::from_utf8_lossy(&bytes).contains(uri.as_str()));
        assert!(
            crate::tui_staged_material::StagedMaterial::create_for_new_config(
                &dir.join("second-material"),
                &cfg
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&cfg).unwrap(), bytes);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wizard_handoff_keeps_original_config_binding_and_requires_profile_id() {
        let mut panel = EnrollmentPanel::new();
        use sha2::{Digest, Sha256};
        let dir =
            std::env::temp_dir().join(crate::tui_editor::generated_id("enroll-handoff").unwrap());
        std::fs::create_dir(&dir).unwrap();
        let cfg = dir.join("client.toml");
        std::fs::write(&cfg, include_str!("../../../examples/client.toml")).unwrap();
        let digest = Sha256::digest(std::fs::read(&cfg).unwrap()).into();
        let root = dir.join("enrollment");
        panel.owned =
            Some(crate::tui_staged_material::StagedMaterial::create(&root, &cfg, digest).unwrap());
        panel.config = Some((cfg.clone(), digest));
        panel.fields[2] = Zeroizing::new(root.join("profile.toml").to_string_lossy().into_owned());
        panel.fields[4] = Zeroizing::new("ab".repeat(32));
        panel.stage = Stage::Done("saved".into());
        panel.key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        assert!(panel.registration.is_some());
        assert!(panel.body().contains("ID профиля"));
        assert!(panel.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(!root.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn source_fields_are_masked_and_cancel_is_read_only() {
        let mut panel = EnrollmentPanel::new();
        panel.paste("SECRET-NEVER-DISPLAY");
        assert!(!panel.body().contains("SECRET-NEVER-DISPLAY"));
        assert!(panel.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
    }

    #[test]
    fn input_validation_and_async_refusal_preserve_unwritten_enrollment() {
        let mut p = EnrollmentPanel::new();
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        p.key(key(KeyCode::Enter));
        assert!(p.error.is_some());
        p.key(key(KeyCode::Char('a')));
        p.key(key(KeyCode::Backspace));
        p.key(key(KeyCode::Tab));
        p.key(key(KeyCode::BackTab));
        p.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert!(p.fields[0].is_empty());
        let dir =
            std::env::temp_dir().join(format!("theia-enrollment-missing-{}", std::process::id()));
        assert!(!dir.exists());
        for (i, field) in ["invitation", "admission", "profile", "trust"]
            .into_iter()
            .enumerate()
        {
            p.fields[i] = Zeroizing::new(dir.join(field).to_str().unwrap().to_owned());
        }
        p.fields[4] = Zeroizing::new("ab".repeat(32));
        p.key(key(KeyCode::Enter));
        assert!(matches!(p.stage, Stage::Loading(_)));
        assert!(p.body().contains("без сети и записи"));
        assert!(!p.key(key(KeyCode::Esc)));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while matches!(p.stage, Stage::Loading(_)) {
            p.poll();
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(p.body().contains("ОТКАЗ"));
        let (tx, rx) = mpsc::channel();
        p.stage = Stage::Applying(rx);
        assert!(p.body().contains("runtime не меняется"));
        drop(tx);
        assert!(p.poll().is_none());
        assert!(p.body().contains("ОТКАЗ"));
        assert!(!dir.exists());
    }
}
