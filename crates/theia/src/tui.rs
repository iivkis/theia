//! M4.1: keyboard-first terminal landing and bounded config editor.
//!
//! M4.1c edits safe fields; M4.4b adds one-time server issuance and reveal.
//! Explicit runtime and Windows proxy actions are isolated in confirmed panels.
use crate::{
    client_import,
    invite::Invitation,
    tui_candidate_batch::CandidateBatchPanel,
    tui_candidates::CandidateReview,
    tui_discovery::DiscoveryPanel,
    tui_domain::DomainPanel,
    tui_editor::{Editor, RecordAction, RecordReview},
    tui_menu::{Action as MenuAction, ConfigDialog, FileBrowser, Menu},
    tui_probe::ProbePanel,
    tui_reality_enroll::EnrollmentPanel,
    tui_reality_provision::ProvisionPanel,
    tui_reality_register::RegistrationPanel,
    tui_reality_status::StatusPanel,
    tui_runtime::RuntimePanel,
    tui_server_process::ProcessPanel,
    tui_widgets::{self, action_layout, Actions, ActionItem, Field, Form, ReferenceReview, ACCENT, BG, ERROR, FOCUS, INPUT, MUTED, SURFACE, TEXT, WARNING},
    Role,
};
use crossterm::{
    cursor::{Hide, Show},
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
        Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
        MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph, Row, Table, Wrap},
    Frame, Terminal,
};
use std::{
    cell::Cell,
    fmt,
    hash::{Hash, Hasher},
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    sync::mpsc::{self, TryRecvError},
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum TuiError {
    NotInteractive,
    Io,
    Configuration(&'static str),
}

impl TuiError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::NotInteractive => "interactive terminal required (stdin and stdout must be TTY)",
            Self::Io => "terminal initialization, drawing or input failed",
            Self::Configuration(reason) => reason,
        }
    }
}

impl fmt::Display for TuiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl From<io::Error> for TuiError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

/// Own terminal restoration even when draw or input fails, or a panic unwinds.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let guard = Self;
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            Hide,
            EnableBracketedPaste,
            EnableMouseCapture
        )?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            DisableMouseCapture,
            DisableBracketedPaste,
            Show,
            LeaveAlternateScreen
        );
        let _ = disable_raw_mode();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Home,
    Server,
    Client,
    Help,
}

#[derive(Debug, Clone, Copy)]
struct Model {
    selected: Role,
    screen: Screen,
    return_from_help: Screen,
}

impl Model {
    fn new(role: Option<Role>) -> Self {
        let selected = role.unwrap_or(Role::Server);
        let screen = match role {
            Some(Role::Server) => Screen::Server,
            Some(Role::Client) => Screen::Client,
            None => Screen::Home,
        };
        Self {
            selected,
            screen,
            return_from_help: screen,
        }
    }

    /// Returns true to quit. The read-only landing cannot acquire a dirty state.
    fn update(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Char('?') | KeyCode::F(1) => {
                if self.screen != Screen::Help {
                    self.return_from_help = self.screen;
                    self.screen = Screen::Help;
                }
                false
            }
            KeyCode::Esc => {
                self.screen = if self.screen == Screen::Help {
                    self.return_from_help
                } else {
                    Screen::Home
                };
                false
            }
            KeyCode::Char('1') if self.screen != Screen::Help => {
                self.selected = Role::Server;
                self.screen = Screen::Server;
                false
            }
            KeyCode::Char('2') if self.screen != Screen::Help => {
                self.selected = Role::Client;
                self.screen = Screen::Client;
                false
            }
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down
                if self.screen == Screen::Home =>
            {
                self.selected = if self.selected == Role::Server {
                    Role::Client
                } else {
                    Role::Server
                };
                false
            }
            KeyCode::Tab | KeyCode::BackTab if self.screen != Screen::Help => {
                self.selected = match self.selected {
                    Role::Server => Role::Client,
                    Role::Client => Role::Server,
                };
                if self.screen != Screen::Home {
                    self.screen = match self.selected {
                        Role::Server => Screen::Server,
                        Role::Client => Screen::Client,
                    };
                }
                false
            }
            KeyCode::Enter if self.screen == Screen::Home => {
                self.screen = match self.selected {
                    Role::Server => Screen::Server,
                    Role::Client => Screen::Client,
                };
                false
            }
            _ => false,
        }
    }
}

/// Creation and rotation both reveal a newly generated bearer only after
/// the guarded save succeeds. Existing user rotation never re-enables a user.
#[derive(Clone, Copy, PartialEq, Eq)]
enum IssueKind {
    NewUser,
    Rotation,
    Reenable,
}

/// Confidential bearer issuance is isolated from ordinary editor commands.
enum IssueFlow {
    Input(String),
    Confirm(String),
    Saving,
    SaveFailed,
    Offer,
    ConfirmExport,
    Exporting,
    Exported(PathBuf),
    ExportFailed,
    Showing(Zeroizing<String>),
    Public(String),
    ShareConfirm {
        action: crate::tui_share::Action,
        public: Option<String>,
    },
    Sharing,
    ShareDone(String),
}

/// Client-only F-14 local file/pasted URI import. Only safe fields may render.
/// A decoded invitation can hold a live bearer; no Debug and no cloning.
enum ImportFlow {
    Input(Zeroizing<String>),
    Preview {
        invitation: Invitation,
        ca: Option<String>,
        public_ref: Option<String>,
    },
    Trust {
        invitation: Invitation,
        ca: String,
        public_ref: Option<String>,
    },
    Credential {
        invitation: Invitation,
        ca: Option<String>,
        reference: String,
    },
    RefreshConfirm(Invitation),
    RefreshSaving,
    RefreshDone,
    Saving,
    Done,
    Failed,
}

/// A deliberate server-only global account disable. No bearer is displayed,
/// and a confirmed change stays pending until guarded TOML save succeeds.
enum DisableFlow {
    Input(String),
    Confirm(String),
    Saving,
    SaveFailed,
    Done,
}

/// UI dispatch is separate from all configuration/OS effects. A queued
/// transition never runs until the user saves, discards or cancels explicitly.
type ExportResult = (Editor, Result<PathBuf, &'static str>);

enum RecordFlow {
    ChooseMode(Role, usize),
    Input {
        action: RecordAction,
        fields: Vec<String>,
        focus: usize,
    },
    Confirm(Box<RecordReview>),
}

impl RecordFlow {
    fn form(&self, editor: Option<&Editor>) -> Option<Form> {
        if let Self::ChooseMode(role, selected) = self {
            let server = *role == Role::Server;
            return Some(Form {
                fields: vec![
                    Field { id: 0, label: "Own-TLS · свой сертификат", value: if server { "У меня есть сертификат и закрытый ключ" } else { "Ввести адрес и параметры доверия вручную" }.into(), hint: "Выбирайте, если у вас есть собственная TLS-инфраструктура." },
                    Field { id: 1, label: "SmartTheia REALITY", value: if server { "Мастер настройки без собственного сертификата" } else { "Импорт приглашения и проверка доверия" }.into(), hint: "Enter — открыть мастер. Запись и запуск потребуют отдельных действий." },
                ],
                selected: *selected,
                lead: "Выберите способ защиты подключения. Стрелки или мышь — выбор; Enter — продолжить.".into(),
                error: String::new(),
            });
        }
        let Self::Input { action, fields, focus } = self else { return None; };
        Some(Form {
            fields: action.fields().iter().zip(fields).enumerate().map(|(id, ((label, hidden), value))| Field {
                id, label, hint: if *hidden { "Только ссылка на материал, не секрет." } else { "Введите значение; Enter — предпросмотр." },
                value: if *hidden && !value.is_empty() { "[скрыто] · ссылка введена".into() } else { value.clone() },
            }).collect(),
            selected: *focus,
            lead: editor.and_then(|e| e.record_user_catalog(*action)).map_or_else(|| action.title().to_owned(), |catalog| format!("{}\n{catalog}", action.title())),
            error: editor.and_then(|e| e.error.clone()).unwrap_or_default(),
        })
    }
    fn select_field(&mut self, id: usize) {
        match self {
            Self::ChooseMode(_, selected) if id < 2 => *selected = id,
            Self::Input { fields, focus, .. } if id < fields.len() => *focus = id,
            _ => {}
        }
    }
    fn body(&self) -> String {
        match self {
            Self::ChooseMode(role, _) => format!("ВЫБЕРИТЕ РЕЖИМ\n\n  1   Own-TLS\n      {}\n\n  2   SmartTheia REALITY\n      {}\n\nEsc: назад. Сохранение не запускает runtime.", if *role == Role::Server {"Свой сертификат и ключ"} else {"Ручные параметры TLS"}, if *role == Role::Server {"Мастер проверки референсов, без своего сертификата"} else {"Импорт с независимым подтверждением доверия"}),
            Self::Confirm(review) => review.body().to_owned(),
            Self::Input {
                action,
                fields,
                focus,
            } => {
                let mut body = format!("{}\n", action.title());
                for (index, ((label, hidden), value)) in
                    action.fields().iter().zip(fields).enumerate()
                {
                    let marker = if index == *focus { '>' } else { ' ' };
                    let shown = if *hidden {
                        if value.is_empty() {
                            "[пусто]"
                        } else {
                            "[скрыто]"
                        }
                    } else {
                        value.as_str()
                    };
                    body.push_str(&format!("{marker} {label}: {shown}\n"));
                }
                body.push_str("\n↑↓ / Tab: поле; Ctrl+U: очистить; Enter: предпросмотр; Esc: отменить.\nВ скрытые поля вводите только ссылки, не секреты.");
                body
            }
        }
    }
}

struct QrScan {
    source: Zeroizing<String>,
    done: mpsc::Receiver<Result<Zeroizing<String>, &'static str>>,
    cancelled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkspaceFocus { Fields, Navigation, Actions, Users }

fn pages(role: Role) -> &'static [&'static str] {
    match role {
        Role::Server => &["Обзор", "Подключения", "Пользователи", "Приглашения", "Статистика", "Настройки", "Диагностика"],
        Role::Client => &["Обзор", "Профили", "Импорт", "Прокси", "Статистика", "Настройки", "Диагностика"],
    }
}

fn page_actions(role: Role, page: usize) -> Vec<ActionItem> {
    let entries: &[(char, &str)] = match (role, page) {
        (Role::Server, 0) => &[('s',"Запустить / остановить сервер"),('W',"Создать REALITY"),('N',"Новое подключение"),('v',"Проверить / применить изменения"),('u',"Добавить пользователя и приглашение"),('b',"Выдать доступ отключённому"),('S',"Сохранить настройки"),('o',"Открыть файл настроек")],
        (Role::Server, 1) => &[('N',"Создать подключение"),('W',"Мастер REALITY"),('V',"Состояние REALITY"),('G',"Настроить доступ"),('Q',"Лимиты"),('E',"Сертификат TLS"),('D',"Удалить подключение")],
        (Role::Server, 2) => &[('u',"Добавить пользователя"),('x',"Отключить"),('b',"Восстановить доступ"),('t',"Обновить токен"),('G',"Назначить доступ"),('U',"Удалить пользователя")],
        (Role::Server, 3) => &[('u',"Создать пользователя и приглашение"),('b',"Выдать приглашение отключённому"),('t',"Обновить приглашение"),('l',"Публичная ссылка")],
        (_, 4) => &[('4',"Открыть монитор трафика")],
        (Role::Server, 5) => &[('o',"Открыть файл"),('S',"Сохранить файл"),('v',"Статус и применение изменений"),('R',"Проверить готовность перезапуска"),('K',"Заменить доверие"),('M',"Регистрация материалов")],
        (Role::Server, 6) => &[('p',"Сетевая диагностика"),('V',"Состояние REALITY")],
        (Role::Client, 0) => &[('V',"Подключить / отключить"),('i',"Импорт приглашения"),('N',"Новый профиль"),('A',"Выбрать активный профиль"),('S',"Сохранить настройки"),('o',"Открыть файл настроек")],
        (Role::Client, 1) => &[('A',"Выбрать активный профиль"),('N',"Создать профиль"),('i',"Импорт"),('E',"Доверие Own-TLS"),('D',"Удалить профиль")],
        (Role::Client, 2) => &[('i',"Импорт ссылки или QR"),('I',"Импорт REALITY")],
        (Role::Client, 3) if cfg!(windows) => &[('p',"Управление системным прокси")],
        (Role::Client, 5) => &[('o',"Открыть файл"),('S',"Сохранить файл"),('V',"Состояние и применение"),('K',"Подтвердить доверие"),('M',"Регистрация материалов")],
        (Role::Client, 6) => &[('V',"Диагностика подключения")],
        _ => &[],
    };
    entries.iter().map(|(key,label)| ActionItem { key:*key, label:*label }).collect()
}

/// A recommendation is navigation only. It never writes, applies, or starts a process.
fn recommended_step(editor: &Editor, owned_running: bool) -> (char, &'static str) {
    if editor.write_uncertain() { return ('o', "Запись не подтверждена. Проверьте файл и откройте его заново (F3)."); }
    if editor.dirty() { return ('S', "Сохраните изменения. Работающий процесс не изменится автоматически."); }
    if editor.role() == Role::Server {
        if editor.record_count() == 0 { return ('W', "Создайте первое подключение."); }
        let users = editor.workspace_users();
        if !users.iter().any(|(_, disabled, granted)| !*disabled && *granted) {
            if users.iter().any(|(_, disabled, granted)| *disabled && *granted) {
                return ('b', "Выдайте приглашение первому пользователю: сейчас его доступ отключён.");
            }
            return ('u', "Создайте пользователя и получите его личное приглашение.");
        }
        if !owned_running { return ('s', "Запустите сервер, если он ещё не работает как внешний сервис."); }
        ('v', "Проверьте, применены ли сохранённые права доступа. Передайте приглашение клиенту безопасным способом.")
    } else if editor.record_count() == 0 {
        ('i', "Получите приглашение у администратора и импортируйте его.")
    } else if owned_running {
        ('V', "Локальный процесс запущен или запускается. Откройте его состояние для проверки туннеля.")
    } else if !editor.selected_record_is_active() {
        ('A', "Выберите этот профиль активным, если хотите подключаться через него.")
    } else {
        ('V', "Откройте подключение и подтвердите запуск. Системный прокси не включается автоматически.")
    }
}

fn invitation_actions(flow: &IssueFlow) -> Vec<ActionItem> {
    match flow {
        IssueFlow::Offer => vec![
            ActionItem { key: 'f', label: "Сохранить приглашение в файл" },
            ActionItem { key: 'Q', label: "Создать QR-код" },
            ActionItem { key: 'c', label: "Копировать в буфер обмена" },
            ActionItem { key: 'n', label: "Закрыть без выдачи" },
        ],
        IssueFlow::Public(_) => vec![
            ActionItem { key: 'Q', label: "Создать QR-код" },
            ActionItem { key: 'c', label: "Копировать в буфер обмена" },
        ],
        _ => Vec::new(),
    }
}

struct Interaction {
    workspace_page: usize,
    workspace_focus: WorkspaceFocus,
    workspace_action: usize,
    workspace_user: usize,
    value_preview: bool,
    preview_text: Option<String>,
    modal_action: usize,
    last_apply: Option<([u8;32], &'static str, u64)>,
    viewport: Viewport,
    welcome_choice: usize,
    editor: Option<Editor>,
    menu: Option<Menu>,
    config_dialog: Option<ConfigDialog>,
    server_process: ProcessPanel,
    show_server_process: bool,
    traffic_monitor: Option<crate::traffic::Monitor>,
    client_background: Option<StatusPanel>,
    issuance: Option<IssueFlow>,
    issue_kind: IssueKind,
    revocation: Option<DisableFlow>,
    importing: Option<ImportFlow>,
    import_browser: Option<FileBrowser>,
    qr_scan: Option<QrScan>,
    records: Option<RecordFlow>,
    discovery: Option<DiscoveryPanel>,
    candidates: Option<CandidateReview>,
    candidate_batch: Option<CandidateBatchPanel>,
    domain: Option<DomainPanel>,
    probe: Option<ProbePanel>,
    reality_provision: Option<ProvisionPanel>,
    reality_enrollment: Option<EnrollmentPanel>,
    reality_registration: Option<RegistrationPanel>,
    reality_status: Option<StatusPanel>,
    runtime: Option<RuntimePanel>,
    #[cfg(windows)]
    system_proxy: Option<crate::tui_system_proxy::Panel>,
    pending: Option<KeyEvent>,
    saving: Option<mpsc::Receiver<(Editor, bool)>>,
    exporting: Option<mpsc::Receiver<ExportResult>>,
    sharing: Option<mpsc::Receiver<Result<(PathBuf, bool), &'static str>>>,
    clipboard: Option<Zeroizing<String>>,
}

impl Interaction {
    fn new(editor: Option<Editor>) -> Self {
        Self {
            workspace_page: usize::from(editor.is_some()),
            workspace_focus: WorkspaceFocus::Fields,
            workspace_action: 0,
            workspace_user: 0,
            value_preview: false,
            preview_text: None,
            modal_action: 0,
            last_apply: None,
            viewport: Viewport::default(),
            welcome_choice: 0,
            editor,
            menu: None,
            config_dialog: None,
            server_process: ProcessPanel::new(),
            show_server_process: false,
            traffic_monitor: None,
            client_background: None,
            issuance: None,
            issue_kind: IssueKind::NewUser,
            revocation: None,
            importing: None,
            import_browser: None,
            qr_scan: None,
            records: None,
            discovery: None,
            candidates: None,
            candidate_batch: None,
            domain: None,
            probe: None,
            reality_provision: None,
            reality_enrollment: None,
            reality_registration: None,
            reality_status: None,
            runtime: None,
            #[cfg(windows)]
            system_proxy: None,
            pending: None,
            saving: None,
            exporting: None,
            sharing: None,
            clipboard: None,
        }
    }

    fn start_save(&mut self) {
        let Some(mut editor) = self.editor.take() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.saving = Some(rx);
        // File I/O and fsync never block terminal rendering or key dispatch.
        let _save_worker = std::thread::spawn(move || {
            let saved = editor.save();
            let _ = tx.send((editor, saved));
        });
    }

    fn start_export(&mut self) {
        let Some(mut editor) = self.editor.take() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.exporting = Some(rx);
        let _worker = std::thread::spawn(move || {
            let result = editor.export_issued_file();
            let _ = tx.send((editor, result));
        });
    }

    fn start_import(
        &mut self,
        invitation: Invitation,
        ca: Option<String>,
        public_ref: Option<String>,
    ) {
        let Some(mut editor) = self.editor.take() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.saving = Some(rx);
        let _worker = std::thread::spawn(move || {
            let saved = editor
                .import_invitation(&invitation, ca.as_deref(), public_ref.as_deref())
                .is_ok();
            let _ = tx.send((editor, saved));
        });
    }

    fn start_refresh(&mut self, invitation: Invitation) {
        let Some(mut editor) = self.editor.take() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.saving = Some(rx);
        let _worker = std::thread::spawn(move || {
            let saved = editor.refresh_credential(&invitation).is_ok();
            let _ = tx.send((editor, saved));
        });
    }

    fn paste_record_field(&mut self, text: &str) {
        if let Some(dialog) = self.config_dialog.as_mut() {
            dialog.paste(text.trim_end_matches(['\r', '\n']));
            return;
        }
        if let Some(panel) = self.reality_status.as_mut() {
            panel.paste(text);
            return;
        }
        if let Some(panel) = self.reality_registration.as_mut() {
            panel.paste(text);
            return;
        }
        if let Some(panel) = self.reality_enrollment.as_mut() {
            panel.paste(text);
            return;
        }
        if let Some(panel) = self.reality_provision.as_mut() {
            panel.paste(text);
            return;
        }
        if let Some(RecordFlow::Input { fields, focus, .. }) = self.records.as_mut() {
            let input = text.trim_end_matches(['\r', '\n']);
            if !input.chars().any(char::is_control)
                && fields[*focus].len().saturating_add(input.len()) <= 1024
            {
                fields[*focus].push_str(input);
            }
        }
    }

    /// Bracketed-paste source text stays in memory and is never rendered.
    fn paste_import_source(&mut self, text: &str) {
        if self.import_browser.is_some() { return; }
        if let Some(ImportFlow::Input(source)) = self.importing.as_mut() {
            let input = text.trim_end_matches(['\r', '\n']);
            if source.len().saturating_add(input.len()) <= crate::invite::MAX_URI
                && !input.contains('\0')
            {
                source.push_str(input);
            }
        }
    }

    fn poll_save(&mut self, model: &mut Model) -> Result<bool, TuiError> {
        if let Some(rx) = self.sharing.as_ref() {
            let message = match rx.try_recv() {
                Ok(Ok((path,true))) => format!("Защищённый QR SVG сохранён: {path:?}. QR содержит само приглашение; храните как исходную ссылку."),
                Ok(Ok((path,false))) => format!("Приглашение превышает вместимость одного QR. Сохранён полный защищённый URI-файл: {path:?}. Ничего не обрезано."),
                Ok(Err(error)) => format!("{error} Для конфиденциальной ссылки повторная выдача требует ротации."),
                Err(TryRecvError::Empty) => return Ok(false),
                Err(TryRecvError::Disconnected) => "Результат записи не подтверждён. Проверьте файлы; не повторяйте вслепую.".into(),
            };
            self.sharing = None;
            self.issuance = Some(IssueFlow::ShareDone(message));
            return Ok(false);
        }
        if let Some(receiver) = self.exporting.as_ref() {
            match receiver.try_recv() {
                Ok((mut editor, result)) => {
                    self.exporting = None;
                    self.issuance = Some(match result {
                        Ok(path) => IssueFlow::Exported(path),
                        Err(message) => {
                            editor.error = Some(message.into());
                            IssueFlow::ExportFailed
                        }
                    });
                    self.editor = Some(editor);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => return Err(TuiError::Io),
            }
            return Ok(false);
        }
        let Some(receiver) = self.saving.as_ref() else {
            return Ok(false);
        };
        match receiver.try_recv() {
            Ok((editor, saved)) => {
                self.saving = None;
                self.editor = Some(editor);
                if matches!(self.issuance, Some(IssueFlow::Saving)) {
                    self.modal_action=0;
                    self.issuance = Some(if saved {
                        IssueFlow::Offer
                    } else {
                        IssueFlow::SaveFailed
                    });
                }
                if matches!(self.revocation, Some(DisableFlow::Saving)) {
                    self.revocation = Some(if saved {
                        DisableFlow::Done
                    } else {
                        DisableFlow::SaveFailed
                    });
                }
                if matches!(self.importing, Some(ImportFlow::RefreshSaving)) {
                    self.importing = Some(if saved {
                        ImportFlow::RefreshDone
                    } else {
                        ImportFlow::Failed
                    });
                }
                if matches!(self.importing, Some(ImportFlow::Saving)) {
                    self.importing = Some(if saved {
                        ImportFlow::Done
                    } else {
                        ImportFlow::Failed
                    });
                }
                if saved {
                    if let Some(original) = self.pending.take() {
                        return Ok(model.update(original));
                    }
                }
                Ok(false)
            }
            Err(TryRecvError::Empty) => Ok(false),
            Err(TryRecvError::Disconnected) => Err(TuiError::Io),
        }
    }

    fn owned_running(&self, role: Role) -> bool {
        if role == Role::Server { self.server_process.running() }
        else { self.client_background.as_ref().is_some_and(StatusPanel::local_running)
            || self.reality_status.as_ref().is_some_and(StatusPanel::local_running) }
    }

    fn recommended_action(&self, role: Role) -> usize {
        let Some(editor) = self.editor_for(role) else { return 0; };
        let (key, _) = recommended_step(editor, self.owned_running(role));
        page_actions(role, 0).iter().position(|item| item.key == key).unwrap_or(0)
    }

    fn select_workspace_page(&mut self, role: Role, page: usize) {
        self.workspace_page = page.min(pages(role).len() - 1);
        self.workspace_action = if self.workspace_page == 0 { self.recommended_action(role) } else { 0 };
        self.workspace_focus = WorkspaceFocus::Navigation;
    }

    fn editor_for(&self, role: Role) -> Option<&Editor> {
        self.editor.as_ref().filter(|edit| edit.role() == role)
    }

    fn panel_role(model: &Model) -> Option<Role> {
        match model.screen {
            Screen::Server => Some(Role::Server),
            Screen::Client => Some(Role::Client),
            _ => None,
        }
    }
    fn open_config(&mut self, role: Role) {
        if self
            .editor
            .as_ref()
            .is_some_and(|e| e.dirty() || e.write_uncertain())
        {
            if let Some(editor) = self.editor.as_mut() {
                editor.error = Some(
                    "Сначала сохраните черновик; при неопределённой записи проверьте файл.".into(),
                );
            }
            return;
        }
        if (role == Role::Server && self.server_process.running())
            || (role == Role::Client
                && self
                    .client_background
                    .as_ref()
                    .is_some_and(StatusPanel::local_running))
        {
            if role == Role::Server {
                self.show_server_process = true;
            } else {
                self.reality_status = self.client_background.take();
            }
            return;
        }
        if role == Role::Client {
            self.client_background = None;
        }
        self.config_dialog = Some(ConfigDialog::new(
            role,
            self.editor_for(role).map(Editor::saved_path),
        ));
    }

    fn poll_navigation(&mut self, model: &mut Model) {
        if let Some(scan) = self.qr_scan.as_ref() {
            let result = match scan.done.try_recv() {
                Ok(result) => Some(result),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Err("Чтение QR не подтверждено.")),
            };
            if let Some(result) = result {
                if let Some(scan) = self.qr_scan.take().filter(|s| !s.cancelled) {
                    match result {
                        Ok(uri) => {
                            self.importing = Some(ImportFlow::Input(uri));
                            self.update(model, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                        }
                        Err(message) => {
                            if let Some(editor) = self.editor.as_mut() {
                                editor.error = Some(message.into());
                            }
                            self.importing = Some(ImportFlow::Input(scan.source));
                        }
                    }
                }
            }
        }
        self.server_process.poll();
        if let Some(monitor) = self.traffic_monitor.as_mut() {
            monitor.poll();
        }
        if let Some(background) = self.client_background.as_mut() {
            background.poll();
        }
        if let Some(dialog) = self.config_dialog.as_mut() {
            if let Some(editor) = dialog.poll() {
                self.editor = Some(editor);
                self.config_dialog = None;
                self.menu = None;
                self.workspace_page=0;
                self.workspace_focus=WorkspaceFocus::Actions;
                if let Some(role) = Self::panel_role(model) {
                    self.workspace_action = self.recommended_action(role);
                }
                self.last_apply=None;
            }
        }
    }

    /// Mouse interaction is confined to harmless selection and navigation.
    /// No click is translated into a save, Apply, start, reveal or confirmation.
    fn active_form(&self) -> Option<Form> {
        if let Some(browser)=&self.import_browser {return Some(browser.form());}
        if let Some(d)=&self.config_dialog {return d.form();}
        if let Some(p)=&self.reality_provision {return p.form();}
        if let Some(p)=&self.reality_enrollment {return p.form();}
        if let Some(p)=&self.reality_registration {return p.form();}
        if let Some(p)=&self.domain {return p.form();}
        if let Some(p)=&self.candidate_batch {return p.form();}
        if let Some(f)=&self.records {return f.form(self.editor.as_ref());}
        None
    }

    fn workspace_visible(&self) -> bool {
        let clear = !self.value_preview && self.menu.is_none()
            && self.config_dialog.is_none()
            && !self.show_server_process
            && self.traffic_monitor.is_none()
            && self.issuance.is_none()
            && self.revocation.is_none()
            && self.importing.is_none()
            && self.qr_scan.is_none()
            && self.records.is_none()
            && self.discovery.is_none()
            && self.candidates.is_none()
            && self.candidate_batch.is_none()
            && self.domain.is_none()
            && self.probe.is_none()
            && self.reality_provision.is_none()
            && self.reality_enrollment.is_none()
            && self.reality_registration.is_none()
            && self.reality_status.is_none()
            && self.runtime.is_none()
            && self.pending.is_none()
            && self.saving.is_none()
            && self.exporting.is_none()
            && self.sharing.is_none()
            && self.clipboard.is_none()
            && !self.editor.as_ref().is_some_and(|e| e.editing);
        #[cfg(windows)]
        let clear = clear && self.system_proxy.is_none();
        clear
    }

    fn mouse(&mut self, model: &mut Model, event: MouseEvent, area: Rect) {
        if area.width < 32 || area.height < 10 {
            return;
        }
        let body = shell_layout(area)[1];
        if matches!(
            event.kind,
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
        ) && event.column >= body.x
            && event.column < body.right()
            && event.row >= body.y
            && event.row < body.bottom()
            && self.menu.is_none()
            && (!self.workspace_visible() || model.screen == Screen::Help)
        {
            self.viewport
                .move_by(if event.kind == MouseEventKind::ScrollUp {
                    -3
                } else {
                    3
                });
            return;
        }
        if event.kind != MouseEventKind::Down(MouseButton::Left) {
            return;
        }
        if let Some(menu) = self.menu.as_mut() {
            menu.click(body, event.column, event.row);
            return;
        }
        // Hit-testing follows the same geometry as the renderer and only
        // changes focus. A click never dispatches Enter, y, or a shortcut.
        if self.show_server_process {
            let items = self.server_process.actions();
            if let Some([_, rect]) = action_layout(body, items.len()) {
                let actions = Actions { items: &items, selected: self.server_process.action_focus() };
                if let Some(index) = actions.hit(rect, event.column, event.row) {
                    self.server_process.select_action(index);
                }
            }
            return;
        }
        if let Some(panel) = self.reality_status.as_mut() {
            let items = panel.actions();
            if let Some([_, rect]) = action_layout(body, items.len()) {
                let actions = Actions { items: &items, selected: panel.action_focus() };
                if let Some(index) = actions.hit(rect, event.column, event.row) {
                    panel.select_action(index);
                }
            }
            return;
        }
        if let Some(browser)=self.import_browser.as_mut() {
            let form=browser.form();
            if let Some(id)=form.hit(guided_form_area(body,form.fields.len()),event.column,event.row){browser.select_field(id);}
            return;
        }
        if let Some(dialog) = self.config_dialog.as_mut() {
            if let Some(form) = dialog.form() {
                let target = if dialog.guide().is_some() { guided_form_area(body, form.fields.len()) } else { centered_column(body, 108) };
                if let Some(id) = form.hit(target, event.column, event.row) { dialog.select_field(id); }
            }
            return;
        }
        if let Some(runtime)=self.runtime.as_ref() {
            let items=runtime.actions();
            if let Some([_,controls])=action_layout(body,items.len()) {
                if let Some(i)=(Actions{items:&items,selected:self.modal_action}).hit(controls,event.column,event.row){self.modal_action=i;}
            }
            return;
        }
        #[cfg(windows)]
        if let Some(proxy)=self.system_proxy.as_ref() {
            let items=proxy.actions();
            if let Some([_,controls])=action_layout(body,items.len()) {
                if let Some(i)=(Actions{items:&items,selected:self.modal_action}).hit(controls,event.column,event.row){self.modal_action=i;}
            }
            return;
        }
        if let Some(domain)=self.domain.as_mut() {
            if let Some(form)=domain.form() {
                if let Some(i)=form.hit(guided_form_area(body,form.fields.len()),event.column,event.row){domain.select_field(i);}
            }
            return;
        }
        if let Some(batch)=self.candidate_batch.as_mut() {
            if let Some(form)=batch.form() {
                if let Some(i)=form.hit(guided_form_area(body,form.fields.len()),event.column,event.row){batch.select_field(i);}
            }
            return;
        }
        if let Some(panel)=self.reality_registration.as_mut() {
            if let Some(form)=panel.form(){
                if let Some(id)=form.hit(guided_form_area(body,form.fields.len()),event.column,event.row){panel.select_field(id);}
            }
            return;
        }
        if let Some(panel) = self.reality_provision.as_mut() {
            if let Some(form) = panel.form() {
                if let Some(id) = form.hit(guided_form_area(body, form.fields.len()), event.column, event.row) { panel.select_field(id); }
            }
            return;
        }
        if let Some(panel) = self.reality_enrollment.as_mut() {
            if let Some(form) = panel.form() {
                if let Some(id) = form.hit(guided_form_area(body, form.fields.len()), event.column, event.row) { panel.select_field(id); }
            }
            return;
        }
        if let Some(flow) = self.records.as_mut() {
            if let Some(form) = flow.form(self.editor.as_ref()) {
                if let Some(id) = form.hit(guided_form_area(body, form.fields.len()), event.column, event.row) { flow.select_field(id); }
            }
            return;
        }
        if let Some(flow) = self.issuance.as_ref() {
            let items = invitation_actions(flow);
            if let Some([_,controls]) = action_layout(body,items.len()) {
                if let Some(index) = (Actions {items:&items,selected:self.modal_action}).hit(controls,event.column,event.row) {
                    self.modal_action=index;
                }
                return;
            }
        }
        if let Some(IssueFlow::Input(id)) = self.issuance.as_mut() {
            if self.issue_kind != IssueKind::NewUser {
                let disabled = self.issue_kind == IssueKind::Reenable;
                if let Some(form) = user_picker(self.editor.as_ref(), id, disabled) {
                    if let Some(index) = form.hit(guided_form_area(body, form.fields.len()), event.column, event.row) {
                        if let Some(field) = form.fields.get(index) { *id = field.value.clone(); }
                    }
                }
            }
            return;
        }
        if let Some(DisableFlow::Input(id)) = self.revocation.as_mut() {
            if let Some(form) = user_picker(self.editor.as_ref(), id, false) {
                if let Some(index) = form.hit(guided_form_area(body, form.fields.len()), event.column, event.row) {
                    if let Some(field) = form.fields.get(index) { *id = field.value.clone(); }
                }
            }
            return;
        }
        if !self.workspace_visible() {
            return;
        }
        let inside = |r: Rect| {
            event.column >= r.x
                && event.column < r.right()
                && event.row >= r.y
                && event.row < r.bottom()
        };
        if model.screen == Screen::Home {
            let cards = home_layout(body);
            if inside(cards[0]) {
                model.selected = Role::Server;
            }
            if inside(cards[1]) {
                model.selected = Role::Client;
            }
            return;
        }
        let Some(role) = Self::panel_role(model) else {
            return;
        };
        if self.editor_for(role).is_none() {
            let form = welcome_form(role, self.welcome_choice);
            if let Some(id) = form.hit(centered_column(body, 88), event.column, event.row) {
                self.welcome_choice = id;
            }
            return;
        }
        let Some(columns) = workspace_columns(body) else {
            if self.workspace_focus==WorkspaceFocus::Navigation {
                if event.row>body.y && event.row<body.bottom().saturating_sub(1) {
                    let i=usize::from(event.row-body.y-1);
                    if i<pages(role).len(){self.select_workspace_page(role,i);}
                }
                return;
            }
            let items=page_actions(role,self.workspace_page);
            let controls=page_layout(body,role,self.workspace_page).map(|p|p[1]).unwrap_or(if self.workspace_focus==WorkspaceFocus::Actions {body} else {Rect::default()});
            if let Some(i)=(Actions {items:&items,selected:self.workspace_action}).hit(controls,event.column,event.row) {
                self.workspace_action=i; self.workspace_focus=WorkspaceFocus::Actions; return;
            }
            if let Some(editor) = self.editor.as_mut().filter(|e| e.role() == role) {
                let content=page_layout(body,role,self.workspace_page).map(|p|p[0]).unwrap_or(body);
                if self.workspace_page==1 {
                    if let Some(id)=editor_field_hit(content,editor,event.column,event.row) {editor.workspace_select_field(id);self.workspace_focus=WorkspaceFocus::Fields;}
                } else if role==Role::Server && self.workspace_page==2 && inside(content) && event.row>=content.y+2 && event.row<content.bottom().saturating_sub(1) {
                    let users=editor.workspace_users();
                    let i=user_table_start(self.workspace_user,users.len(),content)+usize::from(event.row-content.y-2);
                    if i<users.len(){self.workspace_user=i;self.workspace_focus=WorkspaceFocus::Users;}
                }
 
            }
            return;
        };
        let nav = columns[0];
        if inside(nav) && event.row > nav.y && event.row < nav.bottom().saturating_sub(1) {
            let index = usize::from(event.row - nav.y - 1);
            if index < pages(role).len() {
                self.select_workspace_page(role,index);
            }
            return;
        }
        let records = columns[1];
        if inside(records)
            && event.row > records.y
            && event.row < records.bottom().saturating_sub(1)
        {
            if let Some(editor) = self.editor.as_mut().filter(|e| e.role() == role) {
                let start = record_start(editor, records);
                editor.workspace_select(start + usize::from(event.row - records.y - 1));
            }
            return;
        }
        if let Some(editor) = self.editor.as_mut().filter(|e| e.role() == role) {
            if let Some([content, controls]) = page_layout(columns[2], role, self.workspace_page).or_else(||(self.workspace_focus==WorkspaceFocus::Actions).then_some([Rect::default(),columns[2]])) {
                let items = page_actions(role, self.workspace_page);
                if let Some(i) = (Actions { items: &items, selected: self.workspace_action }).hit(controls, event.column, event.row) {
                    self.workspace_action = i;
                    self.workspace_focus = WorkspaceFocus::Actions;
                    return;
                }
                if role == Role::Server && self.workspace_page == 2 && inside(content) && event.row >= content.y + 2 {
                    let users = editor.workspace_users();
                    let start = user_table_start(self.workspace_user, users.len(), content);
                    let i = start + usize::from(event.row - content.y - 2);
                    if i < users.len() && event.row < content.bottom().saturating_sub(1) {
                        self.workspace_user = i;
                        self.workspace_focus = WorkspaceFocus::Users;
                    }
                    return;
                }
                if self.workspace_page == 1 {
                    if let Some(id) = editor_field_hit(content, editor, event.column, event.row) {
                        editor.workspace_select_field(id);
                        self.workspace_focus = WorkspaceFocus::Fields;
                    }
                }
                return;
            }
            if self.workspace_page==1 {
                if let Some(id) = editor_field_hit(columns[2], editor, event.column, event.row) {
                    editor.workspace_select_field(id);
                    self.workspace_focus=WorkspaceFocus::Fields;
                }
            }
        }
    }

    fn update(&mut self, model: &mut Model, key: KeyEvent) -> bool {
        if key.kind == KeyEventKind::Press
            && key.modifiers == KeyModifiers::SHIFT
            && matches!(key.code, KeyCode::PageUp | KeyCode::PageDown)
            && self.menu.is_none()
            && (!self.workspace_visible() || model.screen == Screen::Help)
        {
            let page = self.viewport.page.get().max(1).min(isize::MAX as usize) as isize;
            self.viewport.move_by(if key.code == KeyCode::PageUp {
                -page
            } else {
                page
            });
            return false;
        }
        if key.kind == KeyEventKind::Press {
            self.viewport.reset();
        }
        if key.kind != KeyEventKind::Press
            || self.saving.is_some()
            || self.exporting.is_some()
            || self.sharing.is_some()
            || self.clipboard.is_some()
        {
            return false;
        }
        if self.value_preview {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::F(7)) {
                self.value_preview = false;
                self.preview_text = None;
            }
            return false;
        }
        if key.code == KeyCode::F(7) {
            if let Some(form)=self.active_form() {
                let text=if !form.error.is_empty() {format!("Ошибка: {}",form.error)} else if let Some(field)=form.fields.iter().find(|f|f.id==form.selected) {format!("{}\n\n{}\n\n{}",field.label,field.value,field.hint)} else {String::new()};
                if !text.is_empty() {self.preview_text=Some(text);self.value_preview=true;return false;}
            }
            if let Some(error)=Self::panel_role(model).and_then(|role|self.editor_for(role)).and_then(|e|e.error.as_ref()) {
                self.preview_text=Some(format!("Ошибка: {error}"));self.value_preview=true;return false;
            }
        }
        if let Some(scan) = self.qr_scan.as_mut() {
            if key.code == KeyCode::Esc {
                scan.cancelled = true;
            }
            return false;
        }
        if let Some(dialog) = self.config_dialog.as_mut() {
            if dialog.key(key) {
                self.config_dialog = None;
            }
            return false;
        }
        if self.show_server_process {
            if self.server_process.key(key.code, self.editor.as_ref()) {
                self.show_server_process = false;
            }
            return false;
        }
        if self.traffic_monitor.is_some() {
            if matches!(key.code, KeyCode::Esc | KeyCode::F(10)) {
                self.traffic_monitor = None;
            }
            return false;
        }
        if let Some(menu) = self.menu.as_mut() {
            let Some(action) = menu.key(key.code) else {
                return false;
            };
            self.menu = None;
            match action {
                MenuAction::Close => {}
                MenuAction::Config => {
                    if let Some(role) = Self::panel_role(model) {
                        self.open_config(role);
                    }
                }
                MenuAction::ServerProcess => self.show_server_process = true,
                MenuAction::Traffic => {
                    if let Some(role) = Self::panel_role(model) {
                        self.traffic_monitor = Some(crate::traffic::Monitor::new(role));
                    }
                }
                MenuAction::Shortcut(code, modifiers) => {
                    return self.update(model, KeyEvent::new(code, modifiers))
                }
            }
            return false;
        }
        #[cfg(windows)]
        if let Some(proxy) = self.system_proxy.as_mut() {
            let items=proxy.actions();
            let code=if key.modifiers.is_empty(){tui_widgets::action_key(&items,&mut self.modal_action,key.code)}else{Some(key.code)};
            let Some(code)=code else{return false;};
            if proxy.key(KeyEvent{code,..key}) {
                self.system_proxy = None;
                self.modal_action=0;
            }
            return false;
        }
        if self
            .reality_status
            .as_ref()
            .is_some_and(StatusPanel::can_minimize)
            && matches!(key.code, KeyCode::Esc | KeyCode::F(10))
        {
            self.client_background = self.reality_status.take();
            if key.code == KeyCode::F(10) {
                self.menu = Some(Menu::new(
                    Role::Client,
                    self.editor_for(Role::Client).is_some(),
                ));
            }
            return false;
        }
        if let Some(panel) = self.reality_status.as_mut() {
            if panel.key(key) {
                self.reality_status = None;
            }
            return false;
        }
        if let Some(panel) = self.reality_registration.as_mut() {
            if panel.key(key) {
                self.reality_registration = None;
            }
            return false;
        }
        if let Some(panel) = self.reality_enrollment.as_mut() {
            if panel.key(key) {
                self.reality_enrollment = None;
            }
            return false;
        }
        if let Some(panel) = self.reality_provision.as_mut() {
            if panel.key(key) {
                self.reality_provision = None;
            }
            return false;
        }
        if let Some(runtime) = self.runtime.as_mut() {
            let items=runtime.actions();
            let code=if key.modifiers.is_empty(){tui_widgets::action_key(&items,&mut self.modal_action,key.code)}else{Some(key.code)};
            let Some(code)=code else{return false;};
            if runtime.key(KeyEvent{code,..key}) {
                self.runtime = None;
                self.modal_action=0;
            }
            return false;
        }
        if let Some(domain) = self.domain.as_mut() {
            if domain.is_manual_input() {
                match key.code {
                    KeyCode::Esc => {
                        domain.back_or_close();
                    }
                    KeyCode::Enter => domain.ask_confirmation(),
                    KeyCode::Backspace => domain.manual_backspace(),
                    KeyCode::Char(ch)
                        if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
                    {
                        domain.manual_insert(ch);
                    }
                    _ => {}
                }
                return false;
            }
            match key.code {
                KeyCode::Esc => {
                    if domain.back_or_close() {
                        self.domain = None;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => domain.next(),
                KeyCode::Up | KeyCode::Char('k') => domain.previous(),
                KeyCode::Char(' ') => domain.toggle_current(),
                KeyCode::Enter => domain.ask_confirmation(),
                KeyCode::Char('a') => domain.open_review(),
                KeyCode::Char('m') if key.modifiers.is_empty() => domain.begin_manual(),
                KeyCode::Char('y') if domain.is_dns_confirming() => {
                    domain.confirm_dns_and_start();
                }
                KeyCode::Char('y') if domain.is_probe_confirming() => {
                    domain.confirm_probes_and_start();
                }
                KeyCode::Char('n') => domain.decline(),
                _ => {}
            }
            return false;
        }
        if let Some(batch) = self.candidate_batch.as_mut() {
            match key.code {
                KeyCode::Esc => {
                    if batch.back_or_close() {
                        self.candidate_batch = None;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => batch.next(),
                KeyCode::Up | KeyCode::Char('k') => batch.previous(),
                KeyCode::Char(' ') => batch.toggle_current(),
                KeyCode::Enter => batch.ask_confirmation(),
                KeyCode::Char('a') => batch.open_review(),
                KeyCode::Char('y') if batch.is_confirming() => batch.confirm_and_start(),
                KeyCode::Char('n') => batch.decline(),
                _ => {}
            }
            return false;
        }
        if let Some(review) = self.candidates.as_mut() {
            if key.code == KeyCode::Esc {
                if review.back_or_close() {
                    self.candidates = None;
                }
                return false;
            }
            if review.is_editing() {
                match key.code {
                    KeyCode::Enter => review.review_input(),
                    KeyCode::Backspace => review.backspace(),
                    KeyCode::Char(ch)
                        if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
                    {
                        review.insert(ch);
                    }
                    _ => {}
                }
            } else if review.is_confirming() {
                match key.code {
                    KeyCode::Char('y') => review.confirm_scope(),
                    KeyCode::Char('n') => review.decline(),
                    _ => {}
                }
            } else if key.code == KeyCode::Char('a') {
                review.begin_cidr();
            } else if key.code == KeyCode::Char('b') {
                let server_name = self
                    .editor
                    .as_ref()
                    .filter(|editor| editor.role() == Role::Server)
                    .and_then(Editor::selected_server_name)
                    .map(str::to_owned);
                self.candidate_batch = Some(CandidateBatchPanel::new(
                    review.batch_preview(),
                    server_name,
                ));
            } else if key.code == KeyCode::Char('d') {
                self.domain = Some(DomainPanel::new(review.batch_preview()));
            }
            return false;
        }
        if let Some(probe) = self.probe.as_mut() {
            match key.code {
                KeyCode::Esc => {
                    probe.cancel();
                    self.probe = None;
                }
                KeyCode::Down | KeyCode::Char('j') => probe.next(),
                KeyCode::Up | KeyCode::Char('k') => probe.previous(),
                KeyCode::Enter | KeyCode::Char('t') => probe.ask_confirmation(),
                KeyCode::Char('y') if probe.is_consent_pending() => probe.confirm_and_start(),
                KeyCode::Char('n') => probe.decline(),
                _ => {}
            }
            return false;
        }
        if let Some(panel) = self.discovery.as_mut() {
            match key.code {
                KeyCode::Esc => {
                    panel.cancel();
                    self.discovery = None;
                }
                KeyCode::Char('i') => panel.ask_consent(),
                KeyCode::Char('r') if panel.may_review_probe() => {
                    self.candidates =
                        Some(CandidateReview::new(panel.assigned_interfaces().clone()));
                }
                KeyCode::Char('t') if panel.may_review_probe() => {
                    let server_name = self
                        .editor
                        .as_ref()
                        .filter(|editor| editor.role() == Role::Server)
                        .and_then(Editor::selected_server_name)
                        .map(str::to_owned);
                    self.probe = Some(ProbePanel::new(
                        panel.assigned_interfaces().clone(),
                        server_name,
                    ));
                }
                KeyCode::Char('n') => panel.decline(),
                KeyCode::Char('y') if panel.is_consent_pending() => panel.confirm_and_start(),
                _ => {}
            }
            return false;
        }
        let base = self.records.is_none()
            && self.issuance.is_none()
            && self.revocation.is_none()
            && self.importing.is_none()
            && self.pending.is_none()
            && !self.editor.as_ref().is_some_and(|e| e.editing);
        if base {
            let role = Self::panel_role(model);
            let exiting = key.code == KeyCode::Char('q')
                || (key.code == KeyCode::Char('c')
                    && key.modifiers.contains(KeyModifiers::CONTROL));
            if exiting && self.server_process.running() {
                self.show_server_process = true;
                return false;
            }
            if exiting
                && self
                    .client_background
                    .as_ref()
                    .is_some_and(StatusPanel::local_running)
            {
                self.reality_status = self.client_background.take();
                return false;
            }
            if role == Some(Role::Client)
                && key.code == KeyCode::Char('V')
                && self.client_background.is_some()
            {
                self.reality_status = self.client_background.take();
                return false;
            }
            if role == Some(Role::Client)
                && key.code == KeyCode::Char('p')
                && self
                    .client_background
                    .as_ref()
                    .is_some_and(StatusPanel::local_running)
            {
                self.reality_status = self.client_background.take();
                return false;
            }
            if let Some(role) = role {
                let configured = self.editor_for(role).is_some();
                if !configured {
                    match key.code {
                        KeyCode::Up | KeyCode::BackTab => {
                            self.welcome_choice = (self.welcome_choice + 2) % 3;
                            return false;
                        }
                        KeyCode::Down | KeyCode::Tab => {
                            self.welcome_choice = (self.welcome_choice + 1) % 3;
                            return false;
                        }
                        KeyCode::Enter => {
                            self.open_config(role);
                            if let Some(dialog) = self.config_dialog.as_mut() {
                                dialog.prefer_mode(self.welcome_choice);
                            }
                            return false;
                        }
                        _ => {}
                    }
                }
                if configured && self.workspace_visible() {
                    self.workspace_page = self.workspace_page.min(pages(role).len() - 1);
                    if key.code == KeyCode::F(7) && self.workspace_page == 1 {
                        self.value_preview = true;
                        return false;
                    }
                    if key.code == KeyCode::F(6) {
                        if self.workspace_page == 0 && self.workspace_focus == WorkspaceFocus::Fields {
                            self.workspace_action = self.recommended_action(role);
                        }
                        self.workspace_focus = match self.workspace_focus {
                            WorkspaceFocus::Fields | WorkspaceFocus::Users => WorkspaceFocus::Actions,
                            WorkspaceFocus::Actions => WorkspaceFocus::Navigation,
                            WorkspaceFocus::Navigation => if role == Role::Server && self.workspace_page == 2 { WorkspaceFocus::Users } else { WorkspaceFocus::Fields },
                        };
                        return false;
                    }
                    if key.modifiers == KeyModifiers::ALT && matches!(key.code, KeyCode::Left | KeyCode::Right) {
                        let n = pages(role).len();
                        let page = (self.workspace_page + if key.code == KeyCode::Right { 1 } else { n - 1 }) % n;
                        self.select_workspace_page(role,page);
                        return false;
                    }
                    if self.workspace_focus == WorkspaceFocus::Navigation {
                        match key.code {
                            KeyCode::Up | KeyCode::Down => {
                                let n = pages(role).len();
                                let page = (self.workspace_page + if key.code == KeyCode::Down { 1 } else { n - 1 }) % n;
                                self.select_workspace_page(role,page);
                                return false;
                            }
                            KeyCode::Enter | KeyCode::Tab => {
                                self.workspace_focus = if role == Role::Server && self.workspace_page == 2 { WorkspaceFocus::Users } else if self.workspace_page == 1 { WorkspaceFocus::Fields } else { WorkspaceFocus::Actions };
                                return false;
                            }
                            KeyCode::BackTab => {
                                self.workspace_focus = WorkspaceFocus::Actions;
                                return false;
                            }
                            _ => {}
                        }
                    }
                    if role == Role::Server && self.workspace_page == 2 && matches!(self.workspace_focus, WorkspaceFocus::Fields | WorkspaceFocus::Users) {
                        let count = self.editor_for(role).map_or(0, |e| e.workspace_users().len());
                        self.workspace_focus = WorkspaceFocus::Users;
                        match key.code {
                            KeyCode::Up | KeyCode::Down if count > 0 => {
                                self.workspace_user = (self.workspace_user.min(count-1) + if key.code == KeyCode::Down { 1 } else { count-1 }) % count;
                                return false;
                            }
                            KeyCode::Tab | KeyCode::Enter => {
                                self.workspace_focus = WorkspaceFocus::Actions;
                                return false;
                            }
                            KeyCode::BackTab => { self.workspace_focus = WorkspaceFocus::Navigation; return false; }
                            _ => {}
                        }
                    }
                    if self.workspace_focus == WorkspaceFocus::Actions {
                        let items = page_actions(role, self.workspace_page);
                        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
                            self.workspace_focus = if key.code == KeyCode::Tab { WorkspaceFocus::Navigation } else if role == Role::Server && self.workspace_page == 2 { WorkspaceFocus::Users } else { WorkspaceFocus::Fields };
                            return false;
                        }
                        if matches!(key.code, KeyCode::Up | KeyCode::Down | KeyCode::Home | KeyCode::End | KeyCode::Enter)
                            || (key.modifiers.is_empty() && matches!(key.code,KeyCode::Char(ch) if items.iter().any(|item|item.key==ch))) {
                            if self.workspace_page == 4 && key.code == KeyCode::Enter {
                                self.traffic_monitor = Some(crate::traffic::Monitor::new(role));
                                return false;
                            }
                            if let Some(KeyCode::Char(ch)) = tui_widgets::action_key(&items, &mut self.workspace_action, key.code) {
                                let selected = if role == Role::Server && self.workspace_page == 2 {
                                    self.editor_for(role).and_then(|e| e.workspace_users().get(self.workspace_user).map(|u| u.0.clone()))
                                } else { None };
                                self.workspace_focus = WorkspaceFocus::Fields;
                                let command = match ch {
                                    '4' => KeyEvent::new(KeyCode::F(4),KeyModifiers::NONE),
                                    's' if role == Role::Server => KeyEvent::new(KeyCode::F(5),KeyModifiers::NONE),
                                    'o' => KeyEvent::new(KeyCode::F(3),KeyModifiers::NONE),
                                    'S' => KeyEvent::new(KeyCode::Char('s'),KeyModifiers::CONTROL),
                                    _ => KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
                                };
                                let result = self.update(model, command);
                                if let Some(id) = selected {
                                    if ch == 'x' { if let Some(DisableFlow::Input(value)) = self.revocation.as_mut() { *value = id.clone(); } }
                                    if matches!(ch, 'b' | 't') { if let Some(IssueFlow::Input(value)) = self.issuance.as_mut() { *value = id; } }
                                }
                                return result;
                            }
                            return false;
                        }
                    }
                    if self.workspace_page == 1 && self.workspace_focus == WorkspaceFocus::Fields {
                        let index = self.editor_for(role).map_or(0,Editor::workspace_field_index);
                        let count = self.editor_for(role).map_or(0,Editor::field_count);
                        if key.code == KeyCode::Tab && index+1 >= count {
                            self.workspace_focus=WorkspaceFocus::Actions; return false;
                        }
                        if key.code == KeyCode::BackTab && index==0 {
                            self.workspace_focus=WorkspaceFocus::Navigation; return false;
                        }
                    }
                    if self.workspace_page != 1 && matches!(key.code, KeyCode::Enter | KeyCode::Tab | KeyCode::BackTab) {
                        self.workspace_focus = if key.code == KeyCode::BackTab { WorkspaceFocus::Navigation } else { WorkspaceFocus::Actions };
                        return false;
                    }
                }
                if key.code == KeyCode::F(3)
                    || (!configured && key.code == KeyCode::Char('N'))
                    || (!configured
                        && (key.code == KeyCode::Enter
                            || (role == Role::Client && key.code == KeyCode::Char('V'))))
                {
                    self.open_config(role);
                    return false;
                }
                if matches!(key.code, KeyCode::F(10) | KeyCode::F(2)) {
                    self.menu = Some(Menu::new(role, configured));
                    return false;
                }
                if key.code == KeyCode::F(4) {
                    self.traffic_monitor = Some(crate::traffic::Monitor::new(role));
                    return false;
                }
                if role == Role::Server && key.code == KeyCode::F(5) {
                    self.show_server_process = true;
                    return false;
                }
            }
        }
        // Keep the editor for the other role intact; read-only actions are
        // routed without silently borrowing its saved path or credentials.
        let inactive_editor =
            base && Self::panel_role(model).is_some_and(|role| self.editor_for(role).is_none());
        if self.editor.is_none() || inactive_editor {
            if model.screen == Screen::Client && key.code == KeyCode::Char('I') {
                self.open_config(Role::Client);
                if let Some(dialog) = self.config_dialog.as_mut() { dialog.prefer_reality(); }
                return false;
            }
            if model.screen == Screen::Server && key.code == KeyCode::Char('W') {
                self.open_config(Role::Server);
                if let Some(dialog) = self.config_dialog.as_mut() { dialog.prefer_reality(); }
                return false;
            }
            if model.screen == Screen::Server && key.code == KeyCode::Char('w') {
                self.reality_provision = Some(ProvisionPanel::new());
                return false;
            }
            if model.screen == Screen::Server && key.code == KeyCode::Char('R') {
                self.runtime = Some(RuntimePanel::open_restart());
                return false;
            }
            if model.screen == Screen::Server && key.code == KeyCode::Char('v') {
                self.runtime = Some(RuntimePanel::open(None, false));
                return false;
            }
            if model.screen == Screen::Server && key.code == KeyCode::Char('p') {
                self.discovery = Some(DiscoveryPanel::new());
                return false;
            }
            return model.update(key);
        }
        let Some(editor) = self.editor.as_mut() else {
            return false;
        };
        if let Some(flow) = self.records.take() {
            match flow {
                RecordFlow::ChooseMode(role, selected) => match if key.code == KeyCode::Enter {
                    KeyCode::Char(if selected == 0 { '1' } else { '2' })
                } else { key.code } {
                    KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab => {
                        self.records = Some(RecordFlow::ChooseMode(role, 1 - selected));
                    }
                    KeyCode::Char('1') => {
                        let action = if role == Role::Server {
                            RecordAction::NewInbound
                        } else {
                            RecordAction::NewProfile
                        };
                        match editor.record_fields(action) {
                            Ok(fields) => {
                                self.records = Some(RecordFlow::Input {
                                    action,
                                    fields,
                                    focus: 0,
                                })
                            }
                            Err(message) => editor.error = Some(message.into()),
                        }
                    }
                    KeyCode::Char('2') if role == Role::Server => {
                        match ProvisionPanel::bound(editor) {
                            Ok(panel) => self.reality_provision = Some(panel),
                            Err(message) => editor.error = Some(message.into()),
                        }
                    }
                    KeyCode::Char('2') => match EnrollmentPanel::bound(editor) {
                        Ok(panel) => self.reality_enrollment = Some(panel),
                        Err(message) => editor.error = Some(message.into()),
                    },
                    KeyCode::Esc => {}
                    _ => self.records = Some(RecordFlow::ChooseMode(role, selected)),
                },
                RecordFlow::Confirm(review) => match key.code {
                    KeyCode::Char('y') if key.modifiers.is_empty() => {
                        match editor.stage_record(*review) {
                            Ok(()) => self.start_save(),
                            Err(message) => editor.error = Some(message.into()),
                        }
                    }
                    KeyCode::Esc | KeyCode::Char('n') => {}
                    _ => self.records = Some(RecordFlow::Confirm(review)),
                },
                RecordFlow::Input {
                    action,
                    mut fields,
                    mut focus,
                } => {
                    match key.code {
                        KeyCode::Esc => return false,
                        KeyCode::Enter => match editor.review_record(action, &fields) {
                            Ok(review) => {
                                editor.error = None;
                                self.records = Some(RecordFlow::Confirm(Box::new(review)));
                                return false;
                            }
                            Err(message) => editor.error = Some(message.into()),
                        },
                        KeyCode::Tab | KeyCode::Down => focus = (focus + 1) % fields.len(),
                        KeyCode::BackTab | KeyCode::Up => {
                            focus = (focus + fields.len() - 1) % fields.len()
                        }
                        KeyCode::Backspace => {
                            fields[focus].pop();
                        }
                        KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                            fields[focus].clear();
                        }
                        KeyCode::Char(ch)
                            if (key.modifiers.is_empty()
                                || key.modifiers == KeyModifiers::SHIFT)
                                && !ch.is_control()
                                && fields[focus].len() + ch.len_utf8() <= 1024 =>
                        {
                            fields[focus].push(ch);
                        }
                        _ => {}
                    }
                    self.records = Some(RecordFlow::Input {
                        action,
                        fields,
                        focus,
                    });
                }
            }
            return false;
        }
        if let Some(flow) = self.issuance.take() {
            let items = invitation_actions(&flow);
            let code = if key.modifiers.is_empty() { tui_widgets::action_key(&items, &mut self.modal_action, key.code) } else { Some(key.code) };
            let Some(code) = code else { self.issuance = Some(flow); return false; };
            let key = KeyEvent { code, ..key };
            match flow {
                IssueFlow::Input(mut id) => match key.code {
                    KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab if self.issue_kind != IssueKind::NewUser => {
                        id = cycle_user(
                            editor,
                            &id,
                            self.issue_kind == IssueKind::Reenable,
                            matches!(key.code,KeyCode::Down|KeyCode::Tab),
                        );
                        self.issuance = Some(IssueFlow::Input(id));
                    }
                    KeyCode::Esc => {}
                    KeyCode::Enter if !id.is_empty() => {
                        self.issuance = Some(IssueFlow::Confirm(id));
                    }
                    KeyCode::Backspace => {
                        id.pop();
                        self.issuance = Some(IssueFlow::Input(id));
                    }
                    KeyCode::Char(ch)
                        if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                            && ch.is_ascii_graphic()
                            && id.len() < 64 =>
                    {
                        id.push(ch);
                        self.issuance = Some(IssueFlow::Input(id));
                    }
                    _ => self.issuance = Some(IssueFlow::Input(id)),
                },
                IssueFlow::Confirm(id) => match key.code {
                    KeyCode::Char('y') => {
                        let result = match self.issue_kind {
                            IssueKind::NewUser => editor.issue_user(&id),
                            IssueKind::Rotation => editor.rotate_user(&id),
                            IssueKind::Reenable => editor.reenable_user(&id),
                        };
                        if result.is_ok() {
                            self.issuance = Some(IssueFlow::Saving);
                            self.start_save();
                        } else {
                            self.issuance = Some(IssueFlow::Input(id));
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Esc => {}
                    _ => self.issuance = Some(IssueFlow::Confirm(id)),
                },
                IssueFlow::Saving => self.issuance = Some(IssueFlow::Saving),
                IssueFlow::SaveFailed => match key.code {
                    KeyCode::Char('r') if !editor.write_uncertain() => {
                        self.issuance = Some(IssueFlow::Saving);
                        self.start_save();
                    }
                    KeyCode::Char('d') => editor.discard(),
                    _ => self.issuance = Some(IssueFlow::SaveFailed),
                },
                IssueFlow::Offer => match key.code {
                    KeyCode::Char('Q' | 'c') => {
                        let action = if key.code == KeyCode::Char('Q') {
                            crate::tui_share::Action::Qr
                        } else {
                            crate::tui_share::Action::Clipboard
                        };
                        self.issuance = Some(IssueFlow::ShareConfirm {
                            action,
                            public: None,
                        });
                    }
                    KeyCode::Char('f') => {
                        self.issuance = Some(IssueFlow::ConfirmExport);
                    }
                    KeyCode::Char('y') => {
                        if let Some(invite) = editor.take_issued() {
                            match invite.encode() {
                                Ok(link) => {
                                    self.issuance = Some(IssueFlow::Showing(Zeroizing::new(link)))
                                }
                                Err(_) => {
                                    editor.error = Some("Не удалось сформировать ссылку.".into());
                                    editor.clear_issued();
                                }
                            }
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Esc => editor.clear_issued(),
                    _ => self.issuance = Some(IssueFlow::Offer),
                },
                IssueFlow::ConfirmExport => match key.code {
                    KeyCode::Char('y') => {
                        self.issuance = Some(IssueFlow::Exporting);
                        self.start_export();
                    }
                    KeyCode::Char('n') | KeyCode::Esc => {
                        self.issuance = Some(IssueFlow::Offer);
                    }
                    _ => self.issuance = Some(IssueFlow::ConfirmExport),
                },
                IssueFlow::Exporting => self.issuance = Some(IssueFlow::Exporting),
                IssueFlow::Exported(path) => {
                    if key.code != KeyCode::Esc {
                        self.issuance = Some(IssueFlow::Exported(path));
                    }
                }
                IssueFlow::ExportFailed => {
                    if key.code != KeyCode::Esc {
                        self.issuance = Some(IssueFlow::ExportFailed);
                    }
                }
                IssueFlow::Public(link) => match key.code {
                    KeyCode::Char('Q' | 'c') => {
                        let action = if key.code == KeyCode::Char('Q') {
                            crate::tui_share::Action::Qr
                        } else {
                            crate::tui_share::Action::Clipboard
                        };
                        self.issuance = Some(IssueFlow::ShareConfirm {
                            action,
                            public: Some(link),
                        });
                    }
                    KeyCode::Esc | KeyCode::Enter => {}
                    _ => self.issuance = Some(IssueFlow::Public(link)),
                },
                IssueFlow::ShareConfirm { action, public } => match key.code {
                    KeyCode::Char('n') | KeyCode::Esc => {
                        self.issuance = Some(public.map_or(IssueFlow::Offer, IssueFlow::Public));
                    }
                    KeyCode::Char('y') if key.modifiers.is_empty() => {
                        let link = match public {
                            Some(link) => Some(Zeroizing::new(link)),
                            None => editor
                                .take_issued()
                                .and_then(|invitation| invitation.encode().ok())
                                .map(Zeroizing::new),
                        };
                        if let Some(link) = link {
                            match action {
                                crate::tui_share::Action::Qr => {
                                    let path = editor.saved_path().to_owned();
                                    let (tx, rx) = mpsc::channel();
                                    self.sharing = Some(rx);
                                    self.issuance = Some(IssueFlow::Sharing);
                                    let _worker = std::thread::spawn(move || {
                                        let _ = tx.send(crate::tui_share::export_qr(&path, &link));
                                    });
                                }
                                crate::tui_share::Action::Clipboard => {
                                    self.clipboard = Some(link);
                                    self.issuance = Some(IssueFlow::Sharing);
                                }
                            }
                        } else {
                            self.issuance = Some(IssueFlow::ShareDone("Приглашение больше недоступно. Необходимо перевыпустить credential.".into()));
                        }
                    }
                    _ => self.issuance = Some(IssueFlow::ShareConfirm { action, public }),
                },
                IssueFlow::Sharing => self.issuance = Some(IssueFlow::Sharing),
                IssueFlow::ShareDone(message) => {
                    if key.code != KeyCode::Esc {
                        self.issuance = Some(IssueFlow::ShareDone(message));
                    }
                }
                IssueFlow::Showing(link) => {
                    if key.code == KeyCode::Esc {
                        editor.clear_issued();
                    } else {
                        self.issuance = Some(IssueFlow::Showing(link));
                    }
                }
            }
            return false;
        }

        if let Some(flow) = self.revocation.take() {
            match flow {
                DisableFlow::Input(mut id) => match key.code {
                    KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => {
                        id = cycle_user(editor, &id, false, matches!(key.code,KeyCode::Down|KeyCode::Tab));
                        self.revocation = Some(DisableFlow::Input(id));
                    }
                    KeyCode::Esc => {}
                    KeyCode::Enter if !id.is_empty() => {
                        self.revocation = Some(DisableFlow::Confirm(id));
                    }
                    KeyCode::Backspace => {
                        id.pop();
                        self.revocation = Some(DisableFlow::Input(id));
                    }
                    KeyCode::Char(ch)
                        if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                            && (ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                            && id.len() < 64 =>
                    {
                        id.push(ch);
                        self.revocation = Some(DisableFlow::Input(id));
                    }
                    _ => self.revocation = Some(DisableFlow::Input(id)),
                },
                DisableFlow::Confirm(id) => match key.code {
                    KeyCode::Char('y') => {
                        if editor.disable_user(&id).is_ok() {
                            self.revocation = Some(DisableFlow::Saving);
                            self.start_save();
                        } else {
                            self.revocation = Some(DisableFlow::Input(id));
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Esc => {}
                    _ => self.revocation = Some(DisableFlow::Confirm(id)),
                },
                DisableFlow::Saving => self.revocation = Some(DisableFlow::Saving),
                DisableFlow::SaveFailed => match key.code {
                    KeyCode::Char('r') if !editor.write_uncertain() => {
                        self.revocation = Some(DisableFlow::Saving);
                        self.start_save();
                    }
                    KeyCode::Char('d') => editor.discard(),
                    _ => self.revocation = Some(DisableFlow::SaveFailed),
                },
                DisableFlow::Done => {
                    if !matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                        self.revocation = Some(DisableFlow::Done);
                    }
                }
            }
            return false;
        }

        if let Some(browser)=self.import_browser.as_mut() {
            if key.code==KeyCode::Esc {self.import_browser=None;return false;}
            if let Some(path)=browser.key(key.code,"") {
                if let (Some(path),Some(ImportFlow::Input(source)))=(path.to_str(),self.importing.as_mut()) {
                    if path.len()<=crate::invite::MAX_URI && !path.chars().any(char::is_control) {
                        *source=Zeroizing::new(path.to_owned());
                        editor.error=None;
                    }
                }
                self.import_browser=None;
            }
            return false;
        }
        if let Some(flow) = self.importing.take() {
            match flow {
                ImportFlow::Input(mut source) => match key.code {
                    KeyCode::F(6) => {
                        self.import_browser=Some(FileBrowser::files(source.as_str()));
                        self.importing=Some(ImportFlow::Input(source));
                    }
                    KeyCode::Char('u') if key.modifiers==KeyModifiers::CONTROL => {
                        self.importing=Some(ImportFlow::Input(Zeroizing::new(String::new())));
                        editor.error=None;
                    }
                    KeyCode::Esc => {}
                    KeyCode::Enter if !source.is_empty() => {
                        if crate::qr_import::image_path(source.trim()) {
                            let path = Zeroizing::new(source.trim().to_owned());
                            let (tx, rx) = mpsc::channel();
                            match std::thread::Builder::new()
                                .name("theia-qr-import".into())
                                .spawn(move || {
                                    let _ = tx.send(crate::qr_import::scan_file(&path));
                                }) {
                                Ok(_) => {
                                    self.qr_scan = Some(QrScan {
                                        source,
                                        done: rx,
                                        cancelled: false,
                                    })
                                }
                                Err(_) => {
                                    editor.error =
                                        Some("Не удалось запустить сканирование QR.".into());
                                    self.importing = Some(ImportFlow::Input(source));
                                }
                            }
                            return false;
                        }
                        match client_import::read_product_source(source.trim()) {
                            Ok(client_import::ProductSource::Reality) => {
                                let value = Zeroizing::new(source.trim().to_owned());
                                match EnrollmentPanel::from_source(editor, value) {
                                    Ok(panel) => {
                                        editor.error = None;
                                        self.reality_enrollment = Some(panel);
                                    }
                                    Err(message) => {
                                        editor.error = Some(message.into());
                                        self.importing = Some(ImportFlow::Input(source));
                                    }
                                }
                            }
                            Ok(client_import::ProductSource::OwnTls(invitation)) => {
                                editor.error = None;
                                self.importing = Some(ImportFlow::Preview {
                                    invitation,
                                    ca: None,
                                    public_ref: None,
                                });
                            }
                            Err(_) => {
                                editor.error =
                                    Some("Не удалось прочитать приглашение. Проверьте ссылку целиком или абсолютный путь к файлу; при необходимости запросите новую ссылку.".into());
                                self.importing = Some(ImportFlow::Input(source));
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        source.pop();
                        self.importing = Some(ImportFlow::Input(source));
                    }
                    KeyCode::Char(ch)
                        if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                            && !ch.is_control()
                            && source.len() + ch.len_utf8() <= crate::invite::MAX_URI =>
                    {
                        source.push(ch);
                        self.importing = Some(ImportFlow::Input(source));
                    }
                    _ => self.importing = Some(ImportFlow::Input(source)),
                },
                ImportFlow::Preview {
                    invitation,
                    ca,
                    public_ref,
                } => {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('n') => {}
                        KeyCode::Char('r') if editor.can_refresh_credential(&invitation) => {
                            self.importing = Some(ImportFlow::RefreshConfirm(invitation));
                        }
                        KeyCode::Char('c') => {
                            self.importing = Some(ImportFlow::Trust {
                                invitation,
                                ca: ca.unwrap_or_default(),
                                public_ref,
                            })
                        }
                        KeyCode::Char('e') if !invitation.has_token() => {
                            self.importing = Some(ImportFlow::Credential {
                                invitation,
                                ca,
                                reference: public_ref.unwrap_or_default(),
                            });
                        }
                        KeyCode::Char('y') => {
                            if !invitation.has_token() && public_ref.is_none() {
                                editor.error = Some("Публичное приглашение требует отдельную env: ссылку на секрет.".into());
                                self.importing = Some(ImportFlow::Preview {
                                    invitation,
                                    ca,
                                    public_ref,
                                });
                            } else {
                                self.importing = Some(ImportFlow::Saving);
                                self.start_import(invitation, ca, public_ref);
                            }
                        }
                        _ => {
                            self.importing = Some(ImportFlow::Preview {
                                invitation,
                                ca,
                                public_ref,
                            })
                        }
                    }
                }
                ImportFlow::Trust {
                    invitation,
                    mut ca,
                    public_ref,
                } => match key.code {
                    KeyCode::Esc => {
                        self.importing = Some(ImportFlow::Preview {
                            invitation,
                            ca: None,
                            public_ref,
                        })
                    }
                    KeyCode::Enter => {
                        let verified = if ca.is_empty() {
                            Ok(None)
                        } else {
                            client_import::checked_ca_ref(Some(&ca))
                        };
                        match verified {
                            Ok(value) => {
                                editor.error = None;
                                self.importing = Some(ImportFlow::Preview {
                                    invitation,
                                    ca: value,
                                    public_ref,
                                });
                            }
                            Err(_) => {
                                editor.error = Some(
                                    "CA-файл должен быть доверенным PEM по абсолютному file: пути."
                                        .into(),
                                );
                                self.importing = Some(ImportFlow::Trust {
                                    invitation,
                                    ca,
                                    public_ref,
                                });
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        ca.pop();
                        self.importing = Some(ImportFlow::Trust {
                            invitation,
                            ca,
                            public_ref,
                        });
                    }
                    KeyCode::Char(ch) if !ch.is_control() && ca.len() + ch.len_utf8() <= 1024 => {
                        ca.push(ch);
                        self.importing = Some(ImportFlow::Trust {
                            invitation,
                            ca,
                            public_ref,
                        });
                    }
                    _ => {
                        self.importing = Some(ImportFlow::Trust {
                            invitation,
                            ca,
                            public_ref,
                        })
                    }
                },
                ImportFlow::Credential {
                    invitation,
                    ca,
                    mut reference,
                } => match key.code {
                    KeyCode::Esc => {
                        self.importing = Some(ImportFlow::Preview {
                            invitation,
                            ca,
                            public_ref: None,
                        })
                    }
                    KeyCode::Enter if client_import::valid_explicit_reference(&reference) => {
                        editor.error = None;
                        self.importing = Some(ImportFlow::Preview {
                            invitation,
                            ca,
                            public_ref: Some(reference),
                        });
                    }
                    KeyCode::Enter => {
                        editor.error =
                            Some("Нужна явная ссылка env:NAME, без значения токена.".into());
                        self.importing = Some(ImportFlow::Credential {
                            invitation,
                            ca,
                            reference,
                        });
                    }
                    KeyCode::Backspace => {
                        reference.pop();
                        self.importing = Some(ImportFlow::Credential {
                            invitation,
                            ca,
                            reference,
                        });
                    }
                    KeyCode::Char(ch) if ch.is_ascii_graphic() && reference.len() < 128 => {
                        reference.push(ch);
                        self.importing = Some(ImportFlow::Credential {
                            invitation,
                            ca,
                            reference,
                        });
                    }
                    _ => {
                        self.importing = Some(ImportFlow::Credential {
                            invitation,
                            ca,
                            reference,
                        })
                    }
                },
                ImportFlow::RefreshConfirm(invitation) => match key.code {
                    KeyCode::Char('y') => {
                        self.importing = Some(ImportFlow::RefreshSaving);
                        self.start_refresh(invitation);
                    }
                    KeyCode::Esc | KeyCode::Char('n') => {}
                    _ => self.importing = Some(ImportFlow::RefreshConfirm(invitation)),
                },
                ImportFlow::RefreshSaving => self.importing = Some(ImportFlow::RefreshSaving),
                ImportFlow::Saving => self.importing = Some(ImportFlow::Saving),
                state @ (ImportFlow::Done | ImportFlow::RefreshDone | ImportFlow::Failed) => {
                    if !matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                        self.importing = Some(state);
                    }
                }
            }
            return false;
        }

        if let Some(original) = self.pending {
            match key.code {
                KeyCode::Char('s') => {
                    self.start_save();
                    return false;
                }
                KeyCode::Char('d') => {
                    editor.discard();
                    self.pending = None;
                    return model.update(original);
                }
                KeyCode::Esc => {
                    self.pending = None;
                }
                _ => {}
            }
            return false;
        }

        if editor.editing {
            match key.code {
                KeyCode::Left | KeyCode::Up if !editor.choice_options().is_empty() => editor.cycle_choice(false),
                KeyCode::Right | KeyCode::Down | KeyCode::Char(' ') if !editor.choice_options().is_empty() => editor.cycle_choice(true),
                KeyCode::Esc => editor.cancel(),
                KeyCode::Enter => {
                    editor.accept();
                }
                KeyCode::Backspace => editor.backspace(),
                KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                    editor.input.clear()
                }
                KeyCode::Char(ch)
                    if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
                {
                    editor.insert(ch);
                }
                _ => {}
            }
            return false;
        }

        let active = matches!(
            (model.screen, editor.role()),
            (Screen::Server, Role::Server) | (Screen::Client, Role::Client)
        );
        if active {
            if key.code == KeyCode::Char('V')
                && (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
            {
                if editor.role() == Role::Server && !editor.selected_reality() {
                    editor.error =
                        Some("Выберите зарегистрированный REALITY inbound/профиль.".into());
                } else {
                    match editor.require_clean_records() {
                        Ok(()) => {
                            editor.error = None;
                            self.reality_status = Some(StatusPanel::open(editor));
                        }
                        Err(message) => editor.error = Some(message.into()),
                    }
                }
                return false;
            }
            if key.code == KeyCode::Char('K')
                && (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
            {
                match editor.require_clean_records() {
                    Ok(()) => match RegistrationPanel::reenroll(editor) {
                        Ok(panel) => {
                            editor.error = None;
                            self.reality_registration = Some(panel);
                        }
                        Err(message) => editor.error = Some(message.into()),
                    },
                    Err(message) => editor.error = Some(message.into()),
                }
                return false;
            }
            if key.code == KeyCode::Char('M')
                && (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
            {
                match editor.require_clean_records() {
                    Ok(()) => match RegistrationPanel::new(editor) {
                        Ok(panel) => {
                            editor.error = None;
                            self.reality_registration = Some(panel);
                        }
                        Err(message) => editor.error = Some(message.into()),
                    },
                    Err(message) => editor.error = Some(message.into()),
                }
                return false;
            }
            if key.code == KeyCode::Char('N')
                && (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
            {
                match editor.require_clean_records() {
                    Ok(()) => self.records = Some(RecordFlow::ChooseMode(editor.role(), 1)),
                    Err(message) => editor.error = Some(message.into()),
                }
                return false;
            }
            let record_action = if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT
            {
                match (editor.role(), key.code) {
                    (_, KeyCode::Char('D')) => Some(RecordAction::DeleteRecord),
                    (Role::Client, KeyCode::Char('A')) => Some(RecordAction::ActivateProfile),
                    (Role::Server, KeyCode::Char('G')) => Some(RecordAction::SetGrants),
                    (Role::Server, KeyCode::Char('Q')) => Some(RecordAction::SetQuota),
                    (Role::Server, KeyCode::Char('U')) => Some(RecordAction::DeleteUser),
                    (Role::Server, KeyCode::Char('E')) => Some(RecordAction::EditTls),
                    (Role::Client, KeyCode::Char('E')) => Some(RecordAction::EditTrust),
                    _ => None,
                }
            } else {
                None
            };
            if let Some(action) = record_action {
                match editor.record_fields(action) {
                    Ok(fields) if fields.is_empty() => {
                        match editor.review_record(action, &fields) {
                            Ok(review) => {
                                editor.error = None;
                                self.records = Some(RecordFlow::Confirm(Box::new(review)));
                            }
                            Err(message) => editor.error = Some(message.into()),
                        }
                    }
                    Ok(fields) => {
                        editor.error = None;
                        self.records = Some(RecordFlow::Input {
                            action,
                            fields,
                            focus: 0,
                        });
                    }
                    Err(message) => editor.error = Some(message.into()),
                }
                return false;
            }
            if editor.role() == Role::Client
                && key.code == KeyCode::Char('p')
                && key.modifiers.is_empty()
            {
                if editor.dirty() {
                    editor.error = Some("Сохраните или отмените черновик перед запуском.".into());
                } else {
                    #[cfg(windows)]
                    match crate::tui_system_proxy::Panel::open(
                        editor.saved_path().to_owned(),
                        editor.saved_sha256(),
                    ) {
                        Ok(panel) => {
                            self.system_proxy = Some(panel);
                            editor.error = None;
                        }
                        Err(message) => editor.error = Some(message.into()),
                    }
                    #[cfg(not(windows))]
                    {
                        editor.error = Some("Системный прокси: только Windows.".into());
                    }
                }
                return false;
            }
            // An editable draft is never silently sent to the server.
            // Ctrl+R requires an explicit saved source and then a second 'y'.
            let apply_shortcut =
                key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r');
            if editor.role() == Role::Server && (key.code == KeyCode::Char('v') || apply_shortcut) {
                if apply_shortcut && editor.dirty() {
                    editor.error =
                        Some("Сначала Ctrl+S: нельзя применять несохранённый черновик.".into());
                } else {
                    let saved = if editor.dirty() {
                        None
                    } else {
                        Some(editor.saved_sha256())
                    };
                    self.runtime = Some(RuntimePanel::open(saved, apply_shortcut));
                    editor.error = None;
                }
                return false;
            }
            if editor.role() == Role::Server && key.code == KeyCode::Char('R') {
                if editor.dirty() {
                    editor.error = Some(
                        "Сначала Ctrl+S: проверьте сохранённый TOML перед restart preflight."
                            .into(),
                    );
                } else {
                    self.runtime = Some(RuntimePanel::open_restart());
                    editor.error = None;
                }
                return false;
            }
            if editor.role() == Role::Server && key.code == KeyCode::Char('w') {
                if editor.dirty() {
                    editor.error = Some("Сохраните или отмените черновик перед подготовкой материалов.".into());
                } else {
                    editor.error = None;
                    self.reality_provision = Some(ProvisionPanel::new());
                }
                return false;
            }
            if editor.role() == Role::Server && key.code == KeyCode::Char('W') {
                if editor.dirty() {
                    editor.error =
                        Some("Сохраните или отмените черновик перед подготовкой REALITY.".into());
                } else {
                    match ProvisionPanel::bound(editor) {
                        Ok(panel) => {
                            editor.error = None;
                            self.reality_provision = Some(panel);
                        }
                        Err(message) => editor.error = Some(message.into()),
                    }
                }
                return false;
            }
            if editor.role() == Role::Server && key.code == KeyCode::Char('p') {
                if editor.dirty() {
                    editor.error =
                        Some("Сохраните или отмените черновик перед просмотром сети.".into());
                } else {
                    editor.error = None;
                    self.discovery = Some(DiscoveryPanel::new());
                }
                return false;
            }
            if key.code == KeyCode::Char('l') {
                match editor.public_share() {
                    Ok(link) => {
                        editor.error = None;
                        self.modal_action=0;
                        self.issuance = Some(IssueFlow::Public(link));
                    }
                    Err(message) => editor.error = Some(message.into()),
                }
                return false;
            }
            if editor.role() == Role::Server && key.code == KeyCode::Char('u') {
                if editor.dirty() {
                    editor.error =
                        Some("Сохраните или отмените черновик перед выдачей токена.".into());
                } else {
                    editor.error = None;
                    self.issue_kind = IssueKind::NewUser;
                    self.issuance = Some(IssueFlow::Input(String::new()));
                }
                return false;
            }
            if editor.role() == Role::Server && key.code == KeyCode::Char('t') {
                if editor.dirty() {
                    editor.error =
                        Some("Сохраните или отмените черновик перед ротацией токена.".into());
                } else {
                    editor.error = None;
                    self.issue_kind = IssueKind::Rotation;
                    self.issuance = Some(IssueFlow::Input(String::new()));
                }
                return false;
            }
            if editor.role() == Role::Server && key.code == KeyCode::Char('b') {
                if editor.dirty() {
                    editor.error =
                        Some("Сохраните или отмените черновик перед восстановлением.".into());
                } else {
                    editor.error = None;
                    self.issue_kind = IssueKind::Reenable;
                    let users=eligible_users(editor,true);
                    self.issuance = Some(IssueFlow::Input(if users.len()==1 {users[0].clone()}else{String::new()}));
                }
                return false;
            }
            if editor.role() == Role::Server && key.code == KeyCode::Char('x') {
                if editor.dirty() {
                    editor.error =
                        Some("Сохраните или отмените черновик перед отзывом доступа.".into());
                } else {
                    editor.error = None;
                    self.revocation = Some(DisableFlow::Input(String::new()));
                }
                return false;
            }
            if editor.role() == Role::Client && key.code == KeyCode::Char('I') {
                if editor.dirty() {
                    editor.error =
                        Some("Сохраните или отмените черновик перед импортом REALITY.".into());
                } else {
                    match EnrollmentPanel::bound(editor) {
                        Ok(panel) => {
                            editor.error = None;
                            self.reality_enrollment = Some(panel);
                        }
                        Err(message) => editor.error = Some(message.into()),
                    }
                }
                return false;
            }
            if editor.role() == Role::Client && key.code == KeyCode::Char('i') {
                if editor.dirty() {
                    editor.error = Some("Сохраните или отмените черновик перед импортом.".into());
                } else {
                    editor.error = None;
                    self.importing = Some(ImportFlow::Input(Zeroizing::new(String::new())));
                }
                return false;
            }
            // Focus is navigation inside the explicitly loaded typed form,
            // not a write and not a role switch. Never intercept text input.
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    editor.select_record(true);
                    return false;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    editor.select_record(false);
                    return false;
                }
                KeyCode::Tab | KeyCode::Right => {
                    editor.select_field(true);
                    return false;
                }
                KeyCode::BackTab | KeyCode::Left => {
                    editor.select_field(false);
                    return false;
                }
                _ => {}
            }
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
                self.start_save();
                return false;
            }
            if matches!(key.code, KeyCode::Enter | KeyCode::Char('e')) {
                if editor.selected_reality() && key.code == KeyCode::Enter {
                    self.value_preview = true;
                } else { editor.begin(); }
                return false;
            }
        }
        let navigation = matches!(
            key.code,
            KeyCode::Char('q' | '1' | '2') | KeyCode::Esc | KeyCode::Tab | KeyCode::BackTab
        ) || key.modifiers.contains(KeyModifiers::CONTROL)
            && key.code == KeyCode::Char('c');
        if editor.dirty() && navigation {
            self.pending = Some(key);
            return false;
        }
        model.update(key)
    }
}

fn shell_layout(area: Rect) -> [Rect; 3] {
    let parts = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(6),
        Constraint::Length(2),
    ])
    .split(area);
    [parts[0], parts[1], parts[2]]
}

fn home_layout(area: Rect) -> [Rect; 2] {
    let mut content = centered_column(area, 112);
    let wide = content.width >= 80;
    content.height = content.height.min(if wide { 11 } else { 18 });
    if area.height > content.height + 2 {
        content.y += 2;
    }
    let parts = Layout::default()
        .direction(if wide { Direction::Horizontal } else { Direction::Vertical })
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(content);
    [parts[0], parts[1]]
}

fn workspace_columns(area: Rect) -> Option<[Rect; 3]> {
    if area.width < 90 || area.height < 18 {
        return None;
    }
    let cols = Layout::horizontal([Constraint::Length((area.width / 5).clamp(28, 40)), Constraint::Length(2), Constraint::Min(1)]).split(area);
    let left = Layout::vertical([Constraint::Length(9), Constraint::Min(1)]).split(cols[0]);
    Some([left[0], left[1], cols[2]])
}

fn record_start(editor: &Editor, rect: Rect) -> usize {
    let rows = usize::from(rect.height.saturating_sub(2)).max(1);
    editor
        .workspace_selected()
        .saturating_sub(rows - 1)
        .min(editor.record_count().saturating_sub(rows))
}

/// Scrolling state belongs to presentation only. The signature contains
/// the fixed screen title and row count, not config values or secrets.
#[derive(Default)]
struct Viewport {
    offset: Cell<usize>,
    max: Cell<usize>,
    page: Cell<usize>,
    signature: Cell<u64>,
    focused_row: Cell<Option<usize>>,
}
impl Viewport {
    fn reset(&self) {
        self.offset.set(0);
        self.signature.set(0);
        self.focused_row.set(None);
    }
    fn move_by(&self, delta: isize) {
        self.offset.set(
            self.offset
                .get()
                .saturating_add_signed(delta)
                .min(self.max.get()),
        );
    }
    fn position(&self, title: &str, count: usize, page: usize, focus: Option<usize>) -> usize {
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        title.hash(&mut hash);
        count.hash(&mut hash);
        page.hash(&mut hash);
        let signature = hash.finish();
        let max = count.saturating_sub(page);
        if self.signature.replace(signature) != signature {
            self.offset.set(
                focus
                    .map_or(0, |i| i.saturating_sub(page.saturating_sub(3)))
                    .min(max),
            );
        }
        if self.focused_row.replace(focus) != focus {
            if let Some(row) = focus {
                let current = self.offset.get();
                if row < current {
                    self.offset.set(row.min(max));
                } else if row >= current.saturating_add(page) {
                    self.offset.set(row.saturating_sub(page.saturating_sub(1)).min(max));
                }
            }
        }
        self.max.set(max);
        self.page.set(page);
        let position = self.offset.get().min(max);
        self.offset.set(position);
        position
    }
}

/// Soft-wrap into explicit visual rows so every part of a long review or
/// invitation remains accessible. No screen content is retained by Viewport.
fn visual_rows(body: &str, width: usize) -> (Vec<Line<'_>>, Option<usize>) {
    let width = width.max(1);
    let mut rows = Vec::new();
    let mut focus = None;
    for line in body.split('\n') {
        let selected = line.starts_with("> ") || line.starts_with("› ");
        let style = if selected {
            focus.get_or_insert(rows.len());
            Style::default()
                .fg(ACCENT)
                .bg(FOCUS)
                .add_modifier(Modifier::BOLD)
        } else if line.starts_with("Ошибка") || line.starts_with("ОТКАЗ") || line.starts_with("Отказ:") {
            Style::default().fg(ERROR).add_modifier(Modifier::BOLD)
        } else if line.starts_with("ШАГ ") || line.starts_with("ПРЕДЛОЖЕННЫЙ ") || line.starts_with("ПУТЬ К TOML") || line.starts_with("ВЫБЕРИТЕ ") || line.starts_with("НАЧАЛО РАБОТЫ") || line.starts_with("SMARTTHEIA REALITY") || line.starts_with("СЕТЬ ") || line == "ДОСТУП" || line == "OWN-TLS" || line == "ПРОФИЛИ" {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else if line.starts_with("ВНИМАНИЕ") || line.starts_with("КОНФИДЕНЦИАЛЬНО") || line.starts_with("СЕКРЕТ:")
        {
            Style::default()
                .fg(WARNING)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let mut start = 0;
        let mut used = 0;
        let mut break_at = None;
        for (i, ch) in line.char_indices() {
            let mut encoded = [0; 4];
            let encoded: &str = ch.encode_utf8(&mut encoded);
            let cw = Span::raw(encoded).width();
            if used + cw > width && i > start {
                let end = break_at.filter(|&p| p > start).unwrap_or(i);
                rows.push(tui_widgets::report_row(&line[start..end], style, start == 0));
                start = end;
                used = Span::raw(&line[start..i]).width();
                break_at = None;
            }
            used += cw;
            if ch == ' ' {
                break_at = Some(i + ch.len_utf8());
            }
        }
        rows.push(tui_widgets::report_row(&line[start..], style, start == 0));
    }
    (rows, focus)
}

fn panel_at(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    body: &str,
    focused: bool,
    viewport: Option<&Viewport>,
) {
    tui_widgets::canvas(frame, area);
    let area = if viewport.is_some() { centered_column(area, 132) } else { area };
    let page = usize::from(area.height.saturating_sub(2)).max(1);
    let (rows, focus) = visual_rows(body, usize::from(area.width.saturating_sub(2)));
    let count = rows.len();
    // Auto-reveal focus in typed forms only. Confirmation/review screens
    // start at their first line, including warnings, not at the confirm key.
    let focus = focus.filter(|_| body.contains("Tab: поле") || body.contains("Tab/Shift+Tab: поле"));
    let offset = viewport.map_or(0, |v| v.position(title, count, page, focus));
    let caption = if viewport.is_some() && count > page {
        format!(
            "{title}  ·  {}–{}/{}",
            offset + 1,
            (offset + page).min(count),
            count
        )
    } else {
        title.to_owned()
    };
    let visible: Vec<_> = rows.into_iter().skip(offset).take(page).collect();
    let area = if viewport.is_some() { Rect::new(area.x, area.y, area.width, area.height.min((visible.len() as u16).saturating_add(2))) } else { area };
    frame.render_widget(
        Paragraph::new(visible).block(
            tui_widgets::report_section(&caption, focused),
        ),
        area,
    );
}

fn panel(frame: &mut Frame<'_>, area: Rect, title: &str, body: &str, focused: bool) {
    panel_at(frame, area, title, body, focused, None);
}

/// A persistent step header and action strip separate guidance from the
/// scrollable form/review. No display-only shortcut may commit a transaction.
fn guided_layout(area: Rect, count: Option<usize>, review_rows: usize) -> [Rect; 3] {
    let mut area = centered_column(area, 132);
    let preferred = count.map_or_else(
        || review_rows.saturating_add(8).clamp(10, 40),
        |count| count.saturating_mul(3).saturating_add(10).clamp(18, 36),
    ) as u16;
    let height = area.height.min(preferred);
    area.y += (area.height - height).min(8) / 2;
    area.height = height;
    if area.height < 10 {
        return [Rect::new(area.x, area.y, area.width, 0), area, Rect::new(area.x, area.bottom(), area.width, 0)];
    }
    let footer = if area.width < 90 { 4 } else { 3 };
    let parts = Layout::vertical([Constraint::Length(3), Constraint::Min(4), Constraint::Length(footer)]).split(area);
    [parts[0], parts[1], parts[2]]
}

fn guided_form_area(area: Rect, count: usize) -> Rect {
    guided_layout(area, Some(count), 0)[1]
}

fn draw_guided(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    body: &str,
    guide: (usize, usize, &'static str, &'static str),
    viewport: Option<&Viewport>,
    content: (Option<Form>, Option<ReferenceReview>),
) {
    let (form, review) = content;
    let (step, total, heading, keys) = guide;
    tui_widgets::canvas(frame, area);
    let width = area.width.min(132).saturating_sub(4);
    let review_lines = if form.is_none() {
        Some(match &review {
            Some(review) => review.lines(width),
            None => visual_rows(body, usize::from(width)).0,
        })
    } else {
        None
    };
    let parts = guided_layout(area, form.as_ref().map(|f| f.fields.len()), review_lines.as_ref().map_or(0, Vec::len));
    let caption = format!("{title} · ШАГ {step}/{total}");
    if parts[0].height > 0 {
        let mut segments = vec![Span::styled(format!(" {step}/{total} "), Style::default().fg(BG).bg(ACCENT).add_modifier(Modifier::BOLD)), Span::raw("  ")];
        for number in 1..=total {
            segments.push(Span::styled(if number <= step { "━━━ " } else { "─── " }, Style::default().fg(if number <= step { ACCENT } else { MUTED })));
        }
        segments.push(Span::styled(heading, Style::default().fg(TEXT).add_modifier(Modifier::BOLD)));
        frame.render_widget(Paragraph::new(vec![
            Line::styled(caption.as_str(), Style::default().fg(MUTED)),
            Line::from(segments),
        ]).style(Style::default().bg(SURFACE)), parts[0]);
    }
    if let Some(form) = form {
        let title = if parts[0].height == 0 { caption.as_str() } else { "Параметры" };
        if matches!(heading, "Выбор пользователей" | "Выбор пользователя" | "Выбор защиты" | "Выбор адреса") { form.render_picker(frame, parts[1], title); }
        else { form.render(frame, parts[1], title); }
    } else if let Some(lines) = review_lines {
        // Same width as stepper and key bar: never re-center a nested report.
        let body_area = Rect::new(parts[1].x.saturating_add(2), parts[1].y, parts[1].width.saturating_sub(4), parts[1].height);
        let page = usize::from(body_area.height.saturating_sub(1)).max(1);
        let count = lines.len();
        let offset = viewport.map_or(0, |v| v.position(&caption, count, page, None));
        let status = if count > page {
            format!("{}–{}/{} · Shift+PgUp/PgDn или колесо", offset + 1, (offset + page).min(count), count)
        } else if parts[0].height == 0 {
            caption.clone()
        } else {
            String::new()
        };
        let mut visible: Vec<_> = lines.into_iter().skip(offset).take(page).collect();
        if !status.is_empty() {
            visible.push(Line::styled(status, Style::default().fg(MUTED)));
        }
        frame.render_widget(Paragraph::new(visible).style(Style::default().fg(TEXT).bg(BG)), body_area);
    }
    if parts[2].height > 0 {
        frame.render_widget(Paragraph::new(vec![
            Line::styled("Следующее действие", Style::default().fg(MUTED)),
            tui_widgets::key_line(keys),
        ]).style(Style::default().bg(SURFACE)).wrap(Wrap { trim: true }), parts[2]);
    }
}

fn draw(frame: &mut Frame<'_>, model: &Model, interaction: Option<&Interaction>) {
    let area = frame.area();
    if area.width < 32 || area.height < 10 {
        frame.render_widget(
            Paragraph::new("Терминал слишком мал. Увеличьте окно (минимум 32x10).")
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    tui_widgets::canvas(frame, area);
    let parts = shell_layout(area);
    let viewport = interaction.map(|ui| &ui.viewport);
    macro_rules! modal_panel {
        ($($arg:expr),+ $(,)?) => { panel_at($($arg),+, viewport) }
    }
    let header = match model.screen {
        Screen::Server => format!(
            "THEIA  •  Сервер  |  {}",
            interaction
                .map(|ui| ui.server_process.status())
                .unwrap_or("Состояние неизвестно")
        ),
        Screen::Client => {
            let local = interaction.is_some_and(|ui| {
                ui.reality_status
                    .as_ref()
                    .is_some_and(StatusPanel::local_running)
                    || ui
                        .client_background
                        .as_ref()
                        .is_some_and(StatusPanel::local_running)
            });
            format!(
                "THEIA  •  Клиент  |  {}",
                if local {
                    "Локальный процесс запущен/запускается"
                } else {
                    "Локальный процесс не запущен этой панелью"
                }
            )
        }
        _ => "THEIA  •  Локальное управление".into(),
    };
    let (brand, status) = header.split_once("  |  ").unwrap_or((header.as_str(), ""));
    let file = interaction.and_then(|ui| Interaction::panel_role(model).and_then(|role| ui.editor_for(role)));
    let saved = match file {
        Some(e) if e.write_uncertain() => "Файл: запись не подтверждена",
        Some(e) if e.dirty() => "Файл: не сохранён",
        Some(_) => "Файл: сохранён",
        None => "Файл: не открыт",
    };
    let applied=if model.screen==Screen::Server {
        interaction.and_then(|ui|ui.last_apply).and_then(|(digest,kind,revision)| {
            file.filter(|e| !e.dirty() && e.saved_sha256()==digest).map(|_|format!("Последнее подтверждение: {kind}, rev {revision}"))
        })
    }else{None};
    let state = if status.is_empty() { String::new() } else { format!("{saved} · {}",applied.unwrap_or_else(||"Применение: не подтверждено этой панелью".into())) };
    frame.render_widget(Paragraph::new(vec![Line::from(vec![
        Span::styled(format!(" {brand} "), Style::default().fg(BG).bg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  {status}"), Style::default().fg(TEXT)),
    ]), Line::styled(state, Style::default().fg(MUTED))]).style(Style::default().bg(SURFACE)), parts[0]);
    match model.screen {
        Screen::Home => {
            let cards = home_layout(parts[1]);
            draw_role_card(frame, cards[0], Role::Server, model.selected == Role::Server);
            draw_role_card(frame, cards[1], Role::Client, model.selected == Role::Client);
        }
        Screen::Server | Screen::Client => {
            let role = if model.screen == Screen::Server { Role::Server } else { Role::Client };
            draw_workspace(frame, parts[1], role, interaction.and_then(|ui| ui.editor_for(role)), interaction.map_or(0, |ui| ui.welcome_choice), interaction);
        }
        Screen::Help => modal_panel!(
            frame,
            parts[1],
            "Справка",
            "1 / 2: сервер / клиент\nTab / Shift+Tab: сменить выбор\nEnter: открыть выбранную панель\nEsc: назад\n? / F1: справка\nq / Ctrl+C: выйти\n\nС явными --role и --config: j/k выбирают inbound/профиль, Tab поле, Enter/e правит поле. l: публичная ссылка без токена. В клиентской панели i: общий импорт URI/локального файла: own-TLS CA или REALITY fingerprint/admission, без запуска; p: Windows system proxy (отдельные действия и подтверждения). В серверной панели u создаёт пользователя, t: подтверждённая ротация bearer существующего активного пользователя, x: глобальное отключение существующего пользователя (только TOML), b: восстановление с новым токеном. В сетевом обзоре p: пассивный IP обзор, i: согласие ipify; r: группы кандидатов и ручной CIDR (только офлайн), b: IP-список до 8 (Space), d: домен из каталога (отдельные DNS и H2/H3 согласия), t: один IP H2+H3. Ручное v проверяет состояние; Ctrl+R на сохранённой серверной конфигурации открывает отдельное подтверждение CAS Apply (y), а не молча перезапускает. Открытие панелей не выполняет сетевых запросов и не меняет системный прокси.",
            true,
        ),
    }
    if let Some(ui) = interaction.filter(|ui| ui.value_preview) {
        if let Some(text)=&ui.preview_text {
            modal_panel!(frame,parts[1],"Полное сообщение / значение",text,true);
        } else if let Some(editor) = ui.editor.as_ref() {
            let body = format!("{}\n\n{}\n\nEsc: закрыть", editor.selection_summary(), editor.field_value());
            modal_panel!(frame, parts[1], "Полное значение параметра", &body, true);
        }
    } else if interaction.is_some_and(|ui| ui.qr_scan.is_some()) {
        tui_widgets::canvas(frame, parts[1]);
        let cancelled = interaction
            .and_then(|ui| ui.qr_scan.as_ref())
            .is_some_and(|scan| scan.cancelled);
        modal_panel!(
            frame,
            parts[1],
            "Чтение QR",
            if cancelled {
                "Импорт отменён. Результат декодирования будет отброшен."
            } else {
                "Локальное декодирование изображения. Никакой сети или записи. Esc: отменить."
            },
            true
        );
    } else if let Some(dialog) = interaction.and_then(|ui| ui.config_dialog.as_ref()) {
        tui_widgets::canvas(frame, parts[1]);
        if let Some(guide) = dialog.guide() {
            draw_guided(frame, parts[1], dialog.title(), &dialog.body(), guide, viewport, (dialog.form(), dialog.reference_review()));
        } else if let Some(form) = dialog.form() {
            form.render_picker(frame, centered_column(parts[1], 108), dialog.title());
        } else {
            modal_panel!(frame, parts[1], dialog.title(), &dialog.body(), true);
        }
    } else if let Some(menu) = interaction.and_then(|ui| ui.menu.as_ref()) {
        tui_widgets::canvas(frame, parts[1]);
        menu.render(frame, parts[1]);
    } else if let Some(ui) = interaction.filter(|ui| ui.show_server_process) {
        tui_widgets::canvas(frame, parts[1]);
        let items = ui.server_process.actions();
        if let Some([report, controls]) = action_layout(parts[1], items.len()) {
            modal_panel!(frame, report, "Состояние сервера", &ui.server_process.summary(), false);
            Actions { items: &items, selected: ui.server_process.action_focus() }.render(frame, controls);
        } else {
            modal_panel!(frame, parts[1], "Сервер • запуск и остановка", &ui.server_process.body(), true);
        }
    } else if let Some(monitor) = interaction.and_then(|ui| ui.traffic_monitor.as_ref()) {
        tui_widgets::canvas(frame, parts[1]);
        if parts[1].width < 46
            || parts[1].height < 17
            || (parts[1].width < 86 && parts[1].height < 27)
        {
            modal_panel!(frame, parts[1], "Монитор трафика", &monitor.body(), true);
        } else {
            monitor.render(frame, parts[1]);
        }
    } else if let Some(status) = interaction.and_then(|ui| ui.reality_status.as_ref()) {
        tui_widgets::canvas(frame, parts[1]);
        let items = status.actions();
        if let Some([report, controls]) = action_layout(parts[1], items.len()) {
            modal_panel!(frame, report, "Подключение и состояние REALITY", &status.summary(), false);
            Actions { items: &items, selected: status.action_focus() }.render(frame, controls);
        } else {
            modal_panel!(frame, parts[1], "Подключение и состояние REALITY", &status.body(), true);
        }
    } else if let Some(registration) = interaction.and_then(|ui| ui.reality_registration.as_ref()) {
        if let Some(form)=registration.form() {
            draw_guided(frame,parts[1],"Регистрация материалов",&registration.body(),(1,2,"Параметры доверия","↑↓ поле · Enter проверить · Ctrl+U очистить · Esc назад"),viewport,(Some(form),None));
        }else{modal_panel!(frame,parts[1],"Регистрация материалов",&registration.body(),true);}
    } else if let Some(enrollment) = interaction.and_then(|ui| ui.reality_enrollment.as_ref()) {
        draw_guided(frame, parts[1], "Импорт REALITY", &enrollment.body(), enrollment.guide(), viewport, (enrollment.form(), None));
    } else if let Some(provision) = interaction.and_then(|ui| ui.reality_provision.as_ref()) {
        if let Some(guide) = provision.guide() {
            draw_guided(frame, parts[1], "Мастер REALITY", &provision.body(), guide, viewport, (provision.form(), provision.reference_review()));
        } else {
            modal_panel!(frame, parts[1], "Мастер REALITY", &provision.body(), true);
        }
    } else if let Some(runtime) = interaction.and_then(|ui| ui.runtime.as_ref()) {
        let items=runtime.actions();
        if let Some([report,controls])=action_layout(parts[1],items.len()) {
            modal_panel!(frame,report,runtime.title(),&runtime.body(),false);
            Actions{items:&items,selected:interaction.map_or(0,|ui|ui.modal_action)}.render(frame,controls);
        } else {modal_panel!(frame,parts[1],runtime.title(),&runtime.body(),true);}
    } else if interaction.is_some_and(|ui| ui.saving.is_some()) {
        modal_panel!(
            frame,
            parts[1],
            "Сохранение конфигурации",
            "Проверка изменений и атомарная запись TOML выполняются.\nRuntime не перезагружается.\nДождитесь результата операции.",
            true,
        );
    } else if let Some(flow) = interaction.and_then(|ui| ui.records.as_ref()) {
        let mut body = flow.body();
        if let Some(editor) = interaction.and_then(|ui| ui.editor.as_ref()) {
            if let Some(error) = editor.error.as_deref() {
                body.push_str(&format!("\n\n{error}"));
            }
            if let RecordFlow::Input { action, .. } = flow {
                if let Some(catalog) = editor.record_user_catalog(*action) {
                    body.push_str(&format!("\n\n{catalog}"));
                }
            }
        }
        let form = flow.form(interaction.and_then(|ui| ui.editor.as_ref()));
        if form.is_some() {
            let guide = if matches!(flow, RecordFlow::ChooseMode(..)) {
                (1, 2, "Выбор защиты", "↑↓ выбрать · Enter продолжить · Esc назад")
            } else {
                (1, 2, "Параметры", "↑↓ поле · Ctrl+U очистить · Enter проверить · Esc назад")
            };
            draw_guided(frame, parts[1], "Настройка подключения", &body, guide, viewport, (form, None));
        } else {
            modal_panel!(frame, parts[1], "Настройка записи", &body, true);
        }
    } else if let Some(flow) = interaction.and_then(|ui| ui.issuance.as_ref()) {
        draw_issuance(
            frame,
            parts[1],
            flow,
            interaction.and_then(|ui| ui.editor.as_ref()),
            interaction.map_or(IssueKind::NewUser, |ui| ui.issue_kind),
            viewport,
            interaction.map_or(0, |ui| ui.modal_action),
        );
    } else if let Some(flow) = interaction.and_then(|ui| ui.revocation.as_ref()) {
        draw_revocation(
            frame,
            parts[1],
            flow,
            interaction.and_then(|ui| ui.editor.as_ref()),
            viewport,
        );
    } else if let Some(browser)=interaction.and_then(|ui|ui.import_browser.as_ref()) {
        draw_guided(frame,parts[1],"Выбрать файл приглашения или QR","",(1,2,"Выбор файла","↑↓ выбрать · Enter выбрать путь · Esc назад"),viewport,(Some(browser.form()),None));
    } else if let Some(flow) = interaction.and_then(|ui| ui.importing.as_ref()) {
        draw_import(
            frame,
            parts[1],
            flow,
            interaction.and_then(|ui| ui.editor.as_ref()),
            viewport,
        );
    } else if interaction.is_some_and(|ui| ui.pending.is_some()) {
        modal_panel!(
            frame,
            parts[1],
            "Не сохранено: подтвердите переход",
            "s: сохранить и продолжить\nd: отменить изменения и продолжить\nEsc: остаться в редакторе\n\nНи одна опция не применяет конфигурацию к runtime.",
            true,
        );
    } else if let Some(domain) = interaction.and_then(|ui| ui.domain.as_ref()) {
        if let Some(form)=domain.form() {
            draw_guided(frame,parts[1],"Каталог TLS-референсов",&domain.body(),(1,2,"Выбор адреса","↑↓ выбрать · Space отметить IP · Enter предпросмотр · m домен · Esc назад"),viewport,(Some(form),None));
        } else {modal_panel!(frame,parts[1],"Каталог TLS-референсов",&domain.body(),true);}
    } else if let Some(batch) = interaction.and_then(|ui| ui.candidate_batch.as_ref()) {
        if let Some(form)=batch.form() {
            draw_guided(frame,parts[1],"Проверка выбранных IP",&batch.body(),(1,2,"Выбор адреса","↑↓ выбрать · Space отметить IP · Enter предпросмотр · Esc назад"),viewport,(Some(form),None));
        } else {modal_panel!(frame,parts[1],"Проверка выбранных IP",&batch.body(),true);}
    } else if let Some(review) = interaction.and_then(|ui| ui.candidates.as_ref()) {
        modal_panel!(
            frame,
            parts[1],
            "Области поиска референсов (офлайн)",
            &review.body(),
            true,
        );
    } else if let Some(probe) = interaction.and_then(|ui| ui.probe.as_ref()) {
        modal_panel!(
            frame,
            parts[1],
            "TLS/H2 + QUIC/H3: только один разрешённый IP:443",
            &probe.body(),
            true,
        );
    } else if let Some(discovery) = interaction.and_then(|ui| ui.discovery.as_ref()) {
        modal_panel!(
            frame,
            parts[1],
            "Публичный IP и план кандидатов (без сканирования)",
            &discovery.body(),
            true,
        );
    }
    #[cfg(windows)]
    if let Some(proxy) = interaction.and_then(|ui| ui.system_proxy.as_ref()) {
        tui_widgets::canvas(frame,parts[1]);
        let items=proxy.actions();
        if let Some([report,controls])=action_layout(parts[1],items.len()) {
            modal_panel!(frame,report,"Системный прокси Windows",&proxy.body(),false);
            Actions{items:&items,selected:interaction.map_or(0,|ui|ui.modal_action)}.render(frame,controls);
        } else {modal_panel!(frame,parts[1],"Системный прокси Windows",&proxy.body(),true);}
    }
    let footer = if interaction.is_some_and(|ui| !ui.workspace_visible()) {
        "Shift+PgUp/PgDn прокрутка · F7 полное значение · Esc назад (если доступно)"
    } else {
        match model.screen {
            Screen::Home => "↑↓ / Tab выбрать роль · Enter открыть · F1 помощь · q выход",
            Screen::Help => "Shift+PgUp/PgDn или колесо: прокрутка  ·  Esc назад",
            Screen::Server | Screen::Client if interaction.is_some_and(|ui| Interaction::panel_role(model).is_some_and(|role| ui.editor_for(role).is_none())) => {
                "↑↓ выбрать · Enter продолжить · F2 все действия · Esc назад"
            }
            Screen::Server => {
                "Tab / F6 Фокус · Alt+←/→ Раздел · F7 Значение · F3 Файл · F2 Меню · F5 Сервер · Ctrl+S Сохранить"
            }
            Screen::Client => {
                "Tab / F6 Фокус · Alt+←/→ Раздел · F7 Значение · F3 Файл · F2 Меню · Ctrl+S Сохранить"
            }
        }
    };
    let active_error=interaction.and_then(|ui|ui.active_form()).map(|f|f.error).filter(|s|!s.is_empty());
    let editor_error=interaction.and_then(|ui|Interaction::panel_role(model).and_then(|role|ui.editor_for(role))).and_then(|e|e.error.as_deref());
    if let Some(error)=active_error.as_deref().or(editor_error) {
        let line=tui_widgets::fit_value(&format!("Ошибка: {error}"),parts[2].width,false);
        frame.render_widget(Paragraph::new(vec![Line::styled(line,Style::default().fg(ERROR)),Line::styled("F7 — полное сообщение",Style::default().fg(TEXT))]).style(Style::default().bg(SURFACE)),parts[2]);
        return;
    }
    frame.render_widget(Paragraph::new(tui_widgets::key_line(footer))
        .style(Style::default().bg(SURFACE)).wrap(Wrap { trim: true }), parts[2]);
}

fn eligible_users(editor: &Editor, disabled: bool) -> Vec<String> {
    editor
        .workspace_users()
        .into_iter()
        .filter(|(_, is_disabled, granted)| *granted && *is_disabled == disabled)
        .map(|(id, _, _)| id)
        .collect()
}

fn cycle_user(editor: &Editor, current: &str, disabled: bool, forward: bool) -> String {
    let users = eligible_users(editor, disabled);
    if users.is_empty() {
        return current.to_owned();
    }
    let selected = users.iter().position(|id| id == current);
    let next = match selected {
        Some(i) if forward => (i + 1) % users.len(),
        Some(i) => (i + users.len() - 1) % users.len(),
        None if forward => 0,
        None => users.len() - 1,
    };
    users[next].clone()
}

fn user_picker(editor: Option<&Editor>, current: &str, disabled: bool) -> Option<Form> {
    let editor = editor?;
    let users = eligible_users(editor, disabled);
    if users.is_empty() { return None; }
    let selected = users.iter().position(|id| id == current).unwrap_or(usize::MAX);
    Some(Form {
        fields: users.into_iter().enumerate().map(|(id, value)| Field {
            id, label: if disabled { "Отключённый пользователь" } else { "Пользователь с доступом" },
            value, hint: "Enter — проверить выбранного пользователя. Изменение требует отдельного подтверждения.",
        }).collect(),
        selected,
        lead: if current.is_empty() { "Выберите пользователя стрелками или мышью.".into() }
            else { format!("Выбран: {current}") },
        error: editor.error.clone().unwrap_or_default(),
    })
}

fn user_choices(editor: Option<&Editor>, current: &str, disabled: bool) -> String {
    let users = editor
        .map(|e| eligible_users(e, disabled))
        .unwrap_or_default();
    if users.is_empty() {
        return "Нет подходящих пользователей в выбранном inbound.".into();
    }
    let selected = users.iter().position(|id| id == current).unwrap_or(0);
    let start = selected
        .saturating_sub(4)
        .min(users.len().saturating_sub(5));
    let rows = users
        .iter()
        .skip(start)
        .take(5)
        .map(|id| format!("{} {id}", if id == current { "›" } else { " " }))
        .collect::<Vec<_>>()
        .join("\n");
    format!("Пользователи выбранного inbound · ↑↓ выбрать, Enter проверить\n{rows}\nПоказано {}–{} из {}", start + 1, (start + 5).min(users.len()), users.len())
}

fn draw_issuance(
    frame: &mut Frame<'_>,
    area: Rect,
    flow: &IssueFlow,
    editor: Option<&Editor>,
    kind: IssueKind,
    viewport: Option<&Viewport>,
    action_focus: usize,
) {
    let rotating = kind == IssueKind::Rotation;
    let recovering = kind == IssueKind::Reenable;
    if let IssueFlow::Input(id) = flow {
        if !rotating && !recovering {
            let form = Form {
                fields: vec![Field { id: 0, label: "Имя пользователя", value: id.clone(), hint: "Введите уникальное имя, например phone или laptop. Enter — проверить." }],
                selected: 0,
                lead: "Создаётся новый токен и доступ только к выбранному подключению. Сервер не перезапускается.".into(),
                error: editor.and_then(|e| e.error.clone()).unwrap_or_default(),
            };
            draw_guided(frame, area, "Новый пользователь", "", (1, 2, "Доступ", "Enter продолжить · Backspace удалить · Esc отменить"), viewport, (Some(form), None));
            return;
        }
        if let Some(form) = user_picker(editor, id, recovering) {
            let title = if recovering { "Восстановление отключённого пользователя" } else { "Ротация токена" };
            draw_guided(frame, area, title, "", (1, 2, "Выбор пользователя", "↑↓ выбрать · Enter проверить · Esc отменить"), viewport, (Some(form), None));
            return;
        }
    }
    let (title, body) = match flow {
        IssueFlow::Input(id) => (
            if recovering {
                "Восстановление отключённого пользователя"
            } else if rotating {
                "Ротация токена существующего пользователя"
            } else {
                "Новый пользователь для выбранного inbound"
            },
            format!(
                "ID пользователя: {id}\n\n{}\n\nEnter: продолжить  Backspace: удалить  Esc: отменить\n\n{}",
                if recovering {
                    "Только отключённый пользователь с grant на выбранном inbound. Будет создан новый bearer."
                } else if rotating {
                    "Только активный пользователь с grant на выбранном inbound. Новый bearer будет выдан однократно."
                } else {
                    "Сгенерировать 256-битный токен и назначить доступ только к выбранному inbound."
                },
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        IssueFlow::Confirm(id) => (
            if recovering {
                "Подтверждение восстановления доступа"
            } else if rotating {
                "Подтверждение глобальной ротации токена"
            } else {
                "Подтверждение нового пользователя"
            },
            format!(
                "Пользователь: {id}\nInbound: {}\n\n{}\n\ny: подтвердить и сохранить  n/Esc: отменить",
                editor.map_or("", |e| e.selected_record_id()),
                if recovering {
                    "ВНИМАНИЕ: восстановление глобально по существующим grants. Создаётся НОВЫЙ bearer; прежний токен не восстанавливается. Только отдельный auth-only CAS Apply меняет runtime."
                } else if rotating {
                    "ВНИМАНИЕ: замена bearer глобальна для всех inbound данного пользователя. Старый токен станет недействительным для НОВЫХ подключений только после отдельного auth-only CAS Apply. Уже открытые туннели не разрываются. Grants и disabled не меняются. Runtime НЕ обновляется автоматически."
                } else {
                    "Создать токен CSPRNG и сохранить новую запись в server.toml? Это НЕ перезагружает сервер."
                }
            ),
        ),
        IssueFlow::Saving => (
            "Сохранение токена",
            "Проверка и атомарная запись TOML. Конфиденциальная ссылка скрыта; runtime не меняется."
                .into(),
        ),
        IssueFlow::SaveFailed if editor.is_some_and(Editor::write_uncertain) => (
            "Состояние записи неизвестно: ссылка заблокирована",
            "TOML мог быть заменён. Токен уничтожен; runtime не обновлён. Откройте редактор заново и проверьте состояние. d: закрыть черновик."
                .into(),
        ),
        IssueFlow::SaveFailed => (
            "Сохранение НЕ удалось: ссылка заблокирована",
            format!(
                "{}\n\n{}\n\nr: повторить запись  d: удалить черновик и токен",
                if recovering {
                    "Восстановление НЕ сохранено. Новый токен не показывался."
                } else if rotating {
                    "Новый digest НЕ сохранён. Старый токен остаётся в файле; runtime не меняется."
                } else {
                    "Новый пользователь НЕ записан. Токен не показывался."
                },
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        IssueFlow::Offer => (
            "Одноразовая выдача конфиденциальной ссылки",
            if recovering {
                "Восстановление и новый digest сохранены. Runtime не обновлён; отдельный Apply обязателен. Старый токен не восстанавливается.\n\ny: показать один раз  f: экспорт в защищённый файл  n/Esc: отказаться и стереть токен".into()
            } else if rotating {
                "Новый digest сохранён в server.toml, runtime НЕ обновлён. Старый bearer ещё принимается runtime до отдельного auth-only CAS Apply. Ссылка содержит НОВЫЙ bearer, повторное восстановление невозможно.\n\ny: показать один раз  f: экспорт в защищённый файл  n/Esc: отказаться и стереть токен"
                    .into()
            } else {
                "server.toml сохранён. Runtime ещё не обновлён.\nСсылка содержит действующий bearer-токен. Не публиковать.\nПовторного показа после закрытия не будет.\n\ny: показать ссылку один раз\nf: экспорт в защищённый файл\nn/Esc: отказаться и уничтожить токен в памяти"
                    .into()
            },
        ),
        IssueFlow::ShareConfirm { action, public } => (
            "Подтвердить передачу приглашения",
            format!("{}\n{}\ny: подтвердить | n/Esc: назад",
                match action {
                    crate::tui_share::Action::Qr => "Создать защищённый SVG QR. Если полный URI не помещается, создать защищённый URI-файл без усечения.",
                    crate::tui_share::Action::Clipboard => "Отправить запрос OSC 52 в доверенный терминал. Терминал может отказать; история clipboard или синхронизация могут сохранить ссылку. Очистите буфер самостоятельно.",
                },
                if public.is_none() { "КОНФИДЕНЦИАЛЬНО: будет использован одноразовый bearer; не передавайте недоверенному терминалу или получателю." } else { "Публичное приглашение без bearer." })
        ),
        IssueFlow::Sharing => ("Передача приглашения", "Операция выполняется; URI скрыт.".into()),
        IssueFlow::ShareDone(message) => ("Результат передачи", format!("{message}\nEsc: закрыть. Runtime не изменён.")),
        IssueFlow::ConfirmExport => (
            "Подтверждение конфиденциального экспорта",
            "Создать новый защищённый файл рядом с конфигурацией сервера? Ссылка не будет показана. Файл содержит bearer; храните и передавайте его только доверенным способом. Повторная выдача недоступна.\n\ny: сохранить  n/Esc: назад"
                .into(),
        ),
        IssueFlow::Exporting => (
            "Защищённый экспорт",
            "Создаётся новый конфиденциальный файл. Runtime не обновляется.".into(),
        ),
        IssueFlow::Exported(path) => (
            "Конфиденциальный файл создан",
            format!(
                "Файл содержит bearer. Не публикуйте его.\n\n{path:?}\n\nПуть показан в кавычках. Esc: закрыть. Runtime не обновлён."
            ),
        ),
        IssueFlow::ExportFailed => (
            "Защищённый экспорт не выполнен",
            "Секрет повторно не выдаётся. При необходимости отдельно выполните ротацию. Esc: закрыть."
                .into(),
        ),
        IssueFlow::Public(link) => (
            "Публичное приглашение без токена",
            format!(
                "Только данные профиля. Не содержит bearer, CA или grant. Получателю нужны независимое доверие (CA или REALITY fingerprint/admission) и отдельный credential.\nQ: защищённый QR | c: буфер обмена | Enter/Esc: закрыть.\n\n{link}"
            ),
        ),
        IssueFlow::Showing(link) => (
            "СЕКРЕТ: ссылка подключения (однократный просмотр)",
            format!(
                "КОНФИДЕНЦИАЛЬНО. Скопируйте ссылку целиком.\nТерминал/SSH и экран должны быть доверенными.\n\n{link}\n\nEsc: скрыть и стереть из памяти.\nRuntime не перезагружен.",
                link = link.as_str()
            ),
        ),
    };
    let body = if let IssueFlow::Input(id) = flow {
        if rotating || recovering {
            format!("{body}\n\n{}", user_choices(editor, id, recovering))
        } else {
            body
        }
    } else if matches!(flow, IssueFlow::Offer | IssueFlow::Public(_)) {
        format!("{body}\nQ: защищённый QR | c: буфер обмена (отдельное подтверждение)")
    } else {
        body
    };
    let items = invitation_actions(flow);
    if let Some([report, controls]) = action_layout(area, items.len()) {
        panel_at(frame, report, title, &body, false, viewport);
        Actions {items:&items, selected:action_focus}.render(frame, controls);
    } else {
        panel_at(frame, area, title, &body, true, viewport);
    }
}

fn draw_revocation(
    frame: &mut Frame<'_>,
    area: Rect,
    flow: &DisableFlow,
    editor: Option<&Editor>,
    viewport: Option<&Viewport>,
) {
    if let DisableFlow::Input(id) = flow {
        if let Some(form) = user_picker(editor, id, false) {
            draw_guided(frame, area, "Отключить существующего пользователя", "", (1, 2, "Выбор пользователя", "↑↓ выбрать · Enter проверить · Esc отменить"), viewport, (Some(form), None));
            return;
        }
    }
    let (title, body) = match flow {
        DisableFlow::Input(id) => (
            "Отключить существующего пользователя",
            format!(
                "ID пользователя с доступом к выбранному inbound: {id}\n\nEnter: проверить имя  Esc: отменить\n\n{}",
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        DisableFlow::Confirm(id) => (
            "Подтверждение отзыва доступа",
            format!(
                "Пользователь: {id}\nВыбранный inbound: {}\n\nВНИМАНИЕ: отключение глобальное для всех inbound этого пользователя.\nТокен и grants остаются в TOML, но новые запросы будут отклоняться после отдельного auth-only Apply. Текущие туннели не отзываются принудительно.\n\ny: подтвердить и сохранить  n/Esc: отменить",
                editor.map_or("", |e| e.selected_record_id())
            ),
        ),
        DisableFlow::Saving => (
            "Отзыв доступа: сохранение",
            "Проверка и атомарная запись TOML. Runtime не изменяется.".into(),
        ),
        DisableFlow::SaveFailed if editor.is_some_and(Editor::write_uncertain) => (
            "Отзыв доступа: состояние записи неизвестно",
            "TOML мог быть заменён. Runtime не обновлён. Откройте редактор заново; d: закрыть черновик."
                .into(),
        ),
        DisableFlow::SaveFailed => (
            "Отзыв доступа: ошибка сохранения",
            format!(
                "TOML НЕ сохранён. Runtime не изменён.\n\n{}\n\nr: повторить сохранение  d: отменить черновик",
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        DisableFlow::Done => (
            "Пользователь отключён в TOML",
            "Файл сохранён. Для отказа в новых подключениях требуется отдельно проверить revision и подтвердить auth-only Apply. Уже открытые туннели не разрываются.\n\nEnter/Esc: закрыть.".into(),
        ),
    };
    let body = if let DisableFlow::Input(id) = flow {
        format!("{body}\n\n{}", user_choices(editor, id, false))
    } else {
        body
    };
    panel_at(frame, area, title, &body, true, viewport);
}

fn draw_import(
    frame: &mut Frame<'_>,
    area: Rect,
    flow: &ImportFlow,
    editor: Option<&Editor>,
    viewport: Option<&Viewport>,
) {
    if let ImportFlow::Input(source) = flow {
        let form = Form {
            fields: vec![Field {
                id: 0, label: "Приглашение или локальный файл",
                value: if source.is_empty() { String::new() } else { format!("Введено {} байт (скрыто)", source.len()) },
                hint: "Вставьте ссылку theia:// или нажмите F6, чтобы выбрать файл приглашения или изображение PNG/SVG QR. Содержимое скрыто.",
            }],
            selected: 0,
            lead: "Получите личное приглашение у администратора. Вставьте ссылку или путь к присланному файлу. Подключение не запустится автоматически.".into(),
            error: editor.and_then(|e| e.error.clone()).unwrap_or_default(),
        };
        draw_guided(frame, area, "Импорт подключения", "", (1, 2, "Источник приглашения", "Enter проверить · F6 выбрать файл · Ctrl+U очистить · Esc отменить"), viewport, (Some(form), None));
        return;
    }
    let (title, body) = match flow {
        ImportFlow::Input(source) => (
            "F-14: импорт подключения",
            format!(
                "Введите или вставьте theia://v1/... (новый SmartTheia XHTTP) либо абсолютный путь локального URI-файла / защищённого PNG или SVG QR.\nИсточник и bearer НИКОГДА не показываются в TUI.\nВведено {} байт (скрыто).\n\nEnter: проверить  Esc: отменить\n\n{}",
                source.len(),
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        ImportFlow::Preview { invitation, ca, public_ref } => (
            "F-14: безопасный предпросмотр подключения",
            format!(
                "Профиль: {}\nEndpoint: {}\nTLS SNI: {}\nSecurity mode: {}\nTransport: {:?}\nXHTTP: {:?}\nBearer: {}\nCA trust: {}\nДоверенный CA проверяется отдельно от приглашения.\n\nЗапись добавит НОВЫЙ неактивный профиль. Не перезаписывает существующий ID.\n{}Никакого connect/Apply/Windows proxy.\n\nc: выбрать CA PEM file: путь\n{}y: явно подтвердить запись  n/Esc: отменить\n\n{}",
                invitation.id, invitation.endpoint, invitation.server_name,
                invitation.security_mode().canonical_name(), invitation.transport, invitation.xhttp_mode(),
                if invitation.has_token() { "будет сохранён в защищённый отдельный файл" } else { "нет в ссылке; нужна env: ссылка" },
                if ca.is_some() { "CA указан, ещё НЕ проверено соединение" } else { "НЕТ; профиль не готов к подключению" },
                if editor.is_some_and(|e| e.can_refresh_credential(invitation)) { "r: отдельная замена credential существующего профиля; выбранный CA не используется.\n" } else { "" },
                if invitation.has_token() { "".into() } else { format!("e: указать env:NAME ({})\n", if public_ref.is_some() { "задано" } else { "обязательно" }) },
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        ImportFlow::Trust { ca, .. } => (
            "F-14: отдельный TLS trust",
            format!(
                "Укажите ПРЕДВАРИТЕЛЬНО доверенный file:/абсолютный/ca.pem.\nПуть введён: {} символов.\nПустое значение оставляет профиль неготовым.\n\nEnter: проверить CA  Esc: назад\n\n{}",
                ca.len(), editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        ImportFlow::Credential { reference, .. } => (
            "F-14: отдельная учётная запись для публичного приглашения",
            format!(
                "Укажите заранее созданную env:NAME ссылку (НЕ значение bearer).\nВведено {} символов, скрыто.\n\nEnter: принять  Esc: назад\n\n{}",
                reference.len(), editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        ImportFlow::RefreshConfirm(invitation) => (
            "Подтверждение замены credential",
            format!(
                "Профиль: {}\nEndpoint: {}\nTLS SNI: {}\n\nТолько новая ссылка на защищённый bearer. CA, TLS, transport и active_profile сохраняются. Старый файл не удаляется. Runtime не меняется.\n\ny: сохранить  n/Esc: отменить",
                invitation.id, invitation.endpoint, invitation.server_name
            ),
        ),
        ImportFlow::RefreshSaving => (
            "Замена credential",
            "Создание нового защищённого файла и guarded TOML commit. Runtime не меняется.".into(),
        ),
        ImportFlow::RefreshDone => (
            "Credential сохранён",
            "Старый файл сохранён. Проверьте доступ отдельно; соединение и системный прокси не менялись. Enter/Esc: закрыть.".into(),
        ),
        ImportFlow::Saving => ("F-14: безопасное сохранение", "Создание нового приватного bearer и guarded TOML commit. Секрет не отображается.\nНикакого подключения или системного прокси.".into()),
        ImportFlow::Done => ("Импорт сохранён", "Новый профиль добавлен, исходный active_profile не изменён.\nTLS trust должен быть независимо проверен при подключении.\nНикаких сетевых соединений или OS proxy изменений.\n\nEnter/Esc: закрыть".into()),
        ImportFlow::Failed => (
            "Импорт НЕ подтверждён",
            format!(
                "Проверьте состояние TOML перед повторной попыткой. При отказе до commit новый секрет удалён.\nНикакого connect/OS proxy.\n\n{}\n\nEnter/Esc: закрыть",
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
    };
    panel_at(frame, area, title, &body, true, viewport);
}

fn draw_role_card(frame: &mut Frame<'_>, area: Rect, role: Role, selected: bool) {
    let (key, title, details) = match role {
        Role::Server => ("1", "Для сервера", "У меня есть сервер (VPS)\nХочу дать доступ другим устройствам\nНастройка, пользователи и запуск"),
        Role::Client => ("2", "Для клиента", "Хочу подключиться к готовому серверу\nУ меня есть приглашение администратора\nИмпорт, подключение и статистика"),
    };
    let area = Rect::new(area.x.saturating_add(1), area.y, area.width.saturating_sub(2), area.height);
    let bg = if selected { FOCUS } else { SURFACE };
    let lines = vec![
        Line::from(vec![
            Span::styled(format!(" {key} "), Style::default().bg(if selected { ACCENT } else { MUTED }).fg(BG).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  {title}"), Style::default().fg(if selected { ACCENT } else { TEXT }).add_modifier(Modifier::BOLD)),
        ]),
        Line::raw(""),
        Line::styled(details.lines().next().unwrap_or(""), Style::default().fg(TEXT)),
        Line::styled(details.lines().nth(1).unwrap_or(""), Style::default().fg(MUTED)),
        Line::styled(details.lines().nth(2).unwrap_or(""), Style::default().fg(MUTED)),
        Line::raw(""),
        Line::styled(if selected { "› Enter  Открыть" } else { "  Выбрать ↑↓ / Tab" }, Style::default().fg(if selected { ACCENT } else { MUTED })),
    ];
    frame.render_widget(Paragraph::new(lines).style(Style::default().bg(bg)).wrap(Wrap { trim: true }), area);
}

fn page_layout(area: Rect, role: Role, page: usize) -> Option<[Rect; 2]> {
    let count = page_actions(role, page).len();
    if area.height < 14 || count == 0 { return None; }
    if area.width >= 120 {
        let split = Layout::horizontal([Constraint::Min(50), Constraint::Length(43)]).split(area);
        Some([split[0], split[1]])
    } else if area.height >= 25 || page > 1 {
        let height = (count as u16 + 2).min(area.height / 2).max(4);
        let split = Layout::vertical([Constraint::Min(8), Constraint::Length(height)]).split(area);
        Some([split[0], split[1]])
    } else { None }
}
fn user_table_start(selected: usize, count: usize, area: Rect) -> usize {
    let capacity = usize::from(area.height.saturating_sub(3)).max(1);
    selected.min(count.saturating_sub(1)).saturating_sub(capacity-1).min(count.saturating_sub(capacity))
}
fn draw_page(frame: &mut Frame<'_>, area: Rect, role: Role, editor: &Editor, ui: Option<&Interaction>, compact: bool) {
    let page = ui.map_or(0, |u| u.workspace_page.min(6));
    let items = page_actions(role, page);
    let focus = ui.map_or(WorkspaceFocus::Fields, |u| u.workspace_focus);
    let selected = ui.map_or(0, |u| u.workspace_action);
    if compact && focus==WorkspaceFocus::Navigation {
        let rows=pages(role).iter().enumerate().map(|(i,label)|ListItem::new(format!("{} {label}",if i==page{"›"}else{" "})).style(Style::default().fg(if i==page{ACCENT}else{TEXT}).bg(if i==page{FOCUS}else{SURFACE})));
        frame.render_widget(List::new(rows.collect::<Vec<_>>()).block(tui_widgets::section("Разделы · ↑↓ Enter",true)),area);
        return;
    }
    let [content, controls] = page_layout(area, role, page).unwrap_or([area, Rect::default()]);
    if page == 0 {
        let local=if role==Role::Server {ui.map_or("Неизвестно",|u|u.server_process.status())}
            else if ui.is_some_and(|u|u.client_background.as_ref().is_some_and(StatusPanel::local_running)||u.reality_status.as_ref().is_some_and(StatusPanel::local_running)) {"Локальный процесс запущен или запускается"} else {"Локальный процесс не запущен"};
        let title=if role==Role::Server{"Обзор сервера"}else{"Обзор клиента"};
        let records=if role==Role::Server{"Подключения"}else{"Профили"};
        let users=editor.workspace_users();
        let status=if editor.write_uncertain(){"Запись не подтверждена"}else if editor.dirty(){"Есть несохранённые изменения"}else{"Файл сохранён"};
        let (next_key, help) = recommended_step(editor, ui.is_some_and(|u| u.owned_running(role)));
        let next_label = items.iter().find(|item| item.key == next_key).map_or("Открыть файл (F3)", |item| item.label);
        let lines=vec![Line::styled(format!("{records}: {}",editor.record_count()),Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Line::raw(if role==Role::Server{format!("Пользователи в файле: {}",users.len())}else{editor.selection_summary()}),
            Line::raw(format!("Конфигурация: {status}")),Line::raw(format!("Процесс: {local}")),
            Line::raw(""),Line::styled("Следующий шаг",Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),Line::raw(help),
            Line::styled(next_label,Style::default().fg(TEXT).add_modifier(Modifier::BOLD)),
            Line::raw("Tab — к действиям, Enter — открыть. Сохранение не запускает процесс.")];
        frame.render_widget(Paragraph::new(lines).block(tui_widgets::section(title,true)).wrap(Wrap{trim:true}),content);
    } else if page == 1 {
        draw_editor(frame, content, editor);
    } else if role == Role::Server && page == 2 {
        let users = editor.workspace_users();
        let selected = ui.map_or(0, |u| u.workspace_user).min(users.len().saturating_sub(1));
        let start = user_table_start(selected, users.len(), content);
        let rows = users.iter().enumerate().skip(start).take(usize::from(content.height.saturating_sub(3))).map(|(i,(id,disabled,granted))| {
            let color = if *disabled { WARNING } else { TEXT };
            Row::new(vec![format!("{} {id}", if i == selected { "›" } else { " " }), if *granted { "Выдан" } else { "Нет" }.into(), if *disabled { "Отключён" } else if *granted { "Разрешён" } else { "Нет доступа" }.into()])
                .style(Style::default().fg(color).bg(if i == selected { FOCUS } else { SURFACE }))
        });
        frame.render_widget(Table::new(rows,[Constraint::Percentage(50),Constraint::Percentage(20),Constraint::Percentage(30)])
            .header(Row::new(["Пользователь","Доступ","В файле"]).style(Style::default().fg(MUTED)))
            .block(tui_widgets::section("Пользователи выбранного подключения", focus == WorkspaceFocus::Users)),content);
        if users.is_empty() && content.height > 3 {
            frame.render_widget(Paragraph::new("Нет пользователей. Добавьте первого через действия."), Rect::new(content.x+1,content.y+2,content.width.saturating_sub(2),1));
        }
    } else {
        let description = match (role,page) {
            (Role::Server,3) => "Приглашения дают доступ к выбранному подключению. Приватная ссылка показывается только после подтверждённого сохранения.",
            (Role::Client,2) => "Импортируйте ссылку или изображение QR. Подключение и доверие подтверждаются отдельно.",
            (Role::Client,3) => "Управление системным прокси Windows. Это не VPN. На Linux эта функция недоступна.",
            (_,4) => "Enter или F4 — открыть живой монитор трафика текущего процесса.",
            (_,5) => "F3 — открыть файл; Ctrl+S — сохранить. Применение к работающему процессу выполняется отдельно.",
            _ => "Проверки состояния и диагностика. Сетевые операции требуют отдельного согласия.",
        };
        panel(frame, content, pages(role)[page], description, true);
    }
    if controls.height > 0 {
        Actions { items: &items, selected }.render(frame, controls);
        if focus != WorkspaceFocus::Actions {
            frame.render_widget(Paragraph::new(" Действия · F6 фокус ").style(Style::default().fg(MUTED).bg(SURFACE)), Rect::new(controls.x+1,controls.y,controls.width.saturating_sub(2),1));
        }
    } else if focus == WorkspaceFocus::Actions && !items.is_empty() {
        Actions { items: &items, selected }.render(frame, area);
    }
}
fn draw_workspace(frame: &mut Frame<'_>, area: Rect, role: Role, editor: Option<&Editor>, welcome_choice: usize, ui: Option<&Interaction>) {
    if editor.is_none() {
        draw_welcome(frame, area, role, welcome_choice);
        return;
    }
    let Some([nav, records, details]) = workspace_columns(area) else {
        if let Some(editor) = editor {
            draw_page(frame, area, role, editor, ui, true);
        } else {
            draw_welcome(frame, area, role, welcome_choice);
        }
        return;
    };
    let page = ui.map_or(0, |u| u.workspace_page);
    let categories = pages(role).iter().enumerate().map(|(i,label)| ListItem::new(format!("{} {label}", if i == page { "›" } else { " " })).style(if i == page { Style::default().fg(ACCENT).bg(FOCUS).add_modifier(Modifier::BOLD) } else { Style::default().fg(TEXT) }));
    frame.render_widget(
        List::new(categories.collect::<Vec<_>>()).block(
            tui_widgets::section(" Разделы · F6 ", ui.is_some_and(|u| u.workspace_focus == WorkspaceFocus::Navigation)),
        ),
        nav,
    );
    if let Some(editor) = editor {
        let start = record_start(editor, records);
        let visible = usize::from(records.height.saturating_sub(2));
        let items: Vec<_> = editor
            .workspace_records()
            .into_iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(index, (id, active, reality))| {
                let style = if index == editor.workspace_selected() {
                    Style::default()
                        .fg(ACCENT)
                        .bg(FOCUS)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(format!(
                    "{} {} {}{}",
                    if index == editor.workspace_selected() {
                        "›"
                    } else {
                        " "
                    },
                    if reality { "REALITY" } else { "TLS" },
                    tui_widgets::fit_value(&id, records.width.saturating_sub(13), false),
                    if active { " *" } else { "" }
                ))
                .style(style)
            })
            .collect();
        let title = if role == Role::Server {
            " Подключения · ↑↓ "
        } else {
            " Профили · ↑↓ "
        };
        frame.render_widget(
            List::new(items).block(
                tui_widgets::section(title, true),
            ),
            records,
        );
        if editor.record_count() == 0 {
            let inner = Rect::new(
                records.x + 1,
                records.y + 1,
                records.width.saturating_sub(2),
                records.height.saturating_sub(2),
            );
            frame.render_widget(
                Paragraph::new("Пока ничего нет. N — создать, F2 — все действия.")
                    .wrap(Wrap { trim: true }),
                inner,
            );
        }
        draw_page(frame, details, role, editor, ui, false);
    } else {
        panel(
            frame,
            records,
            " Записи ",
            "Конфигурация ещё не открыта.",
            false,
        );
        draw_welcome(frame, details, role, welcome_choice);
    }
}

fn welcome_form(role: Role, selected: usize) -> Form {
    let (reality, description, lead) = match role {
        Role::Server => ("Создать SmartTheia REALITY", "Для нового сервера без собственного TLS-сертификата", "Настраиваете сервер впервые? Выберите создание REALITY. Если Theia уже настроена, откройте существующий файл."),
        Role::Client => ("Импорт SmartTheia REALITY", "У меня есть приглашение от администратора", "Настраиваете клиент впервые? Получите приглашение у администратора. Если профили уже сохранены, откройте их файл."),
    };
    Form {
        fields: vec![
            Field { id: 0, label: "Открыть конфигурацию", value: "Выбрать существующий TOML".into(), hint: "Enter — выбрать путь. F3 — открыть файл." },
            Field { id: 1, label: reality, value: description.into(), hint: "Enter — выбрать новый путь, затем открыть мастер." },
            Field { id: 2, label: "Создать Own-TLS", value: "Расширенный вариант: свой сертификат".into(), hint: "Выбирайте только если администратор выдал необходимые TLS-данные." },
        ],
        selected,
        lead: lead.into(),
        error: String::new(),
    }
}

fn draw_welcome(frame: &mut Frame<'_>, area: Rect, role: Role, selected: usize) {
    let title = if role == Role::Server { "Для сервера · начало работы" } else { "Для клиента · начало работы" };
    tui_widgets::canvas(frame, area);
    welcome_form(role, selected).render_picker(frame, centered_column(area, 88), title);
}

fn centered_column(area: Rect, max_width: u16) -> Rect {
    let width = area.width.min(max_width);
    Rect::new(area.x + (area.width - width) / 2, area.y, width, area.height)
}

fn editor_layout(area: Rect) -> Option<[Rect; 4]> {
    if area.height < 10 || area.width < 38 { return None; }
    // Four records at most: do not stretch a short form into an empty grid.
    // On wide terminals, contextual guidance sits beside the parameters.
    if area.width >= 92 && area.height >= 18 {
        let parts = Layout::vertical([Constraint::Length(5), Constraint::Length(9), Constraint::Min(4)]).split(area);
        let middle = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).split(parts[1]);
        return Some([parts[0], middle[0], middle[1], parts[2]]);
    }
    if area.height >= 25 {
        let parts = Layout::vertical([Constraint::Length(5), Constraint::Length(9), Constraint::Length(5), Constraint::Min(6)]).split(area);
        return Some([parts[0], parts[1], parts[2], parts[3]]);
    }
    let parts = Layout::vertical([Constraint::Length(3), Constraint::Min(4), Constraint::Length(2), Constraint::Length(2)]).split(area);
    Some([parts[0], parts[1], parts[2], parts[3]])
}

fn editor_table_window(area: Rect, editor: &Editor) -> (usize, usize, bool) {
    let header = area.height >= 7;
    let count = editor.workspace_fields().len();
    let rows = usize::from(area.height.saturating_sub(if header { 3 } else { 2 }));
    let start = editor.workspace_field_index().saturating_sub(rows.saturating_sub(1)).min(count.saturating_sub(rows));
    (start, rows, header)
}

fn editor_field_hit(area: Rect, editor: &Editor, x: u16, y: u16) -> Option<usize> {
    let rect = editor_layout(area)?[1];
    let (start, rows, header) = editor_table_window(rect, editor);
    let y0 = rect.y + if header { 2 } else { 1 };
    if x <= rect.x || x >= rect.right().saturating_sub(1) || y < y0 || y >= rect.bottom().saturating_sub(1) {
        return None;
    }
    let offset = usize::from(y - y0);
    (offset < rows && start + offset < editor.workspace_fields().len()).then_some(start + offset)
}

fn draw_editor(frame: &mut Frame<'_>, area: Rect, editor: &Editor) {
    let dirty = if editor.write_uncertain() { "Не сохранено: запись не подтверждена" }
        else if editor.dirty() { "Не сохранено" } else { "Сохранено" };
    let state_color = if editor.write_uncertain() { ERROR } else if editor.dirty() { WARNING } else { ACCENT };
    let reality = editor.selected_reality();
    let mode = if reality { "SmartTheia REALITY" } else { "Own-TLS" };
    let server = editor.role() == Role::Server;
    let users = if server {
        let users = editor.workspace_users();
        let granted = users.iter().filter(|(_, _, grant)| *grant).count();
        let disabled = users.iter().filter(|(_, disabled, grant)| *disabled && *grant).count();
        format!("В файле: {} пользователей с доступом · {} отключены", granted.saturating_sub(disabled), disabled)
    } else { "Работа профиля проверяется отдельно от сохранения.".into() };
    let help = if editor.editing && !editor.choice_options().is_empty() {
        "←→ / Пробел выбрать · Enter проверить · Esc отменить"
    } else if editor.editing {
        "Ctrl+U очистить · Enter проверить · Esc отменить"
    } else if reality {
        "←→ параметры · Enter / F7 полное значение · раздел Подключения"
    } else { "←→ / Tab поле · Enter изменить" };
    let actions = if server {
        "W Мастер REALITY · N Новое подключение · F5 Сервер"
    } else { "i Импорт приглашения · N Новый профиль · V Подключение" };
    let secondary = if server {
        "u Добавить пользователя · F2 Все действия · Ctrl+S Сохранить"
    } else { "F2 Все действия · F4 Трафик · Ctrl+S Сохранить" };
    let next = if editor.record_count() == 0 {
        if server { "Создайте первое подключение (W или N)." } else { "Импортируйте приглашение (i) или создайте профиль (N)." }
    } else if editor.write_uncertain() { "Откройте конфигурацию заново, прежде чем продолжать." }
    else if editor.dirty() { "Сохраните изменения (Ctrl+S). Это не изменяет работающий процесс." }
    else if server { "F5 — запустить или проверить сервер. u — выдать доступ пользователю." }
    else { "V — открыть подключение и проверить его состояние." };
    let title = if editor.editing { "Изменение параметра" }
        else if reality { "Защищённое подключение · только просмотр" } else { "Параметры · Enter изменить" };
    let fields = editor.workspace_fields();
    let selected = fields.iter().find(|(_, _, selected)| *selected);
    let friendly = match (server, editor.workspace_field_index()) {
        (true, 0) => "Домен, используемый при проверке TLS.",
        (true, 1) => "На каком адресе и порту сервер принимает TCP (HTTP/2).",
        (true, _) => "На каком адресе и порту сервер принимает UDP (HTTP/3).",
        (false, 0) => "Адрес и порт удалённого сервера.",
        (false, 1) => "Имя сервера, используемое при проверке TLS.",
        (false, 2) => "Автоматический выбор HTTP/2 или HTTP/3 либо ручной режим.",
        (false, _) => "Режим передачи данных XHTTP. Обычно оставляют auto.",
    };
    let Some([overview, table_area, detail, bottom]) = editor_layout(area) else {
        let message = format!("{dirty} · {mode}\n{}\n{}\n{}\n{}\n{}\n{}", editor.selection_summary(),
            editor.fields_overview(), editor.error.as_deref().unwrap_or(""), editor.notice, next, actions);
        panel(frame, area, title, &message, true);
        return;
    };
    let heading = if reality { "SmartTheia REALITY · только просмотр" } else if server { "Подключение сервера" } else { "Профиль клиента" };
    let status = vec![
        Line::from(vec![Span::styled(format!(" {dirty} "), Style::default().fg(BG).bg(state_color).add_modifier(Modifier::BOLD)), Span::raw(format!("  {mode}"))]),
        Line::raw(editor.selection_summary()),
        Line::styled(users, Style::default().fg(MUTED)),
    ];
    if overview.height >= 5 {
        frame.render_widget(Paragraph::new(status).block(tui_widgets::section(heading, false)), overview);
    } else {
        frame.render_widget(Paragraph::new(status).style(Style::default().bg(SURFACE)), overview);
    }

    let (start, rows, header) = editor_table_window(table_area, editor);
    let labels = if server { ["Домен TLS", "Адрес TCP (H2)", "Адрес UDP (H3)", ""] }
        else { ["Адрес (Endpoint)", "Домен (TLS SNI)", "Транспорт", "Режим XHTTP"] };
    let label_width = (table_area.width / 2).clamp(12, 24);
    let value_width = table_area.width.saturating_sub(label_width + 5);
    let table_rows = fields.iter().enumerate().skip(start).take(rows).map(|(index, (_, value, selected))| {
        let marker = if *selected { "› " } else { "  " };
        let style = if *selected { Style::default().fg(ACCENT).bg(FOCUS).add_modifier(Modifier::BOLD) }
            else { Style::default().fg(TEXT) };
        let shown = tui_widgets::fit_value(value, value_width.saturating_sub(2), *selected && editor.editing);
        Row::new(vec![
            ratatui::widgets::Cell::from(format!("{marker}{}", labels[index])),
            ratatui::widgets::Cell::from(format!(" {shown}{}", if *selected && editor.editing { " ▏" } else { "" }))
                .style(Style::default().bg(if reality { SURFACE } else if *selected { FOCUS } else { INPUT })),
        ]).style(style)
    });
    let mut table = Table::new(table_rows, [Constraint::Length(label_width), Constraint::Min(1)])
        .column_spacing(1).block(tui_widgets::section(title, true));
    if header { table = table.header(Row::new(["Настройка", "Значение"]).style(Style::default().fg(MUTED))); }
    frame.render_widget(table, table_area);
    if fields.is_empty() && table_area.height >= 3 {
        frame.render_widget(Paragraph::new("Нет записей.").style(Style::default().fg(MUTED)),
            Rect::new(table_area.x + 1, table_area.y + 1, table_area.width.saturating_sub(2), 1));
    }
    let choices = if editor.editing && !editor.choice_options().is_empty() {
        editor.choice_options().iter().map(|value| if *value == editor.input.as_str() { format!("[● {value}]") } else { format!("[○ {value}]") }).collect::<Vec<_>>().join("  ")
    } else { String::new() };
    let context = if reality { "Параметры закреплены при регистрации. Изменения доверия выполняются отдельно." }
        else { friendly };
    let error = editor.error.as_deref();
    if detail.height >= 5 {
        let detail_lines = vec![
            Line::styled(selected.map_or("Параметр", |(label, _, _)| *label), Style::default().fg(TEXT).add_modifier(Modifier::BOLD)),
            Line::styled(context, Style::default().fg(MUTED)),
            Line::styled(choices, Style::default().fg(ACCENT)),
            Line::styled(help, Style::default().fg(TEXT)),
        ];
        frame.render_widget(Paragraph::new(detail_lines).block(tui_widgets::section("Что это значит", false)).wrap(Wrap { trim: true }), detail);
    } else {
        frame.render_widget(Paragraph::new(error.unwrap_or(help)).style(Style::default().fg(if error.is_some() { ERROR } else { TEXT })).wrap(Wrap { trim: true }), detail);
    }
    let mut lines = Vec::new();
    if let Some(error) = error {
        lines.push(Line::styled(format!("Ошибка: {error}"), Style::default().fg(ERROR).add_modifier(Modifier::BOLD)));
    }
    if !editor.notice.is_empty() {
        lines.push(Line::styled(editor.notice, Style::default().fg(MUTED)));
    }
    lines.push(Line::styled(next, Style::default().fg(TEXT).add_modifier(Modifier::BOLD)));
    lines.push(tui_widgets::key_line(actions));
    lines.push(tui_widgets::key_line(secondary));
    if bottom.height >= 5 {
        let height = bottom.height.min(10);
        frame.render_widget(Paragraph::new(lines).block(tui_widgets::section("Что дальше", false)).wrap(Wrap { trim: true }),
            Rect::new(bottom.x, bottom.y, bottom.width, height));
    } else {
        frame.render_widget(Paragraph::new(vec![tui_widgets::key_line(actions), tui_widgets::key_line(secondary)]).wrap(Wrap { trim: true }), bottom);
    }
}

/// Edit only when both role and a config path are explicitly supplied.
/// Saving never changes a service. A separate, explicitly confirmed Linux\n/// IPC transaction is available only for saved server authorization deltas.
pub fn run(role: Option<Role>, config_path: Option<&Path>) -> Result<(), TuiError> {
    crate::diag!(
        Info,
        "tui",
        "start",
        "server_role" = crate::diagnostics::Value::Flag(matches!(role, Some(Role::Server))),
        "editor_requested" = crate::diagnostics::Value::Flag(config_path.is_some())
    );
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        crate::diag!(Warn, "tui", "not_interactive");
        return Err(TuiError::NotInteractive);
    }
    let editor = match (role, config_path) {
        (Some(role), Some(path)) => {
            Some(Editor::load(role, path).map_err(TuiError::Configuration)?)
        }
        (None, Some(_)) => {
            return Err(TuiError::Configuration("TUI config requires explicit role"))
        }
        _ => None,
    };
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut model = Model::new(role);
    let mut interaction = Interaction::new(editor);
    if interaction.editor.is_none() {
        interaction.welcome_choice = ConfigDialog::suggested_mode(model.selected);
    }
    loop {
        interaction.poll_navigation(&mut model);
        if interaction.poll_save(&mut model)? {
            crate::diag!(Info, "tui", "saved_and_closed");
            return Ok(());
        }
        if let Some(runtime) = interaction.runtime.as_mut() {
            runtime.poll();
            if let Some(observation)=runtime.apply_observation() {
                interaction.last_apply=Some(observation);
            } else if runtime.invalidates_apply_observation() {
                interaction.last_apply=None;
            }
        }
        #[cfg(windows)]
        if let Some(proxy) = interaction.system_proxy.as_mut() {
            proxy.poll();
        }
        if let Some(discovery) = interaction.discovery.as_mut() {
            discovery.poll();
        }
        if let Some(probe) = interaction.probe.as_mut() {
            probe.poll();
        }
        if let Some(batch) = interaction.candidate_batch.as_mut() {
            batch.poll();
        }
        if let Some(provision) = interaction.reality_provision.as_mut() {
            if let Some(editor) = provision.poll() {
                interaction.editor = Some(editor);
            }
        }
        if let Some(enrollment) = interaction.reality_enrollment.as_mut() {
            if let Some(editor) = enrollment.poll() {
                interaction.editor = Some(editor);
            }
        }
        if let Some(status) = interaction.reality_status.as_mut() {
            status.poll();
            if let Some(editor) = status.take_refreshed_editor() {
                interaction.editor = Some(editor);
            }
        }
        if let Some(registration) = interaction.reality_registration.as_mut() {
            if let Some(editor) = registration.poll() {
                interaction.editor = Some(editor);
            }
        }
        if let Some(domain) = interaction.domain.as_mut() {
            domain.poll();
        }
        if let Some(link) = interaction.clipboard.take() {
            let message = if crate::tui_share::send_clipboard(io::stdout().lock(), &link).is_ok() {
                "Запрос копирования отправлен терминалу; фактическое содержимое буфера не подтверждено. Проверьте вставкой в доверенное приложение."
            } else {
                "Запрос копирования не подтверждён. Для конфиденциальной ссылки потребуется новая выдача."
            };
            interaction.issuance = Some(IssueFlow::ShareDone(message.into()));
        }
        terminal.draw(|frame| draw(frame, &model, Some(&interaction)))?;
        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) => {
                    if interaction.update(&mut model, key) {
                        crate::diag!(Info, "tui", "closed_by_user");
                        return Ok(());
                    }
                }
                Event::Mouse(mouse) => {
                    let size = terminal.size()?;
                    interaction.mouse(&mut model, mouse, Rect::new(0, 0, size.width, size.height));
                }
                Event::Paste(text) => {
                    interaction.paste_record_field(&text);
                    interaction.paste_import_source(&text);
                    if let Some(editor) = interaction.editor.as_mut().filter(|e| e.editing) {
                        if !text.chars().any(char::is_control) {
                            for ch in text.chars() {
                                editor.insert(ch);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn render(width: u16, height: u16, model: Model) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw(f, &model, None)).unwrap();
        let buffer = terminal.backend().buffer();
        buffer
            .content()
            .chunks(usize::from(width))
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn m4_2c_server_status_and_apply_are_explicit_and_dirty_draft_cannot_commit() {
        use std::fs;
        let path = std::env::temp_dir().join(format!(
            "theia-tui-m42c-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        fs::write(&path, source).unwrap();
        let editor = Editor::load(Role::Server, &path).unwrap();
        let mut ui = Interaction::new(Some(editor));
        let mut model = Model::new(Some(Role::Server));

        assert!(!ui.update(&mut model, press(KeyCode::Char('v'))));
        assert!(ui.runtime.is_some(), "v enters read-only IPC status panel");
        assert!(!ui.update(&mut model, press(KeyCode::Esc)));
        assert!(ui.runtime.is_none());
        let ctrl_r = KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL);
        assert!(!ui.update(&mut model, ctrl_r));
        assert!(ui.runtime.is_some(), "Ctrl+R never directly commits");
        assert!(!ui.update(&mut model, press(KeyCode::Esc)));
        assert!(ui.runtime.is_none());

        let edit = ui.editor.as_mut().unwrap();
        edit.begin();
        edit.input = "edited.example.org".into();
        assert!(edit.accept());
        assert!(edit.dirty());
        assert!(!ui.update(&mut model, ctrl_r));
        assert!(ui.runtime.is_none(), "unsaved edits must block Apply");
        assert!(ui
            .editor
            .as_ref()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("Ctrl+S"));

        // A client panel never gets a server Apply hotkey.
        let client_path =
            std::env::temp_dir().join(format!("theia-tui-m42c-client-{}.toml", std::process::id()));
        fs::write(&client_path, include_str!("../../../examples/client.toml")).unwrap();
        let mut client = Interaction::new(Some(Editor::load(Role::Client, &client_path).unwrap()));
        let mut client_model = Model::new(Some(Role::Client));
        assert!(!client.update(&mut client_model, ctrl_r));
        assert!(client.runtime.is_none());
        fs::remove_file(path).unwrap();
        fs::remove_file(client_path).unwrap();
    }

    #[test]
    fn client_proxy_shortcut_refuses_dirty_or_unconfigured_editor() {
        let path =
            std::env::temp_dir().join(format!("theia-tui-proxy-{}.toml", std::process::id()));
        std::fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
        let editor = Editor::load(Role::Client, &path).unwrap();
        let mut ui = Interaction::new(Some(editor));
        let mut model = Model::new(Some(Role::Client));
        ui.update(&mut model, press(KeyCode::Enter));
        let editor = ui.editor.as_mut().unwrap();
        editor.input = "other.example.org:443".into();
        assert!(editor.accept());
        assert!(editor.dirty());
        ui.update(&mut model, press(KeyCode::Char('p')));
        assert!(ui.editor.as_ref().unwrap().error.is_some());
        #[cfg(windows)]
        assert!(ui.system_proxy.is_none());
        #[cfg(not(windows))]
        {
            ui.editor.as_mut().unwrap().discard();
            ui.update(&mut model, press(KeyCode::Char('p')));
            assert_eq!(
                ui.editor.as_ref().unwrap().error.as_deref(),
                Some("Системный прокси: только Windows.")
            );
        }
        std::fs::remove_file(path).unwrap();
        let mut ui = Interaction::new(None);
        assert!(!ui.update(&mut model, press(KeyCode::Char('p'))));
        #[cfg(windows)]
        assert!(ui.system_proxy.is_none());
    }

    #[test]
    fn model_navigation_help_and_safe_exit() {
        let mut app = Model::new(None);
        assert_eq!(app.screen, Screen::Home);
        assert!(!app.update(press(KeyCode::Tab)));
        assert_eq!(app.selected, Role::Client);
        assert!(!app.update(press(KeyCode::Enter)));
        assert_eq!(app.screen, Screen::Client);
        assert!(!app.update(press(KeyCode::Char('?'))));
        assert_eq!(app.screen, Screen::Help);
        assert!(!app.update(press(KeyCode::Esc)));
        assert_eq!(app.screen, Screen::Client);
        assert!(!app.update(press(KeyCode::Char('1'))));
        assert_eq!(app.screen, Screen::Server);
        assert!(!app.update(press(KeyCode::Esc)));
        assert_eq!(app.screen, Screen::Home);
        assert!(app.update(press(KeyCode::Char('q'))));
    }

    #[test]
    fn review_viewport_can_reach_last_line_and_resets_for_new_screen() {
        let viewport = Viewport::default();
        assert_eq!(viewport.position("review", 40, 10, None), 0);
        viewport.move_by(500);
        assert_eq!(viewport.position("review", 40, 10, None), 30);
        assert_eq!(viewport.position("new review", 40, 10, None), 0);
        assert_eq!(viewport.position("typed", 40, 10, Some(2)), 0);
        assert_eq!(viewport.position("typed", 40, 10, Some(18)), 9);
        viewport.move_by(-3);
        assert_eq!(viewport.position("typed", 40, 10, Some(18)), 6);
        let (rows, _) = visual_rows("one two three four", 5);
        assert!(rows.len() >= 4);
        assert!(rows.iter().all(|row| row.width() <= 5));
    }

    #[test]
    fn onboarding_recommendation_and_invitation_actions_are_read_only() {
        let path=std::env::temp_dir().join(crate::tui_editor::generated_id("onboarding").unwrap());
        std::fs::write(&path,include_str!("../../../examples/client.toml")).unwrap();
        let editor=Editor::load(Role::Client,&path).unwrap();
        assert_eq!(recommended_step(&editor,false).0,'V');
        let actions=invitation_actions(&IssueFlow::Offer);
        assert_eq!(actions[0].key,'f');
        assert!(actions.iter().all(|a| a.key!='y'));
        let before=std::fs::read(&path).unwrap();
        let mut ui=Interaction::new(Some(editor));
        ui.select_workspace_page(Role::Client,0);
        assert_eq!(ui.workspace_focus,WorkspaceFocus::Navigation);
        assert_eq!(std::fs::read(&path).unwrap(),before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn workspace_navigation_and_actions_do_not_write_on_focus() {
        let path=std::env::temp_dir().join(crate::tui_editor::generated_id("workspace-nav").unwrap());
        let original=server_issuance_fixture();
        std::fs::write(&path,&original).unwrap();
        let mut ui=Interaction::new(Some(Editor::load(Role::Server,&path).unwrap()));
        let mut model=Model::new(Some(Role::Server));
        ui.update(&mut model,press(KeyCode::F(6)));
        assert_eq!(ui.workspace_focus,WorkspaceFocus::Actions);
        ui.update(&mut model,press(KeyCode::F(6)));
        ui.update(&mut model,press(KeyCode::Down));
        assert_eq!(ui.workspace_page,2);
        assert!(ui.menu.is_none());
        ui.update(&mut model,press(KeyCode::Enter));
        assert_eq!(ui.workspace_focus,WorkspaceFocus::Users);
        assert!(!ui.server_process.running());
        assert_eq!(std::fs::read_to_string(&path).unwrap(),original);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn compact_workspace_always_shows_error_and_full_message_can_open() {
        let path=std::env::temp_dir().join(crate::tui_editor::generated_id("workspace-error").unwrap());
        std::fs::write(&path,include_str!("../../../examples/client.toml")).unwrap();
        let mut editor=Editor::load(Role::Client,&path).unwrap();
        editor.error=Some("Проверьте адрес сервера".into());
        let mut ui=Interaction::new(Some(editor));
        let mut model=Model::new(Some(Role::Client));
        assert!(rendered_interaction(60,18,&model,&ui).contains("Ошибка: Проверьте адрес сервера"));
        ui.update(&mut model,press(KeyCode::F(7)));
        assert!(ui.value_preview);
        assert!(rendered_interaction(60,18,&model,&ui).contains("Проверьте адрес сервера"));
        ui.update(&mut model,press(KeyCode::Esc));
        assert!(!ui.value_preview);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn mode_picker_focus_is_a_choice_not_a_commit() {
        let mut flow = RecordFlow::ChooseMode(Role::Server, 1);
        let initial = flow.form(None).unwrap();
        assert_eq!(initial.selected, 1);
        assert_eq!(initial.fields.len(), 2);
        flow.select_field(0);
        assert_eq!(flow.form(None).unwrap().selected, 0);
        flow.select_field(99);
        assert_eq!(flow.form(None).unwrap().selected, 0);
    }

    #[test]
    fn workspace_geometry_keeps_short_forms_compact_and_uses_wide_terminal() {
        let area = Rect::new(0, 0, 240, 70);
        let [_, _, workspace] = workspace_columns(area).unwrap();
        let [overview, fields, context, actions] = editor_layout(workspace).unwrap();
        assert_eq!(overview.width, workspace.width);
        assert_eq!(fields.height, 9);
        assert_eq!(fields.right(), context.x);
        assert_eq!(fields.width + context.width, workspace.width);
        assert_eq!(actions.y, fields.bottom());
        assert!(actions.bottom() <= workspace.bottom());
        for (width, height) in [(60, 20), (80, 24), (120, 40)] {
            let area = Rect::new(0, 0, width, height);
            for rect in editor_layout(area).unwrap() {
                assert!(rect.right() <= area.right() && rect.bottom() <= area.bottom());
            }
        }
    }

    #[test]
    fn workspace_mouse_selects_role_without_entering_or_starting() {
        let mut model = Model::new(None);
        let mut ui = Interaction::new(None);
        ui.mouse(
            &mut model,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 90,
                row: 5,
                modifiers: KeyModifiers::NONE,
            },
            Rect::new(0, 0, 120, 40),
        );
        assert_eq!(model.screen, Screen::Home);
        assert_eq!(model.selected, Role::Client);
        assert!(!ui.server_process.running());
        assert!(ui.config_dialog.is_none());
    }

    #[test]
    fn wizard_review_uses_same_width_and_keeps_actions_near_content() {
        for (w, h) in [(80, 24), (132, 65), (240, 90)] {
            let area = Rect::new(0, 0, w, h);
            let [header, body, footer] = guided_layout(area, None, 12);
            assert_eq!(header.x, body.x);
            assert_eq!(body.x, footer.x);
            assert_eq!(header.width, footer.width);
            assert!(footer.bottom() <= area.bottom());
            assert!(footer.bottom() <= area.y + 24);
            let mut terminal = Terminal::new(TestBackend::new(w,h)).unwrap();
            let viewport = Viewport::default();
            terminal.draw(|frame| draw_guided(frame, area, "Мастер REALITY", "Короткий результат",
                (4, 5, "Результат подбора", "Y создать · N / Esc назад"), Some(&viewport), (None, None))).unwrap();
            let screen = terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect::<String>();
            assert!(screen.contains("Короткий результат"));
            assert!(screen.contains("Следующее действие"));
        }
    }

    #[test]
    fn transport_choice_changes_only_draft_after_enter_and_cancel_restores_value() {
        let path = std::env::temp_dir().join(crate::tui_editor::generated_id("transport-choice").unwrap());
        let original = include_str!("../../../examples/client.toml");
        std::fs::write(&path, original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        ui.editor.as_mut().unwrap().workspace_select_field(2);
        ui.update(&mut model, press(KeyCode::Enter));
        let before = ui.editor.as_ref().unwrap().field_value();
        ui.update(&mut model, press(KeyCode::Right));
        assert_ne!(ui.editor.as_ref().unwrap().input, before);
        assert!(!ui.editor.as_ref().unwrap().dirty());
        ui.update(&mut model, press(KeyCode::Esc));
        assert_eq!(ui.editor.as_ref().unwrap().field_value(), before);
        ui.update(&mut model, press(KeyCode::Enter));
        ui.update(&mut model, press(KeyCode::Right));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.editor.as_ref().unwrap().dirty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn welcome_and_parameter_mouse_hits_change_focus_without_writes() {
        let root = std::env::temp_dir().join(crate::tui_editor::generated_id("mouse-focus").unwrap());
        std::fs::create_dir(&root).unwrap();
        let area = Rect::new(0, 0, 120, 40);
        let body = shell_layout(area)[1];
        let mut model = Model::new(Some(Role::Client));
        let mut ui = Interaction::new(None);
        let click = |column, row| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column, row, modifiers: KeyModifiers::NONE,
        };
        let target = centered_column(body, 88);
        let form = welcome_form(Role::Client, 0);
        let y = (target.y..target.bottom()).find(|&y| form.hit(target, target.x + 2, y) == Some(1)).unwrap();
        ui.mouse(&mut model, click(target.x + 2, y), area);
        assert_eq!(ui.welcome_choice, 1);
        assert!(ui.config_dialog.is_none());
        ui.update(&mut model, press(KeyCode::Enter));
        let path = root.join("first.toml");
        let dialog = ui.config_dialog.as_mut().unwrap();
        dialog.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        dialog.paste(path.to_str().unwrap());
        assert_eq!(dialog.form().unwrap().selected, 1);
        ui.update(&mut model, press(KeyCode::Enter));
        let dialog = ui.config_dialog.as_ref().unwrap();
        let _ = dialog;
        ui.update(&mut model,press(KeyCode::F(8)));
        let form = ui.config_dialog.as_ref().unwrap().form().unwrap();
        let target = guided_form_area(body, form.fields.len());
        let y = (target.y..target.bottom()).find(|&y| form.hit(target, target.x + 2, y) == Some(4)).unwrap();
        ui.mouse(&mut model, click(target.x + 2, y), area);
        assert_eq!(ui.config_dialog.as_ref().unwrap().form().unwrap().selected, 4);
        assert!(!path.exists());
        assert!(!ui.server_process.running());

        let path = root.join("existing.toml");
        let original = include_str!("../../../examples/client.toml");
        std::fs::write(&path, original).unwrap();
        ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let details = workspace_columns(body).unwrap()[2];
        let details=page_layout(details,Role::Client,1).map(|p|p[0]).unwrap_or(details);
        let table = editor_layout(details).unwrap()[1];
        let y = (table.y..table.bottom()).find(|&y| editor_field_hit(details, ui.editor.as_ref().unwrap(), table.x + 2, y) == Some(1)).unwrap();
        ui.mouse(&mut model, click(table.x + 2, y), area);
        let editor = ui.editor.as_ref().unwrap();
        assert_eq!(editor.workspace_field_index(), 1);
        assert!(!editor.editing && !editor.dirty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_run_modes_are_visible_and_reality_wizard_has_progress() {
        let root = std::env::temp_dir().join(crate::tui_editor::generated_id("first-run-ui").unwrap());
        std::fs::create_dir(&root).unwrap();
        for role in [Role::Server, Role::Client] {
            let path = root.join(if role == Role::Server { "server.toml" } else { "client.toml" });
            let mut ui = Interaction::new(None);
            let mut model = Model::new(Some(role));
            ui.update(&mut model, press(KeyCode::Enter));
            let dialog = ui.config_dialog.as_mut().unwrap();
            dialog.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
            dialog.paste(path.to_str().unwrap());
            let snapshot = rendered_interaction(120, 40, &model, &ui);
            assert!(snapshot.contains("REALITY"));
            assert!(snapshot.contains("Own-TLS"));
            ui.update(&mut model, press(KeyCode::Down));
            ui.update(&mut model, press(KeyCode::Enter));
            let snapshot = rendered_interaction(120, 40, &model, &ui);
            assert!(snapshot.contains("ШАГ 1/"));
            assert!(snapshot.contains("Следующее действие"));
            if role == Role::Server {
                assert!(snapshot.contains("443"));
                assert!(snapshot.contains("ID первого пользователя"));
            } else {
                assert!(snapshot.contains("Файл допуска"));
                ui.update(&mut model,press(KeyCode::F(8)));
                assert!(rendered_interaction(120,40,&model,&ui).contains("Fingerprint"));
            }
            ui.update(&mut model, press(KeyCode::Esc));
            assert!(!path.exists());
            assert!(ui.config_dialog.is_some());
            ui.update(&mut model, press(KeyCode::Esc));
            assert!(ui.config_dialog.is_none());
            assert!(!ui.server_process.running());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn workspace_action_browser_is_discoverable_and_escape_returns() {
        let mut model = Model::new(Some(Role::Server));
        let mut ui = Interaction::new(None);
        ui.update(&mut model, press(KeyCode::F(2)));
        assert!(ui.menu.is_some());
        let snapshot = rendered_interaction(120, 40, &model, &ui);
        assert!(snapshot.contains("Разделы"));
        assert!(snapshot.contains("Запуск / остановка"));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.menu.is_none());
        assert!(!ui.server_process.running());
    }

    #[test]
    fn explicit_role_selects_panel_without_starting_a_runtime() {
        let server = Model::new(Some(Role::Server));
        let client = Model::new(Some(Role::Client));
        assert_eq!(server.screen, Screen::Server);
        assert_eq!(client.screen, Screen::Client);
        assert!(render(80, 24, client).contains("не проверялся"));
        assert!(render(80, 24, server).contains("IPC"));
    }

    #[test]
    fn screen_renders_on_60_80_120_and_tiny_terminals() {
        let model = Model::new(None);
        for (w, h) in [(60, 18), (80, 24), (120, 40)] {
            let snapshot = render(w, h, model);
            assert!(snapshot.contains("Для сервера"), "{w}x{h}");
            assert!(snapshot.contains("Для клиента"), "{w}x{h}");
            assert!(snapshot.contains("THEIA"), "{w}x{h}");
            assert!(!snapshot.contains("Подключено"));
            assert!(!snapshot.contains("TOKEN"));
        }
        assert!(render(20, 6, model).contains("Терминал"));
    }

    #[test]
    fn dirty_draft_guards_quit_and_navigation_while_editing_is_isolated() {
        use crate::config;
        use sha2::{Digest, Sha256};
        use std::fs;
        let path = std::env::temp_dir().join(format!("theia-tui-ui-{}.toml", std::process::id()));
        let source = include_str!("../../../examples/server.toml").replace(
            "REPLACE_WITH_64_LOWERCASE_HEX",
            &format!("{:x}", Sha256::digest([0x42; 32])),
        );
        fs::write(&path, &source).unwrap();
        let editor = Editor::load(Role::Server, &path).unwrap();
        let mut interaction = Interaction::new(Some(editor));
        let mut model = Model::new(Some(Role::Server));
        assert!(!interaction.update(&mut model, press(KeyCode::Enter)));
        assert!(interaction.editor.as_ref().unwrap().editing);
        assert!(!interaction.update(&mut model, press(KeyCode::Char('q'))));
        assert!(interaction.editor.as_ref().unwrap().input.ends_with('q'));
        assert_eq!(model.screen, Screen::Server);
        assert!(!interaction.update(&mut model, press(KeyCode::Esc)));
        assert!(!interaction.editor.as_ref().unwrap().editing);
        assert!(!interaction.update(&mut model, press(KeyCode::Enter)));
        interaction.editor.as_mut().unwrap().input = "new.example.org".into();
        assert!(!interaction.update(&mut model, press(KeyCode::Enter)));
        assert!(interaction.editor.as_ref().unwrap().dirty());
        assert!(!interaction.update(&mut model, press(KeyCode::Char('q'))));
        assert!(interaction.pending.is_some());
        assert_eq!(model.screen, Screen::Server);
        assert!(!interaction.update(&mut model, press(KeyCode::Esc)));
        assert!(interaction.pending.is_none());
        assert!(!interaction.update(&mut model, press(KeyCode::Char('q'))));
        assert!(interaction.update(&mut model, press(KeyCode::Char('d'))));
        assert!(!interaction.editor.as_ref().unwrap().dirty());
        assert_eq!(fs::read(&path).unwrap(), source.as_bytes());
        assert_eq!(config::read_file(&path).unwrap().validate(), Ok(()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn ctrl_s_saves_in_worker_then_navigation_continues() {
        use crate::config::{self, Config};
        use std::{fs, thread, time::Instant};
        let path =
            std::env::temp_dir().join(format!("theia-tui-save-ui-{}.toml", std::process::id()));
        fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
        let mut interaction = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        assert!(!interaction.update(&mut model, press(KeyCode::Enter)));
        interaction.editor.as_mut().unwrap().input = "changed.example.org:443".into();
        assert!(!interaction.update(&mut model, press(KeyCode::Enter)));
        assert!(interaction.editor.as_ref().unwrap().dirty());
        assert!(!interaction.update(&mut model, press(KeyCode::Char('q'))));
        assert!(interaction.pending.is_some());
        assert!(!interaction.update(&mut model, press(KeyCode::Char('s'))));
        assert!(interaction.saving.is_some());
        let start = Instant::now();
        let finished = loop {
            if interaction.poll_save(&mut model).unwrap() {
                break true;
            }
            if interaction.saving.is_none() || start.elapsed() > Duration::from_secs(5) {
                break false;
            }
            thread::sleep(Duration::from_millis(5));
        };
        assert!(
            finished,
            "save must complete queued quit after confirmed write"
        );
        assert!(interaction.editor.as_ref().unwrap().error.is_none());
        let Config::Client(doc) = config::read_file(&path).unwrap() else {
            panic!("client expected");
        };
        assert_eq!(doc.client.profiles[0].server, "changed.example.org:443");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rendered_editor_shows_only_nonsecret_field_and_dirty_status() {
        use std::fs;
        let path =
            std::env::temp_dir().join(format!("theia-tui-client-ui-{}.toml", std::process::id()));
        fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
        let mut editor = Editor::load(Role::Client, &path).unwrap();
        editor.begin();
        editor.input = "changed.example.org:443".into();
        assert!(editor.accept());
        let interaction = Interaction::new(Some(editor));
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        let model = Model::new(Some(Role::Client));
        terminal
            .draw(|f| draw(f, &model, Some(&interaction)))
            .unwrap();
        let picture = terminal
            .backend()
            .buffer()
            .content()
            .chunks(120)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(picture.contains("Не сохранено"));
        assert!(picture.contains("Адрес (Endpoint)"));
        assert!(!picture.contains("THEIA_AUTH_TOKEN"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn form_keyboard_selects_record_and_field_without_implicit_activation() {
        use crate::config::{self, Config};
        use std::fs;

        let path = std::env::temp_dir().join(format!("theia-tui-m41c-{}.toml", std::process::id()));
        let Config::Client(mut doc) =
            config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client");
        };
        let mut second = doc.client.profiles[0].clone();
        second.id = "backup".into();
        second.server = "backup.example.org:443".into();
        doc.client.profiles.push(second);
        fs::write(&path, Config::Client(doc).to_toml().unwrap()).unwrap();

        let mut interaction = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        assert!(!interaction.update(&mut model, press(KeyCode::Down)));
        assert_eq!(
            interaction.editor.as_ref().unwrap().selected_record_id(),
            "backup"
        );
        assert!(!interaction
            .editor
            .as_ref()
            .unwrap()
            .selected_record_is_active());
        assert!(!interaction.update(&mut model, press(KeyCode::Tab)));
        assert_eq!(
            interaction.editor.as_ref().unwrap().field_name(),
            "client.profiles[1].server_name"
        );
        assert!(!interaction.update(&mut model, press(KeyCode::Enter)));
        assert!(interaction.editor.as_ref().unwrap().editing);
        assert!(!interaction.update(&mut model, press(KeyCode::Char('q'))));
        assert!(interaction.editor.as_ref().unwrap().input.ends_with('q'));
        assert!(!interaction.update(&mut model, press(KeyCode::Esc)));
        assert!(!interaction.update(&mut model, press(KeyCode::BackTab)));
        assert_eq!(
            interaction.editor.as_ref().unwrap().field_name(),
            "client.profiles[1].server"
        );
        assert!(!interaction.update(&mut model, press(KeyCode::Up)));
        assert_eq!(
            interaction.editor.as_ref().unwrap().selected_record_id(),
            "home"
        );
        assert_eq!(model.screen, Screen::Client);
        assert!(!interaction.editor.as_ref().unwrap().dirty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn form_renders_multiple_selected_fields_without_secret_references() {
        use crate::config::{self, Config};
        use std::fs;
        let path = std::env::temp_dir().join(format!(
            "theia-tui-m41c-snapshot-{}.toml",
            std::process::id()
        ));
        let Config::Client(mut doc) =
            config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client");
        };
        let mut profile = doc.client.profiles[0].clone();
        profile.id = "backup".into();
        profile.server_name = "backup.example.org".into();
        doc.client.profiles.push(profile);
        fs::write(&path, Config::Client(doc).to_toml().unwrap()).unwrap();
        let mut editor = Editor::load(Role::Client, &path).unwrap();
        editor.select_record(true);
        editor.select_field(true);
        let interaction = Interaction::new(Some(editor));
        let model = Model::new(Some(Role::Client));
        for (width, height) in [(60, 18), (80, 24), (120, 40)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|f| draw(f, &model, Some(&interaction)))
                .unwrap();
            let screen = terminal
                .backend()
                .buffer()
                .content()
                .chunks(usize::from(width))
                .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(screen.contains("backup"), "{width}x{height}");
            assert!(screen.contains("Endpoint"), "{width}x{height}");
            assert!(screen.contains("TLS SNI"), "{width}x{height}");
            assert!(!screen.contains("THEIA_AUTH_TOKEN"), "{width}x{height}");
            assert!(!screen.contains("token_sha256"), "{width}x{height}");
        }
        fs::remove_file(path).unwrap();
    }

    fn server_issuance_fixture() -> String {
        use sha2::{Digest, Sha256};
        include_str!("../../../examples/server.toml").replace(
            "REPLACE_WITH_64_LOWERCASE_HEX",
            &format!("{:x}", Sha256::digest([0x42; 32])),
        )
    }

    fn rendered_interaction(width: u16, height: u16, model: &Model, ui: &Interaction) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f, model, Some(ui))).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(usize::from(width))
            .map(|line| line.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn record_modal_masks_references_and_requires_separate_save_confirmation() {
        use crate::config::{self, Config};
        use std::{fs, thread, time::Instant};

        let path = std::env::temp_dir().join(format!(
            "theia-record-lifecycle-ui-{}.toml",
            std::process::id()
        ));
        let original = include_str!("../../../examples/client.toml");
        fs::write(&path, original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));

        ui.update(&mut model, press(KeyCode::Char('E')));
        assert!(matches!(ui.records, Some(RecordFlow::Input { .. })));
        ui.paste_record_field("file:/private/ca.pem");
        ui.update(&mut model, press(KeyCode::Tab));
        ui.paste_record_field("env:PRIVATE_CREDENTIAL");
        let rendered = rendered_interaction(120, 40, &model, &ui);
        assert!(rendered.contains("скрыто"));
        assert!(!rendered.contains("PRIVATE_CREDENTIAL"));
        assert!(!rendered.contains("/private/ca.pem"));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(ui.records, Some(RecordFlow::Confirm(_))));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.records.is_none());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        ui.update(&mut model, press(KeyCode::Char('E')));
        ui.paste_record_field("file:/private/ca.pem");
        ui.update(&mut model, press(KeyCode::Tab));
        ui.paste_record_field("env:PRIVATE_CREDENTIAL");
        ui.update(&mut model, press(KeyCode::Enter));
        ui.update(&mut model, press(KeyCode::Char('y')));
        let until = Instant::now() + Duration::from_secs(5);
        while ui.saving.is_some() && Instant::now() < until {
            ui.poll_save(&mut model).unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(ui.saving.is_none());
        assert!(!ui.editor.as_ref().unwrap().dirty());
        let Config::Client(doc) = config::read_file(&path).unwrap() else {
            panic!("client fixture");
        };
        assert_eq!(doc.client.profiles[0].auth_token, "env:PRIVATE_CREDENTIAL");
        assert_eq!(
            doc.client.profiles[0].tls_ca.as_deref(),
            Some("file:/private/ca.pem")
        );
        fs::remove_file(&path).unwrap();
        let _ = fs::remove_file(config::lock_path(&path).unwrap());
    }

    #[test]
    fn common_import_dispatches_reality_uri_to_masked_independent_enrollment() {
        use crate::reference_health::{Evidence, Plan, State, Target};
        let now = crate::reference_health::unix_now().unwrap();
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
                h3_status: Some(200),
            }],
            now,
        )
        .unwrap();
        let identity = crate::identity_tls::Identity::generate(crate::descriptor::Scope {
            inbound: "edge".into(),
            endpoint: "edge.example.org:443".into(),
        })
        .unwrap();
        let signed = crate::reality_bootstrap::initial_descriptor(&state, &identity, now).unwrap();
        let uri = crate::reality_bootstrap::Invitation::public(&identity, &signed, now)
            .unwrap()
            .encode()
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "theia-tui-common-import-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut model = Model::new(Some(Role::Client));
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        ui.update(&mut model, press(KeyCode::Char('i')));
        ui.paste_import_source(&uri);
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.importing.is_none());
        let panel = ui.reality_enrollment.as_ref().unwrap();
        let body = panel.body();
        assert!(body.contains("Fingerprint"));
        assert!(!body.contains(uri.as_str()));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.reality_enrollment.is_none());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn client_import_modal_masks_pasted_link_and_requires_explicit_confirmation() {
        use crate::{
            config::{self, Config},
            invite::Invitation,
        };
        use std::{fs, thread, time::Instant};
        let path =
            std::env::temp_dir().join(format!("theia-f14-client-ui-{}.toml", std::process::id()));
        let Config::Client(original) =
            config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client");
        };
        let mut new_profile = original.client.profiles[0].clone();
        new_profile.id = "remote".into();
        new_profile.server = "remote.example.org:443".into();
        new_profile.server_name = "remote.example.org".into();
        let link = Invitation::public_from_profile(&new_profile)
            .unwrap()
            .encode()
            .unwrap();
        fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        ui.update(&mut model, press(KeyCode::Char('i')));
        assert!(matches!(ui.importing, Some(ImportFlow::Input(_))));
        ui.paste_import_source(&link);
        let hidden = rendered_interaction(120, 40, &model, &ui);
        assert!(hidden.contains("скрыто"));
        assert!(!hidden.contains(&link));
        assert!(!hidden.contains("remote.example.org"));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(ui.importing, Some(ImportFlow::Preview { .. })));
        let preview = rendered_interaction(120, 40, &model, &ui);
        assert!(preview.contains("remote.example.org"));
        assert!(preview.contains("НЕ"));
        assert!(!preview.contains("theia://v1/"));
        ui.update(&mut model, press(KeyCode::Char('y')));
        assert!(
            ui.saving.is_none(),
            "public tokenless link needs explicit env reference"
        );
        ui.update(&mut model, press(KeyCode::Char('e')));
        for ch in "env:REMOTE_TOKEN".chars() {
            ui.update(&mut model, press(KeyCode::Char(ch)));
        }
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(ui.importing, Some(ImportFlow::Preview { .. })));
        ui.update(&mut model, press(KeyCode::Char('y')));
        assert!(ui.saving.is_some());
        let start = Instant::now();
        while ui.saving.is_some() && start.elapsed() < Duration::from_secs(5) {
            ui.poll_save(&mut model).unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(ui.saving.is_none());
        assert!(matches!(ui.importing, Some(ImportFlow::Done)));
        let Config::Client(after) = config::read_file(&path).unwrap() else {
            panic!("client");
        };
        assert_eq!(after.client.active_profile, "home");
        assert_eq!(after.client.profiles.len(), 2);
        assert_eq!(after.client.profiles[1].id, "remote");
        assert_eq!(after.client.profiles[1].auth_token, "env:REMOTE_TOKEN");
        assert!(!fs::read_to_string(&path).unwrap().contains(&link));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.importing.is_none());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn credential_replacement_requires_separate_confirmation_and_keeps_profile() {
        use crate::{
            config::{self, Config},
            invite::Invitation,
        };
        use std::{fs, thread, time::Instant};

        let name = format!("theia-refresh-ui-{}.toml", std::process::id());
        let path = std::env::temp_dir().join(name);
        fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
        let server = config::parse(&server_issuance_fixture()).unwrap();
        let invitation =
            Invitation::issued_from_server(&server, "public", "device-a", &[0x42; 32]).unwrap();
        let mut editor = Editor::load(Role::Client, &path).unwrap();
        let public = Invitation::public_from_server(&server, "public").unwrap();
        editor
            .import_invitation(&public, None, Some("env:PREVIOUS_TOKEN"))
            .unwrap();
        let before = fs::read(&path).unwrap();
        let mut ui = Interaction::new(Some(editor));
        let mut model = Model::new(Some(Role::Client));
        let link = Zeroizing::new(invitation.encode().unwrap());

        for confirm in [false, true] {
            ui.update(&mut model, press(KeyCode::Char('i')));
            ui.paste_import_source(&link);
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(matches!(ui.importing, Some(ImportFlow::Preview { .. })));
            ui.update(&mut model, press(KeyCode::Char('r')));
            assert!(matches!(ui.importing, Some(ImportFlow::RefreshConfirm(_))));
            assert!(ui.saving.is_none());
            assert_eq!(fs::read(&path).unwrap(), before);
            assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
            if !confirm {
                ui.update(&mut model, press(KeyCode::Esc));
                assert!(ui.importing.is_none());
                continue;
            }
            ui.update(&mut model, press(KeyCode::Char('y')));
            assert!(ui.saving.is_some());
            let start = Instant::now();
            while ui.saving.is_some() && start.elapsed() < Duration::from_secs(5) {
                ui.poll_save(&mut model).unwrap();
                thread::sleep(Duration::from_millis(5));
            }
            assert!(matches!(ui.importing, Some(ImportFlow::RefreshDone)));
        }
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        let Config::Client(after) = config::read_file(&path).unwrap() else {
            panic!("client");
        };
        assert_eq!(after.client.active_profile, "home");
        assert_eq!(after.client.profiles.len(), 2);
        assert_eq!(after.client.profiles[1].id, "public");
        let reference = &after.client.profiles[1].auth_token;
        let secret = Path::new(reference.strip_prefix("file:").unwrap());
        fs::remove_file(secret).unwrap();
        fs::remove_dir(secret.parent().unwrap()).unwrap();
        fs::remove_file(&path).unwrap();
        fs::remove_file(config::lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn public_share_is_repeatable_and_never_enters_confidential_flow() {
        use std::fs;

        let name = format!("theia-public-share-ui-{}.toml", std::process::id());
        let path = std::env::temp_dir().join(name);
        let source = server_issuance_fixture();
        fs::write(&path, &source).unwrap();
        let editor = Editor::load(Role::Server, &path).unwrap();
        let mut ui = Interaction::new(Some(editor));
        let mut model = Model::new(Some(Role::Server));
        for _ in 0..2 {
            ui.update(&mut model, press(KeyCode::Char('l')));
            let Some(IssueFlow::Public(link)) = ui.issuance.as_ref() else {
                panic!("public link expected");
            };
            let invite = Invitation::decode(link).unwrap();
            assert!(!invite.has_token());
            assert!(!ui.editor.as_ref().unwrap().issued_ready());
            assert!(ui.saving.is_none());
            assert!(ui.exporting.is_none());
            ui.update(&mut model, press(KeyCode::Esc));
            assert!(ui.issuance.is_none());
        }
        assert_eq!(fs::read_to_string(&path).unwrap(), source);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn reenable_requires_separate_confirmation_and_never_reuses_old_bearer() {
        use std::{fs, thread, time::Instant};

        let name = format!("theia-reenable-ui-{}.toml", std::process::id());
        let path = std::env::temp_dir().join(name);
        fs::write(&path, server_issuance_fixture()).unwrap();
        let mut editor = Editor::load(Role::Server, &path).unwrap();
        editor.disable_user("device-a").unwrap();
        assert!(editor.save());
        let disabled = fs::read(&path).unwrap();
        let mut ui = Interaction::new(Some(editor));
        let mut model = Model::new(Some(Role::Server));

        for confirm in [false, true] {
            ui.update(&mut model, press(KeyCode::Char('b')));
            for ch in "device-a".chars() {
                ui.update(&mut model, press(KeyCode::Char(ch)));
            }
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(matches!(ui.issuance, Some(IssueFlow::Confirm(_))));
            assert!(ui.saving.is_none());
            assert_eq!(fs::read(&path).unwrap(), disabled);
            if !confirm {
                ui.update(&mut model, press(KeyCode::Esc));
                assert!(ui.issuance.is_none());
                continue;
            }
            ui.update(&mut model, press(KeyCode::Char('y')));
            let start = Instant::now();
            while ui.saving.is_some() && start.elapsed() < Duration::from_secs(5) {
                ui.poll_save(&mut model).unwrap();
                thread::sleep(Duration::from_millis(5));
            }
            assert!(matches!(ui.issuance, Some(IssueFlow::Offer)));
        }
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        let invite = ui.editor.as_mut().unwrap().take_issued().unwrap();
        assert!(invite.token_bytes() != Some([0x42; 32]));
        assert!(ui.editor.as_mut().unwrap().take_issued().is_none());
        fs::remove_file(&path).unwrap();
        fs::remove_file(crate::config::lock_path(&path).unwrap()).unwrap();
    }

    #[test]
    fn client_import_refuses_dirty_editor_and_cancellation_does_not_modify_disk() {
        use std::fs;
        let path =
            std::env::temp_dir().join(format!("theia-f14-cancel-ui-{}.toml", std::process::id()));
        let source = include_str!("../../../examples/client.toml");
        fs::write(&path, source).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        ui.update(&mut model, press(KeyCode::Char('i')));
        assert!(matches!(ui.importing, Some(ImportFlow::Input(_))));
        ui.paste_import_source("invalid://fake");
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.importing.is_none());
        assert_eq!(fs::read_to_string(&path).unwrap(), source);
        ui.editor.as_mut().unwrap().begin();
        ui.editor.as_mut().unwrap().input = "different.example.org:443".into();
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.editor.as_ref().unwrap().dirty());
        ui.update(&mut model, press(KeyCode::Char('i')));
        assert!(ui.importing.is_none());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn server_issuance_modal_hides_secret_until_durable_save_and_explicit_reveal() {
        use crate::config::{self, Config};
        use crate::invite::Invitation;
        use sha2::{Digest, Sha256};
        use std::{fs, thread, time::Instant};

        let path = std::env::temp_dir().join(format!(
            "theia-m44b-issuance-ui-{}.toml",
            std::process::id()
        ));
        fs::write(&path, server_issuance_fixture()).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        assert!(!ui.update(&mut model, press(KeyCode::Char('u'))));
        assert!(matches!(ui.issuance, Some(IssueFlow::Input(_))));
        for ch in "new-device".chars() {
            assert!(!ui.update(&mut model, press(KeyCode::Char(ch))));
        }
        assert!(!ui.update(&mut model, press(KeyCode::Enter)));
        assert!(matches!(ui.issuance, Some(IssueFlow::Confirm(_))));
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        assert!(!ui.update(&mut model, press(KeyCode::Char('y'))));
        assert!(ui.saving.is_some());
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        let start = Instant::now();
        while ui.saving.is_some() && start.elapsed() < Duration::from_secs(5) {
            ui.poll_save(&mut model).unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(ui.saving.is_none());
        assert!(matches!(ui.issuance, Some(IssueFlow::Offer)));
        assert!(ui.editor.as_ref().unwrap().issued_ready());
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        let Config::Server(doc) = config::read_file(&path).unwrap() else {
            panic!("server");
        };
        assert!(doc.server.inbounds[0]
            .allowed_user_ids
            .contains(&"new-device".to_owned()));
        assert!(!ui.update(&mut model, press(KeyCode::Char('y'))));
        let IssueFlow::Showing(uri) = ui.issuance.as_ref().unwrap() else {
            panic!("explicit one-time reveal expected");
        };
        let invitation = Invitation::decode(uri).unwrap();
        let bytes = invitation.token_bytes().unwrap();
        let saved_user = doc
            .server
            .users
            .iter()
            .find(|u| u.id == "new-device")
            .unwrap();
        assert_eq!(
            saved_user.token_sha256,
            format!("{:x}", Sha256::digest(bytes))
        );
        assert!(rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        assert!(!ui.update(&mut model, press(KeyCode::Char('q'))));
        assert_eq!(model.screen, Screen::Server);
        assert!(!ui.update(&mut model, press(KeyCode::Esc)));
        assert!(ui.issuance.is_none());
        assert!(ui.editor.as_mut().unwrap().take_issued().is_none());
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn clipboard_and_qr_offer_require_separate_confirmation_and_never_render_secret() {
        let path = std::env::temp_dir()
            .join(crate::tui_editor::generated_id("theia-share-ui").unwrap())
            .with_extension("toml");
        std::fs::write(&path, server_issuance_fixture()).unwrap();
        let mut editor = Editor::load(Role::Server, &path).unwrap();
        editor.issue_user("share-device").unwrap();
        assert!(editor.save());
        let mut ui = Interaction::new(Some(editor));
        let mut model = Model::new(Some(Role::Server));
        ui.issuance = Some(IssueFlow::Offer);
        for key in ['Q', 'c'] {
            ui.update(&mut model, press(KeyCode::Char(key)));
            assert!(matches!(ui.issuance, Some(IssueFlow::ShareConfirm { .. })));
            assert!(ui.clipboard.is_none() && ui.sharing.is_none());
            assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
            ui.update(&mut model, press(KeyCode::Esc));
            assert!(ui.editor.as_ref().unwrap().issued_ready());
        }
        ui.update(&mut model, press(KeyCode::Char('c')));
        ui.update(&mut model, press(KeyCode::Char('y')));
        let link = ui.clipboard.take().unwrap();
        assert!(Invitation::decode(&link).unwrap().has_token());
        assert!(ui.editor.as_mut().unwrap().take_issued().is_none());
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_file(crate::config::lock_path(&path).unwrap());
    }

    #[test]
    fn protected_export_requires_confirmation_and_never_renders_bearer() {
        use std::{fs, thread, time::Instant};

        let path = std::env::temp_dir().join(format!(
            "theia-protected-export-ui-{}.toml",
            std::process::id()
        ));
        fs::write(&path, server_issuance_fixture()).unwrap();
        let mut editor = Editor::load(Role::Server, &path).unwrap();
        editor.issue_user("export-device").unwrap();
        assert!(editor.save());
        let mut ui = Interaction::new(Some(editor));
        let mut model = Model::new(Some(Role::Server));
        ui.issuance = Some(IssueFlow::Offer);

        ui.update(&mut model, press(KeyCode::Char('f')));
        assert!(matches!(ui.issuance, Some(IssueFlow::ConfirmExport)));
        assert!(ui.exporting.is_none());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(matches!(ui.issuance, Some(IssueFlow::Offer)));
        assert!(ui.editor.as_ref().unwrap().issued_ready());
        ui.update(&mut model, press(KeyCode::Char('f')));
        ui.update(&mut model, press(KeyCode::Char('y')));
        assert!(ui.exporting.is_some());
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));

        let start = Instant::now();
        while ui.exporting.is_some() && start.elapsed() < Duration::from_secs(5) {
            ui.poll_save(&mut model).unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        let Some(IssueFlow::Exported(export)) = ui.issuance.as_ref() else {
            panic!("protected file export expected");
        };
        let export = export.clone();
        let invitation = client_import::read_source(export.to_str().unwrap()).unwrap();
        assert!(invitation.has_token());
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        assert!(ui.editor.as_mut().unwrap().take_issued().is_none());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.issuance.is_none());
        fs::remove_file(&export).unwrap();
        fs::remove_dir(export.parent().unwrap()).unwrap();
        fs::remove_file(&path).unwrap();
        let lock = crate::config::lock_path(&path).unwrap();
        fs::remove_file(lock).unwrap();
    }

    #[test]
    fn conflict_after_issuance_refuses_reveal_and_requires_retry_or_discard() {
        use std::{fs, thread, time::Instant};
        let path = std::env::temp_dir().join(format!(
            "theia-m44b-conflict-ui-{}.toml",
            std::process::id()
        ));
        fs::write(&path, server_issuance_fixture()).unwrap();
        let mut editor = Editor::load(Role::Server, &path).unwrap();
        editor.issue_user("new-device").unwrap();
        fs::write(
            &path,
            "# external writer\n".to_string() + &server_issuance_fixture(),
        )
        .unwrap();
        let mut ui = Interaction::new(Some(editor));
        let mut model = Model::new(Some(Role::Server));
        ui.issuance = Some(IssueFlow::Saving);
        ui.start_save();
        let start = Instant::now();
        while ui.saving.is_some() && start.elapsed() < Duration::from_secs(5) {
            ui.poll_save(&mut model).unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(ui.issuance, Some(IssueFlow::SaveFailed)));
        assert!(!ui.editor.as_ref().unwrap().issued_ready());
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        assert!(!ui.update(&mut model, press(KeyCode::Char('y'))));
        assert!(matches!(ui.issuance, Some(IssueFlow::SaveFailed)));
        assert!(!ui.update(&mut model, press(KeyCode::Char('d'))));
        assert!(ui.issuance.is_none());
        assert!(!ui.editor.as_ref().unwrap().dirty());
        assert!(ui.editor.as_mut().unwrap().take_issued().is_none());
        assert!(!fs::read_to_string(&path).unwrap().contains("new-device"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn client_panel_cannot_open_server_issuance_and_dirty_draft_is_guarded() {
        use std::fs;
        let path =
            std::env::temp_dir().join(format!("theia-m44b-client-ui-{}.toml", std::process::id()));
        fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        assert!(!ui.update(&mut model, press(KeyCode::Char('u'))));
        assert!(ui.issuance.is_none());
        fs::remove_file(path).unwrap();

        let path =
            std::env::temp_dir().join(format!("theia-m44b-dirty-ui-{}.toml", std::process::id()));
        fs::write(&path, server_issuance_fixture()).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        ui.editor.as_mut().unwrap().begin();
        ui.editor.as_mut().unwrap().input = "other.example.org".into();
        assert!(!ui.update(&mut model, press(KeyCode::Enter)));
        assert!(ui.editor.as_ref().unwrap().dirty());
        assert!(!ui.update(&mut model, press(KeyCode::Char('u'))));
        assert!(ui.issuance.is_none());
        assert!(ui
            .editor
            .as_ref()
            .unwrap()
            .error
            .as_deref()
            .unwrap()
            .contains("черновик"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rotation_modal_confirms_global_change_and_hides_new_secret_until_saved() {
        use crate::config::{self, Config};
        use crate::invite::Invitation;
        use sha2::{Digest, Sha256};
        use std::{fs, thread, time::Instant};

        let path = std::env::temp_dir().join(format!(
            "theia-m44b2b1-rotate-ui-{}.toml",
            std::process::id()
        ));
        fs::write(&path, server_issuance_fixture()).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        ui.update(&mut model, press(KeyCode::Char('t')));
        assert!(matches!(ui.issuance, Some(IssueFlow::Input(_))));
        for ch in "device-a".chars() {
            ui.update(&mut model, press(KeyCode::Char(ch)));
        }
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(ui.issuance, Some(IssueFlow::Confirm(_))));
        let review = rendered_interaction(120, 40, &model, &ui);
        assert!(review.contains("всех inbound"));
        assert!(review.contains("CAS Apply"));
        assert!(!review.contains("theia://v1/"));
        let Config::Server(before) = config::read_file(&path).unwrap() else {
            panic!("server");
        };
        let old_hash = before.server.users[0].token_sha256.clone();
        ui.update(&mut model, press(KeyCode::Char('y')));
        assert!(ui.saving.is_some());
        let start = Instant::now();
        while ui.saving.is_some() && start.elapsed() < Duration::from_secs(5) {
            ui.poll_save(&mut model).unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(ui.saving.is_none());
        assert!(matches!(ui.issuance, Some(IssueFlow::Offer)));
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        let Config::Server(after) = config::read_file(&path).unwrap() else {
            panic!("server");
        };
        assert_ne!(after.server.users[0].token_sha256, old_hash);
        assert_eq!(
            after.server.inbounds[0].allowed_user_ids,
            before.server.inbounds[0].allowed_user_ids
        );
        ui.update(&mut model, press(KeyCode::Char('y')));
        let IssueFlow::Showing(link) = ui.issuance.as_ref().unwrap() else {
            panic!("one-time rotation reveal expected");
        };
        let token = Invitation::decode(link).unwrap().token_bytes().unwrap();
        assert_eq!(
            after.server.users[0].token_sha256,
            format!("{:x}", Sha256::digest(token))
        );
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.issuance.is_none());
        assert!(ui.editor.as_mut().unwrap().take_issued().is_none());
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rotation_shortcut_rejects_client_dirty_and_cancelled_confirmation() {
        use std::fs;
        let path =
            std::env::temp_dir().join(format!("theia-m44b2b1-client-{}.toml", std::process::id()));
        fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        ui.update(&mut model, press(KeyCode::Char('t')));
        assert!(ui.issuance.is_none());
        fs::remove_file(path).unwrap();

        let path =
            std::env::temp_dir().join(format!("theia-m44b2b1-server-{}.toml", std::process::id()));
        fs::write(&path, server_issuance_fixture()).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        ui.update(&mut model, press(KeyCode::Char('t')));
        for ch in "device-a".chars() {
            ui.update(&mut model, press(KeyCode::Char(ch)));
        }
        ui.update(&mut model, press(KeyCode::Enter));
        ui.update(&mut model, press(KeyCode::Char('n')));
        assert!(ui.issuance.is_none());
        assert!(!ui.editor.as_ref().unwrap().dirty());
        ui.editor.as_mut().unwrap().begin();
        ui.editor.as_mut().unwrap().input = "changed.example.org".into();
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.editor.as_ref().unwrap().dirty());
        ui.update(&mut model, press(KeyCode::Char('t')));
        assert!(ui.issuance.is_none());
        assert!(!ui.editor.as_ref().unwrap().issued_ready());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn explicit_disable_user_is_confirmed_saved_and_never_reveals_credentials() {
        use crate::config::{self, Config};
        use std::{fs, thread, time::Instant};

        let path = std::env::temp_dir().join(format!(
            "theia-m44b2a-disable-ui-{}.toml",
            std::process::id()
        ));
        fs::write(&path, server_issuance_fixture()).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        ui.update(&mut model, press(KeyCode::Char('x')));
        assert!(matches!(ui.revocation, Some(DisableFlow::Input(_))));
        for ch in "device-a".chars() {
            ui.update(&mut model, press(KeyCode::Char(ch)));
        }
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(ui.revocation, Some(DisableFlow::Confirm(_))));
        let before = rendered_interaction(120, 40, &model, &ui);
        assert!(before.contains("всех inbound"));
        assert!(!before.contains("theia://v1/"));
        let Config::Server(before_doc) = config::read_file(&path).unwrap() else {
            panic!("server");
        };
        assert!(!before_doc.server.users[0].disabled);

        ui.update(&mut model, press(KeyCode::Char('y')));
        assert!(ui.saving.is_some());
        let start = Instant::now();
        while ui.saving.is_some() && start.elapsed() < Duration::from_secs(5) {
            ui.poll_save(&mut model).unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(ui.saving.is_none());
        assert!(matches!(ui.revocation, Some(DisableFlow::Done)));
        let Config::Server(after_doc) = config::read_file(&path).unwrap() else {
            panic!("server");
        };
        assert!(after_doc.server.users[0].disabled);
        assert!(after_doc.server.inbounds[0]
            .allowed_user_ids
            .contains(&"device-a".to_string()));
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.revocation.is_none());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn disable_shortcut_rejects_client_and_dirty_server_draft() {
        use std::fs;
        let client_path =
            std::env::temp_dir().join(format!("theia-m44b2a-client-{}.toml", std::process::id()));
        fs::write(&client_path, include_str!("../../../examples/client.toml")).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &client_path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        ui.update(&mut model, press(KeyCode::Char('x')));
        assert!(ui.revocation.is_none());
        fs::remove_file(client_path).unwrap();

        let server_path =
            std::env::temp_dir().join(format!("theia-m44b2a-dirty-{}.toml", std::process::id()));
        fs::write(&server_path, server_issuance_fixture()).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &server_path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        let editor = ui.editor.as_mut().unwrap();
        editor.begin();
        editor.input = "other.example.org".into();
        assert!(editor.accept());
        ui.update(&mut model, press(KeyCode::Char('x')));
        assert!(ui.revocation.is_none());
        assert!(ui.editor.as_ref().unwrap().dirty());
        fs::remove_file(server_path).unwrap();
    }

    #[test]
    fn reality_enrollment_panel_is_client_only() {
        let mut ui = Interaction::new(None);
        let mut model = Model::new(Some(Role::Server));
        ui.update(&mut model, press(KeyCode::Char('I')));
        assert!(ui.reality_enrollment.is_none());
        model.update(press(KeyCode::Char('2')));
        ui.update(&mut model, press(KeyCode::Char('I')));
        assert!(ui.config_dialog.is_some());
        assert!(rendered_interaction(120, 40, &model, &ui).contains("Импорт REALITY"));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.config_dialog.is_none());
    }

    #[test]
    fn reality_provision_panel_is_server_only_and_does_not_change_runtime() {
        let mut ui = Interaction::new(None);
        let mut model = Model::new(Some(Role::Client));
        ui.update(&mut model, press(KeyCode::Char('W')));
        assert!(ui.reality_provision.is_none());
        model.update(press(KeyCode::Char('1')));
        ui.update(&mut model, press(KeyCode::Char('W')));
        assert!(ui.config_dialog.is_some());
        assert!(rendered_interaction(120, 40, &model, &ui).contains("SmartTheia REALITY"));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.config_dialog.is_none());
        assert_eq!(model.screen, Screen::Server);
    }

    #[test]
    fn server_discovery_panel_is_passive_until_separate_ipify_consent() {
        let mut model = Model::new(Some(Role::Server));
        let mut ui = Interaction::new(None);
        assert!(ui.discovery.is_none());
        assert!(!ui.update(&mut model, press(KeyCode::Char('p'))));
        assert_eq!(model.screen, Screen::Server);
        assert!(ui.discovery.is_some());
        assert!(!ui.discovery.as_ref().unwrap().is_consent_pending());
        let passive = rendered_interaction(120, 40, &model, &ui);
        assert!(passive.contains("Пассивный"));
        assert!(passive.contains("14"));
        assert!(passive.contains("api64.ipify.org"));
        assert!(!passive.contains("ЗАПРОС ВЫПОЛНЕН"));

        assert!(!ui.update(&mut model, press(KeyCode::Char('i'))));
        assert!(ui.discovery.as_ref().unwrap().is_consent_pending());
        let ask = rendered_interaction(120, 40, &model, &ui);
        assert!(ask.contains("СОГЛАСИЕ"));
        assert!(ask.contains("api64.ipify.org"));
        assert!(!ui.update(&mut model, press(KeyCode::Char('n'))));
        assert!(!ui.discovery.as_ref().unwrap().is_consent_pending());
        assert!(!ui.update(&mut model, press(KeyCode::Esc)));
        assert!(ui.discovery.is_none());
        assert_eq!(model.screen, Screen::Server);
    }

    #[test]
    fn ip_discovery_is_not_triggered_from_client_help_or_home() {
        let mut ui = Interaction::new(None);
        let mut model = Model::new(None);
        assert!(!ui.update(&mut model, press(KeyCode::Char('p'))));
        assert!(ui.discovery.is_none());
        model.update(press(KeyCode::Char('2')));
        assert_eq!(model.screen, Screen::Client);
        assert!(!ui.update(&mut model, press(KeyCode::Char('p'))));
        assert!(ui.discovery.is_none());
        model.update(press(KeyCode::Char('?')));
        assert!(!ui.update(&mut model, press(KeyCode::Char('p'))));
        assert!(ui.discovery.is_none());
    }

    #[test]
    fn unsaved_server_form_cannot_hide_inside_discovery_without_guard() {
        use std::fs;
        let path =
            std::env::temp_dir().join(format!("theia-m45a-discovery-{}.toml", std::process::id()));
        fs::write(&path, server_issuance_fixture()).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        ui.editor.as_mut().unwrap().begin();
        ui.editor.as_mut().unwrap().input = "changed.example.org".into();
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.editor.as_ref().unwrap().dirty());
        assert!(!ui.update(&mut model, press(KeyCode::Char('p'))));
        assert!(ui.discovery.is_none());
        assert!(ui
            .editor
            .as_ref()
            .unwrap()
            .error
            .as_deref()
            .unwrap()
            .contains("Сохраните"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn explicit_tls_probe_review_requires_server_context_not_ipify_consent() {
        let mut model = Model::new(Some(Role::Server));
        let mut ui = Interaction::new(None);
        assert!(!ui.update(&mut model, press(KeyCode::Char('p'))));
        assert!(ui.discovery.is_some());
        assert!(ui.probe.is_none());
        assert!(!ui.update(&mut model, press(KeyCode::Char('t'))));
        assert!(ui.probe.is_some());
        let review = rendered_interaction(120, 40, &model, &ui);
        assert!(review.contains("TLS/H2"));
        assert!(review.contains("конфигурация"));
        // A standalone y without a selected target and explicit confirmation
        // can never open sockets or mark TLS as verified.
        assert!(!ui.update(&mut model, press(KeyCode::Char('y'))));
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("TLS 1.3 подтверждён"));
        assert!(!ui.update(&mut model, press(KeyCode::Esc)));
        assert!(ui.probe.is_none());
        assert!(ui.discovery.is_some());
    }

    #[test]
    fn server_review_groups_are_passive_and_cidr_confirmation_cannot_be_skipped() {
        let mut model = Model::new(Some(Role::Server));
        let mut ui = Interaction::new(None);
        assert!(!ui.update(&mut model, press(KeyCode::Char('p'))));
        assert!(!ui.update(&mut model, press(KeyCode::Char('r'))));
        assert!(ui.candidates.is_some());
        let text = rendered_interaction(120, 40, &model, &ui);
        assert!(text.contains("Подсеть сервера"));
        assert!(text.contains("Популярные домены"));
        assert!(text.contains("Добавленные вручную"));
        assert!(!ui.update(&mut model, press(KeyCode::Char('y'))));
        assert!(!ui.candidates.as_ref().unwrap().has_scope());
        assert!(!ui.update(&mut model, press(KeyCode::Char('a'))));
        assert!(ui.candidates.as_ref().unwrap().is_editing());
        for ch in "bad-addr".chars() {
            assert!(!ui.update(&mut model, press(KeyCode::Char(ch))));
        }
        assert!(!ui.update(&mut model, press(KeyCode::Enter)));
        assert!(!ui.candidates.as_ref().unwrap().is_confirming());
        assert!(!ui.update(&mut model, press(KeyCode::Esc)));
        assert!(!ui.candidates.as_ref().unwrap().is_editing());
        assert!(!ui.update(&mut model, press(KeyCode::Esc)));
        assert!(ui.candidates.is_none());
        assert!(ui.discovery.is_some());
        assert!(!ui.update(&mut model, press(KeyCode::Esc)));
        assert!(ui.discovery.is_none());
    }

    #[test]
    fn review_hotkey_is_not_available_outside_passive_server_discovery() {
        let mut model = Model::new(Some(Role::Client));
        let mut ui = Interaction::new(None);
        ui.update(&mut model, press(KeyCode::Char('r')));
        assert!(ui.candidates.is_none());
        model.update(press(KeyCode::Char('1')));
        ui.update(&mut model, press(KeyCode::Char('r')));
        assert!(ui.candidates.is_none());
        ui.update(&mut model, press(KeyCode::Char('p')));
        assert!(ui.discovery.is_some());
        ui.update(&mut model, press(KeyCode::Char('i')));
        assert!(ui.discovery.as_ref().unwrap().is_consent_pending());
        ui.update(&mut model, press(KeyCode::Char('r')));
        assert!(ui.candidates.is_none());
        ui.update(&mut model, press(KeyCode::Char('n')));
        ui.update(&mut model, press(KeyCode::Char('r')));
        assert!(ui.candidates.is_some());
    }

    #[test]
    fn server_batch_chooser_remains_offline_until_individual_ip_checks_and_final_y() {
        let mut model = Model::new(Some(Role::Server));
        let mut ui = Interaction::new(None);
        ui.update(&mut model, press(KeyCode::Char('p')));
        ui.update(&mut model, press(KeyCode::Char('r')));
        assert!(ui.candidates.is_some());
        ui.update(&mut model, press(KeyCode::Char('b')));
        assert!(ui.candidate_batch.is_some());
        assert!(!ui.candidate_batch.as_ref().unwrap().is_running());
        let displayed = rendered_interaction(120, 40, &model, &ui);
        assert!(
            displayed.contains("нет серверной конфигурации")
                || displayed.contains("Нет серверной конфигурации")
        );
        ui.update(&mut model, press(KeyCode::Enter));
        ui.update(&mut model, press(KeyCode::Char('y')));
        assert!(!ui.candidate_batch.as_ref().unwrap().is_running());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.candidate_batch.is_none());
        assert!(ui.candidates.is_some());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.candidates.is_none());
        assert!(ui.discovery.is_some());
    }

    #[test]
    fn batch_modal_cannot_open_while_editing_or_confirming_cidr_and_esc_unwinds() {
        let mut model = Model::new(Some(Role::Server));
        let mut ui = Interaction::new(None);
        ui.update(&mut model, press(KeyCode::Char('p')));
        ui.update(&mut model, press(KeyCode::Char('r')));
        ui.update(&mut model, press(KeyCode::Char('a')));
        assert!(ui.candidates.as_ref().unwrap().is_editing());
        ui.update(&mut model, press(KeyCode::Char('b')));
        assert!(ui.candidate_batch.is_none());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(!ui.candidates.as_ref().unwrap().is_editing());
        ui.update(&mut model, press(KeyCode::Char('b')));
        assert!(ui.candidate_batch.is_some());
        ui.update(&mut model, press(KeyCode::Char(' ')));
        ui.update(&mut model, press(KeyCode::Enter));
        ui.update(&mut model, press(KeyCode::Char('y')));
        assert!(!ui.candidate_batch.as_ref().unwrap().is_running());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.candidate_batch.is_none());
    }

    #[test]
    fn domain_catalog_opens_offline_and_requires_distinct_dns_confirmation() {
        let mut model = Model::new(Some(Role::Server));
        let mut ui = Interaction::new(None);
        ui.update(&mut model, press(KeyCode::Char('p')));
        ui.update(&mut model, press(KeyCode::Char('r')));
        ui.update(&mut model, press(KeyCode::Char('d')));
        assert!(ui.domain.is_some());
        assert!(!ui.domain.as_ref().unwrap().is_running());
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("каталог") || screen.contains("Каталог"));
        assert!(screen.contains("DNS ещё НЕ выполнялся"));
        ui.update(&mut model, press(KeyCode::Char('y')));
        assert!(!ui.domain.as_ref().unwrap().is_running());
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.domain.as_ref().unwrap().is_dns_confirming());
        ui.update(&mut model, press(KeyCode::Char('n')));
        assert!(!ui.domain.as_ref().unwrap().is_dns_confirming());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.domain.is_none());
        assert!(ui.candidates.is_some());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.candidates.is_none());
    }

    #[test]
    fn domain_resolver_is_inaccessible_from_client_or_active_cidr_editor() {
        let mut model = Model::new(Some(Role::Client));
        let mut ui = Interaction::new(None);
        ui.update(&mut model, press(KeyCode::Char('d')));
        assert!(ui.domain.is_none());
        model.screen = Screen::Server;
        ui.update(&mut model, press(KeyCode::Char('p')));
        ui.update(&mut model, press(KeyCode::Char('r')));
        ui.update(&mut model, press(KeyCode::Char('a')));
        assert!(ui.candidates.as_ref().unwrap().is_editing());
        ui.update(&mut model, press(KeyCode::Char('d')));
        assert!(ui.domain.is_none());
        ui.update(&mut model, press(KeyCode::Esc));
        ui.update(&mut model, press(KeyCode::Char('d')));
        assert!(ui.domain.is_some());
        assert!(!ui.domain.as_ref().unwrap().is_running());
    }

    #[test]
    fn key_release_and_non_relevant_keys_do_not_navigate() {
        let mut model = Model::new(None);
        let mut key = press(KeyCode::Char('2'));
        key.kind = KeyEventKind::Release;
        assert!(!model.update(key));
        assert_eq!(model.screen, Screen::Home);
        assert!(!model.update(press(KeyCode::Char('x'))));
        assert_eq!(model.screen, Screen::Home);
        assert!(!model.update(press(KeyCode::F(1))));
        assert_eq!(model.screen, Screen::Help);
        assert!(!model.update(press(KeyCode::Char('2'))));
        assert_eq!(model.screen, Screen::Help);
    }

    #[test]
    fn credential_and_revocation_panels_distinguish_saved_state_from_runtime() {
        fn render(mut render_panel: impl FnMut(&mut Frame<'_>, Rect)) -> String {
            let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    render_panel(frame, area);
                })
                .unwrap();
            terminal
                .backend()
                .buffer()
                .content()
                .chunks(120)
                .map(|line| line.iter().map(|cell| cell.symbol()).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        }
        let hidden = "DO-NOT-EXPOSE-BEARER-TEST";
        for (kind, label) in [
            (IssueKind::NewUser, "Новый пользователь"),
            (IssueKind::Rotation, "Ротация токена"),
            (IssueKind::Reenable, "Восстановление отключённого"),
        ] {
            let input = render(|f, a| {
                draw_issuance(f, a, &IssueFlow::Input("device-a".into()), None, kind, None, 0)
            });
            assert!(input.contains(label));
            let confirm = render(|f, a| {
                draw_issuance(
                    f,
                    a,
                    &IssueFlow::Confirm("device-a".into()),
                    None,
                    kind,
                    None,
                    0,
                )
            });
            assert!(confirm.contains("Подтверждение"));
            assert!(confirm.contains("y: подтвердить"));
            let failed =
                render(|f, a| draw_issuance(f, a, &IssueFlow::SaveFailed, None, kind, None, 0));
            assert!(failed.contains("ссылка заблокирована"));
            let offer = render(|f, a| draw_issuance(f, a, &IssueFlow::Offer, None, kind, None, 0));
            assert!(offer.contains("Одноразовая"));
            assert!(offer.contains("Runtime") || offer.contains("runtime"));
            assert!(!offer.contains(hidden));
        }
        for (flow, label) in [
            (IssueFlow::Saving, "Конфиденциальная ссылка скрыта"),
            (IssueFlow::ConfirmExport, "Ссылка не будет показана"),
            (IssueFlow::Exporting, "Runtime не обновляется"),
            (
                IssueFlow::Exported(PathBuf::from("private.invite")),
                "Файл содержит bearer",
            ),
            (IssueFlow::ExportFailed, "Секрет повторно не выдаётся"),
        ] {
            let screen = render(|f, a| draw_issuance(f, a, &flow, None, IssueKind::NewUser, None, 0));
            assert!(screen.contains(label), "{screen}");
            assert!(!screen.contains(hidden));
        }
        let shown = render(|f, a| {
            draw_issuance(
                f,
                a,
                &IssueFlow::Showing(Zeroizing::new(hidden.into())),
                None,
                IssueKind::NewUser,
                None,
                0,
            )
        });
        assert!(shown.contains(hidden));
        assert!(shown.contains("однократный просмотр"));
        for (flow, label) in [
            (
                DisableFlow::Input("device-a".into()),
                "Отключить существующего",
            ),
            (
                DisableFlow::Confirm("device-a".into()),
                "отдельного auth-only Apply",
            ),
            (DisableFlow::Saving, "Runtime не изменяется"),
            (DisableFlow::SaveFailed, "TOML НЕ сохранён"),
            (DisableFlow::Done, "подтвердить auth-only Apply"),
        ] {
            let screen = render(|f, a| draw_revocation(f, a, &flow, None, None));
            assert!(screen.contains(label), "{screen}");
        }
        let input = render(|f, a| {
            draw_import(
                f,
                a,
                &ImportFlow::Input(Zeroizing::new(hidden.into())),
                None,
                None,
            )
        });
        assert!(!input.contains(hidden));
        assert!(input.contains("скрыто"));
        for (flow, label) in [
            (ImportFlow::RefreshSaving, "Runtime не меняется"),
            (
                ImportFlow::RefreshDone,
                "соединение и системный прокси не менялись",
            ),
            (ImportFlow::Saving, "Секрет не отображается"),
            (ImportFlow::Done, "исходный active_profile не изменён"),
            (ImportFlow::Failed, "Импорт НЕ подтверждён"),
        ] {
            let screen = render(|f, a| draw_import(f, a, &flow, None, None));
            assert!(screen.contains(label), "{screen}");
            assert!(!screen.contains(hidden));
        }
    }
}
