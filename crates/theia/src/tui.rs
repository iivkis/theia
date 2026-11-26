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
    tui_widgets::{
        self, ActionItem, Actions, Field, Form, ReferenceReview, ACCENT, BG, ERROR, FOCUS, INPUT,
        MUTED, SURFACE, TEXT, WARNING,
    },
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
            KeyCode::Left if self.screen == Screen::Home => {
                self.selected = Role::Server;
                false
            }
            KeyCode::Right if self.screen == Screen::Home => {
                self.selected = Role::Client;
                false
            }
            // Tab remains an optional accessibility shortcut, not the primary
            // navigation. Vertical arrows do not move horizontal role cards.
            KeyCode::Tab | KeyCode::BackTab if self.screen == Screen::Home => {
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
    ConfirmReveal,
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
    ActivateConfirm,
    Activating,
    ActivationFailed,
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
    GrantPicker {
        selected: Vec<String>,
        focus: usize,
    },
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
        if let Self::GrantPicker { selected, focus } = self {
            let editor = editor?;
            let users = editor.workspace_users();
            let fields = users.iter().enumerate().map(|(id, (name, disabled, _))| Field {
                id,
                label: if selected.contains(name) { "[x] Доступ разрешён" } else { "[ ] Нет доступа" },
                value: if *disabled { format!("{name} (отключён)") } else { name.clone() },
                hint: "Пробел меняет право на это подключение. Статус отключённой учётной записи не изменится.",
            }).collect();
            return Some(Form {
                fields,
                selected: *focus,
                lead: format!("Подключение: {} · выбрано: {}. Отметьте пользователей. Enter проверит изменения, Esc отменит.", editor.selected_record_id(), selected.len()),
                error: editor.error.clone().unwrap_or_default(),
            });
        }
        let Self::Input {
            action,
            fields,
            focus,
        } = self
        else {
            return None;
        };
        Some(Form {
            fields: action.fields().iter().zip(fields).enumerate().map(|(id, ((label, hidden), value))| Field {
                id, label, hint: match (*action, id) {
                    (RecordAction::EditTls, 0) => "Путь к PEM-файлу сертификата, например file:/etc/theia/fullchain.pem.",
                    (RecordAction::EditTls, 1) => "Путь к PEM-файлу закрытого ключа. Не вставляйте содержимое ключа.",
                    (RecordAction::EditTrust, 0) => "Путь к доверенному сертификату CA, полученному от администратора.",
                    (RecordAction::EditTrust, 1) => "Ссылка на файл токена (file:абсолютный путь) или переменную (env:ИМЯ). Не вставляйте сам токен.",
                    (RecordAction::SetQuota, 0) => "Максимум одновременных подключений одного пользователя.",
                    (RecordAction::SetQuota, 1) => "Общий максимум одновременных подключений всех пользователей.",
                    _ if *hidden => "Введите путь или ссылку на материал, а не его секретное содержимое.",
                    _ => "Введите значение; Enter — предпросмотр.",
                },
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
            Self::GrantPicker { focus, .. } => *focus = id,
            Self::Input { fields, focus, .. } if id < fields.len() => *focus = id,
            _ => {}
        }
    }
    fn body(&self) -> String {
        match self {
            Self::ChooseMode(role, _) => format!("ВЫБЕРИТЕ РЕЖИМ\n\n  1   Own-TLS\n      {}\n\n  2   SmartTheia REALITY\n      {}\n\nEsc: назад. Сохранение не запускает runtime.", if *role == Role::Server {"Свой сертификат и ключ"} else {"Ручные параметры TLS"}, if *role == Role::Server {"Мастер проверки референсов, без своего сертификата"} else {"Импорт с независимым подтверждением доверия"}),
            Self::Confirm(review) => review.body().to_owned(),
            Self::GrantPicker { .. } => "Выберите пользователей, которым разрешено это подключение. Изменения сначала проверяются и подтверждаются.".into(),
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
enum WorkspaceFocus {
    Fields,
    Navigation,
    Records,
    Actions,
    Users,
}

fn pages(role: Role) -> &'static [&'static str] {
    match role {
        Role::Server => &[
            "Обзор",
            "Подключения",
            "Пользователи и ключи",
            "Управление",
            "Статистика",
            "Настройки",
            "Диагностика",
            "Маршрутизация",
        ],
        Role::Client => &[
            "Обзор",
            "Профили",
            "Импорт ключа",
            "Подключение",
            "Статистика",
            "Настройки",
            "Маршрутизация",
        ],
    }
}

/// Record selection is only useful on pages scoped to an inbound or profile.
fn page_has_records(role: Role, page: usize) -> bool {
    page == 1 || (role == Role::Server && page == 2) || (role == Role::Client && page == 3)
}

fn page_has_users(role: Role, page: usize) -> bool {
    role == Role::Server && page == 2
}

/// Each operation has one visible owner. The overview only navigates there.
#[cfg(test)]
fn page_actions(role: Role, page: usize, editor: Option<&Editor>) -> Vec<ActionItem> {
    page_actions_for(role, page, editor, 0, false)
}

fn page_actions_for(
    role: Role,
    page: usize,
    editor: Option<&Editor>,
    user: usize,
    advanced: bool,
) -> Vec<ActionItem> {
    let entries: &[(char, &str)] = match (role, page) {
        (_, 0) => &[('>', "Перейти к следующему шагу")],
        (Role::Server, 1) => &[
            ('N', "Создать подключение"),
            ('V', "Состояние REALITY"),
            ('E', "Свой TLS-сертификат"),
            ('D', "Удалить подключение"),
            ('z', "Расширенные настройки"),
            ('l', "Публичная ссылка (без ключа доступа)"),
            ('K', "Заменить доверие REALITY"),
            ('M', "Регистрация материалов"),
            ('w', "Комплект по готовому плану"),
        ],
        (Role::Server, 2) => &[
            ('u', "Добавить пользователя и выдать ключ"),
            ('b', "Восстановить доступ и выдать ключ"),
            ('t', "Заменить ключ пользователя"),
            ('x', "Отключить пользователя"),
            ('G', "Изменить права доступа"),
            ('U', "Удалить пользователя"),
        ],
        (Role::Server, 3) => &[
            ('s', "Запуск / остановка"),
            ('a', "Применить права доступа"),
            ('v', "Состояние / другие изменения"),
            ('R', "Проверить перезапуск"),
        ],
        (_, 4) => &[('4', "Развернуть монитор")],
        (Role::Server, 5) => &[
            ('S', "Сохранить файл"),
            ('o', "Открыть другой файл"),
            ('Q', "Лимиты подключений"),
        ],
        (Role::Server, 6) => &[('p', "Сетевая диагностика")],
        (Role::Server, 7) => &[('J', "Редактор правил и GeoData")],
        (Role::Client, 1) => &[
            ('N', "Добавить профиль вручную (Own-TLS)"),
            ('E', "Доверенный сертификат и ключ"),
            ('D', "Удалить профиль"),
            ('z', "Расширенные настройки"),
            ('K', "Подтвердить доверие REALITY"),
            ('M', "Регистрация материалов"),
            ('l', "Публичная ссылка (без ключа доступа)"),
        ],
        (Role::Client, 2) => &[('i', "Ввести ключ")],
        (Role::Client, 3) if cfg!(windows) => &[
            ('p', "Включить / выключить системный прокси"),
            ('V', "Запустить / остановить локальный прокси"),
            ('L', "Выбрать другой профиль"),
            ('A', "Выбрать активный профиль"),
        ],
        (Role::Client, 3) => &[
            ('V', "Запустить / остановить локальный прокси"),
            ('L', "Выбрать другой профиль"),
            ('A', "Выбрать активный профиль"),
        ],
        (Role::Client, 6) => &[
            ('j', "Обновить состояние"),
            ('d', "Разрешить / отключить Anti-DPI"),
            ('u', "Разрешить / отключить локальный STUN"),
        ],
        (Role::Client, 5) => &[('S', "Сохранить файл"), ('o', "Открыть другой файл")],
        _ => &[],
    };
    let Some(editor) = editor else {
        return entries
            .iter()
            .map(|&(key, label)| ActionItem { key, label })
            .collect();
    };
    let reality = editor.selected_reality();
    let active = editor.selected_record_is_active();
    let has_record = editor.record_count() > 0;
    let users = if role == Role::Server {
        editor.workspace_users()
    } else {
        Vec::new()
    };
    let selected = users.get(user.min(users.len().saturating_sub(1)));
    let can_recover = selected.is_some_and(|(_, disabled, granted)| *disabled && *granted);
    let can_rotate = selected.is_some_and(|(_, disabled, granted)| !*disabled && *granted);
    entries
        .iter()
        .filter_map(|&(key, label)| {
            let available = match (role, key) {
                (_, 'l' | 'M' | 'w' | 'K') if !advanced => false,
                (Role::Server, 'V' | 'K') | (Role::Client, 'K') => has_record && reality,
                (_, 'E') => has_record && !reality,
                (Role::Server, 'D') => editor.record_count() > 1,
                (Role::Client, 'D' | 'A') => has_record && !active,
                (Role::Client, 'u') => editor.direct_dpi_allowed(),
                (Role::Client, 'L') => editor.record_count() > 1,
                (Role::Server, 'b') => can_recover,
                (Role::Server, 'x' | 't') => can_rotate,
                (_, 'l' | 'M') => has_record,
                (Role::Server, 'U') => selected.is_some_and(|(id, _, _)| editor.user_deletable(id)),
                _ => true,
            };
            let label = match (role, key) {
                (Role::Client, 'p') if !editor.system_proxy_allowed() => {
                    "Настроить и включить системный прокси"
                }
                (Role::Client, 'd') if editor.direct_dpi_allowed() => "Отключить Anti-DPI",
                (Role::Client, 'd') => "Разрешить Anti-DPI",
                (Role::Client, 'u') if editor.direct_dpi_stun_allowed() => {
                    "Отключить локальный STUN"
                }
                (Role::Client, 'u') => "Разрешить локальный STUN",
                (Role::Client, 'V') if !active => "Состояние выбранного профиля",
                (_, 'z') if advanced => "Скрыть расширенные настройки",
                _ => label,
            };
            available.then_some(ActionItem { key, label })
        })
        .collect()
}

/// The dashboard is a navigator, not a second command dispatcher.
fn recommendation_page(role: Role, key: char) -> (usize, char) {
    match (role, key) {
        (_, 'o' | 'S') => (5, key),
        (Role::Server, 'N') => (1, key),
        (Role::Server, 'u' | 'b' | 'G') => (2, key),
        (Role::Server, _) => (3, key),
        (Role::Client, 'i') => (2, key),
        (Role::Client, 'A') => (3, key),
        (Role::Client, _) => (3, 'V'),
    }
}

/// A recommendation is navigation only. It never writes, applies, or starts a process.
fn recommended_step(editor: &Editor, owned_running: bool) -> (char, &'static str) {
    if editor.write_uncertain() {
        return (
            'o',
            "Запись не подтверждена. Проверьте файл и откройте его заново.",
        );
    }
    if editor.dirty() {
        return (
            'S',
            "Сохраните изменения. Работающий процесс не изменится автоматически.",
        );
    }
    if editor.role() == Role::Server {
        if editor.record_count() == 0 {
            return ('N', "Создайте первое подключение.");
        }
        let users = editor.workspace_users();
        if !users
            .iter()
            .any(|(_, disabled, granted)| !*disabled && *granted)
        {
            if users
                .iter()
                .any(|(_, disabled, granted)| *disabled && *granted)
            {
                return (
                    'b',
                    "Выдайте приглашение первому пользователю: сейчас его доступ отключён.",
                );
            }
            if users
                .iter()
                .any(|(_, disabled, granted)| !*disabled && !*granted)
            {
                return (
                    'G',
                    "Разрешите доступ существующему пользователю или создайте нового.",
                );
            }
            return (
                'u',
                "Создайте пользователя и получите его личное приглашение.",
            );
        }
        if !owned_running {
            return (
                's',
                "Запустите сервер, если он ещё не работает как внешний сервис.",
            );
        }
        (
            'v',
            "Проверьте состояние сервера. Права, лимиты и структура применяются отдельно.",
        )
    } else if editor.record_count() == 0 {
        (
            'i',
            "Получите приглашение у администратора и импортируйте его.",
        )
    } else if owned_running {
        ('V', "Локальный процесс запущен или запускается. Откройте его состояние для проверки туннеля.")
    } else if !editor.selected_record_is_active() {
        (
            'A',
            "Выберите этот профиль активным, если хотите подключаться через него.",
        )
    } else {
        (
            'P',
            if cfg!(windows) {
                "Выберите системный или локальный прокси. Запуск требует подтверждения."
            } else {
                "Откройте подключение и запустите локальный прокси. Затем настройте нужные приложения."
            },
        )
    }
}

fn save_failure_actions(editor: Option<&Editor>) -> Vec<ActionItem> {
    let mut items = Vec::new();
    if !editor.is_some_and(Editor::write_uncertain) {
        items.push(ActionItem {
            key: 'r',
            label: "Повторить сохранение",
        });
    }
    items.push(ActionItem {
        key: 'd',
        label: "Отменить черновик",
    });
    items
}

fn issuance_actions(flow: &IssueFlow, editor: Option<&Editor>) -> Vec<ActionItem> {
    if matches!(flow, IssueFlow::SaveFailed) {
        save_failure_actions(editor)
    } else {
        invitation_actions(flow)
    }
}

fn invitation_actions(flow: &IssueFlow) -> Vec<ActionItem> {
    match flow {
        IssueFlow::Offer => vec![
            ActionItem {
                key: 'f',
                label: "Сохранить приглашение в файл",
            },
            ActionItem {
                key: 'v',
                label: "Показать ссылку один раз",
            },
            ActionItem {
                key: 'Q',
                label: "Создать QR-код",
            },
            ActionItem {
                key: 'c',
                label: "Копировать в буфер обмена",
            },
            ActionItem {
                key: 'n',
                label: "Закрыть без выдачи",
            },
        ],
        IssueFlow::Public(_) => vec![
            ActionItem {
                key: 'Q',
                label: "Создать QR-код",
            },
            ActionItem {
                key: 'c',
                label: "Копировать в буфер обмена",
            },
        ],
        _ => Vec::new(),
    }
}

// Independent keyboard-first draft. No mutation of the saved file until
// the existing guarded save/Apply workflows are explicitly invoked.
struct RoutingPanel {
    settings: crate::routing::Settings,
    selected: usize,
    fields: Option<(Option<usize>, [String; 4], usize)>,
    message: String,
    directory: PathBuf,
    download: Option<mpsc::Receiver<Result<(String, crate::routing::geodata::Manifest), String>>>,
}

impl RoutingPanel {
    fn new(editor: &Editor) -> Self {
        let settings = editor
            .routing_settings()
            .cloned()
            .unwrap_or(crate::routing::Settings {
                revision: 2,
                geodata_directory: None,
                rules: Vec::new(),
                datasets: None,
            });
        let directory = settings
            .geodata_directory
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                editor
                    .saved_path()
                    .parent()
                    .unwrap_or(Path::new("."))
                    .join("geodata")
            });
        Self {
            settings,
            selected: 0,
            fields: None,
            message: String::new(),
            directory,
            download: None,
        }
    }
    fn action_name(action: crate::routing::Action) -> &'static str {
        action.name()
    }
    fn action_label(value: &str) -> &str {
        match crate::routing::Action::from_name(value) {
            Some(crate::routing::Action::Direct) => "Напрямую",
            Some(crate::routing::Action::DirectDpi) => "Anti-DPI / резерв VPS",
            Some(crate::routing::Action::Blocked) => "Блокировать",
            Some(crate::routing::Action::Allowed) => "Через сервер",
            None => value,
        }
    }
    fn edit(&mut self, index: Option<usize>) {
        let values = index
            .and_then(|i| self.settings.rules.get(i))
            .map(|r| {
                [
                    r.name.clone(),
                    Self::action_name(r.action).into(),
                    r.domains.join(", "),
                    r.ips.join(", "),
                ]
            })
            .unwrap_or_else(|| {
                [
                    String::new(),
                    crate::routing::Action::Allowed.name().into(),
                    String::new(),
                    String::new(),
                ]
            });
        self.fields = Some((index, values, 0));
        self.message.clear();
    }
    fn paste(&mut self, input: &str) {
        if let Some((_, fields, focus)) = &mut self.fields {
            let input = input.trim_end_matches(['\r', '\n']);
            if !input.chars().any(char::is_control)
                && fields[*focus].len().saturating_add(input.len()) <= 8192
            {
                fields[*focus].push_str(input);
            }
        }
    }
    fn poll(&mut self) {
        let Some(rx) = &self.download else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok((directory, manifest))) => {
                self.settings.geodata_directory = Some(directory);
                self.settings.datasets = Some(manifest);
                self.download = None;
                self.message = "Компактные базы проверены. Проверьте правила, затем подтвердите черновик клавишей s.".into();
            }
            Ok(Err(error)) => {
                self.download = None;
                self.message = error;
            }
            Err(TryRecvError::Disconnected) => {
                self.download = None;
                self.message = "Обновление не подтверждено.".into();
            }
            Err(TryRecvError::Empty) => {}
        }
    }
    fn refresh(&mut self, download: bool) {
        let directory = self.directory.clone();
        let rules = self.settings.rules.clone();
        let (tx, rx) = mpsc::channel();
        self.download = Some(rx);
        self.message = "Загрузка XTLS и проверка SHA-256. Действующие правила не изменены.".into();
        let _worker = std::thread::spawn(move || {
            let work = || -> Result<(String, crate::routing::geodata::Manifest), String> {
                if !directory.exists() {
                    let builder = std::fs::DirBuilder::new();
                    #[cfg(unix)]
                    let builder = {
                        use std::os::unix::fs::DirBuilderExt;
                        let mut builder = builder;
                        builder.mode(0o700);
                        builder
                    };
                    builder
                        .create(&directory)
                        .map_err(|_| "Не удалось создать каталог баз.".to_owned())?;
                }
                if !std::fs::symlink_metadata(&directory).is_ok_and(|m| m.file_type().is_dir()) {
                    return Err("Небезопасный каталог баз.".into());
                }
                let directory = directory
                    .canonicalize()
                    .map_err(|_| "Некорректный каталог баз.".to_owned())?;
                let store = crate::routing::geodata::Store::new(directory.clone())
                    .map_err(|e| format!("GeoData: {e:?}"))?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| "Не удалось запустить загрузчик.".to_owned())?;
                let pair = if download {
                    runtime
                        .block_on(store.refresh(&rules))
                        .map_err(|e| format!("GeoData: {e:?}"))?
                } else {
                    store
                        .load(&rules)
                        .map_err(|e| format!("GeoData: {e:?}"))?
                        .ok_or("Загруженных баз нет.")?
                };
                let path = directory.to_str().ok_or("Путь не UTF-8.")?.to_owned();
                Ok((path, pair.manifest().clone()))
            };
            let _ = tx.send(work());
        });
    }
    // true keeps the draft open; false returns to the workspace.
    fn key(&mut self, key: KeyEvent, editor: Option<&mut Editor>) -> bool {
        if self.download.is_some() {
            return true;
        }
        if let Some((index, fields, focus)) = &mut self.fields {
            match key.code {
                KeyCode::Esc => {
                    self.fields = None;
                }
                KeyCode::Up | KeyCode::BackTab => *focus = focus.saturating_sub(1),
                KeyCode::Down | KeyCode::Tab => *focus = (*focus + 1).min(3),
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    fields[*focus].clear()
                }
                KeyCode::Left | KeyCode::Right if *focus == 1 => {
                    let options = crate::routing::Action::ALL.map(crate::routing::Action::name);
                    let index = options.iter().position(|a| *a == fields[1]).unwrap_or(0);
                    let next = if key.code == KeyCode::Right {
                        (index + 1) % options.len()
                    } else {
                        (index + options.len() - 1) % options.len()
                    };
                    fields[1] = options[next].into();
                }
                KeyCode::Backspace => {
                    fields[*focus].pop();
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && !c.is_control()
                        && fields[*focus].len() + c.len_utf8() <= 8192 =>
                {
                    fields[*focus].push(c)
                }
                KeyCode::Enter => {
                    let Some(action) = crate::routing::Action::from_name(fields[1].trim()) else {
                        self.message = "Выберите действие стрелками влево или вправо.".into();
                        return true;
                    };
                    let split = |s: &str| {
                        s.split(|c: char| c == ',' || c.is_whitespace())
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    };
                    let rule = crate::routing::Rule {
                        name: fields[0].trim().into(),
                        action,
                        domains: split(&fields[2]),
                        ips: split(&fields[3]),
                    };
                    if crate::routing::Policy::validate_rules(std::slice::from_ref(&rule)).is_err()
                    {
                        self.message = "Правило не прошло проверку.".into();
                        return true;
                    }
                    if let Some(i) = *index {
                        self.settings.rules[i] = rule;
                        self.selected = i;
                    } else if self.settings.rules.len() < 1024 {
                        self.settings.rules.push(rule);
                        self.selected = self.settings.rules.len() - 1;
                    }
                    self.fields = None;
                    self.message.clear();
                }
                _ => {}
            }
            return true;
        }
        let len = self.settings.rules.len();
        match key.code {
            KeyCode::Esc => return false,
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => self.selected = (self.selected + 1).min(len.saturating_sub(1)),
            KeyCode::Char('n') if len < 1024 => self.edit(None),
            KeyCode::Enter if self.selected < len => self.edit(Some(self.selected)),
            KeyCode::Delete if self.selected < len => {
                self.settings.rules.remove(self.selected);
                self.selected = self
                    .selected
                    .min(self.settings.rules.len().saturating_sub(1));
            }
            KeyCode::Char('[') if self.selected > 0 && self.selected < len => {
                self.settings.rules.swap(self.selected, self.selected - 1);
                self.selected -= 1;
            }
            KeyCode::Char(']') if self.selected + 1 < len => {
                self.settings.rules.swap(self.selected, self.selected + 1);
                self.selected += 1;
            }
            KeyCode::Char('g') => self.refresh(true),
            KeyCode::Char('l') => self.refresh(false),
            KeyCode::Char('s') => {
                if let Some(editor) = editor {
                    match editor.stage_routing(self.settings.clone()) {
                        Ok(()) => return false,
                        Err(e) => self.message = e.into(),
                    }
                }
            }
            _ => {}
        }
        true
    }
    fn body(&self) -> String {
        let mut body = String::new();
        if let Some((_, fields, focus)) = &self.fields {
            for (i, (label, value)) in ["Имя", "Действие", "Домены / GeoSite", "IP / CIDR / GeoIP"]
                .iter()
                .zip(fields)
                .enumerate()
            {
                let value = if i == 1 {
                    Self::action_label(value)
                } else {
                    value.as_str()
                };
                body.push_str(&format!(
                    "{} {label}: {value}\n",
                    if i == *focus { "›" } else { " " }
                ));
            }
            body.push_str("\nПримеры: domain:example.org, geosite:google\nIP: 192.0.2.0/24, geoip:private · через запятую\nGeoIP Lite: in-ru, in-cn, in-ir — региональные наборы, не геолокация\n\n↑↓ / Tab: поле · ←→: действие · Ctrl+U: очистить\nEnter: принять правило · Esc: отменить");
        } else {
            body.push_str(&format!(
                "GeoData: {} (GeoSite Standard + GeoIP Lite)\nПравила проверяются сверху вниз. Без совпадения — через сервер.\n",
                self.settings
                    .datasets
                    .as_ref()
                    .map_or("не выбраны", |m| m.release.as_str())
            ));
            let start = self.selected.saturating_sub(3);
            for (i, rule) in self.settings.rules.iter().enumerate().skip(start).take(7) {
                body.push_str(&format!(
                    "{} {}. {} · {}\n",
                    if i == self.selected { "›" } else { " " },
                    i + 1,
                    rule.name,
                    Self::action_label(Self::action_name(rule.action))
                ));
            }
            if self.settings.rules.is_empty() {
                body.push_str("Нет правил.\n");
            }
            body.push_str("\n↑↓ выбрать · n создать · Enter изменить · Delete удалить\n[ / ] переместить · g загрузить XTLS · l выбрать загруженные базы\ns принять черновик · Esc отменить");
        }
        if !self.message.is_empty() {
            body.push_str(&format!("\n\n{}", self.message));
        }
        body
    }
}

struct RoutingObservation {
    digest: [u8; 32],
    pending: Option<
        mpsc::Receiver<Result<crate::management::StatusReply, crate::management::ManagementError>>,
    >,
    report: String,
    observed: Option<std::time::Instant>,
    next: std::time::Instant,
}
impl RoutingObservation {
    fn new(digest: [u8; 32]) -> Self {
        Self {
            digest,
            pending: None,
            report: String::new(),
            observed: None,
            next: std::time::Instant::now(),
        }
    }
    fn refresh(&mut self) {
        if self.pending.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        let _worker = std::thread::spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| crate::management::ManagementError::Io)
                .and_then(|rt| {
                    rt.block_on(crate::management::query_client_environment(
                        crate::management::StatusCommand::ClientStatus,
                    ))
                });
            let _ = tx.send(result);
        });
    }
    fn poll(&mut self) {
        if let Some(rx) = &self.pending {
            match rx.try_recv() {
                Ok(Ok(crate::management::StatusReply::ClientRunning {
                    config_sha256,
                    routing_revision,
                    routing_state,
                    routing_totals,
                    ..
                })) if config_sha256 == self.digest => {
                    let status = match routing_state {
                        1 => format!("Правила актуальны · ревизия {routing_revision}"),
                        2 => format!("Внимание: правила просрочены · ревизия {routing_revision}\nНовые соединения заблокированы до успешной проверки"),
                        3 => "Синхронизация выполняется".into(),
                        _ => "Правила ещё не подтверждены".into(),
                    };
                    self.report = format!("Источник: защищённый IPC фонового клиента\n{status}\n{}\nСчётчики всего процесса, не отдельного профиля; полезные TCP/UDP-байты.", crate::traffic::routing_summary_from(*routing_totals));
                    self.observed = Some(std::time::Instant::now());
                }
                Err(TryRecvError::Empty) => return,
                _ => {
                    self.report = "Состояние фонового клиента с этим TOML не подтверждено. Проверьте запуск и настройки IPC.".into();
                    self.observed = None;
                }
            }
            self.pending = None;
            self.next = std::time::Instant::now() + Duration::from_secs(3);
        }
        if std::time::Instant::now() >= self.next {
            self.refresh();
        }
    }
    fn body(&self) -> String {
        if self.report.is_empty() {
            return "Проверяем состояние клиента…".into();
        }
        match self.observed {
            Some(time) => format!(
                "{}\nСнимок получен {} с назад{}",
                self.report,
                time.elapsed().as_secs(),
                if time.elapsed() > Duration::from_secs(6) {
                    " (устарел)"
                } else {
                    ""
                }
            ),
            None => self.report.clone(),
        }
    }
}

struct Interaction {
    workspace_page: usize,
    workspace_focus: WorkspaceFocus,
    workspace_action: usize,
    workspace_user: usize,
    workspace_advanced: bool,
    proxy_permission_pending: bool,
    value_preview: bool,
    preview_text: Option<String>,
    modal_action: usize,
    confirm_selected: bool,
    last_apply: Option<([u8; 32], &'static str, u64)>,
    viewport: Viewport,
    welcome_choice: usize,
    editor: Option<Editor>,
    menu: Option<Menu>,
    config_dialog: Option<ConfigDialog>,
    server_process: ProcessPanel,
    show_server_process: bool,
    traffic_monitor: Option<crate::traffic::Monitor>,
    workspace_monitor: Option<crate::traffic::Monitor>,
    client_background: Option<StatusPanel>,
    issuance: Option<IssueFlow>,
    issue_kind: IssueKind,
    revocation: Option<DisableFlow>,
    importing: Option<ImportFlow>,
    import_browser: Option<FileBrowser>,
    qr_scan: Option<QrScan>,
    records: Option<RecordFlow>,
    routing_panel: Option<RoutingPanel>,
    routing_observation: Option<RoutingObservation>,
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
            workspace_advanced: false,
            proxy_permission_pending: false,
            value_preview: false,
            preview_text: None,
            modal_action: 0,
            confirm_selected: false,
            last_apply: None,
            viewport: Viewport::default(),
            welcome_choice: 0,
            editor,
            menu: None,
            config_dialog: None,
            server_process: ProcessPanel::new(),
            show_server_process: false,
            traffic_monitor: None,
            workspace_monitor: None,
            client_background: None,
            issuance: None,
            issue_kind: IssueKind::NewUser,
            revocation: None,
            importing: None,
            import_browser: None,
            qr_scan: None,
            records: None,
            routing_panel: None,
            routing_observation: None,
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
        if let Some(panel) = self.routing_panel.as_mut() {
            panel.paste(text);
            return;
        }
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
    fn paste_workspace_import(&mut self, model: &Model, text: &str) {
        // Only the visible client import section may begin a new draft.
        // A paste on Help/Home or another role must not begin an import.
        if Self::panel_role(model) == Some(Role::Client)
            && self.workspace_page == 2
            && self.workspace_focus == WorkspaceFocus::Actions
            && self.workspace_visible()
        {
            if let Some(editor) = self.editor.as_mut().filter(|e| e.role() == Role::Client) {
                if editor.dirty() || editor.write_uncertain() {
                    editor.error = Some("Сохраните или отмените черновик перед импортом.".into());
                    return;
                }
                self.importing = Some(ImportFlow::Input(Zeroizing::new(String::new())));
            }
        }
        self.paste_import_source(text);
    }

    fn paste_import_source(&mut self, text: &str) {
        if self.import_browser.is_some() {
            return;
        }
        let input = text.trim_end_matches(['\r', '\n']);
        if let Some(ImportFlow::Input(source)) = self.importing.as_mut() {
            let error = if input.chars().any(char::is_control) {
                Some("Ввод содержит недопустимые символы. Вставьте ключ целиком.")
            } else if source.len().saturating_add(input.len()) > crate::invite::MAX_URI {
                Some("Ключ слишком длинный. Вставьте его целиком или запросите новый.")
            } else {
                None
            };
            if error.is_some() {
                *source = Zeroizing::new(String::new());
            } else {
                source.push_str(input);
            }
            if let Some(editor) = self.editor.as_mut() {
                editor.error = error.map(str::to_owned);
            }
            return;
        }
        if input.chars().any(char::is_control) {
            return;
        }
        match self.importing.as_mut() {
            Some(ImportFlow::Trust { ca, .. }) if ca.len().saturating_add(input.len()) <= 1024 => {
                ca.push_str(input)
            }
            Some(ImportFlow::Credential { reference, .. })
                if reference.len().saturating_add(input.len()) <= 1024 =>
            {
                reference.push_str(input)
            }
            _ => {}
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
                if std::mem::take(&mut self.proxy_permission_pending) {
                    #[cfg(windows)]
                    if saved {
                        if let Some(editor) = self.editor.as_mut() {
                            match crate::tui_system_proxy::Panel::open(
                                editor.saved_path().to_owned(),
                                editor.saved_sha256(),
                            ) {
                                Ok(panel) => {
                                    self.system_proxy = Some(panel);
                                    self.modal_action = 0;
                                }
                                Err(message) => editor.error = Some(message.into()),
                            }
                        }
                    }
                }
                if matches!(self.issuance, Some(IssueFlow::Saving)) {
                    self.modal_action = 0;
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
                if matches!(self.importing, Some(ImportFlow::Activating)) {
                    if saved {
                        self.importing = None;
                        self.client_background = None;
                        self.workspace_page = 3;
                        self.workspace_action = 0;
                        self.workspace_focus = WorkspaceFocus::Actions;
                    } else {
                        self.importing = Some(ImportFlow::ActivationFailed);
                    }
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
        if role == Role::Server {
            self.server_process.running()
        } else {
            self.client_background
                .as_ref()
                .is_some_and(StatusPanel::local_running)
                || self
                    .reality_status
                    .as_ref()
                    .is_some_and(StatusPanel::local_running)
        }
    }

    fn visible_workspace_action(&self, role: Role) -> usize {
        if self.workspace_page == 0 {
            return 0;
        }
        let count = page_actions_for(
            role,
            self.workspace_page,
            self.editor_for(role),
            self.workspace_user,
            self.workspace_advanced,
        )
        .len();
        self.workspace_action.min(count.saturating_sub(1))
    }

    fn follow_recommendation(&mut self, role: Role) {
        let Some(editor) = self.editor_for(role) else {
            return;
        };
        let (key, _) = recommended_step(editor, self.owned_running(role));
        let (page, key) = recommendation_page(role, key);
        let user = if role == Role::Server && key == 'b' {
            editor
                .workspace_users()
                .iter()
                .position(|(_, disabled, granted)| *disabled && *granted)
        } else {
            None
        };
        let action = page_actions_for(
            role,
            page,
            Some(editor),
            user.unwrap_or(self.workspace_user),
            false,
        )
        .iter()
        .position(|item| item.key == key)
        .unwrap_or(0);
        self.select_workspace_page(role, page);
        if let Some(user) = user {
            self.workspace_user = user;
        }
        self.workspace_action = action;
        self.workspace_focus = WorkspaceFocus::Actions;
    }

    fn select_workspace_page(&mut self, role: Role, page: usize) {
        self.workspace_page = page.min(pages(role).len() - 1);
        self.routing_observation = None;
        self.workspace_monitor = if self.workspace_page == 4 {
            Some(crate::traffic::Monitor::new(role))
        } else {
            None
        };
        self.workspace_action = 0;
        self.workspace_advanced = false;
        self.workspace_focus = WorkspaceFocus::Navigation;
    }

    fn workspace_content_focus(&self, role: Role) -> WorkspaceFocus {
        match (role, self.workspace_page) {
            (_, 1) => WorkspaceFocus::Fields,
            (Role::Server, 2) => WorkspaceFocus::Users,
            _ => WorkspaceFocus::Actions,
        }
    }

    /// Spatial navigation for the workspace. The left column contains sections
    /// above records; editable rows and actions live on the right. Every arrow
    /// moves selection only, including at boundaries. Compact mode presents
    /// the same focus areas one at a time.
    fn workspace_arrow(&mut self, role: Role, code: KeyCode) -> bool {
        let detail = self.workspace_content_focus(role);
        let count = self.editor_for(role).map_or(0, Editor::record_count);
        let record = self.editor_for(role).map_or(0, Editor::workspace_selected);
        let fields = self.editor_for(role).map_or(0, Editor::field_count);
        let field = self
            .editor_for(role)
            .map_or(0, Editor::workspace_field_index);
        let users = self
            .editor_for(role)
            .map_or(0, |e| e.workspace_users().len());
        let action_count = page_actions_for(
            role,
            self.workspace_page,
            self.editor_for(role),
            self.workspace_user,
            self.workspace_advanced,
        )
        .len();
        self.workspace_action = self.workspace_action.min(action_count.saturating_sub(1));
        let from_detail = if count > 0 && page_has_records(role, self.workspace_page) {
            WorkspaceFocus::Records
        } else {
            WorkspaceFocus::Navigation
        };
        if self.workspace_focus == WorkspaceFocus::Fields && detail != WorkspaceFocus::Fields {
            self.workspace_focus = detail;
            if self.workspace_page == 0 {
                self.workspace_action = 0;
            }
        }
        match (self.workspace_focus, code) {
            (WorkspaceFocus::Navigation, KeyCode::Up) => {
                self.select_workspace_page(role, self.workspace_page.saturating_sub(1));
            }
            (WorkspaceFocus::Navigation, KeyCode::Down) => {
                if self.workspace_page + 1 < pages(role).len() {
                    self.select_workspace_page(role, self.workspace_page + 1);
                }
            }
            (WorkspaceFocus::Navigation, KeyCode::Right) => {
                self.workspace_focus = if page_has_records(role, self.workspace_page) && count > 0 {
                    WorkspaceFocus::Records
                } else {
                    detail
                };
            }
            (WorkspaceFocus::Records, KeyCode::Up) if record == 0 => {
                self.workspace_focus = WorkspaceFocus::Navigation;
            }
            (WorkspaceFocus::Records, KeyCode::Up | KeyCode::Down) => {
                let index = if code == KeyCode::Up {
                    record.saturating_sub(1)
                } else {
                    (record + 1).min(count.saturating_sub(1))
                };
                if index != record {
                    if let Some(editor) = self.editor.as_mut() {
                        editor.workspace_select(index);
                    }
                    self.workspace_user = 0;
                    self.workspace_action = 0;
                }
            }
            (WorkspaceFocus::Records, KeyCode::Left) => {
                self.workspace_focus = WorkspaceFocus::Navigation
            }
            (WorkspaceFocus::Records, KeyCode::Right | KeyCode::Enter) => {
                self.workspace_focus = detail
            }
            (
                WorkspaceFocus::Fields | WorkspaceFocus::Users | WorkspaceFocus::Actions,
                KeyCode::Left,
            ) => {
                self.workspace_focus = from_detail;
            }
            (WorkspaceFocus::Fields, KeyCode::Down) if field + 1 >= fields && action_count > 0 => {
                self.workspace_focus = WorkspaceFocus::Actions;
                self.workspace_action = 0;
            }
            (WorkspaceFocus::Fields, KeyCode::Up | KeyCode::Down) => {
                let index = if code == KeyCode::Up {
                    field.saturating_sub(1)
                } else {
                    (field + 1).min(fields.saturating_sub(1))
                };
                if let Some(editor) = self.editor.as_mut() {
                    if index != field {
                        editor.workspace_select_field(index);
                    }
                }
            }
            (WorkspaceFocus::Users, KeyCode::Down)
                if self.workspace_user + 1 >= users && action_count > 0 =>
            {
                self.workspace_focus = WorkspaceFocus::Actions;
                self.workspace_action = 0;
            }
            (WorkspaceFocus::Users, KeyCode::Up | KeyCode::Down) => {
                self.workspace_user = if code == KeyCode::Up {
                    self.workspace_user.saturating_sub(1)
                } else {
                    (self.workspace_user + 1).min(users.saturating_sub(1))
                };
                self.workspace_action = 0;
            }
            (WorkspaceFocus::Actions, KeyCode::Up)
                if self.workspace_action == 0 && detail != WorkspaceFocus::Actions =>
            {
                self.workspace_focus = detail;
                if detail == WorkspaceFocus::Fields {
                    if let Some(editor) = self.editor.as_mut() {
                        editor.workspace_select_field(fields.saturating_sub(1));
                    }
                } else {
                    self.workspace_user = users.saturating_sub(1);
                }
            }
            (WorkspaceFocus::Actions, KeyCode::Up) => {
                self.workspace_action = self.workspace_action.saturating_sub(1)
            }
            (WorkspaceFocus::Actions, KeyCode::Down) => {
                self.workspace_action =
                    (self.workspace_action + 1).min(action_count.saturating_sub(1));
            }
            // There is no selectable area beyond the right edge.
            (_, KeyCode::Left | KeyCode::Right) => {}
            _ => return false,
        }
        true
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
            .is_some_and(|e| e.dirty() && !(e.write_uncertain() && e.role() == role))
        {
            if let Some(editor) = self.editor.as_mut() {
                editor.error =
                    Some("Сначала сохраните или отмените черновик в текущей панели.".into());
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
        // An uncertain save cannot be retried. Opening a file explicitly
        // re-reads it using the normal loader; the old editor is kept until
        // a successful load. No materials or original file are removed.
        self.config_dialog = Some(ConfigDialog::new(
            role,
            self.editor_for(role).map(Editor::saved_path),
        ));
    }

    fn poll_navigation(&mut self, model: &mut Model) {
        if let Some(panel) = self.routing_panel.as_mut() {
            panel.poll();
        }
        if model.screen == Screen::Client && self.workspace_page == 6 {
            if let Some(editor) = self.editor.as_ref().filter(|e| e.role() == Role::Client) {
                let digest = editor.saved_sha256();
                let observation = self
                    .routing_observation
                    .get_or_insert_with(|| RoutingObservation::new(digest));
                if observation.digest != digest {
                    *observation = RoutingObservation::new(digest);
                }
                observation.poll();
            }
        }
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
        let previous_process_status = self.server_process.status();
        self.server_process.poll();
        if self.server_process.status() != previous_process_status {
            self.last_apply = None;
        }
        if let Some(monitor) = self.traffic_monitor.as_mut() {
            monitor.poll();
        }
        if let Some(monitor) = self.workspace_monitor.as_mut() {
            monitor.poll();
        }
        if let Some(background) = self.client_background.as_mut() {
            background.poll();
        }
        if let Some(dialog) = self.config_dialog.as_mut() {
            if let Some(editor) = dialog.poll() {
                if dialog.imported() {
                    self.importing = Some(ImportFlow::Done);
                } else if dialog.import_after_load() {
                    self.importing = Some(ImportFlow::Input(Zeroizing::new(String::new())));
                }
                let keep_success = dialog.reality_succeeded();
                self.editor = Some(editor);
                if !keep_success {
                    self.config_dialog = None;
                }
                self.menu = None;
                self.workspace_page = if self
                    .editor
                    .as_ref()
                    .is_some_and(|e| e.role() == Role::Client)
                {
                    3
                } else {
                    0
                };
                self.workspace_focus = WorkspaceFocus::Actions;
                self.workspace_action = 0;
                self.last_apply = None;
            }
        }
    }

    /// Mouse interaction is confined to harmless selection and navigation.
    /// No click is translated into a save, Apply, start, reveal or confirmation.
    /// Only explicit workflow states can offer a confirmation.
    fn confirmation_choice(&self) -> Option<(char, &'static str)> {
        if self.value_preview
            || self.saving.is_some()
            || self.exporting.is_some()
            || self.sharing.is_some()
            || self.clipboard.is_some()
            || self.qr_scan.is_some()
            || self.import_browser.is_some()
            || self.menu.is_some()
        {
            return None;
        }
        if let Some(p) = &self.config_dialog {
            return p.confirmation_choice();
        }
        if self.show_server_process {
            return self.server_process.confirmation().map(|start| {
                (
                    'y',
                    if start {
                        "Запустить"
                    } else {
                        "Остановить"
                    },
                )
            });
        }
        #[cfg(windows)]
        if let Some(p) = &self.system_proxy {
            return p.confirmation_choice();
        }
        if let Some(p) = &self.reality_status {
            return p.confirmation_choice();
        }
        if let Some(p) = &self.reality_registration {
            return p.confirmation_choice();
        }
        if let Some(p) = &self.reality_enrollment {
            return p.confirmation_choice();
        }
        if let Some(p) = &self.reality_provision {
            return p.confirmation_choice();
        }
        if let Some(p) = &self.runtime {
            return p.confirmation_choice();
        }
        if let Some(p) = &self.domain {
            return if p.is_dns_confirming() {
                Some(('y', "Разрешить DNS"))
            } else if p.is_probe_confirming() {
                Some(('y', "Проверить адреса"))
            } else {
                None
            };
        }
        if let Some(p) = &self.candidate_batch {
            return p.is_confirming().then_some(('y', "Начать проверку"));
        }
        if let Some(p) = &self.candidates {
            return p.is_confirming().then_some(('y', "Подтвердить область"));
        }
        if let Some(p) = &self.probe {
            return p.is_consent_pending().then_some(('y', "Начать проверку"));
        }
        if let Some(p) = &self.discovery {
            return p.is_consent_pending().then_some(('y', "Разрешить запрос"));
        }
        if let Some(flow) = &self.records {
            return match flow {
                RecordFlow::Confirm(review) => Some(('y', review.confirmation_label())),
                _ => None,
            };
        }
        if let Some(flow) = &self.issuance {
            return match flow {
                IssueFlow::Confirm(_) => Some((
                    'y',
                    match self.issue_kind {
                        IssueKind::NewUser => "Создать пользователя и ключ",
                        IssueKind::Rotation => "Заменить ключ",
                        IssueKind::Reenable => "Восстановить доступ",
                    },
                )),
                IssueFlow::ConfirmReveal => Some(('y', "Показать ссылку")),
                IssueFlow::ConfirmExport => Some(('y', "Экспортировать")),
                IssueFlow::ShareConfirm { .. } => Some(('y', "Подтвердить передачу")),
                _ => None,
            };
        }
        if let Some(flow) = &self.revocation {
            return matches!(flow, DisableFlow::Confirm(_)).then_some(('y', "Отключить доступ"));
        }
        if let Some(flow) = &self.importing {
            return match flow {
                ImportFlow::Preview {
                    invitation,
                    ca: Some(_),
                    public_ref,
                } if invitation.has_token() || public_ref.is_some() => {
                    Some(('y', "Сохранить профиль"))
                }
                ImportFlow::RefreshConfirm(_) => Some(('y', "Сохранить ключ")),
                ImportFlow::ActivateConfirm => Some(('y', "Выбрать профиль")),
                _ => None,
            };
        }
        None
    }

    fn diagnostic_actions(&self) -> Vec<ActionItem> {
        if let Some(p) = &self.domain {
            return p.report_actions();
        }
        if let Some(p) = &self.candidate_batch {
            return p.report_actions();
        }
        if let Some(p) = &self.candidates {
            return p.report_actions();
        }
        if let Some(p) = &self.probe {
            return p.report_actions();
        }
        if let Some(p) = &self.discovery {
            return p.report_actions();
        }
        Vec::new()
    }

    fn active_form(&self) -> Option<Form> {
        if let Some(browser) = &self.import_browser {
            return Some(browser.form());
        }
        if let Some(d) = &self.config_dialog {
            return d.form();
        }
        if let Some(p) = &self.reality_provision {
            return p.form();
        }
        if let Some(p) = &self.reality_enrollment {
            return p.form();
        }
        if let Some(p) = &self.reality_registration {
            return p.form();
        }
        if let Some(p) = &self.domain {
            return p.form();
        }
        if let Some(p) = &self.candidate_batch {
            return p.form();
        }
        if let Some(f) = &self.records {
            return f.form(self.editor.as_ref());
        }
        None
    }

    fn inline_import(&self) -> bool {
        self.workspace_page == 2
            && self.editor_for(Role::Client).is_some()
            && matches!(self.importing, Some(ImportFlow::Input(_)))
            && self.import_browser.is_none()
            && self.qr_scan.is_none()
            && self.config_dialog.is_none()
            && self.reality_enrollment.is_none()
            && !self.value_preview
    }

    fn workspace_visible(&self) -> bool {
        let clear = !self.value_preview
            && self.menu.is_none()
            && self.config_dialog.is_none()
            && !self.show_server_process
            && self.traffic_monitor.is_none()
            && self.issuance.is_none()
            && self.revocation.is_none()
            && self.importing.is_none()
            && self.qr_scan.is_none()
            && self.records.is_none()
            && self.routing_panel.is_none()
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
        if self.routing_panel.is_some() {
            return;
        }
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
        if self.confirmation_choice().is_some() {
            if let Some(rect) = self.viewport.confirm_rect.get() {
                if event.row == rect.bottom().saturating_sub(1)
                    && event.column >= rect.x
                    && event.column < rect.right()
                {
                    self.confirm_selected = event.column >= rect.x + rect.width / 2;
                }
            }
            return;
        }
        if self.pending.is_some() && self.saving.is_none() {
            let items = dirty_transition_actions();
            if let Some([_, controls]) =
                report_action_layout(body, items.len(), DIRTY_TRANSITION_TEXT)
            {
                if let Some(index) = (Actions {
                    items: &items,
                    selected: self.modal_action,
                })
                .hit(controls, event.column, event.row)
                {
                    self.modal_action = index;
                }
            }
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
            if let Some([_, rect]) =
                report_action_layout(body, items.len(), &self.server_process.summary())
            {
                let actions = Actions {
                    items: &items,
                    selected: self.server_process.action_focus(),
                };
                if let Some(index) = actions.hit(rect, event.column, event.row) {
                    self.server_process.select_action(index);
                }
            }
            return;
        }
        if let Some(panel) = self.reality_status.as_mut() {
            let items = panel.actions();
            if let Some([_, rect]) = report_action_layout(body, items.len(), &panel.summary()) {
                let actions = Actions {
                    items: &items,
                    selected: panel.action_focus(),
                };
                if let Some(index) = actions.hit(rect, event.column, event.row) {
                    panel.select_action(index);
                }
            }
            return;
        }
        if let Some(browser) = self.import_browser.as_mut() {
            let form = browser.form();
            if let Some(id) = form.hit(
                guided_form_area(body, form.fields.len()),
                event.column,
                event.row,
            ) {
                browser.select_field(id);
            }
            return;
        }
        if let Some(dialog) = self.config_dialog.as_mut() {
            if let Some(form) = dialog.form() {
                let target = if dialog.guide().is_some() {
                    guided_form_area(body, form.fields.len())
                } else {
                    centered_column(body, 108)
                };
                if let Some(id) = form.hit(target, event.column, event.row) {
                    dialog.select_field(id);
                }
            }
            return;
        }
        if let Some(runtime) = self.runtime.as_ref() {
            let items = runtime.actions();
            if let Some([_, controls]) = report_action_layout(body, items.len(), &runtime.body()) {
                if let Some(i) = (Actions {
                    items: &items,
                    selected: self.modal_action,
                })
                .hit(controls, event.column, event.row)
                {
                    self.modal_action = i;
                }
            }
            return;
        }
        #[cfg(windows)]
        if let Some(proxy) = self.system_proxy.as_ref() {
            let items = proxy.actions();
            if let Some([_, controls]) = report_action_layout(body, items.len(), &proxy.body()) {
                if let Some(i) = (Actions {
                    items: &items,
                    selected: self.modal_action,
                })
                .hit(controls, event.column, event.row)
                {
                    self.modal_action = i;
                }
            }
            return;
        }
        let diagnostic_items = self.diagnostic_actions();
        if !diagnostic_items.is_empty() {
            if let Some(controls) = self.viewport.action_rect.get() {
                if let Some(index) = (Actions {
                    items: &diagnostic_items,
                    selected: self.modal_action,
                })
                .hit(controls, event.column, event.row)
                {
                    self.modal_action = index;
                }
            }
            return;
        }
        if let Some(domain) = self.domain.as_mut() {
            if let Some(form) = domain.form() {
                if let Some(i) = form.hit(
                    guided_form_area(body, form.fields.len()),
                    event.column,
                    event.row,
                ) {
                    domain.select_field(i);
                }
            }
            return;
        }
        if let Some(batch) = self.candidate_batch.as_mut() {
            if let Some(form) = batch.form() {
                if let Some(i) = form.hit(
                    guided_form_area(body, form.fields.len()),
                    event.column,
                    event.row,
                ) {
                    batch.select_field(i);
                }
            }
            return;
        }
        if let Some(panel) = self.reality_registration.as_mut() {
            if let Some(form) = panel.form() {
                if let Some(id) = form.hit(
                    guided_form_area(body, form.fields.len()),
                    event.column,
                    event.row,
                ) {
                    panel.select_field(id);
                }
            }
            return;
        }
        if let Some(panel) = self.reality_provision.as_mut() {
            if let Some(form) = panel.form() {
                if let Some(id) = form.hit(
                    guided_form_area(body, form.fields.len()),
                    event.column,
                    event.row,
                ) {
                    panel.select_field(id);
                }
            }
            return;
        }
        if let Some(panel) = self.reality_enrollment.as_mut() {
            if let Some(form) = panel.form() {
                if let Some(id) = form.hit(
                    guided_form_area(body, form.fields.len()),
                    event.column,
                    event.row,
                ) {
                    panel.select_field(id);
                }
            }
            return;
        }
        if let Some(flow) = self.records.as_mut() {
            if let Some(form) = flow.form(self.editor.as_ref()) {
                if let Some(id) = form.hit(
                    guided_form_area(body, form.fields.len()),
                    event.column,
                    event.row,
                ) {
                    flow.select_field(id);
                }
            }
            return;
        }
        if let Some(flow) = self.issuance.as_ref() {
            let items = issuance_actions(flow, self.editor.as_ref());
            if let Some(controls) = self
                .viewport
                .action_rect
                .get()
                .filter(|r| r.bottom() <= body.bottom())
            {
                if let Some(index) = (Actions {
                    items: &items,
                    selected: self.modal_action,
                })
                .hit(controls, event.column, event.row)
                {
                    self.modal_action = index;
                }
                return;
            }
        }
        if matches!(self.revocation, Some(DisableFlow::SaveFailed)) {
            let items = save_failure_actions(self.editor.as_ref());
            if let Some(controls) = self.viewport.action_rect.get() {
                if let Some(index) = (Actions {
                    items: &items,
                    selected: self.modal_action,
                })
                .hit(controls, event.column, event.row)
                {
                    self.modal_action = index;
                }
            }
            return;
        }
        if let Some(IssueFlow::Input(id)) = self.issuance.as_mut() {
            if self.issue_kind != IssueKind::NewUser {
                let disabled = self.issue_kind == IssueKind::Reenable;
                if let Some(form) = user_picker(self.editor.as_ref(), id, disabled) {
                    if let Some(index) = form.hit(
                        guided_form_area(body, form.fields.len()),
                        event.column,
                        event.row,
                    ) {
                        if let Some(field) = form.fields.get(index) {
                            *id = field.value.clone();
                        }
                    }
                }
            }
            return;
        }
        if let Some(DisableFlow::Input(id)) = self.revocation.as_mut() {
            if let Some(form) = user_picker(self.editor.as_ref(), id, false) {
                if let Some(index) = form.hit(
                    guided_form_area(body, form.fields.len()),
                    event.column,
                    event.row,
                ) {
                    if let Some(field) = form.fields.get(index) {
                        *id = field.value.clone();
                    }
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
            if self.workspace_focus == WorkspaceFocus::Records {
                if inside(body) && event.row > body.y && event.row < body.bottom().saturating_sub(1)
                {
                    if let Some(editor) = self.editor.as_mut().filter(|e| e.role() == role) {
                        if let Some((index, _)) =
                            record_rows(editor, body).get(usize::from(event.row - body.y - 1))
                        {
                            editor.workspace_select(*index);
                            self.workspace_user = 0;
                        }
                    }
                    self.workspace_action = 0;
                }
                return;
            }
            if self.workspace_focus == WorkspaceFocus::Navigation {
                if event.row > body.y && event.row < body.bottom().saturating_sub(1) {
                    let i = usize::from(event.row - body.y - 1);
                    if i < pages(role).len() {
                        self.select_workspace_page(role, i);
                    }
                }
                return;
            }
            let items = page_actions_for(
                role,
                self.workspace_page,
                self.editor_for(role),
                self.workspace_user,
                self.workspace_advanced,
            );
            let controls = page_layout_for(
                body,
                role,
                self.workspace_page,
                self.editor_for(role),
                self.workspace_user,
                self.workspace_advanced,
            )
            .map(|p| p[1])
            .unwrap_or(if self.workspace_focus == WorkspaceFocus::Actions {
                body
            } else {
                Rect::default()
            });
            if let Some(i) = (Actions {
                items: &items,
                selected: self.visible_workspace_action(role),
            })
            .hit(controls, event.column, event.row)
            {
                self.workspace_action = i;
                self.workspace_focus = WorkspaceFocus::Actions;
                return;
            }
            if self.workspace_focus == WorkspaceFocus::Actions && controls == body {
                return;
            }
            if let Some(editor) = self.editor.as_mut().filter(|e| e.role() == role) {
                let content = page_layout_for(
                    body,
                    role,
                    self.workspace_page,
                    Some(editor),
                    self.workspace_user,
                    self.workspace_advanced,
                )
                .map(|p| p[0])
                .unwrap_or(body);
                if role == Role::Client && self.workspace_page == 2 && inside(content) {
                    self.workspace_focus = WorkspaceFocus::Actions;
                    self.workspace_action = 0;
                    return;
                }
                if self.workspace_page == 1 {
                    if let Some(id) = editor_field_hit(content, editor, event.column, event.row) {
                        editor.workspace_select_field(id);
                        self.workspace_focus = WorkspaceFocus::Fields;
                    }
                } else if page_has_users(role, self.workspace_page)
                    && inside(content)
                    && event.row >= content.y + 2
                    && event.row < content.bottom().saturating_sub(1)
                {
                    let users = editor.workspace_users();
                    let i = user_table_start(self.workspace_user, users.len(), content)
                        + usize::from(event.row - content.y - 2);
                    if i < users.len() {
                        self.workspace_user = i;
                        self.workspace_action = 0;
                        self.workspace_focus = WorkspaceFocus::Users;
                    }
                }
            }
            return;
        };
        let nav = columns[0];
        if inside(nav) && event.row > nav.y && event.row < nav.bottom().saturating_sub(1) {
            let index = usize::from(event.row - nav.y - 1);
            if index < pages(role).len() {
                self.select_workspace_page(role, index);
            }
            return;
        }
        let records = columns[1];
        if page_has_records(role, self.workspace_page)
            && inside(records)
            && event.row > records.y
            && event.row < records.bottom().saturating_sub(1)
        {
            if let Some(editor) = self.editor.as_mut().filter(|e| e.role() == role) {
                if let Some((index, _)) =
                    record_rows(editor, records).get(usize::from(event.row - records.y - 1))
                {
                    editor.workspace_select(*index);
                    self.workspace_user = 0;
                }
            }
            self.workspace_action = 0;
            self.workspace_focus = WorkspaceFocus::Records;
            return;
        }
        let visible_action = self.visible_workspace_action(role);
        if let Some(editor) = self.editor.as_mut().filter(|e| e.role() == role) {
            if let Some([content, controls]) = page_layout_for(
                columns[2],
                role,
                self.workspace_page,
                Some(editor),
                self.workspace_user,
                self.workspace_advanced,
            )
            .or_else(|| {
                (self.workspace_focus == WorkspaceFocus::Actions)
                    .then_some([Rect::default(), columns[2]])
            }) {
                let items = page_actions_for(
                    role,
                    self.workspace_page,
                    Some(editor),
                    self.workspace_user,
                    self.workspace_advanced,
                );
                if let Some(i) = (Actions {
                    items: &items,
                    selected: visible_action,
                })
                .hit(controls, event.column, event.row)
                {
                    self.workspace_action = i;
                    self.workspace_focus = WorkspaceFocus::Actions;
                    return;
                }
                if role == Role::Client && self.workspace_page == 2 && inside(content) {
                    self.workspace_focus = WorkspaceFocus::Actions;
                    self.workspace_action = 0;
                    return;
                }
                if page_has_users(role, self.workspace_page)
                    && inside(content)
                    && event.row >= content.y + 2
                {
                    let users = editor.workspace_users();
                    let start = user_table_start(self.workspace_user, users.len(), content);
                    let i = start + usize::from(event.row - content.y - 2);
                    if i < users.len() && event.row < content.bottom().saturating_sub(1) {
                        self.workspace_user = i;
                        self.workspace_action = 0;
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
            if self.workspace_page == 1 {
                if let Some(id) = editor_field_hit(columns[2], editor, event.column, event.row) {
                    editor.workspace_select_field(id);
                    self.workspace_focus = WorkspaceFocus::Fields;
                }
            }
        }
    }

    fn after_reality_success(&mut self, first_user: Option<String>) {
        self.workspace_page = 2;
        self.workspace_focus = WorkspaceFocus::Users;
        self.workspace_action = 0;
        if let Some(editor) = self.editor.as_mut() {
            if editor.role() == Role::Server && !editor.dirty() && !editor.write_uncertain() {
                if let Some(id) = first_user.filter(|id| eligible_users(editor, true).contains(id))
                {
                    editor.error = None;
                    self.issue_kind = IssueKind::Reenable;
                    self.issuance = Some(IssueFlow::Input(id));
                }
            }
        }
    }

    fn update(&mut self, model: &mut Model, mut key: KeyEvent) -> bool {
        if key.kind == KeyEventKind::Press
            && (key.modifiers == KeyModifiers::SHIFT
                || (key.modifiers.is_empty()
                    && (self
                        .reality_provision
                        .as_ref()
                        .and_then(|p| p.guide())
                        .or_else(|| self.config_dialog.as_ref().and_then(|d| d.guide()))
                        .is_some_and(|g| {
                            matches!(
                                g.2,
                                "Полный отчёт" | "Полный список целей" | "Точные адреса проверки"
                            )
                        }))))
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
        if let Some(mut panel) = self.routing_panel.take() {
            if panel.key(key, self.editor.as_mut()) {
                self.routing_panel = Some(panel);
            }
            return false;
        }
        // Cancel is the safe default. Selection never executes an operation.
        if let Some((confirm, _)) = self.confirmation_choice() {
            if key.modifiers.is_empty() {
                match key.code {
                    KeyCode::Left | KeyCode::Home => {
                        self.confirm_selected = false;
                        return false;
                    }
                    KeyCode::Right | KeyCode::End => {
                        self.confirm_selected = true;
                        return false;
                    }
                    KeyCode::Enter => {
                        key.code = KeyCode::Char(if self.confirm_selected { confirm } else { 'n' });
                    }
                    _ => {}
                }
            }
        }
        self.confirm_selected = false;
        if self.value_preview {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::F(7)) {
                self.value_preview = false;
                self.preview_text = None;
            }
            return false;
        }
        if key.code == KeyCode::F(7) {
            if let Some(form) = self.active_form() {
                let text = if !form.error.is_empty() {
                    format!("Ошибка: {}", form.error)
                } else if let Some(field) = form.fields.iter().find(|f| f.id == form.selected) {
                    format!("{}\n\n{}\n\n{}", field.label, field.value, field.hint)
                } else {
                    String::new()
                };
                if !text.is_empty() {
                    self.preview_text = Some(text);
                    self.value_preview = true;
                    return false;
                }
            }
            if let Some(error) = Self::panel_role(model)
                .and_then(|role| self.editor_for(role))
                .and_then(|e| e.error.as_ref())
            {
                self.preview_text = Some(format!("Ошибка: {error}"));
                self.value_preview = true;
                return false;
            }
        }
        if let Some(scan) = self.qr_scan.as_mut() {
            if key.code == KeyCode::Esc {
                scan.cancelled = true;
            }
            return false;
        }
        if let Some(dialog) = self.config_dialog.as_mut() {
            let next = dialog.reality_succeeded()
                && key.code == KeyCode::Char('y')
                && key.modifiers.is_empty();
            let first_user = dialog.reality_success_first_user().map(str::to_owned);
            if dialog.key(key) {
                self.config_dialog = None;
                if next {
                    self.after_reality_success(first_user);
                }
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
            let items = proxy.actions();
            let code = if key.modifiers.is_empty() {
                tui_widgets::action_key(&items, &mut self.modal_action, key.code)
            } else {
                Some(key.code)
            };
            let Some(code) = code else {
                return false;
            };
            if proxy.key(KeyEvent { code, ..key }) {
                self.system_proxy = None;
                self.modal_action = 0;
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
                if self.editor_for(Role::Client).is_some() {
                    self.workspace_focus = WorkspaceFocus::Navigation;
                } else {
                    self.menu = Some(Menu::new(Role::Client, false));
                }
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
            let next =
                panel.succeeded() && key.code == KeyCode::Char('y') && key.modifiers.is_empty();
            let first_user = panel.success_first_user().map(str::to_owned);
            if panel.key(key) {
                self.reality_provision = None;
                if next {
                    self.after_reality_success(first_user);
                }
            }
            return false;
        }
        if let Some(runtime) = self.runtime.as_mut() {
            let items = runtime.actions();
            let code = if key.modifiers.is_empty() {
                tui_widgets::action_key(&items, &mut self.modal_action, key.code)
            } else {
                Some(key.code)
            };
            let Some(code) = code else {
                return false;
            };
            if runtime.key(KeyEvent { code, ..key }) {
                self.runtime = None;
                self.modal_action = 0;
            }
            return false;
        }
        let diagnostic_items = self.diagnostic_actions();
        if !diagnostic_items.is_empty() && key.modifiers.is_empty() {
            let Some(code) =
                tui_widgets::action_key(&diagnostic_items, &mut self.modal_action, key.code)
            else {
                return false;
            };
            key.code = code;
            self.modal_action = 0;
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
            if role == Some(Role::Client)
                && key.code == KeyCode::Char('P')
                && self.editor_for(Role::Client).is_some()
            {
                self.select_workspace_page(Role::Client, 3);
                self.workspace_focus = WorkspaceFocus::Actions;
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
                                if role == Role::Client && self.welcome_choice == 1 {
                                    dialog.begin_client_import();
                                } else {
                                    dialog.prefer_mode(self.welcome_choice);
                                }
                            }
                            return false;
                        }
                        _ => {}
                    }
                }
                if configured && self.workspace_visible() {
                    self.workspace_page = self.workspace_page.min(pages(role).len() - 1);
                    if key.modifiers.is_empty()
                        && matches!(
                            key.code,
                            KeyCode::Left
                                | KeyCode::Right
                                | KeyCode::Up
                                | KeyCode::Down
                                | KeyCode::Enter
                        )
                        && (matches!(
                            key.code,
                            KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down
                        ) || self.workspace_focus == WorkspaceFocus::Records)
                        && self.workspace_arrow(role, key.code)
                    {
                        return false;
                    }
                    // A connection is the scope of user rights and invitations. The
                    // same shortcut works in every server workspace, even when
                    // the sidebar is hidden on a compact terminal.
                    if page_has_records(role, self.workspace_page)
                        && key.modifiers.is_empty()
                        && matches!(key.code, KeyCode::Char('j' | 'k'))
                    {
                        if let Some(editor) = self.editor.as_mut() {
                            editor.select_record(key.code == KeyCode::Char('j'));
                        }
                        self.workspace_user = 0;
                        self.workspace_action = 0;
                        return false;
                    }
                    if key.code == KeyCode::F(7) && self.workspace_focus == WorkspaceFocus::Records
                    {
                        if let Some(editor) = self.editor_for(role) {
                            let id = editor.selected_record_id();
                            self.preview_text = Some(
                                editor
                                    .client_profile_label(id)
                                    .unwrap_or_else(|| id.to_owned()),
                            );
                            self.value_preview = true;
                        }
                        return false;
                    }
                    if key.code == KeyCode::F(7) && self.workspace_page == 1 {
                        self.value_preview = true;
                        return false;
                    }
                    if role == Role::Client
                        && self.workspace_page == 2
                        && matches!(
                            self.workspace_focus,
                            WorkspaceFocus::Actions | WorkspaceFocus::Fields
                        )
                        && key.code == KeyCode::F(6)
                    {
                        // The visible input owns the file shortcut. No parsing,
                        // network or save is started merely by opening the picker.
                        self.update(model, KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE));
                        if self.importing.is_some() {
                            self.update(model, key);
                        }
                        return false;
                    }
                    if key.code == KeyCode::F(6) {
                        if self.workspace_page == 0
                            && self.workspace_focus == WorkspaceFocus::Fields
                        {
                            self.workspace_action = 0;
                        }
                        self.workspace_focus = match self.workspace_focus {
                            WorkspaceFocus::Fields | WorkspaceFocus::Users => {
                                WorkspaceFocus::Actions
                            }
                            WorkspaceFocus::Actions => WorkspaceFocus::Navigation,
                            WorkspaceFocus::Records => self.workspace_content_focus(role),
                            WorkspaceFocus::Navigation => {
                                if page_has_users(role, self.workspace_page) {
                                    WorkspaceFocus::Users
                                } else {
                                    WorkspaceFocus::Fields
                                }
                            }
                        };
                        return false;
                    }
                    if key.modifiers == KeyModifiers::ALT
                        && matches!(key.code, KeyCode::Left | KeyCode::Right)
                    {
                        let n = pages(role).len();
                        let page = (self.workspace_page
                            + if key.code == KeyCode::Right { 1 } else { n - 1 })
                            % n;
                        self.select_workspace_page(role, page);
                        return false;
                    }
                    if self.workspace_focus == WorkspaceFocus::Records {
                        match key.code {
                            KeyCode::Tab => {
                                self.workspace_focus = self.workspace_content_focus(role);
                                return false;
                            }
                            KeyCode::BackTab => {
                                self.workspace_focus = WorkspaceFocus::Navigation;
                                return false;
                            }
                            _ => {}
                        }
                    }
                    if self.workspace_focus == WorkspaceFocus::Navigation {
                        match key.code {
                            KeyCode::Up | KeyCode::Down => {
                                let n = pages(role).len();
                                let page = (self.workspace_page
                                    + if key.code == KeyCode::Down { 1 } else { n - 1 })
                                    % n;
                                self.select_workspace_page(role, page);
                                return false;
                            }
                            KeyCode::Enter | KeyCode::Tab => {
                                self.workspace_focus = if page_has_users(role, self.workspace_page)
                                {
                                    WorkspaceFocus::Users
                                } else if self.workspace_page == 1 {
                                    if self.editor_for(role).is_some_and(|e| e.record_count() > 0) {
                                        WorkspaceFocus::Records
                                    } else {
                                        WorkspaceFocus::Fields
                                    }
                                } else {
                                    WorkspaceFocus::Actions
                                };
                                return false;
                            }
                            KeyCode::BackTab => {
                                self.workspace_focus = WorkspaceFocus::Actions;
                                return false;
                            }
                            _ => {}
                        }
                    }
                    if page_has_users(role, self.workspace_page)
                        && matches!(
                            self.workspace_focus,
                            WorkspaceFocus::Fields | WorkspaceFocus::Users
                        )
                    {
                        let count = self
                            .editor_for(role)
                            .map_or(0, |e| e.workspace_users().len());
                        self.workspace_focus = WorkspaceFocus::Users;
                        match key.code {
                            KeyCode::Up | KeyCode::Down if count > 0 => {
                                self.workspace_user = (self.workspace_user.min(count - 1)
                                    + if key.code == KeyCode::Down {
                                        1
                                    } else {
                                        count - 1
                                    })
                                    % count;
                                return false;
                            }
                            KeyCode::Tab | KeyCode::Enter => {
                                self.workspace_focus = WorkspaceFocus::Actions;
                                return false;
                            }
                            KeyCode::BackTab => {
                                self.workspace_focus = WorkspaceFocus::Navigation;
                                return false;
                            }
                            _ => {}
                        }
                    }
                    if self.workspace_focus == WorkspaceFocus::Actions {
                        let items = page_actions_for(
                            role,
                            self.workspace_page,
                            self.editor_for(role),
                            self.workspace_user,
                            self.workspace_advanced,
                        );
                        self.workspace_action =
                            self.workspace_action.min(items.len().saturating_sub(1));
                        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
                            self.workspace_focus = if key.code == KeyCode::Tab {
                                WorkspaceFocus::Navigation
                            } else if page_has_users(role, self.workspace_page) {
                                WorkspaceFocus::Users
                            } else {
                                WorkspaceFocus::Fields
                            };
                            return false;
                        }
                        if matches!(
                            key.code,
                            KeyCode::Up
                                | KeyCode::Down
                                | KeyCode::Home
                                | KeyCode::End
                                | KeyCode::Enter
                        ) || (key.modifiers.is_empty()
                            && matches!(key.code,KeyCode::Char(ch) if items.iter().any(|item|item.key==ch)))
                        {
                            if self.workspace_page == 4 && key.code == KeyCode::Enter {
                                self.traffic_monitor = Some(crate::traffic::Monitor::new(role));
                                return false;
                            }
                            if let Some(KeyCode::Char(ch)) = tui_widgets::action_key(
                                &items,
                                &mut self.workspace_action,
                                key.code,
                            ) {
                                if ch == 'j' && role == Role::Client && self.workspace_page == 6 {
                                    if let Some(observation) = self.routing_observation.as_mut() {
                                        observation.refresh();
                                    }
                                    return false;
                                }
                                if matches!(ch, 'd' | 'u')
                                    && role == Role::Client
                                    && self.workspace_page == 6
                                {
                                    if let Some(editor) = self.editor.as_mut() {
                                        let review = if ch == 'd' {
                                            editor.review_direct_dpi_permission()
                                        } else {
                                            editor.review_direct_dpi_stun_permission()
                                        };
                                        match review {
                                            Ok(review) => {
                                                self.records =
                                                    Some(RecordFlow::Confirm(Box::new(review)));
                                                editor.error = None;
                                            }
                                            Err(message) => editor.error = Some(message.into()),
                                        }
                                    }
                                    return false;
                                }
                                if ch == 'J' && role == Role::Server && self.workspace_page == 7 {
                                    if let Some(editor) = self.editor.as_mut() {
                                        if editor.dirty() || editor.write_uncertain() {
                                            editor.error = Some(
                                                "Сначала сохраните или отмените текущие изменения."
                                                    .into(),
                                            );
                                        } else {
                                            self.routing_panel = Some(RoutingPanel::new(editor));
                                        }
                                    }
                                    return false;
                                }
                                if ch == '>' && self.workspace_page == 0 {
                                    self.follow_recommendation(role);
                                    return false;
                                }
                                let selected = if page_has_users(role, self.workspace_page) {
                                    self.editor_for(role).and_then(|e| {
                                        let users = e.workspace_users();
                                        users
                                            .get(
                                                self.workspace_user
                                                    .min(users.len().saturating_sub(1)),
                                            )
                                            .map(|u| u.0.clone())
                                    })
                                } else if role == Role::Server
                                    && key.code == KeyCode::Enter
                                    && matches!(ch, 'b' | 'x' | 't')
                                {
                                    self.editor_for(role).and_then(|e| {
                                        let users = eligible_users(e, ch == 'b');
                                        (users.len() == 1).then(|| users[0].clone())
                                    })
                                } else {
                                    None
                                };
                                if ch == 'z' && self.workspace_page == 1 {
                                    self.workspace_advanced = !self.workspace_advanced;
                                    self.workspace_action = page_actions_for(
                                        role,
                                        self.workspace_page,
                                        self.editor_for(role),
                                        self.workspace_user,
                                        self.workspace_advanced,
                                    )
                                    .iter()
                                    .position(|a| a.key == 'z')
                                    .unwrap_or(0);
                                    return false;
                                }
                                if ch == 'L' && role == Role::Client {
                                    self.workspace_focus = WorkspaceFocus::Records;
                                    return false;
                                }
                                self.workspace_focus = WorkspaceFocus::Fields;
                                let command = match ch {
                                    'a' if role == Role::Server => {
                                        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL)
                                    }
                                    '4' => KeyEvent::new(KeyCode::F(4), KeyModifiers::NONE),
                                    's' if role == Role::Server => {
                                        KeyEvent::new(KeyCode::F(5), KeyModifiers::NONE)
                                    }
                                    'o' => KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE),
                                    'S' => KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
                                    _ => KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
                                };
                                let result = self.update(model, command);
                                if let Some(id) = selected {
                                    if ch == 'x' {
                                        if let Some(DisableFlow::Input(value)) =
                                            self.revocation.as_mut()
                                        {
                                            *value = id.clone();
                                        }
                                    }
                                    if ch == 'U' {
                                        if let Some(RecordFlow::Input {
                                            action: RecordAction::DeleteUser,
                                            fields,
                                            ..
                                        }) = self.records.as_mut()
                                        {
                                            if let Some(value) = fields.first_mut() {
                                                *value = id.clone();
                                            }
                                        }
                                    }
                                    if matches!(ch, 'b' | 't') {
                                        if let Some(IssueFlow::Input(value)) =
                                            self.issuance.as_mut()
                                        {
                                            *value = id;
                                        }
                                    }
                                }
                                return result;
                            }
                            return false;
                        }
                    }
                    if self.workspace_page == 1 && self.workspace_focus == WorkspaceFocus::Fields {
                        let index = self
                            .editor_for(role)
                            .map_or(0, Editor::workspace_field_index);
                        let count = self.editor_for(role).map_or(0, Editor::field_count);
                        if key.code == KeyCode::Tab && index + 1 >= count {
                            self.workspace_focus = WorkspaceFocus::Actions;
                            return false;
                        }
                        if key.code == KeyCode::BackTab && index == 0 {
                            self.workspace_focus = WorkspaceFocus::Navigation;
                            return false;
                        }
                    }
                    if self.workspace_page != 1
                        && !page_has_users(role, self.workspace_page)
                        && self.workspace_focus == WorkspaceFocus::Fields
                        && !page_actions_for(
                            role,
                            self.workspace_page,
                            self.editor_for(role),
                            self.workspace_user,
                            self.workspace_advanced,
                        )
                        .is_empty()
                        && key.modifiers.is_empty()
                        && matches!(key.code, KeyCode::Enter | KeyCode::Up | KeyCode::Down)
                    {
                        if self.workspace_page == 0 {
                            self.workspace_action = 0;
                        }
                        self.workspace_focus = WorkspaceFocus::Actions;
                        // Open the selected workflow, not its confirmation.
                        return self.update(model, key);
                    }
                    if self.workspace_page != 1
                        && matches!(key.code, KeyCode::Enter | KeyCode::Tab | KeyCode::BackTab)
                    {
                        if self.workspace_page == 0
                            && self.workspace_focus == WorkspaceFocus::Fields
                        {
                            self.workspace_action = 0;
                        }
                        self.workspace_focus = if key.code == KeyCode::BackTab {
                            WorkspaceFocus::Navigation
                        } else {
                            WorkspaceFocus::Actions
                        };
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
                    if configured {
                        self.workspace_focus = WorkspaceFocus::Navigation;
                    } else {
                        self.menu = Some(Menu::new(role, false));
                    }
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
            if model.screen == Screen::Client && matches!(key.code, KeyCode::Char('i' | 'I')) {
                self.open_config(Role::Client);
                if let Some(dialog) = self.config_dialog.as_mut() {
                    dialog.begin_client_import();
                }
                return false;
            }
            if model.screen == Screen::Server && key.code == KeyCode::Char('W') {
                self.open_config(Role::Server);
                if let Some(dialog) = self.config_dialog.as_mut() {
                    dialog.prefer_reality();
                }
                return false;
            }
            if model.screen == Screen::Server && key.code == KeyCode::Char('w') {
                self.reality_provision = Some(ProvisionPanel::new());
                return false;
            }
            if model.screen == Screen::Server && key.code == KeyCode::Char('R') {
                self.runtime = Some(if self.server_process.running() {
                    RuntimePanel::open_restart_at(self.server_process.management_endpoint())
                } else {
                    RuntimePanel::open_restart()
                });
                return false;
            }
            if model.screen == Screen::Server && key.code == KeyCode::Char('v') {
                self.runtime = Some(if self.server_process.running() {
                    RuntimePanel::open_at(self.server_process.management_endpoint(), None, false)
                } else {
                    RuntimePanel::open(None, false)
                });
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
                } else {
                    key.code
                } {
                    KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => {
                        let next = if matches!(key.code, KeyCode::Down | KeyCode::Tab) {
                            1
                        } else {
                            0
                        };
                        self.records = Some(RecordFlow::ChooseMode(role, next));
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
                    KeyCode::Char('2') => {
                        self.workspace_page = 2;
                        self.workspace_focus = WorkspaceFocus::Actions;
                        self.workspace_action = 0;
                    }
                    KeyCode::Esc => {}
                    _ => self.records = Some(RecordFlow::ChooseMode(role, selected)),
                },
                RecordFlow::GrantPicker {
                    mut selected,
                    mut focus,
                } => {
                    let users = editor.workspace_users();
                    focus = focus.min(users.len().saturating_sub(1));
                    match key.code {
                        KeyCode::Esc => {
                            editor.error = None;
                            return false;
                        }
                        KeyCode::Up | KeyCode::BackTab if !users.is_empty() => {
                            focus = (focus + users.len() - 1) % users.len();
                        }
                        KeyCode::Down | KeyCode::Tab if !users.is_empty() => {
                            focus = (focus + 1) % users.len();
                        }
                        KeyCode::Char(' ') if key.modifiers.is_empty() => {
                            if let Some((id, _, _)) = users.get(focus) {
                                if let Some(i) = selected.iter().position(|value| value == id) {
                                    selected.remove(i);
                                } else {
                                    selected.push(id.clone());
                                }
                                editor.error = None;
                            }
                        }
                        KeyCode::Enter => {
                            if selected.is_empty() {
                                editor.error = Some("Нужен хотя бы один пользователь. Глобальное отключение доступно отдельно и действует на все подключения.".into());
                            } else {
                                match editor
                                    .review_record(RecordAction::SetGrants, &[selected.join(",")])
                                {
                                    Ok(review) => {
                                        editor.error = None;
                                        self.records = Some(RecordFlow::Confirm(Box::new(review)));
                                        return false;
                                    }
                                    Err(message) => editor.error = Some(message.into()),
                                }
                            }
                        }
                        _ => {}
                    }
                    self.records = Some(RecordFlow::GrantPicker { selected, focus });
                }
                RecordFlow::Confirm(review) => match key.code {
                    KeyCode::Char('y') if key.modifiers.is_empty() => {
                        match editor.stage_record(*review) {
                            Ok(()) => self.start_save(),
                            Err(message) => {
                                self.proxy_permission_pending = false;
                                editor.error = Some(message.into());
                            }
                        }
                    }
                    KeyCode::Esc | KeyCode::Char('n') => {
                        self.proxy_permission_pending = false;
                    }
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
            let items = issuance_actions(&flow, Some(editor));
            let code = if key.modifiers.is_empty() {
                tui_widgets::action_key(&items, &mut self.modal_action, key.code)
            } else {
                Some(key.code)
            };
            let Some(code) = code else {
                self.issuance = Some(flow);
                return false;
            };
            let key = KeyEvent { code, ..key };
            if !items.is_empty() {
                self.modal_action = 0;
            }
            match flow {
                IssueFlow::Input(id)
                    if self.issue_kind != IssueKind::NewUser
                        && eligible_users(editor, self.issue_kind == IssueKind::Reenable)
                            .is_empty() =>
                {
                    if key.code != KeyCode::Esc {
                        self.issuance = Some(IssueFlow::Input(id));
                    }
                }
                IssueFlow::Input(mut id) => match key.code {
                    KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab
                        if self.issue_kind != IssueKind::NewUser =>
                    {
                        id = cycle_user(
                            editor,
                            &id,
                            self.issue_kind == IssueKind::Reenable,
                            matches!(key.code, KeyCode::Down | KeyCode::Tab),
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
                    KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                        editor.error = None;
                        self.issuance = Some(IssueFlow::Input(String::new()));
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
                    KeyCode::Char('v' | 'y') => self.issuance = Some(IssueFlow::ConfirmReveal),
                    KeyCode::Char('n') | KeyCode::Esc => editor.clear_issued(),
                    _ => self.issuance = Some(IssueFlow::Offer),
                },
                IssueFlow::ConfirmReveal => match key.code {
                    KeyCode::Char('y') if key.modifiers.is_empty() => {
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
                    KeyCode::Char('n') | KeyCode::Esc => self.issuance = Some(IssueFlow::Offer),
                    _ => self.issuance = Some(IssueFlow::ConfirmReveal),
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
            let items = if matches!(flow, DisableFlow::SaveFailed) {
                save_failure_actions(Some(editor))
            } else {
                Vec::new()
            };
            let Some(code) = (if key.modifiers.is_empty() {
                tui_widgets::action_key(&items, &mut self.modal_action, key.code)
            } else {
                Some(key.code)
            }) else {
                self.revocation = Some(flow);
                return false;
            };
            let key = KeyEvent { code, ..key };
            if !items.is_empty() {
                self.modal_action = 0;
            }
            match flow {
                DisableFlow::Input(id) if eligible_users(editor, false).is_empty() => {
                    if key.code != KeyCode::Esc {
                        self.revocation = Some(DisableFlow::Input(id));
                    }
                }
                DisableFlow::Input(mut id) => match key.code {
                    KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => {
                        id = cycle_user(
                            editor,
                            &id,
                            false,
                            matches!(key.code, KeyCode::Down | KeyCode::Tab),
                        );
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

        if let Some(browser) = self.import_browser.as_mut() {
            if key.code == KeyCode::Esc {
                self.import_browser = None;
                return false;
            }
            if let Some(path) = browser.key(key.code, "") {
                if let Some(path) = path.to_str().filter(|s| !s.chars().any(char::is_control)) {
                    match self.importing.as_mut() {
                        Some(ImportFlow::Input(source)) if path.len() <= crate::invite::MAX_URI => {
                            *source = Zeroizing::new(path.to_owned());
                            editor.error = None;
                        }
                        Some(ImportFlow::Trust { ca, .. }) if path.len() <= 1019 => {
                            *ca = format!("file:{path}");
                            editor.error = None;
                        }
                        _ => {
                            editor.error =
                                Some("Путь слишком длинный. Выберите другой файл.".into())
                        }
                    }
                }
                self.import_browser = None;
            }
            return false;
        }
        if let Some(flow) = self.importing.take() {
            match flow {
                ImportFlow::Input(mut source) => match key.code {
                    KeyCode::F(6) => {
                        self.import_browser = Some(FileBrowser::files(source.as_str()));
                        self.importing = Some(ImportFlow::Input(source));
                    }
                    KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                        self.importing = Some(ImportFlow::Input(Zeroizing::new(String::new())));
                        editor.error = None;
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
                        KeyCode::Enter if ca.is_none() => {
                            self.importing = Some(ImportFlow::Trust {
                                invitation,
                                ca: String::new(),
                                public_ref,
                            });
                        }
                        KeyCode::Enter if !invitation.has_token() && public_ref.is_none() => {
                            self.importing = Some(ImportFlow::Credential {
                                invitation,
                                ca,
                                reference: String::new(),
                            });
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
                        KeyCode::Char('y') if key.modifiers.is_empty() => {
                            if ca.is_none() {
                                editor.error = Some("Сначала подтвердите доверенный сертификат. Enter или c — выбрать.".into());
                                self.importing = Some(ImportFlow::Preview {
                                    invitation,
                                    ca,
                                    public_ref,
                                });
                            } else if !invitation.has_token() && public_ref.is_none() {
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
                    KeyCode::F(6) => {
                        self.import_browser =
                            Some(FileBrowser::files(ca.strip_prefix("file:").unwrap_or(&ca)));
                        self.importing = Some(ImportFlow::Trust {
                            invitation,
                            ca,
                            public_ref,
                        });
                    }
                    KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                        ca.clear();
                        editor.error = None;
                        self.importing = Some(ImportFlow::Trust {
                            invitation,
                            ca,
                            public_ref,
                        });
                    }
                    KeyCode::Esc => {
                        self.importing = Some(ImportFlow::Preview {
                            invitation,
                            ca: None,
                            public_ref,
                        })
                    }
                    KeyCode::Enter => {
                        if !ca.is_empty() && !ca.starts_with("file:") {
                            ca = format!("file:{ca}");
                        }
                        let verified = client_import::checked_ca_ref(Some(&ca));
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
                                    "Не удалось проверить сертификат. Выберите через F6 доверенный PEM-файл, полученный отдельно от администратора."
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
                ImportFlow::Done => match key.code {
                    KeyCode::Enter
                        if self
                            .client_background
                            .as_ref()
                            .is_some_and(StatusPanel::local_running) =>
                    {
                        editor.error = Some("Сначала остановите текущее подключение. Esc — выйти, V — управление подключением.".into());
                        self.importing = Some(ImportFlow::Done);
                    }
                    KeyCode::Enter
                        if editor.selected_record_is_active()
                            && !editor.dirty()
                            && !editor.write_uncertain() =>
                    {
                        self.client_background = None;
                        self.workspace_page = 3;
                        self.workspace_action = 0;
                        self.workspace_focus = WorkspaceFocus::Actions;
                    }
                    KeyCode::Enter => self.importing = Some(ImportFlow::ActivateConfirm),
                    KeyCode::Esc => {
                        self.workspace_page = 3;
                        self.workspace_focus = WorkspaceFocus::Actions;
                        self.workspace_action = 0;
                    }
                    _ => self.importing = Some(ImportFlow::Done),
                },
                ImportFlow::ActivateConfirm => match key.code {
                    KeyCode::Char('y') if key.modifiers.is_empty() => {
                        match editor
                            .review_record(RecordAction::ActivateProfile, &[])
                            .and_then(|review| editor.stage_record(review))
                        {
                            Ok(()) => {
                                self.importing = Some(ImportFlow::Activating);
                                self.start_save();
                            }
                            Err(error) => {
                                editor.error = Some(error.into());
                                self.importing = Some(ImportFlow::Done);
                            }
                        }
                    }
                    KeyCode::Esc | KeyCode::Char('n') => self.importing = Some(ImportFlow::Done),
                    _ => self.importing = Some(ImportFlow::ActivateConfirm),
                },
                ImportFlow::Activating => self.importing = Some(ImportFlow::Activating),
                state @ (ImportFlow::RefreshDone
                | ImportFlow::ActivationFailed
                | ImportFlow::Failed) => {
                    if !matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                        self.importing = Some(state);
                    }
                }
            }
            return false;
        }

        if let Some(original) = self.pending {
            let items = dirty_transition_actions();
            let Some(code) = tui_widgets::action_key(&items, &mut self.modal_action, key.code)
            else {
                return false;
            };
            match code {
                KeyCode::Char('s') => {
                    self.start_save();
                    return false;
                }
                KeyCode::Char('d') => {
                    editor.discard();
                    self.pending = None;
                    return model.update(original);
                }
                KeyCode::Esc | KeyCode::Char('n') => {
                    self.pending = None;
                    self.modal_action = 0;
                }
                _ => {}
            }
            return false;
        }

        if editor.editing {
            match key.code {
                KeyCode::Left | KeyCode::Up if !editor.choice_options().is_empty() => {
                    editor.cycle_choice(false)
                }
                KeyCode::Right | KeyCode::Down | KeyCode::Char(' ')
                    if !editor.choice_options().is_empty() =>
                {
                    editor.cycle_choice(true)
                }
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
                        Some("Это подключение использует собственный TLS. Для состояния сервера откройте F5 или выберите подключение REALITY.".into());
                } else {
                    match editor.require_clean_records() {
                        Ok(()) => {
                            editor.error = None;
                            self.reality_status = Some(
                                if editor.role() == Role::Server && self.server_process.running() {
                                    StatusPanel::open_with_endpoint(
                                        editor,
                                        self.server_process.management_endpoint(),
                                    )
                                } else {
                                    StatusPanel::open(editor)
                                },
                            );
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
                    Ok(()) if editor.role() == Role::Server => {
                        self.records = Some(RecordFlow::ChooseMode(Role::Server, 1));
                    }
                    Ok(()) => match editor.record_fields(RecordAction::NewProfile) {
                        Ok(fields) => {
                            self.records = Some(RecordFlow::Input {
                                action: RecordAction::NewProfile,
                                fields,
                                focus: 0,
                            })
                        }
                        Err(message) => editor.error = Some(message.into()),
                    },
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
                    Ok(_) if matches!(action, RecordAction::SetGrants) => {
                        editor.error = None;
                        let users = editor.workspace_users();
                        let selected = users
                            .iter()
                            .filter(|(_, _, granted)| *granted)
                            .map(|(id, _, _)| id.clone())
                            .collect();
                        let focus = if self.workspace_page == 2 {
                            self.workspace_user.min(users.len().saturating_sub(1))
                        } else {
                            0
                        };
                        self.records = Some(RecordFlow::GrantPicker { selected, focus });
                    }
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
                if let Err(message) = editor.require_clean_records() {
                    editor.error = Some(message.into());
                } else if editor.write_uncertain() {
                    editor.error = Some("Откройте настройки заново.".into());
                } else if !editor.selected_record_is_active() {
                    editor.error = Some("Сначала выберите этот профиль активным (A).".into());
                } else {
                    #[cfg(windows)]
                    {
                        if !editor.system_proxy_allowed() {
                            match editor.review_system_proxy_permission() {
                                Ok(review) => {
                                    self.proxy_permission_pending = true;
                                    self.records = Some(RecordFlow::Confirm(Box::new(review)));
                                    editor.error = None;
                                }
                                Err(message) => editor.error = Some(message.into()),
                            }
                        } else {
                            match crate::tui_system_proxy::Panel::open(
                                editor.saved_path().to_owned(),
                                editor.saved_sha256(),
                            ) {
                                Ok(panel) => {
                                    self.system_proxy = Some(panel);
                                    self.modal_action = 0;
                                    editor.error = None;
                                }
                                Err(message) => editor.error = Some(message.into()),
                            }
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        editor.error = Some("Системный прокси Linux пока не реализован. Выберите локальный HTTP/SOCKS5.".into());
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
                    self.runtime = Some(if self.server_process.running() {
                        RuntimePanel::open_at(
                            self.server_process.management_endpoint(),
                            saved,
                            apply_shortcut,
                        )
                    } else {
                        RuntimePanel::open(saved, apply_shortcut)
                    });
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
                    self.runtime = Some(if self.server_process.running() {
                        RuntimePanel::open_restart_at(self.server_process.management_endpoint())
                    } else {
                        RuntimePanel::open_restart()
                    });
                    editor.error = None;
                }
                return false;
            }
            if editor.role() == Role::Server && key.code == KeyCode::Char('w') {
                if editor.dirty() {
                    editor.error = Some(
                        "Сохраните или отмените черновик перед подготовкой материалов.".into(),
                    );
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
                        self.modal_action = 0;
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
                    self.issuance = Some(IssueFlow::Input(String::new()));
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
            if editor.role() == Role::Client && matches!(key.code, KeyCode::Char('i' | 'I')) {
                if editor.dirty() {
                    editor.error = Some("Сохраните или отмените черновик перед импортом.".into());
                } else {
                    editor.error = None;
                    self.workspace_page = 2;
                    self.workspace_focus = WorkspaceFocus::Actions;
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
                } else {
                    editor.begin();
                }
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
            self.modal_action = 0;
            return false;
        }
        model.update(key)
    }
}

const DIRTY_TRANSITION_TEXT: &str =
    "Сохранить изменения перед выходом?\nРаботающий процесс не изменится.";

fn dirty_transition_actions() -> [ActionItem; 3] {
    [
        ActionItem {
            key: 'n',
            label: "Остаться в редакторе",
        },
        ActionItem {
            key: 's',
            label: "Сохранить и продолжить",
        },
        ActionItem {
            key: 'd',
            label: "Не сохранять и продолжить",
        },
    ]
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
    // Keep the roles side by side even in a narrow terminal so the
    // direction of the arrows never changes with window size.
    content.height = content.height.min(8);
    if area.height > content.height + 2 {
        content.y += 2;
    }
    let parts = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(content);
    [parts[0], parts[1]]
}

fn workspace_columns(area: Rect) -> Option<[Rect; 3]> {
    if area.width < 90 || area.height < 18 {
        return None;
    }
    let cols = Layout::horizontal([
        Constraint::Length(28),
        Constraint::Length(2),
        Constraint::Min(1),
    ])
    .split(area);
    let navigation_height = (pages(Role::Server).len().max(pages(Role::Client).len()) as u16) + 2;
    let left = Layout::vertical([Constraint::Length(navigation_height), Constraint::Min(1)])
        .split(cols[0]);
    Some([left[0], left[1], cols[2]])
}

/// Wrapped rows share the same record-index map for draw and mouse.
fn record_rows(editor: &Editor, area: Rect) -> Vec<(usize, String)> {
    let width = usize::from(area.width.saturating_sub(5)).max(1);
    let capacity = usize::from(area.height.saturating_sub(2));
    let selected = editor.workspace_selected();
    let mut rows = Vec::new();
    for (index, (id, active, reality)) in editor.workspace_records().into_iter().enumerate() {
        let label = if editor.role() == Role::Client {
            format!(
                "{}№{} {}",
                if active { "*" } else { "" },
                index + 1,
                editor.client_profile_address(&id).unwrap_or(&id)
            )
        } else {
            format!("{} · {}", id, if reality { "REALITY" } else { "TLS" })
        };
        let mut line = String::new();
        let mut used = 0;
        for ch in label.chars() {
            let mut encoded = [0; 4];
            let encoded: &str = ch.encode_utf8(&mut encoded);
            let cw = Span::raw(encoded).width();
            if used + cw > width && !line.is_empty() {
                rows.push((index, std::mem::take(&mut line)));
                used = 0;
            }
            line.push(ch);
            used += cw;
        }
        rows.push((index, line));
    }
    let first = rows.iter().position(|(i, _)| *i == selected).unwrap_or(0);
    let end = rows
        .iter()
        .rposition(|(i, _)| *i == selected)
        .map_or(first, |i| i + 1);
    let start = end
        .saturating_sub(capacity)
        .min(first)
        .min(rows.len().saturating_sub(capacity));
    rows.into_iter().skip(start).take(capacity).collect()
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
    confirmation: Cell<bool>,
    confirm_rect: Cell<Option<Rect>>,
    action_rect: Cell<Option<Rect>>,
    guided: Cell<bool>,
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
                    self.offset
                        .set(row.saturating_sub(page.saturating_sub(1)).min(max));
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
        if let Some((bar, suffix)) = line.strip_prefix('[').and_then(|s| s.split_once(']')) {
            if !bar.is_empty()
                && bar.chars().all(|ch| matches!(ch, '█' | '░'))
                && Span::raw(line).width() <= width
            {
                let filled = bar.chars().filter(|&ch| ch == '█').count();
                rows.push(Line::from(vec![
                    Span::styled("█".repeat(filled), Style::default().fg(ACCENT)),
                    Span::styled(
                        "░".repeat(bar.chars().count() - filled),
                        Style::default().fg(MUTED),
                    ),
                    Span::styled(
                        suffix,
                        Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
                    ),
                ]));
                continue;
            }
        }
        let selected = line.starts_with("> ") || line.starts_with("› ");
        let style = if selected {
            focus.get_or_insert(rows.len());
            Style::default()
                .fg(ACCENT)
                .bg(FOCUS)
                .add_modifier(Modifier::BOLD)
        } else if line.starts_with("Ошибка")
            || line.starts_with("ОТКАЗ")
            || line.starts_with("Отказ:")
        {
            Style::default().fg(ERROR).add_modifier(Modifier::BOLD)
        } else if line.starts_with("✓ ")
            || line.starts_with("ШАГ ")
            || line.starts_with("ПРЕДЛОЖЕННЫЙ ")
            || line.starts_with("ПУТЬ К TOML")
            || line.starts_with("ВЫБЕРИТЕ ")
            || line.starts_with("НАЧАЛО РАБОТЫ")
            || line.starts_with("SMARTTHEIA REALITY")
            || line.starts_with("СЕТЬ ")
            || matches!(
                line,
                "ДОСТУП"
                    | "OWN-TLS"
                    | "ПРОФИЛИ"
                    | "НАВИГАЦИЯ"
                    | "СЕРВЕР"
                    | "КЛИЕНТ"
                    | "БЕЗОПАСНОСТЬ"
            )
        {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else if line.starts_with("ВНИМАНИЕ")
            || line.starts_with("СОГЛАСИЕ НА ")
            || line.starts_with("КОНФИДЕНЦИАЛЬНО")
            || line.starts_with("СЕКРЕТ:")
        {
            Style::default().fg(WARNING).add_modifier(Modifier::BOLD)
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
                rows.push(tui_widgets::report_row(
                    &line[start..end],
                    style,
                    start == 0,
                ));
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

/// Remove only standalone legacy confirmation-key legends when the
/// explicit choices are available. Never remove substantive review content.
fn confirmation_body(body: &str) -> String {
    body.lines()
        .filter(|line| {
            let text = line.trim();
            let confirm = text.starts_with("y: ")
                || text.starts_with("Y: ")
                || text.starts_with("y ")
                || text.starts_with("Y ");
            let cancel = text.contains("n/Esc")
                || text.contains("N/Esc")
                || text.contains("n / Esc")
                || text.contains("N / Esc");
            !(confirm && cancel && !text.contains("ВНИМАНИЕ"))
        })
        .collect::<Vec<_>>()
        .join("\n")
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
    let area = if viewport.is_some() {
        centered_column(area, 132)
    } else {
        area
    };
    let confirm = viewport.is_some_and(|v| v.confirmation.get());
    let page = usize::from(area.height.saturating_sub(if confirm { 4 } else { 2 })).max(1);
    let cleaned;
    let body = if viewport.is_some_and(|v| v.confirmation.get()) {
        cleaned = confirmation_body(body);
        cleaned.as_str()
    } else {
        body
    };
    let (rows, focus) = visual_rows(body, usize::from(area.width.saturating_sub(2)));
    let count = rows.len();
    // Auto-reveal focus in typed forms only. Confirmation/review screens
    // start at their first line, including warnings, not at the confirm key.
    let focus =
        focus.filter(|_| body.contains("Tab: поле") || body.contains("Tab/Shift+Tab: поле"));
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
    let area = if viewport.is_some() {
        Rect::new(
            area.x,
            area.y,
            area.width,
            area.height.min((visible.len() as u16).saturating_add(2)),
        )
    } else {
        area
    };
    frame.render_widget(
        Paragraph::new(visible).block(tui_widgets::report_section(&caption, focused)),
        area,
    );
    if confirm {
        if let Some(v) = viewport {
            v.confirm_rect.set(Some(Rect::new(
                area.x,
                area.bottom(),
                area.width.min(72),
                2,
            )));
        }
    }
}

fn report_action_layout(area: Rect, count: usize, body: &str) -> Option<[Rect; 2]> {
    let rows = visual_rows(body, usize::from(area.width.min(132).saturating_sub(2)))
        .0
        .len();
    tui_widgets::action_layout_rows(area, count, rows)
}

fn diagnostic_report(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    body: &str,
    items: &[ActionItem],
    selected: usize,
    viewport: Option<&Viewport>,
) {
    tui_widgets::canvas(frame, area);
    if let Some([report, controls]) = report_action_layout(area, items.len(), body) {
        if let Some(v) = viewport {
            v.action_rect.set(Some(controls));
        }
        panel_at(frame, report, title, body, false, viewport);
        Actions { items, selected }.render(frame, controls);
    } else {
        panel_at(frame, area, title, body, true, viewport);
    }
}

fn panel(frame: &mut Frame<'_>, area: Rect, title: &str, body: &str, focused: bool) {
    panel_at(frame, area, title, body, focused, None);
}

/// A persistent step header and action strip separate guidance from the
/// scrollable form/review. No display-only shortcut may commit a transaction.
fn guided_layout(area: Rect, count: Option<usize>, review_rows: usize) -> [Rect; 3] {
    let mut area = centered_column(area, 108);
    let preferred = count.map_or_else(
        || review_rows.saturating_add(8).clamp(10, 40),
        |count| count.saturating_mul(3).saturating_add(10).clamp(18, 36),
    ) as u16;
    let height = area.height.min(preferred);
    area.y += u16::from(area.height > height + 1);
    area.height = height;
    if area.height < 10 {
        return [
            Rect::new(area.x, area.y, area.width, 0),
            area,
            Rect::new(area.x, area.bottom(), area.width, 0),
        ];
    }
    let footer = if area.width < 90 { 4 } else { 3 };
    let parts = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(4),
        Constraint::Length(footer),
    ])
    .split(area);
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
    if let Some(v) = viewport {
        v.guided.set(true);
    }
    if total == 1 && form.is_none() && review.is_none() {
        panel_at(frame, area, title, body, true, viewport);
        return;
    }
    tui_widgets::canvas(frame, area);
    let width = area.width.min(108).saturating_sub(4);
    let cleaned;
    let body = if viewport.is_some_and(|v| v.confirmation.get()) {
        cleaned = confirmation_body(body);
        cleaned.as_str()
    } else {
        body
    };
    let review_lines = if form.is_none() {
        Some(match &review {
            Some(review) => review.lines(width),
            None => visual_rows(body, usize::from(width)).0,
        })
    } else {
        None
    };
    let parts = guided_layout(
        area,
        form.as_ref().map(|f| f.fields.len()),
        review_lines.as_ref().map_or(0, Vec::len),
    );
    let caption = if total > 1 {
        format!("{title} · ШАГ {step}/{total}")
    } else {
        title.to_owned()
    };
    if parts[0].height > 0 && total == 1 {
        frame.render_widget(
            Paragraph::new(Line::styled(
                title,
                Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
            )),
            parts[0],
        );
    } else if parts[0].height > 0 {
        let mut segments = vec![
            Span::styled(
                format!(" {step}/{total} "),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
        ];
        for number in 1..=total {
            segments.push(Span::styled(
                if number <= step {
                    "━━━ "
                } else {
                    "─── "
                },
                Style::default().fg(if number <= step { ACCENT } else { MUTED }),
            ));
        }
        segments.push(Span::styled(
            heading,
            Style::default()
                .fg(if heading == "Подтверждение" {
                    WARNING
                } else {
                    TEXT
                })
                .add_modifier(Modifier::BOLD),
        ));
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(title, Style::default().fg(MUTED)),
                Line::from(segments),
            ])
            .style(Style::default().bg(SURFACE)),
            parts[0],
        );
    }
    if let Some(form) = form {
        let title = if parts[0].height == 0 {
            caption.as_str()
        } else if title == "Мастер REALITY"
            || matches!(heading, "Настройка сервера" | "Источники поиска")
        {
            ""
        } else {
            "Параметры"
        };
        if matches!(
            heading,
            "Выбор пользователей"
                | "Выбор пользователя"
                | "Выбор защиты"
                | "Выбор адреса"
                | "Выбор файла"
                | "Выбор локального файла"
        ) {
            form.render_picker(frame, parts[1], title);
        } else {
            form.render(frame, parts[1], title);
        }
    } else if let Some(lines) = review_lines {
        // Same width as stepper and key bar: never re-center a nested report.
        let body_area = Rect::new(
            parts[1].x.saturating_add(2),
            parts[1].y,
            parts[1].width.saturating_sub(4),
            parts[1].height,
        );
        let raw_page = usize::from(body_area.height.saturating_sub(1)).max(1);
        let count = lines.len();
        // Reserve space for a repeated heading when the remaining-candidate table
        // is longer than the viewport. The final row must remain reachable.
        let table_header =
            if review.as_ref().is_some_and(|r| r.expanded) && count > raw_page && raw_page > 1 {
                lines
                    .iter()
                    .position(|line| {
                        line.spans
                            .iter()
                            .any(|span| span.content == "Остальные проверенные сайты")
                    })
                    .and_then(|start| {
                        lines
                            .get(start + 1)
                            .filter(|line| {
                                line.spans.iter().any(|span| {
                                    span.content.starts_with("Сайт ")
                                        && span.content.contains("TLS / H2 / H3")
                                })
                            })
                            .map(|_| start + 1)
                    })
            } else {
                None
            };
        let page = raw_page - usize::from(table_header.is_some());
        let offset = viewport.map_or(0, |v| v.position(&caption, count, page, None));
        let status = if count > page {
            format!(
                "{}–{}/{} · {} или колесо",
                offset + 1,
                (offset + page).min(count),
                count,
                if matches!(
                    heading,
                    "Полный отчёт" | "Полный список целей" | "Точные адреса проверки"
                ) {
                    "PgUp/PgDn"
                } else {
                    "Shift+PgUp/PgDn"
                }
            )
        } else if parts[0].height == 0 {
            caption.clone()
        } else {
            String::new()
        };
        let sticky = table_header
            .filter(|&index| index < offset)
            .map(|index| lines[index].clone());
        let mut visible: Vec<_> = lines.into_iter().skip(offset).take(page).collect();
        if let Some(header) = sticky {
            visible.insert(0, header);
        }
        if !status.is_empty() {
            visible.push(Line::styled(status, Style::default().fg(MUTED)));
        }
        let used = (visible.len() as u16).min(body_area.height);
        frame.render_widget(
            Paragraph::new(visible).style(Style::default().fg(TEXT).bg(BG)),
            body_area,
        );
        if let Some(v) = viewport.filter(|v| v.confirmation.get()) {
            let y = (body_area.y + used).min(area.bottom().saturating_sub(2));
            v.confirm_rect
                .set(Some(Rect::new(body_area.x, y, body_area.width.min(72), 2)));
        }
    }
    if parts[2].height > 0 && !keys.is_empty() && !viewport.is_some_and(|v| v.confirmation.get()) {
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled("Следующее действие", Style::default().fg(MUTED)),
                tui_widgets::key_line(keys),
            ])
            .style(Style::default().bg(SURFACE))
            .wrap(Wrap { trim: true }),
            parts[2],
        );
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
    let confirmation = interaction.and_then(Interaction::confirmation_choice);
    if let Some(v) = viewport {
        v.confirmation.set(confirmation.is_some());
        v.confirm_rect.set(None);
        v.action_rect.set(None);
        v.guided.set(false);
    }
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
                    "Локальный прокси запущен/запускается"
                } else {
                    "Локальный прокси не запущен этой панелью"
                }
            )
        }
        _ => "THEIA  •  Локальное управление".into(),
    };
    let (brand, status) = header.split_once("  |  ").unwrap_or((header.as_str(), ""));
    let file = interaction
        .and_then(|ui| Interaction::panel_role(model).and_then(|role| ui.editor_for(role)));
    let saved = match file {
        Some(e) if e.write_uncertain() => "Файл: запись не подтверждена",
        Some(e) if e.dirty() => "Файл: не сохранён",
        Some(_) => "Файл: сохранён",
        None => "Файл: не открыт",
    };
    let applied = if model.screen == Screen::Server {
        interaction
            .and_then(|ui| ui.last_apply)
            .and_then(|(digest, kind, revision)| {
                file.filter(|e| !e.dirty() && e.saved_sha256() == digest)
                    .map(|_| format!("Последнее подтверждение: {kind}, rev {revision}"))
            })
    } else {
        None
    };
    let state = if status.is_empty() {
        String::new()
    } else if file.is_none() {
        saved.to_owned()
    } else {
        format!(
            "{saved} · {}",
            applied.unwrap_or_else(|| "Работа с этими настройками не подтверждена".into())
        )
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!(" {brand} "),
                    Style::default()
                        .fg(BG)
                        .bg(ACCENT)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  {status}"), Style::default().fg(TEXT)),
            ]),
            Line::styled(state, Style::default().fg(MUTED)),
        ])
        .style(Style::default().bg(SURFACE)),
        parts[0],
    );
    match model.screen {
        Screen::Home => {
            let cards = home_layout(parts[1]);
            if cards[0].y > parts[1].y {
                frame.render_widget(Paragraph::new("Что вы хотите сделать?").style(Style::default().fg(TEXT).add_modifier(Modifier::BOLD)),
                    Rect::new(cards[0].x + 1, parts[1].y, cards[0].width.saturating_sub(2), 1));
            }
            draw_role_card(frame, cards[0], Role::Server, model.selected == Role::Server);
            draw_role_card(frame, cards[1], Role::Client, model.selected == Role::Client);
        }
        Screen::Server | Screen::Client => {
            let role = if model.screen == Screen::Server { Role::Server } else { Role::Client };
            if interaction.is_none_or(|ui| ui.workspace_visible()
                || ui.editor_for(role).is_some_and(|e| e.editing)
                || ui.inline_import()) {
                draw_workspace(frame, parts[1], role, interaction.and_then(|ui| ui.editor_for(role)), interaction.map_or(0, |ui| ui.welcome_choice), interaction);
            }
        }
        Screen::Help => modal_panel!(
            frame,
            parts[1],
            "Справка",
            "НАЧАЛО РАБОТЫ\n← →: выбрать роль   Enter: открыть   Esc: назад\nF1: справка   q / Ctrl+C: выйти\n\nНАВИГАЦИЯ\nF2: разделы   F3: открыть файл   F4: трафик\n← →: перейти между областями   ↑ ↓: выбрать строку\nСписок профилей или подключений показывается только в связанных разделах.\nВнизу таблицы параметров или пользователей — к действиям.\nEnter: открыть или изменить выбранное поле\nTab, F6 и Alt+←/→ — дополнительные сочетания.\n\nСЕРВЕР\nN: новое подключение   W: мастер REALITY   F5: запуск и остановка\nu: новый пользователь   G: права доступа   x: отключение\nb: восстановление   t: новый токен   l: публичное приглашение\nv: состояние   Ctrl+R: предпросмотр применения прав\n\nКЛИЕНТ\ni: импорт ссылки, файла или QR   V: подключение и состояние\nN: новый профиль   A: выбрать активный профиль\n\nБЕЗОПАСНОСТЬ\nCtrl+S: сохранить файл, не менять работающий процесс.\nИзменение работающего процесса, доверия и сетевые запросы требуют отдельного подтверждения.",
            true,
        ),
    }
    if interaction.is_some_and(|ui| {
        !ui.workspace_visible()
            && !ui.inline_import()
            && (!ui.editor.as_ref().is_some_and(|e| e.editing) || ui.value_preview)
    }) {
        tui_widgets::canvas(frame, parts[1]);
    }
    if let Some(ui) = interaction.filter(|ui| ui.value_preview) {
        if let Some(text) = &ui.preview_text {
            modal_panel!(frame, parts[1], "Полное сообщение / значение", text, true);
        } else if let Some(editor) = ui.editor.as_ref() {
            let body = format!(
                "{}\n\n{}\n\nEsc: закрыть",
                editor.selection_summary(),
                editor.field_value()
            );
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
            draw_guided(
                frame,
                parts[1],
                dialog.title(),
                &dialog.body(),
                guide,
                viewport,
                (dialog.form(), dialog.reference_review()),
            );
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
        if let Some([report, controls]) =
            report_action_layout(parts[1], items.len(), &ui.server_process.summary())
        {
            modal_panel!(
                frame,
                report,
                "Состояние сервера",
                &ui.server_process.summary(),
                false
            );
            Actions {
                items: &items,
                selected: ui.server_process.action_focus(),
            }
            .render(frame, controls);
        } else if let Some(start) = ui.server_process.confirmation() {
            let body = ui.server_process.body();
            let message = body
                .rsplit_once('\n')
                .map_or(body.as_str(), |(message, _)| message);
            draw_guided(
                frame,
                parts[1],
                if start {
                    "Запуск сервера"
                } else {
                    "Остановка сервера"
                },
                message,
                (
                    1,
                    1,
                    "Подтверждение",
                    if start {
                        "y запустить · n/Esc отменить"
                    } else {
                        "y остановить · n/Esc отменить"
                    },
                ),
                viewport,
                (None, None),
            );
        } else {
            modal_panel!(
                frame,
                parts[1],
                "Сервер • запуск и остановка",
                &ui.server_process.body(),
                true
            );
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
        if let Some(start) = status.client_confirmation() {
            let body = status.body();
            let message = body
                .rsplit_once('\n')
                .map_or(body.as_str(), |(message, _)| message);
            draw_guided(
                frame,
                parts[1],
                if start {
                    "Запуск локального прокси"
                } else {
                    "Остановка локального прокси"
                },
                message,
                (
                    1,
                    1,
                    "Подтверждение",
                    if start {
                        "y запустить · n/Esc отменить"
                    } else {
                        "y остановить · n/Esc отменить"
                    },
                ),
                viewport,
                (None, None),
            );
        } else if let Some([report, controls]) =
            report_action_layout(parts[1], items.len(), &status.summary())
        {
            modal_panel!(frame, report, status.title(), &status.summary(), false);
            Actions {
                items: &items,
                selected: status.action_focus(),
            }
            .render(frame, controls);
        } else {
            modal_panel!(frame, parts[1], status.title(), &status.body(), true);
        }
    } else if let Some(registration) = interaction.and_then(|ui| ui.reality_registration.as_ref()) {
        if let Some(form) = registration.form() {
            draw_guided(
                frame,
                parts[1],
                "Регистрация материалов",
                &registration.body(),
                (
                    1,
                    2,
                    "Параметры доверия",
                    "↑↓ поле · Enter проверить · Ctrl+U очистить · Esc назад",
                ),
                viewport,
                (Some(form), None),
            );
        } else {
            modal_panel!(
                frame,
                parts[1],
                "Регистрация материалов",
                &registration.body(),
                true
            );
        }
    } else if let Some(enrollment) = interaction.and_then(|ui| ui.reality_enrollment.as_ref()) {
        draw_guided(
            frame,
            parts[1],
            "Импорт REALITY",
            &enrollment.body(),
            enrollment.guide(),
            viewport,
            (enrollment.form(), None),
        );
    } else if let Some(provision) = interaction.and_then(|ui| ui.reality_provision.as_ref()) {
        if let Some(guide) = provision.guide() {
            draw_guided(
                frame,
                parts[1],
                "Мастер REALITY",
                &provision.body(),
                guide,
                viewport,
                (provision.form(), provision.reference_review()),
            );
        } else {
            modal_panel!(frame, parts[1], "Мастер REALITY", &provision.body(), true);
        }
    } else if let Some(runtime) = interaction.and_then(|ui| ui.runtime.as_ref()) {
        tui_widgets::canvas(frame, parts[1]);
        let items = runtime.actions();
        if let Some([report, controls]) =
            report_action_layout(parts[1], items.len(), &runtime.body())
        {
            modal_panel!(frame, report, runtime.title(), &runtime.body(), false);
            Actions {
                items: &items,
                selected: interaction.map_or(0, |ui| ui.modal_action),
            }
            .render(frame, controls);
        } else {
            modal_panel!(frame, parts[1], runtime.title(), &runtime.body(), true);
        }
    } else if interaction.is_some_and(|ui| ui.saving.is_some()) {
        modal_panel!(
            frame,
            parts[1],
            "Сохранение конфигурации",
            "Проверка изменений и безопасная запись файла выполняются.\nРаботающий процесс не перезапускается.\nДождитесь результата операции.",
            true,
        );
    } else if let Some(routing) = interaction.and_then(|ui| ui.routing_panel.as_ref()) {
        modal_panel!(frame, parts[1], "Маршрутизация", &routing.body(), true);
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
                (
                    1,
                    2,
                    "Выбор защиты",
                    "↑↓ выбрать · Enter продолжить · Esc назад",
                )
            } else if matches!(flow, RecordFlow::GrantPicker { .. }) {
                (
                    1,
                    2,
                    "Выбор пользователей",
                    "↑↓ выбрать · Space изменить · Enter проверить · Esc отменить",
                )
            } else {
                (
                    1,
                    2,
                    "Параметры",
                    "↑↓ поле · Ctrl+U очистить · Enter проверить · Esc назад",
                )
            };
            let title = match flow {
                RecordFlow::Input { action, .. } => action.title(),
                RecordFlow::GrantPicker { .. } => "Права доступа",
                _ => "Настройка подключения",
            };
            draw_guided(frame, parts[1], title, &body, guide, viewport, (form, None));
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
            interaction.map_or(0, |ui| ui.modal_action),
        );
    } else if let Some(browser) = interaction.and_then(|ui| ui.import_browser.as_ref()) {
        let title = if interaction
            .is_some_and(|ui| matches!(ui.importing.as_ref(), Some(ImportFlow::Trust { .. })))
        {
            "Выбрать доверенный сертификат"
        } else {
            "Выбрать файл приглашения или QR"
        };
        draw_guided(
            frame,
            parts[1],
            title,
            "",
            (
                1,
                2,
                "Выбор файла",
                "↑↓ выбрать · Enter выбрать путь · Esc назад",
            ),
            viewport,
            (Some(browser.form()), None),
        );
    } else if let Some(flow) = interaction
        .filter(|ui| !ui.inline_import())
        .and_then(|ui| ui.importing.as_ref())
    {
        draw_import(
            frame,
            parts[1],
            flow,
            interaction.and_then(|ui| ui.editor.as_ref()),
            viewport,
        );
    } else if let Some(ui) = interaction.filter(|ui| ui.pending.is_some()) {
        tui_widgets::canvas(frame, parts[1]);
        let items = dirty_transition_actions();
        if let Some([report, controls]) =
            report_action_layout(parts[1], items.len(), DIRTY_TRANSITION_TEXT)
        {
            modal_panel!(
                frame,
                report,
                "Есть несохранённые изменения",
                DIRTY_TRANSITION_TEXT,
                false
            );
            Actions {
                items: &items,
                selected: ui.modal_action,
            }
            .render(frame, controls);
        } else {
            Actions {
                items: &items,
                selected: ui.modal_action,
            }
            .render(frame, parts[1]);
        }
    } else if let Some(domain) = interaction.and_then(|ui| ui.domain.as_ref()) {
        if let Some(form) = domain.form() {
            draw_guided(
                frame,
                parts[1],
                "Каталог TLS-референсов",
                &domain.body(),
                (
                    1,
                    2,
                    "Выбор адреса",
                    "↑↓ выбрать · Пробел отметить IP · Enter предпросмотр · Esc назад",
                ),
                viewport,
                (Some(form), None),
            );
        } else {
            diagnostic_report(
                frame,
                parts[1],
                "Каталог TLS-референсов",
                &domain.body(),
                &domain.report_actions(),
                interaction.map_or(0, |u| u.modal_action),
                viewport,
            );
        }
    } else if let Some(batch) = interaction.and_then(|ui| ui.candidate_batch.as_ref()) {
        if let Some(form) = batch.form() {
            draw_guided(
                frame,
                parts[1],
                "Проверка выбранных IP",
                &batch.body(),
                (
                    1,
                    2,
                    "Выбор адреса",
                    "↑↓ выбрать · Space отметить IP · Enter предпросмотр · Esc назад",
                ),
                viewport,
                (Some(form), None),
            );
        } else {
            diagnostic_report(
                frame,
                parts[1],
                "Проверка выбранных IP",
                &batch.body(),
                &batch.report_actions(),
                interaction.map_or(0, |u| u.modal_action),
                viewport,
            );
        }
    } else if let Some(review) = interaction.and_then(|ui| ui.candidates.as_ref()) {
        diagnostic_report(
            frame,
            parts[1],
            "Области поиска референсов (офлайн)",
            &review.body(),
            &review.report_actions(),
            interaction.map_or(0, |u| u.modal_action),
            viewport,
        );
    } else if let Some(probe) = interaction.and_then(|ui| ui.probe.as_ref()) {
        diagnostic_report(
            frame,
            parts[1],
            "TLS/H2 + QUIC/H3: только один разрешённый IP:443",
            &probe.body(),
            &probe.report_actions(),
            interaction.map_or(0, |u| u.modal_action),
            viewport,
        );
    } else if let Some(discovery) = interaction.and_then(|ui| ui.discovery.as_ref()) {
        diagnostic_report(
            frame,
            parts[1],
            "Публичный IP и план кандидатов (без сканирования)",
            &discovery.body(),
            &discovery.report_actions(),
            interaction.map_or(0, |u| u.modal_action),
            viewport,
        );
    }
    #[cfg(windows)]
    if let Some(proxy) = interaction.and_then(|ui| ui.system_proxy.as_ref()) {
        tui_widgets::canvas(frame, parts[1]);
        let items = if proxy.confirmation_choice().is_some() {
            Vec::new()
        } else {
            proxy.actions()
        };
        if let Some([report, controls]) = report_action_layout(parts[1], items.len(), &proxy.body())
        {
            modal_panel!(
                frame,
                report,
                "Системный прокси Windows",
                &proxy.body(),
                false
            );
            Actions {
                items: &items,
                selected: interaction.map_or(0, |ui| ui.modal_action),
            }
            .render(frame, controls);
        } else {
            modal_panel!(
                frame,
                parts[1],
                "Системный прокси Windows",
                &proxy.body(),
                true
            );
        }
    }
    let footer = if interaction.is_some_and(Interaction::inline_import) {
        "Enter проверить · F6 файл / QR · Ctrl+U очистить · Esc отменить"
    } else if viewport.is_some_and(|v| v.guided.get()) {
        ""
    } else if viewport.is_some_and(|v| v.action_rect.get().is_some()) {
        "↑ ↓ выбор · Enter открыть · Esc назад · Shift+PgUp/PgDn прокрутка"
    } else if interaction.is_some_and(|ui| !ui.workspace_visible()) {
        "Esc назад · Shift+PgUp/PgDn прокрутка · F7 детали"
    } else {
        match model.screen {
            Screen::Home => "← → выбор · Enter открыть · F1 помощь · q выход",
            Screen::Help => "Shift+PgUp/PgDn или колесо: прокрутка  ·  Esc назад",
            Screen::Server | Screen::Client
                if interaction.is_some_and(|ui| {
                    Interaction::panel_role(model).is_some_and(|role| ui.editor_for(role).is_none())
                }) =>
            {
                "↑ ↓ выбор · Enter открыть · Esc назад · F1 помощь"
            }
            Screen::Server | Screen::Client => match interaction.map(|ui| ui.workspace_focus) {
                Some(WorkspaceFocus::Navigation) => {
                    "↑ ↓ разделы / записи · → открыть область · Esc назад · F1 помощь"
                }
                Some(WorkspaceFocus::Records) => {
                    "↑ ↓ записи · ← разделы · → открыть · F7 полный адрес · Esc назад"
                }
                Some(WorkspaceFocus::Fields | WorkspaceFocus::Users) => {
                    "↑ ↓ строки / действия · ← список записей · Enter открыть · Esc назад"
                }
                _ => "↑ ↓ действия · ← назад к списку · Enter открыть · Esc назад · F1 помощь",
            },
        }
    };
    let active_error = interaction
        .and_then(|ui| ui.active_form())
        .map(|f| f.error)
        .filter(|s| !s.is_empty());
    let editor_error = interaction
        .and_then(|ui| Interaction::panel_role(model).and_then(|role| ui.editor_for(role)))
        .and_then(|e| e.error.as_deref());
    if let Some((_, label)) = confirmation {
        let error = active_error.as_deref().or(editor_error);
        let heading = error.map_or_else(
            || "Следующее действие · ← → выбор · Enter открыть · Esc назад".to_owned(),
            |e| format!("Ошибка: {e} · F7 детали"),
        );
        let rect = viewport
            .and_then(|v| v.confirm_rect.get())
            .filter(|r| r.bottom() <= parts[1].bottom())
            .unwrap_or(parts[2]);
        if let Some(v) = viewport {
            v.confirm_rect.set(Some(rect));
        }
        tui_widgets::confirmation_bar(
            frame,
            rect,
            &heading,
            error.is_some(),
            label,
            interaction.is_some_and(|ui| ui.confirm_selected),
        );
        if rect != parts[2] {
            if let Some(e) = error {
                frame.render_widget(
                    Paragraph::new(tui_widgets::fit_value(
                        &format!("Ошибка: {e}"),
                        parts[2].width,
                        false,
                    ))
                    .style(Style::default().fg(ERROR)),
                    parts[2],
                );
            }
        }
        return;
    }
    if let Some(error) = active_error.as_deref().or(editor_error) {
        let line = tui_widgets::fit_value(&format!("Ошибка: {error}"), parts[2].width, false);
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(line, Style::default().fg(ERROR)),
                Line::styled("F7 — полное сообщение", Style::default().fg(TEXT)),
            ])
            .style(Style::default().bg(SURFACE)),
            parts[2],
        );
        return;
    }
    frame.render_widget(
        Paragraph::new(tui_widgets::key_line(footer))
            .style(Style::default().bg(SURFACE))
            .wrap(Wrap { trim: true }),
        parts[2],
    );
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
    if users.is_empty() {
        return None;
    }
    let selected = users
        .iter()
        .position(|id| id == current)
        .unwrap_or(usize::MAX);
    Some(Form {
        fields: users.into_iter().enumerate().map(|(id, value)| Field {
            id, label: if disabled { "Отключённый пользователь" } else { "Пользователь с доступом" },
            value, hint: "Enter — проверить выбранного пользователя. Изменение требует отдельного подтверждения.",
        }).collect(),
        selected,
        lead: if selected == usize::MAX { "Выберите пользователя стрелками или мышью.".into() }
            else { format!("Выбран: {current}") },
        error: editor.error.clone().unwrap_or_default(),
    })
}

fn user_choices(editor: Option<&Editor>, current: &str, disabled: bool) -> String {
    let users = editor
        .map(|e| eligible_users(e, disabled))
        .unwrap_or_default();
    if users.is_empty() {
        return "Нет подходящих пользователей в выбранном подключении. Esc — вернуться.".into();
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
    // The workspace is painted before modal flows. Clear all of it, not
    // just the compact report, so no stale rows survive below the actions.
    tui_widgets::canvas(frame, area);
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
            draw_guided(
                frame,
                area,
                "Новый пользователь",
                "",
                (
                    1,
                    2,
                    "Доступ",
                    "Enter продолжить · Ctrl+U очистить · Esc отменить",
                ),
                viewport,
                (Some(form), None),
            );
            return;
        }
        if editor.is_some_and(|e| eligible_users(e, recovering).is_empty()) {
            let title = if recovering {
                "Восстановление доступа"
            } else {
                "Заменить личный ключ"
            };
            let message = if recovering {
                "В этом подключении нет отключённых пользователей с правом доступа.\nЕсли нужен новый ключ для включённого пользователя, выберите «Заменить ключ пользователя»."
            } else {
                "В этом подключении нет включённых пользователей с правом доступа.\nДобавьте пользователя или восстановите его доступ."
            };
            panel_at(
                frame,
                area,
                title,
                &format!("{message}\n\nEsc: вернуться"),
                true,
                viewport,
            );
            return;
        }
        if let Some(form) = user_picker(editor, id, recovering) {
            let title = if recovering {
                "Восстановление отключённого пользователя"
            } else {
                "Заменить личный ключ"
            };
            draw_guided(
                frame,
                area,
                title,
                "",
                (
                    1,
                    2,
                    "Выбор пользователя",
                    "↑↓ выбрать · Enter проверить · Esc отменить",
                ),
                viewport,
                (Some(form), None),
            );
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
                    "Восстановление доступно только отключённым пользователям с правом на это подключение. Будет создан новый ключ."
                } else if rotating {
                    "Выберите включённого пользователя с правом на это подключение. Новый ключ выдаётся один раз."
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
                "Подтверждение замены личного ключа"
            } else {
                "Подтверждение нового пользователя"
            },
            format!(
                "Пользователь: {id}\nПодключение: {}\n\n{}\n\ny: подтвердить и сохранить  n/Esc: отменить",
                editor.map_or("", |e| e.selected_record_id()),
                if recovering {
                    "ВНИМАНИЕ: доступ восстановится для всех ранее разрешённых подключений.\nБудет создан новый ключ; старый восстановить нельзя.\nЧтобы изменить работающий сервер, отдельно примените права."
                } else if rotating {
                    "ВНИМАНИЕ: новый ключ заменит старый для всех подключений пользователя.\nСтарый ключ перестанет работать для новых сеансов после отдельного применения прав.\nТекущие сеансы продолжатся. Права и состояние пользователя не изменятся."
                } else {
                    "Создать личный ключ и сохранить пользователя?\nСервер не перезапускается. После записи отдельно примените права доступа."
                }
            ),
        ),
        IssueFlow::Saving => (
            "Сохранение токена",
            "Проверка и безопасная запись файла. Конфиденциальная ссылка скрыта; runtime не меняется."
                .into(),
        ),
        IssueFlow::SaveFailed if editor.is_some_and(Editor::write_uncertain) => (
            "Состояние записи неизвестно: ссылка заблокирована",
            "Файл мог быть заменён. Ключ уничтожен; работающий сервер не обновлён. Откройте настройки заново и проверьте состояние."
                .into(),
        ),
        IssueFlow::SaveFailed => (
            "Сохранение НЕ удалось: ссылка заблокирована",
            format!(
                "{}\n\n{}",
                if recovering {
                    "Восстановление НЕ сохранено. Новый токен не показывался."
                } else if rotating {
                    "Новый ключ НЕ сохранён. Сохранённые данные старого ключа и работающий сервер не изменены."
                } else {
                    "Новый пользователь НЕ записан. Токен не показывался."
                },
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        IssueFlow::Offer => (
            "Одноразовая выдача конфиденциальной ссылки",
            if recovering {
                "Восстановление доступа сохранено в файле. Старый ключ восстановить нельзя.\nРаботающий сервер ещё не изменён. После передачи приглашения отдельно примените права доступа.\n\nКОНФИДЕНЦИАЛЬНО: передайте новую ссылку только её владельцу. После закрытия повторного показа не будет.".into()
            } else if rotating {
                "Данные нового ключа сохранены. Работающий сервер ещё не изменён.\nСтарый ключ может использоваться для новых сеансов до отдельного применения прав.\n\nКОНФИДЕНЦИАЛЬНО: новая ссылка предназначена только её владельцу. После закрытия повторного показа не будет."
                    .into()
            } else {
                "Новый пользователь сохранён в файле. Работающий сервер ещё не изменён.\nПосле передачи приглашения отдельно примените права доступа.\n\nКОНФИДЕНЦИАЛЬНО: ссылка содержит личный ключ. Не публикуйте её. После закрытия повторного показа не будет."
                    .into()
            },
        ),
        IssueFlow::ConfirmReveal => (
            "Показ конфиденциальной ссылки",
            "Ссылка содержит личный ключ доступа. Любой, кто её получит, сможет подключаться с этими правами.\nУбедитесь, что экран, терминал и его история доступны только вам.\nПосле показа повторная выдача невозможна.".into(),
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
        IssueFlow::ShareDone(message) => ("Результат передачи", format!("{message}\nEsc: закрыть. Работающий процесс не изменён.")),
        IssueFlow::ConfirmExport => (
            "Подтверждение конфиденциального экспорта",
            "Создать новый защищённый файл рядом с конфигурацией сервера? Ссылка не будет показана. Файл содержит bearer; храните и передавайте его только доверенным способом. Повторная выдача недоступна.\n\ny: сохранить  n/Esc: назад"
                .into(),
        ),
        IssueFlow::Exporting => (
            "Защищённый экспорт",
            "Создаётся новый конфиденциальный файл. Работающий процесс не обновляется.".into(),
        ),
        IssueFlow::Exported(path) => (
            "Конфиденциальный файл создан",
            format!(
                "Файл содержит bearer. Не публикуйте его.\n\n{path:?}\n\nПуть показан в кавычках. Esc: закрыть. Работающий сервер не обновлён."
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
                "Технический экспорт без доступа: это НЕ рабочий ключ подключения. Для клиента выдайте конфиденциальный ключ конкретного пользователя.\nQ: защищённый QR | c: буфер обмена | Esc: закрыть.\n\n{link}"
            ),
        ),
        IssueFlow::Showing(link) => (
            "СЕКРЕТ: ссылка подключения (однократный просмотр)",
            format!(
                "КОНФИДЕНЦИАЛЬНО. Скопируйте ссылку целиком.\nТерминал/SSH и экран должны быть доверенными.\n\n{link}\n\nEsc: скрыть и стереть из памяти.\nРаботающий процесс не перезапущен.",
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
    } else if matches!(flow, IssueFlow::Offer) {
        format!("{body}\nФайл настроек останется сохранённым даже без передачи ссылки.")
    } else {
        body
    };
    if matches!(flow, IssueFlow::Confirm(_)) {
        let message = body
            .rsplit_once("\n\n")
            .map_or(body.as_str(), |(message, _)| message);
        draw_guided(
            frame,
            area,
            title,
            message,
            (
                2,
                2,
                "Подтверждение",
                "y подтвердить и сохранить · n/Esc отменить",
            ),
            viewport,
            (None, None),
        );
        return;
    }
    let items = issuance_actions(flow, editor);
    if let Some([report, controls]) = report_action_layout(area, items.len(), &body) {
        if let Some(v) = viewport {
            v.action_rect.set(Some(controls));
        }
        panel_at(frame, report, title, &body, false, viewport);
        Actions {
            items: &items,
            selected: action_focus,
        }
        .render(frame, controls);
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
    action_focus: usize,
) {
    if let DisableFlow::Input(id) = flow {
        if editor.is_some_and(|e| eligible_users(e, false).is_empty()) {
            panel_at(frame, area, "Отключить пользователя", "В этом подключении нет включённых пользователей с правом доступа.\n\nEsc: вернуться", true, viewport);
            return;
        }
        if let Some(form) = user_picker(editor, id, false) {
            draw_guided(
                frame,
                area,
                "Отключить существующего пользователя",
                "",
                (
                    1,
                    2,
                    "Выбор пользователя",
                    "↑↓ выбрать · Enter проверить · Esc отменить",
                ),
                viewport,
                (Some(form), None),
            );
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
                "Пользователь: {id}\nВыбранное подключение: {}\n\nВНИМАНИЕ: отключение действует для всех подключений пользователя.\nКлюч и права останутся в файле. Новые сеансы будут запрещены после отдельного применения прав.\nТекущие сеансы продолжатся.\n\ny: подтвердить и сохранить  n/Esc: отменить",
                editor.map_or("", |e| e.selected_record_id())
            ),
        ),
        DisableFlow::Saving => (
            "Отзыв доступа: сохранение",
            "Проверка и безопасная запись файла. Работающий процесс не изменяется.".into(),
        ),
        DisableFlow::SaveFailed if editor.is_some_and(Editor::write_uncertain) => (
            "Отзыв доступа: состояние записи неизвестно",
            "Файл мог быть заменён. Работающий сервер не обновлён. Откройте настройки заново и проверьте состояние."
                .into(),
        ),
        DisableFlow::SaveFailed => (
            "Отзыв доступа: ошибка сохранения",
            format!(
                "Изменения НЕ сохранены. Работающий сервер не изменён.\n\n{}",
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        DisableFlow::Done => (
            "Отключение сохранено",
            "Настройки сохранены. Работающий сервер ещё не изменён.\n\nСледующий шаг: закройте это окно и выберите «Применить права доступа». После подтверждения новые подключения пользователя будут запрещены. Уже открытые туннели продолжатся.\n\nEnter/Esc: закрыть.".into(),
        ),
    };
    let body = if let DisableFlow::Input(id) = flow {
        format!("{body}\n\n{}", user_choices(editor, id, false))
    } else {
        body
    };
    if matches!(flow, DisableFlow::Confirm(_)) {
        let message = body
            .rsplit_once("\n\n")
            .map_or(body.as_str(), |(message, _)| message);
        draw_guided(
            frame,
            area,
            title,
            message,
            (
                2,
                2,
                "Подтверждение",
                "y подтвердить и сохранить · n/Esc отменить",
            ),
            viewport,
            (None, None),
        );
    } else if matches!(flow, DisableFlow::SaveFailed) {
        let items = save_failure_actions(editor);
        if let Some([report, controls]) = report_action_layout(area, items.len(), &body) {
            if let Some(v) = viewport {
                v.action_rect.set(Some(controls));
            }
            panel_at(frame, report, title, &body, false, viewport);
            Actions {
                items: &items,
                selected: action_focus,
            }
            .render(frame, controls);
        } else {
            panel_at(frame, area, title, &body, true, viewport);
        }
    } else {
        panel_at(frame, area, title, &body, true, viewport);
    }
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
        draw_guided(
            frame,
            area,
            "Импорт подключения",
            "",
            (
                1,
                5,
                "Вставить ключ",
                "Enter проверить · F6 выбрать файл · Ctrl+U очистить · Esc отменить",
            ),
            viewport,
            (Some(form), None),
        );
        return;
    }
    if let ImportFlow::Trust { ca, .. } = flow {
        let form=Form {
            fields:vec![Field {id:0,label:"Доверенный сертификат (CA)",value:if ca.is_empty(){String::new()}else{format!("Путь указан · {} символов",ca.len())},hint:"Нажмите F6 и выберите PEM-файл, полученный от администратора по доверенному каналу."}],
            selected:0,
            lead:"Сертификат подтверждает, что вы подключаетесь к нужному серверу. Получите его отдельно от приглашения. Без сертификата сохранить профиль нельзя.".into(),
            error:editor.and_then(|e|e.error.clone()).unwrap_or_default(),
        };
        draw_guided(
            frame,
            area,
            "Импорт ключа Theia",
            "",
            (
                3,
                5,
                "Проверка сертификата",
                "F6 выбрать файл · Enter проверить · Ctrl+U очистить · Esc назад",
            ),
            viewport,
            (Some(form), None),
        );
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
            "Проверка ключа · собственный TLS",
            format!(
                "Профиль: {}\nАдрес сервера: {}\nИмя сертификата: {}\nТип подключения: {}\nТранспорт: {:?}\nРежим: {:?}\nЛичный ключ: {}\nДоверенный сертификат: {}\nПолучите сертификат отдельно от приглашения.\n\nСохраняется новый профиль без подключения. Существующий профиль не заменяется.\n{}Системный прокси не изменяется.\n\nc: выбрать доверенный сертификат\n{}y: сохранить профиль  n/Esc: отменить\n\n{}",
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
                "Профиль: {}\nEndpoint: {}\nTLS SNI: {}\n\nТолько новая ссылка на защищённый bearer. CA, TLS, transport и active_profile сохраняются. Старый файл не удаляется. Работающий процесс не меняется.\n\ny: сохранить  n/Esc: отменить",
                invitation.id, invitation.endpoint, invitation.server_name
            ),
        ),
        ImportFlow::RefreshSaving => (
            "Замена credential",
            "Создание нового защищённого файла и guarded TOML commit. Работающий процесс не меняется.".into(),
        ),
        ImportFlow::RefreshDone => (
            "Credential сохранён",
            "Старый файл сохранён. Проверьте доступ отдельно; соединение и системный прокси не менялись. Enter/Esc: закрыть.".into(),
        ),
        ImportFlow::Saving => ("Сохранение профиля", "Сохраняем профиль и ключ в защищённом хранилище.\nПодключение не запускается, системный прокси не меняется.".into()),
        ImportFlow::Done => ("Профиль сохранён", format!("Профиль: {}\n{}\nИмпорт не запустил новое соединение и не изменил системный прокси.\n\nEnter: выбрать режим подключения\nEsc: закончить без запуска\n\n{}",
            editor.map_or("Новый профиль", |e| e.client_profile_address(e.selected_record_id()).unwrap_or_else(|| e.selected_record_id())),
            if editor.is_some_and(Editor::selected_record_is_active) { "Этот сервер выбран для подключения." } else { "Выбор сервера не изменён. Перед подключением подтвердите выбор нового профиля." },
            editor.and_then(|e| e.error.as_deref()).unwrap_or(""))),
        ImportFlow::ActivateConfirm => ("Выбрать импортированный профиль", format!("Сделать профиль {} активным?\nДругие профили остаются сохранёнными. Это не запускает соединение.\n\ny: подтвердить · n/Esc: назад", editor.map_or("", Editor::selected_record_id))),
        ImportFlow::Activating => ("Сохранение выбора", "Сохраняется активный профиль. Соединение не запускается.".into()),
        ImportFlow::ActivationFailed => ("Выбор профиля не подтверждён", format!("Сам профиль уже импортирован. Изменение активного профиля не подтверждено; новое соединение не запущено.\nПроверьте состояние файла и заново откройте настройки, прежде чем повторить выбор.\n\n{}\n\nEnter/Esc: закрыть", editor.and_then(|e| e.error.as_deref()).unwrap_or(""))),
        ImportFlow::Failed => (
            "Импорт НЕ подтверждён",
            format!(
                "Перед повторной попыткой проверьте файл настроек. При отказе до фиксации изменений новый ключ удалён.\nПодключение не запущено; системный прокси не изменён.\n\n{}\n\nEnter/Esc: закрыть",
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
    };
    match flow {
        ImportFlow::Preview { .. } => draw_guided(
            frame,
            area,
            title,
            &body,
            (
                3,
                5,
                "Параметры и доверие",
                "Enter следующий шаг · c сертификат · y сохранить · Esc отменить",
            ),
            viewport,
            (None, None),
        ),
        ImportFlow::Saving => draw_guided(
            frame,
            area,
            title,
            &body,
            (
                4,
                5,
                "Сохранение профиля",
                "Идёт запись · новое подключение не запускается",
            ),
            viewport,
            (None, None),
        ),
        ImportFlow::Done => draw_guided(
            frame,
            area,
            title,
            &body,
            (5, 5, "Подключение", "Enter выбрать режим · Esc закончить"),
            viewport,
            (None, None),
        ),
        ImportFlow::ActivateConfirm => draw_guided(
            frame,
            area,
            title,
            &body,
            (5, 5, "Выбор профиля", "y подтвердить · n/Esc назад"),
            viewport,
            (None, None),
        ),
        _ => panel_at(frame, area, title, &body, true, viewport),
    }
}

fn draw_role_card(frame: &mut Frame<'_>, area: Rect, role: Role, selected: bool) {
    let (title, details) = match role {
        Role::Server => ("Для сервера", "Настроить сервер и выдавать доступ."),
        Role::Client => ("Для клиента", "Подключиться по полученному ключу."),
    };
    let area = Rect::new(
        area.x.saturating_add(1),
        area.y,
        area.width.saturating_sub(2),
        area.height,
    );
    let bg = if selected { FOCUS } else { SURFACE };
    let lines = vec![
        Line::from(vec![Span::styled(
            format!("{}{title}", if selected { "› " } else { "  " }),
            Style::default()
                .fg(if selected { ACCENT } else { TEXT })
                .add_modifier(Modifier::BOLD),
        )]),
        Line::raw(""),
        Line::styled(details, Style::default().fg(MUTED)),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().bg(bg))
            .wrap(Wrap { trim: true }),
        area,
    );
}

#[cfg(test)]
fn page_layout(area: Rect, role: Role, page: usize, editor: Option<&Editor>) -> Option<[Rect; 2]> {
    page_layout_for(area, role, page, editor, 0, false)
}

fn page_layout_for(
    area: Rect,
    role: Role,
    page: usize,
    editor: Option<&Editor>,
    user: usize,
    advanced: bool,
) -> Option<[Rect; 2]> {
    let count = page_actions_for(role, page, editor, user, advanced).len();
    let minimum = if page == 1 { 10 } else { 6 };
    if count == 0 || area.height < minimum + 3 {
        return None;
    }
    let height = (count as u16)
        .saturating_add(2)
        .min(area.height - minimum)
        .max(3);
    let preferred = if page == 1 {
        18
    } else if role == Role::Client && page == 3 {
        editor.map_or(16, |e| {
            let body = client_mode_lines(e, true)
                .iter()
                .map(|line| {
                    line.spans
                        .iter()
                        .map(|span| span.content.as_ref())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            (visual_rows(&body, usize::from(area.width.saturating_sub(2)))
                .0
                .len()
                .saturating_add(2))
            .min(u16::MAX as usize) as u16
        })
    } else if page_has_users(role, page) {
        editor.map_or(6, |e| {
            (e.workspace_users().len() as u16)
                .saturating_add(3)
                .clamp(9, 12)
        })
    } else if page == 0 {
        10
    } else if role == Role::Client && page == 2 {
        7
    } else if role == Role::Client && page == 6 {
        if area.width >= 76 {
            10
        } else {
            14
        }
    } else if page == 5 {
        8
    } else if role == Role::Server && page == 3 {
        7
    } else {
        5
    };
    let content_height = if page == 4 && editor.is_some() {
        area.height - height
    } else {
        preferred.min(area.height - height)
    };
    let content = Rect::new(area.x, area.y, area.width, content_height);
    let controls = Rect::new(area.x, content.bottom(), area.width, height);
    Some([content, controls])
}
fn user_table_start(selected: usize, count: usize, area: Rect) -> usize {
    let capacity = usize::from(area.height.saturating_sub(3)).max(1);
    selected
        .min(count.saturating_sub(1))
        .saturating_sub(capacity - 1)
        .min(count.saturating_sub(capacity))
}
fn client_mode_lines(editor: &Editor, running: bool) -> Vec<Line<'static>> {
    let active = editor
        .workspace_records()
        .into_iter()
        .find(|(_, active, _)| *active)
        .and_then(|(id, _, _)| editor.client_profile_label(&id))
        .unwrap_or_else(|| "Нет профиля".into());
    let (http, socks) = editor.client_proxy_addresses().unwrap_or(("—", "—"));
    let mut lines = vec![
        Line::styled(
            if running {
                "● Локальный прокси запущен или запускается (не проверка связи с сервером)"
            } else {
                "○ Локальный прокси не запущен"
            },
            Style::default()
                .fg(if running { ACCENT } else { MUTED })
                .add_modifier(Modifier::BOLD),
        ),
        Line::raw(format!("Активный профиль: {active}")),
        Line::raw(if editor.selected_record_is_active() {
            format!("Защита: {}", if editor.selected_reality() { "REALITY" } else { "Own-TLS" })
        } else {
            format!("Выбран: {} · {}", editor.client_profile_label(editor.selected_record_id()).unwrap_or_else(|| "Нет профиля".into()), if editor.selected_reality() { "REALITY" } else { "Own-TLS" })
        }),
        Line::raw(""),
        Line::styled(
            "Локальный прокси",
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        ),
        Line::raw(format!("HTTP {http} · SOCKS5 {socks}")),
        Line::styled(
            "Укажите адрес в приложении после запуска. Остальной трафик не защищается этим режимом.",
            Style::default().fg(MUTED),
        ),
        Line::raw(""),
        Line::styled(
            "Системный прокси",
            Style::default()
                .fg(if cfg!(windows) { TEXT } else { MUTED })
                .add_modifier(Modifier::BOLD),
        ),
        Line::raw(if cfg!(windows) {
            if editor.system_proxy_allowed() {
                "Для программ, использующих настройки прокси Windows. Не VPN."
            } else {
                "Для программ с системным прокси Windows. Сначала потребуется разрешение."
            }
        } else {
            "На Linux пока недоступен. Настройте прокси в нужных приложениях."
        }),
        Line::styled(
            "TUN / VPN",
            Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
        ),
        Line::styled(
            "Пока недоступен. Весь трафик устройства через Theia не направляется.",
            Style::default().fg(MUTED),
        ),

    ];
    if !editor.selected_record_is_active() {
        lines.insert(
            3,
            Line::styled(
                "Перед запуском подтвердите выбор профиля.",
                Style::default().fg(WARNING),
            ),
        );
    }
    lines
}

fn draw_client_modes(frame: &mut Frame<'_>, area: Rect, editor: &Editor, ui: Option<&Interaction>) {
    let lines = client_mode_lines(editor, ui.is_some_and(|u| u.owned_running(Role::Client)));
    frame.render_widget(
        Paragraph::new(lines)
            .block(tui_widgets::section("Режим подключения", true))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_page(
    frame: &mut Frame<'_>,
    area: Rect,
    role: Role,
    editor: &Editor,
    ui: Option<&Interaction>,
    compact: bool,
) {
    let page = ui.map_or(0, |u| u.workspace_page.min(pages(role).len() - 1));
    let items = page_actions_for(
        role,
        page,
        Some(editor),
        ui.map_or(0, |u| u.workspace_user),
        ui.is_some_and(|u| u.workspace_advanced),
    );
    let focus = ui.map_or(WorkspaceFocus::Fields, |u| u.workspace_focus);
    let selected = ui.map_or(0, |u| u.visible_workspace_action(role));
    if compact && focus == WorkspaceFocus::Navigation {
        let rows = pages(role).iter().enumerate().map(|(i, label)| {
            ListItem::new(format!("{} {label}", if i == page { "›" } else { " " })).style(
                Style::default()
                    .fg(if i == page { ACCENT } else { TEXT })
                    .bg(if i == page { FOCUS } else { SURFACE }),
            )
        });
        frame.render_widget(
            List::new(rows.collect::<Vec<_>>()).block(tui_widgets::section("Разделы", true)),
            area,
        );
        return;
    }
    let [content, controls] = page_layout_for(
        area,
        role,
        page,
        Some(editor),
        ui.map_or(0, |u| u.workspace_user),
        ui.is_some_and(|u| u.workspace_advanced),
    )
    .unwrap_or([area, Rect::default()]);
    if page == 0 {
        let local = if role == Role::Server {
            ui.map_or("Неизвестно", |u| u.server_process.status())
        } else if ui.is_some_and(|u| {
            u.client_background
                .as_ref()
                .is_some_and(StatusPanel::local_running)
                || u.reality_status
                    .as_ref()
                    .is_some_and(StatusPanel::local_running)
        }) {
            "Локальный процесс запущен или запускается"
        } else {
            "Локальный процесс не запущен"
        };
        let title = if role == Role::Server {
            "Обзор сервера"
        } else {
            "Обзор клиента"
        };
        let records = if role == Role::Server {
            "Подключения"
        } else {
            "Профили"
        };
        let users = editor.workspace_users();
        let status = if editor.write_uncertain() {
            "Запись не подтверждена"
        } else if editor.dirty() {
            "Есть несохранённые изменения"
        } else {
            "Файл сохранён"
        };
        let (next_key, help) = recommended_step(editor, ui.is_some_and(|u| u.owned_running(role)));
        let (next_page, action_key) = recommendation_page(role, next_key);
        let next_user = if next_key == 'b' && role == Role::Server {
            users
                .iter()
                .position(|(_, disabled, granted)| *disabled && *granted)
                .unwrap_or(0)
        } else {
            ui.map_or(0, |u| u.workspace_user)
        };
        let next_items = page_actions_for(role, next_page, Some(editor), next_user, false);
        let next_label = next_items
            .iter()
            .find(|item| item.key == action_key)
            .map_or(pages(role)[next_page], |item| item.label);
        if role == Role::Server {
            let allowed = users
                .iter()
                .filter(|(_, disabled, granted)| !*disabled && *granted)
                .count();
            let selection = if editor.record_count() == 0 {
                "Подключений пока нет".to_owned()
            } else {
                format!(
                    "{} · {} из {} пользователей имеют доступ",
                    editor.selected_record_id(),
                    allowed,
                    users.len()
                )
            };
            let color = if editor.write_uncertain() {
                ERROR
            } else if editor.dirty() {
                WARNING
            } else {
                TEXT
            };
            let mut lines = vec![
                Line::styled(
                    selection,
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
                Line::styled(status, Style::default().fg(color)),
                Line::raw(format!("Сервер: {local}")),
                Line::styled(
                    format!("Далее: {next_label}"),
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
            ];
            if content.height >= 9 {
                lines.push(Line::raw(""));
                lines.push(Line::raw(help));
                lines.push(Line::raw(
                    "Сохранение файла не применяет изменения к серверу.",
                ));
            }
            frame.render_widget(
                Paragraph::new(lines)
                    .block(tui_widgets::section("Настройка сервера", true))
                    .wrap(Wrap { trim: true }),
                content,
            );
        } else {
            let lines = vec![
                Line::styled(
                    format!("{records}: {}", editor.record_count()),
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
                Line::raw(
                    editor
                        .client_profile_label(editor.selected_record_id())
                        .unwrap_or_else(|| "Нет профиля".into()),
                ),
                Line::raw(format!("Конфигурация: {status}")),
                Line::raw(format!("Процесс: {local}")),
                Line::raw(""),
                Line::styled(
                    "Следующий шаг",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
                Line::raw(help),
                Line::raw("Сохранение не запускает процесс."),
            ];
            frame.render_widget(
                Paragraph::new(lines)
                    .block(tui_widgets::section(title, true))
                    .wrap(Wrap { trim: true }),
                content,
            );
        }
    } else if role == Role::Client && page == 2 {
        let input = ui.and_then(|u| u.importing.as_ref()).and_then(|flow| {
            if let ImportFlow::Input(source) = flow {
                Some(source.len())
            } else {
                None
            }
        });
        let focused = focus == WorkspaceFocus::Actions;
        let lines = vec![
            Line::raw("Вставьте личный ключ Theia или выберите файл / QR (F6)."),
            Line::raw("Тип подключения определится автоматически."),
            Line::styled(
                input.filter(|n| *n > 0).map_or_else(
                    || " Вставьте ключ (скрыто) ".to_owned(),
                    |n| format!(" Введено {n} байт (скрыто) "),
                ),
                Style::default()
                    .fg(if focused { TEXT } else { MUTED })
                    .bg(if focused { FOCUS } else { SURFACE }),
            ),
            Line::raw("Сохранение и запуск требуют отдельных подтверждений."),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(tui_widgets::section("Импорт ключа", focused))
                .wrap(Wrap { trim: false }),
            content,
        );
        if input.is_some() {
            frame.render_widget(
                Paragraph::new("Enter — проверить · F6 — файл / QR · Esc — отменить")
                    .wrap(Wrap { trim: true }),
                controls,
            );
            return;
        }
    } else if page == 4 {
        if let Some(monitor) = ui.and_then(|u| u.workspace_monitor.as_ref()) {
            let monitor_area = Rect::new(area.x, area.y, area.width, area.height.saturating_sub(3));
            monitor.render(frame, monitor_area);
            let expand = Rect::new(
                area.x,
                monitor_area.bottom(),
                area.width,
                3.min(area.height),
            );
            Actions {
                items: &items,
                selected,
            }
            .render_with_focus(frame, expand, focus == WorkspaceFocus::Actions);
            return;
        }
    } else if role == Role::Client && page == 3 {
        draw_client_modes(frame, content, editor, ui);
    } else if page == 1 {
        draw_editor(frame, content, editor, focus == WorkspaceFocus::Fields);
    } else if page_has_users(role, page) {
        let users = editor.workspace_users();
        let selected = ui
            .map_or(0, |u| u.workspace_user)
            .min(users.len().saturating_sub(1));
        let start = user_table_start(selected, users.len(), content);
        let rows = users
            .iter()
            .enumerate()
            .skip(start)
            .take(usize::from(content.height.saturating_sub(3)))
            .map(|(i, (id, disabled, granted))| {
                let active = i == selected && focus == WorkspaceFocus::Users;
                let color = if *disabled { WARNING } else { TEXT };
                Row::new(vec![
                    format!(
                        "{} {id}",
                        if active {
                            "›"
                        } else if i == selected {
                            "•"
                        } else {
                            " "
                        }
                    ),
                    if *granted {
                        "Разрешено"
                    } else {
                        "Нет права"
                    }
                    .into(),
                    if *disabled {
                        "Отключён"
                    } else {
                        "Включён"
                    }
                    .into(),
                ])
                .style(Style::default().fg(color).bg(if active {
                    FOCUS
                } else {
                    SURFACE
                }))
            });
        frame.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Percentage(50),
                    Constraint::Percentage(20),
                    Constraint::Percentage(30),
                ],
            )
            .header(
                Row::new(["Пользователь", "Право доступа", "Учётная запись"])
                    .style(Style::default().fg(MUTED)),
            )
            .block(tui_widgets::section(
                &format!(
                    "{}: {}",
                    "Пользователи и ключи для",
                    editor.selected_record_id()
                ),
                focus == WorkspaceFocus::Users,
            )),
            content,
        );
        if users.is_empty() && content.height > 3 {
            frame.render_widget(
                Paragraph::new("Нет пользователей. Выберите «Добавить пользователя»."),
                Rect::new(
                    content.x + 1,
                    content.y + 2,
                    content.width.saturating_sub(2),
                    1,
                ),
            );
        }
        // Render explanatory text only in unused table rows. Mouse selection
        // still uses the same row geometry and cannot select the help text.
        if users.len() <= 3 && content.height >= 9 {
            let y = content.y + 2 + users.len() as u16 + 1;
            let hint = match users.get(selected) {
                Some((_, true, true)) => "Пользователь отключён. «Восстановить доступ и выдать ключ» подготовит новый ключ.\nИзменения действуют после применения прав.",
                Some((_, _, false)) => "У пользователя нет права на это подключение. Измените права доступа.\nУдаление возможно только без прав на всех подключениях.",
                Some(_) => "Личный ключ показывается один раз. Замена лишит старый ключ доступа после применения прав.\nУдаление доступно только после снятия прав во всех подключениях.",
                None => "Добавьте пользователя и выдайте ему ключ.",
            };
            frame.render_widget(
                Paragraph::new(hint)
                    .style(Style::default().fg(MUTED))
                    .wrap(Wrap { trim: true }),
                Rect::new(
                    content.x + 1,
                    y,
                    content.width.saturating_sub(2),
                    content.bottom().saturating_sub(y + 1),
                ),
            );
        }
    } else {
        let description = match (role,page) {
            (Role::Server,3) => {
                let status = ui.map_or("Состояние неизвестно", |u| u.server_process.status());
                let applied = ui.and_then(|u| u.last_apply)
                    .filter(|(sha, _, _)| !editor.dirty() && *sha == editor.saved_sha256())
                    .map_or_else(|| "Работа с сохранёнными настройками не подтверждена".into(), |(_, kind, revision)| format!("Последнее подтверждение: {kind}, rev {revision}"));
                format!("Сервер: {status}\n{applied}\nВнешний сервис: проверьте через «Состояние».\nСохранение файла не применяет изменения.")
            }
            (Role::Client,6) => {
                let observation = if editor.dirty() || editor.write_uncertain() { "Сохранённые настройки изменились. Состояние выбранного файла не подтверждено.".into() }
                else if let Some(local) = ui.and_then(|u| u.client_background.as_ref()).and_then(|p| p.routing_observation(editor.saved_sha256())) {
                    format!("Источник: локальный процесс этой панели\n{local}\nСчётчики с запуска процесса, полезные TCP/UDP-байты.")
                } else {
                    ui.and_then(|u| u.routing_observation.as_ref()).filter(|o| o.digest == editor.saved_sha256()).map_or_else(|| "Проверяем состояние клиента…".into(), RoutingObservation::body)
                };
                format!("Anti-DPI в сохранённом файле: {}\n{observation}", if editor.direct_dpi_stun_allowed() { "разрешён; TLS/QUIC v1 и STUN Binding (экспериментально)" } else if editor.direct_dpi_allowed() { "разрешён; TLS/QUIC v1, STUN выключен" } else { "выключен (резерв VPS)" })
            }
            (Role::Server,7) => editor.routing_settings().map_or_else(|| "Правил нет. По умолчанию весь трафик Theia идёт через сервер.".into(), |s| format!("Ревизия: {} · правил: {}\nGeoData: {}\nСохраните TOML, затем примените через Управление.", s.revision, s.rules.len(), s.datasets.as_ref().map_or("не выбраны", |m| m.release.as_str()))),
            (_,5) => format!("Файл: {}\n{}\nСохранение не меняет работающий процесс.", editor.saved_path().display(), editor.settings_summary()),
            _ => "Проверьте состояние подключения.\nСетевые проверки требуют согласия.".into(),
        };
        panel(frame, content, pages(role)[page], &description, true);
    }
    if controls.height > 0 {
        Actions {
            items: &items,
            selected,
        }
        .render_with_focus(
            frame,
            controls,
            focus == WorkspaceFocus::Actions
                || (focus == WorkspaceFocus::Fields && page != 1 && !page_has_users(role, page)),
        );
    } else if focus == WorkspaceFocus::Actions && !items.is_empty() {
        Actions {
            items: &items,
            selected,
        }
        .render(frame, area);
    }
}
fn draw_workspace(
    frame: &mut Frame<'_>,
    area: Rect,
    role: Role,
    editor: Option<&Editor>,
    welcome_choice: usize,
    ui: Option<&Interaction>,
) {
    if editor.is_none() {
        draw_welcome(frame, area, role, welcome_choice);
        return;
    }
    let Some([nav, records, details]) = workspace_columns(area) else {
        if let Some(editor) = editor {
            if ui.is_some_and(|u| {
                u.workspace_focus == WorkspaceFocus::Records
                    && page_has_records(role, u.workspace_page)
            }) {
                draw_workspace_records(frame, area, role, editor, true);
            } else {
                draw_page(frame, area, role, editor, ui, true);
            }
        } else {
            draw_welcome(frame, area, role, welcome_choice);
        }
        return;
    };
    let page = ui.map_or(0, |u| u.workspace_page);
    let nav_focused = ui.is_some_and(|u| u.workspace_focus == WorkspaceFocus::Navigation);
    let categories = pages(role).iter().enumerate().map(|(i, label)| {
        let current = i == page;
        let marker = if current && nav_focused {
            "›"
        } else if current {
            "•"
        } else {
            " "
        };
        let style = if current && nav_focused {
            Style::default()
                .fg(ACCENT)
                .bg(FOCUS)
                .add_modifier(Modifier::BOLD)
        } else if current {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TEXT)
        };
        ListItem::new(format!("{marker} {label}")).style(style)
    });
    frame.render_widget(
        List::new(categories.collect::<Vec<_>>())
            .block(tui_widgets::section(" Разделы ", nav_focused)),
        nav,
    );
    if let Some(editor) = editor {
        if page_has_records(role, page) {
            draw_workspace_records(
                frame,
                records,
                role,
                editor,
                ui.is_some_and(|u| u.workspace_focus == WorkspaceFocus::Records),
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

fn draw_workspace_records(
    frame: &mut Frame<'_>,
    area: Rect,
    role: Role,
    editor: &Editor,
    focused: bool,
) {
    let selected = editor.workspace_selected();
    let mut previous = None;
    let items = record_rows(editor, area)
        .into_iter()
        .map(|(index, label)| {
            let current = index == selected;
            let first = previous != Some(index);
            previous = Some(index);
            let marker = if first && current {
                if focused {
                    "› "
                } else {
                    "• "
                }
            } else {
                "  "
            };
            let style = if current {
                Style::default()
                    .fg(ACCENT)
                    .bg(if focused { FOCUS } else { BG })
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(TEXT)
            };
            ListItem::new(format!("{marker}{label}")).style(style)
        })
        .collect::<Vec<_>>();
    let title = if role == Role::Server {
        "Подключения"
    } else {
        "Профили"
    };
    frame.render_widget(
        List::new(items).block(tui_widgets::section(title, focused)),
        area,
    );
    if editor.record_count() == 0 && area.height > 2 {
        frame.render_widget(
            Paragraph::new("Пока нет записей.").style(Style::default().fg(MUTED)),
            Rect::new(area.x + 1, area.y + 1, area.width.saturating_sub(2), 1),
        );
    }
}

fn welcome_form(role: Role, selected: usize) -> Form {
    let (reality, description, lead) = match role {
        Role::Server => ("Настроить новый сервер (REALITY)", "Рекомендуется: не нужен собственный TLS-сертификат", "Настраиваете сервер впервые? Выберите создание REALITY. Если Theia уже настроена, откройте существующий файл."),
        Role::Client => ("Импортировать ключ Theia", "Ссылка или файл · тип определяется автоматически", "Настраиваете клиент впервые? Получите приглашение у администратора. Если профили уже сохранены, откройте их файл."),
    };
    Form {
        fields: vec![
            Field {
                id: 0,
                label: "Открыть сохранённые настройки",
                value: "У меня уже есть файл настроек (.toml)".into(),
                hint: "Enter — выбрать путь. F3 — открыть файл.",
            },
            Field {
                id: 1,
                label: reality,
                value: description.into(),
                hint: "Enter — подтвердить предложенный файл настроек, затем открыть мастер.",
            },
            Field {
                id: 2,
                label: "Настроить вручную (Own-TLS)",
                value: "Расширенная настройка с сертификатом".into(),
                hint: "Выбирайте только если администратор выдал необходимые TLS-данные.",
            },
        ],
        selected,
        lead: lead.into(),
        error: String::new(),
    }
}

fn draw_welcome(frame: &mut Frame<'_>, area: Rect, role: Role, selected: usize) {
    let title = if role == Role::Server {
        "Для сервера · начало работы"
    } else {
        "Для клиента · начало работы"
    };
    tui_widgets::canvas(frame, area);
    welcome_form(role, selected).render_picker(frame, centered_column(area, 88), title);
}

fn centered_column(area: Rect, max_width: u16) -> Rect {
    let width = area.width.min(max_width);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y,
        width,
        area.height,
    )
}

fn editor_layout(area: Rect) -> Option<[Rect; 4]> {
    if area.height < 10 || area.width < 38 {
        return None;
    }
    // Four records at most: do not stretch a short form into an empty grid.
    // On wide terminals, contextual guidance sits beside the parameters.
    if area.width >= 92 && area.height >= 18 {
        let parts = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(9),
            Constraint::Min(4),
        ])
        .split(area);
        let middle = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(parts[1]);
        return Some([parts[0], middle[0], middle[1], parts[2]]);
    }
    if area.height >= 18 {
        let parts = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Length(3),
            Constraint::Min(3),
        ])
        .split(area);
        return Some([parts[0], parts[1], parts[2], parts[3]]);
    }
    let parts = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(4),
        Constraint::Length(2),
        Constraint::Length(2),
    ])
    .split(area);
    Some([parts[0], parts[1], parts[2], parts[3]])
}

fn editor_table_window(area: Rect, editor: &Editor) -> (usize, usize, bool) {
    let header = area.height >= 7;
    let count = editor.workspace_fields().len();
    let rows = usize::from(area.height.saturating_sub(if header { 3 } else { 2 }));
    let start = editor
        .workspace_field_index()
        .saturating_sub(rows.saturating_sub(1))
        .min(count.saturating_sub(rows));
    (start, rows, header)
}

fn editor_field_hit(area: Rect, editor: &Editor, x: u16, y: u16) -> Option<usize> {
    let rect = editor_layout(area)?[1];
    let (start, rows, header) = editor_table_window(rect, editor);
    let y0 = rect.y + if header { 2 } else { 1 };
    if x <= rect.x
        || x >= rect.right().saturating_sub(1)
        || y < y0
        || y >= rect.bottom().saturating_sub(1)
    {
        return None;
    }
    let offset = usize::from(y - y0);
    (offset < rows && start + offset < editor.workspace_fields().len()).then_some(start + offset)
}

fn draw_editor(frame: &mut Frame<'_>, area: Rect, editor: &Editor, focused: bool) {
    let dirty = if editor.write_uncertain() {
        "Не сохранено: запись не подтверждена"
    } else if editor.dirty() {
        "Не сохранено"
    } else {
        "Сохранено"
    };
    let state_color = if editor.write_uncertain() {
        ERROR
    } else if editor.dirty() {
        WARNING
    } else {
        MUTED
    };
    let reality = editor.selected_reality();
    let mode = if reality {
        "SmartTheia REALITY"
    } else {
        "Own-TLS"
    };
    let server = editor.role() == Role::Server;
    let users = if server {
        let users = editor.workspace_users();
        let granted = users.iter().filter(|(_, _, grant)| *grant).count();
        let disabled = users
            .iter()
            .filter(|(_, disabled, grant)| *disabled && *grant)
            .count();
        format!(
            "В файле: {} пользователей с доступом · {} отключены",
            granted.saturating_sub(disabled),
            disabled
        )
    } else {
        "Работа профиля проверяется отдельно от сохранения.".into()
    };
    let help = if editor.editing && !editor.choice_options().is_empty() {
        "←→ / Пробел выбрать · Enter проверить · Esc отменить"
    } else if editor.editing {
        "Ctrl+U очистить · Enter проверить · Esc отменить"
    } else if reality {
        "Enter — полное значение"
    } else {
        "Enter — изменить выбранное поле"
    };
    let actions = "Другие операции находятся в соответствующих разделах.";
    let next = if editor.record_count() == 0 {
        if server {
            "Создайте первое подключение."
        } else {
            "Откройте раздел «Импорт ключа» или добавьте профиль вручную."
        }
    } else if editor.write_uncertain() {
        "Откройте конфигурацию заново, прежде чем продолжать."
    } else if editor.dirty() {
        "Сохраните изменения (Ctrl+S). Это не изменяет работающий процесс."
    } else if server {
        "Права доступа и ключи находятся в разделе «Пользователи и ключи»."
    } else {
        "Для запуска и проверки откройте раздел «Подключение»."
    };
    let title = if editor.editing {
        "Изменение параметра"
    } else if reality {
        "Защищённое подключение · только просмотр"
    } else {
        "Параметры · Enter изменить"
    };
    let fields = editor.workspace_fields();
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
        let message = format!(
            "{dirty} · {mode}\n{}\n{}\n{}\n{}\n{}\n{}",
            editor.selection_summary(),
            editor.fields_overview(),
            editor.error.as_deref().unwrap_or(""),
            editor.notice,
            next,
            actions
        );
        panel(frame, area, title, &message, true);
        return;
    };
    let heading = if reality {
        "SmartTheia REALITY · только просмотр"
    } else if server {
        "Подключение сервера"
    } else {
        "Профиль клиента"
    };
    let status = vec![
        Line::from(vec![
            Span::styled(
                format!(" {dirty} "),
                Style::default()
                    .fg(BG)
                    .bg(state_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  {mode}")),
        ]),
        Line::raw(editor.selection_summary()),
        Line::styled(users, Style::default().fg(MUTED)),
    ];
    if overview.height >= 5 {
        frame.render_widget(
            Paragraph::new(status).block(tui_widgets::section(heading, false)),
            overview,
        );
    } else {
        frame.render_widget(
            Paragraph::new(status).style(Style::default().bg(SURFACE)),
            overview,
        );
    }

    let (start, rows, header) = editor_table_window(table_area, editor);
    let labels = if server {
        ["Имя сервера", "Адрес TCP (H2)", "Адрес UDP (H3)", ""]
    } else {
        [
            "Адрес сервера",
            "Имя сервера (TLS)",
            "Транспорт",
            "Режим XHTTP",
        ]
    };
    let label_width = (table_area.width / 2).clamp(12, 24);
    let value_width = table_area.width.saturating_sub(label_width + 5);
    let table_rows =
        fields
            .iter()
            .enumerate()
            .skip(start)
            .take(rows)
            .map(|(index, (_, value, selected))| {
                let marker = if *selected && focused {
                    "› "
                } else if *selected {
                    "· "
                } else {
                    "  "
                };
                let style = if *selected && focused {
                    Style::default()
                        .fg(ACCENT)
                        .bg(FOCUS)
                        .add_modifier(Modifier::BOLD)
                } else if *selected {
                    Style::default().fg(TEXT).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(TEXT)
                };
                let shown = tui_widgets::fit_value(
                    value,
                    value_width.saturating_sub(2),
                    *selected && editor.editing,
                );
                Row::new(vec![
                    ratatui::widgets::Cell::from(format!("{marker}{}", labels[index])),
                    ratatui::widgets::Cell::from(format!(
                        " {shown}{}",
                        if *selected && editor.editing {
                            " ▏"
                        } else {
                            ""
                        }
                    ))
                    .style(Style::default().bg(if reality {
                        SURFACE
                    } else if *selected && focused {
                        FOCUS
                    } else {
                        INPUT
                    })),
                ])
                .style(style)
            });
    let mut table = Table::new(
        table_rows,
        [Constraint::Length(label_width), Constraint::Min(1)],
    )
    .column_spacing(1)
    .block(tui_widgets::section(title, focused));
    if header {
        table = table.header(Row::new(["Настройка", "Значение"]).style(Style::default().fg(MUTED)));
    }
    frame.render_widget(table, table_area);
    if fields.is_empty() && table_area.height >= 3 {
        frame.render_widget(
            Paragraph::new("Нет записей.").style(Style::default().fg(MUTED)),
            Rect::new(
                table_area.x + 1,
                table_area.y + 1,
                table_area.width.saturating_sub(2),
                1,
            ),
        );
    }
    let choices = if editor.editing && !editor.choice_options().is_empty() {
        editor
            .choice_options()
            .iter()
            .map(|value| {
                if *value == editor.input.as_str() {
                    format!("[● {value}]")
                } else {
                    format!("[○ {value}]")
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    } else {
        String::new()
    };
    let context = if reality {
        "Параметры закреплены при регистрации. Изменения доверия выполняются отдельно."
    } else {
        friendly
    };
    let error = editor.error.as_deref();
    if detail.height >= 5 {
        let detail_lines = vec![
            Line::styled(
                fields
                    .iter()
                    .position(|(_, _, selected)| *selected)
                    .and_then(|index| labels.get(index))
                    .copied()
                    .unwrap_or("Параметр"),
                Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
            Line::styled(context, Style::default().fg(MUTED)),
            Line::styled(choices, Style::default().fg(ACCENT)),
            Line::styled(help, Style::default().fg(TEXT)),
        ];
        frame.render_widget(
            Paragraph::new(detail_lines)
                .block(tui_widgets::section("Что это значит", false))
                .wrap(Wrap { trim: true }),
            detail,
        );
    } else {
        frame.render_widget(
            Paragraph::new(error.unwrap_or(help))
                .style(Style::default().fg(if error.is_some() { ERROR } else { TEXT }))
                .wrap(Wrap { trim: true }),
            detail,
        );
    }
    let mut lines = Vec::new();
    // Errors already appear in the persistent notification strip.
    lines.push(Line::styled(
        next,
        Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
    ));
    if bottom.height >= 6 && !editor.notice.is_empty() {
        lines.push(Line::styled(editor.notice, Style::default().fg(MUTED)));
    }
    if bottom.height >= 5 {
        let height = bottom.height.min(10);
        frame.render_widget(
            Paragraph::new(lines)
                .block(tui_widgets::section("Что дальше", false))
                .wrap(Wrap { trim: true }),
            Rect::new(bottom.x, bottom.y, bottom.width, height),
        );
    } else {
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), bottom);
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
    if interaction.editor_for(Role::Client).is_some() {
        interaction.workspace_page = 3;
        interaction.workspace_focus = WorkspaceFocus::Actions;
    }
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
            if let Some(observation) = runtime.apply_observation() {
                interaction.last_apply = Some(observation);
            } else if runtime.invalidates_apply_observation() {
                interaction.last_apply = None;
            }
        }
        #[cfg(windows)]
        if let Some(proxy) = interaction.system_proxy.as_mut() {
            if proxy.poll() {
                interaction.modal_action = 0;
            }
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
                interaction.reality_enrollment = None;
                interaction.importing = Some(ImportFlow::Done);
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
                    let old_screen = model.screen;
                    if interaction.update(&mut model, key) {
                        crate::diag!(Info, "tui", "closed_by_user");
                        return Ok(());
                    }
                    if old_screen != model.screen {
                        if let Some(role) = Interaction::panel_role(&model) {
                            if interaction.editor_for(role).is_none() {
                                interaction.welcome_choice = ConfigDialog::suggested_mode(role);
                            }
                        }
                    }
                }
                Event::Mouse(mouse) => {
                    let size = terminal.size()?;
                    interaction.mouse(&mut model, mouse, Rect::new(0, 0, size.width, size.height));
                }
                Event::Paste(text) => {
                    interaction.paste_record_field(&text);
                    interaction.paste_workspace_import(&model, &text);
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

    fn click_at(column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn click_form_field(ui: &mut Interaction, model: &mut Model, area: Rect, id: usize) {
        let form = ui.active_form().expect("visible form");
        let target = guided_form_area(shell_layout(area)[1], form.fields.len());
        let y = (target.y..target.bottom())
            .find(|&y| form.hit(target, target.x + 2, y) == Some(id))
            .expect("visible field");
        ui.mouse(model, click_at(target.x + 2, y), area);
        assert_eq!(ui.active_form().unwrap().selected, id);
    }

    #[test]
    fn workspace_navigation_mouse_and_keyboard_never_commit_or_start() {
        use crate::config::{self, Config};
        let root =
            std::env::temp_dir().join(crate::tui_editor::generated_id("workspace-nav").unwrap());
        std::fs::create_dir(&root).unwrap();
        for role in [Role::Server, Role::Client] {
            let path = root.join(if role == Role::Server {
                "server.toml"
            } else {
                "client.toml"
            });
            let original = if role == Role::Server {
                server_issuance_fixture()
            } else {
                let Config::Client(mut doc) =
                    config::parse(include_str!("../../../examples/client.toml")).unwrap()
                else {
                    panic!("client fixture");
                };
                let mut backup = doc.client.profiles[0].clone();
                backup.id = "backup".into();
                backup.server = "backup.example.org:443".into();
                doc.client.profiles.push(backup);
                Config::Client(doc).to_toml().unwrap()
            };
            std::fs::write(&path, &original).unwrap();
            let mut model = Model::new(Some(role));
            let mut ui = Interaction::new(Some(Editor::load(role, &path).unwrap()));
            for area in [Rect::new(0, 0, 160, 42), Rect::new(0, 0, 70, 34)] {
                let body = shell_layout(area)[1];
                let columns = workspace_columns(body);
                let nav = columns.map_or(body, |c| c[0]);
                for page in 0..pages(role).len() {
                    ui.workspace_focus = WorkspaceFocus::Navigation;
                    ui.mouse(
                        &mut model,
                        click_at(nav.x + 2, nav.y + 1 + page as u16),
                        area,
                    );
                    assert_eq!(ui.workspace_page, page);
                    assert_eq!(ui.workspace_focus, WorkspaceFocus::Navigation);
                    let navigation = rendered_interaction(area.width, area.height, &model, &ui);
                    assert!(navigation.contains(pages(role)[page]));
                    ui.update(&mut model, press(KeyCode::Enter));
                    if page == 1 {
                        assert_eq!(ui.workspace_focus, WorkspaceFocus::Records);
                        ui.update(&mut model, press(KeyCode::Right));
                    }
                    let expected_focus = if page == 1 {
                        WorkspaceFocus::Fields
                    } else if page_has_users(role, page) {
                        WorkspaceFocus::Users
                    } else {
                        WorkspaceFocus::Actions
                    };
                    assert_eq!(ui.workspace_focus, expected_focus);
                    let view = rendered_interaction(area.width, area.height, &model, &ui);
                    assert!(!view.contains("THEIA_AUTH_TOKEN"));
                    assert!(!view.contains("token_sha256"));
                    let details = columns.map_or(body, |c| c[2]);
                    let layout = page_layout(details, role, page, ui.editor.as_ref());
                    if page == 1 {
                        let content = layout.map_or(details, |p| p[0]);
                        let table = editor_layout(content).unwrap()[1];
                        let y = (table.y..table.bottom())
                            .find(|&y| {
                                editor_field_hit(
                                    content,
                                    ui.editor.as_ref().unwrap(),
                                    table.x + 2,
                                    y,
                                ) == Some(1)
                            })
                            .unwrap();
                        ui.mouse(&mut model, click_at(table.x + 2, y), area);
                        assert_eq!(ui.editor.as_ref().unwrap().workspace_field_index(), 1);
                        assert!(!ui.editor.as_ref().unwrap().editing);
                    } else if page_has_users(role, page) {
                        let content = layout.unwrap()[0];
                        ui.mouse(&mut model, click_at(content.x + 2, content.y + 2), area);
                        assert_eq!(ui.workspace_focus, WorkspaceFocus::Users);
                        assert_eq!(ui.workspace_user, 0);
                        ui.update(&mut model, press(KeyCode::Down));
                        assert_eq!(ui.workspace_user, 0);
                        assert_eq!(ui.workspace_focus, WorkspaceFocus::Actions);
                        ui.update(&mut model, press(KeyCode::Up));
                        assert_eq!(ui.workspace_focus, WorkspaceFocus::Users);
                    }
                    if let Some([_, controls]) = layout {
                        let items = page_actions(role, page, ui.editor.as_ref());
                        let actions = Actions {
                            items: &items,
                            selected: ui.visible_workspace_action(role),
                        };
                        let found = (controls.y..controls.bottom())
                            .find_map(|y| actions.hit(controls, controls.x + 2, y).map(|i| (y, i)));
                        if let Some((y, i)) = found {
                            ui.mouse(&mut model, click_at(controls.x + 2, y), area);
                            assert_eq!(ui.workspace_action, i);
                            assert_eq!(ui.workspace_focus, WorkspaceFocus::Actions);
                            ui.update(&mut model, press(KeyCode::End));
                            assert_eq!(ui.workspace_action, items.len() - 1);
                            ui.update(&mut model, press(KeyCode::Home));
                            assert_eq!(ui.workspace_action, 0);
                            ui.update(&mut model, press(KeyCode::Tab));
                            assert_eq!(ui.workspace_focus, WorkspaceFocus::Navigation);
                        }
                    }
                    assert!(ui.workspace_visible());
                    assert!(!ui.owned_running(role));
                    assert!(!ui.editor.as_ref().unwrap().dirty());
                }
            }
            ui.select_workspace_page(role, 0);
            ui.update(&mut model, KeyEvent::new(KeyCode::Left, KeyModifiers::ALT));
            assert_eq!(ui.workspace_page, pages(role).len() - 1);
            ui.update(&mut model, KeyEvent::new(KeyCode::Right, KeyModifiers::ALT));
            assert_eq!(ui.workspace_page, 0);
            ui.update(&mut model, press(KeyCode::F(6)));
            assert_eq!(ui.workspace_focus, WorkspaceFocus::Fields);
            ui.update(&mut model, press(KeyCode::F(6)));
            assert_eq!(ui.workspace_focus, WorkspaceFocus::Actions);
            ui.update(&mut model, press(KeyCode::F(6)));
            assert_eq!(ui.workspace_focus, WorkspaceFocus::Navigation);
            if role == Role::Client {
                let area = Rect::new(0, 0, 160, 42);
                let records = workspace_columns(shell_layout(area)[1]).unwrap()[1];
                ui.select_workspace_page(role, 3);
                // The compact sidebar wraps the active address (including '*').
                // A physical row is not a profile index. Click every visible row
                // of the second profile and verify selection without activation.
                let rows = record_rows(ui.editor.as_ref().unwrap(), records);
                let active_rows: Vec<_> = rows
                    .iter()
                    .enumerate()
                    .filter_map(|(row, (index, _))| (*index == 0).then_some(row))
                    .collect();
                let backup_rows: Vec<_> = rows
                    .iter()
                    .enumerate()
                    .filter_map(|(row, (index, _))| (*index == 1).then_some(row))
                    .collect();
                assert!(!active_rows.is_empty(), "active label must remain visible");
                assert!(!backup_rows.is_empty());
                for row in active_rows {
                    ui.mouse(
                        &mut model,
                        click_at(records.x + 2, records.y + 1 + row as u16),
                        area,
                    );
                    assert_eq!(ui.editor.as_ref().unwrap().selected_record_id(), "home");
                }
                for row in backup_rows {
                    ui.mouse(
                        &mut model,
                        click_at(records.x + 2, records.y + 1 + row as u16),
                        area,
                    );
                    assert_eq!(ui.editor.as_ref().unwrap().selected_record_id(), "backup");
                    assert!(!ui.editor.as_ref().unwrap().selected_record_is_active());
                    assert!(!ui.owned_running(role));
                    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
                }
                let editor = ui.editor.as_ref().unwrap();
                assert_eq!(editor.selected_record_id(), "backup");
                assert!(!editor.selected_record_is_active());
                assert_eq!(recommended_step(editor, false).0, 'A');
                assert_eq!(recommended_step(editor, true).0, 'V');
                let view = rendered_interaction(160, 42, &model, &ui);
                assert!(view.contains("Активный профиль: №1 · edge.example.org:443"));
                assert_eq!(ui.workspace_focus, WorkspaceFocus::Records);
                ui.update(&mut model, press(KeyCode::Right));
                assert_eq!(ui.workspace_focus, WorkspaceFocus::Actions);
                ui.update(&mut model, press(KeyCode::Left));
                assert_eq!(ui.workspace_focus, WorkspaceFocus::Records);
                assert!(view.contains("Выбран: №2 · backup.example.org:443"));
                assert!(!view.contains("(home)"));
                assert!(view.contains("Перед запуском подтвердите выбор профиля"));
            }
            ui.select_workspace_page(role, 4);
            ui.update(&mut model, press(KeyCode::Enter));
            ui.update(&mut model, press(KeyCode::Enter));
            assert!(ui.traffic_monitor.is_some());
            assert!(rendered_interaction(60, 18, &model, &ui).contains("Монитор трафика"));
            ui.poll_navigation(&mut model);
            ui.update(&mut model, press(KeyCode::Esc));
            assert!(ui.traffic_monitor.is_none());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
            assert!(!ui.owned_running(role));
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn modal_mouse_and_safe_preview_select_fields_without_side_effects() {
        let root =
            std::env::temp_dir().join(crate::tui_editor::generated_id("modal-mouse").unwrap());
        std::fs::create_dir(&root).unwrap();
        let path = root.join("server.toml");
        let original = server_issuance_fixture();
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        let area = Rect::new(0, 0, 160, 42);
        ui.records = Some(RecordFlow::ChooseMode(Role::Server, 0));
        click_form_field(&mut ui, &mut model, area, 1);
        ui.update(&mut model, press(KeyCode::F(7)));
        assert!(ui.value_preview);
        assert!(rendered_interaction(160, 42, &model, &ui).contains("SmartTheia REALITY"));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.records.is_some());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.records.is_none());

        ui.reality_registration =
            Some(RegistrationPanel::new(ui.editor.as_ref().unwrap()).unwrap());
        click_form_field(&mut ui, &mut model, area, 1);
        ui.paste_record_field("test-material");
        ui.update(&mut model, press(KeyCode::F(7)));
        assert!(ui.value_preview);
        ui.update(&mut model, press(KeyCode::Esc));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.reality_registration.is_none());

        ui.reality_provision = Some(ProvisionPanel::bound(ui.editor.as_ref().unwrap()).unwrap());
        click_form_field(&mut ui, &mut model, area, 1);
        ui.paste_record_field("test-reference");
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.reality_provision.is_none());

        ui.issue_kind = IssueKind::Rotation;
        ui.issuance = Some(IssueFlow::Input(String::new()));
        let form = user_picker(ui.editor.as_ref(), "", false).unwrap();
        let target = guided_form_area(shell_layout(area)[1], form.fields.len());
        let y = (target.y..target.bottom())
            .find(|&y| form.hit(target, target.x + 2, y) == Some(0))
            .unwrap();
        ui.mouse(&mut model, click_at(target.x + 2, y), area);
        assert!(matches!(&ui.issuance, Some(IssueFlow::Input(id)) if id == "device-a"));
        ui.update(&mut model, press(KeyCode::Esc));
        ui.revocation = Some(DisableFlow::Input(String::new()));
        ui.mouse(&mut model, click_at(target.x + 2, y), area);
        assert!(matches!(&ui.revocation, Some(DisableFlow::Input(id)) if id == "device-a"));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.revocation.is_none());
        assert!(!ui.owned_running(Role::Server));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

        let path = root.join("client.toml");
        let original = include_str!("../../../examples/client.toml");
        std::fs::write(&path, original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        ui.reality_enrollment = Some(EnrollmentPanel::new());
        click_form_field(&mut ui, &mut model, area, 1);
        ui.paste_record_field("test-admission");
        ui.update(&mut model, press(KeyCode::F(7)));
        assert!(ui.value_preview);
        assert!(!rendered_interaction(160, 42, &model, &ui).contains("test-admission"));
        ui.update(&mut model, press(KeyCode::Esc));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.reality_enrollment.is_none());
        ui.importing = Some(ImportFlow::Input(Zeroizing::new(String::new())));
        ui.paste_import_source("not-an-invitation");
        ui.update(&mut model, press(KeyCode::F(6)));
        assert!(ui.import_browser.is_some());
        let form = ui.active_form().unwrap();
        let target = guided_form_area(shell_layout(area)[1], form.fields.len());
        let y = (target.y..target.bottom())
            .find(|&y| form.hit(target, target.x + 2, y).is_some())
            .unwrap();
        ui.mouse(&mut model, click_at(target.x + 2, y), area);
        assert!(ui.import_browser.is_some());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.import_browser.is_none());
        assert!(
            matches!(&ui.importing, Some(ImportFlow::Input(source)) if source.as_str() == "not-an-invitation")
        );
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(!ui.owned_running(Role::Client));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn server_workspace_action_selection_and_diagnostics_require_separate_consent() {
        use crate::camouflage_interfaces::{InterfaceSource, NativeInterfaces, ObservedInterface};
        use crate::camouflage_workflow::{build_preview, PreviewScope};
        let root =
            std::env::temp_dir().join(crate::tui_editor::generated_id("server-controls").unwrap());
        std::fs::create_dir(&root).unwrap();
        let path = root.join("server.toml");
        let original = server_issuance_fixture().replace("allowed_user_ids = [\"device-a\"]", "allowed_user_ids = [\"device-a\", \"device-b\"]").replace("[server.policy]", &format!("[[server.users]]\nid = \"device-b\"\ntoken_sha256 = \"{}\"\ndisabled = false\n\n[[server.users]]\nid = \"device-c\"\ntoken_sha256 = \"{}\"\ndisabled = false\n\n[server.policy]", "11".repeat(32), "22".repeat(32)));
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        let area = Rect::new(0, 0, 160, 42);
        let body = shell_layout(area)[1];
        for command in ['x', 't', 'U'] {
            ui.select_workspace_page(Role::Server, 2);
            ui.update(&mut model, press(KeyCode::Enter));
            ui.workspace_user = 0;
            ui.update(&mut model, press(KeyCode::Down));
            assert_eq!(ui.workspace_user, 1);
            ui.update(&mut model, press(KeyCode::Enter));
            if command == 'U' {
                ui.update(&mut model, press(KeyCode::Up));
                ui.workspace_user = 2;
                ui.workspace_focus = WorkspaceFocus::Actions;
            }
            let items = page_actions_for(
                Role::Server,
                2,
                ui.editor.as_ref(),
                ui.workspace_user,
                false,
            );
            ui.workspace_action = items.iter().position(|item| item.key == command).unwrap();
            ui.update(&mut model, press(KeyCode::Enter));
            match command {
                'x' => assert!(
                    matches!(&ui.revocation, Some(DisableFlow::Input(id)) if id == "device-b")
                ),
                't' => {
                    assert!(matches!(&ui.issuance, Some(IssueFlow::Input(id)) if id == "device-b"))
                }
                'U' => assert!(
                    matches!(&ui.records, Some(RecordFlow::Input { action: RecordAction::DeleteUser, fields, .. }) if fields.first().is_some_and(|id| id == "device-c"))
                ),
                _ => unreachable!(),
            }
            ui.update(&mut model, press(KeyCode::Esc));
            assert!(ui.workspace_visible());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        }
        ui.update(&mut model, press(KeyCode::F(5)));
        assert!(ui.show_server_process);
        let items = ui.server_process.actions();
        let controls =
            report_action_layout(body, items.len(), &ui.server_process.summary()).unwrap()[1];
        ui.mouse(&mut model, click_at(controls.x + 2, controls.y + 1), area);
        assert_eq!(ui.server_process.action_focus(), 0);
        assert!(!ui.server_process.running());
        assert!(ui.server_process.confirmation().is_none());
        ui.update(&mut model, press(KeyCode::Enter));
        assert_eq!(ui.server_process.confirmation(), Some(true));
        assert!(rendered_interaction(160, 42, &model, &ui).contains("Запуск сервера"));
        assert!(!ui.server_process.running());
        ui.update(&mut model, press(KeyCode::Char('n')));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(!ui.show_server_process);

        let native = NativeInterfaces {
            interfaces: vec![ObservedInterface {
                interface_name: "test".into(),
                address: "93.184.216.10".parse().unwrap(),
                prefix_len: 29,
                is_up: true,
                source: InterfaceSource::LinuxGetifaddrs,
            }],
        };
        ui.candidate_batch = Some(CandidateBatchPanel::new(
            build_preview(&native, None, PreviewScope::PassiveOnly),
            Some("edge.example.org".into()),
        ));
        click_form_field(&mut ui, &mut model, area, 0);
        assert_eq!(ui.candidate_batch.as_ref().unwrap().selected_count(), 0);
        assert!(!ui.candidate_batch.as_ref().unwrap().is_running());
        let view = rendered_interaction(160, 42, &model, &ui);
        assert!(view.contains("93.184.216.10:443"));
        ui.update(&mut model, press(KeyCode::Char(' ')));
        assert_eq!(ui.candidate_batch.as_ref().unwrap().selected_count(), 1);
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.candidate_batch.as_ref().unwrap().is_confirming());
        ui.update(&mut model, press(KeyCode::Char('n')));
        assert!(!ui.candidate_batch.as_ref().unwrap().is_running());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.candidate_batch.is_none());

        ui.domain = Some(DomainPanel::new(build_preview(
            &native,
            None,
            PreviewScope::PassiveOnly,
        )));
        click_form_field(&mut ui, &mut model, area, 1);
        assert_eq!(ui.domain.as_ref().unwrap().domain(), Some("samsung.com"));
        assert_eq!(ui.domain.as_ref().unwrap().selected_count(), 0);
        assert!(!ui.domain.as_ref().unwrap().is_running());
        ui.update(&mut model, press(KeyCode::Char('m')));
        assert!(ui.domain.as_ref().unwrap().is_manual_input());
        for ch in "example.orgx".chars() {
            ui.update(&mut model, press(KeyCode::Char(ch)));
        }
        ui.update(&mut model, press(KeyCode::Backspace));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.domain.as_ref().unwrap().is_dns_confirming());
        assert_eq!(ui.domain.as_ref().unwrap().domain(), Some("example.org"));
        assert!(!ui.domain.as_ref().unwrap().is_running());
        ui.update(&mut model, press(KeyCode::Char('n')));
        ui.update(&mut model, press(KeyCode::Esc));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.domain.is_none());
        assert!(!ui.owned_running(Role::Server));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn qr_worker_cancellation_and_failure_never_import_or_write() {
        let root = std::env::temp_dir().join(crate::tui_editor::generated_id("qr-events").unwrap());
        std::fs::create_dir(&root).unwrap();
        let path = root.join("client.toml");
        let original = include_str!("../../../examples/client.toml");
        std::fs::write(&path, original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        let (tx, rx) = mpsc::channel();
        ui.qr_scan = Some(QrScan {
            source: Zeroizing::new("local.png".into()),
            done: rx,
            cancelled: false,
        });
        assert!(rendered_interaction(120, 40, &model, &ui).contains("Локальное декодирование"));
        ui.poll_navigation(&mut model);
        assert!(ui.qr_scan.is_some());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(rendered_interaction(120, 40, &model, &ui).contains("Импорт отменён"));
        tx.send(Ok(Zeroizing::new("discarded-private-value".into())))
            .unwrap();
        ui.poll_navigation(&mut model);
        assert!(ui.qr_scan.is_none() && ui.importing.is_none());
        for disconnected in [false, true] {
            let (tx, rx) = mpsc::channel();
            ui.qr_scan = Some(QrScan {
                source: Zeroizing::new("local.png".into()),
                done: rx,
                cancelled: false,
            });
            if !disconnected {
                tx.send(Err("QR image rejected")).unwrap();
            }
            drop(tx);
            ui.poll_navigation(&mut model);
            assert!(ui.qr_scan.is_none());
            assert!(
                matches!(&ui.importing, Some(ImportFlow::Input(source)) if source.as_str() == "local.png")
            );
            assert!(ui.editor.as_ref().unwrap().error.is_some());
            ui.update(&mut model, press(KeyCode::Esc));
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(!ui.owned_running(Role::Client));
        std::fs::remove_dir_all(root).unwrap();
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
    fn client_connection_modes_are_visible_and_do_not_start_or_write_on_selection() {
        let root =
            std::env::temp_dir().join(crate::tui_editor::generated_id("connection-modes").unwrap());
        std::fs::create_dir(&root).unwrap();
        let path = root.join("client.toml");
        let original = include_str!("../../../examples/client.toml");
        std::fs::write(&path, original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        ui.update(&mut model, press(KeyCode::Char('P')));
        assert_eq!(ui.workspace_page, 3);
        let screen = rendered_interaction(120, 40, &model, &ui);
        for label in [
            "Системный прокси",
            "TUN / VPN",
            "Локальный прокси",
            "Активный профиль",
            "127.0.0.1",
            "edge.example.org:443",
            "Запустить / остановить локальный прокси",
        ] {
            assert!(screen.contains(label), "missing {label}");
        }
        assert!(!ui.owned_running(Role::Client));
        assert!(ui.reality_status.is_none());
        let keys = page_actions(Role::Client, 3, ui.editor.as_ref());
        assert_eq!(keys.iter().any(|a| a.key == 'p'), cfg!(windows));
        #[cfg(windows)]
        assert_eq!(keys[0].label, "Настроить и включить системный прокси");
        ui.update(&mut model, press(KeyCode::Down));
        assert!(!ui.owned_running(Role::Client));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        // The saved permission is separate from all operating-system effects.
        let editor = ui.editor.as_mut().unwrap();
        assert!(!editor.system_proxy_allowed());
        let review = editor.review_system_proxy_permission().unwrap();
        assert!(review
            .body()
            .contains("Прокси Windows и соединение не изменятся"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        editor.stage_record(review).unwrap();
        assert!(!editor.system_proxy_allowed());
        assert!(editor.save());
        assert!(editor.system_proxy_allowed());
        assert!(!ui.owned_running(Role::Client));
        std::fs::remove_dir_all(root).unwrap();
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
                Some("Системный прокси Linux пока не реализован. Выберите локальный HTTP/SOCKS5.")
            );
        }
        std::fs::remove_file(path).unwrap();
        let mut ui = Interaction::new(None);
        assert!(!ui.update(&mut model, press(KeyCode::Char('p'))));
        #[cfg(windows)]
        assert!(ui.system_proxy.is_none());
    }

    #[test]
    fn confirmation_choices_default_to_cancel_and_never_execute_on_focus() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("confirm-choice").unwrap());
        let original = server_issuance_fixture();
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        ui.update(&mut model, press(KeyCode::F(5)));
        ui.update(&mut model, press(KeyCode::Enter));
        assert_eq!(ui.server_process.confirmation(), Some(true));
        let area = Rect::new(0, 0, 120, 40);
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("› Отменить"));
        assert!(screen.contains("Запустить"));
        ui.update(&mut model, press(KeyCode::Right));
        assert!(ui.confirm_selected);
        assert!(!ui.server_process.running());
        let rect = ui.viewport.confirm_rect.get().unwrap();
        assert!(rect.y < area.y + 15);
        assert!(!screen.contains("ШАГ 1/1"));
        ui.mouse(
            &mut model,
            click_at(rect.x + rect.width / 2 + 1, rect.bottom() - 1),
            area,
        );
        assert!(ui.confirm_selected);
        assert!(!ui.server_process.running());
        ui.update(&mut model, press(KeyCode::Left));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.server_process.confirmation().is_none());
        assert!(!ui.server_process.running());
        assert!(!ui.confirm_selected);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn direct_profile_selection_wraps_long_addresses_without_activating() {
        use crate::config::{self, Config};
        let path = std::env::temp_dir()
            .join(crate::tui_editor::generated_id("profile-selection").unwrap());
        let Config::Client(mut doc) =
            config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client")
        };
        let mut backup = doc.client.profiles[0].clone();
        backup.id = "backup".into();
        backup.server = "long-label-for-testing-profile-address.example.org:443".into();
        doc.client.profiles.push(backup);
        let original = Config::Client(doc).to_toml().unwrap();
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        ui.update(&mut model, press(KeyCode::Char('P')));
        let items = page_actions(Role::Client, 3, ui.editor.as_ref());
        ui.workspace_action = items.iter().position(|a| a.key == 'L').unwrap();
        ui.update(&mut model, press(KeyCode::Enter));
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Records);
        ui.update(&mut model, press(KeyCode::Down));
        let editor = ui.editor.as_ref().unwrap();
        assert_eq!(editor.selected_record_id(), "backup");
        assert!(!editor.selected_record_is_active());
        let rows = record_rows(editor, Rect::new(0, 0, 30, 20));
        let label = rows
            .iter()
            .filter(|(id, _)| *id == 1)
            .map(|(_, s)| s.as_str())
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(
            label,
            "№2 long-label-for-testing-profile-address.example.org:443"
        );
        // Both narrow and wide terminal layouts must map continuation rows
        // to the same profile. Re-select the first profile before each click
        // so this also checks that mouse selection actually changes focus.
        for area in [
            Rect::new(0, 0, 70, 34),
            Rect::new(0, 0, 120, 40),
            Rect::new(0, 0, 160, 42),
        ] {
            let body = shell_layout(area)[1];
            let records = workspace_columns(body).map_or(body, |columns| columns[1]);
            ui.editor.as_mut().unwrap().workspace_select(0);
            ui.workspace_focus = WorkspaceFocus::Records;
            let rows = record_rows(ui.editor.as_ref().unwrap(), records);
            let row = rows.iter().rposition(|(index, _)| *index == 1).unwrap();
            ui.mouse(
                &mut model,
                click_at(records.x + 2, records.y + 1 + row as u16),
                area,
            );
            assert_eq!(ui.editor.as_ref().unwrap().selected_record_id(), "backup");
            assert_eq!(ui.workspace_focus, WorkspaceFocus::Records);
            assert!(!ui.editor.as_ref().unwrap().selected_record_is_active());
            assert!(!ui.owned_running(Role::Client));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        }
        ui.update(&mut model, press(KeyCode::F(7)));
        assert!(ui
            .preview_text
            .as_deref()
            .unwrap()
            .contains("long-label-for-testing-profile-address.example.org:443"));
        assert!(!ui.owned_running(Role::Client));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn model_navigation_help_and_safe_exit() {
        let mut app = Model::new(None);
        assert_eq!(app.screen, Screen::Home);
        assert!(!app.update(press(KeyCode::Down)));
        assert_eq!(app.selected, Role::Server);
        assert!(!app.update(press(KeyCode::Right)));
        assert_eq!(app.selected, Role::Client);
        assert!(!app.update(press(KeyCode::Right)));
        assert_eq!(app.selected, Role::Client);
        assert!(!app.update(press(KeyCode::Left)));
        assert_eq!(app.selected, Role::Server);
        assert!(!app.update(press(KeyCode::Right)));
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
    fn server_grant_picker_is_explicit_and_cancel_is_read_only() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("grant-picker").unwrap());
        let original = server_issuance_fixture().replace("[server.policy]", &format!(
            "[[server.users]]\nid = \"device-b\"\ntoken_sha256 = \"{}\"\ndisabled = false\n\n[server.policy]",
            "11".repeat(32),
        ));
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        ui.update(&mut model, press(KeyCode::Char('G')));
        assert!(
            matches!(&ui.records, Some(RecordFlow::GrantPicker { selected, .. }) if selected == &vec!["device-a".to_owned()])
        );
        let screen = rendered_interaction(80, 24, &model, &ui);
        assert!(screen.contains("device-a"));
        ui.update(&mut model, press(KeyCode::Char(' ')));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(
            matches!(&ui.records, Some(RecordFlow::GrantPicker { selected, .. }) if selected.is_empty())
        );
        ui.update(&mut model, press(KeyCode::Down));
        ui.update(&mut model, press(KeyCode::Char(' ')));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(&ui.records, Some(RecordFlow::Confirm(_))));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(!ui.editor.as_ref().unwrap().dirty());
        assert!(!ui.server_process.running());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reality_success_handoff_opens_key_draft_without_issuing_or_starting() {
        let path = std::env::temp_dir()
            .join(crate::tui_editor::generated_id("reality-success-handoff").unwrap());
        let original = server_issuance_fixture().replace("disabled = false", "disabled = true");
        assert_ne!(original, server_issuance_fixture());
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        ui.after_reality_success(Some("device-a".into()));
        assert!(matches!(&ui.issuance, Some(IssueFlow::Input(id)) if id == "device-a"));
        assert_eq!(ui.workspace_page, 2);
        assert!(!ui.editor.as_ref().unwrap().dirty());
        assert!(!ui.server_process.running());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        ui.issuance = None;
        ui.after_reality_success(None);
        assert!(ui.issuance.is_none());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn server_overview_opens_recommended_workflow_without_starting() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("server-overview").unwrap());
        let original = server_issuance_fixture();
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        ui.select_workspace_page(Role::Server, 0);
        ui.workspace_focus = WorkspaceFocus::Fields;
        let screen = rendered_interaction(80, 24, &model, &ui);
        assert!(screen.contains("Запуск / остановка"));
        ui.update(&mut model, press(KeyCode::Enter));
        assert_eq!(ui.workspace_page, 3);
        assert!(!ui.show_server_process);
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.show_server_process);
        assert!(!ui.server_process.running());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn onboarding_recommendation_and_invitation_actions_are_read_only() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("onboarding").unwrap());
        std::fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
        let editor = Editor::load(Role::Client, &path).unwrap();
        assert_eq!(recommended_step(&editor, false).0, 'P');
        let actions = invitation_actions(&IssueFlow::Offer);
        assert_eq!(actions[0].key, 'f');
        assert!(actions.iter().all(|a| a.key != 'y'));
        let before = std::fs::read(&path).unwrap();
        let mut ui = Interaction::new(Some(editor));
        ui.select_workspace_page(Role::Client, 0);
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Navigation);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn workspace_navigation_and_actions_do_not_write_on_focus() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("workspace-nav").unwrap());
        let original = server_issuance_fixture();
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        ui.update(&mut model, press(KeyCode::F(6)));
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Actions);
        ui.update(&mut model, press(KeyCode::F(6)));
        ui.update(&mut model, press(KeyCode::Down));
        assert_eq!(ui.workspace_page, 2);
        assert!(ui.menu.is_none());
        ui.update(&mut model, press(KeyCode::Enter));
        assert_eq!(ui.workspace_focus, WorkspaceFocus::Users);
        assert!(!ui.server_process.running());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn compact_workspace_always_shows_error_and_full_message_can_open() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("workspace-error").unwrap());
        std::fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
        let mut editor = Editor::load(Role::Client, &path).unwrap();
        editor.error = Some("Проверьте адрес сервера".into());
        let mut ui = Interaction::new(Some(editor));
        let mut model = Model::new(Some(Role::Client));
        assert!(
            rendered_interaction(60, 18, &model, &ui).contains("Ошибка: Проверьте адрес сервера")
        );
        ui.update(&mut model, press(KeyCode::F(7)));
        assert!(ui.value_preview);
        assert!(rendered_interaction(60, 18, &model, &ui).contains("Проверьте адрес сервера"));
        ui.update(&mut model, press(KeyCode::Esc));
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
    fn compact_report_actions_follow_the_visible_text() {
        let area = Rect::new(0, 2, 120, 36);
        let [short, controls] = report_action_layout(area, 3, "Одна строка").unwrap();
        assert_eq!(short.height, 3);
        assert_eq!(controls.y, short.bottom());
        let [long, controls] =
            report_action_layout(area, 3, &"Длинный отчёт\n".repeat(100)).unwrap();
        assert!(long.height > short.height);
        assert_eq!(controls.y, long.bottom());
        assert!(controls.bottom() <= area.bottom());
    }

    #[test]
    fn review_layout_keeps_actions_near_content_at_120_columns() {
        let area = Rect::new(0, 0, 120, 40);
        let [_, _, workspace] = workspace_columns(shell_layout(area)[1]).unwrap();
        for role in [Role::Server, Role::Client] {
            for page in [0, 2, 4, 5] {
                let [content, controls] = page_layout(workspace, role, page, None).unwrap();
                assert_eq!(controls.x, content.x);
                assert_eq!(controls.width, content.width);
                assert_eq!(controls.y, content.bottom());
                assert!(controls.y <= content.y + 12);
                assert!(controls.bottom() <= workspace.bottom());
            }
        }
    }

    #[test]
    fn invitation_offer_clears_workspace_and_keeps_reveal_explicit() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("review-offer").unwrap());
        let original = server_issuance_fixture();
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let model = Model::new(Some(Role::Server));
        ui.workspace_page = 1;
        let before = rendered_interaction(120, 40, &model, &ui);
        assert!(before.contains("Создать подключение"));
        for kind in [IssueKind::NewUser, IssueKind::Rotation, IssueKind::Reenable] {
            ui.issue_kind = kind;
            ui.issuance = Some(IssueFlow::Offer);
            let screen = rendered_interaction(120, 40, &model, &ui);
            assert!(screen.contains("Показать ссылку один раз"));
            assert!(screen.contains("Сохранить приглашение в файл"));
            assert!(!screen.contains("Создать подключение"));
            assert!(!screen.contains("edge.example.org"));
            assert!(!screen.contains("доступ пользователю."));
            assert!(!screen.contains("theia://"));
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn workspace_import_and_monitor_are_inline_and_read_only() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("inline-pages").unwrap());
        let original = include_str!("../../../examples/client.toml");
        std::fs::write(&path, original).unwrap();
        let mut model = Model::new(Some(Role::Client));
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        ui.select_workspace_page(Role::Client, 2);
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.importing.is_none());
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("Вставьте ключ (скрыто)"));
        assert!(screen.contains("Разделы"));
        ui.paste_workspace_import(&Model::new(None), "theia://v1/test");
        assert!(ui.importing.is_none());
        ui.paste_workspace_import(&model, "theia://v1/test");
        assert!(ui.inline_import());
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("Введено 15 байт (скрыто)"));
        assert!(!screen.contains("theia://v1/test"));
        assert!(screen.contains("Разделы"));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.importing.is_none());
        ui.update(&mut model, press(KeyCode::F(6)));
        assert!(ui.import_browser.is_some());
        ui.update(&mut model, press(KeyCode::Esc));
        ui.update(&mut model, press(KeyCode::Esc));
        ui.select_workspace_page(Role::Client, 4);
        ui.update(&mut model, press(KeyCode::Enter));
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("Разделы"));
        assert!(screen.contains("H2") && screen.contains("H3"));
        assert!(ui.workspace_monitor.is_some());
        assert!(ui.traffic_monitor.is_none());
        assert!(!ui.owned_running(Role::Client));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn workspace_selected_user_and_advanced_actions_are_contextual() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("context-actions").unwrap());
        let original = server_issuance_fixture()
            .replace("allowed_user_ids = [\"device-a\"]", "allowed_user_ids = [\"device-a\", \"device-b\"]")
            .replace("[server.policy]", &format!("[[server.users]]\nid = \"device-b\"\ntoken_sha256 = \"{}\"\ndisabled = true\n\n[[server.users]]\nid = \"device-c\"\ntoken_sha256 = \"{}\"\ndisabled = false\n\n[server.policy]", "11".repeat(32), "22".repeat(32)));
        std::fs::write(&path, &original).unwrap();
        let editor = Editor::load(Role::Server, &path).unwrap();
        let keys = |user| {
            page_actions_for(Role::Server, 2, Some(&editor), user, false)
                .into_iter()
                .map(|a| a.key)
                .collect::<Vec<_>>()
        };
        assert!(keys(0).contains(&'t') && keys(0).contains(&'x'));
        assert!(!keys(0).contains(&'b') && !keys(0).contains(&'U'));
        assert!(keys(1).contains(&'b') && !keys(1).contains(&'t') && !keys(1).contains(&'U'));
        assert!(keys(2).contains(&'U') && !keys(2).contains(&'b') && !keys(2).contains(&'x'));
        assert!(editor
            .review_record(RecordAction::DeleteUser, &["device-a".into()])
            .is_err());
        let review = editor
            .review_record(RecordAction::DeleteUser, &["device-c".into()])
            .unwrap();
        assert_eq!(review.confirmation_label(), "Удалить пользователя");
        assert!(!page_actions_for(Role::Server, 1, Some(&editor), 0, false)
            .iter()
            .any(|a| a.key == 'M'));
        assert!(page_actions_for(Role::Server, 1, Some(&editor), 0, true)
            .iter()
            .any(|a| a.key == 'M'));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn revocation_failure_replaces_entire_workspace() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("review-revoke").unwrap());
        let original = server_issuance_fixture();
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let model = Model::new(Some(Role::Server));
        ui.revocation = Some(DisableFlow::SaveFailed);
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("Повторить сохранение"));
        assert!(screen.contains("Отменить черновик"));
        assert!(!screen.contains("Что это значит"));
        assert!(!screen.contains("Адрес UDP"));
        assert!(!screen.contains("Создать подключение"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn workspace_has_single_owner_for_every_visible_operation() {
        for role in [Role::Server, Role::Client] {
            let mut seen = std::collections::HashSet::new();
            for page in 0..pages(role).len() {
                for item in page_actions(role, page, None) {
                    assert!(seen.insert(item.key), "duplicate action {}", item.key);
                }
            }
            assert!(!page_has_records(role, 0));
            assert!(!page_has_records(role, 4));
            assert!(!page_has_records(role, 5));
        }
        assert_eq!(recommendation_page(Role::Server, 'b'), (2, 'b'));
        assert_eq!(recommendation_page(Role::Server, 'G'), (2, 'G'));
        let imports = page_actions(Role::Client, 2, None);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].key, 'i');
        assert_eq!(recommendation_page(Role::Client, 'i'), (2, 'i'));
        assert_eq!(recommendation_page(Role::Client, 'A'), (3, 'A'));
        assert_eq!(recommendation_page(Role::Server, 'S'), (5, 'S'));
        assert!(!page_has_users(Role::Server, 3));
        assert_eq!(pages(Role::Client).len(), 7);
        assert_eq!(pages(Role::Server).len(), 8);
    }

    #[test]
    fn routing_workspace_reports_verified_ipc_and_stages_only_draft() {
        let client_path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("routing-client").unwrap());
        let client_source = include_str!("../../../examples/client.toml");
        std::fs::write(&client_path, client_source).unwrap();
        let editor = Editor::load(Role::Client, &client_path).unwrap();
        let digest = editor.saved_sha256();
        let mut client = Interaction::new(Some(editor));
        client.select_workspace_page(Role::Client, 6);
        client.workspace_focus = WorkspaceFocus::Actions;
        let mut observation = RoutingObservation::new(digest);
        let (tx, rx) = mpsc::channel();
        observation.pending = Some(rx);
        tx.send(Ok(crate::management::StatusReply::ClientRunning {
            revision: 1,
            config_sha256: digest,
            descriptor_revision: 0,
            transport: 2,
            xhttp: 1,
            fallback: false,
            routing_revision: 5,
            routing_state: 1,
            routing_totals: Box::new([
                10, 20, 30, 40, 2, 1, 1, 3, 4, 5, 10, 20, 30, 40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            ]),
        }))
        .unwrap();
        observation.poll();
        client.routing_observation = Some(observation);
        let screen = rendered_interaction(120, 40, &Model::new(Some(Role::Client)), &client);
        assert!(screen.contains("ревизия 5"));
        assert!(screen.contains("IPC"));
        assert!(screen.contains("Anti-DPI"));
        assert!(screen.contains("резерв VPS"));
        let editor = client.editor.as_mut().unwrap();
        assert!(!editor.direct_dpi_allowed());
        assert!(!editor.direct_dpi_stun_allowed());
        assert!(editor.review_direct_dpi_stun_permission().is_err());
        let review = editor.review_direct_dpi_permission().unwrap();
        assert_eq!(review.confirmation_label(), "Разрешить Anti-DPI");
        editor.stage_record(review).unwrap();
        assert!(editor.dirty());
        assert!(!editor.direct_dpi_allowed());
        assert_eq!(
            std::fs::read_to_string(&client_path).unwrap(),
            client_source
        );
        std::fs::remove_file(client_path).unwrap();

        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("routing-server").unwrap());
        let source = server_issuance_fixture();
        std::fs::write(&path, &source).unwrap();
        let mut editor = Editor::load(Role::Server, &path).unwrap();
        let mut panel = RoutingPanel::new(&editor);
        panel.edit(None);
        let (_, fields, _) = panel.fields.as_mut().unwrap();
        *fields = [
            "local".into(),
            "direct_via_client".into(),
            "full:localhost".into(),
            String::new(),
        ];
        assert!(panel.key(press(KeyCode::Enter), Some(&mut editor)));
        assert_eq!(panel.settings.rules.len(), 1);
        assert_eq!(
            panel.settings.rules[0].action,
            crate::routing::Action::Direct
        );
        panel.edit(None);
        let (_, fields, _) = panel.fields.as_mut().unwrap();
        *fields = [
            "DPI".into(),
            "direct_via_client_anti_dpi".into(),
            "example.org".into(),
            String::new(),
        ];
        assert!(panel.key(press(KeyCode::Enter), Some(&mut editor)));
        assert_eq!(
            panel.settings.rules[1].action,
            crate::routing::Action::DirectDpi
        );
        assert!(panel.body().contains("Anti-DPI / резерв VPS"));
        assert!(!panel.key(press(KeyCode::Char('s')), Some(&mut editor)));
        assert!(editor.dirty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn configured_sections_shortcut_uses_navigation_not_second_menu() {
        for role in [Role::Server, Role::Client] {
            let path =
                std::env::temp_dir().join(crate::tui_editor::generated_id("single-nav").unwrap());
            let original = if role == Role::Server {
                server_issuance_fixture()
            } else {
                include_str!("../../../examples/client.toml").to_owned()
            };
            std::fs::write(&path, &original).unwrap();
            let mut model = Model::new(Some(role));
            let mut ui = Interaction::new(Some(Editor::load(role, &path).unwrap()));
            for key in [KeyCode::F(2), KeyCode::F(10)] {
                ui.update(&mut model, press(key));
                assert_eq!(ui.workspace_focus, WorkspaceFocus::Navigation);
                assert!(ui.menu.is_none());
                assert!(!ui.owned_running(role));
                assert!(!ui.editor.as_ref().unwrap().dirty());
            }
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn workspace_actions_follow_record_mode_and_eligibility() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("review-actions").unwrap());
        std::fs::write(&path, server_issuance_fixture()).unwrap();
        let editor = Editor::load(Role::Server, &path).unwrap();
        let keys = |page| {
            page_actions(Role::Server, page, Some(&editor))
                .iter()
                .map(|a| a.key)
                .collect::<Vec<_>>()
        };
        assert!(keys(1).contains(&'E'));
        assert!(!keys(1).contains(&'V'));
        assert!(!keys(1).contains(&'D'));
        assert!(!keys(2).contains(&'b'));
        assert!(keys(2).contains(&'t'));
        std::fs::write(&path, include_str!("../../../examples/client.toml")).unwrap();
        let editor = Editor::load(Role::Client, &path).unwrap();
        let items = page_actions(Role::Client, 1, Some(&editor));
        assert!(!items.iter().any(|a| matches!(a.key, 'A' | 'D')));
        assert!(!items.iter().any(|a| matches!(a.key, 'V' | 'i' | 'A')));
        assert!(page_actions(Role::Client, 3, Some(&editor))
            .iter()
            .any(|a| a.key == 'V'));
        let mut selected = 0;
        assert_eq!(
            tui_widgets::action_key(&items, &mut selected, KeyCode::Enter),
            Some(KeyCode::Char('N'))
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn recovery_without_eligible_users_cannot_reach_confirmation() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("review-no-users").unwrap());
        let original = server_issuance_fixture();
        std::fs::write(&path, &original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Server, &path).unwrap()));
        let mut model = Model::new(Some(Role::Server));
        ui.update(&mut model, press(KeyCode::Char('b')));
        assert!(matches!(ui.issuance, Some(IssueFlow::Input(_))));
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("нет отключённых пользователей"));
        for key in [KeyCode::Char('a'), KeyCode::Enter, KeyCode::Char('y')] {
            ui.update(&mut model, press(key));
            assert!(matches!(ui.issuance, Some(IssueFlow::Input(_))));
        }
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.issuance.is_none());
        assert!(!ui.editor.as_ref().unwrap().dirty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn review_client_import_opens_directly_from_page_without_writing() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("review-import").unwrap());
        let original = include_str!("../../../examples/client.toml");
        std::fs::write(&path, original).unwrap();
        let mut ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let mut model = Model::new(Some(Role::Client));
        ui.select_workspace_page(Role::Client, 2);
        ui.workspace_focus = WorkspaceFocus::Fields;
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(ui.importing, Some(ImportFlow::Input(_))));
        ui.update(&mut model, press(KeyCode::Esc));
        ui.update(&mut model, press(KeyCode::Char('I')));
        assert!(matches!(ui.importing, Some(ImportFlow::Input(_))));
        assert!(ui.reality_enrollment.is_none());
        ui.update(&mut model, press(KeyCode::Esc));
        ui.update(&mut model, press(KeyCode::Char('N')));
        assert!(matches!(
            ui.records,
            Some(RecordFlow::Input {
                action: RecordAction::NewProfile,
                ..
            })
        ));
        ui.update(&mut model, press(KeyCode::Esc));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(!ui.editor.as_ref().unwrap().dirty());
        std::fs::remove_file(path).unwrap();
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
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            let viewport = Viewport::default();
            terminal
                .draw(|frame| {
                    draw_guided(
                        frame,
                        area,
                        "Мастер REALITY",
                        "Короткий результат",
                        (4, 5, "Результат подбора", "Y создать · N / Esc назад"),
                        Some(&viewport),
                        (None, None),
                    )
                })
                .unwrap();
            let screen = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(screen.contains("Короткий результат"));
            assert!(screen.contains("Следующее действие"));
        }
    }

    #[test]
    fn transport_choice_changes_only_draft_after_enter_and_cancel_restores_value() {
        let path =
            std::env::temp_dir().join(crate::tui_editor::generated_id("transport-choice").unwrap());
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
        let root =
            std::env::temp_dir().join(crate::tui_editor::generated_id("mouse-focus").unwrap());
        std::fs::create_dir(&root).unwrap();
        let area = Rect::new(0, 0, 120, 40);
        let body = shell_layout(area)[1];
        let mut model = Model::new(Some(Role::Client));
        let mut ui = Interaction::new(None);
        let click = |column, row| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        };
        let target = centered_column(body, 88);
        let form = welcome_form(Role::Client, 0);
        let y = (target.y..target.bottom())
            .find(|&y| form.hit(target, target.x + 2, y) == Some(1))
            .unwrap();
        ui.mouse(&mut model, click(target.x + 2, y), area);
        assert_eq!(ui.welcome_choice, 1);
        assert!(ui.config_dialog.is_none());
        let path = root.join("first.toml");
        let mut dialog = ConfigDialog::new(Role::Client, Some(&path));
        dialog.prefer_mode(ui.welcome_choice);
        ui.config_dialog = Some(dialog);
        assert_eq!(
            ui.config_dialog.as_ref().unwrap().form().unwrap().selected,
            1
        );
        ui.update(&mut model, press(KeyCode::Enter));
        let dialog = ui.config_dialog.as_ref().unwrap();
        let _ = dialog;
        let form = ui.config_dialog.as_ref().unwrap().form().unwrap();
        let target = guided_form_area(body, form.fields.len());
        let y = (target.y..target.bottom())
            .find(|&y| form.hit(target, target.x + 2, y) == Some(0))
            .unwrap();
        ui.mouse(&mut model, click(target.x + 2, y), area);
        assert_eq!(
            ui.config_dialog.as_ref().unwrap().form().unwrap().selected,
            0
        );
        assert!(!path.exists());
        assert!(!ui.server_process.running());

        let path = root.join("existing.toml");
        let original = include_str!("../../../examples/client.toml");
        std::fs::write(&path, original).unwrap();
        ui = Interaction::new(Some(Editor::load(Role::Client, &path).unwrap()));
        let details = workspace_columns(body).unwrap()[2];
        let details = page_layout(details, Role::Client, 1, ui.editor.as_ref())
            .map(|p| p[0])
            .unwrap_or(details);
        let table = editor_layout(details).unwrap()[1];
        let y = (table.y..table.bottom())
            .find(|&y| {
                editor_field_hit(details, ui.editor.as_ref().unwrap(), table.x + 2, y) == Some(1)
            })
            .unwrap();
        ui.mouse(&mut model, click(table.x + 2, y), area);
        let editor = ui.editor.as_ref().unwrap();
        assert_eq!(editor.workspace_field_index(), 1);
        assert!(!editor.editing && !editor.dirty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_run_modes_are_visible_and_reality_wizard_has_progress() {
        let root =
            std::env::temp_dir().join(crate::tui_editor::generated_id("first-run-ui").unwrap());
        std::fs::create_dir(&root).unwrap();
        for role in [Role::Server, Role::Client] {
            let path = root.join(if role == Role::Server {
                "server.toml"
            } else {
                "client.toml"
            });
            let mut ui = Interaction::new(None);
            let mut model = Model::new(Some(role));
            ui.update(&mut model, press(KeyCode::Enter));
            let dialog = ui.config_dialog.as_mut().unwrap();
            dialog.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
            dialog.paste(path.to_str().unwrap());
            let snapshot = rendered_interaction(120, 40, &model, &ui);
            assert!(snapshot.contains(if role == Role::Server {
                "REALITY"
            } else {
                "Импорт ключа Theia"
            }));
            assert!(snapshot.contains("Own-TLS"));
            ui.update(&mut model, press(KeyCode::Down));
            ui.update(&mut model, press(KeyCode::Enter));
            let snapshot = rendered_interaction(120, 40, &model, &ui);
            assert!(snapshot.contains("1/"));
            assert!(snapshot.contains("Следующее действие"));
            if role == Role::Server {
                assert!(snapshot.contains("443"));
                assert!(snapshot.contains("Имя первого пользователя"));
            } else {
                assert!(snapshot.contains("Ключ Theia"));
                assert!(
                    snapshot.contains("тип подключения") || snapshot.contains("Тип подключения")
                );
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
        let client_screen = render(80, 24, client);
        let server_screen = render(80, 24, server);
        assert!(client_screen.contains("Импортировать ключ Theia"));
        assert!(server_screen.contains("Настроить новый сервер"));
        assert!(!client_screen.contains("Подключено"));
        assert!(!server_screen.contains("Запущен"));
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
        assert_eq!(interaction.modal_action, 0);
        assert!(!interaction.update(&mut model, press(KeyCode::Enter)));
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
        assert!(picture.contains("Адрес сервера"));
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
        assert!(!interaction.update(&mut model, press(KeyCode::Left)));
        assert_eq!(interaction.workspace_focus, WorkspaceFocus::Records);
        assert!(!interaction.update(&mut model, press(KeyCode::Down)));
        assert_eq!(
            interaction.editor.as_ref().unwrap().selected_record_id(),
            "backup"
        );
        assert!(!interaction.update(&mut model, press(KeyCode::Right)));
        assert_eq!(interaction.workspace_focus, WorkspaceFocus::Fields);
        assert!(!interaction
            .editor
            .as_ref()
            .unwrap()
            .selected_record_is_active());
        assert!(!interaction.update(&mut model, press(KeyCode::Down)));
        assert_eq!(
            interaction.editor.as_ref().unwrap().field_name(),
            "client.profiles[1].server_name"
        );
        assert!(!interaction.update(&mut model, press(KeyCode::Enter)));
        assert!(interaction.editor.as_ref().unwrap().editing);
        assert!(!interaction.update(&mut model, press(KeyCode::Char('q'))));
        assert!(interaction.editor.as_ref().unwrap().input.ends_with('q'));
        assert!(!interaction.update(&mut model, press(KeyCode::Esc)));
        assert!(!interaction.update(&mut model, press(KeyCode::Up)));
        assert_eq!(
            interaction.editor.as_ref().unwrap().field_name(),
            "client.profiles[1].server"
        );
        assert!(!interaction.update(&mut model, press(KeyCode::Left)));
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
            assert!(screen.contains("Адрес сервера"), "{width}x{height}");
            assert!(screen.contains("Имя сервера (TLS)"), "{width}x{height}");
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
    fn common_import_dispatches_reality_key_to_masked_review_and_cancels_without_writes() {
        use crate::config::{self, Config};
        use crate::reference_health::{Evidence, Plan, State, Target};
        use sha2::{Digest, Sha256};
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
        let bearer = [42u8; 32];
        let server_source = include_str!("../../../examples/server.toml")
            .replace(
                "REPLACE_WITH_64_LOWERCASE_HEX",
                &format!("{:x}", Sha256::digest(bearer)),
            )
            .replace("id = \"public\"", "id = \"edge\"");
        let Config::Server(server) = config::parse(&server_source).unwrap() else {
            panic!("server fixture");
        };
        let admission = crate::reality_admission::Secret::generate().unwrap();
        let uri = crate::reality_bootstrap::Invitation::issued(
            &identity, &signed, &server, "device-a", &bearer, &admission, now,
        )
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
        ui.paste_import_source("theia://v1/test");
        ui.paste_import_source(&"A".repeat(crate::invite::MAX_URI));
        assert!(matches!(&ui.importing, Some(ImportFlow::Input(source)) if source.is_empty()));
        assert!(ui
            .editor
            .as_ref()
            .unwrap()
            .error
            .as_deref()
            .unwrap()
            .contains("слишком длинный"));
        ui.paste_import_source(&uri);
        assert!(ui.editor.as_ref().unwrap().error.is_none());
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.importing.is_none());
        let panel = ui.reality_enrollment.as_ref().unwrap();
        let body = panel.body();
        assert_eq!(panel.guide().2, "Проверка приглашения");
        assert!(body.contains("без сети и записи"));
        assert!(!body.contains(uri.as_str()));
        assert!(!body.contains("Файл допуска"));
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(ui.reality_enrollment.is_none());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_file(&path).unwrap();

        let first_path = path.with_extension("first.toml");
        let mut ui = Interaction::new(None);
        let mut dialog = ConfigDialog::new(Role::Client, Some(&first_path));
        dialog.begin_client_import();
        ui.config_dialog = Some(dialog);
        ui.paste_record_field(uri.as_str());
        ui.update(&mut model, press(KeyCode::Enter));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !ui.config_dialog.as_ref().is_some_and(|d| {
            d.title() == "Импорт REALITY"
                && d.guide().is_some_and(|g| g.2 == "Подтверждение доверия")
        }) {
            ui.poll_navigation(&mut model);
            assert!(
                std::time::Instant::now() < deadline,
                "REALITY import was not detected"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let dialog = ui.config_dialog.as_ref().unwrap();
        assert_eq!(dialog.guide().unwrap().0, 3);
        assert!(dialog.body().contains("Связь с сервером ещё не проверена"));
        assert!(!dialog.body().contains("identity_sha256"));
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(!screen.contains(uri.as_str()));
        assert!(!first_path.exists());
        ui.update(&mut model, press(KeyCode::Esc));
        assert!(!first_path.exists());
    }

    // The visual gallery uses this same real first-run path, with synthetic
    // credentials and an independent local certificate. No connection is started.
    fn first_key_import_fixture(root: &Path, mut capture: impl FnMut(&str, &Model, &Interaction)) {
        use crate::config::{self, Config};
        std::fs::create_dir_all(root).unwrap();
        let path = root.join("client.toml");
        let ca = root.join("ca.pem");
        let cert = rcgen::generate_simple_self_signed(vec!["edge.example.org".into()]).unwrap();
        std::fs::write(&ca, cert.cert.pem()).unwrap();
        let server = config::parse(&server_issuance_fixture()).unwrap();
        let invite =
            Invitation::issued_from_server(&server, "public", "device-a", &[0x42; 32]).unwrap();
        let uri = Zeroizing::new(invite.encode().unwrap());
        let mut model = Model::new(Some(Role::Client));
        let mut ui = Interaction::new(None);
        let mut dialog = ConfigDialog::new(Role::Client, Some(&path));
        dialog.begin_client_import();
        ui.config_dialog = Some(dialog);
        capture("client-first-key-input", &model, &ui);
        ui.paste_record_field(&uri);
        let masked = rendered_interaction(120, 40, &model, &ui);
        assert!(masked.contains("скрыто"));
        assert!(!masked.contains(uri.as_str()));
        ui.update(&mut model, press(KeyCode::Enter));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !ui
            .config_dialog
            .as_ref()
            .and_then(ConfigDialog::guide)
            .is_some_and(|g| g.0 == 3)
        {
            ui.poll_navigation(&mut model);
            assert!(
                std::time::Instant::now() < deadline,
                "first key was not decoded"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!path.exists());
        capture("client-first-key-trust", &model, &ui);
        ui.update(&mut model, press(KeyCode::Enter)); // CA is mandatory.
        assert_eq!(ui.config_dialog.as_ref().unwrap().guide().unwrap().0, 3);
        assert!(!path.exists());
        ui.paste_record_field(ca.to_str().unwrap());
        ui.update(&mut model, press(KeyCode::Enter));
        assert_eq!(ui.config_dialog.as_ref().unwrap().guide().unwrap().0, 4);
        assert!(!path.exists());
        capture("client-first-key-save-review", &model, &ui);
        ui.update(&mut model, press(KeyCode::Char('n')));
        assert!(!path.exists());
        ui.update(&mut model, press(KeyCode::Enter));
        ui.update(&mut model, press(KeyCode::Char('y')));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while ui.config_dialog.is_some() {
            ui.poll_navigation(&mut model);
            assert!(
                std::time::Instant::now() < deadline,
                "first profile was not saved"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(ui.importing, Some(ImportFlow::Done)));
        assert!(ui.reality_status.is_none());
        let editor = ui.editor.as_ref().unwrap();
        assert!(editor.selected_record_is_active());
        let Config::Client(doc) = config::read_file(&path).unwrap() else {
            panic!("client expected");
        };
        assert_eq!(doc.client.profiles.len(), 1);
        assert_eq!(doc.client.active_profile, doc.client.profiles[0].id);
        assert_eq!(doc.client.proxy.system_proxy, config::SystemProxy::Off);
        assert!(doc.client.profiles[0].auth_token.starts_with("file:"));
        let bytes = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(uri.as_str()));
        assert!(Editor::create_first_invitation(
            &path,
            &invite,
            &format!("file:{}", ca.display()),
            None
        )
        .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        capture("client-first-key-saved", &model, &ui);
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.importing.is_none());
        assert!(ui.reality_status.is_none());
        assert_eq!(ui.workspace_page, 3);
        assert!(!ui.owned_running(Role::Client));
        capture("client-first-key-connect", &model, &ui);
    }

    #[test]
    fn first_key_import_creates_active_profile_and_opens_connection_panel() {
        let root =
            std::env::temp_dir().join(crate::tui_editor::generated_id("first-key-import").unwrap());
        first_key_import_fixture(&root, |_, _, _| {});
        std::fs::remove_dir_all(root).unwrap();
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
        assert!(ui.saving.is_none(), "independent CA is required");
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(ui.importing, Some(ImportFlow::Trust { .. })));
        let ca = path.with_extension("pem");
        let cert = rcgen::generate_simple_self_signed(vec!["remote.example.org".into()]).unwrap();
        fs::write(&ca, cert.cert.pem()).unwrap();
        ui.paste_import_source(ca.to_str().unwrap());
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(
            ui.importing,
            Some(ImportFlow::Preview { ca: Some(_), .. })
        ));
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
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(ui.importing, Some(ImportFlow::ActivateConfirm)));
        assert!(ui.saving.is_none());
        ui.update(&mut model, press(KeyCode::Char('y')));
        let start = Instant::now();
        while ui.saving.is_some() && start.elapsed() < Duration::from_secs(5) {
            ui.poll_save(&mut model).unwrap();
            thread::sleep(Duration::from_millis(5));
        }
        assert!(ui.importing.is_none());
        assert!(ui.editor.as_ref().unwrap().selected_record_is_active());
        assert!(ui.reality_status.is_none());
        assert_eq!(ui.workspace_page, 3);
        assert!(!ui.owned_running(Role::Client));
        fs::remove_file(ca).unwrap();
        fs::remove_file(config::lock_path(&path).unwrap()).unwrap();
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
        ui.update(&mut model, press(KeyCode::Down));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(matches!(ui.issuance, Some(IssueFlow::ConfirmReveal)));
        assert!(!rendered_interaction(120, 40, &model, &ui).contains("theia://v1/"));
        ui.update(&mut model, press(KeyCode::Enter)); // cancel selected
        assert!(matches!(ui.issuance, Some(IssueFlow::Offer)));
        assert!(ui.editor.as_ref().unwrap().issued_ready());
        ui.update(&mut model, press(KeyCode::Char('v')));
        ui.update(&mut model, press(KeyCode::Right));
        assert!(ui.editor.as_ref().unwrap().issued_ready());
        ui.update(&mut model, press(KeyCode::Enter));
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
        assert!(rendered_interaction(120, 40, &model, &ui).contains("Повторить сохранение"));
        ui.update(&mut model, press(KeyCode::Down));
        assert!(ui.saving.is_none());
        ui.update(&mut model, press(KeyCode::Enter));
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
        assert!(review.contains("всех подключений"));
        assert!(review.contains("отдельного применения прав"));
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
        assert!(before.contains("всех подключений"));
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
        assert!(rendered_interaction(120, 40, &model, &ui).contains("Импорт ключа Theia"));
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
        assert!(passive.contains(
            &crate::camouflage_discovery::POPULAR_HTTPS_DOMAINS
                .len()
                .to_string()
        ));
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
    fn diagnostics_menu_navigation_never_grants_network_consent() {
        let mut model = Model::new(Some(Role::Server));
        let mut ui = Interaction::new(None);
        ui.update(&mut model, press(KeyCode::Char('p')));
        let screen = rendered_interaction(120, 40, &model, &ui);
        assert!(screen.contains("Узнать внешний IP"));
        assert!(screen.contains("Посмотреть области поиска"));
        ui.update(&mut model, press(KeyCode::Down));
        assert!(!ui.discovery.as_ref().unwrap().is_consent_pending());
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.candidates.is_some());
        assert!(!ui.candidates.as_ref().unwrap().has_scope());
        ui.update(&mut model, press(KeyCode::End));
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.domain.is_some());
        assert!(!ui.domain.as_ref().unwrap().is_running());
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(ui.domain.as_ref().unwrap().is_dns_confirming());
        ui.update(&mut model, press(KeyCode::Enter));
        assert!(!ui.domain.as_ref().unwrap().is_running());
        assert!(!ui.domain.as_ref().unwrap().is_dns_confirming());
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
                draw_issuance(
                    f,
                    a,
                    &IssueFlow::Input("device-a".into()),
                    None,
                    kind,
                    None,
                    0,
                )
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
            assert!(confirm.contains("подтвердить и сохранить"));
            let failed =
                render(|f, a| draw_issuance(f, a, &IssueFlow::SaveFailed, None, kind, None, 0));
            assert!(failed.contains("ссылка заблокирована"));
            let offer = render(|f, a| draw_issuance(f, a, &IssueFlow::Offer, None, kind, None, 0));
            assert!(offer.contains("Одноразовая"));
            assert!(offer.contains("сервер ещё не изменён"));
            assert!(!offer.contains(hidden));
        }
        for (flow, label) in [
            (IssueFlow::Saving, "Конфиденциальная ссылка скрыта"),
            (IssueFlow::ConfirmExport, "Ссылка не будет показана"),
            (IssueFlow::Exporting, "Работающий процесс не обновляется"),
            (
                IssueFlow::Exported(PathBuf::from("private.invite")),
                "Файл содержит bearer",
            ),
            (IssueFlow::ExportFailed, "Секрет повторно не выдаётся"),
        ] {
            let screen =
                render(|f, a| draw_issuance(f, a, &flow, None, IssueKind::NewUser, None, 0));
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
                "отдельного применения прав",
            ),
            (DisableFlow::Saving, "Работающий процесс не изменяется"),
            (DisableFlow::SaveFailed, "Изменения НЕ сохранены"),
            (DisableFlow::Done, "Применить права доступа"),
        ] {
            let screen = render(|f, a| draw_revocation(f, a, &flow, None, None, 0));
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
            (ImportFlow::RefreshSaving, "Работающий процесс не меняется"),
            (
                ImportFlow::RefreshDone,
                "соединение и системный прокси не менялись",
            ),
            (ImportFlow::Saving, "Сохраняем профиль и ключ"),
            (ImportFlow::Done, "Профиль сохранён"),
            (ImportFlow::Failed, "Импорт НЕ подтверждён"),
        ] {
            let screen = render(|f, a| draw_import(f, a, &flow, None, None));
            assert!(screen.contains(label), "{screen}");
            assert!(!screen.contains(hidden));
        }
    }
}
