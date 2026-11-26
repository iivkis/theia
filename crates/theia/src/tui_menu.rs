//! Discoverable, role-specific menu. Actions reuse the existing guarded forms.
use crate::{
    config::{self, Config},
    security_profile::SecurityMode,
    tui_widgets::{self, ACCENT, FOCUS, MUTED, SURFACE, TEXT},
    Role,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph, Wrap},
    Frame,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Shortcut(KeyCode, KeyModifiers),
    Config,
    ServerProcess,
    Traffic,
    Close,
}
const fn key(c: char) -> Action {
    Action::Shortcut(KeyCode::Char(c), KeyModifiers::NONE)
}
const fn ctrl(c: char) -> Action {
    Action::Shortcut(KeyCode::Char(c), KeyModifiers::CONTROL)
}

#[derive(Clone, Copy)]
struct Entry {
    label: &'static str,
    action: Action,
    requires_config: bool,
}
const fn entry(label: &'static str, action: Action) -> Entry {
    Entry {
        label,
        action,
        requires_config: true,
    }
}
const fn always(label: &'static str, action: Action) -> Entry {
    Entry {
        label,
        action,
        requires_config: false,
    }
}
struct Group {
    title: &'static str,
    entries: &'static [Entry],
}
const SERVER: &[Group] = &[
    Group {
        title: "Сервер и состояние",
        entries: &[
            always(
                "Запуск / остановка локального сервера",
                Action::ServerProcess,
            ),
            always("Проверить сервер / применить / откатить", key('v')),
            always("Монитор трафика этого процесса", Action::Traffic),
            always("Проверить готовность к перезапуску", key('R')),
        ],
    },
    Group {
        title: "Входящие подключения",
        entries: &[
            entry("Создать подключение (выбор защиты)", key('N')),
            always("Мастер REALITY (новое подключение)", key('W')),
            entry(
                "Изменить выбранный параметр",
                Action::Shortcut(KeyCode::Enter, KeyModifiers::NONE),
            ),
            entry("Изменить сертификат / ключ Own-TLS", key('E')),
            entry("Выбрать пользователей с доступом", key('G')),
            entry("Настроить лимиты соединений", key('Q')),
            entry("Удалить выбранное подключение", key('D')),
            entry("Сохранить изменения", ctrl('s')),
        ],
    },
    Group {
        title: "Пользователи и приглашения",
        entries: &[
            entry("Создать пользователя и выдать приглашение", key('u')),
            entry("Публичное приглашение без токена", key('l')),
            entry("Обновить токен пользователя", key('t')),
            entry("Отключить пользователя", key('x')),
            entry("Восстановить доступ с новым токеном", key('b')),
            entry("Удалить пользователя без доступа", key('U')),
        ],
    },
    Group {
        title: "REALITY: обслуживание",
        entries: &[
            entry("Состояние, ротация и восстановление", key('V')),
            always("Комплект по готовому плану (расширенные)", key('w')),
            entry("Зарегистрировать существующий комплект", key('M')),
            entry("Независимая замена доверия", key('K')),
            always("Диагностика сети (без автоматических запросов)", key('p')),
        ],
    },
    Group {
        title: "Конфигурация",
        entries: &[
            always("Открыть или создать конфигурацию", Action::Config),
            entry("Сохранить черновик", ctrl('s')),
            entry("Проверить и применить авторизацию", ctrl('r')),
        ],
    },
];
const CLIENT: &[Group] = &[
    Group {
        title: "Подключение",
        entries: &[
            always("Состояние / подключить / отключить / Apply", key('V')),
            always("Монитор трафика этого процесса", Action::Traffic),
            entry("Режим подключения (прокси / TUN)", key('P')),
        ],
    },
    Group {
        title: "Профили и приглашения",
        entries: &[
            always("Импорт ключа, файла или изображения QR", key('i')),
            always("Расширенный импорт REALITY", key('I')),
            entry("Создать профиль", key('N')),
            entry("Выбрать активный профиль", key('A')),
            entry(
                "Изменить выбранное поле профиля",
                Action::Shortcut(KeyCode::Enter, KeyModifiers::NONE),
            ),
            entry("Изменить CA / credential Own-TLS", key('E')),
            entry("Публичное приглашение без токена", key('l')),
            entry("Удалить выбранный профиль", key('D')),
            entry("Сохранить изменения", ctrl('s')),
        ],
    },
    Group {
        title: "REALITY: доверие",
        entries: &[
            always("Отдельный enrollment", key('I')),
            entry("Регистрация готовых материалов", key('M')),
            entry("Повторное подтверждение доверия", key('K')),
            entry("Состояние, обновление credential и recovery", key('V')),
        ],
    },
    Group {
        title: "Конфигурация",
        entries: &[
            always("Открыть или создать конфигурацию", Action::Config),
            entry("Сохранить черновик", ctrl('s')),
        ],
    },
];

const STARTUP_SERVER: &[Group] = &[
    Group {
        title: "Состояние сервера",
        entries: &[
            always(
                "Запуск / остановка локального сервера",
                Action::ServerProcess,
            ),
            always("Проверить сервер", key('v')),
            always("Монитор трафика", Action::Traffic),
            always("Проверить готовность к перезапуску", key('R')),
        ],
    },
    Group {
        title: "Дополнительно",
        entries: &[
            always("Сетевая диагностика", key('p')),
            always("Комплект по готовому плану", key('w')),
            always("Открыть конфигурацию", Action::Config),
        ],
    },
];
const STARTUP_CLIENT: &[Group] = &[Group {
    title: "Дополнительно",
    entries: &[
        always("Монитор трафика", Action::Traffic),
        always("Открыть сохранённые настройки", Action::Config),
    ],
}];

pub(crate) struct Menu {
    role: Role,
    group: usize,
    item: Option<usize>,
    configured: bool,
    notice: Option<&'static str>,
}
impl Menu {
    pub(crate) fn new(role: Role, configured: bool) -> Self {
        Self {
            role,
            group: 0,
            item: None,
            configured,
            notice: None,
        }
    }

    fn groups(&self) -> &'static [Group] {
        match (self.role, self.configured) {
            (Role::Server, true) => SERVER,
            (Role::Client, true) => CLIENT,
            (Role::Server, false) => STARTUP_SERVER,
            (Role::Client, false) => STARTUP_CLIENT,
        }
    }

    fn count(&self) -> usize {
        if self.item.is_some() {
            self.groups()[self.group].entries.len()
        } else {
            self.groups().len()
        }
    }

    fn selected(&self) -> usize {
        self.item.unwrap_or(self.group)
    }

    pub(crate) fn key(&mut self, key: KeyCode) -> Option<Action> {
        let selected = self.selected();
        let count = self.count();
        self.notice = None;
        let next = match key {
            KeyCode::Left => {
                self.item = None;
                return None;
            }
            KeyCode::Esc | KeyCode::Backspace | KeyCode::F(10) => {
                if self.item.take().is_none() || key == KeyCode::F(10) {
                    return Some(Action::Close);
                }
                return None;
            }
            KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => (selected + 1).min(count - 1),
            KeyCode::Home => 0,
            KeyCode::End => count - 1,
            KeyCode::PageUp => selected.saturating_sub(5),
            KeyCode::PageDown => (selected + 5).min(count - 1),
            KeyCode::Right => {
                if self.item.is_none() {
                    self.item = Some(0);
                }
                return None;
            }
            KeyCode::Enter => {
                if let Some(item) = self.item {
                    let e = self.groups()[self.group].entries[item];
                    if e.requires_config && !self.configured {
                        self.notice = Some("Сначала откройте конфигурацию: F3.");
                        return None;
                    }
                    return Some(e.action);
                }
                self.item = Some(0);
                return None;
            }
            _ => return None,
        };
        if self.item.is_some() {
            self.item = Some(next);
        } else {
            self.group = next;
        }
        None
    }

    /// The menu is a workspace, not a list of undocumented hotkeys.
    /// Only the existing action dispatcher can execute an operation.
    #[allow(dead_code)]
    pub(crate) fn categories(role: Role) -> Vec<&'static str> {
        let groups = match role {
            Role::Server => SERVER,
            Role::Client => CLIENT,
        };
        groups.iter().map(|g| g.title).collect()
    }

    #[allow(dead_code)]
    pub(crate) fn select_category(&mut self, index: usize) {
        if index < self.groups().len() {
            self.group = index;
            self.item = Some(0);
            self.notice = None;
        }
    }

    fn columns(area: Rect) -> [Rect; 2] {
        let parts = Layout::horizontal([Constraint::Length(29), Constraint::Min(1)]).split(area);
        [parts[0], parts[1]]
    }

    fn visible_start(selected: usize, count: usize, height: usize) -> usize {
        selected
            .saturating_sub(height.saturating_sub(1))
            .min(count.saturating_sub(height))
    }

    pub(crate) fn click(&mut self, area: Rect, x: u16, y: u16) {
        if area.width < 76 || area.height < 8 {
            let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(area);
            let rect = parts[0];
            if x > rect.x
                && x < rect.right().saturating_sub(1)
                && y > rect.y
                && y < rect.bottom().saturating_sub(1)
            {
                let height = usize::from(rect.height.saturating_sub(2));
                let index = Self::visible_start(self.selected(), self.count(), height)
                    + usize::from(y - rect.y - 1);
                if index < self.count() {
                    if self.item.is_some() {
                        self.item = Some(index);
                    } else {
                        self.group = index;
                    }
                    self.notice = None;
                }
            }
            return;
        }
        let content = Layout::vertical([Constraint::Min(1), Constraint::Length(3)]).split(area);
        let [left, right] = Self::columns(content[0]);
        let index = |rect: Rect, selected: usize, count: usize| -> Option<usize> {
            if x <= rect.x
                || x >= rect.right().saturating_sub(1)
                || y <= rect.y
                || y >= rect.bottom().saturating_sub(1)
            {
                return None;
            }
            let height = usize::from(rect.height.saturating_sub(2));
            let i = Self::visible_start(selected, count, height) + usize::from(y - rect.y - 1);
            (i < count).then_some(i)
        };
        if let Some(i) = index(left, self.group, self.groups().len()) {
            self.select_category(i);
        } else if let Some(i) = index(
            right,
            self.item.unwrap_or(0),
            self.groups()[self.group].entries.len(),
        ) {
            self.item = Some(i);
            self.notice = None;
        }
        // A click selects only. Enter still goes through all guards.
    }

    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        tui_widgets::canvas(frame, area);
        if area.width < 76 || area.height < 8 {
            let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(area);
            let count = self.count();
            let selected = self.selected();
            let height = usize::from(parts[0].height.saturating_sub(2));
            let start = Self::visible_start(selected, count, height);
            let items = (start..(start + height).min(count))
                .map(|i| {
                    let (label, enabled) = if self.item.is_some() {
                        let entry = self.groups()[self.group].entries[i];
                        (entry.label, self.configured || !entry.requires_config)
                    } else {
                        (self.groups()[i].title, true)
                    };
                    let style = if i == selected {
                        Style::default()
                            .fg(ACCENT)
                            .bg(FOCUS)
                            .add_modifier(Modifier::BOLD)
                    } else if !enabled {
                        Style::default().fg(MUTED)
                    } else {
                        Style::default()
                    };
                    ListItem::new(format!(
                        "{} {label}{}",
                        if i == selected { "›" } else { " " },
                        if enabled {
                            ""
                        } else {
                            " [нужен файл]"
                        }
                    ))
                    .style(style)
                })
                .collect::<Vec<_>>();
            let title = if self.item.is_some() {
                self.groups()[self.group].title
            } else {
                self.title()
            };
            frame.render_widget(
                List::new(items).block(tui_widgets::section(
                    &format!("{title} · {}/{}", selected + 1, count),
                    true,
                )),
                parts[0],
            );
            frame.render_widget(
                Paragraph::new(
                    self.notice
                        .unwrap_or("↑↓ выбрать · Enter открыть · Esc назад"),
                ),
                parts[1],
            );
            return;
        }
        let content = Layout::vertical([Constraint::Min(1), Constraint::Length(3)]).split(area);
        let [left, right] = Self::columns(content[0]);
        let groups = self.groups();
        let render_list = |frame: &mut Frame<'_>,
                           rect: Rect,
                           title: &str,
                           items: Vec<(&str, bool)>,
                           selected: usize,
                           focused: bool| {
            let height = usize::from(rect.height.saturating_sub(2));
            let start = Self::visible_start(selected, items.len(), height);
            let rows: Vec<ListItem<'_>> = items
                .into_iter()
                .enumerate()
                .skip(start)
                .take(height)
                .map(|(i, (label, enabled))| {
                    let style = if i == selected {
                        Style::default()
                            .fg(if enabled { ACCENT } else { MUTED })
                            .bg(if focused { FOCUS } else { SURFACE })
                            .add_modifier(Modifier::BOLD)
                    } else if enabled {
                        Style::default()
                    } else {
                        Style::default().fg(MUTED)
                    };
                    ListItem::new(Line::from(vec![
                        Span::raw(if i == selected { " › " } else { "   " }),
                        Span::raw(label),
                        Span::raw(if enabled {
                            ""
                        } else {
                            " [нужен файл]"
                        }),
                    ]))
                    .style(style)
                })
                .collect();
            frame.render_widget(
                List::new(rows).block(tui_widgets::section(title, focused)),
                rect,
            );
        };
        render_list(
            frame,
            left,
            " Разделы ",
            groups.iter().map(|g| (g.title, true)).collect(),
            self.group,
            self.item.is_none(),
        );
        let entries = groups[self.group].entries;
        render_list(
            frame,
            right,
            groups[self.group].title,
            entries
                .iter()
                .map(|e| (e.label, !e.requires_config || self.configured))
                .collect(),
            self.item.unwrap_or(0),
            self.item.is_some(),
        );
        let hint = self.notice.unwrap_or(if self.item.is_none() {
            "↑ ↓ выбор · → действия · Enter открыть · Esc назад"
        } else {
            "↑ ↓ выбор · ← разделы · Enter открыть · Esc назад"
        });
        frame.render_widget(
            Paragraph::new(tui_widgets::key_line(hint))
                .wrap(Wrap { trim: true })
                .style(Style::default().bg(SURFACE).fg(TEXT)),
            content[1],
        );
    }

    pub(crate) fn title(&self) -> &'static str {
        match self.role {
            Role::Server => "Действия сервера",
            Role::Client => "Действия клиента",
        }
    }

    #[cfg(test)]
    fn body(&self, rows: usize) -> String {
        let groups = self.groups();
        let count = self.count();
        let selected = self.selected();
        let height = rows.saturating_sub(5).max(1);
        let start = selected
            .saturating_sub(height - 1)
            .min(count.saturating_sub(height));
        let end = (start + height).min(count);
        let title = if self.item.is_some() {
            groups[self.group].title
        } else {
            "Выберите раздел"
        };
        let mut out = format!("{title}  •  {} / {}\n", selected + 1, count);
        for (i, (name, available)) in (start..end).map(|i| {
            let (name, available) = if self.item.is_some() {
                let e = groups[self.group].entries[i];
                (e.label, !e.requires_config || self.configured)
            } else {
                (groups[i].title, true)
            };
            (i, (name, available))
        }) {
            out.push_str(if i == selected { "› " } else { "  " });
            out.push_str(name);
            if !available {
                out.push_str(" [нужен TOML]");
            }
            out.push('\n');
        }
        out.push_str(
            self.notice
                .unwrap_or("↑↓ выбор · Enter открыть · Esc назад"),
        );
        out
    }
}

/// Read-only local chooser. Picking a path never opens, creates or overwrites a configuration.
pub(crate) struct FileBrowser {
    config_only: bool,
    directory: std::path::PathBuf,
    entries: Vec<(std::path::PathBuf, bool)>,
    focus: usize,
    error: String,
}
impl FileBrowser {
    fn new(input: &str) -> Self {
        Self::with_mode(input, true)
    }
    pub(crate) fn files(input: &str) -> Self {
        Self::with_mode(
            if input.starts_with("theia://") {
                ""
            } else {
                input
            },
            false,
        )
    }
    fn with_mode(input: &str, config_only: bool) -> Self {
        let path = std::path::PathBuf::from(input);
        let directory = if path.is_dir() {
            path
        } else {
            path.parent()
                .filter(|p| p.is_dir())
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()))
        };
        let directory = std::path::absolute(&directory).unwrap_or(directory);
        let mut browser = Self {
            config_only,
            directory,
            entries: Vec::new(),
            focus: 0,
            error: String::new(),
        };
        browser.refresh();
        browser
    }
    fn refresh(&mut self) {
        self.entries.clear();
        self.focus = 0;
        self.error.clear();
        match std::fs::read_dir(&self.directory) {
            Ok(entries) => {
                for entry in entries.take(2048).flatten() {
                    let Ok(kind) = entry.file_type() else {
                        continue;
                    };
                    let path = entry.path();
                    if path
                        .to_str()
                        .is_none_or(|s| s.len() > 4096 || s.chars().any(char::is_control))
                    {
                        continue;
                    }
                    if kind.is_dir()
                        || (kind.is_file()
                            && (!self.config_only
                                || path
                                    .extension()
                                    .is_some_and(|s| s.eq_ignore_ascii_case("toml"))))
                    {
                        self.entries.push((path, kind.is_dir()));
                    }
                }
                self.entries
                    .sort_by(|(a, ad), (b, bd)| bd.cmp(ad).then_with(|| a.cmp(b)));
            }
            Err(_) => self.error =
                "Каталог недоступен. Выберите родительский каталог или вернитесь к ручному вводу."
                    .into(),
        }
    }
    fn entry_offset(&self) -> usize {
        if self.config_only {
            2
        } else {
            1
        }
    }
    pub(crate) fn select_field(&mut self, id: usize) {
        if id < self.entries.len() + self.entry_offset() {
            self.focus = id;
        }
    }
    pub(crate) fn form(&self) -> crate::tui_widgets::Form {
        use crate::tui_widgets::{Field, Form};
        let mut fields = vec![Field {
            id: 0,
            label: "Родительский каталог",
            value: "..".into(),
            hint: "Enter — подняться на уровень выше.",
        }];
        if self.config_only {
            fields.push(Field {
                id: 1,
                label: "Выбрать этот каталог",
                value: self.directory.display().to_string(),
                hint: "Enter — использовать каталог и вернуться к имени файла.",
            });
        }
        fields.extend(self.entries.iter().enumerate().map(|(i, (path, dir))| {
            Field {
                id: i + self.entry_offset(),
                label: if *dir {
                    "Каталог"
                } else if self.config_only {
                    "Конфигурация TOML"
                } else {
                    "Файл"
                },
                value: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                hint: if *dir {
                    "Enter — открыть каталог."
                } else {
                    "Enter — выбрать путь без загрузки файла."
                },
            }
        }));
        Form {
            fields,
            selected: self.focus,
            lead: format!("Каталог: {} · до 2048 записей", self.directory.display()),
            error: self.error.clone(),
        }
    }
    pub(crate) fn key(&mut self, key: KeyCode, filename: &str) -> Option<std::path::PathBuf> {
        let count = self.entries.len() + self.entry_offset();
        match key {
            KeyCode::Up | KeyCode::BackTab => self.focus = (self.focus + count - 1) % count,
            KeyCode::Down | KeyCode::Tab => self.focus = (self.focus + 1) % count,
            KeyCode::Home => self.focus = 0,
            KeyCode::End => self.focus = count - 1,
            KeyCode::Enter => match self.focus {
                0 => {
                    if let Some(parent) = self.directory.parent() {
                        self.directory = parent.to_path_buf();
                        self.refresh();
                    }
                }
                1 if self.config_only => return Some(self.directory.join(filename)),
                i => {
                    if let Some((path, dir)) = self.entries.get(i - self.entry_offset()).cloned() {
                        if dir {
                            self.directory = path;
                            self.refresh();
                        } else {
                            return Some(path);
                        }
                    }
                }
            },
            _ => {}
        }
        None
    }
}

// First-run input is independent of the security mode and contains no
// editable protocol parameters. Only the existing validated backends save.
type FirstInviteRead =
    Result<(Zeroizing<String>, crate::client_import::ProductSource), &'static str>;

struct FirstInvite {
    source: Zeroizing<String>,
    own: Option<crate::invite::Invitation>,
    ca: String,
    reference: String,
    focus: usize,
    review: bool,
    error: Option<&'static str>,
    browser: Option<FileBrowser>,
    reading: Option<std::sync::mpsc::Receiver<FirstInviteRead>>,
}

enum FirstInviteAction {
    Stay,
    Back,
    Save(crate::invite::Invitation, String, Option<String>),
}

impl FirstInvite {
    fn new() -> Self {
        Self {
            source: Zeroizing::new(String::new()),
            own: None,
            ca: String::new(),
            reference: String::new(),
            focus: 0,
            review: false,
            error: None,
            browser: None,
            reading: None,
        }
    }
    fn paste(&mut self, value: &str) {
        if self.browser.is_some() || self.review || self.reading.is_some() {
            return;
        }
        let value = value.trim_end_matches(['\r', '\n']);
        if value.chars().any(char::is_control) {
            if self.own.is_none() {
                self.source = Zeroizing::new(String::new());
            }
            self.error = Some("Ввод содержит недопустимые символы. Вставьте значение целиком.");
            return;
        }
        if self.own.is_none() {
            if self.source.len().saturating_add(value.len()) <= crate::invite::MAX_URI {
                self.source.push_str(value);
                self.error = None;
            } else {
                self.source = Zeroizing::new(String::new());
                self.error =
                    Some("Ключ слишком длинный. Вставьте его целиком или запросите новый.");
            }
        } else {
            let field = if self.focus == 0 {
                &mut self.ca
            } else {
                &mut self.reference
            };
            if field.len().saturating_add(value.len()) <= 4096 {
                field.push_str(value);
            }
        }
    }
    fn select_field(&mut self, id: usize) {
        if let Some(browser) = self.browser.as_mut() {
            browser.select_field(id);
        } else if !self.review && self.reading.is_none() {
            self.focus = if self.own.as_ref().is_some_and(|i| !i.has_token()) {
                id.min(1)
            } else {
                0
            };
        }
    }
    fn form(&self) -> Option<crate::tui_widgets::Form> {
        use crate::tui_widgets::{Field, Form};
        if let Some(browser) = &self.browser {
            return Some(browser.form());
        }
        if self.review || self.reading.is_some() {
            return None;
        }
        let (fields, lead) = if let Some(invite) = &self.own {
            let mut fields = vec![Field {
                id: 0,
                label: "Доверенный сертификат (CA)",
                value: if self.ca.is_empty() {
                    String::new()
                } else {
                    "Файл выбран".into()
                },
                hint: "F6 — выбрать PEM-сертификат, полученный отдельно от администратора.",
            }];
            if !invite.has_token() {
                fields.push(Field {
                    id: 1,
                    label: "Ссылка на отдельный ключ",
                    value: if self.reference.is_empty() {
                        String::new()
                    } else {
                        "Ссылка указана".into()
                    },
                    hint: "Для публичного приглашения укажите env:ИМЯ. Сам секрет не вставляйте.",
                });
            }
            (fields, format!("Тип определён: собственный TLS\nСервер: {} · {}\nПодтвердите доверие к серверу.", invite.endpoint, invite.server_name))
        } else {
            (
                vec![Field {
                    id: 0,
                    label: "Ключ Theia",
                    value: if self.source.is_empty() {
                        String::new()
                    } else {
                        format!("Введено {} байт (скрыто)", self.source.len())
                    },
                    hint:
                        "Вставьте theia:// или выберите файл приглашения / изображение QR через F6.",
                }],
                "Получите личный ключ у администратора. Тип подключения определится автоматически."
                    .into(),
            )
        };
        Some(Form {
            fields,
            selected: self.focus,
            lead,
            error: self.error.unwrap_or_default().into(),
        })
    }
    fn guide(&self) -> (usize, usize, &'static str, &'static str) {
        if self.browser.is_some() {
            return (
                1,
                5,
                "Выбор файла",
                "↑↓ выбрать · Enter принять · Esc назад",
            );
        }
        if self.reading.is_some() {
            return (2, 5, "Определение типа", "Локальная проверка");
        }
        if self.review {
            return (4, 5, "Сохранение профиля", "y сохранить · n/Esc назад");
        }
        if self.own.is_some() {
            (
                3,
                5,
                "Параметры и доверие",
                "↑↓ поле · F6 файл · Enter проверить · Esc назад",
            )
        } else {
            (
                1,
                5,
                "Вставить ключ",
                "Enter проверить · F6 файл/QR · Ctrl+U очистить · Esc назад",
            )
        }
    }
    fn body(&self, path: &str) -> String {
        if self.reading.is_some() {
            return "Проверяем приглашение локально. Сеть не используется.".into();
        }
        if self.review {
            if let Some(invite) = &self.own {
                return format!("Тип: собственный TLS\nПрофиль: {}\nСервер: {}\nИмя TLS: {}\nДоверенный сертификат выбран и проверен локально.\n{credential}\n\nФайл настроек: {path}\nСоздаётся первый активный профиль. Соединение и системный прокси не запускаются.", invite.id, invite.endpoint, invite.server_name, credential = if invite.has_token() { "Личный ключ будет сохранён в защищённом хранилище." } else { "Будет использована указанная ссылка на отдельный ключ." });
            }
        }
        String::new()
    }
    fn key(&mut self, key: KeyEvent) -> FirstInviteAction {
        if self.reading.is_some() {
            if key.code == KeyCode::Esc {
                self.reading = None;
                self.error = None;
            }
            return FirstInviteAction::Stay;
        }
        if let Some(browser) = self.browser.as_mut() {
            if key.code == KeyCode::Esc {
                self.browser = None;
            } else if let Some(path) = browser.key(key.code, "") {
                if let Some(path) = path
                    .to_str()
                    .filter(|p| p.len() <= 4090 && !p.chars().any(char::is_control))
                {
                    if self.own.is_some() {
                        self.ca = format!("file:{path}");
                    } else {
                        self.source = Zeroizing::new(path.to_owned());
                    }
                    self.error = None;
                } else {
                    self.error = Some("Недопустимый путь файла.");
                }
                self.browser = None;
            }
            return FirstInviteAction::Stay;
        }
        if self.review {
            match key.code {
                KeyCode::Char('y') if key.modifiers.is_empty() => {
                    if let Some(invite) = self.own.take() {
                        return FirstInviteAction::Save(
                            invite,
                            std::mem::take(&mut self.ca),
                            (!self.reference.is_empty())
                                .then(|| std::mem::take(&mut self.reference)),
                        );
                    }
                }
                KeyCode::Esc | KeyCode::Char('n') => self.review = false,
                _ => {}
            }
            return FirstInviteAction::Stay;
        }
        self.error = None;
        match key.code {
            KeyCode::Esc => {
                if self.own.take().is_some() {
                    self.ca.clear();
                    self.reference.clear();
                    self.focus = 0;
                } else {
                    return FirstInviteAction::Back;
                }
            }
            KeyCode::F(6) if self.focus == 0 => {
                self.browser = Some(FileBrowser::files(if self.own.is_some() {
                    self.ca.strip_prefix("file:").unwrap_or(&self.ca)
                } else {
                    self.source.as_str()
                }));
            }
            KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab
                if self.own.as_ref().is_some_and(|i| !i.has_token()) =>
            {
                self.focus = 1 - self.focus
            }
            KeyCode::Enter => {
                if let Some(invite) = &self.own {
                    if !self.ca.is_empty() && !self.ca.starts_with("file:") {
                        self.ca = format!("file:{}", self.ca);
                    }
                    if crate::client_import::checked_ca_ref(Some(&self.ca)).is_err() {
                        self.error = Some("Выберите доверенный PEM-сертификат через F6.");
                    } else if !invite.has_token()
                        && !crate::client_import::valid_explicit_reference(&self.reference)
                    {
                        self.error = Some("Укажите отдельную ссылку env:ИМЯ.");
                    } else {
                        self.review = true;
                    }
                } else if !self.source.is_empty() {
                    let source = self.source.clone();
                    let (tx, rx) = std::sync::mpsc::channel();
                    let worker = std::thread::Builder::new().name("theia-first-invite".into()).spawn(move || {
                        let result = (|| {
                            let source = if crate::qr_import::image_path(source.trim()) {
                                crate::qr_import::scan_file(source.trim())?
                            } else { source };
                            let product = crate::client_import::read_product_source(source.trim())
                                .map_err(|_| "Не удалось прочитать ключ. Проверьте ссылку целиком или выберите файл.")?;
                            Ok((source, product))
                        })();
                        let _ = tx.send(result);
                    });
                    if worker.is_ok() {
                        self.reading = Some(rx);
                    } else {
                        self.error = Some("Не удалось начать проверку ключа.");
                    }
                } else {
                    self.error = Some("Вставьте ключ или выберите файл.");
                }
            }
            KeyCode::Backspace => {
                if self.own.is_none() {
                    self.source.pop();
                } else if self.focus == 0 {
                    self.ca.pop();
                } else {
                    self.reference.pop();
                }
            }
            KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                if self.own.is_none() {
                    self.source = Zeroizing::new(String::new());
                } else if self.focus == 0 {
                    self.ca.clear();
                } else {
                    self.reference.clear();
                }
            }
            KeyCode::Char(ch)
                if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
            {
                let mut buf = [0; 4];
                self.paste(ch.encode_utf8(&mut buf));
            }
            _ => {}
        }
        FirstInviteAction::Stay
    }
}

pub(crate) struct ConfigDialog {
    pub(crate) role: Role,
    input: String,
    choice: usize,
    error: Option<&'static str>,
    loading: Option<std::sync::mpsc::Receiver<Result<crate::tui_editor::Editor, &'static str>>>,
    setup: Option<FirstSetup>,
    reality: Option<crate::tui_reality_provision::ProvisionPanel>,
    enrollment: Option<crate::tui_reality_enroll::EnrollmentPanel>,
    first_invite: Option<FirstInvite>,
    imported: bool,
    import_after_load: bool,
    creating: bool,
    browser: Option<FileBrowser>,
}
impl ConfigDialog {
    pub(crate) fn new(role: Role, existing: Option<&std::path::Path>) -> Self {
        let filename = match role {
            Role::Server => "server.toml",
            Role::Client => "client.toml",
        };
        let path = existing
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| default_config(filename));
        let input = path
            .to_str()
            .filter(|p| p.len() <= 4096 && !p.chars().any(char::is_control))
            .unwrap_or(filename)
            .to_owned();
        Self {
            role,
            input,
            choice: 0,
            error: None,
            loading: None,
            setup: None,
            reality: None,
            enrollment: None,
            first_invite: None,
            imported: false,
            import_after_load: false,
            creating: false,
            browser: None,
        }
    }
    pub(crate) fn imported(&self) -> bool {
        self.imported
    }

    pub(crate) fn import_after_load(&self) -> bool {
        self.import_after_load
    }

    pub(crate) fn begin_client_import(&mut self) {
        if self.role != Role::Client {
            return;
        }
        if std::path::Path::new(&self.input).is_file() {
            self.choice = 0;
            self.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
            self.import_after_load = self.loading.is_some();
        } else {
            self.choice = 1;
            self.key(KeyEvent::new(KeyCode::F(4), KeyModifiers::NONE));
        }
    }

    pub(crate) fn suggested_mode(role: Role) -> usize {
        let filename = if role == Role::Server {
            "server.toml"
        } else {
            "client.toml"
        };
        if default_config(filename).is_file() {
            0
        } else {
            1
        }
    }
    pub(crate) fn prefer_reality(&mut self) {
        self.prefer_mode(1);
    }
    pub(crate) fn prefer_mode(&mut self, choice: usize) {
        self.choice = choice.min(2);
    }
    pub(crate) fn paste(&mut self, text: &str) {
        if self.browser.is_some() {
            return;
        }
        if let Some(panel) = self.first_invite.as_mut() {
            panel.paste(text);
            return;
        }
        if let Some(panel) = self.enrollment.as_mut() {
            panel.paste(text);
            return;
        }
        if let Some(panel) = self.reality.as_mut() {
            panel.paste(text);
            return;
        }
        if let Some(setup) = &mut self.setup {
            setup.paste(text);
            return;
        }
        if self.loading.is_none()
            && self.input.len().saturating_add(text.len()) <= 4096
            && !text.chars().any(char::is_control)
        {
            self.input.push_str(text);
        }
    }
    pub(crate) fn confirmation_choice(&self) -> Option<(char, &'static str)> {
        if self.loading.is_some() || self.browser.is_some() {
            return None;
        }
        if let Some(panel) = &self.first_invite {
            return (panel.review && panel.browser.is_none() && panel.reading.is_none())
                .then_some(('y', "Сохранить профиль"));
        }
        if let Some(panel) = &self.reality {
            return panel.confirmation_choice();
        }
        if let Some(panel) = &self.enrollment {
            return panel.confirmation_choice();
        }
        self.setup
            .as_ref()
            .filter(|s| s.review.is_some())
            .map(|_| ('y', "Создать настройки"))
    }

    pub(crate) fn reality_success_first_user(&self) -> Option<&str> {
        self.reality.as_ref().and_then(|p| p.success_first_user())
    }

    pub(crate) fn reality_succeeded(&self) -> bool {
        self.reality.as_ref().is_some_and(|p| p.succeeded())
    }

    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        if self.loading.is_some() {
            return false;
        }
        if let Some(panel) = self.first_invite.as_mut() {
            match panel.key(key) {
                FirstInviteAction::Stay => {}
                FirstInviteAction::Back => {
                    self.first_invite = None;
                }
                FirstInviteAction::Save(invite, ca, reference) => {
                    let path = std::path::PathBuf::from(&self.input);
                    let (tx, rx) = std::sync::mpsc::channel();
                    match std::thread::Builder::new()
                        .name("theia-first-own-tls".into())
                        .spawn(move || {
                            let result = crate::tui_editor::Editor::create_first_invitation(
                                &path,
                                &invite,
                                &ca,
                                reference.as_deref(),
                            );
                            let _ = tx.send(result);
                        }) {
                        Ok(_) => {
                            self.loading = Some(rx);
                            self.creating = true;
                            self.imported = true;
                            self.first_invite = None;
                        }
                        Err(_) => {
                            self.first_invite = None;
                            self.error = Some("Не удалось начать сохранение. Повторите импорт.");
                        }
                    }
                }
            }
            return false;
        }
        if let Some(panel) = self.enrollment.as_mut() {
            if panel.key(key) {
                self.enrollment = None;
            }
            return false;
        }
        if let Some(panel) = self.reality.as_mut() {
            let succeeded = panel.succeeded();
            if panel.key(key) {
                self.reality = None;
                return succeeded;
            }
            return false;
        }
        if let Some(setup) = &mut self.setup {
            match setup.key(key) {
                SetupAction::Continue => return false,
                SetupAction::Back => {
                    self.setup = None;
                    return false;
                }
                SetupAction::Create(config) => {
                    let path = std::path::PathBuf::from(&self.input);
                    let role = self.role;
                    let (tx, rx) = std::sync::mpsc::channel();
                    match std::thread::Builder::new().name("theia-tui-create".into()).spawn(move || {
                        let result = std::path::absolute(path).map_err(|_| "Неверный путь")
                            .and_then(|path| {
                                config::guarded_create(&path, &config).map_err(|e| match e {
                                    config::WriteFailure::BeforeReplace(_) => "Файл не создан: проверьте путь, права и отсутствие существующего TOML.",
                                    config::WriteFailure::AfterReplace(_) => "Создание не подтверждено. Проверьте файл через открытие, не повторяйте запись.",
                                })?;
                                crate::tui_editor::Editor::load(role, &path).map_err(|_| "Файл записан, но не удалось открыть. Откройте его повторно.")
                            });
                        let _ = tx.send(result);
                    }) {
                        Ok(_) => { self.loading = Some(rx); self.creating = true; self.setup = None; self.error = None; }
                        Err(_) => { self.setup = None; self.error = Some("Не удалось запустить создание файла."); }
                    }
                    return false;
                }
            }
        }
        if let Some(browser) = self.browser.as_mut() {
            if key.code == KeyCode::Esc {
                self.browser = None;
                return false;
            }
            let filename = std::path::Path::new(&self.input)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(if self.role == Role::Server {
                    "server.toml"
                } else {
                    "client.toml"
                });
            if let Some(path) = browser.key(key.code, filename) {
                if let Some(path) = path
                    .to_str()
                    .filter(|s| s.len() <= 4096 && !s.chars().any(char::is_control))
                {
                    self.input = path.to_owned();
                    self.error = None;
                    self.browser = None;
                    if self.choice == 3 {
                        self.choice = 0;
                    }
                } else {
                    browser.error = "Недопустимый путь".into();
                }
            }
            return false;
        }
        if key.code == KeyCode::F(6) {
            self.browser = Some(FileBrowser::new(&self.input));
            return false;
        }
        let code = match key.code {
            KeyCode::Up | KeyCode::BackTab => {
                self.choice = (self.choice + 3) % 4;
                return false;
            }
            KeyCode::Down | KeyCode::Tab => {
                self.choice = (self.choice + 1) % 4;
                return false;
            }
            KeyCode::Enter if self.choice == 1 => KeyCode::F(4),
            KeyCode::Enter if self.choice == 2 => KeyCode::F(2),
            KeyCode::Enter if self.choice == 3 => {
                self.browser = Some(FileBrowser::new(&self.input));
                return false;
            }
            code => code,
        };
        match code {
            KeyCode::Esc => return true,
            KeyCode::F(2) => {
                if self.input.is_empty() {
                    self.error = Some("Укажите путь нового TOML.");
                } else {
                    self.setup = Some(FirstSetup::new(self.role));
                    self.error = None;
                }
            }
            KeyCode::F(4) => {
                if self.input.is_empty() {
                    self.error = Some("Укажите путь нового TOML.");
                } else if self.role == Role::Client {
                    let path = std::path::absolute(&self.input);
                    if path.as_ref().is_ok_and(|p| crate::bounded_input::explicit_file_path(p)
                        && matches!(std::fs::symlink_metadata(p), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
                        && p.parent().is_some_and(std::path::Path::is_dir)) {
                        self.first_invite = Some(FirstInvite::new());
                        self.error = None;
                        self.imported = false;
                    } else { self.error = Some("Выберите новый файл настроек в существующем каталоге."); }
                } else {
                    match crate::tui_reality_provision::ProvisionPanel::first(
                        std::path::PathBuf::from(&self.input),
                    ) {
                        Ok(panel) => {
                            self.reality = Some(panel);
                            self.error = None;
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
            }
            KeyCode::Enter => {
                if self.input.is_empty() {
                    self.error = Some("Укажите путь к существующему файлу.");
                    return false;
                }
                let path = std::path::PathBuf::from(&self.input);
                let role = self.role;
                let (tx, rx) = std::sync::mpsc::channel();
                match std::thread::Builder::new()
                    .name("theia-tui-config".into())
                    .spawn(move || {
                        let loaded = std::path::absolute(path)
                            .map_err(|_| "Неверный путь")
                            .and_then(|path| crate::tui_editor::Editor::load(role, &path));
                        let _ = tx.send(loaded);
                    }) {
                    Ok(_) => {
                        self.loading = Some(rx);
                        self.error = None;
                    }
                    Err(_) => self.error = Some("Не удалось запустить чтение файла."),
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => self.input.clear(),
            KeyCode::Char(ch)
                if !ch.is_control()
                    && (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                    && self.input.len().saturating_add(ch.len_utf8()) <= 4096 =>
            {
                self.input.push(ch);
            }
            _ => {}
        }
        false
    }
    pub(crate) fn poll(&mut self) -> Option<crate::tui_editor::Editor> {
        if let Some(panel) = self.first_invite.as_mut() {
            use std::sync::mpsc::TryRecvError;
            let result = match panel.reading.as_ref()?.try_recv() {
                Ok(result) => result,
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => Err("Проверка ключа прервана."),
            };
            panel.reading = None;
            match result {
                Ok((_, crate::client_import::ProductSource::OwnTls(invite))) => {
                    panel.source = Zeroizing::new(String::new());
                    panel.own = Some(invite);
                    panel.focus = 0;
                }
                Ok((source, crate::client_import::ProductSource::Reality)) => {
                    match crate::tui_reality_enroll::EnrollmentPanel::first_from_source(
                        std::path::PathBuf::from(&self.input),
                        source,
                    ) {
                        Ok(enrollment) => {
                            self.enrollment = Some(enrollment);
                            self.first_invite = None;
                        }
                        Err(error) => panel.error = Some(error),
                    }
                }
                Err(error) => panel.error = Some(error),
            }
            return None;
        }
        if let Some(panel) = self.enrollment.as_mut() {
            let result = panel.poll();
            if result.is_some() {
                self.imported = true;
            }
            return result;
        }
        if let Some(panel) = self.reality.as_mut() {
            return panel.poll();
        }
        use std::sync::mpsc::TryRecvError;
        let result = match self.loading.as_ref()?.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => {
                Err("Операция не подтверждена. Проверьте файл через открытие.")
            }
        };
        self.loading = None;
        self.creating = false;
        match result {
            Ok(editor) => Some(editor),
            Err(reason) => {
                self.imported = false;
                self.import_after_load = false;
                self.error = Some(reason);
                None
            }
        }
    }
    pub(crate) fn form(&self) -> Option<crate::tui_widgets::Form> {
        use crate::tui_widgets::{Field, Form};
        if self.loading.is_some() {
            return None;
        }
        if let Some(panel) = &self.first_invite {
            return panel.form();
        }
        if let Some(browser) = &self.browser {
            return Some(browser.form());
        }
        if let Some(panel) = &self.reality {
            return panel.form();
        }
        if let Some(panel) = &self.enrollment {
            return panel.form();
        }
        if let Some(setup) = &self.setup {
            if setup.review.is_some() {
                return None;
            }
            let hints = match setup.role {
                Role::Server => [
                    "Уникальный ID.",
                    "Один адрес для TCP и UDP.",
                    "DNS-имя сертификата.",
                    "Абсолютная file: ссылка на PEM.",
                    "Абсолютная file: ссылка; не вставляйте ключ.",
                    "Пользователь будет отключён до восстановления доступа.",
                ],
                Role::Client => [
                    "Имя профиля.",
                    "Публичный адрес и порт.",
                    "DNS-имя сервера.",
                    "Абсолютная file: ссылка на доверенный CA.",
                    "Ссылка на токен, не сам токен.",
                    "Путь /v1/... из конфигурации сервера.",
                ],
            };
            return Some(Form {
                fields: setup
                    .labels()
                    .iter()
                    .enumerate()
                    .map(|(id, label)| Field {
                        id,
                        label,
                        hint: hints[id],
                        value: if matches!(id, 3 | 4) && !setup.fields[id].is_empty() {
                            "Скрыто · ссылка введена".into()
                        } else {
                            setup.fields[id].to_string()
                        },
                    })
                    .collect(),
                selected: setup.focus,
                lead: format!("Новый файл: {}", self.input),
                error: setup.error.unwrap_or_default().to_owned(),
            });
        }
        let reality = if self.role == Role::Server {
            "SmartTheia REALITY"
        } else {
            "Импорт ключа Theia"
        };
        let fields = vec![
            Field { id: 0, label: "Открыть сохранённые настройки", value: "Для уже настроенной Theia".into(), hint: "Выберите существующий файл .toml через F6 или введите его путь." },
            Field { id: 1, label: reality, value: "Рекомендуемый мастер для новой настройки".into(), hint: "Оставьте предложенный путь, если файл ещё не существует. Существующий файл не заменяется." },
            Field { id: 2, label: "Own-TLS", value: "Расширенная ручная настройка".into(), hint: "Требуются собственный сертификат или данные доверия от администратора." },
            Field { id: 3, label: "Выбрать файл или каталог", value: "F6 · файловый браузер".into(), hint: "Выбор пути не открывает и не создаёт файл." },
        ];
        Some(Form {
            fields,
            selected: self.choice,
            lead: format!(
                "Файл настроек: {}\nEnter продолжить · F6 выбрать файл · Ctrl+U изменить путь",
                self.input
            ),
            error: self.error.unwrap_or_default().to_owned(),
        })
    }

    pub(crate) fn select_field(&mut self, id: usize) {
        if self.loading.is_some() {
            return;
        }
        if let Some(panel) = self.first_invite.as_mut() {
            panel.select_field(id);
            return;
        }
        if let Some(browser) = self.browser.as_mut() {
            browser.select_field(id);
            return;
        }
        if let Some(panel) = self.reality.as_mut() {
            panel.select_field(id);
        } else if let Some(panel) = self.enrollment.as_mut() {
            panel.select_field(id);
        } else if let Some(setup) = self.setup.as_mut() {
            if setup.review.is_none() && id < setup.fields.len() {
                setup.focus = id;
            }
        } else if id < 4 {
            self.choice = id;
        }
    }

    pub(crate) fn reference_review(&self) -> Option<crate::tui_widgets::ReferenceReview> {
        self.reality.as_ref()?.reference_review()
    }

    pub(crate) fn guide(&self) -> Option<(usize, usize, &'static str, &'static str)> {
        if let Some(panel) = &self.first_invite {
            return Some(panel.guide());
        }
        if let Some(panel) = &self.reality {
            return panel.guide();
        }
        if let Some(panel) = &self.enrollment {
            return Some(panel.guide());
        }
        self.setup.as_ref().map(|setup| {
            if setup.review.is_some() {
                (2, 2, "Подтверждение", "Y создать · N / Esc назад")
            } else {
                (
                    1,
                    2,
                    "Параметры Own-TLS",
                    "↑↓ поле · Ctrl+U очистить · Enter проверить · Esc назад",
                )
            }
        })
    }
    pub(crate) fn title(&self) -> &'static str {
        if self.browser.is_some() {
            return "Выбор файла · ↑↓ Enter Esc";
        }
        if self.first_invite.is_some() {
            "Импорт ключа Theia"
        } else if self.enrollment.is_some() {
            "Импорт REALITY"
        } else if self.reality.is_some() {
            "Мастер REALITY"
        } else if self.setup.is_some() {
            "Мастер Own-TLS"
        } else {
            "Открыть конфигурацию"
        }
    }
    pub(crate) fn body(&self) -> String {
        if self.loading.is_some() {
            return if self.creating {
                "Создаётся новый TOML без замены существующих файлов. Runtime не запускается."
                    .into()
            } else {
                "Проверяется существующий TOML; ничего не записывается.".into()
            };
        }
        if let Some(panel) = &self.first_invite {
            return panel.body(&self.input);
        }
        if let Some(panel) = &self.enrollment {
            return panel.body();
        }
        if let Some(panel) = &self.reality {
            return panel.body();
        }
        if let Some(setup) = &self.setup {
            return setup.body(&self.input);
        }
        let role = if self.role == Role::Server {
            "Сервер"
        } else {
            "Клиент"
        };
        let reality = if self.role == Role::Server {
            "SmartTheia REALITY  ·  мастер подбора, без своего сертификата"
        } else {
            "Импорт ключа Theia · Own-TLS или REALITY"
        };
        let choices = [
            ("Enter", "Открыть существующий TOML"),
            ("F4", reality),
            (
                "F2",
                "Own-TLS  ·  собственный сертификат / ручная настройка",
            ),
        ];
        let mut body = format!("{role} • открытие или создание конфигурации\n\nПУТЬ К TOML\n  {}\n\nВЫБЕРИТЕ ДЕЙСТВИЕ\n", self.input);
        for (i, (shortcut, label)) in choices.iter().enumerate() {
            body.push_str(&format!(
                "{} {shortcut:5} {label}\n",
                if i == self.choice { ">" } else { " " }
            ));
        }
        body.push_str("\n↑↓ / Tab выбрать · Enter продолжить\nПуть можно вводить сразу. Ctrl+U очистить · Esc назад");
        if let Some(error) = self.error {
            body.push_str(&format!("\nОшибка: {error}"));
        }
        body
    }
}

/// First-run Own-TLS setup. No dummy profile, implicit access or overwrite.
struct FirstSetup {
    role: Role,
    fields: Vec<Zeroizing<String>>,
    focus: usize,
    review: Option<Config>,
    error: Option<&'static str>,
}
enum SetupAction {
    Continue,
    Back,
    Create(Config),
}

impl FirstSetup {
    fn new(role: Role) -> Self {
        let fields = match role {
            Role::Server => vec!["main", "0.0.0.0:443", "", "", "", "owner"],
            Role::Client => vec!["main", "", "", "", "", ""],
        }
        .into_iter()
        .map(|s| Zeroizing::new(s.to_owned()))
        .collect();
        Self {
            role,
            fields,
            focus: 0,
            review: None,
            error: None,
        }
    }
    fn labels(&self) -> [&'static str; 6] {
        match self.role {
            Role::Server => [
                "ID подключения",
                "Адрес и порт",
                "Имя TLS (SNI)",
                "Сертификат (file:)",
                "Ключ (file:)",
                "ID первого пользователя",
            ],
            Role::Client => [
                "ID профиля",
                "Сервер (host:port)",
                "Имя TLS (SNI)",
                "CA (file:)",
                "Credential (env: или file:)",
                "Путь XHTTP (/v1/...)",
            ],
        }
    }
    fn paste(&mut self, value: &str) {
        if self.review.is_none() && !value.chars().any(char::is_control) {
            let field = &mut self.fields[self.focus];
            if field.len().saturating_add(value.len()) <= 4096 {
                field.push_str(value);
            }
        }
    }
    fn candidate(&self) -> Result<Config, &'static str> {
        let f = |i: usize| self.fields[i].as_str().to_owned();
        let management = config::Management {
            ipc: "auto".into(),
            log_level: "info".into(),
        };
        let ui = config::Ui {
            language: "ru".into(),
        };
        let config = match self.role {
            Role::Server => {
                let mut token = Zeroizing::new([0u8; 32]);
                rustls::crypto::ring::default_provider()
                    .secure_random
                    .fill(&mut token[..])
                    .map_err(|_| "Не удалось получить случайные данные.")?;
                let digest = format!("{:x}", Sha256::digest(&token[..]));
                let inbound = config::Inbound {
                    id: f(0),
                    path_prefix: Some(format!("/v1/{}", crate::tui_editor::generated_id("route")?)),
                    security_mode: SecurityMode::Plain,
                    reality: None,
                    allowed_user_ids: vec![f(5)],
                    quic_listen: f(1),
                    h2_listen: f(1),
                    server_name: f(2),
                    tls_cert: f(3),
                    tls_key: f(4),
                };
                Config::Server(config::ServerDocument {
                    schema_version: 1,
                    management,
                    ui,
                    server: config::ServerSettings {
                        enabled: true,
                        inbounds: vec![inbound],
                        users: vec![config::User {
                            id: f(5),
                            token_sha256: digest,
                            disabled: true,
                        }],
                        policy: config::ServerPolicy {
                            routing: None,
                            allow_private_ips: false,
                            max_connections_per_user: 64,
                            max_connections_total: 1024,
                            connect_timeout_ms: 10000,
                        },
                    },
                })
            }
            Role::Client => Config::Client(config::ClientDocument {
                schema_version: 1,
                management,
                ui,
                client: config::ClientSettings {
                    active_profile: f(0),
                    profiles: vec![config::Profile {
                        id: f(0),
                        path_prefix: Some(f(5)),
                        server: f(1),
                        server_name: f(2),
                        auth_token: f(4),
                        security_mode: SecurityMode::Plain,
                        reality_profile: None,
                        xhttp_mode: Some(config::XhttpMode::Auto),
                        tls_ca: Some(f(3)),
                        transport: config::Transport::Auto,
                        quic_connect_timeout_ms: 1600,
                        quic_negative_cache_ttl_s: 900,
                    }],
                    proxy: config::LocalProxy {
                        http_listen: "127.0.0.1:7890".into(),
                        socks5_listen: "127.0.0.1:7891".into(),
                        system_proxy: config::SystemProxy::Off,
                    },
                },
            }),
        };
        config.validate().map_err(|_| {
            "Некорректные поля. Проверьте ID, адрес, SNI, ссылки file:/env: и путь XHTTP."
        })?;
        Ok(config)
    }
    fn key(&mut self, key: KeyEvent) -> SetupAction {
        if self.review.is_some() {
            match key.code {
                KeyCode::Esc | KeyCode::Char('n') => {
                    self.review = None;
                }
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Some(candidate) = self.review.take() {
                        return SetupAction::Create(candidate);
                    }
                }
                _ => {}
            }
            return SetupAction::Continue;
        }
        self.error = None;
        match key.code {
            KeyCode::Esc => return SetupAction::Back,
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % self.fields.len(),
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = (self.focus + self.fields.len() - 1) % self.fields.len()
            }
            KeyCode::Backspace => {
                self.fields[self.focus].pop();
            }
            KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                self.fields[self.focus].clear()
            }
            KeyCode::Enter => match self.candidate() {
                Ok(config) => self.review = Some(config),
                Err(error) => self.error = Some(error),
            },
            KeyCode::Char(c)
                if !c.is_control()
                    && (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT) =>
            {
                self.paste(&c.to_string())
            }
            _ => {}
        }
        SetupAction::Continue
    }
    fn body(&self, path: &str) -> String {
        let mut out = format!(
            "Own-TLS · {} / 2 · {}\nНовый файл: {path}\n\n",
            if self.review.is_some() { 2 } else { 1 },
            if self.review.is_some() {
                "Подтверждение"
            } else {
                "Параметры"
            }
        );
        for (i, label) in self.labels().iter().enumerate() {
            let hidden = i == 3 || i == 4;
            let value = if hidden && !self.fields[i].is_empty() {
                "•••••• (ссылка введена)"
            } else {
                self.fields[i].as_str()
            };
            out.push_str(&format!(
                "{} {label}: {value}\n",
                if i == self.focus && self.review.is_none() {
                    "›"
                } else {
                    " "
                }
            ));
        }
        if self.role == Role::Server {
            out.push_str("\nПервый пользователь отключён. После сохранения восстановите доступ через меню пользователей: будет выдан новый токен. Grant назначается только введённому ID.");
        } else {
            out.push_str(
                "\nHTTP 127.0.0.1:7890 · SOCKS5 127.0.0.1:7891 · системный прокси выключен.",
            );
        }
        out.push_str("\nTLS и доступность проверяются отдельно перед запуском.");
        if self.review.is_some() {
            out.push_str("\nY создать новый файл · N/Esc назад. Существующий файл не заменяется. Runtime не запускается.");
        } else {
            out.push_str("\n↑↓ / Tab: поле · Ctrl+U очистить · Enter: предпросмотр · Esc назад");
        }
        if let Some(error) = self.error {
            out.push_str(&format!("\nОшибка: {error}"));
        }
        out
    }
}

fn default_config(filename: &str) -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    if filename == "server.toml" {
        let system = std::path::Path::new("/etc/theia");
        return if system.is_dir() {
            system.join(filename)
        } else {
            std::path::PathBuf::from(filename)
        };
    }
    #[cfg(windows)]
    let root = std::env::var_os("APPDATA").map(|p| std::path::PathBuf::from(p).join("Theia"));
    #[cfg(not(windows))]
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|p| !p.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".config")))
        .map(|p| p.join("theia"));
    root.filter(|p| p.is_dir())
        .map(|p| p.join(filename))
        .unwrap_or_else(|| std::path::PathBuf::from(filename))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn wait_dialog(dialog: &mut ConfigDialog) -> Option<crate::tui_editor::Editor> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while dialog.loading.is_some() {
            if let Some(editor) = dialog.poll() {
                return Some(editor);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "configuration worker stalled"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        None
    }

    #[test]
    fn server_setup_masks_material_and_creates_disabled_owner_only_after_review() {
        let mut setup = FirstSetup::new(Role::Server);
        assert!(setup
            .body("server.toml")
            .contains("Первый пользователь отключён"));
        setup.key(press(KeyCode::Enter));
        assert!(setup.review.is_none());
        assert!(setup.body("server.toml").contains("Ошибка:"));
        setup.key(press(KeyCode::Up));
        assert_eq!(setup.focus, 5);
        setup.key(press(KeyCode::Down));
        assert_eq!(setup.focus, 0);
        setup.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        setup.paste("inbound");
        setup.key(press(KeyCode::Char('x')));
        setup.key(press(KeyCode::Backspace));
        assert_eq!(setup.fields[0].as_str(), "inbound");
        setup.paste("bad\nvalue");
        setup.paste(&"a".repeat(4097));
        assert_eq!(setup.fields[0].as_str(), "inbound");
        for (i, value) in [
            "127.0.0.1:443",
            "example.org",
            "file:/cert.pem",
            "file:/key.pem",
        ]
        .iter()
        .enumerate()
        {
            *setup.fields[i + 1] = value.to_string();
        }
        assert!(!setup.body("server.toml").contains("key.pem"));
        setup.key(press(KeyCode::Enter));
        assert!(setup.review.is_some());
        setup.paste("ignored");
        assert_eq!(setup.fields[0].as_str(), "inbound");
        assert!(setup.body("server.toml").contains("Подтверждение"));
        setup.key(press(KeyCode::Char('n')));
        assert!(setup.review.is_none());
        setup.key(press(KeyCode::Enter));
        let SetupAction::Create(Config::Server(doc)) = setup.key(press(KeyCode::Char('Y'))) else {
            panic!("expected reviewed server config");
        };
        assert!(doc.server.users[0].disabled);
        assert_eq!(doc.server.users[0].token_sha256.len(), 64);
        assert_eq!(doc.server.inbounds[0].allowed_user_ids, vec!["owner"]);
        assert_eq!(
            doc.server.inbounds[0].h2_listen,
            doc.server.inbounds[0].quic_listen
        );
        assert!(matches!(setup.key(press(KeyCode::Esc)), SetupAction::Back));
    }

    #[test]
    fn first_config_dialog_creates_once_reopens_and_refuses_overwrite() {
        let root = std::env::temp_dir().join(crate::tui_editor::generated_id("tui-test").unwrap());
        std::fs::create_dir(&root).unwrap();
        let path = root.join("client.toml");
        let mut dialog = ConfigDialog::new(Role::Client, Some(&path));
        assert!(dialog.body().contains("открытие или создание"));
        dialog.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        dialog.key(press(KeyCode::Enter));
        assert!(dialog.body().contains("Укажите путь"));
        dialog.key(press(KeyCode::F(2)));
        assert!(dialog.setup.is_none());
        dialog.key(press(KeyCode::Char('x')));
        dialog.key(press(KeyCode::Backspace));
        dialog.paste("bad\npath");
        dialog.paste(&"a".repeat(4097));
        assert!(dialog.input.is_empty());
        dialog.paste(path.to_str().unwrap());
        dialog.key(press(KeyCode::Enter));
        assert!(dialog.body().contains("Проверяется"));
        assert!(!dialog.key(press(KeyCode::Esc)));
        assert!(wait_dialog(&mut dialog).is_none());
        assert!(dialog.error.is_some());
        assert!(!path.exists());
        dialog.key(press(KeyCode::F(2)));
        dialog.paste("test");
        assert!(dialog.setup.is_some());
        dialog.key(press(KeyCode::Esc));
        assert!(dialog.setup.is_none());

        for attempt in 0..2 {
            dialog.key(press(KeyCode::F(2)));
            let setup = dialog.setup.as_mut().unwrap();
            for (i, value) in [
                "main",
                "example.org:443",
                "example.org",
                "file:/ca.pem",
                "env:THEIA_TOKEN",
                "/v1/route",
            ]
            .iter()
            .enumerate()
            {
                *setup.fields[i] = value.to_string();
            }
            dialog.key(press(KeyCode::Enter));
            assert!(dialog.body().contains("Подтверждение"));
            let before = std::fs::read(&path).ok();
            dialog.key(press(KeyCode::Char('y')));
            assert!(dialog.body().contains("Создаётся"));
            let editor = wait_dialog(&mut dialog);
            if attempt == 0 {
                assert_eq!(editor.unwrap().role(), Role::Client);
                assert!(before.is_none());
            } else {
                assert!(editor.is_none());
                assert!(dialog.error.is_some());
                assert_eq!(std::fs::read(&path).unwrap(), before.unwrap());
            }
        }
        dialog.key(press(KeyCode::Enter));
        assert_eq!(wait_dialog(&mut dialog).unwrap().role(), Role::Client);
        assert!(dialog.key(press(KeyCode::Esc)));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disconnected_config_worker_clears_busy_state() {
        let mut dialog = ConfigDialog::new(Role::Client, None);
        let (tx, rx) = std::sync::mpsc::channel();
        dialog.loading = Some(rx);
        dialog.creating = true;
        drop(tx);
        assert!(dialog.poll().is_none());
        assert!(dialog.loading.is_none());
        assert!(!dialog.creating);
        assert!(dialog.body().contains("Операция не подтверждена"));
    }

    #[test]
    fn general_file_browser_selects_invite_without_reading_contents() {
        let root =
            std::env::temp_dir().join(crate::tui_editor::generated_id("invite-browser").unwrap());
        std::fs::create_dir(&root).unwrap();
        let invite = root.join("invite.theia");
        std::fs::write(&invite, "PRIVATE-INVITATION-TEST").unwrap();
        let mut browser = FileBrowser::files(root.to_str().unwrap());
        let form = browser.form();
        assert!(form
            .fields
            .iter()
            .all(|f| !f.value.contains("PRIVATE-INVITATION-TEST")));
        browser.select_field(1);
        assert_eq!(browser.key(KeyCode::Enter, "").unwrap(), invite);
        assert_eq!(
            std::fs::read_to_string(&invite).unwrap(),
            "PRIVATE-INVITATION-TEST"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_browser_selects_path_without_opening_or_creating() {
        let root = std::env::temp_dir().join(crate::tui_editor::generated_id("browser").unwrap());
        std::fs::create_dir(&root).unwrap();
        let existing = root.join("existing.toml");
        std::fs::write(&existing, "sentinel").unwrap();
        let new = root.join("new.toml");
        let mut dialog = ConfigDialog::new(Role::Server, Some(&new));
        dialog.key(press(KeyCode::F(6)));
        assert!(dialog.browser.is_some());
        dialog.select_field(2);
        dialog.key(press(KeyCode::Enter));
        assert_eq!(std::path::Path::new(&dialog.input), existing.as_path());
        assert!(dialog.loading.is_none());
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), "sentinel");
        assert!(!new.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_setup_requires_valid_fields_and_explicit_confirmation() {
        let mut setup = FirstSetup::new(Role::Client);
        assert!(setup.candidate().is_err());
        for (i, v) in [
            "main",
            "example.org:443",
            "example.org",
            "file:/ca.pem",
            "env:THEIA_TOKEN",
            "/v1/route",
        ]
        .iter()
        .enumerate()
        {
            *setup.fields[i] = v.to_string();
        }
        assert!(matches!(
            setup.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            SetupAction::Continue
        ));
        assert!(setup.review.is_some());
        assert!(!setup.body("client.toml").contains("THEIA_TOKEN"));
        assert!(matches!(
            setup.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            SetupAction::Create(_)
        ));
    }

    #[test]
    fn opens_existing_actions_without_requiring_shortcuts() {
        let mut m = Menu::new(Role::Server, true);
        assert_eq!(m.key(KeyCode::Left), None);
        assert!(m.item.is_none());
        assert_eq!(m.key(KeyCode::Right), None);
        assert_eq!(m.item, Some(0));
        assert_eq!(m.key(KeyCode::Right), None);
        assert_eq!(m.key(KeyCode::Enter), Some(Action::ServerProcess));
        assert_eq!(m.key(KeyCode::Down), None);
        assert_eq!(m.key(KeyCode::Enter), Some(key('v')));
        assert_eq!(m.key(KeyCode::Esc), None);
        assert_eq!(m.key(KeyCode::Esc), Some(Action::Close));
    }
    #[test]
    fn click_selects_but_never_executes_an_action() {
        let mut menu = Menu::new(Role::Server, true);
        let area = Rect::new(0, 0, 100, 24);
        menu.click(area, 2, 2);
        assert_eq!(menu.group, 1);
        assert_eq!(menu.item, Some(0));
        menu.click(area, 32, 6);
        assert_eq!(menu.item, Some(5));
        assert_eq!(menu.key(KeyCode::Enter), Some(key('Q')));
    }

    #[test]
    fn compact_menu_preserves_selection_and_configuration_guards() {
        use ratatui::{backend::TestBackend, Terminal};
        let area = Rect::new(0, 0, 68, 22);
        for role in [Role::Server, Role::Client] {
            for configured in [false, true] {
                let mut menu = Menu::new(role, configured);
                if configured {
                    assert_eq!(Menu::categories(role).len(), menu.groups().len());
                } else {
                    assert!(menu
                        .groups()
                        .iter()
                        .flat_map(|group| group.entries)
                        .all(|entry| !entry.requires_config));
                }
                let group_count = menu.groups().len();
                for group in 0..group_count {
                    menu.click(area, 2, 1 + group as u16);
                    assert_eq!(menu.group, group);
                    assert!(menu.item.is_none());
                    let mut terminal =
                        Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
                    terminal.draw(|frame| menu.render(frame, area)).unwrap();
                    let rendered = terminal
                        .backend()
                        .buffer()
                        .content()
                        .iter()
                        .map(|cell| cell.symbol())
                        .collect::<String>();
                    assert!(rendered.contains(menu.groups()[group].title));
                    assert_eq!(menu.key(KeyCode::Enter), None);
                    assert_eq!(menu.item, Some(0));
                    let entries = menu.groups()[group].entries;
                    for (index, entry) in entries.iter().enumerate() {
                        menu.click(area, 2, 1 + index as u16);
                        assert_eq!(menu.item, Some(index));
                        terminal.draw(|frame| menu.render(frame, area)).unwrap();
                        let allowed = configured || !entry.requires_config;
                        assert_eq!(menu.key(KeyCode::Enter), allowed.then_some(entry.action));
                        assert_eq!(menu.notice.is_some(), !allowed);
                        if !allowed {
                            terminal.draw(|frame| menu.render(frame, area)).unwrap();
                            let rendered = terminal
                                .backend()
                                .buffer()
                                .content()
                                .iter()
                                .map(|cell| cell.symbol())
                                .collect::<String>();
                            assert!(rendered.contains("Сначала откройте конфигурацию"));
                        }
                    }
                    assert_eq!(menu.key(KeyCode::Esc), None);
                    assert!(menu.item.is_none());
                }
                assert_eq!(menu.key(KeyCode::F(10)), Some(Action::Close));
            }
        }
    }

    #[test]
    fn unconfigured_actions_do_not_mutate_and_selection_is_visible() {
        let mut m = Menu::new(Role::Client, false);
        m.key(KeyCode::Enter);
        assert_eq!(m.key(KeyCode::Enter), Some(Action::Traffic));
        assert!(m.body(10).contains("Монитор трафика"));
        m.key(KeyCode::Down);
        assert_eq!(m.key(KeyCode::Enter), Some(Action::Config));
        assert!(!m.body(10).contains("Импорт"));
        m.key(KeyCode::Esc);
        assert_eq!(m.key(KeyCode::Esc), Some(Action::Close));
    }
}
