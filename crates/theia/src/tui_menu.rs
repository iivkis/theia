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
            entry("Системный прокси Windows", key('p')),
        ],
    },
    Group {
        title: "Профили и приглашения",
        entries: &[
            entry("Импорт ссылки, URI-файла или изображения QR", key('i')),
            always("Импорт первого REALITY-профиля", key('I')),
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
        match self.role {
            Role::Server => SERVER,
            Role::Client => CLIENT,
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
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::F(10) => {
                if self.item.take().is_none() || key == KeyCode::F(10) {
                    return Some(Action::Close);
                }
                return None;
            }
            KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => (selected + count - 1) % count,
            KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => (selected + 1) % count,
            KeyCode::Home => 0,
            KeyCode::End => count - 1,
            KeyCode::PageUp => selected.saturating_sub(5),
            KeyCode::PageDown => (selected + 5).min(count - 1),
            KeyCode::Enter | KeyCode::Right => {
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
            if x > rect.x && x < rect.right().saturating_sub(1)
                && y > rect.y && y < rect.bottom().saturating_sub(1) {
                let height = usize::from(rect.height.saturating_sub(2));
                let index = Self::visible_start(self.selected(), self.count(), height) + usize::from(y - rect.y - 1);
                if index < self.count() {
                    if self.item.is_some() { self.item = Some(index); } else { self.group = index; }
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
            let items = (start..(start + height).min(count)).map(|i| {
                let (label, enabled) = if self.item.is_some() {
                    let entry = self.groups()[self.group].entries[i];
                    (entry.label, self.configured || !entry.requires_config)
                } else { (self.groups()[i].title, true) };
                let style = if i == selected { Style::default().fg(ACCENT).bg(FOCUS).add_modifier(Modifier::BOLD) }
                    else if !enabled { Style::default().fg(MUTED) } else { Style::default() };
                ListItem::new(format!("{} {label}{}", if i == selected { "›" } else { " " }, if enabled { "" } else { " [нужен файл]" })).style(style)
            }).collect::<Vec<_>>();
            let title = if self.item.is_some() { self.groups()[self.group].title } else { self.title() };
            frame.render_widget(List::new(items).block(tui_widgets::section(&format!("{title} · {}/{}", selected + 1, count), true)), parts[0]);
            frame.render_widget(Paragraph::new(self.notice.unwrap_or("↑↓ выбрать · Enter открыть · Esc назад")), parts[1]);
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
                            .fg(if enabled {
                                ACCENT
                            } else {
                                MUTED
                            })
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
                        Span::raw(if enabled { "" } else { " [нужен файл]" }),
                    ]))
                    .style(style)
                })
                .collect();
            frame.render_widget(
                List::new(rows).block(
                    tui_widgets::section(title, focused),
                ),
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
            "↑↓ раздел  ·  Enter/→ действия  ·  Esc редактор"
        } else {
            "↑↓ действие  ·  Enter открыть  ·  ←/Esc разделы  ·  F10 редактор"
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
struct FileBrowser {
    directory: std::path::PathBuf,
    entries: Vec<(std::path::PathBuf, bool)>,
    focus: usize,
    error: String,
}
impl FileBrowser {
    fn new(input: &str) -> Self {
        let path = std::path::PathBuf::from(input);
        let directory = if path.is_dir() { path } else { path.parent().filter(|p| p.is_dir()).map(std::path::Path::to_path_buf).unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into())) };
        let directory = std::path::absolute(&directory).unwrap_or(directory);
        let mut browser = Self { directory, entries: Vec::new(), focus: 0, error: String::new() };
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
                    let Ok(kind) = entry.file_type() else { continue; };
                    let path = entry.path();
                    if path.to_str().is_none_or(|s| s.len() > 4096 || s.chars().any(char::is_control)) { continue; }
                    if kind.is_dir() || (kind.is_file() && path.extension().is_some_and(|s| s.eq_ignore_ascii_case("toml"))) {
                        self.entries.push((path, kind.is_dir()));
                    }
                }
                self.entries.sort_by(|(a,ad),(b,bd)| bd.cmp(ad).then_with(|| a.cmp(b)));
            }
            Err(_) => self.error = "Каталог недоступен. Выберите родительский каталог или вернитесь к ручному вводу.".into(),
        }
    }
    fn form(&self) -> crate::tui_widgets::Form {
        use crate::tui_widgets::{Field, Form};
        let mut fields = vec![
            Field { id:0, label:"Родительский каталог", value:"..".into(), hint:"Enter — подняться на уровень выше." },
            Field { id:1, label:"Выбрать этот каталог", value:self.directory.display().to_string(), hint:"Enter — использовать каталог и вернуться к имени файла." },
        ];
        fields.extend(self.entries.iter().enumerate().map(|(i,(path,dir))| Field {
            id:i+2, label:if *dir {"Каталог"} else {"Конфигурация TOML"}, value:path.file_name().unwrap_or_default().to_string_lossy().into_owned(),
            hint:if *dir {"Enter — открыть каталог."} else {"Enter — выбрать путь без загрузки файла."},
        }));
        Form { fields, selected:self.focus, lead:format!("Каталог: {} · до 2048 записей",self.directory.display()), error:self.error.clone() }
    }
    fn key(&mut self, key: KeyCode, filename: &str) -> Option<std::path::PathBuf> {
        let count = self.entries.len()+2;
        match key {
            KeyCode::Up | KeyCode::BackTab => self.focus = (self.focus+count-1)%count,
            KeyCode::Down | KeyCode::Tab => self.focus = (self.focus+1)%count,
            KeyCode::Home => self.focus=0,
            KeyCode::End => self.focus=count-1,
            KeyCode::Enter => match self.focus {
                0 => if let Some(parent)=self.directory.parent() { self.directory=parent.to_path_buf(); self.refresh(); },
                1 => return Some(self.directory.join(filename)),
                i => if let Some((path,dir))=self.entries.get(i-2).cloned() {
                    if dir { self.directory=path; self.refresh(); } else { return Some(path); }
                },
            },
            _ => {}
        }
        None
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
            creating: false,
            browser: None,
        }
    }
    pub(crate) fn prefer_reality(&mut self) {
        self.prefer_mode(1);
    }
    pub(crate) fn prefer_mode(&mut self, choice: usize) {
        self.choice = choice.min(2);
    }
    pub(crate) fn paste(&mut self, text: &str) {
        if self.browser.is_some() { return; }
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
    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        if self.loading.is_some() {
            return false;
        }
        if let Some(panel) = self.enrollment.as_mut() {
            if panel.key(key) {
                self.enrollment = None;
            }
            return false;
        }
        if let Some(panel) = self.reality.as_mut() {
            if panel.key(key) {
                self.reality = None;
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
            if key.code == KeyCode::Esc { self.browser = None; return false; }
            let filename = std::path::Path::new(&self.input).file_name().and_then(|n| n.to_str()).unwrap_or(if self.role == Role::Server { "server.toml" } else { "client.toml" });
            if let Some(path) = browser.key(key.code, filename) {
                if let Some(path) = path.to_str().filter(|s| s.len() <= 4096 && !s.chars().any(char::is_control)) {
                    self.input = path.to_owned();
                    self.error = None;
                    self.browser = None;
                    if self.choice==3{self.choice=0;}
                } else { browser.error = "Недопустимый путь".into(); }
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
            KeyCode::Enter if self.choice == 3 => {self.browser=Some(FileBrowser::new(&self.input));return false;}
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
                    match crate::tui_reality_enroll::EnrollmentPanel::first(std::path::PathBuf::from(&self.input)) {
                        Ok(panel) => { self.enrollment = Some(panel); self.error = None; }
                        Err(error) => self.error = Some(error),
                    }
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
        if let Some(panel) = self.enrollment.as_mut() {
            return panel.poll();
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
                self.error = Some(reason);
                None
            }
        }
    }
    pub(crate) fn form(&self) -> Option<crate::tui_widgets::Form> {
        use crate::tui_widgets::{Field, Form};
        if self.loading.is_some() { return None; }
        if let Some(browser) = &self.browser { return Some(browser.form()); }
        if let Some(panel) = &self.reality { return panel.form(); }
        if let Some(panel) = &self.enrollment { return panel.form(); }
        if let Some(setup) = &self.setup {
            if setup.review.is_some() { return None; }
            let hints = match setup.role {
                Role::Server => ["Уникальный ID.", "Один адрес для TCP и UDP.", "DNS-имя сертификата.", "Абсолютная file: ссылка на PEM.", "Абсолютная file: ссылка; не вставляйте ключ.", "Пользователь будет отключён до восстановления доступа."],
                Role::Client => ["Имя профиля.", "Публичный адрес и порт.", "DNS-имя сервера.", "Абсолютная file: ссылка на доверенный CA.", "Ссылка на токен, не сам токен.", "Путь /v1/... из конфигурации сервера."],
            };
            return Some(Form {
                fields: setup.labels().iter().enumerate().map(|(id, label)| Field {
                    id, label, hint: hints[id],
                    value: if matches!(id, 3 | 4) && !setup.fields[id].is_empty() {
                        "Скрыто · ссылка введена".into()
                    } else { setup.fields[id].to_string() },
                }).collect(),
                selected: setup.focus,
                lead: format!("Новый файл: {}", self.input),
                error: setup.error.unwrap_or_default().to_owned(),
            });
        }
        let reality = if self.role == Role::Server { "SmartTheia REALITY" } else { "Импорт REALITY" };
        let fields = vec![
            Field { id: 0, label: "Открыть TOML", value: "Enter · существующий файл".into(), hint: "Введите путь к существующему файлу." },
            Field { id: 1, label: reality, value: "F4 · создать через мастер".into(), hint: "Новый TOML, без собственного сертификата." },
            Field { id: 2, label: "Own-TLS", value: "F2 · создать вручную".into(), hint: "Новый TOML с собственным TLS." },
            Field { id: 3, label: "Выбрать файл или каталог", value: "F6 · файловый браузер".into(), hint: "Выбор пути не открывает и не создаёт файл." },
        ];
        Some(Form {
            fields,
            selected: self.choice,
            lead: format!("Путь к TOML: {}\nF6 выбрать файл/каталог · Ctrl+U очистить · путь можно ввести", self.input),
            error: self.error.unwrap_or_default().to_owned(),
        })
    }

    pub(crate) fn select_field(&mut self, id: usize) {
        if self.loading.is_some() { return; }
        if let Some(browser) = self.browser.as_mut() {
            if id < browser.entries.len()+2 { browser.focus = id; }
            return;
        }
        if let Some(panel) = self.reality.as_mut() { panel.select_field(id); }
        else if let Some(panel) = self.enrollment.as_mut() { panel.select_field(id); }
        else if let Some(setup) = self.setup.as_mut() {
            if setup.review.is_none() && id < setup.fields.len() { setup.focus = id; }
        } else if id < 4 {
            self.choice = id;
        }
    }

    pub(crate) fn reference_review(&self) -> Option<crate::tui_widgets::ReferenceReview> {
        self.reality.as_ref()?.reference_review()
    }

    pub(crate) fn guide(&self) -> Option<(usize, usize, &'static str, &'static str)> {
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
                (1, 2, "Параметры Own-TLS", "↑↓ поле · Ctrl+U очистить · Enter проверить · Esc назад")
            }
        })
    }
    pub(crate) fn title(&self) -> &'static str {
        if self.browser.is_some() { return "Выбор файла · ↑↓ Enter Esc"; }
        if self.enrollment.is_some() {
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
            "Импорт REALITY  ·  создать TOML из приглашения"
        };
        let choices = [
            ("Enter", "Открыть существующий TOML"),
            ("F4", reality),
            ("F2", "Own-TLS  ·  собственный сертификат / ручная настройка"),
        ];
        let mut body = format!("{role} • открытие или создание конфигурации\n\nПУТЬ К TOML\n  {}\n\nВЫБЕРИТЕ ДЕЙСТВИЕ\n", self.input);
        for (i, (shortcut, label)) in choices.iter().enumerate() {
            body.push_str(&format!("{} {shortcut:5} {label}\n", if i == self.choice { ">" } else { " " }));
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
        return if system.is_dir() { system.join(filename) } else { std::path::PathBuf::from(filename) };
    }
    #[cfg(windows)]
    let root = std::env::var_os("APPDATA").map(|p| std::path::PathBuf::from(p).join("Theia"));
    #[cfg(not(windows))]
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|p| !p.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".config")))
        .map(|p| p.join("theia"));
    root.filter(|p| p.is_dir()).map(|p| p.join(filename))
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
    fn file_browser_selects_path_without_opening_or_creating() {
        let root=std::env::temp_dir().join(crate::tui_editor::generated_id("browser").unwrap());
        std::fs::create_dir(&root).unwrap();
        let existing=root.join("existing.toml");
        std::fs::write(&existing,"sentinel").unwrap();
        let new=root.join("new.toml");
        let mut dialog=ConfigDialog::new(Role::Server,Some(&new));
        dialog.key(press(KeyCode::F(6)));
        assert!(dialog.browser.is_some());
        dialog.select_field(2);
        dialog.key(press(KeyCode::Enter));
        assert_eq!(std::path::Path::new(&dialog.input),existing.as_path());
        assert!(dialog.loading.is_none());
        assert_eq!(std::fs::read_to_string(&existing).unwrap(),"sentinel");
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
        assert_eq!(m.key(KeyCode::Enter), None);
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
    fn unconfigured_actions_do_not_mutate_and_selection_is_visible() {
        let mut m = Menu::new(Role::Client, false);
        m.key(KeyCode::Enter);
        assert_eq!(m.key(KeyCode::Enter), Some(key('V')));
        m.key(KeyCode::Down);
        assert_eq!(m.key(KeyCode::Enter), Some(Action::Traffic));
        m.key(KeyCode::End);
        assert_eq!(m.key(KeyCode::Enter), None);
        assert!(m.body(10).contains("Сначала откройте"));
        assert!(m.body(6).contains("Системный прокси"));
        m.key(KeyCode::Esc);
        m.key(KeyCode::End);
        m.key(KeyCode::Enter);
        assert_eq!(m.key(KeyCode::Enter), Some(Action::Config));
    }
}
