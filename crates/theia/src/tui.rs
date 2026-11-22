//! M4.1: keyboard-first terminal landing and bounded config editor.
//!
//! M4.1c edits safe fields; M4.4b adds one-time server issuance and reveal.
//! No service reload, network or OS proxy effect.
use crate::{tui_editor::Editor, Role};
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use zeroize::Zeroizing;
use std::{
    fmt,
    io::{self, IsTerminal},
    path::Path,
    sync::mpsc::{self, TryRecvError},
    time::Duration,
};

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
        execute!(io::stdout(), EnterAlternateScreen, Hide)?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
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

/// Confidential bearer issuance is isolated from ordinary editor commands.
enum IssueFlow {
    Input(String),
    Confirm(String),
    Saving,
    SaveFailed,
    Offer,
    Showing(Zeroizing<String>),
}

/// UI dispatch is separate from all configuration/OS effects. A queued
/// transition never runs until the user saves, discards or cancels explicitly.
struct Interaction {
    editor: Option<Editor>,
    issuance: Option<IssueFlow>,
    pending: Option<KeyEvent>,
    saving: Option<mpsc::Receiver<(Editor, bool)>>,
}

impl Interaction {
    fn new(editor: Option<Editor>) -> Self {
        Self {
            editor,
            issuance: None,
            pending: None,
            saving: None,
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

    fn poll_save(&mut self, model: &mut Model) -> Result<bool, TuiError> {
        let Some(receiver) = self.saving.as_ref() else {
            return Ok(false);
        };
        match receiver.try_recv() {
            Ok((editor, saved)) => {
                self.saving = None;
                self.editor = Some(editor);
                if matches!(self.issuance, Some(IssueFlow::Saving)) {
                    self.issuance = Some(if saved {
                        IssueFlow::Offer
                    } else {
                        IssueFlow::SaveFailed
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

    fn editor_for(&self, role: Role) -> Option<&Editor> {
        self.editor.as_ref().filter(|edit| edit.role() == role)
    }

    fn update(&mut self, model: &mut Model, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press || self.saving.is_some() {
            return false;
        }
        let Some(editor) = self.editor.as_mut() else {
            return model.update(key);
        };
        if let Some(flow) = self.issuance.take() {
            match flow {
                IssueFlow::Input(mut id) => match key.code {
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
                        if editor.issue_user(&id).is_ok() {
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
                    KeyCode::Char('r') => {
                        self.issuance = Some(IssueFlow::Saving);
                        self.start_save();
                    }
                    KeyCode::Char('d') => editor.discard(),
                    _ => self.issuance = Some(IssueFlow::SaveFailed),
                },
                IssueFlow::Offer => match key.code {
                    KeyCode::Char('y') => {
                        if let Some(invite) = editor.take_issued() {
                            match invite.encode() {
                                Ok(link) => self.issuance =
                                    Some(IssueFlow::Showing(Zeroizing::new(link))),
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
                KeyCode::Esc => editor.cancel(),
                KeyCode::Enter => {
                    editor.accept();
                }
                KeyCode::Backspace => editor.backspace(),
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
            if editor.role() == Role::Server && key.code == KeyCode::Char('u') {
                if editor.dirty() {
                    editor.error = Some("Сохраните или отмените черновик перед выдачей токена.".into());
                } else {
                    editor.error = None;
                    self.issuance = Some(IssueFlow::Input(String::new()));
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
                KeyCode::Tab => {
                    editor.select_field(true);
                    return false;
                }
                KeyCode::BackTab => {
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
                editor.begin();
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

fn panel(frame: &mut Frame<'_>, area: Rect, title: &str, body: &str, focused: bool) {
    let style = if focused {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    frame.render_widget(
        Paragraph::new(body)
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(style),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
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
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(3),
        ])
        .split(area);
    frame.render_widget(
        Paragraph::new("THEIA 0.1  |  Локальное управление  |  Состояние сервиса: неизвестно")
            .block(Block::default().borders(Borders::ALL)),
        parts[0],
    );
    match model.screen {
        Screen::Home => {
            let direction = if area.width >= 80 {
                Direction::Horizontal
            } else {
                Direction::Vertical
            };
            let cards = Layout::default()
                .direction(direction)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(parts[1]);
            panel(
                frame,
                cards[0],
                "[1] Для сервера",
                "Inbound и порты\nПользователи и права\nTLS и политика\nСтатус: не запрашивался",
                model.selected == Role::Server,
            );
            panel(
                frame,
                cards[1],
                "[2] Для клиента",
                "Профили и подключения\nЛокальный HTTP/SOCKS5\nСистемный прокси Windows\nСтатус: не запрашивался",
                model.selected == Role::Client,
            );
        }
        Screen::Server => {
            if let Some(editor) = interaction.and_then(|ui| ui.editor_for(Role::Server)) {
                draw_editor(frame, parts[1], editor);
            } else {
                panel(
                    frame,
                    parts[1],
                    "Для сервера",
                    "Конфигурация: не загружена\nInbound: данные не загружены\nRuntime: состояние неизвестно (IPC ещё не реализован)\n\nЭтот экран только для чтения. Запуск сервера, редактирование и reload пока недоступны.",
                    true,
                );
            }
        }
        Screen::Client => {
            if let Some(editor) = interaction.and_then(|ui| ui.editor_for(Role::Client)) {
                draw_editor(frame, parts[1], editor);
            } else {
                panel(
                    frame,
                    parts[1],
                    "Для клиента",
                    "Профиль: не выбран\nЛокальный прокси: состояние неизвестно\nТранспорт: не проверялся\nСистемный прокси Windows: не изменён\n\nЭтот экран только для чтения. Подключение, редактирование и управление системным прокси пока недоступны.",
                    true,
                );
            }
        }
        Screen::Help => panel(
            frame,
            parts[1],
            "Справка",
            "1 / 2: сервер / клиент\nTab / Shift+Tab: сменить выбор\nEnter: открыть выбранную панель\nEsc: назад\n? / F1: справка\nq / Ctrl+C: выйти\n\nС явными --role и --config: j/k или ↑/↓ выбирают inbound/профиль, Tab/Shift+Tab выбирают поле, Enter/e редактирует. Сеть, runtime и системный прокси не изменяются.",
            true,
        ),
    }
    if interaction.is_some_and(|ui| ui.saving.is_some()) {
        panel(
            frame,
            parts[1],
            "Сохранение конфигурации",
            "Проверка изменений и атомарная запись TOML выполняются.\nRuntime не перезагружается.\nДождитесь результата операции.",
            true,
        );
    } else if interaction.is_some_and(|ui| ui.pending.is_some()) {
        panel(
            frame,
            parts[1],
            "Не сохранено: подтвердите переход",
            "s: сохранить и продолжить\nd: отменить изменения и продолжить\nEsc: остаться в редакторе\n\nНи одна опция не применяет конфигурацию к runtime.",
            true,
        );
    }
    frame.render_widget(
        Paragraph::new(
            "j/k: запись  Tab: поле  Enter/e: ввод  Ctrl+S: сохранить  Esc: назад  q: выход",
        )
        .block(Block::default().borders(Borders::ALL)),
        parts[2],
    );
}

fn draw_editor(frame: &mut Frame<'_>, area: Rect, editor: &Editor) {
    let dirty = if editor.dirty() {
        "* Не сохранено"
    } else {
        "Сохранено"
    };
    let message = format!(
        "{}\n\n{}\nВыбрано: {}\n{}\n\n{}\n{}\n\n{}\n\nRuntime: состояние неизвестно; reload не выполнялся.\nСекреты, ACL и системный прокси не редактируются.",
        editor.selection_summary(),
        editor.fields_overview(),
        editor.field_name(),
        dirty,
        if editor.editing {
            "Ввод: символы/Backspace | Enter: проверить | Esc: отменить"
        } else {
            "↑/↓ или j/k: запись | Tab/Shift+Tab: поле | Enter/e: изменить | Ctrl+S: сохранить"
        },
        editor.notice,
        editor.error.as_deref().unwrap_or(""),
    );
    panel(
        frame,
        area,
        "Редактор TOML (указанный файл, 3 поля)",
        &message,
        true,
    );
}

/// Edit only when both role and a config path are explicitly supplied.
/// No service or OS-proxy changes; a separate IPC transaction is future work.
pub fn run(role: Option<Role>, config_path: Option<&Path>) -> Result<(), TuiError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
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
    loop {
        if interaction.poll_save(&mut model)? {
            return Ok(());
        }
        terminal.draw(|frame| draw(frame, &model, Some(&interaction)))?;
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if interaction.update(&mut model, key) {
                    return Ok(());
                }
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
        assert!(picture.contains("client.profiles[0].server"));
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
}
