//! M4.1a: read-only, keyboard-first terminal landing.
//!
//! The model and renderer are pure: no configuration loading, service starts,
//! management IPC or OS proxy side effects occur in this phase.
use crate::Role;
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
use std::{
    io::{self, IsTerminal},
    fmt,
};

#[derive(Debug)]
pub enum TuiError {
    NotInteractive,
    Io,
}

impl TuiError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::NotInteractive => "interactive terminal required (stdin and stdout must be TTY)",
            Self::Io => "terminal initialization, drawing or input failed",
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
            .block(Block::default().title(title).borders(Borders::ALL).border_style(style))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw(frame: &mut Frame<'_>, model: &Model) {
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
        .constraints([Constraint::Length(3), Constraint::Min(4), Constraint::Length(3)])
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
        Screen::Server => panel(
            frame,
            parts[1],
            "Для сервера",
            "Конфигурация: не загружена\nInbound: данные не загружены\nRuntime: состояние неизвестно (IPC ещё не реализован)\n\nЭтот экран только для чтения. Запуск сервера, редактирование и reload пока недоступны.",
            true,
        ),
        Screen::Client => panel(
            frame,
            parts[1],
            "Для клиента",
            "Профиль: не выбран\nЛокальный прокси: состояние неизвестно\nТранспорт: не проверялся\nСистемный прокси Windows: не изменён\n\nЭтот экран только для чтения. Подключение, редактирование и управление системным прокси пока недоступны.",
            true,
        ),
        Screen::Help => panel(
            frame,
            parts[1],
            "Справка",
            "1 / 2: сервер / клиент\nTab / Shift+Tab: сменить выбор\nEnter: открыть выбранную панель\nEsc: назад\n? / F1: справка\nq / Ctrl+C: выйти\n\nНастройки, сеть и системный прокси этим интерфейсом не изменяются.",
            true,
        ),
    }
    frame.render_widget(
        Paragraph::new("1/2: панель  Tab: выбор  Enter: открыть  Esc: назад  ?: помощь  q: выход")
            .block(Block::default().borders(Borders::ALL)),
        parts[2],
    );
}

/// TUI deliberately does not start the server/client or touch system proxy.
pub fn run(role: Option<Role>) -> Result<(), TuiError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(TuiError::NotInteractive);
    }
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut model = Model::new(role);
    loop {
        terminal.draw(|frame| draw(frame, &model))?;
        if let Event::Key(key) = event::read()? {
            if model.update(key) {
                return Ok(());
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
        terminal.draw(|f| draw(f, &model)).unwrap();
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
