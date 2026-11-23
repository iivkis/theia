//! M4.1: keyboard-first terminal landing and bounded config editor.
//!
//! M4.1c edits safe fields; M4.4b adds one-time server issuance and reveal.
//! No service reload, network or OS proxy effect.
use crate::{
    tui_candidate_batch::CandidateBatchPanel, tui_candidates::CandidateReview,
    tui_discovery::DiscoveryPanel, tui_domain::DomainPanel, tui_editor::Editor,
    tui_probe::ProbePanel, tui_runtime::RuntimePanel, Role,
};
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
    fmt,
    io::{self, IsTerminal},
    path::Path,
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
    discovery: Option<DiscoveryPanel>,
    candidates: Option<CandidateReview>,
    candidate_batch: Option<CandidateBatchPanel>,
    domain: Option<DomainPanel>,
    probe: Option<ProbePanel>,
    runtime: Option<RuntimePanel>,
    pending: Option<KeyEvent>,
    saving: Option<mpsc::Receiver<(Editor, bool)>>,
}

impl Interaction {
    fn new(editor: Option<Editor>) -> Self {
        Self {
            editor,
            issuance: None,
            discovery: None,
            candidates: None,
            candidate_batch: None,
            domain: None,
            probe: None,
            runtime: None,
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
        if let Some(runtime) = self.runtime.as_mut() {
            if runtime.key(key) {
                self.runtime = None;
            }
            return false;
        }
        if let Some(domain) = self.domain.as_mut() {
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
        let Some(editor) = self.editor.as_mut() else {
            if model.screen == Screen::Server && key.code == KeyCode::Char('v') {
                self.runtime = Some(RuntimePanel::open(None, false));
                return false;
            }
            if model.screen == Screen::Server && key.code == KeyCode::Char('p') {
                self.discovery = Some(DiscoveryPanel::new());
                return false;
            }
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
            // An editable draft is never silently sent to the server.
            // Ctrl+R requires an explicit saved source and then a second 'y'.
            let apply_shortcut = key.modifiers.contains(KeyModifiers::CONTROL)
                && key.code == KeyCode::Char('r');
            if editor.role() == Role::Server
                && (key.code == KeyCode::Char('v') || apply_shortcut)
            {
                if apply_shortcut && editor.dirty() {
                    editor.error = Some(
                        "Сначала Ctrl+S: нельзя применять несохранённый черновик.".into(),
                    );
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
            if editor.role() == Role::Server && key.code == KeyCode::Char('u') {
                if editor.dirty() {
                    editor.error =
                        Some("Сохраните или отмените черновик перед выдачей токена.".into());
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
                    "Конфигурация: не загружена\nInbound: данные не загружены\nRuntime: v запрашивает настоящий статус через Linux IPC\n\nЭтот экран только для чтения. Нужен явный --role server --config FILE для редактирования и подтверждаемого Apply; без него здесь только статус.",
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
            "1 / 2: сервер / клиент\nTab / Shift+Tab: сменить выбор\nEnter: открыть выбранную панель\nEsc: назад\n? / F1: справка\nq / Ctrl+C: выйти\n\nС явными --role и --config: j/k выбирают inbound/профиль, Tab поле, Enter/e правит поле. В серверной панели u создаёт пользователя, p: пассивный IP обзор, i: согласие ipify; r: группы кандидатов и ручной CIDR (только офлайн), b: IP-список до 8 (Space), d: домен из каталога (отдельные DNS и H2/H3 согласия), t: один IP H2+H3. Ручное v проверяет состояние; Ctrl+R на сохранённой серверной конфигурации открывает отдельное подтверждение CAS Apply (y), а не молча перезапускает. Сетевые IP/DNS исследования и системный прокси не меняются.",
            true,
        ),
    }
    if let Some(runtime) = interaction.and_then(|ui| ui.runtime.as_ref()) {
        panel(
            frame,
            parts[1],
            runtime.title(),
            &runtime.body(),
            true,
        );
    } else if interaction.is_some_and(|ui| ui.saving.is_some()) {
        panel(
            frame,
            parts[1],
            "Сохранение конфигурации",
            "Проверка изменений и атомарная запись TOML выполняются.\nRuntime не перезагружается.\nДождитесь результата операции.",
            true,
        );
    } else if let Some(flow) = interaction.and_then(|ui| ui.issuance.as_ref()) {
        draw_issuance(
            frame,
            parts[1],
            flow,
            interaction.and_then(|ui| ui.editor.as_ref()),
        );
    } else if interaction.is_some_and(|ui| ui.pending.is_some()) {
        panel(
            frame,
            parts[1],
            "Не сохранено: подтвердите переход",
            "s: сохранить и продолжить\nd: отменить изменения и продолжить\nEsc: остаться в редакторе\n\nНи одна опция не применяет конфигурацию к runtime.",
            true,
        );
    } else if let Some(domain) = interaction.and_then(|ui| ui.domain.as_ref()) {
        panel(
            frame,
            parts[1],
            "F-18: каталог HTTPS доменов, согласие DNS и pinned H2+H3",
            &domain.body(),
            true,
        );
    } else if let Some(batch) = interaction.and_then(|ui| ui.candidate_batch.as_ref()) {
        panel(
            frame,
            parts[1],
            "F-18: ручной список до 8 точных IP для TCP/H2 + UDP/H3",
            &batch.body(),
            true,
        );
    } else if let Some(review) = interaction.and_then(|ui| ui.candidates.as_ref()) {
        panel(
            frame,
            parts[1],
            "F-18: группы кандидатов и ручная область CIDR (офлайн)",
            &review.body(),
            true,
        );
    } else if let Some(probe) = interaction.and_then(|ui| ui.probe.as_ref()) {
        panel(
            frame,
            parts[1],
            "TLS/H2 + QUIC/H3: только один разрешённый IP:443",
            &probe.body(),
            true,
        );
    } else if let Some(discovery) = interaction.and_then(|ui| ui.discovery.as_ref()) {
        panel(
            frame,
            parts[1],
            "Публичный IP и план кандидатов (без сканирования)",
            &discovery.body(),
            true,
        );
    }
    frame.render_widget(
        Paragraph::new(
            "j/k: запись  Tab: поле  Enter/e: ввод  u: пользователь  v: статус  Ctrl+R: подтверждённый Apply  Ctrl+S: сохранить",
        )
        .block(Block::default().borders(Borders::ALL)),
        parts[2],
    );
}

fn draw_issuance(frame: &mut Frame<'_>, area: Rect, flow: &IssueFlow, editor: Option<&Editor>) {
    let (title, body) = match flow {
        IssueFlow::Input(id) => (
            "Новый пользователь для выбранного inbound",
            format!(
                "ID пользователя: {id}\n\nСгенерировать 256-битный токен и назначить доступ только к выбранному inbound.\n\nEnter: продолжить  Backspace: удалить  Esc: отменить\n\n{}",
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        IssueFlow::Confirm(id) => (
            "Подтверждение нового пользователя",
            format!(
                "Пользователь: {id}\nInbound: {}\n\nСоздать токен CSPRNG и сохранить новую запись в server.toml?\nЭто НЕ перезагружает сервер.\n\n y: подтвердить  n/Esc: отменить",
                editor.map_or("", |e| e.selected_record_id())
            ),
        ),
        IssueFlow::Saving => (
            "Сохранение",
            "Сохранение выполняется; конфиденциальная ссылка скрыта.".into(),
        ),
        IssueFlow::SaveFailed => (
            "Сохранение НЕ удалось: ссылка заблокирована",
            format!(
                "Новый пользователь НЕ записан. Токен не показывался.\n\n{}\n\nr: повторить запись  d: удалить черновик и токен",
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        IssueFlow::Offer => (
            "Одноразовая выдача конфиденциальной ссылки",
            "server.toml сохранён. Runtime ещё не обновлён.\nСсылка содержит действующий bearer-токен. Не публиковать.\nПовторного показа после закрытия не будет.\n\n y: показать ссылку один раз\n n/Esc: отказаться и уничтожить токен в памяти".into(),
        ),
        IssueFlow::Showing(link) => (
            "СЕКРЕТ: ссылка подключения (однократный просмотр)",
            format!(
                "КОНФИДЕНЦИАЛЬНО. Скопируйте ссылку целиком.\nТерминал/SSH и экран должны быть доверенными.\n\n{link}\n\nEsc: скрыть и стереть из памяти.\nRuntime не перезагружен.",
                link = link.as_str()
            ),
        ),
    };
    panel(frame, area, title, &body, true);
}

fn draw_editor(frame: &mut Frame<'_>, area: Rect, editor: &Editor) {
    let dirty = if editor.dirty() {
        "* Не сохранено"
    } else {
        "Сохранено"
    };
    let message = format!(
        "{}\n\n{}\nВыбрано: {}\n{}\n\n{}\n{}\n\n{}\n\nRuntime: v — проверить статус; Ctrl+R — отдельное подтверждение auth-only Apply (только сохранённого TOML, Linux).\nНовый пользователь и grant: клавиша u. Ctrl+S только сохраняет, runtime не меняет.",
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
/// Saving never changes a service. A separate, explicitly confirmed Linux\n/// IPC transaction is available only for saved server authorization deltas.
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
        if let Some(runtime) = interaction.runtime.as_mut() {
            runtime.poll();
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
        if let Some(domain) = interaction.domain.as_mut() {
            domain.poll();
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
}
