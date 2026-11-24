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
    tui_editor::{Editor, PinnedModeReview, RecordAction, RecordReview},
    tui_probe::ProbePanel,
    tui_runtime::RuntimePanel,
    Role,
};
use crossterm::{
    cursor::{Hide, Show},
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
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
            EnableBracketedPaste
        )?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
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
type PinnedReviewResult = (Editor, Result<PinnedModeReview, &'static str>);

enum RecordFlow {
    Input {
        action: RecordAction,
        fields: Vec<String>,
        focus: usize,
    },
    Confirm(Box<RecordReview>),
}

impl RecordFlow {
    fn body(&self) -> String {
        match self {
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
                body.push_str("\nTab/Shift+Tab: поле; Ctrl+U: очистить; Enter: preview; Esc: отменить.\nВ скрытые поля вводите только ссылки, не секреты.");
                body
            }
        }
    }
}

struct Interaction {
    editor: Option<Editor>,
    issuance: Option<IssueFlow>,
    issue_kind: IssueKind,
    revocation: Option<DisableFlow>,
    importing: Option<ImportFlow>,
    records: Option<RecordFlow>,
    discovery: Option<DiscoveryPanel>,
    candidates: Option<CandidateReview>,
    candidate_batch: Option<CandidateBatchPanel>,
    domain: Option<DomainPanel>,
    probe: Option<ProbePanel>,
    runtime: Option<RuntimePanel>,
    pinned_review: Option<PinnedModeReview>,
    pinned_loading: Option<mpsc::Receiver<PinnedReviewResult>>,
    #[cfg(windows)]
    system_proxy: Option<crate::tui_system_proxy::Panel>,
    pending: Option<KeyEvent>,
    saving: Option<mpsc::Receiver<(Editor, bool)>>,
    exporting: Option<mpsc::Receiver<ExportResult>>,
}

impl Interaction {
    fn new(editor: Option<Editor>) -> Self {
        Self {
            editor,
            issuance: None,
            issue_kind: IssueKind::NewUser,
            revocation: None,
            importing: None,
            records: None,
            discovery: None,
            candidates: None,
            candidate_batch: None,
            domain: None,
            probe: None,
            runtime: None,
            pinned_review: None,
            pinned_loading: None,
            #[cfg(windows)]
            system_proxy: None,
            pending: None,
            saving: None,
            exporting: None,
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

    fn start_pinned_review(&mut self, stream_up: bool) {
        let Some(mut editor) = self.editor.take() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.pinned_loading = Some(rx);
        let _worker = std::thread::spawn(move || {
            let result = editor.review_pinned_mode(stream_up);
            editor.error = result.as_ref().err().map(|message| (*message).to_owned());
            let _ = tx.send((editor, result));
        });
    }

    fn start_pinned_save(&mut self, review: PinnedModeReview) {
        let Some(mut editor) = self.editor.take() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.saving = Some(rx);
        let _worker = std::thread::spawn(move || {
            let result = editor.apply_pinned_mode(&review);
            if let Err(message) = result {
                editor.error = Some(message.into());
            }
            let _ = tx.send((editor, result.is_ok()));
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
        if let Some(ImportFlow::Input(source)) = self.importing.as_mut() {
            let input = text.trim_end_matches(['\r', '\n']);
            if source.len().saturating_add(input.len()) <= 4096 && !input.contains('\0') {
                source.push_str(input);
            }
        }
    }

    fn poll_save(&mut self, model: &mut Model) -> Result<bool, TuiError> {
        if let Some(receiver) = self.pinned_loading.as_ref() {
            match receiver.try_recv() {
                Ok((editor, result)) => {
                    self.pinned_loading = None;
                    self.editor = Some(editor);
                    self.pinned_review = result.ok();
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => return Err(TuiError::Io),
            }
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

    fn editor_for(&self, role: Role) -> Option<&Editor> {
        self.editor.as_ref().filter(|edit| edit.role() == role)
    }

    fn update(&mut self, model: &mut Model, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press
            || self.saving.is_some()
            || self.exporting.is_some()
            || self.pinned_loading.is_some()
        {
            return false;
        }
        #[cfg(windows)]
        if let Some(proxy) = self.system_proxy.as_mut() {
            if proxy.key(key) {
                self.system_proxy = None;
            }
            return false;
        }
        if let Some(review) = self.pinned_review.take() {
            match key.code {
                KeyCode::Char('y') => self.start_pinned_save(review),
                KeyCode::Esc | KeyCode::Char('n') => {}
                _ => self.pinned_review = Some(review),
            }
            return false;
        }
        if let Some(runtime) = self.runtime.as_mut() {
            if runtime.key(key) {
                self.runtime = None;
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
        let Some(editor) = self.editor.as_mut() else {
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
        };
        if let Some(flow) = self.records.take() {
            match flow {
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
                        KeyCode::Tab => focus = (focus + 1) % fields.len(),
                        KeyCode::BackTab => focus = (focus + fields.len() - 1) % fields.len(),
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
                IssueFlow::Public(link) => {
                    if !matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                        self.issuance = Some(IssueFlow::Public(link));
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

        if let Some(flow) = self.importing.take() {
            match flow {
                ImportFlow::Input(mut source) => match key.code {
                    KeyCode::Esc => {}
                    KeyCode::Enter if !source.is_empty() => {
                        match client_import::read_source(source.trim()) {
                            Ok(invitation) => {
                                editor.error = None;
                                self.importing = Some(ImportFlow::Preview {
                                    invitation,
                                    ca: None,
                                    public_ref: None,
                                });
                            }
                            Err(_) => {
                                editor.error =
                                    Some("Неверный URI или локальный файл приглашения.".into());
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
                            && source.len() + ch.len_utf8() <= 4096 =>
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
            let record_action = if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT
            {
                match (editor.role(), key.code) {
                    (Role::Server, KeyCode::Char('N')) => Some(RecordAction::NewInbound),
                    (Role::Client, KeyCode::Char('N')) => Some(RecordAction::NewProfile),
                    (_, KeyCode::Char('D')) => Some(RecordAction::DeleteRecord),
                    (Role::Client, KeyCode::Char('A')) => Some(RecordAction::ActivateProfile),
                    (Role::Server, KeyCode::Char('G')) => Some(RecordAction::SetGrants),
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
            if editor.role() == Role::Server && matches!(key.code, KeyCode::Char('P' | 'X')) {
                self.start_pinned_review(key.code == KeyCode::Char('X'));
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
                    "Конфигурация: не загружена\nInbound: данные не загружены\nRuntime: v запрашивает настоящий статус через native IPC; R проверяет готовность restart без применения\n\nЭтот экран только для чтения. Нужен явный --role server --config FILE для редактирования и подтверждаемого Apply; без него здесь только статус.",
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
                    "Профиль: не выбран\nЛокальный прокси: состояние неизвестно\nТранспорт: не проверялся\nСистемный прокси Windows: не изменён\n\nЭтот экран только для чтения. С --role client --config FILE можно импортировать приглашение клавишей i. Подключение и системный прокси не запускаются автоматически.",
                    true,
                );
            }
        }
        Screen::Help => panel(
            frame,
            parts[1],
            "Справка",
            "1 / 2: сервер / клиент\nTab / Shift+Tab: сменить выбор\nEnter: открыть выбранную панель\nEsc: назад\n? / F1: справка\nq / Ctrl+C: выйти\n\nС явными --role и --config: j/k выбирают inbound/профиль, Tab поле, Enter/e правит поле. l: публичная ссылка без токена. В клиентской панели i: безопасный импорт URI/локального файла с отдельной проверкой CA и сохранением bearer; p: Windows system proxy (отдельные действия и подтверждения). В серверной панели P: локальный pinned-cert-v1 (stream-one), X: собственный XHTTP stream-up с pin; y подтверждает сохранение (не полноценный REALITY), u создаёт пользователя, t: подтверждённая ротация bearer существующего активного пользователя, x: глобальное отключение существующего пользователя (только TOML), b: восстановление с новым токеном. В сетевом обзоре p: пассивный IP обзор, i: согласие ipify; r: группы кандидатов и ручной CIDR (только офлайн), b: IP-список до 8 (Space), d: домен из каталога (отдельные DNS и H2/H3 согласия), t: один IP H2+H3. Ручное v проверяет состояние; Ctrl+R на сохранённой серверной конфигурации открывает отдельное подтверждение CAS Apply (y), а не молча перезапускает. Открытие панелей не выполняет сетевых запросов и не меняет системный прокси.",
            true,
        ),
    }
    if let Some(runtime) = interaction.and_then(|ui| ui.runtime.as_ref()) {
        panel(frame, parts[1], runtime.title(), &runtime.body(), true);
    } else if let Some(review) = interaction.and_then(|ui| ui.pinned_review.as_ref()) {
        panel(
            frame,
            parts[1],
            "H2/H3: дополнительная identity pin (не REALITY)",
            &review.body(),
            true,
        );
    } else if interaction.is_some_and(|ui| ui.pinned_loading.is_some()) {
        panel(frame, parts[1], "Локальная проверка TLS identity", "Проверяются сохранённый TOML и собственная пара сертификат/ключ. Сеть не используется.", true);
    } else if interaction.is_some_and(|ui| ui.saving.is_some()) {
        panel(
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
        panel(frame, parts[1], "Управление записями TOML", &body, true);
    } else if let Some(flow) = interaction.and_then(|ui| ui.issuance.as_ref()) {
        draw_issuance(
            frame,
            parts[1],
            flow,
            interaction.and_then(|ui| ui.editor.as_ref()),
            interaction.map_or(IssueKind::NewUser, |ui| ui.issue_kind),
        );
    } else if let Some(flow) = interaction.and_then(|ui| ui.revocation.as_ref()) {
        draw_revocation(
            frame,
            parts[1],
            flow,
            interaction.and_then(|ui| ui.editor.as_ref()),
        );
    } else if let Some(flow) = interaction.and_then(|ui| ui.importing.as_ref()) {
        draw_import(
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
    #[cfg(windows)]
    if let Some(proxy) = interaction.and_then(|ui| ui.system_proxy.as_ref()) {
        panel(
            frame,
            parts[1],
            "F-07: системный прокси Windows",
            &proxy.body(),
            true,
        );
    }
    let footer = if model.screen == Screen::Client {
        "N/D/A/E: профили  p: Windows proxy  i: импорт  Ctrl+S: сохранить"
    } else {
        "N/D/G/U/E: записи  j/k: выбор  u/t/x/b: users  v: статус  Ctrl+R: Apply  Ctrl+S: сохранить"
    };
    frame.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::ALL)),
        parts[2],
    );
}

fn draw_issuance(
    frame: &mut Frame<'_>,
    area: Rect,
    flow: &IssueFlow,
    editor: Option<&Editor>,
    kind: IssueKind,
) {
    let rotating = kind == IssueKind::Rotation;
    let recovering = kind == IssueKind::Reenable;
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
                "Только данные профиля. Не содержит bearer, CA или grant. Получателю нужны отдельные доверенные credentials и CA.\n\n{link}\n\nEnter/Esc: закрыть."
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
    panel(frame, area, title, &body, true);
}

fn draw_revocation(frame: &mut Frame<'_>, area: Rect, flow: &DisableFlow, editor: Option<&Editor>) {
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
    panel(frame, area, title, &body, true);
}

fn draw_import(frame: &mut Frame<'_>, area: Rect, flow: &ImportFlow, editor: Option<&Editor>) {
    let (title, body) = match flow {
        ImportFlow::Input(source) => (
            "F-14: импорт подключения",
            format!(
                "Введите или вставьте theia://v1/... (новый SmartTheia XHTTP) либо абсолютный путь локального файла.\nИсточник и bearer НИКОГДА не показываются в TUI.\nВведено {} байт (скрыто).\n\nEnter: проверить  Esc: отменить\n\n{}",
                source.len(),
                editor.and_then(|e| e.error.as_deref()).unwrap_or("")
            ),
        ),
        ImportFlow::Preview { invitation, ca, public_ref } => (
            "F-14: безопасный предпросмотр подключения",
            format!(
                "Профиль: {}\nEndpoint: {}\nTLS SNI: {}\nTLS profile: {}\nTransport: {:?}\nXHTTP: {:?}\nBearer: {}\nCA trust: {}\nPin из приглашения сверяйте по доверенному каналу; это не CA.\n\nЗапись добавит НОВЫЙ неактивный профиль. Не перезаписывает существующий ID.\n{}Никакого connect/Apply/Windows proxy.\n\nc: выбрать CA PEM file: путь\n{}y: явно подтвердить запись  n/Esc: отменить\n\n{}",
                invitation.id, invitation.endpoint, invitation.server_name,
                invitation.tls_profile(), invitation.transport, invitation.xhttp_mode(),
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
    panel(frame, area, title, &body, true);
}

fn draw_editor(frame: &mut Frame<'_>, area: Rect, editor: &Editor) {
    let dirty = if editor.dirty() {
        "* Не сохранено"
    } else {
        "Сохранено"
    };
    let message = format!(
        "{}\n\n{}\nВыбрано: {}\n{}\n\n{}\n{}\n\n{}\n\nRuntime: v — проверить статус; Ctrl+R — отдельно подтвердить auth-only Apply; R — read-only restart readiness (не выполняет restart).\nНовый пользователь: u. Ротация токена активного пользователя: t (глобально по всем inbound). Отключение: x. Восстановление с новым токеном: b. Публичная ссылка без токена: l. Клиентский импорт: i (URI/локальный файл, скрытый ввод). N: создать запись; D: удалить; A: активировать профиль; G: grants; U: удалить пользователя; E: TLS/CA и credential. Ctrl+S только сохраняет; runtime не меняет.",
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
        "Редактор TOML (указанный файл)",
        &message,
        true,
    );
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
    loop {
        if interaction.poll_save(&mut model)? {
            crate::diag!(Info, "tui", "saved_and_closed");
            return Ok(());
        }
        if let Some(runtime) = interaction.runtime.as_mut() {
            runtime.poll();
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
        if let Some(domain) = interaction.domain.as_mut() {
            domain.poll();
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
                Event::Paste(text) => {
                    interaction.paste_record_field(&text);
                    interaction.paste_import_source(&text);
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
                draw_issuance(f, a, &IssueFlow::Input("device-a".into()), None, kind)
            });
            assert!(input.contains(label));
            let confirm = render(|f, a| {
                draw_issuance(f, a, &IssueFlow::Confirm("device-a".into()), None, kind)
            });
            assert!(confirm.contains("Подтверждение"));
            assert!(confirm.contains("y: подтвердить"));
            let failed = render(|f, a| draw_issuance(f, a, &IssueFlow::SaveFailed, None, kind));
            assert!(failed.contains("ссылка заблокирована"));
            let offer = render(|f, a| draw_issuance(f, a, &IssueFlow::Offer, None, kind));
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
            let screen = render(|f, a| draw_issuance(f, a, &flow, None, IssueKind::NewUser));
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
            let screen = render(|f, a| draw_revocation(f, a, &flow, None));
            assert!(screen.contains(label), "{screen}");
        }
        let input = render(|f, a| {
            draw_import(
                f,
                a,
                &ImportFlow::Input(Zeroizing::new(hidden.into())),
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
            let screen = render(|f, a| draw_import(f, a, &flow, None));
            assert!(screen.contains(label), "{screen}");
            assert!(!screen.contains(hidden));
        }
    }
}
