
use crate::{local_proxy::profile_diagnostics::{self, Event}, routing::snapshot::validate_diagnostic_domains};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Frame, layout::Rect, widgets::{Paragraph, Wrap}};
use std::{path::PathBuf, sync::mpsc};
use tokio::sync::{oneshot, watch};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Choose, Custom, Fetching, Confirm, Running, Done }

pub(crate) struct Panel {
    path: PathBuf,
    digest: [u8; 32],
    id: String,
    phase: Phase,
    input: String,
    error: String,
    report: Vec<String>,
    domains: Vec<String>,
    receiver: Option<mpsc::Receiver<Event>>,
    confirm: Option<oneshot::Sender<()>>,
    cancel: Option<watch::Sender<bool>>,
    scroll: u16,
}

impl Panel {
    pub(crate) fn new(path: PathBuf, digest: [u8; 32], id: String) -> Self {
        Self { path, digest, id, phase: Phase::Choose, input: String::new(), error: String::new(),
            report: Vec::new(), domains: Vec::new(), receiver: None, confirm: None, cancel: None, scroll: 0 }
    }
    fn start(&mut self, custom: Option<Vec<String>>) {
        let (tx, rx) = mpsc::channel();
        let (confirm, confirmed) = oneshot::channel();
        let (cancel, cancelled) = watch::channel(false);
        let path = self.path.clone();
        let digest = self.digest;
        let id = self.id.clone();
        let thread = std::thread::Builder::new().name("profile-diagnostics".into()).spawn(move || {
            match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime.block_on(profile_diagnostics::run(path, digest, id, custom, tx, confirmed, cancelled)),
                Err(_) => { let _ = tx.send(Event::Line("Не удалось запустить сетевой runtime.".into())); let _ = tx.send(Event::Done); }
            }
        });
        if thread.is_err() { self.error = "Не удалось запустить проверку.".into(); return; }
        self.phase = Phase::Fetching;
        self.receiver = Some(rx);
        self.confirm = Some(confirm);
        self.cancel = Some(cancel);
        self.error.clear();
        self.report.clear();
        self.scroll = 0;
    }
    pub(crate) fn poll(&mut self) {
        let Some(rx) = &self.receiver else { return; };
        let mut done = false;
        loop {
            match rx.try_recv() {
                Ok(Event::Line(line)) => self.report.push(line),
                Ok(Event::Domains(domains)) => { self.domains = domains; self.phase = Phase::Confirm; self.scroll = 0; }
                Ok(Event::Done) => { done = true; break; }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => { self.report.push("Сетевой worker завершён.".into()); done = true; break; }
            }
        }
        if done { self.phase = Phase::Done; self.receiver = None; self.confirm = None; self.cancel = None; }
    }
    pub(crate) fn scroll_up(&mut self) { self.scroll = self.scroll.saturating_sub(3); }
    pub(crate) fn scroll_down(&mut self) { self.scroll = self.scroll.saturating_add(3).min((self.report.len().saturating_mul(4) + self.domains.len() + 10) as u16); }
    pub(crate) fn paste(&mut self, input: &str) {
        if self.phase == Phase::Custom && self.input.len().saturating_add(input.len()) <= 4096
            && input.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b',' | b' ' | b'\n' | b'\r' | b'\t')) {
            self.input.push_str(input);
        }
    }
    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        if key.code == KeyCode::Esc { return true; }
        match key.code {
            KeyCode::Up | KeyCode::PageUp => self.scroll_up(),
            KeyCode::Down | KeyCode::PageDown => self.scroll_down(),
            KeyCode::Home if self.phase != Phase::Custom => self.scroll = 0,
            KeyCode::Char('1') if self.phase == Phase::Choose => self.start(None),
            KeyCode::Char('2') if self.phase == Phase::Choose => { self.phase = Phase::Custom; self.error.clear(); }
            KeyCode::Backspace if self.phase == Phase::Custom => { self.input.pop(); }
            KeyCode::Char(ch) if self.phase == Phase::Custom && !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => self.paste(&ch.to_string()),
            KeyCode::Enter if self.phase == Phase::Custom => {
                match parse_domains(&self.input) {
                    Some(domains) => self.start(Some(domains)),
                    None => self.error = "Введите 1–16 различных доменов без URL, порта или IP.".into(),
                }
            }
            KeyCode::Enter if self.phase == Phase::Confirm => {
                if self.confirm.take().is_some_and(|tx| tx.send(()).is_ok()) {
                    self.phase = Phase::Running; self.scroll = 0;
                } else { self.phase = Phase::Done; self.error = "Сессия истекла.".into(); }
            }
            KeyCode::Enter if self.phase == Phase::Done => {
                self.phase = Phase::Choose; self.report.clear(); self.domains.clear(); self.scroll = 0; self.error.clear();
            }
            _ => {}
        }
        false
    }
    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let lead = match self.phase {
            Phase::Choose => "1 — получить предложенные сервером домены\n2 — ввести свои домены\nВыбор запускает только авторизованное обращение к серверу. Проверка сайтов потребует отдельного подтверждения.".to_owned(),
            Phase::Custom => format!("Домены через пробел или запятую (до 16):\n{}\nEnter — проверить сервер и подготовить список", self.input),
            Phase::Fetching => "Проверяется связь с сервером…".into(),
            Phase::Confirm => format!("Будут проверены:\n{}\nEnter — разрешить сетевые запросы к этим доменам (HTTPS:443).", self.domains.join("\n")),
            Phase::Running => "Выполняются сетевые проверки…".into(),
            Phase::Done => "Проверка окончена. Enter — новый запуск.".into(),
        };
        let body = format!("Профиль: {} · System Proxy\nEsc — закрыть/отменить · ↑↓ — прокрутка\n\n{}\n{}\n\n{}", self.id, lead, self.error, self.report.join("\n"));
        frame.render_widget(Paragraph::new(body).block(crate::tui_widgets::section("Сетевая диагностика профиля", true))
            .wrap(Wrap { trim: false }).scroll((self.scroll, 0)), area);
    }
}
impl Drop for Panel {
    fn drop(&mut self) { if let Some(tx) = self.cancel.take() { let _ = tx.send(true); } }
}
fn parse_domains(input: &str) -> Option<Vec<String>> {
    let domains: Vec<String> = input.split(|c: char| c == ',' || c.is_ascii_whitespace()).filter(|s| !s.is_empty()).map(str::to_ascii_lowercase).collect();
    validate_diagnostic_domains(&domains).then_some(domains)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn custom_domains_are_canonical_and_bounded() {
        assert_eq!(parse_domains("Discord.COM, x.com\n").unwrap(), vec!["discord.com", "x.com"]);
        assert!(parse_domains("https://x.com").is_none());
        assert!(parse_domains("x.com X.COM").is_none());
        assert!(parse_domains("127.0.0.1").is_none());
    }
    #[test]
    fn opening_panel_does_not_start_network() {
        let panel = Panel::new(PathBuf::from("nonexistent"), [0; 32], "test".into());
        assert!(panel.phase == Phase::Choose);
        assert!(panel.receiver.is_none());
    }
}
