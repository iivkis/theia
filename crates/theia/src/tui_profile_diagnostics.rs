//! Named, consent-driven diagnostics workspace; typed results remain in memory.
use crate::{
    local_proxy::profile_diagnostics::{self, Check, CheckKind, Event, Outcome},
    routing::snapshot::validate_diagnostic_domains,
    tui_widgets::{self, ActionItem, Actions},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Frame, layout::{Constraint, Layout, Rect}, style::Style, widgets::{Paragraph, Row, Table, Wrap}};
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
    checks: Vec<Check>,
    finished: Vec<String>,
    domains: Vec<String>,
    receiver: Option<mpsc::Receiver<Event>>,
    confirm: Option<oneshot::Sender<()>>,
    cancel: Option<watch::Sender<bool>>,
    scroll: u16,
    action: usize,
    details: bool,
    completed: bool,
}
impl Panel {
    pub(crate) fn new(path: PathBuf, digest: [u8; 32], id: String) -> Self {
        Self { path, digest, id, phase: Phase::Choose, input: String::new(), error: String::new(),
            report: Vec::new(), checks: Vec::new(), finished: Vec::new(), domains: Vec::new(), receiver: None,
            confirm: None, cancel: None, scroll: 0, action: 0, details: false, completed: false }
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
                Err(_) => { let _ = tx.send(Event::Done(Err(crate::client::ClientError::Io))); }
            }
        });
        if thread.is_err() { self.error = "Не удалось запустить проверку.".into(); return; }
        self.phase = Phase::Fetching;
        self.receiver = Some(rx);
        self.confirm = Some(confirm);
        self.cancel = Some(cancel);
        self.error.clear();
        self.report.clear();
        self.checks.clear();
        self.finished.clear();
        self.domains.clear();
        self.scroll = 0;
        self.action = 0;
        self.completed = false;
    }
    pub(crate) fn poll(&mut self) {
        let Some(rx) = &self.receiver else { return; };
        let mut done = false;
        loop {
            match rx.try_recv() {
                Ok(Event::Line(line)) => self.report.push(line),
                Ok(Event::Check(check)) => self.checks.push(check),
                Ok(Event::DomainDone(domain)) => self.finished.push(domain),
                Ok(Event::Domains(domains)) => { self.domains = domains; self.phase = Phase::Confirm; self.scroll = 0; self.action = 0; }
                Ok(Event::Done(result)) => {
                    self.completed = result.is_ok();
                    if let Err(error) = result { self.error = format!("Проверка прервана: {error}. Частичные результаты сохранены."); }
                    done = true; break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => { self.error = "Сетевой worker завершён без подтверждения результата.".into(); done = true; break; }
            }
        }
        if done { self.phase = Phase::Done; self.receiver = None; self.confirm = None; self.cancel = None; self.action = 0; }
    }
    pub(crate) fn scroll_up(&mut self) { self.scroll = self.scroll.saturating_sub(3); }
    pub(crate) fn scroll_down(&mut self) {
        let lines = if self.details { self.report.len() + self.checks.len() } else { self.domains.len() + 8 };
        self.scroll = self.scroll.saturating_add(3).min((lines.saturating_mul(2)) as u16);
    }
    pub(crate) fn paste(&mut self, input: &str) {
        if self.phase == Phase::Custom && self.input.len().saturating_add(input.len()) <= 4096
            && input.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b',' | b' ' | b'\n' | b'\r' | b'\t')) {
            self.input.push_str(input);
        }
    }
    fn failed_domains(&self) -> Vec<String> {
        self.domains.iter().filter(|domain| {
            let blocked = self.checks.iter().any(|check| check.domain.as_ref() == Some(*domain)
                && matches!(check.outcome, Outcome::Route(crate::routing::Action::Blocked)));
            !blocked && (!self.finished.contains(domain) || self.checks.iter().any(|check|
                check.domain.as_ref() == Some(*domain) && check.failed()))
        }).cloned().collect()
    }
    fn actions(&self) -> Vec<ActionItem> {
        let item = |key, label| ActionItem { key, label };
        match self.phase {
            Phase::Choose => vec![item('1', "Домены, предложенные сервером"), item('2', "Ввести свои домены")],
            Phase::Custom => vec![],
            Phase::Fetching | Phase::Running => vec![item('c', "Остановить и сохранить результаты"), item('d', "Сводка / подробности")],
            Phase::Confirm => vec![item('y', "Начать проверку указанных ресурсов"), item('c', "Отменить")],
            Phase::Done => {
                let mut actions = vec![item('n', "Новая диагностика"), item('d', "Сводка / подробности")];
                if !self.failed_domains().is_empty() { actions.push(item('r', "Повторить только неуспешные ресурсы")); }
                if !self.checks.is_empty() { actions.push(item('e', "Экспортировать обезличенный отчёт")); }
                actions
            }
        }
    }
    fn export(&mut self) -> std::io::Result<()> {
        use std::{io::Write, time::{SystemTime, UNIX_EPOCH}};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(std::io::Error::other)?;
        let name = format!("theia-diagnostics-{}-{}.txt", now.as_secs(), now.subsec_nanos());
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut file = options.open(&name)?;
        writeln!(file, "Theia · обезличенная сетевая диагностика\nЗавершена: {}", self.completed)?;
        for check in &self.checks {
            let number = check.domain.as_ref().and_then(|d| self.domains.iter().position(|v| v == d));
            if let Some(number) = number { write!(file, "№{} ", number + 1)?; }
            writeln!(file, "{}", check.line(true))?;
        }
        file.sync_all()?;
        self.error = format!("Отчёт сохранён в текущем каталоге: {name}");
        Ok(())
    }
    fn stop(&mut self) {
        if let Some(tx) = &self.cancel { let _ = tx.send(true); }
        self.error = "Остановка проверки…".into();
    }
    pub(crate) fn key(&mut self, mut key: KeyEvent) -> bool {
        if key.code == KeyCode::Esc {
            if matches!(self.phase, Phase::Fetching | Phase::Confirm | Phase::Running) { self.stop(); return false; }
            if self.phase == Phase::Custom { self.phase = Phase::Choose; self.action = 0; return false; }
            return true;
        }
        if self.phase != Phase::Custom && key.modifiers.is_empty() {
            let items = self.actions();
            if let Some(code) = tui_widgets::action_key(&items, &mut self.action, key.code) { key.code = code; } else { return false; }
        }
        match key.code {
            KeyCode::PageUp => self.scroll_up(),
            KeyCode::PageDown => self.scroll_down(),
            KeyCode::Char('1') if self.phase == Phase::Choose => self.start(None),
            KeyCode::Char('2') if self.phase == Phase::Choose => { self.phase = Phase::Custom; self.error.clear(); }
            KeyCode::Backspace if self.phase == Phase::Custom => { self.input.pop(); }
            KeyCode::Char('u') if self.phase == Phase::Custom && key.modifiers.contains(KeyModifiers::CONTROL) => self.input.clear(),
            KeyCode::Char(ch) if self.phase == Phase::Custom && !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => self.paste(&ch.to_string()),
            KeyCode::Enter if self.phase == Phase::Custom => {
                match parse_domains(&self.input) {
                    Some(domains) => self.start(Some(domains)),
                    None => self.error = "Введите 1–16 различных доменов без URL, порта или IP.".into(),
                }
            }
            KeyCode::Char('y') if self.phase == Phase::Confirm => {
                if self.confirm.take().is_some_and(|tx| tx.send(()).is_ok()) {
                    self.phase = Phase::Running; self.scroll = 0; self.action = 0;
                } else { self.phase = Phase::Done; self.error = "Сессия истекла.".into(); }
            }
            KeyCode::Char('c') if matches!(self.phase, Phase::Fetching | Phase::Confirm | Phase::Running) => self.stop(),
            KeyCode::Char('d') if matches!(self.phase, Phase::Fetching | Phase::Running | Phase::Done) => { self.details = !self.details; self.scroll = 0; }
            KeyCode::Char('n') if self.phase == Phase::Done => { self.phase = Phase::Choose; self.error.clear(); self.action = 0; self.scroll = 0; }
            KeyCode::Char('r') if self.phase == Phase::Done => {
                let domains = self.failed_domains();
                if !domains.is_empty() { self.start(Some(domains)); }
            }
            KeyCode::Char('e') if self.phase == Phase::Done && !self.checks.is_empty() => {
                if self.export().is_err() { self.error = "Не удалось записать обезличенный отчёт.".into(); }
            }
            _ => {}
        }
        false
    }
    fn lead(&self) -> String {
        match self.phase {
            Phase::Choose => "Выберите источник списка. Обращение к серверу не запускает проверку сайтов.".into(),
            Phase::Custom => format!("Домены через пробел или запятую (до 16):\n{}\nEnter — проверить сервер · Ctrl+U — очистить", self.input),
            Phase::Fetching => "Проверяются H2/H3 и разрешения сервера…".into(),
            Phase::Confirm => format!("Разрешить HTTPS:443 и QUIC/HTTP3 на этих ресурсах? Локальные запросы возможны только по разрешённым правилам.\n{}", self.domains.join("\n")),
            Phase::Running => format!("Проверено {} из {} ресурсов…", self.finished.len(), self.domains.len()),
            Phase::Done => if self.completed { "Проверки завершены; результаты могут содержать отказы.".into() } else { "Проверка прервана; доступен частичный отчёт.".into() },
        }
    }
    fn cell(&self, domain: &str, check_kind: fn(&CheckKind) -> bool) -> String {
        self.checks.iter().rev().find(|c| c.domain.as_deref() == Some(domain) && check_kind(&c.kind))
            .map_or_else(|| "—".into(), |c| match c.outcome {
                Outcome::Http(status, _, _) | Outcome::Udp(status, _) => format!("{status}"),
                Outcome::Failure(_) => "Ошибка".into(),
                Outcome::Skipped(_) => "Пропуск".into(),
                _ => "—".into(),
            })
    }
    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let actions = self.actions();
        let controls = if !actions.is_empty() && area.height >= 8 { (actions.len() as u16 + 2).min(area.height.saturating_sub(5)) } else { 0 };
        let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(controls)]).split(area);
        let general = self.checks.iter().filter(|check| check.domain.is_none()).map(|check| check.line(false)).collect::<Vec<_>>().join("\n");
        let body = format!("Профиль: {} · System Proxy\n{}\n{}\n{}\nPgUp/PgDn — прокрутка · Esc — назад/остановить", self.id, self.lead(), general, self.error);
        let table_mode = !self.details && matches!(self.phase, Phase::Running | Phase::Done) && !self.domains.is_empty() && parts[0].height >= 12 && parts[0].width >= 55;
        if table_mode {
            let regions = Layout::vertical([Constraint::Length(8.min(parts[0].height.saturating_sub(4))), Constraint::Min(1)]).split(parts[0]);
            frame.render_widget(Paragraph::new(body).block(tui_widgets::section("Сетевая диагностика профиля", true)).wrap(Wrap { trim: false }), regions[0]);
            let rows = self.domains.iter().skip(usize::from(self.scroll)).map(|domain| {
                Row::new(vec![domain.clone(),
                    self.cell(domain, |k| matches!(k, CheckKind::Https("штатный"))),
                    self.cell(domain, |k| matches!(k, CheckKind::Https("H2"))),
                    self.cell(domain, |k| matches!(k, CheckKind::Https("H3"))),
                    self.cell(domain, |k| matches!(k, CheckKind::Udp("H2"))),
                    self.cell(domain, |k| matches!(k, CheckKind::Udp("H3"))),
                ])
            });
            frame.render_widget(Table::new(rows, [Constraint::Min(15), Constraint::Length(7), Constraint::Length(7), Constraint::Length(7), Constraint::Length(7), Constraint::Length(7)])
                .header(Row::new(["Ресурс", "Авто", "H2", "H3", "UDP/H2", "UDP/H3"]).style(Style::default().fg(tui_widgets::MUTED)))
                .block(tui_widgets::section("HTTP-коды · — не проверено", false)), regions[1]);
        } else {
            let lines = if self.details || matches!(self.phase, Phase::Running | Phase::Done) {
                self.checks.iter().filter(|c| c.domain.is_some()).map(|c| c.line(false)).collect::<Vec<_>>().join("\n")
            } else { String::new() };
            let text = format!("{body}\n\n{}\n{lines}", self.report.join("\n"));
            frame.render_widget(Paragraph::new(text).block(tui_widgets::section("Сетевая диагностика профиля", true)).wrap(Wrap { trim: false }).scroll((self.scroll, 0)), parts[0]);
        }
        if controls > 0 { Actions { items: &actions, selected: self.action }.render(frame, parts[1]); }
    }
}
impl Drop for Panel {
    fn drop(&mut self) { if let Some(tx) = self.cancel.take() { let _ = tx.send(true); } }
}
pub(crate) fn parse_domains(input: &str) -> Option<Vec<String>> {
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
    #[test]
    fn retry_and_export_respect_privacy_and_policy() {
        let mut panel = Panel::new(PathBuf::from("nonexistent"), [0; 32], "secret-profile".into());
        panel.domains = vec!["ok.test".into(), "failed.test".into(), "blocked.test".into()];
        panel.finished = vec!["ok.test".into(), "failed.test".into(), "blocked.test".into()];
        panel.checks.push(Check { domain: Some("failed.test".into()), kind: CheckKind::Https("H2"), outcome: Outcome::Failure(crate::client::ClientError::Timeout) });
        panel.checks.push(Check { domain: Some("blocked.test".into()), kind: CheckKind::Policy, outcome: Outcome::Route(crate::routing::Action::Blocked) });
        assert_eq!(panel.failed_domains(), vec!["failed.test"]);
        assert!(!panel.checks[0].line(true).contains("failed.test"));
    }
}
