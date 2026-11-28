//! Named, consent-driven diagnostics workspace; typed results remain in memory.
use crate::{
    local_proxy::profile_diagnostics::{self, Check, CheckKind, Event, Outcome},
    routing::snapshot::validate_diagnostic_domains,
    tui_widgets::{self, ActionItem, Actions},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Rect},
    style::Style,
    widgets::{Paragraph, Row, Table},
    Frame,
};
use std::{path::PathBuf, sync::mpsc};
use tokio::sync::{oneshot, watch};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Choose,
    Custom,
    Fetching,
    Confirm,
    Running,
    Done,
}

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
        Self {
            path,
            digest,
            id,
            phase: Phase::Choose,
            input: String::new(),
            error: String::new(),
            report: Vec::new(),
            checks: Vec::new(),
            finished: Vec::new(),
            domains: Vec::new(),
            receiver: None,
            confirm: None,
            cancel: None,
            scroll: 0,
            action: 0,
            details: false,
            completed: false,
        }
    }
    fn start(&mut self, custom: Option<Vec<String>>) {
        let (tx, rx) = mpsc::channel();
        let (confirm, confirmed) = oneshot::channel();
        let (cancel, cancelled) = watch::channel(false);
        let path = self.path.clone();
        let digest = self.digest;
        let id = self.id.clone();
        let thread = std::thread::Builder::new()
            .name("profile-diagnostics".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(profile_diagnostics::run(
                        path, digest, id, custom, tx, confirmed, cancelled,
                    )),
                    Err(_) => {
                        let _ = tx.send(Event::Done(Err(crate::client::ClientError::Io)));
                    }
                }
            });
        if thread.is_err() {
            self.error = "Не удалось запустить проверку.".into();
            return;
        }
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
        self.details = false;
    }
    pub(crate) fn poll(&mut self) {
        let Some(rx) = &self.receiver else {
            return;
        };
        let mut done = false;
        loop {
            match rx.try_recv() {
                Ok(Event::Line(line)) => self.report.push(line),
                Ok(Event::Check(check)) => self.checks.push(check),
                Ok(Event::DomainDone(domain)) => self.finished.push(domain),
                Ok(Event::Domains(domains)) => {
                    self.domains = domains;
                    self.phase = Phase::Confirm;
                    self.scroll = 0;
                    self.action = 0;
                }
                Ok(Event::Done(result)) => {
                    self.completed = result.is_ok();
                    if let Err(error) = result {
                        self.error =
                            format!("Проверка прервана: {error}. Частичные результаты сохранены.");
                    }
                    done = true;
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.error = "Сетевой worker завершён без подтверждения результата.".into();
                    done = true;
                    break;
                }
            }
        }
        if done {
            self.phase = Phase::Done;
            self.receiver = None;
            self.confirm = None;
            self.cancel = None;
            self.action = 0;
        }
    }
    pub(crate) fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(3);
    }
    pub(crate) fn scroll_down(&mut self) {
        let lines = if self.details {
            self.report.len() + self.checks.len()
        } else {
            self.domains.len() + 8
        };
        self.scroll = self
            .scroll
            .saturating_add(3)
            .min((lines.saturating_mul(2)) as u16);
    }
    pub(crate) fn paste(&mut self, input: &str) {
        if self.phase == Phase::Custom
            && self.input.len().saturating_add(input.len()) <= 4096
            && input.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'.' | b'-' | b',' | b' ' | b'\n' | b'\r' | b'\t')
            })
        {
            self.input.push_str(input);
        }
    }
    fn policy_blocked(&self, domain: &str) -> bool {
        self.checks.iter().any(|check| {
            check.domain.as_deref() == Some(domain)
                && matches!(
                    check.outcome,
                    Outcome::Route(crate::routing::Action::Blocked)
                )
        })
    }

    fn failed_domains(&self) -> Vec<String> {
        self.domains
            .iter()
            .filter(|domain| {
                !self.policy_blocked(domain)
                    && (!self.finished.contains(domain)
                        || self
                            .checks
                            .iter()
                            .any(|check| check.domain.as_ref() == Some(*domain) && check.failed()))
            })
            .cloned()
            .collect()
    }
    fn actions(&self) -> Vec<ActionItem> {
        let item = |key, label| ActionItem { key, label };
        match self.phase {
            Phase::Choose => vec![
                item('1', "Домены, предложенные сервером"),
                item('2', "Ввести свои домены"),
            ],
            Phase::Custom => vec![],
            Phase::Fetching | Phase::Running => vec![
                item('c', "Остановить и сохранить результаты"),
                item('d', "Сводка / подробности"),
            ],
            Phase::Confirm => vec![
                item('c', "Отменить"),
                item('y', "Начать проверку указанных ресурсов"),
            ],
            Phase::Done => {
                let mut actions = vec![
                    item('n', "Новая диагностика"),
                    item('d', "Сводка / подробности"),
                ];
                if !self.failed_domains().is_empty() {
                    actions.push(item('r', "Повторить только неуспешные ресурсы"));
                }
                if !self.checks.is_empty() {
                    actions.push(item('e', "Экспортировать обезличенный отчёт"));
                }
                actions
            }
        }
    }
    fn export(&mut self) -> std::io::Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?;
        let name = format!(
            "theia-diagnostics-{}-{}.txt",
            now.as_secs(),
            now.subsec_nanos()
        );
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&name)?;
        self.write_export(&mut file)?;
        file.sync_all()?;
        self.error = format!("Отчёт сохранён в текущем каталоге: {name}");
        Ok(())
    }
    fn write_export(&self, mut file: impl std::io::Write) -> std::io::Result<()> {
        writeln!(
            file,
            "Theia · обезличенная сетевая диагностика\nЗавершена: {}",
            self.completed
        )?;
        for check in &self.checks {
            let number = check
                .domain
                .as_ref()
                .and_then(|d| self.domains.iter().position(|v| v == d));
            if let Some(number) = number {
                write!(file, "№{} ", number + 1)?;
            }
            writeln!(file, "{}", check.line(true))?;
        }
        Ok(())
    }
    fn stop(&mut self) {
        if let Some(tx) = &self.cancel {
            let _ = tx.send(true);
        }
        self.error = "Остановка проверки…".into();
    }
    pub(crate) fn key(&mut self, mut key: KeyEvent) -> bool {
        if key.code == KeyCode::Esc {
            if matches!(
                self.phase,
                Phase::Fetching | Phase::Confirm | Phase::Running
            ) {
                self.stop();
                return false;
            }
            if self.phase == Phase::Custom {
                self.phase = Phase::Choose;
                self.action = 0;
                self.scroll = 0;
                self.error.clear();
                return false;
            }
            return true;
        }
        if self.phase != Phase::Custom && key.modifiers.is_empty() {
            let items = self.actions();
            if let Some(code) = tui_widgets::action_key(&items, &mut self.action, key.code) {
                key.code = code;
            } else {
                return false;
            }
        }
        match key.code {
            KeyCode::PageUp => self.scroll_up(),
            KeyCode::PageDown => self.scroll_down(),
            KeyCode::Char('1') if self.phase == Phase::Choose => self.start(None),
            KeyCode::Char('2') if self.phase == Phase::Choose => {
                self.phase = Phase::Custom;
                self.error.clear();
                self.scroll = 0;
            }
            KeyCode::Backspace if self.phase == Phase::Custom => {
                self.input.pop();
            }
            KeyCode::Char('u')
                if self.phase == Phase::Custom && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.input.clear()
            }
            KeyCode::Char(ch)
                if self.phase == Phase::Custom
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.paste(&ch.to_string())
            }
            KeyCode::Enter if self.phase == Phase::Custom => match parse_domains(&self.input) {
                Some(domains) => self.start(Some(domains)),
                None => self.error = "Введите 1–16 различных доменов без URL, порта или IP.".into(),
            },
            KeyCode::Char('y') if self.phase == Phase::Confirm => {
                if self.confirm.take().is_some_and(|tx| tx.send(()).is_ok()) {
                    self.phase = Phase::Running;
                    self.scroll = 0;
                    self.action = 0;
                } else {
                    self.phase = Phase::Done;
                    self.error = "Сессия истекла.".into();
                }
            }
            KeyCode::Char('c')
                if matches!(
                    self.phase,
                    Phase::Fetching | Phase::Confirm | Phase::Running
                ) =>
            {
                self.stop()
            }
            KeyCode::Char('d')
                if matches!(self.phase, Phase::Fetching | Phase::Running | Phase::Done) =>
            {
                self.details = !self.details;
                self.scroll = 0;
            }
            KeyCode::Char('n') if self.phase == Phase::Done => {
                self.phase = Phase::Choose;
                self.error.clear();
                self.report.clear();
                self.checks.clear();
                self.finished.clear();
                self.domains.clear();
                self.input.clear();
                self.details = false;
                self.completed = false;
                self.action = 0;
                self.scroll = 0;
            }
            KeyCode::Char('r') if self.phase == Phase::Done => {
                let domains = self.failed_domains();
                if !domains.is_empty() {
                    self.start(Some(domains));
                }
            }
            KeyCode::Char('e') if self.phase == Phase::Done && !self.checks.is_empty() => {
                self.export().unwrap_or_else(|_| {
                    self.error = "Не удалось записать обезличенный отчёт.".into();
                });
            }
            _ => {}
        }
        false
    }
    fn lead(&self) -> String {
        match self.phase {
            Phase::Choose => "Выберите источник списка. Обращение к серверу не запускает проверку сайтов.".into(),
            Phase::Custom => format!("Домены через пробел или запятую (до 16):\n› {}", self.input),
            Phase::Fetching => "Проверяются H2/H3 и разрешения сервера…".into(),
            Phase::Confirm => format!("Разрешить HTTPS:443 и QUIC/HTTP3 на этих ресурсах? Локальные запросы возможны только по разрешённым правилам.\n{}", self.domains.join("\n")),
            Phase::Running => format!("Проверено {} из {} ресурсов…", self.finished.len(), self.domains.len()),
            Phase::Done => {
                let blocked = self.domains.iter().filter(|d| self.policy_blocked(d)).count();
                let failed = self.failed_domains().len();
                let status = if self.completed {
                    "Проверки завершены"
                } else if self.checks.is_empty() {
                    "Проверка не выполнена"
                } else {
                    "Проверка прервана"
                };
                format!("{status}. Обработано: {}/{} · Блокировано политикой: {blocked} · К повтору: {failed}", self.finished.len(), self.domains.len())
            },
        }
    }
    fn cell(&self, domain: &str, check_kind: fn(&CheckKind) -> bool) -> String {
        self.checks
            .iter()
            .rev()
            .find(|c| c.domain.as_deref() == Some(domain) && check_kind(&c.kind))
            .map_or_else(
                || "—".into(),
                |c| match c.outcome {
                    Outcome::Http(status, _, _) | Outcome::Udp(status, _, _) => format!("{status}"),
                    Outcome::Failure(_) => "Ошибка".into(),
                    Outcome::Skipped(_) => "Пропуск".into(),
                    _ => "—".into(),
                },
            )
    }
    pub(crate) fn footer(&self) -> &'static str {
        match self.phase {
            Phase::Choose => "↑ ↓ выбор · Enter открыть · Esc назад",
            Phase::Custom => {
                "Enter проверить сервер · Ctrl+U очистить · Esc назад · PgUp/PgDn прокрутка"
            }
            Phase::Confirm => {
                "↑ ↓ выбор · Enter выполнить выбор · Esc отменить · PgUp/PgDn прокрутка"
            }
            Phase::Fetching | Phase::Running => {
                "↑ ↓ выбор · Enter выполнить · Esc остановить · PgUp/PgDn прокрутка"
            }
            Phase::Done => "↑ ↓ выбор · Enter выполнить · Esc назад · PgUp/PgDn прокрутка",
        }
    }

    fn text(&self, table: bool) -> String {
        let mut lines = vec![format!("Профиль: {}", self.id), self.lead()];
        if !self.error.is_empty() {
            lines.push(self.error.clone());
        }
        lines.extend(
            self.checks
                .iter()
                .filter(|check| check.domain.is_none())
                .map(|check| check.line(false)),
        );
        if !table {
            lines.extend(self.report.iter().cloned());
            if self.details || matches!(self.phase, Phase::Running | Phase::Done) {
                lines.extend(
                    self.checks
                        .iter()
                        .filter(|check| check.domain.is_some())
                        .map(|check| check.line(false)),
                );
            }
        }
        lines.join("\n")
    }

    // One geometry for drawing and hit-testing. Short states never reserve
    // the entire terminal, and long reports keep their actions visible.
    fn layout(&self, area: Rect) -> (Rect, Option<Rect>, Option<Rect>) {
        let count = self.actions().len();
        let controls = if count > 0 && area.height >= 8 {
            (count as u16 + 2).min(area.height / 2)
        } else {
            0
        };
        let available = area.height.saturating_sub(controls);
        let table = !self.details
            && matches!(self.phase, Phase::Running | Phase::Done)
            && !self.domains.is_empty()
            && available >= 12
            && area.width >= 55;
        let body = self.text(table);
        let rows = crate::tui::visual_rows(&body, usize::from(area.width.saturating_sub(2)))
            .0
            .len();
        let preferred = (rows.saturating_add(2)).min(u16::MAX as usize) as u16;
        let report_height = if table {
            preferred.min(available.saturating_sub(4)).min(8)
        } else {
            preferred.min(available)
        };
        let report = Rect::new(area.x, area.y, area.width, report_height);
        let table = table.then(|| {
            Rect::new(
                area.x,
                report.bottom(),
                area.width,
                (self.domains.len() as u16 + 3).min(available.saturating_sub(report_height)),
            )
        });
        let bottom = table.map_or(report.bottom(), |rect| rect.bottom());
        let actions = (controls > 0).then(|| Rect::new(area.x, bottom, area.width, controls));
        (report, table, actions)
    }

    pub(crate) fn select_at(&mut self, area: Rect, x: u16, y: u16) {
        if let (_, _, Some(controls)) = self.layout(area) {
            let items = self.actions();
            if let Some(index) = (Actions {
                items: &items,
                selected: self.action,
            })
            .hit(controls, x, y)
            {
                self.action = index;
            }
        }
    }

    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let (report, table, controls) = self.layout(area);
        let body = self.text(table.is_some());
        let rows = crate::tui::visual_rows(&body, usize::from(report.width.saturating_sub(2))).0;
        let visible = usize::from(report.height.saturating_sub(2));
        let offset = if table.is_some() {
            0
        } else {
            usize::from(self.scroll).min(rows.len().saturating_sub(visible))
        };
        frame.render_widget(
            Paragraph::new(
                rows.into_iter()
                    .skip(offset)
                    .take(visible)
                    .collect::<Vec<_>>(),
            )
            .block(tui_widgets::section("Сетевая диагностика профиля", true)),
            report,
        );
        if let Some(table) = table {
            let visible = usize::from(table.height.saturating_sub(3));
            let offset = usize::from(self.scroll).min(self.domains.len().saturating_sub(visible));
            let rows = self.domains.iter().skip(offset).map(|domain| {
                if self.policy_blocked(domain) {
                    return Row::new(vec![
                        domain.clone(),
                        "Блок".into(),
                        "—".into(),
                        "—".into(),
                        "—".into(),
                        "—".into(),
                        "—".into(),
                    ])
                    .style(Style::default().fg(tui_widgets::WARNING));
                }
                Row::new(vec![
                    domain.clone(),
                    self.cell(domain, |k| matches!(k, CheckKind::Https("штатный"))),
                    self.cell(domain, |k| matches!(k, CheckKind::Https("H2"))),
                    self.cell(domain, |k| matches!(k, CheckKind::Https("H3"))),
                    self.cell(domain, |k| matches!(k, CheckKind::Udp("штатный"))),
                    self.cell(domain, |k| matches!(k, CheckKind::Udp("H2"))),
                    self.cell(domain, |k| matches!(k, CheckKind::Udp("H3"))),
                ])
            });
            frame.render_widget(
                Table::new(
                    rows,
                    [
                        Constraint::Min(12),
                        Constraint::Length(6),
                        Constraint::Length(6),
                        Constraint::Length(6),
                        Constraint::Length(7),
                        Constraint::Length(7),
                        Constraint::Length(7),
                    ],
                )
                .header(
                    Row::new(["Ресурс", "Авто", "H2", "H3", "UDP авт", "UDP/H2", "UDP/H3"])
                        .style(Style::default().fg(tui_widgets::MUTED)),
                )
                .block(tui_widgets::section(
                    "HTTP-коды · Блок: запрещено политикой · — не проверено",
                    false,
                )),
                table,
            );
        }
        if let Some(controls) = controls {
            Actions {
                items: &self.actions(),
                selected: self.action,
            }
            .render(frame, controls);
        }
    }
}
impl Drop for Panel {
    fn drop(&mut self) {
        if let Some(tx) = self.cancel.take() {
            let _ = tx.send(true);
        }
    }
}
pub(crate) fn parse_domains(input: &str) -> Option<Vec<String>> {
    let domains: Vec<String> = input
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    validate_diagnostic_domains(&domains).then_some(domains)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn custom_domains_are_canonical_and_bounded() {
        assert_eq!(
            parse_domains("Discord.COM, x.com\n").unwrap(),
            vec!["discord.com", "x.com"]
        );
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
    fn screen(panel: &Panel, width: u16, height: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| panel.render(frame, frame.area()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn confirmation_and_partial_report_have_distinct_workspace_states() {
        use crate::{client::ClientError, local_proxy::profile_diagnostics::ActualRoute};
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let mut panel = Panel::new(PathBuf::from("nonexistent"), [0; 32], "profile".into());
        assert!(screen(&panel, 100, 25).contains("Домены, предложенные сервером"));
        panel.key(key(KeyCode::Down));
        panel.key(key(KeyCode::Enter));
        assert!(panel.phase == Phase::Custom);
        panel.paste("https://invalid");
        assert!(panel.input.is_empty());
        panel.paste("discord.com, x.com");
        panel.key(key(KeyCode::Backspace));
        assert_eq!(panel.input, "discord.com, x.co");
        panel.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        panel.key(key(KeyCode::Enter));
        assert!(panel.error.contains("Введите"));
        panel.key(key(KeyCode::Esc));
        assert!(panel.phase == Phase::Choose);
        let (tx, rx) = mpsc::channel();
        let (confirm, mut confirmation) = oneshot::channel();
        let (cancel, cancelled) = watch::channel(false);
        panel.phase = Phase::Fetching;
        panel.receiver = Some(rx);
        panel.confirm = Some(confirm);
        panel.cancel = Some(cancel);
        tx.send(Event::Check(Check {
            domain: None,
            kind: CheckKind::Carrier("H2"),
            outcome: Outcome::Verified(8),
        }))
        .unwrap();
        tx.send(Event::Line("Сервер проверен".into())).unwrap();
        tx.send(Event::Domains(vec!["discord.com".into(), "x.com".into()]))
            .unwrap();
        panel.poll();
        assert!(panel.phase == Phase::Confirm);
        assert!(confirmation.try_recv().is_err());
        assert!(screen(&panel, 100, 25).contains("discord.com"));
        assert_eq!(panel.actions()[0].key, 'c');
        panel.key(key(KeyCode::Char('y')));
        assert_eq!(confirmation.try_recv(), Ok(()));
        assert!(panel.phase == Phase::Running);
        tx.send(Event::Check(Check {
            domain: Some("discord.com".into()),
            kind: CheckKind::Https("штатный"),
            outcome: Outcome::Http(200, ActualRoute::Direct, 10),
        }))
        .unwrap();
        tx.send(Event::Check(Check {
            domain: Some("discord.com".into()),
            kind: CheckKind::Https("H2"),
            outcome: Outcome::Skipped("не разрешён"),
        }))
        .unwrap();
        tx.send(Event::Check(Check {
            domain: Some("x.com".into()),
            kind: CheckKind::Udp("H3"),
            outcome: Outcome::Failure(ClientError::Timeout),
        }))
        .unwrap();
        tx.send(Event::DomainDone("discord.com".into())).unwrap();
        panel.poll();
        let table = screen(&panel, 100, 25);
        assert!(table.contains("discord.com") && table.contains("200") && table.contains("UDP/H3"));
        panel.key(key(KeyCode::Char('d')));
        assert!(panel.details);
        assert!(screen(&panel, 100, 25).contains("HTTP 200"));
        panel.key(key(KeyCode::PageDown));
        panel.key(key(KeyCode::PageUp));
        panel.key(key(KeyCode::Esc));
        assert!(*cancelled.borrow());
        tx.send(Event::Done(Err(ClientError::Io))).unwrap();
        panel.poll();
        assert!(panel.phase == Phase::Done && !panel.completed);
        assert_eq!(panel.failed_domains(), vec!["x.com"]);
        assert!(panel.actions().iter().any(|a| a.key == 'r'));
        let mut report = Vec::new();
        panel.write_export(&mut report).unwrap();
        let report = String::from_utf8(report).unwrap();
        assert!(report.contains("№1") && report.contains("№2") && report.contains("HTTP 200"));
        assert!(
            !report.contains("discord.com")
                && !report.contains("x.com")
                && !report.contains("profile")
        );
        panel.key(key(KeyCode::Char('n')));
        assert!(panel.phase == Phase::Choose);
        assert!(panel.key(key(KeyCode::Esc)));
    }

    #[test]
    fn profile_diagnostic_actions_follow_content_and_mouse_only_selects() {
        let mut panel = Panel::new(PathBuf::from("nonexistent"), [0; 32], "profile".into());
        for width in [60, 90, 120] {
            let area = Rect::new(0, 0, width, 36);
            let (report, table, actions) = panel.layout(area);
            let actions = actions.unwrap();
            assert!(table.is_none());
            assert_eq!(report.bottom(), actions.y);
            assert!(actions.y <= 6);
            let view = screen(&panel, width, 36);
            assert!(!view.contains("PgUp/PgDn"));
            assert!(view.contains("Ввести свои домены"));
            panel.select_at(area, actions.x + 2, actions.y + 2);
            assert_eq!(panel.action, 1);
            assert!(panel.phase == Phase::Choose && panel.receiver.is_none());
        }
        panel.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(panel.phase == Phase::Custom);
        assert!(panel.receiver.is_none());
        panel.phase = Phase::Confirm;
        panel.domains = (0..16).map(|i| format!("site{i}.test")).collect();
        panel.action = 0;
        let area = Rect::new(0, 0, 60, 18);
        let (report, _, actions) = panel.layout(area);
        let actions = actions.unwrap();
        assert_eq!(report.bottom(), actions.y);
        assert!(actions.bottom() <= area.bottom());
        assert_eq!(panel.actions()[0].key, 'c');
        panel.select_at(area, actions.x + 2, actions.y + 2);
        assert_eq!(panel.action, 1);
        assert!(panel.phase == Phase::Confirm && panel.receiver.is_none());
        panel.scroll = u16::MAX;
        assert!(screen(&panel, 60, 18).contains("site15.test"));
    }

    #[test]
    fn retry_and_export_respect_privacy_and_policy() {
        let mut panel = Panel::new(
            PathBuf::from("nonexistent"),
            [0; 32],
            "secret-profile".into(),
        );
        panel.domains = vec![
            "ok.test".into(),
            "failed.test".into(),
            "blocked.test".into(),
        ];
        panel.finished = vec![
            "ok.test".into(),
            "failed.test".into(),
            "blocked.test".into(),
        ];
        panel.checks.push(Check {
            domain: Some("failed.test".into()),
            kind: CheckKind::Https("H2"),
            outcome: Outcome::Failure(crate::client::ClientError::Timeout),
        });
        panel.checks.push(Check {
            domain: Some("blocked.test".into()),
            kind: CheckKind::Policy,
            outcome: Outcome::Route(crate::routing::Action::Blocked),
        });
        assert_eq!(panel.failed_domains(), vec!["failed.test"]);
        assert!(panel.policy_blocked("blocked.test"));
        assert!(!panel.policy_blocked("failed.test"));
        panel.phase = Phase::Done;
        let view = screen(&panel, 100, 25);
        assert!(view.contains("Блок"));
        assert!(view.contains("запрещено политикой"));
        assert!(!panel.checks[0].line(true).contains("failed.test"));
    }
}
