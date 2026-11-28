//! Independent, functional standalone diagnostic workspace. Uses the same
//! terminal, catalogue, exact plan consent and backend as the CLI.
use super::{io, event, Event, KeyCode, KeyEventKind, KeyModifiers, Terminal, CrosstermBackend,
    Frame, Layout, Constraint, Paragraph, Row, Table, Wrap, Style, Line,
    TEXT, MUTED, ACCENT, SURFACE, FOCUS, WARNING, tui_widgets, TuiError, TerminalGuard, IsTerminal};
use crate::anti_dpi::{
    authority::Candidate,
    catalog::{Catalog, Overlay, MAX_JOB_DOMAINS},
    diagnostic::{strategy_columns, CellResult, CellStatus, Plan, Report},
    Document,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc},
    thread,
    time::Duration,
};

fn column_label(id: &str) -> &str {
    match id {
        "direct" => "Direct",
        "tcp_header" => "Header",
        "tcp_middle" => "Middle",
        "tcp_balanced" => "Balance",
        "quic_v1_initial_split" => "QUIC1",
        "quic_v2_initial_split" => "QUIC2",
        "stun_fingerprint" => "STUN",
        _ => id,
    }
}

fn status(cell: Option<&CellResult>) -> &'static str {
    match cell {
        None => "—",
        Some(cell) if cell.stale => "устар.",
        Some(cell) => match cell.status {
            CellStatus::Available => "доступ",
            CellStatus::Redirect => "3xx",
            CellStatus::HttpError => "HTTP",
            CellStatus::Unavailable => "нет",
            CellStatus::DnsError => "DNS",
            CellStatus::SecurityError => "TLS",
            CellStatus::PolicyDenied => "запрет",
            CellStatus::Unsupported => "н/п",
            CellStatus::NotApplicable => "н/пр",
            CellStatus::NotChecked => "—",
            CellStatus::Cancelled => "отмена",
        }
    }
}

enum Update {
    Cells(Vec<CellResult>),
    Done(Result<Report, String>),
}

struct Worker {
    cancel: Arc<AtomicBool>,
    updates: mpsc::Receiver<Update>,
    thread: Option<thread::JoinHandle<()>>,
    total: usize,
}

impl Worker {
    fn start(plan: Plan) -> Result<Self, TuiError> {
        let total = plan.planned_cells();
        let digest = plan.digest();
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let (send, updates) = mpsc::channel();
        let thread = thread::Builder::new().name("theia-f20-diagnostic".into()).spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread().enable_all().build()
                .map_err(|_| "Не удалось создать runtime".to_owned())
                .and_then(|runtime| runtime.block_on(plan.run_with_progress(digest, &flag, |cells| {
                    let _ = send.send(Update::Cells(cells.to_vec()));
                })).map_err(|error| error.to_string()));
            let _ = send.send(Update::Done(result));
        }).map_err(|_| TuiError::Io)?;
        Ok(Self { cancel, updates, thread: Some(thread), total })
    }

    fn cancel(&self) { self.cancel.store(true, Ordering::Release); }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.cancel();
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

enum Review {
    Diagnostic(Plan),
    Policy(Candidate, bool),
}

struct Panel {
    path: PathBuf,
    overlay_path: PathBuf,
    overlay: Overlay,
    overlay_bytes: Option<Vec<u8>>,
    catalog: Catalog,
    selected: BTreeSet<String>,
    results: BTreeMap<(String, &'static str), CellResult>,
    row: usize,
    offset: usize,
    filter: String,
    editing: Option<(bool, String)>,
    review: Option<Review>,
    review_scroll: u16,
    worker: Option<Worker>,
    notice: String,
    overview: bool,
}

impl Panel {
    fn new(path: PathBuf) -> Result<Self, TuiError> {
        let overlay_path = path.with_file_name("anti-dpi-domains.toml");
        let (overlay, overlay_bytes) = match std::fs::symlink_metadata(&overlay_path) {
            Ok(_) => {
                let bytes = crate::config::editor_bytes(&overlay_path)
                    .map_err(|_| TuiError::Configuration("unsafe diagnostic overlay"))?;
                let overlay = Overlay::parse(std::str::from_utf8(&bytes)
                    .map_err(|_| TuiError::Configuration("overlay is not UTF-8"))?)
                    .map_err(|_| TuiError::Configuration("invalid diagnostic overlay"))?;
                (overlay, Some(bytes))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (Overlay::default(), None),
            Err(_) => return Err(TuiError::Configuration("cannot inspect diagnostic overlay")),
        };
        let catalog = Catalog::build(&overlay).map_err(|_| TuiError::Configuration("invalid diagnostic catalogue"))?;
        Ok(Self { path, overlay_path, overlay, overlay_bytes, catalog, selected: BTreeSet::new(),
            results: BTreeMap::new(), row: 0, offset: 0, filter: String::new(), editing: None,
            review: None, review_scroll: 0, worker: None,
            notice: "Запросы выполняются только после подтверждения плана.".into(), overview: true })
    }

    fn visible(&self) -> Vec<&crate::anti_dpi::catalog::Entry> {
        self.catalog.entries().iter().filter(|e| e.hostname.contains(&self.filter)).collect()
    }

    fn set_overlay(&mut self, next: Overlay) {
        match next.save(&self.overlay_path, self.overlay_bytes.as_deref()) {
            Ok(()) => match Self::new(self.path.clone()) {
                Ok(new) => {
                    self.overlay = new.overlay;
                    self.overlay_bytes = new.overlay_bytes;
                    self.catalog = new.catalog;
                    self.selected.retain(|host| self.catalog.entries().iter()
                        .any(|entry| &entry.hostname == host && !entry.excluded));
                    self.results.clear();
                    self.row = 0;
                    self.offset = 0;
                    self.notice = "Список сохранён; правила маршрутизации не изменены.".into();
                }
                Err(_) => self.notice = "Сохранено, но перечитать список не удалось.".into(),
            },
            Err(error) => self.notice = format!("Не удалось сохранить список: {error:?}"),
        }
    }

    fn poll(&mut self) {
        let mut done = None;
        if let Some(worker) = &self.worker {
            loop {
                match worker.updates.try_recv() {
                    Ok(Update::Cells(cells)) => for cell in cells {
                        self.results.insert((cell.domain.clone(), cell.strategy_id), cell);
                    },
                    Ok(Update::Done(result)) => { done = Some(result); break; }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        done = Some(Err("Диагностический worker завершился без отчёта.".into()));
                        break;
                    }
                }
            }
        }
        if let Some(result) = done {
            self.worker.take();
            match result {
                Ok(report) => {
                    self.results.clear();
                    for cell in report.cells {
                        self.results.insert((cell.domain.clone(), cell.strategy_id), cell);
                    }
                    self.notice = "Задание завершено. Доступность не доказывает обход DPI.".into();
                }
                Err(error) => self.notice = error,
            }
        }
    }

    fn create_config(&mut self) {
        let result = Document::parse(include_str!("../../../../examples/anti-dpi.toml"))
            .map_err(|e| e.to_string()).and_then(|document| document.save(&self.path, None)
                .map_err(|e| format!("{e:?}")));
        self.notice = match result {
            Ok(()) => "Создана безопасная конфигурация без согласий. Задайте resolver и правила в TOML, затем явно Apply.".into(),
            Err(error) => format!("Не удалось создать: {error}"),
        };
    }

    fn begin_review(&mut self, enroll: Option<bool>) {
        self.review_scroll = 0;
        match enroll {
            Some(enroll) => match Candidate::read(&self.path) {
                Ok(candidate) => self.review = Some(Review::Policy(candidate, enroll)),
                Err(error) => self.notice = error.to_string(),
            },
            None => {
                let hosts = self.selected.iter().cloned().collect::<Vec<_>>();
                let overlay = self.overlay_bytes.as_ref().map(|_| self.overlay_path.as_path());
                match Plan::prepare(&self.path, overlay, &hosts) {
                    Ok(plan) => self.review = Some(Review::Diagnostic(plan)),
                    Err(error) => self.notice = error.to_string(),
                }
            }
        }
    }

    fn key(&mut self, code: KeyCode) -> Result<bool, TuiError> {
        if let Some((custom, mut text)) = self.editing.take() {
            match code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    if custom {
                        let mut next = self.overlay.clone();
                        next.custom.push(text);
                        self.set_overlay(next);
                    } else {
                        self.filter = text.to_ascii_lowercase();
                        self.row = 0;
                        self.offset = 0;
                    }
                }
                KeyCode::Backspace => { text.pop(); self.editing = Some((custom, text)); }
                KeyCode::Char(ch) if !ch.is_control() && text.len() < 253 => {
                    text.push(ch); self.editing = Some((custom, text));
                }
                _ => self.editing = Some((custom, text)),
            }
            return Ok(false);
        }
        if self.review.is_some() {
            match code {
                KeyCode::Esc => { self.review = None; }
                KeyCode::Up => self.review_scroll = self.review_scroll.saturating_sub(1),
                KeyCode::Down => self.review_scroll = self.review_scroll.saturating_add(1),
                KeyCode::PageUp => self.review_scroll = self.review_scroll.saturating_sub(10),
                KeyCode::PageDown => self.review_scroll = self.review_scroll.saturating_add(10),
                KeyCode::Char('y') => if let Some(review) = self.review.take() {
                    match review {
                        Review::Policy(candidate, enroll) => {
                            let digest = candidate.digest();
                            let result = if enroll { candidate.enroll(digest) } else { candidate.apply(digest) };
                            self.notice = result.map_or_else(|e| e.to_string(),
                                |_| "Локальная политика применена; сеть и системный прокси не изменены.".into());
                        }
                        Review::Diagnostic(plan) => {
                            self.results.clear();
                            self.worker = Some(Worker::start(plan)?);
                            self.notice = "Диагностика выполняется. Esc отменяет задание.".into();
                        }
                    }
                },
                _ => {}
            }
            return Ok(false);
        }
        if let Some(worker) = &self.worker {
            if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
                worker.cancel();
                self.notice = "Отмена; сохраняются завершённые проверки.".into();
            }
            return Ok(false);
        }
        match code {
            KeyCode::Esc | KeyCode::Char('q') => return Ok(true),
            KeyCode::Tab | KeyCode::BackTab => self.overview = !self.overview,
            KeyCode::Char('n') if self.overview => self.create_config(),
            KeyCode::Char('e') if self.overview => self.begin_review(Some(true)),
            KeyCode::Char('a') if self.overview => self.begin_review(Some(false)),
            KeyCode::Char('/') if !self.overview => self.editing = Some((false, self.filter.clone())),
            KeyCode::Char('i') if !self.overview => self.editing = Some((true, String::new())),
            KeyCode::Up if !self.overview => self.row = self.row.saturating_sub(1),
            KeyCode::Down if !self.overview => self.row = (self.row + 1).min(self.visible().len().saturating_sub(1)),
            KeyCode::Char(' ') if !self.overview => {
                let chosen = self.visible().get(self.row).filter(|e| !e.excluded).map(|e| e.hostname.clone());
                if let Some(host) = chosen {
                    if !self.selected.remove(&host) {
                        if self.selected.len() < MAX_JOB_DOMAINS { self.selected.insert(host); }
                        else { self.notice = "Лимит: 64 домена за задание.".into(); }
                    }
                }
            }
            KeyCode::Char('s') if !self.overview => {
                let hosts = self.visible().iter().filter(|e| !e.excluded).map(|e| e.hostname.clone()).collect::<Vec<_>>();
                for host in hosts {
                    if self.selected.len() >= MAX_JOB_DOMAINS { break; }
                    self.selected.insert(host);
                }
            }
            KeyCode::Char('c') if !self.overview => self.selected.clear(),
            KeyCode::Char('x') if !self.overview => {
                let chosen = self.visible().get(self.row).map(|e| (e.hostname.clone(), e.excluded));
                if let Some((host, excluded)) = chosen {
                    let mut next = self.overlay.clone();
                    if excluded { next.excluded.retain(|e| e != &host); }
                    else { next.excluded.push(host); }
                    self.set_overlay(next);
                }
            }
            KeyCode::Enter if !self.overview => self.begin_review(None),
            _ => {}
        }
        Ok(false)
    }

    fn draw(&mut self, frame: &mut Frame<'_>) {
        let area = frame.area();
        tui_widgets::canvas(frame, area);
        let parts = Layout::vertical([Constraint::Length(3), Constraint::Min(1), Constraint::Length(3)]).split(area);
        let head = if self.overview { "THEIA ANTI-DPI · Обзор / конфигурация" }
            else { "THEIA ANTI-DPI · Диагностика" };
        frame.render_widget(Paragraph::new(vec![Line::styled(head, Style::default().fg(ACCENT)),
            Line::styled(self.path.display().to_string(), Style::default().fg(MUTED))]), parts[0]);
        if let Some(review) = &self.review {
            let text = match review {
                Review::Diagnostic(plan) => plan.preview(),
                Review::Policy(candidate, enroll) => format!("{}\nОперация: {}", candidate.preview(),
                    if *enroll { "первичная регистрация" } else { "Apply" }),
            };
            frame.render_widget(Paragraph::new(text).style(Style::default().fg(TEXT)).wrap(Wrap { trim: false })
                .scroll((self.review_scroll, 0)), parts[1]);
            frame.render_widget(Paragraph::new("Esc отменить (по умолчанию) · ↑ ↓ / PgUp PgDn просмотр · y подтвердить")
                .style(Style::default().fg(WARNING)).wrap(Wrap { trim: true }), parts[2]);
            return;
        }
        if self.overview {
            let text = match Document::read(&self.path) {
                Ok(doc) => format!("Сохранённая ревизия: {}\nПравил: {}\nDirect consent: {}\nDoH: {}\n\n{}\n\nSystem Proxy: состояние внешнего процесса здесь не подтверждено.\nConnect (режим разработки Pass/Drop) доступен через CLI. Modify пока запрещён.",
                    doc.anti_dpi.revision, doc.anti_dpi.rules.len(), doc.anti_dpi.consent.direct_egress,
                    if doc.anti_dpi.resolver.is_some() { "настроен" } else { "не настроен" },
                    doc.anti_dpi.rules.iter().map(|rule| format!("{} · {:?}", rule.name, rule.action)).collect::<Vec<_>>().join("\n")),
                Err(_) => "Конфигурация отсутствует или недействительна. n — создать новый файл без перезаписи; существующий ошибочный файл исправьте отдельно.".into(),
            };
            frame.render_widget(Paragraph::new(text).style(Style::default().fg(TEXT)).wrap(Wrap { trim: true }), parts[1]);
        } else {
            let body = Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).split(parts[1]);
            let progress = self.worker.as_ref().map_or_else(String::new, |w| format!(" · Готово {}/{}", self.results.len(), w.total));
            frame.render_widget(Paragraph::new(format!("Каталог {} · выбрано {} · поиск: {}{}", self.catalog.builtin_count(),
                self.selected.len(), self.filter, progress)).style(Style::default().fg(MUTED)), body[0]);
            let height = usize::from(body[1].height.saturating_sub(1)).max(1);
            if self.row < self.offset { self.offset = self.row; }
            if self.row >= self.offset + height { self.offset = self.row + 1 - height; }
            let ids = strategy_columns();
            let rows = self.visible().iter().enumerate().skip(self.offset).take(height).map(|(index, entry)| {
                let name = format!("{}{}", if entry.excluded { "× " } else if self.selected.contains(&entry.hostname) { "✓ " } else { "  " }, entry.hostname);
                let mut values = vec![name];
                for &id in &ids { values.push(status(self.results.get(&(entry.hostname.clone(), id))).into()); }
                Row::new(values).style(Style::default().fg(TEXT).bg(if index == self.row { FOCUS } else { SURFACE }))
            }).collect::<Vec<_>>();
            let widths = std::iter::once(Constraint::Min(15)).chain(ids.iter().map(|_| Constraint::Length(7))).collect::<Vec<_>>();
            let headers = std::iter::once("Домен").chain(ids.iter().map(|id| column_label(id))).collect::<Vec<_>>();
            frame.render_widget(Table::new(rows, widths)
                .header(Row::new(headers).style(Style::default().fg(ACCENT))), body[1]);
        }
        let footer = if let Some((custom, text)) = &self.editing {
            format!("{}: {text} · Enter сохранить · Esc отменить", if *custom { "Свой домен" } else { "Поиск" })
        } else if self.worker.is_some() {
            "Esc отменить задание".into()
        } else if self.overview {
            "Tab диагностика · n создать · e регистрация · a Apply · Esc назад".into()
        } else {
            "↑↓ выбор · пробел отметить · s все · c очистить · / поиск · i добавить · x исключить/вернуть · Enter проверка · Tab обзор".into()
        };
        frame.render_widget(Paragraph::new(format!("{}\n{footer}", self.notice)).style(Style::default().fg(MUTED)).wrap(Wrap { trim: true }), parts[2]);
    }
}

pub(super) fn run_in(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, path: &Path) -> Result<(), TuiError> {
    let mut panel = Panel::new(path.to_path_buf())?;
    loop {
        panel.poll();
        terminal.draw(|frame| panel.draw(frame))?;
        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    let code = if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') { KeyCode::Esc } else { key.code };
                    if panel.key(code)? { return Ok(()); }
                }
                Event::Paste(value) => if let Some((_, text)) = &mut panel.editing {
                    if !value.chars().any(char::is_control) && text.len() + value.len() <= 253 { text.push_str(&value); }
                },
                _ => {}
            }
        }
    }
}

pub(super) fn run(path: &Path) -> Result<(), TuiError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() { return Err(TuiError::NotInteractive); }
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    run_in(&mut terminal, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn offline_panel_selects_catalog_without_network_or_configuration() {
        let path = std::env::temp_dir().join(format!("theia-f20-panel-{}", std::process::id())).join("anti-dpi.toml");
        let mut panel = Panel::new(path.clone()).unwrap();
        assert!(panel.overview);
        panel.key(KeyCode::Tab).unwrap();
        panel.key(KeyCode::Char('s')).unwrap();
        assert_eq!(panel.selected.len(), 60);
        assert!(panel.results.is_empty());
        assert!(panel.worker.is_none());
        assert!(!path.exists());
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal.draw(|frame| panel.draw(frame)).unwrap();
        panel.key(KeyCode::Char('c')).unwrap();
        assert!(panel.selected.is_empty());
    }
}
