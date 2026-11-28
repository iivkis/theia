//! Independent, functional standalone diagnostic workspace. Uses the same
//! terminal, catalogue, exact plan consent and backend as the CLI.
use super::{io, event, Event, KeyCode, KeyEventKind, KeyModifiers, Terminal, CrosstermBackend,
    Frame, Layout, Constraint, Paragraph, Row, Table, Wrap, Style, Line, KeyEvent, RoutingPanel,
    TEXT, MUTED, ACCENT, SURFACE, FOCUS, WARNING, tui_widgets, TuiError, TerminalGuard, IsTerminal};
use crate::anti_dpi::{
    authority::Candidate,
    catalog::{Catalog, Overlay, MAX_JOB_DOMAINS},
    diagnostic::{strategy_columns, CellResult, CellStatus, Plan},
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

#[cfg(windows)]
use crate::anti_dpi::session::{Control, DiagnosticUpdate as Update, Phase};

#[cfg(not(windows))]
use crate::anti_dpi::diagnostic::Report;

#[cfg(not(windows))]
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

    #[cfg(windows)]
    fn start_owned(plan: Plan, control: &Control) -> Result<Self, String> {
        let total = plan.planned_cells();
        let cancel = Arc::new(AtomicBool::new(false));
        let (send, updates) = mpsc::channel();
        control.diagnose(plan, cancel.clone(), send).map_err(|e| e.to_string())?;
        Ok(Self { cancel, updates, thread: None, total })
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
    #[cfg(windows)]
    Connect(Candidate),
    #[cfg(windows)]
    Disconnect(bool),
}

#[cfg(windows)]
struct OwnedSession {
    control: Arc<Control>,
    thread: Option<thread::JoinHandle<Result<(), String>>>,
}

#[cfg(windows)]
impl OwnedSession {
    fn start(candidate: Candidate) -> Result<Self, String> {
        let digest = candidate.digest();
        let (control, commands) = Control::channel().map_err(|error| error.to_string())?;
        let owner = control.clone();
        let thread = thread::Builder::new().name("theia-f20-owner".into()).spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2)
                .thread_stack_size(8 * 1024 * 1024).enable_all().build()
                .map_err(|_| "Не удалось создать runtime".to_owned())?;
            runtime.block_on(crate::local_proxy::run_standalone_controlled(candidate, digest, owner, commands))
                .map_err(|error| error.to_string())
        }).map_err(|_| "Не удалось запустить локальный runtime".to_owned())?;
        Ok(Self { control, thread: Some(thread) })
    }
}

#[cfg(windows)]
impl Drop for OwnedSession {
    fn drop(&mut self) {
        self.control.disconnect();
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
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
    routing: Option<(RoutingPanel, Document, Vec<u8>)>,
    #[cfg(windows)]
    session: Option<OwnedSession>,
    #[cfg(windows)]
    apply_reply: Option<mpsc::Receiver<Result<(), String>>>,
    #[cfg(windows)]
    exit_after_stop: bool,
    leave_requested: bool,
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
            review: None, review_scroll: 0, worker: None, routing: None,
            #[cfg(windows)]
            session: None,
            #[cfg(windows)]
            apply_reply: None,
            #[cfg(windows)]
            exit_after_stop: false,
            leave_requested: false,
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
        if let Some((panel, _, _)) = &mut self.routing { panel.poll(); }
        #[cfg(windows)]
        {
            if let Some(reply) = &self.apply_reply {
                match reply.try_recv() {
                    Ok(result) => {
                        self.apply_reply = None;
                        self.notice = result.map_or_else(|e| e, |_| "Политика применена без перезапуска; прежние потоки отозваны.".into());
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.apply_reply = None;
                        self.notice = "Apply: ответ владельца не получен; проверьте состояние.".into();
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }
            if self.session.as_ref().and_then(|s| s.thread.as_ref()).is_some_and(|t| t.is_finished()) {
                if let Some(mut session) = self.session.take() {
                    let result = session.thread.take().unwrap().join().unwrap_or_else(|_| Err("Runtime завершился аварийно".into()));
                    self.leave_requested = self.exit_after_stop && result.is_ok();
                    self.exit_after_stop = false;
                    self.notice = result.map_or_else(|error| format!("Остановка: {error}; проверьте восстановление прокси."), |_| "Отключено; условное восстановление завершено.".into());
                }
            }
        }
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

    fn open_routing(&mut self) {
        let result = (|| {
            let bytes = crate::config::editor_bytes(&self.path).map_err(|e| e.to_string())?;
            let document = Document::parse(std::str::from_utf8(&bytes).map_err(|_| "Некорректный UTF-8".to_owned())?)
                .map_err(|e| e.to_string())?;
            let panel = RoutingPanel::for_standalone(&document, &self.path);
            Ok::<_, String>((panel, document, bytes))
        })();
        match result {
            Ok(panel) => self.routing = Some(panel),
            Err(error) => self.notice = error,
        }
    }

    fn routing_key(&mut self, key: KeyEvent) {
        let Some((mut panel, document, bytes)) = self.routing.take() else { return };
        if panel.key(key, None) {
            self.routing = Some((panel, document, bytes));
            return;
        }
        if !panel.save_requested { return; }
        panel.save_requested = false;
        let mut next = document.clone();
        let result = (|| {
            next.anti_dpi.revision = document.anti_dpi.revision.checked_add(1)
                .ok_or("Исчерпан номер ревизии".to_owned())?;
            next.anti_dpi.rules = panel.settings.rules.clone();
            next.anti_dpi.geodata = match (&panel.settings.geodata_directory, &panel.settings.datasets) {
                (Some(directory), Some(manifest)) => Some(crate::anti_dpi::GeoData { directory: directory.clone(), manifest: manifest.clone() }),
                (None, None) => None,
                _ => return Err("Неполная пара GeoData".into()),
            };
            next.prepare().map_err(|e| e.to_string())?;
            next.save(&self.path, Some(&bytes)).map_err(|e| format!("{e:?}"))
        })();
        match result {
            Ok(()) => {
                self.notice = "Сохранён новый черновик. Для публикации выберите Apply.".into();
                self.results.clear();
            }
            Err(error) => {
                panel.message = error;
                self.routing = Some((panel, document, bytes));
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
        if self.routing.is_some() {
            self.routing_key(KeyEvent::new(code, KeyModifiers::NONE));
            return Ok(false);
        }
        #[cfg(windows)]
        if self.apply_reply.is_some() { return Ok(false); }
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
                            #[cfg(windows)]
                            if let Some(session) = &self.session {
                                if enroll {
                                    self.notice = "Регистрация недоступна при активном владельце.".into();
                                } else {
                                    match session.control.apply(candidate) {
                                        Ok(reply) => { self.apply_reply = Some(reply); self.notice = "Apply выполняется владельцем…".into(); }
                                        Err(error) => self.notice = error.to_string(),
                                    }
                                }
                                return Ok(false);
                            }
                            let digest = candidate.digest();
                            let result = if enroll { candidate.enroll(digest) } else { candidate.apply(digest) };
                            self.notice = result.map_or_else(|e| e.to_string(),
                                |_| "Локальная политика применена; сеть и системный прокси не изменены.".into());
                        }
                        Review::Diagnostic(plan) => {
                            self.results.clear();
                            #[cfg(windows)]
                            if let Some(session) = &self.session {
                                match Worker::start_owned(plan, &session.control) {
                                    Ok(worker) => { self.worker = Some(worker); self.notice = "Диагностика в собственной сессии; Esc отменяет.".into(); }
                                    Err(error) => self.notice = error,
                                }
                                return Ok(false);
                            }
                            self.worker = Some(Worker::start(plan)?);
                            self.notice = "Диагностика выполняется. Esc отменяет задание.".into();
                        }
                        #[cfg(windows)]
                        Review::Connect(candidate) => match OwnedSession::start(candidate) {
                            Ok(session) => { self.session = Some(session); self.notice = "Подготовка listeners и WinINet…".into(); }
                            Err(error) => self.notice = error,
                        },
                        #[cfg(windows)]
                        Review::Disconnect(exit) => {
                            if let Some(session) = &self.session {
                                self.exit_after_stop = exit;
                                session.control.disconnect();
                                self.notice = "Отключение и условное восстановление настроек…".into();
                            }
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
            KeyCode::Esc | KeyCode::Char('q') => {
                #[cfg(windows)]
                if self.session.is_some() {
                    self.review = Some(Review::Disconnect(true));
                    self.review_scroll = 0;
                    return Ok(false);
                }
                return Ok(true);
            },
            KeyCode::Tab | KeyCode::BackTab => self.overview = !self.overview,
            KeyCode::Char('n') if self.overview => self.create_config(),
            KeyCode::Char('e') if self.overview => self.begin_review(Some(true)),
            KeyCode::Char('a') if self.overview => self.begin_review(Some(false)),
            KeyCode::Char('r') if self.overview => self.open_routing(),
            KeyCode::Char('p') if self.overview => {
                #[cfg(windows)]
                {
                    self.review_scroll = 0;
                    if self.session.is_some() { self.review = Some(Review::Disconnect(false)); }
                    else { match Candidate::read(&self.path) {
                        Ok(candidate) => self.review = Some(Review::Connect(candidate)),
                        Err(error) => self.notice = error.to_string(),
                    } }
                }
                #[cfg(not(windows))]
                { self.notice = "System Proxy MVP доступен только на Windows.".into(); }
            },
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
        if let Some((panel, _, _)) = &self.routing {
            panel.render(frame, area, true);
            return;
        }
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
                #[cfg(windows)]
                Review::Connect(candidate) => candidate.connect_preview(),
                #[cfg(windows)]
                Review::Disconnect(exit) => format!("Отключить принадлежащую панели сессию?\nБудет закрыт приём трафика и выполнено условное восстановление Windows proxy.\n{}", if *exit { "Затем выйти из панели." } else { "Панель останется открытой." }),
            };
            frame.render_widget(Paragraph::new(text).style(Style::default().fg(TEXT)).wrap(Wrap { trim: false })
                .scroll((self.review_scroll, 0)), parts[1]);
            frame.render_widget(Paragraph::new("Esc отменить (по умолчанию) · ↑ ↓ / PgUp PgDn просмотр · y подтвердить")
                .style(Style::default().fg(WARNING)).wrap(Wrap { trim: true }), parts[2]);
            return;
        }
        if self.overview {
            let mut text = match Document::read(&self.path) {
                Ok(doc) => format!("Сохранённая ревизия: {}\nПравил: {}\nDirect consent: {}\nDoH: {}\n\n{}\n\nРежим: системный прокси (MVP). Modify пока запрещён.",
                    doc.anti_dpi.revision, doc.anti_dpi.rules.len(), doc.anti_dpi.consent.direct_egress,
                    if doc.anti_dpi.resolver.is_some() { "настроен" } else { "не настроен" },
                    doc.anti_dpi.rules.iter().map(|rule| format!("{} · {:?}", rule.name, rule.action)).collect::<Vec<_>>().join("\n")),
                Err(_) => "Конфигурация отсутствует или недействительна. n — создать новый файл без перезаписи; существующий ошибочный файл исправьте отдельно.".into(),
            };
            #[cfg(windows)]
            if let Some(session) = &self.session {
                let status = session.control.status();
                let phase = match status.phase {
                    Phase::Starting => "подготовка", Phase::Connected => "подключено (readback)",
                    Phase::Stopping => "отключение", Phase::Stopped => "отключено", Phase::Failed => "ошибка",
                };
                text.push_str(&format!("\n\nПринадлежащая панели сессия: {phase}\nПрименённая ревизия: {} · Admission: {}\nЛокальные соединения: {} активных / {} принятых · ошибки: {}\nPayload: записано к цели {} байт · принято от цели {} байт\nДиагностика не входит в эти счётчики.",
                    status.revision, if status.admitting { "разрешён" } else { "закрыт" }, status.active, status.accepted, status.errors, status.uploaded, status.downloaded));
            } else {
                text.push_str("\n\nСобственная сессия отсутствует; состояние внешнего процесса не подтверждено.");
            }
            #[cfg(not(windows))]
            text.push_str("\n\nSystem Proxy MVP недоступен на этой платформе.");
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
            "Tab диагностика · r маршрутизация · p подключить/отключить · n создать · e регистрация · a Apply · Esc назад".into()
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
        if panel.leave_requested { return Ok(()); }
        terminal.draw(|frame| panel.draw(frame))?;
        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    let code = if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') { KeyCode::Esc } else { key.code };
                    if panel.routing.is_some() {
                        panel.routing_key(if code == KeyCode::Esc { KeyEvent::new(code, KeyModifiers::NONE) } else { key });
                    } else if panel.key(code)? { return Ok(()); }
                }
                Event::Paste(value) => {
                    if let Some((routing, _, _)) = &mut panel.routing { routing.paste(&value); }
                    else if let Some((_, text)) = &mut panel.editing {
                        if !value.chars().any(char::is_control) && text.len() + value.len() <= 253 { text.push_str(&value); }
                    }
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

    /// Exercise the actual third-panel renderer. Gallery publication is
    /// optional; the ordinary test does not require the review environment.
    #[test]
    fn standalone_visual_review_gallery() {
        use crate::anti_dpi::diagnostic::{Protocol, Reason, Stage};
        use std::io::Write;
        let root = std::env::temp_dir().join(format!("theia-f20-review-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        struct Scratch(PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
        }
        let root = Scratch(root);
        let path = root.0.join("anti-dpi.toml");
        let cells = std::env::var_os("THEIA_REVIEW_CELLS").map(PathBuf::from);
        let capture = |name: &str, panel: &mut Panel| {
            let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
            terminal.draw(|frame| panel.draw(frame)).unwrap();
            let buffer = terminal.backend().buffer();
            assert!(buffer.content().iter().any(|cell| cell.symbol() != " "));
            if let Some(dir) = &cells {
                let mut out = std::io::BufWriter::new(std::fs::File::create(dir.join(format!("{name}.cells"))).unwrap());
                writeln!(out, "120\t40").unwrap();
                for cell in buffer.content() {
                    write!(out, "{:?}\t{:?}\t{:?}\t", cell.fg, cell.bg, cell.modifier).unwrap();
                    for byte in cell.symbol().as_bytes() { write!(out, "{byte:02x}").unwrap(); }
                    writeln!(out).unwrap();
                }
                out.flush().unwrap();
            }
        };
        let mut panel = Panel::new(path.clone()).unwrap();
        capture("anti-dpi-first-run", &mut panel);
        std::fs::write(&path, format!("{}\n[anti_dpi.resolver]\nhostname='dns.example.com'\nbootstrap=['1.1.1.1']\n",
            include_str!("../../../../examples/anti-dpi.toml"))).unwrap();
        capture("anti-dpi-overview", &mut panel);
        panel.open_routing();
        assert!(panel.routing.is_some());
        capture("anti-dpi-routing", &mut panel);
        panel.routing_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        capture("anti-dpi-routing-editor", &mut panel);
        panel.routing_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        panel.routing_key(KeyEvent::new(KeyCode::Char('B'), KeyModifiers::NONE));
        capture("anti-dpi-geodata", &mut panel);
        panel.routing = None;
        panel.overview = false;
        panel.key(KeyCode::Char('s')).unwrap();
        capture("anti-dpi-catalog", &mut panel);
        panel.selected = ["meduza.io".to_owned()].into_iter().collect();
        panel.begin_review(None);
        assert!(panel.review.is_some());
        capture("anti-dpi-diagnostic-consent", &mut panel);
        panel.review = None;
        for (index, entry) in panel.catalog.entries().iter().take(6).enumerate() {
            let host = entry.hostname.clone();
            let available = index % 2 == 0;
            let direct = CellResult {
                domain: host.clone(), protocol: Protocol::TcpHttps, strategy_id: "direct",
                status: if available { CellStatus::Available } else { CellStatus::Unavailable },
                network: Stage::Passed, tls: if available { Stage::Passed } else { Stage::Failed },
                application: if available { Stage::Passed } else { Stage::NotRun },
                reason: if available { Reason::None } else { Reason::Timeout },
                actual_modification: Some(false), http_status: available.then_some(200),
                duration_ms: if available { 120 } else { 6000 }, attempts: 1,
                endpoint: None, source: None, policy_action: Some(crate::anti_dpi::Decision::Pass), stale: false,
            };
            panel.results.insert((host.clone(), "direct"), direct);
            for strategy_id in strategy_columns().into_iter().filter(|id| *id != "direct") {
                let protocol = match strategy_id {
                    "quic_v1_initial_split" => Protocol::QuicV1,
                    "quic_v2_initial_split" => Protocol::QuicV2,
                    "stun_fingerprint" => Protocol::Stun,
                    _ => Protocol::TcpHttps,
                };
                panel.results.insert((host.clone(), strategy_id), CellResult {
                    domain: host.clone(), protocol, strategy_id, status: CellStatus::Unsupported,
                    network: Stage::NotRun, tls: Stage::NotRun, application: Stage::NotRun,
                    reason: Reason::AwaitingAcceptance, actual_modification: None, http_status: None,
                    duration_ms: 0, attempts: 0, endpoint: None, source: None, policy_action: None, stale: false,
                });
            }
        }
        panel.notice = "СИНТЕТИЧЕСКИЙ ОФЛАЙН-ПРИМЕР · сеть не проверялась".into();
        capture("state-anti-dpi-diagnostic-report", &mut panel);
        assert!(panel.worker.is_none());
        assert!(!panel.results.is_empty());
    }

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
