//! Independent, functional standalone diagnostic workspace. Uses the same
//! terminal, catalogue, exact plan consent and backend as the CLI.
use super::{io, event, Event, KeyCode, KeyEventKind, KeyModifiers, Terminal, CrosstermBackend,
    Frame, Layout, Constraint, Paragraph, Row, Table, Wrap, Style, Line, KeyEvent, RoutingPanel,
    Rect, Modifier, ActionItem, Actions, Field, Form, TEXT, MUTED, ACCENT, SURFACE, FOCUS, WARNING, ERROR,
    tui_widgets, TuiError, TerminalGuard, IsTerminal, workspace_columns};
use crate::anti_dpi::{
    authority::Candidate,
    catalog::{Catalog, Overlay, MAX_JOB_DOMAINS, VERSION},
    diagnostic::{strategy_columns, strategy_unavailable, CellResult, CellStatus, Plan, Report, Reason, Stage},
    Document,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc},
    thread,
    time::{Duration, Instant},
};

fn column_label(id: &str) -> &str {
    match id {
        "direct" => "Прямой",
        "tcp_header" => "Header",
        "tcp_middle" => "Middle",
        "tcp_balanced" => "Balanced",
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


const SECTIONS: &[&str] = &["Обзор", "Подключение", "Маршрутизация", "Диагностика", "Статистика", "Настройки"];
const OVERVIEW: usize = 0;
const CONNECTION: usize = 1;
const ROUTING: usize = 2;
const DIAGNOSTICS: usize = 3;
const STATISTICS: usize = 4;
const SETTINGS: usize = 5;

fn yes(value: bool) -> &'static str { if value { "Разрешено" } else { "Запрещено" } }

fn stage(value: Stage) -> &'static str {
    match value { Stage::Passed => "Пройдено", Stage::Failed => "Ошибка", Stage::NotRun => "Не выполнялось" }
}
fn reason(value: Reason) -> &'static str {
    match value {
        Reason::None => "Нет ошибки",
        Reason::AwaitingAcceptance => "Стратегия не прошла независимую приёмку",
        Reason::MissingEndpointMetadata => "Нет подтверждённых данных о совместимом endpoint",
        Reason::Budget => "Исчерпан бюджет задания",
        Reason::Cancelled => "Отменено пользователем",
        Reason::ContextChanged => "Изменился контекст политики или сети",
        Reason::Dns(_) => "Ошибка защищённого DNS",
        Reason::Timeout => "Истёк срок ожидания",
        Reason::Network => "Сетевая ошибка",
        Reason::Tls => "Ошибка TLS или проверки безопасности",
        Reason::Protocol => "Некорректный ответ протокола",
        Reason::NoTransformation => "Фактическая модификация не подтверждена",
        Reason::ProtectiveDenial => "Защитный отказ политики",
    }
}
fn status_long(value: CellStatus) -> &'static str {
    match value {
        CellStatus::Available => "Доступно (проверенный endpoint)",
        CellStatus::Redirect => "Перенаправление (цель не проверялась)",
        CellStatus::HttpError => "Ограничено / HTTP-ошибка",
        CellStatus::Unavailable => "Недоступно",
        CellStatus::DnsError => "Ошибка DNS",
        CellStatus::SecurityError => "Ошибка TLS / безопасности",
        CellStatus::PolicyDenied => "Запрещено политикой",
        CellStatus::Unsupported => "Не поддерживается",
        CellStatus::NotApplicable => "Неприменимо",
        CellStatus::NotChecked => "Не проверено",
        CellStatus::Cancelled => "Отменено",
    }
}
fn cell_explanation(cell: &CellResult) -> &'static str {
    if cell.stale { return "Условия изменились. Этот результат больше не актуален; нужна новая проверка."; }
    match cell.status {
        CellStatus::Available => if cell.strategy_id == "direct" { "Цель ответила напрямую. Для этой проверки Anti-DPI не требовался." } else { "Цель ответила при проверке стратегии. Это не гарантия обхода DPI." },
        CellStatus::Redirect => "Цель перенаправила запрос. Новый адрес не проверялся.",
        CellStatus::HttpError => "Сервер ответил ошибкой или ограничением; содержимое не подтверждено.",
        CellStatus::Unavailable => "Ответ не получен или проверка завершилась ошибкой. Причина блокировки не доказана.",
        CellStatus::DnsError => "Не удалось получить адрес сайта через защищённый DNS. Проверьте DNS и сеть.",
        CellStatus::SecurityError => "Проверка безопасности не пройдена. Не отключайте проверку сертификатов.",
        CellStatus::PolicyDenied => "Действующие правила или ограничения безопасности запретили проверку.",
        CellStatus::Unsupported => "Этот способ пока недоступен. Проверка не доказывает недоступность сайта.",
        CellStatus::NotApplicable => "Этот способ не подходит для данной цели.",
        CellStatus::NotChecked => "Проверка не выполнена; вывод о доступности сделать нельзя.",
        CellStatus::Cancelled => "Проверка отменена; вывод о доступности сделать нельзя.",
    }
}

fn cell_color(cell: Option<&CellResult>) -> ratatui::style::Color {
    match cell {
        Some(c) if c.stale => MUTED,
        Some(c) => match c.status {
            CellStatus::Available => ACCENT,
            CellStatus::Redirect | CellStatus::HttpError => WARNING,
            CellStatus::Unavailable | CellStatus::DnsError | CellStatus::SecurityError | CellStatus::PolicyDenied => ERROR,
            _ => MUTED,
        },
        None => MUTED,
    }
}

/// All edits stay in this local draft until a separate reviewed Save.
/// Existing routing rules are never implicitly populated from the catalogue.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SetupStep { Mode, Domains, DomainInput, Dns, CustomDns, Direct, Modify, Settings, Advanced }

struct Draft {
    step: SetupStep,
    choice: usize,
    input_backup: Option<[String; 5]>,
    original: Document,
    expected: Option<Vec<u8>>,
    values: [String; 5],
    flags: [bool; 4],
    selected: usize,
    error: String,
}
impl Draft {
    fn new(original: Document, expected: Option<Vec<u8>>) -> Self {
        let local = &original.anti_dpi;
        let values = [
            local.resolver.as_ref().map_or_else(String::new, |r| r.hostname.clone()),
            local.resolver.as_ref().map_or_else(String::new, |r| r.bootstrap.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")),
            local.proxy.http_listen.clone(), local.proxy.socks5_listen.clone(), String::new(),
        ];
        let flags = [local.consent.direct_egress, local.consent.direct_dpi, local.consent.direct_dpi_stun, false];
        Self { step: if expected.is_none() { SetupStep::Mode } else { SetupStep::Settings }, choice: 0, input_backup: None, original, expected, values, flags, selected: 0, error: String::new() }
    }

    fn first_run(&self) -> bool { self.expected.is_none() }
    fn count(&self) -> usize { 7 }
    fn input_index(&self) -> Option<usize> {
        if self.step != SetupStep::Advanced {
            return match self.step {
                SetupStep::DomainInput => Some(4),
                SetupStep::CustomDns => Some(self.selected.min(1)),
                _ => None,
            };
        }
        match self.selected { 0..=3 => Some(self.selected), _ => None }
    }
    fn paste(&mut self, value: &str) {
        if let Some(i) = self.input_index() {
            if !value.chars().any(char::is_control) && self.values[i].len() + value.len() <= 16_384 {
                self.values[i].push_str(value);
            }
        }
    }
    fn move_to(&mut self, step: SetupStep) {
        self.step = step;
        self.choice = 0;
        self.selected = 0;
        self.error.clear();
    }

    fn wizard_choices(&self) -> (&'static str, String, Vec<ActionItem>) {
        let item = |key, label| ActionItem { key, label };
        let domains = self.values[4].split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()).count();
        let (title, text, items) = match self.step {
            SetupStep::Mode => ("Шаг 1 из 5 · Как настроить Anti-DPI?",
                "Anti-DPI помогает проверять доступность сайтов и применять принятые способы изменения трафика.\nРаботает без VPS и ключей. Сейчас стратегии изменения трафика ожидают приёмки.\n\nВыберите способ настройки. Никаких сетевых запросов или изменений Windows пока не будет.".into(),
                vec![item('1', "Рекомендуемая · выбрать нужные сайты"), item('2', "Ручная · настроить правила позднее")]),
            SetupStep::Domains => ("Шаг 2 из 5 · Какие сайты вам нужны?",
                format!("Укажите сайты, для которых хотите использовать Anti-DPI. Остальные не получат это правило.\n\nВыбрано: {domains}\n{}\n\nПока это только черновик. Для продолжения нужен хотя бы один сайт.", if self.values[4].is_empty() { "Пока ничего не выбрано" } else { &self.values[4] }),
                vec![item('1', "Выбрать сайты из каталога"), item('2', "Ввести свои сайты"), item('3', "Далее · подтвердить выбранные сайты")]),
            SetupStep::Settings => ("Настройки · Что изменить?",
                format!("DNS: {}\nПрямой выход: {} · Anti-DPI: {} · STUN: {}\n\nВыберите только то, что хотите изменить. Правила сайтов и адреса локальных прокси сохраняются без изменений.", if self.values[0].is_empty() { "не настроен" } else { &self.values[0] }, yes(self.flags[0]), yes(self.flags[1]), yes(self.flags[2])),
                vec![item('1', "Выбрать защищённый DNS"), item('2', "Изменить разрешения"), item('3', "Расширенные настройки · адреса прокси, STUN")]),
            SetupStep::Dns => (if self.first_run() { if self.flags[3] { "Шаг 3 из 5 · Выберите DNS" } else { "Шаг 2 из 4 · Выберите DNS" } } else { "Настройки · Защищённый DNS" },
                "Защищённый DNS получает адреса сайтов по шифрованному соединению.\nВыберите поставщика самостоятельно: он сможет видеть ваши DNS-запросы и публичный IP.\nCloudflare — обычное разрешение имён; Quad9 фильтрует известные вредоносные домены.\nНи один вариант не гарантирует доступность сайтов. Пока соединение не проверялось.\nБез DNS доменные операции недоступны; системный DNS не используется как запасной.".into(),
                vec![item('1', "Cloudflare · обычный DNS без фильтра вредоносных сайтов"), item('2', "Quad9 · с фильтром известных вредоносных сайтов"), item('3', "Другой DNS · ввести параметры"), item('4', "Без DNS · подключение пока недоступно")]),
            SetupStep::Direct => (if self.first_run() { if self.flags[3] { "Шаг 4 из 5 · Разрешить выход в интернет?" } else { "Шаг 3 из 4 · Разрешить выход в интернет?" } } else { "Разрешения 1 из 2 · Выход в интернет" },
                "Чтобы проверить сайты или подключаться к ним напрямую, требуется ваше разрешение.\nDNS-провайдер и сайты могут видеть ваш публичный IP. Anti-DPI не является VPN.\nЕсли не разрешить прямой выход, рабочий трафик не будет отправляться.\nЭто не запускает подключение. Разрешение можно изменить в настройках.".into(),
                vec![item('1', "Пока не разрешать"), item('2', "Разрешить прямое подключение")]),
            SetupStep::Modify => (if self.first_run() { if self.flags[3] { "Шаг 5 из 5 · Разрешить Anti-DPI?" } else { "Шаг 4 из 4 · Разрешить Anti-DPI?" } } else { "Разрешения 2 из 2 · Anti-DPI" },
                "Разрешить изменение трафика только для сайтов, указанных в правилах.\nПока стратегии не приняты, это разрешение не включает работающий обход.\nПри невозможности применить Anti-DPI соединение блокируется, а не отправляется напрямую.\nSTUN не включается этим шагом. Его отдельное разрешение доступно в расширенных настройках.".into(),
                vec![item('1', "Пока не разрешать · Anti-DPI не активен"), item('2', "Разрешить принятые стратегии Anti-DPI")]),
            SetupStep::DomainInput | SetupStep::CustomDns | SetupStep::Advanced => ("", String::new(), Vec::new()),
        };
        let mut text = text;
        if !self.first_run() {
            match self.step {
                SetupStep::Dns => text.push_str(&format!("\nТекущий DNS: {}", if self.values[0].is_empty() { "не настроен" } else { &self.values[0] })),
                SetupStep::Direct => text.push_str(&format!("\nСейчас: {}", yes(self.flags[0]))),
                SetupStep::Modify => text.push_str(&format!("\nСейчас: Anti-DPI — {}; STUN — {}. Запрет Anti-DPI отключит также STUN.", yes(self.flags[1]), yes(self.flags[2]))),
                _ => {}
            }
        }
        (title, text, items)
    }

    fn wizard_form(&self) -> Form {
        let fields = if self.step == SetupStep::DomainInput {
            vec![Field { id: 0, label: "Адреса сайтов через запятую", value: self.values[4].clone(), hint: "Например: example.org, example.net. Только имена, без https:// и путей." }]
        } else {
            vec![
                Field { id: 0, label: "Имя сервера DNS-over-HTTPS", value: self.values[0].clone(), hint: "Имя сервера из документации вашего поставщика, без https:// и пути." },
                Field { id: 1, label: "Доверенные IP-адреса сервера", value: self.values[1].clone(), hint: "Публичные адреса из документации поставщика. Разделите запятыми." },
            ]
        };
        Form { fields, selected: self.selected, lead: "Введите данные · Enter далее · Esc назад".into(), error: self.error.clone() }
    }

    fn render_wizard(&self, frame: &mut Frame<'_>, area: Rect) {
        if matches!(self.step, SetupStep::DomainInput | SetupStep::CustomDns) {
            self.wizard_form().render(frame, area, if self.step == SetupStep::DomainInput { "Шаг 2 из 5 · Свои сайты" } else if self.first_run() { if self.flags[3] { "Шаг 3 из 5 · Другой DNS" } else { "Шаг 2 из 4 · Другой DNS" } } else { "Настройки · Другой DNS" });
            return;
        }
        let (title, mut text, items) = self.wizard_choices();
        if !self.error.is_empty() { text.push_str("\n\n"); text.push_str(&self.error); }
        let width = usize::from(area.width.saturating_sub(4).max(1));
        let rows = text.lines().map(|line| line.chars().count().div_ceil(width).max(1)).sum::<usize>() + 2;
        let [content, controls] = tui_widgets::action_layout_rows(area, items.len(), rows).unwrap_or([area, Rect::new(area.x, area.bottom(), area.width, 0)]);
        super::panel(frame, content, title, &text, true);
        Actions { items: &items, selected: self.choice }.render_with_focus(frame, controls, true);
    }

    fn form(&self) -> Form {
        let fields = vec![
            Field { id: 0, label: "Имя защищённого DNS (DoH)", value: self.values[0].clone(), hint: "Введите выбранное вами имя HTTPS DNS. Без системного DNS и fallback." },
            Field { id: 1, label: "Доверенные IP-адреса DNS", value: self.values[1].clone(), hint: "Публичные IP выбранного DNS-провайдера через запятую. Не угадываются автоматически." },
            Field { id: 2, label: "Локальный HTTP-прокси", value: self.values[2].clone(), hint: "Только loopback. Изменение требует отключения активной сессии." },
            Field { id: 3, label: "Локальный SOCKS5-прокси", value: self.values[3].clone(), hint: "Только loopback. UDP ASSOCIATE не означает перехват всего UDP системы." },
            Field { id: 4, label: "Прямой выход в сеть (Пробел)", value: yes(self.flags[0]).into(), hint: "Ваш IP виден DNS-провайдеру и получателям. По умолчанию запрещено." },
            Field { id: 5, label: "Anti-DPI (Пробел)", value: yes(self.flags[1]).into(), hint: "Только принятые стратегии. При отказе нет перехода на прямой маршрут." },
            Field { id: 6, label: "STUN (отдельное разрешение)", value: yes(self.flags[2]).into(), hint: "Только совместимый credential-free Binding; приёмка обязательна." },
        ];
        Form { fields, selected: self.selected,
            lead: "Черновик · ↑↓ поля · Пробел разрешения/режим · F5 проверить · Esc отменить".into(),
            error: self.error.clone() }
    }

    fn domain_values(&self) -> Result<BTreeSet<String>, String> {
        let domains = self.values[4].split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty())
            .map(|s| crate::routing::domain_name(s).map_err(|_| "Некорректное имя сайта. Введите только домен, без https:// и пути.".to_owned()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if domains.is_empty() || domains.len() > MAX_JOB_DOMAINS {
            return Err("Выберите от 1 до 64 сайтов.".into());
        }
        let overlay = Overlay { custom: domains.iter().cloned().collect(), ..Overlay::default() };
        Catalog::build(&overlay).map_err(|e| e.to_string())?;
        Ok(domains)
    }

    fn next_document(&self) -> Result<Document, String> {
        let mut next = self.original.clone();
        let local = &mut next.anti_dpi;
        local.proxy.http_listen = self.values[2].trim().to_owned();
        local.proxy.socks5_listen = self.values[3].trim().to_owned();
        local.consent = crate::anti_dpi::Consent { direct_egress: self.flags[0], direct_dpi: self.flags[1], direct_dpi_stun: self.flags[2] };
        let hostname = self.values[0].trim();
        let bootstrap = self.values[1].split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty())
            .map(|s| s.parse::<std::net::IpAddr>().map_err(|_| "Некорректный bootstrap IP".to_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        local.resolver = if hostname.is_empty() && bootstrap.is_empty() { None } else {
            Some(crate::anti_dpi::Resolver { hostname: hostname.to_owned(), bootstrap })
        };
        if self.first_run() && self.flags[3] {
            let domains = self.domain_values()?;
            local.rules = vec![crate::routing::Rule { name: "Выбранные домены".into(),
                action: crate::routing::Action::DirectDpi,
                domains: domains.into_iter().map(|name| format!("full:{name}")).collect(), ips: Vec::new(), applications: Vec::new() }];
        }
        if self.expected.is_some() && next != self.original {
            next.anti_dpi.revision = self.original.anti_dpi.revision.checked_add(1).ok_or("Исчерпан номер ревизии")?;
        }
        next.prepare().map_err(|e| e.to_string())?;
        Ok(next)
    }
}

fn plain_summary(doc: &Document) -> String {
    let local = &doc.anti_dpi;
    let modify = local.rules.iter().filter(|r| r.action == crate::routing::Action::DirectDpi).count();
    format!("Что будет после сохранения?\n• Настройки записаны на диск только после подтверждения.\n• Для работы нужно отдельно применить правила и подключить прокси.\n• Правил Anti-DPI: {modify}. Выход в интернет: {}. Anti-DPI: {}.\n• DNS: {}. Публичный IP виден получателям при выходе в сеть.\n• Если Anti-DPI не сработает, соответствующее соединение будет заблокировано.\n\nТочные параметры и порядок правил:", yes(local.consent.direct_egress), yes(local.consent.direct_dpi), local.resolver.as_ref().map_or("не настроен", |r| r.hostname.as_str()))
}

fn policy_text(doc: &Document) -> String {
    use std::fmt::Write as _;
    let local = &doc.anti_dpi;
    let mut text = format!("Ревизия: {} · Правил: {}\nСистемный прокси · HTTP {} · SOCKS5 {}\n",
        local.revision, local.rules.len(), local.proxy.http_listen, local.proxy.socks5_listen);
    let _ = writeln!(text, "Защищённый DNS: {}", local.resolver.as_ref().map_or_else(|| "не настроен".into(),
        |r| format!("https://{}/dns-query · {}", r.hostname, r.bootstrap.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))));
    let _ = writeln!(text, "Прямой выход: {} · Anti-DPI: {} · STUN: {}", yes(local.consent.direct_egress), yes(local.consent.direct_dpi), yes(local.consent.direct_dpi_stun));
    let _ = writeln!(text, "\nПорядок правил (первое совпадение; условия ИЛИ):");
    for (i, rule) in local.rules.iter().enumerate() {
        let _ = writeln!(text, "{}. {} · {} · домены: {} · IP: {}", i + 1, rule.name,
            match rule.action { crate::routing::Action::Direct => "Напрямую", crate::routing::Action::DirectDpi => "Anti-DPI", crate::routing::Action::Blocked => "Блокировать", _ => "Недопустимый маршрут" },
            rule.domains.join(", "), rule.ips.join(", "));
    }
    let _ = writeln!(text, "По умолчанию: напрямую только если ни одно правило не совпало.\nНеопределённость или отказ Anti-DPI: блокировать, не переключать на прямой маршрут.");
    if local.rules.is_empty() || !local.consent.direct_dpi {
        let _ = writeln!(text, "ВНИМАНИЕ: Anti-DPI не активен.");
    } else if strategy_columns().into_iter().filter(|id| *id != "direct")
        .all(|id| strategy_unavailable(id) == Some(Reason::AwaitingAcceptance)) {
        let _ = writeln!(text, "ВНИМАНИЕ: ни одна стратегия Anti-DPI ещё не принята; соответствующие соединения будут блокироваться.");
    }
    if local.resolver.is_none() || !local.consent.direct_egress {
        let _ = writeln!(text, "ВНИМАНИЕ: подключение недоступно до настройки DNS и разрешения выхода в интернет.");
    }
    let _ = writeln!(text, "Прямое подключение раскрывает публичный IP. TUN/WinDivert недоступны.");
    text
}

struct ReportContext {
    config: Vec<u8>,
    overlay: Option<Vec<u8>>,
    epoch: Option<u64>,
    checked: Instant,
    stale: bool,
}
impl ReportContext {
    fn read(path: &Path, overlay: Option<Vec<u8>>) -> Option<Self> {
        Some(Self { config: crate::config::editor_bytes(path).ok()?, overlay,
            epoch: crate::network_scope::generation(), checked: Instant::now(), stale: false })
    }
    fn refresh(&mut self, path: &Path, overlay_path: &Path) {
        if self.stale || self.checked.elapsed() < Duration::from_secs(1) { return; }
        self.checked = Instant::now();
        let overlay_current = match &self.overlay {
            Some(bytes) => crate::config::editor_bytes(overlay_path).is_ok_and(|value| &value == bytes),
            None => std::fs::symlink_metadata(overlay_path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound),
        };
        self.stale = !overlay_current || crate::network_scope::generation() != self.epoch
            || !crate::config::editor_bytes(path).is_ok_and(|value| value == self.config);
    }
}

#[cfg(windows)]
use crate::anti_dpi::session::{Control, DiagnosticUpdate as Update, Phase};

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
    Save(Box<Draft>, Document),
    DiscardRouting,
    Export(String, PathBuf),
    #[cfg(windows)]
    Connect(Candidate, crate::windows_system_proxy::ApplyReview),
    #[cfg(windows)]
    Recover(crate::windows_system_proxy::RecoveryReview),
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
    fn start(candidate: Candidate, review: crate::windows_system_proxy::ApplyReview) -> Result<Self, String> {
        let digest = candidate.digest();
        let (control, commands) = Control::channel().map_err(|error| error.to_string())?;
        let owner = control.clone();
        let thread = thread::Builder::new().name("theia-f20-owner".into()).spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2)
                .thread_stack_size(8 * 1024 * 1024).enable_all().build()
                .map_err(|_| "Не удалось создать runtime".to_owned())?;
            runtime.block_on(crate::local_proxy::run_standalone_controlled(candidate, digest, owner, commands, review))
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
    report_only: bool,
    report_hosts: BTreeSet<String>,
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
    page: usize,
    navigation: bool,
    action: usize,
    draft: Option<Draft>,
    catalogue_draft: Option<Draft>,
    setup_catalogue_return: Option<(BTreeSet<String>, String, usize, usize)>,
    confirm_selected: bool,
    help: bool,
    details: bool,
    group: usize,
    column: usize,
    report_context: Option<ReportContext>,
    applied_revision: Option<u64>,
    newly_saved: bool,
    #[cfg(windows)]
    os_observation: Option<crate::windows_system_proxy::ObservedProxy>,
    #[cfg(windows)]
    os_checked: Option<Instant>,
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
        let draft = if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
            Some(Draft::new(Document::parse(include_str!("../../../../examples/anti-dpi.toml"))
                .map_err(|_| TuiError::Configuration("invalid embedded standalone example"))?, None))
        } else { None };
        Ok(Self { path, overlay_path, overlay, overlay_bytes, catalog, selected: BTreeSet::new(),
            results: BTreeMap::new(), report_only: false, report_hosts: BTreeSet::new(), row: 0, offset: 0, filter: String::new(), editing: None,
            review: None, review_scroll: 0, worker: None, routing: None,
            #[cfg(windows)]
            session: None,
            #[cfg(windows)]
            apply_reply: None,
            #[cfg(windows)]
            exit_after_stop: false,
            leave_requested: false,
            notice: "Сетевые запросы только после подтверждения.".into(), page: OVERVIEW, navigation: false, action: 0,
            draft, catalogue_draft: None, setup_catalogue_return: None, confirm_selected: false, help: false, details: false, group: 0, column: 0, report_context: None, applied_revision: None, newly_saved: false,
            #[cfg(windows)]
            os_observation: None,
            #[cfg(windows)]
            os_checked: None,
        })
    }

    fn visible(&self) -> Vec<&crate::anti_dpi::catalog::Entry> {
        self.catalog.entries().iter().filter(|e| e.hostname.contains(&self.filter)
            && (self.catalogue_draft.is_some() || !self.report_only || self.report_hosts.contains(&e.hostname))).collect()
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
                    self.mark_stale();
                    self.row = 0;
                    self.offset = 0;
                    self.notice = "Список сохранён; правила маршрутизации не изменены.".into();
                }
                Err(_) => self.notice = "Сохранено, но перечитать список не удалось.".into(),
            },
            Err(error) => self.notice = format!("Не удалось сохранить список: {error:?}"),
        }
    }

    fn mark_stale(&mut self) {
        if let Some(context) = &mut self.report_context { context.stale = true; }
        for cell in self.results.values_mut() { cell.stale = true; }
    }

    fn poll(&mut self) {
        if let Some(context) = &mut self.report_context { context.refresh(&self.path, &self.overlay_path); }
        if let Some((panel, _, _)) = &mut self.routing { panel.poll(); }
        #[cfg(windows)]
        {
            if self.os_checked.is_none_or(|last| last.elapsed() >= Duration::from_secs(1)) {
                self.os_checked = Some(Instant::now());
                self.os_observation = crate::windows_system_proxy::observed_proxy().ok();
            }
            if let Some(reply) = &self.apply_reply {
                match reply.try_recv() {
                    Ok(result) => {
                        self.apply_reply = None;
                        if result.is_ok() { self.mark_stale(); }
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
        if self.report_context.as_ref().is_some_and(|c| c.stale) {
            for cell in self.results.values_mut() { cell.stale = true; }
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
        if !panel.save_requested {
            if panel.settings != panel.original {
                self.routing = Some((panel, document, bytes));
                self.review = Some(Review::DiscardRouting);
                self.review_scroll = 0;
                self.confirm_selected = false;
            } else { self.navigation = true; }
            return;
        }
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
                self.notice = "Правила сохранены. Для публикации отдельно примените политику.".into();
                self.applied_revision = None;
                self.mark_stale();
                self.open_routing();
            }
            Err(error) => {
                panel.message = error;
                self.routing = Some((panel, document, bytes));
            }
        }
    }

    fn open_settings(&mut self) {
        let result = (|| {
            let bytes = crate::config::editor_bytes(&self.path).map_err(|e| e.to_string())?;
            let document = Document::parse(std::str::from_utf8(&bytes).map_err(|_| "Некорректный UTF-8".to_owned())?).map_err(|e| e.to_string())?;
            Ok::<_, String>(Draft::new(document, Some(bytes)))
        })();
        match result {
            Ok(draft) => self.draft = Some(draft),
            Err(error) => self.notice = format!("Файл не изменён: {error}. Откройте исправный файл или создайте новый по другому пути."),
        }
    }

    fn create_config(&mut self) {
        if !std::fs::symlink_metadata(&self.path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
            self.notice = "Файл уже существует; создание не перезаписывает его.".into();
            return;
        }
        match Document::parse(include_str!("../../../../examples/anti-dpi.toml")) {
            Ok(doc) => self.draft = Some(Draft::new(doc, None)),
            Err(error) => self.notice = error.to_string(),
        }
    }

    fn preview_draft(&mut self, mut draft: Draft) {
        match draft.next_document() {
            Ok(next) => {
                self.review = Some(Review::Save(Box::new(draft), next));
                self.review_scroll = 0;
                self.confirm_selected = false;
            }
            Err(error) => {
                draft.error = format!("Проверьте введённые данные: {error}");
                self.draft = Some(draft);
            }
        }
    }

    fn wizard_key(&mut self, mut draft: Draft, code: KeyCode) {
        use SetupStep::*;
        if code == KeyCode::Esc {
            let previous = match draft.step {
                Mode => { self.notice = "Настройка отменена; файл не создан.".into(); return; }
                Settings | Advanced => { self.notice = "Черновик отменён; файл не изменён.".into(); return; }
                Domains => Mode,
                DomainInput => Domains,
                Dns => if !draft.first_run() { Settings } else if draft.flags[3] { Domains } else { Mode },
                CustomDns => Dns,
                Direct => if draft.first_run() { Dns } else { Settings },
                Modify => Direct,
            };
            if let Some(values) = draft.input_backup.take() { draft.values = values; }
            if previous == Settings { draft = Draft::new(draft.original, draft.expected); }
            draft.move_to(previous);
            self.draft = Some(draft);
            return;
        }
        if matches!(draft.step, DomainInput | CustomDns) {
            match code {
                KeyCode::Up | KeyCode::BackTab => draft.selected = 0,
                KeyCode::Down | KeyCode::Tab if draft.step == CustomDns => draft.selected = 1,
                KeyCode::Enter if draft.step == DomainInput => {
                    match draft.domain_values() {
                        Ok(_) => { draft.input_backup = None; draft.move_to(Domains); },
                        Err(error) => draft.error = error,
                    }
                }
                KeyCode::Enter if draft.step == CustomDns && draft.selected == 0 => draft.selected = 1,
                KeyCode::Enter if draft.step == CustomDns => {
                    if draft.values[0].trim().is_empty() || draft.values[1].trim().is_empty() {
                        draft.error = "Нужны имя DNS-сервера и доверенные адреса.".into();
                    } else {
                        match draft.next_document() {
                            Ok(_) => {
                                draft.input_backup = None;
                                if !draft.first_run() { self.preview_draft(draft); return; }
                                draft.move_to(Direct);
                            },
                            Err(error) => draft.error = format!("Проверьте параметры DNS: {error}"),
                        }
                    }
                }
                KeyCode::Backspace => if let Some(i) = draft.input_index() { draft.values[i].pop(); draft.error.clear(); },
                KeyCode::Delete => if let Some(i) = draft.input_index() { draft.values[i].clear(); draft.error.clear(); },
                KeyCode::Char(ch) if !ch.is_control() => draft.paste(&ch.to_string()),
                _ => {}
            }
            self.draft = Some(draft);
            return;
        }
        let (_, _, items) = draft.wizard_choices();
        // Only Enter commits a highlighted option. Movement never grants
        // permission or changes a resolver.
        let code = if code == KeyCode::Enter {
            tui_widgets::action_key(&items, &mut draft.choice, code)
        } else {
            if matches!(code, KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab | KeyCode::Home | KeyCode::End) {
                let _ = tui_widgets::action_key(&items, &mut draft.choice, code);
            }
            None
        };
        match (draft.step, code) {
            (Settings, Some(KeyCode::Char('1'))) => draft.move_to(Dns),
            (Settings, Some(KeyCode::Char('2'))) => draft.move_to(Direct),
            (Settings, Some(KeyCode::Char('3'))) => draft.move_to(Advanced),
            (Mode, Some(KeyCode::Char('1'))) => { draft.flags[3] = true; draft.move_to(Domains); }
            (Mode, Some(KeyCode::Char('2'))) => { draft.flags[3] = false; draft.move_to(Dns); }
            (Domains, Some(KeyCode::Char('1'))) => {
                self.setup_catalogue_return = Some((std::mem::take(&mut self.selected), std::mem::take(&mut self.filter), self.row, self.offset));
                self.selected = draft.values[4].split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty())
                    .filter(|s| self.catalog.entries().iter().any(|e| e.hostname == *s && !e.excluded)).map(str::to_owned).collect();
                self.filter.clear(); self.row = 0; self.offset = 0;
                self.catalogue_draft = Some(draft);
                self.open_page(DIAGNOSTICS);
                self.notice = "Отметьте нужные сайты. Enter — принять выбор; Esc — назад. Проверки не запускаются.".into();
                return;
            }
            (Domains, Some(KeyCode::Char('2'))) => { draft.input_backup = Some(draft.values.clone()); draft.move_to(DomainInput); },
            (Domains, Some(KeyCode::Char('3'))) => {
                match draft.domain_values() {
                    Ok(_) => draft.move_to(Dns),
                    Err(error) => draft.error = error,
                }
            }
            (Dns, Some(KeyCode::Char('1' | '2'))) => {
                // Bundled public DoH endpoints, from the providers' official
                // documentation: developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/
                // and docs.quad9.net/services/. No implicit resolver or fallback.
                let cloudflare = code == Some(KeyCode::Char('1'));
                let (host, ips) = if cloudflare { ("cloudflare-dns.com", "1.1.1.1, 1.0.0.1") }
                    else { ("dns.quad9.net", "9.9.9.9, 149.112.112.112") };
                draft.values[0] = host.into();
                draft.values[1] = ips.into();
                if !draft.first_run() { self.preview_draft(draft); return; }
                draft.move_to(Direct);
            }
            (Dns, Some(KeyCode::Char('3'))) => {
                draft.input_backup = Some(draft.values.clone());
                draft.move_to(CustomDns);
            }
            (Dns, Some(KeyCode::Char('4'))) => {
                draft.values[0].clear(); draft.values[1].clear();
                if !draft.first_run() { self.preview_draft(draft); return; }
                draft.move_to(Direct);
            }
            (Direct, Some(KeyCode::Char('1'))) => {
                draft.flags[0] = false; draft.flags[1] = false; draft.flags[2] = false;
                self.preview_draft(draft);
                return;
            }
            (Direct, Some(KeyCode::Char('2'))) => {
                draft.flags[0] = true;
                draft.move_to(Modify);
            }
            (Modify, Some(KeyCode::Char('1' | '2'))) => {
                draft.flags[1] = code == Some(KeyCode::Char('2'));
                if draft.first_run() || !draft.flags[1] { draft.flags[2] = false; }
                self.preview_draft(draft);
                return;
            }
            _ => {}
        }
        self.draft = Some(draft);
    }

    fn draft_key(&mut self, code: KeyCode) {
        let Some(mut draft) = self.draft.take() else { return };
        if draft.step != SetupStep::Advanced { self.wizard_key(draft, code); return; }
        match code {
            KeyCode::Esc => { self.draft = Some(Draft::new(draft.original, draft.expected)); return; }
            KeyCode::Up | KeyCode::BackTab => draft.selected = draft.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Tab => draft.selected = (draft.selected + 1).min(draft.count() - 1),
            KeyCode::F(5) => match draft.next_document() {
                Ok(next) => {
                    self.review = Some(Review::Save(Box::new(draft), next));
                    self.review_scroll = 0;
                    self.confirm_selected = false;
                    return;
                }
                Err(error) => draft.error = error,
            },
            KeyCode::Char(' ') | KeyCode::Enter if (4..=6).contains(&draft.selected) => {
                let index = draft.selected - 4;
                draft.flags[index] = !draft.flags[index];
                draft.error.clear();
            }
            KeyCode::Backspace => if let Some(i) = draft.input_index() { draft.values[i].pop(); draft.error.clear(); },
            KeyCode::Delete => if let Some(i) = draft.input_index() { draft.values[i].clear(); draft.error.clear(); },
            KeyCode::Char(ch) if !ch.is_control() => draft.paste(&ch.to_string()),
            _ => {}
        }
        self.draft = Some(draft);
    }

    fn open_page(&mut self, page: usize) {
        self.page = page.min(SECTIONS.len() - 1);
        self.navigation = false;
        self.action = 0;
        if self.page == ROUTING && self.routing.is_none() { self.open_routing(); }
    }

    fn actions(&self) -> Vec<ActionItem> {
        let item = |key, label| ActionItem { key, label };
        match self.page {
            OVERVIEW => {
                if let Ok(doc) = Document::read(&self.path) {
                    let local = &doc.anti_dpi;
                    if local.resolver.is_none() || !local.consent.direct_egress {
                        vec![item('t', "Завершить настройку DNS и разрешений"), item('d', "Открыть каталог сайтов"), item('p', "Состояние подключения")]
                    } else if self.newly_saved {
                        vec![item('e', "Применить новую конфигурацию"), item('t', "Изменить настройки"), item('d', "Открыть диагностику")]
                    } else if self.applied_revision != Some(local.revision) {
                        vec![item('a', "Применить сохранённые правила"), item('e', "Первое применение (только новый файл)"), item('t', "Изменить настройки"), item('d', "Открыть диагностику")]
                    } else if cfg!(windows) {
                        vec![item('p', "Открыть подключение"), item('d', "Открыть диагностику"), item('t', "Изменить настройки")]
                    } else { vec![item('d', "Открыть диагностику"), item('t', "Изменить настройки"), item('p', "Состояние подключения")] }
                }
                else if std::fs::symlink_metadata(&self.path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
                    vec![item('n', "Настроить Anti-DPI"), item('d', "Открыть каталог")]
                } else { vec![item('t', "Проверить конфигурацию"), item('d', "Открыть каталог")] }
            }
            CONNECTION => {
                let mut actions = vec![item('t', "Настройки подключения"), item('a', "Применить сохранённые правила"), item('e', "Первое применение (новая конфигурация)")];
                if cfg!(windows) {
                    if self.owner_active() { actions.insert(0, item('p', "Отключить")); }
                    else if Document::read(&self.path).is_ok_and(|doc| doc.anti_dpi.resolver.is_some() && doc.anti_dpi.consent.direct_egress) {
                        actions.insert(0, item('p', "Подключить"));
                    }
                }
                if cfg!(windows) { actions.push(item('v', "Проверить и восстановить системный прокси")); }
                actions
            },
            ROUTING => vec![item('r', "Открыть редактор маршрутизации"), item('a', "Применить сохранённую политику")],
            STATISTICS => vec![item('p', "Открыть подключение"), item('d', "Открыть диагностику")],
            SETTINGS => vec![item('t', "Настроить DNS и разрешения"), item('a', "Применить сохранённую политику"), item('e', "Первично зарегистрировать локальную политику")],
            _ => Vec::new(),
        }
    }

    fn owner_active(&self) -> bool {
        #[cfg(windows)]
        { self.session.is_some() }
        #[cfg(not(windows))]
        { false }
    }

    fn begin_export(&mut self) {
        if self.results.is_empty() || self.worker.is_some() {
            self.notice = "Сначала завершите диагностическое задание.".into();
            return;
        }
        let report = Report { catalog_version: VERSION, catalog_digest: Catalog::builtin_digest(),
            plan_digest: [0; 32], cells: self.results.values().cloned().collect() };
        self.review = Some(Review::Export(report.anonymous_summary(), self.path.with_file_name("anti-dpi-diagnostic-report.txt")));
        self.review_scroll = 0;
        self.confirm_selected = false;
    }

    fn begin_review(&mut self, enroll: Option<bool>) {
        self.review_scroll = 0;
        self.confirm_selected = false;
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
        #[cfg(windows)]
        if self.apply_reply.is_some() { return Ok(false); }
        if self.help {
            if matches!(code, KeyCode::Esc | KeyCode::F(1)) { self.help = false; }
            return Ok(false);
        }
        if self.draft.is_some() {
            self.draft_key(code);
            return Ok(false);
        }
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
                KeyCode::Esc => { if let Some(Review::Save(draft, _)) = self.review.take() { self.draft = Some(*draft); } }
                KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab => self.confirm_selected = !self.confirm_selected,
                KeyCode::Enter if !self.confirm_selected => { if let Some(Review::Save(draft, _)) = self.review.take() { self.draft = Some(*draft); } }
                KeyCode::Up => self.review_scroll = self.review_scroll.saturating_sub(1),
                KeyCode::Down => self.review_scroll = self.review_scroll.saturating_add(1),
                KeyCode::PageUp => self.review_scroll = self.review_scroll.saturating_sub(10),
                KeyCode::PageDown => self.review_scroll = self.review_scroll.saturating_add(10),
                KeyCode::Enter | KeyCode::Char('y') if self.confirm_selected || code == KeyCode::Char('y') => if let Some(review) = self.review.take() {
                    match review {
                        Review::Save(draft, next) => {
                            match next.save(&self.path, draft.expected.as_deref()) {
                                Ok(()) => {
                                    self.notice = "Файл сохранён. Политика ещё не применена; подключения не запускались.".into();
                                    self.applied_revision = None;
                                    self.newly_saved = draft.first_run() || self.newly_saved;
                                    self.mark_stale();
                                    self.open_page(OVERVIEW);
                                }
                                Err(error) => {
                                    let mut draft = *draft;
                                    draft.error = format!("Сохранение не подтверждено: {error:?}");
                                    self.draft = Some(draft);
                                }
                            }
                        }
                        Review::DiscardRouting => {
                            self.routing = None;
                            self.navigation = true;
                            self.notice = "Черновик маршрутизации отменён.".into();
                        }
                        Review::Export(summary, path) => {
                            use std::io::Write as _;
                            let result = std::fs::OpenOptions::new().create_new(true).write(true).open(&path)
                                .and_then(|mut file| { file.write_all(summary.as_bytes())?; file.sync_all() });
                            self.notice = match result {
                                Ok(()) => format!("Обезличенный отчёт сохранён: {}", path.display()),
                                Err(error) => format!("Экспорт не подтверждён: {error}. Существующий файл не перезаписывается."),
                            };
                        }
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
                            let revision = candidate.document().anti_dpi.revision;
                            let digest = candidate.digest();
                            let result = if enroll { candidate.enroll(digest) } else { candidate.apply(digest) };
                            if result.is_ok() { self.applied_revision = Some(revision); self.newly_saved = false; self.mark_stale(); }
                            self.notice = result.map_or_else(|e| e.to_string(),
                                |_| "Локальная политика применена; сеть и системный прокси не изменены.".into());
                        }
                        Review::Diagnostic(plan) => {
                            self.results.clear();
                            self.report_hosts = self.selected.clone();
                            self.report_only = true;
                            self.filter.clear(); self.row = 0; self.offset = 0;
                            self.report_context = ReportContext::read(&self.path, self.overlay_bytes.clone());
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
                        Review::Connect(candidate, review) => match OwnedSession::start(candidate, review) {
                            Ok(session) => { self.session = Some(session); self.notice = "Подготовка listeners и WinINet…".into(); }
                            Err(error) => self.notice = error,
                        },
                        #[cfg(windows)]
                        Review::Recover(review) => {
                            self.notice = match crate::windows_system_proxy::recover_reviewed(review) {
                                Ok(_) => "Условное восстановление завершено; чужие изменения не перезаписывались.".into(),
                                Err(error) => format!("Восстановление не выполнено: {error:?}. Не изменяйте чужие настройки."),
                            };
                            self.os_checked = None;
                        }
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
        if self.routing.is_some() {
            self.routing_key(KeyEvent::new(code, KeyModifiers::NONE));
            return Ok(false);
        }
        if self.catalogue_draft.is_some() {
            if matches!(code, KeyCode::F(3) | KeyCode::Esc | KeyCode::Enter) {
                let mut draft = self.catalogue_draft.take().unwrap();
                if code != KeyCode::Esc {
                    // Keep explicit custom names outside the selectable catalogue.
                    let mut hosts: BTreeSet<String> = draft.values[4].split(|c: char| c == ',' || c.is_whitespace())
                        .filter(|s| !s.is_empty() && !self.catalog.entries().iter().any(|e| e.hostname == *s && !e.excluded))
                        .map(str::to_owned).collect();
                    hosts.extend(self.selected.iter().cloned());
                    if hosts.len() > MAX_JOB_DOMAINS {
                        self.notice = "Лимит: 64 сайта вместе с введёнными вручную. Снимите часть отметок.".into();
                        self.catalogue_draft = Some(draft);
                        return Ok(false);
                    }
                    draft.values[4] = hosts.into_iter().collect::<Vec<_>>().join(", ");
                    draft.error.clear();
                }
                draft.move_to(SetupStep::Domains);
                if let Some((selected, filter, row, offset)) = self.setup_catalogue_return.take() {
                    self.selected = selected; self.filter = filter; self.row = row; self.offset = offset;
                }
                self.notice = "Сайты выбираются только для черновика; сеть не запускается.".into();
                self.page = OVERVIEW;
                self.draft = Some(draft);
                return Ok(false);
            }
            if !matches!(code, KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown |
                KeyCode::Char(' ') | KeyCode::Char('s') | KeyCode::Char('c') | KeyCode::Char('/')) {
                return Ok(false);
            }
        }
        if code == KeyCode::F(1) { self.help = true; return Ok(false); }
        if self.details {
            if matches!(code, KeyCode::Esc | KeyCode::F(7)) { self.details = false; }
            return Ok(false);
        }
        if let Some(worker) = &self.worker {
            if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
                worker.cancel();
                self.notice = "Отмена; сохраняются завершённые проверки.".into();
                return Ok(false);
            }
            if !matches!(code, KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right | KeyCode::PageUp | KeyCode::PageDown | KeyCode::Char('[') | KeyCode::Char(']') | KeyCode::F(7)) {
                return Ok(false);
            }
        }
        if self.navigation {
            match code {
                KeyCode::Up | KeyCode::BackTab => self.page = self.page.saturating_sub(1),
                KeyCode::Down | KeyCode::Tab => self.page = (self.page + 1).min(SECTIONS.len() - 1),
                KeyCode::Enter | KeyCode::Right => self.open_page(self.page),
                KeyCode::Esc | KeyCode::F(2) => self.navigation = false,
                _ => {}
            }
            return Ok(false);
        }
        if code == KeyCode::F(2) || (code == KeyCode::Left && self.page != DIAGNOSTICS) {
            self.navigation = true;
            return Ok(false);
        }
        let code = if self.page != DIAGNOSTICS {
            let actions = self.actions();
            match tui_widgets::action_key(&actions, &mut self.action, code) { Some(code) => code, None => return Ok(false) }
        } else { code };
        match code {
            KeyCode::Esc | KeyCode::Char('q') => {
                #[cfg(windows)]
                if self.session.is_some() {
                    self.review = Some(Review::Disconnect(true));
                    self.review_scroll = 0;
                    self.confirm_selected = false;
                    return Ok(false);
                }
                return Ok(true);
            },
            KeyCode::Tab | KeyCode::BackTab if self.page == DIAGNOSTICS => self.navigation = true,
            KeyCode::Char('n') if self.page != DIAGNOSTICS => self.create_config(),
            KeyCode::Char('t') if self.page != DIAGNOSTICS => { self.page = SETTINGS; self.open_settings(); }
            KeyCode::Char('d') if self.page != DIAGNOSTICS => self.open_page(DIAGNOSTICS),
            KeyCode::Char('e') if self.page != DIAGNOSTICS => self.begin_review(Some(true)),
            KeyCode::Char('a') if self.page != DIAGNOSTICS => self.begin_review(Some(false)),
            KeyCode::Char('r') if self.page != DIAGNOSTICS => self.open_page(ROUTING),
            KeyCode::Char('p') if self.page != DIAGNOSTICS => {
                if self.page != CONNECTION { self.open_page(CONNECTION); return Ok(false); }
                self.confirm_selected = false;
                #[cfg(windows)]
                {
                    self.review_scroll = 0;
                    if self.session.is_some() { self.review = Some(Review::Disconnect(false)); }
                    else { match Candidate::read(&self.path) {
                        Ok(candidate) => {
                            let bind = candidate.document().anti_dpi.proxy.http_listen.parse::<std::net::SocketAddr>();
                            match bind.ok().and_then(|bind| crate::windows_system_proxy::review_apply(bind).ok()) {
                                Some(review) => self.review = Some(Review::Connect(candidate, review)),
                                None => self.notice = "Не удалось получить безопасный снимок WinINet: возможен другой владелец, журнал восстановления или неподходящий listener. Не перезаписываем настройки.".into(),
                            }
                        }
                        Err(error) => self.notice = error.to_string(),
                    } }
                }
                #[cfg(not(windows))]
                { self.notice = "System Proxy MVP доступен только на Windows.".into(); }
            },
            KeyCode::Char('v') if self.page == CONNECTION => {
                #[cfg(windows)]
                if self.session.is_none() {
                    match crate::windows_system_proxy::review_recovery() {
                        Ok(review) => { self.review = Some(Review::Recover(review)); self.review_scroll = 0; self.confirm_selected = false; }
                        Err(error) => self.notice = format!("Восстановление недоступно: {error:?}. Чужой процесс не останавливаем."),
                    }
                } else { self.notice = "Сначала штатно отключите собственную сессию.".into(); }
            },
            KeyCode::Char('v') if self.page == DIAGNOSTICS => {
                if self.report_hosts.is_empty() { self.notice = "Сначала выберите сайты и запустите проверку.".into(); }
                else { self.report_only = !self.report_only; self.filter.clear(); self.row = 0; self.offset = 0; }
            }
            KeyCode::Char('/') if self.page == DIAGNOSTICS => self.editing = Some((false, self.filter.clone())),
            KeyCode::Char('i') if self.page == DIAGNOSTICS => self.editing = Some((true, String::new())),
            KeyCode::Up if self.page == DIAGNOSTICS => self.row = self.row.saturating_sub(1),
            KeyCode::Down if self.page == DIAGNOSTICS => self.row = (self.row + 1).min(self.visible().len().saturating_sub(1)),
            KeyCode::PageUp if self.page == DIAGNOSTICS => self.row = self.row.saturating_sub(12),
            KeyCode::PageDown if self.page == DIAGNOSTICS => self.row = (self.row + 12).min(self.visible().len().saturating_sub(1)),
            KeyCode::Left if self.page == DIAGNOSTICS => self.column = self.column.saturating_sub(1),
            KeyCode::Right if self.page == DIAGNOSTICS => self.column = (self.column + 1).min(if self.group == 0 { 3 } else { 1 }),
            KeyCode::Char('[') if self.page == DIAGNOSTICS => { self.group = self.group.saturating_sub(1); self.column = 0; }
            KeyCode::Char(']') if self.page == DIAGNOSTICS => { self.group = (self.group + 1).min(3); self.column = 0; }
            KeyCode::F(7) if self.page == DIAGNOSTICS => self.details = true,
            KeyCode::Char('z') if self.page == DIAGNOSTICS => self.begin_export(),
            KeyCode::Char('b') if self.page == DIAGNOSTICS => {
                let failed = self.results.values().filter(|c| !c.stale && matches!(c.status, CellStatus::Unavailable | CellStatus::HttpError | CellStatus::DnsError))
                    .map(|c| c.domain.clone()).collect::<BTreeSet<_>>();
                self.selected = failed.into_iter().filter(|h| self.catalog.entries().iter().any(|e| &e.hostname == h && !e.excluded)).take(MAX_JOB_DOMAINS).collect();
                if self.selected.is_empty() { self.notice = "Нет разрешённых неуспешных проверок для повтора.".into(); }
                else { self.begin_review(None); }
            }
            KeyCode::Char('R') if self.page == DIAGNOSTICS => {
                self.set_overlay(Overlay { excluded: Vec::new(), ..self.overlay.clone() });
            }
            KeyCode::Char(' ') if self.page == DIAGNOSTICS => {
                let chosen = self.visible().get(self.row).filter(|e| !e.excluded).map(|e| e.hostname.clone());
                if let Some(host) = chosen {
                    if !self.selected.remove(&host) {
                        if self.selected.len() < MAX_JOB_DOMAINS { self.selected.insert(host); }
                        else { self.notice = "Лимит: 64 домена за задание.".into(); }
                    }
                }
            }
            KeyCode::Char('s') if self.page == DIAGNOSTICS => {
                let hosts = self.visible().iter().filter(|e| !e.excluded).map(|e| e.hostname.clone()).collect::<Vec<_>>();
                for host in hosts {
                    if self.selected.len() >= MAX_JOB_DOMAINS { break; }
                    self.selected.insert(host);
                }
            }
            KeyCode::Char('c') if self.page == DIAGNOSTICS => self.selected.clear(),
            KeyCode::Char('x') if self.page == DIAGNOSTICS => {
                let chosen = self.visible().get(self.row).map(|e| (e.hostname.clone(), e.excluded));
                if let Some((host, excluded)) = chosen {
                    let mut next = self.overlay.clone();
                    if excluded { next.excluded.retain(|e| e != &host); }
                    else { next.excluded.push(host); }
                    self.set_overlay(next);
                }
            }
            KeyCode::Enter if self.page == DIAGNOSTICS => self.begin_review(None),
            _ => {}
        }
        Ok(false)
    }

    fn owner_text(&self) -> &'static str {
        #[cfg(windows)]
        {
            if let Some(session) = &self.session {
                return match session.control.status().phase {
                    Phase::Starting => "Подготовка подключения",
                    Phase::Connected => "Собственная сессия · readback подтверждён",
                    Phase::Stopping => "Отключение / восстановление",
                    Phase::Stopped => "Отключено",
                    Phase::Failed => "Ошибка подключения",
                };
            }
            use crate::windows_system_proxy::{ObservedProxy, ProxyStatus};
            match self.os_observation {
                Some(ObservedProxy::Direct) => "Собственная сессия отсутствует",
                Some(ObservedProxy::External) => "Внешний прокси / PAC / автоопределение",
                Some(ObservedProxy::Journal(ProxyStatus::PendingOwned)) => "Журнал прокси · владелец не подтверждён",
                Some(ObservedProxy::Journal(ProxyStatus::PendingConflict)) => "Требуется восстановление · чужое изменение",
                Some(ObservedProxy::Journal(ProxyStatus::PendingAlreadyRestored)) => "Журнал требует проверки",
                Some(ObservedProxy::Journal(ProxyStatus::NoJournal)) | None => "Состояние Windows не подтверждено",
            }
        }
        #[cfg(not(windows))]
        { "Системный прокси MVP доступен только на Windows" }
    }

    fn file_state(&self, document: Option<&Document>) -> String {
        if self.draft.is_some() || self.catalogue_draft.is_some() || self.routing.as_ref().is_some_and(|(p, _, _)| p.settings != p.original || p.fields.is_some()) {
            return "Файл: черновик не сохранён · рабочая политика не заменена".into();
        }
        if matches!(&self.review, Some(Review::Save(_, _))) { return "Файл: изменения ожидают подтверждения сохранения".into(); }
        let Some(document) = document else {
            return "Файл: отсутствует или не прошёл проверку".into();
        };
        #[cfg(windows)]
        if let Some(session) = &self.session {
            let state = session.control.status();
            return format!("Файл: ревизия {} · Активная: {} · Приём трафика: {}",
                document.anti_dpi.revision, state.revision, if state.admitting { "разрешён" } else { "закрыт" });
        }
        format!("Файл: ревизия {} · {}", document.anti_dpi.revision,
            self.applied_revision.map_or_else(|| "Применение не подтверждено этой панелью".into(),
                |rev| format!("Последнее подтверждение применения: rev {rev}")))
    }

    fn draw_page(&self, frame: &mut Frame<'_>, area: Rect, document: Option<&Document>) {
        use std::fmt::Write as _;
        let mut text = String::new();
        let local = document.map(|doc| &doc.anti_dpi);
        match self.page {
            OVERVIEW => {
                let _ = writeln!(text, "Anti-DPI не активен: стратегии ожидают независимой приёмки.\n{}", self.owner_text());
                if let Some(local) = local {
                    let _ = writeln!(text, "\nРежим: системный прокси\nПравил: {} · По умолчанию: напрямую, если ни одно правило не совпало\nЗащищённый DNS: {}\nПрямой выход: {}\n\nСледующий шаг\n{}",
                        local.rules.len(), if local.resolver.is_some() { "настроен (сеть не проверена)" } else { "не настроен" },
                        yes(local.consent.direct_egress), if local.resolver.is_none() || !local.consent.direct_egress {
                            if local.resolver.is_none() { "Выберите защищённый DNS и разрешения." } else { "Разрешите выход в интернет в настройках, если хотите подключаться." }
                    } else if self.newly_saved { "Примените новую конфигурацию. Это ещё не подключение." }
                    else if self.applied_revision != Some(local.revision) { "Подтвердите применение сохранённых правил." }
                    else if self.owner_active() { "Прокси принадлежит этой панели. Откройте подключение для состояния или отключения." }
                    else if cfg!(windows) { "Откройте подключение или проверьте сайты в диагностике." }
                    else { "Откройте диагностику. Системный прокси MVP доступен только на Windows." });
                } else {
                    let _ = writeln!(text, "\nНастройте локальную конфигурацию. Без VPS, регистрации на сервере и импортируемых ключей.\nСоздание файла не запускает сеть или системный прокси.");
                }
            }
            CONNECTION => {
                let _ = writeln!(text, "Режим: системный прокси (MVP)\nTUN / WinDivert: недоступны, post-MVP\n\nСостояние: {}", self.owner_text());
                if let Some(local) = local {
                    let _ = writeln!(text, "HTTP: {} · SOCKS5: {}\nПрямой выход: {} · Anti-DPI: {}",
                        local.proxy.http_listen, local.proxy.socks5_listen, yes(local.consent.direct_egress), yes(local.consent.direct_dpi));
                }
                #[cfg(windows)]
                if let Some(session) = &self.session {
                    let status = session.control.status();
                    let _ = writeln!(text, "Активная ревизия: {} · Приём: {}", status.revision, if status.admitting { "разрешён" } else { "закрыт" });
                } else {
                    let _ = writeln!(text, "Listeners внешнего процесса не подтверждены.\nПри чужом владельце отключите его штатно. Не захватываем чужой прокси.");
                }
                let _ = writeln!(text, "\nТолько HTTP/CONNECT и SOCKS5; не перехватывает произвольный UDP ОС.\nConnect и восстановление требуют отдельного подтверждения.");
            }
            STATISTICS => {
                let _ = writeln!(text, "Источник: счётчики собственной сессии, не диагностические пробы.");
                #[cfg(windows)]
                if let Some(session) = &self.session {
                    let status = session.control.status();
                    let _ = writeln!(text, "\n{}\nАктивных соединений: {}\nПринято соединений: {}\nОшибок: {}\nБайт к цели: {}\nБайт от цели: {}\n\nРазбивка по стратегиям не подтверждена.",
                        self.owner_text(), status.active, status.accepted, status.errors, status.uploaded, status.downloaded);
                } else { let _ = writeln!(text, "\nНет источника данных. Это не нулевые значения трафика."); }
                #[cfg(not(windows))]
                let _ = writeln!(text, "\nНет источника данных. Это не нулевые значения трафика.");
                let _ = writeln!(text, "\nЯчеек диагностического отчёта: {} (отдельно)", self.results.len());
            }
            SETTINGS => {
                if let Some(doc) = document { text = policy_text(doc); }
                else { text = "Сохранённая конфигурация не прочитана. Ошибочный файл не перезаписывается автоматически.".into(); }
            }
            ROUTING => { text = "Откройте общий редактор правил. Сохранение и применение разделены.".into(); }
            _ => {}
        }
        let items = self.actions();
        let [content, controls] = tui_widgets::action_layout_rows(area, items.len(), 10).unwrap_or([area, Rect::new(area.x, area.bottom(), area.width, 0)]);
        super::panel(frame, content, SECTIONS[self.page], &text, !self.navigation);
        Actions { items: &items, selected: self.action }.render_with_focus(frame, controls, !self.navigation);
    }

    fn columns(&self) -> Vec<Option<&'static str>> {
        let ids = strategy_columns();
        match self.group {
            0 => ids.into_iter().take(4).map(Some).collect(),
            1 => vec![None, Some("quic_v1_initial_split")],
            2 => vec![None, Some("quic_v2_initial_split")],
            _ => vec![None, Some("stun_fingerprint")],
        }
    }

    fn draw_setup_catalogue(&mut self, frame: &mut Frame<'_>, area: Rect) {
        use ratatui::widgets::Cell;
        let body = Layout::vertical([Constraint::Length(4), Constraint::Min(2), Constraint::Length(2)]).split(area);
        let header = format!("Шаг 2 из 5 · Выберите сайты\nОтмечено в каталоге: {} из 64 · Поиск: {}\nИсторический список OONI. Выбор не запускает проверку и не сохраняет правила.", self.selected.len(), if self.filter.is_empty() { "нет" } else { &self.filter });
        frame.render_widget(Paragraph::new(header).style(Style::default().fg(TEXT)).wrap(Wrap { trim: true }), body[0]);
        let height = usize::from(body[1].height.saturating_sub(1)).max(1);
        let len = self.visible().len();
        self.row = self.row.min(len.saturating_sub(1));
        if self.row < self.offset { self.offset = self.row; }
        if self.row >= self.offset + height { self.offset = self.row + 1 - height; }
        self.offset = self.offset.min(len.saturating_sub(1));
        let rows = self.visible().iter().enumerate().skip(self.offset).take(height).map(|(i, entry)| {
            let mark = if entry.excluded { "×" } else if self.selected.contains(&entry.hostname) { "✓" } else { "□" };
            Row::new(vec![Cell::from(mark), Cell::from(entry.hostname.as_str()), Cell::from(if entry.excluded { "Исключён" } else if self.selected.contains(&entry.hostname) { "Выбран" } else { "" })])
                .style(Style::default().fg(if entry.excluded { MUTED } else { TEXT }).bg(if i == self.row { FOCUS } else { SURFACE }))
        }).collect::<Vec<_>>();
        frame.render_widget(Table::new(rows, [Constraint::Length(3), Constraint::Min(16), Constraint::Length(23)])
            .header(Row::new(["", "Сайт", "Выбор"]).style(Style::default().fg(ACCENT))), body[1]);
        frame.render_widget(Paragraph::new("Пробел — отметить сайт. Enter — вернуться к мастеру с выбранными сайтами.").style(Style::default().fg(MUTED)).wrap(Wrap { trim: true }), body[2]);
    }

    fn draw_diagnostics(&mut self, frame: &mut Frame<'_>, area: Rect) {
        use ratatui::widgets::Cell;
        let groups = ["TCP / HTTPS", "QUIC v1", "QUIC v2", "STUN"];
        let cols = self.columns();
        let counts = self.results.values().filter(|c| cols.contains(&Some(c.strategy_id))).fold([0usize; 5], |mut acc, c| {
            let i = if c.stale { 4 } else { match c.status {
                CellStatus::Available => 0,
                CellStatus::Unsupported | CellStatus::NotApplicable | CellStatus::NotChecked => 2,
                CellStatus::Cancelled => 3,
                _ => 1,
            }};
            acc[i] += 1;
            acc
        });
        let progress = self.worker.as_ref().map_or_else(
            || if self.results.is_empty() { "Ожидает запуска".into() } else { "Результаты последнего задания".into() },
            |w| format!("Выполняется: {}/{} ячеек", self.results.len(), w.total));
        let view = if self.report_only { "Результаты · v: открыть каталог" } else { "Каталог · v: результаты" };
        let hint = if self.worker.is_some() { "Esc — остановить проверку" } else if self.report_only { "F7 — объяснение выбранного результата; b — повторить неуспешные" } else { "Пробел — отметить сайт; Enter — проверить выбранные" };
        let header = format!(
            "{view} · {progress}\nСайтов: {} · отмечено для следующей проверки {}/64 · поиск: {}\n{} · [ ] протокол · ← → ячейка\n{hint}",
            self.visible().len(), self.selected.len(), if self.filter.is_empty() { "нет" } else { &self.filter }, groups[self.group]);
        let header_h = if area.width < 90 { 7 } else { 5 };
        let details_h = if area.height >= 20 { 7 } else { 3 };
        let body = Layout::vertical([Constraint::Length(header_h), Constraint::Min(2), Constraint::Length(details_h)]).split(area);
        frame.render_widget(Paragraph::new(header).style(Style::default().fg(MUTED)).wrap(Wrap { trim: true }), body[0]);
        let height = usize::from(body[1].height.saturating_sub(1)).max(1);
        let visible_len = self.visible().len();
        self.row = self.row.min(visible_len.saturating_sub(1));
        if self.row < self.offset { self.offset = self.row; }
        if self.row >= self.offset + height { self.offset = self.row + 1 - height; }
        self.offset = self.offset.min(visible_len.saturating_sub(1));
        // Keep the domain and focused strategy visible on small terminals;
        // expose every other strategy using the same left/right navigation.
        let max_cols = usize::from(body[1].width.saturating_sub(19) / 11).max(1);
        let count = max_cols.min(cols.len());
        self.column = self.column.min(cols.len().saturating_sub(1));
        let start = self.column.saturating_sub(count.saturating_sub(1)).min(cols.len().saturating_sub(count));
        let window = &cols[start..start + count];
        let rows = self.visible().iter().enumerate().skip(self.offset).take(height).map(|(index, entry)| {
            let name = format!("{}{}", if entry.excluded { "× " } else if self.selected.contains(&entry.hostname) { "✓ " } else { "  " }, entry.hostname);
            let mut values = vec![Cell::from(name)];
            for (i, &id) in window.iter().enumerate() {
                let result = id.and_then(|id| self.results.get(&(entry.hostname.clone(), id)));
                let label = if id.is_none() { "нет базы".into() }
                    else if let Some(c) = result.filter(|c| !c.stale) {
                        if let Some(code) = c.http_status { code.to_string() } else { status(Some(c)).into() }
                    } else if result.is_none() && id.is_some_and(|id| strategy_unavailable(id) == Some(Reason::AwaitingAcceptance)) { "н/п".into() }
                    else { status(result).into() };
                let focus = index == self.row && start + i == self.column;
                let style = Style::default().fg(cell_color(result)).bg(if focus { super::INPUT } else if index == self.row { FOCUS } else { SURFACE });
                values.push(Cell::from(label).style(if focus { style.add_modifier(Modifier::BOLD) } else { style }));
            }
            Row::new(values).style(Style::default().fg(TEXT).bg(if index == self.row { FOCUS } else { SURFACE }))
        }).collect::<Vec<_>>();
        let widths = std::iter::once(Constraint::Min(16)).chain(window.iter().map(|_| Constraint::Length(10))).collect::<Vec<_>>();
        let headers = std::iter::once("Домен").chain(window.iter().map(|id| id.map_or("Прямой*", column_label))).collect::<Vec<_>>();
        frame.render_widget(Table::new(rows, widths).header(Row::new(headers).style(Style::default().fg(ACCENT))), body[1]);
        let selected = self.visible().get(self.row).map(|entry| {
            let source = entry.provenance.as_ref().map_or_else(|| "Свой домен; нет исторического доказательства".into(),
                |p| format!("OONI · {} · сетей {}", p.last_confirmed_day, p.confirmed_networks));
            format!("{} · {source}", entry.hostname)
        }).unwrap_or_else(|| "Нет совпадений".into());
        let legend = if self.group == 0 { "2xx — ответ получен · 3xx — перенаправление · 4xx/5xx — HTTP-ошибка\nн/п — не поддерживается · н/пр — неприменимо · — не проверено" }
            else { "Прямой* — контроль UDP не реализован. Сравнение с TCP недопустимо.\nн/п — не поддерживается · — не проверено" };
        let totals = if self.results.is_empty() { "Проверка ещё не выполнялась.".to_owned() } else if counts.iter().sum::<usize>() == 0 { "Для этого протокола результатов нет.".to_owned() } else { format!("Ячейки {}: доступно {} · ошибки/ограничения {} · без проверки {}\nОтменено {} · устарело {}", groups[self.group], counts[0], counts[1], counts[2], counts[3], counts[4]) };
        let summary = format!("{totals}\n{selected}\n{legend}\nКаталог: исторические данные OONI, не текущие блокировки. Правила не меняются.");
        frame.render_widget(Paragraph::new(summary).style(Style::default().fg(MUTED)).wrap(Wrap { trim: true }), body[2]);
    }

    fn detail_text(&self) -> String {
        let visible = self.visible();
        let Some(entry) = visible.get(self.row) else { return "Нет выбранной строки".into(); };
        let cols = self.columns();
        let id = cols.get(self.column).copied().flatten();
        let name = id.map_or("Прямой контроль (UDP)", column_label);
        let provenance = entry.provenance.as_ref().map_or_else(|| "Свой домен; без доказательства ограничения".into(),
            |p| format!("Источник: {}\nПоследнее подтверждение: {} · Сетей: {}\nМасштаб ограничения не установлен", p.source, p.last_confirmed_day, p.confirmed_networks));
        let mut text = format!("{} · {name}\n{provenance}\n\n", entry.hostname);
        if let Some(c) = id.and_then(|id| self.results.get(&(entry.hostname.clone(), id))) {
            text.push_str(&format!("Что это значит: {}\n\nСтатус: {}\nАктуальность: {}\nПричина: {}\nПротокол: {:?}\nСеть: {} · TLS: {} · Приложение: {}\nHTTP: {} · Длительность: {} мс · Попыток: {}\nМодификация: {}\nEndpoint: {} · Source: {}\nРешение политики: {:?}",
                cell_explanation(c), status_long(c.status), if c.stale { "Устарело" } else { "На момент проверки" }, reason(c.reason), c.protocol,
                stage(c.network), stage(c.tls), stage(c.application), c.http_status.map_or_else(|| "—".into(), |code| code.to_string()),
                c.duration_ms, c.attempts, c.actual_modification.map_or("Не подтверждена", |m| if m { "Да" } else { "Нет" }),
                c.endpoint.map_or_else(|| "—".into(), |e| e.to_string()), c.source.map_or_else(|| "—".into(), |ip| ip.to_string()), c.policy_action));
        } else {
            text.push_str(if id.is_none() { "Отдельный Direct-контроль UDP ещё не реализован. Сравнение недоступно." }
                else if id.is_some_and(|id| strategy_unavailable(id) == Some(Reason::AwaitingAcceptance)) { "Стратегия не поддерживается: независимая приёмка не завершена. Проверка не выполнялась." }
                else { "Нет результата для этой стратегии. Не проверено." });
        }
        text
    }

    fn draw(&mut self, frame: &mut Frame<'_>) {
        let area = frame.area();
        tui_widgets::canvas(frame, area);
        if area.width < 40 || area.height < 14 {
            frame.render_widget(Paragraph::new("Увеличьте терминал (минимум 40×14).").wrap(Wrap { trim: true }), area);
            return;
        }
        let document = Document::read(&self.path).ok();
        let parts = Layout::vertical([Constraint::Length(2), Constraint::Min(6), Constraint::Length(3)]).split(area);
        tui_widgets::shell_header(frame, parts[0], "THEIA  •  Anti-DPI", self.owner_text(), &self.file_state(document.as_ref()));
        let modal = self.draft.is_some() || self.catalogue_draft.is_some() || self.review.is_some();
        let body = if modal { parts[1] } else if let Some([nav, _, details]) = workspace_columns(parts[1]) {
            tui_widgets::section_navigation(frame, nav, SECTIONS, self.page, self.navigation);
            details
        } else if self.navigation && self.review.is_none() && self.draft.is_none() {
            tui_widgets::section_navigation(frame, parts[1], SECTIONS, self.page, true);
            frame.render_widget(Paragraph::new(tui_widgets::key_line("↑ ↓ разделы · Enter открыть · Esc назад")).style(Style::default().bg(SURFACE)), parts[2]);
            return;
        } else { parts[1] };

        let footer: String;
        if self.help {
            super::panel(frame, body, "Справка Anti-DPI",
                "F2 — разделы; ↑↓ выбор; Enter открыть; Esc назад.\nНастройки и правила сохраняются отдельно от применения.\nДиагностика: Пробел отметить, s все, c очистить, / поиск, i свой домен, x исключить/вернуть, R восстановить встроенные.\n[ ] протоколы, ←→ ячейка, F7 подробности, b повтор, z экспорт.\nСеть только после явного согласия. Отказ Anti-DPI не превращается в прямой маршрут.", true);
            footer = "Esc закрыть · F1 справка".into();
        } else if let Some(review) = &self.review {
            let (title, text, label) = match review {
                Review::Diagnostic(plan) => ("Диагностика", plan.ui_preview(self.owner_active()), "Запустить проверку"),
                Review::Policy(candidate, enroll) => ("Применение локальной политики", format!("{}\n\n{}\nСеть и настройки ОС не меняются этой операцией.\nСтарые разрешения потоков отзываются при публикации.",
                    if *enroll { "Первичная регистрация локальной ревизии (не регистрация на сервере)." } else { "Применить сохранённую ревизию." },
                    policy_text(candidate.document())), "Применить"),
                Review::Save(draft, next) => ("Проверьте настройки перед сохранением", format!("{}\n\n{}\n\n{}", if draft.first_run() { "Создать новый файл без перезаписи." } else { "Сохранить изменения, не применяя их." }, plain_summary(next), policy_text(next)), "Сохранить"),
                Review::DiscardRouting => ("Отменить черновик?", "Несохранённые изменения маршрутизации будут потеряны. Рабочая политика не меняется.".into(), "Отменить изменения"),
                Review::Export(_, path) => ("Обезличенный экспорт", format!("Сохранить агрегированный отчёт в:\n{}\n\nБез доменов, IP, секретов и идентификаторов. Существующий файл не перезаписывается.", path.display()), "Экспортировать"),
                #[cfg(windows)]
                Review::Connect(candidate, review) => ("Подключение", format!("{}\n{}\n\nПрокси WinINet будет изменён только при совпадении проверенного снимка.\nПри отказе Modify трафик блокируется. Публичный IP виден получателям.\n{}", review.description(), "Системный прокси, не TUN и не полный перехват UDP.", policy_text(candidate.document())), "Подключить"),
                #[cfg(windows)]
                Review::Recover(_) => ("Восстановление системного прокси", "Восстановить только точный проверенный журнал и снимок Windows. Чужой владелец или изменённые настройки не будут перезаписаны.".into(), "Восстановить"),
                #[cfg(windows)]
                Review::Disconnect(exit) => ("Отключение", format!("Остановить принадлежащую панели сессию, отозвать потоки и выполнить условное восстановление настроек Windows.\n{}", if *exit { "Затем выйти из панели." } else { "Остаться в панели." }), "Отключить"),
            };
            let rects = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).split(body);
            frame.render_widget(Paragraph::new(title).style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)), rects[0]);
            // Estimate a conservative upper bound for wrapped lines, so a
            // long selector or DNS/target list never hides the end of consent.
            let width = usize::from(rects[1].width.max(1));
            let wrapped = text.lines().map(|line| line.chars().count().div_ceil(width).max(1) + 1).sum::<usize>();
            let scroll = self.review_scroll.min(wrapped.saturating_sub(1).min(u16::MAX as usize) as u16);
            frame.render_widget(Paragraph::new(text).style(Style::default().fg(TEXT)).wrap(Wrap { trim: false }).scroll((scroll, 0)), rects[1]);
            tui_widgets::confirmation_bar(frame, parts[2], "↑↓ / PgUp PgDn просмотр · ←→ выбор · Enter · Esc отменить", false, label, self.confirm_selected);
            return;
        } else if let Some(draft) = &self.draft {
            if draft.step != SetupStep::Advanced {
                draft.render_wizard(frame, body);
                footer = if matches!(draft.step, SetupStep::DomainInput | SetupStep::CustomDns) {
                    "↑ ↓ поля · Enter далее · Del очистить · Esc назад".into()
                } else { "↑ ↓ выбор · Enter далее · Esc назад".into() };
            } else {
                draft.form().render(frame, body, "Настройки локальной конфигурации");
                footer = "↑ ↓ поля · Пробел выбор · Del очистить · F5 проверить · Esc назад".into();
            }
        } else if let Some((panel, _, _)) = &self.routing {
            panel.render(frame, body, true);
            footer = "↑ ↓ выбор · Tab действия · Enter открыть · s сохранить · Esc назад · F6 GeoData".into();
        } else if self.details {
            super::panel(frame, body, "Подробности проверки", &self.detail_text(), true);
            footer = "Esc назад · F7 закрыть".into();
        } else if self.page == DIAGNOSTICS {
            if self.catalogue_draft.is_some() { self.draw_setup_catalogue(frame, body); } else { self.draw_diagnostics(frame, body); }
            footer = if let Some((custom, text)) = &self.editing {
                format!("{}: {text} · Enter принять · Esc отменить", if *custom { "Свой домен" } else { "Поиск" })
            } else if self.catalogue_draft.is_some() {
                "↑ ↓ сайты · Пробел отметить · s все · c очистить · / поиск · Enter принять · Esc назад".into()
            } else if self.worker.is_some() {
                "Esc отменить · ↑ ↓ строки · ← → ячейки · [ ] протокол · F7 детали".into()
            } else {
                if self.report_only { "↑ ↓ сайты · ← → ячейки · F7 объяснение · v каталог · b повтор · z экспорт · F2 разделы".into() }
                else { "↑ ↓ сайты · Пробел отметить · Enter проверить · / поиск · i свой сайт · F1 помощь · F2 разделы · v результаты".into() }
            };
        } else {
            self.draw_page(frame, body, document.as_ref());
            footer = if self.navigation { "↑ ↓ разделы · Enter открыть · Esc назад".into() }
                else { "↑ ↓ действия · Enter открыть · F2 разделы · F1 помощь · Esc назад".into() };
        }
        let footer_rects = Layout::vertical([Constraint::Length(1), Constraint::Length(2)]).split(parts[2]);
        let notice = if let Some(draft) = &self.draft {
            if draft.error.is_empty() { "Настройки не сохранены. Сеть не запускается." } else { &draft.error }
        } else { &self.notice };
        frame.render_widget(Paragraph::new(tui_widgets::fit_value(notice, footer_rects[0].width, false)).style(Style::default().fg(WARNING).bg(SURFACE)), footer_rects[0]);
        frame.render_widget(Paragraph::new(tui_widgets::key_line(&footer)).style(Style::default().bg(SURFACE)).wrap(Wrap { trim: true }), footer_rects[1]);
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
                    if panel.routing.is_some() && panel.review.is_none() && !panel.help {
                        panel.routing_key(if code == KeyCode::Esc { KeyEvent::new(code, KeyModifiers::NONE) } else { key });
                    } else if panel.key(code)? { return Ok(()); }
                }
                Event::Paste(value) => {
                    if let Some(draft) = &mut panel.draft { draft.paste(&value); }
                    else if panel.review.is_none() && panel.routing.is_some() { if let Some((routing, _, _)) = &mut panel.routing { routing.paste(&value); } }
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
    fn f20_panel_gallery_capture() {
        use crate::anti_dpi::diagnostic::Protocol;
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
        panel.key(KeyCode::Enter).unwrap();
        capture("anti-dpi-setup-domains", &mut panel);
        panel.key(KeyCode::Enter).unwrap();
        panel.key(KeyCode::Char(' ')).unwrap();
        capture("anti-dpi-setup-catalog", &mut panel);
        panel.key(KeyCode::Enter).unwrap();
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Enter).unwrap();
        capture("anti-dpi-setup-dns", &mut panel);
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Enter).unwrap();
        capture("anti-dpi-setup-custom-dns", &mut panel);
        panel.key(KeyCode::Esc).unwrap();
        panel.key(KeyCode::Enter).unwrap();
        capture("anti-dpi-setup-direct", &mut panel);
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Enter).unwrap();
        capture("anti-dpi-setup-modify", &mut panel);
        panel.key(KeyCode::Enter).unwrap();
        assert!(panel.review.is_some());
        capture("anti-dpi-first-run-preview", &mut panel);
        assert!(!path.exists());
        assert!(panel.worker.is_none());
        panel.key(KeyCode::Esc).unwrap();
        while panel.draft.is_some() { panel.key(KeyCode::Esc).unwrap(); }
        panel.create_config();
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Enter).unwrap();
        capture("anti-dpi-setup-manual", &mut panel);
        while panel.draft.is_some() { panel.key(KeyCode::Esc).unwrap(); }
        assert!(!path.exists());
        std::fs::write(&path, format!("{}\n[anti_dpi.resolver]\nhostname='dns.example.com'\nbootstrap=['1.1.1.1']\n",
            include_str!("../../../../examples/anti-dpi.toml"))).unwrap();
        panel.notice = "Конфигурация прочитана. Сеть не запускалась.".into();
        capture("anti-dpi-overview", &mut panel);
        panel.open_page(CONNECTION);
        capture("anti-dpi-connection", &mut panel);
        panel.open_page(STATISTICS);
        capture("anti-dpi-statistics", &mut panel);
        panel.open_page(SETTINGS);
        capture("anti-dpi-settings", &mut panel);
        panel.open_settings();
        capture("anti-dpi-settings-guided", &mut panel);
        panel.key(KeyCode::Enter).unwrap();
        capture("anti-dpi-settings-dns", &mut panel);
        panel.key(KeyCode::Esc).unwrap();
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Enter).unwrap();
        capture("anti-dpi-settings-permissions", &mut panel);
        panel.key(KeyCode::Esc).unwrap();
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Enter).unwrap();
        capture("anti-dpi-settings-editor", &mut panel);
        panel.key(KeyCode::Esc).unwrap();
        panel.key(KeyCode::Esc).unwrap();
        panel.open_page(ROUTING);
        assert!(panel.routing.is_some());
        capture("anti-dpi-routing", &mut panel);
        panel.routing_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        capture("anti-dpi-routing-editor", &mut panel);
        panel.routing_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        panel.routing_key(KeyEvent::new(KeyCode::Char('B'), KeyModifiers::NONE));
        capture("anti-dpi-geodata", &mut panel);
        panel.routing = None;
        panel.open_page(DIAGNOSTICS);
        panel.key(KeyCode::Char('s')).unwrap();
        capture("anti-dpi-catalog", &mut panel);
        panel.selected = panel.catalog.entries().iter().take(6).map(|entry| entry.hostname.clone()).collect();
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
        panel.report_hosts = panel.selected.clone();
        panel.report_only = true;
        panel.row = 0; panel.offset = 0;
        panel.notice = "СИНТЕТИЧЕСКИЙ ОФЛАЙН-ПРИМЕР · сеть не проверялась".into();
        capture("state-anti-dpi-diagnostic-report", &mut panel);
        assert_eq!(panel.visible().len(), 6);
        panel.key(KeyCode::Char('v')).unwrap();
        assert_eq!(panel.visible().len(), 60);
        panel.key(KeyCode::Char('v')).unwrap();
        assert_eq!(panel.visible().len(), 6);
        let (_send, updates) = mpsc::channel();
        panel.worker = Some(Worker { cancel: Arc::new(AtomicBool::new(false)), updates, thread: None, total: 60 });
        panel.notice = "СИНТЕТИЧЕСКИЙ ОФЛАЙН-ПРИМЕР · проверка выполняется".into();
        capture("state-anti-dpi-diagnostic-progress", &mut panel);
        panel.key(KeyCode::Esc).unwrap();
        assert!(panel.worker.as_ref().unwrap().cancel.load(Ordering::Acquire));
        panel.worker.take();
        panel.notice = "СИНТЕТИЧЕСКИЙ ОФЛАЙН-ПРИМЕР · задание отменено, частичные результаты".into();
        capture("state-anti-dpi-diagnostic-cancelled", &mut panel);
        panel.notice = "СИНТЕТИЧЕСКИЙ ОФЛАЙН-ПРИМЕР · сеть не проверялась".into();
        panel.details = true;
        capture("state-anti-dpi-diagnostic-cell", &mut panel);
        panel.details = false;
        panel.group = 1;
        capture("state-anti-dpi-diagnostic-quic", &mut panel);
        panel.group = 0;
        panel.begin_export();
        capture("state-anti-dpi-export-confirm", &mut panel);
        panel.key(KeyCode::Esc).unwrap();
        assert!(panel.worker.is_none());
        assert!(!panel.results.is_empty());
    }

    #[test]
    fn offline_panel_selects_catalog_without_network_or_configuration() {
        let path = std::env::temp_dir().join(format!("theia-f20-panel-{}", std::process::id())).join("anti-dpi.toml");
        let mut panel = Panel::new(path.clone()).unwrap();
        assert_eq!(panel.page, OVERVIEW);
        assert!(panel.draft.is_some());
        panel.key(KeyCode::Esc).unwrap();
        panel.open_page(DIAGNOSTICS);
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

    #[test]
    fn diagnostic_view_is_separate_from_selection_and_catalogue() {
        let path = std::env::temp_dir().join(format!("theia-f20-report-view-{}", std::process::id())).join("anti-dpi.toml");
        let mut panel = Panel::new(path.clone()).unwrap();
        panel.key(KeyCode::Esc).unwrap();
        panel.open_page(DIAGNOSTICS);
        let host = panel.catalog.entries()[0].hostname.clone();
        panel.report_hosts.insert(host.clone());
        panel.report_only = true;
        assert_eq!(panel.visible().len(), 1);
        panel.key(KeyCode::Char('v')).unwrap();
        assert_eq!(panel.visible().len(), 60);
        panel.key(KeyCode::Char('v')).unwrap();
        assert_eq!(panel.visible()[0].hostname, host);
        assert!(panel.selected.is_empty());
        assert!(panel.worker.is_none());
        assert!(!path.exists());
    }

    #[test]
    fn setup_catalogue_preserves_custom_sites_and_diagnostic_selection() {
        let path = std::env::temp_dir().join(format!("theia-f20-selection-{}", std::process::id())).join("anti-dpi.toml");
        let mut panel = Panel::new(path.clone()).unwrap();
        let prior = panel.catalog.entries()[0].hostname.clone();
        panel.selected.insert(prior.clone());
        panel.filter = "prior".into();
        panel.key(KeyCode::Enter).unwrap(); // recommended
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Enter).unwrap(); // custom sites
        panel.draft.as_mut().unwrap().paste("example.org");
        panel.key(KeyCode::Enter).unwrap();
        panel.key(KeyCode::Enter).unwrap(); // catalogue
        panel.key(KeyCode::Char(' ')).unwrap();
        panel.key(KeyCode::Enter).unwrap();
        let hosts = panel.draft.as_ref().unwrap().domain_values().unwrap();
        assert!(hosts.contains("example.org"));
        assert!(hosts.contains(&prior));
        assert_eq!(panel.selected, BTreeSet::from([prior]));
        assert_eq!(panel.filter, "prior");
        assert!(!path.exists());
        assert!(panel.worker.is_none());
    }

    #[test]
    fn guided_settings_preview_changes_only_dns_and_preserves_cancellation() {
        let root = std::env::temp_dir().join(format!("theia-f20-settings-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("anti-dpi.toml");
        let original = include_str!("../../../../examples/anti-dpi.toml");
        std::fs::write(&path, original).unwrap();
        let mut panel = Panel::new(path.clone()).unwrap();
        panel.open_settings();
        assert!(panel.draft.as_ref().unwrap().step == SetupStep::Settings);
        panel.key(KeyCode::Enter).unwrap(); // DNS
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Enter).unwrap(); // Quad9
        if let Some(Review::Save(draft, next)) = &panel.review {
            assert_eq!(next.anti_dpi.resolver.as_ref().unwrap().hostname, "dns.quad9.net");
            assert_eq!(next.anti_dpi.rules, draft.original.anti_dpi.rules);
            assert_eq!(next.anti_dpi.consent, draft.original.anti_dpi.consent);
            assert_eq!(next.anti_dpi.proxy, draft.original.anti_dpi.proxy);
        } else { panic!("expected reviewed Save"); }
        panel.key(KeyCode::Esc).unwrap();
        panel.key(KeyCode::Esc).unwrap();
        panel.key(KeyCode::Esc).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(panel.worker.is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wizard_never_saves_without_review_and_preview_is_localized() {
        let root = std::env::temp_dir().join(format!("theia-f20-wizard-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("anti-dpi.toml");
        let mut panel = Panel::new(path.clone()).unwrap();
        assert_eq!(panel.draft.as_ref().unwrap().flags, [false; 4]);
        panel.key(KeyCode::F(5)).unwrap(); // cannot skip choices
        assert!(panel.review.is_none());
        panel.key(KeyCode::Enter).unwrap(); // recommended
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Enter).unwrap(); // own domains
        panel.draft.as_mut().unwrap().paste("example.org");
        panel.key(KeyCode::Enter).unwrap();
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Down).unwrap();
        panel.key(KeyCode::Enter).unwrap(); // continue with explicit domain
        assert!(panel.draft.as_ref().unwrap().values[0].is_empty());
        panel.key(KeyCode::Enter).unwrap(); // explicit Cloudflare choice
        assert_eq!(panel.draft.as_ref().unwrap().values[0], "cloudflare-dns.com");
        panel.key(KeyCode::Down).unwrap(); // highlighting permission does not grant it
        assert!(!panel.draft.as_ref().unwrap().flags[0]);
        panel.key(KeyCode::Up).unwrap();
        panel.key(KeyCode::Enter).unwrap(); // deny, preview
        assert!(matches!(panel.review, Some(Review::Save(_, _))));
        assert!(!path.exists());
        panel.key(KeyCode::Enter).unwrap();
        assert!(panel.draft.is_some());
        assert!(!path.exists());
        panel.key(KeyCode::Enter).unwrap();
        panel.key(KeyCode::Right).unwrap();
        panel.key(KeyCode::Enter).unwrap();
        let saved = Document::read(&path).unwrap();
        assert_eq!(saved.anti_dpi.rules.len(), 1);
        assert_eq!(saved.anti_dpi.rules[0].domains, ["full:example.org"]);
        assert!(!saved.anti_dpi.consent.direct_egress);
        assert!(!saved.anti_dpi.consent.direct_dpi);
        assert!(!saved.anti_dpi.consent.direct_dpi_stun);
        assert_eq!(saved.anti_dpi.resolver.as_ref().unwrap().hostname, "cloudflare-dns.com");
        assert!(panel.newly_saved);
        assert!(panel.applied_revision.is_none());
        assert!(!panel.owner_active());
        panel.open_page(DIAGNOSTICS);
        for (width, height) in [(80, 24), (120, 40), (160, 50)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| panel.draw(frame)).unwrap();
            assert!(terminal.backend().buffer().content().iter().any(|cell| cell.symbol() != " "));
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
