//! Privacy-preserving, process-local application DATA accounting.
//! Counts complete relay writes/accepted frames, not IP/wire bytes or peer ACKs.
//! No per-destination state, payload, credentials, unbounded history or I/O.
use crate::{
    tui_widgets::{self, ACCENT, MUTED, SURFACE, TEXT},
    Role,
};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Sparkline, Wrap},
    Frame,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub active: u64,
    pub opened: u64,
    pub upload: u64,
    pub download: u64,
}

struct Counters {
    active: AtomicU64,
    opened: AtomicU64,
    upload: AtomicU64,
    download: AtomicU64,
}
impl Counters {
    const fn new() -> Self {
        Self {
            active: AtomicU64::new(0),
            opened: AtomicU64::new(0),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        }
    }

    fn enter(&self) -> Relay<'_> {
        self.opened.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        Relay(self)
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            active: self.active.load(Ordering::Relaxed),
            opened: self.opened.load(Ordering::Relaxed),
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
        }
    }
}

pub(crate) struct Relay<'a>(&'a Counters);
impl Relay<'_> {
    pub(crate) fn upload(&self, bytes: usize) {
        self.0.upload.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub(crate) fn download(&self, bytes: usize) {
        self.0.download.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}
impl Drop for Relay<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

static SERVER_H2: Counters = Counters::new();
static SERVER_H3: Counters = Counters::new();
static CLIENT_H2: Counters = Counters::new();
static CLIENT_H3: Counters = Counters::new();
static CLIENT_DIRECT: Counters = Counters::new();
static CLIENT_BLOCKED: AtomicU64 = AtomicU64::new(0);
static DPI_FIRST_RESPONSE: AtomicU64 = AtomicU64::new(0);
static DPI_FALLBACK_OPEN: AtomicU64 = AtomicU64::new(0);
static DPI_FIRST_FAILURE: AtomicU64 = AtomicU64::new(0);
static UDP_DIRECT: Counters = Counters::new();
static UDP_CLIENT_H2: Counters = Counters::new();
static UDP_CLIENT_H3: Counters = Counters::new();
static UDP_SERVER_H2: Counters = Counters::new();
static UDP_SERVER_H3: Counters = Counters::new();
static UDP_QUIC: AtomicU64=AtomicU64::new(0);
static UDP_STUN: AtomicU64=AtomicU64::new(0);
static UDP_STUN_RESPONSE: AtomicU64=AtomicU64::new(0);
static UDP_DPI_FALLBACK: AtomicU64=AtomicU64::new(0);
pub(crate) fn enter_udp(role:Role,h3:bool,direct:bool)->Relay<'static>{
    if direct {return UDP_DIRECT.enter();}
    (match (role,h3){(Role::Client,false)=>&UDP_CLIENT_H2,(Role::Client,true)=>&UDP_CLIENT_H3,(Role::Server,false)=>&UDP_SERVER_H2,(Role::Server,true)=>&UDP_SERVER_H3}).enter()
}
pub(crate) fn udp_quic_flow(){UDP_QUIC.fetch_add(1,Ordering::Relaxed);}
pub(crate) fn udp_stun_flow(){UDP_STUN.fetch_add(1,Ordering::Relaxed);}
pub(crate) fn udp_stun_response(){UDP_STUN_RESPONSE.fetch_add(1,Ordering::Relaxed);}
pub(crate) fn udp_dpi_fallback(){UDP_DPI_FALLBACK.fetch_add(1,Ordering::Relaxed);}
#[cfg(test)]
#[test]
fn udp_routing_summary_reports_independent_counters(){
    let report=routing_summary_from([0,0,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,10]);
    assert!(report.contains("UDP VPS:"));
    assert!(report.contains("QUIC Initial 7 · STUN 8 · совпавший ответ 9"));
    assert!(report.contains("UDP Anti-DPI: только VPS, открыто 10"));
}

pub(crate) fn enter_direct() -> Relay<'static> {
    CLIENT_DIRECT.enter()
}
pub(crate) fn blocked() {
    CLIENT_BLOCKED.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn dpi_first_response() {
    DPI_FIRST_RESPONSE.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn dpi_fallback_open() {
    DPI_FALLBACK_OPEN.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn dpi_first_failure() {
    DPI_FIRST_FAILURE.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn routing_totals() -> [u64; 20] {
    let direct = CLIENT_DIRECT.snapshot();
    let proxied = snapshot(Role::Client);
    let udp=UDP_DIRECT.snapshot();
    let h2=UDP_CLIENT_H2.snapshot();let h3=UDP_CLIENT_H3.snapshot();
    [
        direct.upload,
        direct.download,
        proxied[0].upload.saturating_add(proxied[1].upload),
        proxied[0].download.saturating_add(proxied[1].download),
        CLIENT_BLOCKED.load(Ordering::Relaxed),
        direct.active,
        proxied[0].active.saturating_add(proxied[1].active),
        DPI_FIRST_RESPONSE.load(Ordering::Relaxed),
        DPI_FALLBACK_OPEN.load(Ordering::Relaxed),
        DPI_FIRST_FAILURE.load(Ordering::Relaxed),
        udp.upload,udp.download,h2.upload.saturating_add(h3.upload),h2.download.saturating_add(h3.download),udp.active,h2.active.saturating_add(h3.active),UDP_QUIC.load(Ordering::Relaxed),UDP_STUN.load(Ordering::Relaxed),UDP_STUN_RESPONSE.load(Ordering::Relaxed),UDP_DPI_FALLBACK.load(Ordering::Relaxed),
    ]
}

pub(crate) fn routing_summary() -> String {
    routing_summary_from(routing_totals())
}

pub(crate) fn routing_summary_from(totals: [u64; 20]) -> String {
    let [direct_up, direct_down, proxy_up, proxy_down, blocked, direct_active, proxy_active,
        dpi_first_response, dpi_fallback_open, dpi_first_failure,udp_direct_up,udp_direct_down,udp_proxy_up,udp_proxy_down,udp_direct_active,udp_proxy_active,quic,stun,stun_response,udp_fallback] = totals;
    format!(
        "Через VPS: ↑ {} ↓ {} · активно {proxy_active}\nНапрямую: ↑ {} ↓ {} · активно {direct_active}\nЗаблокировано: {blocked}\nAnti-DPI: первый ответ TLS {dpi_first_response} · резерв VPS {dpi_fallback_open}\nОшибки первого обмена: {dpi_first_failure}\nUDP VPS: ↑ {} ↓ {} · активно {udp_proxy_active}\nUDP напрямую: ↑ {} ↓ {} · активно {udp_direct_active}\nUDP: QUIC Initial {quic} · STUN {stun} · совпавший ответ {stun_response}\nUDP Anti-DPI: только VPS, открыто {udp_fallback}",
        bytes(proxy_up),
        bytes(proxy_down),
        bytes(direct_up),
        bytes(direct_down),
        bytes(udp_proxy_up),bytes(udp_proxy_down),bytes(udp_direct_up),bytes(udp_direct_down),
    )
}

fn counters(role: Role, h3: bool) -> &'static Counters {
    match (role, h3) {
        (Role::Server, false) => &SERVER_H2,
        (Role::Server, true) => &SERVER_H3,
        (Role::Client, false) => &CLIENT_H2,
        (Role::Client, true) => &CLIENT_H3,
    }
}
pub(crate) fn enter(role: Role, h3: bool) -> Relay<'static> {
    counters(role, h3).enter()
}
pub(crate) fn snapshot(role: Role) -> [Snapshot; 2] {
    [
        counters(role, false).snapshot(),
        counters(role, true).snapshot(),
    ]
}

fn bytes(n: u64) -> String {
    if n >= 1024 * 1024 * 1024 {
        format!("{:.2} ГиБ", n as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if n >= 1024 * 1024 {
        format!("{:.2} МиБ", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} КиБ", n as f64 / 1024.0)
    } else {
        format!("{n} Б")
    }
}

/// Refresh no faster than once a second, with a fixed-size sample.
pub(crate) struct Monitor {
    role: Role,
    previous: [Snapshot; 2],
    current: [Snapshot; 2],
    rate: [(u64, u64); 2],
    sampled: Instant,
    history: VecDeque<[u64; 2]>,
}
impl Monitor {
    pub(crate) fn new(role: Role) -> Self {
        let current = snapshot(role);
        Self {
            role,
            previous: current,
            current,
            rate: [(0, 0); 2],
            sampled: Instant::now(),
            history: VecDeque::with_capacity(60),
        }
    }
    pub(crate) fn poll(&mut self) {
        let elapsed = self.sampled.elapsed().as_secs_f64();
        if elapsed < 1.0 {
            return;
        }
        self.current = snapshot(self.role);
        for (i, (now, old)) in self.current.iter().zip(self.previous.iter()).enumerate() {
            self.rate[i] = (
                (now.upload.saturating_sub(old.upload) as f64 / elapsed) as u64,
                (now.download.saturating_sub(old.download) as f64 / elapsed) as u64,
            );
        }
        if self.history.len() == 60 {
            self.history.pop_front();
        }
        self.history
            .push_back(self.rate.map(|(up, down)| up.saturating_add(down)));
        self.previous = self.current;
        self.sampled = Instant::now();
    }
    /// Render only measured process-local aggregates. Each transport uses
    /// the same chart scale; the history is bounded to 60 sampled intervals.
    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        tui_widgets::canvas(frame, area);
        if area.width < 46 || area.height < 17 || (area.width < 86 && area.height < 27) {
            frame.render_widget(
                Paragraph::new(self.body())
                    .wrap(Wrap { trim: false })
                    .block(tui_widgets::section(" Монитор трафика ", true)),
                area,
            );
            return;
        }
        let area = Rect::new(
            area.x,
            area.y,
            area.width,
            area.height.min(if area.width >= 86 { 25 } else { 36 }),
        );
        let layout = Layout::vertical([
            Constraint::Length(4),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(area);
        let active = self
            .current
            .iter()
            .map(|s| s.active)
            .fold(0u64, u64::saturating_add);
        let opened = self
            .current
            .iter()
            .map(|s| s.opened)
            .fold(0u64, u64::saturating_add);
        let scope = format!("Активные туннели: {active}   •   Всего открыто: {opened}\nДанные этого процесса без служебного трафика; доставка не подтверждается.");
        frame.render_widget(
            Paragraph::new(scope)
                .wrap(Wrap { trim: true })
                .block(tui_widgets::section(" Обзор ", false)),
            layout[0],
        );
        let panels = if area.width >= 86 {
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(layout[1])
        } else {
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(layout[1])
        };
        let max = self
            .history
            .iter()
            .flat_map(|v| v.iter().copied())
            .max()
            .unwrap_or(0)
            .max(1);
        for (i, panel) in panels.iter().copied().enumerate() {
            let color = if i == 0 {
                ACCENT
            } else {
                Color::Rgb(170, 180, 250)
            };
            let title = if i == 0 {
                " H2 · TCP "
            } else {
                " H3 · QUIC "
            };
            let block = tui_widgets::section(title, i == 0);
            let inner = block.inner(panel);
            frame.render_widget(block, panel);
            let regions =
                Layout::vertical([Constraint::Length(4), Constraint::Min(1)]).split(inner);
            let s = self.current[i];
            let (up, down) = self.rate[i];
            let (up_rate, down_rate) = if self.history.is_empty() {
                ("ожидание".into(), "ожидание".into())
            } else {
                (format!("{} /с", bytes(up)), format!("{} /с", bytes(down)))
            };
            frame.render_widget(
                Paragraph::new(format!(
                    "Активно: {}  •  Всего: {}\n↑ Отправлено: {}  ·  {up_rate}\n↓ Получено: {}  ·  {down_rate}",
                    s.active,
                    s.opened,
                    bytes(s.upload),
                    bytes(s.download)
                ))
                .wrap(Wrap { trim: true }),
                regions[0],
            );
            let history: Vec<_> = self.history.iter().map(|sample| sample[i]).collect();
            if history.is_empty() || history.iter().all(|&v| v == 0) {
                let message = if history.is_empty() {
                    "Сбор первого измерения скорости…\nЗдесь появится история передачи данных."
                } else {
                    "В измеренных интервалах нет трафика.\nГрафик появится при передаче данных."
                };
                frame.render_widget(
                    Paragraph::new(message)
                        .wrap(Wrap { trim: true })
                        .block(tui_widgets::section(" Скорость передачи ", false))
                        .style(Style::default().fg(tui_widgets::MUTED)),
                    regions[1],
                );
                continue;
            }
            let chart = Sparkline::default()
                .data(&history)
                .max(max)
                .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
                .block(
                    Block::default()
                        .title(" ↑+↓ скорость · до 60 измерений ")
                        .borders(Borders::TOP)
                        .border_style(Style::default().fg(MUTED)),
                );
            frame.render_widget(chart, regions[1]);
        }
        let note = format!(
            "Общая шкала: {}  •  обновление 1 с  •  внешние сервисы не измеряются  •  Esc назад",
            if self.history.is_empty()
                || self
                    .history
                    .iter()
                    .all(|sample| sample.iter().all(|&v| v == 0))
            {
                "нет данных для графика".into()
            } else {
                format!("{} /с", bytes(max))
            }
        );
        frame.render_widget(
            Paragraph::new(note)
                .wrap(Wrap { trim: true })
                .style(Style::default().bg(SURFACE).fg(TEXT)),
            layout[2],
        );
    }

    pub(crate) fn body(&self) -> String {
        let mut result = String::from("Только трафик текущего процесса Theia; внешние сервисы не измеряются.\nДанные после открытия туннеля, без служебного трафика. Доставка не подтверждается.\n");
        for (i, s) in self.current.iter().enumerate() {
            let transport = if i == 0 { "H2" } else { "H3" };
            let (up, down) = self.rate[i];
            result.push_str(&format!(
                "\n{transport} • открыто сейчас: {} • всего туннелей: {}\n↑ {} ({})   ↓ {} ({})\n",
                s.active,
                s.opened,
                bytes(s.upload),
                if self.history.is_empty() {
                    "ожидание".into()
                } else {
                    format!("{} /с", bytes(up))
                },
                bytes(s.download),
                if self.history.is_empty() {
                    "ожидание".into()
                } else {
                    format!("{} /с", bytes(down))
                }
            ));
        }
        if self.history.is_empty() {
            result.push_str(
                "\nСбор первого интервала скорости; нулевой отсчёт не означает отсутствие трафика.",
            );
        }
        result.push_str("\nОбновление 1 с • Esc: назад");
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_two_directions_and_cancellation_without_leaking_active() {
        let c = Counters::new();
        {
            let a = c.enter();
            let b = c.enter();
            a.upload(12);
            b.download(23);
            assert_eq!(
                c.snapshot(),
                Snapshot {
                    active: 2,
                    opened: 2,
                    upload: 12,
                    download: 23
                }
            );
            drop(a);
            assert_eq!(c.snapshot().active, 1);
        }
        assert_eq!(
            c.snapshot(),
            Snapshot {
                active: 0,
                opened: 2,
                upload: 12,
                download: 23
            }
        );
    }
    #[test]
    fn history_is_bounded_and_waits_for_first_sample() {
        let mut monitor = Monitor::new(Role::Client);
        assert!(monitor.history.is_empty());
        for _ in 0..80 {
            monitor.sampled -= std::time::Duration::from_secs(1);
            monitor.poll();
        }
        assert_eq!(monitor.history.len(), 60);
    }

    #[test]
    fn dashboard_renders_both_transports_at_compact_and_wide_sizes() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut monitor = Monitor::new(Role::Server);
        monitor.current = [
            Snapshot {
                active: 2,
                opened: 10,
                upload: 1024 * 1024,
                download: 1024,
            },
            Snapshot {
                active: 3,
                opened: 20,
                upload: 1024 * 1024 * 1024,
                download: 123,
            },
        ];
        for sampled in [false, true] {
            if sampled {
                monitor.rate = [(1024, 2048), (4096, 8192)];
                monitor.history.push_back([0, 0]);
                monitor.history.push_back([3072, 12288]);
            }
            for (w, h) in [(120, 32), (70, 36), (60, 18)] {
                let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
                terminal
                    .draw(|frame| {
                        let area = frame.area();
                        monitor.render(frame, area);
                    })
                    .unwrap();
                let buffer = terminal.backend().buffer();
                let screen = buffer
                    .content
                    .iter()
                    .map(|cell| cell.symbol())
                    .collect::<String>();
                assert!(screen.contains("H2"), "{w}x{h}");
                assert!(screen.contains("H3"), "{w}x{h}");
                assert!(screen.contains("МиБ"));
                assert!(screen.contains("ГиБ"));
                if w >= 70 {
                    assert!(screen.contains("Активные туннели: 5"));
                    assert!(screen.contains("Всего открыто: 30"));
                    assert!(screen.contains("Общая шкала"));
                    if sampled {
                        assert!(screen.contains("12.0 КиБ"));
                    } else {
                        assert!(screen.contains("Сбор первого измерения"));
                    }
                }
            }
        }
        assert_eq!(bytes(123), "123 Б");
        assert_eq!(bytes(1024 * 1024), "1.00 МиБ");
        assert_eq!(bytes(1024 * 1024 * 1024), "1.00 ГиБ");
    }

    #[test]
    fn idle_monitor_distinguishes_unsampled_and_measured_zero() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut monitor = Monitor::new(Role::Client);
        for sampled in [false, true] {
            if sampled {
                monitor.history.push_back([0, 0]);
            }
            let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    monitor.render(frame, area);
                })
                .unwrap();
            let screen: String = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(screen.contains(if sampled {
                "В измеренных интервалах нет трафика"
            } else {
                "Сбор первого измерения"
            }));
        }
    }

    #[test]
    fn monitor_has_two_transports_and_truthful_scope() {
        let mut m = Monitor::new(Role::Client);
        m.poll();
        let body = m.body();
        assert!(body.contains("H2") && body.contains("H3"));
        assert!(body.contains("внешние сервисы не измеряются"));
        assert_eq!(bytes(1024), "1.0 КиБ");
    }
}
