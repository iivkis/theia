//! Stateless presentation controls. Input and confirmation ownership stay
//! with each workflow. A hit-test returns only a field ID, never a command.
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

// One restrained, terminal-independent dark palette. Colour is supplementary:
// focus, warning, selected and disabled states also have textual markers.
pub(crate) const BG: Color = Color::Rgb(17, 22, 30);
pub(crate) const SURFACE: Color = Color::Rgb(27, 34, 46);
pub(crate) const INPUT: Color = Color::Rgb(42, 53, 70);
pub(crate) const FOCUS: Color = Color::Rgb(39, 76, 82);
pub(crate) const TEXT: Color = Color::Rgb(224, 231, 239);
pub(crate) const MUTED: Color = Color::Rgb(158, 173, 190);
pub(crate) const ACCENT: Color = Color::Rgb(121, 219, 184);
pub(crate) const WARNING: Color = Color::Rgb(244, 194, 118);
pub(crate) const ERROR: Color = Color::Rgb(255, 146, 152);

pub(crate) fn canvas(frame: &mut Frame<'_>, area: Rect) {
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default().style(Style::default().fg(TEXT).bg(BG)),
        area,
    );
}

/// A flat section with an inset header, preserving the traditional one-cell
/// inner geometry used by lists and tables. No visible rectangular outline.
pub(crate) fn section(title: &str, active: bool) -> Block<'_> {
    Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(if active { ACCENT } else { MUTED })
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BG).bg(BG))
        .style(Style::default().fg(TEXT).bg(BG))
}

/// Reports share semantic title and key styling without interpreting their
/// contents as commands. In particular, an invitation can never trigger an action.
pub(crate) fn report_section(title: &str, active: bool) -> Block<'_> {
    let lower = title.to_lowercase();
    let color = if lower.contains("ошибка")
        || lower.contains("не удалось")
        || lower.contains("не выполнен")
        || lower.contains("заблокирована")
        || lower.contains("не подтверждён")
    {
        ERROR
    } else if lower.contains("подтверждение")
        || lower.contains("секрет")
        || lower.contains("не сохранено")
    {
        WARNING
    } else if active {
        ACCENT
    } else {
        MUTED
    };
    Block::default()
        .title(Span::styled(
            title,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BG).bg(BG))
        .style(Style::default().fg(TEXT).bg(BG))
}

pub(crate) fn report_row<'a>(value: &'a str, style: Style, first: bool) -> Line<'a> {
    if first {
        if let Some((key, rest)) = value.split_once(':') {
            if matches!(
                key,
                "Enter"
                    | "Esc"
                    | "Enter/Esc"
                    | "y"
                    | "n/Esc"
                    | "r"
                    | "s"
                    | "d"
                    | "x"
                    | "c"
                    | "f"
                    | "Q"
                    | "F2"
                    | "F3"
                    | "Ctrl+R"
            ) {
                let color = if key == "y" { WARNING } else { TEXT };
                return Line::from(vec![
                    Span::styled(
                        key,
                        Style::default()
                            .fg(color)
                            .bg(INPUT)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(":", style),
                    Span::styled(rest, style),
                ]);
            }
        }
    }
    Line::styled(value, style)
}

pub(crate) fn key_line(keys: &str) -> Line<'_> {
    let mut spans = Vec::new();
    for (i, part) in keys.split(" · ").enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, label) = part.split_once(' ').unwrap_or((part, ""));
        let key = key.trim_end_matches(':');
        let primary = matches!(key, "Enter" | "Y" | "y");
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default()
                .fg(if primary { BG } else { TEXT })
                .bg(if primary { ACCENT } else { INPUT })
                .add_modifier(Modifier::BOLD),
        ));
        if !label.is_empty() {
            spans.push(Span::styled(format!(" {label}"), Style::default().fg(TEXT)));
        }
    }
    Line::from(spans)
}

pub(crate) struct Field {
    pub id: usize,
    pub label: &'static str,
    pub value: String,
    pub hint: &'static str,
}

pub(crate) struct Form {
    pub fields: Vec<Field>,
    pub selected: usize,
    pub lead: String,
    pub error: String,
}

struct Geometry {
    title: Rect,
    lead: Rect,
    rows: Rect,
    help: Rect,
    stride: u16,
    start: usize,
    end: usize,
}

impl Form {
    fn geometry(&self, area: Rect) -> Geometry {
        let count = self.fields.len();
        let margin = u16::from(area.width >= 36);
        let inner = Rect::new(
            area.x.saturating_add(margin),
            area.y,
            area.width.saturating_sub(2 * margin),
            area.height,
        );
        let title_h = u16::from(inner.height >= 3);
        let lead_h = if self.lead.is_empty() || inner.height < 5 {
            0
        } else if inner.height >= 9 {
            2
        } else {
            1
        };
        let side = inner.width >= 96 && inner.height >= 12;
        let help_h = if side {
            0
        } else if !self.error.is_empty() && inner.height >= 3 {
            if inner.height >= 8 {
                3
            } else {
                1
            }
        } else if inner.height < 6 {
            0
        } else if inner.height >= 10 {
            3
        } else {
            1
        };
        let room = inner.height.saturating_sub(title_h + lead_h + help_h);
        let stride = if usize::from(room) >= count.saturating_mul(3) && inner.width >= 42 {
            3
        } else if room >= 2 && inner.width >= 42 {
            2
        } else {
            1
        };
        let capacity = usize::from(room / stride);
        let selected = self
            .fields
            .iter()
            .position(|f| f.id == self.selected)
            .unwrap_or(0);
        let start = selected
            .saturating_sub(capacity.saturating_sub(1))
            .min(count.saturating_sub(capacity));
        let end = (start + capacity).min(count);
        let title = Rect::new(inner.x, inner.y, inner.width, title_h);
        let lead = Rect::new(inner.x, title.bottom(), inner.width, lead_h);
        let rows_width = if side {
            inner.width.saturating_sub(34).min(80)
        } else {
            inner.width
        };
        let rows = Rect::new(
            inner.x,
            lead.bottom(),
            rows_width,
            (end - start) as u16 * stride,
        );
        let help = if side {
            Rect::new(rows.right().saturating_add(3), rows.y, 31, room.min(12))
        } else {
            Rect::new(inner.x, rows.bottom(), inner.width, help_h)
        };
        Geometry {
            title,
            lead,
            rows,
            help,
            stride,
            start,
            end,
        }
    }

    pub(crate) fn hit(&self, area: Rect, x: u16, y: u16) -> Option<usize> {
        let g = self.geometry(area);
        if x < g.rows.x || x >= g.rows.right() || y < g.rows.y || y >= g.rows.bottom() {
            return None;
        }
        let index = g.start + usize::from((y - g.rows.y) / g.stride);
        if index >= g.end {
            return None;
        }
        self.fields.get(index).map(|f| f.id)
    }

    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect, title: &str) {
        self.render_as(frame, area, title, false);
    }

    pub(crate) fn render_picker(&self, frame: &mut Frame<'_>, area: Rect, title: &str) {
        self.render_as(frame, area, title, true);
    }

    fn render_as(&self, frame: &mut Frame<'_>, area: Rect, title: &str, picker: bool) {
        canvas(frame, area);
        let g = self.geometry(area);
        let title = if g.end - g.start < self.fields.len() {
            format!(
                "{title}  ·  {}–{}/{}",
                g.start + 1,
                g.end,
                self.fields.len()
            )
        } else {
            title.to_owned()
        };
        frame.render_widget(
            Paragraph::new(title).style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            g.title,
        );
        if g.lead.height > 0 {
            frame.render_widget(
                Paragraph::new(self.lead.as_str())
                    .style(Style::default().fg(MUTED))
                    .wrap(Wrap { trim: true }),
                g.lead,
            );
        }
        for (offset, field) in self.fields[g.start..g.end].iter().enumerate() {
            let selected = field.id == self.selected;
            let rect = Rect::new(
                g.rows.x,
                g.rows.y + (offset as u16) * g.stride,
                g.rows.width,
                g.stride,
            );
            let marker = if selected { "▎ " } else { "  " };
            let label = if picker && !field.label.starts_with('[') {
                format!(
                    "{marker}{}  {}",
                    if selected { "●" } else { "○" },
                    field.label
                )
            } else {
                format!("{marker}{}", field.label)
            };
            let value = if field.value.is_empty() {
                if picker {
                    "Выбрать"
                } else {
                    "Введите значение"
                }
            } else {
                field.value.as_str()
            };
            let label_style = Style::default()
                .fg(if selected { ACCENT } else { TEXT })
                .add_modifier(Modifier::BOLD);
            let value_style = Style::default()
                .fg(if field.value.is_empty() || picker {
                    MUTED
                } else {
                    TEXT
                })
                .bg(if selected {
                    FOCUS
                } else if picker {
                    BG
                } else {
                    INPUT
                });
            if picker && g.stride >= 2 {
                let style = label_style.bg(if selected { FOCUS } else { SURFACE });
                frame.render_widget(
                    Paragraph::new(label).style(style),
                    Rect::new(rect.x, rect.y, rect.width, 1),
                );
                frame.render_widget(
                    Paragraph::new(format!(
                        "  {}",
                        fit_value(value, rect.width.saturating_sub(2), false)
                    ))
                    .style(value_style),
                    Rect::new(rect.x, rect.y + 1, rect.width, 1),
                );
                continue;
            }
            if g.stride >= 2 {
                frame.render_widget(
                    Paragraph::new(label).style(label_style),
                    Rect::new(rect.x, rect.y, rect.width, 1),
                );
                let input = Rect::new(
                    rect.x.saturating_add(2),
                    rect.y + 1,
                    rect.width.saturating_sub(4),
                    1,
                );
                let shown = fit_value(value, input.width.saturating_sub(3), selected);
                let content = if selected && !picker {
                    format!(" {shown} ▏")
                } else {
                    format!(" {shown}")
                };
                frame.render_widget(Paragraph::new(content).style(value_style), input);
            } else {
                let label_width = rect.width / 2;
                let columns =
                    Layout::horizontal([Constraint::Length(label_width), Constraint::Min(0)])
                        .split(rect);
                frame.render_widget(Paragraph::new(label).style(label_style), columns[0]);
                frame.render_widget(
                    Paragraph::new(fit_value(value, columns[1].width, selected)).style(value_style),
                    columns[1],
                );
            }
        }
        let field = self.fields.iter().find(|f| f.id == self.selected);
        let hint = field.map_or("Выберите строку стрелками или мышью.", |f| f.hint);
        let (message, color) = if self.error.is_empty() {
            (hint, MUTED)
        } else {
            (self.error.as_str(), ERROR)
        };
        if g.help.height > 0 {
            if g.help.x >= g.rows.right() {
                let label = if self.error.is_empty() {
                    "ПОДСКАЗКА"
                } else {
                    "ПРОВЕРЬТЕ ПОЛЕ"
                };
                let lines = vec![
                    Line::styled(
                        label,
                        Style::default()
                            .fg(if self.error.is_empty() { ACCENT } else { ERROR })
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::raw(""),
                    Line::styled(
                        field.map_or("", |f| f.label),
                        Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
                    ),
                    Line::styled(message, Style::default().fg(color)),
                ];
                frame.render_widget(
                    Paragraph::new(lines)
                        .style(Style::default().bg(SURFACE))
                        .wrap(Wrap { trim: true }),
                    g.help,
                );
            } else {
                frame.render_widget(
                    Paragraph::new(message)
                        .style(Style::default().fg(color).bg(SURFACE))
                        .wrap(Wrap { trim: true }),
                    g.help,
                );
            }
        }
    }
}

/// Read-only confirmation data, separate from the operation and its approval.
/// Every candidate is shown, including those not selected by the existing plan.
#[derive(Clone)]
pub(crate) struct ReferenceRow {
    pub name: String,
    pub address: String,
    pub score: u8,
    pub h2: bool,
    pub h3: bool,
    pub selected: Option<usize>,
}

pub(crate) struct ReferenceReview {
    pub rows: Vec<ReferenceRow>,
    pub details: Vec<(&'static str, String)>,
    pub note: String,
}

impl ReferenceReview {
    pub(crate) fn lines(&self, width: u16) -> Vec<Line<'static>> {
        let mut lines = vec![Line::styled(
            "Результаты проверки",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )];
        let wide = width >= 96;
        if wide {
            lines.push(Line::styled(
                format!(
                    "{:<30} {:<25} {:<13} {}",
                    "Референс", "Адрес", "H2 / H3", "Результат"
                ),
                Style::default().fg(MUTED),
            ));
        }
        for row in &self.rows {
            let status = match row.selected {
                Some(0) => "Основной".into(),
                Some(index) => format!("Резерв {index}"),
                None => "Исключён".into(),
            };
            let color = if row.selected == Some(0) {
                ACCENT
            } else if row.selected.is_some() {
                WARNING
            } else {
                ERROR
            };
            let transports = format!(
                "{} H2  {} H3",
                if row.h2 { "✓" } else { "×" },
                if row.h3 { "✓" } else { "×" }
            );
            // Long names and IPv6 addresses must remain visible, not elided.
            if wide && Span::raw(row.name.as_str()).width() <= 28 && row.address.len() <= 23 {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{:<30} {:<25} ", row.name, row.address),
                        Style::default().fg(TEXT),
                    ),
                    Span::styled(format!("{transports:<13} "), Style::default().fg(MUTED)),
                    Span::styled(
                        format!("{status} · {}", row.score),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                ]));
            } else {
                append_wrapped(
                    &mut lines,
                    &row.name,
                    width,
                    Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
                );
                append_wrapped(
                    &mut lines,
                    &format!("  {}", row.address),
                    width,
                    Style::default().fg(MUTED),
                );
                append_wrapped(
                    &mut lines,
                    &format!("  {transports} · {status} · {}", row.score),
                    width,
                    Style::default().fg(color),
                );
            }
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "Конфигурация к сохранению",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
        for (label, value) in &self.details {
            if wide && Span::raw(value.as_str()).width() + 24 <= usize::from(width) {
                lines.push(Line::from(vec![
                    Span::styled(format!("{label:<24}"), Style::default().fg(MUTED)),
                    Span::styled(value.clone(), Style::default().fg(TEXT)),
                ]));
            } else {
                lines.push(Line::styled(*label, Style::default().fg(MUTED)));
                append_wrapped(&mut lines, value, width, Style::default().fg(TEXT));
            }
        }
        lines.push(Line::raw(""));
        append_wrapped(&mut lines, &self.note, width, Style::default().fg(WARNING));
        lines
    }
}

/// Wrap by terminal-cell width, never hide confirmation details behind ellipses.
fn append_wrapped(lines: &mut Vec<Line<'static>>, text: &str, width: u16, style: Style) {
    let width = usize::from(width.max(1));
    for paragraph in text.split('\n') {
        let mut row = String::new();
        let mut used = 0;
        for c in paragraph.chars() {
            let c = if c.is_control() { '�' } else { c };
            let mut buf = [0; 4];
            let encoded: &str = c.encode_utf8(&mut buf);
            let cells = Span::raw(encoded).width();
            if !row.is_empty() && used + cells > width {
                lines.push(Line::styled(std::mem::take(&mut row), style));
                used = 0;
            }
            row.push(c);
            used += cells;
        }
        lines.push(Line::styled(row, style));
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ActionItem {
    pub key: char,
    pub label: &'static str,
}

/// The selected action is only a navigation choice. Owners must dispatch
/// through their existing key handlers, including all confirmation gates.
pub(crate) struct Actions<'a> {
    pub items: &'a [ActionItem],
    pub selected: usize,
}
impl Actions<'_> {
    fn start(&self, area: Rect) -> usize {
        let rows = usize::from(area.height.saturating_sub(2)).max(1);
        self.selected
            .min(self.items.len().saturating_sub(1))
            .saturating_sub(rows.saturating_sub(1))
            .min(self.items.len().saturating_sub(rows))
    }
    pub(crate) fn hit(&self, area: Rect, x: u16, y: u16) -> Option<usize> {
        if x <= area.x
            || x >= area.right().saturating_sub(1)
            || y <= area.y
            || y >= area.bottom().saturating_sub(1)
        {
            return None;
        }
        let i = self.start(area) + usize::from(y - area.y - 1);
        (i < self.items.len()).then_some(i)
    }
    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        self.render_with_focus(frame, area, true);
    }

    pub(crate) fn render_with_focus(&self, frame: &mut Frame<'_>, area: Rect, focused: bool) {
        use ratatui::widgets::{List, ListItem};
        canvas(frame, area);
        let selected = self.selected.min(self.items.len().saturating_sub(1));
        let rows = usize::from(area.height.saturating_sub(2));
        let items = self
            .items
            .iter()
            .enumerate()
            .skip(self.start(area))
            .take(rows)
            .map(|(i, item)| {
                let active = focused && i == selected;
                let style = if active {
                    Style::default()
                        .fg(ACCENT)
                        .bg(FOCUS)
                        .add_modifier(Modifier::BOLD)
                } else if i == selected {
                    Style::default().fg(TEXT).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(TEXT)
                };
                // Named actions are primary. Shortcuts remain available in
                // F1/F2, not repeated next to every visible action.
                let label = fit_value(item.label, area.width.saturating_sub(5), false);
                ListItem::new(Line::from(vec![
                    Span::raw(if active {
                        " › "
                    } else if i == selected {
                        " · "
                    } else {
                        "   "
                    }),
                    Span::raw(label),
                ]))
                .style(style)
            })
            .collect::<Vec<_>>();
        frame.render_widget(
            List::new(items).block(section(
                if focused {
                    " Действия "
                } else {
                    " Действия "
                },
                focused,
            )),
            area,
        );
    }
}

/// Shared confirmation choices: a pointer or an arrow selects, only Enter
/// dispatches through the owning workflow. Keep the negative choice first.
pub(crate) fn confirmation_bar(frame: &mut Frame<'_>, area: Rect, heading: &str, error: bool,
    confirm: &str, selected: bool) {
    canvas(frame, area);
    if area.height == 0 { return; }
    let heading = fit_value(heading, area.width, false);
    frame.render_widget(Paragraph::new(heading).style(Style::default().fg(if error { ERROR } else { MUTED })),
        Rect::new(area.x, area.y, area.width, 1));
    if area.height < 2 { return; }
    let half = area.width / 2;
    for (i, (label, x, width)) in [("Отменить", area.x, half), (confirm, area.x + half, area.width - half)].into_iter().enumerate() {
        let active = (i == 1) == selected;
        let shown = fit_value(label, width.saturating_sub(2), false);
        frame.render_widget(Paragraph::new(format!("{} {shown}", if active { "›" } else { " " }))
            .style(Style::default().fg(if active { ACCENT } else { TEXT })
                .bg(if active { FOCUS } else { BG })),
            Rect::new(x, area.bottom() - 1, width, 1));
    }
}

pub(crate) fn action_layout(area: Rect, count: usize) -> Option<[Rect; 2]> {
    if count == 0 || area.height < 8 { return None; }
    let height = (count as u16).saturating_add(2).min(area.height / 2).max(3);
    let content_height = (area.height - height).min(22);
    let report = Rect::new(area.x, area.y, area.width, content_height);
    let controls = Rect::new(area.x, report.bottom(), area.width, height);
    Some([report, controls])
}

pub(crate) fn action_key(
    items: &[ActionItem],
    focus: &mut usize,
    code: crossterm::event::KeyCode,
) -> Option<crossterm::event::KeyCode> {
    use crossterm::event::KeyCode;
    if items.is_empty() {
        return Some(code);
    }
    *focus = (*focus).min(items.len() - 1);
    match code {
        KeyCode::Up | KeyCode::BackTab => {
            *focus = focus.saturating_sub(1);
            None
        }
        KeyCode::Down | KeyCode::Tab => {
            *focus = (*focus + 1).min(items.len() - 1);
            None
        }
        KeyCode::Home => {
            *focus = 0;
            None
        }
        KeyCode::End => {
            *focus = items.len() - 1;
            None
        }
        KeyCode::Enter => Some(KeyCode::Char(items[*focus].key)),
        other => Some(other),
    }
}

/// Keep the typed end visible for long inputs without splitting Unicode.
pub(crate) fn fit_value(value: &str, width: u16, tail: bool) -> String {
    let clean: String = value
        .chars()
        .map(|c| if c.is_control() { '�' } else { c })
        .collect();
    let width = usize::from(width);
    if Span::raw(clean.as_str()).width() <= width {
        return clean;
    }
    if width <= 1 {
        return "…".chars().take(width).collect();
    }
    let mut used = 1;
    let mut out = Vec::new();
    let mut add = |c: char| {
        let mut encoded = [0; 4];
        let encoded: &str = c.encode_utf8(&mut encoded);
        let w = Span::raw(encoded).width();
        if used + w > width {
            return false;
        }
        used += w;
        out.push(c);
        true
    };
    if tail {
        for c in clean.chars().rev() {
            if !add(c) {
                break;
            }
        }
        out.reverse();
        out.insert(0, '…');
    } else {
        for c in clean.chars() {
            if !add(c) {
                break;
            }
        }
        out.push('…');
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};
    #[test]
    fn inactive_action_list_has_no_active_focus_background() {
        let items = [ActionItem {
            key: 's',
            label: "Запустить сервер",
        }];
        let mut terminal = Terminal::new(TestBackend::new(42, 6)).unwrap();
        for focused in [false, true] {
            terminal
                .draw(|f| {
                    let area = f.area();
                    Actions {
                        items: &items,
                        selected: 0,
                    }
                    .render_with_focus(f, area, focused);
                })
                .unwrap();
            assert_eq!(
                terminal
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .any(|c| c.bg == FOCUS),
                focused
            );
        }
    }

    #[test]
    fn action_selection_matches_rendered_rows_and_enter_dispatches_only_one_key() {
        use crossterm::event::KeyCode;
        let items = [
            ActionItem {
                key: 's',
                label: "Запуск",
            },
            ActionItem {
                key: 'x',
                label: "Остановка",
            },
            ActionItem {
                key: 'r',
                label: "Обновить",
            },
        ];
        let mut focus = 0;
        assert_eq!(action_key(&items, &mut focus, KeyCode::Up), None);
        assert_eq!(focus, 0);
        assert_eq!(action_key(&items, &mut focus, KeyCode::Down), None);
        assert_eq!(focus, 1);
        assert_eq!(action_key(&items, &mut focus, KeyCode::End), None);
        assert_eq!(action_key(&items, &mut focus, KeyCode::Down), None);
        assert_eq!(focus, 2);
        assert_eq!(action_key(&items, &mut focus, KeyCode::Up), None);
        assert_eq!(focus, 1);
        assert_eq!(
            action_key(&items, &mut focus, KeyCode::Enter),
            Some(KeyCode::Char('x'))
        );
        assert_eq!(
            action_key(&[], &mut focus, KeyCode::Enter),
            Some(KeyCode::Enter)
        );
        for (w, h) in [(60, 12), (120, 30)] {
            let area = Rect::new(0, 0, w, h);
            let [_, controls] = action_layout(area, items.len()).unwrap();
            let actions = Actions {
                items: &items,
                selected: focus,
            };
            let first = actions.start(controls);
            assert_eq!(
                actions.hit(controls, controls.x + 1, controls.y + 1),
                Some(first)
            );
            assert_eq!(actions.hit(controls, controls.x, controls.y), None);
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|frame| actions.render(frame, controls)).unwrap();
            let screen = term
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(screen.contains("Остановка"));
        }
    }

    #[test]
    fn reference_review_keeps_rejected_rows_and_long_values_visible() {
        let review = ReferenceReview {
            rows: vec![
                ReferenceRow {
                    name: "example.org".into(),
                    address: "192.0.2.1:443".into(),
                    score: 100,
                    h2: true,
                    h3: true,
                    selected: Some(0),
                },
                ReferenceRow {
                    name: "backup.example.org".into(),
                    address: "192.0.2.2:443".into(),
                    score: 80,
                    h2: true,
                    h3: false,
                    selected: Some(1),
                },
                ReferenceRow {
                    name: "failed.example.org".into(),
                    address: "192.0.2.3:443".into(),
                    score: 0,
                    h2: false,
                    h3: false,
                    selected: None,
                },
            ],
            details: vec![("TOML", "a".repeat(150))],
            note: "Сервер не запускается.".into(),
        };
        for width in [32, 80, 120] {
            let lines = review.lines(width);
            assert!(lines.iter().all(|l| l.width() <= usize::from(width)));
            let text = lines
                .iter()
                .flat_map(|l| l.spans.iter())
                .map(|s| s.content.as_ref())
                .collect::<String>();
            for expected in [
                "example.org",
                "Основной",
                "Резерв 1",
                "Исключён",
                "100",
                "80",
                "Сервер не запускается.",
            ] {
                assert!(text.contains(expected), "{expected}");
            }
            assert!(text.contains(&"a".repeat(150)));
        }
    }

    #[test]
    fn large_terminal_forms_keep_help_near_fields_and_labels_visible() {
        let form = Form {
            fields: vec![
                Field {
                    id: 1,
                    label: "Порт TCP/UDP",
                    value: "443".into(),
                    hint: "Порт сервера.",
                },
                Field {
                    id: 2,
                    label: "Адрес",
                    value: String::new(),
                    hint: "Введите домен.",
                },
                Field {
                    id: 3,
                    label: "Пользователь",
                    value: String::new(),
                    hint: "ID пользователя.",
                },
            ],
            selected: 1,
            lead: "Настройка сервера".into(),
            error: String::new(),
        };
        for (w, h) in [(80, 60), (132, 65), (240, 90)] {
            let area = Rect::new(0, 0, w, h);
            let geometry = form.geometry(area);
            assert!(geometry.rows.height <= 9);
            assert!(geometry.help.y <= geometry.rows.bottom());
            assert_eq!(form.hit(area, geometry.rows.x, geometry.rows.y), Some(1));
            assert_eq!(
                form.hit(area, geometry.rows.x, geometry.rows.bottom()),
                None
            );
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|frame| form.render(frame, area, "Параметры"))
                .unwrap();
            let buffer = term.backend().buffer();
            let screen = buffer
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(screen.contains("Порт TCP/UDP"));
            assert!(screen.contains("443"));
            assert!(screen.contains("Порт сервера."));
            assert!(!screen.contains("┌") && !screen.contains("┐"));
            assert!(buffer.content().iter().all(|c| c.bg != Color::Cyan));
        }
    }

    #[test]
    fn controls_keep_focus_and_hit_regions_in_sync() {
        let form = Form {
            fields: (0..7)
                .map(|id| Field {
                    id,
                    label: "Поле",
                    value: format!("value-{id}"),
                    hint: "Подсказка",
                })
                .collect(),
            selected: 6,
            lead: "Настройка".into(),
            error: String::new(),
        };
        for (w, h) in [(32, 4), (60, 12), (100, 30)] {
            let area = Rect::new(0, 0, w, h);
            let g = form.geometry(area);
            assert!(g.start <= 6 && 6 < g.end);
            assert_eq!(
                form.hit(area, g.rows.x, g.rows.y + (6 - g.start) as u16 * g.stride),
                Some(6)
            );
            assert_eq!(form.hit(area, 0, 0), None);
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| form.render(f, area, "Параметры")).unwrap();
            let screen = term
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(screen.contains("value-6"));
        }
        assert_eq!(fit_value("abcdef", 4, true), "…def");
        assert_eq!(fit_value("abcdef", 4, false), "abc…");
        assert_eq!(fit_value("a\nb", 8, false), "a�b");
    }
}
