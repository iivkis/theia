//! Stateless presentation controls. Input and confirmation ownership stay
//! with each workflow. A hit-test returns only a field ID, never a command.
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

// One restrained, terminal-independent dark palette. Colour is supplementary:
// focus, warning, selected and disabled states also have textual markers.
pub(crate) const BG: Color = Color::Rgb(19, 23, 31);
pub(crate) const SURFACE: Color = Color::Rgb(30, 37, 48);
pub(crate) const INPUT: Color = Color::Rgb(40, 49, 63);
pub(crate) const FOCUS: Color = Color::Rgb(46, 65, 70);
pub(crate) const TEXT: Color = Color::Rgb(224, 231, 239);
pub(crate) const MUTED: Color = Color::Rgb(158, 173, 190);
pub(crate) const ACCENT: Color = Color::Rgb(121, 219, 184);
pub(crate) const WARNING: Color = Color::Rgb(244, 194, 118);
pub(crate) const ERROR: Color = Color::Rgb(255, 146, 152);

pub(crate) fn canvas(frame: &mut Frame<'_>, area: Rect) {
    frame.render_widget(Block::default().style(Style::default().fg(TEXT).bg(BG)), area);
}

/// A flat section with an inset header, preserving the traditional one-cell
/// inner geometry used by lists and tables. No visible rectangular outline.
pub(crate) fn section(title: &str, active: bool) -> Block<'_> {
    Block::default()
        .title(Span::styled(title, Style::default().fg(if active { ACCENT } else { MUTED }).add_modifier(Modifier::BOLD)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SURFACE).bg(SURFACE))
        .style(Style::default().fg(TEXT).bg(SURFACE))
}

pub(crate) fn key_line(keys: &str) -> Line<'_> {
    let mut spans = Vec::new();
    for (i, part) in keys.split(" · ").enumerate() {
        if i > 0 { spans.push(Span::raw("  ")); }
        let (key, label) = part.split_once(' ').unwrap_or((part, ""));
        spans.push(Span::styled(format!(" {key} "), Style::default().fg(BG).bg(MUTED).add_modifier(Modifier::BOLD)));
        if !label.is_empty() { spans.push(Span::styled(format!(" {label}"), Style::default().fg(TEXT))); }
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
        let inner = Rect::new(area.x.saturating_add(margin), area.y,
            area.width.saturating_sub(2 * margin), area.height);
        let title_h = u16::from(inner.height >= 3);
        let lead_h = if self.lead.is_empty() || inner.height < 5 { 0 }
            else if inner.height >= 9 { 2 } else { 1 };
        let side = inner.width >= 96 && inner.height >= 12;
        let help_h = if side || inner.height < 6 { 0 } else if inner.height >= 10 { 3 } else { 1 };
        let room = inner.height.saturating_sub(title_h + lead_h + help_h);
        let stride = if usize::from(room) >= count.saturating_mul(3) && inner.width >= 42 { 3 }
            else if usize::from(room) >= count.saturating_mul(2) { 2 } else { 1 };
        let capacity = usize::from(room / stride);
        let selected = self.fields.iter().position(|f| f.id == self.selected).unwrap_or(0);
        let start = selected.saturating_sub(capacity.saturating_sub(1)).min(count.saturating_sub(capacity));
        let end = (start + capacity).min(count);
        let title = Rect::new(inner.x, inner.y, inner.width, title_h);
        let lead = Rect::new(inner.x, title.bottom(), inner.width, lead_h);
        let rows_width = if side { inner.width.saturating_sub(34) } else { inner.width };
        let rows = Rect::new(inner.x, lead.bottom(), rows_width, (end - start) as u16 * stride);
        let help = if side {
            Rect::new(rows.right().saturating_add(3), rows.y, 31, room.min(12))
        } else {
            Rect::new(inner.x, rows.bottom(), inner.width, help_h)
        };
        Geometry { title, lead, rows, help, stride, start, end }
    }

    pub(crate) fn hit(&self, area: Rect, x: u16, y: u16) -> Option<usize> {
        let g = self.geometry(area);
        if x < g.rows.x || x >= g.rows.right() || y < g.rows.y || y >= g.rows.bottom() {
            return None;
        }
        let index = g.start + usize::from((y - g.rows.y) / g.stride);
        if index >= g.end { return None; }
        self.fields.get(index).map(|f| f.id)
    }

    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect, title: &str) {
        canvas(frame, area);
        let g = self.geometry(area);
        let title = if g.end - g.start < self.fields.len() {
            format!("{title}  ·  {}–{}/{}", g.start + 1, g.end, self.fields.len())
        } else { title.to_owned() };
        frame.render_widget(Paragraph::new(title).style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)), g.title);
        if g.lead.height > 0 {
            frame.render_widget(Paragraph::new(self.lead.as_str()).style(Style::default().fg(MUTED)).wrap(Wrap { trim: true }), g.lead);
        }
        for (offset, field) in self.fields[g.start..g.end].iter().enumerate() {
            let selected = field.id == self.selected;
            let rect = Rect::new(g.rows.x, g.rows.y + (offset as u16) * g.stride, g.rows.width, g.stride);
            let marker = if selected { "▎ " } else { "  " };
            let label = format!("{marker}{}", field.label);
            let value = if field.value.is_empty() { "Введите значение" } else { field.value.as_str() };
            let label_style = Style::default().fg(if selected { ACCENT } else { TEXT }).add_modifier(Modifier::BOLD);
            let value_style = Style::default().fg(if field.value.is_empty() { MUTED } else { TEXT })
                .bg(if selected { FOCUS } else { INPUT });
            if g.stride >= 2 {
                frame.render_widget(Paragraph::new(label).style(label_style), Rect::new(rect.x, rect.y, rect.width, 1));
                let input = Rect::new(rect.x.saturating_add(2), rect.y + 1, rect.width.saturating_sub(4), 1);
                let shown = fit_value(value, input.width.saturating_sub(3), selected);
                let content = if selected { format!(" {shown} ▏") } else { format!(" {shown}") };
                frame.render_widget(Paragraph::new(content).style(value_style), input);
            } else {
                let label_width = rect.width / 2;
                let columns = Layout::horizontal([Constraint::Length(label_width), Constraint::Min(0)]).split(rect);
                frame.render_widget(Paragraph::new(label).style(label_style), columns[0]);
                frame.render_widget(Paragraph::new(fit_value(value, columns[1].width, selected)).style(value_style), columns[1]);
            }
        }
        let field = self.fields.iter().find(|f| f.id == self.selected);
        let hint = field.map_or("", |f| f.hint);
        let (message, color) = if self.error.is_empty() { (hint, MUTED) } else { (self.error.as_str(), ERROR) };
        if g.help.height > 0 {
            if g.help.x >= g.rows.right() {
                let label = if self.error.is_empty() { "ПОДСКАЗКА" } else { "ПРОВЕРЬТЕ ПОЛЕ" };
                let lines = vec![
                    Line::styled(label, Style::default().fg(if self.error.is_empty() { ACCENT } else { ERROR }).add_modifier(Modifier::BOLD)),
                    Line::raw(""),
                    Line::styled(field.map_or("", |f| f.label), Style::default().fg(TEXT).add_modifier(Modifier::BOLD)),
                    Line::styled(message, Style::default().fg(color)),
                ];
                frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), g.help);
            } else {
                frame.render_widget(Paragraph::new(message).style(Style::default().fg(color)).wrap(Wrap { trim: true }), g.help);
            }
        }
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
        self.selected.min(self.items.len().saturating_sub(1))
            .saturating_sub(rows.saturating_sub(1))
            .min(self.items.len().saturating_sub(rows))
    }
    pub(crate) fn hit(&self, area: Rect, x: u16, y: u16) -> Option<usize> {
        if x <= area.x || x >= area.right().saturating_sub(1)
            || y <= area.y || y >= area.bottom().saturating_sub(1) {
            return None;
        }
        let i = self.start(area) + usize::from(y - area.y - 1);
        (i < self.items.len()).then_some(i)
    }
    pub(crate) fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        use ratatui::widgets::{List, ListItem};
        let selected = self.selected.min(self.items.len().saturating_sub(1));
        let rows = usize::from(area.height.saturating_sub(2));
        let items = self.items.iter().enumerate().skip(self.start(area)).take(rows).map(|(i, item)| {
            let style = if i == selected {
                Style::default().fg(ACCENT).bg(FOCUS).add_modifier(Modifier::BOLD)
            } else { Style::default().fg(TEXT) };
            ListItem::new(format!("{} {}: {}", if i == selected { "›" } else { " " }, item.key, item.label)).style(style)
        }).collect::<Vec<_>>();
        frame.render_widget(List::new(items).block(
            section(" Действия · ↑↓ Enter ", true)
        ), area);
    }
}

pub(crate) fn action_layout(area: Rect, count: usize) -> Option<[Rect; 2]> {
    if count == 0 || area.height < 8 { return None; }
    if area.width >= 104 {
        let parts = Layout::horizontal([Constraint::Min(44), Constraint::Length(42)]).split(area);
        Some([parts[0], parts[1]])
    } else {
        let height = (count as u16).saturating_add(2).min(area.height / 2).max(3);
        let parts = Layout::vertical([Constraint::Min(4), Constraint::Length(height)]).split(area);
        Some([parts[0], parts[1]])
    }
}

pub(crate) fn action_key(items: &[ActionItem], focus: &mut usize, code: crossterm::event::KeyCode) -> Option<crossterm::event::KeyCode> {
    use crossterm::event::KeyCode;
    if items.is_empty() { return Some(code); }
    *focus = (*focus).min(items.len() - 1);
    match code {
        KeyCode::Up | KeyCode::BackTab => { *focus = (*focus + items.len() - 1) % items.len(); None }
        KeyCode::Down | KeyCode::Tab => { *focus = (*focus + 1) % items.len(); None }
        KeyCode::Home => { *focus = 0; None }
        KeyCode::End => { *focus = items.len() - 1; None }
        KeyCode::Enter => Some(KeyCode::Char(items[*focus].key)),
        other => Some(other),
    }
}

/// Keep the typed end visible for long inputs without splitting Unicode.
fn fit_value(value: &str, width: u16, tail: bool) -> String {
    let clean: String = value.chars().map(|c| if c.is_control() { '�' } else { c }).collect();
    let width = usize::from(width);
    if Span::raw(clean.as_str()).width() <= width { return clean; }
    if width <= 1 { return "…".chars().take(width).collect(); }
    let mut used = 1;
    let mut out = Vec::new();
    let mut add = |c: char| {
        let mut encoded = [0; 4];
        let encoded: &str = c.encode_utf8(&mut encoded);
        let w = Span::raw(encoded).width();
        if used + w > width { return false; }
        used += w;
        out.push(c);
        true
    };
    if tail {
        for c in clean.chars().rev() { if !add(c) { break; } }
        out.reverse();
        out.insert(0, '…');
    } else {
        for c in clean.chars() { if !add(c) { break; } }
        out.push('…');
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};
    #[test]
    fn action_selection_matches_rendered_rows_and_enter_dispatches_only_one_key() {
        use crossterm::event::KeyCode;
        let items = [ActionItem { key: 's', label: "Запуск" }, ActionItem { key: 'x', label: "Остановка" }, ActionItem { key: 'r', label: "Обновить" }];
        let mut focus = 0;
        assert_eq!(action_key(&items, &mut focus, KeyCode::Down), None);
        assert_eq!(focus, 1);
        assert_eq!(action_key(&items, &mut focus, KeyCode::Enter), Some(KeyCode::Char('x')));
        assert_eq!(action_key(&[], &mut focus, KeyCode::Enter), Some(KeyCode::Enter));
        for (w, h) in [(60, 12), (120, 30)] {
            let area = Rect::new(0, 0, w, h);
            let [_, controls] = action_layout(area, items.len()).unwrap();
            let actions = Actions { items: &items, selected: focus };
            let first = actions.start(controls);
            assert_eq!(actions.hit(controls, controls.x + 1, controls.y + 1), Some(first));
            assert_eq!(actions.hit(controls, controls.x, controls.y), None);
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|frame| actions.render(frame, controls)).unwrap();
            let screen = term.backend().buffer().content().iter().map(|c| c.symbol()).collect::<String>();
            assert!(screen.contains("Остановка"));
        }
    }

    #[test]
    fn controls_keep_focus_and_hit_regions_in_sync() {
        let form = Form {
            fields: (0..7).map(|id| Field { id, label: "Поле", value: format!("value-{id}"), hint: "Подсказка" }).collect(),
            selected: 6, lead: "Настройка".into(), error: String::new(),
        };
        for (w,h) in [(32,4),(60,12),(100,30)] {
            let area = Rect::new(0,0,w,h);
            let g = form.geometry(area);
            assert!(g.start <= 6 && 6 < g.end);
            assert_eq!(form.hit(area, g.rows.x, g.rows.y + (6-g.start) as u16*g.stride), Some(6));
            assert_eq!(form.hit(area, 0, 0), None);
            let mut term = Terminal::new(TestBackend::new(w,h)).unwrap();
            term.draw(|f| form.render(f, area, "Параметры")).unwrap();
            let screen = term.backend().buffer().content().iter().map(|c| c.symbol()).collect::<String>();
            assert!(screen.contains("value-6"));
        }
        assert_eq!(fit_value("abcdef", 4, true), "…def");
        assert_eq!(fit_value("abcdef", 4, false), "abc…");
        assert_eq!(fit_value("a\nb", 8, false), "a�b");
    }
}
