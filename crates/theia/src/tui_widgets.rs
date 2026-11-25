//! Stateless presentation controls. Input and confirmation ownership stay
//! with each workflow. A hit-test returns only a field ID, never a command.
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

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
    lead: Rect,
    rows: Rect,
    help: Rect,
    stride: u16,
    start: usize,
    end: usize,
}

impl Form {
    fn geometry(&self, area: Rect) -> Geometry {
        let inner = Rect::new(
            area.x.saturating_add(1), area.y.saturating_add(1),
            area.width.saturating_sub(2), area.height.saturating_sub(2),
        );
        let lead = if inner.height >= 10 && !self.lead.is_empty() { 2 } else { 0 };
        let help = if inner.height >= 7 { 3 } else if inner.height >= 3 { 1 } else { 0 };
        let parts = Layout::vertical([
            Constraint::Length(lead), Constraint::Min(0), Constraint::Length(help),
        ]).split(inner);
        let count = self.fields.len();
        let stride = if parts[1].height as usize >= count.saturating_mul(3) && parts[1].width >= 42 {
            3
        } else if parts[1].height as usize >= count.saturating_mul(2) {
            2
        } else {
            1
        };
        let capacity = usize::from(parts[1].height / stride);
        let selected = self.fields.iter().position(|f| f.id == self.selected).unwrap_or(0);
        let start = selected.saturating_sub(capacity.saturating_sub(1)).min(count.saturating_sub(capacity));
        Geometry { lead: parts[0], rows: parts[1], help: parts[2], stride, start, end: (start + capacity).min(count) }
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
        let g = self.geometry(area);
        let title = if g.end - g.start < self.fields.len() {
            format!("{title} · {}/{}", g.end, self.fields.len())
        } else { title.to_owned() };
        frame.render_widget(Block::default().title(title).borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)), area);
        if g.lead.height > 0 {
            frame.render_widget(Paragraph::new(self.lead.as_str()).wrap(Wrap { trim: true }), g.lead);
        }
        for (offset, field) in self.fields[g.start..g.end].iter().enumerate() {
            let selected = field.id == self.selected;
            let rect = Rect::new(g.rows.x, g.rows.y + (offset as u16) * g.stride, g.rows.width, g.stride);
            let accent = if selected { Color::Cyan } else { Color::DarkGray };
            let marker = if selected { "› " } else { "  " };
            let label = format!("{marker}{}", field.label);
            let value = if field.value.is_empty() { "Не заполнено" } else { field.value.as_str() };
            let style = if selected { Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD) }
                else if field.value.is_empty() { Style::default().fg(Color::DarkGray) } else { Style::default() };
            if g.stride == 3 {
                let shown = fit_value(value, rect.width.saturating_sub(2), selected);
                frame.render_widget(Paragraph::new(shown).style(style).block(
                    Block::default().title(label).borders(Borders::ALL).border_style(Style::default().fg(accent))
                ), rect);
            } else if g.stride == 2 {
                let shown = fit_value(value, rect.width.saturating_sub(2), selected);
                frame.render_widget(Paragraph::new(vec![
                    Line::styled(label, Style::default().fg(accent).add_modifier(Modifier::BOLD)),
                    Line::styled(format!("  {shown}"), style),
                ]), rect);
            } else {
                let label_width = rect.width / 2;
                let columns = Layout::horizontal([Constraint::Length(label_width), Constraint::Min(0)]).split(rect);
                frame.render_widget(Paragraph::new(label).style(Style::default().fg(accent)), columns[0]);
                frame.render_widget(Paragraph::new(fit_value(value, columns[1].width, selected)).style(style), columns[1]);
            }
        }
        let hint = self.fields.iter().find(|f| f.id == self.selected).map_or("", |f| f.hint);
        let (message, style) = if self.error.is_empty() {
            (hint, Style::default().fg(Color::Gray))
        } else {
            (self.error.as_str(), Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD))
        };
        frame.render_widget(Paragraph::new(message).style(style).wrap(Wrap { trim: true }), g.help);
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
        let w = Span::raw(&*c.encode_utf8(&mut encoded)).width();
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
