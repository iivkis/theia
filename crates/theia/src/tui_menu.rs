//! Discoverable, role-specific menu. Actions reuse the existing guarded forms.
use crate::Role;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Shortcut(KeyCode, KeyModifiers),
    Config,
    ServerProcess,
    Traffic,
    Close,
}
const fn key(c: char) -> Action {
    Action::Shortcut(KeyCode::Char(c), KeyModifiers::NONE)
}
const fn ctrl(c: char) -> Action {
    Action::Shortcut(KeyCode::Char(c), KeyModifiers::CONTROL)
}

#[derive(Clone, Copy)]
struct Entry {
    label: &'static str,
    action: Action,
    requires_config: bool,
}
const fn entry(label: &'static str, action: Action) -> Entry {
    Entry { label, action, requires_config: true }
}
const fn always(label: &'static str, action: Action) -> Entry {
    Entry { label, action, requires_config: false }
}
struct Group {
    title: &'static str,
    entries: &'static [Entry],
}
const SERVER: &[Group] = &[
    Group { title: "Сервер и состояние", entries: &[
        always("Запуск / остановка локального сервера", Action::ServerProcess),
        always("Статус работающего сервера / Apply / Rollback", key('v')),
        always("Монитор трафика этого процесса", Action::Traffic),
        always("Проверить готовность к перезапуску", key('R')),
    ]},
    Group { title: "Входящие подключения", entries: &[
        entry("Создать inbound: Own-TLS или REALITY", key('N')),
        entry("Изменить выбранное поле inbound", Action::Shortcut(KeyCode::Enter, KeyModifiers::NONE)),
        entry("Изменить сертификат / ключ Own-TLS", key('E')),
        entry("Назначить пользователей и права", key('G')),
        entry("Настроить лимиты соединений", key('Q')),
        entry("Удалить выбранный inbound", key('D')),
        entry("Сохранить изменения", ctrl('s')),
    ]},
    Group { title: "Пользователи и приглашения", entries: &[
        entry("Создать пользователя и выдать приглашение", key('u')),
        entry("Публичное приглашение без токена", key('l')),
        entry("Обновить токен пользователя", key('t')),
        entry("Отключить пользователя", key('x')),
        entry("Восстановить доступ с новым токеном", key('b')),
        entry("Удалить пользователя без назначенных прав", key('U')),
    ]},
    Group { title: "REALITY: обслуживание", entries: &[
        entry("Состояние, ротация и восстановление", key('V')),
        always("Подготовить отдельный комплект", key('W')),
        entry("Зарегистрировать существующий комплект", key('M')),
        entry("Независимая замена доверия", key('K')),
        always("Диагностика сети (без автоматических запросов)", key('p')),
    ]},
    Group { title: "Конфигурация", entries: &[
        always("Открыть другой TOML", Action::Config),
        entry("Сохранить черновик", ctrl('s')),
        entry("Проверить и применить авторизацию", ctrl('r')),
    ]},
];
const CLIENT: &[Group] = &[
    Group { title: "Подключение", entries: &[
        always("Состояние / подключить / отключить / Apply", key('V')),
        always("Монитор трафика этого процесса", Action::Traffic),
        entry("Системный прокси Windows", key('p')),
    ]},
    Group { title: "Профили и приглашения", entries: &[
        entry("Импорт ссылки, URI-файла или изображения QR", key('i')),
        entry("Создать профиль", key('N')),
        entry("Выбрать активный профиль", key('A')),
        entry("Изменить выбранное поле профиля", Action::Shortcut(KeyCode::Enter, KeyModifiers::NONE)),
        entry("Изменить CA / credential Own-TLS", key('E')),
        entry("Публичное приглашение без токена", key('l')),
        entry("Удалить выбранный профиль", key('D')),
        entry("Сохранить изменения", ctrl('s')),
    ]},
    Group { title: "REALITY: доверие", entries: &[
        always("Отдельный enrollment", key('I')),
        entry("Регистрация готовых материалов", key('M')),
        entry("Повторное подтверждение доверия", key('K')),
        entry("Состояние, обновление credential и recovery", key('V')),
    ]},
    Group { title: "Конфигурация", entries: &[
        always("Открыть другой TOML", Action::Config),
        entry("Сохранить черновик", ctrl('s')),
    ]},
];

pub(crate) struct Menu {
    role: Role,
    group: usize,
    item: Option<usize>,
    configured: bool,
    notice: Option<&'static str>,
}
impl Menu {
    pub(crate) fn new(role: Role, configured: bool) -> Self {
        Self { role, group: 0, item: None, configured, notice: None }
    }

    fn groups(&self) -> &'static [Group] {
        match self.role {
            Role::Server => SERVER,
            Role::Client => CLIENT,
        }
    }

    fn count(&self) -> usize {
        if self.item.is_some() { self.groups()[self.group].entries.len() } else { self.groups().len() }
    }

    fn selected(&self) -> usize {
        self.item.unwrap_or(self.group)
    }

    pub(crate) fn key(&mut self, key: KeyCode) -> Option<Action> {
        let selected = self.selected();
        let count = self.count();
        self.notice = None;
        let next = match key {
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::F(10) => {
                if self.item.take().is_none() || key == KeyCode::F(10) { return Some(Action::Close); }
                return None;
            }
            KeyCode::Up | KeyCode::Char('k') => (selected + count - 1) % count,
            KeyCode::Down | KeyCode::Char('j') => (selected + 1) % count,
            KeyCode::Home => 0,
            KeyCode::End => count - 1,
            KeyCode::PageUp => selected.saturating_sub(5),
            KeyCode::PageDown => (selected + 5).min(count - 1),
            KeyCode::Enter | KeyCode::Right => {
                if let Some(item) = self.item {
                    let e = self.groups()[self.group].entries[item];
                    if e.requires_config && !self.configured {
                        self.notice = Some("Сначала откройте конфигурацию: F3.");
                        return None;
                    }
                    return Some(e.action);
                }
                self.item = Some(0);
                return None;
            }
            _ => return None,
        };
        if self.item.is_some() { self.item = Some(next); } else { self.group = next; }
        None
    }

    pub(crate) fn title(&self) -> &'static str {
        match self.role {
            Role::Server => "Действия сервера",
            Role::Client => "Действия клиента",
        }
    }

    pub(crate) fn body(&self, rows: usize) -> String {
        let groups = self.groups();
        let count = self.count();
        let selected = self.selected();
        let height = rows.saturating_sub(5).max(1);
        let start = selected.saturating_sub(height - 1).min(count.saturating_sub(height));
        let end = (start + height).min(count);
        let title = if self.item.is_some() { groups[self.group].title } else { "Выберите раздел" };
        let mut out = format!("{title}  •  {} / {}\n", selected + 1, count);
        for (i, (name, available)) in (start..end).map(|i| {
            let (name, available) = if self.item.is_some() {
                let e = groups[self.group].entries[i];
                (e.label, !e.requires_config || self.configured)
            } else { (groups[i].title, true) };
            (i, (name, available))
        }) {
            out.push_str(if i == selected { "› " } else { "  " });
            out.push_str(name);
            if !available { out.push_str(" [нужен TOML]"); }
            out.push('\n');
        }
        out.push_str(self.notice.unwrap_or("↑↓ выбор · Enter открыть · Esc назад"));
        out
    }
}


pub(crate) struct ConfigDialog {
    pub(crate) role: Role,
    input: String,
    error: Option<&'static str>,
    loading: Option<std::sync::mpsc::Receiver<Result<crate::tui_editor::Editor, &'static str>>>,
}
impl ConfigDialog {
    pub(crate) fn new(role: Role, existing: Option<&std::path::Path>) -> Self {
        let filename = match role { Role::Server => "server.toml", Role::Client => "client.toml" };
        let path = existing.map(std::path::Path::to_path_buf).unwrap_or_else(|| default_config(filename));
        let input = path.to_str().filter(|p| p.len() <= 4096 && !p.chars().any(char::is_control))
            .unwrap_or(filename).to_owned();
        Self { role, input, error: None, loading: None }
    }
    pub(crate) fn paste(&mut self, text: &str) {
        if self.loading.is_none() && self.input.len().saturating_add(text.len()) <= 4096 && !text.chars().any(char::is_control) {
            self.input.push_str(text);
        }
    }
    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        if self.loading.is_some() { return false; }
        match key.code {
            KeyCode::Esc => return true,
            KeyCode::Enter => {
                if self.input.is_empty() {
                    self.error = Some("Укажите путь к существующему файлу.");
                    return false;
                }
                let path = std::path::PathBuf::from(&self.input);
                let role = self.role;
                let (tx, rx) = std::sync::mpsc::channel();
                match std::thread::Builder::new().name("theia-tui-config".into()).spawn(move || {
                    let loaded = std::path::absolute(path).map_err(|_| "Неверный путь")
                        .and_then(|path| crate::tui_editor::Editor::load(role, &path));
                    let _ = tx.send(loaded);
                }) {
                    Ok(_) => { self.loading = Some(rx); self.error = None; }
                    Err(_) => self.error = Some("Не удалось запустить чтение файла."),
                }
            }
            KeyCode::Backspace => { self.input.pop(); }
            KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => self.input.clear(),
            KeyCode::Char(ch) if !ch.is_control() && (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT) => {
                if self.input.len().saturating_add(ch.len_utf8()) <= 4096 { self.input.push(ch); }
            }
            _ => {}
        }
        false
    }
    pub(crate) fn poll(&mut self) -> Option<crate::tui_editor::Editor> {
        use std::sync::mpsc::TryRecvError;
        let result = match self.loading.as_ref()?.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Err("Чтение файла не подтверждено"),
        };
        self.loading = None;
        match result {
            Ok(editor) => Some(editor),
            Err(reason) => { self.error = Some(reason); None }
        }
    }
    pub(crate) fn body(&self) -> String {
        if self.loading.is_some() { return "Проверяется существующий TOML; ничего не записывается.".into(); }
        let role = if self.role == Role::Server { "Сервер" } else { "Клиент" };
        format!("{role} • существующий файл конфигурации\n\nПуть: {}\n\n{}\nCtrl+U очистить • Backspace удалить • Enter открыть • Esc отменить\nЗагрузка не запускает runtime, не делает сетевых запросов и не изменяет файл.", self.input, self.error.unwrap_or(""))
    }
}

fn default_config(filename: &str) -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    if filename == "server.toml" { return std::path::PathBuf::from("/etc/theia/server.toml"); }
    #[cfg(windows)]
    let root = std::env::var_os("APPDATA").map(|p| std::path::PathBuf::from(p).join("Theia"));
    #[cfg(not(windows))]
    let root = std::env::var_os("XDG_CONFIG_HOME").filter(|p| !p.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".config")))
        .map(|p| p.join("theia"));
    root.map(|p| p.join(filename)).unwrap_or_else(|| std::path::PathBuf::from(filename))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opens_existing_actions_without_requiring_shortcuts() {
        let mut m = Menu::new(Role::Server, true);
        assert_eq!(m.key(KeyCode::Enter), None);
        assert_eq!(m.key(KeyCode::Enter), Some(Action::ServerProcess));
        assert_eq!(m.key(KeyCode::Down), None);
        assert_eq!(m.key(KeyCode::Enter), Some(key('v')));
        assert_eq!(m.key(KeyCode::Esc), None);
        assert_eq!(m.key(KeyCode::Esc), Some(Action::Close));
    }
    #[test]
    fn unconfigured_actions_do_not_mutate_and_selection_is_visible() {
        let mut m = Menu::new(Role::Client, false);
        m.key(KeyCode::Enter);
        assert_eq!(m.key(KeyCode::Enter), Some(key('V')));
        m.key(KeyCode::Down);
        assert_eq!(m.key(KeyCode::Enter), Some(Action::Traffic));
        m.key(KeyCode::End);
        assert_eq!(m.key(KeyCode::Enter), None);
        assert!(m.body(10).contains("Сначала откройте"));
        assert!(m.body(6).contains("Системный прокси"));
        m.key(KeyCode::Esc);
        m.key(KeyCode::End);
        m.key(KeyCode::Enter);
        assert_eq!(m.key(KeyCode::Enter), Some(Action::Config));
    }
}
