//! The TUI owns only servers it explicitly starts. External service status
//! and guarded Apply remain in tui_runtime; never kill an arbitrary PID.
use crate::{server::ServerError, tui_editor::Editor, Role};
use crossterm::event::KeyCode;
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver, TryRecvError},
    thread::JoinHandle,
};

/// The endpoint exists only for the server owned by this TUI. On Linux a
/// newly created private directory is removed only if its identity is still
/// the one we created, and only when empty. Windows uses the existing SID DACL.
struct OwnedEndpoint {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    identity: (u64, u64),
}

impl OwnedEndpoint {
    #[cfg(target_os = "linux")]
    fn create() -> Result<Self, &'static str> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let id = crate::tui_editor::generated_id("theia-ipc")?;
        let path = std::path::absolute(std::env::temp_dir().join(id))
            .map_err(|_| "Не удалось определить локальный каталог управления.")?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| "Не удалось создать закрытый каталог управления.")?;
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| "Не удалось проверить каталог управления.")?;
        let endpoint = Self {
            path,
            identity: (metadata.dev(), metadata.ino()),
        };
        if !metadata.file_type().is_dir() || metadata.mode() & 0o777 != 0o700 {
            return Err("Каталог управления должен иметь права 0700.");
        }
        Ok(endpoint)
    }

    #[cfg(target_os = "windows")]
    fn create() -> Result<Self, &'static str> {
        Ok(Self {
            path: PathBuf::from(crate::tui_editor::generated_id("theia-ipc")?),
        })
    }
}

impl Drop for OwnedEndpoint {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            if std::fs::symlink_metadata(&self.path)
                .is_ok_and(|m| m.file_type().is_dir() && (m.dev(), m.ino()) == self.identity)
            {
                let _ = std::fs::remove_dir(&self.path);
            }
        }
    }
}

struct Worker {
    endpoint: Option<OwnedEndpoint>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    ready: tokio::sync::oneshot::Receiver<usize>,
    done: Receiver<Result<(), ServerError>>,
    thread: Option<JoinHandle<()>>,
    inbounds: Option<usize>,
}
impl Worker {
    fn request_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.request_stop();
        // Dropping the TUI after an I/O failure still requests bounded drain.
        // No detached thread or claim that an unconfirmed stop has succeeded.
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) struct ProcessPanel {
    worker: Option<Worker>,
    confirm: Option<bool>,
    notice: String,
    action_focus: usize,
}
impl ProcessPanel {
    pub(crate) fn new() -> Self {
        Self {
            worker: None,
            confirm: None,
            notice: "Сервер этой панели не запущен.".into(),
            action_focus: 0,
        }
    }

    pub(crate) fn running(&self) -> bool {
        self.worker.is_some()
    }

    pub(crate) fn management_endpoint(&self) -> Option<PathBuf> {
        self.worker
            .as_ref()
            .and_then(|w| w.endpoint.as_ref())
            .map(|e| e.path.clone())
    }

    fn start(&mut self, editor: &Editor) {
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = editor;
            self.notice = "Управляемый запуск поддерживается на Linux и Windows.".into();
        }
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            if self.worker.is_some()
                || editor.role() != Role::Server
                || editor.require_clean_records().is_err()
            {
                self.notice = "Сначала откройте и сохраните серверную конфигурацию.".into();
                return;
            }
            let endpoint = match OwnedEndpoint::create() {
                Ok(endpoint) => endpoint,
                Err(message) => {
                    self.notice = message.into();
                    return;
                }
            };
            let management_path = endpoint.path.clone();
            let path = editor.saved_path().to_owned();
            let digest = editor.saved_sha256();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let (ready_tx, ready) = tokio::sync::oneshot::channel();
            let (tx, done) = mpsc::channel();
            let thread = std::thread::Builder::new()
                .name("theia-tui-server".into())
                .spawn(move || {
                    let result = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| ServerError::Io)
                        .and_then(|runtime| {
                            runtime.block_on(crate::server::run_tui_file(
                                &path,
                                digest,
                                ready_tx,
                                stopped,
                                Some(management_path),
                            ))
                        });
                    let _ = tx.send(result);
                });
            match thread {
                Ok(thread) => {
                    self.worker = Some(Worker {
                        endpoint: Some(endpoint),
                        stop: Some(stop),
                        ready,
                        done,
                        thread: Some(thread),
                        inbounds: None,
                    });
                    self.notice = "Проверяем настройки, сертификаты, права и сетевые порты...".into();
                }
                Err(_) => self.notice = "Не удалось запустить рабочий поток сервера.".into(),
            }
        }
    }

    pub(crate) fn poll(&mut self) {
        let Some(worker) = self.worker.as_mut() else {
            return;
        };
        if worker.inbounds.is_none() {
            if let Ok(count) = worker.ready.try_recv() {
                worker.inbounds = Some(count);
            }
        }
        let result = match worker.done.try_recv() {
            Ok(value) => Some(value),
            Err(TryRecvError::Disconnected) => Some(Err(ServerError::Io)),
            Err(TryRecvError::Empty) => None,
        };
        if let Some(result) = result {
            self.worker = None;
            self.confirm = None;
            self.notice = match result {
                Ok(()) => "Сервер остановлен; завершение listener tasks подтверждено.".into(),
                Err(e) => format!("Сервер не работает: {e}. Проверьте конфигурацию и журнал."),
            };
        }
    }

    pub(crate) fn confirmation(&self) -> Option<bool> {
        self.confirm
    }

    pub(crate) fn actions(&self) -> Vec<crate::tui_widgets::ActionItem> {
        use crate::tui_widgets::ActionItem;
        if self.confirm.is_some() {
            return Vec::new();
        }
        match &self.worker {
            None => vec![ActionItem {
                key: 's',
                label: "Запустить сервер",
            }],
            Some(worker) if worker.stop.is_some() => vec![ActionItem {
                key: 'x',
                label: "Остановить сервер",
            }],
            Some(_) => Vec::new(),
        }
    }
    pub(crate) fn action_focus(&self) -> usize {
        self.action_focus
    }
    pub(crate) fn select_action(&mut self, index: usize) {
        if index < self.actions().len() {
            self.action_focus = index;
        }
    }

    /// Return true to close the panel. Closing the panel is not stopping.
    pub(crate) fn key(&mut self, key: KeyCode, editor: Option<&Editor>) -> bool {
        let items = self.actions();
        let Some(key) = crate::tui_widgets::action_key(&items, &mut self.action_focus, key) else {
            return false;
        };
        if let Some(start) = self.confirm {
            match key {
                KeyCode::Char('y') => {
                    self.confirm = None;
                    if start {
                        if let Some(editor) = editor {
                            self.start(editor);
                        } else {
                            self.notice = "Сначала откройте файл настроек сервера.".into();
                        }
                    } else if let Some(worker) = self.worker.as_mut() {
                        worker.request_stop();
                    }
                }
                KeyCode::Char('n') | KeyCode::Esc => self.confirm = None,
                _ => {}
            }
            return false;
        }
        match key {
            KeyCode::Esc => true,
            KeyCode::Char('s') if self.worker.is_none() => {
                if editor
                    .is_some_and(|e| e.role() == Role::Server && e.require_clean_records().is_ok())
                {
                    self.confirm = Some(true);
                } else {
                    self.notice =
                        "Сначала откройте и сохраните настройки сервера.".into();
                }
                false
            }
            KeyCode::Char('x') if self.worker.as_ref().is_some_and(|w| w.stop.is_some()) => {
                self.confirm = Some(false);
                false
            }
            _ => false,
        }
    }

    pub(crate) fn status(&self) -> &'static str {
        match &self.worker {
            Some(w) if w.stop.is_none() => "Останавливается",
            Some(w) if w.inbounds.is_some() => "Запущен",
            Some(_) => "Подготовка",
            None => "Не запущен этой панелью",
        }
    }

    pub(crate) fn summary(&self) -> String {
        let report = match &self.worker {
            Some(w) if w.stop.is_none() => {
                "Остановка: новые подключения не принимаются, ожидается завершение задач.".into()
            }
            Some(w) if w.inbounds.is_some() => format!(
                "Сервер запущен. Подключений: {}.\nСостояние относится только к этому экземпляру.",
                w.inbounds.unwrap_or(0)
            ),
            _ => self.notice.clone(),
        };
        format!("{}\n\n{report}\n\nВозврат не останавливает сервер.\nВнешний сервис управляется отдельно.", self.status())
    }

    pub(crate) fn body(&self) -> String {
        if let Some(start) = self.confirm {
            return if start {
                "Запустить сервер по сохранённым настройкам?\nОткрываются указанные сетевые порты и закрытый локальный канал управления. Права ОС не повышаются.\ny: запустить • n/Esc: отменить".into()
            } else {
                "Остановить запущенный этой панелью сервер? Новые подключения будут отклонены; действующие получат ограниченное время на завершение.\ny: остановить • n/Esc: отменить".into()
            };
        }
        let report = match &self.worker {
            Some(w) if w.stop.is_none() => {
                "Остановка: новые подключения не принимаются, ожидается завершение задач.".into()
            }
            Some(w) if w.inbounds.is_some() => format!(
                "Сервер запущен. Подключений: {}.\nСостояние относится только к этому экземпляру.",
                w.inbounds.unwrap_or(0)
            ),
            _ => self.notice.clone(),
        };
        let actions = if self.running() {
            "x: остановить (подтверждение)"
        } else {
            "s: запустить (подтверждение)"
        };
        format!("{report}\n\n{actions} • Esc: назад (не останавливает сервер)\nДля внешнего сервиса откройте отдельный экран состояния.\nВыход из TUI требует предварительной остановки принадлежащего ему сервера.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_worker_reports_ready_and_only_stops_after_confirmation() {
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let (ready_tx, ready) = tokio::sync::oneshot::channel();
        let (done_tx, done) = mpsc::channel();
        let mut panel = ProcessPanel::new();
        panel.worker = Some(Worker {
            endpoint: None,
            stop: Some(stop),
            ready,
            done,
            thread: None,
            inbounds: None,
        });
        panel.poll();
        assert_eq!(panel.status(), "Подготовка");
        ready_tx.send(2).unwrap();
        panel.poll();
        assert_eq!(panel.status(), "Запущен");
        assert!(panel.body().contains("Inbound: 2"));
        assert!(panel.key(KeyCode::Esc, None));
        assert!(panel.running());
        assert!(!panel.key(KeyCode::Char('x'), None));
        assert!(panel.body().contains("Остановить запущенный"));
        panel.key(KeyCode::Char('n'), None);
        assert!(stopped.try_recv().is_err());
        assert_eq!(panel.status(), "Запущен");
        panel.key(KeyCode::Char('x'), None);
        panel.key(KeyCode::Char('y'), None);
        stopped.try_recv().unwrap();
        assert_eq!(panel.status(), "Останавливается");
        assert!(panel.body().contains("новые подключения не принимаются"));
        done_tx.send(Ok(())).unwrap();
        panel.poll();
        assert!(!panel.running());
        assert!(panel
            .body()
            .contains("завершение listener tasks подтверждено"));
    }

    #[test]
    fn worker_disconnect_does_not_claim_success_and_start_confirmation_can_cancel() {
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let (_ready_tx, ready) = tokio::sync::oneshot::channel();
        let (done_tx, done) = mpsc::channel();
        let mut panel = ProcessPanel::new();
        panel.confirm = Some(true);
        assert!(panel.body().contains("Открываются указанные сетевые порты"));
        assert!(!panel.key(KeyCode::Esc, None));
        assert!(panel.confirm.is_none());
        panel.confirm = Some(true);
        panel.key(KeyCode::Char('y'), None);
        assert!(panel.body().contains("Сначала откройте файл настроек сервера"));
        panel.worker = Some(Worker {
            endpoint: None,
            stop: Some(stop),
            ready,
            done,
            thread: None,
            inbounds: None,
        });
        drop(done_tx);
        panel.poll();
        assert!(!panel.running());
        stopped.try_recv().unwrap();
        assert!(panel.body().contains("Сервер не работает"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_endpoint_is_private_unique_and_only_removed_when_empty() {
        use std::os::unix::fs::MetadataExt;
        let first = OwnedEndpoint::create().unwrap();
        let second = OwnedEndpoint::create().unwrap();
        assert_ne!(first.path, second.path);
        let path = first.path.clone();
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().mode() & 0o777,
            0o700
        );
        drop(first);
        assert!(!path.exists());
        let path = second.path.clone();
        let retained = path.join("retain");
        std::fs::write(&retained, b"data").unwrap();
        drop(second);
        assert!(retained.exists());
        std::fs::remove_file(retained).unwrap();
        std::fs::remove_dir(path).unwrap();
    }

    #[test]
    fn no_config_means_no_start_and_no_confirm() {
        let mut p = ProcessPanel::new();
        assert!(!p.key(KeyCode::Char('s'), None));
        assert!(p.body().contains("Сначала откройте и сохраните настройки"));
        assert!(!p.running());
        assert!(p.key(KeyCode::Esc, None));
        assert_eq!(p.status(), "Не запущен этой панелью");
    }
}
