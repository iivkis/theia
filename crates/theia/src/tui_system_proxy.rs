//! Explicit Windows client listener/WinINet lifecycle. The terminal never
//! owns a native mutex and never waits for networking during a keypress.
use crate::{
    client::ClientError,
    local_proxy::{saved_client_bytes, PreparedLocalProxy},
    windows_system_proxy::{
        self as native, ApplyReview, ObservedProxy, OwnedProxy, ProxyStatus, RecoveryReview,
    },
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::mpsc,
    thread,
};
use tokio::{sync::mpsc as async_mpsc, task::JoinHandle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Start,
    Apply,
    Restore,
    Recover,
    Stop,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Refresh,
    Review(Action),
    Confirm,
    Cancel,
}

enum Pending {
    Start,
    Apply(ApplyReview),
    Restore,
    Recover(RecoveryReview),
    Stop,
}

struct Local {
    address: SocketAddr,
    manual: bool,
    task: JoinHandle<Result<(), ClientError>>,
}

struct Worker {
    path: PathBuf,
    digest: [u8; 32],
    local: Option<Local>,
    lease: Option<OwnedProxy>,
    pending: Option<Pending>,
}

#[derive(Default)]
struct View {
    running: bool,
    owned: bool,
    manual: bool,
    status: String,
}

struct Event {
    view: View,
    message: String,
    review: bool,
}

impl Worker {
    fn new(path: PathBuf, digest: [u8; 32]) -> Self {
        Self {
            path,
            digest,
            local: None,
            lease: None,
            pending: None,
        }
    }

    fn unchanged(&self) -> Result<(), String> {
        saved_client_bytes(&self.path, self.digest)
            .map(|_| ())
            .map_err(|_| "TOML изменён или недоступен; остановите клиент и перезагрузите редактор.".into())
    }

    fn view(&self) -> View {
        let status = match native::observed_proxy() {
            Ok(ObservedProxy::Direct) => "Выключен: прямое подключение".into(),
            Ok(ObservedProxy::External) => "Настроен вне этой TUI".into(),
            Ok(ObservedProxy::Journal(ProxyStatus::PendingOwned)) if self.lease.is_some() => {
                "Управляется этой TUI (снимок совпадает)".into()
            }
            Ok(ObservedProxy::Journal(ProxyStatus::PendingOwned)) => {
                "Есть журнал; возможен другой владелец или требуется восстановление".into()
            }
            Ok(ObservedProxy::Journal(ProxyStatus::PendingConflict)) => {
                "Конфликт: чужие настройки не перезаписываются".into()
            }
            Ok(ObservedProxy::Journal(ProxyStatus::PendingAlreadyRestored)) => {
                "Исходный снимок уже на месте; остался журнал".into()
            }
            Ok(ObservedProxy::Journal(ProxyStatus::NoJournal)) => "Неизвестно".into(),
            Err(error) => format!("Неизвестно: {error}"),
        };
        View {
            running: self.local.is_some(),
            owned: self.lease.is_some(),
            manual: self.local.as_ref().is_some_and(|local| local.manual),
            status,
        }
    }

    fn review(&mut self, action: Action) -> Result<String, String> {
        self.pending = None;
        let (pending, message) = match action {
            Action::Start if self.local.is_none() && self.lease.is_none() => {
                self.unchanged()?;
                (Pending::Start, "Запустить только локальные HTTP CONNECT/SOCKS5 listeners? WinINet не меняется.".into())
            }
            Action::Apply if self.lease.is_none() => {
                let local = self.local.as_ref().filter(|local| local.manual && !local.task.is_finished())
                    .ok_or("Сначала запустите локальный клиент с system_proxy=manual.")?;
                self.unchanged()?;
                let review = native::review_apply(local.address).map_err(|error| error.to_string())?;
                let message = format!(
                    "{} Адрес назначения: {}. Сохранить снимок и изменить WinINet текущего пользователя?",
                    review.description(), local.address
                );
                (Pending::Apply(review), message)
            }
            Action::Restore if self.lease.is_some() => {
                (Pending::Restore, "Восстановить только собственные параметры WinINet? Локальные listeners останутся.".into())
            }
            Action::Recover if self.lease.is_none() => {
                let review = native::review_recovery().map_err(|error| error.to_string())?;
                (Pending::Recover(review), "Восстановить проверенный журнал? Чужие изменения и активный владелец блокируют операцию.".into())
            }
            Action::Stop if self.local.is_some() => {
                (Pending::Stop, "Остановить локальный клиент? Сначала будет выполнено условное восстановление WinINet, если есть собственный lease.".into())
            }
            _ => return Err("Действие недоступно в текущем состоянии.".into()),
        };
        self.pending = Some(pending);
        Ok(message)
    }

    async fn confirm(&mut self) -> Result<String, String> {
        let pending = self.pending.take().ok_or("Нет подтверждаемой операции.")?;
        match pending {
            Pending::Start => {
                let prepared = PreparedLocalProxy::start(&self.path, self.digest)
                    .await
                    .map_err(|error| error.to_string())?;
                let address = prepared.http_address().map_err(|error| error.to_string())?;
                let manual = prepared.manual;
                let task = tokio::spawn(prepared.serve());
                self.local = Some(Local { address, manual, task });
                Ok("Оба локальных listener привязаны; удалённый транспорт не проверен.".into())
            }
            Pending::Apply(review) => {
                let local = self.local.as_ref().filter(|local| local.manual && !local.task.is_finished())
                    .ok_or("Локальный клиент не готов.")?;
                self.unchanged()?;
                let lease = OwnedProxy::apply_reviewed(local.address, review)
                    .map_err(|error| error.to_string())?;
                self.lease = Some(lease);
                Ok("WinINet применён; точный снимок проверен.".into())
            }
            Pending::Restore => {
                let lease = self.lease.as_mut().ok_or("Нет собственного lease.")?;
                let result = lease.restore().map_err(|error| error.to_string())?;
                self.lease = None;
                Ok(format!("Восстановление WinINet: {result:?}."))
            }
            Pending::Recover(review) => {
                let result = native::recover_reviewed(review).map_err(|error| error.to_string())?;
                Ok(format!("Восстановление журнала: {result:?}."))
            }
            Pending::Stop => {
                self.stop().await?;
                Ok("Локальный клиент остановлен; собственный lease завершён.".into())
            }
        }
    }

    async fn stop(&mut self) -> Result<(), String> {
        self.pending = None;
        // Restore before releasing listeners. On a refusal preserve the
        // recovery journal; never force the old settings over foreign state.
        let restored = if let Some(mut lease) = self.lease.take() {
            lease.restore().map(|_| ()).map_err(|error| error.to_string())
        } else {
            Ok(())
        };
        if let Some(local) = self.local.take() {
            local.task.abort();
            let _ = local.task.await;
        }
        restored
    }

    async fn command(&mut self, command: Command) -> Event {
        let (result, review) = match command {
            Command::Refresh => {
                self.pending = None;
                (Ok("Состояние прочитано; изменений нет.".into()), false)
            }
            Command::Review(action) => {
                let result = self.review(action);
                let ready = result.is_ok();
                (result, ready)
            }
            Command::Confirm => (self.confirm().await, false),
            Command::Cancel => {
                self.pending = None;
                (Ok("Отменено; изменений нет.".into()), false)
            }
        };
        Event {
            view: self.view(),
            message: result.unwrap_or_else(|error| format!("Отказ/ошибка: {error}. Проверьте статус.")),
            review,
        }
    }
}

async fn local_ended(local: &mut Option<Local>) {
    match local {
        Some(local) => {
            let _ = (&mut local.task).await;
        }
        None => std::future::pending::<()>().await,
    }
}

async fn run(
    mut worker: Worker,
    mut commands: async_mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
) {
    loop {
        tokio::select! {
            biased;
            () = local_ended(&mut worker.local) => {
                // JoinHandle has already been consumed; do not poll it twice.
                worker.local = None;
                let result = worker.stop().await;
                let message = match result {
                    Ok(()) => "Локальный клиент неожиданно завершился; собственный lease завершён.".into(),
                    Err(error) => format!("Клиент завершился; восстановление не подтверждено: {error}."),
                };
                if events.send(Event { view: worker.view(), message, review: false }).is_err() {
                    break;
                }
            }
            command = commands.recv() => {
                let Some(command) = command else { break };
                if events.send(worker.command(command).await).is_err() {
                    break;
                }
            }
        }
    }
    // UI closed or terminal failed: restore owned state before stopping.
    // A hard process exit still relies on the durable recovery journal.
    let _ = worker.stop().await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Busy,
    Confirm,
}

pub(crate) struct Panel {
    commands: Option<async_mpsc::Sender<Command>>,
    events: mpsc::Receiver<Event>,
    thread: Option<thread::JoinHandle<()>>,
    phase: Phase,
    view: View,
    message: String,
    unavailable: bool,
}

impl Panel {
    pub(crate) fn open(path: PathBuf, digest: [u8; 32]) -> Result<Self, &'static str> {
        let (commands, receiver) = async_mpsc::channel(1);
        let (events, incoming) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("theia-tui-proxy".into())
            .spawn(move || {
                if let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    runtime.block_on(run(Worker::new(path, digest), receiver, events));
                }
            })
            .map_err(|_| "Не удалось запустить worker системного прокси.")?;
        let mut panel = Self {
            commands: Some(commands),
            events: incoming,
            thread: Some(thread),
            phase: Phase::Idle,
            view: View::default(),
            message: String::new(),
            unavailable: false,
        };
        panel.send(Command::Refresh);
        Ok(panel)
    }

    fn send(&mut self, command: Command) {
        if self.commands.as_ref().is_some_and(|sender| sender.try_send(command).is_ok()) {
            self.phase = Phase::Busy;
        } else {
            self.message = "Команда не подтверждена; проверьте состояние.".into();
        }
    }

    pub(crate) fn poll(&mut self) {
        loop {
            match self.events.try_recv() {
                Ok(event) => {
                    self.view = event.view;
                    self.message = event.message;
                    self.phase = if event.review { Phase::Confirm } else { Phase::Idle };
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.unavailable = true;
                    self.phase = Phase::Idle;
                    self.message = "Worker недоступен; состояние неизвестно. Проверьте client proxy --status.".into();
                    break;
                }
            }
        }
    }

    /// Return true only when the modal may close; a live local client must
    /// first be explicitly stopped. No key repeat, paste or lone y applies.
    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press || self.phase == Phase::Busy {
            return false;
        }
        let quit = key.code == KeyCode::Esc
            || key.code == KeyCode::Char('q')
            || key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c');
        if self.unavailable {
            return quit;
        }
        if self.phase == Phase::Confirm {
            if key.code == KeyCode::Char('y') && key.modifiers.is_empty() {
                self.send(Command::Confirm);
            } else if quit || key.code == KeyCode::Char('n') {
                self.send(Command::Cancel);
            }
            return false;
        }
        if quit {
            if !self.view.running && !self.view.owned {
                return true;
            }
            self.send(Command::Review(Action::Stop));
            return false;
        }
        if !key.modifiers.is_empty() {
            return false;
        }
        let command = match key.code {
            KeyCode::Char('v') => Command::Refresh,
            KeyCode::Char('s') => Command::Review(Action::Start),
            KeyCode::Char('a') => Command::Review(Action::Apply),
            KeyCode::Char('r') => Command::Review(Action::Restore),
            KeyCode::Char('c') => Command::Review(Action::Recover),
            KeyCode::Char('x') => Command::Review(Action::Stop),
            _ => return false,
        };
        self.send(command);
        false
    }

    pub(crate) fn body(&self) -> String {
        let status = if self.unavailable || self.phase == Phase::Busy {
            "Операция не подтверждена / состояние обновляется"
        } else {
            &self.view.status
        };
        let controls = match self.phase {
            Phase::Busy => "Ожидается результат worker.",
            Phase::Confirm => "y: подтвердить  n/Esc: отменить",
            Phase::Idle => "s: local start  a: WinINet  r: restore  c: recovery  x: stop  v: status  Esc: назад",
        };
        format!(
            "WinINet: {status}\nLocal: {} | manual: {}\nTransport/OPEN_OK: не проверялись\n{}\n{controls}",
            if self.unavailable { "неизвестно" } else if self.view.running { "слушает" } else { "не запущен" },
            if self.view.manual { "да" } else { "нет" },
            self.message
        )
    }
}

impl Drop for Panel {
    fn drop(&mut self) {
        self.commands.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ch: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE)
    }

    #[test]
    fn review_is_required_and_cancel_is_not_confirm() {
        let (commands, mut receiver) = async_mpsc::channel(1);
        let (events, incoming) = mpsc::channel();
        let mut panel = Panel {
            commands: Some(commands),
            events: incoming,
            thread: None,
            phase: Phase::Idle,
            view: View::default(),
            message: String::new(),
            unavailable: false,
        };
        assert!(!panel.key(key('y')));
        assert!(receiver.try_recv().is_err());
        panel.key(key('a'));
        assert_eq!(receiver.try_recv(), Ok(Command::Review(Action::Apply)));
        panel.key(key('y'));
        assert!(receiver.try_recv().is_err());
        events.send(Event { view: View::default(), message: "review".into(), review: true }).unwrap();
        panel.poll();
        panel.key(key('n'));
        assert_eq!(receiver.try_recv(), Ok(Command::Cancel));
        events.send(Event { view: View::default(), message: "cancel".into(), review: false }).unwrap();
        panel.poll();
        panel.key(key('y'));
        assert!(receiver.try_recv().is_err());
        panel.key(key('c'));
        assert_eq!(receiver.try_recv(), Ok(Command::Review(Action::Recover)));
        events.send(Event { view: View::default(), message: "review".into(), review: true }).unwrap();
        panel.poll();
        panel.key(key('y'));
        assert_eq!(receiver.try_recv(), Ok(Command::Confirm));
        panel.key(key('y'));
        assert!(receiver.try_recv().is_err());
    }
}
