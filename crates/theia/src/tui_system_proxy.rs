//! Explicit Windows client listener/WinINet lifecycle. The terminal never
//! owns a native mutex and never waits for networking during a keypress.
use crate::{
    local_proxy::{saved_client_bytes, SystemProxySession},
    windows_system_proxy::{
        self as native, ApplyReview, ObservedProxy, ProxyStatus, RecoveryReview,
    },
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::{net::SocketAddr, path::PathBuf, sync::mpsc, thread};
use tokio::sync::mpsc as async_mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Enable,
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
    Enable(ApplyReview),
    Recover(RecoveryReview),
    Stop,
}

struct Worker {
    path: PathBuf,
    digest: [u8; 32],
    session: Option<SystemProxySession>,
    pending: Option<Pending>,
}

#[derive(Default)]
struct View {
    running: bool,
    owned: bool,
    applied: bool,
    recovery: bool,
    known: bool,
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
            session: None,
            pending: None,
        }
    }

    fn unchanged(&self) -> Result<(), String> {
        saved_client_bytes(&self.path, self.digest)
            .map(|_| ())
            .map_err(|_| {
                "TOML изменён или недоступен; остановите клиент и перезагрузите редактор.".into()
            })
    }

    fn view(&self) -> View {
        let observed = native::observed_proxy();
        let known = observed.is_ok()
            && !matches!(
                &observed,
                Ok(ObservedProxy::Journal(ProxyStatus::NoJournal))
            );
        let applied = self
            .session
            .as_ref()
            .is_some_and(SystemProxySession::applied)
            && matches!(
                &observed,
                Ok(ObservedProxy::Journal(ProxyStatus::PendingOwned))
            );
        let recovery = self.session.is_none()
            && matches!(
                &observed,
                Ok(ObservedProxy::Journal(
                    ProxyStatus::PendingOwned
                        | ProxyStatus::PendingAlreadyRestored
                        | ProxyStatus::PendingConflict
                ))
            );
        let status = match observed {
            Ok(ObservedProxy::Direct) => "В проверенной области WinINet нет прокси".into(),
            Ok(ObservedProxy::External) => "Настроен вне этой TUI".into(),
            Ok(ObservedProxy::Journal(ProxyStatus::PendingOwned)) if self.session.is_some() => {
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
            running: self
                .session
                .as_ref()
                .is_some_and(SystemProxySession::running),
            owned: self.session.is_some(),
            applied,
            recovery,
            known,
            status,
        }
    }

    fn review(&mut self, action: Action) -> Result<String, String> {
        self.pending = None;
        let (pending, message) = match action {
            Action::Enable if self.session.is_none() => {
                let bytes = saved_client_bytes(&self.path, self.digest)
                    .map_err(|error| error.to_string())?;
                let source =
                    std::str::from_utf8(&bytes).map_err(|_| "Некорректный файл клиента.")?;
                let crate::config::Config::Client(document) =
                    crate::config::parse(source).map_err(|_| "Некорректные настройки клиента.")?
                else {
                    return Err("Требуется клиентский профиль.".into());
                };
                let address: SocketAddr = document
                    .client
                    .proxy
                    .http_listen
                    .parse()
                    .map_err(|_| "Некорректный адрес локального HTTP-прокси.")?;
                let review = native::review_apply(address).map_err(|error| error.to_string())?;
                let message = format!(
                    "{}\nПодключиться? Запустить локальный прокси при необходимости и направить приложения Windows на {address}. Исходные настройки будут сохранены для восстановления.",
                    review.description()
                );
                (Pending::Enable(review), message)
            }
            Action::Recover if self.session.is_none() => {
                let review = native::review_recovery().map_err(|error| error.to_string())?;
                (Pending::Recover(review), "Восстановить проверенный журнал? Чужие изменения и активный владелец блокируют операцию.".into())
            }
            Action::Stop if self.session.is_some() => (
                Pending::Stop,
                "Отключиться? Остановить локальный клиент и условно восстановить WinINet.".into(),
            ),
            _ => return Err("Действие недоступно в текущем состоянии.".into()),
        };
        self.pending = Some(pending);
        Ok(message)
    }

    async fn confirm(&mut self) -> Result<String, String> {
        let pending = self.pending.take().ok_or("Нет подтверждаемой операции.")?;
        match pending {
            Pending::Enable(review) => {
                self.unchanged()?;
                let session = Box::pin(SystemProxySession::connect(
                    &self.path,
                    self.digest,
                    Some(review),
                ))
                .await
                .map_err(|error| error.to_string())?;
                self.session = Some(session);
                Ok(
                    "Операция подключения завершена. Проверьте результат чтения настроек ниже."
                        .into(),
                )
            }
            Pending::Recover(review) => {
                let result = native::recover_reviewed(review).map_err(|error| error.to_string())?;
                Ok(format!("Восстановление журнала: {result:?}."))
            }
            Pending::Stop => {
                self.stop().await?;
                Ok("Сеанс завершён. Результат восстановления настроек показан ниже.".into())
            }
        }
    }

    async fn stop(&mut self) -> Result<(), String> {
        self.pending = None;
        if let Some(mut session) = self.session.take() {
            session
                .disconnect()
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(())
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
            message: result
                .unwrap_or_else(|error| format!("Отказ/ошибка: {error}. Проверьте статус.")),
            review,
        }
    }
}

async fn local_ended(
    session: &mut Option<SystemProxySession>,
) -> Result<(), crate::client::ClientError> {
    match session {
        Some(session) => session.ended().await,
        None => std::future::pending().await,
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
            result = local_ended(&mut worker.session) => {
                worker.session = None;
                worker.pending = None;
                let message = match result {
                    Ok(()) => {
                        "Локальный клиент неожиданно завершился; собственный lease завершён.".into()
                    }
                    Err(error) => {
                        format!("Клиент завершился; восстановление не подтверждено: {error}.")
                    }
                };
                if events.send(Event { view: worker.view(), message, review: false }).is_err() {
                    break;
                }
            }
            command = commands.recv() => {
                let Some(command) = command else { break };
                let mut event=worker.command(command).await;
                if let Some(session) = worker.session.as_ref() {
                    event.view.status.push_str("\n\n");
                    event.view.status.push_str(&session.report().await);
                }
                if events.send(event).is_err() {
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
                if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
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
        if self
            .commands
            .as_ref()
            .is_some_and(|sender| sender.try_send(command).is_ok())
        {
            self.phase = Phase::Busy;
        } else {
            self.message = "Команда не подтверждена; проверьте состояние.".into();
        }
    }

    pub(crate) fn poll(&mut self) -> bool {
        let previous = self.phase;
        loop {
            match self.events.try_recv() {
                Ok(event) => {
                    self.view = event.view;
                    self.message = event.message;
                    self.phase = if event.review {
                        Phase::Confirm
                    } else {
                        Phase::Idle
                    };
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.unavailable = true;
                    self.phase = Phase::Idle;
                    self.message =
                        "Worker недоступен; состояние неизвестно. Проверьте client proxy --status."
                            .into();
                    break;
                }
            }
        }
        previous != self.phase
    }

    /// Esc minimizes the live controller; quitting requires explicit Stop.
    /// No key repeat, paste or lone y applies.
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
            if key.code == KeyCode::Esc || (!self.view.running && !self.view.owned) {
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
            KeyCode::Char('e') => Command::Review(Action::Enable),
            KeyCode::Char('c') => Command::Review(Action::Recover),
            KeyCode::Char('x') => Command::Review(Action::Stop),
            _ => return false,
        };
        self.send(command);
        false
    }

    pub(crate) fn running(&self) -> bool {
        !self.unavailable && (self.view.running || self.view.owned)
    }

    pub(crate) fn confirmation_choice(&self) -> Option<(char, &'static str)> {
        (!self.unavailable && self.phase == Phase::Confirm).then_some(('y', "Подтвердить"))
    }

    pub(crate) fn actions(&self) -> Vec<crate::tui_widgets::ActionItem> {
        use crate::tui_widgets::ActionItem;
        if self.unavailable || self.phase == Phase::Busy {
            return Vec::new();
        }
        if self.phase == Phase::Confirm {
            return vec![
                ActionItem {
                    key: 'n',
                    label: "Отменить",
                },
                ActionItem {
                    key: 'y',
                    label: "Подтвердить",
                },
            ];
        }
        let mut items = Vec::new();
        if self.view.owned {
            items.push(ActionItem {
                key: 'x',
                label: "Отключиться",
            });
        } else if self.view.recovery {
            items.push(ActionItem {
                key: 'c',
                label: "Восстановить после сбоя",
            });
        } else if self.view.known {
            items.push(ActionItem {
                key: 'e',
                label: "Подключиться",
            });
        }
        items.push(ActionItem {
            key: 'v',
            label: "Обновить состояние",
        });
        items
    }

    pub(crate) fn body(&self) -> String {
        let status = if self.unavailable || self.phase == Phase::Busy {
            "Нет актуального результата чтения настроек"
        } else {
            &self.view.status
        };
        let headline = if self.unavailable || self.phase == Phase::Busy {
            if self.unavailable {
                "Состояние неизвестно: управление недоступно"
            } else {
                "Выполняется проверка или операция"
            }
        } else if !self.view.known {
            "Состояние системного прокси неизвестно"
        } else if self.view.applied && self.view.running {
            "Настройки прокси применены по последней проверке"
        } else if self.view.owned || self.view.recovery {
            "Требуется проверка / восстановление"
        } else {
            "Нет подтверждённого системного прокси этой панели"
        };
        let controls = match self.phase {
            Phase::Busy => "Выполняется операция…",
            Phase::Confirm => "Выберите подтверждение или отмену (y / n, Esc).",
            Phase::Idle if self.view.owned => {
                "Отключение попытается восстановить исходные параметры, если они не изменены извне."
            }
            Phase::Idle if self.view.recovery => {
                "Сначала проверьте восстановление исходных параметров."
            }
            Phase::Idle if !self.view.known => "Обновите состояние. Изменения не подтверждены.",
            Phase::Idle => "Выберите «Подключиться». Esc — назад.",
        };
        format!(
            "{headline}\n{}\n{controls}\n\nWindows (последнее наблюдение): {status}\nЛокальный сеанс: {}\nПрохождение запросов приложений: не проверено этой панелью. Прокси не охватывает весь трафик устройства.",
            self.message,
            if self.unavailable || self.phase == Phase::Busy {
                "неизвестно"
            } else if self.view.running {
                "работал при последней проверке"
            } else {
                "работа не подтверждена"
            }
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
pub(crate) mod tests {
    use super::*;

    fn key(ch: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE)
    }

    // Run serially inside the existing opt-in disposable WinINet test, never
    // as a parallel ordinary unit test against the developer's OS settings.
    pub(crate) fn native_lifecycle(assert_original: impl Fn(), crash: impl Fn()) {
        use crate::{
            client_import::PrivateBearer,
            config::{self, Config},
        };
        use sha2::{Digest, Sha256};
        use std::{
            fs,
            net::{TcpListener, TcpStream},
            time::{Duration, Instant},
        };

        fn wait(panel: &mut Panel) {
            let deadline = Instant::now() + Duration::from_secs(20);
            while panel.phase == Phase::Busy {
                assert!(Instant::now() < deadline, "proxy worker timeout");
                thread::sleep(Duration::from_millis(10));
                panel.poll();
            }
            assert!(!panel.unavailable);
        }

        fn review(panel: &mut Panel, action: char) {
            panel.key(key(action));
            wait(panel);
            assert!(panel.phase == Phase::Confirm, "{}", panel.message);
        }

        fn confirm(panel: &mut Panel) {
            panel.key(key('y'));
            wait(panel);
            assert!(panel.phase == Phase::Idle);
        }

        fn action(panel: &mut Panel, ch: char) {
            review(panel, ch);
            confirm(panel);
        }

        struct RestoreEnv(Option<std::ffi::OsString>);
        impl Drop for RestoreEnv {
            fn drop(&mut self) {
                if let Some(value) = self.0.take() {
                    std::env::set_var("THEIA_CLIENT_CONTROL_PIPE", value);
                } else {
                    std::env::remove_var("THEIA_CLIENT_CONTROL_PIPE");
                }
            }
        }
        let _environment = RestoreEnv(std::env::var_os("THEIA_CLIENT_CONTROL_PIPE"));
        let pipe = format!("proxy-lifecycle-{}", std::process::id());
        std::env::set_var("THEIA_CLIENT_CONTROL_PIPE", &pipe);
        let directory =
            std::env::temp_dir().join(format!("theia-proxy-tui-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("client.toml");
        let ca_path = directory.join("ca.pem");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(&ca_path, cert.cert.pem()).unwrap();
        let bearer = PrivateBearer::create(&path, &[42; 32]).unwrap();
        // Startup now authenticates the routing snapshot before binding local
        // proxies. Exercise that real preflight instead of assuming an offline
        // example endpoint can start the client.
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let endpoint = upstream.local_addr().unwrap().to_string();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let inbound = config::Inbound {
            id: "proxy-test".into(),
            path_prefix: Some("/v1/theia-example".into()),
            allowed_user_ids: vec!["client".into()],
            h2_listen: endpoint.clone(),
            quic_listen: "127.0.0.1:0".into(),
            server_name: "localhost".into(),
            tls_cert: "unused-test-fixture".into(),
            tls_key: "unused-test-fixture".into(),
            security_mode: Default::default(),
            reality: None,
        };
        let context = std::sync::Arc::new(crate::server::ServerContext::new(
            &inbound,
            &[config::User {
                id: "client".into(),
                token_sha256: format!("{:x}", Sha256::digest([42; 32])),
                disabled: false,
            }],
            &config::ServerPolicy {
                routing: None,
                allow_private_ips: true,
                max_connections_per_user: 8,
                max_connections_total: 8,
                connect_timeout_ms: 1500,
            },
        ));
        let server = runtime.spawn(async move {
            crate::server::serve(
                tokio::net::TcpListener::from_std(upstream).unwrap(),
                tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls)),
                context,
            )
            .await
        });
        let Config::Client(mut doc) =
            config::parse(include_str!("../../../examples/client.toml")).unwrap()
        else {
            panic!("client fixture required");
        };
        let profile = &mut doc.client.profiles[0];
        profile.server = endpoint;
        profile.server_name = "localhost".into();
        profile.transport = config::Transport::H2;
        profile.tls_ca = Some(format!("file:{}", ca_path.display()));
        profile.auth_token = bearer.reference().unwrap();
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let http = first.local_addr().unwrap();
        let socks = second.local_addr().unwrap();
        doc.client.proxy.http_listen = http.to_string();
        doc.client.proxy.socks5_listen = socks.to_string();
        let source = Config::Client(doc.clone()).to_toml().unwrap();
        fs::write(&path, &source).unwrap();
        let digest = Sha256::digest(source.as_bytes()).into();
        let mut panel = Panel::open(path.clone(), digest).unwrap();
        wait(&mut panel);
        assert_original();
        panel.key(key('x'));
        wait(&mut panel);
        assert!(panel.phase == Phase::Idle);
        assert_original();

        // Failed second bind must release the first and never touch WinINet.
        drop(first);
        action(&mut panel, 'e');
        assert!(!panel.view.running);
        assert!(!panel.view.owned);
        assert!(panel.body().contains("Отказ/ошибка"));
        assert!(!panel.body().contains("Настройки прокси применены"));
        assert_original();
        drop(second);

        review(&mut panel, 'e');
        panel.key(key('n'));
        wait(&mut panel);
        assert!(!panel.view.running);
        assert_original();

        // The confirmation is pinned to exact saved bytes.
        review(&mut panel, 'e');
        fs::write(&path, format!("{source}\n# external edit\n")).unwrap();
        confirm(&mut panel);
        assert!(!panel.view.running && !panel.view.owned);
        assert_original();
        fs::write(&path, &source).unwrap();

        action(&mut panel, 'e');
        assert!(panel.view.running && panel.view.applied && panel.view.owned);
        assert!(panel
            .body()
            .contains("Настройки прокси применены по последней проверке"));
        assert!(panel
            .body()
            .contains("Прохождение запросов приложений: не проверено"));
        assert_eq!(native::status().unwrap(), ProxyStatus::PendingOwned);
        assert!(TcpStream::connect_timeout(&http, Duration::from_secs(2)).is_ok());
        assert!(TcpStream::connect_timeout(&socks, Duration::from_secs(2)).is_ok());
        panel.key(key('c'));
        wait(&mut panel);
        assert!(panel.phase == Phase::Idle && panel.view.owned);
        let mut other = Panel::open(path.clone(), digest).unwrap();
        wait(&mut other);
        other.key(key('e'));
        wait(&mut other);
        assert!(!other.view.running && !other.view.owned);
        assert_eq!(native::status().unwrap(), ProxyStatus::PendingOwned);
        drop(other);
        action(&mut panel, 'x');
        assert!(!panel.view.running && !panel.view.owned);
        assert!(!panel.body().contains("Настройки прокси применены"));
        assert_original();
        assert!(TcpStream::connect_timeout(&http, Duration::from_millis(100)).is_err());
        assert!(TcpStream::connect_timeout(&socks, Duration::from_millis(100)).is_err());

        // A real SID-protected IPC request must bind to the exact instance.
        use crate::management::{ManagementError, StatusCommand as C, StatusReply as R};
        use std::io::{Read, Write};
        let query =
            |command| runtime.block_on(crate::windows_control::query_client_pipe(&pipe, command));
        action(&mut panel, 'e');
        assert!(panel.view.owned);
        let R::ClientLifecycle(first_instance) = query(C::ClientLifecycle).unwrap() else {
            panic!("expected lifecycle");
        };
        assert_eq!(first_instance.phase, 2);
        assert!(first_instance.listeners_ready);
        assert_eq!(first_instance.proxy_applied, 1);
        let disconnect = C::ClientDisconnect {
            expected_revision: first_instance.revision,
            config_sha256: first_instance.config_sha256,
            instance: first_instance.instance,
        };
        assert_eq!(
            query(C::ClientDisconnect {
                expected_revision: first_instance.revision,
                config_sha256: first_instance.config_sha256,
                instance: [0; 32],
            }),
            Err(ManagementError::CandidateRejected)
        );
        assert_eq!(native::status().unwrap(), ProxyStatus::PendingOwned);

        // Real active TCP CONNECT and UDP ASSOCIATE control socket, both
        // kept open through IPC Disconnect. A late datagram cannot use a
        // released association or reopen a retired flow.
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        echo.set_nonblocking(true).unwrap();
        let target = echo.local_addr().unwrap();
        let echo_task = runtime.spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let listener = tokio::net::TcpListener::from_std(echo).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4];
            while stream.read_exact(&mut bytes).await.is_ok() {
                if stream.write_all(&bytes).await.is_err() {
                    break;
                }
            }
        });
        let mut tcp = TcpStream::connect_timeout(&http, Duration::from_secs(2)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") && response.len() < 1024 {
            let mut byte = [0; 1];
            tcp.read_exact(&mut byte).unwrap();
            response.push(byte[0]);
        }
        assert!(response.starts_with(b"HTTP/1.1 200"));
        tcp.write_all(b"ping").unwrap();
        let mut echoed = [0; 4];
        tcp.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping");

        let mut udp_control = TcpStream::connect_timeout(&socks, Duration::from_secs(2)).unwrap();
        udp_control
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        udp_control.write_all(&[5, 1, 0]).unwrap();
        let mut selection = [0; 2];
        udp_control.read_exact(&mut selection).unwrap();
        assert_eq!(selection, [5, 0]);
        udp_control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let mut association = [0; 10];
        udp_control.read_exact(&mut association).unwrap();
        assert_eq!(&association[..4], &[5, 0, 0, 1]);
        let relay = std::net::SocketAddr::from((
            [
                association[4],
                association[5],
                association[6],
                association[7],
            ],
            u16::from_be_bytes([association[8], association[9]]),
        ));
        assert!(relay.ip().is_loopback());
        // Exercise an actual datagram flow through the same XHTTP carrier.
        let udp_origin = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp_origin.set_nonblocking(true).unwrap();
        let origin_port = udp_origin.local_addr().unwrap().port();
        let udp_echo = runtime.spawn(async move {
            let socket = tokio::net::UdpSocket::from_std(udp_origin).unwrap();
            let mut buf = [0; 256];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                if socket.send_to(&buf[..n], from).await.is_err() {
                    break;
                }
            }
        });
        let app_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        app_udp
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
        packet.extend_from_slice(&origin_port.to_be_bytes());
        packet.extend_from_slice(b"udp-live");
        app_udp.send_to(&packet, relay).unwrap();
        let mut datagram = [0; 256];
        let (received, source) = app_udp.recv_from(&mut datagram).unwrap();
        assert_eq!(source, relay);
        assert_eq!(&datagram[..received], packet.as_slice());

        assert_eq!(
            query(disconnect),
            Ok(R::ClientDisconnectAccepted {
                revision: first_instance.revision,
                instance: first_instance.instance
            })
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while panel.view.running || panel.view.owned {
            assert!(Instant::now() < deadline, "IPC disconnect did not finish");
            thread::sleep(Duration::from_millis(10));
            panel.poll();
        }
        assert_original();
        for stream in [&mut tcp, &mut udp_control] {
            let mut byte = [0; 1];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) => {}
                result => panic!("session still live after disconnect: {result:?}"),
            }
        }
        app_udp
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let _ = app_udp.send_to(&packet, relay);
        assert!(app_udp.recv_from(&mut datagram).is_err());
        echo_task.abort();
        udp_echo.abort();
        drop(tcp);
        drop(udp_control);
        drop(app_udp);

        action(&mut panel, 'e');
        let R::ClientLifecycle(second_instance) = query(C::ClientLifecycle).unwrap() else {
            panic!("expected reconnected lifecycle");
        };
        assert_ne!(first_instance.instance, second_instance.instance);
        assert_eq!(first_instance.config_sha256, second_instance.config_sha256);
        assert_eq!(query(disconnect), Err(ManagementError::CandidateRejected));
        assert_eq!(native::status().unwrap(), ProxyStatus::PendingOwned);

        // Terminal failure/drop follows the same owned restoration path.
        drop(panel);
        assert_original();

        let saved = Config::Client(doc).to_toml().unwrap();
        fs::write(&path, &saved).unwrap();
        let mut panel = Panel::open(path, Sha256::digest(saved.as_bytes()).into()).unwrap();
        wait(&mut panel);
        review(&mut panel, 'e');
        panel.key(key('n'));
        wait(&mut panel);
        assert!(panel.phase == Phase::Idle && !panel.view.running && !panel.view.owned);
        assert_original();
        crash();
        assert_eq!(native::status().unwrap(), ProxyStatus::PendingOwned);
        review(&mut panel, 'c');
        assert!(panel.body().contains("Требуется проверка / восстановление"));
        assert!(!panel.body().contains("Настройки прокси применены"));
        panel.key(key('n'));
        wait(&mut panel);
        assert_eq!(native::status().unwrap(), ProxyStatus::PendingOwned);
        action(&mut panel, 'c');
        assert!(!panel.body().contains("Настройки прокси применены"));
        assert_original();
        drop(panel);
        drop(bearer);
        server.abort();
        drop(runtime);
        fs::remove_dir_all(directory).unwrap();
        assert_original();
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
            view: View {
                known: true,
                ..View::default()
            },
            message: String::new(),
            unavailable: false,
        };
        assert!(!panel.key(key('y')));
        assert!(receiver.try_recv().is_err());
        assert_eq!(panel.actions()[0].key, 'e');
        panel.key(key('e'));
        assert_eq!(receiver.try_recv(), Ok(Command::Review(Action::Enable)));
        panel.key(key('y'));
        assert!(receiver.try_recv().is_err());
        events
            .send(Event {
                view: View::default(),
                message: "review".into(),
                review: true,
            })
            .unwrap();
        panel.poll();
        assert_eq!(panel.actions()[0].key, 'n');
        assert_eq!(panel.actions()[1].key, 'y');
        panel.key(key('n'));
        assert_eq!(receiver.try_recv(), Ok(Command::Cancel));
        events
            .send(Event {
                view: View::default(),
                message: "cancel".into(),
                review: false,
            })
            .unwrap();
        panel.poll();
        panel.key(key('y'));
        assert!(receiver.try_recv().is_err());
        panel.key(key('c'));
        assert_eq!(receiver.try_recv(), Ok(Command::Review(Action::Recover)));
        events
            .send(Event {
                view: View::default(),
                message: "review".into(),
                review: true,
            })
            .unwrap();
        panel.poll();
        panel.key(key('y'));
        assert_eq!(receiver.try_recv(), Ok(Command::Confirm));
        panel.key(key('y'));
        assert!(receiver.try_recv().is_err());
    }
}
