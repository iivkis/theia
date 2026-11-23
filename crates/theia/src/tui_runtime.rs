//! M4.2c: explicit, cancellation-aware server TUI status and auth-only Apply.
//!
//! This panel never reads token digests or private keys. A confirmed request
//! carries the SHA-256 of the exact TOML bytes last loaded or saved by the
//! editor, so an unrelated running server file cannot be silently applied.
//! Expensive work executes outside the ratatui event loop.
use crate::management::{ManagementError, StatusCommand, StatusReply};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver, TryRecvError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Checking,
    Viewing { inbounds: usize, revision: u64 },
    LegacyStatus,
    Confirming { inbounds: usize, revision: u64 },
    Applying,
    Applied { revision: u64 },
    Rejected,
    Indeterminate,
    Unavailable,
}

/// A modal: status is always fetched first. An Apply only happens following
/// the explicit review screen + 'y', with an optimistic revision and the
/// editor's saved document digest. On an ambiguous response the UI must not
/// retry automatically; the operator can query status again with 'r'.
pub(crate) struct RuntimePanel {
    phase: Phase,
    directory: Option<PathBuf>,
    saved_sha256: Option<[u8; 32]>,
    start_with_review: bool,
    receiver: Option<Receiver<Result<StatusReply, ManagementError>>>,
}

impl RuntimePanel {
    pub(crate) fn open(saved_sha256: Option<[u8; 32]>, start_with_review: bool) -> Self {
        Self::open_at(
            std::env::var_os("THEIA_CONTROL_DIR").map(PathBuf::from),
            saved_sha256,
            start_with_review,
        )
    }

    fn open_at(
        directory: Option<PathBuf>,
        saved_sha256: Option<[u8; 32]>,
        start_with_review: bool,
    ) -> Self {
        let mut panel = Self {
            phase: Phase::Checking,
            directory,
            saved_sha256,
            start_with_review: start_with_review && saved_sha256.is_some(),
            receiver: None,
        };
        #[cfg(target_os = "linux")]
        panel.start(StatusCommand::Status);
        #[cfg(not(target_os = "linux"))]
        {
            panel.phase = Phase::Unavailable;
        }
        panel
    }

    fn start(&mut self, command: StatusCommand) {
        let Some(directory) = self.directory.clone() else {
            self.phase = Phase::Unavailable;
            return;
        };
        let (sender, receiver) = mpsc::channel();
        self.receiver = Some(receiver);
        // One thread per explicitly requested operation. Network and OS I/O
        // cannot freeze the UI; the underlying IPC still has its 2s deadline.
        let _worker = std::thread::spawn(move || {
            let result = {
                #[cfg(target_os = "linux")]
                {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| ManagementError::Io)
                        .and_then(|runtime| runtime.block_on(crate::management::query_in(&directory, command)))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (directory, command);
                    Err(ManagementError::Unsupported)
                }
            };
            let _ = sender.send(result);
        });
    }

    fn complete(&mut self, result: Result<StatusReply, ManagementError>) {
        match self.phase {
            Phase::Checking => {
                self.phase = match result {
                    Ok(StatusReply::RunningRevision { inbounds, revision }) => {
                        if self.start_with_review && self.saved_sha256.is_some() {
                            Phase::Confirming { inbounds, revision }
                        } else {
                            Phase::Viewing { inbounds, revision }
                        }
                    }
                    Ok(StatusReply::Running { .. }) => Phase::LegacyStatus,
                    _ => Phase::Unavailable,
                };
                self.start_with_review = false;
            }
            Phase::Applying => {
                self.phase = match result {
                    Ok(StatusReply::Applied { revision }) => Phase::Applied { revision },
                    Err(ManagementError::CandidateRejected) => Phase::Rejected,
                    Err(ManagementError::Unsupported) => Phase::Unavailable,
                    _ => Phase::Indeterminate,
                };
            }
            _ => {}
        }
    }

    pub(crate) fn poll(&mut self) {
        let Some(receiver) = &self.receiver else {
            return;
        };
        let result = receiver.try_recv();
        match result {
            Ok(reply) => {
                self.receiver = None;
                self.complete(reply);
            }
            Err(TryRecvError::Disconnected) => {
                self.receiver = None;
                self.complete(Err(ManagementError::Io));
            }
            Err(TryRecvError::Empty) => {}
        }
    }

    /// Return true to close the modal. While a confirmed Apply is in flight,
    /// Esc/quit cannot pretend to cancel the irreversible IPC request.
    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        match (self.phase, key.code) {
            (Phase::Checking, KeyCode::Esc) => true,
            (Phase::Checking | Phase::Applying, _) => false,
            (Phase::Viewing { inbounds, revision }, KeyCode::Char('a'))
                if self.saved_sha256.is_some() =>
            {
                self.phase = Phase::Confirming { inbounds, revision };
                false
            }
            (Phase::Confirming { inbounds, revision }, KeyCode::Char('n') | KeyCode::Esc) => {
                self.phase = Phase::Viewing { inbounds, revision };
                false
            }
            (Phase::Confirming { revision, .. }, KeyCode::Char('y')) => {
                let Some(candidate_sha256) = self.saved_sha256 else {
                    self.phase = Phase::Unavailable;
                    return false;
                };
                self.phase = Phase::Applying;
                self.start(StatusCommand::ApplyReloadBound {
                    expected_revision: revision,
                    candidate_sha256,
                });
                false
            }
            (Phase::Confirming { .. }, _) => false,
            (_, KeyCode::Char('r')) => {
                self.start_with_review = false;
                self.phase = Phase::Checking;
                self.start(StatusCommand::Status);
                false
            }
            (_, KeyCode::Esc) => true,
            _ => false,
        }
    }

    pub(crate) fn title(&self) -> &'static str {
        match self.phase {
            Phase::Confirming { .. } => "Подтвердить применение авторизации",
            Phase::Applying => "Применение авторизации H2/H3",
            Phase::Applied { .. } => "Применено: подтверждено сервером",
            Phase::Rejected => "Отказ: авторизация не применена",
            Phase::Indeterminate => "Неизвестный результат: проверить статус",
            _ => "Состояние запущенного сервера",
        }
    }

    pub(crate) fn body(&self) -> String {
        match self.phase {
            Phase::Checking => "Запрос IPC status...\nТолько чтение; ничего не применяется.\nEsc: закрыть".into(),
            Phase::Viewing { inbounds, revision } => format!(
                "Сервер работает. Inbounds: {inbounds}. Авторизация: revision={revision}.\n\n{}\nr: обновить статус | Esc: закрыть",
                if self.saved_sha256.is_some() {
                    "a: проверить и подтвердить Apply сохранённого TOML\nПрименяются только token digest/disabled/grants прежних пользователей."
                } else {
                    "Применение недоступно без явного --role server --config FILE."
                }
            ),
            Phase::LegacyStatus => "Сокет сообщает running, но не поддерживает revision/CAS.\nПрименение заблокировано. r: обновить | Esc: закрыть".into(),
            Phase::Confirming { inbounds, revision } => format!(
                "Работает сервер с {inbounds} inbound. Ожидаемая revision={revision}.\n\nВыбран ТОЛЬКО сохранённый TOML. Сервер сверит SHA-256 всех его байтов со своим конфигом и повторно проверит TLS PEM, политику и grants.\nИзменения listener/TLS/квот запрещены. Уже открытые туннели НЕ отзываются.\n\ny: Явно применить авторизацию | n/Esc: отменить"
            ),
            Phase::Applying => "Отправлен подтверждённый CAS Apply.\nОжидается ответ сервера. Не закрывайте панель: запрос может уже выполняться.\nПри потере ACK повторять автоматически запрещено.".into(),
            Phase::Applied { revision } => format!(
                "Сервер подтвердил atomic Apply: authorization revision={revision}.\nНовые запросы H2/H3 используют опубликованный снимок; старые туннели продолжают работу.\nr: новый статус | Esc: закрыть"
            ),
            Phase::Rejected => "Сервер отклонил кандидат или ревизию. Авторизация не применена.\nПроверьте, что TOML не менялся с момента сохранения, сервер использует тот же файл, а TLS PEM/политика неизменны.\nr: запросить фактический статус | Esc: закрыть".into(),
            Phase::Indeterminate => "Ответ IPC потерян или повреждён. Применение МОГЛО произойти.\nПовторять Apply наугад нельзя. Сначала проверьте текущую revision по r: статус, затем перепроверьте TOML.\nEsc: закрыть".into(),
            Phase::Unavailable => "Нет проверенного Linux IPC с revision или приватного THEIA_CONTROL_DIR.\nНичего не применено через эту панель.\nr: повторить проверку | Esc: закрыть".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    fn fake(saved: Option<[u8; 32]>, review: bool) -> RuntimePanel {
        RuntimePanel {
            phase: Phase::Checking,
            directory: None,
            saved_sha256: saved,
            start_with_review: review,
            receiver: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(target_os = "linux")]
    async fn real_private_ipc_status_then_explicit_y_sends_bound_digest_once() {
        use std::{fs, os::unix::fs::PermissionsExt, sync::atomic::{AtomicUsize, Ordering}};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::UnixListener,
            time::{sleep, Duration},
        };

        let dir = std::env::temp_dir().join(format!(
            "theia-tui-ipc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.join("theia-server.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let seen = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        let responder = tokio::spawn(async move {
            let (mut status, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 7];
            status.read_exact(&mut req).await.unwrap();
            assert_eq!(&req, b"status\n");
            counter.fetch_add(1, Ordering::SeqCst);
            status
                .write_all(b"theia-status-v2 running inbounds=2 revision=8\n")
                .await
                .unwrap();
            status.shutdown().await.unwrap();
            drop(status);

            let (mut apply, _) = listener.accept().await.unwrap();
            let expected = format!("apply-reload rev=8 sha256={}\n", "ab".repeat(32));
            let mut req = vec![0u8; expected.len()];
            apply.read_exact(&mut req).await.unwrap();
            assert_eq!(req, expected.as_bytes());
            counter.fetch_add(1, Ordering::SeqCst);
            apply
                .write_all(b"theia-apply-v1 applied revision=9\n")
                .await
                .unwrap();
            apply.shutdown().await.unwrap();
        });
        let mut panel = RuntimePanel::open_at(Some(dir.clone()), Some([0xabu8; 32]), true);
        for _ in 0..100 {
            panel.poll();
            if matches!(panel.phase, Phase::Confirming { .. }) { break; }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(panel.phase, Phase::Confirming { inbounds: 2, revision: 8 });
        assert_eq!(seen.load(Ordering::SeqCst), 1, "status never implicitly commits");
        panel.key(key(KeyCode::Char('n')));
        assert_eq!(seen.load(Ordering::SeqCst), 1);
        panel.key(key(KeyCode::Char('a')));
        panel.key(key(KeyCode::Char('y')));
        for _ in 0..100 {
            panel.poll();
            if matches!(panel.phase, Phase::Applied { .. }) { break; }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(panel.phase, Phase::Applied { revision: 9 });
        assert_eq!(seen.load(Ordering::SeqCst), 2);
        responder.await.unwrap();
        fs::remove_file(socket).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn status_only_and_legacy_socket_cannot_publish_on_y() {
        let mut panel = fake(None, true);
        panel.complete(Ok(StatusReply::RunningRevision {
            inbounds: 1,
            revision: 8,
        }));
        assert_eq!(panel.phase, Phase::Viewing { inbounds: 1, revision: 8 });
        panel.key(key(KeyCode::Char('y')));
        panel.key(key(KeyCode::Char('a')));
        assert_eq!(panel.phase, Phase::Viewing { inbounds: 1, revision: 8 });
        assert!(panel.body().contains("недоступно"));
        let mut legacy = fake(Some([1u8; 32]), true);
        legacy.complete(Ok(StatusReply::Running { inbounds: 1 }));
        assert_eq!(legacy.phase, Phase::LegacyStatus);
        legacy.key(key(KeyCode::Char('y')));
        assert_eq!(legacy.phase, Phase::LegacyStatus);
    }

    #[test]
    fn approval_requires_status_revision_and_a_second_explicit_keystroke() {
        let mut panel = fake(Some([7u8; 32]), true);
        panel.complete(Ok(StatusReply::RunningRevision {
            inbounds: 2,
            revision: 4,
        }));
        assert_eq!(panel.phase, Phase::Confirming { inbounds: 2, revision: 4 });
        assert!(panel.body().contains("revision=4"));
        panel.key(key(KeyCode::Char('n')));
        assert_eq!(panel.phase, Phase::Viewing { inbounds: 2, revision: 4 });
        panel.key(key(KeyCode::Char('a')));
        assert_eq!(panel.phase, Phase::Confirming { inbounds: 2, revision: 4 });
        // Even a lost ACK cannot be reported as definitely rolled back.
        panel.phase = Phase::Applying;
        assert!(!panel.key(key(KeyCode::Esc)));
        panel.complete(Err(ManagementError::TimedOut));
        assert_eq!(panel.phase, Phase::Indeterminate);
        assert!(panel.body().contains("МОГЛО"));
    }

    #[test]
    fn failed_candidate_does_not_create_applied_receipt() {
        let mut panel = fake(Some([9u8; 32]), false);
        panel.phase = Phase::Applying;
        panel.complete(Err(ManagementError::CandidateRejected));
        assert_eq!(panel.phase, Phase::Rejected);
        assert!(!panel.body().contains("authorization revision="));
        panel.phase = Phase::Applying;
        panel.complete(Ok(StatusReply::Applied { revision: 3 }));
        assert_eq!(panel.phase, Phase::Applied { revision: 3 });
    }
}
