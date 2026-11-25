//! M4.2d: cancellation-aware Linux Unix IPC / Windows SID Named Pipe TUI Apply.
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
    Viewing {
        inbounds: usize,
        revision: u64,
    },
    LegacyStatus,
    Confirming {
        inbounds: usize,
        revision: u64,
    },
    Applying,
    RollbackChecking,
    RollbackConfirming {
        revision: u64,
        remaining_seconds: u64,
    },
    RollbackApplying,
    RollbackApplied {
        revision: u64,
    },
    RollbackUnavailable,
    QuotaChecking {
        revision: u64,
    },
    QuotaConfirming {
        revision: u64,
    },
    QuotaApplying,
    QuotaApplied {
        revision: u64,
    },
    QuotaRejected,
    CutoverChecking {
        revision: u64,
    },
    CutoverConfirming {
        revision: u64,
        same_port: bool,
        material_sha256: [u8; 32],
    },
    CutoverApplying,
    CutoverApplied {
        revision: u64,
    },
    CutoverRejected,
    TlsRollbackChecking,
    TlsRollbackConfirming {
        revision: u64,
        remaining_seconds: u64,
    },
    TlsRollbackApplying,
    TlsRollbackApplied {
        revision: u64,
    },
    TlsRollbackUnavailable,
    RestartRollbackChecking,
    RestartRollbackConfirming {
        revision: u64,
        remaining_seconds: u64,
    },
    RestartRollbackApplying,
    RestartRollbackApplied {
        revision: u64,
    },
    RestartRollbackUnavailable,
    Applied {
        revision: u64,
    },
    Rejected,
    Indeterminate,
    Unavailable,
    RestartChecking,
    RestartAuthorizationOnly,
    RestartSamePortTlsReady,
    RestartRequiresMaintenance,
    RestartFreshPortsBindable,
    RestartRejected,
    RestartUnavailable,
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
        #[cfg(target_os = "linux")]
        let endpoint = std::env::var_os("THEIA_CONTROL_DIR").map(PathBuf::from);
        #[cfg(target_os = "windows")]
        let endpoint = std::env::var_os("THEIA_CONTROL_PIPE").map(PathBuf::from);
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        let endpoint: Option<PathBuf> = None;
        Self::open_at(endpoint, saved_sha256, start_with_review)
    }

    /// Explicit read-only restart readiness review. This modal never sends
    /// Apply or attempts a runtime swap, even if the operator presses y.
    pub(crate) fn open_restart() -> Self {
        #[cfg(target_os = "linux")]
        let endpoint = std::env::var_os("THEIA_CONTROL_DIR").map(PathBuf::from);
        #[cfg(target_os = "windows")]
        let endpoint = std::env::var_os("THEIA_CONTROL_PIPE").map(PathBuf::from);
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        let endpoint: Option<PathBuf> = None;
        Self::open_restart_at(endpoint)
    }

    fn open_restart_at(directory: Option<PathBuf>) -> Self {
        let mut panel = Self {
            phase: Phase::RestartChecking,
            directory,
            saved_sha256: None,
            start_with_review: false,
            receiver: None,
        };
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        panel.start(StatusCommand::CheckRestart);
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            panel.phase = Phase::RestartUnavailable;
        }
        panel
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
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        panel.start(StatusCommand::Status);
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            panel.phase = Phase::Unavailable;
        }
        panel
    }

    fn start(&mut self, command: StatusCommand) {
        let Some(directory) = self.directory.clone() else {
            self.phase = if command == StatusCommand::CheckRestart {
                Phase::RestartUnavailable
            } else {
                Phase::Unavailable
            };
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
                        .and_then(|runtime| {
                            runtime.block_on(crate::management::query_in(&directory, command))
                        })
                }
                #[cfg(target_os = "windows")]
                {
                    let _ = directory;
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| ManagementError::Io)
                        .and_then(|runtime| {
                            runtime.block_on(crate::management::query_environment(command))
                        })
                }
                #[cfg(not(any(target_os = "linux", target_os = "windows")))]
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
            Phase::RestartChecking => {
                self.phase = match result {
                    Ok(StatusReply::RestartAuthorizationOnly) => Phase::RestartAuthorizationOnly,
                    Ok(StatusReply::RestartSamePortTlsReady) => Phase::RestartSamePortTlsReady,
                    Ok(StatusReply::RestartRequiresMaintenance) => {
                        Phase::RestartRequiresMaintenance
                    }
                    Ok(StatusReply::RestartFreshPortsBindable) => Phase::RestartFreshPortsBindable,
                    Err(ManagementError::CandidateRejected) => Phase::RestartRejected,
                    _ => Phase::RestartUnavailable,
                };
            }
            Phase::CutoverChecking { revision } => {
                self.phase = match result {
                    Ok(StatusReply::RestartPreview {
                        same_port,
                        material_sha256,
                    }) => Phase::CutoverConfirming {
                        revision,
                        same_port,
                        material_sha256,
                    },
                    _ => Phase::CutoverRejected,
                };
            }
            Phase::CutoverApplying => {
                self.phase = match result {
                    Ok(StatusReply::RestartApplied { revision }) => {
                        Phase::CutoverApplied { revision }
                    }
                    Err(ManagementError::CandidateRejected | ManagementError::Unsupported) => {
                        Phase::CutoverRejected
                    }
                    _ => Phase::Indeterminate,
                };
            }
            Phase::TlsRollbackChecking => {
                self.phase = match result {
                    Ok(StatusReply::TlsRollbackReady {
                        revision,
                        remaining_seconds,
                    }) => Phase::TlsRollbackConfirming {
                        revision,
                        remaining_seconds,
                    },
                    _ => Phase::TlsRollbackUnavailable,
                };
            }
            Phase::TlsRollbackApplying => {
                self.phase = match result {
                    Ok(StatusReply::TlsRollbackApplied { revision }) => {
                        Phase::TlsRollbackApplied { revision }
                    }
                    Err(ManagementError::CandidateRejected | ManagementError::Unsupported) => {
                        Phase::TlsRollbackUnavailable
                    }
                    _ => Phase::Indeterminate,
                };
            }
            Phase::RestartRollbackChecking => {
                self.phase = match result {
                    Ok(StatusReply::RestartRollbackReady {
                        revision,
                        remaining_seconds,
                    }) => Phase::RestartRollbackConfirming {
                        revision,
                        remaining_seconds,
                    },
                    _ => Phase::RestartRollbackUnavailable,
                };
            }
            Phase::RestartRollbackApplying => {
                self.phase = match result {
                    Ok(StatusReply::RestartRollbackApplied { revision }) => {
                        Phase::RestartRollbackApplied { revision }
                    }
                    Err(ManagementError::CandidateRejected | ManagementError::Unsupported) => {
                        Phase::RestartRollbackUnavailable
                    }
                    _ => Phase::Indeterminate,
                };
            }
            Phase::QuotaChecking { revision } => {
                self.phase = match result {
                    Ok(StatusReply::QuotaReady) => Phase::QuotaConfirming { revision },
                    _ => Phase::QuotaRejected,
                };
            }
            Phase::QuotaApplying => {
                self.phase = match result {
                    Ok(StatusReply::QuotaApplied { revision }) => Phase::QuotaApplied { revision },
                    Err(ManagementError::CandidateRejected | ManagementError::Unsupported) => {
                        Phase::QuotaRejected
                    }
                    _ => Phase::Indeterminate,
                };
            }
            Phase::RollbackChecking => {
                self.phase = match result {
                    Ok(StatusReply::AuthRollbackReady {
                        revision,
                        remaining_seconds,
                    }) => Phase::RollbackConfirming {
                        revision,
                        remaining_seconds,
                    },
                    _ => Phase::RollbackUnavailable,
                };
            }
            Phase::RollbackApplying => {
                self.phase = match result {
                    Ok(StatusReply::AuthRollbackApplied { revision }) => {
                        Phase::RollbackApplied { revision }
                    }
                    Err(ManagementError::CandidateRejected) => Phase::Rejected,
                    Err(ManagementError::Unsupported) => Phase::RollbackUnavailable,
                    _ => Phase::Indeterminate,
                };
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
            (Phase::RestartChecking, KeyCode::Esc) => true,
            (Phase::RestartChecking, _) => false,
            (
                Phase::RestartAuthorizationOnly
                | Phase::RestartSamePortTlsReady
                | Phase::RestartRequiresMaintenance
                | Phase::RestartFreshPortsBindable
                | Phase::RestartRejected
                | Phase::RestartUnavailable,
                KeyCode::Char('r'),
            ) => {
                self.phase = Phase::RestartChecking;
                self.start(StatusCommand::CheckRestart);
                false
            }
            (Phase::Checking, KeyCode::Esc) => true,
            (
                Phase::Checking
                | Phase::Applying
                | Phase::RollbackApplying
                | Phase::QuotaApplying
                | Phase::CutoverApplying
                | Phase::RestartRollbackApplying
                | Phase::TlsRollbackApplying,
                _,
            ) => false,
            (
                Phase::CutoverChecking { .. }
                | Phase::RestartRollbackChecking
                | Phase::TlsRollbackChecking,
                KeyCode::Esc,
            ) => true,
            (
                Phase::CutoverChecking { .. }
                | Phase::RestartRollbackChecking
                | Phase::TlsRollbackChecking,
                _,
            ) => false,
            (
                Phase::Viewing { revision, .. }
                | Phase::Applied { revision }
                | Phase::CutoverApplied { revision },
                KeyCode::Char('s'),
            ) if self.saved_sha256.is_some() => {
                let Some(candidate_sha256) = self.saved_sha256 else {
                    return false;
                };
                self.phase = Phase::CutoverChecking { revision };
                self.start(StatusCommand::CheckRestartBound {
                    expected_revision: revision,
                    candidate_sha256,
                });
                false
            }
            (
                Phase::CutoverConfirming {
                    revision,
                    material_sha256,
                    ..
                },
                KeyCode::Char('y'),
            ) => {
                let Some(candidate_sha256) = self.saved_sha256 else {
                    self.phase = Phase::CutoverRejected;
                    return false;
                };
                self.phase = Phase::CutoverApplying;
                self.start(StatusCommand::ApplyRestartBound {
                    expected_revision: revision,
                    candidate_sha256,
                    tls_sha256: material_sha256,
                });
                false
            }
            (Phase::CutoverConfirming { .. }, KeyCode::Char('n') | KeyCode::Esc) => true,
            (Phase::CutoverConfirming { .. }, _) => false,
            (
                Phase::Viewing { .. } | Phase::Applied { .. } | Phase::CutoverApplied { .. },
                KeyCode::Char('z'),
            ) if self.saved_sha256.is_some() => {
                self.phase = Phase::RestartRollbackChecking;
                self.start(StatusCommand::CheckRestartRollback);
                false
            }
            (
                Phase::Viewing { .. } | Phase::Applied { .. } | Phase::CutoverApplied { .. },
                KeyCode::Char('t'),
            ) if self.saved_sha256.is_some() => {
                self.phase = Phase::TlsRollbackChecking;
                self.start(StatusCommand::CheckTlsRollback);
                false
            }
            (Phase::TlsRollbackConfirming { revision, .. }, KeyCode::Char('y')) => {
                self.phase = Phase::TlsRollbackApplying;
                self.start(StatusCommand::ApplyTlsRollback {
                    expected_revision: revision,
                });
                false
            }
            (Phase::TlsRollbackConfirming { .. }, KeyCode::Char('n') | KeyCode::Esc) => true,
            (Phase::TlsRollbackConfirming { .. }, _) => false,
            (Phase::RestartRollbackConfirming { revision, .. }, KeyCode::Char('y')) => {
                self.phase = Phase::RestartRollbackApplying;
                self.start(StatusCommand::ApplyRestartRollback {
                    expected_revision: revision,
                });
                false
            }
            (Phase::RestartRollbackConfirming { .. }, KeyCode::Char('n') | KeyCode::Esc) => true,
            (Phase::RestartRollbackConfirming { .. }, _) => false,
            (Phase::QuotaChecking { .. }, KeyCode::Esc) => true,
            (Phase::QuotaChecking { .. }, _) => false,
            (Phase::Viewing { revision, .. } | Phase::Applied { revision }, KeyCode::Char('c'))
                if self.saved_sha256.is_some() =>
            {
                self.phase = Phase::QuotaChecking { revision };
                self.start(StatusCommand::CheckQuota);
                false
            }
            (Phase::QuotaConfirming { revision }, KeyCode::Char('y')) => {
                let Some(candidate_sha256) = self.saved_sha256 else {
                    self.phase = Phase::QuotaRejected;
                    return false;
                };
                self.phase = Phase::QuotaApplying;
                self.start(StatusCommand::ApplyQuotaBound {
                    expected_revision: revision,
                    candidate_sha256,
                });
                false
            }
            (Phase::QuotaConfirming { .. }, KeyCode::Char('n') | KeyCode::Esc) => true,
            (Phase::QuotaConfirming { .. }, _) => false,
            (Phase::RollbackChecking, KeyCode::Esc) => true,
            (Phase::RollbackChecking, _) => false,
            (Phase::Viewing { .. } | Phase::Applied { .. }, KeyCode::Char('b'))
                if self.saved_sha256.is_some() =>
            {
                self.phase = Phase::RollbackChecking;
                self.start(StatusCommand::CheckAuthRollback);
                false
            }
            (Phase::RollbackConfirming { revision, .. }, KeyCode::Char('y')) => {
                self.phase = Phase::RollbackApplying;
                self.start(StatusCommand::ApplyAuthRollback {
                    expected_revision: revision,
                });
                false
            }
            (Phase::RollbackConfirming { .. }, KeyCode::Char('n') | KeyCode::Esc) => true,
            (Phase::RollbackConfirming { .. }, _) => false,
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
            Phase::RestartChecking
            | Phase::RestartAuthorizationOnly
            | Phase::RestartSamePortTlsReady
            | Phase::RestartRequiresMaintenance
            | Phase::RestartFreshPortsBindable
            | Phase::RestartRejected
            | Phase::RestartUnavailable => "Проверка готовности к перезапуску",
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
            Phase::RestartChecking => "Проверка сохранённого TOML, TLS identity и TCP/UDP в защищённом IPC...\nЭто ТОЛЬКО проверка. Никаких изменений runtime.\nEsc: закрыть".into(),
            Phase::RestartAuthorizationOnly => "Достаточно существующего auth-only CAS Apply; restart не требуется.\nЭтот экран ничего не применяет.\nr: перепроверить | Esc: закрыть".into(),
            Phase::RestartSamePortTlsReady => "Смена TLS identity на тех же TCP/H3 портах подготовима без закрытия слушателей.\nЭта проверка ничего НЕ применяет, действующие туннели не разрываются.\nТолько операторская CLI: сначала server tls fingerprint --config FILE; затем restart --apply --expected-revision N --sha256 TOMLHEX --tls-sha256 PEMHEX --confirm.\nr: перепроверить | Esc: закрыть".into(),
            Phase::RestartRequiresMaintenance => "Для смены listener/TLS/квот нужен контролируемый перерыв: текущий порт не может быть независимо подготовлен.\nСервер работает БЕЗ ИЗМЕНЕНИЙ. НЕ останавливать его на основании этой проверки.\nr: перепроверить | Esc: закрыть".into(),
            Phase::RestartFreshPortsBindable => "Все НОВЫЕ TCP и UDP порты удалось одновременно пробно открыть.\nОни уже освобождены: НЕТ гарантии будущего bind, НЕТ restart, НЕТ rollback.\nСервер работает БЕЗ ИЗМЕНЕНИЙ.\nr: перепроверить | Esc: закрыть".into(),
            Phase::RestartRejected => "Отказ: кандидат TOML, TLS identity или TCP/UDP bind не прошёл проверку.\nСтарые listeners, авторизация и туннели не изменены этой операцией.\nr: перепроверить | Esc: закрыть".into(),
            Phase::RestartUnavailable => "Нет доступного защищённого IPC/снимка конфигурации для проверки restart.\nНичего не изменено.\nr: повторить | Esc: закрыть".into(),
            Phase::CutoverChecking{..}=>"Проверка точного сохранённого TOML и отпечатка материалов; runtime не меняется.".into(),
            Phase::CutoverConfirming{revision,same_port,material_sha256}=>{
                let digest=material_sha256.iter().map(|b|format!("{b:02x}")).collect::<String>();
                let mode=if same_port {"Смена материалов на текущих портах; независимая замена REALITY root необратима. Заменяемые туннели могут завершиться после drain."}else{"Новые порты готовятся до Apply; неизменённые inbound при частичном cutover сохраняются. Удаляемые/заменяемые соединения получают до 20 с на завершение, затем могут быть закрыты."};
                format!("Структурный Apply, revision={revision}.\n{mode}\nОтпечаток материалов SHA-256: {digest}\nСервер повторно проверит TOML, материалы и CAS.\ny: применить | n/Esc: отменить")
            }
            Phase::CutoverApplying=>"Структурный Apply отправлен; при потере ACK сначала запросите фактический статус.".into(),
            Phase::CutoverApplied{revision}=>format!("Структурный Apply подтверждён, revision={revision}.\nz: структурный откат | t: TLS rollback | r: статус | Esc: закрыть"),
            Phase::CutoverRejected=>"Структурный кандидат отклонён: проверьте порты, материалы, сохранённый TOML и revision.\nr: статус | Esc: закрыть".into(),
            Phase::TlsRollbackChecking => "Проверка доступности TLS rollback. Только чтение.".into(),
            Phase::TlsRollbackConfirming { revision, remaining_seconds } => format!("Одноразовый TLS rollback, revision={revision}, осталось {remaining_seconds} с.\nТолько допустимый сервером откат; независимый REALITY root не откатывается. TOML не меняется.\ny: подтвердить | n/Esc: отменить"),
            Phase::TlsRollbackApplying => "TLS rollback отправлен; при потере ACK не повторяйте автоматически.".into(),
            Phase::TlsRollbackApplied { revision } => format!("TLS rollback подтверждён, revision={revision}. TOML не изменён.\nr: статус | Esc: закрыть"),
            Phase::TlsRollbackUnavailable => "TLS rollback недоступен.\nr: статус | Esc: закрыть".into(),
            Phase::RestartRollbackChecking=>"Проверка доступности структурного отката. Только чтение.".into(),
            Phase::RestartRollbackConfirming{revision,remaining_seconds}=>format!("Одноразовый структурный откат, revision={revision}, осталось {remaining_seconds} с.\nСервер заново проверит прежние порты и текущие доверенные материалы. Старые ключи и trust floor не откатываются. TOML не меняется.\ny: подтвердить | n/Esc: отменить"),
            Phase::RestartRollbackApplying=>"Структурный откат отправлен; при потере ACK не повторяйте запрос автоматически.".into(),
            Phase::RestartRollbackApplied{revision}=>format!("Структурный откат подтверждён, revision={revision}. TOML не изменён.\nr: статус | Esc: закрыть"),
            Phase::RestartRollbackUnavailable=>"Структурный откат недоступен: drain, истечение срока, изменение revision или материалов.\nr: статус | Esc: закрыть".into(),
            Phase::QuotaChecking{..}=>"Проверка quota-only кандидата. Runtime не изменяется.".into(),
            Phase::QuotaConfirming{revision}=>format!("Подтвердить изменение только двух лимитов квот, revision={revision}.\nПри уменьшении лимита действующие соединения остаются; новые ждут освобождения занятых слотов.\ny: применить | n/Esc: отменить"),
            Phase::QuotaApplying=>"Отправлен CAS квот. При потере ACK сначала перечитайте revision.".into(),
            Phase::QuotaApplied{revision}=>format!("Квоты применены, revision={revision}. Действующие туннели сохранены.\nr: статус | Esc: закрыть"),
            Phase::QuotaRejected=>"Кандидат квот отклонён. Ничего не применено.\nr: статус | Esc: закрыть".into(),
            Phase::RollbackChecking=>"Проверка доступности одноразового отката авторизации REALITY. Только чтение.".into(),
            Phase::RollbackConfirming{revision,remaining_seconds}=>format!(
                "Откат авторизации, revision={revision}, осталось {remaining_seconds} с.\nПредыдущие пользователи, grants, disabled и digest снова начнут действовать для новых запросов; занятые квоты сохраняются. Доверие, identity, дескрипторы и активные туннели не откатываются. TOML останется без изменений.\ny: подтвердить | n/Esc: отменить"),
            Phase::RollbackApplying=>"Откат отправлен; при потере ответа сначала перечитайте runtime revision.".into(),
            Phase::RollbackApplied{revision}=>format!("Авторизация восстановлена, новая revision={revision}. Слот отката израсходован. TOML не изменён.\nr: статус | Esc: закрыть"),
            Phase::RollbackUnavailable=>"Одноразовый откат недоступен или истёк. Ничего не изменено.\nr: статус | Esc: закрыть".into(),
            Phase::Checking => "Запрос IPC status...\nТолько чтение; ничего не применяется.\nEsc: закрыть".into(),
            Phase::Viewing { inbounds, revision } => format!(
                "Сервер работает. Inbounds: {inbounds}. Авторизация: revision={revision}.\n\n{}\nr: обновить статус | Esc: закрыть",
                if self.saved_sha256.is_some() {
                    "a: проверить и подтвердить Apply сохранённого TOML\nПрименяются пользователи, token digest, disabled и grants; занятость удалённых ID сохраняется до завершения их туннелей.\nb: проверить одноразовый откат авторизации REALITY (300 с).\nc: проверить quota-only Apply.\ns: проверить структурный Apply.\nz: проверить структурный откат.\nt: проверить TLS rollback."
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
            Phase::Unavailable => "Нет проверенного локального IPC с revision (Linux: THEIA_CONTROL_DIR; Windows: THEIA_CONTROL_PIPE).\nНичего не применено через эту панель.\nr: повторить проверку | Esc: закрыть".into(),
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

    #[test]
    fn tls_rollback_requires_separate_confirmation_and_ack() {
        let mut p = fake(Some([1; 32]), false);
        p.phase = Phase::TlsRollbackChecking;
        p.complete(Ok(StatusReply::TlsRollbackReady {
            revision: 7,
            remaining_seconds: 20,
        }));
        assert_eq!(
            p.phase,
            Phase::TlsRollbackConfirming {
                revision: 7,
                remaining_seconds: 20
            }
        );
        assert!(p.body().contains("revision=7"));
        assert!(p.key(key(KeyCode::Char('n'))));
        p.phase = Phase::TlsRollbackApplying;
        p.complete(Ok(StatusReply::TlsRollbackApplied { revision: 8 }));
        assert_eq!(p.phase, Phase::TlsRollbackApplied { revision: 8 });
        p.phase = Phase::TlsRollbackApplying;
        p.complete(Err(ManagementError::Io));
        assert_eq!(p.phase, Phase::Indeterminate);
        p.phase = Phase::TlsRollbackChecking;
        p.complete(Err(ManagementError::Unsupported));
        assert_eq!(p.phase, Phase::TlsRollbackUnavailable);
    }

    #[test]
    fn restart_preview_never_exposes_a_confirmable_apply_even_after_success() {
        for (reply, expected_phase) in [
            (
                Ok(StatusReply::RestartAuthorizationOnly),
                Phase::RestartAuthorizationOnly,
            ),
            (
                Ok(StatusReply::RestartRequiresMaintenance),
                Phase::RestartRequiresMaintenance,
            ),
            (
                Ok(StatusReply::RestartSamePortTlsReady),
                Phase::RestartSamePortTlsReady,
            ),
            (
                Ok(StatusReply::RestartFreshPortsBindable),
                Phase::RestartFreshPortsBindable,
            ),
            (
                Err(ManagementError::CandidateRejected),
                Phase::RestartRejected,
            ),
            (Err(ManagementError::TimedOut), Phase::RestartUnavailable),
        ] {
            let mut panel = fake(None, false);
            panel.phase = Phase::RestartChecking;
            panel.complete(reply);
            assert_eq!(panel.phase, expected_phase);
            assert_eq!(panel.title(), "Проверка готовности к перезапуску");
            panel.key(key(KeyCode::Char('y')));
            panel.key(key(KeyCode::Char('a')));
            assert_eq!(panel.phase, expected_phase, "no key can commit a restart");
            assert!(!panel.body().contains("authorization revision="));
            assert!(panel.key(key(KeyCode::Esc)), "Esc must close the review");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(target_os = "linux")]
    async fn real_private_ipc_status_then_explicit_y_sends_bound_digest_once() {
        use std::{
            fs,
            os::unix::fs::PermissionsExt,
            sync::atomic::{AtomicUsize, Ordering},
        };
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
            if matches!(panel.phase, Phase::Confirming { .. }) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            panel.phase,
            Phase::Confirming {
                inbounds: 2,
                revision: 8
            }
        );
        assert_eq!(
            seen.load(Ordering::SeqCst),
            1,
            "status never implicitly commits"
        );
        panel.key(key(KeyCode::Char('n')));
        assert_eq!(seen.load(Ordering::SeqCst), 1);
        panel.key(key(KeyCode::Char('a')));
        panel.key(key(KeyCode::Char('y')));
        for _ in 0..100 {
            panel.poll();
            if matches!(panel.phase, Phase::Applied { .. }) {
                break;
            }
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
        assert_eq!(
            panel.phase,
            Phase::Viewing {
                inbounds: 1,
                revision: 8
            }
        );
        panel.key(key(KeyCode::Char('y')));
        panel.key(key(KeyCode::Char('a')));
        assert_eq!(
            panel.phase,
            Phase::Viewing {
                inbounds: 1,
                revision: 8
            }
        );
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
        assert_eq!(
            panel.phase,
            Phase::Confirming {
                inbounds: 2,
                revision: 4
            }
        );
        assert!(panel.body().contains("revision=4"));
        panel.key(key(KeyCode::Char('n')));
        assert_eq!(
            panel.phase,
            Phase::Viewing {
                inbounds: 2,
                revision: 4
            }
        );
        panel.key(key(KeyCode::Char('a')));
        assert_eq!(
            panel.phase,
            Phase::Confirming {
                inbounds: 2,
                revision: 4
            }
        );
        // Even a lost ACK cannot be reported as definitely rolled back.
        panel.phase = Phase::Applying;
        assert!(!panel.key(key(KeyCode::Esc)));
        panel.complete(Err(ManagementError::TimedOut));
        assert_eq!(panel.phase, Phase::Indeterminate);
        assert!(panel.body().contains("МОГЛО"));
    }

    #[test]
    fn structural_preview_is_bound_and_never_auto_commits() {
        let mut panel = fake(Some([7; 32]), false);
        panel.phase = Phase::Viewing {
            inbounds: 1,
            revision: 8,
        };
        panel.key(key(KeyCode::Char('y')));
        assert_eq!(
            panel.phase,
            Phase::Viewing {
                inbounds: 1,
                revision: 8
            }
        );
        panel.phase = Phase::CutoverChecking { revision: 8 };
        panel.complete(Ok(StatusReply::RestartPreview {
            same_port: false,
            material_sha256: [9; 32],
        }));
        assert_eq!(
            panel.phase,
            Phase::CutoverConfirming {
                revision: 8,
                same_port: false,
                material_sha256: [9; 32]
            }
        );
        assert!(panel.body().contains("09".repeat(32).as_str()));
        assert!(panel.body().contains("20 с"));
        assert!(panel.key(key(KeyCode::Char('n'))));
        assert!(panel.receiver.is_none());
        panel.phase = Phase::CutoverApplying;
        assert!(!panel.key(key(KeyCode::Esc)));
        panel.complete(Err(ManagementError::TimedOut));
        assert_eq!(panel.phase, Phase::Indeterminate);
        panel.phase = Phase::RestartRollbackChecking;
        panel.complete(Ok(StatusReply::RestartRollbackReady {
            revision: 9,
            remaining_seconds: 123,
        }));
        assert_eq!(
            panel.phase,
            Phase::RestartRollbackConfirming {
                revision: 9,
                remaining_seconds: 123
            }
        );
        assert!(panel.key(key(KeyCode::Esc)));
        panel.phase = Phase::RestartRollbackApplying;
        panel.complete(Ok(StatusReply::RestartRollbackApplied { revision: 10 }));
        assert_eq!(panel.phase, Phase::RestartRollbackApplied { revision: 10 });
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

    #[test]
    fn quota_and_auth_rollback_receipts_require_the_correct_operation() {
        for (checking, reply, confirmed, applying, ack, applied) in [
            (
                Phase::QuotaChecking { revision: 7 },
                StatusReply::QuotaReady,
                Phase::QuotaConfirming { revision: 7 },
                Phase::QuotaApplying,
                StatusReply::QuotaApplied { revision: 8 },
                Phase::QuotaApplied { revision: 8 },
            ),
            (
                Phase::RollbackChecking,
                StatusReply::AuthRollbackReady {
                    revision: 7,
                    remaining_seconds: 123,
                },
                Phase::RollbackConfirming {
                    revision: 7,
                    remaining_seconds: 123,
                },
                Phase::RollbackApplying,
                StatusReply::AuthRollbackApplied { revision: 8 },
                Phase::RollbackApplied { revision: 8 },
            ),
        ] {
            let mut panel = fake(Some([3; 32]), false);
            panel.phase = checking;
            assert!(panel.key(key(KeyCode::Esc)));
            assert!(!panel.key(key(KeyCode::Char('y'))));
            panel.complete(Ok(reply));
            assert_eq!(panel.phase, confirmed);
            assert!(panel.body().contains("revision=7"));
            assert!(panel.key(key(KeyCode::Char('n'))));
            assert!(panel.receiver.is_none());
            panel.phase = applying;
            assert!(!panel.key(key(KeyCode::Esc)));
            assert!(!panel.body().is_empty());
            let (tx, rx) = mpsc::channel();
            panel.receiver = Some(rx);
            panel.poll();
            assert_eq!(panel.phase, applying);
            tx.send(Ok(ack)).unwrap();
            panel.poll();
            assert_eq!(panel.phase, applied);
            assert!(panel.body().contains("revision=8"));
            assert!(panel.receiver.is_none());
            panel.phase = applying;
            let (tx, rx) = mpsc::channel();
            panel.receiver = Some(rx);
            drop(tx);
            panel.poll();
            assert_eq!(panel.phase, Phase::Indeterminate);
            assert!(panel.body().contains("МОГЛО"));
            panel.phase = checking;
            panel.complete(Err(ManagementError::CandidateRejected));
            assert!(matches!(
                panel.phase,
                Phase::QuotaRejected | Phase::RollbackUnavailable
            ));
        }
    }

    #[test]
    fn rejected_and_ambiguous_operation_results_are_not_success_receipts() {
        for (phase, rejected) in [
            (Phase::CutoverApplying, Phase::CutoverRejected),
            (
                Phase::RestartRollbackApplying,
                Phase::RestartRollbackUnavailable,
            ),
            (Phase::QuotaApplying, Phase::QuotaRejected),
            (Phase::RollbackApplying, Phase::Rejected),
            (Phase::Applying, Phase::Rejected),
        ] {
            let mut panel = fake(Some([3; 32]), false);
            panel.phase = phase;
            panel.complete(Err(ManagementError::CandidateRejected));
            assert_eq!(panel.phase, rejected);
            assert!(!panel.body().contains("revision=8"));
            panel.phase = phase;
            panel.complete(Ok(StatusReply::Running { inbounds: 2 }));
            assert_eq!(panel.phase, Phase::Indeterminate);
        }
        let mut panel = fake(Some([3; 32]), false);
        panel.phase = Phase::CutoverChecking { revision: 7 };
        panel.complete(Ok(StatusReply::RestartPreview {
            same_port: true,
            material_sha256: [5; 32],
        }));
        assert!(panel.body().contains("Смена TLS на текущих портах"));
        panel.phase = Phase::CutoverApplying;
        panel.complete(Ok(StatusReply::RestartApplied { revision: 8 }));
        assert_eq!(panel.phase, Phase::CutoverApplied { revision: 8 });
        assert!(panel.body().contains("revision=8"));
        panel.phase = Phase::RestartRollbackChecking;
        panel.complete(Err(ManagementError::TimedOut));
        assert_eq!(panel.phase, Phase::RestartRollbackUnavailable);
        panel.phase = Phase::CutoverChecking { revision: 8 };
        panel.complete(Err(ManagementError::CandidateRejected));
        assert_eq!(panel.phase, Phase::CutoverRejected);
    }

    #[test]
    fn unavailable_endpoint_cannot_confirm_or_dispatch_mutations() {
        let initial = Phase::Viewing {
            inbounds: 1,
            revision: 7,
        };
        for action in ['a', 'b', 'c', 's', 'z'] {
            let mut panel = fake(None, false);
            panel.phase = initial;
            assert!(!panel.key(key(KeyCode::Char(action))));
            assert_eq!(panel.phase, initial);
            assert!(panel.receiver.is_none());
        }
        for action in ['b', 'c', 's', 'z'] {
            let mut panel = fake(Some([1; 32]), false);
            panel.phase = initial;
            assert!(!panel.key(key(KeyCode::Char(action))));
            assert_eq!(panel.phase, Phase::Unavailable);
            assert!(panel.receiver.is_none());
        }
        for phase in [
            Phase::Confirming {
                inbounds: 1,
                revision: 7,
            },
            Phase::QuotaConfirming { revision: 7 },
            Phase::CutoverConfirming {
                revision: 7,
                same_port: true,
                material_sha256: [2; 32],
            },
            Phase::RollbackConfirming {
                revision: 7,
                remaining_seconds: 10,
            },
            Phase::RestartRollbackConfirming {
                revision: 7,
                remaining_seconds: 10,
            },
        ] {
            let mut panel = fake(Some([1; 32]), false);
            panel.phase = phase;
            assert!(!panel.key(key(KeyCode::Char('y'))));
            assert_eq!(panel.phase, Phase::Unavailable);
            assert!(panel.receiver.is_none());
        }
        for (phase, refused) in [
            (
                Phase::Confirming {
                    inbounds: 1,
                    revision: 7,
                },
                Phase::Unavailable,
            ),
            (Phase::QuotaConfirming { revision: 7 }, Phase::QuotaRejected),
            (
                Phase::CutoverConfirming {
                    revision: 7,
                    same_port: true,
                    material_sha256: [2; 32],
                },
                Phase::CutoverRejected,
            ),
        ] {
            let mut panel = fake(None, false);
            panel.phase = phase;
            assert!(!panel.key(key(KeyCode::Char('y'))));
            assert_eq!(panel.phase, refused);
            assert!(panel.receiver.is_none());
        }
    }

    #[test]
    fn unsupported_mutations_never_display_success_or_retry() {
        for (phase, result) in [
            (Phase::CutoverApplying, Phase::CutoverRejected),
            (
                Phase::RestartRollbackApplying,
                Phase::RestartRollbackUnavailable,
            ),
            (Phase::QuotaApplying, Phase::QuotaRejected),
            (Phase::RollbackApplying, Phase::RollbackUnavailable),
            (Phase::Applying, Phase::Unavailable),
        ] {
            let mut panel = fake(Some([1; 32]), false);
            panel.phase = phase;
            panel.complete(Err(ManagementError::Unsupported));
            assert_eq!(panel.phase, result);
            assert!(!panel.body().contains("revision=8"));
            assert!(!panel.key(key(KeyCode::Char('y'))));
            assert_eq!(panel.phase, result);
            assert!(panel.receiver.is_none());
        }
        let mut panel = fake(None, false);
        panel.phase = Phase::RestartChecking;
        assert!(panel.key(key(KeyCode::Esc)));
        assert!(!panel.key(key(KeyCode::Char('y'))));
        panel.complete(Ok(StatusReply::RestartAuthorizationOnly));
        assert!(!panel.key(key(KeyCode::Char('r'))));
        assert_eq!(panel.phase, Phase::RestartUnavailable);
        assert!(panel.receiver.is_none());
    }
}
