//! M4.5a: server-only, passive-first local discovery and explicitly consented
//! public-egress observation. Pure UI-state transitions run without network.
//! Only confirming the ipify disclosure starts a cancellable background task.
use crate::{
    camouflage_discovery::POPULAR_HTTPS_DOMAINS,
    camouflage_egress::{
        observe_default_ipify, EgressError, EgressObservation, IpifyConsent,
        DEFAULT_EGRESS_SERVICE_URL,
    },
    camouflage_interfaces::{collect_assigned_interfaces, NativeInterfaces},
    camouflage_workflow::{build_preview, EgressAssessment, PreviewScope},
};
use rustls::RootCertStore;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use tokio::sync::oneshot;

enum Phase {
    Passive,
    Confirm,
    Running {
        result: Receiver<Result<EgressObservation, EgressError>>,
        cancel: Option<oneshot::Sender<()>>,
    },
    Complete(Result<EgressObservation, EgressError>),
}

/// Keeps local observations and consent state entirely separate from the
/// editor, runtime configuration, system proxy and active probe batch.
pub(crate) struct DiscoveryPanel {
    native: NativeInterfaces,
    native_error: Option<&'static str>,
    phase: Phase,
}

impl DiscoveryPanel {
    pub(crate) fn new() -> Self {
        let (native, native_error) = match collect_assigned_interfaces() {
            Ok(native) => (native, None),
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => (
                NativeInterfaces::default(),
                Some("Интерфейсы этой ОС пока не поддерживаются. Показан только каталог доменов."),
            ),
            Err(_) => (
                NativeInterfaces::default(),
                Some("Не удалось прочитать адреса интерфейсов. CIDR не выводится по догадке."),
            ),
        };
        Self {
            native,
            native_error,
            phase: Phase::Passive,
        }
    }

    pub(crate) fn is_consent_pending(&self) -> bool {
        matches!(self.phase, Phase::Confirm)
    }

    pub(crate) fn ask_consent(&mut self) {
        if matches!(self.phase, Phase::Passive | Phase::Complete(_)) {
            self.phase = Phase::Confirm;
        }
    }

    pub(crate) fn decline(&mut self) {
        if matches!(self.phase, Phase::Confirm) {
            self.phase = Phase::Passive;
        }
    }

    /// Starts *only* after an explicit positive confirmation in TUI. Root
    /// certificates load and DNS/TLS run outside the terminal event loop.
    /// No untrusted certificate is ever auto-accepted to make ipify work.
    pub(crate) fn confirm_and_start(&mut self) {
        if !matches!(self.phase, Phase::Confirm) {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let started = std::thread::Builder::new()
            .name("theia-ipify-discovery".to_owned())
            .spawn(move || {
                let result = (|| {
                    let certs = rustls_native_certs::load_native_certs();
                    let mut roots = RootCertStore::empty();
                    let (accepted, _) = roots.add_parsable_certificates(certs.certs);
                    if accepted == 0 {
                        return Some(Err(EgressError::NoTrustAnchors));
                    }
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()?;
                    runtime.block_on(async move {
                        tokio::select! {
                            biased;
                            _ = cancel_rx => None,
                            result = observe_default_ipify(roots, IpifyConsent::Approved) => {
                                Some(result)
                            }
                        }
                    })
                })();
                if let Some(result) = result {
                    let _ = tx.send(result);
                }
            });
        if started.is_err() {
            self.phase = Phase::Complete(Err(EgressError::ConnectFailed));
        } else {
            self.phase = Phase::Running {
                result: rx,
                cancel: Some(cancel_tx),
            };
        }
    }

    pub(crate) fn poll(&mut self) {
        let done = match &self.phase {
            Phase::Running { result, .. } => match result.try_recv() {
                Ok(value) => Some(value),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Err(EgressError::ConnectFailed)),
            },
            _ => None,
        };
        if let Some(report) = done {
            self.phase = Phase::Complete(report);
        }
    }

    pub(crate) fn cancel(&mut self) {
        if let Phase::Running { cancel, .. } = &mut self.phase {
            if let Some(sender) = cancel.take() {
                let _ = sender.send(());
            }
        }
    }

    pub(crate) fn body(&self) -> String {
        let egress = match &self.phase {
            Phase::Complete(Ok(report)) => Some(report),
            _ => None,
        };
        let preview = build_preview(&self.native, egress, PreviewScope::PassiveOnly);
        let assessment = match preview.egress_assessment {
            EgressAssessment::Unknown => "не определено",
            EgressAssessment::MatchesAssignedAddress => "совпадает с назначенным адресом",
            EgressAssessment::DiffersFromAssignedAddress => {
                "отличается от назначенных адресов (возможен NAT/маршрутизация)"
            }
        };
        let local = self.native_error.unwrap_or("Linux: локальные адреса/маски ОС прочитаны.");
        let mut body = format!(
            "Пассивный просмотр сетевых адресов и кандидатов\n\n{local}\nПубличных адресов интерфейсов: {}\nКандидатов в офлайн-плане: {} (популярных доменов: {})\nИсходящий IP: {assessment}\n\nCIDR НЕ сканируются. DNS/TLS-проверки доменов НЕ выполняются.\nНаблюдение ipify не доказывает владение IP, CIDR или NAT.\n",
            preview.assigned_public_addresses,
            preview.plan.candidates.len(),
            POPULAR_HTTPS_DOMAINS.len(),
        );
        match &self.phase {
            Phase::Passive => {
                body.push_str(&format!(
                    "\nСервис по умолчанию: {DEFAULT_EGRESS_SERVICE_URL}\nЗапрос пока НЕ отправлялся.\n\ni: запросить отдельное согласие  Esc: назад"
                ));
            }
            Phase::Confirm => {
                body.push_str(&format!(
                    "\nСОГЛАСИЕ НА ВНЕШНИЙ ЗАПРОС\n\nTheia обратится к {DEFAULT_EGRESS_SERVICE_URL}\nDNS и HTTPS передадут сведения о подключении стороннему сервису.\nСервис увидит ваш публичный исходящий IP.\nОдно обращение, до 5 секунд, только TLS 1.3 с проверкой сертификата.\nСканирование подсети НЕ будет запущено.\n\ny: согласиться и выполнить запрос\nn: отказаться, остаться в пассивном режиме\nEsc: закрыть панель"
                ));
            }
            Phase::Running { .. } => body.push_str(
                "\nHTTPS запрос к ipify выполняется в отдельном потоке.\nEsc: отменить запрос и закрыть панель",
            ),
            Phase::Complete(Ok(report)) => {
                body.push_str(&format!(
                    "\nВнешний IP по утверждению ipify: {}\nTLS-проверка сертификата пройдена. Время: локальное наблюдение.\nРезультат не является разрешением активного сканирования.\n\ni: повторить только с новым согласием  Esc: назад",
                    report.ip()
                ));
            }
            Phase::Complete(Err(error)) => {
                let description = match error {
                    EgressError::NotApproved => "нет разрешения",
                    EgressError::InvalidRequest => "некорректные параметры",
                    EgressError::NoTrustAnchors => "системные доверенные CA не найдены",
                    EgressError::TimedOut => "превышено время запроса",
                    EgressError::ConnectFailed => "DNS или подключение не удалось",
                    EgressError::TlsRejected => "сертификат, TLS или ALPN не прошли проверку",
                    EgressError::InvalidResponse => "ответ сервиса не соответствует формату",
                    EgressError::UnusableAddress => "сервис вернул непригодный IP",
                };
                body.push_str(&format!(
                    "\nОпределение внешнего IP НЕ удалось: {description}.\nНет подтверждённого нового адреса.\n\ni: повторить только с новым согласием  Esc: назад"
                ));
            }
        }
        body
    }
}

impl Drop for DiscoveryPanel {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_initialization_never_requires_external_ipify() {
        let p = DiscoveryPanel::new();
        let body = p.body();
        assert!(matches!(p.phase, Phase::Passive));
        assert!(body.contains("Пассивный"));
        assert!(body.contains("14"));
        assert!(body.contains(DEFAULT_EGRESS_SERVICE_URL));
        assert!(body.contains("Запрос пока НЕ отправлялся."));
        assert!(!p.is_consent_pending());
    }

    #[test]
    fn only_separate_consent_state_can_enable_network_worker() {
        let mut p = DiscoveryPanel::new();
        p.confirm_and_start();
        assert!(matches!(p.phase, Phase::Passive));
        p.ask_consent();
        assert!(p.is_consent_pending());
        assert!(p.body().contains("СОГЛАСИЕ"));
        p.decline();
        assert!(matches!(p.phase, Phase::Passive));
        p.confirm_and_start();
        assert!(matches!(p.phase, Phase::Passive));
    }

    #[test]
    fn cleanup_and_poll_without_running_never_claim_success() {
        let mut p = DiscoveryPanel::new();
        p.poll();
        p.cancel();
        assert!(!p.body().contains("TLS-проверка сертификата пройдена"));
    }
}
