//! M4.5b: one explicitly authorized TLS1.3/h2 observation of a local
//! public IP selected by the operator in server TUI.
//! Nothing scans a CIDR or resolves a seed domain; no probe runs on startup.
use crate::{
    camouflage_batch::{probe_explicit_batch, BatchError, BatchTarget, MAX_EXPLICIT_BATCH},
    camouflage_discovery::{
        plausible_public_address, CandidateHost, CandidateSource, TlsEvidence, Transport,
    },
    camouflage_interfaces::NativeInterfaces,
    camouflage_probe::{ProbeApproval, ProbeError, ProbeReport, ProbeRequest},
    camouflage_workflow::{build_preview, DiscoveryPreview, PreviewScope},
};
use rustls::RootCertStore;
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::mpsc::{self, Receiver, TryRecvError},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

/// All diagnostic labels are fixed from the local evidence rubric.
/// They never include IP/SNI, certificate contents, tokens or user input.
fn translated_blocker(blocker: &str, transport: Transport) -> &'static str {
    match blocker {
        "TLS1.3 not measured" => "TLS1.3 не измерен",
        "TLS1.3 rejected" => "TLS1.3 отклонён",
        "certificate chain unverified" => "цепочка сертификата не проверена",
        "untrusted certificate chain" => "цепочка сертификата не доверена",
        "SNI/SAN not measured" => "SNI/SAN не измерены",
        "SNI/SAN mismatch" => "SNI/SAN не совпадают",
        "certificate validity unverified" => "срок действия сертификата не проверен",
        "certificate expired or not yet valid" => "сертификат просрочен или ещё не действует",
        "reachability unverified" => "доступность не измерена",
        "endpoint unreachable" => "адрес недоступен",
        "ALPN not measured" if transport == Transport::H3 => "H3 ALPN не измерен",
        "ALPN not measured" => "H2 ALPN не измерен",
        "ALPN not supported" if transport == Transport::H3 => "H3 ALPN не поддерживается",
        "ALPN not supported" => "H2 ALPN не поддерживается",
        "Theia fingerprint not measured" => "fingerprint Theia не измерен",
        "Theia fingerprint mismatch" => "fingerprint Theia не совпадает",
        _ => "неподтверждённый критерий",
    }
}

/// This score is derived exclusively from actual structured evidence supplied
/// by strict TLS/H2. It is not a bypass probability, REALITY capability or
/// permission to apply the candidate. H3 and fingerprint remain Unknown.
fn describe_evidence(transport: Transport, evidence: &TlsEvidence) -> String {
    let rating = evidence.suitability(transport);
    let name = match transport {
        Transport::H2 => "H2",
        Transport::H3 => "H3",
    };
    let eligible = if rating.eligible { "ДА" } else { "НЕТ" };
    let reasons = rating
        .blockers
        .iter()
        .map(|reason| translated_blocker(reason, transport))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "{name} score: {}/100, confidence: {}%, eligible: {eligible}.\nПричины: {}.",
        rating.score,
        rating.confidence,
        if reasons.is_empty() { "нет" } else { &reasons }
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeUiError {
    NoTrustAnchors,
    RuntimeUnavailable,
    MissingResult,
    Batch(BatchError),
    Handshake(ProbeError),
}

enum ProbeState {
    Select,
    Confirm {
        address: IpAddr,
    },
    Running {
        address: IpAddr,
        receiver: Receiver<Result<ProbeReport, ProbeUiError>>,
        cancel: Option<oneshot::Sender<()>>,
    },
    Complete {
        address: IpAddr,
        outcome: Result<ProbeReport, ProbeUiError>,
    },
}

/// The only eligible active targets are valid, UP, plausible public IPs
/// *actually assigned to local interfaces*, intersected with the offline
/// ServerAddress plan. Not the remote ipify claim, IPv4 neighbours, provider
/// ranges, seed domains or private addresses. Max 8 selectable entries.
pub(crate) struct ProbePanel {
    preview: DiscoveryPreview,
    server_name: Option<String>,
    targets: Vec<IpAddr>,
    selected: usize,
    state: ProbeState,
    observed_at: Option<Instant>,
}

impl ProbePanel {
    pub(crate) fn new(native: NativeInterfaces, server_name: Option<String>) -> Self {
        let preview = build_preview(&native, None, PreviewScope::PassiveOnly);
        let mut seen = HashSet::new();
        let targets = native
            .interfaces
            .iter()
            .filter(|entry| {
                entry.is_up
                    && plausible_public_address(entry.address)
                    && match entry.address {
                        IpAddr::V4(_) => (1..=32).contains(&entry.prefix_len),
                        IpAddr::V6(_) => (1..=128).contains(&entry.prefix_len),
                    }
            })
            .map(|entry| entry.address)
            .filter(|address| seen.insert(*address))
            .filter(|address| {
                preview.plan.candidates.iter().any(|candidate| {
                    candidate.host == CandidateHost::Ip(*address)
                        && candidate.source == CandidateSource::ServerAddress
                })
            })
            .take(MAX_EXPLICIT_BATCH)
            .collect();
        Self {
            preview,
            server_name: server_name.filter(|name| !name.is_empty()),
            targets,
            selected: 0,
            state: ProbeState::Select,
            observed_at: None,
        }
    }

    pub(crate) fn selected_address(&self) -> Option<IpAddr> {
        self.targets.get(self.selected).copied()
    }

    pub(crate) fn is_available(&self) -> bool {
        self.server_name.is_some() && self.selected_address().is_some()
    }

    pub(crate) fn is_consent_pending(&self) -> bool {
        matches!(self.state, ProbeState::Confirm { .. })
    }

    pub(crate) fn next(&mut self) {
        if matches!(self.state, ProbeState::Select | ProbeState::Complete { .. })
            && !self.targets.is_empty()
        {
            self.selected = (self.selected + 1) % self.targets.len();
            self.state = ProbeState::Select;
        }
    }

    pub(crate) fn previous(&mut self) {
        if matches!(self.state, ProbeState::Select | ProbeState::Complete { .. })
            && !self.targets.is_empty()
        {
            self.selected = (self.selected + self.targets.len() - 1) % self.targets.len();
            self.state = ProbeState::Select;
        }
    }

    pub(crate) fn ask_confirmation(&mut self) {
        if !matches!(self.state, ProbeState::Select | ProbeState::Complete { .. }) {
            return;
        }
        if self.is_available() {
            if let Some(address) = self.selected_address() {
                self.state = ProbeState::Confirm { address };
            }
        }
    }

    pub(crate) fn decline(&mut self) {
        if matches!(self.state, ProbeState::Confirm { .. }) {
            self.state = ProbeState::Select;
        }
    }

    /// No network until the separate exact target and SNI disclosure is
    /// approved with y. Strict TLS/PKI and batch quotas are reused unchanged.
    pub(crate) fn confirm_and_start(&mut self) {
        let address = match self.state {
            ProbeState::Confirm { address } => address,
            _ => return,
        };
        let Some(server_name) = self.server_name.clone() else {
            self.state = ProbeState::Select;
            return;
        };
        self.observed_at = None;
        let preview = self.preview.clone();
        let (tx, rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let started = std::thread::Builder::new()
            .name("theia-exact-h2-probe".to_owned())
            .spawn(move || {
                let outcome = (|| {
                    let certs = rustls_native_certs::load_native_certs();
                    let mut roots = RootCertStore::empty();
                    let (accepted, _) = roots.add_parsable_certificates(certs.certs);
                    if accepted == 0 {
                        return Some(Err(ProbeUiError::NoTrustAnchors));
                    }
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(_) => return Some(Err(ProbeUiError::RuntimeUnavailable)),
                    };
                    runtime.block_on(async move {
                        let request = ProbeRequest {
                            address: SocketAddr::new(address, 443),
                            server_name,
                            deadline: Duration::from_secs(5),
                        };
                        let target = BatchTarget {
                            request,
                            roots,
                            approval: ProbeApproval::public_https_ip(address),
                        };
                        tokio::select! {
                            biased;
                            _ = cancel_rx => None,
                            completed = probe_explicit_batch(&preview, vec![target]) => {
                                Some(completed
                                    .map_err(ProbeUiError::Batch)
                                    .and_then(|batch| {
                                        batch.results.into_iter().next()
                                            .ok_or(ProbeUiError::MissingResult)?
                                            .result.map_err(ProbeUiError::Handshake)
                                    }))
                            }
                        }
                    })
                })();
                if let Some(outcome) = outcome {
                    let _ = tx.send(outcome);
                }
            });
        if started.is_err() {
            self.state = ProbeState::Complete {
                address,
                outcome: Err(ProbeUiError::RuntimeUnavailable),
            };
        } else {
            self.state = ProbeState::Running {
                address,
                receiver: rx,
                cancel: Some(cancel_tx),
            };
        }
    }

    pub(crate) fn poll(&mut self) {
        let received = match &self.state {
            ProbeState::Running {
                address, receiver, ..
            } => match receiver.try_recv() {
                Ok(report) => Some((*address, report)),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => {
                    Some((*address, Err(ProbeUiError::RuntimeUnavailable)))
                }
            },
            _ => None,
        };
        if let Some((address, outcome)) = received {
            self.observed_at = Some(Instant::now());
            self.state = ProbeState::Complete { address, outcome };
        }
    }

    pub(crate) fn cancel(&mut self) {
        if let ProbeState::Running { cancel, .. } = &mut self.state {
            if let Some(sender) = cancel.take() {
                let _ = sender.send(());
            }
        }
    }

    pub(crate) fn body(&self) -> String {
        let mut body =
            String::from("TLS/H2: явная одиночная проверка локального публичного IP\n\n");
        let Some(server_name) = &self.server_name else {
            body.push_str(
                "Недоступно: нужна серверная конфигурация с выбранным inbound и проверенным TLS SNI.\nКонфигурация не загружена. Без SNI TLS не проверяется.\n\nEsc: назад",
            );
            return body;
        };
        if self.targets.is_empty() {
            body.push_str(
                "Нет назначенных публичных адресов. Private/LAN/NAT egress и соседние CIDR не допускаются.\nНи одна цель не будет проверена.\n\nEsc: назад",
            );
            return body;
        }
        let Some(selected) = self.selected_address() else {
            return body;
        };
        body.push_str(&format!(
            "Источники: только UP IP, назначенные локальному интерфейсу; никаких CIDR sweep.\nЦель {}/{}: {}:443\nTLS SNI/SAN: {}\nПроверка CA/TLS1.3/ALPN=h2; максимум 5 секунд.\nОбычный TLS успех НЕ доказывает browser fingerprint, REALITY или обход DPI.\n",
            self.selected + 1,
            self.targets.len(),
            selected,
            server_name
        ));
        match &self.state {
            ProbeState::Select => body.push_str(
                "\n↑/↓ или j/k: выбрать адрес  Enter/t: запросить согласие  Esc: назад",
            ),
            ProbeState::Confirm { address } => body.push_str(&format!(
                "\nСОГЛАСИЕ НА АКТИВНУЮ TLS/H2 ПРОВЕРКУ\n\nОператор подтверждает право проверить ОДИН назначенный IP {}:443\nс SNI {}. Будет отправлен один TLS1.3 handshake без HTTP запроса.\nНи соседние IP, ни популярные домены, ни другие порты не затрагиваются.\n\ny: согласиться и запустить  n: отказаться  Esc: назад",
                address, server_name
            )),
            ProbeState::Running { address, .. } => body.push_str(&format!(
                "\nПроверка {}:443 выполняется в отдельном потоке.\nEsc: отменить и вернуться",
                address
            )),
            ProbeState::Complete {
                address,
                outcome: Ok(report),
            } => {
                if report.connected_ip != *address {
                    body.push_str(
                        "\nIP результата не совпадает с выбранной целью.\nНикакие TLS-свойства этого IP не подтверждены; score: Unknown.\n\nEsc: назад",
                    );
                } else {
                    let age = self.observed_at.map_or_else(
                        || "возраст измерения неизвестен".to_owned(),
                        |instant| format!("{} сек назад", instant.elapsed().as_secs()),
                    );
                    body.push_str(&format!(
                        "\nTLS 1.3 подтверждён для {}:443: CA/SNI/SAN/ALPN=h2 проверены.\nВремя handshake: {} мс. Измерение: {age}.\n{}\n{}\nScore не является вероятностью обхода DPI; REALITY и TLS-in-TLS всё ещё НЕ проверены.\n\nEnter/t: повторить только с новым согласием  Esc: назад",
                        address,
                        report.handshake_elapsed.as_millis(),
                        describe_evidence(Transport::H2, &report.evidence),
                        describe_evidence(Transport::H3, &report.evidence),
                    ));
                }
            },
            ProbeState::Complete {
                outcome: Err(error),
                ..
            } => {
                let code = match error {
                    ProbeUiError::NoTrustAnchors => "не найдено доверенных системных CA",
                    ProbeUiError::RuntimeUnavailable => "невозможно запустить worker",
                    ProbeUiError::MissingResult => "нет результата проверки",
                    ProbeUiError::Batch(BatchError::Empty) => "пустая очередь",
                    ProbeUiError::Batch(BatchError::TooManyTargets) => "лимит целей превышен",
                    ProbeUiError::Batch(BatchError::DuplicateAddress) => "повтор цели",
                    ProbeUiError::Batch(BatchError::NotApproved) => "отсутствует одобрение",
                    ProbeUiError::Batch(BatchError::UnplannedAddress) => {
                        "адрес отсутствует в offline-плане"
                    }
                    ProbeUiError::Batch(BatchError::TaskFailed) => "ошибка worker",
                    ProbeUiError::Batch(BatchError::BatchTimedOut) => "таймаут группы",
                    ProbeUiError::Handshake(ProbeError::NotApproved) => "нет разрешения",
                    ProbeUiError::Handshake(ProbeError::InvalidServerName) => "некорректный SNI",
                    ProbeUiError::Handshake(ProbeError::InvalidDeadline) => "нет deadline",
                    ProbeUiError::Handshake(ProbeError::NoTrustAnchors) => "отсутствуют CA",
                    ProbeUiError::Handshake(ProbeError::TimedOut) => "таймаут TLS",
                    ProbeUiError::Handshake(ProbeError::ConnectFailed) => "TCP недоступен",
                    ProbeUiError::Handshake(ProbeError::TlsRejected) => "TLS/сертификат отклонён",
                    ProbeUiError::Handshake(ProbeError::WrongAlpn) => "нет ALPN h2",
                };
                body.push_str(&format!(
                    "\nTLS/H2 проверка НЕ прошла: {code}. Никакая пригодность не подтверждена.\nH2/H3 score: Unknown, данные handshake отсутствуют; нельзя приписывать положительные баллы.\n\nEnter/t: повторить только с новым согласием  Esc: назад"
                ));
            }
        }
        body
    }
}

impl Drop for ProbePanel {
    fn drop(&mut self) {
        self.cancel();
    }
}

// M4.5b tests: exact assigned public-IP TLS/H2 check UI state.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::camouflage_interfaces::{InterfaceSource, ObservedInterface};
    use std::net::IpAddr;

    fn assigned() -> NativeInterfaces {
        NativeInterfaces {
            interfaces: vec![
                ObservedInterface {
                    interface_name: "eth0".into(),
                    address: "10.0.0.1".parse().unwrap(),
                    prefix_len: 24,
                    is_up: true,
                    source: InterfaceSource::LinuxGetifaddrs,
                },
                ObservedInterface {
                    interface_name: "eth0".into(),
                    address: "93.184.216.10".parse().unwrap(),
                    prefix_len: 29,
                    is_up: true,
                    source: InterfaceSource::LinuxGetifaddrs,
                },
                ObservedInterface {
                    interface_name: "eth1".into(),
                    address: "93.184.216.11".parse().unwrap(),
                    prefix_len: 32,
                    is_up: true,
                    source: InterfaceSource::LinuxGetifaddrs,
                },
                ObservedInterface {
                    interface_name: "eth2".into(),
                    address: "93.184.216.12".parse().unwrap(),
                    prefix_len: 0,
                    is_up: true,
                    source: InterfaceSource::LinuxGetifaddrs,
                },
            ],
        }
    }

    #[test]
    fn no_server_name_means_no_probe_even_for_public_owned_local_address() {
        let mut panel = ProbePanel::new(assigned(), None);
        assert!(!panel.is_available());
        assert!(!panel.is_consent_pending());
        panel.confirm_and_start();
        assert!(!panel.is_consent_pending());
        assert!(panel.body().contains("конфигурация"));
    }

    #[test]
    fn public_assigned_ip_only_and_explicit_confirm_are_required() {
        let mut panel = ProbePanel::new(assigned(), Some("proxy.example.org".to_owned()));
        assert!(panel.is_available());
        assert_eq!(
            panel.selected_address(),
            Some("93.184.216.10".parse::<IpAddr>().unwrap())
        );
        assert!(panel.body().contains("93.184.216.10"));
        assert!(!panel.body().contains("10.0.0.1"));
        assert!(!panel.body().contains("93.184.216.12"));
        panel.confirm_and_start(); // Without confirm, must be inert.
        assert!(!panel.is_consent_pending());

        panel.next();
        assert_eq!(
            panel.selected_address(),
            Some("93.184.216.11".parse().unwrap())
        );
        panel.ask_confirmation();
        assert!(panel.is_consent_pending());
        assert!(panel.body().contains("СОГЛАСИЕ"));
        assert!(panel.body().contains("proxy.example.org"));
        assert!(panel.body().contains("93.184.216.11"));
        panel.decline();
        assert!(!panel.is_consent_pending());
        assert!(!panel.body().contains("TLS 1.3 подтверждён"));
    }

    #[test]
    fn private_down_and_invalid_entries_do_not_become_probe_targets() {
        let mut n = assigned();
        for iface in &mut n.interfaces {
            iface.is_up = false;
        }
        let mut p = ProbePanel::new(n, Some("proxy.example.org".into()));
        assert!(!p.is_available());
        assert!(p.selected_address().is_none());
        p.ask_confirmation();
        assert!(!p.is_consent_pending());
        assert!(p.body().contains("Нет назначенных публичных адресов"));
    }

    #[test]
    fn stalled_tls_probe_result_remains_failure_without_positive_fingerprint_claim() {
        let mut p = ProbePanel::new(assigned(), Some("proxy.example.org".into()));
        let (tx, rx) = std::sync::mpsc::channel();
        let (cancel_tx, _cancelled) = tokio::sync::oneshot::channel();
        p.state = ProbeState::Running {
            address: "93.184.216.10".parse().unwrap(),
            receiver: rx,
            cancel: Some(cancel_tx),
        };
        tx.send(Err(ProbeUiError::Handshake(ProbeError::TimedOut)))
            .unwrap();
        p.poll();
        let text = p.body();
        assert!(text.contains("таймаут TLS"));
        assert!(!text.contains("TLS 1.3 подтверждён"));
        assert!(matches!(
            p.state,
            ProbeState::Complete {
                outcome: Err(_),
                ..
            }
        ));
    }

    #[test]
    fn public_target_choices_are_bounded_even_with_large_interface_inventory() {
        let mut n = NativeInterfaces::default();
        for octet in 10..40 {
            n.interfaces.push(ObservedInterface {
                interface_name: "eth-multi".into(),
                address: format!("93.184.216.{octet}").parse().unwrap(),
                prefix_len: 24,
                is_up: true,
                source: InterfaceSource::LinuxGetifaddrs,
            });
        }
        let p = ProbePanel::new(n, Some("proxy.example.org".into()));
        assert_eq!(p.targets.len(), MAX_EXPLICIT_BATCH);
        assert_eq!(p.selected_address(), Some("93.184.216.10".parse().unwrap()));
    }

    #[test]
    fn verified_h2_gives_only_partial_measured_evidence_not_dpi_eligibility() {
        let mut panel = ProbePanel::new(assigned(), Some("proxy.example.org".to_owned()));
        let ip: IpAddr = "93.184.216.10".parse().unwrap();
        let evidence = crate::camouflage_discovery::TlsEvidence {
            tls13: crate::camouflage_discovery::Observation::Verified,
            trusted_chain: crate::camouflage_discovery::Observation::Verified,
            sni_san_match: crate::camouflage_discovery::Observation::Verified,
            certificate_current: crate::camouflage_discovery::Observation::Verified,
            reachable: crate::camouflage_discovery::Observation::Verified,
            alpn_h2: crate::camouflage_discovery::Observation::Verified,
            alpn_h3: crate::camouflage_discovery::Observation::Unknown,
            theia_fingerprint_match: crate::camouflage_discovery::Observation::Unknown,
        };
        panel.state = ProbeState::Complete {
            address: ip,
            outcome: Ok(ProbeReport {
                connected_ip: ip,
                handshake_elapsed: Duration::from_millis(120),
                evidence,
            }),
        };
        panel.observed_at = Some(Instant::now());
        let text = panel.body();
        assert!(text.contains("H2 score: 80/100"));
        assert!(text.contains("confidence: 85%"));
        assert!(text.contains("H3 score: 65/100"));
        assert!(text.contains("confidence: 71%"));
        assert!(text.contains("fingerprint Theia не измерен"));
        assert!(text.contains("H3 ALPN не измерен"));
        assert!(text.contains("eligible: НЕТ"));
        assert!(!text.contains("eligible: ДА"));
        assert!(text.contains("не является вероятностью"));
        assert!(text.contains("120 мс"));
        assert!(text.contains("сек назад"));
    }

    #[test]
    fn a_mismatched_peer_ip_cannot_be_credited_to_the_selected_target() {
        let mut panel = ProbePanel::new(assigned(), Some("proxy.example.org".to_owned()));
        let requested: IpAddr = "93.184.216.10".parse().unwrap();
        let other: IpAddr = "93.184.216.11".parse().unwrap();
        let evidence = crate::camouflage_discovery::TlsEvidence {
            tls13: crate::camouflage_discovery::Observation::Verified,
            trusted_chain: crate::camouflage_discovery::Observation::Verified,
            sni_san_match: crate::camouflage_discovery::Observation::Verified,
            certificate_current: crate::camouflage_discovery::Observation::Verified,
            reachable: crate::camouflage_discovery::Observation::Verified,
            alpn_h2: crate::camouflage_discovery::Observation::Verified,
            alpn_h3: crate::camouflage_discovery::Observation::Unknown,
            theia_fingerprint_match: crate::camouflage_discovery::Observation::Unknown,
        };
        panel.state = ProbeState::Complete {
            address: requested,
            outcome: Ok(ProbeReport {
                connected_ip: other,
                handshake_elapsed: Duration::from_millis(30),
                evidence,
            }),
        };
        let text = panel.body();
        assert!(text.contains("IP результата не совпадает"));
        assert!(!text.contains("TLS 1.3 подтверждён"));
        assert!(!text.contains("H2 score: 80/100"));
    }

    #[test]
    fn rejected_and_timeout_tls_do_not_get_verified_score_or_stale_report() {
        let mut panel = ProbePanel::new(assigned(), Some("proxy.example.org".to_owned()));
        let ip: IpAddr = "93.184.216.10".parse().unwrap();
        panel.state = ProbeState::Complete {
            address: ip,
            outcome: Err(ProbeUiError::Handshake(ProbeError::WrongAlpn)),
        };
        let text = panel.body();
        assert!(text.contains("нет ALPN h2"));
        assert!(text.contains("score: Unknown"));
        assert!(!text.contains("H2 score: 80/100"));
        assert!(!text.contains("TLS 1.3 подтверждён"));
        let (tx, rx) = std::sync::mpsc::channel();
        let (cancel, _cancelled) = tokio::sync::oneshot::channel();
        panel.state = ProbeState::Running {
            address: ip,
            receiver: rx,
            cancel: Some(cancel),
        };
        tx.send(Err(ProbeUiError::Handshake(ProbeError::TimedOut))).unwrap();
        panel.poll();
        let text = panel.body();
        assert!(text.contains("таймаут TLS"));
        assert!(text.contains("score: Unknown"));
        assert!(!text.contains("H2 score: 80/100"));
        assert!(panel.observed_at.is_some());
    }

    #[test]
    fn drop_cancels_a_running_probe_without_touching_network_in_test() {
        let mut p = ProbePanel::new(assigned(), Some("proxy.example.org".into()));
        let (_result_tx, result_rx) = std::sync::mpsc::channel();
        let (cancel_tx, mut cancelled) = tokio::sync::oneshot::channel();
        p.state = ProbeState::Running {
            address: "93.184.216.10".parse().unwrap(),
            receiver: result_rx,
            cancel: Some(cancel_tx),
        };
        drop(p);
        assert!(cancelled.try_recv().is_ok());
    }
}
