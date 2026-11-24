//! M4.5e: two separate opt-in TLS1.3/h2 (TCP) and QUIC/TLS1.3/h3 (UDP)
//! observations of one identical pinned local public IP in server TUI.
//! Nothing scans a CIDR or resolves a seed domain; no probe runs on startup.
use crate::{
    camouflage_batch::MAX_EXPLICIT_BATCH,
    camouflage_discovery::{
        plausible_public_address, CandidateHost, CandidateSource, TlsEvidence, Transport,
    },
    camouflage_dual::{probe_dual_h2_h3, DualProbeError, DualProbeReport, DualProbeTarget},
    camouflage_h3_probe::H3ProbeError,
    camouflage_interfaces::NativeInterfaces,
    camouflage_probe::{ProbeApproval, ProbeError, ProbeRequest},
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

/// Fixed rubric labels only: never render untrusted network strings or
/// reveal TLS headers, certificate contents, private keys or bearer secrets.
fn translated_h2_blocker(blocker: &str) -> &'static str {
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
        "ALPN not measured" => "H2 ALPN не измерен",
        "ALPN not supported" => "H2 ALPN не поддерживается",
        "Theia fingerprint not measured" => "fingerprint Theia не измерен",
        "Theia fingerprint mismatch" => "fingerprint Theia не совпадает",
        _ => "неподтверждённый критерий",
    }
}

/// The only transport measured by the current probe is H2 over TCP/TLS1.3.
/// No H2 TLS fields may be credited to H3, which needs a separate QUIC probe.
fn describe_h2_evidence(evidence: &TlsEvidence) -> String {
    let rating = evidence.suitability(Transport::H2);
    let eligible = if rating.eligible { "ДА" } else { "НЕТ" };
    let reasons = rating
        .blockers
        .iter()
        .map(|reason| translated_h2_blocker(reason))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "H2 score: {}/100, confidence: {}%, eligible: {eligible}.\nПричины: {}.",
        rating.score,
        rating.confidence,
        if reasons.is_empty() {
            "нет"
        } else {
            &reasons
        }
    )
}

/// Only QUIC/TLS1.3/h3 ALPN on the verified exact IP receives H3 credit.
fn describe_h3_evidence(evidence: &TlsEvidence) -> String {
    let rating = evidence.suitability(Transport::H3);
    let reasons = rating
        .blockers
        .iter()
        .map(|reason| translated_h2_blocker(reason))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "H3 score: {}/100, confidence: {}%, eligible: НЕТ.\nПричины: {}.",
        rating.score,
        rating.confidence,
        if reasons.is_empty() {
            "нет"
        } else {
            &reasons
        }
    )
}

fn h2_failure(error: ProbeError) -> &'static str {
    match error {
        ProbeError::NotApproved => "нет согласия",
        ProbeError::InvalidServerName => "SNI некорректен",
        ProbeError::InvalidDeadline => "нет deadline",
        ProbeError::NoTrustAnchors => "нет доверенных CA",
        ProbeError::TimedOut => "таймаут TLS",
        ProbeError::ConnectFailed => "TCP недоступен",
        ProbeError::TlsRejected => "TLS/сертификат отклонён",
        ProbeError::WrongAlpn => "нет ALPN h2",
    }
}

fn h3_failure(error: H3ProbeError) -> &'static str {
    match error {
        H3ProbeError::NotApproved => "нет согласия",
        H3ProbeError::InvalidServerName => "SNI некорректен",
        H3ProbeError::InvalidDeadline => "нет deadline",
        H3ProbeError::NoTrustAnchors => "нет доверенных CA",
        H3ProbeError::TimedOut => "таймаут QUIC",
        H3ProbeError::UdpUnavailable => "UDP недоступен",
        H3ProbeError::BindFailed => "ошибка UDP сокета",
        H3ProbeError::HandshakeRejected => "QUIC/TLS сертификат или ALPN h3 отклонены",
        H3ProbeError::WrongPeer => "IP QUIC peer не совпал с выбранным",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeUiError {
    NoTrustAnchors,
    RuntimeUnavailable,
    Dual(DualProbeError),
}

enum ProbeState {
    Select,
    Confirm {
        address: IpAddr,
    },
    Running {
        address: IpAddr,
        receiver: Receiver<Result<DualProbeReport, ProbeUiError>>,
        cancel: Option<oneshot::Sender<()>>,
    },
    Complete {
        address: IpAddr,
        outcome: Result<DualProbeReport, ProbeUiError>,
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

    /// No TCP or UDP until the operator confirms both exact IP/SNI checks.
    /// Strict TLS/PKI and separate bounded transport quotas are enforced.
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
            .name("theia-exact-h2-h3-probe".to_owned())
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
                        let target = DualProbeTarget {
                            request,
                            roots,
                            approval: ProbeApproval::public_https_ip(address),
                        };
                        tokio::select! {
                            biased;
                            _ = cancel_rx => None,
                            completed = probe_dual_h2_h3(&preview, target) => {
                                Some(completed.map_err(ProbeUiError::Dual))
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
            String::from("TLS/H2 + QUIC/H3: явные проверки одного локального публичного IP\n\n");
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
            "Источники: только UP IP, назначенные локальному интерфейсу; никаких CIDR sweep.\nЦель {}/{}: {}:443 (TCP H2 + UDP H3)\nTLS SNI/SAN: {}\nДВЕ проверки: TLS1.3/ALPN=h2 и QUIC/TLS1.3/ALPN=h3; до 5 секунд на каждую.\nУспех обоих транспортов НЕ доказывает browser fingerprint, REALITY или обход DPI.\n",
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
                "\nСОГЛАСИЕ НА АКТИВНЫЕ H2 И H3 ПРОВЕРКИ\n\nОператор подтверждает право проверить ОДИН назначенный IP {}:443\nс SNI {} по ДВУМ транспортам: TCP/TLS1.3 ALPN=h2 и UDP/QUIC TLS1.3 ALPN=h3.\nДва handshake без HTTP-запросов; ни соседние IP, ни домены, ни другие порты не затрагиваются.\n\ny: согласиться на ОБА запроса  n: отказаться  Esc: назад",
                address, server_name
            )),
            ProbeState::Running { address, .. } => body.push_str(&format!(
                "\nПроверки TCP/H2 и UDP/H3 для {}:443 выполняются в отдельном потоке.\nEsc: отменить оба запроса и вернуться",
                address
            )),
            ProbeState::Complete {
                address,
                outcome: Ok(report),
            } => {
                if report.address != SocketAddr::new(*address, 443)
                    || report
                        .h2
                        .as_ref()
                        .is_ok_and(|h2| h2.connected_ip != *address)
                    || report
                        .h3
                        .as_ref()
                        .is_ok_and(|h3| h3.connected_ip != *address)
                {
                    body.push_str(
                        "\nIP результата не совпадает с выбранной целью.\nНикакие TLS-свойства этого IP не подтверждены; score: Unknown.\n\nEsc: назад",
                    );
                } else {
                    let age = self.observed_at.map_or_else(
                        || "возраст измерения неизвестен".to_owned(),
                        |instant| format!("{} сек назад", instant.elapsed().as_secs()),
                    );
                    body.push_str(&format!(
                        "\nНезависимые результаты TCP/H2 и UDP/H3. Измерение: {age}.\n"
                    ));
                    match &report.h2 {
                        Ok(h2) => body.push_str(&format!(
                            "TLS 1.3 подтверждён для {}:443 по TCP, время handshake: {} мс.\n{}\n",
                            address,
                            h2.handshake_elapsed.as_millis(),
                            describe_h2_evidence(&h2.evidence),
                        )),
                        Err(error) => body.push_str(&format!(
                            "H2: {}, score: Unknown.\n",
                            h2_failure(*error),
                        )),
                    }
                    match &report.h3 {
                        Ok(h3) => body.push_str(&format!(
                            "QUIC/TLS 1.3 + ALPN=h3 подтверждены для {}:443 по UDP, время handshake: {} мс.\n{}\n",
                            address,
                            h3.handshake_elapsed.as_millis(),
                            describe_h3_evidence(&h3.evidence),
                        )),
                        Err(error) => body.push_str(&format!(
                            "H3: {}, score: Unknown.\n",
                            h3_failure(*error),
                        )),
                    }
                    if report.both_transports_verified() {
                        body.push_str(
                            "H2+H3: ОБА TLS/ALPN handshake подтверждены для одного IP/SNI.\n",
                        );
                    } else {
                        body.push_str(
                            "H2+H3: НЕ подтверждены оба транспорта; кандидат НЕ проходит dual-transport gate.\n",
                        );
                    }
                    body.push_str(
                        "REALITY готов: НЕТ. HTTP/3 semantics, fingerprint/identity и anti-DPI НЕ проверены.\nScore не является вероятностью обхода DPI.\n\nEnter/t: повторить только с новым согласием  Esc: назад",
                    );
                }
            }
            ProbeState::Complete {
                outcome: Err(error),
                ..
            } => {
                let code = match error {
                    ProbeUiError::NoTrustAnchors => "не найдены доверенные системные CA",
                    ProbeUiError::RuntimeUnavailable => "невозможно запустить worker",
                    ProbeUiError::Dual(DualProbeError::NotApproved) => "нет согласия на оба транспорта",
                    ProbeUiError::Dual(DualProbeError::InvalidServerName) => "некорректный SNI",
                    ProbeUiError::Dual(DualProbeError::InvalidDeadline) => "некорректный deadline",
                    ProbeUiError::Dual(DualProbeError::NoTrustAnchors) => "отсутствуют CA",
                    ProbeUiError::Dual(DualProbeError::UnplannedAddress) => {
                        "адрес не входит в разрешённый офлайн-план"
                    }
                    ProbeUiError::Dual(DualProbeError::UnplannedDomain) => {
                        "домен не входит в каталог кандидатов"
                    }
                    ProbeUiError::Dual(DualProbeError::DomainNameMismatch) => {
                        "SNI не соответствует явно выбранному домену"
                    }
                    ProbeUiError::Dual(DualProbeError::SelfReference) => "референс совпадает с известным адресом сервера",
                    ProbeUiError::Dual(DualProbeError::DomainAddressMismatch) => {
                        "закреплённый IP домена не соответствует цели"
                    }
                };
                body.push_str(&format!(
                    "\nПроверка H2/H3 НЕ прошла: {code}. Оба транспорта НЕ подтверждены.\nH2/H3 score: Unknown, положительных доказательств нет.\n\nEnter/t: повторить только с новым согласием  Esc: назад"
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
    use crate::camouflage_probe::ProbeReport;
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

    fn failed_dual(ip: IpAddr, h2_error: ProbeError) -> DualProbeReport {
        DualProbeReport {
            address: SocketAddr::new(ip, 443),
            h2: Err(h2_error),
            h3: Err(H3ProbeError::TimedOut),
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
        tx.send(Ok(failed_dual(
            "93.184.216.10".parse().unwrap(),
            ProbeError::TimedOut,
        )))
        .unwrap();
        p.poll();
        let text = p.body();
        assert!(text.contains("таймаут TLS"));
        assert!(!text.contains("TLS 1.3 подтверждён"));
        assert!(matches!(
            p.state,
            ProbeState::Complete { outcome: Ok(_), .. }
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
            outcome: Ok(DualProbeReport {
                address: SocketAddr::new(ip, 443),
                h2: Ok(ProbeReport {
                    connected_ip: ip,
                    handshake_elapsed: Duration::from_millis(120),
                    evidence,
                }),
                h3: Err(H3ProbeError::UdpUnavailable),
            }),
        };
        panel.observed_at = Some(Instant::now());
        let text = panel.body();
        assert!(text.contains("H2 score: 80/100"));
        assert!(text.contains("confidence: 85%"));
        assert!(text.contains("H3: UDP недоступен"));
        assert!(text.contains("H3: UDP недоступен, score: Unknown"));
        assert!(text.contains("fingerprint Theia не измерен"));
        assert!(text.contains("H2+H3: НЕ подтверждены оба транспорта"));
        assert!(text.contains("eligible: НЕТ"));
        assert!(!text.contains("eligible: ДА"));
        assert!(text.contains("не является вероятностью"));
        assert!(text.contains("120 мс"));
        assert!(text.contains("сек назад"));
    }

    #[test]
    fn truly_verified_h2_and_h3_on_one_ip_have_independent_evidence_and_dual_gate() {
        use crate::camouflage_discovery::{Observation, TlsEvidence};
        use crate::camouflage_h3_probe::H3ProbeReport;
        let ip: IpAddr = "93.184.216.10".parse().unwrap();
        let h2 = TlsEvidence {
            tls13: Observation::Verified,
            trusted_chain: Observation::Verified,
            sni_san_match: Observation::Verified,
            certificate_current: Observation::Verified,
            reachable: Observation::Verified,
            alpn_h2: Observation::Verified,
            alpn_h3: Observation::Unknown,
            theia_fingerprint_match: Observation::Unknown,
        };
        let h3 = TlsEvidence {
            alpn_h2: Observation::Unknown,
            alpn_h3: Observation::Verified,
            ..h2
        };
        let mut panel = ProbePanel::new(assigned(), Some("proxy.example.org".into()));
        panel.state = ProbeState::Complete {
            address: ip,
            outcome: Ok(DualProbeReport {
                address: SocketAddr::new(ip, 443),
                h2: Ok(ProbeReport {
                    connected_ip: ip,
                    handshake_elapsed: Duration::from_millis(70),
                    evidence: h2,
                }),
                h3: Ok(H3ProbeReport {
                    connected_ip: ip,
                    handshake_elapsed: Duration::from_millis(85),
                    evidence: h3,
                }),
            }),
        };
        let body = panel.body();
        assert!(body.contains("H2 score: 80/100, confidence: 85%"));
        assert!(body.contains("H3 score: 80/100, confidence: 85%"));
        assert!(body.contains("H2+H3: ОБА TLS/ALPN handshake подтверждены"));
        assert!(body.contains("REALITY готов: НЕТ"));
        assert!(!body.contains("eligible: ДА"));
        assert!(body.contains("не является вероятностью обхода DPI"));
    }

    #[test]
    fn an_h3_only_success_cannot_replace_failed_tcp_h2() {
        use crate::camouflage_discovery::{Observation, TlsEvidence};
        use crate::camouflage_h3_probe::H3ProbeReport;
        let ip: IpAddr = "93.184.216.10".parse().unwrap();
        let mut panel = ProbePanel::new(assigned(), Some("proxy.example.org".into()));
        panel.state = ProbeState::Complete {
            address: ip,
            outcome: Ok(DualProbeReport {
                address: SocketAddr::new(ip, 443),
                h2: Err(ProbeError::WrongAlpn),
                h3: Ok(H3ProbeReport {
                    connected_ip: ip,
                    handshake_elapsed: Duration::from_millis(65),
                    evidence: TlsEvidence {
                        tls13: Observation::Verified,
                        trusted_chain: Observation::Verified,
                        sni_san_match: Observation::Verified,
                        certificate_current: Observation::Verified,
                        reachable: Observation::Verified,
                        alpn_h2: Observation::Unknown,
                        alpn_h3: Observation::Verified,
                        theia_fingerprint_match: Observation::Unknown,
                    },
                }),
            }),
        };
        let body = panel.body();
        assert!(body.contains("H2: нет ALPN h2, score: Unknown"));
        assert!(body.contains("H3 score: 80/100"));
        assert!(body.contains("H2+H3: НЕ подтверждены оба транспорта"));
        assert!(body.contains("REALITY готов: НЕТ"));
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
            outcome: Ok(DualProbeReport {
                address: SocketAddr::new(requested, 443),
                h2: Ok(ProbeReport {
                    connected_ip: other,
                    handshake_elapsed: Duration::from_millis(30),
                    evidence,
                }),
                h3: Err(H3ProbeError::UdpUnavailable),
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
            outcome: Ok(failed_dual(ip, ProbeError::WrongAlpn)),
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
        tx.send(Ok(failed_dual(ip, ProbeError::TimedOut))).unwrap();
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
