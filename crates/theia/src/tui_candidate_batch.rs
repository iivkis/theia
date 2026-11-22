//! M4.5g: select *individual* IPs from a previously reviewed offline
//! server/CIDR plan; probe H2 + H3 only after a second explicit batch consent.
//!
//! An assigned interface mask does not establish CIDR ownership. The UI
//! requires per-IP selection, independently disclosed exact targets and SNI,
//! then an additional y; no automatic subnet sweep, DNS or configuration Apply.
use crate::{
    camouflage_discovery::{CandidateHost, CandidateSource},
    camouflage_dual::{CandidateConsent, DualProbeError, DualProbeTarget},
    camouflage_dual_batch::{
        probe_dual_batch, DualBatchError, DualBatchReport, DualBatchTarget, MAX_DUAL_BATCH,
    },
    camouflage_probe::{ProbeApproval, ProbeRequest},
    camouflage_workflow::DiscoveryPreview,
};
use rustls::RootCertStore;
use std::{
    net::{IpAddr, SocketAddr},
    sync::mpsc::{self, Receiver, TryRecvError},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

const MAX_VISIBLE_TARGETS: usize = 7;
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchUiError {
    NoTrustAnchors,
    WorkerUnavailable,
    Batch(DualBatchError),
}

enum BatchState {
    Select,
    Confirm,
    Running {
        result: Receiver<Result<DualBatchReport, BatchUiError>>,
        cancel: Option<oneshot::Sender<()>>,
    },
    Complete(Result<DualBatchReport, BatchUiError>),
}

/// One disposable, operator-approved review. The input is an immutable
/// snapshot of offline *local* discovery, not a DNS/BGP/egress-derived scan.
pub(crate) struct CandidateBatchPanel {
    preview: DiscoveryPreview,
    server_name: Option<String>,
    entries: Vec<(IpAddr, CandidateSource)>,
    cursor: usize,
    selected: Vec<IpAddr>,
    state: BatchState,
    observed_at: Option<Instant>,
}

impl CandidateBatchPanel {
    pub(crate) fn new(preview: DiscoveryPreview, server_name: Option<String>) -> Self {
        let mut entries = Vec::new();
        for candidate in &preview.plan.candidates {
            if let CandidateHost::Ip(ip) = candidate.host {
                if matches!(
                    candidate.source,
                    CandidateSource::ServerAddress | CandidateSource::AuthorizedSubnet
                ) && !entries.iter().any(|(existing, _)| *existing == ip)
                {
                    entries.push((ip, candidate.source));
                }
            }
        }
        Self {
            preview,
            server_name: server_name.filter(|name| !name.is_empty()),
            entries,
            cursor: 0,
            selected: Vec::new(),
            state: BatchState::Select,
            observed_at: None,
        }
    }

    pub(crate) fn available_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn selected_count(&self) -> usize {
        self.selected.len()
    }

    pub(crate) fn is_confirming(&self) -> bool {
        matches!(self.state, BatchState::Confirm)
    }

    pub(crate) fn is_running(&self) -> bool {
        matches!(self.state, BatchState::Running { .. })
    }

    pub(crate) fn next(&mut self) {
        if matches!(self.state, BatchState::Select | BatchState::Complete(_))
            && !self.entries.is_empty()
        {
            self.cursor = (self.cursor + 1) % self.entries.len();
            self.state = BatchState::Select;
        }
    }

    pub(crate) fn previous(&mut self) {
        if matches!(self.state, BatchState::Select | BatchState::Complete(_))
            && !self.entries.is_empty()
        {
            self.cursor = (self.cursor + self.entries.len() - 1) % self.entries.len();
            self.state = BatchState::Select;
        }
    }

    pub(crate) fn toggle_current(&mut self) {
        if !matches!(self.state, BatchState::Select | BatchState::Complete(_)) {
            return;
        }
        let Some(&(ip, _)) = self.entries.get(self.cursor) else {
            return;
        };
        if let Some(index) = self.selected.iter().position(|value| *value == ip) {
            self.selected.remove(index);
        } else if self.selected.len() < MAX_DUAL_BATCH {
            self.selected.push(ip);
        }
        self.state = BatchState::Select;
    }

    fn pending_targets(&self) -> Vec<IpAddr> {
        self.selected.clone()
    }

    /// Enter is a preview, NOT consent. Never open a socket in this method.
    pub(crate) fn ask_confirmation(&mut self) {
        if !matches!(self.state, BatchState::Select | BatchState::Complete(_))
            || self.server_name.is_none()
            || self.selected.is_empty()
        {
            return;
        }
        self.state = BatchState::Confirm;
    }

    pub(crate) fn decline(&mut self) {
        if self.is_confirming() {
            self.state = BatchState::Select;
        }
    }

    /// Only the final separate y authorizes the listed exact TCP+UDP sockets.
    /// Re-validates the entire batch in camouflage_dual_batch BEFORE any I/O.
    pub(crate) fn confirm_and_start(&mut self) {
        if !self.is_confirming() {
            return;
        }
        let Some(server_name) = self.server_name.clone() else {
            self.state = BatchState::Select;
            return;
        };
        let addresses = self.pending_targets();
        if addresses.is_empty() || addresses.len() > MAX_DUAL_BATCH {
            self.state = BatchState::Select;
            return;
        }
        let preview = self.preview.clone();
        let (tx, rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.observed_at = None;
        let started = std::thread::Builder::new()
            .name("theia-exact-h2-h3-cidr-batch".to_owned())
            .spawn(move || {
                let result = (|| {
                    let certs = rustls_native_certs::load_native_certs();
                    let mut roots = RootCertStore::empty();
                    let (trusted, _) = roots.add_parsable_certificates(certs.certs);
                    if trusted == 0 {
                        return Some(Err(BatchUiError::NoTrustAnchors));
                    }
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(_) => return Some(Err(BatchUiError::WorkerUnavailable)),
                    };
                    let targets = addresses
                        .into_iter()
                        .map(|ip| DualBatchTarget {
                            target: DualProbeTarget {
                                request: ProbeRequest {
                                    address: SocketAddr::new(ip, 443),
                                    server_name: server_name.clone(),
                                    deadline: HANDSHAKE_DEADLINE,
                                },
                                roots: roots.clone(),
                                approval: ProbeApproval::public_https_ip(ip),
                            },
                            consent: CandidateConsent::PlannedIp,
                        })
                        .collect();
                    runtime.block_on(async move {
                        tokio::select! {
                            biased;
                            _ = cancel_rx => None,
                            result = probe_dual_batch(&preview, targets) => {
                                Some(result.map_err(BatchUiError::Batch))
                            }
                        }
                    })
                })();
                if let Some(result) = result {
                    let _ = tx.send(result);
                }
            });
        if started.is_err() {
            self.state = BatchState::Complete(Err(BatchUiError::WorkerUnavailable));
        } else {
            self.state = BatchState::Running {
                result: rx,
                cancel: Some(cancel_tx),
            };
        }
    }

    pub(crate) fn poll(&mut self) {
        let response = match &self.state {
            BatchState::Running { result, .. } => match result.try_recv() {
                Ok(value) => Some(value),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Err(BatchUiError::WorkerUnavailable)),
            },
            _ => None,
        };
        if let Some(outcome) = response {
            self.observed_at = Some(Instant::now());
            self.state = BatchState::Complete(outcome);
        }
    }

    pub(crate) fn cancel(&mut self) {
        if let BatchState::Running { cancel, .. } = &mut self.state {
            if let Some(signal) = cancel.take() {
                let _ = signal.send(());
            }
        }
    }

    /// Escape from confirmation returns to selection. Escape from the list
    /// or the completed/running view leaves and discards all scope/consent.
    pub(crate) fn back_or_close(&mut self) -> bool {
        if self.is_confirming() {
            self.decline();
            false
        } else {
            if self.is_running() {
                self.cancel();
            }
            true
        }
    }

    pub(crate) fn body(&self) -> String {
        let mut out =
            String::from("F-18: выбранные вручную IP из offline-плана, H2 + H3 (без DNS)\n\n");
        if self.server_name.is_none() {
            out.push_str("Нет серверной конфигурации или SNI выбранного inbound.\nНикакие TLS-запросы не выполняются. Esc: назад");
            return out;
        }
        if self.available_count() == 0 {
            out.push_str(
                "Нет доступных публичных IP-кандидатов в offline-плане.\nНикакие TLS-запросы не выполняются. Esc: назад",
            );
            return out;
        }
        match &self.state {
            BatchState::Select => {
                let start = self.cursor.saturating_sub(MAX_VISIBLE_TARGETS / 2).min(
                    self.entries.len().saturating_sub(MAX_VISIBLE_TARGETS),
                );
                out.push_str(&format!(
                    "Доступно IP: {}. Выбрано: {}/{} (не подтверждено).\n",
                    self.available_count(),
                    self.selected_count(),
                    MAX_DUAL_BATCH
                ));
                for (index, (ip, source)) in self.entries.iter().enumerate().skip(start).take(MAX_VISIBLE_TARGETS) {
                    let marker = if index == self.cursor { ">" } else { " " };
                    let checked = if self.selected.contains(ip) { "x" } else { " " };
                    let group = match source {
                        CandidateSource::ServerAddress => "назначен серверу",
                        CandidateSource::AuthorizedSubnet => "Подсеть: заявлен оператором",
                        CandidateSource::PopularDomain => "каталог доменов (не IP)",
                    };
                    out.push_str(&format!("{marker}[{checked}] {ip}:443  {group}\n"));
                }
                out.push_str(
                    "\nj/k: выбрать IP  Space: вручную отметить/снять (до 8)\nEnter: проверить точный список перед двумя соединениями на IP\nEsc: назад, без сканирования\n\nМаска интерфейса не доказывает владение подсетью.\nНужны отдельные права на КАЖДЫЙ отмеченный адрес.",
                );
            }
            BatchState::Confirm => {
                out.push_str(&format!(
                    "ОДОБРЕНИЕ активной проверки только перечисленных целей ({}):\n",
                    self.selected.len()
                ));
                for ip in &self.selected {
                    out.push_str(&format!("  {ip}:443  TCP/H2 + UDP/H3\n"));
                }
                out.push_str(&format!(
                    "\nSNI/SAN: {}\nМаксимум 8 IP, 2 одновременно, 5с/цель и 20с/набор.\nПроверяются только TCP/TLS1.3/h2 и UDP/QUIC/TLS1.3/h3.\nПодтверждая y, оператор заявляет проверенные права на КАЖДЫЙ IP.\nСоседи, не отмеченные Space, не проверяются.\nЭто НЕ доказательство владения и НЕ REALITY-ready.\n\ny: разрешить все показанные точные проверки\nn: отказаться  Esc: вернуться к выбору",
                    self.server_name.as_deref().unwrap_or("нет"),
                ));
            }
            BatchState::Running { .. } => out.push_str(
                "Одобренные TCP/H2 и UDP/H3 проверки выполняются в worker.\nEsc: отменить все оставшиеся проверки, не ждать завершения",
            ),
            BatchState::Complete(Err(error)) => {
                let reason = match error {
                    BatchUiError::NoTrustAnchors => "нет доверенных системных CA",
                    BatchUiError::WorkerUnavailable => "worker недоступен",
                    BatchUiError::Batch(DualBatchError::Empty) => "пустой набор",
                    BatchUiError::Batch(DualBatchError::TooManyTargets) => "целей больше восьми",
                    BatchUiError::Batch(DualBatchError::DuplicateTarget) => "дублирующаяся цель",
                    BatchUiError::Batch(DualBatchError::Target(_)) => "цель не соответствует согласованному offline-плану или CA/SNI",
                    BatchUiError::Batch(DualBatchError::TaskFailed) => "ошибка задачи",
                    BatchUiError::Batch(DualBatchError::BatchTimedOut) => "таймаут группы 20с",
                };
                out.push_str(&format!(
                    "Набор НЕ проверен: {reason}.\nH2/H3 score: Unknown, REALITY: НЕ готов.\nEsc: назад",
                ));
            }
            BatchState::Complete(Ok(report)) => {
                let age = self.observed_at.map_or_else(
                    || "давность неизвестна".to_owned(),
                    |t| format!("{} сек назад", t.elapsed().as_secs()),
                );
                out.push_str(&format!(
                    "Проверено целей: {}. Совместимы по H2+H3: {}/{}; измерение: {age}.\n",
                    report.results.len(),
                    report.dual_verified_count(),
                    report.results.len(),
                ));
                for entry in &report.results {
                    match &entry.result {
                        Ok(both) if both.address == entry.address => {
                            let h2 = match &both.h2 {
                                Ok(observed) if observed.connected_ip == entry.address.ip() => {
                                    let score = observed.evidence.suitability(
                                        crate::camouflage_discovery::Transport::H2,
                                    );
                                    format!("H2: {}% / {}%", score.score, score.confidence)
                                }
                                _ => "H2: отказ/Unknown".to_owned(),
                            };
                            let h3 = match &both.h3 {
                                Ok(observed) if observed.connected_ip == entry.address.ip() => {
                                    let score = observed.evidence.suitability(
                                        crate::camouflage_discovery::Transport::H3,
                                    );
                                    format!("H3: {}% / {}%", score.score, score.confidence)
                                }
                                _ => "H3: отказ/Unknown".to_owned(),
                            };
                            let dual = if both.both_transports_verified() {
                                "оба подтверждены"
                            } else {
                                "НЕ прошёл оба"
                            };
                            out.push_str(&format!(
                                "{}:443  {h2}; {h3}; {dual}\n",
                                entry.address.ip(),
                            ));
                        }
                        _ => out.push_str(&format!(
                            "{}:443  H2: отказ/Unknown; H3: отказ/Unknown; НЕ прошёл оба\n",
                            entry.address.ip(),
                        )),
                    }
                }
                out.push_str(
                    "\nREALITY: НЕ готов. Fingerprint, HTTP/3 semantics, server identity и anti-DPI не проверены.\nScore не является вероятностью обхода DPI. Нет Apply/сохранения/автоподбора.\nEsc: вернуться",
                );
            }
        }
        out
    }
}

impl Drop for CandidateBatchPanel {
    fn drop(&mut self) {
        self.cancel();
    }
}

// M4.5g TDD: no active CIDR probing without exact target selection and y.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        camouflage_discovery::{CandidateSource, NetworkPrefix},
        camouflage_interfaces::{InterfaceSource, NativeInterfaces, ObservedInterface},
        camouflage_workflow::{build_preview, PreviewScope},
    };

    fn native() -> NativeInterfaces {
        NativeInterfaces {
            interfaces: vec![
                ObservedInterface {
                    interface_name: "eth0".to_owned(),
                    address: "93.184.216.10".parse().unwrap(),
                    prefix_len: 29,
                    is_up: true,
                    source: InterfaceSource::LinuxGetifaddrs,
                },
                ObservedInterface {
                    interface_name: "lo".to_owned(),
                    address: "127.0.0.1".parse().unwrap(),
                    prefix_len: 8,
                    is_up: true,
                    source: InterfaceSource::LinuxGetifaddrs,
                },
            ],
        }
    }

    fn panel(with_cidr: bool) -> CandidateBatchPanel {
        let native = native();
        let preview = if with_cidr {
            let subnet: NetworkPrefix = "93.184.216.10/29".parse().unwrap();
            build_preview(
                &native,
                None,
                PreviewScope::OperatorApprovedCidrs(&[subnet]),
            )
        } else {
            build_preview(&native, None, PreviewScope::PassiveOnly)
        };
        CandidateBatchPanel::new(preview, Some("proxy.example.org".to_owned()))
    }

    #[test]
    fn passive_overview_lists_only_actually_assigned_public_ip_and_never_auto_selects() {
        let mut panel = panel(false);
        assert_eq!(panel.available_count(), 1);
        assert_eq!(panel.selected_count(), 0);
        assert!(panel.body().contains("93.184.216.10"));
        assert!(!panel.body().contains("127.0.0.1"));
        assert!(!panel.body().contains("93.184.216.9"));
        panel.ask_confirmation();
        assert!(!panel.is_confirming());
        panel.confirm_and_start(); // impossible to bypass selection + consent
        assert!(!panel.is_running());
    }

    #[test]
    fn reviewed_subnet_requires_explicit_ip_by_ip_checkbox_selection_and_final_y() {
        let mut panel = panel(true);
        assert_eq!(panel.available_count(), 6); // local .10 + five extra /29 hosts
        assert_eq!(panel.selected_count(), 0);
        assert!(panel.body().contains("Подсеть"));
        panel.toggle_current();
        assert_eq!(panel.selected_count(), 1);
        panel.next();
        panel.toggle_current();
        assert_eq!(panel.selected_count(), 2);
        panel.ask_confirmation();
        assert!(panel.is_confirming());
        assert!(!panel.is_running());
        let message = panel.body();
        assert!(message.contains("TCP/H2"));
        assert!(message.contains("UDP/H3"));
        assert!(message.contains("proxy.example.org"));
        assert!(message.contains("ОДОБРЕНИЕ"));
        assert!(message.contains("93.184.216.10:443"));
        assert!(message.contains("93.184.216.9:443"));
        panel.decline();
        assert!(!panel.is_confirming());
        assert_eq!(panel.selected_count(), 2);
        assert!(!panel.is_running());
    }

    #[test]
    fn duplicate_toggles_remove_ip_and_never_increase_unique_selection() {
        let mut panel = panel(true);
        panel.toggle_current();
        panel.toggle_current();
        assert_eq!(panel.selected_count(), 0);
        panel.ask_confirmation();
        assert!(!panel.is_confirming());
        panel.previous();
        panel.toggle_current();
        assert_eq!(panel.selected_count(), 1);
    }

    #[test]
    fn at_most_eight_individually_checked_targets_even_in_slash_24() {
        let mut native = native();
        native.interfaces[0].prefix_len = 24;
        let range: NetworkPrefix = "93.184.216.0/24".parse().unwrap();
        let preview = build_preview(&native, None, PreviewScope::OperatorApprovedCidrs(&[range]));
        let mut panel = CandidateBatchPanel::new(preview, Some("proxy.example.org".into()));
        assert!(panel.available_count() > MAX_DUAL_BATCH);
        for _ in 0..32 {
            panel.toggle_current();
            panel.next();
        }
        assert_eq!(panel.selected_count(), MAX_DUAL_BATCH);
        panel.ask_confirmation();
        assert!(panel.is_confirming());
        assert!(panel.body().contains("8"));
        assert!(!panel.is_running());
    }

    #[test]
    fn no_server_config_and_empty_preview_refuse_consent_or_network() {
        let preview = build_preview(
            &NativeInterfaces::default(),
            None,
            PreviewScope::PassiveOnly,
        );
        let mut unavailable = CandidateBatchPanel::new(preview, Some("proxy.example.org".into()));
        assert_eq!(unavailable.available_count(), 0);
        unavailable.toggle_current();
        unavailable.ask_confirmation();
        unavailable.confirm_and_start();
        assert!(!unavailable.is_running());
        assert!(unavailable.body().contains("Нет доступных"));
        let mut configless = panel(true);
        configless.server_name = None;
        configless.toggle_current();
        configless.ask_confirmation();
        configless.confirm_and_start();
        assert!(!configless.is_running());
        assert!(configless.body().contains("серверной конфигурации"));
    }

    #[test]
    fn preflight_exact_targets_and_in_memory_cancel_do_not_leak_scopes() {
        let mut panel = panel(true);
        panel.toggle_current();
        panel.next();
        panel.toggle_current();
        let targets = panel.pending_targets();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0], "93.184.216.10".parse::<IpAddr>().unwrap());
        assert_eq!(targets[1], "93.184.216.9".parse::<IpAddr>().unwrap());
        assert_eq!(
            panel
                .preview
                .plan
                .candidates
                .iter()
                .filter(|c| c.source == CandidateSource::AuthorizedSubnet)
                .count(),
            5
        );
        panel.ask_confirmation();
        assert!(!panel.back_or_close());
        assert!(!panel.is_confirming());
        assert!(panel.back_or_close());
    }

    #[test]
    fn failed_individual_transport_never_increments_dual_verified_count() {
        use crate::{
            camouflage_dual::{DualProbeError, DualProbeReport},
            camouflage_dual_batch::{DualBatchOutcome, DualBatchReport},
            camouflage_h3_probe::H3ProbeError,
            camouflage_probe::ProbeError,
        };
        let ip: IpAddr = "93.184.216.10".parse().unwrap();
        let report = DualBatchReport {
            results: vec![
                DualBatchOutcome {
                    address: SocketAddr::new(ip, 443),
                    result: Ok(DualProbeReport {
                        address: SocketAddr::new(ip, 443),
                        h2: Err(ProbeError::WrongAlpn),
                        h3: Err(H3ProbeError::TimedOut),
                    }),
                },
                DualBatchOutcome {
                    address: SocketAddr::new("93.184.216.9".parse().unwrap(), 443),
                    result: Err(DualProbeError::NotApproved),
                },
            ],
        };
        let mut panel = panel(true);
        panel.state = BatchState::Complete(Ok(report));
        let output = panel.body();
        assert!(output.contains("Совместимы по H2+H3: 0/2"));
        assert!(output.contains("H2: отказ"));
        assert!(output.contains("H3: отказ"));
        assert!(output.contains("REALITY: НЕ готов"));
        assert!(!output.contains("REALITY: ГОТОВ"));
    }

    #[test]
    fn cancel_running_worker_signal_is_emitted_without_waiting() {
        let mut panel = panel(true);
        let (_tx, rx) = mpsc::channel();
        let (cancel, mut notify) = oneshot::channel();
        panel.state = BatchState::Running {
            result: rx,
            cancel: Some(cancel),
        };
        panel.cancel();
        assert!(notify.try_recv().is_ok());
    }
}
