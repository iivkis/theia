//! M4.5h: separately consented domain DNS and exact pinned IP H2+H3.
//!
//! A catalogue entry is never permission to scan. DNS is one operator
//! approved lookup; TCP and UDP each require further disclosure of selected
//! exact public IPs and affirmative consent, no re-resolution, no Apply.
use crate::{
    camouflage_discovery::{CandidateHost, CandidateSource, POPULAR_HTTPS_DOMAINS},
    camouflage_domain_dns::{
        resolve_catalogued_domain, DnsConsent, DnsError, MAX_PINNED_IPS,
    },
    camouflage_dual::{CandidateConsent, DualProbeTarget},
    camouflage_dual_batch::{
        probe_dual_batch, DualBatchError, DualBatchReport, DualBatchTarget,
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

const DNS_PIN_TTL: Duration = Duration::from_secs(60);
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
const VISIBLE_DOMAINS: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainUiError {
    NoTrustAnchors,
    WorkerUnavailable,
    Batch(DualBatchError),
}

enum DomainState {
    Catalog,
    DnsConfirm,
    DnsRunning {
        result: Receiver<Result<Vec<IpAddr>, DnsError>>,
        cancel: Option<oneshot::Sender<()>>,
    },
    Resolved,
    DnsFailed(DnsError),
    ProbeConfirm,
    ProbeRunning {
        result: Receiver<Result<DualBatchReport, DomainUiError>>,
        cancel: Option<oneshot::Sender<()>>,
    },
    Complete(Result<DualBatchReport, DomainUiError>),
}

pub(crate) struct DomainPanel {
    preview: DiscoveryPreview,
    domains: Vec<&'static str>,
    domain_index: usize,
    addresses: Vec<IpAddr>,
    selected: Vec<IpAddr>,
    address_index: usize,
    dns_received: Option<Instant>,
    probed_at: Option<Instant>,
    state: DomainState,
}

impl DomainPanel {
    pub(crate) fn new(preview: DiscoveryPreview) -> Self {
        let domains = POPULAR_HTTPS_DOMAINS
            .iter()
            .copied()
            .filter(|name| {
                preview.plan.candidates.iter().any(|candidate| {
                    candidate.source == CandidateSource::PopularDomain
                        && candidate.host == CandidateHost::Domain(name)
                })
            })
            .collect();
        Self {
            preview,
            domains,
            domain_index: 0,
            addresses: Vec::new(),
            selected: Vec::new(),
            address_index: 0,
            dns_received: None,
            probed_at: None,
            state: DomainState::Catalog,
        }
    }

    pub(crate) fn domain(&self) -> Option<&'static str> {
        self.domains.get(self.domain_index).copied()
    }

    pub(crate) fn selected_count(&self) -> usize {
        self.selected.len()
    }

    pub(crate) fn is_dns_confirming(&self) -> bool {
        matches!(self.state, DomainState::DnsConfirm)
    }

    pub(crate) fn is_probe_confirming(&self) -> bool {
        matches!(self.state, DomainState::ProbeConfirm)
    }

    pub(crate) fn is_resolved(&self) -> bool {
        matches!(self.state, DomainState::Resolved)
    }

    pub(crate) fn is_running(&self) -> bool {
        matches!(
            self.state,
            DomainState::DnsRunning { .. } | DomainState::ProbeRunning { .. }
        )
    }

    fn fresh(&self) -> bool {
        self.dns_received
            .is_some_and(|received| received.elapsed() <= DNS_PIN_TTL)
    }

    fn reset_pins(&mut self) {
        self.addresses.clear();
        self.selected.clear();
        self.address_index = 0;
        self.dns_received = None;
        self.probed_at = None;
    }

    pub(crate) fn next(&mut self) {
        match self.state {
            DomainState::Catalog if !self.domains.is_empty() => {
                self.domain_index = (self.domain_index + 1) % self.domains.len();
                self.reset_pins();
            }
            DomainState::Resolved if !self.addresses.is_empty() => {
                self.address_index = (self.address_index + 1) % self.addresses.len();
            }
            _ => {}
        }
    }

    pub(crate) fn previous(&mut self) {
        match self.state {
            DomainState::Catalog if !self.domains.is_empty() => {
                self.domain_index = (self.domain_index + self.domains.len() - 1)
                    % self.domains.len();
                self.reset_pins();
            }
            DomainState::Resolved if !self.addresses.is_empty() => {
                self.address_index =
                    (self.address_index + self.addresses.len() - 1) % self.addresses.len();
            }
            _ => {}
        }
    }

    pub(crate) fn ask_confirmation(&mut self) {
        match self.state {
            DomainState::Catalog if self.domain().is_some() => {
                self.state = DomainState::DnsConfirm;
            }
            DomainState::Resolved => self.ask_probe_confirmation(),
            _ => {}
        }
    }

    pub(crate) fn decline(&mut self) {
        match self.state {
            DomainState::DnsConfirm => self.state = DomainState::Catalog,
            DomainState::ProbeConfirm => self.state = DomainState::Resolved,
            _ => {}
        }
    }

    pub(crate) fn toggle_current(&mut self) {
        if !self.is_resolved() || !self.fresh() {
            return;
        }
        let Some(&ip) = self.addresses.get(self.address_index) else {
            return;
        };
        if let Some(index) = self.selected.iter().position(|entry| *entry == ip) {
            self.selected.remove(index);
        } else if self.selected.len() < MAX_PINNED_IPS {
            self.selected.push(ip);
        }
    }

    pub(crate) fn ask_probe_confirmation(&mut self) {
        if self.is_resolved() && self.fresh() && !self.selected.is_empty() {
            self.state = DomainState::ProbeConfirm;
        }
    }

    /// A separate y after a DNS-disclosure is the ONLY path to a DNS query.
    /// A successful lookup never triggers any TCP/UDP handshake.
    pub(crate) fn confirm_dns_and_start(&mut self) {
        if !self.is_dns_confirming() {
            return;
        }
        let Some(domain) = self.domain() else {
            self.state = DomainState::Catalog;
            return;
        };
        self.reset_pins();
        let (tx, rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let started = std::thread::Builder::new()
            .name("theia-catalogue-one-dns-query".to_owned())
            .spawn(move || {
                let result = (|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()?;
                    runtime.block_on(async move {
                        tokio::select! {
                            biased;
                            _ = cancel_rx => None,
                            reply = resolve_catalogued_domain(domain, DnsConsent::Approved) => {
                                Some(reply)
                            }
                        }
                    })
                })();
                if let Some(result) = result {
                    let _ = tx.send(result);
                }
            });
        if started.is_err() {
            self.state = DomainState::DnsFailed(DnsError::LookupFailed);
        } else {
            self.state = DomainState::DnsRunning {
                result: rx,
                cancel: Some(cancel_tx),
            };
        }
    }

    /// Second, separate y after every exact DNS-pinned IP has been shown.
    /// The TLS/QUIC batch cannot cause DNS rebinding: it uses IP:443 sockets.
    pub(crate) fn confirm_probes_and_start(&mut self) {
        if !self.is_probe_confirming() {
            return;
        }
        if !self.fresh() || self.selected.is_empty() {
            self.state = DomainState::Resolved;
            return;
        }
        let Some(domain) = self.domain() else {
            self.state = DomainState::Catalog;
            return;
        };
        let addresses = self.selected.clone();
        let preview = self.preview.clone();
        let (tx, rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.probed_at = None;
        let started = std::thread::Builder::new()
            .name("theia-catalogue-pinned-dual-batch".to_owned())
            .spawn(move || {
                let result = (|| {
                    let certs = rustls_native_certs::load_native_certs();
                    let mut roots = RootCertStore::empty();
                    let (valid, _) = roots.add_parsable_certificates(certs.certs);
                    if valid == 0 {
                        return Some(Err(DomainUiError::NoTrustAnchors));
                    }
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(_) => return Some(Err(DomainUiError::WorkerUnavailable)),
                    };
                    let batch = addresses
                        .into_iter()
                        .map(|ip| DualBatchTarget {
                            target: DualProbeTarget {
                                request: ProbeRequest {
                                    address: SocketAddr::new(ip, 443),
                                    server_name: domain.to_owned(),
                                    deadline: HANDSHAKE_DEADLINE,
                                },
                                roots: roots.clone(),
                                approval: ProbeApproval::public_https_ip(ip),
                            },
                            consent: CandidateConsent::PinnedDomain {
                                domain,
                                pinned_ip: ip,
                            },
                        })
                        .collect();
                    runtime.block_on(async move {
                        tokio::select! {
                            biased;
                            _ = cancel_rx => None,
                            response = probe_dual_batch(&preview, batch) => {
                                Some(response.map_err(DomainUiError::Batch))
                            }
                        }
                    })
                })();
                if let Some(result) = result {
                    let _ = tx.send(result);
                }
            });
        if started.is_err() {
            self.state = DomainState::Complete(Err(DomainUiError::WorkerUnavailable));
        } else {
            self.state = DomainState::ProbeRunning {
                result: rx,
                cancel: Some(cancel_tx),
            };
        }
    }

    /// Nonblocking event-loop poll; errors are fixed safe codes, no DNS/TLS
    /// error string, raw cert, proxy token, response or secret is displayed.
    pub(crate) fn poll(&mut self) {
        enum Finished {
            Dns(Result<Vec<IpAddr>, DnsError>),
            Probe(Result<DualBatchReport, DomainUiError>),
        }
        let completed = match &self.state {
            DomainState::DnsRunning { result, .. } => match result.try_recv() {
                Ok(reply) => Some(Finished::Dns(reply)),
                Err(TryRecvError::Disconnected) => {
                    Some(Finished::Dns(Err(DnsError::LookupFailed)))
                }
                Err(TryRecvError::Empty) => None,
            },
            DomainState::ProbeRunning { result, .. } => match result.try_recv() {
                Ok(reply) => Some(Finished::Probe(reply)),
                Err(TryRecvError::Disconnected) => {
                    Some(Finished::Probe(Err(DomainUiError::WorkerUnavailable)))
                }
                Err(TryRecvError::Empty) => None,
            },
            _ => None,
        };
        match completed {
            Some(Finished::Dns(Ok(ips))) if !ips.is_empty() => {
                self.addresses = ips;
                self.selected.clear();
                self.address_index = 0;
                self.dns_received = Some(Instant::now());
                self.state = DomainState::Resolved;
            }
            Some(Finished::Dns(Err(error))) => {
                self.reset_pins();
                self.state = DomainState::DnsFailed(error);
            }
            Some(Finished::Dns(Ok(_))) => {
                self.reset_pins();
                self.state = DomainState::DnsFailed(DnsError::NoPublicAddresses);
            }
            Some(Finished::Probe(report)) => {
                self.probed_at = Some(Instant::now());
                self.state = DomainState::Complete(report);
            }
            _ => {}
        }
    }

    pub(crate) fn cancel(&mut self) {
        match &mut self.state {
            DomainState::DnsRunning { cancel, .. }
            | DomainState::ProbeRunning { cancel, .. } => {
                if let Some(signal) = cancel.take() {
                    let _ = signal.send(());
                }
            }
            _ => {}
        }
    }

    /// Esc unwinds the confirmation stage or discards DNS pins. Esc from a
    /// running worker cancels it and closes the modal immediately.
    pub(crate) fn back_or_close(&mut self) -> bool {
        match self.state {
            DomainState::DnsConfirm | DomainState::ProbeConfirm => {
                self.decline();
                false
            }
            DomainState::Resolved | DomainState::DnsFailed(_) | DomainState::Complete(_) => {
                self.reset_pins();
                self.state = DomainState::Catalog;
                false
            }
            DomainState::Catalog => true,
            DomainState::DnsRunning { .. } | DomainState::ProbeRunning { .. } => {
                self.cancel();
                true
            }
        }
    }

    pub(crate) fn body(&self) -> String {
        let mut out = String::from(
            "F-18: домены из 14 seed-каталога; DNS и TLS только с двумя согласиями\n\n",
        );
        let Some(domain) = self.domain() else {
            out.push_str("Нет доменов каталога. Запросы не выполняются. Esc: назад");
            return out;
        };
        match &self.state {
            DomainState::Catalog => {
                out.push_str(&format!(
                    "Каталог: {} доменов, ни один пока не разрешён/проверен.\n",
                    self.domains.len()
                ));
                let start = self.domain_index.saturating_sub(VISIBLE_DOMAINS / 2).min(
                    self.domains.len().saturating_sub(VISIBLE_DOMAINS),
                );
                for (index, name) in self.domains.iter().enumerate().skip(start).take(VISIBLE_DOMAINS) {
                    let cursor = if index == self.domain_index { ">" } else { " " };
                    out.push_str(&format!("{cursor} {name}\n"));
                }
                out.push_str(
                    "\nDNS ещё НЕ выполнялся. Наличие домена в каталоге не означает разрешения на сканирование.\nj/k: выбрать домен  Enter: запросить согласие на один DNS A/AAAA\nEsc: назад",
                );
            }
            DomainState::DnsConfirm => out.push_str(&format!(
                "СОГЛАСИЕ: DNS-запрос A/AAAA только для {domain}.\nВаш DNS-resolver увидит это имя. Запрос может уйти сторонним DNS-серверам.\nОдна попытка, до 5с, максимум 64 адреса; приватные/опасные ответы отклоняются целиком.\nОтветы показываются для отдельного выбора, ни один TLS/QUIC не запускается.\nНаличие домена в каталоге НЕ подтверждает право активного сканирования.\n\ny: разрешить DNS-запрос  n: отказаться  Esc: назад",
            )),
            DomainState::DnsRunning { .. } => out.push_str(&format!(
                "Выполняется разрешённый DNS A/AAAA запрос {domain}.\nНикакого TCP/H2 или UDP/H3 пока нет.\nEsc: отменить запрос и выйти",
            )),
            DomainState::DnsFailed(error) => {
                let explanation = match error {
                    DnsError::NotApproved => "не получено разрешение",
                    DnsError::NotCatalogued => "имя отсутствует в каталоге",
                    DnsError::TimedOut => "таймаут DNS",
                    DnsError::LookupFailed => "DNS-запрос не выполнен",
                    DnsError::NoPublicAddresses => "нет публичных адресов",
                    DnsError::UnsafeAddress => "опасный/приватный IP в DNS, все ответы отклонены",
                    DnsError::TooManyAnswers => "слишком много DNS адресов",
                };
                out.push_str(&format!(
                    "DNS не подтверждён: {explanation}.\nH2/H3: Unknown, TLS не запускался.\nEsc: обратно в каталог"
                ));
            }
            DomainState::Resolved => {
                let freshness = if self.fresh() {
                    format!(
                        "свежесть: {} сек назад",
                        self.dns_received.map_or(0, |at| at.elapsed().as_secs())
                    )
                } else {
                    "DNS ответы устарели (более 60с). Повторите DNS, сканирование запрещено".to_owned()
                };
                out.push_str(&format!(
                    "DNS: закреплено {} публичных адресов для {domain}; {freshness}.\nВыбрано: {}/{}. Ничего не проверяется автоматически.\n",
                    self.addresses.len(),
                    self.selected_count(),
                    MAX_PINNED_IPS,
                ));
                for (index, ip) in self.addresses.iter().enumerate() {
                    let cursor = if index == self.address_index { ">" } else { " " };
                    let marked = if self.selected.contains(ip) { "x" } else { " " };
                    out.push_str(&format!(
                        "{cursor}[{marked}] {}  SNI: {domain}\n",
                        SocketAddr::new(*ip, 443)
                    ));
                }
                out.push_str(
                    "\nj/k: адрес  Space: выбрать точный pinned IP  Enter: отдельное согласие на TCP/H2 + UDP/H3\nEsc: отбросить все DNS-пины и вернуться к каталогу\n\nПрава на активную проверку каждого IP подтверждаются отдельно, DNS этому не доказательство.",
                );
            }
            DomainState::ProbeConfirm => {
                out.push_str(&format!(
                    "ОТДЕЛЬНОЕ СОГЛАСИЕ на TCP/H2 + UDP/H3 (без повторного DNS).\nДомен/SNI: {domain}.\nПроверяются только перечисленные закреплённые IP:443:\n",
                ));
                for ip in &self.selected {
                    out.push_str(&format!("  {}  SNI: {domain}\n", SocketAddr::new(*ip, 443)));
                }
                out.push_str(
                    "\nTLS1.3+CA+SNI/SAN+h2 по TCP и QUIC/TLS1.3+CA+SNI/SAN+h3 по UDP.\nДо 8 точных IP, 2 параллельно, 5с/цель, 20с/набор.\nОператор подтверждает права на КАЖДЫЙ адрес; DNS не доказывает права.\nНет HTTP-запросов, перенаправлений, DNS-rebinding, retries и fallback.\n\ny: разрешить все перечисленные проверки  n/Esc: вернуться",
                );
            }
            DomainState::ProbeRunning { .. } => out.push_str(
                "Идут разрешённые H2 и H3 handshake по закреплённым IP, без DNS.\nEsc: отменить все оставшиеся проверки и выйти",
            ),
            DomainState::Complete(Err(error)) => {
                let explanation = match error {
                    DomainUiError::NoTrustAnchors => "нет системных доверенных CA",
                    DomainUiError::WorkerUnavailable => "недоступен worker",
                    DomainUiError::Batch(DualBatchError::Empty) => "пустой список",
                    DomainUiError::Batch(DualBatchError::TooManyTargets) => "слишком много IP",
                    DomainUiError::Batch(DualBatchError::DuplicateTarget) => "дублирующаяся цель",
                    DomainUiError::Batch(DualBatchError::Target(_)) => "цель не в каталоге или не одобрена",
                    DomainUiError::Batch(DualBatchError::TaskFailed) => "ошибка задачи",
                    DomainUiError::Batch(DualBatchError::BatchTimedOut) => "таймаут 20с",
                };
                out.push_str(&format!(
                    "H2+H3 batch не выполнен: {explanation}.\nREALITY: НЕ готов.\nEsc: каталог",
                ));
            }
            DomainState::Complete(Ok(report)) => {
                let age = self.probed_at.map_or_else(
                    || "неизвестна".to_owned(),
                    |at| format!("{} сек назад", at.elapsed().as_secs()),
                );
                out.push_str(&format!(
                    "Домен/SNI: {domain}. Оба H2+H3: {}/{}; измерение {age}.\n",
                    report.dual_verified_count(),
                    report.results.len(),
                ));
                for candidate in &report.results {
                    match &candidate.result {
                        Ok(result) if result.address == candidate.address => {
                            let h2 = result.h2.as_ref().is_ok_and(|p| {
                                p.connected_ip == candidate.address.ip()
                            });
                            let h3 = result.h3.as_ref().is_ok_and(|p| {
                                p.connected_ip == candidate.address.ip()
                            });
                            out.push_str(&format!(
                                "{} H2: {}  H3: {}  dual: {}\n",
                                candidate.address,
                                if h2 { "TLS OK" } else { "отказ/Unknown" },
                                if h3 { "QUIC OK" } else { "отказ/Unknown" },
                                if result.both_transports_verified() { "оба подтверждены" } else { "НЕ прошёл" }
                            ));
                        }
                        _ => out.push_str(&format!(
                            "{} H2: отказ/Unknown  H3: отказ/Unknown  dual: НЕ прошёл\n",
                            candidate.address,
                        )),
                    }
                }
                out.push_str(
                    "\nREALITY: НЕ готов. Результат подтверждает лишь транспортный TLS/ALPN, НЕ HTTP/3 fingerprint/identity/DPI.\nScore не является вероятностью обхода DPI; нет Apply и автоматического сканирования каталога.\nEsc: каталог",
                );
            }
        }
        out
    }
}

impl Drop for DomainPanel {
    fn drop(&mut self) {
        self.cancel();
    }
}

// M4.5h TDD: separate DNS and exact pinned-IP TCP/UDP consent.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        camouflage_interfaces::NativeInterfaces,
        camouflage_workflow::{build_preview, PreviewScope},
    };

    fn panel() -> DomainPanel {
        let preview = build_preview(&NativeInterfaces::default(), None, PreviewScope::PassiveOnly);
        DomainPanel::new(preview)
    }

    #[test]
    fn catalog_browsing_is_offline_and_starts_with_zero_checked_ips() {
        let mut panel = panel();
        assert_eq!(panel.domain(), Some("google.com"));
        assert_eq!(panel.selected_count(), 0);
        panel.confirm_dns_and_start(); // No preceding Enter, no network.
        panel.confirm_probes_and_start();
        assert!(!panel.is_running());
        panel.next();
        assert_eq!(panel.domain(), Some("samsung.com"));
        panel.previous();
        assert_eq!(panel.domain(), Some("google.com"));
        assert!(panel.body().contains("14"));
        assert!(panel.body().contains("DNS ещё НЕ выполнялся"));
        assert!(!panel.body().contains("H2+H3: ОБА"));
    }

    #[test]
    fn dns_and_active_tcp_udp_have_independent_confirmation_states() {
        let mut panel = panel();
        panel.ask_confirmation();
        assert!(panel.is_dns_confirming());
        assert!(!panel.is_probe_confirming());
        assert!(panel.body().contains("DNS-запрос"));
        assert!(panel.body().contains("google.com"));
        panel.decline();
        assert!(!panel.is_dns_confirming());
        assert!(!panel.is_running());
        panel.ask_confirmation();
        assert!(!panel.back_or_close()); // Esc cancels DNS confirmation first.
        assert!(panel.back_or_close()); // Then closes panel.
    }

    #[test]
    fn vetted_pinned_dns_answers_do_not_start_tls_until_space_enter_y() {
        let mut panel = panel();
        panel.state = DomainState::Resolved;
        panel.addresses = vec![
            "93.184.216.10".parse().unwrap(),
            "2606:4700::1111".parse().unwrap(),
        ];
        panel.dns_received = Some(Instant::now());
        panel.ask_probe_confirmation();
        assert!(!panel.is_probe_confirming()); // No selected IP yet.
        panel.toggle_current();
        panel.ask_probe_confirmation();
        assert!(panel.is_probe_confirming());
        assert!(!panel.is_running());
        let text = panel.body();
        assert!(text.contains("93.184.216.10:443"));
        assert!(text.contains("SNI: google.com"));
        assert!(text.contains("TCP/H2"));
        assert!(text.contains("UDP/H3"));
        assert!(text.contains("ОТДЕЛЬНОЕ СОГЛАСИЕ"));
        assert!(!text.contains("2606:4700::1111]:443"));
        panel.decline();
        assert!(!panel.is_probe_confirming());
        assert!(panel.is_resolved());
    }

    #[test]
    fn stale_dns_answer_must_not_become_scan_approval() {
        let mut panel = panel();
        panel.state = DomainState::Resolved;
        panel.addresses = vec!["93.184.216.10".parse().unwrap()];
        panel.dns_received = Some(Instant::now() - Duration::from_secs(61));
        panel.toggle_current();
        panel.ask_probe_confirmation();
        assert!(!panel.is_probe_confirming());
        panel.confirm_probes_and_start();
        assert!(!panel.is_running());
        assert!(panel.body().contains("устарели"));
    }

    #[test]
    fn new_catalog_domain_resets_old_dns_pins_and_checked_addresses() {
        let mut panel = panel();
        panel.state = DomainState::Resolved;
        panel.addresses = vec!["93.184.216.10".parse().unwrap()];
        panel.dns_received = Some(Instant::now());
        panel.toggle_current();
        assert_eq!(panel.selected_count(), 1);
        assert!(!panel.back_or_close());
        assert_eq!(panel.selected_count(), 0);
        assert!(panel.addresses.is_empty());
        panel.next();
        assert_eq!(panel.domain(), Some("samsung.com"));
        panel.ask_confirmation();
        assert!(panel.is_dns_confirming());
    }

    #[test]
    fn hostile_dns_outcome_never_becomes_tls_target() {
        let mut panel = panel();
        let (tx, rx) = mpsc::channel();
        let (cancel, _) = oneshot::channel();
        panel.state = DomainState::DnsRunning {
            result: rx,
            cancel: Some(cancel),
        };
        tx.send(Err(DnsError::UnsafeAddress)).unwrap();
        panel.poll();
        assert!(panel.body().contains("опасный"));
        assert!(panel.addresses.is_empty());
        panel.ask_probe_confirmation();
        assert!(!panel.is_probe_confirming());
    }

    #[test]
    fn async_dns_success_is_pinned_without_resolving_again() {
        let mut panel = panel();
        let (tx, rx) = mpsc::channel();
        let (cancel, _) = oneshot::channel();
        panel.state = DomainState::DnsRunning {
            result: rx,
            cancel: Some(cancel),
        };
        tx.send(Ok(vec!["93.184.216.10".parse().unwrap()])).unwrap();
        panel.poll();
        assert!(panel.is_resolved());
        assert_eq!(panel.addresses.len(), 1);
        assert_eq!(panel.selected_count(), 0);
        assert!(panel.body().contains("DNS: закреплено 1"));
    }

    #[test]
    fn dropping_running_dns_cancels_without_waiting() {
        let mut panel = panel();
        let (_tx, rx) = mpsc::channel();
        let (cancel, mut notify) = oneshot::channel();
        panel.state = DomainState::DnsRunning {
            result: rx,
            cancel: Some(cancel),
        };
        drop(panel);
        assert!(notify.try_recv().is_ok());
    }

    #[test]
    fn reported_h2_only_or_h3_only_failure_is_never_reality_ready() {
        use crate::{
            camouflage_dual::{DualProbeReport, DualProbeError},
            camouflage_dual_batch::{DualBatchReport, DualBatchOutcome},
            camouflage_probe::ProbeError,
            camouflage_h3_probe::H3ProbeError,
        };
        let ip: IpAddr = "93.184.216.10".parse().unwrap();
        let mut panel = panel();
        panel.state = DomainState::Complete(Ok(DualBatchReport {
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
                    address: SocketAddr::new("93.184.216.11".parse().unwrap(), 443),
                    result: Err(DualProbeError::DomainAddressMismatch),
                },
            ],
        }));
        let body = panel.body();
        assert!(body.contains("Оба H2+H3: 0/2"));
        assert!(body.contains("REALITY: НЕ готов"));
        assert!(!body.contains("REALITY: готов"));
    }
}
