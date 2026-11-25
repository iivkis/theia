//! M4.5h: separately consented domain DNS and exact pinned IP H2+H3.
//!
//! A catalogue entry is never permission to scan. DNS is one operator
//! approved lookup; TCP and UDP each require further disclosure of selected
//! exact public IPs and affirmative consent, no re-resolution, no Apply.
use crate::{
    camouflage_discovery::{CandidateHost, CandidateSource, Transport, POPULAR_HTTPS_DOMAINS},
    camouflage_domain_dns::{
        resolve_catalogued_domain, resolve_manual_domain, validate_manual_dns_request, DnsConsent,
        DnsError, MAX_PINNED_IPS,
    },
    camouflage_dual::{known_server_address, CandidateConsent, DualProbeTarget},
    camouflage_dual_batch::{probe_dual_batch, DualBatchError, DualBatchReport, DualBatchTarget},
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
    StaleDnsPin,
    Batch(DualBatchError),
}

#[derive(Debug)]
struct DnsObservation {
    addresses: Vec<IpAddr>,
    completed_at: Instant,
}

/// DNS freshness is based on the resolver completion time, never on when
/// an event loop happens to inspect the worker's channel. Reject timestamps
/// in the future as well as observations beyond the 60-second TTL.
fn dns_pin_fresh_at(completed_at: Instant, now: Instant) -> bool {
    now.checked_duration_since(completed_at)
        .is_some_and(|age| age <= DNS_PIN_TTL)
}

enum DomainState {
    Catalog,
    ManualInput,
    DnsConfirm,
    DnsRunning {
        result: Receiver<Result<DnsObservation, DnsError>>,
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
    manual: Option<String>,
    manual_input: String,
    manual_error: bool,
    addresses: Vec<IpAddr>,
    selected: Vec<IpAddr>,
    address_index: usize,
    dns_received: Option<Instant>,
    probed_at: Option<Instant>,
    review: crate::tui_reality_review::ReviewCursor,
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
            manual: None,
            manual_input: String::new(),
            manual_error: false,
            addresses: Vec::new(),
            selected: Vec::new(),
            address_index: 0,
            dns_received: None,
            probed_at: None,
            review: Default::default(),
            state: DomainState::Catalog,
        }
    }

    pub(crate) fn domain(&self) -> Option<&str> {
        self.manual
            .as_deref()
            .or_else(|| self.domains.get(self.domain_index).copied())
    }

    pub(crate) fn begin_manual(&mut self) {
        if matches!(self.state, DomainState::Catalog) {
            self.reset_pins();
            self.manual = None;
            self.manual_input.clear();
            self.manual_error = false;
            self.state = DomainState::ManualInput;
        }
    }

    pub(crate) fn is_manual_input(&self) -> bool {
        matches!(self.state, DomainState::ManualInput)
    }

    pub(crate) fn manual_insert(&mut self, ch: char) {
        if self.is_manual_input() && ch.is_ascii_graphic() && self.manual_input.len() < 253 {
            self.manual_input.push(ch);
            self.manual_error = false;
        }
    }

    pub(crate) fn manual_backspace(&mut self) {
        if self.is_manual_input() {
            self.manual_input.pop();
            self.manual_error = false;
        }
    }

    fn return_to_catalog(&mut self) {
        self.reset_pins();
        self.manual = None;
        self.manual_input.clear();
        self.manual_error = false;
        self.domain_index = self.domain_index.min(self.domains.len().saturating_sub(1));
        self.state = DomainState::Catalog;
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
            .is_some_and(|received| dns_pin_fresh_at(received, Instant::now()))
    }

    fn reset_pins(&mut self) {
        self.addresses.clear();
        self.selected.clear();
        self.address_index = 0;
        self.dns_received = None;
        self.probed_at = None;
        self.review.reset();
    }

    pub(crate) fn next(&mut self) {
        if let DomainState::Complete(Ok(report)) = &self.state {
            self.review.move_by(report.results.len(), true);
            return;
        }
        match self.state {
            DomainState::Catalog => {
                self.domain_index = (self.domain_index + 1).min(self.domains.len());
                self.reset_pins();
            }
            DomainState::Resolved if !self.addresses.is_empty() => {
                self.address_index = (self.address_index + 1) % self.addresses.len();
            }
            _ => {}
        }
    }

    pub(crate) fn previous(&mut self) {
        if let DomainState::Complete(Ok(report)) = &self.state {
            self.review.move_by(report.results.len(), false);
            return;
        }
        match self.state {
            DomainState::Catalog => {
                self.domain_index = self.domain_index.saturating_sub(1);
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
        if self.review.is_open() {
            return;
        }
        match self.state {
            DomainState::ManualInput => {
                if validate_manual_dns_request(&self.manual_input, DnsConsent::Approved).is_ok() {
                    self.manual = Some(self.manual_input.clone());
                    self.state = DomainState::DnsConfirm;
                } else {
                    self.manual_error = true;
                }
            }
            DomainState::Catalog if self.domain_index == self.domains.len() => {
                self.begin_manual();
            }
            DomainState::Catalog if self.domain().is_some() => {
                self.state = DomainState::DnsConfirm;
            }
            DomainState::Resolved => self.ask_probe_confirmation(),
            _ => {}
        }
    }

    pub(crate) fn decline(&mut self) {
        if self.review.close() {
            return;
        }
        match self.state {
            DomainState::DnsConfirm => {
                if self.manual.is_some() {
                    self.manual = None;
                    self.state = DomainState::ManualInput;
                } else {
                    self.state = DomainState::Catalog;
                }
            }
            DomainState::ProbeConfirm => self.state = DomainState::Resolved,
            _ => {}
        }
    }

    pub(crate) fn toggle_current(&mut self) {
        if self.review.is_open() {
            return;
        }
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
        let Some(domain) = self.domain().map(str::to_owned) else {
            self.return_to_catalog();
            return;
        };
        let catalogued = if self.manual.is_none() {
            self.domains.get(self.domain_index).copied()
        } else {
            None
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
                            reply = async {
                                match catalogued {
                                    Some(name) => resolve_catalogued_domain(name, DnsConsent::Approved).await,
                                    None => resolve_manual_domain(&domain, DnsConsent::Approved).await,
                                }
                            } => {
                                Some(reply.map(|addresses| DnsObservation {
                                    addresses,
                                    completed_at: Instant::now(),
                                }))
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
        let Some(domain) = self.domain().map(str::to_owned) else {
            self.return_to_catalog();
            return;
        };
        let catalogued = if self.manual.is_none() {
            self.domains.get(self.domain_index).copied()
        } else {
            None
        };
        let addresses = self.selected.clone();
        let preview = self.preview.clone();
        let observed_at = self.dns_received;
        let (tx, rx) = mpsc::channel();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        // Conservative age starts before worker I/O; polling cannot refresh it.
        self.probed_at = Some(Instant::now());
        self.review.reset();
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
                    // Recheck immediately before any socket can open. The
                    // background thread may have spent time loading native
                    // trust anchors or waiting to be scheduled.
                    if !observed_at.is_some_and(|at| dns_pin_fresh_at(at, Instant::now())) {
                        return Some(Err(DomainUiError::StaleDnsPin));
                    }
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
                            consent: match catalogued {
                                Some(name) => CandidateConsent::PinnedDomain {
                                    domain: name,
                                    pinned_ip: ip,
                                },
                                None => CandidateConsent::ManualDomain {
                                    domain: domain.clone(),
                                    pinned_ip: ip,
                                },
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
            Dns(Result<DnsObservation, DnsError>),
            Probe(Result<DualBatchReport, DomainUiError>),
        }
        let completed = match &self.state {
            DomainState::DnsRunning { result, .. } => match result.try_recv() {
                Ok(reply) => Some(Finished::Dns(reply)),
                Err(TryRecvError::Disconnected) => Some(Finished::Dns(Err(DnsError::LookupFailed))),
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
            Some(Finished::Dns(Ok(observation))) => {
                if observation.addresses.is_empty() {
                    self.reset_pins();
                    self.state = DomainState::DnsFailed(DnsError::NoPublicAddresses);
                } else if observation
                    .addresses
                    .iter()
                    .any(|ip| known_server_address(&self.preview, *ip))
                {
                    self.reset_pins();
                    self.state = DomainState::DnsFailed(DnsError::UnsafeAddress);
                } else if !dns_pin_fresh_at(observation.completed_at, Instant::now()) {
                    self.reset_pins();
                    self.state = DomainState::DnsFailed(DnsError::StaleObservation);
                } else {
                    self.addresses = observation.addresses;
                    self.selected.clear();
                    self.address_index = 0;
                    self.dns_received = Some(observation.completed_at);
                    self.state = DomainState::Resolved;
                }
            }
            Some(Finished::Dns(Err(error))) => {
                self.reset_pins();
                self.state = DomainState::DnsFailed(error);
            }
            Some(Finished::Probe(report)) => {
                self.state = DomainState::Complete(report);
            }
            _ => {}
        }
    }

    pub(crate) fn cancel(&mut self) {
        match &mut self.state {
            DomainState::DnsRunning { cancel, .. } | DomainState::ProbeRunning { cancel, .. } => {
                if let Some(signal) = cancel.take() {
                    let _ = signal.send(());
                }
            }
            _ => {}
        }
    }

    /// Esc unwinds the confirmation stage or discards DNS pins. Esc from a
    /// running worker cancels it and closes the modal immediately.
    pub(crate) fn open_review(&mut self) {
        if let DomainState::Complete(Ok(report)) = &self.state {
            self.review.open(report);
        }
    }

    pub(crate) fn back_or_close(&mut self) -> bool {
        if self.review.close() {
            return false;
        }
        match self.state {
            DomainState::DnsConfirm | DomainState::ProbeConfirm => {
                self.decline();
                false
            }
            DomainState::ManualInput
            | DomainState::Resolved
            | DomainState::DnsFailed(_)
            | DomainState::Complete(_) => {
                self.return_to_catalog();
                false
            }
            DomainState::Catalog => true,
            DomainState::DnsRunning { .. } | DomainState::ProbeRunning { .. } => {
                self.cancel();
                true
            }
        }
    }

    pub(crate) fn form(&self) -> Option<crate::tui_widgets::Form> {
        use crate::tui_widgets::{Field, Form};
        match self.state {
            DomainState::Catalog => Some(Form {
                fields:self.domains.iter().enumerate().map(|(id,name)| Field {id,label:"Домен",value:(*name).to_owned(),hint:"Enter — запросить отдельное согласие на DNS."})
                    .chain(std::iter::once(Field { id: self.domains.len(), label: "Ввести свой домен", value: "Ручной выбор".into(), hint: "Enter — открыть поле ввода." })).collect(),
                selected:self.domain_index,lead:"DNS ещё НЕ выполнялся. Каталог не даёт права на активную проверку.".into(),error:String::new(),
            }),
            DomainState::Resolved if !self.addresses.is_empty() => Some(Form {
                fields:self.addresses.iter().enumerate().map(|(id,ip)| Field {id,label:if self.selected.contains(ip) {"[x] Отмечен"} else {"[ ] Не отмечен"},value:SocketAddr::new(*ip,443).to_string(),hint:"Space — отметить адрес. Enter — предпросмотр точных целей. Права проверяются отдельно."}).collect(),
                selected:self.address_index,lead:format!("Выбрано: {}/{}. DNS не разрешает активную проверку.",self.selected_count(),MAX_PINNED_IPS),error:if self.fresh(){String::new()}else{"Ответ DNS устарел. Вернитесь в каталог и повторите запрос.".into()},
            }),
            _=>None,
        }
    }
    pub(crate) fn select_field(&mut self, id: usize) {
        match self.state {
            DomainState::Catalog if id <= self.domains.len() => {
                self.domain_index = id;
                self.reset_pins();
            }
            DomainState::Resolved if id < self.addresses.len() => self.address_index = id,
            _ => {}
        }
    }

    pub(crate) fn report_actions(&self) -> Vec<crate::tui_widgets::ActionItem> {
        use crate::tui_widgets::ActionItem;
        if !matches!(self.state, DomainState::Complete(Ok(_))) { return Vec::new(); }
        vec![ActionItem { key: 'a', label: "Подробности результата" },
            ActionItem { key: 'k', label: "Предыдущий результат" },
            ActionItem { key: 'j', label: "Следующий результат" }]
    }

    pub(crate) fn body(&self) -> String {
        let mut out = String::from(
            "F-18: домены из 14 seed-каталога; DNS и TLS только с двумя согласиями\n\n",
        );
        if self.is_manual_input() {
            out.push_str(&format!(
                "Ручной TLS-референс: {}\nТолько одно DNS-имя нижнего регистра, без URL, IP или порта.\nEnter: показать согласие; Esc: отменить. DNS ещё НЕ выполнялся.",
                self.manual_input
            ));
            if self.manual_error {
                out.push_str("\nНекорректное DNS-имя.");
            }
            return out;
        }
        let Some(domain) = self.domain() else {
            out.push_str(
                "Нет доменов каталога. Запросы не выполняются. m: ручной ввод; Esc: назад",
            );
            return out;
        };
        if self.is_running() {
            out.push_str("Работает фоновый DNS или TLS worker. Esc отменяет запрос.\n");
        }
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
                    "\nDNS ещё НЕ выполнялся. Наличие домена в каталоге не означает разрешения на сканирование.",
                );
            }
            DomainState::ManualInput => unreachable!("rendered above"),
            DomainState::DnsConfirm => out.push_str(&format!(
                "СОГЛАСИЕ: DNS-запрос A/AAAA только для {domain}.\nВаш DNS-resolver увидит это имя. Запрос может уйти сторонним DNS-серверам.\nОдна попытка, до 5с, максимум 64 адреса; приватные/опасные ответы отклоняются целиком.\nОтветы показываются для отдельного выбора, ни один TLS/QUIC не запускается.\nНаличие домена в каталоге НЕ подтверждает право активного сканирования.",
            )),
            DomainState::DnsRunning { .. } => out.push_str(&format!(
                "Выполняется разрешённый DNS A/AAAA запрос {domain}.\nНикакого TCP/H2 или UDP/H3 пока нет.\nEsc: отменить запрос и выйти",
            )),
            DomainState::DnsFailed(error) => {
                let explanation = match error {
                    DnsError::NotApproved => "не получено разрешение",
                    DnsError::NotCatalogued => "имя отсутствует в каталоге",
                    DnsError::InvalidDomain => "некорректное ручное DNS-имя",
                    DnsError::TimedOut => "таймаут DNS",
                    DnsError::StaleObservation => "устаревший DNS-ответ, требуется новое согласие",
                    DnsError::LookupFailed => "DNS-запрос не выполнен",
                    DnsError::NoPublicAddresses => "нет публичных адресов",
                    DnsError::UnsafeAddress => "опасный/приватный IP или известный адрес сервера в DNS, все ответы отклонены",
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
                    "\nTLS1.3+CA+SNI/SAN+h2 по TCP и QUIC/TLS1.3+CA+SNI/SAN+h3 по UDP.\nДо 8 точных IP, 2 параллельно, 5с/цель, 20с/набор.\nОператор подтверждает права на КАЖДЫЙ адрес; DNS не доказывает права.\nНет HTTP-запросов, перенаправлений, DNS-rebinding, retries и fallback.",
                );
            }
            DomainState::ProbeRunning { .. } => out.push_str(
                "Идут разрешённые H2 и H3 handshake по закреплённым IP, без DNS.\nEsc: отменить все оставшиеся проверки и выйти",
            ),
            DomainState::Complete(Err(error)) => {
                let explanation = match error {
                    DomainUiError::NoTrustAnchors => "нет системных доверенных CA",
                    DomainUiError::WorkerUnavailable => "недоступен worker",
                    DomainUiError::StaleDnsPin => "DNS-пины устарели до старта TLS; повторите DNS с согласием",
                    DomainUiError::Batch(DualBatchError::Empty) => "пустой список",
                    DomainUiError::Batch(DualBatchError::TooManyTargets) => "слишком много IP",
                    DomainUiError::Batch(DualBatchError::DuplicateTarget) => "дублирующаяся цель",
                    DomainUiError::Batch(DualBatchError::Target(_)) => "цель не соответствует согласованному имени/IP или не одобрена",
                    DomainUiError::Batch(DualBatchError::TaskFailed) => "ошибка задачи",
                    DomainUiError::Batch(DualBatchError::BatchTimedOut) => "таймаут 20с",
                };
                out.push_str(&format!(
                    "H2+H3 batch не выполнен: {explanation}.\nREALITY: НЕ готов.\nEsc: каталог",
                ));
            }
            DomainState::Complete(Ok(report)) => {
                if self.review.is_open() {
                    return self.review.body(report, &self.selected, domain, self.probed_at, self.fresh());
                }
                let age = self.probed_at.map_or_else(
                    || "неизвестна".to_owned(),
                    |at| format!("{} сек с начала проверки", at.elapsed().as_secs()),
                );
                out.push_str(&format!(
                    "Домен/SNI: {domain}. Оба H2+H3: {}/{}; измерение {age}.\n",
                    report.dual_verified_count(),
                    report.results.len(),
                ));
                if !(crate::tui_reality_review::evidence_fresh(self.probed_at, Instant::now()) && self.fresh()) {
                    out.push_str("Исторические наблюдения: срок действия истёк или неизвестен.\n");
                }
                for (index, candidate) in report.results.iter().enumerate() {
                    out.push_str(self.review.marker(index));
                    match &candidate.result {
                        Ok(result) if result.address == candidate.address => {
                            let h2 = result.h2.as_ref().ok().filter(|_| result.h2_verified());
                            let h3 = result.h3.as_ref().ok().filter(|_| result.h3_verified());
                            let h2_display = h2.map_or_else(
                                || "H2: отказ/Unknown".to_owned(),
                                |p| {
                                    let rating = p.evidence.suitability(Transport::H2);
                                    format!("H2: {}/100, {}% confidence", rating.score, rating.confidence)
                                },
                            );
                            let h3_display = h3.map_or_else(
                                || "H3: отказ/Unknown".to_owned(),
                                |p| {
                                    let rating = p.evidence.suitability(Transport::H3);
                                    format!("H3: {}/100, {}% confidence", rating.score, rating.confidence)
                                },
                            );
                            out.push_str(&format!(
                                "{} {h2_display}  {h3_display}  dual: {}\n",
                                candidate.address,
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
                    "\nREALITY: НЕ готов. Результат подтверждает лишь транспортный TLS/ALPN, НЕ HTTP/3 fingerprint/identity/DPI.\nScore не является вероятностью обхода DPI; нет Apply и автоматического сканирования каталога.",
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
        let preview = build_preview(
            &NativeInterfaces::default(),
            None,
            PreviewScope::PassiveOnly,
        );
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
    fn manual_domain_input_is_offline_until_separate_dns_confirmation() {
        let mut panel = panel();
        panel.begin_manual();
        assert!(panel.is_manual_input());
        for ch in "https://bad.example".chars() {
            panel.manual_insert(ch);
        }
        panel.ask_confirmation();
        assert!(panel.is_manual_input());
        assert!(panel.body().contains("Некорректное DNS-имя"));
        panel.confirm_dns_and_start();
        assert!(!panel.is_running());
        assert!(!panel.back_or_close());
        panel.begin_manual();
        for ch in "manual.example".chars() {
            panel.manual_insert(ch);
        }
        panel.ask_confirmation();
        assert!(panel.is_dns_confirming());
        assert_eq!(panel.domain(), Some("manual.example"));
        assert_eq!(panel.selected_count(), 0);
        assert!(!panel.is_running());
        panel.decline();
        assert!(panel.is_manual_input());
        assert!(!panel.back_or_close());
        assert_eq!(panel.domain(), Some("google.com"));
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
        tx.send(Ok(DnsObservation {
            addresses: vec!["93.184.216.10".parse().unwrap()],
            completed_at: Instant::now(),
        }))
        .unwrap();
        panel.poll();
        assert!(panel.is_resolved());
        assert_eq!(panel.addresses.len(), 1);
        assert_eq!(panel.selected_count(), 0);
        assert!(panel.body().contains("DNS: закреплено 1"));
    }

    #[test]
    fn dns_timestamp_ttl_boundary_inclusive_and_future_rejected() {
        let at = Instant::now();
        assert!(dns_pin_fresh_at(at, at));
        assert!(dns_pin_fresh_at(at, at + DNS_PIN_TTL));
        assert!(!dns_pin_fresh_at(
            at,
            at + DNS_PIN_TTL + Duration::from_millis(1)
        ));
        // Windows Instant has coarser clock granularity than 1 nanosecond.
        assert!(!dns_pin_fresh_at(at, at - Duration::from_millis(1)));
    }

    #[test]
    fn delayed_dns_worker_result_is_not_rejuvenated_by_late_ui_poll() {
        let mut panel = panel();
        let (tx, rx) = mpsc::channel();
        let (cancel, _) = oneshot::channel();
        panel.state = DomainState::DnsRunning {
            result: rx,
            cancel: Some(cancel),
        };
        tx.send(Ok(DnsObservation {
            addresses: vec!["93.184.216.10".parse().unwrap()],
            completed_at: Instant::now() - DNS_PIN_TTL - Duration::from_secs(1),
        }))
        .unwrap();
        panel.poll();
        assert!(!panel.is_resolved());
        assert!(panel.addresses.is_empty());
        assert!(panel.dns_received.is_none());
        assert!(panel.body().contains("устар"));
        panel.ask_probe_confirmation();
        assert!(!panel.is_probe_confirming());
    }

    #[test]
    fn recent_dns_worker_result_retains_original_observation_timestamp() {
        let mut panel = panel();
        let (tx, rx) = mpsc::channel();
        let (cancel, _) = oneshot::channel();
        panel.state = DomainState::DnsRunning {
            result: rx,
            cancel: Some(cancel),
        };
        let completed_at = Instant::now() - Duration::from_secs(2);
        tx.send(Ok(DnsObservation {
            addresses: vec!["93.184.216.10".parse().unwrap()],
            completed_at,
        }))
        .unwrap();
        panel.poll();
        assert!(panel.is_resolved());
        assert_eq!(panel.dns_received, Some(completed_at));
        assert_eq!(panel.selected_count(), 0);
    }

    #[test]
    fn a_future_or_expired_dns_timestamp_never_grants_probe_permission() {
        let mut panel = panel();
        panel.state = DomainState::Resolved;
        panel.addresses = vec!["93.184.216.10".parse().unwrap()];
        for timestamp in [
            Instant::now() + Duration::from_secs(3),
            Instant::now() - DNS_PIN_TTL - Duration::from_millis(1),
        ] {
            panel.dns_received = Some(timestamp);
            panel.selected = vec!["93.184.216.10".parse().unwrap()];
            panel.ask_probe_confirmation();
            assert!(!panel.is_probe_confirming());
            panel.confirm_probes_and_start();
            assert!(!panel.is_running());
        }
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
    fn both_transport_evidence_is_scored_only_after_independent_verified_tls() {
        use crate::{
            camouflage_discovery::{Observation, TlsEvidence},
            camouflage_dual::DualProbeReport,
            camouflage_dual_batch::{DualBatchOutcome, DualBatchReport},
            camouflage_h3_probe::H3ProbeReport,
            camouflage_probe::ProbeReport,
        };
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
        let mut panel = panel();
        panel.state = DomainState::Complete(Ok(DualBatchReport {
            results: vec![DualBatchOutcome {
                address: SocketAddr::new(ip, 443),
                result: Ok(DualProbeReport {
                    address: SocketAddr::new(ip, 443),
                    h2: Ok(ProbeReport {
                        connected_ip: ip,
                        handshake_elapsed: Duration::from_millis(40),
                        evidence: h2,
                    }),
                    h3: Ok(H3ProbeReport {
                        connected_ip: ip,
                        handshake_elapsed: Duration::from_millis(50),
                        evidence: h3,
                    }),
                }),
            }],
        }));
        let out = panel.body();
        assert!(out.contains("Оба H2+H3: 1/1"));
        assert!(out.contains("H2: 80/100, 85% confidence"));
        assert!(out.contains("H3: 80/100, 85% confidence"));
        assert!(out.contains("REALITY: НЕ готов"));

        panel.selected = vec![ip];
        panel.dns_received = Some(Instant::now());
        panel.probed_at = Some(Instant::now());
        panel.open_review();
        let preview = panel.body();
        assert!(preview.contains("Оба TLS/ALPN наблюдения актуальны"));
        assert!(preview.contains("Apply ЗАБЛОКИРОВАН"));
        panel.dns_received = None;
        let expired = panel.body();
        assert!(!expired.contains("Оба TLS/ALPN наблюдения актуальны"));
        assert!(expired.contains("устарели/неизвестны"));
    }

    #[test]
    fn review_after_delayed_probe_poll_keeps_original_age_and_cannot_apply() {
        use crate::{camouflage_dual::DualProbeError, camouflage_dual_batch::DualBatchOutcome};
        let mut panel = panel();
        let ip = "93.184.216.10".parse().unwrap();
        panel.selected = vec![ip];
        panel.dns_received = Some(Instant::now());
        let started = Instant::now() - Duration::from_secs(61);
        panel.probed_at = Some(started);
        let (tx, rx) = mpsc::channel();
        panel.state = DomainState::ProbeRunning {
            result: rx,
            cancel: None,
        };
        tx.send(Ok(DualBatchReport {
            results: vec![DualBatchOutcome {
                address: SocketAddr::new(ip, 443),
                result: Err(DualProbeError::NotApproved),
            }],
        }))
        .unwrap();
        panel.poll();
        assert_eq!(panel.probed_at, Some(started));
        panel.open_review();
        assert!(panel.body().contains("Apply ЗАБЛОКИРОВАН"));
        assert!(panel.body().contains("устарели/неизвестны"));
        panel.ask_confirmation();
        panel.confirm_probes_and_start();
        assert!(!panel.is_running());
        assert!(!panel.back_or_close());
        assert!(!panel.review.is_open());
    }

    #[test]
    fn reported_h2_only_or_h3_only_failure_is_never_reality_ready() {
        use crate::{
            camouflage_dual::{DualProbeError, DualProbeReport},
            camouflage_dual_batch::{DualBatchOutcome, DualBatchReport},
            camouflage_h3_probe::H3ProbeError,
            camouflage_probe::ProbeError,
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
