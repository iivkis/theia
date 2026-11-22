//! M4.5c: explicitly reviewed, zero-I/O preview of server IP,
//! popular HTTPS seeds and *self-declared planning-only* IPv4 CIDR scope.
//!
//! A local assigned mask is NOT proof of ownership or permission to scan.
//! This model never provides active ProbeApproval, sends packets or persists
//! an accepted scope. All evidence remains unknown until separately measured.
use crate::{
    camouflage_discovery::{
        CandidateHost, CandidateSource, DiscoveryPlan, NetworkPrefix, TlsEvidence, Transport,
        Warning, POPULAR_HTTPS_DOMAINS,
    },
    camouflage_interfaces::NativeInterfaces,
    camouflage_workflow::{build_preview, PreviewScope},
};
use std::net::IpAddr;

pub(crate) const MAX_CIDR_TEXT: usize = 64;
const MAX_VISIBLE_IPS: usize = 6;

enum ScopeState {
    Overview,
    Input(String),
    Confirm {
        prefix: NetworkPrefix,
        additional: usize,
    },
    Accepted(NetworkPrefix),
}

/// Pure UI state for the planning review. Confirmation is deliberately scoped
/// to a disposable offline preview and never becomes scan authorization.
pub(crate) struct CandidateReview {
    native: NativeInterfaces,
    scope: ScopeState,
    warning: Option<&'static str>,
}

impl CandidateReview {
    pub(crate) fn new(native: NativeInterfaces) -> Self {
        Self {
            native,
            scope: ScopeState::Overview,
            warning: None,
        }
    }

    pub(crate) fn has_scope(&self) -> bool {
        matches!(self.scope, ScopeState::Accepted(_))
    }

    pub(crate) fn is_editing(&self) -> bool {
        matches!(self.scope, ScopeState::Input(_))
    }

    pub(crate) fn is_confirming(&self) -> bool {
        matches!(self.scope, ScopeState::Confirm { .. })
    }

    pub(crate) fn input_length(&self) -> usize {
        match &self.scope {
            ScopeState::Input(input) => input.len(),
            _ => 0,
        }
    }

    pub(crate) fn begin_cidr(&mut self) {
        if matches!(self.scope, ScopeState::Overview | ScopeState::Accepted(_)) {
            self.scope = ScopeState::Input(String::new());
            self.warning = None;
        }
    }

    pub(crate) fn insert(&mut self, ch: char) {
        if let ScopeState::Input(input) = &mut self.scope {
            if input.len() < MAX_CIDR_TEXT && ch.is_ascii_graphic() {
                input.push(ch);
            }
        }
    }

    pub(crate) fn backspace(&mut self) {
        if let ScopeState::Input(input) = &mut self.scope {
            input.pop();
        }
    }

    fn scoped_plan(&self) -> DiscoveryPlan {
        match self.scope {
            ScopeState::Accepted(prefix) => {
                build_preview(
                    &self.native,
                    None,
                    PreviewScope::OperatorApprovedCidrs(&[prefix]),
                )
                .plan
            }
            _ => build_preview(&self.native, None, PreviewScope::PassiveOnly).plan,
        }
    }

    /// Dry-run the existing M3.5 offline planner with a candidate CIDR.
    /// A range must be /24..=/32, contain a real public assigned local IP,
    /// stay within that IP's observed prefix, and not exceed candidate caps.
    /// No DNS or TLS connection is made, and preview scope is not a network
    /// approval, even when the operator later confirms this stage.
    pub(crate) fn review_input(&mut self) {
        let ScopeState::Input(text) = &self.scope else {
            return;
        };
        let Ok(prefix) = text.parse::<NetworkPrefix>() else {
            self.warning = Some("Некорректный CIDR. Укажите публичный IPv4/префикс.");
            return;
        };
        let valid_v4 = text
            .split_once('/')
            .and_then(|(ip, mask)| Some((ip.parse::<IpAddr>().ok()?, mask.parse::<u8>().ok()?)))
            .is_some_and(|(ip, mask)| matches!(ip, IpAddr::V4(_)) && (24..=32).contains(&mask));
        if !valid_v4 {
            self.warning = Some("Только IPv4 /24..=/32. IPv6 соседей нельзя перечислять.");
            return;
        }
        let preview = build_preview(
            &self.native,
            None,
            PreviewScope::OperatorApprovedCidrs(&[prefix]),
        );
        let blocked = preview.plan.warnings.iter().any(|warning| {
            matches!(
                warning,
                Warning::RangeNotOnServer
                    | Warning::RangeTooBroad
                    | Warning::RangeExceedsAssignedPrefix
                    | Warning::Ipv6EnumerationUnsupported
                    | Warning::CandidateLimitReached
            )
        });
        if preview.assigned_public_addresses == 0 {
            self.warning = Some("Нет назначенных публичных IP. Подсеть не может быть одобрена.");
            return;
        }
        if blocked {
            self.warning = Some(
                "Диапазон не подтверждён: IP вне диапазона, маска уже CIDR или лимит превышен.",
            );
            return;
        }
        let any_assigned = preview.plan.candidates.iter().any(|candidate| {
            candidate.source == CandidateSource::ServerAddress
                && matches!(candidate.host, CandidateHost::Ip(ip) if prefix.contains(ip))
        });
        if !any_assigned {
            self.warning = Some("Нет назначенных публичных IP в этом диапазоне.");
            return;
        }
        let additional = preview
            .plan
            .candidates
            .iter()
            .filter(|candidate| candidate.source == CandidateSource::AuthorizedSubnet)
            .count();
        self.scope = ScopeState::Confirm { prefix, additional };
        self.warning = None;
    }

    pub(crate) fn confirm_scope(&mut self) {
        if let ScopeState::Confirm { prefix, .. } = self.scope {
            self.scope = ScopeState::Accepted(prefix);
        }
    }

    pub(crate) fn decline(&mut self) {
        if matches!(self.scope, ScopeState::Confirm { .. }) {
            self.scope = ScopeState::Overview;
            self.warning = None;
        }
    }

    /// Esc discards unconfirmed text/preview first, then closes the pane.
    /// The accepted scope also vanishes when the pane is dropped.
    pub(crate) fn back_or_close(&mut self) -> bool {
        if matches!(
            self.scope,
            ScopeState::Input(_) | ScopeState::Confirm { .. }
        ) {
            self.scope = ScopeState::Overview;
            self.warning = None;
            false
        } else {
            true
        }
    }

    pub(crate) fn group_counts(&self) -> (usize, usize, usize) {
        let plan = self.scoped_plan();
        (
            plan.candidates
                .iter()
                .filter(|candidate| candidate.source == CandidateSource::ServerAddress)
                .count(),
            plan.candidates
                .iter()
                .filter(|candidate| candidate.source == CandidateSource::PopularDomain)
                .count(),
            plan.candidates
                .iter()
                .filter(|candidate| candidate.source == CandidateSource::AuthorizedSubnet)
                .count(),
        )
    }

    pub(crate) fn body(&self) -> String {
        let plan = self.scoped_plan();
        let (server, domains, manual) = self.group_counts();
        let show = |source| {
            let addresses = plan
                .candidates
                .iter()
                .filter(|candidate| candidate.source == source)
                .filter_map(|candidate| match candidate.host {
                    CandidateHost::Ip(ip) => Some(ip.to_string()),
                    CandidateHost::Domain(_) => None,
                })
                .take(MAX_VISIBLE_IPS)
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                "нет".to_owned()
            } else {
                addresses.join(", ")
            }
        };
        let rating = TlsEvidence::default().suitability(Transport::H2);
        let mut body = format!(
            "Пассивный разбор F-18: источники кандидатов (без сети)\n\nПодсеть сервера: {server} назначенных публичных IP\n  {}\nПопулярные домены: {domains} (только каталог, без DNS)\n  {}\nДобавленные вручную: {manual} дополнительных IP\n  {}\n\nTLS/H2: неизвестно, score {}/100, confidence {}%, eligible: НЕТ.\nБалл НЕ означает вероятность обхода DPI.\n",
            show(CandidateSource::ServerAddress),
            POPULAR_HTTPS_DOMAINS.join(", "),
            show(CandidateSource::AuthorizedSubnet),
            rating.score,
            rating.confidence,
        );
        match &self.scope {
            ScopeState::Overview => body.push_str(
                "\nНет разрешения на активные проверки. Маска интерфейса не доказывает владение CIDR.\n\na: ввести собственный IPv4 CIDR только для offline-плана\nEsc: вернуться",
            ),
            ScopeState::Input(input) => body.push_str(&format!(
                "\nВведите IPv4 CIDR (/24..=/32, максимум {MAX_CIDR_TEXT} символа):\n{input}\n{}\n\nEnter: проверить пределы офлайн  Backspace: удалить  Esc: отменить",
                self.warning.unwrap_or("Ожидается явный ввод диапазона; никакой автоматической проверки сети.")
            )),
            ScopeState::Confirm { prefix, additional } => body.push_str(&format!(
                "\nПодтвердить офлайн-план для {prefix}?\n{additional} дополнительных IP-кандидатов.\n\nПОДТВЕРЖДЕНИЕ ОПЕРАТОРА: доступ к этому диапазону необходимо\nподтвердить независимо. Эта отметка не доказывает право владения\nи не является разрешением на активное сканирование.\n\ny: добавить только в offline-просмотр  n: отказаться  Esc: отменить",
            )),
            ScopeState::Accepted(prefix) => body.push_str(&format!(
                "\nЛокально заявленный диапазон: {prefix}.\nЭто не является разрешением на активное сканирование.\nНикакие CIDR-адреса не подключались и не сохранялись.\n\na: изменить диапазон (новое согласие)  Esc: закрыть/стереть",
            )),
        }
        if !matches!(self.scope, ScopeState::Input(_)) {
            if let Some(warning) = self.warning {
                body.push_str(&format!("\n{warning}"));
            }
        }
        body
    }
}

// M4.5c tests: offline CIDR review without network or ownership inference.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::camouflage_interfaces::{InterfaceSource, ObservedInterface};

    fn fixture() -> NativeInterfaces {
        NativeInterfaces {
            interfaces: vec![
                ObservedInterface {
                    interface_name: "eth0".into(),
                    address: "93.184.216.10".parse().unwrap(),
                    prefix_len: 29,
                    is_up: true,
                    source: InterfaceSource::LinuxGetifaddrs,
                },
                ObservedInterface {
                    interface_name: "eth0".into(),
                    address: "10.0.0.3".parse().unwrap(),
                    prefix_len: 24,
                    is_up: true,
                    source: InterfaceSource::LinuxGetifaddrs,
                },
            ],
        }
    }

    fn type_cidr(panel: &mut CandidateReview, cidr: &str) {
        panel.begin_cidr();
        for ch in cidr.chars() {
            panel.insert(ch);
        }
        panel.review_input();
    }

    #[test]
    fn initial_groups_have_only_observed_assigned_address_and_unverified_seed_domains() {
        let panel = CandidateReview::new(fixture());
        let body = panel.body();
        assert!(body.contains("Подсеть сервера"));
        assert!(body.contains("Популярные домены"));
        assert!(body.contains("Добавленные вручную"));
        assert!(body.contains("93.184.216.10"));
        assert!(!body.contains("10.0.0.3"));
        assert!(body.contains("14"));
        assert!(body.contains("0/100"));
        assert!(body.contains("НЕ означает"));
        assert!(!panel.has_scope());
    }

    #[test]
    fn explicit_cidr_requires_separate_confirmation_and_is_canonical() {
        let mut panel = CandidateReview::new(fixture());
        type_cidr(&mut panel, "93.184.216.10/29");
        assert!(panel.is_confirming());
        assert!(!panel.has_scope());
        assert!(panel.body().contains("93.184.216.8/29"));
        assert!(panel.body().contains("5"));
        assert!(panel.body().contains("Подтвердить"));
        panel.confirm_scope();
        assert!(panel.has_scope());
        let body = panel.body();
        assert!(body.contains("93.184.216.8/29"));
        assert!(body.contains("93.184.216.9"));
        assert!(body.contains("Добавленные вручную"));
        assert!(body.contains("не является разрешением на активное сканирование"));
    }

    #[test]
    fn denied_approval_and_esc_erase_temporary_scope() {
        let mut panel = CandidateReview::new(fixture());
        type_cidr(&mut panel, "93.184.216.8/29");
        assert!(panel.is_confirming());
        panel.decline();
        assert!(!panel.has_scope());
        assert!(!panel.is_confirming());
        assert!(!panel.body().contains("93.184.216.9"));
        panel.begin_cidr();
        panel.insert('x');
        assert!(panel.is_editing());
        assert!(!panel.back_or_close());
        assert!(!panel.is_editing());
        assert!(panel.back_or_close());
    }

    #[test]
    fn prohibit_broad_subnets_inferred_ownership_and_unassigned_prefixes() {
        for invalid in [
            "93.184.216.0/24",
            "93.184.216.0/23",
            "93.184.217.0/29",
            "10.0.0.0/24",
            "93.184.216.8/0",
            "93.184.216.8/33",
            "2606:4700::/64",
            "93.184.216.8/29garbage",
        ] {
            let mut panel = CandidateReview::new(fixture());
            type_cidr(&mut panel, invalid);
            assert!(!panel.is_confirming(), "{invalid}");
            assert!(!panel.has_scope(), "{invalid}");
            panel.confirm_scope();
            assert!(!panel.has_scope(), "{invalid}");
        }
    }

    #[test]
    fn assigned_mask_alone_cannot_confirm_cidr_without_operator_review() {
        let mut panel = CandidateReview::new(fixture());
        panel.confirm_scope(); // cannot skip input and review
        assert!(!panel.has_scope());
        panel.begin_cidr();
        for ch in "93.184.216.10/32".chars() {
            panel.insert(ch);
        }
        panel.review_input();
        assert!(panel.is_confirming());
        assert!(!panel.has_scope());
        panel.confirm_scope();
        assert!(panel.has_scope());
        // A /32 yields no neighbor candidates and remains offline.
        assert!(panel.body().contains("0 дополнительных"));
    }

    #[test]
    fn no_assigned_public_interface_cannot_approve_neighbor_expansion() {
        let mut panel = CandidateReview::new(NativeInterfaces::default());
        type_cidr(&mut panel, "93.184.216.8/29");
        assert!(!panel.is_confirming());
        assert!(!panel.has_scope());
        assert!(panel.body().contains("Нет назначенных публичных"));
    }

    #[test]
    fn input_is_bounded_and_never_becomes_network_target() {
        let mut panel = CandidateReview::new(fixture());
        panel.begin_cidr();
        for _ in 0..256 {
            panel.insert('1');
        }
        assert!(panel.input_length() <= MAX_CIDR_TEXT);
        panel.review_input();
        assert!(!panel.is_confirming());
        assert!(!panel.has_scope());
        assert!(!panel.body().contains("TLS 1.3 подтверждён"));
    }

    #[test]
    fn source_groups_have_no_transport_evidence_by_default() {
        let panel = CandidateReview::new(fixture());
        let (assigned, domains, manual) = panel.group_counts();
        assert_eq!(assigned, 1);
        assert_eq!(domains, 14);
        assert_eq!(manual, 0);
        let evidence = crate::camouflage_discovery::TlsEvidence::default();
        let rating = evidence.suitability(crate::camouflage_discovery::Transport::H2);
        assert_eq!(rating.score, 0);
        assert_eq!(rating.confidence, 0);
        assert!(!rating.eligible);
    }
}
