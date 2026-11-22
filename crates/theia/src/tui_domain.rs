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
