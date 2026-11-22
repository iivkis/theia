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
            build_preview(&native, None, PreviewScope::OperatorApprovedCidrs(&[subnet]))
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
        let preview =
            build_preview(&native, None, PreviewScope::OperatorApprovedCidrs(&[range]));
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
        let preview = build_preview(&NativeInterfaces::default(), None, PreviewScope::PassiveOnly);
        let mut unavailable = CandidateBatchPanel::new(preview, None);
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
            panel.preview.plan.candidates.iter().filter(|c|
                c.source == CandidateSource::AuthorizedSubnet).count(),
            5
        );
        panel.ask_confirmation();
        assert!(panel.back_or_close() == false);
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
