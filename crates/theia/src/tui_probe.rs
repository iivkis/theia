//! M4.5b: server-only exact assigned public-IP TLS/H2 check UI state.
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
        assert_eq!(panel.selected_address(), Some("93.184.216.10".parse::<IpAddr>().unwrap()));
        assert!(panel.body().contains("93.184.216.10"));
        assert!(!panel.body().contains("10.0.0.1"));
        assert!(!panel.body().contains("93.184.216.12"));
        panel.confirm_and_start(); // Without confirm, must be inert.
        assert!(!panel.is_consent_pending());

        panel.next();
        assert_eq!(panel.selected_address(), Some("93.184.216.11".parse().unwrap()));
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
