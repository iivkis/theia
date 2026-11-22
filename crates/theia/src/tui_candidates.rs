//! M4.5c: offline candidate groups and explicit *planning-only* CIDR scope.
//! Test-first invariants. No active probing or ownership inference.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::camouflage_interfaces::{InterfaceSource, ObservedInterface};
    use std::net::IpAddr;

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
        let _unused: IpAddr = "93.184.216.10".parse().unwrap();
    }
}
