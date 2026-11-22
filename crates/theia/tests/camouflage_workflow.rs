//! M3.5b2b2: zero-I/O network candidate preview, explicit planning scopes.
use std::{io::ErrorKind, net::IpAddr};
use theia::{
    camouflage_discovery::{CandidateHost, CandidateSource, NetworkPrefix, Warning, POPULAR_HTTPS_DOMAINS},
    camouflage_interfaces::{InterfaceSource, NativeInterfaces, ObservedInterface},
    camouflage_workflow::{build_preview, collect_preview, EgressAssessment, PreviewScope},
};

fn native(ip: &str, prefix: u8, up: bool) -> NativeInterfaces {
    NativeInterfaces {
        interfaces: vec![ObservedInterface {
            interface_name: "eth-test".into(),
            address: ip.parse().unwrap(),
            prefix_len: prefix,
            is_up: up,
            source: InterfaceSource::LinuxGetifaddrs,
        }],
    }
}

#[test]
fn passive_preview_includes_observations_but_never_expands_neighbour_addresses() {
    let n = native("93.184.216.10", 29, true);
    let preview = build_preview(&n, None, PreviewScope::PassiveOnly);
    assert_eq!(preview.egress_assessment, EgressAssessment::Unknown);
    assert!(preview.egress_observed_at.is_none());
    assert_eq!(preview.assigned_public_addresses, 1);
    assert_eq!(preview.plan.candidates.len(), POPULAR_HTTPS_DOMAINS.len() + 1);
    assert!(preview.plan.candidates.iter().any(|entry| {
        entry.host == CandidateHost::Ip("93.184.216.10".parse::<IpAddr>().unwrap())
            && entry.source == CandidateSource::ServerAddress
    }));
    assert!(!preview.plan.candidates.iter().any(|entry| {
        entry.host == CandidateHost::Ip("93.184.216.11".parse::<IpAddr>().unwrap())
    }));
}

#[test]
fn explicit_small_cidr_expands_only_inside_verified_assigned_prefix() {
    let n = native("93.184.216.10", 29, true);
    let approved = ["93.184.216.8/29".parse::<NetworkPrefix>().unwrap()];
    let preview = build_preview(&n, None, PreviewScope::OperatorApprovedCidrs(&approved));
    assert_eq!(preview.plan.candidates.len(), POPULAR_HTTPS_DOMAINS.len() + 6);
    assert!(preview.plan.candidates.iter().any(|entry| {
        entry.host == CandidateHost::Ip("93.184.216.11".parse().unwrap())
            && entry.source == CandidateSource::AuthorizedSubnet
    }));
    assert!(!preview.plan.candidates.iter().any(|entry| {
        entry.host == CandidateHost::Ip("93.184.216.15".parse().unwrap())
    }));

    // Even explicit planning consent cannot override a /32 host assignment.
    let single = native("93.184.216.10", 32, true);
    let blocked = build_preview(&single, None, PreviewScope::OperatorApprovedCidrs(&approved));
    assert!(blocked.plan.warnings.contains(&Warning::RangeExceedsAssignedPrefix));
    assert_eq!(blocked.plan.candidates.len(), POPULAR_HTTPS_DOMAINS.len() + 1);
}

#[test]
fn malformed_or_down_interface_cannot_supply_public_prefix_authorization() {
    let approved = ["93.184.216.0/24".parse::<NetworkPrefix>().unwrap()];
    for (prefix, up) in [(0, true), (33, true), (24, false)] {
        let preview = build_preview(
            &native("93.184.216.10", prefix, up),
            None,
            PreviewScope::OperatorApprovedCidrs(&approved),
        );
        assert_eq!(
            preview.plan.candidates.len(), POPULAR_HTTPS_DOMAINS.len(),
            "invalid interface prefix {prefix} or up={up} must not grant neighbors"
        );
        assert_eq!(preview.assigned_public_addresses, 0);
        assert!(preview.plan.warnings.contains(&Warning::NoPublicServerAddress));
        assert!(preview.plan.warnings.contains(&Warning::RangeNotOnServer));
    }
}

#[test]
fn private_or_loopback_interfaces_do_not_make_public_cidr_scannable() {
    let approved = ["93.184.216.0/24".parse::<NetworkPrefix>().unwrap()];
    for address in ["127.0.0.1", "10.0.0.9", "100.64.8.1"] {
        let preview = build_preview(
            &native(address, 24, true),
            None,
            PreviewScope::OperatorApprovedCidrs(&approved),
        );
        assert_eq!(preview.assigned_public_addresses, 0);
        assert_eq!(preview.plan.candidates.len(), POPULAR_HTTPS_DOMAINS.len());
        assert!(preview.plan.warnings.contains(&Warning::RangeNotOnServer));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn actual_native_linux_preview_never_queries_external_egress_or_expands_neighbors() {
    let result = collect_preview(None, PreviewScope::PassiveOnly).unwrap();
    assert_eq!(result.egress_assessment, EgressAssessment::Unknown);
    assert!(result.egress_observed_at.is_none());
    assert!(result.plan.candidates.len() >= POPULAR_HTTPS_DOMAINS.len());
    assert!(!result.plan.candidates.iter().any(|entry| entry.source == CandidateSource::AuthorizedSubnet));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn native_preview_is_explicitly_unsupported_without_windows_native_collector() {
    assert_eq!(
        collect_preview(None, PreviewScope::PassiveOnly).unwrap_err().kind(),
        ErrorKind::Unsupported
    );
}
