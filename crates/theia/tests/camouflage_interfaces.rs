//! M3.5b2b1: native Linux interface+prefix observations, with no active
//! scanning, remote IP lookup, user consent inference or OS proxy changes.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use theia::camouflage_interfaces::{collect_assigned_interfaces, contiguous_netmask_prefix};
#[cfg(target_os = "linux")]
use theia::camouflage_interfaces::InterfaceSource;

#[test]
fn contiguous_ipv4_and_ipv6_netmasks_only() {
    let v4 = |s: &str| IpAddr::V4(s.parse::<Ipv4Addr>().unwrap());
    let v6 = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());

    assert_eq!(contiguous_netmask_prefix(v4("255.255.255.255")), Some(32));
    assert_eq!(contiguous_netmask_prefix(v4("255.255.255.248")), Some(29));
    assert_eq!(contiguous_netmask_prefix(v4("255.255.255.0")), Some(24));
    assert_eq!(contiguous_netmask_prefix(v4("0.0.0.0")), None);
    assert_eq!(contiguous_netmask_prefix(v4("255.0.255.0")), None);
    assert_eq!(contiguous_netmask_prefix(v4("255.255.255.1")), None);

    assert_eq!(
        contiguous_netmask_prefix(v6("ffff:ffff:ffff:ffff::")),
        Some(64)
    );
    assert_eq!(
        contiguous_netmask_prefix(v6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")),
        Some(128)
    );
    assert_eq!(contiguous_netmask_prefix(v6("::")), None);
    assert_eq!(contiguous_netmask_prefix(v6("ffff:ffff::1")), None);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_collects_actual_loopback_assignment_without_remote_io_or_egress_guess() {
    let observed = collect_assigned_interfaces().expect("Linux getifaddrs must work");
    // The CI Linux runner must have its ordinary loopback, or it is not an
    // acceptable environment for the collector integration regression.
    let local = observed
        .interfaces
        .iter()
        .find(|entry| entry.address == IpAddr::V4(Ipv4Addr::LOCALHOST))
        .expect("native loopback assignment expected");
    assert!(!local.interface_name.is_empty());
    assert_eq!(local.source, InterfaceSource::LinuxGetifaddrs);
    assert!((1..=32).contains(&local.prefix_len));
    assert!(local.is_up);
    assert!(observed.interfaces.len() <= 4096);

    let snapshot = observed.server_snapshot();
    assert!(
        snapshot.egress.is_none(),
        "interface collection cannot prove NAT egress"
    );
    assert!(snapshot.inferred_provider_prefixes.is_empty());
    assert_eq!(snapshot.interfaces.len(), observed.interfaces.len());
    for entry in &observed.interfaces {
        assert!(!entry.interface_name.is_empty());
        assert!(entry.prefix_len >= 1);
        assert!(entry.prefix_len <= if entry.address.is_ipv4() { 32 } else { 128 });
        assert!(snapshot
            .interfaces
            .iter()
            .any(|s| { s.address == entry.address && s.prefix_len == entry.prefix_len }));
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platforms_fail_closed_instead_of_inventing_interface_prefixes() {
    let err = collect_assigned_interfaces().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}
