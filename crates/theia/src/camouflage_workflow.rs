//! M3.5b2b2: safe, zero-network preview connecting native assigned addresses,
//! a verified HTTPS-echo *claim*, and optional caller-approved CIDRs.
//!
//! Neither the local prefix nor the public-egress witness proves ownership or
//! authorization. Even with a nonempty plan, **nothing here runs a scanner**.
use crate::{
    camouflage_discovery::{
        build_plan, plausible_public_address, DiscoveryPlan, NetworkPrefix, ServerSnapshot,
    },
    camouflage_egress::EgressObservation,
    camouflage_interfaces::{collect_assigned_interfaces, NativeInterfaces},
};
use std::{io, time::SystemTime};

/// Explicit caller-supplied *planning* scope; not an active network approval.
/// No third-party domain / public IP is contacted by any preview function.
#[derive(Debug, Clone, Copy)]
pub enum PreviewScope<'a> {
    PassiveOnly,
    OperatorApprovedCidrs(&'a [NetworkPrefix]),
}

/// A TLS witness attests only to an observed egress IP from its vantage.
/// An unmatched IP may indicate NAT, egress routing or a stale observation;
/// a matched IP does not prove ownership or permission to scan a CIDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressAssessment {
    Unknown,
    MatchesAssignedAddress,
    DiffersFromAssignedAddress,
}

#[derive(Debug, Clone)]
pub struct DiscoveryPreview {
    pub plan: DiscoveryPlan,
    pub egress_assessment: EgressAssessment,
    pub assigned_public_addresses: usize,
    pub egress_observed_at: Option<SystemTime>,
}

/// Turn real or fixture-provided local metadata into an offline preview.
/// A failed or missing egress observation never invents an IP, a provider
/// subnet, or a permission to enumerate any address range.
pub fn build_preview(
    native: &NativeInterfaces,
    egress: Option<&EgressObservation>,
    scope: PreviewScope<'_>,
) -> DiscoveryPreview {
    let mut snapshot: ServerSnapshot = native.server_snapshot();
    // Independent defense-in-depth validation of API-supplied observations.
    snapshot.interfaces.retain(|iface| match iface.address {
        std::net::IpAddr::V4(_) => (1..=32).contains(&iface.prefix_len),
        std::net::IpAddr::V6(_) => (1..=128).contains(&iface.prefix_len),
    });
    let assigned_public_addresses = snapshot
        .interfaces
        .iter()
        .filter(|iface| plausible_public_address(iface.address))
        .count();
    let egress_assessment = match egress {
        None => EgressAssessment::Unknown,
        Some(report) => {
            let address = report.ip();
            snapshot.egress = Some(address);
            if snapshot.interfaces.iter().any(|iface| iface.address == address) {
                EgressAssessment::MatchesAssignedAddress
            } else {
                EgressAssessment::DiffersFromAssignedAddress
            }
        }
    };
    let approved = match scope {
        PreviewScope::PassiveOnly => &[][..],
        PreviewScope::OperatorApprovedCidrs(prefixes) => prefixes,
    };
    DiscoveryPreview {
        plan: build_plan(&snapshot, approved),
        egress_assessment,
        assigned_public_addresses,
        egress_observed_at: egress.map(EgressObservation::observed_at),
    }
}

/// Convenience composition root for Linux only: local getifaddrs, then pure
/// preview. No DNS, remote calls, egress lookup, or implicit CIDR approval.
/// Windows returns Unsupported until its native interface collector exists.
pub fn collect_preview(
    egress: Option<&EgressObservation>,
    scope: PreviewScope<'_>,
) -> io::Result<DiscoveryPreview> {
    let native = collect_assigned_interfaces()?;
    Ok(build_preview(&native, egress, scope))
}
