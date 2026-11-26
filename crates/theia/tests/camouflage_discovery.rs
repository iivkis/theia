//! M3.5b1: pure offline discovery planner and evidence scoring.
//! These tests deliberately do not make external network requests or pretend
//! that a planned address has presented a trustworthy TLS certificate.
use std::{net::IpAddr, str::FromStr};
use theia::camouflage_discovery::{
    build_plan, CandidateHost, CandidateSource, InterfaceAddress, NetworkPrefix, Observation,
    ServerSnapshot, TlsEvidence, Transport, Warning, MAX_CANDIDATES, POPULAR_HTTPS_DOMAINS,
};

fn server(address: &str, prefix_len: u8) -> ServerSnapshot {
    ServerSnapshot {
        interfaces: vec![InterfaceAddress {
            address: address.parse().unwrap(),
            prefix_len,
        }],
        ..ServerSnapshot::default()
    }
}

#[test]
fn popular_domains_are_seeded_without_a_manual_list_or_live_probe() {
    let plan = build_plan(&ServerSnapshot::default(), &[]);
    assert_eq!(plan.candidates.len(), POPULAR_HTTPS_DOMAINS.len());
    assert!(plan.candidates.len() >= 64);
    assert_eq!(
        POPULAR_HTTPS_DOMAINS
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        POPULAR_HTTPS_DOMAINS.len()
    );
    for domain in [
        "google.com",
        "samsung.com",
        "amd.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "cloudflare.com",
        "github.com",
        "mozilla.org",
        "wikipedia.org",
        "adobe.com",
        "intel.com",
        "nvidia.com",
        "ubuntu.com",
    ] {
        assert!(plan.candidates.iter().any(|candidate| {
            candidate.host == CandidateHost::Domain(domain)
                && candidate.source == CandidateSource::PopularDomain
        }));
    }
    assert!(plan.warnings.contains(&Warning::NoPublicServerAddress));
}

#[test]
fn public_server_addresses_are_discovered_but_neighbors_are_not_probed_by_default() {
    let mut snapshot = server("93.184.216.10", 24);
    snapshot.interfaces.push(InterfaceAddress {
        address: "2606:4700:4700::1111".parse().unwrap(),
        prefix_len: 64,
    });
    snapshot
        .inferred_provider_prefixes
        .push(NetworkPrefix::from_str("93.184.216.0/22").unwrap());

    let plan = build_plan(&snapshot, &[]);
    for ip in ["93.184.216.10", "2606:4700:4700::1111"] {
        assert!(plan.candidates.iter().any(|c| {
            c.host == CandidateHost::Ip(ip.parse::<IpAddr>().unwrap())
                && c.source == CandidateSource::ServerAddress
        }));
    }
    assert!(!plan
        .candidates
        .iter()
        .any(|c| { c.host == CandidateHost::Ip("93.184.216.11".parse().unwrap()) }));
    assert!(plan
        .warnings
        .contains(&Warning::ProviderPrefixNotAuthorization));
    assert_eq!(plan.candidates.len(), POPULAR_HTTPS_DOMAINS.len() + 2);
}

#[test]
fn authorized_small_ipv4_subnet_creates_a_bounded_deduplicated_queue() {
    let snapshot = server("93.184.216.10", 29);
    let authorized = [NetworkPrefix::from_str("93.184.216.8/29").unwrap()];
    let plan = build_plan(&snapshot, &authorized);
    assert_eq!(
        plan.candidates
            .iter()
            .filter(|c| c.source == CandidateSource::AuthorizedSubnet)
            .count(),
        5
    ); // .9, .11, .12, .13, .14; .10 is already the server
    assert!(!plan.candidates.iter().any(|c| {
        c.host == CandidateHost::Ip("93.184.216.8".parse().unwrap())
            || c.host == CandidateHost::Ip("93.184.216.15".parse().unwrap())
    }));
    assert_eq!(
        plan.candidates
            .iter()
            .filter(|c| c.host == CandidateHost::Ip("93.184.216.10".parse().unwrap()))
            .count(),
        1
    );
    assert_eq!(plan.warnings.len(), 0);
}

#[test]
fn approved_ipv4_range_cannot_expand_beyond_assigned_interface_prefix() {
    // A server may be assigned one /32 in a provider's /24. Containing the
    // server IP and operator approval alone must not enumerate neighbors.
    for assigned_prefix in [0, 28, 32, 33] {
        let plan = build_plan(
            &server("93.184.216.10", assigned_prefix),
            &["93.184.216.0/24".parse().unwrap()],
        );
        assert_eq!(
            plan.candidates.len(),
            POPULAR_HTTPS_DOMAINS.len() + 1,
            "prefix {assigned_prefix} expanded beyond the assigned range"
        );
        assert!(plan.warnings.contains(&Warning::RangeExceedsAssignedPrefix));
    }

    // A subset of the assigned /29 is still eligible with explicit approval.
    let plan = build_plan(
        &server("93.184.216.10", 29),
        &["93.184.216.8/30".parse().unwrap()],
    );
    assert!(plan.candidates.iter().any(|candidate| {
        candidate.host == CandidateHost::Ip("93.184.216.9".parse().unwrap())
            && candidate.source == CandidateSource::AuthorizedSubnet
    }));
    assert!(!plan.candidates.iter().any(|candidate| {
        candidate.host == CandidateHost::Ip("93.184.216.11".parse().unwrap())
    }));

    // A genuinely assigned /32 never needs neighbor expansion.
    let single = build_plan(
        &server("93.184.216.10", 32),
        &["93.184.216.10/32".parse().unwrap()],
    );
    assert_eq!(single.candidates.len(), POPULAR_HTTPS_DOMAINS.len() + 1);
    assert!(single.warnings.is_empty());
}

#[test]
fn broad_provider_range_and_unrelated_authorization_never_expand() {
    let mut snapshot = server("93.184.216.10", 24);
    snapshot
        .inferred_provider_prefixes
        .push("93.184.216.0/22".parse().unwrap());
    let plan = build_plan(
        &snapshot,
        &[
            "93.184.0.0/16".parse().unwrap(),
            "8.8.8.0/24".parse().unwrap(),
        ],
    );
    assert!(plan.warnings.contains(&Warning::RangeTooBroad));
    assert!(plan.warnings.contains(&Warning::RangeNotOnServer));
    assert!(plan
        .warnings
        .contains(&Warning::ProviderPrefixNotAuthorization));
    assert_eq!(plan.candidates.len(), POPULAR_HTTPS_DOMAINS.len() + 1);
}

#[test]
fn private_cgnat_documentation_ranges_and_nat_do_not_authorize_neighbor_sweeps() {
    for address in [
        "10.1.2.3",
        "100.96.0.2",
        "172.17.8.1",
        "192.168.0.1",
        "198.51.100.9",
        "203.0.113.5",
        "127.0.0.1",
    ] {
        let plan = build_plan(&server(address, 24), &[]);
        assert_eq!(plan.candidates.len(), POPULAR_HTTPS_DOMAINS.len());
        assert!(plan.warnings.contains(&Warning::NoPublicServerAddress));
    }
    let mut snapshot = server("10.1.2.3", 24);
    snapshot.egress = Some("93.184.216.10".parse().unwrap());
    let plan = build_plan(&snapshot, &["93.184.216.0/24".parse().unwrap()]);
    assert_eq!(plan.candidates.len(), POPULAR_HTTPS_DOMAINS.len() + 1);
    assert!(plan.warnings.contains(&Warning::NatEgressUnverified));
    assert!(plan.warnings.contains(&Warning::RangeNotOnServer));
}

#[test]
fn ipv6_does_not_enumerate_a_sixty_four_or_fabricate_neighbor_ips() {
    let snapshot = server("2606:4700:4700::1111", 64);
    let plan = build_plan(&snapshot, &["2606:4700:4700::/64".parse().unwrap()]);
    assert_eq!(plan.candidates.len(), POPULAR_HTTPS_DOMAINS.len() + 1);
    assert!(plan.warnings.contains(&Warning::Ipv6EnumerationUnsupported));
}

#[test]
fn candidates_are_capped_even_with_multiple_approved_subnets() {
    let mut snapshot = server("93.184.216.10", 24);
    snapshot.interfaces.push(InterfaceAddress {
        address: "93.184.217.10".parse().unwrap(),
        prefix_len: 24,
    });
    let approved = [
        "93.184.216.0/24".parse().unwrap(),
        "93.184.217.0/24".parse().unwrap(),
    ];
    let plan = build_plan(&snapshot, &approved);
    assert!(plan.candidates.len() <= MAX_CANDIDATES);
    assert!(plan.warnings.contains(&Warning::CandidateLimitReached));
    assert!(plan
        .candidates
        .iter()
        .any(|c| c.host == CandidateHost::Domain("google.com")));
}

#[test]
fn malformed_prefixes_are_rejected_without_panicking() {
    for raw in [
        "",
        "93.184.216.0",
        "93.184.216.0/33",
        "93.184.216.0/-1",
        "2606:4700::/129",
        "localhost/24",
        "93.184.216.0/a",
    ] {
        assert!(NetworkPrefix::from_str(raw).is_err(), "{raw}");
    }
    let normalized = NetworkPrefix::from_str("93.184.216.10/29").unwrap();
    assert_eq!(normalized, "93.184.216.8/29".parse().unwrap());
    assert!(normalized.contains("93.184.216.14".parse().unwrap()));
    assert!(!normalized.contains("93.184.216.16".parse().unwrap()));
}

#[test]
fn unobserved_tls_is_not_ranked_as_usable_camouflage() {
    let evidence = TlsEvidence::default();
    for transport in [Transport::H2, Transport::H3] {
        let assessment = evidence.suitability(transport);
        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.confidence, 0);
        assert!(!assessment.eligible);
        assert!(!assessment.blockers.is_empty());
    }
}

#[test]
fn certificate_fingerprint_and_transport_mismatches_fail_closed() {
    let mut evidence = TlsEvidence {
        tls13: Observation::Verified,
        trusted_chain: Observation::Verified,
        sni_san_match: Observation::Verified,
        certificate_current: Observation::Verified,
        reachable: Observation::Verified,
        alpn_h2: Observation::Verified,
        alpn_h3: Observation::Unknown,
        theia_fingerprint_match: Observation::Verified,
    };
    let approved = evidence.suitability(Transport::H2);
    assert!(approved.eligible);
    assert_eq!(approved.score, 100);
    assert_eq!(approved.confidence, 100);
    assert!(!evidence.suitability(Transport::H3).eligible);
    evidence.trusted_chain = Observation::Rejected;
    let bad_ca = evidence.suitability(Transport::H2);
    assert!(!bad_ca.eligible);
    assert!(bad_ca.score < approved.score);
    assert!(bad_ca.blockers.contains(&"untrusted certificate chain"));
    evidence.trusted_chain = Observation::Verified;
    evidence.certificate_current = Observation::Unknown;
    assert!(!evidence.suitability(Transport::H2).eligible);
}
