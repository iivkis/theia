//! M3.5b1: bounded, zero-I/O candidate planning for a *future* authorized
//! TLS camouflage evaluator. This module never resolves DNS, probes an IP,
//! verifies an SSL certificate or enables a REALITY-like security mode.
//!
//! Local addresses and explicitly approved CIDRs are observations supplied
//! by a future OS/consent collector, **not** discovered by this module.
//! BGP/RDAP provider routes MUST NOT be treated as subnet ownership.
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// Inclusive of domain seeds and known server addresses. Never allocate a
/// queue proportional to the size of an untrusted CIDR.
pub const MAX_CANDIDATES: usize = 256;

/// Version 1 starter catalogue. Not claims of TLS compatibility, suitability,
/// domain ownership or authorization to actively scan third-party services.
pub const POPULAR_HTTPS_DOMAINS: [&str; 14] = [
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
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateHost {
    Ip(IpAddr),
    Domain(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSource {
    ServerAddress,
    AuthorizedSubnet,
    PopularDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub host: CandidateHost,
    pub source: CandidateSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    NoPublicServerAddress,
    NatEgressUnverified,
    ProviderPrefixNotAuthorization,
    RangeNotOnServer,
    RangeTooBroad,
    Ipv6EnumerationUnsupported,
    CandidateLimitReached,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerSnapshot {
    /// **Observed** local interfaces; may include private/LAN addresses.
    pub interfaces: Vec<InterfaceAddress>,
    /// A known egress address (e.g. via operator); not proof that the whole
    /// surrounding provider subnet is controlled by the server operator.
    pub egress: Option<IpAddr>,
    /// Context only: these ranges are **never** authorization for expansion.
    pub inferred_provider_prefixes: Vec<NetworkPrefix>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixError {
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkPrefix {
    network: IpAddr,
    bits: u8,
}

impl NetworkPrefix {
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                mask_v4(address, self.bits) == network
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                mask_v6(address, self.bits) == network
            }
            _ => false,
        }
    }
}

impl FromStr for NetworkPrefix {
    type Err = PrefixError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (address, bits) = text.split_once('/').ok_or(PrefixError::Invalid)?;
        let address = address.parse::<IpAddr>().map_err(|_| PrefixError::Invalid)?;
        let bits = bits.parse::<u8>().map_err(|_| PrefixError::Invalid)?;
        let network = match address {
            IpAddr::V4(address) if bits <= 32 => IpAddr::V4(mask_v4(address, bits)),
            IpAddr::V6(address) if bits <= 128 => IpAddr::V6(mask_v6(address, bits)),
            _ => return Err(PrefixError::Invalid),
        };
        Ok(Self { network, bits })
    }
}

fn mask_v4(address: Ipv4Addr, bits: u8) -> Ipv4Addr {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    Ipv4Addr::from(u32::from(address) & mask)
}

fn mask_v6(address: Ipv6Addr, bits: u8) -> Ipv6Addr {
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    Ipv6Addr::from(u128::from(address) & mask)
}

/// Conservative globally-routable candidate filter: reject common special
/// purpose, private, carrier NAT, documentation, multicast, and reserved IPs.
/// This is a defense-in-depth filter, NOT a comprehensive IANA registry check
/// or authorization to reach a remote host.
fn plausible_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            if matches!(a, 0 | 10 | 127) || a >= 224 {
                return false;
            }
            if (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && matches!(b, 0 | 168))
                || (a == 198 && (18..=19).contains(&b))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
            {
                return false;
            }
            !(a == 192 && b == 0 && c == 2)
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            (segments[0] & 0xe000) == 0x2000
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && !(segments[0] == 0x2001 && segments[1] == 0)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryPlan {
    pub candidates: Vec<Candidate>,
    pub warnings: Vec<Warning>,
}

fn note(warnings: &mut Vec<Warning>, warning: Warning) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

fn add_candidate(plan: &mut DiscoveryPlan, host: CandidateHost, source: CandidateSource) {
    if plan.candidates.iter().any(|candidate| candidate.host == host) {
        return;
    }
    if plan.candidates.len() == MAX_CANDIDATES {
        note(&mut plan.warnings, Warning::CandidateLimitReached);
        return;
    }
    plan.candidates.push(Candidate { host, source });
}

/// Build a *passive offline* plan. The caller must gather interface information
/// and operator-authorized subnet permissions separately. The result is never
/// proof of TLS validity or authorization to connect to any candidate.
///
/// Approvals must be explicitly collected by the future UI and cannot be
/// inferred from BGP/RDAP data. A CIDR must contain a *public assigned local
/// interface* before it is expanded. A NAT egress alone does not qualify.
/// We don't enumerate IPv6 and never expand IPv4 ranges broader than /24.
/// No sockets, DNS requests or TLS probes are used by this function.
pub fn build_plan(snapshot: &ServerSnapshot, approved: &[NetworkPrefix]) -> DiscoveryPlan {
    let mut plan = DiscoveryPlan {
        candidates: Vec::new(),
        warnings: Vec::new(),
    };
    for domain in POPULAR_HTTPS_DOMAINS {
        add_candidate(
            &mut plan,
            CandidateHost::Domain(domain),
            CandidateSource::PopularDomain,
        );
    }
    let mut any_public_assigned = false;
    for interface in &snapshot.interfaces {
        if plausible_public_address(interface.address) {
            any_public_assigned = true;
            add_candidate(
                &mut plan,
                CandidateHost::Ip(interface.address),
                CandidateSource::ServerAddress,
            );
        }
    }
    if !any_public_assigned {
        note(&mut plan.warnings, Warning::NoPublicServerAddress);
    }
    if let Some(egress) = snapshot.egress {
        if plausible_public_address(egress) {
            if !snapshot.interfaces.iter().any(|iface| iface.address == egress) {
                note(&mut plan.warnings, Warning::NatEgressUnverified);
            }
            add_candidate(
                &mut plan,
                CandidateHost::Ip(egress),
                CandidateSource::ServerAddress,
            );
        }
    }
    if !snapshot.inferred_provider_prefixes.is_empty() {
        note(&mut plan.warnings, Warning::ProviderPrefixNotAuthorization);
    }

    for prefix in approved {
        let attached = snapshot.interfaces.iter().any(|iface| {
            plausible_public_address(iface.address) && prefix.contains(iface.address)
        });
        if !attached {
            note(&mut plan.warnings, Warning::RangeNotOnServer);
            continue;
        }
        match prefix.network {
            IpAddr::V6(_) => {
                note(&mut plan.warnings, Warning::Ipv6EnumerationUnsupported);
            }
            IpAddr::V4(_) if prefix.bits < 24 => {
                note(&mut plan.warnings, Warning::RangeTooBroad);
            }
            IpAddr::V4(start) => {
                // At most 256 IPv4 values, even for malformed input or /0.
                let count = 1u32 << (32 - prefix.bits);
                let base = u32::from(start);
                for offset in 0..count {
                    // Ordinary IPv4 subnet network/broadcast addresses are
                    // not usable hosts. /31 and /32 are valid host prefixes.
                    if prefix.bits <= 30 && (offset == 0 || offset == count - 1) {
                        continue;
                    }
                    let address = IpAddr::V4(Ipv4Addr::from(base + offset));
                    if plausible_public_address(address) {
                        add_candidate(
                            &mut plan,
                            CandidateHost::Ip(address),
                            CandidateSource::AuthorizedSubnet,
                        );
                    }
                }
            }
        }
    }
    plan
}

/// Observation is supplied by a *future verified TLS probe*, never inferred
/// from a domain's popularity, DNS result, or mere presence of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Observation {
    Verified,
    Rejected,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    H2,
    H3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TlsEvidence {
    pub tls13: Observation,
    pub trusted_chain: Observation,
    pub sni_san_match: Observation,
    pub certificate_current: Observation,
    pub reachable: Observation,
    pub alpn_h2: Observation,
    pub alpn_h3: Observation,
    pub theia_fingerprint_match: Observation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suitability {
    /// Heuristic evidence score, NOT probability of bypassing DPI.
    pub score: u8,
    /// Percentage of the seven transport-relevant conditions measured.
    pub confidence: u8,
    /// All essential observations verified for this transport.
    pub eligible: bool,
    pub blockers: Vec<&'static str>,
}

impl TlsEvidence {
    /// Rate supplied observations. Unmeasured data contributes ZERO points,
    /// cannot yield eligible=true, and is surfaced as an explicit blocker.
    /// This method does not perform TLS or confirm the provenance of evidence.
    pub fn suitability(&self, transport: Transport) -> Suitability {
        let alpn = match transport {
            Transport::H2 => self.alpn_h2,
            Transport::H3 => self.alpn_h3,
        };
        let checks = [
            (self.tls13, 15, "TLS1.3 not measured", "TLS1.3 rejected"),
            (self.trusted_chain, 15, "certificate chain unverified", "untrusted certificate chain"),
            (self.sni_san_match, 15, "SNI/SAN not measured", "SNI/SAN mismatch"),
            (self.certificate_current, 10, "certificate validity unverified", "certificate expired or not yet valid"),
            (self.reachable, 10, "reachability unverified", "endpoint unreachable"),
            (alpn, 15, "ALPN not measured", "ALPN not supported"),
            (self.theia_fingerprint_match, 20, "Theia fingerprint not measured", "Theia fingerprint mismatch"),
        ];
        let mut score = 0u8;
        let mut observed = 0u8;
        let mut blockers = Vec::new();
        for (state, weight, unknown, rejected) in checks {
            match state {
                Observation::Verified => {
                    score += weight;
                    observed += 1;
                }
                Observation::Rejected => {
                    observed += 1;
                    blockers.push(rejected);
                }
                Observation::Unknown => blockers.push(unknown),
            }
        }
        Suitability {
            score,
            confidence: observed * 100 / 7,
            eligible: blockers.is_empty(),
            blockers,
        }
    }
}
