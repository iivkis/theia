//! M4.5h: one explicitly consented DNS A/AAAA observation for a single
//! known catalogue domain. Safe, bounded, local OS resolver only.
//!
//! Does NOT authorize active TLS probing. Follow-up TLS/QUIC requests must
//! separately approve each pinned public IP:443 and matching domain SNI.
//! DNS answers are never treated as ownership or REALITY compatibility.
use crate::camouflage_discovery::{plausible_public_address, POPULAR_HTTPS_DOMAINS};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::time::timeout;

pub const MAX_DNS_RECORDS: usize = 64;
pub const MAX_PINNED_IPS: usize = 8;
pub const DNS_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsConsent {
    Denied,
    Approved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    NotApproved,
    NotCatalogued,
    TimedOut,
    /// DNS reply reached the UI after its 60-second freshness window.
    StaleObservation,
    LookupFailed,
    NoPublicAddresses,
    UnsafeAddress,
    TooManyAnswers,
}

/// Strict, case-sensitive bounded static whitelist; not an ownership grant.
/// No DNS when the caller has not collected separate prior consent.
pub fn validate_dns_request(domain: &str, consent: DnsConsent) -> Result<(), DnsError> {
    if consent != DnsConsent::Approved {
        return Err(DnsError::NotApproved);
    }
    if !POPULAR_HTTPS_DOMAINS.contains(&domain) {
        return Err(DnsError::NotCatalogued);
    }
    Ok(())
}

/// Converts an already acquired DNS answer set into a bounded list of exact
/// public IPs for *review*, not for automatic network probing. Reject the
/// whole set if any answer is private, special-purpose, invalid or not 443.
/// Never permit a mixed good+bad answer to smuggle an SSRF destination.
pub fn vet_dns_answers(answers: &[SocketAddr]) -> Result<Vec<IpAddr>, DnsError> {
    if answers.len() > MAX_DNS_RECORDS {
        return Err(DnsError::TooManyAnswers);
    }
    let mut ips = Vec::new();
    let mut seen = HashSet::new();
    for address in answers {
        if address.port() != 443 || !plausible_public_address(address.ip()) {
            return Err(DnsError::UnsafeAddress);
        }
        if seen.insert(address.ip()) && ips.len() < MAX_PINNED_IPS {
            ips.push(address.ip());
        }
    }
    if ips.is_empty() {
        return Err(DnsError::NoPublicAddresses);
    }
    Ok(ips)
}

/// Exactly one OS resolver lookup for an operator-selected catalogue domain.
/// No retries, redirects, remote HTTP or connection to any returned IP.
/// Timeout covers lookup + filtering; only up to 64 answers are materialized
/// and all are inspected for unsafe addresses. The active TLS/QUIC path must
/// pin an explicitly selected IP, never invoke DNS again.
pub async fn resolve_catalogued_domain(
    domain: &'static str,
    consent: DnsConsent,
) -> Result<Vec<IpAddr>, DnsError> {
    validate_dns_request(domain, consent)?;
    timeout(DNS_DEADLINE, async move {
        let resolved = tokio::net::lookup_host((domain, 443))
            .await
            .map_err(|_| DnsError::LookupFailed)?;
        let mut addresses = Vec::new();
        for address in resolved {
            if addresses.len() == MAX_DNS_RECORDS {
                return Err(DnsError::TooManyAnswers);
            }
            addresses.push(address);
        }
        vet_dns_answers(&addresses)
    })
    .await
    .map_err(|_| DnsError::TimedOut)?
}

// M4.5h tests first: never query DNS or probe a third party implicitly.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_membership_and_distinct_consent_are_required_before_lookup() {
        assert_eq!(
            validate_dns_request("google.com", DnsConsent::Denied),
            Err(DnsError::NotApproved)
        );
        assert_eq!(
            validate_dns_request("unlisted.example", DnsConsent::Approved),
            Err(DnsError::NotCatalogued)
        );
        assert_eq!(
            validate_dns_request("google.com", DnsConsent::Approved),
            Ok(())
        );
        assert_eq!(
            validate_dns_request("Google.com", DnsConsent::Approved),
            Err(DnsError::NotCatalogued)
        );
    }

    #[tokio::test]
    async fn denial_has_no_dns_side_effects_and_returns_immediately() {
        assert_eq!(
            resolve_catalogued_domain("google.com", DnsConsent::Denied).await,
            Err(DnsError::NotApproved)
        );
        assert_eq!(
            resolve_catalogued_domain("unlisted.example", DnsConsent::Approved).await,
            Err(DnsError::NotCatalogued)
        );
    }

    #[test]
    fn dns_answers_require_public_ips_and_exact_https_port() {
        let valid = [
            "93.184.216.10:443".parse().unwrap(),
            "[2606:4700::1111]:443".parse().unwrap(),
            "93.184.216.10:443".parse().unwrap(),
        ];
        let ips = vet_dns_answers(&valid).unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "93.184.216.10".parse::<IpAddr>().unwrap());
        assert_eq!(ips[1], "2606:4700::1111".parse::<IpAddr>().unwrap());
        for bad in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "169.254.0.3:443",
            "192.168.1.1:443",
            "100.64.0.1:443",
            "203.0.113.5:443",
            "[::1]:443",
            "[2001:db8::1]:443",
            "93.184.216.10:22",
        ] {
            let mut mixed = valid.to_vec();
            mixed.push(bad.parse().unwrap());
            assert_eq!(
                vet_dns_answers(&mixed),
                Err(DnsError::UnsafeAddress),
                "{bad}"
            );
        }
    }

    #[test]
    fn empty_or_oversized_answers_are_refused_without_partial_approval() {
        assert_eq!(vet_dns_answers(&[]), Err(DnsError::NoPublicAddresses));
        let large: Vec<SocketAddr> = (0..=MAX_DNS_RECORDS)
            .map(|i| SocketAddr::new(IpAddr::from([93, 184, 216, (i + 1) as u8]), 443))
            .collect();
        assert_eq!(vet_dns_answers(&large), Err(DnsError::TooManyAnswers));
    }

    #[test]
    fn published_candidate_list_never_exceeds_eight_even_with_many_public_answers() {
        let addresses: Vec<SocketAddr> = (1..=16)
            .map(|octet| SocketAddr::new(IpAddr::from([93, 184, 216, octet]), 443))
            .collect();
        let ips = vet_dns_answers(&addresses).unwrap();
        assert_eq!(ips.len(), MAX_PINNED_IPS);
        assert_eq!(ips[0], "93.184.216.1".parse::<IpAddr>().unwrap());
        assert_eq!(ips[7], "93.184.216.8".parse::<IpAddr>().unwrap());
    }
}
