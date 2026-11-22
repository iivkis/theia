// M4.5h tests first: never query DNS or probe a third party implicitly.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_membership_and_distinct_consent_are_required_before_lookup() {
        assert_eq!(validate_dns_request("google.com", DnsConsent::Denied), Err(DnsError::NotApproved));
        assert_eq!(validate_dns_request("unlisted.example", DnsConsent::Approved), Err(DnsError::NotCatalogued));
        assert_eq!(validate_dns_request("google.com", DnsConsent::Approved), Ok(()));
        assert_eq!(validate_dns_request("Google.com", DnsConsent::Approved), Err(DnsError::NotCatalogued));
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
            assert_eq!(vet_dns_answers(&mixed), Err(DnsError::UnsafeAddress), "{bad}");
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
        assert_eq!(ips[0], "93.184.216.1".parse().unwrap());
        assert_eq!(ips[7], "93.184.216.8".parse().unwrap());
    }
}
