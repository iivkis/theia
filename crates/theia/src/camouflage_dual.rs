//! M4.5e: one explicitly authorized exact-IP candidate gets independent
//! TCP/TLS1.3/h2 AND UDP/QUIC/TLS1.3/h3 observations.
//! No DNS, CIDR expansion, domain sweep, fallback or REALITY claim.
use crate::{
    camouflage_discovery::{CandidateHost, CandidateSource, Observation},
    camouflage_h3_probe::{probe_quic_h3, H3ProbeError, H3ProbeReport},
    camouflage_probe::{probe_tls_h2, ProbeApproval, ProbeError, ProbeReport, ProbeRequest},
    camouflage_workflow::DiscoveryPreview,
};
use rustls::{pki_types::ServerName, RootCertStore};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

#[derive(Clone)]
pub struct DualProbeTarget {
    pub request: ProbeRequest,
    pub roots: RootCertStore,
    pub approval: ProbeApproval,
}

impl fmt::Debug for DualProbeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DualProbeTarget(<redacted>)")
    }
}

/// One reviewed source. The source is not a blanket network permission:
/// every actual IP/port additionally needs an exact ProbeApproval. The domain
/// variant never does DNS and binds both SNI and the pinned socket address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateConsent {
    PlannedIp,
    PinnedDomain {
        domain: &'static str,
        pinned_ip: IpAddr,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DualProbeError {
    NotApproved,
    InvalidServerName,
    InvalidDeadline,
    NoTrustAnchors,
    UnplannedAddress,
    UnplannedDomain,
    DomainNameMismatch,
    DomainAddressMismatch,
    SelfReference,
}

/// Both observations are retained independently, including a timeout or
/// ordinary PKI rejection on just one transport. No implicit retry or fallback.
#[derive(Clone)]
pub struct DualProbeReport {
    pub address: SocketAddr,
    pub h2: Result<ProbeReport, ProbeError>,
    pub h3: Result<H3ProbeReport, H3ProbeError>,
}

impl fmt::Debug for DualProbeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DualProbeReport")
            .field("h2_verified", &self.h2.is_ok())
            .field("h3_verified", &self.h3.is_ok())
            .finish()
    }
}

impl DualProbeReport {
    /// Strictly both independently verified on the SAME pinned IP. This is
    /// just a TLS/QUIC transport-level witness; H3 HTTP semantics, browser
    /// fingerprint and REALITY-like server authentication remain unmeasured.
    pub fn h2_verified(&self) -> bool {
        self.h2.as_ref().is_ok_and(|h2| {
            h2.connected_ip == self.address.ip()
                && h2.evidence.tls13 == Observation::Verified
                && h2.evidence.trusted_chain == Observation::Verified
                && h2.evidence.sni_san_match == Observation::Verified
                && h2.evidence.certificate_current == Observation::Verified
                && h2.evidence.reachable == Observation::Verified
                && h2.evidence.alpn_h2 == Observation::Verified
        })
    }

    pub fn h3_verified(&self) -> bool {
        self.h3.as_ref().is_ok_and(|h3| {
            h3.connected_ip == self.address.ip()
                && h3.evidence.tls13 == Observation::Verified
                && h3.evidence.trusted_chain == Observation::Verified
                && h3.evidence.sni_san_match == Observation::Verified
                && h3.evidence.certificate_current == Observation::Verified
                && h3.evidence.reachable == Observation::Verified
                && h3.evidence.alpn_h3 == Observation::Verified
        })
    }

    pub fn both_transports_verified(&self) -> bool {
        self.h2_verified() && self.h3_verified()
    }

    /// Current releases have no cryptographically authenticated REALITY-like
    /// mode and no measured Theia browser fingerprint. Never infer ready.
    pub fn reality_eligible(&self) -> bool {
        false
    }
}

/// A passive preview can identify known local/egress addresses. This is
/// a rejection check only: an absent match is not proof of non-self routing.
pub(crate) fn known_server_address(preview: &DiscoveryPreview, ip: IpAddr) -> bool {
    preview.plan.candidates.iter().any(|candidate| {
        candidate.source == CandidateSource::ServerAddress
            && candidate.host == CandidateHost::Ip(ip)
    })
}

/// Validate source consent, the explicitly pinned destination and security
/// prerequisites without any DNS or network traffic. Domain names must be
/// in the passive candidate catalogue, and the selected SNI must match the
/// separately approved exact domain/IP pair. Even a catalogue hit is not
/// evidence of domain ownership; callers must obtain operator consent.
pub fn validate_dual_target(
    preview: &DiscoveryPreview,
    target: &DualProbeTarget,
    consent: CandidateConsent,
) -> Result<(), DualProbeError> {
    let address = target.request.address;
    if !target.approval.allows(address) {
        return Err(DualProbeError::NotApproved);
    }
    if target.request.deadline.is_zero() {
        return Err(DualProbeError::InvalidDeadline);
    }
    if !matches!(
        ServerName::try_from(target.request.server_name.as_str()),
        Ok(ServerName::DnsName(_))
    ) {
        return Err(DualProbeError::InvalidServerName);
    }
    match consent {
        CandidateConsent::PlannedIp => {
            if matches!(target.approval, ProbeApproval::PublicHttpsIp(_))
                && !preview.plan.candidates.iter().any(|candidate| {
                    candidate.host == CandidateHost::Ip(address.ip())
                        && matches!(
                            candidate.source,
                            CandidateSource::ServerAddress | CandidateSource::AuthorizedSubnet
                        )
                })
            {
                return Err(DualProbeError::UnplannedAddress);
            }
        }
        CandidateConsent::PinnedDomain { domain, pinned_ip } => {
            if !preview.plan.candidates.iter().any(|candidate| {
                candidate.host == CandidateHost::Domain(domain)
                    && candidate.source == CandidateSource::PopularDomain
            }) {
                return Err(DualProbeError::UnplannedDomain);
            }
            if target.request.server_name != domain {
                return Err(DualProbeError::DomainNameMismatch);
            }
            if address.ip() != pinned_ip {
                return Err(DualProbeError::DomainAddressMismatch);
            }
            if known_server_address(preview, pinned_ip) {
                return Err(DualProbeError::SelfReference);
            }
        }
    }
    if target.roots.is_empty() {
        return Err(DualProbeError::NoTrustAnchors);
    }
    Ok(())
}

/// Validate both transports' shared exact-target approval BEFORE either TCP
/// or UDP socket exists, then independently probe TCP/443 and UDP/443.
/// Both must use the exact same IP, port, SNI and trusted roots. Running both
/// does not mean they can substitute for a true REALITY-like security mode.
pub async fn probe_dual_h2_h3(
    preview: &DiscoveryPreview,
    target: DualProbeTarget,
) -> Result<DualProbeReport, DualProbeError> {
    probe_dual_h2_h3_with_consent(preview, target, CandidateConsent::PlannedIp).await
}

/// Source-aware API: exactly the same H2 and QUIC/H3 conditions, with
/// independent approval for the domain+IP pair when a seed-domain candidate
/// is manually selected. Never follows DNS resolution or redirects.
pub async fn probe_dual_h2_h3_with_consent(
    preview: &DiscoveryPreview,
    target: DualProbeTarget,
    consent: CandidateConsent,
) -> Result<DualProbeReport, DualProbeError> {
    validate_dual_target(preview, &target, consent)?;
    let address = target.request.address;
    let (h2, h3) = tokio::join!(
        probe_tls_h2(
            target.request.clone(),
            target.roots.clone(),
            target.approval
        ),
        probe_quic_h3(target.request, target.roots, target.approval)
    );
    Ok(DualProbeReport { address, h2, h3 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::camouflage_discovery::TlsEvidence;
    use std::{net::IpAddr, time::Duration};

    fn fake_h2(ip: IpAddr) -> ProbeReport {
        ProbeReport {
            connected_ip: ip,
            handshake_elapsed: Duration::from_millis(1),
            evidence: TlsEvidence {
                tls13: Observation::Verified,
                trusted_chain: Observation::Verified,
                sni_san_match: Observation::Verified,
                certificate_current: Observation::Verified,
                reachable: Observation::Verified,
                alpn_h2: Observation::Verified,
                alpn_h3: Observation::Unknown,
                theia_fingerprint_match: Observation::Unknown,
            },
        }
    }

    fn fake_h3(ip: IpAddr) -> H3ProbeReport {
        H3ProbeReport {
            connected_ip: ip,
            handshake_elapsed: Duration::from_millis(1),
            evidence: TlsEvidence {
                tls13: Observation::Verified,
                trusted_chain: Observation::Verified,
                sni_san_match: Observation::Verified,
                certificate_current: Observation::Verified,
                reachable: Observation::Verified,
                alpn_h2: Observation::Unknown,
                alpn_h3: Observation::Verified,
                theia_fingerprint_match: Observation::Unknown,
            },
        }
    }

    #[test]
    fn forged_other_ip_h3_and_unmeasured_alpn_are_never_dual_compatible() {
        let ip = "93.184.216.10".parse().unwrap();
        let other = "93.184.216.11".parse().unwrap();
        let mut report = DualProbeReport {
            address: SocketAddr::new(ip, 443),
            h2: Ok(fake_h2(ip)),
            h3: Ok(fake_h3(other)),
        };
        assert!(!report.both_transports_verified());
        report.h3 = Ok(fake_h3(ip));
        assert!(report.both_transports_verified());
        assert!(!report.reality_eligible());
        report.h3.as_mut().unwrap().evidence.alpn_h3 = Observation::Unknown;
        assert!(!report.both_transports_verified());
        report.h3 = Err(H3ProbeError::TimedOut);
        assert!(!report.both_transports_verified());
        assert_eq!(
            format!("{report:?}"),
            "DualProbeReport { h2_verified: true, h3_verified: false }"
        );
    }

    #[test]
    fn batch_count_rejects_mismatched_inner_and_outer_socket() {
        use crate::camouflage_dual_batch::{DualBatchOutcome, DualBatchReport};
        let ip = "93.184.216.10".parse().unwrap();
        let address = SocketAddr::new(ip, 443);
        let mut batch = DualBatchReport {
            results: vec![DualBatchOutcome {
                address,
                result: Ok(DualProbeReport {
                    address,
                    h2: Ok(fake_h2(ip)),
                    h3: Ok(fake_h3(ip)),
                }),
            }],
        };
        assert_eq!(batch.dual_verified_count(), 1);
        batch.results[0].address.set_port(444);
        assert_eq!(batch.dual_verified_count(), 0);
        batch.results[0].address = SocketAddr::new("93.184.216.11".parse().unwrap(), 443);
        assert_eq!(batch.dual_verified_count(), 0);
    }

    #[test]
    fn seeded_domain_needs_exact_host_and_ip_authority_before_network() {
        use crate::camouflage_interfaces::NativeInterfaces;
        use crate::camouflage_workflow::{build_preview, PreviewScope};
        let preview = build_preview(
            &NativeInterfaces::default(),
            None,
            PreviewScope::PassiveOnly,
        );
        let ip: IpAddr = "93.184.216.10".parse().unwrap();
        let candidate = DualProbeTarget {
            request: ProbeRequest {
                address: SocketAddr::new(ip, 443),
                server_name: "google.com".to_owned(),
                deadline: Duration::from_secs(2),
            },
            roots: RootCertStore::empty(),
            approval: ProbeApproval::public_https_ip(ip),
        };
        let approved = CandidateConsent::PinnedDomain {
            domain: "google.com",
            pinned_ip: ip,
        };
        assert_eq!(
            validate_dual_target(&preview, &candidate, CandidateConsent::PlannedIp),
            Err(DualProbeError::UnplannedAddress)
        );
        assert_eq!(
            validate_dual_target(&preview, &candidate, approved),
            Err(DualProbeError::NoTrustAnchors)
        );
        assert_eq!(
            validate_dual_target(
                &preview,
                &candidate,
                CandidateConsent::PinnedDomain {
                    domain: "google.com",
                    pinned_ip: "93.184.216.11".parse().unwrap(),
                },
            ),
            Err(DualProbeError::DomainAddressMismatch)
        );
        assert_eq!(
            validate_dual_target(
                &preview,
                &candidate,
                CandidateConsent::PinnedDomain {
                    domain: "unlisted.example",
                    pinned_ip: ip,
                },
            ),
            Err(DualProbeError::UnplannedDomain)
        );
        let mut wrong_name = candidate.clone();
        wrong_name.request.server_name = "github.com".to_owned();
        assert_eq!(
            validate_dual_target(&preview, &wrong_name, approved),
            Err(DualProbeError::DomainNameMismatch)
        );
        let mut denied = candidate;
        denied.approval = ProbeApproval::Denied;
        assert_eq!(
            validate_dual_target(&preview, &denied, approved),
            Err(DualProbeError::NotApproved)
        );
    }

    #[test]
    fn known_local_reference_is_rejected_before_trust_or_network() {
        use crate::camouflage_discovery::Candidate;
        use crate::camouflage_interfaces::NativeInterfaces;
        use crate::camouflage_workflow::{build_preview, PreviewScope};

        let mut preview = build_preview(
            &NativeInterfaces::default(),
            None,
            PreviewScope::PassiveOnly,
        );
        let ip = "93.184.216.10".parse().unwrap();
        preview.plan.candidates.push(Candidate {
            host: CandidateHost::Ip(ip),
            source: CandidateSource::ServerAddress,
        });
        let target = DualProbeTarget {
            request: ProbeRequest {
                address: SocketAddr::new(ip, 443),
                server_name: "google.com".to_owned(),
                deadline: Duration::from_secs(1),
            },
            roots: RootCertStore::empty(),
            approval: ProbeApproval::public_https_ip(ip),
        };
        assert!(known_server_address(&preview, ip));
        assert_eq!(
            validate_dual_target(
                &preview,
                &target,
                CandidateConsent::PinnedDomain {
                    domain: "google.com",
                    pinned_ip: ip,
                },
            ),
            Err(DualProbeError::SelfReference)
        );
    }

    #[test]
    fn denied_forged_public_approval_is_redacted_in_debug() {
        let target = DualProbeTarget {
            request: ProbeRequest {
                address: "127.0.0.1:99".parse().unwrap(),
                server_name: "secret.example".into(),
                deadline: Duration::from_secs(2),
            },
            roots: RootCertStore::empty(),
            approval: ProbeApproval::Denied,
        };
        assert_eq!(format!("{target:?}"), "DualProbeTarget(<redacted>)");
    }
}
