//! M4.5e: one explicitly authorized exact-IP candidate gets independent
//! TCP/TLS1.3/h2 AND UDP/QUIC/TLS1.3/h3 observations.
//! No DNS, CIDR expansion, domain sweep, fallback or REALITY claim.
use crate::{
    camouflage_discovery::{CandidateHost, CandidateSource, Observation},
    camouflage_workflow::DiscoveryPreview,
    camouflage_h3_probe::{probe_quic_h3, H3ProbeError, H3ProbeReport},
    camouflage_probe::{probe_tls_h2, ProbeApproval, ProbeError, ProbeReport, ProbeRequest},
};
use rustls::{pki_types::ServerName, RootCertStore};
use std::{fmt, net::SocketAddr};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DualProbeError {
    NotApproved,
    InvalidServerName,
    InvalidDeadline,
    NoTrustAnchors,
    UnplannedAddress,
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
    pub fn both_transports_verified(&self) -> bool {
        matches!(
            (&self.h2, &self.h3),
            (Ok(h2), Ok(h3))
                if h2.connected_ip == self.address.ip()
                    && h3.connected_ip == self.address.ip()
                    && h2.evidence.tls13 == Observation::Verified
                    && h2.evidence.trusted_chain == Observation::Verified
                    && h2.evidence.sni_san_match == Observation::Verified
                    && h2.evidence.certificate_current == Observation::Verified
                    && h2.evidence.reachable == Observation::Verified
                    && h2.evidence.alpn_h2 == Observation::Verified
                    && h3.evidence.tls13 == Observation::Verified
                    && h3.evidence.trusted_chain == Observation::Verified
                    && h3.evidence.sni_san_match == Observation::Verified
                    && h3.evidence.certificate_current == Observation::Verified
                    && h3.evidence.reachable == Observation::Verified
                    && h3.evidence.alpn_h3 == Observation::Verified
        )
    }

    /// Current releases have no cryptographically authenticated REALITY-like
    /// mode and no measured Theia browser fingerprint. Never infer ready.
    pub fn reality_eligible(&self) -> bool {
        false
    }
}

/// Validate both transports' shared exact-target approval BEFORE either TCP
/// or UDP socket exists, then independently probe TCP/443 and UDP/443.
/// Both must use the exact same IP, port, SNI and trusted roots. Running both
/// does not mean they can substitute for a true REALITY-like security mode.
pub async fn probe_dual_h2_h3(
    preview: &DiscoveryPreview,
    target: DualProbeTarget,
) -> Result<DualProbeReport, DualProbeError> {
    if !target.approval.allows(target.request.address) {
        return Err(DualProbeError::NotApproved);
    }
    if matches!(target.approval, ProbeApproval::PublicHttpsIp(_))
        && !preview.plan.candidates.iter().any(|candidate| {
            candidate.host == CandidateHost::Ip(target.request.address.ip())
                && matches!(
                    candidate.source,
                    CandidateSource::ServerAddress | CandidateSource::AuthorizedSubnet
                )
        })
    {
        return Err(DualProbeError::UnplannedAddress);
    }
    if target.request.deadline.is_zero() {
        return Err(DualProbeError::InvalidDeadline);
    }
    if target.roots.is_empty() {
        return Err(DualProbeError::NoTrustAnchors);
    }
    if !matches!(
        ServerName::try_from(target.request.server_name.as_str()),
        Ok(ServerName::DnsName(_))
    ) {
        return Err(DualProbeError::InvalidServerName);
    }

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
        assert_eq!(format!("{report:?}"), "DualProbeReport { h2_verified: true, h3_verified: false }");
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
