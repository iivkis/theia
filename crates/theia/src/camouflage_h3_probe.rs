//! M4.5e: explicit pinned-IP QUIC/TLS1.3 + ALPN h3 witness.
//!
//! A QUIC handshake alone does NOT prove HTTP/3 application behavior,
//! browser fingerprint, REALITY authentication, ownership or DPI resistance.
//! No DNS, HTTP requests, seed-domain scans or implicit H2 fallback.
//! Active network I/O only after exact per-target ProbeApproval.
use crate::{
    camouflage_discovery::{Observation, TlsEvidence},
    camouflage_probe::{ProbeApproval, ProbeRequest},
    quic_transport::{ObservedEndpoint, QuicError},
};
use rustls::{pki_types::ServerName, RootCertStore};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, time::timeout};

const MAX_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
static ACTIVE_H3_PROBES: Semaphore = Semaphore::const_new(4);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3ProbeError {
    NotApproved,
    InvalidServerName,
    InvalidDeadline,
    NoTrustAnchors,
    TimedOut,
    UdpUnavailable,
    BindFailed,
    HandshakeRejected,
    WrongPeer,
}

#[derive(Debug, Clone)]
pub struct H3ProbeReport {
    pub connected_ip: IpAddr,
    pub handshake_elapsed: Duration,
    /// A real PKI-verified QUIC TLS1.3 ALPN=h3 negotiation. No H2 data is
    /// inferred from QUIC, and fingerprint/REALITY remain Unknown.
    pub evidence: TlsEvidence,
}

fn map_error(error: QuicError) -> H3ProbeError {
    match error {
        QuicError::Bind => H3ProbeError::BindFailed,
        QuicError::Unreachable | QuicError::EndpointNetworkRefused => H3ProbeError::UdpUnavailable,
        QuicError::Timeout => H3ProbeError::TimedOut,
        QuicError::Configuration
        | QuicError::Handshake
        | QuicError::Alpn
        | QuicError::CongestionController => H3ProbeError::HandshakeRejected,
    }
}

/// Actively negotiate QUIC/TLS1.3 ALPN=h3 with one explicitly approved exact
/// UDP socket address. Uses the production Quinn/rustls H3 verifier:
/// authentic CA chain, SNI/SAN/expiry, TLS1.3, negotiated h3 and active BBR.
/// No HTTP request, arbitrary DNS, retry, redirect or transport fallback.
/// Deadline includes queue wait, UDP bind and handshake; max 5 seconds.
/// Return zero evidence on any failure.
pub async fn probe_quic_h3(
    request: ProbeRequest,
    roots: RootCertStore,
    approval: ProbeApproval,
) -> Result<H3ProbeReport, H3ProbeError> {
    if !approval.allows(request.address) {
        return Err(H3ProbeError::NotApproved);
    }
    if request.deadline.is_zero() {
        return Err(H3ProbeError::InvalidDeadline);
    }
    if roots.is_empty() {
        return Err(H3ProbeError::NoTrustAnchors);
    }
    if !matches!(
        ServerName::try_from(request.server_name.as_str()),
        Ok(ServerName::DnsName(_))
    ) {
        return Err(H3ProbeError::InvalidServerName);
    }

    let start = Instant::now();
    let deadline = request.deadline.min(MAX_HANDSHAKE_DEADLINE);
    timeout(deadline, async move {
        let _permit = ACTIVE_H3_PROBES
            .acquire()
            .await
            .map_err(|_| H3ProbeError::BindFailed)?;
        let bind = if request.address.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let endpoint = ObservedEndpoint::new(bind, roots).map_err(map_error)?;
        let connection = endpoint
            .connect(request.address, &request.server_name, deadline)
            .await
            .map_err(map_error)?;
        if connection.remote_address() != request.address {
            connection.close(0u32.into(), b"wrong peer");
            return Err(H3ProbeError::WrongPeer);
        }
        // The production verifier already checked full PKI, h3 ALPN and BBR.
        // Quinn's TLS engine negotiates TLS1.3 for QUIC. Do not claim that
        // HTTP/3 SETTINGS, request behavior or camouflage was verified.
        let report = H3ProbeReport {
            connected_ip: request.address.ip(),
            handshake_elapsed: start.elapsed(),
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
        };
        connection.close(0u32.into(), b"probe finished");
        Ok(report)
    })
    .await
    .map_err(|_| H3ProbeError::TimedOut)?
}

/// Independent version-specific native QUIC handshake evidence. It is
/// not a production route permission and cannot authorize H2 fallback.
#[derive(Debug, Clone)]
pub struct NativeH3ProbeReport {
    pub version: crate::quic_core::wire::Version,
    pub source: IpAddr,
    pub transport: H3ProbeReport,
}

/// Explicit source/peer pinned probe, no bearer, OPEN, HTTP, DNS or fallback.
/// In particular a v1 handshake cannot satisfy a v2 probe. This entry point
/// remains separate from the accepted production probe until parity gates.
pub async fn probe_quic_h3_native(
    request: ProbeRequest,
    roots: RootCertStore,
    approval: ProbeApproval,
    source: IpAddr,
    version: crate::quic_core::wire::Version,
) -> Result<NativeH3ProbeReport, H3ProbeError> {
    use crate::quic_core::{handshake_udp, negotiation::VersionPolicy, scope::NetworkScope};
    if !approval.allows(request.address) {
        return Err(H3ProbeError::NotApproved);
    }
    if request.deadline.is_zero() {
        return Err(H3ProbeError::InvalidDeadline);
    }
    if roots.is_empty() {
        return Err(H3ProbeError::NoTrustAnchors);
    }
    let name = ServerName::try_from(request.server_name).map_err(|_| H3ProbeError::InvalidServerName)?;
    if !matches!(&name, ServerName::DnsName(_)) {
        return Err(H3ProbeError::InvalidServerName);
    }
    let scope = NetworkScope::pinned([source; 2], [request.address.ip(); 2]).ok_or(H3ProbeError::BindFailed)?;
    let start = Instant::now();
    timeout(request.deadline.min(MAX_HANDSHAKE_DEADLINE), async move {
        let _permit = ACTIVE_H3_PROBES.acquire().await.map_err(|_| H3ProbeError::BindFailed)?;
        let tls = crate::transport_policy::Carrier::H3.client_tls(roots).map_err(|_| H3ProbeError::HandshakeRejected)?;
        let (actual, mut session) = handshake_udp::connect_versions_scoped(
            SocketAddr::new(source, 0), request.address, VersionPolicy::exact(version),
            std::sync::Arc::new(tls), name, scope,
        ).await.map_err(|error| match error {
            handshake_udp::Error::Timeout => H3ProbeError::TimedOut,
            // A native I/O error is not sufficient evidence for fallback.
            _ => H3ProbeError::HandshakeRejected,
        })?;
        if actual != version || session.peer_addr() != request.address {
            return Err(H3ProbeError::WrongPeer);
        }
        finish_native_handshake(&mut session).await?;
        let report = NativeH3ProbeReport {
            version: actual,
            source,
            transport: H3ProbeReport {
                connected_ip: request.address.ip(),
                handshake_elapsed: start.elapsed(),
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
            },
        };
        // Close only after authenticated confirmation, with no HTTP bytes.
        session.close(0x100, Instant::now()).map_err(|_| H3ProbeError::HandshakeRejected)?;
        session.flush(Instant::now()).await.map_err(|_| H3ProbeError::HandshakeRejected)?;
        Ok(report)
    }).await.map_err(|_| H3ProbeError::TimedOut)?
}

pub(crate) async fn finish_native_handshake(
    session: &mut crate::quic_core::endpoint::LabSession,
) -> Result<(), H3ProbeError> {
    while !session.handshake_confirmed() {
        if session.shutdown_phase() != crate::quic_core::lifecycle::ShutdownPhase::Open {
            return Err(H3ProbeError::HandshakeRejected);
        }
        session.flush(Instant::now()).await.map_err(|_| H3ProbeError::HandshakeRejected)?;
        let wait = session.deadline().map_or(Duration::from_millis(100), |at| {
            at.saturating_duration_since(Instant::now()).min(Duration::from_millis(100))
        });
        session.recv(wait).await.map_err(|_| H3ProbeError::HandshakeRejected)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_refusal_is_unavailable_without_handshake_evidence() {
        assert_eq!(
            map_error(QuicError::EndpointNetworkRefused),
            H3ProbeError::UdpUnavailable
        );
        assert_eq!(
            map_error(QuicError::Unreachable),
            H3ProbeError::UdpUnavailable
        );
        assert_eq!(map_error(QuicError::Timeout), H3ProbeError::TimedOut);
        assert_eq!(
            map_error(QuicError::Handshake),
            H3ProbeError::HandshakeRejected
        );
    }
}
