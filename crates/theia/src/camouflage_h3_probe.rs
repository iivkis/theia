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
        QuicError::Unreachable => H3ProbeError::UdpUnavailable,
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
