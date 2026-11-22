//! M3.5b2a: route-local address discovery and strictly bounded TLS/H2
//! observation of one explicitly authorized pinned socket address.
//!
//! No DNS, HTTP requests, port or subnet sweeps, third-party seed probing,
//! REALITY handshake, fingerprint matching, H3 probing or TUI wiring.
//! Caller approval is required for every socket and never inferred from
//! ASN, provider prefix or the candidate's popularity.
use crate::camouflage_discovery::{plausible_public_address, Observation, TlsEvidence};
use rustls::{pki_types::ServerName, RootCertStore};
use std::{
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, sync::Semaphore, time::timeout};
use tokio_rustls::TlsConnector;

const MAX_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
static ACTIVE_PROBES: Semaphore = Semaphore::const_new(4);

/// Observe the locally selected source address for an existing OS route.
/// UDP connect() selects a route but sends no packet. This tells us neither
/// the public NAT egress nor the assigned subnet prefix/ownership; do not
/// synthesize a /24 or treat this address as permission to scan neighbors.
pub fn route_selected_local_ip(destination: SocketAddr) -> io::Result<IpAddr> {
    let bind = if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(destination)?;
    Ok(socket.local_addr()?.ip())
}

/// No active scanning by default. Public probes are permitted for exactly
/// one previously operator-approved public IP on TCP 443; the approval is
/// provided by the caller, not guessed from ServerSnapshot/BGP/RDAP.
/// The fixture variant is exclusively loopback, exact socket only, with
/// normal PKI verification still enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeApproval {
    Denied,
    PublicHttpsIp(IpAddr),
    IsolatedLoopbackFixture(SocketAddr),
}

impl ProbeApproval {
    pub fn public_https_ip(ip: IpAddr) -> Self {
        Self::PublicHttpsIp(ip)
    }

    pub fn isolated_loopback_fixture(address: SocketAddr) -> Self {
        Self::IsolatedLoopbackFixture(address)
    }

    fn allows(self, address: SocketAddr) -> bool {
        match self {
            Self::Denied => false,
            Self::PublicHttpsIp(ip) => {
                ip == address.ip()
                    && address.port() == 443
                    && plausible_public_address(address.ip())
            }
            Self::IsolatedLoopbackFixture(fixture) => {
                fixture == address && address.ip().is_loopback()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeRequest {
    /// Pinned peer IP and port. No DNS lookup is ever performed by the probe.
    pub address: SocketAddr,
    /// DNS name used for verified TLS SNI/SAN. Not a DNS resolution request.
    pub server_name: String,
    /// End-to-end deadline including waiting for the global four-probe cap.
    pub deadline: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    NotApproved,
    InvalidServerName,
    InvalidDeadline,
    NoTrustAnchors,
    TimedOut,
    ConnectFailed,
    TlsRejected,
    WrongAlpn,
}

#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub connected_ip: IpAddr,
    pub handshake_elapsed: Duration,
    /// Only independently authenticated ordinary TLS/H2 facts are verified.
    /// Browser/Theia fingerprint, H3/QUIC and REALITY remain UNKNOWN.
    pub evidence: TlsEvidence,
}

/// Perform one strictly verified TLS1.3/H2 client handshake to the explicitly
/// approved pinned peer. No HTTP application request is sent, and the
/// connection is closed after handshake. All errors are bounded and return
/// no positive or partially verified evidence.
///
/// CA/hostname/expiry verification is rustls' standard verifier, never
/// insecure_skip_verify/TOFU. The supplied CA roots are a caller-owned trust
/// decision. Ordinary TLS H2 success cannot establish any camouflage or
/// TLS-in-TLS resistance.
pub async fn probe_tls_h2(
    request: ProbeRequest,
    roots: RootCertStore,
    approval: ProbeApproval,
) -> Result<ProbeReport, ProbeError> {
    // These validations run BEFORE acquiring a socket or issuing any I/O.
    if !approval.allows(request.address) {
        return Err(ProbeError::NotApproved);
    }
    if request.deadline.is_zero() {
        return Err(ProbeError::InvalidDeadline);
    }
    if roots.is_empty() {
        return Err(ProbeError::NoTrustAnchors);
    }
    let server_name =
        ServerName::try_from(request.server_name).map_err(|_| ProbeError::InvalidServerName)?;
    if !matches!(server_name, ServerName::DnsName(_)) {
        return Err(ProbeError::InvalidServerName);
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| ProbeError::TlsRejected)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    tls.enable_early_data = false;
    let connector = TlsConnector::from(Arc::new(tls));
    let deadline = request.deadline.min(MAX_HANDSHAKE_DEADLINE);
    let start = Instant::now();

    timeout(deadline, async move {
        let _permit = ACTIVE_PROBES
            .acquire()
            .await
            .map_err(|_| ProbeError::ConnectFailed)?;
        let tcp = TcpStream::connect(request.address)
            .await
            .map_err(|_| ProbeError::ConnectFailed)?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|_| ProbeError::TlsRejected)?;
        let peer = tls.get_ref().1;
        if peer.alpn_protocol() != Some(&b"h2"[..]) {
            return Err(ProbeError::WrongAlpn);
        }
        if peer.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(ProbeError::TlsRejected);
        }
        // On success rustls has verified server chain, DNS name, validity,
        // TLS version and ALPN on this *actual* connected TCP peer.
        Ok(ProbeReport {
            connected_ip: request.address.ip(),
            handshake_elapsed: start.elapsed(),
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
        })
    })
    .await
    .map_err(|_| ProbeError::TimedOut)?
}
