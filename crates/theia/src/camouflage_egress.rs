//! M3.5b2b2: **explicitly consented** HTTPS public-egress observation.
//!
//! This is an independent, tightly bounded IP echo witness, not ownership
//! attestation, a subnet scanner, or a reason to weaken strict TLS validation.
//! No DNS lookup, redirect, proxy, credential, background retry, automatic
//! third-party endpoint, or network I/O occurs without an exact approval.
use crate::camouflage_discovery::plausible_public_address;
use rustls::{pki_types::ServerName, RootCertStore};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    str,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    time::timeout,
};
use tokio_rustls::TlsConnector;

/// Official dual-stack ipify endpoint; IPv4 or IPv6 is returned depending on
/// the outbound connection's address family. The root path is plain-text IP,
/// not JSON. This is a *configured default*, never an automatic network call.
pub const DEFAULT_EGRESS_SERVICE_HOST: &str = "api64.ipify.org";
pub const DEFAULT_EGRESS_SERVICE_URL: &str = "https://api64.ipify.org/";

/// Consent is specifically for contacting the default external ipify
/// service. A non-consenting call performs neither DNS nor TCP/TLS traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpifyConsent {
    #[default]
    Denied,
    Approved,
}

const MAX_DEADLINE: Duration = Duration::from_secs(5);
const MAX_RESPONSE_HEADER: usize = 4096;
const MAX_RESPONSE_BODY: usize = 64;
static ACTIVE_EGRESS_REQUESTS: Semaphore = Semaphore::const_new(2);

/// Caller-granted scope, not automatically derived from a local interface,
/// provider CIDR, popular domain, or external service response. Only a single
/// explicit public TCP/443 IP can be used; loopback variant is for CI only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EgressApproval {
    Denied,
    PublicHttpsIp(IpAddr),
    IsolatedLoopbackFixture(SocketAddr),
}

impl EgressApproval {
    pub fn public_https_ip(ip: IpAddr) -> Self {
        Self::PublicHttpsIp(ip)
    }

    pub fn isolated_loopback_fixture(socket: SocketAddr) -> Self {
        Self::IsolatedLoopbackFixture(socket)
    }

    fn allows(self, socket: SocketAddr) -> bool {
        match self {
            Self::Denied => false,
            Self::PublicHttpsIp(ip) => {
                socket.ip() == ip && socket.port() == 443 && plausible_public_address(ip)
            }
            Self::IsolatedLoopbackFixture(fixture) => {
                socket == fixture && socket.ip().is_loopback()
            }
        }
    }
}

#[derive(Clone)]
pub struct EgressRequest {
    /// Exact pinned IP:port; no name resolution is performed.
    pub address: SocketAddr,
    /// DNS name for verified TLS SNI/SAN and HTTP Host.
    pub server_name: String,
    /// Explicit, limited HTTP path. No redirects or arbitrary headers.
    pub path: String,
    /// Total deadline includes semaphore queue, TCP, TLS and HTTP response.
    pub deadline: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressError {
    NotApproved,
    InvalidRequest,
    NoTrustAnchors,
    TimedOut,
    ConnectFailed,
    TlsRejected,
    InvalidResponse,
    UnusableAddress,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EgressSource {
    server_name: String,
    pinned_ip: IpAddr,
}

impl EgressSource {
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn pinned_ip(&self) -> IpAddr {
        self.pinned_ip
    }
}

/// TLS verified the witness identity. The *claim* about our public egress IP
/// is supplied by that witness, and is not cryptographic proof of ownership,
/// NAT configuration, network reachability from another vantage, or right to
/// scan any surrounding address range.
#[derive(Clone)]
pub struct EgressObservation {
    ip: IpAddr,
    source: EgressSource,
    observed_at: SystemTime,
}

impl EgressObservation {
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn source(&self) -> &EgressSource {
        &self.source
    }

    pub fn observed_at(&self) -> SystemTime {
        self.observed_at
    }
}

// Errors are safe codes, but arbitrary request/response peer IPs and DNS
// targets must never be emitted by default debug/log formatting.
impl fmt::Debug for EgressApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EgressApproval(<redacted>)")
    }
}

impl fmt::Debug for EgressRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EgressRequest(<redacted>)")
    }
}

impl fmt::Debug for EgressSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EgressSource(<redacted>)")
    }
}

impl fmt::Debug for EgressObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EgressObservation(<redacted>)")
    }
}

/// Construct the canonical ipify request with an already pinned address.
/// Caller approval is always checked separately by observe_public_egress.
/// No DNS, I/O or implicit consent occurs here.
pub fn default_ipify_request(pinned_address: SocketAddr) -> EgressRequest {
    EgressRequest {
        address: pinned_address,
        server_name: DEFAULT_EGRESS_SERVICE_HOST.to_owned(),
        path: "/".to_owned(),
        deadline: MAX_DEADLINE,
    }
}

/// Resolve and query the official dual-stack ipify service only after an
/// explicit opt-in. Resolution and TLS/HTTP share the same five-second total
/// deadline. No hardcoded CDN IP, private destination, redirects, DNS-to-IP
/// re-resolution or address-family fallback: select one public resolved IP,
/// pin TCP to it, and authenticate api64.ipify.org with normal TLS 1.3 PKI.
///
/// The caller supplies its approved CA root store. HTTPS authenticates the
/// witness, not independent ownership, NAT type or IP-CIDR scan permission.
pub async fn observe_default_ipify(
    roots: RootCertStore,
    consent: IpifyConsent,
) -> Result<EgressObservation, EgressError> {
    if consent != IpifyConsent::Approved {
        return Err(EgressError::NotApproved);
    }
    if roots.is_empty() {
        return Err(EgressError::NoTrustAnchors);
    }
    timeout(MAX_DEADLINE, async move {
        let peers = tokio::net::lookup_host((DEFAULT_EGRESS_SERVICE_HOST, 443))
            .await
            .map_err(|_| EgressError::ConnectFailed)?;
        let pinned = peers
            .into_iter()
            .find(|peer| peer.port() == 443 && plausible_public_address(peer.ip()))
            .ok_or(EgressError::ConnectFailed)?;
        observe_public_egress(
            default_ipify_request(pinned),
            roots,
            EgressApproval::public_https_ip(pinned.ip()),
        )
        .await
    })
    .await
    .map_err(|_| EgressError::TimedOut)?
}

fn valid_path(path: &str) -> bool {
    path.len() <= 128
        && path.starts_with('/')
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.~?=&%".contains(&b))
}

fn body_length(header: &[u8]) -> Result<usize, EgressError> {
    let text = str::from_utf8(header).map_err(|_| EgressError::InvalidResponse)?;
    let text = text
        .strip_suffix("\r\n\r\n")
        .ok_or(EgressError::InvalidResponse)?;
    let mut lines = text.split("\r\n");
    let status = lines.next().ok_or(EgressError::InvalidResponse)?;
    // Exact success status, no 1xx responses, redirects, content negotiation
    // or plaintext downgrade; the echo endpoint must be deterministic.
    if !status.starts_with("HTTP/1.1 200 ") {
        return Err(EgressError::InvalidResponse);
    }
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(EgressError::InvalidResponse)?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(EgressError::InvalidResponse);
        }
        let value = value.trim();
        if value.bytes().any(|b| !b.is_ascii() || b.is_ascii_control()) {
            return Err(EgressError::InvalidResponse);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(EgressError::InvalidResponse);
            }
            let length = value
                .parse::<usize>()
                .map_err(|_| EgressError::InvalidResponse)?;
            if length > MAX_RESPONSE_BODY {
                return Err(EgressError::InvalidResponse);
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(EgressError::InvalidResponse);
        }
    }
    content_length.ok_or(EgressError::InvalidResponse)
}

/// One *voluntary* request to a preselected HTTPS witness. A caller must
/// independently authorize the exact public IP and supply trusted CA anchors.
/// The only automatic traffic is one TCP/TLS/HTTP request to that exact IP.
/// All errors are fail-closed with no partial/positive IP evidence.
pub async fn observe_public_egress(
    request: EgressRequest,
    roots: RootCertStore,
    approval: EgressApproval,
) -> Result<EgressObservation, EgressError> {
    // No socket, name resolution, or any I/O before all input checks.
    if !approval.allows(request.address) {
        return Err(EgressError::NotApproved);
    }
    if request.deadline.is_zero() || !valid_path(&request.path) {
        return Err(EgressError::InvalidRequest);
    }
    if roots.is_empty() {
        return Err(EgressError::NoTrustAnchors);
    }
    if request.server_name.len() > 253 {
        return Err(EgressError::InvalidRequest);
    }
    let server_name = ServerName::try_from(request.server_name.clone())
        .map_err(|_| EgressError::InvalidRequest)?;
    if !matches!(server_name, ServerName::DnsName(_)) {
        return Err(EgressError::InvalidRequest);
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| EgressError::TlsRejected)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls.enable_early_data = false;
    let connector = TlsConnector::from(Arc::new(tls));
    let source = EgressSource {
        server_name: request.server_name.clone(),
        pinned_ip: request.address.ip(),
    };

    timeout(request.deadline.min(MAX_DEADLINE), async move {
        let _permit = ACTIVE_EGRESS_REQUESTS
            .acquire()
            .await
            .map_err(|_| EgressError::ConnectFailed)?;
        let tcp = TcpStream::connect(request.address)
            .await
            .map_err(|_| EgressError::ConnectFailed)?;
        let mut stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|_| EgressError::TlsRejected)?;
        if stream.get_ref().1.alpn_protocol() != Some(b"http/1.1".as_slice())
            || stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        {
            return Err(EgressError::TlsRejected);
        }
        let get = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: text/plain\r\nConnection: close\r\n\r\n",
            request.path, request.server_name
        );
        stream
            .write_all(get.as_bytes())
            .await
            .map_err(|_| EgressError::InvalidResponse)?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() == MAX_RESPONSE_HEADER {
                return Err(EgressError::InvalidResponse);
            }
            let byte = stream
                .read_u8()
                .await
                .map_err(|_| EgressError::InvalidResponse)?;
            header.push(byte);
        }
        let length = body_length(&header)?;
        let mut body = vec![0; length];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|_| EgressError::InvalidResponse)?;
        let raw = str::from_utf8(&body).map_err(|_| EgressError::InvalidResponse)?;
        let ip = raw
            .trim_matches(|c: char| c == '\r' || c == '\n' || c == ' ')
            .parse::<IpAddr>()
            .map_err(|_| EgressError::InvalidResponse)?;
        if !plausible_public_address(ip) {
            return Err(EgressError::UnusableAddress);
        }
        Ok(EgressObservation {
            ip,
            source,
            observed_at: SystemTime::now(),
        })
    })
    .await
    .map_err(|_| EgressError::TimedOut)?
}
