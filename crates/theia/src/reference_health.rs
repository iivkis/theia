//! Consented F-18 reference application health and persistent approved inventory.
//! This performs ordinary public-PKI HTTPS HEAD only to exact approved pins.
//! It is not a REALITY admission adapter and never switches a live inbound.
#![forbid(unsafe_code)]

use crate::{
    config::{self, WriteFailure},
    quic_transport::ObservedEndpoint,
};
use bytes::Bytes;
use http::{Method, Request};
use rustls::{pki_types::ServerName, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpStream, sync::Semaphore, task::JoinHandle, time::timeout};
use tokio_rustls::TlsConnector;

pub const MAX_PLAN: usize = 16 * 1024;
const MAX_STATE: usize = 64 * 1024;
const MAX_REFERENCES: usize = 3;
pub(crate) const MAX_SEARCH_TARGETS: usize = 112;
const SEARCH_PARALLELISM: usize = 6;
const SEARCH_DEADLINE: Duration = Duration::from_secs(600);
const MAX_OWN_IPS: usize = 64;
const MAX_DNS_ANSWERS: usize = 64;
const ATTEMPT: Duration = Duration::from_secs(5);
const BATCH: Duration = Duration::from_secs(60);
const INTERVAL: u64 = 12 * 60 * 60;
const JITTER: u64 = 30 * 60;
const FAILURE_THRESHOLD: u8 = 2;
static ACTIVE: Semaphore = Semaphore::const_new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Format,
    Approval,
    Dns,
    SelfReference,
    NotEligible,
    NoRoots,
    Timeout,
    Clock,
    Conflict,
    Storage,
    Indeterminate,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Format => "invalid reference document",
            Self::Approval => "reference approval digest does not match",
            Self::Dns => "reference DNS pin rejected",
            Self::SelfReference => "reference points to a known server address",
            Self::NotEligible => "mandatory reference evidence missing",
            Self::NoRoots => "no trusted public CA roots",
            Self::Timeout => "reference check exceeded its deadline",
            Self::Clock => "reference clock is invalid",
            Self::Conflict => "reference state revision changed; inspect before retry",
            Self::Storage => "reference storage operation rejected",
            Self::Indeterminate => "reference write uncertain; inspect before retry",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub server_name: String,
    pub address: SocketAddr,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: u16,
    pub inbound: String,
    pub endpoint: String,
    /// All explicitly known public/NAT and local server addresses.
    pub own_ips: Vec<IpAddr>,
    /// Index zero is the primary. Up to two separately approved reserves.
    pub references: Vec<Target>,
}

impl Plan {
    pub fn parse(raw: &str) -> Result<Self, Error> {
        if raw.len() > MAX_PLAN {
            return Err(Error::Format);
        }
        let plan: Self = toml::from_str(raw).map_err(|_| Error::Format)?;
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), Error> {
        self.validate_scope(MAX_REFERENCES, false)
    }

    fn validate_scope(&self, limit: usize, allow_shared_pins: bool) -> Result<(), Error> {
        if self.schema_version != 1
            || !config::valid_id(&self.inbound)
            || !config::valid_remote(&self.endpoint)
            || !(1..=MAX_OWN_IPS).contains(&self.own_ips.len())
            || !(1..=limit).contains(&self.references.len())
        {
            return Err(Error::Format);
        }
        let endpoint_host = self.endpoint.rsplit_once(':').ok_or(Error::Format)?.0;
        let mut addresses = HashSet::new();
        for ip in &self.own_ips {
            if ip.is_unspecified() || ip.is_multicast() || !addresses.insert(normalize(*ip)) {
                return Err(Error::Format);
            }
        }
        if let Ok(endpoint) = self.endpoint.parse::<SocketAddr>() {
            if !addresses.contains(&normalize(endpoint.ip())) {
                return Err(Error::Format);
            }
        }
        let mut names = HashSet::new();
        let mut pins = HashSet::new();
        let mut pairs = HashSet::new();
        for target in &self.references {
            if crate::camouflage_domain_dns::validate_manual_dns_request(
                &target.server_name,
                crate::camouflage_domain_dns::DnsConsent::Approved,
            )
            .is_err()
                || target.address.port() != 443
                || !public_address(target.address.ip())
                || !pairs.insert((&target.server_name, target.address))
                || (!allow_shared_pins && (!names.insert(&target.server_name) || !pins.insert(target.address)))
            {
                return Err(Error::Format);
            }
            if target.server_name.eq_ignore_ascii_case(endpoint_host)
                || addresses.contains(&normalize(target.address.ip()))
            {
                return Err(Error::SelfReference);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], Error> {
        self.validate()?;
        let raw = toml::to_string(self).map_err(|_| Error::Format)?;
        Ok(digest(&raw))
    }

    /// Explicit preview only; public names and addresses are not credentials.
    pub fn preview(&self) -> Result<String, Error> {
        self.validate()?;
        Ok(self.preview_targets())
    }

    fn preview_targets(&self) -> String {
        let mut out = format!(
            "Reference plan; no network, no runtime Apply\ninbound={}\nendpoint={}",
            self.inbound, self.endpoint
        );
        for (index, target) in self.references.iter().enumerate() {
            out.push_str(&format!(
                "\nreference[{index}]={} {}",
                target.server_name, target.address
            ));
        }
        out.push_str("\nConsent covers inbound endpoint DNS, reference DNS and two HTTPS HEAD / attempts on each exact pin, H2 and H3; no redirects, bearer or request body.");
        out
    }
}

/// Ephemeral search inventory, never a persistent health State.
pub(crate) struct SearchPlan(Plan);
impl SearchPlan {
    pub(crate) fn new(plan: Plan) -> Result<Self, Error> {
        plan.validate_scope(MAX_SEARCH_TARGETS, true)?;
        Ok(Self(plan))
    }
    pub(crate) fn targets(&self) -> &[Target] { &self.0.references }
    pub(crate) fn into_targets(self) -> Vec<Target> { self.0.references }
    pub(crate) fn digest(&self) -> Result<[u8; 32], Error> {
        self.0.validate_scope(MAX_SEARCH_TARGETS, true)?;
        let raw = toml::to_string(&self.0).map_err(|_| Error::Format)?;
        let mut hash = Sha256::new();
        hash.update(b"theia-reference-search-v1\0");
        hash.update(raw.as_bytes());
        Ok(hash.finalize().into())
    }
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        _ => ip,
    }
}

fn public_address(ip: IpAddr) -> bool {
    // Reject mapped forms and share the stricter tunnel destination filter.
    normalize(ip) == ip
        && crate::camouflage_discovery::plausible_public_address(ip)
        && crate::server::allowed_destination(ip, false)
}

pub fn digest(raw: &str) -> [u8; 32] {
    Sha256::digest(raw.as_bytes()).into()
}

pub fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::Clock)
}

fn own_addresses(plan: &Plan) -> Result<HashSet<IpAddr>, Error> {
    let own: HashSet<_> = plan.own_ips.iter().copied().map(normalize).collect();
    #[cfg(target_os = "linux")]
    let own = {
        let mut own = own;
        let interfaces =
            crate::camouflage_interfaces::collect_assigned_interfaces().map_err(|_| Error::Dns)?;
        own.extend(
            interfaces
                .interfaces
                .into_iter()
                .map(|item| normalize(item.address)),
        );
        own
    };
    Ok(own)
}

/// Inspect every DNS answer before allowing the pinned IP. In contrast to
/// the display-limited wizard list, a self address anywhere poisons the set.
fn vet_pin(answers: &[SocketAddr], target: &Target, own: &HashSet<IpAddr>) -> Result<(), Error> {
    if answers.is_empty() || answers.len() > MAX_DNS_ANSWERS {
        return Err(Error::Dns);
    }
    if answers
        .iter()
        .any(|address| own.contains(&normalize(address.ip())))
    {
        return Err(Error::SelfReference);
    }
    if answers
        .iter()
        .any(|address| address.port() != target.address.port() || !public_address(address.ip()))
        || !answers.contains(&target.address)
    {
        return Err(Error::Dns);
    }
    Ok(())
}

async fn extend_endpoint_addresses(
    plan: &Plan,
    mut own: HashSet<IpAddr>,
) -> Result<HashSet<IpAddr>, Error> {
    if plan.endpoint.parse::<SocketAddr>().is_ok() {
        return Ok(own);
    }
    let (name, port) = plan.endpoint.rsplit_once(':').ok_or(Error::Format)?;
    let port: u16 = port.parse().map_err(|_| Error::Format)?;
    let absolute = format!("{name}.");
    timeout(ATTEMPT, async {
        let answers = tokio::net::lookup_host((absolute.as_str(), port))
            .await
            .map_err(|_| Error::Dns)?;
        let mut count = 0;
        for address in answers {
            count += 1;
            if count > MAX_DNS_ANSWERS {
                return Err(Error::Dns);
            }
            own.insert(normalize(address.ip()));
        }
        if count == 0 {
            return Err(Error::Dns);
        }
        if plan
            .references
            .iter()
            .any(|target| own.contains(&normalize(target.address.ip())))
        {
            return Err(Error::SelfReference);
        }
        Ok(own)
    })
    .await
    .map_err(|_| Error::Timeout)?
}

async fn fresh_dns(target: &Target, own: &HashSet<IpAddr>) -> Result<(), Error> {
    let absolute = format!("{}.", target.server_name);
    timeout(ATTEMPT, async {
        let resolved = tokio::net::lookup_host((absolute.as_str(), target.address.port()))
            .await
            .map_err(|_| Error::Dns)?;
        let mut answers = Vec::new();
        for address in resolved {
            if answers.len() == MAX_DNS_ANSWERS {
                return Err(Error::Dns);
            }
            answers.push(address);
        }
        vet_pin(&answers, target, own)
    })
    .await
    .map_err(|_| Error::Timeout)?
}

fn head(target: &Target) -> Option<Request<()>> {
    Request::builder()
        .method(Method::HEAD)
        .uri(format!(
            "https://{}:{}/",
            target.server_name,
            target.address.port()
        ))
        .body(())
        .ok()
}

struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One complete PKI-verified TLS 1.3/X25519 + H2 request, not just ALPN.
/// No arbitrary path, redirect, authentication or application payload.
async fn h2_head(target: &Target, roots: RootCertStore) -> Option<u16> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .kx_groups
        .retain(|group| group.name() == rustls::NamedGroup::X25519);
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    let name = ServerName::try_from(target.server_name.clone()).ok()?;
    let tcp = TcpStream::connect(target.address).await.ok()?;
    if tcp.peer_addr().ok()? != target.address {
        return None;
    }
    let tls = TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await
        .ok()?;
    if tls.get_ref().1.alpn_protocol() != Some(&b"h2"[..])
        || tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
    {
        return None;
    }
    let mut builder = h2::client::Builder::new();
    builder.enable_push(false);
    builder.max_header_list_size(8192);
    let (sender, connection) = builder.handshake::<_, Bytes>(tls).await.ok()?;
    let _driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut sender = sender.ready().await.ok()?;
    let (response, _) = sender.send_request(head(target)?, true).ok()?;
    Some(response.await.ok()?.status().as_u16())
}

/// Separate H3 application witness over the existing strict QUIC verifier.
/// A QUIC handshake alone cannot produce a successful observation.
async fn h3_head(target: &Target, roots: RootCertStore) -> Option<u16> {
    let bind = if target.address.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let endpoint = ObservedEndpoint::new(bind, roots).ok()?;
    let connection = endpoint
        .connect(target.address, &target.server_name, ATTEMPT)
        .await
        .ok()?;
    if connection.remote_address() != target.address {
        return None;
    }
    let mut builder = h3::client::builder();
    builder.max_field_section_size(8192);
    let (mut driver, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await
        .ok()?;
    let keep = sender.clone();
    let _driver = Driver(tokio::spawn(async move {
        let _keep = keep;
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    }));
    let mut stream = sender.send_request(head(target)?).await.ok()?;
    stream.finish().await.ok()?;
    Some(stream.recv_response().await.ok()?.status().as_u16())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub h2_status: Option<u16>,
    pub h3_status: Option<u16>,
}

impl Evidence {
    pub fn eligible(self) -> bool {
        self.h2_status.is_some_and(accepted_status)
    }
    pub fn h3(self) -> bool {
        self.h3_status.is_some_and(accepted_status)
    }
    pub fn score(self) -> u8 {
        if !self.eligible() {
            0
        } else if self.h3() {
            100
        } else {
            80
        }
    }
    fn valid(self) -> bool {
        self.h2_status.is_none_or(accepted_status) && self.h3_status.is_none_or(accepted_status)
    }
}

fn accepted_status(status: u16) -> bool {
    (200..400).contains(&status)
}

fn stable(first: Option<u16>, second: Option<u16>) -> Option<u16> {
    first.filter(|status| Some(*status) == second && accepted_status(*status))
}

async fn check_target(target: &Target, roots: &RootCertStore, own: &HashSet<IpAddr>) -> Evidence {
    let mut rounds = [Evidence::default(); 2];
    for round in &mut rounds {
        // Fresh DNS before each pair, but all TCP/UDP connects use the
        // immutable exact pin, never a re-resolved or redirected address.
        if fresh_dns(target, own).await.is_err() {
            return Evidence::default();
        }
        let (h2, h3) = tokio::join!(
            timeout(ATTEMPT, h2_head(target, roots.clone())),
            timeout(ATTEMPT, h3_head(target, roots.clone()))
        );
        round.h2_status = h2.ok().flatten();
        round.h3_status = h3.ok().flatten();
    }
    // Check once more after the application observations: a DNS change
    // during the last handshake must not be recorded as fresh evidence.
    if fresh_dns(target, own).await.is_err() {
        return Evidence::default();
    }
    Evidence {
        h2_status: stable(rounds[0].h2_status, rounds[1].h2_status),
        h3_status: stable(rounds[0].h3_status, rounds[1].h3_status),
    }
}

/// The caller must have confirmed the exact document before invoking this.
/// One global batch, at most three targets, two sequential rounds per target.
pub async fn check(plan: &Plan, approved: [u8; 32]) -> Result<Vec<Evidence>, Error> {
    plan.validate()?;
    if plan.digest()? != approved {
        return Err(Error::Approval);
    }
    let roots = {
        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        roots.add_parsable_certificates(native.certs);
        if roots.is_empty() {
            return Err(Error::NoRoots);
        }
        roots
    };
    let own = own_addresses(plan)?;
    if plan
        .references
        .iter()
        .any(|target| own.contains(&normalize(target.address.ip())))
    {
        return Err(Error::SelfReference);
    }
    // Also resolve the operator-declared endpoint when it is a DNS name.
    // This is DNS only, never a connection to the inbound or a new target.
    // Reject references resolving back to any of those addresses.
    let own = extend_endpoint_addresses(plan, own).await?;
    timeout(BATCH, async {
        let _permit = ACTIVE.acquire().await.map_err(|_| Error::Timeout)?;
        let mut results = Vec::with_capacity(plan.references.len());
        for target in &plan.references {
            results.push(check_target(target, &roots, &own).await);
        }
        Ok(results)
    })
    .await
    .map_err(|_| Error::Timeout)?
}

/// Same strict health evaluator with a separately bounded search inventory.
/// Exact pins and fresh DNS remain mandatory for every candidate.
pub(crate) async fn check_search(
    search: &SearchPlan,
    approved: [u8; 32],
    progress: &std::sync::atomic::AtomicUsize,
) -> Result<Vec<Evidence>, Error> {
    if search.digest()? != approved { return Err(Error::Approval); }
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if roots.is_empty() { return Err(Error::NoRoots); }
    let roots = Arc::new(roots);
    let own = own_addresses(&search.0)?;
    let mut context = search.0.clone();
    context.references.clear();
    let own = Arc::new(extend_endpoint_addresses(&context, own).await?);
    timeout(SEARCH_DEADLINE, async {
        let _permit = ACTIVE.acquire().await.map_err(|_| Error::Timeout)?;
        let mut results = vec![Evidence::default(); search.targets().len()];
        for (batch, group) in search.targets().chunks(SEARCH_PARALLELISM).enumerate() {
            let mut tasks = tokio::task::JoinSet::new();
            for (offset, target) in group.iter().cloned().enumerate() {
                let roots = Arc::clone(&roots);
                let own = Arc::clone(&own);
                tasks.spawn(async move {
                    let evidence = if own.contains(&normalize(target.address.ip())) {
                        Evidence::default()
                    } else {
                        check_target(&target, &roots, &own).await
                    };
                    (batch * SEARCH_PARALLELISM + offset, evidence)
                });
            }
            while let Some(result) = tasks.join_next().await {
                let (index, evidence) = result.map_err(|_| Error::Timeout)?;
                results[index] = evidence;
                progress.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        Ok(results)
    }).await.map_err(|_| Error::Timeout)?
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub evidence: Evidence,
    pub failures: u8,
    pub h3_failures: u8,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema_version: u16,
    plan: Plan,
    revision: u64,
    last_checked_at: u64,
    health: Vec<Health>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimaryStatus {
    Healthy,
    Suspect,
    Degraded,
    Unavailable,
    Stale,
}

impl State {
    pub fn new(plan: Plan, evidence: Vec<Evidence>, now: u64) -> Result<Self, Error> {
        plan.validate()?;
        if evidence.len() != plan.references.len() || !evidence.iter().all(|item| item.eligible()) {
            return Err(Error::NotEligible);
        }
        let state = Self {
            schema_version: 1,
            plan,
            revision: 1,
            last_checked_at: now,
            health: evidence
                .into_iter()
                .map(|evidence| Health {
                    evidence,
                    failures: 0,
                    h3_failures: if evidence.h3() { 0 } else { 1 },
                })
                .collect(),
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), Error> {
        self.plan.validate()?;
        if self.schema_version != 1
            || self.revision == 0
            || self.last_checked_at == 0
            || self.health.len() != self.plan.references.len()
            || self.health.iter().any(|entry| {
                !entry.evidence.valid()
                    || (entry.failures == 0) != entry.evidence.eligible()
                    || (entry.h3_failures == 0) != entry.evidence.h3()
            })
        {
            return Err(Error::Format);
        }
        Ok(())
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn last_checked_at(&self) -> u64 {
        self.last_checked_at
    }

    /// Evidence digest binds the exact approved pins, check timestamp,
    /// revision and observed transport status for a guarded preview.
    pub fn snapshot_sha256(&self) -> Result<[u8; 32], Error> {
        Ok(digest(&self.encode()?))
    }

    /// Initial provisioning requires recent observations, not merely the
    /// periodic monitoring inventory's ordinary lifetime.
    pub fn provisioning_ready(&self, now: u64) -> Result<(), Error> {
        if now.checked_sub(self.last_checked_at).ok_or(Error::Clock)? > 60 {
            return Err(Error::NotEligible);
        }
        self.eligible_references(now)?;
        Ok(())
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// A fresh, all-eligible inventory for descriptor provisioning. Does not
    /// authorize a switch, expand approved targets or activate a listener.
    pub fn eligible_references(
        &self,
        now: u64,
    ) -> Result<Vec<crate::descriptor::Reference>, Error> {
        self.validate()?;
        if self.status(now)?.0 != PrimaryStatus::Healthy
            || !self.health.iter().all(|entry| entry.evidence.eligible())
        {
            return Err(Error::NotEligible);
        }
        Ok(self
            .plan
            .references
            .iter()
            .zip(&self.health)
            .map(|(target, entry)| crate::descriptor::Reference {
                server_name: target.server_name.clone(),
                port: target.address.port(),
                h3: entry.evidence.h3(),
            })
            .collect())
    }

    /// Observe the actual published reference and required transport set,
    /// not necessarily inventory index zero. H3 absence is a failure only
    /// when the already signed descriptor offers H3.
    pub fn active_status(
        &self,
        signed: &crate::descriptor::Descriptor,
        now: u64,
    ) -> Result<(PrimaryStatus, Option<usize>), Error> {
        self.validate()?;
        if now < self.last_checked_at {
            return Err(Error::Clock);
        }
        if !self.matches_descriptor(signed) {
            return Err(Error::Approval);
        }
        if now > self.next_check_at()?.saturating_add(JITTER) {
            return Ok((PrimaryStatus::Stale, None));
        }
        let active_index = usize::from(signed.active_reference);
        let active = self.health.get(active_index).ok_or(Error::Format)?;
        let eligible = |index: usize, entry: &Health| {
            entry.evidence.eligible()
                && (!signed.h3 || (entry.evidence.h3() && signed.references[index].h3))
        };
        if eligible(active_index, active) {
            return Ok((PrimaryStatus::Healthy, None));
        }
        let failures = if signed.h3 {
            active.failures.max(active.h3_failures)
        } else {
            active.failures
        };
        if failures < FAILURE_THRESHOLD {
            return Ok((PrimaryStatus::Suspect, None));
        }
        let reserve = self
            .health
            .iter()
            .enumerate()
            .filter(|(index, entry)| *index != active_index && eligible(*index, entry))
            .max_by_key(|(index, entry)| (entry.evidence.score(), std::cmp::Reverse(*index)))
            .map(|(index, _)| index);
        Ok(match reserve {
            Some(index) => (PrimaryStatus::Degraded, Some(index)),
            None => (PrimaryStatus::Unavailable, None),
        })
    }

    fn matches_descriptor(&self, signed: &crate::descriptor::Descriptor) -> bool {
        signed.scope.inbound == self.plan.inbound
            && signed.scope.endpoint == self.plan.endpoint
            && signed.references.len() == self.plan.references.len()
            && usize::from(signed.active_reference) < self.health.len()
            && signed
                .references
                .iter()
                .zip(&self.plan.references)
                .all(|(reference, target)| {
                    reference.server_name == target.server_name
                        && reference.port == target.address.port()
                })
    }

    /// One bounded follow-up after the first failure, rather than waiting
    /// another twelve hours to distinguish a transient outage.
    pub fn next_active_check_at(
        &self,
        signed: &crate::descriptor::Descriptor,
        now: u64,
    ) -> Result<u64, Error> {
        if self.active_status(signed, now)?.0 == PrimaryStatus::Suspect {
            self.last_checked_at.checked_add(300).ok_or(Error::Clock)
        } else {
            self.next_check_at()
        }
    }

    /// Validate the active signed reference without requiring every inactive
    /// reserve to be currently reachable. References remain an approved
    /// inventory, not a promise that all of them are currently healthy.
    pub fn validate_active(
        &self,
        signed: &crate::descriptor::Descriptor,
        now: u64,
    ) -> Result<(), Error> {
        self.validate()?;
        if now < self.last_checked_at {
            return Err(Error::Clock);
        }
        if now > self.next_check_at()?.saturating_add(JITTER) || !self.matches_descriptor(signed) {
            return Err(Error::NotEligible);
        }
        let active = self
            .health
            .get(usize::from(signed.active_reference))
            .ok_or(Error::Format)?;
        if !active.evidence.eligible() || (signed.h3 && !active.evidence.h3()) {
            return Err(Error::NotEligible);
        }
        Ok(())
    }

    /// A candidate is not a live switch. The two-cycle failure threshold
    /// applies to the currently published reference, not always index zero.
    /// All newly admitted transport modes must be retained.
    pub fn failover_candidate(
        &self,
        signed: &crate::descriptor::Descriptor,
        now: u64,
    ) -> Result<usize, Error> {
        if now.checked_sub(self.last_checked_at).ok_or(Error::Clock)? > 60 {
            return Err(Error::NotEligible);
        }
        let (status, reserve) = self.active_status(signed, now)?;
        if status != PrimaryStatus::Degraded {
            return Err(Error::NotEligible);
        }
        reserve.ok_or(Error::NotEligible)
    }

    pub fn next_check_at(&self) -> Result<u64, Error> {
        let mut hash = Sha256::new();
        hash.update(self.plan.digest()?);
        hash.update(self.revision.to_be_bytes());
        let bytes: [u8; 32] = hash.finalize().into();
        let offset = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| Error::Format)?)
            % (2 * JITTER + 1);
        self.last_checked_at
            .checked_add(INTERVAL - JITTER + offset)
            .ok_or(Error::Clock)
    }

    pub fn record(&self, evidence: Vec<Evidence>, now: u64) -> Result<Self, Error> {
        if now <= self.last_checked_at {
            return Err(Error::Clock);
        }
        if evidence.len() != self.health.len() || !evidence.iter().all(|item| item.valid()) {
            return Err(Error::Format);
        }
        let mut next = self.clone();
        next.revision = self.revision.checked_add(1).ok_or(Error::Conflict)?;
        next.last_checked_at = now;
        for (entry, observation) in next.health.iter_mut().zip(evidence) {
            entry.failures = if observation.eligible() {
                0
            } else {
                entry.failures.saturating_add(1)
            };
            entry.h3_failures = if observation.h3() {
                0
            } else {
                entry.h3_failures.saturating_add(1)
            };
            entry.evidence = observation;
        }
        next.validate()?;
        Ok(next)
    }

    pub fn status(&self, now: u64) -> Result<(PrimaryStatus, Option<usize>), Error> {
        self.validate()?;
        if now < self.last_checked_at {
            return Err(Error::Clock);
        }
        if now > self.next_check_at()?.saturating_add(JITTER) {
            return Ok((PrimaryStatus::Stale, None));
        }
        let primary = self.health[0];
        if primary.evidence.eligible() {
            return Ok((PrimaryStatus::Healthy, None));
        }
        if primary.failures < FAILURE_THRESHOLD {
            return Ok((PrimaryStatus::Suspect, None));
        }
        let reserve = self
            .health
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, entry)| entry.evidence.eligible())
            .max_by_key(|(index, entry)| (entry.evidence.score(), std::cmp::Reverse(*index)))
            .map(|(index, _)| index);
        Ok(match reserve {
            Some(index) => (PrimaryStatus::Degraded, Some(index)),
            None => (PrimaryStatus::Unavailable, None),
        })
    }

    /// A reserve suggestion is not permission to switch. No automatic
    /// publication until an independently reviewed bootstrap/recovery
    /// contract can establish compatibility of already enrolled clients.
    pub fn report(&self, now: u64) -> Result<String, Error> {
        let (status, reserve) = self.status(now)?;
        let mut result = format!(
            "Reference health only; runtime UNCHANGED\nrevision={}\nlast_checked_at={}\nnext_check_at={}\nprimary_status={status:?}",
            self.revision, self.last_checked_at, self.next_check_at()?
        );
        for (index, entry) in self.health.iter().enumerate() {
            result.push_str(&format!(
                "\nreference[{index}]: h2={} h3={} score={} consecutive_failures={} consecutive_h3_failures={}",
                entry.evidence.eligible(),
                entry.evidence.h3(),
                entry.evidence.score(),
                entry.failures,
                entry.h3_failures
            ));
        }
        if let Some(index) = reserve {
            result.push_str(&format!("\nreserve_candidate={index}; switch blocked pending verified bootstrap compatibility"));
        }
        Ok(result)
    }

    fn encode(&self) -> Result<String, Error> {
        self.validate()?;
        let raw = toml::to_string(self).map_err(|_| Error::Format)?;
        if raw.len() > MAX_STATE {
            return Err(Error::Format);
        }
        Ok(raw)
    }
}

/// A freshly revalidated exact approved reference. Its socket cannot be
/// supplied by network input. Leases expire after 60 seconds; a caller must
/// renew via State and the current verified signed descriptor.
pub struct RelayLease {
    address: SocketAddr,
    expires: tokio::time::Instant,
}

impl RelayLease {
    pub(crate) fn address(&self) -> Result<SocketAddr, Error> {
        if tokio::time::Instant::now() >= self.expires {
            return Err(Error::NotEligible);
        }
        Ok(self.address)
    }
}

impl State {
    // The production reference selection and freshness checks are still
    // exercised by controlled independent-server fixtures. Only the final
    // public DNS/connect address is substituted, in a unit-test binary.
    #[cfg(test)]
    pub(crate) fn fixture_relay_lease(
        &self,
        verified: &crate::descriptor::Verified,
        approved_plan_sha256: [u8; 32],
        approved: SocketAddr,
        fixture: SocketAddr,
    ) -> Result<RelayLease, Error> {
        let now = unix_now()?;
        if self.plan.digest()? != approved_plan_sha256
            || !fixture.ip().is_loopback()
            || fixture.port() == 0
        {
            return Err(Error::Approval);
        }
        verified.check_time(now).map_err(|_| Error::NotEligible)?;
        self.validate_active(verified.descriptor(), now)?;
        let target = self
            .plan
            .references
            .get(usize::from(verified.descriptor().active_reference))
            .ok_or(Error::Format)?;
        if target.address != approved {
            return Err(Error::Approval);
        }
        let remaining = verified
            .descriptor()
            .not_after
            .checked_sub(now)
            .ok_or(Error::Clock)?
            .min(60);
        if remaining == 0 {
            return Err(Error::NotEligible);
        }
        Ok(RelayLease {
            address: fixture,
            expires: tokio::time::Instant::now() + Duration::from_secs(remaining),
        })
    }

    pub async fn relay_lease(
        &self,
        verified: &crate::descriptor::Verified,
        approved_plan_sha256: [u8; 32],
    ) -> Result<RelayLease, Error> {
        if self.plan.digest()? != approved_plan_sha256 {
            return Err(Error::Approval);
        }
        let now = unix_now()?;
        verified.check_time(now).map_err(|_| Error::NotEligible)?;
        self.validate_active(verified.descriptor(), now)?;
        let target = self
            .plan
            .references
            .get(usize::from(verified.descriptor().active_reference))
            .ok_or(Error::Format)?;
        // The target is derived exclusively from the signed active index
        // and immutable approved plan, never from ClientHello contents.
        let _permit = timeout(ATTEMPT, ACTIVE.acquire())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Timeout)?;
        let own = extend_endpoint_addresses(&self.plan, own_addresses(&self.plan)?).await?;
        fresh_dns(target, &own).await?;
        let now = unix_now()?;
        self.validate_active(verified.descriptor(), now)?;
        verified.check_time(now).map_err(|_| Error::NotEligible)?;
        let remaining = verified
            .descriptor()
            .not_after
            .checked_sub(now)
            .ok_or(Error::Clock)?
            .min(60);
        if remaining == 0 {
            return Err(Error::NotEligible);
        }
        Ok(RelayLease {
            address: target.address,
            expires: tokio::time::Instant::now() + Duration::from_secs(remaining),
        })
    }
}

pub struct Store {
    path: PathBuf,
}
impl Store {
    pub fn new(path: &Path) -> Result<Self, Error> {
        if !crate::bounded_input::explicit_file_path(path) {
            return Err(Error::Storage);
        }
        Ok(Self {
            path: path.to_owned(),
        })
    }

    fn snapshot(&self) -> Result<(Vec<u8>, State), Error> {
        let raw = crate::bounded_input::read(&self.path, MAX_STATE as u64, true, true)
            .map_err(|_| Error::Storage)?;
        let text = std::str::from_utf8(&raw).map_err(|_| Error::Format)?;
        let state: State = toml::from_str(text).map_err(|_| Error::Format)?;
        state.validate()?;
        Ok((raw.to_vec(), state))
    }

    pub fn inspect(&self) -> Result<State, Error> {
        self.snapshot().map(|(_, state)| state)
    }

    #[cfg(test)]
    pub(crate) fn fixture_record(&self, evidence: Vec<Evidence>, now: u64) -> Result<State, Error> {
        let (raw, previous) = self.snapshot()?;
        let next = previous.record(evidence, now)?;
        config::guarded_trust_write(&self.path, &next.encode()?, Some(&raw))
            .map_err(storage_error)?;
        Ok(next)
    }

    pub fn enroll(&self, state: &State) -> Result<(), Error> {
        if state.revision != 1 || !state.health.iter().all(|entry| entry.evidence.eligible()) {
            return Err(Error::Format);
        }
        config::guarded_trust_write(&self.path, &state.encode()?, None).map_err(storage_error)
    }

    /// Pin the approved immutable plan and exact persisted state before any
    /// network operation. Publish only if those bytes remain unchanged.
    pub async fn recheck(&self, revision: u64, approved: [u8; 32]) -> Result<State, Error> {
        let (raw, previous) = self.snapshot()?;
        if previous.revision != revision {
            return Err(Error::Conflict);
        }
        if previous.plan.digest()? != approved {
            return Err(Error::Approval);
        }
        let started = unix_now()?;
        if started <= previous.last_checked_at {
            return Err(Error::Clock);
        }
        let evidence = check(&previous.plan, approved).await?;
        let finished = unix_now()?;
        if finished < started {
            return Err(Error::Clock);
        }
        let next = previous.record(evidence, finished)?;
        config::guarded_trust_write(&self.path, &next.encode()?, Some(&raw))
            .map_err(storage_error)?;
        Ok(next)
    }
}

fn storage_error(error: WriteFailure) -> Error {
    match error {
        WriteFailure::BeforeReplace(_) => Error::Storage,
        WriteFailure::AfterReplace(_) => Error::Indeterminate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            schema_version: 1,
            inbound: "edge".into(),
            endpoint: "edge.example.org:443".into(),
            own_ips: vec!["93.184.216.1".parse().unwrap()],
            references: ["93.184.216.2", "93.184.216.3", "93.184.216.4"]
                .into_iter()
                .enumerate()
                .map(|(index, ip)| Target {
                    server_name: format!("reference{index}.example.org"),
                    address: format!("{ip}:443").parse().unwrap(),
                })
                .collect(),
        }
    }

    fn good(h3: bool) -> Evidence {
        Evidence {
            h2_status: Some(200),
            h3_status: h3.then_some(200),
        }
    }

    #[test]
    fn plan_rejects_duplicate_pins_self_and_private_targets() {
        let original = plan();
        assert!(original.validate().is_ok());
        let mut bad = original.clone();
        bad.references[0].address = bad.references[1].address;
        assert_eq!(bad.validate(), Err(Error::Format));
        let mut bad = original.clone();
        bad.references[0].address = "10.0.0.1:443".parse().unwrap();
        assert_eq!(bad.validate(), Err(Error::Format));
        let mut bad = original.clone();
        bad.references[0].address = "93.184.216.1:443".parse().unwrap();
        assert_eq!(bad.validate(), Err(Error::SelfReference));
        let mut bad = original;
        bad.references[0].server_name = "edge.example.org".into();
        assert_eq!(bad.validate(), Err(Error::SelfReference));
    }

    #[test]
    fn fresh_dns_vets_all_answers_not_just_displayed_pins() {
        let plan = plan();
        let target = &plan.references[0];
        let own = plan.own_ips.iter().copied().collect();
        assert_eq!(vet_pin(&[target.address], target, &own), Ok(()));
        assert_eq!(
            vet_pin(&[plan.references[1].address], target, &own),
            Err(Error::Dns)
        );
        assert_eq!(
            vet_pin(
                &[target.address, "10.0.0.1:443".parse().unwrap()],
                target,
                &own
            ),
            Err(Error::Dns)
        );
        assert_eq!(
            vet_pin(
                &[target.address, "93.184.216.1:443".parse().unwrap()],
                target,
                &own
            ),
            Err(Error::SelfReference)
        );
        let mut many = vec![target.address; 9];
        many.push("93.184.216.1:443".parse().unwrap());
        assert_eq!(vet_pin(&many, target, &own), Err(Error::SelfReference));
    }

    #[test]
    fn two_independent_successes_are_required_and_h3_is_optional() {
        assert_eq!(stable(Some(200), Some(200)), Some(200));
        assert_eq!(stable(Some(200), Some(204)), None);
        assert_eq!(stable(Some(200), None), None);
        assert_eq!(stable(Some(403), Some(403)), None);
        assert_eq!(good(false).score(), 80);
        assert_eq!(good(true).score(), 100);
        let h3_only = Evidence {
            h2_status: None,
            h3_status: Some(200),
        };
        assert!(!h3_only.eligible());
        assert_eq!(h3_only.score(), 0);
    }

    #[test]
    fn persistent_hysteresis_suggests_only_fresh_approved_reserves() {
        let plan = plan();
        let good_all = vec![good(false), good(false), good(true)];
        let start = State::new(plan.clone(), good_all.clone(), 100).unwrap();
        assert_eq!(start.status(100), Ok((PrimaryStatus::Healthy, None)));
        let failed = vec![Evidence::default(), good(false), good(true)];
        let once = start.record(failed.clone(), 200).unwrap();
        assert_eq!(once.status(200), Ok((PrimaryStatus::Suspect, None)));
        let twice = once.record(failed, 300).unwrap();
        assert_eq!(twice.status(300), Ok((PrimaryStatus::Degraded, Some(2))));
        assert!(twice.plan() == &plan);
        let restored: State = toml::from_str(&twice.encode().unwrap()).unwrap();
        assert_eq!(restored.status(300), Ok((PrimaryStatus::Degraded, Some(2))));
        assert_eq!(
            restored.status(restored.next_check_at().unwrap() + JITTER + 1),
            Ok((PrimaryStatus::Stale, None))
        );
        assert_eq!(restored.status(299), Err(Error::Clock));
        let recovered = restored.record(good_all, 400).unwrap();
        assert_eq!(recovered.status(400), Ok((PrimaryStatus::Healthy, None)));
        let down = twice.record(vec![Evidence::default(); 3], 401).unwrap();
        assert_eq!(down.status(401), Ok((PrimaryStatus::Unavailable, None)));
    }

    #[test]
    fn active_health_follows_published_index_and_required_transport() {
        let plan = plan();
        let identity = crate::identity_tls::Identity::generate(crate::descriptor::Scope {
            inbound: plan.inbound.clone(),
            endpoint: plan.endpoint.clone(),
        })
        .unwrap();
        let start = State::new(plan, vec![good(true); 3], 100).unwrap();
        let signed = crate::reality_bootstrap::initial_descriptor(&start, &identity, 100).unwrap();
        let anchor = crate::descriptor::Anchor::new(
            identity.scope().clone(),
            identity.public_key(),
            1,
            crate::reality_bootstrap::auto_policy(),
        )
        .unwrap();
        let mut d = crate::descriptor::verify(&signed, &anchor)
            .unwrap()
            .descriptor()
            .clone();
        d.active_reference = 1;
        let once = start
            .record(vec![good(true), good(false), good(true)], 200)
            .unwrap();
        assert_eq!(once.status(200), Ok((PrimaryStatus::Healthy, None)));
        assert_eq!(
            once.active_status(&d, 200),
            Ok((PrimaryStatus::Suspect, None))
        );
        assert_eq!(once.next_active_check_at(&d, 200), Ok(500));
        assert!(once.failover_candidate(&d, 200).is_err());
        let twice = once
            .record(vec![good(false), good(false), good(true)], 500)
            .unwrap();
        assert_eq!(
            twice.active_status(&d, 500),
            Ok((PrimaryStatus::Degraded, Some(2)))
        );
        assert_eq!(twice.failover_candidate(&d, 500), Ok(2));
        assert!(twice.failover_candidate(&d, 561).is_err());
        let reopened: State = toml::from_str(&twice.encode().unwrap()).unwrap();
        assert_eq!(
            reopened.active_status(&d, 500),
            Ok((PrimaryStatus::Degraded, Some(2)))
        );
        d.h3 = false;
        assert_eq!(
            reopened.active_status(&d, 500),
            Ok((PrimaryStatus::Healthy, None))
        );
        d.references[1].server_name = "wrong.example.org".into();
        assert_eq!(reopened.active_status(&d, 500), Err(Error::Approval));
    }

    #[test]
    fn initial_inventory_requires_all_approved_targets_eligible() {
        assert!(matches!(
            State::new(
                plan(),
                vec![good(true), good(false), Evidence::default()],
                100
            ),
            Err(Error::NotEligible)
        ));
        let state = State::new(plan(), vec![good(false); 3], 100).unwrap();
        let scheduled = state.next_check_at().unwrap();
        assert!((100 + INTERVAL - JITTER..=100 + INTERVAL + JITTER).contains(&scheduled));
        assert!(matches!(
            state.record(vec![good(false); 3], 100),
            Err(Error::Clock)
        ));
    }

    #[tokio::test]
    async fn incorrect_digest_is_rejected_before_any_network() {
        assert_eq!(check(&plan(), [0; 32]).await, Err(Error::Approval));
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "theia-reference-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn durable_inventory_rejects_stale_revision_and_wrong_digest_before_network() {
        let dir = Scratch::new();
        let path = dir.0.join("health.toml");
        let state = State::new(plan(), vec![good(false); 3], 100).unwrap();
        let store = Store::new(&path).unwrap();
        store.enroll(&state).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(store.enroll(&state).is_err());
        let reopened = Store::new(&path).unwrap();
        let restored = reopened.inspect().unwrap();
        assert_eq!(restored.revision(), 1);
        let approved = restored.plan().digest().unwrap();
        assert!(matches!(
            reopened.recheck(2, approved).await,
            Err(Error::Conflict)
        ));
        assert!(matches!(
            reopened.recheck(1, [0; 32]).await,
            Err(Error::Approval)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    fn assert_head(request: &Request<()>) {
        assert_eq!(request.method(), Method::HEAD);
        assert_eq!(request.uri().path(), "/");
        assert!(!request.headers().contains_key(http::header::AUTHORIZATION));
        assert!(!request.headers().contains_key(http::header::COOKIE));
    }

    async fn application_fixture(
        h2_status: u16,
        h3_status: u16,
    ) -> (Target, RootCertStore, Driver, Driver) {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let signed = generate_simple_self_signed(vec!["reference.example.org".into()]).unwrap();
        let cert = signed.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(signed.key_pair.serialize_der());
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.clone_key().into())
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (listener, udp_socket) = crate::shared_port::reserve_shared_port();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        udp_socket.set_nonblocking(true).unwrap();
        let listener = TcpListener::from_std(listener).unwrap();
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(crate::quic_transport::server_config(vec![cert], key.into()).unwrap()),
            udp_socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let tcp = Driver(tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let Ok(tls) = acceptor.accept(socket).await else {
                return;
            };
            let mut h2 = h2::server::handshake(tls).await.unwrap();
            while let Some(Ok((request, mut response))) = h2.accept().await {
                let (parts, _) = request.into_parts();
                assert_head(&Request::from_parts(parts, ()));
                response
                    .send_response(
                        http::Response::builder()
                            .status(h2_status)
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
            }
        }));
        let udp = Driver(tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let Ok(connection) = crate::quic_transport::accept(incoming).await else {
                return;
            };
            let mut builder = h3::server::builder();
            builder.max_field_section_size(8192);
            let mut server = builder
                .build::<_, Bytes>(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            while let Ok(Some(resolver)) = server.accept().await {
                let Ok((request, mut stream)) = resolver.resolve_request().await else {
                    break;
                };
                assert_head(&request);
                // HEAD has no request body. Wait for its actual FIN before
                // returning the response and releasing the receive half.
                // Otherwise STOP_SENDING can race the client's finish().
                assert!(stream.recv_data().await.unwrap().is_none());
                assert!(stream.recv_trailers().await.unwrap().is_none());
                stream
                    .send_response(
                        http::Response::builder()
                            .status(h3_status)
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            }
        }));
        (
            Target {
                server_name: "reference.example.org".into(),
                address,
            },
            roots,
            tcp,
            udp,
        )
    }

    // Private fixture bypasses only the public-IP/DNS gate, not PKI or ALPN.
    // Production callers can reach these functions only through check().
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn independent_local_h2_h3_head_responses_are_observed() {
        let (target, roots, _tcp, _udp) = application_fixture(204, 302).await;
        let (h2, h3) = tokio::join!(
            timeout(ATTEMPT, h2_head(&target, roots.clone())),
            timeout(ATTEMPT, h3_head(&target, roots))
        );
        assert_eq!(h2.unwrap(), Some(204));
        assert_eq!(h3.unwrap(), Some(302));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn application_probes_refuse_untrusted_or_wrong_name_before_head() {
        let (mut target, roots, _tcp, _udp) = application_fixture(200, 200).await;
        target.server_name = "wrong.example.org".into();
        let (h2, h3) = tokio::join!(
            timeout(ATTEMPT, h2_head(&target, roots.clone())),
            timeout(ATTEMPT, h3_head(&target, roots))
        );
        assert_eq!(h2.unwrap(), None);
        assert_eq!(h3.unwrap(), None);
        let (target, _, _tcp, _udp) = application_fixture(200, 200).await;
        let other =
            rcgen::generate_simple_self_signed(vec!["reference.example.org".into()]).unwrap();
        let mut wrong = RootCertStore::empty();
        wrong.add(other.cert.der().clone()).unwrap();
        let (h2, h3) = tokio::join!(
            timeout(ATTEMPT, h2_head(&target, wrong.clone())),
            timeout(ATTEMPT, h3_head(&target, wrong))
        );
        assert_eq!(h2.unwrap(), None);
        assert_eq!(h3.unwrap(), None);
    }
}
