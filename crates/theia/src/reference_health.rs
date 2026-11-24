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
        if self.schema_version != 1
            || !config::valid_id(&self.inbound)
            || !config::valid_remote(&self.endpoint)
            || !(1..=MAX_OWN_IPS).contains(&self.own_ips.len())
            || !(1..=MAX_REFERENCES).contains(&self.references.len())
        {
            return Err(Error::Format);
        }
        let endpoint_host = self.endpoint.rsplit_once(':').ok_or(Error::Format)?.0;
        let mut addresses = HashSet::new();
        for ip in &self.own_ips {
            if ip.is_unspecified()
                || ip.is_multicast()
                || !addresses.insert(normalize(*ip))
            {
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
        for target in &self.references {
            if crate::camouflage_domain_dns::validate_manual_dns_request(
                &target.server_name,
                crate::camouflage_domain_dns::DnsConsent::Approved,
            )
            .is_err()
                || target.address.port() != 443
                || !public_address(target.address.ip())
                || !names.insert(&target.server_name)
                || !pins.insert(target.address)
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
        let mut out = format!("Reference plan; no network, no runtime Apply\ninbound={}\nendpoint={}", self.inbound, self.endpoint);
        for (index, target) in self.references.iter().enumerate() {
            out.push_str(&format!(
                "\nreference[{index}]={} {}",
                target.server_name, target.address
            ));
        }
        out.push_str("\nConsent covers DNS and two HTTPS HEAD / attempts on each exact pin, H2 and H3; no redirects, bearer or request body.");
        Ok(out)
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
    let mut own: HashSet<_> = plan.own_ips.iter().copied().map(normalize).collect();
    #[cfg(target_os = "linux")]
    {
        let interfaces = crate::camouflage_interfaces::collect_assigned_interfaces()
            .map_err(|_| Error::Dns)?;
        own.extend(interfaces.interfaces.into_iter().map(|item| normalize(item.address)));
    }
    Ok(own)
}

/// Inspect every DNS answer before allowing the pinned IP. In contrast to
/// the display-limited wizard list, a self address anywhere poisons the set.
fn vet_pin(
    answers: &[SocketAddr],
    target: &Target,
    own: &HashSet<IpAddr>,
) -> Result<(), Error> {
    if answers.is_empty() || answers.len() > MAX_DNS_ANSWERS {
        return Err(Error::Dns);
    }
    if answers.iter().any(|address| own.contains(&normalize(address.ip()))) {
        return Err(Error::SelfReference);
    }
    if answers.iter().any(|address| {
        address.port() != target.address.port() || !public_address(address.ip())
    }) || !answers.contains(&target.address) {
        return Err(Error::Dns);
    }
    Ok(())
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
        .uri(format!("https://{}:{}/", target.server_name, target.address.port()))
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
    provider.kx_groups.retain(|group| group.name() == rustls::NamedGroup::X25519);
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
    let tls = TlsConnector::from(Arc::new(tls)).connect(name, tcp).await.ok()?;
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
    let connection = endpoint.connect(target.address, &target.server_name, ATTEMPT).await.ok()?;
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

async fn check_target(
    target: &Target,
    roots: &RootCertStore,
    own: &HashSet<IpAddr>,
) -> Evidence {
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
    if plan.references.iter().any(|target| own.contains(&normalize(target.address.ip()))) {
        return Err(Error::SelfReference);
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub evidence: Evidence,
    pub failures: u8,
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
            health: evidence.into_iter().map(|evidence| Health { evidence, failures: 0 }).collect(),
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
            })
        {
            return Err(Error::Format);
        }
        Ok(())
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    pub fn next_check_at(&self) -> Result<u64, Error> {
        let mut hash = Sha256::new();
        hash.update(self.plan.digest()?);
        hash.update(self.revision.to_be_bytes());
        let bytes: [u8; 32] = hash.finalize().into();
        let offset = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| Error::Format)?)
            % (2 * JITTER + 1);
        self.last_checked_at.checked_add(INTERVAL - JITTER + offset).ok_or(Error::Clock)
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
        let reserve = self.health.iter().enumerate().skip(1)
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
                "\nreference[{index}]: h2={} h3={} score={} consecutive_failures={}",
                entry.evidence.eligible(), entry.evidence.h3(), entry.evidence.score(), entry.failures
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

pub struct Store {
    path: PathBuf,
}
impl Store {
    pub fn new(path: &Path) -> Result<Self, Error> {
        if !crate::bounded_input::explicit_file_path(path) {
            return Err(Error::Storage);
        }
        Ok(Self { path: path.to_owned() })
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
        Evidence { h2_status: Some(200), h3_status: h3.then_some(200) }
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
        assert_eq!(vet_pin(&[plan.references[1].address], target, &own), Err(Error::Dns));
        assert_eq!(vet_pin(&[target.address, "10.0.0.1:443".parse().unwrap()], target, &own), Err(Error::Dns));
        assert_eq!(vet_pin(&[target.address, "93.184.216.1:443".parse().unwrap()], target, &own), Err(Error::SelfReference));
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
        let h3_only = Evidence { h2_status: None, h3_status: Some(200) };
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
    fn initial_inventory_requires_all_approved_targets_eligible() {
        assert!(matches!(
            State::new(plan(), vec![good(true), good(false), Evidence::default()], 100),
            Err(Error::NotEligible)
        ));
        let state = State::new(plan(), vec![good(false); 3], 100).unwrap();
        let scheduled = state.next_check_at().unwrap();
        assert!((100 + INTERVAL - JITTER..=100 + INTERVAL + JITTER).contains(&scheduled));
        assert!(matches!(state.record(vec![good(false); 3], 100), Err(Error::Clock)));
    }

    #[tokio::test]
    async fn incorrect_digest_is_rejected_before_any_network() {
        assert_eq!(check(&plan(), [0; 32]).await, Err(Error::Approval));
    }
}
