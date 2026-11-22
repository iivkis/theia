//! M3.5b2b3: bounded, *explicit-target-only* TLS1.3/H2 observations.
//!
//! No DNS, subnet expansion, seed domain scanning, HTTP GET, redirects,
//! user-facing scanning command, or automatic approval. The caller must have
//! independently obtained operator permission for every exact public IP,
//! with a separate per-IP ProbeApproval. A preview never grants consent.
use crate::{
    camouflage_discovery::{CandidateHost, CandidateSource},
    camouflage_probe::{probe_tls_h2, ProbeApproval, ProbeError, ProbeReport, ProbeRequest},
    camouflage_workflow::DiscoveryPreview,
};
use rustls::RootCertStore;
use std::{collections::HashSet, fmt, net::SocketAddr, time::Duration};
use tokio::{task::JoinSet, time::timeout};

/// Maximum *explicit* targets per batch, including loopback test fixtures.
/// The underlying TLS probe also has a global four-handshake semaphore.
pub const MAX_EXPLICIT_BATCH: usize = 8;
const MAX_BATCH_DEADLINE: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub struct BatchTarget {
    pub request: ProbeRequest,
    pub roots: RootCertStore,
    pub approval: ProbeApproval,
}

/// The address and its evidence are available to an explicitly authorized
/// caller, but intentionally redacted from default Debug/log formatting.
#[derive(Clone)]
pub struct TargetOutcome {
    pub address: SocketAddr,
    pub result: Result<ProbeReport, ProbeError>,
}

#[derive(Clone)]
pub struct BatchResult {
    pub results: Vec<TargetOutcome>,
    /// This means ordinary TLS1.3/h2 observations completed successfully;
    /// fingerprint, REALITY and TLS-in-TLS suitability still stay UNKNOWN.
    pub all_handshakes_verified: bool,
}

impl fmt::Debug for BatchTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BatchTarget(<redacted>)")
    }
}

impl fmt::Debug for TargetOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TargetOutcome(<redacted>)")
    }
}

impl fmt::Debug for BatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BatchResult")
            .field("count", &self.results.len())
            .field("all_handshakes_verified", &self.all_handshakes_verified)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchError {
    Empty,
    TooManyTargets,
    DuplicateAddress,
    NotApproved,
    UnplannedAddress,
    TaskFailed,
    BatchTimedOut,
}

/// Run at most eight caller-selected exact TLS/H2 checks. This does *not*
/// select addresses from a CIDR or seed domains: every public target must be
/// present in the offline plan and have its own exact public-IP/443 approval.
/// Presence in the plan is **not** evidence of ownership or a substitute for
/// the required independent operator authorization at the UI/caller boundary.
///
/// Loopback fixtures are available only for exact-socket isolated CI tests.
/// No active probe starts if preflight validation fails for *any* target.
/// A per-target error does not discard successful siblings or masquerade as
/// eligible/verified fingerprint evidence. No implicit retries or fallback.
pub async fn probe_explicit_batch(
    preview: &DiscoveryPreview,
    targets: Vec<BatchTarget>,
) -> Result<BatchResult, BatchError> {
    if targets.is_empty() {
        return Err(BatchError::Empty);
    }
    if targets.len() > MAX_EXPLICIT_BATCH {
        return Err(BatchError::TooManyTargets);
    }
    let mut seen = HashSet::with_capacity(targets.len());
    for target in &targets {
        let address = target.request.address;
        if !seen.insert(address) {
            return Err(BatchError::DuplicateAddress);
        }
        if !target.approval.allows(address) {
            return Err(BatchError::NotApproved);
        }
        if matches!(target.approval, ProbeApproval::PublicHttpsIp(_))
            && !preview.plan.candidates.iter().any(|candidate| {
                candidate.host == CandidateHost::Ip(address.ip())
                    && matches!(
                        candidate.source,
                        CandidateSource::ServerAddress | CandidateSource::AuthorizedSubnet
                    )
            })
        {
            return Err(BatchError::UnplannedAddress);
        }
    }
    let count = targets.len();
    timeout(MAX_BATCH_DEADLINE, async move {
        let mut tasks = JoinSet::new();
        for (index, target) in targets.into_iter().enumerate() {
            tasks.spawn(async move {
                let address = target.request.address;
                let result = probe_tls_h2(target.request, target.roots, target.approval).await;
                (index, TargetOutcome { address, result })
            });
        }
        let mut indexed: Vec<Option<TargetOutcome>> = (0..count).map(|_| None).collect();
        while let Some(next) = tasks.join_next().await {
            let (index, outcome) = next.map_err(|_| BatchError::TaskFailed)?;
            if index >= count || indexed[index].is_some() {
                return Err(BatchError::TaskFailed);
            }
            indexed[index] = Some(outcome);
        }
        let results: Vec<_> = indexed
            .into_iter()
            .map(|outcome| outcome.ok_or(BatchError::TaskFailed))
            .collect::<Result<_, _>>()?;
        let all_handshakes_verified = results
            .iter()
            .all(|outcome: &TargetOutcome| outcome.result.is_ok());
        Ok(BatchResult {
            results,
            all_handshakes_verified,
        })
    })
    .await
    .map_err(|_| BatchError::BatchTimedOut)?
}
