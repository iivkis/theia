//! M4.5f: explicit source-aware dual-transport candidates, never a CIDR
//! enumerator, DNS resolver or automatic scanner. Every target must be
//! operator approved before the FIRST TCP or UDP socket is opened.
use crate::{
    camouflage_dual::{
        probe_dual_h2_h3_with_consent, validate_dual_target, CandidateConsent, DualProbeError,
        DualProbeReport, DualProbeTarget,
    },
    camouflage_workflow::DiscoveryPreview,
};
use std::{collections::HashSet, fmt, net::SocketAddr, time::Duration};
use tokio::{task::JoinSet, time::timeout};

/// Hard upper bound of manually selected exact candidate IP:443/SNI pairs.
pub const MAX_DUAL_BATCH: usize = 8;
const MAX_IN_FLIGHT_CANDIDATES: usize = 2;
const MAX_DUAL_BATCH_DEADLINE: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub struct DualBatchTarget {
    pub target: DualProbeTarget,
    pub consent: CandidateConsent,
}

impl fmt::Debug for DualBatchTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DualBatchTarget(<redacted>)")
    }
}

#[derive(Clone)]
pub struct DualBatchOutcome {
    pub address: SocketAddr,
    pub result: Result<DualProbeReport, DualProbeError>,
}

impl fmt::Debug for DualBatchOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DualBatchOutcome(<redacted>)")
    }
}

#[derive(Clone)]
pub struct DualBatchReport {
    /// Stable input order. One entry can have independent H2 and H3 errors.
    pub results: Vec<DualBatchOutcome>,
}

impl fmt::Debug for DualBatchReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DualBatchReport")
            .field("count", &self.results.len())
            .field("dual_verified", &self.dual_verified_count())
            .finish()
    }
}

impl DualBatchReport {
    /// Transport-level TLS witnesses, not proof of REALITY compatibility.
    pub fn dual_verified_count(&self) -> usize {
        self.results
            .iter()
            .filter(|item| item.result.as_ref().is_ok_and(|r| r.both_transports_verified()))
            .count()
    }

    /// No cryptographically authenticated REALITY-like security mode exists.
    pub fn reality_ready(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DualBatchError {
    Empty,
    TooManyTargets,
    DuplicateTarget,
    Target(DualProbeError),
    TaskFailed,
    BatchTimedOut,
}

/// Check the whole operator-supplied batch BEFORE any sockets or DNS lookup.
/// Each public IP needs exact explicit approval, a planned IP or separately
/// approved catalogued domain+pin, validated CA roots, nonzero deadline and
/// DNS SNI. Domain seed presence is not permission to scan a website.
/// Even for approved candidates no DNS lookup is done by this function.
///
/// At most 8 candidates total, 2 concurrently, max 20s for the group. Each
/// candidate's independent H2 and H3 handshakes use the strict <=5s probe
/// deadlines. There are no automatic retries, CIDR sweeps or HTTP requests.
/// Results are in original order; failures on one transport cannot qualify
/// that candidate for a dual-transport security profile.
pub async fn probe_dual_batch(
    preview: &DiscoveryPreview,
    candidates: Vec<DualBatchTarget>,
) -> Result<DualBatchReport, DualBatchError> {
    if candidates.is_empty() {
        return Err(DualBatchError::Empty);
    }
    if candidates.len() > MAX_DUAL_BATCH {
        return Err(DualBatchError::TooManyTargets);
    }

    let mut seen = HashSet::with_capacity(candidates.len());
    for item in &candidates {
        let addr = item.target.request.address;
        if !seen.insert((addr, item.target.request.server_name.clone())) {
            return Err(DualBatchError::DuplicateTarget);
        }
    }
    // Every target is validated before any socket. Separate structural
    // duplicate rejection so invalid entries cannot hide duplicate targets.
    for item in &candidates {
        validate_dual_target(preview, &item.target, item.consent)
            .map_err(DualBatchError::Target)?;
    }

    let count = candidates.len();
    let preview = preview.clone();
    timeout(MAX_DUAL_BATCH_DEADLINE, async move {
        let mut queue = candidates.into_iter().enumerate();
        let mut tasks = JoinSet::new();
        // Both transports can run within one candidate. The in-flight
        // candidate cap bounds simultaneous TCP+UDP sockets to four.
        for _ in 0..MAX_IN_FLIGHT_CANDIDATES {
            let Some((index, item)) = queue.next() else {
                break;
            };
            let plan = preview.clone();
            tasks.spawn(async move {
                let address = item.target.request.address;
                let result =
                    probe_dual_h2_h3_with_consent(&plan, item.target, item.consent).await;
                (index, DualBatchOutcome { address, result })
            });
        }
        let mut indexed: Vec<Option<DualBatchOutcome>> = (0..count).map(|_| None).collect();
        while let Some(next) = tasks.join_next().await {
            let (index, outcome) = next.map_err(|_| DualBatchError::TaskFailed)?;
            if index >= count || indexed[index].is_some() {
                return Err(DualBatchError::TaskFailed);
            }
            indexed[index] = Some(outcome);
            if let Some((next_index, item)) = queue.next() {
                let plan = preview.clone();
                tasks.spawn(async move {
                    let address = item.target.request.address;
                    let result =
                        probe_dual_h2_h3_with_consent(&plan, item.target, item.consent).await;
                    (next_index, DualBatchOutcome { address, result })
                });
            }
        }
        let results = indexed
            .into_iter()
            .map(|entry| entry.ok_or(DualBatchError::TaskFailed))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DualBatchReport { results })
    })
    .await
    .map_err(|_| DualBatchError::BatchTimedOut)?
}
