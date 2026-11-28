//! Shared bounded probe scheduling. Admission, evidence and fallback
//! decisions remain with the protocol owner; a permit is not route permission.
use std::{
    hash::{Hash, Hasher},
    time::Duration,
};
use tokio::{
    sync::{AcquireError, Mutex, MutexGuard, Semaphore, SemaphorePermit, TryAcquireError},
    time::{timeout, Instant},
};

pub(crate) struct ProbeBudget(Semaphore);
impl ProbeBudget {
    pub(crate) const fn new(limit: usize) -> Self {
        Self(Semaphore::const_new(limit))
    }
    pub(crate) async fn acquire(&self) -> Result<SemaphorePermit<'_>, AcquireError> {
        self.0.acquire().await
    }
    pub(crate) fn try_acquire(&self) -> Result<SemaphorePermit<'_>, TryAcquireError> {
        self.0.try_acquire()
    }
}

// One global cap for explicit H2/H3 diagnostic reference handshakes.
// Egress HTTP and health inventory have their own bounded budgets.
pub(crate) static REFERENCE_PROBES: ProbeBudget = ProbeBudget::new(4);

const STRIPES: usize = 32;

/// One instance per client profile. Foreground probes may wait briefly
/// for the same key; background refresh never waits or creates tasks.
pub(crate) struct ProbeScheduler {
    budget: ProbeBudget,
    stripes: [Mutex<()>; STRIPES],
}
impl ProbeScheduler {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            budget: ProbeBudget::new(limit),
            stripes: std::array::from_fn(|_| Mutex::new(())),
        }
    }
    fn stripe(&self, key: impl Hash) -> &Mutex<()> {
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hash);
        &self.stripes[(hash.finish() as usize) % STRIPES]
    }
    pub(crate) async fn lock(&self, key: impl Hash, wait: Duration) -> Option<MutexGuard<'_, ()>> {
        timeout(wait, self.stripe(key).lock()).await.ok()
    }
    pub(crate) fn try_lock(&self, key: impl Hash) -> Option<MutexGuard<'_, ()>> {
        self.stripe(key).try_lock().ok()
    }
    pub(crate) fn try_acquire(&self) -> Result<SemaphorePermit<'_>, TryAcquireError> {
        self.budget.try_acquire()
    }
}

/// A role-local shared budget. Foreground operations queue on the common
/// semaphore; diagnostics never enqueue ahead of a waiting foreground
/// operation. In an owned session, the diagnostic runner also caps itself
/// at two rows.
pub(crate) struct PriorityBudget {
    permits: Semaphore,
    waiters: std::sync::atomic::AtomicUsize,
}

#[cfg(any(windows, test))]
struct Waiting<'a>(&'a std::sync::atomic::AtomicUsize);
#[cfg(any(windows, test))]
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl PriorityBudget {
    #[cfg(any(windows, test))]
    pub(crate) fn new() -> Self {
        Self { permits: Semaphore::new(4), waiters: std::sync::atomic::AtomicUsize::new(0) }
    }

    #[cfg(any(windows, test))]
    pub(crate) async fn production(&self, count: u32) -> Result<SemaphorePermit<'_>, AcquireError> {
        self.waiters.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let _waiting = Waiting(&self.waiters);
        self.permits.acquire_many(count).await
    }

    pub(crate) async fn diagnostic(&self, deadline: Instant) -> Option<SemaphorePermit<'_>> {
        loop {
            if Instant::now() >= deadline { return None; }
            if self.waiters.load(std::sync::atomic::Ordering::Acquire) == 0 {
                if let Ok(permit) = self.permits.try_acquire() {
                    if self.waiters.load(std::sync::atomic::Ordering::Acquire) == 0 {
                        return Some(permit);
                    }
                    drop(permit);
                }
            }
            tokio::time::sleep_until((Instant::now() + Duration::from_millis(20)).min(deadline)).await;
        }
    }
}

/// A probe must fit alongside the remaining setup reserve. Exhaustion is
/// not a transport verdict; callers must not publish negative evidence.
pub(crate) fn fits(deadline: Instant, attempt: Duration, reserve: Duration) -> bool {
    attempt
        .checked_add(reserve)
        .is_some_and(|required| deadline.saturating_duration_since(Instant::now()) >= required)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn contention_is_bounded_and_cancel_releases_capacity() {
        let scheduler = ProbeScheduler::new(1);
        let lock = scheduler.try_lock("same target").unwrap();
        assert!(scheduler.try_lock("same target").is_none());
        assert!(scheduler
            .lock("same target", Duration::from_millis(250))
            .await
            .is_none());
        drop(lock);
        assert!(scheduler.try_lock("same target").is_some());
        let permit = scheduler.try_acquire().unwrap();
        assert!(scheduler.try_acquire().is_err());
        drop(permit);
        assert!(scheduler.try_acquire().is_ok());
    }
    #[tokio::test(start_paused = true)]
    async fn cancelled_waiter_cannot_consume_a_permit() {
        let budget = ProbeBudget::new(1);
        let permit = budget.try_acquire().unwrap();
        assert!(timeout(Duration::from_secs(1), budget.acquire())
            .await
            .is_err());
        drop(permit);
        assert!(budget.try_acquire().is_ok());
    }
    #[tokio::test(start_paused = true)]
    async fn diagnostics_do_not_queue_ahead_of_production() {
        let budget = PriorityBudget::new();
        let held = budget.production(3).await.unwrap();
        let waiting = budget.production(2);
        tokio::pin!(waiting);
        assert!(timeout(Duration::from_millis(1), &mut waiting).await.is_err());
        assert!(budget.diagnostic(Instant::now() + Duration::from_millis(30)).await.is_none());
        drop(held);
        let production = waiting.await.unwrap();
        assert!(budget.diagnostic(Instant::now() + Duration::from_secs(1)).await.is_some());
        drop(production);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_includes_setup_reserve() {
        let deadline = Instant::now() + Duration::from_secs(3);
        assert!(fits(
            deadline,
            Duration::from_secs(2),
            Duration::from_secs(1)
        ));
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(!fits(
            deadline,
            Duration::from_secs(2),
            Duration::from_secs(1)
        ));
        assert!(!fits(deadline, Duration::MAX, Duration::from_secs(1)));
    }
}
