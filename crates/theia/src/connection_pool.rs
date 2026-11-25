//! Bounded per-client, per-carrier pool of verified connections.
//! No global cache. A canceled or failed admission retires only its
//! connection; existing tunnels retain their own lease until completion.
use crate::client::ClientError;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::{watch, Mutex, Notify, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

const MAX_CONNECTIONS: usize = 4;
const MAX_TUNNELS: usize = 16;
const MAX_PROFILE_CONNECTIONS: usize = 8;

pub(crate) fn profile_budget() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(MAX_PROFILE_CONNECTIONS))
}
// Own-TLS defaults are provisional local policy. REALITY derives its
// bounds from the verified descriptor of this immutable client generation.
const MAX_REUSE_AGE: Duration = Duration::from_secs(20);
const MIN_REUSE_AGE_S: u64 = 15;
const MIN_REUSE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_REUSE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
struct RotationPolicy {
    age_min: u64,
    age_max: u64,
    bytes_min: u64,
    bytes_max: u64,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            age_min: MIN_REUSE_AGE_S,
            age_max: MAX_REUSE_AGE.as_secs(),
            bytes_min: MIN_REUSE_BYTES,
            bytes_max: MAX_REUSE_BYTES,
        }
    }
}

// Inclusive, unbiased selection; reject bad ranges or failed entropy rather
// than silently overriding the verified policy. Bounded retries avoid a
// theoretical unbounded loop even if the random source is defective.
fn random_inclusive(min: u64, max: u64) -> Result<u64, ClientError> {
    use ring::rand::{SecureRandom, SystemRandom};
    if min == 0 || max < min {
        return Err(ClientError::Configuration);
    }
    if min == max {
        return Ok(min);
    }
    let span = max - min + 1;
    let threshold = span.wrapping_neg() % span;
    let rng = SystemRandom::new();
    for _ in 0..64 {
        let mut bytes = [0u8; 8];
        rng.fill(&mut bytes).map_err(|_| ClientError::Configuration)?;
        let n = u64::from_ne_bytes(bytes);
        if n >= threshold {
            return Ok(min + n % span);
        }
    }
    Err(ClientError::Configuration)
}

impl RotationPolicy {
    fn sample(self) -> Result<(Duration, u64), ClientError> {
        Ok((
            Duration::from_secs(random_inclusive(self.age_min, self.age_max)?),
            random_inclusive(self.bytes_min, self.bytes_max)?,
        ))
    }
}

pub(crate) struct Pool<C> {
    entries: Arc<Mutex<Vec<Arc<Entry<C>>>>>,
    connections: Arc<Semaphore>,
    profile: Arc<Semaphore>,
    dial: Mutex<()>,
    policy: RotationPolicy,
    lifetime: watch::Sender<()>,
}
struct Entry<C> {
    connection: C,
    route: Option<crate::network_scope::Scope>,
    deadline: Instant,
    byte_limit: u64,
    bytes: AtomicU64,
    active: AtomicUsize,
    next_id: AtomicUsize,
    retired: AtomicBool,
    wake_cleanup: Arc<Notify>,
    _permit: OwnedSemaphorePermit,
    _profile_permit: OwnedSemaphorePermit,
}
impl<C> Entry<C> {
    fn retire(&self) {
        if !self.retired.swap(true, Ordering::AcqRel) {
            self.wake_cleanup.notify_one();
        }
    }
}
pub(crate) struct Lease<C> {
    entry: Arc<Entry<C>>,
    id: u32,
    admitted: bool,
}
impl<C> Lease<C> {
    pub(crate) fn connection(&self) -> &C {
        &self.entry.connection
    }
    pub(crate) fn id(&self) -> u32 {
        self.id
    }
    pub(crate) fn retire(&self) {
        self.entry.retire();
    }
    pub(crate) fn admitted(&mut self) {
        self.admitted = true;
    }
    pub(crate) fn shares_connection(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.entry, &other.entry)
    }

    /// Count successfully relayed DATA in both directions, shared by all
    /// leases. This is a rotation trigger, never a tunnel termination limit.
    pub(crate) fn record_data(&self, size: usize) {
        let increment = size as u64;
        let prior = self.entry.bytes.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |old| Some(old.saturating_add(increment)),
        ).unwrap_or_else(|old| old);
        if prior.saturating_add(increment) >= self.entry.byte_limit {
            self.entry.retire();
        }
    }
}
impl<C> Drop for Lease<C> {
    fn drop(&mut self) {
        if !self.admitted {
            self.entry.retire();
        }
        self.entry.active.fetch_sub(1, Ordering::AcqRel);
    }
}
impl<C> Default for Pool<C> {
    fn default() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            profile: profile_budget(),
            dial: Mutex::new(()),
            policy: RotationPolicy::default(),
            lifetime: watch::channel(()).0,
        }
    }
}
impl<C: Send + Sync + 'static> Pool<C> {
    pub(crate) fn with_rotation(rotation: &crate::descriptor::Rotation) -> Self {
        Self {
            policy: RotationPolicy {
                age_min: u64::from(rotation.lifetime_min_s),
                age_max: u64::from(rotation.lifetime_max_s),
                bytes_min: rotation.volume_min_bytes,
                bytes_max: rotation.volume_max_bytes,
            },
            ..Self::default()
        }
    }

    /// Set before publishing the carrier. A generation never changes its
    /// own budget; live leases keep a profile permit across replacement.
    pub(crate) fn set_profile_budget(&mut self, budget: Arc<Semaphore>) {
        self.profile = budget;
    }

    pub(crate) fn profile_budget(&self) -> Arc<Semaphore> {
        self.profile.clone()
    }

    fn reuse(
        entries: &mut Vec<Arc<Entry<C>>>,
        route: Option<crate::network_scope::Scope>,
        reusable: bool,
        alive: &impl Fn(&C) -> bool,
    ) -> Option<Lease<C>> {
        entries.retain(|entry| {
            let retain = !entry.retired.load(Ordering::Acquire)
                && entry.route == route
                && Instant::now() < entry.deadline
                && entry.bytes.load(Ordering::Acquire) < entry.byte_limit
                && entry.next_id.load(Ordering::Acquire) <= crate::split_http::MAX_PAIR_IDS as usize
                && alive(&entry.connection);
            if !retain {
                entry.retire();
            }
            retain
        });
        if !reusable || route.is_none() {
            return None;
        }
        for entry in entries.iter() {
            if entry.active.load(Ordering::Acquire) >= MAX_TUNNELS
                || entry.retired.load(Ordering::Acquire)
                || Instant::now() >= entry.deadline
                || entry.bytes.load(Ordering::Acquire) >= entry.byte_limit
            {
                continue;
            }
            // The same connection owns a single namespace for both XHTTP
            // modes. A stream-one admission burns an ID as well; no reuse
            // of a pair ID is possible even after cancellation or expiry.
            let id = entry.next_id.fetch_add(1, Ordering::AcqRel) as u32;
            entry.active.fetch_add(1, Ordering::AcqRel);
            return Some(Lease { entry: entry.clone(), id, admitted: false });
        }
        None
    }

    pub(crate) async fn acquire(
        &self,
        route: Option<crate::network_scope::Scope>,
        reusable: bool,
        alive: impl Fn(&C) -> bool,
        create: impl Future<Output = Result<C, ClientError>>,
    ) -> Result<Lease<C>, ClientError> {
        {
            let mut entries = self.entries.lock().await;
            if let Some(lease) = Self::reuse(&mut entries, route, reusable, &alive) {
                return Ok(lease);
            }
        }
        // Only connection creation is single-flight. A slow handshake
        // cannot hold the entries lock or block reuse/retirement of a
        // different already verified connection.
        let _dial = self.dial.lock().await;
        let (permit, profile_permit) = {
            let mut entries = self.entries.lock().await;
            if let Some(lease) = Self::reuse(&mut entries, route, reusable, &alive) {
                return Ok(lease);
            }
            if self.connections.available_permits() == 0 || self.profile.available_permits() == 0 {
                if let Some(index) = entries.iter().position(|entry| entry.active.load(Ordering::Acquire) == 0) {
                    entries.remove(index).retire();
                }
            }
            let limit = || ClientError::Open(crate::protocol::ErrorCode::ResourceLimit);
            let permit = self.connections.clone().try_acquire_owned().map_err(|_| limit())?;
            let profile_permit = self.profile.clone().try_acquire_owned().map_err(|_| limit())?;
            (permit, profile_permit)
        };
        let (age, byte_limit) = self.policy.sample()?;
        let connection = create.await?;
        let deadline = Instant::now().checked_add(age).ok_or(ClientError::Configuration)?;
        let entry = Arc::new(Entry {
            connection,
            route,
            deadline,
            byte_limit,
            bytes: AtomicU64::new(0),
            active: AtomicUsize::new(1),
            next_id: AtomicUsize::new(2),
            retired: AtomicBool::new(false),
            wake_cleanup: Arc::new(Notify::new()),
            _permit: permit,
            _profile_permit: profile_permit,
        });
        if reusable && route.is_some() {
            self.entries.lock().await.push(entry.clone());
            // No traffic is necessary to clean up an idle expired carrier.
            // Keep only weak references across the timer; dropping the
            // profile or evicting a connection cannot extend its lifetime.
            let weak_entries = Arc::downgrade(&self.entries);
            let weak_entry = Arc::downgrade(&entry);
            let wake_cleanup = entry.wake_cleanup.clone();
            let mut lifetime = self.lifetime.subscribe();
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => {},
                    _ = wake_cleanup.notified() => {},
                    _ = lifetime.changed() => {},
                }
                if let (Some(entries), Some(expired)) =
                    (weak_entries.upgrade(), weak_entry.upgrade())
                {
                    expired.retire();
                    entries
                        .lock()
                        .await
                        .retain(|candidate| !Arc::ptr_eq(candidate, &expired));
                }
            });
        }
        Ok(Lease {
            entry,
            id: 1,
            admitted: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn expiry_releases_idle_connection_and_drains_live_lease() {
        let pool = Pool::default();
        let route = Some("127.0.0.1:0".parse().unwrap());
        let mut active = pool
            .acquire(route, true, |_| true, async { Ok(1) })
            .await
            .unwrap();
        active.admitted();
        let mut busy = Vec::new();
        for _ in 1..MAX_TUNNELS {
            let mut lease = pool.acquire(route, true, |_| true, async { Ok(1) }).await.unwrap();
            lease.admitted();
            busy.push(lease);
        }
        let mut idle = pool
            .acquire(route, true, |_| true, async { Ok(2) })
            .await
            .unwrap();
        assert!(!active.shares_connection(&idle));
        drop(busy);
        idle.admitted();
        drop(idle);
        tokio::task::yield_now().await;
        tokio::time::advance(MAX_REUSE_AGE + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(pool.entries.lock().await.is_empty());
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS - 1);
        assert_eq!(*active.connection(), 1);
        let mut fresh = pool
            .acquire(route, true, |_| true, async { Ok(3) })
            .await
            .unwrap();
        fresh.admitted();
        assert_eq!(*fresh.connection(), 3);
        assert!(!active.shares_connection(&fresh));
        drop(active);
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS - 1);
    }

    #[test]
    fn rotation_ranges_are_bounded_and_invalid_ranges_fail_closed() {
        assert_eq!(random_inclusive(4, 4).unwrap(), 4);
        assert!(random_inclusive(0, 4).is_err());
        assert!(random_inclusive(5, 4).is_err());
        for _ in 0..64 {
            assert!((9..=13).contains(&random_inclusive(9, 13).unwrap()));
            assert!(random_inclusive(1, u64::MAX).unwrap() > 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn descriptor_volume_rotation_drains_shared_live_leases() {
        let pool = Pool::with_rotation(&crate::descriptor::Rotation {
            lifetime_min_s: 60,
            lifetime_max_s: 60,
            volume_min_bytes: 10,
            volume_max_bytes: 10,
        });
        let route = Some("127.0.0.1:0".parse().unwrap());
        let mut first = pool.acquire(route, true, |_| true, async { Ok(1) }).await.unwrap();
        first.admitted();
        let mut second = pool.acquire(route, true, |_| true, async { Ok(2) }).await.unwrap();
        second.admitted();
        assert!(first.shares_connection(&second));
        first.record_data(4);
        second.record_data(5);
        assert!(!first.entry.retired.load(Ordering::Acquire));
        first.record_data(1);
        assert!(first.entry.retired.load(Ordering::Acquire));
        second.record_data(usize::MAX);
        assert_eq!(first.entry.bytes.load(Ordering::Acquire), u64::MAX);
        let mut fresh = pool.acquire(route, true, |_| true, async { Ok(3) }).await.unwrap();
        fresh.admitted();
        assert!(!first.shares_connection(&fresh));
        assert_eq!(*first.connection(), 1);
        assert_eq!(*second.connection(), 1);
        assert_eq!(*fresh.connection(), 3);
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS - 2);
        drop(first);
        drop(second);
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS - 1);
        drop(fresh);
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert!(pool.entries.lock().await.is_empty());
    }

    #[tokio::test]
    async fn same_source_network_change_retires_pool_without_cutting_tunnels() {
        use crate::network_scope::Scope;
        let pool = Pool::default();
        let source = "127.0.0.1:0".parse().unwrap();
        let a = Some(Scope::fixture(source, 1));
        let b = Some(Scope::fixture(source, 2));
        let mut old = pool.acquire(a, true, |_| true, async { Ok(1) }).await.unwrap();
        old.admitted();
        let mut fresh = pool.acquire(b, true, |_| true, async { Ok(2) }).await.unwrap();
        fresh.admitted();
        assert!(old.entry.retired.load(Ordering::Acquire));
        assert_eq!(*old.connection(), 1);
        assert_eq!(*fresh.connection(), 2);
        assert!(!old.shares_connection(&fresh));
    }

    #[tokio::test]
    async fn profile_budget_is_shared_across_carriers_and_draining_generations() {
        let budget = profile_budget();
        let mut h2 = Pool::default();
        let mut h3 = Pool::default();
        let mut next = Pool::default();
        h2.set_profile_budget(budget.clone());
        h3.set_profile_budget(budget.clone());
        next.set_profile_budget(budget.clone());
        let mut leases = Vec::new();
        for pool in [&h2, &h3] {
            for _ in 0..MAX_CONNECTIONS {
                let mut lease = pool.acquire(None, false, |_| true, async { Ok(7) }).await.unwrap();
                lease.admitted();
                leases.push(lease);
            }
        }
        assert_eq!(budget.available_permits(), 0);
        assert!(matches!(next.acquire(None, false, |_| true, async { Ok(8) }).await,
            Err(ClientError::Open(crate::protocol::ErrorCode::ResourceLimit))));
        drop(h2);
        drop(h3);
        assert_eq!(budget.available_permits(), 0);
        drop(leases.pop());
        let fresh = next.acquire(None, false, |_| true, async { Ok(8) }).await.unwrap();
        assert_eq!(*fresh.connection(), 8);
    }

    #[tokio::test]
    async fn scope_retirement_and_capacity_keep_live_leases() {
        let pool = Pool::default();
        let route = Some("127.0.0.1:0".parse().unwrap());
        let mut a = pool
            .acquire(route, true, |_| true, async { Ok(1) })
            .await
            .unwrap();
        a.admitted();
        let b = pool
            .acquire(route, true, |_| true, async { Ok(2) })
            .await
            .unwrap();
        assert_eq!(
            (*a.connection(), *b.connection(), a.id(), b.id()),
            (1, 1, 1, 2)
        );
        drop(b);
        let mut c = pool
            .acquire(route, true, |_| true, async { Ok(3) })
            .await
            .unwrap();
        c.admitted();
        assert_eq!((*a.connection(), *c.connection()), (1, 3));
        let mut d = pool
            .acquire(route, false, |_| true, async { Ok(4) })
            .await
            .unwrap();
        d.admitted();
        assert_eq!(*d.connection(), 4);
        let other = Some("127.0.0.2:0".parse().unwrap());
        let e = pool
            .acquire(other, true, |_| true, async { Ok(5) })
            .await
            .unwrap();
        assert_eq!(*e.connection(), 5);
        assert!(matches!(
            pool.acquire(other, false, |_| true, async { Ok(6) })
                .await,
            Err(ClientError::Open(crate::protocol::ErrorCode::ResourceLimit))
        ));
        drop(a);
        assert!(pool
            .acquire(other, false, |_| true, async { Ok(6) })
            .await
            .is_ok());
    }
}
