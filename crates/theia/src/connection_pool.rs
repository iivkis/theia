//! Bounded per-client, per-carrier pool of verified connections.
//! No global cache. A canceled or failed admission retires only its
//! connection; existing tunnels retain their own lease until completion.
use crate::client::ClientError;
use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

const MAX_CONNECTIONS: usize = 4;
const MAX_TUNNELS: usize = 16;
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
    policy: RotationPolicy,
}
struct Entry<C> {
    connection: C,
    route: Option<SocketAddr>,
    split: bool,
    deadline: Instant,
    byte_limit: u64,
    bytes: AtomicU64,
    active: AtomicUsize,
    next_id: AtomicUsize,
    retired: AtomicBool,
    wake_cleanup: Arc<Notify>,
    _permit: OwnedSemaphorePermit,
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
            policy: RotationPolicy::default(),
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

    pub(crate) async fn acquire(
        &self,
        route: Option<SocketAddr>,
        split: bool,
        reusable: bool,
        alive: impl Fn(&C) -> bool,
        create: impl Future<Output = Result<C, ClientError>>,
    ) -> Result<Lease<C>, ClientError> {
        let mut entries = self.entries.lock().await;
        entries.retain(|entry| {
            !entry.retired.load(Ordering::Acquire)
                && entry.route == route
                && Instant::now() < entry.deadline
                && entry.bytes.load(Ordering::Acquire) < entry.byte_limit
                && entry.next_id.load(Ordering::Acquire) <= crate::split_http::MAX_PAIR_IDS as usize
                && alive(&entry.connection)
        });
        if reusable && route.is_some() {
            for entry in entries.iter() {
                if entry.split != split
                    || entry.active.load(Ordering::Acquire) >= MAX_TUNNELS
                    || entry.retired.load(Ordering::Acquire)
                    || Instant::now() >= entry.deadline
                    || entry.bytes.load(Ordering::Acquire) >= entry.byte_limit
                {
                    continue;
                }
                let id = entry.next_id.fetch_add(1, Ordering::AcqRel) as u32;
                entry.active.fetch_add(1, Ordering::AcqRel);
                return Ok(Lease {
                    entry: entry.clone(),
                    id,
                    admitted: false,
                });
            }
        }
        // Count draining connections as well as reusable ones; active
        // leases retain the permit even after their entry is evicted.
        if self.connections.available_permits() == 0 {
            if let Some(index) = entries
                .iter()
                .position(|entry| entry.active.load(Ordering::Acquire) == 0)
            {
                entries.remove(index);
            }
        }
        let permit = self
            .connections
            .clone()
            .try_acquire_owned()
            .map_err(|_| ClientError::Open(crate::protocol::ErrorCode::ResourceLimit))?;
        let (age, byte_limit) = self.policy.sample()?;
        let connection = create.await?;
        let deadline = Instant::now().checked_add(age).ok_or(ClientError::Configuration)?;
        let entry = Arc::new(Entry {
            connection,
            route,
            split,
            deadline,
            byte_limit,
            bytes: AtomicU64::new(0),
            active: AtomicUsize::new(1),
            next_id: AtomicUsize::new(2),
            retired: AtomicBool::new(false),
            wake_cleanup: Arc::new(Notify::new()),
            _permit: permit,
        });
        if reusable && route.is_some() {
            entries.push(entry.clone());
            // No traffic is necessary to clean up an idle expired carrier.
            // Keep only weak references across the timer; dropping the
            // profile or evicting a connection cannot extend its lifetime.
            let weak_entries = Arc::downgrade(&self.entries);
            let weak_entry = Arc::downgrade(&entry);
            let wake_cleanup = entry.wake_cleanup.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => {},
                    _ = wake_cleanup.notified() => {},
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
            .acquire(route, false, true, |_| true, async { Ok(1) })
            .await
            .unwrap();
        active.admitted();
        let mut idle = pool
            .acquire(route, true, true, |_| true, async { Ok(2) })
            .await
            .unwrap();
        idle.admitted();
        drop(idle);
        tokio::task::yield_now().await;
        tokio::time::advance(MAX_REUSE_AGE + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(pool.entries.lock().await.is_empty());
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS - 1);
        assert_eq!(*active.connection(), 1);
        let mut fresh = pool
            .acquire(route, false, true, |_| true, async { Ok(3) })
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
        let mut first = pool.acquire(route, false, true, |_| true, async { Ok(1) }).await.unwrap();
        first.admitted();
        let mut second = pool.acquire(route, false, true, |_| true, async { Ok(2) }).await.unwrap();
        second.admitted();
        assert!(first.shares_connection(&second));
        first.record_data(4);
        second.record_data(5);
        assert!(!first.entry.retired.load(Ordering::Acquire));
        first.record_data(1);
        assert!(first.entry.retired.load(Ordering::Acquire));
        second.record_data(usize::MAX);
        assert_eq!(first.entry.bytes.load(Ordering::Acquire), u64::MAX);
        let mut fresh = pool.acquire(route, false, true, |_| true, async { Ok(3) }).await.unwrap();
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
    async fn scope_retirement_and_capacity_keep_live_leases() {
        let pool = Pool::default();
        let route = Some("127.0.0.1:0".parse().unwrap());
        let mut a = pool
            .acquire(route, true, true, |_| true, async { Ok(1) })
            .await
            .unwrap();
        a.admitted();
        let b = pool
            .acquire(route, true, true, |_| true, async { Ok(2) })
            .await
            .unwrap();
        assert_eq!(
            (*a.connection(), *b.connection(), a.id(), b.id()),
            (1, 1, 1, 2)
        );
        drop(b);
        let mut c = pool
            .acquire(route, true, true, |_| true, async { Ok(3) })
            .await
            .unwrap();
        c.admitted();
        assert_eq!((*a.connection(), *c.connection()), (1, 3));
        let mut d = pool
            .acquire(route, false, true, |_| true, async { Ok(4) })
            .await
            .unwrap();
        d.admitted();
        assert_eq!(*d.connection(), 4);
        let other = Some("127.0.0.2:0".parse().unwrap());
        let e = pool
            .acquire(other, true, true, |_| true, async { Ok(5) })
            .await
            .unwrap();
        assert_eq!(*e.connection(), 5);
        assert!(matches!(
            pool.acquire(other, false, true, |_| true, async { Ok(6) })
                .await,
            Err(ClientError::Open(crate::protocol::ErrorCode::ResourceLimit))
        ));
        drop(a);
        assert!(pool
            .acquire(other, false, true, |_| true, async { Ok(6) })
            .await
            .is_ok());
    }
}
