//! Bounded per-client, per-carrier pool of verified connections.
//! No global cache. A canceled or failed admission retires only its
//! connection; existing tunnels retain their own lease until completion.
use crate::client::ClientError;
use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}},
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

const MAX_CONNECTIONS: usize = 4;
const MAX_TUNNELS: usize = 16;
// Temporary runtime ceiling, not a descriptor-controlled rotation policy.
// The old connection is never aborted merely because it reaches this age.
const MAX_REUSE_AGE: Duration = Duration::from_secs(20);

pub(crate) struct Pool<C> {
    entries: Mutex<Vec<Arc<Entry<C>>>>,
    connections: Arc<Semaphore>,
}
struct Entry<C> {
    connection: C,
    route: Option<SocketAddr>,
    split: bool,
    created: Instant,
    active: AtomicUsize,
    next_id: AtomicUsize,
    retired: AtomicBool,
    _permit: OwnedSemaphorePermit,
}
pub(crate) struct Lease<C> {
    entry: Arc<Entry<C>>,
    id: u32,
    admitted: bool,
}
impl<C> Lease<C> {
    pub(crate) fn connection(&self) -> &C { &self.entry.connection }
    pub(crate) fn id(&self) -> u32 { self.id }
    pub(crate) fn admitted(&mut self) { self.admitted = true; }
    pub(crate) fn shares_connection(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.entry, &other.entry)
    }
}
impl<C> Drop for Lease<C> {
    fn drop(&mut self) {
        if !self.admitted {
            self.entry.retired.store(true, Ordering::Release);
        }
        self.entry.active.fetch_sub(1, Ordering::AcqRel);
    }
}
impl<C> Default for Pool<C> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }
}
impl<C> Pool<C> {
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
                && entry.created.elapsed() < MAX_REUSE_AGE
                && entry.next_id.load(Ordering::Acquire) <= crate::split_http::MAX_PAIR_IDS as usize
                && alive(&entry.connection)
        });
        if reusable && route.is_some() {
            for entry in entries.iter() {
                if entry.split != split || entry.active.load(Ordering::Acquire) >= MAX_TUNNELS
                    || entry.retired.load(Ordering::Acquire) {
                    continue;
                }
                let id = entry.next_id.fetch_add(1, Ordering::AcqRel) as u32;
                entry.active.fetch_add(1, Ordering::AcqRel);
                return Ok(Lease { entry: entry.clone(), id, admitted: false });
            }
        }
        // Count draining connections as well as reusable ones; active
        // leases retain the permit even after their entry is evicted.
        if self.connections.available_permits() == 0 {
            if let Some(index) = entries.iter().position(|entry| entry.active.load(Ordering::Acquire) == 0) {
                entries.remove(index);
            }
        }
        let permit = self.connections.clone().try_acquire_owned()
            .map_err(|_| ClientError::Open(crate::protocol::ErrorCode::ResourceLimit))?;
        let connection = create.await?;
        let entry = Arc::new(Entry {
            connection, route, split, created: Instant::now(),
            active: AtomicUsize::new(1), next_id: AtomicUsize::new(2),
            retired: AtomicBool::new(false), _permit: permit,
        });
        if reusable && route.is_some() {
            entries.push(entry.clone());
        }
        Ok(Lease { entry, id: 1, admitted: false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn scope_retirement_and_capacity_keep_live_leases() {
        let pool = Pool::default();
        let route = Some("127.0.0.1:0".parse().unwrap());
        let mut a = pool.acquire(route, true, true, |_| true, async { Ok(1) }).await.unwrap();
        a.admitted();
        let b = pool.acquire(route, true, true, |_| true, async { Ok(2) }).await.unwrap();
        assert_eq!((*a.connection(), *b.connection(), a.id(), b.id()), (1, 1, 1, 2));
        drop(b);
        let mut c = pool.acquire(route, true, true, |_| true, async { Ok(3) }).await.unwrap();
        c.admitted();
        assert_eq!((*a.connection(), *c.connection()), (1, 3));
        let mut d = pool.acquire(route, false, true, |_| true, async { Ok(4) }).await.unwrap();
        d.admitted();
        assert_eq!(*d.connection(), 4);
        let other = Some("127.0.0.2:0".parse().unwrap());
        let e = pool.acquire(other, true, true, |_| true, async { Ok(5) }).await.unwrap();
        assert_eq!(*e.connection(), 5);
        assert!(matches!(pool.acquire(other, false, true, |_| true, async { Ok(6) }).await, Err(ClientError::Open(crate::protocol::ErrorCode::ResourceLimit))));
        drop(a);
        assert!(pool.acquire(other, false, true, |_| true, async { Ok(6) }).await.is_ok());
    }
}
