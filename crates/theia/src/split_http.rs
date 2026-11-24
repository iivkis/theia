//! Theia stream-up: two HTTP streams on the same verified transport connection.
//! This is a SmartTheia carrier, not the Xray XHTTP/VLESS wire protocol.
use crate::client::ClientError;
use http::{header, HeaderValue, Method, Request, StatusCode, Uri};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::{sync::oneshot, time::timeout};

pub(crate) const UPLOAD_PATH: &str = "/v1/stream-up/upload";
pub(crate) const DOWNLOAD_PATH: &str = "/v1/stream-up/download";
const PAIR_TIMEOUT: Duration = Duration::from_secs(10);
/// A bounded connection lifetime namespace. IDs cannot be recycled, even
/// after failed or canceled pairs. Rotate the connection before exhaustion.
pub(crate) const MAX_PAIR_IDS: u32 = 1024;
const MAX_PENDING_PAIRS: usize = 16;
pub(crate) const PAIR_HEADER: &str = "theia-pair-id";

pub(crate) fn pair_id<T>(request: &Request<T>) -> Option<u32> {
    let headers = request.headers();
    if headers.get_all(PAIR_HEADER).iter().count() != 1 {
        return None;
    }
    let raw = headers.get(PAIR_HEADER)?.to_str().ok()?;
    let id = raw.parse::<u32>().ok()?;
    (id > 0 && id <= MAX_PAIR_IDS && raw == id.to_string()).then_some(id)
}
pub(crate) const HELLO_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Only an admitted stream-one with no response frame bytes may be retried.
/// This state is never set by an HTTP, TLS, protocol, OPEN or write error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum HelloOutcome {
    #[default]
    Pending,
    Silent,
    Acked,
}

#[derive(Clone, Copy)]
pub(crate) struct ModeTicket {
    generation: u64,
    pub(crate) stream_up: bool,
}

#[derive(Default)]
struct ModeCache {
    route: Option<SocketAddr>,
    generation: u64,
    expires: Option<Instant>,
}

impl ModeCache {
    fn observe(&mut self, route: Option<SocketAddr>, now: Instant) -> ModeTicket {
        if route.is_none()
            || route != self.route
            || self.expires.is_some_and(|expires| now >= expires)
        {
            self.route = route;
            self.generation = self.generation.wrapping_add(1);
            self.expires = None;
        }
        ModeTicket {
            generation: self.generation,
            stream_up: self.expires.is_some(),
        }
    }

    fn current(&self, ticket: ModeTicket) -> bool {
        self.route.is_some() && self.generation == ticket.generation
    }

    fn remember(&mut self, ticket: ModeTicket, now: Instant, ttl: Duration) {
        if self.current(ticket) && self.expires.is_none() && !ttl.is_zero() {
            self.expires = now.checked_add(ttl);
        }
    }
}

/// One bounded mode decision per immutable client profile and carrier.
/// It is scoped to its pinned endpoint and observed OS source route.
pub(crate) struct AutoMode {
    remote: SocketAddr,
    ttl: Duration,
    cache: Mutex<ModeCache>,
}

impl AutoMode {
    pub(crate) fn new(remote: SocketAddr, ttl: Duration) -> Self {
        Self {
            remote,
            ttl,
            cache: Mutex::new(ModeCache::default()),
        }
    }

    pub(crate) fn select(&self) -> Result<ModeTicket, ClientError> {
        let mut cache = self.cache.lock().map_err(|_| ClientError::Configuration)?;
        Ok(cache.observe(
            crate::local_proxy::route_source(self.remote),
            Instant::now(),
        ))
    }

    pub(crate) fn current(&self, ticket: ModeTicket) -> Result<bool, ClientError> {
        let mut cache = self.cache.lock().map_err(|_| ClientError::Configuration)?;
        cache.observe(
            crate::local_proxy::route_source(self.remote),
            Instant::now(),
        );
        Ok(cache.current(ticket))
    }

    pub(crate) fn remember(&self, ticket: ModeTicket) -> Result<(), ClientError> {
        let mut cache = self.cache.lock().map_err(|_| ClientError::Configuration)?;
        let now = Instant::now();
        cache.observe(crate::local_proxy::route_source(self.remote), now);
        cache.remember(ticket, now, self.ttl);
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Leg {
    Upload,
    Download,
}

pub(crate) fn leg<T>(request: &Request<T>) -> Option<Leg> {
    if request.uri().query().is_some()
        || request
            .headers()
            .get_all(header::CONTENT_TYPE)
            .iter()
            .count()
            != 1
        || request
            .headers()
            .get(header::CONTENT_TYPE)
            .map(HeaderValue::as_bytes)
            != Some(b"application/octet-stream".as_slice())
    {
        return None;
    }
    if request.method() == Method::POST && request.uri().path() == UPLOAD_PATH {
        Some(Leg::Upload)
    } else if request.method() == Method::GET && request.uri().path() == DOWNLOAD_PATH {
        Some(Leg::Download)
    } else {
        None
    }
}

pub(crate) fn request(
    uri: &Uri,
    leg: Leg,
    authorization: &HeaderValue,
    id: u32,
) -> Result<Request<()>, ClientError> {
    if !(1..=MAX_PAIR_IDS).contains(&id) {
        return Err(ClientError::Configuration);
    }
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(match leg {
        Leg::Upload => http::uri::PathAndQuery::from_static(UPLOAD_PATH),
        Leg::Download => http::uri::PathAndQuery::from_static(DOWNLOAD_PATH),
    });
    Request::builder()
        .method(match leg {
            Leg::Upload => Method::POST,
            Leg::Download => Method::GET,
        })
        .uri(Uri::from_parts(parts).map_err(|_| ClientError::Configuration)?)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::AUTHORIZATION, authorization.clone())
        .header(PAIR_HEADER, id.to_string())
        .body(())
        .map_err(|_| ClientError::Configuration)
}

pub(crate) fn check_status(status: StatusCode) -> Result<(), ClientError> {
    match status {
        StatusCode::OK => Ok(()),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(ClientError::Unauthorized),
        other => Err(ClientError::Rejected(other.as_u16())),
    }
}

enum State<T> {
    Waiting(Leg, oneshot::Sender<T>),
    Used,
}

/// Registry owned by exactly one verified HTTP connection. The first task
/// owns its leg; the second transfers ownership once. Used IDs remain
/// tombstones in a strictly bounded namespace, preventing late-leg reuse.
pub(crate) struct Pair<T> {
    state: Mutex<HashMap<u32, State<T>>>,
}

/// Cancellation and timeout both burn the ID and drop the waiting sender.
struct Waiting<'a, T> {
    pair: &'a Pair<T>,
    id: u32,
}

impl<T> Drop for Waiting<'_, T> {
    fn drop(&mut self) {
        if let Ok(mut states) = self.pair.state.lock() {
            if let Some(state) = states.get_mut(&self.id) {
                *state = State::Used;
            }
        }
    }
}

impl<T> Pair<T> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn join(&self, id: u32, leg: Leg, item: T) -> Option<(T, T)> {
        if !(1..=MAX_PAIR_IDS).contains(&id) {
            return None;
        }
        let receiver = {
            let mut states = self.state.lock().ok()?;
            if let Some(state) = states.get_mut(&id) {
                if let State::Waiting(other, tx) = std::mem::replace(state, State::Used) {
                    if other != leg {
                        let _ = tx.send(item);
                    }
                }
                return None;
            }
            if states.values().filter(|state| matches!(state, State::Waiting(..))).count()
                >= MAX_PENDING_PAIRS
            {
                // Burn rejected IDs too, so a late leg cannot be reassociated.
                states.insert(id, State::Used);
                return None;
            }
            let (tx, rx) = oneshot::channel();
            states.insert(id, State::Waiting(leg, tx));
            rx
        };
        let _waiting = Waiting { pair: self, id };
        let other = timeout(PAIR_TIMEOUT, receiver).await.ok()?.ok()?;
        Some(match leg {
            Leg::Upload => (item, other),
            Leg::Download => (other, item),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_up_only_accepts_current_v1_routes() {
        for (method, path, expected) in [
            (Method::POST, UPLOAD_PATH, Some(Leg::Upload)),
            (Method::GET, DOWNLOAD_PATH, Some(Leg::Download)),
            (Method::POST, "/v2/stream-up/upload", None),
            (Method::GET, "/v2/stream-up/download", None),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(())
                .unwrap();
            assert!(leg(&req) == expected);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn both_orders_pair_once_and_missing_half_expires() {
        for first in [Leg::Upload, Leg::Download] {
            let pair = Pair::new();
            let second = if first == Leg::Upload {
                Leg::Download
            } else {
                Leg::Upload
            };
            let (a, b) = tokio::join!(
                pair.join(1, first, first == Leg::Upload),
                pair.join(1, second, second == Leg::Upload)
            );
            assert_eq!(a, Some((true, false)));
            assert_eq!(b, None);
            assert_eq!(pair.join(1, second, false).await, None);
        }
        let pair = Pair::new();
        assert_eq!(pair.join(1, Leg::Upload, 1).await, None);
        assert_eq!(pair.join(1, Leg::Download, 2).await, None);
    }

    #[test]
    fn pair_id_is_canonical_and_single() {
        for (value, expected) in [("1", Some(1)), ("1024", Some(1024)), ("0", None), ("01", None), ("+1", None), ("1025", None)] {
            let mut req = Request::builder().header(PAIR_HEADER, value).body(()).unwrap();
            assert_eq!(pair_id(&req), expected);
            req.headers_mut().append(PAIR_HEADER, HeaderValue::from_static("1"));
            assert_eq!(pair_id(&req), None);
        }
        assert_eq!(pair_id(&Request::new(())), None);
    }

    #[tokio::test(start_paused = true)]
    async fn independent_pairs_and_cancelled_ids_cannot_reassociate() {
        let pair = Pair::new();
        let (a, b, c, d) = tokio::join!(
            pair.join(1, Leg::Upload, 10),
            pair.join(2, Leg::Download, 21),
            pair.join(2, Leg::Upload, 20),
            pair.join(1, Leg::Download, 11),
        );
        assert_eq!((a, b, c, d), (Some((10, 11)), Some((20, 21)), None, None));
        let mut pending = Box::pin(pair.join(3, Leg::Upload, 30));
        tokio::select! {
            biased;
            _ = &mut pending => panic!("unpaired leg must wait"),
            _ = tokio::task::yield_now() => {}
        }
        drop(pending);
        assert_eq!(pair.join(3, Leg::Download, 31).await, None);
        assert_eq!(pair.join(1, Leg::Upload, 99).await, None);
        assert_eq!(pair.join(MAX_PAIR_IDS + 1, Leg::Upload, 99).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_limit_burns_rejected_id_and_releases_on_cancel() {
        let registry = Pair::new();
        let mut pending = Vec::new();
        for id in 1..=MAX_PENDING_PAIRS as u32 {
            let mut wait = Box::pin(registry.join(id, Leg::Upload, id));
            tokio::select! {
                biased;
                _ = &mut wait => panic!("unpaired leg must wait"),
                _ = tokio::task::yield_now() => {}
            }
            pending.push(wait);
        }
        let overflow = MAX_PENDING_PAIRS as u32 + 1;
        assert_eq!(registry.join(overflow, Leg::Upload, overflow).await, None);
        pending.clear();
        assert_eq!(registry.join(overflow, Leg::Download, overflow).await, None);
        let fresh = overflow + 1;
        let (a, b) = tokio::join!(
            registry.join(fresh, Leg::Upload, 1),
            registry.join(fresh, Leg::Download, 2),
        );
        assert_eq!((a, b), (Some((1, 2)), None));
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_or_other_connection_never_pairs() {
        let pair = Pair::new();
        let (a, b) = tokio::join!(pair.join(1, Leg::Upload, 1), pair.join(1, Leg::Upload, 2));
        assert_eq!((a, b), (None, None));
        assert_eq!(pair.join(1, Leg::Download, 3).await, None);
        let left = Pair::new();
        let right = Pair::new();
        let (a, b) = tokio::join!(left.join(1, Leg::Upload, 1), right.join(1, Leg::Download, 2));
        assert_eq!((a, b), (None, None));
    }
}

#[cfg(test)]
mod auto_tests {
    use super::*;

    #[test]
    fn mode_cache_expires_and_rejects_stale_or_unknown_routes() {
        let a = Some("192.0.2.1:0".parse().unwrap());
        let b = Some("198.51.100.1:0".parse().unwrap());
        let now = Instant::now();
        let ttl = Duration::from_secs(30);
        let mut cache = ModeCache::default();
        let ticket = cache.observe(a, now);
        assert!(!ticket.stream_up);
        cache.remember(ticket, now, ttl);
        assert!(cache.observe(a, now).stream_up);
        cache.remember(ticket, now + Duration::from_secs(20), ttl);
        assert!(!cache.observe(a, now + ttl).stream_up);
        cache.remember(ticket, now + ttl, ttl);
        assert!(!cache.observe(a, now + ttl).stream_up);
        let ticket = cache.observe(a, now + ttl);
        assert!(cache.current(ticket));
        cache.observe(b, now + ttl);
        assert!(!cache.current(ticket));
        cache.remember(ticket, now + ttl, ttl);
        assert!(!cache.observe(b, now + ttl).stream_up);
        let unknown = cache.observe(None, now + ttl);
        assert!(!cache.current(unknown));
        cache.remember(unknown, now + ttl, ttl);
        assert!(!cache.observe(None, now + ttl).stream_up);
    }
}
