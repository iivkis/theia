//! Theia stream-up: two HTTP streams on the same verified transport connection.
//! This is a SmartTheia carrier, not the Xray XHTTP/VLESS wire protocol.
use crate::client::ClientError;
use http::{header, HeaderValue, Method, Request, StatusCode, Uri};
use std::{
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::{sync::oneshot, time::timeout};

pub(crate) const UPLOAD_PATH: &str = "/v1/stream-up/upload";
pub(crate) const DOWNLOAD_PATH: &str = "/v1/stream-up/download";
const PAIR_TIMEOUT: Duration = Duration::from_secs(10);
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
) -> Result<Request<()>, ClientError> {
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
    Empty,
    Waiting(Leg, oneshot::Sender<T>),
    Used,
}

/// One pair per connection. A half never enters a global session map, and
/// the waiting task owns its own stream. No cross-connection association,
/// unbounded queues or reusable IDs. Same-leg duplication burns the slot.
pub(crate) struct Pair<T> {
    state: Mutex<State<T>>,
}

impl<T> Pair<T> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State::Empty),
        }
    }

    pub(crate) async fn join(&self, leg: Leg, item: T) -> Option<(T, T)> {
        let receiver = {
            let mut state = self.state.lock().ok()?;
            match std::mem::replace(&mut *state, State::Used) {
                State::Empty => {
                    let (tx, rx) = oneshot::channel();
                    *state = State::Waiting(leg, tx);
                    rx
                }
                State::Waiting(other, tx) if other != leg => {
                    // The first task will own both streams, or dropping
                    // the failed send releases the late-arriving stream.
                    let _ = tx.send(item);
                    return None;
                }
                _ => return None,
            }
        };
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
                pair.join(first, first == Leg::Upload),
                pair.join(second, second == Leg::Upload)
            );
            assert_eq!(a, Some((true, false)));
            assert_eq!(b, None);
            assert_eq!(pair.join(second, false).await, None);
        }
        let pair = Pair::new();
        assert_eq!(pair.join(Leg::Upload, 1).await, None);
        assert_eq!(pair.join(Leg::Download, 2).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_or_other_connection_never_pairs() {
        let pair = Pair::new();
        let (a, b) = tokio::join!(pair.join(Leg::Upload, 1), pair.join(Leg::Upload, 2));
        assert_eq!((a, b), (None, None));
        assert_eq!(pair.join(Leg::Download, 3).await, None);
        let left = Pair::new();
        let right = Pair::new();
        let (a, b) = tokio::join!(left.join(Leg::Upload, 1), right.join(Leg::Download, 2));
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
