//! Native Theia TCP DPI strategy: split the plaintext first TLS handshake
//! record, preserving the handshake bytes and end-to-end certificate checks.
//! This is TLS record framing, not a promise about TCP packet boundaries.
use crate::{client::ClientError, network_scope, protocol::ErrorCode};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    time::timeout,
};

const RECORD_LIMIT: usize = 16 * 1024;
const CACHE_LIMIT: usize = 128;
const POSITIVE_TTL: Duration = Duration::from_secs(60);
const NEGATIVE_TTL: Duration = Duration::from_secs(20);
const ATTEMPT: Duration = Duration::from_secs(2);
const OPEN_BUDGET: Duration = Duration::from_secs(6);
const FIRST_FLIGHT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Strategy {
    Header,
    Middle,
}

impl Strategy {
    const ALL: [Self; 2] = [Self::Header, Self::Middle];
}

// Only split a complete, structurally bounded first ClientHello record.
// Existing trailing records are left byte-exact. Other protocols and
// already-fragmented ClientHello messages are not this backend's contract.
fn fragment_flight(bytes: &[u8], strategy: Strategy) -> Option<Vec<u8>> {
    let header = bytes.get(..5)?;
    if header[0] != 22 || header[1] != 3 || !(1..=3).contains(&header[2]) {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if !(45..=RECORD_LIMIT).contains(&len) {
        return None;
    }
    let end = 5 + len;
    let body = bytes.get(5..end)?;
    let hello_len = usize::from(body[1]) << 16
        | usize::from(body[2]) << 8
        | usize::from(body[3]);
    if body[0] != 1 || hello_len != len - 4 {
        return None;
    }
    let cut = match strategy {
        Strategy::Header => 4,
        Strategy::Middle => len / 2,
    };
    let mut out = Vec::with_capacity(bytes.len() + 5);
    for part in [&body[..cut], &body[cut..]] {
        out.extend_from_slice(&header[..3]);
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(&bytes[end..]);
    Some(out)
}

fn tls_config(roots: rustls::RootCertStore) -> Option<Arc<rustls::ClientConfig>> {
    if roots.is_empty() {
        return None;
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Some(Arc::new(config))
}

fn native_config() -> Option<Arc<rustls::ClientConfig>> {
    static CONFIG: OnceLock<Option<Arc<rustls::ClientConfig>>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            tls_config(roots)
        })
        .clone()
}

// A separate authenticated TLS probe to the exact policy-pinned address.
// Never send application data or disable hostname/certificate validation.
async fn probe(
    name: &str,
    address: SocketAddr,
    strategy: Strategy,
    config: Arc<rustls::ClientConfig>,
) -> Option<()> {
    let server_name = rustls::pki_types::ServerName::try_from(name.to_owned()).ok()?;
    let mut tls = rustls::ClientConnection::new(config, server_name).ok()?;
    let mut socket = TcpStream::connect(address).await.ok()?;
    let mut first = true;
    let mut input = [0; RECORD_LIMIT];
    loop {
        while tls.wants_write() {
            let mut output = Vec::new();
            if tls.write_tls(&mut output).ok()? == 0 {
                return None;
            }
            if first {
                output = fragment_flight(&output, strategy)?;
                first = false;
            }
            socket.write_all(&output).await.ok()?;
        }
        if !tls.is_handshaking() {
            return (!first).then_some(());
        }
        if !tls.wants_read() {
            return None;
        }
        let count = socket.read(&mut input).await.ok()?;
        if count == 0 {
            return None;
        }
        let mut bytes = &input[..count];
        while !bytes.is_empty() {
            if tls.read_tls(&mut bytes).ok()? == 0 {
                return None;
            }
            tls.process_new_packets().ok()?;
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Key {
    name: String,
    address: SocketAddr,
    policy: [u8; 32],
    network: network_scope::Scope,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Verified(Strategy),
    Unavailable,
}
struct Entry {
    key: Key,
    verdict: Verdict,
    expires: Instant,
}

/// Profile-local, bounded strategy evidence. No state on disk or in logs.
/// Consent is local configuration, not a command in the server snapshot.
pub(crate) struct Engine {
    enabled: AtomicBool,
    cache: Mutex<VecDeque<Entry>>,
    probes: Semaphore,
}

impl Default for Engine {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            cache: Mutex::new(VecDeque::new()),
            probes: Semaphore::new(4),
        }
    }
}

impl Engine {
    pub(crate) fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn cached(&self, key: &Key) -> Option<Verdict> {
        let mut cache = self.cache.lock().ok()?;
        let now = Instant::now();
        cache.retain(|entry| entry.expires > now);
        cache.iter().find(|entry| &entry.key == key).map(|entry| entry.verdict)
    }

    fn remember(&self, key: &Key, verdict: Verdict) {
        // A network change or loss of OS evidence prevents reuse/publication.
        if network_scope::observe(key.address) != Some(key.network) {
            return;
        }
        self.insert(key, verdict);
    }

    fn insert(&self, key: &Key, verdict: Verdict) {
        if let Ok(mut cache) = self.cache.lock() {
            let now = Instant::now();
            cache.retain(|entry| entry.expires > now && &entry.key != key);
            if cache.len() >= CACHE_LIMIT {
                cache.pop_front();
            }
            let ttl = match verdict {
                Verdict::Verified(_) => POSITIVE_TTL,
                Verdict::Unavailable => NEGATIVE_TTL,
            };
            cache.push_back(Entry {
                key: key.clone(),
                verdict,
                expires: now + ttl,
            });
        }
    }

    pub(crate) async fn open(
        self: &Arc<Self>,
        name: &str,
        port: u16,
        ips: &[IpAddr],
        policy: [u8; 32],
    ) -> Option<Tunnel> {
        if !self.enabled() || port != 443 || ips.is_empty() || ips.len() > 64
            || !ips.iter().all(|ip| crate::server::allowed_destination(*ip, false))
        {
            return None;
        }
        let name = super::domain_name(name).ok()?;
        let _permit = self.probes.try_acquire().ok()?;
        timeout(OPEN_BUDGET, async {
            for ip in ips.iter().take(2) {
                let address = SocketAddr::new(*ip, port);
                let Some(network) = network_scope::observe(address) else {
                    continue;
                };
                let key = Key { name: name.clone(), address, policy, network };
                let strategy = match self.cached(&key) {
                    Some(Verdict::Verified(strategy)) => strategy,
                    Some(Verdict::Unavailable) => continue,
                    None => {
                        let config = tokio::task::spawn_blocking(native_config).await.ok()??;
                        let mut verified = None;
                        for strategy in Strategy::ALL {
                            if timeout(ATTEMPT, probe(&name, address, strategy, config.clone()))
                                .await
                                .ok()
                                .flatten()
                                .is_some()
                            {
                                verified = Some(strategy);
                                break;
                            }
                        }
                        let Some(strategy) = verified else {
                            self.remember(&key, Verdict::Unavailable);
                            continue;
                        };
                        self.remember(&key, Verdict::Verified(strategy));
                        strategy
                    }
                };
                if network_scope::observe(address) != Some(network) {
                    continue;
                }
                match timeout(ATTEMPT, TcpStream::connect(address)).await {
                    Ok(Ok(target)) if network_scope::observe(address) == Some(network) => {
                        return Some(Tunnel {
                            target,
                            strategy,
                            engine: self.clone(),
                            key,
                        });
                    }
                    _ => self.remember(&key, Verdict::Unavailable),
                }
            }
            None
        })
        .await
        .ok()
        .flatten()
    }
}

async fn read_record(socket: &mut TcpStream) -> Result<Vec<u8>, ClientError> {
    let mut header = [0; 5];
    socket.read_exact(&mut header).await.map_err(|_| ClientError::Io)?;
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if !(1..=RECORD_LIMIT).contains(&len) {
        return Err(ClientError::Protocol);
    }
    let mut bytes = vec![0; 5 + len];
    bytes[..5].copy_from_slice(&header);
    socket.read_exact(&mut bytes[5..]).await.map_err(|_| ClientError::Io)?;
    Ok(bytes)
}

pub(crate) struct Tunnel {
    target: TcpStream,
    strategy: Strategy,
    engine: Arc<Engine>,
    key: Key,
}

impl Tunnel {
    pub(crate) async fn relay(mut self, mut client: TcpStream) -> Result<(), ClientError> {
        // The application owns the actual TLS session. The probe does not
        // authorize modifying its certificate checks or replaying its bytes.
        let original = match timeout(FIRST_FLIGHT, read_record(&mut client)).await {
            Ok(Ok(record)) => record,
            Ok(Err(error @ ClientError::Protocol)) => {
                self.engine.remember(&self.key, Verdict::Unavailable);
                crate::traffic::dpi_first_failure();
                return Err(error);
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(ClientError::Timeout),
        };
        let Some(transformed) = fragment_flight(&original, self.strategy) else {
            self.engine.remember(&self.key, Verdict::Unavailable);
            crate::traffic::dpi_first_failure();
            return Err(ClientError::Protocol);
        };
        if network_scope::observe(self.key.address) != Some(self.key.network) {
            return Err(ClientError::Open(ErrorCode::DialFailed));
        }
        let response = timeout(FIRST_FLIGHT, async {
            self.target.write_all(&transformed).await.map_err(|_| ClientError::Io)?;
            let response = read_record(&mut self.target).await?;
            if response[0] != 22 || response[1] != 3
                || !(1..=3).contains(&response[2]) || response[5] != 2
            {
                return Err(ClientError::Protocol);
            }
            Ok(response)
        })
        .await;
        let response = match response {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                self.engine.remember(&self.key, Verdict::Unavailable);
                crate::traffic::dpi_first_failure();
                return Err(error);
            }
            Err(_) => {
                self.engine.remember(&self.key, Verdict::Unavailable);
                crate::traffic::dpi_first_failure();
                return Err(ClientError::Timeout);
            }
        };
        timeout(FIRST_FLIGHT, client.write_all(&response))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|_| ClientError::Io)?;
        crate::traffic::dpi_first_response();
        // No rerouting of this live stream. A failed first flight only affects
        // subsequent opens. TLS record overhead is excluded from app counters.
        super::client_state::relay_direct_after_first(
            client, self.target, original.len(), response.len(),
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Vec<u8> {
        let mut bytes = vec![22, 3, 1, 0, 45, 1, 0, 0, 41];
        bytes.extend([0; 41]);
        bytes
    }

    fn join_payload(bytes: &[u8]) -> Vec<u8> {
        let mut joined = Vec::new();
        let mut remaining = bytes;
        while !remaining.is_empty() {
            assert_eq!(&remaining[..3], &[22, 3, 1]);
            let len = usize::from(u16::from_be_bytes([remaining[3], remaining[4]]));
            joined.extend_from_slice(&remaining[5..5 + len]);
            remaining = &remaining[5 + len..];
        }
        joined
    }

    #[test]
    fn first_record_only_and_exact_handshake_bytes() {
        let original = hello();
        for strategy in Strategy::ALL {
            let split = fragment_flight(&original, strategy).unwrap();
            assert_eq!(split.len(), original.len() + 5);
            assert_eq!(join_payload(&split), original[5..]);
            let mut with_tail = original.clone();
            with_tail.extend([20, 3, 3, 0, 1, 1]);
            let transformed = fragment_flight(&with_tail, strategy).unwrap();
            assert_eq!(transformed[split.len()..], with_tail[original.len()..]);
        }
        for i in 0..original.len() {
            assert!(fragment_flight(&original[..i], Strategy::Header).is_none());
        }
        for (offset, invalid) in [(0, 23), (1, 4), (2, 0), (3, 255), (5, 2), (8, 40)] {
            let mut bad = original.clone();
            bad[offset] = invalid;
            assert!(fragment_flight(&bad, Strategy::Middle).is_none());
        }
    }

    #[test]
    fn cache_separates_network_policy_and_destination() {
        let engine = Engine::default();
        assert!(!engine.enabled());
        engine.set_enabled(true);
        assert!(engine.enabled());
        let addr = "127.0.0.1:443".parse().unwrap();
        let mut key = Key {
            name: "example.org".into(),
            address: addr,
            policy: [1; 32],
            network: network_scope::Scope::fixture(addr, 1),
        };
        engine.insert(&key, Verdict::Verified(Strategy::Header));
        assert!(matches!(engine.cached(&key), Some(Verdict::Verified(Strategy::Header))));
        key.policy = [2; 32];
        assert!(engine.cached(&key).is_none());
        key.policy = [1; 32];
        key.network = network_scope::Scope::fixture(addr, 2);
        assert!(engine.cached(&key).is_none());
        key.network = network_scope::Scope::fixture(addr, 1);
        engine.insert(&key, Verdict::Unavailable);
        assert!(matches!(engine.cached(&key), Some(Verdict::Unavailable)));
        for i in 0..=CACHE_LIMIT {
            key.name = format!("{i}.example.org");
            engine.insert(&key, Verdict::Unavailable);
        }
        assert_eq!(engine.cache.lock().unwrap().len(), CACHE_LIMIT);
        engine.cache.lock().unwrap().iter_mut().for_each(|entry| {
            entry.expires = Instant::now() - Duration::from_secs(1);
        });
        assert!(engine.cached(&key).is_none());
    }

    #[tokio::test]
    async fn disabled_or_private_targets_never_probe() {
        let engine = Arc::new(Engine::default());
        assert!(engine.open("example.org", 443, &["8.8.8.8".parse().unwrap()], [1; 32]).await.is_none());
        engine.set_enabled(true);
        assert!(engine.open("localhost", 443, &["127.0.0.1".parse().unwrap()], [1; 32]).await.is_none());
        assert!(engine.open("example.org", 80, &["8.8.8.8".parse().unwrap()], [1; 32]).await.is_none());
        assert!(engine.open("example.org", 443, &[], [1; 32]).await.is_none());
    }

    #[tokio::test]
    async fn real_tls_peer_accepts_both_native_record_strategies_and_rejects_wrong_name() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.cert.der().clone();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let config = tls_config(roots).unwrap();
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        timeout(Duration::from_secs(10), async {
            for (name, strategy, expected) in [
                ("localhost", Strategy::Header, true),
                ("localhost", Strategy::Middle, true),
                ("wrong.invalid", Strategy::Header, false),
            ] {
                let server = async {
                    let (socket, _) = listener.accept().await.unwrap();
                    acceptor.accept(socket).await.is_ok()
                };
                let client = probe(name, address, strategy, config.clone());
                let (server_ok, client_ok) = tokio::join!(server, client);
                assert_eq!(client_ok.is_some(), expected);
                assert_eq!(server_ok, expected);
            }
        }).await.unwrap();
    }
}
