
//! User-initiated diagnostics; never installs or changes the system proxy.
use super::{bind_proxy_listener, egress, load_client_with_budget, xhttp_observation, Carrier, ProxyClient, ProxyTunnel};
use crate::{client::ClientError, config::{self, Config}, routing::{Action, snapshot::{Snapshot, validate_diagnostic_domains}}};
use sha2::{Digest, Sha256};
use std::{path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicU8, Ordering}, mpsc::Sender}, time::{Duration, Instant}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync::{oneshot, watch}, time::timeout};

pub(crate) enum Event { Line(String), Domains(Vec<String>), Done }

fn emit(tx: &Sender<Event>, line: impl Into<String>) -> Result<(), ClientError> {
    tx.send(Event::Line(line.into())).map_err(|_| ClientError::Io)
}

fn source(path: &Path, digest: [u8; 32]) -> Result<zeroize::Zeroizing<Vec<u8>>, ClientError> {
    let raw = zeroize::Zeroizing::new(config::editor_bytes(path).map_err(|_| ClientError::Configuration)?);
    let observed: [u8; 32] = Sha256::digest(raw.as_slice()).into();
    if observed != digest { return Err(ClientError::Configuration); }
    Ok(raw)
}

pub(crate) async fn run(
    path: PathBuf, digest: [u8; 32], id: String, custom: Option<Vec<String>>,
    tx: Sender<Event>, confirm: oneshot::Receiver<()>, mut cancel: watch::Receiver<bool>,
) {
    let work = session(&path, digest, &id, custom, &tx, confirm);
    let result = tokio::select! {
        result = timeout(Duration::from_secs(240), work) => result.unwrap_or(Err(ClientError::Timeout)),
        _ = cancel.changed() => Err(ClientError::Io),
        result = async {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                source(&path, digest)?;
            }
            #[allow(unreachable_code)]
            Ok::<(), ClientError>(())
        } => result,
    };
    if let Err(error) = result { let _ = emit(&tx, format!("Проверка остановлена: {error}")); }
    let _ = tx.send(Event::Done);
}

async fn session(
    path: &Path, digest: [u8; 32], id: &str, custom: Option<Vec<String>>,
    tx: &Sender<Event>, confirm: oneshot::Receiver<()>,
) -> Result<(), ClientError> {
    if custom.as_ref().is_some_and(|v| !validate_diagnostic_domains(v)) { return Err(ClientError::Configuration); }
    let raw = source(path, digest)?;
    let Config::Client(doc) = config::parse(std::str::from_utf8(&raw).map_err(|_| ClientError::Configuration)?)
        .map_err(|_| ClientError::Configuration)? else { return Err(ClientError::Configuration); };
    let profile = doc.client.profiles.iter().find(|p| p.id == id).ok_or(ClientError::Configuration)?;
    let started = Instant::now();
    let client = timeout(Duration::from_secs(20), load_client_with_budget(profile, crate::connection_pool::profile_budget(), Some(path))).await.map_err(|_| ClientError::Timeout)??;
    let cache = client.routing_cache();
    cache.dpi.set_enabled(profile.direct_dpi.unwrap_or(false));
    cache.dpi.set_stun_enabled(profile.direct_dpi_stun.unwrap_or(false));
    let snapshot = timeout(Duration::from_secs(20), client.routing_policy()).await.map_err(|_| ClientError::Timeout)??;
    emit(tx, format!("Сервер: авторизация и политика подтверждены, {} мс; ревизия {}", started.elapsed().as_millis(), snapshot.manifest().revision))?;
    let carrier = match &client {
        ProxyClient::Direct(c) => c.carrier.clone(),
        ProxyClient::Reality(c) => c.generation().await?.carrier.clone(),
    };
    let domains = custom.unwrap_or_else(|| snapshot.manifest().diagnostic_domains.clone());
    tx.send(Event::Domains(domains.clone())).map_err(|_| ClientError::Io)?;
    confirm.await.map_err(|_| ClientError::Io)?;
    source(path, digest)?;
    let expected = snapshot.digest();
    let (h2, h3) = match &carrier {
        Carrier::H2(c) => (Some(Carrier::H2(c.clone())), None),
        Carrier::H3(c) => (None, Some(Carrier::H3(c.clone()))),
        Carrier::Auto(c) => (Some(Carrier::H2(c.h2.clone())), Some(Carrier::H3(c.h3.clone()))),
    };
    let mut verified = Vec::new();
    for (label, transport) in [("H2", h2), ("H3", h3)] {
        let Some(transport) = transport else { emit(tx, format!("{label}: не разрешён профилем"))?; continue; };
        let started = Instant::now();
        let result = timeout(Duration::from_secs(12), transport.fetch_routing(None)).await;
        match result {
            Ok(Ok(wire)) => {
                let observed = Snapshot::decode(&wire, &snapshot.manifest().inbound_id).map_err(|_| ClientError::Protocol)?;
                if observed.digest() != expected { return Err(ClientError::Protocol); }
                emit(tx, format!("{label}: авторизованный канал подтверждён, {} мс", started.elapsed().as_millis()))?;
                verified.push((label, transport));
            }
            Ok(Err(e)) => emit(tx, format!("{label}: {e}"))?,
            Err(_) => emit(tx, format!("{label}: таймаут"))?,
        }
    }
    emit(tx, format!("UDP Anti-DPI: {}. UDP-проверки не выполняются.", crate::routing::dpi::UdpStrategy::capability_summary()))?;
    let roots = tokio::task::spawn_blocking(crate::net::tls::native_roots).await.map_err(|_| ClientError::Tls)?;
    let tls = Arc::new(crate::net::tls::application_probe(roots).map_err(|_| ClientError::Tls)?);
    for domain in domains {
        source(path, digest)?;
        let current = timeout(Duration::from_secs(15), client.refresh_routing_policy()).await.map_err(|_| ClientError::Timeout)??;
        if current.digest() != expected { return Err(ClientError::Protocol); }
        emit(tx, format!("── {domain} ──"))?;
        let (action, ips, pin) = match timeout(Duration::from_secs(12), egress::diagnostic_target(&carrier, cache, &domain, expected)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => { emit(tx, format!("Политика/DNS: {e}; пропуск"))?; continue; }
            Err(_) => { emit(tx, "Политика/DNS: таймаут; пропуск")?; continue; }
        };
        emit(tx, format!("Маршрут: {}", action.name()))?;
        if !matches!(action, Action::Allowed | Action::DirectDpi) {
            emit(tx, "Прямой/запрещённый маршрут: XHTTP и Anti-DPI не проверяются")?;
            continue;
        }
        if action == Action::DirectDpi {
            match cache.dpi.diagnostic_tcp_strategies(&domain, &ips, &pin).await {
                Ok(results) => {
                    if results.is_empty() { emit(tx, "TCP Anti-DPI: нет разрешённых/доступных проб")?; }
                    for (strategy, status, ms) in results { emit(tx, format!("{strategy}: {status}, {ms} мс"))?; }
                }
                Err(e) => { emit(tx, format!("TCP Anti-DPI: {e}; остальные пробы домена отменены"))?; continue; }
            }
        } else { emit(tx, "TCP Anti-DPI: не назначен правилами")?; }
        let result = https(&carrier, cache, &domain, expected, true, tls.clone()).await;
        match result {
            Ok((code, route, ms)) => emit(tx, format!("Авто: HTTP {code}, {route}, {ms} мс"))?,
            Err(e) => { emit(tx, format!("Авто: {e}"))?; if matches!(e, ClientError::Tls | ClientError::Unauthorized | ClientError::Open(_) | ClientError::Protocol) { continue; } }
        }
        for (label, transport) in &verified {
            match https(transport, cache, &domain, expected, false, tls.clone()).await {
                Ok((code, route, ms)) => emit(tx, format!("Контроль XHTTP {label}: HTTP {code}, {route}, {ms} мс"))?,
                Err(e) => { emit(tx, format!("Контроль XHTTP {label}: {e}"))?; if matches!(e, ClientError::Tls | ClientError::Unauthorized | ClientError::Open(_) | ClientError::Protocol) { break; } }
            }
        }
    }
    emit(tx, "Завершено. HTTP-ответ подтверждает обмен, не доступность всех функций сайта. TLS-проба стратегии не доказывает наличие блокировки.")
}

async fn https(carrier: &Carrier, cache: &super::Cache, name: &str, digest: [u8; 32], allow_dpi: bool, tls: Arc<rustls::ClientConfig>) -> Result<(u16, String, u128), ClientError> {
    let started = Instant::now();
    timeout(Duration::from_secs(12), async {
        let mut routed = egress::diagnostic_open(carrier, cache, name, digest, allow_dpi).await?;
        let observed = Arc::new(AtomicU8::new(routed.open_code()));
        if let ProxyTunnel::Dpi(route) = &mut routed.tunnel { route.observed = Some(observed.clone()); }
        let listener = bind_proxy_listener("127.0.0.1:0").await?;
        let addr = listener.local_addr().map_err(|_| ClientError::Io)?;
        let local = TcpStream::connect(addr).await.map_err(|_| ClientError::Io)?;
        let (socket, peer) = listener.accept().await.map_err(|_| ClientError::Io)?;
        if local.local_addr().map_err(|_| ClientError::Io)? != peer { return Err(ClientError::Io); }
        drop(listener);
        let relay = routed.relay(socket);
        let app = async {
            let server_name = rustls::pki_types::ServerName::try_from(name.to_owned()).map_err(|_| ClientError::Configuration)?;
            let mut stream = tokio_rustls::TlsConnector::from(tls).connect(server_name, local).await.map_err(|_| ClientError::Tls)?;
            stream.write_all(format!("HEAD / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").as_bytes()).await.map_err(|_| ClientError::Io)?;
            let mut line = Vec::new();
            for _ in 0..1024 {
                let b = stream.read_u8().await.map_err(|_| ClientError::Io)?;
                if b == b'\n' { return status(&line); }
                line.push(b);
            }
            Err(ClientError::Protocol)
        };
        tokio::pin!(relay, app);
        let status = tokio::select! {
            biased;
            result = &mut app => result?,
            result = &mut relay => { result?; app.await? }
        };
        cache.policy.pin(digest)?.check()?;
        let code = observed.load(Ordering::Relaxed);
        let route = match code >> 2 {
            2 => format!("XHTTP H2 {}", xhttp_observation(code & 3)),
            3 => format!("XHTTP H3 {}", xhttp_observation(code & 3)),
            _ => "локальный Anti-DPI".to_owned(),
        };
        Ok((status, route, started.elapsed().as_millis()))
    }).await.map_err(|_| ClientError::Timeout)?
}

fn status(line: &[u8]) -> Result<u16, ClientError> {
    let text = std::str::from_utf8(line).map_err(|_| ClientError::Protocol)?;
    let mut parts = text.split_whitespace();
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) { return Err(ClientError::Protocol); }
    let code = parts.next().ok_or(ClientError::Protocol)?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) { return Err(ClientError::Protocol); }
    let code: u16 = code.parse().map_err(|_| ClientError::Protocol)?;
    if !(100..=599).contains(&code) { return Err(ClientError::Protocol); }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_status_requires_http() {
        assert_eq!(status(b"HTTP/1.1 403 Forbidden\r").unwrap(), 403);
        assert!(status(b"HTTP/2 200").is_err());
        assert!(status(b"HTTP/1.1 0200").is_err());
        assert!(status(b"not HTTP 200").is_err());
    }
}
