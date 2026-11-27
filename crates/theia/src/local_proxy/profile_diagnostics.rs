
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
    let work = crate::traffic::PROFILE_DIAGNOSTIC.scope((), session(&path, digest, &id, custom, &tx, confirm));
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
    let generation = match &client {
        ProxyClient::Direct(_) => None,
        ProxyClient::Reality(c) => Some(c.generation().await?),
    };
    let carrier = match &client {
        ProxyClient::Direct(c) => c.carrier.clone(),
        ProxyClient::Reality(_) => generation.as_ref().ok_or(ClientError::Configuration)?.carrier.clone(),
    };
    let (h2, h3) = match &carrier {
        Carrier::H2(c) => (Some(Carrier::H2(c.clone())), None),
        Carrier::H3(c) => (None, Some(Carrier::H3(c.clone()))),
        Carrier::Auto(c) => (Some(Carrier::H2(c.h2.clone())), Some(Carrier::H3(c.h3.clone()))),
    };
    let remotes = [h2.as_ref(), h3.as_ref()].into_iter().flatten().map(|transport| match transport {
        Carrier::H2(c) => c.diagnostic_remote(),
        Carrier::H3(c) => Ok(c.remote()),
        Carrier::Auto(_) => Err(ClientError::Configuration),
    }).collect::<Result<Vec<_>, _>>()?;
    let scopes: Vec<_> = remotes.iter().map(|addr| crate::network_scope::observe(*addr)).collect();
    let credential: [u8; 32] = Sha256::digest(super::read_token(profile)?.as_bytes()).into();
    let ca = ca_digest(profile)?;
    let guard = async {
        loop {
            source(path, digest)?;
            if credential != <[u8; 32]>::from(Sha256::digest(super::read_token(profile)?.as_bytes()))
                || ca != ca_digest(profile)?
                || remotes.iter().zip(&scopes).any(|(addr, scope)| crate::network_scope::observe(*addr) != *scope) {
                return Err(ClientError::Configuration);
            }
            if let (ProxyClient::Reality(c), Some(pinned)) = (&client, &generation) {
                if !Arc::ptr_eq(&c.generation().await?, pinned) { return Err(ClientError::Tls); }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        #[allow(unreachable_code)]
        Ok::<(), ClientError>(())
    };
    let checks = async {
    // Independent read-only carrier observations. Neither check authorizes a
    // target request or changes the production Auto fallback decision.
    let (h2_result, h3_result) = tokio::join!(
        check_carrier(h2.as_ref(), cache.scope()), check_carrier(h3.as_ref(), cache.scope())
    );
    let mut verified = Vec::new();
    let mut refused = false;
    for (label, transport, result) in [("H2", h2, h2_result), ("H3", h3, h3_result)] {
        match (transport, result) {
            (Some(transport), Some(Ok((digest, ms)))) => {
                emit(tx, format!("{label}: авторизованный канал подтверждён, {ms} мс"))?;
                verified.push((label, transport, digest));
            }
            (_, Some(Err(error))) => {
                emit(tx, format!("{label}: {error}"))?;
                refused |= protective(error);
            }
            _ => emit(tx, format!("{label}: не разрешён профилем"))?,
        }
    }
    if refused { return Err(ClientError::Protocol); }
    // Preserve the production selection and durable rollback floor separately.
    let snapshot = timeout(Duration::from_secs(30), client.routing_policy()).await.map_err(|_| ClientError::Timeout)??;
    let expected = snapshot.digest();
    if verified.is_empty() || verified.iter().any(|(_, _, digest)| *digest != expected) { return Err(ClientError::Protocol); }
    emit(tx, format!("Сервер: авторизация и политика подтверждены, {} мс; ревизия {}", started.elapsed().as_millis(), snapshot.manifest().revision))?;
    let domains = match custom {
        Some(domains) => domains,
        None => {
            let (_, transport, _) = &verified[0];
            timeout(Duration::from_secs(12), async {
                match transport {
                    Carrier::H2(c) => c.diagnostic_domains(expected).await,
                    Carrier::H3(c) => c.diagnostic_domains(expected).await,
                    Carrier::Auto(_) => Err(ClientError::Configuration),
                }
            }).await.map_err(|_| ClientError::Timeout)??
        }
    };
    tx.send(Event::Domains(domains.clone())).map_err(|_| ClientError::Io)?;
    confirm.await.map_err(|_| ClientError::Io)?;
    source(path, digest)?;
    let pin = cache.policy.pin(expected)?;
    emit(tx, format!("UDP Anti-DPI: {}. UDP-проверки не выполняются.", crate::routing::dpi::UdpStrategy::capability_summary()))?;
    let roots = tokio::task::spawn_blocking(crate::net::tls::native_roots).await.map_err(|_| ClientError::Tls)?;
    let tls = Arc::new(crate::net::tls::application_probe(roots).map_err(|_| ClientError::Tls)?);
    for domain in domains {
        source(path, digest)?;
        pin.check()?;
        let current = timeout(Duration::from_secs(15), client.refresh_routing_policy()).await.map_err(|_| ClientError::Timeout)??;
        if current.digest() != expected { return Err(ClientError::Protocol); }
        emit(tx, format!("── {domain} ──"))?;
        let (action, ips, pin) = match timeout(Duration::from_secs(12), egress::diagnostic_target(&carrier, cache, &domain, expected)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => { emit(tx, format!("Политика/DNS: {e}; пропуск"))?; if protective(e) { return Err(e); } continue; }
            Err(_) => { emit(tx, "Политика/DNS: таймаут; пропуск")?; continue; }
        };
        emit(tx, format!("Маршрут: {}", action.name()))?;
        if action == Action::Blocked {
            emit(tx, "Запрещённый маршрут: сетевые запросы не выполняются")?;
            continue;
        }
        if action == Action::DirectDpi {
            match cache.dpi.diagnostic_tcp_strategies(&domain, &ips, &pin).await {
                Ok(results) => {
                    if results.is_empty() { emit(tx, "TCP Anti-DPI: нет разрешённых/доступных проб")?; }
                    for (strategy, status, ms) in results { emit(tx, format!("{strategy}: {status}, {ms} мс"))?; }
                }
                Err(e) => { emit(tx, format!("TCP Anti-DPI: {e}; остальные пробы домена отменены"))?; if protective(e) { return Err(e); } continue; }
            }
        } else { emit(tx, "TCP Anti-DPI: не назначен правилами")?; }
        let result = https(&carrier, cache, &domain, expected, true, tls.clone()).await;
        match result {
            Ok((code, route, ms)) => {
                let label = if action == Action::DirectDpi && route.starts_with("XHTTP") { "Фактический резерв XHTTP" } else { "Штатный маршрут" };
                emit(tx, format!("{label}: HTTP {code}, {route}, {ms} мс"))?;
            }
            Err(e) => { emit(tx, format!("Авто: {e}"))?; if protective(e) { return Err(e); } }
        }
        if action == Action::Direct { continue; }
        for (label, transport, _) in &verified {
            match https(transport, cache, &domain, expected, false, tls.clone()).await {
                Ok((code, route, ms)) => emit(tx, format!("Контроль XHTTP {label}: HTTP {code}, {route}, {ms} мс"))?,
                Err(e) => { emit(tx, format!("Контроль XHTTP {label}: {e}"))?; if protective(e) { return Err(e); } }
            }
        }
    }
    emit(tx, "Завершено. HTTP-ответ подтверждает обмен, не доступность всех функций сайта. TLS-проба стратегии не доказывает наличие блокировки.")
    };
    let result = tokio::select! { biased; result = guard => result, result = checks => result };
    cache.policy.retire();
    result
}

fn protective(error: ClientError) -> bool {
    matches!(error, ClientError::Configuration | ClientError::Tls | ClientError::Unauthorized |
        ClientError::Protocol | ClientError::Open(_) | ClientError::Rejected(400..=499))
}

fn ca_digest(profile: &config::Profile) -> Result<Option<[u8; 32]>, ClientError> {
    profile.tls_ca.as_deref().filter(|reference| reference.starts_with("file:")).map(|reference| {
        let bytes = super::load_file(reference, super::CA_LIMIT, false)?;
        Ok(Sha256::digest(bytes.as_slice()).into())
    }).transpose()
}

async fn check_carrier(transport: Option<&Carrier>, scope: &str) -> Option<Result<([u8; 32], u128), ClientError>> {
    let transport = transport?;
    let started = Instant::now();
    Some(timeout(Duration::from_secs(30), async {
        let wire = transport.fetch_routing(None).await?;
        let scope = scope.to_owned();
        let digest = tokio::task::spawn_blocking(move || Snapshot::decode(&wire, &scope).map(|s| s.digest()))
            .await.map_err(|_| ClientError::Protocol)?.map_err(|_| ClientError::Protocol)?;
        Ok((digest, started.elapsed().as_millis()))
    }).await.unwrap_or(Err(ClientError::Timeout)))
}

async fn https(carrier: &Carrier, cache: &super::Cache, name: &str, digest: [u8; 32], allow_dpi: bool, tls: Arc<rustls::ClientConfig>) -> Result<(u16, String, u128), ClientError> {
    let started = Instant::now();
    timeout(Duration::from_secs(12), async {
        let mut routed = egress::diagnostic_open(carrier, cache, name, digest, allow_dpi).await?;
        let direct = matches!(&routed.tunnel, ProxyTunnel::Direct(_));
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
            _ if direct => "напрямую (без модификации)".to_owned(),
            _ if allow_dpi => "локальный Anti-DPI".to_owned(),
            _ => return Err(ClientError::Protocol),
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
    fn security_failures_are_not_availability() {
        for error in [ClientError::Configuration, ClientError::Tls, ClientError::Unauthorized, ClientError::Protocol, ClientError::Rejected(403)] {
            assert!(protective(error));
        }
        assert!(!protective(ClientError::Timeout));
        assert!(!protective(ClientError::QuicUnreachable));
    }

    #[test]
    fn bounded_status_requires_http() {
        assert_eq!(status(b"HTTP/1.1 403 Forbidden\r").unwrap(), 403);
        assert!(status(b"HTTP/2 200").is_err());
        assert!(status(b"HTTP/1.1 0200").is_err());
        assert!(status(b"not HTTP 200").is_err());
    }
}
