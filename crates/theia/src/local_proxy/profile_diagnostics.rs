//! User-initiated diagnostics; never installs or changes the system proxy.
use super::{
    bind_proxy_listener, egress, load_client_with_budget, xhttp_observation, Carrier, ProxyClient,
    ProxyTunnel,
};
use crate::{
    client::ClientError,
    config::{self, Config},
    routing::{
        snapshot::{validate_diagnostic_domains, Snapshot},
        Action,
    },
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU8, Ordering},
        mpsc::Sender,
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{oneshot, watch},
    time::timeout,
};

#[derive(Clone, Debug)]
pub(crate) enum CheckKind {
    Carrier(&'static str),
    Policy,
    Strategy(String),
    Https(&'static str),
    Udp(&'static str),
    Proxy(&'static str),
}
#[derive(Clone, Debug)]
pub(crate) enum Outcome {
    Verified(u128),
    Failure(ClientError),
    Skipped(&'static str),
    Route(Action),
    Tls(crate::net::error::ProbeVerdict, u128),
    Http(u16, ActualRoute, u128),
    Udp(u16, ActualRoute, u128),
    Proxy(u8, bool, u8),
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum FallbackCause {
    BeforeFirstSend,
    Disabled,
    NoLocalRoute,
}
impl std::fmt::Display for FallbackCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BeforeFirstSend => "до первой отправки",
            Self::Disabled => "Anti-DPI отключён",
            Self::NoLocalRoute => "локальный маршрут не выбран",
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) enum ActualRoute {
    Direct,
    AntiDpi(&'static str),
    Xhttp {
        carrier: &'static str,
        mode: &'static str,
        fallback: Option<FallbackCause>,
    },
    SystemProxy,
}
impl std::fmt::Display for ActualRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => f.write_str("напрямую (без модификации)"),
            Self::AntiDpi(strategy) => write!(f, "локальный Anti-DPI {strategy}"),
            Self::Xhttp {
                carrier,
                mode,
                fallback,
            } => {
                write!(f, "XHTTP {carrier} {mode}")?;
                if let Some(reason) = fallback {
                    write!(f, " · резерв: {reason}")?;
                }
                Ok(())
            }
            Self::SystemProxy => f.write_str("действующий listener"),
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Check {
    pub(crate) domain: Option<String>,
    pub(crate) kind: CheckKind,
    pub(crate) outcome: Outcome,
}
impl Check {
    pub(crate) fn line(&self, anonymous: bool) -> String {
        let kind = match &self.kind {
            CheckKind::Carrier(label) => format!("Канал {label}"),
            CheckKind::Policy => "Маршрут".to_owned(),
            CheckKind::Strategy(label) => label.clone(),
            CheckKind::Https(label) => format!("HTTPS {label}"),
            CheckKind::Udp(label) => format!("UDP {label}"),
            CheckKind::Proxy(label) => format!("System Proxy {label}"),
        };
        let outcome = match &self.outcome {
            Outcome::Verified(ms) => format!("подтверждён, {ms} мс"),
            Outcome::Failure(error) => format!("ошибка: {error}"),
            Outcome::Skipped(reason) => format!("не проверен: {reason}"),
            Outcome::Route(action) => action.name().to_owned(),
            Outcome::Tls(status, ms) => format!(
                "{}, {ms} мс",
                match status {
                    crate::net::error::ProbeVerdict::Verified => "TLS подтверждён",
                    crate::net::error::ProbeVerdict::StrategyFailed => "стратегия не сработала",
                    crate::net::error::ProbeVerdict::Unavailable => "проба недоступна",
                    crate::net::error::ProbeVerdict::IdentityRejected => "идентичность отклонена",
                    crate::net::error::ProbeVerdict::Denied => "запрещено",
                }
            ),
            Outcome::Http(status, route, ms) => format!("HTTP {status}, {route}, {ms} мс"),
            Outcome::Udp(status, route, ms) => {
                format!("QUIC v1 + HTTP/3 {status}, {route}, {ms} мс")
            }
            Outcome::Proxy(phase, ready, applied) => format!(
                "фаза {phase}, listeners {}, настройки {}",
                if *ready {
                    "готовы"
                } else {
                    "не готовы"
                },
                match applied {
                    1 => "подтверждены",
                    0 => "не применены",
                    _ => "не подтверждены",
                }
            ),
        };
        let prefix = match (&self.domain, anonymous) {
            (Some(domain), false) => format!("{domain} · "),
            (Some(_), true) => "Ресурс · ".to_owned(),
            _ => String::new(),
        };
        format!("{prefix}{kind}: {outcome}")
    }
    pub(crate) fn failed(&self) -> bool {
        matches!(
            self.outcome,
            Outcome::Failure(_) | Outcome::Http(400..=599, _, _) | Outcome::Udp(400..=599, _, _)
        ) || matches!(&self.outcome, Outcome::Tls(status, _) if *status != crate::net::error::ProbeVerdict::Verified)
    }
}
pub(crate) enum Event {
    Line(String),
    Check(Check),
    Domains(Vec<String>),
    DomainDone(String),
    Done(Result<(), ClientError>),
}

fn record(
    tx: &Sender<Event>,
    domain: Option<&str>,
    kind: CheckKind,
    outcome: Outcome,
) -> Result<(), ClientError> {
    tx.send(Event::Check(Check {
        domain: domain.map(str::to_owned),
        kind,
        outcome,
    }))
    .map_err(|_| ClientError::Io)
}

fn emit(tx: &Sender<Event>, line: impl Into<String>) -> Result<(), ClientError> {
    tx.send(Event::Line(line.into()))
        .map_err(|_| ClientError::Io)
}

fn source(path: &Path, digest: [u8; 32]) -> Result<zeroize::Zeroizing<Vec<u8>>, ClientError> {
    let raw = zeroize::Zeroizing::new(
        config::editor_bytes(path).map_err(|_| ClientError::Configuration)?,
    );
    let observed: [u8; 32] = Sha256::digest(raw.as_slice()).into();
    if observed != digest {
        return Err(ClientError::Configuration);
    }
    Ok(raw)
}

pub(crate) async fn run(
    path: PathBuf,
    digest: [u8; 32],
    id: String,
    custom: Option<Vec<String>>,
    tx: Sender<Event>,
    confirm: oneshot::Receiver<()>,
    mut cancel: watch::Receiver<bool>,
) {
    let work = crate::traffic::PROFILE_DIAGNOSTIC.scope(
        (),
        Box::pin(session(&path, digest, &id, custom, &tx, confirm)),
    );
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
    if let Err(error) = result {
        let _ = emit(&tx, format!("Проверка остановлена: {error}"));
    }
    let _ = tx.send(Event::Done(result));
}

async fn session(
    path: &Path,
    digest: [u8; 32],
    id: &str,
    custom: Option<Vec<String>>,
    tx: &Sender<Event>,
    confirm: oneshot::Receiver<()>,
) -> Result<(), ClientError> {
    if custom
        .as_ref()
        .is_some_and(|v| !validate_diagnostic_domains(v))
    {
        return Err(ClientError::Configuration);
    }
    let raw = source(path, digest)?;
    let Config::Client(doc) =
        config::parse(std::str::from_utf8(&raw).map_err(|_| ClientError::Configuration)?)
            .map_err(|_| ClientError::Configuration)?
    else {
        return Err(ClientError::Configuration);
    };
    let profile = doc
        .client
        .profiles
        .iter()
        .find(|p| p.id == id)
        .ok_or(ClientError::Configuration)?;
    let credential: [u8; 32] = Sha256::digest(super::read_token(profile)?.as_bytes()).into();
    let ca = ca_digest(profile)?;
    let started = Instant::now();
    let client = timeout(
        Duration::from_secs(20),
        load_client_with_budget(
            profile,
            crate::connection_pool::profile_budget(),
            Some(path),
        ),
    )
    .await
    .map_err(|_| ClientError::Timeout)??;
    let cache = client.routing_cache();
    cache.dpi.set_enabled(profile.direct_dpi.unwrap_or(false));
    cache
        .dpi
        .set_stun_enabled(profile.direct_dpi_stun.unwrap_or(false));
    let generation = match &client {
        ProxyClient::Direct(_) => None,
        ProxyClient::Reality(c) => Some(c.generation().await?),
    };
    let carrier = match &client {
        ProxyClient::Direct(c) => c.carrier.clone(),
        ProxyClient::Reality(_) => generation
            .as_ref()
            .ok_or(ClientError::Configuration)?
            .carrier
            .clone(),
    };
    let (h2, h3) = match &carrier {
        Carrier::H2(c) => (Some(Carrier::H2(c.clone())), None),
        Carrier::H3(c) => (None, Some(Carrier::H3(c.clone()))),
        Carrier::Auto(c) => (
            Some(Carrier::H2(c.h2.clone())),
            Some(Carrier::H3(c.h3.clone())),
        ),
    };
    let remotes = [h2.as_ref(), h3.as_ref()]
        .into_iter()
        .flatten()
        .map(|transport| match transport {
            Carrier::H2(c) => c.diagnostic_remote(),
            Carrier::H3(c) => Ok(c.remote()),
            Carrier::Auto(_) => Err(ClientError::Configuration),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let scopes: Vec<_> = remotes
        .iter()
        .map(|addr| crate::network_scope::observe(*addr))
        .collect();
    let accepted_digest = std::cell::Cell::new(None);
    let guard = async {
        let mut next_refresh = Instant::now();
        loop {
            source(path, digest)?;
            if credential
                != <[u8; 32]>::from(Sha256::digest(super::read_token(profile)?.as_bytes()))
                || ca != ca_digest(profile)?
                || remotes
                    .iter()
                    .zip(&scopes)
                    .any(|(addr, scope)| crate::network_scope::observe(*addr) != *scope)
            {
                return Err(ClientError::Configuration);
            }
            if let (ProxyClient::Reality(c), Some(pinned)) = (&client, &generation) {
                if !Arc::ptr_eq(&c.generation().await?, pinned) {
                    return Err(ClientError::Tls);
                }
            }
            if let Some(expected) = accepted_digest
                .get()
                .filter(|_| Instant::now() >= next_refresh)
            {
                let current = timeout(Duration::from_secs(15), client.refresh_routing_policy())
                    .await
                    .map_err(|_| ClientError::Timeout)??;
                if current.digest() != expected {
                    return Err(ClientError::Protocol);
                }
                next_refresh = Instant::now() + Duration::from_secs(3);
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
            Box::pin(check_carrier(h2.as_ref(), cache.scope())),
            Box::pin(check_carrier(h3.as_ref(), cache.scope()))
        );
        let mut verified = Vec::new();
        let mut refused = false;
        for (label, transport, result) in [("H2", h2, h2_result), ("H3", h3, h3_result)] {
            match (transport, result) {
                (Some(transport), Some(Ok((digest, ms)))) => {
                    record(tx, None, CheckKind::Carrier(label), Outcome::Verified(ms))?;
                    verified.push((label, transport, digest));
                }
                (_, Some(Err(error))) => {
                    record(tx, None, CheckKind::Carrier(label), Outcome::Failure(error))?;
                    refused |= protective(error);
                }
                _ => record(
                    tx,
                    None,
                    CheckKind::Carrier(label),
                    Outcome::Skipped("не разрешён профилем"),
                )?,
            }
        }
        if refused {
            return Err(ClientError::Protocol);
        }
        // Preserve the production selection and durable rollback floor separately.
        let snapshot = timeout(Duration::from_secs(30), client.routing_policy())
            .await
            .map_err(|_| ClientError::Timeout)??;
        let expected = snapshot.digest();
        if verified.is_empty() || verified.iter().any(|(_, _, digest)| *digest != expected) {
            return Err(ClientError::Protocol);
        }
        accepted_digest.set(Some(expected));
        emit(
            tx,
            format!(
                "Сервер: авторизация и политика подтверждены, {} мс; ревизия {}",
                started.elapsed().as_millis(),
                snapshot.manifest().revision
            ),
        )?;
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
                })
                .await
                .map_err(|_| ClientError::Timeout)??
            }
        };
        tx.send(Event::Domains(domains.clone()))
            .map_err(|_| ClientError::Io)?;
        confirm.await.map_err(|_| ClientError::Io)?;
        source(path, digest)?;
        let current = timeout(Duration::from_secs(30), client.refresh_routing_policy())
            .await
            .map_err(|_| ClientError::Timeout)??;
        if current.digest() != expected {
            return Err(ClientError::Protocol);
        }
        let pin = cache.policy.pin(expected)?;
        emit(tx, format!("UDP Anti-DPI: {}. Локальные UDP-стратегии не запускаются; контроль XHTTP проверяет QUIC/HTTP3.", crate::routing::dpi::UdpStrategy::capability_summary()))?;
        let roots = tokio::task::spawn_blocking(crate::net::tls::native_roots)
            .await
            .map_err(|_| ClientError::Tls)?;
        let quic_tls = Arc::new(
            crate::net::tls::roots_tls13(roots.clone(), b"h3").map_err(|_| ClientError::Tls)?,
        );
        let tls =
            Arc::new(crate::net::tls::application_probe(roots).map_err(|_| ClientError::Tls)?);
        let proxy = proxy_lifecycle(&doc, id, digest, tx).await?;
        let mut proxy_checked = false;
        for domain in domains {
            source(path, digest)?;
            pin.check()?;
            let current = timeout(Duration::from_secs(15), client.refresh_routing_policy())
                .await
                .map_err(|_| ClientError::Timeout)??;
            if current.digest() != expected {
                return Err(ClientError::Protocol);
            }
            emit(tx, format!("── {domain} ──"))?;
            let (action, ips, pin) = match timeout(
                Duration::from_secs(12),
                egress::diagnostic_target(&carrier, cache, &domain, expected),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    record(tx, Some(&domain), CheckKind::Policy, Outcome::Failure(e))?;
                    if protective(e) {
                        return Err(e);
                    }
                    continue;
                }
                Err(_) => {
                    record(
                        tx,
                        Some(&domain),
                        CheckKind::Policy,
                        Outcome::Failure(ClientError::Timeout),
                    )?;
                    continue;
                }
            };
            record(tx, Some(&domain), CheckKind::Policy, Outcome::Route(action))?;
            if action == Action::Blocked {
                record(
                    tx,
                    Some(&domain),
                    CheckKind::Https("штатный"),
                    Outcome::Skipped("запрещено политикой"),
                )?;
                tx.send(Event::DomainDone(domain))
                    .map_err(|_| ClientError::Io)?;
                continue;
            }
            if action == Action::DirectDpi {
                match cache
                    .dpi
                    .diagnostic_tcp_strategies(&domain, &ips, &pin)
                    .await
                {
                    Ok(results) => {
                        if results.is_empty() {
                            record(
                                tx,
                                Some(&domain),
                                CheckKind::Strategy("TCP Anti-DPI".into()),
                                Outcome::Skipped("нет разрешённых/доступных проб"),
                            )?;
                        }
                        for (strategy, status, ms) in results {
                            record(
                                tx,
                                Some(&domain),
                                CheckKind::Strategy(strategy),
                                Outcome::Tls(status, ms),
                            )?;
                        }
                    }
                    Err(e) => {
                        record(
                            tx,
                            Some(&domain),
                            CheckKind::Strategy("TCP Anti-DPI".into()),
                            Outcome::Failure(e),
                        )?;
                        if protective(e) {
                            return Err(e);
                        }
                        continue;
                    }
                }
            } else {
                record(
                    tx,
                    Some(&domain),
                    CheckKind::Strategy("TCP Anti-DPI".into()),
                    Outcome::Skipped("не назначен правилами"),
                )?;
            }
            let result = Box::pin(https(
                &carrier,
                cache,
                &domain,
                expected,
                true,
                action,
                tls.clone(),
            ))
            .await;
            match result {
                Ok((code, route, ms)) => {
                    record(
                        tx,
                        Some(&domain),
                        CheckKind::Https("штатный"),
                        Outcome::Http(code, route, ms),
                    )?;
                }
                Err(e) => {
                    record(
                        tx,
                        Some(&domain),
                        CheckKind::Https("штатный"),
                        Outcome::Failure(e),
                    )?;
                    if protective(e) {
                        return Err(e);
                    }
                }
            }
            if !proxy_checked {
                if let Some(instance) = &proxy {
                    for (label, address, socks) in [
                        ("HTTP CONNECT", &doc.client.proxy.http_listen, false),
                        ("SOCKS5 CONNECT", &doc.client.proxy.socks5_listen, true),
                    ] {
                        let result =
                            proxy_https(instance, digest, address, socks, &domain, tls.clone())
                                .await;
                        match result {
                            Ok((code, ms)) => record(
                                tx,
                                Some(&domain),
                                CheckKind::Proxy(label),
                                Outcome::Http(code, ActualRoute::SystemProxy, ms),
                            )?,
                            Err(error) => {
                                record(
                                    tx,
                                    Some(&domain),
                                    CheckKind::Proxy(label),
                                    Outcome::Failure(error),
                                )?;
                                if protective(error) {
                                    return Err(error);
                                }
                            }
                        }
                    }
                }
                proxy_checked = true;
            }
            if action != Action::Direct {
                if action == Action::DirectDpi {
                    pin.check()?;
                    match Box::pin(udp_https(
                        &carrier,
                        cache,
                        &domain,
                        expected,
                        true,
                        action,
                        quic_tls.clone(),
                    ))
                    .await
                    {
                        Ok((status, route, ms)) => record(
                            tx,
                            Some(&domain),
                            CheckKind::Udp("штатный"),
                            Outcome::Udp(status, route, ms),
                        )?,
                        Err(error) => {
                            record(
                                tx,
                                Some(&domain),
                                CheckKind::Udp("штатный"),
                                Outcome::Failure(error),
                            )?;
                            if protective(error) {
                                return Err(error);
                            }
                        }
                    }
                }
                for (label, transport, _) in &verified {
                    match Box::pin(https(
                        transport,
                        cache,
                        &domain,
                        expected,
                        false,
                        action,
                        tls.clone(),
                    ))
                    .await
                    {
                        Ok((code, route, ms)) => record(
                            tx,
                            Some(&domain),
                            CheckKind::Https(label),
                            Outcome::Http(code, route, ms),
                        )?,
                        Err(e) => {
                            record(
                                tx,
                                Some(&domain),
                                CheckKind::Https(label),
                                Outcome::Failure(e),
                            )?;
                            if protective(e) {
                                return Err(e);
                            }
                        }
                    }
                    pin.check()?;
                    match Box::pin(udp_https(
                        transport,
                        cache,
                        &domain,
                        expected,
                        false,
                        action,
                        quic_tls.clone(),
                    ))
                    .await
                    {
                        Ok((status, route, ms)) => record(
                            tx,
                            Some(&domain),
                            CheckKind::Udp(label),
                            Outcome::Udp(status, route, ms),
                        )?,
                        Err(error) => {
                            record(
                                tx,
                                Some(&domain),
                                CheckKind::Udp(label),
                                Outcome::Failure(error),
                            )?;
                            if protective(error) {
                                return Err(error);
                            }
                        }
                    }
                }
            }
            tx.send(Event::DomainDone(domain))
                .map_err(|_| ClientError::Io)?;
        }
        emit(tx, "Завершено. HTTP-ответ подтверждает обмен, не доступность всех функций сайта. TLS-проба стратегии не доказывает наличие блокировки.")
    };
    let result = tokio::select! { biased; result = guard => result, result = checks => result };
    cache.policy.retire();
    result
}

fn protective(error: ClientError) -> bool {
    matches!(
        error,
        ClientError::Configuration
            | ClientError::Tls
            | ClientError::Unauthorized
            | ClientError::Protocol
            | ClientError::Open(
                crate::protocol::ErrorCode::PolicyDenied
                    | crate::protocol::ErrorCode::AddressInvalid
                    | crate::protocol::ErrorCode::UnsupportedVersion
                    | crate::protocol::ErrorCode::ProtocolError
                    | crate::protocol::ErrorCode::Truncated
                    | crate::protocol::ErrorCode::General
            )
            | ClientError::Rejected(400..=499)
    )
}

fn ca_digest(profile: &config::Profile) -> Result<Option<[u8; 32]>, ClientError> {
    profile
        .tls_ca
        .as_deref()
        .filter(|reference| reference.starts_with("file:"))
        .map(|reference| {
            let bytes = super::load_file(reference, super::CA_LIMIT, false)?;
            Ok(Sha256::digest(bytes.as_slice()).into())
        })
        .transpose()
}

async fn check_carrier(
    transport: Option<&Carrier>,
    scope: &str,
) -> Option<Result<([u8; 32], u128), ClientError>> {
    let transport = transport?;
    let started = Instant::now();
    Some(
        timeout(Duration::from_secs(30), async {
            let wire = transport.fetch_routing(None).await?;
            let scope = scope.to_owned();
            let digest = tokio::task::spawn_blocking(move || {
                Snapshot::decode(&wire, &scope).map(|s| s.digest())
            })
            .await
            .map_err(|_| ClientError::Protocol)?
            .map_err(|_| ClientError::Protocol)?;
            Ok((digest, started.elapsed().as_millis()))
        })
        .await
        .unwrap_or(Err(ClientError::Timeout)),
    )
}

async fn https(
    carrier: &Carrier,
    cache: &super::Cache,
    name: &str,
    digest: [u8; 32],
    allow_dpi: bool,
    action: Action,
    tls: Arc<rustls::ClientConfig>,
) -> Result<(u16, ActualRoute, u128), ClientError> {
    let started = Instant::now();
    timeout(Duration::from_secs(12), async {
        let authorization = cache.policy.pin(digest)?;
        let mut routed = egress::diagnostic_open(carrier, cache, name, digest, allow_dpi).await?;
        let direct = matches!(&routed.tunnel, ProxyTunnel::Direct(_));
        let observed = Arc::new(AtomicU8::new(routed.open_code()));
        let strategy = if let ProxyTunnel::Dpi(route) = &mut routed.tunnel {
            route.observed = Some(observed.clone());
            Some(route.tunnel.diagnostic_strategy())
        } else {
            None
        };
        let listener = bind_proxy_listener("127.0.0.1:0").await?;
        let addr = listener.local_addr().map_err(|_| ClientError::Io)?;
        let local = TcpStream::connect(addr)
            .await
            .map_err(|_| ClientError::Io)?;
        let (socket, peer) = listener.accept().await.map_err(|_| ClientError::Io)?;
        if local.local_addr().map_err(|_| ClientError::Io)? != peer {
            return Err(ClientError::Io);
        }
        drop(listener);
        let relay = routed.relay(socket);
        let app = application_head(local, name, tls);
        tokio::pin!(relay, app);
        let status = tokio::select! {
            biased;
            result = &mut app => result?,
            result = &mut relay => { result?; app.await? }
        };
        authorization.check()?;
        let code = observed.load(Ordering::Relaxed);
        let fallback = if allow_dpi && action == Action::DirectDpi {
            Some(if strategy.is_some() {
                FallbackCause::BeforeFirstSend
            } else if !cache.dpi.enabled() {
                FallbackCause::Disabled
            } else {
                FallbackCause::NoLocalRoute
            })
        } else {
            None
        };
        let route = match code >> 2 {
            2 => ActualRoute::Xhttp {
                carrier: "H2",
                mode: xhttp_observation(code & 3),
                fallback,
            },
            3 => ActualRoute::Xhttp {
                carrier: "H3",
                mode: xhttp_observation(code & 3),
                fallback,
            },
            _ if direct => ActualRoute::Direct,
            _ if allow_dpi => ActualRoute::AntiDpi(strategy.ok_or(ClientError::Protocol)?),
            _ => return Err(ClientError::Protocol),
        };
        Ok((status, route, started.elapsed().as_millis()))
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

async fn application_head(
    local: TcpStream,
    name: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<u16, ClientError> {
    let server_name = rustls::pki_types::ServerName::try_from(name.to_owned())
        .map_err(|_| ClientError::Configuration)?;
    let mut stream = tokio_rustls::TlsConnector::from(tls)
        .connect(server_name, local)
        .await
        .map_err(|_| ClientError::Tls)?;
    stream
        .write_all(
            format!("HEAD / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .map_err(|_| ClientError::Io)?;
    for _ in 0..5 {
        let mut line = Vec::new();
        loop {
            let b = stream.read_u8().await.map_err(|_| ClientError::Io)?;
            if b == b'\n' {
                break;
            }
            if line.len() >= 1024 {
                return Err(ClientError::Protocol);
            }
            line.push(b);
        }
        let code = status(&line)?;
        if code >= 200 {
            return Ok(code);
        }
        // Informational responses are not a completed application exchange.
        let mut tail = [0; 4];
        for _ in 0..8192 {
            tail.rotate_left(1);
            tail[3] = stream.read_u8().await.map_err(|_| ClientError::Io)?;
            if tail.ends_with(b"\r\n\r\n") || tail == [0, 0, b'\r', b'\n'] {
                break;
            }
        }
    }
    Err(ClientError::Protocol)
}

async fn proxy_lifecycle(
    doc: &config::ClientDocument,
    id: &str,
    digest: [u8; 32],
    tx: &Sender<Event>,
) -> Result<Option<crate::management::ProxyLifecycle>, ClientError> {
    use crate::management::{StatusCommand, StatusReply};
    if doc.client.active_profile != id {
        record(
            tx,
            None,
            CheckKind::Proxy("IPC"),
            Outcome::Skipped("выбран неактивный профиль"),
        )?;
        return Ok(None);
    }
    match timeout(
        Duration::from_secs(3),
        crate::management::query_client_environment(StatusCommand::ClientLifecycle),
    )
    .await
    {
        Ok(Ok(StatusReply::ClientLifecycle(view))) if view.config_sha256 == digest => {
            record(
                tx,
                None,
                CheckKind::Proxy("IPC"),
                Outcome::Proxy(view.phase, view.listeners_ready, view.proxy_applied),
            )?;
            Ok(
                (view.phase == 2 && view.listeners_ready && view.proxy_applied == 1)
                    .then_some(view),
            )
        }
        _ => {
            record(
                tx,
                None,
                CheckKind::Proxy("IPC"),
                Outcome::Skipped("владелец и применение настроек не подтверждены"),
            )?;
            Ok(None)
        }
    }
}

async fn check_proxy(
    instance: &crate::management::ProxyLifecycle,
    digest: [u8; 32],
) -> Result<(), ClientError> {
    use crate::management::{StatusCommand, StatusReply};
    match timeout(
        Duration::from_secs(3),
        crate::management::query_client_environment(StatusCommand::ClientLifecycle),
    )
    .await
    {
        Ok(Ok(StatusReply::ClientLifecycle(view)))
            if view.instance == instance.instance
                && view.revision == instance.revision
                && view.config_sha256 == digest
                && view.phase == 2
                && view.listeners_ready
                && view.proxy_applied == 1 =>
        {
            Ok(())
        }
        _ => Err(ClientError::Configuration),
    }
}
async fn proxy_https(
    instance: &crate::management::ProxyLifecycle,
    digest: [u8; 32],
    address: &str,
    socks: bool,
    name: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<(u16, u128), ClientError> {
    let started = Instant::now();
    check_proxy(instance, digest).await?;
    let status = timeout(Duration::from_secs(12), async {
        let address: std::net::SocketAddr =
            address.parse().map_err(|_| ClientError::Configuration)?;
        if !address.ip().is_loopback() {
            return Err(ClientError::Configuration);
        }
        let mut socket = TcpStream::connect(address)
            .await
            .map_err(|_| ClientError::Io)?;
        if socks {
            socket
                .write_all(&[5, 1, 0])
                .await
                .map_err(|_| ClientError::Io)?;
            let mut method = [0; 2];
            socket
                .read_exact(&mut method)
                .await
                .map_err(|_| ClientError::Io)?;
            if method != [5, 0] {
                return Err(ClientError::Protocol);
            }
            let len = u8::try_from(name.len()).map_err(|_| ClientError::Configuration)?;
            let mut req = vec![5, 1, 0, 3, len];
            req.extend_from_slice(name.as_bytes());
            req.extend_from_slice(&443u16.to_be_bytes());
            socket.write_all(&req).await.map_err(|_| ClientError::Io)?;
            let mut header = [0; 4];
            socket
                .read_exact(&mut header)
                .await
                .map_err(|_| ClientError::Io)?;
            if header[..3] != [5, 0, 0] {
                return Err(ClientError::Protocol);
            }
            let n = match header[3] {
                1 => 4,
                4 => 16,
                3 => usize::from(socket.read_u8().await.map_err(|_| ClientError::Io)?),
                _ => return Err(ClientError::Protocol),
            };
            socket
                .read_exact(&mut vec![0; n + 2])
                .await
                .map_err(|_| ClientError::Io)?;
        } else {
            socket
                .write_all(
                    format!("CONNECT {name}:443 HTTP/1.1\r\nHost: {name}:443\r\n\r\n").as_bytes(),
                )
                .await
                .map_err(|_| ClientError::Io)?;
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                if head.len() >= 8192 {
                    return Err(ClientError::Protocol);
                }
                head.push(socket.read_u8().await.map_err(|_| ClientError::Io)?);
            }
            let code = self::status(
                head.split(|b| *b == b'\n')
                    .next()
                    .ok_or(ClientError::Protocol)?,
            )?;
            if code != 200 {
                return Err(ClientError::Rejected(code));
            }
        }
        check_proxy(instance, digest).await?;
        application_head(socket, name, tls).await
    })
    .await
    .map_err(|_| ClientError::Timeout)??;
    check_proxy(instance, digest).await?;
    Ok((status, started.elapsed().as_millis()))
}

async fn udp_https(
    carrier: &Carrier,
    cache: &super::Cache,
    name: &str,
    digest: [u8; 32],
    automatic: bool,
    action: Action,
    tls: Arc<rustls::ClientConfig>,
) -> Result<(u16, ActualRoute, u128), ClientError> {
    use crate::quic_core::{dial, h3_adapter, handshake_udp, wire::Version};
    let started = Instant::now();
    timeout(Duration::from_secs(15), async {
        let observed = Arc::new(AtomicU8::new(0));
        let authorization = cache.policy.pin(digest)?;
        let local_selected = std::cell::Cell::new(false);
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.map_err(|_| ClientError::Io)?;
        let bridge = tokio::net::UdpSocket::bind("127.0.0.1:0").await.map_err(|_| ClientError::Io)?;
        let peer = bridge.local_addr().map_err(|_| ClientError::Io)?;
        bridge.connect(client.local_addr().map_err(|_| ClientError::Io)?).await.map_err(|_| ClientError::Io)?;
        client.connect(peer).await.map_err(|_| ClientError::Io)?;
        let relay_path = async {
            use crate::routing::dpi::udp::{Candidate, Observer};
            let mut buf = vec![0; 65535];
            let count = bridge.recv(&mut buf).await.map_err(|_| ClientError::Io)?;
            let first = buf[..count].to_vec();
            let mut observer = Observer::default();
            let mut candidate = if automatic { observer.outgoing(&first) } else { Candidate::Other };
            let mut pending = vec![first];
            let mut total = count;
            let deadline = tokio::time::Instant::now() + Duration::from_millis(30);
            while candidate == Candidate::Pending && pending.len() < 8 && total < 65536 {
                let Ok(result) = tokio::time::timeout_at(deadline, bridge.recv(&mut buf)).await else { break; };
                let n = result.map_err(|_| ClientError::Io)?;
                total = total.saturating_add(n);
                if total > 65536 { return Err(ClientError::Protocol); }
                candidate = observer.outgoing(&buf[..n]);
                pending.push(buf[..n].to_vec());
            }
            authorization.check()?;
            let routed = egress::diagnostic_udp(carrier, cache, name, digest, &observed, &candidate, &pending[0]).await?;
            routed.record_transport(&observed);
            local_selected.set(matches!(&routed.tunnel, crate::udp_relay::Tunnel::VerifiedLocal(..)));
            if !local_selected.get() && !matches!(observed.load(Ordering::Relaxed) >> 2, 2 | 3) { return Err(ClientError::Protocol); }
            let super::RoutedUdp { tunnel, flow } = routed;
            let (upload, upload_rx) = tokio::sync::mpsc::channel(8);
            let (download, mut download_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
            let relay = tunnel.relay_guarded(upload_rx, download, Some(&flow));
            let forward = async {
                for packet in pending { upload.send(packet).await.map_err(|_| ClientError::Io)?; }
                loop {
                    tokio::select! {
                        result = bridge.recv(&mut buf) => {
                            let count = result.map_err(|_| ClientError::Io)?;
                            upload.send(buf[..count].to_vec()).await.map_err(|_| ClientError::Io)?;
                        }
                        packet = download_rx.recv() => {
                            let packet = packet.ok_or(ClientError::Io)?;
                            if bridge.send(&packet).await.map_err(|_| ClientError::Io)? != packet.len() { return Err(ClientError::Io); }
                        }
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), ClientError>(())
            };
            tokio::select! {
                biased;
                result = flow.wait_revoked() => result,
                result = relay => result,
                result = forward => result,
            }
        };
        let app = async {
            let server_name = rustls::pki_types::ServerName::try_from(name.to_owned()).map_err(|_| ClientError::Configuration)?;
            let mut session = Box::pin(handshake_udp::connect_diagnostic_socket(client, peer, tls, server_name, Version::V1)).await.map_err(|error| {
                match error {
                    handshake_udp::Error::Timeout => ClientError::Timeout,
                    handshake_udp::Error::Scope => ClientError::Configuration,
                    _ => ClientError::Tls,
                }
            })?;
            dial::confirm(&mut session).await.map_err(|_| ClientError::Tls)?;
            let (transport, _) = h3_adapter::NativeConnection::start(session).map_err(|_| ClientError::Tls)?;
            let mut builder = h3::client::builder();
            builder.max_field_section_size(u64::from(crate::transport_policy::MAX_HEADER_LIST_BYTES));
            let (mut driver, mut sender) = builder.build::<_, _, bytes::Bytes>(transport).await.map_err(|_| ClientError::Http3)?;
            let request = async {
                let request = http::Request::head(format!("https://{name}/")).body(()).map_err(|_| ClientError::Configuration)?;
                let mut stream = sender.send_request(request).await.map_err(|_| ClientError::Http3)?;
                stream.finish().await.map_err(|_| ClientError::Http3)?;
                for _ in 0..5 {
                    let status = stream.recv_response().await.map_err(|_| ClientError::Http3)?.status().as_u16();
                    if status >= 200 { return Ok(status); }
                }
                Err(ClientError::Protocol)
            };
            tokio::select! {
                result = request => result,
                _ = std::future::poll_fn(|cx| driver.poll_close(cx)) => Err(ClientError::Http3),
            }
        };
        let status = tokio::select! {
            biased;
            result = relay_path => { result?; return Err(ClientError::Io); }
            result = app => result?,
        };
        authorization.check()?;
        let code = observed.load(Ordering::Relaxed);
        let fallback = if automatic && action == Action::DirectDpi {
            Some(if local_selected.get() { FallbackCause::BeforeFirstSend } else if !cache.dpi.enabled() { FallbackCause::Disabled } else { FallbackCause::NoLocalRoute })
        } else { None };
        let route = match code >> 2 {
            2 => ActualRoute::Xhttp { carrier: "H2", mode: xhttp_observation(code & 3), fallback },
            3 => ActualRoute::Xhttp { carrier: "H3", mode: xhttp_observation(code & 3), fallback },
            _ if local_selected.get() => ActualRoute::AntiDpi("QUIC v1"),
            _ => return Err(ClientError::Protocol),
        };
        Ok((status, route, started.elapsed().as_millis()))
    }).await.map_err(|_| ClientError::Timeout)?
}

fn status(line: &[u8]) -> Result<u16, ClientError> {
    let text = std::str::from_utf8(line).map_err(|_| ClientError::Protocol)?;
    let mut parts = text.split_whitespace();
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(ClientError::Protocol);
    }
    let code = parts.next().ok_or(ClientError::Protocol)?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ClientError::Protocol);
    }
    let code: u16 = code.parse().map_err(|_| ClientError::Protocol)?;
    if !(100..=599).contains(&code) {
        return Err(ClientError::Protocol);
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn security_failures_are_not_availability() {
        for error in [
            ClientError::Configuration,
            ClientError::Tls,
            ClientError::Unauthorized,
            ClientError::Protocol,
            ClientError::Rejected(403),
        ] {
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
