//! Conservative H3/H2 transport selection. A negative decision is scoped
//! to one profile and network generation, never a permission to replay OPEN.
use super::ProxyTunnel;
use crate::{
    client::{error_kind, ClientError, H2Client},
    diagnostics::Value,
    h3_client::H3Client,
    protocol::Address,
};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;

pub(super) const AUTO_QUIC_ATTEMPTS: usize = 2;

use crate::net::evidence::ScopedDecision as NegativeCache;

pub(super) struct AutoClient {
    pub(super) h2: Arc<H2Client>,
    pub(super) h3: Arc<H3Client>,
    ttl: Duration,
    pub(super) negative: Mutex<NegativeCache>,
    cache_changed: Notify,
    recheck_gate: tokio::sync::Mutex<()>,
}

impl AutoClient {
    pub(super) fn new(h2: Arc<H2Client>, h3: Arc<H3Client>, ttl: Duration) -> Self {
        Self {
            h2,
            h3,
            ttl,
            negative: Mutex::new(NegativeCache::default()),
            cache_changed: Notify::new(),
            recheck_gate: tokio::sync::Mutex::new(()),
        }
    }

    pub(super) fn observe(&self) -> Result<(u64, bool), ClientError> {
        let mut cache = self
            .negative
            .lock()
            .map_err(|_| ClientError::Configuration)?;
        let previous = cache.generation;
        let observed = cache.observe(
            crate::network_scope::observe(self.h3.remote()),
            Instant::now(),
        );
        if previous != cache.generation {
            self.cache_changed.notify_one();
        }
        Ok(observed)
    }

    pub(super) fn complete(&self, generation: u64, unreachable: bool) -> Result<bool, ClientError> {
        let mut cache = self
            .negative
            .lock()
            .map_err(|_| ClientError::Configuration)?;
        let current = crate::network_scope::observe(self.h3.remote());
        // Unknown routing is never cached. A known changed route must not
        // inherit a fallback decision obtained on the previous network.
        if current != cache.route {
            cache.route = current;
            cache.invalidate();
            self.cache_changed.notify_one();
        }
        if !unreachable {
            if cache.generation == generation {
                cache.invalidate();
                self.cache_changed.notify_one();
            }
            return Ok(false);
        }
        if cache.generation != generation || current.is_none() {
            return Ok(false);
        }
        if cache.record(generation, Instant::now(), self.ttl) {
            self.cache_changed.notify_one();
        }
        Ok(true)
    }

    /// Check the generation without consuming a due recheck. Both
    /// foreground and maintenance use this before taking another step.
    fn same_scope(&self, generation: u64) -> Result<bool, ClientError> {
        let mut cache = self
            .negative
            .lock()
            .map_err(|_| ClientError::Configuration)?;
        let scope = crate::network_scope::observe(self.h3.remote());
        if scope != cache.route || scope.is_none() {
            cache.route = scope;
            cache.invalidate();
            self.cache_changed.notify_one();
            return Ok(false);
        }
        Ok(cache.generation == generation)
    }

    /// The single fallback decision for tunnel, descriptor and background
    /// probe operations. Only a pre-authenticated QuicUnreachable result
    /// can reach the retry branch. Every other error remains terminal.
    pub(super) async fn attempt_h3<T, F, Fut>(
        &self,
        generation: u64,
        mut attempt: F,
    ) -> Result<Option<T>, ClientError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, ClientError>>,
    {
        for index in 0..AUTO_QUIC_ATTEMPTS {
            // Unknown network scope disables reuse and fallback, not a
            // first authenticated H3 connection attempt.
            if index > 0 && !self.same_scope(generation)? {
                return Err(ClientError::QuicUnreachable);
            }
            match attempt().await {
                Ok(value) => {
                    self.complete(generation, false)?;
                    return Ok(Some(value));
                }
                Err(error)
                    if crate::net::error::endpoint_unavailable(error)
                        == Some(crate::net::error::EndpointUnavailable::NoResponse)
                        && index + 1 < AUTO_QUIC_ATTEMPTS => {}
                Err(error) if crate::net::error::endpoint_unavailable(error).is_some() => {
                    if self.complete(generation, true)? {
                        return Ok(None);
                    }
                    crate::diag!(
                        Warn,
                        "client.auto",
                        "stale_quic_probe_rejected",
                        "generation" = Value::Count(generation)
                    );
                    return Err(ClientError::QuicUnreachable);
                }
                Err(error) => {
                    self.complete(generation, false)?;
                    crate::diag!(
                        Warn,
                        "client.auto",
                        "terminal_h3_failure_no_fallback",
                        "generation" = Value::Count(generation),
                        "reason" = Value::Label(error_kind(&error))
                    );
                    return Err(error);
                }
            }
        }
        Err(ClientError::Configuration)
    }

    /// A due negative-cache expiry has exactly one owner, whether a new
    /// tunnel or the maintenance timer arrives first. Keep the async gate
    /// only for that bounded credential-free probe, not for application OPEN.
    /// Cancellation discards evidence and releases the gate; no fallback
    /// can be published by a canceled probe.
    async fn prepare(&self) -> Result<(u64, bool), ClientError> {
        let _gate = self.recheck_gate.lock().await;
        let recheck = {
            let mut cache = self
                .negative
                .lock()
                .map_err(|_| ClientError::Configuration)?;
            let now = Instant::now();
            let scope = crate::network_scope::observe(self.h3.remote());
            match cache.expires {
                Some(deadline) if now >= deadline => {
                    let generation = cache.generation;
                    cache.begin_recheck(generation, deadline, scope, now)
                }
                _ => None,
            }
        };
        if let Some(generation) = recheck {
            match self.attempt_h3(generation, || self.h3.probe()).await {
                Ok(Some(())) => crate::diag!(Debug, "client.auto", "background_h3_verified"),
                Ok(None) => {}
                Err(error) => {
                    crate::diag!(
                        Warn,
                        "client.auto",
                        "background_h3_terminal_failure",
                        "reason" = Value::Label(error_kind(&error))
                    );
                    return Err(error);
                }
            }
        }
        self.observe()
    }

    /// One maintenance future per immutable carrier generation. Foreground
    /// requests use the exact same expiry gate. No detached probe survives
    /// runtime shutdown or a security/credential generation replacement.
    pub(super) async fn maintain(&self) -> Result<(), ClientError> {
        loop {
            let pending = self
                .negative
                .lock()
                .map_err(|_| ClientError::Configuration)?
                .expires;
            let Some(deadline) = pending else {
                self.cache_changed.notified().await;
                continue;
            };
            tokio::select! {
                _ = self.cache_changed.notified() => continue,
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
            }
            // Terminal remote errors invalidate evidence, not the running
            // local listener. The next request still verifies independently.
            let _ = self.prepare().await;
        }
    }

    pub(super) async fn fetch_routing(
        &self,
        known: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, ClientError> {
        let (generation, cached) = self.prepare().await?;
        if !cached {
            if let Some(value) = self
                .attempt_h3(generation, || self.h3.fetch_routing(known))
                .await?
            {
                return Ok(value);
            }
        }
        if !self.same_scope(generation)? {
            return Err(ClientError::QuicUnreachable);
        }
        self.h2.fetch_routing(known).await
    }

    pub(super) async fn resolve_routing(
        &self,
        name: &str,
        digest: [u8; 32],
    ) -> Result<Vec<IpAddr>, ClientError> {
        let (generation, cached) = self.prepare().await?;
        if !cached {
            if let Some(value) = self
                .attempt_h3(generation, || self.h3.resolve_routing(name, digest))
                .await?
            {
                return Ok(value);
            }
        }
        if !self.same_scope(generation)? {
            return Err(ClientError::QuicUnreachable);
        }
        self.h2.resolve_routing(name, digest).await
    }

    #[cfg(any(
        target_os = "linux",
        all(target_os = "windows", target_arch = "x86_64")
    ))]
    pub(super) async fn resolve_native_dns(
        &self,
        name: &str,
        digest: [u8; 32],
    ) -> Result<Vec<IpAddr>, ClientError> {
        let (generation, cached) = self.prepare().await?;
        if !cached {
            if let Some(value) = self
                .attempt_h3(generation, || self.h3.resolve_native_dns(name, digest))
                .await?
            {
                return Ok(value);
            }
        }
        if !self.same_scope(generation)? {
            return Err(ClientError::QuicUnreachable);
        }
        self.h2.resolve_native_dns(name, digest).await
    }

    pub(super) async fn fetch_identity_document(
        &self,
        successor: bool,
    ) -> Result<String, ClientError> {
        let (generation, cached) = self.prepare().await?;
        if !cached {
            if let Some(value) = self
                .attempt_h3(generation, || self.h3.fetch_identity_document(successor))
                .await?
            {
                return Ok(value);
            }
        }
        if !self.same_scope(generation)? {
            return Err(ClientError::QuicUnreachable);
        }
        self.h2.fetch_identity_document(successor).await
    }

    pub(super) async fn open_udp(
        &self,
        address: Address,
        port: u16,
    ) -> Result<crate::udp_relay::Tunnel, ClientError> {
        let (generation, cached) = self.prepare().await?;
        if !cached {
            if let Some(tunnel) = self
                .attempt_h3(generation, || self.h3.open_udp(address.clone(), port))
                .await?
            {
                return Ok(crate::udp_relay::Tunnel::H3(Box::new(tunnel)));
            }
        }
        if !self.same_scope(generation)? {
            return Err(ClientError::QuicUnreachable);
        }
        self.h2
            .open_udp(address, port)
            .await
            .map(Box::new)
            .map(crate::udp_relay::Tunnel::H2)
    }

    pub(super) async fn open(
        &self,
        address: Address,
        port: u16,
    ) -> Result<ProxyTunnel, ClientError> {
        let (generation, cached) = self.prepare().await?;
        crate::diag!(
            Debug,
            "client.auto",
            "transport_select",
            "generation" = Value::Count(generation),
            "negative_cache_hit" = Value::Flag(cached)
        );
        // XHTTP caches remain carrier-local; only the configured mode
        // restriction crosses the transport boundary.
        if !cached {
            if let Some(tunnel) = self
                .attempt_h3(generation, || self.h3.open(address.clone(), port))
                .await?
            {
                crate::diag!(
                    Debug,
                    "client.auto",
                    "selected_h3",
                    "generation" = Value::Count(generation)
                );
                eprintln!("transport=h3");
                return Ok(ProxyTunnel::H3(Box::new(tunnel)));
            }
            crate::diag!(
                Warn,
                "client.auto",
                "h3_udp_silent_fallback_h2",
                "generation" = Value::Count(generation)
            );
            eprintln!("transport=h2 reason=quic_unreachable");
        } else {
            crate::diag!(
                Debug,
                "client.auto",
                "negative_cache_fallback_h2",
                "generation" = Value::Count(generation)
            );
            eprintln!("transport=h2 reason=quic_negative_cache");
        }
        if !self.same_scope(generation)? {
            return Err(ClientError::QuicUnreachable);
        }
        self.h2
            .open(address, port)
            .await
            .map(Box::new)
            .map(ProxyTunnel::H2)
    }
}
