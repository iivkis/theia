//! Windows System Proxy ownership and CAS recovery. CLI and TUI share
//! this exact session owner, including cancellation and bounded cleanup.
use super::*;

/// Sole product owner for Windows System Proxy, shared by CLI and TUI.
#[cfg(windows)]
pub(crate) struct SystemProxySession {
    runtime: Arc<ClientRuntime>,
    task: Option<tokio::task::JoinHandle<Result<(), ClientError>>>,
}

#[cfg(windows)]
impl ClientRuntime {
    fn set_proxy_phase(&self, phase: u8) {
        self.system_proxy_phase.store(phase, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn proxy_phase(&self) -> u8 {
        self.system_proxy_phase.load(std::sync::atomic::Ordering::Acquire)
    }

    async fn disconnect_requested(&self) {
        let mut stop = self.disconnect_requested.subscribe();
        if !*stop.borrow() { let _ = stop.wait_for(|requested| *requested).await; }
    }

    fn request_disconnect(&self) {
        let _publication = self.publication.lock().unwrap_or_else(|e| e.into_inner());
        self.quiesce_locked();
        if self.proxy_phase() == 2 { self.set_proxy_phase(3); }
        self.disconnect_requested.send_replace(true);
    }

    /// The nonsecret instance nonce changes on every Connect, including
    /// reconnect to the same TOML at the same revision.
    pub(crate) fn proxy_lifecycle(&self) -> Option<crate::management::ProxyLifecycle> {
        let _publication = self.publication.lock().ok()?;
        let view = self.slot.borrow();
        Some(crate::management::ProxyLifecycle {
            revision: view.revision,
            config_sha256: view.digest,
            instance: *self.proxy_instance.get()?,
            phase: self.proxy_phase(),
            listeners_ready: self.proxy_phase() == 2 && self.admitting(),
            proxy_applied: self.system_proxy_applied.load(std::sync::atomic::Ordering::Acquire),
        })
    }

    fn set_proxy_applied(&self, value: u8) {
        self.system_proxy_applied.store(value, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn request_disconnect_bound(
        &self, revision: u64, digest: [u8; 32], instance: [u8; 32],
    ) -> Result<(), ClientError> {
        let _publication = self.publication.lock().map_err(|_| ClientError::Configuration)?;
        let view = self.slot.borrow();
        if self.proxy_phase() != 2 || !self.admitting()
            || view.revision != revision || view.digest != digest
            || self.proxy_instance.get() != Some(&instance) {
            return Err(ClientError::Configuration);
        }
        drop(view);
        self.quiesce_locked();
        self.set_proxy_phase(3);
        self.disconnect_ipc.store(true, std::sync::atomic::Ordering::Release);
        self.disconnect_requested.send_replace(true);
        Ok(())
    }

    pub(crate) fn mark_disconnect_reply_done(&self) {
        self.disconnect_reply_done.send_replace(true);
    }

    async fn wait_disconnect_reply(&self) {
        if self.disconnect_ipc.load(std::sync::atomic::Ordering::Acquire) {
            let mut done = self.disconnect_reply_done.subscribe();
            if !*done.borrow() { let _ = done.wait_for(|done| *done).await; }
        }
    }
}

#[cfg(windows)]
impl SystemProxySession {
    pub(crate) async fn connect(
        path: &Path,
        expected: [u8; 32],
        review: Option<crate::windows_system_proxy::ApplyReview>,
    ) -> Result<Self, ClientError> {
        // Acquire the global per-user owner BEFORE DNS or opening listeners.
        let reservation = crate::windows_system_proxy::ReservedProxy::acquire()
            .map_err(|_| ClientError::SystemProxy)?;
        let bytes = saved_client_bytes(path, expected)?;
        let Config::Client(document) = config::parse(
            std::str::from_utf8(&bytes).map_err(|_| ClientError::Configuration)?
        ).map_err(|_| ClientError::Configuration)? else {
            return Err(ClientError::Configuration);
        };
        let (http, socks, client) = prepare_proxy(&document, path).await?;
        let bind = http.local_addr().map_err(|_| ClientError::Io)?;
        let runtime = ClientRuntime::new(
            std::path::absolute(path).map_err(|_| ClientError::Configuration)?,
            document, expected, client,
        );
        use ring::rand::{SecureRandom, SystemRandom};
        let mut instance = [0; 32];
        SystemRandom::new().fill(&mut instance).map_err(|_| ClientError::Configuration)?;
        runtime.proxy_instance.set(instance).map_err(|_| ClientError::Configuration)?;
        runtime.set_proxy_phase(1); // preparing, not ready
        let control = crate::management::client_server(runtime.clone())
            .map_err(|_| ClientError::Configuration)?;
        saved_client_bytes(path, expected)?;
        let lease = reservation.apply(bind, review).map_err(|_| ClientError::SystemProxy)?;
        lease.verify().map_err(|_| ClientError::SystemProxy)?;
        runtime.set_proxy_applied(1);
        runtime.set_proxy_phase(2); // both listeners bound + exact OS readback
        let owner = runtime.clone();
        let task = tokio::spawn(async move {
            let mut lease = lease;
            let (restored, result, cleanup) = {
            let serving = serve_managed_proxy(http, socks, owner.clone());
            tokio::pin!(serving);
            let management = async move {
                match control {
                    Some(server) => server.serve().await.map_err(|_| ClientError::Io),
                    None => std::future::pending::<Result<(), ClientError>>().await,
                }
            };
            tokio::pin!(management);
            // Inspect the exact journal and current WinINet snapshot even
            // when no traffic or UI action occurs.
            let (result, worker_ended, management_ended) = loop {
                tokio::select! {
                    biased;
                    () = owner.disconnect_requested() => break (Ok(()), false, false),
                    result = &mut serving => break (result, true, false),
                    result = &mut management => break (result, false, true),
                    () = tokio::time::sleep(Duration::from_secs(1)) => {
                        if lease.verify().is_err() {
                            owner.set_proxy_applied(2);
                            break (Err(ClientError::SystemProxy), false, false);
                        }
                    }
                }
            };
            // Block new application admission and revoke active payload
            // permissions before touching OS settings. Keep the listener
            // future owned until the CAS restore finishes.
            owner.set_proxy_phase(3);
            owner.quiesce();
            let restored = lease.restore_held().map_err(|_| ClientError::SystemProxy);
            owner.set_proxy_applied(if restored.is_ok() { 0 } else { 2 });
            owner.stop();
            let drain = async {
                if worker_ended {
                    Ok(())
                } else {
                    timeout(Duration::from_secs(5), &mut serving).await
                        .map_err(|_| ClientError::Timeout)?
                }
            };
            let replies = async {
                if !management_ended {
                    // Await completion of the already-admitted reply, not
                    // an arbitrary fixed grace period. A vanished caller
                    // never prevents eventual shutdown.
                    tokio::select! {
                        () = owner.wait_disconnect_reply() => {},
                        _ = &mut management => {},
                        () = tokio::time::sleep(Duration::from_secs(2)) => {},
                    }
                }
            };
            let (cleanup, ()) = tokio::join!(drain, replies);
            (restored, result, cleanup)
            }; // all serving/management futures and sockets dropped here
            // The product owner remains reserved across CAS and all
            // bounded cleanup. On conflict leave the journal for recovery.
            owner.set_proxy_phase(if restored.is_ok() { 0 } else { 4 });
            if restored.is_err() { lease.abandon_after_conflict(); } else { drop(lease); }
            restored.and(result).and(cleanup)
        });
        Ok(Self { runtime, task: Some(task) })
    }

    pub(crate) fn running(&self) -> bool {
        self.task.as_ref().is_some_and(|task| !task.is_finished())
    }

    pub(crate) fn applied(&self) -> bool {
        self.runtime.proxy_phase() == 2
            && self.runtime.system_proxy_applied.load(std::sync::atomic::Ordering::Acquire) == 1
            && self.running()
    }

    pub(crate) async fn report(&self) -> String {
        let view = self.runtime.slot.borrow().clone();
        view.client.runtime_report().await
    }

    pub(crate) async fn ended(&mut self) -> Result<(), ClientError> {
        let result = match self.task.as_mut() {
            Some(task) => task.await,
            None => return Ok(()),
        };
        self.task.take();
        result.map_err(|_| ClientError::Io)?
    }

    pub(crate) async fn disconnect(&mut self) -> Result<(), ClientError> {
        self.runtime.request_disconnect();
        self.ended().await
    }
}

#[cfg(windows)]
impl Drop for SystemProxySession {
    fn drop(&mut self) {
        self.runtime.request_disconnect();
    }
}

