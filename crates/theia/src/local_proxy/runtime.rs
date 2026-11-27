//! Client generation publication, admission and capture lifecycle.
use super::*;

// The process-level generation owns the exact saved config. Old accepted
// sockets retain their carrier clone; only new accepts use the new snapshot.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) struct ClientView {
    pub(super) document: config::ClientDocument,
    pub(super) digest: [u8; 32],
    pub(super) revision: u64,
    pub(super) client: ProxyClient,
}
// One atomic lifecycle: a concurrent Stop must never be overwritten by
// preparation or a backend's final readiness publication. State 4 is an
// internal terminal state for runtimes that never owned native capture.
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[derive(Default)]
pub(super) struct CaptureLifecycle(std::sync::atomic::AtomicU8);

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl CaptureLifecycle {
    pub(super) fn idle(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire) == 0
    }

    pub(super) fn running(&self) -> bool {
        matches!(self.0.load(std::sync::atomic::Ordering::Acquire), 1 | 2)
    }

    pub(super) fn accepting(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire) == 2
    }

    pub(super) fn begin(&self) -> Result<(), ClientError> {
        self.transition(0, 1)
    }

    pub(super) fn ready(&self) -> Result<(), ClientError> {
        self.transition(1, 2)
    }

    fn transition(&self, from: u8, to: u8) -> Result<(), ClientError> {
        use std::sync::atomic::Ordering;
        self.0
            .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ClientError::Configuration)
    }

    pub(super) fn stop(&self) {
        use std::sync::atomic::Ordering;
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            let next = match state {
                0 => 4,
                1 | 2 => 3,
                _ => return,
            };
            match self
                .0
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(observed) => state = observed,
            }
        }
    }

    pub(super) fn reported(&self) -> u8 {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            4 => 0,
            state => state,
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
mod capture_lifecycle_tests {
    use super::CaptureLifecycle;

    #[test]
    fn stopped_before_preparation_cannot_publish_capture() {
        let state = CaptureLifecycle::default();
        assert!(state.idle());
        state.stop();
        assert_eq!(state.reported(), 0);
        assert!(!state.idle());
        assert!(!state.running());
        assert!(state.begin().is_err());
        assert!(state.ready().is_err());
        state.stop();
        assert_eq!(state.reported(), 0);
    }

    #[test]
    fn interrupted_preparation_is_recovery_required() {
        let state = CaptureLifecycle::default();
        assert!(state.ready().is_err());
        state.begin().unwrap();
        assert_eq!(state.reported(), 1);
        assert!(state.running());
        assert!(!state.accepting());
        assert!(state.begin().is_err());
        state.stop();
        assert_eq!(state.reported(), 3);
        assert!(state.ready().is_err());
        assert!(state.begin().is_err());
        assert!(!state.running());
        state.stop();
        assert_eq!(state.reported(), 3);
    }

    #[test]
    fn ready_then_stop_is_terminal() {
        let state = CaptureLifecycle::default();
        state.begin().unwrap();
        state.ready().unwrap();
        assert_eq!(state.reported(), 2);
        assert!(state.accepting());
        assert!(state.ready().is_err());
        assert!(state.running());
        state.stop();
        assert_eq!(state.reported(), 3);
        assert!(!state.running());
        assert!(!state.accepting());
        assert!(state.ready().is_err());
    }

    #[test]
    fn concurrent_ready_and_stop_cannot_resurrect_capture() {
        let state = CaptureLifecycle::default();
        state.begin().unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                let _ = state.ready();
            });
            barrier.wait();
            state.stop();
        });
        assert_eq!(state.reported(), 3);
        assert!(!state.running());
        assert!(state.ready().is_err());
    }

    #[test]
    fn concurrent_prepare_and_stop_never_leaves_a_live_state() {
        let state = CaptureLifecycle::default();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                let _ = state.begin();
            });
            barrier.wait();
            state.stop();
        });
        assert!(matches!(state.reported(), 0 | 3));
        assert!(!state.running());
        assert!(!state.idle());
        assert!(state.begin().is_err());
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) struct ClientRuntime {
    pub(super) path: std::path::PathBuf,
    pub(super) slot: tokio::sync::watch::Sender<Arc<ClientView>>,
    // Bound one staging operation per process, with no commit on cancellation.
    pub(super) stage: tokio::sync::Mutex<()>,
    pub(super) capture_state: CaptureLifecycle,
    pub(super) stopped: tokio::sync::watch::Sender<bool>,
    pub(super) admission: std::sync::atomic::AtomicBool,
    pub(super) publication: Mutex<()>,
    #[cfg(windows)]
    pub(super) proxy_instance: std::sync::OnceLock<[u8; 32]>,
    #[cfg(windows)]
    pub(super) system_proxy_phase: std::sync::atomic::AtomicU8,
    #[cfg(windows)]
    pub(super) system_proxy_applied: std::sync::atomic::AtomicU8,
    #[cfg(windows)]
    pub(super) disconnect_requested: tokio::sync::watch::Sender<bool>,
    #[cfg(windows)]
    pub(super) disconnect_ipc: std::sync::atomic::AtomicBool,
    #[cfg(windows)]
    pub(super) disconnect_reply_done: tokio::sync::watch::Sender<bool>,
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
impl ClientRuntime {
    pub(super) fn new(
        path: std::path::PathBuf,
        document: config::ClientDocument,
        digest: [u8; 32],
        client: ProxyClient,
    ) -> Arc<Self> {
        let (slot, _) = tokio::sync::watch::channel(Arc::new(ClientView {
            document,
            digest,
            revision: 1,
            client,
        }));
        let (stopped, _) = tokio::sync::watch::channel(false);
        Arc::new(Self {
            path,
            slot,
            stage: tokio::sync::Mutex::new(()),
            capture_state: CaptureLifecycle::default(),
            stopped,
            admission: std::sync::atomic::AtomicBool::new(true),
            publication: Mutex::new(()),
            #[cfg(windows)]
            proxy_instance: std::sync::OnceLock::new(),
            #[cfg(windows)]
            system_proxy_phase: std::sync::atomic::AtomicU8::new(0),
            #[cfg(windows)]
            system_proxy_applied: std::sync::atomic::AtomicU8::new(0),
            #[cfg(windows)]
            disconnect_requested: tokio::sync::watch::channel(false).0,
            #[cfg(windows)]
            disconnect_ipc: std::sync::atomic::AtomicBool::new(false),
            #[cfg(windows)]
            disconnect_reply_done: tokio::sync::watch::channel(false).0,
        })
    }
    pub(super) fn admitting(&self) -> bool {
        self.admission.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(super) fn quiesce_locked(&self) {
        self.admission.store(false, std::sync::atomic::Ordering::Release);
        self.slot.borrow().client.routing_cache().policy.retire();
    }

    pub(super) fn quiesce(&self) {
        // Serialize admission retirement with exact-generation publication.
        // On poison still close admission and retire the last visible owner.
        let _publication = self.publication.lock().unwrap_or_else(|e| e.into_inner());
        self.quiesce_locked();
    }

    pub(super) fn stop(&self) {
        self.quiesce();
        // Capture rules may remain after the queue stops. Never publish
        // inactive/connected until the owner has finished recovery.
        self.capture_state.stop();
        self.stopped.send_replace(true);
    }

    pub(super) async fn stopped(&self) {
        let mut stop = self.stopped.subscribe();
        if !*stop.borrow() {
            let _ = stop.wait_for(|stopped| *stopped).await;
        }
    }

    pub(crate) async fn status(
        &self,
    ) -> (
        u64,
        [u8; 32],
        u64,
        u8,
        u8,
        bool,
        (u64, u8),
        [u64; 38],
        Option<[u16; 4]>,
        u8,
    ) {
        let view = self.slot.borrow().clone();
        let (desc, observed, fallback) = match &view.client {
            ProxyClient::Reality(r) => {
                let g = r.current.lock().await.clone();
                let fallback = match &g.carrier {
                    Carrier::Auto(a) => a.negative.lock().ok().is_some_and(|c| {
                        c.route.is_some()
                            && c.route == crate::network_scope::observe(a.h3.remote())
                            && c.expires.is_some_and(|t| t > Instant::now())
                    }),
                    _ => false,
                };
                (
                    g.value.descriptor().revision,
                    g.last_open.load(std::sync::atomic::Ordering::Relaxed),
                    fallback,
                )
            }
            ProxyClient::Direct(d) => (
                0,
                d.last_open.load(std::sync::atomic::Ordering::Relaxed),
                d.fallback(),
            ),
        };
        (
            view.revision,
            view.digest,
            desc,
            observed >> 2,
            observed & 3,
            fallback,
            view.client.routing_cache().observation(),
            crate::traffic::routing_totals(),
            view.client.routing_cache().flows.counts(),
            self.capture_state.reported(),
        )
    }
    async fn candidate(
        &self,
        previous: &ClientView,
        digest: [u8; 32],
    ) -> Result<(config::ClientDocument, ProxyClient), ClientError> {
        let raw = saved_client_bytes(&self.path, digest)?;
        let Config::Client(candidate) =
            config::parse(std::str::from_utf8(&raw).map_err(|_| ClientError::Configuration)?)
                .map_err(|_| ClientError::Configuration)?
        else {
            return Err(ClientError::Configuration);
        };
        // Structural loopback and OS proxy changes require explicit stop/start.
        if candidate.client.ingress_mode != previous.document.client.ingress_mode
            || candidate.client.proxy != previous.document.client.proxy
            || candidate.management != previous.document.management
        {
            return Err(ClientError::Configuration);
        }
        let old = previous
            .document
            .client
            .profiles
            .iter()
            .find(|p| p.id == previous.document.client.active_profile)
            .ok_or(ClientError::Configuration)?;
        let next = candidate
            .client
            .profiles
            .iter()
            .find(|p| p.id == candidate.client.active_profile)
            .ok_or(ClientError::Configuration)?;
        // No in-place replacement of any existing independently enrolled root.
        for prior in &previous.document.client.profiles {
            if let Some(new) = candidate.client.profiles.iter().find(|p| p.id == prior.id) {
                if prior.security_mode != new.security_mode
                    || (prior.reality_profile != new.reality_profile
                        && !crate::reality_config::credential_only_change(prior, new))
                {
                    return Err(ClientError::Configuration);
                }
            }
        }
        if old.security_mode != next.security_mode {
            return Err(ClientError::Configuration);
        }
        let client = if old.id == next.id {
            load_client_with_budget(next, previous.client.profile_budget(), Some(&self.path))
                .await?
        } else {
            load_client_with_budget(
                next,
                crate::connection_pool::profile_budget(),
                Some(&self.path),
            )
            .await?
        };
        client
            .routing_cache()
            .dpi
            .set_enabled(next.direct_dpi.unwrap_or(false));
        client
            .routing_cache()
            .dpi
            .set_stun_enabled(next.direct_dpi_stun.unwrap_or(false));
        Box::pin(client.routing_policy()).await?;
        saved_client_bytes(&self.path, digest)?;
        Ok((candidate, client))
    }
    pub(crate) async fn change(
        &self,
        expected: u64,
        digest: [u8; 32],
        apply: bool,
    ) -> Result<u64, ClientError> {
        let _stage = self
            .stage
            .try_lock()
            .map_err(|_| ClientError::Configuration)?;
        if !self.admitting() || *self.stopped.borrow() || !self.capture_state.idle() {
            return Err(ClientError::Configuration);
        }
        let previous = self.slot.borrow().clone();
        if previous.revision != expected || previous.digest == digest {
            return Err(ClientError::Configuration);
        }
        let (document, client) = self.candidate(&previous, digest).await?;
        if !apply {
            return Ok(expected);
        }
        let revision = expected.checked_add(1).ok_or(ClientError::Configuration)?;
        // Disconnect and publication cannot cross each other between the
        // final admission check and the new generation becoming visible.
        let _publication = self.publication.lock().map_err(|_| ClientError::Configuration)?;
        saved_client_bytes(&self.path, digest)?;
        if !self.admitting() || *self.stopped.borrow() {
            return Err(ClientError::Configuration);
        }
        previous.client.routing_cache().policy.retire();
        self.slot.send_replace(Arc::new(ClientView {
            document,
            digest,
            revision,
            client,
        }));
        Ok(revision)
    }
    pub(super) async fn maintain(&self) -> Result<(), ClientError> {
        let mut changes = self.slot.subscribe();
        loop {
            let view = changes.borrow_and_update().clone();
            let maintenance = async { view.client.maintain().await };
            tokio::select! {
                biased;
                ()=self.stopped()=>return Ok(()),
                result=maintenance=>return result,
                result=changes.changed()=>if result.is_err(){return Err(ClientError::Io);},
            }
        }
    }
}

