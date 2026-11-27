//! Future native ingress adapters and isolated platform capabilities.
//! Not a System Proxy dependency and not activated by the MVP runtime.
use super::*;

impl ClientRuntime {
    /// Pin exactly the published client generation for native capture.
    /// A structural or profile update needs explicit stop/recovery until
    /// carrier and rule changes can be committed in one platform transaction.
    async fn attach_native(
        self: &Arc<Self>,
        owner: Arc<NativeOwner>,
        registrar: Option<Arc<dyn crate::routing::carrier_socket::Registrar>>,
    ) -> Result<NativeIngress, ClientError> {
        let _stage = self
            .stage
            .try_lock()
            .map_err(|_| ClientError::Configuration)?;
        if !self.admitting() || *self.stopped.borrow() || !self.capture_state.idle() {
            return Err(ClientError::Configuration);
        }
        let view = self.slot.borrow().clone();
        saved_client_bytes(&self.path, view.digest)?;
        crate::routing::carrier_socket::scope(registrar.clone(), view.client.routing_policy())
            .await?;
        saved_client_bytes(&self.path, view.digest)?;
        if !self.admitting() || *self.stopped.borrow() {
            return Err(ClientError::Configuration);
        }
        self.capture_state.begin()?;
        Ok(NativeIngress {
            runtime: self.clone(),
            client: view.client.clone(),
            revision: view.revision,
            registrar: Mutex::new(registrar),
            verdict_gate: Mutex::new(()),
            #[cfg(all(target_os="windows",target_arch="x86_64"))]
            windows_modify: Mutex::new(None),
            #[cfg(target_os = "linux")]
            raw: Mutex::new(std::collections::HashMap::new()),
            #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
            dns_probe_hints: Mutex::new(crate::routing::native_dns::ProbeHints::default()),
            #[cfg(target_os="linux")]
            unified:std::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            udp_consumer: std::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            tcp_consumer: std::sync::atomic::AtomicBool::new(false),
            _owner: owner,
        })
    }

}

/// Experimental native-ingress adapter for an already isolated platform
/// harness. It uses the same authenticated client, classifier, shared flow
/// table and H2/H3 carrier as explicit proxy ingress. It does NOT install
/// system rules, assert capture readiness, or provide an egress exemption.
/// A production backend must own those operations before calling it.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub struct NativeIngress {
    #[cfg(test)]
    // Existing end-to-end regression observes the exact lifecycle.
    pub(super) runtime: Arc<ClientRuntime>,
    #[cfg(not(test))]
    runtime: Arc<ClientRuntime>,
    client: ProxyClient,
    revision: u64,
    registrar: Mutex<Option<Arc<dyn crate::routing::carrier_socket::Registrar>>>,
    verdict_gate: Mutex<()>,
    #[cfg(all(target_os="windows",target_arch="x86_64"))]
    windows_modify: Mutex<Option<Arc<crate::routing::windivert::CarrierRegistry>>>,
    #[cfg(target_os = "linux")]
    raw: Mutex<std::collections::HashMap<crate::routing::packet::FlowKey, RawLease>>,
    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    dns_probe_hints: Mutex<crate::routing::native_dns::ProbeHints>,
    #[cfg(target_os="linux")]
    unified:std::sync::atomic::AtomicBool,
    #[cfg(target_os = "linux")]
    udp_consumer: std::sync::atomic::AtomicBool,
    #[cfg(target_os = "linux")]
    tcp_consumer: std::sync::atomic::AtomicBool,
    _owner: Arc<NativeOwner>,
}

/// A single experimental packet strategy bound to a specific native flow.
/// The caller must prepare it before activating isolated queue rules.
/// It is not a DNS/application attribution credential.
#[cfg(target_os = "linux")]
pub struct LabStunPermit {
    key: crate::routing::packet::FlowKey,
    flow: crate::routing::flow::FlowLease,
    engine: Arc<crate::routing::dpi::Engine>,
    verified: crate::routing::dpi::VerifiedUdp,
    failed: bool,
}

#[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
struct ProtectedDnsAnswer {
    key:crate::routing::packet::FlowKey,
    wire:Vec<u8>,
    digest:[u8;32],
    // Diagnostic only; publish after a successful local response write.
    hint:Option<(String,Vec<IpAddr>)>,
}

#[cfg(target_os = "linux")]
struct RawLease {
    flow: Option<crate::routing::flow::FlowLease>,
    action:crate::routing::PacketAction,
    digest: [u8; 32],
    last: Instant,
    denied: bool,
    socket_cookie:Option<u64>,
    dns_capture:crate::routing::native_dns::CapturedQueries,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
static NATIVE_OWNER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// Field destruction is ordered: release the kernel scope handle before
// allowing another owner in this process to try to acquire it.
#[cfg(any(target_os = "linux", target_os = "windows"))]
struct ProcessOwner;

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Drop for ProcessOwner {
    fn drop(&mut self) {
        NATIVE_OWNER.store(false, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) struct NativeOwner {
    #[cfg(target_os = "linux")]
    _scope: std::os::unix::net::UnixDatagram,
    #[cfg(target_os = "windows")]
    _scope: std::os::windows::io::OwnedHandle,
    _process: ProcessOwner,
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
impl NativeOwner {
    pub(super) fn acquire() -> Result<Self, ClientError> {
        NATIVE_OWNER
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map_err(|_| ClientError::Configuration)?;
        match Self::scope() {
            Ok(owner) => Ok(owner),
            Err(error) => {
                NATIVE_OWNER.store(false, std::sync::atomic::Ordering::Release);
                Err(error)
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn scope() -> Result<Self, ClientError> {
        use std::os::linux::net::SocketAddrExt;
        // Abstract Unix socket names are scoped to the network namespace.
        // Kernel closes the ownership handle on crash; no stale PID file.
        let address =
            std::os::unix::net::SocketAddr::from_abstract_name(b"theia-native-ingress-v1")
                .map_err(|_| ClientError::Configuration)?;
        let socket = std::os::unix::net::UnixDatagram::bind_addr(&address)
            .map_err(|_| ClientError::Configuration)?;
        Ok(Self { _scope: socket, _process: ProcessOwner })
    }

    #[cfg(target_os = "windows")]
    fn scope() -> Result<Self, ClientError> {
        use std::{
            os::windows::io::{FromRawHandle, OwnedHandle},
            ptr,
        };
        use windows_sys::Win32::{
            Foundation::{GetLastError, ERROR_ALREADY_EXISTS},
            System::Threading::CreateEventW,
        };
        // An event is a lifetime handle, not a thread-affine mutex. We
        // reject an existing object instead of sharing or stealing it.
        let name: Vec<u16> = "Global\\Theia.NativeIngress.v1"
            .encode_utf16()
            .chain([0])
            .collect();
        let raw = unsafe { CreateEventW(ptr::null(), 1, 0, name.as_ptr()) };
        if raw.is_null() {
            return Err(ClientError::Configuration);
        }
        let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        // SAFETY: CreateEventW returned one owned non-null kernel handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        if existed {
            return Err(ClientError::Configuration);
        }
        Ok(Self { _scope: handle, _process: ProcessOwner })
    }
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
impl NativeIngress {
    /// Preflight only; the caller owns an isolated network namespace/rule
    /// transaction. No new CLI or second system interception mode.
    pub async fn prepare(path: &Path) -> Result<Self, ClientError> {
        Self::prepare_with_registrar(path,None).await
    }

    async fn prepare_with_registrar(path:&Path, registrar:Option<Arc<dyn crate::routing::carrier_socket::Registrar>>)->Result<Self,ClientError> {
        let owner = Arc::new(NativeOwner::acquire()?);
        let raw = zeroize::Zeroizing::new(
            config::editor_bytes(path).map_err(|_| ClientError::Configuration)?,
        );
        let Config::Client(document) =
            config::parse(std::str::from_utf8(&raw).map_err(|_| ClientError::Configuration)?)
                .map_err(|_| ClientError::Configuration)?
        else {
            return Err(ClientError::Configuration);
        };
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(raw.as_slice()).into();
        let client = crate::routing::carrier_socket::scope(registrar.clone(),prepare_client(&document,path)).await?;
        saved_client_bytes(path, digest)?;
        let runtime = ClientRuntime::new(
            std::path::absolute(path).map_err(|_| ClientError::Configuration)?,
            document,
            digest,
            client,
        );
        runtime.attach_native(owner, registrar).await
    }

    /// Cancels all native relay operations, retires the policy lease and
    /// leaves the externally owned OS capture rules untouched. The platform
    /// owner must perform its own authenticated CAS restoration on explicit Stop.
    pub fn shutdown(&self) {
        let _gate = self.verdict_gate.lock();
        self.runtime.stop();
        self.client.routing_cache().policy.retire();
        if let Ok(mut registrar) = self.registrar.lock() {
            if let Some(registrar)=registrar.take() {
                // Other tasks may still hold Arc clones and carrier
                // drivers may still hold leases. Retire the shared
                // backend explicitly before dropping our reference.
                let _=registrar.retire();
            }
        }
        #[cfg(target_os = "linux")]
        if let Ok(mut raw) = self.raw.lock() {
            raw.clear();
        }
    }

    pub(super) async fn stopped(&self) {
        self.runtime.stopped().await;
    }

    fn registrar(
        &self,
    ) -> Result<Option<Arc<dyn crate::routing::carrier_socket::Registrar>>, ClientError> {
        let slot=self.registrar.lock().map_err(|_|ClientError::Configuration)?;
        self.ensure_running()?;
        Ok(slot.clone())
    }

    pub(super) fn ensure_running(&self) -> Result<(), ClientError> {
        if !self.runtime.capture_state.running()
            || *self.runtime.stopped.borrow()
            || self.runtime.slot.borrow().revision != self.revision
        {
            Err(ClientError::Open(ErrorCode::PolicyDenied))
        } else {
            Ok(())
        }
    }

    fn ensure_accepting(&self) -> Result<(), ClientError> {
        self.ensure_running()?;
        if !self.runtime.capture_state.accepting() {
            return Err(ClientError::Open(ErrorCode::PolicyDenied));
        }
        Ok(())
    }

    /// Own the actual queue consumer and the current runtime's maintenance
    /// for the entire isolated capture lifetime. No production activation:
    /// rules and queue must have been provisioned in the same namespace.
    /// Cancellation or any fatal error retires the runtime and closes the
    /// queue; the journal remains for explicit CAS recovery.
    #[cfg(target_os = "linux")]
    pub async fn serve_linux_queue(
        &self,
        queue: crate::routing::nfqueue::Queue,
        rules: crate::routing::linux_rules::LabRules,
        host_namespace: std::fs::File,
    ) -> Result<(), ClientError> {
        self.serve_linux_queues_inner(queue,None,rules,host_namespace,|_,_,_|Ok(None)).await
    }

    /// Consume both private queues through the same actual verdict path.
    /// The proof establishes socket identity, not application identity.
    #[cfg(target_os="linux")]
    pub async fn serve_linux_socket_queues(
        &self,queue:crate::routing::nfqueue::Queue,tagged:crate::routing::nfqueue::Queue,
        rules:crate::routing::linux_rules::LabRules,host_namespace:std::fs::File,
    )->Result<(),ClientError> {
        self.serve_linux_queues_inner(queue,Some(tagged),rules,host_namespace,|_,_,_|Ok(None)).await
    }

    /// Live private collector records participate in the actual NFQUEUE
    /// verdict, never as application Known. A stale record, wrong fd,
    /// changed image/cookie or lost collector session denies that packet.
    /// The non-Send collector and both queues stay on the namespace's
    /// current-thread executor. This is a single tagged-socket lab.
    #[cfg(all(target_os="linux",feature="linux-ebpf-lab"))]
    pub async fn serve_linux_collected_queues(
        &self,queue:crate::routing::nfqueue::Queue,tagged:crate::routing::nfqueue::Queue,
        rules:crate::routing::linux_rules::LabRules,host_namespace:std::fs::File,
        collector:crate::routing::linux_bpf_loader::VerdictCollector,
    )->Result<(),ClientError> {
        if tokio::runtime::Handle::current().runtime_flavor()!=tokio::runtime::RuntimeFlavor::CurrentThread {
            return Err(ClientError::Configuration);
        }
        let collector=std::cell::RefCell::new(collector);
        self.serve_linux_queues_inner(queue,Some(tagged),rules,host_namespace,|rules,packet,socket|{
            collector.try_borrow_mut().map_err(|_|std::io::ErrorKind::PermissionDenied)?
                .verify(rules,packet,socket).map(Some)
        }).await
    }

    #[cfg(target_os="linux")]
    async fn serve_linux_queues_inner<V>(
        &self,queue:crate::routing::nfqueue::Queue,tagged:Option<crate::routing::nfqueue::Queue>,
        rules:crate::routing::linux_rules::LabRules,host_namespace:std::fs::File,verify:V,
    )->Result<(),ClientError>
    where V:Fn(&crate::routing::linux_rules::LabRules,&crate::routing::nfqueue::Packet<'_>,
        crate::routing::linux_rules::CapturedSocket)->std::io::Result<Option<crate::routing::linux_events::CorroboratedFlow>> {
        self.ensure_running()?;
        if !rules.owns_queue(&queue).map_err(|_|ClientError::Io)? ||
            rules.has_capture_queue()!=tagged.is_some() ||
            tagged.as_ref().is_some_and(|q|!rules.owns_capture_queue(q).unwrap_or(false)) {
            return Err(ClientError::Configuration);
        }
        let rules = Arc::new(Mutex::new(rules));
        let registrar: Arc<dyn crate::routing::carrier_socket::Registrar> = Arc::new(
            crate::routing::linux_rules::LabRegistrar::new(rules.clone(), host_namespace),
        );
        {
            let mut slot = self
                .registrar
                .lock()
                .map_err(|_| ClientError::Configuration)?;
            if slot.is_some() {
                return Err(ClientError::Configuration);
            }
            *slot = Some(registrar.clone());
        }
        self.serve_linux_shared(queue,tagged,rules,registrar,verify).await
    }

    #[cfg(target_os = "linux")]
    async fn serve_linux_shared<V>(
        &self,
        queue: crate::routing::nfqueue::Queue,
        tagged:Option<crate::routing::nfqueue::Queue>,
        rules: Arc<Mutex<crate::routing::linux_rules::LabRules>>,
        registrar: Arc<dyn crate::routing::carrier_socket::Registrar>,
        verify:V,
    ) -> Result<(), ClientError>
    where V:Fn(&crate::routing::linux_rules::LabRules,&crate::routing::nfqueue::Packet<'_>,
        crate::routing::linux_rules::CapturedSocket)->std::io::Result<Option<crate::routing::linux_events::CorroboratedFlow>> {
        struct StopOnDrop<'a>(&'a NativeIngress);
        impl Drop for StopOnDrop<'_> {
            fn drop(&mut self) {
                self.0.shutdown();
            }
        }
        let _stop = StopOnDrop(self);
        self.ensure_running()?;
        if !rules
            .lock()
            .map_err(|_| ClientError::Configuration)?
            .owns_queue(&queue)
            .map_err(|_| ClientError::Io)?
        {
            return Err(ClientError::Configuration);
        }
        {
            let owner=rules.lock().map_err(|_|ClientError::Configuration)?;
            if owner.has_capture_queue()!=tagged.is_some() ||
                tagged.as_ref().is_some_and(|q|!owner.owns_capture_queue(q).unwrap_or(false)) {
                return Err(ClientError::Configuration);
            }
        }
        let mut queue = queue.into_async().map_err(|_| ClientError::Io)?;
        let mut tagged=tagged.map(|q|q.into_async()).transpose().map_err(|_|ClientError::Io)?;
        self.runtime.capture_state.ready()?;
        let consume = async {
            let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let packet = tokio::select! {
                    _ = heartbeat.tick() => {
                        if !rules.lock().map_err(|_| ClientError::Configuration)?.live_admissions().map_err(|_| ClientError::Io)? {
                            return Err(ClientError::Open(ErrorCode::PolicyDenied));
                        }
                        continue;
                    }
                    packet=queue.next()=>packet.map_err(|_| ClientError::Io)?,
                    packet=crate::routing::nfqueue::next_optional(&mut tagged)=>packet.map_err(|_|ClientError::Io)?,
                };
                self.verdict_with_evidence(&rules,packet,&verify).await.map_err(|_|ClientError::Io)?;
            }
        };
        tokio::select! {
            biased;
            result=crate::routing::carrier_socket::scope(Some(registrar.clone()), consume)=>result,
            result=crate::routing::carrier_socket::scope(Some(registrar), self.runtime.maintain())=>result,
            ()=self.stopped()=>Ok(()),
        }
    }

    /// End-to-end managed startup for a dedicated Linux laboratory
    /// namespace. This is intentionally not exposed as the product's
    /// Connect action: transparent Redirect and attribution are incomplete.
    /// No preflight carrier is opened before the registrar is in scope.
    /// A failed or cancelled run leaves the fail-closed table and durable
    /// journal intact. Only an explicit successful Stop may restore rules.
    #[cfg(target_os = "linux")]
    pub async fn run_linux_lab(
        path: &Path,
        host_namespace: std::fs::File,
        journal: &Path,
        queue_number: u16,
        stop: impl std::future::Future<Output = std::io::Result<()>>,
    ) -> Result<(), ClientError> {
        Self::run_linux_managed_lab(path,host_namespace,journal,Some(queue_number),None,false,stop).await
    }

    /// The same native Runtime, but transparent TCP and UDP listeners
    /// replace the raw NFQUEUE-only adapter. No target allowlist: every
    /// nonlocal TCP/UDP destination is redirected or denied by policy.
    /// Requires an explicitly isolated namespace and pre-owned policy
    /// routes; never used by product Connect before physical acceptance.
    #[cfg(target_os="linux")]
    pub async fn run_linux_redirect_lab(
        path:&Path,host_namespace:std::fs::File,journal:&Path,port:u16,
        stop:impl std::future::Future<Output=std::io::Result<()>>,
    )->Result<(),ClientError> {
        Self::run_linux_managed_lab(path,host_namespace,journal,None,Some(port),false,stop).await
    }

    /// Explicit disposable host test only. The same policy queue and
    /// transparent adapters, not a second production mode. Fixed journal
    /// location is the boot guard's only authorized host intent.
    #[cfg(target_os="linux")]
    pub async fn run_linux_host_lab(path:&Path,host_namespace:std::fs::File,port:u16,
        stop:impl std::future::Future<Output=std::io::Result<()>>)->Result<(),ClientError> {
        let journal=Path::new(crate::routing::linux_rules::HOST_GUARD_JOURNAL);
        Self::run_linux_managed_lab(path,host_namespace,journal,None,Some(port),true,stop).await
    }

    #[cfg(target_os="linux")]
    async fn run_linux_managed_lab(
        path:&Path,host_namespace:std::fs::File,journal:&Path,queue_number:Option<u16>,
        redirect_port:Option<u16>,host_mode:bool,stop:impl std::future::Future<Output=std::io::Result<()>>,
    )->Result<(),ClientError> {
        use crate::routing::{
            carrier_socket,
            linux_rules::{self, LabRegistrar, LabRules},
            nfqueue::Queue,
        };
        use sha2::{Digest, Sha256};
        // Namespace ownership must not move between executor threads.
        if tokio::runtime::Handle::current().runtime_flavor()
            != tokio::runtime::RuntimeFlavor::CurrentThread
        {
            return Err(ClientError::Configuration);
        }
        let owner = Arc::new(NativeOwner::acquire()?);
        let path = std::path::absolute(path).map_err(|_| ClientError::Configuration)?;
        let raw = zeroize::Zeroizing::new(
            config::editor_bytes(&path).map_err(|_| ClientError::Configuration)?,
        );
        let Config::Client(document) =
            config::parse(std::str::from_utf8(&raw).map_err(|_| ClientError::Configuration)?)
                .map_err(|_| ClientError::Configuration)?
        else {
            return Err(ClientError::Configuration);
        };
        let digest: [u8; 32] = Sha256::digest(raw.as_slice()).into();
        saved_client_bytes(&path, digest)?;
        // Bind all four listeners before installing the persistent
        // fail-closed table. No network preflight precedes its commit.
        let listeners=redirect_port.map(|port|crate::routing::linux_ingress::RedirectListeners::bind_mode(&host_namespace,port,host_mode))
            .transpose().map_err(|_|ClientError::Io)?;
        let queue=queue_number.or_else(||listeners.as_ref().map(|_|49000))
            .map(|number|Queue::bind(number,256)).transpose().map_err(|_|ClientError::Io)?;
        let routes=if listeners.is_some() {
            Some(linux_rules::PolicyRoutes::install(&host_namespace,journal,host_mode).map_err(|_|ClientError::Io)?)
        } else {None};
        let rules=Arc::new(Mutex::new(match (&queue,&listeners) {
            (Some(queue),None)=>LabRules::install(queue,&host_namespace,journal),
            (Some(queue),Some(listeners))=>LabRules::install_unified(queue,&host_namespace,journal,listeners.port(),host_mode),
            _=>return Err(ClientError::Configuration),
        }.map_err(|_|ClientError::Io)?));
        let registrar: Arc<dyn carrier_socket::Registrar> = Arc::new(LabRegistrar::new(
            rules.clone(),
            host_namespace.try_clone().map_err(|_| ClientError::Io)?,
        ));
        let client =
            carrier_socket::scope(Some(registrar.clone()), prepare_client(&document, &path))
                .await?;
        saved_client_bytes(&path, digest)?;
        let runtime = ClientRuntime::new(path, document, digest, client);
        // Keep the process/namespace owner alive across the entire explicit
        // recovery transaction, not just across the packet consumer.
        let ingress=Arc::new(runtime.attach_native(owner.clone(),Some(registrar.clone())).await?);
        let control = crate::management::client_server(runtime.clone())
            .map_err(|_| ClientError::Configuration)?;
        let management = async move {
            match control {
                Some(server) => server.serve().await.map_err(|_| ClientError::Io),
                None => std::future::pending::<Result<(), ClientError>>().await,
            }
        };
        let capture=async {
            match (queue,listeners) {
                (Some(queue),None)=>ingress.serve_linux_shared(queue,None,rules.clone(),registrar.clone(),|_,_,_|Ok(None)).await,
                (Some(queue),Some(listeners))=>{
                    let port=listeners.port();
                    if !rules.lock().map_err(|_|ClientError::Configuration)?.owns_policy_queue(&queue).map_err(|_|ClientError::Io)? {
                        return Err(ClientError::Open(ErrorCode::PolicyDenied));
                    }
                    ingress.unified.store(true,std::sync::atomic::Ordering::Release);
                    if !rules.lock().map_err(|_|ClientError::Configuration)?.redirect_ready(port).map_err(|_|ClientError::Io)? {
                        return Err(ClientError::Open(ErrorCode::PolicyDenied));
                    }
                    ingress.runtime.capture_state.ready()?;
                    eprintln!("Theia Linux managed laboratory capture ready (host scope={host_mode}); stop applications before explicit Stop");
                    let monitor=async {
                        let mut tick=tokio::time::interval(Duration::from_secs(1));
                        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                        loop {
                            tick.tick().await;
                            if !rules.lock().map_err(|_|ClientError::Configuration)?.redirect_ready(port).map_err(|_|ClientError::Io)? ||
                                !routes.as_ref().ok_or(ClientError::Configuration)?.current().map_err(|_|ClientError::Io)? {
                                return Err(ClientError::Open(ErrorCode::PolicyDenied));
                            }
                        }
                    };
                    tokio::select! {
                        biased;
                        result=ingress.serve_linux_redirect_capture(listeners)=>result,
                        result=carrier_socket::scope(Some(registrar.clone()),ingress.serve_linux_policy_queue(queue,&rules))=>result,
                        result=monitor=>result,
                        result=carrier_socket::scope(Some(registrar.clone()),runtime.maintain())=>result,
                        ()=ingress.stopped()=>Err(ClientError::Open(ErrorCode::PolicyDenied)),
                    }
                },
                _=>Err(ClientError::Configuration),
            }
        };
        let explicit = tokio::select! {
            biased;
            result=capture=>{
                result?;
                Err(ClientError::Io) // unexpected consumer exit, never auto restore
            },
            result=management=>{ result?; Err(ClientError::Io) },
            // When a failure and explicit stop are already ready together,
            // do not reinterpret a failed consumer as a clean shutdown.
            result=stop=>result.map_err(|_| ClientError::Io),
        };
        ingress.shutdown();
        explicit?;
        // A dropped JoinSet aborts its tasks but the abort can be
        // delivered later. Do not recover while native relay tasks
        // still retain the ingress or their socket leases.
        timeout(Duration::from_secs(3),async {
            while Arc::strong_count(&ingress)!=1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.map_err(|_|ClientError::Timeout)?;
        drop(ingress);
        drop(runtime);
        drop(registrar);
        // A failed carrier revocation poisons the rule owner. Do not
        // interpret an explicit Stop as permission to erase that guard.
        if !rules.lock().map_err(|_|ClientError::Configuration)?.current().map_err(|_|ClientError::Io)? {
            return Err(ClientError::Open(ErrorCode::PolicyDenied));
        }
        // Connection drivers may release their socket leases asynchronously
        // after abort. Never restore while a live carrier retains our rules.
        timeout(Duration::from_secs(3), async {
            while Arc::strong_count(&rules) != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)?;
        if !rules.lock().map_err(|_|ClientError::Configuration)?.current().map_err(|_|ClientError::Io)? {
            return Err(ClientError::Open(ErrorCode::PolicyDenied));
        }
        drop(rules);
        drop(routes);
        let recovered=linux_rules::recover_mode(&host_namespace,journal,host_mode).map_err(|_| ClientError::Io);
        drop(owner);
        recovered
    }


    /// One capture worker and the existing runtime for external TCP/UDP
    /// applications. Explicit isolated destination scope only: this
    /// cannot authorize production Connect or establish socket identity.
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub async fn run_windows_redirect_lab(
        path:&Path,directory:std::path::PathBuf,dll:[u8;32],sys:[u8;32],
        targets:Vec<SocketAddr>,seconds:u32,
    )->Result<(),ClientError> {
        Self::run_windows_relay_scope(path,directory,dll,sys,crate::routing::windivert::RelayScope::Targets(targets),seconds).await
    }

    /// All destinations on one explicitly reviewed nonloopback device.
    /// The carrier must use a distinct reviewed device, outside this lab.
    /// No system-wide capture or carrier exemption is asserted.
    #[cfg(all(target_os="windows",target_arch="x86_64"))]
    pub async fn run_windows_interface_redirect_lab(path:&Path,directory:std::path::PathBuf,dll:[u8;32],sys:[u8;32],
        capture:u32,carrier:u32,seconds:u32)->Result<(),ClientError> {
        Self::run_windows_relay_scope(path,directory,dll,sys,crate::routing::windivert::RelayScope::Interface{capture,carrier},seconds).await
    }
    #[cfg(all(target_os="windows",target_arch="x86_64"))]
    async fn run_windows_relay_scope(path:&Path,directory:std::path::PathBuf,dll:[u8;32],sys:[u8;32],
        scope:crate::routing::windivert::RelayScope,seconds:u32)->Result<(),ClientError> {
        use crate::routing::{carrier_socket,windivert::{self,CarrierRegistry,ScopeRelayEvent,RelayScope}};
        let registry=Arc::new(match &scope {
            RelayScope::Targets(targets)=>CarrierRegistry::for_redirect_lab(targets).ok_or(ClientError::Configuration)?,
            RelayScope::Interface{capture,carrier}=>CarrierRegistry::for_interface_lab(*capture,*carrier).map_err(|_|ClientError::Configuration)?,
        });
        if !(5..=120).contains(&seconds) { return Err(ClientError::Configuration); }
        let registrar:Arc<dyn carrier_socket::Registrar>=registry.clone();
        let ingress=Arc::new(Self::prepare_with_registrar(path,Some(registrar.clone())).await?);
        // Only the explicit two-interface lab is permitted to test local
        // Modify. Target-only capture remains Redirect; no whole-host permit.
        if matches!(&scope,RelayScope::Interface{..}) {
            *ingress.windows_modify.lock().map_err(|_|ClientError::Io)?=Some(registry.clone());
        }
        struct Stop<'a>(&'a NativeIngress,&'a CarrierRegistry);
        impl Drop for Stop<'_> {
            fn drop(&mut self) { self.0.shutdown();self.1.retire(); }
        }
        let _stop=Stop(&ingress,&registry);
        let mut lab=windivert::begin_scope_relay_lab(directory,dll,sys,scope,seconds).await
            .map_err(|_|ClientError::Io)?;
        ingress.runtime.capture_state.ready()?;
        eprintln!("WinDivert isolated redirect capture ready; start authorized test applications now");
        let mut udp=NativeUdpDispatch::default();
        let mut tasks=JoinSet::<Option<NativeUdpTicket>>::new();
        let maintenance=carrier_socket::scope(Some(registrar.clone()),ingress.runtime.maintain());
        tokio::pin!(maintenance);
        let result=loop {
            if ingress.ensure_accepting().is_err() { break Err(ClientError::Open(ErrorCode::PolicyDenied)); }
            let event=tokio::select! {
                biased;
                _=&mut lab.ended=>break Ok(()),
                ()=ingress.stopped()=>break Err(ClientError::Open(ErrorCode::PolicyDenied)),
                result=&mut maintenance=>break result,
                finished=tasks.join_next(),if !tasks.is_empty()=>{
                    match finished {
                        Some(Ok(None))=>continue,
                        Some(Ok(Some(ticket))) if udp.complete(ticket)=>continue,
                        _=>break Err(ClientError::Io),
                    }
                }
                event=lab.events.recv()=>match event {Some(event)=>event,None=>break Err(ClientError::Io)},
            };
            match event {
                ScopeRelayEvent::Tcp(captured)=>{
                    if tasks.len()>=LOCAL_LIMIT { drop(captured);continue; }
                    let owner=ingress.clone();
                    let registrar=registrar.clone();
                    tasks.spawn(async move {
                        if let Ok((key,stream))=captured.accept().await {
                            let result=carrier_socket::scope(Some(registrar),owner.relay_terminated_tcp(key,stream)).await;
                            // Allow the local TCP stack's FIN/ACK exchange
                            // to drain before retiring the exact mapping.
                            if result.is_ok() {
                                tokio::select! {
                                    ()=owner.stopped()=>{},
                                    ()=tokio::time::sleep(Duration::from_secs(2))=>{},
                                }
                            }
                        }
                        drop(captured);
                        None
                    });
                }
                ScopeRelayEvent::Udp(packet)=>{
                    if !packet.flow.live() { continue; }
                    let key=packet.flow.key();
                    // Existing UDP queues may accept more packets while
                    // the shared task quota is full. New flows may not.
                    if tasks.len()>=LOCAL_LIMIT && !udp.flows.contains_key(&key) {
                        packet.flow.close();
                        crate::traffic::udp_queue_drop();
                        continue;
                    }
                    if let Some((ticket,first,subsequent))=udp.admit(key,packet) {
                        let owner=ingress.clone();
                        let replies=lab.replies.clone();
                        let registrar=registrar.clone();
                        tasks.spawn(async move {
                            let _=carrier_socket::scope(Some(registrar),
                                owner.relay_windows_scope_udp(first,subsequent,replies)).await;
                            Some(ticket)
                        });
                    }
                }
            }
        };
        ingress.shutdown();
        registry.retire();
        tasks.shutdown().await;
        let backend=lab.finish().await.map_err(|_|ClientError::Io);
        result?;
        backend
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    async fn relay_windows_scope_udp(&self,first:crate::routing::windivert::ScopeUdpPacket,
        mut subsequent:tokio::sync::mpsc::Receiver<crate::routing::windivert::ScopeUdpPacket>,
        replies:crate::routing::windivert::ScopeReplies)->Result<(),ClientError> {
        use crate::routing::{carrier_socket,PacketAction};
        // Every completion path revokes the reply capability; the
        // packet worker retains an un-reusable tuple tombstone.
        struct Retire<F:FnOnce()>(Option<F>);
        impl<F:FnOnce()> Drop for Retire<F> {
            fn drop(&mut self) { if let Some(retire)=self.0.take() { retire(); } }
        }
        let source=first.flow.clone();
        let revoke=source.clone();
        let _retire=Retire(Some(move ||revoke.close()));
        let key=source.key();
        if !source.live() || subsequent.max_capacity()>crate::udp_relay::QUEUE {
            return Err(ClientError::Open(ErrorCode::PolicyDenied));
        }
        if key.destination.port()==53 && self.native_modify_enabled()? {
            return tokio::select! {
                biased;
                ()=self.stopped()=>Err(ClientError::Open(ErrorCode::PolicyDenied)),
                result=self.relay_windows_scope_dns(first,subsequent,replies)=>result,
            };
        }
        tokio::select! {
            biased;
            ()=self.stopped()=>Err(ClientError::Open(ErrorCode::PolicyDenied)),
            result=async {
                let (carrier,flow,address,snapshot,configured)=self.redirect_selection(key).await?;
                let registrar=self.registrar()?.ok_or(ClientError::Open(ErrorCode::PolicyDenied))?;
                let local=if configured==PacketAction::Modify && self.native_modify_enabled()? {
                    carrier_socket::scope(Some(registrar.clone()),
                        self.prepare_unified_udp(key,&first.payload,&carrier,&snapshot)).await?
                } else {None};
                let actual=if local.is_some(){PacketAction::Modify}else{PacketAction::Redirect};
                let (tx,up)=tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
                let (down,mut rx)=tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
                let mut first_payload=Some(first.payload);
                if actual==PacketAction::Redirect {
                    tx.send(first_payload.take().ok_or(ClientError::Protocol)?).await.map_err(|_|ClientError::Io)?;
                }
                let relay=async {
                    self.ensure_accepting()?;
                    if !source.live() {return Err(ClientError::Open(ErrorCode::PolicyDenied));}
                    self.client.routing_cache().policy.check_policy(snapshot.digest())?;
                    if let Some(verified)=local {
                        self.check_native_modify(key,snapshot.digest())?;
                        return crate::udp_relay::relay_native_modify_lab(&verified,
                            first_payload.ok_or(ClientError::Protocol)?,up,down,&flow).await;
                    }
                    let tunnel=carrier_socket::scope(Some(registrar),carrier.open_udp(address,key.destination.port())).await?;
                    tunnel.relay_guarded(up,down,Some(&flow)).await
                };
                let feed=async {
                    let tx=tx;
                    while let Some(packet)=subsequent.recv().await {
                        if !source.live() || !Arc::ptr_eq(&packet.flow,&source) ||
                            packet.payload.len()>crate::protocol::MAX_DATAGRAM {
                            return Err(ClientError::Open(ErrorCode::PolicyDenied));
                        }
                        tx.send(packet.payload).await.map_err(|_|ClientError::Io)?;
                    }
                    Ok::<(),ClientError>(())
                };
                let reverse=async {
                    while let Some(bytes)=rx.recv().await {
                        self.ensure_accepting()?;
                        if !source.live() || !flow.committed(actual) {
                            return Err(ClientError::Open(ErrorCode::PolicyDenied));
                        }
                        // Acknowledged by the sole packet worker only
                        // after exact reverse injection; no echo matching
                        // and no one-request/one-response assumption.
                        replies.send(source.clone(),bytes,self.client.routing_cache().policy.clone(),
                            snapshot.digest()).await.map_err(|_|ClientError::Io)?;
                    }
                    Ok::<(),ClientError>(())
                };
                supervise_native_udp(relay,feed,reverse).await
            }=>result,
        }
    }

    /// DNS interception on the exact live WinDivert UDP reverse token.
    /// The query's QNAME is known; its application provenance is not.
    #[cfg(all(target_os="windows",target_arch="x86_64"))]
    async fn relay_windows_scope_dns(&self,first:crate::routing::windivert::ScopeUdpPacket,
        mut subsequent:tokio::sync::mpsc::Receiver<crate::routing::windivert::ScopeUdpPacket>,
        replies:crate::routing::windivert::ScopeReplies)->Result<(),ClientError> {
        let denied=||ClientError::Open(ErrorCode::PolicyDenied);
        let source=first.flow.clone();
        let key=source.key();
        let (flow,digest)=self.begin_windows_dns(key).await?;
        let mut current=first;
        for _ in 0..64 {
            if !source.live() || !Arc::ptr_eq(&current.flow,&source) {return Err(denied());}
            let answer=self.protected_dns_answer(key,&current.payload,false,Some((&flow,digest))).await?;
            self.check_native_modify(key,digest)?;
            if !source.live() {return Err(denied());}
            replies.send(source.clone(),answer.wire.clone(),self.client.routing_cache().policy.clone(),
                digest).await.map_err(|_|ClientError::Io)?;
            if !source.live() {return Err(denied());}
            self.record_dns_delivery(key,answer)?;
            match timeout(Duration::from_secs(10),subsequent.recv()).await {
                Ok(Some(next))=>current=next,
                _=>return Ok(()),
            }
        }
        Ok(())
    }

    /// Scoped real WinDivert TCP reflection into the existing XHTTP
    /// stream handoff. No application evidence or system-wide Connect.
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub async fn run_windows_tcp_relay_lab(
        path:&Path,directory:std::path::PathBuf,dll:[u8;32],sys:[u8;32],target:SocketAddr,
    )->Result<(),ClientError> {
        use crate::routing::{carrier_socket,windivert::CarrierRegistry};
        let registry=Arc::new(CarrierRegistry::default());
        let registrar:Arc<dyn carrier_socket::Registrar>=registry.clone();
        let ingress=Arc::new(Self::prepare_with_registrar(path,Some(registrar.clone())).await?);
        struct Stop<'a>(&'a NativeIngress,&'a CarrierRegistry);
        impl Drop for Stop<'_> { fn drop(&mut self) { self.0.shutdown();self.1.retire(); } }
        let _stop=Stop(&ingress,&registry);
        let owner=ingress.clone();
        crate::routing::windivert::run_tcp_relay_lab(directory,dll,sys,target,move |key,stream|async move {
            owner.runtime.capture_state.ready().map_err(|_|std::io::ErrorKind::PermissionDenied)?;
            carrier_socket::scope(Some(registrar),owner.relay_terminated_tcp(key,stream)).await
                .map_err(|_|std::io::Error::other("authenticated TCP relay failed"))
        }).await.map_err(|_|ClientError::Io)
    }

    /// Explicit authorized echo acceptance, never a product Connect.
    /// All exact owned UDP tuples use one bounded live dispatcher. Each
    /// worker captures and injects while its authenticated XHTTP flow
    /// is open. No arbitrary application or caller-supplied injection key.
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub async fn run_windows_udp_relay_lab(
        path:&Path, directory:std::path::PathBuf, dll:[u8;32], sys:[u8;32], target:SocketAddr,
        flows:usize,
    )->Result<(),ClientError> {
        use crate::routing::{carrier_socket,windivert::{CarrierRegistry,RelayLab}};
        if !(1..=8).contains(&flows) { return Err(ClientError::Configuration); }
        let registry=Arc::new(CarrierRegistry::default());
        let registrar:Arc<dyn carrier_socket::Registrar>=registry.clone();
        let ingress=Arc::new(Self::prepare_with_registrar(path,Some(registrar.clone())).await?);
        struct Stop<'a>(&'a NativeIngress,&'a CarrierRegistry);
        impl Drop for Stop<'_> { fn drop(&mut self) { self.0.shutdown();self.1.retire(); } }
        let _stop=Stop(&ingress,&registry);
        let (capture_tx,mut capture_rx)=tokio::sync::mpsc::channel(flows*crate::udp_relay::QUEUE);
        let mut preparing=JoinSet::new();
        for _ in 0..flows {
            let directory=directory.clone();
            let capture_tx=capture_tx.clone();
            preparing.spawn(async move {
                crate::routing::windivert::begin_udp_relay_lab(directory,dll,sys,target,capture_tx).await
                    .map_err(|_|ClientError::Io)
            });
        }
        drop(capture_tx);
        let mut labs=std::collections::HashMap::<_,RelayLab>::with_capacity(flows);
        while let Some(joined)=preparing.join_next().await {
            let lab=joined.map_err(|_|ClientError::Io)??;
            if labs.insert(lab.key,lab).is_some() {
                return Err(ClientError::Open(ErrorCode::PolicyDenied));
            }
        }
        ingress.runtime.capture_state.ready()?;
        let mut relays=JoinSet::new();
        let mut dispatch=NativeUdpDispatch::default();
        let mut capture_closed=false;
        let result=loop {
            if labs.is_empty() && relays.is_empty() { break Ok(()); }
            if ingress.ensure_accepting().is_err() { break Err(ClientError::Open(ErrorCode::PolicyDenied)); }
            let (key,payload)=tokio::select! {
                biased;
                ()=ingress.stopped()=>break Err(ClientError::Open(ErrorCode::PolicyDenied)),
                result=relays.join_next(),if !relays.is_empty()=>{
                    match result {
                        Some(Ok((ticket,Ok(())))) if dispatch.complete(ticket)=>continue,
                        Some(Ok((_,Err(error))))=>break Err(error),
                        _=>break Err(ClientError::Io),
                    }
                }
                packet=capture_rx.recv(),if !capture_closed=>{
                    match packet {
                        Some(packet)=>packet,
                        None=>{
                            capture_closed=true;
                            if !labs.is_empty() { break Err(ClientError::Io); }
                            continue;
                        }
                    }
                }
            };
            if let Some((ticket,first,subsequent))=dispatch.admit(key,payload) {
                let Some(lab)=labs.remove(&key) else { break Err(ClientError::Protocol); };
                let ingress=ingress.clone();
                let registrar=registrar.clone();
                relays.spawn(async move {
                    let result=crate::routing::carrier_socket::scope(Some(registrar),
                        ingress.relay_windows_udp_lab(lab,first,subsequent)).await;
                    (ticket,result)
                });
            }
        };
        ingress.shutdown();
        relays.shutdown().await;
        result
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    async fn relay_windows_udp_lab(&self,lab:crate::routing::windivert::RelayLab,
        first:Vec<u8>,mut subsequent:tokio::sync::mpsc::Receiver<Vec<u8>>)->Result<(),ClientError> {
        use crate::routing::{carrier_socket,windivert::UDP_LAB_DATAGRAMS,PacketAction};
        let key=lab.key;
        let (carrier,flow,address)=self.redirect(key).await?;
        let tunnel=carrier_socket::scope(self.registrar()?,carrier.open_udp(address,key.destination.port())).await?;
        let (tx,up)=tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
        let (down,mut rx)=tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
        tx.send(first).await.map_err(|_|ClientError::Io)?;
        let relay=tunnel.relay_guarded(up,down,Some(&flow));
        tokio::pin!(relay);
        let deadline=tokio::time::Instant::now()+Duration::from_secs(20);
        let mut sent=1;
        let mut received=0;
        while received<UDP_LAB_DATAGRAMS {
            tokio::select! {
                biased;
                ()=self.stopped()=>return Err(ClientError::Open(ErrorCode::PolicyDenied)),
                result=&mut relay=>{result?;return Err(ClientError::Io)},
                ()=tokio::time::sleep_until(deadline)=>return Err(ClientError::Timeout),
                packet=subsequent.recv(),if sent<UDP_LAB_DATAGRAMS=>{
                    let bytes=packet.ok_or(ClientError::Io)?;
                    if sent!=received || bytes.len()>crate::protocol::MAX_DATAGRAM {
                        return Err(ClientError::Protocol);
                    }
                    tx.try_send(bytes).map_err(|_|ClientError::Io)?;
                    sent+=1;
                }
                response=rx.recv()=>{
                    let bytes=response.ok_or(ClientError::Io)?;
                    self.ensure_accepting()?;
                    if !flow.committed(PacketAction::Redirect) || received>=sent {
                        return Err(ClientError::Open(ErrorCode::PolicyDenied));
                    }
                    lab.respond(bytes).map_err(|_|ClientError::Io)?;
                    received+=1;
                }
            }
        }
        if sent!=UDP_LAB_DATAGRAMS || subsequent.try_recv().is_ok() { return Err(ClientError::Protocol); }
        // The worker verifies every exact nonce and actual local receive
        // before closing the original socket and removing its lab rules.
        tokio::select! {
            biased;
            ()=self.stopped()=>return Err(ClientError::Open(ErrorCode::PolicyDenied)),
            result=&mut relay=>{result?;return Err(ClientError::Io)},
            result=lab.finish()=>result.map_err(|_|ClientError::Io)?,
        }
        drop(tx);
        timeout(Duration::from_secs(3),&mut relay).await.map_err(|_|ClientError::Timeout)??;
        Ok(())
    }

    /// Correlate an actual private collector/queue observation with
    /// authenticated DNS, rechecking it before publication. The resolver
    /// link is still a claimed link, not trusted evidence of the original
    /// application request. No native route is authorized by this API.
    #[cfg(all(target_os = "linux", feature = "linux-ebpf-lab"))]
    pub async fn corroborate_dns_captured_lab(
        &self,
        observation: &crate::routing::linux_bpf_loader::CapturedObservation<'_, '_>,
        link: &crate::routing::dns_attribution::ResolverLink,
        candidates: &mut crate::routing::dns_attribution::DnsCandidates,
    ) -> Result<bool, ClientError> {
        self.ensure_accepting()?;
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        let flow = observation.flow();
        if observation.revalidate().is_err() {
            candidates.invalidate(flow);
            return Err(denied());
        }
        // Never allow an older, already published candidate to survive
        // a failed attempt to revalidate its source.
        let result = self.corroborate_dns_inner(flow, link, candidates, || {
            self.ensure_accepting()?;
            observation.revalidate().map_err(|_| denied())?;
            Ok(())
        }).await;
        if !matches!(&result, Ok(true)) {
            candidates.invalidate(flow);
        }
        result
    }

    /// Correlate a laboratory resolver link with protected DNS from the
    /// exact active policy generation. This does not grant routing
    /// authorization: neither the BPF reader nor resolver event source
    /// has yet been integrated into the production native backend.
    #[cfg(target_os = "linux")]
    pub async fn corroborate_dns_lab(
        &self,
        flow: crate::routing::linux_events::CorroboratedFlow,
        link: &crate::routing::dns_attribution::ResolverLink,
        candidates: &mut crate::routing::dns_attribution::DnsCandidates,
    ) -> Result<bool, ClientError> {
        let result = self.corroborate_dns_inner(flow, link, candidates, || Ok(())).await;
        if !matches!(&result, Ok(true)) {
            candidates.invalidate(flow);
        }
        result
    }

    #[cfg(target_os = "linux")]
    async fn corroborate_dns_inner(
        &self,
        flow: crate::routing::linux_events::CorroboratedFlow,
        link: &crate::routing::dns_attribution::ResolverLink,
        candidates: &mut crate::routing::dns_attribution::DnsCandidates,
        validate_source: impl FnOnce() -> Result<(), ClientError>,
    ) -> Result<bool, ClientError> {
        self.ensure_running()?;
        if flow.key() != link.key
            || flow.cookie() != link.cookie
            || flow.process_start() != link.process_start
        {
            return Ok(false);
        }
        let registrar = self
            .registrar()?
            .ok_or(ClientError::Open(ErrorCode::PolicyDenied))?;
        crate::routing::carrier_socket::scope(Some(registrar), async {
            let (carrier, cache) = match &self.client {
                ProxyClient::Direct(c) => (c.carrier.clone(), &c.routing),
                ProxyClient::Reality(c) => (c.generation().await?.carrier.clone(), &c.routing),
            };
            let snapshot = cache.get(|known| carrier.fetch_routing(known)).await?;
            let digest = snapshot.digest();
            let name =
                crate::routing::domain_name(&link.domain).map_err(|_| ClientError::Protocol)?;
            // The current wire response contains addresses, not authoritative
            // DNS TTLs. Bound this diagnostic to the original policy lease and
            // a short window beginning BEFORE the authenticated request.
            let original_deadline = cache.observation_deadline(digest)?;
            let requested = Instant::now();
            let ips = carrier.resolve_routing(&name, digest).await?;
            let deadline = original_deadline
                .min(cache.observation_deadline(digest)?)
                .min(requested + Duration::from_secs(30));
            self.ensure_running()?;
            validate_source()?;
            cache.policy.check_policy(digest)?;
            candidates
                .record(flow, link, digest, &ips, deadline)
                .map_err(|_| ClientError::Protocol)
        })
        .await
    }

    /// Prepare a narrowly scoped laboratory Modify permit. The route must
    /// be conclusive even with unknown application/domain evidence; the
    /// supplied name is only an authenticated DNS/reachability probe hint,
    /// never evidence of which name the application actually requested.
    /// No probe is run on the captured application socket or packet.
    #[cfg(target_os = "linux")]
    pub async fn prepare_stun_lab(
        &self,
        key: crate::routing::packet::FlowKey,
        domain: &str,
    ) -> Result<LabStunPermit, ClientError> {
        use crate::routing::{
            dpi::{udp::BindingStrategy, UdpStrategy},
            packet::Transport,
            Evidence, PacketAction,
        };
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        self.ensure_running()?;
        if key.transport != Transport::Udp
            || key.destination.port() != 3478
            || key.source.port() == 0
            || key.source.is_ipv4() != key.destination.is_ipv4()
            || !crate::server::allowed_destination(key.destination.ip(), false)
        {
            return Err(denied());
        }
        let (carrier, cache) = match &self.client {
            ProxyClient::Direct(c) => (c.carrier.clone(), &c.routing),
            ProxyClient::Reality(c) => (c.generation().await?.carrier.clone(), &c.routing),
        };
        let snapshot = cache.get(|known| carrier.fetch_routing(known)).await?;
        let digest = snapshot.digest();
        let name = crate::routing::domain_name(domain).map_err(|_| denied())?;
        let policy = snapshot.policy();
        for evidence in [Evidence::Unknown, Evidence::Known(name.as_str())] {
            if policy
                .classify_with_application(
                    evidence,
                    Evidence::Known(key.destination.ip()),
                    Evidence::Unknown,
                )
                .map_err(|_| denied())?
                .action()
                != Some(Action::DirectDpi)
            {
                return Err(denied());
            }
        }
        if !cache.dpi.stun_enabled() {
            return Err(denied());
        }
        let ips = carrier.resolve_routing(&name, digest).await?;
        if !ips.contains(&key.destination.ip()) {
            return Err(denied());
        }
        let verified = cache
            .dpi
            .open_stun_udp(&name, 3478, &[key.destination.ip()], digest)
            .await
            .ok_or_else(denied)?;
        if verified.strategy != UdpStrategy::StunBinding(BindingStrategy::Fingerprint)
            || verified.socket.peer_addr().ok() != Some(key.destination)
            || !verified
                .socket
                .local_addr()
                .is_ok_and(|a| a.ip() == key.source.ip())
            || !verified.admissible()?
        {
            return Err(denied());
        }
        self.ensure_running()?;
        let flow =
            cache
                .flows
                .begin_native(cache.policy.clone(), key, digest, PacketAction::Modify)?;
        Ok(LabStunPermit {
            key,
            flow,
            engine: cache.dpi.clone(),
            verified,
            failed: false,
        })
    }

    /// The actual NFQUEUE replacement is available only under an owned
    /// isolated lab rules lease. Unsupported packets, stale evidence,
    /// shutdown and all mismatches are terminal for this permit.
    #[cfg(target_os = "linux")]
    pub fn verdict_stun_lab(
        &self,
        rules: &crate::routing::linux_rules::LabRules,
        permit: &mut LabStunPermit,
        packet: crate::routing::nfqueue::Packet<'_>,
    ) -> std::io::Result<crate::routing::PacketAction> {
        use crate::routing::PacketAction;
        let gate = self.verdict_gate.lock();
        let acceptable = gate.is_ok()
            && !permit.failed
            && self.ensure_accepting().is_ok()
            && Arc::ptr_eq(&permit.engine, &self.client.routing_cache().dpi)
            && packet.local_output()
            && !packet.checksum_pending()
            && packet
                .metadata()
                .is_some_and(|meta| meta.flow == permit.key)
            && rules.owns_packet(&packet).unwrap_or(false)
            && permit.verified.admissible().unwrap_or(false);
        if acceptable {
            if let Some(changed) = crate::routing::packet_modify::stun_fingerprint(packet.bytes()) {
                // Commit before the kernel verdict, never retry another egress.
                if permit.flow.commit(PacketAction::Modify).is_ok() {
                    let result = packet.finish_stun_lab(&changed);
                    if !matches!(&result, Ok(PacketAction::Modify)) {
                        permit.failed = true;
                    }
                    return result;
                }
            }
        }
        permit.failed = true;
        packet.finish(PacketAction::Drop)
    }

    /// Deliver only a conclusive early Pass to NFQUEUE. Unknown domain/app,
    /// Modify, Redirect and all errors fail closed on raw packet ingress.
    /// No raw TCP connection is moved to the carrier after its SYN.
    #[cfg(target_os = "linux")]
    pub async fn verdict(
        &self,
        rules: &Mutex<crate::routing::linux_rules::LabRules>,
        packet: crate::routing::nfqueue::Packet<'_>,
    ) -> std::io::Result<crate::routing::PacketAction> {
        self.verdict_with_evidence(rules,packet,&|_,_,_|Ok(None)).await
    }

    #[cfg(target_os="linux")]
    async fn verdict_with_evidence<V>(
        &self,
        rules:&Mutex<crate::routing::linux_rules::LabRules>,
        packet:crate::routing::nfqueue::Packet<'_>,
        verify:&V,
    )->std::io::Result<crate::routing::PacketAction>
    where V:Fn(&crate::routing::linux_rules::LabRules,&crate::routing::nfqueue::Packet<'_>,
        crate::routing::linux_rules::CapturedSocket)->std::io::Result<Option<crate::routing::linux_events::CorroboratedFlow>> {
        use crate::routing::PacketAction;
        let evidence={
            let owner=rules.lock().map_err(|_|std::io::ErrorKind::PermissionDenied)?;
            if !owner.current()? {return Err(std::io::ErrorKind::PermissionDenied.into());}
            owner.packet_evidence(&packet).and_then(|socket|{
                let flow=socket.map(|proof|verify(&owner,&packet,proof)).transpose()?.flatten();
                Ok((socket,flow))
            })
        };
        let (socket,corroborated)=match evidence {
            Ok(value)=>value,
            Err(_)=>{
                self.deny_raw_packet(packet.metadata());
                return packet.finish(PacketAction::Drop);
            }
        };
        let cookie=socket.map(|proof|proof.cookie());
        let meta=packet.metadata();
        let action=if packet.local_output() {
            match meta {
                Some(meta)=>self.raw_verdict_bound(meta,cookie).await,
                None=>PacketAction::Drop,
            }
        } else {PacketAction::Drop};
        let gate = self.verdict_gate.lock();
        // Recheck AFTER the asynchronous policy fetch. Hold the rule mutex
        // through the actual verdict so our own dynamic lease transaction
        // cannot race this check. A foreign change is a terminal error.
        let owned = rules
            .lock()
            .map_err(|_| std::io::ErrorKind::PermissionDenied)?;
        if !owned.current()? {return Err(std::io::ErrorKind::PermissionDenied.into());}
        let unchanged=owned.packet_evidence(&packet).and_then(|current|{
            let flow=current.map(|proof|verify(&owned,&packet,proof)).transpose()?.flatten();
            Ok(current==socket && flow==corroborated)
        }).unwrap_or(false);
        let mut action = if unchanged && gate.is_ok() && self.ensure_accepting().is_ok() {
            action
        } else {
            PacketAction::Drop
        };
        if action == PacketAction::Pass {
            let current = meta
                .and_then(|m| {
                    let key = crate::routing::packet::FlowKey {
                        interface: 0,
                        ..m.flow
                    };
                    let mut raw = self.raw.lock().ok()?;
                    let entry = raw.get_mut(&key)?;
                    if entry.socket_cookie!=cookie {
                        entry.denied=true;
                    }
                    if self
                        .client
                        .routing_cache()
                        .policy
                        .check_policy(entry.digest)
                        .is_err()
                    {
                        entry.denied = true;
                    }
                    Some(!entry.denied)
                })
                .unwrap_or(false);
            if !current {
                action = PacketAction::Drop;
            }
        }
        if action==PacketAction::Drop {self.deny_raw_packet(meta);}
        let result = packet.finish(action);
        drop(owned);
        result
    }

    #[cfg(target_os="linux")]
    fn deny_raw_packet(&self,meta:Option<crate::routing::packet::PacketMeta>) {
        if let Some(meta)=meta {
            let key=crate::routing::packet::FlowKey{interface:0,..meta.flow};
            if let Ok(mut raw)=self.raw.lock() {
                if let Some(entry)=raw.get_mut(&key) {
                    entry.denied=true;
                    entry.dns_capture.retire();
                }
            }
        }
    }

    #[cfg(all(test,target_os="linux"))]
    pub(super) async fn raw_verdict(&self,meta:crate::routing::packet::PacketMeta)->crate::routing::PacketAction {
        self.raw_verdict_bound(meta,None).await
    }

    #[cfg(target_os="linux")]
    async fn serve_linux_policy_queue(&self,queue:crate::routing::nfqueue::Queue,
        rules:&Mutex<crate::routing::linux_rules::LabRules>)->Result<(),ClientError> {
        use crate::routing::PacketAction;
        let mut queue=queue.into_async().map_err(|_|ClientError::Io)?;
        loop {
            let packet=queue.next().await.map_err(|_|ClientError::Io)?;
            if !rules.lock().map_err(|_|ClientError::Configuration)?.owns_policy_packet(&packet).map_err(|_|ClientError::Io)? {
                return Err(ClientError::Open(ErrorCode::PolicyDenied));
            }
            let meta=packet.metadata();
            let action=match meta {
                Some(meta)=>self.raw_decision(meta,None,true).await,
                None=>PacketAction::Drop,
            };
            let gate=self.verdict_gate.lock();
            let owner=rules.lock().map_err(|_|ClientError::Configuration)?;
            if !owner.owns_policy_packet(&packet).map_err(|_|ClientError::Io)? {
                return Err(ClientError::Open(ErrorCode::PolicyDenied));
            }
            let current=meta.is_some_and(|m|{
                let key=crate::routing::packet::FlowKey{interface:0,..m.flow};
                self.raw.lock().ok().is_some_and(|raw|raw.get(&key).is_some_and(|entry|
                    !entry.denied && entry.action==action &&
                    self.client.routing_cache().policy.check_policy(entry.digest).is_ok()))
            });
            let action=if current && gate.is_ok() && self.ensure_accepting().is_ok(){action}else{PacketAction::Drop};
            if action==PacketAction::Redirect {
                if let Some(meta)=meta.filter(|m|m.flow.transport==crate::routing::packet::Transport::Udp
                    && m.flow.destination.port()==53) {
                    // Hold the raw lease mutex through publication and the
                    // kernel verdict; TPROXY cannot consume the commitment
                    // before the exact original datagram is redirected.
                    let key=crate::routing::packet::FlowKey{interface:0,..meta.flow};
                    let mut raw=self.raw.lock().map_err(|_|ClientError::Io)?;
                    let entry=raw.get_mut(&key).ok_or(ClientError::Open(ErrorCode::PolicyDenied))?;
                    let allowed=!entry.denied && entry.action==PacketAction::Redirect &&
                        self.client.routing_cache().policy.check_policy(entry.digest).is_ok() &&
                        packet.bytes().len().checked_sub(meta.payload_len)
                            .and_then(|offset|packet.bytes().get(offset..))
                            .is_some_and(|payload|entry.dns_capture.record(payload));
                    if !allowed {
                        entry.denied=true;
                        entry.dns_capture.retire();
                        packet.finish_routed(PacketAction::Drop).map_err(|_|ClientError::Io)?;
                        continue;
                    }
                    match packet.finish_routed(PacketAction::Redirect) {
                        Ok(PacketAction::Redirect)=>continue,
                        _=>{
                            entry.denied=true;
                            entry.dns_capture.retire();
                            return Err(ClientError::Io);
                        }
                    }
                }
            }
            if action==PacketAction::Drop {self.deny_raw_packet(meta);}
            packet.finish_routed(action).map_err(|_|ClientError::Io)?;
        }
    }

    #[cfg(target_os="linux")]
    pub(super) async fn raw_verdict_bound(&self,meta:crate::routing::packet::PacketMeta,socket_cookie:Option<u64>)->crate::routing::PacketAction {
        self.raw_decision(meta,socket_cookie,false).await
    }

    #[cfg(target_os = "linux")]
    async fn raw_decision(
        &self,
        mut meta: crate::routing::packet::PacketMeta,
        socket_cookie:Option<u64>,
        unified:bool,
    ) -> crate::routing::PacketAction {
        use crate::routing::{packet::Transport, Evidence, PacketAction};
        meta.flow.interface = 0;
        if [meta.flow.source.ip(), meta.flow.destination.ip()].iter().any(|ip| ip.is_unspecified() || ip.is_multicast() || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local() || v6.to_ipv4_mapped().is_some())) {
            return PacketAction::Drop;
        }
        if self.ensure_accepting().is_err() {
            return PacketAction::Drop;
        }
        let snapshot = match timeout(Duration::from_millis(250), self.client.routing_policy()).await
        {
            Ok(Ok(snapshot)) => snapshot,
            _ => {
                if let Ok(mut raw) = self.raw.lock() {
                    if let Some(entry) = raw.get_mut(&meta.flow) {
                        entry.denied = true;
                        entry.last = Instant::now();
                    }
                }
                return PacketAction::Drop;
            }
        };
        let cache = self.client.routing_cache();
        let digest = snapshot.digest();
        let matched = meta
            .classify(snapshot.policy(), Evidence::Unknown, Evidence::Unknown)
            .ok()
            .and_then(|c| c.action())
            .map(Action::packet_action);
        let Ok(mut raw) = self.raw.lock() else {
            return PacketAction::Drop;
        };
        if self.ensure_accepting().is_err() {
            return PacketAction::Drop;
        }
        let now = Instant::now();
        // A terminated flow must never fall back to native egress after
        // its relay closes. Keep bounded route tombstones for the epoch.
        if !unified {raw.retain(|_,entry|now.duration_since(entry.last)<Duration::from_secs(60));}
        let action=match matched {
            Some(PacketAction::Pass)=>PacketAction::Pass,
            Some(PacketAction::Redirect|PacketAction::Modify) if unified=>PacketAction::Redirect,
            _=>PacketAction::Drop,
        };
        // Port 53 is locally terminated for protected resolution; this
        // does not authorize the original resolver or infer a domain
        // for subsequent application flows.
        let action=if meta.flow.destination.port()==53 {
            if unified {PacketAction::Redirect} else {PacketAction::Drop}
        } else {action};
        let current=action!=PacketAction::Drop && cache.policy.check_policy(digest).is_ok();
        if let Some(entry) = raw.get_mut(&meta.flow) {
            entry.last = now;
            if !current || entry.digest!=digest || entry.socket_cookie!=socket_cookie || entry.action!=action {
                entry.denied=true;
            }
            if entry.denied {return PacketAction::Drop;}
            return match (entry.action,&entry.flow) {
                (PacketAction::Pass,Some(flow)) if flow.commit(PacketAction::Pass).is_ok()=>PacketAction::Pass,
                (PacketAction::Redirect,None) if unified=>PacketAction::Redirect,
                _=>PacketAction::Drop,
            };
        }
        // TCP must start from a SYN without ACK/RST/FIN. A lost or expired
        // flow is never silently recreated from a middle-of-stream packet.
        if !current || raw.len()>=crate::routing::flow::MAX_FLOWS
            || (meta.flow.transport == Transport::Tcp
                && !meta.tcp_flags.is_some_and(|f| f & 0x17 == 0x02))
        {
            return PacketAction::Drop;
        }
        let flow=if action==PacketAction::Pass {
            let Ok(flow)=cache.flows.begin_native(cache.policy.clone(),meta.flow,digest,PacketAction::Pass)
                else {return PacketAction::Drop;};
            if flow.commit(PacketAction::Pass).is_err(){return PacketAction::Drop;}
            Some(flow)
        } else {None}; // Redirect owns its common FlowLease on accept.
        raw.insert(meta.flow,RawLease{flow,action,digest,last:now,denied:false,socket_cookie,
            dns_capture:Default::default()});
        action
    }

    /// Terminate an already redirected TCP connection using the original
    /// target from conntrack. Native domain/application are Unknown.
    /// Only carrier Redirect (or legal pre-payload Modify fallback) is
    /// supported here: local Pass must use a separate proven egress path.
    #[cfg(target_os = "linux")]
    pub async fn relay_linux_tcp(&self, stream: TcpStream) -> Result<(), ClientError> {
        self.ensure_accepting()?;
        if self.registrar()?.is_none() {
            return Err(ClientError::Open(ErrorCode::PolicyDenied));
        }
        let key = crate::routing::linux_ingress::original_tcp(&stream)
            .map_err(|_| ClientError::Open(ErrorCode::PolicyDenied))?;
        self.relay_terminated_tcp(key, stream).await
    }

    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    pub(super) async fn relay_terminated_tcp(
        &self,
        key: crate::routing::packet::FlowKey,
        stream: TcpStream,
    ) -> Result<(), ClientError> {
        if key.transport != crate::routing::packet::Transport::Tcp {
            return Err(ClientError::Protocol);
        }
        if key.destination.port()==53 && self.native_modify_enabled()? {
            return tokio::select! {
                ()=self.stopped()=>Err(ClientError::Open(ErrorCode::PolicyDenied)),
                result=self.relay_native_dns_tcp(key,stream)=>result,
            };
        }
        tokio::select! {
            biased;
            () = self.stopped() => Err(ClientError::Open(ErrorCode::PolicyDenied)),
            result = async {
                let (carrier, flow, address, snapshot, configured) = self.redirect_selection(key).await?;
                if configured == crate::routing::PacketAction::Modify
                    && self.native_modify_enabled()? {
                    let registrar = self.registrar()?.ok_or(ClientError::Open(ErrorCode::PolicyDenied))?;
                    return crate::routing::carrier_socket::scope(Some(registrar),
                        self.relay_unified_tcp(key, stream, carrier, address, &snapshot, &flow)).await;
                }
                let tunnel = crate::routing::carrier_socket::scope(self.registrar()?, carrier.open(address, key.destination.port())).await?;
                tunnel.relay_guarded(stream, Some(&flow)).await
            } => result,
        }
    }

    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    fn native_modify_enabled(&self)->Result<bool,ClientError> {
        self.ensure_accepting()?;
        #[cfg(target_os="linux")]
        { Ok(self.unified.load(std::sync::atomic::Ordering::Acquire)) }
        #[cfg(all(target_os="windows",target_arch="x86_64"))]
        { Ok(self.windows_modify.lock().map_err(|_|ClientError::Io)?.is_some()) }
    }

    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    fn check_native_modify(&self,key:crate::routing::packet::FlowKey,digest:[u8;32])->Result<(),ClientError> {
        #[cfg(target_os="linux")]
        { self.check_unified_redirect(key,digest) }
        #[cfg(all(target_os="windows",target_arch="x86_64"))]
        {
            self.ensure_accepting()?;
            let denied=||ClientError::Open(ErrorCode::PolicyDenied);
            let registry=self.windows_modify.lock().map_err(|_|denied())?;
            registry.as_ref().ok_or_else(denied)?.check_modify_scope(key).map_err(|_|denied())?;
            self.client.routing_cache().policy.check_policy(digest)
        }
    }

    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    fn native_modify_source(&self,key:crate::routing::packet::FlowKey)->Result<IpAddr,ClientError> {
        let denied=||ClientError::Open(ErrorCode::PolicyDenied);
        #[cfg(target_os="linux")]
        {
            let source=route_source(key.destination).ok_or_else(denied)?.ip();
            if source!=key.source.ip() {return Err(denied());}
            Ok(source)
        }
        #[cfg(all(target_os="windows",target_arch="x86_64"))]
        {
            let registry=self.windows_modify.lock().map_err(|_|denied())?;
            registry.as_ref().ok_or_else(denied)?.modify_source(key).map_err(|_|denied())
        }
    }

    /// TLS-record Modify on a locally terminated flow in the Linux
    /// unified or Windows two-interface lab. No raw injection is claimed.
    /// Preserve exact prefix and original literal target on pre-send fallback.
    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    async fn relay_unified_tcp(
        &self, key: crate::routing::packet::FlowKey, mut stream: TcpStream,
        carrier: Carrier, address: Address, snapshot: &Snapshot,
        flow: &crate::routing::flow::FlowLease,
    ) -> Result<(), ClientError> {
        use crate::routing::{dpi, Evidence};
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        let digest = snapshot.digest();
        let cache = self.client.routing_cache();
        self.check_native_modify(key, digest)?;
        let mut prefix = Vec::new();
        if cache.dpi.enabled() && matches!(key.destination.port(), 443 | 8443)
            && crate::server::allowed_destination(key.destination.ip(), false) {
            let (bytes, hint) = dpi::read_tcp_hint(&mut stream).await?;
            prefix = bytes;
            self.check_native_modify(key, digest)?;
            if let Some(name) = hint {
                for evidence in [Evidence::Unknown, Evidence::Known(name.as_str())] {
                    if snapshot.policy().classify_with_application(evidence,
                        Evidence::Known(key.destination.ip()), Evidence::Unknown)
                        .map_err(|_| denied())?.action() != Some(Action::DirectDpi) {
                        return Err(denied());
                    }
                }
                let source=self.native_modify_source(key)?;
                match carrier.resolve_routing(&name, digest).await {
                    Ok(ips) => {
                        if !ips.contains(&key.destination.ip()) { return Err(denied()); }
                        self.check_native_modify(key, digest)?;
                        let tunnel = cache.dpi.open_checked(&name, key.destination.port(),
                            &[key.destination.ip()], digest).await?.ok_or_else(denied)?;
                        if self.native_modify_source(key)?!=source || !tunnel.matches_native_target(key,source) {
                            return Err(denied());
                        }
                        self.check_native_modify(key, digest)?;
                        // Once local execution begins, even a pre-write scope
                        // failure is a denial in this lab; no ambiguous fallback.
                        return match tunnel.relay_prefix(stream, prefix, true, Some(flow)).await? {
                            dpi::RelayOutcome::Finished => Ok(()),
                            dpi::RelayOutcome::Fallback { .. } => Err(denied()),
                        };
                    }
                    Err(ClientError::Rejected(502 | 504)) => (),
                    Err(error) => return Err(error),
                }
            }
        }
        self.check_native_modify(key, digest)?;
        let tunnel = carrier.open(address, key.destination.port()).await?;
        self.check_native_modify(key, digest)?;
        let stream = crate::reality_tcp::Prefixed::new(stream, prefix.into());
        match tunnel {
            ProxyTunnel::H2(tunnel) => tunnel.relay_guarded(stream, Some(flow)).await,
            ProxyTunnel::H3(tunnel) => tunnel.relay_guarded(stream, Some(flow)).await,
            _ => Err(denied()),
        }
    }

    /// Serve both TCP and UDP terminated adapters with the same native
    /// runtime/flow table. This is only usable after the existing owned
    /// queue is ready and the caller has provisioned compatible TPROXY,
    /// reverse-path and policy-routing rules in the isolated namespace.
    /// No production ready state or system rule activation is implied.
    #[cfg(target_os = "linux")]
    pub async fn serve_linux_redirect_capture(
        self: &Arc<Self>,
        listeners: crate::routing::linux_ingress::RedirectListeners,
    ) -> Result<(), ClientError> {
        self.ensure_accepting()?;
        let crate::routing::linux_ingress::RedirectListeners { tcp4, tcp6, udp4, udp6, .. } = listeners;
        tokio::try_join!(
            self.serve_linux_tcp_capture(tcp4, tcp6),
            self.serve_linux_udp_capture(udp4, udp6),
        ).map(|_| ())
    }

    #[cfg(target_os = "linux")]
    async fn serve_linux_tcp_capture(
        self: &Arc<Self>,
        v4: TcpListener,
        v6: TcpListener,
    ) -> Result<(), ClientError> {
        use std::sync::atomic::Ordering;
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        self.ensure_accepting()?;
        let a = v4.local_addr().map_err(|_| ClientError::Io)?;
        let b = v6.local_addr().map_err(|_| ClientError::Io)?;
        if !a.is_ipv4() || !b.is_ipv6() || a.port() == 0 || a.port() != b.port()
            || self.registrar()?.is_none()
            || self.tcp_consumer.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            return Err(denied());
        }
        struct StopOnDrop<'a>(&'a NativeIngress);
        impl Drop for StopOnDrop<'_> {
            fn drop(&mut self) {
                self.0.shutdown();
            }
        }
        let _stop = StopOnDrop(self);
        let mut tasks = JoinSet::new();
        let result = loop {
            if self.ensure_accepting().is_err() {
                break Err(denied());
            }
            let accepted = tokio::select! {
                () = self.stopped() => break Ok(()),
                finished = tasks.join_next(), if !tasks.is_empty() => {
                    if finished.is_some_and(|result| result.is_err()) {
                        break Err(ClientError::Io);
                    }
                    continue;
                }
                accepted = crate::routing::linux_ingress::accept_transparent(&v4) => accepted,
                accepted = crate::routing::linux_ingress::accept_transparent(&v6) => accepted,
            };
            let captured = match accepted {
                Ok(captured) => captured,
                Err(error) if matches!(error.kind(), std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidData) => continue,
                Err(_) => break Err(ClientError::Io),
            };
            if tasks.len() >= LOCAL_LIMIT {
                drop(captured);
                continue;
            }
            let ingress = self.clone();
            tasks.spawn(async move {
                // A failed per-flow authorization closes only its stream.
                // All forwarding still uses the shared native policy lease.
                let _ = ingress.relay_terminated_tcp(captured.key, captured.stream).await;
            });
        };
        self.shutdown();
        tasks.shutdown().await;
        result
    }

    /// Supervise both transparent UDP listeners under the already ready
    /// isolated native owner. The caller must provision the kernel redirect
    /// and reverse path rules; this cannot create or publish capture itself.
    /// No tuple can be recycled while its former relay still owns replies.
    #[cfg(target_os = "linux")]
    pub async fn serve_linux_udp_capture(
        self: &Arc<Self>,
        v4: crate::routing::linux_ingress::UdpCapture,
        v6: crate::routing::linux_ingress::UdpCapture,
    ) -> Result<(), ClientError> {
        use std::sync::atomic::Ordering;
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        self.ensure_accepting()?;
        let a = v4.local_addr().map_err(|_| ClientError::Io)?;
        let b = v6.local_addr().map_err(|_| ClientError::Io)?;
        if !a.is_ipv4() || !b.is_ipv6() || a.port() == 0 || a.port() != b.port()
            || self.registrar()?.is_none()
            || self.udp_consumer.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            return Err(denied());
        }
        // A listener failure or cancellation retires the entire native
        // runtime, not merely one address family. Never silently degrade.
        struct StopOnDrop<'a>(&'a NativeIngress);
        impl Drop for StopOnDrop<'_> {
            fn drop(&mut self) {
                self.0.shutdown();
            }
        }
        let _stop = StopOnDrop(self);
        let mut flows = NativeUdpDispatch::default();
        let mut tasks = JoinSet::new();
        let result = loop {
            if self.ensure_accepting().is_err() {
                break Err(denied());
            }
            let packet = tokio::select! {
                () = self.stopped() => break Ok(()),
                finished = tasks.join_next(), if !tasks.is_empty() => {
                    match finished {
                        Some(Ok(ticket)) if flows.complete(ticket) => continue,
                        _ => break Err(ClientError::Io),
                    }
                }
                packet = v4.receive() => packet,
                packet = v6.receive() => packet,
            };
            let packet = match packet {
                Ok(packet) => packet,
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    crate::traffic::udp_queue_drop();
                    continue;
                }
                Err(_) => break Err(ClientError::Io),
            };
            if let Some((ticket, first, subsequent)) = flows.admit(packet.key(), packet) {
                let ingress = self.clone();
                tasks.spawn(async move {
                    // Individual authenticated relay failure closes only
                    // this flow. A panic or inconsistent ownership is fatal.
                    let _ = ingress.relay_linux_udp(first, subsequent).await;
                    ticket
                });
            }
        };
        self.shutdown();
        tasks.shutdown().await;
        result
    }

    /// One terminated Linux UDP flow from UdpCapture. The platform owner
    /// demultiplexes subsequent captured datagrams by the exact key. The
    /// connected reply socket uses the original remote address as source
    /// and refuses nonlocal peers. Requires isolated, correctly provisioned
    /// reverse-path routing; does not exempt sockets from system capture.
    #[cfg(target_os = "linux")]
    pub async fn relay_linux_udp(
        &self,
        first: crate::routing::linux_ingress::CapturedDatagram,
        mut subsequent: tokio::sync::mpsc::Receiver<
            crate::routing::linux_ingress::CapturedDatagram,
        >,
    ) -> Result<(), ClientError> {
        use crate::routing::PacketAction;
        self.ensure_accepting()?;
        let registrar = self.registrar()?.ok_or(ClientError::Open(ErrorCode::PolicyDenied))?;
        let key = first.key;
        if subsequent.max_capacity() > crate::udp_relay::QUEUE {
            return Err(ClientError::Protocol);
        }
        if key.destination.port()==53 && self.unified.load(std::sync::atomic::Ordering::Acquire) {
            return tokio::select! {
                ()=self.stopped()=>Err(ClientError::Open(ErrorCode::PolicyDenied)),
                result=self.relay_native_dns_udp(first,subsequent,registrar)=>result,
            };
        }
        tokio::select! {
            biased;
            () = self.stopped() => Err(ClientError::Open(ErrorCode::PolicyDenied)),
            result = async {
                let (carrier, flow, address, snapshot, configured) = self.redirect_selection(key).await?;
                let local = if self.unified.load(std::sync::atomic::Ordering::Acquire)
                    && configured == PacketAction::Modify {
                    crate::routing::carrier_socket::scope(Some(registrar.clone()),
                        self.prepare_unified_udp(key, &first.payload, &carrier, &snapshot)).await?
                } else { None };
                let actual = if local.is_some() { PacketAction::Modify } else { PacketAction::Redirect };
                let reply = crate::routing::linux_ingress::UdpReply::open(&first).map_err(|_| ClientError::Io)?;
                let _reply_admission = reply.admit_reply(registrar.as_ref()).map_err(|_| ClientError::Io)?;
                let (tx, up) = tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
                let (down, mut rx) = tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
                let mut first_payload = Some(first.payload);
                if actual == PacketAction::Redirect {
                    tx.send(first_payload.take().ok_or(ClientError::Protocol)?).await.map_err(|_| ClientError::Io)?;
                }
                let relay = async {
                    self.ensure_accepting()?;
                    self.client.routing_cache().policy.check_policy(snapshot.digest())?;
                    if self.unified.load(std::sync::atomic::Ordering::Acquire) {
                        self.check_unified_redirect(key, snapshot.digest())?;
                    }
                    if let Some(verified) = local {
                        // This consumes the first datagram exactly once. No
                        // branch back to Redirect after entering local relay.
                        return crate::udp_relay::relay_native_modify_lab(&verified,
                            first_payload.ok_or(ClientError::Protocol)?, up, down, &flow).await;
                    }
                    let tunnel = crate::routing::carrier_socket::scope(Some(registrar.clone()),
                        carrier.open_udp(address, key.destination.port())).await?;
                    tunnel.relay_guarded(up, down, Some(&flow)).await
                };
                let feed = async move {
                    while let Some(datagram) = subsequent.recv().await {
                        if datagram.key != key || datagram.payload.len() > crate::protocol::MAX_DATAGRAM {
                            return Err(ClientError::Protocol);
                        }
                        tx.send(datagram.payload).await.map_err(|_| ClientError::Io)?;
                    }
                    Ok::<(), ClientError>(())
                };
                let replies = async {
                    while let Some(bytes) = rx.recv().await {
                        self.ensure_accepting()?;
                        if !flow.committed(actual) {
                            return Err(ClientError::Open(ErrorCode::PolicyDenied));
                        }
                        reply.send(&bytes).await.map_err(|_| ClientError::Io)?;
                    }
                    Ok::<(), ClientError>(())
                };
                supervise_native_udp(relay, feed, replies).await
            } => result,
        }
    }

    /// Select a real QUIC v1/v2 or credential-free STUN transformation.
    /// SNI/protected DNS observations are only probe hints: unknown
    /// domain/application evidence must already yield Modify.
    /// No local application bytes are sent during preparation.
    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    async fn prepare_unified_udp(
        &self,
        key: crate::routing::packet::FlowKey,
        first: &[u8],
        carrier: &Carrier,
        snapshot: &Snapshot,
    ) -> Result<Option<crate::routing::dpi::VerifiedUdp>, ClientError> {
        use crate::routing::{Evidence, packet::Transport};
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        let cache = self.client.routing_cache();
        let digest = snapshot.digest();
        self.check_native_modify(key, digest)?;
        cache.policy.check_policy(digest)?;
        if !cache.dpi.enabled() || key.transport != Transport::Udp
            || !crate::server::allowed_destination(key.destination.ip(), false)
        {
            return Ok(None);
        }
        let (name, version) = match key.destination.port() {
            443 => {
                let Some((name, version)) = crate::routing::packet_modify::unified_quic_hint(first) else {
                    return Ok(None);
                };
                (name, Some(version))
            }
            3478 if cache.dpi.stun_enabled() && crate::routing::dpi::udp::prepare_binding(
                first, crate::routing::dpi::udp::BindingStrategy::Fingerprint)
                    .is_some_and(|bytes| bytes.as_ref() != first) => {
                let Some(name) = self.dns_probe_hints.lock().map_err(|_| denied())?
                    .get(key.source.ip(), key.destination.ip(), digest) else {
                    return Ok(None);
                };
                (name, None)
            }
            _ => return Ok(None),
        };
        for evidence in [Evidence::Unknown, Evidence::Known(name.as_str())] {
            if snapshot.policy().classify_with_application(evidence,
                Evidence::Known(key.destination.ip()), Evidence::Unknown)
                .map_err(|_| denied())?.action() != Some(Action::DirectDpi) {
                return Err(denied());
            }
        }
        let source=self.native_modify_source(key)?;
        let ips = match carrier.resolve_routing(&name, digest).await {
            Ok(ips) => ips,
            Err(ClientError::Rejected(502 | 504)) => {
                cache.policy.check_policy(digest)?;
                self.check_native_modify(key, digest)?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if !ips.contains(&key.destination.ip()) { return Err(denied()); }
        cache.policy.check_policy(digest)?;
        self.check_native_modify(key, digest)?;
        // The probe API returns None for both transport and security
        // failures. Until it has a typed failure contract, do not treat
        // that ambiguity as permission to fall back.
        let verified = match version {
            Some(version) => cache.dpi.open_quic_udp_version(&name, 443, &[key.destination.ip()], digest, version).await,
            None => cache.dpi.open_stun_udp(&name, 3478, &[key.destination.ip()], digest).await,
        }.ok_or_else(denied)?;
        let modifies = match version {
            Some(_) => verified.quic_batch(first).is_some(),
            None => matches!(verified.strategy, crate::routing::dpi::UdpStrategy::StunBinding(
                crate::routing::dpi::udp::BindingStrategy::Fingerprint))
                && crate::routing::dpi::udp::prepare_binding(first, crate::routing::dpi::udp::BindingStrategy::Fingerprint)
                    .is_some_and(|bytes| bytes.as_ref() != first),
        };
        if !modifies || verified.socket.peer_addr().ok() != Some(key.destination)
            || self.native_modify_source(key)?!=source
            || !verified.socket.local_addr().is_ok_and(|local| local.ip() == source)
            || !verified.admissible()?
        {
            return Err(denied());
        }
        self.check_native_modify(key, digest)?;
        if version.is_none() && self.dns_probe_hints.lock().map_err(|_| denied())?
            .get(key.source.ip(), key.destination.ip(), digest).as_deref() != Some(name.as_str()) {
            return Err(denied());
        }
        // Both actual UDP sockets retain the pre-connect admission lease.
        // Never register a second lease for the same endpoint.
        self.check_native_modify(key, digest)?;
        Ok(Some(verified))
    }

    /// Reserve a single flow and policy generation before any protected
    /// resolver exchange on Windows. The captured tuple is not a trusted
    /// application identity, and this lease never grants physical egress.
    #[cfg(all(target_os="windows",target_arch="x86_64"))]
    async fn begin_windows_dns(&self,key:crate::routing::packet::FlowKey)
        ->Result<(crate::routing::flow::FlowLease,[u8;32]),ClientError> {
        let denied=||ClientError::Open(ErrorCode::PolicyDenied);
        let registrar=self.registrar()?.ok_or_else(denied)?;
        crate::routing::carrier_socket::scope(Some(registrar),async {
            let (carrier,cache)=match &self.client {
                ProxyClient::Direct(c)=>(c.carrier.clone(),&c.routing),
                ProxyClient::Reality(c)=>(c.generation().await?.carrier.clone(),&c.routing),
            };
            let snapshot=cache.get(|known|carrier.fetch_routing(known)).await?;
            let digest=snapshot.digest();
            self.check_native_modify(key,digest)?;
            let flow=cache.flows.begin_native(cache.policy.clone(),key,digest,crate::routing::PacketAction::Redirect)?;
            Ok((flow,digest))
        }).await
    }

    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    async fn protected_dns_answer(&self,key:crate::routing::packet::FlowKey,query:&[u8],tcp:bool,
        session:Option<(&crate::routing::flow::FlowLease,[u8;32])>)
        ->Result<ProtectedDnsAnswer,ClientError> {
        use crate::routing::{Evidence,PacketAction,native_dns::Question};
        let denied=||ClientError::Open(ErrorCode::PolicyDenied);
        self.ensure_accepting()?;
        if key.destination.port()!=53 {return Err(denied());}
        let question=Question::parse(query).ok_or(ClientError::Protocol)?;
        // UDP delivered by Linux TPROXY must consume a one-shot capture
        // commitment from the actual owned queue. Tuple alone is not
        // sufficient. TCP is stream-terminated; it has no such proof.
        #[cfg(target_os="linux")]
        let capture_digest=if !tcp {
            let key=crate::routing::packet::FlowKey{interface:0,..key};
            let mut raw=self.raw.lock().map_err(|_|denied())?;
            let entry=raw.get_mut(&key).ok_or_else(denied)?;
            if entry.denied || entry.action!=PacketAction::Redirect ||
                !entry.dns_capture.consume(query) {
                entry.denied=true;
                entry.dns_capture.retire();
                return Err(denied());
            }
            Some(entry.digest)
        } else {None};
        let registrar=self.registrar()?.ok_or_else(denied)?;
        crate::routing::carrier_socket::scope(Some(registrar),async {
            let (carrier,cache)=match &self.client {
                ProxyClient::Direct(c)=>(c.carrier.clone(),&c.routing),
                ProxyClient::Reality(c)=>(c.generation().await?.carrier.clone(),&c.routing),
            };
            let snapshot=cache.get(|known|carrier.fetch_routing(known)).await?;
            let digest=snapshot.digest();
            let failure=||ProtectedDnsAnswer{key,wire:question.failure(),digest,hint:None};
            let allowed=||->Result<(),ClientError>{
                #[cfg(target_os="linux")]
                if capture_digest.is_some_and(|pinned|pinned!=digest) {return Err(denied());}
                if let Some((flow,pinned))=session {
                    if pinned!=digest {return Err(denied());}
                    flow.check_native(key,digest,PacketAction::Redirect)?;
                }
                self.check_native_modify(key,digest)
            };
            allowed()?;
            if snapshot.policy().classify_with_application(Evidence::Known(question.name()),Evidence::Unknown,Evidence::Unknown)
                .map_err(|_|denied())?.action()==Some(Action::Blocked) {
                return Ok(failure());
            }
            allowed()?;
            if let Some((flow,_))=session {flow.commit(PacketAction::Redirect)?;}
            let ips=match carrier.resolve_native_dns(question.name(),digest).await {
                Ok(ips)=>ips,
                Err(_)=>{allowed()?;return Ok(failure());}
            };
            allowed()?;
            let mut selected=None;
            for ip in &ips {
                let action=snapshot.policy().classify_with_application(Evidence::Known(question.name()),Evidence::Known(*ip),Evidence::Unknown)
                    .map_err(|_|denied())?.action();
                let Some(action)=action else {return Ok(failure());};
                if action==Action::Blocked || selected.is_some_and(|old|old!=action) {
                    return Ok(failure());
                }
                selected=Some(action);
            }
            allowed()?;
            let wire=question.answer(&ips,tcp);
            let hints=question.hint_ips(&wire,&ips);
            allowed()?;
            Ok(ProtectedDnsAnswer{key,wire,digest,
                hint:(!hints.is_empty()).then(||(question.name().to_owned(),hints))})
        }).await
    }

    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    fn record_dns_delivery(&self,key:crate::routing::packet::FlowKey,answer:ProtectedDnsAnswer)->Result<(),ClientError> {
        if answer.key!=key {return Err(ClientError::Open(ErrorCode::PolicyDenied));}
        self.check_native_modify(key,answer.digest)?;
        if let Some((name,ips))=answer.hint {
            self.dns_probe_hints.lock().map_err(|_|ClientError::Io)?
                .record(key.source.ip(),answer.digest,&name,&ips);
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
    async fn relay_native_dns_tcp(&self,key:crate::routing::packet::FlowKey,mut stream:TcpStream)->Result<(),ClientError> {
        #[cfg(all(target_os="windows",target_arch="x86_64"))]
        let (flow,digest)=self.begin_windows_dns(key).await?;
        #[cfg(all(target_os="windows",target_arch="x86_64"))]
        let session=Some((&flow,digest));
        #[cfg(target_os="linux")]
        let session=None;
        for _ in 0..64 {
            let len=match timeout(NEGOTIATE_TIMEOUT,stream.read_u16()).await {
                Ok(Ok(len))=>usize::from(len),
                Ok(Err(e)) if e.kind()==std::io::ErrorKind::UnexpectedEof=>return Ok(()),
                Ok(Err(_))=>return Err(ClientError::Io),
                Err(_)=>return Err(ClientError::Timeout),
            };
            if !(12..=crate::routing::native_dns::MAX_QUERY).contains(&len) {return Err(ClientError::Protocol);}
            let mut query=vec![0u8;len];
            timeout(NEGOTIATE_TIMEOUT,stream.read_exact(&mut query)).await.map_err(|_|ClientError::Timeout)?.map_err(|_|ClientError::Io)?;
            let answer=self.protected_dns_answer(key,&query,true,session).await?;
            self.check_native_modify(key,answer.digest)?;
            timeout(REPLY_TIMEOUT,async {
                stream.write_u16(answer.wire.len() as u16).await?;
                stream.write_all(&answer.wire).await
            }).await.map_err(|_|ClientError::Timeout)?.map_err(|_|ClientError::Io)?;
            self.record_dns_delivery(key,answer)?;
        }
        Ok(())
    }

    #[cfg(target_os="linux")]
    async fn relay_native_dns_udp(&self,first:crate::routing::linux_ingress::CapturedDatagram,
        mut subsequent:tokio::sync::mpsc::Receiver<crate::routing::linux_ingress::CapturedDatagram>,
        registrar:Arc<dyn crate::routing::carrier_socket::Registrar>)->Result<(),ClientError> {
        let key=first.key;
        let reply=crate::routing::linux_ingress::UdpReply::open(&first).map_err(|_|ClientError::Io)?;
        let _lease=reply.admit_reply(registrar.as_ref()).map_err(|_|ClientError::Io)?;
        let mut current=first;
        for _ in 0..64 {
            if current.key!=key {return Err(ClientError::Protocol);}
            let answer=self.protected_dns_answer(key,&current.payload,false,None).await?;
            self.check_unified_redirect(key,answer.digest)?;
            reply.send(&answer.wire).await.map_err(|_|ClientError::Io)?;
            self.record_dns_delivery(key,answer)?;
            match timeout(Duration::from_secs(10),subsequent.recv()).await {
                Ok(Some(next))=>current=next,
                _=>return Ok(()),
            }
        }
        Ok(())
    }

    /// Actual multi-datagram QUIC Modify in the isolated Linux lab.
    /// The caller supplies only kernel-captured UDP and an untrusted
    /// probe-name hint. Domain and application evidence remain Unknown;
    /// the authenticated policy must conclusively authorize Modify without
    /// that hint. No ordinary proxy or production native activation.
    #[cfg(target_os = "linux")]
    pub async fn relay_linux_quic_lab(
        &self,
        first: crate::routing::linux_ingress::CapturedDatagram,
        mut subsequent: tokio::sync::mpsc::Receiver<
            crate::routing::linux_ingress::CapturedDatagram,
        >,
        domain: &str,
    ) -> Result<(), ClientError> {
        use crate::routing::{carrier_socket, packet::Transport, Evidence, PacketAction};
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        let key = first.key;
        if key.transport != Transport::Udp
            || key.destination.port() != 443
            || subsequent.max_capacity() > crate::udp_relay::QUEUE
            || !crate::server::allowed_destination(key.destination.ip(), false)
        {
            return Err(denied());
        }
        let registrar = self.registrar()?.ok_or_else(denied)?;
        tokio::select! {
            biased;
            () = self.stopped() => Err(denied()),
            result = carrier_socket::scope(Some(registrar.clone()), async {
                self.ensure_accepting()?;
                let name = crate::routing::domain_name(domain).map_err(|_| denied())?;
                if crate::routing::packet_modify::quic_initial_datagrams(&first.payload, &name).is_none() {
                    return Err(denied());
                }
                let (carrier, cache) = match &self.client {
                    ProxyClient::Direct(c) => (c.carrier.clone(), &c.routing),
                    ProxyClient::Reality(c) => (c.generation().await?.carrier.clone(), &c.routing),
                };
                let snapshot = cache.get(|known| carrier.fetch_routing(known)).await?;
                let digest = snapshot.digest();
                for evidence in [Evidence::Unknown, Evidence::Known(name.as_str())] {
                    if snapshot.policy().classify_with_application(evidence,Evidence::Known(key.destination.ip()),Evidence::Unknown)
                        .map_err(|_| denied())?.action() != Some(Action::DirectDpi) { return Err(denied()); }
                }
                let ips = carrier.resolve_routing(&name,digest).await?;
                if !ips.contains(&key.destination.ip()) { return Err(denied()); }
                let version = crate::reality_quic_wire::long(&first.payload)
                    .and_then(|header| crate::quic_core::wire::Version::from_wire(header.version))
                    .ok_or_else(denied)?;
                let verified = cache.dpi.open_quic_udp_version(&name,443,&[key.destination.ip()],digest,version).await.ok_or_else(denied)?;
                if verified.quic_batch(&first.payload).is_none() || verified.socket.peer_addr().ok() != Some(key.destination)
                    || !verified.socket.local_addr().is_ok_and(|a| a.ip() == key.source.ip())
                    || !verified.admissible()? { return Err(denied()); }
                let flow = cache.flows.begin_native(cache.policy.clone(),key,digest,PacketAction::Modify)?;
                // VerifiedUdp retains its own exact pre-connect admission.
                let reply = crate::routing::linux_ingress::UdpReply::open(&first).map_err(|_| ClientError::Io)?;
                let _reply_admission = reply.admit_reply(registrar.as_ref()).map_err(|_| denied())?;
                let (tx,up) = tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
                let (down,mut rx) = tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
                let relay = crate::udp_relay::relay_quic_lab(&verified,first.payload,up,down,&flow);
                let feed = async move {
                    while let Some(datagram) = subsequent.recv().await {
                        if datagram.key != key || datagram.payload.len() > crate::protocol::MAX_DATAGRAM {
                            return Err(ClientError::Protocol);
                        }
                        tx.send(datagram.payload).await.map_err(|_| ClientError::Io)?;
                    }
                    Ok::<(),ClientError>(())
                };
                let replies = async {
                    while let Some(bytes) = rx.recv().await {
                        if !flow.committed(PacketAction::Modify) { return Err(denied()); }
                        reply.send(&bytes).await.map_err(|_| ClientError::Io)?;
                    }
                    Ok::<(),ClientError>(())
                };
                supervise_native_udp(relay, feed, replies).await
            }) => result,
        }
    }

    /// Common UDP handoff for a trusted platform adapter with a terminated
    /// datagram flow. The OS-specific receiver/response routing is owned
    /// by the platform adapter; use relay_linux_udp on Linux.
    pub async fn relay_terminated_udp(
        &self,
        key: crate::routing::packet::FlowKey,
        upload: tokio::sync::mpsc::Receiver<Vec<u8>>,
        download: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Result<(), ClientError> {
        if key.transport != crate::routing::packet::Transport::Udp
            || upload.max_capacity() > crate::udp_relay::QUEUE
            || download.max_capacity() > crate::udp_relay::QUEUE
        {
            return Err(ClientError::Protocol);
        }
        tokio::select! {
            biased;
            () = self.stopped() => Err(ClientError::Open(ErrorCode::PolicyDenied)),
            result = async {
                let (carrier, flow, address) = self.redirect(key).await?;
                let tunnel = crate::routing::carrier_socket::scope(self.registrar()?, carrier.open_udp(address, key.destination.port())).await?;
                tunnel.relay_guarded(upload, download, Some(&flow)).await
            } => result,
        }
    }

    pub(super) async fn redirect(
        &self,
        key: crate::routing::packet::FlowKey,
    ) -> Result<(Carrier, crate::routing::flow::FlowLease, Address), ClientError> {
        let (carrier, flow, address, _, _) = self.redirect_selection(key).await?;
        Ok((carrier, flow, address))
    }

    #[cfg(target_os = "linux")]
    fn check_unified_redirect(&self, key: crate::routing::packet::FlowKey, digest: [u8; 32]) -> Result<(), ClientError> {
        use crate::routing::PacketAction;
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        self.ensure_accepting()?;
        let key = crate::routing::packet::FlowKey { interface: 0, ..key };
        if !self.unified.load(std::sync::atomic::Ordering::Acquire)
            || !self.raw.lock().map_err(|_| denied())?.get(&key).is_some_and(|entry|
                !entry.denied && entry.action == PacketAction::Redirect && entry.digest == digest)
        {
            return Err(denied());
        }
        self.client.routing_cache().policy.check_policy(digest)
    }

    async fn redirect_selection(
        &self,
        key: crate::routing::packet::FlowKey,
    ) -> Result<(Carrier, crate::routing::flow::FlowLease, Address, Arc<Snapshot>, crate::routing::PacketAction), ClientError> {
        use crate::routing::{Evidence, PacketAction};
        self.ensure_accepting()?;
        let denied = || ClientError::Open(ErrorCode::PolicyDenied);
        if key.destination.port() == 0
            || key.source.port() == 0
            || key.destination.ip().is_loopback()
            || key.destination.ip().is_unspecified()
            || key.destination.ip().is_multicast()
            || key.destination == key.source
            || matches!(key.destination, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.ip().is_unicast_link_local() || v6.ip().to_ipv4_mapped().is_some())
        {
            return Err(denied());
        }
        let (carrier, cache) = match &self.client {
            ProxyClient::Direct(c) => (c.carrier.clone(), &c.routing),
            ProxyClient::Reality(c) => (c.generation().await?.carrier.clone(), &c.routing),
        };
        let snapshot = crate::routing::carrier_socket::scope(
            self.registrar()?,
            cache.get(|known| carrier.fetch_routing(known)),
        )
        .await?;
        let configured = snapshot
            .policy()
            .classify_with_application(
                Evidence::Unknown,
                Evidence::Known(key.destination.ip()),
                Evidence::Unknown,
            )
            .map_err(|_| denied())?
            .action()
            .ok_or_else(denied)?
            .packet_action();
        if !matches!(configured, PacketAction::Redirect | PacketAction::Modify) {
            return Err(denied());
        }
        #[cfg(target_os="linux")]
        if self.unified.load(std::sync::atomic::Ordering::Acquire) {
            self.check_unified_redirect(key, snapshot.digest())?;
        }
        self.ensure_accepting()?;
        let flow =
            cache
                .flows
                .begin_native(cache.policy.clone(), key, snapshot.digest(), configured)?;
        let address = match key.destination.ip() {
            IpAddr::V4(ip) => Address::V4(ip.octets()),
            IpAddr::V6(ip) => Address::V6(ip.octets()),
        };
        Ok((carrier, flow, address, snapshot, configured))
    }
}

/// Exact tuple dispatch shared by native adapters. A completed task must
/// return its own generation ticket; stale completion cannot release a
/// replacement flow. Packet ownership and routing are separate gates.
#[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeUdpTicket {
    key: crate::routing::packet::FlowKey,
    generation: u64,
}

#[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
struct NativeUdpDispatch<T> {
    flows: std::collections::HashMap<
        crate::routing::packet::FlowKey,
        (NativeUdpTicket, tokio::sync::mpsc::Sender<T>),
    >,
    generation: u64,
}

#[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
impl<T> Default for NativeUdpDispatch<T> {
    fn default() -> Self {
        Self { flows: std::collections::HashMap::new(), generation: 0 }
    }
}

#[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
impl<T> NativeUdpDispatch<T> {
    fn admit(
        &mut self,
        key: crate::routing::packet::FlowKey,
        packet: T,
    ) -> Option<(NativeUdpTicket, T, tokio::sync::mpsc::Receiver<T>)> {
        if key.transport != crate::routing::packet::Transport::Udp {
            crate::traffic::udp_queue_drop();
            return None;
        }
        if let Some((_, tx)) = self.flows.get(&key) {
            // Closed and full both drop. Only the joined relay task may
            // release the tuple, after its response drain and lease drop.
            if tx.try_send(packet).is_err() {
                crate::traffic::udp_queue_drop();
            }
            return None;
        }
        if self.flows.len() >= LOCAL_LIMIT {
            crate::traffic::udp_queue_drop();
            return None;
        }
        let Some(generation) = self.generation.checked_add(1) else {
            crate::traffic::udp_queue_drop();
            return None;
        };
        self.generation = generation;
        let ticket = NativeUdpTicket { key, generation };
        let (tx, rx) = tokio::sync::mpsc::channel(crate::udp_relay::QUEUE);
        self.flows.insert(key, (ticket, tx));
        Some((ticket, packet, rx))
    }

    fn complete(&mut self, ticket: NativeUdpTicket) -> bool {
        if !self.flows.get(&ticket.key).is_some_and(|(current, _)| *current == ticket) {
            return false;
        }
        self.flows.remove(&ticket.key);
        true
    }
}

#[cfg(all(test, any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64"))))]
#[test]
fn native_udp_dispatch_keeps_interleaved_interfaces_and_generations_separate() {
    use crate::routing::packet::{FlowKey, Transport};
    let a = FlowKey {
        source: "192.0.2.1:1234".parse().unwrap(),
        destination: "198.51.100.1:443".parse().unwrap(),
        transport: Transport::Udp,
        interface: 7,
    };
    let b = FlowKey { interface: 8, ..a };
    let mut dispatch = NativeUdpDispatch::default();
    let (a1, first, mut arx) = dispatch.admit(a, vec![1]).unwrap();
    let (b1, second, mut brx) = dispatch.admit(b, vec![2]).unwrap();
    assert_eq!(first, vec![1]);
    assert_eq!(second, vec![2]);
    assert!(dispatch.admit(a, vec![3]).is_none());
    assert!(dispatch.admit(b, vec![4]).is_none());
    assert_eq!(arx.try_recv().unwrap(), vec![3]);
    assert_eq!(brx.try_recv().unwrap(), vec![4]);
    assert!(dispatch.admit(FlowKey { transport: Transport::Tcp, ..a }, vec![0]).is_none());
    drop(arx);
    assert!(dispatch.admit(a, vec![5]).is_none());
    assert!(dispatch.complete(a1));
    let (a2, _, mut new_rx) = dispatch.admit(a, vec![6]).unwrap();
    assert!(!dispatch.complete(a1));
    assert!(dispatch.admit(a, vec![7]).is_none());
    assert_eq!(new_rx.try_recv().unwrap(), vec![7]);
    assert!(dispatch.complete(a2));
    assert!(dispatch.complete(b1));
}

/// A clean relay EOF must not cancel accepted reverse datagrams. Keep the
/// flow lease and reply socket until a bounded drain finishes. Feed EOF is
/// not relay EOF; dropping the upload sender lets the carrier send FIN.
/// Errors and outer runtime cancellation still terminate immediately.
#[cfg(any(target_os = "linux", all(target_os = "windows", target_arch = "x86_64")))]
async fn supervise_native_udp(
    relay: impl std::future::Future<Output = Result<(), ClientError>>,
    feed: impl std::future::Future<Output = Result<(), ClientError>>,
    replies: impl std::future::Future<Output = Result<(), ClientError>>,
) -> Result<(), ClientError> {
    tokio::pin!(relay, feed, replies);
    let mut fed = false;
    let mut replied = false;
    loop {
        tokio::select! {
            biased;
            result = &mut relay => {
                result?;
                if !replied {
                    timeout(Duration::from_secs(2), &mut replies)
                        .await.map_err(|_| ClientError::Timeout)??;
                }
                return Ok(());
            }
            result = &mut feed, if !fed => { result?; fed = true; }
            result = &mut replies, if !replied => { result?; replied = true; }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod native_udp_lifecycle_tests {
    use super::*;

    #[test]
    fn native_udp_tuple_not_reused_before_task_join_and_queues_are_bounded() {
        use crate::routing::{linux_ingress::CapturedDatagram, packet::{FlowKey, Transport}};
        let key = FlowKey {
            source: "192.0.2.1:1234".parse().unwrap(),
            destination: "198.51.100.1:443".parse().unwrap(),
            transport: Transport::Udp,
            interface: 0,
        };
        let packet = |key, n| CapturedDatagram { key, payload: vec![n] };
        let mut dispatch = NativeUdpDispatch::default();
        let (ticket, first, mut rx) = dispatch.admit(key, packet(key, 0)).unwrap();
        assert_eq!(first.payload(), &[0]);
        for n in 1..=crate::udp_relay::QUEUE + 1 {
            assert!(dispatch.admit(key, packet(key, n as u8)).is_none());
        }
        for n in 1..=crate::udp_relay::QUEUE {
            assert_eq!(rx.try_recv().unwrap().payload(), &[n as u8]);
        }
        assert!(rx.try_recv().is_err());
        drop(rx);
        assert!(dispatch.admit(key, packet(key, 99)).is_none());
        assert!(dispatch.complete(ticket));
        assert!(!dispatch.complete(ticket));
        let (replacement, _, _new) = dispatch.admit(key, packet(key, 100)).unwrap();
        assert_ne!(replacement, ticket);
        assert!(!dispatch.complete(ticket));
        // Keep receivers live to make the capacity test independent of EOF.
        let mut receivers = Vec::new();
        for n in 1..LOCAL_LIMIT {
            let other = FlowKey { source: SocketAddr::new(key.source.ip(), 2000 + n as u16), ..key };
            receivers.push(dispatch.admit(other, packet(other, 1)).unwrap().2);
        }
        let overflow = FlowKey { source: "192.0.2.1:65000".parse().unwrap(), ..key };
        assert!(dispatch.admit(overflow, packet(overflow, 1)).is_none());
        assert_eq!(dispatch.flows.len(), LOCAL_LIMIT);
        assert!(dispatch.complete(replacement));
    }

    #[tokio::test]
    async fn relay_completion_drains_accepted_replies_after_upload_eof() {
        let (up, mut upload) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let (down, mut download) = tokio::sync::mpsc::channel::<Vec<u8>>(2);
        let feed = async move {
            up.send(vec![1]).await.unwrap();
            Ok(())
        };
        let relay = async move {
            assert_eq!(upload.recv().await, Some(vec![1]));
            assert!(upload.recv().await.is_none());
            down.send(vec![2]).await.unwrap();
            down.send(vec![3]).await.unwrap();
            Ok(())
        };
        let mut observed = Vec::new();
        let replies = async {
            while let Some(bytes) = download.recv().await {
                tokio::task::yield_now().await;
                observed.push(bytes);
            }
            Ok(())
        };
        supervise_native_udp(relay, feed, replies).await.unwrap();
        assert_eq!(observed, [vec![2], vec![3]]);
    }

    #[tokio::test]
    async fn failed_relay_does_not_drain_or_wait_for_upload() {
        let result = supervise_native_udp(
            async { Err(ClientError::Protocol) },
            std::future::pending(),
            std::future::pending(),
        ).await;
        assert!(matches!(result, Err(ClientError::Protocol)));
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl Drop for NativeIngress {
    fn drop(&mut self) {
        self.shutdown();
    }
}

