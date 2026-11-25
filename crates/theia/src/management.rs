//! M4.2d: shared bounded IPC protocol over private Linux socket or Windows SID Named Pipe.
//!
//! Linux-only opt-in endpoint via THEIA_CONTROL_DIR, a private, operator-owned
//! runtime directory. No administrative TCP, token disclosure or TLS/listener mutation.
//! Windows binds only explicit current-user SID DACL, never default pipe permissions.
//! The endpoint exists only while a server process is actually serving.
use std::fmt;

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::PathBuf,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::{sync::Arc, time::Duration};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use tokio::sync::{mpsc, oneshot};

#[cfg(any(target_os = "linux", target_os = "windows"))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(target_os = "linux")]
use tokio::time::timeout;
#[cfg(target_os = "linux")]
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
};

#[cfg(target_os = "linux")]
const SOCKET_NAME: &str = "theia-server.sock";
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(any(target_os="linux",target_os="windows"))]
pub(crate) const CLIENT_TIMEOUT:Duration=Duration::from_secs(15);
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) const MAX_COMMAND_BYTES: usize = 256;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) const MAX_RESPONSE_BYTES: u64 = 256;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) const MAX_CLIENTS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementError {
    Unsupported,
    NotConfigured,
    UnsafeDirectory,
    UnsafeEndpoint,
    SocketUnavailable,
    Io,
    TimedOut,
    InvalidReply,
    CandidateRejected,
}

impl fmt::Display for ManagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unsupported => "local management IPC unsupported on this platform",
            Self::NotConfigured => "THEIA_CONTROL_DIR is not configured",
            Self::UnsafeDirectory => "management runtime directory is unsafe",
            Self::UnsafeEndpoint => "management pipe name or Windows security identity is unsafe",
            Self::SocketUnavailable => "local management socket unavailable",
            Self::Io => "local management I/O failed",
            Self::TimedOut => "local management request timed out",
            Self::InvalidReply => "invalid local management response",
            Self::CandidateRejected => "candidate or expected revision rejected; query status if Apply outcome is uncertain",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ManagementError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCommand {
    ClientStatus,
    ClientPreview{expected_revision:u64,candidate_sha256:[u8;32]},
    ClientApply{expected_revision:u64,candidate_sha256:[u8;32]},
    Health,
    Status,
    /// Explicitly rejected in this read-only slice. Never reload implicitly.
    Reload,
    /// Read-only preflight; does not modify config or runtime.
    CheckReload,
    /// Read-only restart readiness: validates TLS and tests fresh TCP/UDP ports.
    /// Never reserves a port, stops listeners or commits new runtime state.
    CheckRestart,
    /// Advisory last-same-port-identity recovery readiness (no PEM values).
    CheckTlsRollback,
    CheckAuthRollback,
    ApplyAuthRollback { expected_revision:u64 },
    CheckRestartRollback,
    ApplyRestartRollback{expected_revision:u64},
    CheckRestartBound{expected_revision:u64,candidate_sha256:[u8;32]},
    RealityStatus { id:[u8;64], len:u8, manifest:[u8;32] },
    /// Explicit one-shot CAS on the protected native management endpoint.
    ApplyTlsRollback {
        expected_revision: u64,
    },
    /// Read-only validation of a quota-only saved candidate.
    CheckQuota,
    /// Native occupancy-aware quota resize, mandatory revision/SHA CAS.
    ApplyQuotaBound {
        expected_revision: u64,
        candidate_sha256: [u8; 32],
    },
    /// Explicit restart cutover, requires saved TOML SHA-256 and revision CAS.
    /// Only distinct new ports with unchanged quotas/roster are supported.
    ApplyRestartBound {
        expected_revision: u64,
        candidate_sha256: [u8; 32],
        /// Fingerprint of actual CERT + PRIVATE KEY PEM content, not TOML.
        tls_sha256: [u8; 32],
    },
    /// Explicit opt-in CAS auth publication, supported only by Linux server.
    ApplyReload {
        expected_revision: u64,
    },
    /// Confirm exact saved TOML bytes, not an unrelated file on this server.
    ApplyReloadBound {
        expected_revision: u64,
        candidate_sha256: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusReply {
    ClientRunning{revision:u64,config_sha256:[u8;32],descriptor_revision:u64,transport:u8,fallback:bool},
    ClientReady{revision:u64},
    ClientApplied{revision:u64},
    Healthy,
    Running {
        inbounds: usize,
    },
    RunningRevision {
        inbounds: usize,
        revision: u64,
    },
    Unsupported,
    /// Candidate passes the deliberately narrow compatibility preflight.
    Compatible,
    /// Existing authorization CAS path is sufficient; no restart is needed.
    RestartAuthorizationOnly,
    /// Some active listener bind must be reused: maintenance is required.
    RestartRequiresMaintenance,
    /// Exact existing TCP/UDP ports can rotate fully prevalidated TLS identities.
    RestartSamePortTlsReady,
    /// Valid quota-only candidate, no active connection is revoked.
    QuotaReady,
    QuotaApplied {
        revision: u64,
    },
    /// All NEW candidate ports were temporarily bound, then released.
    RestartFreshPortsBindable,
    RestartApplied {
        revision: u64,
    },
    TlsRollbackReady {
        revision: u64,
        remaining_seconds: u64,
    },
    TlsRollbackApplied {
        revision: u64,
    },
    AuthRollbackReady { revision:u64, remaining_seconds:u64 },
    AuthRollbackApplied { revision:u64 },
    RestartRollbackReady{revision:u64,remaining_seconds:u64},
    RestartRollbackApplied{revision:u64},
    RestartPreview{same_port:bool,material_sha256:[u8;32]},
    RealityRunning { generation:u64, revision:u64, health_revision:u64, active_reference:u8, overlap:bool },
    RealitySuspended,
    Applied {
        revision: u64,
    },
}

impl StatusCommand{
    pub fn reality_status(id:&str,manifest:[u8;32])->Result<Self,ManagementError>{
        if !crate::config::valid_id(id)||manifest==[0;32]{return Err(ManagementError::InvalidReply);}
        let mut bytes=[0;64];bytes[..id.len()].copy_from_slice(id.as_bytes());
        Ok(Self::RealityStatus{id:bytes,len:id.len() as u8,manifest})
    }
}

#[cfg(target_os = "linux")]
fn verify_private_dir(directory: &Path) -> Result<(), ManagementError> {
    let metadata = fs::symlink_metadata(directory).map_err(|_| ManagementError::UnsafeDirectory)?;
    // No symbolic links; private permissions and effective owner are both
    // required, independent of the operator's umask.
    if !directory.is_absolute()
        || !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ManagementError::UnsafeDirectory);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn endpoint_path(directory: &Path) -> Result<PathBuf, ManagementError> {
    verify_private_dir(directory)?;
    let path = directory.join(SOCKET_NAME);
    use std::os::unix::ffi::OsStrExt;
    if path.as_os_str().as_bytes().len() > 100 {
        return Err(ManagementError::UnsafeDirectory);
    }
    Ok(path)
}

/// Linux binding guard. A preexisting socket, regular file or symlink is NEVER
/// removed as a recovery heuristic. The owning server must cleanly release it.
#[cfg(target_os = "linux")]
pub struct StatusServer {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    inbounds: usize,
    preflight: Option<Arc<crate::reload_preflight::ReloadPreflight>>,
    live: Option<Arc<crate::live_auth::LiveAuthorization>>,
    runtime: Option<Arc<crate::runtime_generation::State>>,
    restarts: Option<mpsc::Sender<crate::runtime_generation::RestartRequest>>,
    client:Option<Arc<crate::local_proxy::ClientRuntime>>,
}

#[cfg(target_os = "linux")]
impl StatusServer {
    /// Caller must supply an existing, private 0700 directory owned by the
    /// effective user. Does not read config, touch external networks or reload.
    pub fn bind_in(directory: &Path, inbounds: usize) -> Result<Self, ManagementError> {
        if inbounds == 0 {
            return Err(ManagementError::InvalidReply);
        }
        let path = endpoint_path(directory)?;
        // bind() refuses a preexisting path instead of deleting it. It may
        // briefly create a world-accessible socket, but its parent is 0700.
        let listener = UnixListener::bind(&path).map_err(|_| ManagementError::SocketUnavailable)?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| ManagementError::Io)?;
        if !metadata.file_type().is_socket() {
            return Err(ManagementError::Io);
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| ManagementError::Io)?;
        Ok(Self {
            listener,
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            inbounds,
            preflight: None,
            live: None,
            runtime: None,
            restarts: None,
            client:None,
        })
    }

    pub(crate) fn with_preflight(
        mut self,
        preflight: Arc<crate::reload_preflight::ReloadPreflight>,
    ) -> Self {
        self.preflight = Some(preflight);
        self
    }

    /// Without both the running authorization controller and exact config
    /// preflight, Apply remains unavailable (including test-only sockets).
    pub(crate) fn with_live_authorization(
        mut self,
        live: Arc<crate::live_auth::LiveAuthorization>,
    ) -> Self {
        self.live = Some(live);
        self
    }

    pub(crate) fn with_client(mut self,client:Arc<crate::local_proxy::ClientRuntime>)->Self{
        self.client=Some(client);self
    }
    pub(crate) fn with_runtime(mut self,state:Arc<crate::runtime_generation::State>)->Self{
        self.runtime=Some(state);
        self
    }

    pub(crate) fn with_supervisor(
        mut self,
        state: Arc<crate::runtime_generation::State>,
        requests: mpsc::Sender<crate::runtime_generation::RestartRequest>,
    ) -> Self {
        self.runtime = Some(state);
        self.restarts = Some(requests);
        self
    }

    /// If the operator did not explicitly provision THEIA_CONTROL_DIR, the
    /// existing server continues without management IPC (no secret fallback).
    pub fn from_environment(inbounds: usize) -> Result<Option<Self>, ManagementError> {
        let Some(directory) = std::env::var_os("THEIA_CONTROL_DIR") else {
            return Ok(None);
        };
        Self::bind_in(Path::new(&directory), inbounds).map(Some)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Owned by the actual server runtime; aborting the task closes the
    /// listener and conditionally cleans only this socket's original inode.
    pub async fn serve(self) -> Result<(), ManagementError> {
        let mut tasks = JoinSet::new();
        let concurrency = Arc::new(Semaphore::new(MAX_CLIENTS));
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted.map_err(|_| ManagementError::Io)?;
                    if let Ok(permit) = concurrency.clone().try_acquire_owned() {
                        let inbounds = self.inbounds;
                        let preflight = self.preflight.clone();
                        let live = self.live.clone();
                        let runtime = self.runtime.clone();
                        let restarts = self.restarts.clone();
                        let client=self.client.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            // Only the live supervisor owns generation commits.
                            if let Some(client)=client{
                                let _=timeout(CLIENT_TIMEOUT,handle_client(stream,client)).await;
                            }else{
                                let _=timeout(IO_TIMEOUT,handle_internal(stream,inbounds,preflight,live,runtime,restarts)).await;
                            }
                        });
                    }
                    // Over budget: close socket immediately, never build a
                    // queue or expose success for an unavailable service.
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for StatusServer {
    fn drop(&mut self) {
        // Never unlink another process's replacement socket or regular file.
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if meta.file_type().is_socket() && meta.dev() == self.device && meta.ino() == self.inode
            {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) async fn handle_internal<S>(
    mut stream: S,
    mut inbounds: usize,
    mut preflight: Option<Arc<crate::reload_preflight::ReloadPreflight>>,
    mut live: Option<Arc<crate::live_auth::LiveAuthorization>>,
    runtime: Option<Arc<crate::runtime_generation::State>>,
    restarts: Option<mpsc::Sender<crate::runtime_generation::RestartRequest>>,
) -> Result<(), ManagementError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut command = Vec::with_capacity(16);
    let mut newline = false;
    for _ in 0..MAX_COMMAND_BYTES {
        let mut byte = [0u8];
        match stream.read_exact(&mut byte).await {
            Ok(_) => {
                if byte[0] == b'\n' {
                    newline = true;
                    break;
                }
                command.push(byte[0]);
            }
            Err(_) => break,
        }
    }
    // Resolve exactly one generation snapshot for this request. The CAS
    // publication is separately guarded against a concurrent restart commit.
    let observed = if let Some(runtime) = &runtime {
        let view = runtime.snapshot().map_err(|_| ManagementError::Io)?;
        inbounds = view.inbounds;
        preflight = Some(view.preflight.clone());
        live = Some(view.live.clone());
        Some(view)
    } else {
        None
    };
    let response = if !newline {
        "ERR unsupported\n".to_owned()
    } else {
        match command.as_slice() {
            b"health" => "theia-health-v1 ok\n".to_owned(),
            b"status" => {
                if let Some(live) = &live {
                    match live.revision() {
                        Ok(revision) => {
                            format!(
                                "theia-status-v2 running inbounds={inbounds} revision={revision}\n"
                            )
                        }
                        Err(_) => "ERR unsupported\n".to_owned(),
                    }
                } else {
                    format!("theia-status-v1 running inbounds={inbounds}\n")
                }
            }
            candidate if parse_quota_revision(candidate).is_some()
                && runtime.as_ref().is_some_and(|r|r.has_reality_ledger())=>{
                if let (Some(preflight),Some(runtime),Some(previous))=(&preflight,&runtime,&observed){
                    let (expected,digest)=parse_quota_revision(candidate).expect("parsed");
                    let preflight=preflight.clone();
                    match tokio::task::spawn_blocking(move||preflight.load_quota_candidate_bound(digest)).await{
                        Ok(Ok(document))=>match runtime.apply_reality_quota(previous,expected,&document){
                            Ok(revision)=>format!("theia-quota-v1 applied revision={revision}\n"),
                            Err(_)=>"theia-quota-v1 rejected\n".into(),
                        },
                        _=>"theia-quota-v1 rejected\n".into(),
                    }
                }else{"ERR unsupported\n".into()}
            }
            candidate
                if parse_restart_revision(candidate).is_some()
                    || parse_quota_revision(candidate).is_some() =>
            {
                if let (Some(preflight), Some(runtime), Some(previous), Some(restarts)) =
                    (&preflight, &runtime, &observed, &restarts)
                {
                    let (expected, sha256, kind, tls_pin) =
                        if let Some((revision, digest)) = parse_quota_revision(candidate) {
                            (
                                revision,
                                digest,
                                crate::runtime_generation::ChangeKind::Quota,
                                None,
                            )
                        } else {
                            let (revision, digest, tls_digest) =
                                parse_restart_revision(candidate).expect("already parsed");
                            (
                                revision,
                                digest,
                                crate::runtime_generation::ChangeKind::Restart,
                                Some(tls_digest),
                            )
                        };
                    let verb = if kind == crate::runtime_generation::ChangeKind::Quota {
                        "theia-quota-v1"
                    } else {
                        "theia-restart-v1"
                    };
                    // A timed-out worker may finish a bounded filesystem read
                    // but can NEVER commit a cancelled management operation.
                    let preflight = Arc::clone(preflight);
                    let candidate = tokio::task::spawn_blocking(move || {
                        if kind == crate::runtime_generation::ChangeKind::Quota {
                            let document = preflight.load_quota_candidate_bound(sha256)?;
                            Ok((document, None))
                        } else {
                            let document = preflight.load_restart_candidate_bound(sha256)?;
                            // Capture and validate each PEM exactly once.
                            // No subsequent supervisor disk reads are allowed.
                            let material =
                                crate::server::CapturedTls::capture(&document).map_err(|_| {
                                    crate::restart_guard::RestartError::InvalidTlsIdentity
                                })?;
                            if !material.matches(&tls_pin.expect("restart must pin PEM")) {
                                return Err(crate::restart_guard::RestartError::InvalidTlsIdentity);
                            }
                            Ok((document, Some(material)))
                        }
                    })
                    .await;
                    match candidate {
                        Ok(Ok((candidate, material)))
                            if runtime.still_current(previous, expected) =>
                        {
                            let (complete, result) = oneshot::channel();
                            let request = crate::runtime_generation::RestartRequest {
                                kind,
                                previous: Arc::clone(previous),
                                expected_revision: expected,
                                candidate,
                                material,
                                complete,
                            };
                            if restarts.try_send(request).is_err() {
                                format!("{verb} rejected\n")
                            } else {
                                match result.await {
                                    Ok(Ok(revision)) => {
                                        format!("{verb} applied revision={revision}\n")
                                    }
                                    _ => format!("{verb} rejected\n"),
                                }
                            }
                        }
                        _ => format!("{verb} rejected\n"),
                    }
                } else {
                    "ERR unsupported\n".to_owned()
                }
            }
            candidate if parse_restart_preview(candidate).is_some()=>{
                if let (Some(runtime),Some(previous),Some(preflight))=(&runtime,&observed,&preflight){
                    let (expected,digest)=parse_restart_preview(candidate).expect("parsed");
                    let preflight=preflight.clone();
                    let result=tokio::task::spawn_blocking(move||preflight.preview_restart_bound(digest)).await;
                    match result{
                        Ok(Ok((same_port,material))) if runtime.still_current(previous,expected)=>{
                            let hex=material.iter().map(|b|format!("{b:02x}")).collect::<String>();
                            let mode=if same_port{"same-port"}else{"fresh"};
                            format!("theia-restart-preview-v1 {mode} sha256={hex}\n")
                        }
                        _=>"theia-restart-preview-v1 rejected\n".into(),
                    }
                }else{"ERR unsupported\n".into()}
            }
            b"restart-rollback-check"=>{
                match runtime.as_ref().and_then(|r|r.restart_rollback_status()){
                    Some((revision,seconds))=>format!("theia-restart-rollback-v1 ready revision={revision} seconds={seconds}\n"),
                    None=>"theia-restart-rollback-v1 unavailable\n".into(),
                }
            }
            candidate if parse_restart_rollback(candidate).is_some()=>{
                if let (Some(runtime),Some(previous),Some(restarts))=(&runtime,&observed,&restarts){
                    let expected=parse_restart_rollback(candidate).expect("parsed");
                    if runtime.still_current(previous,expected)&&runtime.restart_rollback_status().map(|(r,_)|r)==Some(expected){
                        let (complete,response)=oneshot::channel();
                        let request=crate::runtime_generation::RestartRequest{
                            kind:crate::runtime_generation::ChangeKind::StructuralRollback,
                            previous:previous.clone(),expected_revision:expected,
                            candidate:previous.document.as_ref().clone(),material:None,complete,
                        };
                        if restarts.try_send(request).is_ok(){
                            match response.await{
                                Ok(Ok(revision))=>format!("theia-restart-rollback-v1 applied revision={revision}\n"),
                                _=>"theia-restart-rollback-v1 rejected\n".into(),
                            }
                        }else{"theia-restart-rollback-v1 rejected\n".into()}
                    }else{"theia-restart-rollback-v1 rejected\n".into()}
                }else{"ERR unsupported\n".into()}
            }
            candidate if parse_reality_status(candidate).is_some()=>{
                let (id,manifest)=parse_reality_status(candidate).expect("parsed");
                match runtime.as_ref().and_then(|state|state.reality_status(id,manifest)){
                    Some(Some(s))=>format!("theia-reality-v1 g={} r={} h={} a={} o={}\n",
                        s.generation,s.revision,s.health_revision,s.active_reference,u8::from(s.overlap)),
                    Some(None)=>"theia-reality-v1 suspended\n".into(),
                    None=>"ERR unsupported\n".into(),
                }
            }
            b"auth-rollback-check" => {
                if let Some(runtime)=&runtime{
                    match runtime.auth_rollback_status(){
                        Some((revision,seconds))=>format!("theia-auth-rollback-v1 ready revision={revision} seconds={seconds}\n"),
                        None=>"theia-auth-rollback-v1 unavailable\n".to_owned(),
                    }
                }else{"ERR unsupported\n".to_owned()}
            }
            candidate if parse_auth_rollback_revision(candidate).is_some()=>{
                if let (Some(runtime),Some(previous))=(&runtime,&observed){
                    let expected=parse_auth_rollback_revision(candidate).expect("parsed");
                    if let Some(document)=runtime.auth_rollback_candidate(previous,expected){
                        let preflight=previous.preflight.clone();
                        let checked=document.clone();
                        let managed=runtime.has_reality_ledger();
                        let valid=tokio::task::spawn_blocking(move||if managed{
                            preflight.validate_managed_candidate(checked.as_ref().clone())
                        }else{preflight.validate_candidate(checked.as_ref().clone())}).await;
                        if matches!(valid,Ok(Ok(_))){
                            match runtime.rollback_auth(previous,&document,expected){
                                Ok(revision)=>format!("theia-auth-rollback-v1 applied revision={revision}\n"),
                                Err(_)=>"theia-auth-rollback-v1 rejected\n".to_owned(),
                            }
                        }else{"theia-auth-rollback-v1 rejected\n".to_owned()}
                    }else{"theia-auth-rollback-v1 rejected\n".to_owned()}
                }else{"ERR unsupported\n".to_owned()}
            }
            b"tls-rollback-check" => {
                if let Some(runtime) = &runtime {
                    match runtime.rollback_status() {
                        Some((revision, seconds)) => format!(
                            "theia-tls-rollback-v1 ready revision={revision} seconds={seconds}\n"
                        ),
                        None => "theia-tls-rollback-v1 unavailable\n".to_owned(),
                    }
                } else {
                    "ERR unsupported\n".to_owned()
                }
            }
            candidate if parse_tls_rollback_revision(candidate).is_some() => {
                if let (Some(runtime), Some(previous), Some(restarts)) =
                    (&runtime, &observed, &restarts)
                {
                    let expected = parse_tls_rollback_revision(candidate)
                        .expect("validated rollback revision");
                    if runtime.still_current(previous, expected)
                        && runtime.rollback_status().map(|(revision, _)| revision) == Some(expected)
                    {
                        let (complete, response) = oneshot::channel();
                        let request = crate::runtime_generation::RestartRequest {
                            kind: crate::runtime_generation::ChangeKind::Rollback,
                            previous: Arc::clone(previous),
                            expected_revision: expected,
                            candidate: previous.document.as_ref().clone(),
                            material: None,
                            complete,
                        };
                        if restarts.try_send(request).is_err() {
                            "theia-tls-rollback-v1 rejected\n".to_owned()
                        } else {
                            match response.await {
                                Ok(Ok(revision)) => {
                                    format!("theia-tls-rollback-v1 applied revision={revision}\n")
                                }
                                _ => "theia-tls-rollback-v1 rejected\n".to_owned(),
                            }
                        }
                    } else {
                        "theia-tls-rollback-v1 rejected\n".to_owned()
                    }
                } else {
                    "ERR unsupported\n".to_owned()
                }
            }
            b"check-quota" => {
                if let Some(preflight) = preflight {
                    match tokio::task::spawn_blocking(move || preflight.check_quota_file()).await {
                        Ok(Ok(())) => "theia-quota-v1 ready\n".to_owned(),
                        _ => "theia-quota-v1 rejected\n".to_owned(),
                    }
                } else {
                    "ERR unsupported\n".to_owned()
                }
            }
            b"check-restart" => {
                if let Some(preflight) = preflight {
                    // Blocking disk/PEM verification and transient native
                    // binds are read-only with respect to the running server.
                    // A worker completing AFTER IPC timeout still cannot
                    // swap the runtime, publish authorization or terminate it.
                    match tokio::task::spawn_blocking(move || preflight.check_restart_file()).await
                    {
                        Ok(Ok(crate::restart_guard::RestartVerdict::AuthorizationOnly)) => {
                            "theia-restart-v1 auth-only\n".to_owned()
                        }
                        Ok(Ok(crate::restart_guard::RestartVerdict::SamePortTlsReady)) => {
                            "theia-restart-v1 same-port-tls\n".to_owned()
                        }
                        Ok(Ok(crate::restart_guard::RestartVerdict::RequiresMaintenance)) => {
                            "theia-restart-v1 maintenance\n".to_owned()
                        }
                        Ok(Ok(crate::restart_guard::RestartVerdict::FreshPortsBindable)) => {
                            "theia-restart-v1 ports-bindable\n".to_owned()
                        }
                        _ => "theia-restart-v1 rejected\n".to_owned(),
                    }
                } else {
                    "ERR unsupported\n".to_owned()
                }
            }
            b"check-reload" => {
                if let Some(preflight) = preflight {
                    // 1 MiB bounded config + PEM reads belong on a worker.
                    // A timed-out worker can NEVER apply, only return a verdict.
                    let managed=runtime.as_ref().is_some_and(|r|r.has_reality_ledger());
                    match tokio::task::spawn_blocking(move || if managed{preflight.check_managed_file()}else{preflight.check_file()}).await {
                        Ok(Ok(())) => "theia-check-v1 compatible\n".to_owned(),
                        _ => "theia-check-v1 rejected\n".to_owned(),
                    }
                } else {
                    "ERR unsupported\n".to_owned()
                }
            }
            candidate if parse_bound_revision(candidate).is_some() => {
                if let (Some(preflight), Some(live)) = (preflight, live) {
                    let (expected, sha256) =
                        parse_bound_revision(candidate).expect("already parsed");
                    // Worker is read-only even after IPC cancellation.
                    // The exact same validated bytes are committed only from
                    // the live async task under CAS, never by the worker.
                    let managed=runtime.as_ref().is_some_and(|r|r.has_reality_ledger());
                    match tokio::task::spawn_blocking(move || {
                        if managed{preflight.load_managed_candidate_bound(sha256)}else{preflight.load_candidate_bound(sha256)}
                    })
                    .await
                    {
                        Ok(Ok(candidate)) => {
                            let result =
                                if let (Some(runtime), Some(previous)) = (&runtime, &observed) {
                                    runtime.apply_auth(previous, &candidate, expected)
                                } else {
                                    live.stage(&candidate, expected)
                                        .and_then(|stage| live.publish(stage))
                                };
                            match result {
                                Ok(revision) => {
                                    format!("theia-apply-v1 applied revision={revision}\n")
                                }
                                Err(_) => "theia-apply-v1 rejected\n".to_owned(),
                            }
                        }
                        _ => "theia-apply-v1 rejected\n".to_owned(),
                    }
                } else {
                    "ERR unsupported\n".to_owned()
                }
            }
            candidate if parse_apply_revision(candidate).is_some() => {
                if observed.as_ref().is_some_and(|view|view.document.server.inbounds.iter().any(|i|i.reality.is_some())) {
                    "theia-apply-v1 rejected\n".to_owned()
                } else if let (Some(preflight), Some(live)) = (preflight, live) {
                    let expected = parse_apply_revision(candidate).expect("already parsed");
                    // The blocking worker can finish after a timeout, but it
                    // NEVER commits. Only this still-live task may stage/CAS
                    // publish the exact document that was just validated.
                    match tokio::task::spawn_blocking(move || preflight.load_candidate()).await {
                        Ok(Ok(candidate)) => {
                            let result =
                                if let (Some(runtime), Some(previous)) = (&runtime, &observed) {
                                    runtime.apply_auth(previous, &candidate, expected)
                                } else {
                                    live.stage(&candidate, expected)
                                        .and_then(|stage| live.publish(stage))
                                };
                            match result {
                                Ok(revision) => {
                                    format!("theia-apply-v1 applied revision={revision}\n")
                                }
                                Err(_) => "theia-apply-v1 rejected\n".to_owned(),
                            }
                        }
                        _ => "theia-apply-v1 rejected\n".to_owned(),
                    }
                } else {
                    "ERR unsupported\n".to_owned()
                }
            }
            _ => "ERR unsupported\n".to_owned(),
        }
    };
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|_| ManagementError::Io)?;
    stream.shutdown().await.map_err(|_| ManagementError::Io)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn positive_decimal(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn parse_apply_revision(command: &[u8]) -> Option<u64> {
    let raw = command.strip_prefix(b"apply-reload rev=")?;
    positive_decimal(std::str::from_utf8(raw).ok()?)
}

/// Canonical lowercase hex only; no ambiguity or relaxed delimiters.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn decode_digest(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut digest = [0u8; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(digest)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn parse_bound_revision(command: &[u8]) -> Option<(u64, [u8; 32])> {
    parse_bound_command(command, b"apply-reload rev=")
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn parse_restart_revision(command: &[u8]) -> Option<(u64, [u8; 32], [u8; 32])> {
    let raw = std::str::from_utf8(command.strip_prefix(b"restart-apply rev=")?).ok()?;
    let (revision, hashes) = raw.split_once(" sha256=")?;
    let (document, tls) = hashes.split_once(" tls-sha256=")?;
    Some((
        positive_decimal(revision)?,
        decode_digest(document)?,
        decode_digest(tls)?,
    ))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn parse_restart_preview(command:&[u8])->Option<(u64,[u8;32])>{
    parse_bound_command(command,b"restart-preview rev=")
}
#[cfg(any(target_os="linux",target_os="windows"))]
fn parse_restart_rollback(command:&[u8])->Option<u64>{
    positive_decimal(std::str::from_utf8(command.strip_prefix(b"restart-rollback-apply rev=")?).ok()?)
}
#[cfg(any(target_os="linux",target_os="windows"))]
fn parse_reality_status(command:&[u8])->Option<(&str,[u8;32])>{
    let raw=std::str::from_utf8(command.strip_prefix(b"reality-status id=")?).ok()?;
    let (id,digest)=raw.split_once(" manifest=")?;
    if !crate::config::valid_id(id){return None;}
    Some((id,decode_digest(digest)?))
}

#[cfg(any(target_os="linux",target_os="windows"))]
fn parse_auth_rollback_revision(command:&[u8])->Option<u64>{
    positive_decimal(std::str::from_utf8(command.strip_prefix(b"auth-rollback-apply rev=")?).ok()?)
}

#[cfg(any(target_os="linux",target_os="windows"))]
fn parse_tls_rollback_revision(command: &[u8]) -> Option<u64> {
    let raw = std::str::from_utf8(command.strip_prefix(b"tls-rollback-apply rev=")?).ok()?;
    positive_decimal(raw)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn parse_quota_revision(command: &[u8]) -> Option<(u64, [u8; 32])> {
    parse_bound_command(command, b"quota-apply rev=")
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn parse_bound_command(command: &[u8], prefix: &[u8]) -> Option<(u64, [u8; 32])> {
    let rest = std::str::from_utf8(command.strip_prefix(prefix)?).ok()?;
    let (revision, digest) = rest.split_once(" sha256=")?;
    Some((positive_decimal(revision)?, decode_digest(digest)?))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) async fn handle_client<S>(mut stream:S,client:Arc<crate::local_proxy::ClientRuntime>)->Result<(),ManagementError>
where S:AsyncRead+AsyncWrite+Unpin{
    let mut command=Vec::new();
    let mut newline=false;
    for _ in 0..MAX_COMMAND_BYTES{
        let mut byte=[0u8;1];
        if stream.read_exact(&mut byte).await.is_err(){break;}
        if byte[0]==b'\n'{newline=true;break;}
        command.push(byte[0]);
    }
    let response=if !newline{"ERR unsupported\n".into()}else if command==b"client-status"{
        let (revision,digest,descriptor,transport,fallback)=client.status().await;
        let hex=digest.iter().map(|b|format!("{b:02x}")).collect::<String>();
        format!("theia-client-v1 r={revision} sha256={hex} d={descriptor} t={transport} f={}\n",u8::from(fallback))
    }else{
        let candidate=parse_bound_command(&command,b"client-preview rev=").map(|(r,d)|(r,d,false))
            .or_else(||parse_bound_command(&command,b"client-apply rev=").map(|(r,d)|(r,d,true)));
        match candidate{
            Some((r,d,apply))=>match client.change(r,d,apply).await{
                Ok(revision)=>format!("theia-client-v1 {} r={revision}\n",if apply{"applied"}else{"ready"}),
                Err(_)=>"theia-client-v1 rejected\n".into(),
            },
            None=>"ERR unsupported\n".into(),
        }
    };
    stream.write_all(response.as_bytes()).await.map_err(|_|ManagementError::Io)?;
    stream.shutdown().await.map_err(|_|ManagementError::Io)
}

#[cfg(any(target_os="linux",target_os="windows"))]
pub(crate) async fn exchange<S>(
    mut stream: S,
    command: StatusCommand,
) -> Result<StatusReply, ManagementError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = match command {
        StatusCommand::ClientStatus=>b"client-status\n".to_vec(),
        StatusCommand::ClientPreview{expected_revision,candidate_sha256}|StatusCommand::ClientApply{expected_revision,candidate_sha256}=>{
            if expected_revision==0{return Err(ManagementError::InvalidReply);}
            let action=if matches!(command,StatusCommand::ClientApply{..}){"apply"}else{"preview"};
            let hex=candidate_sha256.iter().map(|b|format!("{b:02x}")).collect::<String>();
            format!("client-{action} rev={expected_revision} sha256={hex}\n").into_bytes()
        }
        StatusCommand::Health => b"health\n".to_vec(),
        StatusCommand::Status => b"status\n".to_vec(),
        StatusCommand::Reload => b"reload\n".to_vec(),
        StatusCommand::CheckReload => b"check-reload\n".to_vec(),
        StatusCommand::CheckRestart => b"check-restart\n".to_vec(),
        StatusCommand::CheckRestartBound{expected_revision,candidate_sha256}=>{
            if expected_revision==0{return Err(ManagementError::InvalidReply);}
            let digest=candidate_sha256.iter().map(|b|format!("{b:02x}")).collect::<String>();
            format!("restart-preview rev={expected_revision} sha256={digest}\n").into_bytes()
        }
        StatusCommand::CheckRestartRollback=>b"restart-rollback-check\n".to_vec(),
        StatusCommand::ApplyRestartRollback{expected_revision}=>{
            if expected_revision==0{return Err(ManagementError::InvalidReply);}
            format!("restart-rollback-apply rev={expected_revision}\n").into_bytes()
        }
        StatusCommand::RealityStatus{id,len,manifest}=>{
            let raw=id.get(..usize::from(len)).ok_or(ManagementError::InvalidReply)?;
            let name=std::str::from_utf8(raw).map_err(|_|ManagementError::InvalidReply)?;
            if !crate::config::valid_id(name){return Err(ManagementError::InvalidReply);}
            let digest=manifest.iter().map(|b|format!("{b:02x}")).collect::<String>();
            format!("reality-status id={name} manifest={digest}\n").into_bytes()
        }
        StatusCommand::CheckAuthRollback=>b"auth-rollback-check\n".to_vec(),
        StatusCommand::ApplyAuthRollback{expected_revision}=>{
            if expected_revision==0{return Err(ManagementError::InvalidReply);}
            format!("auth-rollback-apply rev={expected_revision}\n").into_bytes()
        }
        StatusCommand::CheckTlsRollback => b"tls-rollback-check\n".to_vec(),
        StatusCommand::ApplyTlsRollback { expected_revision } => {
            if expected_revision == 0 {
                return Err(ManagementError::InvalidReply);
            }
            format!("tls-rollback-apply rev={expected_revision}\n").into_bytes()
        }
        StatusCommand::CheckQuota => b"check-quota\n".to_vec(),
        StatusCommand::ApplyQuotaBound {
            expected_revision,
            candidate_sha256,
        } => {
            if expected_revision == 0 {
                return Err(ManagementError::InvalidReply);
            }
            let digest = candidate_sha256
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("quota-apply rev={expected_revision} sha256={digest}\n").into_bytes()
        }
        StatusCommand::ApplyRestartBound {
            expected_revision,
            candidate_sha256,
            tls_sha256,
        } => {
            if expected_revision == 0 {
                return Err(ManagementError::InvalidReply);
            }
            let digest = candidate_sha256
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let tls = tls_sha256
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("restart-apply rev={expected_revision} sha256={digest} tls-sha256={tls}\n")
                .into_bytes()
        }
        StatusCommand::ApplyReload { expected_revision } => {
            if expected_revision == 0 {
                return Err(ManagementError::InvalidReply);
            }
            format!("apply-reload rev={expected_revision}\n").into_bytes()
        }
        StatusCommand::ApplyReloadBound {
            expected_revision,
            candidate_sha256,
        } => {
            if expected_revision == 0 {
                return Err(ManagementError::InvalidReply);
            }
            let digest = candidate_sha256
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("apply-reload rev={expected_revision} sha256={digest}\n").into_bytes()
        }
    };
    stream
        .write_all(&request)
        .await
        .map_err(|_| ManagementError::Io)?;
    let mut reply = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut reply)
        .await
        .map_err(|_| ManagementError::Io)?;
    if reply.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(ManagementError::InvalidReply);
    }
    if matches!(command,StatusCommand::ClientStatus|StatusCommand::ClientPreview{..}|StatusCommand::ClientApply{..}){
        let raw=std::str::from_utf8(&reply).map_err(|_|ManagementError::InvalidReply)?;
        if raw=="ERR unsupported\n"{return Err(ManagementError::Unsupported);}
        if raw=="theia-client-v1 rejected\n"{return Err(ManagementError::CandidateRejected);}
        let line=raw.strip_prefix("theia-client-v1 ").and_then(|s|s.strip_suffix('\n')).ok_or(ManagementError::InvalidReply)?;
        let parsed=(||match command{
            StatusCommand::ClientStatus=>{
                let mut fields=line.split(' ');
                let revision=positive_decimal(fields.next()?.strip_prefix("r=")?)?;
                let config_sha256=decode_digest(fields.next()?.strip_prefix("sha256=")?)?;
                let d=fields.next()?.strip_prefix("d=")?;
                let descriptor_revision=if d=="0"{0}else{positive_decimal(d)?};
                let transport=match fields.next()?.strip_prefix("t=")?{"0"=>0,"2"=>2,"3"=>3,_=>return None};
                let fallback=match fields.next()?.strip_prefix("f=")?{"0"=>false,"1"=>true,_=>return None};
                if fields.next().is_some()||(descriptor_revision==0&&(transport!=0||fallback)){return None;}
                Some(StatusReply::ClientRunning{revision,config_sha256,descriptor_revision,transport,fallback})
            }
            StatusCommand::ClientPreview{expected_revision,..}=>{
                let revision=positive_decimal(line.strip_prefix("ready r=")?)?;
                (revision==expected_revision).then_some(StatusReply::ClientReady{revision})
            }
            StatusCommand::ClientApply{expected_revision,..}=>{
                let revision=positive_decimal(line.strip_prefix("applied r=")?)?;
                (Some(revision)==expected_revision.checked_add(1)).then_some(StatusReply::ClientApplied{revision})
            }
            _=>None
        })();
        return parsed.ok_or(ManagementError::InvalidReply);
    }
    if reply == b"theia-health-v1 ok\n" && command == StatusCommand::Health {
        return Ok(StatusReply::Healthy);
    }
    if reply == b"ERR unsupported\n" && command == StatusCommand::Reload {
        return Ok(StatusReply::Unsupported);
    }
    if matches!(command,StatusCommand::CheckRestartBound{..}){
        let text=std::str::from_utf8(&reply).map_err(|_|ManagementError::InvalidReply)?;
        if let Some((mode,digest))=text.strip_prefix("theia-restart-preview-v1 ").and_then(|s|s.strip_suffix('\n'))
            .and_then(|s|s.split_once(" sha256=")){
            let same_port=match mode{"same-port"=>true,"fresh"=>false,_=>return Err(ManagementError::InvalidReply)};
            return Ok(StatusReply::RestartPreview{same_port,material_sha256:decode_digest(digest).ok_or(ManagementError::InvalidReply)?});
        }
        return match text{"theia-restart-preview-v1 rejected\n"=>Err(ManagementError::CandidateRejected),
            "ERR unsupported\n"=>Err(ManagementError::Unsupported),_=>Err(ManagementError::InvalidReply)};
    }
    if command==StatusCommand::CheckRestartRollback{
        let text=std::str::from_utf8(&reply).map_err(|_|ManagementError::InvalidReply)?;
        if let Some((revision,seconds))=text.strip_prefix("theia-restart-rollback-v1 ready revision=")
            .and_then(|s|s.strip_suffix('\n')).and_then(|s|s.split_once(" seconds=")){
            if let (Some(revision),Some(remaining_seconds))=(positive_decimal(revision),positive_decimal(seconds)){
                if remaining_seconds<=300{return Ok(StatusReply::RestartRollbackReady{revision,remaining_seconds});}
            }
        }
        return match text{"theia-restart-rollback-v1 unavailable\n"=>Err(ManagementError::CandidateRejected),
            "ERR unsupported\n"=>Err(ManagementError::Unsupported),_=>Err(ManagementError::InvalidReply)};
    }
    if let StatusCommand::ApplyRestartRollback{expected_revision}=command{
        let text=std::str::from_utf8(&reply).map_err(|_|ManagementError::InvalidReply)?;
        let applied=text.strip_prefix("theia-restart-rollback-v1 applied revision=").and_then(|s|s.strip_suffix('\n')).and_then(positive_decimal);
        return match applied{
            Some(revision) if Some(revision)==expected_revision.checked_add(1)=>Ok(StatusReply::RestartRollbackApplied{revision}),
            _ if text=="theia-restart-rollback-v1 rejected\n"=>Err(ManagementError::CandidateRejected),
            _ if text=="ERR unsupported\n"=>Err(ManagementError::Unsupported),_=>Err(ManagementError::InvalidReply)};
    }
    if matches!(command,StatusCommand::RealityStatus{..}){
        let text=std::str::from_utf8(&reply).map_err(|_|ManagementError::InvalidReply)?;
        if text=="theia-reality-v1 suspended\n"{return Ok(StatusReply::RealitySuspended);}
        if text=="ERR unsupported\n"{return Err(ManagementError::Unsupported);}
        let parsed=(||{
            let mut fields=text.strip_prefix("theia-reality-v1 ")?.strip_suffix('\n')?.split(' ');
            let generation=positive_decimal(fields.next()?.strip_prefix("g=")?)?;
            let revision=positive_decimal(fields.next()?.strip_prefix("r=")?)?;
            let health_revision=positive_decimal(fields.next()?.strip_prefix("h=")?)?;
            let active_reference=match fields.next()?.strip_prefix("a=")?{"0"=>0,"1"=>1,"2"=>2,_=>return None};
            let overlap=match fields.next()?.strip_prefix("o=")?{"0"=>false,"1"=>true,_=>return None};
            if fields.next().is_some(){return None;}
            Some(StatusReply::RealityRunning{generation,revision,health_revision,active_reference,overlap})
        })();
        return parsed.ok_or(ManagementError::InvalidReply);
    }
    if command==StatusCommand::CheckAuthRollback{
        let text=std::str::from_utf8(&reply).map_err(|_|ManagementError::InvalidReply)?;
        if let Some((revision,seconds))=text.strip_prefix("theia-auth-rollback-v1 ready revision=")
            .and_then(|s|s.strip_suffix('\n')).and_then(|s|s.split_once(" seconds=")){
            if let (Some(revision),Some(remaining_seconds))=(positive_decimal(revision),positive_decimal(seconds)){
                if remaining_seconds<=300{return Ok(StatusReply::AuthRollbackReady{revision,remaining_seconds});}
            }
        }
        return match text{
            "theia-auth-rollback-v1 unavailable\n"=>Err(ManagementError::CandidateRejected),
            "ERR unsupported\n"=>Err(ManagementError::Unsupported),
            _=>Err(ManagementError::InvalidReply),
        };
    }
    if let StatusCommand::ApplyAuthRollback{expected_revision}=command{
        let text=std::str::from_utf8(&reply).map_err(|_|ManagementError::InvalidReply)?;
        let applied=text.strip_prefix("theia-auth-rollback-v1 applied revision=")
            .and_then(|s|s.strip_suffix('\n')).and_then(positive_decimal);
        return match applied{
            Some(revision) if Some(revision)==expected_revision.checked_add(1)=>Ok(StatusReply::AuthRollbackApplied{revision}),
            _ if text=="theia-auth-rollback-v1 rejected\n"=>Err(ManagementError::CandidateRejected),
            _ if text=="ERR unsupported\n"=>Err(ManagementError::Unsupported),
            _=>Err(ManagementError::InvalidReply),
        };
    }
    if command == StatusCommand::CheckTlsRollback {
        let reply = std::str::from_utf8(&reply).map_err(|_| ManagementError::InvalidReply)?;
        let info = reply
            .strip_prefix("theia-tls-rollback-v1 ready revision=")
            .and_then(|value| value.strip_suffix('\n'))
            .and_then(|value| value.split_once(" seconds="));
        if let Some((revision, seconds)) = info {
            let revision = positive_decimal(revision);
            let remaining_seconds = positive_decimal(seconds);
            if let (Some(revision), Some(remaining_seconds)) = (revision, remaining_seconds) {
                if remaining_seconds <= 300 {
                    return Ok(StatusReply::TlsRollbackReady {
                        revision,
                        remaining_seconds,
                    });
                }
            }
        }
        return match reply {
            "theia-tls-rollback-v1 unavailable\n" => Err(ManagementError::CandidateRejected),
            "ERR unsupported\n" => Err(ManagementError::Unsupported),
            _ => Err(ManagementError::InvalidReply),
        };
    }
    if let StatusCommand::ApplyTlsRollback { expected_revision } = command {
        let text = std::str::from_utf8(&reply).map_err(|_| ManagementError::InvalidReply)?;
        let applied = text
            .strip_prefix("theia-tls-rollback-v1 applied revision=")
            .and_then(|line| line.strip_suffix('\n'))
            .and_then(positive_decimal);
        return match applied {
            Some(revision) if Some(revision) == expected_revision.checked_add(1) => {
                Ok(StatusReply::TlsRollbackApplied { revision })
            }
            _ if reply == b"theia-tls-rollback-v1 rejected\n" => {
                Err(ManagementError::CandidateRejected)
            }
            _ if reply == b"ERR unsupported\n" => Err(ManagementError::Unsupported),
            _ => Err(ManagementError::InvalidReply),
        };
    }
    if command == StatusCommand::CheckQuota {
        return match reply.as_slice() {
            b"theia-quota-v1 ready\n" => Ok(StatusReply::QuotaReady),
            b"theia-quota-v1 rejected\n" => Err(ManagementError::CandidateRejected),
            b"ERR unsupported\n" => Err(ManagementError::Unsupported),
            _ => Err(ManagementError::InvalidReply),
        };
    }
    if let StatusCommand::ApplyQuotaBound {
        expected_revision, ..
    } = command
    {
        let text = std::str::from_utf8(&reply).map_err(|_| ManagementError::InvalidReply)?;
        let applied = text
            .strip_prefix("theia-quota-v1 applied revision=")
            .and_then(|line| line.strip_suffix('\n'))
            .and_then(positive_decimal);
        return match applied {
            Some(revision) if Some(revision) == expected_revision.checked_add(1) => {
                Ok(StatusReply::QuotaApplied { revision })
            }
            _ if reply == b"theia-quota-v1 rejected\n" => Err(ManagementError::CandidateRejected),
            _ if reply == b"ERR unsupported\n" => Err(ManagementError::Unsupported),
            _ => Err(ManagementError::InvalidReply),
        };
    }
    if let StatusCommand::ApplyRestartBound {
        expected_revision, ..
    } = command
    {
        let text = std::str::from_utf8(&reply).map_err(|_| ManagementError::InvalidReply)?;
        let applied = text
            .strip_prefix("theia-restart-v1 applied revision=")
            .and_then(|line| line.strip_suffix('\n'))
            .and_then(positive_decimal);
        return match applied {
            Some(revision) if Some(revision) == expected_revision.checked_add(1) => {
                Ok(StatusReply::RestartApplied { revision })
            }
            _ if reply == b"theia-restart-v1 rejected\n" => Err(ManagementError::CandidateRejected),
            _ if reply == b"ERR unsupported\n" => Err(ManagementError::Unsupported),
            _ => Err(ManagementError::InvalidReply),
        };
    }
    if command == StatusCommand::CheckRestart {
        return match reply.as_slice() {
            b"theia-restart-v1 auth-only\n" => Ok(StatusReply::RestartAuthorizationOnly),
            b"theia-restart-v1 maintenance\n" => Ok(StatusReply::RestartRequiresMaintenance),
            b"theia-restart-v1 same-port-tls\n" => Ok(StatusReply::RestartSamePortTlsReady),
            b"theia-restart-v1 ports-bindable\n" => Ok(StatusReply::RestartFreshPortsBindable),
            b"theia-restart-v1 rejected\n" => Err(ManagementError::CandidateRejected),
            b"ERR unsupported\n" => Err(ManagementError::Unsupported),
            _ => Err(ManagementError::InvalidReply),
        };
    }
    if command == StatusCommand::CheckReload {
        return match reply.as_slice() {
            b"theia-check-v1 compatible\n" => Ok(StatusReply::Compatible),
            b"theia-check-v1 rejected\n" => Err(ManagementError::CandidateRejected),
            _ => Err(ManagementError::InvalidReply),
        };
    }
    if let StatusCommand::ApplyReload { expected_revision }
    | StatusCommand::ApplyReloadBound {
        expected_revision, ..
    } = command
    {
        let text = std::str::from_utf8(&reply).map_err(|_| ManagementError::InvalidReply)?;
        if let Some(revision) = text
            .strip_prefix("theia-apply-v1 applied revision=")
            .and_then(|line| line.strip_suffix('\n'))
            .and_then(positive_decimal)
        {
            if Some(revision) == expected_revision.checked_add(1) {
                return Ok(StatusReply::Applied { revision });
            }
        }
        return if reply == b"theia-apply-v1 rejected\n" {
            Err(ManagementError::CandidateRejected)
        } else if reply == b"ERR unsupported\n" {
            Err(ManagementError::Unsupported)
        } else {
            Err(ManagementError::InvalidReply)
        };
    }
    if command == StatusCommand::Status {
        let reply = std::str::from_utf8(&reply).map_err(|_| ManagementError::InvalidReply)?;
        if let Some((count, revision)) = reply
            .strip_prefix("theia-status-v2 running inbounds=")
            .and_then(|line| line.strip_suffix('\n'))
            .and_then(|line| line.split_once(" revision="))
        {
            let inbounds = positive_decimal(count).filter(|_| count.len() <= 7);
            let revision = positive_decimal(revision);
            if let (Some(inbounds), Some(revision)) = (inbounds, revision) {
                if let Ok(inbounds) = usize::try_from(inbounds) {
                    return Ok(StatusReply::RunningRevision { inbounds, revision });
                }
            }
        }
        if let Some(number) = reply
            .strip_prefix("theia-status-v1 running inbounds=")
            .and_then(|line| line.strip_suffix('\n'))
        {
            if !number.starts_with('0')
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && number.len() <= 7
            {
                if let Ok(inbounds) = number.parse::<usize>() {
                    return Ok(StatusReply::Running { inbounds });
                }
            }
        }
    }
    Err(ManagementError::InvalidReply)
}

#[cfg(target_os = "linux")]
pub async fn query_in(
    directory: &Path,
    command: StatusCommand,
) -> Result<StatusReply, ManagementError> {
    let path = endpoint_path(directory)?;
    timeout(IO_TIMEOUT, async {
        let stream = UnixStream::connect(&path)
            .await
            .map_err(|_| ManagementError::SocketUnavailable)?;
        exchange(stream, command).await
    })
    .await
    .map_err(|_| ManagementError::TimedOut)?
}

#[cfg(target_os="linux")]
pub(crate) fn client_server(client:Arc<crate::local_proxy::ClientRuntime>)->Result<Option<StatusServer>,ManagementError>{
    let Some(directory)=std::env::var_os("THEIA_CLIENT_CONTROL_DIR")else{return Ok(None);};
    StatusServer::bind_in(Path::new(&directory),1).map(|s|Some(s.with_client(client)))
}
#[cfg(target_os="windows")]
pub(crate) fn client_server(client:Arc<crate::local_proxy::ClientRuntime>)->Result<Option<crate::windows_control::WindowsServer>,ManagementError>{
    let Some(id)=std::env::var_os("THEIA_CLIENT_CONTROL_PIPE")else{return Ok(None);};
    let id=id.into_string().map_err(|_|ManagementError::UnsafeEndpoint)?;
    crate::windows_control::WindowsServer::bind(&id,1).map(|s|Some(s.with_client(client)))
}

pub async fn query_client_environment(command:StatusCommand)->Result<StatusReply,ManagementError>{
    if !matches!(command,StatusCommand::ClientStatus|StatusCommand::ClientPreview{..}|StatusCommand::ClientApply{..}){
        return Err(ManagementError::Unsupported);
    }
    #[cfg(target_os="linux")]
    {
        let directory=std::env::var_os("THEIA_CLIENT_CONTROL_DIR").ok_or(ManagementError::NotConfigured)?;
        let path=endpoint_path(Path::new(&directory))?;
        return timeout(CLIENT_TIMEOUT,async{
            let stream=UnixStream::connect(path).await.map_err(|_|ManagementError::SocketUnavailable)?;
            exchange(stream,command).await
        }).await.map_err(|_|ManagementError::TimedOut)?;
    }
    #[cfg(target_os="windows")]
    {
        let id=std::env::var_os("THEIA_CLIENT_CONTROL_PIPE").ok_or(ManagementError::NotConfigured)?
            .into_string().map_err(|_|ManagementError::UnsafeEndpoint)?;
        return crate::windows_control::query_client_pipe(&id,command).await;
    }
    #[cfg(not(any(target_os="linux",target_os="windows")))]
    Err(ManagementError::Unsupported)
}

pub async fn query_environment(command: StatusCommand) -> Result<StatusReply, ManagementError> {
    let kind = match command {
        StatusCommand::ClientStatus|StatusCommand::ClientPreview{..}|StatusCommand::ClientApply{..}=>return Err(ManagementError::Unsupported),
        StatusCommand::Health => "health",
        StatusCommand::Status => "status",
        StatusCommand::Reload => "reload_rejected",
        StatusCommand::CheckReload => "check_reload",
        StatusCommand::CheckRestart => "check_restart",
        StatusCommand::CheckRestartBound{..}=>"restart_preview",
        StatusCommand::CheckRestartRollback=>"restart_rollback_check",
        StatusCommand::ApplyRestartRollback{..}=>"restart_rollback_apply",
        StatusCommand::RealityStatus{..}=>"reality_status",
        StatusCommand::CheckAuthRollback=>"check_auth_rollback",
        StatusCommand::ApplyAuthRollback{..}=>"apply_auth_rollback",
        StatusCommand::CheckTlsRollback => "check_tls_rollback",
        StatusCommand::ApplyTlsRollback { .. } => "apply_tls_rollback",
        StatusCommand::CheckQuota => "check_quota",
        StatusCommand::ApplyQuotaBound { .. } => "apply_quota",
        StatusCommand::ApplyRestartBound { .. } => "apply_restart",
        StatusCommand::ApplyReload { .. } => "apply_reload",
        StatusCommand::ApplyReloadBound { .. } => "apply_reload_bound",
    };
    crate::diag!(
        Info,
        "management",
        "ipc_query_begin",
        "command" = crate::diagnostics::Value::Label(kind)
    );
    let result = {
        #[cfg(target_os = "linux")]
        {
            let directory =
                std::env::var_os("THEIA_CONTROL_DIR").ok_or(ManagementError::NotConfigured)?;
            query_in(Path::new(&directory), command).await
        }
        #[cfg(target_os = "windows")]
        {
            crate::windows_control::query_environment(command).await
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(ManagementError::Unsupported)
        }
    };
    crate::diag!(
        Info,
        "management",
        "ipc_query_result",
        "command" = crate::diagnostics::Value::Label(kind),
        "success" = crate::diagnostics::Value::Flag(result.is_ok())
    );
    result
}

#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
mod tls_rollback_protocol_tests {
    use super::*;

    #[test]
    fn rollback_wire_requires_exact_positive_revision() {
        assert_eq!(
            parse_tls_rollback_revision(b"tls-rollback-apply rev=7"),
            Some(7)
        );
        for invalid in [
            "tls-rollback-apply rev=0",
            "tls-rollback-apply rev=07",
            "tls-rollback-apply rev=-1",
            "tls-rollback-apply rev=+1",
            "tls-rollback-apply rev=7x",
            "tls-rollback-apply rev=7 --force",
            "tls-rollback-apply rev=18446744073709551616",
            "tls-rollback-apply rev=7\n",
        ] {
            assert_eq!(parse_tls_rollback_revision(invalid.as_bytes()), None);
        }
    }

    #[tokio::test]
    async fn standalone_native_ipc_never_exposes_rollback_or_acknowledges_apply() {
        for command in [
            StatusCommand::CheckTlsRollback,
            StatusCommand::ApplyTlsRollback {
                expected_revision: 1,
            },
        ] {
            let (client, server) = tokio::io::duplex(512);
            let handler = tokio::spawn(handle_internal(server, 1, None, None, None, None));
            assert_eq!(
                exchange(client, command).await,
                Err(ManagementError::Unsupported)
            );
            handler.await.unwrap().unwrap();
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
mod tls_restart_pin_tests {
    use super::*;

    #[test]
    fn restart_native_ipc_fails_closed_without_two_exact_hex_digests() {
        let doc = "ab".repeat(32);
        let material = "cd".repeat(32);
        let valid = format!("restart-apply rev=7 sha256={doc} tls-sha256={material}");
        assert_eq!(
            parse_restart_revision(valid.as_bytes()),
            Some((7, [0xab; 32], [0xcd; 32]))
        );
        assert!(valid.len() < MAX_COMMAND_BYTES);
        for invalid in [
            format!("restart-apply rev=7 sha256={doc}"),
            format!("restart-apply rev=0 sha256={doc} tls-sha256={material}"),
            format!("restart-apply rev=07 sha256={doc} tls-sha256={material}"),
            format!(
                "restart-apply rev=7 sha256={doc} tls-sha256={}",
                "CD".repeat(32)
            ),
            format!(
                "restart-apply rev=7 sha256={} tls-sha256={material}",
                "AB".repeat(32)
            ),
            format!("restart-apply rev=7 sha256={doc} tls-sha256={} ", material),
            format!("restart-apply rev=7 sha256={doc} tls-sha256={}0", material),
            format!(
                "restart-apply rev=7 sha256={doc} tls-sha256={}",
                "cd".repeat(31)
            ),
            format!("restart-apply rev=7 sha256={doc} TLS-SHA256={material}"),
        ] {
            assert_eq!(parse_restart_revision(invalid.as_bytes()), None);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod bound_command_tests {
    use super::*;

    #[test]
    fn canonical_sha256_binding_is_required_before_any_apply_side_effect() {
        let valid = format!("apply-reload rev=7 sha256={}", "ab".repeat(32));
        assert_eq!(
            parse_bound_revision(valid.as_bytes()),
            Some((7, [0xabu8; 32]))
        );
        for invalid in [
            format!("apply-reload rev=0 sha256={}", "ab".repeat(32)),
            format!("apply-reload rev=07 sha256={}", "ab".repeat(32)),
            format!("apply-reload rev=7 sha256={}", "AB".repeat(32)),
            format!("apply-reload rev=7 sha256={}", "ab".repeat(31)),
            format!("apply-reload rev=7 sha256={}0", "ab".repeat(32)),
            format!("apply-reload rev=7 sha256={} ", "ab".repeat(32)),
            format!("apply-reload rev=7 sha256={}", "gg".repeat(32)),
            format!("apply-reload rev=7 SHA256={}", "ab".repeat(32)),
            format!(
                "apply-reload rev=18446744073709551616 sha256={}",
                "ab".repeat(32)
            ),
        ] {
            assert_eq!(parse_bound_revision(invalid.as_bytes()), None);
        }
    }
}

#[cfg(all(test, not(any(target_os = "linux", target_os = "windows"))))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsupported_platform_fails_closed_without_creating_a_listener() {
        assert_eq!(
            query_environment(StatusCommand::Status).await,
            Err(ManagementError::Unsupported)
        );
        assert_eq!(
            query_environment(StatusCommand::ApplyReload {
                expected_revision: 1,
            })
            .await,
            Err(ManagementError::Unsupported),
            "Windows cannot silently emulate Unix IPC Apply without Named Pipe DACL"
        );
    }
}
