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
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) const MAX_COMMAND_BYTES: usize = 128;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) const MAX_RESPONSE_BYTES: u64 = 128;
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
    Health,
    Status,
    /// Explicitly rejected in this read-only slice. Never reload implicitly.
    Reload,
    /// Read-only preflight; does not modify config or runtime.
    CheckReload,
    /// Read-only restart readiness: validates TLS and tests fresh TCP/UDP ports.
    /// Never reserves a port, stops listeners or commits new runtime state.
    CheckRestart,
    /// Explicit restart cutover, requires saved TOML SHA-256 and revision CAS.
    /// Only distinct new ports with unchanged quotas/roster are supported.
    ApplyRestartBound {
        expected_revision: u64,
        candidate_sha256: [u8; 32],
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
    /// All NEW candidate ports were temporarily bound, then released.
    RestartFreshPortsBindable,
    RestartApplied {
        revision: u64,
    },
    Applied {
        revision: u64,
    },
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
                        tasks.spawn(async move {
                            let _permit = permit;
                            // Only the live supervisor owns generation commits.
                            let _ = timeout(
                                IO_TIMEOUT,
                                handle_internal(stream, inbounds, preflight, live, runtime, restarts),
                            )
                            .await;
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
pub(crate) async fn handle<S>(
    stream: S,
    inbounds: usize,
    preflight: Option<Arc<crate::reload_preflight::ReloadPreflight>>,
    live: Option<Arc<crate::live_auth::LiveAuthorization>>,
) -> Result<(), ManagementError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handle_internal(stream, inbounds, preflight, live, None, None).await
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
            candidate if parse_restart_revision(candidate).is_some() => {
                if let (Some(preflight), Some(runtime), Some(previous), Some(restarts)) =
                    (&preflight, &runtime, &observed, &restarts)
                {
                    let (expected, sha256) =
                        parse_restart_revision(candidate).expect("already parsed");
                    // A worker may finish after client timeout, but cannot
                    // publish or even request a new generation after the
                    // calling IPC handler has been cancelled.
                    let preflight = Arc::clone(preflight);
                    let candidate = tokio::task::spawn_blocking(move || {
                        preflight.load_restart_candidate_bound(sha256)
                    })
                    .await;
                    match candidate {
                        Ok(Ok(candidate)) if runtime.still_current(previous, expected) => {
                            let (complete, result) = oneshot::channel();
                            let request = crate::runtime_generation::RestartRequest {
                                previous: Arc::clone(previous),
                                expected_revision: expected,
                                candidate,
                                complete,
                            };
                            if restarts.try_send(request).is_err() {
                                "theia-restart-v1 rejected\n".to_owned()
                            } else {
                                match result.await {
                                    Ok(Ok(revision)) => {
                                        format!("theia-restart-v1 applied revision={revision}\n")
                                    }
                                    _ => "theia-restart-v1 rejected\n".to_owned(),
                                }
                            }
                        }
                        _ => "theia-restart-v1 rejected\n".to_owned(),
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
                    match tokio::task::spawn_blocking(move || preflight.check_file()).await {
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
                    match tokio::task::spawn_blocking(move || {
                        preflight.load_candidate_bound(sha256)
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
                if let (Some(preflight), Some(live)) = (preflight, live) {
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
fn parse_restart_revision(command: &[u8]) -> Option<(u64, [u8; 32])> {
    parse_bound_command(command, b"restart-apply rev=")
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn parse_bound_command(command: &[u8], prefix: &[u8]) -> Option<(u64, [u8; 32])> {
    let rest = std::str::from_utf8(command.strip_prefix(prefix)?).ok()?;
    let (revision, digest) = rest.split_once(" sha256=")?;
    Some((positive_decimal(revision)?, decode_digest(digest)?))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) async fn exchange<S>(
    mut stream: S,
    command: StatusCommand,
) -> Result<StatusReply, ManagementError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = match command {
        StatusCommand::Health => b"health\n".to_vec(),
        StatusCommand::Status => b"status\n".to_vec(),
        StatusCommand::Reload => b"reload\n".to_vec(),
        StatusCommand::CheckReload => b"check-reload\n".to_vec(),
        StatusCommand::CheckRestart => b"check-restart\n".to_vec(),
        StatusCommand::ApplyRestartBound {
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
            format!("restart-apply rev={expected_revision} sha256={digest}\n").into_bytes()
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
    if reply == b"theia-health-v1 ok\n" && command == StatusCommand::Health {
        return Ok(StatusReply::Healthy);
    }
    if reply == b"ERR unsupported\n" && command == StatusCommand::Reload {
        return Ok(StatusReply::Unsupported);
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

pub async fn query_environment(command: StatusCommand) -> Result<StatusReply, ManagementError> {
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
        let _ = command;
        Err(ManagementError::Unsupported)
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
