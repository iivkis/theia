//! M4.2b1b: bounded Linux local management IPC with explicit CAS auth Apply.
//!
//! Linux-only opt-in endpoint via THEIA_CONTROL_DIR, a private, operator-owned
//! runtime directory. No administrative TCP, token disclosure or TLS/listener mutation.
//! Windows Named Pipe/DACL and TUI Apply remain separate milestones.
//! The endpoint exists only while a server process is actually serving.
use std::fmt;

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

#[cfg(target_os = "linux")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

#[cfg(target_os = "linux")]
const SOCKET_NAME: &str = "theia-server.sock";
#[cfg(target_os = "linux")]
const IO_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const MAX_COMMAND_BYTES: usize = 64;
#[cfg(target_os = "linux")]
const MAX_RESPONSE_BYTES: u64 = 128;
#[cfg(target_os = "linux")]
const MAX_CLIENTS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementError {
    Unsupported,
    NotConfigured,
    UnsafeDirectory,
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
    /// Explicit opt-in CAS auth publication, supported only by Linux server.
    ApplyReload { expected_revision: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusReply {
    Healthy,
    Running {
        inbounds: usize,
    },
    RunningRevision { inbounds: usize, revision: u64 },
    Unsupported,
    /// Candidate passes the deliberately narrow compatibility preflight.
    Compatible,
    Applied { revision: u64 },
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
                        tasks.spawn(async move {
                            let _permit = permit;
                            // Cancelled handlers cannot publish. Their
                            // spawn_blocking workers only load candidates.
                            let _ = timeout(IO_TIMEOUT, handle(stream, inbounds, preflight, live)).await;
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

#[cfg(target_os = "linux")]
async fn handle(
    mut stream: UnixStream,
    inbounds: usize,
    preflight: Option<Arc<crate::reload_preflight::ReloadPreflight>>,
    live: Option<Arc<crate::live_auth::LiveAuthorization>>,
) -> Result<(), ManagementError> {
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
    let response = if !newline {
        "ERR unsupported\n".to_owned()
    } else {
        match command.as_slice() {
            b"health" => "theia-health-v1 ok\n".to_owned(),
            b"status" => format!("theia-status-v1 running inbounds={inbounds}\n"),
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
            _ => "ERR unsupported\n".to_owned(),
        }
    };
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|_| ManagementError::Io)?;
    stream.shutdown().await.map_err(|_| ManagementError::Io)
}

#[cfg(target_os = "linux")]
pub async fn query_in(
    directory: &Path,
    command: StatusCommand,
) -> Result<StatusReply, ManagementError> {
    let path = endpoint_path(directory)?;
    timeout(IO_TIMEOUT, async {
        let mut stream = UnixStream::connect(&path)
            .await
            .map_err(|_| ManagementError::SocketUnavailable)?;
        let request = match command {
            StatusCommand::Health => b"health\n".as_slice(),
            StatusCommand::Status => b"status\n".as_slice(),
            StatusCommand::Reload => b"reload\n".as_slice(),
            StatusCommand::CheckReload => b"check-reload\n".as_slice(),
        };
        stream
            .write_all(request)
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
        if command == StatusCommand::CheckReload {
            return match reply.as_slice() {
                b"theia-check-v1 compatible\n" => Ok(StatusReply::Compatible),
                b"theia-check-v1 rejected\n" => Err(ManagementError::CandidateRejected),
                _ => Err(ManagementError::InvalidReply),
            };
        }
        if command == StatusCommand::Status {
            let reply = std::str::from_utf8(&reply).map_err(|_| ManagementError::InvalidReply)?;
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
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
        Err(ManagementError::Unsupported)
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsupported_platform_fails_closed_without_creating_a_listener() {
        assert_eq!(
            query_environment(StatusCommand::Status).await,
            Err(ManagementError::Unsupported)
        );
    }
}
