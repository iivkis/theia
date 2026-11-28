//! F-20 role-specific management protocol, carried by the existing
//! current-user SID DACL / local-only Windows pipe implementation.
use super::{
    authority::Candidate,
    diagnostic::Plan,
    session::{Binding, Control, DiagnosticUpdate, Phase},
};
use crate::management::ManagementError;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const LIMIT: usize = 18 * 1024;
const REPORT_LIMIT: usize = 1024 * 1024;
const JOB_TIMEOUT: Duration = Duration::from_secs(605);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Request {
    Status,
    Apply {
        prior: Binding,
        candidate: [u8; 32],
    },
    Disconnect(Binding),
    Diagnose {
        prior: Binding,
        plan: [u8; 32],
        hosts: Vec<String>,
        anonymous: bool,
    },
}

fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut result = String::new();
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}
fn digest(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut result = [0; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(result)
}
fn number(raw: &str) -> Option<u64> {
    if raw.is_empty()
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    raw.parse().ok()
}
fn binding(instance: &str, revision: &str, policy: &str) -> Option<Binding> {
    let revision = number(revision)?;
    let instance = digest(instance)?;
    if revision == 0 || instance == [0; 32] {
        return None;
    }
    Some(Binding {
        instance,
        revision,
        digest: digest(policy)?,
    })
}
fn parse(raw: &str) -> Option<Request> {
    let fields = raw.split(' ').collect::<Vec<_>>();
    match fields.as_slice() {
        ["status"] => Some(Request::Status),
        ["apply", instance, revision, policy, candidate] => Some(Request::Apply {
            prior: binding(instance, revision, policy)?,
            candidate: digest(candidate)?,
        }),
        ["disconnect", instance, revision, policy] => {
            Some(Request::Disconnect(binding(instance, revision, policy)?))
        }
        ["diagnose", instance, revision, policy, plan, selected, anonymous] => {
            let hosts = selected.split(',').map(str::to_owned).collect::<Vec<_>>();
            if hosts.is_empty()
                || hosts.len() > super::catalog::MAX_JOB_DOMAINS
                || hosts.iter().any(|host| {
                    host.is_empty()
                        || host.len() > 253
                        || !host
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
                })
            {
                return None;
            }
            Some(Request::Diagnose {
                prior: binding(instance, revision, policy)?,
                plan: digest(plan)?,
                hosts,
                anonymous: match *anonymous {
                    "0" => false,
                    "1" => true,
                    _ => return None,
                },
            })
        }
        _ => None,
    }
}
fn path_digest(path: &Path) -> Result<[u8; 32], ManagementError> {
    let path = super::authority::canonical_config_path(path)
        .map_err(|_| ManagementError::UnsafeEndpoint)?;
    let mut hash = Sha256::new();
    hash.update(b"theia/anti-dpi/ipc-path/v1\0");
    hash.update(path.as_os_str().as_encoded_bytes());
    Ok(hash.finalize().into())
}
async fn read_line(stream: &mut (impl AsyncRead + Unpin)) -> Result<String, ManagementError> {
    let mut bytes = Vec::new();
    while bytes.len() < LIMIT {
        let byte = stream.read_u8().await.map_err(|_| ManagementError::Io)?;
        if byte == b'\n' {
            return String::from_utf8(bytes).map_err(|_| ManagementError::InvalidReply);
        }
        if !matches!(byte, 0x20..=0x7e) {
            return Err(ManagementError::InvalidReply);
        }
        bytes.push(byte);
    }
    Err(ManagementError::InvalidReply)
}

async fn wait_reply(receiver: mpsc::Receiver<Result<(), String>>) -> Result<(), ManagementError> {
    loop {
        match receiver.try_recv() {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(_)) => return Err(ManagementError::CandidateRejected),
            Err(mpsc::TryRecvError::Disconnected) => return Err(ManagementError::Io),
            Err(mpsc::TryRecvError::Empty) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

pub(crate) struct Endpoint {
    path: PathBuf,
    control: Arc<Control>,
}
impl Endpoint {
    pub(crate) fn new(path: PathBuf, control: Arc<Control>) -> Self {
        Self { path, control }
    }

    async fn execute(
        &self,
        request: Request,
    ) -> Result<(String, Option<tokio::sync::oneshot::Sender<()>>), ManagementError> {
        match request {
            Request::Diagnose { .. } => Err(ManagementError::Unsupported),
            Request::Status => {
                let state = self.control.status();
                let phase = match state.phase {
                    Phase::Starting => "starting",
                    Phase::Connected => "connected",
                    Phase::Stopping => "stopping",
                    Phase::Stopped => "stopped",
                    Phase::Failed => "failed",
                };
                Ok((
                    format!(
                        "theia-anti-dpi-v1 status {} {} {} {} {} {} {} {} {} {} {}",
                        hex(path_digest(&self.path)?),
                        hex(state.binding.instance),
                        state.binding.revision,
                        hex(state.binding.digest),
                        phase,
                        u8::from(state.admitting),
                        state.accepted,
                        state.active,
                        state.errors,
                        state.uploaded,
                        state.downloaded
                    ),
                    None,
                ))
            }
            Request::Apply { prior, candidate } => {
                if !self.control.matches(prior) {
                    return Err(ManagementError::CandidateRejected);
                }
                // The caller cannot supply a path; only the owner's exact
                // configured document is read and prepared.
                let document =
                    Candidate::read(&self.path).map_err(|_| ManagementError::CandidateRejected)?;
                if document.digest() != candidate {
                    return Err(ManagementError::CandidateRejected);
                }
                let receiver = self
                    .control
                    .apply_bound(prior, document)
                    .map_err(|_| ManagementError::CandidateRejected)?;
                wait_reply(receiver).await?;
                Ok((
                    format!("theia-anti-dpi-v1 applied {}", hex(candidate)),
                    None,
                ))
            }
            Request::Disconnect(prior) => {
                let (receiver, ack) = self
                    .control
                    .disconnect_bound(prior)
                    .map_err(|_| ManagementError::CandidateRejected)?;
                wait_reply(receiver).await?;
                // This is an accepted stop, not proof of CAS restore.
                Ok((
                    format!(
                        "theia-anti-dpi-v1 disconnect-accepted {}",
                        hex(prior.instance)
                    ),
                    Some(ack),
                ))
            }
        }
    }

    async fn diagnostic<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        prior: Binding,
        confirmation: [u8; 32],
        hosts: Vec<String>,
        anonymous: bool,
    ) -> Result<(), ManagementError> {
        if !self.control.matches(prior) {
            return Err(ManagementError::CandidateRejected);
        }
        let plan = owned_plan(&self.path, &hosts)?;
        if bound_confirmation(prior, plan.digest()) != confirmation || !self.control.matches(prior)
        {
            return Err(ManagementError::CandidateRejected);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        // Disconnect, timeout or handler cancellation drops this guard.
        struct Cancel(Arc<AtomicBool>);
        impl Drop for Cancel {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let _cancel = Cancel(cancel.clone());
        let (sender, receiver) = mpsc::channel();
        self.control
            .diagnose(plan, cancel, sender)
            .map_err(|_| ManagementError::CandidateRejected)?;
        let wait = async move {
            loop {
                match receiver.try_recv() {
                    Ok(DiagnosticUpdate::Done(result)) => {
                        return result.map_err(|_| ManagementError::CandidateRejected)
                    }
                    Ok(DiagnosticUpdate::Cells(_)) => {}
                    Err(mpsc::TryRecvError::Disconnected) => return Err(ManagementError::Io),
                    Err(mpsc::TryRecvError::Empty) => {
                        tokio::time::sleep(Duration::from_millis(20)).await
                    }
                }
            }
        };
        let report = tokio::select! {
            biased;
            _ = stream.read_u8() => return Err(ManagementError::Io),
            result = tokio::time::timeout(JOB_TIMEOUT, wait) => result.map_err(|_| ManagementError::TimedOut)??,
        };
        let report = if anonymous {
            report.anonymous_summary()
        } else {
            report.render()
        };
        if report.len() > REPORT_LIMIT {
            return Err(ManagementError::InvalidReply);
        }
        stream
            .write_all(format!("report {}\n", report.len()).as_bytes())
            .await
            .map_err(|_| ManagementError::Io)?;
        stream
            .write_all(report.as_bytes())
            .await
            .map_err(|_| ManagementError::Io)?;
        stream.shutdown().await.map_err(|_| ManagementError::Io)
    }

    pub(crate) async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
    ) -> Result<(), ManagementError> {
        let line = tokio::time::timeout(crate::management::CLIENT_TIMEOUT, read_line(&mut stream))
            .await
            .map_err(|_| ManagementError::TimedOut)??;
        let request = parse(&line);
        let (reply, ack) = match request {
            Some(Request::Diagnose {
                prior,
                plan,
                hosts,
                anonymous,
            }) => {
                // A separately bounded report exchange, not an unbounded status reply.
                return tokio::time::timeout(
                    JOB_TIMEOUT + Duration::from_secs(5),
                    self.diagnostic(&mut stream, prior, plan, hosts, anonymous),
                )
                .await
                .map_err(|_| ManagementError::TimedOut)?;
            }
            Some(request) => {
                tokio::time::timeout(crate::management::CLIENT_TIMEOUT, self.execute(request))
                    .await
                    .map_err(|_| ManagementError::TimedOut)?
                    .unwrap_or_else(|_| ("theia-anti-dpi-v1 rejected".into(), None))
            }
            None => ("ERR unsupported".into(), None),
        };
        tokio::time::timeout(crate::management::CLIENT_TIMEOUT, async {
            stream
                .write_all(reply.as_bytes())
                .await
                .map_err(|_| ManagementError::Io)?;
            stream
                .write_all(b"\n")
                .await
                .map_err(|_| ManagementError::Io)?;
            stream.shutdown().await.map_err(|_| ManagementError::Io)
        })
        .await
        .map_err(|_| ManagementError::TimedOut)??;
        if let Some(ack) = ack {
            let _ = ack.send(());
        }
        Ok(())
    }
}

pub(crate) async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &str,
) -> Result<String, ManagementError> {
    if request.len() >= LIMIT || parse(request).is_none() {
        return Err(ManagementError::InvalidReply);
    }
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| ManagementError::Io)?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|_| ManagementError::Io)?;
    read_line(&mut stream).await
}

pub(crate) async fn exchange_report<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &str,
) -> Result<String, ManagementError> {
    if request.len() >= LIMIT || !matches!(parse(request), Some(Request::Diagnose { .. })) {
        return Err(ManagementError::InvalidReply);
    }
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| ManagementError::Io)?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|_| ManagementError::Io)?;
    let header = read_line(&mut stream).await?;
    let size = header
        .strip_prefix("report ")
        .and_then(number)
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n <= REPORT_LIMIT)
        .ok_or(ManagementError::InvalidReply)?;
    let mut bytes = vec![0; size];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| ManagementError::Io)?;
    String::from_utf8(bytes).map_err(|_| ManagementError::InvalidReply)
}

fn owned_plan(path: &Path, hosts: &[String]) -> Result<Plan, ManagementError> {
    let path = super::authority::canonical_config_path(path)
        .map_err(|_| ManagementError::UnsafeEndpoint)?;
    let overlay = path.with_file_name("anti-dpi-domains.toml");
    let overlay = match std::fs::symlink_metadata(&overlay) {
        Ok(_) => Some(overlay),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(ManagementError::UnsafeEndpoint),
    };
    Plan::prepare(&path, overlay.as_deref(), hosts).map_err(|_| ManagementError::CandidateRejected)
}

fn bound_confirmation(binding: Binding, plan: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"theia/anti-dpi/owned-diagnostic/v1\0");
    hash.update(binding.instance);
    hash.update(binding.revision.to_be_bytes());
    hash.update(binding.digest);
    hash.update(plan);
    hash.finalize().into()
}

/// External diagnostics run in the actual owner process, never by claiming
/// its lock or opening a second System Proxy reservation.
pub async fn diagnose_owned(
    path: &Path,
    hosts: &[String],
    confirmation: Option<[u8; 32]>,
    anonymous: bool,
) -> Result<String, ManagementError> {
    let observed = query(path).await?;
    if observed.phase != "connected" {
        return Err(ManagementError::CandidateRejected);
    }
    let plan = owned_plan(path, hosts)?;
    let expected = bound_confirmation(observed.binding, plan.digest());
    match confirmation {
        None => Ok(format!(
            "{}\nOwned session instance={} revision={}\nConfirm owned plan SHA256={}",
            plan.preview(),
            hex(observed.binding.instance),
            observed.binding.revision,
            hex(expected)
        )),
        Some(confirmation) if confirmation == expected => {
            let b = observed.binding;
            let request = format!(
                "diagnose {} {} {} {} {} {}",
                hex(b.instance),
                b.revision,
                hex(b.digest),
                hex(expected),
                hosts.join(","),
                u8::from(anonymous)
            );
            crate::windows_control::query_standalone_report(&request).await
        }
        Some(_) => Err(ManagementError::CandidateRejected),
    }
}

struct Observed {
    binding: Binding,
    path: [u8; 32],
    phase: String,
    admitting: bool,
    counters: [u64; 5],
}
fn observed(line: &str) -> Option<Observed> {
    let fields = line.split(' ').collect::<Vec<_>>();
    let ["theia-anti-dpi-v1", "status", path, instance, revision, policy, phase, admitting, accepted, active, errors, up, down] =
        fields.as_slice()
    else {
        return None;
    };
    if !matches!(
        *phase,
        "starting" | "connected" | "stopping" | "stopped" | "failed"
    ) {
        return None;
    }
    let binding = Binding {
        instance: digest(instance)?,
        revision: number(revision)?,
        digest: digest(policy)?,
    };
    if binding.instance == [0; 32] || (*phase == "connected" && binding.revision == 0) {
        return None;
    }
    let admitting = match *admitting {
        "0" => false,
        "1" if *phase == "connected" => true,
        _ => return None,
    };
    Some(Observed {
        binding,
        path: digest(path)?,
        phase: (*phase).into(),
        admitting,
        counters: [
            number(accepted)?,
            number(active)?,
            number(errors)?,
            number(up)?,
            number(down)?,
        ],
    })
}

async fn query(path: &Path) -> Result<Observed, ManagementError> {
    let response = crate::windows_control::query_standalone("status").await?;
    let status = observed(&response).ok_or(ManagementError::InvalidReply)?;
    if status.path != path_digest(path)? {
        return Err(ManagementError::UnsafeEndpoint);
    }
    Ok(status)
}

pub async fn status(path: &Path) -> Result<String, ManagementError> {
    let status = query(path).await?;
    Ok(format!("Theia Anti-DPI: {} revision={} admission={}\ninstance={} policy-sha256={}\nconnections={} active={} errors={} up={} down={}",
        status.phase, status.binding.revision, status.admitting, hex(status.binding.instance),
        hex(status.binding.digest), status.counters[0], status.counters[1], status.counters[2],
        status.counters[3], status.counters[4]))
}

/// Preview requires no mutation. A subsequent command must supply the
/// exact observed instance, revision and policy digest; never auto-rebind.
pub async fn change(
    path: &Path,
    instance: [u8; 32],
    revision: u64,
    policy: [u8; 32],
    candidate: Option<[u8; 32]>,
) -> Result<String, ManagementError> {
    let status = query(path).await?;
    let prior = Binding {
        instance,
        revision,
        digest: policy,
    };
    if status.phase != "connected" || status.binding != prior {
        return Err(ManagementError::CandidateRejected);
    }
    let request = match candidate {
        Some(candidate) => format!(
            "apply {} {revision} {} {}",
            hex(instance),
            hex(policy),
            hex(candidate)
        ),
        None => format!("disconnect {} {revision} {}", hex(instance), hex(policy)),
    };
    let reply = crate::windows_control::query_standalone(&request).await?;
    let expected = match candidate {
        Some(candidate) => format!("theia-anti-dpi-v1 applied {}", hex(candidate)),
        None => format!("theia-anti-dpi-v1 disconnect-accepted {}", hex(instance)),
    };
    if reply != expected {
        return Err(ManagementError::CandidateRejected);
    }
    Ok(if candidate.is_some() {
        "Applied by the exact running standalone owner".into()
    } else {
        "Disconnect accepted; confirm restored OS state separately".into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_consent_is_bound_to_instance_revision_and_plan() {
        let binding = Binding {
            instance: [1; 32],
            revision: 1,
            digest: [2; 32],
        };
        let plan = [3; 32];
        let first = bound_confirmation(binding, plan);
        assert_ne!(
            first,
            bound_confirmation(
                Binding {
                    revision: 2,
                    ..binding
                },
                plan
            )
        );
        assert_ne!(
            first,
            bound_confirmation(
                Binding {
                    instance: [4; 32],
                    ..binding
                },
                plan
            )
        );
        assert_ne!(first, bound_confirmation(binding, [5; 32]));
        let request = format!(
            "diagnose {} 1 {} {} all 0",
            hex(binding.instance),
            hex(binding.digest),
            hex(first)
        );
        assert!(
            matches!(parse(&request), Some(Request::Diagnose { prior, plan, .. }) if prior == binding && plan == first)
        );
        assert!(parse(&request.replace("all 0", "../bad 0")).is_none());
        assert!(parse(&request.replace("all 0", "all 2")).is_none());
    }

    #[tokio::test]
    async fn report_frame_rejects_oversize_and_truncated_body() {
        let request = format!(
            "diagnose {} 1 {} {} all 0",
            hex([1; 32]),
            hex([2; 32]),
            hex([3; 32])
        );
        for response in ["report 1048577\n", "report 4\nx"] {
            let (mut peer, client) = tokio::io::duplex(2048);
            let serve = async {
                let _ = read_line(&mut peer).await.unwrap();
                peer.write_all(response.as_bytes()).await.unwrap();
                peer.shutdown().await.unwrap();
            };
            let (result, _) = tokio::join!(exchange_report(client, &request), serve);
            assert!(result.is_err());
        }
    }

    #[test]
    fn exact_bound_commands_and_status_reject_malformed_values() {
        let instance = hex([1; 32]);
        let policy = hex([2; 32]);
        let candidate = hex([3; 32]);
        let raw = format!("apply {instance} 2 {policy} {candidate}");
        assert_eq!(
            parse(&raw),
            Some(Request::Apply {
                prior: Binding {
                    instance: [1; 32],
                    revision: 2,
                    digest: [2; 32]
                },
                candidate: [3; 32],
            })
        );
        for invalid in [
            format!("{raw} extra"),
            raw.replace(" 2 ", " 02 "),
            raw.replace(" 2 ", " 0 "),
            raw.replace(&instance, &"00".repeat(32)),
            "disconnect".into(),
            "apply ../../client.toml".into(),
        ] {
            assert!(parse(&invalid).is_none());
        }
        let status = format!(
            "theia-anti-dpi-v1 status {} {instance} 2 {policy} connected 1 4 2 0 32 64",
            hex([4; 32])
        );
        assert_eq!(observed(&status).unwrap().binding.revision, 2);
        assert!(observed(&status.replace("connected 1", "stopping 1")).is_none());
    }
}
