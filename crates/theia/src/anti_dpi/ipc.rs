//! F-20 role-specific management protocol, carried by the existing
//! current-user SID DACL / local-only Windows pipe implementation.
use super::{authority::Candidate, session::{Binding, Control, Phase}};
use crate::management::ManagementError;
use sha2::{Digest, Sha256};
use std::{path::{Path, PathBuf}, sync::{Arc, mpsc}, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const LIMIT: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Request {
    Status,
    Apply { prior: Binding, candidate: [u8; 32] },
    Disconnect(Binding),
}

fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut result = String::new();
    for byte in bytes { let _ = write!(result, "{byte:02x}"); }
    result
}
fn digest(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut result = [0; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[i*2..i*2+2], 16).ok()?;
    }
    Some(result)
}
fn number(raw: &str) -> Option<u64> {
    if raw.is_empty() || (raw.len() > 1 && raw.starts_with('0')) || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}
fn binding(instance: &str, revision: &str, policy: &str) -> Option<Binding> {
    let revision = number(revision)?;
    let instance = digest(instance)?;
    if revision == 0 || instance == [0; 32] { return None; }
    Some(Binding { instance, revision, digest: digest(policy)? })
}
fn parse(raw: &str) -> Option<Request> {
    let fields = raw.split(' ').collect::<Vec<_>>();
    match fields.as_slice() {
        ["status"] => Some(Request::Status),
        ["apply", instance, revision, policy, candidate] =>
            Some(Request::Apply { prior: binding(instance, revision, policy)?, candidate: digest(candidate)? }),
        ["disconnect", instance, revision, policy] => Some(Request::Disconnect(binding(instance, revision, policy)?)),
        _ => None,
    }
}
fn path_digest(path: &Path) -> Result<[u8; 32], ManagementError> {
    let path = std::path::absolute(path).map_err(|_| ManagementError::UnsafeEndpoint)?;
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
        if !matches!(byte, 0x20..=0x7e) { return Err(ManagementError::InvalidReply); }
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
    pub(crate) fn new(path: PathBuf, control: Arc<Control>) -> Self { Self { path, control } }

    async fn execute(&self, request: Request) -> Result<(String, Option<tokio::sync::oneshot::Sender<()>>), ManagementError> {
        match request {
            Request::Status => {
                let state = self.control.status();
                let phase = match state.phase {
                    Phase::Starting => "starting", Phase::Connected => "connected",
                    Phase::Stopping => "stopping", Phase::Stopped => "stopped", Phase::Failed => "failed",
                };
                Ok((format!("theia-anti-dpi-v1 status {} {} {} {} {} {} {} {} {} {} {}",
                    hex(path_digest(&self.path)?), hex(state.binding.instance), state.binding.revision,
                    hex(state.binding.digest), phase, u8::from(state.admitting), state.accepted,
                    state.active, state.errors, state.uploaded, state.downloaded), None))
            }
            Request::Apply { prior, candidate } => {
                if !self.control.matches(prior) { return Err(ManagementError::CandidateRejected); }
                // The caller cannot supply a path; only the owner's exact
                // configured document is read and prepared.
                let document = Candidate::read(&self.path).map_err(|_| ManagementError::CandidateRejected)?;
                if document.digest() != candidate { return Err(ManagementError::CandidateRejected); }
                let receiver = self.control.apply_bound(prior, document)
                    .map_err(|_| ManagementError::CandidateRejected)?;
                wait_reply(receiver).await?;
                Ok((format!("theia-anti-dpi-v1 applied {}", hex(candidate)), None))
            }
            Request::Disconnect(prior) => {
                let (receiver, ack) = self.control.disconnect_bound(prior)
                    .map_err(|_| ManagementError::CandidateRejected)?;
                wait_reply(receiver).await?;
                // This is an accepted stop, not proof of CAS restore.
                Ok((format!("theia-anti-dpi-v1 disconnect-accepted {}", hex(prior.instance)), Some(ack)))
            }
        }
    }

    pub(crate) async fn handle<S: AsyncRead + AsyncWrite + Unpin>(&self, mut stream: S)
        -> Result<(), ManagementError>
    {
        let line = read_line(&mut stream).await?;
        let (reply, ack) = match parse(&line) {
            Some(request) => self.execute(request).await.unwrap_or_else(|_| ("theia-anti-dpi-v1 rejected".into(), None)),
            None => ("ERR unsupported".into(), None),
        };
        stream.write_all(reply.as_bytes()).await.map_err(|_| ManagementError::Io)?;
        stream.write_all(b"\n").await.map_err(|_| ManagementError::Io)?;
        stream.shutdown().await.map_err(|_| ManagementError::Io)?;
        if let Some(ack) = ack { let _ = ack.send(()); }
        Ok(())
    }
}

pub(crate) async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, request: &str)
    -> Result<String, ManagementError>
{
    if request.len() >= LIMIT || parse(request).is_none() {
        return Err(ManagementError::InvalidReply);
    }
    stream.write_all(request.as_bytes()).await.map_err(|_| ManagementError::Io)?;
    stream.write_all(b"\n").await.map_err(|_| ManagementError::Io)?;
    read_line(&mut stream).await
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
    let ["theia-anti-dpi-v1", "status", path, instance, revision, policy, phase, admitting,
        accepted, active, errors, up, down] = fields.as_slice() else { return None };
    if !matches!(*phase, "starting" | "connected" | "stopping" | "stopped" | "failed") {
        return None;
    }
    let binding = Binding { instance: digest(instance)?, revision: number(revision)?, digest: digest(policy)? };
    if binding.instance == [0; 32] || (*phase == "connected" && binding.revision == 0) { return None; }
    let admitting = match *admitting { "0" => false, "1" if *phase == "connected" => true, _ => return None };
    Some(Observed { binding, path: digest(path)?, phase: (*phase).into(), admitting,
        counters: [number(accepted)?, number(active)?, number(errors)?, number(up)?, number(down)?] })
}

async fn query(path: &Path) -> Result<Observed, ManagementError> {
    let response = crate::windows_control::query_standalone("status").await?;
    let status = observed(&response).ok_or(ManagementError::InvalidReply)?;
    if status.path != path_digest(path)? { return Err(ManagementError::UnsafeEndpoint); }
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
pub async fn change(path: &Path, instance: [u8; 32], revision: u64, policy: [u8; 32],
    candidate: Option<[u8; 32]>) -> Result<String, ManagementError>
{
    let status = query(path).await?;
    let prior = Binding { instance, revision, digest: policy };
    if status.phase != "connected" || status.binding != prior {
        return Err(ManagementError::CandidateRejected);
    }
    let request = match candidate {
        Some(candidate) => format!("apply {} {revision} {} {}", hex(instance), hex(policy), hex(candidate)),
        None => format!("disconnect {} {revision} {}", hex(instance), hex(policy)),
    };
    let reply = crate::windows_control::query_standalone(&request).await?;
    let expected = match candidate {
        Some(candidate) => format!("theia-anti-dpi-v1 applied {}", hex(candidate)),
        None => format!("theia-anti-dpi-v1 disconnect-accepted {}", hex(instance)),
    };
    if reply != expected { return Err(ManagementError::CandidateRejected); }
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
    fn exact_bound_commands_and_status_reject_malformed_values() {
        let instance = hex([1; 32]);
        let policy = hex([2; 32]);
        let candidate = hex([3; 32]);
        let raw = format!("apply {instance} 2 {policy} {candidate}");
        assert_eq!(parse(&raw), Some(Request::Apply {
            prior: Binding { instance: [1; 32], revision: 2, digest: [2; 32] },
            candidate: [3; 32],
        }));
        for invalid in [format!("{raw} extra"), raw.replace(" 2 ", " 02 "),
            raw.replace(" 2 ", " 0 "), raw.replace(&instance, &"00".repeat(32)),
            "disconnect".into(), "apply ../../client.toml".into()] {
            assert!(parse(&invalid).is_none());
        }
        let status = format!("theia-anti-dpi-v1 status {} {instance} 2 {policy} connected 1 4 2 0 32 64", hex([4;32]));
        assert_eq!(observed(&status).unwrap().binding.revision, 2);
        assert!(observed(&status.replace("connected 1", "stopping 1")).is_none());
    }
}
