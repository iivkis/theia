//! In-process owner control for the standalone Windows System Proxy.
//! Never accepts an external claim of ownership. IPC is a separate boundary.
use super::{authority::Candidate, diagnostic::{CellResult, Plan, Report}};
use crate::config::ConfigError;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering}, mpsc};
use tokio::sync::mpsc as async_mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase { Starting, Connected, Stopping, Stopped, Failed }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Status {
    pub phase: Phase,
    pub revision: u64,
    pub admitting: bool,
    pub accepted: u64,
    pub active: u64,
    pub errors: u64,
    pub uploaded: u64,
    pub downloaded: u64,
}

pub(crate) enum DiagnosticUpdate {
    Cells(Vec<CellResult>),
    Done(Result<Report, String>),
}

pub(crate) struct Job {
    pub plan: Plan,
    pub confirmation: [u8; 32],
    pub cancel: Arc<AtomicBool>,
    pub updates: mpsc::Sender<DiagnosticUpdate>,
}

pub(crate) enum Command {
    Diagnose(Job),
    Apply { candidate: Candidate, expected: [u8; 32], reply: mpsc::Sender<Result<(), String>> },
}

pub(crate) struct Control {
    phase: AtomicU8,
    pub(crate) stop: AtomicBool,
    commands: async_mpsc::Sender<Command>,
    revision: AtomicU64,
    admitting: AtomicBool,
    accepted: AtomicU64,
    active: AtomicU64,
    errors: AtomicU64,
    pub(crate) uploaded: AtomicU64,
    pub(crate) downloaded: AtomicU64,
}

impl Control {
    pub(crate) fn channel() -> (Arc<Self>, async_mpsc::Receiver<Command>) {
        let (commands, receiver) = async_mpsc::channel(1);
        (Arc::new(Self {
            phase: AtomicU8::new(0), stop: AtomicBool::new(false), commands,
            revision: AtomicU64::new(0), admitting: AtomicBool::new(false),
            accepted: AtomicU64::new(0), active: AtomicU64::new(0),
            errors: AtomicU64::new(0), uploaded: AtomicU64::new(0), downloaded: AtomicU64::new(0),
        }), receiver)
    }

    pub(crate) fn set_phase(&self, phase: Phase) {
        self.phase.store(match phase {
            Phase::Starting => 0, Phase::Connected => 1, Phase::Stopping => 2,
            Phase::Stopped => 3, Phase::Failed => 4,
        }, Ordering::Release);
    }

    pub(crate) fn phase(&self) -> Phase {
        match self.phase.load(Ordering::Acquire) {
            0 => Phase::Starting, 1 => Phase::Connected, 2 => Phase::Stopping,
            3 => Phase::Stopped, _ => Phase::Failed,
        }
    }

    pub(crate) fn ready(&self) -> bool {
        self.phase() == Phase::Connected && !self.stop.load(Ordering::Acquire)
    }

    pub(crate) fn disconnect(&self) {
        self.stop.store(true, Ordering::Release);
    }

    pub(crate) fn status(&self) -> Status {
        Status {
            phase: self.phase(), revision: self.revision.load(Ordering::Acquire),
            admitting: self.ready() && self.admitting.load(Ordering::Acquire),
            accepted: self.accepted.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed), errors: self.errors.load(Ordering::Relaxed),
            uploaded: self.uploaded.load(Ordering::Relaxed), downloaded: self.downloaded.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn diagnose(&self, plan: Plan, cancel: Arc<AtomicBool>,
        updates: mpsc::Sender<DiagnosticUpdate>) -> Result<(), ConfigError>
    {
        if !self.ready() {
            return Err(super::invalid("diagnostic.owner", "owned proxy is not connected"));
        }
        let confirmation = plan.digest();
        self.commands.try_send(Command::Diagnose(Job { plan, confirmation, cancel, updates }))
            .map_err(|_| super::invalid("diagnostic.owner", "owner command queue busy or closed"))
    }

    pub(crate) fn publication(&self, revision: u64, admitting: bool) {
        self.admitting.store(false, Ordering::Release);
        self.revision.store(revision, Ordering::Release);
        self.admitting.store(admitting, Ordering::Release);
    }

    pub(crate) fn apply(&self, candidate: Candidate) -> Result<mpsc::Receiver<Result<(), String>>, ConfigError> {
        if !self.ready() {
            return Err(super::invalid("anti_dpi.owner", "owned proxy is not connected"));
        }
        let expected = candidate.digest();
        let (reply, receiver) = mpsc::channel();
        self.commands.try_send(Command::Apply { candidate, expected, reply })
            .map_err(|_| super::invalid("anti_dpi.owner", "owner command queue busy or closed"))?;
        Ok(receiver)
    }

    pub(crate) fn enter(&self) -> Connection<'_> {
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        Connection(self)
    }
}

pub(crate) struct Connection<'a>(&'a Control);
impl Connection<'_> {
    pub(crate) fn failure(&self) { self.0.errors.fetch_add(1, Ordering::Relaxed); }
}
impl Drop for Connection<'_> {
    fn drop(&mut self) { self.0.active.fetch_sub(1, Ordering::Relaxed); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_state_and_counters_are_local() {
        let (first, _) = Control::channel();
        let (second, _) = Control::channel();
        assert!(!first.ready());
        first.set_phase(Phase::Connected);
        assert!(first.ready());
        let connection = first.enter();
        connection.failure();
        assert_eq!(first.status().active, 1);
        assert_eq!(first.status().errors, 1);
        assert_eq!(second.status().accepted, 0);
        first.disconnect();
        assert!(!first.ready());
        drop(connection);
        assert_eq!(first.status().active, 0);
    }
}
