//! Bounded owner commands shared by the standalone TUI and protected IPC.
//! Mutation is bound to the exact process instance and active policy revision.
use super::{
    authority::Candidate,
    diagnostic::{CellResult, Plan, Report},
};
use crate::config::ConfigError;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
    mpsc, Arc, Mutex,
};
use tokio::sync::mpsc as async_mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Starting,
    Connected,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub instance: [u8; 32],
    pub revision: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default)]
struct Publication {
    revision: u64,
    digest: [u8; 32],
    admitting: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Status {
    pub phase: Phase,
    pub revision: u64,
    pub binding: Binding,
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
    Apply {
        prior: Binding,
        candidate: Candidate,
        expected: [u8; 32],
        reply: mpsc::Sender<Result<(), String>>,
    },
    Disconnect {
        prior: Binding,
        reply: mpsc::Sender<Result<(), String>>,
        ack: tokio::sync::oneshot::Receiver<()>,
    },
}

pub(crate) struct Control {
    phase: AtomicU8,
    pub(crate) stop: AtomicBool,
    commands: async_mpsc::Sender<Command>,
    instance: [u8; 32],
    publication: Mutex<Publication>,
    accepted: AtomicU64,
    active: AtomicU64,
    errors: AtomicU64,
    pub(crate) uploaded: AtomicU64,
    pub(crate) downloaded: AtomicU64,
    pub(crate) modify_meter: Arc<crate::traffic::Counters>,
}

impl Control {
    pub(crate) fn channel() -> Result<(Arc<Self>, async_mpsc::Receiver<Command>), ConfigError> {
        use ring::rand::SecureRandom as _;
        let mut instance = [0; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut instance)
            .map_err(|_| super::invalid("anti_dpi.owner", "cannot create instance nonce"))?;
        let (commands, receiver) = async_mpsc::channel(1);
        Ok((
            Arc::new(Self {
                phase: AtomicU8::new(0),
                stop: AtomicBool::new(false),
                commands,
                instance,
                publication: Mutex::new(Publication::default()),
                accepted: AtomicU64::new(0),
                active: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                uploaded: AtomicU64::new(0),
                downloaded: AtomicU64::new(0),
                modify_meter: Arc::new(crate::traffic::Counters::new()),
            }),
            receiver,
        ))
    }

    pub(crate) fn set_phase(&self, phase: Phase) {
        self.phase.store(
            match phase {
                Phase::Starting => 0,
                Phase::Connected => 1,
                Phase::Stopping => 2,
                Phase::Stopped => 3,
                Phase::Failed => 4,
            },
            Ordering::Release,
        );
    }

    pub(crate) fn phase(&self) -> Phase {
        match self.phase.load(Ordering::Acquire) {
            0 => Phase::Starting,
            1 => Phase::Connected,
            2 => Phase::Stopping,
            3 => Phase::Stopped,
            _ => Phase::Failed,
        }
    }

    pub(crate) fn ready(&self) -> bool {
        self.phase() == Phase::Connected && !self.stop.load(Ordering::Acquire)
    }

    pub(crate) fn disconnect(&self) {
        self.stop.store(true, Ordering::Release);
    }

    pub(crate) fn status(&self) -> Status {
        let publication = self
            .publication
            .lock()
            .map(|state| *state)
            .unwrap_or_default();
        let modify = self.modify_meter.snapshot();
        Status {
            phase: self.phase(),
            revision: publication.revision,
            binding: Binding {
                instance: self.instance,
                revision: publication.revision,
                digest: publication.digest,
            },
            admitting: self.ready() && publication.admitting,
            accepted: self.accepted.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            uploaded: self
                .uploaded
                .load(Ordering::Relaxed)
                .saturating_add(modify.upload),
            downloaded: self
                .downloaded
                .load(Ordering::Relaxed)
                .saturating_add(modify.download),
        }
    }

    pub(crate) fn diagnose(
        &self,
        plan: Plan,
        cancel: Arc<AtomicBool>,
        updates: mpsc::Sender<DiagnosticUpdate>,
    ) -> Result<(), ConfigError> {
        if !self.ready() {
            return Err(super::invalid(
                "diagnostic.owner",
                "owned proxy is not connected",
            ));
        }
        let confirmation = plan.digest();
        self.commands
            .try_send(Command::Diagnose(Job {
                plan,
                confirmation,
                cancel,
                updates,
            }))
            .map_err(|_| super::invalid("diagnostic.owner", "owner command queue busy or closed"))
    }

    pub(crate) fn publication(&self, revision: u64, digest: [u8; 32], admitting: bool) {
        if let Ok(mut state) = self.publication.lock() {
            *state = Publication {
                revision,
                digest,
                admitting,
            };
        }
    }

    pub(crate) fn matches(&self, binding: Binding) -> bool {
        self.ready() && binding.revision != 0 && self.status().binding == binding
    }

    pub(crate) fn apply(
        &self,
        candidate: Candidate,
    ) -> Result<mpsc::Receiver<Result<(), String>>, ConfigError> {
        self.apply_bound(self.status().binding, candidate)
    }

    pub(crate) fn apply_bound(
        &self,
        prior: Binding,
        candidate: Candidate,
    ) -> Result<mpsc::Receiver<Result<(), String>>, ConfigError> {
        if !self.matches(prior) {
            return Err(super::invalid(
                "anti_dpi.owner",
                "stale instance or policy binding",
            ));
        }
        let expected = candidate.digest();
        let (reply, receiver) = mpsc::channel();
        self.commands
            .try_send(Command::Apply {
                prior,
                candidate,
                expected,
                reply,
            })
            .map_err(|_| super::invalid("anti_dpi.owner", "owner command queue busy or closed"))?;
        Ok(receiver)
    }

    pub(crate) fn disconnect_bound(
        &self,
        prior: Binding,
    ) -> Result<
        (
            mpsc::Receiver<Result<(), String>>,
            tokio::sync::oneshot::Sender<()>,
        ),
        ConfigError,
    > {
        if !self.matches(prior) {
            return Err(super::invalid(
                "anti_dpi.owner",
                "stale instance or policy binding",
            ));
        }
        let (reply, receiver) = mpsc::channel();
        let (ack_send, ack) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(Command::Disconnect { prior, reply, ack })
            .map_err(|_| super::invalid("anti_dpi.owner", "owner command queue busy or closed"))?;
        Ok((receiver, ack_send))
    }

    pub(crate) fn enter(&self) -> Connection<'_> {
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        Connection(self)
    }
}

pub(crate) struct Connection<'a>(&'a Control);
impl Connection<'_> {
    pub(crate) fn failure(&self) {
        self.0.errors.fetch_add(1, Ordering::Relaxed);
    }
}
impl Drop for Connection<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_state_and_counters_are_local() {
        let (first, _) = Control::channel().unwrap();
        let (second, _) = Control::channel().unwrap();
        assert!(!first.ready());
        first.set_phase(Phase::Connected);
        assert!(first.ready());
        first.publication(1, [1; 32], true);
        let stale = first.status().binding;
        assert!(first.matches(stale));
        assert!(!second.matches(stale));
        first.publication(2, [2; 32], true);
        assert!(!first.matches(stale));
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
