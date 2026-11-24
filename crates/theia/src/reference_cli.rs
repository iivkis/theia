//! Explicit consent and durable status for reference health. No inbound
//! configuration writes, credential access, or network listener activation.
use crate::{
    reference_health::{self as health, Error, Plan, State, Store},
    CliError,
};
use std::{path::Path, time::Duration};

pub const HELP: &str = "Reference health (not REALITY activation). Paths must be explicit absolute files.\n\
theia reference preview --plan PATH\n\
theia reference check --plan PATH --sha256 HEX --confirm\n\
theia reference enroll --plan PATH --store PATH --sha256 HEX --confirm\n\
theia reference inspect --store PATH\n\
theia reference recheck --store PATH --expected-revision N --plan-sha256 HEX --confirm\n\
theia reference monitor --store PATH --plan-sha256 HEX --confirm\n\
Plan TOML: schema_version=1, inbound, endpoint, own_ips=[all known public/NAT and local server IPs], [[references]] server_name, address (exact public IP:443). Primary first, at most two reserves.\n\
Preview binds exact plan bytes; inspect displays canonical plan SHA for rechecks. Confirm permission for each target, inbound endpoint DNS, reference DNS, and H2/H3 HEAD /. Checks never follow redirects or send credentials. Monitor checks at a jittered 12h interval until Ctrl+C. No automatic reference switch, runtime Apply, or trust changes.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Preview,
    Check([u8; 32]),
    Enroll([u8; 32]),
    Inspect,
    Recheck(u64, [u8; 32]),
    Monitor([u8; 32]),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    plan: Option<String>,
    store: Option<String>,
    action: Action,
}

fn path(raw: &str) -> Result<String, CliError> {
    if !crate::bounded_input::explicit_file_path(Path::new(raw)) {
        return Err(CliError::InvalidConfigPath);
    }
    Ok(raw.to_owned())
}

fn hash(raw: &str) -> Result<[u8; 32], CliError> {
    crate::parse_restart_digest(raw).ok_or(CliError::InvalidArguments)
}

pub(crate) fn parse(args: &[&str]) -> Result<Command, CliError> {
    let (plan, store, action) = match args {
        ["preview", "--plan", p] => (Some(*p), None, Action::Preview),
        ["check", "--plan", p, "--sha256", h, "--confirm"] => {
            (Some(*p), None, Action::Check(hash(h)?))
        }
        ["enroll", "--plan", p, "--store", s, "--sha256", h, "--confirm"] => {
            (Some(*p), Some(*s), Action::Enroll(hash(h)?))
        }
        ["inspect", "--store", s] => (None, Some(*s), Action::Inspect),
        ["recheck", "--store", s, "--expected-revision", r, "--plan-sha256", h, "--confirm"] => (
            None,
            Some(*s),
            Action::Recheck(crate::expected_revision(r)?, hash(h)?),
        ),
        ["monitor", "--store", s, "--plan-sha256", h, "--confirm"] => {
            (None, Some(*s), Action::Monitor(hash(h)?))
        }
        _ => return Err(CliError::InvalidArguments),
    };
    Ok(Command {
        plan: plan.map(path).transpose()?,
        store: store.map(path).transpose()?,
        action,
    })
}

fn hex(hash: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(64);
    for byte in hash {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn read_plan(path: &str) -> Result<(Plan, [u8; 32]), Error> {
    let raw = crate::bounded_input::read(Path::new(path), health::MAX_PLAN as u64, true, false)
        .map_err(|_| Error::Storage)?;
    let text = std::str::from_utf8(&raw).map_err(|_| Error::Format)?;
    Ok((Plan::parse(text)?, health::digest(text)))
}

fn state_report(state: &State) -> Result<String, Error> {
    Ok(format!(
        "{}\nplan_sha256={}",
        state.report(health::unix_now()?)?,
        hex(&state.plan().digest()?)
    ))
}

async fn monitor(store: &Store, approved: [u8; 32]) -> Result<String, Error> {
    let work = async {
        loop {
            let state = store.inspect()?;
            if state.plan().digest()? != approved {
                return Err::<String, Error>(Error::Approval);
            }
            let now = health::unix_now()?;
            state.status(now)?;
            let due = state.next_check_at()?;
            if now >= due {
                let next = store.recheck(state.revision(), approved).await?;
                println!("{}", state_report(&next)?);
            } else {
                // Re-read state periodically so a manual update cannot
                // leave this worker using an old approved plan or revision.
                tokio::time::sleep(Duration::from_secs((due - now).min(60))).await;
            }
        }
    };
    tokio::select! {
        biased;
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|_| Error::Storage)?;
            Ok("Reference monitor stopped; runtime UNCHANGED".into())
        }
        result = work => result,
    }
}

pub async fn run(command: Command) -> Result<String, Error> {
    let plan = command.plan.as_deref().map(read_plan).transpose()?;
    let store = command
        .store
        .as_deref()
        .map(|p| Store::new(Path::new(p)))
        .transpose()?;
    let get_plan = || plan.as_ref().ok_or(Error::Format);
    let get_store = || store.as_ref().ok_or(Error::Format);
    match command.action {
        Action::Preview => {
            let (plan, digest) = get_plan()?;
            Ok(format!(
                "{}\ndocument_sha256={}",
                plan.preview()?,
                hex(digest)
            ))
        }
        Action::Check(expected) | Action::Enroll(expected) => {
            let (plan, actual) = get_plan()?;
            if *actual != expected {
                return Err(Error::Approval);
            }
            let evidence = health::check(plan, plan.digest()?).await?;
            if matches!(command.action, Action::Enroll(_)) {
                let state = State::new(plan.clone(), evidence, health::unix_now()?)?;
                get_store()?.enroll(&state)?;
                state_report(&state)
            } else {
                let mut result = String::from("Reference check; runtime UNCHANGED; nothing saved");
                for (index, entry) in evidence.iter().enumerate() {
                    result.push_str(&format!(
                        "\nreference[{index}]: h2={} h3={} score={}",
                        entry.eligible(),
                        entry.h3(),
                        entry.score()
                    ));
                }
                Ok(result)
            }
        }
        Action::Inspect => state_report(&get_store()?.inspect()?),
        Action::Recheck(revision, expected) => {
            state_report(&get_store()?.recheck(revision, expected).await?)
        }
        Action::Monitor(expected) => monitor(get_store()?, expected).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_active_command_requires_digest_and_confirmation() {
        let dir = std::env::temp_dir();
        let plan = dir.join("plan.toml");
        let store = dir.join("reference.toml");
        let p = plan.to_str().unwrap();
        let s = store.to_str().unwrap();
        let digest = "01".repeat(32);
        assert!(parse(&["preview", "--plan", p]).is_ok());
        assert!(parse(&["inspect", "--store", s]).is_ok());
        assert!(parse(&["check", "--plan", p, "--sha256", &digest]).is_err());
        assert!(parse(&["check", "--plan", p, "--sha256", &digest, "--confirm"]).is_ok());
        assert!(parse(&[
            "enroll",
            "--plan",
            p,
            "--store",
            s,
            "--sha256",
            &digest,
            "--confirm"
        ])
        .is_ok());
        assert!(parse(&[
            "recheck",
            "--store",
            s,
            "--expected-revision",
            "0",
            "--plan-sha256",
            &digest,
            "--confirm"
        ])
        .is_err());
        assert!(parse(&["monitor", "--store", s, "--plan-sha256", &digest]).is_err());
        assert!(parse(&[
            "monitor",
            "--store",
            s,
            "--plan-sha256",
            &digest,
            "--confirm"
        ])
        .is_ok());
    }
}
