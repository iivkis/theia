//! Offline, explicit provisioning commands. Never run a listener or alter
//! the current client/server config. Confidential links are file-only.
use crate::{
    config::{self, Transport, XhttpMode},
    descriptor::{ClientPolicy, Scope},
    identity_tls::Identity,
    reality_bootstrap::{self as bootstrap, Error, Invitation, Profile},
    reference_health,
    CliError,
};
use std::path::Path;

pub const HELP: &str = "REALITY provisioning candidate; runtime UNCHANGED. All paths absolute.\n\
theia reality identity-new --inbound ID --endpoint HOST:PORT --key PATH --confirm\n\
theia reality descriptor-new --health PATH --key PATH --output PATH --confirm\n\
theia reality descriptor-refresh --health PATH --key PATH --previous PATH --output PATH --sha256 HEX --confirm\n\
theia reality invite-public --health PATH --key PATH --descriptor PATH --output PATH --confirm\n\
theia reality invite-issued --health PATH --key PATH --descriptor PATH --server PATH --user ID --token-file PATH --output PATH --confirm\n\
theia reality preview-import --invitation PATH\n\
theia reality import --invitation PATH --profile PATH --trust PATH --sha256 HEX --identity-sha256 HEX --confirm\n\
theia reality import --invitation PATH --profile PATH --trust PATH --sha256 HEX --identity-sha256 HEX --token-ref REF --confirm\n\
theia reality inspect --profile PATH\n\
Identity SHA-256 must be obtained independently. Import never changes active profile, runtime or system proxy. Descriptor-refresh creates a new file; no automatic publication or reference switch.";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Identity { inbound: String, endpoint: String, key: String },
    NewDescriptor { health: String, key: String, output: String },
    Refresh { health: String, key: String, previous: String, output: String, digest: [u8; 32] },
    Public { health: String, key: String, descriptor: String, output: String },
    Issued { health: String, key: String, descriptor: String, server: String, user: String, token: String, output: String },
    Preview { invitation: String },
    Import { invitation: String, profile: String, trust: String, digest: [u8; 32], identity: [u8; 32], token_ref: Option<String> },
    Inspect { profile: String },
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
fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(64);
    for byte in bytes { let _ = write!(result, "{byte:02x}"); }
    result
}

pub(crate) fn parse(args: &[&str]) -> Result<Command, CliError> {
    Ok(match args {
        ["identity-new", "--inbound", i, "--endpoint", e, "--key", k, "--confirm"]
            if config::valid_id(i) && config::valid_remote(e) => Command::Identity {
                inbound: (*i).into(), endpoint: (*e).into(), key: path(k)?,
            },
        ["descriptor-new", "--health", h, "--key", k, "--output", o, "--confirm"] => Command::NewDescriptor {
            health: path(h)?, key: path(k)?, output: path(o)?,
        },
        ["descriptor-refresh", "--health", h, "--key", k, "--previous", p, "--output", o, "--sha256", d, "--confirm"] => Command::Refresh {
            health: path(h)?, key: path(k)?, previous: path(p)?, output: path(o)?, digest: hash(d)?,
        },
        ["invite-public", "--health", h, "--key", k, "--descriptor", d, "--output", o, "--confirm"] => Command::Public {
            health: path(h)?, key: path(k)?, descriptor: path(d)?, output: path(o)?,
        },
        ["invite-issued", "--health", h, "--key", k, "--descriptor", d, "--server", s, "--user", u, "--token-file", t, "--output", o, "--confirm"]
            if config::valid_id(u) => Command::Issued {
                health: path(h)?, key: path(k)?, descriptor: path(d)?, server: path(s)?,
                user: (*u).into(), token: path(t)?, output: path(o)?,
            },
        ["preview-import", "--invitation", i] => Command::Preview { invitation: path(i)? },
        ["import", "--invitation", i, "--profile", p, "--trust", t, "--sha256", d, "--identity-sha256", k, "--confirm"] => Command::Import {
            invitation: path(i)?, profile: path(p)?, trust: path(t)?, digest: hash(d)?,
            identity: hash(k)?, token_ref: None,
        },
        ["import", "--invitation", i, "--profile", p, "--trust", t, "--sha256", d, "--identity-sha256", k, "--token-ref", r, "--confirm"]
            if config::valid_secret_ref(r) => Command::Import {
                invitation: path(i)?, profile: path(p)?, trust: path(t)?, digest: hash(d)?,
                identity: hash(k)?, token_ref: Some((*r).to_owned()),
            },
        ["inspect", "--profile", p] => Command::Inspect { profile: path(p)? },
        _ => return Err(CliError::InvalidArguments),
    })
}

fn material(health: &str, key: &str) -> Result<(reference_health::State, Identity), Error> {
    let state = reference_health::Store::new(Path::new(health)).map_err(|_| Error::Health)?
        .inspect().map_err(|_| Error::Health)?;
    let scope = Scope { inbound: state.plan().inbound.clone(), endpoint: state.plan().endpoint.clone() };
    let identity = Identity::load(Path::new(key), &scope).map_err(|_| Error::Identity)?;
    Ok((state, identity))
}

fn publish(output: &str, raw: &str) -> Result<String, Error> {
    bootstrap::create_text(Path::new(output), raw)?;
    Ok(format!("Local candidate saved; runtime UNCHANGED\ndocument_sha256={}", hex(bootstrap::digest(raw))))
}

pub fn run(command: Command) -> Result<String, Error> {
    let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
    match command {
        Command::Identity { inbound, endpoint, key } => {
            let identity = Identity::generate(Scope { inbound, endpoint }).map_err(|_| Error::Identity)?;
            identity.save_new(Path::new(&key)).map_err(|e| match e {
                crate::identity_tls::Error::Indeterminate => Error::Indeterminate,
                _ => Error::Identity,
            })?;
            Ok(format!("Identity saved; runtime UNCHANGED\nidentity_sha256={}", hex(bootstrap::fingerprint(identity.public_key()))))
        }
        Command::NewDescriptor { health, key, output } => {
            let (state, identity) = material(&health, &key)?;
            publish(&output, &bootstrap::initial_descriptor(&state, &identity, now)?)
        }
        Command::Refresh { health, key, previous, output, digest } => {
            let (state, identity) = material(&health, &key)?;
            let old = bootstrap::read_text(Path::new(&previous), crate::descriptor::MAX_DOCUMENT, false)?;
            if bootstrap::digest(&old) != digest { return Err(Error::Approval); }
            publish(&output, &bootstrap::refresh_descriptor(&state, &identity, &old, now)?)
        }
        Command::Public { health, key, descriptor, output } => {
            let (state, identity) = material(&health, &key)?;
            state.eligible_references(now).map_err(|_| Error::Health)?;
            let raw = bootstrap::read_text(Path::new(&descriptor), crate::descriptor::MAX_DOCUMENT, false)?;
            let invite = Invitation::public(&identity, &raw, now)?;
            publish(&output, &invite.encode()?)
        }
        Command::Issued { health, key, descriptor, server, user, token, output } => {
            let (state, identity) = material(&health, &key)?;
            state.eligible_references(now).map_err(|_| Error::Health)?;
            let raw = bootstrap::read_text(Path::new(&descriptor), crate::descriptor::MAX_DOCUMENT, false)?;
            let config::Config::Server(document) = config::read_file(Path::new(&server)).map_err(|_| Error::Grant)? else {
                return Err(Error::Grant);
            };
            let token = bootstrap::read_credential(Path::new(&token))?;
            let invite = Invitation::issued(&identity, &raw, &document, &user, &token, now)?;
            publish(&output, &invite.encode()?)
        }
        Command::Preview { invitation } => {
            let uri = bootstrap::read_text(Path::new(&invitation), bootstrap::MAX_URI, false)?;
            let invite = Invitation::decode(&uri, now)?;
            Ok(format!("{}\ndocument_sha256={}", invite.preview(now)?, hex(bootstrap::digest(&uri))))
        }
        Command::Import { invitation, profile, trust, digest, identity, token_ref } => {
            let uri = bootstrap::read_text(Path::new(&invitation), bootstrap::MAX_URI, false)?;
            bootstrap::import(&uri, digest, identity, Path::new(&profile), Path::new(&trust),
                token_ref.as_deref(), ClientPolicy { transport: Transport::Auto, xhttp_mode: XhttpMode::Auto }, now)?;
            Ok("Enrollment saved; runtime UNCHANGED".into())
        }
        Command::Inspect { profile } => {
            let value = Profile::read(Path::new(&profile))?.load(now)?;
            let d = value.descriptor();
            let modes = value.effective_modes();
            Ok(format!("Enrollment valid; runtime UNCHANGED\nrevision={}\nidentity_sha256={}\nh2={}\nh3={}\nstream_one={}\nstream_up={}",
                d.revision, hex(bootstrap::fingerprint(value.signer())), modes.h2, modes.h3, modes.stream_one, modes.stream_up))
        }
    }
}
