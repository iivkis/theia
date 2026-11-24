//! Offline operator interface for the candidate signed descriptor store.
//! No network, profile writes, trust-on-first-use, secrets or runtime Apply.
use crate::{
    config::{Transport, XhttpMode},
    descriptor::{self, Anchor, ClientPolicy, Error, Scope, Store, Verified},
    CliError,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const HELP: &str = "Offline trust candidate; does not activate REALITY or change runtime.\n\
theia trust inspect --anchor PATH --store PATH\n\
theia trust verify --anchor PATH --document PATH\n\
theia trust enroll --anchor PATH --store PATH --document PATH --sha256 HEX --confirm\n\
theia trust preview-update --anchor PATH --store PATH --document PATH\n\
theia trust update --anchor PATH --store PATH --document PATH --expected-revision N --sha256 HEX --confirm\n\
theia trust preview-rotation --anchor PATH --store PATH --document PATH --next-key KEY\n\
theia trust rotate --anchor PATH --store PATH --document PATH --next-key KEY --expected-revision N --sha256 HEX --confirm\n\
All paths must be absolute local files. Anchor TOML: schema_version=1, inbound, endpoint, public_key (canonical unpadded base64url), minimum_revision, transport (auto/h2/h3), xhttp_mode (auto/stream-one/stream-up). Obtain and verify the anchor independently; both policy fields are required. Confirm SHA-256 of exact descriptor bytes from preview. Rotate only with separately confirmed public key. For compromise or missed overlap obtain a new independent anchor and use a NEW store; never overwrite an existing store. No private keys accepted.";

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Inspect,
    Verify,
    Enroll {
        digest: [u8; 32],
    },
    PreviewUpdate,
    Update {
        revision: u64,
        digest: [u8; 32],
    },
    PreviewRotation {
        key: [u8; 32],
    },
    Rotate {
        key: [u8; 32],
        revision: u64,
        digest: [u8; 32],
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    anchor: String,
    store: Option<String>,
    document: Option<String>,
    action: Action,
}

fn path(raw: &str) -> Result<String, CliError> {
    if !crate::bounded_input::explicit_file_path(Path::new(raw)) {
        return Err(CliError::InvalidConfigPath);
    }
    Ok(raw.to_owned())
}

fn public_key(raw: &str) -> Result<[u8; 32], Error> {
    if raw.len() != 43 {
        return Err(Error::Format);
    }
    let decoded = URL_SAFE_NO_PAD.decode(raw).map_err(|_| Error::Format)?;
    let key: [u8; 32] = decoded.try_into().map_err(|_| Error::Format)?;
    if key == [0; 32] || URL_SAFE_NO_PAD.encode(key) != raw {
        return Err(Error::Format);
    }
    Ok(key)
}
fn digest(raw: &str) -> Result<[u8; 32], CliError> {
    crate::parse_restart_digest(raw).ok_or(CliError::InvalidArguments)
}
fn key(raw: &str) -> Result<[u8; 32], CliError> {
    public_key(raw).map_err(|_| CliError::InvalidArguments)
}

pub(crate) fn parse(args: &[&str]) -> Result<Command, CliError> {
    let (anchor, store, document, action) = match args {
        ["inspect", "--anchor", a, "--store", s] => (*a, Some(*s), None, Action::Inspect),
        ["verify", "--anchor", a, "--document", d] => (*a, None, Some(*d), Action::Verify),
        ["enroll", "--anchor", a, "--store", s, "--document", d, "--sha256", hash, "--confirm"] => {
            (
                *a,
                Some(*s),
                Some(*d),
                Action::Enroll {
                    digest: digest(hash)?,
                },
            )
        }
        ["preview-update", "--anchor", a, "--store", s, "--document", d] => {
            (*a, Some(*s), Some(*d), Action::PreviewUpdate)
        }
        ["update", "--anchor", a, "--store", s, "--document", d, "--expected-revision", rev, "--sha256", hash, "--confirm"] => {
            (
                *a,
                Some(*s),
                Some(*d),
                Action::Update {
                    revision: crate::expected_revision(rev)?,
                    digest: digest(hash)?,
                },
            )
        }
        ["preview-rotation", "--anchor", a, "--store", s, "--document", d, "--next-key", k] => (
            *a,
            Some(*s),
            Some(*d),
            Action::PreviewRotation { key: key(k)? },
        ),
        ["rotate", "--anchor", a, "--store", s, "--document", d, "--next-key", k, "--expected-revision", rev, "--sha256", hash, "--confirm"] => {
            (
                *a,
                Some(*s),
                Some(*d),
                Action::Rotate {
                    key: key(k)?,
                    revision: crate::expected_revision(rev)?,
                    digest: digest(hash)?,
                },
            )
        }
        _ => return Err(CliError::InvalidArguments),
    };
    Ok(Command {
        anchor: path(anchor)?,
        store: store.map(path).transpose()?,
        document: document.map(path).transpose()?,
        action,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorFile {
    schema_version: u16,
    inbound: String,
    endpoint: String,
    public_key: String,
    minimum_revision: u64,
    transport: Transport,
    xhttp_mode: XhttpMode,
}
fn read(path: &str, limit: u64, private: bool) -> Result<String, Error> {
    let bytes = crate::bounded_input::read(Path::new(path), limit, true, private)
        .map_err(|_| Error::Storage)?;
    std::str::from_utf8(&bytes)
        .map(str::to_owned)
        .map_err(|_| Error::Format)
}
fn load_anchor(path: &str) -> Result<Anchor, Error> {
    let text = read(path, 4096, true)?;
    let file: AnchorFile = toml::from_str(&text).map_err(|_| Error::Format)?;
    if file.schema_version != 1 {
        return Err(Error::Format);
    }
    Anchor::new(
        Scope {
            inbound: file.inbound,
            endpoint: file.endpoint,
        },
        public_key(&file.public_key)?,
        file.minimum_revision,
        ClientPolicy {
            transport: file.transport,
            xhttp_mode: file.xhttp_mode,
        },
    )
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}
fn preview(value: &Verified, now: u64, current: Option<u64>, raw: Option<&str>) -> String {
    let d = value.descriptor();
    let mut result = format!("OFFLINE ONLY; runtime UNCHANGED\nrevision={}\nvalid_now={}\nidentity_sha256={}\ntransports=h2{}\nstream_one={}\nstream_up={}",
        d.revision, value.check_time(now).is_ok(), hex(&Sha256::digest(value.signer())),
        if d.h3 { ",h3" } else { "" }, d.stream_one, d.stream_up);
    let modes = value.effective_modes();
    result.push_str(&format!(
        "\neffective_h2={}\neffective_h3={}\neffective_stream_one={}\neffective_stream_up={}\nnot_before={}\nnot_after={}\nreference_count={}\nactive_reference_index={}",
        modes.h2, modes.h3, modes.stream_one, modes.stream_up,
        d.not_before, d.not_after, d.references.len(), d.active_reference
    ));
    if let Some(revision) = current {
        result.push_str(&format!("\nexpected_revision={revision}"));
    }
    if let Some(raw) = raw {
        result.push_str(&format!(
            "\ndocument_sha256={}",
            hex(&Sha256::digest(raw.as_bytes()))
        ));
    }
    result
}

pub fn run(command: Command) -> Result<String, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Validity)?
        .as_secs();
    let anchor = load_anchor(&command.anchor)?;
    let store = command
        .store
        .as_deref()
        .map(|p| Store::new(Path::new(p), anchor.clone()))
        .transpose()?;
    let document = command
        .document
        .as_deref()
        .map(|p| read(p, descriptor::MAX_DOCUMENT as u64, false))
        .transpose()?;
    let get_store = || store.as_ref().ok_or(Error::Format);
    let get_doc = || document.as_deref().ok_or(Error::Format);
    let checked = |expected: [u8; 32]| {
        let raw = get_doc()?;
        let actual: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
        if actual != expected {
            return Err(Error::Format);
        }
        Ok(raw)
    };
    let applied = || Ok("Offline trust snapshot saved; runtime UNCHANGED".to_owned());
    match command.action {
        Action::Inspect => Ok(preview(&get_store()?.inspect(now)?, now, None, None)),
        Action::Verify => {
            let raw = get_doc()?;
            let verified = descriptor::verify(raw, &anchor)?;
            verified.check_time(now)?;
            Ok(preview(&verified, now, None, Some(raw)))
        }
        Action::Enroll { digest } => {
            get_store()?.initialize(checked(digest)?, now)?;
            applied()
        }
        Action::PreviewUpdate => {
            let raw = get_doc()?;
            let (revision, next) = get_store()?.preview_update(raw, now)?;
            Ok(preview(&next, now, Some(revision), Some(raw)))
        }
        Action::Update { revision, digest } => {
            get_store()?.update_at(checked(digest)?, revision, now)?;
            applied()
        }
        Action::PreviewRotation { key } => {
            let raw = get_doc()?;
            let (revision, next) = get_store()?.preview_promotion(raw, key, now)?;
            Ok(preview(&next, now, Some(revision), Some(raw)))
        }
        Action::Rotate {
            key,
            revision,
            digest,
        } => {
            get_store()?.promote(checked(digest)?, revision, key, now)?;
            applied()
        }
    }
}
