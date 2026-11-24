//! Offline, explicit provisioning commands. Never run a listener or alter
//! the current client/server config. Confidential links are file-only.
use crate::{
    config::{self, Transport, XhttpMode},
    descriptor::{ClientPolicy, Scope},
    identity_tls::Identity,
    reality_bootstrap::{self as bootstrap, Error, Invitation, Profile},
    reference_health, CliError,
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
theia reality recovery-preview --profile PATH --descriptor PATH\n\
theia reality recovery-apply --profile PATH --descriptor PATH --expected-revision N --sha256 HEX --identity-sha256 HEX --confirm\n\
theia reality publish-new --health PATH --key PATH --publication PATH --confirm\n\
theia reality publish-status --publication PATH\n\
theia reality publish-refresh --health PATH --publication PATH --sha256 HEX --confirm\n\
theia reality failover-preview --health PATH --publication PATH\n\
theia reality failover-apply --health PATH --publication PATH --sha256 HEX --health-sha256 HEX --reference N --confirm-recovery-plan\n\
theia reality rotation-stage --publication PATH --next-key PATH --sha256 HEX --identity-sha256 HEX --confirm\n\
theia reality rotation-promote --publication PATH --sha256 HEX --identity-sha256 HEX --confirm\n\
theia reality publish-export --publication PATH --output PATH --confirm\n\
theia reality successor-export --publication PATH --output PATH --confirm\n\
Identity SHA-256 must be obtained independently. Import never changes active profile, runtime or system proxy. Descriptor-refresh creates a new file; no automatic publication or reference switch.";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Identity {
        inbound: String,
        endpoint: String,
        key: String,
    },
    NewDescriptor {
        health: String,
        key: String,
        output: String,
    },
    Refresh {
        health: String,
        key: String,
        previous: String,
        output: String,
        digest: [u8; 32],
    },
    Public {
        health: String,
        key: String,
        descriptor: String,
        output: String,
    },
    Issued {
        health: String,
        key: String,
        descriptor: String,
        server: String,
        user: String,
        token: String,
        output: String,
    },
    Preview {
        invitation: String,
    },
    Import {
        invitation: String,
        profile: String,
        trust: String,
        digest: [u8; 32],
        identity: [u8; 32],
        token_ref: Option<String>,
    },
    Inspect {
        profile: String,
    },
    RecoveryPreview {
        profile: String,
        descriptor: String,
    },
    RecoveryApply {
        profile: String,
        descriptor: String,
        revision: u64,
        digest: [u8; 32],
        identity: [u8; 32],
    },
    PublishNew {
        health: String,
        key: String,
        publication: String,
    },
    PublishStatus {
        publication: String,
    },
    PublishRefresh {
        health: String,
        publication: String,
        digest: [u8; 32],
    },
    FailoverPreview {
        health: String,
        publication: String,
    },
    FailoverApply {
        health: String,
        publication: String,
        approval: crate::identity_publication::FailoverApproval,
    },
    RotationStage {
        publication: String,
        next_key: String,
        digest: [u8; 32],
        identity: [u8; 32],
    },
    RotationPromote {
        publication: String,
        digest: [u8; 32],
        identity: [u8; 32],
    },
    PublishExport {
        publication: String,
        output: String,
        successor: bool,
    },
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
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

pub(crate) fn parse(args: &[&str]) -> Result<Command, CliError> {
    Ok(match args {
        ["identity-new", "--inbound", i, "--endpoint", e, "--key", k, "--confirm"]
            if config::valid_id(i) && config::valid_remote(e) =>
        {
            Command::Identity {
                inbound: (*i).into(),
                endpoint: (*e).into(),
                key: path(k)?,
            }
        }
        ["descriptor-new", "--health", h, "--key", k, "--output", o, "--confirm"] => {
            Command::NewDescriptor {
                health: path(h)?,
                key: path(k)?,
                output: path(o)?,
            }
        }
        ["descriptor-refresh", "--health", h, "--key", k, "--previous", p, "--output", o, "--sha256", d, "--confirm"] => {
            Command::Refresh {
                health: path(h)?,
                key: path(k)?,
                previous: path(p)?,
                output: path(o)?,
                digest: hash(d)?,
            }
        }
        ["invite-public", "--health", h, "--key", k, "--descriptor", d, "--output", o, "--confirm"] => {
            Command::Public {
                health: path(h)?,
                key: path(k)?,
                descriptor: path(d)?,
                output: path(o)?,
            }
        }
        ["invite-issued", "--health", h, "--key", k, "--descriptor", d, "--server", s, "--user", u, "--token-file", t, "--output", o, "--confirm"]
            if config::valid_id(u) =>
        {
            Command::Issued {
                health: path(h)?,
                key: path(k)?,
                descriptor: path(d)?,
                server: path(s)?,
                user: (*u).into(),
                token: path(t)?,
                output: path(o)?,
            }
        }
        ["preview-import", "--invitation", i] => Command::Preview {
            invitation: path(i)?,
        },
        ["import", "--invitation", i, "--profile", p, "--trust", t, "--sha256", d, "--identity-sha256", k, "--confirm"] => {
            Command::Import {
                invitation: path(i)?,
                profile: path(p)?,
                trust: path(t)?,
                digest: hash(d)?,
                identity: hash(k)?,
                token_ref: None,
            }
        }
        ["import", "--invitation", i, "--profile", p, "--trust", t, "--sha256", d, "--identity-sha256", k, "--token-ref", r, "--confirm"]
            if config::valid_secret_ref(r) =>
        {
            Command::Import {
                invitation: path(i)?,
                profile: path(p)?,
                trust: path(t)?,
                digest: hash(d)?,
                identity: hash(k)?,
                token_ref: Some((*r).to_owned()),
            }
        }
        ["inspect", "--profile", p] => Command::Inspect { profile: path(p)? },
        ["recovery-preview", "--profile", p, "--descriptor", d] => Command::RecoveryPreview {
            profile: path(p)?,
            descriptor: path(d)?,
        },
        ["recovery-apply", "--profile", p, "--descriptor", d, "--expected-revision", r, "--sha256", h, "--identity-sha256", i, "--confirm"] => {
            Command::RecoveryApply {
                profile: path(p)?,
                descriptor: path(d)?,
                revision: crate::expected_revision(r)?,
                digest: hash(h)?,
                identity: hash(i)?,
            }
        }
        ["publish-new", "--health", h, "--key", k, "--publication", p, "--confirm"] => {
            Command::PublishNew {
                health: path(h)?,
                key: path(k)?,
                publication: path(p)?,
            }
        }
        ["publish-status", "--publication", p] => Command::PublishStatus {
            publication: path(p)?,
        },
        ["publish-refresh", "--health", h, "--publication", p, "--sha256", d, "--confirm"] => {
            Command::PublishRefresh {
                health: path(h)?,
                publication: path(p)?,
                digest: hash(d)?,
            }
        }
        ["failover-preview", "--health", h, "--publication", p] => Command::FailoverPreview {
            health: path(h)?,
            publication: path(p)?,
        },
        ["failover-apply", "--health", h, "--publication", p, "--sha256", d, "--health-sha256", e, "--reference", r, "--confirm-recovery-plan"] =>
        {
            let selected_reference = match *r {
                "0" => 0,
                "1" => 1,
                "2" => 2,
                _ => return Err(CliError::InvalidArguments),
            };
            Command::FailoverApply {
                health: path(h)?,
                publication: path(p)?,
                approval: crate::identity_publication::FailoverApproval {
                    publication_sha256: hash(d)?,
                    health_sha256: hash(e)?,
                    selected_reference,
                },
            }
        }
        ["rotation-stage", "--publication", p, "--next-key", k, "--sha256", d, "--identity-sha256", i, "--confirm"] => {
            Command::RotationStage {
                publication: path(p)?,
                next_key: path(k)?,
                digest: hash(d)?,
                identity: hash(i)?,
            }
        }
        ["rotation-promote", "--publication", p, "--sha256", d, "--identity-sha256", i, "--confirm"] => {
            Command::RotationPromote {
                publication: path(p)?,
                digest: hash(d)?,
                identity: hash(i)?,
            }
        }
        [kind @ ("publish-export" | "successor-export"), "--publication", p, "--output", o, "--confirm"] => {
            Command::PublishExport {
                publication: path(p)?,
                output: path(o)?,
                successor: *kind == "successor-export",
            }
        }
        _ => return Err(CliError::InvalidArguments),
    })
}

fn material(health: &str, key: &str) -> Result<(reference_health::State, Identity), Error> {
    let state = reference_health::Store::new(Path::new(health))
        .map_err(|_| Error::Health)?
        .inspect()
        .map_err(|_| Error::Health)?;
    let scope = Scope {
        inbound: state.plan().inbound.clone(),
        endpoint: state.plan().endpoint.clone(),
    };
    let identity = Identity::load(Path::new(key), &scope).map_err(|_| Error::Identity)?;
    Ok((state, identity))
}

fn publish(output: &str, raw: &str) -> Result<String, Error> {
    bootstrap::create_text(Path::new(output), raw)?;
    Ok(format!(
        "Local candidate saved; runtime UNCHANGED\ndocument_sha256={}",
        hex(bootstrap::digest(raw))
    ))
}

fn publication_status(
    publication: &crate::identity_publication::Publication,
    now: u64,
) -> Result<String, Error> {
    let status = publication.inspect(now)?;
    let next = status
        .next_fingerprint
        .map(hex)
        .unwrap_or_else(|| "none".into());
    let ends = status
        .overlap_ends_at
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".into());
    Ok(format!("Local publication; runtime UNCHANGED\ngeneration={}\nrevision={}\nactive_reference={}\nvalid_now={}\nidentity_sha256={}\nnext_identity_sha256={}\noverlap_ends_at={}\nplan_sha256={}\nsnapshot_sha256={}",
        status.generation, status.revision, status.active_reference, status.valid_now, hex(status.active_fingerprint), next, ends, hex(status.plan_sha256), hex(status.snapshot_sha256)))
}

pub fn run(command: Command) -> Result<String, Error> {
    let now = reference_health::unix_now().map_err(|_| Error::Clock)?;
    match command {
        Command::RecoveryPreview {
            profile,
            descriptor,
        } => {
            let profile = Profile::read(Path::new(&profile))?;
            let raw = bootstrap::read_text(
                Path::new(&descriptor),
                crate::descriptor::MAX_DOCUMENT,
                false,
            )?;
            let preview = profile.preview_recovery(&raw, now)?;
            Ok(format!("Offline recovery preview; runtime UNCHANGED\nexpected_revision={}\nnext_revision={}\ncurrent_expired={}\nreference_changed={}\ndocument_sha256={}\nidentity_sha256={}\nConfirm the fingerprint independently. This cannot recover a compromised or retired identity.",
                preview.expected_revision, preview.next_revision, preview.current_expired, preview.reference_changed, hex(preview.document_sha256), hex(preview.identity_sha256)))
        }
        Command::RecoveryApply {
            profile,
            descriptor,
            revision,
            digest,
            identity,
        } => {
            let profile = Profile::read(Path::new(&profile))?;
            let raw = bootstrap::read_text(
                Path::new(&descriptor),
                crate::descriptor::MAX_DOCUMENT,
                false,
            )?;
            profile.recover(
                &raw,
                bootstrap::RecoveryApproval {
                    expected_revision: revision,
                    document_sha256: digest,
                    identity_sha256: identity,
                },
                now,
            )?;
            Ok("Trust snapshot recovered; profile, credentials and runtime UNCHANGED".into())
        }
        Command::PublishNew {
            health,
            key,
            publication,
        } => {
            let state = reference_health::Store::new(Path::new(&health))
                .map_err(|_| Error::Health)?
                .inspect()
                .map_err(|_| Error::Health)?;
            let publication =
                crate::identity_publication::Publication::new(Path::new(&publication))?;
            publication.initialize(&state, Path::new(&key), now)?;
            publication_status(&publication, now)
        }
        Command::PublishStatus { publication } => publication_status(
            &crate::identity_publication::Publication::new(Path::new(&publication))?,
            now,
        ),
        Command::PublishRefresh {
            health,
            publication,
            digest,
        } => {
            let state = reference_health::Store::new(Path::new(&health))
                .map_err(|_| Error::Health)?
                .inspect()
                .map_err(|_| Error::Health)?;
            let publication =
                crate::identity_publication::Publication::new(Path::new(&publication))?;
            publication.refresh(&state, digest, now)?;
            publication_status(&publication, now)
        }
        Command::FailoverPreview {
            health,
            publication,
        } => {
            let state = reference_health::Store::new(Path::new(&health))
                .map_err(|_| Error::Health)?
                .inspect()
                .map_err(|_| Error::Health)?;
            let publication =
                crate::identity_publication::Publication::new(Path::new(&publication))?;
            let preview = publication.preview_failover(&state, now)?;
            Ok(format!("Offline failover preview; runtime UNCHANGED\ncurrent_reference={}\nselected_reference={}\nnext_revision={}\npublication_sha256={}\nhealth_sha256={}\nRequires explicit confirmed recovery plan for all existing clients; export the updated signed document and distribute it through authenticated recovery. Evidence must be at most 60s old.",
                preview.current_reference, preview.selected_reference, preview.next_revision, hex(preview.publication_sha256), hex(preview.health_sha256)))
        }
        Command::FailoverApply {
            health,
            publication,
            approval,
        } => {
            let state = reference_health::Store::new(Path::new(&health))
                .map_err(|_| Error::Health)?
                .inspect()
                .map_err(|_| Error::Health)?;
            let publication =
                crate::identity_publication::Publication::new(Path::new(&publication))?;
            publication.apply_failover(&state, approval, now)?;
            publication_status(&publication, now)
        }
        Command::RotationStage {
            publication,
            next_key,
            digest,
            identity,
        } => {
            let publication =
                crate::identity_publication::Publication::new(Path::new(&publication))?;
            publication.begin_rotation(Path::new(&next_key), digest, identity, now)?;
            publication_status(&publication, now)
        }
        Command::RotationPromote {
            publication,
            digest,
            identity,
        } => {
            let publication =
                crate::identity_publication::Publication::new(Path::new(&publication))?;
            publication.promote(digest, identity, now)?;
            publication_status(&publication, now)
        }
        Command::PublishExport {
            publication,
            output,
            successor,
        } => {
            let publication =
                crate::identity_publication::Publication::new(Path::new(&publication))?;
            let (current, next) = publication.documents(now)?;
            publish(
                &output,
                if successor {
                    next.as_deref().ok_or(Error::Identity)?
                } else {
                    &current
                },
            )
        }
        Command::Identity {
            inbound,
            endpoint,
            key,
        } => {
            let identity =
                Identity::generate(Scope { inbound, endpoint }).map_err(|_| Error::Identity)?;
            identity.save_new(Path::new(&key)).map_err(|e| match e {
                crate::identity_tls::Error::Indeterminate => Error::Indeterminate,
                _ => Error::Identity,
            })?;
            Ok(format!(
                "Identity saved; runtime UNCHANGED\nidentity_sha256={}",
                hex(bootstrap::fingerprint(identity.public_key()))
            ))
        }
        Command::NewDescriptor {
            health,
            key,
            output,
        } => {
            let (state, identity) = material(&health, &key)?;
            publish(
                &output,
                &bootstrap::initial_descriptor(&state, &identity, now)?,
            )
        }
        Command::Refresh {
            health,
            key,
            previous,
            output,
            digest,
        } => {
            let (state, identity) = material(&health, &key)?;
            let old =
                bootstrap::read_text(Path::new(&previous), crate::descriptor::MAX_DOCUMENT, false)?;
            if bootstrap::digest(&old) != digest {
                return Err(Error::Approval);
            }
            publish(
                &output,
                &bootstrap::refresh_descriptor(&state, &identity, &old, now)?,
            )
        }
        Command::Public {
            health,
            key,
            descriptor,
            output,
        } => {
            let (state, identity) = material(&health, &key)?;
            let raw = bootstrap::read_text(
                Path::new(&descriptor),
                crate::descriptor::MAX_DOCUMENT,
                false,
            )?;
            bootstrap::validate_publication(&state, &identity, &raw, now)?;
            let invite = Invitation::public(&identity, &raw, now)?;
            publish(&output, &invite.encode()?)
        }
        Command::Issued {
            health,
            key,
            descriptor,
            server,
            user,
            token,
            output,
        } => {
            let (state, identity) = material(&health, &key)?;
            let raw = bootstrap::read_text(
                Path::new(&descriptor),
                crate::descriptor::MAX_DOCUMENT,
                false,
            )?;
            bootstrap::validate_publication(&state, &identity, &raw, now)?;
            let config::Config::Server(document) =
                config::read_file(Path::new(&server)).map_err(|_| Error::Grant)?
            else {
                return Err(Error::Grant);
            };
            let token = bootstrap::read_credential(Path::new(&token))?;
            let invite = Invitation::issued(&identity, &raw, &document, &user, &token, now)?;
            publish(&output, &invite.encode()?)
        }
        Command::Preview { invitation } => {
            let uri = bootstrap::read_text(Path::new(&invitation), bootstrap::MAX_URI, false)?;
            let invite = Invitation::decode(&uri, now)?;
            Ok(format!(
                "{}\ndocument_sha256={}",
                invite.preview(now)?,
                hex(bootstrap::digest(&uri))
            ))
        }
        Command::Import {
            invitation,
            profile,
            trust,
            digest,
            identity,
            token_ref,
        } => {
            let uri = bootstrap::read_text(Path::new(&invitation), bootstrap::MAX_URI, false)?;
            bootstrap::import(
                &uri,
                bootstrap::ImportApproval {
                    document_sha256: digest,
                    identity_sha256: identity,
                },
                Path::new(&profile),
                Path::new(&trust),
                token_ref.as_deref(),
                ClientPolicy {
                    transport: Transport::Auto,
                    xhttp_mode: XhttpMode::Auto,
                },
                now,
            )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "theia-reality-cli-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn file(&self, name: &str) -> String {
            self.0.join(name).to_str().unwrap().into()
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn invoke(args: &[&str]) -> Result<String, Error> {
        run(parse(args).unwrap())
    }
    fn field<'a>(output: &'a str, key: &str) -> &'a str {
        output
            .lines()
            .find_map(|line| {
                line.split_once('=')
                    .filter(|(name, _)| *name == key)
                    .map(|(_, value)| value)
            })
            .unwrap()
    }
    fn health(dir: &Scratch) -> String {
        let health = dir.file("health.toml");
        let now = reference_health::unix_now().unwrap();
        let state = reference_health::State::new(
            reference_health::Plan {
                schema_version: 1,
                inbound: "edge".into(),
                endpoint: "edge.example.org:443".into(),
                own_ips: vec!["93.184.216.1".parse().unwrap()],
                references: vec![reference_health::Target {
                    server_name: "reference.example.org".into(),
                    address: "93.184.216.2:443".parse().unwrap(),
                }],
            },
            vec![reference_health::Evidence {
                h2_status: Some(200),
                h3_status: None,
            }],
            now,
        )
        .unwrap();
        reference_health::Store::new(Path::new(&health))
            .unwrap()
            .enroll(&state)
            .unwrap();
        health
    }

    #[test]
    fn offline_cli_provisions_enrollment_and_never_overwrites_or_implicitly_applies() {
        let dir = Scratch::new();
        let h = health(&dir);
        let k = dir.file("identity.key");
        let d = dir.file("descriptor");
        let i = dir.file("invitation");
        let p = dir.file("profile.toml");
        let t = dir.file("trust.toml");
        let a = [
            "identity-new",
            "--inbound",
            "edge",
            "--endpoint",
            "edge.example.org:443",
            "--key",
            &k,
            "--confirm",
        ];
        let identity = invoke(&a).unwrap();
        let fingerprint = field(&identity, "identity_sha256");
        assert_eq!(fingerprint.len(), 64);
        let original_key = std::fs::read(&k).unwrap();
        assert!(invoke(&a).is_err());
        assert_eq!(std::fs::read(&k).unwrap(), original_key);
        let desc = [
            "descriptor-new",
            "--health",
            &h,
            "--key",
            &k,
            "--output",
            &d,
            "--confirm",
        ];
        let descriptor = invoke(&desc).unwrap();
        let doc_digest = field(&descriptor, "document_sha256");
        assert!(invoke(&desc).is_err());
        let raw = std::fs::read_to_string(&d).unwrap();
        assert_eq!(hex(bootstrap::digest(&raw)), doc_digest);
        invoke(&[
            "invite-public",
            "--health",
            &h,
            "--key",
            &k,
            "--descriptor",
            &d,
            "--output",
            &i,
            "--confirm",
        ])
        .unwrap();
        let preview = invoke(&["preview-import", "--invitation", &i]).unwrap();
        let digest = field(&preview, "document_sha256");
        let wrong = "0".repeat(64);
        assert!(invoke(&[
            "import",
            "--invitation",
            &i,
            "--profile",
            &p,
            "--trust",
            &t,
            "--sha256",
            digest,
            "--identity-sha256",
            &wrong,
            "--token-ref",
            "env:THEIA_TOKEN",
            "--confirm"
        ])
        .is_err());
        assert!(!Path::new(&p).exists());
        assert!(!Path::new(&t).exists());
        assert!(invoke(&[
            "import",
            "--invitation",
            &i,
            "--profile",
            &p,
            "--trust",
            &t,
            "--sha256",
            digest,
            "--identity-sha256",
            fingerprint,
            "--token-ref",
            "env:THEIA_TOKEN",
            "--confirm"
        ])
        .unwrap()
        .contains("runtime UNCHANGED"));
        let inspected = invoke(&["inspect", "--profile", &p]).unwrap();
        assert_eq!(field(&inspected, "revision"), "1");
        assert_eq!(field(&inspected, "identity_sha256"), fingerprint);
        let saved = std::fs::read(&p).unwrap();
        assert!(invoke(&["recovery-preview", "--profile", &p, "--descriptor", &d]).is_err());
        assert!(invoke(&[
            "recovery-apply",
            "--profile",
            &p,
            "--descriptor",
            &d,
            "--expected-revision",
            "1",
            "--sha256",
            doc_digest,
            "--identity-sha256",
            fingerprint,
            "--confirm"
        ])
        .is_err());
        assert_eq!(std::fs::read(&p).unwrap(), saved);
        let next = dir.file("next");
        assert!(invoke(&[
            "descriptor-refresh",
            "--health",
            &h,
            "--key",
            &k,
            "--previous",
            &d,
            "--output",
            &next,
            "--sha256",
            &wrong,
            "--confirm"
        ])
        .is_err());
        assert!(!Path::new(&next).exists());
        assert_eq!(std::fs::read_to_string(&d).unwrap(), raw);
    }

    #[test]
    fn publication_cli_checks_fingerprints_and_create_only_exports() {
        let dir = Scratch::new();
        let h = health(&dir);
        let k = dir.file("identity.key");
        let next = dir.file("next.key");
        let p = dir.file("publication.toml");
        let d = dir.file("current");
        let successor = dir.file("successor");
        for key in [&k, &next] {
            invoke(&[
                "identity-new",
                "--inbound",
                "edge",
                "--endpoint",
                "edge.example.org:443",
                "--key",
                key,
                "--confirm",
            ])
            .unwrap();
        }
        let status = invoke(&[
            "publish-new",
            "--health",
            &h,
            "--key",
            &k,
            "--publication",
            &p,
            "--confirm",
        ])
        .unwrap();
        assert_eq!(field(&status, "revision"), "1");
        assert_eq!(field(&status, "next_identity_sha256"), "none");
        let observed = invoke(&["publish-status", "--publication", &p]).unwrap();
        assert_eq!(
            field(&observed, "snapshot_sha256"),
            field(&status, "snapshot_sha256")
        );
        invoke(&[
            "publish-export",
            "--publication",
            &p,
            "--output",
            &d,
            "--confirm",
        ])
        .unwrap();
        let original = std::fs::read(&d).unwrap();
        assert!(invoke(&[
            "publish-export",
            "--publication",
            &p,
            "--output",
            &d,
            "--confirm"
        ])
        .is_err());
        assert_eq!(std::fs::read(&d).unwrap(), original);
        assert!(invoke(&[
            "successor-export",
            "--publication",
            &p,
            "--output",
            &successor,
            "--confirm"
        ])
        .is_err());
        assert!(!Path::new(&successor).exists());
        let wrong = "0".repeat(64);
        let before = std::fs::read(&p).unwrap();
        assert!(invoke(&[
            "publish-refresh",
            "--health",
            &h,
            "--publication",
            &p,
            "--sha256",
            &wrong,
            "--confirm"
        ])
        .is_err());
        assert!(invoke(&["failover-preview", "--health", &h, "--publication", &p]).is_err());
        assert!(invoke(&[
            "failover-apply",
            "--health",
            &h,
            "--publication",
            &p,
            "--sha256",
            &wrong,
            "--health-sha256",
            &wrong,
            "--reference",
            "0",
            "--confirm-recovery-plan"
        ])
        .is_err());
        assert!(invoke(&[
            "rotation-stage",
            "--publication",
            &p,
            "--next-key",
            &next,
            "--sha256",
            &wrong,
            "--identity-sha256",
            &wrong,
            "--confirm"
        ])
        .is_err());
        assert!(invoke(&[
            "rotation-promote",
            "--publication",
            &p,
            "--sha256",
            &wrong,
            "--identity-sha256",
            &wrong,
            "--confirm"
        ])
        .is_err());
        assert_eq!(std::fs::read(&p).unwrap(), before);
    }

    #[test]
    fn cli_refuses_relative_paths_unconfirmed_commands_and_malformed_digests() {
        let dir = Scratch::new();
        let p = dir.file("profile");
        let d = dir.file("descriptor");
        let h = "a".repeat(64);
        for args in [
            vec!["inspect", "--profile", "relative.toml"],
            vec![
                "identity-new",
                "--inbound",
                "edge",
                "--endpoint",
                "edge.example.org:443",
                "--key",
                &p,
            ],
            vec![
                "recovery-apply",
                "--profile",
                &p,
                "--descriptor",
                &d,
                "--expected-revision",
                "0",
                "--sha256",
                &h,
                "--identity-sha256",
                &h,
                "--confirm",
            ],
            vec![
                "publish-refresh",
                "--health",
                &p,
                "--publication",
                &d,
                "--sha256",
                "xyz",
                "--confirm",
            ],
            vec![
                "failover-apply",
                "--health",
                &p,
                "--publication",
                &d,
                "--sha256",
                &h,
                "--health-sha256",
                &h,
                "--reference",
                "3",
                "--confirm-recovery-plan",
            ],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
        assert!(parse(&[
            "invite-issued",
            "--health",
            &p,
            "--key",
            &p,
            "--descriptor",
            &d,
            "--server",
            &p,
            "--user",
            "device-a",
            "--token-file",
            &d,
            "--output",
            &p,
            "--confirm"
        ])
        .is_ok());
        assert!(parse(&[
            "import",
            "--invitation",
            &d,
            "--profile",
            &p,
            "--trust",
            &d,
            "--sha256",
            &h,
            "--identity-sha256",
            &h,
            "--confirm"
        ])
        .is_ok());
    }
}
