//! Theia command-line contract. Network runtimes and configuration validation
//! are intentionally unavailable until their respective implementation stages.
//! Parsing must never trigger networking, file I/O, or OS proxy modifications.

pub mod camouflage_batch;
pub mod camouflage_discovery;
pub mod camouflage_domain_dns;
pub mod camouflage_dual;
pub mod camouflage_dual_batch;
pub mod camouflage_egress;
pub mod camouflage_h3_probe;
pub mod camouflage_interfaces;
pub mod camouflage_probe;
pub mod camouflage_workflow;
pub mod client;
pub mod config;
#[cfg(feature = "experimental-btls-h2")]
mod h2_btls;
pub mod h3_client;
pub mod h3_server;
pub mod invite;
pub mod live_auth;
pub mod local_proxy;
pub mod management;
pub mod protocol;
pub mod quic_transport;
pub(crate) mod quota;
pub mod reload_preflight;
pub mod restart_guard;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) mod runtime_generation;
pub mod server;
pub mod tui;
pub(crate) mod tui_candidate_batch;
pub(crate) mod tui_candidates;
pub(crate) mod tui_discovery;
pub(crate) mod tui_domain;
pub mod tui_editor;
pub(crate) mod tui_probe;
pub(crate) mod tui_runtime;
#[cfg(target_os = "windows")]
pub mod windows_control;

use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Help(Option<&'static str>),
    Version,
    Tui {
        role: Option<Role>,
    },
    TuiEdit {
        role: Role,
        config: String,
    },
    ServerRun {
        config: String,
    },
    ServerStatus,
    ServerCheckReload,
    ServerCheckRestart,
    ServerCheckQuota,
    ServerApplyQuota {
        expected_revision: u64,
        candidate_sha256: [u8; 32],
    },
    ServerApplyRestart {
        expected_revision: u64,
        candidate_sha256: [u8; 32],
    },
    ServerApplyReload {
        expected_revision: u64,
    },
    ClientRun {
        config: String,
    },
    ConfigValidate {
        config: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    InvalidArguments,
    InvalidRole,
    InvalidConfigPath,
    NonUtf8Argument,
    NotImplemented(&'static str),
    Config(config::ConfigError),
    Server(server::ServerError),
    Management(management::ManagementError),
    Client(client::ClientError),
    Tui(&'static str),
}

impl CliError {
    /// The distinction allows scripts to separate bad syntax from unavailable features.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::NotImplemented(_) => 3,
            _ => 2,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments => {
                write!(f, "invalid arguments; run 'theia --help' for usage")
            }
            Self::InvalidRole => write!(f, "invalid role; expected 'server' or 'client'"),
            Self::InvalidConfigPath => write!(f, "missing or invalid --config path"),
            Self::NonUtf8Argument => write!(f, "arguments must be UTF-8"),
            Self::Config(error) => write!(f, "configuration invalid: {error}"),
            Self::Server(error) => write!(f, "server failed: {error}"),
            Self::Management(error) => write!(f, "management status unavailable: {error}"),
            Self::Client(error) => write!(f, "client failed: {error}"),
            Self::Tui(message) => write!(f, "TUI failed: {message}"),
            Self::NotImplemented(feature) => write!(
                f,
                "{feature} is not implemented; no network or system proxy was started"
            ),
        }
    }
}

impl std::error::Error for CliError {}

fn config_path(raw: &str) -> Result<String, CliError> {
    if raw.is_empty() || raw.starts_with('-') {
        Err(CliError::InvalidConfigPath)
    } else {
        Ok(raw.to_owned())
    }
}

fn role(raw: &str) -> Result<Role, CliError> {
    match raw {
        "server" => Ok(Role::Server),
        "client" => Ok(Role::Client),
        _ => Err(CliError::InvalidRole),
    }
}

/// Accept only exact 64-char lowercase hex for the saved TOML SHA256.
fn parse_restart_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

/// Parse arguments excluding argv[0]; reject unknown and duplicate flags.
/// A recognized runtime command is NOT evidence that a runtime exists.
pub fn parse(args: &[String]) -> Result<Command, CliError> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] | ["tui"] => Ok(Command::Tui { role: None }),
        ["--help" | "-h"] => Ok(Command::Help(None)),
        ["--version" | "-V"] => Ok(Command::Version),
        ["tui", "--help" | "-h"] => Ok(Command::Help(Some("tui"))),
        ["server", "--help" | "-h"] => Ok(Command::Help(Some("server"))),
        ["client", "--help" | "-h"] => Ok(Command::Help(Some("client"))),
        ["config", "--help" | "-h"] => Ok(Command::Help(Some("config"))),
        ["tui", "--role", selected] => Ok(Command::Tui {
            role: Some(role(selected)?),
        }),
        ["tui", "--role", selected, "--config", path]
        | ["tui", "--config", path, "--role", selected] => Ok(Command::TuiEdit {
            role: role(selected)?,
            config: config_path(path)?,
        }),
        ["server", "status"] => Ok(Command::ServerStatus),
        ["server", "reload", "--check"] => Ok(Command::ServerCheckReload),
        ["server", "restart", "--check"] => Ok(Command::ServerCheckRestart),
        ["server", "quota", "--check"] => Ok(Command::ServerCheckQuota),
        ["server", verb @ ("restart" | "quota"), "--apply", "--expected-revision", revision, "--sha256", digest, "--confirm"] =>
        {
            let expected_revision = revision
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .filter(|_| !revision.starts_with('0'))
                .filter(|_| revision.bytes().all(|byte| byte.is_ascii_digit()))
                .ok_or(CliError::InvalidArguments)?;
            let candidate_sha256 =
                parse_restart_digest(digest).ok_or(CliError::InvalidArguments)?;
            if verb == &"quota" {
                Ok(Command::ServerApplyQuota {
                    expected_revision,
                    candidate_sha256,
                })
            } else {
                Ok(Command::ServerApplyRestart {
                    expected_revision,
                    candidate_sha256,
                })
            }
        }
        ["server", "reload", "--expected-revision", raw] => {
            if raw.is_empty() || raw.starts_with('0') || !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(CliError::InvalidArguments);
            }
            let expected_revision = raw.parse::<u64>().map_err(|_| CliError::InvalidArguments)?;
            Ok(Command::ServerApplyReload { expected_revision })
        }
        ["server", "run", "--config", path] => Ok(Command::ServerRun {
            config: config_path(path)?,
        }),
        ["client", "run", "--config", path] => Ok(Command::ClientRun {
            config: config_path(path)?,
        }),
        ["config", "validate", "--config", path] => Ok(Command::ConfigValidate {
            config: config_path(path)?,
        }),
        _ => Err(CliError::InvalidArguments),
    }
}

const HELP: &str = "Theia 0.1.0 (H2 server inbound, H3 inbound, client and M4.1c typed TUI)\n\
Usage:\n\
  theia --help | --version\n\
  theia tui [--role server|client] [--config <path>]\n\
  theia server run --config <path>\n\
  theia server status                # read-only Linux opt-in IPC\n\
  theia server reload --check        # read-only compatibility check\n\
  theia server restart --check       # read-only restart readiness; never commits\n\
  theia server restart --apply --expected-revision N --sha256 HEX --confirm\n\
  theia server quota --check         # read-only occupancy-aware quota validation\n\
  theia server quota --apply --expected-revision N --sha256 HEX --confirm\n\
  theia server reload --expected-revision N  # Linux CAS auth Apply\n\
  theia client run --config <path>\n\
  theia config validate --config <path>\n\
\n--help, --version, config validate, server run and client run (H2/H3/auto) are implemented.\n\
Client requires tls_ca PEM bundle. TUI edits 3 safe fields; server role+config supports u for new user and one-time token link after save; system proxy never changed.";

/// Synchronous introspection/config validation. Server startup is async in the binary.
pub fn execute(command: Command) -> Result<&'static str, CliError> {
    match command {
        Command::Help(None) => Ok(HELP),
        Command::Help(Some("tui")) => {
            Ok("Usage: theia tui [--role server|client] [--config <path>]\nWith role+config, edit 3 non-secret fields per existing record; server panel u creates a user with an inbound grant and one-time URI only after save; no runtime reload or OS proxy changes.")
        }
        Command::Help(Some("server")) => {
            Ok("Usage: theia server run --config <path> | theia server status | theia server reload --check | theia server restart --check | theia server restart --apply --expected-revision N --sha256 HEX --confirm | theia server quota --check | theia server quota --apply --expected-revision N --sha256 HEX --confirm | theia server reload --expected-revision N\nQuota CAS resizes only two session/connection caps, retaining all held permits and denying new admissions while over the decreased cap. All other config, TLS identity bytes, grants, user roster and listener addresses must remain unchanged. Requires private Linux/Windows IPC and exact saved SHA256 TOML; lost ACK is indeterminate, query status. Restart-only fresh-port/TLS cutover uses its separate command.")
        }
        Command::Help(Some("client")) => {
            Ok("Usage: theia client run --config <path>\nHTTP CONNECT/SOCKS5 via H2, H3 or QUIC-first auto; requires tls_ca PEM bundle.")
        }
        Command::Help(Some("config")) => {
            Ok("Usage: theia config validate --config <path>\nValidate TOML v1 without reading secret values.")
        }
        Command::Help(Some(_)) => Err(CliError::InvalidArguments),
        Command::Version => Ok(concat!("theia ", env!("CARGO_PKG_VERSION"))),
        Command::Tui { .. } | Command::TuiEdit { .. } => Err(CliError::NotImplemented("TUI")),
        Command::ServerRun { .. } => Err(CliError::NotImplemented("server runtime")),
        Command::ServerStatus
        | Command::ServerCheckReload
        | Command::ServerCheckRestart
        | Command::ServerCheckQuota
        | Command::ServerApplyQuota { .. }
        | Command::ServerApplyRestart { .. }
        | Command::ServerApplyReload { .. } => {
            Err(CliError::NotImplemented("async management IPC"))
        },
        Command::ClientRun { .. } => Err(CliError::NotImplemented("client runtime")),
        Command::ConfigValidate { config } => {
            config::read_file(Path::new(&config)).map_err(CliError::Config)?;
            Ok("configuration structurally valid (secret/file existence not checked)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(words: &[&str]) -> Result<Command, CliError> {
        parse(
            &words
                .iter()
                .map(|word| (*word).to_owned())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn help_and_version_are_available_without_side_effects() {
        assert_eq!(command(&["--help"]), Ok(Command::Help(None)));
        assert_eq!(command(&["-h"]), Ok(Command::Help(None)));
        assert_eq!(command(&["--version"]), Ok(Command::Version));
        assert!(execute(Command::Version).unwrap().starts_with("theia "));
        assert!(execute(Command::Help(None))
            .unwrap()
            .contains("H2 server inbound"));
    }

    #[test]
    fn quota_apply_requires_canonical_digest_and_explicit_confirmation() {
        let digest = "ab".repeat(32);
        assert_eq!(
            command(&["server", "quota", "--check"]),
            Ok(Command::ServerCheckQuota)
        );
        assert_eq!(
            command(&[
                "server",
                "quota",
                "--apply",
                "--expected-revision",
                "3",
                "--sha256",
                &digest,
                "--confirm"
            ]),
            Ok(Command::ServerApplyQuota {
                expected_revision: 3,
                candidate_sha256: [0xabu8; 32],
            })
        );
        for bad in ["0", "03", "+3", "-3", "3x"] {
            assert_eq!(
                command(&[
                    "server",
                    "quota",
                    "--apply",
                    "--expected-revision",
                    bad,
                    "--sha256",
                    &digest,
                    "--confirm"
                ]),
                Err(CliError::InvalidArguments)
            );
        }
        assert_eq!(
            command(&[
                "server",
                "quota",
                "--apply",
                "--expected-revision",
                "3",
                "--sha256",
                &digest
            ]),
            Err(CliError::InvalidArguments)
        );
        assert_eq!(
            command(&[
                "server",
                "quota",
                "--apply",
                "--expected-revision",
                "3",
                "--sha256",
                &"AB".repeat(32),
                "--confirm"
            ]),
            Err(CliError::InvalidArguments)
        );
    }

    #[test]
    fn restart_requires_pin_of_actual_tls_pem_bytes_and_canonical_digest() {
        let hex = "ab".repeat(32);
        assert_eq!(
            command(&["server", "tls", "fingerprint", "--config", "/tmp/server.toml"]),
            Ok(Command::ServerTlsFingerprint {
                config: "/tmp/server.toml".into(),
            })
        );
        assert_eq!(
            command(&[
                "server", "restart", "--apply", "--expected-revision",
                "7", "--sha256", &hex, "--tls-sha256", &hex, "--confirm",
            ]),
            Ok(Command::ServerApplyRestart {
                expected_revision: 7,
                candidate_sha256: [0xab; 32],
                tls_sha256: [0xab; 32],
            })
        );
        assert_eq!(
            command(&[
                "server", "restart", "--apply", "--expected-revision",
                "7", "--sha256", &hex, "--confirm",
            ]),
            Err(CliError::InvalidArguments),
            "old TOML-only restart Apply must fail closed"
        );
        assert_eq!(
            command(&[
                "server", "restart", "--apply", "--expected-revision",
                "7", "--sha256", &hex, "--tls-sha256", &"AB".repeat(32), "--confirm",
            ]),
            Err(CliError::InvalidArguments)
        );
    }

    #[test]
    fn supervised_restart_requires_explicit_confirmation_and_exact_sha256() {
        let digest = "ab".repeat(32);
        assert_eq!(
            command(&[
                "server",
                "restart",
                "--apply",
                "--expected-revision",
                "7",
                "--sha256",
                &digest,
                "--confirm"
            ]),
            Ok(Command::ServerApplyRestart {
                expected_revision: 7,
                candidate_sha256: [0xabu8; 32],
            })
        );
        for wrong_revision in ["0", "07", "-1", "+1", "1x", "18446744073709551616"] {
            assert_eq!(
                command(&[
                    "server",
                    "restart",
                    "--apply",
                    "--expected-revision",
                    wrong_revision,
                    "--sha256",
                    &digest,
                    "--confirm"
                ]),
                Err(CliError::InvalidArguments)
            );
        }
        for wrong_digest in [
            "AB".repeat(32),
            "ab".repeat(31),
            format!("{}f", digest),
            "xx".repeat(32),
        ] {
            assert_eq!(
                command(&[
                    "server",
                    "restart",
                    "--apply",
                    "--expected-revision",
                    "7",
                    "--sha256",
                    &wrong_digest,
                    "--confirm"
                ]),
                Err(CliError::InvalidArguments)
            );
        }
        assert_eq!(
            command(&[
                "server",
                "restart",
                "--apply",
                "--expected-revision",
                "7",
                "--sha256",
                &digest
            ]),
            Err(CliError::InvalidArguments),
            "a restart without --confirm may never become executable"
        );
    }

    #[test]
    fn only_explicit_tui_roles_are_accepted() {
        assert_eq!(command(&[]), Ok(Command::Tui { role: None }));
        assert_eq!(command(&["tui"]), Ok(Command::Tui { role: None }));
        assert_eq!(
            command(&["tui", "--role", "server"]),
            Ok(Command::Tui {
                role: Some(Role::Server)
            })
        );
        assert_eq!(
            command(&["tui", "--role", "client"]),
            Ok(Command::Tui {
                role: Some(Role::Client)
            })
        );
        assert_eq!(
            command(&["tui", "--role", "client", "--config", "client.toml"]),
            Ok(Command::TuiEdit {
                role: Role::Client,
                config: "client.toml".into(),
            })
        );
        assert_eq!(
            command(&["tui", "--config", "server.toml", "--role", "server"]),
            Ok(Command::TuiEdit {
                role: Role::Server,
                config: "server.toml".into(),
            })
        );
        assert_eq!(
            command(&["tui", "--config", "client.toml"]),
            Err(CliError::InvalidArguments)
        );
        assert_eq!(
            command(&["tui", "--role", "client", "--config", ""]),
            Err(CliError::InvalidConfigPath)
        );
        assert_eq!(
            command(&["tui", "--role", "admin"]),
            Err(CliError::InvalidRole)
        );
        assert_eq!(
            command(&["tui", "--role", "server", "--role", "client"]),
            Err(CliError::InvalidArguments)
        );
    }

    #[test]
    fn recognizes_both_headless_roles_and_config_validation() {
        assert_eq!(command(&["server", "status"]), Ok(Command::ServerStatus));
        assert_eq!(
            command(&["server", "reload", "--check"]),
            Ok(Command::ServerCheckReload)
        );
        assert_eq!(
            command(&["server", "reload", "--expected-revision", "1"]),
            Ok(Command::ServerApplyReload {
                expected_revision: 1
            })
        );
        for invalid in ["0", "01", "-1", "+1", "1x", "18446744073709551616"] {
            assert_eq!(
                command(&["server", "reload", "--expected-revision", invalid]),
                Err(CliError::InvalidArguments)
            );
        }
        assert_eq!(
            command(&["server", "reload"]),
            Err(CliError::InvalidArguments)
        );
        assert_eq!(
            command(&["server", "run", "--config", "server.toml"]),
            Ok(Command::ServerRun {
                config: "server.toml".into()
            })
        );
        assert_eq!(
            command(&["client", "run", "--config", "client.toml"]),
            Ok(Command::ClientRun {
                config: "client.toml".into()
            })
        );
        assert_eq!(
            command(&["config", "validate", "--config", "a.toml"]),
            Ok(Command::ConfigValidate {
                config: "a.toml".into()
            })
        );
    }

    #[test]
    fn missing_paths_and_unknown_options_are_errors() {
        for words in [
            vec!["server", "run"],
            vec!["client", "run", "--config"],
            vec!["config", "validate", "--config", "a.toml", "--verbose"],
            vec!["server", "start", "--config", "a.toml"],
            vec!["--unknown"],
        ] {
            assert_eq!(command(&words), Err(CliError::InvalidArguments));
        }
        assert_eq!(
            command(&["server", "run", "--config", ""]),
            Err(CliError::InvalidConfigPath)
        );
        assert_eq!(
            command(&["client", "run", "--config", "--help"]),
            Err(CliError::InvalidConfigPath)
        );
    }

    #[test]
    fn unavailable_features_never_report_success() {
        for command in [
            Command::Tui { role: None },
            Command::Tui {
                role: Some(Role::Server),
            },
            Command::ClientRun {
                config: "client.toml".into(),
            },
        ] {
            let error = execute(command).expect_err("stub must fail closed");
            assert_eq!(error.exit_code(), 3);
        }
    }
}
