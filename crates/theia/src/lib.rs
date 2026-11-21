//! Theia command-line contract. Network runtimes and configuration validation
//! are intentionally unavailable until their respective implementation stages.
//! Parsing must never trigger networking, file I/O, or OS proxy modifications.

pub mod config;
pub mod protocol;

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
    Tui { role: Option<Role> },
    ServerRun { config: String },
    ClientRun { config: String },
    ConfigValidate { config: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    InvalidArguments,
    InvalidRole,
    InvalidConfigPath,
    NonUtf8Argument,
    NotImplemented(&'static str),
    Config(config::ConfigError),
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

const HELP: &str = "Theia 0.1.0 (M1.2 typed config; no proxy runtime)\n\
Usage:\n\
  theia --help | --version\n\
  theia tui [--role server|client]\n\
  theia server run --config <path>\n\
  theia client run --config <path>\n\
  theia config validate --config <path>\n\
\n--help, --version and config validate are operational. Server/client runtimes and TUI\n\
remain unavailable. Validation never starts a network listener or system proxy.";

/// Introspection and structural TOML validation work; network/TUI commands fail closed.
pub fn execute(command: Command) -> Result<&'static str, CliError> {
    match command {
        Command::Help(None) => Ok(HELP),
        Command::Help(Some("tui")) => {
            Ok("Usage: theia tui [--role server|client]\nTUI is not implemented.")
        }
        Command::Help(Some("server")) => {
            Ok("Usage: theia server run --config <path>\nServer runtime is not implemented.")
        }
        Command::Help(Some("client")) => {
            Ok("Usage: theia client run --config <path>\nClient runtime is not implemented.")
        }
        Command::Help(Some("config")) => {
            Ok("Usage: theia config validate --config <path>\nValidate TOML v1 without reading secret values.")
        }
        Command::Help(Some(_)) => Err(CliError::InvalidArguments),
        Command::Version => Ok(concat!("theia ", env!("CARGO_PKG_VERSION"))),
        Command::Tui { .. } => Err(CliError::NotImplemented("TUI")),
        Command::ServerRun { .. } => Err(CliError::NotImplemented("server runtime")),
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
            .contains("no proxy runtime"));
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
            Command::ServerRun {
                config: "server.toml".into(),
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
