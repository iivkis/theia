use std::path::Path;
use theia::{execute, local_proxy, management, parse, server, tui, CliError, Command};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Result<Vec<String>, CliError> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().map_err(|_| CliError::NonUtf8Argument))
        .collect();
    let result: Result<String, CliError> = match args.and_then(|args| parse(&args)) {
        Ok(Command::Tui { role }) => tui::run(role, None)
            .map(|_| "tui closed".to_owned())
            .map_err(|error| CliError::Tui(error.message())),
        Ok(Command::TuiEdit { role, config }) => tui::run(Some(role), Some(Path::new(&config)))
            .map(|_| "tui closed".to_owned())
            .map_err(|error| CliError::Tui(error.message())),
        Ok(Command::ServerRun { config }) => server::run_file(Path::new(&config))
            .await
            .map(|_| "server stopped".to_owned())
            .map_err(CliError::Server),
        Ok(Command::ClientRun { config }) => local_proxy::run_file(Path::new(&config))
            .await
            .map(|_| "client stopped".to_owned())
            .map_err(CliError::Client),
        Ok(Command::ServerStatus) => {
            match management::query_environment(management::StatusCommand::Status).await {
                Ok(management::StatusReply::Running { inbounds }) => Ok(format!(
                    "server running; {inbounds} inbounds; reload not available"
                )),
                Ok(management::StatusReply::RunningRevision { inbounds, revision }) => Ok(format!(
                    "server running; {inbounds} inbounds; authorization revision={revision}"
                )),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerApplyReload { expected_revision }) => {
            match management::query_environment(management::StatusCommand::ApplyReload {
                expected_revision,
            })
            .await
            {
                Ok(management::StatusReply::Applied { revision }) => Ok(format!(
                    "authorization applied; revision={revision}; existing tunnels retained"
                )),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerCheckQuota) => {
            match management::query_environment(management::StatusCommand::CheckQuota).await {
                Ok(management::StatusReply::QuotaReady) => Ok(
                    "quota-only candidate ready: live session/connection limits may change under CAS; existing tunnels UNCHANGED; nothing applied".to_owned(),
                ),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerApplyQuota {
            expected_revision,
            candidate_sha256,
        }) => {
            match management::query_environment(
                management::StatusCommand::ApplyQuotaBound {
                    expected_revision,
                    candidate_sha256,
                },
            )
            .await
            {
                Ok(management::StatusReply::QuotaApplied { revision }) => Ok(format!(
                    "quota caps applied live; revision={revision}; old tunnels retained; cap contraction blocks new admission until occupancy drops"
                )),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerTlsFingerprint { config }) => {
            match server::tls_fingerprint_file(Path::new(&config)) {
                Ok(digest) => Ok(format!(
                    "theia-tls-pem-v1 sha256={}",
                    digest
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                )),
                Err(error) => Err(CliError::Server(error)),
            }
        }
        Ok(Command::ServerApplyRestart {
            expected_revision,
            candidate_sha256,
            tls_sha256,
        }) => {
            match management::query_environment(
                management::StatusCommand::ApplyRestartBound {
                    expected_revision,
                    candidate_sha256,
                    tls_sha256,
                },
            )
            .await
            {
                Ok(management::StatusReply::RestartApplied { revision }) => Ok(format!(
                    "supervised fresh-port restart applied; revision={revision}; old connections draining (max 20s); no same-port rollback guarantee"
                )),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerCheckRestart) => {
            match management::query_environment(management::StatusCommand::CheckRestart).await {
                Ok(management::StatusReply::RestartAuthorizationOnly) => Ok(
                    "restart not needed for compatible authorization changes; use CAS auth Apply; runtime UNCHANGED".to_owned(),
                ),
                Ok(management::StatusReply::RestartSamePortTlsReady) => Ok(
                    "same-port TLS rotation ready: original H2/H3 bind addresses retained; explicit --apply --expected-revision N --sha256 HEX --confirm required; runtime UNCHANGED".to_owned(),
                ),
                Ok(management::StatusReply::RestartRequiresMaintenance) => Ok(
                    "restart requires controlled maintenance: active listener addresses overlap; runtime UNCHANGED".to_owned(),
                ),
                Ok(management::StatusReply::RestartFreshPortsBindable) => Ok(
                    "restart readiness probe passed: new TCP/UDP ports temporarily bound then released; runtime UNCHANGED; NOT reserved or applied".to_owned(),
                ),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerCheckReload) => {
            match management::query_environment(management::StatusCommand::CheckReload).await {
                Ok(management::StatusReply::Compatible) => {
                    Ok("candidate compatible with running listener; runtime UNCHANGED".to_owned())
                }
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(command) => execute(command).map(str::to_owned),
        Err(error) => Err(error),
    };
    match result {
        Ok(message) => println!("{message}"),
        Err(error) => {
            eprintln!("theia: {error}");
            std::process::exit(error.exit_code());
        }
    }
}
