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
        Ok(Command::ServerStatus) => management::query_environment(management::StatusCommand::Status)
            .await
            .map(|reply| match reply {
                management::StatusReply::Running { inbounds } => {
                    format!("server running; {inbounds} inbounds; reload not available")
                }
                management::StatusReply::Unsupported => "server reload/status unsupported".to_owned(),
                management::StatusReply::Healthy => "server healthy".to_owned(),
            })
            .map_err(CliError::Management),
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
