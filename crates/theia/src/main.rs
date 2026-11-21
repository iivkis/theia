use std::path::Path;
use theia::{execute, parse, server, CliError, Command};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Result<Vec<String>, CliError> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().map_err(|_| CliError::NonUtf8Argument))
        .collect();
    let result = match args.and_then(|args| parse(&args)) {
        Ok(Command::ServerRun { config }) => server::run_file(Path::new(&config))
            .await
            .map(|_| "server stopped")
            .map_err(CliError::Server),
        Ok(command) => execute(command),
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
