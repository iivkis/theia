use theia::{execute, parse, CliError};

fn main() {
    let args: Result<Vec<String>, CliError> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().map_err(|_| CliError::NonUtf8Argument))
        .collect();
    let result = args.and_then(|args| parse(&args)).and_then(execute);

    match result {
        Ok(message) => println!("{message}"),
        Err(error) => {
            eprintln!("theia: {error}");
            std::process::exit(error.exit_code());
        }
    }
}
