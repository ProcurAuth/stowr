//! The command line: `stowr -c <path>` (or `--config`), `--print-config`, and the commands `print-config`,
//! `config-reference`, `healthcheck` and `version` (also `--version` and `-version`).

use std::process::ExitCode;

/// Run the program with the arguments of the process, and give its exit status.
#[allow(clippy::print_stdout)]
pub fn run() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("version" | "--version" | "-version") => {
            println!("stowr {}", super::build_info::current().display);
            ExitCode::SUCCESS
        }
        Some("config-reference") => {
            print!("{}", super::reference());
            ExitCode::SUCCESS
        }
        _ => {
            crate::log!("{}", crate::common::error::Error::not_served("the command line"));
            ExitCode::FAILURE
        }
    }
}
