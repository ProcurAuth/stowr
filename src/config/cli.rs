// SPDX-License-Identifier: MIT OR Apache-2.0
//! The command line: `stowr -c <path>` (or `--config`), `--print-config`, and the commands `check-config`,
//! `print-config`, `config-reference`, `healthcheck`, `version` (also `-V`, `--version` and `-version`) and `help`.
//!
//! - `stowr [-c <path>] [--print-config]` reads the configuration (`config.hcl` by default), writes the effective
//!   configuration and the warnings in the log, and serves. With `--print-config`, it writes the effective
//!   configuration and exits.
//! - `stowr check-config [-c <path>]` checks the configuration and writes the `config.warning` lines on the standard
//!   error. It writes nothing on the standard output. An error gives the status 1.
//! - `stowr print-config [-c <path>]` writes the effective configuration and exits. An error gives the status 1.
//! - `stowr healthcheck [-c <path>] [-url <url>]` sends `GET` to the health URL and exits with 0 for the status 200.
//! - `stowr config-reference` writes docs/configuration-reference.md.
//! - `stowr version` writes `stowr <version>`.
//!
//! An error of the command line writes the error and the help ([`HELP`]) on the standard error, and gives the
//! status 2. An unknown option and an argument that the command does not accept are such errors. `-h`, `--help` or
//! `help` writes the help on the standard output and gives the status 0. Each option also accepts one dash
//! (`-config`) and the form `--name=value`.

use std::io::Write;
use std::process::ExitCode;

use crate::common::config::Config;
use crate::common::time::Timestamp;

use super::flags::{Flag, FlagKind, Parsed, Stop, parse};
use super::health::{Failure, check, url_from_listen};
use super::quote::quote;
use super::{Hooks, format_effective, load_runtime_with, log_start, reference, warnings};

const DEFAULT_CONFIG: &str = "config.hcl";
const DEFAULT_HEALTH_URL: &str = "http://127.0.0.1:8080/healthz";

/// The help of the command line: the commands and the options, one line each.
pub(super) const HELP: &str = "\
Usage: stowr [command] [options]

Commands:
  (none)            Check the configuration, then serve.
  check-config      Check the configuration, write the warnings, and exit. Exit with 1 for an error.
  print-config      Check the configuration, write the value and the source of each key, and exit.
  healthcheck       Send GET to the health URL. Exit with 0 when the status is 200.
  config-reference  Write the configuration reference (Markdown) and exit.
  version           Write the version of the program and exit. Also -V, --version and -version.
  help              Write this help and exit.

Options:
  -c, --config <path>  The HCL configuration file. Default: config.hcl. With healthcheck, it gives the health URL.
  --print-config       Without a command: check the configuration, write the value of each key, and exit.
  --url <url>          With healthcheck: the health URL. Default: http://127.0.0.1:8080/healthz.
  -h, --help           Write this help and exit.

Each option also accepts one dash (-config) and the form --name=value.
Exit status: 0 for success, 1 for a failure, 2 for an error of the command line.
";

const CONFIG_FLAGS: [Flag; 2] = [
    Flag {
        name: "c",
        kind: FlagKind::Text,
    },
    Flag {
        name: "config",
        kind: FlagKind::Text,
    },
];

const MAIN_FLAGS: &[Flag] = &[
    CONFIG_FLAGS[0],
    CONFIG_FLAGS[1],
    Flag {
        name: "print-config",
        kind: FlagKind::Bool,
    },
];

/// The flags of `check-config` and of `print-config`.
const FILE_FLAGS: &[Flag] = &CONFIG_FLAGS;

const HEALTHCHECK_FLAGS: &[Flag] = &[
    CONFIG_FLAGS[0],
    CONFIG_FLAGS[1],
    Flag {
        name: "url",
        kind: FlagKind::Text,
    },
];

/// The exit status of an error of the command line.
const USAGE_STATUS: u8 = 2;

/// What the program does after the command line.
pub(super) enum Next {
    /// Exit with this status.
    Exit(u8),
    /// Serve with this configuration.
    Serve(Box<Config>),
}

/// Run the program with the arguments of the process, and give its exit status.
pub fn run() -> ExitCode {
    let arguments = super::env::arguments();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    match execute(&arguments, &Hooks::system(), &mut out, &mut err) {
        Next::Exit(status) => ExitCode::from(status),
        Next::Serve(config) => serve(*config),
    }
}

/// Write one line of the log: the date and time in UTC and the text.
fn log_to(err: &mut dyn Write, text: &str) {
    let _ = writeln!(err, "{} {text}", Timestamp::now().log_form());
}

/// Write the help on the standard output, and give the status 0.
fn help(out: &mut dyn Write) -> u8 {
    let _ = out.write_all(HELP.as_bytes());
    0
}

/// Write the error and the help on the standard error, and give the status of an error of the command line.
fn usage_error(err: &mut dyn Write, message: &str) -> u8 {
    let _ = writeln!(err, "{message}");
    let _ = err.write_all(HELP.as_bytes());
    USAGE_STATUS
}

/// Read the flags of a command. `Err` holds the exit status after the help or the error.
fn read_flags(flags: &[Flag], arguments: &[String], out: &mut dyn Write, err: &mut dyn Write) -> Result<Parsed, u8> {
    match parse(flags, arguments) {
        Ok(parsed) => Ok(parsed),
        Err(Stop::Help) => Err(help(out)),
        Err(Stop::Error(message)) => Err(usage_error(err, &message)),
    }
}

/// Read the flags of a command that accepts no argument after its flags. An argument after the flags is an error of
/// the command line. `Err` holds the exit status after the help or the error.
fn read_command_flags(
    command: &str,
    flags: &[Flag],
    arguments: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Parsed, u8> {
    let parsed = read_flags(flags, arguments, out, err)?;
    if let Some(argument) = parsed.rest.first() {
        return Err(usage_error(
            err,
            &format!("unexpected argument {} after {command}", quote(argument)),
        ));
    }
    Ok(parsed)
}

/// Run the command line until the start of the server.
pub(super) fn execute(arguments: &[String], hooks: &Hooks<'_>, out: &mut dyn Write, err: &mut dyn Write) -> Next {
    let rest = arguments.get(1..).unwrap_or_default();
    match arguments.first().map(String::as_str) {
        Some("healthcheck") => return healthcheck(rest, hooks, out, err),
        Some(command @ ("version" | "-V" | "--version" | "-version")) => {
            if let Err(status) = read_command_flags(command, &[], rest, out, err) {
                return Next::Exit(status);
            }
            let _ = writeln!(out, "stowr {}", super::build_info::current().display);
            return Next::Exit(0);
        }
        Some("config-reference") => {
            if let Err(status) = read_command_flags("config-reference", &[], rest, out, err) {
                return Next::Exit(status);
            }
            let _ = out.write_all(reference().as_bytes());
            return Next::Exit(0);
        }
        Some("help") => {
            return Next::Exit(match read_command_flags("help", &[], rest, out, err) {
                Ok(_) => help(out),
                Err(status) => status,
            });
        }
        Some("check-config") => return check_config(rest, hooks, out, err),
        Some("print-config") => return print_config(rest, hooks, out, err),
        _ => {}
    }
    let parsed = match read_flags(MAIN_FLAGS, arguments, out, err) {
        Ok(parsed) => parsed,
        Err(status) => return Next::Exit(status),
    };
    if let Some(argument) = parsed.rest.first() {
        return Next::Exit(usage_error(
            err,
            &format!(
                "unexpected argument {}; use -c <path>, --print-config, check-config, print-config, healthcheck, config-reference, version or help",
                quote(argument)
            ),
        ));
    }
    let path = parsed.text(&["c", "config"], DEFAULT_CONFIG);
    let config = match load_runtime_with(&path, hooks) {
        Ok(config) => config,
        Err(error) => {
            log_to(err, &error.to_string());
            return Next::Exit(1);
        }
    };
    if parsed.boolean("print-config") {
        let _ = out.write_all(format_effective(&config).as_bytes());
        return Next::Exit(0);
    }
    Next::Serve(Box::new(config))
}

/// Check the configuration and write each warning of the start as a `config.warning` line of the log on the standard
/// error. It writes nothing on the standard output. An error gives the status 1.
fn check_config(arguments: &[String], hooks: &Hooks<'_>, out: &mut dyn Write, err: &mut dyn Write) -> Next {
    let parsed = match read_command_flags("check-config", FILE_FLAGS, arguments, out, err) {
        Ok(parsed) => parsed,
        Err(status) => return Next::Exit(status),
    };
    let path = parsed.text(&["c", "config"], DEFAULT_CONFIG);
    match load_runtime_with(&path, hooks) {
        Ok(config) => {
            for warning in warnings(&config) {
                log_to(err, &format!("config.warning {warning}"));
            }
            Next::Exit(0)
        }
        Err(error) => {
            let _ = writeln!(err, "configuration error: {error}");
            Next::Exit(1)
        }
    }
}

/// Check the configuration, write the value that applies for each key with its source, and exit with status 0. It
/// hides each secret.
fn print_config(arguments: &[String], hooks: &Hooks<'_>, out: &mut dyn Write, err: &mut dyn Write) -> Next {
    let parsed = match read_command_flags("print-config", FILE_FLAGS, arguments, out, err) {
        Ok(parsed) => parsed,
        Err(status) => return Next::Exit(status),
    };
    let path = parsed.text(&["c", "config"], DEFAULT_CONFIG);
    match load_runtime_with(&path, hooks) {
        Ok(config) => {
            let _ = out.write_all(format_effective(&config).as_bytes());
            Next::Exit(0)
        }
        Err(error) => {
            let _ = writeln!(err, "configuration error: {error}");
            Next::Exit(1)
        }
    }
}

/// Send `GET` to the health URL: `-url`, else the URL of `server.listen` of `-c`, else the default URL.
fn healthcheck(arguments: &[String], hooks: &Hooks<'_>, out: &mut dyn Write, err: &mut dyn Write) -> Next {
    let parsed = match read_command_flags("healthcheck", HEALTHCHECK_FLAGS, arguments, out, err) {
        Ok(parsed) => parsed,
        Err(status) => return Next::Exit(status),
    };
    let config_path = parsed.text(&["c", "config"], "");
    let mut url = parsed.text(&["url"], "");
    if url.is_empty() && !config_path.trim().is_empty() {
        match load_runtime_with(&config_path, hooks) {
            Ok(config) => url = url_from_listen(&config.listen),
            Err(error) => {
                let _ = writeln!(err, "healthcheck config: {error}");
                return Next::Exit(1);
            }
        }
    }
    if url.is_empty() {
        DEFAULT_HEALTH_URL.clone_into(&mut url);
    }
    match check(&url) {
        Ok(()) => Next::Exit(0),
        Err(Failure::Request(message)) => {
            let _ = writeln!(err, "healthcheck request: {message}");
            Next::Exit(1)
        }
        Err(Failure::Failed(message)) => {
            let _ = writeln!(err, "healthcheck failed: {message}");
            Next::Exit(1)
        }
    }
}

/// Write the effective configuration and the warnings in the log, then serve until SIGINT or SIGTERM.
fn serve(config: Config) -> ExitCode {
    log_start(&config);
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            crate::log!("cannot start the runtime: {}", super::oserror::cause(&error));
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(crate::server::serve(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            crate::log!("{error}");
            ExitCode::FAILURE
        }
    }
}
