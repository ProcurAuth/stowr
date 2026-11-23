//! The command line: `stowr -c <path>` (or `--config`), `--print-config`, and the commands `print-config`,
//! `config-reference`, `healthcheck` and `version` (also `--version` and `-version`).
//!
//! - `stowr [-c <path>] [--print-config]` reads the configuration (`config.hcl` by default), writes the effective
//!   configuration and the warnings in the log, and serves. With `--print-config`, it writes the effective
//!   configuration and exits.
//! - `stowr print-config [-c <path>]` writes the effective configuration and exits. An error gives the status 1.
//! - `stowr healthcheck [-c <path>] [-url <url>]` sends `GET` to the health URL and exits with 0 for the status 200.
//! - `stowr config-reference` writes docs/configuration-reference.md.
//! - `stowr version` writes `stowr <version>`.
//!
//! An error of the flags gives the status 2. `-h` gives the help and the status 0.

use std::io::Write;
use std::process::ExitCode;

use crate::common::config::Config;
use crate::common::time::Timestamp;

use super::flags::{Flag, FlagKind, Stop, parse, usage};
use super::health::{Failure, check, url_from_listen};
use super::{Hooks, format_effective, load_runtime_with, log_start, reference};

const CONFIG_USAGE: &str = "path to the HCL configuration file";
const HEALTH_CONFIG_USAGE: &str = "optional HCL configuration used to derive the health endpoint";
const DEFAULT_CONFIG: &str = "config.hcl";
const DEFAULT_HEALTH_URL: &str = "http://127.0.0.1:8080/healthz";

const MAIN_FLAGS: &[Flag] = &[
    Flag {
        name: "c",
        kind: FlagKind::Text(DEFAULT_CONFIG),
        usage: CONFIG_USAGE,
    },
    Flag {
        name: "config",
        kind: FlagKind::Text(DEFAULT_CONFIG),
        usage: CONFIG_USAGE,
    },
    Flag {
        name: "print-config",
        kind: FlagKind::Bool,
        usage: "check the configuration, write the value and the source of each key, and exit",
    },
];

const PRINT_CONFIG_FLAGS: &[Flag] = &[
    Flag {
        name: "c",
        kind: FlagKind::Text(DEFAULT_CONFIG),
        usage: CONFIG_USAGE,
    },
    Flag {
        name: "config",
        kind: FlagKind::Text(DEFAULT_CONFIG),
        usage: CONFIG_USAGE,
    },
];

const HEALTHCHECK_FLAGS: &[Flag] = &[
    Flag {
        name: "c",
        kind: FlagKind::Text(""),
        usage: HEALTH_CONFIG_USAGE,
    },
    Flag {
        name: "config",
        kind: FlagKind::Text(""),
        usage: HEALTH_CONFIG_USAGE,
    },
    Flag {
        name: "url",
        kind: FlagKind::Text(""),
        usage: "health endpoint URL",
    },
];

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

/// Read the flags of a command. `Err` holds the exit status after the help or the error.
fn read_flags(
    set: &str,
    flags: &[Flag],
    arguments: &[String],
    err: &mut dyn Write,
) -> Result<super::flags::Parsed, u8> {
    match parse(flags, arguments) {
        Ok(parsed) => Ok(parsed),
        Err(Stop::Help) => {
            let _ = err.write_all(usage(set, flags).as_bytes());
            Err(0)
        }
        Err(Stop::Error(message)) => {
            let _ = writeln!(err, "{message}");
            let _ = err.write_all(usage(set, flags).as_bytes());
            Err(2)
        }
    }
}

/// Run the command line until the start of the server.
pub(super) fn execute(arguments: &[String], hooks: &Hooks<'_>, out: &mut dyn Write, err: &mut dyn Write) -> Next {
    let rest = arguments.get(1..).unwrap_or_default();
    match arguments.first().map(String::as_str) {
        Some("healthcheck") => return healthcheck(rest, hooks, err),
        Some("version" | "--version" | "-version") => {
            let _ = writeln!(out, "stowr {}", super::build_info::current().display);
            return Next::Exit(0);
        }
        Some("config-reference") => {
            let _ = out.write_all(reference().as_bytes());
            return Next::Exit(0);
        }
        Some("print-config") => return print_config(rest, hooks, out, err),
        _ => {}
    }
    let parsed = match read_flags("stowr", MAIN_FLAGS, arguments, err) {
        Ok(parsed) => parsed,
        Err(status) => return Next::Exit(status),
    };
    if let Some(argument) = parsed.rest.first() {
        log_to(
            err,
            &format!(
                "unexpected argument {}; use -c <path>, --print-config, healthcheck, print-config, config-reference or version",
                super::quote::quote(argument)
            ),
        );
        return Next::Exit(1);
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

/// Check the configuration, write the value that applies for each key with its source, and exit with status 0. It
/// hides each secret.
fn print_config(arguments: &[String], hooks: &Hooks<'_>, out: &mut dyn Write, err: &mut dyn Write) -> Next {
    let parsed = match read_flags("print-config", PRINT_CONFIG_FLAGS, arguments, err) {
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
fn healthcheck(arguments: &[String], hooks: &Hooks<'_>, err: &mut dyn Write) -> Next {
    let parsed = match read_flags("healthcheck", HEALTHCHECK_FLAGS, arguments, err) {
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
