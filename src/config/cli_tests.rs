//! The tests of the command line: the commands, the flags, the exit statuses, print-config and the health check.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;

use super::cli::{Next, execute};
use super::support_tests::{TempDir, minimal_test_config, test_hooks};
use super::{format_effective, reference};

struct Outcome {
    status: Option<u8>,
    out: String,
    err: String,
}

fn run(arguments: &[&str]) -> Outcome {
    let arguments: Vec<String> = arguments.iter().map(|argument| (*argument).to_owned()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = match execute(&arguments, &test_hooks(), &mut out, &mut err) {
        Next::Exit(status) => Some(status),
        Next::Serve(_) => None,
    };
    Outcome {
        status,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

/// The text of a log line without its date and time.
fn log_text(line: &str) -> &str {
    line.splitn(3, ' ').nth(2).unwrap_or_default().trim_end()
}

const MAIN_USAGE: &str = "Usage of stowr:\n  -c string\n    \tpath to the HCL configuration file (default \"config.hcl\")\n  -config string\n    \tpath to the HCL configuration file (default \"config.hcl\")\n  -print-config\n    \tcheck the configuration, write the value and the source of each key, and exit\n";

#[test]
fn version_writes_the_identity_of_the_build() {
    for command in ["version", "--version", "-version"] {
        let outcome = run(&[command]);
        assert_eq!(outcome.status, Some(0));
        assert_eq!(outcome.out, format!("stowr {}\n", super::build_info::current().display));
    }
}

#[test]
fn config_reference_writes_the_reference() {
    let outcome = run(&["config-reference"]);
    assert_eq!(outcome.status, Some(0));
    assert_eq!(outcome.out, reference());
}

#[test]
fn print_config_writes_the_effective_configuration() {
    let dir = TempDir::new();
    dir.write("config.hcl", minimal_test_config("b"));
    let config = super::load_with(&dir.path().join("config.hcl"), &test_hooks()).unwrap();
    let path = dir.join("config.hcl");
    let equal = format!("--config={path}");
    for arguments in [
        vec!["print-config", "-c", path.as_str()],
        vec!["print-config", "--config", path.as_str()],
        vec!["-c", path.as_str(), "--print-config"],
        vec![equal.as_str(), "-print-config=true"],
    ] {
        let outcome = run(&arguments);
        assert_eq!(outcome.status, Some(0), "{arguments:?}: {}", outcome.err);
        assert_eq!(outcome.out, format_effective(&config));
        assert_eq!(outcome.err, "");
    }
}

#[test]
fn print_config_errors_exit_with_status_1() {
    let dir = TempDir::new();
    let path = dir.join("missing.hcl");
    let outcome = run(&["print-config", "-c", &path]);
    assert_eq!(outcome.status, Some(1));
    assert_eq!(outcome.out, "");
    assert_eq!(
        outcome.err,
        format!("configuration error: read configuration \"{path}\": open {path}: no such file or directory\n")
    );
    let outcome = run(&["print-config", "-c", ""]);
    assert_eq!(
        outcome.err,
        "configuration error: configuration path is required; use -c <path> or --config <path>\n"
    );
    let outcome = run(&["print-config", "-x"]);
    assert_eq!(outcome.status, Some(2));
    assert!(
        outcome
            .err
            .starts_with("flag provided but not defined: -x\nUsage of print-config:\n  -c string\n")
    );
}

#[test]
fn the_server_starts_without_print_config() {
    let dir = TempDir::new();
    dir.write("config.hcl", minimal_test_config("b"));
    let outcome = run(&["-c", &dir.join("config.hcl")]);
    assert_eq!(outcome.status, None);
    assert_eq!(outcome.out, "");
    let outcome = run(&["--print-config=false", "--c", &dir.join("config.hcl")]);
    assert_eq!(outcome.status, None);
}

#[test]
fn errors_of_the_main_command() {
    let outcome = run(&["serve"]);
    assert_eq!(outcome.status, Some(1));
    assert_eq!(
        log_text(&outcome.err),
        "unexpected argument \"serve\"; use -c <path>, --print-config, healthcheck, print-config, config-reference or version"
    );
    let outcome = run(&["-x"]);
    assert_eq!(outcome.status, Some(2));
    assert_eq!(outcome.err, format!("flag provided but not defined: -x\n{MAIN_USAGE}"));
    let outcome = run(&["-c"]);
    assert_eq!(outcome.status, Some(2));
    assert_eq!(outcome.err, format!("flag needs an argument: -c\n{MAIN_USAGE}"));
    let outcome = run(&["-h"]);
    assert_eq!(outcome.status, Some(0));
    assert_eq!(outcome.err, MAIN_USAGE);
    let dir = TempDir::new();
    let path = dir.join("config.hcl");
    let outcome = run(&["-c", &path]);
    assert_eq!(outcome.status, Some(1));
    assert_eq!(
        log_text(&outcome.err),
        format!("read configuration \"{path}\": open {path}: no such file or directory")
    );
}

/// A server of one connection: it reads the request and answers with the status. It gives the address and the
/// request that it read.
fn one_answer(status: &'static str) -> (String, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        let answer = format!("HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        stream.write_all(answer.as_bytes()).unwrap();
        String::from_utf8(request).unwrap()
    });
    (address, handle)
}

#[test]
fn the_health_check_expects_the_status_200() {
    let (address, server) = one_answer("200 OK");
    let outcome = run(&["healthcheck", "-url", &format!("http://{address}/healthz")]);
    assert_eq!(outcome.status, Some(0), "{}", outcome.err);
    let request = server.join().unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /healthz http/1.1\r\n"), "{request}");
    assert!(request.contains(&format!("host: {address}\r\n")), "{request}");

    let (address, server) = one_answer("503 Service Unavailable");
    let outcome = run(&["healthcheck", "--url", &format!("http://{address}/healthz")]);
    server.join().unwrap();
    assert_eq!(outcome.status, Some(1));
    assert_eq!(outcome.err, "healthcheck failed: HTTP 503\n");

    let (address, server) = one_answer("301 Moved Permanently");
    let outcome = run(&["healthcheck", "--url", &format!("http://{address}/healthz")]);
    server.join().unwrap();
    assert_eq!(outcome.err, "healthcheck failed: HTTP 301\n");
}

#[test]
fn the_health_check_reads_the_listen_address_of_the_configuration() {
    let (address, server) = one_answer("200 OK");
    let dir = TempDir::new();
    dir.write(
        "config.hcl",
        format!("server {{ listen = \"{address}\" }}\n{}", minimal_test_config("b")),
    );
    let outcome = run(&["healthcheck", "-c", &dir.join("config.hcl")]);
    assert_eq!(outcome.status, Some(0), "{}", outcome.err);
    server.join().unwrap();
    let outcome = run(&["healthcheck", "-c", &dir.join("missing.hcl")]);
    assert_eq!(outcome.status, Some(1));
    assert!(
        outcome.err.starts_with("healthcheck config: read configuration "),
        "{}",
        outcome.err
    );
}

#[test]
fn a_health_check_without_a_server_fails() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    let url = format!("http://{address}/healthz");
    let outcome = run(&["healthcheck", "-url", &url]);
    assert_eq!(outcome.status, Some(1));
    assert_eq!(
        outcome.err,
        format!("healthcheck failed: Get \"{url}\": cannot connect to {address}: connection refused\n")
    );
    let outcome = run(&["healthcheck", "-url", "http://127.0.0.1:x/"]);
    assert_eq!(
        outcome.err,
        "healthcheck request: parse \"http://127.0.0.1:x/\": invalid port \":x\" after host\n"
    );
    let outcome = run(&["healthcheck", "-h"]);
    assert_eq!(outcome.status, Some(0));
    assert_eq!(
        outcome.err,
        "Usage of healthcheck:\n  -c string\n    \toptional HCL configuration used to derive the health endpoint\n  -config string\n    \toptional HCL configuration used to derive the health endpoint\n  -url string\n    \thealth endpoint URL\n"
    );
}
