//! The flags of the command line: `-name value`, `-name=value`, `--name value` and `--name=value`, a boolean flag
//! without a value, `--` at the end of the flags, and `-h` or `-help` for the help.
//!
//! The flags stop at the first argument that is not a flag. The command line writes the help after each error.

use super::quote::quote;

/// The kind of a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FlagKind {
    /// A text. The command gives the default.
    Text,
    /// A boolean, false by default.
    Bool,
}

/// One flag.
#[derive(Clone, Copy, Debug)]
pub(super) struct Flag {
    pub(super) name: &'static str,
    pub(super) kind: FlagKind,
}

/// A value that the command line gives to a flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Given {
    Text(String),
    Bool(bool),
}

/// The result of the read of the flags.
#[derive(Debug, Default)]
pub(super) struct Parsed {
    /// Each flag that the command line gives, in the order of the command line.
    pub(super) given: Vec<(&'static str, Given)>,
    /// The arguments after the flags.
    pub(super) rest: Vec<String>,
}

impl Parsed {
    /// The last text that the command line gives to one of the names, else the default.
    pub(super) fn text(&self, names: &[&str], default: &str) -> String {
        self.given
            .iter()
            .rev()
            .find_map(|(name, value)| match value {
                Given::Text(text) if names.contains(name) => Some(text.clone()),
                _ => None,
            })
            .unwrap_or_else(|| default.to_owned())
    }

    /// The last value of a boolean flag, else false.
    pub(super) fn boolean(&self, name: &str) -> bool {
        self.given
            .iter()
            .rev()
            .find_map(|(given, value)| match value {
                Given::Bool(value) if *given == name => Some(*value),
                _ => None,
            })
            .unwrap_or(false)
    }
}

/// Why the read of the flags stops.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Stop {
    /// `-h` or `-help`: write the help and exit with status 0.
    Help,
    /// An error: write the message and the help, and exit with status 2.
    Error(String),
}

fn parse_bool(text: &str) -> Option<bool> {
    match text {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Read the flags of the arguments.
pub(super) fn parse(flags: &[Flag], arguments: &[String]) -> Result<Parsed, Stop> {
    let mut parsed = Parsed::default();
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument.len() < 2 || !argument.starts_with('-') {
            break;
        }
        let mut name = &argument[1..];
        if let Some(rest) = name.strip_prefix('-') {
            if rest.is_empty() {
                index += 1;
                break;
            }
            name = rest;
        }
        if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
            return Err(Stop::Error(format!("bad option: {argument}")));
        }
        index += 1;
        let mut value = None;
        if let Some(equal) = name.get(1..).and_then(|tail| tail.find('=')) {
            value = Some(name[equal + 2..].to_owned());
            name = &name[..equal + 1];
        }
        let Some(flag) = flags.iter().find(|flag| flag.name == name) else {
            if name == "help" || name == "h" {
                return Err(Stop::Help);
            }
            return Err(Stop::Error(format!("unknown option: -{name}")));
        };
        match flag.kind {
            FlagKind::Bool => {
                let given = match value {
                    Some(value) => parse_bool(&value).ok_or_else(|| {
                        Stop::Error(format!("the option -{name} takes true or false, not {}", quote(&value)))
                    })?,
                    None => true,
                };
                parsed.given.push((flag.name, Given::Bool(given)));
            }
            FlagKind::Text => {
                let value = match value {
                    Some(value) => value,
                    None => {
                        let Some(next) = arguments.get(index) else {
                            return Err(Stop::Error(format!("the option -{name} needs a value")));
                        };
                        index += 1;
                        next.clone()
                    }
                };
                parsed.given.push((flag.name, Given::Text(value)));
            }
        }
    }
    parsed.rest = arguments.get(index..).unwrap_or_default().to_vec();
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAGS: &[Flag] = &[
        Flag {
            name: "c",
            kind: FlagKind::Text,
        },
        Flag {
            name: "config",
            kind: FlagKind::Text,
        },
        Flag {
            name: "print-config",
            kind: FlagKind::Bool,
        },
    ];

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn each_form_of_a_flag_is_read() {
        let parsed = parse(FLAGS, &args(&["-c", "a.hcl", "--config=b.hcl", "--print-config"])).unwrap();
        assert_eq!(parsed.text(&["c", "config"], "config.hcl"), "b.hcl");
        assert!(parsed.boolean("print-config"));
        assert!(parsed.rest.is_empty());
        let parsed = parse(FLAGS, &args(&["-print-config=false", "--c", "x=y", "extra", "-c", "z"])).unwrap();
        assert!(!parsed.boolean("print-config"));
        assert_eq!(parsed.text(&["c", "config"], "config.hcl"), "x=y");
        assert_eq!(parsed.rest, args(&["extra", "-c", "z"]));
        let parsed = parse(FLAGS, &args(&["--", "-c"])).unwrap();
        assert_eq!(parsed.rest, args(&["-c"]));
        assert_eq!(parsed.text(&["c", "config"], "config.hcl"), "config.hcl");
        let parsed = parse(FLAGS, &args(&["-", "-c"])).unwrap();
        assert_eq!(parsed.rest, args(&["-", "-c"]));
    }

    #[test]
    fn errors_and_help_stop_the_read() {
        assert_eq!(parse(FLAGS, &args(&["-h"])).unwrap_err(), Stop::Help);
        assert_eq!(parse(FLAGS, &args(&["--help=1"])).unwrap_err(), Stop::Help);
        assert_eq!(
            parse(FLAGS, &args(&["-x"])).unwrap_err(),
            Stop::Error("unknown option: -x".to_owned())
        );
        assert_eq!(
            parse(FLAGS, &args(&["-c"])).unwrap_err(),
            Stop::Error("the option -c needs a value".to_owned())
        );
        assert_eq!(
            parse(FLAGS, &args(&["---c"])).unwrap_err(),
            Stop::Error("bad option: ---c".to_owned())
        );
        assert_eq!(
            parse(FLAGS, &args(&["-=c"])).unwrap_err(),
            Stop::Error("bad option: -=c".to_owned())
        );
        assert_eq!(
            parse(FLAGS, &args(&["-print-config=yes"])).unwrap_err(),
            Stop::Error("the option -print-config takes true or false, not \"yes\"".to_owned())
        );
    }
}
