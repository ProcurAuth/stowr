//! The flags of the command line: `-name value`, `-name=value`, `--name value` and `--name=value`, a boolean flag
//! without a value, `--` at the end of the flags, and `-h` or `-help` for the help.
//!
//! The flags stop at the first argument that is not a flag. The help and each error give the list of the flags.

use std::fmt::Write as _;

use super::quote::quote;

/// The kind of a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FlagKind {
    /// A text with its default.
    Text(&'static str),
    /// A boolean, false by default.
    Bool,
}

/// One flag.
#[derive(Clone, Copy, Debug)]
pub(super) struct Flag {
    pub(super) name: &'static str,
    pub(super) kind: FlagKind,
    pub(super) usage: &'static str,
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

/// The help of a set of flags: `Usage of <set>:` and one entry for each flag, in the order of the names.
pub(super) fn usage(set: &str, flags: &[Flag]) -> String {
    let mut sorted: Vec<&Flag> = flags.iter().collect();
    sorted.sort_by_key(|flag| flag.name);
    let mut out = format!("Usage of {set}:\n");
    for flag in sorted {
        let mut line = format!("  -{}", flag.name);
        if let FlagKind::Text(_) = flag.kind {
            line.push_str(" string");
        }
        if line.len() <= 4 {
            line.push('\t');
        } else {
            line.push_str("\n    \t");
        }
        line.push_str(&flag.usage.replace('\n', "\n    \t"));
        if let FlagKind::Text(default) = flag.kind
            && !default.is_empty()
        {
            let _ = write!(line, " (default {})", quote(default));
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
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
            return Err(Stop::Error(format!("bad flag syntax: {argument}")));
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
            return Err(Stop::Error(format!("flag provided but not defined: -{name}")));
        };
        match flag.kind {
            FlagKind::Bool => {
                let given = match value {
                    Some(value) => parse_bool(&value).ok_or_else(|| {
                        Stop::Error(format!(
                            "invalid boolean value {} for -{name}: parse error",
                            quote(&value)
                        ))
                    })?,
                    None => true,
                };
                parsed.given.push((flag.name, Given::Bool(given)));
            }
            FlagKind::Text(_) => {
                let value = match value {
                    Some(value) => value,
                    None => {
                        let Some(next) = arguments.get(index) else {
                            return Err(Stop::Error(format!("flag needs an argument: -{name}")));
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
            kind: FlagKind::Text("config.hcl"),
            usage: "path to the HCL configuration file",
        },
        Flag {
            name: "config",
            kind: FlagKind::Text("config.hcl"),
            usage: "path to the HCL configuration file",
        },
        Flag {
            name: "print-config",
            kind: FlagKind::Bool,
            usage: "check the configuration, write the value and the source of each key, and exit",
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
            Stop::Error("flag provided but not defined: -x".to_owned())
        );
        assert_eq!(
            parse(FLAGS, &args(&["-c"])).unwrap_err(),
            Stop::Error("flag needs an argument: -c".to_owned())
        );
        assert_eq!(
            parse(FLAGS, &args(&["---c"])).unwrap_err(),
            Stop::Error("bad flag syntax: ---c".to_owned())
        );
        assert_eq!(
            parse(FLAGS, &args(&["-=c"])).unwrap_err(),
            Stop::Error("bad flag syntax: -=c".to_owned())
        );
        assert_eq!(
            parse(FLAGS, &args(&["-print-config=yes"])).unwrap_err(),
            Stop::Error("invalid boolean value \"yes\" for -print-config: parse error".to_owned())
        );
    }

    #[test]
    fn the_help_lists_the_flags_in_the_order_of_their_names() {
        assert_eq!(
            usage("stowr", FLAGS),
            "Usage of stowr:\n  -c string\n    \tpath to the HCL configuration file (default \"config.hcl\")\n  -config string\n    \tpath to the HCL configuration file (default \"config.hcl\")\n  -print-config\n    \tcheck the configuration, write the value and the source of each key, and exit\n"
        );
        let short = [Flag {
            name: "v",
            kind: FlagKind::Bool,
            usage: "verbose",
        }];
        assert_eq!(usage("x", &short), "Usage of x:\n  -v\tverbose\n");
    }
}
