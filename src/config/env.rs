//! The only reader of the process environment. The configuration names each variable with an attribute
//! `<name>_env`; the program reads no other variable (scripts/check-invariants.sh checks it).

/// The value of an environment variable that the configuration names, or `None` when it does not exist (or is not
/// valid Unicode).
pub fn lookup(name: &str) -> Option<String> {
    std::env::var(name).ok()
}
