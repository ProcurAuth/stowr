//! The check of the URLs of the configuration: the endpoint of a provider, of an admin API and of the PDP.

use crate::common::error::{Error, Result};

/// The parts of a checked endpoint URL.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Endpoint {
    /// `http` or `https`.
    pub scheme: String,
    /// The host, with the brackets of an IPv6 address.
    pub host: String,
    /// The port, when the URL gives it.
    pub port: Option<u16>,
    /// The path, possibly empty.
    pub path: String,
}

/// Check an endpoint: `http` or `https`, a host, no user information, no query, no fragment.
pub fn parse_endpoint(provider: &str, raw: &str) -> Result<Endpoint> {
    let _ = (provider, raw);
    Err(Error::not_served("the check of the endpoints"))
}
