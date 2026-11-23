// SPDX-License-Identifier: MIT OR Apache-2.0
//! The check of the URLs of the configuration: the endpoint of a provider, of an admin API and of the PDP, and the
//! host and port of `server.listen`.
//!
//! [`parse`] reads a URL with the rules of RFC 3986 of the program: the scheme in lower case, the
//! user information, the host with its port, the path with its escapes, the query and the fragment. It refuses a
//! control character, a bad escape, a bad port and a host with a character that a host cannot have.

use crate::common::error::{Error, Result};

use super::quote::quote;

/// The parts of a checked endpoint URL.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Endpoint {
    /// `http` or `https`.
    pub scheme: String,
    /// The host, with the brackets of an IPv6 address.
    pub host: String,
    /// The port, when the URL gives it.
    pub port: Option<u16>,
    /// The path after its escapes, possibly empty.
    pub path: String,
    /// The path with its escapes, as a request writes it, possibly empty.
    pub escaped_path: String,
    /// The host and the port as the URL writes them, for example `garage:3903` (the `Host` header).
    pub authority: String,
}

impl Endpoint {
    /// The host without the brackets of an IPv6 address.
    pub fn hostname(&self) -> &str {
        self.host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(&self.host)
    }
}

/// Check an endpoint: `http` or `https`, a host, no user information, no query, no fragment. `provider` names the
/// endpoint in the message, for example `s3 endpoint scheme must be http or https`.
pub fn parse_endpoint(provider: &str, raw: &str) -> Result<Endpoint> {
    let url = parse(raw).map_err(|error| Error::internal(format!("invalid {provider} endpoint: {error}")))?;
    if url.scheme != "http" && url.scheme != "https" {
        return Err(Error::internal(format!(
            "{provider} endpoint scheme must be http or https"
        )));
    }
    if url.host.is_empty() {
        return Err(Error::internal(format!("{provider} endpoint must include a host")));
    }
    if url.user.is_some() {
        return Err(Error::internal(format!(
            "{provider} endpoint must not contain user information"
        )));
    }
    if !url.raw_query.is_empty() || url.force_query || !url.fragment.is_empty() {
        return Err(Error::internal(format!(
            "{provider} endpoint must not contain a query string or fragment"
        )));
    }
    let (host, port_text) = match url.host.rfind(':') {
        Some(colon) if valid_optional_port(&url.host[colon..]) => (&url.host[..colon], &url.host[colon + 1..]),
        _ => (url.host.as_str(), ""),
    };
    let port = if port_text.is_empty() {
        None
    } else {
        Some(port_text.parse::<u16>().map_err(|_| {
            Error::internal(format!(
                "{provider} endpoint port must be an integer between 0 and 65535"
            ))
        })?)
    };
    let escaped_path = url.escaped_path();
    let host = host.to_owned();
    Ok(Endpoint {
        scheme: url.scheme,
        host,
        port,
        path: url.path,
        escaped_path,
        authority: url.host,
    })
}

/// The user information of a URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserInfo {
    /// The user name.
    pub username: String,
    /// The password, when the URL gives one.
    pub password: Option<String>,
}

/// The parts of a URL.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Url {
    /// The scheme, in lower case.
    pub scheme: String,
    /// The opaque part of a URL without `//` after the scheme.
    pub opaque: String,
    /// The user information.
    pub user: Option<UserInfo>,
    /// The host and the port, as the URL writes them (after the escapes).
    pub host: String,
    /// The path after its escapes.
    pub path: String,
    /// The path with its escapes, when it differs from the default escapes of `path`.
    pub raw_path: String,
    /// True when the URL ends with a `?` and has no query.
    pub force_query: bool,
    /// The query, without `?`.
    pub raw_query: String,
    /// The fragment after its escapes.
    pub fragment: String,
}

impl Url {
    /// The host without the port and without the brackets of an IPv6 address.
    pub fn hostname(&self) -> &str {
        split_url_host_port(&self.host).0
    }

    /// The port, or an empty text.
    pub fn port(&self) -> &str {
        split_url_host_port(&self.host).1
    }

    /// The path with its escapes.
    pub fn escaped_path(&self) -> String {
        if !self.raw_path.is_empty()
            && valid_encoded(&self.raw_path, Mode::Path)
            && let Ok(path) = unescape(&self.raw_path, Mode::Path)
            && path == self.path
        {
            return self.raw_path.clone();
        }
        if self.path == "*" {
            return "*".to_owned();
        }
        escape(&self.path, Mode::Path)
    }
}

/// The host and the port of the host part of a URL. A port that is not digits stays in the host.
fn split_url_host_port(host_port: &str) -> (&str, &str) {
    let mut host = host_port;
    let mut port = "";
    if let Some(colon) = host.rfind(':')
        && valid_optional_port(&host[colon..])
    {
        port = &host[colon + 1..];
        host = &host[..colon];
    }
    if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
        host = &host[1..host.len() - 1];
    }
    (host, port)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Path,
    Host,
    Zone,
    UserPassword,
    Fragment,
}

fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if (mode == Mode::Host || mode == Mode::Zone)
        && matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            Mode::Path => return c == b'?',
            Mode::UserPassword => return c == b'@' || c == b'/' || c == b'?' || c == b':',
            Mode::Fragment => return false,
            Mode::Host | Mode::Zone => {}
        },
        _ => {}
    }
    if mode == Mode::Fragment && matches!(c, b'!' | b'(' | b')' | b'*') {
        return false;
    }
    true
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn unescape(text: &str, mode: Mode) -> std::result::Result<String, String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let valid = index + 2 < bytes.len()
                    && hex_digit(bytes[index + 1]).is_some()
                    && hex_digit(bytes[index + 2]).is_some();
                if !valid {
                    let end = (index + 3).min(bytes.len());
                    return Err(format!(
                        "invalid percent escape {}",
                        super::quote::quote_bytes(&bytes[index..end])
                    ));
                }
                let escaped = &bytes[index..index + 3];
                let high = hex_digit(bytes[index + 1]).unwrap_or(0);
                let low = hex_digit(bytes[index + 2]).unwrap_or(0);
                if mode == Mode::Host && high < 8 && escaped != b"%25" {
                    return Err(format!("invalid percent escape {}", super::quote::quote_bytes(escaped)));
                }
                if mode == Mode::Zone {
                    let value = (high << 4) | low;
                    if escaped != b"%25" && value != b' ' && should_escape(value, Mode::Host) {
                        return Err(format!("invalid percent escape {}", super::quote::quote_bytes(escaped)));
                    }
                }
                index += 3;
            }
            byte => {
                if (mode == Mode::Host || mode == Mode::Zone) && byte < 0x80 && should_escape(byte, mode) {
                    return Err(format!(
                        "the host name has the character {}",
                        super::quote::quote_bytes(&[byte])
                    ));
                }
                index += 1;
            }
        }
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_digit(bytes[index + 1]).unwrap_or(0);
            let low = hex_digit(bytes[index + 2]).unwrap_or(0);
            out.push((high << 4) | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn escape(text: &str, mode: Mode) -> String {
    const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if should_escape(byte, mode) {
            out.push('%');
            out.push(char::from(UPPER_HEX[usize::from(byte >> 4)]));
            out.push(char::from(UPPER_HEX[usize::from(byte & 0xf)]));
        } else {
            out.push(char::from(byte));
        }
    }
    out
}

fn valid_encoded(text: &str, mode: Mode) -> bool {
    text.bytes().all(|byte| {
        matches!(
            byte,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'['
                | b']'
                | b'%'
        ) || !should_escape(byte, mode)
    })
}

fn valid_optional_port(port: &str) -> bool {
    if port.is_empty() {
        return true;
    }
    match port.strip_prefix(':') {
        Some(digits) => digits.bytes().all(|byte| byte.is_ascii_digit()),
        None => false,
    }
}

fn valid_userinfo(text: &str) -> bool {
    text.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '-' | '.'
                    | '_'
                    | ':'
                    | '~'
                    | '!'
                    | '$'
                    | '&'
                    | '\''
                    | '('
                    | ')'
                    | '*'
                    | '+'
                    | ','
                    | ';'
                    | '='
                    | '%'
                    | '@'
            )
    })
}

fn get_scheme(raw: &str) -> std::result::Result<(&str, &str), String> {
    for (index, byte) in raw.bytes().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if index == 0 {
                    return Ok(("", raw));
                }
            }
            b':' => {
                if index == 0 {
                    return Err("no scheme".to_owned());
                }
                return Ok((&raw[..index], &raw[index + 1..]));
            }
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

fn parse_host(host: &str) -> std::result::Result<String, String> {
    if host.starts_with('[') {
        let Some(close) = host.rfind(']') else {
            return Err("no closing ']' in the host".to_owned());
        };
        let colon_port = &host[close + 1..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {}", quote(colon_port)));
        }
        if let Some(zone) = host[..close].find("%25") {
            let first = unescape(&host[..zone], Mode::Host)?;
            let second = unescape(&host[zone..close], Mode::Zone)?;
            let third = unescape(&host[close..], Mode::Host)?;
            return Ok(first + &second + &third);
        }
    } else if let Some(colon) = host.rfind(':') {
        let colon_port = &host[colon..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {}", quote(colon_port)));
        }
    }
    unescape(host, Mode::Host)
}

fn parse_authority(authority: &str) -> std::result::Result<(Option<UserInfo>, String), String> {
    let at = authority.rfind('@');
    let host = match at {
        Some(index) => parse_host(&authority[index + 1..])?,
        None => parse_host(authority)?,
    };
    let Some(index) = at else {
        return Ok((None, host));
    };
    let userinfo = &authority[..index];
    if !valid_userinfo(userinfo) {
        return Err("invalid user information".to_owned());
    }
    let user = match userinfo.split_once(':') {
        None => UserInfo {
            username: unescape(userinfo, Mode::UserPassword)?,
            password: None,
        },
        Some((username, password)) => UserInfo {
            username: unescape(username, Mode::UserPassword)?,
            password: Some(unescape(password, Mode::UserPassword)?),
        },
    };
    Ok((Some(user), host))
}

fn parse_without_fragment(raw: &str) -> std::result::Result<Url, String> {
    if raw.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err("the URL has a control character".to_owned());
    }
    let mut url = Url::default();
    if raw == "*" {
        url.path = "*".to_owned();
        return Ok(url);
    }
    let (scheme, rest) = get_scheme(raw)?;
    url.scheme = scheme.to_ascii_lowercase();
    let mut rest = rest;
    if rest.ends_with('?') && rest.matches('?').count() == 1 {
        url.force_query = true;
        rest = &rest[..rest.len() - 1];
    } else if let Some((before, query)) = rest.split_once('?') {
        url.raw_query = query.to_owned();
        rest = before;
    }
    if !rest.starts_with('/') {
        if !url.scheme.is_empty() {
            url.opaque = rest.to_owned();
            return Ok(url);
        }
        let segment = rest.split('/').next().unwrap_or_default();
        if segment.contains(':') {
            return Err("the first segment of the path has a colon".to_owned());
        }
    }
    let mut path = rest;
    if (!url.scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let authority_and_path = &rest[2..];
        let (authority, remaining) = match authority_and_path.find('/') {
            Some(index) => (&authority_and_path[..index], &authority_and_path[index..]),
            None => (authority_and_path, ""),
        };
        let (user, host) = parse_authority(authority)?;
        url.user = user;
        url.host = host;
        path = remaining;
    }
    url.path = unescape(path, Mode::Path)?;
    if escape(&url.path, Mode::Path) != path {
        url.raw_path = path.to_owned();
    }
    Ok(url)
}

/// Read a URL. The error is `invalid URL "<raw>": <cause>`.
pub fn parse(raw: &str) -> std::result::Result<Url, String> {
    let (without_fragment, fragment) = match raw.split_once('#') {
        Some((before, after)) => (before, Some(after)),
        None => (raw, None),
    };
    let mut url = parse_without_fragment(without_fragment)
        .map_err(|cause| format!("invalid URL {}: {cause}", quote(without_fragment)))?;
    if let Some(fragment) = fragment
        && !fragment.is_empty()
    {
        url.fragment =
            unescape(fragment, Mode::Fragment).map_err(|cause| format!("invalid URL {}: {cause}", quote(raw)))?;
    }
    Ok(url)
}

/// Split `host:port`, as the listener and the clients read an address. The error is `address <value>: <cause>`.
pub fn split_host_port(host_port: &str) -> std::result::Result<(&str, &str), String> {
    let error = |cause: &str| format!("address {host_port}: {cause}");
    let Some(last_colon) = host_port.rfind(':') else {
        return Err(error("no port in the address"));
    };
    let (host, open_from, close_from);
    if host_port.starts_with('[') {
        let Some(end) = host_port.find(']') else {
            return Err(error("no closing ']' in the address"));
        };
        if end + 1 == host_port.len() {
            return Err(error("no port in the address"));
        } else if end + 1 != last_colon {
            if host_port.as_bytes().get(end + 1) == Some(&b':') {
                return Err(error("too many colons in the address"));
            }
            return Err(error("no port in the address"));
        }
        host = &host_port[1..end];
        open_from = 1;
        close_from = end + 1;
    } else {
        host = &host_port[..last_colon];
        if host.contains(':') {
            return Err(error("too many colons in the address"));
        }
        open_from = 0;
        close_from = 0;
    }
    if host_port[open_from..].contains('[') {
        return Err(error("an unexpected '[' in the address"));
    }
    if host_port[close_from..].contains(']') {
        return Err(error("unexpected ']' in address"));
    }
    Ok((host, &host_port[last_colon + 1..]))
}

/// Join a host and a port. A host with a `:` (an IPv6 address) gets brackets.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_with_credentials_a_query_or_a_fragment_are_refused() {
        for raw in [
            "ftp://example.test",
            "https://user:secret@example.test",
            "https://example.test?mode=test",
            "https://example.test/#fragment",
        ] {
            assert!(parse_endpoint("s3", raw).is_err(), "{raw}");
        }
        let endpoint = parse_endpoint("gcs", "https://example.test/emulator/v1").unwrap();
        assert_eq!(endpoint.path, "/emulator/v1");
        assert_eq!(endpoint.escaped_path, "/emulator/v1");
        assert_eq!(endpoint.scheme, "https");
        assert_eq!(endpoint.host, "example.test");
        assert_eq!(endpoint.port, None);
    }

    #[test]
    fn endpoint_errors_name_the_provider() {
        let message = |provider: &str, raw: &str| parse_endpoint(provider, raw).unwrap_err().to_string();
        assert_eq!(message("s3", "ftp://x"), "s3 endpoint scheme must be http or https");
        assert_eq!(message("s3", "http://"), "s3 endpoint must include a host");
        assert_eq!(
            message("usage", "http://u:p@h"),
            "usage endpoint must not contain user information"
        );
        assert_eq!(
            message("usage", "http://h?a=b"),
            "usage endpoint must not contain a query string or fragment"
        );
        assert_eq!(
            message("usage", "http://h#a"),
            "usage endpoint must not contain a query string or fragment"
        );
        assert_eq!(
            message("usage", "http://h?"),
            "usage endpoint must not contain a query string or fragment"
        );
        assert_eq!(
            message("s3", "http://h:port"),
            "invalid s3 endpoint: invalid URL \"http://h:port\": invalid port \":port\""
        );
        assert_eq!(
            message("s3", "1host:9000"),
            "invalid s3 endpoint: invalid URL \"1host:9000\": the first segment of the path has a colon"
        );
        assert_eq!(
            message("s3", "localhost:9000"),
            "s3 endpoint scheme must be http or https"
        );
        assert_eq!(message("s3", "localhost"), "s3 endpoint scheme must be http or https");
        assert_eq!(
            message("s3", "http://h\n"),
            "invalid s3 endpoint: invalid URL \"http://h\\n\": the URL has a control character"
        );
        assert_eq!(
            message("s3", "http://h h"),
            "invalid s3 endpoint: invalid URL \"http://h h\": the host name has the character \" \""
        );
        assert_eq!(
            message("s3", "http://h/%zz"),
            "invalid s3 endpoint: invalid URL \"http://h/%zz\": invalid percent escape \"%zz\""
        );
    }

    #[test]
    fn endpoint_parts_keep_the_port_and_the_escapes() {
        let endpoint = parse_endpoint("s3", "http://[::1]:9000/base%20x/a%2Fb").unwrap();
        assert_eq!(endpoint.host, "[::1]");
        assert_eq!(endpoint.hostname(), "::1");
        assert_eq!(endpoint.port, Some(9000));
        assert_eq!(endpoint.authority, "[::1]:9000");
        assert_eq!(endpoint.path, "/base x/a/b");
        assert_eq!(endpoint.escaped_path, "/base%20x/a%2Fb");
        let endpoint = parse_endpoint("usage", "HTTP://garage:3903").unwrap();
        assert_eq!(endpoint.scheme, "http");
        assert_eq!(endpoint.authority, "garage:3903");
        assert_eq!(endpoint.path, "");
    }

    #[test]
    fn urls_give_their_parts() {
        let url = parse("https://user:pass@pdp.example:4182/base?x=1#top").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(
            url.user,
            Some(UserInfo {
                username: "user".to_owned(),
                password: Some("pass".to_owned())
            })
        );
        assert_eq!(url.host, "pdp.example:4182");
        assert_eq!(url.hostname(), "pdp.example");
        assert_eq!(url.port(), "4182");
        assert_eq!(url.path, "/base");
        assert_eq!(url.raw_query, "x=1");
        assert_eq!(url.fragment, "top");
        assert!(parse("https://:4182").unwrap().hostname().is_empty());
        assert!(parse("https://h?").unwrap().force_query);
        assert_eq!(
            parse("1pdp.example:4182").unwrap_err(),
            "invalid URL \"1pdp.example:4182\": the first segment of the path has a colon"
        );
        let opaque = parse("pdp.example:4182").unwrap();
        assert_eq!(
            (opaque.scheme.as_str(), opaque.opaque.as_str()),
            ("pdp.example", "4182")
        );
        assert_eq!(parse(":x").unwrap_err(), "invalid URL \":x\": no scheme");
        assert_eq!(
            parse("http://[::1").unwrap_err(),
            "invalid URL \"http://[::1\": no closing ']' in the host"
        );
        assert_eq!(
            parse("http://a b@h").unwrap_err(),
            "invalid URL \"http://a b@h\": invalid user information"
        );
    }

    #[test]
    fn host_and_port_are_split_as_the_listener_reads_them() {
        assert_eq!(split_host_port(":8080"), Ok(("", "8080")));
        assert_eq!(split_host_port("0.0.0.0:80"), Ok(("0.0.0.0", "80")));
        assert_eq!(split_host_port("[::]:8080"), Ok(("::", "8080")));
        assert_eq!(
            split_host_port("localhost"),
            Err("address localhost: no port in the address".to_owned())
        );
        assert_eq!(
            split_host_port("a:b:c"),
            Err("address a:b:c: too many colons in the address".to_owned())
        );
        assert_eq!(
            split_host_port("[::1]"),
            Err("address [::1]: no port in the address".to_owned())
        );
        assert_eq!(
            split_host_port("[::1]x:80"),
            Err("address [::1]x:80: no port in the address".to_owned())
        );
        assert_eq!(
            split_host_port("[::1]:8:80"),
            Err("address [::1]:8:80: too many colons in the address".to_owned())
        );
        assert_eq!(
            split_host_port("[a:80"),
            Err("address [a:80: no closing ']' in the address".to_owned())
        );
        assert_eq!(
            split_host_port("a]:80"),
            Err("address a]:80: unexpected ']' in address".to_owned())
        );
        assert_eq!(
            split_host_port("a[:80"),
            Err("address a[:80: an unexpected '[' in the address".to_owned())
        );
        assert_eq!(join_host_port("::1", "80"), "[::1]:80");
        assert_eq!(join_host_port("127.0.0.1", "80"), "127.0.0.1:80");
    }
}
