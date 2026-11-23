//! The URLs of the providers: the base URL of an `auth` block, and the session URL of a GCS resumable upload.
//!
//! The rules of the paths are these. The escaped form of a path keeps the text of the URL when that text is a valid
//! escaped path; else each byte that a path cannot carry becomes `%XX`. A provider URL always uses the escaped form.

use crate::common::query::unescape;
use crate::config::url::Endpoint;

/// The base of the URLs of a provider: the scheme, the host and the path of the endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BaseUrl {
    /// `http` or `https`, in lower case.
    pub scheme: String,
    /// The host and the port as the URL gives them, for example `[::1]:9000`.
    pub authority: String,
    /// The host without the brackets of an IPv6 address.
    pub hostname: String,
    /// The escaped path, possibly empty.
    pub escaped_path: String,
}

impl BaseUrl {
    /// The base URL of a checked endpoint.
    pub fn from_endpoint(endpoint: &Endpoint) -> Self {
        let mut authority = endpoint.host.clone();
        if let Some(port) = endpoint.port {
            authority.push(':');
            authority.push_str(&port.to_string());
        }
        Self {
            scheme: endpoint.scheme.to_ascii_lowercase(),
            hostname: strip_brackets(&endpoint.host).to_owned(),
            authority,
            escaped_path: escaped_path_of(&endpoint.path),
        }
    }

    /// The base URL of an absolute `http` or `https` URL without user information, query or fragment.
    pub fn from_url(raw: &str) -> Result<Self, String> {
        let url = WebUrl::parse(raw)?;
        if url.scheme != "http" && url.scheme != "https" {
            return Err("the scheme must be http or https".to_owned());
        }
        if url.authority.is_empty() || url.has_user || url.has_query || !url.fragment.is_empty() {
            return Err("the URL must have a host and no user information, query or fragment".to_owned());
        }
        Ok(Self {
            hostname: url.hostname().to_owned(),
            scheme: url.scheme,
            authority: url.authority,
            escaped_path: url.escaped_path,
        })
    }

    /// The escaped path without the `/` characters at its end.
    pub fn trimmed_path(&self) -> &str {
        self.escaped_path.trim_end_matches('/')
    }

    /// A full URL: the base, the escaped path that follows the path of the endpoint, and the raw query.
    pub fn join(&self, escaped_suffix: &str, raw_query: &str) -> String {
        let mut out = format!(
            "{}://{}{}{}",
            self.scheme,
            self.authority,
            self.trimmed_path(),
            escaped_suffix
        );
        if !raw_query.is_empty() {
            out.push('?');
            out.push_str(raw_query);
        }
        out
    }
}

fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|rest| rest.split_once(']').map(|(inside, _)| inside))
        .unwrap_or(host)
}

/// True for a byte that an escaped path carries as it is.
fn path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'@'
        )
}

/// True when the text is a valid escaped path: each byte is a path byte, `!'()*[]` or the `%` of an escape.
fn valid_encoded(text: &str) -> bool {
    text.bytes()
        .all(|byte| path_byte(byte) || matches!(byte, b'!' | b'\'' | b'(' | b')' | b'*' | b'[' | b']' | b'%'))
        && unescape(text, false).is_some()
}

/// Escape a decoded path: each byte that is not a path byte becomes `%XX`.
pub fn escape_path(path: &str) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(path.len());
    for &byte in path.as_bytes() {
        if path_byte(byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
        }
    }
    out
}

/// The escaped form of a path that is escaped or decoded.
fn escaped_path_of(path: &str) -> String {
    if valid_encoded(path) {
        path.to_owned()
    } else {
        escape_path(path)
    }
}

/// An absolute URL with its parts: the session URL of a GCS resumable upload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WebUrl {
    /// The scheme in lower case, empty for a relative reference.
    pub scheme: String,
    /// True when the URL has user information.
    pub has_user: bool,
    /// The host and the port as the URL gives them.
    pub authority: String,
    /// The escaped path.
    pub escaped_path: String,
    /// The raw query, without the `?`.
    pub raw_query: String,
    /// True when the URL has a `?`.
    pub has_query: bool,
    /// The fragment, decoded.
    pub fragment: String,
}

impl WebUrl {
    /// Parse a URL or a relative reference. The text of the error tells the reason.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err("invalid control character in URL".to_owned());
        }
        let (rest, fragment) = match raw.split_once('#') {
            Some((rest, fragment)) => {
                let decoded = unescape(fragment, false).ok_or_else(|| "invalid URL escape".to_owned())?;
                (rest, decoded)
            }
            None => (raw, String::new()),
        };
        let mut url = WebUrl {
            fragment,
            ..Self::default()
        };
        let mut rest = rest;
        if let Some((scheme, after)) = split_scheme(rest)? {
            url.scheme = scheme.to_ascii_lowercase();
            rest = after;
        }
        if let Some((before, query)) = rest.split_once('?') {
            url.has_query = true;
            url.raw_query = query.to_owned();
            rest = before;
        }
        if !rest.starts_with('/') && !url.scheme.is_empty() {
            return Err("a URL with a scheme needs an absolute path".to_owned());
        }
        if let Some(after) = rest.strip_prefix("//") {
            let (authority, path) = match after.find('/') {
                Some(index) => after.split_at(index),
                None => (after, ""),
            };
            let host = match authority.rsplit_once('@') {
                Some((_, host)) => {
                    url.has_user = true;
                    host
                }
                None => authority,
            };
            check_host(host)?;
            url.authority = host.to_owned();
            rest = path;
        } else if url.scheme.is_empty() && rest.split('/').next().is_some_and(|first| first.contains(':')) {
            return Err("first path segment in URL cannot contain colon".to_owned());
        }
        let decoded = unescape(rest, false).ok_or_else(|| "invalid URL escape".to_owned())?;
        url.escaped_path = if valid_encoded(rest) {
            rest.to_owned()
        } else {
            escape_path(&decoded)
        };
        Ok(url)
    }

    /// True when the URL has a scheme.
    pub fn is_absolute(&self) -> bool {
        !self.scheme.is_empty()
    }

    /// The host without the port and without the brackets of an IPv6 address.
    pub fn hostname(&self) -> &str {
        if let Some(rest) = self.authority.strip_prefix('[') {
            return rest.split_once(']').map_or(rest, |(inside, _)| inside);
        }
        self.authority
            .rsplit_once(':')
            .map_or(self.authority.as_str(), |(host, _)| host)
    }

    /// Resolve a relative reference against a base URL.
    pub fn resolve_against(self, base: &BaseUrl) -> Self {
        let mut url = self;
        if !url.scheme.is_empty() || !url.authority.is_empty() || url.has_user {
            if url.scheme.is_empty() {
                url.scheme = base.scheme.clone();
            }
            url.escaped_path = resolve_path(&url.escaped_path, "");
            return url;
        }
        url.scheme = base.scheme.clone();
        url.authority = base.authority.clone();
        url.escaped_path = resolve_path(&base.escaped_path, &url.escaped_path);
        url
    }

    /// The text of the URL.
    pub fn text(&self) -> String {
        let mut out = String::new();
        if !self.scheme.is_empty() {
            out.push_str(&self.scheme);
            out.push(':');
        }
        if !self.authority.is_empty() || self.scheme == "http" || self.scheme == "https" {
            out.push_str("//");
            out.push_str(&self.authority);
        }
        if !self.escaped_path.is_empty() && !self.escaped_path.starts_with('/') && !self.authority.is_empty() {
            out.push('/');
        }
        out.push_str(&self.escaped_path);
        if self.has_query || !self.raw_query.is_empty() {
            out.push('?');
            out.push_str(&self.raw_query);
        }
        out
    }
}

/// The scheme of a URL and the rest, or `None` when the text has no scheme.
fn split_scheme(raw: &str) -> Result<Option<(&str, &str)>, String> {
    for (index, byte) in raw.bytes().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if index > 0 => {}
            b':' if index == 0 => return Err("missing protocol scheme".to_owned()),
            b':' => return Ok(Some((&raw[..index], &raw[index + 1..]))),
            _ => return Ok(None),
        }
    }
    Ok(None)
}

/// Check the host and the port of an authority.
fn check_host(host: &str) -> Result<(), String> {
    let port = if let Some(rest) = host.strip_prefix('[') {
        let Some((_, after)) = rest.split_once(']') else {
            return Err("missing ']' in host".to_owned());
        };
        match after {
            "" => None,
            _ => Some(
                after
                    .strip_prefix(':')
                    .ok_or_else(|| "invalid port after host".to_owned())?,
            ),
        }
    } else {
        host.rsplit_once(':').map(|(_, port)| port)
    };
    if let Some(port) = port
        && !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("invalid port {port:?} after host"));
    }
    if unescape(host, false).is_none() {
        return Err("invalid URL escape in host".to_owned());
    }
    Ok(())
}

/// Merge a reference path with a base path and remove the `.` and `..` segments (RFC 3986, section 5.2).
pub fn resolve_path(base: &str, reference: &str) -> String {
    let full = if reference.is_empty() {
        base.to_owned()
    } else if !reference.starts_with('/') {
        let cut = base.rfind('/').map_or(0, |index| index + 1);
        format!("{}{reference}", &base[..cut])
    } else {
        reference.to_owned()
    };
    if full.is_empty() {
        return String::new();
    }
    let mut out = String::from("/");
    let mut first = true;
    let mut last = "";
    for element in full.split('/') {
        last = element;
        if element == "." {
            first = false;
            continue;
        }
        if element == ".." {
            let kept = out[1..].to_owned();
            out = String::from("/");
            match kept.rfind('/') {
                Some(index) => out.push_str(&kept[..index]),
                None => first = true,
            }
        } else {
            if !first {
                out.push('/');
            }
            out.push_str(element);
            first = false;
        }
    }
    if last == "." || last == ".." {
        out.push('/');
    }
    if out.len() > 1 && out.as_bytes()[1] == b'/' {
        out.remove(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(scheme: &str, host: &str, port: Option<u16>, path: &str) -> Endpoint {
        Endpoint {
            scheme: scheme.to_owned(),
            host: host.to_owned(),
            port,
            path: path.to_owned(),
        }
    }

    #[test]
    fn the_base_keeps_the_host_the_port_and_the_escaped_path() {
        let base = BaseUrl::from_endpoint(&endpoint("HTTPS", "[::1]", Some(9000), "/a b/"));
        assert_eq!(base.authority, "[::1]:9000");
        assert_eq!(base.hostname, "::1");
        assert_eq!(base.join("/x", "q=1"), "https://[::1]:9000/a%20b/x?q=1");
        let base = BaseUrl::from_endpoint(&endpoint("http", "example.test", None, "/a%20b"));
        assert_eq!(base.join("/x", ""), "http://example.test/a%20b/x");
    }

    #[test]
    fn dot_segments_are_removed() {
        assert_eq!(resolve_path("/a/b/c", "../d"), "/a/d");
        assert_eq!(resolve_path("/a/b/", "./"), "/a/b/");
        assert_eq!(resolve_path("/a/b", "/x/./y/../z"), "/x/z");
        assert_eq!(resolve_path("/resumable/session-1", ""), "/resumable/session-1");
        assert_eq!(resolve_path("", ""), "");
    }

    #[test]
    fn a_session_url_parses_and_resolves() {
        let url = WebUrl::parse("HTTPS://Storage.googleapis.com:443/upload?upload_id=a%2Fb").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.hostname(), "Storage.googleapis.com");
        assert_eq!(url.text(), "https://Storage.googleapis.com:443/upload?upload_id=a%2Fb");
        let base = BaseUrl::from_endpoint(&endpoint("http", "127.0.0.1", Some(8080), "/base/"));
        let relative = WebUrl::parse("../upload/x?id=1").unwrap().resolve_against(&base);
        assert_eq!(relative.text(), "http://127.0.0.1:8080/upload/x?id=1");
        assert!(WebUrl::parse("http://a b\u{1}").is_err());
        assert!(WebUrl::parse(":nothing").is_err());
        assert!(WebUrl::parse("http://host:port/x").is_err());
        assert!(WebUrl::parse("http://user@host/x").unwrap().has_user);
        assert_eq!(WebUrl::parse("http://host/x#frag").unwrap().fragment, "frag");
    }
}
