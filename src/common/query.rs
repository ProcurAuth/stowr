// SPDX-License-Identifier: MIT OR Apache-2.0
//! The query string of a request, and the escape rules of URLs.
//!
//! [`Query::parse`] reads a raw query as the routes always read it: the parts split at `&`, each part splits at
//! its first `=`, `+` is a space, `%XX` is a byte. A part with `;` or with a bad escape is left out, and the other
//! parts stay. The order of the values of one name stays.

/// The parsed query of a request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    pairs: Vec<(String, String)>,
}

impl Query {
    /// Parse a raw query (the text after `?`, without the fragment).
    pub fn parse(raw: &str) -> Self {
        let mut pairs = Vec::new();
        for part in raw.split('&') {
            if part.is_empty() || part.contains(';') {
                continue;
            }
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            let (Some(name), Some(value)) = (unescape(name, true), unescape(value, true)) else {
                continue;
            };
            pairs.push((name, value));
        }
        Self { pairs }
    }

    /// The first value of a name, or an empty text.
    pub fn get(&self, name: &str) -> &str {
        self.pairs
            .iter()
            .find(|(key, _)| key == name)
            .map_or("", |(_, value)| value.as_str())
    }

    /// Each value of a name, in order.
    pub fn values(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// True when the name is in the query, also with an empty value.
    pub fn has(&self, name: &str) -> bool {
        self.pairs.iter().any(|(key, _)| key == name)
    }

    /// Each name and value, in order.
    pub fn pairs(&self) -> &[(String, String)] {
        &self.pairs
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode `%XX` escapes (and `+` as a space when `plus_is_space`). A bad escape or bytes that are not UTF-8 give
/// `None`.
pub fn unescape(text: &str, plus_is_space: bool) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = hex_value(*bytes.get(index + 1)?)?;
                let low = hex_value(*bytes.get(index + 2)?)?;
                out.push(high << 4 | low);
                index += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn escape_with(text: &str, keep: impl Fn(u8) -> bool, space_as_plus: bool) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || keep(byte) {
            out.push(char::from(byte));
        } else if byte == b' ' && space_as_plus {
            out.push('+');
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
        }
    }
    out
}

/// Escape a value of a query: letters, digits and `-_.~` stay, a space is `+`, each other byte is `%XX`.
pub fn query_escape(text: &str) -> String {
    escape_with(text, |byte| matches!(byte, b'-' | b'_' | b'.' | b'~'), true)
}

/// Escape one part of a path: letters, digits and `-_.~$&+:=@` stay, each other byte is `%XX`.
pub fn path_escape(text: &str) -> String {
    escape_with(
        text,
        |byte| {
            matches!(
                byte,
                b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b':' | b'=' | b'@'
            )
        },
        false,
    )
}

/// Encode pairs as a query, in the order of the names (`a=1&b=2`).
pub fn encode_sorted(pairs: &[(&str, &str)]) -> String {
    let mut sorted: Vec<(&str, &str)> = pairs.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(right.0));
    sorted
        .iter()
        .map(|(name, value)| format!("{}={}", query_escape(name), query_escape(value)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keeps_the_good_parts_only() {
        let query = Query::parse("key=a%2Fb+c&bad=%zz&semi=a;b&key=second&flag");
        assert_eq!(query.get("key"), "a/b c");
        assert_eq!(query.values("key"), vec!["a/b c", "second"]);
        assert!(!query.has("bad"));
        assert!(!query.has("semi"));
        assert!(query.has("flag"));
        assert_eq!(query.get("missing"), "");
    }

    #[test]
    fn escapes() {
        assert_eq!(query_escape("a b/c~"), "a+b%2Fc~");
        assert_eq!(path_escape("a b/c"), "a%20b%2Fc");
        assert_eq!(encode_sorted(&[("b", "2"), ("a", "x y")]), "a=x+y&b=2");
    }
}
