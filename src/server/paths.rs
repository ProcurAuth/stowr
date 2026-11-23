//! The rules of the paths of the requests: the lexical clean of a path, the escape of a path for a URL, the last
//! element and the extension of a key, and the decode of the escapes of a path.

/// The lexical clean of a slash path: one slash between the elements, no `.` element, no `..` element after a name,
/// no `..` at the root, no slash at the end. An empty path gives `.`.
pub fn clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let rooted = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    // The number of `..` elements at the start of a relative path that stay.
    let mut kept_parents = 0usize;
    for element in path.split('/') {
        match element {
            "" | "." => {}
            ".." => {
                if parts.len() > kept_parents {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                    kept_parents += 1;
                }
            }
            name => parts.push(name),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_owned(),
        (false, false) => joined,
    }
}

/// The clean of the path of a request: a `/` at the start, the lexical clean, and the `/` at the end kept.
pub fn clean_request_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_owned();
    }
    let rooted = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let mut cleaned = clean(&rooted);
    if rooted.ends_with('/') && cleaned != "/" {
        cleaned.push('/');
    }
    cleaned
}

/// The last element of a slash path: the slashes at the end removed. An empty path gives `.` and a path of slashes
/// gives `/`.
pub fn base(path: &str) -> &str {
    if path.is_empty() {
        return ".";
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    match trimmed.rfind('/') {
        Some(index) => &trimmed[index + 1..],
        None => trimmed,
    }
}

/// The extension of the last element of a slash path, with its dot (`.pdf`), or an empty text.
pub fn ext(path: &str) -> &str {
    let bytes = path.as_bytes();
    let mut index = bytes.len();
    while index > 0 {
        index -= 1;
        match bytes[index] {
            b'/' => return "",
            b'.' => return &path[index..],
            _ => {}
        }
    }
    ""
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode the `%XX` escapes of a path. `+` stays. A `%` without two hexadecimal digits gives `None`.
pub fn unescape_bytes(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            out.push(high << 4 | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Some(out)
}

/// True when a byte stays as it is in the path of a URL.
fn path_byte_stays(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'@'
        )
}

/// Escape a path for a URL: letters, digits, `-_.~` and `$&+,/:;=@` stay, each other byte is `%XX`.
pub fn escape_path_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        if path_byte_stays(byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
        }
    }
    out
}

/// True when the text is a valid escaped form: each `%` has two hexadecimal digits, and each other byte stays as it is
/// in a path, or is one of `!*'()` and `[]` that clients send without an escape.
fn valid_escaped_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let digits = (bytes.get(index + 1), bytes.get(index + 2));
            match digits {
                (Some(high), Some(low)) if hex_value(*high).is_some() && hex_value(*low).is_some() => index += 3,
                _ => return false,
            }
            continue;
        }
        if !(path_byte_stays(byte) || matches!(byte, b'!' | b'*' | b'\'' | b'(' | b')' | b'[' | b']')) {
            return false;
        }
        index += 1;
    }
    true
}

/// The escaped form of the path of a request: the raw path as the client sent it when it is a valid escaped form of
/// the decoded path, else the escape of the decoded path.
pub fn escaped_request_path(raw: &str, decoded: &[u8]) -> String {
    if !raw.is_empty()
        && valid_escaped_path(raw)
        && unescape_bytes(raw).is_some_and(|value| value.as_slice() == decoded)
    {
        return raw.to_owned();
    }
    escape_path_bytes(decoded)
}

/// Replace each byte that is not ASCII with `%XX`.
pub fn hex_escape_non_ascii(text: &str) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if byte < 0x80 {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
        }
    }
    out
}

/// Escape the HTML characters `&<>"'`.
pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// A relative prefix: the `/` at the start removed, and one `/` at the end (an empty prefix stays empty).
pub fn normalize_prefix(value: &str) -> String {
    let value = value.trim_start_matches('/');
    if value.is_empty() {
        return String::new();
    }
    format!("{}/", value.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lexical_clean_follows_the_slash_rules() {
        for (input, want) in [
            ("", "."),
            ("/", "/"),
            ("//a//b/", "/a/b"),
            ("/a/./b/../c", "/a/c"),
            ("/../a", "/a"),
            ("a/../../b", "../b"),
            ("./", "."),
            ("/a/b/..", "/a"),
        ] {
            assert_eq!(clean(input), want, "{input:?}");
        }
        assert_eq!(clean_request_path(""), "/");
        assert_eq!(clean_request_path("/a//b/"), "/a/b/");
        assert_eq!(clean_request_path("a"), "/a");
        assert_eq!(clean_request_path("/a/../"), "/");
    }

    #[test]
    fn base_and_extension_of_keys() {
        assert_eq!(base(""), ".");
        assert_eq!(base("///"), "/");
        assert_eq!(base("a/b/c.txt"), "c.txt");
        assert_eq!(base("a/b/"), "b");
        assert_eq!(ext("a/b.tar.gz"), ".gz");
        assert_eq!(ext("a.b/c"), "");
        assert_eq!(ext("name"), "");
    }

    #[test]
    fn escaped_path_keeps_the_valid_form_of_the_client() {
        assert_eq!(escaped_request_path("/api/li%73t", b"/api/list"), "/api/li%73t");
        assert_eq!(escaped_request_path("/a b", b"/a b"), "/a%20b");
        assert_eq!(escape_path_bytes("/a?b%c d".as_bytes()), "/a%3Fb%25c%20d");
        assert_eq!(normalize_prefix("//a//"), "a/");
        assert_eq!(normalize_prefix("/"), "");
    }
}
