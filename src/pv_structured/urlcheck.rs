//! The check of the URIs of the alternative names of a certificate. A URI is valid when a strict URL reader
//! accepts it and its host has valid labels.

/// How a part of a URL is unescaped.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Host,
    Zone,
    Other,
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn unhex(byte: u8) -> u8 {
    (byte as char).to_digit(16).map_or(0, |digit| digit as u8)
}

/// True when a byte below 0x80 must be written as an escape in a host.
fn should_escape_in_host(byte: u8) -> bool {
    if byte.is_ascii_alphanumeric() {
        return false;
    }
    !matches!(
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
            | b'['
            | b']'
            | b'<'
            | b'>'
            | b'"'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
    )
}

/// Decode the escapes of a text. `None` for an escape that is not valid in the mode.
fn unescape(text: &[u8], mode: Mode) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        let byte = text[index];
        if byte == b'%' {
            if index + 2 >= text.len() || !is_hex(text[index + 1]) || !is_hex(text[index + 2]) {
                return None;
            }
            let is_percent = text[index + 1] == b'2' && text[index + 2] == b'5';
            if mode == Mode::Host && unhex(text[index + 1]) < 8 && !is_percent {
                return None;
            }
            let value = unhex(text[index + 1]) << 4 | unhex(text[index + 2]);
            if mode == Mode::Zone && !is_percent && value != b' ' && value < 0x80 && should_escape_in_host(value) {
                return None;
            }
            out.push(value);
            index += 3;
            continue;
        }
        if matches!(mode, Mode::Host | Mode::Zone) && byte < 0x80 && should_escape_in_host(byte) {
            return None;
        }
        out.push(byte);
        index += 1;
    }
    Some(out)
}

fn valid_optional_port(port: &[u8]) -> bool {
    match port.split_first() {
        None => true,
        Some((b':', digits)) => digits.iter().all(u8::is_ascii_digit),
        Some(_) => false,
    }
}

/// Read the host of an authority.
fn parse_host(host: &[u8]) -> Option<Vec<u8>> {
    if host.first() == Some(&b'[') {
        let close = host.iter().rposition(|byte| *byte == b']')?;
        if !valid_optional_port(&host[close + 1..]) {
            return None;
        }
        if let Some(zone) = host[..close].windows(3).position(|window| window == b"%25") {
            let mut out = unescape(&host[..zone], Mode::Host)?;
            out.extend(unescape(&host[zone..close], Mode::Zone)?);
            out.extend(unescape(&host[close..], Mode::Host)?);
            return Some(out);
        }
    } else if let Some(colon) = host.iter().rposition(|byte| *byte == b':')
        && !valid_optional_port(&host[colon..])
    {
        return None;
    }
    unescape(host, Mode::Host)
}

fn valid_userinfo(text: &[u8]) -> bool {
    text.iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(byte))
}

/// Read an authority: the host, after the user information that the text may have.
fn parse_authority(authority: &[u8]) -> Option<Vec<u8>> {
    match authority.iter().rposition(|byte| *byte == b'@') {
        None => parse_host(authority),
        Some(index) => {
            let host = parse_host(&authority[index + 1..])?;
            let userinfo = &authority[..index];
            if !valid_userinfo(userinfo) {
                return None;
            }
            match userinfo.iter().position(|byte| *byte == b':') {
                None => unescape(userinfo, Mode::Other)?,
                Some(colon) => {
                    unescape(&userinfo[..colon], Mode::Other)?;
                    unescape(&userinfo[colon + 1..], Mode::Other)?
                }
            };
            Some(host)
        }
    }
}

/// The scheme and the rest of a URL. `Err` for a colon at the start.
fn get_scheme(raw: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    for (index, byte) in raw.iter().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if index == 0 {
                    return Ok((&[], raw));
                }
            }
            b':' => {
                if index == 0 {
                    return Err(());
                }
                return Ok((&raw[..index], &raw[index + 1..]));
            }
            _ => return Ok((&[], raw)),
        }
    }
    Ok((&[], raw))
}

/// Read a URL without its fragment. Gives the host.
fn parse(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.iter().any(|byte| *byte < 0x20 || *byte == 0x7f) {
        return None;
    }
    if raw == b"*" {
        return Some(Vec::new());
    }
    let (scheme, rest) = get_scheme(raw).ok()?;
    let rest = if rest.ends_with(b"?") && rest.iter().filter(|byte| **byte == b'?').count() == 1 {
        &rest[..rest.len() - 1]
    } else {
        match rest.iter().position(|byte| *byte == b'?') {
            Some(index) => &rest[..index],
            None => rest,
        }
    };
    if !rest.starts_with(b"/") {
        if !scheme.is_empty() {
            return Some(Vec::new());
        }
        let segment = rest.split(|byte| *byte == b'/').next().unwrap_or(&[]);
        if segment.contains(&b':') {
            return None;
        }
    }
    let mut host = Vec::new();
    let mut path = rest;
    if (!scheme.is_empty() || !rest.starts_with(b"///")) && rest.starts_with(b"//") {
        let authority_and_path = &rest[2..];
        let (authority, after) = match authority_and_path.iter().position(|byte| *byte == b'/') {
            Some(index) => (&authority_and_path[..index], &authority_and_path[index..]),
            None => (authority_and_path, &[][..]),
        };
        host = parse_authority(authority)?;
        path = after;
    }
    unescape(path, Mode::Other)?;
    Some(host)
}

/// True when the host has labels that a name may have: no empty label and only bytes from 33 to 126.
pub fn valid_labels(host: &[u8]) -> bool {
    if host.is_empty() {
        return true;
    }
    let labels: Vec<&[u8]> = host.rsplit(|byte| *byte == b'.').collect();
    if labels.first().is_some_and(|label| label.is_empty()) {
        return false;
    }
    labels
        .iter()
        .all(|label| !label.is_empty() && label.iter().all(|byte| (33..=126).contains(byte)))
}

/// True when the text is a URI that a certificate may hold in an alternative name.
pub fn uri_is_valid(text: &str) -> bool {
    let bytes = text.as_bytes();
    let (main, fragment) = match bytes.iter().position(|byte| *byte == b'#') {
        Some(index) => (&bytes[..index], Some(&bytes[index + 1..])),
        None => (bytes, None),
    };
    let Some(host) = parse(main) else {
        return false;
    };
    if let Some(fragment) = fragment
        && unescape(fragment, Mode::Other).is_none()
    {
        return false;
    }
    valid_labels(&host)
}

/// True when the text is a mailbox: a local part, `@` and a domain with valid labels. The local part is an atom
/// list or a quoted string.
pub fn mailbox_is_valid(input: &str) -> bool {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut rest = bytes;
    let mut local: Vec<u8> = Vec::new();
    if rest[0] == b'"' {
        rest = &rest[1..];
        loop {
            let Some((&byte, after)) = rest.split_first() else {
                return false;
            };
            rest = after;
            match byte {
                b'"' => break,
                b'\\' => {
                    let Some((&escaped, after)) = rest.split_first() else {
                        return false;
                    };
                    if escaped == 11 || escaped == 12 || (1..=9).contains(&escaped) || (14..=127).contains(&escaped) {
                        local.push(escaped);
                        rest = after;
                    } else {
                        return false;
                    }
                }
                11 | 12 | 32 | 33 | 127 | 1..=8 | 14..=31 | 35..=91 | 93..=126 => local.push(byte),
                _ => return false,
            }
        }
    } else {
        while let Some((&byte, after)) = rest.split_first() {
            let mut current = byte;
            let mut remaining = after;
            if byte == b'\\' {
                let Some((&escaped, after_escaped)) = after.split_first() else {
                    return false;
                };
                current = escaped;
                remaining = after_escaped;
                local.push(current);
                rest = remaining;
                continue;
            }
            let atext = current.is_ascii_alphanumeric()
                || matches!(
                    current,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                        | b'.'
                );
            if !atext {
                break;
            }
            local.push(current);
            rest = remaining;
        }
        if local.is_empty() {
            return false;
        }
        if local[0] == b'.' || local[local.len() - 1] == b'.' || local.windows(2).any(|pair| pair == b"..") {
            return false;
        }
    }
    if rest.first() != Some(&b'@') {
        return false;
    }
    valid_labels(&rest[1..])
}
