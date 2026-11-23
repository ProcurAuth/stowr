//! A strict XML reader for the package manifests: a pull tokenizer and a tree of elements.
//!
//! The reader keeps the local part of each name. It accepts the five predefined entities and the numeric
//! references. It refuses any other entity. It ignores the declaration of the type of the document and the
//! instructions for programs. These documents are not valid: a document with an encoding other than UTF-8,
//! a document with a name that has two colons, and a document with a tag that its end tag does not close.

/// One token of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// A start tag: the local name and the attributes with their local names. A tag that closes itself gives a
    /// start token and then an end token.
    Start {
        /// The local name.
        name: String,
        /// The attributes: the local name and the value.
        attrs: Vec<(String, String)>,
    },
    /// An end tag.
    End,
    /// Text or CDATA, with the entities expanded and the line ends changed to LF.
    Text(String),
}

/// The tokenizer of a document.
pub struct Tokenizer<'a> {
    data: &'a [u8],
    position: usize,
    stack: Vec<String>,
    pending_end: bool,
    failed: bool,
}

fn is_name_start(character: char) -> bool {
    character == '_' || character == ':' || character.is_alphabetic()
}

fn is_name_char(character: char) -> bool {
    is_name_start(character)
        || character == '-'
        || character == '.'
        || character.is_alphanumeric()
        || character == '\u{b7}'
        || ('\u{300}'..='\u{36f}').contains(&character)
}

fn is_xml_char(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r')
        || ('\u{20}'..='\u{d7ff}').contains(&character)
        || ('\u{e000}'..='\u{fffd}').contains(&character)
        || ('\u{10000}'..='\u{10ffff}').contains(&character)
}

/// The local part of a name. A name with more than one colon is not valid.
fn local_name(name: &str) -> Option<String> {
    if name.matches(':').count() > 1 {
        return None;
    }
    match name.split_once(':') {
        Some((space, local)) if !space.is_empty() && !local.is_empty() => Some(local.to_owned()),
        _ => Some(name.to_owned()),
    }
}

impl<'a> Tokenizer<'a> {
    /// A tokenizer over the bytes of a document.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            position: 0,
            stack: Vec::new(),
            pending_end: false,
            failed: false,
        }
    }

    fn rest(&self) -> &'a [u8] {
        &self.data[self.position..]
    }

    fn fail<T>(&mut self) -> Option<Result<T, ()>> {
        self.failed = true;
        Some(Err(()))
    }

    /// The next token. `None` at the end of a complete document, `Some(Err(()))` at the first fault.
    pub fn next_token(&mut self) -> Option<Result<Token, ()>> {
        if self.failed {
            return Some(Err(()));
        }
        if self.pending_end {
            self.pending_end = false;
            self.stack.pop();
            return Some(Ok(Token::End));
        }
        loop {
            if self.position >= self.data.len() {
                if self.stack.is_empty() {
                    return None;
                }
                return self.fail();
            }
            let rest = self.rest();
            if rest[0] != b'<' {
                return self.read_text();
            }
            if rest.starts_with(b"<!--") {
                let Some(end) = find(&rest[4..], b"--") else {
                    return self.fail();
                };
                if rest.get(4 + end + 2) != Some(&b'>') {
                    return self.fail();
                }
                self.position += 4 + end + 3;
                continue;
            }
            if rest.starts_with(b"<![CDATA[") {
                let Some(end) = find(&rest[9..], b"]]>") else {
                    return self.fail();
                };
                let Ok(text) = std::str::from_utf8(&rest[9..9 + end]) else {
                    return self.fail();
                };
                if !text.chars().all(is_xml_char) {
                    return self.fail();
                }
                let text = normalize_line_ends(text);
                self.position += 9 + end + 3;
                return Some(Ok(Token::Text(text)));
            }
            if rest.starts_with(b"<?") {
                let Some(end) = find(&rest[2..], b"?>") else {
                    return self.fail();
                };
                let content = &rest[2..2 + end];
                if !check_declaration(content) {
                    return self.fail();
                }
                self.position += 2 + end + 2;
                continue;
            }
            if rest.starts_with(b"<!") {
                match skip_directive(rest) {
                    Some(length) => {
                        self.position += length;
                        continue;
                    }
                    None => return self.fail(),
                }
            }
            if rest.starts_with(b"</") {
                return self.read_end_tag();
            }
            return self.read_start_tag();
        }
    }

    fn read_text(&mut self) -> Option<Result<Token, ()>> {
        let rest = self.rest();
        let end = rest.iter().position(|byte| *byte == b'<').unwrap_or(rest.len());
        let Ok(raw) = std::str::from_utf8(&rest[..end]) else {
            return self.fail();
        };
        let Some(text) = decode_text(raw) else {
            return self.fail();
        };
        self.position += end;
        // A text before the first element or after the last one is not part of the tree.
        Some(Ok(Token::Text(text)))
    }

    fn read_end_tag(&mut self) -> Option<Result<Token, ()>> {
        let rest = self.rest();
        let Some(close) = rest.iter().position(|byte| *byte == b'>') else {
            return self.fail();
        };
        let Ok(inside) = std::str::from_utf8(&rest[2..close]) else {
            return self.fail();
        };
        let name = inside.trim_end_matches([' ', '\t', '\r', '\n']);
        let Some(local) = local_name(name) else {
            return self.fail();
        };
        if name.is_empty() || !name.chars().next().is_some_and(is_name_start) || !name.chars().all(is_name_char) {
            return self.fail();
        }
        let Some(open) = self.stack.last() else {
            return self.fail();
        };
        if *open != local {
            return self.fail();
        }
        self.stack.pop();
        self.position += close + 1;
        Some(Ok(Token::End))
    }

    fn read_start_tag(&mut self) -> Option<Result<Token, ()>> {
        let rest = self.rest();
        let mut index = 1;
        let name_end = rest[index..]
            .iter()
            .position(|byte| byte.is_ascii_whitespace() || *byte == b'>' || *byte == b'/')
            .map_or(rest.len(), |offset| index + offset);
        let Ok(name) = std::str::from_utf8(&rest[index..name_end]) else {
            return self.fail();
        };
        if name.is_empty() || !name.chars().next().is_some_and(is_name_start) || !name.chars().all(is_name_char) {
            return self.fail();
        }
        let Some(local) = local_name(name) else {
            return self.fail();
        };
        index = name_end;
        let mut attrs: Vec<(String, String)> = Vec::new();
        loop {
            while index < rest.len() && rest[index].is_ascii_whitespace() {
                index += 1;
            }
            if index >= rest.len() {
                return self.fail();
            }
            match rest[index] {
                b'>' => {
                    self.position += index + 1;
                    self.stack.push(local.clone());
                    return Some(Ok(Token::Start { name: local, attrs }));
                }
                b'/' => {
                    if rest.get(index + 1) != Some(&b'>') {
                        return self.fail();
                    }
                    self.position += index + 2;
                    self.stack.push(local.clone());
                    self.pending_end = true;
                    return Some(Ok(Token::Start { name: local, attrs }));
                }
                _ => {}
            }
            let attr_end = rest[index..]
                .iter()
                .position(|byte| byte.is_ascii_whitespace() || *byte == b'=' || *byte == b'>' || *byte == b'/')
                .map_or(rest.len(), |offset| index + offset);
            let Ok(attr_name) = std::str::from_utf8(&rest[index..attr_end]) else {
                return self.fail();
            };
            if attr_name.is_empty()
                || !attr_name.chars().next().is_some_and(is_name_start)
                || !attr_name.chars().all(is_name_char)
            {
                return self.fail();
            }
            let Some(attr_local) = local_name(attr_name) else {
                return self.fail();
            };
            index = attr_end;
            while index < rest.len() && rest[index].is_ascii_whitespace() {
                index += 1;
            }
            if rest.get(index) != Some(&b'=') {
                return self.fail();
            }
            index += 1;
            while index < rest.len() && rest[index].is_ascii_whitespace() {
                index += 1;
            }
            let Some(&quote) = rest.get(index) else {
                return self.fail();
            };
            if quote != b'"' && quote != b'\'' {
                return self.fail();
            }
            index += 1;
            let Some(value_end) = rest[index..].iter().position(|byte| *byte == quote) else {
                return self.fail();
            };
            let Ok(raw) = std::str::from_utf8(&rest[index..index + value_end]) else {
                return self.fail();
            };
            if raw.contains('<') {
                return self.fail();
            }
            let Some(value) = decode_text(raw) else {
                return self.fail();
            };
            index += value_end + 1;
            attrs.push((attr_local, value));
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn normalize_line_ends(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// The value of a parameter of a declaration: the text between the quotes after `name=`. An empty text when the
/// declaration has no such parameter.
fn declaration_parameter(name: &str, content: &str) -> String {
    let key = format!("{name}=");
    let Some(index) = content.find(&key) else {
        return String::new();
    };
    let value = &content[index + key.len()..];
    let Some(quote) = value.chars().next().filter(|quote| *quote == '"' || *quote == '\'') else {
        return String::new();
    };
    let inner = &value[1..];
    match inner.find(quote) {
        Some(end) => inner[..end].to_owned(),
        None => String::new(),
    }
}

/// Check a processing instruction: its target must be a name. The declaration `xml` must have the version 1.0
/// (or no version) and the encoding UTF-8 (or no encoding).
fn check_declaration(data: &[u8]) -> bool {
    let target_end = data
        .iter()
        .position(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'.' | b'-') || *byte >= 0x80))
        .unwrap_or(data.len());
    if target_end == 0 {
        return false;
    }
    let target = String::from_utf8_lossy(&data[..target_end]).into_owned();
    if !target.chars().next().is_some_and(is_name_start) || !target.chars().all(is_name_char) {
        return false;
    }
    if target != "xml" {
        return true;
    }
    let content_start = data[target_end..]
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map_or(data.len(), |offset| target_end + offset);
    let content = String::from_utf8_lossy(&data[content_start..]).into_owned();
    let version = declaration_parameter("version", &content);
    if !version.is_empty() && version != "1.0" {
        return false;
    }
    let encoding = declaration_parameter("encoding", &content);
    encoding.is_empty() || encoding.eq_ignore_ascii_case("utf-8")
}

/// The length of a directive `<!...>` (with brackets and quotes), or `None` when it does not end.
fn skip_directive(data: &[u8]) -> Option<usize> {
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    let mut index = 2;
    while index < data.len() {
        let byte = data[index];
        if let Some(open) = quote {
            if byte == open {
                quote = None;
            }
        } else {
            match byte {
                b'"' | b'\'' => quote = Some(byte),
                b'<' => depth += 1,
                b'>' => {
                    if depth == 0 {
                        return Some(index + 1);
                    }
                    depth -= 1;
                }
                b'-' if data[index..].starts_with(b"--") && data[..index].ends_with(b"<!") => {
                    return None;
                }
                _ => {}
            }
        }
        index += 1;
    }
    None
}

/// Expand the references of a text and check its characters. `None` for a reference that the reader refuses.
fn decode_text(raw: &str) -> Option<String> {
    if !raw.chars().all(is_xml_char) {
        return None;
    }
    if raw.contains("]]>") {
        return None;
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(index) = rest.find('&') {
        out.push_str(&rest[..index]);
        let after = &rest[index + 1..];
        let end = after.find(';')?;
        let name = &after[..end];
        match name {
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "amp" => out.push('&'),
            "apos" => out.push('\''),
            "quot" => out.push('"'),
            _ => {
                let digits = name.strip_prefix('#')?;
                let value = match digits.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                    None => digits.parse::<u32>().ok()?,
                };
                let character = char::from_u32(value)?;
                if !is_xml_char(character) {
                    return None;
                }
                out.push(character);
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(normalize_line_ends(&out))
}

/// An element with its text and its children.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Element {
    /// The local name.
    pub name: String,
    /// The attributes: the local name and the value.
    pub attrs: Vec<(String, String)>,
    /// The text of the element itself: the text parts and the CDATA parts, without the text of the children.
    pub text: String,
    /// The children in the order of the document.
    pub children: Vec<Element>,
}

impl Element {
    /// The value of an attribute. When the element has the attribute twice, the last value.
    pub fn attr(&self, name: &str) -> &str {
        self.attrs
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map_or("", |(_, value)| value.as_str())
    }

    /// The children with this name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }

    /// The children at a path of names below this element: `a>b` gives the `b` of each `a`.
    pub fn at_path<'a>(&'a self, path: &[&str]) -> Vec<&'a Element> {
        let mut current: Vec<&Element> = vec![self];
        for name in path {
            let mut next: Vec<&Element> = Vec::new();
            for element in current {
                for child in &element.children {
                    if child.name == *name {
                        next.push(child);
                    }
                }
            }
            current = next;
        }
        current
    }
}

/// Read the first element of a document and its whole content. `None` when the document is not valid before the
/// end of its first element. What follows the first element does not count.
pub fn parse_document(data: &[u8]) -> Option<Element> {
    let mut tokenizer = Tokenizer::new(data);
    let mut stack: Vec<Element> = Vec::new();
    loop {
        match tokenizer.next_token()? {
            Err(()) => return None,
            Ok(Token::Start { name, attrs }) => stack.push(Element {
                name,
                attrs,
                ..Element::default()
            }),
            Ok(Token::Text(text)) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&text);
                }
            }
            Ok(Token::End) => {
                let finished = stack.pop()?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(finished),
                    None => return Some(finished),
                }
            }
        }
    }
}

/// Read the text of the element that a start token opened: the text parts of the element itself, with the nested
/// elements skipped. Reads to the end token of that element.
pub fn read_element_text(tokenizer: &mut Tokenizer<'_>) -> Result<String, ()> {
    let mut depth = 0usize;
    let mut text = String::new();
    loop {
        match tokenizer.next_token() {
            None | Some(Err(())) => return Err(()),
            Some(Ok(Token::Start { .. })) => depth += 1,
            Some(Ok(Token::End)) => {
                if depth == 0 {
                    return Ok(text);
                }
                depth -= 1;
            }
            Some(Ok(Token::Text(part))) => {
                if depth == 0 {
                    text.push_str(&part);
                }
            }
        }
    }
}
