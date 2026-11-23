//! A small strict XML reader for the documents of the S3 provider (tags, lifecycle rules, versioning, errors).
//!
//! The reader gives tokens with their byte offsets and a tree of elements. It expands no external entity and no
//! entity of a DTD. It knows the five predefined entities and the numeric references. A name keeps its local
//! part only: the prefix of a namespace goes away. The attributes `xmlns` are not kept.
//!
//! The editor of the lifecycle rules keeps the bytes of each element that it does not edit. Thus the reader gives
//! the exact offsets of each token.

/// The deepest nesting that the reader accepts.
const MAX_DEPTH: usize = 128;

/// Why a document is not valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XmlError {
    /// The document ends before its first element.
    NoRoot,
    /// Any other fault, with a short text.
    Syntax(String),
}

impl std::fmt::Display for XmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRoot => f.write_str("the document has no element"),
            Self::Syntax(text) => f.write_str(text),
        }
    }
}

fn syntax(text: impl Into<String>) -> XmlError {
    XmlError::Syntax(text.into())
}

/// An element with its text and its children.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Element {
    /// The local name.
    pub name: String,
    /// The attributes: the local name and the value. The attributes `xmlns` are not here.
    pub attrs: Vec<(String, String)>,
    /// The text of the element as the document has it: each text part and each CDATA part, joined.
    pub raw_text: String,
    /// The children, in the order of the document.
    pub children: Vec<Element>,
}

impl Element {
    /// The text without the space at its start and at its end.
    pub fn text(&self) -> &str {
        self.raw_text.trim()
    }

    /// True for an element with no child, whose text has space at its start or at its end.
    pub fn padded(&self) -> bool {
        self.children.is_empty() && self.text() != self.raw_text
    }

    /// The first child with this name.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|child| child.name == name)
    }

    /// The last child with this name: a later element replaces an earlier one with the same name.
    pub fn last_child(&self, name: &str) -> Option<&Element> {
        self.children.iter().rev().find(|child| child.name == name)
    }

    /// The children with this name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }

    /// A text that is the same for two elements with the same names, attributes, texts and children. The order of
    /// the children does not count.
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        out.push('<');
        out.push_str(&self.name);
        let mut attrs: Vec<String> = self
            .attrs
            .iter()
            .map(|(name, value)| format!("{name}={}", super::quote_text(value)))
            .collect();
        attrs.sort();
        for attr in attrs {
            out.push(' ');
            out.push_str(&attr);
        }
        out.push('>');
        let mut children: Vec<String> = self.children.iter().map(Element::canonical).collect();
        children.sort();
        out.push_str(&super::quote_text(self.text()));
        out.push_str(&children.concat());
        out.push_str("</");
        out.push_str(&self.name);
        out.push('>');
        out
    }
}

/// One token of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// A start tag. A tag that closes itself gives a start token and then an end token.
    Start {
        /// The name as the tag writes it, with its prefix.
        raw_name: String,
        /// The local name.
        name: String,
        /// The attributes without `xmlns`.
        attrs: Vec<(String, String)>,
        /// True for `<a/>`.
        self_closing: bool,
    },
    /// An end tag.
    End,
    /// Text or CDATA, with the entities expanded.
    Text(String),
    /// A comment, a processing instruction or a directive.
    Other,
}

/// The reader of the tokens.
pub struct Tokenizer<'a> {
    data: &'a [u8],
    pos: usize,
    stack: Vec<String>,
    pending_end: bool,
}

fn is_name_start(c: char) -> bool {
    c == '_' || c == ':' || c.is_alphabetic()
}

fn is_name_char(c: char) -> bool {
    is_name_start(c) || c == '-' || c == '.' || c.is_numeric()
}

fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

fn split_name(raw: &str) -> (&str, &str) {
    if raw.matches(':').count() > 1 {
        return ("", raw);
    }
    match raw.split_once(':') {
        Some((space, local)) if !space.is_empty() && !local.is_empty() => (space, local),
        _ => ("", raw),
    }
}

fn find(data: &[u8], from: usize, pattern: &[u8]) -> Option<usize> {
    let tail = data.get(from..)?;
    tail.windows(pattern.len())
        .position(|window| window == pattern)
        .map(|index| index + from)
}

impl<'a> Tokenizer<'a> {
    /// A reader over bytes.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            stack: Vec::new(),
            pending_end: false,
        }
    }

    /// The offset of the end of the last token.
    pub fn offset(&self) -> usize {
        self.pos
    }

    fn text_of(&self, from: usize, to: usize) -> Result<&'a str, XmlError> {
        std::str::from_utf8(&self.data[from..to]).map_err(|_| syntax("the document has bytes that are not UTF-8"))
    }

    fn skip_space(&mut self) {
        while self.pos < self.data.len() && matches!(self.data[self.pos], b' ' | b'\t' | b'\r' | b'\n') {
            self.pos += 1;
        }
    }

    fn read_name(&mut self) -> Result<String, XmlError> {
        let from = self.pos;
        while self.pos < self.data.len()
            && !matches!(
                self.data[self.pos],
                b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>' | b'=' | b'<' | b'"' | b'\''
            )
        {
            self.pos += 1;
        }
        let name = self.text_of(from, self.pos)?;
        let mut chars = name.chars();
        let valid = chars.next().is_some_and(is_name_start) && chars.all(is_name_char);
        if !valid {
            return Err(syntax(format!("the name {name:?} is not valid")));
        }
        Ok(name.to_owned())
    }

    /// The next token, or `None` at the end of the document.
    pub fn next_token(&mut self) -> Result<Option<Token>, XmlError> {
        if self.pending_end {
            self.pending_end = false;
            self.stack.pop();
            return Ok(Some(Token::End));
        }
        if self.pos >= self.data.len() {
            return Ok(None);
        }
        if self.data[self.pos] != b'<' {
            return self.read_text().map(Some);
        }
        let rest = &self.data[self.pos..];
        if rest.starts_with(b"<!--") {
            let end = find(self.data, self.pos + 4, b"-->").ok_or_else(|| syntax("a comment does not end"))?;
            self.pos = end + 3;
            return Ok(Some(Token::Other));
        }
        if rest.starts_with(b"<![CDATA[") {
            let from = self.pos + 9;
            let end = find(self.data, from, b"]]>").ok_or_else(|| syntax("a CDATA part does not end"))?;
            let text = self.text_of(from, end)?;
            if let Some(bad) = text.chars().find(|c| !xml_char(*c)) {
                return Err(syntax(format!(
                    "the character U+{:04X} is not valid in XML",
                    bad as u32
                )));
            }
            self.pos = end + 3;
            return Ok(Some(Token::Text(text.replace("\r\n", "\n").replace('\r', "\n"))));
        }
        if rest.starts_with(b"<?") {
            let end = find(self.data, self.pos + 2, b"?>").ok_or_else(|| syntax("an instruction does not end"))?;
            let body = self.text_of(self.pos + 2, end)?;
            if body.starts_with("xml") {
                check_declaration(body)?;
            }
            self.pos = end + 2;
            return Ok(Some(Token::Other));
        }
        if rest.starts_with(b"<!") {
            self.skip_directive()?;
            return Ok(Some(Token::Other));
        }
        if rest.starts_with(b"</") {
            self.pos += 2;
            let name = self.read_name()?;
            self.skip_space();
            if self.data.get(self.pos) != Some(&b'>') {
                return Err(syntax("an end tag does not close"));
            }
            self.pos += 1;
            return match self.stack.pop() {
                Some(open) if open == name => Ok(Some(Token::End)),
                Some(open) => Err(syntax(format!("the element <{open}> is closed by </{name}>"))),
                None => Err(syntax(format!("the end tag </{name}> has no start tag"))),
            };
        }
        self.read_start().map(Some)
    }

    fn skip_directive(&mut self) -> Result<(), XmlError> {
        let mut depth = 0usize;
        let mut quote: Option<u8> = None;
        while self.pos < self.data.len() {
            let byte = self.data[self.pos];
            self.pos += 1;
            match (quote, byte) {
                (Some(open), _) if byte == open => quote = None,
                (Some(_), _) => {}
                (None, b'"' | b'\'') => quote = Some(byte),
                (None, b'<') => depth += 1,
                (None, b'>') => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Err(syntax("a directive does not end"))
    }

    fn read_start(&mut self) -> Result<Token, XmlError> {
        self.pos += 1;
        let raw_name = self.read_name()?;
        let mut attrs = Vec::new();
        let self_closing;
        loop {
            self.skip_space();
            match self.data.get(self.pos) {
                None => return Err(syntax("a start tag does not end")),
                Some(b'>') => {
                    self.pos += 1;
                    self_closing = false;
                    break;
                }
                Some(b'/') => {
                    if self.data.get(self.pos + 1) != Some(&b'>') {
                        return Err(syntax("a start tag has a stray slash"));
                    }
                    self.pos += 2;
                    self_closing = true;
                    break;
                }
                Some(_) => {
                    let name = self.read_name()?;
                    self.skip_space();
                    if self.data.get(self.pos) != Some(&b'=') {
                        return Err(syntax(format!("the attribute {name:?} has no value")));
                    }
                    self.pos += 1;
                    self.skip_space();
                    let quote = match self.data.get(self.pos) {
                        Some(&q) if q == b'"' || q == b'\'' => q,
                        _ => return Err(syntax(format!("the value of the attribute {name:?} has no quote"))),
                    };
                    self.pos += 1;
                    let from = self.pos;
                    while self.pos < self.data.len() && self.data[self.pos] != quote {
                        self.pos += 1;
                    }
                    if self.pos >= self.data.len() {
                        return Err(syntax("an attribute value does not end"));
                    }
                    let value = decode_text(self.text_of(from, self.pos)?)?;
                    self.pos += 1;
                    let (space, local) = split_name(&name);
                    if space == "xmlns" || (space.is_empty() && local == "xmlns") {
                        continue;
                    }
                    attrs.push((local.to_owned(), value));
                }
            }
        }
        if self.stack.len() >= MAX_DEPTH {
            return Err(syntax("the elements are nested too deep"));
        }
        self.stack.push(raw_name.clone());
        self.pending_end = self_closing;
        let (_, local) = split_name(&raw_name);
        Ok(Token::Start {
            name: local.to_owned(),
            raw_name,
            attrs,
            self_closing,
        })
    }

    fn read_text(&mut self) -> Result<Token, XmlError> {
        let from = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != b'<' {
            self.pos += 1;
        }
        let text = decode_text(self.text_of(from, self.pos)?)?;
        Ok(Token::Text(text))
    }
}

fn check_declaration(body: &str) -> Result<(), XmlError> {
    if let Some(index) = body.find("encoding") {
        let rest = &body[index + 8..];
        let value: String = rest
            .trim_start()
            .trim_start_matches('=')
            .trim_start()
            .trim_start_matches(['"', '\''])
            .chars()
            .take_while(|c| *c != '"' && *c != '\'')
            .collect();
        if !value.is_empty() && !value.eq_ignore_ascii_case("utf-8") {
            return Err(syntax(format!("the encoding {value:?} is not supported")));
        }
    }
    Ok(())
}

/// Expand the entities of a text, and turn each line end into `\n`.
fn decode_text(text: &str) -> Result<String, XmlError> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '&' => {
                let mut name = String::new();
                loop {
                    match chars.next() {
                        Some(';') => break,
                        Some(next) if name.len() < 16 => name.push(next),
                        _ => return Err(syntax("an entity does not end")),
                    }
                }
                let expanded = match name.as_str() {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "apos" => '\'',
                    "quot" => '"',
                    _ => {
                        let digits = name
                            .strip_prefix('#')
                            .ok_or_else(|| syntax(format!("the entity &{name}; is unknown")))?;
                        let code = match digits.strip_prefix('x') {
                            Some(hex) => u32::from_str_radix(hex, 16),
                            None => digits.parse::<u32>(),
                        }
                        .map_err(|_| syntax(format!("the reference &{name}; is not valid")))?;
                        char::from_u32(code)
                            .filter(|value| xml_char(*value))
                            .ok_or_else(|| syntax(format!("the reference &{name}; is not a valid character")))?
                    }
                };
                out.push(expanded);
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            other => {
                if !xml_char(other) {
                    return Err(syntax(format!(
                        "the character U+{:04X} is not valid in XML",
                        other as u32
                    )));
                }
                out.push(other);
            }
        }
    }
    Ok(out)
}

/// Read the element that a start token opens, up to its end tag.
pub fn read_element(tokenizer: &mut Tokenizer<'_>, start: Token) -> Result<Element, XmlError> {
    let Token::Start { name, attrs, .. } = start else {
        return Err(syntax("an element must start with a start tag"));
    };
    let mut element = Element {
        name,
        attrs,
        ..Element::default()
    };
    loop {
        match tokenizer.next_token()? {
            None => return Err(syntax("the document ends in an element")),
            Some(Token::Text(text)) => element.raw_text.push_str(&text),
            Some(Token::Other) => {}
            Some(Token::End) => return Ok(element),
            Some(token @ Token::Start { .. }) => element.children.push(read_element(tokenizer, token)?),
        }
    }
}

/// Read the first element of a document, with its tree. Anything after the element stays unread.
pub fn parse_document(data: &[u8]) -> Result<Element, XmlError> {
    let mut tokenizer = Tokenizer::new(data);
    loop {
        match tokenizer.next_token()? {
            None => return Err(XmlError::NoRoot),
            Some(token @ Token::Start { .. }) => return read_element(&mut tokenizer, token),
            Some(_) => {}
        }
    }
}

/// Escape a text for an XML document: the quotes, the line ends and the tab as references, and a character that XML
/// does not allow as U+FFFD.
pub fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other if xml_char(other) => out.push(other),
            _ => out.push('\u{fffd}'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_gives_a_tree_without_prefixes_or_namespace_attributes() {
        let root = parse_document(
            b"<?xml version=\"1.0\"?><!-- c --><s3:Root xmlns:s3=\"u\" a=\"1&amp;2\"><x> t </x><y/>text<![CDATA[<c>]]></s3:Root>",
        )
        .unwrap();
        assert_eq!(root.name, "Root");
        assert_eq!(root.attrs, vec![("a".to_owned(), "1&2".to_owned())]);
        assert_eq!(root.children.len(), 2);
        assert_eq!(root.children[0].text(), "t");
        assert!(root.children[0].padded());
        assert_eq!(root.raw_text, "text<c>");
    }

    #[test]
    fn a_document_that_is_not_well_formed_is_refused() {
        for text in [
            "<a><b></a>",
            "<a>",
            "<a></b>",
            "<a b=1/>",
            "<a>&nope;</a>",
            "<a>\u{1}</a>",
            "<1a/>",
        ] {
            assert!(parse_document(text.as_bytes()).is_err(), "{text:?} is accepted");
        }
        assert_eq!(parse_document(b"just text").err(), Some(XmlError::NoRoot));
        assert_eq!(parse_document(b"").err(), Some(XmlError::NoRoot));
    }

    #[test]
    fn the_first_element_ends_the_read() {
        let root = parse_document(b"<a><b/></a>trailing <<< garbage").unwrap();
        assert_eq!(root.name, "a");
    }

    #[test]
    fn nesting_has_a_limit() {
        let deep = "<a>".repeat(MAX_DEPTH + 1);
        assert!(parse_document(deep.as_bytes()).is_err());
    }

    #[test]
    fn entities_and_line_ends_are_expanded() {
        let root = parse_document("<a>x&#65;&#x42;&lt;\r\ny\rz</a>".as_bytes()).unwrap();
        assert_eq!(root.raw_text, "xAB<\ny\nz");
    }

    #[test]
    fn the_escape_follows_the_rules_of_documents() {
        assert_eq!(
            escape_text("<a&b>\"'\t\n\r"),
            "&lt;a&amp;b&gt;&#34;&#39;&#x9;&#xA;&#xD;"
        );
        assert_eq!(escape_text("a\u{1}b"), "a\u{fffd}b");
    }

    #[test]
    fn offsets_follow_the_bytes_of_the_document() {
        let data = b"<r> <a>1</a><b/> </r>";
        let mut tokenizer = Tokenizer::new(data);
        assert!(matches!(tokenizer.next_token().unwrap(), Some(Token::Start { .. })));
        assert_eq!(tokenizer.offset(), 3);
        let _ = tokenizer.next_token().unwrap();
        let before = tokenizer.offset();
        let start = tokenizer.next_token().unwrap().unwrap();
        read_element(&mut tokenizer, start).unwrap();
        assert_eq!(&data[before..tokenizer.offset()], b"<a>1</a>");
    }
}
