// SPDX-License-Identifier: MIT OR Apache-2.0
//! A strict pull reader of XML over a stream of bytes.
//!
//! The reader gives start tags, end tags and text. It knows the five predefined entities and the numeric
//! references. It expands no external entity and no entity of a DTD, and it skips comments, instructions and
//! directives. A name keeps its local part (the text after the colon). The reader refuses an end tag that does not
//! match, a document that ends inside an element, an entity that it does not know, a byte that is not UTF-8, and a
//! character that XML 1.0 does not allow. A text node and an attribute have a line feed for each line end.
//!
//! The reader keeps one buffer of 64 KiB and the text of the node that it reads. It does not keep the document.

use std::io::Read;

/// Why a read stopped.
#[derive(Debug)]
pub enum XmlFault {
    /// The document is not valid.
    Syntax(String),
    /// The source gave an error.
    Source(std::io::Error),
}

impl std::fmt::Display for XmlFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syntax(text) => f.write_str(text),
            Self::Source(error) => write!(f, "{error}"),
        }
    }
}

fn syntax(text: impl Into<String>) -> XmlFault {
    XmlFault::Syntax(text.into())
}

/// One token of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XmlEvent {
    /// A start tag. A tag that closes itself gives a start event and then an end event.
    Start {
        /// The local name.
        name: String,
        /// The attributes, as the local name and the value.
        attrs: Vec<(String, String)>,
    },
    /// An end tag.
    End {
        /// The local name.
        name: String,
    },
    /// Text, with its entities expanded. A CDATA section gives text too.
    Text(String),
}

/// The value of the first attribute with this local name.
pub fn attribute<'a>(attrs: &'a [(String, String)], local: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(name, _)| name == local)
        .map(|(_, value)| value.as_str())
}

/// The value of the last attribute with this local name.
pub fn last_attribute<'a>(attrs: &'a [(String, String)], local: &str) -> Option<&'a str> {
    attrs
        .iter()
        .rev()
        .find(|(name, _)| name == local)
        .map(|(_, value)| value.as_str())
}

const BUFFER_BYTES: usize = 64 * 1024;

/// The pull reader.
pub struct XmlReader<R: Read> {
    reader: R,
    buffer: Box<[u8]>,
    position: usize,
    end: usize,
    ended: bool,
    stack: Vec<(String, String)>,
    pending_end: Option<String>,
}

/// The local part of a name with a prefix: the text after the colon, when the name has one colon only and each side
/// is not empty.
fn local_name(raw: &str) -> String {
    if raw.matches(':').count() == 1
        && let Some((space, local)) = raw.split_once(':')
        && !space.is_empty()
        && !local.is_empty()
    {
        return local.to_owned();
    }
    raw.to_owned()
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn is_name_end(byte: u8) -> bool {
    is_space(byte) || matches!(byte, b'/' | b'>' | b'=' | b'<' | b'"' | b'\'')
}

fn in_character_range(value: char) -> bool {
    let code = u32::from(value);
    code == 0x09
        || code == 0x0A
        || code == 0x0D
        || (0x20..=0xD7FF).contains(&code)
        || (0xE000..=0xFFFD).contains(&code)
        || (0x10000..=0x10FFFF).contains(&code)
}

impl<R: Read> XmlReader<R> {
    /// A reader over a source.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: vec![0u8; BUFFER_BYTES].into_boxed_slice(),
            position: 0,
            end: 0,
            ended: false,
            stack: Vec::new(),
            pending_end: None,
        }
    }

    /// The number of elements that are open.
    pub fn depth(&self) -> usize {
        self.stack.len() + usize::from(self.pending_end.is_some())
    }

    fn fill(&mut self) -> Result<bool, XmlFault> {
        if self.position < self.end {
            return Ok(true);
        }
        if self.ended {
            return Ok(false);
        }
        loop {
            match self.reader.read(&mut self.buffer) {
                Ok(0) => {
                    self.ended = true;
                    return Ok(false);
                }
                Ok(count) => {
                    self.position = 0;
                    self.end = count;
                    return Ok(true);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(XmlFault::Source(error)),
            }
        }
    }

    fn peek(&mut self) -> Result<Option<u8>, XmlFault> {
        if !self.fill()? {
            return Ok(None);
        }
        Ok(Some(self.buffer[self.position]))
    }

    fn next_byte(&mut self) -> Result<Option<u8>, XmlFault> {
        if !self.fill()? {
            return Ok(None);
        }
        let value = self.buffer[self.position];
        self.position += 1;
        Ok(Some(value))
    }

    fn require_byte(&mut self) -> Result<u8, XmlFault> {
        self.next_byte()?.ok_or_else(|| syntax("unexpected end of the data"))
    }

    fn skip_spaces(&mut self) -> Result<(), XmlFault> {
        while let Some(byte) = self.peek()? {
            if !is_space(byte) {
                break;
            }
            self.position += 1;
        }
        Ok(())
    }

    fn read_name(&mut self) -> Result<String, XmlFault> {
        let mut name: Vec<u8> = Vec::new();
        while let Some(byte) = self.peek()? {
            if is_name_end(byte) {
                break;
            }
            name.push(byte);
            self.position += 1;
        }
        if name.is_empty() {
            return Err(syntax("expected a name"));
        }
        String::from_utf8(name).map_err(|_| syntax("invalid UTF-8"))
    }

    /// Read bytes up to the text `stop` (it is read, not given). The text before it is the result.
    fn read_until(&mut self, stop: &[u8]) -> Result<Vec<u8>, XmlFault> {
        let mut out: Vec<u8> = Vec::new();
        loop {
            let byte = self.require_byte()?;
            out.push(byte);
            if out.ends_with(stop) {
                out.truncate(out.len() - stop.len());
                return Ok(out);
            }
        }
    }

    /// An entity after `&`.
    fn read_entity(&mut self, out: &mut String) -> Result<(), XmlFault> {
        let mut name = String::new();
        loop {
            let byte = self.next_byte()?.ok_or_else(|| syntax("unexpected end of the data"))?;
            if byte == b';' {
                break;
            }
            if name.len() > 16 || is_name_end(byte) && byte != b'#' {
                return Err(syntax(format!("the character entity &{name} has no semicolon")));
            }
            name.push(char::from(byte));
        }
        let value = match name.as_str() {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "apos" => '\'',
            "quot" => '"',
            other => {
                let digits = other.strip_prefix('#');
                let code = match digits {
                    Some(hex) if hex.starts_with(['x', 'X']) => u32::from_str_radix(&hex[1..], 16).ok(),
                    Some(decimal) => decimal.parse::<u32>().ok(),
                    None => None,
                };
                code.and_then(char::from_u32)
                    .filter(|value| in_character_range(*value))
                    .ok_or_else(|| syntax(format!("unknown character entity &{other};")))?
            }
        };
        out.push(value);
        Ok(())
    }

    /// Text up to a character that `stop` names (it is not read), with the entities expanded. `quote` makes the
    /// text an attribute value: it stops at the quote, and `<` is an error.
    fn read_text(&mut self, quote: Option<u8>) -> Result<String, XmlFault> {
        let mut out = String::new();
        let mut raw: Vec<u8> = Vec::new();
        loop {
            let Some(byte) = self.peek()? else {
                if quote.is_some() {
                    return Err(syntax("unexpected end of the data"));
                }
                break;
            };
            match byte {
                b'<' if quote.is_none() => break,
                b'<' => return Err(syntax("unescaped < inside quoted string")),
                b'&' => {
                    self.position += 1;
                    Self::flush(&mut raw, &mut out)?;
                    self.read_entity(&mut out)?;
                }
                _ if Some(byte) == quote => break,
                b'\r' => {
                    self.position += 1;
                    if self.peek()? == Some(b'\n') {
                        self.position += 1;
                    }
                    raw.push(b'\n');
                }
                _ => {
                    let available = &self.buffer[self.position..self.end];
                    let count = available
                        .iter()
                        .position(|current| matches!(current, b'<' | b'&' | b'\r') || Some(*current) == quote)
                        .unwrap_or(available.len());
                    raw.extend_from_slice(&available[..count]);
                    self.position += count;
                }
            }
        }
        Self::flush(&mut raw, &mut out)?;
        Ok(out)
    }

    /// Move the bytes of `raw` to `out`, after a check of the encoding and of the characters.
    fn flush(raw: &mut Vec<u8>, out: &mut String) -> Result<(), XmlFault> {
        if raw.is_empty() {
            return Ok(());
        }
        let text = std::str::from_utf8(raw).map_err(|_| syntax("invalid UTF-8"))?;
        if let Some(bad) = text.chars().find(|value| !in_character_range(*value)) {
            return Err(syntax(format!(
                "the character U+{:04X} is not allowed in XML",
                u32::from(bad)
            )));
        }
        out.push_str(text);
        raw.clear();
        Ok(())
    }

    fn read_attributes(&mut self) -> Result<(Vec<(String, String)>, bool), XmlFault> {
        let mut attrs: Vec<(String, String)> = Vec::new();
        loop {
            self.skip_spaces()?;
            match self.peek()? {
                None => return Err(syntax("unexpected end of the data")),
                Some(b'>') => {
                    self.position += 1;
                    return Ok((attrs, false));
                }
                Some(b'/') => {
                    self.position += 1;
                    if self.require_byte()? != b'>' {
                        return Err(syntax("expected /> in element"));
                    }
                    return Ok((attrs, true));
                }
                Some(_) => {}
            }
            let name = self.read_name()?;
            self.skip_spaces()?;
            if self.require_byte()? != b'=' {
                return Err(syntax(format!("attribute name without = in element: {name}")));
            }
            self.skip_spaces()?;
            let quote = self.require_byte()?;
            if quote != b'"' && quote != b'\'' {
                return Err(syntax("unquoted or missing attribute value in element"));
            }
            let value = self.read_text(Some(quote))?;
            self.position += 1;
            attrs.push((local_name(&name), value));
        }
    }

    fn skip_directive(&mut self) -> Result<(), XmlFault> {
        let mut depth = 1usize;
        let mut quote: Option<u8> = None;
        while depth > 0 {
            let byte = self.require_byte()?;
            match (quote, byte) {
                (Some(open), current) if current == open => quote = None,
                (Some(_), _) => {}
                (None, b'"' | b'\'') => quote = Some(byte),
                (None, b'<') => depth += 1,
                (None, b'>') => depth -= 1,
                _ => {}
            }
        }
        Ok(())
    }

    fn read_instruction(&mut self) -> Result<(), XmlFault> {
        let body = self.read_until(b"?>")?;
        let text = String::from_utf8_lossy(&body).into_owned();
        if let Some(rest) = text.strip_prefix("xml")
            && rest.starts_with(|value: char| value.is_ascii_whitespace())
            && let Some(index) = rest.find("encoding")
        {
            let after = rest[index + "encoding".len()..].trim_start();
            if let Some(after) = after.strip_prefix('=') {
                let after = after.trim_start();
                let quote = after.chars().next().unwrap_or('"');
                let value = after[quote.len_utf8()..].split(quote).next().unwrap_or("");
                if !value.is_empty() && !value.eq_ignore_ascii_case("utf-8") {
                    return Err(syntax(format!("encoding {value:?} is not supported")));
                }
            }
        }
        Ok(())
    }

    /// The next token. `None` at the end of the document.
    pub fn next_event(&mut self) -> Result<Option<XmlEvent>, XmlFault> {
        if let Some(name) = self.pending_end.take() {
            return Ok(Some(XmlEvent::End { name }));
        }
        loop {
            let Some(byte) = self.peek()? else {
                if let Some((raw, _)) = self.stack.last() {
                    return Err(syntax(format!(
                        "unexpected end of the data: element <{raw}> is not closed"
                    )));
                }
                return Ok(None);
            };
            if byte != b'<' {
                let text = self.read_text(None)?;
                return Ok(Some(XmlEvent::Text(text)));
            }
            self.position += 1;
            match self.require_byte()? {
                b'/' => {
                    let raw = self.read_name()?;
                    self.skip_spaces()?;
                    if self.require_byte()? != b'>' {
                        return Err(syntax("invalid characters in a closing tag"));
                    }
                    let Some((open, local)) = self.stack.pop() else {
                        return Err(syntax(format!("unexpected end element </{raw}>")));
                    };
                    if open != raw {
                        return Err(syntax(format!("element <{open}> closed by </{raw}>")));
                    }
                    return Ok(Some(XmlEvent::End { name: local }));
                }
                b'?' => self.read_instruction()?,
                b'!' => match self.peek()? {
                    Some(b'-') => {
                        self.position += 1;
                        if self.require_byte()? != b'-' {
                            return Err(syntax("invalid sequence <!- not part of <!--"));
                        }
                        self.read_until(b"-->")?;
                    }
                    Some(b'[') => {
                        for expected in b"[CDATA[" {
                            if self.require_byte()? != *expected {
                                return Err(syntax("invalid <![ sequence"));
                            }
                        }
                        let data = self.read_until(b"]]>")?;
                        let mut out = String::new();
                        let mut raw: Vec<u8> = Vec::new();
                        let mut index = 0;
                        while index < data.len() {
                            if data[index] == b'\r' {
                                raw.push(b'\n');
                                if data.get(index + 1) == Some(&b'\n') {
                                    index += 1;
                                }
                            } else {
                                raw.push(data[index]);
                            }
                            index += 1;
                        }
                        Self::flush(&mut raw, &mut out)?;
                        return Ok(Some(XmlEvent::Text(out)));
                    }
                    _ => self.skip_directive()?,
                },
                first => {
                    self.position -= 1;
                    let _ = first;
                    let raw = self.read_name()?;
                    let (attrs, self_closing) = self.read_attributes()?;
                    let local = local_name(&raw);
                    if self_closing {
                        self.pending_end = Some(local.clone());
                    } else {
                        self.stack.push((raw, local.clone()));
                    }
                    return Ok(Some(XmlEvent::Start { name: local, attrs }));
                }
            }
        }
    }

    /// After a start event: the text that the element holds directly (the text of its children is not in it), up to
    /// the matching end tag, which it reads.
    pub fn element_text(&mut self) -> Result<String, XmlFault> {
        let mut out = String::new();
        let mut depth = 1usize;
        while depth > 0 {
            match self.next_event()? {
                None => return Err(syntax("unexpected end of the data")),
                Some(XmlEvent::Start { .. }) => depth += 1,
                Some(XmlEvent::End { .. }) => depth -= 1,
                Some(XmlEvent::Text(text)) => {
                    if depth == 1 {
                        out.push_str(&text);
                    }
                }
            }
        }
        Ok(out)
    }

    /// After a start event: read up to the matching end tag.
    pub fn skip_element(&mut self) -> Result<(), XmlFault> {
        self.skip_to_depth(1)
    }

    /// Read up to the end of an element with `depth` levels open (1: the element that the last start event opened).
    pub fn skip_to_depth(&mut self, mut depth: usize) -> Result<(), XmlFault> {
        while depth > 0 {
            match self.next_event()? {
                None => return Err(syntax("unexpected end of the data")),
                Some(XmlEvent::Start { .. }) => depth += 1,
                Some(XmlEvent::End { .. }) => depth -= 1,
                Some(XmlEvent::Text(_)) => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(text: &str) -> Result<Vec<XmlEvent>, XmlFault> {
        let mut reader = XmlReader::new(text.as_bytes());
        let mut out = Vec::new();
        while let Some(event) = reader.next_event()? {
            out.push(event);
        }
        Ok(out)
    }

    fn start(name: &str, attrs: &[(&str, &str)]) -> XmlEvent {
        XmlEvent::Start {
            name: name.to_owned(),
            attrs: attrs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    fn end(name: &str) -> XmlEvent {
        XmlEvent::End { name: name.to_owned() }
    }

    fn text(value: &str) -> XmlEvent {
        XmlEvent::Text(value.to_owned())
    }

    #[test]
    fn tags_attributes_and_text_are_events() {
        let got =
            events("<?xml version=\"1.0\" encoding=\"UTF-8\"?><a:r xmlns:a=\"u\" id='1'><b/>x &amp; &#65;&#x42;</a:r>")
                .unwrap();
        assert_eq!(
            got,
            vec![
                start("r", &[("a", "u"), ("id", "1")]),
                start("b", &[]),
                end("b"),
                text("x & AB"),
                end("r"),
            ]
        );
    }

    #[test]
    fn a_comment_a_directive_and_cdata_are_handled() {
        let got = events("<!DOCTYPE a [<!ENTITY x \"y\">]><a><!-- c --><![CDATA[<t>&]]></a>").unwrap();
        assert_eq!(got, vec![start("a", &[]), text("<t>&"), end("a")]);
    }

    #[test]
    fn line_ends_become_line_feeds() {
        let got = events("<a v=\"1\r\n2\">a\r\nb\rc</a>").unwrap();
        assert_eq!(got, vec![start("a", &[("v", "1\n2")]), text("a\nb\nc"), end("a")]);
    }

    #[test]
    fn a_wrong_document_is_refused() {
        for bad in [
            "<a><b></a>",
            "<a>",
            "</a>",
            "<a>&unknown;</a>",
            "<a>&amp</a>",
            "<a b></a>",
            "<a b=1></a>",
            "<a b=\"<\"></a>",
            "<a>\u{1}</a>",
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?><a/>",
        ] {
            assert!(events(bad).is_err(), "{bad}");
        }
        let mut reader = XmlReader::new(&b"<a>\xFF</a>"[..]);
        reader.next_event().unwrap();
        assert!(reader.next_event().is_err());
    }

    #[test]
    fn the_text_of_an_element_skips_its_children() {
        let mut reader = XmlReader::new(&b"<t>a<b>x</b>c</t><u/>"[..]);
        assert!(matches!(reader.next_event().unwrap(), Some(XmlEvent::Start { .. })));
        assert_eq!(reader.element_text().unwrap(), "ac");
        assert!(matches!(reader.next_event().unwrap(), Some(XmlEvent::Start { .. })));
    }

    #[test]
    fn names_with_more_than_one_colon_keep_the_whole_name() {
        assert_eq!(local_name("a:b"), "b");
        assert_eq!(local_name("a:b:c"), "a:b:c");
        assert_eq!(local_name(":b"), ":b");
        assert_eq!(local_name("a:"), "a:");
    }
}
