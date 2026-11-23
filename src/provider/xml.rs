//! The XML of the S3 answers and requests: a reader that walks the elements of a document, and the escape of a text.
//!
//! The reader follows these rules. The first element is the root. An element matches by its local name: a namespace
//! prefix has no effect. The text of an element is its direct character data, with the references decoded and the
//! line ends normalized. A reference that is not a character reference or one of the five predefined entities stops
//! the read. The reader stops at the end of the root and ignores the bytes after it.

use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// The largest depth of the elements of a document.
const MAX_DEPTH: usize = 10_000;

/// One event of [`walk`]. The path holds the local names of the elements below the root, the last one included.
pub enum Node<'a> {
    /// The start of an element.
    Start(&'a [String]),
    /// The end of an element, with its direct character data.
    End(&'a [String], String),
}

/// Walk the elements of the root of a document. `visit` gets the start and the end of each element below the root.
/// The result is the local name of the root, or the text of the error.
pub fn walk(bytes: &[u8], mut visit: impl FnMut(Node<'_>)) -> Result<String, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "the XML document is not valid UTF-8".to_owned())?;
    let mut reader = Reader::from_str(text);
    let mut root: Option<String> = None;
    let mut path: Vec<String> = Vec::new();
    let mut texts: Vec<String> = Vec::new();
    loop {
        let event = reader
            .read_event()
            .map_err(|error| format!("XML syntax error: {error}"))?;
        match event {
            Event::Start(start) => {
                let name = start.local_name().as_ref().to_owned();
                open(&mut root, &mut path, &mut texts, name, &mut visit)?;
            }
            Event::Empty(start) => {
                let name = start.local_name().as_ref().to_owned();
                open(&mut root, &mut path, &mut texts, name, &mut visit)?;
                if let Some(name) = close(&root, &mut path, &mut texts, &mut visit) {
                    return Ok(name);
                }
            }
            Event::End(_) => {
                if let Some(name) = close(&root, &mut path, &mut texts, &mut visit) {
                    return Ok(name);
                }
            }
            Event::Text(data) => {
                if let Some(current) = texts.last_mut() {
                    current.push_str(&data.xml10_content());
                }
            }
            Event::CData(data) => {
                if let Some(current) = texts.last_mut() {
                    current.push_str(&data.into_inner());
                }
            }
            Event::GeneralRef(reference) => {
                let character = if reference.is_char_ref() {
                    reference
                        .resolve_char_ref()
                        .map_err(|error| format!("XML syntax error: {error}"))?
                } else {
                    match reference.as_ref() {
                        "lt" => Some('<'),
                        "gt" => Some('>'),
                        "amp" => Some('&'),
                        "apos" => Some('\''),
                        "quot" => Some('"'),
                        _ => None,
                    }
                };
                let Some(character) = character else {
                    return Err(format!(
                        "XML syntax error: invalid character entity &{};",
                        reference.as_ref()
                    ));
                };
                if let Some(current) = texts.last_mut() {
                    current.push(character);
                }
            }
            Event::Eof => return Err("XML syntax error: unexpected EOF".to_owned()),
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) | Event::DocType(_) => {}
        }
    }
}

fn open(
    root: &mut Option<String>,
    path: &mut Vec<String>,
    texts: &mut Vec<String>,
    name: String,
    visit: &mut impl FnMut(Node<'_>),
) -> Result<(), String> {
    if root.is_none() {
        *root = Some(name);
    } else {
        if path.len() >= MAX_DEPTH {
            return Err("XML syntax error: the elements are nested too deep".to_owned());
        }
        path.push(name);
        visit(Node::Start(path));
    }
    texts.push(String::new());
    Ok(())
}

/// Close the current element. The result is the name of the root when the root closes.
fn close(
    root: &Option<String>,
    path: &mut Vec<String>,
    texts: &mut Vec<String>,
    visit: &mut impl FnMut(Node<'_>),
) -> Option<String> {
    let text = texts.pop().unwrap_or_default();
    if path.is_empty() {
        return root.clone();
    }
    visit(Node::End(path, text));
    path.pop();
    None
}

/// True when the path below the root is exactly these names.
pub fn at(path: &[String], names: &[&str]) -> bool {
    path.len() == names.len() && path.iter().zip(names).all(|(left, right)| left == right)
}

/// The value of a boolean element: an empty text is false; else `1`, `t`, `T`, `true`, `TRUE`, `True` or the false
/// forms, after the removal of the spaces.
pub fn parse_bool(text: &str) -> Result<bool, String> {
    if text.is_empty() {
        return Ok(false);
    }
    match text.trim() {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        other => Err(format!("invalid boolean {other:?}")),
    }
}

/// The value of an integer element: an empty text is 0; else a decimal integer, after the removal of the spaces.
pub fn parse_int(text: &str) -> Result<i64, String> {
    if text.is_empty() {
        return Ok(0);
    }
    text.trim()
        .parse::<i64>()
        .map_err(|_| format!("invalid integer {:?}", text.trim()))
}

/// True for a character that XML 1.0 can carry.
fn in_character_range(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

/// Escape a text for the content of an element. A character that XML cannot carry becomes U+FFFD.
pub fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other if in_character_range(other) => out.push(other),
            _ => out.push('\u{FFFD}'),
        }
    }
    out
}

/// One element with its escaped text: `<name>text</name>`.
pub fn element(name: &str, text: &str) -> String {
    format!("<{name}>{}</{name}>", escape_text(text))
}

/// The root name and the `Code` and the `Message` of a document, when the document reads. An S3 error document has
/// the root `Error`.
pub fn error_document(bytes: &[u8]) -> Option<(String, String, String)> {
    let mut code = String::new();
    let mut message = String::new();
    let root = walk(bytes, |node| {
        if let Node::End(path, text) = node {
            if at(path, &["Code"]) {
                code = text;
            } else if at(path, &["Message"]) {
                message = text;
            }
        }
    })
    .ok()?;
    Some((root, code, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_walk_gives_paths_texts_and_the_root() {
        let document = br#"<?xml version="1.0"?><!-- c --><s3:Result xmlns:s3="x"><s3:Key> a &amp; b &#x41;</s3:Key><Empty/><Part><N>1</N><![CDATA[<x>]]></Part></s3:Result>trailing <bad"#;
        let mut seen = Vec::new();
        let root = walk(document, |node| match node {
            Node::Start(path) => seen.push(format!("start {}", path.join(">"))),
            Node::End(path, text) => seen.push(format!("end {} {text:?}", path.join(">"))),
        })
        .unwrap();
        assert_eq!(root, "Result");
        assert_eq!(
            seen,
            vec![
                "start Key",
                "end Key \" a & b A\"",
                "start Empty",
                "end Empty \"\"",
                "start Part",
                "start Part>N",
                "end Part>N \"1\"",
                "end Part \"<x>\"",
            ]
        );
    }

    #[test]
    fn a_broken_document_is_an_error() {
        assert!(walk(b"", |_| {}).is_err());
        assert!(walk(b"<a><b></a>", |_| {}).is_err());
        assert!(walk(b"<a>&unknown;</a>", |_| {}).is_err());
        assert!(walk(b"<a>", |_| {}).is_err());
    }

    #[test]
    fn scalars_follow_the_rules_of_the_answers() {
        assert_eq!(parse_bool(""), Ok(false));
        assert_eq!(parse_bool(" true "), Ok(true));
        assert!(parse_bool("yes").is_err());
        assert_eq!(parse_int(""), Ok(0));
        assert_eq!(parse_int(" 42\n"), Ok(42));
        assert!(parse_int("4x").is_err());
    }

    #[test]
    fn text_escape_uses_the_numeric_forms() {
        assert_eq!(
            escape_text("\"a\" & <b>'\t\n\r\u{1}"),
            "&#34;a&#34; &amp; &lt;b&gt;&#39;&#x9;&#xA;&#xD;\u{FFFD}"
        );
        assert_eq!(element("Key", "a & b"), "<Key>a &amp; b</Key>");
    }

    #[test]
    fn an_error_document_gives_its_code_and_message() {
        let (root, code, message) =
            error_document(b"<Error><Code>InternalError</Code><Message>failed</Message></Error>").unwrap();
        assert_eq!(
            (root.as_str(), code.as_str(), message.as_str()),
            ("Error", "InternalError", "failed")
        );
        assert!(error_document(b"not xml").is_none());
    }
}
