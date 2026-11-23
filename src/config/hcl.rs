//! The reader of the HCL subset of the configuration: blocks with labels, attributes, quoted strings, integers without
//! sign, the booleans `true` and `false`, and lists of strings. The comments are `#`, `//` and `/* */`.
//!
//! The reader works on the bytes of the file. A line and a column count bytes from 1. Each error starts with
//! `line L:C:`. An attribute name that is two times in one block stops the read.

use super::quote::{quote_bytes, quote_char, unquote};

/// The kind of a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// A quoted string.
    String,
    /// `true` or `false`.
    Bool,
    /// A list of quoted strings.
    List,
    /// An integer.
    Number,
}

impl Kind {
    /// The expected form in the message of a value of a wrong kind.
    pub(super) fn expected(self) -> &'static str {
        match self {
            Self::String => "a quoted string",
            Self::Bool => "a boolean",
            Self::List => "a string list",
            Self::Number => "an integer",
        }
    }
}

/// The data of a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Data {
    /// A quoted string, after its escapes.
    String(String),
    /// A boolean.
    Bool(bool),
    /// A list of strings.
    List(Vec<Value>),
    /// An integer from 0 to 9223372036854775807.
    Number(i64),
}

/// A value and its position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Value {
    pub(super) data: Data,
    pub(super) line: usize,
    pub(super) column: usize,
}

impl Value {
    pub(super) fn kind(&self) -> Kind {
        match self.data {
            Data::String(_) => Kind::String,
            Data::Bool(_) => Kind::Bool,
            Data::List(_) => Kind::List,
            Data::Number(_) => Kind::Number,
        }
    }
}

/// An attribute and the position of its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Attr {
    pub(super) name: Vec<u8>,
    pub(super) value: Value,
    pub(super) line: usize,
    pub(super) column: usize,
}

/// A block: its type, its labels, its attributes in the order of the file and its nested blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Block {
    pub(super) kind: Vec<u8>,
    pub(super) labels: Vec<Vec<u8>>,
    pub(super) attrs: Vec<Attr>,
    pub(super) blocks: Vec<Block>,
    pub(super) line: usize,
    pub(super) column: usize,
}

impl Block {
    fn new(kind: Vec<u8>, line: usize, column: usize) -> Self {
        Self {
            kind,
            labels: Vec::new(),
            attrs: Vec::new(),
            blocks: Vec::new(),
            line,
            column,
        }
    }

    /// The text of an error at the position of the block.
    pub(super) fn error(&self, message: impl std::fmt::Display) -> String {
        format!("line {}:{}: {message}", self.line, self.column)
    }

    /// The type of the block as text.
    pub(super) fn kind_text(&self) -> String {
        String::from_utf8_lossy(&self.kind).into_owned()
    }

    /// The attribute with this name.
    pub(super) fn attr(&self, name: &str) -> Option<&Attr> {
        self.attrs.iter().find(|attr| attr.name == name.as_bytes())
    }

    /// The value of a string attribute. An attribute of another kind gives `None`.
    pub(super) fn string(&self, name: &str) -> Option<&str> {
        match &self.attr(name)?.value.data {
            Data::String(text) => Some(text),
            _ => None,
        }
    }

    /// The value of a boolean attribute.
    pub(super) fn boolean(&self, name: &str) -> Option<bool> {
        match self.attr(name)?.value.data {
            Data::Bool(value) => Some(value),
            _ => None,
        }
    }

    /// The value of an integer attribute.
    pub(super) fn integer(&self, name: &str) -> Option<i64> {
        match self.attr(name)?.value.data {
            Data::Number(value) => Some(value),
            _ => None,
        }
    }

    /// The values of a list attribute.
    pub(super) fn strings(&self, name: &str) -> Option<Vec<String>> {
        match &self.attr(name)?.value.data {
            Data::List(values) => values
                .iter()
                .map(|value| match &value.data {
                    Data::String(text) => Some(text.clone()),
                    _ => None,
                })
                .collect(),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenKind {
    Eof,
    Ident,
    String,
    Number,
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    Equal,
    Comma,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    text: Vec<u8>,
    line: usize,
    column: usize,
}

/// A white space byte: tab, line feed, vertical tab, form feed, carriage return, space, 0x85 and 0xA0.
fn is_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ' | 0x85 | 0xa0)
}

/// A letter: a byte that is a letter when it is read as the character with the same number (A to Z, a to z and the
/// letters from 0xAA to 0xFF).
fn is_letter(byte: u8) -> bool {
    char::from(byte).is_alphabetic()
}

fn is_ident_start(byte: u8) -> bool {
    is_letter(byte) || byte == b'_'
}

fn is_ident_part(byte: u8) -> bool {
    is_letter(byte) || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
}

struct Lexer<'a> {
    source: &'a [u8],
    pos: usize,
    line: usize,
    column: usize,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            pos: 0,
            line: 1,
            column: 1,
        }
    }

    fn byte_at(&self, pos: usize) -> Option<u8> {
        self.source.get(pos).copied()
    }

    fn advance(&mut self) {
        let Some(byte) = self.byte_at(self.pos) else {
            return;
        };
        if byte == b'\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        self.pos += 1;
    }

    fn token(&mut self, kind: TokenKind, start: usize, line: usize, column: usize) -> Token {
        Token {
            kind,
            text: self.source.get(start..self.pos).unwrap_or_default().to_vec(),
            line,
            column,
        }
    }

    fn next_token(&mut self) -> Result<Token, String> {
        self.skip_space_and_comments()?;
        let (line, column, start) = (self.line, self.column, self.pos);
        let Some(byte) = self.byte_at(self.pos) else {
            return Ok(Token {
                kind: TokenKind::Eof,
                text: Vec::new(),
                line,
                column,
            });
        };
        let single = match byte {
            b'{' => Some(TokenKind::LeftBrace),
            b'}' => Some(TokenKind::RightBrace),
            b'[' => Some(TokenKind::LeftBracket),
            b']' => Some(TokenKind::RightBracket),
            b'=' => Some(TokenKind::Equal),
            b',' => Some(TokenKind::Comma),
            _ => None,
        };
        if let Some(kind) = single {
            self.advance();
            return Ok(self.token(kind, start, line, column));
        }
        if byte == b'"' {
            return self.scan_string();
        }
        if byte.is_ascii_digit() {
            while self.byte_at(self.pos).is_some_and(|b| b.is_ascii_digit()) {
                self.advance();
            }
            return Ok(self.token(TokenKind::Number, start, line, column));
        }
        if is_ident_start(byte) {
            while self.byte_at(self.pos).is_some_and(is_ident_part) {
                self.advance();
            }
            return Ok(self.token(TokenKind::Ident, start, line, column));
        }
        Err(format!(
            "line {line}:{column}: unexpected character {}",
            quote_char(u32::from(byte))
        ))
    }

    fn skip_space_and_comments(&mut self) -> Result<(), String> {
        while let Some(byte) = self.byte_at(self.pos) {
            if is_space(byte) {
                self.advance();
                continue;
            }
            if byte == b'#' {
                self.skip_line();
                continue;
            }
            if byte == b'/' {
                match self.byte_at(self.pos + 1) {
                    Some(b'/') => {
                        self.skip_line();
                        continue;
                    }
                    Some(b'*') => {
                        let (line, column) = (self.line, self.column);
                        self.advance();
                        self.advance();
                        while self.pos + 1 < self.source.len()
                            && !(self.byte_at(self.pos) == Some(b'*') && self.byte_at(self.pos + 1) == Some(b'/'))
                        {
                            self.advance();
                        }
                        if self.pos + 1 >= self.source.len() {
                            return Err(format!("line {line}:{column}: unterminated block comment"));
                        }
                        self.advance();
                        self.advance();
                        continue;
                    }
                    _ => {}
                }
            }
            break;
        }
        Ok(())
    }

    fn skip_line(&mut self) {
        while let Some(byte) = self.byte_at(self.pos) {
            self.advance();
            if byte == b'\n' {
                return;
            }
        }
    }

    fn scan_string(&mut self) -> Result<Token, String> {
        let (line, column, start) = (self.line, self.column, self.pos);
        self.advance();
        while let Some(byte) = self.byte_at(self.pos) {
            if byte == b'\n' || byte == b'\r' {
                return Err(format!(
                    "line {line}:{column}: quoted strings cannot contain a raw newline"
                ));
            }
            if byte == b'\\' {
                self.advance();
                if self.pos >= self.source.len() {
                    break;
                }
                self.advance();
                continue;
            }
            self.advance();
            if byte == b'"' {
                let raw = self.source.get(start..self.pos).unwrap_or_default();
                let Some(value) = unquote(raw) else {
                    return Err(format!(
                        "line {line}:{column}: invalid string: bad escape or bad character"
                    ));
                };
                if std::str::from_utf8(&value).is_err() {
                    return Err(format!(
                        "line {line}:{column}: invalid string: an escape gives bytes that are not UTF-8"
                    ));
                }
                return Ok(Token {
                    kind: TokenKind::String,
                    text: value,
                    line,
                    column,
                });
            }
        }
        Err(format!("line {line}:{column}: unterminated string"))
    }
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    peeked: Option<Token>,
}

impl Parser<'_> {
    fn peek(&mut self) -> Result<Token, String> {
        if let Some(token) = &self.peeked {
            return Ok(token.clone());
        }
        let token = self.lexer.next_token()?;
        self.peeked = Some(token.clone());
        Ok(token)
    }

    fn next(&mut self) -> Result<Token, String> {
        if let Some(token) = self.peeked.take() {
            return Ok(token);
        }
        self.lexer.next_token()
    }

    fn parse_body(&mut self, target: &mut Block, stop_at_brace: bool) -> Result<(), String> {
        loop {
            let token = self.peek()?;
            match token.kind {
                TokenKind::Eof => {
                    if stop_at_brace {
                        return Err(target.error("expected closing brace"));
                    }
                    return Ok(());
                }
                TokenKind::RightBrace => {
                    if !stop_at_brace {
                        return Err(format!(
                            "line {}:{}: unexpected closing brace",
                            token.line, token.column
                        ));
                    }
                    self.next()?;
                    return Ok(());
                }
                TokenKind::Ident => {}
                _ => {
                    return Err(format!(
                        "line {}:{}: expected attribute or block name",
                        token.line, token.column
                    ));
                }
            }
            let name = self.next()?;
            let mut next = self.peek()?;
            if next.kind == TokenKind::Equal {
                self.next()?;
                let value = self.parse_value()?;
                if target.attrs.iter().any(|attr| attr.name == name.text) {
                    return Err(format!(
                        "line {}:{}: duplicate attribute {}",
                        name.line,
                        name.column,
                        quote_bytes(&name.text)
                    ));
                }
                target.attrs.push(Attr {
                    name: name.text,
                    value,
                    line: name.line,
                    column: name.column,
                });
                continue;
            }
            let mut block = Block::new(name.text.clone(), name.line, name.column);
            while next.kind == TokenKind::String || next.kind == TokenKind::Ident {
                let label = self.next()?;
                block.labels.push(label.text);
                next = self.peek()?;
            }
            if next.kind != TokenKind::LeftBrace {
                return Err(format!(
                    "line {}:{}: expected '=' or '{{' after {}",
                    next.line,
                    next.column,
                    quote_bytes(&name.text)
                ));
            }
            self.next()?;
            self.parse_body(&mut block, true)?;
            target.blocks.push(block);
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        let token = self.next()?;
        let (line, column) = (token.line, token.column);
        let value = |data| Value { data, line, column };
        match token.kind {
            TokenKind::String => Ok(value(Data::String(
                String::from_utf8(token.text).map_err(|_| format!("line {line}:{column}: invalid string"))?,
            ))),
            TokenKind::Number => {
                let parsed = std::str::from_utf8(&token.text)
                    .ok()
                    .and_then(|text| text.parse::<i64>().ok());
                match parsed {
                    Some(number) => Ok(value(Data::Number(number))),
                    None => Err(format!(
                        "line {line}:{column}: invalid integer {}",
                        quote_bytes(&token.text)
                    )),
                }
            }
            TokenKind::Ident => match token.text.as_slice() {
                b"true" => Ok(value(Data::Bool(true))),
                b"false" => Ok(value(Data::Bool(false))),
                _ => Err(format!(
                    "line {line}:{column}: bare value {} is not supported; quote strings",
                    quote_bytes(&token.text)
                )),
            },
            TokenKind::LeftBracket => {
                let mut items = Vec::new();
                loop {
                    let next = self.peek()?;
                    if next.kind == TokenKind::RightBracket {
                        self.next()?;
                        return Ok(value(Data::List(items)));
                    }
                    let item = self.parse_value()?;
                    if item.kind() != Kind::String {
                        return Err(format!(
                            "line {}:{}: lists may only contain strings",
                            item.line, item.column
                        ));
                    }
                    items.push(item);
                    let next = self.peek()?;
                    if next.kind == TokenKind::Comma {
                        self.next()?;
                        continue;
                    }
                    if next.kind != TokenKind::RightBracket {
                        return Err(format!("line {}:{}: expected ',' or ']'", next.line, next.column));
                    }
                }
            }
            _ => Err(format!("line {line}:{column}: expected a value")),
        }
    }
}

/// Read the text of a configuration file into its root block (type `root`, at line 1, column 1).
pub(super) fn parse(source: &[u8]) -> Result<Block, String> {
    let mut parser = Parser {
        lexer: Lexer::new(source),
        peeked: None,
    };
    let mut root = Block::new(b"root".to_vec(), 1, 1);
    parser.parse_body(&mut root, false)?;
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_of(source: &str) -> String {
        parse(source.as_bytes()).err().unwrap_or_default()
    }

    #[test]
    fn comments_and_escapes_are_read() {
        let root = parse(
            b"\n// line comment\nserver { listen = \":8080\" }\n/* block comment */\nbucket \"one\" {\n  name = \"A\\nB\"\n  permissions = [\"read\", \"write\",]\n}\n",
        )
        .unwrap();
        assert_eq!(root.blocks.len(), 2);
        assert_eq!(root.blocks[1].string("name"), Some("A\nB"));
        assert_eq!(
            root.blocks[1].strings("permissions"),
            Some(vec!["read".to_owned(), "write".to_owned()])
        );
        assert_eq!(root.blocks[0].string("listen"), Some(":8080"));
    }

    #[test]
    fn values_have_their_kinds_and_positions() {
        let root = parse(b"a = 15\nb = true\nc = false\nd = []\nx y \"z\" {\n  e = \"f\" }\n").unwrap();
        assert_eq!(root.integer("a"), Some(15));
        assert_eq!(root.boolean("b"), Some(true));
        assert_eq!(root.boolean("c"), Some(false));
        assert_eq!(root.strings("d"), Some(Vec::new()));
        let block = &root.blocks[0];
        assert_eq!(block.kind, b"x");
        assert_eq!(block.labels, vec![b"y".to_vec(), b"z".to_vec()]);
        assert_eq!((block.line, block.column), (5, 1));
        let attr = block.attr("e").unwrap();
        assert_eq!((attr.line, attr.column), (6, 3));
        assert_eq!((attr.value.line, attr.value.column), (6, 7));
    }

    #[test]
    fn each_syntax_error_gives_its_position() {
        assert_eq!(error_of("a = -5"), "line 1:5: unexpected character '-'");
        assert_eq!(error_of("a = 1\na = 2"), "line 2:1: duplicate attribute \"a\"");
        assert_eq!(error_of("a = \"x"), "line 1:5: unterminated string");
        assert_eq!(
            error_of("a = \"x\ny\""),
            "line 1:5: quoted strings cannot contain a raw newline"
        );
        assert_eq!(
            error_of("a = \"\\q\""),
            "line 1:5: invalid string: bad escape or bad character"
        );
        assert_eq!(error_of("/* x"), "line 1:1: unterminated block comment");
        assert_eq!(error_of("  b {\n"), "line 1:3: expected closing brace");
        assert_eq!(error_of("}"), "line 1:1: unexpected closing brace");
        assert_eq!(error_of("\"a\" = 1"), "line 1:1: expected attribute or block name");
        assert_eq!(error_of("b c = 1"), "line 1:5: expected '=' or '{' after \"b\"");
        assert_eq!(
            error_of("a = b"),
            "line 1:5: bare value \"b\" is not supported; quote strings"
        );
        assert_eq!(error_of("a = [1]"), "line 1:6: lists may only contain strings");
        assert_eq!(error_of("a = [\"x\" \"y\"]"), "line 1:10: expected ',' or ']'");
        assert_eq!(error_of("a = ="), "line 1:5: expected a value");
        assert_eq!(error_of("a ="), "line 1:4: expected a value");
        assert_eq!(
            error_of("a = 99999999999999999999"),
            "line 1:5: invalid integer \"99999999999999999999\""
        );
        assert_eq!(error_of("a = /"), "line 1:5: unexpected character '/'");
        assert_eq!(
            error_of("a = \"\\xff\""),
            "line 1:5: invalid string: an escape gives bytes that are not UTF-8"
        );
    }

    #[test]
    fn a_value_error_comes_before_the_duplicate_error() {
        assert_eq!(
            error_of("a = 1\na = b"),
            "line 2:5: bare value \"b\" is not supported; quote strings"
        );
    }

    #[test]
    fn identifiers_take_letters_digits_underscores_and_dashes() {
        let root = parse("_a-1 = 1\nêê = 2".as_bytes()).unwrap();
        assert_eq!(root.integer("_a-1"), Some(1));
        assert_eq!(root.integer("êê"), Some(2));
        assert_eq!(error_of("é = 1"), "line 1:2: unexpected character '©'");
    }

    #[test]
    fn the_bytes_0x85_and_0xa0_are_spaces() {
        let root = parse(b"a\xa0=\x85\"x\"").unwrap();
        assert_eq!(root.string("a"), Some("x"));
    }

    #[test]
    fn comments_can_hold_bytes_that_are_not_utf8() {
        let root = parse(b"# caf\xe9\na = 1 // \xff\n").unwrap();
        assert_eq!(root.integer("a"), Some(1));
    }
}
