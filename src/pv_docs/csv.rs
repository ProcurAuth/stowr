// SPDX-License-Identifier: MIT OR Apache-2.0
//! The reader of delimited records over an [`ObjectStream`].
//!
//! The rules of the reader:
//! - A record ends at a line feed. A carriage return before the line feed goes away.
//! - An empty line is not a record.
//! - A field in quotes can have the delimiter, line ends and `""` for a quote.
//! - A quote in a field without quotes, or a quote that closes a field and has other text after it, is an error.
//! - A record can have any number of fields.
//!
//! The reader counts the bytes that it took from the stream. The count is the offset after the last record.

use super::stream::ObjectStream;
use crate::common::error::Error;

/// Why a read of a record failed.
#[derive(Debug)]
pub enum CsvFailure {
    /// The text is not valid. The message has the line and the column.
    Parse(String),
    /// The read of the object failed.
    Source(Error),
}

impl From<Error> for CsvFailure {
    fn from(error: Error) -> Self {
        Self::Source(error)
    }
}

const BARE_QUOTE: &str = "a quote in a field that does not start with a quote";
const BAD_QUOTE: &str = "a quote is missing or extra in a quoted field";

fn parse_failure(start_line: i64, line: i64, column: usize, reason: &str) -> CsvFailure {
    if start_line != line {
        return CsvFailure::Parse(format!(
            "CSV error on line {line}, column {column}, in the record that starts on line {start_line}: {reason}"
        ));
    }
    CsvFailure::Parse(format!("CSV error on line {line}, column {column}: {reason}"))
}

/// 1 when the bytes end with a line feed, else 0.
fn length_newline(bytes: &[u8]) -> usize {
    usize::from(bytes.last() == Some(&b'\n'))
}

/// A reader of records.
pub struct CsvReader<'a> {
    stream: &'a mut ObjectStream,
    comma: u8,
    line_number: i64,
    offset: i64,
}

impl<'a> CsvReader<'a> {
    /// A reader over a stream with this delimiter.
    pub fn new(stream: &'a mut ObjectStream, comma: u8) -> Self {
        Self {
            stream,
            comma,
            line_number: 0,
            offset: 0,
        }
    }

    /// The number of bytes that the reader took from the stream.
    pub fn input_offset(&self) -> i64 {
        self.offset
    }

    /// The next line, with `\r\n` changed to `\n`. `None` at the end of the object.
    async fn read_line(&mut self) -> Result<Option<Vec<u8>>, CsvFailure> {
        let line = self.stream.read_line().await?;
        self.line_number += 1;
        let Some(mut line) = line else {
            return Ok(None);
        };
        self.offset += i64::try_from(line.len()).unwrap_or(0);
        // A carriage return at the very end of the object goes away.
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let length = line.len();
        if length >= 2 && line[length - 2] == b'\r' && line[length - 1] == b'\n' {
            line[length - 2] = b'\n';
            line.pop();
        }
        Ok(Some(line))
    }

    /// The next record, or `None` at the end of the object. A field is bytes: the reader does not check the
    /// encoding.
    pub async fn read(&mut self) -> Result<Option<Vec<Vec<u8>>>, CsvFailure> {
        let mut line = loop {
            let Some(line) = self.read_line().await? else {
                return Ok(None);
            };
            if line.len() == length_newline(&line) {
                continue;
            }
            break line;
        };
        let record_line = self.line_number;
        let mut fields: Vec<Vec<u8>> = Vec::new();
        let mut position_line = self.line_number;
        let mut column: usize = 1;
        let mut start = 0usize;
        'fields: loop {
            let rest = &line[start..];
            if rest.is_empty() || rest[0] != b'"' {
                let comma_at = rest.iter().position(|byte| *byte == self.comma);
                let field = match comma_at {
                    Some(index) => &rest[..index],
                    None => &rest[..rest.len() - length_newline(rest)],
                };
                if let Some(quote) = field.iter().position(|byte| *byte == b'"') {
                    return Err(parse_failure(record_line, self.line_number, column + quote, BARE_QUOTE));
                }
                fields.push(field.to_vec());
                if let Some(index) = comma_at {
                    start += index + 1;
                    column += index + 1;
                    continue 'fields;
                }
                break 'fields;
            }
            start += 1;
            column += 1;
            let mut field: Vec<u8> = Vec::new();
            loop {
                let rest = &line[start..];
                if let Some(quote) = rest.iter().position(|byte| *byte == b'"') {
                    field.extend_from_slice(&rest[..quote]);
                    start += quote + 1;
                    column += quote + 1;
                    let after = &line[start..];
                    if after.first() == Some(&b'"') {
                        field.push(b'"');
                        start += 1;
                        column += 1;
                    } else if after.first() == Some(&self.comma) {
                        start += 1;
                        column += 1;
                        fields.push(field);
                        continue 'fields;
                    } else if length_newline(after) == after.len() {
                        fields.push(field);
                        break 'fields;
                    } else {
                        return Err(parse_failure(record_line, self.line_number, column - 1, BAD_QUOTE));
                    }
                } else if !rest.is_empty() {
                    field.extend_from_slice(rest);
                    column += rest.len();
                    match self.read_line().await? {
                        Some(next) => {
                            if !next.is_empty() {
                                position_line += 1;
                                column = 1;
                            }
                            line = next;
                            start = 0;
                        }
                        None => {
                            line = Vec::new();
                            start = 0;
                        }
                    }
                } else {
                    return Err(parse_failure(record_line, position_line, column, BAD_QUOTE));
                }
            }
        }
        Ok(Some(fields))
    }
}
