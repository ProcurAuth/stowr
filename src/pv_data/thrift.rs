// SPDX-License-Identifier: MIT OR Apache-2.0
//! A small reader of the Thrift compact protocol: the field headers, the collection headers, the integers in zigzag
//! varint form, the binary values and the skip of the unknown values. The Parquet metadata uses it.
//!
//! The skip of nested values stops at a depth of 64, and each declared count of a collection must fit in the bytes
//! that remain: a hostile footer cannot use the stack or the processor without limit.

use std::fmt;

/// The deepest level of the skipped structures and collections.
pub(crate) const MAX_SKIP_DEPTH: usize = 64;

/// The end of a structure.
pub(crate) const STOP: u8 = 0;
/// A boolean `true` (in a field header).
pub(crate) const BOOLEAN_TRUE: u8 = 1;
/// A boolean `false` (in a field header).
pub(crate) const BOOLEAN_FALSE: u8 = 2;
/// A byte.
pub(crate) const BYTE: u8 = 3;
/// A 16-bit integer.
pub(crate) const I16: u8 = 4;
/// A 32-bit integer.
pub(crate) const I32: u8 = 5;
/// A 64-bit integer.
pub(crate) const I64: u8 = 6;
/// A double.
pub(crate) const DOUBLE: u8 = 7;
/// A binary value or a text.
pub(crate) const BINARY: u8 = 8;
/// A list.
pub(crate) const LIST: u8 = 9;
/// A set.
pub(crate) const SET: u8 = 10;
/// A map.
pub(crate) const MAP: u8 = 11;
/// A structure.
pub(crate) const STRUCT: u8 = 12;

/// An error of the reader. The text is the message of the answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ThriftError(pub(crate) String);

impl fmt::Display for ThriftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl ThriftError {
    /// An error with a message.
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The end of the bytes before the end of a value.
    pub(crate) fn unexpected_end() -> Self {
        Self::new("unexpected end of the data")
    }
}

/// The result of the reader.
pub(crate) type ThriftResult<T> = Result<T, ThriftError>;

/// A reader of Thrift compact bytes.
#[derive(Debug)]
pub(crate) struct CompactReader<'a> {
    /// The bytes.
    pub(crate) data: &'a [u8],
    /// The offset of the next byte.
    pub(crate) pos: usize,
    depth: usize,
}

/// The value of a zigzag integer.
pub(crate) fn decode_zigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

impl<'a> CompactReader<'a> {
    /// A reader at the start of the bytes.
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, depth: 0 }
    }

    /// The bytes that remain.
    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Read one byte.
    pub(crate) fn read_byte(&mut self) -> ThriftResult<u8> {
        let value = *self.data.get(self.pos).ok_or_else(ThriftError::unexpected_end)?;
        self.pos += 1;
        Ok(value)
    }

    /// Skip `count` bytes.
    pub(crate) fn advance(&mut self, count: usize) -> ThriftResult<()> {
        if count > self.remaining() {
            return Err(ThriftError::unexpected_end());
        }
        self.pos += count;
        Ok(())
    }

    /// Read an unsigned varint of at most ten bytes.
    pub(crate) fn read_varint(&mut self) -> ThriftResult<u64> {
        let mut value: u64 = 0;
        let mut shift = 0;
        while shift < 64 {
            let byte = self.read_byte()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
        Err(ThriftError::new("invalid Thrift varint"))
    }

    /// Read a zigzag integer.
    pub(crate) fn read_zigzag(&mut self) -> ThriftResult<i64> {
        Ok(decode_zigzag(self.read_varint()?))
    }

    /// Read a field header after the field `last`: the field id, the type and the id to keep as `last`. The type
    /// [`STOP`] ends the structure.
    pub(crate) fn field_header(&mut self, last: i16) -> ThriftResult<(i16, u8, i16)> {
        let value = self.read_byte()?;
        let field_type = value & 0x0f;
        if field_type == STOP {
            return Ok((0, STOP, last));
        }
        let delta = i16::from(value >> 4);
        let field_id = if delta == 0 {
            decode_zigzag(self.read_varint()?) as i16
        } else {
            last.wrapping_add(delta)
        };
        Ok((field_id, field_type, field_id))
    }

    /// Read a list or set header: the number of elements and their type.
    pub(crate) fn collection_header(&mut self) -> ThriftResult<(usize, u8)> {
        let value = self.read_byte()?;
        let mut size = usize::from(value >> 4);
        let element_type = value & 0x0f;
        if size == 15 {
            let raw = self.read_varint()?;
            if raw > 1 << 31 {
                return Err(ThriftError::new("Thrift collection is too large"));
            }
            size = raw as usize;
        }
        Ok((size, element_type))
    }

    /// Read an integer of type i16, i32 or i64.
    pub(crate) fn read_integer(&mut self, field_type: u8) -> ThriftResult<i64> {
        if !matches!(field_type, I16 | I32 | I64) {
            return Err(ThriftError::new(format!("unexpected Thrift integer type {field_type}")));
        }
        self.read_zigzag()
    }

    /// Read a binary value as bytes. A value longer than `max_length` is skipped and gives no bytes.
    pub(crate) fn read_binary(&mut self, max_length: usize) -> ThriftResult<&'a [u8]> {
        let length = self.read_varint()?;
        if length > self.remaining() as u64 {
            return Err(ThriftError::unexpected_end());
        }
        let length = length as usize;
        if length > max_length {
            self.advance(length)?;
            return Ok(&[]);
        }
        let value = &self.data[self.pos..self.pos + length];
        self.pos += length;
        Ok(value)
    }

    /// Skip one value of a field.
    pub(crate) fn skip(&mut self, field_type: u8) -> ThriftResult<()> {
        self.skip_value(field_type, false)
    }

    /// Skip one value. In a collection each element has at least one byte, also a boolean; a boolean field has no
    /// byte after its header.
    pub(crate) fn skip_value(&mut self, field_type: u8, in_collection: bool) -> ThriftResult<()> {
        match field_type {
            BOOLEAN_TRUE | BOOLEAN_FALSE => {
                if in_collection {
                    self.advance(1)
                } else {
                    Ok(())
                }
            }
            STOP => {
                if in_collection {
                    Err(ThriftError::new("invalid Thrift collection element type"))
                } else {
                    Ok(())
                }
            }
            BYTE => self.read_byte().map(|_| ()),
            I16 | I32 | I64 => self.read_varint().map(|_| ()),
            DOUBLE => self.advance(8),
            BINARY => {
                let length = self.read_varint()?;
                if length > self.data.len() as u64 {
                    return Err(ThriftError::unexpected_end());
                }
                self.advance(length as usize)
            }
            LIST | SET | MAP | STRUCT => {
                if self.depth >= MAX_SKIP_DEPTH {
                    return Err(ThriftError::new("Thrift metadata is nested too deeply"));
                }
                self.depth += 1;
                let result = self.skip_container(field_type);
                self.depth -= 1;
                result
            }
            other => Err(ThriftError::new(format!("unsupported Thrift compact type {other}"))),
        }
    }

    fn skip_container(&mut self, field_type: u8) -> ThriftResult<()> {
        match field_type {
            LIST | SET => {
                let (size, element_type) = self.collection_header()?;
                if size == 0 {
                    return Ok(());
                }
                if size > self.remaining() {
                    return Err(ThriftError::unexpected_end());
                }
                for _ in 0..size {
                    self.skip_value(element_type, true)?;
                }
                Ok(())
            }
            MAP => {
                let size = self.read_varint()?;
                if size == 0 {
                    return Ok(());
                }
                if size > (self.remaining() / 2) as u64 {
                    return Err(ThriftError::unexpected_end());
                }
                let types = self.read_byte()?;
                let (key_type, value_type) = (types >> 4, types & 0x0f);
                for _ in 0..size {
                    self.skip_value(key_type, true)?;
                    self.skip_value(value_type, true)?;
                }
                Ok(())
            }
            _ => {
                let mut last = 0;
                loop {
                    let (_, nested_type, next_last) = self.field_header(last)?;
                    if nested_type == STOP {
                        return Ok(());
                    }
                    last = next_last;
                    self.skip_value(nested_type, false)?;
                }
            }
        }
    }
}
