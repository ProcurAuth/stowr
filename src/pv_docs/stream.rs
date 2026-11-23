// SPDX-License-Identifier: MIT OR Apache-2.0
//! A buffered byte reader over an object: the windows of a [`WindowReader`], or the body of a read.
//!
//! The reader keeps one chunk at a time. It never holds more than a chunk and the bytes that a caller asks to
//! see in front (a sample, a line).

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;

#[cfg(test)]
use super::util::REPLACEMENT;
use super::util::{decode_rune, full_rune};
use crate::common::error::Result;
use crate::common::http::Body;
use crate::instance::range::{ObjectVersion, WindowReader};

/// Where the chunks come from.
pub enum ChunkSource {
    /// The windows of exact ranges of an object.
    Windows(Box<WindowReader>),
    /// The body of one read of an object.
    Body(Body),
    /// Chunks in memory.
    #[cfg(test)]
    Memory(std::collections::VecDeque<Bytes>),
}

impl ChunkSource {
    /// The next chunk, or an empty chunk at the end.
    async fn next(&mut self) -> Result<Bytes> {
        match self {
            Self::Windows(reader) => reader.next_chunk().await,
            Self::Body(body) => loop {
                match body.frame().await {
                    None => return Ok(Bytes::new()),
                    Some(frame) => {
                        if let Ok(data) = frame?.into_data()
                            && !data.is_empty()
                        {
                            return Ok(data);
                        }
                    }
                }
            },
            #[cfg(test)]
            Self::Memory(chunks) => Ok(chunks.pop_front().unwrap_or_default()),
        }
    }
}

/// A reader of bytes and of characters, in order, with a count of the bytes that it gave.
pub struct ObjectStream {
    source: ChunkSource,
    chunk: Bytes,
    position: usize,
    offset: i64,
    ended: bool,
}

impl ObjectStream {
    /// A reader. `offset` is the position of the first byte in the object.
    pub fn new(source: ChunkSource, offset: i64) -> Self {
        Self {
            source,
            chunk: Bytes::new(),
            position: 0,
            offset,
            ended: false,
        }
    }

    /// A reader over the windows of an object, from the offset of the window reader.
    pub fn windows(reader: WindowReader) -> Self {
        let offset = reader.offset;
        Self::new(ChunkSource::Windows(Box::new(reader)), offset)
    }

    /// A reader over the body of a read, from the start of the object.
    pub fn body(body: Body) -> Self {
        Self::new(ChunkSource::Body(body), 0)
    }

    /// The reader over bytes in memory, in chunks.
    #[cfg(test)]
    pub fn memory(chunks: Vec<Bytes>) -> Self {
        Self::new(ChunkSource::Memory(chunks.into()), 0)
    }

    /// The position of the next byte in the object.
    pub fn offset(&self) -> i64 {
        self.offset
    }

    /// The version of the object that the reads found. The body of a read has none.
    pub fn version(&self) -> ObjectVersion {
        match &self.source {
            ChunkSource::Windows(reader) => reader.version(),
            _ => ObjectVersion::default(),
        }
    }

    fn buffered(&self) -> &[u8] {
        &self.chunk[self.position..]
    }

    /// Make sure that a byte is in the buffer. False at the end of the object.
    async fn fill(&mut self) -> Result<bool> {
        while self.position >= self.chunk.len() {
            if self.ended {
                return Ok(false);
            }
            let next = self.source.next().await?;
            if next.is_empty() {
                self.ended = true;
                return Ok(false);
            }
            self.chunk = next;
            self.position = 0;
        }
        Ok(true)
    }

    /// Make sure that the buffer has at least `count` bytes, or all the bytes that remain. The bytes that remain
    /// in the buffer stay in front of the new bytes.
    async fn fill_at_least(&mut self, count: usize) -> Result<()> {
        while self.buffered().len() < count && !self.ended {
            let next = self.source.next().await?;
            if next.is_empty() {
                self.ended = true;
                break;
            }
            let mut joined = BytesMut::with_capacity(self.buffered().len() + next.len());
            joined.extend_from_slice(self.buffered());
            joined.extend_from_slice(&next);
            self.chunk = joined.freeze();
            self.position = 0;
        }
        Ok(())
    }

    /// The next byte without a move. `None` at the end of the object.
    pub async fn peek_byte(&mut self) -> Result<Option<u8>> {
        if !self.fill().await? {
            return Ok(None);
        }
        Ok(self.chunk.get(self.position).copied())
    }

    /// The next byte. `None` at the end of the object.
    pub async fn read_byte(&mut self) -> Result<Option<u8>> {
        if !self.fill().await? {
            return Ok(None);
        }
        let value = self.chunk.get(self.position).copied();
        self.position += 1;
        self.offset += 1;
        Ok(value)
    }

    /// The next character and its width in bytes. A byte that does not start a valid sequence gives the
    /// replacement character and the width 1. `None` at the end of the object.
    pub async fn read_rune(&mut self) -> Result<Option<(char, usize)>> {
        if !self.fill().await? {
            return Ok(None);
        }
        let first = self.chunk[self.position];
        if first < 0x80 {
            self.position += 1;
            self.offset += 1;
            return Ok(Some((char::from(first), 1)));
        }
        if !full_rune(self.buffered()) {
            self.fill_at_least(4).await?;
        }
        let (value, width) = decode_rune(self.buffered());
        let width = width.max(1);
        self.position += width;
        self.offset += i64::try_from(width).unwrap_or(1);
        Ok(Some((value, width)))
    }

    /// The first `count` bytes that remain, without a move: fewer at the end of the object.
    pub async fn peek(&mut self, count: usize) -> Result<Bytes> {
        self.fill_at_least(count).await?;
        let end = (self.position + count).min(self.chunk.len());
        Ok(self.chunk.slice(self.position..end))
    }

    /// The bytes up to the first line feed (it is in the result), at most `limit` bytes. The result is shorter at
    /// the end of the object. `None` when no byte remains.
    pub async fn read_slice(&mut self, limit: usize) -> Result<Option<Vec<u8>>> {
        let mut line: Vec<u8> = Vec::new();
        loop {
            if !self.fill().await? {
                return Ok(if line.is_empty() { None } else { Some(line) });
            }
            let room = limit - line.len();
            let available = self.buffered();
            let window = &available[..available.len().min(room)];
            if let Some(index) = window.iter().position(|byte| *byte == b'\n') {
                line.extend_from_slice(&window[..=index]);
                self.position += index + 1;
                self.offset += i64::try_from(index + 1).unwrap_or(0);
                return Ok(Some(line));
            }
            let taken = window.len();
            line.extend_from_slice(window);
            self.position += taken;
            self.offset += i64::try_from(taken).unwrap_or(0);
            if line.len() >= limit {
                return Ok(Some(line));
            }
        }
    }

    /// The bytes that remain in the buffer, or the next chunk. `None` at the end of the object.
    pub async fn take_chunk(&mut self) -> Result<Option<Bytes>> {
        if !self.fill().await? {
            return Ok(None);
        }
        let chunk = self.chunk.slice(self.position..);
        self.position = self.chunk.len();
        self.offset += i64::try_from(chunk.len()).unwrap_or(0);
        Ok(Some(chunk))
    }

    /// The bytes up to the first line feed with no limit. `None` when no byte remains.
    pub async fn read_line(&mut self) -> Result<Option<Vec<u8>>> {
        self.read_slice(usize::MAX).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(chunks: &[&[u8]]) -> ObjectStream {
        ObjectStream::memory(chunks.iter().map(|chunk| Bytes::copy_from_slice(chunk)).collect())
    }

    #[tokio::test]
    async fn a_character_in_two_chunks_is_one_character() {
        let bytes = "é雪".as_bytes();
        let mut reader = stream(&[&bytes[..1], &bytes[1..4], &bytes[4..]]);
        assert_eq!(reader.read_rune().await.unwrap(), Some(('é', 2)));
        assert_eq!(reader.read_rune().await.unwrap(), Some(('雪', 3)));
        assert_eq!(reader.read_rune().await.unwrap(), None);
        assert_eq!(reader.offset(), 5);
    }

    #[tokio::test]
    async fn a_broken_sequence_gives_one_replacement_for_each_byte() {
        let mut reader = stream(&[&[0xE2, 0x82], b"a"]);
        assert_eq!(reader.read_rune().await.unwrap(), Some((REPLACEMENT, 1)));
        assert_eq!(reader.read_rune().await.unwrap(), Some((REPLACEMENT, 1)));
        assert_eq!(reader.read_rune().await.unwrap(), Some(('a', 1)));
    }

    #[tokio::test]
    async fn a_slice_stops_at_the_line_feed_or_at_the_limit() {
        let mut reader = stream(&[b"ab\ncd", b"efgh"]);
        assert_eq!(reader.read_slice(10).await.unwrap(), Some(b"ab\n".to_vec()));
        assert_eq!(reader.read_slice(3).await.unwrap(), Some(b"cde".to_vec()));
        assert_eq!(reader.read_slice(10).await.unwrap(), Some(b"fgh".to_vec()));
        assert_eq!(reader.read_slice(10).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_peek_keeps_the_bytes_for_the_next_read() {
        let mut reader = stream(&[b"abc", b"def"]);
        assert_eq!(&reader.peek(5).await.unwrap()[..], b"abcde");
        assert_eq!(reader.offset(), 0);
        assert_eq!(reader.read_byte().await.unwrap(), Some(b'a'));
        assert_eq!(reader.peek_byte().await.unwrap(), Some(b'b'));
        assert_eq!(&reader.peek(100).await.unwrap()[..], b"bcdef");
    }
}
