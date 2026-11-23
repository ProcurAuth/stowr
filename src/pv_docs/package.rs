//! The Office Open XML package as a ZIP archive: the names of the parts, the read of the size of an object, and the
//! bridge between the stream of an entry and a parser that runs on a blocking thread.
//!
//! The decompressed bytes of an entry go through a small channel to a blocking thread. The thread reads them as a
//! [`std::io::Read`]. The parser never holds the whole part. A parser that stops early closes the channel, and the
//! stream of the entry stops.

use std::collections::HashMap;
use std::io::Read;

use bytes::Bytes;
use tokio::sync::mpsc;

use super::xml::XmlFault;
use crate::archive::zip::{EntryStream, ZipEntry, ZipReader};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::instance::Instance;
use crate::instance::range::RangeSource;

/// The chunks that wait between the stream and the parser.
const CHANNEL_DEPTH: usize = 4;

/// A name in the lexical form: no `.` part, no empty part, and the `..` parts resolved. An empty result is `.`.
pub fn clean_path(name: &str) -> String {
    let rooted = name.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_owned(),
        (false, false) => joined,
    }
}

/// The name of a part of a package: the `/` at the start goes away, and the name is cleaned.
pub fn part_name(name: &str) -> String {
    clean_path(name.trim_start_matches('/'))
}

/// The name of a path in a folder: the lexical form of `folder/name`.
pub fn join_path(folder: &str, name: &str) -> String {
    clean_path(&format!("{folder}/{name}"))
}

/// A ZIP archive with its parts by name.
pub struct Package {
    /// The archive.
    pub reader: ZipReader,
    index: HashMap<String, usize>,
    names: Vec<String>,
}

impl Package {
    /// The package of an archive. Of two parts with the same name, the last one counts.
    pub fn new(reader: ZipReader) -> Self {
        let names: Vec<String> = reader.entries.iter().map(|entry| part_name(&entry.name)).collect();
        let mut index = HashMap::with_capacity(names.len());
        for (position, name) in names.iter().enumerate() {
            index.insert(name.clone(), position);
        }
        Self { reader, index, names }
    }

    /// The part with this name.
    pub fn part(&self, name: &str) -> Option<&ZipEntry> {
        self.index
            .get(name)
            .and_then(|position| self.reader.entries.get(*position))
    }

    /// The names of the parts, in the order of the archive.
    pub fn names(&self) -> &[String] {
        &self.names
    }
}

/// The source of an object with a known size. The size comes from the caller, else from the end of the object.
/// Gives `None` for an object without a size (an empty object).
pub async fn open_sized_source(
    ctx: &OpCtx,
    instance: &std::sync::Arc<Instance>,
    key: &str,
    known_size: i64,
    etag: &str,
) -> Result<(RangeSource, Option<i64>)> {
    let mut source = RangeSource::open(ctx, instance, key).await?;
    source.set_known_size(known_size);
    source.set_expected_etag(etag);
    if source.size().is_none() {
        match source.read_suffix(64 << 10).await {
            Ok(_) => {}
            Err(error) if error.as_upstream().is_some_and(|upstream| upstream.status == 416) => {}
            Err(error) => return Err(error),
        }
    }
    let size = source.size();
    Ok((source, size))
}

/// The reason that a read of an entry ended.
#[derive(Debug)]
pub enum ReadFailure {
    /// The part is larger than the limit of the reader.
    Limit,
    /// The stream of the entry gave an error.
    Source(Error),
}

impl std::fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limit => f.write_str("the part exceeds the limit of the preview"),
            Self::Source(error) => write!(f, "{}", error.public_message()),
        }
    }
}

impl std::error::Error for ReadFailure {}

/// What stopped a parser.
#[derive(Debug)]
pub enum Fault {
    /// The part is larger than the limit.
    Limit,
    /// The XML is not valid.
    Syntax(String),
    /// The stream of the entry gave an error.
    Source(Error),
}

impl From<XmlFault> for Fault {
    fn from(fault: XmlFault) -> Self {
        match fault {
            XmlFault::Syntax(text) => Self::Syntax(text),
            XmlFault::Source(error) => {
                let inner = error.get_ref().and_then(|inner| inner.downcast_ref::<ReadFailure>());
                match inner {
                    Some(ReadFailure::Limit) => Self::Limit,
                    Some(ReadFailure::Source(source)) => Self::Source(source.clone()),
                    None => Self::Syntax(error.to_string()),
                }
            }
        }
    }
}

/// A reader of the chunks that the stream of an entry sends.
struct ChunkReader {
    receiver: mpsc::Receiver<Result<Bytes>>,
    current: Bytes,
}

impl Read for ChunkReader {
    fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
        if destination.is_empty() {
            return Ok(0);
        }
        while self.current.is_empty() {
            match self.receiver.blocking_recv() {
                Some(Ok(chunk)) => self.current = chunk,
                Some(Err(error)) => return Err(std::io::Error::other(ReadFailure::Source(error))),
                None => return Ok(0),
            }
        }
        let count = destination.len().min(self.current.len());
        destination[..count].copy_from_slice(&self.current[..count]);
        let _ = self.current.split_to(count);
        Ok(count)
    }
}

/// A reader that stops with [`ReadFailure::Limit`] after `limit` bytes.
pub struct HardLimit<R: Read> {
    inner: R,
    limit: u64,
    read: u64,
}

impl<R: Read> HardLimit<R> {
    /// A reader that gives an error when it has given `limit` bytes and the caller asks for more.
    pub fn new(inner: R, limit: u64) -> Self {
        Self { inner, limit, read: 0 }
    }
}

impl<R: Read> Read for HardLimit<R> {
    fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
        if self.read >= self.limit {
            return Err(std::io::Error::other(ReadFailure::Limit));
        }
        let room = usize::try_from(self.limit - self.read).unwrap_or(usize::MAX);
        let take = destination.len().min(room);
        let count = self.inner.read(&mut destination[..take])?;
        self.read += count as u64;
        Ok(count)
    }
}

/// A reader that ends (without an error) after `limit` bytes.
pub struct Truncate<R: Read> {
    inner: R,
    left: u64,
}

impl<R: Read> Truncate<R> {
    /// A reader of the first `limit` bytes.
    pub fn new(inner: R, limit: u64) -> Self {
        Self { inner, left: limit }
    }
}

impl<R: Read> Read for Truncate<R> {
    fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            return Ok(0);
        }
        let take = destination.len().min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let count = self.inner.read(&mut destination[..take])?;
        self.left -= count as u64;
        Ok(count)
    }
}

/// Run a parser on a blocking thread over the decompressed bytes of an entry. The result is what the parser
/// gives. A stream that fails sends its error to the parser, which sees it as the error of its reader.
pub async fn parse_entry<T, F>(mut stream: EntryStream<&ZipReader>, parse: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&mut dyn Read) -> T + Send + 'static,
{
    let (sender, receiver) = mpsc::channel::<Result<Bytes>>(CHANNEL_DEPTH);
    let worker = tokio::task::spawn_blocking(move || {
        let mut source = ChunkReader {
            receiver,
            current: Bytes::new(),
        };
        parse(&mut source)
    });
    let pump = async move {
        loop {
            match stream.next_chunk().await {
                Ok(Some(chunk)) => {
                    if sender.send(Ok(chunk)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(error) => {
                    let _ = sender.send(Err(error)).await;
                    return;
                }
            }
        }
    };
    let (_, joined) = tokio::join!(pump, worker);
    joined.map_err(|_| Error::internal("the worker of the preview stopped"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_cleaned_with_lexical_rules() {
        assert_eq!(clean_path("xl//worksheets/./sheet1.xml"), "xl/worksheets/sheet1.xml");
        assert_eq!(clean_path("xl/../docProps/core.xml"), "docProps/core.xml");
        assert_eq!(clean_path("../a"), "../a");
        assert_eq!(clean_path(""), ".");
        assert_eq!(clean_path("/a/b/../c"), "/a/c");
        assert_eq!(part_name("/word/document.xml"), "word/document.xml");
        assert_eq!(join_path("xl", "worksheets/sheet1.xml"), "xl/worksheets/sheet1.xml");
        assert_eq!(join_path("xl", "../x"), "x");
    }

    #[test]
    fn the_limit_reader_stops_after_the_limit() {
        let mut reader = HardLimit::new(&b"abcdef"[..], 4);
        let mut out = Vec::new();
        let error = reader.read_to_end(&mut out).unwrap_err();
        assert_eq!(out, b"abcd");
        assert!(error.get_ref().is_some_and(|inner| inner.is::<ReadFailure>()));
        let mut short = HardLimit::new(&b"ab"[..], 4);
        let mut out = Vec::new();
        short.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"ab");
        let mut cut = Truncate::new(&b"abcdef"[..], 3);
        let mut out = Vec::new();
        cut.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"abc");
    }
}
