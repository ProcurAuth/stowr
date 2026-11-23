//! The ZIP format: the central directory read over exact byte ranges (ZIP64 too), the entries stored or deflated,
//! and the streamed writer with data descriptors.

use bytes::Bytes;

use crate::common::error::{Error, Result};
use crate::instance::range::RangeSource;

/// One entry of a central directory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZipEntry {
    /// The name, as the archive gives it.
    pub name: String,
    /// The compression method (0 stored, 8 deflate).
    pub method: u16,
    /// The compressed size.
    pub compressed_size: u64,
    /// The size.
    pub size: u64,
    /// The CRC-32.
    pub crc32: u32,
    /// The offset of the local header.
    pub header_offset: u64,
    /// The general purpose flags (bit 0: encrypted).
    pub flags: u16,
    /// The external attributes (the type of a symbolic link).
    pub external_attributes: u32,
    /// The time of the last change, as the archive gives it.
    pub modified: Option<crate::common::time::Timestamp>,
}

/// A ZIP archive read over byte ranges.
pub struct ZipReader {
    /// The source of the bytes.
    pub source: RangeSource,
    /// The entries, in the order of the central directory.
    pub entries: Vec<ZipEntry>,
}

impl ZipReader {
    /// Read the central directory: at most `max_entries` entries.
    pub async fn open(source: RangeSource, max_entries: usize) -> Result<Self> {
        let _ = (source, max_entries);
        Err(Error::not_served("the ZIP reader"))
    }

    /// The entry with this exact name.
    pub fn entry(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    /// The bytes of an entry, decompressed, at most `maximum` bytes.
    pub async fn read_entry(&self, entry: &ZipEntry, maximum: u64) -> Result<Bytes> {
        let _ = (entry, maximum);
        Err(Error::not_served("the ZIP reader"))
    }
}
