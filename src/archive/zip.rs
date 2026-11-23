// SPDX-License-Identifier: MIT OR Apache-2.0
//! The ZIP format: the central directory read over exact byte ranges (ZIP64 too), the entries stored or deflated,
//! and the streamed writer with data descriptors.
//!
//! [`ZipReader`] reads an object through a [`ByteSource`], in blocks of 1 MiB that start at a multiple of 1 MiB.
//! It reads the end record of the central directory, the ZIP64 records, then each header of the central
//! directory. It never reads the whole object. [`EntryStream`] gives the bytes of one entry, stored or deflated.
//!
//! The rules of the reader:
//! - The end record is in the last 1 KiB of the archive, else in the last 65 KiB. A comment that the end of the
//!   object cuts stops the search.
//! - The values `0xffff` (records or size) and `0xffffffff` (offset) of the end record send the reader to the
//!   ZIP64 locator and the ZIP64 end record.
//! - The reader reads the headers until the first header that is not valid. The count of the headers must agree
//!   with the end record on its 16 low bits.
//! - An entry gives at most its size. More bytes, fewer bytes, or another CRC-32 stop the read with an error.
//! - A method other than 0 (stored) and 8 (deflate) gives the error `unsupported_compression`.
//! - A central directory with more entries than the limit gives `413 archive_too_many_entries`.

pub mod writer;

use std::ops::Deref;
use std::sync::{Arc, Mutex};

use bytes::{Buf, Bytes, BytesMut};
use flate2::{Crc, Decompress, FlushDecompress, Status};

use crate::common::BoxFuture;
use crate::common::error::{Error, Result};
use crate::common::time::Timestamp;
use crate::instance::range::RangeSource;

/// The method of a stored entry.
pub const METHOD_STORE: u16 = 0;
/// The method of a deflated entry.
pub const METHOD_DEFLATE: u16 = 8;

/// The size of one read of the object. Each read starts at a multiple of this size.
pub const BLOCK_BYTES: u64 = 1 << 20;
/// The suffix that the reader reads first when the size of the object is not known.
pub const SUFFIX_BYTES: u64 = 128 << 10;
/// The prefix that [`ZipReader::open_package`] reads to find the archive in a CRX package.
pub const CRX_HEADER_BYTES: u64 = 64 << 10;

/// The code of an object that has no readable central directory.
pub const CODE_INVALID_ZIP: &str = "invalid_zip";
/// The message of an object that has no readable central directory.
pub const MESSAGE_INVALID_ZIP: &str = "the object does not contain a readable ZIP central directory";
/// The code of a central directory with more entries than the limit.
pub const CODE_TOO_MANY_ENTRIES: &str = "archive_too_many_entries";
/// The code of an entry whose local header is not valid.
pub const CODE_INVALID_ENTRY: &str = "invalid_zip_entry";
/// The code of an entry with a compression method that the reader does not know.
pub const CODE_UNSUPPORTED_METHOD: &str = "unsupported_compression";
/// The code of an entry that is larger than the limit of [`ZipReader::read_entry`].
pub const CODE_ENTRY_TOO_LARGE: &str = "archive_entry_too_large";

const LOCAL_HEADER_SIGNATURE: u32 = 0x0403_4b50;
const DIRECTORY_HEADER_SIGNATURE: u32 = 0x0201_4b50;
const DIRECTORY64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const DIRECTORY64_END_SIGNATURE: u32 = 0x0606_4b50;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const LOCAL_HEADER_LEN: usize = 30;
const DIRECTORY_HEADER_LEN: usize = 46;
const DIRECTORY_END_LEN: usize = 22;
const DIRECTORY64_LOCATOR_LEN: u64 = 20;
const DIRECTORY64_END_LEN: u64 = 56;
const DATA_DESCRIPTOR_LEN: u64 = 16;

const EXTRA_ZIP64: u16 = 0x0001;
const EXTRA_NTFS: u16 = 0x000a;
const EXTRA_UNIX: u16 = 0x000d;
const EXTRA_EXTENDED_TIME: u16 = 0x5455;
const EXTRA_INFOZIP_UNIX: u16 = 0x5855;

const CREATOR_FAT: u16 = 0;
const CREATOR_UNIX: u16 = 3;
const CREATOR_NTFS: u16 = 11;
const CREATOR_VFAT: u16 = 14;
const CREATOR_MACOS: u16 = 19;

const UNIX_TYPE_MASK: u32 = 0o170_000;
const UNIX_SOCKET: u32 = 0o140_000;
const UNIX_SYMLINK: u32 = 0o120_000;
const UNIX_BLOCK_DEVICE: u32 = 0o060_000;
const UNIX_DIRECTORY: u32 = 0o040_000;
const UNIX_CHAR_DEVICE: u32 = 0o020_000;
const UNIX_FIFO: u32 = 0o010_000;
const DOS_DIRECTORY: u32 = 0x10;

/// The flag of an encrypted entry.
pub const FLAG_ENCRYPTED: u16 = 0x1;
/// The flag of an entry with a data descriptor after its data.
pub const FLAG_DATA_DESCRIPTOR: u16 = 0x8;
/// The flag of a name in UTF-8.
pub const FLAG_UTF8: u16 = 0x800;

/// The size of the output of one step of the inflate.
const INFLATE_CHUNK: usize = 64 << 10;
/// The seconds from 0001-01-01T00:00:00Z to 1970-01-01T00:00:00Z: a time at this value is the zero time.
const ZERO_TIME_SECS: i64 = -62_135_596_800;
/// The seconds from 1601-01-01T00:00:00Z to 1970-01-01T00:00:00Z, negative.
const NTFS_EPOCH_SECS: i64 = -11_644_473_600;

/// A source of exact byte ranges of one object.
pub trait ByteSource: Send + Sync {
    /// The size of the object, when it is known and above 0.
    fn source_size(&self) -> Option<u64>;
    /// Read the last `length` bytes of the object. After the read, [`ByteSource::source_size`] knows the size.
    fn fetch_suffix(&self, length: u64) -> BoxFuture<'_, Result<Bytes>>;
    /// Read `length` bytes from `offset`. The range is inside the object.
    fn fetch(&self, offset: u64, length: u64) -> BoxFuture<'_, Result<Bytes>>;
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl ByteSource for RangeSource {
    fn source_size(&self) -> Option<u64> {
        self.size()
            .and_then(|size| u64::try_from(size).ok())
            .filter(|size| *size > 0)
    }

    fn fetch_suffix(&self, length: u64) -> BoxFuture<'_, Result<Bytes>> {
        Box::pin(self.read_suffix(to_i64(length)))
    }

    fn fetch(&self, offset: u64, length: u64) -> BoxFuture<'_, Result<Bytes>> {
        Box::pin(self.read_range(to_i64(offset), to_i64(length)))
    }
}

/// The bytes of an object in memory: an archive in a test, or an archive that a caller already has.
impl ByteSource for Bytes {
    fn source_size(&self) -> Option<u64> {
        (!self.is_empty()).then_some(self.len() as u64)
    }

    fn fetch_suffix(&self, length: u64) -> BoxFuture<'_, Result<Bytes>> {
        let start = self.len().saturating_sub(usize::try_from(length).unwrap_or(usize::MAX));
        let data = self.slice(start..);
        Box::pin(async move { Ok(data) })
    }

    fn fetch(&self, offset: u64, length: u64) -> BoxFuture<'_, Result<Bytes>> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(self.len());
        let end = start
            .saturating_add(usize::try_from(length).unwrap_or(usize::MAX))
            .min(self.len());
        let data = self.slice(start..end);
        Box::pin(async move { Ok(data) })
    }
}

impl<T: ByteSource + ?Sized> ByteSource for Arc<T> {
    fn source_size(&self) -> Option<u64> {
        (**self).source_size()
    }

    fn fetch_suffix(&self, length: u64) -> BoxFuture<'_, Result<Bytes>> {
        (**self).fetch_suffix(length)
    }

    fn fetch(&self, offset: u64, length: u64) -> BoxFuture<'_, Result<Bytes>> {
        (**self).fetch(offset, length)
    }
}

/// One entry of a central directory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZipEntry {
    /// The name, as the archive gives it. A byte that is not part of valid UTF-8 becomes U+FFFD.
    pub name: String,
    /// True when the name of the archive is valid UTF-8. A name with another byte never matches a requested name.
    pub name_is_utf8: bool,
    /// The compression method (0 stored, 8 deflate).
    pub method: u16,
    /// The compressed size.
    pub compressed_size: u64,
    /// The size.
    pub size: u64,
    /// The CRC-32.
    pub crc32: u32,
    /// The offset of the local header in the archive.
    pub header_offset: u64,
    /// The general purpose flags (bit 0: encrypted, bit 3: data descriptor, bit 11: UTF-8).
    pub flags: u16,
    /// The external attributes (the Unix mode in the 16 high bits, the DOS attributes in the low byte).
    pub external_attributes: u32,
    /// The time of the last change: the extended timestamp when the entry has one, else the DOS date and time in
    /// UTC. The offset is the difference between the two, when the entry has both.
    pub modified: Option<Timestamp>,
    /// The version that made the entry: the system in the high byte.
    pub creator_version: u16,
    /// The version that the extraction needs.
    pub reader_version: u16,
    /// The DOS time of the last change.
    pub modified_time: u16,
    /// The DOS date of the last change.
    pub modified_date: u16,
    /// The comment of the entry.
    pub comment: String,
    /// The extra fields of the central directory.
    pub extra: Vec<u8>,
    /// True when the entry has a ZIP64 extra field.
    pub zip64: bool,
}

impl ZipEntry {
    /// The Unix mode of the 16 high bits of the attributes, for an entry of a Unix or macOS system.
    fn unix_mode(&self) -> Option<u32> {
        match self.creator_version >> 8 {
            CREATOR_UNIX | CREATOR_MACOS => Some(self.external_attributes >> 16),
            _ => None,
        }
    }

    fn dos_attributes(&self) -> Option<u32> {
        match self.creator_version >> 8 {
            CREATOR_NTFS | CREATOR_VFAT | CREATOR_FAT => Some(self.external_attributes),
            _ => None,
        }
    }

    /// True for a folder: the name ends with `/`, or the attributes give a folder.
    pub fn is_dir(&self) -> bool {
        if self.name.ends_with('/') {
            return true;
        }
        if let Some(mode) = self.unix_mode() {
            return mode & UNIX_TYPE_MASK == UNIX_DIRECTORY;
        }
        self.dos_attributes()
            .is_some_and(|attributes| attributes & DOS_DIRECTORY != 0)
    }

    /// True for a symbolic link: the Unix type of the attributes.
    pub fn is_symlink(&self) -> bool {
        self.unix_mode()
            .is_some_and(|mode| mode & UNIX_TYPE_MASK == UNIX_SYMLINK)
    }

    /// True for a regular file: not a folder, a symbolic link, a device, a pipe or a socket.
    pub fn is_regular(&self) -> bool {
        if self.is_dir() {
            return false;
        }
        !matches!(
            self.unix_mode().map(|mode| mode & UNIX_TYPE_MASK),
            Some(UNIX_SOCKET | UNIX_SYMLINK | UNIX_BLOCK_DEVICE | UNIX_CHAR_DEVICE | UNIX_FIFO)
        )
    }

    /// True when the flags mark the entry as encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    fn has_data_descriptor(&self) -> bool {
        self.flags & FLAG_DATA_DESCRIPTOR != 0
    }
}

/// Why a read of the archive stopped.
#[derive(Debug)]
enum Fault {
    /// The source failed: the caller gets the error as it is.
    Source(Error),
    /// The bytes are not a valid ZIP structure, or the archive ends too soon.
    Format,
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        Self::Source(error)
    }
}

/// The `422 invalid_zip` answer.
pub fn invalid_zip() -> Error {
    Error::api(422, CODE_INVALID_ZIP, MESSAGE_INVALID_ZIP)
}

/// True for the error of an object without a readable central directory: not an error of the source.
pub fn is_format_error(error: &Error) -> bool {
    error.has_code(CODE_INVALID_ZIP)
}

/// True for the error of an entry with a compression method that the reader does not know.
pub fn is_unsupported_method(error: &Error) -> bool {
    error.has_code(CODE_UNSUPPORTED_METHOD)
}

fn invalid_entry() -> Error {
    Error::api(
        422,
        CODE_INVALID_ENTRY,
        "the local header of the archive entry is not valid",
    )
}

fn unsupported_method() -> Error {
    Error::api(
        422,
        CODE_UNSUPPORTED_METHOD,
        "the archive entry uses an unsupported compression method",
    )
}

/// The `413 archive_too_many_entries` answer of a central directory with more entries than the limit.
pub fn too_many_entries(limit: usize) -> Error {
    Error::api(
        413,
        CODE_TOO_MANY_ENTRIES,
        format!("the archive contains more than the configured limit of {limit} entries"),
    )
}

impl Fault {
    fn into_open_error(self) -> Error {
        match self {
            Self::Source(error) => error,
            Self::Format => invalid_zip(),
        }
    }

    fn into_entry_error(self) -> Error {
        match self {
            Self::Source(error) => error,
            Self::Format => invalid_entry(),
        }
    }
}

/// A reader of little-endian fields. A field after the end reads as 0: each caller checks the length first.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn take(&mut self, count: usize) -> &'a [u8] {
        let count = count.min(self.0.len());
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        head
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn u8(&mut self) -> u8 {
        self.take(1).first().copied().unwrap_or(0)
    }

    fn u16(&mut self) -> u16 {
        let mut bytes = [0u8; 2];
        let head = self.take(2);
        bytes[..head.len()].copy_from_slice(head);
        u16::from_le_bytes(bytes)
    }

    fn u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        let head = self.take(4);
        bytes[..head.len()].copy_from_slice(head);
        u32::from_le_bytes(bytes)
    }

    fn u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        let head = self.take(8);
        bytes[..head.len()].copy_from_slice(head);
        u64::from_le_bytes(bytes)
    }
}

/// The text of bytes: each byte that is not part of valid UTF-8 becomes one U+FFFD.
pub fn lossy_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for _ in chunk.invalid() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
    out
}

/// The day number (days since 1970-01-01) of a date of the proleptic Gregorian calendar, month 1 to 12.
pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date (year, month, day) of a day number.
pub(crate) fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The seconds since 1970 of a DOS date and time, in UTC. A field out of its range moves to the next unit. For
/// example, the month 0 is the last month of the year before, and the day 0 is the last day of the month before.
pub fn dos_seconds(date: u16, time: u16) -> i64 {
    let year = i64::from(date >> 9) + 1980;
    let month = i64::from((date >> 5) & 0xf) - 1;
    let day = i64::from(date & 0x1f);
    let hour = i64::from(time >> 11);
    let minute = i64::from((time >> 5) & 0x3f);
    let second = i64::from(time & 0x1f) * 2;
    let year = year + month.div_euclid(12);
    let month = month.rem_euclid(12) + 1;
    let days = days_from_civil(year, month, 1) + day - 1;
    days * 86_400 + hour * 3600 + minute * 60 + second
}

/// The offset in seconds between the DOS time and the extended time: the difference rounded to 15 minutes (half
/// away from zero). An offset outside -12 h to +14 h gives 0.
fn zone_offset(dos_secs: i64, secs: i64, nanos: u32) -> i32 {
    const UNIT: i128 = 15 * 60 * 1_000_000_000;
    const MIN: i128 = -12 * 3600 * 1_000_000_000;
    const MAX: i128 = 14 * 3600 * 1_000_000_000;
    let difference = (i128::from(dos_secs) - i128::from(secs)) * 1_000_000_000 - i128::from(nanos);
    let difference = difference.clamp(i128::from(i64::MIN), i128::from(i64::MAX));
    let rest = difference % UNIT;
    let rounded = if difference < 0 {
        let rest = -rest;
        if rest + rest < UNIT {
            difference + rest
        } else {
            difference - UNIT + rest
        }
    } else if rest + rest < UNIT {
        difference - rest
    } else {
        difference + UNIT - rest
    };
    if !(MIN..=MAX).contains(&rounded) {
        return 0;
    }
    i32::try_from(rounded / 1_000_000_000).unwrap_or(0)
}

/// A time from seconds and nanoseconds that can be out of range: the nanoseconds move into the seconds.
fn normalized_time(secs: i64, nanos: i64) -> (i64, u32) {
    let secs = secs.saturating_add(nanos.div_euclid(1_000_000_000));
    let nanos = u32::try_from(nanos.rem_euclid(1_000_000_000)).unwrap_or(0);
    (secs, nanos)
}

/// The fields of a central directory header that the variable part does not give.
struct HeaderFields {
    creator_version: u16,
    reader_version: u16,
    flags: u16,
    method: u16,
    modified_time: u16,
    modified_date: u16,
    crc32: u32,
    compressed_size: u32,
    size: u32,
    name_len: usize,
    extra_len: usize,
    comment_len: usize,
    external_attributes: u32,
    header_offset: u32,
}

fn header_fields(fixed: &[u8]) -> Option<HeaderFields> {
    let mut fields = Fields(fixed);
    if fields.u32() != DIRECTORY_HEADER_SIGNATURE {
        return None;
    }
    let creator_version = fields.u16();
    let reader_version = fields.u16();
    let flags = fields.u16();
    let method = fields.u16();
    let modified_time = fields.u16();
    let modified_date = fields.u16();
    let crc32 = fields.u32();
    let compressed_size = fields.u32();
    let size = fields.u32();
    let name_len = usize::from(fields.u16());
    let extra_len = usize::from(fields.u16());
    let comment_len = usize::from(fields.u16());
    fields.take(4);
    let external_attributes = fields.u32();
    let header_offset = fields.u32();
    Some(HeaderFields {
        creator_version,
        reader_version,
        flags,
        method,
        modified_time,
        modified_date,
        crc32,
        compressed_size,
        size,
        name_len,
        extra_len,
        comment_len,
        external_attributes,
        header_offset,
    })
}

/// Build an entry from a header and its variable part. `None`: the header is not valid.
fn build_entry(header: &HeaderFields, variable: &[u8]) -> Option<ZipEntry> {
    let mut parts = Fields(variable);
    let name = parts.take(header.name_len);
    let extra = parts.take(header.extra_len);
    let comment = parts.take(header.comment_len);
    let mut entry = ZipEntry {
        name: lossy_text(name),
        name_is_utf8: std::str::from_utf8(name).is_ok(),
        method: header.method,
        compressed_size: u64::from(header.compressed_size),
        size: u64::from(header.size),
        crc32: header.crc32,
        header_offset: u64::from(header.header_offset),
        flags: header.flags,
        external_attributes: header.external_attributes,
        modified: None,
        creator_version: header.creator_version,
        reader_version: header.reader_version,
        modified_time: header.modified_time,
        modified_date: header.modified_date,
        comment: lossy_text(comment),
        extra: extra.to_vec(),
        zip64: false,
    };
    let mut need_size = header.size == u32::MAX;
    let mut need_compressed = header.compressed_size == u32::MAX;
    let mut need_offset = header.header_offset == u32::MAX;
    let mut extended: Option<(i64, u32)> = None;
    let mut fields = Fields(extra);
    'extras: while fields.len() >= 4 {
        let tag = fields.u16();
        let size = usize::from(fields.u16());
        if fields.len() < size {
            break;
        }
        let mut field = Fields(fields.take(size));
        match tag {
            EXTRA_ZIP64 => {
                entry.zip64 = true;
                if need_size {
                    need_size = false;
                    if field.len() < 8 {
                        return None;
                    }
                    entry.size = field.u64();
                }
                if need_compressed {
                    need_compressed = false;
                    if field.len() < 8 {
                        return None;
                    }
                    entry.compressed_size = field.u64();
                }
                if need_offset {
                    need_offset = false;
                    if field.len() < 8 {
                        return None;
                    }
                    entry.header_offset = field.u64();
                }
            }
            EXTRA_NTFS => {
                if field.len() < 4 {
                    continue 'extras;
                }
                field.take(4);
                while field.len() >= 4 {
                    let attribute = field.u16();
                    let length = usize::from(field.u16());
                    if field.len() < length {
                        continue 'extras;
                    }
                    let mut value = Fields(field.take(length));
                    if attribute != 1 || length != 24 {
                        continue;
                    }
                    let ticks = value.u64() as i64;
                    let secs = ticks / 10_000_000;
                    let nanos = 100 * (ticks % 10_000_000);
                    extended = Some(normalized_time(NTFS_EPOCH_SECS.saturating_add(secs), nanos));
                }
            }
            EXTRA_UNIX | EXTRA_INFOZIP_UNIX => {
                if field.len() < 8 {
                    continue 'extras;
                }
                field.take(4);
                extended = Some((i64::from(field.u32()), 0));
            }
            EXTRA_EXTENDED_TIME => {
                if field.len() < 5 || field.u8() & 1 == 0 {
                    continue 'extras;
                }
                extended = Some((i64::from(field.u32()), 0));
            }
            _ => {}
        }
    }
    let dos = dos_seconds(header.modified_date, header.modified_time);
    let modified = match extended.filter(|time| *time != (ZERO_TIME_SECS, 0)) {
        None => Timestamp::from_unix(dos, 0),
        Some((secs, nanos)) => {
            let offset = if header.modified_time != 0 || header.modified_date != 0 {
                zone_offset(dos, secs, nanos)
            } else {
                0
            };
            Timestamp { secs, nanos, offset }
        }
    };
    entry.modified = Some(modified);
    // A size of 0xffffffff without a ZIP64 field stays: an old archive can have an entry of exactly this size.
    let _ = need_size;
    if need_compressed || need_offset {
        return None;
    }
    Some(entry)
}

/// The values of the end record of the central directory.
struct DirectoryEnd {
    records: u64,
    size: u64,
    offset: u64,
    comment: String,
}

/// The position of the end record in a block: the last signature whose comment ends in the block. A last
/// signature whose comment continues after the block stops the search.
fn find_end_record(block: &[u8]) -> Option<usize> {
    if block.len() < DIRECTORY_END_LEN {
        return None;
    }
    for index in (0..=block.len() - DIRECTORY_END_LEN).rev() {
        if block[index..index + 4] == [b'P', b'K', 0x05, 0x06] {
            let comment = usize::from(block[index + DIRECTORY_END_LEN - 2])
                | (usize::from(block[index + DIRECTORY_END_LEN - 1]) << 8);
            if comment + DIRECTORY_END_LEN + index > block.len() {
                return None;
            }
            return Some(index);
        }
    }
    None
}

/// The result of a read of a number of bytes in order.
enum Take {
    /// All the bytes.
    Full(Bytes),
    /// Some bytes, then the end of the archive.
    Short,
    /// No byte: the archive ends here.
    Empty,
}

/// A position in the archive for a read in order, with the bytes that the reader fetched after it.
struct Cursor {
    /// The offset in the archive of the first byte after `buffer`.
    next: u64,
    /// The fetched bytes that the reader did not use yet.
    buffer: Bytes,
}

impl Cursor {
    fn at(offset: u64) -> Self {
        Self {
            next: offset,
            buffer: Bytes::new(),
        }
    }
}

/// The result of the read of one header of the central directory.
enum HeaderRead {
    /// A valid header.
    Entry(ZipEntry),
    /// A header that is not valid, or the end of the archive in the header: the list stops here.
    Stop,
    /// An error that stops the read of the archive.
    Fatal(Fault),
}

/// A ZIP archive read over byte ranges.
pub struct ZipReader<S = RangeSource> {
    /// The source of the bytes.
    pub source: S,
    /// The entries, in the order of the central directory. A reader with a limit keeps at most the limit.
    pub entries: Vec<ZipEntry>,
    /// The comment of the archive.
    pub comment: String,
    /// The offset of the archive in the object: the length of the header of a CRX package, else 0.
    pub start: u64,
    /// The size of the archive: the size of the object minus `start`.
    pub size: u64,
    /// The last block that the reader read.
    block: Mutex<Option<(u64, Bytes)>>,
}

impl<S> std::fmt::Debug for ZipReader<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipReader")
            .field("entries", &self.entries.len())
            .field("start", &self.start)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// True for the extensions of the packages that the ZIP reader opens: ZIP, JAR, WAR, EAR, APK, AAR, XPI, CRX,
/// VSIX and EPUB (lower case, without the dot).
pub fn is_zip_archive_extension(extension: &str) -> bool {
    matches!(
        extension,
        "zip" | "jar" | "war" | "ear" | "apk" | "aar" | "xpi" | "crx" | "vsix" | "epub"
    )
}

/// The offset of the archive in a CRX package (versions 2 and 3), from the first bytes of the object. `None`: the
/// header is not a valid CRX header, or the archive starts at or after the end of the object.
pub fn crx_zip_offset(header: &[u8], size: u64) -> Option<u64> {
    if header.len() < 12 || &header[..4] != b"Cr24" {
        return None;
    }
    let mut fields = Fields(&header[4..]);
    let offset = match fields.u32() {
        2 => {
            if header.len() < 16 {
                return None;
            }
            let public_key = u64::from(fields.u32());
            let signature = u64::from(fields.u32());
            16 + public_key + signature
        }
        3 => 12 + u64::from(fields.u32()),
        _ => return None,
    };
    (offset < size).then_some(offset)
}

impl<S: ByteSource> ZipReader<S> {
    /// Read the central directory of the object: at most `max_entries` entries (0: no limit). A larger central
    /// directory gives `413 archive_too_many_entries` after the read of all its headers. An object without a
    /// readable central directory gives `422 invalid_zip`; the caller gets an error of the source as it is.
    /// When the size is not known, the reader reads the last 128 KiB first.
    pub async fn open(source: S, max_entries: usize) -> Result<Self> {
        Self::open_at(source, 0, max_entries).await
    }

    /// Open the archive of a package: [`ZipReader::open`], and for the extension `crx` the archive after the CRX
    /// header.
    pub async fn open_package(source: S, extension: &str, max_entries: usize) -> Result<Self> {
        let total = Self::discover_size(&source).await?;
        let mut start = 0;
        if extension == "crx" {
            let header = source.fetch(0, total.min(CRX_HEADER_BYTES)).await?;
            start = crx_zip_offset(&header, total).ok_or_else(invalid_zip)?;
        }
        Self::open_at(source, start, max_entries).await
    }

    /// Read the central directory of the archive that starts at `start` in the object.
    pub async fn open_at(source: S, start: u64, max_entries: usize) -> Result<Self> {
        let total = Self::discover_size(&source).await?;
        if start >= total {
            return Err(invalid_zip());
        }
        let mut reader = Self {
            source,
            entries: Vec::new(),
            comment: String::new(),
            start,
            size: total - start,
            block: Mutex::new(None),
        };
        let (entries, count, comment) = reader
            .read_directory(max_entries)
            .await
            .map_err(Fault::into_open_error)?;
        if max_entries > 0 && count > max_entries {
            return Err(too_many_entries(max_entries));
        }
        reader.entries = entries;
        reader.comment = comment;
        Ok(reader)
    }

    async fn discover_size(source: &S) -> Result<u64> {
        if let Some(size) = source.source_size() {
            return Ok(size);
        }
        source.fetch_suffix(SUFFIX_BYTES).await?;
        source.source_size().ok_or_else(invalid_zip)
    }

    /// The first entry with this exact name. A name of the archive that is not valid UTF-8 never matches.
    pub fn entry(&self, name: &str) -> Option<&ZipEntry> {
        self.entries
            .iter()
            .find(|entry| entry.name_is_utf8 && entry.name == name)
    }

    /// Each entry with this exact name. A name of the archive that is not valid UTF-8 never matches.
    pub fn entries_named<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a ZipEntry> {
        self.entries
            .iter()
            .filter(move |entry| entry.name_is_utf8 && entry.name == name)
    }

    /// The bytes of an entry, decompressed and checked (size and CRC-32). An entry whose size is above `maximum`
    /// gives `413 archive_entry_too_large` without a read.
    pub async fn read_entry(&self, entry: &ZipEntry, maximum: u64) -> Result<Bytes> {
        if entry.size > maximum {
            return Err(Error::api(
                413,
                CODE_ENTRY_TOO_LARGE,
                format!("the archive entry exceeds the limit of {maximum} bytes"),
            ));
        }
        let mut stream = self.open_entry(entry).await?;
        let capacity = usize::try_from(entry.size).unwrap_or(0).min(1 << 20);
        let mut out = BytesMut::with_capacity(capacity);
        while let Some(chunk) = stream.next_chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }

    /// Open the stream of the bytes of an entry. The local header gives the start of the data. A local header that
    /// is not valid gives `422 invalid_zip_entry`; a method other than stored and deflate gives
    /// `422 unsupported_compression`.
    pub async fn open_entry(&self, entry: &ZipEntry) -> Result<EntryStream<&Self>> {
        EntryStream::open(self, entry).await
    }

    /// [`ZipReader::open_entry`] for a reader that the stream shares: the stream can move to another task.
    pub async fn open_entry_shared(self: &Arc<Self>, entry: &ZipEntry) -> Result<EntryStream<Arc<Self>>> {
        EntryStream::open(self.clone(), entry).await
    }

    /// Read the end records and each header of the central directory. Gives the kept entries, the count of the
    /// headers and the comment.
    async fn read_directory(&self, max_entries: usize) -> Result<(Vec<ZipEntry>, usize, String), Fault> {
        let (end, base) = self.directory_end().await?;
        let start = base.wrapping_add(end.offset as i64);
        let mut cursor = Cursor::at(u64::try_from(start).map_err(|_| Fault::Format)?);
        let mut entries = Vec::new();
        let mut count = 0usize;
        loop {
            match self.read_header(&mut cursor).await {
                HeaderRead::Entry(mut entry) => {
                    entry.header_offset =
                        u64::try_from((entry.header_offset as i64).wrapping_add(base)).unwrap_or(u64::MAX);
                    count += 1;
                    if max_entries == 0 || entries.len() < max_entries {
                        entries.push(entry);
                    }
                }
                HeaderRead::Stop => break,
                HeaderRead::Fatal(fault) => return Err(fault),
            }
        }
        if count as u16 != end.records as u16 {
            return Err(Fault::Format);
        }
        Ok((entries, count, end.comment))
    }

    /// Find and read the end record (and the ZIP64 records). Gives the values and the offset of the start of the
    /// archive in the section: a value above 0 when the archive has bytes before it.
    async fn directory_end(&self) -> Result<(DirectoryEnd, i64), Fault> {
        let size = self.size;
        let mut found = None;
        for (round, wanted) in [1024u64, 65 * 1024].into_iter().enumerate() {
            let length = wanted.min(size);
            let block = self.read_section(size - length, length).await?;
            if block.len() as u64 != length {
                return Err(Fault::Format);
            }
            if let Some(position) = find_end_record(&block) {
                found = Some((block.slice(position..), size - length + position as u64));
                break;
            }
            if round == 1 || length == size {
                return Err(Fault::Format);
            }
        }
        let (record, end_offset) = found.ok_or(Fault::Format)?;
        let mut fields = Fields(&record[4..]);
        fields.take(6);
        let mut end = DirectoryEnd {
            records: u64::from(fields.u16()),
            size: u64::from(fields.u32()),
            offset: u64::from(fields.u32()),
            comment: String::new(),
        };
        let comment_len = usize::from(fields.u16());
        if comment_len > fields.len() {
            return Err(Fault::Format);
        }
        end.comment = lossy_text(fields.take(comment_len));
        let mut end_offset = end_offset as i64;
        if (end.records == 0xffff || end.size == 0xffff || end.offset == 0xffff_ffff)
            && let Some(position) = self.find_directory64_end(end_offset).await?
            && position >= 0
        {
            end_offset = position;
            self.read_directory64_end(position as u64, &mut end).await?;
        }
        let maximum = i64::MAX as u64;
        if end.size > maximum || end.offset > maximum {
            return Err(Fault::Format);
        }
        let mut base = end_offset.wrapping_sub(end.size as i64).wrapping_sub(end.offset as i64);
        let directory = base.wrapping_add(end.offset as i64);
        if directory < 0 || directory >= size as i64 {
            return Err(Fault::Format);
        }
        // An end record that gives bytes before the archive can be wrong: a valid header at the offset of the
        // record, without the bytes before, wins.
        if base > 0 {
            let mut probe = Cursor::at(end.offset);
            if let HeaderRead::Entry(_) = self.read_header(&mut probe).await {
                base = 0;
            }
        }
        Ok((end, base))
    }

    /// The offset of the ZIP64 end record that the ZIP64 locator before the end record gives, when the locator is
    /// valid.
    async fn find_directory64_end(&self, end_offset: i64) -> Result<Option<i64>, Fault> {
        let locator = end_offset - DIRECTORY64_LOCATOR_LEN as i64;
        if locator < 0 {
            return Ok(None);
        }
        let bytes = self.read_section(locator as u64, DIRECTORY64_LOCATOR_LEN).await?;
        if (bytes.len() as u64) < DIRECTORY64_LOCATOR_LEN {
            return Err(Fault::Format);
        }
        let mut fields = Fields(&bytes);
        if fields.u32() != DIRECTORY64_LOCATOR_SIGNATURE || fields.u32() != 0 {
            return Ok(None);
        }
        let position = fields.u64() as i64;
        if fields.u32() != 1 {
            return Ok(None);
        }
        Ok(Some(position))
    }

    async fn read_directory64_end(&self, offset: u64, end: &mut DirectoryEnd) -> Result<(), Fault> {
        let bytes = self.read_section(offset, DIRECTORY64_END_LEN).await?;
        if (bytes.len() as u64) < DIRECTORY64_END_LEN {
            return Err(Fault::Format);
        }
        let mut fields = Fields(&bytes);
        if fields.u32() != DIRECTORY64_END_SIGNATURE {
            return Err(Fault::Format);
        }
        fields.take(12 + 4 + 4 + 8);
        end.records = fields.u64();
        end.size = fields.u64();
        end.offset = fields.u64();
        Ok(())
    }

    /// Read one header of the central directory at the cursor.
    async fn read_header(&self, cursor: &mut Cursor) -> HeaderRead {
        let fixed = match self.take(cursor, DIRECTORY_HEADER_LEN).await {
            Ok(Take::Full(bytes)) => bytes,
            Ok(Take::Short) => return HeaderRead::Stop,
            Ok(Take::Empty) => return HeaderRead::Fatal(Fault::Format),
            Err(fault) => return HeaderRead::Fatal(fault),
        };
        let Some(header) = header_fields(&fixed) else {
            return HeaderRead::Stop;
        };
        let variable_len = header.name_len + header.extra_len + header.comment_len;
        let variable = if variable_len == 0 {
            Bytes::new()
        } else {
            match self.take(cursor, variable_len).await {
                Ok(Take::Full(bytes)) => bytes,
                Ok(Take::Short) => return HeaderRead::Stop,
                Ok(Take::Empty) => return HeaderRead::Fatal(Fault::Format),
                Err(fault) => return HeaderRead::Fatal(fault),
            }
        };
        match build_entry(&header, &variable) {
            Some(entry) => HeaderRead::Entry(entry),
            None => HeaderRead::Stop,
        }
    }

    /// Read `length` bytes in order at the cursor.
    async fn take(&self, cursor: &mut Cursor, length: usize) -> Result<Take, Fault> {
        while cursor.buffer.len() < length && cursor.next < self.size {
            let object_offset = self.start + cursor.next;
            let to_block_end = BLOCK_BYTES - object_offset % BLOCK_BYTES;
            let want = to_block_end.min(self.size - cursor.next);
            let more = self.read_section(cursor.next, want).await?;
            if more.is_empty() {
                break;
            }
            cursor.next += more.len() as u64;
            if cursor.buffer.is_empty() {
                cursor.buffer = more;
            } else {
                let mut joined = BytesMut::with_capacity(cursor.buffer.len() + more.len());
                joined.extend_from_slice(&cursor.buffer);
                joined.extend_from_slice(&more);
                cursor.buffer = joined.freeze();
            }
        }
        if cursor.buffer.len() >= length {
            return Ok(Take::Full(cursor.buffer.split_to(length)));
        }
        if cursor.buffer.is_empty() {
            return Ok(Take::Empty);
        }
        cursor.buffer = Bytes::new();
        Ok(Take::Short)
    }

    /// Read at most `length` bytes at an offset of the archive. The result is shorter only at the end of the
    /// archive.
    async fn read_section(&self, offset: u64, length: u64) -> Result<Bytes, Fault> {
        if offset >= self.size || length == 0 {
            return Ok(Bytes::new());
        }
        let length = length.min(self.size - offset);
        self.read_object(self.start + offset, length).await
    }

    /// Read a range of the object, block by block.
    async fn read_object(&self, offset: u64, length: u64) -> Result<Bytes, Fault> {
        let total = self.start + self.size;
        let end = offset + length;
        let mut cursor = offset;
        let mut joined: Option<BytesMut> = None;
        while cursor < end {
            let block_start = cursor / BLOCK_BYTES * BLOCK_BYTES;
            let block_len = BLOCK_BYTES.min(total - block_start);
            let block = self.block(block_start, block_len).await?;
            let within = usize::try_from(cursor - block_start).map_err(|_| Fault::Format)?;
            let wanted = usize::try_from(end - cursor).map_err(|_| Fault::Format)?;
            let count = wanted.min(block.len() - within);
            let piece = block.slice(within..within + count);
            cursor += count as u64;
            match joined.as_mut() {
                None if cursor == end => return Ok(piece),
                None => {
                    let mut buffer = BytesMut::with_capacity(usize::try_from(length).unwrap_or(0));
                    buffer.extend_from_slice(&piece);
                    joined = Some(buffer);
                }
                Some(buffer) => buffer.extend_from_slice(&piece),
            }
        }
        Ok(joined.map(BytesMut::freeze).unwrap_or_default())
    }

    /// One block of the object: the last block again, or a read of the source.
    async fn block(&self, start: u64, length: u64) -> Result<Bytes, Fault> {
        if let Ok(guard) = self.block.lock()
            && let Some((cached_start, data)) = guard.as_ref()
            && *cached_start == start
        {
            return Ok(data.clone());
        }
        let data = self.source.fetch(start, length).await?;
        if data.len() as u64 != length {
            return Err(Fault::Format);
        }
        if let Ok(mut guard) = self.block.lock() {
            *guard = Some((start, data.clone()));
        }
        Ok(data)
    }
}

/// The state of an [`EntryStream`].
#[derive(Debug)]
enum StreamState {
    /// The stream gives data.
    Data,
    /// The entry is a folder: it has no data.
    Folder,
    /// The stream ended with success.
    Ended,
    /// The stream ended with this error. The next reads give it again.
    Failed(Error),
}

/// The bytes of one entry, decompressed, in chunks. The stream checks the size and the CRC-32 at its end.
pub struct EntryStream<R> {
    reader: R,
    entry: ZipEntry,
    /// The offset of the compressed data in the archive.
    data_start: u64,
    /// The compressed bytes that the archive has: the compressed size, or less at the end of the archive.
    available: u64,
    /// The compressed bytes that the stream fetched.
    fetched: u64,
    /// The fetched compressed bytes that the inflate did not use yet.
    input: Bytes,
    /// The inflate of a deflated entry.
    inflate: Option<Box<Decompress>>,
    /// True after the end of the deflate stream.
    inflate_done: bool,
    crc: Crc,
    /// The decompressed bytes that the stream gave.
    produced: u64,
    state: StreamState,
}

impl<R> std::fmt::Debug for EntryStream<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryStream")
            .field("entry", &self.entry.name)
            .field("produced", &self.produced)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl<S: ByteSource, R: Deref<Target = ZipReader<S>>> EntryStream<R> {
    async fn open(reader: R, entry: &ZipEntry) -> Result<Self> {
        let header = reader
            .read_section(entry.header_offset, LOCAL_HEADER_LEN as u64)
            .await
            .map_err(Fault::into_entry_error)?;
        if header.len() < LOCAL_HEADER_LEN {
            return Err(invalid_entry());
        }
        let mut fields = Fields(&header);
        if fields.u32() != LOCAL_HEADER_SIGNATURE {
            return Err(invalid_entry());
        }
        fields.take(22);
        let name_len = u64::from(fields.u16());
        let extra_len = u64::from(fields.u16());
        let body = LOCAL_HEADER_LEN as u64 + name_len + extra_len;
        let data_start = entry.header_offset.checked_add(body).ok_or_else(invalid_entry)?;
        let mut stream = Self {
            available: entry.compressed_size.min(reader.size.saturating_sub(data_start)),
            reader,
            entry: entry.clone(),
            data_start,
            fetched: 0,
            input: Bytes::new(),
            inflate: None,
            inflate_done: false,
            crc: Crc::new(),
            produced: 0,
            state: StreamState::Data,
        };
        if entry.name.ends_with('/') {
            stream.state = StreamState::Folder;
            return Ok(stream);
        }
        match entry.method {
            METHOD_STORE => {}
            METHOD_DEFLATE => stream.inflate = Some(Box::new(Decompress::new(false))),
            _ => return Err(unsupported_method()),
        }
        Ok(stream)
    }

    /// The entry of the stream.
    pub fn entry(&self) -> &ZipEntry {
        &self.entry
    }

    /// The decompressed bytes that the stream gave.
    pub fn produced(&self) -> u64 {
        self.produced
    }

    /// The next decompressed bytes, or `None` at the end. The end checks the size and the CRC-32 of the central
    /// directory, and the data descriptor when the entry has one. The caller gets an error of the source as it is;
    /// an error of the data is an internal error.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        match &self.state {
            StreamState::Data => {}
            StreamState::Ended => return Ok(None),
            StreamState::Failed(error) => return Err(error.clone()),
            StreamState::Folder => {
                if self.entry.size != 0 {
                    return Err(self.fail(Error::internal("a folder entry of the archive declares data")));
                }
                self.state = StreamState::Ended;
                return Ok(None);
            }
        }
        if self.inflate.is_none() {
            if self.fetched < self.available {
                let chunk = self.fetch_input().await?;
                return self.emit(chunk);
            }
            self.finish().await?;
            return Ok(None);
        }
        loop {
            if self.inflate_done {
                self.finish().await?;
                return Ok(None);
            }
            if self.input.is_empty() && self.fetched < self.available {
                self.input = self.fetch_input().await?;
            }
            let Some(inflate) = self.inflate.as_mut() else {
                return Err(self.fail(Error::internal("the inflate of the archive entry is missing")));
            };
            let before_in = inflate.total_in();
            let mut out = Vec::with_capacity(INFLATE_CHUNK);
            let status = inflate.decompress_vec(&self.input, &mut out, FlushDecompress::None);
            let consumed = usize::try_from(inflate.total_in() - before_in).unwrap_or(usize::MAX);
            let status = match status {
                Ok(status) => status,
                Err(_) => return Err(self.fail(Error::internal("the deflate data of the archive entry is not valid"))),
            };
            self.input.advance(consumed.min(self.input.len()));
            if status == Status::StreamEnd {
                self.inflate_done = true;
            }
            if !out.is_empty() {
                return self.emit(Bytes::from(out));
            }
            if self.inflate_done {
                continue;
            }
            if consumed == 0 {
                if self.fetched < self.available {
                    let more = self.fetch_input().await?;
                    let mut joined = BytesMut::with_capacity(self.input.len() + more.len());
                    joined.extend_from_slice(&self.input);
                    joined.extend_from_slice(&more);
                    self.input = joined.freeze();
                    continue;
                }
                return Err(self.fail(Error::internal("the deflate data of the archive entry ends too soon")));
            }
        }
    }

    /// Keep an error: the next reads give it again.
    fn fail(&mut self, error: Error) -> Error {
        self.state = StreamState::Failed(error.clone());
        error
    }

    /// Give a chunk of decompressed bytes, after the check of the size.
    fn emit(&mut self, chunk: Bytes) -> Result<Option<Bytes>> {
        self.crc.update(&chunk);
        self.produced += chunk.len() as u64;
        if self.produced > self.entry.size {
            return Err(self.fail(Error::internal("the archive entry is larger than its size")));
        }
        Ok(Some(chunk))
    }

    /// Fetch the next compressed bytes: to the end of the block, at most the rest of the data.
    async fn fetch_input(&mut self) -> Result<Bytes> {
        let offset = self.data_start + self.fetched;
        let object_offset = self.reader.start + offset;
        let to_block_end = BLOCK_BYTES - object_offset % BLOCK_BYTES;
        let want = to_block_end.min(self.available - self.fetched);
        match self.reader.read_section(offset, want).await {
            Ok(bytes) => {
                if bytes.is_empty() {
                    self.available = self.fetched;
                }
                self.fetched += bytes.len() as u64;
                Ok(bytes)
            }
            Err(Fault::Source(error)) => Err(self.fail(error)),
            Err(Fault::Format) => Err(self.fail(Error::internal("the archive ends inside an entry"))),
        }
    }

    /// The checks at the end of the data: the size, the data descriptor, the CRC-32.
    async fn finish(&mut self) -> Result<()> {
        if self.produced != self.entry.size {
            return Err(self.fail(Error::internal("the archive entry is shorter than its size")));
        }
        let crc = self.crc.sum();
        if self.entry.has_data_descriptor() {
            let offset = self.data_start.saturating_add(self.entry.compressed_size);
            let descriptor = match self.reader.read_section(offset, DATA_DESCRIPTOR_LEN).await {
                Ok(bytes) => bytes,
                Err(Fault::Source(error)) => return Err(self.fail(error)),
                Err(Fault::Format) => Bytes::new(),
            };
            let mut fields = Fields(&descriptor);
            let signed = descriptor.len() >= 4 && fields.u32() == DATA_DESCRIPTOR_SIGNATURE;
            let (needed, crc_at) = if signed { (16, 4) } else { (12, 0) };
            if descriptor.len() < needed {
                return Err(self.fail(Error::internal(
                    "the data descriptor of the archive entry ends too soon",
                )));
            }
            let stored = Fields(&descriptor[crc_at..]).u32();
            if stored != self.entry.crc32 || crc != self.entry.crc32 {
                return Err(self.fail(Error::internal("the checksum of the archive entry does not match")));
            }
        } else if self.entry.crc32 != 0 && crc != self.entry.crc32 {
            return Err(self.fail(Error::internal("the checksum of the archive entry does not match")));
        }
        self.state = StreamState::Ended;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
