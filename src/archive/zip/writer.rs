//! The streamed ZIP writer of the ZIP of a folder.
//!
//! Each entry is stored (method 0). A file entry has a local header with a CRC-32 and sizes of 0 and the flag
//! 0x8, its data, then a data descriptor with a signature. A folder entry (a name that ends with `/`) has no data
//! and no data descriptor. The central directory comes after the entries. The ZIP64 fields and records appear only
//! when a size, an offset or the count of the entries needs them.
//!
//! Each header has these fields: the version 2.0 (4.5 in the central directory for an entry of 4 GiB or more), the
//! system Unix, the flag UTF-8 when the name has a character outside the safe ASCII set, the DOS date and time and
//! an extended timestamp when the entry has a time, and the Unix mode of a regular file. The writer keeps no data
//! of an entry: [`ZipWriter::take_output`] gives the bytes to send.

use bytes::{BufMut, Bytes, BytesMut};
use flate2::Crc;

use super::{FLAG_DATA_DESCRIPTOR, FLAG_UTF8, METHOD_STORE, civil_from_days};
use crate::common::error::{Error, Result};
use crate::common::time::Timestamp;

const VERSION_20: u16 = 20;
const VERSION_45: u16 = 45;
const CREATOR_UNIX: u16 = 3 << 8;
const LOCAL_HEADER_SIGNATURE: u32 = 0x0403_4b50;
const DIRECTORY_HEADER_SIGNATURE: u32 = 0x0201_4b50;
const DIRECTORY_END_SIGNATURE: u32 = 0x0605_4b50;
const DIRECTORY64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const DIRECTORY64_END_SIGNATURE: u32 = 0x0606_4b50;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const DIRECTORY64_END_LEN: u64 = 56;
const EXTRA_ZIP64: u16 = 0x0001;
const EXTRA_EXTENDED_TIME: u16 = 0x5455;
const UINT16_MAX: u64 = 0xffff;
const UINT32_MAX: u64 = 0xffff_ffff;
const UNIX_REGULAR: u32 = 0o100_000;
const DOS_READ_ONLY: u32 = 0x01;

/// The header of a new entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryHeader {
    /// The name. A name that ends with `/` is a folder.
    pub name: String,
    /// The time of the last change, in UTC. `None` gives a DOS date and time of 0 and no extended timestamp.
    pub modified: Option<Timestamp>,
    /// The Unix permissions (for example `0o600`). The type of the entry is always a regular file.
    pub permissions: u32,
}

/// One entry of the central directory.
#[derive(Debug)]
struct Record {
    name: Vec<u8>,
    extra: Vec<u8>,
    reader_version: u16,
    flags: u16,
    modified_time: u16,
    modified_date: u16,
    crc32: u32,
    compressed_size: u64,
    size: u64,
    external_attributes: u32,
    offset: u64,
}

impl Record {
    fn is_zip64(&self) -> bool {
        self.compressed_size >= UINT32_MAX || self.size >= UINT32_MAX
    }
}

/// The entry that takes the data now.
#[derive(Debug)]
struct OpenEntry {
    index: usize,
    folder: bool,
    crc: Crc,
    size: u64,
}

/// A ZIP writer that gives its bytes in order.
#[derive(Debug, Default)]
pub struct ZipWriter {
    written: u64,
    records: Vec<Record>,
    open: Option<OpenEntry>,
    pending: Vec<Bytes>,
    closed: bool,
}

/// True when a name needs the flag UTF-8: a character below 0x20, above 0x7d, or `\`.
fn requires_utf8(name: &str) -> bool {
    name.chars().any(|c| {
        let code = u32::from(c);
        !(0x20..=0x7d).contains(&code) || code == 0x5c
    })
}

/// The DOS date and time of a time, with the fields of its own offset. A year before 1980 wraps as the 16-bit
/// fields do.
pub fn dos_date_time(time: Timestamp) -> (u16, u16) {
    let local = time.secs + i64::from(time.offset);
    let (year, month, day) = civil_from_days(local.div_euclid(86_400));
    let rest = local.rem_euclid(86_400);
    let (hour, minute, second) = (rest / 3600, (rest / 60) % 60, rest % 60);
    let date = day + (month << 5) + ((year - 1980) << 9);
    let clock = second / 2 + (minute << 5) + (hour << 11);
    (date as u16, clock as u16)
}

impl ZipWriter {
    /// A writer at the offset 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// The bytes that the writer gave so far, in total.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// The bytes to send, in order. The writer forgets them.
    pub fn take_output(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.pending)
    }

    fn push(&mut self, bytes: Bytes) {
        self.written += bytes.len() as u64;
        self.pending.push(bytes);
    }

    /// End the entry that takes the data: its data descriptor.
    fn close_entry(&mut self) {
        let Some(open) = self.open.take() else {
            return;
        };
        if open.folder {
            return;
        }
        let Some(record) = self.records.get_mut(open.index) else {
            return;
        };
        record.crc32 = open.crc.sum();
        record.compressed_size = open.size;
        record.size = open.size;
        let zip64 = record.is_zip64();
        if zip64 {
            record.reader_version = VERSION_45;
        }
        let mut descriptor = BytesMut::with_capacity(24);
        descriptor.put_u32_le(DATA_DESCRIPTOR_SIGNATURE);
        descriptor.put_u32_le(record.crc32);
        if zip64 {
            descriptor.put_u64_le(record.compressed_size);
            descriptor.put_u64_le(record.size);
        } else {
            descriptor.put_u32_le(record.compressed_size as u32);
            descriptor.put_u32_le(record.size as u32);
        }
        self.push(descriptor.freeze());
    }

    /// Start an entry: end the entry before it, then write the local header.
    pub fn create(&mut self, header: &EntryHeader) -> Result<()> {
        self.close_entry();
        if self.closed {
            return Err(Error::internal("the archive writer is closed"));
        }
        let name = header.name.as_bytes().to_vec();
        if name.len() > usize::from(u16::MAX) {
            return Err(Error::internal("the name of the archive entry is too long"));
        }
        let folder = header.name.ends_with('/');
        let mut flags = 0u16;
        if requires_utf8(&header.name) {
            flags |= FLAG_UTF8;
        }
        if !folder {
            flags |= FLAG_DATA_DESCRIPTOR;
        }
        let (modified_date, modified_time, extra) = match header.modified {
            Some(time) => {
                let (date, clock) = dos_date_time(time);
                let mut extra = Vec::with_capacity(9);
                extra.extend_from_slice(&EXTRA_EXTENDED_TIME.to_le_bytes());
                extra.extend_from_slice(&5u16.to_le_bytes());
                extra.push(1);
                extra.extend_from_slice(&(time.secs as u32).to_le_bytes());
                (date, clock, extra)
            }
            None => (0, 0, Vec::new()),
        };
        let mut external_attributes = (UNIX_REGULAR | (header.permissions & 0o777)) << 16;
        if header.permissions & 0o200 == 0 {
            external_attributes |= DOS_READ_ONLY;
        }
        let record = Record {
            name,
            extra,
            reader_version: VERSION_20,
            flags,
            modified_time,
            modified_date,
            crc32: 0,
            compressed_size: 0,
            size: 0,
            external_attributes,
            offset: self.written,
        };
        let mut local = BytesMut::with_capacity(30 + record.name.len() + record.extra.len());
        local.put_u32_le(LOCAL_HEADER_SIGNATURE);
        local.put_u16_le(record.reader_version);
        local.put_u16_le(record.flags);
        local.put_u16_le(METHOD_STORE);
        local.put_u16_le(record.modified_time);
        local.put_u16_le(record.modified_date);
        local.put_u32_le(0);
        local.put_u32_le(0);
        local.put_u32_le(0);
        local.put_u16_le(record.name.len() as u16);
        local.put_u16_le(record.extra.len() as u16);
        local.put_slice(&record.name);
        local.put_slice(&record.extra);
        self.records.push(record);
        self.open = Some(OpenEntry {
            index: self.records.len() - 1,
            folder,
            crc: Crc::new(),
            size: 0,
        });
        self.push(local.freeze());
        Ok(())
    }

    /// Add data to the entry that the last [`ZipWriter::create`] started. A folder entry takes no data.
    pub fn write(&mut self, data: Bytes) -> Result<()> {
        let Some(open) = self.open.as_mut() else {
            return Err(Error::internal("the archive writer has no open entry"));
        };
        if data.is_empty() {
            return Ok(());
        }
        if open.folder {
            return Err(Error::internal("a folder entry of the archive takes no data"));
        }
        open.crc.update(&data);
        open.size += data.len() as u64;
        self.push(data);
        Ok(())
    }

    /// End the archive: the data descriptor of the last entry, the central directory and the end records.
    pub fn finish(&mut self) -> Result<()> {
        self.close_entry();
        if self.closed {
            return Err(Error::internal("the archive writer is closed two times"));
        }
        self.closed = true;
        let start = self.written;
        let records = std::mem::take(&mut self.records);
        for record in &records {
            let mut extra = record.extra.clone();
            let mut header = BytesMut::with_capacity(46 + record.name.len() + extra.len() + 28);
            header.put_u32_le(DIRECTORY_HEADER_SIGNATURE);
            header.put_u16_le(CREATOR_UNIX | VERSION_20);
            header.put_u16_le(record.reader_version);
            header.put_u16_le(record.flags);
            header.put_u16_le(METHOD_STORE);
            header.put_u16_le(record.modified_time);
            header.put_u16_le(record.modified_date);
            header.put_u32_le(record.crc32);
            if record.is_zip64() || record.offset >= UINT32_MAX {
                header.put_u32_le(UINT32_MAX as u32);
                header.put_u32_le(UINT32_MAX as u32);
                extra.extend_from_slice(&EXTRA_ZIP64.to_le_bytes());
                extra.extend_from_slice(&24u16.to_le_bytes());
                extra.extend_from_slice(&record.size.to_le_bytes());
                extra.extend_from_slice(&record.compressed_size.to_le_bytes());
                extra.extend_from_slice(&record.offset.to_le_bytes());
            } else {
                header.put_u32_le(record.compressed_size as u32);
                header.put_u32_le(record.size as u32);
            }
            header.put_u16_le(record.name.len() as u16);
            header.put_u16_le(extra.len() as u16);
            header.put_u16_le(0);
            header.put_u16_le(0);
            header.put_u16_le(0);
            header.put_u32_le(record.external_attributes);
            header.put_u32_le(if record.offset > UINT32_MAX {
                UINT32_MAX as u32
            } else {
                record.offset as u32
            });
            header.put_slice(&record.name);
            header.put_slice(&extra);
            self.push(header.freeze());
        }
        let end = self.written;
        let mut count = records.len() as u64;
        let mut size = end - start;
        let mut offset = start;
        let mut tail = BytesMut::with_capacity(98);
        if count >= UINT16_MAX || size >= UINT32_MAX || offset >= UINT32_MAX {
            tail.put_u32_le(DIRECTORY64_END_SIGNATURE);
            tail.put_u64_le(DIRECTORY64_END_LEN - 12);
            tail.put_u16_le(VERSION_45);
            tail.put_u16_le(VERSION_45);
            tail.put_u32_le(0);
            tail.put_u32_le(0);
            tail.put_u64_le(count);
            tail.put_u64_le(count);
            tail.put_u64_le(size);
            tail.put_u64_le(offset);
            tail.put_u32_le(DIRECTORY64_LOCATOR_SIGNATURE);
            tail.put_u32_le(0);
            tail.put_u64_le(end);
            tail.put_u32_le(1);
            count = UINT16_MAX;
            size = UINT32_MAX;
            offset = UINT32_MAX;
        }
        tail.put_u32_le(DIRECTORY_END_SIGNATURE);
        tail.put_u16_le(0);
        tail.put_u16_le(0);
        tail.put_u16_le(count as u16);
        tail.put_u16_le(count as u16);
        tail.put_u32_le(size as u32);
        tail.put_u32_le(offset as u32);
        tail.put_u16_le(0);
        self.push(tail.freeze());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn concat(parts: Vec<Bytes>) -> Vec<u8> {
        parts.iter().flat_map(|part| part.iter().copied()).collect()
    }

    #[test]
    fn a_stored_entry_has_the_header_fields_of_the_archives_of_folders() {
        let mut writer = ZipWriter::new();
        let modified = Timestamp::parse_rfc3339("2024-05-06T07:08:10Z");
        writer
            .create(&EntryHeader {
                name: "a.txt".to_owned(),
                modified,
                permissions: 0o600,
            })
            .unwrap();
        writer.write(Bytes::from_static(b"hello")).unwrap();
        writer.finish().unwrap();
        let bytes = concat(writer.take_output());
        let (date, clock) = dos_date_time(modified.unwrap());
        let mut expected = Vec::new();
        // The local header.
        expected.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04, 20, 0, 0x08, 0x00, 0, 0]);
        expected.extend_from_slice(&clock.to_le_bytes());
        expected.extend_from_slice(&date.to_le_bytes());
        expected.extend_from_slice(&[0; 12]);
        expected.extend_from_slice(&[5, 0, 9, 0]);
        expected.extend_from_slice(b"a.txt");
        let unix = modified.unwrap().secs as u32;
        let mut extra = vec![0x55, 0x54, 5, 0, 1];
        extra.extend_from_slice(&unix.to_le_bytes());
        expected.extend_from_slice(&extra);
        expected.extend_from_slice(b"hello");
        // The data descriptor.
        let crc = {
            let mut crc = Crc::new();
            crc.update(b"hello");
            crc.sum()
        };
        expected.extend_from_slice(&[0x50, 0x4b, 0x07, 0x08]);
        expected.extend_from_slice(&crc.to_le_bytes());
        expected.extend_from_slice(&[5, 0, 0, 0, 5, 0, 0, 0]);
        let directory = expected.len() as u32;
        // The central directory.
        expected.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02, 20, 3, 20, 0, 0x08, 0x00, 0, 0]);
        expected.extend_from_slice(&clock.to_le_bytes());
        expected.extend_from_slice(&date.to_le_bytes());
        expected.extend_from_slice(&crc.to_le_bytes());
        expected.extend_from_slice(&[5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 9, 0, 0, 0, 0, 0, 0, 0]);
        expected.extend_from_slice(&(0o100_600u32 << 16).to_le_bytes());
        expected.extend_from_slice(&[0, 0, 0, 0]);
        expected.extend_from_slice(b"a.txt");
        expected.extend_from_slice(&extra);
        let size = expected.len() as u32 - directory;
        expected.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 1, 0, 1, 0]);
        expected.extend_from_slice(&size.to_le_bytes());
        expected.extend_from_slice(&directory.to_le_bytes());
        expected.extend_from_slice(&[0, 0]);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn a_folder_entry_has_no_data_descriptor_and_refuses_data() {
        let mut writer = ZipWriter::new();
        writer
            .create(&EntryHeader {
                name: "docs/".to_owned(),
                modified: None,
                permissions: 0o755,
            })
            .unwrap();
        assert!(writer.write(Bytes::from_static(b"x")).is_err());
        writer.write(Bytes::new()).unwrap();
        writer.finish().unwrap();
        let bytes = concat(writer.take_output());
        // Flags 0, no extra, no descriptor: the central directory follows the local header at once.
        assert_eq!(&bytes[6..8], &[0, 0]);
        assert_eq!(&bytes[30..35], b"docs/");
        assert_eq!(&bytes[35..39], &[0x50, 0x4b, 0x01, 0x02]);
        // The mode of a regular file with 0755.
        assert_eq!(&bytes[35 + 38..35 + 42], &(0o100_755u32 << 16).to_le_bytes());
    }

    #[test]
    fn names_outside_the_safe_ascii_set_get_the_utf8_flag() {
        assert!(!requires_utf8("plain name.txt"));
        assert!(requires_utf8("name~2.txt"));
        assert!(requires_utf8("back\\slash"));
        assert!(requires_utf8("café"));
        assert!(requires_utf8("tab\t"));
    }

    #[test]
    fn dos_dates_wrap_before_1980() {
        let time = Timestamp::parse_rfc3339("1979-11-30T00:00:00Z").unwrap();
        let (date, clock) = dos_date_time(time);
        assert_eq!(clock, 0);
        assert_eq!(date, (30 + (11 << 5) + ((-1i64) << 9)) as u16);
        let time = Timestamp::parse_rfc3339("2026-11-23T10:20:31Z").unwrap();
        assert_eq!(
            dos_date_time(time),
            (
                (23 + (11 << 5) + (46 << 9)) as u16,
                (15 + (20 << 5) + (10 << 11)) as u16
            )
        );
    }

    #[test]
    fn a_closed_writer_refuses_a_second_end() {
        let mut writer = ZipWriter::new();
        writer.finish().unwrap();
        assert!(writer.finish().is_err());
        assert!(
            writer
                .create(&EntryHeader {
                    name: "late".to_owned(),
                    ..EntryHeader::default()
                })
                .is_err()
        );
        let bytes = concat(writer.take_output());
        assert_eq!(
            bytes,
            [
                0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }
}
