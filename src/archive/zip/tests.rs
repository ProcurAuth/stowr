use std::sync::Mutex;

use flate2::{Compress, Compression, FlushCompress};

use super::writer::{EntryHeader, ZipWriter};
use super::*;

/// One entry of a test archive.
#[derive(Clone)]
pub(crate) struct Spec {
    pub(crate) name: Vec<u8>,
    pub(crate) data: Vec<u8>,
    pub(crate) method: u16,
    pub(crate) flags: u16,
    /// The data descriptor: `Some(true)` with a signature, `Some(false)` without.
    pub(crate) descriptor: Option<bool>,
    pub(crate) crc: Option<u32>,
    pub(crate) size: Option<u64>,
    pub(crate) creator: u16,
    pub(crate) attributes: u32,
    pub(crate) date: u16,
    pub(crate) time: u16,
    pub(crate) extra: Vec<u8>,
    pub(crate) zip64: bool,
}

impl Spec {
    pub(crate) fn new(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            data: data.to_vec(),
            method: METHOD_STORE,
            flags: 0,
            descriptor: None,
            crc: None,
            size: None,
            creator: 20,
            attributes: 0,
            date: 0x5b37,
            time: 0x5a21,
            extra: Vec::new(),
            zip64: false,
        }
    }

    pub(crate) fn deflated(mut self) -> Self {
        self.method = METHOD_DEFLATE;
        self
    }
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut compress = Compress::new(Compression::default(), false);
    let mut out = Vec::with_capacity(data.len() + 1024);
    loop {
        let before = compress.total_in() as usize;
        let status = compress
            .compress_vec(&data[before..], &mut out, FlushCompress::Finish)
            .unwrap();
        if status == flate2::Status::StreamEnd {
            return out;
        }
        out.reserve(64 << 10);
    }
}

fn crc_of(data: &[u8]) -> u32 {
    let mut crc = Crc::new();
    crc.update(data);
    crc.sum()
}

/// Build an archive: a prefix, the entries, the central directory, the ZIP64 records when asked, the end record.
pub(crate) fn build(specs: &[Spec], prefix: &[u8], comment: &[u8], zip64_end: bool, records: Option<u16>) -> Vec<u8> {
    let mut out = prefix.to_vec();
    let mut central = Vec::new();
    for spec in specs {
        let offset = (out.len() - prefix.len()) as u64;
        let payload = if spec.method == METHOD_DEFLATE {
            deflate(&spec.data)
        } else {
            spec.data.clone()
        };
        let crc = spec.crc.unwrap_or_else(|| crc_of(&spec.data));
        let size = spec.size.unwrap_or(spec.data.len() as u64);
        let mut flags = spec.flags;
        if spec.descriptor.is_some() {
            flags |= FLAG_DATA_DESCRIPTOR;
        }
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&spec.method.to_le_bytes());
        out.extend_from_slice(&spec.time.to_le_bytes());
        out.extend_from_slice(&spec.date.to_le_bytes());
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&(spec.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&spec.name);
        out.extend_from_slice(&payload);
        match spec.descriptor {
            Some(true) => {
                out.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
                out.extend_from_slice(&crc.to_le_bytes());
                out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                out.extend_from_slice(&(size as u32).to_le_bytes());
            }
            Some(false) => {
                out.extend_from_slice(&crc.to_le_bytes());
                out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                out.extend_from_slice(&(size as u32).to_le_bytes());
            }
            None => {}
        }
        let mut extra = spec.extra.clone();
        let (compressed32, size32, offset32) = if spec.zip64 {
            extra.extend_from_slice(&1u16.to_le_bytes());
            extra.extend_from_slice(&24u16.to_le_bytes());
            extra.extend_from_slice(&size.to_le_bytes());
            extra.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            extra.extend_from_slice(&offset.to_le_bytes());
            (u32::MAX, u32::MAX, u32::MAX)
        } else {
            (payload.len() as u32, size as u32, offset as u32)
        };
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&spec.creator.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&spec.method.to_le_bytes());
        central.extend_from_slice(&spec.time.to_le_bytes());
        central.extend_from_slice(&spec.date.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&compressed32.to_le_bytes());
        central.extend_from_slice(&size32.to_le_bytes());
        central.extend_from_slice(&(spec.name.len() as u16).to_le_bytes());
        central.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&[0; 4]);
        central.extend_from_slice(&spec.attributes.to_le_bytes());
        central.extend_from_slice(&offset32.to_le_bytes());
        central.extend_from_slice(&spec.name);
        central.extend_from_slice(&extra);
    }
    let directory_offset = (out.len() - prefix.len()) as u64;
    let directory_size = central.len() as u64;
    out.extend_from_slice(&central);
    let count = records.unwrap_or(specs.len() as u16);
    if zip64_end {
        let end64 = (out.len() - prefix.len()) as u64;
        out.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
        out.extend_from_slice(&44u64.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&(specs.len() as u64).to_le_bytes());
        out.extend_from_slice(&(specs.len() as u64).to_le_bytes());
        out.extend_from_slice(&directory_size.to_le_bytes());
        out.extend_from_slice(&directory_offset.to_le_bytes());
        out.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&end64.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
    }
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    let (records16, size32, offset32) = if zip64_end {
        (0xffffu16, u32::MAX, u32::MAX)
    } else {
        (count, directory_size as u32, directory_offset as u32)
    };
    out.extend_from_slice(&records16.to_le_bytes());
    out.extend_from_slice(&records16.to_le_bytes());
    out.extend_from_slice(&size32.to_le_bytes());
    out.extend_from_slice(&offset32.to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    out
}

pub(crate) fn simple(specs: &[Spec]) -> Bytes {
    Bytes::from(build(specs, b"", b"", false, None))
}

async fn read_all<S: ByteSource>(reader: &ZipReader<S>, name: &str) -> Result<Vec<u8>> {
    let entry = reader.entry(name).cloned().expect("entry");
    let mut stream = reader.open_entry(&entry).await?;
    let mut out = Vec::new();
    while let Some(chunk) = stream.next_chunk().await? {
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// A source that records each read and can hide its size until a suffix read.
struct RecordingSource {
    data: Bytes,
    known: Mutex<bool>,
    reads: Mutex<Vec<(u64, u64)>>,
    suffixes: Mutex<Vec<u64>>,
}

impl RecordingSource {
    fn new(data: Bytes, known: bool) -> Self {
        Self {
            data,
            known: Mutex::new(known),
            reads: Mutex::new(Vec::new()),
            suffixes: Mutex::new(Vec::new()),
        }
    }
}

impl ByteSource for RecordingSource {
    fn source_size(&self) -> Option<u64> {
        if *self.known.lock().unwrap() {
            self.data.source_size()
        } else {
            None
        }
    }

    fn fetch_suffix(&self, length: u64) -> BoxFuture<'_, Result<Bytes>> {
        self.suffixes.lock().unwrap().push(length);
        *self.known.lock().unwrap() = true;
        self.data.fetch_suffix(length)
    }

    fn fetch(&self, offset: u64, length: u64) -> BoxFuture<'_, Result<Bytes>> {
        self.reads.lock().unwrap().push((offset, length));
        self.data.fetch(offset, length)
    }
}

#[tokio::test]
async fn the_reader_lists_the_entries_of_a_stored_archive() {
    let archive = simple(&[Spec::new("a.txt", b"alpha"), Spec::new("dir/b.txt", b"beta beta")]);
    let reader = ZipReader::open(archive, 0).await.unwrap();
    let names: Vec<&str> = reader.entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, ["a.txt", "dir/b.txt"]);
    let entry = reader.entry("dir/b.txt").unwrap();
    assert_eq!(entry.size, 9);
    assert_eq!(entry.compressed_size, 9);
    assert_eq!(entry.crc32, crc_of(b"beta beta"));
    assert_eq!(entry.method, METHOD_STORE);
    assert_eq!(read_all(&reader, "a.txt").await.unwrap(), b"alpha");
    assert_eq!(read_all(&reader, "dir/b.txt").await.unwrap(), b"beta beta");
    assert_eq!(reader.read_entry(entry, 9).await.unwrap(), &b"beta beta"[..]);
    let error = reader.read_entry(entry, 8).await.unwrap_err();
    assert!(error.has_code(CODE_ENTRY_TOO_LARGE));
}

#[tokio::test]
async fn deflated_entries_of_several_blocks_stream_and_check_their_checksum() {
    let mut large = Vec::with_capacity(3 << 20);
    let mut seed = 7u32;
    for _ in 0..(3 << 20) {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        large.push((seed >> 24) as u8 % 7 + b'a');
    }
    let archive = simple(&[
        Spec::new("small.txt", b"small text").deflated(),
        Spec::new("large.bin", &large).deflated(),
        Spec::new("stored.bin", &large[..1_500_000]),
    ]);
    assert!(archive.len() > (2 << 20));
    let source = Arc::new(RecordingSource::new(archive, true));
    let reader = ZipReader::open(source.clone(), 0).await.unwrap();
    assert_eq!(read_all(&reader, "small.txt").await.unwrap(), b"small text");
    assert_eq!(read_all(&reader, "large.bin").await.unwrap(), large);
    assert_eq!(read_all(&reader, "stored.bin").await.unwrap(), &large[..1_500_000]);
    let reads = source.reads.lock().unwrap().clone();
    let total = source.data.len() as u64;
    for (offset, length) in reads {
        assert_eq!(offset % BLOCK_BYTES, 0, "a read starts inside a block");
        assert_eq!(length, BLOCK_BYTES.min(total - offset), "a read is not one whole block");
    }
}

#[tokio::test]
async fn the_central_directory_read_needs_only_the_last_block() {
    let payload = vec![b'x'; (5 << 20) - (200 << 10)];
    let archive = simple(&[Spec::new("big.bin", &payload), Spec::new("tail.txt", b"tail")]);
    let total = archive.len() as u64;
    let source = Arc::new(RecordingSource::new(archive, true));
    let reader = ZipReader::open(source.clone(), 0).await.unwrap();
    assert_eq!(reader.entries.len(), 2);
    let reads = source.reads.lock().unwrap().clone();
    assert_eq!(reads, vec![(4 * BLOCK_BYTES, total - 4 * BLOCK_BYTES)]);
}

#[tokio::test]
async fn an_unknown_size_reads_a_suffix_first() {
    let archive = simple(&[Spec::new("a.txt", b"alpha")]);
    let source = Arc::new(RecordingSource::new(archive, false));
    let reader = ZipReader::open(source.clone(), 0).await.unwrap();
    assert_eq!(reader.entries.len(), 1);
    assert_eq!(*source.suffixes.lock().unwrap(), vec![SUFFIX_BYTES]);
}

#[tokio::test]
async fn data_descriptors_with_and_without_signature_are_checked() {
    let mut signed = Spec::new("signed.txt", b"signed data").deflated();
    signed.descriptor = Some(true);
    let mut plain = Spec::new("plain.txt", b"plain data");
    plain.descriptor = Some(false);
    let archive = simple(&[signed, plain]);
    let reader = ZipReader::open(archive, 0).await.unwrap();
    assert_eq!(read_all(&reader, "signed.txt").await.unwrap(), b"signed data");
    assert_eq!(read_all(&reader, "plain.txt").await.unwrap(), b"plain data");
}

#[tokio::test]
async fn a_wrong_checksum_fails_at_the_end_of_the_entry() {
    let mut stored = Spec::new("stored.txt", b"content");
    stored.crc = Some(0x1234_5678);
    let mut deflated = Spec::new("deflated.txt", b"content").deflated();
    deflated.crc = Some(0x1234_5678);
    let mut unchecked = Spec::new("unchecked.txt", b"content");
    unchecked.crc = Some(0);
    let mut described = Spec::new("described.txt", b"content");
    described.crc = Some(0);
    described.descriptor = Some(true);
    let archive = simple(&[stored, deflated, unchecked, described]);
    let reader = ZipReader::open(archive, 0).await.unwrap();
    let entry = reader.entry("stored.txt").cloned().unwrap();
    let mut stream = reader.open_entry(&entry).await.unwrap();
    assert_eq!(stream.next_chunk().await.unwrap().unwrap(), &b"content"[..]);
    let error = stream.next_chunk().await.unwrap_err();
    assert!(error.to_string().contains("checksum"));
    assert!(stream.next_chunk().await.is_err(), "the error stays");
    assert!(read_all(&reader, "deflated.txt").await.is_err());
    // A CRC-32 of 0 without a data descriptor is not checked.
    assert_eq!(read_all(&reader, "unchecked.txt").await.unwrap(), b"content");
    // With a data descriptor, the CRC-32 is always checked.
    assert!(read_all(&reader, "described.txt").await.is_err());
}

#[tokio::test]
async fn an_entry_never_gives_more_or_fewer_bytes_than_its_size() {
    let mut longer = Spec::new("longer.txt", b"0123456789");
    longer.size = Some(4);
    let mut shorter = Spec::new("shorter.txt", b"0123");
    shorter.size = Some(10);
    let mut bomb = Spec::new("bomb.txt", &[0u8; 100_000]).deflated();
    bomb.size = Some(1000);
    let archive = simple(&[longer, shorter, bomb]);
    let reader = ZipReader::open(archive, 0).await.unwrap();
    let error = read_all(&reader, "longer.txt").await.unwrap_err();
    assert!(error.to_string().contains("larger"));
    let error = read_all(&reader, "shorter.txt").await.unwrap_err();
    assert!(error.to_string().contains("shorter"));
    let entry = reader.entry("bomb.txt").cloned().unwrap();
    let mut stream = reader.open_entry(&entry).await.unwrap();
    let mut total = 0;
    let error = loop {
        match stream.next_chunk().await {
            Ok(Some(chunk)) => total += chunk.len(),
            Ok(None) => panic!("the stream ended without an error"),
            Err(error) => break error,
        }
    };
    assert!(total <= 1000);
    assert!(error.to_string().contains("larger"));
}

#[tokio::test]
async fn zip64_fields_and_records_give_the_sizes_and_the_offsets() {
    let mut big = Spec::new("zip64.txt", b"sixty four");
    big.zip64 = true;
    let archive = Bytes::from(build(&[Spec::new("first.txt", b"one"), big], b"", b"", true, None));
    let reader = ZipReader::open(archive, 0).await.unwrap();
    assert_eq!(reader.entries.len(), 2);
    let entry = reader.entry("zip64.txt").unwrap();
    assert!(entry.zip64);
    assert_eq!(entry.size, 10);
    assert_eq!(entry.compressed_size, 10);
    assert_eq!(read_all(&reader, "zip64.txt").await.unwrap(), b"sixty four");
}

#[tokio::test]
async fn bytes_before_the_archive_move_the_offsets() {
    let specs = [Spec::new("a.txt", b"alpha"), Spec::new("b.txt", b"beta")];
    let prefix = b"#!/bin/sh\nexit 0\n";
    let archive = Bytes::from(build(&specs, prefix, b"", false, None));
    let reader = ZipReader::open(archive, 0).await.unwrap();
    assert_eq!(reader.entries[0].header_offset, prefix.len() as u64);
    assert_eq!(read_all(&reader, "b.txt").await.unwrap(), b"beta");
    // Bytes between the central directory and the end record: the header at the offset of the end record wins.
    let plain = build(&specs, b"", b"", false, None);
    let (body, end) = plain.split_at(plain.len() - 22);
    let mut padded = body.to_vec();
    padded.extend_from_slice(&[0xaa; 40]);
    padded.extend_from_slice(end);
    let reader = ZipReader::open(Bytes::from(padded), 0).await.unwrap();
    assert_eq!(reader.entries[0].header_offset, 0);
    assert_eq!(read_all(&reader, "a.txt").await.unwrap(), b"alpha");
}

#[tokio::test]
async fn an_end_record_with_a_comment_is_found_and_a_cut_comment_is_refused() {
    let specs = [Spec::new("a.txt", b"alpha")];
    let archive = Bytes::from(build(&specs, b"", b"the comment", false, None));
    let reader = ZipReader::open(archive.clone(), 0).await.unwrap();
    assert_eq!(reader.comment, "the comment");
    let cut = archive.slice(..archive.len() - 3);
    let error = ZipReader::open(cut, 0).await.unwrap_err();
    assert!(is_format_error(&error));
    assert_eq!(error.status(), 422);
    assert_eq!(error.public_message(), MESSAGE_INVALID_ZIP);
}

#[tokio::test]
async fn objects_that_are_not_archives_are_refused() {
    for data in [&b"not a zip file at all"[..], b"PK\x05\x06", &[0u8; 5000][..]] {
        let error = ZipReader::open(Bytes::copy_from_slice(data), 0).await.unwrap_err();
        assert!(is_format_error(&error), "{data:?}");
    }
    let error = ZipReader::open(Bytes::new(), 0).await.unwrap_err();
    assert!(is_format_error(&error));
}

#[tokio::test]
async fn the_count_of_the_headers_must_agree_with_the_end_record() {
    let specs = [Spec::new("a.txt", b"alpha"), Spec::new("b.txt", b"beta")];
    let archive = Bytes::from(build(&specs, b"", b"", false, Some(3)));
    assert!(is_format_error(&ZipReader::open(archive, 0).await.unwrap_err()));
    // The low 16 bits only: 65537 headers in an end record of 1 are valid.
    let many: Vec<Spec> = (0..65_537).map(|_| Spec::new("a", b"")).collect();
    let archive = Bytes::from(build(&many, b"", b"", false, None));
    let reader = ZipReader::open(archive.clone(), 0).await.unwrap();
    assert_eq!(reader.entries.len(), 65_537);
    let error = ZipReader::open(archive, 10_000).await.unwrap_err();
    assert!(error.has_code(CODE_TOO_MANY_ENTRIES));
}

#[tokio::test]
async fn a_central_directory_over_the_limit_is_refused() {
    let specs: Vec<Spec> = (0..5)
        .map(|index| Spec::new(&format!("file-{index}.txt"), b"x"))
        .collect();
    let archive = simple(&specs);
    let error = ZipReader::open(archive.clone(), 3).await.unwrap_err();
    assert_eq!(error.status(), 413);
    assert!(error.has_code(CODE_TOO_MANY_ENTRIES));
    assert_eq!(
        error.public_message(),
        "the archive contains more than the configured limit of 3 entries"
    );
    assert_eq!(ZipReader::open(archive.clone(), 5).await.unwrap().entries.len(), 5);
    assert_eq!(ZipReader::open(archive, 0).await.unwrap().entries.len(), 5);
}

#[tokio::test]
async fn the_kind_of_an_entry_comes_from_its_name_and_its_attributes() {
    let mut unix_dir = Spec::new("unix-dir", b"");
    unix_dir.creator = 3 << 8;
    unix_dir.attributes = 0o040_755 << 16;
    let mut link = Spec::new("link", b"target");
    link.creator = 3 << 8;
    link.attributes = 0o120_777 << 16;
    let mut fifo = Spec::new("fifo", b"");
    fifo.creator = 3 << 8;
    fifo.attributes = 0o010_644 << 16;
    let mut dos_dir = Spec::new("dos-dir", b"");
    dos_dir.creator = 0;
    dos_dir.attributes = 0x10;
    let mut encrypted = Spec::new("secret.txt", b"xxxx");
    encrypted.flags = FLAG_ENCRYPTED;
    let archive = simple(&[
        Spec::new("folder/", b""),
        unix_dir,
        link,
        fifo,
        dos_dir,
        encrypted,
        Spec::new("plain.txt", b"x"),
    ]);
    let reader = ZipReader::open(archive, 0).await.unwrap();
    let get = |name: &str| reader.entry(name).unwrap();
    assert!(get("folder/").is_dir());
    assert!(get("unix-dir").is_dir());
    assert!(get("dos-dir").is_dir());
    assert!(get("link").is_symlink() && !get("link").is_regular());
    assert!(!get("fifo").is_regular() && !get("fifo").is_dir());
    assert!(get("secret.txt").is_encrypted());
    assert!(get("plain.txt").is_regular() && !get("plain.txt").is_dir() && !get("plain.txt").is_symlink());
    assert_eq!(read_all(&reader, "folder/").await.unwrap(), b"");
}

#[tokio::test]
async fn unknown_methods_and_bad_local_headers_fail_at_open() {
    let mut bzip = Spec::new("bzip.txt", b"data");
    bzip.method = 12;
    let archive = simple(&[bzip, Spec::new("good.txt", b"good")]);
    let reader = ZipReader::open(archive.clone(), 0).await.unwrap();
    let entry = reader.entry("bzip.txt").cloned().unwrap();
    let error = reader.open_entry(&entry).await.unwrap_err();
    assert!(is_unsupported_method(&error));
    let mut moved = reader.entry("good.txt").cloned().unwrap();
    moved.header_offset += 1;
    let error = reader.open_entry(&moved).await.unwrap_err();
    assert!(error.has_code(CODE_INVALID_ENTRY));
    moved.header_offset = u64::MAX;
    assert!(
        reader
            .open_entry(&moved)
            .await
            .unwrap_err()
            .has_code(CODE_INVALID_ENTRY)
    );
}

#[tokio::test]
async fn the_time_of_an_entry_follows_its_extended_timestamp() {
    // DOS only: 2025-09-23 11:17:02 in UTC.
    let dos = Spec::new("dos.txt", b"x");
    // An extended timestamp one hour before the DOS time: an offset of +01:00.
    let mut extended = Spec::new("extended.txt", b"x");
    let dos_secs = dos_seconds(0x5b37, 0x5a21);
    let mut extra = vec![0x55, 0x54, 5, 0, 1];
    extra.extend_from_slice(&((dos_secs - 3600) as u32).to_le_bytes());
    extended.extra = extra.clone();
    // The same timestamp without a DOS time: UTC.
    let mut alone = Spec::new("alone.txt", b"x");
    alone.extra = extra;
    alone.date = 0;
    alone.time = 0;
    // An NTFS time with a fraction.
    let mut ntfs = Spec::new("ntfs.txt", b"x");
    let ticks: u64 = (11_644_473_600 + 1_700_000_000) * 10_000_000 + 1_234_567;
    let mut field = vec![0x0a, 0x00, 32, 0, 0, 0, 0, 0, 1, 0, 24, 0];
    field.extend_from_slice(&ticks.to_le_bytes());
    field.extend_from_slice(&[0; 16]);
    ntfs.extra = field;
    ntfs.date = 0;
    ntfs.time = 0;
    // No date: the month 0 and the day 0 move the time back to 1979-11-30.
    let mut zero = Spec::new("zero.txt", b"x");
    zero.date = 0;
    zero.time = 0;
    let archive = simple(&[dos, extended, alone, ntfs, zero]);
    let reader = ZipReader::open(archive, 0).await.unwrap();
    let time = |name: &str| reader.entry(name).unwrap().modified.unwrap();
    assert_eq!(time("dos.txt").rfc3339(), "2025-09-23T11:17:02Z");
    assert_eq!(time("extended.txt").rfc3339(), "2025-09-23T11:17:02+01:00");
    assert_eq!(time("extended.txt").utc().rfc3339(), "2025-09-23T10:17:02Z");
    assert_eq!(time("alone.txt").rfc3339(), "2025-09-23T10:17:02Z");
    assert_eq!(time("ntfs.txt").secs, 1_700_000_000);
    assert_eq!(time("ntfs.txt").nanos, 123_456_700);
    assert_eq!(time("zero.txt").rfc3339(), "1979-11-30T00:00:00Z");
}

#[tokio::test]
async fn names_that_are_not_utf8_never_match_a_request() {
    let mut raw = Spec::new("x", b"data");
    raw.name = b"caf\xe9.txt".to_vec();
    let archive = simple(&[raw]);
    let reader = ZipReader::open(archive, 0).await.unwrap();
    assert_eq!(reader.entries[0].name, "caf\u{fffd}.txt");
    assert!(!reader.entries[0].name_is_utf8);
    assert!(reader.entry("caf\u{fffd}.txt").is_none());
    assert_eq!(lossy_text(b"a\xe2\x82b"), "a\u{fffd}\u{fffd}b");
}

#[tokio::test]
async fn crx_packages_open_after_their_header() {
    let inner = build(&[Spec::new("manifest.json", b"{}")], b"", b"", false, None);
    let mut v3 = b"Cr24".to_vec();
    v3.extend_from_slice(&3u32.to_le_bytes());
    v3.extend_from_slice(&6u32.to_le_bytes());
    v3.extend_from_slice(b"header");
    v3.extend_from_slice(&inner);
    let reader = ZipReader::open_package(Bytes::from(v3), "crx", 0).await.unwrap();
    assert_eq!(reader.start, 18);
    assert_eq!(read_all(&reader, "manifest.json").await.unwrap(), b"{}");
    let mut v2 = b"Cr24".to_vec();
    v2.extend_from_slice(&2u32.to_le_bytes());
    v2.extend_from_slice(&3u32.to_le_bytes());
    v2.extend_from_slice(&2u32.to_le_bytes());
    v2.extend_from_slice(b"keysg");
    v2.extend_from_slice(&inner);
    assert_eq!(crx_zip_offset(&v2, v2.len() as u64), Some(21));
    let reader = ZipReader::open_package(Bytes::from(v2), "crx", 0).await.unwrap();
    assert_eq!(read_all(&reader, "manifest.json").await.unwrap(), b"{}");
    assert_eq!(crx_zip_offset(b"Cr24\x04\x00\x00\x00\x00\x00\x00\x00", 100), None);
    assert_eq!(crx_zip_offset(b"PK\x03\x04", 100), None);
    let error = ZipReader::open_package(Bytes::from_static(b"Cr24\x03\x00\x00\x00\xff\x00\x00\x00"), "crx", 0)
        .await
        .unwrap_err();
    assert!(is_format_error(&error));
    assert!(is_zip_archive_extension("epub") && !is_zip_archive_extension("tar"));
}

#[tokio::test]
async fn a_shared_reader_gives_a_stream_that_moves_to_another_task() {
    let archive = simple(&[Spec::new("a.txt", b"alpha").deflated()]);
    let reader = Arc::new(ZipReader::open(archive, 0).await.unwrap());
    let entry = reader.entry("a.txt").cloned().unwrap();
    let mut stream = reader.open_entry_shared(&entry).await.unwrap();
    let task = tokio::spawn(async move {
        let mut out = Vec::new();
        while let Some(chunk) = stream.next_chunk().await.unwrap() {
            out.extend_from_slice(&chunk);
        }
        out
    });
    assert_eq!(task.await.unwrap(), b"alpha");
}

#[tokio::test]
async fn the_writer_output_reads_back_with_its_times_and_modes() {
    let mut writer = ZipWriter::new();
    let modified = Timestamp::parse_rfc3339("2024-02-29T23:59:58Z");
    writer
        .create(&EntryHeader {
            name: "folder/".to_owned(),
            modified,
            permissions: 0o755,
        })
        .unwrap();
    writer
        .create(&EntryHeader {
            name: "folder/file~2.txt".to_owned(),
            modified,
            permissions: 0o600,
        })
        .unwrap();
    writer.write(Bytes::from_static(b"first ")).unwrap();
    writer.write(Bytes::from_static(b"second")).unwrap();
    writer.finish().unwrap();
    let bytes: Vec<u8> = writer
        .take_output()
        .iter()
        .flat_map(|part| part.iter().copied())
        .collect();
    let reader = ZipReader::open(Bytes::from(bytes), 0).await.unwrap();
    assert_eq!(reader.entries.len(), 2);
    let file = reader.entry("folder/file~2.txt").unwrap();
    assert_eq!(file.flags, FLAG_DATA_DESCRIPTOR | FLAG_UTF8);
    assert_eq!(file.creator_version, 0x0314);
    assert_eq!(file.external_attributes, 0o100_600 << 16);
    assert_eq!(file.modified.unwrap().utc().rfc3339(), "2024-02-29T23:59:58Z");
    assert!(file.is_regular());
    assert!(reader.entry("folder/").unwrap().is_dir());
    assert_eq!(read_all(&reader, "folder/file~2.txt").await.unwrap(), b"first second");
}
