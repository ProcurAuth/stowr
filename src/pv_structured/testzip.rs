//! A small builder of ZIP archives for the tests: stored and deflated entries, with the system and the attributes
//! of each entry.

use std::io::Write as _;

use flate2::Compression;
use flate2::write::DeflateEncoder;

/// One entry of a test archive.
pub struct Entry {
    /// The name.
    pub name: String,
    /// The data, before the compression.
    pub data: Vec<u8>,
    /// The method: 0 stored, 8 deflate.
    pub method: u16,
    /// The system that made the entry: 3 for Unix, 0 for DOS.
    pub creator: u8,
    /// The external attributes: the Unix mode in the 16 high bits.
    pub attributes: u32,
}

impl Entry {
    /// A deflated file.
    pub fn file(name: &str, data: &str) -> Self {
        Self {
            name: name.to_owned(),
            data: data.as_bytes().to_vec(),
            method: 8,
            creator: 3,
            attributes: 0o100_644 << 16,
        }
    }

    /// A stored file.
    pub fn stored(name: &str, data: &str) -> Self {
        Self {
            method: 0,
            ..Self::file(name, data)
        }
    }

    /// A folder record.
    pub fn folder(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            data: Vec::new(),
            method: 0,
            creator: 3,
            attributes: (0o040_755 << 16) | 0x10,
        }
    }

    /// A symbolic link.
    pub fn symlink(name: &str, target: &str) -> Self {
        Self {
            name: name.to_owned(),
            data: target.as_bytes().to_vec(),
            method: 0,
            creator: 3,
            attributes: 0o120_777 << 16,
        }
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}

/// The bytes of an archive with these entries.
pub fn build(entries: &[Entry]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut directory: Vec<u8> = Vec::new();
    for entry in entries {
        let offset = out.len() as u32;
        let compressed = if entry.method == 8 {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            let _ = encoder.write_all(&entry.data);
            encoder.finish().unwrap_or_default()
        } else {
            entry.data.clone()
        };
        let crc = crc32(&entry.data);
        let name = entry.name.as_bytes();
        // The local header.
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&entry.method.to_le_bytes());
        out.extend_from_slice(&0x6000u16.to_le_bytes());
        out.extend_from_slice(&0x5c64u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        out.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&compressed);
        // The central directory header.
        directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        directory.extend_from_slice(&(u16::from(entry.creator) << 8 | 20).to_le_bytes());
        directory.extend_from_slice(&20u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&entry.method.to_le_bytes());
        directory.extend_from_slice(&0x6000u16.to_le_bytes());
        directory.extend_from_slice(&0x5c64u16.to_le_bytes());
        directory.extend_from_slice(&crc.to_le_bytes());
        directory.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        directory.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
        directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&entry.attributes.to_le_bytes());
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name);
    }
    let directory_offset = out.len() as u32;
    out.extend_from_slice(&directory);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    out.extend_from_slice(&directory_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}
