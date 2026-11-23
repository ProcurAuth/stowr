// SPDX-License-Identifier: MIT OR Apache-2.0
//! The integers of a byte slice in big-endian and little-endian order. A read past the end of the slice gives 0: the
//! readers check each length before a read.

fn array<const N: usize>(data: &[u8], at: usize) -> Option<[u8; N]> {
    data.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// The big-endian 16-bit integer at `at`.
pub(crate) fn be16(data: &[u8], at: usize) -> u16 {
    array(data, at).map_or(0, u16::from_be_bytes)
}

/// The big-endian 32-bit integer at `at`.
pub(crate) fn be32(data: &[u8], at: usize) -> u32 {
    array(data, at).map_or(0, u32::from_be_bytes)
}

/// The big-endian 64-bit integer at `at`.
pub(crate) fn be64(data: &[u8], at: usize) -> u64 {
    array(data, at).map_or(0, u64::from_be_bytes)
}

/// The little-endian 16-bit integer at `at`.
pub(crate) fn le16(data: &[u8], at: usize) -> u16 {
    array(data, at).map_or(0, u16::from_le_bytes)
}

/// The little-endian 32-bit integer at `at`.
pub(crate) fn le32(data: &[u8], at: usize) -> u32 {
    array(data, at).map_or(0, u32::from_le_bytes)
}

/// The little-endian 64-bit integer at `at`.
pub(crate) fn le64(data: &[u8], at: usize) -> u64 {
    array(data, at).map_or(0, u64::from_le_bytes)
}

/// The byte order of a TIFF structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Order {
    /// `II`: the least significant byte first.
    Little,
    /// `MM`: the most significant byte first.
    Big,
}

impl Order {
    /// The 16-bit integer at `at`.
    pub fn u16(self, data: &[u8], at: usize) -> u16 {
        match self {
            Self::Little => le16(data, at),
            Self::Big => be16(data, at),
        }
    }

    /// The 32-bit integer at `at`.
    pub fn u32(self, data: &[u8], at: usize) -> u32 {
        match self {
            Self::Little => le32(data, at),
            Self::Big => be32(data, at),
        }
    }

    /// The 64-bit integer at `at`.
    pub fn u64(self, data: &[u8], at: usize) -> u64 {
        match self {
            Self::Little => le64(data, at),
            Self::Big => be64(data, at),
        }
    }
}
