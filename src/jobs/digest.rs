//! The CRC-32C (Castagnoli) digest of the per-object integrity, which reads the object in a stream. MD5 comes from
//! `crate::common::md5`, SHA-256 from `aws-lc-rs` and CRC-32 (IEEE) from `flate2`.
//!
//! MD5 and the CRC values only compare the object with the values of the provider. They are not security functions.

const CRC32C_TABLE: [u32; 256] = crc32c_table();

const fn crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 1 {
                (value >> 1) ^ 0x82f6_3b78
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

/// The CRC-32C (Castagnoli) of a stream of bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Crc32c {
    value: u32,
}

impl Crc32c {
    /// A new checksum.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add bytes.
    pub fn update(&mut self, data: &[u8]) {
        let mut crc = !self.value;
        for byte in data {
            crc = CRC32C_TABLE[((crc ^ u32::from(*byte)) & 0xff) as usize] ^ (crc >> 8);
        }
        self.value = !crc;
    }

    /// The checksum of the bytes.
    pub fn sum(&self) -> u32 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::md5::Md5;
    use crate::common::misc::hex;

    #[test]
    fn the_md5_of_the_reference_vectors_is_right_in_any_split() {
        let cases: [(&str, &str); 5] = [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (text, want) in cases {
            for split in [1, 3, 63, 64, 65, 1000] {
                let mut digest = Md5::new();
                for part in text.as_bytes().chunks(split) {
                    digest.update(part);
                }
                assert_eq!(hex(&digest.finish()), want, "{text:?} in parts of {split}");
            }
        }
    }

    #[test]
    fn the_crc32c_of_the_check_value_is_right() {
        let mut crc = Crc32c::new();
        crc.update(b"1234");
        crc.update(b"56789");
        assert_eq!(crc.sum(), 0xe306_9283);
        assert_eq!(Crc32c::new().sum(), 0);
    }
}
