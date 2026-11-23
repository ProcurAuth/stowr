//! The CRC-32C (Castagnoli) digest of the per-object integrity, which reads the object in a stream. MD5 comes from
//! `crate::common::md5`, SHA-256 from `aws-lc-rs` and CRC-32 (IEEE) from `flate2`.
//!
//! MD5 and the CRC values only compare the object with the values of the provider. They are not security functions.

/// The eight tables of the CRC-32C: `CRC32C_TABLES[0]` is the table of one byte, and `CRC32C_TABLES[k]` gives the
/// value of a byte that has `k` more bytes after it. The update reads eight bytes in one step.
const CRC32C_TABLES: [[u32; 256]; 8] = crc32c_tables();

const fn crc32c_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
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
        tables[0][index] = value;
        index += 1;
    }
    let mut index = 0;
    while index < 256 {
        let mut table = 1;
        while table < 8 {
            let previous = tables[table - 1][index];
            tables[table][index] = (previous >> 8) ^ tables[0][(previous & 0xff) as usize];
            table += 1;
        }
        index += 1;
    }
    tables
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
        let [t0, t1, t2, t3, t4, t5, t6, t7] = &CRC32C_TABLES;
        let mut crc = !self.value;
        let (blocks, rest) = data.as_chunks::<8>();
        for &[b0, b1, b2, b3, b4, b5, b6, b7] in blocks {
            let low = crc ^ u32::from_le_bytes([b0, b1, b2, b3]);
            let [l0, l1, l2, l3] = low.to_le_bytes();
            crc = t7[usize::from(l0)]
                ^ t6[usize::from(l1)]
                ^ t5[usize::from(l2)]
                ^ t4[usize::from(l3)]
                ^ t3[usize::from(b4)]
                ^ t2[usize::from(b5)]
                ^ t1[usize::from(b6)]
                ^ t0[usize::from(b7)];
        }
        for byte in rest {
            crc = t0[usize::from(crc.to_le_bytes()[0] ^ byte)] ^ (crc >> 8);
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

    /// The CRC-32C of the definition: one bit in each step.
    fn crc32c_by_bits(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for byte in data {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0x82f6_3b78
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn the_crc32c_of_eight_bytes_in_one_step_is_the_crc32c_of_the_definition_in_any_split() {
        let data: Vec<u8> = (0..4099u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        for length in [0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 65, 1000, 4099] {
            let want = crc32c_by_bits(&data[..length]);
            for split in [1, 3, 5, 8, 13, 64, 4099] {
                let mut crc = Crc32c::new();
                for part in data[..length].chunks(split) {
                    crc.update(part);
                }
                assert_eq!(crc.sum(), want, "{length} bytes in parts of {split}");
            }
        }
        // The value of 32 bytes of zero (RFC 3720, B.4).
        let mut crc = Crc32c::new();
        crc.update(&[0u8; 32]);
        assert_eq!(crc.sum(), 0x8a91_36aa);
    }
}
