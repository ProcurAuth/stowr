// SPDX-License-Identifier: MIT OR Apache-2.0
//! The MD5 digest (RFC 1321). S3 asks for it in the header `Content-MD5` of the batch delete, of the lifecycle and of
//! the Object Lock requests. The integrity of an archive entry gives it to a person, who compares it with a value of
//! the provider or of another tool. It is not a security function.

/// The shift of each step.
const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15,
    21,
];

/// The constant of each step: the integer part of `abs(sin(i + 1)) * 2^32`.
const CONSTANTS: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// The state of an MD5 digest.
#[derive(Clone, Debug)]
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    /// A new digest.
    pub fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    fn block(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 16];
        let (quads, _) = block.as_chunks::<4>();
        for (word, bytes) in words.iter_mut().zip(quads) {
            *word = u32::from_le_bytes(*bytes);
        }
        let [mut a, mut b, mut c, mut d] = self.state;
        for index in 0..64 {
            let (mixed, word) = match index / 16 {
                0 => ((b & c) | (!b & d), index),
                1 => ((d & b) | (!d & c), (5 * index + 1) % 16),
                2 => (b ^ c ^ d, (3 * index + 5) % 16),
                _ => (c ^ (b | !d), (7 * index) % 16),
            };
            let rotated = a
                .wrapping_add(mixed)
                .wrapping_add(CONSTANTS[index])
                .wrapping_add(words[word])
                .rotate_left(SHIFTS[index]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }

    /// Add bytes to the digest.
    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let room = 64 - self.buffered;
            let count = room.min(data.len());
            self.buffer[self.buffered..self.buffered + count].copy_from_slice(&data[..count]);
            self.buffered += count;
            data = &data[count..];
            if self.buffered < 64 {
                return;
            }
            let block = self.buffer;
            self.block(&block);
            self.buffered = 0;
        }
        let (blocks, rest) = data.as_chunks::<64>();
        for block in blocks {
            self.block(block);
        }
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// The 16 bytes of the digest.
    pub fn finish(mut self) -> [u8; 16] {
        let bits = self.length.wrapping_mul(8);
        let mut padding = vec![0x80u8];
        let used = (self.buffered + 1) % 64;
        let zeros = if used <= 56 { 56 - used } else { 120 - used };
        padding.extend(std::iter::repeat_n(0u8, zeros));
        padding.extend_from_slice(&bits.to_le_bytes());
        let length = self.length;
        self.update(&padding);
        self.length = length;
        let mut out = [0u8; 16];
        for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *bytes = word.to_le_bytes();
        }
        out
    }
}

/// The MD5 digest of bytes.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(data);
    digest.finish()
}

/// The value of the header `Content-MD5`: the base64 text of the digest.
pub fn content_md5(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(md5(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::misc::hex;

    fn digest(parts: &[&[u8]]) -> String {
        let mut md5 = Md5::new();
        for part in parts {
            md5.update(part);
        }
        hex(&md5.finish())
    }

    #[test]
    fn the_constants_are_the_sine_table() {
        for (index, constant) in CONSTANTS.iter().enumerate() {
            let expected = ((index as f64 + 1.0).sin().abs() * 4_294_967_296.0).floor() as u32;
            assert_eq!(*constant, expected, "constant {index}");
        }
    }

    #[test]
    fn the_digests_of_rfc_1321() {
        let cases: [(&str, &str); 7] = [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
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
            assert_eq!(hex(&md5(text.as_bytes())), want, "digest of {text:?}");
            assert_eq!(digest(&[text.as_bytes()]), want, "streamed digest of {text:?}");
        }
        let digits = b"12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        assert_eq!(
            digest(&[&digits[..3], &digits[3..70], &digits[70..]]),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn each_length_around_a_block_gives_the_digest_of_one_update() {
        let data: Vec<u8> = (0..200u8).collect();
        for length in [55, 56, 57, 63, 64, 65, 119, 120, 128, 200] {
            let whole = md5(&data[..length]);
            let mut parts = Md5::new();
            for chunk in data[..length].chunks(7) {
                parts.update(chunk);
            }
            assert_eq!(parts.finish(), whole, "length {length}");
        }
        assert_ne!(md5(&data[..55]), md5(&data[..56]));
    }

    #[test]
    fn the_header_value_is_the_base64_digest() {
        assert_eq!(content_md5(b""), "1B2M2Y8AsgTpgAmY7PhCfg==");
    }
}
