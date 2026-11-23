//! The audio headers: MP3 (the ID3v2 tag and the first MPEG audio frame), WAV (RIFF chunks and the INFO list), FLAC
//! (STREAMINFO and the Vorbis comments) and the last granule position of an Ogg stream.

use super::bin::{be64, le16, le32, le64};
use super::metadata::MediaMetadata;
use super::text::{fold_upper, format_fixed, latin1, lossy, trim_bytes};

/// The label of an ID3v2 text frame.
fn id3_label(frame: &[u8]) -> Option<&'static str> {
    Some(match frame {
        b"TIT2" => "Title",
        b"TPE1" => "Artist",
        b"TALB" => "Album",
        b"TDRC" | b"TYER" => "Year",
        b"TRCK" => "Track",
        b"TCON" => "Genre",
        b"TCOM" => "Composer",
        _ => return None,
    })
}

/// The metadata of an MP3 file: the text frames of the ID3v2 tag, then the bit rate, the sample rate and the
/// channels of the first MPEG audio frame. The duration comes from the bit rate and the size of the object.
pub(crate) fn parse_mp3_metadata(data: &[u8], object_size: i64) -> MediaMetadata {
    let mut result = MediaMetadata {
        codecs: vec!["mp3".to_owned()],
        ..MediaMetadata::default()
    };
    let mut cursor = 0;
    if data.len() >= 10 && &data[..3] == b"ID3" {
        let version = data[3];
        let tag_size = synchsafe_u32(&data[6..10]) as usize;
        let end = data.len().min(10 + tag_size);
        cursor = 10;
        while cursor + 10 <= end {
            let frame_id = &data[cursor..cursor + 4];
            if frame_id.iter().all(|byte| *byte == 0) {
                break;
            }
            let frame_size = if version >= 4 {
                synchsafe_u32(&data[cursor + 4..cursor + 8])
            } else {
                super::bin::be32(data, cursor + 4)
            } as usize;
            cursor += 10;
            if frame_size == 0 || cursor + frame_size > end {
                break;
            }
            if let Some(label) = id3_label(frame_id) {
                result.set(label, &decode_id3_text(&data[cursor..cursor + frame_size]));
            }
            cursor += frame_size;
        }
        cursor = data.len().min(10 + tag_size);
    }
    let (bitrate, sample_rate, channels) = find_mp3_frame(data, cursor);
    if bitrate > 0 {
        result.set("Bit rate", &format!("{} kb/s", bitrate / 1000));
        if object_size > 0 {
            result.duration_seconds = object_size.wrapping_mul(8) as f64 / bitrate as f64;
        }
    }
    if sample_rate > 0 {
        result.set(
            "Sample rate",
            &format!("{} kHz", format_fixed(sample_rate as f64 / 1000.0, 1)),
        );
    }
    if channels > 0 {
        result.set("Channels", &channels.to_string());
    }
    result
}

/// A synchsafe integer of ID3v2: four bytes of seven bits.
pub(crate) fn synchsafe_u32(data: &[u8]) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    (u32::from(data[0] & 0x7f) << 21)
        | (u32::from(data[1] & 0x7f) << 14)
        | (u32::from(data[2] & 0x7f) << 7)
        | u32::from(data[3] & 0x7f)
}

/// The text of an ID3v2 text frame: ISO 8859-1, UTF-16 with or without a byte order mark, or UTF-8.
pub(crate) fn decode_id3_text(data: &[u8]) -> String {
    if data.len() < 2 {
        return String::new();
    }
    let encoding = data[0];
    let mut payload = trim_bytes(&data[1..], b"\x00");
    match encoding {
        0 => latin1(payload).trim().to_owned(),
        1 | 2 => {
            let mut big_endian = encoding == 2;
            if payload.len() >= 2 {
                if payload[0] == 0xff && payload[1] == 0xfe {
                    big_endian = false;
                    payload = &payload[2..];
                } else if payload[0] == 0xfe && payload[1] == 0xff {
                    big_endian = true;
                    payload = &payload[2..];
                }
            }
            let units = payload.as_chunks::<2>().0.iter().map(|pair| {
                if big_endian {
                    u16::from_be_bytes(*pair)
                } else {
                    u16::from_le_bytes(*pair)
                }
            });
            let text: String = char::decode_utf16(units)
                .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect();
            text.trim().trim_matches('\0').to_owned()
        }
        _ => lossy(payload).trim().to_owned(),
    }
}

/// The bit rate, the sample rate and the channels of the first MPEG audio frame (layer III) from `start`, or zeros.
pub(crate) fn find_mp3_frame(data: &[u8], start: usize) -> (i64, i64, i64) {
    const BITRATES: [i64; 16] = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0];
    const SAMPLE_RATES: [i64; 4] = [44100, 48000, 32000, 0];
    let mut offset = start;
    while offset + 4 <= data.len() {
        let header = super::bin::be32(data, offset);
        offset += 1;
        if header & 0xffe0_0000 != 0xffe0_0000 {
            continue;
        }
        let version = (header >> 19) & 0x3;
        let layer = (header >> 17) & 0x3;
        let bitrate_index = ((header >> 12) & 0xf) as usize;
        let sample_index = ((header >> 10) & 0x3) as usize;
        if version == 1 || layer != 1 || bitrate_index == 0 || bitrate_index == 15 || sample_index == 3 {
            continue;
        }
        let mut bitrate = BITRATES[bitrate_index] * 1000;
        if version != 3 {
            bitrate /= 2;
        }
        let mut sample_rate = SAMPLE_RATES[sample_index];
        if version == 2 {
            sample_rate /= 2;
        } else if version == 0 {
            sample_rate /= 4;
        }
        let channels = if (header >> 6) & 0x3 == 3 { 1 } else { 2 };
        return (bitrate, sample_rate, channels);
    }
    (0, 0, 0)
}

/// The metadata of a WAV file: the codec, the channels, the sample rate and the bit depth of `fmt `, the INFO list,
/// and the duration when the complete `data` chunk is in the bytes.
pub(crate) fn parse_wav_metadata(data: &[u8]) -> MediaMetadata {
    let mut result = MediaMetadata::default();
    if data.len() < 12 || &data[..4] != b"RIFF" || &data[8..12] != b"WAVE" {
        return result;
    }
    result.codecs = vec!["pcm".to_owned()];
    let mut byte_rate = 0u32;
    let mut data_size = 0u32;
    let mut offset = 12usize;
    while offset + 8 <= data.len() {
        let id = &data[offset..offset + 4];
        let size = le32(data, offset + 4) as usize;
        let start = offset + 8;
        let end = start + size;
        if end > data.len() {
            break;
        }
        let chunk = &data[start..end];
        match id {
            b"fmt " => {
                if chunk.len() >= 16 {
                    let format = le16(chunk, 0);
                    let channels = le16(chunk, 2);
                    let sample_rate = le32(chunk, 4);
                    byte_rate = le32(chunk, 8);
                    let bits = le16(chunk, 14);
                    let codec = match format {
                        1 => "pcm",
                        3 => "ieee float",
                        6 => "a-law",
                        7 => "µ-law",
                        _ => "",
                    };
                    if !codec.is_empty() {
                        result.codecs = vec![codec.to_owned()];
                    }
                    result.set("Channels", &channels.to_string());
                    result.set(
                        "Sample rate",
                        &format!("{} kHz", format_fixed(f64::from(sample_rate) / 1000.0, 1)),
                    );
                    result.set("Bit depth", &format!("{bits}-bit"));
                }
            }
            b"data" => data_size = size as u32,
            b"LIST" if chunk.len() > 4 && &chunk[..4] == b"INFO" => parse_wav_info(&chunk[4..], &mut result),
            _ => {}
        }
        offset = end + size % 2;
    }
    if byte_rate > 0 && data_size > 0 {
        result.duration_seconds = f64::from(data_size) / f64::from(byte_rate);
    }
    result
}

/// The labels of the INFO list of a WAV file.
fn wav_info_label(id: &[u8]) -> Option<&'static str> {
    Some(match id {
        b"INAM" => "Title",
        b"IART" => "Artist",
        b"IPRD" => "Album",
        b"ICRD" => "Year",
        b"IGNR" => "Genre",
        b"ICMT" => "Comment",
        _ => return None,
    })
}

fn parse_wav_info(data: &[u8], result: &mut MediaMetadata) {
    let mut offset = 0usize;
    while offset + 8 <= data.len() {
        let id = &data[offset..offset + 4];
        let size = le32(data, offset + 4) as usize;
        let (start, end) = (offset + 8, offset + 8 + size);
        if end > data.len() {
            break;
        }
        if let Some(label) = wav_info_label(id) {
            result.set(label, &lossy(trim_bytes(&data[start..end], b"\x00 \r\n\t")));
        }
        offset = end + size % 2;
    }
}

/// The metadata of a FLAC file: the sample rate, the channels, the bit depth and the duration of STREAMINFO, and the
/// Vorbis comments.
pub(crate) fn parse_flac_metadata(data: &[u8]) -> MediaMetadata {
    let mut result = MediaMetadata::default();
    if data.len() < 8 || &data[..4] != b"fLaC" {
        return result;
    }
    result.codecs = vec!["flac".to_owned()];
    let mut offset = 4usize;
    while offset + 4 <= data.len() {
        let header = data[offset];
        let block_type = header & 0x7f;
        let length = (usize::from(data[offset + 1]) << 16)
            | (usize::from(data[offset + 2]) << 8)
            | usize::from(data[offset + 3]);
        let (start, end) = (offset + 4, offset + 4 + length);
        if end > data.len() {
            break;
        }
        let block = &data[start..end];
        if block_type == 0 && block.len() >= 34 {
            let packed = be64(block, 10);
            let sample_rate = ((packed >> 44) & 0xfffff) as i64;
            let channels = ((packed >> 41) & 0x7) + 1;
            let bits = ((packed >> 36) & 0x1f) + 1;
            let total_samples = packed & 0xf_ffff_ffff;
            if sample_rate > 0 {
                result.duration_seconds = total_samples as f64 / sample_rate as f64;
                result.set(
                    "Sample rate",
                    &format!("{} kHz", format_fixed(sample_rate as f64 / 1000.0, 1)),
                );
            }
            result.set("Channels", &channels.to_string());
            result.set("Bit depth", &format!("{bits}-bit"));
        } else if block_type == 4 {
            parse_vorbis_comments(block, &mut result);
        }
        offset = end;
        if header & 0x80 != 0 {
            break;
        }
    }
    result
}

/// The label of a Vorbis comment field, or an empty label for another field.
fn vorbis_label(field: &str) -> &'static str {
    match field {
        "TITLE" => "Title",
        "ARTIST" => "Artist",
        "ALBUM" => "Album",
        "DATE" => "Year",
        "TRACKNUMBER" => "Track",
        "GENRE" => "Genre",
        "COMMENT" => "Comment",
        _ => "",
    }
}

/// Read the Vorbis comments (256 at most). A field without a label sets the property with the empty label.
pub(crate) fn parse_vorbis_comments(data: &[u8], result: &mut MediaMetadata) {
    if data.len() < 8 {
        return;
    }
    let vendor_length = le32(data, 0) as usize;
    let mut cursor = 4 + vendor_length;
    if cursor + 4 > data.len() {
        return;
    }
    let count = le32(data, cursor) as usize;
    cursor += 4;
    let mut index = 0;
    while index < count && cursor + 4 <= data.len() && index < 256 {
        let length = le32(data, cursor) as usize;
        cursor += 4;
        if cursor + length > data.len() {
            break;
        }
        let entry = lossy(&data[cursor..cursor + length]);
        cursor += length;
        if let Some((field, value)) = entry.split_once('=') {
            result.set(vorbis_label(&fold_upper(field)), value);
        }
        index += 1;
    }
}

/// The number of bytes that the FLAC metadata blocks need, and true when the last block is in the bytes (or when
/// the bytes are not FLAC).
pub(crate) fn flac_metadata_requirement(data: &[u8]) -> (i64, bool) {
    if data.len() < 4 || &data[..4] != b"fLaC" {
        return (4, true);
    }
    let mut offset = 4usize;
    loop {
        if offset + 4 > data.len() {
            return (offset as i64 + 4, false);
        }
        let last = data[offset] & 0x80 != 0;
        let length = (usize::from(data[offset + 1]) << 16)
            | (usize::from(data[offset + 2]) << 8)
            | usize::from(data[offset + 3]);
        offset += 4;
        if offset + length > data.len() {
            return ((offset + length) as i64, false);
        }
        offset += length;
        if last {
            return (offset as i64, true);
        }
    }
}

/// The number of bytes that the RIFF chunks before `data` need, and true when the header of the `data` chunk is in
/// the bytes (or when the bytes are not RIFF).
pub(crate) fn riff_metadata_requirement(data: &[u8]) -> (i64, bool) {
    if data.len() < 12 || &data[..4] != b"RIFF" {
        return (12, true);
    }
    let mut offset = 12usize;
    while offset + 8 <= data.len() {
        if &data[offset..offset + 4] == b"data" {
            return (offset as i64 + 8, true);
        }
        let chunk_length = i64::from(le32(data, offset + 4));
        let next = offset as i64 + 8 + chunk_length + chunk_length % 2;
        if next > data.len() as i64 {
            return (next, false);
        }
        offset = next as usize;
    }
    (offset as i64 + 8, false)
}

/// The granule position of the last Ogg page that starts in the bytes.
pub(crate) fn last_ogg_granule(data: &[u8]) -> Option<u64> {
    let last = data.len().checked_sub(27)?;
    (0..=last)
        .rev()
        .find(|offset| offset + 14 <= data.len() && &data[*offset..offset + 4] == b"OggS")
        .map(|offset| le64(data, offset + 6))
}
