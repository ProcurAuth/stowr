//! The metadata readers over byte ranges and their dispatch by extension and media type.
//!
//! Each reader makes the first range request of its format and then follows the lengths and the offsets that the
//! format declares: PNG reads its fixed header and its chunk headers, JPEG reads to the start of scan, TIFF follows
//! its IFD offsets, ISO base media skips to its `moov` box, Matroska reads to the first cluster, and the audio
//! readers read their metadata blocks. A guard of 128 MiB stops a corrupt or hostile structure. The decoding of a
//! large part runs on a blocking thread.

use std::collections::{HashSet, VecDeque};

use bytes::Bytes;

use super::audio::{
    flac_metadata_requirement, last_ogg_granule, parse_flac_metadata, parse_mp3_metadata, parse_wav_metadata,
    riff_metadata_requirement, synchsafe_u32,
};
use super::bin::{be32, be64, le32};
use super::image::{
    PNG_SIGNATURE, find_svg_start_tag, parse_additional_image_dimensions, parse_exr_dimensions, parse_fits_cards,
    parse_j2k_codestream_dimensions, parse_pnm_dimensions, parse_radiance_hdr_dimensions, parse_svg_start_tag,
    parse_webp_dimensions,
};
use super::iso::{find_iso_box_payloads, parse_iso_base_media, parse_iso_tracks, parse_ispe_image_dimensions};
use super::matroska::parse_matroska_header;
use super::metadata::{MediaMetadata, parse_bounded_file_metadata, push_unique};
use super::text::{find, fold_lower, lossy};
use super::tiff::{
    embedded_tiff_jpeg_range, parse_exif_metadata, parse_tiff_layout, raf_preview_range, tiff_metadata_tag,
    tiff_type_size, tiff_uint_values,
};
use crate::common::error::{Error, Result};
use crate::instance::range::RangeSource;

/// The largest metadata structure that a reader accepts: 128 MiB. It is a guard against a corrupt or hostile file,
/// not a read size: the readers stop at the end of the metadata of each format and usually read much less.
pub const MAX_METADATA_STRUCTURE_BYTES: i64 = 128 << 20;

/// The first read of most readers, and the smallest growth of a read: 64 KiB.
pub const METADATA_GROWTH_FLOOR: i64 = 64 << 10;

/// The largest FITS header that the reader scans: 1 MiB.
const MAX_FITS_HEADER_BYTES: i64 = 1 << 20;

/// Bytes up to this size are decoded on the thread of the request; a larger part goes to a blocking thread.
const INLINE_PARSE_BYTES: usize = 256 << 10;

/// The length of a read of `desired` bytes from `start`: 0 at or after the end of the object, else at most the
/// bytes to the end. Without a known size, `desired`.
pub fn metadata_range_length(source: &RangeSource, start: i64, desired: i64) -> i64 {
    if desired <= 0 {
        return 0;
    }
    let size = source.size_or_zero();
    if size <= 0 {
        return desired;
    }
    if start >= size {
        return 0;
    }
    desired.min(size - start)
}

/// The largest structure for this object: the size of the object, at most 128 MiB.
pub fn metadata_structure_limit(source: &RangeSource) -> i64 {
    let size = source.size_or_zero();
    if size > 0 {
        size.min(MAX_METADATA_STRUCTURE_BYTES)
    } else {
        MAX_METADATA_STRUCTURE_BYTES
    }
}

/// The error of a read that ends before the bytes that a structure declares.
fn unexpected_end() -> Error {
    Error::internal("unexpected end of the object")
}

fn too_large(code: &str, message: &str) -> Error {
    Error::api(422, code, message)
}

fn tiff_too_large() -> Error {
    too_large(
        "image_metadata_too_large",
        "the TIFF metadata structure is too large to inspect safely",
    )
}

/// Read `length` bytes from `start`. The flag is true when the object ends before the bytes that the call asked for.
async fn read_with_end(source: &RangeSource, start: i64, length: i64) -> Result<(Bytes, bool)> {
    let size = source.size_or_zero();
    let data = source.read_range(start, length).await?;
    if size > 0 && start >= size {
        return Ok((data, true));
    }
    let expected = if size > 0 { length.min(size - start) } else { length };
    let short = (data.len() as i64) < expected;
    Ok((data, short))
}

/// Read `length` bytes from `start`; fewer bytes at the end of the object.
async fn read(source: &RangeSource, start: i64, length: i64) -> Result<Bytes> {
    source.read_range(start, length).await
}

/// Read `length` bytes from `start`; an object that ends before is an error.
async fn read_exact(source: &RangeSource, start: i64, length: i64) -> Result<Bytes> {
    match read_with_end(source, start, length).await? {
        (_, true) => Err(unexpected_end()),
        (data, false) => Ok(data),
    }
}

/// Decode bytes: on this thread for a small part, else on a blocking thread.
async fn compute<T: Send + 'static>(data: Bytes, work: impl FnOnce(&[u8]) -> T + Send + 'static) -> Result<T> {
    if data.len() <= INLINE_PARSE_BYTES {
        return Ok(work(&data));
    }
    tokio::task::spawn_blocking(move || work(&data))
        .await
        .map_err(|_| Error::internal("the metadata decoder stopped"))
}

/// True for the extensions and the media types of TIFF and of the TIFF-based RAW files.
pub(crate) fn is_tiff_based_image(extension: &str, content_type: &str) -> bool {
    matches!(
        extension,
        "tif"
            | "tiff"
            | "dng"
            | "cr2"
            | "nef"
            | "nrw"
            | "arw"
            | "srf"
            | "sr2"
            | "orf"
            | "rw2"
            | "pef"
            | "erf"
            | "mef"
            | "mos"
            | "kdc"
            | "dcr"
            | "mrw"
            | "rwl"
            | "iiq"
            | "3fr"
            | "fff"
            | "raw"
    ) || content_type == "image/tiff"
        || content_type == "image/x-adobe-dng"
}

/// True for the extensions and the media types of HEIF, AVIF and Canon CR3.
pub(crate) fn is_heif_image(extension: &str, content_type: &str) -> bool {
    matches!(extension, "heic" | "heif" | "avif" | "cr3")
        || content_type.contains("heif")
        || content_type.contains("heic")
        || content_type.contains("avif")
}

/// True for the extensions and the media types of MP4 and QuickTime.
pub(crate) fn is_iso_base_media(extension: &str, content_type: &str) -> bool {
    matches!(extension, "mp4" | "m4v" | "m4a" | "mov" | "qt")
        || content_type == "video/mp4"
        || content_type == "audio/mp4"
        || content_type == "video/quicktime"
}

/// The metadata of an object: the reader of the format that the extension or the media type names. Another format
/// gets the bounded reader of the first 64 KiB.
pub(crate) async fn inspect_adaptive_metadata(
    source: &RangeSource,
    extension: &str,
    content_type: &str,
) -> Result<MediaMetadata> {
    let extension = fold_lower(extension.trim());
    let content_type = fold_lower(content_type.split(';').next().unwrap_or("").trim());
    let ext = extension.as_str();
    let ct = content_type.as_str();
    if ext == "jpg" || ext == "jpeg" || ct == "image/jpeg" {
        let mut result = MediaMetadata::default();
        result.merge(read_jpeg_metadata_at(source, 0, source.size_or_zero()).await?);
        return Ok(result);
    }
    if ext == "png" || ct == "image/png" {
        return inspect_png_metadata(source).await;
    }
    let fixed = match ext {
        _ if ext == "gif" || ct == "image/gif" => Some(16),
        _ if ext == "webp" || ct == "image/webp" => return inspect_webp_metadata(source).await,
        _ if ext == "bmp" || ext == "dib" || ct == "image/bmp" => Some(64),
        "psd" | "psb" => Some(32),
        "tga" | "ico" | "cur" => Some(64),
        "dds" | "pcx" => Some(128),
        "sgi" | "rgb" | "rgba" | "bw" => Some(512),
        _ if ext == "qoi" || ct == "image/qoi" => Some(14),
        _ if ext == "ff" || ext == "farbfeld" || ct == "image/farbfeld" => Some(16),
        _ => None,
    };
    if let Some(length) = fixed {
        return inspect_fixed_header_image(source, ext, ct, length).await;
    }
    if matches!(ext, "fits" | "fit" | "fts") || ct == "image/fits" || ct == "application/fits" {
        return inspect_fits_metadata(source).await;
    }
    match ext {
        "pnm" | "ppm" | "pgm" | "pbm" | "pam" => return inspect_pnm_metadata(source).await,
        "hdr" | "rgbe" => return inspect_radiance_hdr_metadata(source).await,
        "exr" => return inspect_exr_metadata(source).await,
        "jp2" | "j2k" | "jpf" | "jpx" | "jpc" => return inspect_jpeg2000_metadata(source).await,
        _ => {}
    }
    if ext == "svg" || ct == "image/svg+xml" {
        return inspect_svg_metadata(source).await;
    }
    if ext == "raf" {
        return inspect_raf_metadata(source).await;
    }
    if is_tiff_based_image(ext, ct) {
        return inspect_tiff_metadata(source).await;
    }
    if is_iso_base_media(ext, ct) || is_heif_image(ext, ct) {
        return inspect_iso_metadata(source).await;
    }
    if ext == "mkv" || ext == "webm" || ct.contains("matroska") || ct == "video/webm" {
        return inspect_matroska_metadata(source).await;
    }
    if ext == "mp3" || ct == "audio/mpeg" {
        return inspect_mp3_metadata(source).await;
    }
    if ext == "flac" || ct == "audio/flac" {
        return inspect_flac_metadata(source).await;
    }
    if ext == "wav" || ext == "wave" || ct == "audio/wav" || ct == "audio/x-wav" {
        return inspect_wav_metadata(source).await;
    }
    if matches!(ext, "ogg" | "oga" | "opus" | "ogv") || ct.contains("ogg") {
        return inspect_ogg_metadata(source).await;
    }
    let prefix = source
        .read_prefix(metadata_range_length(source, 0, METADATA_GROWTH_FLOOR))
        .await?;
    bounded_image_metadata(source, prefix, ext, ct).await
}

/// The bounded metadata of a part of a file, then the dimensions of a fixed image header.
async fn bounded_image_metadata(
    source: &RangeSource,
    data: Bytes,
    extension: &str,
    content_type: &str,
) -> Result<MediaMetadata> {
    let size = source.size_or_zero();
    let (extension, content_type) = (extension.to_owned(), content_type.to_owned());
    compute(data, move |data| {
        let mut result = MediaMetadata::default();
        result.merge(parse_bounded_file_metadata(data, &extension, &content_type, size));
        if let Some((width, height)) = parse_additional_image_dimensions(data, &extension, &content_type) {
            result.width = width;
            result.height = height;
        }
        result
    })
    .await
}

async fn inspect_fixed_header_image(
    source: &RangeSource,
    extension: &str,
    content_type: &str,
    length: i64,
) -> Result<MediaMetadata> {
    let data = read(source, 0, metadata_range_length(source, 0, length)).await?;
    bounded_image_metadata(source, data, extension, content_type).await
}

async fn inspect_png_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let data = read(source, 0, metadata_range_length(source, 0, METADATA_GROWTH_FLOOR)).await?;
    if data.len() < 24 || data[..8] != PNG_SIGNATURE {
        return Ok(result);
    }
    result.width = i64::from(be32(&data, 16));
    result.height = i64::from(be32(&data, 20));
    let mut offset = 8i64;
    for _ in 0..4096 {
        let header = read(source, offset, metadata_range_length(source, offset, 8)).await?;
        if header.len() < 8 {
            break;
        }
        let length = i64::from(be32(&header, 0));
        let chunk_type = &header[4..8];
        if length > MAX_METADATA_STRUCTURE_BYTES {
            return Err(too_large(
                "image_metadata_too_large",
                "the PNG metadata chunk is too large to inspect safely",
            ));
        }
        let payload_start = offset + 8;
        match chunk_type {
            b"eXIf" => {
                let payload = read(
                    source,
                    payload_start,
                    metadata_range_length(source, payload_start, length),
                )
                .await?;
                if let Some(exif) = compute(payload, parse_exif_metadata).await? {
                    result.merge(exif);
                }
            }
            b"tEXt" | b"iTXt" => {
                if length > 0
                    && length <= 256 << 10
                    && let Ok(payload) = read(
                        source,
                        payload_start,
                        metadata_range_length(source, payload_start, length),
                    )
                    .await
                {
                    parse_png_text_metadata(&mut result, chunk_type, &payload);
                }
            }
            b"IDAT" | b"IEND" => return Ok(result),
            _ => {}
        }
        offset = payload_start + length + 4;
        let size = source.size_or_zero();
        if size > 0 && offset >= size {
            break;
        }
    }
    Ok(result)
}

/// Keep the keyword and the text of a PNG text chunk. A compressed `iTXt` chunk is not decoded.
pub(crate) fn parse_png_text_metadata(metadata: &mut MediaMetadata, chunk_type: &[u8], payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    if chunk_type == b"tEXt" {
        if let Some(split) = payload.iter().position(|byte| *byte == 0)
            && split > 0
        {
            metadata.set(&lossy(&payload[..split]), &lossy(&payload[split + 1..]));
        }
        return;
    }
    let parts: Vec<&[u8]> = payload.splitn(6, |byte| *byte == 0).collect();
    if parts.len() == 6 && parts[1].len() == 1 && parts[1][0] == 0 {
        metadata.set(&lossy(parts[0]), &lossy(parts[5]));
    }
}

async fn inspect_webp_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let prefix = read(source, 0, metadata_range_length(source, 0, METADATA_GROWTH_FLOOR)).await?;
    if prefix.len() < 12 || &prefix[..4] != b"RIFF" || &prefix[8..12] != b"WEBP" {
        return Ok(result);
    }
    if let Some((width, height)) = parse_webp_dimensions(&prefix) {
        result.width = width;
        result.height = height;
    }
    let mut offset = 12i64;
    for _ in 0..4096 {
        let header = read(source, offset, metadata_range_length(source, offset, 8)).await?;
        if header.len() < 8 {
            break;
        }
        let chunk_type = &header[..4];
        let length = i64::from(le32(&header, 4));
        if length > MAX_METADATA_STRUCTURE_BYTES {
            return Err(too_large(
                "image_metadata_too_large",
                "the WebP metadata chunk is too large to inspect safely",
            ));
        }
        let payload_start = offset + 8;
        match chunk_type {
            b"VP8X" | b"VP8L" | b"VP8 " => {
                if (result.width == 0 || result.height == 0)
                    && let Ok(payload) = read(
                        source,
                        offset,
                        metadata_range_length(source, offset, 8 + length.min(64)),
                    )
                    .await
                    && let Some((width, height)) = parse_webp_dimensions(&payload)
                {
                    result.width = width;
                    result.height = height;
                }
            }
            b"EXIF" => {
                let payload = read(
                    source,
                    payload_start,
                    metadata_range_length(source, payload_start, length),
                )
                .await?;
                if let Some(exif) = compute(payload, parse_exif_metadata).await? {
                    result.merge(exif);
                }
            }
            b"XMP " => {
                if length > 0
                    && length <= 256 << 10
                    && let Ok(payload) = read(
                        source,
                        payload_start,
                        metadata_range_length(source, payload_start, length),
                    )
                    .await
                {
                    result.set("XMP", lossy(&payload).trim());
                }
            }
            _ => {}
        }
        offset = payload_start + length + length % 2;
        let size = source.size_or_zero();
        if size > 0 && offset >= size {
            break;
        }
    }
    Ok(result)
}

/// The reader of a text header that grows from 4 KiB to 1 MiB: PNM and Radiance HDR.
async fn inspect_growing_text_header(
    source: &RangeSource,
    parse: fn(&[u8]) -> (i64, i64, bool, bool),
) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let limit = metadata_structure_limit(source).min(1 << 20);
    let mut target = 4i64 << 10;
    while target <= limit {
        let data = source.read_prefix(metadata_range_length(source, 0, target)).await?;
        let length = data.len() as i64;
        let (width, height, complete, valid) = compute(data, parse).await?;
        if !valid {
            return Ok(result);
        }
        if complete {
            result.width = width;
            result.height = height;
            return Ok(result);
        }
        if length < target || target == limit {
            break;
        }
        target = limit.min(target * 2);
    }
    Ok(result)
}

async fn inspect_pnm_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    inspect_growing_text_header(source, parse_pnm_dimensions).await
}

async fn inspect_radiance_hdr_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    inspect_growing_text_header(source, parse_radiance_hdr_dimensions).await
}

/// The FITS reader: the 2880-byte blocks of 80-byte cards, read in parts that double in size, until the `END` card.
/// The reader never reads the image data.
async fn inspect_fits_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    const BLOCK: i64 = 2880;
    let mut result = MediaMetadata::default();
    let limit = metadata_structure_limit(source).min(MAX_FITS_HEADER_BYTES);
    let (mut width, mut height) = (0i64, 0i64);
    let mut offset = 0i64;
    let mut chunk = BLOCK;
    while offset < limit {
        let length = chunk.min(limit - offset);
        let data = read(source, offset, metadata_range_length(source, offset, length)).await?;
        if offset == 0 {
            if data.len() < 80 {
                return Ok(result);
            }
            if !data.starts_with(b"SIMPLE  =") && !data.starts_with(b"XTENSION=") {
                return Ok(result);
            }
        }
        let received = data.len() as i64;
        let (found, cards_width, cards_height) = compute(data, move |data| {
            let (mut width, mut height) = (width, height);
            let found = parse_fits_cards(data, &mut width, &mut height);
            (found, width, height)
        })
        .await?;
        width = cards_width;
        height = cards_height;
        if found {
            if width > 0 && height > 0 {
                result.width = width;
                result.height = height;
            }
            return Ok(result);
        }
        if received < length {
            break;
        }
        offset += length;
        chunk *= 2;
    }
    Ok(result)
}

async fn inspect_exr_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let limit = metadata_structure_limit(source);
    let mut target = METADATA_GROWTH_FLOOR;
    while target <= limit {
        let data = source.read_prefix(metadata_range_length(source, 0, target)).await?;
        let received = data.len() as i64;
        let (width, height, required, complete, valid) = compute(data, parse_exr_dimensions).await?;
        if !valid {
            return Ok(result);
        }
        if complete {
            result.width = width;
            result.height = height;
            return Ok(result);
        }
        if required > target {
            target = limit.min((required - 1).max(target));
        }
        if received >= limit || received < target {
            break;
        }
        target = limit.min(target * 2);
    }
    Ok(result)
}

/// The header of one box of an ISO base media file or of a JPEG 2000 file.
#[derive(Clone, Debug)]
struct IsoBoxHeader {
    offset: i64,
    size: i64,
    header_size: i64,
    box_type: [u8; 4],
}

async fn read_iso_box_header(source: &RangeSource, offset: i64) -> Result<IsoBoxHeader> {
    let data = read_exact(source, offset, metadata_range_length(source, offset, 16)).await?;
    if data.len() < 8 {
        return Err(unexpected_end());
    }
    let mut size = i64::from(be32(&data, 0));
    let mut header_size = 8;
    if size == 1 {
        if data.len() < 16 {
            return Err(unexpected_end());
        }
        size = be64(&data, 8) as i64;
        header_size = 16;
    } else if size == 0 {
        size = source.size_or_zero() - offset;
    }
    if size < header_size {
        return Err(Error::internal("invalid ISO base media box size"));
    }
    let mut box_type = [0u8; 4];
    box_type.copy_from_slice(&data[4..8]);
    Ok(IsoBoxHeader {
        offset,
        size,
        header_size,
        box_type,
    })
}

async fn inspect_jpeg2000_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let prefix = read(source, 0, metadata_range_length(source, 0, METADATA_GROWTH_FLOOR)).await?;
    if let Some((width, height)) = parse_j2k_codestream_dimensions(&prefix) {
        result.width = width;
        result.height = height;
        return Ok(result);
    }
    if prefix.len() < 12 || &prefix[4..8] != b"jP  " {
        return Ok(result);
    }
    let mut offset = 0i64;
    for _ in 0..4096 {
        let size = source.size_or_zero();
        if size > 0 && offset + 8 > size {
            break;
        }
        let header = read_iso_box_header(source, offset).await?;
        let size = source.size_or_zero();
        if header.size <= 0 || (size > 0 && offset + header.size > size) {
            break;
        }
        if &header.box_type == b"jp2h" {
            if header.size > MAX_METADATA_STRUCTURE_BYTES {
                return Err(too_large(
                    "image_metadata_too_large",
                    "the JPEG 2000 header is too large to inspect safely",
                ));
            }
            let found = read_exact(source, offset, header.size).await?;
            let dimensions = compute(found, |data| {
                find_iso_box_payloads(data, b"ihdr")
                    .into_iter()
                    .filter(|payload| payload.len() >= 8)
                    .map(|payload| (i64::from(be32(payload, 4)), i64::from(be32(payload, 0))))
                    .find(|(width, height)| *width > 0 && *height > 0)
            })
            .await?;
            if let Some((width, height)) = dimensions {
                result.width = width;
                result.height = height;
                return Ok(result);
            }
        }
        if &header.box_type == b"jp2c" {
            let read_length = (header.size - header.header_size).min(METADATA_GROWTH_FLOOR);
            if read_length > 0
                && let Ok(codestream) = read(source, offset + header.header_size, read_length).await
                && let Some((width, height)) = parse_j2k_codestream_dimensions(&codestream)
            {
                result.width = width;
                result.height = height;
            }
            return Ok(result);
        }
        offset += header.size;
    }
    Ok(result)
}

async fn inspect_svg_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let limit = 1i64 << 20;
    let mut target = 4i64 << 10;
    while target <= limit {
        let data = source.read_prefix(metadata_range_length(source, 0, target)).await?;
        let received = data.len() as i64;
        let found = compute(data, |data| find_svg_start_tag(data).map(parse_svg_start_tag)).await?;
        if let Some((width, height)) = found {
            result.width = width;
            result.height = height;
            return Ok(result);
        }
        if received < target || target == limit {
            break;
        }
        target = limit.min(target * 2);
    }
    Ok(result)
}

/// The number of bytes that the JPEG header needs, true when the header is complete (the start of scan or the end
/// of the image), and true when the bytes are a JPEG image.
pub(crate) fn jpeg_header_requirement(data: &[u8]) -> (i64, bool, bool) {
    if data.len() < 2 {
        return (2, false, true);
    }
    if data[0] != 0xff || data[1] != 0xd8 {
        return (0, true, false);
    }
    let mut offset = 2usize;
    loop {
        while offset < data.len() && data[offset] != 0xff {
            offset += 1;
        }
        if offset >= data.len() {
            return (offset as i64 + 1, false, true);
        }
        while offset < data.len() && data[offset] == 0xff {
            offset += 1;
        }
        if offset >= data.len() {
            return (offset as i64 + 1, false, true);
        }
        let marker = data[offset];
        offset += 1;
        if marker == 0xd9 {
            return (offset as i64, true, true);
        }
        if marker == 0xd8 || marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        if offset + 2 > data.len() {
            return (offset as i64 + 2, false, true);
        }
        let length = usize::from(super::bin::be16(data, offset));
        if length < 2 {
            return (offset as i64 + 2, true, false);
        }
        let segment_end = offset + length;
        if segment_end > data.len() {
            return (segment_end as i64, false, true);
        }
        offset = segment_end;
        if marker == 0xda {
            return (offset as i64, true, true);
        }
    }
}

/// The metadata of the JPEG image at `start`: the reads grow until the start of scan. `available` is the size of the
/// image when the caller knows it (the preview of a RAW file), else 0.
pub(crate) async fn read_jpeg_metadata_at(source: &RangeSource, start: i64, available: i64) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let mut available = available;
    let size = source.size_or_zero();
    if available <= 0 && size > start {
        available = size - start;
    }
    let limit = if available > 0 {
        available.min(MAX_METADATA_STRUCTURE_BYTES)
    } else {
        MAX_METADATA_STRUCTURE_BYTES
    };
    let mut target = limit.min(METADATA_GROWTH_FLOOR);
    while target > 0 {
        let data = read(source, start, target).await?;
        let received = data.len() as i64;
        let (required, valid, metadata) = compute(data, move |data| {
            let (required, done, valid) = jpeg_header_requirement(data);
            // The end of the object also ends the header: a longer read gives no more bytes.
            let metadata = (valid && (done || data.len() as i64 >= limit || (data.len() as i64) < target))
                .then(|| parse_bounded_file_metadata(data, "jpeg", "image/jpeg", available));
            (required, valid, metadata)
        })
        .await?;
        if !valid {
            return Ok(result);
        }
        if let Some(metadata) = metadata {
            result.merge(metadata);
            return Ok(result);
        }
        let mut next = required.max(received * 2 + METADATA_GROWTH_FLOOR);
        if next <= received {
            next = received + METADATA_GROWTH_FLOOR;
        }
        target = limit.min(next);
    }
    Ok(result)
}

async fn inspect_raf_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let header = read(source, 0, metadata_range_length(source, 0, 128)).await?;
    let Some((offset, mut length)) = raf_preview_range(&header) else {
        return Ok(result);
    };
    let size = source.size_or_zero();
    if offset < 0 || length <= 0 || (size > 0 && offset >= size) {
        return Ok(result);
    }
    if size > 0 {
        length = length.min(size - offset);
    }
    result.merge(read_jpeg_metadata_at(source, offset, length).await?);
    Ok(result)
}

async fn inspect_tiff_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let (data, valid) = read_adaptive_tiff_header(source).await?;
    if !valid {
        return Ok(result);
    }
    let (exif, preview) = compute(Bytes::from(data), |data| {
        (parse_exif_metadata(data), embedded_tiff_jpeg_range(data))
    })
    .await?;
    if let Some(exif) = exif {
        result.merge(exif);
    }
    let size = source.size_or_zero();
    if let Some((offset, length)) = preview
        && offset >= 0
        && length > 0
        && (size <= 0 || offset < size)
        && let Ok(metadata) = read_jpeg_metadata_at(source, offset, metadata_range_length(source, offset, length)).await
    {
        result.merge(metadata);
    }
    Ok(result)
}

/// Copy `length` bytes of the object from `offset` into `data` at the same offset.
async fn place(source: &RangeSource, data: &mut Vec<u8>, offset: i64, length: i64) -> Result<()> {
    if offset < 0
        || length <= 0
        || offset > MAX_METADATA_STRUCTURE_BYTES
        || length > MAX_METADATA_STRUCTURE_BYTES - offset
    {
        return Err(tiff_too_large());
    }
    let size = source.size_or_zero();
    if size > 0 && (offset > size || length > size - offset) {
        return Err(unexpected_end());
    }
    let chunk = read(source, offset, metadata_range_length(source, offset, length)).await?;
    if (chunk.len() as i64) < length {
        return Err(unexpected_end());
    }
    if source.bytes_read() > MAX_METADATA_STRUCTURE_BYTES {
        return Err(tiff_too_large());
    }
    let (start, required) = (offset as usize, (offset + length) as usize);
    if required > data.len() {
        data.resize(required, 0);
    }
    data[start..required].copy_from_slice(&chunk[..length as usize]);
    Ok(())
}

/// The TIFF structure of a TIFF or RAW file as a sparse copy of the object: the first 64 KiB (most camera files
/// have their complete IFD tree there), then only the IFDs and the values that the structure declares. Values that
/// are near each other come in one request. The flag is false when the object is not TIFF.
pub(crate) async fn read_adaptive_tiff_header(source: &RangeSource) -> Result<(Vec<u8>, bool)> {
    let header = read(source, 0, metadata_range_length(source, 0, METADATA_GROWTH_FLOOR)).await?;
    let Some(layout) = parse_tiff_layout(&header) else {
        return Ok((header.to_vec(), false));
    };
    let mut data = header.to_vec();
    let order = layout.order;
    let read_count = |raw: &[u8]| {
        if layout.big {
            order.u64(raw, 0)
        } else {
            u64::from(order.u16(raw, 0))
        }
    };
    let read_offset = |raw: &[u8]| {
        if layout.big {
            order.u64(raw, 0)
        } else {
            u64::from(order.u32(raw, 0))
        }
    };
    let value_of = |entry: &[u8]| -> (u16, u16, u64, Vec<u8>) {
        let tag = order.u16(entry, 0);
        let type_id = order.u16(entry, 2);
        if layout.big {
            (tag, type_id, order.u64(entry, 4), entry[12..20].to_vec())
        } else {
            (tag, type_id, u64::from(order.u32(entry, 4)), entry[8..12].to_vec())
        }
    };
    let max = MAX_METADATA_STRUCTURE_BYTES as u64;
    let mut queue = VecDeque::from([layout.first_ifd]);
    let mut visited = HashSet::new();
    while let Some(offset) = queue.pop_front() {
        if offset == 0 || !visited.insert(offset) {
            continue;
        }
        if visited.len() > 256 {
            return Ok((data, true));
        }
        if offset > max {
            return Err(tiff_too_large());
        }
        let ifd = offset as usize;
        place(source, &mut data, offset as i64, layout.count_size as i64).await?;
        let count = read_count(&data[ifd..ifd + layout.count_size]);
        if count > 4096 {
            return Err(Error::api(
                422,
                "invalid_image_metadata",
                "the TIFF metadata table has too many entries",
            ));
        }
        let table_length = layout.count_size + count as usize * layout.entry_size + layout.next_offset_size;
        place(source, &mut data, offset as i64, table_length as i64).await?;
        let table = data[ifd..ifd + table_length].to_vec();
        let entries: Vec<&[u8]> = (0..count as usize)
            .map(|index| {
                let cursor = layout.count_size + index * layout.entry_size;
                &table[cursor..cursor + layout.entry_size]
            })
            .collect();

        let mut ranges: Vec<(i64, i64)> = Vec::new();
        for entry in &entries {
            let (tag, type_id, value_count, value_bytes) = value_of(entry);
            let type_size = tiff_type_size(type_id);
            if type_size <= 0 || value_count > max / type_size as u64 {
                continue;
            }
            let value_size = type_size * value_count as i64;
            if value_size > layout.inline_value_size && tiff_metadata_tag(tag) {
                let value_offset = read_offset(&value_bytes);
                if value_offset <= max
                    && value_size > 0
                    && value_size <= MAX_METADATA_STRUCTURE_BYTES - value_offset as i64
                {
                    ranges.push((value_offset as i64, value_offset as i64 + value_size));
                }
            }
        }
        // Values near each other come in one provider request: a small read past a value costs less than one
        // request for each value.
        ranges.sort_by_key(|range| range.0);
        let mut merged: Vec<(i64, i64)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            if start < 0 || end <= start || end > MAX_METADATA_STRUCTURE_BYTES {
                continue;
            }
            if let Some(last) = merged.last_mut()
                && start <= last.1 + 4096
            {
                last.1 = last.1.max(end);
                continue;
            }
            merged.push((start, end));
        }
        for (start, end) in merged {
            place(source, &mut data, start, end - start).await?;
        }

        for entry in &entries {
            let (tag, type_id, value_count, inline) = value_of(entry);
            let type_size = tiff_type_size(type_id);
            if type_size <= 0 || value_count > max / type_size as u64 {
                continue;
            }
            let value_size = type_size * value_count as i64;
            let mut value_bytes: &[u8] = &inline;
            if value_size > layout.inline_value_size {
                let value_offset = read_offset(&inline);
                if value_offset <= data.len() as u64 && value_size <= data.len() as i64 - value_offset as i64 {
                    value_bytes = &data[value_offset as usize..value_offset as usize + value_size as usize];
                }
            }
            if tag == 0x8769 || tag == 0x8825 {
                let child = tiff_uint_values(order, type_id, value_bytes, 1)
                    .first()
                    .copied()
                    .unwrap_or(0);
                if child > 0 {
                    queue.push_back(child);
                }
            }
            if tag == 0x014a {
                let limit = value_count.min(4096) as usize;
                for child in tiff_uint_values(order, type_id, value_bytes, limit) {
                    if child > 0 {
                        queue.push_back(child);
                    }
                }
            }
        }
        let next = read_offset(&table[table.len() - layout.next_offset_size..]);
        if next > 0 {
            queue.push_back(next);
        }
    }
    Ok((data, true))
}

async fn inspect_iso_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let mut selected: Option<Bytes> = None;
    let mut offset = 0i64;
    for _ in 0..4096 {
        let size = source.size_or_zero();
        if size > 0 && offset + 8 > size {
            break;
        }
        if !source.has_byte(offset) {
            read(
                source,
                offset,
                metadata_range_length(source, offset, METADATA_GROWTH_FLOOR),
            )
            .await?;
        }
        let header = read_iso_box_header(source, offset).await?;
        let size = source.size_or_zero();
        if header.size <= 0 || (size > 0 && header.offset + header.size > size) {
            break;
        }
        if &header.box_type == b"moov" || &header.box_type == b"meta" {
            if header.size > MAX_METADATA_STRUCTURE_BYTES {
                return Err(too_large(
                    "media_metadata_too_large",
                    "the media metadata structure is too large to inspect safely",
                ));
            }
            selected = Some(read_exact(source, header.offset, header.size).await?);
            if &header.box_type == b"moov" {
                break;
            }
        }
        offset += header.size;
    }
    let Some(selected) = selected.filter(|selected| !selected.is_empty()) else {
        return Ok(result);
    };
    let (width, height, duration, codecs, ispe, tracks) = compute(selected, |data| {
        let (width, height, duration, codecs) = parse_iso_base_media(&[data]);
        let ispe = if width == 0 || height == 0 {
            parse_ispe_image_dimensions(data)
        } else {
            (0, 0)
        };
        (width, height, duration, codecs, ispe, parse_iso_tracks(data))
    })
    .await?;
    result.width = width;
    result.height = height;
    result.duration_seconds = duration;
    result.codecs = codecs;
    if (width == 0 || height == 0) && ispe.0 > 0 && ispe.1 > 0 {
        result.width = ispe.0;
        result.height = ispe.1;
    }
    result.tracks = tracks.unwrap_or_default();
    if result.codecs.is_empty() {
        let mut codecs = Vec::new();
        for track in &result.tracks {
            if !track.codec.is_empty() {
                push_unique(&mut codecs, &track.codec);
            }
        }
        result.codecs = codecs;
    }
    Ok(result)
}

async fn inspect_matroska_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let limit = metadata_structure_limit(source);
    let mut target = limit.min(1 << 20);
    while target > 0 {
        let data = source.read_prefix(target).await?;
        let received = data.len() as i64;
        let (metadata, complete, valid) = compute(data, parse_matroska_header).await?;
        if !valid {
            return Ok(result);
        }
        result = metadata;
        // The end of the object also ends the header: a longer read gives no more bytes.
        if complete || received >= limit || received < target {
            return Ok(result);
        }
        target = limit.min((received * 2).max(received + (1 << 20)));
    }
    Ok(result)
}

async fn inspect_mp3_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let header = read(source, 0, metadata_range_length(source, 0, 10)).await?;
    let mut target = METADATA_GROWTH_FLOOR;
    if header.len() >= 10 && &header[..3] == b"ID3" {
        target = 10 + i64::from(synchsafe_u32(&header[6..10])) + (64 << 10);
    }
    target = metadata_structure_limit(source).min(target.max(METADATA_GROWTH_FLOOR));
    let data = source.read_prefix(target).await?;
    let size = source.size_or_zero();
    result.merge(compute(data, move |data| parse_mp3_metadata(data, size)).await?);
    Ok(result)
}

async fn inspect_flac_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let mut target = metadata_range_length(source, 0, METADATA_GROWTH_FLOOR);
    while target > 0 {
        let data = source.read_prefix(target).await?;
        let received = data.len() as i64;
        let limit = metadata_structure_limit(source);
        let (required, metadata) = compute(data, move |data| {
            let (required, complete) = flac_metadata_requirement(data);
            let metadata = (complete || data.len() as i64 >= limit).then(|| parse_flac_metadata(data));
            (required, metadata)
        })
        .await?;
        if let Some(metadata) = metadata {
            result.merge(metadata);
            return Ok(result);
        }
        target = metadata_structure_limit(source).min(required.max(received * 2));
    }
    Ok(result)
}

async fn inspect_wav_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let mut target = metadata_range_length(source, 0, METADATA_GROWTH_FLOOR);
    while target > 0 {
        let data = source.read_prefix(target).await?;
        let received = data.len() as i64;
        let limit = source.size_or_zero().min(MAX_METADATA_STRUCTURE_BYTES);
        let (required, metadata) = compute(data, move |data| {
            let (required, complete) = riff_metadata_requirement(data);
            let metadata = (complete || data.len() as i64 >= limit).then(|| parse_wav_metadata(data));
            (required, metadata)
        })
        .await?;
        if let Some(metadata) = metadata {
            result.merge(metadata);
            return Ok(result);
        }
        target = metadata_structure_limit(source).min(required.max(received * 2));
    }
    Ok(result)
}

async fn inspect_ogg_metadata(source: &RangeSource) -> Result<MediaMetadata> {
    let mut result = MediaMetadata::default();
    let prefix = read(source, 0, metadata_range_length(source, 0, METADATA_GROWTH_FLOOR)).await?;
    let mut sample_rate = 0i64;
    let opus = find(&prefix, b"OpusHead").filter(|index| index + 19 <= prefix.len());
    let vorbis = || find(&prefix, b"\x01vorbis").filter(|index| index + 16 <= prefix.len());
    if let Some(index) = opus {
        result.codecs = vec!["opus".to_owned()];
        sample_rate = 48_000;
        result
            .properties
            .insert("Channels".to_owned(), prefix[index + 9].to_string());
    } else if let Some(index) = vorbis() {
        result.codecs = vec!["vorbis".to_owned()];
        result
            .properties
            .insert("Channels".to_owned(), prefix[index + 11].to_string());
        sample_rate = i64::from(le32(&prefix, index + 12));
    }
    let size = source.size_or_zero();
    if sample_rate > 0 && size > 0 {
        let tail_length = size.min(METADATA_GROWTH_FLOOR);
        if let Ok((tail, false)) = read_with_end(source, size - tail_length, tail_length).await
            && let Some(granule) = last_ogg_granule(&tail)
        {
            result.duration_seconds = granule as f64 / sample_rate as f64;
        }
    }
    Ok(result)
}
