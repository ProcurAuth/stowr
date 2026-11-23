//! The tests of the routes `/api/media-info` and `/api/image-preview` over the memory back end, and of the bounded
//! readers of EXIF and MP3.

use std::sync::Arc;

use http::HeaderMap;
use serde_json::Value;

use super::metadata::parse_bounded_file_metadata;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::common::http::empty;
use crate::common::storage::{Backend, ObjectResponse};
use crate::server::testing::{TestRequest, TestResponse, app_of, bucket_config, instance};
use crate::testkit::{MemoryBackend, MemoryLayer};

// --- Helpers ----------------------------------------------------------------------------------------------------

/// An application with the instances `readonly` and `rw` (root prefix `tenant/`, the permissions read, write and
/// delete). The instance `rw` reads `backend`.
pub(super) fn test_app(backend: Arc<dyn Backend>) -> Arc<App> {
    app_of(vec![
        instance(
            bucket_config("readonly", "", &[PERMISSION_READ]),
            Arc::new(MemoryBackend::with_objects(&[("readonly.txt", "read")])),
        ),
        instance(
            bucket_config("rw", "tenant/", &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]),
            backend,
        ),
    ])
}

/// A memory back end with the objects of the test instance `rw`.
pub(super) fn memory() -> Arc<MemoryBackend> {
    Arc::new(MemoryBackend::with_objects(&[
        ("tenant/folder/direct.txt", "direct"),
        ("tenant/folder/nested/deep.txt", "deep"),
    ]))
}

/// Send a request through the whole dispatch: the middlewares, the router and the handler.
pub(super) async fn call(app: &Arc<App>, method: &str, target: &str) -> TestResponse {
    TestRequest::new(method, target).send(app).await
}

/// The details of a key of the instance `rw`; the answer must be 200.
pub(super) async fn request_media_info(app: &Arc<App>, key: &str) -> Value {
    let called = call(app, "GET", &format!("/api/media-info?instance=rw&key={key}")).await;
    assert_eq!(called.status, 200, "body = {}", called.text());
    called.json()
}

/// The GET count, the HEAD count and the ranges of the GET requests.
pub(super) fn read_counts(backend: &MemoryBackend) -> (usize, usize, Vec<String>) {
    let state = backend.state();
    (state.get_count, state.head_count, state.get_ranges.clone())
}

pub(super) fn number(value: &Value, name: &str) -> i64 {
    value[name].as_i64().unwrap_or(0)
}

fn put_u16_be(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_u32_be(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_u16_le(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32_le(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64_le(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

// --- Synthetic files --------------------------------------------------------------------------------------------

pub(super) fn iso_box(box_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 8];
    put_u32_be(&mut out, 0, (8 + payload.len()) as u32);
    out[4..8].copy_from_slice(box_type.as_bytes());
    out.extend_from_slice(payload);
    out
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|part| part.iter().copied()).collect()
}

/// An MP4 file: `ftyp`, 256 KiB of `mdat`, then `moov` with a video track (avc1, 1920x1080) and an audio track
/// (mp4a, 2 channels, 48 kHz) and a duration of 12.5 seconds.
pub(super) fn test_mp4_metadata_object() -> Vec<u8> {
    let mut mvhd = vec![0u8; 20];
    put_u32_be(&mut mvhd, 12, 1000);
    put_u32_be(&mut mvhd, 16, 12500);
    let mut tkhd = vec![0u8; 84];
    put_u32_be(&mut tkhd, 76, 1920 << 16);
    put_u32_be(&mut tkhd, 80, 1080 << 16);

    let mut handler_video = vec![0u8; 12];
    handler_video[8..12].copy_from_slice(b"vide");
    let mut video_entry = vec![0u8; 36];
    put_u32_be(&mut video_entry, 0, 36);
    video_entry[4..8].copy_from_slice(b"avc1");
    put_u16_be(&mut video_entry, 32, 1920);
    put_u16_be(&mut video_entry, 34, 1080);
    let mut video_stsd = vec![0u8; 8];
    put_u32_be(&mut video_stsd, 4, 1);
    video_stsd.extend_from_slice(&video_entry);
    let video_mdia = iso_box(
        "mdia",
        &concat(&[
            &iso_box("hdlr", &handler_video),
            &iso_box("minf", &iso_box("stbl", &iso_box("stsd", &video_stsd))),
        ]),
    );
    let video_trak = iso_box("trak", &concat(&[&iso_box("tkhd", &tkhd), &video_mdia]));

    let mut handler_audio = vec![0u8; 12];
    handler_audio[8..12].copy_from_slice(b"soun");
    let mut audio_entry = vec![0u8; 36];
    put_u32_be(&mut audio_entry, 0, 36);
    audio_entry[4..8].copy_from_slice(b"mp4a");
    put_u16_be(&mut audio_entry, 24, 2);
    put_u32_be(&mut audio_entry, 32, 48000 << 16);
    let mut audio_stsd = vec![0u8; 8];
    put_u32_be(&mut audio_stsd, 4, 1);
    audio_stsd.extend_from_slice(&audio_entry);
    let audio_mdia = iso_box(
        "mdia",
        &concat(&[
            &iso_box("hdlr", &handler_audio),
            &iso_box("minf", &iso_box("stbl", &iso_box("stsd", &audio_stsd))),
        ]),
    );
    let audio_trak = iso_box("trak", &audio_mdia);

    let moov = iso_box("moov", &concat(&[&iso_box("mvhd", &mvhd), &video_trak, &audio_trak]));
    let ftyp = iso_box("ftyp", b"isom\x00\x00\x00\x00isommp42");
    let mdat = iso_box("mdat", &vec![0u8; 256 << 10]);
    concat(&[&ftyp, &mdat, &moov])
}

/// A PNG file with an IHDR chunk and an IEND chunk.
pub(super) fn synthetic_png(width: u32, height: u32) -> Vec<u8> {
    let mut data = vec![137, 80, 78, 71, 13, 10, 26, 10];
    data.extend_from_slice(&[0u8; 25]);
    put_u32_be(&mut data, 8, 13);
    data[12..16].copy_from_slice(b"IHDR");
    put_u32_be(&mut data, 16, width);
    put_u32_be(&mut data, 20, height);
    data[24] = 8;
    data[25] = 2;
    data.extend_from_slice(&[0, 0, 0, 0]);
    data.extend_from_slice(&[0, 0, 0, 0]);
    data.extend_from_slice(b"IEND");
    data.extend_from_slice(&[0, 0, 0, 0]);
    data
}

/// A JPEG file with two APP segments of 64 KiB before its start-of-frame segment.
fn synthetic_jpeg_with_large_header(width: u16, height: u16) -> Vec<u8> {
    let mut data = vec![0xff, 0xd8];
    for index in 0..2u8 {
        data.extend_from_slice(&[0xff, 0xe2 + index, 0xff, 0xff]);
        data.extend_from_slice(&vec![0u8; 65533]);
    }
    let mut sof = vec![
        0xff, 0xc0, 0x00, 0x11, 0x08, 0, 0, 0, 0, 0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11, 0x00,
    ];
    put_u16_be(&mut sof, 5, height);
    put_u16_be(&mut sof, 7, width);
    data.extend_from_slice(&sof);
    data.extend_from_slice(&[0xff, 0xda, 0x00, 0x02]);
    data
}

/// A small JPEG file: a start-of-frame segment and the end of the image.
pub(super) fn synthetic_jpeg(width: u16, height: u16) -> Vec<u8> {
    let mut data = vec![
        0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, 0, 0, 0, 0, 0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11,
        0x00, 0xff, 0xd9,
    ];
    put_u16_be(&mut data, 7, height);
    put_u16_be(&mut data, 9, width);
    data
}

/// A Fujifilm RAF file: the header, then a JPEG preview at offset 128.
fn synthetic_raf(width: u16, height: u16) -> Vec<u8> {
    let preview = synthetic_jpeg(width, height);
    let mut data = vec![0u8; 128 + preview.len()];
    data[..16].copy_from_slice(b"FUJIFILMCCD-RAW ");
    put_u32_be(&mut data, 84, 128);
    put_u32_be(&mut data, 88, preview.len() as u32);
    data[128..].copy_from_slice(&preview);
    data
}

fn put_tiff_entry(data: &mut [u8], ifd_offset: usize, index: usize, tag: u16, type_id: u16, count: u32, value: u32) {
    let entry = ifd_offset + 2 + index * 12;
    put_u16_le(data, entry, tag);
    put_u16_le(data, entry + 2, type_id);
    put_u32_le(data, entry + 4, count);
    put_u32_le(data, entry + 8, value);
}

/// A little-endian TIFF with the camera, an EXIF IFD and a GPS IFD.
pub(super) fn synthetic_tiff_with_exif_and_gps() -> Vec<u8> {
    let mut data = vec![0u8; 520];
    data[..2].copy_from_slice(b"II");
    put_u16_le(&mut data, 2, 42);
    put_u32_le(&mut data, 4, 8);

    const IFD0: usize = 8;
    const EXIF: usize = 128;
    const GPS: usize = 256;
    const MAKE: u32 = 96;
    const MODEL: u32 = 104;
    const DATE: u32 = 352;
    const LENS: u32 = 384;
    const EXPOSURE: usize = 416;
    const APERTURE: usize = 424;
    const FOCAL: usize = 432;
    const LATITUDE: usize = 448;
    const LONGITUDE: usize = 472;
    const ALTITUDE: usize = 496;

    put_u16_le(&mut data, IFD0, 6);
    put_tiff_entry(&mut data, IFD0, 0, 0x0100, 4, 1, 4000);
    put_tiff_entry(&mut data, IFD0, 1, 0x0101, 4, 1, 3000);
    put_tiff_entry(&mut data, IFD0, 2, 0x010f, 2, 6, MAKE);
    put_tiff_entry(&mut data, IFD0, 3, 0x0110, 2, 7, MODEL);
    put_tiff_entry(&mut data, IFD0, 4, 0x8769, 4, 1, EXIF as u32);
    put_tiff_entry(&mut data, IFD0, 5, 0x8825, 4, 1, GPS as u32);
    data[MAKE as usize..MAKE as usize + 6].copy_from_slice(b"Canon\x00");
    data[MODEL as usize..MODEL as usize + 7].copy_from_slice(b"EOS R5\x00");

    put_u16_le(&mut data, EXIF, 8);
    put_tiff_entry(&mut data, EXIF, 0, 0x9003, 2, 20, DATE);
    put_tiff_entry(&mut data, EXIF, 1, 0x8827, 3, 1, 800);
    put_tiff_entry(&mut data, EXIF, 2, 0x829a, 5, 1, EXPOSURE as u32);
    put_tiff_entry(&mut data, EXIF, 3, 0x829d, 5, 1, APERTURE as u32);
    put_tiff_entry(&mut data, EXIF, 4, 0x920a, 5, 1, FOCAL as u32);
    put_tiff_entry(&mut data, EXIF, 5, 0xa434, 2, 12, LENS);
    put_tiff_entry(&mut data, EXIF, 6, 0xa002, 4, 1, 4000);
    put_tiff_entry(&mut data, EXIF, 7, 0xa003, 4, 1, 3000);
    data[DATE as usize..DATE as usize + 20].copy_from_slice(b"2026:07:23 10:11:12\x00");
    data[LENS as usize..LENS as usize + 12].copy_from_slice(b"RF50mm F1.2\x00");
    put_u32_le(&mut data, EXPOSURE, 1);
    put_u32_le(&mut data, EXPOSURE + 4, 250);
    put_u32_le(&mut data, APERTURE, 28);
    put_u32_le(&mut data, APERTURE + 4, 10);
    put_u32_le(&mut data, FOCAL, 50);
    put_u32_le(&mut data, FOCAL + 4, 1);

    put_u16_le(&mut data, GPS, 6);
    put_tiff_entry(&mut data, GPS, 0, 0x0001, 2, 2, u32::from(b'N'));
    put_tiff_entry(&mut data, GPS, 1, 0x0002, 5, 3, LATITUDE as u32);
    put_tiff_entry(&mut data, GPS, 2, 0x0003, 2, 2, u32::from(b'E'));
    put_tiff_entry(&mut data, GPS, 3, 0x0004, 5, 3, LONGITUDE as u32);
    put_tiff_entry(&mut data, GPS, 4, 0x0005, 1, 1, 0);
    put_tiff_entry(&mut data, GPS, 5, 0x0006, 5, 1, ALTITUDE as u32);
    for (index, (numerator, denominator)) in [(48, 1), (51, 1), (30, 1)].into_iter().enumerate() {
        put_u32_le(&mut data, LATITUDE + index * 8, numerator);
        put_u32_le(&mut data, LATITUDE + index * 8 + 4, denominator);
    }
    for (index, (numerator, denominator)) in [(2, 1), (20, 1), (0, 1)].into_iter().enumerate() {
        put_u32_le(&mut data, LONGITUDE + index * 8, numerator);
        put_u32_le(&mut data, LONGITUDE + index * 8 + 4, denominator);
    }
    put_u32_le(&mut data, ALTITUDE, 35);
    put_u32_le(&mut data, ALTITUDE + 4, 1);
    data
}

/// An MP3 file: an ID3v2.3 tag with a title and an artist, then the header of one MPEG-1 layer III frame.
pub(super) fn synthetic_id3_mp3() -> Vec<u8> {
    let frame = |id: &str, value: &str| {
        let mut payload = vec![3u8];
        payload.extend_from_slice(value.as_bytes());
        let mut out = vec![0u8; 10 + payload.len()];
        out[..4].copy_from_slice(id.as_bytes());
        put_u32_be(&mut out, 4, payload.len() as u32);
        out[10..].copy_from_slice(&payload);
        out
    };
    let frames = concat(&[&frame("TIT2", "Example song"), &frame("TPE1", "Example artist")]);
    let mut header = vec![0u8; 10];
    header[..3].copy_from_slice(b"ID3");
    header[3] = 3;
    let size = frames.len();
    header[6] = ((size >> 21) & 0x7f) as u8;
    header[7] = ((size >> 14) & 0x7f) as u8;
    header[8] = ((size >> 7) & 0x7f) as u8;
    header[9] = (size & 0x7f) as u8;
    concat(&[&header, &frames, &[0xff, 0xfb, 0x90, 0x00]])
}

/// A classic TIFF header with a magic number of a RAW format and the width and the height in IFD0.
fn synthetic_classic_tiff_variant(magic: u16, width: u32, height: u32) -> Vec<u8> {
    let mut data = vec![0u8; 8 + 2 + 2 * 12 + 4];
    data[..2].copy_from_slice(b"II");
    put_u16_le(&mut data, 2, magic);
    put_u32_le(&mut data, 4, 8);
    put_u16_le(&mut data, 8, 2);
    put_tiff_entry(&mut data, 8, 0, 0x0100, 4, 1, width);
    put_tiff_entry(&mut data, 8, 1, 0x0101, 4, 1, height);
    data
}

/// A little-endian BigTIFF header with the width and the height in IFD0.
fn synthetic_big_tiff(width: u32, height: u32) -> Vec<u8> {
    let mut data = vec![0u8; 16 + 8 + 2 * 20 + 8];
    data[..2].copy_from_slice(b"II");
    put_u16_le(&mut data, 2, 43);
    put_u16_le(&mut data, 4, 8);
    put_u16_le(&mut data, 6, 0);
    put_u64_le(&mut data, 8, 16);
    put_u64_le(&mut data, 16, 2);
    for (index, (tag, value)) in [(0x0100u16, width), (0x0101u16, height)].into_iter().enumerate() {
        let offset = 24 + index * 20;
        put_u16_le(&mut data, offset, tag);
        put_u16_le(&mut data, offset + 2, 4);
        put_u64_le(&mut data, offset + 4, 1);
        put_u32_le(&mut data, offset + 12, value);
    }
    data
}

/// One 80-byte FITS card.
fn fits_card(key: &str, value: &str) -> String {
    let mut card = if value.is_empty() {
        key.to_owned()
    } else {
        format!("{key:<8}= {value:>20}")
    };
    card.truncate(80);
    format!("{card:<80}")
}

/// A TIFF-based RAW file whose IFD0 gives the range of a JPEG preview.
fn synthetic_tiff_with_preview(width: u16, height: u16) -> Vec<u8> {
    let preview = synthetic_jpeg(width, height);
    let mut data = vec![0u8; 64];
    data[..2].copy_from_slice(b"II");
    put_u16_le(&mut data, 2, 42);
    put_u32_le(&mut data, 4, 8);
    put_u16_le(&mut data, 8, 2);
    put_tiff_entry(&mut data, 8, 0, 0x0201, 4, 1, 64);
    put_tiff_entry(&mut data, 8, 1, 0x0202, 4, 1, preview.len() as u32);
    data.extend_from_slice(&preview);
    data
}

// --- Routes -----------------------------------------------------------------------------------------------------

#[tokio::test]
async fn media_info_reads_only_the_png_header_and_sends_no_head() {
    let backend = memory();
    backend.insert("tenant/image.png", synthetic_png(640, 480), "image/png");
    let app = test_app(backend.clone());

    let response = request_media_info(&app, "image.png").await;
    assert_eq!(number(&response, "width"), 640, "{response}");
    assert_eq!(number(&response, "height"), 480);
    assert_eq!(response["container"], "PNG");
    assert_eq!(response["headers"]["x-amz-meta-test"], "visible", "{response}");
    let (gets, heads, ranges) = read_counts(&backend);
    assert_eq!((gets, heads), (1, 0), "ranges = {ranges:?}");
    // The PNG reader asks for its fixed header, then walks IHDR and IEND in the same span. The memory back end cuts
    // the answer at the end of the object.
    assert_eq!(ranges, ["bytes=0-65535"]);
}

#[tokio::test]
async fn media_info_reads_trailing_mp4_metadata_without_reading_the_media_payload() {
    let backend = memory();
    backend.insert("tenant/movie.1080p.mp4", test_mp4_metadata_object(), "video/mp4");
    let app = test_app(backend.clone());

    let response = request_media_info(&app, "movie.1080p.mp4").await;
    assert_eq!((number(&response, "width"), number(&response, "height")), (1920, 1080));
    assert_eq!(response["durationSeconds"].as_f64(), Some(12.5));
    assert_eq!(response["codecs"], serde_json::json!(["avc1", "mp4a"]));
    let tracks = response["tracks"].as_array().cloned().unwrap_or_default();
    assert_eq!(tracks.len(), 2, "{response}");
    assert_eq!(tracks[0]["type"], "video");
    assert_eq!(tracks[1]["type"], "audio");
    let (gets, heads, ranges) = read_counts(&backend);
    assert_eq!((gets, heads), (2, 0), "ranges = {ranges:?}");
    assert_eq!(ranges[0], "bytes=0-65535");
    assert!(ranges[1].starts_with("bytes=262"), "ranges = {ranges:?}");
    assert!(
        ranges.iter().all(|range| !range.is_empty()),
        "full-object GET: {ranges:?}"
    );
}

#[tokio::test]
async fn media_info_reads_a_complete_jpeg_header_beyond_64_kib() {
    let backend = memory();
    backend.insert(
        "tenant/large-header.jpg",
        synthetic_jpeg_with_large_header(8256, 5504),
        "image/jpeg",
    );
    let app = test_app(backend.clone());

    let response = request_media_info(&app, "large-header.jpg").await;
    assert_eq!((number(&response, "width"), number(&response, "height")), (8256, 5504));
    let (gets, heads, ranges) = read_counts(&backend);
    assert_eq!((gets, heads), (2, 0), "ranges = {ranges:?}");
    assert_eq!(ranges[0], "bytes=0-65535");
    assert!(ranges[1].starts_with("bytes=65536-"), "ranges = {ranges:?}");
}

#[tokio::test]
async fn media_info_has_no_cache_between_requests() {
    let backend = memory();
    backend.insert("tenant/image.png", synthetic_png(320, 200), "image/png");
    let app = test_app(backend.clone());

    request_media_info(&app, "image.png").await;
    let (first_gets, first_heads, _) = read_counts(&backend);
    request_media_info(&app, "image.png").await;
    let (second_gets, second_heads, _) = read_counts(&backend);
    assert_eq!((first_gets, first_heads, second_gets, second_heads), (1, 0, 2, 0));
}

#[tokio::test]
async fn media_info_uses_the_listed_media_type_for_an_image_without_extension() {
    let backend = memory();
    let data = synthetic_png(2048, 1365);
    let size = data.len();
    backend.insert("tenant/extensionless", data, "image/png");
    let app = test_app(backend.clone());

    let called = call(
        &app,
        "GET",
        &format!("/api/media-info?instance=rw&key=extensionless&mime=image%2Fpng&size={size}"),
    )
    .await;
    assert_eq!(called.status, 200, "body = {}", called.text());
    let response = called.json();
    assert_eq!((number(&response, "width"), number(&response, "height")), (2048, 1365));
    let (gets, heads, ranges) = read_counts(&backend);
    assert_eq!((gets, heads, ranges.len()), (1, 0, 1), "ranges = {ranges:?}");
    assert!(!ranges[0].is_empty());
}

#[tokio::test]
#[ignore = "the container of a text comes from the document readers"]
async fn text_details_use_one_head_and_leave_the_line_count_explicit() {
    let backend = memory();
    backend.insert("tenant/file.txt", "hello\nworld", "text/plain");
    let app = test_app(backend.clone());

    let response = request_media_info(&app, "file.txt").await;
    assert_eq!(number(&response, "size"), 11, "{response}");
    assert_eq!(response["mime"], "text/plain");
    assert_eq!(response["container"], "Plain text", "{response}");
    assert!(response.get("properties").is_none(), "{response}");
    let (gets, heads, ranges) = read_counts(&backend);
    assert_eq!((gets, heads, ranges.len()), (0, 1, 0));
}

#[tokio::test]
async fn raf_files_use_the_embedded_jpeg_for_bounded_metadata_and_the_preview() {
    let backend = memory();
    backend.insert("tenant/photo.raf", synthetic_raf(6240, 4160), "image/x-fuji-raf");
    let app = test_app(backend.clone());

    let info = request_media_info(&app, "photo.raf").await;
    assert_eq!((number(&info, "width"), number(&info, "height")), (6240, 4160));
    assert_eq!(info["container"], "RAF");

    let preview = call(&app, "GET", "/api/image-preview?instance=rw&key=photo.raf").await;
    assert_eq!(preview.status, 200, "body = {}", preview.text());
    assert_eq!(preview.header("content-type"), "image/jpeg");
    assert!(preview.body.starts_with(&[0xff, 0xd8]), "preview = {:x?}", preview.body);
    assert_eq!(preview.body.len(), synthetic_jpeg(6240, 4160).len());
}

#[tokio::test]
async fn the_image_preview_refuses_formats_without_an_embedded_preview() {
    let backend = memory();
    let mut data = b"P6\n2 1\n255\n".to_vec();
    data.extend_from_slice(&[255, 0, 0, 0, 255, 0]);
    backend.insert("tenant/two-pixels.ppm", data, "image/x-portable-pixmap");
    let app = test_app(backend);

    let called = call(&app, "GET", "/api/image-preview?instance=rw&key=two-pixels.ppm").await;
    assert_eq!(called.status, 501, "body = {}", called.text());
    assert!(
        called.text().contains("embedded JPEG preview"),
        "body = {}",
        called.text()
    );
}

#[test]
fn bounded_exif_metadata_includes_the_camera_and_gps() {
    let metadata = parse_bounded_file_metadata(&synthetic_tiff_with_exif_and_gps(), "tiff", "image/tiff", 520);
    assert_eq!((metadata.width, metadata.height), (4000, 3000));
    let want = [
        ("Camera make", "Canon"),
        ("Camera model", "EOS R5"),
        ("Captured", "2026:07:23 10:11:12"),
        ("Lens", "RF50mm F1.2"),
        ("ISO", "800"),
        ("Exposure", "1/250 s"),
        ("Aperture", "f/2.8"),
        ("Focal length", "50.0 mm"),
        ("GPS", "48.858333, 2.333333"),
        ("GPS altitude", "35.0 m"),
    ];
    for (key, expected) in want {
        assert_eq!(
            metadata.properties.get(key).map(String::as_str),
            Some(expected),
            "{key}"
        );
    }
}

#[test]
fn bounded_mp3_metadata_includes_the_tags_and_the_audio_properties() {
    let metadata = parse_bounded_file_metadata(&synthetic_id3_mp3(), "mp3", "audio/mpeg", 128_000);
    let property = |name: &str| metadata.properties.get(name).cloned().unwrap_or_default();
    assert_eq!(property("Title"), "Example song");
    assert_eq!(property("Artist"), "Example artist");
    assert_eq!(property("Bit rate"), "128 kb/s");
    assert_eq!(property("Sample rate"), "44.1 kHz");
    assert_eq!(property("Channels"), "2");
    assert_eq!(metadata.duration_seconds, 8.0);
}

#[tokio::test]
async fn details_read_the_dimensions_of_tiff_like_raw_headers() {
    let cases = [
        (
            "Olympus ORF",
            "orf",
            "image/x-olympus-orf",
            synthetic_classic_tiff_variant(0x4f52, 5184, 3888),
            (5184, 3888),
        ),
        (
            "Panasonic RW2",
            "rw2",
            "image/x-panasonic-rw2",
            synthetic_classic_tiff_variant(0x0055, 6000, 4000),
            (6000, 4000),
        ),
        (
            "BigTIFF DNG",
            "dng",
            "image/x-adobe-dng",
            synthetic_big_tiff(8256, 5504),
            (8256, 5504),
        ),
    ];
    for (name, extension, content_type, data, dimensions) in cases {
        let backend = memory();
        backend.insert(&format!("tenant/photo.{extension}"), data, content_type);
        let app = test_app(backend.clone());
        let response = request_media_info(&app, &format!("photo.{extension}")).await;
        assert_eq!(
            (number(&response, "width"), number(&response, "height")),
            dimensions,
            "{name}"
        );
        let (gets, heads, _) = read_counts(&backend);
        assert_eq!((gets, heads), (1, 0), "{name}");
    }
}

#[tokio::test]
async fn details_read_additional_image_header_formats() {
    let mut fits = [
        fits_card("SIMPLE", "T"),
        fits_card("NAXIS", "2"),
        fits_card("NAXIS1", "4096"),
        fits_card("NAXIS2", "2160"),
        fits_card("END", ""),
    ]
    .concat()
    .into_bytes();
    fits.resize(2880, 0);
    let mut qoi = vec![0u8; 14];
    qoi[..4].copy_from_slice(b"qoif");
    put_u32_be(&mut qoi, 4, 1920);
    put_u32_be(&mut qoi, 8, 1080);
    let mut farbfeld = vec![0u8; 16];
    farbfeld[..8].copy_from_slice(b"farbfeld");
    put_u32_be(&mut farbfeld, 8, 3000);
    put_u32_be(&mut farbfeld, 12, 2000);

    let cases = [
        ("image.qoi", "image/qoi", qoi, (1920, 1080)),
        ("image.ff", "image/farbfeld", farbfeld, (3000, 2000)),
        ("image.fits", "image/fits", fits, (4096, 2160)),
    ];
    for (key, content_type, data, dimensions) in cases {
        let backend = memory();
        backend.insert(&format!("tenant/{key}"), data, content_type);
        let app = test_app(backend);
        let response = request_media_info(&app, key).await;
        assert_eq!(
            (number(&response, "width"), number(&response, "height")),
            dimensions,
            "{key}"
        );
    }
}

#[tokio::test]
async fn details_refuse_a_provider_that_ignores_the_range_of_a_large_object() {
    let backend = memory();
    let mut data = synthetic_png(640, 480);
    data.extend_from_slice(&vec![0u8; 2 << 20]);
    backend.insert("tenant/large.png", data, "image/png");
    backend.state().ignore_ranges = true;
    let app = test_app(backend);

    let called = call(&app, "GET", "/api/media-info?instance=rw&key=large.png").await;
    assert_eq!(called.status, 502, "body = {}", called.text());
    assert!(
        called.text().contains("range_not_supported"),
        "body = {}",
        called.text()
    );
}

#[tokio::test]
async fn the_fits_header_scan_is_incremental_and_bounded() {
    let blank = " ".repeat(80);
    // A real header with many blocks of blank cards before the dimensions.
    let mut header = fits_card("SIMPLE", "T")
        + &blank.repeat(3600)
        + &fits_card("NAXIS1", "640")
        + &fits_card("NAXIS2", "480")
        + &fits_card("END", "");
    header += &" ".repeat(2880 - header.len() % 2880);
    // A header without END that is larger than the limit of the scan.
    let endless = fits_card("SIMPLE", "T") + &blank.repeat((1536 << 10) / 80);
    let backend = memory();
    backend.insert("tenant/ok.fits", header, "image/fits");
    backend.insert("tenant/endless.fits", endless, "image/fits");
    let app = test_app(backend.clone());

    let response = request_media_info(&app, "ok.fits").await;
    assert_eq!((number(&response, "width"), number(&response, "height")), (640, 480));
    let (gets, _, _) = read_counts(&backend);
    assert!(gets <= 12, "GETs = {gets}, want a doubling read pattern");
    let response = request_media_info(&app, "endless.fits").await;
    assert_eq!((number(&response, "width"), number(&response, "height")), (0, 0));
    let (after, _, _) = read_counts(&backend);
    assert!(after - gets <= 12, "the endless header used {} GETs", after - gets);
}

// --- More cases of the routes -----------------------------------------------------------------------------------

#[tokio::test]
async fn media_info_refuses_another_method_and_an_empty_key() {
    let app = test_app(memory());
    let called = call(&app, "POST", "/api/media-info?instance=rw&key=a.png").await;
    assert_eq!(called.status, 405);
    assert_eq!(called.header("allow"), "GET");
    let called = call(&app, "GET", "/api/media-info?instance=rw&key=%2F").await;
    assert_eq!(called.status, 400);
    assert_eq!(called.json()["error"]["code"], "invalid_key");
    assert_eq!(called.json()["error"]["message"], "object key cannot be empty");
    let called = call(&app, "PUT", "/api/image-preview?instance=rw&key=a.raf").await;
    assert_eq!(called.status, 405);
    assert_eq!(called.header("allow"), "GET, HEAD");
    let called = call(&app, "GET", "/api/image-preview?instance=rw&key=").await;
    assert_eq!(called.json()["error"]["message"], "image key cannot be empty");
    let called = call(&app, "GET", "/api/media-info?instance=nope&key=a.png").await;
    assert_eq!(called.status, 404);
}

#[tokio::test]
async fn a_key_without_media_metadata_gets_one_head_and_no_container() {
    let backend = memory();
    backend.insert("tenant/archive.bin", vec![1u8; 300], "application/octet-stream");
    let app = test_app(backend.clone());

    let called = call(&app, "GET", "/api/media-info?instance=rw&key=archive.bin").await;
    assert_eq!(called.status, 200);
    assert_eq!(called.header("cache-control"), "no-store");
    let response = called.json();
    assert_eq!(number(&response, "size"), 300);
    assert_eq!(response["mime"], "application/octet-stream");
    assert!(response.get("container").is_none(), "{response}");
    assert_eq!(response["headers"]["etag"], "\"etag-tenant/archive.bin\"");
    assert!(response["headers"].get("set-cookie").is_none(), "{response}");
    let (gets, heads, _) = read_counts(&backend);
    assert_eq!((gets, heads), (0, 1));
}

#[tokio::test]
async fn a_missing_media_object_gives_the_error_of_the_provider() {
    let app = test_app(memory());
    let called = call(&app, "GET", "/api/media-info?instance=rw&key=missing.png").await;
    assert_eq!(called.status, 404, "body = {}", called.text());
}

/// A back end that answers 416 to each range request, as some providers do for an empty object.
struct UnsatisfiableRanges {
    memory: MemoryBackend,
}

impl MemoryLayer for UnsatisfiableRanges {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }

    fn get<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            self.memory.state().get_count += 1;
            Ok(ObjectResponse {
                status: 416,
                headers: HeaderMap::new(),
                body: empty(),
            })
        })
    }
}

#[tokio::test]
async fn an_unsatisfiable_first_range_falls_back_to_one_head() {
    let layer = Arc::new(UnsatisfiableRanges {
        memory: MemoryBackend::new(),
    });
    layer.memory.insert("tenant/empty.png", Vec::new(), "image/png");
    let app = test_app(layer.clone());

    let called = call(&app, "GET", "/api/media-info?instance=rw&key=empty.png").await;
    assert_eq!(called.status, 200, "body = {}", called.text());
    let response = called.json();
    assert_eq!(number(&response, "size"), 0);
    assert_eq!(response["mime"], "image/png");
    assert!(response.get("container").is_none(), "{response}");
    let (gets, heads, _) = read_counts(&layer.memory);
    assert_eq!((gets, heads), (1, 1));
}

#[tokio::test]
async fn an_empty_object_answers_its_storage_facts() {
    let backend = memory();
    backend.insert("tenant/empty.png", Vec::new(), "image/png");
    let app = test_app(backend.clone());

    let response = request_media_info(&app, "empty.png").await;
    assert_eq!(number(&response, "size"), 0);
    assert_eq!(response["container"], "PNG");
    assert!(response.get("width").is_none(), "{response}");
}

#[tokio::test]
async fn the_preview_of_a_tiff_based_raw_file_sends_its_embedded_jpeg() {
    let backend = memory();
    backend.insert(
        "tenant/photo.nef",
        synthetic_tiff_with_preview(4000, 3000),
        "image/x-nikon-nef",
    );
    let app = test_app(backend.clone());

    let preview = call(&app, "GET", "/api/image-preview?instance=rw&key=photo.nef").await;
    assert_eq!(preview.status, 200, "body = {}", preview.text());
    assert_eq!(preview.body.as_ref(), synthetic_jpeg(4000, 3000).as_slice());
    assert_eq!(
        preview.header("content-length"),
        synthetic_jpeg(4000, 3000).len().to_string()
    );
    assert_eq!(preview.header("cache-control"), "no-store");
    assert_eq!(preview.header("x-content-type-options"), "nosniff");
    assert_eq!(preview.header("cross-origin-resource-policy"), "same-origin");
    assert!(preview.header("content-security-policy").starts_with("sandbox;"));
    let ranges = read_counts(&backend).2;
    assert_eq!(ranges.last().map(String::as_str), Some("bytes=64-86"), "{ranges:?}");

    let info = request_media_info(&app, "photo.nef").await;
    assert_eq!((number(&info, "width"), number(&info, "height")), (4000, 3000));
    assert_eq!(info["container"], "NEF");

    let head = call(&app, "HEAD", "/api/image-preview?instance=rw&key=photo.nef").await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_eq!(head.header("content-type"), "image/jpeg");
    assert_eq!(
        head.header("content-length"),
        synthetic_jpeg(4000, 3000).len().to_string()
    );
}

#[tokio::test]
async fn the_preview_refuses_a_provider_that_ignores_the_range() {
    // The header read works; then the provider sends the complete object for the range of the preview.
    let layer = Arc::new(IgnoredPreviewRange {
        memory: MemoryBackend::new(),
    });
    layer
        .memory
        .insert("tenant/photo.raf", synthetic_raf(64, 48), "image/x-fuji-raf");
    let app = test_app(layer);
    let called = call(&app, "GET", "/api/image-preview?instance=rw&key=photo.raf").await;
    assert_eq!(called.status, 502, "body = {}", called.text());
    assert_eq!(called.json()["error"]["code"], "range_not_supported");
    assert_eq!(
        called.json()["error"]["message"],
        "the storage provider ignored the embedded image preview range"
    );
}

/// A back end that sends the complete object for each range that does not start at 0.
struct IgnoredPreviewRange {
    memory: MemoryBackend,
}

impl MemoryLayer for IgnoredPreviewRange {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }

    fn get<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            let range = headers
                .get(http::header::RANGE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            if range.starts_with("bytes=0-") {
                return self.memory.get(ctx, key, headers).await;
            }
            self.memory.get(ctx, key, &HeaderMap::new()).await
        })
    }
}

#[tokio::test]
async fn the_routes_refuse_an_instance_without_the_read_permission() {
    let backend = memory();
    backend.insert("tenant/photo.raf", synthetic_raf(64, 48), "image/x-fuji-raf");
    let app = app_of(vec![
        instance(
            bucket_config("readonly", "", &[PERMISSION_READ]),
            Arc::new(MemoryBackend::new()),
        ),
        instance(bucket_config("wo", "tenant/", &[PERMISSION_WRITE]), backend.clone()),
    ]);
    for endpoint in ["/api/media-info", "/api/image-preview"] {
        let called = call(&app, "GET", &format!("{endpoint}?instance=wo&key=photo.raf&size=6")).await;
        assert_eq!(called.status, 403, "{endpoint}: {}", called.text());
    }
    let (gets, heads, _) = read_counts(&backend);
    assert_eq!((gets, heads), (0, 0));
}

/// A back end that refuses each read of an object with a key of the client: the HEAD answer has no text, the GET
/// answer names the encryption.
struct CustomerKeyObjects {
    memory: MemoryBackend,
}

impl MemoryLayer for CustomerKeyObjects {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }

    fn head<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            self.memory.state().head_count += 1;
            Err(crate::common::error::Error::upstream(400, "", ""))
        })
    }

    fn get<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            self.memory.state().get_count += 1;
            Err(crate::common::error::Error::upstream(
                400,
                "InvalidRequest",
                "The object was stored using a form of Server Side Encryption",
            ))
        })
    }
}

#[tokio::test]
async fn an_object_with_a_key_of_the_client_gets_its_listed_facts() {
    let layer = Arc::new(CustomerKeyObjects {
        memory: MemoryBackend::new(),
    });
    layer
        .memory
        .insert("tenant/secret.bin", vec![7u8; 42], "application/octet-stream");
    layer.memory.insert("tenant/secret.png", vec![7u8; 42], "image/png");
    let app = test_app(layer.clone());

    for key in ["secret.bin", "secret.png"] {
        let called = call(&app, "GET", &format!("/api/media-info?instance=rw&key={key}")).await;
        assert_eq!(called.status, 200, "{key}: {}", called.text());
        assert_eq!(called.header("cache-control"), "no-store");
        let response = called.json();
        assert_eq!(response["customerKey"], true, "{response}");
        assert_eq!(number(&response, "size"), 42);
        assert_eq!(response["headers"]["etag"], format!("\"etag-tenant/{key}\""));
        assert!(response.get("container").is_none(), "{response}");
    }
}
