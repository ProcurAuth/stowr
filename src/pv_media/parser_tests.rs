// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the format readers: the image headers, TIFF and EXIF, the audio headers, ISO base media, Matroska,
//! the text helpers, and the routes over these formats.

use serde_json::json;

use super::adaptive::jpeg_header_requirement;
use super::audio::{decode_id3_text, find_mp3_frame, last_ogg_granule, parse_flac_metadata, parse_wav_metadata};
use super::image::{
    find_svg_start_tag, parse_additional_image_dimensions, parse_exr_dimensions, parse_image_dimensions,
    parse_j2k_codestream_dimensions, parse_pnm_dimensions, parse_radiance_hdr_dimensions, parse_svg_length,
    parse_svg_start_tag,
};
use super::iso::{parse_iso_base_media, parse_iso_tracks, parse_mdhd_language, parse_mvhd_duration};
use super::matroska::{parse_matroska_header, read_ebml_vint};
use super::metadata::{MediaMetadata, parse_bounded_file_metadata};
use super::tests::{
    call, iso_box, memory, number, read_counts, request_media_info, synthetic_id3_mp3, synthetic_jpeg, synthetic_png,
    synthetic_tiff_with_exif_and_gps, test_app, test_mp4_metadata_object,
};
use super::text::{
    float_to_int, fold_lower, fold_upper, format_general, lossy, lower_bytes, parse_float, parse_int,
    parse_int_saturating,
};
use super::tiff::{embedded_tiff_jpeg_range, format_exposure, orientation_label, parse_tiff_layout, raf_preview_range};
use super::{MediaInfoResponse, MediaTrackInfo, media_container, parse_int64_default, populate_media_storage_fields};

// --- Builders ---------------------------------------------------------------------------------------------------

/// An EBML element: the ID bytes, a size of 8 bytes, and the payload.
fn ebml(id: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = id.to_vec();
    out.push(0x01);
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes()[1..]);
    out.extend_from_slice(payload);
    out
}

fn ebml_uint(id: &[u8], value: u64) -> Vec<u8> {
    ebml(id, &value.to_be_bytes())
}

fn ebml_float(id: &[u8], value: f64) -> Vec<u8> {
    ebml(id, &value.to_be_bytes())
}

fn join(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// A WebM file: the EBML header, a segment of unknown size with Info (title, scale, 5 seconds), a video track
/// (VP9, 1280x720, default) and an audio track (Opus, 48 kHz, 2 channels, English), then a cluster.
fn synthetic_webm() -> Vec<u8> {
    let header = ebml(&[0x1a, 0x45, 0xdf, 0xa3], &ebml(&[0x42, 0x82], b"webm"));
    let info = ebml(
        &[0x15, 0x49, 0xa9, 0x66],
        &join(&[
            ebml_uint(&[0x2a, 0xd7, 0xb1], 1_000_000),
            ebml_float(&[0x44, 0x89], 5000.0),
            ebml(&[0x7b, 0xa9], b"Clip"),
            ebml(&[0x4d, 0x80], b"muxer 1"),
        ]),
    );
    let video = ebml(
        &[0xae],
        &join(&[
            ebml_uint(&[0x83], 1),
            ebml(&[0x86], b"V_VP9"),
            ebml_uint(&[0x88], 1),
            ebml(&[0xe0], &join(&[ebml_uint(&[0xb0], 1280), ebml_uint(&[0xba], 720)])),
        ]),
    );
    let audio = ebml(
        &[0xae],
        &join(&[
            ebml_uint(&[0x83], 2),
            ebml(&[0x86], b"A_OPUS"),
            ebml(&[0x22, 0xb5, 0x9c], b"eng"),
            ebml(&[0xe1], &join(&[ebml_float(&[0xb5], 48000.0), ebml_uint(&[0x9f], 2)])),
        ]),
    );
    let tracks = ebml(&[0x16, 0x54, 0xae, 0x6b], &join(&[video, audio]));
    let cluster = ebml(&[0x1f, 0x43, 0xb6, 0x75], &[0u8; 32]);
    let mut segment = vec![0x18, 0x53, 0x80, 0x67, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    segment.extend_from_slice(&join(&[info, tracks, cluster]));
    join(&[header, segment])
}

/// A WAV file: `fmt ` (PCM, 2 channels, 44.1 kHz, 16 bits), an INFO list with a title and the `data` chunk.
fn synthetic_wav(data_bytes: usize) -> Vec<u8> {
    let mut fmt = Vec::new();
    fmt.extend_from_slice(&1u16.to_le_bytes());
    fmt.extend_from_slice(&2u16.to_le_bytes());
    fmt.extend_from_slice(&44_100u32.to_le_bytes());
    fmt.extend_from_slice(&176_400u32.to_le_bytes());
    fmt.extend_from_slice(&4u16.to_le_bytes());
    fmt.extend_from_slice(&16u16.to_le_bytes());
    let chunk = |id: &[u8], payload: &[u8]| {
        let mut out = id.to_vec();
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        if payload.len() % 2 == 1 {
            out.push(0);
        }
        out
    };
    let info = [b"INFO".to_vec(), chunk(b"INAM", b"Song\x00")].concat();
    let body = join(&[
        b"WAVE".to_vec(),
        chunk(b"fmt ", &fmt),
        chunk(b"LIST", &info),
        chunk(b"data", &vec![0u8; data_bytes]),
    ]);
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// A FLAC file: STREAMINFO (44.1 kHz, 2 channels, 16 bits, 441000 samples) and the Vorbis comments (last block).
fn synthetic_flac() -> Vec<u8> {
    let mut streaminfo = vec![0u8; 34];
    let packed: u64 = (44_100u64 << 44) | (1u64 << 41) | (15u64 << 36) | 441_000;
    streaminfo[10..18].copy_from_slice(&packed.to_be_bytes());
    let mut comments = Vec::new();
    comments.extend_from_slice(&6u32.to_le_bytes());
    comments.extend_from_slice(b"vendor");
    let fields: [&[u8]; 3] = [b"TITLE=Tune", b"artist=Band", b"foo=bar"];
    comments.extend_from_slice(&(fields.len() as u32).to_le_bytes());
    for field in fields {
        comments.extend_from_slice(&(field.len() as u32).to_le_bytes());
        comments.extend_from_slice(field);
    }
    let block = |kind: u8, payload: &[u8]| {
        let mut out = vec![kind];
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(payload);
        out
    };
    join(&[
        b"fLaC".to_vec(),
        block(0, &streaminfo),
        block(0x84, &comments),
        vec![0xff, 0xf8, 0, 0],
    ])
}

/// One Ogg page with one segment.
fn ogg_page(granule: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = b"OggS".to_vec();
    out.push(0);
    out.push(0);
    out.extend_from_slice(&granule.to_le_bytes());
    out.extend_from_slice(&[1, 0, 0, 0]);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.push(1);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    out
}

/// An Ogg Opus stream of 2 seconds with 2 channels.
fn synthetic_opus() -> Vec<u8> {
    let mut head = b"OpusHead".to_vec();
    head.push(1);
    head.push(2);
    head.extend_from_slice(&[0u8; 9]);
    join(&[
        ogg_page(0, &head),
        ogg_page(0, b"OpusTags"),
        ogg_page(96_000, &[0u8; 40]),
    ])
}

/// A little-endian TIFF entry of 12 bytes.
fn tiff_entry(tag: u16, type_id: u16, count: u32, value: u32) -> Vec<u8> {
    join(&[
        tag.to_le_bytes().to_vec(),
        type_id.to_le_bytes().to_vec(),
        count.to_le_bytes().to_vec(),
        value.to_le_bytes().to_vec(),
    ])
}

// --- Text helpers -----------------------------------------------------------------------------------------------

#[test]
fn the_general_number_form_has_three_significant_digits() {
    assert_eq!(format_general(2.0, 3), "2");
    assert_eq!(format_general(1.5, 3), "1.5");
    assert_eq!(format_general(30.0, 3), "30");
    assert_eq!(format_general(123.456, 3), "123");
    assert_eq!(format_general(99.95, 3), "100");
    assert_eq!(format_general(1234.0, 3), "1.23e+03");
    assert_eq!(format_general(12_345_678.0, 3), "1.23e+07");
    assert_eq!(format_general(0.000_012_34, 3), "1.23e-05");
    assert_eq!(format_general(0.001_5, 3), "0.0015");
}

#[test]
fn exposures_below_one_second_are_fractions() {
    assert_eq!(format_exposure(1.0 / 250.0), "1/250 s");
    assert_eq!(format_exposure(0.3), "1/3 s");
    assert_eq!(format_exposure(2.0), "2 s");
    assert_eq!(format_exposure(1.0), "1 s");
    assert_eq!(format_exposure(2.5), "2.5 s");
    assert_eq!(orientation_label(6), "Rotated 90° clockwise");
    assert_eq!(orientation_label(9), "9");
}

#[test]
fn invalid_bytes_become_one_replacement_character_each() {
    assert_eq!(lossy(b"a\xe2\x82b"), "a\u{fffd}\u{fffd}b");
    assert_eq!(lossy(b"\xff"), "\u{fffd}");
    assert_eq!(lossy("é".as_bytes()), "é");
    assert_eq!(lower_bytes(b"<SVG \xff>"), "<svg \u{fffd}>".as_bytes());
}

#[test]
fn the_case_helpers_use_one_character_mappings() {
    assert_eq!(fold_lower("PNG"), "png");
    assert_eq!(fold_lower("\u{130}X"), "ix");
    assert_eq!(fold_upper("ab"), "AB");
    assert_eq!(fold_upper("\u{fb00}"), "\u{fb00}");
    assert_eq!(fold_upper("éa"), "ÉA");
}

#[test]
fn the_number_helpers_follow_the_rules_of_the_queries() {
    assert_eq!(parse_int("+12"), Some(12));
    assert_eq!(parse_int("-3"), Some(-3));
    assert_eq!(parse_int(" 3"), None);
    assert_eq!(parse_int("1_0"), None);
    assert_eq!(parse_int_saturating("99999999999999999999"), (i64::MAX, false));
    assert_eq!(parse_int_saturating("-99999999999999999999"), (i64::MIN, false));
    assert_eq!(parse_int_saturating("x"), (0, false));
    assert_eq!(parse_int64_default(" 42 ", 0), 42);
    assert_eq!(parse_int64_default("abc", 7), 7);
    assert_eq!(parse_float("1e400"), None);
    assert_eq!(parse_float("inf"), Some(f64::INFINITY));
    assert_eq!(parse_float("2.5"), Some(2.5));
    assert_eq!(float_to_int(f64::NAN), i64::MIN);
    assert_eq!(float_to_int(1e19), i64::MIN);
    assert_eq!(float_to_int(-2.9), -2);
}

#[test]
fn a_merge_keeps_the_codecs_of_the_target_and_adds_first_occurrences_after_them() {
    let mut target = MediaMetadata {
        codecs: vec!["a".to_owned()],
        width: 10,
        ..MediaMetadata::default()
    };
    let mut properties = std::collections::BTreeMap::new();
    properties.insert("Title".to_owned(), "  Song ".to_owned());
    properties.insert("Empty".to_owned(), "   ".to_owned());
    target.merge(MediaMetadata {
        width: 20,
        height: 0,
        duration_seconds: 3.0,
        codecs: vec![" b ".to_owned(), "a".to_owned(), String::new()],
        properties,
        tracks: Vec::new(),
    });
    assert_eq!(target.codecs, ["a", "a", "b"]);
    assert_eq!(
        target.width, 10,
        "a width without a height does not replace the dimensions"
    );
    assert_eq!(target.duration_seconds, 3.0);
    assert_eq!(target.properties.get("Title").map(String::as_str), Some("Song"));
    assert!(!target.properties.contains_key("Empty"));
}

// --- Storage facts ----------------------------------------------------------------------------------------------

#[test]
fn the_storage_facts_keep_the_object_headers_only() {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", "image/png; charset=binary".parse().unwrap());
    headers.insert("content-length", "1234".parse().unwrap());
    headers.insert("set-cookie", "a=b".parse().unwrap());
    headers.append("x-amz-meta-tag", "one".parse().unwrap());
    headers.append("x-amz-meta-tag", "two".parse().unwrap());
    headers.insert("x-amz-server-side-encryption", "AES256".parse().unwrap());
    headers.insert(
        "x-amz-server-side-encryption-customer-key-md5",
        "secret".parse().unwrap(),
    );
    let mut response = MediaInfoResponse::default();
    populate_media_storage_fields(&mut response, &headers, 0);
    assert_eq!(response.size, 1234);
    assert_eq!(response.mime, "image/png");
    assert_eq!(
        serde_json::to_value(&response.headers).unwrap(),
        json!({
            "content-length": "1234",
            "content-type": "image/png; charset=binary",
            "x-amz-meta-tag": "one, two",
            "x-amz-server-side-encryption": "AES256",
        })
    );
    populate_media_storage_fields(&mut response, &headers, 99);
    assert_eq!(response.size, 99);
    populate_media_storage_fields(&mut response, &http::HeaderMap::new(), -5);
    assert_eq!(response.size, 0);
    assert!(response.headers.is_empty());
}

#[test]
fn the_container_label_comes_from_the_extension_or_the_media_type() {
    assert_eq!(media_container("jpg", ""), "JPEG");
    assert_eq!(media_container("m4a", ""), "MP4");
    assert_eq!(media_container("wave", ""), "WAV");
    assert_eq!(media_container("mkv", "video/mp4"), "MKV");
    assert_eq!(media_container("", "video/quicktime"), "MOV");
    assert_eq!(media_container("", "image/webp"), "WEBP");
    assert_eq!(media_container("", "text/plain"), "");
}

#[test]
fn the_answer_omits_the_empty_members() {
    let response = MediaInfoResponse {
        instance: "rw".to_owned(),
        key: "a.mkv".to_owned(),
        tracks: vec![MediaTrackInfo {
            kind: "audio".to_owned(),
            default: true,
            sample_rate: 48_000,
            ..MediaTrackInfo::default()
        }],
        ..MediaInfoResponse::default()
    };
    let text = String::from_utf8(crate::common::json::to_vec(&response).unwrap()).unwrap();
    assert_eq!(
        text,
        r#"{"instance":"rw","key":"a.mkv","size":0,"tracks":[{"index":0,"type":"audio","sampleRate":48000,"default":true}]}"#
    );
}

// --- Images -----------------------------------------------------------------------------------------------------

#[test]
fn the_usual_image_headers_give_their_dimensions() {
    let mut gif = b"GIF89a".to_vec();
    gif.extend_from_slice(&[0x40, 0x01, 0xf0, 0x00]);
    assert_eq!(parse_image_dimensions(&gif, "gif", ""), Some((320, 240)));
    assert_eq!(
        parse_image_dimensions(&synthetic_png(7, 9), "", "image/png"),
        Some((7, 9))
    );
    assert_eq!(
        parse_image_dimensions(&synthetic_jpeg(30, 20), "jpeg", ""),
        Some((30, 20))
    );

    let mut vp8x = b"RIFF\x00\x00\x00\x00WEBPVP8X".to_vec();
    vp8x.resize(30, 0);
    vp8x[24..27].copy_from_slice(&[0x7f, 0x07, 0x00]);
    vp8x[27..30].copy_from_slice(&[0x37, 0x04, 0x00]);
    assert_eq!(parse_image_dimensions(&vp8x, "webp", ""), Some((1920, 1080)));
    let mut vp8 = b"RIFF\x00\x00\x00\x00WEBPVP8 ".to_vec();
    vp8.resize(30, 0);
    vp8[23..26].copy_from_slice(&[0x9d, 0x01, 0x2a]);
    vp8[26..28].copy_from_slice(&640u16.to_le_bytes());
    vp8[28..30].copy_from_slice(&480u16.to_le_bytes());
    assert_eq!(parse_image_dimensions(&vp8, "webp", ""), Some((640, 480)));
    let mut vp8l = b"RIFF\x00\x00\x00\x00WEBPVP8L".to_vec();
    vp8l.resize(30, 0);
    vp8l[20] = 0x2f;
    // A width of 100 and a height of 50: 14 bits each, minus one.
    let bits: u32 = 99 | (49 << 14);
    vp8l[21..25].copy_from_slice(&bits.to_le_bytes());
    assert_eq!(parse_image_dimensions(&vp8l, "webp", ""), Some((100, 50)));
    assert_eq!(parse_image_dimensions(&synthetic_png(7, 9), "gif", ""), None);
}

#[test]
fn fixed_image_headers_give_their_dimensions() {
    let mut bmp = vec![0u8; 26];
    bmp[..2].copy_from_slice(b"BM");
    bmp[18..22].copy_from_slice(&800i32.to_le_bytes());
    bmp[22..26].copy_from_slice(&(-600i32).to_le_bytes());
    assert_eq!(parse_additional_image_dimensions(&bmp, "BMP", ""), Some((800, 600)));

    let mut psd = vec![0u8; 26];
    psd[..4].copy_from_slice(b"8BPS");
    psd[14..18].copy_from_slice(&300u32.to_be_bytes());
    psd[18..22].copy_from_slice(&400u32.to_be_bytes());
    assert_eq!(parse_additional_image_dimensions(&psd, "psd", ""), Some((400, 300)));

    let mut tga = vec![0u8; 18];
    tga[12..14].copy_from_slice(&64u16.to_le_bytes());
    tga[14..16].copy_from_slice(&32u16.to_le_bytes());
    assert_eq!(parse_additional_image_dimensions(&tga, "tga", ""), Some((64, 32)));

    let ico = [0, 0, 1, 0, 1, 0, 0, 48];
    assert_eq!(parse_additional_image_dimensions(&ico, "ico", ""), Some((256, 48)));

    let mut dds = vec![0u8; 20];
    dds[..4].copy_from_slice(b"DDS ");
    dds[12..16].copy_from_slice(&512u32.to_le_bytes());
    dds[16..20].copy_from_slice(&1024u32.to_le_bytes());
    assert_eq!(parse_additional_image_dimensions(&dds, "dds", ""), Some((1024, 512)));

    let mut pcx = vec![0u8; 12];
    pcx[0] = 0x0a;
    pcx[8..10].copy_from_slice(&99u16.to_le_bytes());
    pcx[10..12].copy_from_slice(&49u16.to_le_bytes());
    assert_eq!(parse_additional_image_dimensions(&pcx, "pcx", ""), Some((100, 50)));

    let mut sgi = vec![0u8; 10];
    sgi[..2].copy_from_slice(&0x01dau16.to_be_bytes());
    sgi[6..8].copy_from_slice(&16u16.to_be_bytes());
    sgi[8..10].copy_from_slice(&8u16.to_be_bytes());
    assert_eq!(parse_additional_image_dimensions(&sgi, "rgb", ""), Some((16, 8)));

    // Another extension with an image media type gets the usual headers.
    assert_eq!(
        parse_additional_image_dimensions(&synthetic_png(5, 6), "dat", "image/png"),
        Some((5, 6))
    );
    assert_eq!(parse_additional_image_dimensions(&synthetic_png(5, 6), "dat", ""), None);
}

#[test]
fn pnm_and_hdr_headers_give_their_dimensions() {
    assert_eq!(
        parse_pnm_dimensions(b"P6\n# comment\n640 480\n255\n"),
        (640, 480, true, true)
    );
    assert_eq!(parse_pnm_dimensions(b"P6\n640#c\n 480 255"), (640, 480, true, true));
    assert_eq!(parse_pnm_dimensions(b"P6\n640"), (0, 0, false, true));
    assert_eq!(parse_pnm_dimensions(b"P6\n# no line end"), (0, 0, false, true));
    assert_eq!(parse_pnm_dimensions(b"XX"), (0, 0, true, false));
    assert_eq!(
        parse_pnm_dimensions(b"P7\r\nWIDTH 32\r\nheight 16\r\nDEPTH 4\r\nENDHDR\r\n"),
        (32, 16, true, true)
    );
    assert_eq!(parse_pnm_dimensions(b"P7\nWIDTH 32\n"), (0, 0, false, true));

    assert_eq!(
        parse_radiance_hdr_dimensions(b"#?RADIANCE\nFORMAT=32-bit_rle_rgbe\n\n-Y 512 +X 768\n"),
        (768, 512, true, true)
    );
    assert_eq!(parse_radiance_hdr_dimensions(b"#?RADIANCE\n"), (0, 0, false, true));
    assert_eq!(parse_radiance_hdr_dimensions(b"P6"), (0, 0, true, false));
}

#[test]
fn exr_and_jpeg_2000_headers_give_their_dimensions() {
    let mut exr = 0x0131_2f76u32.to_le_bytes().to_vec();
    exr.extend_from_slice(&[2, 0, 0, 0]);
    exr.extend_from_slice(b"compression\x00compression\x00");
    exr.extend_from_slice(&1u32.to_le_bytes());
    exr.push(0);
    exr.extend_from_slice(b"dataWindow\x00box2i\x00");
    exr.extend_from_slice(&16u32.to_le_bytes());
    for value in [0i32, 0, 1919, 1079] {
        exr.extend_from_slice(&value.to_le_bytes());
    }
    let required = exr.len() as i64 + 1;
    assert_eq!(parse_exr_dimensions(&exr), (0, 0, required + 255, false, true));
    exr.push(0);
    assert_eq!(parse_exr_dimensions(&exr), (1920, 1080, required, true, true));
    assert!(!parse_exr_dimensions(&exr[..30]).3);
    assert_eq!(parse_exr_dimensions(b"notanexr"), (0, 0, 8, true, false));

    let mut siz = vec![0xff, 0x4f, 0xff, 0x51];
    siz.extend_from_slice(&41u16.to_be_bytes());
    siz.extend_from_slice(&[0, 0]);
    for value in [2048u32, 1024, 48, 24, 2048, 1024, 0, 0] {
        siz.extend_from_slice(&value.to_be_bytes());
    }
    siz.extend_from_slice(&[0u8; 7]);
    assert_eq!(parse_j2k_codestream_dimensions(&siz), Some((2000, 1000)));
    assert_eq!(parse_j2k_codestream_dimensions(&siz[..20]), None);
}

#[test]
fn svg_start_tags_give_their_dimensions() {
    let tag = |text: &str| find_svg_start_tag(text.as_bytes()).map(parse_svg_start_tag);
    assert_eq!(
        tag(r#"<?xml version="1.0"?><svg xmlns="x" width="120px" height='80'>"#),
        Some((120, 80))
    );
    // The reader skips the first item after the element name together with the name.
    assert_eq!(tag(r#"<svg width="120px" height='80'>"#), Some((0, 80)));
    assert_eq!(tag(r#"<SVG id="a" viewBox="0 0 300.4 150.6">"#), Some((300, 151)));
    assert_eq!(
        tag(r#"<svg id="a" width="100%" height="50" viewBox="0,0,10,20">"#),
        Some((10, 20))
    );
    assert_eq!(tag(r#"<svg id="a" width="100%" height="50">"#), Some((0, 50)));
    assert_eq!(tag(r#"<svg width="64""#), None);
    assert_eq!(tag("<html>"), None);
    assert_eq!(parse_svg_length(b" 12.6mm "), 13);
    assert_eq!(parse_svg_length(b"-4"), 0);
    assert_eq!(parse_svg_length(b"em"), 0);
}

// --- TIFF and EXIF ----------------------------------------------------------------------------------------------

#[test]
fn tiff_layouts_cover_classic_big_and_raw_headers() {
    assert!(parse_tiff_layout(b"II*\x00\x08\x00\x00\x00").is_some_and(|layout| !layout.big));
    assert!(parse_tiff_layout(b"MM\x00*\x00\x00\x00\x08").is_some());
    assert!(parse_tiff_layout(b"IIRO\x08\x00\x00\x00").is_some());
    assert!(
        parse_tiff_layout(b"II+\x00\x08\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00").is_some_and(|layout| layout.big)
    );
    assert!(parse_tiff_layout(b"II+\x00\x04\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00").is_none());
    assert!(parse_tiff_layout(b"XX*\x00\x08\x00\x00\x00").is_none());
}

#[test]
fn exif_in_a_jpeg_app1_segment_gives_the_camera() {
    let tiff = synthetic_tiff_with_exif_and_gps();
    let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe1];
    jpeg.extend_from_slice(&((tiff.len() + 8) as u16).to_be_bytes());
    jpeg.extend_from_slice(b"Exif\x00\x00");
    jpeg.extend_from_slice(&tiff);
    jpeg.extend_from_slice(&synthetic_jpeg(4000, 3000)[2..]);
    let metadata = parse_bounded_file_metadata(&jpeg, "jpeg", "image/jpeg", 0);
    assert_eq!((metadata.width, metadata.height), (4000, 3000));
    assert_eq!(
        metadata.properties.get("Camera make").map(String::as_str),
        Some("Canon")
    );
    assert_eq!(metadata.properties.get("ISO").map(String::as_str), Some("800"));
    assert_eq!(jpeg_header_requirement(&jpeg), (jpeg.len() as i64, true, true));
}

#[test]
fn gps_references_south_and_west_give_negative_coordinates() {
    let mut tiff = synthetic_tiff_with_exif_and_gps();
    // GPS IFD at 256: entry 0 (latitude reference) and entry 2 (longitude reference).
    tiff[256 + 2 + 8] = b'S';
    tiff[256 + 2 + 2 * 12 + 8] = b'w';
    tiff[256 + 2 + 4 * 12 + 8] = 1;
    let metadata = parse_bounded_file_metadata(&tiff, "tiff", "", 0);
    assert_eq!(
        metadata.properties.get("GPS").map(String::as_str),
        Some("-48.858333, -2.333333")
    );
    assert_eq!(
        metadata.properties.get("GPS altitude").map(String::as_str),
        Some("-35.0 m")
    );
}

#[test]
fn raw_previews_come_from_the_raf_header_and_the_tiff_ifds() {
    let mut raf = vec![0u8; 92];
    raf[..16].copy_from_slice(b"FUJIFILMCCD-RAW ");
    raf[84..88].copy_from_slice(&1000u32.to_be_bytes());
    raf[88..92].copy_from_slice(&5000u32.to_be_bytes());
    assert_eq!(raf_preview_range(&raf), Some((1000, 5000)));
    raf[88..92].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(raf_preview_range(&raf), None);

    // IFD0 at 8 points to a sub-IFD at 40 that gives the preview.
    let mut tiff = b"II*\x00\x08\x00\x00\x00".to_vec();
    tiff.extend_from_slice(&1u16.to_le_bytes());
    tiff.extend_from_slice(&tiff_entry(0x014a, 4, 1, 40));
    tiff.extend_from_slice(&[0u8; 4]);
    tiff.resize(40, 0);
    tiff.extend_from_slice(&2u16.to_le_bytes());
    tiff.extend_from_slice(&tiff_entry(0x0201, 4, 1, 4096));
    tiff.extend_from_slice(&tiff_entry(0x0202, 4, 1, 777));
    tiff.extend_from_slice(&[0u8; 4]);
    assert_eq!(embedded_tiff_jpeg_range(&tiff), Some((4096, 777)));
}

// --- Audio ------------------------------------------------------------------------------------------------------

#[test]
fn id3_text_frames_decode_each_encoding() {
    assert_eq!(decode_id3_text(b"\x00Caf\xe9 "), "Café");
    assert_eq!(decode_id3_text(b"\x01\xff\xfeH\x00i\x00"), "H");
    assert_eq!(decode_id3_text(b"\x01\xfe\xff\x00H\x00i"), "Hi");
    // The reader removes the NUL bytes at the two ends before the decode: a big-endian text without a mark loses its
    // first byte.
    assert_eq!(decode_id3_text(b"\x02\x00H\x00i"), "\u{4800}");
    assert_eq!(decode_id3_text(b"\x03Hello\x00"), "Hello");
    assert_eq!(decode_id3_text(b"\x03"), "");
}

#[test]
fn mpeg_frames_give_the_rates_and_the_channels() {
    assert_eq!(find_mp3_frame(&[0xff, 0xfb, 0x90, 0x00], 0), (128_000, 44_100, 2));
    // MPEG-2 layer III: half of the bit rate of the table and half of the sample rate, mono.
    assert_eq!(find_mp3_frame(&[0x00, 0xff, 0xf3, 0x80, 0xc0], 0), (56_000, 22_050, 1));
    assert_eq!(find_mp3_frame(&[0xff, 0xfb, 0xf0, 0x00], 0), (0, 0, 0));
}

#[test]
fn wav_files_give_the_format_the_info_list_and_the_duration() {
    let metadata = parse_wav_metadata(&synthetic_wav(176_400));
    assert_eq!(metadata.codecs, ["pcm"]);
    assert_eq!(metadata.duration_seconds, 1.0);
    assert_eq!(metadata.properties.get("Channels").map(String::as_str), Some("2"));
    assert_eq!(
        metadata.properties.get("Sample rate").map(String::as_str),
        Some("44.1 kHz")
    );
    assert_eq!(metadata.properties.get("Bit depth").map(String::as_str), Some("16-bit"));
    assert_eq!(metadata.properties.get("Title").map(String::as_str), Some("Song"));
    let mut cut = synthetic_wav(176_400);
    cut.truncate(cut.len() - 100);
    assert_eq!(
        parse_wav_metadata(&cut).duration_seconds,
        0.0,
        "the data chunk must be complete"
    );
}

#[test]
fn flac_files_give_streaminfo_and_the_vorbis_comments() {
    let metadata = parse_flac_metadata(&synthetic_flac());
    assert_eq!(metadata.codecs, ["flac"]);
    assert_eq!(metadata.duration_seconds, 10.0);
    let property = |name: &str| metadata.properties.get(name).cloned().unwrap_or_default();
    assert_eq!(property("Sample rate"), "44.1 kHz");
    assert_eq!(property("Channels"), "2");
    assert_eq!(property("Bit depth"), "16-bit");
    assert_eq!(property("Title"), "Tune");
    assert_eq!(property("Artist"), "Band");
    // A field without a label sets the property with the empty label.
    assert_eq!(property(""), "bar");
}

#[test]
fn the_last_ogg_page_gives_the_granule_position() {
    assert_eq!(last_ogg_granule(&synthetic_opus()), Some(96_000));
    assert_eq!(last_ogg_granule(b"OggS"), None);
}

// --- ISO base media and Matroska --------------------------------------------------------------------------------

#[test]
fn iso_metadata_gives_the_duration_the_dimensions_the_codecs_and_the_tracks() {
    let data = test_mp4_metadata_object();
    let moov = &data[data.len() - (data.len() - 24 - (8 + (256 << 10)))..];
    let (width, height, duration, codecs) = parse_iso_base_media(&[moov]);
    assert_eq!((width, height, duration), (1920, 1080, 12.5));
    assert_eq!(codecs, ["avc1", "mp4a"]);
    let tracks = parse_iso_tracks(moov).unwrap();
    assert_eq!(tracks.len(), 2);
    assert_eq!(
        (
            tracks[0].kind.as_str(),
            tracks[0].codec.as_str(),
            tracks[0].width,
            tracks[0].height
        ),
        ("video", "avc1", 1920, 1080)
    );
    assert_eq!(
        (
            tracks[1].kind.as_str(),
            tracks[1].index,
            tracks[1].channels,
            tracks[1].sample_rate
        ),
        ("audio", 1, 2, 48_000)
    );
    assert!(parse_iso_tracks(&iso_box("free", b"")).is_none());

    let mut version1 = vec![1u8; 32];
    version1[20..24].copy_from_slice(&600u32.to_be_bytes());
    version1[24..32].copy_from_slice(&1200u64.to_be_bytes());
    assert_eq!(parse_mvhd_duration(&version1), 2.0);
    let mut mdhd = vec![0u8; 24];
    // "eng": e=5, n=14, g=7.
    mdhd[20..22].copy_from_slice(&((5u16 << 10) | (14 << 5) | 7).to_be_bytes());
    assert_eq!(parse_mdhd_language(&mdhd), "eng");
}

#[test]
fn matroska_headers_give_the_tracks_and_the_duration() {
    let data = synthetic_webm();
    let (metadata, complete, valid) = parse_matroska_header(&data);
    assert!(complete && valid);
    assert_eq!((metadata.width, metadata.height), (1280, 720));
    assert_eq!(metadata.duration_seconds, 5.0);
    assert_eq!(metadata.codecs, ["V_VP9", "A_OPUS"]);
    assert_eq!(metadata.properties.get("Title").map(String::as_str), Some("Clip"));
    assert_eq!(
        metadata.properties.get("Muxing application").map(String::as_str),
        Some("muxer 1")
    );
    assert_eq!(metadata.tracks.len(), 2);
    assert!(metadata.tracks[0].default);
    assert_eq!(metadata.tracks[1].language, "eng");
    assert_eq!(
        (metadata.tracks[1].sample_rate, metadata.tracks[1].channels),
        (48_000, 2)
    );

    let (_, complete, valid) = parse_matroska_header(&data[..60]);
    assert!(!complete && valid);
    assert!(!parse_matroska_header(b"RIFF....").2);
    assert_eq!(
        read_ebml_vint(&[0x1a, 0x45, 0xdf, 0xa3], 0, true),
        Some((0x1a45_dfa3, 4, false))
    );
    assert_eq!(read_ebml_vint(&[0xff], 0, false), Some((0x7f, 1, true)));
    assert_eq!(read_ebml_vint(&[0x00, 0x01], 0, false), None);
}

// --- Routes over the formats ------------------------------------------------------------------------------------

#[tokio::test]
async fn the_details_of_a_webm_file_list_its_tracks() {
    let backend = memory();
    backend.insert("tenant/clip.webm", synthetic_webm(), "video/webm");
    let app = test_app(backend.clone());
    let response = request_media_info(&app, "clip.webm").await;
    assert_eq!(response["container"], "WEBM");
    assert_eq!(response["durationSeconds"], json!(5));
    assert_eq!(response["codecs"], json!(["V_VP9", "A_OPUS"]));
    assert_eq!(response["tracks"][0]["default"], json!(true));
    assert_eq!(response["tracks"][1]["sampleRate"], json!(48000));
    assert_eq!(response["properties"]["Title"], "Clip");
    assert_eq!(read_counts(&backend).2, ["bytes=0-1048575"]);
}

#[tokio::test]
async fn a_truncated_matroska_header_ends_at_the_end_of_the_object() {
    let backend = memory();
    let mut data = synthetic_webm();
    data.truncate(60);
    backend.insert("tenant/cut.mkv", data, "video/x-matroska");
    let app = test_app(backend.clone());
    let response = request_media_info(&app, "cut.mkv").await;
    assert_eq!(response["container"], "MKV");
    assert_eq!(read_counts(&backend).0, 1);
}

#[tokio::test]
async fn a_truncated_jpeg_header_ends_at_the_end_of_the_object() {
    let backend = memory();
    backend.insert(
        "tenant/cut.jpg",
        vec![0xff, 0xd8, 0xff, 0xe1, 0x40, 0x00, 1, 2, 3],
        "image/jpeg",
    );
    let app = test_app(backend.clone());
    let response = request_media_info(&app, "cut.jpg").await;
    assert_eq!(response["container"], "JPEG");
    assert!(response.get("width").is_none());
    assert_eq!(read_counts(&backend).0, 1);
}

#[tokio::test]
async fn the_details_of_audio_files_read_their_metadata_blocks() {
    let backend = memory();
    backend.insert("tenant/song.wav", synthetic_wav(1 << 20), "audio/wav");
    backend.insert("tenant/tune.flac", synthetic_flac(), "audio/flac");
    backend.insert("tenant/voice.opus", synthetic_opus(), "audio/ogg");
    backend.insert("tenant/song.mp3", synthetic_id3_mp3(), "audio/mpeg");
    let app = test_app(backend.clone());

    let wav = request_media_info(&app, "song.wav").await;
    assert_eq!(wav["container"], "WAV");
    assert_eq!(wav["codecs"], json!(["pcm"]));
    assert_eq!(wav["properties"]["Title"], "Song");
    assert!(
        wav.get("durationSeconds").is_none(),
        "the data chunk is not read: {wav}"
    );
    let flac = request_media_info(&app, "tune.flac").await;
    assert_eq!(flac["durationSeconds"], json!(10));
    assert_eq!(flac["properties"][""], "bar");
    let opus = request_media_info(&app, "voice.opus").await;
    assert_eq!(opus["codecs"], json!(["opus"]));
    assert_eq!(opus["properties"]["Channels"], "2");
    assert_eq!(opus["durationSeconds"], json!(2));
    let mp3 = request_media_info(&app, "song.mp3").await;
    assert_eq!(mp3["properties"]["Title"], "Example song");
    let size = synthetic_id3_mp3().len() as f64;
    assert_eq!(mp3["durationSeconds"].as_f64(), Some(size * 8.0 / 128_000.0));
}

#[tokio::test]
async fn the_details_of_a_png_keep_its_text_and_exif_chunks() {
    let mut png = synthetic_png(16, 16);
    let iend = png.split_off(33);
    let chunk = |kind: &[u8], payload: &[u8]| {
        let mut out = (payload.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(payload);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out
    };
    png.extend_from_slice(&chunk(b"tEXt", b"Title\x00Sunset"));
    png.extend_from_slice(&chunk(b"iTXt", b"Author\x00\x00\x00en\x00\x00Me"));
    png.extend_from_slice(&chunk(b"eXIf", &synthetic_tiff_with_exif_and_gps()));
    png.extend_from_slice(&iend);
    let backend = memory();
    backend.insert("tenant/photo.png", png, "image/png");
    let app = test_app(backend);
    let response = request_media_info(&app, "photo.png").await;
    assert_eq!(response["properties"]["Title"], "Sunset");
    assert!(response["properties"].get("Author").is_none(), "{response}");
    assert_eq!(response["properties"]["Camera model"], "EOS R5");
    assert_eq!(number(&response, "width"), 4000, "EXIF dimensions replace IHDR");
}

#[tokio::test]
async fn a_png_chunk_above_the_limit_is_refused() {
    let mut png = synthetic_png(16, 16);
    png[33..37].copy_from_slice(&0x9000_0000u32.to_be_bytes());
    let backend = memory();
    backend.insert("tenant/huge.png", png, "image/png");
    let app = test_app(backend);
    let called = call(&app, "GET", "/api/media-info?instance=rw&key=huge.png").await;
    assert_eq!(called.status, 422);
    assert_eq!(called.json()["error"]["code"], "image_metadata_too_large");
    assert_eq!(
        called.json()["error"]["message"],
        "the PNG metadata chunk is too large to inspect safely"
    );
}

#[tokio::test]
async fn the_details_of_a_heif_image_read_its_spatial_extents() {
    let mut ispe = vec![0u8; 12];
    ispe[4..8].copy_from_slice(&4032u32.to_be_bytes());
    ispe[8..12].copy_from_slice(&3024u32.to_be_bytes());
    let meta = iso_box(
        "meta",
        &[vec![0u8; 4], iso_box("iprp", &iso_box("ipco", &iso_box("ispe", &ispe)))].concat(),
    );
    let data = [
        iso_box("ftyp", b"heic\x00\x00\x00\x00mif1heic"),
        meta,
        iso_box("mdat", &[0u8; 64]),
    ]
    .concat();
    let backend = memory();
    backend.insert("tenant/photo.heic", data, "image/heic");
    let app = test_app(backend);
    let response = request_media_info(&app, "photo.heic").await;
    assert_eq!((number(&response, "width"), number(&response, "height")), (4032, 3024));
    assert_eq!(response["container"], "HEIC");
}

#[tokio::test]
async fn the_details_of_a_jpeg_2000_file_read_its_header_box() {
    let mut ihdr = vec![0u8; 14];
    ihdr[..4].copy_from_slice(&600u32.to_be_bytes());
    ihdr[4..8].copy_from_slice(&800u32.to_be_bytes());
    let data = [
        iso_box("jP  ", &[0x0d, 0x0a, 0x87, 0x0a]),
        iso_box("ftyp", b"jp2 \x00\x00\x00\x00jp2 "),
        iso_box("jp2h", &iso_box("ihdr", &ihdr)),
        iso_box("jp2c", &[0xff, 0x4f]),
    ]
    .concat();
    let backend = memory();
    backend.insert("tenant/scan.jp2", data, "image/jp2");
    let app = test_app(backend);
    let response = request_media_info(&app, "scan.jp2").await;
    assert_eq!((number(&response, "width"), number(&response, "height")), (800, 600));
}

#[tokio::test]
async fn the_tiff_reader_asks_only_for_the_declared_structures() {
    // IFD0 at 100000, the make and the model at 150000 and 150010: one request for the two values.
    let mut data = vec![0u8; 200_000];
    data[..8].copy_from_slice(b"II*\x00\xa0\x86\x01\x00");
    let ifd = 100_000;
    data[ifd..ifd + 2].copy_from_slice(&2u16.to_le_bytes());
    data[ifd + 2..ifd + 14].copy_from_slice(&tiff_entry(0x010f, 2, 6, 150_000));
    data[ifd + 14..ifd + 26].copy_from_slice(&tiff_entry(0x0110, 2, 7, 150_010));
    data[150_000..150_006].copy_from_slice(b"Canon\x00");
    data[150_010..150_017].copy_from_slice(b"EOS R5\x00");
    let backend = memory();
    backend.insert("tenant/photo.tif", data, "image/tiff");
    let app = test_app(backend.clone());
    let response = request_media_info(&app, "photo.tif").await;
    assert_eq!(response["properties"]["Camera make"], "Canon");
    assert_eq!(response["properties"]["Camera model"], "EOS R5");
    assert_eq!(response["container"], "TIFF");
    assert_eq!(
        read_counts(&backend).2,
        [
            "bytes=0-65535",
            "bytes=100000-100001",
            "bytes=100002-100029",
            "bytes=150000-150016"
        ]
    );
}

#[tokio::test]
async fn a_tiff_table_with_too_many_entries_is_refused() {
    let mut data = b"II*\x00\x08\x00\x00\x00".to_vec();
    data.extend_from_slice(&5000u16.to_le_bytes());
    data.resize(1024, 0);
    let backend = memory();
    backend.insert("tenant/bad.tif", data, "image/tiff");
    let app = test_app(backend);
    let called = call(&app, "GET", "/api/media-info?instance=rw&key=bad.tif").await;
    assert_eq!(called.status, 422);
    assert_eq!(called.json()["error"]["code"], "invalid_image_metadata");
}

#[tokio::test]
async fn the_details_of_svg_and_pnm_images_read_a_growing_prefix() {
    let mut svg = b"<?xml version=\"1.0\"?>\n<!-- ".to_vec();
    svg.extend_from_slice(&vec![b'x'; 6000]);
    svg.extend_from_slice(b" -->\n<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"48\" height=\"24\"></svg>");
    let size = svg.len();
    let backend = memory();
    // An `.svg` key gets the details of a text: a key without extension and the media type of the listing reach the
    // reader of SVG.
    backend.insert("tenant/icon", svg, "image/svg+xml");
    backend.insert(
        "tenant/two.ppm",
        b"P6\n2 1\n255\n\xff\x00\x00\x00\xff\x00".to_vec(),
        "image/x-portable-pixmap",
    );
    let app = test_app(backend.clone());
    let called = call(
        &app,
        "GET",
        "/api/media-info?instance=rw&key=icon&mime=image%2Fsvg%2Bxml",
    )
    .await;
    let response = called.json();
    assert_eq!(
        (number(&response, "width"), number(&response, "height")),
        (48, 24),
        "{response}"
    );
    assert!(response.get("container").is_none(), "{response}");
    assert_eq!(
        read_counts(&backend).2,
        ["bytes=0-4095".to_owned(), format!("bytes=4096-{}", size - 1)]
    );
    let response = request_media_info(&app, "two.ppm").await;
    assert_eq!((number(&response, "width"), number(&response, "height")), (2, 1));
}

#[tokio::test]
async fn the_details_of_a_webp_image_keep_its_exif_and_xmp() {
    let chunk = |kind: &[u8], payload: &[u8]| {
        let mut out = kind.to_vec();
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        if payload.len() % 2 == 1 {
            out.push(0);
        }
        out
    };
    let mut vp8x = vec![0u8; 10];
    vp8x[4..7].copy_from_slice(&[0x3f, 0x00, 0x00]);
    vp8x[7..10].copy_from_slice(&[0x1f, 0x00, 0x00]);
    let body = [
        b"WEBP".to_vec(),
        chunk(b"VP8X", &vp8x),
        chunk(b"EXIF", &synthetic_tiff_with_exif_and_gps()),
        chunk(b"XMP ", b"  <x:xmpmeta/>  "),
    ]
    .concat();
    let mut data = b"RIFF".to_vec();
    data.extend_from_slice(&(body.len() as u32).to_le_bytes());
    data.extend_from_slice(&body);
    let backend = memory();
    backend.insert("tenant/photo.webp", data, "image/webp");
    let app = test_app(backend);
    let response = request_media_info(&app, "photo.webp").await;
    assert_eq!(response["properties"]["XMP"], "<x:xmpmeta/>");
    assert_eq!(response["properties"]["Lens"], "RF50mm F1.2");
    assert_eq!(number(&response, "width"), 4000);
}

#[tokio::test]
async fn other_media_extensions_read_a_bounded_prefix() {
    let backend = memory();
    backend.insert("tenant/movie.avi", vec![0u8; 100_000], "video/x-msvideo");
    let app = test_app(backend.clone());
    let response = request_media_info(&app, "movie.avi").await;
    assert_eq!(response["container"], "AVI");
    assert_eq!(number(&response, "size"), 100_000);
    assert_eq!(read_counts(&backend).2, ["bytes=0-65535"]);
}

#[test]
fn the_search_of_bytes_finds_the_first_occurrence() {
    use super::text::find;
    assert_eq!(find(b"abcabc", b"bc"), Some(1));
    assert_eq!(find(b"abcabc", b"c"), Some(2));
    assert_eq!(find(b"abcabc", b""), Some(0));
    assert_eq!(find(b"ab", b"abc"), None);
    assert_eq!(find(b"aab", b"ab"), Some(1));
    assert_eq!(find(b"xyz", b"yz"), Some(1));
    assert_eq!(find(b"xyz", b"za"), None);
}
