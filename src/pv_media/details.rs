//! The route `/api/media-info`: the details of one object.
//!
//! The readers of the documents get the request first. A media key then gets the reader of its format over byte
//! ranges; another key gets one HEAD request. A refusal for a key of the client (SSE-C) is not an error: the answer
//! tells that the object has such a key.

use std::collections::BTreeMap;
use std::sync::Arc;

use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Method};

use super::adaptive::inspect_adaptive_metadata;
use super::text::{fold_lower, fold_upper, lossy, parse_int_saturating};
use super::{MediaInfoResponse, MediaSourceMetadata};
use crate::access;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::PERMISSION_READ;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, answer, api_error, empty, json, method_not_allowed};
use crate::common::misc::clean_relative_key;
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::range::RangeSource;
use crate::server::gateway::copy_object_headers;

/// A decimal integer of a query, or `fallback` for a text that is not an integer in range.
pub fn parse_int64_default(value: &str, fallback: i64) -> i64 {
    match parse_int_saturating(value.trim()) {
        (parsed, true) => parsed,
        _ => fallback,
    }
}

/// The text of the first value of a header, or an empty text.
fn header_value(headers: &HeaderMap, name: &http::header::HeaderName) -> String {
    headers
        .get(name)
        .map(|value| lossy(value.as_bytes()))
        .unwrap_or_default()
}

/// Fill the storage facts of an answer from the headers of a provider answer: the size (`known_size` when it is above
/// 0, else `Content-Length`), the media type without its parameters, and the object headers that the downloads copy,
/// by lower-case name (the values of one name joined with `, `).
pub fn populate_media_storage_fields(response: &mut MediaInfoResponse, headers: &HeaderMap, known_size: i64) {
    let mut known_size = known_size;
    if known_size <= 0 {
        known_size = parse_int_saturating(header_value(headers, &CONTENT_LENGTH).trim()).0;
    }
    response.size = known_size.max(0);
    response.mime = header_value(headers, &CONTENT_TYPE)
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    let mut filtered = HeaderMap::new();
    copy_object_headers(&mut filtered, headers);
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in &filtered {
        grouped
            .entry(name.as_str().to_owned())
            .or_default()
            .push(lossy(value.as_bytes()));
    }
    response.headers = grouped
        .into_iter()
        .map(|(name, values)| (name, values.join(", ")))
        .collect();
}

/// The container label of the details: the extension in upper case (with a few aliases), else a label for the usual
/// media types.
pub fn media_container(extension: &str, content_type: &str) -> String {
    if !extension.is_empty() {
        let alias = match extension {
            "jpg" | "jpeg" => "JPEG",
            "tif" | "tiff" => "TIFF",
            "m4v" | "m4a" => "MP4",
            "qt" => "MOV",
            "wave" => "WAV",
            _ => return fold_upper(extension),
        };
        return alias.to_owned();
    }
    match content_type {
        "image/jpeg" => "JPEG",
        "image/png" => "PNG",
        "image/gif" => "GIF",
        "image/webp" => "WEBP",
        "video/mp4" | "audio/mp4" => "MP4",
        "video/quicktime" => "MOV",
        _ => "",
    }
    .to_owned()
}

/// True for a media type that a media reader can read: images, video, audio, Matroska, HEIF and AVIF.
fn content_type_may_contain_inspectable_metadata(content_type: &str) -> bool {
    let value = fold_lower(content_type.split(';').next().unwrap_or("").trim());
    value.starts_with("image/")
        || value.starts_with("video/")
        || value.starts_with("audio/")
        || value.contains("matroska")
        || value.contains("heif")
        || value.contains("avif")
}

/// True for an extension that a media reader can read.
pub fn extension_may_contain_inspectable_metadata(extension: &str) -> bool {
    matches!(
        fold_lower(extension).as_str(),
        "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "webp"
            | "bmp"
            | "dib"
            | "svg"
            | "avif"
            | "ico"
            | "cur"
            | "tif"
            | "tiff"
            | "heic"
            | "heif"
            | "jxl"
            | "jp2"
            | "j2k"
            | "jpf"
            | "jpx"
            | "jpc"
            | "psd"
            | "psb"
            | "tga"
            | "exr"
            | "hdr"
            | "rgbe"
            | "dds"
            | "pcx"
            | "pnm"
            | "ppm"
            | "pgm"
            | "pbm"
            | "pam"
            | "sgi"
            | "rgb"
            | "rgba"
            | "bw"
            | "qoi"
            | "ff"
            | "farbfeld"
            | "fits"
            | "fit"
            | "fts"
            | "raf"
            | "raw"
            | "dng"
            | "cr2"
            | "cr3"
            | "nef"
            | "nrw"
            | "arw"
            | "srf"
            | "sr2"
            | "orf"
            | "rw2"
            | "pef"
            | "x3f"
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
            | "mp4"
            | "mkv"
            | "webm"
            | "avi"
            | "mov"
            | "m4v"
            | "mpg"
            | "mpeg"
            | "flv"
            | "f4v"
            | "3gp"
            | "3g2"
            | "wmv"
            | "asf"
            | "ogv"
            | "mts"
            | "m2ts"
            | "ts"
            | "vob"
            | "mxf"
            | "dv"
            | "m2v"
            | "mp3"
            | "flac"
            | "wav"
            | "wave"
            | "m4a"
            | "aac"
            | "ogg"
            | "oga"
            | "opus"
            | "aiff"
            | "aif"
            | "alac"
            | "wma"
            | "amr"
            | "midi"
            | "mid"
            | "ape"
            | "wv"
            | "tta"
            | "ac3"
            | "eac3"
            | "dts"
            | "mka"
            | "au"
            | "caf"
    )
}

/// The extension of the last element of a key, with its dot, or an empty text.
pub(crate) fn file_extension(key: &str) -> &str {
    for (index, byte) in key.bytes().enumerate().rev() {
        match byte {
            b'/' => break,
            b'.' => return &key[index..],
            _ => {}
        }
    }
    ""
}

/// The lower-case extension of a key, without its dot.
pub(crate) fn key_extension(key: &str) -> String {
    let extension = file_extension(key);
    fold_lower(extension.strip_prefix('.').unwrap_or(extension))
}

/// The answer of the details. A duration that is not a finite number has no JSON form: that answer has the status
/// and the headers, and no body.
fn media_answer(response: &MediaInfoResponse) -> Response {
    if !response.duration_seconds.is_finite() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return answer(200, headers, empty());
    }
    json(200, response)
}

/// The details of an object that the provider refused to read because it has a key of the client, or `None` for any
/// other error.
async fn customer_key_details(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    error: &Error,
) -> Option<MediaInfoResponse> {
    let info = crate::bucket::customer_key_media_info(ctx, instance, key, error).await?;
    Some(MediaInfoResponse {
        instance: instance.cfg.id.clone(),
        key: key.to_owned(),
        size: info.size,
        headers: info.headers,
        customer_key: true,
        ..MediaInfoResponse::default()
    })
}

/// The answer of a failed read of the details. The refusal of an object with a key of the client is not an error.
async fn media_info_error(ctx: &OpCtx, instance: &Arc<Instance>, key: &str, error: Error) -> Response {
    match customer_key_details(ctx, instance, key, &error).await {
        Some(response) => media_answer(&response),
        None => api_error(&error),
    }
}

/// The details of a document (delimited text, JSON, Office Open XML, Parquet, SQLite, structured text, text), or
/// `None` when the readers of the documents do not handle the key.
async fn document_details(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    content_type: &str,
    listed: &MediaSourceMetadata,
) -> Result<Option<MediaInfoResponse>> {
    let details = crate::pv_data::inspect_document_details(ctx, instance, key, extension, content_type, listed).await?;
    // The pattern names each member of the details: a new member must get its place in the answer here.
    let crate::pv_data::DocumentDetails {
        container,
        properties,
        handled,
        headers,
        size,
    } = details;
    if !handled {
        return Ok(None);
    }
    let mut response = MediaInfoResponse {
        instance: instance.cfg.id.clone(),
        key: key.to_owned(),
        ..MediaInfoResponse::default()
    };
    populate_media_storage_fields(&mut response, &headers, size);
    response.container = container;
    response.properties = properties;
    Ok(Some(response))
}

/// The handler of `/api/media-info` (`GET`, permission read): the storage facts of an object and the facts that the
/// reader of its format finds. The query gives the key, and optionally the values of the listing: `size`, `mime`,
/// `etag` and `lastModified`.
pub fn handle_media_info(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move { media_info(app, req).await.unwrap_or_else(|error| api_error(&error)) })
}

async fn media_info(app: Arc<App>, req: Req) -> Result<Response> {
    if req.method != Method::GET {
        return Ok(method_not_allowed(&["GET"]));
    }
    let instance = app.instance_of("", req.query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    let key = clean_relative_key(req.query.get("key"));
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", "object key cannot be empty"));
    }
    access::authorize_read(&app, &req.ctx, &instance, &key).await?;
    let ctx = &req.ctx;

    let extension = key_extension(&key);
    let content_type_hint = req.query.get("mime").split(';').next().unwrap_or("").trim().to_owned();
    let last_modified = req.query.get("lastModified").trim();
    let listed = MediaSourceMetadata {
        size: parse_int64_default(req.query.get("size"), 0),
        etag: req.query.get("etag").trim().to_owned(),
        last_modified: Timestamp::parse_http_date(last_modified).or_else(|| Timestamp::parse_rfc3339(last_modified)),
        content_type: content_type_hint.clone(),
    };
    let mut response = MediaInfoResponse {
        instance: instance.cfg.id.clone(),
        key: key.clone(),
        ..MediaInfoResponse::default()
    };
    match document_details(ctx, &instance, &key, &extension, &content_type_hint, &listed).await {
        Ok(Some(document)) => return Ok(media_answer(&document)),
        Ok(None) => {}
        Err(error) => return Ok(media_info_error(ctx, &instance, &key, error).await),
    }

    if !extension_may_contain_inspectable_metadata(&extension)
        && !content_type_may_contain_inspectable_metadata(&content_type_hint)
    {
        return Ok(match instance.head(ctx, &instance.full_key(&key)).await {
            Ok(head) => {
                populate_media_storage_fields(&mut response, &head.headers, 0);
                media_answer(&response)
            }
            Err(error) => media_info_error(ctx, &instance, &key, error).await,
        });
    }

    let source = match RangeSource::open(ctx, &instance, &key).await {
        Ok(source) => source,
        Err(error) => return Ok(media_info_error(ctx, &instance, &key, error).await),
    };
    // The reader of the format makes the first range request: PNG reads its fixed header, JPEG, TIFF, ISO base media,
    // Matroska and the audio formats follow their declared lengths and offsets.
    let metadata = match inspect_adaptive_metadata(&source, &extension, &content_type_hint).await {
        Ok(metadata) => metadata,
        Err(error) => {
            // Some providers answer 416 to a range of an empty object: only that case gets a HEAD request. Another
            // range error stays an error, so that a later preview never becomes a silent download of the object.
            let unsatisfiable = error.as_upstream().is_some_and(|upstream| upstream.status == 416);
            if source.request_count() == 0
                && unsatisfiable
                && let Ok(head) = instance.head(ctx, &instance.full_key(&key)).await
            {
                populate_media_storage_fields(&mut response, &head.headers, 0);
                return Ok(media_answer(&response));
            }
            return Ok(media_info_error(ctx, &instance, &key, error).await);
        }
    };
    if source.request_count() == 0 {
        match instance.head(ctx, &instance.full_key(&key)).await {
            Ok(head) => populate_media_storage_fields(&mut response, &head.headers, 0),
            Err(error) => return Ok(media_info_error(ctx, &instance, &key, error).await),
        }
    } else {
        populate_media_storage_fields(&mut response, &source.headers(), source.size_or_zero());
    }
    response.container = media_container(&extension, &response.mime);
    response.width = metadata.width;
    response.height = metadata.height;
    response.duration_seconds = metadata.duration_seconds;
    response.codecs = metadata.codecs;
    response.tracks = metadata.tracks;
    response.properties = metadata.properties;
    Ok(media_answer(&response))
}
