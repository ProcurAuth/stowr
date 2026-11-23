//! The S3 requests of the list of the incomplete multipart uploads: `ListMultipartUploads` and `ListParts`.
//!
//! The list never sends a prefix to the provider: MinIO gives an empty list for a prefix that is not a full key. The
//! server keeps the uploads under the root prefix of the instance and under the prefix of the request. Each page of
//! the provider continues with the markers that the provider sent: SeaweedFS sends `NextUploadIdMarker` only, Garage
//! and AWS send both markers, and MinIO sends all the uploads in one page.

use http::{HeaderMap, Method};
use quick_xml::Reader;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;

use super::{MultipartCursor, MultipartPartsSummary, MultipartUpload, MultipartUploadLister, MultipartUploadPage};
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::time::Timestamp;
use crate::provider::S3Backend;
use crate::provider::s3::S3Request;

/// The largest answer of `ListMultipartUploads` that the server reads: 32 MiB.
const MAXIMUM_UPLOADS_ANSWER: usize = 32 << 20;
/// The largest answer of `ListParts` that the server reads: 8 MiB.
const MAXIMUM_PARTS_ANSWER: usize = 8 << 20;

/// The request `ListMultipartUploads` for a page: the query pairs are in the order of their names.
pub fn list_uploads_query(cursor: &MultipartCursor, maximum: u32) -> Vec<(String, String)> {
    let mut query = Vec::with_capacity(4);
    if !cursor.key_marker.is_empty() {
        query.push(("key-marker".to_owned(), cursor.key_marker.clone()));
    }
    if maximum > 0 {
        query.push(("max-uploads".to_owned(), maximum.to_string()));
    }
    if !cursor.upload_id_marker.is_empty() {
        query.push(("upload-id-marker".to_owned(), cursor.upload_id_marker.clone()));
    }
    query.push(("uploads".to_owned(), String::new()));
    query
}

/// The request `ListParts` for the first page of the parts of an upload.
pub fn list_parts_query(upload_id: &str, maximum: u32) -> Vec<(String, String)> {
    vec![
        ("max-parts".to_owned(), maximum.to_string()),
        ("uploadId".to_owned(), upload_id.to_owned()),
    ]
}

fn decode_error(what: &str, detail: &str) -> Error {
    Error::internal(format!("decode s3 multipart {what} response: {detail}"))
}

/// Read an XML text and give, for each element that has no child element, the names of the open elements and the text.
/// An entity that is not predefined and a text that is not complete are errors.
fn each_leaf(body: &[u8], what: &str, mut leaf: impl FnMut(&[String], &str)) -> Result<()> {
    let text = std::str::from_utf8(body).map_err(|error| decode_error(what, &error.to_string()))?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().expand_empty_elements = true;
    let mut path: Vec<String> = Vec::new();
    let mut content = String::new();
    let mut started = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| decode_error(what, &error.to_string()))?;
        match event {
            Event::Start(start) => {
                started = true;
                let local = start.local_name();
                let name: &str = local.as_ref();
                path.push(name.to_owned());
                content.clear();
            }
            Event::End(_) => {
                leaf(&path, &content);
                path.pop();
                content.clear();
            }
            Event::Text(text) => content.push_str(&text.xml10_content()),
            Event::CData(data) => content.push_str(&data),
            Event::GeneralRef(reference) => {
                if let Some(character) = reference
                    .resolve_char_ref()
                    .map_err(|error| decode_error(what, &error.to_string()))?
                {
                    content.push(character);
                } else if let Some(replacement) = resolve_predefined_entity(&reference) {
                    content.push_str(replacement);
                } else {
                    return Err(decode_error(
                        what,
                        &format!("invalid character entity &{};", &*reference),
                    ));
                }
            }
            Event::Eof => {
                if !started {
                    return Err(decode_error(what, "EOF"));
                }
                if path.is_empty() {
                    return Ok(());
                }
                return Err(decode_error(what, "unexpected EOF"));
            }
            _ => {}
        }
    }
}

/// The boolean of the text of an element: `true`, `false`, `1`, `0` and their short forms.
fn parse_bool(text: &str) -> Option<bool> {
    match text.trim() {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Read the answer of `ListMultipartUploads`.
pub fn parse_list_uploads(body: &[u8]) -> Result<MultipartUploadPage> {
    let mut truncated = false;
    let mut bad_flag = false;
    let mut next = MultipartCursor::default();
    let mut uploads: Vec<(String, String, String)> = Vec::new();
    let mut current = (String::new(), String::new(), String::new());
    each_leaf(body, "uploads", |path, text| match path {
        [_, name] => match name.as_str() {
            "IsTruncated" => match parse_bool(text) {
                Some(value) => truncated = value,
                None => bad_flag = true,
            },
            "NextKeyMarker" => next.key_marker = text.to_owned(),
            "NextUploadIdMarker" => next.upload_id_marker = text.to_owned(),
            "Upload" => uploads.push(std::mem::take(&mut current)),
            _ => {}
        },
        [_, group, field] if group == "Upload" => match field.as_str() {
            "Key" => current.0 = text.to_owned(),
            "UploadId" => current.1 = text.to_owned(),
            "Initiated" => current.2 = text.to_owned(),
            _ => {}
        },
        _ => {}
    })?;
    if bad_flag {
        return Err(decode_error("uploads", "IsTruncated is not a boolean"));
    }
    let uploads = uploads
        .into_iter()
        .map(|(key, upload_id, initiated)| MultipartUpload {
            key,
            upload_id,
            initiated: Timestamp::parse_rfc3339(initiated.trim()).map(Timestamp::utc),
        })
        .collect();
    Ok(MultipartUploadPage {
        uploads,
        next: truncated.then_some(next),
    })
}

/// Read the answer of `ListParts`: the count and the bytes of the parts, and whether the list has more parts.
pub fn parse_list_parts(body: &[u8]) -> Result<(u32, i64, bool)> {
    let mut truncated = false;
    let mut bad = false;
    let mut parts: u32 = 0;
    let mut bytes: i64 = 0;
    let mut size: i64 = 0;
    each_leaf(body, "parts", |path, text| match path {
        [_, name] => match name.as_str() {
            "IsTruncated" => match parse_bool(text) {
                Some(value) => truncated = value,
                None => bad = true,
            },
            "Part" => {
                parts += 1;
                bytes = bytes.saturating_add(std::mem::take(&mut size));
            }
            _ => {}
        },
        [_, group, field] if group == "Part" && field == "Size" => {
            let trimmed = text.trim();
            match if trimmed.is_empty() {
                Ok(0)
            } else {
                trimmed.parse::<i64>()
            } {
                Ok(value) => size = value,
                Err(_) => bad = true,
            }
        }
        _ => {}
    })?;
    if bad {
        return Err(decode_error("parts", "a value is not valid"));
    }
    Ok((parts, bytes, truncated))
}

fn check_status(answer: &crate::provider::s3::S3Answer) -> Result<()> {
    if (200..300).contains(&answer.status) {
        Ok(())
    } else {
        Err(S3Backend::s3_error(answer))
    }
}

impl MultipartUploadLister for S3Backend {
    fn list_uploads<'a>(
        &'a self,
        ctx: &'a OpCtx,
        cursor: &'a MultipartCursor,
        maximum: u32,
    ) -> BoxFuture<'a, Result<MultipartUploadPage>> {
        Box::pin(async move {
            let request = S3Request {
                method: Method::GET,
                key: "",
                query: list_uploads_query(cursor, maximum),
                headers: HeaderMap::new(),
                body: None,
            };
            let answer = self.send(ctx, request, MAXIMUM_UPLOADS_ANSWER).await?;
            check_status(&answer)?;
            parse_list_uploads(&answer.body)
        })
    }

    fn upload_parts<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        maximum: u32,
    ) -> BoxFuture<'a, Result<MultipartPartsSummary>> {
        Box::pin(async move {
            let request = S3Request {
                method: Method::GET,
                key,
                query: list_parts_query(upload_id, maximum),
                headers: HeaderMap::new(),
                body: None,
            };
            let answer = self.send(ctx, request, MAXIMUM_PARTS_ANSWER).await?;
            check_status(&answer)?;
            let (parts, bytes, truncated) = parse_list_parts(&answer.body)?;
            Ok(MultipartPartsSummary {
                parts,
                bytes,
                at_least: truncated,
                unknown: false,
            })
        })
    }
}
