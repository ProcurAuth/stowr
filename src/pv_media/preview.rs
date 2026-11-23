//! The route `/api/image-preview`: the JPEG preview that a camera puts in a RAW file. A Fujifilm RAF header or the
//! IFDs of a TIFF-based RAW file give the range of the preview; the route sends that range of the object. The route
//! never decodes an image.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HeaderName, HeaderValue, RANGE};
use http::{HeaderMap, Method};
use http_body::Frame;
use http_body_util::BodyExt;

use super::adaptive::{is_tiff_based_image, read_adaptive_tiff_header};
use super::details::key_extension;
use super::text::{lossy, parse_int};
use super::tiff::{embedded_tiff_jpeg_range, raf_preview_range};
use crate::access;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::PERMISSION_READ;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, Req, Response, answer, api_error, empty, method_not_allowed};
use crate::common::misc::clean_relative_key;
use crate::instance::Instance;
use crate::instance::ops::is_successful_read_status;
use crate::instance::range::RangeSource;
use crate::server::gateway::apply_object_safety_headers;

/// The largest embedded preview that the route sends: 128 MiB.
pub const MAX_EMBEDDED_IMAGE_PREVIEW_BYTES: i64 = 128 << 20;

/// The handler of `/api/image-preview` (`GET` or `HEAD`, permission read): the embedded JPEG preview of a RAF or
/// TIFF-based RAW file. Another file gets `501 embedded_image_preview_unavailable`.
pub fn handle_image_preview(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move { image_preview(app, req).await.unwrap_or_else(|error| api_error(&error)) })
}

async fn image_preview(app: Arc<App>, req: Req) -> Result<Response> {
    if req.method != Method::GET && req.method != Method::HEAD {
        return Ok(method_not_allowed(&["GET", "HEAD"]));
    }
    let instance = app.instance_of("", req.query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    let key = clean_relative_key(req.query.get("key"));
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", "image key cannot be empty"));
    }
    access::authorize_read(&app, &req.ctx, &instance, &key).await?;
    let extension = key_extension(&key);
    let head = req.method == Method::HEAD;

    // A RAW file often holds a JPEG preview of the camera. The header gives its range: one more range request costs
    // much less than a download of the complete RAW file.
    if (extension == "raf" || is_tiff_based_image(&extension, ""))
        && let Ok(source) = RangeSource::open(&req.ctx, &instance, &key).await
    {
        if extension == "raf" {
            if let Ok(header) = source.read_range(0, 128).await
                && source.size_or_zero() > 0
                && let Some((offset, length)) = raf_preview_range(&header)
                && embedded_preview_fits_object(offset, length, source.size_or_zero())
            {
                return serve_embedded_image_range(&req.ctx, &instance, &key, offset, length, head).await;
            }
        } else if let Ok((header, true)) = read_adaptive_tiff_header(&source).await
            && source.size_or_zero() > 0
            && let Some((offset, length)) = embedded_tiff_jpeg_range(&header)
            && embedded_preview_fits_object(offset, length, source.size_or_zero())
        {
            return serve_embedded_image_range(&req.ctx, &instance, &key, offset, length, head).await;
        }
    }
    Err(Error::api(
        501,
        "embedded_image_preview_unavailable",
        "this self-contained build can preview this image only when the original is browser-readable or the file contains an embedded JPEG preview",
    ))
}

/// True when the range of a preview is inside the object and not larger than 128 MiB.
fn embedded_preview_fits_object(offset: i64, length: i64, object_size: i64) -> bool {
    offset >= 0
        && length > 0
        && length <= MAX_EMBEDDED_IMAGE_PREVIEW_BYTES
        && object_size > 0
        && offset <= object_size
        && length <= object_size - offset
}

fn range_not_supported(message: &str) -> Error {
    Error::api(502, "range_not_supported", message)
}

/// Send `length` bytes of the object from `offset` as a JPEG image. The function refuses a provider that sends the
/// complete object for the range: a small preview must not become a download of a large RAW file.
async fn serve_embedded_image_range(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    offset: i64,
    length: i64,
    head: bool,
) -> Result<Response> {
    if offset < 0 || length <= 0 || length > MAX_EMBEDDED_IMAGE_PREVIEW_BYTES {
        return Err(Error::api(
            422,
            "invalid_embedded_preview",
            "the embedded image preview range is invalid",
        ));
    }
    let mut request = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&format!("bytes={}-{}", offset, offset + length - 1)) {
        request.insert(RANGE, value);
    }
    let object = instance.get(ctx, &instance.full_key(key), &request).await?;
    if !is_successful_read_status(object.status) {
        return Err(Error::upstream(object.status, "ImagePreviewReadFailed", ""));
    }
    let text = |name: &HeaderName| {
        object
            .headers
            .get(name)
            .map(|value| lossy(value.as_bytes()).trim().to_owned())
            .unwrap_or_default()
    };
    let content_range = text(&CONTENT_RANGE);
    let content_length = parse_int(&text(&CONTENT_LENGTH));
    if object.status == 206 && content_range.is_empty() {
        return Err(range_not_supported(
            "the storage provider omitted Content-Range for the embedded image preview",
        ));
    }
    if object.status == 200 && content_range.is_empty() && (offset != 0 || content_length != Some(length)) {
        return Err(range_not_supported(
            "the storage provider ignored the embedded image preview range",
        ));
    }
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
    if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
        headers.insert(CONTENT_LENGTH, value);
    }
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    apply_object_safety_headers(&mut headers);
    if head {
        return Ok(answer(200, headers, empty()));
    }
    let body = LimitedBody {
        inner: Some(object.body),
        remaining: length as u64,
    }
    .boxed_unsync();
    Ok(answer(200, headers, body))
}

/// A body that gives at most `remaining` bytes of another body, then ends. The other body (and its slot of the
/// gates) goes away at the end.
struct LimitedBody {
    inner: Option<Body>,
    remaining: u64,
}

impl http_body::Body for LimitedBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        loop {
            if self.remaining == 0 {
                self.inner = None;
                return Poll::Ready(None);
            }
            let Some(inner) = self.inner.as_mut() else {
                return Poll::Ready(None);
            };
            match Pin::new(inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.inner = None;
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(error))),
                Poll::Ready(Some(Ok(frame))) => {
                    let Ok(mut data) = frame.into_data() else {
                        continue;
                    };
                    if data.len() as u64 > self.remaining {
                        data.truncate(self.remaining as usize);
                    }
                    self.remaining -= data.len() as u64;
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
            }
        }
    }
}
