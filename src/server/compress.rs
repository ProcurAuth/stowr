// SPDX-License-Identifier: MIT OR Apache-2.0
//! The gzip of the answers: the check of `Accept-Encoding`, the media types of the interface that gzip makes smaller,
//! and the gzip of the large JSON answers of the API.

use std::io::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use flate2::Compression;
use flate2::write::GzEncoder;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HeaderValue, VARY};
use http::{HeaderMap, Method};
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;

use crate::common::error::{Error, Result};
use crate::common::http::{Body, Response};

/// The smallest JSON body that gets gzip: under it, the gzip header and the work cost more than they save.
pub const GZIP_JSON_MIN_BYTES: usize = 1024;

/// The largest part of a body that one step of the gzip encoder reads, so that one step stays short.
const GZIP_STEP: usize = 64 << 10;

/// True for a media type of the interface that gzip makes smaller.
pub fn compressible_content_type(content_type: &str) -> bool {
    matches!(
        super::mediatype::base_media_type(content_type).as_str(),
        "text/html" | "text/css" | "text/javascript" | "application/javascript" | "application/json" | "image/svg+xml"
    )
}

/// True when the first `Accept-Encoding` header lets gzip (`gzip;q=0` refuses it).
pub fn accepts_gzip(headers: &HeaderMap) -> bool {
    let value = headers
        .get(http::header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    for part in value.split(',') {
        let mut fields = part.split(';');
        if !fields.next().unwrap_or("").trim().eq_ignore_ascii_case("gzip") {
            continue;
        }
        for param in fields {
            let (name, weight) = param.trim().split_once('=').unwrap_or((param.trim(), ""));
            if name.eq_ignore_ascii_case("q")
                && let Ok(weight) = weight.trim().parse::<f64>()
                && weight <= 0.0
            {
                return false;
            }
        }
        return true;
    }
    false
}

/// True when the gzip of the JSON answers applies to a request: a path of the API, not `HEAD`, and gzip accepted.
pub fn gzip_json_applies(path: &str, method: &Method, headers: &HeaderMap) -> bool {
    path.starts_with("/api/") && *method != Method::HEAD && accepts_gzip(headers)
}

/// Apply the gzip of the JSON answers to an answer. Only a JSON answer with a body of at least 1024 bytes changes: it
/// gets `Content-Encoding: gzip`, `Vary: Accept-Encoding` and no `Content-Length`. Each other answer stays as it is.
pub async fn gzip_json(response: Response) -> Response {
    let status = response.status().as_u16();
    let headers = response.headers();
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if status < 200
        || status == 204
        || status == 304
        || headers.get(CONTENT_ENCODING).is_some_and(|value| !value.is_empty())
        || headers.get(CONTENT_RANGE).is_some_and(|value| !value.is_empty())
        || !content_type.starts_with("application/json")
    {
        return response;
    }
    let (mut parts, mut body) = response.into_parts();
    // Read the body until it reaches the threshold or ends.
    let mut head = BytesMut::new();
    let mut trailers = None;
    let mut failed = None;
    let mut ended = false;
    while head.len() < GZIP_JSON_MIN_BYTES {
        match body.frame().await {
            None => {
                ended = true;
                break;
            }
            Some(Err(error)) => {
                failed = Some(error);
                break;
            }
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => head.extend_from_slice(&data),
                Err(frame) => {
                    trailers = frame.into_trailers().ok();
                    ended = true;
                    break;
                }
            },
        }
    }
    if head.len() < GZIP_JSON_MIN_BYTES {
        // A short body stays plain.
        let replay = Replay {
            head: Some(head.freeze()).filter(|data| !data.is_empty()),
            error: failed,
            trailers,
            rest: if ended { None } else { Some(body) },
        };
        return http::Response::from_parts(parts, replay.boxed_unsync());
    }
    parts.headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    parts.headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
    parts.headers.remove(CONTENT_LENGTH);
    let gzip = GzipBody {
        encoder: Some(GzEncoder::new(Vec::new(), Compression::fast())),
        pending: head.freeze(),
        rest: if ended || failed.is_some() { None } else { Some(body) },
        error: failed,
        trailers,
        finished: false,
    };
    http::Response::from_parts(parts, gzip.boxed_unsync())
}

/// A body that sends the bytes that a step read, then the rest of the body.
struct Replay {
    head: Option<Bytes>,
    error: Option<Error>,
    trailers: Option<HeaderMap>,
    rest: Option<Body>,
}

impl http_body::Body for Replay {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        if let Some(head) = self.head.take() {
            return Poll::Ready(Some(Ok(Frame::data(head))));
        }
        if let Some(error) = self.error.take() {
            return Poll::Ready(Some(Err(error)));
        }
        if let Some(rest) = self.rest.as_mut() {
            return Pin::new(rest).poll_frame(cx);
        }
        Poll::Ready(self.trailers.take().map(|trailers| Ok(Frame::trailers(trailers))))
    }

    fn size_hint(&self) -> SizeHint {
        let head = self.head.as_ref().map_or(0, |head| head.len() as u64);
        match (&self.rest, &self.error, &self.trailers) {
            (None, None, None) => SizeHint::with_exact(head),
            _ => SizeHint::default(),
        }
    }
}

/// A body that compresses the bytes of another body, in steps of at most 64 KiB.
struct GzipBody {
    encoder: Option<GzEncoder<Vec<u8>>>,
    pending: Bytes,
    rest: Option<Body>,
    error: Option<Error>,
    trailers: Option<HeaderMap>,
    finished: bool,
}

impl GzipBody {
    fn take_output(&mut self) -> Option<Bytes> {
        let encoder = self.encoder.as_mut()?;
        let output = std::mem::take(encoder.get_mut());
        (!output.is_empty()).then(|| Bytes::from(output))
    }
}

impl http_body::Body for GzipBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        loop {
            if self.finished {
                return Poll::Ready(self.trailers.take().map(|trailers| Ok(Frame::trailers(trailers))));
            }
            if !self.pending.is_empty() {
                let step = self.pending.len().min(GZIP_STEP);
                let chunk = self.pending.split_to(step);
                if let Some(encoder) = self.encoder.as_mut()
                    && let Err(error) = encoder.write_all(&chunk)
                {
                    return Poll::Ready(Some(Err(Error::internal(format!("gzip error: {error}")))));
                }
                if let Some(output) = self.take_output() {
                    return Poll::Ready(Some(Ok(Frame::data(output))));
                }
                continue;
            }
            if let Some(error) = self.error.take() {
                return Poll::Ready(Some(Err(error)));
            }
            if let Some(rest) = self.rest.as_mut() {
                match Pin::new(rest).poll_frame(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                        Ok(data) => {
                            self.pending = data;
                            continue;
                        }
                        Err(frame) => {
                            self.trailers = frame.into_trailers().ok();
                            self.rest = None;
                            continue;
                        }
                    },
                    Poll::Ready(Some(Err(error))) => {
                        self.rest = None;
                        return Poll::Ready(Some(Err(error)));
                    }
                    Poll::Ready(None) => {
                        self.rest = None;
                        continue;
                    }
                }
            }
            // The end: write the gzip trailer.
            self.finished = true;
            if let Some(encoder) = self.encoder.take() {
                match encoder.finish() {
                    Ok(output) if !output.is_empty() => return Poll::Ready(Some(Ok(Frame::data(Bytes::from(output))))),
                    Ok(_) => {}
                    Err(error) => return Poll::Ready(Some(Err(Error::internal(format!("gzip error: {error}"))))),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::ACCEPT_ENCODING, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn accept_encoding_rules() {
        assert!(accepts_gzip(&headers("br, gzip")));
        assert!(accepts_gzip(&headers("GZIP;q=0.5")));
        assert!(!accepts_gzip(&headers("gzip;q=0, identity")));
        assert!(!accepts_gzip(&headers("identity")));
        assert!(!accepts_gzip(&HeaderMap::new()));
        assert!(compressible_content_type("text/css; charset=utf-8"));
        assert!(compressible_content_type("image/svg+xml"));
        assert!(!compressible_content_type("image/png"));
    }
}
