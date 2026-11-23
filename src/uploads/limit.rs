// SPDX-License-Identifier: MIT OR Apache-2.0
//! A body that ends after a fixed number of bytes.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt as _;

use crate::common::error::{Error, Result};
use crate::common::http::Body;

struct Limited {
    inner: Body,
    remaining: u64,
}

impl HttpBody for Limited {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(mut data) => {
                    let room = usize::try_from(self.remaining).unwrap_or(usize::MAX);
                    if data.len() > room {
                        data.truncate(room);
                    }
                    self.remaining -= data.len() as u64;
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(frame) => Poll::Ready(Some(Ok(frame))),
            },
            other => other,
        }
    }

    fn size_hint(&self) -> SizeHint {
        let inner = self.inner.size_hint();
        let upper = inner.upper().map_or(self.remaining, |upper| upper.min(self.remaining));
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower().min(self.remaining));
        hint.set_upper(upper);
        hint
    }
}

/// The body with at most `maximum` bytes of the data of `body`.
pub fn limit_body(body: Body, maximum: i64) -> Body {
    Limited {
        inner: body,
        remaining: u64::try_from(maximum).unwrap_or(0),
    }
    .boxed_unsync()
}
