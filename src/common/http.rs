//! The HTTP types of the handlers: the request, the answer, the body, the route, and the writers of the usual
//! answers (JSON, error, text error, 404, 405).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE, HeaderValue, RETRY_AFTER, X_CONTENT_TYPE_OPTIONS};
use http::{HeaderMap, Method, StatusCode};
use http_body::Frame;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::mpsc;

use super::BoxFuture;
use super::app::App;
use super::ctx::OpCtx;
use super::error::{Error, Result};
use super::json;
use super::query::Query;

/// The body of a request, of an answer, or of an object.
pub type Body = UnsyncBoxBody<Bytes, Error>;

/// An answer.
pub type Response = http::Response<Body>;

/// An empty body.
pub fn empty() -> Body {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed_unsync()
}

/// A body of known bytes.
pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed_unsync()
}

/// The sending side of a streamed body. A task sends the data, then optionally the trailers.
#[derive(Debug)]
pub struct BodySender {
    sender: mpsc::Sender<Result<Frame<Bytes>>>,
}

impl BodySender {
    /// Send bytes. `Err` when the client is gone.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.sender
            .send(Ok(Frame::data(data)))
            .await
            .map_err(|_| Error::Canceled)
    }

    /// Send the trailers (the last frame).
    pub async fn send_trailers(&self, trailers: HeaderMap) -> Result<()> {
        self.sender
            .send(Ok(Frame::trailers(trailers)))
            .await
            .map_err(|_| Error::Canceled)
    }

    /// Stop the body with an error: the connection ends without the end of the body.
    pub async fn abort(&self, error: Error) {
        let _ = self.sender.send(Err(error)).await;
    }
}

struct ChannelBody {
    receiver: mpsc::Receiver<Result<Frame<Bytes>>>,
}

impl http_body::Body for ChannelBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        self.receiver.poll_recv(cx)
    }
}

/// A streamed body and its sender. `depth` frames wait in memory at most.
pub fn channel(depth: usize) -> (BodySender, Body) {
    let (sender, receiver) = mpsc::channel(depth.max(1));
    (BodySender { sender }, ChannelBody { receiver }.boxed_unsync())
}

/// Read a body to its end, or to `maximum` bytes. The flag is true when the body has more than `maximum` bytes.
pub async fn read_limited(mut body: Body, maximum: usize) -> Result<(Bytes, bool)> {
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            if out.len() + data.len() > maximum {
                let room = maximum - out.len();
                out.extend_from_slice(&data[..room]);
                return Ok((Bytes::from(out), true));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok((Bytes::from(out), false))
}

/// The largest JSON body of a request: 1 MiB.
pub const MAX_JSON_BODY: usize = 1 << 20;

/// Read the JSON body of a request: one value of at most 1 MiB, no unknown member (the request types have
/// `#[serde(deny_unknown_fields)]`), nothing after the value. An error gives `400 invalid_json`.
pub async fn decode_json<T: DeserializeOwned>(body: Body) -> Result<T> {
    let (bytes, truncated) = read_limited(body, MAX_JSON_BODY + 1).await?;
    if truncated {
        return Err(Error::api(
            400,
            "invalid_json",
            "invalid JSON body: the body is larger than 1 MiB",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let value = T::deserialize(&mut deserializer)
        .map_err(|error| Error::api(400, "invalid_json", format!("invalid JSON body: {error}")))?;
    if deserializer.end().is_err() {
        return Err(Error::api(400, "invalid_json", "JSON body must contain one object"));
    }
    Ok(value)
}

/// A request, as a handler gets it.
pub struct Req {
    /// The method.
    pub method: Method,
    /// The path, with its escapes decoded.
    pub path: String,
    /// The query, as the client sent it.
    pub raw_query: String,
    /// The parsed query.
    pub query: Query,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Body,
    /// The context of the storage calls of the request.
    pub ctx: OpCtx,
    /// The host of the request (the `Host` header).
    pub host: String,
}

impl Req {
    /// The value of a header as text, or an empty text.
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    }
}

/// The handler of a route.
pub type Handler = fn(Arc<App>, Req) -> BoxFuture<'static, Response>;

/// The kind of access of a route (docs/ACCESS.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAccess {
    /// No rule: the route answers 403 with the action `unknown`.
    Denied,
    /// No identity token: `/healthz` and the action document.
    Exempt,
    /// The identity token and no PDP question: the static files, the pages, `/api/build`.
    TokenOnly,
    /// The identity token; the handler asks the PDP for each operation.
    HandlerAsks,
}

/// One route: a pattern, its kind of access and its handler.
#[derive(Clone, Copy)]
pub struct Route {
    /// The exact path, or a subtree that ends with `/` (`/api/jobs/`), or `/` for the rest.
    pub pattern: &'static str,
    /// The kind of access.
    pub access: RouteAccess,
    /// The handler.
    pub handler: Handler,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("pattern", &self.pattern)
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
}

/// A route of the table.
pub const fn route(pattern: &'static str, access: RouteAccess, handler: Handler) -> Route {
    Route {
        pattern,
        access,
        handler,
    }
}

/// An answer with a status, headers and a body.
pub fn answer(status: u16, headers: HeaderMap, body: Body) -> Response {
    let mut response = http::Response::new(body);
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    *response.headers_mut() = headers;
    response
}

/// A JSON answer: `Content-Type: application/json; charset=utf-8`, `Cache-Control: no-store`, the JSON text and a
/// line end.
pub fn json<T: Serialize + ?Sized>(status: u16, value: &T) -> Response {
    match json::to_body(value) {
        Ok(bytes) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            );
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            answer(status, headers, full(bytes))
        }
        Err(error) => text_error(500, &error.to_string()),
    }
}

fn set_retry_after(headers: &mut HeaderMap, seconds: u64) {
    if seconds > 0
        && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
    {
        headers.insert(RETRY_AFTER, value);
    }
}

/// The answer of an action that needs an approval: 403 with exactly `{"error":"approval_cannot_wait"}`, on each route.
fn approval_answer(error: &Error) -> Option<Response> {
    #[derive(Serialize)]
    struct Flat {
        error: &'static str,
    }
    error.has_code(super::error::CODE_APPROVAL_CANNOT_WAIT).then(|| {
        json(
            403,
            &Flat {
                error: super::error::CODE_APPROVAL_CANNOT_WAIT,
            },
        )
    })
}

/// The JSON error answer of an API route: `{"error":{"code":...,"message":...}}`.
pub fn api_error(error: &Error) -> Response {
    if let Some(response) = approval_answer(error) {
        return response;
    }
    let mut response = json(error.status(), &error.envelope());
    set_retry_after(response.headers_mut(), error.retry_after());
    response
}

/// A text error: `Content-Type: text/plain; charset=utf-8`, `X-Content-Type-Options: nosniff`, the message and a
/// line end.
pub fn text_error(status: u16, message: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    answer(status, headers, full(format!("{message}\n")))
}

/// The error answer of the object routes (`/s3`, `/open/`): the message as text, with `Cache-Control: no-store`.
pub fn gateway_error(error: &Error) -> Response {
    if let Some(response) = approval_answer(error) {
        return response;
    }
    let mut response = text_error(error.status(), &error.public_message());
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    set_retry_after(response.headers_mut(), error.retry_after());
    response
}

/// The plain 404 answer: `404 page not found`.
pub fn not_found() -> Response {
    text_error(404, "404 page not found")
}

/// The 405 answer with the header `Allow`.
pub fn method_not_allowed(methods: &[&str]) -> Response {
    let mut response = text_error(405, "method not allowed");
    if let Ok(value) = HeaderValue::from_str(&methods.join(", ")) {
        response.headers_mut().insert(ALLOW, value);
    }
    response
}

/// The 204 answer.
pub fn no_content() -> Response {
    answer(204, HeaderMap::new(), empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_error_envelope_has_sorted_members_and_a_line_end() {
        let mut api = crate::common::error::ApiError {
            status: 429,
            code: "too_many_requests".to_owned(),
            message: "The budget of the action object.write is used.".to_owned(),
            action: Some("object.write".to_owned()),
            retry_after: 7,
            ceiling: None,
        };
        let response = api_error(&Error::Api(Box::new(api.clone())));
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "7");
        let (bytes, _) = read_limited(response.into_body(), 4096).await.unwrap();
        assert_eq!(
            &bytes[..],
            b"{\"error\":{\"action\":\"object.write\",\"code\":\"too_many_requests\",\"message\":\"The budget of the action object.write is used.\",\"retryable\":true}}\n"
        );
        api.ceiling = Some(("max_object_size".to_owned(), 1_048_576));
        api.code = "ceiling_exceeded".to_owned();
        let body = json::to_vec(&Error::Api(Box::new(api)).envelope()).unwrap();
        assert!(
            String::from_utf8(body)
                .unwrap()
                .contains("\"ceiling\":\"max_object_size\",\"code\":\"ceiling_exceeded\",\"limit\":1048576")
        );
    }

    #[tokio::test]
    async fn an_action_that_needs_an_approval_has_one_fixed_body_on_each_route() {
        let error = Error::api(403, super::super::error::CODE_APPROVAL_CANNOT_WAIT, "any text");
        for response in [api_error(&error), gateway_error(&error)] {
            assert_eq!(response.status(), 403);
            assert_eq!(
                response.headers().get(CONTENT_TYPE).unwrap(),
                "application/json; charset=utf-8"
            );
            let (bytes, _) = read_limited(response.into_body(), 4096).await.unwrap();
            assert_eq!(&bytes[..], b"{\"error\":\"approval_cannot_wait\"}\n");
        }
    }

    #[tokio::test]
    async fn json_bodies_refuse_a_second_value() {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            #[allow(dead_code)]
            key: String,
        }
        assert!(decode_json::<Body>(full("{\"key\":\"a\"}")).await.is_ok());
        let error = decode_json::<Body>(full("{\"key\":\"a\"} {}")).await.err().unwrap();
        assert!(error.has_code("invalid_json"));
        assert!(decode_json::<Body>(full("{\"other\":1}")).await.is_err());
    }
}
