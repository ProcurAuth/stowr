//! The routes `/api/uploads` and `/api/uploads/resume`.
//!
//! `POST /api/uploads` makes a session. `GET` gives the state of a session, `PUT` sends one chunk, and `DELETE`
//! cancels the session. The resume token is in the header `X-Stowr-Resume-Token`. `POST /api/uploads/resume` takes it
//! in the body.

use std::sync::{Arc, Weak};

use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::{HeaderMap, Method};
use serde::Deserialize;

use super::manager::{ChunkInput, CreateUploadRequest};
use super::session::UploadSession;
use super::target::{AccessCheck, UploadTarget};
use crate::access::{ACTION_WRITE, Operation, authorize, object_ask};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, decode_json, json, method_not_allowed, not_found};

/// The header that carries the resume token.
pub const RESUME_TOKEN_HEADER: &str = "X-Stowr-Resume-Token";

/// The body of `POST /api/uploads/resume`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeRequest {
    #[serde(default, rename = "resumeToken")]
    resume_token: Option<String>,
}

/// The access check of an upload request: it asks `object.write` on the node of the key. The instance and the key come
/// from the upload, never from the client. A continuation asks no usage.
struct RouteCheck {
    app: Arc<App>,
    ctx: OpCtx,
    continuation: bool,
}

impl AccessCheck for RouteCheck {
    fn check<'a>(&'a self, target: &'a dyn UploadTarget, key: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let instance = self.app.instance(target.id())?;
            let operation = Operation {
                use_ask: object_ask(&self.app, ACTION_WRITE, instance, key),
                continuation: self.continuation,
                ..Operation::default()
            };
            authorize(&self.app, &self.ctx, operation).await.map(|_| ())
        })
    }
}

/// The length that the client declared: `-1` for a body without a known length.
fn declared_length(headers: &HeaderMap) -> i64 {
    if let Some(value) = headers.get(CONTENT_LENGTH).and_then(|value| value.to_str().ok())
        && let Ok(length) = value.trim().parse::<i64>()
    {
        return length;
    }
    let chunked = headers.get_all(TRANSFER_ENCODING).iter().any(|value| {
        value
            .to_str()
            .is_ok_and(|text| text.to_ascii_lowercase().contains("chunked"))
    });
    if chunked { -1 } else { 0 }
}

/// A session as the client sees it. A completed or canceled session leaves the memory of the process.
fn upload_response(app: &App, status: u16, upload: &UploadSession) -> Response {
    app.uploads.release_terminal(upload);
    json(status, &upload.public())
}

fn token_of(headers: &HeaderMap) -> Result<String> {
    let token = headers
        .get(RESUME_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    if token.is_empty() {
        return Err(Error::api(
            400,
            "resume_token_required",
            "upload resume token is required",
        ));
    }
    Ok(token.to_owned())
}

/// The handler of `/api/uploads` and `/api/uploads/resume`.
pub fn handle_uploads(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match uploads_route(app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

async fn uploads_route(app: Arc<App>, req: Req) -> Result<Response> {
    let weak: Weak<App> = Arc::downgrade(&app);
    app.uploads.ensure_reaper(weak);
    let Req {
        method,
        path,
        query,
        headers,
        body,
        ctx,
        ..
    } = req;
    let check = |continuation: bool| RouteCheck {
        app: app.clone(),
        ctx: ctx.clone(),
        continuation,
    };
    if path == "/api/uploads/resume" {
        if method != Method::POST {
            return Ok(method_not_allowed(&["POST"]));
        }
        let request: ResumeRequest = decode_json(body).await?;
        let upload = app
            .uploads
            .resume_checked(&*app, &ctx, request.resume_token.as_deref().unwrap_or(""), &check(true))
            .await?;
        return Ok(upload_response(&app, 200, &upload));
    }
    if path != "/api/uploads" && path != "/api/uploads/" {
        return Ok(not_found());
    }
    match method {
        Method::POST => {
            let mut request: CreateUploadRequest = decode_json(body).await?;
            if request.instance.is_empty() {
                request.instance = query.get("instance").to_owned();
            }
            let upload = app.uploads.create_checked(&*app, &ctx, request, &check(false)).await?;
            Ok(upload_response(&app, 201, &upload))
        }
        Method::GET => {
            let token = token_of(&headers)?;
            let upload = app.uploads.resume_checked(&*app, &ctx, &token, &check(true)).await?;
            Ok(upload_response(&app, 200, &upload))
        }
        Method::PUT => {
            let token = token_of(&headers)?;
            let upload = app.uploads.resume_checked(&*app, &ctx, &token, &check(true)).await?;
            let input = ChunkInput {
                content_length: declared_length(&headers),
                headers,
                body,
            };
            let upload = app.uploads.upload_chunk(&*app, &ctx, &upload.id, input).await?;
            Ok(upload_response(&app, 200, &upload))
        }
        Method::DELETE => {
            let token = token_of(&headers)?;
            let upload = app.uploads.resume_checked(&*app, &ctx, &token, &check(true)).await?;
            let upload = app.uploads.cancel(&*app, &ctx, &upload.id).await?;
            Ok(upload_response(&app, 200, &upload))
        }
        _ => Ok(method_not_allowed(&["GET", "POST", "PUT", "DELETE"])),
    }
}
