// SPDX-License-Identifier: MIT OR Apache-2.0
//! One entry of an archive, and the runners of two jobs:
//! - `GET|HEAD /api/archive-entry`: the bytes of one entry.
//! - `POST /api/archive-extract`: the job `extract_archive`.
//! - `POST /api/archive-entry/integrity`: the job `archive_entry_integrity`.
//!
//! Each route opens the central directory with the limit `max_archive_entries` and finds the entry by its exact
//! name. It refuses a folder, an unsafe path, a symbolic link and an encrypted entry. It also refuses an entry above
//! the limit of bytes: `max_storage_bytes_per_request` for the route, `max_background_storage_bytes` for the jobs.
//! The bytes of an entry move from the archive to the client or to the destination object as a stream. No
//! temporary file holds them.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aws_lc_rs::digest;
use http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Method};
use http_body_util::BodyExt;
use serde::Deserialize;

use super::content::{
    apply_object_safety_headers, archive_entry_active_content, browser_inline_content, format_disposition,
    is_svg_content, preview_content_type,
};
use super::names::{
    DEFAULT_MAX_ARCHIVE_ENTRIES, normalize_archive_entry_selection, normalize_prefix, path_base, path_ext, quote,
    safe_archive_entry_name,
};
use super::stream::{EntryBody, STREAM_IDLE_TIMEOUT, stream};
use super::zip::{
    ByteSource, CODE_TOO_MANY_ENTRIES, ZipEntry, ZipReader, invalid_zip, is_unsupported_method,
    is_zip_archive_extension,
};
use super::{ArchiveEntryIntegrityRequest, ArchiveEntryIntegrityResult, ArchiveExtractResult};
use crate::access::{ACTION_READ, ACTION_WRITE, Operation, authorize, authorize_read, object_ask};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::{GateMode, OpCtx};
use crate::common::error::{Error, Result};
use crate::common::http::{Body, Req, Response, answer, api_error, decode_json, empty, method_not_allowed};
use crate::common::md5::Md5;
use crate::common::misc::{clean_relative_key, hex};
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::ceiling::{Ceilings, ceiling_applies, ceiling_error_of, ceilings_of, check_object_ceiling};
use crate::instance::range::{ObjectVersion, RangeSource};
use crate::jobs::{JobRun, JobState, job_type};

/// The size of a part of the hash work.
const HASH_CHUNK: usize = 128 << 10;

/// The body of `POST /api/archive-extract`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArchiveExtractRequest {
    /// The instance of the archive.
    pub instance: String,
    /// The relative key of the archive.
    pub key: String,
    /// The version of the archive.
    pub version: String,
    /// The exact names of the selected entries.
    pub entries: Vec<String>,
    /// The instance of the destination (the instance of the archive when empty).
    #[serde(rename = "targetInstance")]
    pub target_instance: String,
    /// The destination folder.
    pub target: String,
}

/// The body of `POST /api/archive-entry/integrity`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArchiveEntryIntegrityBody {
    /// The instance of the archive.
    pub instance: String,
    /// The relative key of the archive.
    pub key: String,
    /// The version of the archive.
    pub version: String,
    /// The exact name of the entry.
    pub entry: String,
}

fn find_instance(app: &App, id: &str) -> Option<Arc<Instance>> {
    app.instances.iter().find(|instance| instance.cfg.id == id).cloned()
}

/// What the listing tells about an archive: its size (0 when not known), its ETag and the date of its last change,
/// as the client sends them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListedArchive {
    /// The size, or 0.
    pub size: i64,
    /// The ETag.
    pub etag: String,
    /// The date of the last change.
    pub modified: String,
}

/// Open the range reader of an archive (a relative key), bound to the size, the ETag and the date of the listing when
/// they are known.
pub async fn open_archive_source(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    version: &str,
    listed: &ListedArchive,
) -> Result<RangeSource> {
    let mut source = RangeSource::open_version(ctx, instance, key, version).await?;
    source.set_known_size(listed.size);
    source.set_expected_version(&ObjectVersion {
        etag: listed.etag.clone(),
        version: String::new(),
        modified: listed.modified.clone(),
    });
    Ok(source)
}

/// The extension of a key in lower case, without its dot.
fn archive_extension(key: &str) -> String {
    let extension = path_ext(key);
    extension.strip_prefix('.').unwrap_or(extension).to_lowercase()
}

/// Read the central directory of an archive for the selection of entries. The answers of a failure:
/// - a key without a ZIP-compatible extension: `415 unsupported_archive`;
/// - more entries than the limit (0: the default limit): `413 archive_too_many_entries`;
/// - a refusal for a ceiling: the refusal;
/// - any other failure: `422 invalid_zip`.
pub async fn open_archive_reader(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    version: &str,
    listed: &ListedArchive,
    max_entries: usize,
) -> Result<ZipReader<RangeSource>> {
    let extension = archive_extension(key);
    if !is_zip_archive_extension(&extension) {
        return Err(Error::api(
            415,
            "unsupported_archive",
            "selective extraction is available only for indexed ZIP-compatible archives",
        ));
    }
    let source = open_archive_source(ctx, instance, key, version, listed).await?;
    let max_entries = if max_entries == 0 {
        DEFAULT_MAX_ARCHIVE_ENTRIES
    } else {
        max_entries
    };
    match ZipReader::open_package(source, &extension, max_entries).await {
        Ok(reader) => Ok(reader),
        Err(error) if error.has_code(CODE_TOO_MANY_ENTRIES) || ceiling_error_of(&error).is_some() => Err(error),
        Err(_) => Err(invalid_zip()),
    }
}

/// The only entry with this exact name: `404 archive_entry_not_found` without one, `409 ambiguous_archive_entry` with
/// two or more.
pub fn exact_archive_entry<'a, S: ByteSource>(reader: &'a ZipReader<S>, name: &str) -> Result<&'a ZipEntry> {
    let mut matches = reader.entries_named(name);
    let Some(found) = matches.next() else {
        return Err(Error::api(
            404,
            "archive_entry_not_found",
            "archive entry was not found",
        ));
    };
    if matches.next().is_some() {
        return Err(Error::api(
            409,
            "ambiguous_archive_entry",
            "the archive contains multiple entries with the selected name",
        ));
    }
    Ok(found)
}

/// Refuse an entry that a person cannot open or extract as a file: a folder, an unsafe path, a symbolic link, an
/// encrypted entry. Also refuse an entry larger than `maximum` bytes (0 or less: no limit).
pub fn validate_selectable_archive_entry(entry: &ZipEntry, maximum: i64) -> Result<()> {
    if entry.is_dir() {
        return Err(Error::api(
            400,
            "archive_entry_is_directory",
            "directories cannot be extracted as files",
        ));
    }
    if safe_archive_entry_name(&entry.name).as_deref() != Some(entry.name.replace('\\', "/").as_str()) {
        return Err(Error::api(
            400,
            "unsafe_archive_entry",
            "the archive entry has an unsafe path",
        ));
    }
    if entry.is_symlink() {
        return Err(Error::api(
            403,
            "archive_symlink_blocked",
            "symbolic link entries cannot be opened",
        ));
    }
    if entry.is_encrypted() {
        return Err(Error::api(
            422,
            "archive_entry_encrypted",
            "encrypted archive entries are not supported",
        ));
    }
    if maximum > 0 && entry.size > maximum as u64 {
        return Err(Error::api(
            413,
            "archive_entry_too_large",
            format!("the entry exceeds the configured {maximum}-byte extraction limit"),
        ));
    }
    Ok(())
}

/// The `422 archive_entry_open_failed` answer of an entry that the reader cannot open.
pub fn archive_entry_open_error(name: &str, error: &Error) -> Error {
    let message = if is_unsupported_method(error) {
        "archive entry uses an unsupported compression method"
    } else {
        "archive entry could not be decompressed"
    };
    Error::api(
        422,
        "archive_entry_open_failed",
        format!("{message}: {}", path_base(name)),
    )
}

/// The handler of `/api/archive-entry`.
pub fn handle_archive_entry(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::GET && req.method != Method::HEAD {
            return method_not_allowed(&["GET", "HEAD"]);
        }
        // The bytes of a member come from whoever can write the bucket: each answer has the sandbox headers.
        let mut response = match serve_archive_entry(app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        };
        apply_object_safety_headers(response.headers_mut());
        response
    })
}

async fn serve_archive_entry(app: Arc<App>, req: Req) -> Result<Response> {
    let instance = app.instance_of("", req.query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    let key = clean_relative_key(req.query.get("key"));
    let version = req.query.get("version").trim().to_owned();
    let entry_name = req.query.get("entry").trim().to_owned();
    if key.is_empty() || entry_name.is_empty() {
        return Err(Error::api(
            400,
            "invalid_archive_entry",
            "archive key and entry are required",
        ));
    }
    authorize_read(&app, &req.ctx, &instance, &key).await?;
    let listed = ListedArchive {
        size: req.query.get("size").trim().parse().unwrap_or(0),
        etag: req.query.get("etag").trim().to_owned(),
        modified: req.query.get("lastModified").trim().to_owned(),
    };
    let max_entries = app.config.runtime.max_archive_entries as usize;
    let reader = open_archive_reader(&req.ctx, &instance, &key, &version, &listed, max_entries).await?;
    let entry = exact_archive_entry(&reader, &entry_name)?.clone();
    validate_selectable_archive_entry(&entry, app.config.runtime.max_storage_bytes_per_request)?;
    let options = EntryAnswer {
        head: req.method == Method::HEAD,
        inline: req.query.get("inline") == "1",
        image: req.header("sec-fetch-dest") == "image",
    };
    entry_answer(Arc::new(reader), entry, options).await
}

/// What the request asks of the answer of an entry.
#[derive(Clone, Copy, Debug, Default)]
pub struct EntryAnswer {
    /// A HEAD request: the headers only.
    pub head: bool,
    /// `inline=1`: the browser may display the entry.
    pub inline: bool,
    /// `Sec-Fetch-Dest: image`: an `<img>` element asks for the entry.
    pub image: bool,
}

/// The answer with the bytes of an entry: the headers, then the stream of the entry. A stream that stops before
/// the size of the entry stops the answer with an error.
pub async fn entry_answer<S: ByteSource + 'static>(
    reader: Arc<ZipReader<S>>,
    entry: ZipEntry,
    options: EntryAnswer,
) -> Result<Response> {
    let mut filename = path_base(&entry.name);
    if filename == "." || filename == "/" || filename.is_empty() {
        filename = "archive-entry";
    }
    let mut content_type = preview_content_type(filename);
    if content_type.is_empty() {
        content_type = "application/octet-stream";
    }
    let mut disposition = "attachment";
    if options.inline && browser_inline_content(filename, content_type) {
        disposition = "inline";
    }
    // A member is served from the origin of the application. A document or a script never reaches the browser as
    // such; an SVG for an `<img>` element cannot run a script and keeps its type.
    if archive_entry_active_content(filename, content_type)
        && !(is_svg_content(filename, content_type) && options.image)
    {
        content_type = "application/octet-stream";
        disposition = "attachment";
    }
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(value) = HeaderValue::from_str(&entry.size.to_string()) {
        headers.insert(CONTENT_LENGTH, value);
    }
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    if let Some(value) = format_disposition(disposition, filename.as_bytes())
        && let Ok(value) = HeaderValue::from_str(&value)
    {
        headers.insert(CONTENT_DISPOSITION, value);
    }
    if options.head {
        return Ok(answer(200, headers, empty()));
    }
    let mut entry_stream = reader
        .open_entry_shared(&entry)
        .await
        .map_err(|error| archive_entry_open_error(&entry.name, &error))?;
    let (sender, body) = stream(STREAM_IDLE_TIMEOUT);
    tokio::spawn(async move {
        loop {
            match entry_stream.next_chunk().await {
                Ok(Some(chunk)) => {
                    if sender.send(chunk).await.is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                // All the bytes are sent: the answer is complete, the error stays in the stream.
                Err(_) if entry_stream.produced() == entry_stream.entry().size => break,
                Err(_) => return,
            }
        }
        sender.finish();
    });
    Ok(answer(200, headers, body))
}

/// The handler of `/api/archive-extract`: it starts the job `extract_archive`.
pub fn handle_archive_extract(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::POST {
            return method_not_allowed(&["POST"]);
        }
        match start_extraction(app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

async fn start_extraction(app: Arc<App>, req: Req) -> Result<Response> {
    let ctx = req.ctx.clone();
    let query_instance = req.query.get("instance").to_owned();
    let mut request: ArchiveExtractRequest = decode_json(req.body).await?;
    let source = app.instance_of(&request.instance, &query_instance)?.clone();
    if request.target_instance.trim().is_empty() {
        request.target_instance = source.cfg.id.clone();
    }
    let target = find_instance(&app, &request.target_instance)
        .ok_or_else(|| Error::api(404, "unknown_target_instance", "target storage instance was not found"))?;
    source.require_permission(PERMISSION_READ)?;
    target.require_permission(PERMISSION_WRITE)?;
    target.require_permission(PERMISSION_READ)?;
    request.key = clean_relative_key(&request.key);
    request.version = request.version.trim().to_owned();
    request.target = normalize_prefix(&clean_relative_key(&request.target));
    let entries = normalize_archive_entry_selection(&request.entries, app.config.runtime.max_archive_entries as usize)?;
    if request.key.is_empty() {
        return Err(Error::api(400, "invalid_archive", "archive key is required"));
    }
    let operation = Operation {
        others: vec![
            object_ask(&app, ACTION_READ, &source, &request.key),
            object_ask(&app, ACTION_READ, &target, &request.target),
        ],
        use_ask: object_ask(&app, ACTION_WRITE, &target, &request.target),
        continuation: false,
    };
    authorize(&app, &ctx, operation).await?;
    let job = app.jobs.create(JobState {
        job_type: job_type::EXTRACT_ARCHIVE.to_owned(),
        instance: source.cfg.id.clone(),
        target_instance: target.cfg.id.clone(),
        source: request.key,
        version: request.version,
        target: request.target,
        entries,
        ceilings: job_ceilings(&ctx),
        ..JobState::default()
    })?;
    Ok(crate::jobs::job_answer(202, &job))
}

/// The handler of `/api/archive-entry/integrity`: it starts the job `archive_entry_integrity` and gives the job when
/// it ends or pauses in 100 ms.
pub fn handle_archive_entry_integrity(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::POST {
            return method_not_allowed(&["POST"]);
        }
        match start_entry_integrity(app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

async fn start_entry_integrity(app: Arc<App>, req: Req) -> Result<Response> {
    let ctx = req.ctx.clone();
    let query_instance = req.query.get("instance").to_owned();
    let body: ArchiveEntryIntegrityBody = decode_json(req.body).await?;
    let instance = app.instance_of(&body.instance, &query_instance)?.clone();
    let key = clean_relative_key(&body.key);
    instance.require_permission(PERMISSION_READ)?;
    let version = body.version.trim().to_owned();
    let entry = body.entry.trim().to_owned();
    if key.is_empty() || entry.is_empty() {
        return Err(Error::api(
            400,
            "invalid_archive_entry",
            "archive key and entry are required",
        ));
    }
    authorize_read(&app, &ctx, &instance, &key).await?;
    let job = app.jobs.create(JobState {
        job_type: job_type::ARCHIVE_ENTRY_INTEGRITY.to_owned(),
        instance: instance.cfg.id.clone(),
        archive_entry_integrity_request: Some(ArchiveEntryIntegrityRequest { key, version, entry }),
        ceilings: job_ceilings(&ctx),
        ..JobState::default()
    })?;
    Ok(crate::jobs::analysis_job_answer(&app, &job).await)
}

/// A copy of the ceilings of the request (those of the PDP answers and those that the context carries), for the job.
fn job_ceilings(ctx: &OpCtx) -> Option<Arc<Ceilings>> {
    let map = ceilings_of(ctx);
    (!map.is_empty()).then(|| Arc::new(Ceilings::from_map(&map)))
}

/// The destination of an extraction and the save of the progress of the job.
pub trait ExtractTarget: Send + Sync {
    /// Write a new object at a relative key: `409` when an object exists there.
    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>>;

    /// Save the progress of the job.
    fn save(&self, job: &JobState) -> Result<()>;
}

/// The destination of a running job: the target instance, and the job manager for the progress.
struct RunTarget<'a> {
    run: &'a JobRun,
    target: Arc<Instance>,
}

impl ExtractTarget for RunTarget<'_> {
    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.target
                .put_if_absent(ctx, &self.target.full_key(key), body, size, content_type)
                .await
        })
    }

    fn save(&self, job: &JobState) -> Result<()> {
        self.run.save(job)
    }
}

/// Run the job `extract_archive`: each selected entry of the archive to a new object under the target folder.
pub async fn run_extraction(run: &JobRun, job: &mut JobState) -> Result<()> {
    let app = &run.app;
    let (Some(source), Some(target)) = (
        find_instance(app, &job.instance),
        find_instance(app, &job.target_instance),
    ) else {
        return Err(Error::api(
            404,
            "unknown_instance",
            "source or target storage instance was not found",
        ));
    };
    source.require_permission(PERMISSION_READ)?;
    target.require_permission(PERMISSION_WRITE)?;
    // A create-only write tells whether a destination exists: the target must also let the reads.
    target.require_permission(PERMISSION_READ)?;
    // The upload of an entry holds a storage slot while it reads the archive. The reads of the archive take no
    // second slot: else two extractions can wait on each other for ever.
    let reader_ctx = run.ctx.gated(GateMode::Exempt);
    let reader = open_archive_reader(
        &reader_ctx,
        &source,
        &job.source,
        &job.version,
        &ListedArchive::default(),
        app.config.runtime.max_archive_entries as usize,
    )
    .await?;
    let same_instance = Arc::ptr_eq(&source, &target);
    let destination = RunTarget { run, target };
    extract_archive(
        &run.ctx,
        Arc::new(reader),
        job,
        same_instance,
        app.config.runtime.max_background_storage_bytes,
        &destination,
    )
    .await
}

/// The extraction of the selected entries of an open archive. A job that resumes keeps the entries that it wrote.
pub async fn extract_archive<S: ByteSource + 'static, T: ExtractTarget>(
    ctx: &OpCtx,
    reader: Arc<ZipReader<S>>,
    job: &mut JobState,
    same_instance: bool,
    max_bytes: i64,
    target: &T,
) -> Result<()> {
    // One index of the names instead of a search for each selected name.
    let mut index: HashMap<&str, Vec<&ZipEntry>> = HashMap::with_capacity(reader.entries.len());
    for (position, entry) in reader.entries.iter().enumerate() {
        if position % 1024 == 0 {
            ctx.check()?;
        }
        if entry.name_is_utf8 {
            index.entry(entry.name.as_str()).or_default().push(entry);
        }
    }
    let mut selected: Vec<(ZipEntry, String)> = Vec::with_capacity(job.entries.len());
    let mut destinations = HashSet::with_capacity(job.entries.len());
    for name in &job.entries {
        ctx.check()?;
        let entry = match index.get(name.as_str()).map(Vec::as_slice) {
            None | Some([]) => {
                return Err(Error::api(
                    404,
                    "archive_entry_not_found",
                    "archive entry was not found",
                ));
            }
            Some([entry]) => *entry,
            Some(_) => {
                return Err(Error::api(
                    409,
                    "ambiguous_archive_entry",
                    "the archive contains multiple entries with the selected name",
                ));
            }
        };
        validate_selectable_archive_entry(entry, max_bytes)?;
        let safe_name = safe_archive_entry_name(&entry.name).unwrap_or_default();
        let destination = clean_relative_key(&format!("{}{safe_name}", job.target));
        if destination.is_empty() {
            return Err(Error::api(
                400,
                "invalid_archive_target",
                "an extracted archive entry has an invalid destination",
            ));
        }
        if same_instance && destination == job.source {
            return Err(Error::api(
                409,
                "archive_source_collision",
                "an extracted entry would overwrite the archive while it is being read",
            ));
        }
        if !destinations.insert(destination.clone()) {
            return Err(Error::api(
                409,
                "archive_target_collision",
                "multiple selected entries resolve to the same destination",
            ));
        }
        selected.push((entry.clone(), destination));
    }
    // The ceiling object.write: the central directory gives the size of each member, so the check of all of them
    // comes before the first write. A size that does not fit in 63 bits is an unknown size.
    if ceiling_applies(ctx, &[ACTION_WRITE]) {
        for (entry, _) in &selected {
            check_object_ceiling(ctx, ACTION_WRITE, i64::try_from(entry.size).unwrap_or(-1))?;
        }
    }
    let kept = job.archive_extract.clone().filter(|result| {
        result.archive_key == job.source
            && result.version == job.version
            && result.target_instance == job.target_instance
            && result.target == job.target
            && result.extracted == job.processed
    });
    let mut result = match kept {
        Some(result) => result,
        None => {
            job.processed = 0;
            job.last_key.clear();
            ArchiveExtractResult {
                archive_key: job.source.clone(),
                version: job.version.clone(),
                target_instance: job.target_instance.clone(),
                target: job.target.clone(),
                ..ArchiveExtractResult::default()
            }
        }
    };
    job.archive_extract = Some(result.clone());
    target.save(job)?;
    let start = usize::try_from(job.processed)
        .ok()
        .filter(|start| *start <= selected.len())
        .ok_or_else(|| {
            Error::api(
                409,
                "invalid_archive_progress",
                "archive extraction progress is invalid",
            )
        })?;
    for (position, (entry, destination)) in selected.iter().enumerate().skip(start) {
        ctx.check()?;
        let entry_stream = reader
            .open_entry_shared(entry)
            .await
            .map_err(|error| archive_entry_open_error(&entry.name, &error))?;
        let counter = Arc::new(AtomicU64::new(0));
        let body = EntryBody::new(entry_stream, ctx.clone(), counter.clone()).boxed_unsync();
        let mut content_type = preview_content_type(&entry.name);
        if content_type.is_empty() {
            content_type = "application/octet-stream";
        }
        if let Err(error) = target
            .put(ctx, destination, body, entry.size as i64, content_type)
            .await
        {
            // A pause or a cancel that stopped the body wins over the error of the write.
            ctx.check()?;
            return Err(error);
        }
        let count = counter.load(Ordering::SeqCst);
        if count != entry.size {
            return Err(Error::api(
                502,
                "archive_entry_truncated",
                format!(
                    "archive entry {} was truncated while being extracted",
                    quote(&entry.name)
                ),
            ));
        }
        result.bytes += count as i64;
        result.extracted = position as i64 + 1;
        job.processed = result.extracted;
        job.last_key = entry.name.clone();
        job.archive_extract = Some(result.clone());
        job.updated_at = Timestamp::now();
        target.save(job)?;
    }
    result.completed_at = Some(Timestamp::now());
    job.archive_extract = Some(result);
    target.save(job)
}

/// Run the job `archive_entry_integrity`: the SHA-256, the MD5 and the CRC-32 of one entry, and the comparison of
/// the CRC-32 with the central directory.
pub async fn run_entry_integrity(run: &JobRun, job: &mut JobState) -> Result<()> {
    let request = job
        .archive_entry_integrity_request
        .clone()
        .ok_or_else(|| Error::internal("archive entry integrity request is missing"))?;
    let app = &run.app;
    let instance = find_instance(app, &job.instance)
        .ok_or_else(|| Error::api(404, "unknown_instance", "storage instance was not found"))?;
    instance.require_permission(PERMISSION_READ)?;
    let reader = open_archive_reader(
        &run.ctx,
        &instance,
        &request.key,
        &request.version,
        &ListedArchive::default(),
        app.config.runtime.max_archive_entries as usize,
    )
    .await?;
    let result = entry_integrity(
        &run.ctx,
        &reader,
        &request,
        app.config.runtime.max_background_storage_bytes,
    )
    .await?;
    job.archive_entry_integrity = Some(result);
    job.processed = 1;
    job.last_key = request.entry;
    run.save(job)
}

/// The digests of the entry that `request` names, from a complete read of the entry.
pub async fn entry_integrity<S: ByteSource>(
    ctx: &OpCtx,
    reader: &ZipReader<S>,
    request: &ArchiveEntryIntegrityRequest,
    max_bytes: i64,
) -> Result<ArchiveEntryIntegrityResult> {
    let entry = exact_archive_entry(reader, &request.entry)?;
    validate_selectable_archive_entry(entry, max_bytes)?;
    let mut entry_stream = reader
        .open_entry(entry)
        .await
        .map_err(|error| archive_entry_open_error(&entry.name, &error))?;
    let mut hashes = Some(Hashes::new());
    let mut written = 0u64;
    loop {
        ctx.check()?;
        let Some(chunk) = entry_stream.next_chunk().await? else {
            break;
        };
        written += chunk.len() as u64;
        let Some(mut state) = hashes.take() else {
            return Err(Error::internal("the hash state is missing"));
        };
        // The hash of a large chunk runs on a blocking thread.
        state = tokio::task::spawn_blocking(move || {
            for part in chunk.chunks(HASH_CHUNK) {
                state.update(part);
            }
            state
        })
        .await
        .map_err(|_| Error::internal("the hash task stopped"))?;
        hashes = Some(state);
    }
    let Some(hashes) = hashes else {
        return Err(Error::internal("the hash state is missing"));
    };
    if written != entry.size {
        return Err(Error::api(
            502,
            "archive_entry_size_mismatch",
            "archive entry size did not match its central-directory metadata",
        ));
    }
    let (sha256, md5, crc) = hashes.finish();
    Ok(ArchiveEntryIntegrityResult {
        archive_key: request.key.clone(),
        version: request.version.clone(),
        entry: request.entry.clone(),
        size: written as i64,
        compressed_size: entry.compressed_size as i64,
        sha256,
        md5,
        crc32: format!("{crc:08x}"),
        expected_crc32: format!("{:08x}", entry.crc32),
        crc32_matches: crc == entry.crc32,
    })
}

/// The three digests of an entry.
struct Hashes {
    sha256: digest::Context,
    md5: Md5,
    crc: flate2::Crc,
}

impl Hashes {
    fn new() -> Self {
        Self {
            sha256: digest::Context::new(&digest::SHA256),
            md5: Md5::new(),
            crc: flate2::Crc::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.sha256.update(data);
        self.md5.update(data);
        self.crc.update(data);
    }

    fn finish(self) -> (String, String, u32) {
        (
            hex(self.sha256.finish().as_ref()),
            hex(&self.md5.finish()),
            self.crc.sum(),
        )
    }
}
