//! The embedded browser interface: the pages, the assets, the fingerprint of the build, the prepared answers, the
//! pages of the addresses `/-/<host>/<bucket>/...` and the 404 page.
//!
//! The first-party files keep stable names. The pages add the fingerprint of the whole interface to each asset URL
//! (`?v=...`). An asset that a request asks with the fingerprint of this build is cacheable for one year. Without it,
//! the client revalidates the asset with its weak ETag. A vendored library has a versioned path: it is always
//! cacheable.

use std::collections::HashMap;
use std::io::Write as _;
use std::sync::{Arc, LazyLock, RwLock};

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, ETAG, HeaderValue, LOCATION, RANGE, VARY};
use http::{HeaderMap, Method};

use super::compress::{accepts_gzip, compressible_content_type};
use super::mediatype::type_by_extension;
use super::paths;
use super::serve_content::serve_content;
use crate::common::app::App;
use crate::common::assets;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, answer, empty, full, method_not_allowed, not_found};
use crate::common::misc::hex;

/// The placeholder of the base address of a page.
pub const BASE_PLACEHOLDER: &str = "{{APP_BASE}}";
/// The placeholder of the fingerprint of the assets.
pub const ASSET_VERSION_PLACEHOLDER: &str = "{{ASSET_VERSION}}";
/// The deepest path (in segments) that gets a page. The base address grows with the depth and is part of the key of
/// the prepared answers.
pub const MAX_FRONTEND_DEPTH: usize = 32;
/// The largest number of prepared answers in memory.
pub const STATIC_CACHE_LIMIT: usize = 512;
/// The largest number of bytes of the prepared answers in memory. Each entry counts two times: its gzip form too.
pub const STATIC_CACHE_BYTE_LIMIT: usize = 64 << 20;

const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// The fingerprint of the embedded interface: the first 12 hexadecimal digits of the SHA-256 of each file (its path,
/// a zero byte and its bytes), in the order of the folders.
pub fn frontend_version() -> &'static str {
    static VERSION: LazyLock<String> = LazyLock::new(|| fingerprint(assets::FILES));
    VERSION.as_str()
}

/// The fingerprint of a set of files.
pub fn fingerprint(files: &[(&str, &[u8])]) -> String {
    let mut ordered: Vec<&(&str, &[u8])> = files.iter().collect();
    // The order of a walk of the folders: each folder sorts its entries by name.
    ordered.sort_by(|left, right| left.0.split('/').cmp(right.0.split('/')));
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for (name, data) in ordered {
        context.update(name.as_bytes());
        context.update(&[0]);
        context.update(data);
    }
    let digest = context.finish();
    hex(digest.as_ref()).chars().take(12).collect()
}

/// Fill the fingerprint placeholder of a page and add the fingerprint to each local asset URL of the page
/// (`href="assets/..."` and `src="assets/..."` without a query).
pub fn version_html(html: &[u8], version: &str) -> Vec<u8> {
    let html = replace_all(html, ASSET_VERSION_PLACEHOLDER.as_bytes(), version.as_bytes());
    let marker = b"=\"assets/";
    let mut out = Vec::with_capacity(html.len() + 256);
    let mut index = 0;
    while index < html.len() {
        let Some(found) = find(&html[index..], marker).map(|offset| index + offset) else {
            break;
        };
        let attribute =
            found >= 4 && &html[found - 4..found] == b"href" || found >= 3 && &html[found - 3..found] == b"src";
        let path_start = found + 2;
        let mut end = path_start + "assets/".len();
        while end < html.len() && !matches!(html[end], b'"' | b'?' | b'#') {
            end += 1;
        }
        let has_name = end > path_start + "assets/".len();
        if attribute && has_name && html.get(end) == Some(&b'"') {
            out.extend_from_slice(&html[index..end]);
            out.extend_from_slice(b"?v=");
            out.extend_from_slice(version.as_bytes());
            out.push(b'"');
            index = end + 1;
        } else {
            out.extend_from_slice(&html[index..found + 1]);
            index = found + 1;
        }
    }
    out.extend_from_slice(&html[index..]);
    out
}

/// Add the fingerprint to the icon URLs (`url("../icons/...")`) and to the imported stylesheets
/// (`@import url("name.css")`) of a stylesheet.
pub fn version_css(css: &[u8], version: &str) -> Vec<u8> {
    let icons = find_matches(css, b"url(\"../icons/", |rest| {
        let length = rest
            .iter()
            .take_while(|byte| !matches!(byte, b'"' | b'?' | b')'))
            .count();
        (length > 0 && rest.get(length..length + 2) == Some(b"\")".as_slice())).then_some(length)
    });
    let icons = splice_version(&icons.0, &icons.1, b"url(\"../icons/".len(), version);
    let imports = find_matches(&icons, b"@import url(\"", |rest| {
        let first = *rest.first()?;
        if !(first.is_ascii_alphanumeric() || first == b'_') {
            return None;
        }
        let length = rest
            .iter()
            .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'/' | b'-'))
            .count();
        (rest[..length].ends_with(b".css") && rest.get(length..length + 2) == Some(b"\")".as_slice())).then_some(length)
    });
    splice_version(&imports.0, &imports.1, b"@import url(\"".len(), version)
}

/// The positions of the matches of a marker that the check accepts: the start of each marker and the length of the
/// path after it.
fn find_matches(text: &[u8], marker: &[u8], check: impl Fn(&[u8]) -> Option<usize>) -> (Vec<u8>, Vec<(usize, usize)>) {
    let mut matches = Vec::new();
    let mut index = 0;
    while let Some(offset) = find(&text[index..], marker) {
        let start = index + offset;
        let path = start + marker.len();
        match check(&text[path..]) {
            Some(length) => {
                matches.push((start, length));
                // The match ends after the path, the quote and the parenthesis.
                index = path + length + 2;
            }
            None => index = start + 1,
        }
    }
    (text.to_vec(), matches)
}

/// Insert `?v=<version>` after the path of each match.
fn splice_version(text: &[u8], matches: &[(usize, usize)], marker_length: usize, version: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + matches.len() * (version.len() + 3));
    let mut index = 0;
    for &(start, length) in matches {
        let end = start + marker_length + length;
        out.extend_from_slice(&text[index..end]);
        out.extend_from_slice(b"?v=");
        out.extend_from_slice(version.as_bytes());
        index = end;
    }
    out.extend_from_slice(&text[index..]);
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn replace_all(text: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut index = 0;
    while let Some(offset) = find(&text[index..], from) {
        out.extend_from_slice(&text[index..index + offset]);
        out.extend_from_slice(to);
        index += offset + from.len();
    }
    out.extend_from_slice(&text[index..]);
    out
}

/// A prepared answer of a file of the interface: the final bytes, their weak ETag and, on the first demand, their gzip
/// form. Nothing depends on the request, so the requests share it. The ETag is weak because the same content goes plain
/// and with gzip.
#[derive(Debug)]
pub struct StaticEntry {
    /// The bytes.
    pub data: Bytes,
    /// The weak ETag: `W/"` and the first 24 hexadecimal digits of the SHA-256.
    pub etag: String,
    gzipped: tokio::sync::OnceCell<Bytes>,
}

impl StaticEntry {
    /// A prepared answer of bytes.
    pub fn new(data: Bytes) -> Self {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &data);
        let etag = format!("W/\"{}\"", hex(&digest.as_ref()[..12]));
        Self {
            data,
            etag,
            gzipped: tokio::sync::OnceCell::new(),
        }
    }

    /// The gzip form of the bytes, made one time (best compression, on a blocking thread).
    pub async fn gzip(&self) -> Bytes {
        self.gzipped
            .get_or_init(|| async {
                let data = self.data.clone();
                let data_again = data.clone();
                match tokio::task::spawn_blocking(move || gzip_best(&data)).await {
                    Ok(compressed) => compressed,
                    Err(_) => gzip_best(&data_again),
                }
            })
            .await
            .clone()
    }
}

fn gzip_best(data: &[u8]) -> Bytes {
    let mut encoder = flate2::write::GzEncoder::new(Vec::with_capacity(data.len() / 3), flate2::Compression::best());
    if encoder.write_all(data).is_err() {
        return Bytes::new();
    }
    encoder.finish().map(Bytes::from).unwrap_or_default()
}

/// The prepared answers in memory, with a limit of entries and of bytes. A file that does not fit is prepared again
/// at each request.
#[derive(Debug, Default)]
pub struct PreparedCache {
    inner: RwLock<CacheInner>,
}

#[derive(Debug, Default)]
struct CacheInner {
    entries: HashMap<String, Arc<StaticEntry>>,
    bytes: usize,
}

impl PreparedCache {
    /// The prepared answer of one file. The key holds the fingerprint of the interface, the name and the variant (the
    /// base address of a page).
    pub fn prepared(
        &self,
        version: &str,
        name: &str,
        variant: &str,
        build: impl FnOnce() -> Result<Vec<u8>>,
    ) -> Result<Arc<StaticEntry>> {
        let key = format!("{version}\0{name}\0{variant}");
        if let Some(entry) = self
            .inner
            .read()
            .ok()
            .and_then(|inner| inner.entries.get(&key).cloned())
        {
            return Ok(entry);
        }
        let entry = Arc::new(StaticEntry::new(Bytes::from(build()?)));
        let Ok(mut inner) = self.inner.write() else {
            return Ok(entry);
        };
        if let Some(existing) = inner.entries.get(&key) {
            return Ok(existing.clone());
        }
        let size = 2 * entry.data.len();
        if inner.entries.len() < STATIC_CACHE_LIMIT && inner.bytes + size <= STATIC_CACHE_BYTE_LIMIT {
            inner.entries.insert(key, entry.clone());
            inner.bytes += size;
        }
        Ok(entry)
    }

    /// The number of entries and the counted bytes.
    pub fn usage(&self) -> (usize, usize) {
        self.inner
            .read()
            .map(|inner| (inner.entries.len(), inner.bytes))
            .unwrap_or_default()
    }

    /// True when an entry of this variant exists.
    pub fn has_variant(&self, variant: &str) -> bool {
        let suffix = format!("\0{variant}");
        self.inner
            .read()
            .map(|inner| inner.entries.keys().any(|key| key.ends_with(&suffix)))
            .unwrap_or(false)
    }
}

/// The prepared answers of the process.
pub fn static_cache() -> &'static PreparedCache {
    static CACHE: LazyLock<PreparedCache> = LazyLock::new(PreparedCache::default);
    &CACHE
}

/// The number of folder levels that a browser climbs to leave a path, empty segments included.
pub fn frontend_depth(request_path: &str) -> usize {
    let clean = request_path.trim().trim_matches('/');
    if clean.is_empty() {
        return 0;
    }
    let depth = clean.split('/').count();
    if request_path.ends_with('/') { depth } else { depth - 1 }
}

/// The base address of a page: `./`, or `../` for each level, at most [`MAX_FRONTEND_DEPTH`] levels.
pub fn frontend_base_href(request_path: &str) -> String {
    let depth = frontend_depth(request_path).min(MAX_FRONTEND_DEPTH);
    if depth < 1 {
        return "./".to_owned();
    }
    "../".repeat(depth)
}

fn header_first(headers: &HeaderMap, name: http::header::HeaderName) -> &str {
    headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("")
}

/// Answer with a prepared file: the validators, the cache rule and, when the client accepts it, the gzip body. A
/// range and a `HEAD` get the plain body.
pub async fn serve_frontend_entry(
    method: &Method,
    request: &HeaderMap,
    content_type: &'static str,
    cache_control: &'static str,
    entry: &StaticEntry,
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(cache_control));
    if let Ok(value) = HeaderValue::from_str(&entry.etag) {
        headers.insert(ETAG, value);
    }
    headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
    let mut body = entry.data.clone();
    if *method == Method::GET
        && header_first(request, RANGE).is_empty()
        && accepts_gzip(request)
        && compressible_content_type(content_type)
    {
        body = entry.gzip().await;
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    serve_content(method, request, headers, body)
}

/// The answer to an unknown address: the styled 404 page for a browser navigation (`GET` that accepts `text/html`),
/// and the plain `404 page not found` for each other request.
pub fn not_found_page(method: &Method, request: &HeaderMap, path: &str) -> Response {
    if *method != Method::GET || !header_first(request, http::header::ACCEPT).contains("text/html") {
        return not_found();
    }
    let Some(data) = assets::file("404.html") else {
        return not_found();
    };
    let data = replace_all(data, BASE_PLACEHOLDER.as_bytes(), frontend_base_href(path).as_bytes());
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    answer(404, headers, full(data))
}

/// Answer with a page of the interface (`/index.html`, `/preview.html` or `/info.html`) for a base address.
async fn serve_embedded_frontend(method: &Method, request: &HeaderMap, requested: &str, base_href: &str) -> Response {
    let name = requested.trim_start_matches('/');
    let version = frontend_version();
    let entry = static_cache().prepared(version, name, base_href, || {
        let data = assets::file(name).ok_or_else(|| Error::internal(format!("open {name}: file does not exist")))?;
        let data = replace_all(data, BASE_PLACEHOLDER.as_bytes(), base_href.as_bytes());
        Ok(version_html(&data, version))
    });
    match entry {
        Ok(entry) => serve_frontend_entry(method, request, "text/html; charset=utf-8", "no-cache", &entry).await,
        Err(_) => not_found(),
    }
}

fn file_exists(name: &str) -> bool {
    assets::file(name).is_some() || assets::is_folder(name)
}

/// Answer with a file of the interface that is not a page.
async fn serve_embedded_file(req: &super::RequestHead, requested: &str) -> Response {
    let name = requested.trim_start_matches('/');
    if assets::file(name).is_none() {
        return not_found_page(&req.method, &req.headers, &req.path);
    }
    let extension = paths::ext(requested).to_ascii_lowercase();
    let content_type = type_by_extension(&extension);
    let version = frontend_version();
    let entry = static_cache().prepared(version, name, "", || {
        let data = assets::file(name).ok_or_else(|| Error::internal(format!("open {name}: file does not exist")))?;
        if extension == ".css" {
            return Ok(version_css(data, version));
        }
        Ok(data.to_vec())
    });
    let Ok(entry) = entry else {
        return crate::common::http::text_error(500, "read embedded file");
    };
    let cache_control = if requested.starts_with("/assets/vendor/") || req.query.get("v") == version {
        IMMUTABLE
    } else {
        "no-cache"
    };
    serve_frontend_entry(&req.method, &req.headers, content_type, cache_control, &entry).await
}

/// The handler of `/`: the pages and the assets of the interface.
pub fn handle_static(app: Arc<App>, req: Req) -> crate::common::BoxFuture<'static, Response> {
    Box::pin(async move {
        let _ = app;
        let req = super::split(req).0;
        if req.method != Method::GET && req.method != Method::HEAD {
            return method_not_allowed(&["GET", "HEAD"]);
        }
        if frontend_depth(&req.path) > MAX_FRONTEND_DEPTH {
            return not_found();
        }
        let mut requested = paths::clean(&format!("/{}", req.path));
        if requested == "/" {
            requested = "/index.html".to_owned();
        } else {
            let last = requested.rsplit('/').next().unwrap_or("");
            if !last.contains('.') {
                let candidate = format!("{requested}.html");
                if file_exists(candidate.trim_start_matches('/')) {
                    requested = candidate;
                }
            }
        }
        if matches!(requested.as_str(), "/index.html" | "/preview.html" | "/info.html") {
            let base = frontend_base_href(&req.path);
            return serve_embedded_frontend(&req.method, &req.headers, &requested, &base).await;
        }
        serve_embedded_file(&req, &requested).await
    })
}

/// The handler of `/-/<host>/<bucket>/...`: the browser page of a folder (a path that ends with `/`), the information
/// page of an instance (`/-/<host>/<bucket>/?info`), and the preview page of an object.
pub fn handle_storage_frontend(app: Arc<App>, req: Req) -> crate::common::BoxFuture<'static, Response> {
    Box::pin(async move {
        let req = super::split(req).0;
        if req.method != Method::GET && req.method != Method::HEAD {
            return method_not_allowed(&["GET", "HEAD"]);
        }
        if frontend_depth(&req.path) > MAX_FRONTEND_DEPTH {
            return not_found();
        }
        let relative = req.path.strip_prefix("/-/").unwrap_or("");
        if relative.is_empty() {
            return not_found_page(&req.method, &req.headers, &req.path);
        }
        let trailing = req.path.ends_with('/');
        let trimmed = relative.strip_suffix('/').unwrap_or(relative);
        let segments: Vec<&str> = trimmed.split('/').collect();
        if segments.len() >= 2 {
            let (host, bucket) = (segments[0], segments[1]);
            let known = app
                .instances
                .iter()
                .any(|instance| instance.cfg.id == bucket && instance.cfg.auth_id == host);
            if known {
                if segments.len() == 2 && !trailing {
                    let mut target = format!("{bucket}/");
                    if !req.raw_query.is_empty() {
                        target.push('?');
                        target.push_str(&req.raw_query);
                    }
                    let mut headers = HeaderMap::new();
                    if let Ok(value) = HeaderValue::from_bytes(target.as_bytes()) {
                        headers.insert(LOCATION, value);
                    }
                    return answer(308, headers, empty());
                }
                let requested = if !trailing {
                    "/preview.html"
                } else if segments.len() == 2 && req.query.has("info") {
                    "/info.html"
                } else {
                    "/index.html"
                };
                let base = frontend_base_href(&req.path);
                return serve_embedded_frontend(&req.method, &req.headers, requested, &base).await;
            }
        }
        not_found_page(&req.method, &req.headers, &req.path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_get_the_fingerprint_on_each_local_asset() {
        let html = br#"<meta content="{{ASSET_VERSION}}"><link href="assets/a.css"><script src="assets/b.js?x=1"></script><img data-src="assets/c.png"><a href="https://x/assets/d">"#;
        let out = String::from_utf8(version_html(html, "abc")).unwrap();
        assert_eq!(
            out,
            r#"<meta content="abc"><link href="assets/a.css?v=abc"><script src="assets/b.js?x=1"></script><img data-src="assets/c.png?v=abc"><a href="https://x/assets/d">"#
        );
    }

    #[test]
    fn stylesheets_get_the_fingerprint_on_icons_and_imports() {
        let css = br#"@import url("dialogs.css"); @import url("../x.css"); .a { --icon: url("../icons/tabler/folder.svg"); } .b { --icon: url("../icons/x.svg?y"); }"#;
        let out = String::from_utf8(version_css(css, "abc")).unwrap();
        assert_eq!(
            out,
            r#"@import url("dialogs.css?v=abc"); @import url("../x.css"); .a { --icon: url("../icons/tabler/folder.svg?v=abc"); } .b { --icon: url("../icons/x.svg?y"); }"#
        );
    }

    #[test]
    fn the_fingerprint_walks_the_folders_in_order() {
        let a: &[(&str, &[u8])] = &[("a/x", b"1"), ("a-b", b"2")];
        let b: &[(&str, &[u8])] = &[("a-b", b"2"), ("a/x", b"1")];
        assert_eq!(fingerprint(a), fingerprint(b));
        assert_eq!(fingerprint(a).len(), 12);
        assert_eq!(frontend_version().len(), 12);
    }
}
