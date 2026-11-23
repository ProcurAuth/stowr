//! The versions of the objects: the version calls of an instance, the start probe of the versioning, the status of
//! the bucket for `/api/instances`, the checksums of an answer, the order of the versions and the page token of the
//! S3 versions (docs/ARCHITECTURE.md, "Version capability and version access").

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::HeaderMap;
use serde::{Deserialize, Serialize};

use super::Instance;
use super::ceiling::{ACTION_READ, ACTION_WRITE, ceiling_applies, check_copy_ceilings, header_text};
use crate::bucket::{is_object_locked, kept_encryption_headers};
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::storage::{
    MultipartCopyOptions, ObjectResponse, ObjectVersionPage, StoredObjectVersion, VersionStore,
};

/// The time of the start probe of the versioning.
pub const VERSIONING_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn versioning_unavailable() -> Error {
    Error::api(
        501,
        "versioning_unavailable",
        "object versioning is not available for this storage bucket",
    )
}

fn version_required() -> Error {
    Error::api(400, "version_required", "version is required")
}

impl Instance {
    /// The version store of the back end. `501 versioning_unavailable` without one, or when the start probe found
    /// no versions.
    pub fn version_store(&self) -> Result<&dyn VersionStore> {
        match self.backend.version_store() {
            Some(store) if !(self.versioning_probe_finished() && !self.versioning_available()) => Ok(store),
            _ => Err(versioning_unavailable()),
        }
    }

    /// One page of the versions of one key.
    pub async fn list_versions(
        &self,
        ctx: &OpCtx,
        key: &str,
        page_token: &str,
        maximum: u32,
    ) -> Result<ObjectVersionPage> {
        let store = self.version_store()?;
        let _slot = self.begin_storage_request(ctx).await?;
        let result = ctx.run(store.list_versions(ctx, key, page_token, maximum)).await;
        self.observe_permission(PERMISSION_READ, result.as_ref().err());
        result
    }

    /// The headers of one version. An empty version reads the current object (or the version of the context).
    pub async fn head_version(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<ObjectResponse> {
        let version = version.trim();
        if version.is_empty() {
            return self.head(ctx, key).await;
        }
        self.head_stored_version(ctx, key, version).await
    }

    pub(crate) async fn head_stored_version(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<ObjectResponse> {
        let store = self.version_store()?;
        let _slot = self.begin_storage_request(ctx).await?;
        let result = match ctx.run(store.head_version(ctx, key, version)).await {
            Ok(response) if response.status == 401 || response.status == 403 => {
                Err(Error::upstream(response.status, "AccessDenied", ""))
            }
            other => other,
        };
        self.observe_permission(PERMISSION_READ, result.as_ref().err());
        result
    }

    /// The bytes of one version. An empty version reads the current object (or the version of the context). The
    /// ceiling `object.read` applies before any byte goes to the caller.
    pub async fn get_version(
        &self,
        ctx: &OpCtx,
        key: &str,
        version: &str,
        headers: &HeaderMap,
    ) -> Result<ObjectResponse> {
        let version = version.trim();
        if version.is_empty() {
            return self.get(ctx, key, headers).await;
        }
        self.get_stored_version(ctx, key, version, headers).await
    }

    pub(crate) async fn get_stored_version(
        &self,
        ctx: &OpCtx,
        key: &str,
        version: &str,
        headers: &HeaderMap,
    ) -> Result<ObjectResponse> {
        let store = self.version_store()?;
        let slot = self.begin_storage_request(ctx).await?;
        let headers = without_version_preconditions(headers);
        let result = ctx.run(store.get_version(ctx, key, version, &headers)).await;
        self.finish_read(ctx, slot, result)
    }

    /// Delete one version for ever. A refusal that an active Object Lock explains gives `409 object_locked`.
    pub async fn delete_version(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<()> {
        if version.trim().is_empty() {
            return Err(version_required());
        }
        let store = self.version_store()?;
        let slot = self.begin_storage_request(ctx).await?;
        let result = store.delete_version(ctx, key, version).await;
        drop(slot);
        match result {
            Ok(()) => {
                self.observe_permission(PERMISSION_DELETE, None);
                Ok(())
            }
            Err(error) => {
                // SeaweedFS refuses the delete of a locked version with 403: that refusal says nothing about the
                // delete permission.
                let error = self.explain_lock_refusal(ctx, key, version, error).await;
                if !is_object_locked(&error) {
                    self.observe_permission(PERMISSION_DELETE, Some(&error));
                }
                Err(error)
            }
        }
    }

    /// Copy one version onto its key. A version from the copy threshold up goes in parts. The copy sends the SSE-S3
    /// or SSE-KMS headers of the version: the restored object keeps its encryption. A ceiling of read or write
    /// applies to the size of the version, which a HEAD gives before the restore.
    pub async fn restore_version(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<()> {
        if version.trim().is_empty() {
            return Err(version_required());
        }
        let store = self.version_store()?;
        let mut kept = HeaderMap::new();
        let in_parts = self.backend.multipart_copier().is_some();
        let bound = ceiling_applies(ctx, &[ACTION_READ, ACTION_WRITE]);
        if in_parts || bound {
            match self.head_version(ctx, key, version).await {
                Ok(response) => {
                    let size = header_text(&response.headers, "content-length").parse::<i64>();
                    if bound {
                        let known = match size {
                            Ok(value) if value >= 0 => value,
                            _ => -1,
                        };
                        check_copy_ceilings(ctx, known)?;
                    }
                    if in_parts {
                        kept = kept_encryption_headers(&response.headers);
                        if let Ok(size) = size
                            && self.copies_in_parts(size)
                        {
                            let options = MultipartCopyOptions {
                                source_version: version.to_owned(),
                                extra_headers: kept,
                                ..MultipartCopyOptions::default()
                            };
                            return self.copy_multipart_object(ctx, key, key, options).await;
                        }
                    }
                }
                // A failed HEAD stops the restore when a ceiling applies. Else the restore gives the error of the
                // provider.
                Err(error) if bound => return Err(error),
                Err(_) => {}
            }
        }
        let _slot = self.begin_storage_request(ctx).await?;
        let result = store.restore_version(ctx, key, version, &kept).await;
        match &result {
            Ok(()) => {
                self.observe_permission(PERMISSION_READ, None);
                self.observe_permission(PERMISSION_WRITE, None);
            }
            Err(error) => self.observe_permission(PERMISSION_WRITE, Some(error)),
        }
        result
    }

    /// True when the start probe found the versions. False before the probe, and when the provider refused the list
    /// of the versions or does not know it.
    pub fn versioning_available(&self) -> bool {
        self.versioning
            .probe
            .lock()
            .map(|probe| probe.1 && probe.0)
            .unwrap_or(false)
    }

    /// True after the start probe of the versioning.
    pub fn versioning_probe_finished(&self) -> bool {
        self.versioning.probe.lock().map(|probe| probe.1).unwrap_or(false)
    }

    /// Keep the result of the start probe of the versioning.
    pub fn set_versioning_available(&self, supported: bool) {
        if let Ok(mut probe) = self.versioning.probe.lock() {
            *probe = (supported, true);
        }
    }

    /// Keep the last status of `GetBucketVersioning` that the server read.
    pub fn set_versioning_status(&self, status: &str) {
        if let Ok(mut current) = self.versioning.status.lock() {
            *current = Some(status.to_owned());
        }
    }

    /// The start probe of the versioning: one bounded list of the versions, at most 5 seconds. A refused, unknown
    /// or failed list hides the versions and does not stop the start. With the versions, the probe also reads the
    /// status of the bucket for `/api/instances`; a failure of that read hides the status only.
    pub async fn probe_versioning(&self, ctx: &OpCtx) -> bool {
        if self.backend.version_store().is_none() {
            self.set_versioning_available(false);
            return false;
        }
        let probe = ctx.with_timeout(VERSIONING_PROBE_TIMEOUT);
        let supported = self.list_versions(&probe, &self.cfg.root_prefix, "", 1).await.is_ok();
        self.set_versioning_available(supported);
        if supported
            && let Some(rules) = self.backend.bucket_rules()
            && let Ok(status) = probe.run(rules.versioning_status(&probe)).await
        {
            self.set_versioning_status(&status);
        }
        supported
    }

    /// The versioning of the bucket for `/api/instances`: `enabled`, `suspended`, `off`, or `None` when the server
    /// has no status. A provider without versions is `off`.
    pub fn versioning_state(&self) -> Option<&'static str> {
        let (supported, checked) = self.versioning.probe.lock().map(|probe| *probe).unwrap_or_default();
        if checked && !supported {
            return Some("off");
        }
        let status = self.versioning.status.lock().ok().and_then(|status| status.clone())?;
        Some(match status.as_str() {
            "Enabled" => "enabled",
            "Suspended" => "suspended",
            _ => "off",
        })
    }
}

/// The headers of a read that names a version, without `If-Match` and `If-Unmodified-Since`. The bytes of a version
/// never change: the precondition adds no safety. A provider can also compare `If-Match` with the current object
/// instead of the version: SeaweedFS then answers 412 for each older version. The caller still compares the ETag of
/// the answer with the ETag that it expects.
pub fn without_version_preconditions(headers: &HeaderMap) -> HeaderMap {
    let mut clean = headers.clone();
    clean.remove(http::header::IF_MATCH);
    clean.remove(http::header::IF_UNMODIFIED_SINCE);
    clean
}

/// The checksums of the headers of an answer, by algorithm: `sha256`, `sha1`, `crc32c`, `crc32`, `md5`. An ETag of
/// a multipart upload is never a hash: it is not used.
pub fn provider_checksums(headers: &HeaderMap) -> BTreeMap<String, String> {
    const CANDIDATES: [(&str, &[&str]); 5] = [
        ("sha256", &["x-amz-checksum-sha256", "x-goog-hash-sha256"]),
        ("sha1", &["x-amz-checksum-sha1"]),
        ("crc32c", &["x-amz-checksum-crc32c", "x-goog-hash-crc32c"]),
        ("crc32", &["x-amz-checksum-crc32"]),
        ("md5", &["content-md5", "x-goog-hash-md5"]),
    ];
    let mut out = BTreeMap::new();
    for (algorithm, names) in CANDIDATES {
        for name in names {
            let value = header_text(headers, name);
            if value.is_empty() {
                continue;
            }
            out.insert(algorithm.to_owned(), value.trim_matches('"').to_owned());
            break;
        }
    }
    for combined in headers.get_all("x-goog-hash") {
        let Ok(combined) = combined.to_str() else {
            continue;
        };
        for item in combined.split(',') {
            let Some((name, value)) = item.trim().split_once('=') else {
                continue;
            };
            if value.trim().is_empty() {
                continue;
            }
            let name = name.trim().to_lowercase();
            if name == "crc32c" || name == "md5" {
                out.insert(name, value.trim().to_owned());
            }
        }
    }
    out
}

/// Sort versions: the current version first, then the newer change first, then the larger version id first.
pub fn sort_versions(versions: &mut [StoredObjectVersion]) {
    versions.sort_by(|left, right| {
        right
            .is_current
            .cmp(&left.is_current)
            .then_with(|| {
                right
                    .last_modified
                    .unwrap_or_default()
                    .cmp(&left.last_modified.unwrap_or_default())
            })
            .then_with(|| right.version.cmp(&left.version))
    });
}

/// The position in the list of the versions of S3: the page token of `/api/versions`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3VersionCursor {
    /// `key-marker`.
    #[serde(rename = "keyMarker", default, skip_serializing_if = "String::is_empty")]
    pub key_marker: String,
    /// `version-id-marker`.
    #[serde(rename = "versionIdMarker", default, skip_serializing_if = "String::is_empty")]
    pub version_id_marker: String,
}

/// The page token of a position in the list of the versions of S3: the JSON text in unpadded URL-safe base64.
pub fn encode_s3_version_cursor(cursor: &S3VersionCursor) -> String {
    let json = crate::common::json::to_vec(cursor).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(json)
}

/// Read a page token of the versions of S3. An empty token is the first page.
pub fn decode_s3_version_cursor(token: &str) -> Result<S3VersionCursor> {
    if token.trim().is_empty() {
        return Ok(S3VersionCursor::default());
    }
    let data = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|error| Error::internal(format!("decode version page token: {error}")))?;
    serde_json::from_slice(&data).map_err(|error| Error::internal(format!("decode version page token: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::time::Timestamp;

    #[test]
    fn a_read_of_a_version_keeps_the_range_and_drops_the_preconditions() {
        let mut headers = HeaderMap::new();
        headers.insert("Range", "bytes=0-9".parse().unwrap());
        headers.insert("If-Match", "\"abc\"".parse().unwrap());
        headers.insert("If-Unmodified-Since", "Mon, 02 Jan 2006 15:04:05 GMT".parse().unwrap());
        let clean = without_version_preconditions(&headers);
        assert_eq!(clean.get("Range").unwrap(), "bytes=0-9");
        assert!(clean.get("If-Match").is_none());
        assert!(clean.get("If-Unmodified-Since").is_none());
        assert!(headers.get("If-Match").is_some(), "the headers of the caller changed");
        let mut plain = HeaderMap::new();
        plain.insert("Range", "bytes=0-9".parse().unwrap());
        assert_eq!(without_version_preconditions(&plain).get("Range").unwrap(), "bytes=0-9");
    }

    #[test]
    fn the_checksums_come_from_the_provider_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-checksum-sha256", "\"abc=\"".parse().unwrap());
        headers.insert("content-md5", "md5value".parse().unwrap());
        headers.append("x-goog-hash", "crc32c=AAAA, md5=BBBB".parse().unwrap());
        headers.append("x-goog-hash", "other=1,crc32c=".parse().unwrap());
        let checksums = provider_checksums(&headers);
        assert_eq!(checksums["sha256"], "abc=");
        assert_eq!(checksums["md5"], "BBBB");
        assert_eq!(checksums["crc32c"], "AAAA");
        assert_eq!(checksums.len(), 3);
        assert!(provider_checksums(&HeaderMap::new()).is_empty());
    }

    #[test]
    fn the_current_version_comes_first_then_the_newest() {
        let version = |id: &str, current: bool, secs: i64| StoredObjectVersion {
            version: id.to_owned(),
            is_current: current,
            last_modified: Some(Timestamp::from_unix(secs, 0)),
            ..StoredObjectVersion::default()
        };
        let mut versions = vec![
            version("a", false, 10),
            version("b", false, 20),
            version("c", true, 5),
            version("d", false, 20),
        ];
        sort_versions(&mut versions);
        let order: Vec<&str> = versions.iter().map(|value| value.version.as_str()).collect();
        assert_eq!(order, vec!["c", "d", "b", "a"]);
    }

    #[test]
    fn the_page_token_of_the_versions_goes_and_comes_back() {
        let cursor = S3VersionCursor {
            key_marker: "a/<b>.txt".to_owned(),
            version_id_marker: "v1".to_owned(),
        };
        let token = encode_s3_version_cursor(&cursor);
        assert!(!token.contains('='));
        assert_eq!(decode_s3_version_cursor(&token).unwrap(), cursor);
        assert_eq!(decode_s3_version_cursor(" ").unwrap(), S3VersionCursor::default());
        assert!(decode_s3_version_cursor("!!").is_err());
        assert_eq!(
            encode_s3_version_cursor(&S3VersionCursor::default()),
            URL_SAFE_NO_PAD.encode("{}")
        );
    }
}
