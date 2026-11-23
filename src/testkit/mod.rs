//! The test kit: an in-memory back end and the helpers that the tests of each work package share. The work
//! package `instance` owns this folder; it completes the back end (ranges, conditions, multipart, versions) for the
//! tests that need them.

use std::collections::BTreeMap;
use std::sync::Mutex;

use bytes::Bytes;
use http::HeaderMap;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, ETAG, HeaderValue};

use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, empty, full, read_limited};
use crate::common::misc::hex;
use crate::common::storage::{Backend, DiscoveredCapabilities, ListOptions, ListPage, ObjectInfo, ObjectResponse};

/// One object of the memory back end.
#[derive(Clone, Debug, Default)]
pub struct MemoryObject {
    /// The bytes.
    pub data: Bytes,
    /// The media type.
    pub content_type: String,
}

/// A back end that keeps its objects in memory.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    /// The objects by full key.
    pub objects: Mutex<BTreeMap<String, MemoryObject>>,
}

impl MemoryBackend {
    /// A back end with these objects (key and text).
    pub fn with_objects(objects: &[(&str, &str)]) -> Self {
        let map = objects
            .iter()
            .map(|(key, text)| {
                (
                    (*key).to_owned(),
                    MemoryObject {
                        data: Bytes::from(text.to_string()),
                        content_type: String::new(),
                    },
                )
            })
            .collect();
        Self {
            objects: Mutex::new(map),
        }
    }

    fn snapshot(&self) -> BTreeMap<String, MemoryObject> {
        self.objects.lock().map(|objects| objects.clone()).unwrap_or_default()
    }

    fn etag(data: &[u8]) -> String {
        hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data).as_ref())
            .chars()
            .take(32)
            .collect()
    }

    fn headers(object: &MemoryObject) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(&object.data.len().to_string()) {
            headers.insert(CONTENT_LENGTH, value);
        }
        if let Ok(value) = HeaderValue::from_str(&format!("\"{}\"", Self::etag(&object.data))) {
            headers.insert(ETAG, value);
        }
        if let Ok(value) = HeaderValue::from_str(&object.content_type)
            && !object.content_type.is_empty()
        {
            headers.insert(CONTENT_TYPE, value);
        }
        headers
    }

    fn missing() -> Error {
        Error::upstream(404, "NoSuchKey", "The specified key does not exist.")
    }
}

impl Backend for MemoryBackend {
    fn list<'a>(&'a self, _ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        let objects = self.snapshot();
        Box::pin(async move {
            let mut page = ListPage::default();
            let limit = if options.max_results == 0 {
                1000
            } else {
                options.max_results as usize
            };
            let after = if options.page_token.is_empty() {
                options.start_after.clone()
            } else {
                options.page_token.clone()
            };
            let mut count = 0;
            let mut last = String::new();
            for (key, object) in objects.range(options.prefix.clone()..) {
                if !key.starts_with(&options.prefix) {
                    break;
                }
                let rest = &key[options.prefix.len()..];
                let entry = match (options.delimiter.is_empty(), rest.find(&options.delimiter)) {
                    (false, Some(index)) => format!("{}{}", options.prefix, &rest[..index + options.delimiter.len()]),
                    _ => key.clone(),
                };
                if !after.is_empty() && entry.as_str() <= after.as_str() {
                    continue;
                }
                if entry != *key {
                    if page.prefixes.last() != Some(&entry) {
                        if count == limit {
                            page.next_page_token = last;
                            return Ok(page);
                        }
                        page.prefixes.push(entry.clone());
                        count += 1;
                        last = entry;
                    }
                    continue;
                }
                if count == limit {
                    page.next_page_token = last;
                    return Ok(page);
                }
                page.objects.push(ObjectInfo {
                    key: key.clone(),
                    size: object.data.len() as i64,
                    etag: Self::etag(&object.data),
                    content_type: object.content_type.clone(),
                    ..ObjectInfo::default()
                });
                count += 1;
                last = key.clone();
            }
            Ok(page)
        })
    }

    fn head<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        let object = self.snapshot().get(key).cloned();
        Box::pin(async move {
            let object = object.ok_or_else(Self::missing)?;
            Ok(ObjectResponse {
                status: 200,
                headers: Self::headers(&object),
                body: empty(),
            })
        })
    }

    fn get<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        let object = self.snapshot().get(key).cloned();
        Box::pin(async move {
            let object = object.ok_or_else(Self::missing)?;
            Ok(ObjectResponse {
                status: 200,
                headers: Self::headers(&object),
                body: full(object.data.clone()),
            })
        })
    }

    fn put<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        _size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let (data, _) = read_limited(body, usize::MAX).await?;
            if let Ok(mut objects) = self.objects.lock() {
                objects.insert(
                    key.to_owned(),
                    MemoryObject {
                        data,
                        content_type: content_type.to_owned(),
                    },
                );
            }
            Ok(())
        })
    }

    fn delete<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if let Ok(mut objects) = self.objects.lock() {
                objects.remove(key);
            }
            Ok(())
        })
    }

    fn copy<'a>(&'a self, _ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut objects = self.objects.lock().map_err(|_| Error::internal("lock"))?;
            let object = objects.get(source).cloned().ok_or_else(Self::missing)?;
            objects.insert(destination.to_owned(), object);
            Ok(())
        })
    }

    fn discover_capabilities<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        Box::pin(async move { Ok(DiscoveredCapabilities::default()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_memory_back_end_lists_one_folder_in_pages() {
        let backend = MemoryBackend::with_objects(&[("a/1", "x"), ("a/2", "y"), ("b/1", "z"), ("c", "w")]);
        let ctx = OpCtx::default();
        let options = ListOptions {
            delimiter: "/".to_owned(),
            max_results: 2,
            ..ListOptions::default()
        };
        let page = backend.list(&ctx, &options).await.unwrap();
        assert_eq!(page.prefixes, vec!["a/", "b/"]);
        assert_eq!(page.next_page_token, "b/");
        let next = ListOptions {
            page_token: page.next_page_token.clone(),
            ..options
        };
        let page = backend.list(&ctx, &next).await.unwrap();
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "c");
        assert!(page.next_page_token.is_empty());
    }
}
