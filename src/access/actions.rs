// SPDX-License-Identifier: MIT OR Apache-2.0
//! The action document of the service (ProcurAuth 5.1 to 5.5a).
//!
//! The service builds the document one time at start, from the typed configuration, and it serves the same bytes on
//! each read. In mode `open` the service builds no document.

use std::collections::{BTreeMap, BTreeSet};

use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Method};
use serde::Serialize;

use super::tree::{TYPE_BUCKET, TYPE_FOLDER, TYPE_SERVICE, TYPE_SUBFOLDER, percent_encode_id};
use super::{ACTION_BUCKET_ADMIN, ACTION_DELETE, ACTION_LOCK, ACTION_READ, ACTION_WRITE};
use crate::common::config::{Config, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::error::{Error, Result};
use crate::common::http::{Response, answer, empty, full, method_not_allowed, not_found};

/// The path of the action document.
pub const ACTIONS_PATH: &str = "/.well-known/procurauth/actions";
/// The budget `writes`.
pub const LIMIT_WRITES: &str = "writes";
/// The ceiling `max_object_size`.
pub const LIMIT_MAX_OBJECT_SIZE: &str = "max_object_size";
/// The size that each reader accepts (ProcurAuth 5.3c).
pub const MAX_DOCUMENT_BYTES: usize = 64 << 10;
/// The longest label that each reader accepts (ProcurAuth 5.3c).
pub const MAX_LABEL_CHARS: usize = 60;
/// The largest object of the S3 protocol: 5 TiB.
pub const MAX_OBJECT_SIZE_CEILING: i64 = 5_497_558_138_880;

const KIND_BUDGET: &str = "budget";
const KIND_CEILING: &str = "ceiling";

/// The four types of the tree.
pub const ALL_TYPES: [&str; 4] = [TYPE_SERVICE, TYPE_BUCKET, TYPE_FOLDER, TYPE_SUBFOLDER];

/// One resource type of the document.
#[derive(Clone, Debug, Serialize)]
pub struct DocumentType {
    /// The name.
    pub name: &'static str,
    /// The parent.
    pub parent: &'static str,
    /// The text.
    pub description: &'static str,
}

/// One action of the document.
#[derive(Clone, Debug, Serialize)]
pub struct DocumentAction {
    /// The name.
    pub name: &'static str,
    /// The types where a grant of the action is valid.
    pub resource_types: &'static [&'static str],
    /// The text.
    pub description: &'static str,
    /// The names of the limits.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub limits: &'static [&'static str],
}

/// One node that the service names. It has no `actions` member: it takes each action that lists its type.
#[derive(Clone, Debug, Serialize)]
struct DocumentResource {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

/// One limit declaration. A budget has no `min` and no `max`. A ceiling has both.
#[derive(Clone, Debug, Serialize)]
pub struct DocumentLimit {
    /// The name.
    pub name: &'static str,
    /// The label.
    pub label: &'static str,
    /// The text.
    pub description: &'static str,
    /// The unit: a singular noun for a budget, a plural noun for a ceiling.
    pub unit: &'static str,
    /// `budget` or `ceiling`.
    pub kind: &'static str,
    /// The smallest value of a ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    /// The largest value of a ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
}

#[derive(Serialize)]
struct DocumentBody<'a> {
    server: &'a str,
    resource_types: &'a [DocumentType],
    actions: Vec<DocumentAction>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    resources: Vec<DocumentResource>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    limits: Vec<DocumentLimit>,
}

/// The actions in the order of the document, with their text and their limits.
pub const ACTION_ROWS: [DocumentAction; 5] = [
    DocumentAction {
        name: ACTION_READ,
        resource_types: &ALL_TYPES,
        description: "List, preview, inspect and download objects. Show versions, tags, metadata, usage and archive entries. Check the integrity of an object.",
        limits: &[LIMIT_MAX_OBJECT_SIZE],
    },
    DocumentAction {
        name: ACTION_WRITE,
        resource_types: &ALL_TYPES,
        description: "Upload objects, make folders, restore versions, and change tags and metadata. Be the destination of a copy, a move or an extraction.",
        limits: &[LIMIT_WRITES, LIMIT_MAX_OBJECT_SIZE],
    },
    DocumentAction {
        name: ACTION_DELETE,
        resource_types: &ALL_TYPES,
        description: "Delete objects, versions and folders. Be the source of a move or a rename.",
        limits: &[LIMIT_WRITES],
    },
    DocumentAction {
        name: ACTION_LOCK,
        resource_types: &ALL_TYPES,
        description: "Set or remove a legal hold. Set, extend or shorten the retention of an object version.",
        limits: &[LIMIT_WRITES],
    },
    DocumentAction {
        name: ACTION_BUCKET_ADMIN,
        resource_types: &[TYPE_SERVICE, TYPE_BUCKET],
        description: "Change the lifecycle rules of a bucket.",
        limits: &[LIMIT_WRITES],
    },
];

/// The types below the service, from the top.
pub const RESOURCE_TYPES: [DocumentType; 3] = [
    DocumentType {
        name: TYPE_BUCKET,
        parent: TYPE_SERVICE,
        description: "One bucket block or one volume block of the configuration. The id is the label of the block.",
    },
    DocumentType {
        name: TYPE_FOLDER,
        parent: TYPE_BUCKET,
        description: "One top-level folder of a bucket or a volume, below its root prefix. The id is the first part of the object key.",
    },
    DocumentType {
        name: TYPE_SUBFOLDER,
        parent: TYPE_FOLDER,
        description: "One folder in a top-level folder. The id is the second part of the object key.",
    },
];

/// The limits that the service can declare, in the order of the document.
pub const LIMIT_DECLARATIONS: [DocumentLimit; 2] = [
    DocumentLimit {
        name: LIMIT_WRITES,
        label: "Writes",
        description: "Operations that change objects or bucket settings.",
        unit: "operation",
        kind: KIND_BUDGET,
        min: None,
        max: None,
    },
    DocumentLimit {
        name: LIMIT_MAX_OBJECT_SIZE,
        label: "Largest object",
        description: "The largest object that one use reads or writes, in bytes.",
        unit: "bytes",
        kind: KIND_CEILING,
        min: Some(1),
        max: Some(MAX_OBJECT_SIZE_CEILING),
    },
];

/// The action document, built one time. The default value is the document of mode `open`: it publishes nothing.
#[derive(Clone, Debug, Default)]
pub struct ActionDocument {
    raw: Vec<u8>,
    actions: BTreeMap<&'static str, DocumentAction>,
    limits: BTreeMap<&'static str, DocumentLimit>,
}

/// The permission list of a block gives a permission. A block without a list gives read, write and delete. This is
/// the process ceiling without the provider probes.
fn instance_allows(permissions: &[String], defined: bool, permission: &str) -> bool {
    !defined || permissions.iter().any(|value| value == permission)
}

/// The label of a block: its name, only when the name has 1 to 60 characters and no control character.
pub fn block_label(name: &str) -> Option<&str> {
    let count = name.chars().count();
    ((1..=MAX_LABEL_CHARS).contains(&count) && !super::tree::has_control_character(name)).then_some(name)
}

impl ActionDocument {
    /// Build the document from the configuration. In mode `open` it builds nothing. In mode `authzen` it gives an
    /// error when the JSON is larger than 64 KiB (ProcurAuth 5.3c).
    pub fn build(config: &Config) -> Result<Self> {
        if !config.access.enforced() {
            return Ok(Self::default());
        }
        let read_only = config.runtime.force_read_only();
        // One bucket block gives read and write: Object Lock and the lifecycle rules need both, and a volume has
        // neither feature.
        let (mut read, mut write, mut delete, mut bucket_read_write) = (false, false, false, false);
        for bucket in &config.buckets {
            let r = instance_allows(&bucket.permissions, bucket.permissions_defined, PERMISSION_READ);
            let w = instance_allows(&bucket.permissions, bucket.permissions_defined, PERMISSION_WRITE);
            read |= r;
            write |= w;
            bucket_read_write |= r && w;
            delete |= instance_allows(&bucket.permissions, bucket.permissions_defined, PERMISSION_DELETE);
        }
        for volume in &config.volumes {
            read |= instance_allows(&volume.permissions, volume.permissions_defined, PERMISSION_READ);
            write |= instance_allows(&volume.permissions, volume.permissions_defined, PERMISSION_WRITE);
            delete |= instance_allows(&volume.permissions, volume.permissions_defined, PERMISSION_DELETE);
        }
        let serves_write = !read_only && write;
        let serves = |name: &str| match name {
            ACTION_READ => read,
            ACTION_WRITE => serves_write,
            ACTION_DELETE => !read_only && delete,
            ACTION_LOCK | ACTION_BUCKET_ADMIN => serves_write && bucket_read_write,
            _ => false,
        };

        let mut document = Self::default();
        let mut listed = BTreeSet::new();
        let mut actions = Vec::new();
        for row in ACTION_ROWS {
            if !serves(row.name) {
                continue;
            }
            listed.extend(row.limits.iter().copied());
            document.actions.insert(row.name, row.clone());
            actions.push(row);
        }
        let mut limits = Vec::new();
        for limit in LIMIT_DECLARATIONS {
            if listed.contains(limit.name) {
                document.limits.insert(limit.name, limit.clone());
                limits.push(limit);
            }
        }
        let resources = config
            .buckets
            .iter()
            .map(|bucket| (bucket.id.as_str(), bucket.name.as_str()))
            .chain(
                config
                    .volumes
                    .iter()
                    .map(|volume| (volume.id.as_str(), volume.name.as_str())),
            )
            .map(|(id, name)| DocumentResource {
                path: format!("{TYPE_BUCKET}:{}", percent_encode_id(id)),
                label: block_label(name).map(str::to_owned),
            })
            .collect();
        let body = DocumentBody {
            server: config.access.audience(),
            resource_types: &RESOURCE_TYPES,
            actions,
            resources,
            limits,
        };
        document.raw = super::plain_json(&body)?;
        if document.raw.len() > MAX_DOCUMENT_BYTES {
            return Err(Error::internal(format!(
                "the action document has {} bytes, and the limit is {MAX_DOCUMENT_BYTES} bytes (ProcurAuth 5.3c): use fewer bucket blocks and volume blocks, or shorter labels and names",
                document.raw.len()
            )));
        }
        Ok(document)
    }

    /// The bytes of the document. The bytes are empty in mode `open`.
    pub fn json(&self) -> &[u8] {
        &self.raw
    }

    /// True when the document has the action.
    pub fn published(&self, action: &str) -> bool {
        self.actions.contains_key(action)
    }

    /// The published action, when the document has it.
    pub fn action(&self, action: &str) -> Option<&DocumentAction> {
        self.actions.get(action)
    }

    /// The published actions, in the order of the document.
    pub fn published_actions(&self) -> Vec<&'static str> {
        ACTION_ROWS
            .iter()
            .filter(|row| self.published(row.name))
            .map(|row| row.name)
            .collect()
    }

    /// The declared limits, in the order of the document.
    pub fn declared_limits(&self) -> Vec<&DocumentLimit> {
        LIMIT_DECLARATIONS
            .iter()
            .filter_map(|limit| self.limits.get(limit.name))
            .collect()
    }

    /// True when the published action lists a budget.
    pub fn lists_budget(&self, action: &str) -> bool {
        self.actions
            .get(action)
            .is_some_and(|row| row.limits.iter().any(|name| self.is_budget(name)))
    }

    /// True when the published action lists the ceiling.
    pub fn lists_ceiling(&self, action: &str, ceiling: &str) -> bool {
        let declared = self.limits.get(ceiling).is_some_and(|limit| limit.kind == KIND_CEILING);
        declared
            && self
                .actions
                .get(action)
                .is_some_and(|row| row.limits.contains(&ceiling))
    }

    /// True when the document declares the limit and the limit is a budget.
    pub fn is_budget(&self, name: &str) -> bool {
        self.limits.get(name).is_some_and(|limit| limit.kind == KIND_BUDGET)
    }

    /// The answer of a read of the document. It needs no identity token and never asks the PDP. In mode `open` the
    /// route does not exist.
    pub fn response(&self, enforced: bool, method: &Method) -> Response {
        if method != Method::GET && method != Method::HEAD {
            return method_not_allowed(&["GET", "HEAD"]);
        }
        if !enforced {
            return not_found();
        }
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(CONTENT_LENGTH, HeaderValue::from(self.raw.len()));
        let body = if method == Method::GET {
            full(self.raw.clone())
        } else {
            empty()
        };
        answer(200, headers, body)
    }
}

#[cfg(test)]
#[path = "actions_tests.rs"]
mod tests;
