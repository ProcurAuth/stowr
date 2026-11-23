// SPDX-License-Identifier: MIT OR Apache-2.0
//! The resource tree of the access policy (docs/ACCESS.md, "The resource tree").
//!
//! ```text
//! service (access.identity.audience)
//! └── bucket (the label of a bucket block or of a volume block)
//!     └── folder (the first part of the object key, below root_prefix)
//!         └── subfolder (the second part of the object key)
//! ```
//!
//! An object is not a node. The node of an object key or of a list prefix is the deepest folder that holds all the
//! keys of the operation. The guard sends this node and the chain of its ancestors to the PDP.

use serde::Serialize;
use serde::ser::SerializeStruct;

/// The type of the root node.
pub const TYPE_SERVICE: &str = "service";
/// The type of a bucket block or of a volume block.
pub const TYPE_BUCKET: &str = "bucket";
/// The type of a top-level folder.
pub const TYPE_FOLDER: &str = "folder";
/// The type of a folder in a top-level folder.
pub const TYPE_SUBFOLDER: &str = "subfolder";

/// The longest id of a node, in bytes.
pub const MAX_ID_BYTES: usize = 256;

/// The types below a bucket, from the top. The length of this list is the number of folder levels of the tree.
pub const FOLDER_TYPES: [&str; 2] = [TYPE_FOLDER, TYPE_SUBFOLDER];

/// One node of the resource tree: its type and its id.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize)]
pub struct Node {
    /// The type.
    #[serde(rename = "type")]
    pub node_type: String,
    /// The id, not encoded.
    pub id: String,
}

impl Node {
    /// A node of a type and an id.
    pub fn new(node_type: &str, id: &str) -> Self {
        Self {
            node_type: node_type.to_owned(),
            id: id.to_owned(),
        }
    }
}

/// The resource of a question: the node and the chain of its ancestors, from the service to the parent of the node.
/// The service has no ancestors.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Resource {
    /// The type of the node.
    pub node_type: String,
    /// The id of the node.
    pub id: String,
    /// The ancestors, from the service.
    pub ancestors: Vec<Node>,
}

impl Resource {
    /// The text form of the chain, for example `service:stowr/bucket:logs/folder:2026`. Each id is
    /// percent-encoded. The log, the cache and [`super::Ask`] use this form.
    pub fn path(&self) -> String {
        let mut out = String::new();
        for node in &self.ancestors {
            out.push_str(&node.node_type);
            out.push(':');
            out.push_str(&percent_encode_id(&node.id));
            out.push('/');
        }
        out.push_str(&self.node_type);
        out.push(':');
        out.push_str(&percent_encode_id(&self.id));
        out
    }

    /// Read the text form of a chain. `None` when a part has no `:`, a bad escape or an id that is not UTF-8.
    pub fn parse(text: &str) -> Option<Self> {
        let mut nodes = Vec::new();
        for part in text.split('/') {
            let (node_type, encoded) = part.split_once(':')?;
            let id = percent_decode(encoded.as_bytes())?;
            nodes.push(Node::new(node_type, &String::from_utf8(id).ok()?));
        }
        let last = nodes.pop()?;
        Some(Self {
            node_type: last.node_type,
            id: last.id,
            ancestors: nodes,
        })
    }

    /// The nodes from the service down to the node.
    pub fn nodes(&self) -> Vec<Node> {
        let mut nodes = self.ancestors.clone();
        nodes.push(Node {
            node_type: self.node_type.clone(),
            id: self.id.clone(),
        });
        nodes
    }

    /// The text form for the log. A folder id and a subfolder id are parts of object keys: without `detailed`, the
    /// log shows `-` in their place. The service id and the bucket id stay.
    pub fn logged_path(&self, detailed: bool) -> String {
        if detailed {
            return self.path();
        }
        let mask = |node_type: &str, id: &str| -> String {
            if node_type == TYPE_FOLDER || node_type == TYPE_SUBFOLDER {
                "-".to_owned()
            } else {
                id.to_owned()
            }
        };
        Self {
            node_type: self.node_type.clone(),
            id: mask(&self.node_type, &self.id),
            ancestors: self
                .ancestors
                .iter()
                .map(|node| Node {
                    node_type: node.node_type.clone(),
                    id: mask(&node.node_type, &node.id),
                })
                .collect(),
        }
        .path()
    }
}

/// The AuthZEN resource: a node below the service carries its chain in `properties.ancestors`. The service carries
/// no properties.
impl Serialize for Resource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Properties<'a> {
            ancestors: &'a [Node],
        }
        let with_properties = !self.ancestors.is_empty();
        let mut state = serializer.serialize_struct("Resource", if with_properties { 3 } else { 2 })?;
        state.serialize_field("type", &self.node_type)?;
        state.serialize_field("id", &self.id)?;
        if with_properties {
            state.serialize_field(
                "properties",
                &Properties {
                    ancestors: &self.ancestors,
                },
            )?;
        }
        state.end()
    }
}

/// Encode each byte outside `A-Z`, `a-z`, `0-9`, `-`, `.`, `_` and `~` as `%XX` with upper-case hexadecimal digits.
pub fn percent_encode_id(id: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(id.len());
    for &byte in id.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    out
}

/// Decode each `%XX` one time. `+` stays a `+`. A `%` without two hexadecimal digits gives `None`.
pub fn percent_decode(text: &[u8]) -> Option<Vec<u8>> {
    fn digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        if text[index] == b'%' {
            let high = text.get(index + 1).copied().and_then(digit)?;
            let low = text.get(index + 2).copied().and_then(digit)?;
            out.push(high << 4 | low);
            index += 3;
        } else {
            out.push(text[index]);
            index += 1;
        }
    }
    Some(out)
}

/// True when the text has a control character: a character below U+0020, or from U+007F to U+009F.
pub fn has_control_character(value: &str) -> bool {
    value
        .chars()
        .any(|c| (c as u32) < 0x20 || (0x7f..0xa0).contains(&(c as u32)))
}

/// True when a value can be the id of a node: 1 to 256 bytes of UTF-8 without a control character.
pub fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_ID_BYTES && !has_control_character(value)
}

/// True when bytes can be the id of a node: [`valid_id`] of bytes that must also be UTF-8.
pub fn valid_id_bytes(value: &[u8]) -> bool {
    std::str::from_utf8(value).is_ok_and(valid_id)
}

/// The node of the service. It has no ancestors.
pub fn service_resource(service: &str) -> Resource {
    Resource {
        node_type: TYPE_SERVICE.to_owned(),
        id: service.to_owned(),
        ancestors: Vec::new(),
    }
}

/// The node of a bucket block or of a volume block.
pub fn bucket_resource(service: &str, bucket: &str) -> Resource {
    Resource {
        node_type: TYPE_BUCKET.to_owned(),
        id: bucket.to_owned(),
        ancestors: vec![Node::new(TYPE_SERVICE, service)],
    }
}

/// The node of a key of a bucket. `relative` is the exact key or prefix that the route sends to the storage,
/// relative to `root_prefix`.
///
/// The function cuts the key at each `/` and removes the last part: the name of an object, the empty part after the
/// `/` at the end of a folder path, or the incomplete last part of a list prefix. The other parts give the folder
/// levels, from the top. The walk stops at the depth of the tree, and at the first part that cannot be an id. A walk
/// that stops early gives a node nearer to the bucket: a grant must then be broader, never narrower.
pub fn key_resource(service: &str, bucket: &str, relative: &str) -> Resource {
    let mut chain = vec![Node::new(TYPE_SERVICE, service), Node::new(TYPE_BUCKET, bucket)];
    let parts: Vec<&str> = relative.split('/').collect();
    let folders = &parts[..parts.len().saturating_sub(1)];
    for (level, part) in folders.iter().enumerate() {
        let Some(node_type) = FOLDER_TYPES.get(level) else {
            break;
        };
        if !valid_id(part) {
            break;
        }
        chain.push(Node::new(node_type, part));
    }
    let last = chain.pop().unwrap_or_default();
    Resource {
        node_type: last.node_type,
        id: last.id,
        ancestors: chain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_of_a_key_is_the_deepest_folder_of_the_key() {
        let long = "x".repeat(257);
        let long_key = format!("{long}/x");
        let cases: Vec<(&str, &str)> = vec![
            ("", "service:svc/bucket:b"),
            ("a.txt", "service:svc/bucket:b"),
            ("rep", "service:svc/bucket:b"),
            ("reports/", "service:svc/bucket:b/folder:reports"),
            ("reports/q1.csv", "service:svc/bucket:b/folder:reports"),
            ("reports/20", "service:svc/bucket:b/folder:reports"),
            ("reports/2026/", "service:svc/bucket:b/folder:reports/subfolder:2026"),
            (
                "reports/2026/q1.csv",
                "service:svc/bucket:b/folder:reports/subfolder:2026",
            ),
            (
                "reports/2026/q1/x.csv",
                "service:svc/bucket:b/folder:reports/subfolder:2026",
            ),
            ("reports/2026/q1/", "service:svc/bucket:b/folder:reports/subfolder:2026"),
            ("reports//x", "service:svc/bucket:b/folder:reports"),
            ("/x", "service:svc/bucket:b"),
            ("team a/x", "service:svc/bucket:b/folder:team%20a"),
            (long_key.as_str(), "service:svc/bucket:b"),
            ("bad\x01/x", "service:svc/bucket:b"),
            ("bad\u{85}/x", "service:svc/bucket:b"),
            ("public/../secret/x", "service:svc/bucket:b/folder:public/subfolder:.."),
        ];
        for (relative, want) in cases {
            assert_eq!(key_resource("svc", "b", relative).path(), want, "{relative:?}");
        }
    }

    #[test]
    fn a_node_below_the_service_carries_its_chain_in_the_json() {
        let cases = [
            (service_resource("svc"), r#"{"type":"service","id":"svc"}"#),
            (
                bucket_resource("svc", "b"),
                r#"{"type":"bucket","id":"b","properties":{"ancestors":[{"type":"service","id":"svc"}]}}"#,
            ),
            (
                key_resource("svc", "b", "r/2/x"),
                r#"{"type":"subfolder","id":"2","properties":{"ancestors":[{"type":"service","id":"svc"},{"type":"bucket","id":"b"},{"type":"folder","id":"r"}]}}"#,
            ),
        ];
        for (resource, want) in cases {
            assert_eq!(serde_json::to_string(&resource).unwrap(), want);
        }
    }

    #[test]
    fn percent_encoding_keeps_only_the_unreserved_bytes() {
        assert_eq!(percent_encode_id("a/b c~é"), "a%2Fb%20c~%C3%A9");
        assert!(valid_id("é"));
        assert!(!valid_id(""));
        assert!(!valid_id(&"a".repeat(257)));
        assert!(!valid_id("a\x7f"));
        assert!(valid_id(&"a".repeat(256)));
    }

    #[test]
    fn the_text_form_of_a_chain_reads_back() {
        let resource = key_resource("svc", "a b/é", "team a/2026/x");
        let text = resource.path();
        assert_eq!(text, "service:svc/bucket:a%20b%2F%C3%A9/folder:team%20a/subfolder:2026");
        assert_eq!(Resource::parse(&text), Some(resource));
        assert_eq!(Resource::parse("service"), None);
        assert_eq!(Resource::parse("service:%zz"), None);
        assert_eq!(Resource::parse("service:%ff"), None);
    }

    #[test]
    fn the_log_form_masks_the_folder_ids() {
        let resource = key_resource("svc", "b", "secret/inner/x");
        assert_eq!(resource.logged_path(false), "service:svc/bucket:b/folder:-/subfolder:-");
        assert_eq!(
            resource.logged_path(true),
            "service:svc/bucket:b/folder:secret/subfolder:inner"
        );
        assert_eq!(bucket_resource("svc", "b").logged_path(false), "service:svc/bucket:b");
    }
}
