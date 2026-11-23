//! The lifecycle rules: the public form of a rule, the rules of the editor, their checks, their XML, and the split
//! of a configuration into elements.
//!
//! `PutBucketLifecycleConfiguration` replaces the whole configuration. The editor keeps each element that it does
//! not edit byte for byte. Thus the split of a document keeps the bytes of each element of the root.

use serde::{Deserialize, Serialize};

use super::tags::validate_tags;
use super::xml::{self, Element, Token, Tokenizer, XmlError};
use super::{Tag, quote_text};
use crate::common::error::{Error, Result};
use crate::common::misc::hex;

/// The limit of S3 for the rules of one configuration.
pub const MAX_LIFECYCLE_RULES: usize = 1000;
/// The largest number of days of an action of the editor.
pub const MAX_LIFECYCLE_DAYS: i64 = 36500;
/// The limit of S3 for the ID of a rule.
pub const MAX_LIFECYCLE_ID_CHARS: usize = 255;
/// The limit of S3 for a key, and so for a prefix.
pub const MAX_LIFECYCLE_PREFIX_BYTES: usize = 1024;
/// The largest configuration that the server reads.
pub const MAX_LIFECYCLE_DOCUMENT_BYTES: usize = 4 << 20;
/// The namespace of the S3 documents.
pub const LIFECYCLE_NAMESPACE: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
/// The key of the read request that tells the provider. The object does not exist.
pub const FLAVOUR_PROBE_KEY: &str = ".stowr-provider-probe";

/// The field of the editor: the tag filter.
pub const FIELD_TAG: &str = "tagFilter";
/// The field of the editor: the expiration of the noncurrent versions.
pub const FIELD_NONCURRENT: &str = "noncurrentExpiration";
/// The field of the editor: the abort of the incomplete multipart uploads.
pub const FIELD_ABORT: &str = "abortMultipart";
/// The field of the editor: the removal of the expired delete markers.
pub const FIELD_DELETE_MARKER: &str = "expiredDeleteMarker";

/// The fields that a provider can drop or refuse. The expiration after N days with a prefix works on each provider.
pub const FIELDS: [&str; 4] = [FIELD_TAG, FIELD_NONCURRENT, FIELD_ABORT, FIELD_DELETE_MARKER];

/// The provider AWS S3.
pub const FLAVOUR_AWS: &str = "aws";
/// The provider MinIO.
pub const FLAVOUR_MINIO: &str = "minio";
/// The provider SeaweedFS.
pub const FLAVOUR_SEAWEEDFS: &str = "seaweedfs";
/// The provider Garage.
pub const FLAVOUR_GARAGE: &str = "garage";

/// The name of a field in a message.
pub fn field_name(field: &str) -> &'static str {
    match field {
        FIELD_TAG => "the tag filter",
        FIELD_NONCURRENT => "the expiration of noncurrent versions",
        FIELD_ABORT => "the abort of incomplete multipart uploads",
        FIELD_DELETE_MARKER => "the removal of expired delete markers",
        _ => "this setting",
    }
}

/// The name of a known provider in a message.
pub fn flavour_name(flavour: &str) -> &'static str {
    match flavour {
        FLAVOUR_AWS => "AWS S3",
        FLAVOUR_MINIO => "MinIO",
        FLAVOUR_SEAWEEDFS => "SeaweedFS",
        FLAVOUR_GARAGE => "Garage",
        _ => "",
    }
}

/// True when the known provider keeps the field. The facts come from requests to SeaweedFS 4.41, MinIO
/// RELEASE.2025-10-15T17-29-55Z and Garage v2.4.1, and from the documentation of AWS S3.
pub fn provider_keeps(flavour: &str, field: &str) -> bool {
    match flavour {
        FLAVOUR_AWS | FLAVOUR_SEAWEEDFS => FIELDS.contains(&field),
        FLAVOUR_MINIO => matches!(field, FIELD_TAG | FIELD_NONCURRENT | FIELD_DELETE_MARKER),
        FLAVOUR_GARAGE => field == FIELD_ABORT,
        _ => false,
    }
}

/// The reason why a known provider does not keep a field, or an empty text.
pub fn provider_reason(flavour: &str, field: &str) -> &'static str {
    match (flavour, field) {
        (FLAVOUR_MINIO, FIELD_ABORT) => {
            "MinIO does not keep the abort of incomplete multipart uploads: it refuses a rule with this action only, and drops the action from a rule with another action."
        }
        (FLAVOUR_GARAGE, FIELD_TAG) => {
            "Garage drops the tag filter of a rule without an error: the rule then applies to every object under the prefix."
        }
        (FLAVOUR_GARAGE, FIELD_NONCURRENT) => {
            "Garage keeps no versions and drops the expiration of noncurrent versions."
        }
        (FLAVOUR_GARAGE, FIELD_DELETE_MARKER) => "Garage refuses the removal of expired delete markers.",
        _ => "",
    }
}

/// A fact about the effect of the rules that the page shows for a provider.
pub fn provider_note(flavour: &str) -> &'static str {
    match flavour {
        FLAVOUR_SEAWEEDFS => {
            "SeaweedFS keeps all these rules and applies them with its lifecycle worker, in a daily pass. Its TTL fast path at write is off by default and never applies to a bucket with versioning."
        }
        FLAVOUR_GARAGE => "Garage applies the expiration and the abort of incomplete uploads in a daily pass.",
        _ => "",
    }
}

/// The reason that the editor keeps a rule that applies outside of the folder of the instance.
pub const REASON_OUTSIDE: &str = "It applies outside of the folder of this instance.";
/// The reason of a rule whose fields are complete but outside of the limits of the editor.
pub const REASON_VALUES: &str = "Its values are outside of the limits of the editor.";

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// One transition of a rule, as `/api/lifecycle` gives it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct LifecycleTransition {
    /// The days.
    #[serde(skip_serializing_if = "is_zero")]
    pub days: i64,
    /// The date.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub date: String,
    /// The storage class.
    #[serde(rename = "storageClass", skip_serializing_if = "String::is_empty")]
    pub storage_class: String,
}

/// One lifecycle rule as `/api/lifecycle` gives it in `rules`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct LifecycleRule {
    /// The ID of the rule.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// True when the rule is on.
    pub enabled: bool,
    /// The prefix.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    /// The tag filters.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,
    /// The size filter: more than.
    #[serde(rename = "sizeGreaterThan", skip_serializing_if = "is_zero")]
    pub size_greater_than: i64,
    /// The size filter: less than.
    #[serde(rename = "sizeLessThan", skip_serializing_if = "is_zero")]
    pub size_less_than: i64,
    /// The expiration in days.
    #[serde(rename = "expirationDays", skip_serializing_if = "is_zero")]
    pub expiration_days: i64,
    /// The expiration date.
    #[serde(rename = "expirationDate", skip_serializing_if = "String::is_empty")]
    pub expiration_date: String,
    /// True for the removal of the expired delete markers.
    #[serde(rename = "expiredObjectDeleteMarker", skip_serializing_if = "std::ops::Not::not")]
    pub expired_object_delete_marker: bool,
    /// The transitions.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transitions: Vec<LifecycleTransition>,
    /// The expiration of the noncurrent versions in days.
    #[serde(rename = "noncurrentExpirationDays", skip_serializing_if = "is_zero")]
    pub noncurrent_expiration_days: i64,
    /// The abort of the incomplete multipart uploads in days.
    #[serde(rename = "abortIncompleteMultipartDays", skip_serializing_if = "is_zero")]
    pub abort_incomplete_multipart_days: i64,
}

/// A number of an element, as the XML decoder reads it: an empty text is 0, else a whole number. A text with
/// space only is a fault.
fn read_int(text: &str) -> std::result::Result<i64, XmlError> {
    if text.is_empty() {
        return Ok(0);
    }
    text.trim()
        .parse::<i64>()
        .map_err(|_| XmlError::Syntax(format!("the text {text:?} is not a whole number")))
}

/// A truth value of an element: an empty text is false.
fn read_bool(text: &str) -> std::result::Result<bool, XmlError> {
    match text.trim() {
        _ if text.is_empty() => Ok(false),
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(XmlError::Syntax(format!("the text {text:?} is not a truth value"))),
    }
}

fn leaf_text<'a>(element: &'a Element, name: &str) -> &'a str {
    element.last_child(name).map_or("", |child| child.raw_text.as_str())
}

fn leaf_int(element: &Element, name: &str) -> std::result::Result<i64, XmlError> {
    element
        .last_child(name)
        .map_or(Ok(0), |child| read_int(&child.raw_text))
}

fn tag_of(element: &Element) -> Tag {
    Tag {
        key: leaf_text(element, "Key").to_owned(),
        value: leaf_text(element, "Value").to_owned(),
    }
}

fn rule_from_element(item: &Element) -> std::result::Result<LifecycleRule, XmlError> {
    let mut rule = LifecycleRule {
        id: leaf_text(item, "ID").to_owned(),
        enabled: leaf_text(item, "Status") == "Enabled",
        prefix: leaf_text(item, "Prefix").to_owned(),
        ..LifecycleRule::default()
    };
    if let Some(expiration) = item.last_child("Expiration") {
        rule.expiration_days = leaf_int(expiration, "Days")?;
        rule.expiration_date = leaf_text(expiration, "Date").to_owned();
        rule.expired_object_delete_marker = expiration
            .last_child("ExpiredObjectDeleteMarker")
            .map_or(Ok(false), |marker| read_bool(&marker.raw_text))?;
    }
    if let Some(noncurrent) = item.last_child("NoncurrentVersionExpiration") {
        rule.noncurrent_expiration_days = leaf_int(noncurrent, "NoncurrentDays")?;
    }
    if let Some(abort) = item.last_child("AbortIncompleteMultipartUpload") {
        rule.abort_incomplete_multipart_days = leaf_int(abort, "DaysAfterInitiation")?;
    }
    if let Some(filter) = item.last_child("Filter") {
        rule.size_greater_than = leaf_int(filter, "ObjectSizeGreaterThan")?;
        rule.size_less_than = leaf_int(filter, "ObjectSizeLessThan")?;
        let prefix = leaf_text(filter, "Prefix");
        if !prefix.is_empty() {
            rule.prefix = prefix.to_owned();
        }
        if let Some(tag) = filter.last_child("Tag") {
            rule.tags.push(tag_of(tag));
        }
        if let Some(and) = filter.last_child("And") {
            let prefix = leaf_text(and, "Prefix");
            if !prefix.is_empty() {
                rule.prefix = prefix.to_owned();
            }
            rule.tags.extend(and.children_named("Tag").map(tag_of));
            let greater = leaf_int(and, "ObjectSizeGreaterThan")?;
            if greater > 0 {
                rule.size_greater_than = greater;
            }
            let less = leaf_int(and, "ObjectSizeLessThan")?;
            if less > 0 {
                rule.size_less_than = less;
            }
        }
    }
    for transition in item.children_named("Transition") {
        rule.transitions.push(LifecycleTransition {
            days: leaf_int(transition, "Days")?,
            date: leaf_text(transition, "Date").to_owned(),
            storage_class: leaf_text(transition, "StorageClass").to_owned(),
        });
    }
    Ok(rule)
}

/// Read the rules of a configuration. An empty document gives an empty list.
pub fn parse_lifecycle_rules(body: &[u8]) -> Result<Vec<LifecycleRule>> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let invalid = |error: XmlError| Error::internal(format!("decode s3 lifecycle response: {error}"));
    let root = xml::parse_document(body).map_err(invalid)?;
    root.children_named("Rule")
        .map(rule_from_element)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(invalid)
}

// --- Rules of the editor -----------------------------------------------------------------------------------------

/// A rule that the editor shows and writes. The prefix is relative to the root prefix of the instance. A zero
/// number of days means "no such action".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditRule {
    /// The ID.
    #[serde(default, deserialize_with = "super::nullable")]
    pub id: String,
    /// True when the rule is on.
    #[serde(default, deserialize_with = "super::nullable")]
    pub enabled: bool,
    /// The prefix, relative to the root prefix.
    #[serde(default, deserialize_with = "super::nullable")]
    pub prefix: String,
    /// The tag filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<Tag>,
    /// The expiration of the objects, in days.
    #[serde(
        default,
        rename = "expirationDays",
        deserialize_with = "super::nullable",
        skip_serializing_if = "is_zero"
    )]
    pub expiration_days: i64,
    /// The expiration of the noncurrent versions, in days.
    #[serde(
        default,
        rename = "noncurrentDays",
        deserialize_with = "super::nullable",
        skip_serializing_if = "is_zero"
    )]
    pub noncurrent_days: i64,
    /// The abort of the incomplete multipart uploads, in days.
    #[serde(
        default,
        rename = "abortMultipartDays",
        deserialize_with = "super::nullable",
        skip_serializing_if = "is_zero"
    )]
    pub abort_multipart_days: i64,
    /// The removal of the expired delete markers.
    #[serde(
        default,
        rename = "expiredDeleteMarker",
        deserialize_with = "super::nullable",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub expired_delete_marker: bool,
}

impl EditRule {
    /// The fields of the provider table that the rule uses.
    pub fn fields(&self) -> Vec<&'static str> {
        let mut used = Vec::new();
        if self.tag.is_some() {
            used.push(FIELD_TAG);
        }
        if self.noncurrent_days > 0 {
            used.push(FIELD_NONCURRENT);
        }
        if self.abort_multipart_days > 0 {
            used.push(FIELD_ABORT);
        }
        if self.expired_delete_marker {
            used.push(FIELD_DELETE_MARKER);
        }
        used
    }

    /// True for an enabled rule that deletes objects, versions or delete markers.
    pub fn destructive(&self) -> bool {
        self.enabled && (self.expiration_days > 0 || self.noncurrent_days > 0 || self.expired_delete_marker)
    }
}

/// True when two rules of the editor have the same fields.
pub fn same_edit_rule(left: &EditRule, right: &EditRule) -> bool {
    left == right
}

/// The error of an invalid rule: `400 invalid_lifecycle`.
pub fn invalid_lifecycle(message: impl Into<String>) -> Error {
    Error::api(400, "invalid_lifecycle", message)
}

/// The error of a provider without the lifecycle rules: `501 lifecycle_unsupported`.
pub fn lifecycle_unsupported() -> Error {
    Error::api(
        501,
        "lifecycle_unsupported",
        "this storage provider does not give lifecycle rules",
    )
}

/// The error of a configuration that changed after the read: `409 lifecycle_changed`.
pub fn lifecycle_changed() -> Error {
    Error::api(
        409,
        "lifecycle_changed",
        "the lifecycle rules of the bucket changed after the window read them: read them again and make the change again",
    )
}

/// The name of a rule in a message.
pub fn rule_name(id: &str) -> String {
    if id.is_empty() {
        "without an ID".to_owned()
    } else {
        quote_text(id)
    }
}

fn is_control(c: char) -> bool {
    c < ' ' || c == '\u{7f}'
}

/// Check one rule of the editor. The checks follow the limits of S3: AWS refuses the abort of incomplete uploads
/// and the removal of delete markers in a rule with a tag filter, and the removal of delete markers next to an
/// expiration in days.
pub fn validate_edit_rule(rule: &EditRule) -> Result<()> {
    let name = rule_name(&rule.id);
    let id_chars = rule.id.chars().count();
    if rule.id.trim().is_empty() {
        return Err(invalid_lifecycle("each rule needs an ID"));
    }
    if rule.id != rule.id.trim() {
        return Err(invalid_lifecycle(format!(
            "the ID of the rule {name} starts or ends with a space"
        )));
    }
    if id_chars > MAX_LIFECYCLE_ID_CHARS {
        return Err(invalid_lifecycle(format!(
            "the ID of a rule has at most {MAX_LIFECYCLE_ID_CHARS} characters, got {id_chars}"
        )));
    }
    if rule.id.chars().any(is_control) {
        return Err(invalid_lifecycle(format!(
            "the ID of the rule {name} has a control character"
        )));
    }
    if rule.prefix.len() > MAX_LIFECYCLE_PREFIX_BYTES {
        return Err(invalid_lifecycle(format!(
            "the prefix of the rule {name} has more than {MAX_LIFECYCLE_PREFIX_BYTES} bytes"
        )));
    }
    if rule.prefix.chars().any(is_control) {
        return Err(invalid_lifecycle(format!(
            "the prefix of the rule {name} has a control character"
        )));
    }
    for (value, what) in [
        (rule.expiration_days, "the expiration"),
        (rule.noncurrent_days, "the expiration of noncurrent versions"),
        (rule.abort_multipart_days, "the abort of incomplete uploads"),
    ] {
        if !(0..=MAX_LIFECYCLE_DAYS).contains(&value) {
            return Err(invalid_lifecycle(format!(
                "the number of days of {what} of the rule {name} is a whole number from 1 to {MAX_LIFECYCLE_DAYS}, got {value}"
            )));
        }
    }
    if rule.expiration_days == 0
        && rule.noncurrent_days == 0
        && rule.abort_multipart_days == 0
        && !rule.expired_delete_marker
    {
        return Err(invalid_lifecycle(format!(
            "the rule {name} has no action: give at least one"
        )));
    }
    if rule.expiration_days > 0 && rule.expired_delete_marker {
        return Err(invalid_lifecycle(format!(
            "the rule {name} cannot expire the objects after a number of days and remove the expired delete markers: use two rules"
        )));
    }
    if let Some(tag) = &rule.tag {
        if let Err(error) = validate_tags(std::slice::from_ref(tag)) {
            let message = error.as_api().map(|api| api.message.clone()).unwrap_or_default();
            return Err(invalid_lifecycle(format!(
                "the tag filter of the rule {name}: {message}"
            )));
        }
        if rule.abort_multipart_days > 0 || rule.expired_delete_marker {
            return Err(invalid_lifecycle(format!(
                "the rule {name} has a tag filter: S3 does not let such a rule abort incomplete uploads or remove delete markers"
            )));
        }
    }
    Ok(())
}

/// The XML of a rule of the editor. `prefix` is the full prefix in the bucket.
pub fn lifecycle_rule_xml(rule: &EditRule, prefix: &str) -> String {
    let text = xml::escape_text;
    let mut out = String::new();
    out.push_str("<Rule><ID>");
    out.push_str(&text(&rule.id));
    out.push_str("</ID><Filter>");
    match &rule.tag {
        Some(tag) if !prefix.is_empty() => {
            out.push_str("<And><Prefix>");
            out.push_str(&text(prefix));
            out.push_str("</Prefix><Tag><Key>");
            out.push_str(&text(&tag.key));
            out.push_str("</Key><Value>");
            out.push_str(&text(&tag.value));
            out.push_str("</Value></Tag></And>");
        }
        Some(tag) => {
            out.push_str("<Tag><Key>");
            out.push_str(&text(&tag.key));
            out.push_str("</Key><Value>");
            out.push_str(&text(&tag.value));
            out.push_str("</Value></Tag>");
        }
        None => {
            out.push_str("<Prefix>");
            out.push_str(&text(prefix));
            out.push_str("</Prefix>");
        }
    }
    out.push_str("</Filter><Status>");
    out.push_str(if rule.enabled { "Enabled" } else { "Disabled" });
    out.push_str("</Status>");
    if rule.expiration_days > 0 {
        out.push_str(&format!(
            "<Expiration><Days>{}</Days></Expiration>",
            rule.expiration_days
        ));
    } else if rule.expired_delete_marker {
        out.push_str("<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>");
    }
    if rule.noncurrent_days > 0 {
        out.push_str(&format!(
            "<NoncurrentVersionExpiration><NoncurrentDays>{}</NoncurrentDays></NoncurrentVersionExpiration>",
            rule.noncurrent_days
        ));
    }
    if rule.abort_multipart_days > 0 {
        out.push_str(&format!(
            "<AbortIncompleteMultipartUpload><DaysAfterInitiation>{}</DaysAfterInitiation></AbortIncompleteMultipartUpload>",
            rule.abort_multipart_days
        ));
    }
    out.push_str("</Rule>");
    out
}

// --- Elements of a configuration ---------------------------------------------------------------------------------

/// An element with no child, no attribute and no space around its text.
fn leaf_node(node: Option<&Element>) -> bool {
    node.is_some_and(|node| node.children.is_empty() && node.attrs.is_empty() && !node.padded())
}

/// An element with no attribute and no text, whose children have the allowed names, one of each.
fn only_children(node: &Element, allowed: &[&str]) -> bool {
    if !node.attrs.is_empty() || !node.text().is_empty() {
        return false;
    }
    let mut seen: Vec<&str> = Vec::new();
    for child in &node.children {
        if seen.contains(&child.name.as_str()) || !allowed.contains(&child.name.as_str()) {
            return false;
        }
        seen.push(&child.name);
    }
    true
}

fn days_value(node: Option<&Element>) -> Option<i64> {
    if !leaf_node(node) {
        return None;
    }
    let days = node?.text().parse::<i64>().ok()?;
    (1..=MAX_LIFECYCLE_DAYS).contains(&days).then_some(days)
}

/// The tag of a filter. A key with `=` or `,`, or a value with `,`, stays out of the editor: the page writes a tag
/// as `key=value` and would read it back as another tag.
fn tag_from_node(node: &Element) -> Option<Tag> {
    let key = node.child("Key");
    if !only_children(node, &["Key", "Value"]) || !leaf_node(key) {
        return None;
    }
    let key = key?.text();
    if key.contains(['=', ',']) {
        return None;
    }
    let mut tag = Tag {
        key: key.to_owned(),
        value: String::new(),
    };
    if let Some(value) = node.child("Value") {
        if !leaf_node(Some(value)) || value.text().contains(',') {
            return None;
        }
        tag.value = value.text().to_owned();
    }
    Some(tag)
}

/// Why the editor keeps a rule as it is, from the elements that the editor does not edit.
pub fn kept_reason(node: &Element) -> &'static str {
    let has = |path: &[&str]| {
        let mut current = node;
        for name in path {
            match current.child(name) {
                Some(next) => current = next,
                None => return false,
            }
        }
        true
    };
    if has(&["Transition"]) || has(&["NoncurrentVersionTransition"]) {
        return "It moves objects to another storage class.";
    }
    if has(&["Expiration", "Date"]) {
        return "It expires the objects on a date.";
    }
    if has(&["Filter", "ObjectSizeGreaterThan"])
        || has(&["Filter", "ObjectSizeLessThan"])
        || has(&["Filter", "And", "ObjectSizeGreaterThan"])
        || has(&["Filter", "And", "ObjectSizeLessThan"])
    {
        return "It filters the objects by size.";
    }
    if has(&["NoncurrentVersionExpiration", "NewerNoncurrentVersions"]) {
        return "It keeps a number of noncurrent versions.";
    }
    if has(&["Prefix"]) {
        return "It has the old Prefix element outside of a filter.";
    }
    if node.child("ID").is_none_or(|id| id.text().is_empty()) {
        return "It has no ID.";
    }
    if let Some(and) = node.child("Filter").and_then(|filter| filter.child("And"))
        && and.children_named("Tag").count() > 1
    {
        return "It filters by more than one tag.";
    }
    "It has settings that the editor does not show."
}

/// The rule of the editor for an element, or a reason to keep it as it is. `root_prefix` is the root prefix of the
/// instance: a rule outside of it stays as it is.
pub fn edit_rule_from_node(node: &Element, root_prefix: &str) -> (EditRule, &'static str) {
    let mut rule = EditRule::default();
    if node.name != "Rule"
        || !only_children(
            node,
            &[
                "ID",
                "Status",
                "Filter",
                "Expiration",
                "NoncurrentVersionExpiration",
                "AbortIncompleteMultipartUpload",
            ],
        )
    {
        return (rule, kept_reason(node));
    }
    let (id, status) = (node.child("ID"), node.child("Status"));
    let status_ok = leaf_node(status) && status.is_some_and(|s| s.text() == "Enabled" || s.text() == "Disabled");
    if !leaf_node(id) || id.is_none_or(|id| id.text().is_empty()) || !status_ok {
        return (rule, kept_reason(node));
    }
    rule.id = id.map(|id| id.text().to_owned()).unwrap_or_default();
    rule.enabled = status.is_some_and(|status| status.text() == "Enabled");
    let mut prefix = String::new();
    if let Some(filter) = node.child("Filter") {
        if !only_children(filter, &["Prefix", "Tag", "And"]) || filter.children.len() > 1 {
            return (rule, kept_reason(node));
        }
        for child in &filter.children {
            match child.name.as_str() {
                "Prefix" => {
                    if !leaf_node(Some(child)) {
                        return (rule, kept_reason(node));
                    }
                    prefix = child.text().to_owned();
                }
                "Tag" => match tag_from_node(child) {
                    Some(tag) => rule.tag = Some(tag),
                    None => return (rule, kept_reason(node)),
                },
                _ => {
                    if !only_children(child, &["Prefix", "Tag"]) || child.child("Tag").is_none() {
                        return (rule, kept_reason(node));
                    }
                    if let Some(and_prefix) = child.child("Prefix") {
                        if !leaf_node(Some(and_prefix)) {
                            return (rule, kept_reason(node));
                        }
                        prefix = and_prefix.text().to_owned();
                    }
                    match child.child("Tag").and_then(tag_from_node) {
                        Some(tag) => rule.tag = Some(tag),
                        None => return (rule, kept_reason(node)),
                    }
                }
            }
        }
    }
    if let Some(expiration) = node.child("Expiration") {
        if !only_children(expiration, &["Days", "ExpiredObjectDeleteMarker"]) || expiration.children.len() != 1 {
            return (rule, kept_reason(node));
        }
        if let Some(days) = expiration.child("Days") {
            match days_value(Some(days)) {
                Some(value) => rule.expiration_days = value,
                None => return (rule, kept_reason(node)),
            }
        } else {
            let marker = expiration.child("ExpiredObjectDeleteMarker");
            if !leaf_node(marker) || marker.is_none_or(|marker| marker.text() != "true") {
                return (rule, kept_reason(node));
            }
            rule.expired_delete_marker = true;
        }
    }
    if let Some(noncurrent) = node.child("NoncurrentVersionExpiration") {
        let ok = only_children(noncurrent, &["NoncurrentDays"]) && noncurrent.children.len() == 1;
        match ok.then(|| days_value(noncurrent.child("NoncurrentDays"))).flatten() {
            Some(value) => rule.noncurrent_days = value,
            None => return (rule, kept_reason(node)),
        }
    }
    if let Some(abort) = node.child("AbortIncompleteMultipartUpload") {
        let ok = only_children(abort, &["DaysAfterInitiation"]) && abort.children.len() == 1;
        match ok.then(|| days_value(abort.child("DaysAfterInitiation"))).flatten() {
            Some(value) => rule.abort_multipart_days = value,
            None => return (rule, kept_reason(node)),
        }
    }
    let Some(relative) = prefix.strip_prefix(root_prefix) else {
        return (rule, REASON_OUTSIDE);
    };
    rule.prefix = relative.to_owned();
    if validate_edit_rule(&rule).is_err() {
        return (rule, REASON_VALUES);
    }
    (rule, "")
}

/// An element of the root of a configuration with its bytes as the provider sent them.
#[derive(Clone, Debug)]
pub struct LifecycleItem {
    /// The bytes of the document.
    pub raw: Vec<u8>,
    /// The element.
    pub node: Element,
}

/// A configuration split into the elements of its root.
#[derive(Clone, Debug, Default)]
pub struct LifecycleConfig {
    /// The start tag of the root as the provider sent it. Empty for a bucket without a configuration.
    pub root_start: Vec<u8>,
    /// The name of the root with its prefix.
    pub root_name: String,
    /// The elements.
    pub items: Vec<LifecycleItem>,
}

fn not_valid(error: XmlError) -> Error {
    Error::internal(format!("the lifecycle configuration is not valid XML: {error}"))
}

/// Cut the document into the elements of its root. The bytes of each element are the bytes of the document: a rule
/// that the editor keeps goes back to the provider unchanged.
pub fn split_lifecycle_document(body: &[u8]) -> Result<LifecycleConfig> {
    let mut config = LifecycleConfig::default();
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(config);
    }
    let mut tokenizer = Tokenizer::new(body);
    loop {
        let before = tokenizer.offset();
        let Some(token) = tokenizer.next_token().map_err(not_valid)? else {
            return Err(not_valid(XmlError::Syntax(
                "the document ends before its root".to_owned(),
            )));
        };
        let Token::Start {
            name,
            raw_name,
            self_closing,
            ..
        } = token
        else {
            continue;
        };
        if name != "LifecycleConfiguration" {
            return Err(Error::internal(format!(
                "the lifecycle configuration starts with the element {name}"
            )));
        }
        config.root_start = body[before..tokenizer.offset()].to_vec();
        config.root_name = raw_name;
        if self_closing {
            // `<LifecycleConfiguration/>`: a root without an element. The writer opens it again.
            config.root_start.clear();
            return Ok(config);
        }
        break;
    }
    loop {
        let before = tokenizer.offset();
        let Some(token) = tokenizer.next_token().map_err(not_valid)? else {
            return Err(not_valid(XmlError::Syntax("the document ends in its root".to_owned())));
        };
        match token {
            Token::Start { .. } => {
                let node = xml::read_element(&mut tokenizer, token).map_err(not_valid)?;
                config.items.push(LifecycleItem {
                    raw: body[before..tokenizer.offset()].to_vec(),
                    node,
                });
            }
            Token::End => return Ok(config),
            _ => {}
        }
    }
}

/// The hash that the page sends back: the SHA-256 of the document as the provider sent it, and of the indexes of
/// the rules that the editor showed as editable. A rule that becomes "kept as it is" also stops the save.
pub fn lifecycle_hash(body: &[u8], editable: &[usize]) -> String {
    let mut data = body.to_vec();
    for index in editable {
        data.extend_from_slice(format!("\u{0}{index}").as_bytes());
    }
    hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &data).as_ref())
}

/// The elements of a configuration without the element `ID`.
pub fn without_id(node: &Element) -> Element {
    Element {
        children: node
            .children
            .iter()
            .filter(|child| child.name != "ID")
            .cloned()
            .collect(),
        ..node.clone()
    }
}
