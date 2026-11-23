// SPDX-License-Identifier: MIT OR Apache-2.0
//! The editor of the lifecycle rules of a bucket (`PUT /api/lifecycle`), the start probes, and the facts of the
//! bucket.
//!
//! `PutBucketLifecycleConfiguration` replaces the whole configuration. Thus the server reads the configuration first.
//! It keeps each element that the editor does not edit, byte for byte. It puts the edited rules next to them and
//! writes the whole document. The page sends the SHA-256 hash of the document that it read. A different hash stops
//! the write.
//!
//! The providers do not keep the same settings, and some drop a setting without an error. Garage drops a tag
//! filter, and the rule then applies to every object under the prefix. Thus the editor offers a field only where the
//! provider keeps it. Each known provider has a table. An unknown provider keeps the expiration after N days with a
//! prefix, and each field that a rule of the bucket already uses. After each write the server reads the
//! configuration again and compares it with the document that it sent. It restores nothing. It tells the person what
//! the provider changed, and it does not offer again a field that the provider dropped.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;
use std::sync::{Arc, MutexGuard};
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::Serialize;

use super::rules::{
    EditRule, FIELD_ABORT, FIELD_DELETE_MARKER, FIELD_NONCURRENT, FIELD_TAG, FIELDS, LifecycleConfig, LifecycleItem,
    LifecycleRule, MAX_LIFECYCLE_DAYS, MAX_LIFECYCLE_RULES, REASON_OUTSIDE, REASON_VALUES, edit_rule_from_node,
    field_name, flavour_name, invalid_lifecycle, lifecycle_changed, lifecycle_hash, lifecycle_rule_xml,
    lifecycle_unsupported, parse_lifecycle_rules, provider_keeps, provider_note, provider_reason, rule_name,
    same_edit_rule, split_lifecycle_document, validate_edit_rule, without_id,
};
use super::tags::provider_refused_feature;
use super::xml::Element;
use super::{BucketRules, RulesInner};
use crate::common::config::{PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result, safe_provider_code};
use crate::instance::Instance;

/// The age of the versioning status and of the number of rules after which a request of `/api/instances` reads
/// them again. The read runs in the background: the request does not wait for it.
pub const BUCKET_FACTS_TTL: Duration = Duration::from_secs(60);
/// The longest wait of a probe and of a read of the facts.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// A field that the editor does not offer, with the reason for the person.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct HiddenField {
    /// The field.
    pub field: String,
    /// The reason.
    pub reason: String,
}

/// One rule of the configuration. An editable rule has `rule`. A rule that the editor keeps as it is has its XML and
/// the reason. The entries and the rules of the answer have the same order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct LifecycleEntry {
    /// True for a rule that the editor shows and writes.
    pub editable: bool,
    /// The rule of the editor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<EditRule>,
    /// The XML of a rule that the editor keeps as it is.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub xml: String,
    /// Why the editor keeps the rule as it is.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// The state of the editor, as `GET /api/lifecycle` gives it in `editor`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct EditorState {
    /// The SHA-256 of the configuration that the server read. The page sends it back with the change.
    pub hash: String,
    /// The rules.
    pub entries: Vec<LifecycleEntry>,
    /// The fields that the editor offers.
    pub fields: BTreeMap<String, bool>,
    /// The reason for each other field.
    pub hidden: Vec<HiddenField>,
    /// The provider that the server found, or an empty text.
    pub provider: String,
    /// A fact about the effect of the rules for this provider.
    #[serde(rename = "providerNote", skip_serializing_if = "String::is_empty")]
    pub provider_note: String,
    /// The versioning status of the bucket: `Enabled`, `Suspended` or an empty text.
    pub versioning: String,
    /// The root prefix of the instance.
    #[serde(rename = "rootPrefix")]
    pub root_prefix: String,
    /// False when the person or the provider cannot change the rules.
    pub writable: bool,
    /// Why the editor is read only.
    #[serde(rename = "readOnlyReason", skip_serializing_if = "String::is_empty")]
    pub read_only_reason: String,
    /// The largest number of days.
    #[serde(rename = "maxDays")]
    pub max_days: i64,
    /// The most rules of a configuration.
    #[serde(rename = "maxRules")]
    pub max_rules: usize,
}

/// The answer of `/api/lifecycle`.
#[derive(Clone, Debug, Serialize)]
pub struct LifecycleResponse {
    /// The instance.
    pub instance: String,
    /// The rules.
    pub rules: Vec<LifecycleRule>,
    /// The state of the editor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub editor: Option<EditorState>,
    /// What the provider changed in the rules of a save.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// A configuration that the server read for the editor.
#[derive(Clone, Debug, Default)]
pub struct LifecycleState {
    /// The document as the provider sent it.
    pub body: Bytes,
    /// The document split into its elements.
    pub config: LifecycleConfig,
    /// The rules.
    pub rules: Vec<LifecycleRule>,
    /// The state of the editor.
    pub editor: EditorState,
    /// The rule of the editor for each editable entry, at the index of the entry.
    pub edit: BTreeMap<usize, EditRule>,
    /// The bytes of each editable rule, by ID: a rule that the save does not change goes back with its bytes.
    pub raw: BTreeMap<String, Vec<u8>>,
    /// The IDs of the rules that the editor keeps as they are.
    pub kept_ids: Vec<String>,
}

fn lowercase_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn status_text(status: u16, code: &str) -> String {
    let code = safe_provider_code(code);
    if code.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status} {code}")
    }
}

fn node_id(node: &Element) -> String {
    node.child("ID").map(|id| id.text().to_owned()).unwrap_or_default()
}

// --- Document of a save ------------------------------------------------------------------------------------------

/// The document of a save. It has the start tag of the root as the provider sent it, the rules of the editor, and
/// each other element of the configuration with its bytes. `None` when no element stays.
pub fn lifecycle_document_for(state: &LifecycleState, rules: &[EditRule], root_prefix: &str) -> Option<Vec<u8>> {
    let mut kept: Vec<&LifecycleItem> = Vec::with_capacity(state.config.items.len());
    let mut rule_index = 0usize;
    for item in &state.config.items {
        if item.node.name == "Rule" {
            let editable = state.edit.contains_key(&rule_index);
            rule_index += 1;
            if editable {
                continue;
            }
        }
        kept.push(item);
    }
    if rules.is_empty() && kept.is_empty() {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    if !state.config.root_start.is_empty() && !state.config.root_name.is_empty() {
        out.extend_from_slice(&state.config.root_start);
    } else {
        out.extend_from_slice(
            format!(
                "<LifecycleConfiguration xmlns=\"{}\">",
                super::rules::LIFECYCLE_NAMESPACE
            )
            .as_bytes(),
        );
    }
    let mut unchanged: BTreeMap<&str, bool> = state.edit.values().map(|rule| (rule.id.as_str(), true)).collect();
    for old in state.edit.values() {
        for rule in rules {
            if rule.id == old.id && !same_edit_rule(rule, old) {
                unchanged.insert(old.id.as_str(), false);
            }
        }
    }
    for rule in rules {
        if let Some(raw) = state.raw.get(&rule.id)
            && unchanged.get(rule.id.as_str()).copied().unwrap_or(false)
        {
            out.extend_from_slice(raw);
            continue;
        }
        let prefix = format!("{root_prefix}{}", rule.prefix);
        out.extend_from_slice(lifecycle_rule_xml(rule, &prefix).as_bytes());
    }
    for item in kept {
        out.extend_from_slice(&item.raw);
    }
    let name = if state.config.root_start.is_empty() || state.config.root_name.is_empty() {
        "LifecycleConfiguration"
    } else {
        state.config.root_name.as_str()
    };
    out.extend_from_slice(format!("</{name}>").as_bytes());
    Some(out)
}

// --- Read back ---------------------------------------------------------------------------------------------------

fn find_match(read_rules: &[&Element], matched: &[bool], node: &Element) -> Option<usize> {
    let id = node_id(node);
    for (index, candidate) in read_rules.iter().enumerate() {
        if matched[index] {
            continue;
        }
        if !id.is_empty() && candidate.child("ID").is_some_and(|child| child.text() == id) {
            return Some(index);
        }
    }
    // A rule without an ID: the same rule, or the same rule with an ID that the provider gave (MinIO).
    if id.is_empty() {
        for (index, candidate) in read_rules.iter().enumerate() {
            if !matched[index] && without_id(candidate).canonical() == node.canonical() {
                return Some(index);
            }
        }
    }
    None
}

/// What the provider changed in a rule of the editor. The second value has the fields that the provider dropped.
fn rule_differences(root_prefix: &str, sent: &EditRule, node: &Element) -> (Vec<String>, Vec<&'static str>) {
    let name = rule_name(&sent.id);
    let (got, reason) = edit_rule_from_node(node, "");
    if !reason.is_empty() && reason != REASON_VALUES {
        // The fields of the rule are not complete: the server tells the change and marks no field.
        return (
            vec![format!(
                "The storage provider changed the rule {name}: {}",
                lowercase_first(reason)
            )],
            Vec::new(),
        );
    }
    let sent_prefix = format!("{root_prefix}{}", sent.prefix);
    let scope = if got.prefix.is_empty() {
        "every object of the bucket".to_owned()
    } else {
        format!("every object under {}", got.prefix)
    };
    let mut warnings = Vec::new();
    let mut dropped = Vec::new();
    if let (Some(tag), None) = (&sent.tag, &got.tag) {
        dropped.push(FIELD_TAG);
        warnings.push(format!(
            "The storage provider dropped the tag filter {}={} of the rule {name}. The rule now applies to {scope}: disable or delete the rule if you do not want this.",
            tag.key, tag.value
        ));
    }
    if got.prefix != sent_prefix {
        warnings.push(format!(
            "The storage provider changed the prefix of the rule {name} from {} to {}. The rule now applies to {scope}.",
            super::quote_text(&sent_prefix),
            super::quote_text(&got.prefix)
        ));
    }
    if got.enabled != sent.enabled {
        warnings.push(format!("The storage provider changed the status of the rule {name}."));
    }
    if got.expiration_days != sent.expiration_days {
        warnings.push(format!(
            "The storage provider changed the expiration of the rule {name} from {} to {} days.",
            sent.expiration_days, got.expiration_days
        ));
    }
    for (field, sent_has, got_has) in [
        (FIELD_NONCURRENT, sent.noncurrent_days > 0, got.noncurrent_days > 0),
        (FIELD_ABORT, sent.abort_multipart_days > 0, got.abort_multipart_days > 0),
        (
            FIELD_DELETE_MARKER,
            sent.expired_delete_marker,
            got.expired_delete_marker,
        ),
    ] {
        if sent_has && !got_has {
            dropped.push(field);
            warnings.push(format!(
                "The storage provider dropped {} of the rule {name}.",
                field_name(field)
            ));
        }
    }
    if got.noncurrent_days > 0 && sent.noncurrent_days > 0 && got.noncurrent_days != sent.noncurrent_days {
        warnings.push(format!(
            "The storage provider changed the days of the noncurrent versions of the rule {name}."
        ));
    }
    if got.abort_multipart_days > 0
        && sent.abort_multipart_days > 0
        && got.abort_multipart_days != sent.abort_multipart_days
    {
        warnings.push(format!(
            "The storage provider changed the days of the abort of incomplete uploads of the rule {name}."
        ));
    }
    if warnings.is_empty() {
        warnings.push(format!("The storage provider changed the rule {name}."));
    }
    (warnings, dropped)
}

/// Compare the rules that the server sent with the rules that the provider gives after the save, and give a
/// sentence for each difference. The second value has each field that the provider dropped.
pub fn lifecycle_warnings(
    root_prefix: &str,
    sent: &[u8],
    read: &LifecycleState,
    rules: &[EditRule],
) -> (Vec<String>, Vec<&'static str>) {
    let Ok(sent_config) = split_lifecycle_document(sent) else {
        return (
            vec!["Stowr cannot read the document that it sent: compare the rules with care.".to_owned()],
            Vec::new(),
        );
    };
    let edited: BTreeMap<&str, &EditRule> = rules.iter().map(|rule| (rule.id.as_str(), rule)).collect();
    let read_rules: Vec<&Element> = read
        .config
        .items
        .iter()
        .filter(|item| item.node.name == "Rule")
        .map(|item| &item.node)
        .collect();
    let mut matched = vec![false; read_rules.len()];
    let mut warnings = Vec::new();
    let mut dropped = Vec::new();
    for item in sent_config.items.iter().filter(|item| item.node.name == "Rule") {
        let id = node_id(&item.node);
        let Some(index) = find_match(&read_rules, &matched, &item.node) else {
            warnings.push(format!(
                "The storage provider did not keep the rule {}.",
                rule_name(&id)
            ));
            continue;
        };
        matched[index] = true;
        let got = read_rules[index];
        if got.canonical() == item.node.canonical()
            || (id.is_empty() && without_id(got).canonical() == item.node.canonical())
        {
            continue;
        }
        let Some(rule) = edited.get(id.as_str()) else {
            warnings.push(format!(
                "The storage provider changed the rule {}, which the editor keeps as is.",
                rule_name(&id)
            ));
            continue;
        };
        let (more, fields) = rule_differences(root_prefix, rule, got);
        warnings.extend(more);
        dropped.extend(fields);
    }
    for (index, node) in read_rules.iter().enumerate() {
        if !matched[index] {
            warnings.push(format!(
                "The storage provider has a rule {} that Stowr did not send.",
                rule_name(&node_id(node))
            ));
        }
    }
    (warnings, dropped)
}

// --- Checks of a save --------------------------------------------------------------------------------------------

/// Check the rules of a save against the state that the server read: the fields that the editor offers, unique IDs
/// (also with the kept rules), and the limit of rules.
pub fn check_lifecycle_rules(state: &LifecycleState, rules: &[EditRule]) -> Result<()> {
    let mut ids: BTreeSet<&str> = state
        .kept_ids
        .iter()
        .filter(|id| !id.is_empty())
        .map(String::as_str)
        .collect();
    let total = state.kept_ids.len() + rules.len();
    if total > MAX_LIFECYCLE_RULES {
        return Err(invalid_lifecycle(format!(
            "a bucket has at most {MAX_LIFECYCLE_RULES} lifecycle rules, got {total}"
        )));
    }
    for rule in rules {
        validate_edit_rule(rule)?;
        if ids.contains(rule.id.as_str()) {
            return Err(invalid_lifecycle(format!(
                "the ID {} is on more than one rule",
                rule_name(&rule.id)
            )));
        }
        ids.insert(&rule.id);
        for field in rule.fields() {
            if !state.editor.fields.get(field).copied().unwrap_or(false) {
                let reason = state
                    .editor
                    .hidden
                    .iter()
                    .rev()
                    .find(|hidden| hidden.field == field)
                    .map(|hidden| format!(" {}", hidden.reason))
                    .unwrap_or_default();
                return Err(Error::api(
                    400,
                    "lifecycle_field_unsupported",
                    format!(
                        "the rule {} uses {}, which the editor does not offer for this instance.{reason}",
                        rule_name(&rule.id),
                        field_name(field)
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// True when the save adds or changes a rule that deletes objects. Such a save needs the permission `delete`.
pub fn lifecycle_deletes(state: &LifecycleState, rules: &[EditRule]) -> bool {
    let old: BTreeMap<&str, &EditRule> = state.edit.values().map(|rule| (rule.id.as_str(), rule)).collect();
    for rule in rules {
        if let Some(previous) = old.get(rule.id.as_str())
            && same_edit_rule(previous, rule)
        {
            continue;
        }
        if rule.destructive() {
            return true;
        }
    }
    false
}

// --- Instance ----------------------------------------------------------------------------------------------------

impl Instance {
    fn rules_state(&self) -> MutexGuard<'_, RulesInner> {
        self.rules
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// True when the instance gives the lifecycle rules. Until the probe has run, the answer is yes for a back end
    /// with the rules.
    pub fn lifecycle_available(&self) -> bool {
        self.backend.bucket_rules().is_some() && !self.rules.off.load(Ordering::SeqCst)
    }

    /// The number of rules for `/api/instances`, or `None` when the server has not read the rules or the instance has
    /// no lifecycle rules.
    pub fn lifecycle_rule_count(&self) -> Option<usize> {
        if !self.lifecycle_available() {
            return None;
        }
        self.rules_state().rule_count
    }

    fn set_lifecycle_rule_count(&self, count: usize) {
        self.rules_state().rule_count = Some(count);
    }

    /// The provider that an earlier probe recognised, or an empty text. It never asks the provider.
    pub fn known_flavour(&self) -> String {
        let state = self.rules_state();
        if state.flavour_known {
            state.flavour.clone()
        } else {
            String::new()
        }
    }

    /// The provider of the instance. The first call asks the provider.
    pub async fn lifecycle_flavour(&self, ctx: &OpCtx) -> String {
        {
            let state = self.rules_state();
            if state.flavour_known {
                return state.flavour.clone();
            }
        }
        let Some(rules) = self.backend.bucket_rules() else {
            return String::new();
        };
        let probe = ctx.with_timeout(PROBE_TIMEOUT);
        let Ok(flavour) = probe.run(rules.provider_flavour(&probe)).await else {
            return String::new();
        };
        let mut state = self.rules_state();
        state.flavour.clone_from(&flavour);
        state.flavour_known = true;
        flavour
    }

    fn lifecycle_write_refusal(&self) -> String {
        self.rules_state().write_refusal.clone()
    }

    fn set_lifecycle_write_refusal(&self, reason: &str) {
        self.rules_state().write_refusal = reason.to_owned();
    }

    fn lifecycle_dropped(&self, field: &str) -> bool {
        self.rules_state().dropped.contains(&field)
    }

    /// Mark a field that the provider dropped after a save: the editor never offers it again.
    pub fn mark_lifecycle_dropped(&self, field: &'static str) {
        let mut state = self.rules_state();
        if !state.dropped.contains(&field) {
            state.dropped.push(field);
        }
    }

    /// The fields of the editor. A field needs the provider: the table of a known provider, or for an unknown
    /// provider a rule of the bucket that uses the field. A field also needs its condition. The tag filter needs the
    /// tags of the instance. The noncurrent versions and the delete markers need the versioning of the bucket. A field
    /// that the provider dropped after a save in this process is never offered again. The reason of the provider table
    /// comes before the reason of a condition: it tells what the provider does with the field.
    pub fn lifecycle_fields_for(
        &self,
        flavour: &str,
        versioning: &str,
        used: &BTreeSet<&'static str>,
    ) -> (BTreeMap<String, bool>, Vec<HiddenField>) {
        let mut fields = BTreeMap::new();
        let mut hidden = Vec::new();
        let versioned = versioning == "Enabled" || versioning == "Suspended";
        for field in FIELDS {
            let reason = if self.lifecycle_dropped(field) {
                "The storage provider dropped this setting after a save: Stowr does not offer it again.".to_owned()
            } else if !flavour.is_empty() && !provider_keeps(flavour, field) {
                match provider_reason(flavour, field) {
                    "" => format!("{} does not keep this setting.", flavour_name(flavour)),
                    reason => reason.to_owned(),
                }
            } else if field == FIELD_TAG && !self.tags_available() {
                "This storage provider keeps no object tags.".to_owned()
            } else if (field == FIELD_NONCURRENT || field == FIELD_DELETE_MARKER) && !versioned {
                "The bucket has no versioning.".to_owned()
            } else if flavour.is_empty() && !used.contains(field) {
                "Stowr does not know this storage provider, and no rule of the bucket uses this setting: the provider can drop it without an error.".to_owned()
            } else {
                String::new()
            };
            fields.insert(field.to_owned(), reason.is_empty());
            if !reason.is_empty() {
                hidden.push(HiddenField {
                    field: field.to_owned(),
                    reason,
                });
            }
        }
        (fields, hidden)
    }

    pub(super) fn lifecycle_writer(&self) -> Result<&dyn BucketRules> {
        match self.backend.bucket_rules() {
            Some(rules) if !self.rules.off.load(Ordering::SeqCst) => Ok(rules),
            _ => Err(lifecycle_unsupported()),
        }
    }

    /// The rules of the bucket, parsed. A bucket without rules gives an empty list.
    pub async fn lifecycle(&self, ctx: &OpCtx) -> Result<Vec<LifecycleRule>> {
        let rules = self.lifecycle_writer()?;
        let slot = self.begin_lifecycle_call(ctx).await?;
        let result = rules.lifecycle_rules(ctx).await;
        drop(slot);
        if let Err(error) = &result
            && provider_refused_feature(error)
        {
            self.rules.off.store(true, Ordering::SeqCst);
            return Err(lifecycle_unsupported());
        }
        result
    }

    /// Read the versioning status of the bucket and keep it. Gives an empty text for an instance without versions.
    pub async fn bucket_versioning(&self, ctx: &OpCtx) -> String {
        let Some(rules) = self.backend.bucket_rules() else {
            return String::new();
        };
        if !self.versions_found() {
            return String::new();
        }
        let Ok(slot) = self.begin_lifecycle_call(ctx).await else {
            return String::new();
        };
        let result = rules.versioning_status(ctx).await;
        drop(slot);
        match result {
            Ok(status) => {
                if let Ok(mut known) = self.versioning.status.lock() {
                    *known = Some(status.clone());
                }
                status
            }
            Err(_) => String::new(),
        }
    }

    /// The start probe of the lifecycle: read the configuration of the bucket, then the answer to an object that
    /// does not exist. A provider without the lifecycle answers 501 or 405. The second answer tells the provider.
    /// Both requests are reads. Any other failure leaves the answer at yes. An instance without the read permission is
    /// not probed.
    pub async fn probe_lifecycle(&self, ctx: &OpCtx) {
        let Some(rules) = self.backend.bucket_rules() else {
            return;
        };
        if !self.permitted(PERMISSION_READ) {
            return;
        }
        let probe = ctx.with_timeout(PROBE_TIMEOUT);
        let result = async {
            let document = probe.run(rules.read_lifecycle(&probe)).await?;
            parse_lifecycle_rules(&document.body)
        }
        .await;
        match result {
            Err(error) if provider_refused_feature(&error) => {
                self.rules.off.store(true, Ordering::SeqCst);
                return;
            }
            Ok(found) => self.set_lifecycle_rule_count(found.len()),
            Err(_) => {}
        }
        self.lifecycle_flavour(&probe).await;
    }

    /// Note the time of the read of the facts of the bucket at start.
    pub fn mark_bucket_facts_read(&self) {
        self.rules_state().facts_at = Some(Instant::now());
    }

    /// Read the versioning status and the lifecycle rules of the bucket again when the last read is older than
    /// [`BUCKET_FACTS_TTL`]. One read at a time for each instance, 5 seconds at most, inside the limits of the
    /// provider calls. A failed read keeps the last values. Before the probe at start, nothing is read. The call
    /// returns at once.
    pub fn refresh_bucket_facts(self: &Arc<Self>) {
        if !self.permitted(PERMISSION_READ) {
            return;
        }
        {
            let mut state = self.rules_state();
            let fresh = state.facts_at.is_none_or(|at| at.elapsed() < BUCKET_FACTS_TTL);
            if state.facts_running || fresh {
                return;
            }
            state.facts_running = true;
        }
        let instance = Arc::clone(self);
        tokio::spawn(async move {
            let ctx = OpCtx::default().with_timeout(PROBE_TIMEOUT);
            instance.read_bucket_facts(&ctx).await;
            let mut state = instance.rules_state();
            state.facts_running = false;
            state.facts_at = Some(Instant::now());
        });
    }

    async fn read_bucket_facts(&self, ctx: &OpCtx) {
        self.bucket_versioning(ctx).await;
        let Ok(rules) = self.lifecycle_writer() else {
            return;
        };
        let Ok(slot) = self.begin_lifecycle_call(ctx).await else {
            return;
        };
        let document = ctx.run(rules.read_lifecycle(ctx)).await;
        drop(slot);
        if let Ok(document) = document
            && let Ok(found) = parse_lifecycle_rules(&document.body)
        {
            self.set_lifecycle_rule_count(found.len());
        }
    }

    /// Read the configuration and decide the rules that the editor shows.
    pub async fn read_lifecycle_state(&self, ctx: &OpCtx) -> Result<LifecycleState> {
        let rules_api = self.lifecycle_writer()?;
        let slot = self.begin_lifecycle_call(ctx).await?;
        let document = rules_api.read_lifecycle(ctx).await;
        drop(slot);
        if let Err(error) = &document
            && provider_refused_feature(error)
        {
            self.rules.off.store(true, Ordering::SeqCst);
            return Err(lifecycle_unsupported());
        }
        self.observe_lifecycle_call(PERMISSION_READ, document.as_ref().err());
        let document = document?;
        let invalid = |error: Error| Error::api(502, "lifecycle_invalid", error.to_string());
        let config = split_lifecycle_document(&document.body).map_err(invalid)?;
        let mut rules = parse_lifecycle_rules(&document.body).map_err(invalid)?;
        self.set_lifecycle_rule_count(rules.len());
        let flavour = self.lifecycle_flavour(ctx).await;
        let versioning = self.bucket_versioning(ctx).await;
        let root_prefix = self.cfg.root_prefix.clone();
        // The shape of each rule first: for an unknown provider, a field that a rule of the bucket already uses is a
        // field that the provider keeps.
        let mut used: BTreeSet<&'static str> = BTreeSet::new();
        for item in config.items.iter().filter(|item| item.node.name == "Rule") {
            let (rule, reason) = edit_rule_from_node(&item.node, "");
            if reason.is_empty() {
                used.extend(rule.fields());
            }
        }
        let (fields, hidden) = self.lifecycle_fields_for(&flavour, &versioning, &used);
        let mut state = LifecycleState {
            body: document.body.clone(),
            ..LifecycleState::default()
        };
        let mut entries: Vec<LifecycleEntry> = Vec::with_capacity(config.items.len());
        let mut editable: Vec<usize> = Vec::new();
        for item in config.items.iter().filter(|item| item.node.name == "Rule") {
            let (rule, base_reason) = edit_rule_from_node(&item.node, &root_prefix);
            let mut reason = base_reason.to_owned();
            if reason.is_empty() {
                for field in rule.fields() {
                    if !fields.get(field).copied().unwrap_or(false) {
                        reason = format!("It uses {}, which the editor does not offer here.", field_name(field));
                        break;
                    }
                }
            }
            let index = entries.len();
            if reason.is_empty() {
                state.edit.insert(index, rule.clone());
                state.raw.insert(rule.id.clone(), item.raw.clone());
                editable.push(index);
                entries.push(LifecycleEntry {
                    editable: true,
                    rule: Some(rule),
                    ..LifecycleEntry::default()
                });
            } else if reason == REASON_OUTSIDE {
                // A rule of another part of the bucket: the person of this instance does not see its XML or its filter.
                if let Some(found) = rules.get_mut(index) {
                    state.kept_ids.push(found.id.clone());
                    *found = LifecycleRule {
                        enabled: found.enabled,
                        ..LifecycleRule::default()
                    };
                }
                entries.push(LifecycleEntry {
                    reason,
                    ..LifecycleEntry::default()
                });
            } else {
                entries.push(self.kept_entry(&mut state, &rules, index, &item.raw, &reason));
            }
        }
        let (writable, read_only) = if !self.permitted(PERMISSION_WRITE) {
            (false, "This instance has no write permission.".to_owned())
        } else if !self.lifecycle_write_refusal().is_empty() {
            (false, self.lifecycle_write_refusal())
        } else if config.root_name.contains(':') {
            (
                false,
                "The configuration uses an XML namespace prefix that the editor does not write.".to_owned(),
            )
        } else {
            (true, String::new())
        };
        state.editor = EditorState {
            hash: lifecycle_hash(&document.body, &editable),
            entries,
            fields,
            hidden,
            provider: flavour.clone(),
            provider_note: provider_note(&flavour).to_owned(),
            versioning,
            root_prefix,
            writable,
            read_only_reason: read_only,
            max_days: MAX_LIFECYCLE_DAYS,
            max_rules: MAX_LIFECYCLE_RULES,
        };
        state.rules = rules;
        state.config = config;
        Ok(state)
    }

    /// The entry of a rule that the editor keeps as it is. The ID of the rule goes in the list of the kept IDs.
    fn kept_entry(
        &self,
        state: &mut LifecycleState,
        rules: &[LifecycleRule],
        index: usize,
        raw: &[u8],
        reason: &str,
    ) -> LifecycleEntry {
        if let Some(found) = rules.get(index) {
            state.kept_ids.push(found.id.clone());
        }
        LifecycleEntry {
            editable: false,
            rule: None,
            xml: String::from_utf8_lossy(raw).into_owned(),
            reason: reason.to_owned(),
        }
    }

    /// The answer of the provider to a refused write, as the answer of the API. A 403, 501 or 405 makes the editor
    /// of the instance read only, with the reason.
    fn lifecycle_write_error(&self, error: Error) -> Error {
        let Some(upstream) = error.as_upstream() else {
            return error;
        };
        let text = status_text(upstream.status, &upstream.code);
        if provider_refused_feature(&error) {
            let reason = format!("The storage provider does not let Stowr change the lifecycle rules ({text}).");
            self.set_lifecycle_write_refusal(&reason);
            return Error::api(501, "lifecycle_write_unsupported", reason);
        }
        if upstream.status == 403 {
            let reason = format!(
                "The storage provider refused the change ({text}): the credentials of this instance cannot change the lifecycle rules."
            );
            self.set_lifecycle_write_refusal(&reason);
            return Error::api(403, "lifecycle_write_denied", reason);
        }
        if (400..500).contains(&upstream.status) {
            return Error::api(
                400,
                "lifecycle_refused",
                format!("The storage provider refused the rules ({text}). The rules of the bucket did not change."),
            );
        }
        error
    }

    /// Check the hash, write the configuration with the rules of the editor and the kept elements, and read it again.
    /// Gives the new state and a sentence for each difference between the sent and the kept rules. A state with an
    /// empty hash means that the read back failed: the sentence says it.
    pub async fn save_lifecycle(
        &self,
        ctx: &OpCtx,
        hash: &str,
        rules: &[EditRule],
    ) -> Result<(LifecycleState, Vec<String>)> {
        let backend = self.lifecycle_writer()?;
        let _step = self.rules.write.lock().await;
        let state = self.read_lifecycle_state(ctx).await?;
        if state.editor.hash != hash {
            return Err(lifecycle_changed());
        }
        if state.config.root_name.contains(':') {
            return Err(Error::api(
                409,
                "lifecycle_read_only",
                state.editor.read_only_reason.clone(),
            ));
        }
        check_lifecycle_rules(&state, rules)?;
        let body = lifecycle_document_for(&state, rules, &self.cfg.root_prefix);
        let slot = self.begin_lifecycle_call(ctx).await?;
        let result = match &body {
            None => backend.delete_lifecycle(ctx).await,
            Some(document) => backend.write_lifecycle(ctx, Bytes::from(document.clone())).await,
        };
        drop(slot);
        self.observe_lifecycle_call(PERMISSION_WRITE, result.as_ref().err());
        if let Err(error) = result {
            return Err(self.lifecycle_write_error(error));
        }
        self.set_lifecycle_write_refusal("");
        let mut read = match self.read_lifecycle_state(ctx).await {
            Ok(read) => read,
            Err(error) => {
                // The write worked: the answer must not say that the save failed. The page reads the rules again.
                let text = format!(
                    "The rules are saved, but Stowr cannot read them again ({}): read them again before another change.",
                    error.public_message()
                );
                return Ok((LifecycleState::default(), vec![text]));
            }
        };
        let (warnings, dropped) = lifecycle_warnings(&self.cfg.root_prefix, &body.unwrap_or_default(), &read, rules);
        for field in dropped {
            self.mark_lifecycle_dropped(field);
        }
        if !warnings.is_empty() {
            // A field that the provider dropped is no longer offered: the state of the answer follows.
            if let Ok(again) = self.read_lifecycle_state(ctx).await {
                read = again;
            }
        }
        Ok((read, warnings))
    }
}
