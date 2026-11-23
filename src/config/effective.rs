// SPDX-License-Identifier: MIT OR Apache-2.0
//! The effective configuration: the value that applies for each key, and its source. `print-config` writes it, and
//! the server writes it in its log at start. The output hides each secret.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::common::config::{Config, IdentityConfig, PdpConfig};

use super::EffectiveSetting;
use super::access_block::duration_text;
use super::keys::keys_of_block;
use super::quote::quote;

fn quoted_or_none(value: &str) -> String {
    if value.is_empty() {
        "<none>".to_owned()
    } else {
        quote(value)
    }
}

fn quoted_list(values: &[String]) -> String {
    let quoted: Vec<String> = values.iter().map(|value| quote(value)).collect();
    format!("[{}]", quoted.join(", "))
}

fn hidden(value: &str) -> &'static str {
    if value.is_empty() { "<none>" } else { "<hidden>" }
}

/// The text of a duration key of the access block: the text of the file or the default text. A configuration that
/// no file made has no such text: the function then gives the shortest strict text.
fn access_duration_text(config: &Config, path: &str, value: Duration) -> String {
    config
        .duration_texts
        .get(path)
        .cloned()
        .unwrap_or_else(|| duration_text(value))
}

struct Lines<'a> {
    config: &'a Config,
    out: Vec<EffectiveSetting>,
}

impl Lines<'_> {
    fn add_block(&mut self, path: &str, block_type: &str, values: &BTreeMap<&str, String>) {
        for key in keys_of_block(block_type) {
            let name = format!("{path}.{}", key.name);
            let value = values.get(key.name).cloned().unwrap_or_else(|| "<none>".to_owned());
            let source = self
                .config
                .sources
                .get(&name)
                .cloned()
                .unwrap_or_else(|| "default".to_owned());
            self.out.push(EffectiveSetting { name, value, source });
        }
    }

    fn add(&mut self, path: &str, values: &BTreeMap<&str, String>) {
        let block_type = path.split_once(' ').map_or(path, |(first, _)| first);
        self.add_block(path, block_type, values);
    }
}

/// The effective configuration: one line for each key, in the order of the table of the keys.
pub(super) fn effective(config: &Config) -> Vec<EffectiveSetting> {
    let mut lines = Lines {
        config,
        out: Vec::with_capacity(96),
    };
    let runtime = &config.runtime;
    lines.add(
        "server",
        &BTreeMap::from([
            ("listen", quote(&config.listen)),
            ("job_history_limit", config.job_history_limit.to_string()),
            ("access_mode", quote(runtime.access_mode.as_str())),
            ("log_mode", quote(runtime.log_mode.as_str())),
            (
                "allow_full_object_fallback",
                runtime.allow_full_object_fallback.to_string(),
            ),
            ("memory_limit_bytes", runtime.memory_limit_bytes.to_string()),
            (
                "max_storage_bytes_per_request",
                runtime.max_storage_bytes_per_request.to_string(),
            ),
            (
                "max_storage_requests_per_request",
                runtime.max_storage_requests_per_request.to_string(),
            ),
            ("max_range_cache_bytes", runtime.max_range_cache_bytes.to_string()),
            (
                "max_concurrent_storage_requests",
                runtime.max_concurrent_storage_requests.to_string(),
            ),
            (
                "max_concurrent_requests_per_storage",
                runtime.max_concurrent_requests_per_storage.to_string(),
            ),
            ("session_ttl_seconds", runtime.session_ttl_seconds.to_string()),
            ("max_stats_folders", runtime.max_stats_folders.to_string()),
            ("max_archive_entries", runtime.max_archive_entries.to_string()),
            (
                "max_background_storage_bytes",
                runtime.max_background_storage_bytes.to_string(),
            ),
            (
                "max_background_storage_requests",
                runtime.max_background_storage_requests.to_string(),
            ),
        ]),
    );
    let access = &config.access;
    let mode = if access.enforced() { "authzen" } else { "open" };
    lines.add_block("access", "access", &BTreeMap::from([("mode", quote(mode))]));
    if access.enforced() {
        let identity = access.identity.clone().unwrap_or_default();
        let pdp = access.pdp.clone().unwrap_or_default();
        add_identity(&mut lines, &identity);
        add_pdp(&mut lines, &pdp);
    }
    for auth in &config.auths {
        let mut values = BTreeMap::from([
            ("provider", quote(auth.provider.as_str())),
            ("mode", quote(&auth.mode)),
            ("endpoint", quote(&auth.endpoint)),
            ("access_key_id", quoted_or_none(&auth.access_key_id)),
            ("secret_access_key", hidden(&auth.secret_access_key).to_owned()),
            ("session_token", hidden(&auth.session_token).to_owned()),
            ("insecure_skip_verify", auth.insecure_skip_verify.to_string()),
        ]);
        if !auth.region.is_empty() {
            values.insert("region", quote(&auth.region));
        }
        if let Some(file) = &auth.credentials_file {
            values.insert("credentials_file", quote(&file.to_string_lossy()));
        }
        let path = format!("auth {}", quote(&auth.id));
        lines.add(&path, &values);
        if let Some(usage) = &auth.usage {
            lines.add_block(
                &format!("{path}.usage"),
                "auth.usage",
                &BTreeMap::from([
                    ("source", quote(usage.source.as_str())),
                    ("endpoint", quote(&usage.endpoint)),
                    ("filer_endpoint", quoted_or_none(&usage.filer_endpoint)),
                    ("token", hidden(&usage.token).to_owned()),
                ]),
            );
        }
    }
    for bucket in &config.buckets {
        let mut values = BTreeMap::from([
            ("name", quote(&bucket.name)),
            ("auth", quote(&bucket.auth_id)),
            ("bucket", quote(&bucket.bucket)),
            ("root_prefix", quote(&bucket.root_prefix)),
            ("max_scan_pages", bucket.max_scan_pages.to_string()),
            ("encryption", quote(bucket.encryption.as_str())),
        ]);
        if bucket.permissions_defined {
            values.insert("permissions", quoted_list(&bucket.permissions));
        }
        if bucket.quota_bytes != 0 {
            values.insert("quota_bytes", bucket.quota_bytes.to_string());
        }
        lines.add(&format!("bucket {}", quote(&bucket.id)), &values);
    }
    for volume in &config.volumes {
        let mut values = BTreeMap::from([
            ("name", quote(&volume.name)),
            ("path", quote(&volume.path.to_string_lossy())),
            ("root_prefix", quote(&volume.root_prefix)),
            ("max_scan_pages", volume.max_scan_pages.to_string()),
        ]);
        if volume.permissions_defined {
            values.insert("permissions", quoted_list(&volume.permissions));
        }
        lines.add(&format!("volume {}", quote(&volume.id)), &values);
    }
    lines.out
}

fn add_identity(lines: &mut Lines<'_>, identity: &IdentityConfig) {
    let config = lines.config;
    lines.add_block(
        "access.identity",
        "access.identity",
        &BTreeMap::from([
            ("header", quote(&identity.header)),
            ("issuer", quote(&identity.issuer)),
            ("audience", quote(&identity.audience)),
            ("public_keys", quoted_list(&identity.key_names)),
            (
                "max_age",
                quote(&access_duration_text(
                    config,
                    "access.identity.max_age",
                    identity.max_age,
                )),
            ),
            (
                "clock_skew",
                quote(&access_duration_text(
                    config,
                    "access.identity.clock_skew",
                    identity.clock_skew,
                )),
            ),
        ]),
    );
}

fn add_pdp(lines: &mut Lines<'_>, pdp: &PdpConfig) {
    let config = lines.config;
    lines.add_block(
        "access.pdp",
        "access.pdp",
        &BTreeMap::from([
            ("url", quote(&pdp.url)),
            ("plain_http", pdp.plain_http.to_string()),
            ("token", "<hidden>".to_owned()),
            (
                "timeout",
                quote(&access_duration_text(config, "access.pdp.timeout", pdp.timeout)),
            ),
            (
                "usage_timeout",
                quote(&access_duration_text(
                    config,
                    "access.pdp.usage_timeout",
                    pdp.usage_timeout,
                )),
            ),
            (
                "cache_ttl",
                quote(&access_duration_text(config, "access.pdp.cache_ttl", pdp.cache_ttl)),
            ),
            ("max_evaluations", pdp.max_evaluations.to_string()),
        ]),
    );
}
