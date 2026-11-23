//! The decoder of the configuration: the blocks `server`, `auth` (with `usage`) and `bucket`, the order of the checks,
//! the checks between the blocks, and the typed result. `access_block` and `volume_block` decode the other blocks.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use crate::common::config::{
    AccessConfig, AccessMode, AuthConfig, BucketConfig, Config, Encryption, LogMode, PERMISSION_DELETE,
    PERMISSION_READ, PERMISSION_WRITE, Provider, RuntimePolicy, UsageConfig, UsageSource, VOLUME_HOST_ID, VolumeConfig,
};

use super::env::resolve_value_source;
use super::hcl::{Block, Kind};
use super::keys::{FORM_ENV, FORM_FILE, FORM_VALUE, attribute_names, key_of_attribute, keys_of_block};
use super::paths::{clean, is_absolute, join, resolve_config_path};
use super::quote::{quote, quote_bytes};
use super::url::{parse, parse_endpoint, split_host_port};
use super::{Hooks, access_block, volume_block};

/// The longest admin token of a usage block.
const MAX_USAGE_TOKEN_BYTES: usize = 4096;
/// The largest value of `bucket.quota_bytes` (1 EiB).
const MAX_QUOTA_BYTES: i64 = 1 << 60;
/// The form of the label of an `auth`, `bucket` or `volume` block.
pub(super) const ID_PATTERN: &str = "^(?:[A-Za-z0-9][A-Za-z0-9._-]*|-)$";
/// The encryption `sse-s3`.
const ENCRYPTION_SSE_S3: &str = "sse-s3";

/// The configuration while the decoder reads the blocks. The values of the `server` block stay as integers of the
/// file until the check of their ranges.
pub(super) struct Draft {
    pub(super) listen: String,
    pub(super) job_history_limit: i64,
    pub(super) access_mode: String,
    pub(super) log_mode: String,
    pub(super) allow_full_object_fallback: bool,
    pub(super) memory_limit_bytes: i64,
    pub(super) max_storage_bytes_per_request: i64,
    pub(super) max_storage_requests_per_request: i64,
    pub(super) max_range_cache_bytes: i64,
    pub(super) max_concurrent_storage_requests: i64,
    pub(super) max_concurrent_requests_per_storage: i64,
    pub(super) session_ttl_seconds: i64,
    pub(super) max_stats_folders: i64,
    pub(super) max_archive_entries: i64,
    pub(super) max_background_storage_bytes: i64,
    pub(super) max_background_storage_requests: i64,
    pub(super) access: AccessConfig,
    pub(super) auths: Vec<AuthConfig>,
    pub(super) buckets: Vec<BucketConfig>,
    pub(super) volumes: Vec<VolumeConfig>,
    pub(super) sources: BTreeMap<String, String>,
    pub(super) duration_texts: BTreeMap<String, String>,
}

impl Draft {
    fn new() -> Self {
        let defaults = RuntimePolicy::default();
        Self {
            listen: ":8080".to_owned(),
            job_history_limit: 10,
            access_mode: defaults.access_mode.as_str().to_owned(),
            log_mode: defaults.log_mode.as_str().to_owned(),
            allow_full_object_fallback: defaults.allow_full_object_fallback,
            memory_limit_bytes: defaults.memory_limit_bytes,
            max_storage_bytes_per_request: defaults.max_storage_bytes_per_request,
            max_storage_requests_per_request: defaults.max_storage_requests_per_request,
            max_range_cache_bytes: defaults.max_range_cache_bytes,
            max_concurrent_storage_requests: i64::from(defaults.max_concurrent_storage_requests),
            max_concurrent_requests_per_storage: i64::from(defaults.max_concurrent_requests_per_storage),
            session_ttl_seconds: i64::from(defaults.session_ttl_seconds),
            max_stats_folders: i64::from(defaults.max_stats_folders),
            max_archive_entries: i64::from(defaults.max_archive_entries),
            max_background_storage_bytes: defaults.max_background_storage_bytes,
            max_background_storage_requests: defaults.max_background_storage_requests,
            access: AccessConfig::default(),
            auths: Vec::new(),
            buckets: Vec::new(),
            volumes: Vec::new(),
            sources: BTreeMap::new(),
            duration_texts: BTreeMap::new(),
        }
    }
}

/// True for a control character: C0, DEL or C1.
pub(super) fn has_control_character(value: &str) -> bool {
    value
        .chars()
        .any(|c| (c as u32) < 0x20 || (0x7f..0xa0).contains(&(c as u32)))
}

/// True for a space or a control character of C0, or DEL.
fn has_space_or_control(value: &str) -> bool {
    value.chars().any(|c| c <= ' ' || c == '\u{7f}')
}

/// True when the label is an id: a letter or a digit, then letters, digits, `.`, `_` and `-`; or `-` alone.
pub(super) fn valid_id(label: &[u8]) -> bool {
    if label == b"-" {
        return true;
    }
    match label.split_first() {
        Some((first, rest)) => {
            first.is_ascii_alphanumeric()
                && rest
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        }
        None => false,
    }
}

/// Stop at the first attribute of the block, in the order of the file, that the block does not accept.
pub(super) fn reject_unknown_attrs(block: &Block, allowed: &[String]) -> Result<(), String> {
    for attr in &block.attrs {
        if !allowed.iter().any(|name| name.as_bytes() == attr.name.as_slice()) {
            return Err(format!(
                "line {}:{}: unknown attribute {} in {} block",
                attr.line,
                attr.column,
                quote_bytes(&attr.name),
                block.kind_text()
            ));
        }
    }
    Ok(())
}

/// Stop at the first attribute of the block, in the order of the file, with a value of a wrong kind. `kind_of`
/// gives the kind of each name that has one.
pub(super) fn require_attr_kinds(block: &Block, kind_of: impl Fn(&[u8]) -> Option<Kind>) -> Result<(), String> {
    for attr in &block.attrs {
        let Some(kind) = kind_of(&attr.name) else {
            continue;
        };
        if attr.value.kind() != kind {
            return Err(format!(
                "line {}:{}: attribute {} must be {}",
                attr.line,
                attr.column,
                quote_bytes(&attr.name),
                kind.expected()
            ));
        }
    }
    Ok(())
}

/// Stop when the block has a secret in clear text. The error names the key and never shows the value.
pub(super) fn reject_clear_secrets(block: &Block, path: &str, block_type: &str) -> Result<(), String> {
    for key in keys_of_block(block_type) {
        if !key.secret || key.forms & FORM_VALUE != 0 {
            continue;
        }
        if let Some(attr) = block.attr(key.name) {
            let name = key.name;
            return Err(format!(
                "line {}:{}: {path}.{name} is a secret: use {name}_env or {name}_file, not the value in clear text",
                attr.line, attr.column
            ));
        }
    }
    Ok(())
}

/// Read a text attribute as it is in the file. An empty value, or a value with a space at the start or at the end,
/// is an error.
pub(super) fn text_attr(block: &Block, path: &str, name: &str) -> Result<Option<String>, String> {
    let Some(value) = block.string(name) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err(block.error(format!(
            "{path}.{name} must not be empty; remove the attribute to use its default"
        )));
    }
    if value.trim() != value {
        return Err(block.error(format!(
            "{path}.{name} must not have a space at the start or at the end, got {}",
            quote(value)
        )));
    }
    Ok(Some(value.to_owned()))
}

/// Note the source of each attribute of a block: `file` for a value in the file, `env:VAR` or `file:/path` for an
/// indirect form.
pub(super) fn record_sources(
    sources: &mut BTreeMap<String, String>,
    path: &str,
    block_type: &str,
    block: &Block,
    base_dir: &str,
) {
    for attr in &block.attrs {
        let Some((key, form)) = key_of_attribute(block_type, &attr.name) else {
            continue;
        };
        let value = match &attr.value.data {
            super::hcl::Data::String(text) => text.as_str(),
            _ => "",
        };
        let source = match form {
            FORM_ENV => format!("env:{value}"),
            FORM_FILE => format!("file:{}", resolve_config_path(value, base_dir)),
            _ => "file".to_owned(),
        };
        sources.insert(format!("{path}.{}", key.name), source);
    }
}

/// Check `server.listen`: a `host:port` address with a port from 1 to 65535, not a URL. The value does not change.
pub(super) fn normalize_listen_address(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("cannot be empty".to_owned());
    }
    if value.chars().any(|c| c <= ' ') {
        return Err("must not contain a space or a control character".to_owned());
    }
    if value.contains("://") {
        return Err("must be a host:port address, not a URL".to_owned());
    }
    let (_, port) = split_host_port(value).map_err(|error| format!("must be a valid host:port address: {error}"))?;
    match parse_decimal(port) {
        Some(number) if (1..=65535).contains(&number) => Ok(value.to_owned()),
        _ => Err("port must be an integer between 1 and 65535".to_owned()),
    }
}

/// A decimal integer with an optional sign, as the port of `server.listen` accepts it.
fn parse_decimal(text: &str) -> Option<i64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok()
}

/// Read the text of a configuration into the typed configuration.
pub(super) fn decode(data: &[u8], source_name: &str, source_dir: &str, hooks: &Hooks<'_>) -> Result<Config, String> {
    let root =
        super::hcl::parse(data).map_err(|error| format!("parse configuration {}: {error}", quote(source_name)))?;
    let mut draft = Draft::new();
    if let Some(attr) = root.attrs.first() {
        return Err(format!(
            "line {}:{}: root attribute {} is not supported; use a block",
            attr.line,
            attr.column,
            quote_bytes(&attr.name)
        ));
    }
    let (mut server_seen, mut access_seen) = (false, false);
    let mut instance_ids: HashSet<Vec<u8>> = HashSet::new();
    let mut bucket_blocks: Vec<&Block> = Vec::new();
    for block in &root.blocks {
        match block.kind.as_slice() {
            b"server" => {
                if server_seen {
                    return Err("only one server block is allowed".to_owned());
                }
                server_seen = true;
                decode_server_block(block, &mut draft)?;
                record_sources(&mut draft.sources, "server", "server", block, source_dir);
            }
            b"access" => {
                if access_seen {
                    return Err(block.error("only one access block is allowed"));
                }
                access_seen = true;
                access_block::decode(block, &mut draft, source_dir, hooks)?;
            }
            b"auth" => {
                let auth = decode_auth_block(block, source_dir, hooks)?;
                let path = format!("auth {}", quote(&auth.id));
                record_sources(&mut draft.sources, &path, "auth", block, source_dir);
                if let Ok(Some(usage)) = auth_usage_block(block) {
                    record_sources(
                        &mut draft.sources,
                        &format!("{path}.usage"),
                        "auth.usage",
                        usage,
                        source_dir,
                    );
                }
                if draft.auths.iter().any(|known| known.id == auth.id) {
                    return Err(block.error(format!("duplicate auth id {}", quote(&auth.id))));
                }
                draft.auths.push(auth);
            }
            b"bucket" => {
                let [label] = block.labels.as_slice() else {
                    return Err(block.error("bucket block requires exactly one quoted identifier"));
                };
                if !instance_ids.insert(label.clone()) {
                    return Err(block.error(format!("duplicate bucket id {}", quote_bytes(label))));
                }
                bucket_blocks.push(block);
            }
            b"volume" => {
                let volume = volume_block::decode(block, hooks)?;
                if !instance_ids.insert(volume.id.as_bytes().to_vec()) {
                    return Err(block.error(format!(
                        "duplicate bucket or volume id {}: a volume block and a bucket block cannot have the same label",
                        quote(&volume.id)
                    )));
                }
                let path = format!("volume {}", quote(&volume.id));
                draft.volumes.push(volume);
                record_sources(&mut draft.sources, &path, "volume", block, source_dir);
            }
            _ => {
                return Err(block.error(format!(
                    "unknown block type {}; supported blocks are server, access, auth, bucket and volume",
                    quote_bytes(&block.kind)
                )));
            }
        }
    }

    if bucket_blocks.is_empty() && draft.volumes.is_empty() {
        return Err("at least one bucket block or one volume block is required".to_owned());
    }
    if !bucket_blocks.is_empty() && draft.auths.is_empty() {
        return Err("at least one auth block is required".to_owned());
    }
    if draft.auths.iter().any(|auth| auth.id == VOLUME_HOST_ID) && !draft.volumes.is_empty() {
        let word = quote(VOLUME_HOST_ID);
        return Err(format!(
            "auth {word}: the label {word} is the address word of the volumes in the interface (/-/{VOLUME_HOST_ID}/<id>/), and the file has a volume block; give the auth block an other label"
        ));
    }
    for block in bucket_blocks {
        let bucket = decode_bucket_block(block, &draft.auths)?;
        let path = format!("bucket {}", quote(&bucket.id));
        draft.buckets.push(bucket);
        record_sources(&mut draft.sources, &path, "bucket", block, source_dir);
    }
    let (listen, job_history_limit, runtime) = validate_runtime_policy(&draft)?;
    if !access_seen {
        return Err("the access block is required: add `access { mode = \"open\" }` (no check), or an access block with mode = \"authzen\", an identity block and a pdp block".to_owned());
    }
    access_block::validate_resources(&draft)?;
    let refuse_links = draft.access.enforced();
    for volume in &mut draft.volumes {
        volume.refuse_links = refuse_links;
    }
    Ok(Config {
        listen,
        job_history_limit,
        runtime,
        access: draft.access,
        auths: draft.auths,
        buckets: draft.buckets,
        volumes: draft.volumes,
        source_dir: PathBuf::from(source_dir),
        source_name: PathBuf::from(source_name),
        sources: draft.sources,
        duration_texts: draft.duration_texts,
    })
}

fn decode_server_block(block: &Block, draft: &mut Draft) -> Result<(), String> {
    if !block.labels.is_empty() {
        return Err(block.error("server block does not accept labels"));
    }
    if !block.blocks.is_empty() {
        return Err(block.error("nested blocks are not supported inside server"));
    }
    reject_unknown_attrs(block, &attribute_names("server"))?;
    require_attr_kinds(block, |name| match name {
        b"listen" | b"access_mode" | b"log_mode" => Some(Kind::String),
        b"allow_full_object_fallback" => Some(Kind::Bool),
        b"job_history_limit"
        | b"memory_limit_bytes"
        | b"max_storage_bytes_per_request"
        | b"max_storage_requests_per_request"
        | b"max_range_cache_bytes"
        | b"max_concurrent_storage_requests"
        | b"max_concurrent_requests_per_storage"
        | b"session_ttl_seconds"
        | b"max_stats_folders"
        | b"max_archive_entries"
        | b"max_background_storage_bytes"
        | b"max_background_storage_requests" => Some(Kind::Number),
        _ => None,
    })?;
    if let Some(value) = block.string("listen") {
        let listen = normalize_listen_address(value)
            .map_err(|error| block.error(format!("server.listen: {error}, got {}", quote(value))))?;
        draft.listen = listen;
    }
    if let Some(value) = block.integer("job_history_limit") {
        if !(1..=20).contains(&value) {
            return Err(block.error(format!(
                "server.job_history_limit must be between 1 and 20, got {value}"
            )));
        }
        draft.job_history_limit = value;
    }
    if let Some(value) = block.string("access_mode") {
        value.clone_into(&mut draft.access_mode);
    }
    if let Some(value) = block.string("log_mode") {
        value.clone_into(&mut draft.log_mode);
    }
    if let Some(value) = block.boolean("allow_full_object_fallback") {
        draft.allow_full_object_fallback = value;
    }
    let integers: [(&str, &mut i64); 11] = [
        ("memory_limit_bytes", &mut draft.memory_limit_bytes),
        (
            "max_storage_bytes_per_request",
            &mut draft.max_storage_bytes_per_request,
        ),
        (
            "max_storage_requests_per_request",
            &mut draft.max_storage_requests_per_request,
        ),
        ("max_range_cache_bytes", &mut draft.max_range_cache_bytes),
        ("max_background_storage_bytes", &mut draft.max_background_storage_bytes),
        (
            "max_background_storage_requests",
            &mut draft.max_background_storage_requests,
        ),
        (
            "max_concurrent_storage_requests",
            &mut draft.max_concurrent_storage_requests,
        ),
        (
            "max_concurrent_requests_per_storage",
            &mut draft.max_concurrent_requests_per_storage,
        ),
        ("session_ttl_seconds", &mut draft.session_ttl_seconds),
        ("max_stats_folders", &mut draft.max_stats_folders),
        ("max_archive_entries", &mut draft.max_archive_entries),
    ];
    for (name, destination) in integers {
        if let Some(value) = block.integer(name) {
            *destination = value;
        }
    }
    Ok(())
}

fn small(value: i64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Check the values of the `server` block. The errors have no line: a value can be a default.
fn validate_runtime_policy(draft: &Draft) -> Result<(String, u32, RuntimePolicy), String> {
    let listen = normalize_listen_address(&draft.listen).map_err(|error| format!("server.listen: {error}"))?;
    let access_mode = match draft.access_mode.as_str() {
        "inherit_credentials" => AccessMode::InheritCredentials,
        "force_read_only" => AccessMode::ForceReadOnly,
        other => {
            return Err(format!(
                "server.access_mode must be \"inherit_credentials\" or \"force_read_only\", got {}",
                quote(other)
            ));
        }
    };
    let log_mode = match draft.log_mode.as_str() {
        "anonymous" => LogMode::Anonymous,
        "detailed" => LogMode::Detailed,
        other => {
            return Err(format!(
                "server.log_mode must be \"anonymous\" or \"detailed\", got {}",
                quote(other)
            ));
        }
    };
    let check = |name: &str, value: i64, minimum: i64, maximum: i64| {
        if value < minimum || value > maximum {
            return Err(format!(
                "server.{name} must be between {minimum} and {maximum}, got {value}"
            ));
        }
        Ok(())
    };
    if draft.memory_limit_bytes != 0 {
        check("memory_limit_bytes", draft.memory_limit_bytes, 32 << 20, 1 << 50)?;
    }
    check(
        "max_storage_bytes_per_request",
        draft.max_storage_bytes_per_request,
        1 << 20,
        1 << 50,
    )?;
    check(
        "max_storage_requests_per_request",
        draft.max_storage_requests_per_request,
        1,
        10_000_000,
    )?;
    check("max_range_cache_bytes", draft.max_range_cache_bytes, 1 << 20, 4 << 30)?;
    check(
        "max_background_storage_bytes",
        draft.max_background_storage_bytes,
        1 << 20,
        1 << 50,
    )?;
    check(
        "max_background_storage_requests",
        draft.max_background_storage_requests,
        1,
        10_000_000,
    )?;
    check(
        "max_concurrent_storage_requests",
        draft.max_concurrent_storage_requests,
        1,
        1024,
    )?;
    check(
        "max_concurrent_requests_per_storage",
        draft.max_concurrent_requests_per_storage,
        1,
        256,
    )?;
    if draft.max_concurrent_requests_per_storage > draft.max_concurrent_storage_requests {
        return Err(format!(
            "server.max_concurrent_requests_per_storage ({}) cannot exceed max_concurrent_storage_requests ({})",
            draft.max_concurrent_requests_per_storage, draft.max_concurrent_storage_requests
        ));
    }
    check("session_ttl_seconds", draft.session_ttl_seconds, 30, 7 * 24 * 60 * 60)?;
    check("max_stats_folders", draft.max_stats_folders, 100, 1_000_000)?;
    check("max_archive_entries", draft.max_archive_entries, 1, 1_000_000)?;
    let runtime = RuntimePolicy {
        access_mode,
        allow_full_object_fallback: draft.allow_full_object_fallback,
        log_mode,
        memory_limit_bytes: draft.memory_limit_bytes,
        max_storage_bytes_per_request: draft.max_storage_bytes_per_request,
        max_storage_requests_per_request: draft.max_storage_requests_per_request,
        max_range_cache_bytes: draft.max_range_cache_bytes,
        max_concurrent_storage_requests: small(draft.max_concurrent_storage_requests),
        max_concurrent_requests_per_storage: small(draft.max_concurrent_requests_per_storage),
        session_ttl_seconds: small(draft.session_ttl_seconds),
        max_stats_folders: small(draft.max_stats_folders),
        max_archive_entries: small(draft.max_archive_entries),
        max_background_storage_bytes: draft.max_background_storage_bytes,
        max_background_storage_requests: draft.max_background_storage_requests,
    };
    Ok((listen, small(draft.job_history_limit), runtime))
}

/// The `usage` block of an `auth` block, or `None`. It is the only nested block of `auth`, and it can be there one
/// time.
fn auth_usage_block(block: &Block) -> Result<Option<&Block>, String> {
    let mut usage = None;
    for nested in &block.blocks {
        if nested.kind != b"usage" {
            return Err(nested.error(format!(
                "unknown block {} in auth; the only block is usage",
                quote_bytes(&nested.kind)
            )));
        }
        if usage.is_some() {
            let label = block.labels.first().map(Vec::as_slice).unwrap_or_default();
            return Err(nested.error(format!(
                "only one usage block is allowed in auth {}",
                quote_bytes(label)
            )));
        }
        usage = Some(nested);
    }
    Ok(usage)
}

/// Read an S3 secret of an `auth` block: only the forms `_env` and `_file`. A value with a space or a control
/// character is an error, and the error does not show the value.
fn resolve_secret_source(
    block: &Block,
    path: &str,
    name: &str,
    base_dir: &str,
    hooks: &Hooks<'_>,
) -> Result<Option<String>, String> {
    let Some(value) = resolve_value_source(block, path, name, base_dir, FORM_ENV | FORM_FILE, hooks)? else {
        return Ok(None);
    };
    if has_space_or_control(&value) {
        return Err(block.error(format!("{path}.{name} must not contain a space or a control character")));
    }
    Ok(Some(value))
}

fn decode_auth_block(block: &Block, base_dir: &str, hooks: &Hooks<'_>) -> Result<AuthConfig, String> {
    let [label] = block.labels.as_slice() else {
        return Err(block.error("auth block requires exactly one quoted identifier"));
    };
    reject_clear_secrets(block, &format!("auth {}", quote_bytes(label)), "auth")?;
    let allowed = attribute_names("auth");
    reject_unknown_attrs(block, &allowed)?;
    require_attr_kinds(block, |name| {
        if name == b"insecure_skip_verify" {
            return Some(Kind::Bool);
        }
        allowed
            .iter()
            .any(|allowed| allowed.as_bytes() == name)
            .then_some(Kind::String)
    })?;
    let usage_block = auth_usage_block(block)?;
    if !valid_id(label) {
        return Err(block.error(format!(
            "auth label must match {ID_PATTERN}, got {}",
            quote_bytes(label)
        )));
    }
    let id = String::from_utf8_lossy(label).into_owned();
    let path = format!("auth {}", quote(&id));
    let provider = text_attr(block, &path, "provider")?.unwrap_or_default();
    let mut mode = text_attr(block, &path, "mode")?.unwrap_or_default();
    let mut endpoint = text_attr(block, &path, "endpoint")?.unwrap_or_default();
    let region = text_attr(block, &path, "region")?.unwrap_or_default();
    let mut credentials_file = text_attr(block, &path, "credentials_file")?.unwrap_or_default();
    let insecure_skip_verify = block.boolean("insecure_skip_verify").unwrap_or(false);
    if endpoint.ends_with('/') {
        return Err(block.error(format!(
            "{path}.endpoint must not end with \"/\", got {}",
            quote(&endpoint)
        )));
    }

    // access_key_id is an identifier, not a secret: it accepts the three forms.
    let access_key = resolve_value_source(
        block,
        &path,
        "access_key_id",
        base_dir,
        FORM_VALUE | FORM_ENV | FORM_FILE,
        hooks,
    )?;
    if let Some(key) = &access_key
        && (key.trim() != key || has_control_character(key))
    {
        return Err(block.error(format!(
            "{path}.access_key_id must not have a space at the start or at the end or a control character, got {}",
            quote(key)
        )));
    }
    let secret_access_key = resolve_secret_source(block, &path, "secret_access_key", base_dir, hooks)?;
    let session_token = resolve_secret_source(block, &path, "session_token", base_dir, hooks)?;
    let has_credentials = access_key.is_some() || secret_access_key.is_some() || session_token.is_some();

    if provider.is_empty() {
        return Err(block.error(format!("{path}.provider is required: \"s3\" or \"gcs\"")));
    }
    let provider = match provider.as_str() {
        "s3" => {
            if !credentials_file.is_empty() {
                return Err(block.error(format!(
                    "{path}.credentials_file is only supported for provider \"gcs\""
                )));
            }
            if endpoint.is_empty() {
                return Err(block.error(format!("{path}.endpoint is required for provider \"s3\"")));
            }
            if region.is_empty() {
                return Err(block.error(format!("{path}.region is required for provider \"s3\"")));
            }
            if mode.is_empty() {
                mode = if has_credentials { "access_key" } else { "anonymous" }.to_owned();
            }
            match mode.as_str() {
                "access_key" => {
                    if access_key.is_none() || secret_access_key.is_none() {
                        return Err(block.error(format!(
                            "{path}: mode \"access_key\" requires access_key_id and secret_access_key (_env or _file)"
                        )));
                    }
                }
                "anonymous" => {
                    if has_credentials {
                        return Err(block.error(format!("{path}: mode \"anonymous\" cannot define access credentials")));
                    }
                }
                _ => {
                    return Err(block.error(format!(
                        "{path}.mode must be \"access_key\" or \"anonymous\" for provider \"s3\", got {}",
                        quote(&mode)
                    )));
                }
            }
            Provider::S3
        }
        "gcs" => {
            if has_credentials {
                return Err(block.error(format!(
                    "{path}: the S3 credential attributes are only supported for provider \"s3\""
                )));
            }
            if endpoint.is_empty() {
                "https://storage.googleapis.com".clone_into(&mut endpoint);
            }
            if mode.is_empty() {
                mode = if credentials_file.is_empty() {
                    "anonymous"
                } else {
                    "service_account"
                }
                .to_owned();
            }
            match mode.as_str() {
                "service_account" => {
                    if credentials_file.is_empty() {
                        return Err(block.error(format!("{path}: mode \"service_account\" requires credentials_file")));
                    }
                }
                "anonymous" => {
                    if !credentials_file.is_empty() {
                        return Err(block.error(format!("{path}: mode \"anonymous\" cannot define credentials_file")));
                    }
                }
                _ => {
                    return Err(block.error(format!(
                        "{path}.mode must be \"service_account\" or \"anonymous\" for provider \"gcs\", got {}",
                        quote(&mode)
                    )));
                }
            }
            Provider::Gcs
        }
        other => {
            return Err(block.error(format!(
                "{path}.provider must be \"s3\" or \"gcs\", got {}",
                quote(other)
            )));
        }
    };
    if !credentials_file.is_empty() {
        credentials_file = if is_absolute(&credentials_file) {
            clean(&credentials_file)
        } else {
            join(base_dir, &credentials_file)
        };
    }
    if let Err(error) = parse_endpoint(provider.as_str(), &endpoint) {
        return Err(block.error(format!("{path}.endpoint: {error}, got {}", quote(&endpoint))));
    }
    let mut auth = AuthConfig {
        id,
        provider,
        mode,
        endpoint,
        region,
        access_key_id: access_key.unwrap_or_default(),
        secret_access_key: secret_access_key.unwrap_or_default(),
        session_token: session_token.unwrap_or_default(),
        credentials_file: (!credentials_file.is_empty()).then(|| PathBuf::from(credentials_file)),
        insecure_skip_verify,
        usage: None,
    };
    if let Some(usage_block) = usage_block {
        auth.usage = Some(decode_usage_block(usage_block, &auth, base_dir, hooks)?);
    }
    Ok(auth)
}

/// Check the URL of an admin API: http or https, a host, no credentials, no query, no fragment, and no `/` at the
/// end.
fn validate_usage_endpoint(value: &str) -> Result<(), String> {
    parse_endpoint("usage", value).map_err(|error| error.to_string())?;
    if value.ends_with('/') {
        return Err("must not end with \"/\"".to_owned());
    }
    Ok(())
}

/// Read the `usage` block of an `auth` block. The source is explicit: the server never guesses it. Each source has
/// its own keys, and a key of another source is a contradiction.
fn decode_usage_block(
    block: &Block,
    auth: &AuthConfig,
    base_dir: &str,
    hooks: &Hooks<'_>,
) -> Result<UsageConfig, String> {
    let path = format!("auth {}.usage", quote(&auth.id));
    if !block.labels.is_empty() {
        return Err(block.error(format!("{path} block does not accept labels")));
    }
    if !block.blocks.is_empty() {
        return Err(block.error(format!("nested blocks are not supported inside {path}")));
    }
    reject_clear_secrets(block, &path, "auth.usage")?;
    reject_unknown_attrs(block, &attribute_names("auth.usage"))?;
    require_attr_kinds(block, |_| Some(Kind::String))?;
    let Some(source) = text_attr(block, &path, "source")? else {
        return Err(block.error(format!(
            "{path}.source is required: \"garage\", \"seaweedfs\" or \"minio\""
        )));
    };
    let source = match source.as_str() {
        "garage" => UsageSource::Garage,
        "seaweedfs" => UsageSource::SeaweedFs,
        "minio" => UsageSource::MinIo,
        other => {
            return Err(block.error(format!(
                "{path}.source must be \"garage\", \"seaweedfs\" or \"minio\" (lower case), got {}",
                quote(other)
            )));
        }
    };
    if auth.provider != Provider::S3 {
        return Err(block.error(format!(
            "{path}: a usage block needs provider \"s3\", but auth {} has provider {}; remove the block",
            quote(&auth.id),
            quote(auth.provider.as_str())
        )));
    }
    let endpoint = text_attr(block, &path, "endpoint")?;
    let filer = text_attr(block, &path, "filer_endpoint")?;
    for (name, value) in [("endpoint", &endpoint), ("filer_endpoint", &filer)] {
        let Some(value) = value else {
            continue;
        };
        if let Err(error) = validate_usage_endpoint(value) {
            // A URL with user information can hold a password: the error does not show such a value.
            if parse(value).is_ok_and(|url| url.user.is_some()) {
                return Err(block.error(format!("{path}.{name}: {error}")));
            }
            return Err(block.error(format!("{path}.{name}: {error}, got {}", quote(value))));
        }
    }
    let token = resolve_value_source(block, &path, "token", base_dir, FORM_ENV | FORM_FILE, hooks)?;
    if let Some(token) = &token
        && (token.len() > MAX_USAGE_TOKEN_BYTES || has_space_or_control(token))
    {
        // The error never shows the token.
        return Err(block.error(format!(
            "{path}.token must have 1 to {MAX_USAGE_TOKEN_BYTES} bytes without a space or a control character"
        )));
    }
    let name = quote(source.as_str());
    let (garage, seaweedfs) = (quote("garage"), quote("seaweedfs"));
    let mut endpoint = endpoint;
    match source {
        UsageSource::Garage => {
            if endpoint.is_none() {
                return Err(block.error(format!(
                    "{path}.endpoint is required with source {name}: the URL of the admin API of Garage (port 3903 by default)"
                )));
            }
            if token.is_none() {
                return Err(block.error(format!(
                    "{path}.token is required with source {name}: give token_env or token_file (the admin token of Garage)"
                )));
            }
            if filer.is_some() {
                return Err(block.error(format!(
                    "{path}.filer_endpoint is only for source {seaweedfs}; remove it for source {name}"
                )));
            }
        }
        UsageSource::SeaweedFs => {
            if endpoint.is_none() {
                return Err(block.error(format!(
                    "{path}.endpoint is required with source {name}: the URL of the master of SeaweedFS (port 9333 by default)"
                )));
            }
            if filer.is_none() {
                return Err(block.error(format!(
                    "{path}.filer_endpoint is required with source {name}: the URL of the filer of SeaweedFS (port 8888 by default)"
                )));
            }
            if token.is_some() {
                return Err(block.error(format!(
                    "{path}.token is only for source {garage}; remove it for source {name}"
                )));
            }
        }
        UsageSource::MinIo => {
            if filer.is_some() {
                return Err(block.error(format!(
                    "{path}.filer_endpoint is only for source {seaweedfs}; remove it for source {name}"
                )));
            }
            if token.is_some() {
                return Err(block.error(format!(
                    "{path}.token is only for source {garage}; source {name} signs with the S3 credentials of auth {}",
                    quote(&auth.id)
                )));
            }
            if auth.mode != "access_key" {
                return Err(block.error(format!(
                    "{path}: source {name} needs auth {} with mode \"access_key\" (the admin API of MinIO refuses anonymous requests), got mode {}",
                    quote(&auth.id),
                    quote(&auth.mode)
                )));
            }
            if endpoint.is_none() {
                endpoint = Some(auth.endpoint.clone());
            }
        }
    }
    Ok(UsageConfig {
        source,
        endpoint: endpoint.unwrap_or_default(),
        filer_endpoint: filer.unwrap_or_default(),
        token: token.unwrap_or_default(),
    })
}

/// Read the permissions of a `bucket` or `volume` block: `read`, `write` and `delete`, each one time.
pub(super) fn decode_permissions(block: &Block, path: &str) -> Result<Option<Vec<String>>, String> {
    let Some(values) = block.strings("permissions") else {
        return Ok(None);
    };
    let mut permissions: Vec<String> = Vec::with_capacity(3);
    for value in values {
        match value.as_str() {
            PERMISSION_READ | PERMISSION_WRITE | PERMISSION_DELETE => {
                if permissions.contains(&value) {
                    return Err(block.error(format!("{path}.permissions contains {} two times", quote(&value))));
                }
                permissions.push(value);
            }
            _ => {
                return Err(block.error(format!(
                    "{path}.permissions must contain only \"read\", \"write\" and \"delete\", got {}",
                    quote(&value)
                )));
            }
        }
    }
    Ok(Some(permissions))
}

fn decode_bucket_block(block: &Block, auths: &[AuthConfig]) -> Result<BucketConfig, String> {
    let [label] = block.labels.as_slice() else {
        return Err(block.error("bucket block requires exactly one quoted identifier"));
    };
    reject_unknown_attrs(block, &attribute_names("bucket"))?;
    require_attr_kinds(block, |name| match name {
        b"name" | b"auth" | b"bucket" | b"root_prefix" | b"encryption" => Some(Kind::String),
        b"permissions" => Some(Kind::List),
        b"max_scan_pages" | b"quota_bytes" => Some(Kind::Number),
        _ => None,
    })?;
    if !block.blocks.is_empty() {
        return Err(block.error("nested blocks are not supported inside bucket"));
    }
    if !valid_id(label) {
        return Err(block.error(format!(
            "bucket label must match {ID_PATTERN}, got {}",
            quote_bytes(label)
        )));
    }
    let id = String::from_utf8_lossy(label).into_owned();
    let path = format!("bucket {}", quote(&id));
    let name = text_attr(block, &path, "name")?.unwrap_or_else(|| id.clone());
    let auth_id = text_attr(block, &path, "auth")?.unwrap_or_default();
    let bucket_name = text_attr(block, &path, "bucket")?.unwrap_or_default();
    let mut root_prefix = String::new();
    if let Some(value) = block.string("root_prefix") {
        // The value applies as it is: "" (the whole bucket), or a key prefix that ends with "/".
        if !value.is_empty() && (value.starts_with('/') || !value.ends_with('/') || value.contains('\0')) {
            return Err(block.error(format!(
                "{path}.root_prefix must be \"\" or a prefix that ends with \"/\" and does not start with \"/\" (for example \"published/\"), got {}",
                quote(value)
            )));
        }
        value.clone_into(&mut root_prefix);
    }
    let mut max_scan_pages = 1;
    if let Some(value) = block.integer("max_scan_pages") {
        if !(0..=1_000_000).contains(&value) {
            return Err(block.error(format!(
                "{path}.max_scan_pages must be between 0 and 1000000, got {value}"
            )));
        }
        max_scan_pages = small(value);
    }
    let mut encryption = Encryption::None;
    if let Some(value) = block.string("encryption") {
        // The value applies as it is: no change of case, no space removed.
        encryption = match value {
            "" => Encryption::None,
            ENCRYPTION_SSE_S3 => Encryption::SseS3,
            _ => {
                return Err(block.error(format!(
                    "{path}.encryption must be \"\" (no encryption header) or {} (x-amz-server-side-encryption: AES256), got {}; SSE-C and SSE-KMS are not supported",
                    quote(ENCRYPTION_SSE_S3),
                    quote(value)
                )));
            }
        };
    }
    let mut quota_bytes = 0;
    if let Some(value) = block.integer("quota_bytes") {
        if !(1..=MAX_QUOTA_BYTES).contains(&value) {
            return Err(block.error(format!(
                "{path}.quota_bytes must be between 1 and {MAX_QUOTA_BYTES}, got {value}; remove the key for no limit"
            )));
        }
        quota_bytes = value;
    }
    let permissions = decode_permissions(block, &path)?;
    if auth_id.is_empty() {
        return Err(block.error(format!("{path}.auth is required")));
    }
    if bucket_name.is_empty() {
        return Err(block.error(format!("{path}.bucket is required")));
    }
    let Some(auth) = auths.iter().find(|auth| auth.id == auth_id) else {
        return Err(block.error(format!("{path}.auth: no auth block has the label {}", quote(&auth_id))));
    };
    // The GCS API has no x-amz-server-side-encryption header: the two keys contradict each other.
    if encryption != Encryption::None && auth.provider != Provider::S3 {
        return Err(block.error(format!(
            "{path}.encryption = {} needs an auth block with provider \"s3\", but auth {} has provider {}; remove the key for this bucket",
            quote(encryption.as_str()),
            quote(&auth_id),
            quote(auth.provider.as_str())
        )));
    }
    // The limit of the operator needs the used bytes, and only a usage block gives them.
    if quota_bytes != 0 && auth.usage.is_none() {
        return Err(block.error(format!(
            "{path}.quota_bytes needs a usage block in auth {}: without it, the server cannot read the used bytes; add the block or remove the key",
            quote(&auth_id)
        )));
    }
    Ok(BucketConfig {
        id,
        name,
        auth_id,
        provider: auth.provider.as_str().to_owned(),
        bucket: bucket_name,
        region: auth.region.clone(),
        permissions_defined: permissions.is_some(),
        permissions: permissions.unwrap_or_default(),
        root_prefix,
        max_scan_pages,
        encryption,
        quota_bytes,
    })
}
