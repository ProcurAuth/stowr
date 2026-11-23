//! The `access` block (docs/ACCESS.md): mode `authzen` (the server checks the identity token and asks the PDP) or mode
//! `open` (no check), the blocks `identity` and `pdp`, the strict durations, the checks against the bucket and volume
//! blocks, and the warnings of the start.

use std::time::Duration;

use crate::common::config::{AccessConfig, AccessPolicy, Config, IdentityConfig, PdpConfig};

use super::Hooks;
use super::decode::{
    Draft, has_control_character, record_sources, reject_clear_secrets, reject_unknown_attrs, require_attr_kinds,
};
use super::env::resolve_value_source;
use super::hcl::{Block, Kind};
use super::keys::{FORM_ENV, FORM_FILE, FORM_VALUE, attribute_names};
use super::quote::{quote, quote_bytes};
use super::url::{parse, split_host_port};

/// The default name of the header of the identity token.
pub const DEFAULT_IDENTITY_HEADER: &str = "X-Identity-Token";
/// The default text of `access.identity.max_age`.
pub const DEFAULT_IDENTITY_MAX_AGE: &str = "5m";
/// The default text of `access.identity.clock_skew`.
pub const DEFAULT_IDENTITY_CLOCK_SKEW: &str = "60s";
/// The default text of `access.pdp.timeout`.
pub const DEFAULT_PDP_TIMEOUT: &str = "500ms";
/// The default text of `access.pdp.usage_timeout`.
pub const DEFAULT_PDP_USAGE_TIMEOUT: &str = "6s";
/// The default text of `access.pdp.cache_ttl`.
pub const DEFAULT_PDP_CACHE_TTL: &str = "30s";
/// The default of `access.pdp.max_evaluations`.
pub const DEFAULT_PDP_MAX_EVALUATIONS: u32 = 64;
/// The largest value of `access.pdp.max_evaluations`.
pub const MAX_PDP_EVALUATIONS: i64 = 1024;
/// The longest name of the header of the identity token.
const MAX_IDENTITY_HEADER_CHARS: usize = 64;
/// The longest issuer.
const MAX_ISSUER_BYTES: usize = 1024;
/// The longest audience and the longest label of a bucket or a volume in mode `authzen`: the id of a node.
pub const MAX_ACCESS_ID_BYTES: usize = 256;
/// The longest token of the PDP.
const MAX_PDP_TOKEN_BYTES: usize = 4096;
/// The most bucket blocks and volume blocks together in mode `authzen`: the action document lists one resource for
/// each of them.
pub const MAX_ACCESS_RESOURCES: usize = 256;

const MILLISECOND: u128 = 1_000_000;
const SECOND: u128 = 1_000 * MILLISECOND;
const MINUTE: u128 = 60 * SECOND;
const HOUR: u128 = 60 * MINUTE;

/// Read a duration in the strict form: one whole number without sign and without fraction, and one unit (`ms`, `s`,
/// `m` or `h`). For example `500ms`, `30s`, `5m` or `1h`.
pub fn parse_duration_text(text: &str) -> Result<Duration, String> {
    const FORM: &str =
        "is not a duration: use one whole number and one unit (ms, s, m or h), for example \"500ms\" or \"5m\"";
    let digits_end = text
        .bytes()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, unit) = text.split_at(digits_end);
    let unit_nanos = match unit {
        "ms" => MILLISECOND,
        "s" => SECOND,
        "m" => MINUTE,
        "h" => HOUR,
        _ => return Err(FORM.to_owned()),
    };
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(FORM.to_owned());
    }
    let number: u128 = digits.parse().map_err(|_| "is too large".to_owned())?;
    let largest = u128::from(i64::MAX.unsigned_abs());
    if number > largest || number > largest / unit_nanos {
        return Err("is too large".to_owned());
    }
    let nanos = number * unit_nanos;
    let seconds = u64::try_from(nanos / SECOND).map_err(|_| "is too large".to_owned())?;
    let rest = u32::try_from(nanos % SECOND).map_err(|_| "is too large".to_owned())?;
    Ok(Duration::new(seconds, rest))
}

/// The shortest strict text of a duration, in the largest unit that divides it without a rest.
pub fn duration_text(value: Duration) -> String {
    let nanos = value.as_nanos();
    if nanos == 0 {
        return "0s".to_owned();
    }
    for (unit, name) in [(HOUR, "h"), (MINUTE, "m"), (SECOND, "s")] {
        if nanos.is_multiple_of(unit) {
            return format!("{}{name}", nanos / unit);
        }
    }
    format!("{}ms", nanos / MILLISECOND)
}

/// Read a duration key of a block. The text that applies (the text of the file, or the default text) goes to the
/// duration texts for print-config.
fn decode_duration(
    block: &Block,
    draft: &mut Draft,
    path: &str,
    name: &str,
    default_text: &str,
    minimum: Duration,
    maximum: Duration,
) -> Result<Duration, String> {
    let text = block.string(name).unwrap_or(default_text).to_owned();
    draft.duration_texts.insert(format!("{path}.{name}"), text.clone());
    let value = parse_duration_text(&text)
        .map_err(|error| block.error(format!("{path}.{name} {error}, got {}", quote(&text))))?;
    if value < minimum || value > maximum {
        return Err(block.error(format!(
            "{path}.{name} must be from {} to {}, got {}",
            duration_text(minimum),
            duration_text(maximum),
            quote(&text)
        )));
    }
    Ok(value)
}

/// The canonical form of a header name: an upper-case letter at the start and after each `-`, lower case elsewhere.
fn canonical_header_key(value: &str) -> String {
    let mut upper = true;
    value
        .chars()
        .map(|c| {
            let out = if upper {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            upper = c == '-';
            out
        })
        .collect()
}

/// Check the name of the header of the identity token.
fn validate_identity_header(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_IDENTITY_HEADER_CHARS {
        return Err(format!("must have 1 to {MAX_IDENTITY_HEADER_CHARS} characters"));
    }
    if !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
        return Err("must have only letters, digits and \"-\"".to_owned());
    }
    match canonical_header_key(value).as_str() {
        "Cookie" | "Authorization" | "Host" | "Content-Type" | "Content-Length" => {
            Err("must not be Cookie, Authorization, Host, Content-Type or Content-Length".to_owned())
        }
        _ => Ok(()),
    }
}

/// Check the base URL of the PDP: http or https, a host, no credentials, no query, no fragment, and no `/` at the
/// end. The value is not changed.
fn validate_pdp_url(raw: &str) -> Result<(), String> {
    if !raw.starts_with("http://") && !raw.starts_with("https://") {
        return Err("must start with http:// or https://".to_owned());
    }
    let parsed = parse(raw).map_err(|_| "is not a valid URL".to_owned())?;
    if parsed.hostname().is_empty() {
        return Err("must have a host".to_owned());
    }
    if parsed.user.is_some() {
        return Err("must not have credentials".to_owned());
    }
    if !parsed.raw_query.is_empty() || parsed.force_query {
        return Err("must not have a query".to_owned());
    }
    if !parsed.fragment.is_empty() || raw.contains('#') {
        return Err("must not have a fragment".to_owned());
    }
    if raw.ends_with('/') {
        return Err("must not end with \"/\"".to_owned());
    }
    Ok(())
}

/// True for an id of a node: 1 to 256 bytes of UTF-8 without a control character.
fn valid_access_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_ACCESS_ID_BYTES && !has_control_character(value)
}

/// Read the `access` block and its `identity` and `pdp` blocks. It never changes a value.
pub(super) fn decode(block: &Block, draft: &mut Draft, base_dir: &str, hooks: &Hooks<'_>) -> Result<(), String> {
    if !block.labels.is_empty() {
        return Err(block.error("access block does not accept labels"));
    }
    reject_unknown_attrs(block, &attribute_names("access"))?;
    require_attr_kinds(block, |name| (name == b"mode").then_some(Kind::String))?;
    record_sources(&mut draft.sources, "access", "access", block, base_dir);

    let (mut identity_block, mut pdp_block): (Option<&Block>, Option<&Block>) = (None, None);
    for nested in &block.blocks {
        match nested.kind.as_slice() {
            b"identity" => {
                if identity_block.is_some() {
                    return Err(nested.error("only one access.identity block is allowed"));
                }
                identity_block = Some(nested);
            }
            b"pdp" => {
                if pdp_block.is_some() {
                    return Err(nested.error("only one access.pdp block is allowed"));
                }
                pdp_block = Some(nested);
            }
            _ => {
                return Err(nested.error(format!(
                    "unknown block {} in access; the blocks are identity and pdp",
                    quote_bytes(&nested.kind)
                )));
            }
        }
        if !nested.labels.is_empty() {
            return Err(nested.error(format!("access.{} block does not accept labels", nested.kind_text())));
        }
    }

    let Some(mode) = block.string("mode") else {
        return Err(block.error("access.mode is required: \"authzen\" or \"open\""));
    };
    let mode = match mode {
        "authzen" => AccessPolicy::AuthZen,
        "open" => AccessPolicy::Open,
        other => {
            return Err(block.error(format!(
                "access.mode must be \"authzen\" or \"open\" (lower case), got {}",
                quote(other)
            )));
        }
    };
    if mode == AccessPolicy::Open {
        if let Some(nested) = identity_block.or(pdp_block) {
            return Err(nested.error(format!(
                "access.mode = \"open\" contradicts the access.{} block; remove the block or set access.mode = \"authzen\"",
                nested.kind_text()
            )));
        }
        draft.access = AccessConfig {
            mode,
            identity: None,
            pdp: None,
        };
        return Ok(());
    }
    let Some(identity_block) = identity_block else {
        return Err(block.error(
            "access.mode = \"authzen\" needs the access.identity block; add the block or set access.mode = \"open\"",
        ));
    };
    let Some(pdp_block) = pdp_block else {
        return Err(block.error(
            "access.mode = \"authzen\" needs the access.pdp block; add the block or set access.mode = \"open\"",
        ));
    };
    let identity = decode_identity_block(identity_block, draft, base_dir, hooks)?;
    let pdp = decode_pdp_block(pdp_block, draft, base_dir, hooks)?;
    draft.access = AccessConfig {
        mode,
        identity: Some(identity),
        pdp: Some(pdp),
    };
    Ok(())
}

/// Read the `access.identity` block: the rules to check the identity token.
fn decode_identity_block(
    block: &Block,
    draft: &mut Draft,
    base_dir: &str,
    hooks: &Hooks<'_>,
) -> Result<IdentityConfig, String> {
    const PATH: &str = "access.identity";
    if !block.blocks.is_empty() {
        return Err(block.error(format!("nested blocks are not supported inside {PATH}")));
    }
    reject_unknown_attrs(block, &attribute_names(PATH))?;
    require_attr_kinds(block, |_| Some(Kind::String))?;
    record_sources(&mut draft.sources, PATH, PATH, block, base_dir);

    let mut header = DEFAULT_IDENTITY_HEADER.to_owned();
    if let Some(value) = block.string("header") {
        validate_identity_header(value)
            .map_err(|error| block.error(format!("{PATH}.header: {error}, got {}", quote(value))))?;
        value.clone_into(&mut header);
    }
    let Some(issuer) = block.string("issuer") else {
        return Err(block.error(format!("{PATH}.issuer is required: the iss of the identity tokens")));
    };
    if issuer.is_empty() || issuer.len() > MAX_ISSUER_BYTES || has_control_character(issuer) {
        return Err(block.error(format!(
            "{PATH}.issuer must have 1 to {MAX_ISSUER_BYTES} bytes of UTF-8 without a control character, got {}",
            quote(issuer)
        )));
    }
    let Some(audience) = block.string("audience") else {
        return Err(block.error(format!("{PATH}.audience is required: the id of this service")));
    };
    if !valid_access_id(audience) {
        return Err(block.error(format!(
            "{PATH}.audience must have 1 to {MAX_ACCESS_ID_BYTES} bytes of UTF-8 without a control character, got {}",
            quote(audience)
        )));
    }
    let Some(public_keys_text) = resolve_value_source(
        block,
        PATH,
        "public_keys",
        base_dir,
        FORM_VALUE | FORM_ENV | FORM_FILE,
        hooks,
    )?
    else {
        return Err(block.error(format!(
            "{PATH}.public_keys is required: give public_keys, public_keys_env or public_keys_file (a JWK Set)"
        )));
    };
    let key_names =
        (hooks.public_keys)(&public_keys_text).map_err(|error| block.error(format!("{PATH}.public_keys: {error}")))?;
    let max_age = decode_duration(
        block,
        draft,
        PATH,
        "max_age",
        DEFAULT_IDENTITY_MAX_AGE,
        Duration::from_secs(1),
        Duration::from_secs(24 * 60 * 60),
    )?;
    let clock_skew = decode_duration(
        block,
        draft,
        PATH,
        "clock_skew",
        DEFAULT_IDENTITY_CLOCK_SKEW,
        Duration::ZERO,
        Duration::from_secs(5 * 60),
    )?;
    if clock_skew.subsec_nanos() != 0 {
        let text = draft
            .duration_texts
            .get(&format!("{PATH}.clock_skew"))
            .cloned()
            .unwrap_or_default();
        return Err(block.error(format!(
            "{PATH}.clock_skew must be a whole number of seconds, got {}",
            quote(&text)
        )));
    }
    Ok(IdentityConfig {
        header,
        issuer: issuer.to_owned(),
        audience: audience.to_owned(),
        public_keys_text,
        key_names,
        max_age,
        clock_skew,
    })
}

/// Read the `access.pdp` block: the connection to the policy decision point.
fn decode_pdp_block(block: &Block, draft: &mut Draft, base_dir: &str, hooks: &Hooks<'_>) -> Result<PdpConfig, String> {
    const PATH: &str = "access.pdp";
    if !block.blocks.is_empty() {
        return Err(block.error(format!("nested blocks are not supported inside {PATH}")));
    }
    reject_clear_secrets(block, PATH, PATH)?;
    reject_unknown_attrs(block, &attribute_names(PATH))?;
    require_attr_kinds(block, |name| match name {
        b"plain_http" => Some(Kind::Bool),
        b"max_evaluations" => Some(Kind::Number),
        _ => Some(Kind::String),
    })?;
    record_sources(&mut draft.sources, PATH, PATH, block, base_dir);

    let Some(url) = resolve_value_source(block, PATH, "url", base_dir, FORM_VALUE | FORM_ENV | FORM_FILE, hooks)?
    else {
        return Err(block.error(format!("{PATH}.url is required: give url, url_env or url_file")));
    };
    if let Err(error) = validate_pdp_url(&url) {
        // A URL with credentials or a query can hold a secret: the error does not show such a value.
        if parse(&url).is_ok_and(|parsed| parsed.user.is_some() || !parsed.raw_query.is_empty() || parsed.force_query) {
            return Err(block.error(format!("{PATH}.url: {error}")));
        }
        return Err(block.error(format!("{PATH}.url: {error}, got {}", quote(&url))));
    }
    let plain_http = block.boolean("plain_http").unwrap_or(false);
    let plain = url.starts_with("http://");
    if plain && !plain_http {
        return Err(block.error(format!(
            "{PATH}.url is an http URL, but {PATH}.plain_http = false; use an https URL, or set plain_http = true on a trusted network"
        )));
    }
    if !plain && plain_http {
        return Err(block.error(format!(
            "{PATH}.url is an https URL, but {PATH}.plain_http = true; remove plain_http, or use an http URL"
        )));
    }
    let Some(token) = resolve_value_source(block, PATH, "token", base_dir, FORM_ENV | FORM_FILE, hooks)? else {
        return Err(block.error(format!("{PATH}.token is required: give token_env or token_file")));
    };
    if token.len() > MAX_PDP_TOKEN_BYTES
        || has_control_character(&token)
        || token.chars().any(|c| c <= ' ' || c == '\u{7f}')
    {
        // The error never shows the token.
        return Err(block.error(format!(
            "{PATH}.token must have 1 to {MAX_PDP_TOKEN_BYTES} bytes without a space or a control character"
        )));
    }
    let timeout = decode_duration(
        block,
        draft,
        PATH,
        "timeout",
        DEFAULT_PDP_TIMEOUT,
        Duration::from_millis(10),
        Duration::from_secs(60),
    )?;
    let usage_timeout = decode_duration(
        block,
        draft,
        PATH,
        "usage_timeout",
        DEFAULT_PDP_USAGE_TIMEOUT,
        Duration::from_millis(100),
        Duration::from_secs(60),
    )?;
    if usage_timeout < timeout {
        let text = |name: &str| {
            draft
                .duration_texts
                .get(&format!("{PATH}.{name}"))
                .cloned()
                .unwrap_or_default()
        };
        return Err(block.error(format!(
            "{PATH}.usage_timeout = {} is less than {PATH}.timeout = {}; usage_timeout must not be less than timeout",
            quote(&text("usage_timeout")),
            quote(&text("timeout"))
        )));
    }
    let cache_ttl = decode_duration(
        block,
        draft,
        PATH,
        "cache_ttl",
        DEFAULT_PDP_CACHE_TTL,
        Duration::ZERO,
        Duration::from_secs(60 * 60),
    )?;
    let mut max_evaluations = DEFAULT_PDP_MAX_EVALUATIONS;
    if let Some(value) = block.integer("max_evaluations") {
        if !(1..=MAX_PDP_EVALUATIONS).contains(&value) {
            return Err(block.error(format!(
                "{PATH}.max_evaluations must be between 1 and {MAX_PDP_EVALUATIONS}, got {value}"
            )));
        }
        max_evaluations = u32::try_from(value).unwrap_or(DEFAULT_PDP_MAX_EVALUATIONS);
    }
    Ok(PdpConfig {
        url,
        plain_http,
        token,
        timeout,
        usage_timeout,
        cache_ttl,
        max_evaluations,
    })
}

/// Check the `access` block against the bucket and volume blocks. In mode `authzen`, each label is the id of a node,
/// and the action document lists one resource for each label.
pub(super) fn validate_resources(draft: &Draft) -> Result<(), String> {
    if !draft.access.enforced() {
        return Ok(());
    }
    let labels: Vec<&str> = draft
        .buckets
        .iter()
        .map(|bucket| bucket.id.as_str())
        .chain(draft.volumes.iter().map(|volume| volume.id.as_str()))
        .collect();
    for label in &labels {
        if label.len() > MAX_ACCESS_ID_BYTES {
            let shown = format!("{}...", label.get(..32).unwrap_or(label));
            return Err(format!(
                "access.mode = \"authzen\" contradicts the bucket or volume label {} ({} bytes): a label is the id of a node and has at most {MAX_ACCESS_ID_BYTES} bytes",
                quote(&shown),
                label.len()
            ));
        }
    }
    if labels.len() > MAX_ACCESS_RESOURCES {
        return Err(format!(
            "access.mode = \"authzen\" contradicts the number of bucket and volume blocks ({}): the action document lists one resource for each, and the most is {MAX_ACCESS_RESOURCES}",
            labels.len()
        ));
    }
    Ok(())
}

/// The warnings that the server logs at start. A warning is not an error.
pub fn warnings(config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    if !config.access.enforced() {
        out.push("access.mode = \"open\": the server checks no identity token and asks no PDP".to_owned());
    }
    if config.access.pdp.as_ref().is_some_and(|pdp| pdp.plain_http) {
        out.push(
            "access.pdp.plain_http = true: the server sends the PDP token and the questions without TLS".to_owned(),
        );
    }
    if config.access.enforced()
        && let Ok((host, _)) = split_host_port(&config.listen)
        && (host.is_empty() || host == "0.0.0.0" || host == "::")
    {
        out.push(format!(
            "server.listen = {} accepts requests on each network interface: the service must accept requests only through the edge, so limit the network",
            quote(&config.listen)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_have_one_whole_number_and_one_unit() {
        for (text, want) in [
            ("0s", Duration::ZERO),
            ("0ms", Duration::ZERO),
            ("1ms", Duration::from_millis(1)),
            ("500ms", Duration::from_millis(500)),
            ("60s", Duration::from_secs(60)),
            ("5m", Duration::from_secs(300)),
            ("24h", Duration::from_secs(24 * 3600)),
            ("100h", Duration::from_secs(100 * 3600)),
            ("10s", Duration::from_secs(10)),
        ] {
            assert_eq!(parse_duration_text(text), Ok(want), "{text}");
        }
        for text in [
            "", "5", "s", "ms", "1.5s", ".5s", "+5s", "-5s", "1m30s", "05s", "00s", "5 s", " 5s", "5s ", "5S", "5d",
            "5us", "5µs", "0x10s", "1e3s", "5\n",
        ] {
            assert!(parse_duration_text(text).is_err(), "{text:?}");
        }
        for (value, want) in [
            (Duration::ZERO, "0s"),
            (Duration::from_millis(1), "1ms"),
            (Duration::from_millis(1500), "1500ms"),
            (Duration::from_secs(1), "1s"),
            (Duration::from_secs(90), "90s"),
            (Duration::from_secs(60), "1m"),
            (Duration::from_secs(3600), "1h"),
            (Duration::from_secs(36 * 3600), "36h"),
        ] {
            assert_eq!(duration_text(value), want);
        }
    }

    #[test]
    fn a_duration_that_does_not_fit_is_too_large() {
        assert_eq!(
            parse_duration_text("99999999999999999999s"),
            Err("is too large".to_owned())
        );
        assert_eq!(
            parse_duration_text("9223372036854775807h"),
            Err("is too large".to_owned())
        );
        assert_eq!(
            parse_duration_text("9223372036854775807ms"),
            Err("is too large".to_owned())
        );
        assert!(parse_duration_text("9223372036854ms").is_ok());
    }

    #[test]
    fn the_header_has_letters_digits_and_dashes_and_is_not_a_reserved_header() {
        assert!(validate_identity_header("X-Edge-Token").is_ok());
        assert!(validate_identity_header("A").is_ok());
        assert_eq!(
            validate_identity_header("content-TYPE"),
            Err("must not be Cookie, Authorization, Host, Content-Type or Content-Length".to_owned())
        );
        assert_eq!(
            validate_identity_header("X_Y"),
            Err("must have only letters, digits and \"-\"".to_owned())
        );
        assert_eq!(
            validate_identity_header(""),
            Err("must have 1 to 64 characters".to_owned())
        );
        assert_eq!(canonical_header_key("x-identity-TOKEN"), "X-Identity-Token");
    }

    #[test]
    fn warnings_of_the_access_mode_and_of_the_listener() {
        let authzen = AccessConfig {
            mode: AccessPolicy::AuthZen,
            identity: Some(IdentityConfig::default()),
            pdp: Some(PdpConfig {
                url: "https://pdp".to_owned(),
                ..PdpConfig::default()
            }),
        };
        let plain = AccessConfig {
            pdp: Some(PdpConfig {
                url: "http://pdp".to_owned(),
                plain_http: true,
                ..PdpConfig::default()
            }),
            ..authzen.clone()
        };
        let open = AccessConfig::default();
        let config = |listen: &str, access: &AccessConfig| Config {
            listen: listen.to_owned(),
            access: access.clone(),
            ..Config::default()
        };
        let cases: [(&str, Config, &[&str]); 9] = [
            (
                "open",
                config("127.0.0.1:8080", &open),
                &["the server checks no identity token and asks no PDP"],
            ),
            (
                "open on all interfaces",
                config(":8080", &open),
                &["checks no identity token"],
            ),
            ("authzen on a loopback address", config("127.0.0.1:8080", &authzen), &[]),
            ("authzen on a private address", config("10.0.0.5:8080", &authzen), &[]),
            (
                "authzen without a host",
                config(":8080", &authzen),
                &["server.listen = \":8080\""],
            ),
            (
                "authzen on 0.0.0.0",
                config("0.0.0.0:8080", &authzen),
                &["server.listen = \"0.0.0.0:8080\""],
            ),
            (
                "authzen on ::",
                config("[::]:8080", &authzen),
                &["server.listen = \"[::]:8080\""],
            ),
            (
                "plain http on a loopback",
                config("127.0.0.1:8080", &plain),
                &["access.pdp.plain_http = true"],
            ),
            (
                "plain http and no host",
                config(":8080", &plain),
                &["access.pdp.plain_http = true", "only through the edge"],
            ),
        ];
        for (name, config, want) in cases {
            let got = warnings(&config);
            assert_eq!(got.len(), want.len(), "{name}: {got:?}");
            for (index, want) in want.iter().enumerate() {
                assert!(
                    got[index].contains(want),
                    "{name}: {} does not contain {want}",
                    got[index]
                );
            }
        }
    }
}
