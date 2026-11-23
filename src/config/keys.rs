//! The table of the keys of the configuration. The decoders, the reference (docs/configuration-reference.md) and the
//! effective configuration (`print-config`) read this table. Thus they always agree.

use std::fmt::Write as _;

/// The form `<name> = "..."`: the value is in the file.
pub const FORM_VALUE: u8 = 1;
/// The form `<name>_env = "VAR"`: the value is in the environment variable that the file names.
pub const FORM_ENV: u8 = 2;
/// The form `<name>_file = "/path"`: the value is the content of the file that the file names.
pub const FORM_FILE: u8 = 4;

/// One key of the configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    /// The path of the block, for example `access.pdp`.
    pub block: &'static str,
    /// The name of the key.
    pub name: &'static str,
    /// The type of the value.
    pub kind: &'static str,
    /// The default value, or `(required)`.
    pub default: &'static str,
    /// The values that the key accepts.
    pub range: &'static str,
    /// The forms of the key: [`FORM_VALUE`], [`FORM_ENV`], [`FORM_FILE`].
    pub forms: u8,
    /// True for a secret: only `_env` and `_file`, and the output hides it.
    pub secret: bool,
    /// The use of the key.
    pub description: &'static str,
}

/// One block of the configuration, for the reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockDoc {
    /// The path of the block.
    pub path: &'static str,
    /// The syntax of the block.
    pub syntax: &'static str,
    /// The use of the block.
    pub description: &'static str,
}

/// The blocks, in the order of the reference.
pub static BLOCKS: &[BlockDoc] = &[
    BlockDoc {
        path: "server",
        syntax: "server { ... }",
        description: "Zero or one block. The listener, the logs and the limits of the process.",
    },
    BlockDoc {
        path: "access",
        syntax: "access { ... }",
        description: "Exactly one block. Required. It sets the policy of access (docs/ACCESS.md). Without it, the start stops.",
    },
    BlockDoc {
        path: "access.identity",
        syntax: "access { identity { ... } }",
        description: "One block with mode authzen. No block with mode open. The rules to check the identity token.",
    },
    BlockDoc {
        path: "access.pdp",
        syntax: "access { pdp { ... } }",
        description: "One block with mode authzen. No block with mode open. The connection to the policy decision point (PDP).",
    },
    BlockDoc {
        path: "auth",
        syntax: "auth \"<id>\" { ... }",
        description: "One or more blocks. A credential set and an endpoint that one or more buckets use.",
    },
    BlockDoc {
        path: "auth.usage",
        syntax: "auth \"<id>\" { usage { ... } }",
        description: "Zero or one block in an auth block with provider \"s3\". The admin API that gives the usage and the quota of the buckets of the auth block (docs/ARCHITECTURE.md, \"Usage and quota of a bucket\"). Without it, the interface shows no usage and no quota.",
    },
    BlockDoc {
        path: "bucket",
        syntax: "bucket \"<id>\" { ... }",
        description: "One or more blocks. One bucket that the browser shows. The label is the id of the bucket in the URL.",
    },
    BlockDoc {
        path: "volume",
        syntax: "volume \"<id>\" { ... }",
        description: "Zero or more blocks. One folder of the server that the browser shows as a bucket: a Docker volume, an NFS, CephFS or FUSE mount (docs/ARCHITECTURE.md, \"Volumes\"). The label is the id of the volume in the URL (/-/volume/<id>/). A file needs one bucket block or one volume block at least.",
    },
];

#[allow(clippy::too_many_arguments)]
const fn key(
    block: &'static str,
    name: &'static str,
    kind: &'static str,
    default: &'static str,
    range: &'static str,
    forms: u8,
    secret: bool,
    description: &'static str,
) -> Key {
    Key {
        block,
        name,
        kind,
        default,
        range,
        forms,
        secret,
        description,
    }
}

const VALUE: u8 = FORM_VALUE;
const ALL_FORMS: u8 = FORM_VALUE | FORM_ENV | FORM_FILE;
const INDIRECT: u8 = FORM_ENV | FORM_FILE;

/// The keys, block after block, in the order of the reference and of the effective configuration.
#[rustfmt::skip]
pub static KEYS: &[Key] = &[
    key("server", "listen", "text", "\":8080\"", "a numeric host:port, not a URL", VALUE, false, "The address and the port that the server listens on."),
    key("server", "job_history_limit", "integer", "10", "1 to 20", VALUE, false, "The number of finished background jobs that the process keeps in memory."),
    key("server", "access_mode", "text", "\"inherit_credentials\"", "inherit_credentials or force_read_only", VALUE, false, "force_read_only refuses each write and each delete."),
    key("server", "log_mode", "text", "\"anonymous\"", "anonymous or detailed", VALUE, false, "anonymous keeps the object keys out of the request log. detailed writes them."),
    key("server", "allow_full_object_fallback", "boolean", "false", "", VALUE, false, "Let a parser read a full object when a format has no range reader."),
    key("server", "memory_limit_bytes", "integer", "0", "0, or 33554432 to 1125899906842624", VALUE, false, "A soft limit of the memory of the process. 0 sets no limit. The server accepts the value and shows it."),
    key("server", "max_storage_bytes_per_request", "integer", "274877906944", "1048576 to 1125899906842624", VALUE, false, "The provider bytes that one HTTP request can transfer."),
    key("server", "max_storage_requests_per_request", "integer", "4096", "1 to 10000000", VALUE, false, "The provider calls that one HTTP request can make."),
    key("server", "max_range_cache_bytes", "integer", "8388608", "1048576 to 4294967296", VALUE, false, "The memory cache of one range reader session."),
    key("server", "max_concurrent_storage_requests", "integer", "4", "1 to 1024", VALUE, false, "The provider calls that run at the same time, for all the buckets."),
    key("server", "max_concurrent_requests_per_storage", "integer", "2", "1 to 256, and not more than max_concurrent_storage_requests", VALUE, false, "The provider calls that run at the same time for one bucket."),
    key("server", "session_ttl_seconds", "integer", "1200", "30 to 604800", VALUE, false, "The life of a preview session in memory."),
    key("server", "max_stats_folders", "integer", "1000", "100 to 1000000", VALUE, false, "The folder totals that one Insights result keeps."),
    key("server", "max_archive_entries", "integer", "10000", "1 to 1000000", VALUE, false, "The entries of a ZIP central directory that the server reads, and the members that a request can select."),
    key("server", "max_background_storage_bytes", "integer", "274877906944", "1048576 to 1125899906842624", VALUE, false, "The provider bytes that one background job can transfer."),
    key("server", "max_background_storage_requests", "integer", "100000", "1 to 10000000", VALUE, false, "The provider calls that one background job can make."),

    key("access", "mode", "text", "(required)", "authzen or open (lower case)", VALUE, false, "authzen: the server checks the identity token and asks the PDP. open: the server makes no check and writes a warning at start."),

    key("access.identity", "header", "text", "\"X-Identity-Token\"", "1 to 64 characters: letters, digits and \"-\". Not Cookie, Authorization, Host, Content-Type or Content-Length", VALUE, false, "The name of the HTTP header that holds the identity token."),
    key("access.identity", "issuer", "text", "(required)", "1 to 1024 bytes of UTF-8, without a control character", VALUE, false, "The iss of the identity tokens that the server accepts."),
    key("access.identity", "audience", "text", "(required)", "1 to 256 bytes of UTF-8, without a control character", VALUE, false, "The id of this service. It is the aud of the tokens, the server of the action document and the root of each chain of resources."),
    key("access.identity", "public_keys", "text", "(required)", "PEM (1 to 16 -----BEGIN PUBLIC KEY----- blocks) or a JWK Set (RFC 7517) with 1 to 16 keys. Each key is Ed25519 or P-256", ALL_FORMS, false, "The public keys of the issuer. A text that starts with \"{\" is a JWK Set, other text is PEM. The server checks the signature of each identity token with them. It is not a secret: print-config shows the type and the kid of each key."),
    key("access.identity", "max_age", "duration", "\"5m\"", "1s to 24h", VALUE, false, "The longest life (exp minus iat) of an identity token."),
    key("access.identity", "clock_skew", "duration", "\"60s\"", "0s to 5m, whole seconds", VALUE, false, "The difference between the clock of the server and the clock of the issuer that the server accepts."),

    key("access.pdp", "url", "URL", "(required)", "http or https, with a host, without credentials, query or fragment, and without a \"/\" at the end", ALL_FORMS, false, "The base URL of the PDP. The client adds /access/v1/evaluation and /access/v1/evaluations to it."),
    key("access.pdp", "plain_http", "boolean", "false", "true with an http URL. false with an https URL", VALUE, false, "true accepts an http URL: the server then sends the token and the questions without TLS. Use it only on a trusted network."),
    key("access.pdp", "token", "text", "(required)", "1 to 4096 bytes, no space and no control character", INDIRECT, true, "The bearer token that the server sends to the PDP. It is a secret: the form in clear text stops the start."),
    key("access.pdp", "timeout", "duration", "\"500ms\"", "10ms to 1m", VALUE, false, "The deadline of one request to the PDP, without context.usage."),
    key("access.pdp", "usage_timeout", "duration", "\"2s\"", "100ms to 1m, and not less than timeout", VALUE, false, "The deadline of one question with context.usage."),
    key("access.pdp", "cache_ttl", "duration", "\"30s\"", "0s to 1h", VALUE, false, "The life of an answer of the PDP in memory. 0s keeps no answer."),
    key("access.pdp", "max_evaluations", "integer", "64", "1 to 1024", VALUE, false, "The most items in one Access Evaluations request."),

    key("auth", "provider", "text", "(required)", "s3 or gcs (lower case)", VALUE, false, "The storage protocol."),
    key("auth", "mode", "text", "s3: access_key with credentials, else anonymous. gcs: service_account with credentials_file, else anonymous", "s3: access_key or anonymous. gcs: service_account or anonymous", VALUE, false, "How the server signs the provider requests."),
    key("auth", "endpoint", "URL", "s3: (required). gcs: https://storage.googleapis.com", "http or https, without credentials, query or fragment, and without a \"/\" at the end", VALUE, false, "The base URL of the provider."),
    key("auth", "region", "text", "s3: (required)", "", VALUE, false, "The region that the S3 signature uses."),
    key("auth", "access_key_id", "text", "(none)", "s3 access_key mode only; no space at the start or at the end", ALL_FORMS, false, "The S3 access key id. It is an identifier, not a secret: print-config shows it."),
    key("auth", "secret_access_key", "text", "(none)", "s3 access_key mode only; no space and no control character", INDIRECT, true, "The S3 secret access key. It is a secret: the form in clear text stops the start."),
    key("auth", "session_token", "text", "(none)", "s3 only; no space and no control character", INDIRECT, true, "The S3 session token. It is a secret: the form in clear text stops the start."),
    key("auth", "credentials_file", "file path", "(none)", "gcs service_account mode only", VALUE, false, "The JSON file of a GCS service account. A relative path starts at the directory of the configuration file."),
    key("auth", "insecure_skip_verify", "boolean", "false", "", VALUE, false, "Do not verify the TLS certificate of the provider. Use it only for a test."),

    key("auth.usage", "source", "text", "(required)", "garage, seaweedfs or minio, exact (lower case)", VALUE, false, "The reader of the usage and of the quota. The server never guesses it from the provider."),
    key("auth.usage", "endpoint", "URL", "garage: (required), the admin API. seaweedfs: (required), the master. minio: the endpoint of the auth block", "http or https, without credentials, query or fragment, and without a \"/\" at the end", VALUE, false, "The base URL of the admin API. print-config and the effective configuration in the log show it. The answers of the server and the error messages never show it."),
    key("auth.usage", "filer_endpoint", "URL", "seaweedfs: (required). Other sources: (none)", "seaweedfs only. http or https, without credentials, query or fragment, and without a \"/\" at the end", VALUE, false, "The base URL of the filer of SeaweedFS. The filer gives the quota of a bucket."),
    key("auth.usage", "token", "text", "garage: (required). Other sources: (none)", "garage only; 1 to 4096 bytes, no space and no control character", INDIRECT, true, "The admin token of Garage. It is a secret: the form in clear text stops the start. minio signs with the S3 credentials of the auth block. seaweedfs sends no credential."),

    key("bucket", "name", "text", "the label of the block", "", VALUE, false, "The name that the user interface shows."),
    key("bucket", "auth", "text", "(required)", "the label of an auth block", VALUE, false, "The auth block that this bucket uses."),
    key("bucket", "bucket", "text", "(required)", "", VALUE, false, "The name of the bucket at the provider."),
    key("bucket", "permissions", "list of text", "(none: no ceiling)", "read, write, delete (lower case, each one time)", VALUE, false, "The operations that the server can do on this bucket. It is a ceiling: the provider can refuse more."),
    key("bucket", "root_prefix", "text", "\"\"", "\"\", or a prefix that ends with \"/\" and does not start with \"/\"", VALUE, false, "The part of the bucket that the browser shows. The keys are relative to it."),
    key("bucket", "max_scan_pages", "integer", "1", "0 to 1000000", VALUE, false, "The 1000-entry provider pages that one listing combines. 0 = no limit."),
    key("bucket", "encryption", "text", "\"\"", "\"\" or sse-s3, exact (lower case). SSE-C and SSE-KMS are not supported. Only for an s3 auth block", VALUE, false, "The server-side encryption that the server asks for each object that it writes: upload, copy, move, rename, metadata edit, restore of a version, extraction. sse-s3 sends x-amz-server-side-encryption: AES256. \"\" sends no encryption header: the default encryption of the bucket applies."),
    key("bucket", "quota_bytes", "integer", "(none: the limit of the provider, or no limit)", "1 to 1152921504606846976. Only with a usage block in the auth block", VALUE, false, "The size limit of the bucket that the interface shows when the provider gives no limit. The server does not enforce it."),

    key("volume", "name", "text", "the label of the block", "", VALUE, false, "The name that the user interface shows."),
    key("volume", "path", "file path", "(required)", "an absolute path, without \"/\" at the end and without an empty, \".\" or \"..\" part. The folder must exist at start, and the process must read it", VALUE, false, "The folder of the volume. The server reads and writes its files with the identity of the process. With write or delete in permissions (or without permissions), the start writes and removes a test file: a folder that the process cannot write stops the start."),
    key("volume", "permissions", "list of text", "(none: read, write and delete)", "read, write, delete (lower case, each one time)", VALUE, false, "The operations that the server can do in this volume. It is a ceiling: the file system can refuse more. Give [\"read\"] for a folder that the process cannot write."),
    key("volume", "root_prefix", "text", "\"\"", "\"\", or a relative folder path that ends with \"/\", without an empty, \".\" or \"..\" part. The folder must exist at start", VALUE, false, "The folder of path that the browser shows. The keys are relative to it. A symbolic link that leaves it is not followed."),
    key("volume", "max_scan_pages", "integer", "1", "0 to 1000000", VALUE, false, "The 1000-entry pages of a folder that one listing combines. 0 = no limit."),
];

/// The keys of one block, in the order of the table.
pub fn keys_of_block(block: &str) -> impl Iterator<Item = &'static Key> + '_ {
    KEYS.iter().filter(move |key| key.block == block)
}

/// Each attribute name that a block accepts: the name of each key, and its `_env` and `_file` forms when the key has
/// them.
pub fn attribute_names(block: &str) -> Vec<String> {
    let mut names = Vec::with_capacity(24);
    for key in keys_of_block(block) {
        if key.forms & FORM_VALUE != 0 {
            names.push(key.name.to_owned());
        }
        if key.forms & FORM_ENV != 0 {
            names.push(format!("{}_env", key.name));
        }
        if key.forms & FORM_FILE != 0 {
            names.push(format!("{}_file", key.name));
        }
    }
    names
}

/// The key and the form of an attribute name of a block.
pub fn key_of_attribute(block: &str, attribute: &[u8]) -> Option<(&'static Key, u8)> {
    for key in keys_of_block(block) {
        let name = key.name.as_bytes();
        if key.forms & FORM_VALUE != 0 && attribute == name {
            return Some((key, FORM_VALUE));
        }
        if key.forms & FORM_ENV != 0 && attribute.strip_suffix(b"_env") == Some(name) {
            return Some((key, FORM_ENV));
        }
        if key.forms & FORM_FILE != 0 && attribute.strip_suffix(b"_file") == Some(name) {
            return Some((key, FORM_FILE));
        }
    }
    None
}

fn markdown_cell(value: &str) -> String {
    if value.is_empty() {
        return " ".to_owned();
    }
    value.replace('|', "\\|")
}

fn forms_text(forms: u8) -> String {
    let mut parts = Vec::with_capacity(3);
    if forms & FORM_VALUE != 0 {
        parts.push("value");
    }
    if forms & FORM_ENV != 0 {
        parts.push("`_env`");
    }
    if forms & FORM_FILE != 0 {
        parts.push("`_file`");
    }
    parts.join(", ")
}

const REFERENCE_HEADER: &str = "# Configuration reference

This document uses ASD-STE100 Simplified Technical English.

Do not edit this file. The program makes it from the table of keys in `src/config/keys.rs`.
To make it again, run `scripts/cargo.sh run --quiet -- config-reference > docs/configuration-reference.md` in the root
of the repository. A test makes sure that this file and the table agree.

## Rules

- An unknown block, an unknown attribute or a duplicate attribute stops the start.
- A value that is not in its range stops the start. The error gives the key and the line.
- A key without a value in the file has its default value. A key with `(required)` must have a value.
- A file needs one `access` block. The block has mode `authzen` or mode `open`.
- A file needs one `bucket` block or one `volume` block at least. A `bucket` block needs an `auth` block.
- A duration is one whole number and one unit: `ms`, `s`, `m` or `h`. For example: `500ms`, `30s`, `5m`, `1h`.
  A sign, a fraction, a space or two units (`1m30s`) stops the start.
- `stowr print-config -c <file>` checks the file, writes the value of each key and its source, and exits with status 0.
  The source is `file`, `env:<VAR>`, `file:<path>` or `default`. The output hides each secret.
- At start, the server writes the same values in its log.

## Values from the environment or from a file

The column *Forms* gives the forms of each key:

- `value`: `<name> = \"...\"`. The value is in the file.
- `_env`: `<name>_env = \"VAR\"`. The value is in the environment variable `VAR`.
- `_file`: `<name>_file = \"/path\"`. The value is the content of the file, without the last line end.
  A relative path starts at the directory of the configuration file.

Give one form only. Two forms stop the start. A variable that does not exist, an empty value, or a file that the
server cannot read stops the start. The server reads each variable and each file one time, at start. The server reads
no environment variable that the file does not name.

A secret key has *yes* in the column *Secret*. A secret accepts only `_env` and `_file`: a secret in clear text in
the file stops the start. The output of `print-config` and the log show `<hidden>` for it.

## No change of a value

The value in the file is the value that applies. The server does not remove spaces, does not change the case, and does
not add or remove a `/`. A value that does not fit stops the start. The error gives the key, the expected form and the
value. An error about a secret does not show the value. A text value must not be empty and must not have a space at
the start or at the end: to use the default of a key, remove the key.
";

/// The text of docs/configuration-reference.md.
pub fn reference() -> String {
    let mut out = String::with_capacity(32 * 1024);
    out.push_str(REFERENCE_HEADER);
    for block in BLOCKS {
        let _ = write!(out, "\n## `{}`\n\n", block.path);
        let _ = write!(out, "Syntax: `{}`. {}\n\n", block.syntax, block.description);
        out.push_str("| Key | Type | Default | Range | Forms | Secret | Use |\n");
        out.push_str("|---|---|---|---|---|---|---|\n");
        for key in keys_of_block(block.path) {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} | {} | {} | {} |",
                key.name,
                key.kind,
                markdown_cell(key.default),
                markdown_cell(key.range),
                forms_text(key.forms),
                if key.secret { "yes" } else { "no" },
                markdown_cell(key.description)
            );
        }
    }
    out
}
