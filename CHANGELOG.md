# Changelog

This file follows the layout of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version can change a key or a route.
The release workflow reads the section `## X.Y.Z (date)` of the tag as the notes of the release.

## Unreleased

## 0.3.1 (2026-11-24)

Stowr 0.3.1 is a patch release. It adds no key and removes no key of the configuration file.

### Added

- The command `check-config` checks the configuration and writes the `config.warning` lines on the standard error. An
  error gives the status 1.
- The command `help` writes the help. `-V` writes the version, as `version` does.
- The release also has the file `SHA256SUMS`, with the same content as `checksums.txt`.
- The Content-Security-Policy of the pages has `form-action 'self'`.
- In the mode `open`, a `server.listen` on each network interface gives a warning at start.
- The workflow `nightly.yaml` runs the heavy checks: clippy, the tests, the static binary, the scratch image, the browser
  tests and the conformance test. It runs every night, by hand and before a release.
- The script `scripts/heavy.sh` runs the heavy checks of the CI on a developer machine.
- `CARGO_BUILD_JOBS` on the host limits the compile jobs of `scripts/cargo.sh`, `scripts/static.sh`, the scratch image and
  the browser test stack.

### Changed

- An error of the command line gives the status 2, as the help says. An unexpected argument gave the status 1.
- A command refuses an argument after its options with the status 2. Before, `version`, `config-reference`,
  `print-config` and `healthcheck` ignored it.
- `-h`, `--help` and `help` write the help on the standard output.
- `access.identity.max_age` must be a whole number of seconds, as `clock_skew` is. A value such as `"1500ms"` stops
  the start.
- `access.identity.header` must not be `Proxy-Authorization`.
- A mutation from a browser with `Origin: null` gets `403` with `origin_mismatch`. Before, the server ignored that header.
- A `_file` form loses only its last line end: one `\n`, or one `\r\n`. A `\r` at the end without `\n` stays in the
  value.
- The workflow `ci.yaml` is the fast path of a push and of a pull request. It runs the policy of the images, the format,
  the rules of the runtime and the syntax of the shell scripts. It uses the cached Rust toolchain of the runner and builds
  no Docker image. Clippy, the tests, the static binary, the scratch image and the browser tests now run in `nightly.yaml`.
- The workflow `conformance.yml` no longer runs on a pull request. `nightly.yaml` and a manual start run it.
- The job `rust` of `ci.yaml` ("Format, clippy, tests and rules of the runtime") is now the job `fast` ("Format, rules of
  the runtime and shell syntax"). The jobs "Static binary and scratch image" and "Browser tests of the interface" moved to
  `nightly.yaml`.
- The workflow `release.yaml` runs `ci.yaml` and `nightly.yaml` before it builds the binaries.

## 0.3.0 (2026-11-23)

Stowr 0.3.0 is a new implementation of the product. It replaces the program of the earlier versions. The configuration
keys, the routes and the JSON of the answers stay the same. The mode `authzen` follows ProcurAuth 1.1.

### Added

- The release has a static binary for Linux amd64 and for Linux arm64. The archives are `stowr_0.3.0_linux_amd64.tar.gz`
  and `stowr_0.3.0_linux_arm64.tar.gz`, with `checksums.txt`. Neither has a dynamic loader or a shared library. To build
  the binary from the source, refer to `docs/DEVELOPMENT.md`.
- Stowr reads the metadata of the PDP at `/.well-known/authzen-configuration` before its first question, and again after
  one hour. It uses the endpoints and the limits of the metadata. A PDP without metadata gets the default paths.
- The ceiling `max_object_size` of the action document has the unit `bytes`.

### Changed

- When the PDP answers a use with a reason of approval (`approval_required`, `approval_pending`, `approval_denied` or
  `approval_expired`), Stowr answers `403` with the body `{"error":"approval_cannot_wait"}`. No route of Stowr waits for
  an approval. The operation has no effect.
- The questions for the other permissions of an operation have `"context":{"permission_only":true}` and no usage. Stowr asks
  the use in a separate question. The answer cache keeps the two kinds of answers apart.
- The interface, the pages, `GET /api/build`, `OPTIONS /s3` and `/api/jobs` without an id ask the action `access` on the
  service node. A `false` answer gives `403 forbidden`. `/healthz` and `/.well-known/procurauth/actions` need no token and
  ask the PDP nothing.
- The default of `access.pdp.usage_timeout` is `6s`. For a question with usage, Stowr waits for the longer of two times:
  `usage_timeout`, and the time that the PDP publishes plus 1 second.
- `iat`, `exp` and `nbf` of the identity token must be whole numbers of seconds (JSON integers with digits only). Stowr
  refuses a fraction, an exponent and a sign.
- Stowr checks `nbf` when the token has it, with the clock skew.
- When `public_keys` holds more than one key, a token without `kid` is refused. With one key, a token without `kid` stays
  valid.
- Stowr sends the trailers `X-Stowr-Storage-Requests`, `X-Stowr-Storage-Bytes`, `X-Stowr-Elapsed-Ms` and
  `X-Stowr-Archive-*` only when the request has the header `TE: trailers`.
- A JSON request body must use the exact names of the members. A name with other upper and lower case letters, for
  example `"Instance"`, is an unknown member and gives `400 invalid_json`.
- The connections to the providers, to the admin APIs and to the PDP use HTTP/1.1.
- An archive entry that is a symbolic link gives `403 archive_symlink_blocked`.
- A read of a file of a volume that is not a regular file (a device, a socket or a pipe) gives `403 volume_not_file`.
- The details of a package show a manifest value that is a list or an object as compact JSON, for example
  `{"email":"y","name":"x"}` or `[1,2]`. A `null` value shows as an empty text. A number shows in its shortest decimal
  form, for example `1000000` or `1.5`. Below 1e-6 and from 1e21, it shows in the exponent form, for example `1e-7`.
- `stowr -h` writes one help with a table of the commands and the options.
- The conformance test runs the series U of ProcurAuth 1.1 against the static build (`docs/CONFORMANCE.md`).
- An error of an option has a new text, for example `unknown option: -x`. The names and the forms of the options and the
  exit statuses do not change.
- Some error texts are new. They are the errors of a URL in the configuration, of `stowr healthcheck`, and of a CSV or XML preview. The error codes and the HTTP statuses do not change.
- `server.memory_limit_bytes` keeps its key and its range. It is a soft limit of the memory of the process: the server
  accepts the value and shows it.

### Upgrade steps from 0.2.1

1. Make the edge write `iat`, `exp` and `nbf` as whole numbers of seconds.
2. When `public_keys` holds more than one key, make the edge write `kid` in the header of each token.
3. In the PDP, give the action `access` on the service node to each person who uses the interface.
4. Make sure that the PDP gives no reason of approval for the action `access` and for the other permissions.
5. If the PDP reads the unit of `max_object_size`, change it to `bytes`.
6. A client that reads the `X-Stowr-*` trailers must send `TE: trailers`.
7. A client of the JSON API must use the exact names of the members.

## 0.2.1 (2026-11-08)

### Changed

- `access.identity.public_keys` accepts PEM text again. A text that starts with `{` is a JWK Set. Other text is PEM: 1 to 16
  `-----BEGIN PUBLIC KEY-----` blocks, Ed25519 or P-256 with an uncompressed point. The `kid` of a PEM key is its RFC 7638
  thumbprint. Refer to `docs/ACCESS.md`, "Public keys".
- `iat` and `exp` of the identity token are NumericDate numbers (RFC 7519). A fraction, an exponent and a sign are valid.
  Stowr rounds the value down to a whole second. Before, Stowr refused a token whose `iat` or `exp` was not a whole number,
  for example `1800000290.0`.
- A JWK follows these rules: the `alg` `EdDSA` of an `OKP` key is accepted, and the members `use` and `key_ops` have no
  effect. A token header with the `alg` `EdDSA` stays refused.
- No configuration of 0.2.0 stops the start.

## 0.2.0 (2026-11-08)

Stowr follows the protocol ProcurAuth for the access of people. The `access` block is mandatory again.

### Added

- ProcurAuth, mode `authzen`:
  - The identity token: Stowr accepts `Ed25519` and `ES256` only, and refuses `EdDSA`. The keys are a JWK Set. The key
    `clock_skew` is new.
  - The PDP client. It has the default paths `/access/v1/evaluation` and `/access/v1/evaluations`. It asks a usage question for each use of an action that lists a budget. It never retries. An answer cache that `cache_ttl` bounds keeps the answers.
  - The action document at `/.well-known/procurauth/actions`. It publishes five actions: `object.read`, `object.write`,
    `object.delete`, `object.lock` and `bucket.admin`.
  - The resource tree: service, bucket, folder and subfolder. The node of a key is the deepest folder that holds it.
  - The options route `/.well-known/procurauth/resources`. It lists the buckets and the folders that a person can see.
  - The budget `writes`: each use of an action that changes objects takes one unit. A used budget gives
    `429 too_many_requests` with `Retry-After`.
  - The ceiling `max_object_size` bounds each object that an operation reads or writes. A size over it gives
    `403 ceiling_exceeded`.
- The new document `docs/ACCESS.md` gives the access policy.
- The conformance test `test/conformance/run.sh` runs the series U of the ProcurAuth runner against Stowr in Docker. A
  workflow runs it on a pull request. Refer to `docs/CONFORMANCE.md`.

### Changed

- The `access` block is mandatory. A file without it stops the start. Its key `mode` is `authzen` or `open`. The mode `open`
  checks no token and asks no PDP. The mode `authzen` needs the blocks `identity` and `pdp`.
- The interface lists only the buckets where the person holds one action. `/api/list` gives the `access` of the node and a
  navigation list of the folders on the path to a folder that the person can read.
- A route with no access rule gives 403. A PDP failure gives `503 pdp_unavailable`, never 403.
- With `access.mode = "authzen"`, a volume follows no symbolic link in the path of a key. Each link gives
  `403 volume_link_refused`.

### Upgrade steps from 0.1.2

1. Add the `access` block to the configuration file. A file without it stops the start.
2. To keep the behavior of 0.1.2, write `access { mode = "open" }` and keep the reverse proxy that authenticates the users.
3. To use the access policy, write `mode = "authzen"` with the blocks `identity` and `pdp`. Refer to `docs/ACCESS.md`.
4. In the mode `authzen`, limit the network so that only the edge reaches Stowr.

### Upgrade steps from the access block of 0.1.0

1. Make the edge sign with `Ed25519`. Stowr refuses `EdDSA`. `ES256` stays valid.
2. Give `public_keys` as a JWK Set (RFC 7517). Stowr accepts no PEM now.
3. Read the action document at `/.well-known/procurauth/actions`. The path `/.well-known/access-actions` has no alias and
   gives 404. Change the address in the edge.
4. Make the grants again. The tree and the actions are new: `object.read`, `object.write`, `object.delete`, `object.lock` and
   `bucket.admin` on a service, a bucket, a folder or a subfolder.
5. Add `plain_http = true` to the `pdp` block when the PDP URL starts with `http://`. A URL with `https://` needs no key.
6. Write each duration as one whole number and one unit: `ms`, `s`, `m` or `h`. For example `500ms` or `5m`.
7. Check `usage_timeout` (default `2s`). It must not be less than `timeout`.

## 0.1.2 (2026-11-08)

### Fixed

- The list page has no "Back to site" link. Stowr behind a reverse proxy path prefix, for example `/s3/`, showed it on its
  home page. A reverse proxy or the address bar gives the way back to the site.

## 0.1.1 (2026-10-23)

Stowr has one browser interface and no authentication of its own. The API, the routes, the other keys and the behavior of
the storage operations do not change.

### Changed

- The binary embeds one browser interface: the newer of the two interfaces of 0.1.0, with the dense tables, the bucket
  selector and the information page.
- The browser keeps its settings under new keys that start with `stowr.`. The settings of 0.1.0 go back to their defaults one time. They are the theme, the columns of the listing, the open sections of the details and the tags of the uploads.
- The browser tests are in `test/frontend/`.

### Removed

- The interface `default` and the key `server.frontend`.
- The `access` block: the modes `authzen` and `open`, the check of the identity token, the client of the AuthZEN PDP and the
  route `/.well-known/access-actions`. The permissions of the buckets and the volumes, and `server.access_mode`, do not
  change.
- The vendored styles that only the removed interface used (Buefy, github-markdown-css and the style of highlight.js).
  PDF.js, highlight.js and marked stay.

### Upgrade steps from 0.1.0

1. Delete the line `frontend = "..."` from the `server` block. A file with this key stops the server at start:
   `unknown attribute "frontend" in server block`.
2. Delete the `access { ... }` block. A file with this block stops the server at start: `unknown block type "access"`.
3. Put a reverse proxy that authenticates the users in front of Stowr, and do not publish the port of Stowr. Each request
   that reaches Stowr can do each operation that the permissions of the buckets and the volumes let.

## 0.1.0 (2026-10-23)

The first release of Stowr. It is one static binary with an embedded browser interface. It browses S3-compatible buckets, Google Cloud Storage buckets and folders of the server (volumes).

### Added

- Storage: S3-compatible providers (AWS S3, MinIO, SeaweedFS, Garage), Google Cloud Storage, and volumes. A volume is a folder of the server, such as a Docker volume or a FUSE mount. Shared `auth` blocks serve many `bucket` blocks.
- Configuration: one HCL file with a closed schema. An error stops the start and names the key. Secrets come only from
  `_env` or `_file`. `print-config` shows the value and the source of each key. The reference comes from the table of keys
  in the code.
- Listing: dense tables, folders, search, sort, tags, versions, and the settings of the columns.
- Previews of many file types with bounded byte ranges: text, code, Markdown, JSON, CSV, Parquet, SQLite, Excel, Word, PDF,
  images, audio, video, archives and email.
- Operations: upload with resume and SHA-256 checksums, download, copy, move, rename and delete of files and folders. Also archive download and extraction, edit of the metadata and of the tags, restore and delete of versions, and comparison of two versions.
- Bucket functions: lifecycle rules, Object Lock (retention and legal hold), and encryption (SSE-S3, SSE-KMS and SSE-C). Also the cleanup of incomplete multipart uploads, and the usage and the quota of a bucket.
- Information page of a bucket or a volume (`?info`): the permissions, the functions and the storage.
- Permissions: a ceiling of read, write and delete for each bucket and volume, and `server.access_mode = "force_read_only"`.
- Runtime: no local state, bounded memory, bounded provider requests and transfers, a read-only root file system, and a
  static binary.
