# Development and validation

This document uses ASD-STE100 Simplified Technical English.

## Requirements

- Docker. The scripts run the compiler in a container. Do not install a compiler on the host.
- Nothing else for the build. The test stacks (SeaweedFS, MinIO, Garage, Playwright) also run in Docker.

## Scripts

| Script | Use |
|---|---|
| `scripts/cargo.sh <arguments>` | Run cargo in the development image (`stowr-dev:1`). The script runs as the user of the host. The cargo registry and the target folder are Docker volumes: no file of root appears in the repository. |
| `scripts/static.sh` | Build the static program for `x86_64-unknown-linux-musl`. `--check` also checks that the file is static and runs it. `--copy <folder>` copies the file to a folder of the host. |
| `scripts/check-invariants.sh` | Check the rules of the runtime that the compiler does not check. Refer to "Rules of the runtime". |

The release build reads `STOWR_BUILD_VERSION`, `STOWR_BUILD_COMMIT` and `STOWR_BUILD_DATE` at compile time. `stowr version`
and `/api/build` show them. A build without them shows `dev`.

## Validation

```sh
scripts/cargo.sh fmt --all -- --check
scripts/cargo.sh clippy --all-targets --locked -- -D warnings
scripts/cargo.sh test --locked
scripts/check-invariants.sh
scripts/static.sh --check
```

## Layout of the code

The crate is at the root of the repository: `Cargo.toml`, `build.rs` and `src/`. `src/main.rs` starts the program.
`src/lib.rs` has one module for each part of the program. Each part is a folder `src/<part>/` with its `mod.rs`.

| Folder | Content |
|---|---|
| `src/common/` | The shared types: the error and its envelope, the typed configuration, the context of an operation, the request and the answer, the storage traits, the JSON encoder of the answers, the times, the query, the embedded interface, the application. |
| `src/config/` | The reader of the HCL file, the table of the keys, the reference, `print-config`, the command line, the identity of the build. `src/config/env.rs` is the only reader of the environment. |
| `src/server/` | The HTTP server, the route table, the middlewares, the interface, the object gateway, the listing, the copy and the delete. |
| `src/instance/` | The storage instance: the gates, the budgets, the ceilings, the learned permissions, the versions, the range readers, the signed cursors. |
| `src/provider/` | The clients of S3 and of GCS, and the shared client of each `auth` block. |
| `src/volume/` | The volume back end. It is the only folder that writes to the local file system. |
| `src/uploads/` | The resumable uploads, the resume token, the incomplete multipart uploads. |
| `src/jobs/` | The background jobs, Insights, the integrity, the inspection, the version routes. |
| `src/archive/` | The ZIP reader and writer, the ZIP of a folder, the archive entries, the extraction. |
| `src/lifecycle/` | The object tags and the lifecycle rules. |
| `src/bucket/` | Object Lock, the encryption, the edit of the metadata, the usage and the quota. |
| `src/access/` | The access policy: the routes and their actions, the resource tree, the options route, the guard of the PDP. |
| `src/pv_docs/`, `src/pv_data/`, `src/pv_structured/`, `src/pv_media/` | The previews and the details of the objects. |
| `src/testkit/` | The test kit: the memory back end and the shared helpers of the tests. |
| `src/public/` | The browser interface. `build.rs` embeds each file in the binary. |

## Dependencies

Each dependency has an exact version in `Cargo.toml`, and `Cargo.lock` fixes the others. Add a dependency only when the
code that it replaces is larger or less strict. The program writes its own HCL reader, ZIP reader and writer, SQLite reader,
Parquet reader, DER reader, CSV reader, MIME reader, image and media header readers, and the S3 signature.

| Crate | Reason |
|---|---|
| `tokio` | The asynchronous runtime: the listener, the timers, the signals, the tasks of the jobs, the blocking threads of the CPU work. |
| `hyper`, `hyper-util`, `http`, `http-body`, `http-body-util`, `bytes` | The HTTP/1.1 server and the HTTP/1.1 client of the providers, of the admin APIs and of the PDP. The client follows no redirect and uses no proxy. |
| `rustls`, `tokio-rustls`, `hyper-rustls` | TLS 1.2 and 1.3 to the providers and to the PDP. The roots are the certificate bundle of the image. No environment variable. |
| `aws-lc-rs` | SHA-256, HMAC-SHA-256, AES-GCM, RSA signatures and the random generator. It is also the cryptography of `rustls`. |
| `serde`, `serde_json` | The JSON of the answers, of the requests and of the provider APIs. `src/common/json.rs` gives the exact form of the answers. |
| `flate2` | Deflate, gzip and zlib with the pure Rust back end: the ZIP entries, the gzip answers, the compressed parts of the previews. |
| `quick-xml` | The pull reader of XML: the provider answers, the Office Open XML parts, EPUB and SVG headers. It expands no external entity. |
| `base64` | The base64 forms of the checksums, of the tokens and of the previews. |
| `libc` | `statfs`, `O_NOFOLLOW` and the error numbers of the volume back end. |

## Rules of the runtime

`scripts/check-invariants.sh` checks these rules. The CI runs it.

- The program never runs another program.
- Only `src/config/env.rs` reads the environment: the variables that the configuration names with `_env`.
- The clients of the providers use no proxy and follow no redirect.
- Only the folder `src/volume/` writes to the local file system: the files of a `volume` block. Put the code of a test that
  makes fixtures in a file named `tests.rs` or `*_tests.rs`.
- Only `src/volume/statfs.rs` has `unsafe` code (`unsafe_code` is `deny` for the crate).
- The repository has no font file.
- The interface loads nothing from another origin.
- Each dependency has an exact version.

The compiler and clippy also refuse `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `dbg!` and the print macros in
the code of the program. The tests can use them. A function that is not written yet returns `Error::not_served`: the answer
`501 not_served`.

The program keeps no state on the local file system. It runs as a static binary in a scratch container with a read-only
root file system. Only the HCL file, the credential files and the folders of the `volume` blocks are mounted.

## Configuration reference

`docs/configuration-reference.md` comes from the table of the keys in `src/config/`. After a change of the table, make it
again:

```sh
scripts/cargo.sh run --quiet -- config-reference > docs/configuration-reference.md
```

A test fails when the file and the table do not agree.

## Frontend

The frontend under `src/public` is plain HTML, CSS and JavaScript. It has no build step. Edit the files, build the program
again and reload. The program embeds one interface: no key selects an interface.

- Change a colour, a size, a radius or a duration in the tokens at the top of `assets/css/stowr.css`. The components name
  tokens only.
- A new icon name needs a rule in `assets/css/icons.css` and a Tabler file in `assets/icons/tabler/`.
- A test of the server finds an external URL, a missing asset, a missing icon file and an icon name without a rule.

## Browser tests of the interface

`test/frontend/run.sh` starts three S3 providers (SeaweedFS, MinIO and Garage) and Stowr, puts the test objects in the
buckets and in the volume `files`, and runs `browser-tests.js` in a Playwright container. Refer to
[test/README.md](../test/README.md). Two runs at the same time on one machine need two project names: set
`FRONTEND_TEST_PROJECT`. To run some tests only, set `ONLY` to a part of their names.

```sh
./test/frontend/run.sh
```

## FUSE test of the volumes

`test/volume-fuse/run.sh` runs the tests of the volumes and a browser smoke test on a FUSE mount of SeaweedFS
(`weed mount`). Only the container of the mount gets `/dev/fuse`, `SYS_ADMIN` and no AppArmor profile.

```sh
./test/volume-fuse/run.sh
```

## Conformance test of the access policy

`test/conformance/run.sh` runs the ProcurAuth conformance runner against Stowr in Docker. Set `PROCURAUTH_DIR` when the
ProcurAuth repository is not next to the checkout of Stowr. Refer to [CONFORMANCE.md](CONFORMANCE.md).

```sh
./test/conformance/run.sh
```

## Shell syntax

```sh
for file in scripts/*.sh test/*.sh test/*/*.sh test/*/scripts/*.sh; do
  [ -e "$file" ] || continue
  bash -n "$file"
done
```

## PDF.js assets

The repository has the official `pdfjs-dist` 4.10.38 ESM module and worker at:

```text
src/public/assets/vendor/pdfjs/4.10.38/pdf.min.mjs
src/public/assets/vendor/pdfjs/4.10.38/pdf.worker.min.mjs
```

Keep the Apache-2.0 license notice in the same folder. The program does not get these assets at start or at run time.

## Scratch runtime

```sh
./test/scratch-runtime.sh
```

The test builds the scratch image, checks the numeric user and the identity of the static binary, starts the container with
`--read-only`, and runs the health check of the program.

## Release validation

Before you distribute an archive, extract that archive into a clean folder and do the full validation there.
