# Stowr

This document uses ASD-STE100 Simplified Technical English.

Stowr is a self-contained web application that browses S3-compatible storage and Google Cloud Storage, and operates on
the objects. It can also show a folder of the server as a bucket (a volume), for example a FUSE mount of SeaweedFS.
Stowr is for hosts with a small memory budget, and for objects of hundreds of gigabytes.

Core properties:

- One static binary for Linux (amd64 and arm64), with the browser interface in it.
- An HCL configuration file only.
- No configuration and no provider credentials from environment variables. The only exception is a variable that the
  HCL file names with an `_env` attribute.
- No local database, no cache folder, no temporary file and no job state on disk. A volume is the exception: an upload
  to a volume writes a temporary file in the volume.
- No hidden control objects, indexes or checkpoints in the connected buckets.
- A read-only root file system is sufficient.
- One `auth` block can serve many buckets that have their own configuration.
- Exact byte-range readers for the previews and the inspection of large objects.
- Limits on the provider requests, the transferred bytes, the concurrency, the cache size and the job history in memory.
- The interface resolves each URL relative to `document.baseURI`: a reverse proxy can remove a path prefix.
- No request to a CDN or to another origin at run time.
- An access policy in the `access` block. The mode `authzen` checks the identity token of the edge and asks a PDP for
  each operation (protocol ProcurAuth). The mode `open` needs a reverse proxy that authenticates the users.

## Quick start

Get the archive of your architecture from the page of the release, with `checksums.txt`. Then do these steps:

```sh
sha256sum --check --ignore-missing checksums.txt
tar -xzf stowr_0.3.0_linux_amd64.tar.gz
cp config.example.hcl config.hcl
./stowr print-config -c config.hcl
./stowr -c config.hcl
```

To build the binary from the source, use Docker only. The binary goes into the current folder:

```sh
scripts/static.sh --copy .
```

The configuration must contain one `access` block, and one `bucket` block or one `volume` block at least. A `bucket`
block needs an `auth` block. Refer to "Access policy" for the `access` block.

## Access policy

The `access` block is mandatory. The mode `authzen` checks the identity token that the edge signs, and asks a PDP
(Policy Decision Point) for each operation. The mode `open` checks nothing: use it only behind a reverse proxy that
authenticates the users.

```hcl
access {
  mode = "authzen"

  identity {
    issuer           = "https://edge.example"
    audience         = "infra-s3"
    public_keys_file = "/run/keys/edge-jwks.json"
  }

  pdp {
    url        = "https://pdp.example:4182"
    token_file = "/run/secrets/pdp-token"
  }
}
```

Refer to [docs/ACCESS.md](docs/ACCESS.md) for the rules, and to [docs/CONFORMANCE.md](docs/CONFORMANCE.md) for the
conformance test.

## Shared authentication and bucket-specific policy

```hcl
auth "primary-s3" {
  provider               = "s3"
  mode                   = "access_key"
  endpoint               = "https://s3.example.internal"
  region                 = "eu-west-1"
  access_key_id_file     = "/run/secrets/s3-access-key-id"
  secret_access_key_file = "/run/secrets/s3-secret-access-key"
}

bucket "documents" {
  name           = "Documents"
  auth           = "primary-s3"
  bucket         = "documents"
  permissions    = ["read", "write", "delete"]
  max_scan_pages = 15
}

bucket "archive" {
  name           = "Archive"
  auth           = "primary-s3"
  bucket         = "archive"
  permissions    = ["read"]
  root_prefix    = "published/"
  max_scan_pages = 0
}
```

The two buckets use one set of credentials and one HTTP connection pool. Each bucket keeps its own root prefix,
permission ceiling, scan limit and learned provider capabilities.

Without `permissions`, the application tries each file operation that it supports. When the provider refuses an
operation, the process keeps this fact in memory until it stops. With `permissions`, the application applies a ceiling
on top of the policy of the provider.

`max_scan_pages` is the maximum number of provider listing pages (1,000 entries each) for one navigation batch. `0`
sets no limit. The sort of a column applies to the full listing only when the listing reached its real end.

Refer to [Configuration](docs/CONFIGURATION.md) for all the fields.

## Stateless runtime

The server writes no application state to the local file system. The files of a `volume` block are the only local
files that it writes: they are the data of the volume, not the state of the application. The background jobs, the
preview sessions, the learned permissions and the active upload sessions are in bounded process memory only. A restart
removes them.

A resumable upload gives the client an encrypted and authenticated token. The token contains the coordinates of the
multipart upload or of the resumable session on the provider. A new server process with the same credentials can find
the upload on the provider again with this token. The server does not keep the token or a checkpoint file.

The server removes a completed or cancelled upload from its memory. The process keeps four active upload sessions at
most. The background jobs are four active or queued operations at most, and a small history of finished jobs in memory
(`server.job_history_limit`).

## Volumes

A `volume` block shows a folder of the server as a bucket: a Docker volume, an NFS or CephFS mount, or a FUSE mount such
as `weed mount` of SeaweedFS. The server reads and writes the files with the identity of its process. Each write goes
to a temporary file, and one rename replaces the target. The server does not follow a symbolic link that goes out of the
folder. With `access.mode = "authzen"`, the server follows no symbolic link.

```hcl
volume "shared" {
  name        = "Shared files"
  path        = "/data/shared"
  permissions = ["read", "write", "delete"]
}
```

The address of a volume is `/-/volume/<id>/`. Refer to [docs/CONFIGURATION.md](docs/CONFIGURATION.md) and to the
section "Volumes" of [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Version support

At start, the server sends one bounded version listing to each bucket of the configuration. When the provider answers
`501 Not Implemented`, refuses the operation, or gives another error, the bucket has no version browser. The interface
then shows no version controls and asks for no version counts for that bucket.

When the bucket has versions:

- The listing shows the exact number of versions (delete markers excluded) of each visible file.
- Preview and Details have a version selector.
- The version browser has a listing in pages, the download of an exact version, the restore, and the permanent delete of
  an exact version, as the bucket permissions let.
- The comparison is only between two versions of the same object.
- The comparison runs in the browser only, with two bounded range buffers. It stops at the first byte that is not equal.

The server has no comparison of two different objects.

## Large-object tools

- **Verify integrity** reads the full object, one object at a time, when you ask for it. The server calculates the
  hashes on the stream. It does not keep the content of the object in memory.
- **Inspect** is a bounded technical inspection. It uses the metadata of the object and small exact ranges at the start
  and at the end of the object.
- The two tools are only in the **Advanced** tab of Details. To open Details or the Advanced tab starts no operation. The
  operation starts when you click its button. The result stays in Details.
- **Archive entry access** uses the central directory of a ZIP file. It reads only the selected regular entries that have
  no encryption. You can open, download or verify an entry, or copy it directly to an object that you name.
- **Insights** gives the result at once when it ends in 100 ms. If not, it continues as a background job in memory, with
  pause, resume and cancel. The server also makes the tree of the treemap. It applies the rule that groups the entries
  below one percent, and it contracts each chain of folders that have one child only. The browser receives the result.

The project has no global duplicate finder and no global checksum manifest. Exact global results need a large scan
state in memory or on disk. This is not possible with a stateless runtime of low memory.

## Reverse proxy path prefixes

The server always serves its paths from `/`. The interface uses relative URLs. To publish Stowr at `/stowr/`, remove
this prefix in the reverse proxy:

```nginx
location /stowr/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Keep the slash at the end of the public path: the relative URLs of the browser then stay in the prefix. The HCL file has
no key for a public path.

## PDF.js

The PDF preview is a local canvas viewer with its own `PDFDataRangeTransport`. It uses no iframe, no embed, no object
element and no viewer of the browser.

The binary embeds these files:

```text
src/public/assets/vendor/pdfjs/4.10.38/pdf.min.mjs
src/public/assets/vendor/pdfjs/4.10.38/pdf.worker.min.mjs
```

The application never downloads these files at run time.

## Documentation

- [Configuration](docs/CONFIGURATION.md)
- [Configuration reference](docs/configuration-reference.md) (generated)
- [Access policy](docs/ACCESS.md)
- [Conformance of the access policy](docs/CONFORMANCE.md)
- [Changes](CHANGELOG.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Preview and metadata behavior](docs/PREVIEWS.md)
- [Security model](docs/SECURITY.md)
- [Development and validation](docs/DEVELOPMENT.md)

## License

Add the project license that your deployment needs before you distribute Stowr. The third-party assets keep their own
notices under `src/public/assets/vendor/`.
