# Tests

This folder holds the integration tests of Stowr. Each test runs in Docker. No test pushes an image to a registry. The unit
tests are in `src/`: run them with `scripts/cargo.sh test --locked`. [docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md) tells
how to run each check.

## Layout

| Path | Content |
| --- | --- |
| `docker-compose.yaml`, `config.hcl`, `smoke.sh` | A small stack: Stowr and one SeaweedFS. Use it to try Stowr by hand and to run a smoke test of the API. |
| `frontend/` | The browser tests of the interface, with three S3 providers and one volume. |
| `volume-fuse/` | The test of a volume on a real FUSE mount of SeaweedFS. |
| `conformance/` | The conformance test of the access policy against the runner of ProcurAuth. |
| `browser/` | The Dockerfile that builds a static Stowr for the test stacks. The image stays on the machine. |
| `seaweedfs/`, `minio/`, `garage/` | The Dockerfiles and the entrypoints of the three providers. |
| `secrets/` | The fixed test credentials. They protect nothing: see "Test credentials". |
| `scratch-runtime.sh` | The test of the scratch image with a read-only root file system. |

## Small stack

`docker-compose.yaml` starts one SeaweedFS and Stowr. The entrypoint of SeaweedFS reads the identity from `config.hcl`, and it
creates the buckets `default`, `archive` and `encrypted`, and the bucket `locked` with Object Lock. `config.hcl` has one `auth` block that
two buckets share. Each bucket has its own permission ceiling and scan limit.

```sh
docker compose -f test/docker-compose.yaml up --build
test/smoke.sh http://127.0.0.1:8080
```

Open `http://localhost:8080/`. The argument of `smoke.sh` is the base URL of a Stowr that is up. The key and the secret in `config.hcl` and in `secrets/` belong to this isolated service only.
The browser refuses a secret in clear text in the HCL file, so the secret is in `secrets/s3_secret_access_key`.

The Stowr container uses the HCL file read-only. It runs with a read-only root file system and has no application volume. It keeps the jobs and the upload sessions in memory. It must start when a provider answers HTTP 501 for the list of versions.

## Browser tests

`frontend/run.sh` starts the stack of `frontend/compose.yaml`. It puts the test objects in the buckets (`seed.js`), runs
`browser-tests.js` in a Playwright container, and removes the stack. Two runs at the same time need two project names: set
`FRONTEND_TEST_PROJECT`. To run some tests only, set `ONLY` to a part of their names. To use a Playwright copy that is already on
the disk, set `PLAYWRIGHT_NODE_MODULES`.

```sh
./test/frontend/run.sh
```

The stack has three S3 providers and one Stowr:

| Provider | How the image is made | Instances | Endpoint |
| --- | --- | --- | --- |
| SeaweedFS 4.41 | The release archive, with its SHA-256 checksum | `seaweedfs-main`, `seaweedfs-archive`, `seaweedfs-locked`, `seaweedfs-encrypted` | `http://seaweedfs:8333` |
| MinIO RELEASE.2025-10-15T17-29-55Z | A build from the Git tag, with a check of its commit | `minio-main`, `minio-locked`, `minio-encrypted` | `http://minio:9000` |
| Garage v2.4.1 | The binary of the official image, pinned by its digest | `garage-main`, `garage-encrypted` | `http://garage:3900` |

The MinIO project does not publish a server image or a server binary now, and its repository is archived. Thus
`minio/Dockerfile` builds the last release from the source of that tag. The build takes about one minute, one time.

The three `auth` blocks of `frontend/config.hcl` use the same key. Garage needs a key id of `GK` and 24 hexadecimal
characters, and a secret of 64 hexadecimal characters. Each entrypoint creates the bucket `default`, and then writes a ready
file. The health check of each provider reads this file, so Stowr starts after the buckets exist.

The data of each provider is on a tmpfs of 4 GiB. The Docker volume of the volume `files` is a tmpfs of 1 GiB. Thus the capacity of the storage is the same on each test host.

The tests cover these parts of the interface:

- The list, the sort, the search, the tags, the version counts and the settings of the columns.
- The uploads with SHA-256 checksums, the resume of an upload and the copy in parts. The test image copies in parts from 8 KiB
  up, in parts of 5 MiB. The build arguments `MULTIPART_COPY_THRESHOLD` and `MULTIPART_COPY_PART_SIZE` of `browser/Dockerfile`
  set these values at compile time.
- The edit of the metadata, the restore and the delete of versions, and the comparison of two versions.
- The lifecycle editor, the incomplete uploads, Object Lock and the encryption (SSE-S3, SSE-C and SSE-KMS where the provider has
  them). The providers really encrypt in this stack: SeaweedFS gets a random key encryption key and MinIO gets a random KMS key.
  Each start makes new keys, and they stay in the environment of the process.
- The usage and the quota of each bucket, the state icons and the banner of a full bucket.
- The layout of the header and of the selector at 14 widths from 320 to 1920 px. The menus in the two themes. The information page.
- The volume `files`: the real and empty folders, the symbolic links and the temporary files of the uploads. Also the functions of S3 that a volume does not have.

`frontend/providers.js` has the flags of each provider: tags, versions, Object Lock and encryption. A test reads them to know what
the provider supports.

## FUSE test of the volumes

`volume-fuse/run.sh` runs the unit tests of the volumes and a browser smoke test on a FUSE mount of SeaweedFS (`weed mount`).
Only the container of the mount gets `/dev/fuse`, `SYS_ADMIN` and `apparmor:unconfined`. [docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md#fuse-test-of-the-volumes)
tells more.

- The service `seaweedfs` is the SeaweedFS of the browser tests.
- The service `mount` has the same pinned `weed` binary, FUSE 3, the pinned Rust image, the source of Stowr with its compiled
  tests, and Stowr. Its entrypoint runs `weed mount` on `/mnt/sw`. The data goes through the filer. Stowr then starts with the
  volume `sw`.
- `run.sh` runs `cargo test --locked --offline volume::` on the mount, with `STOWR_TEST_VOLUME_DIR` set to a folder of the mount.
  Then it runs `volume-fuse/smoke.js` in the Playwright container. The smoke test lists a folder, uploads a file with SHA-256, renames, copies and reads a range. It resumes an upload of 40 MiB. It copies, moves and deletes a folder.

These facts come from runs on a Debian 13 host with Docker and `/dev/fuse`:

- FUSE works in Docker with these three options. The mount is `fuse.seaweedfs` with `allow_other`.
- The 44 unit tests of the volumes pass on the mount. The writes of Stowr are visible at once through the mount.
- `statfs` of the mount gives the capacity of the volume servers. One run gave a size of 0 after the delete of a folder. The
  server then gives `storageError` and keeps what the volume holds.
- The used bytes follow with a delay. The server finds the type FUSE in the answer of `statfs`, so the usage of the volume is
  approximate. The page shows it with `~` and the reason.

When a host refuses FUSE in Docker, `run.sh` stops with the log of `weed mount` and a message. The browser tests then cover a
volume on a plain Docker volume.

## Conformance test

`conformance/run.sh` runs the series U of the ProcurAuth conformance runner (`access-conformance`, role `pep`) against Stowr.
[docs/CONFORMANCE.md](../docs/CONFORMANCE.md) gives the rules and the expected result.

```sh
test/conformance/run.sh
```

The script needs Docker, `git` and `python3`. It reads the ProcurAuth repository in the directory `procurauth` next to the
checkout of Stowr. Set `PROCURAUTH_DIR` for another place. The options are `--cases`, `--format` and `--no-build`.

| File | Use |
| --- | --- |
| `conformance/run.sh` | Builds the runner and Stowr, starts Stowr in a container with no network, and runs the runner in its network namespace. |
| `conformance/config.hcl` | The configuration of Stowr: mode `authzen`, the test keys of ProcurAuth, a PDP on `127.0.0.1:8181` and one volume `conf`. |
| `conformance/profile.json` | The profile of the service: the service id `stowr`, the token rules and four operations. |
| `conformance/expected.txt` | The cases that do not pass and the cases that the runner skips. |

The fixture is a volume with the file `reports/a.txt` (12 bytes) and the empty folder `reports/2026`. The runner is the client,
the edge and the PDP.

## Scratch runtime test

`scratch-runtime.sh` builds the test image on `scratch`. It checks the numeric user and the identity of the static binary. It starts the container with `--read-only` and runs the health check of the program.

## Test credentials

The key id `GK0123456789abcdef01234567` in `frontend/config.hcl` and `config.hcl`, and the files in `secrets/`, are fixed test
values. They belong to the isolated test services. They protect nothing.

## Functions of each provider

These facts come from S3 requests to the three providers of the browser test stack, with a check of the effect by a second request. "Yes" means that the request works and has its effect. "Dropped" means that the provider answers 200 but does not keep the setting. Other cells give the HTTP status and the S3 error code.

| Function | SeaweedFS 4.41 | MinIO 2025-10-15 | Garage v2.4.1 |
| --- | --- | --- | --- |
| Object tags (Get, Put, Delete) | Yes | Yes | 501 NotImplemented |
| Header `x-amz-tagging` on PutObject | Yes | Yes | Dropped |
| Versioning (PutBucketVersioning, ListObjectVersions) | Yes | Yes | 501 NotImplemented. GetBucketVersioning gives 200 with no status |
| GET or DELETE with `versionId` | Yes | Yes | The provider ignores `versionId`. A DELETE with any `versionId` deletes the object |
| DeleteObjects (batch delete) | Yes | Yes. A request with no checksum header gives 400 MissingContentMD5 | Yes |
| `x-amz-checksum-sha256` on PutObject | Yes. A wrong value gives 400 BadDigest | Yes. A wrong value gives 400 XAmzContentChecksumMismatch | Yes. A wrong value gives 400 InvalidDigest |
| `x-amz-checksum-sha256` on UploadPart | Yes. ListParts does not show the part checksum | Yes | Yes |
| Composite checksum of a multipart object (HEAD) | `<digest>-<parts>` | `<digest>-<parts>` | `<digest>`, with no part count |
| ListMultipartUploads | Yes. No `Initiated` date. Only `NextUploadIdMarker` for the next page | Partial. A prefix that is not a full key gives an empty list. `max-uploads` has no effect | Yes |
| ListMultipartUploads: order and pages, with three uploads of one key and `max-uploads=2` | Order of the upload ids. The pages continue with `upload-id-marker` only, and each upload comes one time | One page with all the uploads, in the order of the keys | Order of the keys. The pages continue with `key-marker` and `upload-id-marker`, and each upload comes one time |
| ListParts, AbortMultipartUpload | Yes. ListParts of an aborted upload gives 200 with no part | Yes | Yes |
| ListParts with `max-parts=1` of an upload with two parts | One part, `IsTruncated` true | One part, `IsTruncated` true | One part, `IsTruncated` true |
| ListParts or AbortMultipartUpload of an unknown upload id | 404 NoSuchUpload | ListParts: 404 NoSuchUpload. Abort: 404 NoSuchUpload, but 204 for the id of an upload of another key (the upload stays) | 404 NoSuchUpload |
| UploadPartCopy with `x-amz-copy-source-range` | Yes | Yes | Yes |
| UploadPartCopy or CopyObject of an older version | Yes | Yes | 404 NoSuchKey |
| `x-amz-copy-source-if-match` on UploadPartCopy, with the ETag of the source | Yes | Yes | Yes |
| Header `x-amz-tagging` on CreateMultipartUpload | Yes | Yes | No tags (not tested) |
| ETag of a copy in 3 parts | `<digest>-3` | `<digest>-3` | `<digest>-3` |
| CopyObject onto itself with `MetadataDirective=REPLACE` | Yes. The tags stay, the date changes, a new version comes | Yes. The tags stay, the date changes, a new version comes | Yes. The date changes |
| ETag after CopyObject REPLACE of an object in one part | The ETag stays | The ETag stays | The ETag stays |
| ETag after CopyObject REPLACE of a multipart object | The ETag stays (`<digest>-<parts>`) | The ETag changes: it becomes the MD5 of the object | The ETag stays (`<digest>-<parts>`) |
| CopyObject REPLACE with no `Content-Type` | `binary/octet-stream` | `binary/octet-stream` | No `Content-Type` |
| `x-amz-copy-source-if-match` on CopyObject, with another ETag | 412 PreconditionFailed | 412 PreconditionFailed | 412 PreconditionFailed |
| `x-amz-copy-source-if-match` on CopyObject of an older version | Compared with the ETag of that version | Compared with the ETag of that version | 404 NoSuchKey (no versions) |
| CopyObject REPLACE of a key that does not exist (the start probe of the metadata edit) | 404 NoSuchKey, no object | 404 NoSuchKey, no object | 404 NoSuchKey, no object |
| Lifecycle: expiration after N days, with a prefix | Yes | Yes | Yes |
| Lifecycle: abort of incomplete multipart uploads | Yes | 400 InvalidArgument. With an expiration in the same rule: dropped | Yes |
| Lifecycle: expiration of noncurrent versions | Yes | Yes | Dropped |
| Lifecycle: tag filter | Yes | Yes | Dropped: the rule applies to all the prefix |
| Lifecycle: removal of expired delete markers | Yes | Yes | 400 InvalidRequest |
| Lifecycle: transition to a storage class | 501 NotImplemented | 400 InvalidStorageClass | Dropped |
| Lifecycle: expiration on a date, size filter (`ObjectSizeGreaterThan`) | Yes | Yes. The children of `And` come back in another order | Yes |
| Lifecycle: the old `Prefix` element outside of `Filter` | Yes | Yes | Dropped: the rule applies to the whole bucket |
| Lifecycle: a rule with no ID | Yes, with no ID | Yes. The provider gives the rule an ID | Yes, with no ID |
| Lifecycle: two rules with one ID | Yes | 400 InvalidArgument | Yes |
| Lifecycle: a configuration with no rule | Yes | 400 InvalidArgument | 400 MalformedXML |
| Lifecycle: an empty `Filter` | Yes | Yes | The provider removes the `Filter` |
| Effect of the lifecycle rules | A lifecycle worker in a daily pass. The TTL at write is off by default, and an object written after a rule has no TTL | Not measured | Not measured |
| Header `Server` | `SeaweedFS 30GB 4.41` | `MinIO` | None. No request id. The error document has `Region` and no `RequestId` |
| Object Lock: bucket with lock, legal hold, retention | Yes. A refusal gives 403 AccessDenied | Yes. A refusal gives 400 InvalidRequest | 501 NotImplemented |
| Creation of a bucket with Object Lock | `s3.bucket.create -withLock` in `weed shell`. It turns on the versioning | `x-amz-bucket-object-lock-enabled: true` at CreateBucket. It turns on the versioning | 403 AccessDenied: the key cannot make buckets |
| GetObjectLockConfiguration on a bucket with no lock | 404 ObjectLockConfigurationNotFoundError | 404 ObjectLockConfigurationNotFoundError | 501 NotImplemented |
| GetObjectLockConfiguration on a bucket with lock | 200, `ObjectLockEnabled` Enabled, and the default retention when it has one | 200, the same | 501 NotImplemented |
| GetObjectRetention of a version with no retention | 404 ObjectLockConfigurationNotFoundError | 400 NoSuchObjectLockConfiguration | 501 NotImplemented |
| GetObjectLegalHold of a version with no legal hold | 404 NoSuchObjectLegalHold. After a legal hold OFF: 200 with OFF | 400 NoSuchObjectLockConfiguration. After a legal hold OFF: 200 with OFF | 501 NotImplemented |
| `RetainUntilDate` of GetObjectRetention | Seconds (`2026-10-20T15:56:32Z`) | Milliseconds (`2026-10-20T15:56:31.000Z`) | - |
| Lock headers of HEAD | `x-amz-object-lock-mode`, `x-amz-object-lock-retain-until-date`, `x-amz-object-lock-legal-hold` (also OFF) | The same. `x-amz-object-lock-legal-hold` only when it is ON | - |
| Delete of a version with a legal hold or an active retention | 403 AccessDenied, also with `x-amz-bypass-governance-retention` for a legal hold | 400 InvalidRequest, "Object is WORM protected and cannot be overwritten" | - |
| DeleteObjects of a locked version | 200 with an `Error` for the key: AccessDenied | 200 with an `Error` for the key: InvalidRequest | - |
| Delete with no `versionId` of a locked object (DELETE and DeleteObjects) | Yes: a delete marker. The locked version stays | Yes: a delete marker. The locked version stays | - |
| PutObjectRetention: a later date in the same mode | Yes | Yes | - |
| PutObjectRetention: an earlier Governance date | 403 AccessDenied. With the bypass header: yes | 400 InvalidRequest. With the bypass header: yes | - |
| PutObjectRetention: Governance to Compliance with a later date | 403 AccessDenied. With the bypass header: yes | 400 InvalidRequest. With the bypass header: yes | - |
| PutObjectRetention: an earlier Compliance date, or Compliance to Governance | 403 AccessDenied, also with the bypass header | 400 InvalidRequest, also with the bypass header | - |
| PutObjectRetention: a date in the past | 400 InvalidRequest | 400 MalformedXML | - |
| PutObjectRetention with an empty `Retention` (removal) | 400 InvalidRequest, also with the bypass header | Yes with the bypass header for Governance. Without it: 400 InvalidRequest | - |
| Delete of a version after the end of its Compliance retention | Yes | Yes | - |
| PutObjectLegalHold, GetObjectRetention on a bucket with no lock | 400 InvalidRequest | 400 InvalidRequest, "Bucket is missing ObjectLockConfiguration" | 501 NotImplemented |
| Usage of a bucket (admin API) | Master `GET /vol/status`: `Size` and `DeletedByteCount` of the volumes of the collection of the bucket. Each volume adds 8 bytes. A delay of some seconds. No count of objects | `GET /minio/admin/v3/datausageinfo` (SigV4, service `s3`): `size` and `objectsCount`. A background scan, about one time each minute | `GET /v2/GetBucketInfo?globalAlias=` (bearer token): `bytes` and `objects`, at once on one node |
| Quota of a bucket (admin API) | Filer `GET /buckets/<bucket>?metadata=true`: `Quota` in bytes, 0 for none. Set with `s3.bucket.quota`, enforced only after `s3.bucket.quota.enforce -apply` | `GET /minio/admin/v3/get-bucket-quota?bucket=`: `quota` (and `size`) in bytes, 0 for none. A hard quota refuses a write | `quotas.maxSize` and `quotas.maxObjects`, `null` for none |
| Admin request with a wrong credential | No credential (closed network) | 403 | 403 |
| SSE-S3 (`x-amz-server-side-encryption: AES256`) on PutObject, CreateMultipartUpload and CopyObject | Yes, with a KEK (`WEED_S3_SSE_KEK`). Without it: 500 InternalError, no object | Yes, with a KMS (`MINIO_KMS_SECRET_KEY`). Without it: 501 NotImplemented | Dropped: the provider answers 200, does not encrypt, and gives no encryption header |
| Encryption header in the answer of PutObject with SSE-S3 | `AES256` | `AES256` | None |
| CopyObject of an SSE-S3 object without the header | The copy is not encrypted | The copy is not encrypted | - |
| SSE-KMS (`aws:kms`) on PutObject | 500 InternalError | Yes, with the KMS key of MinIO (`arn:aws:kms:<name>`) | Not tested |
| SSE-C on PutObject over HTTP | Yes | 400 InvalidRequest: SSE-C needs TLS | Yes |
| HEAD of an SSE-C object without the key | 400 with no body. The answer has `x-amz-server-side-encryption-customer-algorithm` | - | 400 with no body |
| GET of an SSE-C object without the key | 400 InvalidArgument, "...Customer provided keys must provide the customer key." | - | 400 InvalidRequest, "Bad request: Object is encrypted" |
| ListObjectsV2 of an SSE-C object | Yes, with the size | - | Yes, with the size |
| GetBucketEncryption on a bucket with no default | 404 ServerSideEncryptionConfigurationNotFoundError | 404 ServerSideEncryptionConfigurationNotFoundError | 501 NotImplemented |
| PutBucketEncryption with AES256 | Yes. A later PutObject with no header gets AES256 | Yes (tested with Content-MD5). The effect on a PutObject is not tested | Not tested |

Notes for the code:

- Garage answers 501 NotImplemented for each function that it does not have. The message is `Unimplemented action: <name>`.
- Do not send a `versionId` to Garage. Garage gives an `x-amz-version-id` header on each write, but it keeps no versions.
- Garage drops some lifecycle settings with no error. After a write, read the configuration again and compare it.
  The lifecycle editor offers only the fields that each provider keeps. Refer to the section "Edit of the lifecycle
  rules" of [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md).
- Delete the lifecycle configuration with `DeleteBucketLifecycle`: MinIO and Garage refuse a configuration with no rule.
- Send `Content-MD5` or an `x-amz-checksum-*` header with DeleteObjects: MinIO refuses the request without one.
- On MinIO, list the multipart uploads with no prefix. Then Stowr filters the keys.
- The lock refusal codes are different: 403 AccessDenied on SeaweedFS, 400 InvalidRequest on MinIO. The bypass header does not remove a legal hold or a Compliance retention. After such a refusal, read the lock of the version: the code alone does not tell a lock from a permission that the person lacks.
- A delete with no `versionId` in a bucket with Object Lock writes a delete marker. Only the delete of a version can meet a lock.
- SSE-S3 needs a key service: a KEK for SeaweedFS (`WEED_S3_SSE_KEK`, or `s3.sse.kek` in `security.toml`), a KMS for MinIO. Without it, the write fails. Garage accepts the header and does not encrypt: Stowr writes a warning at start for a Garage bucket with `encryption = "sse-s3"`.
- A copy without `x-amz-server-side-encryption` loses the SSE-S3 of its source on SeaweedFS and MinIO. Send the header with each copy.
