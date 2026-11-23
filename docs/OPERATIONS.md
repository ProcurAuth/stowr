# Operations

This guide tells how to run Stowr in production: the process, the network, the logs, the limits and the upgrade.
[CONFIGURATION.md](CONFIGURATION.md) and [configuration-reference.md](configuration-reference.md) tell about the keys.

## What runs

Stowr is one static binary. It starts one process and no other program. It keeps no state on disk.

- The browser interface is in the binary. The server needs no file for it.
- The jobs, the preview sessions, the upload sessions and the learned permissions are in memory. A restart discards them.
- A volume is the one exception: Stowr writes the files of a `volume` block, in the folder of that block.
- The process reads the configuration file and the files that the configuration names (secrets, keys). It reads each of
  them one time, at start.
- The process reads the bundle of certificate authorities of the system for TLS to a provider and to the PDP. It reads the
  first file that exists in this list: `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`,
  `/etc/ssl/ca-bundle.pem`, `/etc/pki/tls/cacert.pem`, `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` and
  `/etc/ssl/cert.pem`. An endpoint with `http://` needs none of them.

## Run Stowr with systemd

This unit file is an example. Change the paths for your machine.

```ini
[Unit]
Description=Stowr
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/stowr -c /etc/stowr/config.hcl
User=stowr
Group=stowr
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
# Add one ReadWritePaths line for the folder of each volume block.
# ReadWritePaths=/srv/shared

[Install]
WantedBy=multi-user.target
```

Put the configuration and the secrets in `/etc/stowr`. Give the user `stowr` the read right, and nobody else. A secret
file is read without its last line end. Stowr stops with the status 0 on `SIGTERM` or `SIGINT`. It lets the open
requests end for 10 seconds at most (refer to "Fixed bounds of the server").

## Run Stowr in a container

The binary is static. It needs no shared library and no loader, so a `scratch` image can hold it. Follow these rules:

- Add a bundle of certificate authorities to the image when a provider or the PDP uses `https://`.
- Run the container with `--read-only`. Mount the configuration file and the secret files read-only.
- Mount the folder of each `volume` block with the write right for the user of the process.
- Mount the configuration file at `/etc/stowr/config.hcl`, the path of the systemd example.
- Start the process with the arguments `-c /etc/stowr/config.hcl`. The default path is `config.hcl` in the current folder.
- Use `stowr healthcheck -c /etc/stowr/config.hcl` as the health check. The image has no shell and no `curl`.

The directory `test/` builds such an image for the tests, and `test/scratch-runtime.sh` checks it. The test image keeps
the path `/config/config.hcl`. The image stays on the machine that builds it. The project publishes no image: a release
has binaries only.

## Network

Stowr serves plain HTTP. It has no TLS server. Put a reverse proxy in front of it for HTTPS.

- `server.listen` is the address and the port. The default `:8080` listens on each network interface. Use
  `127.0.0.1:8080` when the proxy runs on the same machine. Stowr writes a warning at start when `listen` has no host,
  or the host `0.0.0.0` or `::`.
- With the mode `authzen`, only the edge can reach Stowr. Use a firewall, a network policy or a private network. A client
  that reaches Stowr with no edge skips the check of the edge.
- With the mode `open`, only a reverse proxy that signs users in can reach Stowr.
- The server reads the `Host` header, never `X-Forwarded-Host`. It refuses a request that changes data when `Origin` and
  `Host` differ (`403 origin_mismatch`). Make the proxy send the public host name in `Host`.
- Connections to the providers, to the admin APIs and to the PDP use HTTP/1.1. They use no proxy and follow no redirect.

### Reverse proxy and a path prefix

Stowr serves its paths from `/`. The interface uses relative URLs, so a proxy can remove a path prefix. The HCL file has no
key for a public path. To publish Stowr at `/stowr/`, use this nginx rule:

```nginx
location /stowr/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 0;
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_read_timeout 300s;
}
```

Keep the slash at the end of the public path. The relative URLs of the browser then stay in the prefix.
The upload of a file sends chunks of 16 MiB or more. Set `client_max_body_size` to the chunk size or more. The
settings `proxy_request_buffering off` and `proxy_buffering off` let the bytes of a large object pass without a copy on
the proxy.

## Health check

`GET /healthz` answers `200` with `{"instances":N,"status":"ok"}`. It needs no token, asks the PDP nothing and gives no
data of a bucket. The command `stowr healthcheck` sends this request and exits with 0 when the status is 200. The
address comes from `--url`. Without it, the address comes from `server.listen` of the file that `-c` names. Without
both, it is `http://127.0.0.1:8080/healthz`.

## Start

Stowr checks the whole configuration before it serves. A mistake stops the start, and the message names the key, the
expected form and the value. Run `stowr check-config -c <file>` to check a file without a start.

After the check, Stowr sends bounded read requests to each bucket. It asks for a list of versions, for the tags of a key that does not exist, and for a list of multipart uploads. It also reads the lifecycle rules, the Object Lock and the encryption.

Stowr uses the answers to show only what the provider can do. These probes make no change in a bucket. They make the start last a few seconds. A bucket that fails a probe stays usable, without the feature of that probe.

## Effective configuration

Three commands check the file and then exit. They do not start the server and they do not send the probes of the buckets.

- `stowr check-config -c <file>` writes each warning as a `config.warning` line on the standard error. It writes nothing on
  the standard output.
- `stowr print-config -c <file>` writes the value that applies for each key on the standard output.
- `stowr -c <file> --print-config` writes the same text as `print-config`.

An error of the configuration gives the exit status 1. An error of the command line gives the status 2. Each line of
`print-config` has the form `key = value  # source`:

```text
server.listen = "127.0.0.1:8080"  # file
server.job_history_limit = 10  # default
auth "primary-s3".secret_access_key = <hidden>  # file:/run/secrets/s3-secret-access-key
access.pdp.token = <hidden>  # env:STOWR_PDP_TOKEN
```

The source is `default`, `file`, `env:VAR` or `file:/path`. Stowr shows a relative path as an absolute path. It joins
the path to the folder of the HCL file. A secret with a value always shows `<hidden>`, and a key with no value shows
`<none>`. The keys of `public_keys` are not secret: the line gives the type and the `kid` of each key.

At start, Stowr writes the same lines on the standard error, before the probes of the buckets. Each line is
`config.effective key = value  # source`, after the date and the time. One `config.warning` line follows for each
warning. The line `object browser listening on ...` then tells that the probes are done.

## Logs

Stowr writes its log on the standard error stream (stderr), one line for each event. A line starts with the date and the
time in UTC, in the form `YYYY/MM/DD hh:mm:ss`. Most events give their fields as `key=value`. A line has no level field. The
request log has the method, the quoted path, the status, the size of the answer and the duration:

```text
2026/11/23 16:07:34 POST "/api/uploads" 201 765B 11ms
```

- With `server.log_mode = "anonymous"` (the default), the request log and the access lines have no object key, with two
  exceptions. The path `/open/<name>` shows the file name, which is the last part of the key. The line
  `object_lock.change` always has the key. `detailed` writes the keys: use it only to find a problem.
- With the mode `authzen`, each request line also has the fields `subject` and `request_id`.
- At start, the log has each effective value of the configuration. A secret shows as `<hidden>`.

### Events

The table gives each event name that the code writes. The line has no level, so the column "Kind" is only a guide for a
filter. [ACCESS.md](ACCESS.md), section "Log lines", tells more about the events `access.*`.

| Event | Kind | When | Fields |
|---|---|---|---|
| `config.effective` | info | At start, one line for each key. | `key = value  # source` |
| `config.warning` | warning | At start: `access.mode = "open"`, `access.pdp.plain_http = true`, or `server.listen` with no host, `0.0.0.0` or `::`. After the probe of a bucket: `encryption` on Garage, or a `usage` source that differs from the provider. | A text that names the key and the risk. |
| `access.unauthenticated` | warning | Stowr refuses an identity token. | `request_id`, `method`, `path`, `reason` |
| `access.no_rule` | error | A route has no access rule. | `request_id`, `method`, `path` |
| `access.decision` | info | One question: an answer of the PDP, an error, or an answer of the cache (with `detailed` only). | `request_id`, `subject`, `action`, `resource`, `match`, `usage`, `decision`, `units`, `retry_after`, `reason`, `source`, `failed` |
| `access.options` | info | One request to the options route. | `request_id`, `subject`, `type`, `parent`, `items`, `questions` |
| `access.pdp_metadata` | info | At start, after the read of the metadata of the PDP. | `usage_max_seconds`, `usage_wait_ms`, `idle_max_seconds`, `evaluations_max_items`, `evaluations_max_bytes` |
| `access.pdp_failed` | error | A request to the PDP failed. At start, the read of the metadata failed (`request_id=-`). | `request_id`, `evaluations`, `error` |
| `access.pdp_credential_refused` | error | The PDP answered 401 or 403. | `request_id`, `status` |
| `access.pdp_invalid_answer` | error | An answer of the PDP is not valid. | `request_id`, `action`, and `reason` or `limit` |
| `access.ceiling_unenforceable` | warning | A `true` answer has a ceiling that the action does not list. | `request_id`, `action`, `ceiling` |
| `access.ceiling_refused` | info | A size is more than `max_object_size`. | `request_id`, `action`, `ceiling`, `limit`, `size` |
| `usage.error` | error | The read of the usage of a bucket failed. | `bucket`, `source`, `part` (only for the storage part), then the error |
| `object_lock.change` | info | A change of the Object Lock of one version. | `instance`, `key`, `version`, `legal_hold`, `retention`, `bypass_governance` |

These lines have no event name:

| Line | Kind | When |
|---|---|---|
| `object browser listening on <address> with ...` | info | At start, after the probes. It gives the numbers of buckets, auth blocks and volumes, and `server.access_mode`. |
| `loaded configuration from <path>` | info | At start, only with `server.log_mode = "detailed"`. |
| `received terminated; shutting down` | info | Stowr received `SIGTERM`. For `SIGINT`, the word is `interrupt`. |
| `the open connections did not end in time: the server closes them` | warning | The graceful stop did not end in 10 seconds. |
| `cannot accept a connection: <error>; next try in <time>` | error | The listen socket failed. The wait doubles from 5 ms to 1 s. |
| `job <id> (<type>) panicked: <text>` | error | A background job stopped on a fault of the program. |
| The request line | info | The end of each answer. |
| `<text of the error>` | error | The start failed, for example on a configuration error or on `listen tcp <address>: bind: address already in use`. Stowr exits with the status 1. |
| `cannot start the runtime: <cause>` | error | Stowr cannot start its runtime. It exits with the status 1. |
| `build.multipart_copy_threshold = <N>  # set at build time, for tests` | info | At start, only in a test build. The line `build.multipart_copy_part_size` has the same form. |

## Limits and memory

Stowr bounds its resources. The keys of the block `server` set the bounds. Their defaults are in
[configuration-reference.md](configuration-reference.md).

- `max_concurrent_storage_requests` and `max_concurrent_requests_per_storage` bound the calls to the providers.
- `max_storage_bytes_per_request` and `max_storage_requests_per_request` bound the work of one interactive request.
- `max_background_storage_bytes` and `max_background_storage_requests` bound one background job. At most four jobs are
  active or queued.
- `max_range_cache_bytes` bounds the memory cache of one range reader.
- `memory_limit_bytes` is a soft limit of the memory of the process. It is not a reservation. Set the limit of the
  container or of the unit as well.

A request that cannot get a storage slot in 30 seconds gets `503 storage_busy`. An upload or a download that makes no
progress for 30 seconds is cut. The section "Resource limits" of [SECURITY-MODEL.md](SECURITY-MODEL.md) lists the other bounds.

### Fixed bounds of the server

These bounds are constants of the HTTP server (`src/server/runtime.rs`). No key changes them. Use these values when you set
the timeouts of the reverse proxy and of the health check.

| Bound | Constant | Value | Effect |
|---|---|---|---|
| Time to read the head of a request | `READ_HEADER_TIMEOUT` | 10 s | The time starts when the connection opens, or at the first byte of the next request. When the head is not complete, the server closes the connection. |
| Idle time of a connection | `IDLE_TIMEOUT` | 120 s | A connection that sends no new request in this time closes. |
| Size of the head of a request | `MAX_HEADER_BYTES` | 1 MiB | The read buffer is this size plus 12 KiB. A head that does not fit gets `431`. |
| Header fields of a request | none | 1024 | A request with more fields gets `431`. |
| Write with no progress | `WRITE_IDLE_TIMEOUT` | 30 s | When the client reads no byte of the answer in this time, the server closes the connection. |
| Graceful stop | `SHUTDOWN_TIMEOUT` | 10 s | After `SIGTERM` or `SIGINT`, the open requests can end in this time. The server then closes the connections that stay open. |

## Volumes

A `volume` block shows a folder of the server as a bucket. Use it for a Docker volume, an NFS or CephFS mount, or a FUSE
mount such as `weed mount` of SeaweedFS.

- Stowr reads and writes the files with the identity of its process.
- A write goes to a temporary file in the folder of the target. One rename then replaces the target.
- Stowr does not follow a symbolic link that leaves the folder. With `access.mode = "authzen"`, it follows no link.
- The address of a volume in the interface is `/-/volume/<id>/`.

The sections "Volumes" of [ARCHITECTURE.md](ARCHITECTURE.md) and [CONFIGURATION.md](CONFIGURATION.md) tell more.

## Versions, large objects and archives

- At start, Stowr sends one bounded request for the versions of each bucket. When the provider answers `501`, refuses the
  request or fails, the bucket has no version browser. The interface then shows no version control for that bucket.
- When a bucket has versions, the listing shows the number of versions of each file. The details have a version selector,
  the restore, the permanent delete of one version, and the comparison of two versions of one object.
- The comparison runs in the browser. It reads two buffers with exact ranges and stops at the first byte that differs.
- **Verify integrity** reads a full object, one object at a time, when you click the button. Stowr hashes the stream and
  keeps no copy of the object.
- **Inspect** uses the metadata of the object and small exact ranges at the start and at the end of the object.
- Archive entries use the central directory of a ZIP file. Stowr reads only the selected regular entries that have no
  encryption. You can open, download or verify an entry, or copy it to an object that you name.
- **Insights** gives the result at once when it ends in 100 ms. If not, it runs as a background job in memory, with pause,
  resume and cancel.

Stowr has no global duplicate finder and no global checksum manifest. Such a result needs a large scan state, and Stowr
keeps no state on disk.

## Upgrade

1. Read the section of the new version in [CHANGELOG.md](../CHANGELOG.md), with its upgrade steps.
2. Download the archive and `checksums.txt`. Run `sha256sum --check --ignore-missing checksums.txt`.
3. Run `stowr print-config -c <file>` with the new binary on the current file. Change each key that it refuses.
4. Replace the binary and restart the service. The jobs and the upload sessions in memory end at the restart. A client of
   the API can resume an upload with its token, when the credentials stay the same.
5. Run `stowr healthcheck`, then open the interface.

To go back, put the old binary back. A new version can refuse a file of the old version, and the reverse. Keep the old file.

## Rotate keys and secrets

Stowr reads each key and each secret one time, at start. To rotate a secret, change the file or the variable that the
configuration names, then restart Stowr. The steps for the keys of the edge are in [ACCESS.md](ACCESS.md), section
"Rotate a key".

## Troubleshooting

| Symptom | Cause and action |
|---|---|
| The process stops at start. | The configuration has a mistake. The message names the key, the expected form and the value. Run `stowr print-config`. |
| The interface shows "session ended" or the API gives `401`. | The edge sent no valid identity token. Check the issuer, the audience, the clock and the key set. |
| `403 forbidden`. | The PDP refused the action. Check the grant of the person on the node of the key. |
| `403 permission_denied`. | The `permissions` of the bucket or `server.access_mode` refuse the operation. |
| `403 origin_mismatch` or `cross_site_request_blocked`. | The proxy sent a `Host` header that differs from the `Origin` of the browser. |
| `429 too_many_requests`. | The budget `writes` of the PDP is used. Read the header `Retry-After`. |
| `429 resource_budget_exceeded`. | One request went over a `server.max_*` bound. |
| `503 pdp_unavailable`. | The PDP gave no valid answer. Stowr never sends a question again. |
| `503 storage_busy`. | All storage slots were in use for 30 seconds. Raise the concurrency keys, or wait. |
| `502` on an upload. | The provider refused a request. The body has the code of the provider error. |
| A bucket shows no versions or no tags. | The provider does not support them, or the start probe failed. The probe never blocks the bucket. |
