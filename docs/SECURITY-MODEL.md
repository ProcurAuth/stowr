# Security model

This document tells what Stowr protects and how. To report a vulnerability, read [SECURITY.md](../SECURITY.md).

## No application storage

The runtime does not create or change these things:

- local state files;
- a local database;
- cache or checkpoint folders;
- temporary files, except the files of a volume;
- hidden provider objects;
- control prefixes, tags or metadata;
- probe uploads or probe deletes.

A scratch container can run Stowr with a read-only root file system and no data volume. A change in a provider happens
only for an explicit operation of a person: upload, copy, move, restore, extraction, overwrite or delete.

A provider can record each network request in its audit log. Stowr cannot make its reads and writes invisible to S3, to GCS,
to Garage or to a proxy.

## Access policy

The `access` block is mandatory. Its key `mode` is `authzen` or `open`. [ACCESS.md](ACCESS.md) gives the full rules.

### Mode authzen

The edge authenticates the person and signs an identity token. Stowr checks the token on each request. It asks a PDP (Policy
Decision Point) for each operation. Stowr follows the ProcurAuth protocol.

- Stowr accepts a token with the algorithm `Ed25519` or `ES256` only. It refuses `EdDSA`. It reads the token only from the
  configured header, never from `Authorization`, a cookie or a query parameter.
- Stowr accepts requests only through the edge (P 9.4). Use a network rule: a firewall, a network policy or a private
  network. Do not publish the port of Stowr. A client that reaches Stowr without the edge skips the other checks of the edge.
  Stowr writes a warning at start when `server.listen` accepts requests on each network interface.
- The routes `/healthz` and `/.well-known/procurauth/actions` need no token and ask the PDP nothing. Other routes hold no data
  of a bucket: the static files, the pages, `/api/build`, `OPTIONS /s3` and `/api/jobs` without an id. They need a token and
  ask the action `access` on the service node. A `false` answer gives `403 forbidden`. Each other route asks the actions of
  the action document.
- A route that has no access rule answers 403. An action that the configuration does not serve answers 403.
- Stowr fails closed. When the PDP gives no valid answer, Stowr answers `503 pdp_unavailable`. It never answers 403 and it
  never grants access. Stowr never sends a question again.
- A kept answer of the PDP stays valid for `access.pdp.cache_ttl` at most (default 30 s). A revoked grant can stay active for
  this time. Set `cache_ttl = "0s"` to keep no answer.
- A volume follows no symbolic link in the path of a key. A grant is on the key of an object, not on its real path.
- The PDP token is a secret. The file refuses it in clear text: give `token_env` or `token_file`. Keep the network of the PDP
  closed, and use an https URL. The setting `plain_http = true` sends the token and the questions without TLS.
- The log line `access.decision` shows the subject and the node. With `server.log_mode = "anonymous"`, it shows `-` in place
  of the folder ids. Keep the log under the rules of your data policy.

### Mode open

Stowr checks no token and asks no PDP. Each request that reaches Stowr can do each operation that the process ceilings let.
The ceilings are the `permissions` of the blocks and `server.access_mode`.

Use this mode only behind a reverse proxy that authenticates the users. Do not publish the port of Stowr. Stowr writes a warning at start. The interface shows one notice when the reverse proxy answers 401.

## Permission enforcement

The interface adapts to the known capabilities. Each handler of the server also checks the permissions that it needs. The
interface never decides.

The effective access is the intersection of these things:

- the operations that Stowr implements;
- the permission ceiling of the bucket;
- the decision of the PDP, in the mode `authzen`;
- the policy of the credentials at the provider;
- the retention, the encryption and the policy of the provider;
- the access mode `force_read_only`, when it is set.

Stowr treats an unknown capability as usable until the provider gives an explicit denial. The observations stay in the
process. A denial that one object operation learns is reported for a minute. It never blocks the requests for other objects.
Only these things are enforced: the configuration, the runtime policy and the bucket-level probes that deny a permission. A
probe that fails, is canceled or gives a status other than 403 leaves the capability unknown.

## Version capability probe

Stowr enables the version controls only after one successful bounded request for the list of versions at start. A `501`
answer, a denial, a time-out or a parse error hides all version controls for that bucket. The probe never creates, changes
or deletes an object.

Restore and permanent delete of a version need the permission and an explicit confirmation in the interface.

## Upload resume token

Stowr seals the provider coordinates of an upload in an authenticated AES-GCM token. It gives the token to the client. The
token is bound to the id of the `auth` block and to the bucket instance. It expires after 30 days at most. Stowr does not
write it.

The opaque token is enough to find the state of the provider again after a restart. Treat it as a bearer capability. A client
must not log it, put it in a URL or show it to a third party.

## Provider connections

- An endpoint uses HTTP or HTTPS. It has no user information, no query string and no fragment.
- Stowr follows no redirect.
- Stowr ignores the proxies of the environment.
- Stowr uses TLS 1.2 or newer.
- Only an explicit attribute of the configuration can stop the check of a certificate. It is for tests.
- Stowr bounds the size of the configuration file and of each credential file.

## Browser isolation

The interface loads only assets of its own origin. It makes no request to a CDN at run time. A strict CSP stops the previews of email, EPUB, SVG, Markdown and structured data. They cannot load third-party resources.

Stowr checks the origin of each request that changes data. The credentials of a provider never reach the browser.

Each route that returns object bytes carries the sandbox CSP. These routes are `/s3`, `/open/`, the image previews and
`/api/archive-entry`. Stowr always sends an archive member that is an active document or a script as an attachment, with a
neutral content type. Such members are HTML, SVG, XML, JavaScript and WebAssembly. Thus a ZIP member never runs as a page or
a script of the same origin. Stowr delivers an SVG member only as an image to an `<img>` request.

## Raw private-key preview

The preview of a raw key is a deliberate function. It needs the read permission. Its content stays in the application, on the
same origin. A deployment that holds private keys must limit the grants of `object.read` to the folders that need them. It can
also use an access control at the reverse proxy. Keep `server.log_mode = "anonymous"`.

## Complete-object operations

An integrity check and the comparison of two versions in the browser are explicit actions of a person.

- The integrity check runs with finite budgets of provider bytes and requests. It hashes with constant memory.
- The comparison reads exact bounded ranges of two immutable versions of one key. The browser keeps two small buffers.

Stowr has no global analysis that needs a large exact result set in memory.

## Resource limits

These limits protect the storage slots from slow or hostile clients:

- An upload body or a download must make progress at least every 30 seconds. Else Stowr cuts the connection and frees the slot.
- A request that cannot get a storage slot in 30 seconds gets `503 storage_busy`. A background job waits in a queue.
- Stowr cancels a paused job after 30 minutes. It aborts an idle upload session after 30 minutes.
- A SQLite preview session expires after three idle periods at most. When the table is full, Stowr evicts the oldest session.
- The preview parsers bound the depth of nesting, the count of elements, the decoded sizes and the output size. The bounds
  cover email parts, vCard and iCalendar lines, Parquet metadata, PDF page markers, FITS headers, spreadsheet rows, cells
  and pages, and SQLite sorts.
- The cache of prepared static answers has a limit of entries and of bytes. The depth of the base URL has a limit.

## Archive members

An extraction of selected members refuses these cases:

- a directory that is used as a file;
- a symbolic link;
- an encrypted entry;
- an absolute path or a traversal;
- a duplicate destination;
- a destination object that already exists;
- a collision of sources;
- an entry whose expanded size is over the configured budget.

Stowr streams the content from the archive to the provider destination. It makes no temporary file. An extraction needs the
read and the write permission on the target. Thus the create-only conflict check cannot show that an object exists on a
write-only target.

## Logging

The anonymous mode is the default. It keeps object keys out of the log, also the keys in the `/-/` URLs of the browser. Stowr
quotes each logged path, so a control character cannot forge a log line. Use the detailed mode only in a controlled
environment. The technical inspection never shows authorization headers, cookies, tokens or credential headers.
