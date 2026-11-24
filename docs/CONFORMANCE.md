# Conformance of the access policy

The ProcurAuth repository has a conformance runner, `access-conformance`. The runner tests a service (a PEP) with the
series U of cases. Stowr runs this series in Docker. The behavior that the cases test is in [ACCESS.md](ACCESS.md).

## Run the test

The script `test/conformance/run.sh` does the whole test. It needs Docker, `git` and `python3`.

```sh
PROCURAUTH_DIR=/path/to/procurauth test/conformance/run.sh
```

The workflow `nightly.yaml` runs this test every night and before a release. The workflow `conformance.yml` runs it by hand.
It takes about 4 minutes, so it does not run on a pull request. Run the script when you change the access policy.

`PROCURAUTH_DIR` gives the checkout of the ProcurAuth repository. The default is the directory `procurauth` next to the
checkout of Stowr. The checkout must be at the commit of "The commit of the runner". The script does not change the
checkout.

| Option | Use |
|---|---|
| `--cases U01,U02,...` | Run only these cases. The check of `expected.txt` then covers only these cases. |
| `--format text` or `--format json` | The form of the report of the runner on the standard output. The default is `text`. |
| `--no-build` | Do not build the runner. Use the runner of the last build. |
| `--log FILE` | Write the log of Stowr to this file at the end. |

| Exit code | Result |
|---|---|
| 0 | The failed cases and the skipped cases are equal to `expected.txt`. |
| 1 | The failed cases or the skipped cases are not equal to `expected.txt`. |
| 2 | A problem of the preparation: a bad profile, a target that does not answer, no tool, another commit of ProcurAuth. |

## What the script does

1. It makes sure that the ProcurAuth checkout is at the commit of the runner.
2. It builds the runner with `scripts/cargo.sh` of the ProcurAuth repository, unless the option `--no-build` is set. The
   runner goes to the directory `stowr-conformance` of the target volume of that checkout.
3. It builds Stowr as a static binary with `scripts/static.sh`.
4. It copies the test keys of ProcurAuth, the configuration and the profile to a temporary directory. It makes the fixture:
   one file of 12 bytes and one empty folder.
5. It starts Stowr in a container with no network (`--network none`) and a read-only root. The configuration is
   `test/conformance/config.hcl`: the mode `authzen` and one volume.
6. It starts the runner in the network namespace of the container of Stowr. The two programs share only the loopback address.
7. It compares the failed cases and the skipped cases with `expected.txt`, and removes the container.

The runner has three roles. It is the client. It is the edge: it signs the identity tokens with the test keys of ProcurAuth. It is
the PDP, on `127.0.0.1:8181`. Stowr never reaches a real PDP. The script removes only the container that it started.

## The files

| File | Use |
|---|---|
| `test/conformance/run.sh` | The script. |
| `test/conformance/config.hcl` | The configuration of Stowr for the test. It uses `public_keys_file` and `token_file`, and a `cache_ttl` of `0s`. |
| `test/conformance/profile.json` | The profile of the service: the service id, the token rules, the PDP, and the operations. |
| `test/conformance/expected.txt` | The cases that do not pass, with their status and their reason. |

The operations of the profile:

| Operation | Request | Action and node |
|---|---|---|
| `use_plain` | `GET /s3` of the file `reports/a.txt` | `object.read` on `folder:reports` |
| `use_ceiling` | The same read, with the ceiling `max_object_size` | `object.read` on `folder:reports` |
| `use_budget` | `PUT /s3` of `reports/new.txt` | `object.write` on `folder:reports`, with usage |
| `use_multi` | `POST /api/copy` of `reports/a.txt` to `reports/copy.txt` | the use `object.write`, and the other `object.read` with `permission_only` |
| `read_health` | `GET /healthz`, with no token | no question |
| `use_no_action` | `GET /`, a static page | `access` on the service |
| `read_actions`, `list_options` | The defaults of the runner: the action document, and the options route with the type `bucket` | |

The profile has no operation `use_service`. In the cases, this operation is the use of an action of the action document on
the node of the service. No route of Stowr uses such a permission: the routes without data of a bucket ask the action
`access`, and `use_no_action` tests them. The profile has no member `approval_calls`: the runner reads it only for an MCP
endpoint. The case U113 tests the answer `approval_cannot_wait` of the HTTP routes.

The profile says that the service has no answer cache that the runner must count, because `cache_ttl` is `0s`.

## Expected result

The run of the series U gives 127 cases: 81 passed, 0 failed and 46 skipped. No case gives a warning.

The runner skips these cases:

| Cases | Reason |
|---|---|
| U18, U23, U25 to U31, U85 to U111, U114 to U117, U121 to U125 (45 cases) | The service has no MCP endpoint. |
| U84 | The profile has no operation `use_service` (refer to "The files"). |

The cases U02, U40, U59 and U113 also have steps with the operation `use_service`. The runner skips these steps and runs
the other steps of the cases. These cases pass.

The new cases of ProcurAuth 1.1 that run all pass:

- U118 tests the form of `iat` and `exp`.
- U119 tests a token without `kid` and a key set with two keys.
- U120 tests `nbf`.
- U126 tests a reason of 17.1 for an other permission.
- U127 tests the health probe and a route without action.

The cases U121 to U125 need an MCP endpoint.

## The file expected.txt

The file `expected.txt` lists each case that does not pass. Write one case id for each line, then the status `fail` or `skip`,
then an optional `#` and the reason. A line with a case id only is a failed case. The file can have blank lines and comment lines.

The script exits with 0 only when the failed cases and the skipped cases are equal to this list. A case that fails or skips
and is not in the list is a failure of the test. A case in the list that has another result is also a failure: change the list.

## The commit of the runner

The script pins one commit of the ProcurAuth repository: `c820b4ac0e37c4769394876105fd549a6c8b38cc`, the tag `v1.1`
(ProcurAuth 1.1, 127 cases in the series U). Thus a change of the runner never changes the result by itself. The library
`procurauth-pep` of `Cargo.toml` has the same commit.

To change the commit:

1. Check out the new commit of the ProcurAuth repository.
2. Write the full SHA of the new commit in `procurauth_commit` of `test/conformance/run.sh`.
3. Run `PROCURAUTH_DIR=/path/to/procurauth test/conformance/run.sh`.
4. Update `test/conformance/expected.txt` and the numbers of "Expected result" in this document.
5. Write the full SHA in `ref` of `.github/workflows/conformance.yml` and in this section.
