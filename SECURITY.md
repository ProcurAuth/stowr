# Security policy

This document tells how to report a vulnerability in Stowr. It also tells what the project covers. For the design of the
protections, read the [security model](docs/SECURITY-MODEL.md).

## Report a vulnerability

Do not open a public issue for a vulnerability. Use the private reports of GitHub.

1. Open [the page to report a vulnerability](https://github.com/ProcurAuth/stowr/security/advisories/new).
2. Describe the problem. Name the version, the configuration that you used, and the steps to repeat it.
3. Add a test or a proof of concept if you have one. Remove each real secret and each real host name from it.

Only the maintainers of the repository can read your report. We never ask for an e-mail address or for a secret. If the page
is not available, open a public issue with the title "Security contact needed". Write no detail in it. A maintainer then
starts a private channel.

## Response times

These times are targets for a project that has no paid staff.

| Step | Target |
| --- | --- |
| We acknowledge your report. | 5 working days |
| We tell you if we accept it as a vulnerability. | 15 working days |
| We publish a fix and an advisory. | 90 days after the report, or sooner |

We ask you to wait for the fix before you publish details. We give credit in the advisory, unless you ask us not to.

## Supported versions

| Version | Supported |
| --- | --- |
| The latest release (0.3.x) | Yes |
| The branch `main` | Yes |
| Older releases | No. Update to the latest release. |

## What the project covers

- **The access policy.** A bypass of the check of the identity token is a vulnerability. So is a route that skips the question to the PDP, or a decision that Stowr applies in the wrong way.
- **The isolation of the browser.** A preview that runs active content from an object is a vulnerability. So is a way to load a resource from another origin, or a route that gives object bytes with no sandbox.
- **The storage back ends.** A read or a write outside the folder of a `volume` block is a vulnerability. So is a path traversal in an archive entry, a way to use an object that the permissions refuse, or a leak of a credential.
- **The configuration.** A secret that appears in the output of `print-config`, in the log or in an answer is a vulnerability.
- **The release.** A release archive that does not match its checksum, or a build that is not static, is a defect.

## What the project does not cover

- A deployment that does not follow the documents. Examples: the mode `open` with no proxy that signs users in, or the mode
  `authzen` with a port that the edge does not guard.
- A weakness of a storage provider, of an edge or of a PDP. Report it to that project.
- Provider audit systems that record each request. Stowr cannot make a request invisible to them.
- A denial of service that needs an authorized person to ask for work that the documented limits already bound.

## Test values

The directory `test/` holds fixed credentials, such as the key in `test/secrets/` and the key id in `test/frontend/config.hcl`.
They belong to the isolated test services. They are public on purpose and they protect nothing. A report about one of them is
not a vulnerability.
