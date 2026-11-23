# Repository metadata

This file lists the settings that a maintainer applies on GitHub with `gh`. The repository files do not apply them.

## About

- Description (106 characters): `Browse S3, Google Cloud Storage and server folders in one page. One static binary, one HCL file, no state.`
- Website: `https://procurauth.github.io/stowr/`
- Social preview image: upload `docs/assets/og.png` (1200 by 630 pixels).

## Topics

`s3`, `object-storage`, `google-cloud-storage`, `storage-browser`, `file-browser`, `minio`, `seaweedfs`, `garage`, `procurauth`, `authzen`, `self-hosted`, `rust`

## Settings

- Pages: serve the branch `main`, from the folder `/docs`.
- Enable the private reports of vulnerabilities (Settings, Code security). `SECURITY.md` and `CODE_OF_CONDUCT.md` link to them.
- Enable the alerts of Dependabot. `.github/dependabot.yml` updates the actions of the workflows.
- Protect `main`: require the checks `Format, clippy, tests and rules of the runtime` and `docs` before a merge.
- Do not publish a container image. The releases hold binaries only.

## Labels

Create these labels. The issue forms use them: `bug`, `enhancement`, `documentation`.

## Commands

```sh
gh repo edit ProcurAuth/stowr \
  --description "Browse S3, Google Cloud Storage and server folders in one page. One static binary, one HCL file, no state." \
  --homepage "https://procurauth.github.io/stowr/" \
  --add-topic s3 --add-topic object-storage --add-topic google-cloud-storage --add-topic storage-browser \
  --add-topic file-browser --add-topic minio --add-topic seaweedfs --add-topic garage --add-topic procurauth \
  --add-topic authzen --add-topic self-hosted --add-topic rust
for label in bug enhancement documentation; do gh label create "$label" --repo ProcurAuth/stowr || true; done
```
