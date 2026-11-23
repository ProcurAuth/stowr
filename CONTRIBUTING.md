# Contribute to Stowr

Thank you for your interest. This document tells how to propose a change.

## Ask a question or report a defect

Open an issue with [the issue forms](https://github.com/ProcurAuth/stowr/issues/new/choose). Give the version of Stowr
(`stowr version`), the provider, and the part of the configuration that matters. Remove each secret and each real host name.
Do not report a vulnerability in an issue. Read [SECURITY.md](SECURITY.md).

## Change the code

1. Open an issue first for a large change or a new feature. State the problem and the idea.
2. Use Docker only. Do not install Rust on your machine. [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) tells how.
3. Write a test for each change of behavior. The tests are in the same folder as the code, in files that end with `_tests.rs`.
4. Run the checks:

```sh
scripts/cargo.sh fmt --all -- --check
scripts/cargo.sh clippy --all-targets --locked -- -D warnings
scripts/cargo.sh test --locked
scripts/check-invariants.sh
python3 -I scripts/check-docs.py
```

The browser tests (`test/frontend/run.sh`) and the conformance test (`test/conformance/run.sh`) need Docker and take longer.
Run them when you change the interface or the access policy.

## Rules of the code

- Each dependency has an exact version in `Cargo.toml`. Add a dependency only when the code that it replaces is larger or
  less strict.
- The program reads its configuration from the HCL file only. It reads an environment variable only when the file names it
  with an `_env` attribute. A change to the configuration changes the table of keys in `src/config/keys.rs`. Make the
  reference again with the command in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
- The program keeps no state on disk. Only `src/volume/` writes files.
- The interface loads nothing from another origin and uses no font file.
- Add `SPDX-License-Identifier: MIT OR Apache-2.0` as the first comment of each new source file.

## Rules for the documents

- Write in ASD-STE100 Simplified Technical English. A procedural sentence has 20 words at most. A descriptive sentence has
  25 words at most. A paragraph has six sentences at most. Use the active voice and the imperative in a procedure.
- The text must describe the real behavior of the code. Check the code, not the old text.
- The Markdown files in `docs/` are the source of the website. After you change one, run `python3 -I scripts/build-site.py`.
- Use `example.com` and the address range `203.0.113.0/24` in examples. Never write a real host name, a real address or a
  real secret.
- Do not add a container image to the release or to a registry. A release holds binaries only.

## Pull requests

Open a pull request against `main`. Complete the template. The CI must pass. Your contribution is under the licence of the
project: `MIT OR Apache-2.0`.

## Code of conduct

This project follows [the code of conduct](CODE_OF_CONDUCT.md).
