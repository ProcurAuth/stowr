## What changes

Describe the change in a few sentences.

## Why

Give the reason. Link the issue.

## Checks

- [ ] I ran `scripts/cargo.sh fmt --all -- --check`, `scripts/cargo.sh clippy --all-targets --locked -- -D warnings` and `scripts/cargo.sh test --locked`.
- [ ] I ran `scripts/check-invariants.sh` and `python3 -I scripts/check-docs.py`.
- [ ] A change of the configuration changes `src/config/keys.rs`, and I made `docs/configuration-reference.md` again.
- [ ] A change of a document follows ASD-STE100, and I ran `python3 -I scripts/build-site.py`.
- [ ] I updated `CHANGELOG.md` under "Unreleased".
- [ ] The files have no real host name, no real address and no secret.
