#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Run the heavy checks of the CI on this machine. The workflow nightly.yaml runs the same checks.
# Use: scripts/heavy.sh [--list] [GROUP...]
# A GROUP is one of: rust, static, frontend, conformance. Without a GROUP, the script runs all of them.
#   rust         clippy and the tests                       (scripts/cargo.sh)
#   static       the static binary and the scratch image    (scripts/static.sh, test/scratch-runtime.sh)
#   frontend     the browser tests of the interface         (test/frontend/run.sh)
#   conformance  the ProcurAuth runner against Stowr        (test/conformance/run.sh, PROCURAUTH_DIR)
# The script needs Docker. It stops at the first failed group. Each image stays on this machine.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

groups=(rust static frontend conformance)

usage() {
    echo "usage: scripts/heavy.sh [--list] [rust|static|frontend|conformance]..." >&2
    exit 2
}

run_group() {
    case "$1" in
    rust)
        scripts/cargo.sh clippy --all-targets --locked -- -D warnings
        scripts/cargo.sh test --locked
        ;;
    static)
        STOWR_BUILD_VERSION=ci STOWR_BUILD_COMMIT="$(git rev-parse HEAD)" scripts/static.sh --check
        BUILD_VERSION=ci BUILD_COMMIT="$(git rev-parse HEAD)" ./test/scratch-runtime.sh
        ;;
    frontend)
        ./test/frontend/run.sh
        ;;
    conformance)
        ./test/conformance/run.sh
        ;;
    esac
}

selected=()
for argument in "$@"; do
    case "$argument" in
    --list)
        printf '%s\n' "${groups[@]}"
        exit 0
        ;;
    rust | static | frontend | conformance) selected+=("$argument") ;;
    *) usage ;;
    esac
done
[ "${#selected[@]}" -gt 0 ] || selected=("${groups[@]}")

for group in "${selected[@]}"; do
    echo "== heavy: $group"
    start="$(date +%s)"
    run_group "$group"
    echo "== heavy: $group ok in $(($(date +%s) - start)) s"
done
