#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Run cargo inside Docker. Nothing is installed on the host.
# Use: scripts/cargo.sh check --all-targets
#      scripts/cargo.sh test
#      scripts/cargo.sh fmt --all -- --check
#      scripts/cargo.sh clippy --all-targets -- -D warnings
#
# The script runs as the host user. The cargo registry and the target
# directory live in named Docker volumes, so no root-owned file appears
# in the repository.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/docker-env.sh"
ensure_image
ensure_volumes

# CARGO_BUILD_JOBS, when set on the host, limits the compile jobs in the container.
jobs_env=()
if [ -n "${CARGO_BUILD_JOBS:-}" ]; then
    jobs_env=(--env "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS")
fi

tty_flag=()
if [ -t 0 ] && [ -t 1 ]; then
    tty_flag=(--tty)
fi

exec docker run --rm --interactive "${tty_flag[@]}" \
    --user "$uid:$gid" \
    --volume "$root:/work" \
    --volume "$registry_volume:/cargo-home" \
    --volume "$target_volume:/cargo-target" \
    --workdir /work \
    --env CARGO_HOME=/cargo-home \
    --env CARGO_TARGET_DIR=/cargo-target \
    --env HOME=/cargo-home \
    --env CARGO_TERM_COLOR=never \
    "${jobs_env[@]}" \
    "$image" cargo "$@"
