#!/usr/bin/env bash
# Build the program as a static Linux file with the musl target of the host architecture (x86_64 or aarch64), inside
# Docker.
# Use: scripts/static.sh            (build)
#      scripts/static.sh --check    (build, then check that the file is static and runs)
# The file is in the target volume, in /cargo-target/<architecture>-unknown-linux-musl/release/stowr.
# Give it to the host with: scripts/static.sh --copy <directory>
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/docker-env.sh"
ensure_image
ensure_volumes

static_image="stowr-static:1"
if ! docker image inspect "$static_image" >/dev/null 2>&1; then
    docker build --quiet --tag "$static_image" --file "$root/scripts/Dockerfile.static" "$root/scripts" >/dev/null
fi

case "$(uname -m)" in
    x86_64 | amd64) target=x86_64-unknown-linux-musl ;;
    aarch64 | arm64) target=aarch64-unknown-linux-musl ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac
binary="/cargo-target/$target/release/stowr"
after=""
mounts=()
case "${1:-}" in
    --check)
        after="
if ! file $binary | grep -q 'static'; then echo 'not static: stowr' >&2; exit 1; fi
if readelf -l $binary | grep -q 'Requesting program interpreter'; then echo 'stowr needs a dynamic loader' >&2; exit 1; fi
$binary version"
        ;;
    --copy)
        destination="$(cd "${2:?give the destination directory}" && pwd)"
        mounts=(--volume "$destination:/out")
        after="
cp $binary /out/stowr"
        ;;
    "") ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

exec docker run --rm \
    --user "$uid:$gid" \
    --volume "$root:/work" \
    --volume "$registry_volume:/cargo-home" \
    --volume "$target_volume:/cargo-target" \
    "${mounts[@]}" \
    --workdir /work \
    --env CARGO_HOME=/cargo-home \
    --env CARGO_TARGET_DIR=/cargo-target \
    --env HOME=/cargo-home \
    --env CARGO_TERM_COLOR=never \
    --env STOWR_BUILD_VERSION="${STOWR_BUILD_VERSION:-}" \
    --env STOWR_BUILD_COMMIT="${STOWR_BUILD_COMMIT:-}" \
    --env STOWR_BUILD_DATE="${STOWR_BUILD_DATE:-}" \
    "$static_image" bash -c "cargo build --release --locked --target $target $after"
