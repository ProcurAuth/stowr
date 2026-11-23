# Shared settings of the scripts that run Docker. Source this file. Do not run it.
# It sets: root, image, registry_volume, target_volume, uid and gid.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="stowr-dev:1"
registry_volume="stowr-cargo-registry"
# One target volume for each checkout: a worktree never shares build files with another.
target_volume="stowr-target-$(printf %s "$root" | sha1sum | cut -c1-8)"
uid="$(id -u)"
gid="$(id -g)"

# Build the development image one time: the pinned Rust image with fmt and clippy.
ensure_image() {
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        docker build --quiet --tag "$image" --file "$root/scripts/Dockerfile.dev" "$root/scripts" >/dev/null
    fi
}

# Create each volume one time, and give it to the host user with a root container.
ensure_volumes() {
    local volume owner
    for volume in "$registry_volume" "$target_volume"; do
        if ! docker volume inspect "$volume" >/dev/null 2>&1; then
            docker volume create "$volume" >/dev/null
        fi
        owner="$(docker run --rm --user 0:0 --volume "$volume:/v" "$image" stat -c '%u:%g' /v)"
        if [ "$owner" != "$uid:$gid" ]; then
            docker run --rm --user 0:0 --volume "$volume:/v" "$image" chown -R "$uid:$gid" /v
        fi
    done
}
