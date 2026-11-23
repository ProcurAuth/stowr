#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Check the rules of the runtime that the compiler does not check (docs/DEVELOPMENT.md, "Rules of the runtime").
# Use: scripts/check-invariants.sh
# The script reads the files of the repository only. It needs bash, grep and find.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
status=0

fail() {
    echo "invariant: $1" >&2
    status=1
}

# search PATTERN [EXCLUDED_PATH...]: the lines of the Rust sources of src/ that match, outside the excluded paths.
# Each file named tests.rs or *_tests.rs is test code: it can make fixtures in temporary folders.
search() {
    local pattern="$1"
    shift
    local excluded=(--exclude=tests.rs --exclude='*_tests.rs' --exclude-dir=testkit)
    local path
    for path in "$@"; do
        if [ -d "src/$path" ]; then excluded+=(--exclude-dir="$path"); else excluded+=(--exclude="$(basename "$path")"); fi
    done
    grep -rnE --include='*.rs' "${excluded[@]}" "$pattern" src || true
}

# 1. The program never runs another program.
hits="$(search 'process::Command|Command::new|std::process::Stdio|posix_spawn|libc::(fork|exec)')"
[ -z "$hits" ] || fail "the program must not run another program:
$hits"

# 2. Only src/config/env.rs reads the process environment: the variables that the configuration names with _env.
hits="$(search 'env::(var|vars|var_os|vars_os|set_var|remove_var)\b|\bvar_os\(' config/env.rs)"
[ -z "$hits" ] || fail "only src/config/env.rs may read an environment variable:
$hits"

# 3. No proxy from the environment, no system proxy.
hits="$(search 'client::proxy|Proxy::|from_env\(|HTTPS?_PROXY|NO_PROXY|ALL_PROXY')"
[ -z "$hits" ] || fail "the clients must not use a proxy:
$hits"

# 4. Only the volume back end (src/volume/) writes to the local file system: the files of a volume block.
hits="$(search '(fs|std::fs)::(write|create_dir|create_dir_all|remove_file|remove_dir|remove_dir_all|rename|hard_link|copy|set_permissions)\b|File::create|OpenOptions|os::unix::fs::symlink|tokio::fs|\.set_len\(|\.set_permissions\(' volume)"
[ -z "$hits" ] || fail "only src/volume/ may write to the local file system:
$hits"

# 5. Unsafe code only in src/volume/statfs.rs (one call to statfs).
# A text such as "an unsafe path" or 'unsafe-inline' is no code: the rule looks for the keyword before a block, an item or
# an attribute.
hits="$(search '\bunsafe[[:space:]]*(\{|\(|fn\b|impl\b|trait\b|extern\b)|allow\(unsafe_code\)' volume/statfs.rs | grep -vE '^[^:]+:[0-9]+:\s*//' || true)"
[ -z "$hits" ] || fail "unsafe code is allowed only in src/volume/statfs.rs:
$hits"

# 6. No font file in the repository.
hits="$(find . -path ./.git -prune -o -type f \( -iname '*.ttf' -o -iname '*.otf' -o -iname '*.woff' -o -iname '*.woff2' -o -iname '*.eot' \) -print)"
[ -z "$hits" ] || fail "font binaries must not be shipped:
$hits"

# 7. The interface loads nothing from another origin.
hits="$(grep -R -nE --exclude-dir=vendor --include='*.html' --include='*.js' --include='*.css' 'https?://|//cdn\.' src/public || true)"
[ -z "$hits" ] || fail "the interface must not contact an external origin:
$hits"

# 8. Each dependency has an exact version.
hits="$(awk '/^\[(dependencies|dev-dependencies|build-dependencies)\]/{on=1; next} /^\[/{on=0} on && /=/ && !/^#/' Cargo.toml | grep -vE '"=[0-9]|version = "=[0-9]|git = "[^"]+", rev = "[0-9a-f]{40}"' || true)"
[ -z "$hits" ] || fail "each dependency must have an exact version (=x.y.z) or a full commit:
$hits"

# 9. The lock file exists: each build uses --locked.
[ -f Cargo.lock ] || fail "Cargo.lock is missing"

if [ "$status" -eq 0 ]; then
    echo "invariants: ok"
fi
exit "$status"
