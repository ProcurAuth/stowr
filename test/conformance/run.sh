#!/usr/bin/env bash
# Run the ProcurAuth conformance series U (role PEP) against Stowr. The script uses Docker, git and python3.
# Use: test/conformance/run.sh [--no-build] [--cases U01,U02,...] [--format text|json] [--log FILE]
#
#   --no-build   Do not build the runner. Use the runner of the last build. Stowr is always built (cargo builds only
#                the changes).
#   --cases      Run only these cases. The check of expected.txt then covers only these cases.
#   --format     The form of the report of the runner on the standard output. The default is text.
#   --log        Write the log of Stowr to this file at the end.
#
# The variable PROCURAUTH_DIR gives the checkout of the ProcurAuth repository. The default is the directory
# procurauth next to the checkout of Stowr. The checkout must be at the commit of ProcurAuth 1.1 below. The script
# does not change the checkout: the runner goes to the directory stowr-conformance of the target volume of that
# checkout.
#
# The script builds the runner access-conformance with the scripts of ProcurAuth, and Stowr as a static binary with
# scripts/static.sh. Then it starts Stowr in a container with no network (--network none) and a read-only root. The
# runner runs in the network namespace of that container: the two share only the loopback address. The runner acts
# as the client, as the edge (it signs the identity tokens with the test keys of ProcurAuth) and as the PDP
# (127.0.0.1:8181). Stowr never reaches a real PDP.
#
# Exit codes:
#   0  The failed cases and the skipped cases are equal to expected.txt.
#   1  The failed cases or the skipped cases are not equal to expected.txt.
#   2  A problem of the set-up: a bad profile, a target that is not reachable, a missing tool, another commit.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
procurauth="${PROCURAUTH_DIR:-$(cd "$repo/.." && pwd)/procurauth}"
# ProcurAuth 1.1 (tag v1.1). The cases and the runner come from this commit only.
procurauth_commit="c820b4ac0e37c4769394876105fd549a6c8b38cc"
stowr_image="alpine:3.22"
runner_target="/cargo-target/stowr-conformance"
expected_file="$here/expected.txt"

die() {
    echo "ERROR: $*" >&2
    exit 2
}

build=1
cases=""
format="text"
log_file=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-build) build=0 ;;
        --cases | --format | --log)
            [ "$#" -ge 2 ] || die "The option $1 needs a value."
            case "$1" in
                --cases) cases="$2" ;;
                --format) format="$2" ;;
                --log) log_file="$2" ;;
            esac
            shift
            ;;
        *)
            echo "Use: $0 [--no-build] [--cases ID,ID,...] [--format text|json] [--log FILE]" >&2
            exit 2
            ;;
    esac
    shift
done
case "$format" in
    text | json) ;;
    *) die "The option --format takes text or json. Found: $format" ;;
esac
runner_args=(--format "$format")
if [ -n "$cases" ]; then
    runner_args+=(--cases "$cases")
fi

for tool in docker git python3; do
    command -v "$tool" >/dev/null 2>&1 || die "The tool $tool is missing."
done
[ -f "$expected_file" ] || die "The file $expected_file is missing."
if [ ! -f "$procurauth/scripts/docker-env.sh" ]; then
    die "The file $procurauth/scripts/docker-env.sh is missing. Set PROCURAUTH_DIR to the ProcurAuth checkout."
fi
found_commit="$(git -C "$procurauth" rev-parse HEAD 2>/dev/null || true)"
if [ "$found_commit" != "$procurauth_commit" ]; then
    die "The checkout $procurauth is at the commit ${found_commit:-unknown}. Check out $procurauth_commit (ProcurAuth 1.1)."
fi
# This sets image, target_volume, uid and gid, as the scripts of ProcurAuth do.
# shellcheck source=/dev/null
source "$procurauth/scripts/docker-env.sh"
ensure_image

scratch="$(mktemp -d)"
work="$scratch/work"
name="stowr-procurauth-conformance-$$"
cleanup() {
    # Remove only the container of this run.
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT INT TERM
mkdir -p "$work" "$scratch/bin"

# Build the runner in its own target directory, and Stowr as a static binary.
if [ "$build" -eq 1 ]; then
    echo "== build access-conformance" >&2
    "$procurauth/scripts/cargo.sh" build --release --locked -p access-conformance --target-dir "$runner_target" >&2
fi
echo "== build stowr" >&2
"$repo/scripts/static.sh" --copy "$scratch/bin" >&2
[ -x "$scratch/bin/stowr" ] || die "The static binary of Stowr is missing."

# The files of the run. The paths agree with config.hcl and profile.json.
keys="$procurauth/crates/access-conformance/examples"
for file in test-edge-ed25519.pem test-edge-es256.pem edge-jwks.json pdp-credential.txt; do
    [ -f "$keys/$file" ] || die "The file $keys/$file is missing."
done
cp "$keys/test-edge-ed25519.pem" "$keys/test-edge-es256.pem" "$keys/edge-jwks.json" "$work/"
tr -d '\n' <"$keys/pdp-credential.txt" >"$work/pdp-token"
cp "$here/config.hcl" "$here/profile.json" "$work/"
# The fixture: one file of 12 bytes and one empty folder.
mkdir -p "$work/data/reports/2026"
printf 'hello stowr\n' >"$work/data/reports/a.txt"
chmod 0755 "$scratch" "$work"
chmod -R a+rwX "$work"

# Stowr, with no network, a read-only root, and the binary and the files mounted read-only.
# The container has no --rm option: the log stays readable after a crash. The trap removes it.
echo "== start stowr" >&2
docker run --detach --name "$name" --network none --read-only --user "$uid:$gid" \
    --volume "$scratch/bin/stowr:/stowr:ro" \
    --volume "$work:/conformance:ro" \
    --volume "$work/data:/data" \
    "$stowr_image" /stowr -c /conformance/config.hcl >/dev/null
sleep 1
if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != "true" ]; then
    echo "--- log of stowr" >&2
    docker logs --tail 60 "$name" >&2 || true
    die "Stowr did not stay running."
fi

# The runner, in the network namespace of Stowr. It waits for the port 8080 first.
echo "== run the series U" >&2
result="$scratch/result.txt"
set +e
timeout 900 docker run --rm --init --network "container:$name" --user "$uid:$gid" \
    --volume "$work:/work:ro" --volume "$target_volume:/cargo-target:ro" \
    --env HOME=/tmp "$image" timeout 840 bash -c '
for i in $(seq 1 100); do
    (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null && break
    sleep 0.1
done
exec "$0" --role pep --series U --profile /work/profile.json --url http://127.0.0.1:8080 "$@"
' "$runner_target/release/access-conformance" "${runner_args[@]}" | tee "$result"
code="${PIPESTATUS[0]}"
set -e
if [ -n "$log_file" ]; then
    docker logs "$name" >"$log_file" 2>&1 || true
fi

# The runner gives 0 or 1 for a run that ended. Any other code is a problem of the set-up.
if [ "$code" -ne 0 ] && [ "$code" -ne 1 ]; then
    echo "--- log of stowr (last 60 lines)" >&2
    docker logs --tail 60 "$name" >&2 || true
    if [ "$code" -eq 2 ]; then
        exit 2
    fi
    die "The runner stopped with the code $code."
fi

# The verdict: compare the failed cases and the skipped cases with expected.txt.
python3 -I - "$expected_file" "$result" "$format" "$cases" <<'PY'
import json
import re
import sys

expected_file, result_file, form, only = sys.argv[1:5]


def stop(message):
    print(message, file=sys.stderr)
    sys.exit(2)


expected = {}
for number, line in enumerate(open(expected_file, encoding="utf-8"), 1):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    entry, _, _reason = line.partition("#")
    words = entry.split()
    if len(words) == 1:
        words.append("fail")
    if len(words) != 2 or not re.fullmatch(r"U[0-9]{2,3}", words[0]) or words[1] not in ("fail", "skip"):
        stop(f"ERROR: {expected_file}:{number}: write one case id of the series U, then fail or skip, then an optional # and the reason")
    case, status = words
    if case in expected:
        stop(f"ERROR: {expected_file}:{number}: the case {case} occurs two times")
    expected[case] = status

results = {}
text = open(result_file, encoding="utf-8").read()
if form == "json":
    try:
        report = json.loads(text)
    except ValueError as error:
        stop(f"ERROR: the report of the runner is not JSON: {error}")
    for entry in report["cases"]:
        results[entry["id"]] = entry["status"]
else:
    for line in text.splitlines():
        match = re.match(r"^(U[0-9]{2,3})\s+(pass|fail|warn|skip)\b", line)
        if match:
            results[match.group(1)] = match.group(2)
if not results:
    stop("ERROR: the report of the runner has no case")

# With --cases, check only the expected cases that ran.
if only:
    expected = {case: status for case, status in expected.items() if case in results}
unknown = sorted(case for case in expected if case not in results)
if unknown:
    stop("ERROR: expected.txt names cases that the runner does not know: " + ", ".join(unknown))

out = sys.stderr if form == "json" else sys.stdout
problems = []
for case, status in sorted(results.items()):
    want = expected.get(case)
    if status in ("fail", "skip") and want != status:
        problems.append(f"UNEXPECTED {status.upper()} {case}: add it to expected.txt with its reason, or fix Stowr")
    elif want is not None and status != want:
        problems.append(f"UNEXPECTED {status.upper()} {case} (expected {want}): change expected.txt")
counts = {state: sum(1 for status in results.values() if status == state) for state in ("pass", "fail", "skip", "warn")}
# The report of the runner stays alone on the standard output when it is JSON.
print(file=out)
print(
    f"cases: {len(results)}, passed: {counts['pass']}, failed: {counts['fail']}, skipped: {counts['skip']}, warned: {counts['warn']}",
    file=out,
)
for problem in problems:
    print(problem, file=out)
sys.exit(1 if problems else 0)
PY
