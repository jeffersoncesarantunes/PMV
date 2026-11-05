#!/bin/sh
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
BIN="$ROOT/pmv"
CC=${CC:-cc}

if [ "$(uname -s)" != "OpenBSD" ]; then
    echo "SKIP: integration tests require OpenBSD"
    exit 0
fi

WORK=$(mktemp -d)
pids=""
cleanup() {
    for pid in $pids; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf -- "$WORK"
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

start() {
    "$1" &
    STARTED_PID=$!
    pids="$pids $STARTED_PID"
}

json_for_pid() {
    (cd "$WORK" && "$BIN" --pid "$1" --format json > "$2")
}

check_bool() {
    python3 - "$1" "$2" "$3" "$4" <<'PY'
import json
import sys

path, pid, field, want = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
with open(path, encoding="utf-8") as handle:
    doc = json.load(handle)
rows = [row for row in doc if row["pid"] == pid]
if not rows:
    print(f"pid {pid} not found in output", file=sys.stderr)
    sys.exit(2)
got = rows[0][field]
expected = want == "true"
if got != expected:
    print(f"{field}={got}, expected {expected}", file=sys.stderr)
    sys.exit(1)
PY
}

[ -x "$BIN" ] || fail "$BIN not found (run make first)"

$CC -O2 -o "$WORK/pledged" "$ROOT/tests/integration/helpers/pledged.c" \
    || fail "could not build pledged helper"
$CC -O2 -o "$WORK/naked" "$ROOT/tests/integration/helpers/naked.c" \
    || fail "could not build naked helper"

echo "== pledge/unveil detection"
start "$WORK/pledged"
pid=$STARTED_PID
sleep 1
json_for_pid "$pid" "$WORK/pledged.json"
check_bool "$WORK/pledged.json" "$pid" pledge true || fail "pledged helper not detected"
check_bool "$WORK/pledged.json" "$pid" unveil true || fail "unveil not detected"
pass "pledge and unveil reported as present"

echo "== unmitigated process detection"
start "$WORK/naked"
pid=$STARTED_PID
sleep 1
json_for_pid "$pid" "$WORK/naked.json"
check_bool "$WORK/naked.json" "$pid" pledge false || fail "naked helper reported pledge"
check_bool "$WORK/naked.json" "$pid" unveil false || fail "naked helper reported unveil"
pass "unmitigated process reported as absent"

echo "== JSON export schema and score"
(cd "$WORK" && "$BIN" --format json > "$WORK/all.json")
python3 - "$WORK/all.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    doc = json.load(handle)

required = {
    "pid", "ppid", "name", "ppname", "pledge", "unveil",
    "chrooted", "context", "score",
}
assert isinstance(doc, list) and doc, "expected a non-empty JSON array"
for row in doc:
    missing = required - row.keys()
    assert not missing, f"missing keys: {missing}"
    expected = (
        (3 if row["pledge"] else 0)
        + (2 if row["unveil"] else 0)
        + (1 if row["chrooted"] else 0)
    )
    assert row["score"] == expected, (row, expected)
PY
pass "JSON schema is valid and scores match the documented formula"

echo "== W^X memory scan"
if $CC -O2 -Wl,-z,wxneeded -o "$WORK/wx" "$ROOT/tests/integration/helpers/wx.c" 2>/dev/null; then
    sysctl kern.allowkmem=1 >/dev/null 2>&1 || true
    start "$WORK/wx"
    pid=$STARTED_PID
    sleep 1
    (cd "$WORK" && "$BIN" --scan-wx "$pid" > "$WORK/wx.txt" 2>&1) || true
    if grep -q 'VIOLATION' "$WORK/wx.txt"; then
        pass "RWX mapping detected"
    elif grep -Eq 'restricted|Permission denied|not available' "$WORK/wx.txt"; then
        echo "SKIP: kernel blocked KERN_PROC_VMMAP (documented in LIMITATIONS.md)"
    else
        cat "$WORK/wx.txt" >&2
        fail "RWX mapping was not detected"
    fi
else
    echo "SKIP: could not build the wxneeded helper on this system"
fi

echo "All integration tests completed."
