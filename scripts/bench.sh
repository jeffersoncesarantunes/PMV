#!/bin/sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
BIN=${1:-$ROOT/pmv}
N=${N:-10}

if [ "$(uname -s)" != "OpenBSD" ]; then
    echo "SKIP: benchmark requires OpenBSD"
    exit 0
fi

if [ ! -x "$BIN" ]; then
    echo "error: $BIN not found or not executable" >&2
    exit 1
fi

TMP=$(mktemp)
WORK=$(mktemp -d)
cleanup() {
    rm -f -- "$TMP"
    rm -rf -- "$WORK"
}
trap cleanup EXIT INT TERM

i=0
while [ "$i" -lt "$N" ]; do
    /usr/bin/time -l "$BIN" > /dev/null 2>> "$TMP"
    i=$((i + 1))
done

PROCS=$(cd "$WORK" && "$BIN" --format json 2>/dev/null | grep -c '"pid"' || true)

printf 'command: %s\n' "$BIN"
printf 'processes observed: %s\n' "$PROCS"
awk -v runs="$N" '
    $2 == "real" {
        sum += $1
        n++
        if ($1 > max) max = $1
    }
    /maximum resident set size/ {
        if ($1 > rss) rss = $1
    }
    END {
        if (n == 0) {
            print "error: no timing measurements found" > "/dev/stderr"
            exit 1
        }
        printf "runs: %d\n", n
        printf "mean real: %.3f s\n", sum / n
        printf "max real: %.3f s\n", max
        if (rss > 0)
            printf "max RSS: %.1f MiB\n", rss / 1024 / 1024
    }
' "$TMP"
