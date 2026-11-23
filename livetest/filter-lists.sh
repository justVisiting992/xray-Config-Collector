#!/usr/bin/env bash
# filter-lists.sh — live-test the Collector's published lists in place.
#
# For each published list in the repo root, run the livetest CLI on it and
# replace the list with only the configs that carried real traffic, with
# remarks relabelled by true exit IP (handled inside the CLI when -out is
# set, using Country.mmdb).
#
# Usage: filter-lists.sh [path-to-livetest-binary]
#   Default binary: <repo-root>/livetest
#
# Failure policy: a tool failure on one file never aborts the run and never
# empties a list — the original file is kept and a warning is echoed.
# Safety guard: if a non-empty list yields 0 passing, that is treated
# as an environment failure (e.g. the runner cannot reach the proxies),
# not a true result — the original list is kept and a warning is echoed.
# An empty published list would also drop those configs from the
# history the next run re-tests, losing them permanently.
#
# Poison isolation: a single malformed config can panic the xray-core
# inside the tester (observed 2026-11-24: a VLESS XHTTP config killed
# the test of a 53,689-config mixed list). Large lists are therefore
# tested in chunks; when a chunk run fails, the chunk is split in half
# and retried, down to single configs — a poisonous config can then
# only ever take itself out, never the whole list.
#
# Reporting honesty: the script records per-list whether the published
# file is live-tested output ("filtered") or the kept original
# ("kept"), and the report.md rewrite below uses that record: kept
# lists are labelled "unfiltered" and never counted as live.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || { echo "ERROR: cannot cd to repo root $REPO_ROOT" >&2; exit 1; }

BIN="${1:-$REPO_ROOT/livetest}"
if [[ ! -x "$BIN" ]]; then
    echo "ERROR: livetest binary not found or not executable: $BIN" >&2
    exit 1
fi

LISTS=(vless_iran.txt vmess_iran.txt trojan_iran.txt ss_iran.txt hy2_iran.txt mixed_iran.txt)
CHUNK_SIZE=1000

STATUS_FILE="$(mktemp)"
export FILTER_STATUS_FILE="$STATUS_FILE"
trap 'rm -f "$STATUS_FILE"' EXIT

count_lines() {
    # Number of non-empty lines in $1 (0 if missing).
    if [[ -f "$1" ]]; then
        grep -c . "$1" || true
    else
        echo 0
    fi
}

# process_chunk <chunk-file> <merged-out>
# Runs the tester on one chunk and appends its passing configs to the
# merged output. On failure the chunk is split in half and each half is
# processed recursively; a failing single config is dropped with a
# warning (it is the poison this isolation exists for). Always returns
# 0: per-config failures must never abort the list.
process_chunk() {
    local chunk="$1" merged="$2"
    local n out
    n="$(count_lines "$chunk")"
    out="$chunk.out"
    rm -f "$out"
    if "$BIN" -files "$chunk" -geo-db Country.mmdb -concurrency 200 -timeout 6s -out "$out"; then
        if [[ -f "$out" ]]; then
            cat "$out" >> "$merged"
            rm -f "$out"
        fi
        return 0
    fi
    if [[ "$n" -le 1 ]]; then
        echo "WARNING: dropping 1 unprocessable config (livetest failed on it): $(head -c 120 "$chunk")" >&2
        return 0
    fi
    echo "WARNING: livetest failed on a chunk of $n configs; splitting to isolate the failure" >&2
    local half=$(( (n + 1) / 2 )) d p
    d="$(mktemp -d)"
    split -l "$half" "$chunk" "$d/part-"
    for p in "$d"/part-*; do
        process_chunk "$p" "$merged"
    done
    rm -rf "$d"
    return 0
}

# test_one_list <file> <tmp-out>
# Fills tmp-out with the live-tested replacement for file. Returns 0
# when the file was fully processed (tmp-out may still be empty — the
# caller applies the 0-passing guard), 1 when processing itself failed
# and the original must be kept.
test_one_list() {
    local f="$1" tmp="$2"
    local before
    before="$(count_lines "$f")"
    if [[ "$before" -le "$CHUNK_SIZE" ]]; then
        "$BIN" -files "$f" -geo-db Country.mmdb -concurrency 200 -timeout 6s -out "$tmp"
        return $?
    fi
    echo "info: $f has $before configs; testing in chunks of $CHUNK_SIZE"
    local d
    d="$(mktemp -d)"
    split -l "$CHUNK_SIZE" "$f" "$d/chunk-"
    : > "$tmp"
    local c
    for c in "$d"/chunk-*; do
        process_chunk "$c" "$tmp"
    done
    rm -rf "$d"
    # Chunks are labelled and numbered independently; a remark can
    # repeat across chunk boundaries. One final numbering pass over
    # the merged file restores the uniqueness guarantee.
    if [[ -s "$tmp" ]]; then
        "$BIN" -renumber "$tmp" || echo "WARNING: renumber pass failed for $f; chunk numbering kept" >&2
    fi
    return 0
}

echo "filter-lists: binary=$BIN root=$REPO_ROOT"
total_before=0
total_after=0

for f in "${LISTS[@]}"; do
    if [[ ! -s "$f" ]]; then
        echo "skip: $f (missing or empty)"
        continue
    fi

    before="$(count_lines "$f")"
    tmp="$f.livetmp"
    rm -f "$tmp"

    if test_one_list "$f" "$tmp"; then
        if [[ -f "$tmp" ]]; then
            after="$(count_lines "$tmp")"
            if [[ "$after" -eq 0 && "$before" -ge 1 ]]; then
                echo "WARNING: $f — 0 of $before passed; treating as environment failure, original kept" >&2
                echo "$f kept" >> "$STATUS_FILE"
                rm -f "$tmp"
                total_before=$((total_before + before))
                total_after=$((total_after + before))
                continue
            fi
            mv "$tmp" "$f"
            echo "$f filtered" >> "$STATUS_FILE"
            echo "done: $f $before -> $after"
            total_before=$((total_before + before))
            total_after=$((total_after + after))
        else
            echo "WARNING: $f — tool succeeded but produced no output file; original kept ($before lines)" >&2
            echo "$f kept" >> "$STATUS_FILE"
            total_before=$((total_before + before))
            total_after=$((total_after + before))
        fi
    else
        rc=$?
        echo "WARNING: $f — livetest failed (exit $rc); original kept ($before lines)" >&2
        echo "$f kept" >> "$STATUS_FILE"
        rm -f "$tmp"
        total_before=$((total_before + before))
        total_after=$((total_after + before))
    fi
done

echo "filter-lists summary: $total_before -> $total_after configs across ${#LISTS[@]} lists"

# report.md is generated by main.go BEFORE this filtering step, so its
# "live" counts describe the old TCP test, not what was actually
# published. Rewrite those numbers from the final list files so the
# committed report matches the committed lists — but honestly: a list
# whose original was kept (see the status record) is reported as
# "unfiltered", and Total Alive counts only configs that actually
# passed the live test. "found" counts are harvest statistics and are
# left untouched. Best-effort: any failure here only leaves the
# original report in place.
if [[ -f report.md ]] && command -v python3 >/dev/null 2>&1; then
    if ! python3 - <<'PYEOF'
import os
import re

status = {}
try:
    with open(os.environ["FILTER_STATUS_FILE"], encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2:
                status[parts[0]] = parts[1]
except (OSError, KeyError):
    status = {}

def line_count(fname):
    try:
        with open(fname, encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return None

proto_files = {
    "VLess": "vless_iran.txt",
    "VMess": "vmess_iran.txt",
    "Trojan": "trojan_iran.txt",
    "SS": "ss_iran.txt",
    "Hy2": "hy2_iran.txt",
}
counts = {p: line_count(fn) for p, fn in proto_files.items()}
mixed_count = line_count("mixed_iran.txt")
mixed_filtered = status.get("mixed_iran.txt") == "filtered"

with open("report.md", encoding="utf-8") as f:
    report = f.read()

def fix_proto(m):
    proto = m.group(1)
    n = counts.get(proto)
    if n is None:
        return m.group(0)
    if status.get(proto_files[proto]) == "kept":
        return f"**{proto}:** {m.group(2)} found ({n} unfiltered — live test unavailable)"
    return f"**{proto}:** {m.group(2)} found ({n} live)"

report = re.sub(r"\*\*(VLess|VMess|Trojan|SS|Hy2):\*\* (\d+) found \(\d+ live\)", fix_proto, report)

# Total Alive = configs verified live. When the mixed list itself was
# live-tested, its count is the total (it is the union of the protocol
# lists). When it was kept unfiltered, fall back to the sum of the
# protocol lists that were actually filtered.
if mixed_filtered and mixed_count is not None:
    total_alive = mixed_count
elif not mixed_filtered:
    total_alive = sum(
        n for p, n in counts.items()
        if n is not None and status.get(proto_files[p]) == "filtered"
    )
else:
    total_alive = None
if total_alive is not None:
    report = re.sub(r"(\*\*Total Alive:\*\* `)\d+(`)", rf"\g<1>{total_alive}\g<2>", report)

with open("report.md", "w", encoding="utf-8") as f:
    f.write(report)
print("report.md live counts updated from published lists")
PYEOF
    then
        echo "WARNING: report.md live-count update failed; original report kept" >&2
    fi
fi
