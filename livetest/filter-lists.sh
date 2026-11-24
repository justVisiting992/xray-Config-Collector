#!/usr/bin/env bash
# filter-lists.sh — live-test the Collector's published lists in place.
#
# Unified verified pool: the mixed list holds every config that passed
# the Collector's first (TCP) test, uncapped. It is live-tested first,
# and each protocol list is then DERIVED from the verified mixed file —
# its own protocol's lines, first 200, renumbered. A config therefore
# reaches a protocol list only by passing the same real-traffic test
# as the mixed list, and every verified config is eligible for its
# protocol list (previously the 200 cap was applied BEFORE the real
# test, so thousands of verified configs never reached their list).
#
# Fallback: if the mixed test itself fails or passes 0 (treated as an
# environment failure), the original mixed list is kept and each
# protocol list is live-tested independently, as before.
#
# Usage: filter-lists.sh [path-to-livetest-binary]
#   Default binary: <repo-root>/livetest
#
# Failure policy: a tool failure never aborts the run and never
# empties a list on the independent path — the original file is kept
# and a warning is echoed. Safety guard: a non-empty list yielding 0
# passing is treated as an environment failure, not a true result.
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
# ("kept"), plus the mode ("derived" / "independent"), and the
# report.md rewrite below uses that record: kept lists are labelled
# "unfiltered", and in derived mode the per-protocol live counts are
# the verified totals inside the mixed list, so they sum exactly to
# Total Alive.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT" || { echo "ERROR: cannot cd to repo root $REPO_ROOT" >&2; exit 1; }

BIN="${1:-$REPO_ROOT/livetest}"
if [[ ! -x "$BIN" ]]; then
    echo "ERROR: livetest binary not found or not executable: $BIN" >&2
    exit 1
fi

PROTO_LISTS=(vless_iran.txt vmess_iran.txt trojan_iran.txt ss_iran.txt hy2_iran.txt)
MIXED_LIST=mixed_iran.txt
CHUNK_SIZE=1000
LIST_CAP=200

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

record_status() {
    echo "$1 $2" >> "$STATUS_FILE"
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

# filter_independent <file>
# Live-tests one list on its own (the fallback path). Records the
# outcome in the status file. Returns 0 when the published file is
# live-tested output, 1 when the original was kept (or file skipped).
filter_independent() {
    local f="$1"
    if [[ ! -s "$f" ]]; then
        echo "skip: $f (missing or empty)"
        return 1
    fi
    local before tmp after rc
    before="$(count_lines "$f")"
    tmp="$f.livetmp"
    rm -f "$tmp"
    test_one_list "$f" "$tmp"
    rc=$?
    if [[ $rc -eq 0 ]]; then
        if [[ -f "$tmp" ]]; then
            after="$(count_lines "$tmp")"
            if [[ "$after" -eq 0 && "$before" -ge 1 ]]; then
                echo "WARNING: $f — 0 of $before passed; treating as environment failure, original kept" >&2
                record_status "$f" kept
                rm -f "$tmp"
                return 1
            fi
            mv "$tmp" "$f"
            record_status "$f" filtered
            echo "done: $f $before -> $after"
            return 0
        fi
        echo "WARNING: $f — tool succeeded but produced no output file; original kept ($before lines)" >&2
        record_status "$f" kept
        return 1
    fi
    echo "WARNING: $f — livetest failed (exit $rc); original kept ($before lines)" >&2
    record_status "$f" kept
    rm -f "$tmp"
    return 1
}

# derive_protocol_lists <verified-mixed-file>
# Builds each protocol list from the verified mixed pool: the
# protocol's own lines, in pool order (the pool is shuffled by the
# tester, so the cap takes a random sample of the verified configs),
# capped at LIST_CAP, remarks renumbered within the list. Every
# derived config has passed the real-traffic test.
derive_protocol_lists() {
    local mixed="$1"
    local spec file pattern tmp n total
    for spec in \
        "vless_iran.txt|^vless://" \
        "vmess_iran.txt|^vmess://" \
        "trojan_iran.txt|^trojan://" \
        "ss_iran.txt|^ss://" \
        "hy2_iran.txt|^(hy2|hysteria2)://"
    do
        file="${spec%%|*}"
        pattern="${spec#*|}"
        tmp="$file.livetmp"
        rm -f "$tmp"
        total="$(grep -ciE "$pattern" "$mixed" || true)"
        grep -iE "$pattern" "$mixed" | head -n "$LIST_CAP" > "$tmp" || true
        n="$(count_lines "$tmp")"
        if [[ "$n" -eq 0 ]]; then
            echo "WARNING: $file — 0 verified configs in the mixed pool; publishing an empty list" >&2
        elif ! "$BIN" -renumber "$tmp"; then
            echo "WARNING: renumber pass failed for $file; pool numbering kept" >&2
        fi
        mv "$tmp" "$file"
        record_status "$file" filtered
        echo "done: $file derived $n of $total verified from the mixed pool (cap $LIST_CAP)"
    done
}

echo "filter-lists: binary=$BIN root=$REPO_ROOT"
total_before=0
for f in "${PROTO_LISTS[@]}" "$MIXED_LIST"; do
    total_before=$((total_before + $(count_lines "$f")))
done

# Step 1: live-test the full uncapped pool.
if filter_independent "$MIXED_LIST"; then
    # Step 2a: derive every protocol list from the one verified pool.
    echo "mode derived" >> "$STATUS_FILE"
    derive_protocol_lists "$MIXED_LIST"
else
    # Step 2b: mixed could not be verified — test each protocol list
    # on its own, as before.
    echo "mode independent" >> "$STATUS_FILE"
    for f in "${PROTO_LISTS[@]}"; do
        filter_independent "$f"
    done
fi

total_after=0
for f in "${PROTO_LISTS[@]}" "$MIXED_LIST"; do
    total_after=$((total_after + $(count_lines "$f")))
done
echo "filter-lists summary: $total_before -> $total_after configs across 6 lists"

# report.md is generated by main.go BEFORE this filtering step, so its
# "live" counts describe the old TCP test, not what was actually
# published. Rewrite those numbers from the final list files so the
# committed report matches the committed lists — honestly:
#  - derived mode: per-protocol live = that protocol's verified total
#    inside the mixed list (the parts sum exactly to Total Alive),
#    and a note explains the 200 cap on the protocol lists;
#  - independent mode: per-protocol live = the protocol list's own
#    count when it was filtered; a kept list is reported as
#    "unfiltered" and never counted as live.
# "found" counts are harvest statistics and are left untouched.
# Best-effort: any failure here only leaves the original report.
if [[ -f report.md ]] && command -v python3 >/dev/null 2>&1; then
    if ! python3 - <<'PYEOF'
import os
import re

status = {}
mode = "independent"
try:
    with open(os.environ["FILTER_STATUS_FILE"], encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2:
                if parts[0] == "mode":
                    mode = parts[1]
                else:
                    status[parts[0]] = parts[1]
except (OSError, KeyError):
    pass

def read_lines(fname):
    try:
        with open(fname, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError:
        return None

proto_files = {
    "VLess": "vless_iran.txt",
    "VMess": "vmess_iran.txt",
    "Trojan": "trojan_iran.txt",
    "SS": "ss_iran.txt",
    "Hy2": "hy2_iran.txt",
}
proto_schemes = {
    "VLess": ("vless://",),
    "VMess": ("vmess://",),
    "Trojan": ("trojan://",),
    "SS": ("ss://",),
    "Hy2": ("hy2://", "hysteria2://"),
}
counts = {}
for p, fn in proto_files.items():
    lines = read_lines(fn)
    counts[p] = None if lines is None else len(lines)
mixed_lines = read_lines("mixed_iran.txt")
mixed_count = None if mixed_lines is None else len(mixed_lines)
mixed_filtered = status.get("mixed_iran.txt") == "filtered"

with open("report.md", encoding="utf-8") as f:
    report = f.read()

if mode == "derived" and mixed_filtered and mixed_lines is not None:
    # Per-protocol live = verified totals inside the mixed pool.
    mixed_counts = {
        p: sum(1 for line in mixed_lines if line.lower().startswith(schemes))
        for p, schemes in proto_schemes.items()
    }

    def fix_proto_derived(m):
        proto = m.group(1)
        return f"**{proto}:** {m.group(2)} found ({mixed_counts[proto]} live)"

    report = re.sub(r"\*\*(VLess|VMess|Trojan|SS|Hy2):\*\* (\d+) found \(\d+ live\)", fix_proto_derived, report)
    report = re.sub(r"(\*\*Total Alive:\*\* `)\d+(`)", rf"\g<1>{mixed_count}\g<2>", report)
    note = "\n> ℹ️ Live counts are verified totals from the mixed pool; each protocol list holds a random 200 of its verified configs (list order is shuffled, not ranked)."
    report = re.sub(r"(\*\*Total Alive:\*\* `\d+`[^\n]*)", r"\g<1>" + note, report, count=1)
else:
    def fix_proto(m):
        proto = m.group(1)
        n = counts.get(proto)
        if n is None:
            return m.group(0)
        if status.get(proto_files[proto]) == "kept":
            return f"**{proto}:** {m.group(2)} found ({n} unfiltered — live test unavailable)"
        return f"**{proto}:** {m.group(2)} found ({n} live)"

    report = re.sub(r"\*\*(VLess|VMess|Trojan|SS|Hy2):\*\* (\d+) found \(\d+ live\)", fix_proto, report)

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
