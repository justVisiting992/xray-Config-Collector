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
# Safety guard: if a list of 10+ configs yields 0 passing, that is treated
# as an environment failure (e.g. the runner cannot reach the proxies),
# not a true result — the original list is kept and a warning is echoed.
# Freshly scraped, TCP-verified lists never legitimately score exactly 0.

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

count_lines() {
    # Number of non-empty lines in $1 (0 if missing).
    if [[ -f "$1" ]]; then
        grep -c . "$1" || true
    else
        echo 0
    fi
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

    if "$BIN" -files "$f" -geo-db Country.mmdb -concurrency 200 -timeout 6s -out "$tmp"; then
        if [[ -f "$tmp" ]]; then
            after="$(count_lines "$tmp")"
            if [[ "$after" -eq 0 && "$before" -ge 10 ]]; then
                echo "WARNING: $f — 0 of $before passed; treating as environment failure, original kept" >&2
                rm -f "$tmp"
                total_before=$((total_before + before))
                total_after=$((total_after + before))
                continue
            fi
            mv "$tmp" "$f"
            echo "done: $f $before -> $after"
            total_before=$((total_before + before))
            total_after=$((total_after + after))
        else
            echo "WARNING: $f — tool succeeded but produced no output file; original kept ($before lines)" >&2
            total_before=$((total_before + before))
            total_after=$((total_after + before))
        fi
    else
        rc=$?
        echo "WARNING: $f — livetest failed (exit $rc); original kept ($before lines)" >&2
        rm -f "$tmp"
        total_before=$((total_before + before))
        total_after=$((total_after + before))
    fi
done

echo "filter-lists summary: $total_before -> $total_after configs across ${#LISTS[@]} lists"
