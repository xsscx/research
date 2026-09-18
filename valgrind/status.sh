#!/usr/bin/env bash
# Summarize one Valgrind evidence directory, or the newest local run.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
evidence_dir="${1:-}"
if [[ -z "$evidence_dir" ]]; then
    output_base="${VALGRIND_OUTPUT_DIR:-$REPO_ROOT/valgrind/output}"
    evidence_dir="$(find "$output_base" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null | sort -nr | sed -n '1s/^[^ ]* //p')"
fi
[[ -n "$evidence_dir" && -f "$evidence_dir/summary.tsv" ]] || { echo "No Valgrind summary found." >&2; exit 1; }

echo "Evidence: $evidence_dir"
column -t -s $'\t' "$evidence_dir/summary.tsv" 2>/dev/null || sed -n '1,200p' "$evidence_dir/summary.tsv"
