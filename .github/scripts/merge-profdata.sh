#!/bin/bash
#
# merge-profdata.sh — Merge LLVM profraw files into a single profdata file
#
# Usage:
#   merge-profdata.sh <profraw-dir> [output.profdata]
#   merge-profdata.sh cfl/profraw
#   merge-profdata.sh cfl/profraw cfl/merged.profdata
#
# Scans <profraw-dir> for *.profraw files and merges them with llvm-profdata.
# Default output: <profraw-dir>/../merged.profdata
#
# Environment:
#   LLVM_PROFDATA  — path to llvm-profdata (auto-detected if unset)

set -euo pipefail

die() { echo "[FAIL] ERROR: $*" >&2; exit 1; }

# --- Argument parsing ---
PROFRAW_DIR="${1:?Usage: merge-profdata.sh <profraw-dir> [output.profdata]}"
[ -d "$PROFRAW_DIR" ] || die "Directory not found: $PROFRAW_DIR"

OUTPUT="${2:-$(dirname "$PROFRAW_DIR")/merged.profdata}"

# --- Locate llvm-profdata ---
if [ -z "${LLVM_PROFDATA:-}" ]; then
  for candidate in llvm-profdata llvm-profdata-{18,17,16,15,14}; do
    if command -v "$candidate" &>/dev/null; then
      LLVM_PROFDATA="$candidate"
      break
    fi
  done
fi
[ -n "${LLVM_PROFDATA:-}" ] || die "llvm-profdata not found. Install LLVM or set LLVM_PROFDATA env var."

# --- Collect profraw files ---
PROFRAW_FILES=()
while IFS= read -r -d '' f; do
  PROFRAW_FILES+=("$f")
done < <(find "$PROFRAW_DIR" -name '*.profraw' -type f -print0 2>/dev/null)

if [ "${#PROFRAW_FILES[@]}" -eq 0 ]; then
  die "No .profraw files found in $PROFRAW_DIR"
fi

echo "Merging ${#PROFRAW_FILES[@]} profraw files from $PROFRAW_DIR"
echo "  Tool:   $($LLVM_PROFDATA --version 2>/dev/null | head -1 || echo "$LLVM_PROFDATA")"
echo "  Output: $OUTPUT"

# --- List files by fuzzer (group by name prefix) ---
declare -A FUZZER_COUNTS
for f in "${PROFRAW_FILES[@]}"; do
  basename_f="$(basename "$f")"
  # Extract fuzzer name: everything before the first dash-followed-by-digits
  fuzzer_name="${basename_f%%-[0-9]*}"
  FUZZER_COUNTS["$fuzzer_name"]=$(( ${FUZZER_COUNTS["$fuzzer_name"]:-0} + 1 ))
done

echo ""
echo "  Files per fuzzer:"
for name in $(echo "${!FUZZER_COUNTS[@]}" | tr ' ' '\n' | sort); do
  printf "    %-40s %d\n" "$name" "${FUZZER_COUNTS[$name]}"
done

# --- Merge ---
echo ""
"$LLVM_PROFDATA" merge -sparse "${PROFRAW_FILES[@]}" -o "$OUTPUT" 2>&1

SIZE=$(ls -lh "$OUTPUT" | awk '{print $5}')
echo "[OK] Merged profdata: $OUTPUT ($SIZE)"
echo ""
echo "Next: generate-coverage-report.sh $OUTPUT <output-dir> [binary...]"
