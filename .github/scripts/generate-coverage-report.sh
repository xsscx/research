#!/bin/bash
#
# generate-coverage-report.sh — Generate text + HTML coverage reports from profdata
#
# Usage:
#   generate-coverage-report.sh <profdata-file> <output-dir> [binary...]
#   generate-coverage-report.sh merged.profdata coverage-report
#   generate-coverage-report.sh merged.profdata coverage-report cfl/bin/icc_profile_fuzzer
#
# If no binaries are specified, auto-discovers all fuzzer binaries in cfl/bin/.
#
# Outputs:
#   <output-dir>/coverage-report.txt   — text summary (llvm-cov report)
#   <output-dir>/html/                 — interactive HTML report (llvm-cov show)
#
# Environment:
#   LLVM_COV       — path to llvm-cov (auto-detected if unset)
#   LLVM_PROFDATA  — path to llvm-profdata (for validation, auto-detected)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

die() { echo "[FAIL] ERROR: $*" >&2; exit 1; }

# --- Argument parsing ---
PROFDATA="${1:?Usage: generate-coverage-report.sh <profdata-file> <output-dir> [binary...]}"
OUTPUT_DIR="${2:?Usage: generate-coverage-report.sh <profdata-file> <output-dir> [binary...]}"
shift 2
BINARIES=("$@")

[ -f "$PROFDATA" ] || die "Profdata file not found: $PROFDATA"

# --- Locate llvm-cov ---
if [ -z "${LLVM_COV:-}" ]; then
  for candidate in llvm-cov llvm-cov-{18,17,16,15,14}; do
    if command -v "$candidate" &>/dev/null; then
      LLVM_COV="$candidate"
      break
    fi
  done
fi
[ -n "${LLVM_COV:-}" ] || die "llvm-cov not found. Install LLVM or set LLVM_COV env var."

# --- Auto-discover binaries ---
if [ "${#BINARIES[@]}" -eq 0 ]; then
  CFL_BIN="$REPO_ROOT/cfl/bin"
  if [ -d "$CFL_BIN" ]; then
    while IFS= read -r -d '' b; do
      BINARIES+=("$b")
    done < <(find "$CFL_BIN" -maxdepth 1 -type f -executable -name 'icc_*' -print0 2>/dev/null)
  fi
fi

if [ "${#BINARIES[@]}" -eq 0 ]; then
  die "No binaries specified and none found in $REPO_ROOT/cfl/bin/"
fi

# Build -object flags for llvm-cov
OBJECT_FLAGS=()
for b in "${BINARIES[@]}"; do
  [ -f "$b" ] || die "Binary not found: $b"
  OBJECT_FLAGS+=("-object" "$b")
done

echo "════════════════════════════════════════"
echo "  Coverage Report Generator"
echo "════════════════════════════════════════"
echo "  Profdata: $PROFDATA"
echo "  Binaries: ${#BINARIES[@]}"
echo "  Output:   $OUTPUT_DIR"
echo "  Tool:     $($LLVM_COV --version 2>/dev/null | head -1 || echo "$LLVM_COV")"
echo ""

mkdir -p "$OUTPUT_DIR"

# --- Text report ---
echo "Generating text report..."
"$LLVM_COV" report "${OBJECT_FLAGS[@]}" \
  -instr-profile="$PROFDATA" \
  > "$OUTPUT_DIR/coverage-report.txt" 2>&1

LINES=$(wc -l < "$OUTPUT_DIR/coverage-report.txt")
echo "  [OK] $OUTPUT_DIR/coverage-report.txt ($LINES lines)"

# Extract and display summary line
SUMMARY=$(tail -1 "$OUTPUT_DIR/coverage-report.txt" | grep -oP 'TOTAL.*' || true)
if [ -n "$SUMMARY" ]; then
  echo ""
  echo "  $SUMMARY"
  echo ""
fi

# --- HTML report ---
echo "Generating HTML report..."
"$LLVM_COV" show "${OBJECT_FLAGS[@]}" \
  -instr-profile="$PROFDATA" \
  -format=html \
  -output-dir="$OUTPUT_DIR/html" \
  -show-line-counts-or-regions \
  -show-expansions \
  2>&1

HTML_COUNT=$(find "$OUTPUT_DIR/html" -name '*.html' 2>/dev/null | wc -l)
HTML_SIZE=$(du -sh "$OUTPUT_DIR/html" 2>/dev/null | cut -f1)
echo "  [OK] $OUTPUT_DIR/html/ ($HTML_COUNT HTML files, $HTML_SIZE)"

echo ""
echo "════════════════════════════════════════"
echo "  Reports ready"
echo "════════════════════════════════════════"
echo "  Text:  $OUTPUT_DIR/coverage-report.txt"
echo "  HTML:  $OUTPUT_DIR/html/index.html"
echo ""
echo "  View:  open $OUTPUT_DIR/html/index.html"
