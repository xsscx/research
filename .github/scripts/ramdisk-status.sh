#!/bin/bash
#
# ramdisk-status.sh — Report ramdisk state and identify stray vs legit directories
#
# Usage:
#   .github/scripts/ramdisk-status.sh
#   .github/scripts/ramdisk-status.sh /tmp/fuzz-ramdisk
#
# Shows mount status, corpus sizes, stray directories, loose artifacts,
# and disk-side corpus state. Helps decide what to clean/merge/sync.

set -euo pipefail

RAMDISK="${1:-/tmp/fuzz-ramdisk}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CFL_DIR="$REPO_ROOT/cfl"

# Canonical fuzzer names
ALL_FUZZERS=(
  icc_apply_fuzzer
  icc_applynamedcmm_fuzzer
  icc_applyprofiles_fuzzer
  icc_calculator_fuzzer
  icc_deep_dump_fuzzer
  icc_dump_fuzzer
  icc_fromxml_fuzzer
  icc_io_fuzzer
  icc_link_fuzzer
  icc_multitag_fuzzer
  icc_profile_fuzzer
  icc_roundtrip_fuzzer
  icc_specsep_fuzzer
  icc_spectral_fuzzer
  icc_tiffdump_fuzzer
  icc_toxml_fuzzer
  icc_v5dspobs_fuzzer
)

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                  Ramdisk Status Report                         ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ── Mount status ─────────────────────────────────────────────────────
echo "── 1. MOUNT STATUS ──────────────────────────────────────────────"
if mountpoint -q "$RAMDISK" 2>/dev/null; then
  df -h "$RAMDISK"
  echo "  Status: MOUNTED (tmpfs)"
else
  if [ -d "$RAMDISK" ]; then
    echo "  Status: EXISTS but NOT mounted as tmpfs (plain directory)"
    du -sh "$RAMDISK" 2>/dev/null || true
  else
    echo "  Status: DOES NOT EXIST"
    echo ""
    echo "Nothing to report."
    exit 0
  fi
fi
echo ""

# ── Legit corpus directories ────────────────────────────────────────
echo "── 2. LEGITIMATE CORPUS DIRECTORIES ─────────────────────────────"
LEGIT_TOTAL_FILES=0
LEGIT_TOTAL_SIZE=0
for f in "${ALL_FUZZERS[@]}"; do
  d="$RAMDISK/corpus-${f}"
  if [ -d "$d" ]; then
    count=$(find "$d" -type f 2>/dev/null | wc -l)
    size=$(du -sb "$d" 2>/dev/null | cut -f1)
    size_h=$(du -sh "$d" 2>/dev/null | cut -f1)
    printf "  ✓ %-45s %6d files  %s\n" "corpus-${f}" "$count" "$size_h"
    LEGIT_TOTAL_FILES=$((LEGIT_TOTAL_FILES + count))
    LEGIT_TOTAL_SIZE=$((LEGIT_TOTAL_SIZE + size))
  else
    printf "  ○ %-45s (missing)\n" "corpus-${f}"
  fi
done
echo ""
echo "  Total legit corpus: $LEGIT_TOTAL_FILES files, $(numfmt --to=iec $LEGIT_TOTAL_SIZE 2>/dev/null || echo "${LEGIT_TOTAL_SIZE} bytes")"
echo ""

# ── Stray corpus directories ────────────────────────────────────────
echo "── 3. STRAY CORPUS DIRECTORIES (not matching any fuzzer) ────────"
STRAY_CORPUS=0
for d in "$RAMDISK"/corpus-*; do
  [ -d "$d" ] || continue
  name=$(basename "$d" | sed 's/^corpus-//')
  is_legit=false
  for f in "${ALL_FUZZERS[@]}"; do
    [ "$name" = "$f" ] && is_legit=true && break
  done
  if ! $is_legit; then
    count=$(find "$d" -type f 2>/dev/null | wc -l)
    size_h=$(du -sh "$d" 2>/dev/null | cut -f1)
    printf "  ⚠ %-45s %6d files  %s\n" "corpus-${name}" "$count" "$size_h"
    STRAY_CORPUS=$((STRAY_CORPUS + 1))
  fi
done
[ "$STRAY_CORPUS" -eq 0 ] && echo "  (none)"
echo ""

# ── Stray directories (non-corpus) ──────────────────────────────────
echo "── 4. STRAY DIRECTORIES (non-corpus) ────────────────────────────"
STRAY_DIRS=0
for d in "$RAMDISK"/*/; do
  [ -d "$d" ] || continue
  name=$(basename "$d")
  case "$name" in
    corpus-*|findings|profraw|merged-*) continue ;;
  esac
  count=$(find "$d" -type f 2>/dev/null | wc -l)
  size_h=$(du -sh "$d" 2>/dev/null | cut -f1)
  printf "  ⚠ %-45s %6d files  %s\n" "$name/" "$count" "$size_h"
  STRAY_DIRS=$((STRAY_DIRS + 1))
done
[ "$STRAY_DIRS" -eq 0 ] && echo "  (none)"
echo ""

# ── Loose artifacts ─────────────────────────────────────────────────
echo "── 5. LOOSE ARTIFACTS (ramdisk root) ────────────────────────────"
CRASH_N=$(find "$RAMDISK" -maxdepth 1 -name 'crash-*' -type f 2>/dev/null | wc -l)
OOM_N=$(find "$RAMDISK" -maxdepth 1 -name 'oom-*' -type f 2>/dev/null | wc -l)
TIMEOUT_N=$(find "$RAMDISK" -maxdepth 1 -name 'timeout-*' -type f 2>/dev/null | wc -l)
SLOW_N=$(find "$RAMDISK" -maxdepth 1 -name 'slow-unit-*' -type f 2>/dev/null | wc -l)
LEAK_N=$(find "$RAMDISK" -maxdepth 1 -name 'leak-*' -type f 2>/dev/null | wc -l)
LATEST_N=$(find "$RAMDISK" -maxdepth 1 -name 'latest*' -type f 2>/dev/null | wc -l)
UPDATED_N=$(find "$RAMDISK" -maxdepth 1 -name 'updated*' -type f 2>/dev/null | wc -l)

printf "  crash-*:     %4d\n" "$CRASH_N"
printf "  oom-*:       %4d\n" "$OOM_N"
printf "  timeout-*:   %4d\n" "$TIMEOUT_N"
printf "  slow-unit-*: %4d\n" "$SLOW_N"
printf "  leak-*:      %4d\n" "$LEAK_N"
printf "  latest*:     %4d  (stale libfuzzer prefixed artifacts)\n" "$LATEST_N"
printf "  updated*:    %4d  (stale libfuzzer prefixed artifacts)\n" "$UPDATED_N"
echo ""

# ── Stray files (non-artifact, non-directory) ───────────────────────
echo "── 6. OTHER STRAY FILES ─────────────────────────────────────────"
STRAY_FILES=0
while IFS= read -r -d '' file; do
  name=$(basename "$file")
  case "$name" in
    crash-*|oom-*|timeout-*|slow-unit-*|leak-*|latest*|updated*) continue ;;
  esac
  size_h=$(ls -lh "$file" | awk '{print $5}')
  printf "  ⚠ %-50s %s\n" "$name" "$size_h"
  STRAY_FILES=$((STRAY_FILES + 1))
done < <(find "$RAMDISK" -maxdepth 1 -type f -print0 2>/dev/null)
[ "$STRAY_FILES" -eq 0 ] && echo "  (none)"
echo ""

# ── On-disk corpus state ────────────────────────────────────────────
echo "── 7. ON-DISK CORPUS (cfl/corpus-*) ─────────────────────────────"
DISK_ANY=false
for d in "$CFL_DIR"/corpus-*; do
  [ -d "$d" ] || continue
  DISK_ANY=true
  count=$(find "$d" -type f 2>/dev/null | wc -l)
  size_h=$(du -sh "$d" 2>/dev/null | cut -f1)
  printf "  %-45s %6d files  %s\n" "$(basename "$d")" "$count" "$size_h"
done
$DISK_ANY || echo "  (none — ramdisk corpus has NOT been synced to disk)"
echo ""

# ── Summary ─────────────────────────────────────────────────────────
echo "── SUMMARY ──────────────────────────────────────────────────────"
TOTAL_ARTIFACTS=$((CRASH_N + OOM_N + TIMEOUT_N + SLOW_N + LEAK_N + LATEST_N + UPDATED_N))
echo "  Legit corpus dirs:  ${#ALL_FUZZERS[@]} expected, $(ls -d "$RAMDISK"/corpus-icc_* 2>/dev/null | wc -l) found"
echo "  Stray corpus dirs:  $STRAY_CORPUS"
echo "  Stray other dirs:   $STRAY_DIRS"
echo "  Loose artifacts:    $TOTAL_ARTIFACTS"
echo "  Stray files:        $STRAY_FILES"
echo ""

if [ "$STRAY_CORPUS" -gt 0 ] || [ "$STRAY_DIRS" -gt 0 ] || [ "$TOTAL_ARTIFACTS" -gt 0 ] || [ "$STRAY_FILES" -gt 0 ]; then
  echo "  → Run:  .github/scripts/ramdisk-clean.sh       # remove stray items"
fi
if ! $DISK_ANY; then
  echo "  → Run:  .github/scripts/ramdisk-sync-to-disk.sh # sync corpus to disk"
fi
echo "  → Run:  .github/scripts/ramdisk-merge.sh        # deduplicate corpus"
echo ""
