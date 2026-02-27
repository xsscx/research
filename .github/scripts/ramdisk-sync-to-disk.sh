#!/bin/bash
#
# ramdisk-sync-to-disk.sh — Sync corpus from ramdisk to on-disk cfl/corpus-*
#
# Usage:
#   .github/scripts/ramdisk-sync-to-disk.sh              # sync all
#   .github/scripts/ramdisk-sync-to-disk.sh --dry-run    # show what would sync
#   .github/scripts/ramdisk-sync-to-disk.sh icc_profile_fuzzer icc_io_fuzzer
#
# Copies ramdisk corpus → cfl/corpus-<name>/ and saves crash artifacts
# to cfl/findings/. Does NOT unmount the ramdisk.

set -euo pipefail

die() { echo "[FAIL] ERROR: $*" >&2; exit 1; }

RAMDISK="/tmp/fuzz-ramdisk"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CFL_DIR="$REPO_ROOT/cfl"
DRY_RUN=false

ALL_FUZZERS=(
  icc_apply_fuzzer
  icc_applynamedcmm_fuzzer
  icc_applyprofiles_fuzzer
  icc_calculator_fuzzer
  icc_deep_dump_fuzzer
  icc_dump_fuzzer
  icc_fromcube_fuzzer
  icc_fromxml_fuzzer
  icc_io_fuzzer
  icc_link_fuzzer
  icc_multitag_fuzzer
  icc_profile_fuzzer
  icc_roundtrip_fuzzer
  icc_specsep_fuzzer
  # icc_spectral_fuzzer  # Variant A — disabled for A/B test
  icc_spectral_b_fuzzer
  icc_tiffdump_fuzzer
  icc_toxml_fuzzer
  icc_v5dspobs_fuzzer
)

# ── Parse args ───────────────────────────────────────────────────────
SELECTED_FUZZERS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=true ;;
    --ramdisk) RAMDISK="$2"; shift ;;
    icc_*) SELECTED_FUZZERS+=("$1") ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

FUZZERS=("${SELECTED_FUZZERS[@]:-${ALL_FUZZERS[@]}}")
[ -d "$RAMDISK" ] || die "Ramdisk not found: $RAMDISK"

RSYNC_FLAGS="-a --quiet"
$DRY_RUN && RSYNC_FLAGS="-a --dry-run --stats"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║               Sync Ramdisk → Disk                             ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
$DRY_RUN && echo "  [INFO] DRY RUN — showing what would sync"
echo ""

# ── Sync corpus directories ─────────────────────────────────────────
echo "── Corpus sync ──────────────────────────────────────────────────"
SYNCED=0
TOTAL_FILES=0
for f in "${FUZZERS[@]}"; do
  ram_corpus="$RAMDISK/corpus-${f}"
  disk_corpus="$CFL_DIR/corpus-${f}"

  if [ ! -d "$ram_corpus" ]; then
    continue
  fi

  count=$(find "$ram_corpus" -type f 2>/dev/null | wc -l)
  [ "$count" -eq 0 ] && continue

  size_h=$(du -sh "$ram_corpus" 2>/dev/null | cut -f1)

  if $DRY_RUN; then
    echo "  [sync] corpus-${f}  ($count files, $size_h) → $disk_corpus"
  else
    mkdir -p "$disk_corpus"
    rsync $RSYNC_FLAGS "$ram_corpus/" "$disk_corpus/"
    printf "  [OK] %-42s %6d files  %s\n" "$f" "$count" "$size_h"
  fi
  SYNCED=$((SYNCED + 1))
  TOTAL_FILES=$((TOTAL_FILES + count))
done
echo ""

# ── Save crash artifacts ────────────────────────────────────────────
echo "── Artifacts ────────────────────────────────────────────────────"
ARTIFACTS=0
for pattern in 'crash-*' 'oom-*' 'timeout-*' 'slow-unit-*' 'leak-*'; do
  while IFS= read -r -d '' file; do
    ARTIFACTS=$((ARTIFACTS + 1))
    if ! $DRY_RUN; then
      mkdir -p "$CFL_DIR/findings"
      cp -n "$file" "$CFL_DIR/findings/" 2>/dev/null || true
    fi
  done < <(find "$RAMDISK" -maxdepth 1 -name "$pattern" -type f -print0 2>/dev/null)
done

if [ "$ARTIFACTS" -gt 0 ]; then
  if $DRY_RUN; then
    echo "  [save] $ARTIFACTS artifacts → cfl/findings/"
  else
    echo "  [OK] $ARTIFACTS artifacts saved to cfl/findings/"
  fi
else
  echo "  (no artifacts)"
fi
echo ""

# ── Summary ─────────────────────────────────────────────────────────
echo "── Summary ──────────────────────────────────────────────────────"
echo "  Synced:    $SYNCED corpus dirs ($TOTAL_FILES total files)"
echo "  Artifacts: $ARTIFACTS"
if $DRY_RUN; then
  echo ""
  echo "  Re-run without --dry-run to apply."
fi
echo ""
