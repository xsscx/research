#!/bin/bash
#
# ramdisk-clean.sh — Remove stray files/dirs from the fuzzing ramdisk
#
# Usage:
#   .github/scripts/ramdisk-clean.sh              # dry-run (default)
#   .github/scripts/ramdisk-clean.sh --execute     # actually delete
#   .github/scripts/ramdisk-clean.sh --execute /tmp/fuzz-ramdisk
#
# Removes:
#   - Stray corpus dirs not matching any of the 18 fuzzers
#   - Stray non-corpus dirs (latest/, updated/, tmp/, etc.)
#   - Loose artifacts (crash-*, oom-*, timeout-*, slow-unit-*, leak-*)
#     → saved to cfl/findings/ before deletion
#   - Stray files (binaries, source, dicts left on ramdisk root)
#
# Safe by default: runs in dry-run mode unless --execute is passed.

set -euo pipefail

die() { echo "[FAIL] ERROR: $*" >&2; exit 1; }

# ── Parse args ───────────────────────────────────────────────────────
DRY_RUN=true
RAMDISK="/tmp/fuzz-ramdisk"

for arg in "$@"; do
  case "$arg" in
    --execute) DRY_RUN=false ;;
    --dry-run) DRY_RUN=true ;;
    /*) RAMDISK="$arg" ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CFL_DIR="$REPO_ROOT/cfl"
FINDINGS_DIR="$CFL_DIR/findings"

[ -d "$RAMDISK" ] || die "Ramdisk directory not found: $RAMDISK"

if $DRY_RUN; then
  echo "[INFO] DRY RUN — showing what would be removed (pass --execute to apply)"
else
  echo "[INFO] EXECUTING — removing stray items from $RAMDISK"
fi
echo ""

# Canonical fuzzer names
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
  icc_spectral_fuzzer
  icc_tiffdump_fuzzer
  icc_toxml_fuzzer
  icc_v5dspobs_fuzzer
)

is_legit_corpus() {
  local name="$1"
  for f in "${ALL_FUZZERS[@]}"; do
    [ "corpus-${f}" = "$name" ] && return 0
  done
  return 1
}

REMOVED_DIRS=0
REMOVED_FILES=0
SAVED_ARTIFACTS=0

# ── 1. Save loose artifacts to findings/ ─────────────────────────────
echo "── Saving artifacts to cfl/findings/ ────────────────────────────"
ARTIFACT_PATTERNS=( 'crash-*' 'oom-*' 'timeout-*' 'slow-unit-*' 'leak-*' )
for pattern in "${ARTIFACT_PATTERNS[@]}"; do
  while IFS= read -r -d '' file; do
    name=$(basename "$file")
    if $DRY_RUN; then
      echo "  [save] $name"
    else
      mkdir -p "$FINDINGS_DIR"
      cp -n "$file" "$FINDINGS_DIR/" 2>/dev/null || true
    fi
    SAVED_ARTIFACTS=$((SAVED_ARTIFACTS + 1))
  done < <(find "$RAMDISK" -maxdepth 1 -name "$pattern" -type f -print0 2>/dev/null)
done
# Also save latest*/updated* prefixed artifacts
for pattern in 'latest*' 'updated*'; do
  while IFS= read -r -d '' file; do
    [ -f "$file" ] || continue
    name=$(basename "$file")
    if $DRY_RUN; then
      echo "  [save] $name"
    else
      mkdir -p "$FINDINGS_DIR"
      cp -n "$file" "$FINDINGS_DIR/" 2>/dev/null || true
    fi
    SAVED_ARTIFACTS=$((SAVED_ARTIFACTS + 1))
  done < <(find "$RAMDISK" -maxdepth 1 -name "$pattern" -type f -print0 2>/dev/null)
done
[ "$SAVED_ARTIFACTS" -eq 0 ] && echo "  (none)"
echo ""

# ── 2. Remove loose artifacts from ramdisk ───────────────────────────
echo "── Removing loose artifacts from ramdisk root ───────────────────"
ARTIFACT_COUNT=0
for pattern in "${ARTIFACT_PATTERNS[@]}" 'latest*' 'updated*'; do
  while IFS= read -r -d '' file; do
    [ -f "$file" ] || continue
    name=$(basename "$file")
    if $DRY_RUN; then
      echo "  [rm] $name"
    else
      rm -f "$file"
    fi
    ARTIFACT_COUNT=$((ARTIFACT_COUNT + 1))
  done < <(find "$RAMDISK" -maxdepth 1 -name "$pattern" -print0 2>/dev/null)
done
[ "$ARTIFACT_COUNT" -eq 0 ] && echo "  (none)"
REMOVED_FILES=$((REMOVED_FILES + ARTIFACT_COUNT))
echo ""

# ── 3. Remove stray corpus directories ──────────────────────────────
echo "── Removing stray corpus directories ────────────────────────────"
for d in "$RAMDISK"/corpus-*; do
  [ -d "$d" ] || continue
  name=$(basename "$d")
  if ! is_legit_corpus "$name"; then
    count=$(find "$d" -type f 2>/dev/null | wc -l)
    size_h=$(du -sh "$d" 2>/dev/null | cut -f1)
    if $DRY_RUN; then
      echo "  [rm -rf] $name  ($count files, $size_h)"
    else
      rm -rf "$d"
      echo "  [OK] removed $name  ($count files, $size_h)"
    fi
    REMOVED_DIRS=$((REMOVED_DIRS + 1))
  fi
done
[ "$REMOVED_DIRS" -eq 0 ] && echo "  (none)"
echo ""

# ── 4. Remove stray non-corpus directories ──────────────────────────
echo "── Removing stray non-corpus directories ────────────────────────"
STRAY_DIR_COUNT=0
for d in "$RAMDISK"/*/; do
  [ -d "$d" ] || continue
  name=$(basename "$d")
  case "$name" in
    corpus-*|findings|profraw|merged-*) continue ;;
  esac
  count=$(find "$d" -type f 2>/dev/null | wc -l)
  size_h=$(du -sh "$d" 2>/dev/null | cut -f1)
  if $DRY_RUN; then
    echo "  [rm -rf] $name/  ($count files, $size_h)"
  else
    rm -rf "$d"
    echo "  [OK] removed $name/  ($count files, $size_h)"
  fi
  STRAY_DIR_COUNT=$((STRAY_DIR_COUNT + 1))
done
[ "$STRAY_DIR_COUNT" -eq 0 ] && echo "  (none)"
REMOVED_DIRS=$((REMOVED_DIRS + STRAY_DIR_COUNT))
echo ""

# ── 5. Remove stray files (binaries, source, dicts on root) ─────────
echo "── Removing stray files from ramdisk root ───────────────────────"
STRAY_FILE_COUNT=0
while IFS= read -r -d '' file; do
  name=$(basename "$file")
  # Skip artifacts (already handled above)
  case "$name" in
    crash-*|oom-*|timeout-*|slow-unit-*|leak-*|latest*|updated*) continue ;;
  esac
  size_h=$(ls -lh "$file" | awk '{print $5}')
  if $DRY_RUN; then
    echo "  [rm] $name  ($size_h)"
  else
    rm -f "$file"
    echo "  [OK] removed $name  ($size_h)"
  fi
  STRAY_FILE_COUNT=$((STRAY_FILE_COUNT + 1))
done < <(find "$RAMDISK" -maxdepth 1 -type f -print0 2>/dev/null)
[ "$STRAY_FILE_COUNT" -eq 0 ] && echo "  (none)"
REMOVED_FILES=$((REMOVED_FILES + STRAY_FILE_COUNT))
echo ""

# ── Summary ─────────────────────────────────────────────────────────
echo "── Summary ──────────────────────────────────────────────────────"
if $DRY_RUN; then
  echo "  Would save:   $SAVED_ARTIFACTS artifacts to cfl/findings/"
  echo "  Would remove: $REMOVED_DIRS directories, $REMOVED_FILES files"
  echo ""
  echo "  Re-run with --execute to apply."
else
  echo "  Saved:   $SAVED_ARTIFACTS artifacts to cfl/findings/"
  echo "  Removed: $REMOVED_DIRS directories, $REMOVED_FILES files"
  echo ""
  if mountpoint -q "$RAMDISK" 2>/dev/null; then
    echo "  Ramdisk: $(df -h "$RAMDISK" | tail -1 | awk '{print $4 " free"}')"
  fi
fi
echo ""
