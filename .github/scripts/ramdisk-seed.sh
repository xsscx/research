#!/bin/bash
#
# ramdisk-seed.sh — Seed corpus from disk to ramdisk
#
# Usage:
#   .github/scripts/ramdisk-seed.sh                    # seed all 17 fuzzers
#   .github/scripts/ramdisk-seed.sh icc_profile_fuzzer # seed one fuzzer
#   .github/scripts/ramdisk-seed.sh --mount            # mount ramdisk first
#   .github/scripts/ramdisk-seed.sh --mount --size 8G  # custom size
#
# Seeds ramdisk corpus dirs from:
#   1. cfl/<fuzzer>_seed_corpus/      (hand-curated seeds)
#   2. cfl/corpus-<fuzzer>/           (on-disk grown corpus)
#   3. test-profiles/                 (shared ICC test profiles)
#   4. extended-test-profiles/        (additional profiles)
#
# If --mount is passed, mounts a tmpfs ramdisk first (requires root).

set -euo pipefail

die() { echo "[FAIL] ERROR: $*" >&2; exit 1; }

RAMDISK="/tmp/fuzz-ramdisk"
RAMDISK_SIZE="4G"
DO_MOUNT=false
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CFL_DIR="$REPO_ROOT/cfl"

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

# ── Parse args ───────────────────────────────────────────────────────
SELECTED_FUZZERS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --mount) DO_MOUNT=true; shift ;;
    --size) RAMDISK_SIZE="${2:?--size requires a value}"; shift 2 ;;
    --ramdisk) RAMDISK="${2:?--ramdisk requires a path}"; shift 2 ;;
    icc_*) SELECTED_FUZZERS+=("$1"); shift ;;
    *) die "Unknown argument: $1" ;;
  esac
done

FUZZERS=("${SELECTED_FUZZERS[@]:-${ALL_FUZZERS[@]}}")

# ── Mount if requested ──────────────────────────────────────────────
if $DO_MOUNT; then
  if mountpoint -q "$RAMDISK" 2>/dev/null; then
    echo "  Ramdisk already mounted at $RAMDISK"
  else
    [ "$(id -u)" -eq 0 ] || die "Root required to mount tmpfs. Run with sudo."
    echo "  Mounting ${RAMDISK_SIZE} tmpfs at $RAMDISK"
    mkdir -p "$RAMDISK"
    mount -t tmpfs -o "size=$RAMDISK_SIZE,noatime,nodev,nosuid" tmpfs "$RAMDISK"
  fi
fi

[ -d "$RAMDISK" ] || die "Ramdisk not found: $RAMDISK (use --mount to create)"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                  Seed Disk → Ramdisk                           ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

SEEDED=0
for f in "${FUZZERS[@]}"; do
  ram_corpus="$RAMDISK/corpus-${f}"
  mkdir -p "$ram_corpus"

  before=$(find "$ram_corpus" -type f 2>/dev/null | wc -l)
  sources=""

  # Source 1: seed corpus
  seed_dir="$CFL_DIR/${f}_seed_corpus"
  if [ -d "$seed_dir" ]; then
    rsync -a --quiet --ignore-existing "$seed_dir/" "$ram_corpus/"
    sources+="seed "
  fi

  # Source 2: on-disk grown corpus
  disk_corpus="$CFL_DIR/corpus-${f}"
  if [ -d "$disk_corpus" ]; then
    rsync -a --quiet --ignore-existing "$disk_corpus/" "$ram_corpus/"
    sources+="corpus "
  fi

  # Source 3: shared test profiles (for non-XML, non-TIFF fuzzers)
  case "$f" in
    icc_fromxml_fuzzer|icc_toxml_fuzzer|icc_tiffdump_fuzzer)
      # XML fuzzers need XML, TIFF fuzzer needs TIFF — skip ICC profiles
      ;;
    *)
      for profile_dir in "$REPO_ROOT/test-profiles" "$REPO_ROOT/extended-test-profiles"; do
        if [ -d "$profile_dir" ]; then
          rsync -a --quiet --ignore-existing "$profile_dir/" "$ram_corpus/" 2>/dev/null || true
          sources+="$(basename "$profile_dir") "
        fi
      done
      ;;
  esac

  # Source 4: XML corpus for XML fuzzers
  if [ "$f" = "icc_fromxml_fuzzer" ] || [ "$f" = "icc_toxml_fuzzer" ]; then
    xml_corpus="$CFL_DIR/corpus-xml"
    if [ -d "$xml_corpus" ]; then
      rsync -a --quiet --ignore-existing "$xml_corpus/" "$ram_corpus/" 2>/dev/null || true
      sources+="corpus-xml "
    fi
  fi

  after=$(find "$ram_corpus" -type f 2>/dev/null | wc -l)
  added=$((after - before))

  if [ "$added" -gt 0 ] || [ "$after" -gt 0 ]; then
    printf "  [OK] %-42s %6d inputs (+%d new)  [%s]\n" "$f" "$after" "$added" "${sources% }"
    SEEDED=$((SEEDED + 1))
  else
    printf "  ○ %-42s (no seeds available)\n" "$f"
  fi
done

echo ""
echo "── Summary ──────────────────────────────────────────────────────"
echo "  Seeded: $SEEDED/${#FUZZERS[@]} fuzzers"
if mountpoint -q "$RAMDISK" 2>/dev/null; then
  echo "  Ramdisk: $(df -h "$RAMDISK" | tail -1 | awk '{print $4 " free (" $3 " used)"}')"
fi
echo ""
