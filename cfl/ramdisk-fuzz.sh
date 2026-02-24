#!/bin/bash
#
# ramdisk-fuzz.sh — Run ICC LibFuzzer harnesses on a tmpfs ramdisk
#
# Moves corpus I/O to a RAM-backed filesystem so the fuzzer avoids
# disk bottlenecks on corpus sync, merge, and crash writes.
#
# Usage:
#   sudo ./ramdisk-fuzz.sh                  # run all 18 fuzzers, 300s each
#   sudo ./ramdisk-fuzz.sh 60               # run all 18 fuzzers, 60s each
#   sudo ./ramdisk-fuzz.sh 120 icc_profile_fuzzer icc_io_fuzzer
#                                           # run only the named fuzzers
#
# The ramdisk is automatically unmounted on exit (or Ctrl-C).
# Corpus is synced back to cfl/corpus-<name>/ on disk before teardown.
#
# Requirements: root (for mount), fuzzers already built in cfl/bin/

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
RAMDISK="/tmp/fuzz-ramdisk"
RAMDISK_SIZE="4G"
FUZZ_SECONDS="${1:-300}"
JOBS="$(nproc 2>/dev/null || echo 4)"

# Shift past the seconds argument (if given) so $@ is fuzzer names only
if [[ "${1:-}" =~ ^[0-9]+$ ]]; then shift; fi

# ── All 18 fuzzers ──────────────────────────────────────────────────
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

FUZZERS=("${@:-${ALL_FUZZERS[@]}}")

# ── Ramdisk helpers ─────────────────────────────────────────────────
mount_ramdisk() {
  echo "[*] Mounting ${RAMDISK_SIZE} tmpfs ramdisk at ${RAMDISK}"
  mkdir -p "$RAMDISK"
  mount -t tmpfs -o size="$RAMDISK_SIZE",noatime,nodev,nosuid tmpfs "$RAMDISK"
}

unmount_ramdisk() {
  echo "[*] Syncing corpus back to disk..."
  for f in "${FUZZERS[@]}"; do
    local ram_corpus="$RAMDISK/corpus-${f}"
    local disk_corpus="$SCRIPT_DIR/corpus-${f}"
    if [ -d "$ram_corpus" ]; then
      mkdir -p "$disk_corpus"
      rsync -a --quiet "$ram_corpus/" "$disk_corpus/"
      echo "    [OK] $f  ($(find "$ram_corpus" -type f | wc -l) inputs)"
    fi
  done

  # Copy any crash/oom/timeout artifacts
  mkdir -p "$SCRIPT_DIR/findings"
  local found_artifacts=0
  while IFS= read -r -d '' artifact; do
    cp -- "$artifact" "$SCRIPT_DIR/findings/"
    found_artifacts=1
  done < <(find "$RAMDISK" -maxdepth 1 \( -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' -o -name 'slow-unit-*' \) -print0 2>/dev/null)
  if [ "$found_artifacts" -eq 1 ]; then
    echo "    [WARN] Crash artifacts saved to cfl/findings/"
  fi

  echo "[*] Unmounting ramdisk"
  umount "$RAMDISK" 2>/dev/null || true
  rmdir "$RAMDISK" 2>/dev/null || true
}

trap unmount_ramdisk EXIT

# ── Preflight checks ───────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: root required to mount tmpfs. Run with sudo." >&2
  exit 1
fi

if [ ! -d "$BIN_DIR" ]; then
  echo "Error: $BIN_DIR not found. Run ./build.sh first." >&2
  exit 1
fi

# ── Mount + seed ────────────────────────────────────────────────────
mount_ramdisk

# Copy fuzzer binaries to ramdisk to reduce SSD I/O
RAM_BIN="$RAMDISK/bin"
mkdir -p "$RAM_BIN"
echo "[*] Copying fuzzer binaries to ramdisk..."
copied_bins=0
for f in "${FUZZERS[@]}"; do
  if [ -x "$BIN_DIR/$f" ]; then
    cp "$BIN_DIR/$f" "$RAM_BIN/$f"
    copied_bins=$((copied_bins + 1))
  fi
done
echo "    Copied $copied_bins binaries ($(du -sh "$RAM_BIN" | cut -f1))"

# Copy dictionaries to ramdisk
RAM_DICT="$RAMDISK/dict"
mkdir -p "$RAM_DICT"
for dict in "$SCRIPT_DIR"/*.dict; do
  [ -f "$dict" ] && cp "$dict" "$RAM_DICT/"
done

# Create per-fuzzer dict aliases for fuzzers that share a base dict
declare -A FUZZER_DICTS=(
  [icc_toxml_fuzzer]="icc_xml_consolidated.dict"
  [icc_fromxml_fuzzer]="icc_xml_consolidated.dict"
  [icc_io_fuzzer]="icc_core.dict"
  [icc_link_fuzzer]="icc_core.dict"
  [icc_roundtrip_fuzzer]="icc_core.dict"
  [icc_spectral_fuzzer]="icc_core.dict"
  [icc_tiffdump_fuzzer]="icc_core.dict"
  [icc_multitag_fuzzer]="icc_multitag.dict"
  [icc_profile_fuzzer]="icc_profile.dict"
)
for fuzzer in "${!FUZZER_DICTS[@]}"; do
  base="${FUZZER_DICTS[$fuzzer]}"
  if [ -f "$RAM_DICT/$base" ] && [ ! -f "$RAM_DICT/${fuzzer}.dict" ]; then
    cp "$RAM_DICT/$base" "$RAM_DICT/${fuzzer}.dict"
  fi
done

echo "    Copied $(ls "$RAM_DICT"/*.dict 2>/dev/null | wc -l) dictionaries"

XIF_DIR="$SCRIPT_DIR/../xif"

for f in "${FUZZERS[@]}"; do
  ram_corpus="$RAMDISK/corpus-${f}"
  mkdir -p "$ram_corpus"

  # Seed from on-disk corpus (if any)
  disk_corpus="$SCRIPT_DIR/corpus-${f}"
  [ -d "$disk_corpus" ] && rsync -a --quiet "$disk_corpus/" "$ram_corpus/"

  # Seed from seed_corpus directory (if any)
  seed_dir="$SCRIPT_DIR/${f}_seed_corpus"
  [ -d "$seed_dir" ] && rsync -a --quiet "$seed_dir/" "$ram_corpus/"

  # Seed from xif/ directory — TIFF files for tiffdump, ICC profiles for deep_dump
  if [ -d "$XIF_DIR" ]; then
    if [ "$f" = "icc_tiffdump_fuzzer" ]; then
      # Add TIFF and image files from xif/ (may embed ICC profiles in TIFF containers)
      find "$XIF_DIR" -maxdepth 1 -type f -print0 2>/dev/null | \
        xargs -0 file --mime-type 2>/dev/null | \
        grep -E 'image/tiff|image/jpeg|image/png|image/gif' | \
        cut -d: -f1 | \
        xargs -I{} cp --update=none {} "$ram_corpus/" 2>/dev/null
    elif [ "$f" = "icc_deep_dump_fuzzer" ] || [ "$f" = "icc_dump_fuzzer" ]; then
      # Add ICC profile files from xif/ (most comprehensive fuzzers benefit from diversity)
      find "$XIF_DIR" -maxdepth 1 -type f -print0 2>/dev/null | \
        xargs -0 file 2>/dev/null | \
        grep -i 'color profile' | \
        cut -d: -f1 | \
        xargs -I{} cp --update=none {} "$ram_corpus/" 2>/dev/null
    fi
  fi
done

echo "[*] Ramdisk ready: $(df -h "$RAMDISK" | tail -1 | awk '{print $4 " free"}')"

# ── Run fuzzers ─────────────────────────────────────────────────────
echo "[*] Running ${#FUZZERS[@]} fuzzers for ${FUZZ_SECONDS}s each ($(nproc) cores)"
echo ""

PIDS=()
for f in "${FUZZERS[@]}"; do
  # Use ramdisk copy of binary (falls back to SSD if not copied)
  fuzzer_bin="$RAM_BIN/$f"
  [ -x "$fuzzer_bin" ] || fuzzer_bin="$BIN_DIR/$f"
  if [ ! -x "$fuzzer_bin" ]; then
    echo "    [WARN] Skipping $f (binary not found)"
    continue
  fi

  ram_corpus="$RAMDISK/corpus-${f}"

  # Resolve dictionary (prefer ramdisk copy)
  DICT_ARG=""
  for dict in "$RAM_DICT/${f}.dict" "$RAM_DICT/icc.dict" "$SCRIPT_DIR/${f}.dict" "$SCRIPT_DIR/icc.dict"; do
    if [ -f "$dict" ]; then
      DICT_ARG="-dict=$dict"
      break
    fi
  done

  echo "    → $f"
  timeout --kill-after=10s $((FUZZ_SECONDS + 30))s \
    "$fuzzer_bin" \
      -max_total_time="$FUZZ_SECONDS" \
      -print_final_stats=1 \
      -detect_leaks=0 \
      -timeout=30 \
      -rss_limit_mb=4096 \
      -use_value_profile=1 \
      -max_len=65536 \
      -jobs="$JOBS" \
      -workers="$JOBS" \
      -artifact_prefix="$RAMDISK/" \
      $DICT_ARG \
      "$ram_corpus" \
      > "$RAMDISK/${f}.log" 2>&1 &

  PIDS+=($!)
done

echo ""
echo "[*] Waiting for all fuzzers to finish..."
FAIL=0
for pid in "${PIDS[@]}"; do
  wait "$pid" || FAIL=$((FAIL + 1))
done

echo ""
echo "[*] Done. $((${#PIDS[@]} - FAIL))/${#PIDS[@]} fuzzers exited cleanly."

# Show stats summary
echo ""
echo "── Stats ──────────────────────────────────────────────────────"
for f in "${FUZZERS[@]}"; do
  log="$RAMDISK/${f}.log"
  if [ -f "$log" ]; then
    cov=$(grep -oP 'cov: \K[0-9]+' "$log" | tail -1)
    execs=$(grep -oP 'stat::number_of_executed_units:\s*\K[0-9]+' "$log" || echo "?")
    printf "  %-35s cov=%-8s execs=%s\n" "$f" "${cov:-?}" "$execs"
  fi
done
echo ""

# Trap will sync corpus + unmount on exit
