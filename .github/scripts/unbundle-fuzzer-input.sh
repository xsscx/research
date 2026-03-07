#!/bin/bash
# unbundle-fuzzer-input.sh — Extract ICC profiles from CFL fuzzer crash/PoC files
#
# Unbundles multi-profile fuzzer inputs into separate ICC files for
# manual reproduction with the corresponding iccDEV tool.
#
# Supported fuzzers:
#   v5dspobs    — [4B BE size][display.icc][observer.icc]
#   link        — [50% profile1][50% profile2][4B trailing control]
#   applyprofiles — [75% profile][25% control (intent, interp, flags, W×H, pixels)]
#
# Usage:
#   .github/scripts/unbundle-fuzzer-input.sh <fuzzer_name> <crash_file> [tool_root]
#
# Examples:
#   .github/scripts/unbundle-fuzzer-input.sh v5dspobs crash-8f8b4b...
#   .github/scripts/unbundle-fuzzer-input.sh link /mnt/g/fuzz-ssd/crash-abc123
#   .github/scripts/unbundle-fuzzer-input.sh v5dspobs crash-file iccDEV/Build/Tools
#
# Output:
#   ./tmp/icc_<fuzzer_name>/profile_display.icc   (v5dspobs)
#   ./tmp/icc_<fuzzer_name>/profile_observer.icc   (v5dspobs)
#   ./tmp/icc_<fuzzer_name>/profile_1.icc          (link)
#   ./tmp/icc_<fuzzer_name>/profile_2.icc          (link)
#   ./tmp/icc_<fuzzer_name>/profile.icc            (applyprofiles)
#   ./tmp/icc_<fuzzer_name>/control.bin            (link, applyprofiles)
#   ./tmp/icc_<fuzzer_name>/output.icc             (tool output, if tool ran)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ─── Usage ───────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $(basename "$0") <fuzzer_name> <crash_file> [tool_root]

Fuzzer names:
  v5dspobs       icc_v5dspobs_fuzzer  → IccV5DspObsToV4Dsp
  link           icc_link_fuzzer      → IccApplyToLink
  applyprofiles  icc_applyprofiles_fuzzer → IccApplyProfiles

Arguments:
  fuzzer_name    Short name (v5dspobs, link, applyprofiles)
  crash_file     Path to crash/PoC file from LibFuzzer
  tool_root      Optional: path to iccDEV/Build/Tools (auto-detected)

Output directory: ./tmp/icc_<fuzzer_name>/
EOF
  exit 1
}

# ─── Argument parsing ────────────────────────────────────────────────
[ $# -lt 2 ] && usage

FUZZER="$1"
CRASH_FILE="$2"
TOOL_ROOT="${3:-}"

if [ ! -f "$CRASH_FILE" ]; then
  echo "ERROR: Crash file not found: $CRASH_FILE"
  exit 1
fi

FILE_SIZE=$(stat -c%s "$CRASH_FILE" 2>/dev/null || stat -f%z "$CRASH_FILE" 2>/dev/null)
echo "═══════════════════════════════════════════════════"
echo "  CFL Fuzzer Input Unbundler"
echo "═══════════════════════════════════════════════════"
echo "Fuzzer:     $FUZZER"
echo "Input:      $CRASH_FILE"
echo "File size:  $FILE_SIZE bytes"
echo ""

# ─── Output directory ────────────────────────────────────────────────
OUT_DIR="./tmp/icc_${FUZZER}"
mkdir -p "$OUT_DIR"
echo "Output dir: $OUT_DIR"

# ─── Auto-detect tool root ──────────────────────────────────────────
if [ -z "$TOOL_ROOT" ]; then
  for candidate in \
    "$REPO_ROOT/iccDEV/Build/Tools" \
    "$REPO_ROOT/cfl/iccDEV/Build/Tools" \
    "$REPO_ROOT/iccanalyzer-lite/iccDEV/Build/Tools"; do
    if [ -d "$candidate" ]; then
      TOOL_ROOT="$candidate"
      break
    fi
  done
fi

if [ -n "$TOOL_ROOT" ] && [ -d "$TOOL_ROOT" ]; then
  echo "Tool root:  $TOOL_ROOT"
else
  echo "Tool root:  (not found — extraction only)"
fi
echo ""

# ─── Helper: read 4-byte big-endian uint32 at offset ─────────────────
read_be32() {
  local file="$1" offset="$2"
  od -A n -t u1 -j "$offset" -N 4 "$file" | awk '{printf "%d", ($1*16777216)+($2*65536)+($3*256)+$4}'
}

# ─── Helper: validate ICC magic at offset ────────────────────────────
check_icc_magic() {
  local file="$1" label="$2"
  local magic
  magic=$(od -A n -t x1 -j 36 -N 4 "$file" | tr -d ' ')
  if [ "$magic" = "61637370" ]; then
    echo "  ✓ $label: valid ICC magic (acsp)"
  else
    echo "  ✗ $label: invalid magic at offset 36 (got 0x${magic}, expected 0x61637370)"
  fi
}

# ─── Helper: print ICC header summary ────────────────────────────────
icc_header_summary() {
  local file="$1" label="$2"
  local size version class colorspace
  size=$(read_be32 "$file" 0)
  version=$(od -A n -t x1 -j 8 -N 4 "$file" | tr -d ' ')
  class=$(od -A n -t c -j 12 -N 4 "$file" | tr -d ' ')
  colorspace=$(od -A n -t c -j 16 -N 4 "$file" | tr -d ' ')
  echo "  $label: size=$size, version=0x${version}, class='${class}', colorSpace='${colorspace}'"
}

# ─── Helper: run tool with timeout and ASAN ──────────────────────────
run_tool() {
  local tool_path="$1"
  shift
  local tool_name
  tool_name=$(basename "$tool_path")

  echo ""
  echo "─── Running $tool_name ───────────────────────────"
  echo "Command: $tool_path $*"
  echo ""

  local exit_code=0
  ASAN_OPTIONS=detect_leaks=0 \
    timeout 30 "$tool_path" "$@" 2>&1 || exit_code=$?

  echo ""
  if [ $exit_code -eq 0 ]; then
    echo "Result: ✓ EXIT CODE 0 (success)"
  elif [ $exit_code -eq 124 ]; then
    echo "Result: ⚠ TIMEOUT (30s limit)"
  elif [ $exit_code -ge 128 ]; then
    local sig=$((exit_code - 128))
    echo "Result: ✗ CRASH — signal $sig (exit code $exit_code)"
    case $sig in
      6)  echo "         SIGABRT — likely assertion or ASAN error" ;;
      9)  echo "         SIGKILL — OOM or external kill" ;;
      11) echo "         SIGSEGV — segmentation fault" ;;
    esac
  else
    echo "Result: ✗ ERROR — exit code $exit_code"
  fi
  return $exit_code
}

# ═══════════════════════════════════════════════════════════════════════
# Unbundle: v5dspobs — [4B BE size][display][observer]
# ═══════════════════════════════════════════════════════════════════════
unbundle_v5dspobs() {
  echo "Format: [4-byte BE uint32: display_size][display.icc][observer.icc]"
  echo ""

  if [ "$FILE_SIZE" -lt 132 ]; then
    echo "ERROR: File too small ($FILE_SIZE < 132 bytes minimum)"
    return 1
  fi

  local dsp_size
  dsp_size=$(read_be32 "$CRASH_FILE" 0)
  local obs_size=$((FILE_SIZE - 4 - dsp_size))

  echo "Parsed header:"
  echo "  Display profile size: $dsp_size bytes (from offset 4)"
  echo "  Observer profile size: $obs_size bytes (from offset $((4 + dsp_size)))"

  if [ "$dsp_size" -lt 128 ] || [ "$dsp_size" -gt $((FILE_SIZE - 4 - 128)) ]; then
    echo "ERROR: Display size out of range (need 128 ≤ $dsp_size ≤ $((FILE_SIZE - 132)))"
    return 1
  fi

  if [ "$obs_size" -lt 128 ]; then
    echo "ERROR: Observer profile too small ($obs_size < 128 bytes)"
    return 1
  fi

  # Extract profiles
  dd if="$CRASH_FILE" of="$OUT_DIR/profile_display.icc" bs=1 skip=4 count="$dsp_size" 2>/dev/null
  dd if="$CRASH_FILE" of="$OUT_DIR/profile_observer.icc" bs=1 skip=$((4 + dsp_size)) count="$obs_size" 2>/dev/null

  echo ""
  echo "Extracted:"
  ls -lh "$OUT_DIR"/profile_*.icc
  echo ""

  check_icc_magic "$OUT_DIR/profile_display.icc" "Display"
  check_icc_magic "$OUT_DIR/profile_observer.icc" "Observer"
  icc_header_summary "$OUT_DIR/profile_display.icc" "Display"
  icc_header_summary "$OUT_DIR/profile_observer.icc" "Observer"

  # Run tool if available
  local tool="$TOOL_ROOT/IccV5DspObsToV4Dsp/iccV5DspObsToV4Dsp"
  if [ -n "$TOOL_ROOT" ] && [ -x "$tool" ]; then
    run_tool "$tool" \
      "$OUT_DIR/profile_display.icc" \
      "$OUT_DIR/profile_observer.icc" \
      "$OUT_DIR/output.icc"
  else
    echo ""
    echo "Tool not found: IccV5DspObsToV4Dsp"
    echo "Manual repro:"
    echo "  iccV5DspObsToV4Dsp $OUT_DIR/profile_display.icc $OUT_DIR/profile_observer.icc $OUT_DIR/output.icc"
  fi
}

# ═══════════════════════════════════════════════════════════════════════
# Unbundle: link — [50% profile1][50% profile2][4B trailing control]
# ═══════════════════════════════════════════════════════════════════════
unbundle_link() {
  echo "Format: [~50% profile_1][~50% profile_2][4-byte trailing control]"
  echo ""

  if [ "$FILE_SIZE" -lt 260 ]; then
    echo "ERROR: File too small ($FILE_SIZE < 260 bytes minimum for 2 profiles + control)"
    return 1
  fi

  local data_size=$((FILE_SIZE - 4))
  local half=$((data_size / 2))
  local profile1_size=$half
  local profile2_size=$((data_size - half))

  echo "Parsed layout:"
  echo "  Profile 1 size: $profile1_size bytes (offset 0)"
  echo "  Profile 2 size: $profile2_size bytes (offset $profile1_size)"
  echo "  Control bytes:  4 bytes (offset $data_size)"

  # Extract profiles
  dd if="$CRASH_FILE" of="$OUT_DIR/profile_1.icc" bs=1 count="$profile1_size" 2>/dev/null
  dd if="$CRASH_FILE" of="$OUT_DIR/profile_2.icc" bs=1 skip="$profile1_size" count="$profile2_size" 2>/dev/null
  dd if="$CRASH_FILE" of="$OUT_DIR/control.bin" bs=1 skip="$data_size" count=4 2>/dev/null

  # Parse control bytes
  local ctrl
  ctrl=$(od -A n -t u1 -j "$data_size" -N 4 "$CRASH_FILE")
  local intent interp flags extra
  intent=$(echo "$ctrl" | awk '{print $1 % 4}')
  interp=$(echo "$ctrl" | awk '{print $2 % 3}')
  flags=$(echo "$ctrl" | awk '{print $3}')
  extra=$(echo "$ctrl" | awk '{print $4}')

  echo ""
  echo "Control bytes:"
  echo "  Rendering intent: $intent"
  echo "  Interpolation:    $interp"
  echo "  Flags byte:       $flags"
  echo "  Extra byte:       $extra"
  echo ""
  echo "Extracted:"
  ls -lh "$OUT_DIR"/profile_*.icc "$OUT_DIR"/control.bin
  echo ""

  check_icc_magic "$OUT_DIR/profile_1.icc" "Profile 1"
  check_icc_magic "$OUT_DIR/profile_2.icc" "Profile 2"
  icc_header_summary "$OUT_DIR/profile_1.icc" "Profile 1"
  icc_header_summary "$OUT_DIR/profile_2.icc" "Profile 2"

  # Run tool if available
  local tool="$TOOL_ROOT/IccApplyToLink/iccApplyToLink"
  if [ -n "$TOOL_ROOT" ] && [ -x "$tool" ]; then
    run_tool "$tool" \
      "$OUT_DIR/output.icc" \
      "$intent" "0" \
      "$OUT_DIR/profile_1.icc" \
      "$OUT_DIR/profile_2.icc"
  else
    echo ""
    echo "Tool not found: IccApplyToLink"
    echo "Manual repro:"
    echo "  iccApplyToLink $OUT_DIR/output.icc $intent 0 $OUT_DIR/profile_1.icc $OUT_DIR/profile_2.icc"
  fi
}

# ═══════════════════════════════════════════════════════════════════════
# Unbundle: applyprofiles — [75% profile][25% control]
# ═══════════════════════════════════════════════════════════════════════
unbundle_applyprofiles() {
  echo "Format: [~75% ICC profile][~25% control (intent, interp, flags, W×H, pixels)]"
  echo ""

  if [ "$FILE_SIZE" -lt 256 ]; then
    echo "ERROR: File too small ($FILE_SIZE < 256 bytes)"
    return 1
  fi

  local profile_size=$(( (FILE_SIZE * 3) / 4 ))
  local control_size=$((FILE_SIZE - profile_size))

  echo "Parsed layout:"
  echo "  Profile size:  $profile_size bytes (75% of input)"
  echo "  Control size:  $control_size bytes (25% of input)"

  # Extract
  dd if="$CRASH_FILE" of="$OUT_DIR/profile.icc" bs=1 count="$profile_size" 2>/dev/null
  dd if="$CRASH_FILE" of="$OUT_DIR/control.bin" bs=1 skip="$profile_size" count="$control_size" 2>/dev/null

  echo ""
  echo "Extracted:"
  ls -lh "$OUT_DIR"/profile.icc "$OUT_DIR"/control.bin
  echo ""

  check_icc_magic "$OUT_DIR/profile.icc" "Profile"
  icc_header_summary "$OUT_DIR/profile.icc" "Profile"

  # Parse control header
  if [ "$control_size" -ge 14 ]; then
    local ctrl
    ctrl=$(od -A n -t u1 -j "$profile_size" -N 14 "$CRASH_FILE")
    echo ""
    echo "Control header (first 14 bytes):"
    echo "  Raw: $ctrl"
  fi

  echo ""
  echo "Tool: IccApplyProfiles requires TIFF input — manual repro needed:"
  echo "  iccApplyProfiles $OUT_DIR/profile.icc <input.tiff> <output.tiff>"
}

# ═══════════════════════════════════════════════════════════════════════
# Dispatch
# ═══════════════════════════════════════════════════════════════════════
case "$FUZZER" in
  v5dspobs|icc_v5dspobs_fuzzer)
    unbundle_v5dspobs
    ;;
  link|icc_link_fuzzer)
    unbundle_link
    ;;
  applyprofiles|icc_applyprofiles_fuzzer)
    unbundle_applyprofiles
    ;;
  *)
    echo "ERROR: Unknown fuzzer '$FUZZER'"
    echo ""
    echo "Supported fuzzers: v5dspobs, link, applyprofiles"
    echo ""
    echo "Single-profile fuzzers (profile, dump, calculator, roundtrip, etc.)"
    echo "don't need unbundling — pass the crash file directly to the tool."
    exit 1
    ;;
esac

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Done — files in $OUT_DIR/"
echo "═══════════════════════════════════════════════════"
