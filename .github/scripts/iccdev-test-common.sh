#!/bin/bash
# =============================================================================
# iccdev-test-common.sh — Shared test framework for per-tool test scripts
# =============================================================================
# Source this file in each test-icc*.sh script:
#   source "$(dirname "$0")/iccdev-test-common.sh"
#
# Provides:
#   - Environment detection (research repo vs iccDEV repo)
#   - ASAN/UBSAN configuration
#   - run_test() — single test (sequential)
#   - run_batch_parallel() — parallel batch over file list
#   - Profile path variables, summary printing
# =============================================================================

set -uo pipefail
# Note: NOT set -e — run_test() handles exit codes internally

# Detect repo root: walk up from script location until we find IccProfLib or .git
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$_SCRIPT_DIR"
for _i in 1 2 3 4 5; do
  REPO_ROOT="$(dirname "$REPO_ROOT")"
  [ -d "$REPO_ROOT/IccProfLib" ] || [ -f "$REPO_ROOT/.github/copilot-instructions.md" ] && break
done

# CPU count for parallel jobs
NCPU="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

# Detect if running inside iccDEV directly (cfl branch) or research repo
if [ -d "$REPO_ROOT/IccProfLib" ]; then
  TOOLS="${ICCDEV_TOOLS_DIR:-$REPO_ROOT/Build/Tools}"
  ICCDEV_TESTING="${ICCDEV_TESTING_DIR:-$REPO_ROOT/Testing}"
  export LD_LIBRARY_PATH="${REPO_ROOT}/Build/IccProfLib:${REPO_ROOT}/Build/IccXML${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  TP="$ICCDEV_TESTING/Fuzzing/seeds/icc"
  TP_TIFF="$ICCDEV_TESTING/Fuzzing/seeds/tiff"
  TP_IMG="$ICCDEV_TESTING/Fuzzing/seeds/images"
  TP_SPECTRAL="$ICCDEV_TESTING/Fuzzing/seeds/tiff/spectral"
  for gendir in Named Display; do
    if [ -d "$ICCDEV_TESTING/$gendir" ]; then
      for icc in "$ICCDEV_TESTING/$gendir"/*.icc; do
        [ -f "$icc" ] || continue
        cp -f "$icc" "$TP/" 2>/dev/null || true
      done
    fi
  done
else
  TOOLS="${ICCDEV_TOOLS_DIR:-$REPO_ROOT/iccDEV/Build/Tools}"
  ICCDEV_TESTING="${ICCDEV_TESTING_DIR:-$REPO_ROOT/iccDEV/Testing}"
  export LD_LIBRARY_PATH="${REPO_ROOT}/iccDEV/Build/IccProfLib:${REPO_ROOT}/iccDEV/Build/IccXML${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  TP="$REPO_ROOT/test-profiles"
  TP_TIFF="$REPO_ROOT/test-profiles"
  TP_IMG="$REPO_ROOT/test-profiles"
  TP_SPECTRAL="$REPO_ROOT/test-profiles/spectral"
fi

# Test data directory
if [ -d "$REPO_ROOT/tmp/iccdev-tool-tests" ]; then
  TD="$REPO_ROOT/tmp/iccdev-tool-tests"
elif [ -d "$REPO_ROOT/IccProfLib" ] && [ -d "$ICCDEV_TESTING/Fuzzing/docs/Tools/test-data" ]; then
  TD="$ICCDEV_TESTING/Fuzzing/docs/Tools/test-data"
else
  TD="$REPO_ROOT/docs/iccDEV/Tools/test-data"
fi

OUTDIR="${ICCDEV_TEST_OUTDIR:-/tmp/iccdev-tool-output}"

# Parse common options
ASAN_MODE=0
QUICK_MODE=0
for arg in "$@"; do
  case "$arg" in
    --asan)  ASAN_MODE=1 ;;
    --quick) QUICK_MODE=1 ;;
    --help)  ;; # handled by individual scripts
    *)       ;;
  esac
done

if [ "$ASAN_MODE" -eq 1 ]; then
  export ASAN_OPTIONS="halt_on_error=0,detect_leaks=0"
else
  export ASAN_OPTIONS="detect_leaks=0"
fi
export UBSAN_OPTIONS="halt_on_error=0,print_stacktrace=1"

mkdir -p "$OUTDIR"

# Counters
PASS=0
FAIL=0
TOTAL=0
ASAN_FINDINGS=0
UBSAN_FINDINGS=0

# Parallel results directory — each job writes a 1-line result file
_PARALLEL_DIR="$OUTDIR/.parallel-$$"
mkdir -p "$_PARALLEL_DIR"

# _classify_result — classify exit code + log, write result file
# Usage: _classify_result <test_id> <description> <exit_code> <logfile>
_classify_result() {
  local test_id="$1" description="$2" exit_code="$3" logfile="$4"
  local has_asan=0 has_ubsan=0 status="PASS" note=""

  if grep -q "ERROR: AddressSanitizer" "$logfile" 2>/dev/null; then has_asan=1; fi
  if grep -q "runtime error:" "$logfile" 2>/dev/null; then has_ubsan=1; fi

  if [ "$exit_code" -eq 134 ] || [ "$exit_code" -eq 136 ] || \
     [ "$exit_code" -eq 137 ] || [ "$exit_code" -eq 139 ]; then
    status="CRASH"; note=" [signal $((exit_code - 128))]"
  elif [ "$exit_code" -ge 128 ]; then
    status="ERROR"; note=" [exit=$exit_code]"
  elif [ "$exit_code" -eq 124 ]; then
    status="TIMEOUT"; note=" [>60s]"
  elif [ "$exit_code" -ne 0 ]; then
    status="FAIL"; note=" [exit=$exit_code]"
  fi

  local sanitizer_note=""
  [ "$has_asan" -eq 1 ] && sanitizer_note="$sanitizer_note ASAN!"
  [ "$has_ubsan" -eq 1 ] && sanitizer_note="$sanitizer_note UBSAN!"

  # Write structured result (tab-separated: status exit_code has_asan has_ubsan description note sanitizer_note)
  printf "%s\t%d\t%d\t%d\t%s\t%s\t%s\n" "$status" "$exit_code" "$has_asan" "$has_ubsan" "$description" "$note" "$sanitizer_note" \
    > "$_PARALLEL_DIR/$test_id.result"
}

# run_test — run a single test sequentially (for named/specific tests)
run_test() {
  local test_id="$1"
  local description="$2"
  shift 2
  local cmd=("$@")

  TOTAL=$((TOTAL + 1))
  local logfile="$OUTDIR/${test_id}.log"

  local exit_code=0
  timeout 60 "${cmd[@]}" > "$logfile" 2>&1 || exit_code=$?

  local has_asan=0
  local has_ubsan=0
  if grep -q "ERROR: AddressSanitizer" "$logfile" 2>/dev/null; then
    has_asan=1
    ASAN_FINDINGS=$((ASAN_FINDINGS + 1))
  fi
  if grep -q "runtime error:" "$logfile" 2>/dev/null; then
    has_ubsan=1
    UBSAN_FINDINGS=$((UBSAN_FINDINGS + 1))
  fi

  local status="PASS"
  local note=""
  if [ "$exit_code" -eq 134 ] || [ "$exit_code" -eq 136 ] || \
     [ "$exit_code" -eq 137 ] || [ "$exit_code" -eq 139 ]; then
    status="CRASH"
    FAIL=$((FAIL + 1))
    note=" [signal $((exit_code - 128))]"
  elif [ "$exit_code" -ge 128 ]; then
    status="ERROR"
    FAIL=$((FAIL + 1))
    note=" [exit=$exit_code]"
  elif [ "$exit_code" -eq 124 ]; then
    status="TIMEOUT"
    FAIL=$((FAIL + 1))
    note=" [>60s]"
  elif [ "$exit_code" -ne 0 ]; then
    status="FAIL"
    FAIL=$((FAIL + 1))
    note=" [exit=$exit_code]"
  else
    PASS=$((PASS + 1))
  fi

  local sanitizer_note=""
  if [ "$has_asan" -eq 1 ]; then sanitizer_note="$sanitizer_note ASAN!"; fi
  if [ "$has_ubsan" -eq 1 ]; then sanitizer_note="$sanitizer_note UBSAN!"; fi

  printf "  [%-7s] %-55s exit=%-3d%s%s\n" "$status" "$description" "$exit_code" "$note" "$sanitizer_note"
}

# run_batch_parallel — run a tool against a list of files using all CPUs
# Usage: run_batch_parallel <id_prefix> <desc_prefix> <tool_binary> [tool_args...] -- <file1> <file2> ...
# Files come after the -- separator. Each file becomes a parallel job.
run_batch_parallel() {
  local id_prefix="$1" desc_prefix="$2" tool="$3"
  shift 3

  # Collect tool args (before --) and files (after --)
  local -a tool_args=()
  local -a files=()
  local past_separator=0
  for arg in "$@"; do
    if [ "$arg" = "--" ]; then
      past_separator=1
      continue
    fi
    if [ "$past_separator" -eq 1 ]; then
      files+=("$arg")
    else
      tool_args+=("$arg")
    fi
  done

  if [ "${#files[@]}" -eq 0 ]; then return 0; fi

  local pids=() test_ids=() idx=0
  local max_jobs="$NCPU"

  for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    idx=$((idx + 1))
    local base
    base=$(basename "$f" | sed 's/\.[^.]*$//' | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-40)
    local test_id="${id_prefix}-${base}"
    local logfile="$OUTDIR/${test_id}.log"
    local desc="${desc_prefix}: $(basename "$f" | cut -c1-50)"

    # Launch in background
    (
      local ec=0
      timeout 60 "$tool" "${tool_args[@]}" "$f" > "$logfile" 2>&1 || ec=$?
      _classify_result "$test_id" "$desc" "$ec" "$logfile"
    ) &
    pids+=($!)
    test_ids+=("$test_id")

    # Throttle to max_jobs
    if [ "${#pids[@]}" -ge "$max_jobs" ]; then
      wait "${pids[0]}" 2>/dev/null || true
      pids=("${pids[@]:1}")
    fi
  done

  # Wait for all remaining jobs
  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done

  # Collect results from result files
  for tid in "${test_ids[@]}"; do
    local rf="$_PARALLEL_DIR/$tid.result"
    if [ -f "$rf" ]; then
      local status exit_code has_asan has_ubsan description note sanitizer_note
      IFS=$'\t' read -r status exit_code has_asan has_ubsan description note sanitizer_note < "$rf"
      TOTAL=$((TOTAL + 1))
      if [ "$status" = "PASS" ]; then
        PASS=$((PASS + 1))
      else
        FAIL=$((FAIL + 1))
      fi
      [ "$has_asan" -eq 1 ] && ASAN_FINDINGS=$((ASAN_FINDINGS + 1))
      [ "$has_ubsan" -eq 1 ] && UBSAN_FINDINGS=$((UBSAN_FINDINGS + 1))
      printf "  [%-7s] %-55s exit=%-3d%s%s\n" "$status" "$description" "$exit_code" "$note" "$sanitizer_note"
    fi
  done
}

print_summary() {
  local tool_name="${1:-Tool}"
  echo ""
  echo "--- $tool_name Summary ---"
  echo "  PASS=$PASS  FAIL=$FAIL  TOTAL=$TOTAL"
  echo "  ASAN=$ASAN_FINDINGS  UBSAN=$UBSAN_FINDINGS"
  if [ "$TOTAL" -gt 0 ]; then
    echo "  Pass rate: $(( PASS * 100 / TOTAL ))%"
  fi

  if [ "$ASAN_FINDINGS" -gt 0 ]; then
    echo ""
    echo "  ASAN details:"
    grep -rl "ERROR: AddressSanitizer" "$OUTDIR/"*.log 2>/dev/null | while read f; do
      local asan_line
      asan_line="$(grep 'ERROR: AddressSanitizer' "$f" | head -1)"
      if echo "$asan_line" | grep -q "alloc-dealloc-mismatch"; then
        echo "    $(basename "$f"): $asan_line [KNOWN — CWE-762]"
      else
        echo "    $(basename "$f"): $asan_line [INVESTIGATE]"
      fi
    done
  fi

  if [ "$UBSAN_FINDINGS" -gt 0 ]; then
    echo ""
    echo "  UBSAN details:"
    grep -rl "runtime error:" "$OUTDIR/"*.log 2>/dev/null | while read f; do
      echo "    $(basename "$f"): $(grep 'runtime error:' "$f" | head -1)"
    done
  fi

  # Cleanup parallel temp
  rm -rf "$_PARALLEL_DIR"
  echo ""
}

# Key test profiles
SRGB="$TP/sRGB_D65_MAT.icc"
SRGB_500="$TP/sRGB_D65_MAT-500lx.icc"
CMYK="$TP/CMYK-3DLUTs2.icc"
REC2020="$TP/Rec2020rgbSpectral.icc"
NAMED="$TP/NamedColor.icc"
SPARSE_NAMED="$TP/SparseMatrixNamedColor.icc"
FLUOR_NAMED="$TP/FluorescentNamedColor.icc"
MULTICHAN="$TP/17ChanPart1.icc"
MVIS="$TP/17ChanWithSpots-MVIS.icc"
CAT8="$TP/Cat8Lab-D65_2degMeta.icc"
DISPLAY_P3="$TP/ios-gen-DisplayP3.icc"
ADOBE="$TP/ios-gen-AdobeRGB1998.icc"
CAMERA="$TP/CameraModel.icc"
TIFF_8BIT="$TP_TIFF/catalyst-8bit-ACESCG.tiff"
TIFF_16BIT="$TP_TIFF/catalyst-16bit-ITU2020.tiff"
TIFF_32BIT="$TP_TIFF/catalyst-32bit-ITU709.tiff"
TIFF_MISMATCH="$TP_TIFF/catalyst-16bit-mismatch.tiff"
TIFF_MUTATED="$TP_TIFF/catalyst-16bit-mutated.tiff"
PNG_CVE="$TP_IMG/p0-2225-cve-2021-30942-colorsync-uninit-mem.png"
JPG_CVE="$TP_IMG/p0-2225-cve-2021-30942-colorsync-uninit-mem.jpg"
SPECTRAL_TIFF="$ICCDEV_TESTING/hybrid/Data/smCows380_5_780.tif"
V5_DISPLAY="$ICCDEV_TESTING/Display/LCDDisplay.icc"
NAMED_DATA="$ICCDEV_TESTING/Named/NamedColorTest.txt"
FLUOR_DATA="$ICCDEV_TESTING/Named/FluorescentNamedColorTest.txt"
SRGB_CALC_DATA="$ICCDEV_TESTING/Calc/srgbCalcTest.txt"
SIXCHAN_DATA="$ICCDEV_TESTING/SpecRef/sixChanTest.txt"
CMYK_DATA="$ICCDEV_TESTING/hybrid/Data/cmykGrays.txt"
HYBRID_XML="$ICCDEV_TESTING/hybrid/LCDDisplay.xml"
MACOS_SPECTRAL="$REPO_ROOT/fuzz/xnuimagegenerator/tiff/spectral"
FUZZ_TIF_DIR="$REPO_ROOT/fuzz/graphics/tif"
FUZZ_JPG_DIR="$REPO_ROOT/fuzz/graphics/jpg"
FUZZ_PNG_DIR="$REPO_ROOT/fuzz/graphics/png"
