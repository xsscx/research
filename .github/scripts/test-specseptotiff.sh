#!/usr/bin/env bash
# test-specseptotiff.sh — Comprehensive iccSpecSepToTiff testing
#
# Tests all command-line options, input variations, error cases,
# and cross-validates output with iccTiffDump and iccDumpProfile.
#
# Usage: ./test-specseptotiff.sh [--generate-seeds] [--quick]
#
# Environment:
#   ICCDEV_BUILD  — path to iccDEV/Build (default: auto-detect)
#   SPEC_SEEDS    — path to spectral seed TIFFs (default: auto-detect)
#   TEST_PROFILES — path to ICC test profiles (default: auto-detect)

set -euo pipefail

# ---------- Configuration ----------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ICCDEV_BUILD="${ICCDEV_BUILD:-$REPO_ROOT/iccDEV/Build}"
SPEC_SEEDS="${SPEC_SEEDS:-$REPO_ROOT/iccDEV/Testing/Fuzzing/seeds/tiff/spectral}"
TEST_PROFILES="${TEST_PROFILES:-$REPO_ROOT/test-profiles}"
OUTDIR="/tmp/specsep-test-$$"
GENERATE_SEEDS=0
QUICK=0

for arg in "$@"; do
  case "$arg" in
    --generate-seeds) GENERATE_SEEDS=1 ;;
    --quick)          QUICK=1 ;;
    --help|-h)
      echo "Usage: $0 [--generate-seeds] [--quick]"
      echo "  --generate-seeds  Generate spectral TIFF seeds before testing"
      echo "  --quick           Run minimal test subset"
      exit 0
      ;;
  esac
done

export LD_LIBRARY_PATH="${ICCDEV_BUILD}/IccProfLib:${ICCDEV_BUILD}/IccXML"
export ASAN_OPTIONS="halt_on_error=0,detect_leaks=0"
export LLVM_PROFILE_FILE="/dev/null"

SPECSEP="${ICCDEV_BUILD}/Tools/IccSpecSepToTiff/iccSpecSepToTiff"
TIFFDUMP="${ICCDEV_BUILD}/Tools/IccTiffDump/iccTiffDump"
DUMPPROF="${ICCDEV_BUILD}/Tools/IccDumpProfile/iccDumpProfile"

PASS=0; FAIL=0; ASAN_HITS=0; TOTAL=0

# ---------- Helpers ----------
log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  [FAIL] $1: $2"; }

run_specsep() {
    local label="$1"; shift
    local output
    output=$("$SPECSEP" "$@" 2>&1)
    local ec=$?
    local asan_count=$(echo "$output" | grep -c "ERROR: AddressSanitizer" || true)
    local ubsan_count=$(echo "$output" | grep -c "runtime error:" || true)

    if [ "$asan_count" -gt 0 ] || [ "$ubsan_count" -gt 0 ]; then
        ASAN_HITS=$((ASAN_HITS+1))
        fail "$label" "ASAN=$asan_count UBSAN=$ubsan_count"
        echo "$output" | grep -A5 "ERROR: AddressSanitizer\|runtime error:" | head -20
        return 1
    fi
    return $ec
}

validate_tiff() {
    local label="$1"
    local tiff="$2"
    local expect_spp="$3"
    local expect_bps="${4:-}"

    if [ ! -f "$tiff" ]; then
        fail "$label" "output file missing"
        return 1
    fi

    local info
    info=$("$TIFFDUMP" "$tiff" 2>&1) || true
    local spp=$(echo "$info" | grep "SamplesPerPixel:" | awk '{print $2}')
    local bps=$(echo "$info" | grep "BitsPerSample:" | awk '{print $2}')

    if [ "$spp" != "$expect_spp" ]; then
        fail "$label" "SPP=$spp expected=$expect_spp"
        return 1
    fi
    if [ -n "$expect_bps" ] && [ "$bps" != "$expect_bps" ]; then
        fail "$label" "BPS=$bps expected=$expect_bps"
        return 1
    fi
    pass "$label (SPP=$spp BPS=$bps)"
}

# ---------- Pre-flight ----------
log "iccSpecSepToTiff comprehensive test suite"
echo "  Binary:   $SPECSEP"
echo "  Seeds:    $SPEC_SEEDS"
echo "  Profiles: $TEST_PROFILES"
echo "  Output:   $OUTDIR"
echo ""

mkdir -p "$OUTDIR"

if [ ! -x "$SPECSEP" ]; then
    echo "ERROR: iccSpecSepToTiff not found at $SPECSEP"
    exit 1
fi

# Check seed availability
HAVE_SPEC=$( [ -f "$SPEC_SEEDS/spec_001.tif" ] && echo 1 || echo 0 )
HAVE_WL=$( [ -f "$SPEC_SEEDS/wl_380.tif" ] && echo 1 || echo 0 )
HAVE_LG=$( [ -f "$SPEC_SEEDS/lg_400.tif" ] && echo 1 || echo 0 )
HAVE_CH8=$( [ -f "$SPEC_SEEDS/ch8_001.tif" ] && echo 1 || echo 0 )
HAVE_WHITE=$( [ -f "$SPEC_SEEDS/white_001.tif" ] && echo 1 || echo 0 )
HAVE_BIG=$( [ -f "$SPEC_SEEDS/big_001.tif" ] && echo 1 || echo 0 )

if [ "$GENERATE_SEEDS" -eq 1 ]; then
    log "Generating spectral seed TIFFs..."
    python3 "$SCRIPT_DIR/generate-spectral-tiffs.py" "$SPEC_SEEDS"
    HAVE_WL=1; HAVE_LG=1; HAVE_CH8=1; HAVE_WHITE=1; HAVE_BIG=1
fi

# ---------- Test Suite ----------

# --- Section 1: Usage and error handling ---
log "Section 1: Usage and error handling"

output=$("$SPECSEP" 2>&1) || true
if echo "$output" | grep -q "Usage:"; then
    pass "T01: no-args shows usage"
else
    fail "T01: no-args shows usage" "no usage text"
fi

output=$("$SPECSEP" "$OUTDIR/x.tif" 2>&1) || true
if echo "$output" | grep -q "Usage:"; then
    pass "T02: too-few-args shows usage"
else
    fail "T02: too-few-args shows usage" "no usage text"
fi

output=$("$SPECSEP" "$OUTDIR/step0.tif" 0 0 "$SPEC_SEEDS/spec_%03d.tif" 1 10 0 2>&1) || true
if echo "$output" | grep -qi "zero\|increment.*cannot"; then
    pass "T03: step=0 rejected"
else
    fail "T03: step=0 rejected" "no error for step=0"
fi

output=$("$SPECSEP" "$OUTDIR/badstep.tif" 0 0 "$SPEC_SEEDS/spec_%03d.tif" 10 1 1 2>&1) || true
if echo "$output" | grep -qi "bad\|overflow\|would"; then
    pass "T04: bad step direction rejected"
else
    fail "T04: bad step direction rejected" "no error for bad step"
fi

output=$("$SPECSEP" "$OUTDIR/negstep.tif" 0 0 "$SPEC_SEEDS/spec_%03d.tif" 10 1 -1 2>&1) || true
if echo "$output" | grep -qi "zero\|bad\|overflow"; then
    pass "T05: negative step rejected"
else
    fail "T05: negative step rejected" "no error for negative step"
fi

output=$("$SPECSEP" "$OUTDIR/missing.tif" 0 0 "$SPEC_SEEDS/spec_%03d.tif" 1 99 1 2>&1) || true
if echo "$output" | grep -qi "cannot open\|unable"; then
    pass "T06: missing input file detected"
else
    fail "T06: missing input file detected" "no error for missing file"
fi

# --- Section 2: Basic merging (spec_001-010) ---
if [ "$HAVE_SPEC" -eq 1 ]; then
    log "Section 2: Basic merging (spec_001-010, 4x4 16-bit)"

    run_specsep "T10" "$OUTDIR/basic.tif" 0 0 "$SPEC_SEEDS/spec_%03d.tif" 1 10 1 && \
        validate_tiff "T10: basic 10-ch" "$OUTDIR/basic.tif" 10 16

    run_specsep "T11" "$OUTDIR/compress.tif" 1 0 "$SPEC_SEEDS/spec_%03d.tif" 1 10 1 && \
        validate_tiff "T11: compressed" "$OUTDIR/compress.tif" 10 16

    run_specsep "T12" "$OUTDIR/sep.tif" 0 1 "$SPEC_SEEDS/spec_%03d.tif" 1 10 1 && \
        validate_tiff "T12: separated" "$OUTDIR/sep.tif" 10 16

    run_specsep "T13" "$OUTDIR/comp_sep.tif" 1 1 "$SPEC_SEEDS/spec_%03d.tif" 1 10 1 && \
        validate_tiff "T13: compressed+separated" "$OUTDIR/comp_sep.tif" 10 16

    run_specsep "T14" "$OUTDIR/subset.tif" 0 0 "$SPEC_SEEDS/spec_%03d.tif" 3 7 1 && \
        validate_tiff "T14: subset 3-7" "$OUTDIR/subset.tif" 5 16

    run_specsep "T15" "$OUTDIR/step2.tif" 0 0 "$SPEC_SEEDS/spec_%03d.tif" 1 9 2 && \
        validate_tiff "T15: step=2" "$OUTDIR/step2.tif" 5 16

    run_specsep "T16" "$OUTDIR/single.tif" 0 0 "$SPEC_SEEDS/spec_%03d.tif" 5 5 1 && \
        validate_tiff "T16: single channel" "$OUTDIR/single.tif" 1 16
fi

# --- Section 3: Wavelength suite (81-channel) ---
if [ "$HAVE_WL" -eq 1 ] && [ "$QUICK" -eq 0 ]; then
    log "Section 3: Wavelength suite (wl_380-780, 4x4 16-bit)"

    run_specsep "T20" "$OUTDIR/wl_full.tif" 0 0 "$SPEC_SEEDS/wl_%03d.tif" 380 780 5 && \
        validate_tiff "T20: full visible 81-ch" "$OUTDIR/wl_full.tif" 81 16

    run_specsep "T21" "$OUTDIR/wl_blue.tif" 0 0 "$SPEC_SEEDS/wl_%03d.tif" 380 500 5 && \
        validate_tiff "T21: blue region" "$OUTDIR/wl_blue.tif" 25 16

    run_specsep "T22" "$OUTDIR/wl_green.tif" 0 0 "$SPEC_SEEDS/wl_%03d.tif" 500 600 5 && \
        validate_tiff "T22: green region" "$OUTDIR/wl_green.tif" 21 16

    run_specsep "T23" "$OUTDIR/wl_red.tif" 0 0 "$SPEC_SEEDS/wl_%03d.tif" 600 780 5 && \
        validate_tiff "T23: red region" "$OUTDIR/wl_red.tif" 37 16

    run_specsep "T24" "$OUTDIR/wl_10nm.tif" 0 0 "$SPEC_SEEDS/wl_%03d.tif" 380 780 10 && \
        validate_tiff "T24: 10nm step" "$OUTDIR/wl_10nm.tif" 41 16

    run_specsep "T25" "$OUTDIR/wl_compress.tif" 1 0 "$SPEC_SEEDS/wl_%03d.tif" 380 780 5 && \
        validate_tiff "T25: 81-ch compressed" "$OUTDIR/wl_compress.tif" 81 16

    run_specsep "T26" "$OUTDIR/wl_sep.tif" 0 1 "$SPEC_SEEDS/wl_%03d.tif" 380 780 5 && \
        validate_tiff "T26: 81-ch separated" "$OUTDIR/wl_sep.tif" 81 16
fi

# --- Section 4: Different bit depths and sizes ---
if [ "$HAVE_CH8" -eq 1 ] && [ "$QUICK" -eq 0 ]; then
    log "Section 4: 8-bit images"

    run_specsep "T30" "$OUTDIR/ch8_10ch.tif" 0 0 "$SPEC_SEEDS/ch8_%03d.tif" 1 10 1 && \
        validate_tiff "T30: 8-bit 10-ch" "$OUTDIR/ch8_10ch.tif" 10 8
fi

if [ "$HAVE_WHITE" -eq 1 ] && [ "$QUICK" -eq 0 ]; then
    log "Section 4b: MINISWHITE images"

    run_specsep "T31" "$OUTDIR/white_10ch.tif" 0 0 "$SPEC_SEEDS/white_%03d.tif" 1 10 1 && \
        validate_tiff "T31: MINISWHITE 10-ch" "$OUTDIR/white_10ch.tif" 10 16
fi

if [ "$HAVE_LG" -eq 1 ] && [ "$QUICK" -eq 0 ]; then
    log "Section 4c: 64x64 images"

    run_specsep "T32" "$OUTDIR/lg_31ch.tif" 0 0 "$SPEC_SEEDS/lg_%03d.tif" 400 700 10 && \
        validate_tiff "T32: 64x64 31-ch" "$OUTDIR/lg_31ch.tif" 31 16

    run_specsep "T33" "$OUTDIR/lg_comp_sep.tif" 1 1 "$SPEC_SEEDS/lg_%03d.tif" 400 700 10 && \
        validate_tiff "T33: 64x64 compressed+separated" "$OUTDIR/lg_comp_sep.tif" 31 16
fi

if [ "$HAVE_BIG" -eq 1 ] && [ "$QUICK" -eq 0 ]; then
    log "Section 4d: 256x256 images (stress)"

    run_specsep "T34" "$OUTDIR/big_5ch.tif" 0 0 "$SPEC_SEEDS/big_%03d.tif" 1 5 1 && \
        validate_tiff "T34: 256x256 5-ch" "$OUTDIR/big_5ch.tif" 5 16

    run_specsep "T35" "$OUTDIR/big_compress.tif" 1 0 "$SPEC_SEEDS/big_%03d.tif" 1 5 1 && \
        validate_tiff "T35: 256x256 compressed" "$OUTDIR/big_compress.tif" 5 16
fi

# --- Section 5: ICC profile embedding ---
log "Section 5: ICC profile embedding"

SPECTRAL_PROFILE="$TEST_PROFILES/Rec2020rgbSpectral.icc"
if [ -f "$SPECTRAL_PROFILE" ] && [ "$HAVE_SPEC" -eq 1 ]; then
    run_specsep "T40" "$OUTDIR/with_spectral.tif" 0 0 \
        "$SPEC_SEEDS/spec_%03d.tif" 1 10 1 "$SPECTRAL_PROFILE" && \
        validate_tiff "T40: with Rec2020 spectral" "$OUTDIR/with_spectral.tif" 10 16

    # Verify profile is embedded
    info=$("$TIFFDUMP" "$OUTDIR/with_spectral.tif" 2>&1) || true
    if echo "$info" | grep -q "Profile:.*Embedded"; then
        pass "T40b: ICC profile embedded"
    else
        fail "T40b: ICC profile embedded" "profile not found in output"
    fi
fi

# Try other profile types
for pname in "sRGB_D65_MAT.icc" "CMYKOGP-MVIS-Smooth.icc" "17ChanWithSpots-MVIS.icc"; do
    ppath="$TEST_PROFILES/$pname"
    if [ -f "$ppath" ] && [ "$HAVE_SPEC" -eq 1 ]; then
        safe=$(echo "$pname" | tr '.' '_' | tr '-' '_')
        run_specsep "T41_$safe" "$OUTDIR/prof_$safe.tif" 0 0 \
            "$SPEC_SEEDS/spec_%03d.tif" 1 10 1 "$ppath" && \
            validate_tiff "T41: embed $pname" "$OUTDIR/prof_$safe.tif" 10 16
    fi
done

# Non-existent profile (tool silently skips)
if [ "$HAVE_SPEC" -eq 1 ]; then
    run_specsep "T42" "$OUTDIR/bad_profile.tif" 0 0 \
        "$SPEC_SEEDS/spec_%03d.tif" 1 10 1 "/tmp/nonexistent.icc"
    if [ -f "$OUTDIR/bad_profile.tif" ]; then
        pass "T42: non-existent profile (tool continues)"
    else
        fail "T42: non-existent profile" "output not created"
    fi
fi

# --- Section 6: Cross-validate with other tools ---
if [ "$QUICK" -eq 0 ]; then
    log "Section 6: Cross-validate output with iccDEV tools"

    if [ -f "$OUTDIR/wl_full.tif" ] && [ -x "$TIFFDUMP" ]; then
        output=$("$TIFFDUMP" "$OUTDIR/wl_full.tif" 2>&1) || true
        asan=$(echo "$output" | grep -c "ERROR: AddressSanitizer" || true)
        if [ "$asan" -eq 0 ]; then
            pass "T50: iccTiffDump on 81-ch output (0 ASAN)"
        else
            fail "T50: iccTiffDump on 81-ch output" "ASAN=$asan"
            ASAN_HITS=$((ASAN_HITS+1))
        fi
    fi

    if [ -f "$OUTDIR/with_spectral.tif" ] && [ -x "$DUMPPROF" ]; then
        output=$("$DUMPPROF" "$OUTDIR/with_spectral.tif" 2>&1) || true
        asan=$(echo "$output" | grep -c "ERROR: AddressSanitizer" || true)
        if [ "$asan" -eq 0 ]; then
            pass "T51: iccDumpProfile on ICC-embedded TIFF (0 ASAN)"
        else
            fail "T51: iccDumpProfile on ICC-embedded TIFF" "ASAN=$asan"
            ASAN_HITS=$((ASAN_HITS+1))
        fi
    fi
fi

# ---------- Summary ----------
echo ""
log "========================================="
log "iccSpecSepToTiff Test Summary"
log "========================================="
log "Total: $TOTAL  Pass: $PASS  Fail: $FAIL  ASAN hits: $ASAN_HITS"
log "Output dir: $OUTDIR"

if [ "$FAIL" -eq 0 ] && [ "$ASAN_HITS" -eq 0 ]; then
    log "RESULT: ALL TESTS PASSED"
    exit 0
else
    log "RESULT: $FAIL FAILURES, $ASAN_HITS ASAN HITS"
    exit 1
fi
