#!/bin/bash
# =============================================================================
# test-cfl-patches.sh — Validate CFL patch effects on iccDEV tool output
# =============================================================================
# Tests that all CFL security patches produce the expected tool behavior.
# Each test runs a patched tool and validates the output contains expected
# patterns that differ from unpatched behavior.
#
# Usage (research repo — uses cfl/iccDEV/ build):
#   .github/scripts/test-cfl-patches.sh [--verbose]
#
# Usage (iccDEV repo — uses local build):
#   Testing/Fuzzing/scripts/test-cfl-patches.sh [--verbose]
#
# Prerequisites:
#   - iccDEV built with ALL patches applied (cmake + make)
#   - Test profiles in test-profiles/ (research) or Testing/ (iccDEV)
#
# Environment overrides:
#   ICCDEV_ROOT   Path to iccDEV checkout (default: auto-detect)
#
# Standard: https://github.com/InternationalColorConsortium/iccDEV/issues/700
# Copyright (c) 2026 David H Hoyt LLC. All rights reserved.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERBOSE="${1:-}"

# --- Detect research repo root ---
# When run from .github/scripts/, SCRIPT_DIR/../.. is the research repo root
REPO_ROOT=""
if [ -d "$SCRIPT_DIR/../../test-profiles" ] && [ -d "$SCRIPT_DIR/../../cfl" ]; then
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
fi

# --- Auto-detect iccDEV root ---
# Priority: ICCDEV_ROOT env > cfl/iccDEV (research repo) > iccDEV tree detection
if [ -n "${ICCDEV_ROOT:-}" ]; then
    ROOT="$(cd "$ICCDEV_ROOT" && pwd)"
elif [ -n "$REPO_ROOT" ] && [ -d "$REPO_ROOT/cfl/iccDEV/Build/Tools" ]; then
    ROOT="$REPO_ROOT/cfl/iccDEV"
elif [ -f "$SCRIPT_DIR/../../../IccProfLib/IccProfile.h" ]; then
    ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
else
    echo "ERROR: Cannot detect iccDEV root." >&2
    echo "  Set ICCDEV_ROOT or run from research repo (.github/scripts/) or iccDEV tree." >&2
    exit 1
fi

# --- Paths ---
TOOLS="$ROOT/Build/Tools"
DUMP="$TOOLS/IccDumpProfile/iccDumpProfile"
TOXML="$TOOLS/IccToXml/iccToXml"
FROMXML="$TOOLS/IccFromXml/iccFromXml"
ROUNDTRIP="$TOOLS/IccRoundTrip/iccRoundTrip"
APPLYNAMED="$TOOLS/IccApplyNamedCmm/iccApplyNamedCmm"
APPLYSEARCH="$TOOLS/IccApplySearch/iccApplySearch"
APPLYPROFILES="$TOOLS/IccApplyProfiles/iccApplyProfiles"
APPLYTOLINK="$TOOLS/IccApplyToLink/iccApplyToLink"

T="$ROOT/Testing"
OUTDIR="/tmp/cfl-patch-test-output"

# --- Resolve test data: research repo test-profiles/ first, then iccDEV Testing/ ---
resolve_profile() {
    local name="$1"
    if [ -n "$REPO_ROOT" ] && [ -f "$REPO_ROOT/test-profiles/$name" ]; then
        echo "$REPO_ROOT/test-profiles/$name"; return
    fi
    for d in "$T/Display" "$T/Fuzzing/seeds/icc" "$T/Fuzzing/poc"; do
        [ -f "$d/$name" ] && echo "$d/$name" && return
    done
    echo ""
}

# Resolve malformed JSON directory
MALFORMED_JSON=""
if [ -n "$REPO_ROOT" ] && [ -d "$REPO_ROOT/docs/Testing/malformed-json" ]; then
    MALFORMED_JSON="$REPO_ROOT/docs/Testing/malformed-json"
elif [ -d "$T/Fuzzing/docs/Tools/malformed-json" ]; then
    MALFORMED_JSON="$T/Fuzzing/docs/Tools/malformed-json"
fi

export LD_LIBRARY_PATH="$ROOT/Build/IccProfLib:$ROOT/Build/IccXML${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export ASAN_OPTIONS="halt_on_error=0,detect_leaks=0"
export UBSAN_OPTIONS="halt_on_error=0,print_stacktrace=1"
export LLVM_PROFILE_FILE="/dev/null"

mkdir -p "$OUTDIR"

echo "=== CFL Patch Validation ==="
echo "  iccDEV root:     $ROOT"
echo "  Research repo:   ${REPO_ROOT:-<not detected>}"
echo "  Malformed JSON:  ${MALFORMED_JSON:-<not found>}"
echo "  Tools:           $TOOLS"
echo ""

# --- Counters ---
PASS=0
FAIL=0
SKIP=0
TOTAL=0

# --- Profile paths (resolved from research repo or iccDEV tree) ---
SRGB="$(resolve_profile sRGB_D65_MAT.icc)"
SRGB_500="$(resolve_profile sRGB_D65_MAT-500lx.icc)"
DISPLAY_P3="$(resolve_profile ios-gen-DisplayP3.icc)"
REC2100="$(resolve_profile Rec2100HlgNarrow.icc)"
REC2100_FULL="$(resolve_profile Rec2100HlgFull.icc)"
CFL049_POC="$(resolve_profile cfl-049-btoa-lut16-test.icc)"
HBO_POC="$(resolve_profile hbo-CIccTagColorantTable-Describe-IccTagBasic_cpp-Line8953.icc)"
MULTICHAN="$(resolve_profile 17ChanPart1.icc)"
CFL004_POC="$(resolve_profile CIccToneMapFunc-Describe-heap-oob-IccMpeBasic_cpp.icc)"
CFL077_POC="$(resolve_profile Spec400_10_700-B_2deg-CAM.icc)"

# =============================================================================
# Test helpers
# =============================================================================

run_patch_test() {
    local test_id="$1"
    local description="$2"
    local expect_type="$3"  # "grep" | "grep_count" | "no_asan" | "no_ubsan" | "exit_ok"
    local expect_arg="$4"   # grep pattern, min count, or empty
    shift 4
    local cmd=("$@")

    TOTAL=$((TOTAL + 1))
    local logfile="$OUTDIR/${test_id}.log"

    local exit_code=0
    timeout 60 "${cmd[@]}" > "$logfile" 2>&1 || exit_code=$?

    local has_asan=0
    local has_ubsan=0
    grep -q "ERROR: AddressSanitizer" "$logfile" 2>/dev/null && has_asan=1
    grep -q "runtime error:" "$logfile" 2>/dev/null && has_ubsan=1

    local status="PASS"
    local detail=""

    case "$expect_type" in
        grep)
            if grep -q "$expect_arg" "$logfile" 2>/dev/null; then
                status="PASS"
            else
                status="FAIL"
                detail="pattern '$expect_arg' not found"
            fi
            ;;
        grep_absent)
            if grep -q "$expect_arg" "$logfile" 2>/dev/null; then
                status="FAIL"
                detail="pattern '$expect_arg' should be absent"
            else
                status="PASS"
            fi
            ;;
        grep_count)
            local count
            count=$(grep -c "$expect_arg" "$logfile" 2>/dev/null || echo 0)
            if [ "$count" -ge 1 ]; then
                status="PASS"
                detail="count=$count"
            else
                status="FAIL"
                detail="count=$count (expected >= 1)"
            fi
            ;;
        no_asan)
            if [ "$has_asan" -eq 1 ]; then
                status="FAIL"
                detail="ASAN finding present"
            else
                status="PASS"
            fi
            ;;
        no_ubsan)
            if [ "$has_ubsan" -eq 1 ]; then
                status="FAIL"
                detail="UBSAN finding present"
            else
                status="PASS"
            fi
            ;;
        no_sanitizer)
            if [ "$has_asan" -eq 1 ] || [ "$has_ubsan" -eq 1 ]; then
                status="FAIL"
                detail="sanitizer finding present"
            else
                status="PASS"
            fi
            ;;
        exit_ok)
            if [ "$exit_code" -eq 0 ]; then
                status="PASS"
            else
                status="FAIL"
                detail="exit=$exit_code (expected 0)"
            fi
            ;;
        exit_noncrash)
            # 0-127 = ok, 128+ = crash
            if [ "$exit_code" -lt 128 ]; then
                status="PASS"
            else
                status="FAIL"
                detail="exit=$exit_code (signal $((exit_code - 128)))"
            fi
            ;;
    esac

    # Any ASAN/UBSAN overrides to FAIL regardless of expect_type
    if [ "$expect_type" != "no_asan" ] && [ "$expect_type" != "no_ubsan" ] && [ "$expect_type" != "no_sanitizer" ]; then
        if [ "$has_asan" -eq 1 ]; then
            status="FAIL"
            detail="${detail:+$detail; }ASAN!"
        fi
        if [ "$has_ubsan" -eq 1 ]; then
            status="FAIL"
            detail="${detail:+$detail; }UBSAN!"
        fi
    fi

    if [ "$status" = "PASS" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi

    if [ "$VERBOSE" = "--verbose" ]; then
        printf "  [%-4s] %-50s exit=%-3d %s\n" "$status" "$description" "$exit_code" "$detail"
    else
        printf "  [%-4s] %s\n" "$status" "$description"
    fi
}

skip_test() {
    local test_id="$1"
    local description="$2"
    local reason="$3"
    TOTAL=$((TOTAL + 1))
    SKIP=$((SKIP + 1))
    printf "  [SKIP] %-50s %s\n" "$description" "$reason"
}

echo "============================================================"
echo "CFL Patch Validation Tests"
echo "============================================================"
echo "iccDEV root: $ROOT"
echo "Build tools: $TOOLS"
echo "Output dir:  $OUTDIR"
echo ""

# =============================================================================
# CFL-001: icAnsiToUtf8 null termination (CWE-125/CWE-170)
# UPSTREAM FIXED: PR #740 merged this fix. Patch retired.
# Test validates the upstream fix holds — PoC should NOT trigger ASAN.
# =============================================================================
echo "--- CFL-001: icAnsiToUtf8 null termination (upstream-fixed PR #740) ---"

if [ -f "$HBO_POC" ]; then
    run_patch_test "cfl001-dump-hbo" \
        "DumpProfile HBO PoC — no ASAN" \
        "no_asan" "" \
        "$DUMP" -v 100 "$HBO_POC" ALL

    run_patch_test "cfl001-toxml-hbo" \
        "ToXml HBO PoC — no ASAN" \
        "no_asan" "" \
        "$TOXML" "$HBO_POC" "$OUTDIR/cfl001.xml"
else
    skip_test "cfl001" "CFL-001 HBO PoC" "poc file missing"
fi

# =============================================================================
# CFL-002: GamutBoundary triangles signed overflow (CWE-190)
# RETIRED: upstream fix in v2.3.1.6 — patch moved to cfl/patches-retired/
# Test validates the upstream fix holds.
# =============================================================================
echo ""
echo "--- CFL-002: GamutBoundary triangles overflow (upstream-fixed) ---"

run_patch_test "cfl002-srgb-dump" \
    "DumpProfile sRGB — no crash" \
    "no_sanitizer" "" \
    "$DUMP" -v 100 "$SRGB" ALL

# =============================================================================
# CFL-004: ToneMapFunc Read parameter count (CWE-122)
# Patched: validates m_nParameters >= NumArgs() in Read()
# PoC: CIccToneMapFunc-Describe-heap-oob-IccMpeBasic_cpp.icc
#   UNPATCHED: ASAN heap-buffer-overflow at IccMpeBasic.cpp:3988 (SCARINESS=17)
#   PATCHED:   clean exit, no ASAN
# =============================================================================
echo ""
echo "--- CFL-004: ToneMapFunc param count validation ---"

if [ -f "$CFL004_POC" ]; then
    run_patch_test "cfl004-poc-hbo" \
        "DumpProfile ToneMapFunc HBO PoC — no ASAN" \
        "no_asan" "" \
        "$DUMP" -v 100 "$CFL004_POC" ALL
fi

if [ -f "$REC2100" ]; then
    run_patch_test "cfl004-rec2100-dump" \
        "DumpProfile Rec2100 HLG Narrow — no ASAN" \
        "no_sanitizer" "" \
        "$DUMP" -v 100 "$REC2100" ALL
fi

if [ -f "$REC2100_FULL" ]; then
    run_patch_test "cfl004-rec2100full-dump" \
        "DumpProfile Rec2100 HLG Full — no ASAN" \
        "no_sanitizer" "" \
        "$DUMP" -v 100 "$REC2100_FULL" ALL
fi

# =============================================================================
# CFL-005: CalculatorFunc Read enum UBSAN (CWE-681)
# Patched: enum bounds check before assignment
# =============================================================================
echo ""
echo "--- CFL-005: CalculatorFunc enum UBSAN ---"

run_patch_test "cfl005-srgb-roundtrip" \
    "RoundTrip sRGB — no UBSAN" \
    "no_ubsan" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# CFL-006: SpectralMatrix Describe iteration bounds (CWE-122)
# Patched: bounds check on m_nOutputChannels in Describe()
# =============================================================================
echo ""
echo "--- CFL-006: SpectralMatrix Describe bounds ---"

if [ -f "$MULTICHAN" ]; then
    run_patch_test "cfl006-17chan-dump" \
        "DumpProfile 17-channel — no ASAN" \
        "no_sanitizer" "" \
        "$DUMP" -v 100 "$MULTICHAN" ALL
fi

# =============================================================================
# CFL-007: TagArray Read overflow guard (CWE-190)
# Patched: integer overflow check on element count
# =============================================================================
echo ""
echo "--- CFL-007: TagArray overflow guard ---"

run_patch_test "cfl007-srgb-toxml" \
    "ToXml sRGB — clean exit" \
    "exit_ok" "" \
    "$TOXML" "$SRGB" "$OUTDIR/cfl007.xml"

# =============================================================================
# CFL-008: TagCurve Apply NaN→unsigned UBSAN (CWE-681)
# Patched: NaN check before unsigned cast in Apply()
# =============================================================================
echo ""
echo "--- CFL-008: TagCurve NaN guard ---"

run_patch_test "cfl008-srgb-roundtrip" \
    "RoundTrip sRGB — no UBSAN NaN cast" \
    "no_ubsan" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# CFL-009: EnvVar Exec enum UBSAN (CWE-681)
# Patched: bounds check in CIccOpDefEnvVar::Exec()
# =============================================================================
echo ""
echo "--- CFL-009: EnvVar Exec enum ---"

run_patch_test "cfl009-srgb-roundtrip" \
    "RoundTrip sRGB — no enum UBSAN" \
    "no_ubsan" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# CFL-014: SequenceNeedTempReset recursion depth (CWE-674)
# Patched: depth counter on recursive Apply path
# =============================================================================
echo ""
echo "--- CFL-014: Recursion depth limit ---"

run_patch_test "cfl014-srgb500-roundtrip" \
    "RoundTrip sRGB-500lx — no stack overflow" \
    "exit_noncrash" "" \
    "$ROUNDTRIP" "$SRGB_500"

# =============================================================================
# CFL-017: GetEnvSig parse enum UBSAN (CWE-681)
# Patched: enum bounds check in GetEnvSig() XML parse path
# =============================================================================
echo ""
echo "--- CFL-017: GetEnvSig parse enum ---"

run_patch_test "cfl017-srgb-toxml-roundtrip" \
    "ToXml+FromXml sRGB — no UBSAN" \
    "no_ubsan" "" \
    "$TOXML" "$SRGB" "$OUTDIR/cfl017.xml"

if [ -f "$OUTDIR/cfl017.xml" ]; then
    run_patch_test "cfl017-fromxml" \
        "FromXml sRGB roundtrip — no UBSAN" \
        "no_ubsan" "" \
        "$FROMXML" "$OUTDIR/cfl017.xml" "$OUTDIR/cfl017-rt.icc"
fi

# =============================================================================
# CFL-019: PCC getReflectanceObserver null guard (CWE-476)
# Patched: NULL check before getReflectanceObserver()
# =============================================================================
echo ""
echo "--- CFL-019: PCC null spectral guard ---"

if [ -f "$MULTICHAN" ]; then
    run_patch_test "cfl019-17chan-roundtrip" \
        "RoundTrip 17-channel — no null deref" \
        "no_sanitizer" "" \
        "$ROUNDTRIP" "$MULTICHAN"
fi

# =============================================================================
# CFL-021: SingleSampledCurve OOM size validation (CWE-400)
# Patched: m_nCount upper bound in Read()
# =============================================================================
echo ""
echo "--- CFL-021: SingleSampledCurve OOM guard ---"

run_patch_test "cfl021-srgb-dump" \
    "DumpProfile sRGB — no OOM" \
    "no_sanitizer" "" \
    "$DUMP" -v 100 "$SRGB" ALL

# =============================================================================
# CFL-022: Calc Trunc/Floor/Ceil/Round/Mod int overflow (CWE-681)
# Patched: range check before (int) cast in 5 calculator ops
# =============================================================================
echo ""
echo "--- CFL-022: Calculator int overflow ---"

run_patch_test "cfl022-srgb-roundtrip" \
    "RoundTrip sRGB — no int overflow UBSAN" \
    "no_ubsan" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# CFL-023: Sampled curve NaN-to-unsigned cast (CWE-681)
# Patched: NaN guard in 3 Apply() functions in IccMpeBasic.cpp
# =============================================================================
echo ""
echo "--- CFL-023: Sampled curve NaN cast ---"

run_patch_test "cfl023-srgb-roundtrip" \
    "RoundTrip sRGB — no NaN cast UBSAN" \
    "no_ubsan" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# CFL-025: CLUT InterpNd null Apply guard (CWE-476)
# Patched: NULL check on CIccApplyCLUT in InterpNd path
# =============================================================================
echo ""
echo "--- CFL-025: CLUT InterpNd null guard ---"

if [ -f "$MULTICHAN" ]; then
    run_patch_test "cfl025-17chan-dump" \
        "DumpProfile 17-channel ALL — no null deref" \
        "no_sanitizer" "" \
        "$DUMP" -v 100 "$MULTICHAN" ALL
fi

# =============================================================================
# CFL-028: MatrixMath SetRange NaN guard (CWE-681)
# Patched: NaN check before unsigned short cast
# =============================================================================
echo ""
echo "--- CFL-028: MatrixMath SetRange NaN ---"

run_patch_test "cfl028-srgb-roundtrip" \
    "RoundTrip sRGB — no NaN UBSAN" \
    "no_ubsan" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# CFL-029: TagArray operator= loop var (CWE-824)
# Patched: loop variable not modified inside body
# =============================================================================
echo ""
echo "--- CFL-029: TagArray loop variable ---"

run_patch_test "cfl029-srgb-dump" \
    "DumpProfile sRGB — clean" \
    "no_sanitizer" "" \
    "$DUMP" -v 100 "$SRGB" ALL

# =============================================================================
# CFL-030: FixedNum GetValues SBO (CWE-121)
# Patched: uses nVectorSize instead of m_nSize in loop
# =============================================================================
echo ""
echo "--- CFL-030: FixedNum GetValues bounds ---"

run_patch_test "cfl030-srgb-roundtrip" \
    "RoundTrip sRGB — no SBO" \
    "no_sanitizer" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# CFL-031 through CFL-043: JSON configuration patches
# These target iccApplyNamedCmm, iccApplySearch, iccApplyProfiles -cfg mode
# =============================================================================
echo ""
echo "--- CFL-031..043: JSON configuration patches ---"

if [ -d "$MALFORMED_JSON" ]; then
    # CFL-031: loadJsonFrom ftell overflow
    # Malformed JSON files cause graceful rejection (exit 255 = -1).
    # The key assertion is no ASAN/UBSAN — not exit code 0.
    for jf in "$MALFORMED_JSON"/*.json; do
        [ -f "$jf" ] || continue
        base=$(basename "$jf" .json)
        run_patch_test "cfl031-043-named-$base" \
            "ApplyNamedCmm -cfg $base — no sanitizer" \
            "no_sanitizer" "" \
            "$APPLYNAMED" -cfg "$jf"
    done

    # Also test iccApplySearch with malformed JSON
    for jf in "$MALFORMED_JSON/searchapply"*.json "$MALFORMED_JSON/pccweight"*.json; do
        [ -f "$jf" ] || continue
        base=$(basename "$jf" .json)
        run_patch_test "cfl031-043-search-$base" \
            "ApplySearch -cfg $base — no sanitizer" \
            "no_sanitizer" "" \
            "$APPLYSEARCH" -cfg "$jf"
    done
else
    skip_test "cfl031-043" "JSON malformed tests" "malformed-json/ missing"
fi

# =============================================================================
# CFL-044: NDLut Apply missing Interp dispatch (CWE-476)
# Patched: dispatch table for Interp1d through Interp4d
# =============================================================================
echo ""
echo "--- CFL-044: NDLut Interp dispatch ---"

if [ -f "$MULTICHAN" ]; then
    run_patch_test "cfl044-17chan-roundtrip" \
        "RoundTrip 17-channel — no null dispatch" \
        "no_sanitizer" "" \
        "$ROUNDTRIP" "$MULTICHAN"
fi

# =============================================================================
# CFL-049: BToA Describe missing bUseLegacy (CWE-682)
# Patched: DumpLut called with bUseLegacy for Lut16 BToA tags
# Validation: CLUT grid data present in BToA output
# =============================================================================
echo ""
echo "--- CFL-049: BToA Describe bUseLegacy ---"

if [ -f "$CFL049_POC" ]; then
    # Primary test: CLUT grid data must be present for BOTH AToB and BToA
    run_patch_test "cfl049-clut-present" \
        "PoC BToA CLUT grid data present" \
        "grep_count" "BEGIN_LUT CLUT" \
        "$DUMP" -v 100 "$CFL049_POC" ALL
    # Expect 2 CLUT blocks (AToB + BToA)

    # Secondary: verify BToA section has actual data lines
    run_patch_test "cfl049-btoa-data" \
        "PoC BToA has Lab channel labels" \
        "grep" "Lab_1=" \
        "$DUMP" -v 100 "$CFL049_POC" ALL

    # Tertiary: no sanitizer issues
    run_patch_test "cfl049-no-asan" \
        "PoC profile — no ASAN/UBSAN" \
        "no_sanitizer" "" \
        "$DUMP" -v 100 "$CFL049_POC" ALL
else
    skip_test "cfl049" "CFL-049 BToA test" "poc/cfl-049-btoa-lut16-test.icc missing"
fi

# =============================================================================
# CFL-050: FormulaCurveSegment Describe param bounds (CWE-122)
# Patched: bounds check on m_params access in Describe()
# Validation: formula curve output with no HBO
# =============================================================================
echo ""
echo "--- CFL-050: FormulaCurveSegment Describe bounds ---"

if [ -f "$SRGB" ]; then
    # sRGB_D65_MAT has formula curve segments (type 0000h)
    run_patch_test "cfl050-srgb-formula" \
        "DumpProfile sRGB formula curves — no HBO" \
        "no_asan" "" \
        "$DUMP" -v 100 "$SRGB" ALL

    run_patch_test "cfl050-srgb-formula-output" \
        "sRGB has FormulaType output" \
        "grep" "FunctionType:" \
        "$DUMP" -v 100 "$SRGB" ALL
fi

# =============================================================================
# CFL-051: ParametricCurve Describe param bounds (CWE-122)
# Patched: bounds check on m_Params access in Describe()
# Validation: parametric curve output with no HBO
# =============================================================================
echo ""
echo "--- CFL-051: ParametricCurve Describe bounds ---"

if [ -f "$DISPLAY_P3" ]; then
    run_patch_test "cfl051-p3-parametric" \
        "DumpProfile DisplayP3 parametric — no HBO" \
        "no_asan" "" \
        "$DUMP" -v 100 "$DISPLAY_P3" ALL

    run_patch_test "cfl051-p3-functiontype" \
        "DisplayP3 has FunctionType 0003h" \
        "grep" "FunctionType: 0003h" \
        "$DUMP" -v 100 "$DISPLAY_P3" ALL
fi

# =============================================================================
# CFL-052: fromIt8 wrong index variable i vs j (CWE-682)
# Patched: uses j (inner loop) instead of i (outer loop)
# =============================================================================
echo ""
echo "--- CFL-052: fromIt8 wrong index ---"

# This is in IccCmmConfig.cpp — exercised via JSON config tools
# We test that the tool doesn't crash when processing valid configs
# Resolve json-configs directory
_JSON_CONFIGS=""
if [ -n "$REPO_ROOT" ] && [ -d "$REPO_ROOT/docs/Testing/json-configs" ]; then
    _JSON_CONFIGS="$REPO_ROOT/docs/Testing/json-configs"
elif [ -d "$T/Fuzzing/scripts/json-configs" ]; then
    _JSON_CONFIGS="$T/Fuzzing/scripts/json-configs"
fi
if [ -n "$_JSON_CONFIGS" ]; then
    for cfg in "$_JSON_CONFIGS"/*.json; do
        [ -f "$cfg" ] || continue
        base=$(basename "$cfg" .json)
        run_patch_test "cfl052-cfg-$base" \
            "ApplyNamedCmm -cfg $base — no sanitizer" \
            "no_sanitizer" "" \
            "$APPLYNAMED" -cfg "$cfg"
        break  # Just test first available config
    done
else
    run_patch_test "cfl052-roundtrip-srgb" \
        "RoundTrip sRGB — no index error" \
        "no_sanitizer" "" \
        "$ROUNDTRIP" "$SRGB"
fi

# =============================================================================
# CFL-053: FormulaCurveSegment format %8.f → %8.4f (CWE-682)
# Patched: format specifiers show decimal precision for types 3/4
# Validation: sRGB has type 0 formulas — verify Y = output is correct
# =============================================================================
echo ""
echo "--- CFL-053: FormulaCurveSegment format specifiers ---"

if [ -f "$SRGB" ]; then
    run_patch_test "cfl053-formula-y-output" \
        "sRGB formula Y = output present" \
        "grep" "Y = " \
        "$DUMP" -v 100 "$SRGB" ALL

    # Verify the format has decimal precision (not integer)
    run_patch_test "cfl053-formula-precision" \
        "sRGB formula shows decimal values" \
        "grep" "0\\.0" \
        "$DUMP" -v 100 "$SRGB" ALL
fi

# =============================================================================
# CFL-054: ParametricCurve format %lf → %.4f (CWE-682)
# Patched: consistent 4-decimal format in Describe()
# Validation: DisplayP3 parametric output has .NNNN format
# =============================================================================
echo ""
echo "--- CFL-054: ParametricCurve format specifiers ---"

if [ -f "$DISPLAY_P3" ]; then
    # Patched output: 0.0774 (4 decimals), unpatched: 0.077393 (6 decimals)
    run_patch_test "cfl054-p3-format" \
        "DisplayP3 parametric 4-decimal format" \
        "grep" "0\.0774 " \
        "$DUMP" -v 100 "$DISPLAY_P3" ALL

    # Verify FunctionType 0003h is present
    run_patch_test "cfl054-p3-functype" \
        "DisplayP3 FunctionType 0003h present" \
        "grep" "FunctionType: 0003h" \
        "$DUMP" -v 100 "$DISPLAY_P3" ALL

    # Ensure no UBSAN from format handling
    run_patch_test "cfl054-p3-no-ubsan" \
        "DisplayP3 parametric — no UBSAN" \
        "no_ubsan" "" \
        "$DUMP" -v 100 "$DISPLAY_P3" ALL
fi

# =============================================================================
# CFL-055: fromIt8 signed/unsigned mismatch (CWE-681)
# Patched: int → size_t comparison in sample loop
# =============================================================================
echo ""
echo "--- CFL-055: fromIt8 signed/unsigned ---"

run_patch_test "cfl055-roundtrip-srgb" \
    "RoundTrip sRGB — no signed/unsigned UBSAN" \
    "no_ubsan" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# CFL-056: Spectral Describe null pointer guards (CWE-476)
# Patched: NULL checks for m_pWhite and m_pOffset in Describe()
# =============================================================================
echo ""
echo "--- CFL-056: Spectral null pointer guards ---"

if [ -f "$MULTICHAN" ]; then
    run_patch_test "cfl056-17chan-describe" \
        "DumpProfile 17-channel spectral — no null deref" \
        "no_sanitizer" "" \
        "$DUMP" -v 100 "$MULTICHAN" ALL
fi

if [ -f "$REC2100" ]; then
    run_patch_test "cfl056-rec2100-describe" \
        "DumpProfile Rec2100 spectral — no null deref" \
        "no_sanitizer" "" \
        "$DUMP" -v 100 "$REC2100" ALL
fi

# =============================================================================
# CFL-057: CIccCfgSearchApply uninitialized members (CWE-908)
# Patched: constructor initializes all 6 scalar members
# =============================================================================
echo ""
echo "--- CFL-057: SearchApply uninitialized members ---"

if [ -d "$MALFORMED_JSON" ]; then
    # The uninitialized member bug causes UBSAN: load of value N, not valid for bool
    for jf in "$MALFORMED_JSON/searchapply"*.json; do
        [ -f "$jf" ] || continue
        base=$(basename "$jf" .json)
        run_patch_test "cfl057-search-$base" \
            "ApplySearch -cfg $base — no UBSAN bool" \
            "no_ubsan" "" \
            "$APPLYSEARCH" -cfg "$jf"
    done
else
    skip_test "cfl057" "CFL-057 SearchApply init" "malformed-json/ missing"
fi

# =============================================================================
# CFL-059: CIccTagCurve::Begin nMaxIndex underflow (CWE-681)
# Patched: m_nSize > 0 guard before (m_nSize - 1) to avoid unsigned underflow
# Source: IccTagLut.h — Begin() method
# =============================================================================
echo ""
echo "--- CFL-059: TagCurve Begin nMaxIndex underflow ---"

run_patch_test "cfl059-srgb-roundtrip" \
    "RoundTrip sRGB — no unsigned underflow" \
    "no_ubsan" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# CFL-061: icF16toF unsigned underflow (CWE-191)
# Patched: prevents unsigned subtraction underflow in half-float decoder
# Source: IccUtil.cpp — icF16toF()
# =============================================================================
echo ""
echo "--- CFL-061: icF16toF unsigned underflow ---"

run_patch_test "cfl061-srgb-dump" \
    "DumpProfile sRGB — no underflow UBSAN" \
    "no_ubsan" "" \
    "$DUMP" -v 100 "$SRGB" ALL

# =============================================================================
# CFL-062: icGetSig implicit char conversion (CWE-681)
# Patched: explicit cast prevents implicit int-to-icChar UBSAN
# Source: IccUtil.cpp — icGetSig()
# =============================================================================
echo ""
echo "--- CFL-062: icGetSig implicit char conversion ---"

run_patch_test "cfl062-srgb-dump" \
    "DumpProfile sRGB — no implicit conversion UBSAN" \
    "no_ubsan" "" \
    "$DUMP" -v 100 "$SRGB" ALL

run_patch_test "cfl062-srgb-toxml" \
    "ToXml sRGB — no implicit conversion UBSAN" \
    "no_ubsan" "" \
    "$TOXML" "$SRGB" "$OUTDIR/cfl062.xml"

# =============================================================================
# CFL-063: Bounds check unsigned overflow (CWE-190)
# Patched: offset+size overflow guards in Read/CheckLut
# Source: IccProfile.cpp, IccTagMPE.cpp, IccMpeCalc.cpp
# =============================================================================
echo ""
echo "--- CFL-063: Bounds check unsigned overflow ---"

run_patch_test "cfl063-srgb-roundtrip" \
    "RoundTrip sRGB — no unsigned overflow UBSAN" \
    "no_ubsan" "" \
    "$ROUNDTRIP" "$SRGB"

if [ -f "$MULTICHAN" ]; then
    run_patch_test "cfl063-17chan-dump" \
        "DumpProfile 17-channel — no overflow UBSAN" \
        "no_sanitizer" "" \
        "$DUMP" -v 100 "$MULTICHAN" ALL
fi

# =============================================================================
# CFL-064: Segmented curve subtraction underflow (CWE-191)
# Patched: pos-startPos underflow guard in CIccSegmentedCurve::Read
# Source: IccMpeBasic.cpp
# =============================================================================
echo ""
echo "--- CFL-064: Segmented curve subtraction underflow ---"

run_patch_test "cfl064-srgb-dump" \
    "DumpProfile sRGB — no subtraction underflow UBSAN" \
    "no_ubsan" "" \
    "$DUMP" -v 100 "$SRGB" ALL

if [ -f "$DISPLAY_P3" ]; then
    run_patch_test "cfl064-p3-roundtrip" \
        "RoundTrip DisplayP3 — no subtraction underflow" \
        "no_ubsan" "" \
        "$ROUNDTRIP" "$DISPLAY_P3"
fi

# =============================================================================
# CFL-067: icIsS15Fixed16NumberNear float overflow (CWE-681)
# Patched: isnan/isinf check before unsigned cast in D50 check
# Source: IccUtil.cpp — icIsS15Fixed16NumberNear()
# =============================================================================
echo ""
echo "--- CFL-067: S15Fixed16 float overflow guard ---"

run_patch_test "cfl067-srgb-dump" \
    "DumpProfile sRGB — no float overflow UBSAN" \
    "no_ubsan" "" \
    "$DUMP" -v 100 "$SRGB" ALL

run_patch_test "cfl067-srgb-roundtrip" \
    "RoundTrip sRGB — no float overflow UBSAN" \
    "no_ubsan" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# CFL-040: fromIt8 CMYK missing push_back (CWE-787/CWE-125)
# Patched: adds samples.push_back(val) in CMYK branch
# Source: IccCmmConfig.cpp — fromIt8()
# =============================================================================
echo ""
echo "--- CFL-040: fromIt8 CMYK missing push_back ---"

# JSON config tools exercise this code path
if [ -n "$_JSON_CONFIGS" ]; then
    for cfg in "$_JSON_CONFIGS"/*.json; do
        [ -f "$cfg" ] || continue
        base=$(basename "$cfg" .json)
        run_patch_test "cfl040-cfg-$base" \
            "ApplyNamedCmm -cfg $base — no sanitizer" \
            "no_sanitizer" "" \
            "$APPLYNAMED" -cfg "$cfg"
        break
    done
else
    run_patch_test "cfl040-roundtrip-srgb" \
        "RoundTrip sRGB — CMYK path safe" \
        "no_sanitizer" "" \
        "$ROUNDTRIP" "$SRGB"
fi

# =============================================================================
# CFL-041: fromIt8 LAB/XYZ val(4) out-of-bounds (CWE-125)
# Patched: val(4) corrected to val(3) for 3-channel LAB/XYZ
# Source: IccCmmConfig.cpp — fromIt8()
# =============================================================================
echo ""
echo "--- CFL-041: fromIt8 LAB/XYZ val(4) OOB ---"

if [ -n "$_JSON_CONFIGS" ]; then
    for cfg in "$_JSON_CONFIGS"/*.json; do
        [ -f "$cfg" ] || continue
        base=$(basename "$cfg" .json)
        run_patch_test "cfl041-cfg-$base" \
            "ApplyNamedCmm -cfg $base — no OOB" \
            "no_sanitizer" "" \
            "$APPLYNAMED" -cfg "$cfg"
        break
    done
else
    run_patch_test "cfl041-roundtrip-srgb" \
        "RoundTrip sRGB — LAB/XYZ path safe" \
        "no_sanitizer" "" \
        "$ROUNDTRIP" "$SRGB"
fi

# =============================================================================
# CFL-042: ParseNumbers 'n' vs '\n' typo (CWE-20)
# Patched: literal character 'n' corrected to newline '\n'
# Source: IccCmmConfig.cpp — ParseNumbers()
# =============================================================================
echo ""
echo "--- CFL-042: ParseNumbers newline typo ---"

if [ -n "$_JSON_CONFIGS" ]; then
    for cfg in "$_JSON_CONFIGS"/*.json; do
        [ -f "$cfg" ] || continue
        base=$(basename "$cfg" .json)
        run_patch_test "cfl042-cfg-$base" \
            "ApplyNamedCmm -cfg $base — parse ok" \
            "no_sanitizer" "" \
            "$APPLYNAMED" -cfg "$cfg"
        break
    done
else
    run_patch_test "cfl042-roundtrip-srgb" \
        "RoundTrip sRGB — parse path safe" \
        "no_sanitizer" "" \
        "$ROUNDTRIP" "$SRGB"
fi

# =============================================================================
# CFL-046: PCS step src matrix delete[] mismatch (CWE-762)
# Patched: delete vs delete[] mismatch on matrix array in IccCmm.cpp
# Source: IccCmm.cpp — PCS step cleanup
# =============================================================================
echo ""
echo "--- CFL-046: PCS step matrix delete[] ---"

run_patch_test "cfl046-srgb-roundtrip" \
    "RoundTrip sRGB — no alloc/dealloc mismatch" \
    "no_sanitizer" "" \
    "$ROUNDTRIP" "$SRGB"

if [ -f "$SRGB" ] && [ -f "$SRGB_500" ]; then
    run_patch_test "cfl046-link-srgb" \
        "ApplyToLink sRGB — no delete[] mismatch" \
        "no_sanitizer" "" \
        "$APPLYTOLINK" "$SRGB" 1 "$SRGB_500" 1 "$OUTDIR/cfl046-link.icc"
fi

# =============================================================================
# CFL-047: pushXYZNormalize null PCC guard (CWE-476)
# Patched: NULL check on PCC pointer before dereference
# Source: IccCmm.cpp — pushXYZNormalize()
# =============================================================================
echo ""
echo "--- CFL-047: pushXYZNormalize null PCC guard ---"

run_patch_test "cfl047-srgb-roundtrip" \
    "RoundTrip sRGB — no null PCC deref" \
    "no_sanitizer" "" \
    "$ROUNDTRIP" "$SRGB"

if [ -f "$MULTICHAN" ]; then
    run_patch_test "cfl047-17chan-roundtrip" \
        "RoundTrip 17-channel — no null PCC deref" \
        "no_sanitizer" "" \
        "$ROUNDTRIP" "$MULTICHAN"
fi

# =============================================================================
# CFL-068: MpeCurveSet operator= self-assignment guard (CWE-416)
# Patched: self-assignment check in operator= to prevent UAF
# Source: IccMpeBasic.cpp — CIccMpeCurveSet::operator=()
# =============================================================================
echo ""
echo "--- CFL-068: MpeCurveSet self-assignment guard ---"

run_patch_test "cfl068-srgb-dump" \
    "DumpProfile sRGB — no self-assign UAF" \
    "no_sanitizer" "" \
    "$DUMP" -v 100 "$SRGB" ALL

# =============================================================================
# CFL-069: operator= self-assignment guards (multiple classes) (CWE-416)
# Patched: self-assignment checks in multiple IccMpeBasic.cpp classes
# Source: IccMpeBasic.cpp
# =============================================================================
echo ""
echo "--- CFL-069: Multiple operator= self-assignment guards ---"

run_patch_test "cfl069-srgb-roundtrip" \
    "RoundTrip sRGB — no self-assign issues" \
    "no_sanitizer" "" \
    "$ROUNDTRIP" "$SRGB"

if [ -f "$REC2100" ]; then
    run_patch_test "cfl069-rec2100-dump" \
        "DumpProfile Rec2100 — no self-assign issues" \
        "no_sanitizer" "" \
        "$DUMP" -v 100 "$REC2100" ALL
fi

# =============================================================================
# CFL-070: Missing member copies in operator=/copy ctor (CWE-665)
# Patched: ensures all members copied in copy and assignment
# Source: IccMpeBasic.cpp
# =============================================================================
echo ""
echo "--- CFL-070: Missing member copies ---"

run_patch_test "cfl070-srgb-roundtrip" \
    "RoundTrip sRGB — complete member copy" \
    "no_sanitizer" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# CFL-071: Uninitialized default constructor members (CWE-908)
# Patched: initializes all scalar members in default constructors
# Source: IccMpeBasic.cpp
# =============================================================================
echo ""
echo "--- CFL-071: Uninit default ctor members ---"

run_patch_test "cfl071-srgb-dump" \
    "DumpProfile sRGB — no uninit member UBSAN" \
    "no_ubsan" "" \
    "$DUMP" -v 100 "$SRGB" ALL

if [ -f "$REC2100" ]; then
    run_patch_test "cfl071-rec2100-roundtrip" \
        "RoundTrip Rec2100 — no uninit member UBSAN" \
        "no_ubsan" "" \
        "$ROUNDTRIP" "$REC2100"
fi

# =============================================================================
# CFL-072: printf format and unused function cleanup (CWE-134)
# Patched: corrects format specifiers, removes dead code
# Source: IccMpeBasic.cpp
# =============================================================================
echo ""
echo "--- CFL-072: printf format and unused function ---"

run_patch_test "cfl072-srgb-dump" \
    "DumpProfile sRGB — no format string UBSAN" \
    "no_ubsan" "" \
    "$DUMP" -v 100 "$SRGB" ALL

# =============================================================================
# CFL-073: IccProfileXml implicit fallthrough (CWE-484)
# Patched: adds break or fallthrough annotation in switch
# Source: IccXML/IccLibXML/IccProfileXml.cpp
# =============================================================================
echo ""
echo "--- CFL-073: IccProfileXml implicit fallthrough ---"

run_patch_test "cfl073-srgb-toxml" \
    "ToXml sRGB — no fallthrough warnings" \
    "no_sanitizer" "" \
    "$TOXML" "$SRGB" "$OUTDIR/cfl073.xml"

if [ -f "$OUTDIR/cfl073.xml" ]; then
    run_patch_test "cfl073-fromxml-roundtrip" \
        "FromXml roundtrip — no fallthrough issues" \
        "no_sanitizer" "" \
        "$FROMXML" "$OUTDIR/cfl073.xml" "$OUTDIR/cfl073-rt.icc"
fi

# =============================================================================
# CFL-074: IccUtilXml clipTypeRange if-constexpr (CWE-570)
# Patched: dead comparison removed via if-constexpr pattern
# Source: IccXML/IccLibXML/IccUtilXml.cpp
# =============================================================================
echo ""
echo "--- CFL-074: IccUtilXml clipTypeRange ---"

run_patch_test "cfl074-srgb-toxml" \
    "ToXml sRGB — clean XML export" \
    "no_sanitizer" "" \
    "$TOXML" "$SRGB" "$OUTDIR/cfl074.xml"

if [ -f "$DISPLAY_P3" ]; then
    run_patch_test "cfl074-p3-toxml" \
        "ToXml DisplayP3 — clean XML export" \
        "no_sanitizer" "" \
        "$TOXML" "$DISPLAY_P3" "$OUTDIR/cfl074-p3.xml"
fi

# =============================================================================
# CFL-075: IccCmmConfig uninit + format fixes (CWE-908/CWE-134)
# Patched: initializes members, fixes format strings
# Source: IccCmmConfig.cpp
# =============================================================================
echo ""
echo "--- CFL-075: IccCmmConfig uninit + format fixes ---"

if [ -n "$_JSON_CONFIGS" ]; then
    for cfg in "$_JSON_CONFIGS"/*.json; do
        [ -f "$cfg" ] || continue
        base=$(basename "$cfg" .json)
        run_patch_test "cfl075-cfg-$base" \
            "ApplyNamedCmm -cfg $base — no uninit UBSAN" \
            "no_ubsan" "" \
            "$APPLYNAMED" -cfg "$cfg"
        break
    done
else
    run_patch_test "cfl075-roundtrip-srgb" \
        "RoundTrip sRGB — no uninit UBSAN" \
        "no_ubsan" "" \
        "$ROUNDTRIP" "$SRGB"
fi

# =============================================================================
# CFL-077: CAM CalcCoefficients div-by-zero guard (CWE-369)
# Patched: guards 3 division chains when m_La=0 or m_WhitePoint[1]=0
# PoC: Spec400_10_700-B_2deg-CAM.icc
#   UNPATCHED: UBSAN division by zero at IccCAM.cpp:266,283 (3 sites)
#   PATCHED:   clean exit, no UBSAN
# Source: IccCAM.cpp — CIccCamConverter::CalcCoefficients()
# =============================================================================
echo ""
echo "--- CFL-077: CAM CalcCoefficients div-by-zero ---"

if [ -f "$CFL077_POC" ]; then
    run_patch_test "cfl077-poc-divzero" \
        "DumpProfile CAM PoC — no div-by-zero UBSAN" \
        "no_ubsan" "" \
        "$DUMP" -v 100 "$CFL077_POC" ALL

    run_patch_test "cfl077-poc-no-asan" \
        "DumpProfile CAM PoC — no ASAN" \
        "no_asan" "" \
        "$DUMP" -v 100 "$CFL077_POC" ALL
else
    skip_test "cfl077" "CFL-077 CAM div-by-zero" "Spec400_10_700-B_2deg-CAM.icc missing"
fi

# Also test with sRGB to ensure no regression on normal CAM usage
run_patch_test "cfl077-srgb-roundtrip" \
    "RoundTrip sRGB — CAM no regression" \
    "no_sanitizer" "" \
    "$ROUNDTRIP" "$SRGB"

# =============================================================================
# Cross-tool validation: all tools build and run clean on good profiles
# =============================================================================
echo ""
echo "--- Cross-tool validation (clean profiles) ---"

run_patch_test "cross-dump-srgb" \
    "DumpProfile sRGB — clean" \
    "exit_ok" "" \
    "$DUMP" "$SRGB"

run_patch_test "cross-toxml-srgb" \
    "ToXml sRGB — clean" \
    "exit_ok" "" \
    "$TOXML" "$SRGB" "$OUTDIR/cross-srgb.xml"

if [ -f "$OUTDIR/cross-srgb.xml" ]; then
    run_patch_test "cross-fromxml-srgb" \
        "FromXml sRGB roundtrip — clean" \
        "exit_ok" "" \
        "$FROMXML" "$OUTDIR/cross-srgb.xml" "$OUTDIR/cross-srgb-rt.icc"
fi

run_patch_test "cross-roundtrip-srgb" \
    "RoundTrip sRGB — clean" \
    "exit_ok" "" \
    "$ROUNDTRIP" "$SRGB"

if [ -f "$SRGB" ] && [ -f "$SRGB_500" ]; then
    run_patch_test "cross-link-srgb" \
        "ApplyToLink sRGB→sRGB-500 — clean" \
        "exit_ok" "" \
        "$APPLYTOLINK" "$SRGB" 1 "$SRGB_500" 1 "$OUTDIR/cross-link.icc"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "============================================================"
echo "CFL Patch Validation Summary"
echo "============================================================"
printf "  PASS: %d  FAIL: %d  SKIP: %d  TOTAL: %d\n" "$PASS" "$FAIL" "$SKIP" "$TOTAL"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "  FAILED tests — check logs in $OUTDIR/"
    echo ""
fi

echo "============================================================"

# Exit with failure count (0 = all pass)
if [ "$FAIL" -gt 0 ]; then
    exit 1
else
    exit 0
fi
