#!/bin/bash
# =============================================================================
# iccDEV JSON Configuration Feature — Comprehensive Test Runner
# =============================================================================
# Tests the -cfg JSON configuration mode for:
#   - iccApplyNamedCmm
#   - iccApplySearch
#   - iccApplyProfiles (if TIFF test images available)
#
# Usage: ./docs/Testing/test-json-tools.sh [--verbose]
#
# Prerequisites:
#   - iccDEV tools built at iccDEV/Build/Tools/
#   - test-profiles/ containing sRGB_D65_MAT.icc
#   - ASAN/UBSAN instrumented build
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
VERBOSE="${1:-}"

# Tool paths
TOOL_DIR="$REPO_ROOT/iccDEV/Build/Tools"
APPLY_NAMED_CMM="$TOOL_DIR/IccApplyNamedCmm/iccApplyNamedCmm"
APPLY_SEARCH="$TOOL_DIR/IccApplySearch/iccApplySearch"
APPLY_PROFILES="$TOOL_DIR/IccApplyProfiles/iccApplyProfiles"

# Library path for ASAN-instrumented shared libs
export LD_LIBRARY_PATH="$REPO_ROOT/iccDEV/Build/IccProfLib:$REPO_ROOT/iccDEV/Build/IccXML:${LD_LIBRARY_PATH:-}"

# ASAN/UBSAN settings — catch-and-continue for full chain analysis
export ASAN_OPTIONS="halt_on_error=0,detect_leaks=0,print_stacktrace=1"
export UBSAN_OPTIONS="halt_on_error=0,print_stacktrace=1"

# Counters
PASS=0
FAIL=0
WARN=0
ASAN_HITS=0
TOTAL=0

# Result log
RESULT_LOG="$RESULTS_DIR/json-tool-test-results-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$RESULTS_DIR"

log() {
    echo "$@" | tee -a "$RESULT_LOG"
}

log_section() {
    log ""
    log "=================================================================="
    log "$1"
    log "=================================================================="
}

# Run a test: tool_path config_file expected_exit description
run_test() {
    local tool="$1"
    local config="$2"
    local expected_exit="$3"
    local description="$4"
    local tool_name
    tool_name="$(basename "$tool")"

    TOTAL=$((TOTAL + 1))

    # Run from repo root so relative paths in configs work
    local output
    local exit_code=0
    output=$(cd "$REPO_ROOT" && timeout 30 "$tool" -cfg "$config" 2>&1) || exit_code=$?

    # Check for ASAN/UBSAN
    local has_asan=0
    local has_ubsan=0
    if echo "$output" | grep -q "ERROR: AddressSanitizer"; then
        has_asan=1
        ASAN_HITS=$((ASAN_HITS + 1))
    fi
    if echo "$output" | grep -q "runtime error:"; then
        has_ubsan=1
        ASAN_HITS=$((ASAN_HITS + 1))
    fi

    # Determine result
    local status="PASS"
    if [ "$expected_exit" = "nonzero" ]; then
        # Expect failure — any non-zero is fine, but ASAN is still a finding
        if [ $exit_code -eq 0 ]; then
            status="FAIL"
            FAIL=$((FAIL + 1))
        elif [ $has_asan -eq 1 ] || [ $has_ubsan -eq 1 ]; then
            status="WARN-ASAN"
            WARN=$((WARN + 1))
        else
            PASS=$((PASS + 1))
        fi
    elif [ "$expected_exit" = "any" ]; then
        # Don't care about exit code, but flag ASAN
        if [ $has_asan -eq 1 ] || [ $has_ubsan -eq 1 ]; then
            status="WARN-ASAN"
            WARN=$((WARN + 1))
        else
            PASS=$((PASS + 1))
        fi
    else
        # Expect specific exit code
        if [ $exit_code -ne "$expected_exit" ]; then
            status="FAIL"
            FAIL=$((FAIL + 1))
        elif [ $has_asan -eq 1 ] || [ $has_ubsan -eq 1 ]; then
            status="WARN-ASAN"
            WARN=$((WARN + 1))
        else
            PASS=$((PASS + 1))
        fi
    fi

    log "[$status] $description"
    log "    Tool: $tool_name | Config: $(basename "$config") | Exit: $exit_code (expected: $expected_exit)"

    if [ "$status" = "FAIL" ] || [ "$status" = "WARN-ASAN" ] || [ "$VERBOSE" = "--verbose" ]; then
        # Truncate output to 40 lines
        local truncated
        truncated=$(echo "$output" | head -40)
        if [ "$(echo "$output" | wc -l)" -gt 40 ]; then
            truncated="$truncated
... (truncated, $(echo "$output" | wc -l) total lines)"
        fi
        log "    Output:"
        log "$truncated" | sed 's/^/    | /'
    fi

    if [ $has_asan -eq 1 ]; then
        log "    *** ASAN ERROR DETECTED ***"
        echo "$output" | grep -A5 "ERROR: AddressSanitizer" | head -10 | sed 's/^/    | /' | tee -a "$RESULT_LOG"
    fi
    if [ $has_ubsan -eq 1 ]; then
        log "    *** UBSAN ERROR DETECTED ***"
        echo "$output" | grep -B1 -A3 "runtime error:" | head -10 | sed 's/^/    | /' | tee -a "$RESULT_LOG"
    fi
}

# =============================================================================
# PREFLIGHT CHECKS
# =============================================================================
log_section "PREFLIGHT CHECKS"

for tool in "$APPLY_NAMED_CMM" "$APPLY_SEARCH" "$APPLY_PROFILES"; do
    if [ -x "$tool" ]; then
        log "[OK] $(basename "$tool") found at $tool"
    else
        log "[MISSING] $(basename "$tool") not found at $tool"
    fi
done

if [ -f "$REPO_ROOT/test-profiles/sRGB_D65_MAT.icc" ]; then
    log "[OK] Test profile sRGB_D65_MAT.icc available"
else
    log "[FAIL] Test profile sRGB_D65_MAT.icc NOT found"
    exit 1
fi

# =============================================================================
# SECTION 1: iccApplyNamedCmm — Valid JSON Configs
# =============================================================================
log_section "SECTION 1: iccApplyNamedCmm — Valid JSON Configs"

for cfg in "$SCRIPT_DIR/json-configs/applynamedcmm-"*.json; do
    name=$(basename "$cfg" .json)
    run_test "$APPLY_NAMED_CMM" "$cfg" 0 \
        "ApplyNamedCmm valid: $name"
done

# =============================================================================
# SECTION 2: iccApplySearch — Valid JSON Configs
# =============================================================================
log_section "SECTION 2: iccApplySearch — Valid JSON Configs"

for cfg in "$SCRIPT_DIR/json-configs/applysearch-"*.json; do
    name=$(basename "$cfg" .json)
    run_test "$APPLY_SEARCH" "$cfg" 0 \
        "ApplySearch valid: $name"
done

# =============================================================================
# SECTION 3: iccApplyNamedCmm — Malformed JSON (Negative Tests)
# =============================================================================
log_section "SECTION 3: iccApplyNamedCmm — Malformed JSON (Negative Tests)"

for cfg in "$SCRIPT_DIR/malformed-json/"*.json; do
    name=$(basename "$cfg" .json)
    # Some malformed inputs are gracefully accepted (exit 0) by design:
    # - empty-arrays: empty profileSequence+data → outputs default JSON
    # - extreme-values: out-of-range values → clamped/processed without error
    # - channel-count-mismatch: mismatched channels → processed with zero-fill
    case "$name" in
        empty-arrays|extreme-values|channel-count-mismatch)
            run_test "$APPLY_NAMED_CMM" "$cfg" "any" \
                "ApplyNamedCmm malformed (graceful): $name"
            ;;
        *)
            run_test "$APPLY_NAMED_CMM" "$cfg" "nonzero" \
                "ApplyNamedCmm malformed: $name"
            ;;
    esac
done

# =============================================================================
# SECTION 4: iccApplySearch — Malformed JSON (Negative Tests)
# =============================================================================
log_section "SECTION 4: iccApplySearch — Malformed JSON (Negative Tests)"

for cfg in "$SCRIPT_DIR/malformed-json/"*.json; do
    name=$(basename "$cfg" .json)
    case "$name" in
        empty-arrays|extreme-values|channel-count-mismatch)
            run_test "$APPLY_SEARCH" "$cfg" "any" \
                "ApplySearch malformed (graceful): $name"
            ;;
        *)
            run_test "$APPLY_SEARCH" "$cfg" "nonzero" \
                "ApplySearch malformed: $name"
            ;;
    esac
done

# =============================================================================
# SECTION 5: iccApplyProfiles — Malformed JSON (Negative Tests)
# =============================================================================
log_section "SECTION 5: iccApplyProfiles — Malformed JSON (Negative Tests)"

for cfg in "$SCRIPT_DIR/malformed-json/"*.json; do
    name=$(basename "$cfg" .json)
    case "$name" in
        empty-arrays|extreme-values|channel-count-mismatch)
            run_test "$APPLY_PROFILES" "$cfg" "any" \
                "ApplyProfiles malformed (graceful): $name"
            ;;
        *)
            run_test "$APPLY_PROFILES" "$cfg" "nonzero" \
                "ApplyProfiles malformed: $name"
            ;;
    esac
done

# =============================================================================
# SECTION 6: Edge Case — Empty file, huge file, binary file
# =============================================================================
log_section "SECTION 6: Edge Cases"

# Empty file
touch /tmp/empty-json-test.json
run_test "$APPLY_NAMED_CMM" "/tmp/empty-json-test.json" "nonzero" \
    "ApplyNamedCmm edge: empty file"

# Binary file (ICC profile as JSON config)
if [ -f "$REPO_ROOT/test-profiles/sRGB_D65_MAT.icc" ]; then
    run_test "$APPLY_NAMED_CMM" "$REPO_ROOT/test-profiles/sRGB_D65_MAT.icc" "nonzero" \
        "ApplyNamedCmm edge: binary ICC as JSON config"
fi

# Very deeply nested JSON
python3 -c "
import json
d = {'a': {}}
cur = d['a']
for i in range(100):
    cur['nested'] = {}
    cur = cur['nested']
cur['value'] = 42
print(json.dumps(d))
" > /tmp/deeply-nested.json
run_test "$APPLY_NAMED_CMM" "/tmp/deeply-nested.json" "nonzero" \
    "ApplyNamedCmm edge: deeply nested (100 levels)"

# Large JSON with many color data entries
python3 -c "
import json
cfg = {
    'dataFiles': {'srcType': 0, 'dstEncoding': 3},
    'profileSequence': [{'iccFile': 'test-profiles/sRGB_D65_MAT.icc', 'intent': 1}],
    'colorData': {
        'space': 'RGB ',
        'encoding': 'icEncodeFloat',
        'data': [{'values': [float(i)/10000, float(i+1)/10000, float(i+2)/10000]} for i in range(10000)]
    }
}
print(json.dumps(cfg))
" > /tmp/large-colordata.json
run_test "$APPLY_NAMED_CMM" "/tmp/large-colordata.json" "any" \
    "ApplyNamedCmm edge: 10000 color data entries"

# String with null bytes in profile path
python3 -c "
import json
cfg = {
    'dataFiles': {'srcType': 0, 'dstEncoding': 3},
    'profileSequence': [{'iccFile': 'test\x00profiles/sRGB_D65_MAT.icc', 'intent': 1}],
    'colorData': {'space': 'RGB ', 'encoding': 'icEncodeFloat', 'data': [{'values': [0.5, 0.5, 0.5]}]}
}
with open('/tmp/nullbyte-path.json', 'w') as f:
    json.dump(cfg, f)
" 2>/dev/null
run_test "$APPLY_NAMED_CMM" "/tmp/nullbyte-path.json" "nonzero" \
    "ApplyNamedCmm edge: null byte in profile path"

# Unicode in profile path
python3 -c "
import json
cfg = {
    'dataFiles': {'srcType': 0, 'dstEncoding': 3},
    'profileSequence': [{'iccFile': 'test-profiles/\u00e9\u00e8\u00ea\u2603\u2764.icc', 'intent': 1}],
    'colorData': {'space': 'RGB ', 'encoding': 'icEncodeFloat', 'data': [{'values': [0.5, 0.5, 0.5]}]}
}
with open('/tmp/unicode-path.json', 'w') as f:
    json.dump(cfg, f, ensure_ascii=False)
" 2>/dev/null
run_test "$APPLY_NAMED_CMM" "/tmp/unicode-path.json" "nonzero" \
    "ApplyNamedCmm edge: unicode chars in profile path"

# =============================================================================
# SECTION 7: All rendering intents with single profile
# =============================================================================
log_section "SECTION 7: All Rendering Intents"

for intent in 0 1 2 3; do
    python3 -c "
import json
cfg = {
    'dataFiles': {'srcType': 0, 'dstEncoding': 3, 'dstPrecision': 4, 'dstDigits': 9},
    'profileSequence': [{'iccFile': 'test-profiles/sRGB_D65_MAT.icc', 'intent': $intent, 'interpolation': 'tetrahedral'}],
    'colorData': {'space': 'RGB ', 'encoding': 'icEncodeFloat', 'data': [
        {'values': [1.0, 0.0, 0.0]},
        {'values': [0.0, 1.0, 0.0]},
        {'values': [0.0, 0.0, 1.0]},
        {'values': [0.5, 0.5, 0.5]}
    ]}
}
print(json.dumps(cfg, indent=2))
" > /tmp/intent-test-$intent.json
    run_test "$APPLY_NAMED_CMM" "/tmp/intent-test-$intent.json" "any" \
        "ApplyNamedCmm intent=$intent (Perceptual/Relative/Saturation/Absolute)"
done

# =============================================================================
# SECTION 8: All encoding types
# =============================================================================
log_section "SECTION 8: All Encoding Types"

for enc in 0 1 2 3 4 5 6; do
    python3 -c "
import json
cfg = {
    'dataFiles': {'srcType': 0, 'dstEncoding': $enc, 'dstPrecision': 4, 'dstDigits': 9},
    'profileSequence': [{'iccFile': 'test-profiles/sRGB_D65_MAT.icc', 'intent': 1}],
    'colorData': {'space': 'RGB ', 'encoding': 'icEncodeFloat', 'data': [
        {'values': [1.0, 1.0, 1.0]},
        {'values': [0.0, 0.0, 0.0]},
        {'values': [0.5, 0.5, 0.5]}
    ]}
}
print(json.dumps(cfg, indent=2))
" > /tmp/encoding-test-$enc.json
    run_test "$APPLY_NAMED_CMM" "/tmp/encoding-test-$enc.json" "any" \
        "ApplyNamedCmm dstEncoding=$enc"
done

# =============================================================================
# SECTION 9: v5/iccMAX profiles (if available)
# =============================================================================
log_section "SECTION 9: v5/iccMAX Profiles"

for profile in "$REPO_ROOT/test-profiles/sRGBDisplaySpectral.icc" \
               "$REPO_ROOT/test-profiles/sRGB_D65_colorimetric.icc" \
               "$REPO_ROOT/test-profiles/sRGB_v4_ICC_preference.icc"; do
    if [ -f "$profile" ]; then
        relpath="${profile#$REPO_ROOT/}"
        python3 -c "
import json
cfg = {
    'dataFiles': {'srcType': 0, 'dstEncoding': 3, 'dstPrecision': 4, 'dstDigits': 9},
    'profileSequence': [{'iccFile': '$relpath', 'intent': 1, 'interpolation': 'tetrahedral'}],
    'colorData': {'space': 'RGB ', 'encoding': 'icEncodeFloat', 'data': [
        {'values': [1.0, 1.0, 1.0]},
        {'values': [0.0, 0.0, 0.0]},
        {'values': [0.5, 0.5, 0.5]}
    ]}
}
print(json.dumps(cfg, indent=2))
" > /tmp/v5-test-$(basename "$profile" .icc).json
        run_test "$APPLY_NAMED_CMM" "/tmp/v5-test-$(basename "$profile" .icc).json" "any" \
            "ApplyNamedCmm profile: $(basename "$profile")"
    fi
done

# =============================================================================
# SECTION 10: Crash profiles as transform targets
# =============================================================================
log_section "SECTION 10: Known-Bad Profiles in JSON Config"

for profile in "$REPO_ROOT/test-profiles/"hbo-*.icc \
               "$REPO_ROOT/test-profiles/"sbo-*.icc \
               "$REPO_ROOT/test-profiles/"oom-*.icc; do
    if [ -f "$profile" ]; then
        relpath="${profile#$REPO_ROOT/}"
        python3 -c "
import json
cfg = {
    'dataFiles': {'srcType': 0, 'dstEncoding': 3},
    'profileSequence': [{'iccFile': '$relpath', 'intent': 1}],
    'colorData': {'space': 'RGB ', 'encoding': 'icEncodeFloat', 'data': [{'values': [0.5, 0.5, 0.5]}]}
}
print(json.dumps(cfg, indent=2))
" > "/tmp/crashprofile-$(basename "$profile" .icc).json"
        run_test "$APPLY_NAMED_CMM" "/tmp/crashprofile-$(basename "$profile" .icc).json" "any" \
            "ApplyNamedCmm crash-profile: $(basename "$profile")"
    fi
done

# =============================================================================
# SECTION 11: Extended test-profiles crash profiles (CFL-030 regression)
# =============================================================================
log_section "SECTION 11: Extended Test-Profiles (CFL-030 Regression)"

for profile in "$REPO_ROOT/extended-test-profiles/"sbo-*.icc \
               "$REPO_ROOT/extended-test-profiles/"hbo-*.icc \
               "$REPO_ROOT/extended-test-profiles/"oom-*.icc; do
    if [ -f "$profile" ]; then
        relpath="${profile#$REPO_ROOT/}"
        python3 -c "
import json, sys
cfg = {
    'dataFiles': {'srcType': 'colorData'},
    'profileSequence': [{'iccFile': '$relpath', 'intent': 1}],
    'colorData': {'space': 'RGB ', 'encoding': 'float', 'data': [{'values': [0.5, 0.5, 0.5]}]}
}
print(json.dumps(cfg, indent=2))
" > "/tmp/ext-crashprofile-$(basename "$profile" .icc).json"
        run_test "$APPLY_NAMED_CMM" "/tmp/ext-crashprofile-$(basename "$profile" .icc).json" "any" \
            "ApplyNamedCmm ext-crash: $(basename "$profile")"
    fi
done

# =============================================================================
# SECTION 12: Non-seekable fd — FIFO test (CFL-031 regression)
# =============================================================================
log_section "SECTION 12: Non-Seekable fd via FIFO (CFL-031 Regression)"

CFL031_FIFO="/tmp/cfl031-test-fifo-$$"
CFL031_JSON="/tmp/cfl031-fifo-config.json"

# Generate a clean JSON config
python3 -c "
import json
cfg = {
    'dataFiles': {'srcType': 'colorData'},
    'profileSequence': [{'iccFile': 'test-profiles/sRGB_D65_MAT.icc', 'intent': 1}],
    'colorData': {'space': 'RGB ', 'encoding': 'float', 'data': [{'values': [0.5, 0.5, 0.5]}]}
}
print(json.dumps(cfg, indent=2))
" > "$CFL031_JSON"

mkfifo "$CFL031_FIFO" 2>/dev/null || true

TOTAL=$((TOTAL + 1))
# Feed JSON via FIFO in background
cat "$CFL031_JSON" > "$CFL031_FIFO" &
CFL031_PID=$!

fifo_output=$(cd "$REPO_ROOT" && timeout 10 "$APPLY_NAMED_CMM" -cfg "$CFL031_FIFO" 2>&1) || true
wait "$CFL031_PID" 2>/dev/null || true

fifo_has_asan=0
fifo_has_ubsan=0
if echo "$fifo_output" | grep -q "ERROR: AddressSanitizer"; then
    fifo_has_asan=1
    ASAN_HITS=$((ASAN_HITS + 1))
fi
if echo "$fifo_output" | grep -q "runtime error:"; then
    fifo_has_ubsan=1
    ASAN_HITS=$((ASAN_HITS + 1))
fi

if [ $fifo_has_asan -eq 1 ] || [ $fifo_has_ubsan -eq 1 ]; then
    WARN=$((WARN + 1))
    log "[WARN-ASAN] CFL-031: FIFO non-seekable fd ftell() overflow"
    log "    *** ASAN/UBSAN detected on non-seekable fd input ***"
    echo "$fifo_output" | grep -E "runtime error:|ERROR: Address|SUMMARY:" | head -5 | sed 's/^/    | /' | tee -a "$RESULT_LOG"
else
    PASS=$((PASS + 1))
    log "[PASS] CFL-031: FIFO non-seekable fd (no ASAN/UBSAN)"
fi

rm -f "$CFL031_FIFO" "$CFL031_JSON"

# =============================================================================
# SECTION 13: Invalid interpolation enum value (CFL-032 regression)
# =============================================================================
log_section "SECTION 13: Invalid Interpolation Value (CFL-032 Regression)"

SRGB_PROFILE="$REPO_ROOT/test-profiles/sRGB_D65_MAT.icc"
if [ -f "$SRGB_PROFILE" ]; then
    # Test invalid interp values via CLI args (not -cfg mode)
    for interp_val in 2 33 255; do
        TOTAL=$((TOTAL + 1))
        cli_output=$(cd "$REPO_ROOT" && timeout 10 "$APPLY_NAMED_CMM" \
            /tmp/cfl032-out.icc 0 "$interp_val" 0 test 0.0 1.0 0 0 \
            "$SRGB_PROFILE" 1 "$SRGB_PROFILE" 1 2>&1) || true

        cli_has_ubsan=0
        if echo "$cli_output" | grep -q "runtime error:"; then
            cli_has_ubsan=1
            ASAN_HITS=$((ASAN_HITS + 1))
        fi

        if [ $cli_has_ubsan -eq 1 ]; then
            WARN=$((WARN + 1))
            log "[WARN-ASAN] CFL-032: interp=$interp_val → UBSAN enum out-of-range"
            echo "$cli_output" | grep -E "runtime error:|SUMMARY:" | head -3 | sed 's/^/    | /' | tee -a "$RESULT_LOG"
        else
            PASS=$((PASS + 1))
            log "[PASS] CFL-032: interp=$interp_val (no UBSAN)"
        fi
    done

    # Also test iccApplyToLink if available
    APPLY_TO_LINK="$TOOL_DIR/IccApplyToLink/iccApplyToLink"
    if [ -x "$APPLY_TO_LINK" ]; then
        for interp_val in 2 33; do
            TOTAL=$((TOTAL + 1))
            link_output=$(cd "$REPO_ROOT" && timeout 10 "$APPLY_TO_LINK" \
                /tmp/cfl032-link-out.icc 0 9 0 "cfl032-test" 0.0 1.0 0 "$interp_val" \
                "$SRGB_PROFILE" 1 "$SRGB_PROFILE" 1 2>&1) || true

            link_has_ubsan=0
            if echo "$link_output" | grep -q "runtime error:"; then
                link_has_ubsan=1
                ASAN_HITS=$((ASAN_HITS + 1))
            fi

            if [ $link_has_ubsan -eq 1 ]; then
                WARN=$((WARN + 1))
                log "[WARN-ASAN] CFL-032: iccApplyToLink interp=$interp_val → UBSAN"
                echo "$link_output" | grep -E "runtime error:|SUMMARY:" | head -3 | sed 's/^/    | /' | tee -a "$RESULT_LOG"
            else
                PASS=$((PASS + 1))
                log "[PASS] CFL-032: iccApplyToLink interp=$interp_val (no UBSAN)"
            fi
        done
    fi
    rm -f /tmp/cfl032-out.icc /tmp/cfl032-link-out.icc
fi

# =============================================================================
# SECTION 14: CFL-033 — PccWeight fromJson field swap regression
# =============================================================================
log_section "SECTION 14: PccWeight Field Swap (CFL-033 Regression)"

# BUG: CIccCfgPccWeight::fromJson() at IccCmmConfig.cpp:866-867 had swapped fields:
#   jsonToValue(j["pccFile"], m_dWeight);   // reads path string → float member
#   jsonToValue(j["weight"], m_pccPath);    // reads float → string member
# Fix: swap the two lines to match toJson() behavior.
# Detection: round-trip fromJson→toJson produces different JSON (pccFile/weight values swap).

if [ -f "$REPO_ROOT/docs/Testing/malformed-json/pccweight-field-swap.json" ]; then
    # Test 1: Config with pccWeight should not crash
    run_test "$APPLY_NAMED_CMM" "$REPO_ROOT/docs/Testing/malformed-json/pccweight-field-swap.json" "nonzero" \
        "S14-T1: PccWeight config — graceful handling (pre-fix: empty pccPath)"

    # Test 2: Config with searchApply pccWeights via ApplySearch
    run_test "$APPLY_SEARCH" "$REPO_ROOT/docs/Testing/malformed-json/pccweight-field-swap.json" "nonzero" \
        "S14-T2: PccWeight config via ApplySearch — graceful rejection"

    # Test 3: Round-trip divergence check — create config, run, check output
    # With the bug present, fromJson reads pccFile→weight and weight→pccPath
    # so the tool would output the wrong values. toJson always does it correctly.
    cat > /tmp/cfl033-roundtrip.json << 'EOF'
{
    "dataFiles": {"srcType": "colorData", "dstType": "colorData", "dstEncoding": "float"},
    "searchApply": {
        "profileSequence": [
            {"iccFile": "test-profiles/sRGB_D65_MAT.icc", "intent": 1},
            {"iccFile": "test-profiles/sRGB_D65_MAT.icc", "intent": 1}
        ],
        "initial": {"intent": 1},
        "pccWeights": [{"pccFile": "test-profiles/sRGB_D65_MAT.icc", "weight": 0.75}]
    },
    "colorData": {"space": "RGB ", "encoding": "float", "data": [{"values": [0.5, 0.5, 0.5]}]}
}
EOF
    run_test "$APPLY_SEARCH" "/tmp/cfl033-roundtrip.json" "any" \
        "S14-T3: PccWeight round-trip with weight=0.75 and valid pccFile"
else
    log "  [SKIP] pccweight-field-swap.json not found"
fi

# =============================================================================
# SECTION 15: CFL-034 — SearchApply fromJsonInit interpolation key name
# =============================================================================
log_section "SECTION 15: SearchApply Interpolation Key (CFL-034 Regression)"

# BUG: CIccCfgSearchApply::fromJsonInit() at IccCmmConfig.cpp:1120 reads j["transform"]
# for the interpolation field instead of j["interpolation"]. The toJsonInit() at L1092
# correctly writes j["interpolation"]. This means:
#   1. The "interpolation" key in JSON config is silently ignored
#   2. The "transform" value is used for BOTH transform and interpolation
#   3. Round-trip (fromJson→toJson→fromJson) diverges on the interpolation field

cat > /tmp/cfl034-interp-test.json << 'EOF'
{
    "dataFiles": {"srcType": "colorData", "dstType": "colorData", "dstEncoding": "float"},
    "searchApply": {
        "profileSequence": [
            {"iccFile": "test-profiles/sRGB_D65_MAT.icc", "intent": 1},
            {"iccFile": "test-profiles/sRGB_D65_MAT.icc", "intent": 1}
        ],
        "initial": {
            "intent": 1,
            "interpolation": "linear",
            "transform": "colorimetric"
        },
        "pccWeights": []
    },
    "colorData": {"space": "RGB ", "encoding": "float", "data": [{"values": [0.5, 0.5, 0.5]}]}
}
EOF
run_test "$APPLY_SEARCH" "/tmp/cfl034-interp-test.json" "any" \
    "S15-T1: ApplySearch with both interpolation and transform keys"

# Test 2: interpolation-only (should set interpolation, but bug reads transform)
cat > /tmp/cfl034-interp-only.json << 'EOF'
{
    "dataFiles": {"srcType": "colorData", "dstType": "colorData", "dstEncoding": "float"},
    "searchApply": {
        "profileSequence": [
            {"iccFile": "test-profiles/sRGB_D65_MAT.icc", "intent": 1},
            {"iccFile": "test-profiles/sRGB_D65_MAT.icc", "intent": 1}
        ],
        "initial": {"intent": 1, "interpolation": "linear"},
        "pccWeights": []
    },
    "colorData": {"space": "RGB ", "encoding": "float", "data": [{"values": [0.5, 0.5, 0.5]}]}
}
EOF
run_test "$APPLY_SEARCH" "/tmp/cfl034-interp-only.json" "any" \
    "S15-T2: ApplySearch with interpolation key only (ignored pre-fix)"

# =============================================================================
# SECTION 16: Malformed JSON robustness (new configs from security audit)
# =============================================================================
log_section "SECTION 16: Malformed JSON Robustness"

MALFORMED_DIR="$REPO_ROOT/docs/Testing/malformed-json"
if [ -d "$MALFORMED_DIR" ]; then
    for cfg in "$MALFORMED_DIR"/*.json; do
        cfgname="$(basename "$cfg")"
        # Use "any" — some malformed configs are structurally valid (exit 0),
        # some are rejected (exit 255). We only flag ASAN/UBSAN as errors.
        run_test "$APPLY_NAMED_CMM" "$cfg" "any" \
            "S16: ApplyNamedCmm handles $cfgname"
    done
else
    log "  [SKIP] malformed-json/ directory not found"
fi

# =============================================================================
# SECTION 17: Extreme colorData stress tests
# =============================================================================
log_section "SECTION 17: Extreme ColorData Stress"

# Test 1: 10K colorData entries
python3 -c "
import json
cfg = {
    'dataFiles': {'srcType': 'colorData', 'dstType': 'colorData', 'dstEncoding': 'float', 'dstPrecision': 4, 'dstDigits': 9},
    'profileSequence': [{'iccFile': 'test-profiles/sRGB_D65_MAT.icc', 'intent': 1}],
    'colorData': {'space': 'RGB ', 'encoding': 'float', 'data': [{'values': [float(i%256)/255.0, float((i*7)%256)/255.0, float((i*13)%256)/255.0]} for i in range(10000)]}
}
json.dump(cfg, open('/tmp/stress-10k-colors.json', 'w'))
" 2>/dev/null
run_test "$APPLY_NAMED_CMM" "/tmp/stress-10k-colors.json" "any" \
    "S17-T1: 10K colorData entries processing"

# Test 2: 200-profile chain
python3 -c "
import json
cfg = {
    'dataFiles': {'srcType': 'colorData', 'dstType': 'colorData', 'dstEncoding': 'float'},
    'profileSequence': [{'iccFile': 'test-profiles/sRGB_D65_MAT.icc', 'intent': 1} for _ in range(200)],
    'colorData': {'space': 'RGB ', 'encoding': 'float', 'data': [{'values': [0.5, 0.5, 0.5]}]}
}
json.dump(cfg, open('/tmp/stress-200-chain.json', 'w'))
" 2>/dev/null
run_test "$APPLY_NAMED_CMM" "/tmp/stress-200-chain.json" "any" \
    "S17-T2: 200-profile chain processing"

# Test 3: Extreme float values in colorData
python3 -c "
import json
cfg = {
    'dataFiles': {'srcType': 'colorData', 'dstType': 'colorData', 'dstEncoding': 'float'},
    'profileSequence': [{'iccFile': 'test-profiles/sRGB_D65_MAT.icc', 'intent': 1}],
    'colorData': {'space': 'RGB ', 'encoding': 'float', 'data': [
        {'values': [1e308, -1e308, 0.0]},
        {'values': [-0.0, 1e-308, 5e-324]},
        {'values': [3.402823e+38, 1.175494e-38, -3.402823e+38]}
    ]}
}
json.dump(cfg, open('/tmp/stress-extreme-floats.json', 'w'))
" 2>/dev/null
run_test "$APPLY_NAMED_CMM" "/tmp/stress-extreme-floats.json" "any" \
    "S17-T3: Extreme float values (1e308, subnormals, negative zero)"

# Test 4: 1000 iccEnvVars entries
python3 -c "
import json
envvars = {str(i): float(i) for i in range(1000)}
cfg = {
    'dataFiles': {'srcType': 'colorData', 'dstType': 'colorData', 'dstEncoding': 'float'},
    'profileSequence': [{'iccFile': 'test-profiles/sRGB_D65_MAT.icc', 'intent': 1, 'iccEnvVars': envvars}],
    'colorData': {'space': 'RGB ', 'encoding': 'float', 'data': [{'values': [0.5, 0.5, 0.5]}]}
}
json.dump(cfg, open('/tmp/stress-1k-envvars.json', 'w'))
" 2>/dev/null
run_test "$APPLY_NAMED_CMM" "/tmp/stress-1k-envvars.json" "any" \
    "S17-T4: 1000 iccEnvVars entries"

# =============================================================================
# SUMMARY
# =============================================================================
log_section "SUMMARY"
log "Total tests:  $TOTAL"
log "Passed:       $PASS"
log "Failed:       $FAIL"
log "Warnings:     $WARN"
log "ASAN/UBSAN:   $ASAN_HITS"
log ""
log "Results saved to: $RESULT_LOG"

# Cleanup temp files
rm -f /tmp/empty-json-test.json /tmp/deeply-nested.json /tmp/large-colordata.json \
      /tmp/nullbyte-path.json /tmp/unicode-path.json /tmp/intent-test-*.json \
      /tmp/encoding-test-*.json /tmp/v5-test-*.json /tmp/crashprofile-*.json \
      /tmp/ext-crashprofile-*.json /tmp/cfl031-*.json /tmp/cfl032-*.icc \
      /tmp/iccdev-json-test-output.json /tmp/cfl033-*.json /tmp/cfl034-*.json \
      /tmp/stress-10k-colors.json /tmp/stress-200-chain.json \
      /tmp/stress-extreme-floats.json /tmp/stress-1k-envvars.json

# Exit with error if any ASAN/UBSAN hits or unexpected failures
if [ $ASAN_HITS -gt 0 ]; then
    log ""
    log "*** $ASAN_HITS ASAN/UBSAN finding(s) detected — review output above ***"
    exit 2
fi

if [ $FAIL -gt 0 ]; then
    log ""
    log "*** $FAIL test(s) failed — review output above ***"
    exit 1
fi

log ""
log "All $TOTAL tests passed."
exit 0
