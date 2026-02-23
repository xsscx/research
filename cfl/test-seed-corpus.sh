#!/bin/bash
# Test Seed Corpus - Verify fuzzer corpus integrity
# Based on: WORKFLOW_REFERENCE_BASELINE.md patterns
# Created: 2026-02-06

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../../Build/Testing/Fuzzing"

echo "═══════════════════════════════════════════════════════"
echo "  Fuzzer Seed Corpus Test"
echo "═══════════════════════════════════════════════════════"
echo ""

# Check if fuzzers are built
if [ ! -d "$BUILD_DIR" ]; then
    echo "[FAIL] ERROR: Build directory not found at $BUILD_DIR"
    echo "Please build fuzzers first: cd Build && cmake Cmake && make"
    exit 1
fi

FUZZERS=(
    "icc_apply_fuzzer"
    "icc_applynamedcmm_fuzzer"
    "icc_applyprofiles_fuzzer"
    "icc_calculator_fuzzer"
    "icc_dump_fuzzer"
    "icc_fromcube_fuzzer"
    "icc_fromxml_fuzzer"
    "icc_io_fuzzer"
    "icc_link_fuzzer"
    "icc_multitag_fuzzer"
    "icc_profile_fuzzer"
    "icc_roundtrip_fuzzer"
    "icc_specsep_fuzzer"
    "icc_spectral_fuzzer"
    "icc_toxml_fuzzer"
    "icc_v5dspobs_fuzzer"
)

declare -A FUZZER_DICTS
FUZZER_DICTS[icc_apply_fuzzer]="icc_apply_fuzzer.dict"
FUZZER_DICTS[icc_applynamedcmm_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_applyprofiles_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_calculator_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_dump_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_fromcube_fuzzer]="icc_fromcube_fuzzer.dict"
FUZZER_DICTS[icc_fromxml_fuzzer]="icc_xml_consolidated.dict"
FUZZER_DICTS[icc_io_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_link_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_multitag_fuzzer]="icc_multitag.dict"
FUZZER_DICTS[icc_profile_fuzzer]="icc_profile.dict"
FUZZER_DICTS[icc_roundtrip_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_specsep_fuzzer]="icc_specsep_fuzzer.dict"
FUZZER_DICTS[icc_spectral_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_toxml_fuzzer]="icc_xml_consolidated.dict"
FUZZER_DICTS[icc_v5dspobs_fuzzer]="icc_v5dspobs_fuzzer.dict"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

printf "%-35s %-15s %-15s %s\n" "Fuzzer" "Executable" "Dictionary" "Corpus"
echo "────────────────────────────────────────────────────────────────────────────────────"

for fuzzer in "${FUZZERS[@]}"; do
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # Check executable
    if [ -f "$BUILD_DIR/$fuzzer" ] && [ -x "$BUILD_DIR/$fuzzer" ]; then
        EXE_STATUS="[OK]"
    else
        EXE_STATUS="[FAIL]"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    # Check dictionary
    dict="${FUZZER_DICTS[$fuzzer]}"
    if [ -f "$SCRIPT_DIR/$dict" ]; then
        DICT_STATUS="[OK]"
    else
        DICT_STATUS="[FAIL]"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    # Check corpus
    corpus_dir="$SCRIPT_DIR/${fuzzer}_seed_corpus"
    if [ -d "$corpus_dir" ]; then
        count=$(find "$corpus_dir" -type f | wc -l)
        if [ "$count" -gt 0 ]; then
            CORPUS_STATUS="[OK] ($count files)"
        else
            CORPUS_STATUS="[WARN]  (0 files)"
        fi
    else
        CORPUS_STATUS="[FAIL]"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    # All checks passed?
    if [ "$EXE_STATUS" = "[OK]" ] && [ "$DICT_STATUS" = "[OK]" ] && [[ "$CORPUS_STATUS" == [OK]* ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    fi
    
    printf "%-35s %-15s %-15s %s\n" "$fuzzer" "$EXE_STATUS" "$DICT_STATUS" "$CORPUS_STATUS"
done

echo "────────────────────────────────────────────────────────────────────────────────────"
echo ""
echo "Summary:"
echo "  Total Fuzzers: $TOTAL_TESTS"
echo "  Ready:         $PASSED_TESTS [OK]"
echo "  Issues:        $FAILED_TESTS [FAIL]"
echo ""

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo "[OK] All fuzzers ready for testing!"
    echo ""
    echo "Quick test (5s per fuzzer):"
    echo "  cd $BUILD_DIR"
    for fuzzer in "${FUZZERS[@]}"; do
        dict="${FUZZER_DICTS[$fuzzer]}"
        echo "  ./$fuzzer -dict=$SCRIPT_DIR/$dict -max_total_time=5 $SCRIPT_DIR/${fuzzer}_seed_corpus"
    done
    exit 0
else
    echo "[FAIL] Some fuzzers have issues. Please check and resolve."
    exit 1
fi
