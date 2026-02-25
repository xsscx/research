#!/bin/bash
# Fuzzer Corpus Seeding Script
# Based on: WORKFLOW_REFERENCE_BASELINE.md patterns
# Created: 2026-02-06
# Purpose: Populate fuzzer seed corpus from existing test files

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CFL_DIR="$REPO_ROOT/cfl"
FUZZ_BASE="$REPO_ROOT/../fuzz"

echo "═══════════════════════════════════════════════════════"
echo "  Fuzzer Corpus Seeding - CFL Campaign"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "CFL Dir: $CFL_DIR"
echo "Repo Root: $REPO_ROOT"
echo "Fuzz Base: $FUZZ_BASE"
echo ""

# Verify fuzz directory exists
if [ ! -d "$FUZZ_BASE" ]; then
    echo "[FAIL] ERROR: Fuzz directory not found at $FUZZ_BASE"
    exit 1
fi

# Create seed corpus directories for each fuzzer
FUZZERS=(
    "icc_apply_fuzzer"
    "icc_applynamedcmm_fuzzer"
    "icc_applyprofiles_fuzzer"
    "icc_calculator_fuzzer"
    "icc_deep_dump_fuzzer"
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
    "icc_spectral_b_fuzzer"
    "icc_tiffdump_fuzzer"
    "icc_toxml_fuzzer"
    "icc_v5dspobs_fuzzer"
)

echo "Creating seed corpus directories..."
for fuzzer in "${FUZZERS[@]}"; do
    mkdir -p "$CFL_DIR/${fuzzer}_seed_corpus"
    echo "  [OK] $fuzzer"
done
echo ""

# Seed ICC profile-based fuzzers from graphics/icc
echo "Seeding ICC profile fuzzers from graphics/icc..."
ICC_COUNT=0
if [ -d "$FUZZ_BASE/graphics/icc" ]; then
    for icc_file in "$FUZZ_BASE/graphics/icc"/*.icc; do
        if [ -f "$icc_file" ]; then
            basename_file=$(basename "$icc_file")
            
            # Copy to profile-based fuzzers
            for fuzzer in icc_profile_fuzzer icc_io_fuzzer icc_dump_fuzzer icc_deep_dump_fuzzer icc_roundtrip_fuzzer icc_apply_fuzzer icc_applyprofiles_fuzzer icc_applynamedcmm_fuzzer icc_calculator_fuzzer icc_link_fuzzer icc_multitag_fuzzer icc_spectral_fuzzer icc_spectral_b_fuzzer icc_v5dspobs_fuzzer; do
                cp "$icc_file" "$CFL_DIR/${fuzzer}_seed_corpus/$basename_file"
            done
            ICC_COUNT=$((ICC_COUNT + 1))
        fi
    done
    echo "  [OK] Copied $ICC_COUNT ICC files to 12 profile fuzzers"
else
    echo "  [WARN] graphics/icc directory not found"
fi
echo ""

# Seed XML-based fuzzers from xml/icc
echo "Seeding XML fuzzers from xml/icc..."
XML_COUNT=0
if [ -d "$FUZZ_BASE/xml/icc" ]; then
    for xml_file in "$FUZZ_BASE/xml/icc"/*.xml; do
        if [ -f "$xml_file" ]; then
            basename_file=$(basename "$xml_file")
            
            # Copy to XML fuzzers
            for fuzzer in icc_fromxml_fuzzer icc_toxml_fuzzer; do
                cp "$xml_file" "$CFL_DIR/${fuzzer}_seed_corpus/$basename_file"
            done
            XML_COUNT=$((XML_COUNT + 1))
        fi
    done
    echo "  [OK] Copied $XML_COUNT XML files to 2 XML fuzzers"
else
    echo "  [WARN] xml/icc directory not found"
fi
echo ""

# Add spectral-specific files if they exist
echo "Seeding spectral fuzzer with TIFF files..."
TIFF_COUNT=0
if [ -d "$FUZZ_BASE/graphics/tiff" ]; then
    find "$FUZZ_BASE/graphics/tiff" -type f \( -name "*.tiff" -o -name "*.tif" \) -print0 2>/dev/null | while IFS= read -r -d '' tiff_file; do
        cp "$tiff_file" "$CFL_DIR/icc_specsep_fuzzer_seed_corpus/$(basename "$tiff_file")"
        TIFF_COUNT=$((TIFF_COUNT + 1))
    done
    echo "  [OK] Copied $TIFF_COUNT TIFF files to specsep fuzzer"
else
    echo "  [WARN] graphics/tiff directory not found"
fi
echo ""

# Report corpus sizes
echo "═══════════════════════════════════════════════════════"
echo "  Seed Corpus Statistics"
echo "═══════════════════════════════════════════════════════"
echo ""
printf "%-35s %10s\n" "Fuzzer" "Files"
echo "───────────────────────────────────────────────────────"
for fuzzer in "${FUZZERS[@]}"; do
    count=$(find "$CFL_DIR/${fuzzer}_seed_corpus" -type f 2>/dev/null | wc -l)
    printf "%-35s %10d\n" "$fuzzer" "$count"
done
echo "───────────────────────────────────────────────────────"
echo ""

# Verify dictionary assignments
echo "═══════════════════════════════════════════════════════"
echo "  Dictionary Assignments"
echo "═══════════════════════════════════════════════════════"
echo ""

declare -A FUZZER_DICTS
FUZZER_DICTS[icc_apply_fuzzer]="icc_apply_fuzzer.dict"
FUZZER_DICTS[icc_applynamedcmm_fuzzer]="icc_applynamedcmm_fuzzer.dict"
FUZZER_DICTS[icc_applyprofiles_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_calculator_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_deep_dump_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_dump_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_fromcube_fuzzer]="icc_fromcube_fuzzer.dict"
FUZZER_DICTS[icc_fromxml_fuzzer]="icc_fromxml_fuzzer.dict"
FUZZER_DICTS[icc_io_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_link_fuzzer]="icc_link_fuzzer.dict"
FUZZER_DICTS[icc_multitag_fuzzer]="icc_multitag.dict"
FUZZER_DICTS[icc_profile_fuzzer]="icc_profile.dict"
FUZZER_DICTS[icc_roundtrip_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_specsep_fuzzer]="icc_specsep_fuzzer.dict"
FUZZER_DICTS[icc_spectral_fuzzer]="icc_core.dict"
FUZZER_DICTS[icc_spectral_b_fuzzer]="icc_spectral_b_fuzzer.dict"
FUZZER_DICTS[icc_tiffdump_fuzzer]="icc_tiffdump_fuzzer.dict"
FUZZER_DICTS[icc_toxml_fuzzer]="icc_xml_consolidated.dict"
FUZZER_DICTS[icc_v5dspobs_fuzzer]="icc_v5dspobs_fuzzer.dict"

printf "%-35s %-40s %s\n" "Fuzzer" "Dictionary" "Status"
echo "───────────────────────────────────────────────────────────────────────────────"
for fuzzer in "${FUZZERS[@]}"; do
    dict="${FUZZER_DICTS[$fuzzer]}"
    if [ -f "$CFL_DIR/$dict" ]; then
        size=$(wc -l < "$CFL_DIR/$dict")
        printf "%-35s %-40s [OK] (%d entries)\n" "$fuzzer" "$dict" "$size"
    else
        printf "%-35s %-40s [FAIL] MISSING\n" "$fuzzer" "$dict"
    fi
done
echo "───────────────────────────────────────────────────────────────────────────────"
echo ""

echo "[OK] Seed corpus setup complete!"
echo ""
echo "Next steps:"
echo "  1. Test corpus with: .github/scripts/test-seed-corpus.sh"
echo "  2. Run fuzzers with: make -C ../../Build fuzzer-test"
echo "  3. Monitor coverage and add more seeds as needed"
echo ""
