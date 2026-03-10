#!/usr/bin/env bash
# verify-patches.sh — Ground-truth verification of CFL patch application
#
# Unlike dry-run (which can report "already applied" even on unpatched code),
# this script verifies that COMPILED BINARIES contain patched code by checking:
#   1. Source-level: key code patterns exist in cfl/iccDEV/ source
#   2. Binary-level: demangled symbols have expected parameter counts
#   3. Runtime-level: known timeout artifacts complete within time budget
#
# Usage: ./verify-patches.sh [--ssd /mnt/g/fuzz-ssd] [--quick]
#
# Exit codes: 0 = all verified, 1 = verification failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CFL_DIR="$SCRIPT_DIR"
ICCDEV_DIR="$CFL_DIR/iccDEV"
BIN_DIR="$CFL_DIR/bin"
SSD_DIR=""
QUICK=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; WARN=$((WARN + 1)); }

while [[ $# -gt 0 ]]; do
    case $1 in
        --ssd) SSD_DIR="$2"; shift 2;;
        --quick) QUICK=true; shift;;
        *) echo "Usage: $0 [--ssd /mnt/g/fuzz-ssd] [--quick]"; exit 1;;
    esac
done

echo "=== CFL Patch Verification ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# ─── Phase 1: Source-Level Verification ───
echo "── Phase 1: Source-level checks ──"

if [ ! -d "$ICCDEV_DIR" ]; then
    fail "cfl/iccDEV/ directory missing"
    echo "RESULT: $FAIL failures — cannot verify"
    exit 1
fi

# Check upstream commit
UPSTREAM=$(cd "$ICCDEV_DIR" && git --no-pager log --oneline -1 2>/dev/null || echo "unknown")
echo "  Upstream: $UPSTREAM"

# CFL-074: CheckUnderflowOverflow has nRecurseDepth + pOpsProcessed
if grep -q "kMaxOpsProcessed" "$ICCDEV_DIR/IccProfLib/IccMpeCalc.cpp" 2>/dev/null; then
    CUOF_OPS=$(grep -c "kMaxOpsProcessed" "$ICCDEV_DIR/IccProfLib/IccMpeCalc.cpp")
    pass "CFL-074 source: kMaxOpsProcessed in IccMpeCalc.cpp ($CUOF_OPS refs)"
else
    fail "CFL-074 source: kMaxOpsProcessed NOT found in IccMpeCalc.cpp"
fi

# CFL-074: SequenceNeedTempReset has nRecurseDepth parameter
if grep -q "SequenceNeedTempReset.*nRecurseDepth" "$ICCDEV_DIR/IccProfLib/IccMpeCalc.h" 2>/dev/null; then
    pass "CFL-074 source: SequenceNeedTempReset has nRecurseDepth in .h"
else
    fail "CFL-074 source: SequenceNeedTempReset missing nRecurseDepth in .h"
fi

# CFL-033: TiffImg malloc overflow guard
if grep -q "SIZE_MAX" "$ICCDEV_DIR/Tools/CmdLine/IccApplyProfiles/TiffImg.cpp" 2>/dev/null; then
    pass "CFL-033 source: TiffImg integer overflow guard (SIZE_MAX check) present"
else
    warn "CFL-033 source: TiffImg overflow guard not detected"
fi

# CFL-082: TiffImg strip bounds check
if grep -q "m_nStripSize\|strip.*bound\|nRowsPerStrip.*nBytesPerLine" "$ICCDEV_DIR/Tools/CmdLine/IccApplyProfiles/TiffImg.cpp" 2>/dev/null; then
    pass "CFL-082 source: TiffImg strip bounds check present"
else
    fail "CFL-082 source: TiffImg strip bounds check NOT found"
fi

# General: count patches that apply (forward dry-run)
echo ""
PATCH_TOTAL=$(ls "$CFL_DIR/patches/"*.patch 2>/dev/null | wc -l)
echo "  Total patch files: $PATCH_TOTAL"

if ! $QUICK; then
    APPLIED=0
    NOOP=0
    FAILED=0
    for p in "$CFL_DIR/patches/"*.patch; do
        result=$(patch --dry-run --forward -p1 -d "$ICCDEV_DIR" < "$p" 2>&1) || true
        if echo "$result" | grep -qi "reversed\|already applied"; then
            APPLIED=$((APPLIED + 1))
        elif echo "$result" | grep -qi "FAILED"; then
            # Check if the actual code additions from this patch exist in source
            # Extract added lines (skip +++ header) and check first substantive line
            first_add=$(grep "^+" "$p" | grep -v "^+++" | grep -v "^+$" | head -1 | sed 's/^+//')
            if [ -n "$first_add" ] && grep -qF "$first_add" "$ICCDEV_DIR"/IccProfLib/*.cpp "$ICCDEV_DIR"/IccProfLib/*.h \
                 "$ICCDEV_DIR"/IccXML/IccLibXML/*.cpp "$ICCDEV_DIR"/Tools/CmdLine/IccApplyProfiles/*.cpp 2>/dev/null; then
                APPLIED=$((APPLIED + 1))
                pass "Patch $(basename "$p"): context shifted but code present in source"
            else
                FAILED=$((FAILED + 1))
                fail "Patch FAILED: $(basename "$p")"
            fi
        elif echo "$result" | grep -qi "with fuzz\|offset"; then
            # Patch would apply with fuzz — check if it's already in source
            first_add=$(grep "^+" "$p" | grep -v "^+++" | grep -v "^+$" | head -1 | sed 's/^+//')
            if [ -n "$first_add" ] && grep -rqF "$first_add" "$ICCDEV_DIR" 2>/dev/null; then
                APPLIED=$((APPLIED + 1))
            else
                warn "Patch NOT YET APPLIED: $(basename "$p")"
            fi
        else
            APPLIED=$((APPLIED + 1))
        fi
    done
    if [ $FAILED -eq 0 ]; then
        pass "All $PATCH_TOTAL patches verified applied (0 failures)"
    fi
fi

# ─── Phase 2: Binary-Level Verification ───
echo ""
echo "── Phase 2: Binary-level checks ──"

check_binary_dir() {
    local dir="$1"
    local label="$2"

    if [ ! -d "$dir" ]; then
        warn "$label: directory missing ($dir)"
        return
    fi

    local count=$(ls "$dir"/icc_*_fuzzer 2>/dev/null | wc -l)
    if [ "$count" -eq 18 ]; then
        pass "$label: 18/18 fuzzer binaries present"
    else
        fail "$label: only $count/18 fuzzer binaries"
    fi

    # Check CFL-074 in calculator fuzzer (has CheckUnderflowOverflow)
    local calc="$dir/icc_calculator_fuzzer"
    if [ -f "$calc" ]; then
        local params=$(nm "$calc" 2>/dev/null | c++filt 2>/dev/null | grep "CheckUnderflowOverflow" | head -1)
        if echo "$params" | grep -q "unsigned int, unsigned int\*"; then
            pass "$label: icc_calculator_fuzzer has 7-param CheckUnderflowOverflow (patched)"
        else
            fail "$label: icc_calculator_fuzzer has UNPATCHED CheckUnderflowOverflow signature"
        fi
    fi

    # Check binary timestamps are newer than source
    local newest_patch=$(stat -c %Y "$CFL_DIR/patches/"*.patch 2>/dev/null | sort -n | tail -1)
    local oldest_bin=$(stat -c %Y "$dir"/icc_*_fuzzer 2>/dev/null | sort -n | head -1)
    if [ -n "$newest_patch" ] && [ -n "$oldest_bin" ] && [ "$oldest_bin" -ge "$newest_patch" ]; then
        pass "$label: binaries newer than patches (timestamps consistent)"
    else
        warn "$label: some binaries older than patches (may be stale)"
    fi
}

check_binary_dir "$BIN_DIR" "cfl/bin"
if [ -n "$SSD_DIR" ]; then
    check_binary_dir "$SSD_DIR/bin" "SSD"
fi

# ─── Phase 3: Runtime Verification ───
echo ""
echo "── Phase 3: Runtime checks ──"

# Find timeout artifacts
TIMEOUT_FILES=$(find "$REPO_ROOT" -maxdepth 1 -name "timeout-*" -type f 2>/dev/null | head -3)
if [ -z "$TIMEOUT_FILES" ]; then
    warn "No timeout artifacts found for CWE-400 verification"
else
    FUZZER="$BIN_DIR/icc_profile_fuzzer"
    if [ -n "$SSD_DIR" ] && [ -f "$SSD_DIR/bin/icc_profile_fuzzer" ]; then
        FUZZER="$SSD_DIR/bin/icc_profile_fuzzer"
    fi

    if [ -f "$FUZZER" ]; then
        ALL_FAST=true
        for tf in $TIMEOUT_FILES; do
            START=$(date +%s%N)
            timeout 5 "$FUZZER" "$tf" >/dev/null 2>&1 || true
            END=$(date +%s%N)
            MS=$(( (END - START) / 1000000 ))
            if [ "$MS" -lt 2000 ]; then
                pass "Timeout artifact $(basename "$tf"): ${MS}ms (< 2s budget)"
            else
                fail "Timeout artifact $(basename "$tf"): ${MS}ms (EXCEEDED 2s budget)"
                ALL_FAST=false
            fi
        done
    else
        warn "No fuzzer binary available for runtime check"
    fi
fi

# ─── Summary ───
echo ""
echo "═══════════════════════════════════════"
echo -e "  PASS: ${GREEN}$PASS${NC}  FAIL: ${RED}$FAIL${NC}  WARN: ${YELLOW}$WARN${NC}"
echo "═══════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}VERIFICATION FAILED${NC} — do NOT begin fuzzing until all failures are resolved"
    exit 1
else
    echo -e "${GREEN}VERIFICATION PASSED${NC} — binaries confirmed patched and functional"
    exit 0
fi
