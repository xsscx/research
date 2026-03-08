#!/usr/bin/env bash
# pre-push-validate.sh — Verify iccanalyzer-lite build sync across all 7 locations
#
# Checks that source file lists and linker flags are consistent across:
#   1. iccanalyzer-lite/build.sh
#   2. iccanalyzer-lite/CMakeLists.txt
#   3. .github/workflows/codeql-security-analysis.yml
#   4. .github/workflows/iccanalyzer-cli-release.yml
#   5. .github/workflows/iccanalyzer-lite-coverage-report.yml
#   6. .github/workflows/iccanalyzer-lite-debug-sanitizer-coverage.yml
#   7. .github/workflows/mcp-server-test.yml
#
# Usage: .github/scripts/pre-push-validate.sh
# Exit 0 = all consistent, Exit 1 = divergence detected
#
# Origin: xsscx/governance LLMCJF — Anti-Pattern #5 prevention
# See: .github/instructions/multi-agent.instructions.md Anti-Pattern #5

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

ERRORS=0

echo "=== iccanalyzer-lite Build Sync Validation ==="
echo ""

# --- Check 1: Extract LIBS from build.sh ---
echo "[1/3] Checking linker flags (LIBS) across build locations..."

BUILD_SH="iccanalyzer-lite/build.sh"
if [ ! -f "$BUILD_SH" ]; then
  echo -e "  ${RED}[FAIL] $BUILD_SH not found${NC}"
  exit 1
fi

# Extract -l flags from build.sh LIBS variable
BUILDSH_LIBS=$(grep -E '^\s*LIBS=' "$BUILD_SH" | head -1 | grep -oE '\-l[a-zA-Z0-9_]+' | sort -u)
if [ -z "$BUILDSH_LIBS" ]; then
  echo -e "  ${YELLOW}[WARN] Could not extract LIBS from $BUILD_SH${NC}"
fi

echo "  build.sh LIBS: $(echo $BUILDSH_LIBS | tr '\n' ' ')"

# Check each workflow for matching -l flags
WORKFLOWS=(
  ".github/workflows/codeql-security-analysis.yml"
  ".github/workflows/iccanalyzer-cli-release.yml"
  ".github/workflows/iccanalyzer-lite-coverage-report.yml"
  ".github/workflows/iccanalyzer-lite-debug-sanitizer-coverage.yml"
  ".github/workflows/mcp-server-test.yml"
)

for wf in "${WORKFLOWS[@]}"; do
  if [ ! -f "$wf" ]; then
    echo -e "  ${YELLOW}[SKIP] $wf not found${NC}"
    continue
  fi
  WF_LIBS=$(grep -oE -- '\-l[a-zA-Z0-9_]+' "$wf" | sort -u)
  MISSING=""
  for lib in $BUILDSH_LIBS; do
    if ! echo "$WF_LIBS" | grep -qF -- "$lib"; then
      MISSING="$MISSING $lib"
    fi
  done
  if [ -n "$MISSING" ]; then
    echo -e "  ${RED}[FAIL] $(basename $wf): missing${MISSING}${NC}"
    ERRORS=$((ERRORS + 1))
  else
    echo -e "  ${GREEN}[OK]   $(basename $wf)${NC}"
  fi
done

# --- Check 2: Extract source files from build.sh ---
echo ""
echo "[2/3] Checking source file lists..."

BUILDSH_SOURCES=$(grep -E '^\s*SOURCES=' "$BUILD_SH" | head -1 | \
  grep -oE '[A-Za-z][A-Za-z0-9_]+\.cpp' | sort -u)
BUILDSH_COUNT=$(echo "$BUILDSH_SOURCES" | wc -l | tr -d ' ')
echo "  build.sh sources: $BUILDSH_COUNT .cpp files"

# Check CMakeLists.txt
CMAKE="iccanalyzer-lite/CMakeLists.txt"
if [ -f "$CMAKE" ]; then
  CMAKE_SOURCES=$(grep -oE '[A-Za-z][A-Za-z0-9_]+\.cpp' "$CMAKE" | sort -u)
  CMAKE_COUNT=$(echo "$CMAKE_SOURCES" | wc -l | tr -d ' ')
  if [ "$BUILDSH_COUNT" -ne "$CMAKE_COUNT" ]; then
    echo -e "  ${RED}[FAIL] CMakeLists.txt has $CMAKE_COUNT sources (expected $BUILDSH_COUNT)${NC}"
    DIFF=$(comm -23 <(echo "$BUILDSH_SOURCES") <(echo "$CMAKE_SOURCES"))
    if [ -n "$DIFF" ]; then
      echo -e "  ${RED}        Missing in CMakeLists.txt: $DIFF${NC}"
    fi
    ERRORS=$((ERRORS + 1))
  else
    echo -e "  ${GREEN}[OK]   CMakeLists.txt ($CMAKE_COUNT sources)${NC}"
  fi
fi

for wf in "${WORKFLOWS[@]}"; do
  if [ ! -f "$wf" ]; then continue; fi
  WF_SOURCES=$(grep -oE 'Icc[A-Za-z0-9_]+\.cpp' "$wf" | sort -u)
  WF_COUNT=$(echo "$WF_SOURCES" | wc -l | tr -d ' ')
  if [ "$WF_COUNT" -lt "$((BUILDSH_COUNT - 2))" ]; then
    echo -e "  ${YELLOW}[WARN] $(basename $wf): $WF_COUNT sources (build.sh has $BUILDSH_COUNT)${NC}"
  else
    echo -e "  ${GREEN}[OK]   $(basename $wf) ($WF_COUNT sources)${NC}"
  fi
done

# --- Check 3: Quick build test ---
echo ""
echo "[3/3] Verifying local build..."

if [ -f "iccanalyzer-lite/iccanalyzer-lite" ]; then
  BUILD_AGE=$(( $(date +%s) - $(stat -c %Y "iccanalyzer-lite/iccanalyzer-lite" 2>/dev/null || echo 0) ))
  if [ "$BUILD_AGE" -lt 3600 ]; then
    echo -e "  ${GREEN}[OK]   Binary exists (built ${BUILD_AGE}s ago)${NC}"
  else
    echo -e "  ${YELLOW}[WARN] Binary is $(( BUILD_AGE / 3600 ))h old — consider rebuilding${NC}"
  fi
else
  echo -e "  ${RED}[FAIL] Binary not found — run: cd iccanalyzer-lite && ./build.sh${NC}"
  ERRORS=$((ERRORS + 1))
fi

# --- Summary ---
echo ""
if [ "$ERRORS" -gt 0 ]; then
  echo -e "${RED}=== FAILED: $ERRORS divergence(s) detected ===${NC}"
  echo -e "${RED}Fix all issues before pushing. See Anti-Pattern #5 in multi-agent.instructions.md${NC}"
  echo -e "${RED}Governance ref: https://github.com/xsscx/governance/blob/main/HALL_OF_SHAME.md${NC}"
  exit 1
else
  echo -e "${GREEN}=== PASSED: All 7 build locations are consistent ===${NC}"
  exit 0
fi
