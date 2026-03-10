#!/usr/bin/env bash
# pre-push-gate.sh — Unified pre-push validation for ALL components
#
# Runs the minimum viable checks before ANY push to main.
# Detects which components changed and runs appropriate tests.
#
# Usage: .github/scripts/pre-push-gate.sh
# Exit 0 = safe to push, Exit 1 = fix issues first
#
# This replaces the scattered "MANDATORY" sections across 4 instruction files
# with a single executable checklist.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

ERRORS=0
WARNINGS=0
SKIPPED=0

echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         PRE-PUSH VALIDATION GATE                ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Detect what changed (uncommitted + last commit vs remote)
CHANGED_FILES=$(git diff --name-only HEAD~1 HEAD 2>/dev/null || echo "")
CHANGED_FILES="$CHANGED_FILES
$(git diff --name-only 2>/dev/null || echo "")"

has_changes() {
  echo "$CHANGED_FILES" | grep -q "$1" 2>/dev/null
}

# ═══════════════════════════════════════════════════
# GATE 1: iccanalyzer-lite (if C++ changed)
# ═══════════════════════════════════════════════════
echo -e "${BOLD}[GATE 1] iccanalyzer-lite${NC}"

if has_changes "iccanalyzer-lite/.*\.cpp\|iccanalyzer-lite/.*\.h\|iccanalyzer-lite/build.sh"; then
  # 1a. Build
  echo -n "  Build: "
  if (cd iccanalyzer-lite && ./build.sh) >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
  else
    echo -e "${RED}FAILED${NC}"
    ERRORS=$((ERRORS + 1))
  fi

  # 1b. Unit tests
  echo -n "  Tests (230): "
  TEST_OUT=$(python3 iccanalyzer-lite/tests/run_tests.py 2>&1)
  if echo "$TEST_OUT" | grep -q "230/230 passed"; then
    echo -e "${GREEN}230/230${NC}"
  else
    RESULT=$(echo "$TEST_OUT" | grep -oE '[0-9]+/[0-9]+ passed' | tail -1)
    echo -e "${RED}${RESULT:-FAILED}${NC}"
    ERRORS=$((ERRORS + 1))
  fi

  # 1c. ASAN spot-check
  echo -n "  ASAN spot-check: "
  ASAN_OUT=$(ASAN_OPTIONS=halt_on_error=1,detect_leaks=0 \
    ./iccanalyzer-lite/iccanalyzer-lite -a test-profiles/sRGB_D65_MAT.icc 2>&1)
  ASAN_RC=$?
  if [ $ASAN_RC -le 1 ] && ! echo "$ASAN_OUT" | grep -q "AddressSanitizer\|runtime error:"; then
    echo -e "${GREEN}clean${NC}"
  else
    echo -e "${RED}ASAN/UBSAN error detected (exit $ASAN_RC)${NC}"
    ERRORS=$((ERRORS + 1))
  fi

  # 1d. Build sync
  echo -n "  Build sync (7 locations): "
  if .github/scripts/pre-push-validate.sh >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
  else
    echo -e "${RED}DIVERGENCE${NC}"
    ERRORS=$((ERRORS + 1))
  fi
else
  echo -e "  ${YELLOW}(no C++ changes — skipped)${NC}"
  SKIPPED=$((SKIPPED + 1))

  # Still verify binary exists
  if [ ! -f "iccanalyzer-lite/iccanalyzer-lite" ]; then
    echo -e "  ${RED}Binary missing — tests below may fail${NC}"
    WARNINGS=$((WARNINGS + 1))
  fi
fi

echo ""

# ═══════════════════════════════════════════════════
# GATE 2: MCP Server (if Python/HTML changed)
# ═══════════════════════════════════════════════════
echo -e "${BOLD}[GATE 2] MCP Server${NC}"

if has_changes "mcp-server/"; then
  # 2a. MCP tests
  echo -n "  MCP tests (1816): "
  MCP_OUT=$(cd mcp-server && python3 test_mcp.py 2>&1)
  if echo "$MCP_OUT" | grep -q "1816/1816 passed"; then
    echo -e "${GREEN}1816/1816${NC}"
  else
    RESULT=$(echo "$MCP_OUT" | grep -oE '[0-9]+/[0-9]+ passed' | tail -1)
    echo -e "${RED}${RESULT:-FAILED}${NC}"
    ERRORS=$((ERRORS + 1))
  fi

  # 2b. WebUI tests
  echo -n "  WebUI tests (256): "
  WEBUI_OUT=$(cd mcp-server && python3 test_web_ui.py 2>&1)
  if echo "$WEBUI_OUT" | grep -q "ALL TESTS PASSED"; then
    RESULT=$(echo "$WEBUI_OUT" | grep -oE '[0-9]+/[0-9]+ passed' | tail -1)
    echo -e "${GREEN}${RESULT}${NC}"
  else
    RESULT=$(echo "$WEBUI_OUT" | grep -oE '[0-9]+/[0-9]+ passed' | tail -1)
    echo -e "${RED}${RESULT:-FAILED}${NC}"
    ERRORS=$((ERRORS + 1))
  fi

  # 2c. Docker gate (only if Dockerfile changed)
  if has_changes "mcp-server/Dockerfile\|Dockerfile"; then
    echo -n "  Docker build: "
    if docker build -t icc-mcp-gate:test -f mcp-server/Dockerfile . >/dev/null 2>&1; then
      echo -e "${GREEN}OK${NC}"
      # Quick health check
      docker run --rm -d -p 8082:8080 --name mcp-gate icc-mcp-gate:test web >/dev/null 2>&1
      sleep 3
      echo -n "  Docker health: "
      HEALTH=$(curl -s http://localhost:8082/api/health 2>/dev/null || echo "{}")
      if echo "$HEALTH" | grep -q '"ok":true'; then
        echo -e "${GREEN}OK${NC}"
      else
        echo -e "${RED}FAILED${NC}"
        ERRORS=$((ERRORS + 1))
      fi
      docker stop mcp-gate >/dev/null 2>&1 || true
    else
      echo -e "${RED}FAILED${NC}"
      ERRORS=$((ERRORS + 1))
    fi
  fi

  # 2d. Browser verification reminder (if HTML changed)
  if has_changes "mcp-server/index.html"; then
    echo -e "  ${YELLOW}⚠ index.html changed — verify in browser at http://127.0.0.1:8080${NC}"
    echo -e "  ${YELLOW}  Click 5+ tools, check DevTools console for 0 errors${NC}"
    WARNINGS=$((WARNINGS + 1))
  fi
else
  echo -e "  ${YELLOW}(no MCP changes — skipped)${NC}"
  SKIPPED=$((SKIPPED + 1))
fi

echo ""

# ═══════════════════════════════════════════════════
# GATE 3: Documentation (always check counts)
# ═══════════════════════════════════════════════════
echo -e "${BOLD}[GATE 3] Consistency checks${NC}"

# 3a. Heuristic count
if [ -f "iccanalyzer-lite/iccanalyzer-lite" ]; then
  echo -n "  Heuristic count: "
  H_COUNT=$(./iccanalyzer-lite/iccanalyzer-lite --registry 2>/dev/null | python3 -c "
import json,sys
try:
  r=json.load(sys.stdin)
  print(r.get('totalHeuristics','?'))
except: print('?')" 2>/dev/null || echo "?")
  if [ "$H_COUNT" = "150" ]; then
    echo -e "${GREEN}150${NC}"
  elif [ "$H_COUNT" = "?" ]; then
    echo -e "${YELLOW}could not read${NC}"
    WARNINGS=$((WARNINGS + 1))
  else
    echo -e "${RED}$H_COUNT (expected 150)${NC}"
    ERRORS=$((ERRORS + 1))
  fi
fi

# 3b. Git status clean
echo -n "  Working tree: "
if [ -z "$(git status --porcelain 2>/dev/null)" ]; then
  echo -e "${GREEN}clean${NC}"
else
  DIRTY=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')
  echo -e "${YELLOW}$DIRTY uncommitted file(s)${NC}"
  WARNINGS=$((WARNINGS + 1))
fi

echo ""

# ═══════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
if [ "$ERRORS" -gt 0 ]; then
  echo -e "${RED}BLOCKED: $ERRORS error(s), $WARNINGS warning(s)${NC}"
  echo -e "${RED}Fix errors before pushing.${NC}"
  exit 1
elif [ "$WARNINGS" -gt 0 ]; then
  echo -e "${YELLOW}PASS with $WARNINGS warning(s) ($SKIPPED gate(s) skipped)${NC}"
  echo -e "${YELLOW}Review warnings, then: git push${NC}"
  exit 0
else
  echo -e "${GREEN}ALL GATES PASSED ($SKIPPED skipped)${NC}"
  echo -e "${GREEN}Safe to push: git push${NC}"
  exit 0
fi
