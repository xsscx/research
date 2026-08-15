#!/usr/bin/env bash
# pre-push-gate.sh - Unified pre-push validation for active components
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
AFL_JPEG_SEED_PATTERN='afl/targets.sh\|afl/start.sh\|afl/README.md\|\.github/scripts/validate-afl-jpeg-seeds.sh\|\.github/instructions/afl.instructions.md\|\.github/instructions/fuzz.instructions.md\|\.github/prompts/.*fuzzer.*\.prompt.md\|\.github/skills/corpus-management/SKILL.md\|AGENTS.md\|\.github/copilot-instructions.md'
AFL_NAMEDCMM_PATTERN='afl/targets.sh\|afl/start.sh\|afl/README.md\|docs/afl/index.md\|\.github/scripts/validate-afl-applynamedcmm-targets.sh\|\.github/instructions/afl.instructions.md'

echo -e "${BOLD}+--------------------------------------------------+${NC}"
echo -e "${BOLD}|         PRE-PUSH VALIDATION GATE                |${NC}"
echo -e "${BOLD}+--------------------------------------------------+${NC}"
echo ""

# Detect what changed (uncommitted + last commit vs remote)
CHANGED_FILES=$(git diff --name-only HEAD~1 HEAD 2>/dev/null || echo "")
CHANGED_FILES="$CHANGED_FILES
$(git diff --name-only 2>/dev/null || echo "")"

has_changes() {
  echo "$CHANGED_FILES" | grep -q "$1" 2>/dev/null
}

# ---------------------------------------------------
# GATE 0: GitHub/workflow/hook preflight
# ---------------------------------------------------
echo -e "${BOLD}[GATE 0] GitHub/workflow preflight${NC}"

if has_changes "\.github/\|\.githooks/"; then
  if .github/scripts/preflight-safety-checks.sh; then
    echo -e "  ${GREEN}preflight OK${NC}"
  else
    echo -e "  ${RED}preflight FAILED${NC}"
    ERRORS=$((ERRORS + 1))
  fi
else
  echo -e "  ${YELLOW}(no GitHub/hook/container changes - skipped)${NC}"
  SKIPPED=$((SKIPPED + 1))
fi

echo ""

# ---------------------------------------------------
# GATE 1: AFL ApplyNamedCmm target contracts
# ---------------------------------------------------
echo -e "${BOLD}[GATE 1] AFL ApplyNamedCmm target contracts${NC}"

if has_changes "$AFL_NAMEDCMM_PATTERN"; then
  if .github/scripts/validate-afl-applynamedcmm-targets.sh; then
    echo -e "  ${GREEN}AFL ApplyNamedCmm target contracts OK${NC}"
  else
    echo -e "  ${RED}AFL ApplyNamedCmm target contracts FAILED${NC}"
    ERRORS=$((ERRORS + 1))
  fi
else
  echo -e "  ${YELLOW}(no AFL ApplyNamedCmm target contract changes - skipped)${NC}"
  SKIPPED=$((SKIPPED + 1))
fi

echo ""

# ---------------------------------------------------
# GATE 2: AFL JPEG seed policy
# ---------------------------------------------------
echo -e "${BOLD}[GATE 2] AFL JPEG seed policy${NC}"

if has_changes "$AFL_JPEG_SEED_PATTERN"; then
  if .github/scripts/validate-afl-jpeg-seeds.sh; then
    echo -e "  ${GREEN}AFL JPEG seed policy OK${NC}"
  else
    echo -e "  ${RED}AFL JPEG seed policy FAILED${NC}"
    ERRORS=$((ERRORS + 1))
  fi
else
  echo -e "  ${YELLOW}(no AFL JPEG seed policy changes - skipped)${NC}"
  SKIPPED=$((SKIPPED + 1))
fi

echo ""

# ---------------------------------------------------
# GATE 3: Documentation and repository state
# ---------------------------------------------------
echo -e "${BOLD}[GATE 3] Consistency checks${NC}"

# 3a. Git status clean
echo -n "  Working tree: "
if [ -z "$(git status --porcelain 2>/dev/null)" ]; then
  echo -e "${GREEN}clean${NC}"
else
  DIRTY=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')
  echo -e "${YELLOW}$DIRTY uncommitted file(s)${NC}"
  WARNINGS=$((WARNINGS + 1))
fi

echo ""

# ---------------------------------------------------
# SUMMARY
# ---------------------------------------------------
echo -e "${BOLD}===================================================${NC}"
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
