#!/usr/bin/env bash
# analyze-profile.sh — Run full iccanalyzer-lite analysis and generate markdown report
# Usage: ./analyze-profile.sh <profile-path>
# Output: analysis-reports/<profile-name>-analysis.md
set -uo pipefail

ANALYZER="iccanalyzer-lite/iccanalyzer-lite"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <profile-path>"
  exit 3
fi

PROFILE="$1"
BASENAME=$(basename "$PROFILE" .icc)
REPORT="analysis-reports/${BASENAME}-analysis.md"

if [ ! -f "$PROFILE" ]; then
  echo "[FAIL] Profile not found: $PROFILE"
  exit 2
fi

if [ ! -x "$ANALYZER" ]; then
  echo "[FAIL] Analyzer not found: $ANALYZER"
  exit 2
fi

mkdir -p analysis-reports

FILESIZE=$(stat -c%s "$PROFILE" 2>/dev/null || stat -f%z "$PROFILE" 2>/dev/null)

# Strip ANSI escape sequences from output
strip_ansi() { sed 's/\x1b\[[0-9;]*m//g'; }

# Run all 3 commands, capture stdout+stderr and exit codes, strip color
OUT_A=$(${ANALYZER} -a "$PROFILE" 2>&1 | strip_ansi);  EC_A=${PIPESTATUS[0]}
OUT_NF=$(${ANALYZER} -nf "$PROFILE" 2>&1 | strip_ansi); EC_NF=${PIPESTATUS[0]}
OUT_R=$(${ANALYZER} -r "$PROFILE" 2>&1 | strip_ansi);  EC_R=${PIPESTATUS[0]}

# Check for ASAN/UBSAN
ASAN_A=$(echo "$OUT_A" | grep -c "ERROR: AddressSanitizer\|ERROR: LeakSanitizer\|runtime error:" || true)
ASAN_NF=$(echo "$OUT_NF" | grep -c "ERROR: AddressSanitizer\|ERROR: LeakSanitizer\|runtime error:" || true)
ASAN_R=$(echo "$OUT_R" | grep -c "ERROR: AddressSanitizer\|ERROR: LeakSanitizer\|runtime error:" || true)
ASAN_TOTAL=$((ASAN_A + ASAN_NF + ASAN_R))

# Generate report
cat > "$REPORT" << 'HEADER'
# ICC Profile Analysis Report
HEADER

cat >> "$REPORT" << EOF

**Profile**: \`${PROFILE}\`
**File Size**: ${FILESIZE} bytes
**Date**: $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| \`-a\` (comprehensive) | ${EC_A} | $([ $EC_A -eq 0 ] && echo "Clean" || ([ $EC_A -eq 1 ] && echo "Finding detected" || ([ $EC_A -eq 2 ] && echo "Error" || echo "Signal/crash"))) |
| \`-nf\` (ninja full dump) | ${EC_NF} | $([ $EC_NF -eq 0 ] && echo "Clean" || ([ $EC_NF -eq 1 ] && echo "Finding detected" || ([ $EC_NF -eq 2 ] && echo "Error" || echo "Signal/crash"))) |
| \`-r\` (round-trip) | ${EC_R} | $([ $EC_R -eq 0 ] && echo "Clean" || ([ $EC_R -eq 1 ] && echo "Finding detected" || ([ $EC_R -eq 2 ] && echo "Error" || echo "Signal/crash"))) |

**ASAN/UBSAN**: $([ $ASAN_TOTAL -gt 0 ] && echo "[CRITICAL] ${ASAN_TOTAL} sanitizer error(s) detected" || echo "No sanitizer errors detected")

---

## Command 1: Comprehensive Analysis (\`-a\`)

**Exit Code: ${EC_A}**

\`\`\`
${OUT_A}
\`\`\`

---

## Command 2: Ninja Full Dump (\`-nf\`)

**Exit Code: ${EC_NF}**

\`\`\`
${OUT_NF}
\`\`\`

---

## Command 3: Round-Trip Test (\`-r\`)

**Exit Code: ${EC_R}**

\`\`\`
${OUT_R}
\`\`\`
EOF

echo "[OK] Report written to ${REPORT}"
echo "  Exit codes: -a=${EC_A} -nf=${EC_NF} -r=${EC_R}"
echo "  ASAN/UBSAN: ${ASAN_TOTAL} finding(s)"
echo "  File: ${REPORT} ($(wc -l < "$REPORT") lines)"

# Exit with worst exit code
if [ $ASAN_TOTAL -gt 0 ]; then exit 1; fi
if [ $EC_A -ge 2 ] || [ $EC_NF -ge 2 ] || [ $EC_R -ge 2 ]; then exit 2; fi
if [ $EC_A -eq 1 ] || [ $EC_NF -eq 1 ] || [ $EC_R -eq 1 ]; then exit 1; fi
exit 0
