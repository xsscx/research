#!/bin/bash
# copilot-crash-triage.sh -- Non-interactive crash artifact triage
# Usage: .github/scripts/copilot-crash-triage.sh <crash-file> [output-dir]
set -euo pipefail

CRASH="${1:?Usage: $0 <crash-file> [output-dir]}"
OUTPUT_DIR="${2:-/tmp/copilot-triage}"
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
TRANSCRIPT="${OUTPUT_DIR}/triage-${TIMESTAMP}.md"

mkdir -p "$OUTPUT_DIR"

if ! command -v copilot >/dev/null 2>&1; then
  echo "[FAIL] copilot CLI not found" >&2
  exit 1
fi

if [ ! -f "$CRASH" ]; then
  echo "[FAIL] Crash file not found: $CRASH" >&2
  exit 1
fi

echo "[OK] Triaging: $CRASH"
echo "[OK] Transcript: $TRANSCRIPT"

copilot -p "Triage this fuzzer crash artifact: ${CRASH}. Reproduce against unpatched iccDEV/Build/Tools/. Classify exit code, attribute by ASAN stack trace file path, map CWE. Determine upstream vs our code ownership. Trim ASAN output to SCARINESS + frames 0-4." \
  --agent crash-triage \
  --allow-tool='bash' \
  --allow-tool='read' \
  --allow-tool='grep' \
  --no-ask-user \
  --share="$TRANSCRIPT" \
  -s

echo "[OK] Triage complete. Transcript: $TRANSCRIPT"
