#!/bin/bash
# copilot-security-scan.sh -- Non-interactive ICC profile security scan
# Usage: .github/scripts/copilot-security-scan.sh <profile.icc> [output-dir]
set -euo pipefail

PROFILE="${1:?Usage: $0 <profile.icc> [output-dir]}"
OUTPUT_DIR="${2:-/tmp/copilot-scan}"
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
TRANSCRIPT="${OUTPUT_DIR}/scan-${TIMESTAMP}.md"

mkdir -p "$OUTPUT_DIR"

if ! command -v copilot >/dev/null 2>&1; then
  echo "[FAIL] copilot CLI not found" >&2
  exit 1
fi

if [ ! -f "$PROFILE" ]; then
  echo "[FAIL] Profile not found: $PROFILE" >&2
  exit 1
fi

echo "[OK] Scanning: $PROFILE"
echo "[OK] Transcript: $TRANSCRIPT"

copilot -p "Run current iccDEV structural, PAWG, and round-trip analysis on the ICC profile at ${PROFILE}. Report findings with command evidence and sanitizer or signal status." \
  --agent security-scan \
  --allow-tool='bash' \
  --allow-tool='read' \
  --no-ask-user \
  --share="$TRANSCRIPT" \
  -s

echo "[OK] Scan complete. Transcript: $TRANSCRIPT"
