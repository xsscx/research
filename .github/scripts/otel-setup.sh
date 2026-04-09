#!/usr/bin/env bash
# OpenTelemetry monitoring for Copilot CLI sessions
# Source this file before launching copilot: source .github/scripts/otel-setup.sh
#
# Traces go to ~/.copilot/otel/traces-YYYY-MM-DD.jsonl (JSON-lines)
# Full prompt/response content is captured for debugging.
# Review https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference#opentelemetry-monitoring

set -euo pipefail

OTEL_DIR="${HOME}/.copilot/otel"
mkdir -p "${OTEL_DIR}"

TODAY=$(date +%Y-%m-%d)
TRACE_FILE="${OTEL_DIR}/traces-${TODAY}.jsonl"

# Core OTel activation
export COPILOT_OTEL_ENABLED=true
export COPILOT_OTEL_EXPORTER_TYPE=file
export COPILOT_OTEL_FILE_EXPORTER_PATH="${TRACE_FILE}"

# Service identity
export OTEL_SERVICE_NAME="icc-security-research"

# Capture full prompt/response content (disable for production)
export OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true

echo "[OK] OTel file exporter: ${TRACE_FILE}"
