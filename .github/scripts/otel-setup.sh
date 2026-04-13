#!/usr/bin/env bash
# OpenTelemetry monitoring for Copilot CLI sessions
# Source this file before launching copilot: source .github/scripts/otel-setup.sh
#
# Traces go to ~/.copilot/otel/traces-YYYY-MM-DD.jsonl (JSON-lines)
# Full prompt/response content is captured for debugging.
# Review https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference#opentelemetry-monitoring
#
# Security: This file is sourced into interactive shells. Never use
# set -euo pipefail here -- it kills the caller on any transient error.
# All operations use explicit error checks and local variables via a
# setup function to avoid polluting the caller namespace.

__otel_setup() {
  local otel_dir="${HOME}/.copilot/otel"
  local today trace_file

  if ! mkdir -p "${otel_dir}" 2>/dev/null; then
    echo "[FAIL] OTel: cannot create ${otel_dir}" >&2
    return 1
  fi

  today=$(date +%Y-%m-%d)
  trace_file="${otel_dir}/traces-${today}.jsonl"

  # Core OTel activation
  export COPILOT_OTEL_ENABLED=true
  export COPILOT_OTEL_EXPORTER_TYPE=file
  export COPILOT_OTEL_FILE_EXPORTER_PATH="${trace_file}"

  # Service identity
  export OTEL_SERVICE_NAME="icc-security-research"

  # Capture full prompt/response content (disable for production)
  export OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true

  # Auto-start background watcher (runs live.sh every 60s)
  local watcher_script="${HOME}/otel/report/otel-watcher.sh"
  local watcher_pid_file="${otel_dir}/watcher.pid"
  local old_pid

  if [[ -x "${watcher_script}" ]]; then
    if [[ -f "${watcher_pid_file}" ]]; then
      old_pid=$(cat "${watcher_pid_file}" 2>/dev/null) || old_pid=""
      if [[ -n "${old_pid}" ]] && kill -0 "${old_pid}" 2>/dev/null; then
        echo "[OK] OTel watcher already running (PID ${old_pid})"
      else
        rm -f "${watcher_pid_file}"
      fi
    fi

    if [[ ! -f "${watcher_pid_file}" ]]; then
      nohup bash "${watcher_script}" >> "${otel_dir}/watcher.log" 2>&1 &
      disown
      sleep 0.2
      if [[ -f "${watcher_pid_file}" ]]; then
        echo "[OK] OTel watcher started (PID $(cat "${watcher_pid_file}"), every 60s)"
      else
        echo "[WARN] OTel watcher may not have started"
      fi
    fi
  fi

  echo "[OK] OTel file exporter: ${trace_file}"
}

__otel_setup
unset -f __otel_setup
