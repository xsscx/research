#!/bin/bash
# test-iccdev-all.sh — Run all per-tool iccDEV test scripts
# Usage: test-iccdev-all.sh [--asan] [--quick] [--tool=NAME]
# --tool=NAME: Run only a specific tool (e.g., --tool=dump, --tool=toxml)
# Without --tool: runs ALL tool scripts and aggregates results
# Note: Full run may take several minutes depending on test data availability
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_FILTER=""
PASS_ARGS=()

for arg in "$@"; do
  case "$arg" in
    --tool=*) TOOL_FILTER="${arg#--tool=}" ;;
    --list-tools)
      echo "Available tools:"
      for f in "$SCRIPT_DIR"/test-icc*.sh; do
        basename "$f" .sh | sed 's/^test-/  /'
      done
      exit 0
      ;;
    --help|-h)
      echo "Usage: $0 [--asan] [--quick] [--tool=NAME] [--list-tools]"
      echo ""
      echo "Options:"
      echo "  --asan        Enable ASAN=halt_on_error=1"
      echo "  --quick       Reduce batch sizes and slow tests"
      echo "  --tool=NAME   Run only one tool (e.g., --tool=DumpProfile)"
      echo "  --list-tools  Show available tool names"
      echo ""
      echo "Examples:"
      echo "  $0                        # Run all tools"
      echo "  $0 --quick                # Quick run of all tools"
      echo "  $0 --tool=DumpProfile     # Run only iccDumpProfile tests"
      echo "  $0 --tool=TiffDump --asan # iccTiffDump with ASAN halt"
      exit 0
      ;;
    *) PASS_ARGS+=("$arg") ;;
  esac
done

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_ASAN=0
TOTAL_UBSAN=0
TOTAL_CRASH=0
TOOL_RESULTS=()

run_tool_script() {
  local script="$1"
  local name
  name=$(basename "$script" .sh | sed 's/^test-//')

  # Filter by --tool if specified
  if [ -n "$TOOL_FILTER" ]; then
    # Case-insensitive partial match
    if ! echo "$name" | grep -qi "$TOOL_FILTER"; then
      return 0
    fi
  fi

  echo ""
  echo "================================================================"
  echo "  Running: $name"
  echo "================================================================"

  bash "$script" "${PASS_ARGS[@]}" 2>&1
  local rc=$?

  # Parse summary line from output (last SUMMARY line)
  TOOL_RESULTS+=("$name: exit=$rc")
  if [ "$rc" -gt 0 ]; then
    TOTAL_FAIL=$((TOTAL_FAIL + rc))
  fi
}

# Run all per-tool test scripts
for script in "$SCRIPT_DIR"/test-icc*.sh; do
  [ -f "$script" ] && [ -x "$script" ] && run_tool_script "$script"
done

echo ""
echo "================================================================"
echo "  AGGREGATE RESULTS"
echo "================================================================"
for result in "${TOOL_RESULTS[@]}"; do
  echo "  $result"
done
echo ""
echo "Total tools tested: ${#TOOL_RESULTS[@]}"
echo "Aggregate failures: $TOTAL_FAIL"
echo ""

if [ "$TOTAL_FAIL" -gt 0 ]; then
  echo "RESULT: SOME TESTS FAILED"
  exit 1
else
  echo "RESULT: ALL TOOLS PASSED"
  exit 0
fi
