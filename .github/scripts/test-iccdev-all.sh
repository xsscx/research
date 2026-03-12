#!/bin/bash
# test-iccdev-all.sh — Run all per-tool iccDEV test scripts IN PARALLEL
# Usage: test-iccdev-all.sh [--asan] [--quick] [--tool=NAME]
# --tool=NAME: Run only a specific tool (e.g., --tool=dump, --tool=toxml)
# Without --tool: runs ALL tool scripts in parallel and aggregates results
# Note: Full run uses all CPU cores; individual tools run their own parallel batches
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
        [ "$(basename "$f")" = "test-iccdev-all.sh" ] && continue
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
      echo "  $0                        # Run all tools in parallel"
      echo "  $0 --quick                # Quick parallel run"
      echo "  $0 --tool=DumpProfile     # Run only iccDumpProfile tests"
      echo "  $0 --tool=TiffDump --asan # iccTiffDump with ASAN halt"
      exit 0
      ;;
    *) PASS_ARGS+=("$arg") ;;
  esac
done

LOGDIR=$(mktemp -d /tmp/iccdev-all-XXXXXX)
trap 'rm -rf "$LOGDIR"' EXIT

# Collect scripts to run
SCRIPTS=()
for script in "$SCRIPT_DIR"/test-icc*.sh; do
  [ -f "$script" ] || continue
  [ -x "$script" ] || continue
  [ "$(basename "$script")" = "test-iccdev-all.sh" ] && continue
  [ "$(basename "$script")" = "test-iccdev-tools-comprehensive.sh" ] && continue
  name=$(basename "$script" .sh | sed 's/^test-//')
  if [ -n "$TOOL_FILTER" ]; then
    echo "$name" | grep -qi "$TOOL_FILTER" || continue
  fi
  SCRIPTS+=("$script")
done

if [ "${#SCRIPTS[@]}" -eq 0 ]; then
  echo "No matching tool scripts found."
  exit 1
fi

echo "================================================================"
echo "  iccDEV Tool Tests — Parallel Execution"
echo "  Tools: ${#SCRIPTS[@]} | CPUs: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
echo "================================================================"

# Launch ALL tool scripts in parallel
PIDS=()
NAMES=()
for script in "${SCRIPTS[@]}"; do
  name=$(basename "$script" .sh | sed 's/^test-//')
  logfile="$LOGDIR/${name}.log"
  bash "$script" "${PASS_ARGS[@]}" > "$logfile" 2>&1 &
  PIDS+=($!)
  NAMES+=("$name")
done

# Wait for all and collect exit codes
EXITS=()
for pid in "${PIDS[@]}"; do
  wait "$pid" 2>/dev/null
  EXITS+=($?)
done

# Aggregate results
TOTAL_TOOLS=0
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_ASAN=0
TOTAL_UBSAN=0
HAS_FAILURE=0

echo ""
echo "================================================================"
echo "  AGGREGATE RESULTS"
echo "================================================================"

for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"
  ec="${EXITS[$i]}"
  logfile="$LOGDIR/${name}.log"

  # Parse summary from log (look for SUMMARY line)
  pass=$(grep -oP 'PASS=\K[0-9]+' "$logfile" 2>/dev/null | tail -1)
  fail=$(grep -oP 'FAIL=\K[0-9]+' "$logfile" 2>/dev/null | tail -1)
  asan=$(grep -oP 'ASAN=\K[0-9]+' "$logfile" 2>/dev/null | tail -1)
  ubsan=$(grep -oP 'UBSAN=\K[0-9]+' "$logfile" 2>/dev/null | tail -1)
  total=$(grep -oP 'TOTAL=\K[0-9]+' "$logfile" 2>/dev/null | tail -1)
  pass=${pass:-0}; fail=${fail:-0}; asan=${asan:-0}; ubsan=${ubsan:-0}; total=${total:-0}

  TOTAL_PASS=$((TOTAL_PASS + pass))
  TOTAL_FAIL=$((TOTAL_FAIL + fail))
  TOTAL_ASAN=$((TOTAL_ASAN + asan))
  TOTAL_UBSAN=$((TOTAL_UBSAN + ubsan))
  TOTAL_TOOLS=$((TOTAL_TOOLS + 1))

  status="OK"
  [ "$asan" -gt 0 ] && status="ASAN!"
  [ "$ubsan" -gt 0 ] && status="UBSAN!"
  [ "$ec" -gt 0 ] && HAS_FAILURE=1

  printf "  %-25s %3d PASS / %3d FAIL / %3d TOTAL  ASAN=%d UBSAN=%d  [%s]\n" \
    "$name" "$pass" "$fail" "$total" "$asan" "$ubsan" "$status"
done

echo ""
echo "────────────────────────────────────────────────────────────────"
printf "  %-25s %3d PASS / %3d FAIL / %3d TOTAL  ASAN=%d UBSAN=%d\n" \
  "GRAND TOTAL" "$TOTAL_PASS" "$TOTAL_FAIL" "$((TOTAL_PASS + TOTAL_FAIL))" "$TOTAL_ASAN" "$TOTAL_UBSAN"
echo "────────────────────────────────────────────────────────────────"
echo "  Tools: $TOTAL_TOOLS  Logs: $LOGDIR/"
echo ""

if [ "$TOTAL_ASAN" -gt 0 ] || [ "$TOTAL_UBSAN" -gt 0 ]; then
  echo "⚠ SANITIZER FINDINGS DETECTED — review logs above"
  exit 2
elif [ "$HAS_FAILURE" -gt 0 ]; then
  echo "RESULT: SOME TESTS HAD FAILURES (0 ASAN, 0 UBSAN)"
  exit 1
else
  echo "RESULT: ALL TOOLS PASSED"
  exit 0
fi
