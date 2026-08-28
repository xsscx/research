#!/usr/bin/env bash
# batch-test-external.sh — Test ICC profiles from any directory with iccDEV tools
#
# Runs iccDumpProfile, iccToXml, and iccRoundTrip against all .icc files in a
# directory, detecting ASAN/UBSAN errors, signal crashes, and timeouts.
# Results are NOT committed — this is for external profile testing.
#
# Usage:
#   ./batch-test-external.sh <directory> [--timeout N] [--max N] [--csv]
#
# Examples:
#   ./batch-test-external.sh /path/to/poc-profiles
#   ./batch-test-external.sh /path/to/mutants --timeout 15 --max 50
#   ./batch-test-external.sh /path/to/test-dir --csv
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# iccDEV tool paths
ICCDEV_BUILD="${ICCDEV_BUILD:-${REPO_ROOT}/iccDEV/Build}"
DUMP="${ICCDEV_BUILD}/Tools/IccDumpProfile/iccDumpProfile"
TOXML="${ICCDEV_BUILD}/Tools/IccToXml/iccToXml"
ROUND="${ICCDEV_BUILD}/Tools/IccRoundTrip/iccRoundTrip"
PAWG="${ICCDEV_BUILD}/Tools/IccPawgReport/iccPawgReport"

export LD_LIBRARY_PATH="${ICCDEV_BUILD}/IccProfLib:${ICCDEV_BUILD}/IccXML:${LD_LIBRARY_PATH:-}"

# Defaults
TIMEOUT=30
MAX_FILES=500
CSV_MODE=0
DIR=""

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift 2;;
    --max)     MAX_FILES="$2"; shift 2;;
    --csv)     CSV_MODE=1; shift;;
    -h|--help)
      echo "Usage: $0 <directory> [--timeout N] [--max N] [--csv]"
      echo "  --timeout N   Per-file timeout in seconds (default: 30)"
      echo "  --max N       Max files to process (default: 500)"
      echo "  --csv         Output results as CSV"
      exit 0;;
    *) DIR="$1"; shift;;
  esac
done

if [[ -z "$DIR" ]]; then
  echo "Error: specify a directory containing .icc files"
  exit 1
fi

if [[ ! -d "$DIR" ]]; then
  echo "Error: directory not found: $DIR"
  exit 1
fi

# Verify tools
missing=0
for tool in "$DUMP" "$TOXML" "$ROUND" "$PAWG"; do
  if [[ ! -x "$tool" ]]; then
    echo "Warning: tool not found: $tool"
    missing=1
  fi
done
if [[ $missing -eq 1 ]]; then
  echo "Build iccDEV first: cd iccDEV && cmake -B Build && cmake --build Build"
  exit 2
fi

# Counters
total=0; ok=0; errors=0; crashes=0; sanitizer=0; timeouts=0

# CSV header
if [[ $CSV_MODE -eq 1 ]]; then
  echo "file,size_bytes,dump_exit,toxml_exit,round_exit,pawg_exit,sanitizer_hits,status"
fi

# Collect files
mapfile -t files < <(find "$DIR" -maxdepth 1 -name '*.icc' -type f | sort | head -n "$MAX_FILES")
file_count=${#files[@]}

if [[ $file_count -eq 0 ]]; then
  echo "No .icc files found in $DIR"
  exit 0
fi

[[ $CSV_MODE -eq 0 ]] && echo "Testing $file_count profiles from $(realpath "$DIR") (timeout=${TIMEOUT}s, max=${MAX_FILES})"
[[ $CSV_MODE -eq 0 ]] && echo "═══════════════════════════════════════════════════════════════"

TMPXML=$(mktemp /tmp/batch-test-XXXXXX.xml)
trap 'rm -f "$TMPXML"' EXIT

for f in "${files[@]}"; do
  name=$(basename "$f")
  fsize=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
  total=$((total+1))

  # Run iccDumpProfile
  dump_stderr=$(timeout "$TIMEOUT" "$DUMP" "$f" 2>&1 >/dev/null)
  dump_rc=$?

  # Run iccToXml
  toxml_stderr=$(timeout "$TIMEOUT" "$TOXML" "$f" "$TMPXML" 2>&1)
  toxml_rc=$?

  # Run iccRoundTrip
  round_stderr=$(timeout "$TIMEOUT" "$ROUND" "$f" 2>&1 >/dev/null)
  round_rc=$?

  # Run the current PAWG assessment.
  pawg_stderr=$(timeout "$TIMEOUT" "$PAWG" --json "$f" 2>&1 >/dev/null)
  pawg_rc=$?

  # Check for sanitizer errors across all tools
  all_stderr="${dump_stderr}${toxml_stderr}${round_stderr}${pawg_stderr}"
  san_count=$(echo "$all_stderr" | grep -ciE 'ERROR.*AddressSanitizer|runtime error:|LeakSanitizer' || true)

  # Determine status
  max_rc=$dump_rc
  [[ $toxml_rc -gt $max_rc ]] && max_rc=$toxml_rc
  [[ $round_rc -gt $max_rc ]] && max_rc=$round_rc
  [[ $pawg_rc -gt $max_rc ]] && max_rc=$pawg_rc

  # Classify: 124=timeout, 128-254=signal crash, 255=tool rejection (-1), 1-127=error
  status="OK"
  has_timeout=0; has_crash=0
  for rc in $dump_rc $toxml_rc $round_rc $pawg_rc; do
    [[ $rc -eq 124 ]] && has_timeout=1
    [[ $rc -ge 128 ]] && [[ $rc -lt 255 ]] && has_crash=1
  done

  if [[ $has_timeout -eq 1 ]]; then
    status="TIMEOUT"
    timeouts=$((timeouts+1))
  elif [[ $has_crash -eq 1 ]]; then
    status="CRASH"
    crashes=$((crashes+1))
  elif [[ $san_count -gt 0 ]]; then
    status="SANITIZER"
    sanitizer=$((sanitizer+1))
  elif [[ $dump_rc -eq 255 ]] || [[ $toxml_rc -eq 255 ]] || [[ $round_rc -eq 255 ]] || [[ $pawg_rc -eq 255 ]]; then
    status="REJECTED"
    errors=$((errors+1))
  elif [[ $max_rc -ne 0 ]]; then
    status="ERROR"
    errors=$((errors+1))
  else
    ok=$((ok+1))
  fi

  if [[ $CSV_MODE -eq 1 ]]; then
    echo "$name,$fsize,$dump_rc,$toxml_rc,$round_rc,$pawg_rc,$san_count,$status"
  else
    case "$status" in
      OK)        [[ $file_count -le 100 ]] && echo "  ✅ $name";;
      TIMEOUT)   echo "  ⏰ $name: TIMEOUT (${TIMEOUT}s)";;
      CRASH)     echo "  💥 $name: SIGNAL CRASH (dump=$dump_rc xml=$toxml_rc rt=$round_rc pawg=$pawg_rc)"
                 echo "$all_stderr" | grep -iE 'ERROR.*Sanitizer|SUMMARY' | head -2 | sed 's/^/     /';;
      SANITIZER) echo "  ⚠️  $name: SANITIZER ($san_count hits)"
                 echo "$all_stderr" | grep -iE 'ERROR.*Sanitizer|SUMMARY|runtime error' | head -2 | sed 's/^/     /';;
      REJECTED)  [[ $file_count -le 100 ]] && echo "  🚫 $name: REJECTED (malformed)";;
      ERROR)     echo "  ❌ $name: ERROR (dump=$dump_rc xml=$toxml_rc rt=$round_rc pawg=$pawg_rc)";;
    esac
  fi
done

rm -f "$TMPXML"

if [[ $CSV_MODE -eq 0 ]]; then
  echo "═══════════════════════════════════════════════════════════════"
  echo "Results: $total tested | $ok OK | $errors rejected/errors | $sanitizer sanitizer | $crashes signal-crashes | $timeouts timeouts"

  if [[ $crashes -gt 0 ]] || [[ $sanitizer -gt 0 ]]; then
    echo ""
    echo "⚠️  FINDINGS DETECTED — review crash/sanitizer profiles with:"
    echo "   xxd <profile.icc>"
    echo "   iccPawgReport --json <profile.icc>"
    exit 1
  fi
fi

exit 0
