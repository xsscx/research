#!/bin/bash
# afl/stop.sh - Stop AFL++ fuzzer instances
#
# Usage: ./afl/stop.sh [target|all] [--force] [--reap]

set -euo pipefail

TARGET=""
FORCE=0
REAP=0
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
BIN_DIR="$AFL_BASE/bin"

source "$AFL_BASE/targets.sh"

usage() {
    sed -n '2,5p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Options:"
    echo "  --force      send SIGKILL if SIGINT does not stop the process"
    echo "  --reap       remove empty stale AFL output instance directories"
    echo "  --help, -h   show help"
    echo ""
    afl_print_targets
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force) FORCE=1; shift ;;
        --reap) REAP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        all) TARGET=""; shift ;;
        -*) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 1 ;;
        *) TARGET="$1"; shift ;;
    esac
done

reap_empty_outputs() {
    local base="$1"
    local removed=0
    local d
    while IFS= read -r -d '' d; do
        if rmdir "$d" 2>/dev/null; then
            echo "    reaped $d"
            removed=$((removed + 1))
        fi
    done < <(find "$base" -path '*/output/*' -type d -empty -print0 2>/dev/null)
    echo "[OK] Reaped $removed empty AFL output directorie(s)"
}

if [[ "$REAP" -eq 1 ]]; then
    if [[ -n "$TARGET" ]]; then
        if ! afl_configure_target "$TARGET"; then
            echo "ERROR: Unknown target '$TARGET'" >&2
            afl_print_targets >&2
            exit 1
        fi
        reap_empty_outputs "$AFL_DIR/output"
    else
        reap_empty_outputs "$AFL_BASE"
    fi
fi

if [[ -z "$TARGET" ]]; then
    echo "[*] Stopping ALL afl-fuzz processes..."
    PIDS=$(pgrep -f "afl-fuzz" 2>/dev/null || true)
else
    if ! afl_configure_target "$TARGET"; then
        echo "ERROR: Unknown target '$TARGET'" >&2
        afl_print_targets >&2
        exit 1
    fi
    echo "[*] Stopping afl-fuzz for target: $TARGET"
    PIDS=$(pgrep -f "afl-fuzz.*$AFL_DIR/output" 2>/dev/null || true)
fi

if [[ -z "$PIDS" ]]; then
    echo "[*] No afl-fuzz processes found"
    exit 0
fi

COUNT=0
for pid in $PIDS; do
    if kill -0 "$pid" 2>/dev/null; then
        echo "    Sending SIGINT to PID $pid"
        kill -INT "$pid" 2>/dev/null || true
        COUNT=$((COUNT + 1))
    fi
done

if [[ $COUNT -gt 0 ]]; then
    echo "[*] Sent SIGINT to $COUNT process(es)"
    echo "[*] Waiting 3s for graceful shutdown..."
    sleep 3

    REMAINING=0
    for pid in $PIDS; do
        if kill -0 "$pid" 2>/dev/null; then
            REMAINING=$((REMAINING + 1))
            if [[ "$FORCE" -eq 1 ]]; then
                echo "    PID $pid still running - sending SIGKILL"
                kill -KILL "$pid" 2>/dev/null || true
            else
                echo "    [WARN] PID $pid still running; rerun with --force if needed"
            fi
        fi
    done

    if [[ $REMAINING -eq 0 ]]; then
        echo "[OK] All AFL instances stopped gracefully"
    elif [[ "$FORCE" -eq 1 ]]; then
        echo "[OK] $REMAINING instance(s) force-killed"
    else
        echo "[WARN] $REMAINING instance(s) still running"
        exit 1
    fi
fi
