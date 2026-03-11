#!/bin/bash
# afl/stop.sh — Stop AFL++ fuzzer instances
#
# Usage: ./afl/stop.sh [target]
#
# Without target: stops ALL afl-fuzz processes
# With target: stops only processes for that target

set -euo pipefail

TARGET="${1:-}"
AFL_SSD="${AFL_SSD:-/mnt/g/fuzz-ssd}"

if [[ -z "$TARGET" ]]; then
    echo "[*] Stopping ALL afl-fuzz processes..."
    PIDS=$(pgrep -f "afl-fuzz" 2>/dev/null || true)
else
    AFL_DIR="$AFL_SSD/afl-$TARGET"
    echo "[*] Stopping afl-fuzz for target: $TARGET"
    PIDS=$(pgrep -f "afl-fuzz.*afl-$TARGET" 2>/dev/null || true)
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

    # Check if any are still running
    REMAINING=0
    for pid in $PIDS; do
        if kill -0 "$pid" 2>/dev/null; then
            echo "    PID $pid still running — sending SIGKILL"
            kill -9 "$pid" 2>/dev/null || true
            REMAINING=$((REMAINING + 1))
        fi
    done

    if [[ $REMAINING -eq 0 ]]; then
        echo "[OK] All AFL instances stopped gracefully"
    else
        echo "[OK] $REMAINING instance(s) force-killed"
    fi
fi
