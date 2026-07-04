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
BIN_DIR="${AFL_BIN_DIR:-$REPO_ROOT/afl/bin}"

source "$REPO_ROOT/afl/targets.sh"

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
    echo "[OK] Reaped $removed empty AFL output directories"
}

reap_stale_resume_dirs() {
    local base="$1"
    local resume_removed=0
    local fastresume_removed=0
    local d

    while IFS= read -r -d '' d; do
        rm -rf -- "$d"
        echo "    reaped stale $d"
        resume_removed=$((resume_removed + 1))
    done < <(find "$base" -path '*/output/*/_resume' -type d -print0 2>/dev/null)
    echo "[OK] Reaped $resume_removed stale AFL _resume directories"

    while IFS= read -r -d '' d; do
        rm -f -- "$d"
        echo "    reaped stale $d"
        fastresume_removed=$((fastresume_removed + 1))
    done < <(find "$base" -path '*/output/*/fastresume.bin' -type f -print0 2>/dev/null)
    echo "[OK] Reaped $fastresume_removed stale AFL fastresume.bin files"
}

read_fuzzer_pid() {
    local stats="$1"

    awk -F: '$1 == "fuzzer_pid" {
        gsub(/^[ \t]+|[ \t]+$/, "", $2)
        print $2
        exit
    }' "$stats" 2>/dev/null || true
}

is_live_afl_pid() {
    local pid="$1"
    local cmdline

    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    [[ -r "/proc/$pid/cmdline" ]] || return 1
    cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
    [[ "$cmdline" == *"afl-fuzz"* ]]
}

collect_fuzzer_pids() {
    local base="$1"
    local stats
    local pid
    local seen=" "
    local proc_cmdline
    local cmdline

    [[ -d "$base" ]] || return 0
    while IFS= read -r -d '' stats; do
        pid="$(read_fuzzer_pid "$stats")"
        if is_live_afl_pid "$pid" && [[ "$seen" != *" $pid "* ]]; then
            printf '%s\n' "$pid"
            seen="${seen}${pid} "
        fi
    done < <(find "$base" -name fuzzer_stats -type f -print0 2>/dev/null)

    while IFS= read -r -d '' proc_cmdline; do
        pid="${proc_cmdline#/proc/}"
        pid="${pid%/cmdline}"
        cmdline="$(dd if="$proc_cmdline" bs=4096 count=1 2>/dev/null | tr '\0' ' ' || true)"
        if [[ "$cmdline" == *"afl-fuzz"* && "$cmdline" == *"$base"* && "$seen" != *" $pid "* ]]; then
            printf '%s\n' "$pid"
            seen="${seen}${pid} "
        fi
    done < <(find /proc -maxdepth 2 -path '/proc/[0-9]*/cmdline' -print0 2>/dev/null)
}

if [[ "$REAP" -eq 1 ]]; then
    if [[ -n "$TARGET" ]]; then
        if ! afl_configure_target "$TARGET"; then
            echo "ERROR: Unknown target '$TARGET'" >&2
            afl_print_targets >&2
            exit 1
        fi
        if [[ -n "$(collect_fuzzer_pids "$AFL_DIR/output")" ]]; then
            echo "ERROR: Refusing to reap while target AFL processes are running" >&2
            exit 1
        fi
        reap_stale_resume_dirs "$AFL_DIR/output"
        reap_empty_outputs "$AFL_DIR/output"
    else
        if [[ -n "$(collect_fuzzer_pids "$AFL_BASE")" ]]; then
            echo "ERROR: Refusing to reap while AFL processes are running" >&2
            exit 1
        fi
        reap_stale_resume_dirs "$AFL_BASE"
        reap_empty_outputs "$AFL_BASE"
    fi
fi

if [[ -z "$TARGET" ]]; then
    echo "[*] Stopping ALL afl-fuzz processes..."
    mapfile -t PIDS < <(collect_fuzzer_pids "$AFL_BASE")
else
    if ! afl_configure_target "$TARGET"; then
        echo "ERROR: Unknown target '$TARGET'" >&2
        afl_print_targets >&2
        exit 1
    fi
    echo "[*] Stopping afl-fuzz for target: $TARGET"
    mapfile -t PIDS < <(collect_fuzzer_pids "$AFL_DIR/output")
fi

if [[ ${#PIDS[@]} -eq 0 ]]; then
    echo "[*] No afl-fuzz processes found"
    exit 0
fi

COUNT=0
for pid in "${PIDS[@]}"; do
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
    for pid in "${PIDS[@]}"; do
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
