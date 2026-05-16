#!/bin/bash
# afl/status.sh - Show AFL++ fuzzer status
#
# Usage: ./afl/status.sh [target]
#
# Without target: shows status for all targets
# With target: shows detailed status for that target

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
TARGET="${1:-}"

print_status() {
    local name="$1"
    local dir="$AFL_BASE/afl-$name/output"

    local instances=()
    for d in "$dir"/*/fuzzer_stats; do
        [[ -f "$d" ]] && instances+=("$(dirname "$d")")
    done

    if [[ ${#instances[@]} -eq 0 ]]; then
        echo "[$name] No active session"
        return
    fi

    for inst_dir in "${instances[@]}"; do
        local inst_name
        inst_name=$(basename "$inst_dir")
        local stats="$inst_dir/fuzzer_stats"

        local run_time
        local execs
        local eps
        local corpus
        local found
        local crashes
        local hangs
        local bitmap
        local stability
        local cycles
        local pid
        run_time=$(grep "^run_time" "$stats" | awk '{print $3}')
        execs=$(grep "^execs_done" "$stats" | awk '{print $3}')
        eps=$(grep "^execs_per_sec" "$stats" | awk '{print $3}')
        corpus=$(grep "^corpus_count" "$stats" | awk '{print $3}')
        found=$(grep "^corpus_found" "$stats" | awk '{print $3}')
        crashes=$(grep "^saved_crashes" "$stats" | awk '{print $3}')
        hangs=$(grep "^saved_hangs" "$stats" | awk '{print $3}')
        bitmap=$(grep "^bitmap_cvg" "$stats" | awk '{print $3}')
        stability=$(grep "^stability" "$stats" | awk '{print $3}')
        cycles=$(grep "^cycles_done" "$stats" | awk '{print $3}')
        pid=$(grep "^fuzzer_pid" "$stats" | awk '{print $3}')

        local status="STOPPED"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            status="RUNNING"
        fi

        local hours=$((run_time / 3600))
        local mins=$(((run_time % 3600) / 60))
        local secs=$((run_time % 60))
        local runtime_fmt="${hours}h${mins}m${secs}s"

        echo "[$name/$inst_name] $status"
        echo "  Runtime:    $runtime_fmt (cycles: $cycles)"
        echo "  Execs:      $execs ($eps exec/s)"
        echo "  Corpus:     $corpus (found: $found)"
        echo "  Coverage:   $bitmap (stability: $stability)"
        echo "  Crashes:    $crashes"
        echo "  Hangs:      $hangs"

        local crash_dir="$inst_dir/crashes"
        if [[ -d "$crash_dir" ]]; then
            local crash_count
            crash_count=$(find "$crash_dir" -maxdepth 1 -type f ! -name 'README*' 2>/dev/null | wc -l)
            if [[ $crash_count -gt 0 ]]; then
                echo "  Crash files:"
                find "$crash_dir" -maxdepth 1 -type f ! -name 'README*' -printf '%f\n' | while read -r f; do
                    echo "    $crash_dir/$f"
                done
            fi
        fi

        local hang_dir="$inst_dir/hangs"
        if [[ -d "$hang_dir" ]]; then
            local hang_count
            hang_count=$(find "$hang_dir" -maxdepth 1 -type f ! -name 'README*' 2>/dev/null | wc -l)
            if [[ $hang_count -gt 0 ]]; then
                echo "  Hang files:"
                find "$hang_dir" -maxdepth 1 -type f ! -name 'README*' -printf '%f\n' | sed -n '1,5p' | while read -r f; do
                    echo "    $hang_dir/$f"
                done
                if [[ $hang_count -gt 5 ]]; then
                    echo "    ... and $((hang_count - 5)) more"
                fi
            fi
        fi
        echo ""
    done
}

TARGETS=(dump toxml fromxml roundtrip tiffdump jpegdump pngdump fromcube search)

if [[ -n "$TARGET" ]]; then
    print_status "$TARGET"
else
    echo "=== AFL++ Fuzzer Status ==="
    echo ""
    for t in "${TARGETS[@]}"; do
        print_status "$t"
    done

    echo "--- Active Processes ---"
    ps -C afl-fuzz -o pid=,pcpu=,pmem=,comm= 2>/dev/null | awk '{printf "  PID %-8s CPU %-5s MEM %-5s %s\n", $1, $2, $3, $4}' || echo "  (none)"
fi
