#!/bin/bash
# afl/status.sh — Show AFL++ fuzzer status
#
# Usage: ./afl/status.sh [target]
#
# Without target: shows status for all targets
# With target: shows detailed status for that target

set -euo pipefail

AFL_SSD="${AFL_SSD:-/mnt/g/fuzz-ssd}"
TARGET="${1:-}"

print_status() {
    local name="$1"
    local dir="$AFL_SSD/afl-$name/output"

    # Find all instance directories (default, main, secondary_*)
    local instances=()
    for d in "$dir"/*/fuzzer_stats; do
        [[ -f "$d" ]] && instances+=("$(dirname "$d")")
    done

    if [[ ${#instances[@]} -eq 0 ]]; then
        echo "[$name] No active session"
        return
    fi

    for inst_dir in "${instances[@]}"; do
        local inst_name=$(basename "$inst_dir")
        local stats="$inst_dir/fuzzer_stats"

        # Parse key stats
        local run_time=$(grep "^run_time" "$stats" | awk '{print $3}')
        local execs=$(grep "^execs_done" "$stats" | awk '{print $3}')
        local eps=$(grep "^execs_per_sec" "$stats" | awk '{print $3}')
        local corpus=$(grep "^corpus_count" "$stats" | awk '{print $3}')
        local found=$(grep "^corpus_found" "$stats" | awk '{print $3}')
        local crashes=$(grep "^saved_crashes" "$stats" | awk '{print $3}')
        local hangs=$(grep "^saved_hangs" "$stats" | awk '{print $3}')
        local bitmap=$(grep "^bitmap_cvg" "$stats" | awk '{print $3}')
        local stability=$(grep "^stability" "$stats" | awk '{print $3}')
        local cycles=$(grep "^cycles_done" "$stats" | awk '{print $3}')
        local pid=$(grep "^fuzzer_pid" "$stats" | awk '{print $3}')

        # Check if still running
        local status="STOPPED"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            status="RUNNING"
        fi

        # Format runtime
        local hours=$((run_time / 3600))
        local mins=$(( (run_time % 3600) / 60 ))
        local secs=$((run_time % 60))
        local runtime_fmt="${hours}h${mins}m${secs}s"

        echo "[$name/$inst_name] $status"
        echo "  Runtime:    $runtime_fmt (cycles: $cycles)"
        echo "  Execs:      $execs ($eps exec/s)"
        echo "  Corpus:     $corpus (found: $found)"
        echo "  Coverage:   $bitmap (stability: $stability)"
        echo "  Crashes:    $crashes"
        echo "  Hangs:      $hangs"

        # List crash files if any
        local crash_dir="$inst_dir/crashes"
        if [[ -d "$crash_dir" ]]; then
            local crash_count=$(ls "$crash_dir" 2>/dev/null | grep -v README | wc -l)
            if [[ $crash_count -gt 0 ]]; then
                echo "  Crash files:"
                ls -1 "$crash_dir" | grep -v README | while read -r f; do
                    echo "    $crash_dir/$f"
                done
            fi
        fi

        # List hang files if any
        local hang_dir="$inst_dir/hangs"
        if [[ -d "$hang_dir" ]]; then
            local hang_count=$(ls "$hang_dir" 2>/dev/null | grep -v README | wc -l)
            if [[ $hang_count -gt 0 ]]; then
                echo "  Hang files:"
                ls -1 "$hang_dir" | grep -v README | sed -n '1,5p' | while read -r f; do
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

# Known targets
TARGETS=(fromcube)

if [[ -n "$TARGET" ]]; then
    print_status "$TARGET"
else
    echo "=== AFL++ Fuzzer Status ==="
    echo ""
    for t in "${TARGETS[@]}"; do
        print_status "$t"
    done

    # Show running afl-fuzz processes
    echo "--- Active Processes ---"
    ps aux 2>/dev/null | grep "[a]fl-fuzz" | awk '{printf "  PID %-8s CPU %-5s MEM %-5s %s\n", $2, $3, $4, $11}' || echo "  (none)"
fi
