#!/bin/bash
# Shared sanitizer runtime settings for AFL execution and replay scripts.

AFL_ASAN_OPTIONS_FUZZ="${AFL_ASAN_OPTIONS_FUZZ:-detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=0:allocator_may_return_null=1}"
AFL_UBSAN_OPTIONS_FUZZ="${AFL_UBSAN_OPTIONS_FUZZ:-halt_on_error=1:abort_on_error=1:print_stacktrace=0}"
AFL_ASAN_OPTIONS_TRIAGE="${AFL_ASAN_OPTIONS_TRIAGE:-detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1}"
AFL_UBSAN_OPTIONS_TRIAGE="${AFL_UBSAN_OPTIONS_TRIAGE:-halt_on_error=1:abort_on_error=1:print_stacktrace=1}"
AFL_MSAN_OPTIONS_FUZZ="${AFL_MSAN_OPTIONS_FUZZ:-halt_on_error=1:abort_on_error=1:symbolize=0:exit_code=86}"
AFL_MSAN_OPTIONS_TRIAGE="${AFL_MSAN_OPTIONS_TRIAGE:-halt_on_error=1:abort_on_error=1:symbolize=1:exit_code=86}"
AFL_TSAN_OPTIONS_FUZZ="${AFL_TSAN_OPTIONS_FUZZ:-halt_on_error=1:abort_on_error=1:history_size=7:exitcode=86}"
AFL_TSAN_OPTIONS_TRIAGE="${AFL_TSAN_OPTIONS_TRIAGE:-halt_on_error=1:abort_on_error=1:history_size=7:exitcode=86}"

afl_normalize_sanitizer_mode() {
    case "${1:-address}" in
        address|asan) printf 'address' ;;
        memory|msan) printf 'memory' ;;
        thread|tsan) printf 'thread' ;;
        *) return 1 ;;
    esac
}

afl_detect_sanitizer_mode() {
    local bin_dir="${1:-}"
    local requested="${AFL_SANITIZER:-}"
    local marker=""

    if [[ -n "$requested" ]]; then
        afl_normalize_sanitizer_mode "$requested"
        return
    fi
    if [[ -n "$bin_dir" && -f "$bin_dir/.sanitizer-mode" ]]; then
        IFS= read -r marker < "$bin_dir/.sanitizer-mode"
        afl_normalize_sanitizer_mode "$marker"
        return
    fi
    case "$bin_dir" in
        *-msan) printf 'memory' ;;
        *-tsan) printf 'thread' ;;
        *) printf 'address' ;;
    esac
}

afl_default_bin_dir() {
    local default_dir="$1"
    local mode

    if [[ -n "${AFL_BIN_DIR:-}" ]]; then
        printf '%s' "$AFL_BIN_DIR"
        return
    fi
    mode="$(afl_normalize_sanitizer_mode "${AFL_SANITIZER:-address}")" || return 1
    case "$mode" in
        address) printf '%s' "$default_dir" ;;
        memory) printf '%s-msan' "$default_dir" ;;
        thread) printf '%s-tsan' "$default_dir" ;;
    esac
}

afl_export_sanitizer_env() {
    local phase="$1"
    local mode

    mode="$(afl_detect_sanitizer_mode "${2:-}")" || {
        echo "ERROR: unsupported AFL sanitizer '${AFL_SANITIZER:-unknown}'" >&2
        return 1
    }
    unset ASAN_OPTIONS UBSAN_OPTIONS LSAN_OPTIONS MSAN_OPTIONS TSAN_OPTIONS
    case "$mode:$phase" in
        address:fuzz)
            export ASAN_OPTIONS="$AFL_ASAN_OPTIONS_FUZZ"
            export UBSAN_OPTIONS="$AFL_UBSAN_OPTIONS_FUZZ"
            ;;
        address:triage)
            export ASAN_OPTIONS="$AFL_ASAN_OPTIONS_TRIAGE"
            export UBSAN_OPTIONS="$AFL_UBSAN_OPTIONS_TRIAGE"
            ;;
        memory:fuzz) export MSAN_OPTIONS="$AFL_MSAN_OPTIONS_FUZZ" ;;
        memory:triage) export MSAN_OPTIONS="$AFL_MSAN_OPTIONS_TRIAGE" ;;
        thread:fuzz) export TSAN_OPTIONS="$AFL_TSAN_OPTIONS_FUZZ" ;;
        thread:triage) export TSAN_OPTIONS="$AFL_TSAN_OPTIONS_TRIAGE" ;;
        *)
            echo "ERROR: unsupported AFL sanitizer phase '$phase'" >&2
            return 1
            ;;
    esac
    AFL_ACTIVE_SANITIZER="$mode"
    export -n AFL_ACTIVE_SANITIZER
}

afl_export_fuzz_sanitizer_env() {
    afl_export_sanitizer_env fuzz "${1:-}"
}

afl_export_triage_sanitizer_env() {
    afl_export_sanitizer_env triage "${1:-}"
}
