#!/bin/bash
# Shared sanitizer runtime settings for AFL execution and replay scripts.

AFL_ASAN_OPTIONS_FUZZ="${AFL_ASAN_OPTIONS_FUZZ:-detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=0:allocator_may_return_null=1}"
AFL_UBSAN_OPTIONS_FUZZ="${AFL_UBSAN_OPTIONS_FUZZ:-halt_on_error=1:abort_on_error=1:print_stacktrace=0}"
AFL_ASAN_OPTIONS_TRIAGE="${AFL_ASAN_OPTIONS_TRIAGE:-detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1}"
AFL_UBSAN_OPTIONS_TRIAGE="${AFL_UBSAN_OPTIONS_TRIAGE:-halt_on_error=1:abort_on_error=1:print_stacktrace=1}"

afl_export_fuzz_sanitizer_env() {
    export ASAN_OPTIONS="$AFL_ASAN_OPTIONS_FUZZ"
    export UBSAN_OPTIONS="$AFL_UBSAN_OPTIONS_FUZZ"
    unset LSAN_OPTIONS MSAN_OPTIONS TSAN_OPTIONS
}

afl_export_triage_sanitizer_env() {
    export ASAN_OPTIONS="$AFL_ASAN_OPTIONS_TRIAGE"
    export UBSAN_OPTIONS="$AFL_UBSAN_OPTIONS_TRIAGE"
    unset LSAN_OPTIONS MSAN_OPTIONS TSAN_OPTIONS
}
