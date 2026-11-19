#!/usr/bin/env bash
# Validate the Valgrind target registry without requiring a build.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VG_SOURCE_DIR="$REPO_ROOT/iccDEV"
VG_BUILD_DIR="$REPO_ROOT/valgrind/build"
VG_RUN_WORK="$REPO_ROOT/valgrind/validation-work"

# shellcheck source=valgrind/targets.sh
source "$REPO_ROOT/valgrind/targets.sh"

errors=0
declare -A seen=()
for target in "${VG_TARGETS[@]}"; do
    if [[ -n "${seen[$target]:-}" ]]; then
        echo "ERROR: duplicate target: $target" >&2
        errors=$((errors + 1))
        continue
    fi
    seen[$target]=1
    if ! vg_configure_target "$target"; then
        echo "ERROR: target does not configure: $target" >&2
        errors=$((errors + 1))
        continue
    fi
    [[ -n "$VG_BINARY" && -n "$VG_CMAKE_TARGET" && ${#VG_ARGS[@]} -gt 0 ]] || {
        echo "ERROR: incomplete target: $target" >&2
        errors=$((errors + 1))
    }
    for extra_target in "${VG_EXTRA_CMAKE_TARGETS[@]}"; do
        [[ -n "$extra_target" ]] || { echo "ERROR: empty extra CMake target for $target" >&2; errors=$((errors + 1)); }
    done
    if (( ${#VG_EXPECTED_SHA256[@]} % 2 != 0 )); then
        echo "ERROR: incomplete SHA-256 expectation for $target" >&2
        errors=$((errors + 1))
    fi
    if [[ -n "$VG_PREPARE_STDOUT" && ${#VG_PREPARE[@]} -eq 0 ]]; then
        echo "ERROR: prepare stdout configured without a command for $target" >&2
        errors=$((errors + 1))
    fi
    case "$VG_RECOMMENDED_TOOL" in
        memcheck|helgrind|drd) ;;
        *) echo "ERROR: bad recommended tool for $target: $VG_RECOMMENDED_TOOL" >&2; errors=$((errors + 1)) ;;
    esac
done

[[ "$errors" -eq 0 ]] || exit 1

validation_tmp="$(mktemp -d)"
trap 'rm -rf -- "$validation_tmp"' EXIT
mkdir -p "$validation_tmp/bin" \
    "$validation_tmp/build/Tools/IccDumpProfile" \
    "$validation_tmp/build/Tools/IccFromJson" \
    "$validation_tmp/build/Tools/IccToJson" \
    "$validation_tmp/build/Tools/IccToXml"
# The single-quoted expansions below belong to the generated fake Valgrind.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'log_file=""' \
    'for arg in "$@"; do' \
    '    case "$arg" in' \
    '        --log-file=*) log_file="${arg#--log-file=}" ;;' \
    '    esac' \
    'done' \
    'if [[ "${FAKE_COMPLETE:-1}" -eq 1 ]]; then' \
    '    printf "==1== ERROR SUMMARY: %s errors from %s contexts (suppressed: 0 from 0)\\n" "${FAKE_ERRORS:-0}" "${FAKE_ERRORS:-0}" > "$log_file"' \
    'fi' \
    'printf "fake target output\\n"' \
    'exit "${FAKE_RC:-0}"' \
    > "$validation_tmp/bin/valgrind"
printf '#!/usr/bin/env bash\nprintf "dump output\\n"\n' \
    > "$validation_tmp/build/Tools/IccDumpProfile/iccDumpProfile"
printf '#!/usr/bin/env bash\nexit 0\n' \
    > "$validation_tmp/build/Tools/IccFromJson/iccFromJson"
printf '#!/usr/bin/env bash\nexit 7\n' \
    > "$validation_tmp/build/Tools/IccToJson/iccToJson"
printf '#!/usr/bin/env bash\nexit 0\n' \
    > "$validation_tmp/build/Tools/IccToXml/iccToXml"
chmod +x "$validation_tmp/bin/valgrind" \
    "$validation_tmp/build/Tools/IccDumpProfile/iccDumpProfile" \
    "$validation_tmp/build/Tools/IccFromJson/iccFromJson" \
    "$validation_tmp/build/Tools/IccToJson/iccToJson" \
    "$validation_tmp/build/Tools/IccToXml/iccToXml"

set +e
FAKE_COMPLETE=0 PATH="$validation_tmp/bin:$PATH" \
    VALGRIND_BUILD_DIR="$validation_tmp/build" \
    "$REPO_ROOT/valgrind/run.sh" --tool memcheck --timeout 1 \
    --output-dir "$validation_tmp/incomplete" dump \
    >"$validation_tmp/stdout.log" 2>"$validation_tmp/stderr.log"
run_rc=$?
set -e
if [[ "$run_rc" -eq 0 ]]; then
    echo "ERROR: runner accepted an incomplete Memcheck log" >&2
    exit 1
fi
if ! grep -Fq $'dump\tmemcheck\t0\tNA\tincomplete-log\t' \
    "$validation_tmp/incomplete/summary.tsv"; then
    echo "ERROR: runner did not classify an incomplete Memcheck log" >&2
    exit 1
fi

set +e
FAKE_COMPLETE=1 FAKE_ERRORS=1 FAKE_RC=86 PATH="$validation_tmp/bin:$PATH" \
    VALGRIND_BUILD_DIR="$validation_tmp/build" \
    "$REPO_ROOT/valgrind/run.sh" --tool memcheck --allow-findings \
    --output-dir "$validation_tmp/finding" --timeout 1 dump \
    >"$validation_tmp/allowed-stdout.log" 2>"$validation_tmp/allowed-stderr.log"
allowed_rc=$?
set -e
if [[ "$allowed_rc" -ne 0 ]]; then
    echo "ERROR: --allow-findings rejected a complete Valgrind finding" >&2
    exit 1
fi
if ! grep -Fq $'dump\tmemcheck\t86\t1\tfinding\t' \
    "$validation_tmp/finding/summary.tsv"; then
    echo "ERROR: runner did not preserve the allowed Valgrind finding" >&2
    exit 1
fi

for failure_case in tool-failure:1 signal:139 timeout:124; do
    expected_result="${failure_case%%:*}"
    fake_rc="${failure_case##*:}"
    set +e
    FAKE_COMPLETE=1 FAKE_ERRORS=0 FAKE_RC="$fake_rc" PATH="$validation_tmp/bin:$PATH" \
        VALGRIND_BUILD_DIR="$validation_tmp/build" \
        "$REPO_ROOT/valgrind/run.sh" --tool memcheck --allow-findings \
        --output-dir "$validation_tmp/$expected_result" --timeout 1 dump \
        >"$validation_tmp/$expected_result.stdout.log" \
        2>"$validation_tmp/$expected_result.stderr.log"
    failure_rc=$?
    set -e
    if [[ "$failure_rc" -eq 0 ]]; then
        echo "ERROR: --allow-findings accepted $expected_result" >&2
        exit 1
    fi
    if ! grep -Fq $'dump\tmemcheck\t'"$fake_rc"$'\t0\t'"$expected_result"$'\t' \
        "$validation_tmp/$expected_result/summary.tsv"; then
        echo "ERROR: runner did not classify $expected_result" >&2
        exit 1
    fi
done

FAKE_COMPLETE=1 FAKE_ERRORS=0 FAKE_RC=0 PATH="$validation_tmp/bin:$PATH" \
    VALGRIND_BUILD_DIR="$validation_tmp/build" \
    "$REPO_ROOT/valgrind/run.sh" --tool memcheck \
    --output-dir "$validation_tmp/duplicates" --timeout 1 dump dump \
    >"$validation_tmp/duplicates.stdout.log" 2>"$validation_tmp/duplicates.stderr.log"
if [[ ! -s "$validation_tmp/duplicates/dump/memcheck.log" ||
      ! -s "$validation_tmp/duplicates/dump-2/memcheck.log" ]]; then
    echo "ERROR: repeated targets did not retain separate evidence" >&2
    exit 1
fi

set +e
FAKE_COMPLETE=1 FAKE_ERRORS=0 FAKE_RC=0 PATH="$validation_tmp/bin:$PATH" \
    VALGRIND_BUILD_DIR="$validation_tmp/build" \
    "$REPO_ROOT/valgrind/run.sh" --tool memcheck --allow-findings \
    --output-dir "$validation_tmp/setup-failure" --timeout 1 fromjson \
    >"$validation_tmp/setup-failure.stdout.log" 2>"$validation_tmp/setup-failure.stderr.log"
setup_rc=$?
set -e
if [[ "$setup_rc" -eq 0 ]] || \
    ! grep -Fq $'fromjson\tmemcheck\t7\tNA\tsetup-failure\t' \
        "$validation_tmp/setup-failure/summary.tsv"; then
    echo "ERROR: runner did not preserve setup-failure classification" >&2
    exit 1
fi

set +e
FAKE_COMPLETE=1 FAKE_ERRORS=0 FAKE_RC=0 PATH="$validation_tmp/bin:$PATH" \
    VALGRIND_BUILD_DIR="$validation_tmp/build" \
    "$REPO_ROOT/valgrind/run.sh" --tool memcheck \
    --output-dir "$validation_tmp/verification-failure" --timeout 1 toxml \
    >"$validation_tmp/verification-failure.stdout.log" \
    2>"$validation_tmp/verification-failure.stderr.log"
verification_rc=$?
set -e
if [[ "$verification_rc" -eq 0 ]] || \
    ! grep -Fq $'toxml\tmemcheck\t0\t0\tverification-failure\t' \
        "$validation_tmp/verification-failure/summary.tsv"; then
    echo "ERROR: runner did not preserve verification-failure classification" >&2
    exit 1
fi

echo "[OK] Valgrind target registry passed: ${#VG_TARGETS[@]} targets"
