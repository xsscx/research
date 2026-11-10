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
    case "$VG_RECOMMENDED_TOOL" in
        memcheck|helgrind|drd) ;;
        *) echo "ERROR: bad recommended tool for $target: $VG_RECOMMENDED_TOOL" >&2; errors=$((errors + 1)) ;;
    esac
done

[[ "$errors" -eq 0 ]] || exit 1

validation_tmp="$(mktemp -d)"
trap 'rm -rf -- "$validation_tmp"' EXIT
mkdir -p "$validation_tmp/bin" "$validation_tmp/build/Tools/IccDumpProfile"
printf '#!/usr/bin/env bash\nexit 0\n' > "$validation_tmp/bin/valgrind"
printf '#!/usr/bin/env bash\nexit 0\n' > "$validation_tmp/build/Tools/IccDumpProfile/iccDumpProfile"
chmod +x "$validation_tmp/bin/valgrind" "$validation_tmp/build/Tools/IccDumpProfile/iccDumpProfile"

set +e
PATH="$validation_tmp/bin:$PATH" \
    VALGRIND_BUILD_DIR="$validation_tmp/build" \
    VALGRIND_OUTPUT_DIR="$validation_tmp/output" \
    "$REPO_ROOT/valgrind/run.sh" --tool memcheck --timeout 1 dump \
    >"$validation_tmp/stdout.log" 2>"$validation_tmp/stderr.log"
run_rc=$?
set -e
summary="$(find "$validation_tmp/output" -type f -name summary.tsv -print -quit)"
if [[ "$run_rc" -eq 0 ]]; then
    echo "ERROR: runner accepted an incomplete Memcheck log" >&2
    exit 1
fi
if [[ -z "$summary" ]] || ! grep -Fq $'dump\tmemcheck\t0\tNA\tincomplete-log\t' "$summary"; then
    echo "ERROR: runner did not classify an incomplete Memcheck log" >&2
    exit 1
fi

printf '#!/usr/bin/env bash\nexit 86\n' > "$validation_tmp/bin/valgrind"
set +e
PATH="$validation_tmp/bin:$PATH" \
    VALGRIND_BUILD_DIR="$validation_tmp/build" \
    "$REPO_ROOT/valgrind/run.sh" --tool memcheck --allow-findings \
    --output-dir "$validation_tmp/allowed-output" --timeout 1 dump \
    >"$validation_tmp/allowed-stdout.log" 2>"$validation_tmp/allowed-stderr.log"
allowed_rc=$?
set -e
if [[ "$allowed_rc" -eq 0 ]]; then
    echo "ERROR: --allow-findings accepted an incomplete Memcheck log" >&2
    exit 1
fi
if ! grep -Fq $'dump\tmemcheck\t86\tNA\tincomplete-log\t' \
    "$validation_tmp/allowed-output/summary.tsv"; then
    echo "ERROR: nonzero run did not preserve incomplete-log classification" >&2
    exit 1
fi

echo "[OK] Valgrind target registry passed: ${#VG_TARGETS[@]} targets"
