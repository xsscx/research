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
echo "[OK] Valgrind target registry passed: ${#VG_TARGETS[@]} targets"
