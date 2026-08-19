#!/usr/bin/env bash
# Validate iccProfilePlot AFL target contracts and their shared ICC fixture.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=afl/targets.sh
source "$REPO_ROOT/afl/targets.sh"

AFL_BASE="$(mktemp -d /tmp/afl-profileplot-contracts-XXXXXX)"
BIN_DIR="${AFL_BIN_DIR:-$REPO_ROOT/afl/bin}"
BINARY=""
trap 'rm -rf -- "$AFL_BASE"' EXIT

errors=0

fail() {
    echo "ERROR: $*" >&2
    errors=$((errors + 1))
}

expect_value() {
    local label="$1"
    local actual="$2"
    local expected="$3"

    if [[ "$actual" != "$expected" ]]; then
        fail "$label: expected '$expected', got '$actual'"
    fi
}

validate_target() {
    local target="$1"
    shift
    local expected_args=("$@")
    local matches

    matches="$(printf '%s\n' "${AFL_TARGETS[@]}" | grep -Fxc -- "$target" || true)"
    expect_value "$target inventory count" "$matches" "1"

    afl_configure_target "$target"
    expect_value "$target binary" "$BINARY" "$BIN_DIR/iccProfilePlot"
    expect_value "$target seed maximum" "$SEED_MAX_BYTES" "262144"
    expect_value "$target dry run" "$SEED_DRY_RUN_TARGET" "1"
    expect_value "$target exit-zero screening" "$SEED_DRY_RUN_REQUIRE_ZERO_TARGET" "1"
    expect_value "$target argument count" "${#AFL_ARGS[@]}" "${#expected_args[@]}"

    local i
    for i in "${!expected_args[@]}"; do
        if [[ "${expected_args[$i]}" == __TMP__ ]]; then
            [[ "${AFL_ARGS[$i]}" == "$AFL_TMP_PREFIX"* ]] ||
                fail "$target argument $i does not use its process scratch prefix"
        else
            expect_value "$target argument $i" "${AFL_ARGS[$i]}" "${expected_args[$i]}"
        fi
    done

    expect_value "$target fixture count" "${#SEED_FILES[@]}" "1"
    expect_value "$target required fixture count" "${#REQUIRED_FILES[@]}" "1"
    expect_value "$target fixture contract" "${SEED_FILES[0]}" "${REQUIRED_FILES[0]}"
    [[ -f "${SEED_FILES[0]}" ]] || fail "$target fixture is missing: ${SEED_FILES[0]}"
}

validate_target profileplot '@@' list
validate_target profileplot-graph '@@' graph 'chroma:xy'
validate_target profileplot-raster '@@' raster 'clut:A2B0' __TMP__

if [[ "${1:-}" == "--replay" ]]; then
    fixture="$REPO_ROOT/test-profiles/sRGB_v4_ICC_preference.icc"
    binary="$BIN_DIR/iccProfilePlot"
    raw_out="$AFL_BASE/profileplot.raw"
    list_output=""
    graph_output=""
    raster_output=""

    [[ -x "$binary" ]] || fail "replay binary is missing or not executable: $binary"
    [[ -f "$fixture" ]] || fail "replay fixture is missing: $fixture"
    if [[ -x "$binary" && -f "$fixture" ]]; then
        list_output="$("$binary" "$fixture" list)"
        [[ "$list_output" == *'"id":"chroma:xy"'* ]] ||
            fail "list replay did not enumerate chroma:xy"
        graph_output="$("$binary" "$fixture" graph 'chroma:xy')"
        [[ "$graph_output" == *'"series"'* ]] ||
            fail "graph replay did not emit graph series"
        raster_output="$("$binary" "$fixture" raster 'clut:A2B0' "$raw_out")"
        [[ "$raster_output" == *'"samplesFile"'* ]] ||
            fail "raster replay did not report raw samples"
        [[ -s "$raw_out" ]] || fail "raster replay did not create raw sample data"
    fi
elif [[ $# -gt 0 ]]; then
    echo "Usage: $0 [--replay]" >&2
    exit 1
fi

if [[ "$errors" -ne 0 ]]; then
    echo "iccProfilePlot AFL target validation failed with $errors error(s)." >&2
    exit 1
fi

echo "iccProfilePlot AFL target validation passed."
