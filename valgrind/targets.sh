#!/usr/bin/env bash
# Shared target definitions for local Valgrind-family analysis.

VG_TARGETS=(
    connect-thread
    dump
    roundtrip
    fromxml
    fromjson
    toxml
    tojson
    tiffdump
    applynamedcmm
    applynamedcmm-calculator
    applyprofiles-row
    applysearch-row
    applytolink
    benchapply
    fromcube
    v5dspobs
)

VG_BUILD_TARGETS=(
    iccConnectThreadTest
    iccDumpProfile
    iccRoundTrip
    iccFromXml
    iccFromJson
    iccToXml
    iccToJson
    iccTiffDump
    iccApplyNamedCmm
    iccApplyProfiles
    iccApplySearch
    iccApplyToLink
    iccBenchApply
    iccV5DspObsToV4Dsp
    iccFromCube
)

vg_print_targets() {
    echo "Available targets:"
    echo "  connect-thread    - threaded CMM regression (best Helgrind/DRD target)"
    echo "  dump              - binary profile load, validate, and dump"
    echo "  roundtrip         - MPE profile load/write/reload path"
    echo "  fromxml           - XML profile parser and binary writer"
    echo "  fromjson          - JSON profile parser and binary writer"
    echo "  toxml             - binary profile to XML serializer"
    echo "  tojson            - binary profile to deterministic JSON serializer"
    echo "  tiffdump          - TIFF parser and embedded-profile extraction"
    echo "  applynamedcmm     - named CMM data application"
    echo "  applynamedcmm-calculator - calculator CMM application and registry lifetime"
    echo "  applyprofiles-row - four-worker TIFF row application"
    echo "  applysearch-row   - threshold-crossing inverse-search application"
    echo "  applytolink       - DeviceLink generation"
    echo "  benchapply        - threaded benchmark application path"
    echo "  fromcube          - .cube LUT conversion to an ICC DeviceLink"
    echo "  v5dspobs          - v5 display/observer conversion to a v4 display"
}

vg_tool_binary() {
    local tool_dir="$1"
    local binary_name="$2"
    printf '%s/Tools/%s/%s' "$VG_BUILD_DIR" "$tool_dir" "$binary_name"
}

vg_binary_uses_sanitizer() {
    local binary="$1"
    local library_path="$2"
    local build_dir="$3"
    local ldd_output
    local candidate
    local sanitizer_pattern='lib(asan|ubsan|tsan|msan|lsan)|libclang_rt\.(asan|ubsan|tsan|msan|lsan)|__(asan_init|ubsan_handle_|tsan_init|msan_init|lsan_init)'
    local -a candidates

    ldd_output="$(LD_LIBRARY_PATH="$library_path" ldd "$binary" 2>/dev/null || true)"
    if grep -Ei "$sanitizer_pattern" <<< "$ldd_output" >/dev/null; then
        return 0
    fi

    command -v nm >/dev/null 2>&1 || return 1
    candidates=("$binary")
    while IFS= read -r candidate; do
        if [[ -f "$candidate" && "$candidate" == "$build_dir"/* ]]; then
            candidates+=("$candidate")
        fi
    done < <(awk '/=> \// { print $3 } /^\// { print $1 }' <<< "$ldd_output")

    for candidate in "${candidates[@]}"; do
        if nm -a "$candidate" 2>/dev/null | grep -E "$sanitizer_pattern" >/dev/null; then
            return 0
        fi
    done

    return 1
}

vg_verify_target() {
    local stdout_log="$1"
    local output
    local actual
    local expected
    local i

    for output in "${VG_EXPECTED_OUTPUTS[@]}"; do
        if [[ ! -s "$output" ]]; then
            echo "expected nonempty output is missing: $output" >&2
            return 1
        fi
    done

    if [[ "$VG_EXPECT_STDOUT" -eq 1 && ! -s "$stdout_log" ]]; then
        echo "expected nonempty stdout: $stdout_log" >&2
        return 1
    fi

    if (( ${#VG_EXPECTED_SHA256[@]} % 2 != 0 )); then
        echo "invalid SHA-256 verification configuration" >&2
        return 1
    fi
    if [[ ${#VG_EXPECTED_SHA256[@]} -gt 0 ]]; then
        command -v sha256sum >/dev/null 2>&1 || {
            echo "sha256sum is required for output verification" >&2
            return 1
        }
    fi
    for ((i = 0; i < ${#VG_EXPECTED_SHA256[@]}; i += 2)); do
        output="${VG_EXPECTED_SHA256[$i]}"
        expected="${VG_EXPECTED_SHA256[$((i + 1))]}"
        actual="$(sha256sum "$output" | awk '{ print $1 }')"
        if [[ "$actual" != "$expected" ]]; then
            echo "SHA-256 mismatch for $output: expected $expected, got $actual" >&2
            return 1
        fi
    done

    return 0
}

vg_configure_target() {
    local target="$1"
    local profile="$VG_SOURCE_DIR/Testing/sRGB_v4_ICC_preference.icc"
    local xml_profile="$VG_SOURCE_DIR/Testing/Display/sRGB_D65_MAT.xml"
    local rgb_data="$REPO_ROOT/docs/iccDEV/Tools/test-data/test-data-rgb-16bit.txt"
    local tiff_input="$REPO_ROOT/fuzz/graphics/tif/1x1-rgb8--Rec2020rgbSpectral.tiff"
    local threaded_tiff_input="$REPO_ROOT/fuzz/graphics/tif/64x64-tile32--Rec2020rgbColorimetric.tiff"
    local search_data="$VG_SOURCE_DIR/Testing/ApplyDataFiles/RGBSurface.txt"
    local calculator_data="$VG_SOURCE_DIR/Testing/Calc/srgbCalcTest.txt"
    local calculator_profile="$REPO_ROOT/test-profiles/argbCalc.icc"
    local cube_input="$REPO_ROOT/docs/iccDEV/Tools/test-data/test-identity.cube"
    local v5_display="$REPO_ROOT/test-profiles/LCDDisplay.icc"
    local v5_observer="$REPO_ROOT/test-profiles/XYZ_float-D65_2deg-Part1.icc"
    local search_lines="${VALGRIND_APPLYSEARCH_LINES:-259}"

    VG_BINARY=""
    VG_CMAKE_TARGET=""
    VG_NOTE=""
    VG_RECOMMENDED_TOOL="memcheck"
    VG_ARGS=()
    VG_EXTRA_CMAKE_TARGETS=()
    VG_ENV=()
    VG_PREPARE=()
    VG_PREPARE_STDOUT=""
    VG_PREPARED_FILES=()
    VG_REQUIRED_FILES=()
    VG_EXPECTED_OUTPUTS=()
    VG_EXPECTED_SHA256=()
    VG_EXPECT_STDOUT=0

    case "$target" in
        connect-thread)
            VG_CMAKE_TARGET="iccConnectThreadTest"
            VG_BINARY="$VG_BUILD_DIR/Testing/iccConnectThreadTest"
            VG_ARGS=("$profile")
            VG_REQUIRED_FILES=("$profile")
            VG_RECOMMENDED_TOOL="helgrind"
            VG_NOTE="Exercises concurrent CIccCmm apply-object creation."
            ;;
        dump)
            VG_CMAKE_TARGET="iccDumpProfile"
            VG_BINARY="$(vg_tool_binary IccDumpProfile iccDumpProfile)"
            VG_ARGS=("-v" "100" "$profile" "ALL")
            VG_REQUIRED_FILES=("$profile")
            VG_EXPECT_STDOUT=1
            VG_NOTE="Exercises eager profile validation and tag dumping."
            ;;
        roundtrip)
            VG_CMAKE_TARGET="iccRoundTrip"
            VG_BINARY="$(vg_tool_binary IccRoundTrip iccRoundTrip)"
            VG_ARGS=("$profile" "1" "1")
            VG_REQUIRED_FILES=("$profile")
            VG_EXPECT_STDOUT=1
            VG_NOTE="Exercises the MPE round-trip path."
            ;;
        fromxml)
            VG_CMAKE_TARGET="iccFromXml"
            VG_BINARY="$(vg_tool_binary IccFromXml iccFromXml)"
            VG_ARGS=("$xml_profile" "$VG_RUN_WORK/fromxml.icc" "-noid")
            VG_REQUIRED_FILES=("$xml_profile")
            VG_EXPECTED_OUTPUTS=("$VG_RUN_WORK/fromxml.icc")
            VG_NOTE="Exercises XML parsing and binary serialization."
            ;;
        fromjson)
            VG_CMAKE_TARGET="iccFromJson"
            VG_BINARY="$(vg_tool_binary IccFromJson iccFromJson)"
            VG_PREPARE=("$(vg_tool_binary IccToJson iccToJson)" "$profile" "$VG_RUN_WORK/input.json" "-sort")
            VG_EXTRA_CMAKE_TARGETS=("iccToJson")
            VG_ARGS=("$VG_RUN_WORK/input.json" "$VG_RUN_WORK/fromjson.icc" "-noid")
            VG_REQUIRED_FILES=("$profile" "$(vg_tool_binary IccToJson iccToJson)")
            VG_PREPARED_FILES=("$VG_RUN_WORK/input.json")
            VG_EXPECTED_OUTPUTS=("$VG_RUN_WORK/fromjson.icc")
            VG_NOTE="Generates deterministic JSON, then analyzes JSON parsing and binary serialization."
            ;;
        toxml)
            VG_CMAKE_TARGET="iccToXml"
            VG_BINARY="$(vg_tool_binary IccToXml iccToXml)"
            VG_ARGS=("$profile" "$VG_RUN_WORK/output.xml")
            VG_REQUIRED_FILES=("$profile")
            VG_EXPECTED_OUTPUTS=("$VG_RUN_WORK/output.xml")
            VG_NOTE="Exercises XML serialization."
            ;;
        tojson)
            VG_CMAKE_TARGET="iccToJson"
            VG_BINARY="$(vg_tool_binary IccToJson iccToJson)"
            VG_ARGS=("$profile" "$VG_RUN_WORK/output.json" "-sort")
            VG_REQUIRED_FILES=("$profile")
            VG_EXPECTED_OUTPUTS=("$VG_RUN_WORK/output.json")
            VG_NOTE="Exercises deterministic JSON serialization."
            ;;
        tiffdump)
            VG_CMAKE_TARGET="iccTiffDump"
            VG_BINARY="$(vg_tool_binary IccTiffDump iccTiffDump)"
            VG_ARGS=("$tiff_input" "$VG_RUN_WORK/embedded.icc")
            VG_REQUIRED_FILES=("$tiff_input")
            VG_EXPECTED_OUTPUTS=("$VG_RUN_WORK/embedded.icc")
            VG_EXPECTED_SHA256=(
                "$VG_RUN_WORK/embedded.icc"
                "34ffc5f67f83947d1bd93cdadba0c08fba051d91af1f023fa032ccbd533f3d9d"
            )
            VG_NOTE="Exercises TIFF parsing and byte-for-byte embedded-profile extraction."
            ;;
        applynamedcmm)
            VG_CMAKE_TARGET="iccApplyNamedCmm"
            VG_BINARY="$(vg_tool_binary IccApplyNamedCmm iccApplyNamedCmm)"
            VG_ARGS=("$rgb_data" "5" "1" "$profile" "3")
            VG_REQUIRED_FILES=("$rgb_data" "$profile")
            VG_EXPECT_STDOUT=1
            VG_NOTE="Exercises 16-bit tetrahedral named CMM application."
            ;;
        applynamedcmm-calculator)
            VG_CMAKE_TARGET="iccApplyNamedCmm"
            VG_BINARY="$(vg_tool_binary IccApplyNamedCmm iccApplyNamedCmm)"
            VG_ARGS=("-debugcalc" "$calculator_data" "3" "0" "$calculator_profile" "1")
            VG_REQUIRED_FILES=("$calculator_data" "$calculator_profile")
            VG_EXPECT_STDOUT=1
            VG_NOTE="Exercises calculator operations and the process-lifetime CIccCalcOpMgr registry reported in iccDEV issue #3095."
            ;;
        applyprofiles-row)
            VG_CMAKE_TARGET="iccApplyProfiles"
            VG_BINARY="$(vg_tool_binary IccApplyProfiles iccApplyProfiles)"
            VG_ENV=("ICC_APPLY_PROFILES_BAND_ROWS=16")
            VG_ARGS=("-threads" "4" "$threaded_tiff_input" "$VG_RUN_WORK/applied.tif" "1" "0" "0" "1" "1" "$profile" "1")
            VG_REQUIRED_FILES=("$threaded_tiff_input" "$profile")
            VG_EXPECTED_OUTPUTS=("$VG_RUN_WORK/applied.tif")
            VG_RECOMMENDED_TOOL="helgrind"
            VG_NOTE="Exercises four active workers across four TIFF row batches."
            ;;
        applysearch-row)
            VG_CMAKE_TARGET="iccApplySearch"
            VG_BINARY="$(vg_tool_binary IccApplySearch iccApplySearch)"
            VG_PREPARE=(head -n "$search_lines" "$search_data")
            VG_PREPARE_STDOUT="$VG_RUN_WORK/input.txt"
            VG_PREPARED_FILES=("$VG_RUN_WORK/input.txt")
            VG_ARGS=("-threads" "4" "$VG_RUN_WORK/input.txt" "5" "1" "$profile" "1" "$profile" "1" "-INIT" "1" "$profile" "1")
            VG_REQUIRED_FILES=("$search_data" "$profile")
            VG_EXPECT_STDOUT=1
            VG_RECOMMENDED_TOOL="helgrind"
            VG_NOTE="Exercises a threshold-crossing inverse-search batch."
            ;;
        applytolink)
            VG_CMAKE_TARGET="iccApplyToLink"
            VG_BINARY="$(vg_tool_binary IccApplyToLink iccApplyToLink)"
            VG_ARGS=("$VG_RUN_WORK/link.icc" "0" "9" "0" "Valgrind" "0.0" "1.0" "1" "1" "$profile" "1" "$profile" "1")
            VG_REQUIRED_FILES=("$profile")
            VG_EXPECTED_OUTPUTS=("$VG_RUN_WORK/link.icc")
            VG_NOTE="Exercises DeviceLink generation with two profile transforms."
            ;;
        benchapply)
            VG_CMAKE_TARGET="iccBenchApply"
            VG_BINARY="$(vg_tool_binary IccBenchApply iccBenchApply)"
            VG_ARGS=("-pixels" "2048" "-repeats" "4" "-threads" "1,2,4" "1" "$profile" "140")
            VG_REQUIRED_FILES=("$profile")
            VG_EXPECT_STDOUT=1
            VG_RECOMMENDED_TOOL="helgrind"
            VG_NOTE="Exercises repeated benchmark calls with one, two, and four active threads."
            ;;
        fromcube)
            VG_CMAKE_TARGET="iccFromCube"
            VG_BINARY="$(vg_tool_binary IccFromCube iccFromCube)"
            VG_ARGS=("$cube_input" "$VG_RUN_WORK/from-cube.icc")
            VG_REQUIRED_FILES=("$cube_input")
            VG_EXPECTED_OUTPUTS=("$VG_RUN_WORK/from-cube.icc")
            VG_NOTE="Exercises bounded .cube parsing and DeviceLink serialization."
            ;;
        v5dspobs)
            VG_CMAKE_TARGET="iccV5DspObsToV4Dsp"
            VG_BINARY="$(vg_tool_binary IccV5DspObsToV4Dsp iccV5DspObsToV4Dsp)"
            VG_ARGS=("$v5_display" "$v5_observer" "$VG_RUN_WORK/v4-display.icc")
            VG_REQUIRED_FILES=("$v5_display" "$v5_observer")
            VG_EXPECTED_OUTPUTS=("$VG_RUN_WORK/v4-display.icc")
            VG_NOTE="Exercises v5 display and observer conversion to a v4 display profile."
            ;;
        *)
            return 1
            ;;
    esac
}
