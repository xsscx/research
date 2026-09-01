#!/bin/bash
# Shared AFL++ target definitions for iccDEV tool binaries.

AFL_TARGETS=(
    applynamedcmm
    applynamedcmm-debugcalc
    applynamedcmm-cfg
    applynamedcmm-hybrid-chain
    applynamedcmm-hybrid-pcc
    applyprofiles
    applyprofiles-fast
    applyprofiles-deep
    applyprofiles-cfg
    applyprofiles-hybrid-embedded
    applyprofiles-hybrid-pcc
    applyprofiles-row
    applysearch
    applysearch-noinit
    applysearch-cfg
    applysearch-fast
    applysearch-hybrid-pcc
    applysearch-weight-positive
    applysearch-weight-positive-fast
    applysearch-weight-zero
    applysearch-weight-negative
    applysearch-weight-nan
    applytolink
    applytolink-v5
    applytolink-cube
    dump
    dump-diag
    dump-read
    fromcube
    fromjson
    fromxml
    fromxml-includes
    fromxml-noid
    jpegdump
    jpegdump-inject
    pawgreport
    pawgreport-fast
    pngdump
    pngdump-inject
    profileplot
    profileplot-graph
    profileplot-raster
    profilevisualize
    profilevisualize-fast
    roundtrip
    roundtrip-mpe
    specseptotiff
    specseptotiff-compress
    specseptotiff-desc
    specseptotiff-harvest
    specseptotiff-sep
    specseptotiff-short
    specseptotiff-tiff
    tiffdump
    tiffdump-extract
    tojson
    toxml
    toxml-fast
    v5dspobs
)

afl_print_targets() {
    echo "Available targets:"
    echo "  applynamedcmm    - iccApplyNamedCmm (fixed data, fuzz ICC profile)"
    echo "  applynamedcmm-debugcalc - iccApplyNamedCmm (float/linear calculator trace lane)"
    echo "  applynamedcmm-cfg - iccApplyNamedCmm (-cfg JSON config lane)"
    echo "  applynamedcmm-hybrid-chain - iccApplyNamedCmm (fixed v5 profile, fuzz second profile)"
    echo "  applynamedcmm-hybrid-pcc - iccApplyNamedCmm hybrid v5/PCC lane"
    echo "  applyprofiles    - iccApplyProfiles (fixed TIFF, fuzz ICC profile)"
    echo "  applyprofiles-fast - iccApplyProfiles (small ICC profile lane)"
    echo "  applyprofiles-deep - iccApplyProfiles (large ICC profile lane)"
    echo "  applyprofiles-cfg - iccApplyProfiles (-cfg JSON config lane)"
    echo "  applyprofiles-hybrid-embedded - iccApplyProfiles hybrid embedded/PCC argv lane"
    echo "  applyprofiles-hybrid-pcc - iccApplyProfiles hybrid -exportcfg PCC lane"
    echo "  applyprofiles-row - iccApplyProfiles (-threads row-apply lane)"
    echo "  applysearch      - iccApplySearch (fixed data, fuzz ICC profiles)"
    echo "  applysearch-noinit - iccApplySearch (float/linear destination, no -INIT)"
    echo "  applysearch-cfg  - iccApplySearch (-cfg JSON config lane)"
    echo "  applysearch-fast - iccApplySearch (small/no-trim search lane)"
    echo "  applysearch-hybrid-pcc - iccApplySearch hybrid v5/PCC lane"
    echo "  applysearch-weight-positive - iccApplySearch (fuzz PCC profile, fixed weight 1)"
    echo "  applysearch-weight-positive-fast - iccApplySearch (small/no-trim weight 1 lane)"
    echo "  applysearch-weight-zero - iccApplySearch (fuzz PCC profile, fixed weight 0)"
    echo "  applysearch-weight-negative - iccApplySearch (fuzz PCC profile, fixed weight -1)"
    echo "  applysearch-weight-nan - iccApplySearch (fuzz PCC profile, fixed finite max-float weight)"
    echo "  applytolink      - iccApplyToLink (DeviceLink/.cube generation)"
    echo "  applytolink-v5   - iccApplyToLink (v5 extended-range DeviceLink)"
    echo "  applytolink-cube - iccApplyToLink (.cube text generation)"
    echo "  dump             - iccDumpProfile (ICC binary -> text dump)"
    echo "  dump-diag        - iccDumpProfile (--diag size/load diagnostics)"
    echo "  dump-read        - iccDumpProfile (--read eager profile load)"
    echo "  fromcube         - iccFromCube (.cube LUT text -> ICC)"
    echo "  fromjson         - iccFromJson (ICC JSON -> binary)"
    echo "  fromxml          - iccFromXml (ICC XML -> binary)"
    echo "  fromxml-includes - iccFromXml (fixed external TXT/XML include tree)"
    echo "  fromxml-noid     - iccFromXml (-noid save policy)"
    echo "  jpegdump         - iccJpegDump (JPEG -> ICC extraction)"
    echo "  jpegdump-inject  - iccJpegDump (--write-icc injection lane)"
    echo "  pawgreport       - iccPawgReport (PAWG profile assessment)"
    echo "  pawgreport-fast  - iccPawgReport (small/no-trim profile assessment lane)"
    echo "  pngdump          - iccPngDump (PNG -> ICC extraction)"
    echo "  pngdump-inject   - iccPngDump (--write-icc injection lane)"
    echo "  profileplot      - iccProfilePlot (descriptor list JSON lane)"
    echo "  profileplot-graph - iccProfilePlot (graph JSON lane)"
    echo "  profileplot-raster - iccProfilePlot (CLUT raster/raw-output lane)"
    echo "  profilevisualize - iccProfileVisualize (ICC profile visualization)"
    echo "  profilevisualize-fast - iccProfileVisualize (small/no-trim visualization lane)"
    echo "  roundtrip        - iccRoundTrip (ICC binary round-trip)"
    echo "  roundtrip-mpe    - iccRoundTrip (MPE round-trip lane)"
    echo "  specseptotiff    - iccSpecSepToTiff (fixed spectral TIFFs, fuzz embedded ICC)"
    echo "  specseptotiff-compress - iccSpecSepToTiff (compressed output lane)"
    echo "  specseptotiff-desc - iccSpecSepToTiff (descending channel range lane)"
    echo "  specseptotiff-harvest - iccSpecSepToTiff (gray300 spectral TIFF lane)"
    echo "  specseptotiff-sep - iccSpecSepToTiff (separated planes lane)"
    echo "  specseptotiff-short - iccSpecSepToTiff (short-range compatibility lane)"
    echo "  specseptotiff-tiff - iccSpecSepToTiff (fuzz spectral TIFF input via wrapper)"
    echo "  tiffdump         - iccTiffDump (TIFF -> ICC extraction)"
    echo "  tiffdump-extract - iccTiffDump (TIFF -> saved embedded ICC extraction)"
    echo "  tojson           - iccToJson (ICC binary -> JSON)"
    echo "  toxml            - iccToXml (ICC binary -> XML)"
    echo "  toxml-fast       - iccToXml (small/no-trim XML conversion lane)"
    echo "  v5dspobs         - iccV5DspObsToV4Dsp (fuzz v5 display profile)"
}

afl_target_names() {
    printf '%s\n' "${AFL_TARGETS[@]}"
}

afl_first_existing() {
    local candidate
    for candidate in "$@"; do
        if [[ -e "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    printf '%s' "$1"
}

afl_configure_target() {
    local target="$1"
    local tmp_root="${AFL_TMP_ROOT:-$AFL_BASE/tmp}"
    local tmp_prefix="$tmp_root/afl-${target}-$$"
    AFL_TMP_PREFIX="$tmp_prefix"
    local rgb_data="$REPO_ROOT/docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt"
    local rgb_16_data="$REPO_ROOT/docs/iccDEV/Tools/test-data/test-data-rgb-16bit.txt"
    local rgb_float_data="$REPO_ROOT/docs/iccDEV/Tools/test-data/test-data-rgb-float.txt"
    local srgb_profile
    local fixed_tiff
    local fixed_observer
    local fixed_jpeg
    local fixed_plot_profile
    local iccdev_testing_dir
    local hybrid_source_dir
    local hybrid_support_dir
    local fromxml_kind
    local fromxml_fixture
    local fromxml_detail

    mkdir -p "$tmp_root"

    srgb_profile="$(afl_first_existing \
        "$REPO_ROOT/test-profiles/sRGB_v4_ICC_preference.icc" \
        "$REPO_ROOT/afl/iccDEV/Testing/sRGB_v4_ICC_preference.icc" \
        "$REPO_ROOT/iccDEV/Testing/sRGB_v4_ICC_preference.icc" \
        "$REPO_ROOT/test-profiles/sRgbEncoding.icc")"
    fixed_tiff="$(afl_first_existing \
        "$REPO_ROOT/test-profiles/tiff-codecs/seed-tiff-none-rgb-8x8.tif" \
        "$REPO_ROOT/afl/iccDEV/Testing/hybrid/Data/TShirtDesignKW.tif" \
        "$REPO_ROOT/test-profiles/Tek350Monaco2_A2B0.tif")"
    fixed_observer="$(afl_first_existing \
        "$REPO_ROOT/test-profiles/XYZ_float-D65_2deg-Part1.icc" \
        "$REPO_ROOT/test-profiles/Lab_float-D65_2deg-Part1.icc" \
        "$REPO_ROOT/test-profiles/Spec400_10_700-D50_2deg-Part1.icc")"
    fixed_jpeg="$(afl_first_existing \
        "$REPO_ROOT/test-profiles/p0-2225-cve-2021-30942-colorsync-uninit-mem.jpg" \
        "$REPO_ROOT/fuzz/graphics/jpg/2x2-rgb--sRGB_v4_ICC_preference.jpg")"
    fixed_plot_profile="$(afl_first_existing \
        "$REPO_ROOT/test-profiles/sRGB_v4_ICC_preference.icc" \
        "$REPO_ROOT/iccDEV/Testing/sRGB_v4_ICC_preference.icc" \
        "$REPO_ROOT/afl/iccDEV/Testing/sRGB_v4_ICC_preference.icc")"
    iccdev_testing_dir="$(afl_first_existing \
        "$REPO_ROOT/iccDEV/Testing" \
        "$REPO_ROOT/afl/iccDEV/Testing")"
    hybrid_source_dir="$(afl_first_existing \
        "$REPO_ROOT/iccDEV/Testing/hybrid" \
        "$REPO_ROOT/afl/iccDEV/Testing/hybrid")"
    hybrid_support_dir="$AFL_BASE/support/hybrid"

    BINARY=""
    AFL_WORK_DIR="$REPO_ROOT"
    AFL_DIR="$AFL_BASE/afl-$target"
    AFL_COVERAGE_CACHE_KEY=""
    DICT=""
    TARGET_NOTE=""
    SEED_MAX_BYTES=0
    SEED_LIMIT=200
    AFL_DISABLE_TRIM_TARGET=0
    AFL_FAST_CAL_TARGET=0
    AFL_EXPAND_HAVOC_TARGET=0
    AFL_SKIP_DETERMINISTIC_TARGET=0
    AFL_NO_FORKSRV_TARGET=0
    AFL_SKIP_BIN_CHECK_TARGET=0
    AFL_TARGET_TIMEOUT=0
    SEED_DRY_RUN_TARGET=0
    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=0
    SEED_DRY_RUN_TIMEOUT=5
    SEED_INCLUDE_REGEX=""
    SEED_EXCLUDE_REGEX=""
    SEED_REQUIRE_JPEG_ICC=0
    REQUIRED_FILES=()
    SEED_FILES=()
    SEED_DIRS=()
    SEED_FIND_MAXDEPTH=1
    SEED_FILE_TYPE_REGEX=""
    AFL_ARGS=()
    HYBRID_NEEDS_SUPPORT=0
    FROMXML_INCLUDES_NEEDS_SUPPORT=0
    ISOLATED_WORK_NEEDS_SUPPORT=0
    ISOLATED_WORK_FILES=()
    FROMXML_INCLUDES_MANIFEST="$REPO_ROOT/afl/fromxml-includes.manifest"
    FROMXML_INCLUDES_SOURCE_DIR="$(afl_first_existing \
        "$REPO_ROOT/iccDEV/Testing" \
        "$REPO_ROOT/afl/iccDEV/Testing")"
    FROMXML_INCLUDES_SUPPORT_DIR="$AFL_BASE/support/fromxml-includes"
    ICCDEV_TESTING_DIR="$iccdev_testing_dir"
    HYBRID_SOURCE_DIR="$hybrid_source_dir"
    HYBRID_SUPPORT_DIR="$hybrid_support_dir"
    HYBRID_CONFIG_DIR="$hybrid_support_dir/config"
    HYBRID_DATA_DIR="$hybrid_support_dir/Data"
    HYBRID_ICC_DIR="$hybrid_support_dir/ICC"
    HYBRID_RESULTS_DIR="$hybrid_support_dir/Results"
    HYBRID_MS_TIFF="$hybrid_support_dir/Results/MS_smCows.tif"
    HYBRID_CMYK_DATA="$hybrid_support_dir/Data/cmykGrays.txt"
    HYBRID_CMYK_REF="$hybrid_support_dir/Results/cmykGraysRef.txt"
    HYBRID_CMYK_PROFILE="$hybrid_support_dir/ICC/CMYK_Hybrid_Profile.icc"
    HYBRID_LAB_D50="$hybrid_support_dir/ICC/Lab_float-D50_2deg.icc"
    HYBRID_LAB_D93="$hybrid_support_dir/ICC/Lab_float-D93_2deg-MAT.icc"
    HYBRID_LAB_F11="$hybrid_support_dir/ICC/Lab_float-F11_2deg-MAT.icc"
    HYBRID_LAB_ILLUMA="$hybrid_support_dir/ICC/Lab_float-IllumA_2deg-MAT.icc"
    HYBRID_SPEC_D50="$hybrid_support_dir/ICC/Spec380_10_730-D50_2deg.icc"
    HYBRID_SPEC_F11="$hybrid_support_dir/ICC/Spec400_10_700-F11_2deg-Abs.icc"
    HYBRID_SPEC_ILLUMA="$hybrid_support_dir/ICC/Spec400_10_700-IllumA_2deg-Abs.icc"
    HYBRID_SENTINEL_ICC="$AFL_BASE/support/nonicc-seed.icc"
    HYBRID_SENTINEL_TIFF="$AFL_BASE/support/nontiff-seed.tif"
    HYBRID_SRGB="$(afl_first_existing \
        "$REPO_ROOT/iccDEV/Testing/sRGB_v4_ICC_preference.icc" \
        "$REPO_ROOT/afl/iccDEV/Testing/sRGB_v4_ICC_preference.icc" \
        "$REPO_ROOT/test-profiles/sRGB_D65_MAT.icc")"

    case "$target" in
        applynamedcmm|applynamedcmm-debugcalc|applynamedcmm-cfg|namedcmm-cfg)
            BINARY="$BIN_DIR/iccApplyNamedCmm"
            DICT="$REPO_ROOT/cfl/icc_applynamedcmm_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_MAX_BYTES=1048576
            SEED_FILE_TYPE_REGEX='^(color profile|ColorSync color profile|data)'
            REQUIRED_FILES=("$rgb_16_data")
            if [[ "$target" == applynamedcmm-cfg || "$target" == namedcmm-cfg ]]; then
                AFL_DIR="$AFL_BASE/afl-applynamedcmm-cfg"
                AFL_WORK_DIR="$AFL_BASE/work/applynamedcmm-cfg/root"
                ISOLATED_WORK_NEEDS_SUPPORT=1
                ISOLATED_WORK_FILES=(
                    "$REPO_ROOT/test-profiles/sRGB_D65_MAT.icc"
                    "$rgb_data"
                    "$REPO_ROOT/docs/Testing/test-data/rgb-float.txt"
                    "$REPO_ROOT/fuzz/graphics/icc/sbo-CIccCalculatorFunc-Apply-IccMpeCalc_cpp-Line3873.icc"
                )
                DICT="$REPO_ROOT/cfl/icc_cfg.dict"
                SEED_MAX_BYTES=262144
                SEED_FILE_TYPE_REGEX='^(JSON text data|ASCII text)'
                SEED_LIMIT=300
                AFL_DISABLE_TRIM_TARGET=1
                AFL_FAST_CAL_TARGET=1
                SEED_DRY_RUN_TARGET=1
                SEED_INCLUDE_REGEX='(^|/)(applynamedcmm-|sbo-repro-applynamedcmm|array-not-object|empty-object|invalid-syntax|null-value|missing-profilesequence|wrong-types|type-confusion-all-fields|empty-arrays|null-all-fields|null-sections|empty-string-paths|nonexistent-profile|path-traversal-|extreme-|negative-nan-infinity|envvars-extreme-values|deep-profile-chain)'
                [[ -z "${AFL_INPUT_FORMAT:-}" ]] && AFL_INPUT_FORMAT="text"
                [[ -z "${AFL_MAX_LENGTH:-}" ]] && AFL_MAX_LENGTH=65536
                SEED_EXCLUDE_REGEX='output-to-file\.json$'
                SEED_DIRS=(
                    "$REPO_ROOT/docs/Testing/json-configs"
                    "$REPO_ROOT/docs/Testing/malformed-json"
                )
                REQUIRED_FILES=()
                TARGET_NOTE="ApplyNamedCmm JSON config lane: fuzzes the first-class -cfg command-line mode."
                AFL_ARGS=("-cfg" "@@")
            elif [[ "$target" == applynamedcmm-debugcalc ]]; then
                AFL_DIR="$AFL_BASE/afl-applynamedcmm-debugcalc"
                REQUIRED_FILES=("$rgb_float_data")
                SEED_MAX_BYTES=262144
                SEED_LIMIT=96
                SEED_DRY_RUN_TARGET=1
                SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                AFL_DISABLE_TRIM_TARGET=1
                AFL_FAST_CAL_TARGET=1
                TARGET_NOTE="ApplyNamedCmm calculator lane: float output, linear interpolation, and -debugcalc exercise calculator tracing and non-integer encoding paths."
                AFL_ARGS=("-debugcalc" "$rgb_float_data" "3:8:12" "0" "@@" "0")
            else
                TARGET_NOTE="ApplyNamedCmm ICC lane: 16-bit data output with tetrahedral interpolation exercises a different apply path than the former 8-bit linear shape."
                AFL_ARGS=("$rgb_16_data" "5" "1" "@@" "1")
            fi
            ;;
        applynamedcmm-hybrid-chain|namedcmm-hybrid-chain)
            BINARY="$BIN_DIR/iccApplyNamedCmm"
            AFL_DIR="$AFL_BASE/afl-applynamedcmm-hybrid-chain"
            DICT="$REPO_ROOT/cfl/icc_applynamedcmm_fuzzer.dict"
            HYBRID_NEEDS_SUPPORT=1
            SEED_MAX_BYTES=1048576
            SEED_LIMIT=200
            SEED_DRY_RUN_TARGET=1
            SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
            SEED_FIND_MAXDEPTH=2
            SEED_DIRS=(
                "$ICCDEV_TESTING_DIR"
                "$HYBRID_ICC_DIR"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_FILE_TYPE_REGEX='^(color profile|ColorSync color profile|data)'
            REQUIRED_FILES=("$HYBRID_CMYK_DATA" "$HYBRID_CMYK_PROFILE")
            TARGET_NOTE="Hybrid NamedCmm chain lane: exports embedded data, applies the fixed CMYK v5 profile with intent 10003, then fuzzes the second profile with no-D2Bx intent 10."
            AFL_ARGS=("-exportcfganddata" "${tmp_prefix}.json" "$HYBRID_CMYK_DATA" "3" "1" "$HYBRID_CMYK_PROFILE" "10003" "@@" "10")
            ;;
        applynamedcmm-hybrid-pcc|namedcmm-hybrid-pcc)
            BINARY="$BIN_DIR/iccApplyNamedCmm"
            AFL_DIR="$AFL_BASE/afl-applynamedcmm-hybrid-pcc"
            DICT="$REPO_ROOT/cfl/icc_applynamedcmm_fuzzer.dict"
            HYBRID_NEEDS_SUPPORT=1
            SEED_MAX_BYTES=1048576
            SEED_LIMIT=300
            SEED_DRY_RUN_TARGET=1
            SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
            SEED_FIND_MAXDEPTH=2
            SEED_DIRS=(
                "$ICCDEV_TESTING_DIR"
                "$HYBRID_ICC_DIR"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/extended-test-profiles"
            )
            REQUIRED_FILES=("$HYBRID_CMYK_DATA" "$HYBRID_CMYK_PROFILE" "$HYBRID_SPEC_D50")
            TARGET_NOTE="Hybrid NamedCmm PCC lane: applies the fixed CMYK v5 profile with environment variables, fuzzes its PCC profile, and retains only seeds that build and apply the full transform."
            AFL_ARGS=("-exportcfganddata" "${tmp_prefix}.json" "$HYBRID_CMYK_DATA" "5" "1" "-ENV:bkgX" "0.0985" "-ENV:bkgY" "0.159" "-ENV:bkgZ" "0.122" "$HYBRID_CMYK_PROFILE" "10003" "-PCC" "@@" "$HYBRID_SPEC_D50" "3")
            ;;
        applyprofiles|profiles|applyprofiles-fast|profiles-fast|applyprofiles-deep|profiles-deep|applyprofiles-cfg|profiles-cfg|applyprofiles-hybrid-embedded|profiles-hybrid-embedded|applyprofiles-hybrid-pcc|profiles-hybrid-pcc|applyprofiles-row|profiles-row)
            BINARY="$BIN_DIR/iccApplyProfiles"
            DICT="$REPO_ROOT/cfl/icc_applyprofiles_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_MAX_BYTES=1048576
            SEED_FILE_TYPE_REGEX='^(color profile|ColorSync color profile|data)'
            REQUIRED_FILES=("$fixed_tiff")
            case "$target" in
                applyprofiles-fast|profiles-fast)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles-fast"
                    SEED_MAX_BYTES=262144
                    SEED_LIMIT=300
                    SEED_DRY_RUN_TARGET=1
                    TARGET_NOTE="Fast ApplyProfiles lane: 8-bit, uncompressed, chunky, non-embedded, linear output with only seeds <= 256 KiB copied into a fresh corpus."
                    AFL_ARGS=("$fixed_tiff" "${tmp_prefix}.tif" "0" "0" "0" "0" "0" "@@" "1")
                    ;;
                applyprofiles-deep|profiles-deep)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles-deep"
                    SEED_LIMIT=200
                    SEED_DRY_RUN_TARGET=1
                    TARGET_NOTE="Deep ApplyProfiles lane: 8-bit, uncompressed, chunky, non-embedded, linear output with seeds capped at AFL++'s default 1 MiB testcase limit."
                    AFL_ARGS=("$fixed_tiff" "${tmp_prefix}.tif" "0" "0" "0" "0" "0" "@@" "1")
                    ;;
                applyprofiles-cfg|profiles-cfg)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles-cfg"
                    AFL_WORK_DIR="$AFL_BASE/work/applyprofiles-cfg/root"
                    ISOLATED_WORK_NEEDS_SUPPORT=1
                    ISOLATED_WORK_FILES=(
                        "$REPO_ROOT/test-profiles/sRGB_D65_MAT.icc"
                        "$fixed_tiff"
                        "$REPO_ROOT/docs/Testing/test-data/rgb-4x4-8bit.tif"
                        "$REPO_ROOT/fuzz/graphics/icc/sbo-CIccCalculatorFunc-Apply-IccMpeCalc_cpp-Line3873.icc"
                    )
                    DICT="$REPO_ROOT/cfl/icc_cfg.dict"
                    SEED_MAX_BYTES=262144
                    SEED_FILE_TYPE_REGEX='^(JSON text data|ASCII text)'
                    SEED_LIMIT=300
                    AFL_DISABLE_TRIM_TARGET=1
                    AFL_FAST_CAL_TARGET=1
                    SEED_DRY_RUN_TARGET=1
                    SEED_INCLUDE_REGEX='(^|/)(applyprofiles-|sbo-repro-applyprofiles|array-not-object|empty-object|invalid-syntax|null-value|missing-profilesequence|wrong-types|type-confusion-all-fields|empty-arrays|null-all-fields|null-sections|empty-string-paths|nonexistent-profile|path-traversal-|extreme-|negative-nan-infinity|envvars-extreme-values|deep-profile-chain)'
                    [[ -z "${AFL_INPUT_FORMAT:-}" ]] && AFL_INPUT_FORMAT="text"
                    [[ -z "${AFL_MAX_LENGTH:-}" ]] && AFL_MAX_LENGTH=65536
                    SEED_EXCLUDE_REGEX='output-to-file\.json$'
                    SEED_DIRS=(
                        "$REPO_ROOT/docs/Testing/json-configs"
                        "$REPO_ROOT/docs/Testing/malformed-json"
                    )
                    TARGET_NOTE="ApplyProfiles JSON config lane: fuzzes the documented -threads N -cfg config_file shape from the iccApplyProfiles CLI."
                    AFL_ARGS=("-threads" "1" "-cfg" "@@")
                    ;;
                applyprofiles-hybrid-embedded|profiles-hybrid-embedded)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles-hybrid-embedded"
                    DICT="$REPO_ROOT/cfl/icc_tiffdump_fuzzer.dict"
                    HYBRID_NEEDS_SUPPORT=1
                    SEED_MAX_BYTES=3145728
                    [[ -z "${AFL_MAX_LENGTH:-}" ]] && AFL_MAX_LENGTH=3145728
                    SEED_LIMIT=300
                    SEED_DRY_RUN_TARGET=1
                    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                    SEED_DRY_RUN_TIMEOUT=15
                    AFL_TARGET_TIMEOUT=15000
                    AFL_FAST_CAL_TARGET=1
                    AFL_EXPAND_HAVOC_TARGET=1
                    AFL_SKIP_DETERMINISTIC_TARGET=1
                    SEED_FILES=("$HYBRID_MS_TIFF")
                    SEED_FILE_TYPE_REGEX='^(TIFF image data|Big TIFF image data)'
                    SEED_DIRS=()
                    REQUIRED_FILES=("$HYBRID_SOURCE_DIR" "$HYBRID_SRGB")
                    TARGET_NOTE="Hybrid ApplyProfiles embedded/PCC lane: fuzzes the full-size generated multispectral TIFF with fast calibration, immediate expanded havoc, and no enhanced deterministic inference stage."
                    AFL_ARGS=("@@" "${tmp_prefix}.tif" "3" "1" "1" "1" "1" "-embedded" "10003" "-PCC" "$HYBRID_SPEC_F11" "$HYBRID_SRGB" "41")
                    ;;
                applyprofiles-hybrid-pcc|profiles-hybrid-pcc)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles-hybrid-pcc"
                    HYBRID_NEEDS_SUPPORT=1
                    SEED_MAX_BYTES=524288
                    SEED_LIMIT=1
                    SEED_DRY_RUN_TARGET=1
                    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                    SEED_DRY_RUN_TIMEOUT=15
                    AFL_TARGET_TIMEOUT=15000
                    SEED_FILES=("$HYBRID_ICC_DIR/MultSpectralRGB.icc")
                    SEED_DIRS=()
                    REQUIRED_FILES=("$HYBRID_SOURCE_DIR" "$HYBRID_SRGB")
                    TARGET_NOTE="Hybrid ApplyProfiles PCC lane: places the fuzzed MultSpectralRGB profile after -PCC and screens the complete embedded-to-sRGB transform before launch."
                    AFL_ARGS=("-exportcfg" "${tmp_prefix}.json" "$HYBRID_MS_TIFF" "${tmp_prefix}.tif" "3" "1" "1" "1" "1" "-embedded" "10003" "-PCC" "@@" "$HYBRID_SRGB" "41")
                    ;;
                applyprofiles-row|profiles-row)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles-row"
                    SEED_MAX_BYTES=524288
                    SEED_LIMIT=300
                    TARGET_NOTE="Row ApplyProfiles lane: uses four explicit workers to exercise deterministic row/batched CMM Apply."
                    SEED_DRY_RUN_TARGET=1
                    AFL_ARGS=("-threads" "4" "$fixed_tiff" "${tmp_prefix}.tif" "3" "1" "1" "1" "1" "@@" "40")
                    ;;
                profiles)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles"
                    SEED_DRY_RUN_TARGET=1
                    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                    SEED_FILES=("$srgb_profile")
                    SEED_EXCLUDE_REGEX='^sRGB_v4_ICC_preference\.icc$'
                    TARGET_NOTE="ApplyProfiles ICC lane: float, compressed, planar, embedded, tetrahedral output with BPC exercises every high-value image argv option."
                    AFL_ARGS=("$fixed_tiff" "${tmp_prefix}.tif" "3" "1" "1" "1" "1" "@@" "40")
                    ;;
                *)
                    SEED_DRY_RUN_TARGET=1
                    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                    SEED_FILES=("$srgb_profile")
                    SEED_EXCLUDE_REGEX='^sRGB_v4_ICC_preference\.icc$'
                    TARGET_NOTE="ApplyProfiles ICC lane: float, compressed, planar, embedded, tetrahedral output with BPC exercises every high-value image argv option."
                    AFL_ARGS=("$fixed_tiff" "${tmp_prefix}.tif" "3" "1" "1" "1" "1" "@@" "40")
                    ;;
            esac
            ;;
        applysearch|search|applysearch-noinit|applysearch-cfg|search-cfg|applysearch-fast|search-fast|applysearch-hybrid-pcc|search-hybrid-pcc|applysearch-weight|search-weight|applysearch-weight-positive|search-weight-positive|applysearch-weight-positive-fast|search-weight-positive-fast|applysearch-weight-zero|search-weight-zero|applysearch-weight-negative|search-weight-negative|applysearch-weight-nan|search-weight-nan)
            BINARY="$BIN_DIR/iccApplySearch"
            if [[ "$target" == "search" ]]; then
                AFL_DIR="$AFL_BASE/afl-search"
            elif [[ "$target" == applysearch-cfg || "$target" == search-cfg ]]; then
                AFL_DIR="$AFL_BASE/afl-applysearch-cfg"
            elif [[ "$target" == applysearch-fast || "$target" == search-fast ]]; then
                AFL_DIR="$AFL_BASE/afl-applysearch-fast"
            elif [[ "$target" == applysearch-noinit ]]; then
                AFL_DIR="$AFL_BASE/afl-applysearch-noinit"
            elif [[ "$target" == applysearch-hybrid-pcc || "$target" == search-hybrid-pcc ]]; then
                AFL_DIR="$AFL_BASE/afl-applysearch-hybrid-pcc"
            elif [[ "$target" == applysearch-weight-positive-fast ]]; then
                AFL_DIR="$AFL_BASE/afl-applysearch-weight-positive-fast"
            elif [[ "$target" == search-weight-positive-fast ]]; then
                AFL_DIR="$AFL_BASE/afl-applysearch-weight-positive-fast"
            elif [[ "$target" == applysearch-weight* ]]; then
                AFL_DIR="$AFL_BASE/afl-$target"
            elif [[ "$target" == search-weight* ]]; then
                AFL_DIR="$AFL_BASE/afl-applysearch-weight-${target#search-weight-}"
            else
                AFL_DIR="$AFL_BASE/afl-applysearch"
            fi
            DICT="$REPO_ROOT/cfl/icc_applysearch_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/cfl/corpus-icc_applysearch_fuzzer"
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_MAX_BYTES=1048576
            SEED_FILE_TYPE_REGEX='^(color profile|ColorSync color profile|data)'
            REQUIRED_FILES=("$rgb_data" "$srgb_profile")
            if [[ "$target" == applysearch-cfg || "$target" == search-cfg ]]; then
                AFL_WORK_DIR="$AFL_BASE/work/applysearch-cfg/root"
                ISOLATED_WORK_NEEDS_SUPPORT=1
                ISOLATED_WORK_FILES=("$REPO_ROOT/test-profiles/sRGB_D65_MAT.icc")
                DICT="$REPO_ROOT/cfl/icc_cfg.dict"
                SEED_MAX_BYTES=262144
                SEED_FILE_TYPE_REGEX='^(JSON text data|ASCII text)'
                SEED_LIMIT=300
                AFL_DISABLE_TRIM_TARGET=1
                AFL_FAST_CAL_TARGET=1
                SEED_DRY_RUN_TARGET=1
                SEED_INCLUDE_REGEX='(^|/)(applysearch-|pccweight-|searchapply-|array-not-object|empty-object|invalid-syntax|null-value|missing-profilesequence|wrong-types|type-confusion-all-fields|empty-arrays|null-all-fields|null-sections|empty-string-paths|nonexistent-profile|path-traversal-|extreme-|negative-nan-infinity|envvars-extreme-values|deep-profile-chain)'
                [[ -z "${AFL_INPUT_FORMAT:-}" ]] && AFL_INPUT_FORMAT="text"
                [[ -z "${AFL_MAX_LENGTH:-}" ]] && AFL_MAX_LENGTH=65536
                SEED_EXCLUDE_REGEX='output-to-file\.json$'
                SEED_DIRS=(
                    "$REPO_ROOT/docs/Testing/json-configs"
                    "$REPO_ROOT/docs/Testing/malformed-json"
                )
                REQUIRED_FILES=()
                TARGET_NOTE="ApplySearch JSON config lane: fuzzes the first-class -cfg command-line mode."
                AFL_ARGS=("-cfg" "@@")
            elif [[ "$target" == applysearch-noinit ]]; then
                REQUIRED_FILES=("$rgb_float_data" "$srgb_profile")
                SEED_MAX_BYTES=262144
                SEED_LIMIT=96
                SEED_DRY_RUN_TARGET=1
                SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                AFL_DISABLE_TRIM_TARGET=1
                AFL_FAST_CAL_TARGET=1
                TARGET_NOTE="ApplySearch no-init lane: fuzzes the destination profile with float data and linear interpolation while omitting -INIT."
                AFL_ARGS=("$rgb_float_data" "3" "0" "$srgb_profile" "1" "@@" "1")
            elif [[ "$target" == applysearch-hybrid-pcc || "$target" == search-hybrid-pcc ]]; then
                DICT="$REPO_ROOT/cfl/icc_applysearch_fuzzer.dict"
                HYBRID_NEEDS_SUPPORT=1
                SEED_MAX_BYTES=524288
                SEED_FILE_TYPE_REGEX='^(color profile|ColorSync color profile|data)'
                SEED_LIMIT=64
                SEED_DRY_RUN_TARGET=1
                SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                AFL_DISABLE_TRIM_TARGET=1
                AFL_FAST_CAL_TARGET=1
                AFL_MAX_LENGTH=65536
                SEED_FILES=(
                    "$HYBRID_LAB_D50"
                    "$HYBRID_LAB_D93"
                    "$HYBRID_LAB_F11"
                    "$HYBRID_LAB_ILLUMA"
                )
                SEED_DIRS=(
                    "$HYBRID_ICC_DIR"
                )
                REQUIRED_FILES=("$HYBRID_SOURCE_DIR" "$HYBRID_SRGB")
                TARGET_NOTE="Hybrid ApplySearch lane: fuzzes the first PCC weight profile in the known-good spectral search command-line shape, with fast calibration and trim disabled."
                AFL_ARGS=("-exportcfganddata" "$HYBRID_CONFIG_DIR/afl-applysearch-hybrid.json" "$HYBRID_CMYK_REF" "0" "1" "$HYBRID_SPEC_D50" "3" "$HYBRID_LAB_D50" "3" "$HYBRID_CMYK_PROFILE" "10003" "-INIT" "3" "@@" "1" "$HYBRID_LAB_D93" "1" "$HYBRID_LAB_F11" "1" "$HYBRID_LAB_ILLUMA" "1")
            elif [[ "$target" == applysearch-weight* || "$target" == search-weight* ]]; then
                local weight_value="1"
                case "$target" in
                    *zero) weight_value="0" ;;
                    *negative) weight_value="-1" ;;
                    *nan) weight_value="3.402823e+38" ;;
                esac
                SEED_MAX_BYTES=8192
                SEED_LIMIT=0
                SEED_FILES=(
                    "$REPO_ROOT/test-profiles/sRgbEncoding.icc"
                    "$REPO_ROOT/test-profiles/sRgbEncodingOverrides.icc"
                    "$REPO_ROOT/test-profiles/issue-809-vendor-flags-cwe681.icc"
                )
                SEED_DIRS=(
                    "$REPO_ROOT/cfl/corpus-icc_applysearch_weight_fuzzer"
                )
                REQUIRED_FILES=("$rgb_data" "$srgb_profile" "${SEED_FILES[@]}")
                AFL_DISABLE_TRIM_TARGET=1
                AFL_FAST_CAL_TARGET=1
                AFL_MAX_LENGTH=8192
                if [[ "$target" == *positive-fast ]]; then
                    SEED_MAX_BYTES=512
                    SEED_LIMIT=96
                    SEED_DRY_RUN_TARGET=1
                    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                    AFL_MAX_LENGTH=2048
                    REQUIRED_FILES=("$rgb_float_data" "$srgb_profile" "${SEED_FILES[@]}")
                    TARGET_NOTE="Fast weight-positive apply-search lane: tiny valid PCC seeds plus screened CFL weight corpus entries, shorter float data, AFL_FAST_CAL=1, AFL_DISABLE_TRIM=1."
                    AFL_ARGS=("$rgb_float_data" "0" "0" "$srgb_profile" "1" "$srgb_profile" "1" "-INIT" "1" "@@" "$weight_value")
                elif [[ "$target" == *nan ]]; then
                    SEED_LIMIT=96
                    SEED_DRY_RUN_TARGET=1
                    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                    TARGET_NOTE="Extreme-weight apply-search target: @@ is the fuzzed PCC profile; fixed finite max-float weight is $weight_value because iccApplySearch rejects nan/inf at argument parsing; screened positive-result seeds keep calibration tractable."
                    AFL_ARGS=("$rgb_data" "0" "0" "$srgb_profile" "1" "$srgb_profile" "1" "-INIT" "1" "@@" "$weight_value")
                else
                    if [[ "$weight_value" == "1" ]]; then
                        SEED_LIMIT=96
                        SEED_DRY_RUN_TARGET=1
                        SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                        TARGET_NOTE="Weight-focused apply-search target: @@ is the fuzzed PCC profile; fixed weight is $weight_value; screened CFL weight corpus entries keep calibration tractable."
                    else
                        SEED_DIRS=()
                        TARGET_NOTE="Weight-validation apply-search target: @@ is the fuzzed PCC profile; fixed invalid weight is $weight_value, so this lane intentionally stops at AttachPCC validation and is not a deep coverage lane."
                    fi
                    AFL_ARGS=("$rgb_data" "0" "0" "$srgb_profile" "1" "$srgb_profile" "1" "-INIT" "1" "@@" "$weight_value")
                fi
            else
                REQUIRED_FILES=("$rgb_16_data" "$srgb_profile")
                SEED_FILES=(
                    "$REPO_ROOT/test-profiles/argbCalc.icc"
                    "$REPO_ROOT/test-profiles/Lab_float-D50_2deg.icc"
                    "$REPO_ROOT/test-profiles/Lab_float-D93_2deg-MAT.icc"
                    "$REPO_ROOT/test-profiles/XYZ_float-D50_2deg.icc"
                    "$REPO_ROOT/test-profiles/XYZ_float-D65_2deg-MAT.icc"
                    "$REPO_ROOT/test-profiles/npd-CIccCombinedConnectionConditions-IccPcc_cpp-Line337.icc"
                    "$REPO_ROOT/test-profiles/xml-to-icc-to-xml-fidelity-test-001.icc"
                    "$REPO_ROOT/fuzz/graphics/icc/dbz-CIccCamConverter-HyperbolicInv-IccCAM_cpp-Line214.icc"
                    "$REPO_ROOT/fuzz/graphics/icc/dbz-CIccFormulaCurveSegment-Apply-IccMpeBasic_cpp-Line682.icc"
                    "$REPO_ROOT/fuzz/graphics/icc/dbz-CIccFormulaCurveSegment-Apply-FT6-IccMpeBasic_cpp-Line668.icc"
                )
                if [[ "$target" == applysearch-fast || "$target" == search-fast ]]; then
                    SEED_MAX_BYTES=8192
                    SEED_LIMIT=96
                    SEED_DRY_RUN_TARGET=1
                    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                    AFL_DISABLE_TRIM_TARGET=1
                    AFL_FAST_CAL_TARGET=1
                    TARGET_NOTE="Fast apply-search lane: valid ApplySearch-compatible seeds <= 8 KiB, AFL_FAST_CAL=1, AFL_DISABLE_TRIM=1."
                else
                    SEED_MAX_BYTES=262144
                    SEED_LIMIT=32
                    SEED_DRY_RUN_TARGET=1
                    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                    AFL_DISABLE_TRIM_TARGET=1
                    AFL_FAST_CAL_TARGET=1
                    TARGET_NOTE="ApplySearch ICC lane: fuzzes the destination profile with a small screened ICC sample <= 256 KiB and a fixed PCC weight profile, AFL_FAST_CAL=1, AFL_DISABLE_TRIM=1."
                fi
                AFL_ARGS=("$rgb_16_data" "5" "1" "$srgb_profile" "1" "@@" "1" "-INIT" "1" "$srgb_profile" "1")
            fi
            ;;
        applytolink|applytolink-v5|applytolink-cube)
            BINARY="$BIN_DIR/iccApplyToLink"
            DICT="$REPO_ROOT/cfl/icc_link_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_DRY_RUN_TARGET=1
            if [[ "$target" == "applytolink-cube" ]]; then
                AFL_DIR="$AFL_BASE/afl-applytolink-cube"
                TARGET_NOTE="ApplyToLink .cube lane: link_type=1, precision=4, valid input range 0.0..1.0."
                AFL_ARGS=("${tmp_prefix}.cube" "1" "2" "4" "AFL" "0.0" "1.0" "0" "0" "@@" "13")
            elif [[ "$target" == "applytolink-v5" ]]; then
                AFL_DIR="$AFL_BASE/afl-applytolink-v5"
                REQUIRED_FILES=("$srgb_profile")
                SEED_MAX_BYTES=262144
                SEED_LIMIT=96
                SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                AFL_DISABLE_TRIM_TARGET=1
                AFL_FAST_CAL_TARGET=1
                TARGET_NOTE="ApplyToLink v5 lane: extended input range and linear interpolation exercise the alternate DeviceLink writer path while fuzzing the destination profile."
                AFL_ARGS=("${tmp_prefix}.icc" "0" "9" "1" "AFL v5 DeviceLink" "-0.25" "1.25" "1" "0" "$srgb_profile" "1" "@@" "1")
            else
                REQUIRED_FILES=("$srgb_profile")
                TARGET_NOTE="ApplyToLink DeviceLink lane: 17-point v4 output, source-first tetrahedral interpolation, fuzzed source profile, and fixed sRGB destination profile."
                AFL_ARGS=("${tmp_prefix}.icc" "0" "17" "0" "AFL DeviceLink" "0.0" "1.0" "1" "1" "@@" "1" "$srgb_profile" "1")
            fi
            ;;
        dump|dump-diag|dump-read)
            BINARY="$BIN_DIR/iccDumpProfile"
            DICT="$REPO_ROOT/cfl/icc_dump_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_MAX_BYTES=1048576
            SEED_FILE_TYPE_REGEX='^(color profile|ColorSync color profile|data)'
            case "$target" in
                dump-diag)
                    TARGET_NOTE="Diagnostic dump lane: exercises --diag size/load tracing with validation enabled."
                    AFL_ARGS=("--diag" "-v" "100" "@@" "ALL")
                    ;;
                dump-read)
                    SEED_MAX_BYTES=8192
                    SEED_LIMIT=96
                    AFL_DISABLE_TRIM_TARGET=1
                    AFL_FAST_CAL_TARGET=1
                    TARGET_NOTE="Eager-read dump lane: exercises --read instead of the default lazy OpenIccProfile path."
                    AFL_ARGS=("--read" "-v" "100" "@@" "ALL")
                    ;;
                *)
                    AFL_ARGS=("-v" "100" "@@" "ALL")
                    ;;
            esac
            ;;
        fromcube)
            BINARY="$BIN_DIR/iccFromCube"
            DICT="$REPO_ROOT/cfl/icc_fromcube_fuzzer.dict"
            SEED_FILES=(
                "$REPO_ROOT/docs/iccDEV/Tools/test-data/test-identity.cube"
                "$REPO_ROOT/docs/iccDEV/Tools/test-data/test-warmfilm-5x5x5.cube"
                "$REPO_ROOT/fuzz/graphics/cube/control-clean-no-domain-ascii.cube"
                "$REPO_ROOT/fuzz/graphics/cube/ub-tagmpe-size-line1158-shared-curves.cube"
                "$REPO_ROOT/fuzz/graphics/cube/ub-curveset-line3456-distinct-curves.cube"
                "$REPO_ROOT/test-profiles/cube/path-input-range-video-flags-3x3x3.cube"
                "$REPO_ROOT/fuzz/graphics/cube/dbz-matrix-identity.cube"
            )
            SEED_DIRS=(
                "$REPO_ROOT/cfl/corpus-icc_fromcube_fuzzer"
                "$REPO_ROOT/fuzz/graphics/cube"
                "${HOME:-$REPO_ROOT}/cube-lut"
            )
            REQUIRED_FILES=("${SEED_FILES[@]}")
            if [[ -f "$REPO_ROOT/cfl/cube.cube" ]]; then
                SEED_FILES+=("$REPO_ROOT/cfl/cube.cube")
            fi
            if [[ -f "$REPO_ROOT/cfl/link.cube" ]]; then
                SEED_FILES+=("$REPO_ROOT/cfl/link.cube")
            fi
            SEED_MAX_BYTES=131072
            SEED_LIMIT=256
            SEED_DRY_RUN_TARGET=1
            SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
            AFL_DISABLE_TRIM_TARGET=1
            AFL_FAST_CAL_TARGET=1
            [[ -z "${AFL_INPUT_FORMAT:-}" ]] && AFL_INPUT_FORMAT="text"
            [[ -z "${AFL_MAX_LENGTH:-}" ]] && AFL_MAX_LENGTH=131072
            TARGET_NOTE="FromCube .cube text lane: iccFromCube @@ <output>, checked-in .cube corpora, AFL text mode, fast calibration, and trim disabled. For coverage growth after baseline cycles, build a LAF or CmpLog variant."
            AFL_ARGS=("@@" "${tmp_prefix}.icc")
            ;;
        fromjson)
            BINARY="$BIN_DIR/iccFromJson"
            DICT="$REPO_ROOT/cfl/icc_json.dict"
            SEED_DIRS=(
                "$REPO_ROOT/fuzz/graphics/json"
                "$REPO_ROOT/cfl/corpus-icc_fromjson_fuzzer"
                "$REPO_ROOT/docs/Testing/malformed-json"
                "$REPO_ROOT/afl/iccDEV/Testing"
            )
            AFL_ARGS=("@@" "${tmp_prefix}.icc")
            ;;
        fromxml|fromxml-noid|fromxml-includes)
            BINARY="$BIN_DIR/iccFromXml"
            [[ "$target" == "fromxml-noid" ]] && AFL_DIR="$AFL_BASE/afl-fromxml-noid"
            DICT="$REPO_ROOT/cfl/icc_fromxml_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/fuzz/xml/icc"
                "$REPO_ROOT/fuzz/xml/icc/minimized"
                "$REPO_ROOT/cfl/corpus-icc_fromxml_fuzzer"
            )
            SEED_MAX_BYTES=262144
            SEED_DRY_RUN_TARGET=1
            AFL_INPUT_FORMAT="text"
            AFL_MAX_LENGTH=262144
            if [[ "$target" == "fromxml-includes" ]]; then
                AFL_DIR="$AFL_BASE/afl-fromxml-includes"
                FROMXML_INCLUDES_NEEDS_SUPPORT=1
                AFL_WORK_DIR="$FROMXML_INCLUDES_SUPPORT_DIR"
                SEED_FILES=()
                SEED_DIRS=()
                while IFS='|' read -r fromxml_kind fromxml_fixture fromxml_detail; do
                    [[ -z "$fromxml_kind" || "$fromxml_kind" == \#* ]] && continue
                    if [[ "$fromxml_kind" == "profile" ]]; then
                        SEED_FILES+=("$FROMXML_INCLUDES_SOURCE_DIR/$fromxml_fixture")
                    fi
                done < "$FROMXML_INCLUDES_MANIFEST"
                SEED_MAX_BYTES=1048577
                SEED_LIMIT=0
                SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                AFL_MAX_LENGTH=1048576
                TARGET_NOTE="FromXml include lane: 10 checked sub-1-MiB primary XML seeds run from a read-only staged TXT/XML support tree; five oversized profiles remain direct-replay fixtures and calcImport.xml is support-only."
                AFL_ARGS=("@@" "${tmp_prefix}.icc")
            elif [[ "$target" == "fromxml-noid" ]]; then
                TARGET_NOTE="FromXml no-id lane: exercises SaveIccProfile with icNeverWriteID."
                AFL_ARGS=("@@" "${tmp_prefix}.icc" "-noid")
            else
                TARGET_NOTE="FromXml lane: XML text corpus with dictionary/CmpLog-compatible bounded inputs."
                AFL_ARGS=("@@" "${tmp_prefix}.icc")
            fi
            ;;
        jpegdump|jpegdump-inject)
            BINARY="$BIN_DIR/iccJpegDump"
            DICT="$REPO_ROOT/cfl/icc.dict"
            SEED_FILE_TYPE_REGEX='^JPEG image data'
            SEED_INCLUDE_REGEX='\.([Jj][Pp][Ee]?[Gg])$'
            SEED_REQUIRE_JPEG_ICC=1
            SEED_MAX_BYTES=1048576
            SEED_LIMIT=200
            SEED_FIND_MAXDEPTH=3
            AFL_MAX_LENGTH=1048576
            SEED_DIRS=(
                "$REPO_ROOT/fuzz/graphics/jpg"
            )
            if [[ "$target" == "jpegdump-inject" ]]; then
                AFL_DIR="$AFL_BASE/afl-jpegdump-inject"
                REQUIRED_FILES=("$srgb_profile")
                TARGET_NOTE="JPEG injection lane: fuzzed JPEG input with a fixed ICC profile supplied through --write-icc; only .jpg/.jpeg media with embedded ICC profiles are accepted."
                AFL_ARGS=("@@" "--write-icc" "$srgb_profile" "--output" "${tmp_prefix}.jpg")
            else
                TARGET_NOTE="JPEG dump lane: only .jpg/.jpeg media with embedded ICC profiles are accepted; raw ICC profile seeds are rejected."
                AFL_ARGS=("@@" "${tmp_prefix}.icc")
            fi
            ;;
        pawgreport|pawgreport-fast)
            BINARY="$BIN_DIR/iccPawgReport"
            [[ "$target" == "pawgreport-fast" ]] && AFL_DIR="$AFL_BASE/afl-pawgreport-fast"
            DICT="$REPO_ROOT/cfl/icc_dump_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_MAX_BYTES=1048576
            SEED_FILE_TYPE_REGEX='^(color profile|ColorSync color profile|data)'
            if [[ "$target" == "pawgreport-fast" ]]; then
                SEED_MAX_BYTES=8192
                SEED_LIMIT=96
                AFL_DISABLE_TRIM_TARGET=1
                AFL_FAST_CAL_TARGET=1
                TARGET_NOTE="Fast PAWG report lane: seeds <= 8 KiB, AFL_FAST_CAL=1, AFL_DISABLE_TRIM=1."
            fi
            AFL_ARGS=("--json" "@@")
            ;;
        pngdump|pngdump-inject)
            BINARY="$BIN_DIR/iccPngDump"
            DICT="$REPO_ROOT/cfl/png.dict"
            if [[ "$target" == "pngdump-inject" ]]; then
                AFL_DIR="$AFL_BASE/afl-pngdump-inject"
                SEED_FILE_TYPE_REGEX='^PNG image data'
                SEED_MAX_BYTES=0
                SEED_LIMIT=256
                SEED_DRY_RUN_TARGET=1
                SEED_DIRS=(
                    "$REPO_ROOT/fuzz/graphics/png"
                    "$REPO_ROOT/test-profiles"
                    "$REPO_ROOT/extended-test-profiles"
                )
                REQUIRED_FILES=("$srgb_profile")
                TARGET_NOTE="PNG injection lane: fuzzed PNG input with a fixed ICC profile supplied through --write-icc; seeds are screened for crashes and hangs without a byte-size cap."
                AFL_ARGS=("@@" "--write-icc" "$srgb_profile" "--output" "${tmp_prefix}.png")
            else
                SEED_FILE_TYPE_REGEX='^PNG image data'
                SEED_MAX_BYTES=0
                SEED_LIMIT=256
                SEED_DRY_RUN_TARGET=1
                SEED_DIRS=(
                    "$REPO_ROOT/fuzz/graphics/png"
                    "$REPO_ROOT/test-profiles"
                    "$REPO_ROOT/extended-test-profiles"
                )
                TARGET_NOTE="PNG dump lane: screened PNG corpus exercises metadata and optional ICC extraction without a byte-size cap."
                AFL_ARGS=("@@" "${tmp_prefix}.icc")
            fi
            ;;
        profilevisualize|profilevisualize-fast)
            BINARY="$BIN_DIR/iccProfileVisualize"
            [[ "$target" == "profilevisualize-fast" ]] && AFL_DIR="$AFL_BASE/afl-profilevisualize-fast"
            DICT="$REPO_ROOT/cfl/icc_dump_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_MAX_BYTES=262144
            SEED_FILE_TYPE_REGEX='^(color profile|ColorSync color profile|data)'
            SEED_DRY_RUN_TARGET=1
            if [[ "$target" == "profilevisualize-fast" ]]; then
                SEED_MAX_BYTES=8192
                SEED_LIMIT=96
                AFL_DISABLE_TRIM_TARGET=1
                AFL_FAST_CAL_TARGET=1
                TARGET_NOTE="Fast ProfileVisualize lane: seeds <= 8 KiB, AFL_FAST_CAL=1, AFL_DISABLE_TRIM=1."
            else
                SEED_LIMIT=200
                TARGET_NOTE="ProfileVisualize lane: screened ICC corpus capped at 256 KiB to avoid oversized visualization seeds before long runs."
            fi
            AFL_ARGS=("@@")
            ;;
        profileplot|profileplot-graph|profileplot-raster)
            BINARY="$BIN_DIR/iccProfilePlot"
            DICT="$REPO_ROOT/cfl/icc_dump_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_FILES=("$fixed_plot_profile")
            SEED_MAX_BYTES=262144
            SEED_LIMIT=200
            SEED_FILE_TYPE_REGEX='^(color profile|ColorSync color profile|data)'
            SEED_DRY_RUN_TARGET=1
            SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
            SEED_DRY_RUN_TIMEOUT=10
            REQUIRED_FILES=("$fixed_plot_profile")
            case "$target" in
                profileplot)
                    TARGET_NOTE="ProfilePlot list lane: enumerates every visualization descriptor and serializes the descriptor list as JSON."
                    AFL_ARGS=("@@" "list")
                    ;;
                profileplot-graph)
                    TARGET_NOTE="ProfilePlot graph lane: renders chromaticity geometry and serializes graph points, labels, and axis hints as JSON."
                    AFL_ARGS=("@@" "graph" "chroma:xy")
                    ;;
                profileplot-raster)
                    TARGET_NOTE="ProfilePlot raster lane: renders the A2B0 CLUT and writes raw samples to a per-process scratch path."
                    AFL_ARGS=("@@" "raster" "clut:A2B0" "${tmp_prefix}.raw")
                    ;;
            esac
            ;;
        roundtrip|roundtrip-mpe)
            BINARY="$BIN_DIR/iccRoundTrip"
            [[ "$target" == "roundtrip-mpe" ]] && AFL_DIR="$AFL_BASE/afl-roundtrip-mpe"
            DICT="$REPO_ROOT/cfl/icc_roundtrip_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_MAX_BYTES=8192
            SEED_LIMIT=96
            AFL_DISABLE_TRIM_TARGET=1
            AFL_FAST_CAL_TARGET=1
            if [[ "$target" == "roundtrip-mpe" ]]; then
                TARGET_NOTE="RoundTrip MPE lane: exercises optional rendering_intent/use_mpe args as '@@ 0 1'."
                AFL_ARGS=("@@" "0" "1")
            else
                TARGET_NOTE="RoundTrip lane: capped small seeds keep full load/save calibration tractable."
                AFL_ARGS=("@@")
            fi
            ;;
        specseptotiff|spec|specseptotiff-compress|specseptotiff-desc|specseptotiff-harvest|specseptotiff-sep|specseptotiff-short|specseptotiff-tiff)
            BINARY="$BIN_DIR/iccSpecSepToTiff"
            if [[ "$target" == "spec" ]]; then
                AFL_DIR="$AFL_BASE/afl-spec"
            elif [[ "$target" == specseptotiff-* ]]; then
                AFL_DIR="$AFL_BASE/afl-$target"
            else
                AFL_DIR="$AFL_BASE/afl-specseptotiff"
            fi
            DICT="$REPO_ROOT/cfl/icc_specsep_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_MAX_BYTES=1048576
            SEED_FILE_TYPE_REGEX='^(color profile|ColorSync color profile|data)'
            SEED_MAX_BYTES=8192
            SEED_LIMIT=32
            AFL_DISABLE_TRIM_TARGET=1
            AFL_FAST_CAL_TARGET=1
            [[ -z "${AFL_MAX_LENGTH:-}" ]] && AFL_MAX_LENGTH=8192
            SPECSEP_SOURCE_PREFIX="$REPO_ROOT/test-profiles/spectral/spec_00"
            SPECSEP_COPY_START=1
            SPECSEP_COPY_END=9
            REQUIRED_FILES=(
                "$REPO_ROOT/test-profiles/spectral/spec_001.tif"
                "$REPO_ROOT/test-profiles/spectral/spec_002.tif"
                "$REPO_ROOT/test-profiles/spectral/spec_003.tif"
                "$REPO_ROOT/test-profiles/spectral/spec_004.tif"
                "$REPO_ROOT/test-profiles/spectral/spec_005.tif"
                "$REPO_ROOT/test-profiles/spectral/spec_006.tif"
                "$REPO_ROOT/test-profiles/spectral/spec_007.tif"
                "$REPO_ROOT/test-profiles/spectral/spec_008.tif"
                "$REPO_ROOT/test-profiles/spectral/spec_009.tif"
            )
            case "$target" in
                specseptotiff-compress)
                    SEED_MAX_BYTES=65536
                    SEED_LIMIT=64
                    [[ -z "${AFL_MAX_LENGTH:-}" || "${AFL_MAX_LENGTH:-}" == "8192" ]] && AFL_MAX_LENGTH=65536
                    TARGET_NOTE="SpecSep compressed-output lane: fuzzes a bounded optional ICC profile with compress=1, sep=0, ascending range; 64 KiB cap keeps richer seeds without reopening the oversized corpus."
                    AFL_ARGS=("${tmp_prefix}.tif" "1" "0" "${tmp_prefix}-spec_00" "1" "9" "1" "@@")
                    ;;
                specseptotiff-desc)
                    TARGET_NOTE="SpecSep descending lane: fuzzes a small optional ICC profile with start=9, end=1, increment=-1 to cover reverse channel iteration."
                    AFL_ARGS=("${tmp_prefix}.tif" "0" "0" "${tmp_prefix}-spec_00" "9" "1" "-1" "@@")
                    ;;
                specseptotiff-harvest)
                    TARGET_NOTE="SpecSep gray300 lane: fuzzes optional ICC profile parsing while fixed gray300 spectral TIFF inputs exercise larger 8-bit image rows."
                    SPECSEP_SOURCE_PREFIX="$REPO_ROOT/fuzz/graphics/spectral/specsep-harvest-gray300/spec_"
                    SPECSEP_COPY_START=1
                    SPECSEP_COPY_END=8
                    REQUIRED_FILES=(
                        "$REPO_ROOT/fuzz/graphics/spectral/specsep-harvest-gray300/spec_1"
                        "$REPO_ROOT/fuzz/graphics/spectral/specsep-harvest-gray300/spec_2"
                        "$REPO_ROOT/fuzz/graphics/spectral/specsep-harvest-gray300/spec_3"
                        "$REPO_ROOT/fuzz/graphics/spectral/specsep-harvest-gray300/spec_4"
                        "$REPO_ROOT/fuzz/graphics/spectral/specsep-harvest-gray300/spec_5"
                        "$REPO_ROOT/fuzz/graphics/spectral/specsep-harvest-gray300/spec_6"
                        "$REPO_ROOT/fuzz/graphics/spectral/specsep-harvest-gray300/spec_7"
                        "$REPO_ROOT/fuzz/graphics/spectral/specsep-harvest-gray300/spec_8"
                    )
                    AFL_ARGS=("${tmp_prefix}.tif" "0" "0" "${tmp_prefix}-harvest-spec_" "1" "8" "1" "@@")
                    ;;
                specseptotiff-short)
                    TARGET_NOTE="SpecSep short-range lane: fuzzes a small optional ICC profile with start=1, end=3, increment=1, AFL_FAST_CAL=1, AFL_DISABLE_TRIM=1."
                    AFL_ARGS=("${tmp_prefix}.tif" "0" "0" "${tmp_prefix}-spec_00" "1" "3" "1" "@@")
                    ;;
                specseptotiff-sep)
                    TARGET_NOTE="SpecSep separated-plane lane: fuzzes a small optional ICC profile with compress=0, sep=1, ascending range, AFL_FAST_CAL=1, AFL_DISABLE_TRIM=1."
                    AFL_ARGS=("${tmp_prefix}.tif" "0" "1" "${tmp_prefix}-spec_00" "1" "9" "1" "@@")
                    ;;
                specseptotiff-tiff)
                    BINARY="$REPO_ROOT/afl/specsep-tiff-wrapper.sh"
                    DICT="$REPO_ROOT/cfl/icc_tiffdump_fuzzer.dict"
                    TARGET_NOTE="SpecSep TIFF-input lane: wrapper copies @@ to a one-channel prefix so AFL mutates CTiffImg/open/readline paths instead of the optional ICC profile."
                    AFL_NO_FORKSRV_TARGET=1
                    AFL_SKIP_BIN_CHECK_TARGET=1
                    SEED_FILE_TYPE_REGEX='^(TIFF image data|Big TIFF image data)'
                    SEED_DIRS=(
                        "$REPO_ROOT/fuzz/graphics/spectral/specsep-ci-small"
                        "$REPO_ROOT/fuzz/graphics/spectral/specsep-qa-2x1"
                        "$REPO_ROOT/fuzz/graphics/spectral/specsep-harvest-gray300"
                        "$REPO_ROOT/fuzz/graphics/spectral/valid"
                        "$REPO_ROOT/fuzz/graphics/spectral/malformed"
                        "$REPO_ROOT/fuzz/graphics/tif"
                        "$REPO_ROOT/test-profiles/spectral"
                        "$REPO_ROOT/test-profiles/tiff-codecs"
                    )
                    SEED_MAX_BYTES=262144
                    SEED_LIMIT=128
                    SEED_DRY_RUN_TARGET=1
                    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                    AFL_DISABLE_TRIM_TARGET=1
                    REQUIRED_FILES=("$BINARY" "$BIN_DIR/iccSpecSepToTiff")
                    AFL_MAX_LENGTH=262144
                    AFL_ARGS=("@@")
                    ;;
                *)
                    TARGET_NOTE="SpecSep default lane: fuzzes a small optional ICC profile with fixed spectral TIFF inputs, AFL_FAST_CAL=1, AFL_DISABLE_TRIM=1."
                    AFL_ARGS=("${tmp_prefix}.tif" "0" "0" "${tmp_prefix}-spec_00" "1" "9" "1" "@@")
                    ;;
            esac
            ;;
        tiffdump|tiff|tiffdump-extract)
            BINARY="$BIN_DIR/iccTiffDump"
            if [[ "$target" == "tiffdump-extract" ]]; then
                AFL_DIR="$AFL_BASE/afl-tiffdump-extract"
            else
                AFL_DIR="$AFL_BASE/afl-tiffdump"
            fi
            DICT="$REPO_ROOT/cfl/icc_tiffdump_fuzzer.dict"
            SEED_FILE_TYPE_REGEX='^(TIFF image data|Big TIFF image data)'
            SEED_DIRS=(
                "$AFL_BASE/afl-tiffdump/input"
                "$REPO_ROOT/fuzz/graphics/tif"
                "$REPO_ROOT/mangled-images"
                "$REPO_ROOT/test-profiles/tiff-codecs"
                "$REPO_ROOT/test-profiles"
            )
            if [[ "$target" == "tiffdump-extract" ]]; then
                TARGET_NOTE="TIFF ICC extraction lane: supplies argv[2] so embedded profiles are saved through SaveIccProfile."
                AFL_ARGS=("@@" "${tmp_prefix}.icc")
            else
                TARGET_NOTE="TIFF dump lane: seed corpus is filtered by file(1) to TIFF/BigTIFF inputs."
                AFL_ARGS=("@@")
            fi
            ;;
        tojson)
            BINARY="$BIN_DIR/iccToJson"
            DICT="$REPO_ROOT/cfl/icc_core.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            AFL_ARGS=("@@" "${tmp_prefix}.json")
            ;;
        toxml|toxml-fast)
            BINARY="$BIN_DIR/iccToXml"
            [[ "$target" == "toxml-fast" ]] && AFL_DIR="$AFL_BASE/afl-toxml-fast"
            DICT="$REPO_ROOT/cfl/icc_toxml_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_MAX_BYTES=8192
            SEED_LIMIT=96
            AFL_DISABLE_TRIM_TARGET=1
            AFL_FAST_CAL_TARGET=1
            if [[ "$target" == "toxml-fast" ]]; then
                TARGET_NOTE="Fast ToXml lane: seeds <= 8 KiB, AFL_FAST_CAL=1, AFL_DISABLE_TRIM=1."
            else
                TARGET_NOTE="ToXml lane: capped small seeds keep XML conversion calibration tractable."
            fi
            AFL_ARGS=("@@" "${tmp_prefix}.xml")
            ;;
        v5dspobs)
            BINARY="$BIN_DIR/iccV5DspObsToV4Dsp"
            DICT="$REPO_ROOT/cfl/icc_v5dspobs_fuzzer.dict"
            SEED_FILES=(
                "$REPO_ROOT/test-profiles/LCDDisplay.icc"
                "$REPO_ROOT/test-profiles/Rec2020rgbSpectral.icc"
                "$REPO_ROOT/test-profiles/sRGBDisplaySpectral.icc"
                "$REPO_ROOT/test-profiles/P3DisplaySpectral.icc"
                "$REPO_ROOT/test-profiles/OLEDDisplaySpectral.icc"
                "$REPO_ROOT/test-profiles/MicroLEDSpectral.icc"
                "$REPO_ROOT/test-profiles/WideGamutSpectral.icc"
                "$REPO_ROOT/test-profiles/RGBWProjectorSpectral.icc"
            )
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            REQUIRED_FILES=("$fixed_observer" "${SEED_FILES[@]}")
            SEED_MAX_BYTES=524288
            SEED_FILE_TYPE_REGEX='^(color profile|ColorSync color profile|data)'
            TARGET_NOTE="v5 display/observer conversion lane: iccV5DspObsToV4Dsp @@ $fixed_observer <output>; curated v5 display seeds are always copied."
            AFL_ARGS=("@@" "$fixed_observer" "${tmp_prefix}.icc")
            ;;
        *)
            return 1
            ;;
    esac
}

afl_copy_if_missing() {
    local src="$1"
    local dst="$2"

    if [[ ! -e "$dst" ]]; then
        mkdir -p "$(dirname "$dst")"
        cp -- "$src" "$dst"
    fi
}

afl_fromxml_if_missing() {
    local src="$1"
    local dst="$2"

    if [[ ! -e "$dst" ]]; then
        mkdir -p "$(dirname "$dst")"
        "$BIN_DIR/iccFromXml" "$src" "$dst" >/dev/null
    fi
}

afl_prepare_hybrid_support_files() {
    if [[ "${HYBRID_NEEDS_SUPPORT:-0}" -ne 1 ]]; then
        return 0
    fi

    if [[ ! -d "$HYBRID_SOURCE_DIR" ]]; then
        echo "ERROR: Hybrid source directory not found: $HYBRID_SOURCE_DIR" >&2
        return 1
    fi
    if [[ ! -x "$BIN_DIR/iccFromXml" || ! -x "$BIN_DIR/iccApplyProfiles" || ! -x "$BIN_DIR/iccApplyNamedCmm" ]]; then
        echo "ERROR: Hybrid AFL lanes require iccFromXml, iccApplyProfiles, and iccApplyNamedCmm in $BIN_DIR" >&2
        return 1
    fi

    mkdir -p "$HYBRID_CONFIG_DIR" "$HYBRID_DATA_DIR" "$HYBRID_ICC_DIR" "$HYBRID_RESULTS_DIR"
    if [[ ! -e "$HYBRID_SENTINEL_ICC" ]]; then
        mkdir -p "$(dirname "$HYBRID_SENTINEL_ICC")"
        printf 'not-an-icc\n' > "$HYBRID_SENTINEL_ICC"
    fi
    if [[ ! -e "$HYBRID_SENTINEL_TIFF" ]]; then
        mkdir -p "$(dirname "$HYBRID_SENTINEL_TIFF")"
        printf 'not-a-tiff\n' > "$HYBRID_SENTINEL_TIFF"
    fi
    afl_copy_if_missing "$HYBRID_SOURCE_DIR/Data/cmykGrays.txt" "$HYBRID_CMYK_DATA"
    afl_copy_if_missing "$HYBRID_SOURCE_DIR/Data/smCows380_5_780.tif" "$HYBRID_DATA_DIR/smCows380_5_780.tif"

    afl_fromxml_if_missing "$HYBRID_SOURCE_DIR/CMYK_Hybrid_Profile.xml" "$HYBRID_CMYK_PROFILE"
    afl_fromxml_if_missing "$HYBRID_SOURCE_DIR/MultSpectralRGB.xml" "$HYBRID_ICC_DIR/MultSpectralRGB.icc"
    afl_fromxml_if_missing "$HYBRID_SOURCE_DIR/Data/Lab_float-D50_2deg.xml" "$HYBRID_LAB_D50"
    afl_fromxml_if_missing "$HYBRID_SOURCE_DIR/Data/Lab_float-D93_2deg-MAT.xml" "$HYBRID_LAB_D93"
    afl_fromxml_if_missing "$HYBRID_SOURCE_DIR/Data/Lab_float-F11_2deg-MAT.xml" "$HYBRID_LAB_F11"
    afl_fromxml_if_missing "$HYBRID_SOURCE_DIR/Data/Lab_float-IllumA_2deg-MAT.xml" "$HYBRID_LAB_ILLUMA"
    afl_fromxml_if_missing "$HYBRID_SOURCE_DIR/Data/Spec380_10_730-D50_2deg.xml" "$HYBRID_SPEC_D50"
    afl_fromxml_if_missing "$HYBRID_SOURCE_DIR/Data/Spec400_10_700-F11_2deg-Abs.xml" "$HYBRID_SPEC_F11"
    afl_fromxml_if_missing "$HYBRID_SOURCE_DIR/Data/Spec400_10_700-IllumA_2deg-Abs.xml" "$HYBRID_SPEC_ILLUMA"

    if [[ ! -e "$HYBRID_MS_TIFF" ]]; then
        "$BIN_DIR/iccApplyProfiles" \
            -exportcfg "$HYBRID_CONFIG_DIR/makeMS_smCows.json" \
            "$HYBRID_DATA_DIR/smCows380_5_780.tif" "$HYBRID_MS_TIFF" \
            2 1 0 1 1 -embedded 3 "$HYBRID_ICC_DIR/MultSpectralRGB.icc" 10003 >/dev/null
    fi
    if [[ ! -e "$HYBRID_CMYK_REF" ]]; then
        "$BIN_DIR/iccApplyNamedCmm" \
            -exportcfganddata "$HYBRID_CONFIG_DIR/cmykGraysRef.json" \
            "$HYBRID_CMYK_DATA" 3 1 "$HYBRID_CMYK_PROFILE" 10003 \
            "$HYBRID_SPEC_D50" 3 > "$HYBRID_CMYK_REF"
    fi
}

afl_fromxml_live_references() {
    local xml_file="$1"

    awk '
        BEGIN { in_comment = 0 }
        {
            line = $0
            output = ""
            while (length(line)) {
                if (in_comment) {
                    end = index(line, "-->")
                    if (!end) {
                        line = ""
                        break
                    }
                    line = substr(line, end + 3)
                    in_comment = 0
                    continue
                }
                start = index(line, "<!--")
                if (!start) {
                    output = output line
                    line = ""
                    break
                }
                output = output substr(line, 1, start - 1)
                line = substr(line, start + 4)
                in_comment = 1
            }
            print output
        }
    ' "$xml_file" | LC_ALL=C grep -o 'Filename="[^"]*"' | sed 's/^Filename="//; s/"$//' || true
}

afl_stage_fromxml_include() {
    local source_dir="$1"
    local relative_path="$2"
    local source_file="$source_dir/$relative_path"
    local destination="$FROMXML_INCLUDES_SUPPORT_DIR/$relative_path"
    local support_real
    local destination_real
    local reference

    if [[ "$relative_path" == /* || "$relative_path" == ".." || "$relative_path" == ../* || "$relative_path" == */../* || "$relative_path" == */.. ]]; then
        echo "ERROR: Unsafe FromXml include path in manifest or fixture: $relative_path" >&2
        return 1
    fi
    support_real="$(realpath -m "$FROMXML_INCLUDES_SUPPORT_DIR")"
    destination_real="$(realpath -m "$destination")"
    if [[ "$destination_real" != "$support_real"/* ]]; then
        echo "ERROR: FromXml include escapes the support tree: $relative_path" >&2
        return 1
    fi
    if [[ ! -f "$source_file" ]]; then
        echo "ERROR: Required FromXml include not found: $source_file" >&2
        return 1
    fi
    if [[ -L "$destination" ]]; then
        echo "ERROR: Refusing symlinked FromXml support destination: $destination" >&2
        return 1
    fi

    if [[ -n "${FROMXML_STAGED_SOURCES[$relative_path]:-}" ]]; then
        if ! cmp -s "$source_file" "$destination"; then
            echo "ERROR: Conflicting FromXml include path: $relative_path" >&2
            echo "       ${FROMXML_STAGED_SOURCES[$relative_path]}" >&2
            echo "       $source_file" >&2
            return 1
        fi
        return 0
    fi

    if [[ -f "$destination" ]] && cmp -s "$source_file" "$destination"; then
        FROMXML_STAGED_SOURCES[$relative_path]="$source_file"
        if [[ "$relative_path" == *.xml ]]; then
            while IFS= read -r reference; do
                afl_stage_fromxml_include "$source_dir" "$reference"
            done < <(afl_fromxml_live_references "$source_file")
        fi
        return 0
    fi

    mkdir -p "$(dirname "$destination")"
    if [[ -e "$destination" ]]; then
        chmod u+w "$destination"
    fi
    cp -- "$source_file" "$destination"
    chmod a-w "$destination"
    FROMXML_STAGED_SOURCES[$relative_path]="$source_file"

    if [[ "$relative_path" == *.xml ]]; then
        while IFS= read -r reference; do
            afl_stage_fromxml_include "$source_dir" "$reference"
        done < <(afl_fromxml_live_references "$source_file")
    fi
}

afl_prepare_fromxml_include_support_files() {
    local kind
    local fixture
    local detail
    local source_dir
    local reference

    if [[ "${FROMXML_INCLUDES_NEEDS_SUPPORT:-0}" -ne 1 ]]; then
        return 0
    fi
    if [[ ! -f "$FROMXML_INCLUDES_MANIFEST" ]]; then
        echo "ERROR: FromXml include manifest not found: $FROMXML_INCLUDES_MANIFEST" >&2
        return 1
    fi
    if [[ ! -d "$FROMXML_INCLUDES_SOURCE_DIR" ]]; then
        echo "ERROR: FromXml include fixture root not found: $FROMXML_INCLUDES_SOURCE_DIR" >&2
        return 1
    fi

    mkdir -p "$FROMXML_INCLUDES_SUPPORT_DIR"
    declare -gA FROMXML_STAGED_SOURCES=()
    while IFS='|' read -r kind fixture detail; do
        [[ -z "$kind" || "$kind" == \#* ]] && continue
        case "$kind" in
            profile|profile-oversize|support-fragment) ;;
            *) echo "ERROR: Unknown FromXml manifest kind: $kind" >&2; return 1 ;;
        esac
        if [[ ! -f "$FROMXML_INCLUDES_SOURCE_DIR/$fixture" ]]; then
            echo "ERROR: FromXml manifest fixture not found: $fixture" >&2
            return 1
        fi
        source_dir="$(dirname "$FROMXML_INCLUDES_SOURCE_DIR/$fixture")"
        while IFS= read -r reference; do
            afl_stage_fromxml_include "$source_dir" "$reference"
        done < <(afl_fromxml_live_references "$FROMXML_INCLUDES_SOURCE_DIR/$fixture")
    done < "$FROMXML_INCLUDES_MANIFEST"
}

afl_prepare_isolated_work_files() {
    local source_file
    local relative_path
    local destination
    local repo_real
    local source_real

    if [[ "${ISOLATED_WORK_NEEDS_SUPPORT:-0}" -ne 1 ]]; then
        return 0
    fi

    repo_real="$(realpath -m "$REPO_ROOT")"
    mkdir -p "$AFL_WORK_DIR"
    for source_file in "${ISOLATED_WORK_FILES[@]}"; do
        if [[ ! -f "$source_file" ]]; then
            echo "ERROR: Required isolated-work fixture not found: $source_file" >&2
            return 1
        fi
        source_real="$(realpath -m "$source_file")"
        if [[ "$source_real" != "$repo_real"/* ]]; then
            echo "ERROR: Isolated-work fixture is outside the repository: $source_file" >&2
            return 1
        fi
        relative_path="${source_real#"$repo_real"/}"
        destination="$AFL_WORK_DIR/$relative_path"
        mkdir -p "$(dirname "$destination")"
        if [[ -L "$destination" ]]; then
            echo "ERROR: Refusing symlinked isolated-work destination: $destination" >&2
            return 1
        fi
        if [[ -e "$destination" ]]; then
            chmod u+w "$destination"
        fi
        cp -- "$source_real" "$destination"
        chmod a-w "$destination"
    done

    source_file="$REPO_ROOT/fuzz/graphics/icc/sbo-CIccCalculatorFunc-Apply-IccMpeCalc_cpp-Line3873.icc"
    if [[ -f "$source_file" ]]; then
        destination="$AFL_WORK_DIR/$(basename "$source_file")"
        if [[ -L "$destination" ]]; then
            echo "ERROR: Refusing symlinked isolated-work destination: $destination" >&2
            return 1
        fi
        if [[ -e "$destination" ]]; then
            chmod u+w "$destination"
        fi
        cp -- "$source_file" "$destination"
        chmod a-w "$destination"
    fi
}

afl_prepare_target_support_files() {
    local target="$1"

    afl_prepare_hybrid_support_files || return 1
    afl_prepare_fromxml_include_support_files || return 1
    afl_prepare_isolated_work_files || return 1

    case "$target" in
        specseptotiff|spec|specseptotiff-compress|specseptotiff-desc|specseptotiff-harvest|specseptotiff-sep|specseptotiff-short)
            local spectral_prefix="${AFL_ARGS[3]}"
            local n src dst

            mkdir -p "$(dirname "$spectral_prefix")"
            for ((n=SPECSEP_COPY_START; n<=SPECSEP_COPY_END; n++)); do
                src="${SPECSEP_SOURCE_PREFIX}${n}"
                if [[ ! -e "$src" && "$n" -lt 10 ]]; then
                    src="${SPECSEP_SOURCE_PREFIX}${n}.tif"
                fi
                dst="${spectral_prefix}${n}"
                if [[ ! -e "$src" ]]; then
                    echo "ERROR: Required spectral TIFF not found: $src" >&2
                    return 1
                fi
                if [[ ! -e "$dst" ]]; then
                    cp -- "$src" "$dst"
                fi
            done
            ;;
    esac
}
