#!/bin/bash
# Shared AFL++ target definitions for iccDEV tool binaries.

AFL_TARGETS=(
    applynamedcmm
    applynamedcmm-cfg
    applynamedcmm-hybrid-pcc
    applyprofiles
    applyprofiles-fast
    applyprofiles-deep
    applyprofiles-cfg
    applyprofiles-hybrid-embedded
    applyprofiles-hybrid-pcc
    applyprofiles-row
    applysearch
    applysearch-cfg
    applysearch-fast
    applysearch-hybrid-pcc
    applysearch-weight-positive
    applysearch-weight-positive-fast
    applysearch-weight-zero
    applysearch-weight-negative
    applysearch-weight-nan
    applytolink
    applytolink-cube
    dump
    dump-diag
    dump-read
    fromcube
    fromjson
    fromxml
    fromxml-noid
    jpegdump
    jpegdump-inject
    pawgreport
    pawgreport-fast
    pngdump
    pngdump-inject
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
    echo "  applynamedcmm-cfg - iccApplyNamedCmm (-cfg JSON config lane)"
    echo "  applynamedcmm-hybrid-pcc - iccApplyNamedCmm hybrid v5/PCC lane"
    echo "  applyprofiles    - iccApplyProfiles (fixed TIFF, fuzz ICC profile)"
    echo "  applyprofiles-fast - iccApplyProfiles (small ICC profile lane)"
    echo "  applyprofiles-deep - iccApplyProfiles (large ICC profile lane)"
    echo "  applyprofiles-cfg - iccApplyProfiles (-cfg JSON config lane)"
    echo "  applyprofiles-hybrid-embedded - iccApplyProfiles hybrid embedded/PCC argv lane"
    echo "  applyprofiles-hybrid-pcc - iccApplyProfiles hybrid -exportcfg PCC lane"
    echo "  applyprofiles-row - iccApplyProfiles (-threads row-apply lane)"
    echo "  applysearch      - iccApplySearch (fixed data, fuzz ICC profiles)"
    echo "  applysearch-cfg  - iccApplySearch (-cfg JSON config lane)"
    echo "  applysearch-fast - iccApplySearch (small/no-trim search lane)"
    echo "  applysearch-hybrid-pcc - iccApplySearch hybrid v5/PCC lane"
    echo "  applysearch-weight-positive - iccApplySearch (fuzz PCC profile, fixed weight 1)"
    echo "  applysearch-weight-positive-fast - iccApplySearch (small/no-trim weight 1 lane)"
    echo "  applysearch-weight-zero - iccApplySearch (fuzz PCC profile, fixed weight 0)"
    echo "  applysearch-weight-negative - iccApplySearch (fuzz PCC profile, fixed weight -1)"
    echo "  applysearch-weight-nan - iccApplySearch (fuzz PCC profile, fixed finite max-float weight)"
    echo "  applytolink      - iccApplyToLink (DeviceLink/.cube generation)"
    echo "  applytolink-cube - iccApplyToLink (.cube text generation)"
    echo "  dump             - iccDumpProfile (ICC binary -> text dump)"
    echo "  dump-diag        - iccDumpProfile (--diag size/load diagnostics)"
    echo "  dump-read        - iccDumpProfile (--read eager profile load)"
    echo "  fromcube         - iccFromCube (.cube LUT text -> ICC)"
    echo "  fromjson         - iccFromJson (ICC JSON -> binary)"
    echo "  fromxml          - iccFromXml (ICC XML -> binary)"
    echo "  fromxml-noid     - iccFromXml (-noid save policy)"
    echo "  jpegdump         - iccJpegDump (JPEG -> ICC extraction)"
    echo "  jpegdump-inject  - iccJpegDump (--write-icc injection lane)"
    echo "  pawgreport       - iccPawgReport (PAWG profile assessment)"
    echo "  pawgreport-fast  - iccPawgReport (small/no-trim profile assessment lane)"
    echo "  pngdump          - iccPngDump (PNG -> ICC extraction)"
    echo "  pngdump-inject   - iccPngDump (--write-icc injection lane)"
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
    local hybrid_source_dir
    local hybrid_support_dir

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
    hybrid_source_dir="$(afl_first_existing \
        "$REPO_ROOT/iccDEV/Testing/hybrid" \
        "$REPO_ROOT/afl/iccDEV/Testing/hybrid")"
    hybrid_support_dir="$AFL_BASE/support/hybrid"

    BINARY=""
    AFL_DIR="$AFL_BASE/afl-$target"
    AFL_COVERAGE_CACHE_KEY=""
    DICT=""
    TARGET_NOTE=""
    SEED_MAX_BYTES=0
    SEED_LIMIT=200
    AFL_DISABLE_TRIM_TARGET=0
    AFL_FAST_CAL_TARGET=0
    AFL_NO_FORKSRV_TARGET=0
    AFL_SKIP_BIN_CHECK_TARGET=0
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
    HYBRID_SOURCE_DIR="$hybrid_source_dir"
    HYBRID_SUPPORT_DIR="$hybrid_support_dir"
    HYBRID_CONFIG_DIR="$hybrid_support_dir/config"
    HYBRID_DATA_DIR="$hybrid_support_dir/Data"
    HYBRID_ICC_DIR="$hybrid_support_dir/ICC"
    HYBRID_RESULTS_DIR="$hybrid_support_dir/Results"
    HYBRID_MS_TIFF="$hybrid_support_dir/Results/MS_smCows.tif"
    HYBRID_MS_TIFF_SEED="$hybrid_support_dir/Results/MS_smCows_64x64.tif"
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
        applynamedcmm|applynamedcmm-cfg|namedcmm-cfg)
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
            else
                TARGET_NOTE="ApplyNamedCmm ICC lane: 16-bit data output with tetrahedral interpolation exercises a different apply path than the former 8-bit linear shape."
                AFL_ARGS=("$rgb_16_data" "5" "1" "@@" "1")
            fi
            ;;
        applynamedcmm-hybrid-pcc|namedcmm-hybrid-pcc)
            BINARY="$BIN_DIR/iccApplyNamedCmm"
            AFL_DIR="$AFL_BASE/afl-applynamedcmm-hybrid-pcc"
            DICT="$REPO_ROOT/cfl/icc_applynamedcmm_fuzzer.dict"
            HYBRID_NEEDS_SUPPORT=1
            SEED_MAX_BYTES=4194304
            SEED_LIMIT=300
            SEED_DRY_RUN_TARGET=1
            SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
            [[ -z "${AFL_MAX_LENGTH:-}" ]] && AFL_MAX_LENGTH=4194304
            SEED_FILES=("$HYBRID_CMYK_PROFILE")
            SEED_EXCLUDE_REGEX='^CMYK_Hybrid_Profile\.icc$'
            SEED_DIRS=(
                "$HYBRID_ICC_DIR"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/extended-test-profiles"
            )
            REQUIRED_FILES=("$HYBRID_SOURCE_DIR" "$HYBRID_SRGB")
            TARGET_NOTE="Hybrid NamedCmm lane: fuzzes the first v5 profile in the upstream QA environment/PCC shape and retains only seeds that build and apply the full transform."
            AFL_ARGS=("-exportcfganddata" "$HYBRID_CONFIG_DIR/afl-namedcmm-hybrid.json" "$HYBRID_CMYK_DATA" "5" "1" "-ENV:bkgX" "0.0985" "-ENV:bkgY" "0.159" "-ENV:bkgZ" "0.122" "@@" "10003" "-PCC" "$HYBRID_SPEC_ILLUMA" "$HYBRID_SPEC_D50" "3")
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
                    SEED_LIMIT=300
                    SEED_DRY_RUN_TARGET=1
                    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                    SEED_FILES=("$HYBRID_MS_TIFF_SEED")
                    SEED_FILE_TYPE_REGEX='^(TIFF image data|Big TIFF image data)'
                    SEED_DIRS=()
                    REQUIRED_FILES=("$HYBRID_SOURCE_DIR" "$HYBRID_SRGB")
                    TARGET_NOTE="Hybrid ApplyProfiles embedded/PCC lane: fuzzes the generated multispectral TIFF through float, compressed, planar, embedded, tetrahedral, and BPC output paths."
                    AFL_ARGS=("@@" "${tmp_prefix}.tif" "3" "1" "1" "1" "1" "-embedded" "10003" "-PCC" "$HYBRID_SPEC_F11" "$HYBRID_SRGB" "41")
                    ;;
                applyprofiles-hybrid-pcc|profiles-hybrid-pcc)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles-hybrid-pcc"
                    HYBRID_NEEDS_SUPPORT=1
                    SEED_MAX_BYTES=524288
                    SEED_LIMIT=300
                    SEED_DRY_RUN_TARGET=1
                    SEED_DRY_RUN_REQUIRE_ZERO_TARGET=1
                    SEED_FILES=(
                        "$HYBRID_LAB_D50"
                        "$HYBRID_SPEC_F11"
                        "$HYBRID_SPEC_ILLUMA"
                    )
                    SEED_DIRS=(
                        "$HYBRID_ICC_DIR"
                        "$REPO_ROOT/fuzz/graphics/icc"
                        "$REPO_ROOT/test-profiles"
                        "$REPO_ROOT/extended-test-profiles"
                    )
                    REQUIRED_FILES=("$HYBRID_SOURCE_DIR" "$HYBRID_SRGB")
                    TARGET_NOTE="Hybrid ApplyProfiles PCC lane: places the fuzzed profile after -PCC and screens for a complete embedded-to-sRGB transform."
                    AFL_ARGS=("-exportcfg" "$HYBRID_CONFIG_DIR/afl-applyprofiles-hybrid.json" "$HYBRID_MS_TIFF" "${tmp_prefix}.tif" "3" "1" "1" "1" "1" "-embedded" "10003" "-PCC" "@@" "$HYBRID_SRGB" "41")
                    ;;
                applyprofiles-row|profiles-row)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles-row"
                    SEED_MAX_BYTES=524288
                    SEED_LIMIT=300
                    TARGET_NOTE="Row ApplyProfiles lane: uses -threads 0 to exercise row/batched CMM Apply."
                    SEED_DRY_RUN_TARGET=1
                    AFL_ARGS=("-threads" "0" "$fixed_tiff" "${tmp_prefix}.tif" "3" "1" "1" "1" "1" "@@" "40")
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
        applysearch|search|applysearch-cfg|search-cfg|applysearch-fast|search-fast|applysearch-hybrid-pcc|search-hybrid-pcc|applysearch-weight|search-weight|applysearch-weight-positive|search-weight-positive|applysearch-weight-positive-fast|search-weight-positive-fast|applysearch-weight-zero|search-weight-zero|applysearch-weight-negative|search-weight-negative|applysearch-weight-nan|search-weight-nan)
            BINARY="$BIN_DIR/iccApplySearch"
            if [[ "$target" == "search" ]]; then
                AFL_DIR="$AFL_BASE/afl-search"
            elif [[ "$target" == applysearch-cfg || "$target" == search-cfg ]]; then
                AFL_DIR="$AFL_BASE/afl-applysearch-cfg"
            elif [[ "$target" == applysearch-fast || "$target" == search-fast ]]; then
                AFL_DIR="$AFL_BASE/afl-applysearch-fast"
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
        applytolink|applytolink-cube)
            BINARY="$BIN_DIR/iccApplyToLink"
            DICT="$REPO_ROOT/cfl/icc_link_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            SEED_DRY_RUN_TARGET=1
            if [[ "$target" == "applytolink-cube" ]]; then
                TARGET_NOTE="ApplyToLink .cube lane: link_type=1, precision=4, valid input range 0.0..1.0."
                AFL_ARGS=("${tmp_prefix}.cube" "1" "2" "4" "AFL" "0.0" "1.0" "0" "0" "@@" "13")
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
                "$REPO_ROOT/cfl/icc_fromcube_fuzzer_seed_corpus"
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
        fromxml|fromxml-noid)
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
            if [[ "$target" == "fromxml-noid" ]]; then
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
                    BINARY="$AFL_BASE/specsep-tiff-wrapper.sh"
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
    if [[ ! -e "$HYBRID_MS_TIFF_SEED" ]]; then
        if command -v tiffcrop >/dev/null 2>&1; then
            tiffcrop -U px -z 0,0,63,63 "$HYBRID_MS_TIFF" "$HYBRID_MS_TIFF_SEED" >/dev/null 2>&1
        else
            cp -- "$HYBRID_MS_TIFF" "$HYBRID_MS_TIFF_SEED"
        fi
    fi
    if [[ ! -e "$HYBRID_CMYK_REF" ]]; then
        "$BIN_DIR/iccApplyNamedCmm" \
            -exportcfganddata "$HYBRID_CONFIG_DIR/cmykGraysRef.json" \
            "$HYBRID_CMYK_DATA" 3 1 "$HYBRID_CMYK_PROFILE" 10003 \
            "$HYBRID_SPEC_D50" 3 > "$HYBRID_CMYK_REF"
    fi
}

afl_prepare_target_support_files() {
    local target="$1"

    afl_prepare_hybrid_support_files

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
