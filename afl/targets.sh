#!/bin/bash
# Shared AFL++ target definitions for iccDEV tool binaries.

AFL_TARGETS=(
    applynamedcmm
    applyprofiles
    applyprofiles-fast
    applyprofiles-deep
    applyprofiles-row
    applysearch
    applysearch-weight-positive
    applysearch-weight-zero
    applysearch-weight-negative
    applysearch-weight-nan
    applytolink
    describesink
    dump
    dumpgui
    fromcube
    fromjson
    fromxml
    jpegdump
    pawgreport
    pngdump
    profilevisualize
    roundtrip
    specseptotiff
    tiffdump
    tojson
    toxml
    v5dspobs
)

afl_print_targets() {
    echo "Available targets:"
    echo "  applynamedcmm    - iccApplyNamedCmm (fixed data, fuzz ICC profile)"
    echo "  applyprofiles    - iccApplyProfiles (fixed TIFF, fuzz ICC profile)"
    echo "  applyprofiles-fast - iccApplyProfiles (small ICC profile lane)"
    echo "  applyprofiles-deep - iccApplyProfiles (large ICC profile lane)"
    echo "  applyprofiles-row - iccApplyProfiles (-threads row-apply lane)"
    echo "  applysearch      - iccApplySearch (fixed data, fuzz ICC profiles)"
    echo "  applysearch-weight-positive - iccApplySearch (fuzz PCC profile, fixed weight 1)"
    echo "  applysearch-weight-zero - iccApplySearch (fuzz PCC profile, fixed weight 0)"
    echo "  applysearch-weight-negative - iccApplySearch (fuzz PCC profile, fixed weight -1)"
    echo "  applysearch-weight-nan - iccApplySearch (fuzz PCC profile, fixed weight nan)"
    echo "  applytolink      - iccApplyToLink (DeviceLink/.cube generation)"
    echo "  describesink     - iccDescribeSinkTest (profile sink description)"
    echo "  dump             - iccDumpProfile (ICC binary -> text dump)"
    echo "  dumpgui          - iccDumpProfileGui (GUI profile loader; may require DISPLAY)"
    echo "  fromcube         - iccFromCube (.cube LUT text -> ICC)"
    echo "  fromjson         - iccFromJson (ICC JSON -> binary)"
    echo "  fromxml          - iccFromXml (ICC XML -> binary)"
    echo "  jpegdump         - iccJpegDump (JPEG -> ICC extraction)"
    echo "  pawgreport       - iccPawgReport (PAWG profile assessment)"
    echo "  pngdump          - iccPngDump (PNG -> ICC extraction)"
    echo "  profilevisualize - iccProfileVisualize (ICC profile visualization)"
    echo "  roundtrip        - iccRoundTrip (ICC binary round-trip)"
    echo "  specseptotiff    - iccSpecSepToTiff (fixed spectral TIFFs, fuzz embedded ICC)"
    echo "  tiffdump         - iccTiffDump (TIFF -> ICC extraction)"
    echo "  tojson           - iccToJson (ICC binary -> JSON)"
    echo "  toxml            - iccToXml (ICC binary -> XML)"
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
    local tmp_prefix="${TMPDIR:-/tmp}/afl-${target}-$$"
    local rgb_data="$REPO_ROOT/docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt"
    local srgb_profile="$REPO_ROOT/test-profiles/sRGB_D65_MAT.icc"
    local fixed_tiff
    local fixed_observer

    fixed_tiff="$(afl_first_existing \
        "$REPO_ROOT/test-profiles/tiff-codecs/seed-tiff-none-rgb-8x8.tif" \
        "$REPO_ROOT/afl/iccDEV/Testing/hybrid/Data/TShirtDesignKW.tif" \
        "$REPO_ROOT/test-profiles/Tek350Monaco2_A2B0.tif")"
    fixed_observer="$(afl_first_existing \
        "$REPO_ROOT/test-profiles/XYZ_float-D65_2deg-Part1.icc" \
        "$REPO_ROOT/test-profiles/Lab_float-D65_2deg-Part1.icc" \
        "$REPO_ROOT/test-profiles/Spec400_10_700-D50_2deg-Part1.icc")"

    BINARY=""
    AFL_DIR="$AFL_BASE/afl-$target"
    DICT=""
    TARGET_NOTE=""
    SEED_MAX_BYTES=0
    SEED_LIMIT=200
    REQUIRED_FILES=()
    SEED_DIRS=()
    AFL_ARGS=()

    case "$target" in
        applynamedcmm)
            BINARY="$BIN_DIR/iccApplyNamedCmm"
            DICT="$REPO_ROOT/cfl/icc_applynamedcmm_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            REQUIRED_FILES=("$rgb_data")
            AFL_ARGS=("$rgb_data" "0" "0" "@@" "1")
            ;;
        applyprofiles|profiles|applyprofiles-fast|profiles-fast|applyprofiles-deep|profiles-deep|applyprofiles-row|profiles-row)
            BINARY="$BIN_DIR/iccApplyProfiles"
            DICT="$REPO_ROOT/cfl/icc_applyprofiles_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            REQUIRED_FILES=("$fixed_tiff")
            case "$target" in
                applyprofiles-fast|profiles-fast)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles-fast"
                    SEED_MAX_BYTES=262144
                    SEED_LIMIT=300
                    TARGET_NOTE="Fast ApplyProfiles lane: only seeds <= 256 KiB are copied into a fresh corpus."
                    AFL_ARGS=("$fixed_tiff" "${tmp_prefix}.tif" "1" "0" "0" "0" "0" "@@" "1")
                    ;;
                applyprofiles-deep|profiles-deep)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles-deep"
                    SEED_MAX_BYTES=0
                    SEED_LIMIT=200
                    TARGET_NOTE="Deep ApplyProfiles lane: includes large ICC profiles and may run much slower."
                    AFL_ARGS=("$fixed_tiff" "${tmp_prefix}.tif" "1" "0" "0" "0" "0" "@@" "1")
                    ;;
                applyprofiles-row|profiles-row)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles-row"
                    SEED_MAX_BYTES=524288
                    SEED_LIMIT=300
                    TARGET_NOTE="Row ApplyProfiles lane: uses -threads 0 to exercise row/batched CMM Apply."
                    AFL_ARGS=("-threads" "0" "$fixed_tiff" "${tmp_prefix}.tif" "1" "0" "0" "0" "0" "@@" "1")
                    ;;
                profiles)
                    AFL_DIR="$AFL_BASE/afl-applyprofiles"
                    AFL_ARGS=("$fixed_tiff" "${tmp_prefix}.tif" "1" "0" "0" "0" "0" "@@" "1")
                    ;;
                *)
                    AFL_ARGS=("$fixed_tiff" "${tmp_prefix}.tif" "1" "0" "0" "0" "0" "@@" "1")
                    ;;
            esac
            ;;
        applysearch|search|applysearch-weight|search-weight|applysearch-weight-positive|search-weight-positive|applysearch-weight-zero|search-weight-zero|applysearch-weight-negative|search-weight-negative|applysearch-weight-nan|search-weight-nan)
            BINARY="$BIN_DIR/iccApplySearch"
            if [[ "$target" == "search" ]]; then
                AFL_DIR="$AFL_BASE/afl-search"
            elif [[ "$target" == applysearch-weight* ]]; then
                AFL_DIR="$AFL_BASE/afl-$target"
            elif [[ "$target" == search-weight* ]]; then
                AFL_DIR="$AFL_BASE/afl-applysearch-weight-${target#search-weight-}"
            else
                AFL_DIR="$AFL_BASE/afl-applysearch"
            fi
            DICT="$REPO_ROOT/cfl/icc_applysearch_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            REQUIRED_FILES=("$rgb_data" "$srgb_profile")
            if [[ "$target" == applysearch-weight* || "$target" == search-weight* ]]; then
                local weight_value="1"
                case "$target" in
                    *zero) weight_value="0" ;;
                    *negative) weight_value="-1" ;;
                    *nan) weight_value="nan" ;;
                esac
                AFL_ARGS=("$rgb_data" "0" "0" "$srgb_profile" "1" "$srgb_profile" "1" "-INIT" "1" "@@" "$weight_value")
                TARGET_NOTE="Weight-focused apply-search target: @@ is the fuzzed PCC profile; fixed weight is $weight_value."
            else
                AFL_ARGS=("$rgb_data" "0" "0" "$srgb_profile" "1" "@@" "1" "-INIT" "1")
            fi
            ;;
        applytolink)
            BINARY="$BIN_DIR/iccApplyToLink"
            DICT="$REPO_ROOT/cfl/icc_link_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            AFL_ARGS=("${tmp_prefix}.icc" "0" "9" "0" "AFL" "0.0" "1.0" "0" "0" "@@" "1")
            ;;
        describesink)
            BINARY="$BIN_DIR/iccDescribeSinkTest"
            DICT="$REPO_ROOT/cfl/icc_dump_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            AFL_ARGS=("@@")
            ;;
        dump)
            BINARY="$BIN_DIR/iccDumpProfile"
            DICT="$REPO_ROOT/cfl/icc_dump_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            AFL_ARGS=("@@" "ALL")
            ;;
        dumpgui)
            BINARY="$BIN_DIR/iccDumpProfileGui"
            DICT="$REPO_ROOT/cfl/icc_dump_fuzzer.dict"
            TARGET_NOTE="iccDumpProfileGui is a wx GUI binary and may require DISPLAY/headed execution."
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            AFL_ARGS=("@@")
            ;;
        fromcube)
            BINARY="$BIN_DIR/iccFromCube"
            DICT="$REPO_ROOT/cfl/icc_fromcube_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/docs/iccDEV/Tools/test-data"
                "$REPO_ROOT/cfl/icc_fromcube_fuzzer_seed_corpus"
                "$REPO_ROOT/cfl/corpus-icc_fromcube_fuzzer"
            )
            AFL_ARGS=("@@" "${tmp_prefix}.icc")
            ;;
        fromjson)
            BINARY="$BIN_DIR/iccFromJson"
            DICT="$REPO_ROOT/cfl/icc_cfg_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/docs/Testing/json-configs"
                "$REPO_ROOT/docs/Testing/malformed-json"
                "$REPO_ROOT/fuzz/graphics/json"
                "$REPO_ROOT/afl/iccDEV/Testing"
            )
            AFL_ARGS=("@@" "${tmp_prefix}.icc")
            ;;
        fromxml)
            BINARY="$BIN_DIR/iccFromXml"
            DICT="$REPO_ROOT/cfl/icc_fromxml_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/fuzz/xml/icc"
                "$REPO_ROOT/fuzz/xml/icc/minimized"
                "$REPO_ROOT/cfl/corpus-icc_fromxml_fuzzer"
            )
            AFL_ARGS=("@@" "${tmp_prefix}.icc")
            ;;
        jpegdump)
            BINARY="$BIN_DIR/iccJpegDump"
            DICT="$REPO_ROOT/cfl/icc.dict"
            SEED_DIRS=("$REPO_ROOT/fuzz/graphics/jpg")
            AFL_ARGS=("@@")
            ;;
        pawgreport)
            BINARY="$BIN_DIR/iccPawgReport"
            DICT="$REPO_ROOT/cfl/icc_dump_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            AFL_ARGS=("--json" "@@")
            ;;
        pngdump)
            BINARY="$BIN_DIR/iccPngDump"
            DICT="$REPO_ROOT/cfl/icc.dict"
            SEED_DIRS=("$REPO_ROOT/fuzz/graphics/png")
            AFL_ARGS=("@@")
            ;;
        profilevisualize)
            BINARY="$BIN_DIR/iccProfileVisualize"
            DICT="$REPO_ROOT/cfl/icc_dump_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            AFL_ARGS=("@@")
            ;;
        roundtrip)
            BINARY="$BIN_DIR/iccRoundTrip"
            DICT="$REPO_ROOT/cfl/icc_roundtrip_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            AFL_ARGS=("@@")
            ;;
        specseptotiff|spec)
            BINARY="$BIN_DIR/iccSpecSepToTiff"
            if [[ "$target" == "spec" ]]; then
                AFL_DIR="$AFL_BASE/afl-spec"
            else
                AFL_DIR="$AFL_BASE/afl-specseptotiff"
            fi
            DICT="$REPO_ROOT/cfl/icc_specsep_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            REQUIRED_FILES=("$REPO_ROOT/test-profiles/spectral/spec_001.tif")
            AFL_ARGS=("${tmp_prefix}.tif" "0" "0" "$REPO_ROOT/test-profiles/spectral/spec_%03d.tif" "1" "10" "1" "@@")
            ;;
        tiffdump|tiff)
            BINARY="$BIN_DIR/iccTiffDump"
            AFL_DIR="$AFL_BASE/afl-tiffdump"
            DICT="$REPO_ROOT/cfl/icc_tiffdump_fuzzer.dict"
            SEED_DIRS=(
                "$AFL_BASE/afl-tiffdump/input"
                "$REPO_ROOT/fuzz/graphics/tif"
                "$REPO_ROOT/mangled-images"
                "$REPO_ROOT/test-profiles/tiff-codecs"
                "$REPO_ROOT/test-profiles"
            )
            AFL_ARGS=("@@")
            ;;
        tojson)
            BINARY="$BIN_DIR/iccToJson"
            DICT="$REPO_ROOT/cfl/icc_dump_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            AFL_ARGS=("@@" "${tmp_prefix}.json")
            ;;
        toxml)
            BINARY="$BIN_DIR/iccToXml"
            DICT="$REPO_ROOT/cfl/icc_toxml_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            AFL_ARGS=("@@" "${tmp_prefix}.xml")
            ;;
        v5dspobs)
            BINARY="$BIN_DIR/iccV5DspObsToV4Dsp"
            DICT="$REPO_ROOT/cfl/icc_v5dspobs_fuzzer.dict"
            SEED_DIRS=(
                "$REPO_ROOT/test-profiles"
                "$REPO_ROOT/fuzz/graphics/icc"
                "$REPO_ROOT/extended-test-profiles"
            )
            REQUIRED_FILES=("$fixed_observer")
            AFL_ARGS=("@@" "$fixed_observer" "${tmp_prefix}.icc")
            ;;
        *)
            return 1
            ;;
    esac
}
