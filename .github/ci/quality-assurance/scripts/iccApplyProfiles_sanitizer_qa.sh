#!/usr/bin/env bash
# Run bounded, deterministic iccApplyProfiles ASAN/UBSAN QA.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/../../../.." && pwd)"
seconds=300
jobs=8
mutations=1000
start_at=1
binary="$repo_root/iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles"
output_dir=""
strict_rejections=0

usage() {
    cat <<'EOF'
Usage: iccApplyProfiles_sanitizer_qa.sh [options]

  --seconds N          Hard wall-clock limit (default: 300)
  --jobs N             Concurrent cases (default: 8)
  --mutations N|max    Maximum generated cases (default: 1000)
  --start-at N         First deterministic mutation index (default: 1)
  --binary PATH        ASAN/UBSAN iccApplyProfiles binary
  --output-dir PATH    Native-Linux evidence directory
  --strict-rejections  Fail when otherwise clean tool rejections occur
EOF
}

die() { echo "ERROR: $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --seconds) seconds="$2"; shift 2 ;;
        --jobs) jobs="$2"; shift 2 ;;
        --mutations) mutations="$2"; shift 2 ;;
        --start-at) start_at="$2"; shift 2 ;;
        --binary) binary="$2"; shift 2 ;;
        --output-dir) output_dir="$2"; shift 2 ;;
        --strict-rejections) strict_rejections=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

for value in "$seconds" "$jobs" "$start_at"; do
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "numeric options must be positive integers"
done
if [[ "$mutations" != "max" && ! "$mutations" =~ ^[1-9][0-9]*$ ]]; then
    die "--mutations must be a positive integer or max"
fi

driver="$repo_root/iccDEV/.github/ci/quality-assurance/scripts/iccApplyProfiles_ci_path_exercise.sh"
testing="$repo_root/iccDEV/Testing"
hybrid_source="$testing/hybrid"
[[ -x "$binary" ]] || die "binary is not executable: $binary"
[[ -f "$driver" ]] || die "upstream deterministic driver is missing: $driver"
for input in \
    "$hybrid_source/Data/smCows380_5_780.tif" \
    "$hybrid_source/Data/TShirtDesignCMYKW.tif" \
    "$hybrid_source/Data/TShirtDesignKW.tif" \
    "$hybrid_source/Results/MS_smCows.tif" \
    "$hybrid_source/ICC/MultSpectralRGB.icc" \
    "$hybrid_source/ICC/Spec400_10_700-IllumA_2deg-Abs.icc" \
    "$hybrid_source/ICC/Spec400_10_700-F11_2deg-Abs.icc" \
    "$hybrid_source/ICC/CMYK-W_Overprint_Profile.icc" \
    "$hybrid_source/ICC/CMYK-S_Overprint_Profile.icc" \
    "$hybrid_source/ICC/CMYK-STop_Overprint_Profile.icc" \
    "$hybrid_source/ICC/MW-Mid_Overprint.icc" \
    "$hybrid_source/ICC/MS-Mid_Overprint.icc" \
    "$hybrid_source/ICC/SC-Mid_Overprint.icc" \
    "$testing/sRGB_v4_ICC_preference.icc"; do
    [[ -f "$input" ]] || die "run iccDEV/Testing/hybrid/BuildAndTest.sh to generate: $input"
done

if [[ -z "$output_dir" ]]; then
    output_dir="$(mktemp -d "${TMPDIR:-/tmp}/iccApplyProfiles-sanitizer-qa-XXXXXX")"
else
    if [[ -d "$output_dir" && -n "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        die "--output-dir must be empty: $output_dir"
    fi
    mkdir -p "$output_dir"
    output_dir="$(cd "$output_dir" && pwd)"
fi
case "$output_dir" in
    /mnt/*) die "use a native Linux output path, not $output_dir" ;;
esac

work="$output_dir/hybrid"
mkdir -p "$work/Results" "$work/config" "$work/logs" "$output_dir/bin"
ln -sfn "$hybrid_source/Data" "$work/Data"
ln -sfn "$hybrid_source/ICC" "$work/ICC"
ln -sfn "$testing/sRGB_v4_ICC_preference.icc" "$output_dir/sRGB_v4_ICC_preference.icc"
ln -sfn "$hybrid_source/Results/MS_smCows.tif" "$work/Results/MS_smCows.tif"
ln -sfn "$binary" "$output_dir/bin/iccApplyProfiles"

build_root="$(cd "$(dirname "$binary")/../.." && pwd)"
library_path="$build_root/IccProfLib:$build_root/IccXML:$build_root/IccJSON:$build_root/IccConnect"
if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
    library_path="$library_path:$LD_LIBRARY_PATH"
fi

set +e
(
    cd "$work"
    PATH="$output_dir/bin:/usr/local/bin:/usr/bin:/bin" \
    LD_LIBRARY_PATH="$library_path" \
    ASAN_OPTIONS='detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1' \
    UBSAN_OPTIONS='halt_on_error=1:abort_on_error=1:print_stacktrace=1' \
    timeout -k 10s "${seconds}s" bash "$driver" \
        --mutations "$mutations" --start-at "$start_at" --jobs "$jobs" \
        --no-risky-scalars --log-dir logs
)
runner_rc=$?
set -e

sanitizer_summary="$work/logs/sanitizer-summary.txt"
failure_summary="$work/logs/failures.txt"
rejection_records="$work/logs/rejection-records.tsv"
rejection_categories="$work/logs/rejection-categories.tsv"
sanitizer_lines=0
rejection_lines=0
[[ -f "$sanitizer_summary" ]] && sanitizer_lines="$(grep -cve '^[[:space:]]*$' "$sanitizer_summary" || true)"
[[ -f "$failure_summary" ]] && rejection_lines="$(grep -cE '^[0-9]+ (export|cfg) rc=' "$failure_summary" || true)"
configs="$(find "$work/config" -type f -name '*.json' -size +0c | wc -l)"
outputs="$(find "$work/Results" -type f -name 'ci_path_*.tif' -size +0c | wc -l)"

printf 'mutation\tmode\texit_code\tcategory\tlog\n' > "$rejection_records"
if [[ -f "$failure_summary" ]]; then
    while read -r mutation mode rc; do
        [[ "$mutation" =~ ^[0-9]+$ && "$mode" =~ ^(export|cfg)$ && "$rc" =~ ^rc=[0-9]+$ ]] || continue
        log_file="$work/logs/${mutation}.${mode}.out"
        category="unclassified-tool-rejection"
        if [[ ! -f "$log_file" ]]; then
            category="missing-tool-log"
        elif grep -q 'AddXform failed.*Invalid profile transform' "$log_file"; then
            category="invalid-profile-transform"
        elif grep -qiE 'invalid argument|unknown option|usage:' "$log_file"; then
            category="invalid-arguments"
        elif grep -qiE 'timed out|timeout' "$log_file"; then
            category="per-case-timeout"
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$mutation" "$mode" "${rc#rc=}" "$category" "$log_file" >> "$rejection_records"
    done < "$failure_summary"
fi
{
    printf 'category\tcount\n'
    awk -F '\t' 'NR > 1 { print $4 }' "$rejection_records" |
        LC_ALL=C sort | uniq -c |
        awk '{ print $2 "\t" $1 }'
} > "$rejection_categories"
unclassified_rejections="$(
    awk -F '\t' '
        NR > 1 &&
        $4 != "invalid-profile-transform" &&
        $4 != "invalid-arguments" {
            count++
        }
        END { print count + 0 }
    ' "$rejection_records"
)"

printf 'runner_rc=%s sanitizer_lines=%s rejections=%s unclassified_rejections=%s configs=%s outputs=%s rejection_categories=%s evidence=%s\n' \
    "$runner_rc" "$sanitizer_lines" "$rejection_lines" "$unclassified_rejections" \
    "$configs" "$outputs" "$rejection_categories" "$output_dir"

[[ "$sanitizer_lines" -eq 0 ]] || exit 86
if [[ "$configs" -eq 0 || "$outputs" -eq 0 ]]; then
    exit 1
fi
if [[ "$runner_rc" -ne 0 && "$runner_rc" -ne 124 ]]; then
    # The upstream driver returns 1 after it records any case failure. In
    # non-strict mode that is clean only when every record is classified.
    if [[ "$runner_rc" -ne 1 || "$rejection_lines" -eq 0 ||
          "$unclassified_rejections" -ne 0 ]]; then
        exit "$runner_rc"
    fi
fi
if [[ "$strict_rejections" -eq 1 && "$rejection_lines" -ne 0 ]]; then
    exit 1
fi
exit 0
