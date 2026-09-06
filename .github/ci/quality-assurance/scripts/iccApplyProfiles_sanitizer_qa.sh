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
driver=""
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
  --driver PATH        Deterministic CI path driver
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
        --driver) driver="$2"; shift 2 ;;
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

if [[ -z "$driver" ]]; then
    driver="$repo_root/iccDEV/.github/ci/quality-assurance/scripts/iccApplyProfiles_ci_path_exercise.sh"
fi
driver_dir="$(cd "$(dirname "$driver")" && pwd)"
driver="$driver_dir/$(basename "$driver")"
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

driver_jobs="$jobs"
completion_manifest=0
if grep -q 'expected-export-count' "$driver"; then
    completion_manifest=1
elif [[ "$jobs" -gt 1 ]]; then
    driver_jobs=1
    echo "[WARN] deterministic driver lacks completion records; using one worker" >&2
fi

set +e
(
    cd "$work"
    PATH="$output_dir/bin:/usr/local/bin:/usr/bin:/bin" \
    LD_LIBRARY_PATH="$library_path" \
    ASAN_OPTIONS='detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1' \
    UBSAN_OPTIONS='halt_on_error=1:abort_on_error=1:print_stacktrace=1' \
    timeout -k 10s "${seconds}s" bash "$driver" \
        --mutations "$mutations" --start-at "$start_at" --jobs "$driver_jobs" \
        --no-risky-scalars --log-dir logs
)
runner_rc=$?
set -e

sanitizer_summary="$work/logs/sanitizer-summary.txt"
failure_summary="$work/logs/failures.txt"
rejection_records="$work/logs/rejection-records.tsv"
rejection_categories="$work/logs/rejection-categories.tsv"
status_dir="$work/logs/status"
sanitizer_lines=0
rejection_lines=0
[[ -f "$sanitizer_summary" ]] && sanitizer_lines="$(grep -cve '^[[:space:]]*$' "$sanitizer_summary" || true)"
configs="$(find "$work/config" -type f -name '*.json' -size +0c | wc -l)"
outputs="$(find "$work/Results" -type f -name 'ci_path_*.tif' -size +0c | wc -l)"

printf 'mutation\tmode\texit_code\tcategory\tlog\n' > "$rejection_records"
status_errors=0
record_rejection() {
    local mutation="$1"
    local mode="$2"
    local rc="$3"
    local log_file="$work/logs/${mutation}.${mode}.out"
    local category="unclassified-tool-rejection"

    if [[ ! -f "$log_file" ]]; then
        category="missing-tool-log"
    elif grep -q 'AddXform failed.*Invalid profile transform' "$log_file"; then
        category="invalid-profile-transform"
    elif grep -qiE 'invalid argument|unknown option|usage:' "$log_file"; then
        category="invalid-arguments"
    elif grep -qiE 'timed out|timeout' "$log_file"; then
        category="per-case-timeout"
    fi
    rejection_lines=$((rejection_lines + 1))
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$mutation" "$mode" "$rc" "$category" "$log_file" >> "$rejection_records"
}

if [[ "$completion_manifest" -eq 1 && -d "$status_dir" ]]; then
    while IFS= read -r status_file; do
        status_name="$(basename "$status_file")"
        if [[ ! "$status_name" =~ ^([0-9]+)\.(export|cfg)\.rc$ ]]; then
            status_errors=$((status_errors + 1))
            continue
        fi
        mutation="${BASH_REMATCH[1]}"
        mode="${BASH_REMATCH[2]}"
        rc="$(<"$status_file")"
        if [[ ! "$rc" =~ ^[0-9]+$ ]]; then
            status_errors=$((status_errors + 1))
            continue
        fi
        [[ "$rc" -eq 0 ]] && continue
        record_rejection "$mutation" "$mode" "$rc"
    done < <(find "$status_dir" -maxdepth 1 -type f -name '*.rc' -print | LC_ALL=C sort)
elif [[ "$completion_manifest" -eq 1 && "$runner_rc" -ne 124 ]]; then
    status_errors=1
fi
if [[ "$completion_manifest" -eq 1 && "$runner_rc" -ne 124 ]]; then
    expected_file="$status_dir/expected-export-count"
    if [[ ! -f "$expected_file" ]]; then
        status_errors=$((status_errors + 1))
    else
        expected_exports="$(<"$expected_file")"
        completed_exports="$(find "$status_dir" -maxdepth 1 -type f -name '*.export.rc' | wc -l)"
        if [[ ! "$expected_exports" =~ ^[0-9]+$ ||
              "$completed_exports" -ne "$expected_exports" ]]; then
            status_errors=$((status_errors + 1))
        fi
    fi
fi
if [[ "$completion_manifest" -eq 0 && -f "$failure_summary" ]]; then
    while IFS= read -r record; do
        [[ -z "$record" || "$record" == "iccApplyProfiles "* ]] && continue
        if [[ "$record" =~ ^([0-9]+)\ (export|cfg)\ rc=([0-9]+)$ ]]; then
            record_rejection "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
        else
            status_errors=$((status_errors + 1))
        fi
    done < "$failure_summary"
elif [[ "$completion_manifest" -eq 0 && "$runner_rc" -ne 124 ]]; then
    status_errors=1
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
[[ "$status_errors" -eq 0 ]] || exit 1
[[ "$unclassified_rejections" -eq 0 ]] || exit 1
if [[ "$runner_rc" -ne 0 && "$runner_rc" -ne 124 ]]; then
    # The upstream driver returns 1 after it records any case failure. In
    # non-strict mode that is clean only when every record is classified.
    if [[ "$runner_rc" -ne 1 || "$rejection_lines" -eq 0 ]]; then
        exit "$runner_rc"
    fi
fi
if [[ "$strict_rejections" -eq 1 && "$rejection_lines" -ne 0 ]]; then
    exit 1
fi
exit 0
