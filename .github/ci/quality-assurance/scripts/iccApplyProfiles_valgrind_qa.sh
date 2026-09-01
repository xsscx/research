#!/usr/bin/env bash
# Run deterministic positive-path iccApplyProfiles Memcheck or Helgrind QA.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/../../../.." && pwd)"
tool=memcheck
seconds=300
case_timeout=120
binary=""
output_dir=""

usage() {
    cat <<'EOF'
Usage: iccApplyProfiles_valgrind_qa.sh --binary PATH [options]

  --tool memcheck|helgrind  Valgrind analysis mode (default: memcheck)
  --seconds N               Total interval (default: 300)
  --case-timeout N          Per-case ceiling (default: 120)
  --output-dir PATH         Native-Linux evidence directory

The binary must be a non-sanitized Debug build. Build it with:
  cmake -S iccDEV/Build/Cmake -B /home/xss/qa/iccdev-valgrind-build -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON -DENABLE_TESTS=OFF -DENABLE_SANITIZERS=OFF
  cmake --build /home/xss/qa/iccdev-valgrind-build --target iccApplyProfiles --parallel 32
EOF
}

die() { echo "ERROR: $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tool) tool="$2"; shift 2 ;;
        --seconds) seconds="$2"; shift 2 ;;
        --case-timeout) case_timeout="$2"; shift 2 ;;
        --binary) binary="$2"; shift 2 ;;
        --output-dir) output_dir="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[[ "$tool" == memcheck || "$tool" == helgrind ]] || die "--tool must be memcheck or helgrind"
[[ "$seconds" =~ ^[1-9][0-9]*$ && "$case_timeout" =~ ^[1-9][0-9]*$ ]] || die "time limits must be positive integers"
[[ "$seconds" -gt $((case_timeout + 10)) ]] || die "--seconds must exceed --case-timeout by at least 10"
[[ -n "$binary" && -x "$binary" ]] || die "--binary must name an executable"
command -v valgrind >/dev/null 2>&1 || die "valgrind is not installed"
command -v timeout >/dev/null 2>&1 || die "timeout is not installed"
if ldd "$binary" 2>/dev/null | grep -Eq 'libasan|libubsan|clang_rt\.(asan|ubsan)'; then
    die "Valgrind must not wrap an ASAN/UBSAN binary: $binary"
fi

testing="$repo_root/iccDEV/Testing"
hybrid="$testing/hybrid"
for input in \
    "$hybrid/Data/smCows380_5_780.tif" \
    "$hybrid/Results/MS_smCows.tif" \
    "$hybrid/ICC/Spec400_10_700-IllumA_2deg-Abs.icc" \
    "$hybrid/ICC/Spec400_10_700-F11_2deg-Abs.icc" \
    "$testing/sRGB_v4_ICC_preference.icc"; do
    [[ -f "$input" ]] || die "required input is missing: $input"
done

if [[ -z "$output_dir" ]]; then
    output_dir="$(mktemp -d "${TMPDIR:-/tmp}/iccApplyProfiles-${tool}-qa-XXXXXX")"
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
mkdir -p "$output_dir/config" "$output_dir/results" "$output_dir/logs"

build_root="$(cd "$(dirname "$binary")/../.." && pwd)"
library_path="$build_root/IccProfLib:$build_root/IccXML:$build_root/IccJSON:$build_root/IccConnect"
if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
    library_path="$library_path:$LD_LIBRARY_PATH"
fi
export LD_LIBRARY_PATH="$library_path"

if [[ "$tool" == memcheck ]]; then
    valgrind_args=(--tool=memcheck --error-exitcode=86 --leak-check=full
        '--show-leak-kinds=definite,indirect' '--errors-for-leak-kinds=definite,indirect'
        --track-origins=yes --num-callers=40 --fair-sched=yes)
else
    valgrind_args=(--tool=helgrind --error-exitcode=86 --history-level=approx
        --fair-sched=yes --num-callers=40)
fi

threads=(0 1 2 4)
encodings=(1 2 3)
pccs=(
    "$hybrid/ICC/Spec400_10_700-IllumA_2deg-Abs.icc"
    "$hybrid/ICC/Spec400_10_700-F11_2deg-Abs.icc"
)
cases=(
    "$hybrid/Data/smCows380_5_780.tif|3|0"
    "$hybrid/Data/smCows380_5_780.tif|3|1"
    "$hybrid/Data/smCows380_5_780.tif|3|2"
    "$hybrid/Data/smCows380_5_780.tif|3|3"
    "$hybrid/Data/smCows380_5_780.tif|3|10"
    "$hybrid/Data/smCows380_5_780.tif|3|11"
    "$hybrid/Data/smCows380_5_780.tif|3|12"
    "$hybrid/Data/smCows380_5_780.tif|3|13"
    "$hybrid/Results/MS_smCows.tif|10003|40"
    "$hybrid/Results/MS_smCows.tif|10003|41"
    "$hybrid/Results/MS_smCows.tif|10003|42"
)

printf 'case\trc\tvg_errors\tthread\tsource\tpcc\tintent\tencoding\toutput_ok\n' > "$output_dir/summary.tsv"
start_seconds=$SECONDS
launch_deadline=$((start_seconds + seconds - case_timeout - 5))
case_id=0
successes=0
findings=0
rejections=0
timeouts=0
output_failures=0

while (( SECONDS < launch_deadline )); do
    case_id=$((case_id + 1))
    z=$((case_id - 1))
    IFS='|' read -r source embedded intent <<< "${cases[$((z % ${#cases[@]}))]}"
    thread="${threads[$((z % ${#threads[@]}))]}"
    encoding="${encodings[$(((z / 2) % ${#encodings[@]}))]}"
    pcc="${pccs[$(((z / 4) % ${#pccs[@]}))]}"
    tag="$(printf '%05d' "$case_id")"
    cfg="$output_dir/config/$tag.json"
    result="$output_dir/results/$tag.tif"
    vglog="$output_dir/logs/$tag.valgrind.log"
    stdout="$output_dir/logs/$tag.stdout"

    set +e
    timeout -k 5s "${case_timeout}s" valgrind "${valgrind_args[@]}" \
        --log-file="$vglog" "$binary" -threads "$thread" -exportcfg "$cfg" \
        "$source" "$result" "$encoding" 1 0 1 1 \
        -embedded "$embedded" -PCC "$pcc" \
        "$testing/sRGB_v4_ICC_preference.icc" "$intent" >"$stdout" 2>&1
    rc=$?
    set -e

    vg_errors="$(sed -n 's/.*ERROR SUMMARY: \([0-9][0-9]*\) errors.*/\1/p' "$vglog" | tail -1)"
    vg_errors="${vg_errors:-0}"
    output_ok=0
    if [[ "$rc" -eq 0 && -s "$cfg" && -s "$result" ]] && file "$result" | grep -q 'TIFF image data'; then
        output_ok=1
        successes=$((successes + 1))
    elif [[ "$rc" -eq 86 || "$vg_errors" -gt 0 ]]; then
        findings=$((findings + 1))
    elif [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
        timeouts=$((timeouts + 1))
    elif [[ "$rc" -eq 0 ]]; then
        output_failures=$((output_failures + 1))
    else
        rejections=$((rejections + 1))
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$case_id" "$rc" "$vg_errors" "$thread" "$source" "$pcc" \
        "$intent" "$encoding" "$output_ok" >> "$output_dir/summary.tsv"
done

printf 'tool=%s cases=%s successes=%s rejections=%s findings=%s timeouts=%s output_failures=%s evidence=%s\n' \
    "$tool" "$case_id" "$successes" "$rejections" "$findings" "$timeouts" \
    "$output_failures" "$output_dir"

if [[ "$case_id" -eq 0 || "$findings" -ne 0 || "$timeouts" -ne 0 || \
      "$output_failures" -ne 0 || "$rejections" -ne 0 ]]; then
    exit 1
fi
exit 0
