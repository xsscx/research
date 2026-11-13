#!/usr/bin/env bash
# Run one ICC parser command inside the repository's hostile-input boundary.
set -euo pipefail

SCRIPT_DIR=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR
REPO_ROOT=$(cd -P -- "$SCRIPT_DIR/../.." && pwd)
readonly REPO_ROOT
readonly MAX_INPUT_BYTES=$((512 * 1024 * 1024))
readonly MAX_OUTPUT_BYTES=$((64 * 1024 * 1024))
readonly MEMORY_MAX_BYTES=$((4 * 1024 * 1024 * 1024))
readonly WALL_SECONDS=45
readonly CPU_SECONDS=60
readonly TASKS_MAX=64

usage() {
    echo "Usage: $0 --input FILE [--input FILE ...] [--workdir DIR] -- TOOL [ARG ...]" >&2
    echo "Use @INPUT0@, @INPUT1@, and @SCRATCH@ tokens in tool arguments." >&2
}

fail() {
    echo "[FAIL] $*" >&2
    exit 70
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

case "$(uname -s)" in
    Linux) ;;
    *) fail "the hostile-input runner currently requires Linux" ;;
esac

for required in bwrap cp jq prlimit sha256sum stat systemctl systemd-run; do
    require_command "$required"
done

declare -a input_paths=()
workdir=$REPO_ROOT

while (($#)); do
    case "$1" in
        --input)
            (($# >= 2)) || { usage; exit 64; }
            input_paths+=("$2")
            shift 2
            ;;
        --workdir)
            (($# >= 2)) || { usage; exit 64; }
            workdir=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 64
            ;;
    esac
done

((${#input_paths[@]} > 0)) || fail "at least one --input is required"
((${#input_paths[@]} <= 8)) || fail "at most eight inputs are supported"
(($# > 0)) || fail "a tool command is required after --"

workdir=$(realpath -e -- "$workdir")
case "$workdir/" in
    "$REPO_ROOT/"*) ;;
    *) fail "working directory is outside the repository: $workdir" ;;
esac
[ -d "$workdir" ] || fail "working directory is not a directory: $workdir"

tool_arg=$1
shift
if [[ $tool_arg = /* ]]; then
    tool_path=$tool_arg
else
    tool_path=$REPO_ROOT/$tool_arg
fi
tool_path=$(realpath -e -- "$tool_path")
[ -f "$tool_path" ] && [ -x "$tool_path" ] || fail "tool is not executable: $tool_path"

tool_name=${tool_path##*/}
case "$tool_path" in
    "$REPO_ROOT"/iccDEV/Build*/Tools/*/*|"$REPO_ROOT"/afl/iccDEV/Build*/Tools/*/*|"$REPO_ROOT"/afl/bin*/*|"$REPO_ROOT"/cfl/bin*/*|"$REPO_ROOT"/colorbleed_tools/*_unsafe) ;;
    *) fail "tool is outside the approved ICC executable roots: $tool_path" ;;
esac
case "$tool_name" in
    iccDumpProfile|iccPawgReport|iccToXml|iccFromXml|iccToJson|iccFromJson|iccProfilePlot|iccApplyNamedCmm|iccApplyProfiles|iccTiffDump_unsafe|iccJpegDump_unsafe|iccToXml_unsafe|iccFromXml_unsafe|iccToJson_unsafe|iccFromJson_unsafe|icc_*_fuzzer) ;;
    *) fail "tool is not on the hostile-input allowlist: $tool_name" ;;
esac

evidence_dir=$(mktemp -d /tmp/icc-hostile-evidence.XXXXXX)
chmod 0770 "$evidence_dir"
stdout_file=$evidence_dir/stdout.txt
stderr_file=$evidence_dir/stderr.txt
: >"$stdout_file"
: >"$stderr_file"
chmod 0660 "$stdout_file" "$stderr_file"

declare -a pinned_inputs=()
inputs_json='[]'
input_index=0
for input_path in "${input_paths[@]}"; do
    resolved_input=$(realpath -e -- "$input_path")
    [ -f "$resolved_input" ] || fail "input is not a regular file: $resolved_input"
    case "$resolved_input" in
        "$REPO_ROOT"/*|/tmp/*) ;;
        *) fail "input is outside the repository and /tmp handoff roots: $resolved_input" ;;
    esac
    input_size=$(stat -Lc '%s' -- "$resolved_input")
    ((input_size <= MAX_INPUT_BYTES)) || fail "input exceeds 512 MiB: $resolved_input"

    input_name=${resolved_input##*/}
    input_lower=${input_name,,}
    case "$input_lower" in
        *.icc|*.icm) input_suffix=.icc ;;
        *.tiff|*.tif) input_suffix=.tiff ;;
        *.jpeg|*.jpg) input_suffix=.jpeg ;;
        *.png) input_suffix=.png ;;
        *.xml) input_suffix=.xml ;;
        *.json) input_suffix=.json ;;
        *.cube) input_suffix=.cube ;;
        *) input_suffix=.bin ;;
    esac

    pinned_input=$evidence_dir/input-${input_index}${input_suffix}
    cp --reflink=never -- "$resolved_input" "$pinned_input"
    chmod 0440 "$pinned_input"
    pinned_digest=$(sha256sum -- "$pinned_input")
    pinned_digest=${pinned_digest%% *}
    pinned_inputs+=("$pinned_input")
    inputs_json=$(jq -cn \
        --argjson current "$inputs_json" \
        --arg source "$resolved_input" \
        --arg pinned "$pinned_input" \
        --arg sha256 "$pinned_digest" \
        --argjson bytes "$input_size" \
        '$current + [{source:$source,pinned:$pinned,sha256:$sha256,bytes:$bytes}]')
    ((input_index += 1))
done

declare -a tool_args=()
for raw_arg in "$@"; do
    resolved_arg=${raw_arg//@SCRATCH@/$evidence_dir}
    for ((input_index = 0; input_index < ${#pinned_inputs[@]}; input_index++)); do
        resolved_arg=${resolved_arg//@INPUT${input_index}@/${pinned_inputs[$input_index]}}
    done
    [[ $resolved_arg != *'@INPUT'* && $resolved_arg != *'@SCRATCH@'* ]] || \
        fail "unresolved runner token in argument: $raw_arg"
    tool_args+=("$resolved_arg")
done

declare -a bwrap_args=(
    --die-with-parent
    --new-session
    --unshare-all
    --clearenv
    --setenv PATH /usr/local/bin:/usr/bin:/bin
    --setenv HOME /nonexistent
    --setenv TMPDIR /tmp
    --setenv LC_ALL C
    --setenv ASAN_OPTIONS halt_on_error=0:detect_leaks=0:print_scariness=1
    --setenv MSAN_OPTIONS halt_on_error=1:abort_on_error=1:symbolize=1:exit_code=86
    --setenv UBSAN_OPTIONS print_stacktrace=1
    --setenv LLVM_PROFILE_FILE /dev/null
)

for system_path in /usr /bin /lib /lib64 /etc; do
    [ ! -e "$system_path" ] || bwrap_args+=(--ro-bind "$system_path" "$system_path")
done

bwrap_args+=(
    --proc /proc
    --dev /dev
    --tmpfs /tmp
    --dir /home
    --dir /home/xss
    --ro-bind "$REPO_ROOT" "$REPO_ROOT"
    --bind "$evidence_dir" "$evidence_dir"
    --chdir "$workdir"
    --uid 65534
    --gid 65534
    --
    "$tool_path"
    "${tool_args[@]}"
)

unit_name=icc-hostile-${UID}-$$-${RANDOM}
set +e
systemd-run --user \
    --unit="$unit_name" \
    --wait \
    --quiet \
    --property="CPUQuota=200%" \
    --property="MemoryMax=$MEMORY_MAX_BYTES" \
    --property="TasksMax=$TASKS_MAX" \
    --property="RuntimeMaxSec=${WALL_SECONDS}s" \
    --property="NoNewPrivileges=yes" \
    --property="StandardOutput=file:$stdout_file" \
    --property="StandardError=file:$stderr_file" \
    prlimit \
        --cpu="$CPU_SECONDS" \
        --fsize="$MAX_OUTPUT_BYTES" \
        --nofile=128 \
        --core=0 \
        -- \
        bwrap "${bwrap_args[@]}"
run_rc=$?
set -e

unit_result=$(systemctl --user show "$unit_name" --property=Result --value 2>/dev/null || true)
exec_code=$(systemctl --user show "$unit_name" --property=ExecMainCode --value 2>/dev/null || true)
exec_status=$(systemctl --user show "$unit_name" --property=ExecMainStatus --value 2>/dev/null || true)
systemctl --user reset-failed "$unit_name" >/dev/null 2>&1 || true
chmod 0700 "$evidence_dir"

[ -n "$unit_result" ] || fail "systemd did not retain a result for $unit_name"
[[ $exec_code =~ ^[0-9]+$ ]] || fail "invalid systemd ExecMainCode: $exec_code"
[[ $exec_status =~ ^[0-9]+$ ]] || fail "invalid systemd ExecMainStatus: $exec_status"

timed_out=false
resource_limited=false
signal_number=0
exit_code=$exec_status

case "$unit_result" in
    timeout)
        timed_out=true
        signal_number=$exec_status
        exit_code=124
        ;;
    oom-kill)
        resource_limited=true
        signal_number=$exec_status
        exit_code=$((128 + exec_status))
        ;;
    success)
        exit_code=0
        ;;
    exit-code)
        exit_code=$exec_status
        ;;
    signal|core-dump)
        signal_number=$exec_status
        exit_code=$((128 + exec_status))
        ;;
    *)
        exit_code=$run_rc
        ;;
esac

cat -- "$stdout_file"
cat -- "$stderr_file" >&2
jq -cn \
    --arg schema 'icc-hostile-run/v1' \
    --arg tool "$tool_path" \
    --arg workdir "$workdir" \
    --arg evidenceDir "$evidence_dir" \
    --arg unitResult "$unit_result" \
    --argjson inputs "$inputs_json" \
    --argjson rawExecCode "$exec_code" \
    --argjson rawExecStatus "$exec_status" \
    --argjson signal "$signal_number" \
    --argjson timedOut "$timed_out" \
    --argjson resourceLimited "$resource_limited" \
    --argjson exitCode "$exit_code" \
    '{schema:$schema,tool:$tool,workdir:$workdir,evidenceDir:$evidenceDir,inputs:$inputs,unitResult:$unitResult,rawExecCode:$rawExecCode,rawExecStatus:$rawExecStatus,signal:$signal,timedOut:$timedOut,resourceLimited:$resourceLimited,exitCode:$exitCode}' >&2

exit "$exit_code"
