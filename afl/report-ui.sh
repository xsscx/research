#!/bin/bash
# afl/report-ui.sh - Serve the AFL report viewer from the local afl/ tree
#
# Usage: ./afl/report-ui.sh [report-dir] [port] [host]
#        report-dir may be under afl/reports/generated/ or an external
#        session artifact directory such as ~/work/copilot/<report>.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AFL_ROOT="$REPO_ROOT/afl"
REPORT_DIR="${1:-}"
PORT="${2:-8765}"
HOST="${3:-127.0.0.1}"

usage() {
    sed -n '2,6p' "$0" | sed 's/^# \?//'
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

if [[ -z "$REPORT_DIR" ]]; then
    REPORT_DIR="$(find "$AFL_ROOT/reports/generated" -maxdepth 1 -type d \( -name 'afl-report-*' -o -name 'afl-coverage-*' \) -printf '%T@\t%p\n' 2>/dev/null | sort -nr | awk 'NR == 1 {print $2}')"
fi

if [[ -z "$REPORT_DIR" ]]; then
    echo "ERROR: no generated AFL report found under $AFL_ROOT/reports/generated" >&2
    echo "Run ./afl/report.sh or pass an explicit report directory." >&2
    exit 1
fi

case "$REPORT_DIR" in
    /*) REPORT_ABS="$REPORT_DIR" ;;
    *) REPORT_ABS="$REPO_ROOT/$REPORT_DIR" ;;
esac

if [[ ! -d "$REPORT_ABS" ]]; then
    echo "ERROR: report directory not found: $REPORT_ABS" >&2
    exit 1
fi

REPORT_ABS="$(cd "$REPORT_ABS" && pwd)"
REPORT_DISPLAY="$REPORT_ABS"
REPORT_MOUNT=""
case "$REPORT_ABS" in
    "$AFL_ROOT"/*)
        REPORT_REL="${REPORT_ABS#"$AFL_ROOT"/}"
        ;;
    *)
        mount_name="$(printf "%s" "$(basename "$REPORT_ABS")" | tr -c 'A-Za-z0-9_.+-' '-')"
        REPORT_MOUNT="$AFL_ROOT/reports/generated/external-$mount_name"
        mkdir -p "$AFL_ROOT/reports/generated"
        if [[ -e "$REPORT_MOUNT" && ! -L "$REPORT_MOUNT" ]]; then
            echo "ERROR: external report mount exists and is not a symlink: $REPORT_MOUNT" >&2
            exit 1
        fi
        ln -sfn "$REPORT_ABS" "$REPORT_MOUNT"
        REPORT_REL="${REPORT_MOUNT#"$AFL_ROOT"/}"
        ;;
esac

URL="http://$HOST:$PORT/dashboard/report-viewer/?report=$REPORT_REL"
LATEST_LINK="$AFL_ROOT/reports/generated/latest"

if [[ -z "$REPORT_MOUNT" && "$REPORT_ABS" == "$AFL_ROOT"/reports/generated/* ]]; then
    if [[ -e "$LATEST_LINK" && ! -L "$LATEST_LINK" ]]; then
        echo "WARN: latest report path exists and is not a symlink: $LATEST_LINK" >&2
    else
        ln -sfn "$(basename "$REPORT_ABS")" "$LATEST_LINK"
    fi
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required to serve the static report viewer" >&2
    exit 1
fi

echo "[*] AFL report: $REPORT_DISPLAY"
if [[ -n "$REPORT_MOUNT" ]]; then
    echo "[*] Mounted external report: $REPORT_MOUNT -> $REPORT_DISPLAY"
fi
echo "[*] AFL report UI: $URL"
echo "[*] Serving $AFL_ROOT"
cd "$AFL_ROOT"
exec python3 -m http.server "$PORT" --bind "$HOST"
