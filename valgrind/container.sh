#!/usr/bin/env bash
# Run the local Valgrind build or analysis scripts inside the iccDEV image.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
image="${ICCDEV_VALGRIND_IMAGE:-ghcr.io/internationalcolorconsortium/iccdev:latest}"

usage() {
    echo "Usage: $0 [--image IMAGE] build|run|status [arguments ...]"
}

if [[ "${1:-}" == "--image" ]]; then
    [[ $# -ge 3 ]] || { usage >&2; exit 2; }
    image="$2"
    shift 2
fi
action="${1:-}"
[[ -n "$action" ]] || { usage >&2; exit 2; }
shift

case "$action" in
    build|run|status) ;;
    *) usage >&2; exit 2 ;;
esac
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is not installed" >&2; exit 127; }

docker run --rm --user "$(id -u):$(id -g)" \
    -v "$REPO_ROOT:/research" -w /research \
    -e VALGRIND_ICCDEV_DIR=/research/iccDEV \
    -e VALGRIND_BUILD_DIR=/research/valgrind/container-build \
    -e VALGRIND_OUTPUT_DIR=/research/valgrind/container-output \
    "$image" "/research/valgrind/$action.sh" "$@"
