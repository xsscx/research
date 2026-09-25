#!/bin/bash
# Reproduce an iccApplyNamedCmm MSan finding in the published iccDEV image.

set -euo pipefail

IMAGE="${ICCDEV_DOCKER_IMAGE:-ghcr.io/internationalcolorconsortium/iccdev@sha256:0504c43e0204e36aa36377fceee1de9c5f49468d578202c388525c75d42da079}"
EXPECTED_REVISION="da7e075706d76e5451f2924b8818ef57114b0d66"

usage() {
    echo "Usage: $0 <icc-profile>"
}

if [[ $# -ne 1 ]]; then
    usage >&2
    exit 2
fi
if [[ ! -f "$1" ]]; then
    echo "ERROR: ICC profile not found: $1" >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is required" >&2
    exit 1
fi

PROFILE="$(realpath "$1")"
REVISION="$(docker image inspect "$IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null || true)"
if [[ -n "$REVISION" && "$IMAGE" == *"@sha256:"* && "$REVISION" != "$EXPECTED_REVISION" ]]; then
    echo "ERROR: pinned image revision is $REVISION, expected $EXPECTED_REVISION" >&2
    exit 1
fi

echo "Image:   $IMAGE"
echo "Profile: $PROFILE"
sha256sum "$PROFILE"

LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/iccdev-docker-msan.XXXXXX")"
trap 'rm -f "$LOG_FILE"' EXIT

set +e
docker run --rm --pull=missing --network none \
    --security-opt seccomp=unconfined \
    --mount "type=bind,src=$PROFILE,dst=/tmp/poc.icc,readonly" \
    --entrypoint bash "$IMAGE" -lc '
set -e
printf "iccDEV revision: "
git rev-parse HEAD
ICCDEV_MSAN_LIBCXX_DIR=/opt/iccdev-msan-libcxx \
    cmake --preset linux-clang-msan -S Build/Cmake -B /tmp/iccdev-msan
cmake --build /tmp/iccdev-msan --target iccApplyNamedCmm --parallel "$(nproc)"
set +e
MSAN_OPTIONS=halt_on_error=1:abort_on_error=1:symbolize=1:exit_code=86 \
    timeout 60s /tmp/iccdev-msan/Tools/IccApplyNamedCmm/iccApplyNamedCmm \
    docs/Testing/test-data/rgb-8bit.txt 0 1 /tmp/poc.icc 41
rc=$?
set -e
printf "EXIT=%s\n" "$rc"
exit 0
' 2>&1 | tee "$LOG_FILE"
DOCKER_EXIT="${PIPESTATUS[0]}"
set -e

if grep -Fq 'SUMMARY: MemorySanitizer: use-of-uninitialized-value /workspace/iccDEV/IccProfLib/IccTagMPE.cpp:1487:14 in CIccTagMultiProcessElement::GetNewApply()' "$LOG_FILE" &&
   grep -Fq 'EXIT=134' "$LOG_FILE"; then
    echo "DOCKER_REPRO=CONFIRMED"
    exit 86
fi
if [[ "$DOCKER_EXIT" -ne 0 ]]; then
    echo "ERROR: Docker reproduction failed before confirmation (exit $DOCKER_EXIT)" >&2
    exit 1
fi

echo "ERROR: Docker run did not reproduce the expected MSan signature" >&2
exit 1
