#!/usr/bin/env bash
# cfl/rebuild.sh - Stop running CFL fuzzers and rebuild local LibFuzzer bins.
#
# Usage: ./cfl/rebuild.sh [build.sh args]
#
# This preserves corpora and the nested cfl/iccDEV source checkout. It only
# removes local build outputs before delegating to cfl/build.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "[*] Full CFL rebuild requested"
echo ""

"$SCRIPT_DIR/stop.sh" all --quiet || true

echo "[*] Removing CFL build outputs"
rm -rf "${SCRIPT_DIR:?}/bin" \
       "${SCRIPT_DIR:?}/profraw" \
       "${SCRIPT_DIR:?}/.build_tmp" \
       "${SCRIPT_DIR:?}/.build_cfg_tmp"

exec "$REPO_ROOT/cfl/build.sh" "$@"
