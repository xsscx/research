#!/usr/bin/env bash
# Clean and rebuild the selected ICC FuzzTest mode.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec "$SCRIPT_DIR/build.sh" clean "$@"
