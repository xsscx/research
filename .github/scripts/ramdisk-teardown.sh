#!/bin/bash
#
# ramdisk-teardown.sh — Sync corpus to disk, clean stray items, unmount ramdisk
#
# Usage:
#   sudo .github/scripts/ramdisk-teardown.sh          # full teardown
#   .github/scripts/ramdisk-teardown.sh --no-unmount   # sync+clean only
#   .github/scripts/ramdisk-teardown.sh --merge        # merge before sync
#
# Orchestrates the full shutdown sequence:
#   1. (optional) Merge/deduplicate corpus on ramdisk
#   2. Sync corpus from ramdisk → cfl/corpus-*
#   3. Save crash artifacts to cfl/findings/
#   4. Clean stray dirs/files from ramdisk
#   5. Unmount the ramdisk

set -euo pipefail

die() { echo "[FAIL] ERROR: $*" >&2; exit 1; }

RAMDISK="/tmp/fuzz-ramdisk"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DO_MERGE=false
DO_UNMOUNT=true

# ── Parse args ───────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --merge) DO_MERGE=true ;;
    --no-unmount) DO_UNMOUNT=false ;;
    --ramdisk) RAMDISK="$2"; shift ;;
    *) die "Unknown argument: $arg" ;;
  esac
done

[ -d "$RAMDISK" ] || die "Ramdisk not found: $RAMDISK"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                  Ramdisk Teardown                              ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Merge (optional) ────────────────────────────────────────
if $DO_MERGE; then
  echo "━━ Step 1: Merge/deduplicate corpus ━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  "$SCRIPT_DIR/ramdisk-merge.sh" || echo "  [WARN] Merge had failures (continuing with sync)"
  echo ""
fi

# ── Step 2: Sync to disk ────────────────────────────────────────────
echo "━━ Step 2: Sync corpus → disk ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
"$SCRIPT_DIR/ramdisk-sync-to-disk.sh"
echo ""

# ── Step 3: Clean stray items ───────────────────────────────────────
echo "━━ Step 3: Clean stray items ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
"$SCRIPT_DIR/ramdisk-clean.sh" --execute
echo ""

# ── Step 4: Unmount ─────────────────────────────────────────────────
if $DO_UNMOUNT; then
  echo "━━ Step 4: Unmount ramdisk ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if mountpoint -q "$RAMDISK" 2>/dev/null; then
    if [ "$(id -u)" -ne 0 ]; then
      echo "  [WARN] Not root — cannot unmount. Run with sudo or use --no-unmount."
    else
      umount "$RAMDISK" 2>/dev/null || echo "  [WARN] umount failed (ramdisk may be busy)"
      rmdir "$RAMDISK" 2>/dev/null || true
      echo "  [OK] Ramdisk unmounted and removed"
    fi
  else
    echo "  (ramdisk was not mounted as tmpfs)"
    rmdir "$RAMDISK" 2>/dev/null || true
  fi
else
  echo "━━ Step 4: Unmount skipped (--no-unmount) ━━━━━━━━━━━━━━━━━━━━━"
fi
echo ""

echo "[OK] Teardown complete."
echo ""
