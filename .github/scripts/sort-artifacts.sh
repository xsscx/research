#!/usr/bin/env bash
# sort-artifacts.sh — Sort crash/oom/timeout/slow-unit files from repo root
# into their proper directories. ONE script, ONE commit.
#
# Usage:
#   .github/scripts/sort-artifacts.sh              # dry-run (default)
#   .github/scripts/sort-artifacts.sh --execute     # actually move files
#   .github/scripts/sort-artifacts.sh --delete-empty # also delete empty/sentinel files
#
# Sorting rules:
#   crash-* / oom-* with ICC magic (acsp at byte 36) → fuzz/graphics/icc/
#   timeout-* / slow-unit-*                          → test-profiles/cwe-400/
#   Empty files (0 bytes) or da39a3ee sentinels      → delete
#   Core dumps, stale profraw                        → delete
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

DRY_RUN=1
DELETE_EMPTY=0
for arg in "$@"; do
  case "$arg" in
    --execute) DRY_RUN=0 ;;
    --delete-empty) DELETE_EMPTY=1 ;;
  esac
done

MOVED=0
DELETED=0
SKIPPED=0

action() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRY-RUN] $*"
  else
    "$@"
  fi
}

# Check if file has ICC magic (acsp at offset 36)
has_icc_magic() {
  local f="$1"
  [ -f "$f" ] && [ "$(stat -c%s "$f" 2>/dev/null || echo 0)" -ge 40 ] || return 1
  local magic
  magic=$(xxd -s 36 -l 4 -p "$f" 2>/dev/null)
  [ "$magic" = "61637370" ]
}

# Sort crash/oom files
for f in crash-* oom-*; do
  [ -f "$f" ] || continue

  # Delete empty files and da39a3ee sentinels (empty SHA1)
  fsize=$(stat -c%s "$f" 2>/dev/null || echo 0)
  if [ "$fsize" -eq 0 ] || echo "$f" | grep -q 'da39a3ee'; then
    if [ "$DELETE_EMPTY" -eq 1 ]; then
      action rm "$f"
      DELETED=$((DELETED + 1))
      echo "  DELETE (empty/sentinel): $f"
    else
      echo "  SKIP (empty, use --delete-empty): $f"
      SKIPPED=$((SKIPPED + 1))
    fi
    continue
  fi

  # ICC profiles → fuzz/graphics/icc/
  if has_icc_magic "$f"; then
    dest="fuzz/graphics/icc/${f}.icc"
    if [ ! -f "$dest" ]; then
      action mv "$f" "$dest"
      MOVED=$((MOVED + 1))
      echo "  MOVE → fuzz/graphics/icc/: $f"
    else
      echo "  SKIP (exists): $dest"
      SKIPPED=$((SKIPPED + 1))
    fi
  else
    # Non-ICC crash/oom — keep in root for manual triage
    echo "  SKIP (non-ICC, triage manually): $f"
    SKIPPED=$((SKIPPED + 1))
  fi
done

# Sort timeout/slow-unit files
for f in timeout-* slow-unit-*; do
  [ -f "$f" ] || continue

  fsize=$(stat -c%s "$f" 2>/dev/null || echo 0)
  if [ "$fsize" -eq 0 ]; then
    if [ "$DELETE_EMPTY" -eq 1 ]; then
      action rm "$f"
      DELETED=$((DELETED + 1))
      echo "  DELETE (empty): $f"
    else
      echo "  SKIP (empty, use --delete-empty): $f"
      SKIPPED=$((SKIPPED + 1))
    fi
    continue
  fi

  dest="test-profiles/cwe-400/$f"
  if [ ! -f "$dest" ]; then
    action mv "$f" "$dest"
    MOVED=$((MOVED + 1))
    echo "  MOVE → test-profiles/cwe-400/: $f"
  else
    echo "  SKIP (exists): $dest"
    SKIPPED=$((SKIPPED + 1))
  fi
done

# Delete stale profraw and core dumps
for f in default.profraw core core.*; do
  [ -f "$f" ] || continue
  action rm "$f"
  DELETED=$((DELETED + 1))
  echo "  DELETE (stale): $f"
done

echo ""
echo "--- Summary ---"
echo "  Moved:   $MOVED"
echo "  Deleted: $DELETED"
echo "  Skipped: $SKIPPED"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "  (dry-run — use --execute to apply)"
fi
