#!/usr/bin/env bash
# sort-artifacts.sh - Sort loose crash/oom/timeout/slow-unit files from repo root.
#
# Usage:
#   .github/scripts/sort-artifacts.sh                # dry-run (default)
#   .github/scripts/sort-artifacts.sh --execute      # actually move files
#   .github/scripts/sort-artifacts.sh --delete-empty # also delete empty/sentinel files
#
# Sorting rules:
#   crash-* / oom-* with exact ICC profile length -> fuzz/graphics/icc/
#   crash-* / oom-* with ICC magic but extra/trailing bytes -> manual triage
#   timeout-* / slow-unit-* -> test-profiles/cwe-400/
#   Empty files, da39a3ee sentinels, core dumps, stale profraw -> delete
#
# Do not promote CFL compound fuzzer artifacts based on acsp magic alone.
# A prefix-valid ICC blob followed by control bytes or another payload is not a
# maintainer-actionable iccDEV CLI reproducer without fuzzer-aware unbundling.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

DRY_RUN=1
DELETE_EMPTY=0
for arg in "$@"; do
  case "$arg" in
    --execute) DRY_RUN=0 ;;
    --delete-empty) DELETE_EMPTY=1 ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $arg" >&2
      exit 1
      ;;
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

file_size() {
  stat -c%s "$1" 2>/dev/null || stat -f%z "$1" 2>/dev/null
}

read_be32() {
  local file="$1" offset="$2"
  od -A n -t u1 -j "$offset" -N 4 "$file" |
    awk '{printf "%d", ($1*16777216)+($2*65536)+($3*256)+$4}'
}

has_icc_magic() {
  local f="$1"
  [ -f "$f" ] && [ "$(file_size "$f")" -ge 40 ] || return 1
  [ "$(xxd -s 36 -l 4 -p "$f" 2>/dev/null)" = "61637370" ]
}

is_exact_icc_profile() {
  local f="$1"
  local actual declared

  has_icc_magic "$f" || return 1
  actual=$(file_size "$f")
  declared=$(read_be32 "$f" 0)

  [ "$declared" -eq "$actual" ]
}

describe_icc_like() {
  local f="$1"
  local actual declared

  actual=$(file_size "$f")
  declared=$(read_be32 "$f" 0)
  echo "  SKIP (ICC-like compound/trailing data; declared=$declared actual=$actual): $f"
}

# Sort crash/oom files.
for f in crash-* oom-*; do
  [ -f "$f" ] || continue

  fsize=$(file_size "$f")
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

  if is_exact_icc_profile "$f"; then
    dest="fuzz/graphics/icc/${f}.icc"
    if [ ! -f "$dest" ]; then
      action mv "$f" "$dest"
      MOVED=$((MOVED + 1))
      echo "  MOVE -> fuzz/graphics/icc/: $f"
    else
      echo "  SKIP (exists): $dest"
      SKIPPED=$((SKIPPED + 1))
    fi
  elif has_icc_magic "$f"; then
    describe_icc_like "$f"
    SKIPPED=$((SKIPPED + 1))
  else
    echo "  SKIP (non-ICC, triage manually): $f"
    SKIPPED=$((SKIPPED + 1))
  fi
done

# Sort timeout/slow-unit files.
for f in timeout-* slow-unit-*; do
  [ -f "$f" ] || continue

  fsize=$(file_size "$f")
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
    echo "  MOVE -> test-profiles/cwe-400/: $f"
  else
    echo "  SKIP (exists): $dest"
    SKIPPED=$((SKIPPED + 1))
  fi
done

# Delete stale profraw and core dumps.
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
  echo "  (dry-run - use --execute to apply)"
fi
