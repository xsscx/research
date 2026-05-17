#!/usr/bin/env bash
# Manual rolling backup for upstream iccDEV refs.

set -euo pipefail

REPO_URL="${ICCDEV_BACKUP_REPO_URL:-https://github.com/InternationalColorConsortium/iccDEV.git}"
BACKUP_ROOT="${ICCDEV_BACKUP_ROOT:-$HOME/work/codex/backup}"
RETENTION_DAYS="${ICCDEV_BACKUP_RETENTION_DAYS:-30}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SKIP_PRUNE=0

usage() {
  printf '%s\n' \
    "Usage: $0 [options]" \
    "" \
    "Create a verified mirror and all-refs bundle backup of iccDEV." \
    "" \
    "Options:" \
    "  --backup-root DIR     Backup parent directory (default: $BACKUP_ROOT)" \
    "  --repo-url URL        Repository URL or local mirror path (default: $REPO_URL)" \
    "  --retention-days N    Prune timestamped backups older than N days (default: $RETENTION_DAYS)" \
    "  --timestamp TS        UTC timestamp override, format YYYYMMDDTHHMMSSZ" \
    "  --skip-prune          Do not prune old backups after creating this backup" \
    "  -h, --help            Show this help"
}

fail() {
  printf '[FAIL] %s\n' "$*" >&2
  exit 1
}

is_uint() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --backup-root)
      [ "$#" -ge 2 ] || fail "--backup-root requires a value"
      BACKUP_ROOT="$2"
      shift 2
      ;;
    --repo-url)
      [ "$#" -ge 2 ] || fail "--repo-url requires a value"
      REPO_URL="$2"
      shift 2
      ;;
    --retention-days)
      [ "$#" -ge 2 ] || fail "--retention-days requires a value"
      RETENTION_DAYS="$2"
      shift 2
      ;;
    --timestamp)
      [ "$#" -ge 2 ] || fail "--timestamp requires a value"
      TIMESTAMP="$2"
      shift 2
      ;;
    --skip-prune)
      SKIP_PRUNE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown option: $1"
      ;;
  esac
done

is_uint "$RETENTION_DAYS" || fail "--retention-days must be a non-negative integer"

case "$TIMESTAMP" in
  20??????T??????Z) ;;
  *) fail "--timestamp must match YYYYMMDDTHHMMSSZ" ;;
esac

[ -n "$BACKUP_ROOT" ] || fail "backup root must not be empty"
[ "$BACKUP_ROOT" != "/" ] || fail "backup root must not be /"

mkdir -p "$BACKUP_ROOT"
BACKUP_ROOT="$(cd "$BACKUP_ROOT" && pwd)"

BACKUP_DIR="$BACKUP_ROOT/$TIMESTAMP"
WORK_DIR="$BACKUP_ROOT/.${TIMESTAMP}.tmp.$$"
MIRROR_DIR="$WORK_DIR/iccDEV.git"
BUNDLE_FILE="$WORK_DIR/iccDEV-${TIMESTAMP}-all-refs.bundle"
COMPLETED=0

cleanup() {
  if [ "$COMPLETED" -eq 0 ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

[ ! -e "$BACKUP_DIR" ] || fail "backup already exists: $BACKUP_DIR"
[ ! -e "$WORK_DIR" ] || fail "temporary backup path already exists: $WORK_DIR"

printf '[INFO] Repository: %s\n' "$REPO_URL"
printf '[INFO] Backup root: %s\n' "$BACKUP_ROOT"
printf '[INFO] Backup timestamp: %s\n' "$TIMESTAMP"

mkdir -p "$WORK_DIR"

printf '[INFO] Cloning mirror...\n'
git clone --mirror "$REPO_URL" "$MIRROR_DIR"

printf '[INFO] Fetching all refs...\n'
git -C "$MIRROR_DIR" fetch --prune origin '+refs/*:refs/*'

LFS_DETECTED="no"
mapfile -t REFS_TO_SCAN < <(git -C "$MIRROR_DIR" for-each-ref --format='%(refname)')
if [ "${#REFS_TO_SCAN[@]}" -gt 0 ] \
  && git -C "$MIRROR_DIR" grep -I -q 'filter=lfs' "${REFS_TO_SCAN[@]}" -- .gitattributes 2>/dev/null; then
  LFS_DETECTED="yes"
  if git lfs version >/dev/null 2>&1; then
    printf '[INFO] Git LFS filters detected; fetching LFS objects...\n'
    git -C "$MIRROR_DIR" lfs fetch --all origin
  else
    printf '[WARN] Git LFS filters detected, but git-lfs is not installed; LFS objects were not fetched.\n' >&2
  fi
fi

printf '[INFO] Writing ref inventories...\n'
git -C "$MIRROR_DIR" for-each-ref --sort=refname --format='%(objectname) %(refname)' \
  > "$WORK_DIR/all-refs.txt"
git -C "$MIRROR_DIR" for-each-ref --sort=refname --format='%(objectname) %(refname)' \
  refs/heads refs/tags > "$WORK_DIR/refs-heads-tags.txt"

printf '[INFO] Verifying mirror object graph...\n'
git -C "$MIRROR_DIR" fsck --full --strict

printf '[INFO] Creating all-refs bundle...\n'
git -C "$MIRROR_DIR" bundle create "$BUNDLE_FILE" --all

printf '[INFO] Verifying bundle...\n'
if git bundle verify "$BUNDLE_FILE" > "$WORK_DIR/bundle-verify.txt" 2>&1; then
  sed -n '1p;/complete history/p' "$WORK_DIR/bundle-verify.txt"
else
  cat "$WORK_DIR/bundle-verify.txt" >&2
  exit 1
fi

BRANCH_HEADS="$(git -C "$MIRROR_DIR" for-each-ref --count=0 --format='%(refname)' refs/heads | wc -l | tr -d ' ')"
TAGS="$(git -C "$MIRROR_DIR" for-each-ref --count=0 --format='%(refname)' refs/tags | wc -l | tr -d ' ')"
PULL_REFS="$(git -C "$MIRROR_DIR" for-each-ref --count=0 --format='%(refname)' refs/pull | wc -l | tr -d ' ')"
TOTAL_REFS="$(git -C "$MIRROR_DIR" for-each-ref --count=0 --format='%(refname)' | wc -l | tr -d ' ')"
HEAD_REF="$(git -C "$MIRROR_DIR" symbolic-ref -q HEAD || printf 'detached')"
HEAD_SHA="$(git -C "$MIRROR_DIR" rev-parse HEAD)"
TOTAL_SIZE="$(du -sh "$WORK_DIR" | awk '{print $1}')"

printf '[INFO] Writing manifest and checksums...\n'
{
  printf 'backup_timestamp=%s\n' "$TIMESTAMP"
  printf 'backup_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'repo_url=%s\n' "$REPO_URL"
  printf 'backup_root=%s\n' "$BACKUP_ROOT"
  printf 'mirror_dir=%s\n' "$BACKUP_DIR/iccDEV.git"
  printf 'bundle_file=%s\n' "$BACKUP_DIR/iccDEV-${TIMESTAMP}-all-refs.bundle"
  printf 'branch_heads=%s\n' "$BRANCH_HEADS"
  printf 'tags=%s\n' "$TAGS"
  printf 'pull_refs=%s\n' "$PULL_REFS"
  printf 'total_refs=%s\n' "$TOTAL_REFS"
  printf 'head_ref=%s\n' "$HEAD_REF"
  printf 'head_sha=%s\n' "$HEAD_SHA"
  printf 'git_lfs_filters_detected=%s\n' "$LFS_DETECTED"
  printf 'total_size=%s\n' "$TOTAL_SIZE"
  printf '\n'
  printf 'restore_mirror=git clone %s iccDEV\n' "$BACKUP_DIR/iccDEV.git"
  printf 'restore_bundle=git clone %s iccDEV\n' "$BACKUP_DIR/iccDEV-${TIMESTAMP}-all-refs.bundle"
  printf 'verify_bundle=git bundle verify %s\n' "$BACKUP_DIR/iccDEV-${TIMESTAMP}-all-refs.bundle"
} > "$WORK_DIR/MANIFEST.txt"

(
  cd "$WORK_DIR"
  sha256sum \
    "iccDEV-${TIMESTAMP}-all-refs.bundle" \
    all-refs.txt \
    bundle-verify.txt \
    refs-heads-tags.txt \
    MANIFEST.txt > SHA256SUMS
  sha256sum -c SHA256SUMS
)

mv "$WORK_DIR" "$BACKUP_DIR"
COMPLETED=1

prune_old_backups() {
  local pruned=0
  local candidate
  local name

  [ "$SKIP_PRUNE" -eq 0 ] || return 0

  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    name="$(basename "$candidate")"
    [ "$name" != "$TIMESTAMP" ] || continue

    case "$name" in
      20??????T??????Z) ;;
      *) continue ;;
    esac

    if [ -f "$candidate/MANIFEST.txt" ] && [ -d "$candidate/iccDEV.git" ]; then
      printf '[INFO] Pruning expired backup: %s\n' "$candidate"
      rm -rf "$candidate"
      pruned=$((pruned + 1))
    fi
  done < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -name '20??????T??????Z' -mtime +"$RETENTION_DAYS" -print)

  printf '[INFO] Pruned expired backups: %s\n' "$pruned"
}

prune_old_backups

printf '[OK] Backup complete: %s\n' "$BACKUP_DIR"
