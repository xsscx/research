#!/bin/bash
# Validate AFL/CFL local patch stacks with git apply --check.
#
# This intentionally checks from fresh temporary clones of the nested iccDEV
# checkouts so dirty build trees and already-applied patches do not hide patch
# syntax or drift problems.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

check_stack() {
    local label="$1"
    local checkout="$2"
    local patch_dir="$3"
    local tmp
    local patch

    if [[ ! -d "$checkout/.git" ]]; then
        echo "SKIP $label: nested checkout not found: $checkout"
        return 0
    fi

    if ! compgen -G "$patch_dir/*.patch" >/dev/null; then
        echo "SKIP $label: no patches in $patch_dir"
        return 0
    fi

    tmp="$(mktemp -d "/tmp/${label}-patchcheck.XXXXXX")"
    git clone --quiet "$checkout" "$tmp"
    git -C "$tmp" reset --quiet --hard HEAD

    echo "CHECK $label patches"
    for patch in "$patch_dir"/*.patch; do
        git -C "$tmp" reset --quiet --hard HEAD
        if git -C "$tmp" apply --check "$patch" >/dev/null 2>&1; then
            echo "  OK $(basename "$patch")"
        elif git -C "$tmp" apply --reverse --check "$patch" >/dev/null 2>&1; then
            echo "  OK $(basename "$patch") already-applied"
        else
            git -C "$tmp" apply --check "$patch"
        fi
    done
}

check_stack "afl" "$REPO_ROOT/afl/iccDEV" "$REPO_ROOT/afl/patches"
check_stack "cfl" "$REPO_ROOT/cfl/iccDEV" "$REPO_ROOT/cfl/patches"
