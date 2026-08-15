#!/bin/bash
# Validate the checked iccFromXml external-include lane and replay its profiles.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AFL_BASE="${AFL_BASE:-$REPO_ROOT/afl}"
BIN_DIR="${AFL_BIN_DIR:-$REPO_ROOT/afl/bin}"

source "$REPO_ROOT/afl/targets.sh"
source "$REPO_ROOT/afl/sanitizer-env.sh"

if ! afl_configure_target fromxml-includes; then
    echo "[FAIL] Unable to configure fromxml-includes" >&2
    exit 1
fi
if [[ ! -x "$BINARY" ]]; then
    echo "[FAIL] Binary not found: $BINARY" >&2
    exit 1
fi

afl_prepare_target_support_files fromxml-includes

manifest_list="$(mktemp)"
discovered_list="$(mktemp)"
output_dir="$(mktemp -d)"
trap 'rm -f "$manifest_list" "$discovered_list"' EXIT

awk -F'|' '$1 !~ /^#/ && NF >= 2 { print $2 }' "$FROMXML_INCLUDES_MANIFEST" | sort > "$manifest_list"
find "$FROMXML_INCLUDES_SOURCE_DIR" -type f -name '*.xml' -print0 \
    | xargs -0 grep -l 'Filename="[^"]*"' \
    | sed "s#^$FROMXML_INCLUDES_SOURCE_DIR/##" \
    | sort > "$discovered_list"

if ! cmp -s "$manifest_list" "$discovered_list"; then
    echo "[FAIL] Manifest does not match dependency-bearing XML fixtures" >&2
    diff -u "$manifest_list" "$discovered_list" >&2 || true
    exit 1
fi

profile_count=0
oversize_count=0
support_count=0
while IFS='|' read -r kind fixture detail; do
    [[ -z "$kind" || "$kind" == \#* ]] && continue
    case "$kind" in
        profile|profile-oversize|profile-oversize-optional-missing)
            profile_count=$((profile_count + 1))
            if [[ "$kind" == profile-oversize* ]]; then
                oversize_count=$((oversize_count + 1))
                if [[ "$(stat -c %s "$FROMXML_INCLUDES_SOURCE_DIR/$fixture")" -le 1048576 ]]; then
                    echo "[FAIL] Oversized fixture classification is stale: $fixture" >&2
                    exit 1
                fi
            elif [[ "$(stat -c %s "$FROMXML_INCLUDES_SOURCE_DIR/$fixture")" -gt 1048576 ]]; then
                echo "[FAIL] Promoted fixture exceeds AFL++'s 1 MiB ceiling: $fixture" >&2
                exit 1
            fi
            output="$output_dir/${profile_count}.icc"
            log="$output_dir/${profile_count}.log"
            if ! (
                cd "$AFL_WORK_DIR"
                LD_LIBRARY_PATH="$BIN_DIR" \
                ASAN_OPTIONS="$AFL_ASAN_OPTIONS_TRIAGE" \
                UBSAN_OPTIONS="$AFL_UBSAN_OPTIONS_TRIAGE" \
                timeout 30 "$BINARY" "$FROMXML_INCLUDES_SOURCE_DIR/$fixture" "$output"
            ) > "$log" 2>&1; then
                echo "[FAIL] Include-aware replay failed: $fixture" >&2
                sed -n '1,80p' "$log" >&2
                exit 1
            fi
            if [[ ! -s "$output" ]]; then
                echo "[FAIL] Include-aware replay produced no profile: $fixture" >&2
                exit 1
            fi
            ;;
        support-fragment)
            support_count=$((support_count + 1))
            ;;
        *)
            echo "[FAIL] Unknown manifest kind: $kind" >&2
            exit 1
            ;;
    esac
done < "$FROMXML_INCLUDES_MANIFEST"

if [[ "$profile_count" -ne 15 || "$oversize_count" -ne 5 || "$support_count" -ne 1 ]]; then
    echo "[FAIL] Expected 15 profiles (five oversized) and one support fragment" >&2
    echo "       Got $profile_count profiles, $oversize_count oversized, and $support_count support" >&2
    exit 1
fi
if [[ -e "$FROMXML_INCLUDES_SOURCE_DIR/CMYK-3DLUTs/BingPhongCMYK2MonoParams.txt" ]]; then
    echo "[FAIL] Optional-missing classification is stale: BingPhongCMYK2MonoParams.txt now exists" >&2
    exit 1
fi
if [[ -e "$FROMXML_INCLUDES_SUPPORT_DIR/BingPhongCMYK2MonoParams.txt" ]]; then
    echo "[FAIL] Optional-missing dependency has stale staged data" >&2
    exit 1
fi
if [[ ! -r "$FROMXML_INCLUDES_SUPPORT_DIR/calcImport.xml" || ! -r "$FROMXML_INCLUDES_SUPPORT_DIR/calcVars.xml" ]]; then
    echo "[FAIL] Transitive calculator imports were not staged" >&2
    exit 1
fi
if find "$FROMXML_INCLUDES_SUPPORT_DIR" -type f -perm /222 -print -quit | grep -q .; then
    echo "[FAIL] Staged support files must be read-only" >&2
    exit 1
fi

echo "[OK] Manifest matches 16 dependency-bearing XML fixtures"
echo "[OK] Staged read-only support tree includes transitive calculator imports"
echo "[OK] Replayed 15 standalone profiles successfully from the staged working directory"
echo "[OK] Classified five profiles above AFL++'s 1 MiB testcase ceiling as replay-only"
echo "[OK] Classified calcImport.xml as support-only and BingPhongCMYK2MonoParams.txt as optional-missing"
