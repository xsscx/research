#!/usr/bin/env bash
# Validate the checked-in iccApplyProfiles QA contracts without a long run.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
sanitizer="$repo_root/.github/ci/quality-assurance/scripts/iccApplyProfiles_sanitizer_qa.sh"
valgrind="$repo_root/.github/ci/quality-assurance/scripts/iccApplyProfiles_valgrind_qa.sh"
errors=0

fail() {
    echo "ERROR: $*" >&2
    errors=$((errors + 1))
}

for script in "$sanitizer" "$valgrind"; do
    [[ -f "$script" ]] || { fail "missing QA script: $script"; continue; }
    bash -n "$script" || fail "invalid Bash syntax: $script"
    bash "$script" --help >/dev/null || fail "--help failed: $script"
    file "$script" | grep -q 'ASCII text' || fail "script is not ASCII: $script"
done

grep -Fq '45bb74bd3a6591e6853b704c390ab6156c0a3c88' \
    "$repo_root/afl/build-afl-runtime.sh" || fail "AFL++ stable pin is stale"
grep -Fq "JOBS=\"\${JOBS:-32}\"" "$repo_root/afl/build-afl-runtime.sh" || \
    fail "AFL++ runtime builder does not default to -j32"
if rg -n '05507e1880dc6df997c19e01423444ef37c36846' \
    "$repo_root/AGENTS.md" "$repo_root/afl" "$repo_root/docs/afl" \
    "$repo_root/.github" --glob '!**/validate-iccapplyprofiles-qa.sh' >/dev/null; then
    fail "stale AFL++ runtime pin remains in active guidance"
fi

for reference in \
    .github/skills/icc-tool-qa/SKILL.md \
    .github/prompts/iccapplyprofiles-qa.prompt.md \
    .github/agents/icc-tool-qa.agent.md \
    docs/afl/iccapplyprofiles-qa.md; do
    [[ -f "$repo_root/$reference" ]] || fail "missing QA guidance: $reference"
done

if [[ "$errors" -ne 0 ]]; then
    echo "iccApplyProfiles QA validation failed with $errors error(s)." >&2
    exit 1
fi
echo "iccApplyProfiles QA contracts passed."
