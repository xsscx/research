#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <repo> <workflow-file> <branch> <artifact-name>" >&2
    exit 1
fi

repo=$1
workflow_file=$2
branch=$3
artifact_name=$4

if ! command -v gh >/dev/null 2>&1; then
    exit 0
fi

gh_api_with_retries() {
    local attempt

    for attempt in 1 2 3; do
        if gh api "$@"; then
            return 0
        fi

        if [[ ${attempt} -lt 3 ]]; then
            sleep $((attempt * 2))
        fi
    done

    return 1
}

run_ids=$(
    gh_api_with_retries "repos/${repo}/actions/workflows/${workflow_file}/runs?branch=${branch}&status=completed&per_page=100" \
        --jq '.workflow_runs[] | select(.conclusion == "success") | .id' 2>/dev/null || true
)

while IFS= read -r run_id; do
    [[ -z "${run_id}" ]] && continue

    if gh_api_with_retries "repos/${repo}/actions/runs/${run_id}/artifacts?per_page=100" \
        --jq '.artifacts[].name' 2>/dev/null | grep -Fxq "${artifact_name}"; then
        printf '%s\n' "${run_id}"
        exit 0
    fi
done <<< "${run_ids}"
