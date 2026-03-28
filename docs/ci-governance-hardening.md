# CI Workflow Governance Hardening

> **This document has been consolidated.** The canonical workflow governance reference
> is split between two files:
>
> - **Developer rules** (auto-loaded for `.github/workflows/**`):
>   [`.github/instructions/workflow-governance.instructions.md`](../.github/instructions/workflow-governance.instructions.md)
> - **AI audit workflow**:
>   [`.github/prompts/workflow-governance.prompt.md`](../.github/prompts/workflow-governance.prompt.md)

## Quick Reference

The four security pillars for every GitHub Actions workflow step:

1. **Shell Isolation** — `bash --noprofile --norc {0}` + `BASH_ENV: /dev/null`
2. **Credential Reduction** — `git config --global credential.helper ""` + `unset GITHUB_TOKEN`
3. **Strict Error Handling** — `set -euo pipefail`
4. **Output Sanitization** — `sanitize_line()` for all `GITHUB_STEP_SUMMARY` writes

## Sanitizer Scripts

| Script | Language | Location |
|--------|----------|----------|
| `sanitize-sed.sh` | Bash (V3, 279 lines) | `.github/scripts/sanitize-sed.sh` |
| `sanitize.ps1` | PowerShell (V1, ~310 lines) | `.github/scripts/sanitize.ps1` |

## Origin

Based on [xsscx/governance](https://github.com/xsscx/governance) standards.
Hardened through WASM CI workflow remediation (March 2026, `ci-workflow-updates` branch).

## See Also

- `ci-pr-action.yml` — Reference compliant workflow (bash)
- `ci-pr-win.yml` — Reference compliant workflow (PowerShell)
