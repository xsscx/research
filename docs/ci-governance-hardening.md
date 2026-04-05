# CI Workflow Governance Hardening

## Automated Scanner

`ci-pr-risk-security-analysis.yml` runs 10 governance checks across all workflows:

| # | Check | What It Catches |
|---|-------|-----------------|
| 1 | **SHA Pinning** | Actions using tags/branches instead of SHA commits |
| 2 | **Dangerous Triggers** | `pull_request_target` with write access |
| 3 | **Credential Hygiene** | Missing `unset GITHUB_TOKEN` or `credential.helper ""` |
| 4 | **Shell Hardening** | Missing `set -euo pipefail` (bash) or `$ErrorActionPreference` (PowerShell) |
| 5 | **Matrix Injection** | `${{ matrix.* }}` or `${{ github.event.* }}` directly in `run:` blocks |
| 6 | **Output Sanitization** | Raw writes to `GITHUB_STEP_SUMMARY` without `sanitize_line()` |
| 7 | **Permissions** | Missing or overly-broad `permissions:` blocks |
| 8 | **Supply-Chain Score** | Composite risk score (0-100+) based on findings |
| 9 | **Trivy Indicators** | Unpinned or misconfigured Trivy container scanners |
| 10 | **Workflow Inventory** | Lists all workflows with trigger types for review |

Check 6 uses a 4-tier whitelist to reduce false positives:
1. Explicit sanitizer function calls (`sanitize_line`, `Sanitize-Line`, etc.)
2. Pre-sanitized variable naming (`$SANITIZED_*`, `$safe_*`, `$SAFE_*`)
3. Tool output / system info commands (`$(nproc)`, `$(uname)`, `$(tool --version)`)
4. Env-block intermediary variables (`$MATRIX_*`, `$CC`, `$BUILD_*`)

## Four Security Pillars

Every GitHub Actions `run:` step must implement:

1. **Shell Isolation** -- `bash --noprofile --norc {0}` + `BASH_ENV: /dev/null`
2. **Credential Reduction** -- `git config --global credential.helper ""` + `unset GITHUB_TOKEN`
3. **Strict Error Handling** -- `set -euo pipefail`
4. **Output Sanitization** -- `sanitize_line()` for all `GITHUB_STEP_SUMMARY` writes

## Sanitizer Scripts

| Script | Language | Location |
|--------|----------|----------|
| `sanitize-sed.sh` | Bash (V3, 279 lines) | `.github/scripts/sanitize-sed.sh` |
| `sanitize.ps1` | PowerShell (V1, ~310 lines) | `.github/scripts/sanitize.ps1` |

## Key Patterns

### SIGPIPE Avoidance
Never use `echo "$var" | grep -q` under `set -o pipefail` -- use `grep -q <<< "$var"`.

### Expression Injection Prevention
Never put `${{ matrix.* }}` or `${{ github.event.* }}` in `run:` blocks -- use `env:`.

## Origin

Based on [xsscx/governance](https://github.com/xsscx/governance) standards.
Hardened through WASM CI workflow remediation (March 2026, `ci-workflow-updates` branch)
and iccDEV onboarding audit (June 2026, `ci-governance-audit` branch).

## See Also

- [`workflow-governance.instructions.md`](../.github/instructions/workflow-governance.instructions.md) -- Developer rules (auto-loaded)
- [`workflow-governance.prompt.md`](../.github/prompts/workflow-governance.prompt.md) -- AI audit prompt
- `ci-pr-action.yml` -- Reference compliant workflow (bash)
- `ci-pr-win.yml` -- Reference compliant workflow (PowerShell)
