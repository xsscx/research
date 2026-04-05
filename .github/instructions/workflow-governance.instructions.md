---
applyTo: ".github/workflows/**"
---

# GitHub Actions Workflow — Governance Instructions

## What This Is

Security governance rules for ALL GitHub Actions workflow files in this repository.
Based on [xsscx/governance/actions](https://github.com/xsscx/governance/tree/main/actions)
and hardened through real CI failures documented in the WASM workflow remediation
(March 2026, ci-workflow-updates branch).

## Mandatory Shell Hardening — Every Step

Every `run:` step using bash MUST include:

```yaml
- name: Any Step
  env:
    BASH_ENV: /dev/null
  run: |
    set -euo pipefail
    git config --global credential.helper ""
    unset GITHUB_TOKEN || true
```

Or set `defaults.run.shell` at job level:
```yaml
jobs:
  build:
    defaults:
      run:
        shell: bash --noprofile --norc {0}
```

**Note**: `defaults.run.env` does NOT exist in GitHub Actions — `env:` must be
set per-step or at job level.

## Sanitize Every Write — MANDATORY

**Rule**: Every write to `GITHUB_STEP_SUMMARY`, artifact names, or user-visible
output MUST pass through sanitizer functions.

### Load sanitizer with inline fallback

```bash
SANITIZER="$GITHUB_WORKSPACE/.github/scripts/sanitize-sed.sh"
if [[ -f "$SANITIZER" ]]; then
  # shellcheck disable=SC1090
  source "$SANITIZER"
else
  escape_html() {
    local s="$1"
    s="${s//&/&amp;}" ; s="${s//</&lt;}" ; s="${s//>/&gt;}"
    s="${s//\"/&quot;}" ; s="${s//\'/&#39;}"
    printf '%s' "$s"
  }
  sanitize_line() { escape_html "$1"; }
fi
```

### Multiline output — iterate line-by-line

```bash
# WRONG — collapses to 1 line
sanitize_line "$MULTILINE_VAR"

# CORRECT — 1 file per line
find . -name '*.wasm' -exec ls -lh {} \; | while IFS= read -r line; do
  sanitize_line "$line"
  echo ""
done
```

**Root cause**: `sanitize_line()` uses `printf '%s'` (no newline). A multiline
argument is printed as a single blob. The `while read` pattern processes each
line individually.

## Matrix Expression Safety — CRITICAL

**NEVER** put `${{ matrix.* }}` directly in `run:` blocks.

```yaml
# WRONG — injectable
run: cmake -DCMAKE_BUILD_TYPE=${{ matrix.build_type }} ..

# CORRECT — safe via env
env:
  MATRIX_BUILD_TYPE: ${{ matrix.build_type }}
run: cmake -DCMAKE_BUILD_TYPE="${MATRIX_BUILD_TYPE}" ..
```

## GitHub Actions Expression Parsing Gotcha

`${{ }}` with empty braces causes a parse error even inside bash comments
in `run:` blocks. GitHub Actions evaluates ALL expression patterns in YAML
string values before bash sees them.

```yaml
# WRONG — parse error
run: |
  # Never use ${{ }} directly

# CORRECT — avoid the pattern in text
run: |
  # Never use direct expression interpolation
```

## Credential Reduction

Every step that runs bash MUST:
1. `git config --global credential.helper ""` — prevent token caching
2. `unset GITHUB_TOKEN || true` — remove token from child process environment
3. Use `env: BASH_ENV: /dev/null` — block startup file injection

## Audit Findings Reference

Findings from the WASM workflow governance audit (March 2026):

| # | Finding | Severity | Fix |
|---|---------|----------|-----|
| 1 | Missing `BASH_ENV: /dev/null` on 6 steps | CRITICAL | Add to every step |
| 2 | `${{ matrix.build_type }}` in `run:` block | CRITICAL | Move to `env:` block |
| 3 | `${{ }}` (empty) in bash comment | CRITICAL | Rephrase comment text |
| 4 | Missing credential cleanup | HIGH | Add `credential.helper ""` + `unset` |
| 5 | Missing `set -euo pipefail` | HIGH | Add to every `run:` block |
| 6 | Unsanitized GITHUB_STEP_SUMMARY writes | HIGH | Use `sanitize_line()` |
| 7 | `sanitize_line "$MULTILINE"` → 1 line | MEDIUM | Use `while read` per-line |
| 8 | `echo "$var" \| grep -q` SIGPIPE under pipefail | HIGH | Use `grep -q "pat" <<< "$var"` or `grep -q "pat" file` |
| 9 | `${{ github.event.inputs.* }}` in `run:` blocks | CRITICAL | Move to `env:` block, use `$ENV_VAR` |

## SIGPIPE / Broken Pipe Avoidance — MANDATORY

**Rule**: NEVER use `echo "$variable" | grep -q "pattern"` in any `run:` block
that has `set -o pipefail` (which is ALL steps per our governance).

**Root cause**: When `grep -q` finds a match, it immediately exits and closes
stdin. If the variable is large, `echo` gets SIGPIPE trying to write remaining
data to the closed pipe. Under `pipefail`, the non-zero exit from `echo`
propagates as pipeline failure.

**Three safe alternatives** (in preference order):

```bash
# 1. BEST — here-string (no pipe, no subshell)
if grep -qE 'pattern' <<< "$variable"; then ...

# 2. GOOD — grep reads file directly (for file content checks)
if grep -q 'pattern' "$filepath"; then ...

# 3. OK — bash pattern matching (no external command)
if [[ "$variable" =~ pattern ]]; then ...
```

**WRONG** (causes SIGPIPE under pipefail):
```bash
# WRONG — broken pipe when $variable is large
if echo "$variable" | grep -q 'pattern'; then ...
# WRONG — same issue with printf
if printf '%s' "$variable" | grep -q 'pattern'; then ...
```

This bug appeared in 3 separate workflow steps across 3 fix cycles (March 2026).
Always use here-strings or direct file grep.

## Script Injection Prevention — MANDATORY

**Rule**: NEVER place `${{ github.event.inputs.* }}`, `${{ github.head_ref }}`,
`${{ github.event.pull_request.title }}`, `${{ github.event.issue.body }}`,
or any other user-controlled expression directly in `run:` blocks.

```yaml
# WRONG — injectable via crafted input value
run: echo "Building ref ${{ github.event.inputs.ref }}"

# CORRECT — safe via env intermediary
env:
  TARGET_REF: ${{ github.event.inputs.ref }}
run: echo "Building ref ${TARGET_REF}"
```

Expressions in `name:`, `with:`, `key:`, and `if:` fields are evaluated by the
GitHub Actions YAML parser (not shell), so they are safe from shell injection.
However, governance rules still prefer env intermediaries for consistency.

Reference: https://docs.github.com/en/actions/reference/security/secure-use

## sanitize-sed.sh — Source of Truth

Location: `.github/scripts/sanitize-sed.sh` (V3, 279 lines)

Key functions:
- `escape_html "$str"` — HTML entity encode `& < > " '`
- `sanitize_line "$str"` — escape + strip control chars (single-line)
- `sanitize_print "$str"` — sanitize + newline
- `sanitize_ref "$ref"` — sanitize git ref names
- `sanitize_filename "$name"` — sanitize file paths

## Complete Compliant Step Template

```yaml
- name: Build and Report
  env:
    BASH_ENV: /dev/null
    MATRIX_BUILD_TYPE: ${{ matrix.build_type }}
  run: |
    set -euo pipefail
    git config --global credential.helper ""
    unset GITHUB_TOKEN || true

    SANITIZER="$GITHUB_WORKSPACE/.github/scripts/sanitize-sed.sh"
    if [[ -f "$SANITIZER" ]]; then source "$SANITIZER"
    else
      escape_html() { local s="$1"; s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; s="${s//\"/&quot;}"; s="${s//\'/&#39;}"; printf '%s' "$s"; }
      sanitize_line() { escape_html "$1"; }
    fi

    # ... build steps ...

    {
      echo "### Build: $(sanitize_line "${MATRIX_BUILD_TYPE}")"
      echo '```'
      find . -name '*.wasm' -exec ls -lh {} \; | while IFS= read -r line; do
        sanitize_line "$line"
        echo ""
      done
      echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
```

## PowerShell Steps — Same Four Pillars

Windows workflow steps use PowerShell with parallel governance requirements.
The PowerShell sanitizer lives at `.github/scripts/sanitize.ps1`.

### PowerShell Step Template

```yaml
- name: Build (Windows)
  shell: pwsh -NoProfile -NoLogo -NonInteractive -Command {0}
  env:
    POWERSHELL_TELEMETRY_OPTOUT: 1
    POWERSHELL_UPDATECHECK: Off
    GH_REPOSITORY: ${{ github.repository }}
  run: |
    $ErrorActionPreference = 'Stop'
    $PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
    git config --global credential.helper ""
    if (Test-Path env:GITHUB_TOKEN) { Remove-Item env:GITHUB_TOKEN }

    . .github/scripts/sanitize.ps1

    # ... build steps ...

    "Repository: $(Sanitize-Line $env:GH_REPOSITORY)" |
      Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
```

### PowerShell Sanitizer Functions (sanitize.ps1)

| Function | Purpose | Bash Equivalent |
|----------|---------|-----------------|
| `Escape-Html $str` | HTML entity encode | `escape_html "$str"` |
| `Sanitize-Line $str` | Single-line sanitize | `sanitize_line "$str"` |
| `Sanitize-Print $str` | Multi-line sanitize (keeps LF) | `sanitize_print "$str"` |
| `Sanitize-Ref $ref` | Safe ref name | `sanitize_ref "$ref"` |
| `Sanitize-Filename $name` | Safe filename | `sanitize_filename "$name"` |
| `Safe-EchoForSummary $str` | Sanitize + Write-Output | N/A |

### Multiline Output (PowerShell)

```powershell
# Per-file listing (1 line each)
Get-ChildItem -Recurse -Filter "*.wasm" | ForEach-Object {
    "$(Sanitize-Line $_.FullName)  ($($_.Length) bytes)" |
      Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
}
```

### Bash vs PowerShell Quick Reference

| Control | Bash | PowerShell |
|---------|------|------------|
| Shell flags | `bash --noprofile --norc {0}` | `pwsh -NoProfile -NoLogo -NonInteractive -Command {0}` |
| Env lockdown | `BASH_ENV: /dev/null` | `POWERSHELL_TELEMETRY_OPTOUT: 1` |
| Error mode | `set -euo pipefail` | `$ErrorActionPreference = 'Stop'` |
| Token cleanup | `unset GITHUB_TOKEN \|\| true` | `Remove-Item env:GITHUB_TOKEN` |
| Load sanitizer | `source sanitize-sed.sh` | `. sanitize.ps1` |
| Summary write | `echo "$(sanitize_line "$v")" >> "$GITHUB_STEP_SUMMARY"` | `"$(Sanitize-Line $v)" \| Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append` |

## See Also

- `.github/prompts/workflow-governance.prompt.md` — Full audit workflow prompt
- [xsscx/governance/actions](https://github.com/xsscx/governance/tree/main/actions) — Upstream standards
- `ci-pr-action.yml` — Reference compliant workflow (bash)
- `ci-pr-win.yml` — Reference compliant workflow (PowerShell)
- `.github/scripts/sanitize-sed.sh` — V3 bash sanitizer (279 lines)
- `.github/scripts/sanitize.ps1` — V1 PowerShell sanitizer (~310 lines)
