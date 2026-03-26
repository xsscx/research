# Workflow Governance Compliance — Prompt

> **Task**: Harden GitHub Actions workflows to comply with xsscx/governance security standards.
> **Reference**: https://github.com/xsscx/governance/tree/main/actions
> **Reference workflow**: `ci-pr-action.yml` in iccDEV repo

## When to Use This Prompt

- Creating or modifying any GitHub Actions workflow (`.github/workflows/*.yml`)
- Reviewing existing workflows for governance compliance
- Adding GITHUB_STEP_SUMMARY output to any workflow step
- Fixing CI failures related to shell hardening or credential leakage

## Mandatory Requirements — Every Bash Step

Every `run:` block using bash MUST include ALL of the following:

### 1. Shell Specification (job-level or step-level)

```yaml
defaults:
  run:
    shell: bash --noprofile --norc {0}
```

Or per-step:
```yaml
- name: My Step
  shell: bash --noprofile --norc {0}
```

**Why**: `--noprofile --norc` prevents user/system bashrc from injecting
attacker-controlled environment variables or aliases. `{0}` is GitHub Actions'
placeholder for the script file path.

### 2. Environment Lockdown

```yaml
env:
  BASH_ENV: /dev/null
```

**Why**: `BASH_ENV` specifies a file bash sources before executing commands.
Setting to `/dev/null` prevents injection via this variable.

### 3. Strict Mode + Credential Cleanup

```bash
set -euo pipefail
git config --global credential.helper ""
unset GITHUB_TOKEN || true
```

**Why**:
- `set -euo pipefail` — fail on errors, undefined vars, pipe failures
- Credential helper reset — prevents Git from caching tokens in child processes
- `unset GITHUB_TOKEN` — removes the token from environment; `|| true` because
  some runners don't set it

### 4. Load Sanitizer for Any Output

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

**Why**: Every write to `GITHUB_STEP_SUMMARY`, artifact names, log output,
or any user-visible string MUST be sanitized through `escape_html()` or
`sanitize_line()` to prevent HTML/script injection in the Actions UI.

## Sanitize Every Write — No Exceptions

### Rule: NEVER write unsanitized content to GITHUB_STEP_SUMMARY

```bash
# WRONG — direct variable interpolation
echo "Build: $BUILD_TYPE" >> "$GITHUB_STEP_SUMMARY"

# CORRECT — sanitize every variable
echo "Build: $(sanitize_line "$BUILD_TYPE")" >> "$GITHUB_STEP_SUMMARY"
```

### Rule: Multiline output must iterate line-by-line

```bash
# WRONG — sanitize_line collapses multiline to 1 line
JS_LISTING=$(find . -name '*.js' -exec ls -lh {} \;)
sanitize_line "$JS_LISTING"

# CORRECT — iterate per line for 1-file-per-line rendering
find . -name '*.js' -exec ls -lh {} \; | while IFS= read -r line; do
  sanitize_line "$line"
  echo ""
done
```

**Why**: `sanitize_line()` uses `printf '%s'` (no trailing newline). When
given a multiline argument, the entire content renders as one blob line.
The `while read` pattern sanitizes each line individually and adds newlines.

### Rule: Matrix expressions NEVER in run: blocks directly

```yaml
# WRONG — allows injection via matrix value
run: |
  cmake -DCMAKE_BUILD_TYPE=${{ matrix.build_type }} ..

# CORRECT — pass through env: block
env:
  MATRIX_BUILD_TYPE: ${{ matrix.build_type }}
run: |
  cmake -DCMAKE_BUILD_TYPE="${MATRIX_BUILD_TYPE}" ..
```

**Why**: `${{ }}` expressions in `run:` blocks are string-interpolated before
bash executes. A malicious PR title/branch name/matrix value could inject
arbitrary shell commands. The `env:` block safely passes the value as an
environment variable.

## GitHub Actions Expression Gotcha

**CRITICAL**: `${{ }}` with empty braces is a parse error, even inside bash
comments within `run:` blocks. GitHub Actions evaluates ALL `${{ }}` patterns
in the YAML string value, including inside `# comments`.

```yaml
# WRONG — parse error at the empty expression
run: |
  # Never use direct ${{ }} interpolation
  echo "safe"

# CORRECT — rephrase to avoid the pattern
run: |
  # Never use direct expression interpolation
  echo "safe"
```

## Complete Step Template

```yaml
- name: My Governance-Compliant Step
  env:
    BASH_ENV: /dev/null
  run: |
    set -euo pipefail
    git config --global credential.helper ""
    unset GITHUB_TOKEN || true

    # Load sanitizer
    SANITIZER="$GITHUB_WORKSPACE/.github/scripts/sanitize-sed.sh"
    if [[ -f "$SANITIZER" ]]; then
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

    # ... actual work ...

    # Write sanitized summary
    {
      echo "### Results"
      echo '```'
      some_command | while IFS= read -r line; do
        sanitize_line "$line"
        echo ""
      done
      echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
```

## Audit Checklist

Run this against every workflow file before pushing:

| # | Check | Severity | Pattern to Find |
|---|-------|----------|-----------------|
| 1 | Shell hardening | CRITICAL | Missing `bash --noprofile --norc {0}` |
| 2 | BASH_ENV lockdown | CRITICAL | Missing `BASH_ENV: /dev/null` |
| 3 | Credential cleanup | HIGH | Missing `credential.helper ""` or `unset GITHUB_TOKEN` |
| 4 | Strict mode | HIGH | Missing `set -euo pipefail` |
| 5 | Direct matrix interpolation | CRITICAL | `${{ matrix.*` inside `run:` block |
| 6 | Unsanitized summary write | HIGH | `>> "$GITHUB_STEP_SUMMARY"` without `sanitize_line` |
| 7 | Empty expression | CRITICAL | `${{ }}` (empty) anywhere in YAML |
| 8 | Multiline sanitize | MEDIUM | `sanitize_line "$MULTILINE_VAR"` (collapses to 1 line) |

## Anti-Patterns Learned

### 1. Empty `${{ }}` in bash comments
GitHub Actions evaluates expressions in ALL string values including `run:` blocks.
Even `# Never use ${{ }}` causes a parse error. Rephrase comments to avoid.

### 2. sanitize_line on multiline variables
`sanitize_line "$VAR"` where VAR has newlines → all files on one line.
Always pipe through `while IFS= read -r line` for per-line sanitization.

### 3. Storing multiline find output in variables then sanitizing
```bash
# WRONG
FILES=$(find . -name '*.js' -exec ls -lh {} \;)
sanitize_line "$FILES"  # → one giant line

# CORRECT — pipe directly, sanitize per line
find . -name '*.js' -exec ls -lh {} \; | while IFS= read -r line; do
  sanitize_line "$line"; echo ""
done
```

### 4. Assuming defaults.run.env exists
GitHub Actions has `defaults.run.shell` and `defaults.run.working-directory`
but NOT `defaults.run.env`. Environment variables must be set per-step or
at job/workflow level.

## sanitize-sed.sh Functions Reference

| Function | Purpose | Usage |
|----------|---------|-------|
| `escape_html "$str"` | HTML entity encode (`&<>"'`) | All GITHUB_STEP_SUMMARY writes |
| `sanitize_line "$str"` | HTML escape + strip control chars | Single-line output |
| `sanitize_print "$str"` | Like sanitize_line + newline | Convenience wrapper |
| `sanitize_ref "$ref"` | Sanitize git ref names | Branch/tag names in summaries |
| `sanitize_filename "$name"` | Sanitize file paths | Artifact names, file listings |

## PowerShell Governance — Windows Steps

Windows CI steps (e.g., `ci-pr-win.yml`, `ci-latest-release.yml`) use PowerShell
with the same four-pillar hardening model. The PowerShell sanitizer lives at
`.github/scripts/sanitize.ps1` (V1, ~310 lines).

### Mandatory PowerShell Step Template

```yaml
- name: My Governance-Compliant Step (Windows)
  shell: pwsh -NoProfile -NoLogo -NonInteractive -Command {0}
  env:
    POWERSHELL_TELEMETRY_OPTOUT: 1
    POWERSHELL_UPDATECHECK: Off
    GH_REPOSITORY: ${{ github.repository }}
    GH_COMMIT_SHA: ${{ github.sha }}
  run: |
    $ErrorActionPreference = 'Stop'
    $PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
    git config --global credential.helper ""
    if (Test-Path env:GITHUB_TOKEN) { Remove-Item env:GITHUB_TOKEN }

    # Load sanitizer
    . .github/scripts/sanitize.ps1

    # ... actual work ...

    # Write sanitized summary
    "### Build Results" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
    "- Repository: $(Sanitize-Line $env:GH_REPOSITORY)" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
    "- Commit SHA: $(Sanitize-Line $env:GH_COMMIT_SHA)" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
```

### Shell Specification

```yaml
shell: pwsh -NoProfile -NoLogo -NonInteractive -Command {0}
```

| Flag | Purpose |
|------|---------|
| `-NoProfile` | Prevents profile script execution (same as bash `--noprofile`) |
| `-NoLogo` | Suppresses startup banner |
| `-NonInteractive` | Disables interactive prompts |
| `-Command {0}` | Executes the script file |

### Environment Lockdown

```yaml
env:
  POWERSHELL_TELEMETRY_OPTOUT: 1
  POWERSHELL_UPDATECHECK: Off
```

Analog to `BASH_ENV: /dev/null` — disables telemetry and update checks that
could leak information or cause non-deterministic behavior.

### Error Handling

```powershell
$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
```

Equivalent to `set -euo pipefail` — any error terminates the step.

### Credential Cleanup

```powershell
git config --global credential.helper ""
if (Test-Path env:GITHUB_TOKEN) { Remove-Item env:GITHUB_TOKEN }
if (Test-Path env:GH_TOKEN) { Remove-Item env:GH_TOKEN }
if (Test-Path env:ACTIONS_RUNTIME_TOKEN) { Remove-Item env:ACTIONS_RUNTIME_TOKEN }
```

### PowerShell Sanitizer Functions (sanitize.ps1)

| Function | Purpose | Bash Equivalent |
|----------|---------|-----------------|
| `Escape-Html "$str"` | HTML entity encode `& < > " '` | `escape_html "$str"` |
| `Sanitize-Line "$str"` | Strip control chars + escape + truncate (single-line) | `sanitize_line "$str"` |
| `Sanitize-Print "$str"` | Strip ctrl (keep LF) + escape + truncate (multi-line) | `sanitize_print "$str"` |
| `Sanitize-Ref "$ref"` | Safe ref name (alphanumeric + `._/-`) | `sanitize_ref "$ref"` |
| `Sanitize-Filename "$name"` | Safe filename (no slashes) | `sanitize_filename "$name"` |
| `Safe-EchoForSummary "$str"` | Sanitize + Write-Output (drop-in echo) | `echo "$(sanitize_line "$str")"` |
| `Sanitizer-Version` | Returns version marker | (no equivalent) |

### PowerShell Multiline Output

PowerShell's `Sanitize-Print` preserves newlines (unlike `Sanitize-Line`), making
it suitable for multi-line output. For file listings:

```powershell
# Single-line per file (using Sanitize-Line per item)
Get-ChildItem -Recurse -Filter "*.wasm" | ForEach-Object {
    "$(Sanitize-Line $_.FullName)  ($($_.Length) bytes)" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
}

# Multi-line block (using Sanitize-Print for the whole block)
$listing = Get-ChildItem -Recurse -Filter "*.wasm" | Format-Table -AutoSize | Out-String
Sanitize-Print $listing | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
```

### Matrix Expression Safety (PowerShell)

Same rule applies — never put `${{ }}` directly in `run:` blocks:

```yaml
# WRONG
run: |
  cmake -B build -DCMAKE_BUILD_TYPE=${{ matrix.build_type }}

# CORRECT
env:
  MATRIX_BUILD_TYPE: ${{ matrix.build_type }}
run: |
  $ErrorActionPreference = 'Stop'
  . .github/scripts/sanitize.ps1
  $BuildType = Sanitize-Line $env:MATRIX_BUILD_TYPE
  cmake -B build -DCMAKE_BUILD_TYPE=$BuildType
```

### Input Validation Pattern

```powershell
$BuildType = if ([string]::IsNullOrEmpty($env:USER_INPUT)) { 'Release' } else { $env:USER_INPUT }
$ValidTypes = @('Debug', 'Release', 'RelWithDebInfo', 'MinSizeRel')
if ($BuildType -notin $ValidTypes) {
    Write-Error "Invalid build type: $BuildType"
    exit 1
}
```

### Path Traversal Prevention

```powershell
$ResolvedPath = [System.IO.Path]::GetFullPath($InstallPath)
$WorkspacePath = [System.IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)
if (-not $ResolvedPath.StartsWith($WorkspacePath)) {
    Write-Error "Path traversal detected: $ResolvedPath"
    exit 1
}
```

## Bash vs PowerShell Comparison Table

| Security Control | Bash | PowerShell |
|-----------------|------|------------|
| Shell flags | `bash --noprofile --norc {0}` | `pwsh -NoProfile -NoLogo -NonInteractive -Command {0}` |
| Env lockdown | `BASH_ENV: /dev/null` | `POWERSHELL_TELEMETRY_OPTOUT: 1` + `POWERSHELL_UPDATECHECK: Off` |
| Error handling | `set -euo pipefail` | `$ErrorActionPreference = 'Stop'` + `$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'` |
| Token removal | `unset GITHUB_TOKEN \|\| true` | `if (Test-Path env:GITHUB_TOKEN) { Remove-Item env:GITHUB_TOKEN }` |
| Sanitizer | `source .github/scripts/sanitize-sed.sh` | `. .github/scripts/sanitize.ps1` |
| Escape HTML | `escape_html "$str"` | `Escape-Html $str` |
| Sanitize line | `sanitize_line "$str"` | `Sanitize-Line $str` |
| Sanitize multi-line | `sanitize_print "$str"` | `Sanitize-Print $str` |
| Summary write | `echo "$(sanitize_line "$val")" >> "$GITHUB_STEP_SUMMARY"` | `"$(Sanitize-Line $val)" \| Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append` |

## See Also

- [xsscx/governance/actions](https://github.com/xsscx/governance/tree/main/actions) — Bash/PowerShell prologue standards
- `ci-pr-action.yml` in iccDEV — Reference governance-compliant workflow (bash steps)
- `ci-pr-win.yml` in iccDEV — Reference governance-compliant workflow (PowerShell steps)
- `ci-latest-release.yml` in iccDEV — Cross-platform release workflow (bash + PowerShell)
- `.github/scripts/sanitize-sed.sh` — V3 bash sanitizer (279 lines)
- `.github/scripts/sanitize.ps1` — V1 PowerShell sanitizer (~310 lines)
