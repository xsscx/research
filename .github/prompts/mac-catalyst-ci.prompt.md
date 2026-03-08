---
mode: agent
description: Review and debug Mac Catalyst / macOS CI workflows for xnuimagefuzzer and xnuimagetools
---

# Mac Catalyst CI Workflow Maintenance

## Context
The xnuimagefuzzer/ and xnuimagetools/ sub-repos build Mac Catalyst apps with ASAN, UBSAN,
and code coverage instrumentation. Mac Catalyst CI has many pitfalls not documented elsewhere.

## Critical Rules

### App Launch
- Mac Catalyst binaries MUST be launched via `open "$APP_BUNDLE"` — bare Mach-O exits immediately
- `open` blocks until the app exits — use `open "$APP_BUNDLE" & ; disown $!`
- Pass env vars via `open --env KEY=VALUE` (macOS 13+), NOT `launchctl setenv`
- Mac Catalyst apps do NOT respond to `osascript quit` — use `pgrep -f "App Name"` + `kill`
- SIGTERM does NOT trigger `atexit()` — send SIGINT first to flush profraw coverage

### SIGPIPE Prevention
NEVER pipe macOS tools through `| head`. They crash with SIGABRT (exit 134).
```bash
# BAD:  ls -la | head -20     → SIGPIPE crash
# GOOD: ls -la | sed -n '1,20p'
# BAD:  xcodebuild -version | head -1  → NSFileHandleOperationException
# GOOD: xcodebuild -version | sed -n '1p'
# BAD:  file -b "$f" | head -c 40
# GOOD: file -b "$f" | cut -c1-40
```

### LLVM Coverage Symbols
Use `dlsym(RTLD_DEFAULT, "__llvm_profile_write_file")` — NOT `__attribute__((weak)) extern`.
Weak extern breaks iOS Simulator linker without `-fprofile-instr-generate`.

### Action Pinning
All actions must be SHA-pinned:
- checkout: `11bd71901bbe5b1630ceea73d27597364c9af683` (v4.2.2)
- upload-artifact: `ea165f8d65b6e75b540449e92b4886f43607fa02` (v4.6.2)
- cache: `5a3ec84eff668545956fd18022155c47e93e2684` (v4.2.3)

### VideoToolbox ASAN
VT fuzzer runs 10-50x slower under ASAN. Never call `malloc_zone_print()` in hot loops.
The VT instrumented job is disabled in CI — test locally with extended timeouts.

## Debugging Steps
1. Check workflow YAML for `| head` patterns — replace with `| sed -n`
2. Check app launch uses `open --env` not bare binary or `launchctl setenv`
3. Verify polling threshold >= 80 and timeout >= 120s for xnuimagefuzzer
4. Confirm SIGPIPE-safe output in all artifact upload steps
5. Check `set -euo pipefail` is first line of every `run:` block

## See Also
- [image-fuzzer-quality.prompt.md](image-fuzzer-quality.prompt.md) — Image fuzzer assessment
- [cooperative-development.prompt.md](cooperative-development.prompt.md) — Multi-agent coordination
- [health-check.prompt.yml](health-check.prompt.yml) — MCP server verification
