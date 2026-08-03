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
- Mac Catalyst binaries MUST be launched via `open "$APP_BUNDLE"` -- bare Mach-O exits immediately
- `open` blocks until the app exits -- use `open "$APP_BUNDLE" & ; disown $!`
- Pass env vars via `open --env KEY=VALUE` (macOS 13+), NOT `launchctl setenv`
- Mac Catalyst apps do NOT respond to `osascript quit` -- use `pgrep -f "App Name"` + `kill`
- SIGTERM does NOT trigger `atexit()` -- send SIGINT first to flush profraw coverage

### SIGPIPE Prevention
NEVER pipe macOS tools through `| head`. They crash with SIGABRT (exit 134).
```bash
# BAD:  ls -la | head -20     -> SIGPIPE crash
# GOOD: ls -la | sed -n '1,20p'
# BAD:  xcodebuild -version | head -1  -> NSFileHandleOperationException
# GOOD: xcodebuild -version | sed -n '1p'
# BAD:  file -b "$f" | head -c 40
# GOOD: file -b "$f" | cut -c1-40
```

### LLVM Coverage Symbols
Use `dlsym(RTLD_DEFAULT, "__llvm_profile_write_file")` -- NOT `__attribute__((weak)) extern`.
Weak extern breaks iOS Simulator linker without `-fprofile-instr-generate`.

### Action Pinning
All actions must be SHA-pinned (node24-compatible):
- checkout: `08c6903cd8c0fde910a37f88322edcfb5dd907a8` (v5.0.0, node24)
- upload-artifact: `b7c566a772e6b6bfb58ed0dc250532a479d7789f` (v6.0.0, node24)
- cache: `a7833574556fa59680c1b7cb190c1735db73ebf0` (v5.0.0, node24)
- download-artifact: `37930b1c2abaa49bbe596cd826c3c89aef350131` (v7.0.0, node24)

**Node.js 20 deprecation**: GitHub Actions forces Node.js 24 starting June 2, 2026.
Actions pinned to older SHAs (node20) will emit deprecation warnings then fail.

### VideoToolbox ASAN
VT fuzzer runs 10-50x slower under ASAN. Never call `malloc_zone_print()` in hot loops.
The VT instrumented job is disabled in CI -- test locally with extended timeouts.

### CodeQL on macOS (Known Limitations)
- **macOS 15 + Xcode 16**: CodeQL C/C++ extractor cannot trace xcodebuild -- SIP strips
  `DYLD_INSERT_LIBRARIES` from sandboxed child processes. All runs fail with:
  `"CodeQL detected code written in C/C++ but could not process any of it"`
- **Upstream**: [github/codeql-action#2506](https://github.com/github/codeql-action/issues/2506)
- **Workaround**: Rewrite build step to use direct `clang` invocation (not xcodebuild),
  or disable C/C++ CodeQL on `macos-latest` until fixed upstream.
- **CodeQL Action v3 API**: `packs` input MUST be on `codeql-action/init@v3`,
  NOT `codeql-action/analyze@v3`. Placing it on analyze produces silent
  `Unexpected input(s)` warning and `JOB_STATUS_CONFIGURATION_ERROR`.
- xnuimagefuzzer's `codeql-analysis.yml` is marked DISABLED due to the SIP issue.

## Debugging Steps
1. Check workflow YAML for `| head` patterns -- replace with `| sed -n`
2. Check app launch uses `open --env` not bare binary or `launchctl setenv`
3. Verify polling threshold >= 80 and timeout >= 120s for xnuimagefuzzer
4. Confirm SIGPIPE-safe output in all artifact upload steps
5. Check `set -euo pipefail` is first line of every `run:` block
6. If CodeQL fails with "could not process" -- check macOS/Xcode version vs SIP issue
7. If CodeQL fails with `Unexpected input(s) 'packs'` -- move `packs` to `init` step

## See Also
- [image-fuzzer-quality.prompt.md](image-fuzzer-quality.prompt.md) -- Image fuzzer assessment
- [cooperative-development.prompt.md](cooperative-development.prompt.md) -- Multi-agent coordination
