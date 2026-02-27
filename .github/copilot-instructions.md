# Copilot Instructions — ICC Security Research

## Environment Detection

This repo is used in two contexts. Detect which one you are in:

### GitHub Copilot Coding Agent (cloud)
If `copilot-setup-steps.yml` ran, binaries are pre-built in the Docker image.
**Do NOT run** `build.sh`, `cmake`, or `git clone` for iccDEV — they are already built.
Binaries:
- `iccanalyzer-lite/iccanalyzer-lite` — security analyzer (ASAN+UBSAN)
- `colorbleed_tools/iccToXml_unsafe` — ICC to XML converter
- `colorbleed_tools/iccFromXml_unsafe` — XML to ICC converter

### Local / Copilot CLI
Binaries must be built before use. See **Local Build** section below.

**First action** on any analysis issue: run `ls -la iccanalyzer-lite/iccanalyzer-lite` to confirm the binary exists. If missing, build it (local) or report the error (cloud).

## Local Build

```bash
# Prerequisites: clang/clang++ 18+, cmake 3.15+, libxml2-dev, libtiff-dev,
#                libclang-rt-18-dev (provides ASan/UBSan/fuzzer runtimes)

# Build iccanalyzer-lite (ASAN + UBSAN + coverage)
cd iccanalyzer-lite && ./build.sh

# Build CFL fuzzers (clones iccDEV, applies 52 patches, builds 19 fuzzers)
cd cfl && ./build.sh

# Build colorbleed_tools
cd colorbleed_tools && make setup && make
```

`cfl/build.sh` reuses an existing `cfl/iccDEV/` checkout if present — it does NOT reclone unless the directory is missing.

## Ramdisk Fuzzing Setup

All fuzzing should run on a tmpfs ramdisk to avoid SSD wear and maximize I/O speed.

```bash
# One-stop setup: mount ramdisk, copy binaries + dicts + corpus
.github/scripts/ramdisk-seed.sh --mount

# Status check
.github/scripts/ramdisk-status.sh

# Run a single fuzzer (smoke test, 60 seconds)
LLVM_PROFILE_FILE=/tmp/fuzz-ramdisk/profraw/%m.profraw \
ASAN_OPTIONS=detect_leaks=0 \
FUZZ_TMPDIR=/tmp/fuzz-ramdisk \
  /tmp/fuzz-ramdisk/bin/icc_profile_fuzzer \
  -max_total_time=60 -detect_leaks=0 -timeout=30 -rss_limit_mb=4096 \
  -use_value_profile=1 -max_len=65536 \
  -artifact_prefix=/tmp/fuzz-ramdisk/ \
  -dict=/tmp/fuzz-ramdisk/dict/icc_profile_fuzzer.dict \
  /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer/

# Corpus merge/minimize (after extended fuzzing)
.github/scripts/ramdisk-merge.sh

# Sync minimized corpus back to disk
.github/scripts/ramdisk-sync-to-disk.sh

# Generate coverage report
.github/scripts/merge-profdata.sh
.github/scripts/generate-coverage-report.sh
```

Special fuzzer notes:
- **icc_link_fuzzer** needs `ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256` (2 profiles per input = 2x ASAN memory)
- Coverage collection: `LLVM_PROFILE_FILE=$RAMDISK/profraw/%m_%p.profraw`
- Suppress profile errors during fuzzing: `LLVM_PROFILE_FILE=/dev/null`

## FAILURE IDENTIFICATION — READ THIS

You MUST accurately report failures. Do NOT claim success when errors occur.

**How to detect failures:**
1. **Exit code != 0** — Any non-zero exit code is a failure or finding. Report it explicitly.
2. **ASAN output** — Lines containing `ERROR: AddressSanitizer` indicate memory safety bugs. This is a CRITICAL finding.
3. **UBSAN output** — Lines containing `runtime error:` indicate undefined behavior. This is a finding.
4. **Signal termination** — Exit codes 128+ (e.g., 134=SIGABRT, 137=SIGKILL, 139=SIGSEGV) are crashes. Report as CRITICAL.
5. **Timeout** — If a tool hangs, that is a finding (possible infinite loop/recursion). Kill it after 60 seconds.
6. **Empty output** — If a tool produces no stdout, something went wrong. Report it.

**What counts as SUCCESS:** Exit code 0 AND no ASAN/UBSAN stderr AND non-empty output.

**What you MUST NOT do:**
- Do NOT say "analysis completed successfully" if exit code was non-zero
- Do NOT omit ASAN/UBSAN stderr from the report
- Do NOT summarize tool output — include it VERBATIM
- Do NOT skip any of the 3 required commands (`-a`, `-nf`, `-r`)

## Build Commands (REFERENCE ONLY — do NOT run these)

These commands are for CI documentation. For local builds, see **Local Build** above.

## Fuzzing

```bash
# Automated ramdisk workflow (mounts tmpfs, seeds corpus, runs all 19 fuzzers)
cd cfl && ./ramdisk-fuzz.sh

# Local fuzzing (uses existing ramdisk, manages workers/timeouts)
cd cfl && ./fuzz-local.sh

# Ramdisk management scripts (in .github/scripts/)
.github/scripts/ramdisk-status.sh       # Report ramdisk state
.github/scripts/ramdisk-clean.sh        # Remove stray dirs (dry-run default)
.github/scripts/ramdisk-merge.sh        # LibFuzzer -merge=1 dedup
.github/scripts/ramdisk-sync-to-disk.sh # Sync corpus ramdisk → cfl/corpus-*
.github/scripts/ramdisk-seed.sh         # Seed corpus disk → ramdisk
.github/scripts/ramdisk-teardown.sh     # Orchestrate sync → clean → unmount

# Single fuzzer on ramdisk (short smoke test)
cfl/bin/icc_profile_fuzzer -max_total_time=60 -rss_limit_mb=4096 \
  -dict=cfl/icc_profile.dict /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer

# Single fuzzer on ramdisk (extended 4-hour run with env vars)
FUZZ_TMPDIR=/tmp/fuzz-ramdisk LLVM_PROFILE_FILE=/dev/null \
  /tmp/fuzz-ramdisk/bin/icc_toxml_fuzzer -max_total_time=14400 -detect_leaks=0 \
  -timeout=30 -rss_limit_mb=4096 -use_value_profile=1 -max_len=65536 \
  -artifact_prefix=/tmp/fuzz-ramdisk/ \
  -dict=/tmp/fuzz-ramdisk/dict/icc_toxml_fuzzer.dict \
  /tmp/fuzz-ramdisk/corpus-icc_toxml_fuzzer/

# Link fuzzer needs quarantine cap (2 profiles per input = 2x ASAN memory)
ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256 \
FUZZ_TMPDIR=/tmp/fuzz-ramdisk LLVM_PROFILE_FILE=/dev/null \
  /tmp/fuzz-ramdisk/bin/icc_link_fuzzer -max_total_time=14400 -detect_leaks=0 \
  -timeout=30 -rss_limit_mb=4096 -use_value_profile=1 -max_len=65536 \
  -artifact_prefix=/tmp/fuzz-ramdisk/ \
  -dict=/tmp/fuzz-ramdisk/dict/icc_link_fuzzer.dict \
  /tmp/fuzz-ramdisk/corpus-icc_link_fuzzer/

# Corpus merge/minimize
.github/scripts/ramdisk-merge.sh              # all fuzzers
.github/scripts/ramdisk-merge.sh --jobs 32    # parallel

# Validate seed corpus readiness
.github/scripts/test-seed-corpus.sh
```

## MCP Server

The ICC Profile MCP server exposes 15 tools (9 analysis + 6 maintainer build) for AI-assisted ICC profile security research. Three integration methods:

### 1. Copilot CLI (`/mcp` command)
Use `/mcp` to add the server with stdio transport:
- Command: `python3 mcp-server/icc_profile_mcp.py`
- Prereq: `cd mcp-server && pip install -e .`

### 2. VS Code Copilot Chat
Already configured in `.vscode/mcp.json`. Open the repo in VS Code and tools auto-register.
Prereq: `cd mcp-server && pip install -e .`

### 3. GitHub Copilot Coding Agent (cloud)
Paste `.github/copilot-mcp-config.json` into repo Settings → Copilot → Coding agent → MCP configuration. The `copilot-setup-steps.yml` workflow builds native deps automatically.

### ICC file attachments on GitHub Issues
GitHub does not allow `.icc` file attachments. Users should rename files to `.icc.txt` before attaching. When processing an issue with an attached `.icc.txt` file:
1. Download the attachment
2. Rename from `*.icc.txt` to `*.icc`
3. Run the analysis tools against the renamed file

### Required analysis workflow for ICC profile issues
When an issue asks to analyze an ICC profile, run this ONE command:

```bash
./analyze-profile.sh test-profiles/<filename>.icc
```

This script runs all 3 analysis commands (`-a`, `-nf`, `-r`), captures exit codes and ASAN/UBSAN output, and writes the complete report to `analysis-reports/`. Do NOT run the commands individually.

Then:
1. `git add analysis-reports/ && git commit -m "Analysis: <profile-name>"` 
2. Update the PR description with the exit code summary from the script output
3. If ASAN/UBSAN findings were detected, note them prominently in the PR description
4. Post each report as a comment on the originating issue:
   ```bash
   gh issue comment <ISSUE_NUMBER> --body "$(cat analysis-reports/<profile>-analysis.md)"
   ```

The script exits with the worst exit code across all 3 commands. Exit 0 = clean, 1 = finding, 2 = error.

### Code coverage for a single profile
Use `iccdev-single-profile-coverage.yml` (NOT `ci-code-coverage.yml`) for per-profile coverage. The full coverage workflow runs `CreateAllProfiles.sh` which pollutes results with hundreds of generated profiles. The single-profile workflow accepts a `profile_path` input (relative to `test-profiles/`) and runs only IccDumpProfile, IccRoundTrip, XML round-trip, and IccApplyProfiles against that one file.

### Available MCP tools
| Tool | Description |
|------|-------------|
| `inspect_profile` | Full structural dump (header, tags, values) |
| `analyze_security` | 19-heuristic security scan |
| `validate_roundtrip` | Bidirectional transform validation |
| `full_analysis` | Combined security + validation + inspection |
| `profile_to_xml` | ICC to XML conversion |
| `compare_profiles` | Side-by-side diff of two profiles |
| `list_test_profiles` | List available test profiles |
| `upload_and_analyze` | Accept base64-encoded ICC profile, analyze in any mode |
| `build_tools` | Build native analysis tools from source |
| `cmake_configure` | Configure iccDEV cmake (build type, sanitizers, generator, tools) |
| `cmake_build` | Build iccDEV with cmake --build (cross-platform) |
| `create_all_profiles` | Run CreateAllProfiles.sh from Testing/ directory |
| `run_iccdev_tests` | Run RunTests.sh test suite |
| `cmake_option_matrix` | Test cmake option toggles independently |
| `windows_build` | Windows MSVC + vcpkg build (native or script generation) |

## Architecture

This repo contains security research tools targeting the ICC color profile specification via the iccDEV library (formerly DemoIccMAX):

- **cfl/** — 19 LibFuzzer harnesses, each scoped to a specific ICC project tool's API surface. Fuzzers must only call library APIs reachable from their corresponding tool (see Fuzzer→Tool Mapping in README.md).
- **iccanalyzer-lite/** — 19-heuristic static/dynamic security analyzer (v2.9.1) built with full sanitizer instrumentation. 14 C++ modules compiled in parallel. Deterministic exit codes: 0=clean, 1=finding, 2=error, 3=usage.
- **colorbleed_tools/** — Intentionally unsafe ICC↔XML converters used as CodeQL targets for mutation testing. Output paths validated against `..` traversal.
- **mcp-server/** — Python FastMCP server (stdio transport) + Starlette web UI wrapping iccanalyzer-lite and colorbleed_tools. 15 tools: 9 analysis + 6 maintainer (cmake configure/build, option matrix, CreateAllProfiles, RunTests, Windows build). Multi-layer path traversal defense, output sanitization, upload/download size caps. Default binding: 127.0.0.1. 3 custom Python CodeQL queries (subprocess injection, path traversal, output sanitization).
- **cfl/patches/** — 52 security patches (001–052) applied to iccDEV before fuzzer builds. Includes OOM caps (16MB–128MB), UBSAN fixes, heap-buffer-overflow guards, stack-overflow depth caps, null-deref guards, memory leak fixes, float-to-int overflow clamps, and alloc/dealloc mismatch corrections. See `cfl/patches/README.md` for full details.
- **cfl/iccDEV/** — Cloned upstream iccDEV library (patched at build time, not committed patched).
- **test-profiles/** and **extended-test-profiles/** — ICC profile corpora for fuzzing and regression testing.

Each iccDEV subdirectory (under cfl/, iccanalyzer-lite/, colorbleed_tools/) is an independent clone of the upstream library — they are not shared.

## Key Conventions

### No emojis
Do not use emojis in code, CI output, or reports. Use bracketed text labels: `[OK]`, `[WARN]`, `[FAIL]`, `[SKIP]`, `[CRITICAL]`, `[INFO]`.

### Exit codes (iccanalyzer-lite)
Deterministic exit codes defined in `IccAnalyzerErrors.h`:
- `0` — Clean (no findings)
- `1` — Finding (heuristic detections)
- `2` — Error (I/O, parse, or runtime failure)
- `3` — Usage (bad arguments)

Signals (128+N) are never returned by the analyzer — their presence always indicates a real crash. `NormalizeExit()` in main clamps unbounded raw returns.

### Non-fatal diagnostic macros
Upstream `ICC_TRACE_NAN` calls `__builtin_trap()` and `ICC_SANITY_CHECK_SIGNATURE` calls `assert(false)` — both fatal. `IccAnalyzerCommon.h` overrides them to log-only (non-fatal) via `#undef`/`#define` AFTER `#include "IccSignatureUtils.h"`.

### Fuzzer structure
Every fuzzer implements `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` with:
- Early return on size bounds: `if (size < MIN || size > MAX) return 0;`
- Temp file via `mkstemp()` → `write()` → `close()` → process → `unlink()`
- Error/warning handlers suppressed during fuzzing
- Optional `LLVMFuzzerInitialize()` for one-time setup
- Trailing bytes for parameter derivation (never consume leading bytes — shifts ICC header)

### Fuzzer scope alignment
Each fuzzer must only exercise APIs reachable from its corresponding project tool. For example:
- `icc_profile_fuzzer` / `icc_spectral_fuzzer` must NOT use `CIccCmm` (AddXform/Begin/Apply)
- `icc_deep_dump_fuzzer` must NOT call FindColor/FindDeviceColor/FindPcsColor
- See the Fuzzer→Tool Mapping table in README.md

### Dictionary files
- Format: LibFuzzer dict format with `\xNN` hex escapes only (no octal, no inline comments)
- Lookup order in CI: `cfl/${FUZZER_NAME}.dict` → `cfl/icc_core.dict` → `cfl/icc.dict`
- Use `.github/scripts/convert-libfuzzer-dict.py` to convert raw LibFuzzer recommended dictionary output
- CI auto-merges recommended dict entries after fuzzing (convert-libfuzzer-dict.py --append)
- Several fuzzers share base dicts (e.g., `icc_toxml_fuzzer` → `icc_xml_consolidated.dict`, `icc_io_fuzzer` → `icc_core.dict`). The mapping is defined as `FUZZER_DICTS` in `ramdisk-fuzz.sh`, `fuzz-local.sh`, and `.github/scripts/seed-corpus-setup.sh`. Per-fuzzer aliases are created on ramdisk so `-dict=${fuzzer}.dict` resolves correctly.

### OOM patches
Named `NNN-brief-description.patch` in `cfl/patches/`. Applied automatically by `cfl/build.sh` AND all CI fuzzer workflows before cmake. Build alignment rule: local build.sh and CI workflows MUST apply identical patches/flags.

### Patch creation workflow
When creating a new patch for `cfl/patches/`:
1. Reproduce the crash with the PoC profile against the existing iccDEV binary
2. Create the `.patch` file in unified diff format (`diff -u a/path b/path`)
3. Apply to the existing iccDEV checkout: `patch -p1 -d cfl/iccDEV --forward < cfl/patches/NNN-name.patch`
4. Rebuild iccDEV libraries: `cd cfl/iccDEV/Build && cmake --build . --target IccProfLib2-static -j$(nproc)`
5. Rebuild fuzzers: `cd cfl && ./build.sh` (reuses existing checkout, applies all patches)
6. Copy rebuilt binaries to ramdisk: `cp cfl/bin/* /tmp/fuzz-ramdisk/bin/`
7. Verify the PoC no longer crashes (exit 0, no ASAN/UBSAN output)
8. Run a smoke test across all 19 fuzzers to confirm no regressions
9. Update `cfl/patches/README.md` (table entry + description paragraph)
10. Patches MUST be incremental diffs (not cumulative). Each patch applies cleanly atop all prior patches.

### Sanitizer flags
- **Fuzzers**: `-fsanitize=fuzzer,address,undefined -fprofile-instr-generate -fcoverage-mapping`
- **iccanalyzer-lite**: `-fsanitize=address,undefined,float-divide-by-zero,float-cast-overflow,integer -g3 -O0 --coverage`
- Both the iccDEV libs AND the tool linking them must use matching sanitizer flags
- Suppress LLVM profile errors during fuzzing: `LLVM_PROFILE_FILE=/dev/null`
- iccDEV diagnostic flags: `-DICC_LOG_SAFE=ON -DICC_TRACE_NAN_ENABLED=ON` (cmake) or `-DICC_LOG_SAFE -DICC_TRACE_NAN_ENABLED` (CXXFLAGS)

### Stale coverage files
After recompilation, old `.gcda` files mismatch new `.gcno` files. `build.sh` auto-cleans them with `find . -name "*.gcda" -delete` before building.

### Byte-shift patterns
`(data[i] << 24)` causes signed integer overflow when `data[i] >= 128`. Fix: `static_cast<icUInt32Number>(data[i]) << 24`. Similarly, use `tagOffset <= fileSize - tagSize` instead of `tagOffset + tagSize <= fileSize`.

### MCP server security patterns
- Path validation: allowlist of base dirs + symlink resolution + normpath checks + null byte rejection
- Build dir validation: triple layer (web_ui regex, _resolve_build_dir, Path.resolve containment check)
- CMake args: regex allowlist (`-DVAR=VALUE`, `-Wflag` only), shell metachar rejection
- Subprocess: `asyncio.create_subprocess_exec` (never `shell=True`), minimal env vars
- Output: `_sanitize_output` strips control chars/ANSI, 10MB cap. All output paths verified sanitized
- Uploads: 20MB cap, temp dir with 700 mode
- CSP with per-request nonce, strict security headers
- Default binding: 127.0.0.1 (not 0.0.0.0)

### CI workflows
26 workflows use `workflow_dispatch` (manual trigger). Actions are 100% SHA-pinned. Key workflows:
- `libfuzzer-smoke-test.yml` — 60-second smoke test for all 19 fuzzers
- `cfl-libfuzzer-parallel.yml` — Extended parallel fuzzing with dict auto-selection and auto-merge
- `codeql-security-analysis.yml` — 17 custom C++ queries x 3 targets + 3 custom Python queries + security-and-quality
- `iccanalyzer-cli-release.yml` — CLI test suite + release artifacts
- `iccanalyzer-lite-debug-sanitizer-coverage.yml` — Debug+ASan+UBSan+coverage with structured exit code dispatch
- `mcp-server-test.yml` — MCP server unit tests
- `copilot-setup-steps.yml` — Coding agent environment setup

### CI caching
16 workflows have 3-layer caching: APT packages → iccDEV clone → iccDEV build. Cache keys include patch hashes and build config suffixes (lite-debug, lite-debug-san, lite-gcov, lite-reldbg, cfl, mcp, scan). SHA-pinned: `actions/cache@5a3ec84eff668545956fd18022155c47e93e2684`.

### CI exit code handling
With `set -euo pipefail`, non-zero exits from `timeout` abort the script. Use `EXIT_CODE=0; timeout ... || EXIT_CODE=$?` pattern instead of bare `timeout` calls.

### CodeQL
15 custom queries shared across cfl/, iccanalyzer-lite/, and colorbleed_tools/ (buffer-overflow, integer-overflow, XXE, UAF, type-confusion, enum UB, unchecked I/O, injection, argv-output-path, alloc-dealloc-mismatch, etc.). Config in each target's `codeql-config.yml`. All 3 `security-research-suite.qls` files must be kept in sync.

### Compiler
All C++ code requires clang/clang++. GCC is used only in the colorbleed_tools CI matrix build.
