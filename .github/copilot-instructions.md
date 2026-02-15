# Copilot Instructions — ICC Security Research

## Build Commands

```bash
# iccanalyzer-lite (ASAN + UBSAN + coverage, clang++ only)
cd iccanalyzer-lite && ./build.sh

# CFL fuzzers (17 LibFuzzer harnesses, auto-applies OOM patches to iccDEV)
cd cfl && ./build.sh

# colorbleed_tools (unsafe ICC↔XML converters for mutation testing)
cd colorbleed_tools && make setup && make

# MCP server (Python venv + native deps)
cd mcp-server && ./build.sh build

# MCP server tests (run from venv)
cd mcp-server && ./build.sh test
# Or individually:
cd mcp-server && python test_mcp.py    # ~201 tests
cd mcp-server && python test_web_ui.py  # ~123 tests

# colorbleed_tools tests
cd colorbleed_tools && make test
```

## Fuzzing

```bash
# Ramdisk workflow (mounts 4GB tmpfs, seeds corpus, runs all 17 fuzzers)
cd cfl && ./ramdisk-fuzz.sh

# Ramdisk management scripts (in .github/scripts/)
.github/scripts/ramdisk-status.sh       # Report ramdisk state
.github/scripts/ramdisk-clean.sh        # Remove stray dirs (dry-run default)
.github/scripts/ramdisk-merge.sh        # LibFuzzer -merge=1 dedup
.github/scripts/ramdisk-sync-to-disk.sh # Sync corpus ramdisk → cfl/corpus-*
.github/scripts/ramdisk-seed.sh         # Seed corpus disk → ramdisk
.github/scripts/ramdisk-teardown.sh     # Orchestrate sync → clean → unmount

# Single fuzzer on ramdisk
cfl/bin/icc_profile_fuzzer -max_total_time=60 -rss_limit_mb=4096 \
  -dict=cfl/icc_profile.dict /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer

# Corpus merge/minimize
cfl/bin/icc_profile_fuzzer -merge=1 /tmp/fuzz-ramdisk/corpus-merged /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer

# Validate seed corpus readiness
cd cfl && ./test-seed-corpus.sh
```

## MCP Server

The ICC Profile MCP server exposes 7 tools for AI-assisted ICC profile analysis. Three integration methods:

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
When an issue asks to analyze an ICC profile, you MUST run ALL of these steps and include the **complete raw output** from each tool in the report. Do NOT summarize or omit tool output.

1. `iccanalyzer-lite -a <file>` — comprehensive analysis (security heuristics + round-trip + structural). Include the **complete raw output**.
2. `iccanalyzer-lite -nf <file>` — ninja mode full dump (no truncation). Include the **complete raw output**.
3. `iccanalyzer-lite -r <file>` — round-trip accuracy test. Include the **complete raw output**.
4. Record the exit code from each command (0=clean, 1=finding, 2=error, 3=usage).
5. Include any ASAN/UBSAN stderr output — this is security-relevant.
6. Add your own analysis AFTER all raw tool output — do not replace it with a summary.

### Where to put the report
Post the complete report (all raw tool output + your analysis) as a **comment on the PR** you create. The PR description should contain a brief summary linking back to the issue, but the full raw output MUST be in a PR comment so it is visible and searchable. Do NOT only put the report in the PR description — always add it as a comment.

The raw iccanalyzer-lite output uses `[OK]`, `[WARN]`, `[FAIL]`, `[CRITICAL]` labels and heuristic IDs `[H1]`–`[H19]`. This output MUST appear verbatim in the report. If you summarize instead of including the raw output, the report is incomplete.

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

## Architecture

This repo contains security research tools targeting the ICC color profile specification via the iccDEV library (formerly DemoIccMAX):

- **cfl/** — 17 LibFuzzer harnesses, each scoped to a specific ICC project tool's API surface. Fuzzers must only call library APIs reachable from their corresponding tool (see Fuzzer→Tool Mapping in README.md).
- **iccanalyzer-lite/** — 19-heuristic static/dynamic security analyzer (v2.9.1) built with full sanitizer instrumentation. 14 C++ modules compiled in parallel. Deterministic exit codes: 0=clean, 1=finding, 2=error, 3=usage.
- **colorbleed_tools/** — Intentionally unsafe ICC↔XML converters used as CodeQL targets for mutation testing. Output paths validated against `..` traversal.
- **mcp-server/** — Python FastMCP server (stdio transport) + Starlette web UI wrapping iccanalyzer-lite and colorbleed_tools. Multi-layer path traversal defense, output sanitization, upload/download size caps. Default binding: 127.0.0.1.
- **cfl/patches/** — OOM mitigation patches (001–005+) applied to iccDEV before fuzzer builds. Patch 001 caps CLUT at 16MB; others cap at 128MB (patch 005 caps hex dumps at 256KB).
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

### OOM patches
Named `NNN-brief-description.patch` in `cfl/patches/`. Applied automatically by `cfl/build.sh` AND all CI fuzzer workflows before cmake. Build alignment rule: local build.sh and CI workflows MUST apply identical patches/flags.

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
- Subprocess: `asyncio.create_subprocess_exec` (never `shell=True`), minimal env vars
- Output: strip control chars/ANSI, 10MB cap. Uploads: 20MB cap, temp dir with 700 mode
- CSP with per-request nonce, strict security headers
- Default binding: 127.0.0.1 (not 0.0.0.0)

### CI workflows
26 workflows use `workflow_dispatch` (manual trigger). Actions are 100% SHA-pinned. Key workflows:
- `libfuzzer-smoke-test.yml` — 60-second smoke test for all 17 fuzzers
- `cfl-libfuzzer-parallel.yml` — Extended parallel fuzzing with dict auto-selection and auto-merge
- `codeql-security-analysis.yml` — 15 custom queries × 3 targets + security-and-quality
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
