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

# Build CFL fuzzers (clones iccDEV, applies 53 patches, builds 19 fuzzers)
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
  -use_value_profile=1 -max_len=5242880 \
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
  -timeout=30 -rss_limit_mb=4096 -use_value_profile=1 -max_len=5242880 \
  -artifact_prefix=/tmp/fuzz-ramdisk/ \
  -dict=/tmp/fuzz-ramdisk/dict/icc_toxml_fuzzer.dict \
  /tmp/fuzz-ramdisk/corpus-icc_toxml_fuzzer/

# Link fuzzer needs quarantine cap (2 profiles per input = 2x ASAN memory)
ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256 \
FUZZ_TMPDIR=/tmp/fuzz-ramdisk LLVM_PROFILE_FILE=/dev/null \
  /tmp/fuzz-ramdisk/bin/icc_link_fuzzer -max_total_time=14400 -detect_leaks=0 \
  -timeout=30 -rss_limit_mb=4096 -use_value_profile=1 -max_len=5242880 \
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

The ICC Profile MCP server exposes 15 tools (8 analysis + 7 maintainer build) for AI-assisted ICC profile security research.

### Setup — Three integration methods

#### 1. Copilot CLI (`/mcp` command)
Use `/mcp` to add the server with stdio transport:
- Command: `python3 mcp-server/icc_profile_mcp.py`
- Prereq: `cd mcp-server && pip install -e .`

#### 2. VS Code Copilot Chat
Already configured in `.vscode/mcp.json`. Open the repo in VS Code and tools auto-register.
Prereq: `cd mcp-server && pip install -e .`

#### 3. GitHub Copilot Coding Agent (cloud)
Paste `.github/copilot-mcp-config.json` into repo Settings → Copilot → Coding agent → MCP configuration. The `copilot-setup-steps.yml` workflow extracts pre-built binaries from the Docker image — **no build step runs**. The MCP config exposes only the 8 analysis tools (build tools are excluded so the agent does not trigger unnecessary builds).

### ICC file attachments on GitHub Issues
GitHub does not allow `.icc` file attachments. Users should rename files to `.icc.txt` before attaching. When processing an issue with an attached `.icc.txt` file:
1. Download the attachment
2. Rename from `*.icc.txt` to `*.icc`
3. Run the analysis tools against the renamed file

### Required analysis workflow for ICC profile issues
When an issue asks to analyze an ICC profile, perform **two phases**:

#### Phase 1 — MCP tool analysis (Copilot's independent review)
Use the MCP tools to perform your own analysis of the profile before running the script:

1. **`inspect_profile`** — Examine the profile structure: header fields, tag table, data values
2. **`analyze_security`** — Run the 27-heuristic security scan (H1–H27)
3. **`validate_roundtrip`** — Check AToB/BToA and DToB/BToD tag pair completeness
4. **`profile_to_xml`** — Convert to XML for human-readable inspection

Write a summary of your independent findings in the PR description under a **"## MCP Tool Analysis"** heading. Include:
- Profile class, color space, PCS, version, creator
- Any heuristic warnings or critical findings from `analyze_security`
- Round-trip validation status
- Notable structural observations (unusual tags, suspicious sizes, etc.)

#### Phase 2 — iccanalyzer-lite report (automated script)
Run the analysis script to generate the full report:

```bash
./analyze-profile.sh test-profiles/<filename>.icc
```

This script runs all 3 analysis commands (`-a`, `-nf`, `-r`), captures exit codes and ASAN/UBSAN output, and writes the complete report to `analysis-reports/`. Do NOT run the 3 commands individually.

#### Commit and PR
1. `git add analysis-reports/ && git commit -m "Analysis: <profile-name>"`
2. Update the PR description with:
   - **MCP Tool Analysis** section (from Phase 1)
   - **iccanalyzer-lite Results** section with exit code summary from the script
   - ASAN/UBSAN findings noted prominently if detected
3. Post each report as a comment on the originating issue:
   ```bash
   gh issue comment <ISSUE_NUMBER> --body "$(cat analysis-reports/<profile>-analysis.md)"
   ```

The script exits with the worst exit code across all 3 commands. Exit 0 = clean, 1 = finding, 2 = error.

### Code coverage for a single profile
Use `iccdev-single-profile-coverage.yml` (NOT `ci-code-coverage.yml`) for per-profile coverage. The full coverage workflow runs `CreateAllProfiles.sh` which pollutes results with hundreds of generated profiles. The single-profile workflow accepts a `profile_path` input (relative to `test-profiles/`) and runs only IccDumpProfile, IccRoundTrip, XML round-trip, and IccApplyProfiles against that one file.

### Docker Web UI

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:dev
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:dev web
```

Open http://localhost:8080/ — provides browser-based access to all analysis tools. The entrypoint command is `web` (not `icc-profile-web`).

### Developer Demo Container

```bash
docker pull ghcr.io/xsscx/icc-profile-demo:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-demo
```

Open http://localhost:8080/ — self-contained HTML demo report with live API at `/api/*`. Three modes: `demo` (default), `api` (production WebUI), `mcp` (stdio). Build locally with `docker build -f Dockerfile.demo -t icc-profile-demo .`

**REST API endpoints** (same parameter names as MCP tools):

| Endpoint | Method | Parameters |
|----------|--------|------------|
| `/api/health` | GET | — |
| `/api/list` | GET | `directory` |
| `/api/inspect` | GET | `path` |
| `/api/security` | GET | `path` |
| `/api/roundtrip` | GET | `path` |
| `/api/full` | GET | `path` |
| `/api/xml` | GET | `path` |
| `/api/compare` | GET | `path_a`, `path_b` |
| `/api/upload` | POST | `file` (multipart) |

### Available MCP Tools — Detailed Reference

**Analysis tools (exposed to coding agent via `copilot-mcp-config.json`):**

| Tool | Args | Description |
|------|------|-------------|
| `inspect_profile` | `path` | Full structural dump using ninja-full mode. Shows header fields, tag table, tag data values. Use for understanding what's inside a profile. |
| `analyze_security` | `path` | 27-heuristic security scan (H1–H27). Detects size inflation, invalid signatures, tag overlaps, CLUT bombs, MPE chain depth, TagArrayType UAF risk, repeat-byte fuzz artifacts, spectral anomalies, date validation. |
| `validate_roundtrip` | `path` | Check AToB/BToA, DToB/BToD, and Matrix/TRC tag pairs. Validates bidirectional transform completeness required by ICC spec. |
| `full_analysis` | `path` | Runs all 3 modes (`-a`, `-nf`, `-r`) in one call. Use this for comprehensive analysis. Equivalent to `./analyze-profile.sh`. |
| `profile_to_xml` | `path` | ICC→XML conversion via iccToXml. Falls back to iccToXml_unsafe for malformed profiles. Output is the XML representation of the profile. |
| `compare_profiles` | `path_a`, `path_b` | Ninja-full dump of both profiles with unified diff. Use to spot structural differences between two ICC profiles. |
| `list_test_profiles` | `directory` (default: `test-profiles`) | Lists `.icc` files in the given directory. Also accepts `extended-test-profiles`. |
| `upload_and_analyze` | `data_base64`, `filename`, `mode` | Upload a base64-encoded ICC profile and analyze it. Modes: `security` (default), `inspect`, `roundtrip`, `full`, `xml`. Temp file auto-cleaned after analysis. |

**Maintainer build tools (local/VS Code only — NOT exposed to coding agent):**

| Tool | Args | Description |
|------|------|-------------|
| `build_tools` | — | Build native analysis tools from source |
| `cmake_configure` | build type, sanitizers, generator, tools | Configure iccDEV cmake |
| `cmake_build` | build dir | Build iccDEV with cmake --build |
| `create_all_profiles` | — | Run CreateAllProfiles.sh from Testing/ directory |
| `run_iccdev_tests` | — | Run RunTests.sh test suite |
| `cmake_option_matrix` | — | Test cmake option toggles independently |
| `windows_build` | — | Windows MSVC + vcpkg build |

### MCP Tool Usage — Best Practices

**Path resolution**: All analysis tools accept either:
- An absolute path: `/home/user/profiles/test.icc`
- A filename from `test-profiles/`: just pass `sRGB_D65_MAT.icc` and the server resolves it
- A relative path from the repo root: `test-profiles/sRGB_D65_MAT.icc`

**Choosing the right tool**:
- Start with `analyze_security` for quick security triage (fastest, most actionable)
- Use `full_analysis` for complete reports destined for issues/PRs
- Use `inspect_profile` to understand profile structure (what tags exist, header fields)
- Use `validate_roundtrip` to check spec compliance (AToB↔BToA pairs)
- Use `profile_to_xml` to get human-readable XML for manual inspection
- Use `compare_profiles` when investigating regressions or differences between profile versions

**Upload workflow**: When a user provides an ICC profile via an issue attachment:
1. Download the attachment (may be `.icc.txt` — GitHub blocks `.icc`)
2. Use `upload_and_analyze` with the file content base64-encoded and `mode: "full"`
3. Alternatively, save to `test-profiles/` and use `full_analysis` with the path

**Interpreting results**:
- Exit code 0 = clean profile, no findings
- Exit code 1 = heuristic finding(s) detected — review the `[WARN]` and `[CRITICAL]` lines
- Exit code 2 = error (I/O failure, parse error, or profile too malformed to process)
- Look for `[H1]`–`[H19]` prefixes to identify which heuristic triggered
- ASAN/UBSAN output in stderr indicates a real memory safety bug — this is a CRITICAL finding

**Automated issue→PR→merge pipeline**: When Copilot coding agent processes an analysis issue:
1. Create issue with ICC profile to analyze, then assign Copilot via GitHub UI (Assignees sidebar)
   Note: `gh issue create --assignee copilot` and REST API assignment do **not** work. Use the GitHub web UI.
2. Agent uses MCP tools (`inspect_profile`, `analyze_security`, `validate_roundtrip`, `profile_to_xml`) for independent analysis
3. Agent runs `./analyze-profile.sh` for the full iccanalyzer-lite report
4. Agent commits the report to `analysis-reports/`, opens a draft PR with both MCP and script findings
5. When the agent's workflow run completes, `copilot-auto-merge.yml` triggers via `workflow_run[completed]`
6. The auto-merge workflow finds the PR by branch, marks it ready, and squash-merges it
7. The originating issue is closed via `Fixes #N` in the PR body

No manual intervention required — the entire pipeline is hands-free from issue to merge.

## Architecture

This repo contains security research tools targeting the ICC color profile specification via the iccDEV library (formerly DemoIccMAX):

- **cfl/** — 19 LibFuzzer harnesses, each scoped to a specific ICC project tool's API surface. Fuzzers must only call library APIs reachable from their corresponding tool (see Fuzzer→Tool Mapping in README.md).
- **iccanalyzer-lite/** — 27-heuristic static/dynamic security analyzer (v2.9.1) built with full sanitizer instrumentation. 14 C++ modules compiled in parallel. Deterministic exit codes: 0=clean, 1=finding, 2=error, 3=usage.
- **colorbleed_tools/** — Intentionally unsafe ICC↔XML converters used as CodeQL targets for mutation testing. Output paths validated against `..` traversal.
- **mcp-server/** — Python FastMCP server (stdio transport) + Starlette web UI wrapping iccanalyzer-lite and colorbleed_tools. 15 tools: 9 analysis + 6 maintainer (cmake configure/build, option matrix, CreateAllProfiles, RunTests, Windows build). Multi-layer path traversal defense, output sanitization, upload/download size caps. Default binding: 127.0.0.1. 3 custom Python CodeQL queries (subprocess injection, path traversal, output sanitization).
- **cfl/patches/** — 61 security patches (001–061) applied to iccDEV before fuzzer builds. Includes OOM caps (16MB–128MB), UBSAN fixes, heap-buffer-overflow guards, stack-overflow depth caps, null-deref guards, memory leak fixes, float-to-int overflow clamps, alloc/dealloc mismatch corrections, and recursion depth limits. 5 no-op patches (023, 028, 039, 040, 058 — upstream-adopted). See `cfl/patches/README.md` for full details.
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
31 workflows use `workflow_dispatch` (manual trigger). Actions are 100% SHA-pinned. Key workflows:
- `copilot-auto-merge.yml` — Auto squash-merges Copilot coding agent PRs on agent `workflow_run` completion
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

### Workflow Shell Prologue
All workflow `run:` steps must follow the governance shell prologue template:
```yaml
shell: bash --noprofile --norc {0}
env:
  BASH_ENV: /dev/null
run: |
  set -euo pipefail
  source .github/scripts/sanitize-sed.sh 2>/dev/null || true
```
- `shell` and `BASH_ENV` may be set at the job level via `defaults.run.shell` and job-level `env`
- `set -euo pipefail` must be the first line of every `run:` block
- `source .github/scripts/sanitize-sed.sh` is required in every step that writes to `$GITHUB_STEP_SUMMARY`
- Reference: `https://github.com/xsscx/governance/blob/main/actions/hoyt-bash-shell-prologue-actions.md`

### Workflow Output Sanitization
All data written to `$GITHUB_STEP_SUMMARY` or `$GITHUB_OUTPUT` must be sanitized against injection:
- Source `.github/scripts/sanitize-sed.sh` to make sanitization functions available
- Use `sanitize_line()` for single-line user-controllable strings (strips control chars, HTML-escapes, truncates)
- Use `sanitize_print()` for multi-line output (preserves LF, collapses blanks, HTML-escapes)
- Use `sanitize_codeblock()` inside markdown fenced code blocks (strips control chars, no HTML escape)
- Use `sanitize_ref()` for branch/tag names in filenames or concurrency groups
- Use `sanitize_filename()` for safe filenames (no directory traversal)
- User-controllable inputs include: `${{ inputs.* }}`, `${{ github.event.* }}`, `${{ steps.*.outputs.* }}`, command output via `$(...)`, file contents via `cat`
- Static strings (hardcoded labels, job status values) are safe but the sanitizer should still be sourced for defense-in-depth

## Image+ICC Seed Pipeline

### Tool Ecosystem
| Tool | Repo | Platform | Purpose |
|------|------|----------|---------|
| xnuimagetools | github.com/xsscx/xnuimagetools | iOS/macOS/watchOS/visionOS | Create baseline images across XNU platforms |
| xnuimagefuzzer | github.com/xsscx/xnuimagefuzzer | iOS/macOS (Xcode) | Fuzz images via 12 CGCreateBitmap functions |
| iOSOnMac CLI | macos-research/code/iOSOnMac | macOS (CLI) | Run xnuimagefuzzer at scale via posix_spawn |
| colorbleed_tools | research/colorbleed_tools | Linux/macOS | Build ICC profiles (iccToXml/iccFromXml) |
| seed-pipeline.sh | .github/scripts/seed-pipeline.sh | Linux | Validate, embed ICC, distribute seeds |
| craft-seeds.py | .github/scripts/craft-seeds.py | Linux | Generate synthetic edge-case image seeds |

### Workflow
1. Create baseline images → **xnuimagetools** (macOS)
2. Fuzz images → **xnuimagefuzzer** (macOS) — produces 9 pixel formats × 6 output formats
3. Transfer fuzzed images to Linux (place in `temp/`)
4. Validate + embed ICC → **seed-pipeline.sh** `temp/ --distribute --ramdisk`
5. Generate synthetic seeds → **craft-seeds.py** `--outdir temp/icc-crafted`
6. Re-seed ramdisk → `.github/scripts/ramdisk-seed.sh`

### Pipeline Scripts

```bash
# Validate images, embed 15 ICC profiles, distribute to seed corpuses
.github/scripts/seed-pipeline.sh <image-dir> [--distribute] [--ramdisk]

# Generate synthetic edge-case seeds (tiny, 16-bit, float, tiled, BigTIFF, etc.)
python3 .github/scripts/craft-seeds.py --outdir temp/icc-crafted --profiles test-profiles
```

### Quality Gates (seed-pipeline.sh)
- Reject files < 64 bytes (truncated)
- Reject images with < 5 unique pixel values (flat/degenerate)
- Validate TIFF magic bytes (II\*/MM\* or BigTIFF)
- Deduplicate by MD5 content hash
- Enforce max size = 5MB (max\_len limit)

### Known Issues with xnuimagefuzzer Output
- 32BitFloat and HDR float fuzzed variants produce all-zero pixels (CoreGraphics clamps float→8-bit)
- `LittleEndian-image.tiff` is actually big-endian (MM) — name refers to CGColorSpace component order
- Base images have NO embedded ICC profiles by design — the pipeline adds them
