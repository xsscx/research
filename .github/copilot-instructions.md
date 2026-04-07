# Copilot Instructions -- ICC Security Research

Cross-cutting rules for ALL components. Component-specific details live in
path-specific instruction files that auto-load when you touch those paths.
Task-specific workflows are available as skills in `.github/skills/`.

## Architecture

| Component | Purpose |
|-----------|---------|
| **iccanalyzer-lite/** | Security analyzer (ASAN+UBSAN). Links **unpatched** upstream iccDEV. |
| **cfl/** | 13 LibFuzzer harnesses + security patches on a separate iccDEV clone. |
| **mcp-server/** | MCP server (FastMCP) + REST API + WebUI wrapping the analyzer. |
| **colorbleed_tools/** | Intentionally unsafe ICC-to-XML converters (no ASAN). |
| **fuzz/** | Curated malicious input files (CVE PoCs, injection sigs, malformed media). |
| **afl/** | AFL++ tool-level fuzzing of unpatched upstream iccDEV CLI tools. |

**CRITICAL -- Two iccDEV checkouts with DIFFERENT purposes:**

| Path | Purpose | Patched? |
|------|---------|----------|
| `iccDEV/` | Upstream reference (UNPATCHED, Debug+ASAN+UBSAN+Coverage) | No |
| `cfl/iccDEV/` | CFL fuzzer build (security patches applied) | Yes |

For crash fidelity, ALWAYS use `iccDEV/Build/Tools/` (unpatched).

## Key Counts

Do NOT hardcode counts in documentation. Use `./iccanalyzer-lite --registry | jq`
for authoritative heuristic, CVE, and GHSA counts. When updating counts, sync
ALL locations listed in the relevant path-specific instructions file.

## Build Commands

```bash
# Prerequisites: clang/clang++ 18+, cmake 3.15+, libxml2-dev, libtiff-dev,
#   libpng-dev, libjpeg-dev, libssl-dev, libclang-rt-18-dev
cd iccanalyzer-lite && ./build.sh       # analyzer (ASAN+UBSAN+coverage)
cd cfl && ./build.sh                    # 13 fuzzers (clones iccDEV, applies patches)
cd colorbleed_tools && make setup && make # unsafe tools (no ASAN)
./afl/build.sh                          # AFL-instrumented upstream tools
cd mcp-server && pip install -e .       # MCP server
```

- **Cloud CI**: `copilot-setup-steps.yml` pre-builds everything. Do NOT run build scripts.
- **Local/WSL-2**: Build before use.

## Test Commands

```bash
python3 iccanalyzer-lite/tests/run_tests.py                    # analyzer tests
cd mcp-server && python test_mcp.py && python test_web_ui.py   # MCP tests
ASAN_OPTIONS=detect_leaks=0 cfl/bin/icc_dump_fuzzer \
  -max_total_time=60 -timeout=30 -rss_limit_mb=4096 \
  cfl/corpus-icc_dump_fuzzer/                                   # CFL smoke (60s)
```

## Coding Conventions

### Exit codes
- **0**: Success. **1-127**: Soft failure (NOT a crash).
- **128+**: Signal termination (crash). 134=SIGABRT, 139=SIGSEGV.
- The tool exit code is authoritative. The fuzzer DEADLYSIGNAL is a test artifact.

### Sanitizer flags
- **Fuzzers**: `-fsanitize=fuzzer,address,undefined`
- **Analyzer**: `-fsanitize=address,undefined,float-divide-by-zero,float-cast-overflow,integer -g3 -O0`
- Both iccDEV libs AND the linking tool must use matching sanitizer flags
- `-fsanitize=integer` required for unsigned overflow detection

### Style
- No emojis in code/CI/reports. Use `[OK]`, `[WARN]`, `[FAIL]`, `[SKIP]`, `[CRITICAL]`.
- All C++ requires clang/clang++.
- 4-space indent in C++ and Python. Tabs only in Makefiles.

### CI
- All actions 100% SHA-pinned.
- Every `run:` step: `set -euo pipefail` first line.
- Source `.github/scripts/sanitize-sed.sh` for `GITHUB_STEP_SUMMARY` writes.
- See `workflow-governance.instructions.md` for full shell hardening details.

### File output encoding
All generated files MUST be ASCII. Verify with `file FILENAME`.
Use `edit`/`create` tools for file writes (exact byte control),
never shell heredocs. See `AGENTS.md` for TUI encoding defect details.

## ASAN/UBSAN Attribution

Classify by **stack frame file path** (frame #2-#3), NEVER by profile filename:
- Path contains `iccanalyzer-lite/`, `colorbleed_tools/`, `cfl/` -- **OUR CODE**
- Path contains `iccDEV/` -- **UPSTREAM** -- cite file:line and upstream issue#

## Pre-push Verification

```bash
cd iccanalyzer-lite && ./build.sh           # 1. Build
python3 tests/run_tests.py                   # 2. Test
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  ./iccanalyzer-lite -a ../test-profiles/sRGB_D65_MAT-500lx.icc  # 3. ASAN check
.github/scripts/pre-push-validate.sh         # 4. Verify all build locations
```

Step 4 is mandatory. A local `build.sh` success does NOT guarantee CI success.
