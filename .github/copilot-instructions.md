# Copilot Instructions -- ICC Security Research

Cross-cutting rules for ALL components. Component-specific details live in
path-specific instruction files that auto-load when you touch those paths.

## Documentation Routing

| Component | Instructions | Key Commands |
|-----------|-------------|--------------|
| iccanalyzer-lite/ | [iccanalyzer-lite.instructions.md](instructions/iccanalyzer-lite.instructions.md) | `cd iccanalyzer-lite && ./build.sh` / `python3 tests/run_tests.py` |
| cfl/ | [cfl.instructions.md](instructions/cfl.instructions.md) | `cd cfl && ./build.sh` / `./fuzz-local.sh` |
| mcp-server/ | [mcp-server.instructions.md](instructions/mcp-server.instructions.md) | `python mcp-server/launch.py mcp` / `python mcp-server/launch.py web` |
| fuzz/ | [fuzz.instructions.md](instructions/fuzz.instructions.md) | Seed corpus (input data only) |
| colorbleed_tools/ | [colorbleed_tools.instructions.md](instructions/colorbleed_tools.instructions.md) | `cd colorbleed_tools && make setup && make` |
| afl/ | [afl.instructions.md](instructions/afl.instructions.md) | `./afl/build.sh` / `./afl/start.sh dump` |
| call-graph/ | [call-graph.instructions.md](instructions/call-graph.instructions.md) | `python3 scripts/generate-callgraphs.py` |
| Multi-agent | [multi-agent.instructions.md](instructions/multi-agent.instructions.md) | Platform detection, handoff protocols |
| CI governance | [workflow-governance.instructions.md](instructions/workflow-governance.instructions.md) | Shell hardening, sanitizer functions |

Task-specific prompt templates live in `.github/prompts/` (19 files).
Reference docs live in `docs/` (shell helpers, PoC techniques, specifications).

## Architecture

Security research tools targeting the ICC color profile spec via the iccDEV library.

| Component | Purpose |
|-----------|---------|
| **iccanalyzer-lite/** | 180-heuristic security analyzer (ASAN+UBSAN). Links **unpatched** upstream iccDEV. |
| **cfl/** | 13 LibFuzzer harnesses + security patches applied to a separate iccDEV clone. |
| **mcp-server/** | 28-tool MCP server (FastMCP) + REST API + WebUI wrapping the analyzer. |
| **colorbleed_tools/** | Intentionally unsafe ICC-to-XML converters (no ASAN -- tests real-world crash surface). |
| **fuzz/** | 1,139 curated malicious input files (CVE PoCs, injection signatures, malformed media). |
| **afl/** | AFL++ tool-level fuzzing of unpatched upstream iccDEV CLI tools. |
| **call-graph/** | LLVM-based call graphs + AST dumps for 37 compilation targets. |
| **test-profiles/** | ICC profiles for fuzzing and regression testing. |

**CRITICAL -- Two iccDEV checkouts exist with DIFFERENT purposes:**

| Path | Purpose | Patched? |
|------|---------|----------|
| `iccDEV/` | Upstream reference (UNPATCHED, Debug+ASAN+UBSAN+Coverage) | No |
| `cfl/iccDEV/` | CFL fuzzer build (security patches applied) | Yes |

For crash fidelity testing, ALWAYS use `iccDEV/Build/Tools/` (unpatched).
If upstream doesn't crash but the fuzzer does, it's a fuzzer alignment issue.

## Key Counts (update ALL sync locations when changed)

| Metric | Value | Sync details |
|--------|-------|--------------|
| Heuristics | 180 | See iccanalyzer-lite.instructions.md |
| MCP tools | 28 (13 analysis + 7 maintainer + 6 ops + 2 graph) | See mcp-server.instructions.md |
| CFL fuzzers | 13 | cfl.instructions.md |
| iccDEV advisories | 113 (87 CVEs + 95 GHSAs) | Use `--registry` for live counts |
| Build locations | 7 | iccanalyzer-lite.instructions.md Build System Sync |

Authoritative counts come from `./iccanalyzer-lite --registry | jq`.

## Build Commands

```bash
# Prerequisites: clang/clang++ 18+, cmake 3.15+, libxml2-dev, libtiff-dev,
#   libpng-dev, libjpeg-dev, libssl-dev, libclang-rt-18-dev

# iccanalyzer-lite (ASAN + UBSAN + coverage)
cd iccanalyzer-lite && ./build.sh

# CFL fuzzers (clones iccDEV if missing, applies patches, builds 13 fuzzers)
cd cfl && ./build.sh

# colorbleed_tools (intentionally unsafe -- no ASAN)
cd colorbleed_tools && make setup && make

# AFL-instrumented upstream tools
./afl/build.sh

# MCP server
cd mcp-server && python3 -m venv .venv && .venv/bin/pip install -e .

# iccDEV upstream tools (ALWAYS Debug+ASAN+UBSAN -- never Release)
cd iccDEV/Build && cmake Cmake \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON -DENABLE_COVERAGE=ON
make -j$(nproc)
```

### Environment Detection

- **Cloud CI**: `copilot-setup-steps.yml` pre-builds everything. Do NOT run build scripts.
- **Local/WSL-2**: Build before use. First action: `ls -la iccanalyzer-lite/iccanalyzer-lite`

## Test Commands

```bash
# iccanalyzer-lite
python3 iccanalyzer-lite/tests/run_tests.py
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  ./iccanalyzer-lite/iccanalyzer-lite -a test-profiles/sRGB_D65_MAT-500lx.icc

# MCP server
cd mcp-server && .venv/bin/python test_mcp.py
cd mcp-server && .venv/bin/python test_web_ui.py

# CFL fuzzer smoke test (60s)
ASAN_OPTIONS=detect_leaks=0 cfl/bin/icc_dump_fuzzer \
  -max_total_time=60 -timeout=30 -rss_limit_mb=4096 cfl/corpus-icc_dump_fuzzer/

# iccDEV upstream tool
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile test-profiles/sRGB_D65_MAT-500lx.icc ALL

# CodeQL (pre-installed -- do NOT re-install gh-codeql or re-download packs)
gh codeql database analyze /tmp/codeql-db-analyzer \
  --format=sarif-latest --output=/tmp/codeql-results.sarif --threads=0 \
  codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls \
  iccanalyzer-lite/codeql-queries/
```

## MCP Server Quick Reference

28 tools for AI-assisted ICC profile security analysis. See
[mcp-server.instructions.md](instructions/mcp-server.instructions.md) for full details.

**Key tools**: `analyze_security` (180-heuristic scan), `full_analysis` (all modes),
`inspect_profile`, `validate_roundtrip`, `profile_to_xml`, `compare_profiles`,
`upload_and_analyze`.

**Run locally**: `python mcp-server/launch.py mcp` (stdio) or `python mcp-server/launch.py web` (REST+UI on :8080)

**Docker**: `docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web`
Image MUST have ASAN+UBSAN. Never add `NO_SANITIZERS=1`. Apple Silicon: Docker Desktop only.

**Path resolution**: filename (`sRGB_D65_MAT.icc`), relative, or absolute path.
GitHub blocks `.icc` attachments -- rename to `.icc.txt` before uploading.

**Exit codes**: 0=clean, 1=finding, 2=error, 3=usage. Exit 1 is NOT a crash.

## ICC Profile Analysis Workflow

When analyzing an ICC profile, use the automated script:

```bash
.github/scripts/analyze-profile.sh test-profiles/<filename>.icc
```

This runs all 3 analysis modes (`-a`, `-nf`, `-r`), captures ASAN/UBSAN output,
and writes the report to `analysis-reports/`.

For TIFF images, use `-a` mode which auto-detects format and extracts embedded ICC.

## ICC Specification Constants (ICC.1-2022-05)

```
Header:     128 bytes (offsets 0-127)
Magic:      'acsp' = 0x61637370 at bytes 36-39
Version:    BCD -- byte 8 = major, byte 9 = minor.bugfix (nibbles), bytes 10-11 = 0x0000
PCS D50:    X=0.9642, Y=1.0000, Z=0.8249 at bytes 68-79
Intent:     0=Perceptual, 1=Relative, 2=Saturation, 3=Absolute (bytes 64-67)
Reserved:   bytes 100-127 must be 0x00
ProfileID:  MD5 of entire profile with bytes 44-47, 64-67, 84-99 zeroed
Tag table:  starts at byte 128, 4-byte count + 12-byte entries (sig + offset + size)
Classes:    scnr(Input) mntr(Display) prtr(Output) link(DeviceLink) spac(ColorSpace)
            abst(Abstract) nmcl(NamedColor)
Required:   profileDescriptionTag, mediaWhitePointTag, copyrightTag
            + chromaticAdaptationTag if adopted white != D50
```

Primary spec: `https://www.color.org/specification/ICC.1-2022-05.pdf`

## Key Coding Conventions

### Exit code classification
- **0**: Success. **1-127**: Soft failure (graceful, NOT a crash).
- **128+**: Signal termination (crash). 134=SIGABRT, 139=SIGSEGV.
- The tool's exit code is authoritative. The fuzzer's DEADLYSIGNAL is a test artifact.

### UBSAN fix patterns
```cpp
// Widen to uint64_t before arithmetic to prevent overflow:
if ((uint64_t)tOff + 12 > fileSize) continue;

// Cast ICC signatures through unsigned char:
sigCC[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));

// Byte-shift overflow:
static_cast<icUInt32Number>(data[i]) << 24   // not: data[i] << 24
```

### NaN/float-to-integer safety
IEEE 754 NaN fails ALL ordered comparisons. Clamp functions pass NaN through.
```cpp
if (v != v) return 0.0;  // NaN check FIRST (self-inequality idiom)
if (v < 0.0) return 0.0;
if (v > 1.0) return 1.0;
return v;
```

### AddXform ownership semantics
`CIccCmm::AddXform(CIccProfile*)` transfers ownership. On `icCmmStatBadXform`,
the profile is already freed -- do NOT delete. On other errors, caller must delete.

### Non-fatal diagnostic macros
`IccAnalyzerCommon.h` overrides upstream `ICC_TRACE_NAN` (`__builtin_trap()`) and
`ICC_SANITY_CHECK_SIGNATURE` (`assert(false)`) to log-only via `#undef`/`#define`.

### Sanitizer flags
- **Fuzzers**: `-fsanitize=fuzzer,address,undefined`
- **iccanalyzer-lite**: `-fsanitize=address,undefined,float-divide-by-zero,float-cast-overflow,integer -g3 -O0`
- Both iccDEV libs AND the linking tool must use matching sanitizer flags
- Suppress profraw during fuzzing: `LLVM_PROFILE_FILE=/dev/null`

### Style rules
- No emojis in code/CI/reports. Use `[OK]`, `[WARN]`, `[FAIL]`, `[SKIP]`, `[CRITICAL]`.
- All C++ requires clang/clang++. GCC only in colorbleed_tools CI matrix.
- Scripts go in `.github/scripts/` (build scripts stay with their component).
- 4-space indent in C++ and Python. Tabs only in Makefiles.

### Known upstream UBSAN (iccDEV library, not our code)
- `IccCAM.cpp:262,266,283` -- div-by-zero (CFL-077 fixes)
- `IccProfile.cpp:3153,3155` -- div-by-zero
- `IccTagLut.cpp:5009` -- signed integer overflow
- `IccMpeBasic.cpp:1821,2446` -- NaN-to-unsigned cast
- `IccMpeCalc.cpp:1215` -- float-to-int overflow (CFL-022 fixes)

### CI conventions
- All actions are 100% SHA-pinned.
- Workflow `run:` steps must use `set -euo pipefail` as the first line.
- Source `.github/scripts/sanitize-sed.sh` in steps writing to `$GITHUB_STEP_SUMMARY`.
- With `set -euo pipefail`, use `EXIT_CODE=0; timeout ... || EXIT_CODE=$?` pattern.
- See [workflow-governance.instructions.md](instructions/workflow-governance.instructions.md)
  for shell prologue, output sanitization, and credential reduction details.

### Pre-push verification (iccanalyzer-lite changes)
```bash
cd iccanalyzer-lite && ./build.sh           # 1. Build
python3 tests/run_tests.py                   # 2. Test
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  ./iccanalyzer-lite -a ../test-profiles/sRGB_D65_MAT-500lx.icc  # 3. ASAN check
.github/scripts/pre-push-validate.sh         # 4. Verify 7 build locations
```

Step 4 is mandatory. A local `build.sh` success does NOT guarantee CI success.

## ASAN/UBSAN Attribution

When reporting ASAN/UBSAN findings, classify by **stack frame file path** (frame #2-#3),
NEVER by profile filename:
- Path contains `iccanalyzer-lite/`, `colorbleed_tools/`, `cfl/` (non-iccDEV) -- **OUR CODE**
- Path contains `iccDEV/` -- **UPSTREAM** -- cite file:line and upstream issue#
