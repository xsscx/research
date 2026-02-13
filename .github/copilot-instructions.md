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

# MCP server tests
cd mcp-server && ./build.sh test
# Or individually:
cd mcp-server && python test_mcp.py    # ~195 tests
cd mcp-server && python test_web_ui.py  # ~124 tests

# colorbleed_tools tests
cd colorbleed_tools && make test
```

## Fuzzing

```bash
# Ramdisk workflow (mounts 4GB tmpfs, seeds corpus, runs all 17 fuzzers)
cd cfl && ./ramdisk-fuzz.sh

# Single fuzzer on ramdisk
cfl/bin/icc_profile_fuzzer -max_total_time=60 -rss_limit_mb=4096 \
  -dict=cfl/icc_profile.dict /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer

# Corpus merge/minimize
cfl/bin/icc_profile_fuzzer -merge=1 /tmp/fuzz-ramdisk/corpus-merged /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer

# Validate seed corpus readiness
cd cfl && ./test-seed-corpus.sh
```

## Architecture

This repo contains security research tools targeting the ICC color profile specification via the iccDEV (DemoIccMAX) library:

- **cfl/** — 17 LibFuzzer harnesses, each scoped to a specific ICC project tool's API surface. Fuzzers must only call library APIs reachable from their corresponding tool (see Fuzzer→Tool Mapping in README.md).
- **iccanalyzer-lite/** — 19-heuristic static/dynamic security analyzer built with full sanitizer instrumentation. 14 C++ modules compiled in parallel.
- **colorbleed_tools/** — Intentionally unsafe ICC↔XML converters used as CodeQL targets for mutation testing.
- **mcp-server/** — Python MCP server + Starlette web UI wrapping iccanalyzer-lite and colorbleed_tools. Multi-layer path traversal defense, output sanitization, upload/download size caps.
- **cfl/patches/** — OOM mitigation patches (001–005) applied to iccDEV before fuzzer builds. All cap allocations at 128MB (patch 005 caps hex dumps at 256KB).
- **cfl/iccDEV/** — Cloned upstream DemoIccMAX library (patched at build time, not committed patched).
- **test-profiles/** and **extended-test-profiles/** — ICC profile corpora for fuzzing and regression testing.

Each iccDEV subdirectory (under cfl/, iccanalyzer-lite/, colorbleed_tools/) is an independent clone of the upstream library — they are not shared.

## Key Conventions

### Fuzzer structure
Every fuzzer implements `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` with:
- Early return on size bounds: `if (size < MIN || size > MAX) return 0;`
- Temp file via `mkstemp()` → `write()` → `close()` → process → `unlink()`
- Error/warning handlers suppressed during fuzzing
- Optional `LLVMFuzzerInitialize()` for one-time setup

### Fuzzer scope alignment
Each fuzzer must only exercise APIs reachable from its corresponding project tool. For example:
- `icc_profile_fuzzer` / `icc_spectral_fuzzer` must NOT use `CIccCmm` (AddXform/Begin/Apply)
- `icc_deep_dump_fuzzer` must NOT call FindColor/FindDeviceColor/FindPcsColor
- See the Fuzzer→Tool Mapping table in README.md

### Dictionary files
- Format: LibFuzzer dict format with `\xNN` hex escapes only (no octal, no inline comments)
- Lookup order in CI: `cfl/${FUZZER_NAME}.dict` → `cfl/icc_core.dict` → `cfl/icc.dict`
- Use `.github/scripts/convert-libfuzzer-dict.py` to convert raw LibFuzzer recommended dictionary output

### OOM patches
Named `NNN-brief-description.patch` in `cfl/patches/`. Applied automatically by `cfl/build.sh` before cmake. All cap allocations at 128MB.

### Sanitizer flags
- **Fuzzers**: `-fsanitize=fuzzer,address,undefined -fprofile-instr-generate -fcoverage-mapping`
- **iccanalyzer-lite**: `-fsanitize=address,undefined,float-divide-by-zero,float-cast-overflow,integer -g3 -O0 --coverage`
- Both the iccDEV libs AND the tool linking them must use matching sanitizer flags
- Suppress LLVM profile errors during fuzzing: `LLVM_PROFILE_FILE=/dev/null`

### Byte-shift patterns
`(data[i] << 24)` causes signed integer overflow when `data[i] >= 128`. Fix: `static_cast<icUInt32Number>(data[i]) << 24`. Similarly, use `tagOffset <= fileSize - tagSize` instead of `tagOffset + tagSize <= fileSize`.

### MCP server security patterns
- Path validation: allowlist of base dirs + symlink resolution + normpath checks
- Subprocess: `asyncio.create_subprocess_exec` (never `shell=True`), minimal env vars
- Output: strip control chars/ANSI, 10MB cap. Uploads: 20MB cap, temp dir with 700 mode
- CSP with per-request nonce, strict security headers

### CI workflows
All 25 workflows use `workflow_dispatch` (manual trigger). Actions are 100% SHA-pinned. Key workflows:
- `libfuzzer-smoke-test.yml` — 60-second smoke test for all 17 fuzzers
- `cfl-libfuzzer-parallel.yml` — Extended parallel fuzzing with dict auto-selection
- `codeql-security-analysis.yml` — 15 custom queries × 3 targets + security-and-quality
- `iccanalyzer-cli-release.yml` — CLI test suite + release artifacts
- `mcp-server-test.yml` — MCP server unit tests

### CodeQL
15 custom queries shared across cfl/, iccanalyzer-lite/, and colorbleed_tools/ (buffer-overflow, integer-overflow, XXE, UAF, type-confusion, enum UB, unchecked I/O, injection, etc.). Config in each target's `codeql-config.yml`.

### Compiler
All C++ code requires clang/clang++. GCC is used only in the colorbleed_tools CI matrix build.
