# Copilot Instructions for Research Repository

## Overview

This is a security research project focused on **ICC color profile** analysis, fuzzing, and vulnerability discovery. It contains three main tools and a fuzzing infrastructure, all built with Clang and heavy sanitizer instrumentation.

## Projects

| Directory | Tool | Purpose |
|-----------|------|---------|
| `iccanalyzer-lite/` | iccAnalyzer-lite | Static ICC profile security analyzer with 4 analysis modes |
| `cfl/` | LibFuzzer harnesses | 16 fuzzing targets for ICC profile attack surfaces |
| `colorbleed_tools/` | iccToXml_unsafe / iccFromXml_unsafe | Intentionally unsafe ICC↔XML converters for research |
| `fuzz/` | — | Public attack payload corpus (XML, JSON, shell, SQLi, etc.) |
| `xif/` | — | Fuzzer-generated crash samples for regression testing |

## Build Commands

### iccanalyzer-lite

```bash
cd iccanalyzer-lite

# Script build (preferred — includes ASAN+UBSAN+coverage)
./build.sh

# CMake build
cmake -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=RelWithDebInfo .
cmake --build . -j$(nproc)
```

### colorbleed_tools

```bash
cd colorbleed_tools
make setup    # Clone iccDEV, patch wxWidgets, build static libs
make          # Build iccToXml_unsafe + iccFromXml_unsafe
make test     # Roundtrip conversion test
make clean    # Remove build artifacts
make distclean  # Remove everything including iccDEV clone
```

### cfl (fuzzing harnesses)

```bash
cd cfl
./build.sh        # Clones iccDEV, builds all 16 fuzzers
./build.sh clean  # Clean build artifacts
```

## Running Tests

### iccanalyzer-lite modes

```bash
# Single profile, specific mode:
./iccanalyzer-lite -h profile.icc   # Heuristic security analysis
./iccanalyzer-lite -r profile.icc   # Round-trip validation
./iccanalyzer-lite -a profile.icc   # Comprehensive analysis
./iccanalyzer-lite -n profile.icc   # Ninja mode (minimal output)
./iccanalyzer-lite -nf profile.icc  # Ninja mode (file-based)

# Batch test all profiles:
for f in ../test-profiles/*.icc; do ./iccanalyzer-lite -h "$f"; done
```

### Fuzzer execution

```bash
cd cfl
./bin/icc_profile_fuzzer corpus/ -max_total_time=60 -detect_leaks=0 -rss_limit_mb=4096
```

### Test profiles

- `test-profiles/` — Clean, curated ICC profiles for validation
- `extended-test-profiles/` — Crash PoCs, CVE samples, and edge cases
- `xif/` — Raw fuzzer crash corpus for regression testing

## Compiler Flags & Sanitizers

All projects use **Clang** with this standard instrumentation stack:

```
-fsanitize=address,undefined    # ASAN + UBSAN (always on)
-fno-omit-frame-pointer         # Full stack traces
-g -O1                          # Debug symbols, light optimization
-fprofile-arcs -ftest-coverage  # GCov coverage
-fprofile-instr-generate -fcoverage-mapping  # Clang source coverage
-std=c++17
```

Fuzzers additionally use `-fsanitize=fuzzer`.

## Ninja Mode Detection

Ninja modes (`-n`, `-nf`) always exit 0. To detect findings programmatically, grep output for: `MISMATCH`, `overlap`, `Suspicious`, `UAF RISK`, `INVALID`, `CORRUPT`.

## Code Conventions

- **C++17** throughout, exception-free design (no try/catch)
- **Naming**: PascalCase classes (`CIccProfile`), camelCase methods, `pIcc` pointer prefix, `m_` member prefix
- **File layout**: `.cpp` + `.h` pairs in same directory; each fuzzer is a self-contained `.cpp`
- **iccDEV dependency**: Cloned at build time from GitHub, with wxWidgets patched out
- **Memory**: Manual `new`/`delete`; `volatile` variables used to prevent dead-code elimination by sanitizers
- **Error handling**: Integer return codes (0 = success); string-based report accumulation
- **Sanitize user input**: `.github/scripts/sanitize-sed.sh` provides `sanitize_line`, `sanitize_ref`, `sanitize_filename` functions for CI workflows

## Fuzzing Dictionaries

Custom `.dict` and `.options` files live alongside each fuzzer in `cfl/`. The root `test.dict` and `new.dict` contain ICC-specific tokens for profile structure fuzzing.

## MCP Server

`mcp-server/` contains a Python MCP server and REST Web UI for interactive ICC profile analysis.

### Architecture

| Component | File | Purpose |
|-----------|------|---------|
| MCP Server | `icc_profile_mcp.py` | 7 MCP tools wrapping iccanalyzer-lite and iccToXml |
| Web UI Backend | `web_ui.py` | Starlette REST API with nonce-based CSP |
| Web UI Frontend | `index.html` | Single-page dark-themed UI, vanilla JS, zero dependencies |
| MCP Tests | `test_mcp.py` | 195 security + functional tests |
| Web UI Tests | `test_web_ui.py` | 124 endpoint, header, and security tests |
| Packaging | `pyproject.toml` | PyPI packaging with `hatchling` backend |

### MCP Tools

| Tool | Mode | Description |
|------|------|-------------|
| `inspect_profile` | `-nf` | Raw header dump, tag table, structure |
| `analyze_security` | `-h` | 14-phase security heuristic scan |
| `validate_roundtrip` | `-r` | Bidirectional transform validation |
| `full_analysis` | `-a` | Comprehensive combined analysis |
| `profile_to_xml` | iccToXml | ICC→XML conversion (3-tier: pre-generated → safe → unsafe) |
| `compare_profiles` | `-nf` ×2 | Unified diff of two profiles |
| `list_test_profiles` | — | List available profiles with sizes |

### Build & Test

```bash
# Quick start (build script handles iccDEV clone, compile, venv setup)
cd mcp-server
./build.sh              # Build everything
./build.sh test         # Run 195 MCP + 124 Web UI tests
./build.sh web          # Start Web UI → http://0.0.0.0:8000
./build.sh web 8080     # Custom port
./build.sh web 8080 IP  # Specific IP and port
./build.sh mcp          # Start MCP stdio server

# Manual build (from repo root)
cd iccanalyzer-lite && git clone --depth 1 https://github.com/InternationalColorConsortium/DemoIccMAX.git iccDEV
cd iccDEV/Build && cmake Cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -std=c++17" \
  -DENABLE_TOOLS=ON -DENABLE_STATIC_LIBS=ON -Wno-dev && make -j$(nproc)
cd ../.. && ./build.sh && cd ..
cd colorbleed_tools && ln -sf ../iccanalyzer-lite/iccDEV iccDEV && make && cd ..

# Install & test MCP server
cd mcp-server && pip install -e ".[dev]"
ASAN_OPTIONS=detect_leaks=0 python test_mcp.py      # 195 tests
ASAN_OPTIONS=detect_leaks=0 python test_web_ui.py    # 124 tests

# Run servers
ASAN_OPTIONS=detect_leaks=0 python web_ui.py --host 0.0.0.0 --port 8080  # Web UI
```

### Security Model (10 rounds of hardening)

The MCP server processes untrusted binary files (fuzzer crash samples, CVE PoCs). Key protections:

- **Path traversal**: `Path.resolve()` + `relative_to()` against allowed base dirs
- **Symlink boundary**: resolved targets must stay within allowed directories
- **Null byte rejection**: explicit check before any filesystem access
- **Command injection**: all subprocess via `asyncio.create_subprocess_exec` (no shell)
- **Output sanitization**: 3-layer — ANSI strip → control char strip → blank line collapse
- **Subprocess isolation**: minimal env (PATH, HOME=/nonexistent, LANG, ASAN_OPTIONS only)
- **CSP nonce**: per-request `secrets.token_urlsafe(32)` nonce for inline script/style
- **No inline handlers**: all `onclick`/`style=""` converted to `addEventListener`/CSS classes
- **Upload security**: 20MB limit, random-prefix filenames (0o600), secure temp dir (0o700)
- **Body size pre-check**: Content-Length validated before parsing upload/download bodies
- **Docker**: non-root `mcp` user, minimal runtime image, only `.so*` libs copied

### Important Conventions

- `ASAN_OPTIONS=detect_leaks=0` is **required** when running the MCP server or tests — the ASAN-instrumented binaries can crash the Python process otherwise
- `MallocNanoZone=0` suppresses macOS malloc warnings
- Web UI caches `index.html` on first request; restart server after HTML changes
- SSE endpoint requires `allowed_hosts=['*']` and `allowed_origins=['*']` for LAN access
- The `_validate_path()` function in `web_ui.py` allows absolute paths **only** if they resolve into the upload temp directory
- Profile path resolution searches: repo root → test-profiles → extended-test-profiles → xif → fuzz/graphics/icc → reference-profiles → upload dir

## CI Workflows

Key workflows in `.github/workflows/`:

| Workflow | Purpose |
|----------|---------|
| `mcp-server-test.yml` | Build iccDEV + tools, run 195 MCP + 124 Web UI tests, wheel + Docker → Release |
| `mcp-server-release.yml` | PyPI + GitHub Release + ghcr.io Docker publish |
| `iccanalyzer-lite-debug-sanitizer-coverage.yml` | Build + test all 4 modes + coverage report |
| `cfl-libfuzzer-parallel.yml` | Parallel fuzzing (16 fuzzers, configurable duration/sanitizer) |
| `colorbleed-tools-build.yml` | Build validation for unsafe tools |
| `clusterfuzzlite.yml` | Google ClusterFuzz integration |
| `codeql-security-analysis.yml` | CodeQL security scanning |
| `iccanalyzer-cli-release.yml` | iccAnalyzer CLI test suite → Release |
| `colorbleed-tools-release.yml` | ColorBleed tools test suite → Release |

### Cross-Workflow Patterns (Known-Good References)

These patterns are validated across multiple workflows. When creating or modifying workflows, reference these as canonical examples.

#### wxWidgets Sed Patch (REQUIRED for any iccDEV cmake build)

iccDEV's `CMakeLists.txt` has `find_package(wxWidgets REQUIRED)`. Comment out 3 lines before cmake:

```bash
sed -i 's/^  find_package(wxWidgets/#  find_package(wxWidgets/' Build/Cmake/CMakeLists.txt
sed -i 's/^      ADD_SUBDIRECTORY(Tools\/wxProfileDump)/#      ADD_SUBDIRECTORY(Tools\/wxProfileDump)/' Build/Cmake/CMakeLists.txt
sed -i 's/^    message(FATAL_ERROR "wxWidgets not found/#    message(FATAL_ERROR "wxWidgets not found/' Build/Cmake/CMakeLists.txt
```

**Used in**: `mcp-server-test.yml:66-68`, `mcp-server-release.yml:66-68`, `clusterfuzzlite.yml:91-93`, `cfl-libfuzzer-parallel.yml:102-104`, `Dockerfile:23-25`

#### Sanitizer Linker Flags (REQUIRED when linking against ASAN-instrumented iccDEV)

When iccDEV static libs are built with `-fsanitize=address,undefined`, downstream linking **must** also pass those flags or the linker fails with undefined `__asan_*`/`__ubsan_*` symbols:

```bash
make clean all \
  CXXFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -std=gnu++17 -Wall" \
  LINK_LIBS="-fsanitize=address,undefined -lxml2 -lz -llzma -lm"
```

**Used in**: `mcp-server-test.yml:96-97`, `mcp-server-release.yml:96-97`

#### Ubuntu 24.04 Package List (canonical for iccDEV builds)

```
build-essential cmake clang-18 llvm-18 libxml2-dev libtiff-dev
libjpeg-dev libpng-dev zlib1g-dev liblzma-dev nlohmann-json3-dev
libssl-dev python3 python3-venv python3-pip
```

**Docker additionally needs**: `libclang-rt-18-dev` (ASAN runtime static libs), `file`, `git`

#### Clang Compiler Symlinks

`iccanalyzer-lite/build.sh` hardcodes `export CXX=clang++`. When only `clang++-18` is available (Docker, minimal CI images), create symlinks:

```bash
ln -sf /usr/bin/clang++-18 /usr/local/bin/clang++
ln -sf /usr/bin/clang-18 /usr/local/bin/clang
```

### MCP Server Test Workflow (`mcp-server-test.yml`)

Triggers: push to `mcp` branch, pull requests to `main`/`mcp`, manual dispatch.

10 steps:
1. Checkout
2. Install system deps (clang-18, cmake, libxml2-dev, etc.)
3. Build iccDEV libraries + tools (`-DENABLE_TOOLS=ON -DENABLE_SHARED_LIBS=ON`)
4. Install safe iccToXml from iccDEV build
5. Build iccanalyzer-lite (`CXX=clang++-18 ./build.sh`)
6. Build colorbleed_tools (symlinks iccDEV from step 3 — no second clone)
7. Setup Python venv + install MCP SDK
8. Run MCP test suite (195 tests)
9. Run Web UI security + functional tests (124 tests)
10. Summary to `$GITHUB_STEP_SUMMARY`

**Known gotcha**: `$GITHUB_STEP_SUMMARY` must NOT be backslash-escaped in YAML `|` blocks.

### MCP Server Release Workflow (`mcp-server-release.yml`)

Triggers: tag push `v*`, manual `workflow_dispatch` with `publish_pypi` / `publish_ghcr` checkboxes.

5 jobs (dependency chain: test → build-wheel → publish-pypi / github-release / publish-docker):

| Job | Depends On | Runs When |
|-----|-----------|-----------|
| `test` | — | Always (gate for all publishing) |
| `build-wheel` | test | Always |
| `publish-pypi` | build-wheel | Tag push OR manual `publish_pypi=true` |
| `github-release` | build-wheel | Tag push only |
| `publish-docker` | test | Tag push OR manual `publish_ghcr=true` |

**Permissions**: Top-level `contents: write` + `packages: write`. `publish-pypi` overrides with job-level `id-token: write` for PyPI trusted publishing (OIDC).

**Prerequisites**: PyPI trusted publishing requires a `pypi` environment in GitHub Settings → Environments linked to the pypi.org project.

## Reference Profiles

`reference-profiles/` contains 206 ICC profiles + 205 pre-generated XML files built from iccDEV's `Testing/CreateAllProfiles.sh`. These provide instant XML responses without subprocess calls.

## Distribution

| Method | Status |
|--------|--------|
| PyPI (`pip install icc-profile-mcp`) | `pyproject.toml` ready, hatchling backend |
| Docker (`docker build -t icc-profile-mcp .`) | Multi-stage Dockerfile, non-root runtime |
| GitHub Container Registry | `ghcr.io/xsscx/icc-profile-mcp` via release workflow |
| VS Code | `.vscode/mcp.json` configured |
| Claude Desktop | Config snippet in README |
| GitHub Copilot CLI | Config snippet in README |

### Docker Build & Run

```bash
# Build
docker build -t icc-profile-mcp .

# Run MCP server (stdio, for Claude Desktop / VS Code)
docker run --rm -i icc-profile-mcp

# Run Web UI (HTTP on port 8080)
docker run --rm -p 8080:8080 icc-profile-mcp icc-profile-web --host 0.0.0.0 --port 8080
```

### Docker Architecture

Multi-stage build: `ubuntu:24.04` builder → `ubuntu:24.04` runtime.

**Builder stage** installs full toolchain (clang-18, cmake, libclang-rt-18-dev), clones iccDEV, applies wxWidgets sed patch, builds all 3 tools with ASAN+UBSAN.

**Runtime stage** copies only:
- `iccanalyzer-lite` binary (ASAN statically linked by Clang — no shared ASAN lib needed)
- `iccToXml` (safe) + `iccToXml_unsafe` binaries
- `libIccProfLib2.so*` + `libIccXML2.so*` shared libs
- Test profiles, reference profiles, Python MCP server

**Known Docker gotchas**:
- `ICC_MCP_ROOT=/app` env var is **required** — when installed via pip, `__file__.parent.parent` resolves to the venv's `site-packages`, not the app root
- `ASAN_OPTIONS=detect_leaks=0` set in runtime ENV — ASAN-instrumented binaries crash Python if leak detection is enabled
- Builder needs `libclang-rt-18-dev` for ASAN static libs, `nlohmann-json3-dev` for iccDEV cmake, and `file` for build.sh's `file` command
- `clang++` / `clang` symlinks to versioned binaries are needed because `build.sh` hardcodes `export CXX=clang++`
- Runtime image uses `curl` for health checks; `libxml2` pulls in `libicu74` transitively

### Publishing

```bash
# PyPI + GitHub Release + Docker — all at once:
git tag v0.1.0
git push origin v0.1.0

# Manual selective publish:
gh workflow run mcp-server-release.yml --field publish_pypi=true --field publish_ghcr=true
```
