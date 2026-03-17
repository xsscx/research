# iccDEV WASM Build — Reference Documentation

## Overview

The iccDEV ICC color profile library compiles to WebAssembly via Emscripten,
producing 14 browser/Node.js-ready tools. All builds live on the `wasm` branch
of `InternationalColorConsortium/iccDEV`.

**npm package**: [`iccdev`](https://www.npmjs.com/package/iccdev) (v2.3.5)
**Branch**: `wasm` (rebased onto `master` at `4df1fe0`)
**Tools built**: 14 (28 artifacts: 14 `.js` + 14 `.wasm`)
**CMake version**: `2.3.1.5` (4-part, extracted from individual components)
**npm version**: `2.3.5` (semver 3-part, independent of cmake)
**CI workflows**: 4 (see [CI Workflows](#ci-workflows))

## Quick Start

### Local Build (wasm.sh — recommended)

```bash
cd iccDEV
./wasm.sh                    # Release (default)
./wasm.sh --debug            # Debug with ASSERTIONS + SAFE_HEAP
./wasm.sh --sanitizer        # ASan with ASSERTIONS + STACK_OVERFLOW_CHECK
./wasm.sh --all              # All 3 configs sequentially
```

Build artifacts land in `wasm/iccDEV/Build-{release,debug,sanitizer}/Tools/`.
The script also assembles `wasm-pages/` with `.js`/`.wasm` copied in.

### Test with Node.js

```bash
cd wasm-pages
npm install        # installs http-server
npm test           # runs test_all.js — 14/14 tests
npm start          # serves at http://localhost:8088
```

### Browser Demo

```bash
cd wasm-pages && npx http-server . -p 8088 -c-1
# Browse http://localhost:8088
```

## 14 WASM Tools

| # | Tool | Input | Output | JSON Config |
|---|------|-------|--------|-------------|
| 1 | IccDumpProfile | `.icc` | Text dump | No |
| 2 | IccToXml | `.icc` | `.xml` | No |
| 3 | IccFromXml | `.xml` | `.icc` | No |
| 4 | IccRoundTrip | `.icc` | Validation text | No |
| 5 | IccFromCube | `.cube` | `.icc` | No |
| 6 | IccApplyNamedCmm | `.icc` + config | Transform output | **Yes** (`-cfg`) |
| 7 | IccApplyProfiles | `.icc` + TIFF + config | TIFF output | **Yes** (`-cfg`) |
| 8 | IccApplySearch | `.icc` + config | Search results | **Yes** (`-cfg`) |
| 9 | IccApplyToLink | `.icc` (multiple) | DeviceLink `.icc` | No |
| 10 | IccTiffDump | `.tiff` | Metadata text | No |
| 11 | IccJpegDump | `.jpg` | Metadata text | No |
| 12 | IccPngDump | `.png` | Metadata text | No |
| 13 | IccSpecSepToTiff | Spectral TIFFs | Separated TIFF | No |
| 14 | IccV5DspObsToV4Dsp | v5 `.icc` (×2) | v4 `.icc` | No |

**IccDEVCmm** is a Windows-only shared library — no WASM artifact produced.

## Build Configurations

### Release

```
Compiler: -O3
Linker:   -s INITIAL_MEMORY=128MB -s ALLOW_MEMORY_GROWTH=1
```

### Debug

```
Compiler: -g -O0 -sASSERTIONS=2 -sSAFE_HEAP=1 -sSTACK_OVERFLOW_CHECK=2
Linker:   -s INITIAL_MEMORY=256MB -s ALLOW_MEMORY_GROWTH=1 --source-map-base=./
```

### ASan (Sanitizer)

```
Compiler: -fsanitize=address -O1 -g -sASSERTIONS=2 -sSTACK_OVERFLOW_CHECK=2
Linker:   -fsanitize=address -s INITIAL_MEMORY=256MB -s ALLOW_MEMORY_GROWTH=1
```

**CRITICAL**: ASan and `SAFE_HEAP` are mutually exclusive in Emscripten.
`em++: error: ASan does not work with SAFE_HEAP`. The ASan config must NOT
include `-sSAFE_HEAP=1`.

## Critical Emscripten Flags

All builds MUST include these linker flags:

| Flag | Purpose | Consequence if missing |
|------|---------|----------------------|
| `-s MODULARIZE=1` | Creates factory function `createModule()` | Global pollution, can't control init |
| `-s EXPORT_NAME=createModule` | Names the factory function | Consumers can't find entry point |
| `-s INVOKE_RUN=0` | Prevents `main()` auto-execution | **Files passed via process.argv are opened before FS.writeFile — "Unable to open" errors** |
| `-s FORCE_FILESYSTEM=1` | Enables virtual filesystem API | `FS.writeFile()` / `FS.readFile()` unavailable |
| `-s EXPORTED_RUNTIME_METHODS=['FS','callMain']` | Exposes FS and callMain on module | Can't write files or invoke main |
| `-s ALLOW_MEMORY_GROWTH=1` | Dynamic memory expansion | OOM on large profiles |
| `-s INITIAL_MEMORY=128MB` (or 256MB) | Starting heap size | OOM on module init for complex tools |

### The INVOKE_RUN=0 Bug (Most Important Discovery)

Without `-s INVOKE_RUN=0`, this sequence fails:

```javascript
// BROKEN (without INVOKE_RUN=0):
const createModule = require('./iccToXml.js');
const mod = await createModule();
// ↑ main() already ran here using process.argv → "Unable to open 'test.icc'"
mod.FS.writeFile('input.icc', data);   // too late
mod.callMain(['input.icc', 'out.xml']); // works, but stderr already has error
```

With `INVOKE_RUN=0`, `main()` only runs when explicitly called via `callMain()`.

## CMake EMSCRIPTEN Platform Guard

The iccDEV `CMakeLists.txt` has native cmake guards for Emscripten — no `sed`
stripping or build-time CMakeLists.txt modification needed.

### Problem

Emscripten sets `UNIX=ON` and `APPLE=OFF`, causing WASM builds to fall into the
Linux platform block. That block adds ELF-only flags that produce `wasm-ld` warnings:

| Flag | Warning |
|------|---------|
| `-Wl,-z,relro,-z,now` | `wasm-ld: warning: unknown -z value: relro/now` |
| `-fstack-protector-strong` | Unsupported for WASM target |
| `-fstack-clash-protection` | Unsupported for WASM target |

### Solution (committed to CMakeLists.txt)

```cmake
# Line 908: Linux block now excludes Emscripten
elseif(UNIX AND NOT APPLE AND NOT EMSCRIPTEN)
    # Linux-specific ELF hardening flags...

# Lines 937-939: Dedicated Emscripten platform block
elseif(EMSCRIPTEN)
    message(STATUS "Emscripten (WASM) build — skipping platform-specific flags")
```

Additional guards:
- Line 83: `if(UNIX AND NOT APPLE AND NOT EMSCRIPTEN)` — sanitizer runtime detection
- Line 153: `if(EMSCRIPTEN)` — LTO check (`check_ipo_supported()` returns false for Emscripten)

### Version Extraction

CMakeLists.txt does **NOT** use `set(PROJECT_VERSION ...)`. Version is defined as
4 individual components:

```cmake
set(${PROJECT_UP_NAME}_MAJOR_VERSION 2)    # line 123
set(${PROJECT_UP_NAME}_MINOR_VERSION 3)    # line 124
set(${PROJECT_UP_NAME}_MICRO_VERSION 1)    # line 125
set(${PROJECT_UP_NAME}_PATCH_VERSION 5)    # line 126
```

CI workflows extract these individually:
```bash
MAJOR=$(grep '_MAJOR_VERSION' Build/Cmake/CMakeLists.txt | grep -oE '[0-9]+' | sed -n '1p')
MINOR=$(grep '_MINOR_VERSION' Build/Cmake/CMakeLists.txt | grep -oE '[0-9]+' | sed -n '1p')
MICRO=$(grep '_MICRO_VERSION' Build/Cmake/CMakeLists.txt | grep -oE '[0-9]+' | sed -n '1p')
PATCH=$(grep '_PATCH_VERSION' Build/Cmake/CMakeLists.txt | grep -oE '[0-9]+' | sed -n '1p')
VERSION="${MAJOR}.${MINOR}.${MICRO}.${PATCH}"   # → 2.3.1.5
```

## CI Workflows

Four workflows handle WASM builds, each serving a different purpose:

### 1. ci-wasm-build-test.yml (PR validation)

- **Triggers**: PRs to `master` or `cfl`, manual dispatch
- **Matrix**: `[Release, Debug, Asan]`
- **Runner**: `ubuntu-24.04` (pinned)
- **Timeout**: 30 minutes
- **Caching**: emsdk (`wasm-emsdk-Linux-v1`) + third-party deps (hash-keyed)
- **Builds deps from source**: zlib, libjpeg, libpng, libtiff, libxml2, nlohmann-json
- **Validation**: WASM magic number check + Node.js smoke test
- **npm pack**: validation on Release config only

### 2. wasm-latest-matrix.yml (WASM-only dispatch)

- **Triggers**: Manual dispatch only
- **Matrix**: `[Release, Debug, Asan]`
- **Runner**: `ubuntu-24.04` (pinned)
- **Timeout**: 30 minutes
- **Caching**: emsdk + third-party deps (shared cache keys with ci-wasm-build-test.yml)
- **Package job**: assembles npm package, runs 14/14 tests, npm pack, SBOM, attestation
- **GitHub Release**: creates `wasm-v{VERSION}` prerelease with tarball + SBOM
- **Artifact upload**: `.js` + `.wasm` + `.a` files, 7-day retention
- **npm publish**: commented out pending ICC npm account setup

### 3. ci-latest-release.yml (unified cross-platform release)

- **Triggers**: Manual dispatch only
- **Jobs**: `linux` (gcc/clang matrix), `macos`, `windows`, `wasm`, `release`
- **WASM job**: Release config only, emsdk + deps cached, creates zip/tarball/npm archives
- **Release job**: downloads all platform artifacts, creates unified GitHub Release tag `v{CMAKE_VERSION}`
- **Release assets**: 4 native platform zips + WASM zip + tarball + npm tgz + SHA-256 checksums
- **Version extraction**: 4-component grep from CMakeLists.txt (not `PROJECT_VERSION`)
- **Version alignment**: all platforms built from same commit

**Release `v2.3.1.5` assets**:
```
iccdev-linux-gcc-v2.3.1.5.zip
iccdev-linux-clang-v2.3.1.5.zip
iccdev-macos-clang-v2.3.1.5.zip
iccdev-windows-msvc-v2.3.1.5.zip
iccdev-wasm-v2.3.1.5.zip
iccdev-wasm-v2.3.1.5.tar.gz
iccdev-npm-v2.3.1.5.tgz
iccdev-wasm-v2.3.1.5.sha256sums.txt
SHA256SUMS-v2.3.1.5.txt
```

### 4. ci-comprehensive-build-test.yml (ci-build-matrix — full matrix)

- **Triggers**: Manual dispatch with branch selector (master, cfl, **wasm**)
- **WASM job**: `wasm-build` with matrix `[Release, Debug, Asan]`
- **Caching**: emsdk + third-party deps
- **Package assembly**: Release config only — copies 14 tools to wasm-pages/, runs Node.js tests
- **Artifact upload**: WASM build artifacts per config
- **Final summary**: includes WASM results alongside native platform results (linux, macos, windows, cmake-options)

### Dependency Caching Strategy (all 4 workflows)

| Cache | Key | Scope |
|-------|-----|-------|
| emsdk | `wasm-emsdk-${{ runner.os }}-v1` | Shared across all WASM workflows; bump `v1` to invalidate |
| third-party deps | `wasm-deps-${{ runner.os }}-${{ hashFiles(workflow) }}` | Per-workflow; auto-invalidates on workflow changes |

Third-party deps are built identically for all 3 build configs — one cache serves the entire matrix.
A "Verify third-party dependencies" step runs unconditionally as a safety net after cache restore.

### Security Hardening (all workflows)

| Protection | Implementation |
|------------|---------------|
| Shell injection prevention | `BASH_ENV: /dev/null` + `bash --noprofile --norc {0}` |
| Runner pinning | `ubuntu-24.04` (not `ubuntu-latest`) |
| Shallow clones | `--depth 1` for all dependency repos |
| Concurrency control | `cancel-in-progress: true` per branch |
| Artifact scoping | Only `*.js`, `*.wasm`, `*.a` uploaded |
| SIGPIPE safety | `sed -n '1,Np'` instead of `head -N` |

## wasm-pages/ Structure

```
wasm-pages/
├── .gitignore              # Excludes *.js, *.wasm build artifacts
├── index.html              # Landing page — 14 tools in 5 categories
├── index.js                # Node.js entry: module.exports = { IccDumpProfile, ... }
├── package.json            # npm package (v2.3.5), scripts: test, start
├── test_all.js             # 14-test Node.js suite (4 functional + 10 usage)
├── test.icc                # Test profile (copied from Testing/ during build)
├── IccDumpProfile/
│   ├── index.html          # Browser UI: upload → callMain → textarea output
│   ├── iccDumpProfile.js   # Emscripten glue (build artifact, gitignored)
│   └── iccDumpProfile.wasm # WASM binary (build artifact, gitignored)
├── IccToXml/
│   └── index.html          # Upload ICC → download XML
├── IccFromXml/
│   └── index.html          # Upload XML → download ICC
├── IccRoundTrip/
│   └── index.html          # Upload ICC → validation output
├── IccFromCube/
│   └── index.html          # Upload .cube → download ICC
├── IccApplyNamedCmm/
│   └── index.html          # Upload ICC + optional JSON config
├── IccApplyProfiles/
│   └── index.html          # Shows usage (needs multiple files)
├── IccApplySearch/
│   └── index.html          # Upload ICC + optional JSON config
├── IccApplyToLink/
│   └── index.html          # Shows usage (needs multiple profiles)
├── IccTiffDump/
│   └── index.html          # Upload TIFF → metadata dump
├── IccJpegDump/
│   └── index.html          # Upload JPEG → ICC extraction
├── IccPngDump/
│   └── index.html          # Upload PNG → ICC extraction
├── IccSpecSepToTiff/
│   └── index.html          # Shows usage (complex multi-file)
└── IccV5DspObsToV4Dsp/
    └── index.html          # Shows usage (needs 2 profiles)
```

### HTML Page Pattern

Every tool page follows the same pattern:

```javascript
// 1. Load module at page load (INVOKE_RUN=0 prevents main() auto-run)
let mod;
const script = document.createElement('script');
script.src = 'iccToolName.js';
script.onload = () => {
  createModule({
    print: (text) => { output.value += text + '\n'; },
    printErr: (text) => { output.value += '[stderr] ' + text + '\n'; }
  }).then(m => { mod = m; });
};

// 2. On file upload: write to WASM FS, then callMain
const data = new Uint8Array(e.target.result);
mod.FS.writeFile('input.icc', data);
try {
  mod.callMain(['input.icc']);
} catch (e) {
  if (e.name !== 'ExitStatus') throw e;
}

// 3. For tools with output files: read from WASM FS
const xmlData = mod.FS.readFile('output.xml');
```

### Design Decisions

- **Zero CDN dependencies** — all CSS inline, no external libraries
- **Dark navy header** (#1a237e) with "← All Tools" back link
- **ExitStatus handling** — `callMain()` throws `ExitStatus` on non-zero exit;
  this is normal (e.g., usage text) and must be caught
- **Complex tools** show usage text instead of upload form (ApplyProfiles,
  ApplyToLink, SpecSepToTiff, V5DspObsToV4Dsp need multiple input files)
- **Download buttons** use `Blob` + `URL.createObjectURL` pattern

## JSON Config Support in WASM

Three tools accept `-cfg config.json` for JSON-driven operation:

| Tool | JSON Config | Notes |
|------|------------|-------|
| IccApplyNamedCmm | ✅ | Full config support |
| IccApplyProfiles | ✅ | Full config support |
| IccApplySearch | ✅ | Full config support |
| IccApplyToLink | ❌ | Does NOT support JSON |

### WASM JSON Usage Pattern

```javascript
// Write ICC profiles to WASM FS directory structure
mod.FS.mkdir('test-profiles');
mod.FS.writeFile('test-profiles/sRGB_D65_MAT.icc', profileData);

// Write JSON config
mod.FS.writeFile('config.json', new TextEncoder().encode(jsonString));

// Run with -cfg flag
mod.callMain(['-cfg', 'config.json']);
```

### JSON Exception Handling

C++ exceptions from nlohmann::json on invalid JSON propagate as raw pointer
numbers in WASM (not ExitStatus). Must catch ALL exception types:

```javascript
try {
  mod.callMain(['-cfg', 'bad.json']);
} catch (e) {
  // e may be ExitStatus, a number (C++ exception pointer), or Error
  console.log('Caught:', typeof e === 'number' ? 'C++ exception' : e.message);
}
```

### Validated JSON Configs

11 valid configs in `docs/Testing/json-configs/` tested against WASM —
output is bit-exact identical to native builds.

24 malformed configs in `docs/Testing/malformed-json/` tested —
22/24 pass (2 expected C++ exceptions on intentionally invalid JSON).

## Build Dependencies

### wasm.sh (local build)

Uses Emscripten ports for zlib, libjpeg, libpng (`embuilder build --pic`).
Builds from source: libtiff, libxml2, nlohmann-json.

### CI workflows

Build ALL dependencies from source (no Emscripten ports):
- zlib (madler/zlib, `--depth 1`)
- libjpeg-turbo (libjpeg-turbo/libjpeg-turbo, `--depth 1`)
- libpng (pnggroup/libpng, `--depth 1`)
- libtiff (libsdl-org/libtiff, `--depth 1`)
- libxml2 (GNOME/libxml2, `--depth 1`)
- nlohmann-json (nlohmann/json, `--depth 1`, cmake build for `find_package()`)

### Required cmake Variables

```cmake
-DENABLE_TOOLS=ON
-DENABLE_STATIC_LIBS=ON
-DENABLE_SHARED_LIBS=OFF          # No shared libs in WASM
-DENABLE_TESTS=OFF                # Tests fail with cp errors in WASM
-DLIBXML2_INCLUDE_DIR=...
-DLIBXML2_LIBRARY=...
-DTIFF_INCLUDE_DIR=...
-DTIFF_LIBRARY=...
-DJPEG_INCLUDE_DIR=...
-DJPEG_LIBRARY=...
-DPNG_PNG_INCLUDE_DIR=...         # Note: PNG_PNG_INCLUDE_DIR (not just PNG_INCLUDE_DIR)
-DPNG_INCLUDE_DIR=...
-DPNG_LIBRARY=...
-DZLIB_INCLUDE_DIR=...
-DZLIB_LIBRARY=...
-Dnlohmann_json_DIR=...           # Path to nlohmann_jsonConfig.cmake
```

**Note**: `-DENABLE_TESTS=OFF` is required because the cmake test infrastructure
uses `cp` to stage test files, and `make check` fails with
`cp: cannot stat` errors in the WASM cross-compilation environment.

## Common Pitfalls

### 1. Missing INVOKE_RUN=0

Without this flag, `main()` auto-runs during module initialization using
`process.argv` as arguments. Files haven't been written to WASM FS yet,
causing "Unable to open" errors on stderr. The subsequent explicit
`callMain()` then succeeds because files exist by then — making the bug
appear as a harmless warning rather than a correctness issue.

### 2. ASan + SAFE_HEAP conflict

These are mutually exclusive in Emscripten. ASan config must NOT include
`-sSAFE_HEAP=1`. The error is:
```
em++: error: ASan does not work with SAFE_HEAP
```

### 3. ELF hardening flags in CMakeLists.txt (RESOLVED)

**Resolved** via native cmake guards — see [CMake EMSCRIPTEN Platform Guard](#cmake-emscripten-platform-guard).
CMakeLists.txt line 908: `AND NOT EMSCRIPTEN` guard + dedicated `elseif(EMSCRIPTEN)`
platform block at lines 937-939. No `sed` stripping needed.

### 4. nlohmann-json find_package

If nlohmann-json is downloaded as a single header file, cmake's
`find_package(nlohmann_json)` fails. Build nlohmann-json with cmake to
generate the `nlohmann_jsonConfig.cmake` file, then point to it with
`-Dnlohmann_json_DIR=<path>/share/cmake/nlohmann_json`.

### 5. PNG_PNG_INCLUDE_DIR

cmake's FindPNG module uses `PNG_PNG_INCLUDE_DIR` (note the doubled PNG).
Setting only `PNG_INCLUDE_DIR` may not be sufficient.

### 6. SIGPIPE in CI workflows

Never pipe Node.js or shell output through `head` in CI — it causes
SIGPIPE/SIGABRT. Use `sed -n '1,Np'` instead.

### 7. test.icc for smoke tests (RESOLVED)

`test_all.js` now self-generates a minimal valid ICC v4 profile header
(132 bytes: mntr/RGB/XYZ, D50 illuminant, 0 tags) when `test.icc` is
absent. This eliminates the CI dependency on `Testing/Display/sRGB_D65_MAT.icc`
which only exists when `-DENABLE_TESTS=ON` (not feasible in WASM cross-compile).
If `test.icc` exists (e.g., from a local wasm.sh build), it is used instead.

### 8. emsdk git tags vs SDK versions

emsdk repo tags are emsdk release versions (`5.0.3`), NOT Emscripten SDK
versions (`3.1.78`). **Never** use `--branch 3.1.78` when cloning emsdk.
Correct pattern: clone without `--branch`, then `./emsdk install latest`.

### 9. CMake PROJECT_VERSION does not exist

CMakeLists.txt does NOT use `set(PROJECT_VERSION ...)`. Using
`grep 'set(PROJECT_VERSION' CMakeLists.txt` finds NOTHING. Version is defined
as 4 individual `${PROJECT_UP_NAME}_*_VERSION` variables. See
[Version Extraction](#version-extraction) for the correct extraction pattern.

### 10. Dependency cache invalidation

If a CI WASM build fails with mysterious dep errors after workflow changes,
bump the emsdk cache key suffix (`wasm-emsdk-Linux-v1` → `v2`). The
third-party deps cache auto-invalidates on workflow file changes via
`hashFiles()`. The "Verify third-party dependencies" step catches stale
caches by checking for required headers and libraries.

## npm Package Publishing

The `wasm-pages/` directory IS the npm package. To publish:

```bash
# 1. Build Release
./wasm.sh

# 2. Verify artifacts are assembled
ls wasm-pages/IccDumpProfile/iccDumpProfile.{js,wasm}

# 3. Test
cd wasm-pages && npm test   # 14/14 pass

# 4. Publish (bump version in package.json first)
cd wasm-pages && npm publish
```

The `.gitignore` excludes `.js`/`.wasm` build artifacts from git, but
`package.json` `files` array includes them for npm publish.

## Verification Commands

```bash
# Count WASM tools built
find wasm/iccDEV/Build-release/Tools -name "*.js" | wc -l    # → 14
find wasm/iccDEV/Build-release/Tools -name "*.wasm" | wc -l  # → 14

# Validate WASM magic number
xxd -l4 wasm-pages/IccDumpProfile/iccDumpProfile.wasm | grep "0061 736d"

# Node.js smoke test
node -e "var m=require('./wasm-pages/IccDumpProfile/iccDumpProfile.js'); \
  m().then(function(M){M.callMain([]);})" 2>&1 | sed -n '1p'
# Expected: "Usage: iccDumpProfile {-v} {int} profile {tagId to dump/\"ALL\"}"

# Full test suite
cd wasm-pages && node test_all.js   # 14/14 PASS

# HTTP serving test
cd wasm-pages && npx http-server . -p 8088 -c-1 &
curl -s -o /dev/null -w '%{http_code}' http://localhost:8088/         # → 200
curl -s -o /dev/null -w '%{http_code}' http://localhost:8088/IccDumpProfile/  # → 200
```

## Git History (wasm branch)

```
e7f47e0 ci: add WASM build matrix to ci-build-matrix workflow
4cd20b5 fix: use cmake version components instead of PROJECT_VERSION
dd01caf ci: add WASM build + release job to ci-latest-release
c3a9206 wasm: complete WASM build infrastructure with demo pages and hardened CI
60087d5 fix: wasm.sh checkout correct branch name
e30da88 Add WASM build script for iccDEV project
4df1fe0 (origin/master) ... upstream master HEAD
```

Key changes by commit:

| Commit | Files Changed | Summary |
|--------|--------------|---------|
| `e7f47e0` | ci-comprehensive-build-test.yml | WASM 3-config matrix in ci-build-matrix, branch selector, final summary |
| `4cd20b5` | ci-latest-release.yml | Fix version extraction: 4-component grep (not PROJECT_VERSION) |
| `dd01caf` | ci-latest-release.yml | Add `wasm` job + `release` job for unified cross-platform release |
| `c3a9206` | 25 files (+2480 lines) | Squashed: wasm.sh fixes, CMakeLists.txt EMSCRIPTEN guard, wasm-pages/, CI workflows, caching, security hardening |
| `60087d5` | wasm.sh | Fix branch name (wasm, not wasm-latest-6a37766) |
| `e30da88` | wasm.sh | Initial WASM build script |

## CI Workflow Matrix

| Workflow | Trigger | WASM Configs | Release Artifacts | GitHub Release |
|----------|---------|-------------|-------------------|---------------|
| ci-wasm-build-test.yml | PR to master/cfl | Release, Debug, Asan | npm pack validation | No |
| wasm-latest-matrix.yml | dispatch | Release, Debug, Asan | tarball + SBOM | `wasm-v{VERSION}` |
| ci-latest-release.yml | dispatch | Release only | zip + tarball + npm tgz + checksums | `v{CMAKE_VERSION}` (unified) |
| ci-comprehensive-build-test.yml | dispatch | Release, Debug, Asan | per-config artifacts | No |

## Pinned Action SHAs

All CI workflows use SHA-pinned actions (no mutable tags):

| Action | SHA | Version |
|--------|-----|---------|
| actions/checkout | `11bd71901bbe5b1630ceea73d27597364c9af683` | v4.2.2 |
| actions/checkout | `c2d88d3ecc89a9ef08eebf45d9637801dcee7eb5` | (ci-latest-release) |
| actions/upload-artifact | `330a01c490aca151604b8cf639adc76d48f6c5d4` | v4.3.0 |
| actions/download-artifact | `fa0a91b85d4f404e444e00e005971372dc801d16` | v4.1.8 |
| actions/cache | `5a3ec84eff668545956fd18022155c47e93e2684` | v4.2.3 |
