# iccDEV WASM Build — Reference Documentation

## Overview

The iccDEV ICC color profile library compiles to WebAssembly via Emscripten,
producing 14 browser/Node.js-ready tools. All builds live on the `wasm` branch
of `InternationalColorConsortium/iccDEV`.

**npm package**: [`iccdev`](https://www.npmjs.com/package/iccdev)
**Branch**: `wasm` (rebased onto `master` at `4df1fe0`)
**Tools built**: 14 (28 artifacts: 14 `.js` + 14 `.wasm`)

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

## ELF-Only Flag Stripping

The iccDEV `CMakeLists.txt` adds native Linux hardening flags that produce
`wasm-ld` warnings. These are stripped via `sed` at build time — the CMakeLists.txt
is NOT permanently modified (it must remain valid for native builds).

| Flag | CMakeLists.txt Line | Warning |
|------|-------------------|---------|
| `-Wl,-z,relro,-z,now` | 928 | `wasm-ld: warning: unknown -z value: relro/now` |
| `-fstack-protector-strong` | 924 | Unsupported for WASM target |
| `-fstack-clash-protection` | 925 | Unsupported for WASM target |

**Resolution**: CMakeLists.txt has `if(EMSCRIPTEN)` platform guards that skip these flags
automatically. No `sed` stripping needed — the cmake build system handles it natively.

## CI Workflows

### ci-wasm-build-test.yml (PR trigger)

- **Triggers**: PRs to `master` or `cfl`, manual dispatch
- **Matrix**: `[Release, Debug, Asan]`
- **Runner**: `ubuntu-24.04` (pinned)
- **Timeout**: 30 minutes
- **Builds deps from source**: zlib, libjpeg, libpng, libtiff, libxml2, nlohmann-json
- **Validation**: WASM magic number check + Node.js smoke test

### wasm-latest-matrix.yml (dispatch only)

- **Triggers**: Manual dispatch only
- **Matrix**: `[Release, Debug, Asan]`
- **Runner**: `ubuntu-24.04` (pinned)
- **Timeout**: 30 minutes
- **Same build pattern** as ci-wasm-build-test.yml
- **Artifact upload**: `.js` + `.wasm` + `.a` files, 7-day retention

### Security Hardening (both workflows)

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

### 3. ELF hardening flags in CMakeLists.txt

The CMakeLists.txt adds `-Wl,-z,relro,-z,now`, `-fstack-protector-strong`,
and `-fstack-clash-protection`. These produce dozens of `wasm-ld: warning`
lines. Strip them with `sed` before cmake — do NOT permanently remove them
from CMakeLists.txt (needed for native builds).

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

### 7. test.icc for smoke tests

The wasm.sh build copies `Testing/sRGB_D65_MAT.icc` → `wasm-pages/test.icc`.
If this file is missing, `test_all.js` and CI smoke tests fail.

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
c8c6fe6 ci: harden WASM workflows — security review + alignment
9157b39 wasm: integrate wasm-pages assembly into build script
af9862a wasm-pages: fresh HTML/JS demo pages for all 14 WASM tools
2315e76 wasm: align script and workflows for all 3 build configs
60087d5 fix: wasm.sh checkout correct branch name
e30da88 Add WASM build script for iccDEV project
4df1fe0 (origin/master) ... upstream master HEAD
```

4 unpushed commits above `60087d5` (as of 2026-03-17).
