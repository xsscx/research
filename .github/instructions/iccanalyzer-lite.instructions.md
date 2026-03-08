---
applyTo: "iccanalyzer-lite/**"
---

# iccanalyzer-lite — Path-Specific Instructions

## What This Is

A 141-heuristic ICC profile security analyzer (16,000+ LOC, C++17) built with full
ASAN+UBSAN+Coverage instrumentation. It validates ICC color profiles against
ICC.1-2022-05 and ICC.2-2023 specifications, detecting CVE patterns, CWE violations,
malformed structures, and potential exploitation vectors.

**v3.4.0**: Added TIFF image analysis — auto-detects TIFF files in `-a` mode, extracts
embedded ICC profiles (TIFFTAG_ICCPROFILE tag 34675), reports TIFF metadata and security
checks, scans pixel data for xnuimagefuzzer injection signatures, then runs full
141-heuristic analysis (H1-H138 on ICC + H139-H141 on TIFF) on extracted ICC profiles. New explicit `-img` mode available.

## Build

```bash
cd iccanalyzer-lite && ./build.sh    # ASAN+UBSAN+coverage, uses 32 cores
```

- Compiler: clang++ 18+ with `-fsanitize=address,undefined`
- Requires: libxml2-dev, libtiff-dev, libclang-rt-18-dev
- The build links against the **unpatched** upstream iccDEV library at `iccDEV/Build/`
- iccanalyzer-lite does NOT use CFL patches — it handles all user-controllable
  inputs through its own defensive programming (bounds checks, size validation,
  ASAN+UBSAN instrumentation, signal recovery, heuristic guards)
- Output: `iccanalyzer-lite/iccanalyzer-lite` (32MB with debug info)

## Build System Sync — 7 Locations

When adding new `.cpp` modules, ALL 7 build locations must be updated:

| # | File | Variable | Notes |
|---|------|----------|-------|
| 1 | `iccanalyzer-lite/build.sh` | `SOURCES=` | Primary local build |
| 2 | `iccanalyzer-lite/CMakeLists.txt` | `add_executable()` | CI/IDE builds |
| 3 | `.github/workflows/codeql-security-analysis.yml` | `SRCS=` | + linker flags |
| 4 | `.github/workflows/iccanalyzer-cli-release.yml` | `SOURCES=` | + linker flags |
| 5 | `.github/workflows/iccanalyzer-lite-coverage-report.yml` | `SOURCES=` | + linker flags |
| 6 | `.github/workflows/iccanalyzer-lite-debug-sanitizer-coverage.yml` | `SOURCES=` | + linker flags |
| 7 | `.github/workflows/mcp-server-test.yml` | `SRCS=` | + linker flags |

For `IccImageAnalyzer.cpp`, also add `-ltiff` to linker flags in all CI workflows.

## Test

```bash
python3 iccanalyzer-lite/tests/run_tests.py   # 172 unit tests, ~25s
```

- Tests use synthesized ICC profiles in `iccanalyzer-lite/tests/corpus/`
- Profile synthesis: `python3 iccanalyzer-lite/tests/synthesize_profiles.py`
- When adding heuristics, update the test for `summary.141_heuristics` pattern

## Architecture — 4 Modules (3 Heuristic + 1 Image Analysis)

| Module | Heuristics | API Level |
|--------|-----------|-----------|
| `IccAnalyzerSecurity.cpp` | H1-H8, H15-H17 | Raw header bytes, orchestrator |
| `IccHeuristicsLibrary.cpp` | H9-H32, H56-H138 | CIccProfile library API |
| `IccHeuristicsRawPost.cpp` | H33-H55, H57-H69 | Raw file I/O fallback |
| `IccImageAnalyzer.cpp` | H139-H141 | TIFF image security, metadata, ICC extraction, injection scan |

- Entry point: `RunSecurityHeuristics()` in `IccAnalyzerSecurity.cpp`
- When the library fails to load a malformed profile, raw fallback runs H10/H13/H25/H28/H32
- Gate: if `heuristicCount >= kCriticalHeuristicThreshold`, library phase is skipped

## Adding a New Heuristic

1. Choose the next ID: **H139** (current max is H138)
2. Add function declaration to `IccHeuristicsLibrary.h`
3. Implement in `IccHeuristicsLibrary.cpp` (append after H138)
4. Wire dispatch in `IccAnalyzerSecurity.cpp` (after H138 call)
5. Update heuristic count (138→139) in these files:
   - `IccAnalyzerSecurity.cpp` — CVE Coverage printf
   - `iccanalyzer-lite/tests/run_tests.py` — `summary.141_heuristics`
   - `.github/copilot-instructions.md` — multiple locations
   - `README.md` — two locations
   - `.github/prompts/analyze-icc-profile.prompt.yml`
   - `mcp-server/icc_profile_mcp.py`
   - `.github/workflows/iccanalyzer-lite-unit-tests.yml`
6. Add ICC spec citation in printf: `ICC.1-2022-05 §X.Y.Z`

### Implemented TIFF Heuristics (H139-H141)

**H139: TIFF Strip Geometry Validation** — Validates TIFF strip buffer geometry:
`StripByteCounts >= RowsPerStrip × Width × SamplesPerPixel × (BitsPerSample/8)`,
`RowsPerStrip <= Height`, integer overflow checks in strip size calculations.
CWE-122/CWE-190. Detects the exact bug pattern fixed by CFL-082.

**H140: TIFF Dimension and Sample Validation** — Validates TIFF dimensions
(Width, Height ≤ 65535), BitsPerSample (1/8/16/32), SamplesPerPixel (≤ 6),
and cross-checks dimension × sample products for integer overflow.
CWE-400/CWE-131.

**H141: TIFF IFD Offset Bounds** — Validates all TIFF IFD tag data offsets
point within the file. Detects file truncation attacks where TIFF headers reference
data beyond EOF. CWE-125.

### Candidate Heuristics (Not Yet Implemented)

**H142: TIFF Multi-IFD Chain Depth** — Limit the number of IFD pages followed
to prevent infinite loops from circular IFD next-pointers. CWE-835.

**H143: TIFF Tile Geometry Validation** — For tiled TIFFs, validate TileWidth,
TileLength, and TileByteCounts consistency. CWE-122/CWE-131.

## Heuristic Categories

| Range | Module | Focus |
|-------|--------|-------|
| H1-H8 | IccAnalyzerSecurity.cpp | Raw header (size, magic, version, reserved bytes) |
| H9-H32 | IccHeuristicsLibrary.cpp | Library API (tags, color spaces, rendering intents) |
| H33-H55 | IccHeuristicsRawPost.cpp | Raw file I/O (tag overlaps, embedded images, duplicates) |
| H56-H135 | IccHeuristicsLibrary.cpp | Spec compliance (ICC.1-2022-05 required tags, LUT validation) |
| H136-H138 | IccHeuristicsLibrary.cpp | CWE-400 complexity (ResponseCurve, grid, calculator) |
| H139-H141 | IccImageAnalyzer.cpp | TIFF image security (strip geometry, dimension/sample validation, IFD bounds) |

## Image Analysis (v3.4.0+)

The `-a` mode auto-detects image files via magic bytes and routes to `IccImageAnalyzer.cpp`.
The explicit `-img` mode also available. Currently supports TIFF; PNG/JPEG planned.

### TIFF Analysis Pipeline
1. **Metadata**: dimensions, BPS, SPP, compression, photometric, planar config,
   sample format, orientation, strip/tile layout, software, datetime
2. **Security checks**: extreme dimensions (>65535), zero dimensions, unusual BPS
   (not 1/8/16/32), excessive SPP (>6), strip offset bounds, multi-IFD page counting
3. **Injection scan**: 10 xnuimagefuzzer INJECT_STRING patterns (buffer overflow,
   XSS, SQLi, format string, path traversal, XXE), ICC mutation strategy markers,
   BigTIFF-in-TIFF type confusion
4. **ICC extraction**: TIFFTAG_ICCPROFILE (tag 34675) → temp file → full
   ComprehensiveAnalyze() with all 141 heuristics

### Format Detection (magic bytes)
- TIFF LE: `II\x2a\x00` (0x49492a00)
- TIFF BE: `MM\x00\x2a` (0x4d4d002a)
- BigTIFF LE: `II\x2b\x00` (0x49492b00)
- BigTIFF BE: `MM\x00\x2b` (0x4d4d002b)
- PNG: `\x89PNG` (0x89504e47)
- JPEG: `\xff\xd8\xff` (0xffd8ff)
- ICC: `acsp` at offset 36 (0x61637370)

### Usage
```bash
# Auto-detect (TIFF → image analyzer, ICC → profile analyzer)
./iccanalyzer-lite -a image.tif

# Explicit image analysis mode
./iccanalyzer-lite -img image.tif
```

## Heuristic Output Format

Every heuristic MUST follow this pattern:
```
[H<N>] <Title> (<spec reference>)
      <detail lines>
      [OK] <success message>    OR
      [WARN]  HEURISTIC: <finding> — ICC.1-2022-05 §X.Y
       CWE-<N>: <description>
```

## ICC Specification References — Sources of Truth

- **ICC.1-2022-05**: v2/v4 profile structure, header fields §7.2, tag table §7.3, tag types §10
- **ICC.2-2023**: v5 profiles, spectral PCS, calculator elements, MPE
- **ADGC spec** (April 2025): Adaptive Gain Curve tag, RGB+Input/Display only
- Header field map: §7.2.2 size, §7.2.4 version, §7.2.5 class, §7.2.6 colorSpace,
  §7.2.7 PCS, §7.2.9 magic, §7.2.10 platform, §7.2.11 flags, §7.2.15 intent,
  §7.2.16 illuminant, §7.2.18 profileID, §7.2.19 reserved bytes 100-127

## Pre-Push Validation (MANDATORY)

1. `cd iccanalyzer-lite && ./build.sh` — must succeed
2. `python3 iccanalyzer-lite/tests/run_tests.py` — all tests pass
3. ASAN spot-check on 5+ diverse profiles — 0 failures
4. `gh api /repos/xsscx/research/code-scanning/alerts` — 0 open alerts
5. Only then: `git push`

## Common Pitfalls

- `std::string(wstr.begin(), wstr.end())` triggers UBSAN when wchar_t > 127 —
  use `static_cast<char>(static_cast<unsigned char>(wc & 0xFF))`
- When extracting ICC signatures into `char[5]`, always cast through `unsigned char`:
  `sigCC[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));`
  Direct assignment `sigCC[0] = (sig >> 24) & 0xFF` or C-cast `(char)(...)` triggers
  UBSAN implicit-conversion when byte value > 127
- `icGetSpaceSamples()` returns declared channel count, but malformed LUTs can
  have `m_nOutput > declared` — always use `tmpPixel[16]` sized buffers
- H111 reserved bytes are 100-127 (NOT 84-127; 84-99 is Profile ID)
- H112 D50 values are ICC s15Fixed16 (0.9642/1.0/0.8249), NOT CIE (0.9505/1.0/1.089)
- Don't modify for-loop counter inside loop body (CodeQL cpp/loop-variable-changed)

## Coverage Instrumentation

- Uses clang source-based coverage: `-fprofile-instr-generate -fcoverage-mapping`
- NOT gcov (`--coverage` / `-fprofile-arcs -ftest-coverage`)
- Collect: `LLVM_PROFILE_FILE=output_%m_%p.profraw ./iccanalyzer-lite -a profile.icc`
- Merge: `llvm-profdata-18 merge -sparse *.profraw -o merged.profdata`
- Report: `llvm-cov-18 report ./iccanalyzer-lite -instr-profile=merged.profdata`
- `%m` = binary hash (same for all runs of same binary — use sequential filenames for batch)
- Baseline: Lines 70.54%, Functions 63.54%, Branches 61.21%

## UBSAN Status

- 0 analyzer-code UBSAN errors
- Remaining upstream iccDEV UBSAN: IccCAM.cpp div-by-zero, IccProfile.cpp div-by-zero,
  IccTagLut.cpp signed overflow — these are NOT in analyzer code
