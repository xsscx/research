---
applyTo: "iccanalyzer-lite/**"
---

# iccanalyzer-lite — Path-Specific Instructions

## What This Is

A 150-heuristic ICC profile security analyzer (22,000+ LOC across 30 C++ modules, C++17)
built with full ASAN+UBSAN+Coverage instrumentation. It validates ICC color profiles
against ICC.1-2022-05 and ICC.2-2023 specifications, detecting CVE patterns, CWE
violations, malformed structures, and potential exploitation vectors. Heuristics cover
44+ CWE categories and detect patterns from 48 CVEs across 93 iccDEV security advisories.

**v3.4.0**: Added TIFF image analysis — auto-detects TIFF files in `-a` mode, extracts
embedded ICC profiles (TIFFTAG_ICCPROFILE tag 34675), reports TIFF metadata and security
checks, scans pixel data for xnuimagefuzzer injection signatures, then runs full
150-heuristic analysis (H1-H138 ICC + H139-H141, H149-H150 TIFF + H142-H145 XML + H146-H148 data validation) on extracted ICC profiles. New explicit `-img` mode available.

## Build

```bash
cd iccanalyzer-lite && ./build.sh    # ASAN+UBSAN+coverage, uses 32 cores
```

- Compiler: clang++ 18+ with `-fsanitize=address,undefined`
- Requires: libxml2-dev, libtiff-dev, libpng-dev, libjpeg-dev, libssl-dev, libclang-rt-18-dev
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

**CRITICAL — Linker flag sync**: When adding new library dependencies (e.g., `-lssl -lcrypto`
for OpenSSL), ALL 7 locations must be updated. Pay special attention to
`iccanalyzer-cli-release.yml` which has its own **manual static LTO link command**
(line ~488) that is independent of `build.sh` — it will NOT automatically inherit
new flags. A local `build.sh` success does NOT guarantee CI success.

## Test

```bash
python3 iccanalyzer-lite/tests/run_tests.py   # 230 tests (19 functions), ~36s
```

- Tests use synthesized ICC profiles in `iccanalyzer-lite/tests/corpus/`
- Profile synthesis: `python3 iccanalyzer-lite/tests/synthesize_profiles.py`
- When adding heuristics, update the test for `summary.150_heuristics` pattern

## Architecture — 8 Heuristic Modules + 1 Image Analysis

After v3.6.0 refactoring, heuristics are organized into standalone functions across
8 category modules. Each heuristic is a `RunHeuristic_H##_Name()` function.

| Module | Heuristics | API Level |
|--------|-----------|-----------|
| `IccHeuristicsHeader.cpp` | H1-H8, H15-H17 | Raw header bytes (11 functions) |
| `IccHeuristicsTagValidation.cpp` | H9-H32 | Tag table structure via CIccProfile API |
| `IccHeuristicsRawPost.cpp` | H33-H55, H57-H69 | Raw file I/O fallback |
| `IccHeuristicsDataValidation.cpp` | H56-H102 | Data integrity via CIccProfile API |
| `IccHeuristicsProfileCompliance.cpp` | H103-H120 | ICC spec compliance |
| `IccHeuristicsIntegrity.cpp` | H121-H138 | Profile integrity + CWE-400 |
| `IccImageAnalyzer.cpp` | H139-H141, H149-H150 | TIFF/PNG/JPEG image security + ICC extraction |
| `IccHeuristicsXmlSafety.cpp` | H142-H145 | XML serialization safety |

### Support Modules

| Module | Purpose |
|--------|---------|
| `IccAnalyzerSecurity.cpp` | Orchestrator — `RunSecurityHeuristics()` dispatcher |
| `IccHeuristicsLibrary.cpp` | Thin dispatcher for H9-H138 (99 lines) |
| `IccHeuristicsLibrary.h` | Collector header including 4 sub-headers |
| `IccHeuristicsRegistry.h` | 150-entry metadata registry (id, name, specRef, CWE, CVE refs, phase, severity) |
| `IccHeuristicsHelpers.h` | `FindAndCast<T>()` template, `SigToChars()`, `ReadU32BE()`, `RawFileHandle` RAII |
| `IccAnalyzerJson.cpp/.h` | `--json` structured output mode |
| `IccAnalyzerReport.cpp/.h` | `--report` severity-sorted professional report |
| `IccAnalyzerXMLExport.cpp/.h` | `-xml` per-heuristic XML with dark-themed XSLT |

- Entry point: `RunSecurityHeuristics()` in `IccAnalyzerSecurity.cpp`
- When the library fails to load a malformed profile, raw fallback runs H10/H13/H25/H28/H32
- Gate: if `heuristicCount >= kCriticalHeuristicThreshold`, library phase is skipped

## Adding a New Heuristic

1. Choose the next ID: **H151** (current max is H150)
2. Add `RunHeuristic_H151_Name()` function to the appropriate category file:
   - Tag structure → `IccHeuristicsTagValidation.cpp`
   - Data integrity → `IccHeuristicsDataValidation.cpp`
   - Spec compliance → `IccHeuristicsProfileCompliance.cpp`
   - Profile integrity → `IccHeuristicsIntegrity.cpp`
   - Image analysis → `IccImageAnalyzer.cpp`
3. Add function declaration to the corresponding `.h` file
4. Wire dispatch call in `IccHeuristicsLibrary.cpp` (or `IccAnalyzerSecurity.cpp` for image)
5. Add entry to `IccHeuristicsRegistry.h` (id, name, specRef, CWE, cveRefs, phase, severity)
6. Update heuristic count (150→151) in these files:
   - `iccanalyzer-lite/tests/run_tests.py` — `summary.150_heuristics`
   - `.github/copilot-instructions.md` — multiple locations
   - `README.md` — two locations
   - `.github/prompts/analyze-icc-profile.prompt.yml`
   - `mcp-server/icc_profile_mcp.py`
   - `.github/workflows/iccanalyzer-lite-unit-tests.yml`
7. Add ICC spec citation in printf: `ICC.1-2022-05 §X.Y.Z`

**Note**: After v3.6.0 refactoring, adding a new heuristic requires editing only
4 files (function + declaration + dispatcher + registry entry) instead of the
previous 7+ file pattern.

### Implemented TIFF Heuristics (H139-H141, H149-H150)

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

**H149: TIFF IFD Chain Cycle Detection** — Walks raw IFD next-pointers to detect
circular references that would cause infinite loops. Tracks visited offsets in a set;
flags cycles and excessive chain depth (>1024). CWE-835.

**H150: TIFF Tile Geometry Validation** — For tiled TIFFs, validates TileWidth
and TileLength are multiples of 16 (TIFF 6.0 §15), tile count matches expected
grid layout, tile byte counts checked for integer overflow and EOF overrun.
CWE-122/CWE-131.

### Candidate Heuristics (Not Yet Implemented)

**H151: TIFF Compression Bomb Detection** — Detect decompression bombs where
compressed tile/strip size is tiny but uncompressed size is enormous. CWE-400.

**H152: PNG iCCP Chunk ICC Extraction** — Extract ICC profiles from PNG iCCP
chunks and run full heuristic analysis. Requires libpng. CWE-125.

### Implemented XML Safety Heuristics (H142-H145)

**H142: XML Serialization Safety** — Fork-isolates `CIccProfileXml::ToXml()` to
detect crashes/hangs in the IccLibXML serialization path. Registers XML factories,
pre-allocates 4MB output buffer, sets 10s alarm. Child crash (WIFSIGNALED) or
timeout = CRITICAL finding. Covers ALL 25 XML-related iccDEV advisories (HBO,
SBO, NPD, type confusion, stack overflow in XML serialization).
CWE-787/CWE-125. References 24 GHSA/CVE identifiers.

**H143: XML Array Bounds Precheck** — Before ToXml: validates array tag element
counts vs available data size. Pattern: `CIccXmlArrayType<T>::DumpArray` uses
`m_nSize` without bounds check — if `m_nSize * elementSize > tagDataSize`, the
serializer reads out-of-bounds. CWE-131.

**H144: XML String Termination Precheck** — Validates null-termination of fixed
32-byte string fields in ColorantTable entries and NamedColor2 prefix. Unterminated
strings cause `strlen()` overflow during XML text generation. CWE-170.

**H145: XML Curve Type Consistency** — Validates MPE CurveSet element type
signatures match `icSigCurveSetElemType`. Type confusion causes invalid casts in
`ToXmlCurve()` leading to memory corruption. CWE-843.

### Implemented Advanced Data Validation (H146-H148)

**H146: Stack Buffer Overflow GetValues** — Detects numeric array tags (XYZ,
S15Fixed16, U16Fixed16) where `GetSize()` exceeds 16 elements (kMaxSafeChannels),
indicating potential stack buffer overflow when `GetValues()` writes into fixed-size
caller buffers. Also checks LUT output channels vs declared color space. CWE-121.
PoCs: #551, #618, #649, #625, #624, #537.

**H147: Null Pointer After Tag Read** — Checks post-Read() state of tags that
leave internal pointers null on malformed data: Utf16Text `GetText()` null,
TextDescription null text, MPE null sub-elements, tag table null pTag pointers.
CWE-476. PoCs: #553, #560, #484, #485, #507, #633.

**H148: Memory Copy Bounds Overlap** — Analyzes MPE element chains for channel
count oscillation that causes memcpy src/dst overlap in Apply() ping-pong buffers.
Also validates NamedColor2 deviceCoords ≤ 15 (ICC spec max). CWE-119.
PoC: #577.

## Heuristic Categories

| Range | Module | Focus |
|-------|--------|-------|
| H1-H8, H15-H17 | IccHeuristicsHeader.cpp | Raw header (size, magic, version, dates, spectral) |
| H9-H32 | IccHeuristicsTagValidation.cpp | Tag structure (counts, offsets, types, sizes) |
| H33-H55, H57-H69 | IccHeuristicsRawPost.cpp | Raw file I/O (overlaps, embedded images, duplicates) |
| H56-H102 | IccHeuristicsDataValidation.cpp | Data integrity (calculator, LUT, matrices, curves) |
| H103-H120 | IccHeuristicsProfileCompliance.cpp | ICC spec compliance (required tags, encoding) |
| H121-H138 | IccHeuristicsIntegrity.cpp | Profile integrity + CWE-400 (MD5, alignment, complexity) |
| H139-H141, H149-H150 | IccImageAnalyzer.cpp | TIFF image security (strip/tile geometry, dimensions, IFD, cycles) |
| H142-H145 | IccHeuristicsXmlSafety.cpp | XML serialization safety (ToXml crash, arrays, strings, curves) |
| H146-H148 | IccHeuristicsDataValidation.cpp | Advanced data validation (SBO GetValues, NPD post-Read, memcpy bounds) |

## CVE Coverage (93 iccDEV Advisories)

52 heuristics detect patterns from 87 CVEs + 95 GHSAs (182 unique) across the 93 iccDEV
security advisories. Use `./iccanalyzer-lite --registry | jq` for authoritative counts.
All 25 XML parser/serializer advisories are now in-scope via H142-H145.
All 93 advisories are in scope (iccFromCube mapped to H34).
Source of truth: `docs/cve/iccDEV-CVE-Report.md`.

CVE cross-references are stored in `IccHeuristicsRegistry.h` per heuristic entry.
Use `--json` mode for programmatic access to per-heuristic CVE mappings, or
`--registry` mode for the full database without requiring a profile argument.

### Enrichment Workflow (when new advisories appear)

```bash
# 1. Fetch current advisory count
gh api --paginate "repos/InternationalColorConsortium/iccDEV/security-advisories" --jq '.[].ghsa_id' | wc -l

# 2. Find unmapped GHSAs
gh api --paginate "repos/InternationalColorConsortium/iccDEV/security-advisories" --jq '.[] | select(.cve_id == null) | .ghsa_id' | sort > /tmp/all_ghsa.txt
grep -oP 'GHSA-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+' iccanalyzer-lite/IccHeuristicsRegistry.h | sort -u > /tmp/registered.txt
comm -23 /tmp/all_ghsa.txt /tmp/registered.txt

# 3. Classify each as in-scope (binary ICC) or out-of-scope (XML/tool)
# 4. Add GHSA IDs to cveRefs field in IccHeuristicsRegistry.h
# 5. Update counts in ALL 6 sync locations (see plan.md)
# 6. Build, then read uniqueCVEs from --json output (do NOT guess)
# 7. Update test expectations with actual values
# 8. Verify: 230/230 tests pass
```

## JSON Output Mode (v3.6.0+)

```bash
./iccanalyzer-lite --json profile.icc
```

Emits structured JSON with per-heuristic results, registry metadata (specRef, CWE,
CVE refs, severity), and summary counts. Uses `pipe()`/`dup2()` stdout capture internally —
no heuristic function modifications needed. Suitable for MCP server, CI pipelines,
and automated analysis.

## Report Output Mode (v3.6.0+)

```bash
./iccanalyzer-lite --report profile.icc
```

Emits a professional severity-sorted report with banner header, SHA-256 hash, build info,
findings grouped by CRITICAL/HIGH/MEDIUM/LOW/INFO, CWE summary table, and CVE
cross-reference section. Uses same pipe/dup2 capture pattern as --json and -xml.

## XML Output Mode (v3.6.0+)

```bash
./iccanalyzer-lite -xml profile.icc output.xml
```

Generates per-heuristic XML with embedded dark-themed XSLT stylesheet. Each `<check>`
element includes id, severity, CWE, CVE refs, spec reference, and detail text.
XSLT renders as a professional dark-themed HTML report with severity color coding,
executive summary cards, and findings table.

## Registry Output Mode (v3.6.2+)

```bash
./iccanalyzer-lite --registry          # Full JSON database
./iccanalyzer-lite --registry | jq .totalHeuristics
```

Emits the complete heuristic registry as JSON — no profile argument needed. Includes
`totalHeuristics`, `heuristicsWithCVE`, `uniqueCVEs`, `uniqueGHSAs`, severity
distribution, and per-heuristic metadata (id, name, specRef, CWE, CVE refs, phase,
severity). This is the **source of truth** for all counts — adding a new entry to
`kHeuristicRegistry[]` in `IccHeuristicsRegistry.h` automatically updates all values.

## Severity Classification (v3.6.0+)

All 150 heuristics are classified by CWE impact:
- **CRITICAL** (~44): Memory corruption/RCE — CWE-119, CWE-121, CWE-122, CWE-476, CWE-787, CWE-416, CWE-190, CWE-506
- **HIGH** (~36): DoS/crash — CWE-674, CWE-400, CWE-843, CWE-476
- **MEDIUM** (~28): Data integrity — CWE-682, CWE-345
- **LOW** (~37): Spec compliance — CWE-20
- **INFO** (3): Metadata — H16, H35, H108

Severity field is included in `--json`, `--report`, and `-xml` output modes.
`HeuristicSeverity` enum and `severity` field are defined in `IccHeuristicsRegistry.h`.

## Image Analysis (v3.4.0+)

The `-a` mode auto-detects image files via magic bytes and routes to `IccImageAnalyzer.cpp`.
The explicit `-img` mode also available. Supports TIFF (libtiff), PNG (libpng iCCP
chunk extraction), and JPEG (libjpeg APP2 ICC_PROFILE multi-segment reassembly).
Table-driven format dispatch via `kFormatHandlers[]` — adding a new format requires
only a handler function + 1 table entry.

### TIFF Analysis Pipeline
1. **Metadata**: dimensions, BPS, SPP, compression, photometric, planar config,
   sample format, orientation, strip/tile layout, software, datetime
2. **Security checks**: extreme dimensions (>65535), zero dimensions, unusual BPS
   (not 1/8/16/32), excessive SPP (>6), strip offset bounds, multi-IFD page counting
3. **Injection scan**: 10 xnuimagefuzzer INJECT_STRING patterns (buffer overflow,
   XSS, SQLi, format string, path traversal, XXE), ICC mutation strategy markers,
   BigTIFF-in-TIFF type confusion
4. **ICC extraction**: TIFFTAG_ICCPROFILE (tag 34675) → temp file → full
   ComprehensiveAnalyze() with all 150 heuristics

### Format Detection (magic bytes)
- TIFF LE: `II\x2a\x00` (0x49492a00)
- TIFF BE: `MM\x00\x2a` (0x4d4d002a)
- BigTIFF LE: `II\x2b\x00` (0x49492b00)
- BigTIFF BE: `MM\x00\x2b` (0x4d4d002b)
- PNG: `\x89PNG` (0x89504e47)
- JPEG: `\xff\xd8\xff` (0xffd8ff)
- ICC: `acsp` at offset 36 (0x61637370)

### PNG Analysis Pipeline
1. **Metadata**: dimensions, bit depth, color type, interlace method, compression
2. **ICC extraction**: iCCP chunk via `png_get_iCCP()` → decompress → temp file →
   full ComprehensiveAnalyze() with all 150 heuristics
3. **Security checks**: dimensions, color type validation

### JPEG Analysis Pipeline
1. **Metadata**: dimensions, color space, component count, data precision
2. **ICC extraction**: APP2 `ICC_PROFILE` markers with multi-segment reassembly
   (supports profiles >64KB split across multiple APP2 segments). Validates
   sequence numbers and total count, reassembles in order.
3. **ICC extraction**: reassembled data → temp file → full ComprehensiveAnalyze()

### Usage
```bash
# Auto-detect (TIFF/PNG/JPEG → image analyzer, ICC → profile analyzer)
./iccanalyzer-lite -a image.tif
./iccanalyzer-lite -a photo.png
./iccanalyzer-lite -a photo.jpg

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
5. **Verify linker flags match across ALL 7 build locations** (see Build System Sync table).
   Specifically check that `iccanalyzer-cli-release.yml` static link command has the
   same `-l` flags as `build.sh` LIBS variable. A local build.sh success is NOT
   sufficient — the release workflow has independent linker flags that can diverge.
6. Only then: `git push`

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
- When iterating iccDEV container types (e.g., `CIccTagProfileSequenceId`), use
  range-based `for (const auto& entry : *pTag)` instead of cached `begin()`/`end()`
  iterators — CodeQL's `cpp/use-after-expired-lifetime` flags cached iterators as
  potentially referencing expired objects even when the container is clearly in scope
- `new` in fork child processes must use `std::nothrow` — CodeQL flags
  `cpp/new-free-mismatch` ("unsafe use of `new[]`") for allocations in signal-unsafe
  contexts. Include `<new>` header.
- Avoid constant comparisons in loops — a `for(int c=0; c<N; c++) { ... break; }`
  where the loop always exits on first iteration triggers CodeQL
  `cpp/comparison-always-true`. Replace with a simple `if` block.
- **libtiff string lifetime** — `TIFFGetField(tif, TIFFTAG_SOFTWARE, &ptr)` returns
  an interior pointer owned by the TIFF directory. `TIFFReadDirectory()` and
  `TIFFSetDirectory()` call `TIFFFreeDirectory()` which frees those strings.
  ALWAYS copy to `std::string` before any directory-walking operations (H141, H149).
  Bug reference: commit bfafaba — HUAF at `IccImageAnalyzer.cpp:962` from `strstr()`
  on freed `software` pointer after H141's `TIFFSetDirectory(tif, 0)`.

## Local CodeQL Analysis

**All prerequisites are pre-installed. Do NOT re-install `gh-codeql`, re-download
query packs, or recreate the build script.** The committed build script at
`.github/scripts/codeql-build.sh` has the correct flags.

### Quick analysis (< 2 minutes)

```bash
# If code changed since last analysis — rebuild database
gh codeql database create /tmp/codeql-db-analyzer \
  --language=cpp --overwrite \
  --command=".github/scripts/codeql-build.sh" \
  --source-root="$(git rev-parse --show-toplevel)"

# Run analysis (reuse existing DB if no code changes)
gh codeql database analyze /tmp/codeql-db-analyzer \
  --format=sarif-latest --output=/tmp/codeql-results.sarif --threads=0 \
  codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls \
  iccanalyzer-lite/codeql-queries/

# Filter results to analyzer code only (exclude upstream iccDEV)
python3 -c "
import json
with open('/tmp/codeql-results.sarif') as f:
    sarif = json.load(f)
for r in sarif['runs'][0]['results']:
    uri = r['locations'][0]['physicalLocation']['artifactLocation']['uri']
    if 'iccanalyzer-lite' in uri:
        line = r['locations'][0]['physicalLocation']['region']['startLine']
        print(f'{r[\"ruleId\"]} @ {uri}:{line}')
"
```

### What NOT to do (anti-patterns that waste 30+ minutes)
- ❌ `gh extensions install github/gh-codeql` — already installed
- ❌ `cd codeql-queries && gh codeql pack install` — already done, lock file committed
- ❌ Creating `/tmp/codeql-build.sh` ad-hoc — use `.github/scripts/codeql-build.sh`
- ❌ Iterating on build flags (`-DICCANALYZER_LITE`, `-I/usr/include/libxml2`) — all in the committed script
- ❌ Always creating a fresh database when code hasn't changed — reuse `/tmp/codeql-db-analyzer`

### Pre-installed assets
| Asset | Location | Status |
|-------|----------|--------|
| `gh codeql` CLI | `gh extensions` | v2.24.1+ installed |
| Query packs | `iccanalyzer-lite/codeql-queries/codeql-pack.lock.yml` | Lock file committed |
| Build script | `.github/scripts/codeql-build.sh` | Committed, executable |
| Database | `/tmp/codeql-db-analyzer` | Persists across sessions |

### Expected informational alerts (not bugs)
- `icc/xml-all-attacks`, `icc/xml-external-entity-attacks` — custom queries flagging
  intentional XML export patterns
- `cpp/iccanalyzer-security` — custom informational query
- `cpp/icc-buffer-overflow` @ `IccTagParsers.h:172` — false positive (guarded by
  `if (idx < size)` bounds check on line 171)
- `icc/injection-attacks` @ `IccAnalyzerLUT.cpp:110` — `SafeSnprintf` is internal-only
  with `__attribute__((format))` validation; format strings are always literals
- `cpp/poorly-documented-function` — style alert for large functions

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
- Remaining upstream iccDEV UBSAN (NOT in analyzer code):
  - `IccCAM.cpp:262,266` — div-by-zero (m_WhitePoint[1] can be 0)
  - `IccProfile.cpp:3153,3155` — div-by-zero (m_illuminantXYZ.Y can be 0)
  - `IccTagLut.cpp:5009` — signed integer overflow (int sum += m_XYZMatrix)
  - `IccMatrixMath.cpp:386` — NaN→unsigned short in SetRange
  - `IccMpeBasic.cpp:1821` — NaN→unsigned int in CIccSingleSampledCurve::Apply()
- Fixed upstream (no longer triggered):
  - `IccSignatureUtils.h` uint→char (PR #648)
  - `iccApplyProfiles.cpp` UnitClip NaN (PR #654)
