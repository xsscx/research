---
applyTo: "iccanalyzer-lite/**"
---

# iccanalyzer-lite -- Path-Specific Instructions

## What This Is

A security analyzer (22,000+ LOC, 30 C++ modules, C++17) with full ASAN+UBSAN+Coverage
instrumentation. Validates ICC profiles against ICC.1-2022-05 and ICC.2-2023 specs.
Use `--registry` for authoritative heuristic/CVE/GHSA counts.

Heuristic and conformance namespaces are expected to grow toward 1000 checks each.
Use the registries as the source of truth, and preserve V1/V2 parity when extending.

## Build

```bash
cd iccanalyzer-lite && ./build.sh    # ASAN+UBSAN+coverage, uses 32 cores
```

- Compiler: clang++ 18+ with `-fsanitize=address,undefined`
- Requires: libxml2-dev, libtiff-dev, libpng-dev, libjpeg-dev, libssl-dev, libclang-rt-18-dev
- Links **unpatched** upstream iccDEV at `iccDEV/Build/` (NOT CFL patches)
- Output: `iccanalyzer-lite/iccanalyzer-lite` (~32MB with debug info)
- V2 artifacts: `icctest`, `icctest-parity`, `README.md`, `heuristic-remap.tsv`,
  `verify-parity-summary.json`

### Build System Sync (7 locations)

| # | File | Variable |
|---|------|----------|
| 1 | `iccanalyzer-lite/build.sh` | `SOURCES=` |
| 2 | `iccanalyzer-lite/CMakeLists.txt` | `add_executable()` |
| 3 | `codeql-security-analysis.yml` | `SRCS=` + linker flags |
| 4 | `iccanalyzer-lite-coverage-report.yml` | `SOURCES=` + linker flags |
| 5 | `iccanalyzer-lite-debug-sanitizer-coverage.yml` | `SOURCES=` + linker flags |
| 6 | `mcp-server-test.yml` | `SRCS=` + linker flags |

For `IccImageAnalyzer.cpp`, also add `-ltiff` to linker flags in all CI workflows.

## Test

```bash
python3 iccanalyzer-lite/tests/run_tests.py
```

- Profile synthesis: `python3 iccanalyzer-lite/tests/synthesize_profiles.py`
- Under V2 unit/parity: `ASAN_OPTIONS=detect_leaks=0 LLVM_PROFILE_FILE=/dev/null`
- Quarantine known resource-bomb families listed in `tests/profile-resource-quarantine.txt`

## Architecture

All heuristics use the `HeuristicCollector` API for structured output.
No raw `printf("[H##]...")` in the codebase.

### HeuristicCollector API

```cpp
HeuristicCollector &hc = HeuristicCollector::instance();
hc.begin("H174", "Title");        // Start -- prints header
hc.info("Checked %u items", n);   // Informational
hc.warn("HEURISTIC: ...");        // Finding (increments count)
hc.critical("Buffer overflow");   // Critical finding
hc.cweNote("CWE-122: ...");       // CWE classification
hc.end("Tag structure valid");    // Success -- [OK]
hc.skip("No relevant tag");      // Skip -- [SKIP]
```

### Heuristic Modules (10)

| Module | Heuristics | Focus |
|--------|-----------|-------|
| IccHeuristicsHeader.cpp | H1-H8, H15-H17 | Raw header bytes |
| IccHeuristicsTagValidation.cpp | H9-H32 | Tag table structure |
| IccHeuristicsRawPost.cpp | H33-H55, H57-H69, H152-H153 | Raw file I/O |
| IccHeuristicsDataValidation.cpp | H56-H102, H146-H148, H151 | Data integrity |
| IccHeuristicsProfileCompliance.cpp | H103-H120 | ICC spec compliance |
| IccHeuristicsIntegrity.cpp | H121-H138 | Profile integrity + CWE-400 |
| IccImageAnalyzer.cpp | H139-H141, H149-H150 | TIFF/PNG/JPEG image security |
| IccHeuristicsXmlSafety.cpp | H142-H145 | XML serialization safety |
| IccHeuristicsCodeQLPatterns.cpp | H154-H161 | CodeQL-derived patterns |
| IccHeuristicsExploitGap.cpp | H162-H171 | Exploit gap analysis |

### Support Modules

| Module | Purpose |
|--------|---------|
| IccHeuristicResult.h/.cpp | HeuristicCollector singleton |
| IccAnalyzerSecurity.cpp | Orchestrator dispatcher |
| IccHeuristicsRegistry.h | Metadata registry (id, name, specRef, CWE, CVE, severity) |
| IccHeuristicsHelpers.h | FindAndCast<T>(), SigToChars(), ReadU32BE(), RawFileHandle |
| IccAnalyzerJson.cpp | `--json` structured output |
| IccAnalyzerReport.cpp | `--report` severity-sorted report |
| IccAnalyzerXMLExport.cpp | `-xml` per-heuristic XML with XSLT |
| IccAnalyzerPAWG.cpp | `--pawg` ICC PAWG assessment |
| IccAnalyzerCapture.cpp | Shared capture: quiet mode + read results |
| IccConformanceRegistry.h | 329-entry conformance metadata |
| IccConformance*.cpp (5) | 7 conformance dispatchers |
| IccDevSafeOverrides.cpp | Upstream UB safe overrides (preferred extension point) |

### Structured Output

All modes (`--json`, `--report`, `-xml`, `--pawg`) use the same pattern:
reset collector -> quiet mode -> suppress stdout -> ComprehensiveAnalyze() ->
restore stdout -> read `HeuristicCollector::results()` -> format output.

### Output Modes

| Flag | Description |
|------|-------------|
| `-a` | Comprehensive analysis (auto-detects ICC/TIFF/PNG/JPEG) |
| `-img` | Explicit image analysis mode |
| `--json` | Structured JSON with per-heuristic results |
| `--report` | Professional severity-sorted report |
| `-xml out.xml` | Per-heuristic XML with dark-themed XSLT |
| `--pawg` | ICC PAWG assessment (31 checklist items) |
| `--registry` | Full heuristic registry JSON (no profile needed) |
| `-xt` | LUT text export (curves, CLUTs, matrices) |
| `-it` | LUT text import |
| `-cube` | 3D CLUT as .cube format (3->3 channel only) |
| `-from-cube` | Create ICC from .cube file |
| `-r` | Round-trip mode |
| `-nf` | Ninja-full structural dump |

## Adding a New Heuristic

1. Choose next ID (current max from `--registry`)
2. Add `RunHeuristic_HNNN_Name()` to appropriate category file
3. **Use HeuristicCollector API** (MANDATORY -- no raw printf)
4. Add declaration to corresponding `.h` file
5. Wire dispatch in `IccHeuristicsLibrary.cpp` or `IccAnalyzerSecurity.cpp`
6. Add entry to `IccHeuristicsRegistry.h`
7. Update test expectations in `run_tests.py`
8. Build, test, ASAN spot-check

## Conformance Checks (CF-001..CF-329)

329 canonical ICC conformance checks across 7 dispatchers. CF functions use
`printf` (NOT HeuristicCollector) and return `int` (issue count). The `CF_WRAP`
macro handles collector integration. ID numbering: CF ID = 1000 + CF number.

Next available: **CF-330**.

Adding: create `RunCF330_Name()`, add `CF_WRAP(1330, ...)` to dispatcher,
add entry to `IccConformanceRegistry.h`, update test assertions.

## Image Analysis

`-a` mode auto-detects via magic bytes: TIFF (`II\x2a`/`MM\x00\x2a`),
PNG (`\x89PNG`), JPEG (`\xff\xd8\xff`), ICC (`acsp` at offset 36).

Pipeline: metadata -> security checks -> injection scan (xnuimagefuzzer patterns)
-> ICC extraction -> full heuristic analysis on extracted profile.

JPEG supports multi-segment APP2 ICC_PROFILE reassembly (profiles >64KB).
`.cube` requires exactly 3->3 channels. Test profile: `test-profiles/fuzzed-prtr-Lab-414k.icc`.

## Upstream UB Hardening

When upstream iccDEV exposes user-controlled UB affecting analyzer runtime:
1. Fingerprint the trigger into appropriate heuristic/conformance lane
2. Prefer analyzer-owned safe wrappers or symbol overrides
3. Keep V1 and V2 aligned
4. Do NOT move these into `cfl/patches`

Extension point: `IccDevSafeOverrides.cpp` (hardens shared-helper UB sites).

## CVE Coverage

Use `--registry | jq` for authoritative counts. All 113 iccDEV advisories in scope.
Source of truth: `docs/cve/iccDEV-CVE-Report.md`.

### Enrichment Workflow

```bash
gh api --paginate "repos/InternationalColorConsortium/iccDEV/security-advisories" \
  --jq '.[] | select(.cve_id == null) | .ghsa_id' | sort > /tmp/all_ghsa.txt
grep -oP 'GHSA-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+' IccHeuristicsRegistry.h | sort -u > /tmp/registered.txt
comm -23 /tmp/all_ghsa.txt /tmp/registered.txt   # unmapped GHSAs
```

## Severity Classification

- **CRITICAL**: Memory corruption/RCE (CWE-119, 121, 122, 476, 787, 416, 190, 506, 789, 762)
- **HIGH**: DoS/crash (CWE-674, 400, 843, 681, 369, 252)
- **MEDIUM**: Data integrity (CWE-682, 345)
- **LOW**: Spec compliance (CWE-20)
- **INFO**: Metadata (H16, H35, H108)

## Pre-Push Validation (MANDATORY)

1. `cd iccanalyzer-lite && ./build.sh`
2. `python3 tests/run_tests.py` -- all tests pass
3. ASAN spot-check on 5+ diverse profiles
4. `gh api /repos/xsscx/research/code-scanning/alerts` -- 0 open alerts
5. Verify linker flags match across ALL 7 build locations
6. Only then: `git push`

## Common Pitfalls

- `std::string(wstr.begin(), wstr.end())` triggers UBSAN when wchar_t > 127 --
  use `static_cast<char>(static_cast<unsigned char>(wc & 0xFF))`
- ICC signature extraction: always cast through `unsigned char` to avoid UBSAN
- `icGetSpaceSamples()` may report fewer channels than malformed LUTs have --
  always use `tmpPixel[16]` sized buffers
- H111 reserved bytes are 100-127 (NOT 84-127; 84-99 is Profile ID)
- H112 D50 values are ICC s15Fixed16 (0.9642/1.0/0.8249), NOT CIE values
- Don't modify for-loop counter inside loop body (CodeQL)
- Use range-based `for` for iccDEV containers (CodeQL lifetime warnings)
- `new` in fork children: use `std::nothrow` (signal-unsafe context)
- **libtiff string lifetime**: `TIFFGetField(tif, TIFFTAG_SOFTWARE, &ptr)` returns
  interior pointer freed by `TIFFReadDirectory()`. Copy to `std::string` first.
- **Format string args**: ensure `%s`/`%u`/`%d` match arguments in hc.info/warn/critical

## Local CodeQL

Prerequisites pre-installed. Do NOT re-install `gh-codeql` or re-download packs.

```bash
# Build database (if code changed)
gh codeql database create /tmp/codeql-db-analyzer --language=cpp --overwrite \
  --command=".github/scripts/codeql-build.sh" \
  --source-root="$(git rev-parse --show-toplevel)"

# Analyze
gh codeql database analyze /tmp/codeql-db-analyzer \
  --format=sarif-latest --output=/tmp/codeql-results.sarif --threads=0 \
  codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls \
  iccanalyzer-lite/codeql-queries/
```

Known informational alerts (NOT bugs): `icc/xml-all-attacks`, `icc/xml-external-entity-attacks`,
`icc/wrong-variable-index` (58 FPs -- outer var selects structure, not inner data),
`cpp/path-injection` (CLI inherently takes user paths), `cpp/equality-on-floats`
(intentional s15Fixed16 comparisons).

## Coverage

Uses clang source-based coverage (`-fprofile-instr-generate -fcoverage-mapping`), NOT gcov.

```bash
LLVM_PROFILE_FILE=output_%m_%p.profraw ./iccanalyzer-lite -a profile.icc
llvm-profdata-18 merge -sparse *.profraw -o merged.profdata
llvm-cov-18 report ./iccanalyzer-lite -instr-profile=merged.profdata
```

Baseline: Lines 70.54%, Functions 63.54%, Branches 61.21%.
