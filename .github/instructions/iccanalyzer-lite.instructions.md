---
applyTo: "iccanalyzer-lite/**"
---

# iccanalyzer-lite — Path-Specific Instructions

## What This Is

A 135-heuristic ICC profile security analyzer (15,500+ LOC, C++17) built with full
ASAN+UBSAN+Coverage instrumentation. It validates ICC color profiles against
ICC.1-2022-05 and ICC.2-2023 specifications, detecting CVE patterns, CWE violations,
malformed structures, and potential exploitation vectors.

## Build

```bash
cd iccanalyzer-lite && ./build.sh    # ASAN+UBSAN+coverage, uses 32 cores
```

- Compiler: clang++ 18+ with `-fsanitize=address,undefined`
- Requires: libxml2-dev, libtiff-dev, libclang-rt-18-dev
- The build links against a patched iccDEV library at `iccDEV/Build/`
- Output: `iccanalyzer-lite/iccanalyzer-lite` (32MB with debug info)

## Test

```bash
python3 iccanalyzer-lite/tests/run_tests.py   # 147 unit tests, ~3s
```

- Tests use synthesized ICC profiles in `iccanalyzer-lite/tests/corpus/`
- Profile synthesis: `python3 iccanalyzer-lite/tests/synthesize_profiles.py`
- When adding heuristics, update the test for `summary.135_heuristics` pattern

## Architecture — 3 Heuristic Modules

| Module | Heuristics | API Level |
|--------|-----------|-----------|
| `IccAnalyzerSecurity.cpp` | H1-H8, H15-H17 | Raw header bytes, orchestrator |
| `IccHeuristicsLibrary.cpp` | H9-H32, H56-H135 | CIccProfile library API |
| `IccHeuristicsRawPost.cpp` | H33-H55, H57-H69 | Raw file I/O fallback |

- Entry point: `RunSecurityHeuristics()` in `IccAnalyzerSecurity.cpp`
- When the library fails to load a malformed profile, raw fallback runs H10/H13/H25/H28/H32
- Gate: if `heuristicCount >= kCriticalHeuristicThreshold`, library phase is skipped

## Adding a New Heuristic

1. Choose the next ID: **H136** (current max is H135)
2. Add function declaration to `IccHeuristicsLibrary.h`
3. Implement in `IccHeuristicsLibrary.cpp` (append after H135)
4. Wire dispatch in `IccAnalyzerSecurity.cpp` (after H135 call)
5. Update heuristic count (135→136) in these files:
   - `IccAnalyzerSecurity.cpp` — CVE Coverage printf
   - `iccanalyzer-lite/tests/run_tests.py` — `summary.135_heuristics`
   - `.github/copilot-instructions.md` — multiple locations
   - `README.md` — two locations
   - `.github/prompts/analyze-icc-profile.prompt.yml`
   - `mcp-server/icc_profile_mcp.py`
   - `.github/workflows/iccanalyzer-lite-unit-tests.yml`
6. Add ICC spec citation in printf: `ICC.1-2022-05 §X.Y.Z`

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
