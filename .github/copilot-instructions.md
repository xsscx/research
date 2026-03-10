# Copilot Instructions — ICC Security Research

## Quick Reference — Documentation Index

**Read the routing table first.** Component-specific details live in specialized files.
This file contains cross-cutting rules that apply to ALL components.

### Component Documentation (path-specific — auto-loaded when touching these paths)

| Component | Instructions File | Key Commands |
|-----------|------------------|--------------|
| **iccanalyzer-lite/** | [iccanalyzer-lite.instructions.md](instructions/iccanalyzer-lite.instructions.md) | `cd iccanalyzer-lite && ./build.sh` ∥ `python3 tests/run_tests.py` |
| **cfl/** | [cfl.instructions.md](instructions/cfl.instructions.md) | `cd cfl && ./build.sh` ∥ `./fuzz-local.sh` |
| **mcp-server/** | [mcp-server.instructions.md](instructions/mcp-server.instructions.md) | `pip install -e .` ∥ `python3 web_ui.py` |
| **fuzz/** | [fuzz.instructions.md](instructions/fuzz.instructions.md) | Seed corpus (input data only) |
| **colorbleed_tools/** | [colorbleed_tools.instructions.md](instructions/colorbleed_tools.instructions.md) | `make setup && make` |
| **call-graph/** | [call-graph.instructions.md](instructions/call-graph.instructions.md) | `python3 scripts/generate-callgraphs.py` |
| Multi-agent coordination | [multi-agent.instructions.md](instructions/multi-agent.instructions.md) | Platform detection, handoff protocols |

### Reference Documentation

| Document | Path | Content |
|----------|------|---------|
| iccDEV Shell Helpers (Unix) | [docs/iccdev-shell-helpers/unix.md](../../docs/iccdev-shell-helpers/unix.md) | Build, test, ASAN, coverage, Homebrew |
| iccDEV Shell Helpers (Windows) | [docs/iccdev-shell-helpers/windows.md](../../docs/iccdev-shell-helpers/windows.md) | MSVC, vcpkg, ASAN, SARIF analysis |
| iccDEV Issue Reproductions | [docs/pocs/iccdev-issue-reproductions.md](../../docs/pocs/iccdev-issue-reproductions.md) | 63 PoC reproductions from closed issues #480–#656 |
| iccDEV PoC Techniques | [docs/pocs/iccdev-poc-techniques.md](../../docs/pocs/iccdev-poc-techniques.md) | printf pipe technique, image format helpers, regression testing |

### Workflow Prompts (task-specific guides)

| Task | Prompt File |
|------|-------------|
| Analyze an ICC profile | [analyze-icc-profile.prompt.yml](prompts/analyze-icc-profile.prompt.yml) |
| Triage a fuzzer crash | [triage-fuzzer-crash.prompt.md](prompts/triage-fuzzer-crash.prompt.md) |
| Improve fuzzer coverage | [improve-fuzzer-coverage.prompt.md](prompts/improve-fuzzer-coverage.prompt.md) |
| Optimize a specific fuzzer | [fuzzer-optimization.prompt.md](prompts/fuzzer-optimization.prompt.md) |
| Manage corpus storage | [corpus-management.prompt.md](prompts/corpus-management.prompt.md) |
| Sync upstream iccDEV | [upstream-sync.prompt.md](prompts/upstream-sync.prompt.md) |
| Enrich CVE mappings | [cve-enrichment.prompt.md](prompts/cve-enrichment.prompt.md) |
| Remote Docker analysis | [remote-analysis.prompt.md](prompts/remote-analysis.prompt.md) |
| Agent task priorities | [cooperative-development.prompt.md](prompts/cooperative-development.prompt.md) |

### Pre-installed Tools (do NOT re-install)

| Tool | Status | Fast-path |
|------|--------|-----------|
| `gh codeql` | Installed (v2.24.1+) | `.github/scripts/codeql-build.sh` + DB at `/tmp/codeql-db-analyzer` |
| iccanalyzer-lite | Built at `iccanalyzer-lite/iccanalyzer-lite` | `ls -la iccanalyzer-lite/iccanalyzer-lite` to verify |
| CFL fuzzers | Built at `cfl/bin/icc_*_fuzzer` | `ls cfl/bin/icc_*_fuzzer \| wc -l` → 18 |
| colorbleed_tools | Built at `colorbleed_tools/icc{To,From}Xml_unsafe` | `ls colorbleed_tools/icc*_unsafe` |
| Query packs | Lock file at `iccanalyzer-lite/codeql-queries/codeql-pack.lock.yml` | Never re-download |

### Key Counts (source of truth — update ALL locations when changed)

| Metric | Value | Sync locations |
|--------|-------|----------------|
| Heuristics | 150 (H1-H138 ICC + H139-H141 TIFF + H142-H145 XML + H146-H148 data validation + H149-H150 TIFF extended) | 10+ files (see iccanalyzer-lite.instructions.md) |
| MCP tools | 24 (11 analysis + 7 maintainer + 6 operations) | 4 files (see mcp-server.instructions.md) |
| CFL fuzzers | 18 | cfl.instructions.md, README.md |
| iccDEV advisories | 93 (85 CVEs + 95 GHSAs = 180 unique, 52 heuristics with refs) | 6 files (see CVE count sync memory) |
| Build locations | 7 | iccanalyzer-lite.instructions.md Build System Sync |

## ICC Specification References — Sources of Truth

All heuristic validation rules in iccanalyzer-lite are derived from the official ICC specification
and technical notes published by the International Color Consortium. These are the authoritative
documents for profile structure, encoding constraints, and required-tag rules.

### Primary Specification
- **ICC.1-2022-05** (v4.4) — Main profile specification (126 pages)
  - URL: `https://www.color.org/specification/ICC.1-2022-05.pdf`
  - Defines: header layout (128 bytes), tag table structure, required tags per class,
    data type encodings, PCS illuminant (D50), profile ID MD5 calculation, version BCD encoding

### Technical Notes (archive.color.org — all publicly accessible)
| Document | URL | Relevance |
|----------|-----|-----------|
| ICC TN-06-2025 Tristimulus Calculation | `https://archive.color.org/files/technotes/ICC_TN-06-2025_Recommendations_on_calculation_of_tristimulus_values.pdf` | Weighting functions, observer data |
| Profile Embedding | `https://archive.color.org/files/technotes/ICC-Technote-ProfileEmbedding.pdf` | Embedding in TIFF/JPEG/EPS, flags validation |
| Partial Chromatic Adaptation | `https://archive.color.org/files/technotes/ICC-Technote-PartialAdaptation.pdf` | chad tag validation, adaptation matrix |
| Negative PCS XYZ Values | `https://archive.color.org/files/technotes/Guidelines_on_the_use_of_negative_PCSXYZ_values.pdf` | Wide-gamut (BT.2020/DCI-P3) XYZ ranges |
| V4 Matrix Entries | `https://archive.color.org/files/v4_matrix_entries.pdf` | s15Fixed16Number precision, matrix column constraints |
| V2 Profiles in V4 | `https://archive.color.org/files/v2profiles_v4.pdf` | Version interop, CIELAB encoding differences |
| Profile Sequence Desc | `https://archive.color.org/files/PSD_TechNote.pdf` | PSD parsing pitfalls, size inference attacks |

### Registry Pages (require browser access — 403 from CLI)
- `https://www.color.org/whitepapers.xalter` — ICC white papers index
- `https://registry.color.org/dicttype-metadata/` — Dictionary type metadata registry
- `https://registry.color.org/colorimetry-data/` — Standard colorimetry data
- `https://www.color.org/v4spec.xalter` — V4 specification page
- `https://www.color.org/chadtag.xalter` — Chromatic adaptation tag details
- `https://www.color.org/technotes2.xalter` — Technical notes index
- `https://www.color.org/finger.xalter` — Profile fingerprinting
- `https://www.color.org/unicode.xalter` — Unicode handling in profiles

### Key Validation Constants (from ICC.1-2022-05)
```
Header:     128 bytes (offsets 0-127)
Magic:      'acsp' = 0x61637370 at bytes 36-39
Version:    BCD — byte 8 = major, byte 9 = minor.bugfix (nibbles), bytes 10-11 = 0x0000
            v4.4.0.0 = 0x04400000
PCS D50:    X=0.9642, Y=1.0000, Z=0.8249 at bytes 68-79
Intent:     0=Perceptual, 1=Relative, 2=Saturation, 3=Absolute (bytes 64-67, upper 16 bits = 0)
Reserved:   bytes 100-127 must be 0x00
ProfileID:  MD5 of entire profile with bytes 44-47, 64-67, 84-99 zeroed
Tag table:  starts at byte 128, 4-byte count + 12-byte entries (sig + offset + size)
            No duplicate sigs, no partial overlaps, shared offsets require matching sizes, 4-byte alignment
Classes:    scnr(Input) mntr(Display) prtr(Output) link(DeviceLink) spac(ColorSpace) abst(Abstract) nmcl(NamedColor)
All classes require: profileDescriptionTag, mediaWhitePointTag, copyrightTag
            + chromaticAdaptationTag if adopted white ≠ D50
```

### MD5 Reference
- RFC 1321: `https://www.ietf.org/rfc/rfc1321.txt`

## Multi-Agent Coordination

This repo is developed by multiple Copilot agents on different platforms (WSL-2/Linux,
macOS, Cloud CI). See `.github/instructions/multi-agent.instructions.md` for setup,
handoff protocols, file ownership rules, and conflict prevention. See
`.github/prompts/cooperative-development.prompt.md` for prioritized task lists,
coverage targets, and batch analysis workflows.

**Key principle**: WSL-2 owns analysis/fuzzing artifacts (`analysis-reports/`, `cfl/`,
`call-graph/`). macOS owns iOS/image artifacts (`xnuimagetools/`, `fuzz/graphics/*/xig-*`).
Both contribute to shared docs (`.github/prompts/`, `.github/instructions/`).

## Environment Detection

This repo is used in three contexts. Detect which one you are in:

### GitHub Copilot Coding Agent (cloud)
If `copilot-setup-steps.yml` ran, binaries are pre-built in the Docker image.
**Do NOT run** `build.sh`, `cmake`, or `git clone` for iccDEV — they are already built.
Binaries:
- `iccanalyzer-lite/iccanalyzer-lite` — security analyzer (ASAN+UBSAN)
- `colorbleed_tools/iccToXml_unsafe` — ICC to XML converter
- `colorbleed_tools/iccFromXml_unsafe` — XML to ICC converter

### Local / Copilot CLI
Binaries must be built before use. See **Local Build** section below.

**First action** on any analysis issue: run `ls -la iccanalyzer-lite/iccanalyzer-lite` to confirm the binary exists. If missing, build it (local) or report the error (cloud).

## Local Build

```bash
# Prerequisites: clang/clang++ 18+, cmake 3.15+, libxml2-dev, libtiff-dev,
#                libpng-dev, libjpeg-dev, libssl-dev,
#                libclang-rt-18-dev (provides ASan/UBSan/fuzzer runtimes)

# Build iccanalyzer-lite (ASAN + UBSAN + coverage)
cd iccanalyzer-lite && ./build.sh

# Build CFL fuzzers (clones iccDEV, applies 68 patches, builds 18 fuzzers)
cd cfl && ./build.sh

# Build colorbleed_tools
cd colorbleed_tools && make setup && make
```

`cfl/build.sh` reuses an existing `cfl/iccDEV/` checkout if present — it does NOT reclone unless the directory is missing.

```bash
# Build ASAN-instrumented upstream tools (for coverage comparison)
cd iccDEV && mkdir -p Build-ASAN && cd Build-ASAN
cmake ../Build/Cmake -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON -DENABLE_COVERAGE=ON
make -j32
```

### iccDEV Tools — Source of Truth

**CRITICAL**: Two iccDEV checkouts exist with DIFFERENT purposes:

| Path | Purpose | Patched? |
|------|---------|----------|
| `iccDEV/Build/Tools/` | **Upstream reference tools (UNPATCHED, Debug+ASAN+UBSAN+Coverage)** | No |
| `iccDEV/Build-ASAN/Tools/` | **Upstream tools (ASAN+UBSAN+Coverage, alternate build dir)** | No |
| `cfl/iccDEV/` | CFL fuzzer build (60+ patches applied) | Yes |

**CRITICAL BUILD POLICY**: `iccDEV/Build/` must ALWAYS be built with full
Debug+ASAN+UBSAN+coverage instrumentation. **NEVER use Release builds.**
Use `halt_on_error=0` for catch-and-continue to fully analyze the crash chain.

**For crash fidelity testing**: ALWAYS use `iccDEV/Build/Tools/` (unpatched).
If the upstream tool doesn't crash but the fuzzer does, it's a fuzzer alignment
issue — not an upstream bug. NEVER use `cfl/iccDEV/` for this purpose.

```bash
# Build iccDEV with full instrumentation (ALWAYS — never Release)
cd iccDEV/Build
cmake Cmake \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_CXX_FLAGS="-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined -fprofile-instr-generate" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined -fprofile-instr-generate"
make -j32

# Run upstream tool against a PoC (catch-and-continue for full chain)
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=0,print_stacktrace=1 \
LLVM_PROFILE_FILE=/tmp/tool-cov/dump_%m.profraw \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <profile.icc>

# Generate coverage report
llvm-profdata-18 merge -sparse /tmp/tool-cov/*.profraw -o /tmp/tool-cov/merged.profdata
llvm-cov-18 report iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile \
  -instr-profile=/tmp/tool-cov/merged.profdata \
  -object iccDEV/Build/IccProfLib/libIccProfLib2.so.2.3.1.5
```

### Upstream Tool vs Fuzzer Fidelity (March 2026)

Coverage comparison using ASAN-instrumented upstream tools vs fuzzer corpus replay:

| Tool / Fuzzer | Functions | Lines | Notes |
|---------------|-----------|-------|-------|
| iccFromCube (upstream) | 3.62% | 3.96% | Simple text→profile pipeline |
| icc_fromcube_fuzzer | 3.75% | 4.07% | **100% function fidelity** (only `main` differs) |
| iccDumpProfile (upstream) | 1.56% | 1.88% | Describe() paths |
| icc_dump_fuzzer | 29.99% | 27.65% | Fuzzer covers 15× more (custom icRealloc, deeper iteration) |
| iccToXml (upstream) | 13.47% | 20.30% | XML serialization |
| iccRoundTrip (upstream) | 22.58% | 28.65% | CMM Apply pipeline |

Available tools (15):
`iccApplyNamedCmm`, `iccApplyProfiles`, `iccApplySearch`, `iccApplyToLink`,
`iccDumpProfile`, `iccFromCube`, `iccFromXml`, `iccJpegDump`, `iccPngDump`,
`iccRoundTrip`, `iccSpecSepToTiff`, `iccTiffDump`, `iccToXml`,
`iccV5DspObsToV4Dsp`, `iccDumpProfileGui`

### iccDEV Doxygen Documentation

- **Class hierarchy**: `https://xss.cx/public/docs/iccdev/hierarchy.html` (textual, ~200+ classes)
- **Graphical hierarchy**: `https://xss.cx/public/docs/iccdev/inherits.html` (SVG graphs)
- **Version**: 2.3.1
- Key class trees for fuzzer coverage analysis:
  - `CIccTag` — largest hierarchy (~40+ tag types), covered by dump/profile/deep_dump fuzzers
  - `CIccMultiProcessElement` — MPE elements, covered by calculator/spectral fuzzers
  - `CIccCurveSetCurve` — curve types (Segmented, SingleSampled, SampledCalculator)
  - `CIccXform` — transform pipeline, covered by apply/link/roundtrip fuzzers

### Research Repo Doxygen Documentation

Config at `docs/doxygen/Doxyfile`. Generates interactive SVG class graphs for all
research components (iccanalyzer-lite, CFL fuzzers, MCP server, colorbleed_tools).

```bash
# Build HTML docs (run from repo root)
doxygen docs/doxygen/Doxyfile    # output → docs/doxygen/html/

# Zip for release upload
cd docs/doxygen && zip -r /tmp/doxygen-html.zip html/
gh release upload <TAG> /tmp/doxygen-html.zip --clobber
```

**Key settings**: interactive SVG graphs, UML look, class/collaboration/include/directory
graphs enabled, per-function call graphs disabled (too many SVGs). Excludes: `iccDEV/`,
`site-packages/`, `.venv/`. Output: ~23MB / 1498 files / 347 SVGs.

### Dynamic Heuristic Count — Source of Truth

All heuristic, CVE, and severity counts are computed dynamically from
`IccHeuristicsRegistry.h` at runtime. Use `--registry` mode for authoritative data:

```bash
./iccanalyzer-lite --registry | jq .totalHeuristics    # → 150
./iccanalyzer-lite --registry | jq .uniqueCVEs         # → 85
./iccanalyzer-lite --registry | jq .uniqueGHSAs        # → 95
./iccanalyzer-lite --registry | jq .heuristicsWithCVE  # → 52
./iccanalyzer-lite --registry | jq .severity           # → {CRITICAL:44, HIGH:36, ...}
```

Adding a new entry to `kHeuristicRegistry[]` in `IccHeuristicsRegistry.h` automatically
updates all C++ counts. No manual sync needed for C++ code — only documentation files
reference specific numbers.

### CWE-400 Timeout Patterns in iccDEV

**Systemic theme**: every value read from an ICC profile that controls loop iteration
or recursion depth needs a spec-derived upper bound. Seven patterns identified:

1. **Recursive validation without global budget** — `CheckUnderflowOverflow()` in
   `IccMpeCalc.cpp` had depth limit but no total-operations counter. Calculator ops
   with branching (if/else/select/case) cause exponential path exploration.
   Fix: CFL-074 (100K ops budget + depth 100→16).

2. **Exponential grid iteration** — `EvaluateProfile()` in `IccEval.cpp` iterates
   nGran^ndim grid points. For high-dimensional profiles (ndim≥6), 33^6 = 1.29B
   iterations × 2 Apply() calls. Fix: CFL-075 (cap total iterations to 100K,
   dynamically reduce nGran).

3. **Uncapped NamedColor2 nDeviceCoords** — `CIccTagNamedColor2::Read()` uses
   uint32 `m_nDeviceCoords` to allocate `m_nColorEntrySize` with no upper bound.
   Fix: CFL-076 (cap to 32, ICC spec max 15).

4. **ResponseCurve nMeasurements[]** — `CIccResponseCurveStruct::Read()` reads
   per-channel measurement count as uint32 with no validation. 500K measurements
   × sizeof(icResponse16Number) = multi-GB allocation. Ref: CFL-077.

5. **NamedColor2 Describe() iteration** — `CIccTagNamedColor2::Describe()` loops
   over m_nSize entries (up to 3.5M after CFL-004 alloc cap) with 5 snprintf calls
   per entry. Ref: CFL-078.

6. **ApplySequence() runtime recursion** — 5 recursive call sites with zero depth
   tracking during execution (validation has depth=16 via CFL-074, but Apply path
   was unprotected). Ref: CFL-079.

7. **Multiple Describe() unbounded loops** — XYZ, Chromaticity, ColorantTable
   `Describe()` methods loop over file-controlled counters with no output cap.
   Ref: CFL-080, CFL-081.

**Patches CFL-077 through CFL-081** are in `cfl/patches/` and ARE applied
to CFL fuzzer builds (build.sh applies all `*.patch` files). They harden the
fuzzers against CWE-400 timeout patterns. iccanalyzer-lite is NOT patched —
it links the unpatched upstream iccDEV library and handles all user-controllable
inputs through its own defensive programming (H136-H138 detect these patterns
via bounds checks and complexity estimation, not library patches).

**Diagnosis**: run PoC through upstream `iccDEV/Build/Tools/` with `timeout 30`.
If upstream also hangs → report upstream + create CFL patch.
If upstream handles it → fuzzer-only alignment issue.

### CWE-122 TIFF Image Reader Patterns in iccDEV

**Theme**: TIFF parameters read from file (strip sizes, row counts, dimensions)
must be cross-validated against each other before use as buffer offsets.

8. **Strip buffer vs row geometry mismatch** — `CTiffImg::Open()` allocates
   `m_pStripBuf` sized by `TIFFStripSize()` (from TIFF StripByteCounts tag), but
   `ReadLine()` accesses `nRowOffset * m_nBytesPerLine` without bounds check.
   A malformed TIFF with StripByteCounts < m_nRowsPerStrip × m_nBytesPerLine
   causes heap-buffer-overflow in ReadLine()'s memcpy.
   Fix: CFL-082 (validate `m_nStripSize >= m_nRowsPerStrip * m_nBytesPerLine`
   in Open() after malloc). CWE-122 / CWE-125.
   Affects: iccApplyProfiles, iccSpecSepToTiff, icc_tiffdump_fuzzer,
   icc_specsep_fuzzer — any tool using `CTiffImg::ReadLine()`.
   **iccTiffDump is NOT affected** — it reads TIFF metadata only.

### Fuzzer Optimization Patterns

Proven techniques for improving fuzzer coverage and crash discovery:

1. **2-phase architecture** — Phase 1: lightweight in-memory parse (cheap, broad).
   Phase 2: deep file-based analysis (expensive, targeted). Skip Phase 2 on
   malformed input to maximize throughput. (Example: icc_tiffdump_fuzzer V3,
   +16.6% edge coverage.)

2. **OOM guards before tag iteration** — Validate before expensive loops:
   - Skip profiles with `profileSize < 1024`
   - Skip tags with `tSize > 256KB` or `tSize > profileSize`
   - MPE amplification guard: `tSize * 1024 > profileSize` (catches CWE-789)
   - Offset bounds: `tOffset + tSize > profileSize`

3. **Dictionary consolidation** — Merge hand-curated format tokens with
   auto-extracted corpus tokens. Deduplicate. All entries must use `\xHH` hex
   escapes (NOT raw binary bytes — LibFuzzer rejects dicts with raw control chars).

4. **Seed corpus diversity** — Add profiles exercising under-covered code paths:
   high-dimensional (6+ channels), MPE calculator elements, spectral PCS,
   named colors with large palettes, deeply nested tag structures.
   **Critical**: Audit profile class distribution — all 7 ICC classes (mntr, prtr,
   scnr, link, spac, abst, nmcl) must be represented. Printer profiles exercise
   AToB/BToA LUT pairs, gamut tags, and CMYK handling that other classes skip.

5. **Harvest pipeline** — Extract ICC profiles and TIFF files from xnuimagetools/
   xnuimagefuzzer fuzzed-images and inject into CFL corpora:
   ```bash
   .github/scripts/harvest-xnu-seeds.sh              # local harvest
   .github/scripts/harvest-xnu-seeds.sh --dry-run     # preview only
   .github/scripts/harvest-xnu-seeds.sh --ramdisk /tmp/fuzz-ramdisk  # + deploy to ramdisk
   ```
   Both repos produce `cfl-seeds` artifacts in CI via `extract-icc-seeds.py`.
   Stage outputs to `fuzz/xnuimagegenerator/{format}/` and `fuzz/xnuimagefuzzer/{format}/`
   before injecting into CFL corpora.
   **Note**: xnuimagetools uses xnuimagefuzzer as a git submodule — clone with
   `git clone --recurse-submodules` to ensure fuzzed-images are populated.

### WASM Build (Deferred)

WASM build of iccanalyzer-lite is **not yet supported**. Known blockers:
- POSIX signal recovery (alarm, sigsetjmp, sigaltstack) — needs `#ifndef __EMSCRIPTEN__` guards
- ASAN/UBSAN `__asan_default_options` / `__ubsan_default_options` — must be stubbed
- `ICCANALYZER_LITE` compile flag required to skip fingerprint DB code (`RiskLevel` enum)
- Third-party deps (zlib, libpng, libjpeg, libtiff, libxml2, nlohmann/json) **do** build successfully with Emscripten
- Reference: upstream `iccDEV/.github/workflows/wasm-latest-matrix.yml`

## Fuzz Corpus (`fuzz/`)

Curated corpus of 1,139 malicious input files (201 MB, 34 subdirectories) for security testing.
Originally "Commodity-Injection-Signatures" by David Hoyt (xss.cx/srd.cx), maintained since 2015.

### Key Assets
- `fuzz/graphics/icc/` — **95 ICC CVE PoC profiles** (CVE-2022-26730, CVE-2023-46602, CVE-2024-38427)
- `fuzz/xml/icc/` — 42 ICC XML crash PoCs + 74 AFL-minimized crash samples
- `fuzz/graphics/{jpg,png,tif,gif,bmp,heic,exr}/` — 733 malformed image files for ImageIO/Skia fuzzing
- `fuzz/{angular,javascript,sqlinjection,css,ssi,xxe,...}/` — Web injection signatures

### Relationship to CFL Fuzzers
- `fuzz/` is **input data only** — no build scripts or harnesses (those are in `cfl/`)
- fuzz/ ICC profiles seed → `cfl/corpus-*` directories
- cfl/ crash discoveries → new `crash-*`, `oom-*`, `slow-unit-*` files in repo root
- cfl/ timeout discoveries → `test-profiles/cwe-400/timeout-*`
- Use `ramdisk-seed.sh` to propagate fuzz/ seeds into ramdisk for fuzzing campaigns

### ICC File Naming Convention
```
{crash_type}-{Class}-{Method}-{File}_cpp-Line{N}.icc
cve-{YYYY}-{NNNNN}-{description}-variant-{NNN}.icc
```
Crash types: `hbo` (heap overflow), `sbo` (stack overflow), `segv` (SIGSEGV),
`oom` (OOM), `ub` (undefined behavior), `npd` (null deref), `so` (stack overflow)

## Fuzzing Storage Setup

Fuzzing can run on a tmpfs ramdisk (fast, limited by RAM) or an external SSD (large capacity).

```bash
# Option A: tmpfs ramdisk (8GB default — good for short runs)
.github/scripts/ramdisk-seed.sh --mount

# Option B: External SSD at /mnt/g/fuzz-ssd (1TB — extended fuzzing)
# Mount:  sudo mount -o defaults,noatime /dev/sde /mnt/g
# Seed:   .github/scripts/ramdisk-seed.sh --ramdisk /mnt/g/fuzz-ssd
# Fuzz:   cfl/fuzz-local.sh -r /mnt/g/fuzz-ssd
# Merge:  .github/scripts/ramdisk-merge.sh --ramdisk /mnt/g/fuzz-ssd
# Sync:   .github/scripts/ramdisk-sync-to-disk.sh --ramdisk /mnt/g/fuzz-ssd
# Status: .github/scripts/ramdisk-status.sh /mnt/g/fuzz-ssd

# End-of-session SSD cleanup (see .github/prompts/corpus-management.prompt.md):
# 1. Clear stale profraw:  find /mnt/g/fuzz-ssd -name '*.profraw' -delete
# 2. Preserve artifacts:   rsync crash-*/oom-*/slow-unit-* to repo
# 2b. Preserve timeouts:   rsync timeout-* to test-profiles/cwe-400/
# 3. Parallel rsync:       10 concurrent rsyncs with --ignore-existing
# 4. Verify:               local count >= SSD count per fuzzer
# 5. Clean SSD:            rm -rf corpus-*/bin/dict/seed/profraw/logs

# Status check
.github/scripts/ramdisk-status.sh

# Run a single fuzzer (smoke test, 60 seconds)
LLVM_PROFILE_FILE=/tmp/fuzz-ramdisk/profraw/icc_profile_fuzzer_%m_%p.profraw \
ASAN_OPTIONS=detect_leaks=0 \
FUZZ_TMPDIR=/tmp/fuzz-ramdisk \
  /tmp/fuzz-ramdisk/bin/icc_profile_fuzzer \
  -max_total_time=60 -detect_leaks=0 -timeout=30 -rss_limit_mb=4096 \
  -use_value_profile=1 -max_len=5242880 \
  -artifact_prefix=/tmp/fuzz-ramdisk/ \
  -dict=/tmp/fuzz-ramdisk/dict/icc_profile_fuzzer.dict \
  /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer/

# Corpus merge/minimize (after extended fuzzing)
.github/scripts/ramdisk-merge.sh

# Sync minimized corpus back to disk
.github/scripts/ramdisk-sync-to-disk.sh

# Generate coverage report
.github/scripts/merge-profdata.sh
.github/scripts/generate-coverage-report.sh
```

Special fuzzer notes:
- **icc_link_fuzzer** needs `ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256` (2 profiles per input = 2x ASAN memory). **Ownership caveat**: `CIccCmm::AddXform(CIccProfile*)` transfers ownership to `CIccXform::Create`, which may free the profile even on failure. On `icCmmStatBadXform`, do NOT delete the profile (already freed). On other error codes, the profile was not consumed and must be deleted.
- Coverage collection: `LLVM_PROFILE_FILE=$RAMDISK/profraw/${fuzzer_name}_%m_%p.profraw` (include fuzzer name — `%m` is just a numeric hash)
- Suppress profile errors during fuzzing: `LLVM_PROFILE_FILE=/dev/null`
- **Begin()/Apply() pattern**: `CIccTagMultiProcessElement::Begin()` and `CIccMpeCurveSet::Begin()` can return false when sub-curves have invalid state (e.g., `m_nCount < 2`). Always check the return value — `Apply()` will NULL-deref `m_pSamples` otherwise (CWE-476). This is an upstream bug in multiple tools (patched in CFL-072 for IccV5DspObsToV4Dsp). Audit all fuzzers that call `Begin()` then `Apply()`.
- **Multi-profile crash triage**: For fuzzers with concatenated input formats (v5dspobs, link, applyprofiles), do NOT pass the raw crash file to the tool — it will fail with "Unable to parse". Use `.github/scripts/unbundle-fuzzer-input.sh` to extract profiles first.

## FAILURE IDENTIFICATION — READ THIS

You MUST accurately report failures. Do NOT claim success when errors occur.

**How to detect failures:**
1. **Exit code != 0** — Any non-zero exit code is a failure or finding. Report it explicitly.
2. **ASAN output** — Lines containing `ERROR: AddressSanitizer` indicate memory safety bugs. This is a CRITICAL finding.
3. **UBSAN output** — Lines containing `runtime error:` indicate undefined behavior. This is a finding.
4. **Signal termination** — Exit codes 128+ (e.g., 134=SIGABRT, 137=SIGKILL, 139=SIGSEGV) are crashes. Report as CRITICAL.
5. **Timeout** — If a tool hangs, that is a finding (possible infinite loop/recursion). Kill it after 60 seconds.
6. **Empty output** — If a tool produces no stdout, something went wrong. Report it.

**What counts as SUCCESS:** Exit code 0 AND no ASAN/UBSAN stderr AND non-empty output.

**ASAN/UBSAN Attribution — MANDATORY** (CJF Envelope Rule):
When reporting any ASAN/UBSAN finding, you MUST:
1. Read stack frame #2-#3 to identify the **actual source file:line**
2. Classify by **file path**, NEVER by profile filename:
   - Path contains `iccanalyzer-lite/`, `colorbleed_tools/`, `cfl/` (non-iccDEV) → **OUR CODE** → fix immediately
   - Path contains `iccDEV/` → **UPSTREAM** → cite specific file:line and upstream issue#
3. If claiming "pre-existing", provide the **commit SHA** where it was introduced
4. NEVER store a memory or update a baseline without completing steps 1-3

**Incident reference**: Session 2026-03-10 — agent misclassified HUAF in
`IccImageAnalyzer.cpp:962` as "upstream iccDEV" because the profile was named
`ub-runtime-error-type-confusion-*`. The ASAN trace clearly showed our code at
frames #2 and #5. Bug sat unfixed for an entire session. Fix was 10 lines.

**What you MUST NOT do:**
- Do NOT say "analysis completed successfully" if exit code was non-zero
- Do NOT omit ASAN/UBSAN stderr from the report
- Do NOT summarize tool output — include it VERBATIM
- Do NOT skip any of the 3 required commands (`-a`, `-nf`, `-r`)
- Do NOT classify ASAN findings by profile filename — READ THE STACK FRAMES
- Do NOT accept a test count regression as "baseline" without attribution evidence

## VERIFICATION PROTOCOL — MANDATORY

**Origin**: [xsscx/governance](https://github.com/xsscx/governance) — 62.5% of all
agent violations are false success claims. This protocol exists because agents
systematically declare success without verifying it.

### Evidence-Based Claims

Every success claim MUST include verification evidence in this format:
```
[OK] Verified: <claim> (<command> → <result>)
```

**Examples:**
- `[OK] Verified: build succeeded (cd iccanalyzer-lite && ./build.sh → exit 0)`
- `[OK] Verified: 230 tests pass (python3 tests/run_tests.py → 230/230 passed)`
- `[OK] Verified: 0 ASAN errors (./iccanalyzer-lite -a profile.icc 2>&1 | grep -c AddressSanitizer → 0)`
- `[OK] Verified: all 7 build locations synced (.github/scripts/pre-push-validate.sh → exit 0)`

### Exit Code Classification (CJF-13)

Exit codes have precise meaning. Misclassifying them is the #1 crash documentation error:

| Exit Code | Classification | Meaning | Document as crash? |
|-----------|---------------|---------|-------------------|
| **0** | Success | Clean exit | No |
| **1-127** | Soft failure | Graceful error, input rejected | **NO — NOT a crash** |
| **128+** | Hard crash | Signal termination | **YES (if 3× reproducible)** |

**Signal mapping**: 134=SIGABRT, 136=SIGFPE, 137=SIGKILL, 139=SIGSEGV

**CRITICAL**: A tool exiting with code 1 is NOT a crash — it means the tool rejected
the input gracefully. Do NOT document exit code 1 as a security finding.
The **tool's** exit code is reality. The **fuzzer's** DEADLYSIGNAL is a test artifact.
When they disagree, the tool is authoritative.

### Pre-Push Build Verification

Before pushing ANY iccanalyzer-lite changes:
```bash
# 1. Build locally
cd iccanalyzer-lite && ./build.sh

# 2. Run tests
python3 tests/run_tests.py

# 3. ASAN spot-check (5+ diverse profiles)
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 ./iccanalyzer-lite -a ../test-profiles/sRGB_D65_MAT-500lx.icc

# 4. Verify ALL 7 build locations are synced
.github/scripts/pre-push-validate.sh

# 5. Only then push
git push
```

Step 4 is **mandatory**. A local `build.sh` success does NOT guarantee CI success.
See Anti-Pattern #5 in `multi-agent.instructions.md`.

### Contradiction Detection

If you make a numeric claim (e.g., "built 18 fuzzers", "329 test profiles"),
verify it with a command before stating it:
```bash
ls cfl/bin/icc_*_fuzzer | wc -l     # verify fuzzer count
find test-profiles -name '*.icc' | wc -l  # verify profile count
find analysis-reports -name '*.md' | wc -l  # verify report count
```

If a count changes between turns, acknowledge the correction explicitly.
Do NOT silently revise numbers.

### Agent Accountability

This project maintains an agent violation record at
[xsscx/governance](https://github.com/xsscx/governance). Key documents:
- `HALL_OF_SHAME.md` — Documented violations with root cause analysis
- `VAULT_OF_SHAME.md` — Cryptographic fingerprints of all violations
- `README_CLAIM_VERIFICATION.md` — Evidence-based validation system
- `PATTERNS.md` — Common failure patterns and prevention

The user is the source of truth. When the user corrects an agent claim,
the agent is wrong. Full stop.

## Build Commands (REFERENCE ONLY — do NOT run these)

These commands are for CI documentation. For local builds, see **Local Build** above.

## Fuzzing

```bash
# Automated ramdisk workflow (mounts tmpfs, seeds corpus, runs all 18 fuzzers)
cd cfl && ./ramdisk-fuzz.sh

# Local fuzzing (uses existing ramdisk or external SSD)
cd cfl && ./fuzz-local.sh                      # default: /tmp/fuzz-ramdisk
cd cfl && ./fuzz-local.sh -r /mnt/g/fuzz-ssd   # external SSD

# Storage management scripts (in .github/scripts/)
# All accept --ramdisk PATH to override default /tmp/fuzz-ramdisk
.github/scripts/ramdisk-status.sh       # Report storage state
.github/scripts/ramdisk-clean.sh        # Remove stray dirs (dry-run default)
.github/scripts/ramdisk-merge.sh        # LibFuzzer -merge=1 dedup
.github/scripts/ramdisk-sync-to-disk.sh # Sync corpus storage → cfl/corpus-*
.github/scripts/ramdisk-seed.sh         # Seed corpus disk → storage
.github/scripts/ramdisk-teardown.sh     # Orchestrate sync → clean → unmount

# Single fuzzer on ramdisk (short smoke test)
cfl/bin/icc_profile_fuzzer -max_total_time=60 -rss_limit_mb=4096 \
  -dict=cfl/icc_profile.dict /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer

# Single fuzzer on ramdisk (extended 4-hour run with env vars)
FUZZ_TMPDIR=/tmp/fuzz-ramdisk LLVM_PROFILE_FILE=/dev/null \
  /tmp/fuzz-ramdisk/bin/icc_toxml_fuzzer -max_total_time=14400 -detect_leaks=0 \
  -timeout=30 -rss_limit_mb=4096 -use_value_profile=1 -max_len=5242880 \
  -artifact_prefix=/tmp/fuzz-ramdisk/ \
  -dict=/tmp/fuzz-ramdisk/dict/icc_toxml_fuzzer.dict \
  /tmp/fuzz-ramdisk/corpus-icc_toxml_fuzzer/

# Link fuzzer needs quarantine cap (2 profiles per input = 2x ASAN memory)
ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256 \
FUZZ_TMPDIR=/tmp/fuzz-ramdisk LLVM_PROFILE_FILE=/dev/null \
  /tmp/fuzz-ramdisk/bin/icc_link_fuzzer -max_total_time=14400 -detect_leaks=0 \
  -timeout=30 -rss_limit_mb=4096 -use_value_profile=1 -max_len=5242880 \
  -artifact_prefix=/tmp/fuzz-ramdisk/ \
  -dict=/tmp/fuzz-ramdisk/dict/icc_link_fuzzer.dict \
  /tmp/fuzz-ramdisk/corpus-icc_link_fuzzer/

# Corpus merge/minimize
.github/scripts/ramdisk-merge.sh              # all fuzzers
.github/scripts/ramdisk-merge.sh --jobs 32    # parallel

# Validate seed corpus readiness
.github/scripts/test-seed-corpus.sh

# Unbundle multi-profile crash files for manual tool reproduction
.github/scripts/unbundle-fuzzer-input.sh v5dspobs <crash-file>
.github/scripts/unbundle-fuzzer-input.sh link <crash-file>
.github/scripts/unbundle-fuzzer-input.sh applyprofiles <crash-file>
# Extracts profiles to ./tmp/icc_<fuzzer>/, runs tool if found in iccDEV/Build/Tools/
```

## MCP Server

The ICC Profile MCP server exposes 24 tools (11 analysis + 7 maintainer + 6 operations) for AI-assisted ICC profile security research.

### Setup — Four integration methods

#### 1. Copilot CLI (`/mcp` command)
Use `/mcp` to add the server with stdio transport:
- Command: `python3 mcp-server/icc_profile_mcp.py`
- Prereq: `cd mcp-server && pip install -e .`

#### 2. VS Code Copilot Chat
Already configured in `.vscode/mcp.json`. Open the repo in VS Code and tools auto-register.
Prereq: `cd mcp-server && pip install -e .`

#### 3. GitHub Copilot Coding Agent (cloud)
Paste `.github/copilot-mcp-config.json` into repo Settings → Copilot → Coding agent → MCP configuration. The `copilot-setup-steps.yml` workflow extracts pre-built binaries from the Docker image — **no build step runs**. The MCP config exposes all 24 tools (11 analysis + 7 maintainer + 6 operations).

#### 4. Docker REST API (remote agents — macOS, CI, any platform)
Run the MCP Docker image for remote ICC analysis with full ASAN+UBSAN instrumentation.
Image is `linux/amd64` — on Apple Silicon Macs, **Docker Desktop** runs it via Rosetta 2
(which supports ASAN). **Colima and OrbStack do NOT support ASAN** — they use
QEMU/VZ backends that cannot handle ASAN shadow memory mappings:
```bash
# Start API server (Apple Silicon: runs via Rosetta 2 automatically)
docker run --rm -d -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web

# Upload and analyze from any machine
curl -s -F "file=@profile.icc" http://<host>:8080/api/upload
curl -s "http://<host>:8080/api/security-json?path=<uploaded_path>"
curl -s "http://<host>:8080/api/full?path=<uploaded_path>"
```
Key endpoints: `/api/upload` (POST), `/api/security-json` (GET), `/api/full` (GET),
`/api/inspect` (GET), `/api/roundtrip` (GET), `/api/xml` (GET), `/api/compare` (GET),
`/api/health` (GET). See `.github/prompts/remote-analysis.prompt.md` for the full workflow.

### Reusable Prompts

Sixteen prompt templates in `.github/prompts/` guide AI through standard analysis workflows:
- `analyze-icc-profile.prompt.yml` — full 150-heuristic security scan
- `compare-icc-profiles.prompt.yml` — side-by-side structural diff
- `triage-cve-poc.prompt.yml` — CVE PoC analysis with CVE mapping
- `triage-fuzzer-crash.prompt.md` — fuzzer crash triage, minimization, and patch workflow
- `triage-fuzzer-oom.prompt.yml` — LibFuzzer OOM triage and patch workflow
- `health-check.prompt.yml` — MCP server verification
- `image-fuzzer-quality.prompt.md` — xnuimagefuzzer output quality assessment
- `mac-catalyst-ci.prompt.md` — Mac Catalyst CI debugging guide
- `improve-fuzzer-coverage.prompt.md` — Coverage gap analysis and seed creation workflow
- `corpus-management.prompt.md` — SSD/ramdisk corpus lifecycle, migration, and coverage reporting
- `upstream-sync.prompt.md` — CFL iccDEV patch reconciliation after upstream updates
- `remote-analysis.prompt.md` — MCP Docker API for remote ICC analysis (macOS/CI agents)
- `cooperative-development.prompt.md` — Multi-agent task lists and coverage roadmap
- `fuzz-corpus-analysis.prompt.md` — Fuzz corpus quality and coverage analysis
- `fuzzer-optimization.prompt.md` — Per-fuzzer coverage optimization strategies
- `cve-enrichment.prompt.md` — CVE-to-heuristic mapping and enrichment

### ICC file attachments on GitHub Issues
GitHub does not allow `.icc` file attachments. Users should rename files to `.icc.txt` before attaching. When processing an issue with an attached `.icc.txt` file:
1. Download the attachment
2. Rename from `*.icc.txt` to `*.icc`
3. Run the analysis tools against the renamed file

### Required analysis workflow for ICC profile issues
When an issue asks to analyze an ICC profile, perform **two phases**:

**Note**: For TIFF image files, use `./iccanalyzer-lite/iccanalyzer-lite -a <file.tif>` which
auto-detects TIFF format, extracts embedded ICC profiles, and runs full 150-heuristic analysis (H1-H138 on ICC + H139-H141, H149-H150 on TIFF + H142-H145 XML + H146-H148 data validation).

#### Phase 1 — MCP tool analysis (Copilot's independent review)
Use the MCP tools to perform your own analysis of the profile before running the script:

1. **`inspect_profile`** — Examine the profile structure: header fields, tag table, data values
2. **`analyze_security`** — Run the 150-heuristic security scan (H1–H150)
3. **`validate_roundtrip`** — Check AToB/BToA and DToB/BToD tag pair completeness
4. **`profile_to_xml`** — Convert to XML for human-readable inspection

Write a summary of your independent findings in the PR description under a **"## MCP Tool Analysis"** heading. Include:
- Profile class, color space, PCS, version, creator
- Any heuristic warnings or critical findings from `analyze_security`
- Round-trip validation status
- Notable structural observations (unusual tags, suspicious sizes, etc.)

#### Phase 2 — iccanalyzer-lite report (automated script)
Run the analysis script to generate the full report:

```bash
.github/scripts/analyze-profile.sh test-profiles/<filename>.icc
```

This script runs all 3 analysis commands (`-a`, `-nf`, `-r`), captures exit codes and ASAN/UBSAN output, and writes the complete report to `analysis-reports/`. Do NOT run the 3 commands individually.

#### Commit and PR
1. `git add analysis-reports/ && git commit -m "Analysis: <profile-name>"`
2. Update the PR description with:
   - **MCP Tool Analysis** section (from Phase 1)
   - **iccanalyzer-lite Results** section with exit code summary from the script
   - ASAN/UBSAN findings noted prominently if detected
3. Post each report as a comment on the originating issue:
   ```bash
   gh issue comment <ISSUE_NUMBER> --body "$(cat analysis-reports/<profile>-analysis.md)"
   ```

The script exits with the worst exit code across all 3 commands. Exit 0 = clean, 1 = finding, 2 = error.

### Code coverage for a single profile
Use `iccdev-single-profile-coverage.yml` (NOT `ci-code-coverage.yml`) for per-profile coverage. The full coverage workflow runs `CreateAllProfiles.sh` which pollutes results with hundreds of generated profiles. The single-profile workflow accepts a `profile_path` input (relative to `test-profiles/`) and runs only IccDumpProfile, IccRoundTrip, XML round-trip, and IccApplyProfiles against that one file.

### Docker Container

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web
```

Open http://localhost:8080/ — WebUI with REST API at `/api/*`. Two modes: `mcp` (default, stdio), `web` (REST API + HTML UI).

**Docker validation gate (MANDATORY before pushing Dockerfile/MCP changes)**:
```bash
# Local build + test
docker build -t icc-mcp-local:test -f mcp-server/Dockerfile .
docker run --rm -d -p 8081:8080 --name mcp-test icc-mcp-local:test web
curl -s http://localhost:8081/api/health          # → {"ok":true,"tools":24}
docker exec mcp-test which xmllint               # → /usr/bin/xmllint
docker stop mcp-test
# Then push → CI rebuilds → pull latest → re-validate
```

**CRITICAL**: The Docker image MUST be built with ASAN+UBSAN (the whole point is
security analysis). Do NOT add `NO_SANITIZERS=1` or remove `libclang-rt-18-dev`.
Image is `linux/amd64` only — ASAN shadow memory is incompatible with QEMU
cross-arch emulation. Apple Silicon Macs run it via **Docker Desktop** Rosetta 2.
**Colima and OrbStack do NOT support ASAN** (QEMU/VZ backends lack shadow memory).

**Tool count**: 24 tools (11 analysis + 7 maintainer + 6 operations). When adding
tools, update: `icc_profile_mcp.py`, `web_ui.py`, `test_mcp.py`, `test_web_ui.py`.

**Build sync**: iccanalyzer-lite has **7 independent build locations** (see
`.github/instructions/iccanalyzer-lite.instructions.md`). When adding library deps
(e.g., `-lssl -lcrypto`), ALL 7 must be updated — especially `iccanalyzer-cli-release.yml`
which has its own manual static link command. A local `build.sh` success does NOT
guarantee CI success.

**REST API endpoints** (same parameter names as MCP tools):

| Endpoint | Method | Parameters |
|----------|--------|------------|
| `/api/health` | GET | — |
| `/api/list` | GET | `directory` |
| `/api/inspect` | GET | `path` |
| `/api/security` | GET | `path` |
| `/api/roundtrip` | GET | `path` |
| `/api/full` | GET | `path` |
| `/api/xml` | GET | `path` |
| `/api/compare` | GET | `path_a`, `path_b` |
| `/api/upload` | POST | `file` (multipart) |

### MCP Tool Quick Reference

For the complete 24-tool reference (11 analysis + 7 maintainer + 6 operations),
see [mcp-server.instructions.md](instructions/mcp-server.instructions.md).

**Key analysis tools** (exposed to coding agent):
- `analyze_security` — 150-heuristic security scan (fastest, most actionable)
- `full_analysis` — All 3 modes (`-a`, `-nf`, `-r`) for comprehensive reports
- `inspect_profile` — Header fields, tag table, data values
- `validate_roundtrip` — AToB/BToA tag pair completeness
- `profile_to_xml` — ICC→XML conversion
- `compare_profiles` — Unified diff of two profiles
- `upload_and_analyze` — Base64 upload + analysis

**Path resolution**: filename (`sRGB_D65_MAT.icc`), relative (`test-profiles/sRGB_D65_MAT.icc`),
or absolute path. GitHub blocks `.icc` attachments — rename to `.icc.txt` before uploading.

**Interpreting results**: Exit 0=clean, 1=finding, 2=error. Look for `[H1]`–`[H145]` prefixes.
ASAN/UBSAN in stderr = CRITICAL memory safety finding.

**Automated issue→PR→merge**: Create issue → assign Copilot via GitHub UI → agent runs MCP tools +
`analyze-profile.sh` → commits report → `copilot-auto-merge.yml` squash-merges on completion.

## Architecture

This repo contains security research tools targeting the ICC color profile specification
via the iccDEV library. Each component has detailed documentation in its instructions file.

| Component | Purpose | Instructions |
|-----------|---------|--------------|
| **iccanalyzer-lite/** | 150-heuristic security analyzer (ASAN+UBSAN). Links **unpatched** upstream iccDEV — does NOT receive CFL patches. | [iccanalyzer-lite.instructions.md](instructions/iccanalyzer-lite.instructions.md) |
| **cfl/** | 18 LibFuzzer harnesses + 68 security patches applied to a separate iccDEV clone. | [cfl.instructions.md](instructions/cfl.instructions.md) |
| **mcp-server/** | 24-tool MCP server (FastMCP) + REST API + WebUI wrapping the analyzer. | [mcp-server.instructions.md](instructions/mcp-server.instructions.md) |
| **colorbleed_tools/** | Intentionally unsafe ICC↔XML converters (no ASAN — tests real-world crash surface). | [colorbleed_tools.instructions.md](instructions/colorbleed_tools.instructions.md) |
| **fuzz/** | 1,139 curated malicious input files (CVE PoCs, injection signatures, malformed media). | [fuzz.instructions.md](instructions/fuzz.instructions.md) |
| **call-graph/** | LLVM-based call graphs + AST dumps for 37 compilation targets. | [call-graph.instructions.md](instructions/call-graph.instructions.md) |
| **test-profiles/** | 329 ICC profiles for fuzzing and regression testing. |
| **.github/scripts/** | Shell/Python scripts for analysis, fuzzing, ramdisk, coverage, corpus handling. |

Each iccDEV subdirectory (under cfl/, iccanalyzer-lite/, colorbleed_tools/) is an independent
clone of the upstream library — they are not shared.

## Key Conventions

### Script locations
All scripts MUST live in `.github/scripts/` (or subdirectories). Never place scripts in `cfl/`, `analysis-reports/`, or the repo root.
- Shell scripts: `.github/scripts/*.sh`
- Python utilities: `.github/scripts/*.py`
- Call graph analysis: `.github/scripts/callgraphs/*-callgraph.py`
- Build scripts: `cfl/build.sh`, `iccanalyzer-lite/build.sh` (exception — build scripts stay with their component)

### No emojis
Do not use emojis in code, CI output, or reports. Use bracketed text labels: `[OK]`, `[WARN]`, `[FAIL]`, `[SKIP]`, `[CRITICAL]`, `[INFO]`.

### Exit codes (iccanalyzer-lite)
Deterministic exit codes defined in `IccAnalyzerErrors.h`:
- `0` — Clean (no findings)
- `1` — Finding (heuristic detections)
- `2` — Error (I/O, parse, or runtime failure)
- `3` — Usage (bad arguments)

Signals (128+N) are never returned by the analyzer — their presence always indicates a real crash. `NormalizeExit()` in main clamps unbounded raw returns.

### Non-fatal diagnostic macros
Upstream `ICC_TRACE_NAN` calls `__builtin_trap()` and `ICC_SANITY_CHECK_SIGNATURE` calls `assert(false)` — both fatal. `IccAnalyzerCommon.h` overrides them to log-only (non-fatal) via `#undef`/`#define` AFTER `#include "IccSignatureUtils.h"`.

### CFL fuzzer conventions
See [cfl.instructions.md](instructions/cfl.instructions.md) for fuzzer structure, scope alignment,
dictionary files, build categories, OOM triage, and CMM seed creation formats.

### UBSAN fix patterns
When writing bounds-check arithmetic in heuristic code, always use `(uint64_t)` widening to prevent unsigned overflow:
```cpp
// WRONG (UBSAN when tOff is 0xFFFFFFFF):
if (tOff + 12 > fileSize) continue;

// CORRECT:
if ((uint64_t)tOff + 12 > fileSize) continue;

// For wraparound detection:
if (tagOffset > 0 && tagSize > 0 && ((uint64_t)tagOffset + tagSize) > 0xFFFFFFFFULL) { ... }
```
When extracting ICC signatures into `char[5]`, always cast through `unsigned char`:
```cpp
// WRONG (UBSAN implicit-conversion when value > 127):
sigCC[0] = (sig >> 24) & 0xFF;
sigCC[0] = (char)((sig >> 24) & 0xFF);

// CORRECT:
sigCC[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));
```
Use `SignatureToFourCC()` helper when displaying signatures (trims trailing spaces).

**Known upstream UBSAN** (in iccDEV library, not our code):
- `IccCAM.cpp:262,266` — division by zero in CAM color appearance model (m_WhitePoint[1] can be 0)
- `IccProfile.cpp:3153,3155` — division by zero (m_illuminantXYZ.Y can be 0)
- `IccTagLut.cpp:5009` — signed integer overflow in LUT matrix validation (int sum += m_XYZMatrix)
- `IccMatrixMath.cpp:386` — NaN→unsigned short in SetRange (patch 051 fixes in CFL)

**Fixed upstream** (no longer triggered in our pinned iccDEV at `1ffa7a8` / v2.3.1.5):
- `IccSignatureUtils.h` — uint→char implicit conversion (fixed in PR #648, now uses static_cast)
- `iccApplyProfiles.cpp UnitClip` — NaN→unsigned char (fixed in PR #654, now handles NaN/Inf)
- `IccMD5.cpp` — unsigned wrapping (intentional, not UB per spec)

### CFL patch workflow
See [cfl.instructions.md](instructions/cfl.instructions.md) for patch creation, naming conventions,
NO-OP management, and reproducer testing. Next patch number: **083**.

### Crash reproducer testing
```bash
# Single fuzzer test
ASAN_OPTIONS=detect_leaks=0 /tmp/fuzz-ramdisk/bin/<fuzzer_name> test-profiles/<crash-file>.icc 2>&1 | grep -c "ERROR: AddressSanitizer"

# Batch all fuzzers against a profile
for f in /tmp/fuzz-ramdisk/bin/icc_*_fuzzer; do echo -n "$(basename $f): "; ASAN_OPTIONS=detect_leaks=0 timeout 10 "$f" test-profiles/<file>.icc 2>&1 | grep -c "ERROR: AddressSanitizer" || true; done
```

### CVE/GHSA reference
77 CVEs reported for iccDEV (as of Feb 2026). Top CWEs by frequency:
CWE-20 (49), CWE-122 (17), CWE-476 (16), CWE-125 (11), CWE-758 (11), CWE-787 (10).
1 Critical (CVE-2026-21675: UAF in CIccXform::Create, CVSS 9.8), 45 High, 30 Medium, 1 Low.
Full list: `https://github.com/InternationalColorConsortium/iccDEV/security/advisories`

### Sanitizer flags
- **Fuzzers**: `-fsanitize=fuzzer,address,undefined -fprofile-instr-generate -fcoverage-mapping`
- **iccanalyzer-lite**: `-fsanitize=address,undefined,float-divide-by-zero,float-cast-overflow,integer -g3 -O0 -fprofile-instr-generate -fcoverage-mapping`
- Both the iccDEV libs AND the tool linking them must use matching sanitizer flags
- Suppress LLVM profile errors during fuzzing: `LLVM_PROFILE_FILE=/dev/null`
- iccDEV diagnostic flags: `-DICC_LOG_SAFE=ON -DICC_TRACE_NAN_ENABLED=ON` (cmake) or `-DICC_LOG_SAFE -DICC_TRACE_NAN_ENABLED` (CXXFLAGS)

### UBSAN fix patterns (iccanalyzer-lite code)
- ICC 4-byte signatures use values >127 (e.g. 0xBD = 189). Extracting to `char` triggers UBSAN implicit-conversion. ALWAYS use `static_cast<char>()`.
- Prefer `SignatureToFourCC()` helper — handles cast correctly AND trims trailing spaces.
- For `tOffset + tSize` (both `icUInt32Number`), widen to `(uint64_t)` before adding to prevent unsigned overflow.
- When adding new heuristics with raw signature display, grep for existing patterns: `SignatureToFourCC(sig, fourcc)` → `printf("(%s)", fourcc)`.

### Coverage and fuzzer build details
See [cfl.instructions.md](instructions/cfl.instructions.md) for fuzzer build categories,
CMM seed formats, coverage workflow, and fuzzer-specific notes.

### CodeQL static analysis
- **All prerequisites pre-installed** — `gh codeql` CLI, query packs, build script. Do NOT re-install or re-download.
- **Build script**: `.github/scripts/codeql-build.sh` (committed) — has all correct flags (`-DICCANALYZER_LITE`, `-I/usr/include/libxml2`, per-file compilation). NEVER recreate this script ad-hoc.
- **Database**: `/tmp/codeql-db-analyzer` — persists across sessions. Rebuild only when code changes: `gh codeql database create /tmp/codeql-db-analyzer --language=cpp --overwrite --command=".github/scripts/codeql-build.sh" --source-root="$(git rev-parse --show-toplevel)"`
- **Analyze**: `gh codeql database analyze /tmp/codeql-db-analyzer --format=sarif-latest --output=/tmp/codeql-results.sarif --threads=0 codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls iccanalyzer-lite/codeql-queries/`
- **Filter**: `python3 -c "import json; [print(r['ruleId'], r['locations'][0]['physicalLocation']['artifactLocation']['uri']) for r in json.load(open('/tmp/codeql-results.sarif'))['runs'][0]['results'] if 'iccanalyzer-lite' in r['locations'][0]['physicalLocation']['artifactLocation']['uri']]"`
- **Status** (March 2026): 0 actionable alerts in analyzer code. 8 informational/false-positive (custom queries + bounds-guarded access). 10 in iccDEV upstream (not modifiable). Fixed patterns: `std::nothrow` for operator new in fork children (`cpp/new-free-mismatch`), range-based for instead of cached iterators (`cpp/use-after-expired-lifetime`), replace always-exiting loops with if-blocks (`cpp/comparison-always-true`).
- **Anti-patterns**: ❌ re-installing gh-codeql, ❌ re-downloading query packs, ❌ creating ad-hoc build scripts, ❌ iterating on build flags. See `iccanalyzer-lite.instructions.md` "Local CodeQL Analysis" for the complete fast-path workflow.

### Byte-shift patterns
`(data[i] << 24)` causes signed integer overflow when `data[i] >= 128`. Fix: `static_cast<icUInt32Number>(data[i]) << 24`. Similarly, use `tagOffset <= fileSize - tagSize` instead of `tagOffset + tagSize <= fileSize`.

### NaN/float-to-integer safety
IEEE 754 NaN fails ALL ordered comparisons (`NaN < 0` → false, `NaN > 1` → false). Clamp functions like `UnitClip(v) { if(v<0) return 0; if(v>1) return 1; return v; }` pass NaN through to integer casts (UBSAN CWE-758). Fix pattern:
```cpp
// NaN self-inequality idiom (avoids std::isnan header dependency)
if (v != v) return 0.0;  // must be FIRST check, before any comparison
if (v < 0.0) return 0.0;
if (v > 1.0) return 1.0;
return v;
```
This pattern applies to any float→integer conversion path (unsigned char, unsigned short, uint16_t). For float arrays before cast, guard with: `if (std::isnan(val) || std::isinf(val)) val = 0.0f; else if (val < 0.0f) val = 0.0f; else if (val > 1.0f) val = 1.0f;`

### AddXform ownership semantics
`CIccCmm::AddXform(CIccProfile*, ...)` transfers profile ownership to `CIccXform::Create()`. On success, the CMM owns the profile — do not delete. On `icCmmStatBadXform` failure, `Create()` already freed the profile — do NOT delete (double-free → heap-use-after-free CWE-416). On other error codes (`BadSpaceLink`, `BadLutType`, etc.), `Create()` was never reached — the caller must delete. Pattern:
```cpp
icStatusCMM stat = cmm.AddXform(pProfile, ...);
if (stat != icCmmStatOk) {
  if (stat != icCmmStatBadXform)
    delete pProfile;  // only delete if Create() was never called
  return;
}
// pProfile now owned by cmm — do not delete
```

### MCP server conventions
See [mcp-server.instructions.md](instructions/mcp-server.instructions.md) for security model,
path validation, Docker build policy, tool count sync, and API details.

### CI workflows
31 workflows use `workflow_dispatch` (manual trigger). Actions are 100% SHA-pinned. Key workflows:
- `copilot-auto-merge.yml` — Auto squash-merges Copilot coding agent PRs on agent `workflow_run` completion
- `libfuzzer-smoke-test.yml` — 60-second smoke test for all 18 fuzzers
- `cfl-libfuzzer-parallel.yml` — Extended parallel fuzzing with dict auto-selection and auto-merge
- `codeql-security-analysis.yml` — 17 custom C++ queries x 3 targets + 3 custom Python queries + security-and-quality
- `iccanalyzer-cli-release.yml` — CLI test suite + release artifacts
- `iccanalyzer-lite-debug-sanitizer-coverage.yml` — Debug+ASan+UBSan+coverage with structured exit code dispatch
- `mcp-server-test.yml` — MCP server unit tests
- `copilot-setup-steps.yml` — Coding agent environment setup

### CI caching
16 workflows have 3-layer caching: APT packages → iccDEV clone → iccDEV build. Cache keys include patch hashes and build config suffixes (lite-debug, lite-debug-san, lite-coverage, lite-reldbg, cfl, mcp, scan). SHA-pinned: `actions/cache@5a3ec84eff668545956fd18022155c47e93e2684`.

### CI exit code handling
With `set -euo pipefail`, non-zero exits from `timeout` abort the script. Use `EXIT_CODE=0; timeout ... || EXIT_CODE=$?` pattern instead of bare `timeout` calls.

### CodeQL
15 custom queries shared across cfl/, iccanalyzer-lite/, and colorbleed_tools/ (buffer-overflow, integer-overflow, XXE, UAF, type-confusion, enum UB, unchecked I/O, injection, argv-output-path, alloc-dealloc-mismatch, etc.). Config in each target's `codeql-config.yml`. All 3 `security-research-suite.qls` files must be kept in sync.

### Compiler
All C++ code requires clang/clang++. GCC is used only in the colorbleed_tools CI matrix build.

### Workflow Shell Prologue
All workflow `run:` steps must follow the governance shell prologue template:
```yaml
shell: bash --noprofile --norc {0}
env:
  BASH_ENV: /dev/null
run: |
  set -euo pipefail
  source .github/scripts/sanitize-sed.sh 2>/dev/null || true
```
- `shell` and `BASH_ENV` may be set at the job level via `defaults.run.shell` and job-level `env`
- `set -euo pipefail` must be the first line of every `run:` block
- `source .github/scripts/sanitize-sed.sh` is required in every step that writes to `$GITHUB_STEP_SUMMARY`
- Reference: `https://github.com/xsscx/governance/blob/main/actions/hoyt-bash-shell-prologue-actions.md`

### Workflow Output Sanitization
All data written to `$GITHUB_STEP_SUMMARY` or `$GITHUB_OUTPUT` must be sanitized against injection:
- Source `.github/scripts/sanitize-sed.sh` to make sanitization functions available
- Use `sanitize_line()` for single-line user-controllable strings (strips control chars, HTML-escapes, truncates)
- Use `sanitize_print()` for multi-line output (preserves LF, collapses blanks, HTML-escapes)
- Use `sanitize_codeblock()` inside markdown fenced code blocks (strips control chars, no HTML escape)
- Use `sanitize_ref()` for branch/tag names in filenames or concurrency groups
- Use `sanitize_filename()` for safe filenames (no directory traversal)
- User-controllable inputs include: `${{ inputs.* }}`, `${{ github.event.* }}`, `${{ steps.*.outputs.* }}`, command output via `$(...)`, file contents via `cat`
- Static strings (hardcoded labels, job status values) are safe but the sanitizer should still be sourced for defense-in-depth

## Image+ICC Seed Pipeline

See [multi-agent.instructions.md](instructions/multi-agent.instructions.md) for the full
Image+ICC seed pipeline (xnuimagetools, xnuimagefuzzer, seed-pipeline.sh, craft-seeds.py)
and macOS CI patterns (SIGPIPE prevention, Mac Catalyst launch, VideoToolbox ASAN, profraw symbols).
