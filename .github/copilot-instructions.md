# Copilot Instructions — ICC Security Research

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

## Environment Detection

This repo is used in two contexts. Detect which one you are in:

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
#                libclang-rt-18-dev (provides ASan/UBSan/fuzzer runtimes)

# Build iccanalyzer-lite (ASAN + UBSAN + coverage)
cd iccanalyzer-lite && ./build.sh

# Build CFL fuzzers (clones iccDEV, applies 57 patches, builds 18 fuzzers)
cd cfl && ./build.sh

# Build colorbleed_tools
cd colorbleed_tools && make setup && make
```

`cfl/build.sh` reuses an existing `cfl/iccDEV/` checkout if present — it does NOT reclone unless the directory is missing.

### iccDEV Tools — Source of Truth

**CRITICAL**: Two iccDEV checkouts exist with DIFFERENT purposes:

| Path | Purpose | Patched? |
|------|---------|----------|
| `iccDEV/Build/Tools/` | **Upstream reference tools (UNPATCHED)** | No |
| `cfl/iccDEV/` | CFL fuzzer build (60+ patches applied) | Yes |

**For crash fidelity testing**: ALWAYS use `iccDEV/Build/Tools/` (unpatched).
If the upstream tool doesn't crash but the fuzzer does, it's a fuzzer alignment
issue — not an upstream bug. NEVER use `cfl/iccDEV/` for this purpose.

```bash
# Run upstream tool against a PoC
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <profile.icc>
```

Available tools (15):
`iccApplyNamedCmm`, `iccApplyProfiles`, `iccApplySearch`, `iccApplyToLink`,
`iccDumpProfile`, `iccFromCube`, `iccFromXml`, `iccJpegDump`, `iccPngDump`,
`iccRoundTrip`, `iccSpecSepToTiff`, `iccTiffDump`, `iccToXml`,
`iccV5DspObsToV4Dsp`, `iccDumpProfileGui`

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

**Reference patches CFL-077 through CFL-081** are in `cfl/patches/` but NOT applied
to fuzzer builds — fuzzers should continue finding these patterns. Only
iccanalyzer-lite (H136-H138) detects them; colorbleed_tools may be hardened later.

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

5. **Harvest pipeline** — Extract ICC profiles and TIFF files from xnuimagetools/
   xnuimagefuzzer fuzzed-images and inject into CFL corpora:
   ```bash
   .github/scripts/harvest-xnu-seeds.sh              # local harvest
   .github/scripts/harvest-xnu-seeds.sh --dry-run     # preview only
   .github/scripts/harvest-xnu-seeds.sh --ramdisk /tmp/fuzz-ramdisk  # + deploy to ramdisk
   ```
   Both repos produce `cfl-seeds` artifacts in CI via `extract-icc-seeds.py`.

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
# 2. Preserve artifacts:   rsync crash-*/oom-*/timeout-*/slow-unit-* to repo
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

**What you MUST NOT do:**
- Do NOT say "analysis completed successfully" if exit code was non-zero
- Do NOT omit ASAN/UBSAN stderr from the report
- Do NOT summarize tool output — include it VERBATIM
- Do NOT skip any of the 3 required commands (`-a`, `-nf`, `-r`)

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

The ICC Profile MCP server exposes 22 tools (9 analysis + 7 maintainer + 6 operations) for AI-assisted ICC profile security research.

### Setup — Three integration methods

#### 1. Copilot CLI (`/mcp` command)
Use `/mcp` to add the server with stdio transport:
- Command: `python3 mcp-server/icc_profile_mcp.py`
- Prereq: `cd mcp-server && pip install -e .`

#### 2. VS Code Copilot Chat
Already configured in `.vscode/mcp.json`. Open the repo in VS Code and tools auto-register.
Prereq: `cd mcp-server && pip install -e .`

#### 3. GitHub Copilot Coding Agent (cloud)
Paste `.github/copilot-mcp-config.json` into repo Settings → Copilot → Coding agent → MCP configuration. The `copilot-setup-steps.yml` workflow extracts pre-built binaries from the Docker image — **no build step runs**. The MCP config exposes only the 9 analysis tools (build tools are excluded so the agent does not trigger unnecessary builds).

### Reusable Prompts

Eleven prompt templates in `.github/prompts/` guide AI through standard analysis workflows:
- `analyze-icc-profile.prompt.yml` — full 138-heuristic security scan
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

### ICC file attachments on GitHub Issues
GitHub does not allow `.icc` file attachments. Users should rename files to `.icc.txt` before attaching. When processing an issue with an attached `.icc.txt` file:
1. Download the attachment
2. Rename from `*.icc.txt` to `*.icc`
3. Run the analysis tools against the renamed file

### Required analysis workflow for ICC profile issues
When an issue asks to analyze an ICC profile, perform **two phases**:

**Note**: For TIFF image files, use `./iccanalyzer-lite/iccanalyzer-lite -a <file.tif>` which
auto-detects TIFF format, extracts embedded ICC profiles, and runs full 138-heuristic analysis.

#### Phase 1 — MCP tool analysis (Copilot's independent review)
Use the MCP tools to perform your own analysis of the profile before running the script:

1. **`inspect_profile`** — Examine the profile structure: header fields, tag table, data values
2. **`analyze_security`** — Run the 138-heuristic security scan (H1–H138)
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

### Docker Web UI

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:dev
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:dev web
```

Open http://localhost:8080/ — provides browser-based access to all analysis tools. The entrypoint command is `web` (not `icc-profile-web`).

### Developer Demo Container

```bash
docker pull ghcr.io/xsscx/icc-profile-demo:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-demo
```

Open http://localhost:8080/ — self-contained HTML demo report with live API at `/api/*`. Three modes: `demo` (default), `api` (production WebUI), `mcp` (stdio). Build locally with `docker build -f Dockerfile.demo -t icc-profile-demo .`

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

### Available MCP Tools — Detailed Reference

**Analysis tools (exposed to coding agent via `copilot-mcp-config.json`):**

| Tool | Args | Description |
|------|------|-------------|
| `inspect_profile` | `path` | Full structural dump using ninja-full mode. Shows header fields, tag table, tag data values. Use for understanding what's inside a profile. |
| `analyze_security` | `path` | 138-heuristic security scan (H1–H138). H1-H32: core structural validation. H33-H36: mBA/mAB sub-element OOB, integer overflow, fill patterns. H37-H45: CFL dictionary coverage (calc, curves, aliasing, alignment, v5 types). H46-H54: CWE-driven CVE coverage (unicode HBO, ncl2 overflow, CLUT grid, NaN/Inf, zero-size loop, channel counts, underflow, recursion, div-by-zero). H55-H60: UTF-16, calc depth, embedded profiles, spectral, dict. H61-H70: viewing conditions, mluc bombs, LUT channels, NamedColor2, chromaticity, NumArray, ResponseCurveSet, GBD, Profile ID, measurement. H71-H78: ColorantTable, SparseMatrix, nesting, type confusion, small tags, data flags, calculator, CLUT grid overflow. H79-H86: LoadTag overflow, UAF patterns, MPE channels, I/O bit-shift, float SBO, 3D LUT OOB, memcpy overlap, mluc HBO. H87-H94: TRC curve anomalies, chromatic adaptation matrix, profile sequence descriptions, preview tag channels, colorant order, spectral viewing conditions, embedded profile flags, matrix/TRC colorant consistency. H95-H102: sparse matrix array bounds, embedded profile recursion, profile sequence ID validation, spectral MPE elements, embedded image tags, profile sequence description, MPE channel continuity, tag size cross-check. H103-H106: PCC viewing conditions, PRMG gamut evaluation, matrix-TRC validation, environment variable tags. H107-H115: LUT channel/colorspace cross-check (patch 071 SBO root cause), private tag identification, shellcode/NOP-sled patterns, class-required tag validation, reserved byte validation, wtpt profile-class validation, round-trip fidelity, TRC curve monotonicity, characterization data. H116-H127: ICC Technical Secretary feedback — cprt/desc encoding per spec version, tag-type-per-signature validation, calculator computation cost estimate, round-trip ΔE measurement, curve invertibility assessment, characterization data round-trip, deep tag encoding validation (XYZ ranges, measurement, chromaticity), non-required tag classification, version-tag correspondence, overall transform smoothness, private tag malware content scan (PE/ELF/MachO/script signatures), private tag registry lookup. H128-H132: ICC.1-2022-05 spec compliance — version BCD encoding (§7.2.4), PCS illuminant exact D50 (§7.2.16), tag 4-byte alignment (§7.3.1), Profile ID MD5 verification (§7.2.18), chromaticAdaptation matrix determinant. H133-H135: ICC.1-2022-05 additional spec compliance — profile flags reserved bits (§7.2.11), tag type reserved bytes (§10.1), duplicate tag signatures (§7.3.1). H136-H138: CWE-400 systemic patterns — ResponseCurve per-channel measurement count (CFL-077), high-dimensional color space grid complexity (CFL-075), calculator element branching depth (CFL-074). |
| `validate_roundtrip` | `path` | Check AToB/BToA, DToB/BToD, and Matrix/TRC tag pairs. Validates bidirectional transform completeness required by ICC spec. |
| `full_analysis` | `path` | Runs all 3 modes (`-a`, `-nf`, `-r`) in one call. Use this for comprehensive analysis. Equivalent to `.github/scripts/analyze-profile.sh`. |
| `profile_to_xml` | `path` | ICC→XML conversion via iccToXml. Falls back to iccToXml_unsafe for malformed profiles. Output is the XML representation of the profile. |
| `compare_profiles` | `path_a`, `path_b` | Ninja-full dump of both profiles with unified diff. Use to spot structural differences between two ICC profiles. |
| `list_test_profiles` | `directory` (default: `test-profiles`) | Lists `.icc` files in the given directory. Also accepts `extended-test-profiles`. |
| `upload_and_analyze` | `data_base64`, `filename`, `mode` | Upload a base64-encoded ICC profile and analyze it. Modes: `security` (default), `inspect`, `roundtrip`, `full`, `xml`. Temp file auto-cleaned after analysis. |

**Maintainer build tools (local/VS Code only — NOT exposed to coding agent):**

| Tool | Args | Description |
|------|------|-------------|
| `build_tools` | — | Build native analysis tools from source |
| `cmake_configure` | build type, sanitizers, generator, tools | Configure iccDEV cmake |
| `cmake_build` | build dir | Build iccDEV with cmake --build |
| `create_all_profiles` | — | Run CreateAllProfiles.sh from Testing/ directory |
| `run_iccdev_tests` | — | Run RunTests.sh test suite |
| `cmake_option_matrix` | — | Test cmake option toggles independently |
| `windows_build` | — | Windows MSVC + vcpkg build |

**Operations tools (local/VS Code only — NOT exposed to coding agent):**

| Tool | Args | Description |
|------|------|-------------|
| `check_dependencies` | — | Check build dependencies installed on the current system (apt/brew/vcpkg). Reports missing packages with install commands. |
| `find_build_artifacts` | `build_dir` | Find built binaries under iccDEV/Build/, list SHA-256 checksums, verify static vs dynamic ICC linkage. |
| `batch_test_profiles` | `directory`, `tool`, `build_dir` | Run iccDumpProfile/iccToXml/iccRoundTrip over all .icc files in a directory with per-file pass/fail results and sanitizer detection. |
| `validate_xml` | `directory`, `checks` | Run xmllint validation on ICC XML files: well-formedness, encoding, size limits (100 MB), entity safety. |
| `coverage_report` | `build_dir` | Merge .profraw files with llvm-profdata and generate llvm-cov coverage report. Requires a build with `sanitizers="coverage"`. |
| `scan_logs` | `directory`, `categories` | Grep build/test .log files for 6 pattern categories: errors, signals, invalid data, overflow, memory issues, hangs. |

### MCP Tool Usage — Best Practices

**Path resolution**: All analysis tools accept either:
- An absolute path: `/home/user/profiles/test.icc`
- A filename from `test-profiles/`: just pass `sRGB_D65_MAT.icc` and the server resolves it
- A relative path from the repo root: `test-profiles/sRGB_D65_MAT.icc`

**Choosing the right tool**:
- Start with `analyze_security` for quick security triage (fastest, most actionable)
- Use `full_analysis` for complete reports destined for issues/PRs
- Use `inspect_profile` to understand profile structure (what tags exist, header fields)
- Use `validate_roundtrip` to check spec compliance (AToB↔BToA pairs)
- Use `profile_to_xml` to get human-readable XML for manual inspection
- Use `compare_profiles` when investigating regressions or differences between profile versions

**Operations workflow** (for maintainers doing build/test/debug cycles):
- Start with `check_dependencies` to verify the build environment is ready
- After `cmake_build`, use `find_build_artifacts` to see what was produced and verify checksums
- Use `batch_test_profiles` to run tools over all .icc files (more granular than `run_iccdev_tests`)
- After `profile_to_xml`, use `validate_xml` to check XML well-formedness and encoding
- After instrumented test runs, use `coverage_report` to merge profraw and see coverage
- Use `scan_logs` to search .log files for errors, crashes, and sanitizer findings

**Upload workflow**: When a user provides an ICC profile via an issue attachment:
1. Download the attachment (may be `.icc.txt` — GitHub blocks `.icc`)
2. Use `upload_and_analyze` with the file content base64-encoded and `mode: "full"`
3. Alternatively, save to `test-profiles/` and use `full_analysis` with the path

**Interpreting results**:
- Exit code 0 = clean profile, no findings
- Exit code 1 = heuristic finding(s) detected — review the `[WARN]` and `[CRITICAL]` lines
- Exit code 2 = error (I/O failure, parse error, or profile too malformed to process)
- Look for `[H1]`–`[H135]` prefixes to identify which heuristic triggered
- ASAN/UBSAN output in stderr indicates a real memory safety bug — this is a CRITICAL finding

**Automated issue→PR→merge pipeline**: When Copilot coding agent processes an analysis issue:
1. Create issue with ICC profile to analyze, then assign Copilot via GitHub UI (Assignees sidebar)
   Note: `gh issue create --assignee copilot` and REST API assignment do **not** work. Use the GitHub web UI.
2. Agent uses MCP tools (`inspect_profile`, `analyze_security`, `validate_roundtrip`, `profile_to_xml`) for independent analysis
3. Agent runs `.github/scripts/analyze-profile.sh` for the full iccanalyzer-lite report
4. Agent commits the report to `analysis-reports/`, opens a draft PR with both MCP and script findings
5. When the agent's workflow run completes, `copilot-auto-merge.yml` triggers via `workflow_run[completed]`
6. The auto-merge workflow finds the PR by branch, marks it ready, and squash-merges it
7. The originating issue is closed via `Fixes #N` in the PR body

No manual intervention required — the entire pipeline is hands-free from issue to merge.

## Architecture

This repo contains security research tools targeting the ICC color profile specification via the iccDEV library (formerly DemoIccMAX):

- **cfl/** — 18 LibFuzzer harnesses, each scoped to a specific ICC project tool's API surface. Fuzzers must only call library APIs reachable from their corresponding tool (see Fuzzer→Tool Mapping in README.md).
- **iccanalyzer-lite/** — 138-heuristic static/dynamic security analyzer (v3.4.0) built with full sanitizer instrumentation. 17 C++ modules (16,000+ LOC) compiled in parallel. Deterministic exit codes: 0=clean, 1=finding, 2=error, 3=usage. Heuristics cover 44+ CWE categories from 77+ CVEs. **TIFF image analysis** (v3.4.0): `-a` mode auto-detects TIFF files via magic bytes, extracts embedded ICC profiles (TIFFTAG_ICCPROFILE tag 34675), reports TIFF metadata/security checks, scans pixel data for xnuimagefuzzer injection signatures (10 INJECT_STRING patterns + ICC mutation markers), then runs full 138-heuristic analysis on extracted ICC. New `-img` mode for explicit image analysis. **Unit tests**: 172 tests in `run_tests.py` (41 synthesized corpus profiles, heuristic trigger tests, ASAN corpus checks, mode coverage tests). **Coverage**: clang source-based instrumentation (`-fprofile-instr-generate -fcoverage-mapping`), Lines 70.54%, Functions 63.54%. Call graph analysis mode (`-cg`) parses ASAN/UBSAN crash logs into DOT/JSON/PNG with exploitability assessment (10 ASAN error types + UBSAN runtime errors). When the iccDEV library fails to load malformed profiles, a raw-file fallback engine runs heuristics H10, H13, H25, H28, H32 independently using direct file I/O. **Build systems (5 locations)**: `build.sh` (primary, local), `CMakeLists.txt` (CI/IDE), and 4 CI workflows with manual SOURCES lists (`codeql-security-analysis.yml`, `iccanalyzer-cli-release.yml`, `iccanalyzer-lite-coverage-report.yml`, `iccanalyzer-lite-debug-sanitizer-coverage.yml`, `mcp-server-test.yml`) — ALL must be updated when adding new .cpp modules. Code split across 4 modules: `IccAnalyzerSecurity.cpp` (orchestrator + H1-H8, H15-H17), `IccHeuristicsLibrary.cpp` (H9-H32, H56-H138 via CIccProfile API), `IccHeuristicsRawPost.cpp` (H33-H69 raw file + fallback engine), `IccImageAnalyzer.cpp` (TIFF/PNG/JPEG image analysis with ICC extraction). H95-H102 target coverage-gap APIs: IccSparseMatrix, IccTagEmbedIcc, IccTagProfSeqId, IccMpeSpectral, IccProfile tag iteration. H103-H106 target coverage-gap APIs: IccPcc (viewing conditions), IccPrmg (gamut evaluation), IccMatrixMath (determinant/inversion), IccEnvVar (spectral ranges). H107-H115 feedback-driven: LUT channel/colorspace cross-check (CWE-121, patch 071 root cause), private tag identification (CWE-829), shellcode/NOP-sled patterns (CWE-506), class-required tag validation, reserved byte validation, wtpt D50 validation, round-trip fidelity, TRC curve monotonicity, characterization data presence. H116-H127 ICC feedback-driven: cprt/desc encoding per profile version (CWE-20), tag-type-per-signature validation, calculator computation cost estimate, round-trip ΔE measurement, curve invertibility, characterization data round-trip, deep tag encoding (XYZ ranges, measurement observer/geometry, chromaticity), non-required tag classification, version-tag correspondence, transform smoothness, private tag malware scan (CWE-506), private tag registry lookup. **UBSAN status**: 0 analyzer-code UBSAN errors (53 overflow sites fixed with uint64_t widening + 4 sig-to-char implicit-conversion sites fixed with static_cast<char>(static_cast<unsigned char>(...))). Remaining UBSAN is upstream iccDEV only (IccCAM.cpp div-by-zero, IccProfile.cpp div-by-zero, IccTagLut.cpp signed overflow, IccMD5.cpp unsigned wrapping). IccSignatureUtils.h UB fixed upstream in PR #648. **CodeQL**: 0 alerts in analyzer code (4 remaining in iccDEV upstream). Path-injection sanitization uses realpath(dirname) + character-whitelist basename. **OOM patches**: 57 patches in cfl/patches/ (14 NO-OPs dropped during upstream sync + patch 069 re-used for CLUT interp bounds). Patch 067-068 cap allocation loops in IccTagXml.cpp and IccTagBasic.cpp (mluc, ProfileSeqDesc, ResponseCurveSet, MPE, Dict, ProfileSeqId). Patch 069 adds bounds checks to 7 CIccCLUT::Interp functions (SEGV fix). Patch 070 adds NaN guard to UnitClip. Patch 071 guards SBO in CIccApplyBPC::pixelXfm (XYZbp[3] overflow, CWE-121, SCARINESS 51). Next patch: 083. **Upstream sync**: CFL iccDEV pinned at `7db2273` (upstream PRs #630-#639 + #648 + #652-#657). Dropped patches: 023, 027, 028, 029, 032, 039, 040, 041, 045, 047, 055, 056, 058, 062, 064, 066, 070, 072.
- **colorbleed_tools/** — Intentionally unsafe ICC↔XML converters used as CodeQL targets for mutation testing. Output paths validated against `..` traversal.
- **mcp-server/** — Python FastMCP server (stdio transport) + Starlette web UI wrapping iccanalyzer-lite and colorbleed_tools. 22 tools: 9 analysis + 7 maintainer (cmake configure/build, option matrix, CreateAllProfiles, RunTests, Windows build) + 6 operations (dependency check, build artifacts, batch testing, XML validation, coverage reports, log scanning). Multi-layer path traversal defense, output sanitization, upload/download size caps. Default binding: 127.0.0.1. 3 custom Python CodeQL queries (subprocess injection, path traversal, output sanitization).
- **cfl/patches/** — 59 active security patches applied to iccDEV before fuzzer builds. Includes OOM caps (16MB–128MB), UBSAN fixes, heap-buffer-overflow guards, stack-overflow depth caps, null-deref guards, memory leak fixes, float-to-int overflow clamps, alloc/dealloc mismatch corrections, recursion depth limits, IO underflow guards, calculator ops array bounds clamping, XML entity expansion caps, XML parsing limits, CLUT interpolation bounds checks (Interp1d–6d + InterpND), NaN-to-integer cast guards (UnitClip), BPC black-point stack-buffer-overflow guard (pixelXfm), and Begin() return value NULL-deref guard (V5DspObsToV4Dsp), and XML channel count validation (icMBBFromXml). 14 patches dropped as NO-OPs during upstream sync (023, 027, 028, 029, 032, 039, 040, 041, 045, 055, 056, 058, 062, 066). Next patch: 077. See `cfl/patches/README.md` for full details.
- **cfl/iccDEV/** — Cloned upstream iccDEV library (patched at build time, not committed patched).
- **test-profiles/** and **extended-test-profiles/** — ICC profile corpora for fuzzing and regression testing. Includes crash reproducers (SBO, SEGV, SO, OOM) with descriptive filenames mapping to root cause function and source line.
- **.github/scripts/** — Shell scripts for analysis, fuzzing, ramdisk management, coverage, and corpus handling. Key scripts: `analyze-profile.sh` (3-mode analysis), `batch-test-external.sh` (external profile batch testing), `ramdisk-seed.sh` (8GB tmpfs setup), `ramdisk-merge.sh` (corpus dedup), `unbundle-fuzzer-input.sh` (extract ICC profiles from multi-profile fuzzer crash files for tool reproduction).

Each iccDEV subdirectory (under cfl/, iccanalyzer-lite/, colorbleed_tools/) is an independent clone of the upstream library — they are not shared.

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

### Fuzzer structure
Every fuzzer implements `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` with:
- Early return on size bounds: `if (size < MIN || size > MAX) return 0;`
- Temp file via `mkstemp()` → `write()` → `close()` → process → `unlink()`
- Error/warning handlers suppressed during fuzzing
- Optional `LLVMFuzzerInitialize()` for one-time setup
- Trailing bytes for parameter derivation (never consume leading bytes — shifts ICC header)

### Fuzzer scope alignment
Each fuzzer must only exercise APIs reachable from its corresponding project tool. For example:
- `icc_profile_fuzzer` / `icc_spectral_fuzzer` must NOT use `CIccCmm` (AddXform/Begin/Apply)
- `icc_deep_dump_fuzzer` must NOT call FindColor/FindDeviceColor/FindPcsColor
- See the Fuzzer→Tool Mapping table in README.md
- Call graph scripts in `.github/scripts/callgraphs/` measure fidelity per tool (90.0% aggregate)
- Run: `python3 .github/scripts/callgraphs/iccDumpProfile-callgraph.py` for text summary
- Output artifacts (JSON, DOT, SVG) go to `analysis-reports/callgraph-{toolName}/`

### Dictionary files
- Format: LibFuzzer dict format with `\xNN` hex escapes only (no octal, no inline comments)
- Lookup order in CI: `cfl/${FUZZER_NAME}.dict` → `cfl/icc_core.dict` → `cfl/icc.dict`
- Use `.github/scripts/convert-libfuzzer-dict.py` to convert raw LibFuzzer recommended dictionary output
- CI auto-merges recommended dict entries after fuzzing (convert-libfuzzer-dict.py --append)
- Several fuzzers share base dicts (e.g., `icc_toxml_fuzzer` → `icc_xml_consolidated.dict`, `icc_io_fuzzer` → `icc_core.dict`). The mapping is defined as `FUZZER_DICTS` in `ramdisk-fuzz.sh`, `fuzz-local.sh`, and `.github/scripts/seed-corpus-setup.sh`. Per-fuzzer aliases are created on ramdisk so `-dict=${fuzzer}.dict` resolves correctly.

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

**Known upstream UBSAN** (unfixable — in iccDEV library, not our code):
- `IccSignatureUtils.h:402-405` — uint→char implicit conversion
- `IccCAM.cpp:266,283` — division by zero in CAM color appearance model
- `IccProfile.cpp:3153,3155` — division by zero in profile size checks
- `IccTagLut.cpp:5640` — signed integer overflow in LUT interpolation
- `iccApplyProfiles.cpp:559-560` — NaN→unsigned char via UnitClip (patch 070 fixes in CFL, 8% of corpus triggers upstream)
- `IccMatrixMath.cpp:386` — NaN→unsigned short in SetRange (patch 051 fixes in CFL)

### OOM patches
Named `NNN-brief-description.patch` in `cfl/patches/`. Applied automatically by `cfl/build.sh` AND all CI fuzzer workflows before cmake. Build alignment rule: local build.sh and CI workflows MUST apply identical patches/flags.

### Patch creation workflow
When creating a new patch for `cfl/patches/`:
1. Reproduce the crash with the PoC profile against the existing iccDEV binary
2. **CRITICAL**: Reset iccDEV checkout, then apply ALL prior patches (001 through N-1) to establish the correct baseline. Never diff against raw upstream — intermediate patches shift context lines.
3. Save a copy of the baseline source files you will modify
4. Make your fixes in the patched checkout
5. Create the `.patch` file: `diff -u baseline/path fixed/path > cfl/patches/NNN-name.patch`
6. Verify clean application: reset checkout → apply 001 through N → confirm no rejects
7. Rebuild fuzzers: `cd cfl && ./build.sh` (resets checkout, applies all patches, builds)
8. Copy rebuilt binaries to ramdisk: `cp cfl/bin/* /tmp/fuzz-ramdisk/bin/` (or SSD)
9. Verify the PoC no longer crashes (exit 0, no ASAN/UBSAN output)
10. Run a smoke test across all 18 fuzzers to confirm no regressions
11. Update `cfl/patches/README.md` (table entry + description paragraph)
12. Patches MUST be incremental diffs (not cumulative). Each patch applies cleanly atop all prior patches.

**Lesson learned (patch 066→067)**: Patch 066 failed to apply because patch 049 modified the same file (`IccProfileXml.cpp`), shifting context lines. The fix was to mark 066 as NO-OP and create 067 with correct context from the post-049 baseline.

### Crash reproducer testing
To verify a crash reproducer against all 18 fuzzers:
```bash
# Single fuzzer test (1-liner)
ASAN_OPTIONS=detect_leaks=0 /tmp/fuzz-ramdisk/bin/<fuzzer_name> test-profiles/<crash-file>.icc 2>&1 | grep -c "ERROR: AddressSanitizer"
# Result: 0 = no crash (fixed), 1 = crash found

# Batch test all fuzzers against a profile
for f in /tmp/fuzz-ramdisk/bin/icc_*_fuzzer; do echo -n "$(basename $f): "; ASAN_OPTIONS=detect_leaks=0 timeout 10 "$f" test-profiles/<file>.icc 2>&1 | grep -c "ERROR: AddressSanitizer" || true; done

# Test external profiles (not committed)
.github/scripts/batch-test-external.sh /path/to/profiles --timeout 15

# Test upstream iccApplyProfiles for UBSAN (needs a test TIFF first)
# Create 2x2 RGB TIFF: python3 -c "import struct; ..." or use bar.tif/foo.tif
ASAN_OPTIONS=detect_leaks=0 timeout 5 iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles \
  /tmp/test_rgb.tif /tmp/out.tif 1 0 0 0 0 profile.icc 0 2>&1 | grep "runtime error"

# ASAN SCARINESS scoring (useful for severity triage)
ASAN_OPTIONS=print_scariness=1:halt_on_error=0:detect_leaks=0 <tool> <crash-file>
```

### iccApplyProfiles CLI syntax
```
iccApplyProfiles src.tif dst.tif ri bpc luminance env pcc profile.icc interp [profile2.icc interp2 ...]
```
- `ri`: rendering intent (0=perceptual, 1=relative, 2=saturation, 3=absolute)
- `bpc`: black point compensation (0=off, 1=on)
- `luminance`: luminance matching (0=off, 1=on)
- `env`/`pcc`: environment/PCC profile (0=none)
- `interp`: interpolation (0=linear, 1=tetrahedral)

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

### CMM fuzzer seed creation
CMM fuzzers need special input formats (not just raw ICC profiles):
| Fuzzer | Format | Seed Dir |
|--------|--------|----------|
| `icc_link_fuzzer` | profile1 (padded) + profile2 (padded) + 3 ctrl bytes | `cfl/seeds-link-pairs/` |
| `icc_applyprofiles_fuzzer` | 75% profile + 25% control data | `cfl/seeds-applyprofiles/` |
| `icc_applynamedcmm_fuzzer` | 4-byte header + profile | `cfl/seeds-applynamedcmm/` |

`ramdisk-seed.sh` Source 3 auto-seeds these directories. See `improve-fuzzer-coverage.prompt.md` for format details.

**Link fuzzer gotcha**: Uses `AddXform(CIccProfile*, ...)` which transfers ownership — see [AddXform ownership semantics](#addxform-ownership-semantics) above. The link fuzzer needs `quarantine_size_mb=256` because it allocates 2 full profiles per input.

### Fuzzer build categories
Fuzzers are grouped by link dependencies in `cfl/build.sh`:
- **CORE_FUZZERS** (IccProfLib only): profile, spectral, calculator, deep_dump, dump, io, multitag, roundtrip, apply
- **XML_FUZZERS** (+IccXML+libxml2): toxml, fromxml, fromcube
- **TIFF_FUZZERS** (+TiffImg.o+libtiff): applyprofiles, applynamedcmm, link, specsep, tiffdump, v5dspobs

Note: `icc_applyprofiles_fuzzer` was moved from CORE to TIFF to exercise the full TIFF I/O pipeline (97.8% fidelity with iccApplyProfiles tool). It creates a source TIFF in-memory, builds CMM with BPC/Luminance hints, runs the complete pixel loop, and embeds the destination profile.

### OOM triage workflow
When a fuzzer reports `ERROR: libFuzzer: out-of-memory`:
1. Identify the allocation chain from the OOM stack trace (top frames show the hot allocator)
2. Inspect the PoC file to understand the trigger (use `xxd | head`, `xmllint`, or `file`)
3. Common OOM patterns in iccDEV XML parsing:
   - Unbounded tag/element counts → add `MAX_*` caps (256–1024 entries)
   - Unbounded string content → add byte-size cap (64KB for localized text)
   - Unbounded list children (ProfileSeqId, Dict) → cap entries AND strings-per-entry
4. After patching, verify: `ASAN_OPTIONS=detect_leaks=0 /path/to/fuzzer oom-file 2>&1` — RSS should drop 10x+
5. Save reproducer to `test-profiles/` with descriptive name: `oom-<description>-<patch#>.icc`

### Coverage workflow tips
- **Static vs shared libs**: Coverage reports using static libs only show tool `.cpp` coverage (~5K lines). Use `ENABLE_STATIC_LIBS=OFF` to build shared libs so llvm-cov sees all 46K library source lines.
- **Shared lib collection**: Collect `.so` files with `find Build -name '*.so'` and pass each as `-object` arg to `llvm-cov`.
- **Runtime**: Set `LD_LIBRARY_PATH` to the shared lib directory before running instrumented tools.
- **Profraw management**: Use `LLVM_PROFILE_FILE=${fuzzer_name}_%m_%p.profraw` (not `%m.profraw` or `default.profraw`) to avoid clobbering and to identify which fuzzer generated each profraw file. The `%m` specifier is a numeric module hash — there is NO LLVM specifier for the binary name, so it must be prepended manually.
- **Fuzzer coverage collection**: `fuzz-local.sh` sets `LLVM_PROFILE_FILE` per-fuzzer inside the loop. To collect coverage from all 18 fuzzers manually:
  ```bash
  # Run all fuzzers with profraw collection (60s each, parallel)
  for f in /mnt/g/fuzz-ssd/bin/icc_*_fuzzer; do
    name=$(basename "$f")
    ASAN_OPTIONS=detect_leaks=0 \
    LLVM_PROFILE_FILE="/mnt/g/fuzz-ssd/profraw/${name}_%m_%p.profraw" \
      "$f" -max_total_time=60 -detect_leaks=0 -timeout=30 -rss_limit_mb=4096 \
      -use_value_profile=1 -max_len=5242880 \
      -artifact_prefix=/mnt/g/fuzz-ssd/ \
      -dict="cfl/${name}.dict" \
      "/mnt/g/fuzz-ssd/corpus-${name}/" > /tmp/fuzz_${name}.log 2>&1 &
  done
  wait

  # Merge and report
  llvm-profdata-18 merge -sparse /mnt/g/fuzz-ssd/profraw/*.profraw -o /mnt/g/fuzz-ssd/merged.profdata
  OBJS=$(printf ' -object %s' cfl/bin/icc_*_fuzzer)
  llvm-cov-18 report $OBJS -instr-profile=/mnt/g/fuzz-ssd/merged.profdata
  llvm-cov-18 show $OBJS -instr-profile=/mnt/g/fuzz-ssd/merged.profdata --format=html --output-dir=/mnt/g/fuzz-ssd/coverage-report/html
  ```
- **Coverage baseline** (as of March 2026, all 18 fuzzers): Functions 63.23%, Lines 61.15%, Branches 58.47%, Instantiations 62.99%. HTML reports committed to `coverage-report/` (needs `git add -f` due to `.gitignore` pattern).
- **Seed corpus strategy**: Copy profiles from `test-profiles/` with novel tag types not already in fuzzer seed corpora. Set `doOpenPath` bit (`data[-2] |= 0x08`) on seeds to use the non-validating `Read()` path in deep_dump fuzzer. Minimal hand-crafted ICC profiles fail `ValidateIccProfile()` — always patch existing valid profiles instead.
- **Fuzzer-specific coverage notes**:
  - Only `toxml` and `fromxml` link IccXML — they provide all IccXML coverage
  - Only `specsep`, `tiffdump` link TiffImg — they provide all TIFF coverage
  - `toxml` may crash on large corpora — use a 100-200 file subset via `ls | shuf | head -200`
  - `roundtrip` is very slow (5032+ corpus files, Read→Write→Read per input) — allow 120s+
  - `link` needs `ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256` (2 profiles per input)

### Stale coverage files
After recompilation, old `.gcda` files mismatch new `.gcno` files. `build.sh` auto-cleans them with `find . -name "*.gcda" -delete` before building.

### CodeQL static analysis
- **Setup**: Download CodeQL v2.24.2+ bundle to `/tmp/codeql/`. Run from `iccanalyzer-lite/` directory.
- **Create DB**: `/tmp/codeql/codeql database create /tmp/codeql-db --language=cpp --source-root=. --command=./build.sh --overwrite`
- **Analyze**: `/tmp/codeql/codeql database analyze /tmp/codeql-db /tmp/codeql/qlpacks/codeql/cpp-queries/1.5.11/codeql-suites/cpp-security-and-quality.qls --format=sarif-latest --output=/tmp/codeql-results.sarif --threads=4`
- **Parse SARIF**: `python3 -c "import json; [print(r['ruleId'], r['locations'][0]['physicalLocation']['artifactLocation']['uri']) for r in json.load(open('/tmp/codeql-results.sarif'))['runs'][0]['results']]"`
- **Status** (March 2026): 0 alerts in analyzer code. 4 in iccDEV upstream (`cpp/assignment-does-not-return-this` in IccTagBasic.h — not modifiable). Fixed patterns: use `std::nothrow` for operator new (CodeQL cpp/incorrect-allocation-error-handling), copy iterator elements instead of binding references (cpp/use-after-expired-lifetime), rename variables to avoid shadowing outer scope (cpp/declaration-hides-variable).
- **Path-injection pattern**: CodeQL recognizes `realpath()` as a sanitizer for `cpp/path-injection`. For output files that don't exist yet, resolve parent directory with `realpath(dirname)` + sanitize basename via character whitelist. Custom validators (IsPathSafe, etc.) are NOT recognized by CodeQL.
- **Constant-comparison**: CodeQL flags `x >= N` as always-true when an earlier guard already constrains `x`. Remove the redundant inner check.
- **Complex-condition**: Extract helper functions to reduce condition complexity below CodeQL's threshold.

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

### MCP server security patterns
- Path validation: allowlist of base dirs + symlink resolution + normpath checks + null byte rejection
- Build dir validation: triple layer (web_ui regex, _resolve_build_dir, Path.resolve containment check)
- CMake args: regex allowlist (`-DVAR=VALUE`, `-Wflag` only), shell metachar rejection
- Subprocess: `asyncio.create_subprocess_exec` (never `shell=True`), minimal env vars
- Output: `_sanitize_output` strips control chars/ANSI, 10MB cap. All output paths verified sanitized
- Uploads: 20MB cap, temp dir with 700 mode
- CSP with per-request nonce, strict security headers
- Default binding: 127.0.0.1 (not 0.0.0.0)

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

### Tool Ecosystem
| Tool | Repo | Platform | Purpose |
|------|------|----------|---------|
| xnuimagetools | github.com/xsscx/xnuimagetools | iOS/macOS/watchOS/visionOS | Create baseline images across XNU platforms |
| xnuimagefuzzer | github.com/xsscx/xnuimagefuzzer | iOS/macOS (Xcode) | Fuzz images via 15 CGCreateBitmap functions |
| iOSOnMac CLI | macos-research/code/iOSOnMac | macOS (CLI) | Run xnuimagefuzzer at scale via posix_spawn |
| colorbleed_tools | research/colorbleed_tools | Linux/macOS | Build ICC profiles (iccToXml/iccFromXml) |
| seed-pipeline.sh | .github/scripts/seed-pipeline.sh | Linux | Validate, embed ICC, distribute seeds |
| craft-seeds.py | .github/scripts/craft-seeds.py | Linux | Generate synthetic edge-case image seeds |

### Workflow
1. Create baseline images → **xnuimagetools** (macOS)
2. Fuzz images → **xnuimagefuzzer** (macOS) — produces 15 pixel formats × 30+ output formats
3. ICC variant generation (automatic for TIFF/PNG):
   - Real ICC profiles from `FUZZ_ICC_DIR` via `CGColorSpaceCreateWithICCData()` (round-robin)
   - Stripped color space (DeviceRGB, no ICC metadata)
   - Mismatched profiles (CMYK/Gray/Lab/truncated on RGB)
   - Mutated ICC profiles (6 corruption strategies)
4. CI pipeline generates images on iOS Simulator + Mac Catalyst (with system ICC profiles)
5. Extract ICC seeds → `extract-icc-seeds.py --inject-cfl ../cfl` (automated in CI as `extract-seeds` job)
6. Validate + embed ICC → **seed-pipeline.sh** `temp/ --distribute --ramdisk`
7. Generate synthetic seeds → **craft-seeds.py** `--outdir temp/icc-crafted`
8. Re-seed ramdisk → `.github/scripts/ramdisk-seed.sh`

### Pipeline Scripts

```bash
# Validate images, embed 15 ICC profiles, distribute to seed corpuses
.github/scripts/seed-pipeline.sh <image-dir> [--distribute] [--ramdisk]

# Generate synthetic edge-case seeds (tiny, 16-bit, float, tiled, BigTIFF, etc.)
python3 .github/scripts/craft-seeds.py --outdir temp/icc-crafted --profiles test-profiles
```

### Quality Gates (seed-pipeline.sh)
- Reject files < 64 bytes (truncated)
- Reject images with < 5 unique pixel values (flat/degenerate)
- Validate TIFF magic bytes (II\*/MM\* or BigTIFF)
- Deduplicate by MD5 content hash
- Enforce max size = 5MB (max\_len limit)

### Known Issues with xnuimagefuzzer Output
- 32BitFloat and HDR float fuzzed variants produce all-zero pixels (CoreGraphics clamps float→8-bit)
- `LittleEndian-image.tiff` is actually big-endian (MM) — name refers to CGColorSpace component order
- ICC variants require `FUZZ_ICC_DIR` for real/mutated profiles; stripped and mismatched are always generated
- `kCGImagePropertyICCProfile` does NOT exist in Apple SDKs — use `CGColorSpaceCreateWithICCData()`
- xnuimagetools is the source of truth for xnuimagefuzzer.m; always sync after changes
- Mac Catalyst CI job sets `FUZZ_ICC_DIR=/System/Library/ColorSync/Profiles` for system ICC profiles
- xnuimagetools `build-and-test.yml` has 8 jobs: build-ios, generate-images, generate-catalyst-images,
  generate-ios-gen-images, build-watch, commit-images, extract-seeds

## macOS CI Patterns (xnuimagefuzzer / xnuimagetools)

These patterns apply to the `xnuimagefuzzer/` and `xnuimagetools/` sub-repos within this workspace.

### SIGPIPE Prevention
NEVER pipe macOS/BSD tools (`ls`, `file`, `find`, `xcodebuild`, `xcrun`) through `| head`.
They use NSFileHandle for stdout and crash with `NSFileHandleOperationException` (SIGABRT exit 134)
or `stdout: Undefined error: 0` when the reader closes early.
```bash
# ❌ Crashes: ls -la /tmp/output/ | head -20
# ✅ Safe:   ls -la /tmp/output/ | sed -n '1,20p'
# ❌ Crashes: xcodebuild -version | head -1
# ✅ Safe:   xcodebuild -version | sed -n '1p'
# ❌ Crashes: file -b "$f" | head -c 40
# ✅ Safe:   file -b "$f" | cut -c1-40
```

### LLVM Profraw Coverage Symbols
Use `dlsym(RTLD_DEFAULT, "__llvm_profile_write_file")` instead of `__attribute__((weak)) extern`.
Weak extern works on Mac Catalyst with `-fprofile-instr-generate` but causes linker failures on
iOS Simulator builds without coverage flags. The `dlsym()` approach works across all configurations.

### Mac Catalyst App Launch in CI
Mac Catalyst binaries must be launched via `open "$APP_BUNDLE"` (bare Mach-O exits immediately).
- `open` blocks until app exits → use `open "$APP_BUNDLE" & ; disown $!`
- Pass env vars via `open --env KEY=VALUE` (macOS 13+) — `launchctl setenv` is unreliable
- Mac Catalyst ignores `osascript quit` — use `pgrep -f "App Name"` + `kill`
- SIGTERM does NOT trigger `atexit()` → send SIGINT first for profraw flush

### VideoToolbox ASAN Performance
VideoToolbox fuzzer runs 10-50x slower under ASAN. Never call `malloc_zone_print()` in hot
loops under ASAN — it dumps entire memory zone per call. The VT instrumented CI job is disabled
(`if: false` in `xnuimagetools/.github/workflows/instrumented.yml`). Run VT ASAN testing on
local macOS hardware with extended timeouts (10+ minutes).

### xnuimagefuzzer Output Expectations
17 seed specs × 6 files each (seed + corrupted + 4 format variants) = 102 expected files.
CI polling threshold must be ≥80 with 120s timeout. The app uses `FUZZ_OUTPUT_DIR` env var
for output directory and generates PNG, JPEG, GIF, BMP, TIFF, HEIF formats.

### Pinned Action SHAs (both sub-repos)
```yaml
actions/checkout: 11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
actions/upload-artifact: ea165f8d65b6e75b540449e92b4886f43607fa02  # v4.6.2
actions/cache: 5a3ec84eff668545956fd18022155c47e93e2684  # v4.2.3
actions/download-artifact: d3f86a106a0bac45b974a628896c90dbdf5c8093  # v4.3.0
```
