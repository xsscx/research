---
mode: agent
description: Per-fuzzer optimization reference for the active CFL LibFuzzer harnesses
---

# CFL Fuzzer Optimization Guide

Per-fuzzer reference for optimizing CFL LibFuzzer harnesses. The active
inventory is always derived from `cfl/fuzzers.sh`; the selected entries below
documents input format, coverage gaps, input crafting, and dictionary focus.

Use this when a fuzzer's coverage has plateaued and you need to identify which code paths are
unreachable, which need new seeds, and which need dictionary tokens.

If this prompt is used for a repeated correction or wrap-up request, do not run
a full optimization pass. Patch the named fuzzer policy or script, run the
targeted validator or seed-only command that proves the fix, then commit and
push if requested.

## Prerequisites
- Active fuzzers: `source cfl/fuzzers.sh; printf '%s\n' "${#CFL_FUZZERS[@]}"`
- Built fuzzers: `find cfl/bin -maxdepth 1 -type f -name 'icc_*_fuzzer' | wc -l`
- Coverage HTML: `coverage-report/html/` (paths reflect build directory structure)
- LLVM tools: `llvm-profdata-18`, `llvm-cov-18`
- Source: `cfl/icc_*_fuzzer.cpp`, dicts in `cfl/icc_*_fuzzer.dict`

## General Optimization Methodology

### Step 1: Extract Coverage Gaps
```bash
# Parse uncovered lines from HTML report
grep -B1 "class='uncovered-line'" \
  coverage-report/html/coverage/cfl/<fuzzer>.cpp.html | \
  grep -oP 'data-linenumber="\K[0-9]+'
```

### Step 2: Classify Each Gap
For each uncovered line, determine:
1. **Dead code** -- unreachable due to upstream bugs (document and skip)
2. **Allocation failure** -- `new` returning NULL (never triggered under ASAN; skip)
3. **Input-reachable** -- needs a specific seed or dictionary token
4. **Gate-blocked** -- requires passing N prior checks to reach

### Step 3: Craft Seeds or Dict Entries
- Seeds: Start from valid profiles in `iccDEV/Testing/` or `test-profiles/`
- Dict: Use `\xHH` format only (no `\n`, `\t` -- LibFuzzer rejects them)
- Verify: `ASAN_OPTIONS=detect_leaks=0 LLVM_PROFILE_FILE=/dev/null timeout 10 bin/<fuzzer> <seed>`

### Step 4: Measure
```bash
# 30-60s verification run
ASAN_OPTIONS=detect_leaks=0 LLVM_PROFILE_FILE=/dev/null \
  bin/<fuzzer> -max_total_time=30 corpus-<fuzzer>/ 2>&1 | grep "INITED\|DONE\|NEW"
# Compare "cov:" value before and after
```

### Step 5: Cross-Pollinate from XNU Image Tools
The `xnuimagetools/` pipeline generates TIFF/PNG/JPEG images with embedded ICC profiles
across 15 bitmap context types, 7 color spaces, and 22+ output formats on real Apple hardware.
**Note**: xnuimagetools uses xnuimagefuzzer as a git submodule at `XNU Image Fuzzer/`.
Clone with `git clone --recurse-submodules` to populate the fuzzer directory.

Extract and inject seeds into CFL corpora:
```bash
# Extract ICC profiles + TIFF files from fuzzed-images
python3 xnuimagetools/contrib/scripts/extract-icc-seeds.py \
  --input xnuimagetools/fuzzed-images/ --inject-cfl cfl

# For maximum ICC diversity, run the fuzzer with FUZZ_ICC_DIR set:
# FUZZ_ICC_DIR=test-profiles FUZZ_OUTPUT_DIR=/tmp/icc-rich ./XNU\ Image\ Fuzzer
```

Targets: ICC profiles -> profile/dump/deep_dump/toxml fuzzers; TIFF files -> tiffdump/specsep fuzzers.
For AFL `jpegdump` and `jpegdump-inject`, seed only `.jpg`/`.jpeg` files with
embedded ICC profiles from `fuzz/graphics/jpg`; do not use raw `.icc` seeds.
Before optimizing AFL lanes, run `./afl/build-afl-runtime.sh`; it pins stable
commit `45bb74bd3a6591e6853b704c390ab6156c0a3c88`, `-j32`, and a 4 MiB testcase ceiling.
Keep `applyprofiles-hybrid-embedded` on its complete generated TIFF and validate
all target assets with `.github/scripts/validate-afl-target-configs.sh --local`.
For profile visualization, CFL's `profileplot` alias exercises the in-memory
`IccVizModel` API. AFL owns the CLI split: `profileplot` lists descriptors,
`profileplot-graph` renders `chroma:xy`, and `profileplot-raster` renders
`clut:A2B0` plus raw output. Keep the shared sRGB v4 fixture valid for both IDs.

---

## Selected Per-Fuzzer Reference

| # | Fuzzer | Tool Equivalent | Input | Min/Max | Branch Cov | Key Coverage Area |
|---|--------|----------------|-------|---------|------------|-------------------|
| 1 | icc_dump_fuzzer | iccDumpProfile | ICC binary | 128B/2MB | 66% | Read+Validate+Describe, tag iteration |
| 2 | icc_toxml_fuzzer | iccToXml | ICC binary | 128B/2MB | 72% | Read+SaveXml, XML serialization |
| 3 | icc_fromxml_fuzzer | iccFromXml | ICC XML | 64B/128KB | 68% | LoadXml parser, entity handling |
| 4 | icc_fromcube_fuzzer | iccFromCube | .cube text | 16B/128KB | 45% | LUT text parsing, 3D CLUT |
| 5 | icc_roundtrip_fuzzer | iccRoundTrip | ICC binary | 128B/2MB | 58% | AToB/BToA transforms |
| 6 | icc_link_fuzzer | iccLinkCmm | 2x ICC | 256B/4MB | 52% | Profile linking, PCS conversion |
| 7 | icc_applyprofiles_fuzzer | iccApplyProfiles | ICC+control | 128B/4MB | 55% | CMM Apply, pixel transforms |
| 8 | icc_applynamedcmm_fuzzer | iccApplyNamedCmm | ICC+control | 128B/2MB | 48% | Named color CMM |
| 9 | icc_applysearch_fuzzer | iccApplySearch | ICC binary | 128B/2MB | 40% | CIccCmmSearch optimization |
| 10 | icc_v5dspobs_fuzzer | iccV5DspObsToV4 | 2x ICC | 256B/4MB | 61% | v5 DspObs->v4, spectral |
| 11 | icc_specsep_fuzzer | iccSpecSepToTiff | TIFF+ICC | 128B/4MB | 38% | Spectral separation, TIFF I/O |
| 12 | icc_tiffdump_fuzzer | iccTiffDump | TIFF | 8B/2MB | 44% | TIFF tag reading, ICC extraction |
| 13 | icc_cfg_fuzzer | iccApplyNamedCmm | JSON config | 2B/64KB | 35% | JSON config parsing |
| 14 | icc_profilevisualize_fuzzer | iccProfilePlot | ICC binary | 132B/5MB | measure | IccVizModel enumerate, graph, raster |

### Multi-Profile Input Formats

| Fuzzer | Format |
|--------|--------|
| v5dspobs | `[4B BE size][display.icc][observer.icc]` |
| link | `[50% profile1][50% profile2][4B control]` |
| applyprofiles | `[75% profile][25% control (intent, interp, WxH, pixels)]`; unbundler emits `profile.icc`, generated `source.tiff`, `repro.json`, `control.txt`, and raw `control.bin` |
| applynamedcmm | one raw ICC profile; the harness applies a fixed tool-control matrix |
| specsep | `[1B nFiles][14B TIFF meta][TIFF+ICC data]` |

Unbundle crash files: `.github/scripts/unbundle-fuzzer-input.sh <fuzzer> <crash_file>`.
For applyprofiles, use the generated `source.tiff` and `repro.json`; `control.bin`
is only the exact fuzzer control/pixel seed bytes.

### Key Per-Fuzzer Notes

**fromcube**: Use `-max_len=131072` (not 5MB) since .cube is text (64^3 x 20 chars = ~5KB max useful).

**link**: 2x ASAN memory -- add `quarantine_size_mb=256` to ASAN_OPTIONS.

**v5dspobs**: Must check `Begin()` return before `Apply()` (CFL-072 fix). Uses SafeDescribe.

**specsep**: 5+ entry-point paths (1-8 channel configs). Seed with xnuimagetools TIFFs.

**tiffdump**: 4215-entry dict combining TIFF 6.0 tags + ICC sigs + corpus tokens.

**cfg_fuzzer**: Tests the JSON config path (`iccApplyNamedCmm -cfg FILE`). Exercises `fromJson()`/`toJson()` round-trip.

For AFL tool-level `-cfg` lanes, keep the process working directory in the
isolated `afl/work/<target>/root` tree. Fuzzed destination fields are target
behavior and must not create files in the repository root. For
`fromxml-includes`, preserve the staged support working directory during seed
screening, queue mapping, minimization, and crash replay.

**applynamedcmm**: Do not prepend control bytes or modify reserved bytes to
select behavior. Use pure ICC seeds; the harness deterministically exercises
transform types, intents, interpolation, hints, environment values, encodings,
directions, named-color interfaces, and a same-profile chain.

**Large profile/conversion inputs**: The aligned NamedCmm, Connect, config, and
JSON/XML lanes use repository `max_len=0`; the CFL runners derive the explicit
limit from the largest corpus file. Retain RSS and timeout limits;
ICC-to-JSON serialization may amplify multi-megabyte profiles into tens of
megabytes in memory.

## Cross-Cutting Optimization Tips

### LibFuzzer Dictionary Syntax
```
# CORRECT -- only \xHH escapes
keyword_newline="\x0a"
keyword_tab="\x09"
keyword_cr="\x0d"
tag_sig="\x64\x65\x73\x63"

# WRONG -- will be rejected or misinterpreted
keyword_newline="\n"
keyword_empty=""
keyword_utf8="--"
```

### Patch Stack Validation
Before committing AFL/CFL patch-stack changes, run:
```bash
.github/scripts/check-afl-cfl-patches.sh
```
This validates every `afl/patches/*.patch` and `cfl/patches/*.patch` file
against fresh temporary clones of the nested iccDEV checkouts.

### ASAN Ownership Semantics
`CIccCmm::AddXform(CIccProfile*)` transfers ownership:
- **icCmmStatOk**: CMM owns the profile -- do NOT delete
- **icCmmStatBadXform**: `CIccXform::Create()` already freed -- do NOT delete
- **Other errors**: Caller still owns -- MUST delete

### Seed Creation from iccDEV/Testing/
```bash
# Find all ICC profiles in iccDEV test data
find iccDEV/Testing/ -name "*.icc" -type f | head -20

# Copy to corpus with force-add (gitignored)
cp iccDEV/Testing/Display/Rec2020rgbSpectral.icc cfl/corpus-icc_io_fuzzer/
git add -f cfl/corpus-icc_io_fuzzer/Rec2020rgbSpectral.icc
```

### Coverage Report Quick Reference
```bash
# Per-fuzzer line counts
llvm-cov-18 report -object bin/<fuzzer> -instr-profile=merged.profdata

# Uncovered lines for one source file
llvm-cov-18 show -object bin/<fuzzer> -instr-profile=merged.profdata \
  --format=text cfl/<fuzzer>.cpp 2>/dev/null | grep "|      0|"
```

### Performance Tiers
| Tier | Fuzzers | exec/s | Notes |
|------|---------|--------|-------|
| Fast (>5000) | profile, dump, io, multitag | 5k-20k | Single Read+Validate |
| Medium (500-5000) | apply, toxml, fromxml, calculator, deep_dump | 500-5k | Read+Transform or XML |
| Slow (<500) | link, roundtrip, v5dspobs, specsep | 10-500 | Multi-profile or TIFF I/O |
| Very slow | applynamedcmm | 50-200 | Complex CMM chains |

### CWE-400 Timeout Patterns -- Triage and Fix Guide

When a fuzzer produces a `timeout-*` artifact:

1. **Verify with upstream tool** (CRITICAL -- use `iccDEV/Build/Tools/`, NOT `cfl/iccDEV/`):
   ```bash
   LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
     timeout 30 iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <timeout-file>
   ```
   If the upstream tool also hangs -> **upstream algorithmic bug** (report + patch).
   If upstream handles it fine -> **fuzzer-only issue** (patch library in CFL).

2. **Common timeout root causes in iccDEV**:

| Root Cause | Example | Fix Pattern |
|-----------|---------|-------------|
| Unbounded recursion depth | `CheckUnderflowOverflow` depth=100, no ops budget | Add `pOpsProcessed` counter + reduce depth (CFL-074) |
| Exponential grid iteration | `EvaluateProfile` nGran^ndim = 33^6 = 1.29B | Cap total iterations, dynamically reduce nGran (CFL-075) |
| Large allocation loops | `IccTagXml` mluc/ProfileSeqDesc parsing | Cap element count (CFL-067/068) |
| Recursive Read() | `CIccTagStruct::Read()` self-referencing | Already guarded by read-depth limit |

3. **Fix workflow**:
   ```bash
   # a) Backup pre-patch state
   cp cfl/iccDEV/IccProfLib/<file>.cpp cfl/iccDEV/IccProfLib/<file>.cpp.preNNN
   # b) Apply fix
   # c) Generate patch
   diff -u <file>.cpp.preNNN <file>.cpp > cfl/patches/NNN-descriptive-name.patch
   # d) Rebuild library + fuzzer
   cd cfl/iccDEV/Build && cmake --build . -j32
   clang++ ... icc_<name>_fuzzer.cpp ... -o bin/icc_<name>_fuzzer
   # e) Verify fix
   LLVM_PROFILE_FILE=/dev/null ASAN_OPTIONS=detect_leaks=0 \
     timeout 30 cfl/bin/icc_<name>_fuzzer <timeout-file>
   # f) Copy to SSD
   cp cfl/bin/icc_<name>_fuzzer /mnt/g/fuzz-ssd/bin/
   ```

4. **Key constants in timeout fixes**:
   - `kMaxOpsProcessed = 100000` -- global operation budget (matches SequenceNeedTempReset)
   - `kMaxRecurseDepth = 16` -- recursion depth cap (was 100)
   - `kMaxIterations = 100000` -- EvaluateProfile grid cap

## Class Hierarchy Coverage Gaps

Key under-exercised classes (from Doxygen inheritance analysis):

| Class | Line Cov | Target Fuzzers |
|-------|----------|---------------|
| CIccTagProfSeqId | 33% | profile, dump |
| CIccTagDict | 43% | profile, dump |
| CIccTagEmbedIcc | 55% | profile, dump |
| CIccMpeSpectralCLUT | 52% | spectral, v5dspobs |
| IccCmmSearch.cpp | 0% | None (needs new harness) |

## Common Fidelity Gaps

| Gap | Fix Pattern |
|-----|-------------|
| Unchecked `Begin()` return | Check `if (!pTag->Begin(...))` before `Apply()` |
| Raw ptr vs shared_ptr ownership | Match tool's `CIccProfileSharedPtr` semantics |
| Multi-profile input format | Use `unbundle-fuzzer-input.sh` for crash repro |
| Missing `GetNewApply()` null check | Guard all MPE Apply paths |
