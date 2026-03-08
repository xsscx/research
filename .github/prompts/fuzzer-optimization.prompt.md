# CFL Fuzzer Optimization Guide

## Goal
Per-fuzzer reference for optimizing the 19 CFL LibFuzzer harnesses. Each entry documents the
fuzzer's input format, iccDEV tool alignment, coverage gaps, input crafting strategy, dictionary
focus areas, and known dead code.

Use this when a fuzzer's coverage has plateaued and you need to identify which code paths are
unreachable, which need new seeds, and which need dictionary tokens.

## Prerequisites
- Fuzzers built: `ls cfl/bin/icc_*_fuzzer | wc -l` → 19
- Coverage HTML: `coverage-report/html/coverage/home/h02332/po/research/cfl/*.cpp.html`
- LLVM tools: `llvm-profdata-18`, `llvm-cov-18`
- Source: `cfl/icc_*_fuzzer.cpp`, dicts in `cfl/icc_*_fuzzer.dict`

## General Optimization Methodology

### Step 1: Extract Coverage Gaps
```bash
# Parse uncovered lines from HTML report
grep -B1 "class='uncovered-line'" \
  coverage-report/html/coverage/home/h02332/po/research/cfl/<fuzzer>.cpp.html | \
  grep -oP 'data-linenumber="\K[0-9]+'
```

### Step 2: Classify Each Gap
For each uncovered line, determine:
1. **Dead code** — unreachable due to upstream bugs (document and skip)
2. **Allocation failure** — `new` returning NULL (never triggered under ASAN; skip)
3. **Input-reachable** — needs a specific seed or dictionary token
4. **Gate-blocked** — requires passing N prior checks to reach

### Step 3: Craft Seeds or Dict Entries
- Seeds: Start from valid profiles in `iccDEV/Testing/` or `test-profiles/`
- Dict: Use `\xHH` format only (no `\n`, `\t` — LibFuzzer rejects them)
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
Extract and inject seeds into CFL corpora:
```bash
# Extract ICC profiles + TIFF files from fuzzed-images
python3 xnuimagetools/contrib/scripts/extract-icc-seeds.py \
  --input xnuimagetools/fuzzed-images/ --inject-cfl cfl

# For maximum ICC diversity, run the fuzzer with FUZZ_ICC_DIR set:
# FUZZ_ICC_DIR=test-profiles FUZZ_OUTPUT_DIR=/tmp/icc-rich ./XNU\ Image\ Fuzzer
```

Targets: ICC profiles → profile/dump/deep_dump/toxml fuzzers; TIFF files → tiffdump/specsep fuzzers.

---

## Per-Fuzzer Reference

---

### 1. icc_profile_fuzzer
**Tool**: IccDumpProfile (partial — Read + Validate only)
**Input**: Raw ICC profile bytes
**Min/Max**: 128 bytes / 1MB
**Fidelity**: ~80%

**What it exercises**: `CIccProfile::Read()`, `Validate()`, tag table parsing, header field validation. The broadest fuzzer — covers all tag types that survive `Read()`.

**Coverage focus**:
- Tag type constructors and `Read()` methods in IccTagBasic.cpp
- Malformed tag table entries (overlapping offsets, duplicate sigs)
- Version-dependent code paths (v2 vs v4 vs v5)

**Dict focus**: 4-byte ICC tag type signatures, tag signatures, color space sigs, device class sigs, platform sigs. All in big-endian.

**Seed strategy**: Harvest diverse profiles from `iccDEV/Testing/` covering all 7 profile classes.

---

### 2. icc_toxml_fuzzer
**Tool**: IccDumpProfile (with -x XML output)
**Input**: Raw ICC profile bytes
**Min/Max**: 128 bytes / 2MB
**Fidelity**: ~75%
**Branch coverage**: 64%

**What it exercises**: `CIccProfile::Read()` → `SaveXml()`. Exercises XML serialization of every tag type. Requires `IccXML2` library linkage.

**Coverage focus**:
- `CIccTag*::ToXml()` methods for each tag type
- XML attribute encoding (special chars, Unicode)
- Float formatting precision paths
- MPE element XML serialization

**Dict focus**: Tag type sigs that trigger specific `ToXml()` paths. Float edge cases (NaN, Inf, subnormals) in `\xHH` IEEE 754 format.

**Dead code**: Any `ToXml()` for tag types that `Read()` cannot construct (rare).

---

### 3. icc_fromxml_fuzzer
**Tool**: IccFromXml
**Input**: XML text (ICC profile XML format)
**Min/Max**: 64 bytes / 2MB
**Fidelity**: ~70%

**What it exercises**: `CIccProfile::LoadXml()`. Parses XML into ICC profile structures. Exercises XML parsing, type construction, validation.

**Coverage focus**:
- `CIccTag*::ParseXml()` for each tag type
- Malformed XML (unclosed tags, invalid attributes)
- Numeric parsing (hex, float, int edge cases)
- MPE element XML parsing paths

**Dict focus**: XML element names (`<IccProfile>`, `<Header>`, `<Tags>`, `<Tag>`), attribute names, ICC-specific XML tokens.

**Seed strategy**: Generate XML from valid profiles via `iccToXml_unsafe`, then mutate.

---

### 4. icc_dump_fuzzer
**Tool**: IccDumpProfile
**Input**: Raw ICC profile bytes
**Min/Max**: 128 bytes / 1MB
**Fidelity**: ~90%
**Branch coverage**: 98%

**What it exercises**: `CIccProfile::Read()`, `Describe()`, `Validate()`. High coverage — mostly saturated.

**Coverage focus**: Remaining 2% branches are allocation-failure and rare tag type combinations.

**Dict focus**: Minimal additional needed. Focus on rare tag type sigs not already in corpus.

---

### 5. icc_deep_dump_fuzzer
**Tool**: IccDumpProfile (enhanced)
**Input**: Raw ICC profile bytes
**Min/Max**: 128 bytes / 2MB
**Fidelity**: >100% (fuzzer does MORE than tool)
**Branch coverage**: 66%

**What it exercises**: All of `dump_fuzzer` plus: type-specific `dynamic_cast` checks, CLUT deep-dive (`GetData()`, `NumPoints()`, `GetGridPoint()`), MPE element iteration, 40+ signature string lookups via `CIccInfo`.

**Coverage focus**:
- Named color lookup paths (requires `icSigNamedColor2Type` tags)
- Sparse matrix tag handling (`icSigSparseMatrixType`)
- Response curve set paths
- Spectral viewing conditions tag

**Dict focus**: Named color strings, sparse matrix patterns, unusual tag type combinations.

**Seed strategy**: Profiles with named color tables (`nmcl` class profiles from iccDEV/Testing/).

---

### 6. icc_io_fuzzer
**Tool**: N/A (tests IccIO directly)
**Input**: Raw ICC profile bytes
**Min/Max**: 128 bytes / 1MB
**Fidelity**: N/A
**Branch coverage**: 58%

**What it exercises**: `CIccMemIO`, `CIccFileIO` read/write/seek operations, `CIccProfile::Read()` via memory buffer.

**Coverage focus**:
- Seek beyond bounds
- Read at EOF
- Profile read via `CIccMemIO::Attach()`
- V5 profile paths (spectral PCS, MPE)

**Dict focus**: Profile sizes (4-byte BE), tag counts, D50 illuminant values, version bytes.

**Seed strategy**: V5 profiles from `iccDEV/Testing/` (Rec2020, sRGB_D65_MAT, PCC observers).

---

### 7. icc_apply_fuzzer
**Tool**: IccApplyProfiles (single profile)
**Input**: Raw ICC profile bytes (entire input is one profile)
**Min/Max**: 130 bytes / 2MB
**Fidelity**: ~65%

**What it exercises**: `OpenIccProfile()` → `CIccCmm::AddXform()` → `Begin()` → `Apply()`. Tests CMM pipeline with single profile.

**Coverage focus**:
- CMM Begin() initialization paths
- Apply() with various color spaces
- Out-of-gamut pixel handling

**Dict focus**: Profile class sigs, color space sigs, rendering intent values.

**Known timeout (CFL-074)**: `CIccCalculatorFunc::CheckUnderflowOverflow()` had O(nOps^depth) complexity with `kMaxRecurseDepth=100` and no global operation budget. Crafted calculator ops with nested if/else/select caused >1000s execution in `Begin()`. Fix: added `pOpsProcessed` counter (100K budget) + reduced depth to 16. PoC: `test-profiles/cwe-400/timeout-77e98c61cfeffdbce4b720f7758928c525c4f1a9` (1515 bytes, v5 mntr RGB with 6 nested if/else in calc element).

---

### 8. icc_applyprofiles_fuzzer
**Tool**: IccApplyProfiles (multi-profile)
**Input**: 75% profile + 25% control bytes
**Min/Max**: 200 bytes / 2MB
**Fidelity**: ~30% (tiny 13-line harness)
**Branch coverage**: ~0%

**What it exercises**: Minimal — reads profile and basic CMM path. Smallest harness.

**Coverage focus**: Almost everything is uncovered. Major expansion opportunity.

**Input format**:
```
[profile data: 0 to size*0.75] [intent(1) interp(1) unused(1) flags(1)]
```

---

### 9. icc_applynamedcmm_fuzzer
**Tool**: IccApplyNamedCmm
**Input**: 4-byte header + ICC profile
**Min/Max**: 132 bytes / 2MB
**Fidelity**: ~75% (improved from 60%)

**What it exercises**: `CIccNamedColorCmm` with all 4 interface types: Pixel2Pixel, Named2Pixel, Pixel2Named, Named2Named. Tests encoding conversions, BPC, luminance matching, env var hints.

**Input format**:
```
[flags(1) intent(1) extra1(1) extra2(1)] [ICC profile data]
Flags byte: bit0=BPC, bit1=D2Bx, bit2=luminance, bit3=subProfile,
            bit4=tetrahedral, bit5=reserved, bit6=pccEnvVars, bit7=envVars
Intent byte: bits0-1=intent(0-3), bits4-6=nType(0-7), bit7=useHToS
```

**Coverage focus**:
- Named color interface (requires `nmcl` class profiles)
- Encoding conversion edge cases (icEncode16BitV2 with Lab space)
- Apply() error return value paths

**Dict focus**: Named color strings ("White", "Black", "Red"), encoding format IDs, xform type values.

**Seed strategy**: Named color profiles from `iccDEV/Testing/NamedColor/`.

---

### 10. icc_link_fuzzer
**Tool**: IccApplyToLink
**Input**: Two ICC profiles concatenated + 4 control bytes
**Min/Max**: 258 bytes / 2MB
**Fidelity**: ~65% (improved from 35%)

**What it exercises**: `CIccCmm` with 2-profile chain, `AddXform()` with BPC/Luminance/EnvVar hints, `Begin()` → `Apply()` grid sweep, `IterateXforms()` callback, `SaveIccProfile()` device link output.

**Input format**:
```
[profile1: 0..mid] [profile2: mid..size-4]
ctrl byte (size-3): bit0=firstTransform, bit1=noD2Bx, bit2=BPC, bit3=luminance,
                    bit4=subProfile, bits5-7=lutType(0-7)
ctrl2 byte (size-4): bit0=saveLink, bit1=envVars, bits2-3=gridSize(3-6)
interp byte (size-2): bit0 selects linear/tetrahedral
intent byte (size-1): mod 4 for rendering intent
```

**Coverage focus**:
- IXformIterator callback paths
- SaveIccProfile with device link class
- Multi-dimensional grid sweep (Apply with parameterized colors)
- All 8 icXformLutType values
- `CIccCmmEnvVarHint` environment variable injection

**Dict focus**: D50 illuminant, profile class sigs (especially `link`), xform type bytes.

**Seed strategy**: Profile pairs from `iccDEV/Testing/` (sRGB+CMYK, Lab+sRGB, display+display). Use `cfl/seeds-link-pairs/` as starting point.

**Ownership caveat**: `AddXform()` transfers profile ownership to `CIccXform::Create()`. On `icCmmStatBadXform`, the profile is already freed — do NOT delete. On other errors, caller must delete.

---

### 11. icc_calculator_fuzzer
**Tool**: N/A (tests CIccCalculator directly)
**Input**: Raw ICC profile bytes
**Min/Max**: 128 bytes / 2MB
**Fidelity**: N/A
**Branch coverage**: 69%

**What it exercises**: `CIccMpeCalculator` evaluation — stack-based calculator elements in MPE tags. Exercises operator parsing, stack operations, conditional branches, channel operations.

**Coverage focus**:
- Calculator operator decode paths
- Stack overflow/underflow handling
- Conditional jump targets
- Temporary variable allocation

**Dict focus**: Calculator opcode bytes, MPE element sigs, channel count patterns.

**Seed strategy**: Profiles with `AToB0` MPE containing `CIccMpeCalculator` elements from `iccDEV/Testing/`.

---

### 12. icc_fromcube_fuzzer
**Tool**: IccFromCube (.cube LUT → ICC profile)
**Input**: .cube text file
**Min/Max**: 16 bytes / 5MB
**Fidelity**: ~85%
**Branch coverage**: 80%

**What it exercises**: `.cube` file parsing (TITLE, LUT_3D_SIZE, LUT_3D_INPUT_RANGE, DOMAIN_MIN/MAX, float triplet data rows), CLUT construction, ICC profile creation.

**Coverage focus**:
- Missing TITLE → default description path
- No comments → skip copyright tag
- Truncated data → `parse3DTable` failure
- Incomplete rows (1 or 2 values instead of 3)
- `LUT_3D_INPUT_RANGE` with custom non-default domain

**Known dead code** (upstream bugs):
1. `DOMAIN_MIN/MAX` parsing uses `getNext(line.c_str())` instead of `getNext(line.c_str()+11)` — channel 1 always equals channel 0
2. `getNext()` never returns NULL (returns pointer to NUL byte) — 1-value/2-value DOMAIN fallback paths unreachable
3. `toEnd()` function is never called

**Dict focus**: .cube keywords (`TITLE`, `LUT_3D_SIZE`, `DOMAIN_MIN`, `DOMAIN_MAX`, `LUT_3D_INPUT_RANGE`), float patterns, comment markers.

**Dict syntax warning**: LibFuzzer dicts only support `\xHH` escapes. `\n` → `\x0a`, `\t` → `\x09`. Empty string `""` is a parse error.

---

### 13. icc_multitag_fuzzer
**Tool**: N/A (tests multi-tag extraction)
**Input**: Raw ICC profile bytes
**Min/Max**: 128 bytes / 2MB
**Fidelity**: N/A
**Branch coverage**: 67%

**What it exercises**: Tag table enumeration, shared tag offset detection, tag type identification, `IsArrayType()` checks, tag iteration patterns.

**Coverage focus**:
- Tags sharing the same offset (legitimate in ICC spec)
- Array tag types (`CIccTagArray`)
- Large tag count (255+)
- Tag table overflow (offset + size > profile size)

---

### 14. icc_roundtrip_fuzzer
**Tool**: IccRoundTrip
**Input**: ICC profile bytes + 2 control bytes at end
**Min/Max**: 130 bytes / 1MB
**Fidelity**: ~95% (improved from 85%)

**What it exercises**: `CIccEvalCompare::EvaluateProfile()` round-trip accuracy (AToB→BToA), `CIccPRMG::EvaluateProfile()` interoperability, `CIccInfo::GetRenderingIntentName()`.

**Input format**:
```
[ICC profile: 0..size-2] [nUseMPE(1): %2] [nIntent(1): %4]
```

**Coverage focus**:
- `CIccMinMaxEval::Compare()` accumulation paths
- PRMG DE threshold counting
- V5 intent name resolution

**Performance note**: SLOW fuzzer — each input requires Read→CMM setup→full evaluation grid. Corpus grows slowly.

**Known timeout (CFL-075)**: `CIccEvalCompare::EvaluateProfile()` iterates over `nGran^ndim` grid points. A 6-channel profile with default `nGran=33` produces 33^6 = 1.29B iterations, each calling `Apply()` twice — causing >1675s timeout. This is also an **upstream bug** (iccRoundTrip tool also hangs). Fix: dynamically cap nGran so total iterations stay under 100K. PoC: `test-profiles/cwe-400/timeout-4e821e5627852351ccfcf35c2006d53c1d10d068` (3352 bytes, v5 mntr MCH6/6ColorData with spectral PCS).

---

### 15. icc_spectral_fuzzer
**Tool**: N/A (tests spectral processing)
**Input**: Raw ICC profile bytes
**Min/Max**: 128 bytes / 1MB
**Fidelity**: N/A
**Branch coverage**: 70%

**What it exercises**: `CIccMpeSpectralMatrix`, `CIccMpeSpectralCLUT`, spectral PCS handling, wavelength range validation.

**Coverage focus**:
- Spectral matrix heap-OOB patterns (seed: `spectral_matrix_oob.icc`)
- Allocation-failure paths (L60-62, L72-74, L78-81, L87-90, L165-168 — unreachable under ASAN)
- V5 spectral viewing conditions

**Dict focus**: Spectral tags (`svcn`, `c2sp`, `SDsc`), wavelength ranges (380-780nm), MPE element sigs, illuminant enums.

---

### 16. icc_v5dspobs_fuzzer
**Tool**: IccV5DspObsToAToB0 (display + observer → AToB0)
**Input**: `[4-byte BE display-size] [display profile] [observer profile]`
**Min/Max**: 264 bytes / 5MB
**Fidelity**: ~80%

**What it exercises**: V5 display+observer pipeline with 15 validation gates. Requires V5 display profile (class `mntr`, AToB1Tag with MPE CurveSet+EmissionMatrix) and V5 observer profile (SpectralViewingConditionsTag + CustomToStandardPccTag as MPE).

**15 validation gates** (all must pass to reach Apply):
1. Display size > 128  2. Observer data present  3. Display Read() succeeds
4. Observer Read() succeeds  5. Display version ≥ v5  6. Display class == mntr
7. AToB1Tag exists  8. AToB1Tag is MPE  9. MPE has exactly 2 elements
10. Element[0] is CurveSetElem  11. Element[1] is EmissionMatrixElem
12. 3 input channels  13. 3 output channels  14. Observer has svcn tag
15. Observer has c2sp tag as MPE with 3-in/3-out

**Seed strategy**: Combine profiles from `iccDEV/Testing/Display/` + `iccDEV/Testing/PCC/` using:
```python
import struct
display = open('display.icc', 'rb').read()
observer = open('observer.icc', 'rb').read()
seed = struct.pack('>I', len(display)) + display + observer
```

---

### 18. icc_specsep_fuzzer
**Tool**: IccSpecSepToTiff
**Input**: Control header + TIFF pixel data + optional ICC profile
**Min/Max**: 16 bytes / 10MB
**Fidelity**: ~85% (improved from 70%)

**What it exercises**: TIFF I/O via `CTiffImg`, multi-file spectral separation, pixel interleaving, ICC profile embedding, MINISWHITE inversion.

**Input format**:
```
[nFiles(1) width(1) height(1) photoMode(1) reserved(8) bps(1) compress(1) separate(1)]
[TIFF pixel data] [optional ICC profile at end]
```

**Coverage focus**:
- MINISWHITE XOR 0xff inversion (now exercised)
- Format consistency validation across multi-file inputs (6 dimensions)
- ICC profile embedding and parsing through `CIccMemIO`
- Float TIFF paths (bitsPerSample=32)

**Dict focus**: TIFF tag patterns, photometric mode values, bits-per-sample options.

---

### 19. icc_tiffdump_fuzzer
**Tool**: N/A (tests TIFF + ICC integration)
**Input**: Raw TIFF file bytes
**Min/Max**: 8 bytes / 10MB
**Fidelity**: N/A

**What it exercises**: TIFF opening via CTiffImg (Open/ReadLine/GetPhoto), ICC profile
extraction from TIFF tag 34675, profile validation (Validate/Describe), libtiff pixel
data reading (TIFFReadEncodedStrip/TIFFReadScanline). V3 architecture: Phase 1 in-memory
libtiff + Phase 2 file-based CTiffImg.

**Coverage breakthrough (V3)**: 7896→9203 edges (+16.6%) in 2 minutes by adding:
- Pixel data reading (TIFFReadEncodedStrip/TIFFReadScanline — previously untested)
- CTiffImg wrapper exercise (Open/ReadLine/GetPhoto)
- Validate()/Describe() on extracted ICC profiles
- PLANARCONFIG_SEPARATE path

**OOM guards**: Skip tiny profiles (<1KB), MPE amplification guard (`tSize*1024 > profileSize`),
tag size > 256KB. Without these, CIccTagArray::Read() OOM from small MPE tags (CWE-789).

**CFL-082 fix integrated**: Strip buffer bounds check prevents heap-BOF in ReadLine().

**Dict focus**: TIFF header magic (`II*\0`, `MM\0*`), TIFF tag IDs, ICC profile TIFF tag (34675),
compression types, photometric values, bits-per-sample. 4215 consolidated entries in
`cfl/icc_tiffdump_fuzzer.dict`.

**Seed strategy**: Harvest TIFF files from xnuimagetools/xnuimagefuzzer fuzzed-images
using `extract-icc-seeds.py --inject-cfl` or `harvest-xnu-seeds.sh`.

---

## Cross-Cutting Optimization Tips

### LibFuzzer Dictionary Syntax
```
# CORRECT — only \xHH escapes
keyword_newline="\x0a"
keyword_tab="\x09"
keyword_cr="\x0d"
tag_sig="\x64\x65\x73\x63"

# WRONG — will be rejected or misinterpreted
keyword_newline="\n"
keyword_empty=""
keyword_utf8="—"
```

### ASAN Ownership Semantics
`CIccCmm::AddXform(CIccProfile*)` transfers ownership:
- **icCmmStatOk**: CMM owns the profile — do NOT delete
- **icCmmStatBadXform**: `CIccXform::Create()` already freed — do NOT delete
- **Other errors**: Caller still owns — MUST delete

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

### CWE-400 Timeout Patterns — Triage and Fix Guide

When a fuzzer produces a `timeout-*` artifact:

1. **Verify with upstream tool** (CRITICAL — use `iccDEV/Build/Tools/`, NOT `cfl/iccDEV/`):
   ```bash
   LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
     timeout 30 iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <timeout-file>
   ```
   If the upstream tool also hangs → **upstream algorithmic bug** (report + patch).
   If upstream handles it fine → **fuzzer-only issue** (patch library in CFL).

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
   - `kMaxOpsProcessed = 100000` — global operation budget (matches SequenceNeedTempReset)
   - `kMaxRecurseDepth = 16` — recursion depth cap (was 100)
   - `kMaxIterations = 100000` — EvaluateProfile grid cap

## Doxygen Inheritance Analysis — Coverage Gap Map

Analysis of the iccDEV class hierarchy (from Doxygen SVG graphs at
`xss.cx/public/docs/iccdev/inherits.html`) cross-referenced against
fuzzer coverage reports reveals the following under-exercised classes:

### CIccTag Hierarchy (inherit_graph_53.svg — 35+ leaf classes)

All CIccTag subclasses are exercised through `CIccProfile::Read()` which
dispatches to `CIccTagFactory`. The following have the lowest library coverage:

| Class | Library File | Line Cov | Branch Cov | Exercised By |
|-------|-------------|----------|------------|--------------|
| CIccTagProfSeqId | IccTagProfSeqId.cpp | 33% | 30% | profile, dump, deep_dump |
| CIccTagDict | IccTagDict.cpp | 43% | 65% | profile, dump, deep_dump |
| CIccTagEmbedIcc | IccTagEmbedIcc.cpp | 55% | 36% | profile, dump, deep_dump |
| CIccTagComposite | IccTagComposite.cpp | 70% | 57% | profile, dump, deep_dump |

**Targeted seeds added**: NamedColor, SparseMatrixNamedColor, FluorescentNamedColor,
MCS (CMYKOGP, 6ChanSelect), Encoding (ISO22028), SpecRef (6ChanInput, 6ChanCamera),
ICS (Rec2100HlgFull-Part3), CalcTest, PCC-CAM profiles.

### CIccMultiProcessElement Hierarchy (inherit_graph_39.svg — 17 leaf classes)

MPE elements are exercised through `CIccTagMultiProcessElement::Read()`.
Coverage varies by element type:

| Class | Status | Primary Fuzzer |
|-------|--------|---------------|
| CIccMpeCLUT | Well covered (79% lines) | profile, calculator, v5dspobs |
| CIccMpeMatrix | Well covered (79% lines) | profile, calculator, v5dspobs |
| CIccMpeCurveSet | Well covered | profile, calculator |
| CIccMpeCalculator | Good (92% lines) | calculator |
| CIccMpeCAM (JabToXYZ/XYZToJab) | Moderate | profile (via PCC-CAM seeds) |
| CIccMpeSpectralCLUT | Low (52% lines, 30% branches) | spectral, v5dspobs |
| CIccMpeSpectralMatrix | Low | spectral |
| CIccMpeSpectralObserver | Low | spectral, v5dspobs |
| CIccMpeTintArray | Moderate | profile (via NamedColor seeds) |
| CIccMpeToneMap | Moderate | profile (via Display seeds) |
| CIccMpeAcs (BAcs/EAcs) | Good (87% lines) | profile, calculator |

### Core Infrastructure Coverage

| Library File | Lines | Branches | Impact |
|-------------|-------|----------|--------|
| IccCmmSearch.cpp | **0%** | **0%** | No fuzzer targets CIccCmmSearch |
| IccCmm.cpp | 47% | 37% | Core CMM — all apply/link fuzzers |
| IccCmm.h | 31% | 35% | Inline methods in CMM header |

**IccCmmSearch.cpp** is completely un-fuzzed. It implements `CIccCmmSearch` which
does iterative search through profile connections. Candidate for a future
`icc_search_fuzzer` (maps to the `IccApplySearch` tool which has no fuzzer).

### Improvement Strategy

1. **Tag diversity seeds** — Added 14 profiles per fuzzer covering NamedColor,
   MCS, Encoding, SpecRef, ICS, Calc, PCC-CAM, and Display/GSDF types
2. **IccCmmSearch** — Requires new fuzzer harness (future work)
3. **IccMpeSpectral** — Existing spectral + v5dspobs fuzzers need more V5
   spectral profiles with spectral CLUT/matrix/observer elements
4. **IccTagEmbedIcc** — The applyprofiles fuzzer now exercises embedded profile
   paths through the embed_icc flag
5. **Begin()/Apply() audit** — All fuzzers that call `Begin()` then `Apply()`
   must check Begin()'s return value. `CIccMpeCurveSet::Begin()` returns false
   when any sub-curve fails (e.g., `CIccSingleSampledCurve` with `m_nCount < 2`),
   leaving `m_pSamples` NULL. Calling `Apply()` without checking → NULL deref
   (CWE-476). Fixed in v5dspobs (CFL-072). Audit: apply, link, calculator,
   spectral fuzzers for the same pattern.

## Common Fidelity Gaps

Known patterns where fuzzers diverge from their target tool behavior:

| Gap | Fuzzers Affected | Fix Pattern |
|-----|-----------------|-------------|
| Unchecked `Begin()` return | v5dspobs (fixed), apply, link, calculator | Check `if (!pTag->Begin(...))` before `Apply()` |
| Raw ptr vs shared_ptr | v5dspobs, link | Tool uses `CIccProfileSharedPtr`; fuzzer uses raw `CIccProfile*` — ensure matching ownership semantics |
| Multi-profile input format | v5dspobs, link, applyprofiles, specsep | Crash files need unbundling before tool repro — use `unbundle-fuzzer-input.sh` |
| Missing `GetNewApply()` null check | All MPE fuzzers | `GetNewApply()` can return NULL on allocation failure |
