# iccDEV CLI Tools — Reference Documentation

Comprehensive usage documentation and tested examples for all 14 iccDEV command-line tools.
Built against IccProfLib version 2.3.1.5 with full ASAN+UBSAN instrumentation.

## Quick Reference

| # | Tool | Purpose | Primary Input |
|---|------|---------|---------------|
| 1 | [iccDumpProfile](iccDumpProfile/) | Display profile header, tags, data | ICC profile |
| 2 | [iccToXml](iccToXml/) | Convert ICC → XML | ICC profile |
| 3 | [iccFromXml](iccFromXml/) | Convert XML → ICC | XML file |
| 4 | [iccRoundTrip](iccRoundTrip/) | Test transform accuracy | ICC profile |
| 5 | [iccFromCube](iccFromCube/) | Create ICC from .cube LUT | .cube file |
| 6 | [iccApplyNamedCmm](iccApplyNamedCmm/) | Apply transforms to color data | Data file + ICC |
| 7 | [iccApplyProfiles](iccApplyProfiles/) | Apply transforms to TIFF images | TIFF + ICC |
| 8 | [iccApplySearch](iccApplySearch/) | Search optimal PCC transforms | Data file + ICC pair |
| 9 | [iccApplyToLink](iccApplyToLink/) | Create DeviceLink / .cube | ICC profile chain |
| 10 | [iccTiffDump](iccTiffDump/) | Dump TIFF metadata, extract ICC | TIFF image |
| 11 | [iccJpegDump](iccJpegDump/) | Extract/inject ICC from JPEG | JPEG image |
| 12 | [iccPngDump](iccPngDump/) | Extract/inject ICC from PNG | PNG image |
| 13 | [iccV5DspObsToV4Dsp](iccV5DspObsToV4Dsp/) | Convert v5 display → v4 | v5 ICC pair |
| 14 | [iccSpecSepToTiff](iccSpecSepToTiff/) | Merge spectral TIFFs | TIFF sequence |

## Prerequisites

### Library Path

All tools require the iccDEV shared libraries. Set `LD_LIBRARY_PATH` before use:

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML
```

### ASAN-Instrumented Builds

For security testing with untrusted profiles:

```bash
export ASAN_OPTIONS=halt_on_error=0,detect_leaks=0
export UBSAN_OPTIONS=halt_on_error=0,print_stacktrace=1
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML
```

### Build

```bash
cd iccDEV/Build
cmake Cmake \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer"
make -j32
```

## JSON Configuration Feature

Three tools support a JSON configuration mode via the `-cfg` flag:

| Tool | JSON Support | Top-Level Keys |
|------|-------------|----------------|
| [iccApplyNamedCmm](iccApplyNamedCmm/) | ✓ `-cfg` | `dataFiles`, `profileSequence`, `colorData` |
| [iccApplyProfiles](iccApplyProfiles/) | ✓ `-cfg` | `imageFiles`, `profileSequence` |
| [iccApplySearch](iccApplySearch/) | ✓ `-cfg` | `dataFiles`, `searchApply`, `colorData` |
| iccApplyToLink | ✗ | Args only |

### Shared Infrastructure

All JSON parsing uses a shared implementation:
- **IccJsonUtil.{h,cpp}** — nlohmann/json wrappers (`loadJsonFrom`, `saveJsonAs`, type converters)
- **IccCmmConfig.{h,cpp}** — 9 configuration classes with `fromJson()`/`toJson()` methods (2,426 LOC)

### Critical: String Encoding Values

JSON configs use **string** encoding names — NOT numeric enum integers.
Numeric values silently return `icEncodeUnknown` → `"Invalid source data encoding"`.

| JSON String | C++ Enum | Range |
|-------------|----------|-------|
| `"value"` | icEncodeValue | Varies |
| `"percent"` | icEncodePercent | 0–100 |
| `"unitFloat"` | icEncodeUnitFloat | 0.0–1.0 |
| `"float"` | icEncodeFloat | Unbounded |
| `"8Bit"` | icEncode8Bit | 0–255 |
| `"16Bit"` | icEncode16Bit | 0–65535 |
| `"16BitV2"` | icEncode16BitV2 | 0–65535 |

Data type fields also use strings: `"colorData"`, `"legacy"`, `"it8"`.

### Known JSON Serialization Bugs (toJson round-trip)

| Bug | Location | Description |
|-----|----------|-------------|
| `dstDigits]"` typo | CIccCfgDataApply::toJson ~L303 | "]" inside key string |
| `srcImageFile` ↔ `srcImgFile` | CIccCfgImageApply L405 vs L422 | fromJson/toJson key mismatch |
| `iccFile` ↔ `iccProfile` | CIccCfgProfile L623 vs L683 | fromJson/toJson key mismatch |
| `interpolation` array assign | CIccCfgProfile::toJson ~L706 | Assigns `icInterpNames` array, not `icInterpNames[i]` |
| Duplicate `transform` key | CIccCfgProfile::fromJson L633+L655 | Same key for transform type AND interpolation |

All 5 bugs affect `toJson()` output — input `fromJson()` parsing works correctly.
**Fix**: CFL-026 patch — onboarded to both `cfl/patches/` (research repo) and
`Testing/Fuzzing/patches/` (iccDEV cfl branch). Standalone upstream patch at `~/typos.patch`.

### JSON Test Suite (90 tests)

| Section | Tests | Pass | Tool(s) |
|---------|-------|------|---------|
| Valid configs | 9 | 9 | ApplyNamedCmm, ApplySearch |
| Malformed JSON (ApplyNamedCmm) | 14 | 14 | ApplyNamedCmm |
| Malformed JSON (ApplySearch) | 14 | 14 | ApplySearch |
| Malformed JSON (ApplyProfiles) | 14 | 14 | ApplyProfiles |
| Edge cases | 3 | 3 | ApplyNamedCmm |
| All intents (×3 profiles) | 12 | 12 | ApplyNamedCmm |
| All encodings | 7 | 7 | ApplyNamedCmm |
| Profile variants | 7 | 7 | ApplyNamedCmm |
| Crash profiles | 10 | 10 | ApplyNamedCmm |
| **Total** | **90** | **90** | **0 ASAN, 0 UBSAN** |

Test configs: `docs/Testing/json-configs/` (9 valid) + `docs/Testing/malformed-json/` (14 malformed)
Test runner: `docs/Testing/test-json-tools.sh`
Results: `docs/Testing/README.md`

## Coverage Baseline

### Structured Test Scripts

| Script | Path | Tests | Scope |
|--------|------|-------|-------|
| `test-iccdev-all.sh` | `.github/scripts/test-iccdev-all.sh` | 843 | All 14 tools, parallel, full corpus |
| `test-json-tools.sh` | `docs/Testing/test-json-tools.sh` | 90 | JSON `-cfg` mode (3 tools, ASAN+UBSAN) |
| `test-specseptotiff.sh` | `.github/scripts/test-specseptotiff.sh` | 34 | Spectral TIFF merging, all option combos |
| `test-iccdev-tools-comprehensive.sh` | `.github/scripts/test-iccdev-tools-comprehensive.sh` | 103 | Original baseline (see table below) |

Run the primary test suite:

```bash
bash .github/scripts/test-iccdev-all.sh
```

### Results Summary (v2.3.1.5, 2026-03-12)

**Original baseline** (103 structured tests):

| Tool | Tests | Pass | Fail | Notes |
|------|-------|------|------|-------|
| iccDumpProfile | 14 | 13 | 1 | NamedColor exit 255 |
| iccToXml | 7 | 7 | 0 | |
| iccFromXml | 6 | 6 | 0 | |
| iccRoundTrip | 8 | 8 | 0 | |
| iccFromCube | 5 | 5 | 0 | |
| iccApplyNamedCmm | 15 | 14 | 1 | encoding=4 unsupported |
| iccApplyToLink | 7 | 7 | 0 | |
| iccApplyProfiles | 6 | 6 | 0 | |
| iccApplySearch | 4 | 3 | 1 | Chain incompatible |
| iccTiffDump | 7 | 7 | 0 | |
| iccJpegDump | 4 | 2 | 2 | No ICC in test JPEGs |
| iccPngDump | 4 | 4 | 0 | |
| iccV5DspObsToV4Dsp | 3 | 0 | 3 | Observer pairing issue |
| iccSpecSepToTiff | 2 | 0 | 2 | No sequential TIFFs |
| PoC profiles | 10 | 10 | 0 | All patched |
| XML round-trip | 1 | 0 | 1 | NamedColor dump |
| **Total** | **103** | **92** | **11** | **0 ASAN, 0 UBSAN** |

**Mass TIFF testing** (5,748 runs against 22,218-file tiff-main corpus, 2026-03-12):

| Tool | Runs | Success | ASAN | UBSAN | Option Combos |
|------|------|---------|------|-------|---------------|
| iccTiffDump | 1,000 | 1,000 | 0 | 0 | 500 files × 2 modes (dump, dump+extract ICC) |
| iccDumpProfile | 1,500 | 1,500 | 0 | 0 | 500 files × 3 modes (basic, -v, ALL tags) |
| iccApplyProfiles | 3,200 | 3,200 | 0 | 0 | 50 files × option matrix (enc×comp×planar×embed×interp×intent) |
| iccSpecSepToTiff | 48 | 48 | 0 | 0 | 4 seed series × compress × sep × 3 ICC profiles |
| **Total** | **5,748** | **5,748** | **0** | **0** | |

**Dedicated specsep testing** (34 tests via `test-specseptotiff.sh`):

| Category | Tests | Pass | Fail |
|----------|-------|------|------|
| Error handling | 6 | 6 | 0 |
| Basic merging | 6 | 6 | 0 |
| Compression | 4 | 4 | 0 |
| Separation modes | 4 | 4 | 0 |
| ICC profile embedding | 4 | 4 | 0 |
| Cross-validation | 10 | 10 | 0 |
| **Total** | **34** | **34** | **0** |

### TIFF Test Corpus

A consolidated deduplicated TIFF corpus at `~/po/tiff-main/`:

| Metric | Count |
|--------|-------|
| Total unique TIFFs | 22,218 |
| Size | 642.7 MB |
| TIFF-LE | 15,139 |
| TIFF-BE | 4,461 |
| BigTIFF-LE | 2,429 |
| Sources | cfl, xnuimagetools, fuzz, xnuimagefuzzer, external corpora |

### Spectral Seed Corpus

147 structured spectral TIFF seeds at `iccDEV/Testing/Fuzzing/seeds/tiff/spectral/`:

| Series | Files | Channels | Description |
|--------|-------|----------|-------------|
| `spec_%03d.tif` | 1–10 | 10 | 4×4 8-bit MINISBLACK baseline |
| `wl_%03d.tif` | 380–780 step 5 | 81 | Full visible spectrum 8-bit |
| `ch8_%03d.tif` | 1–10 | 10 | 8×8 8-bit MINISBLACK |
| `white_%03d.tif` | 1–10 | 10 | 16-bit MINISBLACK (all-white) |
| `lg_%03d.tif` | 1–10 | 10 | 256×256 8-bit large images |
| `big_%03d.tif` | 1–10 | 10 | BigTIFF format 4×4 8-bit |

## Tool Categories

### Profile Inspection

| Tool | What It Shows |
|------|--------------|
| [iccDumpProfile](iccDumpProfile/) | Human-readable text dump of header + tags |
| [iccToXml](iccToXml/) | Full XML serialization of profile |

### Profile Creation

| Tool | Creates From |
|------|-------------|
| [iccFromXml](iccFromXml/) | XML source |
| [iccFromCube](iccFromCube/) | .cube LUT file |
| [iccApplyToLink](iccApplyToLink/) | Profile transform chain |
| [iccV5DspObsToV4Dsp](iccV5DspObsToV4Dsp/) | v5 display + observer pair |

### Color Transform Application

| Tool | Input Type |
|------|-----------|
| [iccApplyNamedCmm](iccApplyNamedCmm/) | Text data files |
| [iccApplyProfiles](iccApplyProfiles/) | TIFF images |
| [iccApplySearch](iccApplySearch/) | Text data + PCC search |
| [iccRoundTrip](iccRoundTrip/) | Forward + inverse accuracy test |

### Image ICC Management

| Tool | Format | Operations |
|------|--------|-----------|
| [iccTiffDump](iccTiffDump/) | TIFF | Metadata dump, ICC extraction |
| [iccJpegDump](iccJpegDump/) | JPEG | ICC extraction and injection |
| [iccPngDump](iccPngDump/) | PNG | ICC extraction and injection |

### Spectral Processing

| Tool | Function |
|------|----------|
| [iccSpecSepToTiff](iccSpecSepToTiff/) | Merge spectral channel TIFFs |

## Exit Code Reference

| Code | Classification | Meaning |
|------|---------------|---------|
| 0 | Success | Clean operation |
| 1 | Soft failure | Graceful rejection (e.g., no ICC in image) |
| 254 (-2) | Tool error | Transform matrix error |
| 255 (-1) | Tool error | General tool error |
| 134 | CRASH | SIGABRT (assert/abort) |
| 137 | CRASH | SIGKILL (OOM killed) |
| 139 | CRASH | SIGSEGV (segmentation fault) |

**Important**: Exit codes 1, 254, 255 are graceful failures — NOT crashes.
Only exit codes matching known signal values (134, 136, 137, 139) indicate crashes.

## CFL Fuzzer Mapping

Each tool has a corresponding CFL LibFuzzer harness:

| Tool | CFL Fuzzer | Fidelity |
|------|-----------|----------|
| iccDumpProfile | `icc_dump_fuzzer`, `icc_deep_dump_fuzzer` | >100% (fuzzer covers more) |
| iccToXml | `icc_toxml_fuzzer` | ~85% |
| iccFromXml | `icc_fromxml_fuzzer` | ~80% |
| iccRoundTrip | `icc_roundtrip_fuzzer` | ~95% |
| iccFromCube | `icc_fromcube_fuzzer` | **100%** (only `main` differs) |
| iccApplyNamedCmm | `icc_applynamedcmm_fuzzer` | ~75% |
| iccApplyProfiles | `icc_applyprofiles_fuzzer` | ~70% |
| iccApplySearch | (via applynamedcmm) | ~60% |
| iccApplyToLink | `icc_link_fuzzer` | ~65% |
| iccTiffDump | `icc_tiffdump_fuzzer` | ~80% |
| iccV5DspObsToV4Dsp | `icc_v5dspobs_fuzzer` | ~70% |
| iccSpecSepToTiff | `icc_specsep_fuzzer` (V2.1) | ~85% (+ICC embed) |

## Test Data

Test data files are in [test-data/](test-data/):

| File | Format | Description |
|------|--------|-------------|
| `test-data-rgb-8bit.txt` | iccDEV data | RGB 8-bit samples (11 colors) |
| `test-data-rgb-16bit.txt` | iccDEV data | RGB 16-bit samples (6 colors) |
| `test-data-rgb-float.txt` | iccDEV data | RGB float samples (8 colors) |
| `test-data-cmyk-percent.txt` | iccDEV data | CMYK percent samples (10 colors) |
| `test-data-lab-float.txt` | iccDEV data | Lab float samples (9 colors) |
| `test-identity.cube` | .cube LUT | Identity 2×2×2 passthrough |
| `test-warmfilm-5x5x5.cube` | .cube LUT | Warm film grade 5×5×5 (125 entries) |

### iccDEV Data File Format

```
'RGB '  ; Color Space (4-char ICC signature in single quotes)
icEncodeValue  ; Encoding enum name

255 255 255     ; White
0 0 0           ; Black
128 128 128     ; Mid-gray
```

## Encoding Reference

Used by iccApplyNamedCmm, iccApplySearch, iccApplyProfiles:

| Code | Name | Range | Description |
|------|------|-------|-------------|
| 0 | icEncodeValue | Varies | Native value encoding (Lab conversion when 3-channel) |
| 1 | icEncodePercent | 0–100 | Percentage values |
| 2 | icEncodeUnitFloat | 0.0–1.0 | Unit float (clips to range) |
| 3 | icEncodeFloat | Unbounded | Unclamped float |
| 4 | icEncode8Bit | 0–255 | 8-bit integer |
| 5 | icEncode16Bit | 0–65535 | 16-bit integer |
| 6 | icEncode16BitV2 | 0–65535 | 16-bit v2 encoding |

## Rendering Intent Reference

| Code | Intent | Description |
|------|--------|-------------|
| 0 | Perceptual | Preserves visual relationships |
| 1 | Relative Colorimetric | Maps white point, preserves in-gamut colors |
| 2 | Saturation | Maximizes saturation (for business graphics) |
| 3 | Absolute Colorimetric | No white point mapping |

## Related Resources

- [iccanalyzer-lite](../../../iccanalyzer-lite/) — 150-heuristic ICC security analyzer
- [CFL Fuzzers](../../../cfl/) — 12 LibFuzzer harnesses for iccDEV
- [colorbleed_tools](../../../colorbleed_tools/) — Unsafe ICC↔XML for mutation testing
- [ICC.1-2022-05](https://www.color.org/specification/ICC.1-2022-05.pdf) — ICC specification
- [iccDEV Doxygen](https://xss.cx/public/docs/iccdev/hierarchy.html) — Class hierarchy docs
