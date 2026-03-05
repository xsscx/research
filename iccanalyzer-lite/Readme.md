## iccAnalyzer-lite

Last Updated: 2026-03-05 15:10:00 UTC

tl;dr ICC Profile Security Analyzer — 86 heuristics, ASAN/UBSAN instrumented, callgraph analysis

## Target Audience
- Security Researcher
- NVD Analyst
- Developer

## Analysis Modes

```
iccAnalyzer-lite [MODE] <file>

  -h  <file.icc>              Security heuristics (86 checks)
  -a  <file.icc>              Comprehensive analysis (all modes)
  -r  <file.icc>              Round-trip accuracy test
  -n  <file.icc>              Ninja mode (minimal output)
  -nf <file.icc>              Ninja mode (full dump, no truncation)
  -cg <crash.log> [out.png]   Call graph from ASAN/UBSAN crash log
  -x  <file.icc> <basename>   Extract LUT tables
  -xml <file.icc> <out.xml>   Export heuristics report as XML + XSLT
```

## Architecture (16 modules, 13,200+ LOC)

| Module | LOC | Purpose |
|--------|-----|---------|
| IccHeuristicsRawPost.cpp | 2,955 | Raw-file heuristics H33–H69, fallback engine |
| IccHeuristicsLibrary.cpp | 2,715 | Library-API heuristics H9–H32, H56–H86 |
| IccAnalyzerLUT.cpp | 833 | LUT extraction and analysis |
| IccAnalyzerNinja.cpp | 727 | Ninja mode (compact dump) |
| IccAnalyzerSecurity.cpp | 652 | Orchestrator: header heuristics H1–H8, H15–H17 |
| IccAnalyzerCallGraph.cpp | 652 | ASAN/UBSAN callgraph, DOT/JSON/PNG export |
| IccAnalyzerTagDetails.cpp | 569 | Tag-level detailed output |
| IccAnalyzerXMLExport.cpp | 378 | XML + XSLT report export |
| IccAnalyzerPathValidation.cpp | 359 | Path validation, sanitization, DB format |
| iccAnalyzer-lite.cpp | 348 | Main entry, crash recovery, mode dispatch |
| IccAnalyzerValidation.cpp | 302 | Profile validation and round-trip |
| IccAnalyzerErrors.cpp | 231 | Error formatting and reporting |
| IccAnalyzerInspect.cpp | 201 | Profile inspection utilities |
| IccAnalyzerConfig.cpp | 183 | Build config and version |
| IccAnalyzerComprehensive.cpp | 172 | Comprehensive analysis orchestrator |
| IccAnalyzerSignatures.cpp | 161 | Known signature database |

## Security Heuristics (H1–H86)

### Header-Level (H1–H8, H15–H17)
| ID | Check | Risk |
|----|-------|------|
| H1 | Profile size bounds | Oversized/zero-length profiles |
| H2 | Magic bytes (`acsp`) | Corrupted header |
| H3 | Data ColorSpace | Invalid colorspace enum |
| H4 | PCS ColorSpace | Invalid PCS enum |
| H5 | Platform signature | Unknown platform |
| H6 | Rendering Intent | Out-of-range intent |
| H7 | Profile Class | Unknown device class |
| H8 | Illuminant XYZ | NaN/Inf/negative illuminant |
| H15 | Date validation | Malformed timestamp |
| H16 | Signature patterns | Suspicious repeat-byte patterns |
| H17 | Spectral range | Invalid spectral parameters |

### Tag-Level (H9–H14, H18–H19)
| ID | Check | Risk |
|----|-------|------|
| H9 | Text tag presence | Missing description/copyright |
| H10 | Tag count | Excessive (>200) or zero tags |
| H11 | CLUT entry limit | >16M CLUT entries (OOM) — CVE-2026-21490, CVE-2026-21494 |
| H12 | MPE chain depth | Excessive element chains |
| H13 | Per-tag size | Tags >64MB |
| H14 | TagArrayType (tary) | UAF via type confusion — CVE-2026-21677 |
| H18 | Technology signature | Non-standard technology |
| H19 | Tag offset overlap | Overlapping tag data regions |

### Deep Content Analysis (H20–H24)
| ID | Check | Risk |
|----|-------|------|
| H20 | Tag type signature validation | Non-printable/null type bytes → corrupted tag data |
| H21 | tagStruct member inspection | Malformed struct members, invalid member types |
| H22 | NumArray scalar expectation | Multi-value array in scalar context → **SBO** (patch 027) |
| H23 | NumArray value ranges | NaN/Inf values → FPE/div-by-zero |
| H24 | Nesting depth | Recursive struct/array depth >4 → stack overflow (patch 061) |

### Raw File Analysis (H25–H32)
| ID | Check | Risk | CVE Coverage |
|----|-------|------|-------------|
| H25 | Tag offset/size OOB | Tag data extends past file/profile bounds → **HBO** | CVE-2026-25583, CVE-2026-24852 |
| H26 | NamedColor2 string validation | Prefix/suffix with XML-expandable chars → **SBO** | CVE-2026-21488 |
| H27 | MPE matrix dimensions | Matrix with <3 output channels → **HBO** | CVE-2026-25634, CVE-2026-22047 |
| H28 | LUT dimension validation | LUT8/LUT16 nInput^nGrid CLUT → **OOM** | GHSA-x9hr-pxxc-h38p |
| H29 | ColorantTable string validation | Unterminated name[32] → strlen overflow | GHSA-4wqv-pvm8-5h27, CVE-2026-27692 |
| H30 | GamutBoundaryDesc allocation | Triangle/vertex count vs tag size → **OOM** | GHSA-rc3h-95ph-j363 |
| H31 | MPE channel count validation | Input/output channels >32 → **SBO** | CVE-2026-25634, CVE-2026-25584 |
| H32 | Tag type confusion detection | Unknown type signature → memory corruption | GHSA-2pjj-3c98-qp37 |

### Library-API Heuristics (H33–H60)
| ID | Check | Risk |
|----|-------|------|
| H33 | Dict tag deep analysis | DictEntry name/value/localized data integrity |
| H34 | Named color validation | Oversized count/color entries → **HBO** |
| H35 | MPE calculator opcode scan | Dangerous opcodes: tGet, tPut, tSave |
| H36 | tagArray recursion guard | Recursive TagArray elements |
| H37 | ResponseCurve measurements | Excessive measurement count → allocation bomb |
| H38 | Tag data entropy analysis | Low-entropy = padding/repetition anomaly |
| H39 | Tag alignment and padding | Misaligned tag offsets |
| H40 | Profile class/colorspace consistency | Class vs spaces mismatch |
| H41 | Rendering intent consistency | Tag presence vs declared intent |
| H42–H54 | Library API surface | CIccProfile::Read, Validate, FindTag, Describe coverage |
| H55 | CLUT precision validation | LUT bit-depth anomalies |
| H56 | Curve function type validation | Invalid parametric curve types |
| H57 | Profile ID / MD5 consistency | Missing or mismatched profile identifier |
| H58 | MPE sub-element recursion guard | Infinite recursion in nested MPE elements |
| H59 | XYZ value range validation | Out-of-range D50 illuminant values |
| H60 | Viewing conditions validation | Malformed viewing condition tags |

### Extended Library Coverage (H61–H78)
| ID | Check | Risk |
|----|-------|------|
| H61 | Measurement type validation | Geometry, flare, illuminant fields |
| H62 | Spectral data validation | Wavelength range, step, array consistency |
| H63 | Profile sequence desc validation | Device manufacturer/model integrity |
| H64 | Chromatic adaptation validation | 3×3 matrix determinant and conditioning |
| H65 | Multi-localized Unicode | String length, language code validation |
| H66 | Colorant order validation | Table index bounds |
| H67 | CIccCmm transform validation | Transform chain initialization |
| H68 | Screening descriptor validation | Frequency/angle per channel |
| H69 | Profile ID / MD5 consistency | Computed vs stored ID comparison |
| H70 | Device attributes validation | Reflective/transparency/matte/gloss flags |
| H71–H78 | Tag type completeness | Coverage of all iccDEV tag type parsers |

### Advanced Heuristics (H79–H86)
| ID | Check | Risk |
|----|-------|------|
| H79 | CIccIO Read/Write validation | I/O operation error paths |
| H80 | Tag table binary search | Sorted-order assumptions |
| H81 | MPE formula element validation | Element type coverage |
| H82 | BRDF/spectral structure validation | Complex nested structures |
| H83 | Embedded profile validation | Recursion and size limits |
| H84 | UTF-16 string handling | Surrogate pair, BOM validation |
| H85 | Numeric conversion safety | Float-to-fixed overflow |
| H86 | Comprehensive tag cross-references | Inter-tag dependency validation |

## Call Graph Analysis (-cg)

Parses ASAN/UBSAN crash logs and generates:
- **DOT graph** — Graphviz visualization (entry→crash)
- **PNG image** — Rendered call chain
- **JSON report** — Machine-readable crash analysis

Supports 10 ASAN error types + UBSAN runtime errors with exploitability assessment.

```bash
# From ASAN crash log
iccanalyzer-lite -cg crash_log.txt output.png

# From UBSAN runtime error
iccanalyzer-lite -cg ubsan_log.txt output.png

# Output: output.png, output.png.dot, output.png.json
```

## Build

Links against **unpatched upstream iccDEV** to detect bugs in the original library.

```bash
cd iccanalyzer-lite && ./build.sh
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no issues detected |
| 1 | Finding — security heuristic warnings |
| 2 | Error — I/O failure |
| 3 | Usage — bad arguments |
