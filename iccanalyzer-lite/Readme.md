## iccAnalyzer-lite

Last Updated: 2026-03-08 14:00:00 UTC

tl;dr ICC Profile Security Analyzer — 141 heuristics (H1-H138 ICC + H139-H141 TIFF), ASAN/UBSAN instrumented, CVE cross-referenced, JSON output, callgraph analysis

## Target Audience
- Security Researcher
- NVD Analyst
- Developer

## Analysis Modes

```
iccAnalyzer-lite [MODE] <file>

  -h  <file.icc>              Security heuristics (141 checks)
  -a  <file.icc|file.tif>     Comprehensive analysis (all modes, auto-detects TIFF)
  -r  <file.icc>              Round-trip accuracy test
  -n  <file.icc>              Ninja mode (minimal output)
  -nf <file.icc>              Ninja mode (full dump, no truncation)
  -cg <crash.log> [out.png]   Call graph from ASAN/UBSAN crash log
  -x  <file.icc> <basename>   Extract LUT tables
  -xml <file.icc> <out.xml>   Export heuristics report as XML + XSLT
  -img <file.tif>             Explicit image analysis mode
  --json <file.icc>           JSON structured output
```

## Architecture (27 modules, 20,400+ LOC)

### Heuristic Modules (8 files)

| Module | Heuristics | LOC | Purpose |
|--------|-----------|-----|---------|
| IccHeuristicsHeader.cpp | H1-H8, H15-H17 | ~500 | Raw header byte validation |
| IccHeuristicsTagValidation.cpp | H9-H32 | 1,627 | Tag structure and type checks |
| IccHeuristicsRawPost.cpp | H33-H55, H57-H69 | 2,955 | Raw file I/O heuristics |
| IccHeuristicsDataValidation.cpp | H56, H58, H60-H67, H70-H102 | 2,624 | Deep data validation |
| IccHeuristicsProfileCompliance.cpp | H103-H120 | 1,749 | ICC spec compliance |
| IccHeuristicsIntegrity.cpp | H121-H138 | 1,707 | Integrity and CWE-400 checks |
| IccImageAnalyzer.cpp | H139-H141 | ~800 | TIFF image security analysis |
| IccHeuristicsLibrary.cpp | — | 99 | Thin dispatcher for H9-H138 |

### Support Modules

| Module | Purpose |
|--------|---------|
| IccHeuristicsRegistry.h | 141-entry metadata table (name, CWE, CVE, phase) |
| IccHeuristicsHelpers.h | FindAndCast<T> template, RawFileHandle RAII |
| IccAnalyzerJson.cpp | --json structured output with CVE cross-refs |
| IccAnalyzerSecurity.cpp | Orchestrator: phase dispatch, crash recovery |
| IccAnalyzerComprehensive.cpp | Comprehensive analysis orchestrator |
| IccAnalyzerCallGraph.cpp | ASAN/UBSAN callgraph, DOT/JSON/PNG export |
| IccAnalyzerNinja.cpp | Ninja mode (compact dump) |
| IccAnalyzerLUT.cpp | LUT extraction and analysis |
| IccAnalyzerXMLExport.cpp | XML + XSLT report export |
| IccAnalyzerTagDetails.cpp | Tag-level detailed output |
| IccAnalyzerPathValidation.cpp | Path validation, sanitization, DB format |
| IccAnalyzerValidation.cpp | Profile validation and round-trip |
| IccAnalyzerErrors.cpp | Error formatting and reporting |
| IccAnalyzerInspect.cpp | Profile inspection utilities |
| IccAnalyzerConfig.cpp | Build config and version |
| IccAnalyzerSignatures.cpp | Known signature database |
| IccAnalyzerColors.cpp | Color output formatting |
| iccAnalyzer-lite.cpp | Main entry, crash recovery, mode dispatch |

## CVE Coverage

38 heuristics detect patterns from 46 CVEs (from 77 iccDEV security advisories).
22 XML-parser CVEs are out of scope (binary-only analyzer).

## Security Heuristics (H1–H141)

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

### Coverage-Driven Heuristics (H87–H94)
| ID | Check | Risk |
|----|-------|------|
| H87 | TRC curve anomalies | Extreme gamma, degenerate curves |
| H88 | Chromatic adaptation matrix | Determinant, conditioning, identity check |
| H89 | Profile sequence descriptions | Device manufacturer/model integrity |
| H90 | Preview tag channel consistency | Channel count vs colorspace mismatch |
| H91 | Colorant order validation | Index bounds, duplicate detection |
| H92 | Spectral viewing conditions | Illuminant range, observer data integrity |
| H93 | Embedded profile flag consistency | Flag vs tag presence mismatch |
| H94 | Matrix/TRC colorant consistency | Matrix determinant vs colorant XYZ |

### Gap-Targeted Heuristics (H95–H102)
| ID | Check | Risk |
|----|-------|------|
| H95 | Sparse matrix array bounds | SparseMatrix row/col overflow |
| H96 | Embedded profile recursion | Nested profile depth bomb |
| H97 | Profile sequence ID validation | MD5 consistency in sequence |
| H98 | Spectral MPE element validation | Wavelength range, observer data |
| H99 | Embedded image tags | Size limits, format validation |
| H100 | Profile sequence description | Cross-tag consistency |
| H101 | MPE sub-element channel continuity | Input→output channel chaining |
| H102 | Tag size cross-check | Declared vs actual size mismatch |

### Coverage-Gap API Heuristics (H103–H120)
| ID | Check | Risk |
|----|-------|------|
| H103 | PCC viewing conditions | D50 deviation, spectral data integrity |
| H104 | PRMG gamut evaluation | Gamut boundary description analysis |
| H105 | Matrix-TRC determinant/inversion | Singular matrix detection, colorant XYZ |
| H106 | Environment variable tags | Spectral range validation, MPE env vars |
| H107 | Channel cross-check | Colorspace channel count vs tag channel count |
| H108 | Private tag detection | Non-ICC-registered private tags |
| H109 | Shellcode pattern scan | x86/ARM shellcode sequences in tag data |
| H110 | Class tag validation | Required tags per profile class (§8) |
| H111 | Reserved bytes | Header bytes 100-127 must be zero |
| H112 | White point validation | wtpt tag D50 consistency check |
| H113 | Round-trip fidelity | AToB/BToA transform accuracy |
| H114 | Curve smoothness | TRC curve monotonicity and smoothness — CVE-2026-21687 |
| H115 | Characterization data | Metadata tag validation |
| H116 | Copyright/desc encoding | String encoding consistency |
| H117 | Tag type allowed | Per-class tag type restrictions |
| H118 | Calculator cost estimate | MPE calculator complexity estimation |
| H119 | Round-trip deltaE | Color difference threshold |
| H120 | Curve invertibility | TRC curve invertibility check |

### Integrity Heuristics (H121–H138)
| ID | Check | Risk |
|----|-------|------|
| H121 | Characterization data round-trip | Data preservation through transforms |
| H122 | Tag encoding | UTF-8/ASCII encoding validation |
| H123 | Non-required tags | Unexpected tag presence |
| H124 | Version-specific tags | Tag presence vs version consistency |
| H125 | Transform smoothness | Smooth output across input range |
| H126 | Private tag malware | Entropy/size anomaly in private tags |
| H127 | Private tag registry | Known private tag signature matching |
| H128 | Version BCD encoding | Major.minor.bugfix BCD validation — CVE-2026-24403 |
| H129 | PCS illuminant D50 | s15Fixed16 D50 XYZ validation |
| H130 | Tag alignment | 4-byte alignment of tag offsets |
| H131 | Profile ID MD5 | Computed vs stored MD5 comparison |
| H132 | Chad determinant | Chromatic adaptation matrix conditioning |
| H133 | Flags reserved bits | Header flag reserved bit validation |
| H134 | Tag type reserved bytes | Type signature reserved field check |
| H135 | Duplicate tag signatures | Tag table uniqueness constraint |
| H136 | Response curve measurement count | CWE-400: excessive measurements |
| H137 | High dimensional grid complexity | CWE-400: nGran^ndim iteration |
| H138 | Calculator branching depth | CWE-674: recursive calculator ops — CVE-2026-24407 |

### TIFF Image Heuristics (H139–H141)
| ID | Check | Risk |
|----|-------|------|
| H139 | Strip geometry validation | StripByteCounts vs RowsPerStrip×Width bounds — CWE-122/CWE-190 |
| H140 | Dimension/sample validation | Width/Height/BPS/SPP range and overflow — CWE-400/CWE-131 |
| H141 | IFD offset bounds | TIFF IFD tag data offsets within file — CWE-125 |

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
