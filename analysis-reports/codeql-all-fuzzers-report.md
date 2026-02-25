# CodeQL Security Analysis — All Fuzzers Report

**Generated:** 2026-02-25 14:16:41 UTC
**Repository:** xsscx/research
**Total Fuzzers:** 19
**Categories:** 14 Core + 2 XML + 3 TIFF

## Fuzzer Inventory

| # | Fuzzer | Category | LOC | Dict | Corpus (SSD) | Corpus (RAM) | Binary (SSD) | Binary (RAM) |
|---|--------|----------|-----|------|-------------|-------------|-------------|-------------|
| 1 | `icc_apply_fuzzer` | Core | 105 | 378 | 122 | 669 | ✅ 17MB | ✅ |
| 2 | `icc_applynamedcmm_fuzzer` | Core | 266 | 35 | 105 | 255 | ✅ 17MB | ✅ |
| 3 | `icc_applyprofiles_fuzzer` | Core | 125 | 164 | 115 | 115 | ✅ 17MB | ✅ |
| 4 | `icc_calculator_fuzzer` | Core | 103 | 451 | 147 | 388 | ✅ 17MB | ✅ |
| 5 | `icc_deep_dump_fuzzer` | Core | 767 | 283 | 216 | 229 | ✅ 17MB | ✅ |
| 6 | `icc_dump_fuzzer` | Core | 130 | 952 | 254 | 262 | ✅ 17MB | ✅ |
| 7 | `icc_fromcube_fuzzer` | Core | 367 | 558 | 271 | 278 | ✅ 17MB | ✅ |
| 8 | `icc_io_fuzzer` | Core | 87 | 1902 | 107 | 293 | ✅ 17MB | ✅ |
| 9 | `icc_link_fuzzer` | Core | 91 | 276 | 109 | 1024 | ✅ 17MB | ✅ |
| 10 | `icc_multitag_fuzzer` | Core | 96 | 220 | 133 | 149 | ✅ 17MB | ✅ |
| 11 | `icc_profile_fuzzer` | Core | 118 | 232 | 147 | 158 | ✅ 17MB | ✅ |
| 12 | `icc_roundtrip_fuzzer` | Core | 146 | 506 | 149 | 235 | ✅ 17MB | ✅ |
| 13 | `icc_spectral_fuzzer` | Core | 140 | 158 | 155 | 363 | ✅ 17MB | ✅ |
| 14 | `icc_v5dspobs_fuzzer` | Core | 622 | 845 | 211 | 1663 | ✅ 17MB | ✅ |
| 15 | `icc_fromxml_fuzzer` | XML | 117 | 99 | 1397 | 1405 | ✅ 22MB | ✅ |
| 16 | `icc_toxml_fuzzer` | XML | 72 | 411 | 1251 | 1251 | ✅ 2MB | ✅ |
| 17 | `icc_specsep_fuzzer` | TIFF | 190 | 808 | 145 | 429 | ✅ 2MB | ✅ |
| 18 | `icc_spectral_b_fuzzer` | TIFF | 177 | 397 | 569 | 1889 | ✅ 2MB | ✅ |
| 19 | `icc_tiffdump_fuzzer` | TIFF | 167 | 999 | 136 | 139 | ✅ 17MB | ✅ |
| | **TOTALS** | | **3886** | | **5739** | **11194** | | |

## CodeQL Query Suite

### Custom Security Queries (17)

- **all-tools-enum-reachability.ql** (problem): Identifies enum UB issues reachable from ALL project tools
- **alloc-dealloc-mismatch.ql** (problem): Finds mismatched allocation/deallocation pairs (e.g., new[] with free(),
- **argv-output-path.ql** (problem): Detects file write operations using argv without path traversal validation
- **buffer-overflow.ql** (problem): Finds potential buffer overflow vulnerabilities in ICC profile parsing
- **enum-undefined-behavior.ql** (problem): Finds all locations where invalid values are loaded into enum types
- **iccanalyzer-security.ql** (problem): Finds potential security issues in IccAnalyzer tool
- **iccdumpprofile-enum-reachability.ql** (problem): Identifies enum undefined behavior issues reachable via IccDumpProfile tool
- **injection-attacks.ql** (problem): Detects injection vulnerabilities using taint tracking from user input
- **integer-overflow-allocation.ql** (problem): Finds integer overflows that could lead to heap corruption
- **integer-overflow-multiply.ql** (problem): Detects multiplication operations that may overflow
- **null-pointer-deref.ql** (problem): Finds pointer dereferences where the pointer may be null
- **type-confusion.ql** (problem): Finds type confusion vulnerabilities in virtual function calls
- **unchecked-io-return.ql** (problem): Finds calls to fread/fwrite/fopen where return value is not checked.
- **uninitialized-read.ql** (problem): Finds local variables that may be used before initialization,
- **use-after-free.ql** (problem): Finds potential use-after-free vulnerabilities using control flow analysis
- **xml-all-attacks.ql** (problem): Detects all XML-related security vulnerabilities including XXE, XPath injection,
- **xml-external-entity-attacks.ql** (problem): Detects XML External Entity (XXE) vulnerabilities, unsafe XML parsing,

### Built-in Query Packs
- `security-and-quality` — Official CodeQL security queries
- `security-experimental` — Experimental security detections
- `codeql/cpp-queries@latest` — Full C++ query pack
- `codeql/cpp-all@latest` — Extended C++ analysis

## Per-Fuzzer Security Analysis

### `icc_apply_fuzzer` (Core)

- **Source:** `cfl/icc_apply_fuzzer.cpp` (105 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccApplyCmm`, `CIccCmm`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Temp file handling, Max size limit, Profile validation
- **Key includes:** #include "IccCmm.h", #include "IccUtil.h"

### `icc_applynamedcmm_fuzzer` (Core)

- **Source:** `cfl/icc_applynamedcmm_fuzzer.cpp` (266 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccApplyBPCHint`, `CIccCmm`, `CIccCmmEnvVarHint`, `CIccCreateXformHintManager`, `CIccLuminanceMatchingHint`, `CIccNamedColorCmm`, `CIccProfile`, `OpenIccProfile`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Temp file handling, Max size limit, Profile validation, OpenIccProfile
- **Key includes:** #include "IccCmm.h", #include "IccUtil.h", #include "IccDefs.h", #include "IccApplyBPC.h", #include "IccEnvVar.h"

### `icc_applyprofiles_fuzzer` (Core)

- **Source:** `cfl/icc_applyprofiles_fuzzer.cpp` (125 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccCmm`, `CIccCreateXformHintManager`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Temp file handling, Max size limit, Profile validation
- **Key includes:** #include "IccCmm.h", #include "IccUtil.h", #include "IccDefs.h"

### `icc_calculator_fuzzer` (Core)

- **Source:** `cfl/icc_calculator_fuzzer.cpp` (103 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccMemIO`, `CIccProfile`, `CIccTag`, `CIccTagLutAtoB`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Max size limit, Profile validation, Attach/Detach IO
- **Key includes:** #include "IccProfile.h", #include "IccTag.h", #include "IccTagLut.h", #include "IccUtil.h", #include "IccMpeFactory.h"

### `icc_deep_dump_fuzzer` (Core)

- **Source:** `cfl/icc_deep_dump_fuzzer.cpp` (767 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccCLUT`, `CIccCalculatorFunc`, `CIccCurve`, `CIccInfo`, `CIccMBB`, `CIccMemIO`, `CIccMpeCalculator`, `CIccMpeTintArray`, `CIccMultiProcessElement`, `CIccProfile` (+15 more)
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Profile validation, Attach/Detach IO, OpenIccProfile
- **Key includes:** #include "IccProfile.h", #include "IccTag.h", #include "IccTagBasic.h", #include "IccTagLut.h", #include "IccTagMPE.h"

### `icc_dump_fuzzer` (Core)

- **Source:** `cfl/icc_dump_fuzzer.cpp` (130 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccInfo`, `CIccProfile`, `ValidateIccProfile`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Max size limit, Profile validation
- **Key includes:** #include "IccProfile.h", #include "IccTag.h", #include "IccTagLut.h", #include "IccUtil.h"

### `icc_fromcube_fuzzer` (Core)

- **Source:** `cfl/icc_fromcube_fuzzer.cpp` (367 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccCLUT`, `CIccMpeCLUT`, `CIccMpeCurveSet`, `CIccProfile`, `CIccSingleSampledCurve`, `CIccTagMultiLocalizedUnicode`, `CIccTagMultiProcessElement`, `SaveIccProfile`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Temp file handling, Max size limit, Attach/Detach IO
- **Key includes:** #include "IccProfile.h", #include "IccTagBasic.h", #include "IccTagMPE.h", #include "IccMpeBasic.h", #include "IccUtil.h"

### `icc_io_fuzzer` (Core)

- **Source:** `cfl/icc_io_fuzzer.cpp` (87 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccFileIO`, `CIccProfile`, `OpenIccProfile`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Temp file handling, Max size limit, Profile validation, OpenIccProfile
- **Key includes:** #include "IccProfile.h", #include "IccUtil.h", #include "IccIO.h"

### `icc_link_fuzzer` (Core)

- **Source:** `cfl/icc_link_fuzzer.cpp` (91 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccCmm`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Temp file handling, Max size limit
- **Key includes:** #include "IccCmm.h", #include "IccUtil.h"

### `icc_multitag_fuzzer` (Core)

- **Source:** `cfl/icc_multitag_fuzzer.cpp` (96 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccMemIO`, `CIccProfile`, `CIccTag`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Max size limit, Profile validation, Attach/Detach IO
- **Key includes:** #include "IccProfile.h", #include "IccTag.h", #include "IccUtil.h"

### `icc_profile_fuzzer` (Core)

- **Source:** `cfl/icc_profile_fuzzer.cpp` (118 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccMemIO`, `CIccProfile`, `CIccTag`, `OpenIccProfile`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Profile validation, OpenIccProfile
- **Key includes:** #include "IccProfile.h", #include "IccUtil.h", #include "IccIO.h", #include "IccTag.h", #include "IccTagLut.h"

### `icc_roundtrip_fuzzer` (Core)

- **Source:** `cfl/icc_roundtrip_fuzzer.cpp` (146 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccEvalCompare`, `CIccMinMaxEval`, `CIccPRMG`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Temp file handling, Max size limit
- **Key includes:** #include "IccEval.h", #include "IccPrmg.h", #include "IccUtil.h"

### `icc_spectral_fuzzer` (Core)

- **Source:** `cfl/icc_spectral_fuzzer.cpp` (140 LOC)
- **Entry points:** 1 (`LLVMFuzzerTestOneInput`)
- **ICC API surface:** `CIccMemIO`, `CIccProfile`, `CIccTag`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Profile validation, Attach/Detach IO
- **Key includes:** #include "IccProfile.h", #include "IccTag.h", #include "IccUtil.h"

### `icc_v5dspobs_fuzzer` (Core)

- **Source:** `cfl/icc_v5dspobs_fuzzer.cpp` (622 LOC)
- **Entry points:** 2 (`LLVMFuzzerTestOneInput` + `LLVMFuzzerInitialize`)
- **ICC API surface:** `CIccApplyTagMpe`, `CIccFileIO`, `CIccMemIO`, `CIccMultiProcessElement`, `CIccProfile`, `CIccTag`, `CIccTagArray`, `CIccTagCurve`, `CIccTagMultiLocalizedUnicode`, `CIccTagMultiProcessElement` (+4 more)
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Temp file handling, Profile validation, Attach/Detach IO
- **Key includes:** #include "IccProfile.h", #include "IccTag.h", #include "IccTagMPE.h", #include "IccTagLut.h", #include "IccMpeBasic.h"

### `icc_fromxml_fuzzer` (XML)

- **Source:** `cfl/icc_fromxml_fuzzer.cpp` (117 LOC)
- **Entry points:** 2 (`LLVMFuzzerTestOneInput` + `LLVMFuzzerInitialize`)
- **ICC API surface:** `CIccMpeCreator`, `CIccMpeXmlFactory`, `CIccProfileXml`, `CIccTagCreator`, `CIccTagXmlFactory`, `SaveIccProfile`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Temp file handling, Max size limit, Profile validation
- **Key includes:** #include "IccTagXmlFactory.h", #include "IccMpeXmlFactory.h", #include "IccProfileXml.h", #include "IccIO.h", #include "IccUtil.h"

### `icc_toxml_fuzzer` (XML)

- **Source:** `cfl/icc_toxml_fuzzer.cpp` (72 LOC)
- **Entry points:** 2 (`LLVMFuzzerTestOneInput` + `LLVMFuzzerInitialize`)
- **ICC API surface:** `CIccMemIO`, `CIccProfileXml`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Max size limit, Attach/Detach IO
- **Key includes:** #include "IccProfile.h", #include "IccTag.h", #include "IccUtil.h", #include "IccProfileXml.h", #include "IccUtilXml.h"

### `icc_specsep_fuzzer` (TIFF)

- **Source:** `cfl/icc_specsep_fuzzer.cpp` (190 LOC)
- **Entry points:** 2 (`LLVMFuzzerTestOneInput` + `LLVMFuzzerInitialize`)
- **ICC API surface:** `CTiffImg`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Temp file handling, Error handler, Max size limit
- **Key includes:** #include "IccProfile.h", #include "IccUtil.h", #include "TiffImg.h"

### `icc_spectral_b_fuzzer` (TIFF)

- **Source:** `cfl/icc_spectral_b_fuzzer.cpp` (177 LOC)
- **Entry points:** 2 (`LLVMFuzzerTestOneInput` + `LLVMFuzzerInitialize`)
- **ICC API surface:** `CTiffImg`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Temp file handling, Error handler, Max size limit
- **Key includes:** #include "IccProfile.h", #include "IccUtil.h", #include "TiffImg.h"

### `icc_tiffdump_fuzzer` (TIFF)

- **Source:** `cfl/icc_tiffdump_fuzzer.cpp` (167 LOC)
- **Entry points:** 2 (`LLVMFuzzerTestOneInput` + `LLVMFuzzerInitialize`)
- **ICC API surface:** `CIccInfo`, `CIccProfile`, `CIccTag`, `CIccTagEmbeddedProfile`, `CIccTagMultiLocalizedUnicode`, `CIccTagTextDescription`, `CTiffImg`, `OpenIccProfile`
- **Security patterns:** Size bounds check, Null check, Memory cleanup, Error handler, Max size limit, Profile validation, OpenIccProfile
- **Key includes:** #include "IccProfile.h", #include "IccTag.h", #include "IccUtil.h", #include "TiffImg.h"

## Analysis Configuration

### Paths Analyzed
```yaml
paths:
  - IccProfLib/**     # Core ICC library
  - IccXML/**         # XML serialization
  - cfl/*.cpp         # All fuzzer harnesses
```

### Build Categories for CodeQL
```
Core Fuzzers (14):  -I iccDEV/IccProfLib
XML Fuzzers  (2):   -I iccDEV/IccProfLib -I iccDEV/IccXML/IccLibXML -I/usr/include/libxml2
TIFF Fuzzers (3):  -I iccDEV/IccProfLib -I iccDEV/Tools/CmdLine/IccApplyProfiles + TiffImg.o
```

## CI/CD Integration

| Workflow | Fuzzers | Status |
|----------|---------|--------|
| `codeql-security-analysis.yml` | All 19 | Triggered |
| `cfl-libfuzzer-parallel.yml` | Matrix (18 active) | Active |
| `libfuzzer-smoke-test.yml` | All active | Active |
| `ci-comprehensive-build-test.yml` | All 19 | Active |
| `clusterfuzzlite.yml` | Matrix (18 active) | Active |

## A/B Test Status

| Fuzzer | Status | Notes |
|--------|--------|-------|
| `icc_spectral_fuzzer` (A) | ⏸️ Inactive | Kept in repo, removed from scripts/workflows (AST_LOG spam) |
| `icc_spectral_b_fuzzer` (B) | ✅ Active | IccSpecSepToTiff fidelity, TIFF category, 397 dict entries |

## Security Patches Applied: 32

- `001-clut-init-alloc-cap.patch`
- `002-sampled-curve-alloc-cap.patch`
- `003-gamut-boundary-alloc-cap.patch`
- `004-named-color2-alloc-cap.patch`
- `005-memdump-alloc-cap.patch`
- `006-ubsan-integer-overflow.patch`
- `007-tagdata-alloc-cap.patch`
- `008-calc-enum-read.patch`
- `009-unknown-tag-describe-oob.patch`
- `010-tagarray-copy-ctor-uninit.patch`
- `011-tagnum-setsize-alloc-cap.patch`
- `012-tagarray-alloc-dealloc-mismatch.patch`
- `013-channelfunc-enum-read.patch`
- `014-seqneedtempreset-infinite-loop.patch`
- `015-single-sampled-curve-alloc-cap.patch`
- `016-curve-apply-nan-guard.patch`
- `017-tagcurve-setsize-alloc-cap.patch`
- `018-spectralmatrix-setsize-alloc-cap.patch`
- `019-coloranttable-describe-strlen-oob.patch`
- `020-coloranttable-namedcolor-toxml-strlen-oob.patch`
- `021-spectralmatrix-describe-oob.patch`
- `022-xyzmatrix-sum-overflow.patch`
- `023-initselectop-oob-read.patch`
- `024-envvar-enum-load.patch`
- `025-triangles-signed-overflow.patch`
- `026-tagcurve-null-deref.patch`
- `027-getvalues-buffer-overflow.patch`
- `028-interpolate-buffer-overflow.patch`
- `029-interp-negative-clamp.patch`
- `030-sampled-curve-nan-cast.patch`
- `031-matrixmath-setrange-oob.patch`
- `032-applysequence-select-oob.patch`
