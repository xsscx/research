# ICC Binary Format — Security Research Quick Reference

> **Audience**: AI agents (Copilot, MCP, fuzzer pipelines) and human researchers
> working on ICC profile security analysis, fuzzer harness development, and
> heuristic authoring.
>
> **Sources**: ICC.1-2022-05, ICC.2-2019 (with September 2021 errata), ICC.2-2023,
> ICS Parts 1–3, iccanalyzer-lite source code, CFL fuzzer corpus,
> 93 iccDEV security advisories (87 CVEs + 95 GHSAs).
>
> **Last verified**: 2026-07-24 — 171 heuristics (H1–H171) + 279 conformance checks
> (CF-001..CF-316, with gaps), 601 tests, 45 CFL patches, 13 fuzzers.

---

## Table of Contents

1. [ICC Profile Header (128 bytes)](#1-icc-profile-header-128-bytes)
2. [Tag Table](#2-tag-table)
3. [Device Class Signatures](#3-device-class-signatures)
4. [Color Space Signatures](#4-color-space-signatures)
5. [Tag Signatures](#5-tag-signatures)
6. [Tag Type Signatures](#6-tag-type-signatures)
7. [Multi-Process Element (MPE) Internals](#7-multi-process-element-mpe-internals)
8. [Calculator Element Layout](#8-calculator-element-layout)
9. [mAB / mBA Tag Layout](#9-mab--mba-tag-layout)
10. [Data Type Encodings](#10-data-type-encodings)
11. [Image Container Formats (TIFF / PNG / JPEG)](#11-image-container-formats-tiff--png--jpeg)
12. [Security Patterns — CWE Catalog](#12-security-patterns--cwe-catalog)
13. [CFL Patch Catalog (45 Active)](#13-cfl-patch-catalog-45-active)
14. [Heuristic → Format Mapping](#14-heuristic--format-mapping)
14.5. [ICC Conformance Checks (CF-001..CF-316)](#145-icc-conformance-checks-cf-001cf-316)
14.6. [ICC.2:2019 Errata Coverage](#146-icc22019-errata-coverage)
14.7. [ICS Sub-Class Conformance (CF-308..CF-316)](#147-ics-sub-class-conformance-cf-308cf-316)
15. [Version History and BCD Encoding](#15-version-history-and-bcd-encoding)
16. [Profile ID (MD5) Computation](#16-profile-id-md5-computation)
17. [Useful Code Patterns](#17-useful-code-patterns)
18. [Specification References](#18-specification-references)

---

## 1. ICC Profile Header (128 bytes)

All multi-byte fields are **big-endian** (network byte order).

```
Offset  Size  Field                    ICC.1-2022-05 §   Validation (Heuristic)
──────  ────  ───────────────────────   ────────────────   ──────────────────────
0       4     Profile size (uint32)     §7.2.2             H1 — size vs file size
4       4     CMM type signature        §7.2.3             (info only)
8       4     Version (BCD encoded)     §7.2.4             H3 — valid BCD range
12      4     Device class signature    §7.2.5             H4 — valid class enum
16      4     Color space signature     §7.2.6             H5 — valid color space
20      4     PCS (XYZ or Lab)          §7.2.7             H5 — valid PCS
24      12    Date/time (6 × uint16)    §7.2.8             H7 — sane date range
36      4     Magic 'acsp' (0x61637370) §7.2.9             H2 — must be 'acsp'
40      4     Primary platform          §7.2.10            (info only)
44      4     Profile flags             §7.2.11            H111 — upper bits = 0
48      4     Device manufacturer       §7.2.12            (info only)
52      4     Device model              §7.2.13            (info only)
56      8     Device attributes         §7.2.14            (info only)
64      4     Rendering intent          §7.2.15            H6 — 0-3, upper 16 = 0
68      12    PCS illuminant (XYZ)      §7.2.16            H112 — D50 values
80      4     Profile creator           §7.2.17            (info only)
84      16    Profile ID (MD5)          §7.2.18            H131 — MD5 integrity
100     28    Reserved (must be 0x00)   §7.2.19            H111 — all zeros
```

### Key Constants

| Field | Expected Value | Hex |
|-------|---------------|-----|
| Magic | `'acsp'` | `0x61637370` |
| PCS illuminant X | 0.9642 (s15Fixed16) | `0x0000F6D6` |
| PCS illuminant Y | 1.0000 (s15Fixed16) | `0x00010000` |
| PCS illuminant Z | 0.8249 (s15Fixed16) | `0x0000D32D` |
| Rendering intent max | 3 (Absolute Colorimetric) | `0x00000003` |

### Size Validation Logic

```
file_size = stat(path).st_size
header_size = ReadU32BE(data, 0)   // big-endian uint32

if header_size > file_size:       → TRUNCATED (H1 CRITICAL) — do NOT load via library
if file_size > header_size + 3:   → APPENDED DATA (H1 WARN) — possible polyglot
if header_size < 132:             → TOO SMALL (minimum: 128-byte header + 4-byte tag count)
```

---

## 2. Tag Table

Starts immediately after the header at **offset 128**.

```
Offset 128:  Tag count (uint32)        — number of tag entries
Offset 132+: Tag entries, each 12 bytes:
  +0   4 bytes   Tag signature (FourCC)
  +4   4 bytes   Data offset (from profile start, must be ≥ 132)
  +8   4 bytes   Data size (bytes)
```

### Tag Table Validation Rules (H9–H32)

| Rule | Heuristic | CWE |
|------|-----------|-----|
| Tag count × 12 + 132 ≤ profile size | H9 | CWE-131 |
| No duplicate tag signatures | H25 | CWE-694 |
| offset + size ≤ profile size | H10 | CWE-125 |
| All offsets 4-byte aligned | H121 | CWE-20 |
| Shared offsets must have matching sizes | H13 | CWE-131 |
| No partial overlaps between tag data | H33 | CWE-119 |
| Type signature at tag offset matches expected | H32 | CWE-843 |

### Tag Data Structure

Every tag's data begins with a type signature:

```
Tag data offset + 0:  Type signature (4 bytes, e.g., 'XYZ ', 'text', 'desc')
Tag data offset + 4:  Reserved (4 bytes, should be 0)
Tag data offset + 8:  Type-specific payload
```

---

## 3. Device Class Signatures

ICC.1-2022-05 §7.2.5 defines 7 profile classes (4-byte FourCC):

| Class | Signature | Hex | Required Tags (beyond common) |
|-------|-----------|-----|-------------------------------|
| Input (Scanner) | `'scnr'` | `0x73636E72` | AToB0, grayTRC or RGB TRCs |
| Display (Monitor) | `'mntr'` | `0x6D6E7472` | AToB0/BToA0 or TRC+matrix |
| Output (Printer) | `'prtr'` | `0x70727472` | AToB0/BToA0, gamut |
| DeviceLink | `'link'` | `0x6C696E6B` | AToB0, profileSequenceDesc |
| ColorSpace | `'spac'` | `0x73706163` | AToB0/BToA0 |
| Abstract | `'abst'` | `0x61627374` | AToB0 |
| NamedColor | `'nmcl'` | `0x6E6D636C` | namedColor2 |

**All classes require**: `profileDescriptionTag`, `mediaWhitePointTag`, `copyrightTag`
**+ `chromaticAdaptationTag`** if adopted white ≠ D50.

**ICC.2-2023 (v5) adds**: `'cenc'` (Color Encoding), `'mid '` (Material ID), `'mvis'` (Multi-Visualization)

**ICS sub-classes** (ICC Interoperability Conformance Specifications):

| Sub-Class | Signature | Hex | Purpose |
|-----------|-----------|-----|---------|
| Profile Connection Conditions | `'pcc '` | `0x70636320` | Colorimetric PCC (Part 1/2/3) |
| Extended Range | `'xrng'` | `0x78726E67` | Extended gamut (Part 1/2/3) |
| Spectral Reference | `'sref'` | `0x73726566` | Spectral reflectance (Part 1/2/3) |
| Extended Output | `'ext '` | `0x65787420` | Extended output modeling (Part 1/2/3) |

---

## 4. Color Space Signatures

ICC.1-2022-05 §7.2.6 — 4-byte FourCC at header offset 16 (data color space) and 20 (PCS).

| Color Space | Signature | Channels | Notes |
|-------------|-----------|----------|-------|
| XYZ | `'XYZ '` | 3 | PCS only |
| Lab | `'Lab '` | 3 | PCS only |
| RGB | `'RGB '` | 3 | Most common device space |
| CMYK | `'CMYK'` | 4 | Printer profiles |
| Gray | `'GRAY'` | 1 | Monochrome |
| HSV | `'HSV '` | 3 | Rare |
| HLS | `'HLS '` | 3 | Rare |
| YCbCr | `'YCbr'` | 3 | Video |
| 2-color | `'2CLR'` | 2 | Multi-channel |
| 3-color | `'3CLR'` | 3 | Multi-channel |
| ... | ... | ... | ... |
| 15-color | `'FCLR'` | 15 | Max standard channels |

**ICC.2-2023 (v5) spectral PCS signatures**:

| PCS | Hex Prefix | Meaning |
|-----|------------|---------|
| Reflectance | `0x72730000` | `'rs\0\0'` — Reflectance spectral data |
| Transmission | `0x74730000` | `'ts\0\0'` — Transmission spectral data |
| Emission | `0x65730000` | `'es\0\0'` — Emission spectral data |
| Bi-Spectral Reflectance | `0x62730000` | `'bs\0\0'` — Bi-spectral reflectance |

Lower 16 bits encode the number of spectral channels.

**Security note**: `icGetSpaceSamples()` returns the declared channel count, but
malformed LUTs can have `m_nOutput > declared`. Always use `tmpPixel[16]` sized buffers.

---

## 5. Tag Signatures

Common tags validated by iccanalyzer-lite heuristics:

### Required Tags

| Tag | Signature | Purpose |
|-----|-----------|---------|
| profileDescriptionTag | `'desc'` | Human-readable profile name |
| mediaWhitePointTag | `'wtpt'` | Adapted white point XYZ |
| copyrightTag | `'cprt'` | Copyright string |
| chromaticAdaptationTag | `'chad'` | 3×3 adaptation matrix (v4 req if ≠D50) |

### Transform Tags (AToB / BToA / DToB / BToD)

```
AToB0  'A2B0'    Device → PCS, perceptual intent       (ICC.1 §9.2.1)
AToB1  'A2B1'    Device → PCS, relative colorimetric  (ICC.1 §9.2.2)
AToB2  'A2B2'    Device → PCS, saturation              (ICC.1 §9.2.3)
AToB3  'A2B3'    Device → PCS, absolute colorimetric   (ICC.2 v5+ ONLY — NOT in ICC.1-2022-05)
BToA0  'B2A0'    PCS → Device, perceptual              (ICC.1 §9.2.4)
BToA1  'B2A1'    PCS → Device, relative                (ICC.1 §9.2.5)
BToA2  'B2A2'    PCS → Device, saturation              (ICC.1 §9.2.6)
BToA3  'B2A3'    PCS → Device, absolute                (ICC.2 v5+ ONLY — NOT in ICC.1-2022-05)
DToB0  'D2B0'    Device → PCS, spectral                (ICC.1 §9.2.51, v4.0+)
DToB1  'D2B1'    ...                                    (ICC.1 §9.2.52)
BToD0  'B2D0'    PCS → Device, spectral                (ICC.1 §9.2.7)
BToD1  'B2D1'    ...                                    (ICC.1 §9.2.8)
```

### Other Important Tags

| Tag | Signature | Heuristic | Notes |
|-----|-----------|-----------|-------|
| namedColor2Tag | `'ncl2'` | H148 | deviceCoords ≤ 15 |
| gamutTag | `'gamt'` | H103+ | Required for prtr class |
| colorantTableTag | `'clrt'` | H144 | String termination check |
| responseCurveSet16Tag | `'rcs2'` | H136 | Measurement count DoS |
| metaDataTag | `'meta'` | — | Dictionary type |
| spectralDataInfoTag | `'sdin'` | H15 | v5 spectral |
| spectralViewingConditionsTag | `'svcn'` | CF-316 | v5 viewing conditions |
| embeddedV5ProfileTag | `'ICCe'` | H147 | Nested profile |

### v5-Only Tags (ICC.2-2023)

| Tag | Signature | Hex | Purpose |
|-----|-----------|-----|---------|
| customToStandardPccTag | `'c2sp'` | `0x63327370` | PCC custom→standard matrix |
| standardToCustomPccTag | `'s2cp'` | `0x73326370` | PCC standard→custom matrix |
| surfaceMapTag | `'smap'` | `0x736D6170` | Surface reflectance map |
| multiplexDefaultValuesTag | `'mdv '` | `0x6D647620` | Multiplex device defaults |
| multiplexTypeArrayTag | `'mcta'` | `0x6D637461` | Multiplex type array |
| AToM0Tag | `'A2M0'` | `0x41324D30` | Device → Multiplex transform |
| MToB0–MToB3 | `'M2B0'`..`'M2B3'` | `0x4D324230`–`33` | Multiplex → PCS |
| MToS0–MToS3 | `'M2S0'`..`'M2S3'` | `0x4D325330`–`33` | Multiplex → Spectral PCS |
| gamutBoundaryDescription0–3Tag | `'gbd0'`..`'gbd3'` | `0x67626430`–`33` | GBD per intent |
| BRDFAToB0–3Tag | `'bAB0'`..`'bAB3'` | `0x62414230`–`33` | BRDF colorimetric A→B |
| BRDFDToB0–3Tag | `'bDB0'`..`'bDB3'` | `0x62444230`–`33` | BRDF device D→B |
| BRDFMToB0–3Tag | `'bMB0'`..`'bMB3'` | `0x624D4230`–`33` | BRDF multiplex M→B |
| BRDFMToS0–3Tag | `'bMS0'`..`'bMS3'` | `0x624D5330`–`33` | BRDF multiplex M→S |

---

## 6. Tag Type Signatures

The type signature at `tag_offset + 0` determines how payload data is parsed.

| Type | Signature | Hex | Security Notes |
|------|-----------|-----|----------------|
| signatureType | `'sig '` | `0x73696720` | 4-byte enum value |
| textType | `'text'` | `0x74657874` | Null-terminated string |
| textDescriptionType | `'desc'` | `0x64657363` | v2 description (H147: NPD) |
| multiLocalizedUnicodeType | `'mluc'` | `0x6D6C7563` | v4 unicode strings |
| XYZType | `'XYZ '` | `0x58595A20` | 3 × s15Fixed16 per element (H146: SBO) |
| curveType | `'curv'` | `0x63757276` | 0/1/N entries (gamma or table) |
| parametricCurveType | `'para'` | `0x70617261` | Parametric function (7 types) |
| lutAtoBType | `'mAB '` | `0x6D414220` | Multi-dimensional transform |
| lutBtoAType | `'mBA '` | `0x6D424120` | Inverse transform |
| lut8Type | `'mft1'` | `0x6D667431` | Legacy 8-bit LUT |
| lut16Type | `'mft2'` | `0x6D667432` | Legacy 16-bit LUT |
| multiProcessElementType | `'mpet'` | `0x6D706574` | MPE chain (v4.4/v5) |
| namedColor2Type | `'ncl2'` | `0x6E636C32` | Named color palette |
| s15Fixed16ArrayType | `'sf32'` | `0x73663332` | Fixed-point array (H146) |
| u16Fixed16ArrayType | `'uf32'` | `0x75663332` | Unsigned fixed array (H146) |
| colorantTableType | `'clrt'` | `0x636C7274` | Colorant names + XYZ (H144) |
| colorantOrderType | `'clro'` | `0x636C726F` | Channel ordering |
| chromaticityType | `'chrm'` | `0x6368726D` | Phosphor chromaticities |
| measurementType | `'meas'` | `0x6D656173` | Measurement conditions |
| responseCurveSet16Type | `'rcs2'` | `0x72637332` | Response curves (H136: DoS) |
| dateTimeType | `'dtim'` | `0x6474696D` | Date/time (12 bytes) |
| viewingConditionsType | `'view'` | `0x76696577` | Viewing environment |
| float16ArrayType | `'fl16'` | `0x666C3136` | v5 half-float array |
| float32ArrayType | `'fl32'` | `0x666C3332` | v5 single-float array |
| float64ArrayType | `'fl64'` | `0x666C3634` | v5 double-float array |
| gamutBoundaryDescType | `'gbd '` | `0x67626420` | v5 gamut boundary (CF-140, CF-286) |
| sparseMatrixArrayType | `'smAt'` | `0x736D6174` | v5 sparse matrix (CF-141) |
| tagStructType | `'tstr'` | `0x74737472` | v5 struct container |
| tagArrayType | `'tary'` | `0x74617279` | v5 array container (CFL-003, CFL-007) |
| embeddedHeightImageType | `'ehim'` | `0x6568696D` | v5 height map (CF-138) |
| embeddedNormalImageType | `'enim'` | `0x656E696D` | v5 normal map (CF-139) |
| uInt8ArrayType | `'ui08'` | `0x75693038` | v5 uint8 array |
| uInt16ArrayType | `'ui16'` | `0x75693136` | v5 uint16 array |
| utf16TextType | `'ut16'` | `0x75743136` | v5 UTF-16 text (H147: null check) |
| dictType | `'dict'` | `0x64696374` | v5 dictionary (H169) |

---

## 7. Multi-Process Element (MPE) Internals

**Type signature**: `'mpet'` (0x6D706574) — ICC.1-2022-05 §10.18

MPE tags contain a chain of processing elements applied sequentially.

```
MPE Header:
  +0    4   Type signature ('mpet')
  +4    4   Reserved (0x00000000)
  +8    2   Number of input channels
  +10   2   Number of output channels
  +12   4   Number of processing elements (nElements)
  +16   nElements × 8 bytes: position table
        Each entry: offset(4) + size(4) relative to tag data start

Processing Element (at each offset):
  +0    4   Element type signature
  +4    4   Reserved
  +8    2   Element input channels
  +10   2   Element output channels
  +12   ... Element-specific data
```

### MPE Element Type Signatures

| Element | Signature | Hex | Security Notes |
|---------|-----------|-----|----------------|
| Curve Set | `'cvst'` | `0x63767374` | H145: type consistency |
| Matrix | `'matf'` | `0x6D617466` | H84: matrix bounds |
| CLUT | `'clut'` | `0x636C7574` | H11/H63: grid overflow |
| Extended CLUT | `'xclt'` | `0x78636C74` | v5: extended precision CLUT |
| Calculator | `'calc'` | `0x63616C63` | H56/H81/H138: Turing-complete, DoS |
| Curve Set Factory | `'curf'` | `0x63757266` | Curve construction |
| SingleSampledCurve | `'sngf'` | `0x736E6766` | H152/H153: OOM, NaN cast |
| SampledCalculatorCurve | `'clcf'` | `0x636C6366` | H153: NaN-to-unsigned |
| BAcs | `'bACS'` | `0x62414353` | Begin ACS placeholder |
| EAcs | `'eACS'` | `0x65414353` | End ACS placeholder |
| XYZ to Jab | `'XtoJ'` | `0x58746F4A` | v5: CAM02 forward |
| Jab to XYZ | `'JtoX'` | `0x4A746F58` | v5: CAM02 inverse |
| Tint Array | `'tint'` | `0x74696E74` | v5: tint transform |
| Tone Map | `'tmap'` | `0x746D6170` | v5: tone mapping (CFL-004) |
| Sparse Matrix | `'smet'` | `0x736D6574` | v5: sparse matrix element |
| Emission Matrix | `'emtx'` | `0x656D7478` | v5: spectral emission |
| Inv Emission Matrix | `'iemx'` | `0x69656D78` | v5: inverse emission |
| Emission CLUT | `'eclt'` | `0x65636C74` | v5: emission CLUT |
| Reflectance CLUT | `'rclt'` | `0x72636C74` | v5: reflectance CLUT |
| Emission Observer | `'eobs'` | `0x656F6273` | v5: spectral observer |
| Reflectance Observer | `'robs'` | `0x726F6273` | v5: spectral observer |

### MPE Chain Depth Risk (CWE-674)

Calculator elements can reference sub-elements which themselves contain calculators,
enabling unbounded recursion. Heuristic H138 estimates chain depth; CFL-014 limits
recursion depth in SequenceNeedTempReset. CFL-010 (CheckUnderflowOverflow recursion
budget) was retired after upstream acceptance (PR #684).

---

## 8. Calculator Element Layout

**Type signature**: `'calc'` (0x63616C63) — ICC.2-2023 §10.3.6

The calculator is **Turing-complete** — the single most dangerous ICC element type.

```
calc header:
  +0    4   Signature ('calc')
  +4    4   Reserved
  +8    2   nInput channels
  +10   2   nOutput channels
  +12   4   nSubElements

  Position table: (nSubElements + 1) × 8 bytes
    pos[0] = channel function (func)
    pos[1..n] = sub-elements (curves, CLUTs, matrices)

Channel Function (func) layout:
  +0    4   Signature ('func' = 0x66756E63)
  +4    4   Reserved
  +8    4   nOps (number of operations)
  +12   nOps × 8 bytes: operation entries
    Each: opcode_sig(4) + operand_data(4)
```

### Calculator Operator Opcodes (90 valid)

All opcodes are **printable ASCII FourCC** (each byte 0x20–0x7E):

| Category | Opcodes |
|----------|---------|
| Stack I/O | `'in  '`, `'out '`, `'data'` |
| Arithmetic | `'add '`, `'sub '`, `'mul '`, `'div '`, `'mod '`, `'neg '` |
| Math | `'pow '`, `'sqrt'`, `'abs '`, `'flor'`, `'ceil'`, `'rond'` |
| Trig | `'sin '`, `'cos '`, `'atan'`, `'exp '`, `'log '`, `'ln  '` |
| Comparison | `'min '`, `'max '`, `'lt  '`, `'le  '`, `'eq  '`, `'ne  '`, `'gt  '`, `'ge  '` |
| Logic | `'not '`, `'and '`, `'or  '`, `'vor '` |
| Branching | `'if  '`, `'else'`, `'sel '`, `'case'` |
| Temp vars | `'tget'`, `'tput'`, `'tsav'`, `'tlab'` |
| Sub-element | `'curv'`, `'clut'`, `'mtx '`, `'calc'`, `'elem'` |
| Environment | `'env '`, `'copy'`, `'rotl'`, `'rotr'`, `'pop '`, `'posd'` |
| Conversion | `'fJab'`, `'tJab'`, `'tXYZ'`, `'fXYZ'`, `'tLab'`, `'fLab'` |
| Clipping | `'clip'`, `'clpv'` |
| Spectral | `'solv'`, `'tran'` |

**Note**: `'vor '` (vector-or) was corrected from `'vor\0'` by the ICC.2:2019 September 2021
errata, Item 7 — trailing space replaces null byte. CF-142 and CF-307 audit this.

**Security implications**:
- `'if  '`/`'else'`/`'sel '`/`'case'` enable exponential path exploration (CWE-400)
- `'calc'` enables recursive sub-element invocation (CWE-674)
- Invalid enum values at `icChannelFuncSignature` and `m_Op[i].sig` trigger UBSAN (CFL-005/009)

---

## 9. mAB / mBA Tag Layout

**Type signatures**: `'mAB '` (0x6D414220) / `'mBA '` (0x6D424120) — ICC.1-2022-05 §10.12/§10.13

```
mAB/mBA Tag Data:
  +0    4   Type signature
  +4    4   Reserved
  +8    1   Number of input channels
  +9    1   Number of output channels
  +10   2   Reserved (padding)
  +12   4   Offset to B curves (0 = not present)
  +16   4   Offset to Matrix (0 = not present)
  +20   4   Offset to M curves (0 = not present)
  +24   4   Offset to CLUT (0 = not present)
  +28   4   Offset to A curves (0 = not present)

Processing order:
  mAB (AToB): A curves → CLUT → M curves → Matrix → B curves
  mBA (BToA): B curves → Matrix → M curves → CLUT → A curves
```

### Sub-element Offset Validation (H33–H55)

```
Each sub-element offset must satisfy:
  offset > 0 (0 = element not present)
  offset ≥ 32 (minimum header size)
  offset + element_size ≤ tag_size
  offset must be 4-byte aligned
  No integer overflow: offset + addend must not wrap uint32
```

**Critical bug pattern**: `offset = 0xFFFFFFFF`, `addend = 0x14` → wraps to `0x13`,
passes `< tag_size` check but accesses invalid memory.

---

## 10. Data Type Encodings

### s15Fixed16Number (Signed 15.16 Fixed-Point)

```
32-bit signed integer:
  Upper 16 bits = integer part (signed)
  Lower 16 bits = fractional part (unsigned)
  Value = raw_int32 / 65536.0
  Range: approximately -32768.0 to +32767.999985

Used in: XYZ values, matrix elements, chad tag
Example: 0.9642 (D50 X) = 0x0000F6D6 = 63190 / 65536 ≈ 0.96420
```

### u16Fixed16Number (Unsigned 16.16 Fixed-Point)

```
32-bit unsigned integer:
  Upper 16 bits = integer part
  Lower 16 bits = fractional part
  Value = raw_uint32 / 65536.0
  Range: 0.0 to 65535.999985
```

### u8Fixed8Number

```
16-bit unsigned: integer(8) + fraction(8)
Value = raw_uint16 / 256.0
Used in: curve entry values in lut8Type
```

### dateTimeNumber (12 bytes)

```
6 × uint16 (big-endian):
  Year (full 4-digit), Month (1-12), Day (1-31),
  Hour (0-23), Minute (0-59), Second (0-59)
```

### XYZ Number (12 bytes per triplet)

```
3 × s15Fixed16Number:
  X (4 bytes) + Y (4 bytes) + Z (4 bytes)
Validation: typical range [-5.0, 10.0] per component
H146: GetSize() > 16 elements → stack buffer overflow risk
```

### Version BCD Encoding

```
Byte 8:  Major version (e.g., 0x04 = v4)
Byte 9:  Minor.bugfix (nibbles: 0x40 = minor 4, bugfix 0)
Bytes 10-11: Reserved (must be 0x0000)

Examples:
  v2.0.0  = 0x02000000
  v2.1.0  = 0x02100000
  v2.4.0  = 0x02400000
  v4.0.0  = 0x04000000
  v4.3.0  = 0x04300000
  v4.4.0  = 0x04400000
  v5.0.0  = 0x05000000
  v5.1.0  = 0x05100000
```

---

## 11. Image Container Formats (TIFF / PNG / JPEG)

iccanalyzer-lite auto-detects image files via magic bytes and extracts embedded ICC profiles.

### Format Detection (Magic Bytes)

| Format | Magic Bytes | Hex | Detection Offset |
|--------|-------------|-----|-----------------|
| TIFF Little-Endian | `II*\0` | `49 49 2A 00` | 0 |
| TIFF Big-Endian | `MM\0*` | `4D 4D 00 2A` | 0 |
| BigTIFF Little-Endian | `II+\0` | `49 49 2B 00` | 0 |
| BigTIFF Big-Endian | `MM\0+` | `4D 4D 00 2B` | 0 |
| PNG | `\x89PNG\r\n\x1A\n` | `89 50 4E 47 0D 0A 1A 0A` | 0 |
| JPEG | `\xFF\xD8\xFF` | `FF D8 FF` | 0 |
| ICC Profile | `acsp` | `61 63 73 70` | **36** (not 0!) |

### TIFF ICC Extraction

ICC profiles are stored in **TIFFTAG_ICCPROFILE** (tag number **34675**, `0x8773`).

```
TIFF IFD entry for ICC profile:
  Tag ID:   34675 (0x8773)
  Type:     7 (UNDEFINED — raw bytes)
  Count:    N (profile size in bytes)
  Value:    Offset to ICC profile data (if N > 4)
```

### TIFF Security Heuristics

| Heuristic | Check | CWE |
|-----------|-------|-----|
| H139 | Strip geometry: `StripByteCounts ≥ RowsPerStrip × Width × SPP × (BPS/8)` | CWE-122/CWE-190 |
| H140 | Dimensions ≤ 65535, BPS ∈ {1,8,16,32}, SPP ≤ 6 | CWE-400/CWE-131 |
| H141 | IFD tag data offsets within file bounds | CWE-125 |
| H149 | IFD chain cycle detection (visited offset set) | CWE-835 |
| H150 | Tile geometry: TileWidth/TileLength multiples of 16 | CWE-122/CWE-131 |

### PNG ICC Extraction

ICC profiles are stored in the **iCCP chunk**:

```
iCCP chunk:
  Profile name (1-79 bytes, null-terminated)
  Compression method (1 byte, must be 0 = zlib)
  Compressed ICC profile data (zlib deflate)

Extraction: png_get_iCCP() → inflate → temp file → 171-heuristic analysis
```

### JPEG ICC Extraction

ICC profiles are stored in **APP2 markers** with the `ICC_PROFILE\0` identifier:

```
APP2 Marker:
  0xFF 0xE2 (marker)
  Length (uint16, big-endian)
  "ICC_PROFILE\0" (12 bytes identifier)
  Sequence number (1 byte, 1-based)
  Total chunks (1 byte)
  ICC profile data chunk

Multi-segment reassembly:
  Profiles > 64KB are split across multiple APP2 segments.
  Reassemble in sequence order, validate total count consistency.
```

---

## 12. Security Patterns — CWE Catalog

44 distinct CWE categories across 171 heuristics + 279 conformance checks + 45 CFL patches:

| CWE | Name | Sources | Key References |
|-----|------|---------|----------------|
| CWE-20 | Improper Input Validation | H2–H7, H111, H121, CFL-032/042 | ~37 heuristics, conformance checks |
| CWE-119 | Buffer Access | H33, H148, H162 | Tag data overlap detection |
| CWE-121 | Stack Buffer Overflow | H146, H161 | GetValues SBO, deep Apply chains |
| CWE-122 | Heap Buffer Overflow | H139, H150, CFL-001/004/006/035/048 | Strip geometry, ToneMap, GBD |
| CWE-125 | Out-of-bounds Read | H10, H141, H143, H165, H171, CFL-040/041/049–051 | IFD bounds, LUT sufficiency |
| CWE-126 | Buffer Over-read | H144 | String termination |
| CWE-131 | Incorrect Buffer Size | H9, H63, H78, H84, H140, H164 | LUT channel cross-check |
| CWE-134 | Format String Injection | H160, CFL-053/054 | `%n`/`%s` in text tags |
| CWE-170 | Improper Null Termination | H144, CFL-001 | Colorant/NamedColor names |
| CWE-190 | Integer Overflow | H11, H33, H34, H139, H155, H168, CFL-002/007/031 | Dimension multiplication |
| CWE-191 | Integer Underflow | H34 | Tag size arithmetic |
| CWE-252 | Unchecked Return Value | H156, CFL-031 | Allocation failure, ftell |
| CWE-345 | Insufficient Verification | H131, H112, CFL-033/034/036–039 | JSON field integrity |
| CWE-369 | Divide By Zero | H166 | CAM/Array/MPE zero divisors |
| CWE-400 | Resource Exhaustion | H136–H138, H142, H143, H152 | Uncapped iteration, OOM |
| CWE-416 | Use After Free | H159, CFL-003 | Tag ownership chains |
| CWE-476 | NULL Pointer Dereference | H147, H167, CFL-019/025/044/045/047/056 | Null PCS/PCC/CLUT guards |
| CWE-506 | Embedded Malicious Code | H35, H163 | ELF/PE/MachO in tag data |
| CWE-561 | Dead Code | CFL-039 | jsonExistsField on fresh JSON |
| CWE-674 | Uncontrolled Recursion | H56, H138, CFL-014 | Calculator/MPE chain depth |
| CWE-681 | Incorrect Type Conversion | H151, H153, H158, CFL-005/008/009/017/022/023/028/032/055 | Enum range, NaN cast |
| CWE-682 | Incorrect Calculation | H112 | D50 illuminant precision |
| CWE-694 | Use of Non-unique Identifier | H25 | Duplicate tag signatures |
| CWE-697 | Incorrect Comparison | CFL-043 | is_object vs is_array |
| CWE-762 | Alloc-Dealloc Mismatch | H157, CFL-003/046 | new[] vs free(), delete vs delete[] |
| CWE-787 | Out-of-bounds Write | H142, CFL-040 | XML serialization, fromIt8 |
| CWE-789 | Uncontrolled Memory Allocation | H154, H168, H169 | File-controlled tag sizes |
| CWE-824 | Access to Uninitialized Pointer | CFL-029 | TagArray loop variable |
| CWE-835 | Loop w/o Exit Condition | H149 | IFD chain cycles |
| CWE-843 | Type Confusion | H32, H145, H170, CFL-033 | Wrong tag cast, PCS null |
| CWE-908 | Uninitialized Resource | CFL-057 | SearchApply constructor |

---

## 13. CFL Patch Catalog (45 Active)

Active patches in `cfl/patches/` targeting verified upstream iccDEV bugs.
Patches numbered CFL-001 through CFL-057, with 12 gaps (003/010/011/012/013/015/016/018/020/024/026/027)
retired after upstream acceptance.

| # | Patch | Bug | CWE | File |
|---|-------|-----|-----|------|
| 001 | icAnsiToUtf8 null termination | HBO via strlen on unterminated 32-byte name | CWE-125/170 | IccTagBasic.cpp, IccUtilXml.cpp |
| 002 | GamutBoundary triangles overflow | Signed int overflow: m_NumberOfTriangles×3 | CWE-190 | IccTagLut.cpp |
| 004 | ToneMapFunc Read parameter count | HBO via Describe() accessing m_params[0..2] with 1 allocated | CWE-122 | IccMpeBasic.cpp |
| 005 | CalculatorFunc Read enum UBSAN | Enum out-of-range in calculator op read | CWE-681 | IccMpeCalc.cpp |
| 006 | SpectralMatrix Describe bounds | HBO via Describe() iterating m_nOutputChannels rows | CWE-122 | IccMpeSpectral.cpp |
| 007 | TagArray Read overflow guard | Integer overflow in TagArray element count | CWE-190 | IccTagComposite.cpp |
| 008 | TagCurve Apply NaN-to-unsigned | NaN bypasses [0,1] clamp, cast to unsigned = UB | CWE-681 | IccTagLut.cpp |
| 009 | EnvVar Exec enum UBSAN | Enum out-of-range in CIccOpDefEnvVar::Exec() | CWE-681 | IccMpeCalc.cpp |
| 014 | SequenceNeedTempReset recursion | Unbounded recursion depth in sequence reset | CWE-674 | IccMpeCalc.cpp |
| 017 | EnvVar GetEnvSig parse enum | Enum parse UB in env variable signature | CWE-681 | IccMpeCalc.cpp, IccMpeCalc.h |
| 019 | PCC getReflectanceObserver null | NULL deref: spectral viewing conditions | CWE-476 | IccPcc.cpp |
| 021 | SingleSampledCurve OOM size | Oversized m_nCount allocation | CWE-400 | IccMpeBasic.cpp |
| 022 | Calc Trunc/Floor/Ceil/Round/Mod | Large float-to-int cast in 5 calculator ops | CWE-681 | IccMpeCalc.cpp |
| 023 | Sampled curve NaN-to-unsigned | 3 Apply() NaN-to-unsigned casts | CWE-681 | IccMpeBasic.cpp |
| 025 | CLUT InterpNd null Apply guard | NULL CIccApplyCLUT deref in InterpNd path | CWE-476 | IccTagLut.cpp |
| 028 | MatrixMath SetRange NaN guard | NaN-to-unsigned-short in SetRange() | CWE-681 | IccMatrixMath.cpp |
| 029 | TagArray operator= loop var | Loop variable modified inside body | CWE-824 | IccTagComposite.cpp |
| 030 | FixedNum GetValues SBO | GetValues loop uses m_nSize instead of nVectorSize | CWE-121 | IccTagBasic.cpp |
| 031 | loadJsonFrom ftell overflow | ftell() unchecked return on non-seekable fd | CWE-190/252 | IccJsonUtil.cpp |
| 032 | icXformInterp enum range | Unchecked atoi() → enum out-of-range UBSAN | CWE-20/681 | IccCmmConfig.cpp, iccApplyToLink.cpp |
| 033 | PccWeight fromJson field swap | pccFile↔weight members swapped in fromJson | CWE-843 | IccCmmConfig.cpp |
| 034 | SearchApply fromJsonInit interp | Reads j["transform"] instead of j["interpolation"] | CWE-345 | IccCmmConfig.cpp |
| 035 | ApplyCmmSearch m_nApply OOB | HBO via unclamped m_nApply index into m_dst_to_mid | CWE-122 | IccCmmSearch.cpp |
| 036 | CreateLink toJson linkGridSize | toJson never writes m_linkGridSize — data loss | CWE-345 | IccCmmConfig.cpp |
| 037 | Profile toJson missing transform | toJson never writes m_transform + interpolation guard | CWE-345 | IccCmmConfig.cpp |
| 038 | SearchApply toJsonInit transform | toJsonInit never writes m_transformInitial | CWE-345 | IccCmmConfig.cpp |
| 039 | SearchApply toJson dead guards | jsonExistsField on fresh empty json → nothing written | CWE-561 | IccCmmConfig.cpp |
| 040 | fromIt8 CMYK missing push_back | CMYK branch missing samples.push_back(val) | CWE-787/125 | IccCmmConfig.cpp |
| 041 | fromIt8 LAB/XYZ val(4) OOB | val(4) should be val(3) for 3-channel LAB/XYZ | CWE-125 | IccCmmConfig.cpp |
| 042 | ParseNumbers 'n' vs '\\n' typo | Skip-number loop uses 'n' instead of newline | CWE-20 | IccCmmConfig.cpp |
| 043 | Tool toJson is_object vs is_array | seq.is_object() fails on array from toJson | CWE-697 | iccApplyNamedCmm.cpp, iccApplySearch.cpp |
| 044 | NDLut Apply missing interp dispatch | Missing interpolation method dispatch in NDLut | CWE-476 | IccCmm.cpp |
| 045 | AddXform null PCS guard | NULL PCS pointer dereference in AddXform | CWE-476 | IccCmm.cpp |
| 046 | PCS step src matrix delete[] | delete vs delete[] mismatch on matrix array | CWE-762 | IccCmm.cpp |
| 047 | pushXYZNormalize null PCC guard | NULL PCC pointer dereference | CWE-476 | IccCmm.cpp |
| 048 | DumpLut iterate missing bufsize | Missing buffer size in DumpLut iteration | CWE-122 | IccTagLut.cpp |
| 049 | MBB Describe BToA missing legacy | Missing bUseLegacy check in MBB Describe BToA | CWE-125 | IccTagLut.cpp |
| 050 | FormulaCurve Describe param bounds | OOB read in FormulaCurve Describe parameter access | CWE-125 | IccMpeBasic.cpp |
| 051 | ParametricCurve Describe param | OOB read in ParametricCurve Describe | CWE-125 | IccTagLut.cpp |
| 052 | fromIt8 wrong index variable | Wrong loop index variable in fromIt8 | CWE-125 | IccCmmConfig.cpp |
| 053 | FormulaCurve Describe format | Wrong printf format specifiers | CWE-134 | IccMpeBasic.cpp |
| 054 | ParametricCurve Describe format | Wrong printf format specifiers | CWE-134 | IccTagLut.cpp |
| 055 | fromIt8 signed-unsigned mismatch | Signed/unsigned comparison in fromIt8 loop | CWE-681 | IccCmmConfig.cpp |
| 056 | Spectral Describe null guards | NULL pointer dereference in spectral Describe | CWE-476 | IccMpeSpectral.cpp |
| 057 | SearchApply uninitialized members | Uninitialized member variables in constructor | CWE-908 | IccCmmConfig.cpp |

**Retired patches** (accepted upstream in PRs #680–#695):
003, 010, 011, 012, 013, 015, 016, 018, 020, 024, 026, 027 — 12 patches, 71 total in `cfl/patches-retired/`.

**Next patch**: CFL-058.

---

## 14. Heuristic → Format Mapping

Which ICC binary format fields each heuristic group validates:

| Heuristic Range | Module | Format Region |
|-----------------|--------|---------------|
| H1–H8, H15–H17 | IccHeuristicsHeader.cpp | Header bytes 0–127 (raw byte access) |
| H9–H32 | IccHeuristicsTagValidation.cpp | Tag table at offset 128+ (CIccProfile API) |
| H33–H55, H57–H69, H153 | IccHeuristicsRawPost.cpp | Raw file I/O: sub-element offsets, overlaps, embedded data, NaN |
| H56–H102, H146–H148, H151–H152 | IccHeuristicsDataValidation.cpp | Tag data payloads: LUT, matrix, curves, calculator, SBO, NPD |
| H103–H120 | IccHeuristicsProfileCompliance.cpp | Required tags per class, encoding rules, PCS constraints |
| H121–H138 | IccHeuristicsIntegrity.cpp | MD5, alignment, complexity estimation, CWE-400 patterns |
| H139–H141, H149–H150 | IccImageAnalyzer.cpp | TIFF strip/tile geometry, IFD bounds, cycle detection |
| H142–H145 | IccHeuristicsXmlSafety.cpp | XML serialization crash isolation (fork + alarm) |
| H154–H161 | IccHeuristicsCodeQLPatterns.cpp | CodeQL-derived: alloc, overflow, enum, UAF, format string |
| H162–H171 | IccHeuristicsExploitGap.cpp | Exploit gap: overlap, exec sigs, LUT, div-zero, null, curves |

---

## 14.5. ICC Conformance Checks (CF-001..CF-316)

279 conformance checks (numbered CF-001..CF-316, with gaps in unused ranges) across 7 dispatcher
modules, validating ICC.1-2022-05, ICC.2-2019 (with September 2021 errata), ICC.2-2023,
and ICS Parts 1–3. These run by default in `-a` mode (conformance audit).

Registry: `IccConformanceRegistry.h` (IDs offset by 1000: CF-001 = ID 1001).

| Dispatcher | CF Ranges | Count | Spec Coverage |
|------------|-----------|-------|---------------|
| RunHeaderConformance | CF-001..015, 107, 121–122, 184–187, 199–201, 203, 206, 210, 214–219, 243–246 | 40 | Header: size, magic, version BCD, class, color space, PCS, rendering intent, D50 illuminant, reserved bytes, dateTime, embedding flags (§7.2) |
| RunTagTypeConformance | CF-020..034, 112, 123–132, 169–174, 188–190, 208–213, 220–234, 247–254, 263–265, 273–281 | 68 | Tag types: s15Fixed16, XYZ, text, mluc, curves, parametric, viewing conditions, named colors, chromaticity, colorant table/order, measurement, response curves (§9–10) |
| RunRequiredTagConformance | CF-039..059, 095–098, 103–104, 111, 117–120, 202, 204–205, 207, 211, 258–260, 266–272, 282–283 | 44 | Required tags per class (mntr/prtr/scnr/link/spac/abst/nmcl), chad ≠D50 rule, ICC.2 additional required tags (§8.2–8.9) |
| RunLUTConformance | CF-060..070, 105–110, 116, 163–168, 255–256, 261–262 | 29 | LUT channel consistency, CLUT grid, curve points, matrix ranges, AToB/BToA pairs, MBB structure (§10.8–10.13) |
| RunV5Conformance | CF-080..089, 113–115, 137–162, 175–198, 235–242, 257, 284–316 | 100 | v5/iccMAX: spectral PCS, MPE structure, multiProcessElementsType, tagStruct/tagArray, embedded images, GBD, sparse matrix, ICC.2:2019 errata items, ICS sub-classes, BRDF tags, PCC matrices (ICC.2 §7–11) |
| RunQualityConformance | CF-091..094 | 6† | Profile quality: curve monotonicity, white point accuracy |
| RunSecurityConformance | (reserved) | 6† | Security-specific validation (reserved for future) |

† Quality and Security dispatchers include placeholder CF_WRAP entries.

### Key Conformance Check Categories

| Category | CF Examples | Description |
|----------|------------|-------------|
| Header validation | CF-001..015 | Profile size vs file size, magic `'acsp'`, BCD version, class enum, color space enum |
| Date/time | CF-243..246 | dateTimeNumber field ranges: month 1–12, day 1–31, hour 0–23, minute/second 0–59 |
| Tag type integrity | CF-020..034 | Type signature consistency, s15Fixed16 bounds, XYZ value ranges |
| Required tags | CF-039..059 | Per-class required tag presence (v2/v4 vs v5 differences) |
| LUT structure | CF-060..070 | Channel counts match color space, CLUT grid ≤ 255, curve/matrix consistency |
| Parametric curves | CF-123..132 | Function type 0–4 parameter count validation, domain restrictions |
| v5 MPE | CF-080..089 | multiProcessElementsType structure, element chain validation |
| v5 errata | CF-137..143 | ICC.2:2019 errata: embedded image lengths, GBD vertices, sparse matrix, 'vor ' opcode |
| v5 ICS | CF-308..316 | ICS sub-class element restrictions, required tags, spectral range, PCC matrices |
| Extended range | CF-144..152, CF-235..242 | xrng sub-class: flag validation, radiance white, element restrictions |
| BRDF/GBD | CF-284..290 | BRDF tag presence, GBD vertex validation, surface map |
| Spectral | CF-291..300 | Spectral data info, wavelength consistency, spectral viewing conditions |
| ICC.2 general | CF-301..307 | Tag struct validation, multiplex naming, calculator element, 'vor ' audit |

**Spec coverage**: ICC.1-2022-05 (v4) ~95%, ICC.2-2019/2023 (v5) ~70%, ICS Parts 1–3 ~60%.

---

## 14.6. ICC.2:2019 Errata Coverage

The ICC.2:2019 specification has two published errata documents (March 8, 2021 and
September 9, 2021). The September 2021 errata is the newer version, adding Item 7
(vector-or opcode trailing space). All 10 errata items are covered:

| # | Errata Item | Section | Type | CF Check |
|---|-------------|---------|------|----------|
| 1 | MultiplexDefaultValues allowed types | §9.2.84 | Critical | CF-137 |
| 2 | multiLocalizedUnicodeType encoding | §10.2.5 | Critical | Multiple CF-020+ |
| 3 | embeddedHeightImage data length calc | §10.2.6 | Critical | CF-138 |
| 4 | embeddedNormalImage data length calc | §10.2.7 | Critical | CF-139 |
| 5 | GBD vertices uint32 vs uint16 | §10.2.11 | Critical | CF-140, CF-286 |
| 6 | SparseMatrix element count | §10.2.20 | Critical | CF-141 |
| 7 | `'vor\0'` → `'vor '` (trailing space) | §11.2.1.9 | Critical | CF-142, CF-307 |
| 8 | measurement tagStructType (§9.2.86) | §9.2.86 | Technical | CF-143 |
| 9 | measurement tagStructType (§9.2.87) | §9.2.87 | Technical | CF-143 |
| 10 | multiProcessElement**s**Type naming | Multiple | Technical | CF-305 |

**Note**: The iccDEV C++ API uses the singular name (`icSigMultiProcessElementType`)
while the spec uses plural (`multiProcessElementsType`). CF-305 audits this naming
divergence in profile output.

---

## 14.7. ICS Sub-Class Conformance (CF-308..CF-316)

ICC Interoperability Conformance Specifications (ICS) define 4 v5 sub-classes, each
with Part 1 (basic), Part 2 (extended), and Part 3 (full) tiers. Part 1 restricts
which MPE element types are permitted in transform tags.

| CF | Check | Sub-Class | ICS Reference |
|----|-------|-----------|---------------|
| CF-308 | pcc AToB1/BToA1 Part 1 element restriction | pcc | ICS-ExtendedRange Part 1 |
| CF-309 | sref PCC matrix restriction (single 3×3) | sref | ICS-ExtendedRange Part 1 |
| CF-310 | sref DToB3/BToD3 Part 1 element restriction | sref | ICS-ExtendedRange Part 1 |
| CF-311 | sref spectral range mandatory | sref | ICS-ExtendedRange Part 1 |
| CF-312 | ext required tag completeness | ext | ICS-ExtendedOutput Part 1 |
| CF-313 | ext Part 1 element type restriction | ext | ICS-ExtendedOutput Part 1 |
| CF-314 | xrng Part 1 AToB1/BToA1 element restriction | xrng | ICS-ExtendedRange Part 1 |
| CF-315 | xrng Part 2 PCC tag & matrix check | xrng | ICS-ExtendedRange Part 2 |
| CF-316 | ICS svcn observer/illuminant plausibility | all ICS | ICS-ExtendedRange Part 1 |

**Part 1 element type restrictions**: curveSet, matrix, CLUT, extCLUT, tintArray only
(no calculator, no sparse matrix — prevents Turing-complete element types in basic profiles).

**ICS sub-class detection**: Read `icHeader.deviceSubClass` — 4-byte signature at header offset 12
(within the v5 class byte range). Values: `'pcc '` (0x70636320), `'xrng'` (0x78726E67),
`'sref'` (0x73726566), `'ext '` (0x65787420).

---

## 15. Version History and BCD Encoding

| Version | Year | Hex | Key Features |
|---------|------|-----|-------------|
| v2.0 | 1994 | `0x02000000` | Original ICC spec |
| v2.1 | 1998 | `0x02100000` | Minor revisions |
| v2.4 | 2001 | `0x02400000` | Widely deployed (sRGB IEC61966) |
| v4.0 | 2004 | `0x04000000` | ProfileID MD5, chad tag, D2B/B2D |
| v4.2 | 2004 | `0x04200000` | Minor update |
| v4.3 | 2010 | `0x04300000` | ICC.1:2010 |
| v4.4 | 2022 | `0x04400000` | ICC.1-2022-05 (current standard) |
| v5.0 | 2022 | `0x05000000` | ICC.2-2019 / iccMAX: spectral PCS, MPE calculator |
| v5.1 | 2023 | `0x05100000` | ICC.2-2023: updated iccMAX |

**Validation**: byte 8 = major (2/4/5), byte 9 upper nibble = minor, lower nibble = bugfix.
Bytes 10–11 must be `0x0000`. Values outside known versions trigger H3 warning.

---

## 16. Profile ID (MD5) Computation

ICC.1-2022-05 §7.2.18 — RFC 1321 MD5:

```
1. Read entire profile into buffer
2. Zero out these fields in the buffer copy:
   - Bytes 44–47  (profile flags)
   - Bytes 64–67  (rendering intent)
   - Bytes 84–99  (profile ID field itself)
3. Compute MD5 of modified buffer
4. Compare with bytes 84–99 of original
5. All-zero Profile ID = "not computed" (valid but less secure)
```

**H131**: If Profile ID is non-zero AND doesn't match computed MD5 → WARN (possible
tampering or corruption). CWE-345.

---

## 17. Useful Code Patterns

### Reading Big-Endian uint32 (C/Python)

```c
// C — used throughout iccanalyzer-lite
static inline uint32_t ReadU32BE(const uint8_t *p, size_t off) {
    return ((uint32_t)p[off] << 24) | ((uint32_t)p[off+1] << 16) |
           ((uint32_t)p[off+2] << 8) | (uint32_t)p[off+3];
}
```

```python
# Python — quick profile inspection
import struct

def read_u32be(data, offset):
    return struct.unpack('>I', data[offset:offset+4])[0]

def read_s15f16(data, offset):
    raw = struct.unpack('>i', data[offset:offset+4])[0]
    return raw / 65536.0

# Read header
with open('profile.icc', 'rb') as f:
    data = f.read()

profile_size = read_u32be(data, 0)
version = read_u32be(data, 8)
magic = data[36:40]
tag_count = read_u32be(data, 128)

# Iterate tags
for i in range(tag_count):
    base = 132 + i * 12
    sig = data[base:base+4].decode('ascii', errors='replace')
    offset = read_u32be(data, base + 4)
    size = read_u32be(data, base + 8)
    print(f"  Tag '{sig}' @ offset {offset}, size {size}")
```

### FourCC Validity Check

```python
# All 4 bytes must be printable ASCII (0x20–0x7E)
def is_valid_fourcc(data, offset):
    return all(0x20 <= b <= 0x7E for b in data[offset:offset+4])
```

### Extracting ICC from TIFF (Python)

```python
import struct

def extract_icc_from_tiff(data):
    """Extract ICC profile from TIFF ICCPROFILE tag (34675)."""
    if data[:2] == b'II':
        endian = '<'
    elif data[:2] == b'MM':
        endian = '>'
    else:
        return None

    ifd_offset = struct.unpack(f'{endian}I', data[4:8])[0]
    num_entries = struct.unpack(f'{endian}H', data[ifd_offset:ifd_offset+2])[0]

    for i in range(num_entries):
        entry = ifd_offset + 2 + i * 12
        tag_id = struct.unpack(f'{endian}H', data[entry:entry+2])[0]
        if tag_id == 34675:  # ICCPROFILE
            count = struct.unpack(f'{endian}I', data[entry+4:entry+8])[0]
            value_offset = struct.unpack(f'{endian}I', data[entry+8:entry+12])[0]
            return data[value_offset:value_offset+count]
    return None
```

---

## 18. Specification References

### Primary

| Document | URL |
|----------|-----|
| ICC.1-2022-05 (v4.4) | `https://www.color.org/specification/ICC.1-2022-05.pdf` |
| ICC.2-2019 (v5.0) | ICC.2-2019 specification (iccMAX — base for errata) |
| ICC.2-2023 (v5.1) | ICC.2-2023 specification (iccMAX — current) |
| ICC.2:2019 Errata (Sep 2021) | 7 critical + 3 technical corrections (see §14.6) |
| ICS-ExtendedRange Part 1–3 | `docs/iccDEV/specifications/ICS-ExtendedRange-Part*.pdf` |
| ICS-ExtendedOutput Part 1 | `docs/iccDEV/specifications/ICS-ExtendedOutput-Part1.pdf` |
| RFC 1321 (MD5) | `https://www.ietf.org/rfc/rfc1321.txt` |

### Technical Notes

| Document | URL | Relevance |
|----------|-----|-----------|
| Profile Embedding | `https://archive.color.org/files/technotes/ICC-Technote-ProfileEmbedding.pdf` | TIFF/JPEG/EPS embedding |
| Partial Chromatic Adaptation | `https://archive.color.org/files/technotes/ICC-Technote-PartialAdaptation.pdf` | chad tag validation |
| Negative PCS XYZ | `https://archive.color.org/files/technotes/Guidelines_on_the_use_of_negative_PCSXYZ_values.pdf` | Wide-gamut ranges |
| V4 Matrix Entries | `https://archive.color.org/files/v4_matrix_entries.pdf` | s15Fixed16 precision |
| V2 Profiles in V4 | `https://archive.color.org/files/v2profiles_v4.pdf` | Version interop |
| Profile Sequence Desc | `https://archive.color.org/files/PSD_TechNote.pdf` | PSD parsing pitfalls |

### iccDEV Doxygen

| Resource | URL |
|----------|-----|
| Class hierarchy | `https://xss.cx/public/docs/iccdev/hierarchy.html` |
| Graphical hierarchy | `https://xss.cx/public/docs/iccdev/inherits.html` |

---

## Cross-References

| Related Document | Path |
|-----------------|------|
| iccanalyzer-lite instructions | `.github/instructions/iccanalyzer-lite.instructions.md` |
| CFL fuzzer instructions | `.github/instructions/cfl.instructions.md` |
| CVE report | `docs/cve/iccDEV-CVE-Report.md` |
| PoC reproduction techniques | `docs/pocs/iccdev-poc-techniques.md` |
| PoC issue reproductions | `docs/pocs/iccdev-issue-reproductions.md` |
| TIFF image analysis | `docs/tiffimg/` |
| Call graph infrastructure | `call-graph/` |
| Analyze profile prompt | `.github/prompts/analyze-icc-profile.prompt.yml` |
| Triage fuzzer crash prompt | `.github/prompts/triage-fuzzer-crash.prompt.md` |

---

*Generated from icc-format-info-learned.txt, enriched with repository source analysis.*
*iccanalyzer-lite v3.7.0+ · 171 heuristics · 279 conformance checks (CF-001..CF-316) · 45 CFL patches · 13 fuzzers · 93 advisories*
