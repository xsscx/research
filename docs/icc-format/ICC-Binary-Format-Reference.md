# ICC Binary Format — Security Research Quick Reference

> **Audience**: AI agents (Copilot, MCP, fuzzer pipelines) and human researchers
> working on ICC profile security analysis, fuzzer harness development, and
> heuristic authoring.
>
> **Sources**: ICC.1-2022-05, ICC.2-2023, iccanalyzer-lite source code,
> CFL fuzzer corpus, 93 iccDEV security advisories (85 CVEs + 95 GHSAs).
>
> **Last verified**: 2026-03-14 — 150 heuristics, 20 CFL patches, 12 fuzzers.

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
13. [CFL Patch Catalog (20 Active)](#13-cfl-patch-catalog-20-active)
14. [Heuristic → Format Mapping](#14-heuristic--format-mapping)
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
AToB0  'A2B0'    Device → PCS, perceptual intent
AToB1  'A2B1'    Device → PCS, relative colorimetric
AToB2  'A2B2'    Device → PCS, saturation
AToB3  'A2B3'    Device → PCS, absolute colorimetric
BToA0  'B2A0'    PCS → Device, perceptual
BToA1  'B2A1'    PCS → Device, relative
BToA2  'B2A2'    PCS → Device, saturation
BToA3  'B2A3'    PCS → Device, absolute
DToB0  'D2B0'    Device → PCS, spectral (v5)
DToB1  'D2B1'    ...
BToD0  'B2D0'    PCS → Device, spectral (v5)
BToD1  'B2D1'    ...
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
| spectralViewingConditionsTag | `'svcn'` | — | v5 viewing conditions |
| embeddedV5ProfileTag | `'ICCe'` | H147 | Nested profile |

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
| float16ArrayType | `'fl16'` | — | v5 half-float array |
| float32ArrayType | `'fl32'` | — | v5 single-float array |
| float64ArrayType | `'fl64'` | — | v5 double-float array |
| gamutBoundaryDescType | `'gbd '` | — | v5 gamut boundary (H146) |
| sparseMatrixArrayType | `'smAt'` | — | v5 sparse matrix |

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
| Matrix | `'mAtx'` | `0x6D417478` | H84: matrix bounds |
| CLUT | `'clut'` | `0x636C7574` | H11/H63: grid overflow |
| Calculator | `'calc'` | `0x63616C63` | H56/H81/H138: Turing-complete, DoS |
| Curve Set Factory | `'curf'` | `0x63757266` | Curve construction |
| SingleSampledCurve | `'sngf'` | `0x736E6766` | OOM risk: large nCount |
| Emission Matrix | `'emtx'` | — | v5 spectral |
| Inv Emission Matrix | `'iemx'` | — | v5 spectral |
| Emission Observer | `'eobs'` | — | v5 spectral |
| Reflectance Observer | `'robs'` | — | v5 spectral |

### MPE Chain Depth Risk (CWE-674)

Calculator elements can reference sub-elements which themselves contain calculators,
enabling unbounded recursion. Heuristic H138 estimates chain depth; CFL-010 limits
recursion to depth 50 with a 200K operations budget.

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

### Calculator Operator Opcodes (89 valid)

All opcodes are **printable ASCII FourCC** (each byte 0x20–0x7E):

| Category | Opcodes |
|----------|---------|
| Stack I/O | `'in  '`, `'out '`, `'data'` |
| Arithmetic | `'add '`, `'sub '`, `'mul '`, `'div '`, `'mod '`, `'neg '` |
| Math | `'pow '`, `'sqrt'`, `'abs '`, `'flor'`, `'ceil'`, `'rond'` |
| Trig | `'sin '`, `'cos '`, `'atan'`, `'exp '`, `'log '`, `'ln  '` |
| Comparison | `'min '`, `'max '`, `'lt  '`, `'le  '`, `'eq  '`, `'ne  '`, `'gt  '`, `'ge  '` |
| Logic | `'not '`, `'and '`, `'or  '` |
| Branching | `'if  '`, `'else'`, `'sel '`, `'case'` |
| Temp vars | `'tget'`, `'tput'`, `'tsav'`, `'tlab'` |
| Sub-element | `'curv'`, `'clut'`, `'mtx '`, `'calc'`, `'elem'` |
| Environment | `'env '`, `'copy'`, `'rotl'`, `'rotr'`, `'pop '`, `'posd'` |
| Conversion | `'fJab'`, `'tJab'`, `'tXYZ'`, `'fXYZ'`, `'tLab'`, `'fLab'` |
| Clipping | `'clip'`, `'clpv'` |
| Spectral | `'solv'`, `'tran'` |

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

Extraction: png_get_iCCP() → inflate → temp file → 150-heuristic analysis
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

23 distinct CWE categories across 150 heuristics:

| CWE | Name | Count | Key Heuristics |
|-----|------|-------|----------------|
| CWE-20 | Improper Input Validation | ~37 | H2, H3, H4, H5, H6, H7, H111, H121 |
| CWE-119 | Buffer Access | ~4 | H33, H148 |
| CWE-121 | Stack Buffer Overflow | ~3 | H146 |
| CWE-122 | Heap Buffer Overflow | ~8 | H139, H150 |
| CWE-125 | Out-of-bounds Read | ~6 | H10, H141, H143 |
| CWE-126 | Buffer Over-read | ~2 | H144 |
| CWE-131 | Incorrect Buffer Size | ~10 | H9, H63, H78, H84, H140 |
| CWE-170 | Improper Null Termination | ~2 | H144 |
| CWE-190 | Integer Overflow | ~8 | H11, H33, H34, H139 |
| CWE-191 | Integer Underflow | ~1 | H34 |
| CWE-345 | Insufficient Verification | ~5 | H131, H112 |
| CWE-369 | Divide By Zero | ~1 | — |
| CWE-400 | Resource Exhaustion | ~8 | H136, H137, H138, H142, H143 |
| CWE-416 | Use After Free | ~2 | — |
| CWE-476 | NULL Pointer Dereference | ~10 | H147 |
| CWE-506 | Embedded Malicious Code | ~1 | H35 |
| CWE-674 | Uncontrolled Recursion | ~4 | H56, H138 |
| CWE-681 | Incorrect Type Conversion | ~3 | — |
| CWE-682 | Incorrect Calculation | ~5 | H112 |
| CWE-694 | Use of Non-unique Identifier | ~1 | H25 |
| CWE-787 | Out-of-bounds Write | ~5 | H142 |
| CWE-835 | Loop w/o Exit Condition | ~2 | H149 |
| CWE-843 | Type Confusion | ~3 | H32, H145 |

---

## 13. CFL Patch Catalog (20 Active)

Active patches in `cfl/patches/` targeting verified upstream iccDEV bugs:

| # | Patch | Bug | CWE | File |
|---|-------|-----|-----|------|
| 001 | icAnsiToUtf8 null termination | HBO via strlen on unterminated 32-byte name | CWE-125/170 | IccTagBasic.cpp, IccUtilXml.cpp |
| 002 | GamutBoundary triangles overflow | Signed int overflow: m_NumberOfTriangles×3 | CWE-190 | IccTagLut.cpp |
| 003 | TagArray alloc-dealloc mismatch | `new[]` in copy ctor, `free()` in Cleanup() | CWE-762 | IccTagComposite.cpp |
| 004 | ToneMapFunc Read parameter count | HBO via Describe() accessing m_params[0..2] with 1 allocated | CWE-122 | IccMpeBasic.cpp |
| 005 | CalculatorFunc Read enum UBSAN | Enum out-of-range in calculator op read | CWE-681 | IccMpeCalc.cpp |
| 006 | SpectralMatrix Describe bounds | HBO via Describe() iterating m_nOutputChannels rows | CWE-122 | IccMpeSpectral.cpp |
| 007 | TagArray Read overflow guard | Integer overflow in TagArray element count | CWE-190 | IccTagComposite.cpp |
| 008 | TagCurve Apply NaN-to-unsigned | NaN bypasses [0,1] clamp, cast to unsigned = UB | CWE-681 | IccTagLut.cpp |
| 009 | EnvVar Exec enum UBSAN | Enum out-of-range in CIccOpDefEnvVar::Exec() | CWE-681 | IccMpeCalc.cpp |
| 010 | CheckUnderflowOverflow recursion | Unbounded recursion: depth 50 + 200K ops budget | CWE-674 | IccMpeCalc.cpp |
| 011 | SpecSepToTiff unique_ptr array | unique_ptr array mismatch | CWE-762 | IccApplyBPC.h |
| 012 | ndLUT InterpND null ApplyCLUT | NULL deref in CLUT interpolation | CWE-476 | IccTagLut.cpp |
| 013 | TagArray cleanup uninit guard | Uninitialized members + UAF in tag array | CWE-908/416 | IccTagComposite.cpp |
| 014 | SequenceNeedTempReset recursion | Unbounded recursion depth in sequence reset | CWE-674 | IccMpeCalc.cpp |
| 015 | SpecSep BPS validation | BPS validation for spectral separation | CWE-20 | IccApplyBPC.cpp |
| 016 | NaN guard unsigned cast UBSAN | NaN→unsigned conversion UB | CWE-681 | IccMpeBasic.cpp |
| 017 | EnvVar GetEnvSig parse enum | Enum parse UB in env variable signature | CWE-681 | IccMpeCalc.cpp |
| 018 | TagUnknown Describe HBO | Underflow in Describe() size calculation | CWE-122 | IccTagBasic.cpp |
| 019 | PCC null spectral viewing | NULL deref: spectral viewing conditions | CWE-476 | IccPcc.cpp |
| 020 | SampledCalculatorCurve Begin | SBO: channel count mismatch in Begin() | CWE-121 | IccMpeBasic.cpp |

**Next patch**: CFL-021. 62 legacy patches in `cfl/patches-retired/`.

---

## 14. Heuristic → Format Mapping

Which ICC binary format fields each heuristic group validates:

| Heuristic Range | Module | Format Region |
|-----------------|--------|---------------|
| H1–H8, H15–H17 | IccHeuristicsHeader.cpp | Header bytes 0–127 (raw byte access) |
| H9–H32 | IccHeuristicsTagValidation.cpp | Tag table at offset 128+ (CIccProfile API) |
| H33–H55, H57–H69 | IccHeuristicsRawPost.cpp | Raw file I/O: sub-element offsets, overlaps, embedded data |
| H56–H102 | IccHeuristicsDataValidation.cpp | Tag data payloads: LUT, matrix, curves, calculator, CLUT |
| H103–H120 | IccHeuristicsProfileCompliance.cpp | Required tags per class, encoding rules, PCS constraints |
| H121–H138 | IccHeuristicsIntegrity.cpp | MD5, alignment, complexity estimation, CWE-400 patterns |
| H139–H141, H149–H150 | IccImageAnalyzer.cpp | TIFF strip/tile geometry, IFD bounds, cycle detection |
| H142–H145 | IccHeuristicsXmlSafety.cpp | XML serialization crash isolation (fork + alarm) |
| H146–H148 | IccHeuristicsDataValidation.cpp | Advanced: SBO GetValues, NPD post-Read, memcpy bounds |

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
| ICC.2-2023 (v5.1) | ICC.2-2023 specification (iccMAX) |
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
*iccanalyzer-lite v3.6.2+ · 150 heuristics · 20 CFL patches · 12 fuzzers · 93 advisories*
