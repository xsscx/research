# ICC Profile Security Analysis Report

**Profile**: `stack-smashing-CIccTagFloatNum-CIccTagStruct-GetElemNumberValue-IccTagBasic_cpp-Line6634.icc`
**Source**: [GitHub Issue Attachment](https://github.com/user-attachments/files/25326721/stack-smashing-CIccTagFloatNum-CIccTagStruct-GetElemNumberValue-IccTagBasic_cpp-Line6634.icc.txt)
**Date**: 2026-02-15
**Analyzer**: iccanalyzer-lite v2.9.1 (ASAN + UBSAN instrumented)

---

## File Properties

| Property | Value |
|----------|-------|
| File size | 742 bytes |
| Header-declared size | 720 bytes (0x000002D0) |
| ICC version | 5.0 |
| Device class | ColorEncodingClass (cenc) |
| Color space | RGB |
| PCS | 0x00000000 (null/invalid) |
| Magic bytes | `acsp` [OK] |
| Tag count | 3 |

---

## 1. Security Analysis (`iccanalyzer-lite -a`)

**Exit code**: 1 (finding detected)

### Complete Raw Output

```
=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: stack-smashing-CIccTagFloatNum-CIccTagStruct-GetElemNumberValue-IccTagBasic_cpp-Line6634.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: stack-smashing-CIccTagFloatNum-CIccTagStruct-GetElemNumberValue-IccTagBasic_cpp-Line6634.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 720 bytes (0x000002D0)  [actual file: 742 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x52474220 (RGB )
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
     [OK] Valid colorSpace: RgbData

[H4] PCS ColorSpace: 0x00000000 (....)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x00000000 (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h: ColorSpace signature: 0x00000000 (Unknown)
     [WARN]  HEURISTIC: Invalid PCS signature (must be Lab, XYZ, or spectral)
     Risk: Colorimetric transform failures
     Name: Unknown  Bytes: ''

[H5] Platform: 0x00000000 (....)
     [OK] Known platform code

[H6] Rendering Intent: 0 (0x00000000)
     [OK] Valid intent: Perceptual

[H7] Profile Class: 0x63656E63 (cenc)
     [OK] Known class: ColorEncodingClass

[H8] Illuminant XYZ: (0.000000, 0.000000, 0.000000)
     [OK] Illuminant values within physical range

[H15] Date Validation: 0-00-00 00:00:00
      [WARN]  HEURISTIC: Invalid month: 0
      [WARN]  HEURISTIC: Invalid day: 0
      [WARN]  HEURISTIC: Suspicious year: 0 (expected 1900-2100)
      Risk: Malformed date may indicate crafted/corrupted profile

[H16] Signature Pattern Analysis
      [OK] No suspicious signature patterns detected

[H17] Spectral Range Validation
      [OK] No spectral data (standard profile)

=======================================================================
TAG-LEVEL HEURISTICS
=======================================================================

[H9] Critical Text Tags:
     Description: Missing
     Copyright: Missing
     Manufacturer: Missing
     Device Model: Missing
     [WARN]  HEURISTIC: Multiple required text tags missing
       Risk: Incomplete/malformed profile

[H10] Tag Count: 3
      [OK] Tag count within normal range

[H11] CLUT Entry Limit Check
      Max safe CLUT entries per tag: 16777216 (16M)
      [OK] Low tag count reduces CLUT exhaustion risk

[H12] MPE Chain Depth Limit
      Max MPE elements per chain: 1024
      Note: Full MPE analysis requires tag-level parsing
      [OK] Limit defined (1024 elements max)

[H13] Per-Tag Size Limit
      Max tag size: 64 MB (67108864 bytes)
      [OK] Theoretical max within limits: 201326592 bytes

[H14] TagArrayType Detection (UAF Risk)
      Checking for TagArrayType (0x74617279 = 'tary')
      Note: Tag signature != tag type - must check tag DATA
      [OK] No TagArrayType tags detected

[H18] Technology Signature Validation
      INFO: No technology tag present

[H19] Tag Offset/Size Overlap Detection
      [OK] No tag overlaps detected

=======================================================================
HEURISTIC SUMMARY
=======================================================================

[WARN]  3 HEURISTIC WARNING(S) DETECTED

  This profile exhibits patterns associated with:
  - Malformed/corrupted data
  - Resource exhaustion attempts
  - Enum confusion vulnerabilities
  - Parser exploitation attempts

  Recommendations:
  - Validate profile with official ICC tools
  - Use -n (ninja mode) for detailed byte-level analysis
  - Do NOT use in production color workflows
  - Consider as potential security test case


=======================================================================
PHASE 2: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: stack-smashing-CIccTagFloatNum-CIccTagStruct-GetElemNumberValue-IccTagBasic_cpp-Line6634.icc

Device Class: 0x63656E63

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [ ] [ ]
  AToB1/BToA1 (Rel. Colorimetric): [ ] [ ]
  AToB2/BToA2 (Saturation):        [ ] [ ]

  DToB0/BToD0 (Perceptual):        [ ] [ ]
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]
  DToB2/BToD2 (Saturation):        [ ] [ ]

  Matrix/TRC Tags:                 [ ]

[ERR] RESULT: Profile does NOT support round-trip validation
   (Missing symmetric AToB/BToA, DToB/BToD, or Matrix/TRC tag pairs)

Result: NOT round-trip capable

=======================================================================
PHASE 3: SIGNATURE ANALYSIS
=======================================================================


=== Signature Analysis ===

Header Signatures:
  Device Class:    0x63656E63  ''  ColorEncodingClass
  Color Space:     0x52474220  'RGB '  RgbData
  PCS:             0x00000000  '....'  NoData [WARN] non-printable
  Manufacturer:    0x00000000  '....'
  Model:           0x00000000  '....'

Tag Signatures:
Idx  Tag          FourCC     Type         Issues
---  ------------ ---------- ------------ ------
0    referenceNameTag 'rfnm    '  utf8Type
1    colorSpaceNameTag 'csnm    '  utf8Type
2    colorEncodingParamsTag 'cept    '  tagStructType

Summary: 1 signature issue(s) detected

=======================================================================
PHASE 4: PROFILE STRUCTURE DUMP
=======================================================================

=== ICC Profile Header ===

=== ICC Profile Header (0x0000-0x007F) ===
0x0000: 00 00 02 D0 00 00 00 00  05 00 00 00 63 65 6E 63  |............cenc|
0x0010: 52 47 42 20 00 00 00 00  00 00 00 00 00 00 00 00  |RGB ............|
0x0020: 00 00 00 00 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields:
  Size:            0x000002D0 (720 bytes)
  CMM:
  Version:         0x05000000
  Device Class:    ColorEncodingClass
  Color Space:     RgbData
  PCS:             NoData

=== Tag Table ===

=== Tag Table ===
Tag Count: 3

Tag Table Raw Data (0x0080-0x00A8):
0x0080: 00 00 00 03 72 66 6E 6D  00 00 00 A8 00 00 00 14  |....rfnm........|
0x0090: 63 73 6E 6D 00 00 00 BC  00 00 00 10 63 65 70 74  |csnm........cept|
0x00A0: 00 00 00 CC 00 00 02 04                           |........|

Tag Entries:
Idx  Signature    FourCC       Offset     Size
---  ------------ ------------ ---------- ----
0    referenceNameTag 'rfnm      '  0x000000A8  20
1    colorSpaceNameTag 'csnm      '  0x000000BC  16
2    colorEncodingParamsTag 'cept      '  0x000000CC  516

=======================================================================
COMPREHENSIVE ANALYSIS SUMMARY
=======================================================================

File: stack-smashing-CIccTagFloatNum-CIccTagStruct-GetElemNumberValue-IccTagBasic_cpp-Line6634.icc
Total Issues Detected: 4

[WARN] ANALYSIS COMPLETE - 4 issue(s) detected
  Review detailed output above for security concerns.
```

---

## 2. Structural Dump (`iccanalyzer-lite -n`)

**Exit code**: 0 (clean - ninja mode bypasses validation)

### Complete Raw Output

```
=========================================================================
|                   *** REDUCED SECURITY MODE ***                       |
|                                                                       |
|             Copyright (c) 2021-2026 David H Hoyt LLC                 |
|                          hoyt.net                                     |
=========================================================================

WARNING: Analyzing malformed/corrupted ICC profile without validation.
         This mode bypasses all safety checks and may expose parser bugs.
         Use only for security research, fuzzing, or forensic analysis.

File: stack-smashing-CIccTagFloatNum-CIccTagStruct-GetElemNumberValue-IccTagBasic_cpp-Line6634.icc

Raw file size: 742 bytes (0x2E6)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 02 D0 00 00 00 00  05 00 00 00 63 65 6E 63  |............cenc|
0x0010: 52 47 42 20 00 00 00 00  00 00 00 00 00 00 00 00  |RGB ............|
0x0020: 00 00 00 00 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x000002D0 (720 bytes) MISMATCH
  CMM:             0x00000000  '....'
  Version:         0x05000000
  Device Class:    0x63656E63  'cenc'
  Color Space:     0x52474220  'RGB '
  PCS:             0x00000000  '....'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 3 (0x00000003)

Tag Table Raw Data:
0x0080: 00 00 00 03 72 66 6E 6D  00 00 00 A8 00 00 00 14  |....rfnm........|
0x0090: 63 73 6E 6D 00 00 00 BC  00 00 00 10 63 65 70 74  |csnm........cept|
0x00A0: 00 00 00 CC 00 00 02 04                           |........|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x72666E6D   'rfnm'        0x000000A8   0x00000014   'utf8'        OK
1    0x63736E6D   'csnm'        0x000000BC   0x00000010   'utf8'        OK
2    0x63657074   'cept'        0x000000CC   0x00000204   'tstr'        OK

=== FULL FILE HEX DUMP (first 2048 bytes) ===
0x0000: 00 00 02 D0 00 00 00 00  05 00 00 00 63 65 6E 63  |............cenc|
0x0010: 52 47 42 20 00 00 00 00  00 00 00 00 00 00 00 00  |RGB ............|
0x0020: 00 00 00 00 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0080: 00 00 00 03 72 66 6E 6D  00 00 00 A8 00 00 00 14  |....rfnm........|
0x0090: 63 73 6E 6D 00 00 00 BC  00 00 00 10 63 65 70 74  |csnm........cept|
0x00A0: 00 00 00 CC 00 00 02 04  75 74 66 38 00 00 00 00  |........utf8....|
0x00B0: 49 53 4F 20 32 32 30 32  38 2D 31 00 75 74 66 38  |ISO 22028-1.utf8|
0x00C0: 00 00 00 00 62 67 2D 73  52 47 42 00 74 73 74 72  |....bg-sRGB.tstr|
0x00D0: 00 00 00 00 63 65 70 74  00 00 00 0F 72 58 59 5A  |....cept....rXYZ|
0x00E0: 00 00 00 C4 00 00 00 14  67 58 59 5A 00 00 00 D8  |........gXYZ....|
0x00F0: 00 00 00 14 62 58 59 5A  00 00 00 EC 00 00 00 14  |....bXYZ........|
0x0100: 66 75 6E 63 00 00 01 00  00 00 00 70 77 6C 75 6D  |func.......pwlum|
0x0110: 00 00 01 70 00 00 00 0C  77 58 59 5A 00 00 01 7C  |...p....wXYZ...||
0x0120: 00 00 00 10 65 52 6E 67  00 00 01 8C 00 00 00 10  |....eRng........|
0x0130: 62 69 74 73 00 00 01 9C  00 00 00 0B 69 6D 73 74  |bits........imst|
0x0140: 00 00 01 A8 00 00 00 0C  69 62 6B 67 00 00 01 B4  |........ibkg....|
0x0150: 00 00 00 0C 73 72 6E 64  00 00 01 C0 00 00 00 0C  |....srnd........|
0x0160: 61 69 6C 6D 00 00 01 CC  00 00 00 0C 6D 77 70 6C  |ailm........mwpl|
0x0170: 00 00 01 D8 00 00 00 0C  6D 77 70 63 00 00 01 E4  |........mwpc....|
0x0180: 00 00 00 10 6D 62 70 63  00 00 01 F4 00 00 00 10  |....mbpc........|
0x0190: 66 6C 33 32 00 00 00 00  3F 23 D7 0A 3E A8 F5 C3  |fl32....?#..>...|
0x01A0: 3C F5 C2 8F 66 6C 33 32  00 00 00 00 3E 99 99 9A  |<...fl32....>...|
0x01B0: 3F 19 99 9A 3D CC CC CD  66 6C 33 32 00 00 00 00  |?...=...fl32....|
0x01C0: 3E 19 99 9A 3D 75 C2 8F  3F 4A 3D 71 63 75 72 66  |>...=u..?J=qcurf|
0x01D0: 00 00 00 00 00 03 00 00  BB 4D 2E 1C 3B 4D 2E 1C  |.........M..;M..|
0x01E0: 70 61 72 66 00 00 00 00  00 03 00 00 3E D5 55 55  |parf........>.UU|
0x01F0: BF 87 78 3D BF 80 00 00  00 00 00 00 00 00 00 00  |..x=............|
0x0200: 70 61 72 66 00 00 00 00  00 00 00 00 3F 80 00 00  |parf........?...|
0x0210: 41 4E B8 52 00 00 00 00  00 00 00 00 70 61 72 66  |AN.R........parf|
0x0220: 00 00 00 00 00 03 00 00  3E D5 55 55 3F 87 0A 3D  |........>.UU?..=|
0x0230: 3F 80 00 00 00 00 00 00  00 00 00 00 66 6C 31 36  |?...........fl16|
0x0240: 00 00 00 00 42 A0 00 00  66 6C 33 32 00 42 32 44  |....B...fl32.B2D|
0x0250: 33 00 00 00 A0 3E 1A 37  3E A8 72 B0 66 6C 33 32  |3....>.7>.r.fl32|
0x0260: 00 00 00 00 BF 07 AE 14  3F D7 0A 3D 75 69 30 34  |........?..=ui04|
0x0270: 00 00 00 00 0A 0C 10 00  73 69 67 20 00 00 00 00  |........sig ....|
0x0280: 64 6F 72 63 66 6C 33 32  00 00 00 00 41 80 00 00  |dorcfl32....A...|
0x0290: 66 6C 33 32 00 00 00 00  40 83 33 4D 65 61 73 75  |fl32....@.3Measu|
0x02A0: 72 65 6D 65 6E 74 42 61  63 6B 69 6E 67 33 66 6C  |rementBacking3fl|
0x02B0: 33 32 00 00 00 00 42 80  00 00 66 6C 33 32 00 00  |32....B...fl32..|
0x02C0: 00 00 42 A0 00 00 66 6C  33 32 00 00 00 00 3E A0  |..B...fl32....>.|
0x02D0: 1A 37 3E A8 72 B0 66 6C  33 32 00 00 00 00 3E A0  |.7>.r.fl32....>.|
0x02E0: 1A 37 3E A8 72 B0                                 |.7>.r.|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## 3. Round-Trip Validation

**Exit code**: 1 (from `-a` mode which includes round-trip)

### Complete Raw Output

```
=== Round-Trip Tag Pair Analysis ===
Profile: stack-smashing-CIccTagFloatNum-CIccTagStruct-GetElemNumberValue-IccTagBasic_cpp-Line6634.icc

Device Class: 0x63656E63

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [ ] [ ]
  AToB1/BToA1 (Rel. Colorimetric): [ ] [ ]
  AToB2/BToA2 (Saturation):        [ ] [ ]

  DToB0/BToD0 (Perceptual):        [ ] [ ]
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]
  DToB2/BToD2 (Saturation):        [ ] [ ]

  Matrix/TRC Tags:                 [ ]

[ERR] RESULT: Profile does NOT support round-trip validation
   (Missing symmetric AToB/BToA, DToB/BToD, or Matrix/TRC tag pairs)
```

---

## 4. ASAN/UBSAN Output

### Security analysis mode (`-a`)

**Exit code**: 1
**stderr**:
```
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x00000000 (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h: ColorSpace signature: 0x00000000 (Unknown)
```

**No ASAN violations. No UBSAN violations. No stack buffer overflow detected by sanitizers.**

### Ninja mode (`-n`)

**Exit code**: 0
**stderr**: (empty)

**No ASAN violations. No UBSAN violations.**

---

## 5. Security Assessment

### Profile Summary

This is a 742-byte ICC v5.0 ColorEncodingClass (`cenc`) profile with RGB data color space. The profile was submitted with the filename suggesting it triggers a stack-smashing condition in `CIccTagFloatNum`/`CIccTagStruct::GetElemNumberValue` at `IccTagBasic.cpp` line 6634.

### Findings

| ID | Severity | Finding |
|----|----------|---------|
| [H4] | [WARN] | **Invalid PCS signature**: PCS is 0x00000000 (null), which is not a valid ICC PCS (must be Lab, XYZ, or spectral). Risk: colorimetric transform failures and potential enum confusion in parsers that assume valid PCS. |
| [H15] | [WARN] | **Invalid date fields**: Year=0, Month=0, Day=0. All-zero date indicates the profile was crafted or corrupted, not generated by a legitimate color management tool. |
| [H9] | [WARN] | **Missing required text tags**: Description, Copyright, Manufacturer, and Device Model tags are all absent. The profile contains only 3 tags (`rfnm`, `csnm`, `cept`), all related to ICC v5.0 color encoding. |
| Header | [INFO] | **Size mismatch**: Header declares 720 bytes but file is 742 bytes (22 trailing bytes at 0x02D0-0x02E5). The trailing data contains `fl32` floating-point values that extend beyond the declared profile boundary. |

### Tag Structure Analysis

The profile contains a `colorEncodingParamsTag` (`cept`) at offset 0xCC with size 516 bytes. This tag is of type `tagStructType` (`tstr`) and contains sub-elements including:

- **rXYZ, gXYZ, bXYZ**: RGB primaries (XYZ coordinates)
- **func**: Transfer function data (112 bytes)
- **wlum**: Peak white luminance
- **wXYZ**: White point
- **eRng**: Encoding range
- **bits**: Bit depth
- **imst, ibkg, srnd, ailm**: Image state, image background, surround, adapted illuminant
- **mwpl, mwpc, mbpc**: Measurement white, measurement white PCS, measurement black PCS
- Multiple **fl32** (float32) and **parf** (parametricCurve) sub-tags
- **curf** (segmented curve), **fl16** (float16), **ui04**, **sig** sub-tags

### Vulnerability Context

The filename references `CIccTagFloatNum` and `CIccTagStruct::GetElemNumberValue` at `IccTagBasic.cpp` line 6634. This code path is invoked when the library attempts to extract numeric values from structured tag elements within a `tagStructType` tag. The profile's `cept` tag contains densely packed float values that could trigger:

1. **Stack buffer overflow**: If `GetElemNumberValue` reads beyond bounds when parsing nested float elements within the struct tag, particularly when the struct contains misaligned or truncated sub-elements.
2. **Type confusion**: The `fl32` tags at the end of the file (offsets 0x02D0+) extend past the declared profile size boundary. A parser that trusts the tag table offsets without validating against the header-declared size could read into these trailing bytes.
3. **Nested struct parsing**: The `tstr` tag type contains a sub-tag table that mirrors the outer tag structure. Malformed sub-tag entries could cause recursive or out-of-bounds access in `CIccTagStruct::GetElemNumberValue`.

### Sanitizer Result

iccanalyzer-lite (built with `-fsanitize=address,undefined,float-divide-by-zero,float-cast-overflow,integer`) did **not** trigger any ASAN or UBSAN violations when processing this profile. This means either:

1. The iccanalyzer-lite code path for `GetElemNumberValue` includes bounds checking that prevents the overflow, or
2. The specific vulnerable code path is not exercised by the analysis modes (`-a` and `-n`), or
3. The vulnerability manifests only in specific downstream consumers (e.g., `iccApplyProfiles`, `iccDumpProfile`) that invoke `GetElemNumberValue` in a different context.

### Recommendations

1. **Fuzzing target**: This profile should be added to fuzzer seed corpora, particularly for `icc_roundtrip_fuzzer` and `icc_apply_profiles_fuzzer` which exercise `CIccTagStruct` parsing via CMM operations.
2. **Upstream investigation**: The vulnerability at `IccTagBasic.cpp:6634` should be investigated in the upstream DemoIccMAX library's `CIccTagStruct::GetElemNumberValue` implementation.
3. **Do NOT use in production**: This profile has invalid PCS, zeroed dates, missing required tags, and a size mismatch - it should be treated exclusively as a security test case.
4. **Trailing bytes**: The 22 bytes beyond the declared profile size warrant investigation for information leakage or parsing oracle attacks.
