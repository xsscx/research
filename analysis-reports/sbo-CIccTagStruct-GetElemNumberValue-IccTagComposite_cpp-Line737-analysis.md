# ICC Profile Analysis Report

**Profile**: `sbo-CIccTagStruct-GetElemNumberValue-IccTagComposite_cpp-Line737.icc`
**File Size**: 720 bytes
**Date**: 2026-03-01T01:40:12Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 1 | Finding detected |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 1**

```
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x00000000 (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:️ ColorSpace signature: 0x00000000 (Unknown)

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/h02332/po/research/sbo-CIccTagStruct-GetElemNumberValue-IccTagComposite_cpp-Line737.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/h02332/po/research/sbo-CIccTagStruct-GetElemNumberValue-IccTagComposite_cpp-Line737.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 720 bytes (0x000002D0)  [actual file: 720 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x52474220 (RGB )
     [OK] Valid colorSpace: RgbData

[H4] PCS ColorSpace: 0x00000000 (....)
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
      [OK] No CLUT tags to check

[H12] MPE Chain Depth Check
      Max MPE elements per chain: 1024
      [OK] No MPE tags to check

[H13] Per-Tag Size Check
      Max tag size: 64 MB (67108864 bytes)
      [OK] All 3 tags within size limits

[H14] TagArrayType Detection (UAF Risk)
      Checking for TagArrayType (0x74617279 = 'tary')
      Note: Tag signature ≠ tag type - must check tag DATA
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
  • Validate profile with official ICC tools
  • Use -n (ninja mode) for detailed byte-level analysis
  • Do NOT use in production color workflows
  • Consider as potential security test case


=======================================================================
PHASE 2: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/sbo-CIccTagStruct-GetElemNumberValue-IccTagComposite_cpp-Line737.icc

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
PHASE 5: TAG CONTENT ANALYSIS
=======================================================================

--- 5A: LUT Tag Geometry ---

  No legacy LUT tags (A2B/B2A/D2B/B2D) found

--- 5B: MPE Element Chains ---

  No MPE tags found

--- 5C: TRC Curve Analysis ---

  No TRC curve tags found

--- 5D: NamedColor2 Validation ---

  No NamedColor2 tag

--- 5E: XYZ Tag Values ---

  No XYZ colorant/white-point tags

--- 5F: ICC v5 Spectral Data ---

  No ICC v5 spectral tags

--- 5G: Profile ID Verification ---

  Profile ID: not set (all zeros)
      INFO: Profile integrity cannot be verified without ID

--- 5H: Per-Tag Size Analysis ---

  Tag sizes (flagging >10MB):
      [OK] All tags within 10MB limit


=======================================================================
COMPREHENSIVE ANALYSIS SUMMARY
=======================================================================

File: /home/h02332/po/research/sbo-CIccTagStruct-GetElemNumberValue-IccTagComposite_cpp-Line737.icc
Total Issues Detected: 4

[WARN] ANALYSIS COMPLETE - 4 issue(s) detected
  Review detailed output above for security concerns.
```

---

## Command 2: Ninja Full Dump (`-nf`)

**Exit Code: 0**

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

File: /home/h02332/po/research/sbo-CIccTagStruct-GetElemNumberValue-IccTagComposite_cpp-Line737.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 720 bytes (0x2D0)

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
  Profile Size:    0x000002D0 (720 bytes) OK
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

=== FULL FILE HEX DUMP (all 720 bytes) ===
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
0x01E0: 70 61 72 66 00 00 00 00  00 03 00 00 43 D5 55 55  |parf........C.UU|
0x01F0: BF 87 0A 3D BF 80 00 00  00 00 00 00 00 00 00 00  |...=............|
0x0200: 70 61 72 66 00 00 00 00  00 00 00 00 3F 80 00 00  |parf........?...|
0x0210: 41 4E B8 52 00 00 00 00  00 00 00 00 70 61 72 66  |AN.R........parf|
0x0220: 00 00 00 00 00 03 00 00  3E D5 55 55 3F 87 0A 3D  |........>.UU?..=|
0x0230: 3F 80 00 00 00 00 00 00  00 00 00 00 66 6C 33 32  |?...........fl32|
0x0240: 00 00 00 00 42 A0 00 00  66 6C 33 32 00 00 00 00  |....B...fl32....|
0x0250: 3E 87 0A 3D 3F 80 00 00  00 00 00 00 00 00 00 00  |>..=?...........|
0x0260: 66 6C 33 32 00 00 00 00  42 A0 00 00 66 6C 33 32  |fl32....B...fl32|
0x0270: 00 00 00 00 3E A0 1A 37  3E A8 72 B0 66 6C 33 32  |....>..7>.r.fl32|
0x0280: 00 00 00 00 BF 07 AE 14  3F D7 0A 3D 75 69 30 38  |........?..=ui08|
0x0290: 00 00 00 00 0A 0C 10 00  73 69 67 20 00 00 00 00  |........sig ....|
0x02A0: 64 6F 72 63 66 6C 33 32  00 00 00 00 42 A0 00 00  |dorcfl32....B...|
0x02B0: 66 6C 33 32 00 00 00 00  3E A0 1A 37 3E A8 72 B0  |fl32....>..7>.r.|
0x02C0: 66 6C 33 32 00 00 00 00  3E A0 1A 37 3E A8 72 B0  |fl32....>..7>.r.|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 1**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/sbo-CIccTagStruct-GetElemNumberValue-IccTagComposite_cpp-Line737.icc

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
