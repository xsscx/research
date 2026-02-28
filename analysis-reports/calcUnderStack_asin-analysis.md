# ICC Profile Analysis Report

**Profile**: `test-profiles/calcUnderStack_asin.icc`
**File Size**: 3936 bytes
**Date**: 2026-02-28T18:26:58Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 0 | Clean |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 0 | Clean |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 0**

```
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/runner/work/research/research/test-profiles/calcUnderStack_asin.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/runner/work/research/research/test-profiles/calcUnderStack_asin.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 3936 bytes (0x00000F60)  [actual file: 3936 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x52474220 (RGB )
     [OK] Valid colorSpace: RgbData

[H4] PCS ColorSpace: 0x58595A20 (XYZ )
     [OK] Valid PCS: XYZData

[H5] Platform: 0x00000000 (....)
     [OK] Known platform code

[H6] Rendering Intent: 1 (0x00000001)
     [OK] Valid intent: Relative Colorimetric

[H7] Profile Class: 0x73706163 (spac)
     [OK] Known class: ColorSpaceClass

[H8] Illuminant XYZ: (0.950500, 1.000000, 1.089096)
     [OK] Illuminant values within physical range

[H15] Date Validation: 2018-08-15 10:22:18
      [OK] Date values within valid ranges

[H16] Signature Pattern Analysis
      [OK] No suspicious signature patterns detected

[H17] Spectral Range Validation
      [OK] No spectral data (standard profile)

=======================================================================
TAG-LEVEL HEURISTICS
=======================================================================

[H9] Critical Text Tags:
     Description: Present [OK]
     Copyright: Present [OK]
     Manufacturer: Missing
     Device Model: Missing

[H10] Tag Count: 8
      [OK] Tag count within normal range

[H11] CLUT Entry Limit Check
      Max safe CLUT entries per tag: 16777216 (16M)
      [OK] No CLUT tags to check

[H12] MPE Chain Depth Check
      Max MPE elements per chain: 1024
      Inspected 2 MPE tag(s)

[H13] Per-Tag Size Check
      Max tag size: 64 MB (67108864 bytes)
      [OK] All 8 tags within size limits

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

[OK] NO HEURISTIC WARNINGS DETECTED
  Profile appears well-formed with no obvious security concerns.


=======================================================================
PHASE 2: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/calcUnderStack_asin.icc

Device Class: 0x73706163

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [ ] [ ]  
  AToB1/BToA1 (Rel. Colorimetric): [[X]] [[X]]  [X] Round-trip capable
  AToB2/BToA2 (Saturation):        [ ] [ ]  

  DToB0/BToD0 (Perceptual):        [ ] [ ]  
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]  
  DToB2/BToD2 (Saturation):        [ ] [ ]  

  Matrix/TRC Tags:                 [ ]  

[OK] RESULT: Profile supports round-trip validation

Result: Round-trip capable [OK]

=======================================================================
PHASE 3: SIGNATURE ANALYSIS
=======================================================================


=== Signature Analysis ===

Header Signatures:
  Device Class:    0x73706163  ''  ColorSpaceClass
  Color Space:     0x52474220  'RGB '  RgbData
  PCS:             0x58595A20  'XYZ '  XYZData
  Manufacturer:    0x00000000  '....'
  Model:           0x00000000  '....'

Tag Signatures:
Idx  Tag          FourCC     Type         Issues
---  ------------ ---------- ------------ ------
0    profileDescriptionTag 'desc    '  multiLocalizedUnicodeType
1    AToB1Tag     'A2B1    '  multiProcessElementType
2    BToA1Tag     'B2A1    '  multiProcessElementType
3    customToStandardPccTag 'c2sp    '  multiProcessElementType
4    standardToCustomPccTag 's2cp    '  multiProcessElementType
5    spectralViewingConditionsTag 'svcn    '  spectralViewingConditionsType
6    mediaWhitePointTag 'wtpt    '  XYZArrayType
7    copyrightTag 'cprt    '  multiLocalizedUnicodeType

Summary: 0 signature issue(s) detected

=======================================================================
PHASE 4: PROFILE STRUCTURE DUMP
=======================================================================

=== ICC Profile Header ===

=== ICC Profile Header (0x0000-0x007F) ===
0x0000: 00 00 0F 60 00 00 00 00  05 00 00 00 73 70 61 63  |...`........spac|
0x0010: 52 47 42 20 58 59 5A 20  07 E2 00 08 00 0F 00 0A  |RGB XYZ ........|
0x0020: 00 16 00 12 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 54  00 01 00 00 00 01 16 CF  |.......T........|
0x0050: 49 43 43 20 AD C2 6A 85  CD A0 DE 91 CD FD 8D 74  |ICC ..j........t|
0x0060: 6F FC 5C 00 00 00 00 00  00 00 00 00 00 00 00 00  |o.\.............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields:
  Size:            0x00000F60 (3936 bytes)
  CMM:             
  Version:         0x05000000
  Device Class:    ColorSpaceClass
  Color Space:     RgbData
  PCS:             XYZData

=== Tag Table ===

=== Tag Table ===
Tag Count: 8

Tag Table Raw Data (0x0080-0x00E4):
0x0080: 00 00 00 08 64 65 73 63  00 00 00 E4 00 00 00 42  |....desc.......B|
0x0090: 41 32 42 31 00 00 01 28  00 00 03 DC 42 32 41 31  |A2B1...(....B2A1|
0x00A0: 00 00 05 04 00 00 03 DC  63 32 73 70 00 00 08 E0  |........c2sp....|
0x00B0: 00 00 00 54 73 32 63 70  00 00 09 34 00 00 00 54  |...Ts2cp...4...T|
0x00C0: 73 76 63 6E 00 00 09 88  00 00 05 4C 77 74 70 74  |svcn.......Lwtpt|
0x00D0: 00 00 0E D4 00 00 00 14  63 70 72 74 00 00 0E E8  |........cprt....|
0x00E0: 00 00 00 76                                       |...v|

Tag Entries:
Idx  Signature    FourCC       Offset     Size
---  ------------ ------------ ---------- ----
0    profileDescriptionTag 'desc      '  0x000000E4  66
1    AToB1Tag     'A2B1      '  0x00000128  988
2    BToA1Tag     'B2A1      '  0x00000504  988
3    customToStandardPccTag 'c2sp      '  0x000008E0  84
4    standardToCustomPccTag 's2cp      '  0x00000934  84
5    spectralViewingConditionsTag 'svcn      '  0x00000988  1356
6    mediaWhitePointTag 'wtpt      '  0x00000ED4  20
7    copyrightTag 'cprt      '  0x00000EE8  118

=======================================================================
PHASE 5: TAG CONTENT ANALYSIS
=======================================================================

--- 5A: LUT Tag Geometry ---

  No legacy LUT tags (A2B/B2A/D2B/B2D) found

--- 5B: MPE Element Chains ---

  [A2B1] MPE Tag 'A2B1'
      Input channels:  3
      Output channels: 3
      Elements:        1
        [0] type='calc' in=3 out=3
      [INFO] Calculator element detected — #1 source of UBSAN findings

  [B2A1] MPE Tag 'B2A1'
      Input channels:  3
      Output channels: 3
      Elements:        1
        [0] type='calc' in=3 out=3
      [INFO] Calculator element detected — #1 source of UBSAN findings

--- 5C: TRC Curve Analysis ---

  No TRC curve tags found

--- 5D: NamedColor2 Validation ---

  No NamedColor2 tag

--- 5E: XYZ Tag Values ---

  [wtpt] X=0.9505 Y=1.0000 Z=1.0891

--- 5F: ICC v5 Spectral Data ---

  SpectralViewingConditions:
      Observer:    CIE 1931 (two degree) standard observer
      Illuminant:  Illuminant D65 (CCT=6500 K)
      Illuminant XYZ: (95.0500, 100.0000, 108.9100)

--- 5G: Profile ID Verification ---

  Profile ID (header):   adc26a85cda0de91cdfd8d746ffc5c00
  Profile ID (computed): adc26a85cda0de91cdfd8d746ffc5c00
  [OK] Profile ID matches — integrity verified

--- 5H: Per-Tag Size Analysis ---

  Tag sizes (flagging >10MB):
      [OK] All tags within 10MB limit


=======================================================================
COMPREHENSIVE ANALYSIS SUMMARY
=======================================================================

File: /home/runner/work/research/research/test-profiles/calcUnderStack_asin.icc
Total Issues Detected: 0

[OK] ANALYSIS COMPLETE - No critical issues detected
  Profile appears well-formed.
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

File: /home/runner/work/research/research/test-profiles/calcUnderStack_asin.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 3936 bytes (0xF60)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 0F 60 00 00 00 00  05 00 00 00 73 70 61 63  |...`........spac|
0x0010: 52 47 42 20 58 59 5A 20  07 E2 00 08 00 0F 00 0A  |RGB XYZ ........|
0x0020: 00 16 00 12 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 54  00 01 00 00 00 01 16 CF  |.......T........|
0x0050: 49 43 43 20 AD C2 6A 85  CD A0 DE 91 CD FD 8D 74  |ICC ..j........t|
0x0060: 6F FC 5C 00 00 00 00 00  00 00 00 00 00 00 00 00  |o.\.............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x00000F60 (3936 bytes) OK
  CMM:             0x00000000  '....'
  Version:         0x05000000
  Device Class:    0x73706163  'spac'
  Color Space:     0x52474220  'RGB '
  PCS:             0x58595A20  'XYZ '

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 8 (0x00000008)

Tag Table Raw Data:
0x0080: 00 00 00 08 64 65 73 63  00 00 00 E4 00 00 00 42  |....desc.......B|
0x0090: 41 32 42 31 00 00 01 28  00 00 03 DC 42 32 41 31  |A2B1...(....B2A1|
0x00A0: 00 00 05 04 00 00 03 DC  63 32 73 70 00 00 08 E0  |........c2sp....|
0x00B0: 00 00 00 54 73 32 63 70  00 00 09 34 00 00 00 54  |...Ts2cp...4...T|
0x00C0: 73 76 63 6E 00 00 09 88  00 00 05 4C 77 74 70 74  |svcn.......Lwtpt|
0x00D0: 00 00 0E D4 00 00 00 14  63 70 72 74 00 00 0E E8  |........cprt....|
0x00E0: 00 00 00 76                                       |...v|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x64657363   'desc'        0x000000E4   0x00000042   'mluc'        OK
1    0x41324231   'A2B1'        0x00000128   0x000003DC   'mpet'        OK
2    0x42324131   'B2A1'        0x00000504   0x000003DC   'mpet'        OK
3    0x63327370   'c2sp'        0x000008E0   0x00000054   'mpet'        OK
4    0x73326370   's2cp'        0x00000934   0x00000054   'mpet'        OK
5    0x7376636E   'svcn'        0x00000988   0x0000054C   'svcn'        OK
6    0x77747074   'wtpt'        0x00000ED4   0x00000014   'XYZ '        OK
7    0x63707274   'cprt'        0x00000EE8   0x00000076   'mluc'        OK

=== FULL FILE HEX DUMP (all 3936 bytes) ===
0x0000: 00 00 0F 60 00 00 00 00  05 00 00 00 73 70 61 63  |...`........spac|
0x0010: 52 47 42 20 58 59 5A 20  07 E2 00 08 00 0F 00 0A  |RGB XYZ ........|
0x0020: 00 16 00 12 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 54  00 01 00 00 00 01 16 CF  |.......T........|
0x0050: 49 43 43 20 AD C2 6A 85  CD A0 DE 91 CD FD 8D 74  |ICC ..j........t|
0x0060: 6F FC 5C 00 00 00 00 00  00 00 00 00 00 00 00 00  |o.\.............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0080: 00 00 00 08 64 65 73 63  00 00 00 E4 00 00 00 42  |....desc.......B|
0x0090: 41 32 42 31 00 00 01 28  00 00 03 DC 42 32 41 31  |A2B1...(....B2A1|
0x00A0: 00 00 05 04 00 00 03 DC  63 32 73 70 00 00 08 E0  |........c2sp....|
0x00B0: 00 00 00 54 73 32 63 70  00 00 09 34 00 00 00 54  |...Ts2cp...4...T|
0x00C0: 73 76 63 6E 00 00 09 88  00 00 05 4C 77 74 70 74  |svcn.......Lwtpt|
0x00D0: 00 00 0E D4 00 00 00 14  63 70 72 74 00 00 0E E8  |........cprt....|
0x00E0: 00 00 00 76 6D 6C 75 63  00 00 00 00 00 00 00 01  |...vmluc........|
0x00F0: 00 00 00 0C 65 6E 55 53  00 00 00 26 00 00 00 1C  |....enUS...&....|
0x0100: 00 63 00 61 00 6C 00 63  00 55 00 6E 00 64 00 65  |.c.a.l.c.U.n.d.e|
0x0110: 00 72 00 53 00 74 00 61  00 63 00 6B 00 5F 00 61  |.r.S.t.a.c.k._.a|
0x0120: 00 73 00 69 00 6E 00 00  6D 70 65 74 00 00 00 00  |.s.i.n..mpet....|
0x0130: 00 03 00 03 00 00 00 01  00 00 00 18 00 00 03 C4  |................|
0x0140: 63 61 6C 63 00 00 00 00  00 03 00 03 00 00 00 07  |calc............|
0x0150: 00 00 00 50 00 00 01 8C  00 00 01 8C 00 00 00 9C  |...P............|
0x0160: 00 00 02 28 00 00 00 3C  00 00 02 64 00 00 00 7C  |...(...<...d...||
0x0170: 00 00 02 E0 00 00 00 54  00 00 03 34 00 00 00 2C  |.......T...4...,|
0x0180: 00 00 03 60 00 00 00 2C  00 00 03 8C 00 00 00 38  |...`...,.......8|
0x0190: 66 75 6E 63 00 00 00 00  00 00 00 26 69 6E 20 20  |func.......&in  |
0x01A0: 00 00 00 02 64 61 74 61  40 0C C0 00 67 61 6D 61  |....data@...gama|
0x01B0: 00 02 00 00 74 73 61 76  00 00 00 02 64 61 74 61  |....tsav....data|
0x01C0: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x01D0: 00 00 00 00 65 71 20 20  00 02 00 00 73 75 6D 20  |....eq  ....sum |
0x01E0: 00 01 00 00 64 61 74 61  40 40 00 00 65 71 20 20  |....data@@..eq  |
0x01F0: 00 00 00 00 69 66 20 20  00 00 00 07 64 61 74 61  |....if  ....data|
0x0200: 3F 80 00 00 64 61 74 61  40 00 00 00 74 70 75 74  |?...data@...tput|
0x0210: 00 05 00 01 64 61 74 61  3F 80 00 00 74 70 75 74  |....data?...tput|
0x0220: 00 07 00 00 61 73 69 6E  00 00 00 00 70 6F 70 20  |....asin....pop |
0x0230: 00 00 00 00 74 67 65 74  00 00 00 02 64 61 74 61  |....tget....data|
0x0240: 3F 13 A0 8E 64 61 74 61  3E 3E 03 0D 64 61 74 61  |?...data>>..data|
0x0250: 3E 40 BE C7 6D 75 6C 20  00 02 00 00 73 75 6D 20  |>@..mul ....sum |
0x0260: 00 01 00 00 74 67 65 74  00 00 00 02 64 61 74 61  |....tget....data|
0x0270: 3E 98 3D 5C 64 61 74 61  3F 20 9A D1 64 61 74 61  |>.=\data? ..data|
0x0280: 3D 9A 30 7F 6D 75 6C 20  00 02 00 00 73 75 6D 20  |=.0.mul ....sum |
0x0290: 00 01 00 00 74 67 65 74  00 00 00 02 64 61 74 61  |....tget....data|
0x02A0: 3C DD 74 59 64 61 74 61  3D 90 C5 0F 64 61 74 61  |<.tYdata=...data|
0x02B0: 3F 7D C8 A1 6D 75 6C 20  00 02 00 00 73 75 6D 20  |?}..mul ....sum |
0x02C0: 00 01 00 00 6F 75 74 20  00 00 00 02 63 76 73 74  |....out ....cvst|
0x02D0: 00 00 00 00 00 03 00 03  00 00 00 24 00 00 00 28  |...........$...(|
0x02E0: 00 00 00 4C 00 00 00 28  00 00 00 74 00 00 00 28  |...L...(...t...(|
0x02F0: 63 75 72 66 00 00 00 00  00 01 00 00 70 61 72 66  |curf........parf|
0x0300: 00 00 00 00 00 00 00 00  3F 80 00 00 3F 00 00 00  |........?...?...|
0x0310: 00 00 00 00 00 00 00 00  63 75 72 66 00 00 00 00  |........curf....|
0x0320: 00 01 00 00 70 61 72 66  00 00 00 00 00 00 00 00  |....parf........|
0x0330: 3F 80 00 00 3F 80 00 00  00 00 00 00 00 00 00 00  |?...?...........|
0x0340: 63 75 72 66 00 00 00 00  00 01 00 00 70 61 72 66  |curf........parf|
0x0350: 00 00 00 00 00 00 00 00  3F 80 00 00 3F C0 00 00  |........?...?...|
0x0360: 00 00 00 00 00 00 00 00  6D 61 74 66 00 00 00 00  |........matf....|
0x0370: 00 03 00 03 3F 80 00 00  3F 80 00 00 BF 80 00 00  |....?...?.......|
0x0380: 40 00 00 00 3F 80 00 00  BF 80 00 00 3F 80 00 00  |@...?.......?...|
0x0390: BF 80 00 00 3F 80 00 00  00 00 00 00 00 00 00 00  |....?...........|
0x03A0: 00 00 00 00 63 6C 75 74  00 00 00 00 00 03 00 03  |....clut........|
0x03B0: 02 02 02 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x03C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x03D0: 00 00 00 00 3F 40 00 00  00 00 00 00 3F 00 00 00  |....?@......?...|
0x03E0: 00 00 00 00 00 00 00 00  3F 00 00 00 3F 40 00 00  |........?...?@..|
0x03F0: 3E 80 00 00 00 00 00 00  00 00 00 00 3E 80 00 00  |>...........>...|
0x0400: 00 00 00 00 3F 40 00 00  3E 80 00 00 3F 00 00 00  |....?@..>...?...|
0x0410: 00 00 00 00 3E 80 00 00  3F 00 00 00 3F 40 00 00  |....>...?...?@..|
0x0420: 63 61 6C 63 00 00 00 00  00 03 00 03 00 00 00 00  |calc............|
0x0430: 00 00 00 18 00 00 00 3C  66 75 6E 63 00 00 00 00  |.......<func....|
0x0440: 00 00 00 06 69 6E 20 20  00 00 00 02 64 61 74 61  |....in  ....data|
0x0450: 3F 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |?...data?...data|
0x0460: 3F 80 00 00 61 64 64 20  00 02 00 00 6F 75 74 20  |?...add ....out |
0x0470: 00 00 00 02 4A 74 6F 58  00 00 00 00 00 03 00 03  |....JtoX........|
0x0480: 3F 76 D5 D0 3F 80 00 00  3F 53 2C A5 43 FA 00 00  |?v..?...?S,.C...|
0x0490: 41 A0 00 00 3F 30 A3 D7  3F 80 00 00 3F 80 00 00  |A...?0..?...?...|
0x04A0: 58 74 6F 4A 00 00 00 00  00 03 00 03 3F 76 D5 D0  |XtoJ........?v..|
0x04B0: 3F 80 00 00 3F 53 2C A5  43 FA 00 00 41 A0 00 00  |?...?S,.C...A...|
0x04C0: 3F 30 A3 D7 3F 80 00 00  3F 80 00 00 74 69 6E 74  |?0..?...?...tint|
0x04D0: 00 00 00 00 00 01 00 03  66 6C 33 32 00 00 00 00  |........fl32....|
0x04E0: 3F 80 00 00 3F 80 00 00  BF 80 00 00 40 00 00 00  |?...?.......@...|
0x04F0: 3F 80 00 00 BF 80 00 00  3F 80 00 00 BF 80 00 00  |?.......?.......|
0x0500: 3F 80 00 00 6D 70 65 74  00 00 00 00 00 03 00 03  |?...mpet........|
0x0510: 00 00 00 01 00 00 00 18  00 00 03 C4 63 61 6C 63  |............calc|
0x0520: 00 00 00 00 00 03 00 03  00 00 00 07 00 00 00 50  |...............P|
0x0530: 00 00 01 8C 00 00 01 8C  00 00 00 9C 00 00 02 28  |...............(|
0x0540: 00 00 00 3C 00 00 02 64  00 00 00 7C 00 00 02 E0  |...<...d...|....|
0x0550: 00 00 00 54 00 00 03 34  00 00 00 2C 00 00 03 60  |...T...4...,...`|
0x0560: 00 00 00 2C 00 00 03 8C  00 00 00 38 66 75 6E 63  |...,.......8func|
0x0570: 00 00 00 00 00 00 00 26  69 6E 20 20 00 00 00 02  |.......&in  ....|
0x0580: 74 73 61 76 00 00 00 02  64 61 74 61 00 00 00 00  |tsav....data....|
0x0590: 64 61 74 61 00 00 00 00  64 61 74 61 00 00 00 00  |data....data....|
0x05A0: 65 71 20 20 00 02 00 00  73 75 6D 20 00 01 00 00  |eq  ....sum ....|
0x05B0: 64 61 74 61 40 40 00 00  65 71 20 20 00 00 00 00  |data@@..eq  ....|
0x05C0: 69 66 20 20 00 00 00 07  64 61 74 61 3F 80 00 00  |if  ....data?...|
0x05D0: 64 61 74 61 40 00 00 00  74 70 75 74 00 05 00 01  |data@...tput....|
0x05E0: 64 61 74 61 3F 80 00 00  74 70 75 74 00 07 00 00  |data?...tput....|
0x05F0: 61 73 69 6E 00 00 00 00  70 6F 70 20 00 00 00 00  |asin....pop ....|
0x0600: 74 67 65 74 00 00 00 02  64 61 74 61 40 02 A9 69  |tget....data@..i|
0x0610: 64 61 74 61 BF 10 A4 7F  64 61 74 61 BE B0 80 73  |data....data...s|
0x0620: 6D 75 6C 20 00 02 00 00  73 75 6D 20 00 01 00 00  |mul ....sum ....|
0x0630: 69 6E 20 20 00 00 00 02  64 61 74 61 BF 78 20 1D  |in  ....data.x .|
0x0640: 64 61 74 61 3F F0 1F C9  64 61 74 61 3D 2A 3A D2  |data?...data=*:.|
0x0650: 6D 75 6C 20 00 02 00 00  73 75 6D 20 00 01 00 00  |mul ....sum ....|
0x0660: 69 6E 20 20 00 00 00 02  64 61 74 61 3C 5C 33 72  |in  ....data<\3r|
0x0670: 64 61 74 61 BD F2 66 BA  64 61 74 61 3F 81 F1 17  |data..f.data?...|
0x0680: 6D 75 6C 20 00 02 00 00  73 75 6D 20 00 01 00 00  |mul ....sum ....|
0x0690: 64 61 74 61 3E E8 CF 59  67 61 6D 61 00 02 00 00  |data>..Ygama....|
0x06A0: 6F 75 74 20 00 00 00 02  63 76 73 74 00 00 00 00  |out ....cvst....|
0x06B0: 00 03 00 03 00 00 00 24  00 00 00 28 00 00 00 4C  |.......$...(...L|
0x06C0: 00 00 00 28 00 00 00 74  00 00 00 28 63 75 72 66  |...(...t...(curf|
0x06D0: 00 00 00 00 00 01 00 00  70 61 72 66 00 00 00 00  |........parf....|
0x06E0: 00 00 00 00 3F 80 00 00  3F 00 00 00 00 00 00 00  |....?...?.......|
0x06F0: 00 00 00 00 63 75 72 66  00 00 00 00 00 01 00 00  |....curf........|
0x0700: 70 61 72 66 00 00 00 00  00 00 00 00 3F 80 00 00  |parf........?...|
0x0710: 3F 80 00 00 00 00 00 00  00 00 00 00 63 75 72 66  |?...........curf|
0x0720: 00 00 00 00 00 01 00 00  70 61 72 66 00 00 00 00  |........parf....|
0x0730: 00 00 00 00 3F 80 00 00  3F C0 00 00 00 00 00 00  |....?...?.......|
0x0740: 00 00 00 00 6D 61 74 66  00 00 00 00 00 03 00 03  |....matf........|
0x0750: 3F 80 00 00 3F 80 00 00  BF 80 00 00 40 00 00 00  |?...?.......@...|
0x0760: 3F 80 00 00 BF 80 00 00  3F 80 00 00 BF 80 00 00  |?.......?.......|
0x0770: 3F 80 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |?...............|
0x0780: 63 6C 75 74 00 00 00 00  00 03 00 03 02 02 02 00  |clut............|
0x0790: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x07A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x07B0: 3F 40 00 00 00 00 00 00  3F 00 00 00 00 00 00 00  |?@......?.......|
0x07C0: 00 00 00 00 3F 00 00 00  3F 40 00 00 3E 80 00 00  |....?...?@..>...|
0x07D0: 00 00 00 00 00 00 00 00  3E 80 00 00 00 00 00 00  |........>.......|
0x07E0: 3F 40 00 00 3E 80 00 00  3F 00 00 00 00 00 00 00  |?@..>...?.......|
0x07F0: 3E 80 00 00 3F 00 00 00  3F 40 00 00 63 61 6C 63  |>...?...?@..calc|
0x0800: 00 00 00 00 00 03 00 03  00 00 00 00 00 00 00 18  |................|
0x0810: 00 00 00 3C 66 75 6E 63  00 00 00 00 00 00 00 06  |...<func........|
0x0820: 69 6E 20 20 00 00 00 02  64 61 74 61 3F 80 00 00  |in  ....data?...|
0x0830: 64 61 74 61 3F 80 00 00  64 61 74 61 3F 80 00 00  |data?...data?...|
0x0840: 61 64 64 20 00 02 00 00  6F 75 74 20 00 00 00 02  |add ....out ....|
0x0850: 4A 74 6F 58 00 00 00 00  00 03 00 03 3F 76 D5 D0  |JtoX........?v..|
0x0860: 3F 80 00 00 3F 53 2C A5  43 FA 00 00 41 A0 00 00  |?...?S,.C...A...|
0x0870: 3F 30 A3 D7 3F 80 00 00  3F 80 00 00 58 74 6F 4A  |?0..?...?...XtoJ|
0x0880: 00 00 00 00 00 03 00 03  3F 76 D5 D0 3F 80 00 00  |........?v..?...|
0x0890: 3F 53 2C A5 43 FA 00 00  41 A0 00 00 3F 30 A3 D7  |?S,.C...A...?0..|
0x08A0: 3F 80 00 00 3F 80 00 00  74 69 6E 74 00 00 00 00  |?...?...tint....|
0x08B0: 00 01 00 03 66 6C 33 32  00 00 00 00 3F 80 00 00  |....fl32....?...|
0x08C0: 3F 80 00 00 BF 80 00 00  40 00 00 00 3F 80 00 00  |?.......@...?...|
0x08D0: BF 80 00 00 3F 80 00 00  BF 80 00 00 3F 80 00 00  |....?.......?...|
0x08E0: 6D 70 65 74 00 00 00 00  00 03 00 03 00 00 00 01  |mpet............|
0x08F0: 00 00 00 18 00 00 00 3C  6D 61 74 66 00 00 00 00  |.......<matf....|
0x0900: 00 03 00 03 3F 93 79 27  BD 7F 06 97 BD 80 E0 11  |....?.y'........|
0x0910: 3D CA 96 ED 3F 6F 1F 3E  BC D3 53 DB BC E8 61 EF  |=...?o.>..S...a.|
0x0920: 3D 0E 18 47 3F 40 14 F8  00 00 00 00 00 00 00 00  |=..G?@..........|
0x0930: 00 00 00 00 6D 70 65 74  00 00 00 00 00 03 00 03  |....mpet........|
0x0940: 00 00 00 01 00 00 00 18  00 00 00 3C 6D 61 74 66  |...........<matf|
0x0950: 00 00 00 00 00 03 00 03  3F 5D 75 71 3D 60 DD 1E  |........?]uq=`..|
0x0960: 3D 98 73 6C BD B9 89 BF  3F 88 1F BD 3C ED 48 91  |=.sl....?...<.H.|
0x0970: 3D 17 1E 44 BD 40 E5 B3  3F AA C8 5F 00 00 00 00  |=..D.@..?.._....|
0x0980: 00 00 00 00 00 00 00 00  73 76 63 6E 00 00 00 00  |........svcn....|
0x0990: 00 00 00 01 5D F0 62 18  00 51 00 00 3A B3 4E 77  |....].b..Q..:.Nw|
0x09A0: 3B 12 89 DB 3B 8B 08 DD  3B FA AC DA 3C 6A 74 7E  |;...;...;...<jt~|
0x09B0: 3C BD F8 F4 3D 32 37 8B  3D 9E FC 7A 3E 09 9A E9  |<...=27.=..z>...|
0x09C0: 3E 5B EC AB 3E 91 5B 57  3E A8 31 27 3E B2 51 C2  |>[..>.[W>.1'>.Q.|
0x09D0: 3E B2 34 EC 3E AC 22 68  3E A3 2C A5 3E 94 E3 BD  |>.4.>."h>.,.>...|
0x09E0: 3E 80 90 2E 3E 48 0C 74  3E 11 82 AA 3D C3 DE E8  |>...>H.t>...=...|
0x09F0: 3D 6D 5C FB 3D 03 1C EB  3C 70 D8 45 3B A0 90 2E  |=m\.=...<p.E;...|
0x0A00: 3B 1D 49 52 3C 18 5F 07  3C EE 63 20 3D 81 93 B4  |;.IR<._.<.c =...|
0x0A10: 3D E0 75 F7 3E 29 78 D5  3E 67 2B 02 3E 94 AF 4F  |=.u.>)x.>g+.>..O|
0x0A20: 3E B8 2A 99 3E DD ED 29  3F 03 15 B5 3F 18 31 27  |>.*.>..)?...?.1'|
0x0A30: 3F 2D AB 9F 3F 43 18 FC  3F 57 AE 14 3F 6A 92 A3  |?-..?C..?W..?j..|
0x0A40: 3F 7A 85 88 3F 83 5D CC  3F 87 41 F2 3F 87 F6 2B  |?z..?.].?.A.?..+|
0x0A50: 3F 85 D6 39 3F 80 55 32  3F 70 3A FB 3F 5A BD 3C  |?..9?.U2?p:.?Z.<|
0x0A60: 3F 40 5B C0 3F 24 74 54  3F 0A B9 F5 3E E5 53 26  |?@[.?$tT?...>.S&|
0x0A70: 3E B8 BA C7 3E 91 26 E9  3E 5F F2 E5 3E 28 DB 8C  |>...>.&.>_..>(..|
0x0A80: 3D F8 37 B5 3D B2 FE C5  3D 82 40 B8 3D 3F 91 E6  |=.7.=...=.@.=?..|
0x0A90: 3D 06 C2 27 3C B9 F5 5A  3C 81 C2 E3 3C 3A 1B 19  |=..'<..Z<...<:..|
0x0AA0: 3C 04 E4 00 3B BD BA 0A  3B 86 A4 CA 3B 3D FD 26  |<...;...;...;=.&|
0x0AB0: 3B 06 48 84 3A BC BE 62  3A 83 12 6F 3A 34 E1 1E  |;.H.:..b:..o:4..|
0x0AC0: 39 F9 8F A3 39 AE 10 49  39 76 6A 55 39 2E 10 49  |9...9..I9vjU9..I|
0x0AD0: 38 F5 5D E6 38 AE 10 49  38 77 76 C5 38 30 29 28  |8.].8..I8wv.80)(|
0x0AE0: 38 23 93 EE 38 86 37 BD  38 FB A8 82 39 63 8A 7E  |8#..8.7.8...9c.~|
0x0AF0: 39 CF 9E 38 3A 27 C5 AC  3A 9E 98 DD 3B 0E DE 55  |9..8:'..:...;..U|
0x0B00: 3B 83 12 6F 3B EF 34 D7  3C 3E 0D ED 3C 89 F4 0A  |;..o;.4.<>..<...|
0x0B10: 3C BC 6A 7F 3C F4 1F 21  3D 1B A5 E3 3D 44 9B A6  |<.j.<..!=...=D..|
0x0B20: 3D 75 C2 8F 3D 97 58 E2  3D BA 53 B9 3D E6 9A D4  |=u..=.X.=.S.=...|
0x0B30: 3E 0E 5B 42 3E 2D 5C FB  3E 55 03 32 3E 84 67 38  |>.[B>-\.>U.2>.g8|
0x0B40: 3E A5 60 42 3E D0 89 A0  3F 00 C4 9C 3F 1B B2 FF  |>.`B>...?...?...|
0x0B50: 3F 35 C2 8F 3F 4B 0F 28  3F 5C AC 08 3F 6A 33 9C  |?5..?K.(?\..?j3.|
0x0B60: 3F 74 39 58 3F 7A F4 F1  3F 7E B5 0B 3F 80 00 00  |?t9X?z..?~..?...|
0x0B70: 3F 7E B8 52 3F 7A 85 88  3F 73 B6 46 3F 6A 57 A8  |?~.R?z..?s.F?jW.|
0x0B80: 3F 5E B8 52 3F 50 F9 09  3F 41 CA C1 3F 31 E4 F7  |?^.R?P..?A..?1..|
0x0B90: 3F 21 89 37 3F 11 19 CE  3F 00 C4 9C 3E E1 E4 F7  |?!.7?...?...>...|
0x0BA0: 3E C3 12 6F 3E A4 5A 1D  3E 87 AE 14 3E 5E 35 3F  |>..o>.Z.>...>^5?|
0x0BB0: 3E 33 33 33 3E 0D 84 4D  3D DB 22 D1 3D A7 1D E7  |>333>..M=.".=...|
0x0BC0: 3D 79 DB 23 3D 36 99 85  3D 03 12 6F 3C BE 0D ED  |=y.#=6..=..o<...|
0x0BD0: 3C 8B 43 96 3C 43 4C 1B  3C 06 83 3C 3B BB 88 01  |<.C.<CL.<..<;...|
0x0BE0: 3B 86 6A 12 3B 3F F4 77  3B 09 09 29 3A C2 82 C7  |;.j.;?.w;..):...|
0x0BF0: 3A 89 3B 7E 3A 41 FC 8F  3A 08 50 9C 39 BD 44 9A  |:.;~:A..:.P.9.D.|
0x0C00: 39 82 8C 37 39 34 5A E6  38 FB A8 82 38 B2 42 07  |9..794Z.8...8.B.|
0x0C10: 38 7B A8 82 38 30 29 28  37 FB A8 82 37 B0 29 28  |8{..80)(7...7.)(|
0x0C20: 37 7B A8 82 3B D3 5A 86  3C 2C D9 E8 3C A4 3F E6  |7{..;.Z.<,..<.?.|
0x0C30: 3D 14 50 F0 3D 8A F4 F1  3D E1 B0 8A 3E 54 60 AA  |=.P.=...=...>T`.|
0x0C40: 3E BE 1B 09 3F 25 46 0B  3F 84 FF 97 3F B1 5B 57  |>...?%F.?...?.[W|
0x0C50: 3F CF BD 27 3F DF 9F A9  3F E4 2C 3D 3F E2 D4 80  |?..'?...?.,=?...|
0x0C60: 3F DF 3E AB 3F D5 A8 58  3F C3 98 C8 3F A4 D1 63  |?.>.?..X?...?..c|
0x0C70: 3F 85 5C FB 3F 50 1D 7E  3F 1D BF 48 3E EE 2C 13  |?.\.?P.~?..H>.,.|
0x0C80: 3E B4 E3 BD 3E 8B 43 96  3E 59 65 2C 3E 21 FF 2E  |>...>.C.>Ye,>!..|
0x0C90: 3D E4 C2 F8 3D A0 41 89  3D 6A 7E FA 3D 2C AF F7  |=...=.A.=j~.=,..|
0x0CA0: 3C F4 73 04 3C A6 4C 30  3C 5B 8B AC 3C 0F 5C 29  |<.s.<.L0<[..<.\)|
0x0CB0: 3B BC 6A 7F 3B 7F 97 24  3B 34 39 58 3B 09 A0 27  |;.j.;..$;49X;..'|
0x0CC0: 3A EB ED FA 3A D8 44 D0  3A B7 80 34 3A 90 2D E0  |:...:.D.:..4:.-.|
0x0CD0: 3A 83 12 6F 3A 51 B7 17  3A 1D 49 52 39 B2 42 07  |:..o:Q..:.IR9.B.|
0x0CE0: 39 7B A8 82 39 47 3A BD  38 D1 B7 17 38 51 B7 17  |9{..9G:.8...8Q..|
0x0CF0: 37 FB A8 82 37 A7 C5 AC  37 27 C5 AC 00 00 00 00  |7...7...7'......|
0x0D00: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D10: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D20: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D30: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D40: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D50: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D60: 00 00 00 00 00 00 00 00  00 00 00 02 45 CB 20 00  |............E. .|
0x0D70: 5D F0 62 18 00 51 00 00  42 47 E6 E9 42 51 3F 48  |].b..Q..BG..BQ?H|
0x0D80: 42 5A 97 C2 42 89 67 2B  42 A5 82 82 42 AE 3D A5  |BZ..B.g+B...B.=.|
0x0D90: 42 B6 F8 D5 42 B8 EA F5  42 BA DD 15 42 B4 1D 2F  |B...B...B...B../|
0x0DA0: 42 AD 5D 56 42 BF 8C 15  42 D1 BA E1 42 DD DF 3B  |B.]VB...B...B..;|
0x0DB0: 42 EA 04 19 42 EA D1 EC  42 EB 9F BE 42 E8 AC 08  |B...B...B...B...|
0x0DC0: 42 E5 B8 D5 42 E6 C8 B4  42 E7 D8 93 42 E0 BB E7  |B...B...B...B...|
0x0DD0: 42 D9 9F 3B 42 DA 29 FC  42 DA B5 3F 42 D9 27 F0  |B..;B.).B..?B.'.|
0x0DE0: 42 D7 9A A0 42 D4 97 8D  42 D1 94 7B 42 D4 7A 5E  |B...B...B..{B.z^|
0x0DF0: 42 D7 60 C5 42 D4 18 10  42 D0 CF 5C 42 D0 73 33  |B.`.B...B..\B.s3|
0x0E00: 42 D0 17 8D 42 CC 0B C7  42 C8 00 00 42 C4 55 8E  |B...B...B...B.U.|
0x0E10: 42 C0 AB 1C 42 C0 1F 48  42 BF 93 75 42 B8 79 3E  |B...B..HB..uB.y>|
0x0E20: 42 B1 5F 07 42 B2 B1 1A  42 B4 03 2D 42 B3 9A EE  |B._.B...B..-B...|
0x0E30: 42 B3 32 BD 42 B1 4C 3D  42 AF 65 BC 42 AA FC B9  |B.2.B.L=B.e.B...|
0x0E40: 42 A6 93 C3 42 A6 FC E0  42 A7 65 FE 42 A3 B9 DB  |B...B...B.e.B...|
0x0E50: 42 A0 0D B9 42 A0 3D CC  42 A0 6D E0 42 A2 7E 0E  |B...B.=.B.m.B.~.|
0x0E60: 42 A4 8E 3C 42 A0 8F DF  42 9C 91 83 42 94 01 62  |B..<B...B...B..b|
0x0E70: 42 8B 71 4E 42 8D 54 95  42 8F 37 DC 42 91 F5 3F  |B.qNB.T.B.7.B..?|
0x0E80: 42 94 B2 B0 42 87 F3 F8  42 76 6A 7F 42 83 7D 56  |B...B...Bvj.B.}V|
0x0E90: 42 8B C5 6D 42 90 F8 FC  42 96 2C 8B 42 8A AD FA  |B..mB...B.,.B...|
0x0EA0: 42 7E 5E ED 42 5C 05 88  42 39 AC 3D 42 62 72 7C  |B~^.B\..B9.=Bbr||
0x0EB0: 42 85 9C 5D 42 82 30 2E  42 7D 87 FD 42 BE 19 9A  |B..]B.0.B}..B...|
0x0EC0: 42 C8 00 00 42 D9 D1 EC  42 BE 19 9A 42 C8 00 00  |B...B...B...B...|
0x0ED0: 42 D9 D1 EC 58 59 5A 20  00 00 00 00 00 00 F3 54  |B...XYZ .......T|
0x0EE0: 00 01 00 00 00 01 16 CF  6D 6C 75 63 00 00 00 00  |........mluc....|
0x0EF0: 00 00 00 01 00 00 00 0C  65 6E 55 53 00 00 00 5A  |........enUS...Z|
0x0F00: 00 00 00 1C 00 43 00 6F  00 70 00 79 00 72 00 69  |.....C.o.p.y.r.i|
0x0F10: 00 67 00 68 00 74 00 20  00 32 00 30 00 31 00 38  |.g.h.t. .2.0.1.8|
0x0F20: 00 20 00 49 00 6E 00 74  00 65 00 72 00 6E 00 61  |. .I.n.t.e.r.n.a|
0x0F30: 00 74 00 69 00 6F 00 6E  00 61 00 6C 00 20 00 43  |.t.i.o.n.a.l. .C|
0x0F40: 00 6F 00 6C 00 6F 00 72  00 20 00 43 00 6F 00 6E  |.o.l.o.r. .C.o.n|
0x0F50: 00 73 00 6F 00 72 00 74  00 69 00 75 00 6D 00 00  |.s.o.r.t.i.u.m..|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 0**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/calcUnderStack_asin.icc

Device Class: 0x73706163

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [ ] [ ]  
  AToB1/BToA1 (Rel. Colorimetric): [[X]] [[X]]  [X] Round-trip capable
  AToB2/BToA2 (Saturation):        [ ] [ ]  

  DToB0/BToD0 (Perceptual):        [ ] [ ]  
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]  
  DToB2/BToD2 (Saturation):        [ ] [ ]  

  Matrix/TRC Tags:                 [ ]  

[OK] RESULT: Profile supports round-trip validation
```
