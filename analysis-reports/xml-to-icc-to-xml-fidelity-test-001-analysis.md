# ICC Profile Analysis Report

**Profile**: `test-profiles/xml-to-icc-to-xml-fidelity-test-001.icc`
**File Size**: 1376 bytes
**Date**: 2026-02-15T18:40:41Z
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
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:344] IsValidTechnologySignature(): input = 0x76696463

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/runner/work/research/research/test-profiles/xml-to-icc-to-xml-fidelity-test-001.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/runner/work/research/research/test-profiles/xml-to-icc-to-xml-fidelity-test-001.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 1376 bytes (0x00000560)  [actual file: 1376 bytes]
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

[H7] Profile Class: 0x73636E72 (scnr)
     [OK] Known class: InputClass

[H8] Illuminant XYZ: (0.964203, 1.000000, 0.824905)
     [OK] Illuminant values within physical range

[H15] Date Validation: 2007-10-24 00:00:00
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

[H10] Tag Count: 12
      [OK] Tag count within normal range

[H11] CLUT Entry Limit Check
      Max safe CLUT entries per tag: 16777216 (16M)
      INFO: Profile has 12 tags
      Theoretical max CLUT: 201326592 entries (16777216 per tag)

[H12] MPE Chain Depth Limit
      Max MPE elements per chain: 1024
      Note: Full MPE analysis requires tag-level parsing
      [OK] Limit defined (1024 elements max)

[H13] Per-Tag Size Limit
      Max tag size: 64 MB (67108864 bytes)
      [OK] Theoretical max within limits: 805306368 bytes

[H14] TagArrayType Detection (UAF Risk)
      Checking for TagArrayType (0x74617279 = 'tary')
      Note: Tag signature ≠ tag type - must check tag DATA
      [OK] No TagArrayType tags detected

[H18] Technology Signature Validation
      [OK] Valid technology: VideoCamera

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
Profile: /home/runner/work/research/research/test-profiles/xml-to-icc-to-xml-fidelity-test-001.icc

Device Class: 0x73636E72

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [[X]] [[X]]  [X] Round-trip capable
  AToB1/BToA1 (Rel. Colorimetric): [[X]] [[X]]  [X] Round-trip capable
  AToB2/BToA2 (Saturation):        [[X]] [[X]]  [X] Round-trip capable

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
  Device Class:    0x73636E72  ''  InputClass
  Color Space:     0x52474220  'RGB '  RgbData
  PCS:             0x58595A20  'XYZ '  XYZData
  Manufacturer:    0x00000000  '....'
  Model:           0x00000000  '....'

Tag Signatures:
Idx  Tag          FourCC     Type         Issues
---  ------------ ---------- ------------ ------
0    copyrightTag 'cprt    '  multiLocalizedUnicodeType
1    profileDescriptionTag 'desc    '  multiLocalizedUnicodeType
2    mediaWhitePointTag 'wtpt    '  XYZArrayType
3    AToB0Tag     'A2B0    '  lutAtoBType 
4    AToB2Tag     'A2B2    '  lutAtoBType 
5    AToB1Tag     'A2B1    '  lutAtoBType 
6    BToA0Tag     'B2A0    '  lutBtoAType 
7    BToA2Tag     'B2A2    '  lutBtoAType 
8    BToA1Tag     'B2A1    '  lutBtoAType 
9    chromaticAdaptationTag 'chad    '  s15Fixed16ArrayType
10   technologyTag 'tech    '  signatureType
11   Unknown 'ciis' = 63696973 'ciis    '  signatureType

Summary: 0 signature issue(s) detected

=======================================================================
PHASE 4: PROFILE STRUCTURE DUMP
=======================================================================

=== ICC Profile Header ===

=== ICC Profile Header (0x0000-0x007F) ===
0x0000: 00 00 05 60 41 44 42 45  04 20 00 00 73 63 6E 72  |...`ADBE. ..scnr|
0x0010: 52 47 42 20 58 59 5A 20  07 D7 00 0A 00 18 00 00  |RGB XYZ ........|
0x0020: 00 00 00 00 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 41 44 42 45 D8 3D 88 36  75 28 11 67 B2 3A 43 57  |ADBE.=.6u(.g.:CW|
0x0060: E5 E0 04 5A 00 00 00 00  00 00 00 00 00 00 00 00  |...Z............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields:
  Size:            0x00000560 (1376 bytes)
  CMM:             ADBE
  Version:         0x04200000
  Device Class:    InputClass
  Color Space:     RgbData
  PCS:             XYZData

=== Tag Table ===

=== Tag Table ===
Tag Count: 12

Tag Table Raw Data (0x0080-0x0114):
0x0080: 00 00 00 0C 63 70 72 74  00 00 01 14 00 00 00 70  |....cprt.......p|
0x0090: 64 65 73 63 00 00 01 84  00 00 00 3C 77 74 70 74  |desc.......<wtpt|
0x00A0: 00 00 01 C0 00 00 00 14  41 32 42 30 00 00 01 D4  |........A2B0....|
0x00B0: 00 00 00 84 41 32 42 32  00 00 01 D4 00 00 00 84  |....A2B2........|
0x00C0: 41 32 42 31 00 00 02 58  00 00 00 EC 42 32 41 30  |A2B1...X....B2A0|
0x00D0: 00 00 03 44 00 00 00 EC  42 32 41 32 00 00 03 44  |...D....B2A2...D|
0x00E0: 00 00 00 EC 42 32 41 31  00 00 04 30 00 00 00 EC  |....B2A1...0....|
0x00F0: 63 68 61 64 00 00 05 1C  00 00 00 2C 74 65 63 68  |chad.......,tech|
0x0100: 00 00 05 48 00 00 00 0C  63 69 69 73 00 00 05 54  |...H....ciis...T|
0x0110: 00 00 00 0C                                       |....|

Tag Entries:
Idx  Signature    FourCC       Offset     Size
---  ------------ ------------ ---------- ----
0    copyrightTag 'cprt      '  0x00000114  112
1    profileDescriptionTag 'desc      '  0x00000184  60
2    mediaWhitePointTag 'wtpt      '  0x000001C0  20
3    AToB0Tag     'A2B0      '  0x000001D4  132
4    AToB2Tag     'A2B2      '  0x000001D4  132
5    AToB1Tag     'A2B1      '  0x00000258  236
6    BToA0Tag     'B2A0      '  0x00000344  236
7    BToA2Tag     'B2A2      '  0x00000344  236
8    BToA1Tag     'B2A1      '  0x00000430  236
9    chromaticAdaptationTag 'chad      '  0x0000051C  44
10   technologyTag 'tech      '  0x00000548  12
11   Unknown 'ciis' = 63696973 'ciis      '  0x00000554  12

=======================================================================
COMPREHENSIVE ANALYSIS SUMMARY
=======================================================================

File: /home/runner/work/research/research/test-profiles/xml-to-icc-to-xml-fidelity-test-001.icc
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

File: /home/runner/work/research/research/test-profiles/xml-to-icc-to-xml-fidelity-test-001.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 1376 bytes (0x560)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 05 60 41 44 42 45  04 20 00 00 73 63 6E 72  |...`ADBE. ..scnr|
0x0010: 52 47 42 20 58 59 5A 20  07 D7 00 0A 00 18 00 00  |RGB XYZ ........|
0x0020: 00 00 00 00 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 41 44 42 45 D8 3D 88 36  75 28 11 67 B2 3A 43 57  |ADBE.=.6u(.g.:CW|
0x0060: E5 E0 04 5A 00 00 00 00  00 00 00 00 00 00 00 00  |...Z............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x00000560 (1376 bytes) OK
  CMM:             0x41444245  'ADBE'
  Version:         0x04200000
  Device Class:    0x73636E72  'scnr'
  Color Space:     0x52474220  'RGB '
  PCS:             0x58595A20  'XYZ '

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 12 (0x0000000C)

Tag Table Raw Data:
0x0080: 00 00 00 0C 63 70 72 74  00 00 01 14 00 00 00 70  |....cprt.......p|
0x0090: 64 65 73 63 00 00 01 84  00 00 00 3C 77 74 70 74  |desc.......<wtpt|
0x00A0: 00 00 01 C0 00 00 00 14  41 32 42 30 00 00 01 D4  |........A2B0....|
0x00B0: 00 00 00 84 41 32 42 32  00 00 01 D4 00 00 00 84  |....A2B2........|
0x00C0: 41 32 42 31 00 00 02 58  00 00 00 EC 42 32 41 30  |A2B1...X....B2A0|
0x00D0: 00 00 03 44 00 00 00 EC  42 32 41 32 00 00 03 44  |...D....B2A2...D|
0x00E0: 00 00 00 EC 42 32 41 31  00 00 04 30 00 00 00 EC  |....B2A1...0....|
0x00F0: 63 68 61 64 00 00 05 1C  00 00 00 2C 74 65 63 68  |chad.......,tech|
0x0100: 00 00 05 48 00 00 00 0C  63 69 69 73 00 00 05 54  |...H....ciis...T|
0x0110: 00 00 00 0C                                       |....|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x63707274   'cprt'        0x00000114   0x00000070   'mluc'        OK
1    0x64657363   'desc'        0x00000184   0x0000003C   'mluc'        OK
2    0x77747074   'wtpt'        0x000001C0   0x00000014   'XYZ '        OK
3    0x41324230   'A2B0'        0x000001D4   0x00000084   'mAB '        OK
4    0x41324232   'A2B2'        0x000001D4   0x00000084   'mAB '        OK
5    0x41324231   'A2B1'        0x00000258   0x000000EC   'mAB '        OK
6    0x42324130   'B2A0'        0x00000344   0x000000EC   'mBA '        OK
7    0x42324132   'B2A2'        0x00000344   0x000000EC   'mBA '        OK
8    0x42324131   'B2A1'        0x00000430   0x000000EC   'mBA '        OK
9    0x63686164   'chad'        0x0000051C   0x0000002C   'sf32'        OK
10   0x74656368   'tech'        0x00000548   0x0000000C   'sig '        OK
11   0x63696973   'ciis'        0x00000554   0x0000000C   'sig '        OK

=== FULL FILE HEX DUMP (all 1376 bytes) ===
0x0000: 00 00 05 60 41 44 42 45  04 20 00 00 73 63 6E 72  |...`ADBE. ..scnr|
0x0010: 52 47 42 20 58 59 5A 20  07 D7 00 0A 00 18 00 00  |RGB XYZ ........|
0x0020: 00 00 00 00 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 41 44 42 45 D8 3D 88 36  75 28 11 67 B2 3A 43 57  |ADBE.=.6u(.g.:CW|
0x0060: E5 E0 04 5A 00 00 00 00  00 00 00 00 00 00 00 00  |...Z............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0080: 00 00 00 0C 63 70 72 74  00 00 01 14 00 00 00 70  |....cprt.......p|
0x0090: 64 65 73 63 00 00 01 84  00 00 00 3C 77 74 70 74  |desc.......<wtpt|
0x00A0: 00 00 01 C0 00 00 00 14  41 32 42 30 00 00 01 D4  |........A2B0....|
0x00B0: 00 00 00 84 41 32 42 32  00 00 01 D4 00 00 00 84  |....A2B2........|
0x00C0: 41 32 42 31 00 00 02 58  00 00 00 EC 42 32 41 30  |A2B1...X....B2A0|
0x00D0: 00 00 03 44 00 00 00 EC  42 32 41 32 00 00 03 44  |...D....B2A2...D|
0x00E0: 00 00 00 EC 42 32 41 31  00 00 04 30 00 00 00 EC  |....B2A1...0....|
0x00F0: 63 68 61 64 00 00 05 1C  00 00 00 2C 74 65 63 68  |chad.......,tech|
0x0100: 00 00 05 48 00 00 00 0C  63 69 69 73 00 00 05 54  |...H....ciis...T|
0x0110: 00 00 00 0C 6D 6C 75 63  00 00 00 00 00 00 00 01  |....mluc........|
0x0120: 00 00 00 0C 65 6E 55 53  00 00 00 54 00 00 00 1C  |....enUS...T....|
0x0130: 00 43 00 6F 00 70 00 79  00 72 00 69 00 67 00 68  |.C.o.p.y.r.i.g.h|
0x0140: 00 74 00 20 00 32 00 30  00 30 00 37 00 20 00 41  |.t. .2.0.0.7. .A|
0x0150: 00 64 00 6F 00 62 00 65  00 20 00 53 00 79 00 73  |.d.o.b.e. .S.y.s|
0x0160: 00 74 00 65 00 6D 00 73  00 20 00 49 00 6E 00 63  |.t.e.m.s. .I.n.c|
0x0170: 00 6F 00 72 00 70 00 6F  00 72 00 61 00 74 00 65  |.o.r.p.o.r.a.t.e|
0x0180: 00 64 00 00 6D 6C 75 63  00 00 00 00 00 00 00 01  |.d..mluc........|
0x0190: 00 00 00 0C 65 6E 55 53  00 00 00 20 00 00 00 1C  |....enUS... ....|
0x01A0: 00 48 00 44 00 54 00 56  00 20 00 28 00 52 00 65  |.H.D.T.V. .(.R.e|
0x01B0: 00 63 00 2E 00 20 00 37  00 30 00 39 00 29 00 00  |.c... .7.0.9.)..|
0x01C0: 58 59 5A 20 00 00 00 00  00 00 F6 D6 00 01 00 00  |XYZ ............|
0x01D0: 00 00 D3 2C 6D 41 42 20  00 00 00 00 03 01 00 00  |...,mAB ........|
0x01E0: 00 00 00 20 00 00 00 2C  00 00 00 5C 00 00 00 00  |... ...,...\....|
0x01F0: 00 00 00 00 63 75 72 76  00 00 00 00 00 00 00 00  |....curv........|
0x0200: 00 00 37 9F 00 00 31 1F  00 00 12 3F 00 00 1C 61  |..7...1....?...a|
0x0210: 00 00 5B 72 00 00 07 BB  00 00 01 C6 00 00 0C 62  |..[r...........b|
0x0220: 00 00 5B 10 00 00 00 6E  00 00 00 72 00 00 00 5E  |..[....n...r...^|
0x0230: 70 61 72 61 00 00 00 00  00 04 00 00 00 02 38 E4  |para..........8.|
0x0240: 00 00 E8 F0 00 00 17 10  00 00 38 E4 00 00 14 BC  |..........8.....|
0x0250: 00 00 00 00 00 00 00 00  6D 41 42 20 00 00 00 00  |........mAB ....|
0x0260: 03 03 00 00 00 00 00 20  00 00 00 44 00 00 00 74  |....... ...D...t|
0x0270: 00 00 00 00 00 00 00 00  63 75 72 76 00 00 00 00  |........curv....|
0x0280: 00 00 00 00 63 75 72 76  00 00 00 00 00 00 00 00  |....curv........|
0x0290: 63 75 72 76 00 00 00 00  00 00 00 00 00 00 37 D1  |curv..........7.|
0x02A0: 00 00 31 4B 00 00 12 50  00 00 1C 7B 00 00 5B C4  |..1K...P...{..[.|
0x02B0: 00 00 07 C2 00 00 01 C8  00 00 0C 6D 00 00 5B 61  |...........m..[a|
0x02C0: 00 00 00 00 00 00 00 00  00 00 00 00 70 61 72 61  |............para|
0x02D0: 00 00 00 00 00 04 00 00  00 02 38 E4 00 00 E8 F0  |..........8.....|
0x02E0: 00 00 17 10 00 00 38 E4  00 00 14 BC 00 00 00 00  |......8.........|
0x02F0: 00 00 00 00 70 61 72 61  00 00 00 00 00 04 00 00  |....para........|
0x0300: 00 02 38 E4 00 00 E8 F0  00 00 17 10 00 00 38 E4  |..8...........8.|
0x0310: 00 00 14 BC 00 00 00 00  00 00 00 00 70 61 72 61  |............para|
0x0320: 00 00 00 00 00 04 00 00  00 02 38 E4 00 00 E8 F0  |..........8.....|
0x0330: 00 00 17 10 00 00 38 E4  00 00 14 BC 00 00 00 00  |......8.........|
0x0340: 00 00 00 00 6D 42 41 20  00 00 00 00 03 03 00 00  |....mBA ........|
0x0350: 00 00 00 20 00 00 00 44  00 00 00 74 00 00 00 00  |... ...D...t....|
0x0360: 00 00 00 00 63 75 72 76  00 00 00 00 00 00 00 00  |....curv........|
0x0370: 63 75 72 76 00 00 00 00  00 00 00 00 63 75 72 76  |curv........curv|
0x0380: 00 00 00 00 00 00 00 00  00 06 4A 3B FF FC C1 2D  |..........J;...-|
0x0390: FF FF 03 E1 FF FE 09 25  00 03 D8 74 00 00 11 2F  |.......%...t.../|
0x03A0: 00 00 24 FE FF FF 8A 54  00 02 D2 43 FF FF FF 19  |..$....T...C....|
0x03B0: FF FF FF 1C FF FF FF 1B  70 61 72 61 00 00 00 00  |........para....|
0x03C0: 00 04 00 00 00 00 73 33  00 01 3B C0 00 00 00 00  |......s3..;.....|
0x03D0: 00 04 80 00 00 00 04 9C  FF FF E6 A8 00 00 00 00  |................|
0x03E0: 70 61 72 61 00 00 00 00  00 04 00 00 00 00 73 33  |para..........s3|
0x03F0: 00 01 3B C0 00 00 00 00  00 04 80 00 00 00 04 9C  |..;.............|
0x0400: FF FF E6 A8 00 00 00 00  70 61 72 61 00 00 00 00  |........para....|
0x0410: 00 04 00 00 00 00 73 33  00 01 3B C0 00 00 00 00  |......s3..;.....|
0x0420: 00 04 80 00 00 00 04 9C  FF FF E6 A8 00 00 00 00  |................|
0x0430: 6D 42 41 20 00 00 00 00  03 03 00 00 00 00 00 20  |mBA ........... |
0x0440: 00 00 00 44 00 00 00 74  00 00 00 00 00 00 00 00  |...D...t........|
0x0450: 63 75 72 76 00 00 00 00  00 00 00 00 63 75 72 76  |curv........curv|
0x0460: 00 00 00 00 00 00 00 00  63 75 72 76 00 00 00 00  |........curv....|
0x0470: 00 00 00 00 00 06 44 9F  FF FC C4 10 FF FF 04 C1  |......D.........|
0x0480: FF FE 0A E5 00 03 D5 08  00 00 11 20 00 00 24 DD  |........... ..$.|
0x0490: FF FF 8A BD 00 02 CF BF  00 00 00 00 00 00 00 00  |................|
0x04A0: 00 00 00 00 70 61 72 61  00 00 00 00 00 04 00 00  |....para........|
0x04B0: 00 00 73 33 00 01 3B C0  00 00 00 00 00 04 80 00  |..s3..;.........|
0x04C0: 00 00 04 9C FF FF E6 A8  00 00 00 00 70 61 72 61  |............para|
0x04D0: 00 00 00 00 00 04 00 00  00 00 73 33 00 01 3B C0  |..........s3..;.|
0x04E0: 00 00 00 00 00 04 80 00  00 00 04 9C FF FF E6 A8  |................|
0x04F0: 00 00 00 00 70 61 72 61  00 00 00 00 00 04 00 00  |....para........|
0x0500: 00 00 73 33 00 01 3B C0  00 00 00 00 00 04 80 00  |..s3..;.........|
0x0510: 00 00 04 9C FF FF E6 A8  00 00 00 00 73 66 33 32  |............sf32|
0x0520: 00 00 00 00 00 01 0C 42  00 00 05 DE FF FF F3 25  |.......B.......%|
0x0530: 00 00 07 93 00 00 FD 90  FF FF FB A1 FF FF FD A2  |................|
0x0540: 00 00 03 DC 00 00 C0 6E  73 69 67 20 00 00 00 00  |.......nsig ....|
0x0550: 76 69 64 63 73 69 67 20  00 00 00 00 66 70 63 65  |vidcsig ....fpce|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 0**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/xml-to-icc-to-xml-fidelity-test-001.icc

Device Class: 0x73636E72

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [[X]] [[X]]  [X] Round-trip capable
  AToB1/BToA1 (Rel. Colorimetric): [[X]] [[X]]  [X] Round-trip capable
  AToB2/BToA2 (Saturation):        [[X]] [[X]]  [X] Round-trip capable

  DToB0/BToD0 (Perceptual):        [ ] [ ]  
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]  
  DToB2/BToD2 (Saturation):        [ ] [ ]  

  Matrix/TRC Tags:                 [ ]  

[OK] RESULT: Profile supports round-trip validation
```
