# ICC Profile Analysis Report

**Profile**: `test-profiles/CIccTagStruct-Read-recursive-stack-overflow.icc`
**File Size**: 1326 bytes
**Date**: 2026-02-28T18:05:48Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 2 | Error |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 1**

```
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x4e554c4c (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h: ColorSpace signature: 0x4e554c4c (Unknown)

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/runner/work/research/research/test-profiles/CIccTagStruct-Read-recursive-stack-overflow.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/runner/work/research/research/test-profiles/CIccTagStruct-Read-recursive-stack-overflow.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 720 bytes (0x000002D0)  [actual file: 1326 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x52474220 (RGB )
     [OK] Valid colorSpace: RgbData

[H4] PCS ColorSpace: 0x4E554C4C (NULL)
     [WARN]  HEURISTIC: Invalid PCS signature (must be Lab, XYZ, or spectral)
     Risk: Colorimetric transform failures
     Name: Unknown  Bytes: 'NULL'

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
Profile: /home/runner/work/research/research/test-profiles/CIccTagStruct-Read-recursive-stack-overflow.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/CIccTagStruct-Read-recursive-stack-overflow.icc
Result: NOT round-trip capable

=======================================================================
PHASE 3: SIGNATURE ANALYSIS
=======================================================================

[ERROR] Profile failed to load - skipping phases 3-5
        Use -n (ninja mode) for raw analysis of malformed profiles
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

File: /home/runner/work/research/research/test-profiles/CIccTagStruct-Read-recursive-stack-overflow.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 1326 bytes (0x52E)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 02 D0 4E 55 4C 4C  05 00 00 00 63 65 6E 63  |....NULL....cenc|
0x0010: 52 47 42 20 4E 55 4C 4C  00 00 00 00 00 00 00 00  |RGB NULL........|
0x0020: 00 00 00 00 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0050: 4E 55 4C 4C 00 00 00 02  00 00 F9 FF 00 00 00 00  |NULL............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 FD 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x000002D0 (720 bytes) MISMATCH
  CMM:             0x4E554C4C  'NULL'
  Version:         0x05000000
  Device Class:    0x63656E63  'cenc'
  Color Space:     0x52474220  'RGB '
  PCS:             0x4E554C4C  'NULL'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 3 (0x00000003)

Tag Table Raw Data:
0x0080: 00 00 00 03 72 66 6E 6D  00 00 00 A8 00 00 00 14  |....rfnm........|
0x0090: 63 73 70 6D 00 00 00 BC  00 00 00 10 63 65 70 74  |cspm........cept|
0x00A0: 00 00 00 CC 00 00 02 04                           |........|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x72666E6D   'rfnm'        0x000000A8   0x00000014   'utf8'        OK
1    0x6373706D   'cspm'        0x000000BC   0x00000010   'utf8'        OK
2    0x63657074   'cept'        0x000000CC   0x00000204   'tstr'        OK

=== FULL FILE HEX DUMP (all 1326 bytes) ===
0x0000: 00 00 02 D0 4E 55 4C 4C  05 00 00 00 63 65 6E 63  |....NULL....cenc|
0x0010: 52 47 42 20 4E 55 4C 4C  00 00 00 00 00 00 00 00  |RGB NULL........|
0x0020: 00 00 00 00 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0050: 4E 55 4C 4C 00 00 00 02  00 00 F9 FF 00 00 00 00  |NULL............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 FD 00  |................|
0x0080: 00 00 00 03 72 66 6E 6D  00 00 00 A8 00 00 00 14  |....rfnm........|
0x0090: 63 73 70 6D 00 00 00 BC  00 00 00 10 63 65 70 74  |cspm........cept|
0x00A0: 00 00 00 CC 00 00 02 04  75 74 66 38 00 00 00 00  |........utf8....|
0x00B0: 49 53 4F 20 32 32 30 32  38 2D 31 00 75 74 66 38  |ISO 22028-1.utf8|
0x00C0: 00 00 00 00 62 67 2D 73  52 47 42 00 74 73 74 72  |....bg-sRGB.tstr|
0x00D0: 00 00 00 00 63 65 70 74  00 00 00 0F 72 58 59 5A  |....cept....rXYZ|
0x00E0: 00 00 00 C4 00 00 00 14  67 58 59 5A 00 00 00 D8  |........gXYZ....|
0x00F0: 00 00 00 14 62 58 59 5A  00 00 00 EC 00 00 00 14  |....bXYZ........|
0x0100: 66 75 6E 63 00 00 01 00  00 00 00 70 77 6C 75 6D  |func.......pwlum|
0x0110: 00 00 01 70 00 00 00 0C  77 58 59 5A 00 00 01 80  |...p....wXYZ....|
0x0120: FF FF FF EF 9A AD 91 67  00 00 01 8C 00 00 10 62  |.......g.......b|
0x0130: 74 00 69 73 00 00 01 9C  00 00 00 0B 00 00 0F 60  |t.is...........`|
0x0140: 00 00 00 00 05 00 00 00  73 70 61 63 52 47 42 20  |........spacRGB |
0x0150: 58 59 5A 20 07 E2 00 08  00 0F 00 0A 00 16 00 12  |XYZ ............|
0x0160: 61 63 73 70 00 00 00 00  00 00 00 00 00 00 00 00  |acsp............|
0x0170: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 01  |................|
0x0180: 00 00 F3 54 00 01 00 00  00 01 16 CF 49 43 43 20  |...T........ICC |
0x0190: C4 FB ED B9 C0 11 C2 D3  0E 3B A1 B1 D7 A0 7A 00  |.........;....z.|
0x01A0: 17 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x01B0: 00 00 00 00 00 00 50 30  00 1A F2 DC 00 00 00 00  |......P0........|
0x01C0: 00 00 00 00 00 00 00 08  64 65 73 63 00 00 00 00  |........desc....|
0x01D0: 4E 55 4C 4C 00 00 00 00  00 00 00 00 00 00 00 00  |NULL............|
0x01E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x01F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 FD 00  |................|
0x0200: 00 00 00 03 72 66 6E 6D  00 00 00 A8 00 00 00 14  |....rfnm........|
0x0210: 63 73 6E 6D 00 00 00 BC  00 00 00 10 63 65 70 74  |csnm........cept|
0x0220: 00 00 00 CC 00 00 02 04  75 74 66 38 00 00 00 00  |........utf8....|
0x0230: 49 53 4F 20 32 32 30 32  38 2D 31 00 75 74 66 38  |ISO 22028-1.utf8|
0x0240: 00 00 00 00 62 67 2D 73  52 47 42 00 74 73 74 72  |....bg-sRGB.tstr|
0x0250: 00 00 00 00 63 65 70 74  00 00 00 0F 72 58 59 5A  |....cept....rXYZ|
0x0260: 00 00 00 C4 00 00 00 14  67 58 59 5A 00 00 00 D8  |........gXYZ....|
0x0270: 00 00 00 14 62 58 59 5A  00 00 00 EC 00 00 00 14  |....bXYZ........|
0x0280: 66 75 6E 63 00 00 01 00  00 00 00 70 77 6C 75 6D  |func.......pwlum|
0x0290: 00 00 01 70 00 00 00 0C  77 58 59 AB FF FF FE 80  |...p....wXY.....|
0x02A0: FF DF 74 72 00 AD 91 67  00 00 01 8C 00 00 00 10  |..tr...g........|
0x02B0: 62 69 74 73 00 00 01 9C  00 00 00 3B A1 B1 D7 A0  |bits.......;....|
0x02C0: 7A 00 17 00 00 00 00 00  00 00 00 00 00 00 00 00  |z...............|
0x02D0: 00 66 6C 33 32 00 00 00  00 40 83 33 33 66 6C 33  |.fl32....@.33fl3|
0x02E0: 32 00 00 00 00 42 80 00  00 66 6C 33 32 00 00 00  |2....B...fl32...|
0x02F0: 00 42 A0 3F 4A 3D 71 64  72 64 69 00 00 00 00 00  |.B.?J=qdrdi.....|
0x0300: 03 00 00 BB 4D 2E E4 C4  B2 CB 1C 70 61 38 00 00  |....M......pa8..|
0x0310: 00 00 62 67 2D 73 52 47  42 00 74 73 74 72 00 00  |..bg-sRGB.tstr..|
0x0320: 00 00 63 65 70 74 00 00  00 0F 72 58 59 5A 00 00  |..cept....rXYZ..|
0x0330: 00 C4 00 00 00 14 67 58  59 5A 92 00 00 00 D8 00  |......gXYZ......|
0x0340: 00 00 14 62 58 59 5A 00  00 00 EC 00 00 00 14 66  |...bXYZ........f|
0x0350: 75 6E 63 00 00 01 00 00  00 00 70 77 6C 75 6D 00  |unc.......pwlum.|
0x0360: 00 01 70 00 00 01 14 00  76 2C 00 00 70 64 65 73  |..p.....v,..pdes|
0x0370: 63 00 00 01 84 00 00 00  3C 77 74 70 74 00 00 01  |c.......<wtpt...|
0x0380: C0 00 00 00 14 41 32 42  30 00 00 01 D4 00 00 00  |.....A2B0.......|
0x0390: 84 41 32 42 32 00 00 01  D4 00 00 00 84 41 32 42  |.A2B2........A2B|
0x03A0: 31 00 00 02 58 00 00 00  EC 42 32 41 30 00 00 03  |1...X....B2A0...|
0x03B0: 44 00 00 00 EC 42 32 41  32 00 00 03 44 00 00 00  |D....B2A2...D...|
0x03C0: EC 42 32 41 31 00 00 04  30 00 00 00 EC 73 76 63  |.B2A1...0....svc|
0x03D0: 81 34 1B 00 80 51 00 00  6E 00 00 05 1C 00 00 00  |.4...Q..n.......|
0x03E0: 2C 74 65 63 68 00 00 05  48 00 00 00 0C 63 69 69  |,tech...H....cii|
0x03F0: 73 00 00 05 54 00 00 00  0C 6D 6C 75 63 00 00 00  |s...T....mluc...|
0x0400: 00 00 00 00 01 00 00 00  FF FF 63 61 53 00 00 00  |..........caS...|
0x0410: 54 00 00 00 1C 77 6C 75  6D 00 00 01 70 00 00 01  |T....wlum...p...|
0x0420: 14 00 76 2C 3D 00 00 70  64 65 73 63 00 00 01 84  |..v,=..pdesc....|
0x0430: 00 00 00 3C 77 74 70 74  00 00 01 C0 00 00 00 14  |...<wtpt........|
0x0440: 41 32 42 30 00 00 01 D4  00 00 00 84 41 32 42 32  |A2B0........A2B2|
0x0450: 00 00 01 D4 00 00 00 84  41 32 42 31 00 00 02 58  |........A2B1...X|
0x0460: 00 00 00 EC 42 32 41 30  00 00 03 44 00 00 00 EC  |....B2A0...D....|
0x0470: 42 32 41 32 00 00 03 44  00 00 00 EC 42 32 41 31  |B2A2...D....B2A1|
0x0480: 00 00 04 30 00 00 00 EC  73 76 63 6E 00 00 00 84  |...0....svcn....|
0x0490: 41 32 42 31 00 00 02 58  00 00 00 EC 42 32 41 30  |A2B1...X....B2A0|
0x04A0: 00 00 03 56 00 00 00 44  00 00 00 EC 42 32 41 32  |...V...D....B2A2|
0x04B0: 00 00 03 44 00 00 00 EC  42 32 41 31 00 00 04 30  |...D....B2A1...0|
0x04C0: 00 00 00 EC 73 76 63 6E  00 00 05 1C 00 00 00 2C  |....svcn.......,|
0x04D0: 74 65 63 68 00 00 05 48  00 00 00 0C 63 69 69 73  |tech...H....ciis|
0x04E0: 00 00 05 54 00 00 00 0C  6D 6C 75 63 00 00 00 00  |...T....mluc....|
0x04F0: 00 00 00 01 00 00 00 FF  FF 63 61 53 00 00 00 54  |.........caS...T|
0x0500: 00 00 00 1C 77 6C 75 6D  00 00 01 70 00 00 01 14  |....wlum...p....|
0x0510: 00 76 2C 00 00 70 64 65  43 43 20 6D AB 72 00 74  |.v,..pdeCC m.r.t|
0x0520: 00 69 00 75 00 00 6D 00  00 62 73 65 64 00        |.i.u..m..bsed.|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/CIccTagStruct-Read-recursive-stack-overflow.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/CIccTagStruct-Read-recursive-stack-overflow.icc
```
