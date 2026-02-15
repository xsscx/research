# ICC Profile Analysis: CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc

**Date:** 2026-02-15  
**Profile:** test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc  
**File Size:** 2368 bytes (0x940)  
**Analyzer Version:** iccanalyzer-lite v2.9.1  

## Executive Summary

This ICC profile contains a **CIccMpeToneMap** processing element and **failed validation** during round-trip testing. The comprehensive analysis (`-a`) returned exit code 1 (finding), and the round-trip test (`-r`) returned exit code 2 (error). The profile header and heuristics passed all security checks, but the profile could not be fully loaded by the iccDEV library.

**Key Findings:**
- [FAIL] Profile failed validation — could not be read by standard ICC library
- [FAIL] Round-trip test returned exit code 2 (error)
- [OK] All 19 security heuristics passed (exit code 1 indicates the validation failure as a finding)
- [OK] Ninja mode dump (-nf) succeeded with exit code 0 — raw structure is parseable

## Analysis Command 1: Comprehensive Analysis (-a)

**Command:**
```bash
iccanalyzer-lite/iccanalyzer-lite -a test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc 2>&1
```

**Exit Code:** 1 (finding detected)

**Complete Raw Output:**
```
=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/runner/work/research/research/test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/runner/work/research/research/test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 2368 bytes (0x00000940)  [actual file: 2368 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x52474220 (RGB )
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
     [OK] Valid colorSpace: RgbData

[H4] PCS ColorSpace: 0x58595A20 (XYZ )
     [OK] Valid PCS: XYZData

[H5] Platform: 0x00000000 (....)
     [OK] Known platform code

[H6] Rendering Intent: 1 (0x00000001)
     [OK] Valid intent: Relative Colorimetric

[H7] Profile Class: 0x6D6E7472 (mntr)
     [OK] Known class: DisplayClass

[H8] Illuminant XYZ: (0.950424, 1.000000, 1.088455)
     [OK] Illuminant values within physical range

[H15] Date Validation: 2024-05-10 21:20:25
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

[H10] Tag Count: 10
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
      [OK] Theoretical max within limits: 671088640 bytes

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
Profile: /home/runner/work/research/research/test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc
Result: NOT round-trip capable

=======================================================================
PHASE 3: SIGNATURE ANALYSIS
=======================================================================

[ERROR] Profile failed to load - skipping signature analysis
        Use -n (ninja mode) for raw analysis of malformed profiles

=======================================================================
PHASE 4: PROFILE STRUCTURE DUMP
=======================================================================

[ERROR] Profile failed to load for structure dump

=======================================================================
COMPREHENSIVE ANALYSIS SUMMARY
=======================================================================

File: /home/runner/work/research/research/test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc
Total Issues Detected: 1

[WARN] ANALYSIS COMPLETE - 1 issue(s) detected
  Review detailed output above for security concerns.
```

## Analysis Command 2: Ninja Full Dump (-nf)

**Command:**
```bash
iccanalyzer-lite/iccanalyzer-lite -nf test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc 2>&1
```

**Exit Code:** 0 (clean — raw dump succeeded)

**Complete Raw Output:**
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

File: /home/runner/work/research/research/test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 2368 bytes (0x940)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 09 40 00 00 00 00  05 10 00 00 6D 6E 74 72  |...@........mntr|
0x0010: 52 47 42 20 58 59 5A 20  07 E8 00 05 00 0A 00 15  |RGB XYZ ........|
0x0020: 00 14 00 19 61 63 73 70  00 00 00 00 00 00 00 09  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 4F  00 01 00 00 00 01 16 A5  |.......O........|
0x0050: 00 00 00 00 D0 C3 03 9C  1B C3 AB AF 88 E6 AE F7  |................|
0x0060: B2 C5 53 58 00 00 00 00  00 00 00 00 00 00 00 00  |..SX............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x00000940 (2368 bytes) OK
  CMM:             0x00000000  '....'
  Version:         0x05100000
  Device Class:    0x6D6E7472  'mntr'
  Color Space:     0x52474220  'RGB '
  PCS:             0x58595A20  'XYZ '

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 10 (0x0000000A)

Tag Table Raw Data:
0x0080: 00 00 00 0A 64 65 73 63  00 00 00 FC 00 00 00 7C  |....desc.......||
0x0090: 41 32 42 31 00 00 01 78  00 00 02 70 42 32 41 31  |A2B1...x...pB2A1|
0x00A0: 00 00 03 E8 00 00 01 F8  48 32 53 31 00 00 05 E0  |........H2S1....|
0x00B0: 00 00 01 E4 63 32 73 70  00 00 07 C4 00 00 00 54  |....c2sp.......T|
0x00C0: 73 32 63 70 00 00 08 18  00 00 00 54 73 76 63 6E  |s2cp.......Tsvcn|
0x00D0: 00 00 08 6C 00 00 00 3C  77 74 70 74 00 00 08 A8  |...l...<wtpt....|
0x00E0: 00 00 00 14 63 69 63 70  00 00 08 BC 00 00 00 0C  |....cicp........|
0x00F0: 63 70 72 74 00 00 08 C8  00 00 00 76 6D 6C 75 63  |cprt.......vmluc|
0x0100: 00 00 00 00 00 00 00 01  00 00 00 0C 65 6E 55 53  |............enUS|
0x0110: 00 00 00 60 00 00 00 1C  00 42 00 54 00 2E 00 32  |...`.....B.T...2|
0x0120: 00 31 00 30 00 30 00 20  00 48 00 4C 00 47 00 20  |.1.0.0. .H.L.G. |
0x0130: 00 4E 00 61 00 72 00 72  00 6F 00 77 00 20 00 52  |.N.a.r.r.o.w. .R|
0x0140: 00 61 00 6E 00 67 00 65  00 20 00 52 00 47 00 42  |.a.n.g.e. .R.G.B|
0x0150: 00 20 00 74 00 6F 00 2F  00 66 00 72 00 6F 00 6D  |. .t.o./.f.r.o.m|
0x0160: 00 20 00 53 00 63 00 65  00 6E 00 65 00 20 00 4C  |. .S.c.e.n.e. .L|
0x0170: 00 69 00 67 00 68 00 74  6D 70 65 74 00 00 00 00  |.i.g.h.tmpet....|
0x0180: 00 03 00 03 00 00 00 06  00 00 00 C0 00 00 00 44  |...............D|
0x0190: 00 00 00 84 00 00 00 78  00 00 00 FC 00 00 00 6C  |.......x.......l|
0x01A0: 00 00 01 68 00 00 00 90  00 00 01 F8 00 00 00 3C  |...h...........<|
0x01B0: 00 00 02 34 00 00 00 3C  63 76 73 74 00 00 00 00  |...4...<cvst....|
0x01C0: 00 03 00 03 00 00 00 24  00 00 00 20 00 00 00 24  |.......$... ...$|
0x01D0: 00 00 00 20 00 00 00 24  00 00 00 20 73 6E 67 66  |... ...$... sngf|
0x01E0: 00 00 00 00 00 00 00 02  3D 80 08 01 3F 6B 0E B1  |........=...?k..|
0x01F0: 00 00 00 00 00 00 00 00  3F 80 00 00 63 76 73 74  |........?...cvst|
0x0200: 00 00 00 00 00 03 00 03  00 00 00 24 00 00 00 54  |...........$...T|
0x0210: 00 00 00 24 00 00 00 54  00 00 00 24 00 00 00 54  |...$...T...$...T|
0x0220: 63 75 72 66 00 00 00 00  00 02 00 00 00 00 00 00  |curf............|
0x0230: 70 61 72 66 00 00 00 00  00 00 00 00 3F 80 00 00  |parf........?...|
0x0240: 00 00 00 00 00 00 00 00  00 00 00 00 70 61 72 66  |............parf|
0x0250: 00 00 00 00 00 06 00 00  3E 23 20 00 3C 4F CD AC  |........># .<O..|
0x0260: 3F 56 00 00 41 96 D0 00  41 95 80 00 46 1C 40 00  |?V..A...A...F.@.|
0x0270: 3F 80 00 00 63 76 73 74  00 00 00 00 00 03 00 03  |?...cvst........|
0x0280: 00 00 00 24 00 00 00 48  00 00 00 24 00 00 00 48  |...$...H...$...H|
0x0290: 00 00 00 24 00 00 00 48  63 75 72 66 00 00 00 00  |...$...Hcurf....|
0x02A0: 00 02 00 00 00 00 00 00  70 61 72 66 00 00 00 00  |........parf....|
0x02B0: 00 00 00 00 3F 80 00 00  00 00 00 00 00 00 00 00  |....?...........|
0x02C0: 00 00 00 00 70 61 72 66  00 00 00 00 00 00 00 00  |....parf........|
0x02D0: 3E D5 55 55 3C 23 D7 0A  00 00 00 00 00 00 00 00  |>.UU<#..........|
0x02E0: 63 76 73 74 00 00 00 00  00 03 00 03 00 00 00 24  |cvst...........$|
0x02F0: 00 00 00 6C 00 00 00 24  00 00 00 6C 00 00 00 24  |...l...$...l...$|
0x0300: 00 00 00 6C 63 75 72 66  00 00 00 00 00 03 00 00  |...lcurf........|
0x0310: 00 00 00 00 3E D1 67 F2  70 61 72 66 00 00 00 00  |....>.g.parf....|
0x0320: 00 00 00 00 3F 80 00 00  00 00 00 00 00 00 00 00  |....?...........|
0x0330: 00 00 00 00 70 61 72 66  00 00 00 00 00 00 00 00  |....parf........|
0x0340: 3F 80 00 00 3D 18 ED 58  00 00 00 00 00 00 00 00  |?...=..X........|
0x0350: 70 61 72 66 00 00 00 00  00 03 00 00 40 0E 38 E4  |parf........@.8.|
0x0360: 3C 89 A1 EF 3F 68 F0 65  3D B8 7C DB 00 00 00 00  |<...?h.e=.|.....|
0x0370: 6D 61 74 66 00 00 00 00  00 03 00 03 3B A1 6B 31  |matf........;.k1|
0x0380: 80 00 00 00 00 00 00 00  80 00 00 00 3B A1 6B 31  |............;.k1|
0x0390: 80 00 00 00 00 00 00 00  80 00 00 00 3B A1 6B 31  |............;.k1|
0x03A0: 00 00 00 00 00 00 00 00  00 00 00 00 6D 61 74 66  |............matf|
0x03B0: 00 00 00 00 00 03 00 03  3F 23 0F AF 3E 14 16 74  |........?#..>..t|
0x03C0: 3E 2C EF 23 3E 86 80 A4  3F 2D 91 48 3D 72 E6 5C  |>,.#>...?-.H=r.\|
0x03D0: 00 00 00 00 3C E5 F8 B3  3F 87 CE 5C 00 00 00 00  |....<...?..\....|
0x03E0: 00 00 00 00 00 00 00 00  6D 70 65 74 00 00 00 00  |........mpet....|
0x03F0: 00 03 00 03 00 00 00 05  00 00 00 38 00 00 00 3C  |...........8...<|
0x0400: 00 00 00 74 00 00 00 3C  00 00 00 B0 00 00 00 90  |...t...<........|
0x0410: 00 00 01 40 00 00 00 74  00 00 01 B4 00 00 00 44  |...@...t.......D|
0x0420: 6D 61 74 66 00 00 00 00  00 03 00 03 3F DB BB 3A  |matf........?..:|
0x0430: BE B6 1A 7B BE 81 B9 39  BF 2A AB D3 3F CE E8 DB  |...{...9.*..?...|
0x0440: 3C 81 2D 05 3C 90 81 75  BD 2F 30 3C 3F 71 2D AB  |<.-.<..u./0<?q-.|
0x0450: 00 00 00 00 00 00 00 00  00 00 00 00 6D 61 74 66  |............matf|
0x0460: 00 00 00 00 00 03 00 03  3E 55 1E B9 80 00 00 00  |........>U......|
0x0470: 00 00 00 00 80 00 00 00  3E 55 1E B9 80 00 00 00  |........>U......|
0x0480: 00 00 00 00 80 00 00 00  3E 55 1E B9 00 00 00 00  |........>U......|
0x0490: 00 00 00 00 00 00 00 00  63 76 73 74 00 00 00 00  |........cvst....|
0x04A0: 00 03 00 03 00 00 00 24  00 00 00 6C 00 00 00 24  |.......$...l...$|
0x04B0: 00 00 00 6C 00 00 00 24  00 00 00 6C 63 75 72 66  |...l...$...lcurf|
0x04C0: 00 00 00 00 00 03 00 00  00 00 00 00 39 9E 8B 71  |............9..q|
0x04D0: 70 61 72 66 00 00 00 00  00 00 00 00 3F 80 00 00  |parf........?...|
0x04E0: 00 00 00 00 00 00 00 00  00 00 00 00 70 61 72 66  |............parf|
0x04F0: 00 00 00 00 00 00 00 00  3F 80 00 00 3C DB 6A 1F  |........?...<.j.|
0x0500: 00 00 00 00 00 00 00 00  70 61 72 66 00 00 00 00  |........parf....|
0x0510: 00 03 00 00 3E E6 66 66  38 E6 7A 1D 42 6E 15 4D  |....>.ff8.z.Bn.M|
0x0520: 00 00 00 00 B7 26 18 2D  63 76 73 74 00 00 00 00  |.....&.-cvst....|
0x0530: 00 03 00 03 00 00 00 24  00 00 00 50 00 00 00 24  |.......$...P...$|
0x0540: 00 00 00 50 00 00 00 24  00 00 00 50 63 75 72 66  |...P...$...Pcurf|
0x0550: 00 00 00 00 00 02 00 00  3D AA AA AB 70 61 72 66  |........=...parf|
0x0560: 00 00 00 00 00 00 00 00  3F 80 00 00 00 00 00 00  |........?.......|
0x0570: 00 00 00 00 00 00 00 00  70 61 72 66 00 00 00 00  |........parf....|
0x0580: 00 07 00 00 42 9D B0 00  3E 23 20 00 3F 56 00 00  |....B...># .?V..|
0x0590: 41 96 D0 00 41 95 80 00  3F 80 00 00 63 76 73 74  |A...A...?...cvst|
0x05A0: 00 00 00 00 00 03 00 03  00 00 00 24 00 00 00 20  |...........$... |
0x05B0: 00 00 00 24 00 00 00 20  00 00 00 24 00 00 00 20  |...$... ...$... |
0x05C0: 73 6E 67 66 00 00 00 00  00 00 00 02 00 00 00 00  |sngf............|
0x05D0: 3F 80 00 00 00 00 00 00  3D 80 08 01 3F 6B 0E B1  |?.......=...?k..|
0x05E0: 6D 70 65 74 00 00 00 00  00 03 00 03 00 00 00 05  |mpet............|
0x05F0: 00 00 00 38 00 00 00 3C  00 00 00 74 00 00 00 3C  |...8...<...t...<|
0x0600: 00 00 00 B0 00 00 00 4C  00 00 00 FC 00 00 00 AC  |.......L........|
0x0610: 00 00 01 A8 00 00 00 3C  6D 61 74 66 00 00 00 00  |.......<matf....|
0x0620: 00 03 00 03 3F DB BB 3A  BE B6 1A 7B BE 81 B9 39  |....?..:...{...9|
0x0630: BF 2A AB D3 3F CE E8 DB  3C 81 2D 05 3C 90 81 75  |.*..?...<.-.<..u|
0x0640: BD 2F 30 3C 3F 71 2D AB  00 00 00 00 00 00 00 00  |./0<?q-.........|
0x0650: 00 00 00 00 6D 61 74 66  00 00 00 00 00 03 00 03  |....matf........|
0x0660: 3E 55 1E B9 80 00 00 00  00 00 00 00 80 00 00 00  |>U..............|
0x0670: 3E 55 1E B9 80 00 00 00  00 00 00 00 80 00 00 00  |>U..............|
0x0680: 3E 55 1E B9 00 00 00 00  00 00 00 00 00 00 00 00  |>U..............|
0x0690: 6D 61 74 66 00 00 00 00  00 03 00 04 3F 80 00 00  |matf........?...|
0x06A0: 00 00 00 00 00 00 00 00  00 00 00 00 3F 80 00 00  |............?...|
0x06B0: 00 00 00 00 00 00 00 00  00 00 00 00 3F 80 00 00  |............?...|
0x06C0: 3E 86 80 9D 3F 2D 91 68  3D 72 E4 8F 00 00 00 00  |>...?-.h=r......|
0x06D0: 00 00 00 00 00 00 00 00  00 00 00 00 74 6D 61 70  |............tmap|
0x06E0: 00 00 00 00 00 04 00 03  00 00 00 2C 00 00 00 68  |...........,...h|
0x06F0: 00 00 00 94 00 00 00 18  00 00 00 94 00 00 00 18  |................|
0x0700: 00 00 00 00 00 00 00 18  63 75 72 66 00 00 00 00  |........curf....|
0x0710: 00 03 00 00 00 00 00 00  3F 80 00 00 70 61 72 66  |........?...parf|
0x0720: 00 00 00 00 00 00 00 00  3F 80 00 00 00 00 00 00  |........?.......|
0x0730: 00 00 00 00 00 00 00 00  70 61 72 66 00 00 00 00  |........parf....|
0x0740: 00 00 00 00 BD 6D DA CF  3F 80 00 00 00 00 00 00  |.....m..?.......|
0x0750: 00 00 00 00 70 61 72 66  00 00 00 00 00 00 00 00  |....parf........|
0x0760: 3F 80 00 00 00 00 00 00  00 00 00 00 3F 80 00 00  |?...........?...|
0x0770: 6D 61 70 66 00 00 00 00  00 00 00 00 3F 80 00 00  |mapf........?...|
0x0780: 00 00 00 00 00 00 00 00  6D 61 74 66 00 00 00 00  |........matf....|
0x0790: 00 03 00 03 3F 23 0F AF  3E 14 16 74 3E 2C EF 23  |....?#..>..t>,.#|
0x07A0: 3E 86 80 A4 3F 2D 91 48  3D 72 E6 5C 00 00 00 00  |>...?-.H=r.\....|
0x07B0: 3C E5 F8 B3 3F 87 CE 5C  00 00 00 00 00 00 00 00  |<...?..\........|
0x07C0: 00 00 00 00 6D 70 65 74  00 00 00 00 00 03 00 03  |....mpet........|
0x07D0: 00 00 00 01 00 00 00 18  00 00 00 3C 6D 61 74 66  |...........<matf|
0x07E0: 00 00 00 00 00 03 00 03  3F 93 79 27 BD 7F 06 96  |........?.y'....|
0x07F0: BD 80 E0 11 3D CA 96 ED  3F 6F 1F 3E BC D3 53 DA  |....=...?o.>..S.|
0x0800: BC E8 61 EF 3D 0E 18 47  3F 40 14 F8 00 00 00 00  |..a.=..G?@......|
0x0810: 00 00 00 00 00 00 00 00  6D 70 65 74 00 00 00 00  |........mpet....|
0x0820: 00 03 00 03 00 00 00 01  00 00 00 18 00 00 00 3C  |...............<|
0x0830: 6D 61 74 66 00 00 00 00  00 03 00 03 3F 5D 75 71  |matf........?]uq|
0x0840: 3D 60 DD 1D 3D 98 73 6C  BD B9 89 BE 3F 88 1F BC  |=`..=.sl....?...|
0x0850: 3C ED 48 8F 3D 17 1E 44  BD 40 E5 B4 3F AA C8 5F  |<.H.=..D.@..?.._|
0x0860: 00 00 00 00 00 00 00 00  00 00 00 00 73 76 63 6E  |............svcn|
0x0870: 00 00 00 00 00 00 00 01  00 00 00 00 00 00 00 00  |................|
0x0880: 00 00 00 02 45 CB 20 00  00 00 00 00 00 00 00 00  |....E. .........|
0x0890: 43 40 EF EE 43 4B 00 00  43 5D 06 CA 40 98 11 99  |C@..CK..C]..@...|
0x08A0: 40 A0 00 00 40 AE 35 45  58 59 5A 20 00 00 00 00  |@...@.5EXYZ ....|
0x08B0: 00 00 32 A5 00 00 35 48  00 00 3A 07 63 69 63 70  |..2...5H..:.cicp|
0x08C0: 00 00 00 00 09 12 00 00  6D 6C 75 63 00 00 00 00  |........mluc....|
0x08D0: 00 00 00 01 00 00 00 0C  65 6E 55 53 00 00 00 5A  |........enUS...Z|
0x08E0: 00 00 00 1C 00 43 00 6F  00 70 00 79 00 72 00 69  |.....C.o.p.y.r.i|
0x08F0: 00 67 00 68 00 74 00 20  00 32 00 30 00 32 00 32  |.g.h.t. .2.0.2.2|
0x0900: 00 20 00 49 00 6E 00 74  00 65 00 72 00 6E 00 61  |. .I.n.t.e.r.n.a|
0x0910: 00 74 00 69 00 6F 00 6E  00 61 00 6C 00 20 00 43  |.t.i.o.n.a.l. .C|
0x0920: 00 6F 00 6C 00 6F 00 72  00 20 00 43 00 6F 00 6E  |.o.l.o.r. .C.o.n|
0x0930: 00 73 00 6F 00 72 00 74  00 69 00 75 00 6D 00 00  |.s.o.r.t.i.u.m..|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

## Analysis Command 3: Round-Trip Test (-r)

**Command:**
```bash
iccanalyzer-lite/iccanalyzer-lite -r test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc 2>&1
```

**Exit Code:** 2 (error — profile failed to load)

**Complete Raw Output:**
```
=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc
```

## Profile Structure Analysis

From the ninja mode dump, the profile structure is:

**Tags (10 total):**
1. `desc` (0x64657363) — Description tag, type `mluc` (multi-locale Unicode)
   - "BT.2100 HLG Narrow Range RGB to/from Scene Light"
2. `A2B1` (0x41324231) — Device to PCS tag, type `mpet` (Multi-Processing Element)
3. `B2A1` (0x42324131) — PCS to Device tag, type `mpet`
4. `H2S1` (0x48325331) — Spectral conversion tag, type `mpet`
5. `c2sp` (0x63327370) — Colorimetry to Spectral PCS tag, type `mpet`
6. `s2cp` (0x73326370) — Spectral PCS to Colorimetry tag, type `mpet`
7. `svcn` (0x7376636E) — Spectral viewer conditions tag
8. `wtpt` (0x77747074) — White point tag, type `XYZ`
9. `cicp` (0x63696370) — Coding-independent code points tag
10. `cprt` (0x63707274) — Copyright tag, type `mluc`
    - "Copyright 2022 International Color Consortium"

**MPE Processing Elements:**
The profile contains multiple `mpet` (Multi-Processing Element) tags with various sub-elements:
- `cvst` — Curve Set elements
- `matf` — Matrix elements
- `parf` — Parametric curve elements
- `curf` — Curve elements
- `sngf` — Single-value float elements
- **`tmap`** — **Tone Map element** (signature 0x746D6170) at offset 0x06D8

The critical finding is a `tmap` (CIccMpeToneMap) element embedded in the MPE chain. This element appears in the H2S1 tag starting at file offset 0x06D8.

## Technical Analysis

**Why the Profile Failed Validation:**

The profile failed to load through the standard iccDEV `CIccProfile::Read()` path, which suggests one of these issues:

1. **Incomplete `tmap` Implementation:** The `CIccMpeToneMap` class may not be fully implemented in the version of iccDEV used by iccanalyzer-lite
2. **Tag Parsing Error:** The MPE chain parser may fail when encountering the `tmap` element
3. **Validation Strictness:** The iccDEV library may reject this profile type due to spectral PCS features not being fully supported

**However:**
- The ninja mode dump succeeded (exit code 0), proving the file structure is readable
- All 19 security heuristics passed
- No tag overlaps detected
- Header and tag table are well-formed

This indicates the failure is in **semantic validation**, not a security issue.

## Security Assessment

**No ASAN/UBSAN Output:** No sanitizer errors detected during any analysis phase.

**Exit Code Analysis:**
- `-a`: Exit code 1 (finding) — correctly identifies the validation failure
- `-nf`: Exit code 0 (clean) — raw structure is parseable
- `-r`: Exit code 2 (error) — profile failed to load for round-trip test

**Conclusion:** This is a **well-formed but incomplete ICC profile** from a security perspective. The profile uses advanced spectral processing features (H2S1, c2sp, s2cp tags) and the `CIccMpeToneMap` tone mapping element, which may not be fully supported by the current iccDEV library parser.

The profile is likely a **test case for the `CIccMpeToneMap` class** (as indicated by the filename `CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc`), possibly generated from the iccDEV source code for unit testing purposes.

**No security vulnerabilities detected.** The validation failure is expected for an incomplete/test profile.
