# ICC Profile Analysis Report

**Profile**: `test-profiles/xsscx-infinite-recursion-test-CIccTagFloatNum~CIccTagFloatNum-IccTagBasic_cpp-L6346.icc`
**File Size**: 352 bytes
**Date**: 2026-02-15T18:40:30Z
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

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/runner/work/research/research/test-profiles/xsscx-infinite-recursion-test-CIccTagFloatNum~CIccTagFloatNum-IccTagBasic_cpp-L6346.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/runner/work/research/research/test-profiles/xsscx-infinite-recursion-test-CIccTagFloatNum~CIccTagFloatNum-IccTagBasic_cpp-L6346.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 3916 bytes (0x00000F4C)  [actual file: 352 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x52474220 (RGB )
     [OK] Valid colorSpace: RgbData

[H4] PCS ColorSpace: 0x58595A20 (XYZ )
     [OK] Valid PCS: XYZData

[H5] Platform: 0x00FFFF62 (...b)
     [WARN]  HEURISTIC: Unknown platform signature
     Risk: Platform-specific code path exploitation

[H6] Rendering Intent: 1 (0x00000001)
     [OK] Valid intent: Relative Colorimetric

[H7] Profile Class: 0x6C696E6B (link)
     [OK] Known class: LinkClass

[H8] Illuminant XYZ: (0.950500, 1.000000, 1.089096)
     [OK] Illuminant values within physical range

[H15] Date Validation: 2018-08-15 10:07:19
      [OK] Date values within valid ranges

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

[H10] Tag Count: 8
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
      [OK] Theoretical max within limits: 536870912 bytes

[H14] TagArrayType Detection (UAF Risk)
      Checking for TagArrayType (0x74617279 = 'tary')
      Note: Tag signature ≠ tag type - must check tag DATA
      [OK] No TagArrayType tags detected

[H18] Technology Signature Validation
      INFO: No technology tag present

[H19] Tag Offset/Size Overlap Detection
      [WARN]  Tags 'desc' and 'A2B1' overlap: [228+10302] vs [292+980]
      [WARN]  Tags 'desc' and 'B2A]' overlap: [228+10302] vs [1272+980]
      [WARN]  Tags 'desc' and 'c2sp' overlap: [228+10302] vs [2252+84]
      [WARN]  Tags 'desc' and 's2cp' overlap: [228+10302] vs [2336+28]
      [WARN]  Tags '.c.a' and '.d.e' overlap: [7077987+5570670] vs [7471187+7602273]
      [WARN]  Tags '.c.a' and '.c.k' overlap: [7077987+5570670] vs [6226025+6684672]
      [WARN]  Tags '.d.e' and '.c.k' overlap: [7471187+7602273] vs [6226025+6684672]
      Risk: 7 tag overlap(s) — possible data corruption or exploitation

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
Profile: /home/runner/work/research/research/test-profiles/xsscx-infinite-recursion-test-CIccTagFloatNum~CIccTagFloatNum-IccTagBasic_cpp-L6346.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/xsscx-infinite-recursion-test-CIccTagFloatNum~CIccTagFloatNum-IccTagBasic_cpp-L6346.icc
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

File: /home/runner/work/research/research/test-profiles/xsscx-infinite-recursion-test-CIccTagFloatNum~CIccTagFloatNum-IccTagBasic_cpp-L6346.icc
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

File: /home/runner/work/research/research/test-profiles/xsscx-infinite-recursion-test-CIccTagFloatNum~CIccTagFloatNum-IccTagBasic_cpp-L6346.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 352 bytes (0x160)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 0F 4C 00 00 00 00  05 00 00 00 6C 69 6E 6B  |...L........link|
0x0010: 52 47 42 20 58 59 5A 20  07 E2 00 08 00 0F 00 0A  |RGB XYZ ........|
0x0020: 00 07 00 13 61 63 73 70  00 FF FF 62 D3 57 F2 D0  |....acsp...b.W..|
0x0030: 14 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 54  00 01 00 00 00 01 16 CF  |.......T........|
0x0050: 49 43 43 20 26 E6 B2 5A  F9 06 08 DB 53 6C 8B EF  |ICC &..Z....Sl..|
0x0060: D6 30 85 50 00 00 00 00  00 00 00 00 00 00 00 00  |.0.P............|
0x0070: 00 00 00 00 00 00 00 00  00 11 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x00000F4C (3916 bytes) MISMATCH
  CMM:             0x00000000  '....'
  Version:         0x05000000
  Device Class:    0x6C696E6B  'link'
  Color Space:     0x52474220  'RGB '
  PCS:             0x58595A20  'XYZ '

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 8 (0x00000008)

Tag Table Raw Data:
0x0080: 00 00 00 08 64 65 73 63  00 00 00 E4 00 00 28 3E  |....desc......(>|
0x0090: 41 32 42 31 00 00 01 24  00 00 03 D4 42 32 41 5D  |A2B1...$....B2A]|
0x00A0: 00 00 04 F8 00 00 03 D4  63 32 73 70 00 00 08 CC  |........c2sp....|
0x00B0: 00 00 00 54 73 32 63 70  00 00 09 20 00 00 00 1C  |...Ts2cp... ....|
0x00C0: 00 63 00 61 00 6C 00 63  00 55 00 6E 00 64 00 65  |.c.a.l.c.U.n.d.e|
0x00D0: 00 72 00 53 00 74 00 61  00 63 00 6B 00 5F 00 69  |.r.S.t.a.c.k._.i|
0x00E0: 00 66 00 00                                       |.f..|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x64657363   'desc'        0x000000E4   0x0000283E   'mpet'        OOB size
1    0x41324231   'A2B1'        0x00000124   0x000003D4   '    '        OOB size
2    0x4232415D   'B2A]'        0x000004F8   0x000003D4   '----'        OOB offset
3    0x63327370   'c2sp'        0x000008CC   0x00000054   '----'        OOB offset
4    0x73326370   's2cp'        0x00000920   0x0000001C   '----'        OOB offset
5    0x00630061   '    '        0x006C0063   0x0055006E   '----'        OOB offset
6    0x00640065   '    '        0x00720053   0x00740061   '----'        OOB offset
7    0x0063006B   '    '        0x005F0069   0x00660000   '----'        OOB offset

[WARN] TAG OVERLAP: 7 overlapping tag pair(s) detected
   Risk: Data corruption, possible exploit crafting

=== FULL FILE HEX DUMP (all 352 bytes) ===
0x0000: 00 00 0F 4C 00 00 00 00  05 00 00 00 6C 69 6E 6B  |...L........link|
0x0010: 52 47 42 20 58 59 5A 20  07 E2 00 08 00 0F 00 0A  |RGB XYZ ........|
0x0020: 00 07 00 13 61 63 73 70  00 FF FF 62 D3 57 F2 D0  |....acsp...b.W..|
0x0030: 14 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 54  00 01 00 00 00 01 16 CF  |.......T........|
0x0050: 49 43 43 20 26 E6 B2 5A  F9 06 08 DB 53 6C 8B EF  |ICC &..Z....Sl..|
0x0060: D6 30 85 50 00 00 00 00  00 00 00 00 00 00 00 00  |.0.P............|
0x0070: 00 00 00 00 00 00 00 00  00 11 00 00 00 00 00 00  |................|
0x0080: 00 00 00 08 64 65 73 63  00 00 00 E4 00 00 28 3E  |....desc......(>|
0x0090: 41 32 42 31 00 00 01 24  00 00 03 D4 42 32 41 5D  |A2B1...$....B2A]|
0x00A0: 00 00 04 F8 00 00 03 D4  63 32 73 70 00 00 08 CC  |........c2sp....|
0x00B0: 00 00 00 54 73 32 63 70  00 00 09 20 00 00 00 1C  |...Ts2cp... ....|
0x00C0: 00 63 00 61 00 6C 00 63  00 55 00 6E 00 64 00 65  |.c.a.l.c.U.n.d.e|
0x00D0: 00 72 00 53 00 74 00 61  00 63 00 6B 00 5F 00 69  |.r.S.t.a.c.k._.i|
0x00E0: 00 66 00 00 6D 70 65 74  00 00 00 00 00 03 00 03  |.f..mpet........|
0x00F0: 00 00 00 01 00 00 00 18  00 00 03 BC 63 61 6C 63  |............calc|
0x0100: 00 FC 00 00 00 03 CE FF  FF FF FF FF FF 3F 00 03  |.............?..|
0x0110: 00 00 00 00 2C 00 00 03  84 00 00 00 38 66 75 6E  |....,.......8fun|
0x0120: FD 63 00 00 00 00 00 00  00 0F 4C 00 00 00 00 05  |.c........L.....|
0x0130: 00 00 00 73 70 61 63 52  47 42 20 5F 63 78 01 00  |...spacRGB _cx..|
0x0140: 00 04 78 61 64 61 61 00  74 00 00 00 65 71 20 20  |..xadaa.t...eq  |
0x0150: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 00 00  |....sum ....da..|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/xsscx-infinite-recursion-test-CIccTagFloatNum~CIccTagFloatNum-IccTagBasic_cpp-L6346.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/xsscx-infinite-recursion-test-CIccTagFloatNum~CIccTagFloatNum-IccTagBasic_cpp-L6346.icc
```
