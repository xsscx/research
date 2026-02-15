# ICC Profile Analysis Report

**Profile**: `test-profiles/memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.icc`
**File Size**: 427 bytes
**Date**: 2026-02-15T18:59:06Z
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

File: /home/runner/work/research/research/test-profiles/memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/runner/work/research/research/test-profiles/memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 60960 bytes (0x0000EE20)  [actual file: 427 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x52474220 (RGB )
     [OK] Valid colorSpace: RgbData

[H4] PCS ColorSpace: 0x4C616220 (Lab )
     [OK] Valid PCS: LabData

[H5] Platform: 0x00000064 (...d)
     [WARN]  HEURISTIC: Unknown platform signature
     Risk: Platform-specific code path exploitation

[H6] Rendering Intent: 256 (0x00000100)
     [WARN]  HEURISTIC: Invalid rendering intent (> 3)
     Risk: Out-of-bounds enum access

[H7] Profile Class: 0x53706163 (Spac)
     [OK] Known class: Unknown 'Spac' = 53706163

[H8] Illuminant XYZ: (253.035782, -254.976562, 0.824905)
     [WARN]  HEURISTIC: Negative illuminant values (non-physical)
     Risk: Undefined behavior in color calculations

[H15] Date Validation: 63784-65528-65511 09:05:37
      [WARN]  HEURISTIC: Invalid month: 65528
      [WARN]  HEURISTIC: Invalid day: 65511
      [WARN]  HEURISTIC: Suspicious year: 63784 (expected 1900-2100)
      Risk: Malformed date may indicate crafted/corrupted profile

[H16] Signature Pattern Analysis
      [OK] No suspicious signature patterns detected

[H17] Spectral Range Validation
      BiSpectral: start=0.00nm end=0.00nm steps=19536
      [WARN]  HEURISTIC: Excessive bispectral steps: 19536

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

[H10] Tag Count: 9
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
      [OK] Theoretical max within limits: 603979776 bytes

[H14] TagArrayType Detection (UAF Risk)
      Checking for TagArrayType (0x74617279 = 'tary')
      Note: Tag signature â‰  tag type - must check tag DATA
      [OK] No TagArrayType tags detected

[H18] Technology Signature Validation
      INFO: No technology tag present

[H19] Tag Offset/Size Overlap Detection
      [WARN]  Tags 'A2B0' and '..ps' overlap: [360+4294967295] vs [1768187609+30072]
      [WARN]  Tags 'A2B0' and '....' overlap: [360+4294967295] vs [1110524208+30508]
      [WARN]  Tags 'A2B0' and '..t4' overlap: [360+4294967295] vs [1110589896+4294907039]
      [WARN]  Tags 'A2B0' and '....' overlap: [360+4294967295] vs [1919510320+60764]
      [WARN]  Tags 'A2B0' and '....' overlap: [360+4294967295] vs [4294967295+4294967295]
      [WARN]  Tags 'A2B0' and ',...' overlap: [360+4294967295] vs [4294967295+4294967295]
      [WARN]  Tags 'A2B0' and '....' overlap: [360+4294967295] vs [4294967295+4294967295]
      [WARN]  Tags '..ps' and '..t4' overlap: [1768187609+30072] vs [1110589896+4294907039]
      [WARN]  Tags '..t4' and '....' overlap: [1110589896+4294907039] vs [1919510320+60764]
      [WARN]  Tags '..t4' and '....' overlap: [1110589896+4294907039] vs [4294967295+4294967295]
      [WARN]  Tags '..t4' and ',...' overlap: [1110589896+4294907039] vs [4294967295+4294967295]
      [WARN]  Tags '..t4' and '....' overlap: [1110589896+4294907039] vs [4294967295+4294967295]
      Risk: 12 tag overlap(s) â€” possible data corruption or exploitation

=======================================================================
HEURISTIC SUMMARY
=======================================================================

[WARN]  7 HEURISTIC WARNING(S) DETECTED

  This profile exhibits patterns associated with:
  - Malformed/corrupted data
  - Resource exhaustion attempts
  - Enum confusion vulnerabilities
  - Parser exploitation attempts

  Recommendations:
  â€¢ Validate profile with official ICC tools
  â€¢ Use -n (ninja mode) for detailed byte-level analysis
  â€¢ Do NOT use in production color workflows
  â€¢ Consider as potential security test case


=======================================================================
PHASE 2: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.icc
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

File: /home/runner/work/research/research/test-profiles/memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.icc
Total Issues Detected: 8

[WARN] ANALYSIS COMPLETE - 8 issue(s) detected
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

File: /home/runner/work/research/research/test-profiles/memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 427 bytes (0x1AB)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 EE 20 00 00 00 00  04 20 00 00 53 70 61 63  |... ..... ..Spac|
0x0010: 52 47 42 20 4C 61 62 20  F9 28 FF F8 FF E7 00 09  |RGB Lab .(......|
0x0020: 00 05 00 25 61 63 73 70  00 00 00 64 73 65 64 00  |...%acsp...dsed.|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 01 00 00 FD 09 29  FF 01 06 00 00 00 D3 2D  |.......).......-|
0x0050: 00 00 00 00 68 B1 7E A1  36 45 A8 B3 1B 60 C0 B4  |....h.~.6E...`..|
0x0060: 83 C5 AD 7A 00 00 00 00  00 00 00 00 00 00 00 00  |...z............|
0x0070: 00 00 4C 50 50 41 00 00  00 00 00 00 00 00 00 00  |..LPPA..........|

Header Fields (RAW - no validation):
  Profile Size:    0x0000EE20 (60960 bytes) MISMATCH
  CMM:             0x00000000  '....'
  Version:         0x04200000
  Device Class:    0x53706163  'Spac'
  Color Space:     0x52474220  'RGB '
  PCS:             0x4C616220  'Lab '

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 9 (0x00000009)

Tag Table Raw Data:
0x0080: 00 00 00 09 41 32 42 31  00 00 00 F0 00 00 00 78  |....A2B1.......x|
0x0090: 41 32 42 30 00 00 01 68  FF FF FF FF FF FF 70 73  |A2B0...h......ps|
0x00A0: 69 64 66 D9 00 00 75 78  00 00 01 B4 42 31 41 30  |idf...ux....B1A0|
0x00B0: 00 00 77 2C 00 00 74 34  42 32 41 C8 FF FF 14 9F  |..w,..t4B2A.....|
0x00C0: FF FF FE FC 72 69 67 30  00 00 ED 5C 00 00 00 0C  |....rig0...\....|
0x00D0: FF FF FF FF FF FF FF FF  2C FF FF FF FF FF FF FF  |........,.......|
0x00E0: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x41324231   'A2B1'        0x000000F0   0x00000078   'ÿÿÿÿ'        OK
1    0x41324230   'A2B0'        0x00000168   0xFFFFFFFF   'mpet'        OOB size
2    0xFFFF7073   'ÿÿps'        0x696466D9   0x00007578   '----'        OOB offset
3    0x000001B4   '    '        0x42314130   0x0000772C   '----'        OOB offset
4    0x00007434   '    '        0x423241C8   0xFFFF149F   '----'        OOB offset
5    0xFFFFFEFC   'ÿÿþü'        0x72696730   0x0000ED5C   '----'        OOB offset
6    0x0000000C   '    '        0xFFFFFFFF   0xFFFFFFFF   '----'        OOB offset
7    0x2CFFFFFF   ',ÿÿÿ'        0xFFFFFFFF   0xFFFFFFFF   '----'        OOB offset
8    0xFFFFFFFF   'ÿÿÿÿ'        0xFFFFFFFF   0xFFFFFFFF   '----'        OOB offset

[WARN] TAG OVERLAP: 12 overlapping tag pair(s) detected
   Risk: Data corruption, possible exploit crafting

=== FULL FILE HEX DUMP (all 427 bytes) ===
0x0000: 00 00 EE 20 00 00 00 00  04 20 00 00 53 70 61 63  |... ..... ..Spac|
0x0010: 52 47 42 20 4C 61 62 20  F9 28 FF F8 FF E7 00 09  |RGB Lab .(......|
0x0020: 00 05 00 25 61 63 73 70  00 00 00 64 73 65 64 00  |...%acsp...dsed.|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 01 00 00 FD 09 29  FF 01 06 00 00 00 D3 2D  |.......).......-|
0x0050: 00 00 00 00 68 B1 7E A1  36 45 A8 B3 1B 60 C0 B4  |....h.~.6E...`..|
0x0060: 83 C5 AD 7A 00 00 00 00  00 00 00 00 00 00 00 00  |...z............|
0x0070: 00 00 4C 50 50 41 00 00  00 00 00 00 00 00 00 00  |..LPPA..........|
0x0080: 00 00 00 09 41 32 42 31  00 00 00 F0 00 00 00 78  |....A2B1.......x|
0x0090: 41 32 42 30 00 00 01 68  FF FF FF FF FF FF 70 73  |A2B0...h......ps|
0x00A0: 69 64 66 D9 00 00 75 78  00 00 01 B4 42 31 41 30  |idf...ux....B1A0|
0x00B0: 00 00 77 2C 00 00 74 34  42 32 41 C8 FF FF 14 9F  |..w,..t4B2A.....|
0x00C0: FF FF FE FC 72 69 67 30  00 00 ED 5C 00 00 00 0C  |....rig0...\....|
0x00D0: FF FF FF FF FF FF FF FF  2C FF FF FF FF FF FF FF  |........,.......|
0x00E0: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x00F0: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x0100: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x0110: FF FF FF FF FF FF FF FF  FF FF FF FB FF FF FF FF  |................|
0x0120: FF FF FF FF FF FF FF FF  FF FF FF FF FF 3C FF FF  |.............<..|
0x0130: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x0140: FF FF FF FF 77 74 70 74  00 00 ED 68 86 B7 37 1D  |....wtpt...h..7.|
0x0150: 63 70 72 74 00 00 ED 7C  00 00 00 78 63 68 61 64  |cprt...|...xchad|
0x0160: 00 00 ED F4 00 00 00 2C  6D 70 65 74 FB FF FF FF  |.......,mpet....|
0x0170: FF FF FF FF 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0180: 01 00 00 FD 09 FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x0190: FF FF FF 02 A2 00 B8 BD  DF 43 4C 52 20 00 00 00  |.........CLR ...|
0x01A0: 2B 01 00 00 00 0C A2 00  00 C0 8C                 |+..........|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/memcpy-param-overlap-CIccTagMultiProcessElement-Apply-IccTagMPE_cpp-Line1451.icc
```
