# ICC Profile Analysis Report

**Profile**: `test-profiles/heap-buffer-overflow-display-CIccFileIO-Read8-IccIO_cpp-Line508.icc`
**File Size**: 504 bytes
**Date**: 2026-02-15T18:34:10Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Clean |
| `-r` (round-trip) | 2 | Error |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 1**

```
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x7b616220 (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:️ ColorSpace signature: 0x7b616220 (Unknown)

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/runner/work/research/research/test-profiles/heap-buffer-overflow-display-CIccFileIO-Read8-IccIO_cpp-Line508.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/runner/work/research/research/test-profiles/heap-buffer-overflow-display-CIccFileIO-Read8-IccIO_cpp-Line508.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 504 bytes (0x000001F8)  [actual file: 504 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x52474220 (RGB )
     [OK] Valid colorSpace: RgbData

[H4] PCS ColorSpace: 0x7B616220 ({ab )
     [WARN]  HEURISTIC: Invalid PCS signature (must be Lab, XYZ, or spectral)
     Risk: Colorimetric transform failures
     Name: Unknown  Bytes: '{ab '

[H5] Platform: 0x97979797 (....)
     [WARN]  HEURISTIC: Unknown platform signature
     Risk: Platform-specific code path exploitation

[H6] Rendering Intent: 1073741833 (0x40000009)
     [WARN]  HEURISTIC: Invalid rendering intent (> 3)
     Risk: Out-of-bounds enum access

[H7] Profile Class: 0x63FA6E72 (c.nr)
     [OK] Known class: Unknown 'c?nr' = 63FA6E72

[H8] Illuminant XYZ: (2570.041260, 1.000000, 0.824905)
     [WARN]  HEURISTIC: Illuminant values > 5.0 (suspicious)
     Risk: Floating-point overflow in transforms

[H15] Date Validation: 2001-07-151 38807:38807:38807
      [WARN]  HEURISTIC: Invalid day: 151
      [WARN]  HEURISTIC: Invalid hours: 38807
      [WARN]  HEURISTIC: Invalid minutes: 38807
      [WARN]  HEURISTIC: Invalid seconds: 38807
      Risk: Malformed date may indicate crafted/corrupted profile

[H16] Signature Pattern Analysis
      [WARN]  platform: 0x97979797 repeat-byte pattern (fuzz artifact?)
      [WARN]  manufacturer: 0x97979797 repeat-byte pattern (fuzz artifact?)
      Risk: 2 repeat-byte signature(s) — likely crafted/fuzzed profile

[H17] Spectral Range Validation
      Spectral: start=10.00nm end=0.00nm steps=0
      [WARN]  HEURISTIC: Spectral end < start (0.00 < 10.00)

=======================================================================
TAG-LEVEL HEURISTICS
=======================================================================

[H9] Critical Text Tags:
     Description: Present [OK]
     Copyright: Missing
     Manufacturer: Missing
     Device Model: Missing
     [WARN]  HEURISTIC: Multiple required text tags missing
       Risk: Incomplete/malformed profile

[H10] Tag Count: 5
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
      [OK] Theoretical max within limits: 335544320 bytes

[H14] TagArrayType Detection (UAF Risk)
      Checking for TagArrayType (0x74617279 = 'tary')
      Note: Tag signature ≠ tag type - must check tag DATA
      [OK] No TagArrayType tags detected

[H18] Technology Signature Validation
      INFO: No technology tag present

[H19] Tag Offset/Size Overlap Detection
      [WARN]  Tags 'desc' and '.esc' overlap: [187+50] vs [192+7]
      Risk: 1 tag overlap(s) — possible data corruption or exploitation

=======================================================================
HEURISTIC SUMMARY
=======================================================================

[WARN]  9 HEURISTIC WARNING(S) DETECTED

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
Profile: /home/runner/work/research/research/test-profiles/heap-buffer-overflow-display-CIccFileIO-Read8-IccIO_cpp-Line508.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/heap-buffer-overflow-display-CIccFileIO-Read8-IccIO_cpp-Line508.icc
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

File: /home/runner/work/research/research/test-profiles/heap-buffer-overflow-display-CIccFileIO-Read8-IccIO_cpp-Line508.icc
Total Issues Detected: 10

[WARN] ANALYSIS COMPLETE - 10 issue(s) detected
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

File: /home/runner/work/research/research/test-profiles/heap-buffer-overflow-display-CIccFileIO-Read8-IccIO_cpp-Line508.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 504 bytes (0x1F8)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 01 F8 61 70 70 CD  02 20 00 72 63 FA 6E 72  |....app.. .rc.nr|
0x0010: 52 47 42 20 7B 61 62 20  07 D1 00 07 00 97 97 97  |RGB {ab ........|
0x0020: 97 97 97 97 61 63 73 70  97 97 97 97 D7 97 97 97  |....acsp........|
0x0030: 97 97 97 97 97 97 97 97  97 97 97 97 97 97 97 97  |................|
0x0040: 40 00 00 09 0A 0A 0A 97  00 01 00 00 00 00 D3 2D  |@..............-|
0x0050: 61 70 76 6C 00 00 00 03  06 FF FA 00 00 08 00 00  |apvl............|
0x0060: 00 00 00 00 00 71 43 43  49 00 00 0A 00 00 00 00  |.....qCCI.......|
0x0070: 00 00 00 00 00 02 00 01  00 00 00 00 3B 75 00 00  |............;u..|

Header Fields (RAW - no validation):
  Profile Size:    0x000001F8 (504 bytes) OK
  CMM:             0x617070CD  'app.'
  Version:         0x02200072
  Device Class:    0x63FA6E72  'c.nr'
  Color Space:     0x52474220  'RGB '
  PCS:             0x7B616220  '{ab '

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 5 (0x00000005)

Tag Table Raw Data:
0x0080: 00 00 00 05 64 65 73 63  00 00 00 BB 00 00 00 32  |....desc.......2|
0x0090: 01 08 00 00 00 00 00 F7  00 00 00 FB C6 65 73 63  |.............esc|
0x00A0: 00 00 00 C0 00 00 00 07  01 00 07 00 00 00 00 00  |................|
0x00B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x64657363   'desc'        0x000000BB   0x00000032   '    '        OK
1    0x01080000   '  '        0x000000F7   0x000000FB   '    '        OK
2    0xC6657363   '�esc'        0x000000C0   0x00000007   'ut16'        OK
3    0x01000700   '   '        0x00000000   0x00000000   '    '        overlap
4    0x00000000   '    '        0x00000000   0x00000000   '    '        overlap

[WARN] TAG OVERLAP: 1 overlapping tag pair(s) detected
   Risk: Data corruption, possible exploit crafting

=== FULL FILE HEX DUMP (all 504 bytes) ===
0x0000: 00 00 01 F8 61 70 70 CD  02 20 00 72 63 FA 6E 72  |....app.. .rc.nr|
0x0010: 52 47 42 20 7B 61 62 20  07 D1 00 07 00 97 97 97  |RGB {ab ........|
0x0020: 97 97 97 97 61 63 73 70  97 97 97 97 D7 97 97 97  |....acsp........|
0x0030: 97 97 97 97 97 97 97 97  97 97 97 97 97 97 97 97  |................|
0x0040: 40 00 00 09 0A 0A 0A 97  00 01 00 00 00 00 D3 2D  |@..............-|
0x0050: 61 70 76 6C 00 00 00 03  06 FF FA 00 00 08 00 00  |apvl............|
0x0060: 00 00 00 00 00 71 43 43  49 00 00 0A 00 00 00 00  |.....qCCI.......|
0x0070: 00 00 00 00 00 02 00 01  00 00 00 00 3B 75 00 00  |............;u..|
0x0080: 00 00 00 05 64 65 73 63  00 00 00 BB 00 00 00 32  |....desc.......2|
0x0090: 01 08 00 00 00 00 00 F7  00 00 00 FB C6 65 73 63  |.............esc|
0x00A0: 00 00 00 C0 00 00 00 07  01 00 07 00 00 00 00 00  |................|
0x00B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x00C0: 75 74 31 36 74 FF FF FF  FF FF 4F 00 00 00 00 00  |ut16t.....O.....|
0x00D0: 5B 00 00 00 00 00 00 00  00 00 00 00 00 00 00 80  |[...............|
0x00E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x00F0: 00 00 00 00 00 00 F7 00  00 00 05 6D 70 65 74 00  |...........mpet.|
0x0100: 00 00 C0 00 00 00 00 00  00 00 0B 00 00 00 7F 00  |................|
0x0110: 00 00 3B 00 00 00 03 00  00 00 45 00 00 00 00 00  |..;.......E.....|
0x0120: 00 00 64 00 00 00 00 00  00 00 00 00 00 00 00 00  |..d.............|
0x0130: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0140: 00 00 00 00 00 00 01 00  00 00 F7 00 00 00 00 00  |................|
0x0150: 00 00 00 00 00 00 00 00  00 00 00 01 00 00 00 00  |................|
0x0160: 00 00 00 00 00 00 D3 00  00 01 BB 00 00 00 00 00  |................|
0x0170: 00 00 00 00 00 00 00 00  00 00 4A 74 6F 58 97 97  |..........JtoX..|
0x0180: 97 40 00 00 09 00 00 0A  0A 0A 97 00 01 99 00 00  |.@..............|
0x0190: 00 D3 2D 61 70 75 00 00  00 00 00 05 64 65 73 63  |..-apu......desc|
0x01A0: 00 00 BB 00 00 00 31 01  08 00 00 00 00 00 28 00  |......1.......(.|
0x01B0: 00 00 00 00 00 BC 00 00  00 00 00 00 00 00 00 94  |................|
0x01C0: 00 00 62 72 64 66 00 00  00 00 00 00 00 00 00 00  |..brdf..........|
0x01D0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x01E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x01F0: 00 00 00 00 00 00 00 00                           |........|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/heap-buffer-overflow-display-CIccFileIO-Read8-IccIO_cpp-Line508.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/heap-buffer-overflow-display-CIccFileIO-Read8-IccIO_cpp-Line508.icc
```
