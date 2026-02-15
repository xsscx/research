# ICC Profile Analysis Report

**Profile**: `test-profiles/oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc`
**File Size**: 504 bytes
**Date**: 2026-02-15T18:26:55Z
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
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x81004224 (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:ï¸ ColorSpace signature: 0x81004224 (Unknown)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x81004224 (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:ï¸ ColorSpace signature: 0x81004224 (Unknown)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x4c616269 (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:ï¸ ColorSpace signature: 0x4c616269 (Unknown)

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/runner/work/research/research/test-profiles/oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/runner/work/research/research/test-profiles/oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 504 bytes (0x000001F8)  [actual file: 504 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x81004224 (..B$)
     [WARN]  HEURISTIC: ColorSpace contains non-printable characters
     Risk: Binary signature exploitation
     Name: Unknown  Bytes: ''

[H4] PCS ColorSpace: 0x4C616269 (Labi)
     [WARN]  HEURISTIC: Invalid PCS signature (must be Lab, XYZ, or spectral)
     Risk: Colorimetric transform failures
     Name: Unknown  Bytes: 'Labi'

[H5] Platform: 0x97979797 (....)
     [WARN]  HEURISTIC: Unknown platform signature
     Risk: Platform-specific code path exploitation

[H6] Rendering Intent: 9 (0x00000009)
     [WARN]  HEURISTIC: Invalid rendering intent (> 3)
     Risk: Out-of-bounds enum access

[H7] Profile Class: 0x72636E72 (rcnr)
     [OK] Known class: Unknown 'rcnr' = 72636E72

[H8] Illuminant XYZ: (2570.041260, 1.000687, 0.824905)
     [WARN]  HEURISTIC: Illuminant values > 5.0 (suspicious)
     Risk: Floating-point overflow in transforms

[H15] Date Validation: 25965-30727-151 38807:38807:38807
      [WARN]  HEURISTIC: Invalid month: 30727
      [WARN]  HEURISTIC: Invalid day: 151
      [WARN]  HEURISTIC: Invalid hours: 38807
      [WARN]  HEURISTIC: Invalid minutes: 38807
      [WARN]  HEURISTIC: Invalid seconds: 38807
      [WARN]  HEURISTIC: Suspicious year: 25965 (expected 1900-2100)
      Risk: Malformed date may indicate crafted/corrupted profile

[H16] Signature Pattern Analysis
      [WARN]  platform: 0x97979797 repeat-byte pattern (fuzz artifact?)
      [WARN]  manufacturer: 0x97979797 repeat-byte pattern (fuzz artifact?)
      Risk: 2 repeat-byte signature(s) â€” likely crafted/fuzzed profile

[H17] Spectral Range Validation
      Spectral: start=0.00nm end=0.00nm steps=1
      BiSpectral: start=0.01nm end=0.00nm steps=0

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
      Note: Tag signature â‰  tag type - must check tag DATA
      [OK] No TagArrayType tags detected

[H18] Technology Signature Validation
      INFO: No technology tag present

[H19] Tag Offset/Size Overlap Detection
      [WARN]  Tags 'desc' and '....' overlap: [187+125] vs [247+251]
      [WARN]  Tags 'desc' and '.esc' overlap: [187+125] vs [192+125]
      [WARN]  Tags 'desc' and 'tepm' overlap: [187+125] vs [247+5]
      [WARN]  Tags 'desc' and 'desc' overlap: [187+125] vs [192+125]
      [WARN]  Tags '....' and '.esc' overlap: [247+251] vs [192+125]
      [WARN]  Tags '....' and 'desc' overlap: [247+251] vs [192+125]
      [WARN]  Tags '.esc' and 'tepm' overlap: [192+125] vs [247+5]
      [WARN]  Tags 'tepm' and 'desc' overlap: [247+5] vs [192+125]
      Risk: 8 tag overlap(s) â€” possible data corruption or exploitation

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
  â€¢ Validate profile with official ICC tools
  â€¢ Use -n (ninja mode) for detailed byte-level analysis
  â€¢ Do NOT use in production color workflows
  â€¢ Consider as potential security test case


=======================================================================
PHASE 2: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc
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

File: /home/runner/work/research/research/test-profiles/oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc
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

File: /home/runner/work/research/research/test-profiles/oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 504 bytes (0x1F8)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 01 F8 61 70 70 F1  02 20 00 FA 72 63 6E 72  |....app.. ..rcnr|
0x0010: 81 00 42 24 4C 61 62 69  65 6D 78 07 00 97 97 97  |..B$Labiemx.....|
0x0020: 97 97 97 97 61 63 73 70  97 97 97 97 97 97 97 97  |....acsp........|
0x0030: 97 97 97 97 97 97 97 97  97 97 97 97 01 00 00 0B  |................|
0x0040: 00 00 00 09 0A 0A 0A 97  00 01 00 2D 00 00 D3 2D  |...........-...-|
0x0050: 9F 00 71 FF 76 FF FE 7B  F9 09 FA 00 00 00 00 01  |..q.v..{........|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 01 21 00  |..............!.|
0x0070: 00 00 00 00 00 00 00 01  00 00 00 00 3B 00 00 00  |............;...|

Header Fields (RAW - no validation):
  Profile Size:    0x000001F8 (504 bytes) OK
  CMM:             0x617070F1  'app.'
  Version:         0x022000FA
  Device Class:    0x72636E72  'rcnr'
  Color Space:     0x81004224  '..B$'
  PCS:             0x4C616269  'Labi'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 5 (0x00000005)

Tag Table Raw Data:
0x0080: 00 00 00 05 64 65 73 63  00 00 00 BB 00 00 00 7D  |....desc.......}|
0x0090: 01 00 00 00 00 00 00 F7  00 00 00 FB 93 65 73 63  |.............esc|
0x00A0: 00 00 00 C0 00 00 00 7D  74 65 70 6D 00 00 00 F7  |.......}tepm....|
0x00B0: 00 00 00 05 64 65 73 63  00 00 00 C0 00 00 00 7D  |....desc.......}|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x64657363   'desc'        0x000000BB   0x0000007D   'À   '        OK
1    0x01000000   '   '        0x000000F7   0x000000FB   'ÿÿÿÿ'        OK
2    0x93657363   '“esc'        0x000000C0   0x0000007D   'dict'        OK
3    0x7465706D   'tepm'        0x000000F7   0x00000005   'ÿÿÿÿ'        OK
4    0x64657363   'desc'        0x000000C0   0x0000007D   'dict'        OK

[WARN] TAG OVERLAP: 8 overlapping tag pair(s) detected
   Risk: Data corruption, possible exploit crafting

=== FULL FILE HEX DUMP (all 504 bytes) ===
0x0000: 00 00 01 F8 61 70 70 F1  02 20 00 FA 72 63 6E 72  |....app.. ..rcnr|
0x0010: 81 00 42 24 4C 61 62 69  65 6D 78 07 00 97 97 97  |..B$Labiemx.....|
0x0020: 97 97 97 97 61 63 73 70  97 97 97 97 97 97 97 97  |....acsp........|
0x0030: 97 97 97 97 97 97 97 97  97 97 97 97 01 00 00 0B  |................|
0x0040: 00 00 00 09 0A 0A 0A 97  00 01 00 2D 00 00 D3 2D  |...........-...-|
0x0050: 9F 00 71 FF 76 FF FE 7B  F9 09 FA 00 00 00 00 01  |..q.v..{........|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 01 21 00  |..............!.|
0x0070: 00 00 00 00 00 00 00 01  00 00 00 00 3B 00 00 00  |............;...|
0x0080: 00 00 00 05 64 65 73 63  00 00 00 BB 00 00 00 7D  |....desc.......}|
0x0090: 01 00 00 00 00 00 00 F7  00 00 00 FB 93 65 73 63  |.............esc|
0x00A0: 00 00 00 C0 00 00 00 7D  74 65 70 6D 00 00 00 F7  |.......}tepm....|
0x00B0: 00 00 00 05 64 65 73 63  00 00 00 C0 00 00 00 7D  |....desc.......}|
0x00C0: 64 69 63 74 01 80 00 08  F0 00 00 00 00 00 00 20  |dict........... |
0x00D0: 30 24 42 31 00 00 00 2C  CC 01 00 00 49 43 43 90  |0$B1...,....ICC.|
0x00E0: BD CD 00 00 05 64 65 73  63 00 00 00 3C 00 00 00  |.....desc...<...|
0x00F0: 7D 01 00 FF FF FF FF FF  FF FF FF FF FF FF FF FF  |}...............|
0x0100: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x0110: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF 00  |................|
0x0120: 00 00 00 00 00 F7 00 00  00 FB 93 65 73 63 00 00  |...........esc..|
0x0130: 00 C0 00 00 00 7D 74 65  70 6D 00 00 00 F7 00 00  |.....}tepm......|
0x0140: 00 05 64 65 73 63 00 00  00 C0 00 00 00 7D 64 69  |..desc.......}di|
0x0150: 63 74 01 80 00 08 08 00  00 00 00 00 00 20 30 24  |ct........... 0$|
0x0160: 42 31 00 00 00 2C CC 01  00 00 49 43 43 90 BD CD  |B1...,....ICC...|
0x0170: 00 00 05 64 65 73 63 00  00 00 3C 00 00 00 7D 01  |...desc...<...}.|
0x0180: 00 FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x0190: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x01A0: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x01B0: FF FF FF 00 00 00 BB 00  00 00 7D 01 00 00 10 00  |..........}.....|
0x01C0: 00 00 00 00 00 00 12 92  92 92 92 92 92 92 92 92  |................|
0x01D0: 92 92 92 92 92 92 92 92  92 92 92 92 92 92 92 92  |................|
0x01E0: 92 90 92 92 92 92 92 92  12 92 92 92 92 92 92 92  |................|
0x01F0: 92 92 92 92 92 92 92 92                           |........|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc
```
