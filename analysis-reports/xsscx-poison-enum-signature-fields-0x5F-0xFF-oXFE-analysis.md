# ICC Profile Analysis Report

**Profile**: `test-profiles/xsscx-poison-enum-signature-fields-0x5F-0xFF-oXFE.icc`
**File Size**: 205 bytes
**Date**: 2026-02-15T18:34:18Z
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
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x5f5f5f5f (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:️ ColorSpace signature: 0x5f5f5f5f (Unknown)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x5f5f5f5f (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:️ ColorSpace signature: 0x5f5f5f5f (Unknown)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x5f5f5fff (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:️ ColorSpace signature: 0x5f5f5fff (Unknown)
ICC_WARN: [IccAnalyzerSecurity.cpp:477] NaN detected in biSpectralRange.start: value=NaN [bits=0xffc00000]
ICC_WARN: [IccAnalyzerSecurity.cpp:478] NaN detected in biSpectralRange.end: value=NaN [bits=0xffc00000]

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/runner/work/research/research/test-profiles/xsscx-poison-enum-signature-fields-0x5F-0xFF-oXFE.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/runner/work/research/research/test-profiles/xsscx-poison-enum-signature-fields-0x5F-0xFF-oXFE.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 4294967295 bytes (0xFFFFFFFF)  [actual file: 205 bytes]
     [WARN]  HEURISTIC: Profile size > 1 GiB (possible memory exhaustion)
     Risk: Resource exhaustion attack
     [WARN]  HEURISTIC: Header claims 4294967295 bytes but file is 205 bytes (20951060x inflation)
     Risk: OOM via tag-internal allocations sized from inflated header

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x5F5F5F5F (____)
     [WARN]  HEURISTIC: Unknown/invalid colorSpace signature
     Risk: Parser may not handle unknown values safely
     Name: Unknown  Bytes: '____'

[H4] PCS ColorSpace: 0x5F5F5FFF (___.)
     [WARN]  HEURISTIC: Invalid PCS signature (must be Lab, XYZ, or spectral)
     Risk: Colorimetric transform failures
     Name: Unknown  Bytes: '___�'

[H5] Platform: 0xFFFE0000 (....)
     [WARN]  HEURISTIC: Unknown platform signature
     Risk: Platform-specific code path exploitation

[H6] Rendering Intent: 3691118592 (0xDC020000)
     [WARN]  HEURISTIC: Invalid rendering intent (> 3)
     Risk: Out-of-bounds enum access

[H7] Profile Class: 0x5F5F5F8D (___.)
     [OK] Known class: Unknown '___?' = 5F5F5F8D

[H8] Illuminant XYZ: (-0.343765, -0.316956, 767.380432)
     [WARN]  HEURISTIC: Negative illuminant values (non-physical)
     Risk: Undefined behavior in color calculations

[H15] Date Validation: 65535-65535-65535 65535:63487:65535
      [WARN]  HEURISTIC: Invalid month: 65535
      [WARN]  HEURISTIC: Invalid day: 65535
      [WARN]  HEURISTIC: Invalid hours: 65535
      [WARN]  HEURISTIC: Invalid minutes: 63487
      [WARN]  HEURISTIC: Invalid seconds: 65535
      [WARN]  HEURISTIC: Suspicious year: 65535 (expected 1900-2100)
      Risk: Malformed date may indicate crafted/corrupted profile

[H16] Signature Pattern Analysis
      [WARN]  colorSpace: 0x5F5F5F5F repeat-byte pattern (fuzz artifact?)
      Risk: 1 repeat-byte signature(s) — likely crafted/fuzzed profile

[H17] Spectral Range Validation
      Spectral: start=471.75nm end=511.75nm steps=65535
      [WARN]  HEURISTIC: Excessive spectral steps: 65535
      BiSpectral: start=-nannm end=-nannm steps=65535
      [WARN]  HEURISTIC: Excessive bispectral steps: 65535

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

[H10] Tag Count: 1
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
      [OK] Theoretical max within limits: 67108864 bytes

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

[WARN]  12 HEURISTIC WARNING(S) DETECTED

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
Profile: /home/runner/work/research/research/test-profiles/xsscx-poison-enum-signature-fields-0x5F-0xFF-oXFE.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/xsscx-poison-enum-signature-fields-0x5F-0xFF-oXFE.icc
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

File: /home/runner/work/research/research/test-profiles/xsscx-poison-enum-signature-fields-0x5F-0xFF-oXFE.icc
Total Issues Detected: 13

[WARN] ANALYSIS COMPLETE - 13 issue(s) detected
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

File: /home/runner/work/research/research/test-profiles/xsscx-poison-enum-signature-fields-0x5F-0xFF-oXFE.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 205 bytes (0xCD)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: FF FF FF FF FF FF FF 5F  5F 5F 5F 5F 5F 5F 5F 8D  |.......________.|
0x0010: 5F 5F 5F 5F 5F 5F 5F FF  FF FF FF FF FF FF FF FF  |_______.........|
0x0020: F7 FF FF FF 61 63 73 70  FF FE 00 00 00 00 AF 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 A7 FF FF FF AE  |................|
0x0040: DC 02 00 00 FF FF A7 FF  FF FF AE DC 02 FF 61 63  |..............ac|
0x0050: 73 70 FF FE 00 00 00 00  00 FF FF 5F 5F 5F 5F 5F  |sp........._____|
0x0060: 5F 5F 5F 5F 5F 5F 5F 5F  5F 5F 5F FF FF FF FF FF  |___________.....|
0x0070: FF FF FF FF F7 FF FF FF  61 63 73 70 FF FE 00 00  |........acsp....|

Header Fields (RAW - no validation):
  Profile Size:    0xFFFFFFFF (4294967295 bytes) MISMATCH
  CMM:             0xFFFFFF5F  '..._'
  Version:         0x5F5F5F5F
  Device Class:    0x5F5F5F8D  '___.'
  Color Space:     0x5F5F5F5F  '____'
  PCS:             0x5F5F5FFF  '___.'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 1 (0x00000001)

Tag Table Raw Data:
0x0080: 00 00 00 01 00 00 00 04  00 00 00 A9 A9 A9 A9 A9  |................|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x00000004   '    '        0x000000A9   0xA9A9A9A9   'XYZ '        OOB size

[WARN] SIZE INFLATION: Header claims 4294967295 bytes, file is 205 bytes (20951060x)
   Risk: OOM via tag-internal allocations based on inflated header size

=== FULL FILE HEX DUMP (all 205 bytes) ===
0x0000: FF FF FF FF FF FF FF 5F  5F 5F 5F 5F 5F 5F 5F 8D  |.......________.|
0x0010: 5F 5F 5F 5F 5F 5F 5F FF  FF FF FF FF FF FF FF FF  |_______.........|
0x0020: F7 FF FF FF 61 63 73 70  FF FE 00 00 00 00 AF 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 A7 FF FF FF AE  |................|
0x0040: DC 02 00 00 FF FF A7 FF  FF FF AE DC 02 FF 61 63  |..............ac|
0x0050: 73 70 FF FE 00 00 00 00  00 FF FF 5F 5F 5F 5F 5F  |sp........._____|
0x0060: 5F 5F 5F 5F 5F 5F 5F 5F  5F 5F 5F FF FF FF FF FF  |___________.....|
0x0070: FF FF FF FF F7 FF FF FF  61 63 73 70 FF FE 00 00  |........acsp....|
0x0080: 00 00 00 01 00 00 00 04  00 00 00 A9 A9 A9 A9 A9  |................|
0x0090: A9 A9 A9 A9 A9 A9 A9 A9  A9 2D A9 A9 A9 A9 A9 A9  |.........-......|
0x00A0: A9 A9 A9 A9 A9 A9 A9 A9  A9 58 59 5A 20 49 43 43  |.........XYZ ICC|
0x00B0: 70 A9 A9 A9 A9 A9 A9 A9  A9 A9 A9 00 00 00 A5 00  |p...............|
0x00C0: 00 00 00 DC DC FF 2F DC  45 FF FF FF 1A           |....../.E....|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/xsscx-poison-enum-signature-fields-0x5F-0xFF-oXFE.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/xsscx-poison-enum-signature-fields-0x5F-0xFF-oXFE.icc
```
