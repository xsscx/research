# ICC Profile Security Analysis Report

**Profile:** `test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc`
**File Size:** 258 bytes
**Date:** 2026-02-20
**Analyzer:** iccanalyzer-lite (pre-built binary)

## Exit Code Summary

| Command | Exit Code | Status |
|---------|-----------|--------|
| `iccanalyzer-lite -a` | 1 | [FINDING] 11 issues detected |
| `iccanalyzer-lite -nf` | 0 | [OK] Raw dump completed |
| `iccanalyzer-lite -r` | 2 | [ERROR] Profile failed validation |

## Key Findings

- **SIZE INFLATION:** Header claims 1,414,091,852 bytes; actual file is 258 bytes (5,480,976x inflation). Risk: OOM via tag-internal allocations.
- **INVALID MAGIC BYTES:** Expected "acsp", got "0000". Not a valid ICC profile — possible format confusion attack.
- **MALFORMED CONTENT:** File appears to be a `.cube` LUT text file (`TITLE "Identity LUT"`, `LUT_3D_SIZE 200000000000000000.0`) incorrectly renamed/treated as an ICC profile. This is the source of the undefined behavior at IccFromCube.cpp Line 218.
- **INVALID SIGNATURES:** Color space 0x4C555422 (`LUT"`), PCS 0x0A4C5554 (`.LUT`), platform 0x30303030, rendering intent 705301002 (> 3).
- **SUSPICIOUS TAG COUNT:** 807,415,854 tags claimed; all have out-of-bounds offsets.
- **REPEAT-BYTE PATTERN:** Platform signature is a repeat-byte pattern — likely crafted/fuzzed profile.
- **TAG OVERLAP:** 36 overlapping tag pairs detected.
- **MALFORMED DATE:** Year 24371, month 17503, day 21321 — all invalid.

## Root Cause

The file is a `.cube` LUT text file (not a binary ICC profile). When `IccFromCube.cpp` processes a malformed or oversized `LUT_3D_SIZE` value (`200000000000000000.0`), it reaches Line 218 where undefined behavior (likely integer overflow or out-of-bounds allocation) occurs during 3D table parsing.

---

## Command 1: `iccanalyzer-lite -a` (EXIT_CODE=1)

```
=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/runner/work/research/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/runner/work/research/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 1414091852 bytes (0x5449544C)  [actual file: 258 bytes]
     [WARN]  HEURISTIC: Profile size > 1 GiB (possible memory exhaustion)
     Risk: Resource exhaustion attack
     [WARN]  HEURISTIC: Header claims 1414091852 bytes but file is 258 bytes (5480976x inflation)
     Risk: OOM via tag-internal allocations sized from inflated header

[H2] Magic Bytes (offset 0x24): 30 30 30 30 (0000)
     [WARN]  HEURISTIC: Invalid magic bytes (expected "acsp")
     Risk: Not a valid ICC profile, possible format confusion attack

[H3] Data ColorSpace: 0x4C555422 (LUT")
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x4c555422 (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h: ColorSpace signature: 0x4c555422 (Unknown)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x4c555422 (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h: ColorSpace signature: 0x4c555422 (Unknown)
     [WARN]  HEURISTIC: Unknown/invalid colorSpace signature
     Risk: Parser may not handle unknown values safely
     Name: Unknown  Bytes: 'LUT"'

[H4] PCS ColorSpace: 0x0A4C5554 (.LUT)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x0a4c5554 (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h: ColorSpace signature: 0x0a4c5554 (Unknown)
     [WARN]  HEURISTIC: Invalid PCS signature (must be Lab, XYZ, or spectral)
     Risk: Colorimetric transform failures
     Name: Unknown  Bytes: '
LUT'

[H5] Platform: 0x30303030 (0000)
     [WARN]  HEURISTIC: Unknown platform signature
     Risk: Platform-specific code path exploitation

[H6] Rendering Intent: 705301002 (0x2A0A0A0A)
     [WARN]  HEURISTIC: Invalid rendering intent (> 3)
     Risk: Out-of-bounds enum access

[H7] Profile Class: 0x69747920 (ity )
     [OK] Known class: Unknown 'ity ' = 69747920

[H8] Illuminant XYZ: (2655.325439, 23109.125000, 12334.187500)
     [WARN]  HEURISTIC: Illuminant values > 5.0 (suspicious)
     Risk: Floating-point overflow in transforms

[H15] Date Validation: 24371-17503-21321 23109:8242:12336
      [WARN]  HEURISTIC: Invalid month: 17503
      [WARN]  HEURISTIC: Invalid day: 21321
      [WARN]  HEURISTIC: Invalid hours: 23109
      [WARN]  HEURISTIC: Invalid minutes: 8242
      [WARN]  HEURISTIC: Invalid seconds: 12336
      [WARN]  HEURISTIC: Suspicious year: 24371 (expected 1900-2100)
      Risk: Malformed date may indicate crafted/corrupted profile

[H16] Signature Pattern Analysis
      [WARN]  platform: 0x30303030 repeat-byte pattern (fuzz artifact?)
      Risk: 1 repeat-byte signature(s) — likely crafted/fuzzed profile

[H17] Spectral Range Validation
      Spectral: start=0.01nm end=0.10nm steps=2608
      BiSpectral: start=0.00nm end=0.10nm steps=8202

=======================================================================
[WARN]  Profile failed to load - skipping tag-level heuristics
   Use -n (ninja mode) for raw analysis of malformed profiles
=======================================================================

=======================================================================
HEURISTIC SUMMARY
=======================================================================

[WARN]  10 HEURISTIC WARNING(S) DETECTED

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
Profile: /home/runner/work/research/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc
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

File: /home/runner/work/research/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc
Total Issues Detected: 11

[WARN] ANALYSIS COMPLETE - 11 issue(s) detected
  Review detailed output above for security concerns.
EXIT_CODE=1
```

---

## Command 2: `iccanalyzer-lite -nf` (EXIT_CODE=0)

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

File: /home/runner/work/research/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 258 bytes (0x102)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 54 49 54 4C 45 20 22 49  64 65 6E 74 69 74 79 20  |TITLE "Identity |
0x0010: 4C 55 54 22 0A 4C 55 54  5F 33 44 5F 53 49 5A 45  |LUT".LUT_3D_SIZE|
0x0020: 20 32 30 30 30 30 30 30  30 30 30 30 30 30 30 30  | 200000000000000|
0x0030: 30 30 30 2E 30 20 30 2E  30 0A 31 2E 30 20 0A 0A  |000.0 0.0.1.0 ..|
0x0040: 2A 0A 0A 0A 0A 5F 53 49  5A 45 20 32 30 2E 30 20  |*...._SIZE 20.0 |
0x0050: 30 2E 30 2E 30 0A 31 2E  30 20 0A 0A 2A 0A 0A 0A  |0.0.0.1.0 ..*...|
0x0060: 0A 0A 2E 30 20 0A 2E 3D  20 30 2E 30 0A 30 0A 31  |...0 ..= 0.0.0.1|
0x0070: 2E 30 20 0A 0A 2A 0A 0A  0A 0A 0A 2E 30 20 0A 2E  |.0 ..*......0 ..|

Header Fields (RAW - no validation):
  Profile Size:    0x5449544C (1414091852 bytes) MISMATCH
  CMM:             0x45202249  'E "I'
  Version:         0x64656E74
  Device Class:    0x69747920  'ity '
  Color Space:     0x4C555422  'LUT"'
  PCS:             0x0A4C5554  '.LUT'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 807415854 (0x3020302E)
WARNING: Suspicious tag count (>1000) - possible corruption

Tag Table Raw Data:
Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x300A313C   '0
1<'        0x30200A0A   0x0A20312E   '----'        OOB offset
1    0x3020302E   '0 0.'        0x300A302E   0x3020312E   '----'        OOB offset
2    0x3020310A   '0 1
'        0x0A0A2031   0x2E300B31   '----'        OOB offset
3    0x2E302030   '.0 0'        0x2E302030   0x2E300A31   '----'        OOB offset
4    0x2E302030   '.0 0'        0x2E302031   0x2E300A31   '----'        OOB offset
5    0x2E302031   '.0 1'        0x2E300000   0x000A0A0A   '----'        OOB offset
6    0x230A0A0A   '#


'        0x0A0A2320   0x6C550A04   '----'        OOB offset
7    0x0A0A5554   '

UT'        0x5F31445F   0x5F312032   '----'        OOB offset
8    0x302E3020   '0.0 '        0x302E300A   0x312E3020   '----'        OOB offset
9    0x0A0A2A0A   '

*
'        0x0A0A0A0A   0x2E30200A   '----'        OOB offset
... (807415754 more tags not shown)

[WARN] SIZE INFLATION: Header claims 1414091852 bytes, file is 258 bytes (5480976x)
   Risk: OOM via tag-internal allocations based on inflated header size

[WARN] TAG OVERLAP: 36 overlapping tag pair(s) detected
   Risk: Data corruption, possible exploit crafting

=== FULL FILE HEX DUMP (all 258 bytes) ===
0x0000: 54 49 54 4C 45 20 22 49  64 65 6E 74 69 74 79 20  |TITLE "Identity |
0x0010: 4C 55 54 22 0A 4C 55 54  5F 33 44 5F 53 49 5A 45  |LUT".LUT_3D_SIZE|
0x0020: 20 32 30 30 30 30 30 30  30 30 30 30 30 30 30 30  | 200000000000000|
0x0030: 30 30 30 2E 30 20 30 2E  30 0A 31 2E 30 20 0A 0A  |000.0 0.0.1.0 ..|
0x0040: 2A 0A 0A 0A 0A 5F 53 49  5A 45 20 32 30 2E 30 20  |*...._SIZE 20.0 |
0x0050: 30 2E 30 2E 30 0A 31 2E  30 20 0A 0A 2A 0A 0A 0A  |0.0.0.1.0 ..*...|
0x0060: 0A 0A 2E 30 20 0A 2E 3D  20 30 2E 30 0A 30 0A 31  |...0 ..= 0.0.0.1|
0x0070: 2E 30 20 0A 0A 2A 0A 0A  0A 0A 0A 2E 30 20 0A 2E  |.0 ..*......0 ..|
0x0080: 30 20 30 2E 30 0A 31 3C  30 20 0A 0A 0A 20 31 2E  |0 0.0.1<0 ... 1.|
0x0090: 30 20 30 2E 30 0A 30 2E  30 20 31 2E 30 20 31 0A  |0 0.0.0.0 1.0 1.|
0x00A0: 0A 0A 20 31 2E 30 0B 31  2E 30 20 30 2E 30 20 30  |.. 1.0.1.0 0.0 0|
0x00B0: 2E 30 0A 31 2E 30 20 30  2E 30 20 31 2E 30 0A 31  |.0.1.0 0.0 1.0.1|
0x00C0: 2E 30 20 31 2E 30 00 00  00 0A 0A 0A 23 0A 0A 0A  |.0 1.0......#...|
0x00D0: 0A 0A 23 20 6C 55 0A 04  0A 0A 55 54 5F 31 44 5F  |..# lU....UT_1D_|
0x00E0: 5F 31 20 32 30 2E 30 20  30 2E 30 0A 31 2E 30 20  |_1 20.0 0.0.1.0 |
0x00F0: 0A 0A 2A 0A 0A 0A 0A 0A  2E 30 20 0A 2E 30 20 44  |..*......0 ..0 D|
0x0100: 5F 2E                                             |_.|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
EXIT_CODE=0
```

---

## Command 3: `iccanalyzer-lite -r` (EXIT_CODE=2)

```
=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc
EXIT_CODE=2
```

---

## Security Assessment

**Severity:** [CRITICAL]

This file is a crafted/malformed `.cube` LUT text file presented as an ICC profile. It triggers undefined behavior in `IccFromCube.cpp` at Line 218 during `parse3Dtable` processing.

### Attack Vectors

1. **Integer Overflow / UB in parse3Dtable:** The `LUT_3D_SIZE` value `200000000000000000.0` far exceeds valid range. When cast to an integer type to allocate the 3D lookup table, this causes undefined behavior (signed integer overflow or allocation size overflow) at IccFromCube.cpp Line 218.

2. **Memory Exhaustion (OOM):** Header size field claims 1,414,091,852 bytes (1.3 GiB) against an actual 258-byte file. Any parser trusting the header for allocation sizing faces OOM.

3. **Format Confusion:** The file is plaintext `.cube` LUT format, not a binary ICC profile. Parsers that do not validate the `acsp` magic bytes before processing are vulnerable to confusion attacks.

4. **Out-of-Bounds Tag Access:** 807,415,854 tags are claimed; all 10 sampled entries have out-of-bounds offsets. Any code iterating the tag table without bounds checking will access memory outside the file.

5. **Enum Out-of-Bounds:** Rendering intent value 705,301,002 (expected 0–3) can cause out-of-bounds array access in intent dispatch tables.

### Recommendations

- **IccFromCube.cpp Line 218:** Add bounds check on parsed `LUT_3D_SIZE` value before use in allocation. Validate that the size is within a sane maximum (e.g., <= 256) before computing table dimensions.
- **Profile loader:** Validate `acsp` magic bytes before any further parsing.
- **Tag iteration:** Enforce tag count <= a safe maximum and validate all offsets against actual file size before access.
- **Rendering intent:** Clamp or validate rendering intent to range 0–3 before use as array index.

**Do NOT use this profile in production color workflows.**
