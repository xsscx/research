# ICC Profile Security Analysis Report

**Profile:** xsscx-poison-enum-signature-fields-0x5F-0xFF-0XFE.icc  
**Date:** 2026-02-15  
**Analyzer:** iccanalyzer-lite v2.9.1  
**File Size:** 205 bytes  

---

## Executive Summary

This ICC profile is a **maliciously crafted security test case** designed to exploit multiple vulnerability classes in ICC parsers. The analysis detected **13 distinct security issues** spanning memory exhaustion, enum confusion, integer overflow, and malformed data structures.

**VERDICT:** This profile is NOT suitable for production use and represents a deliberate attempt to trigger parser vulnerabilities.

---

## Complete iccanalyzer-lite Output

### Security Analysis Mode (`-a`)

```
=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /tmp/xsscx-poison-enum-signature-fields-0x5F-0xFF-0XFE.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /tmp/xsscx-poison-enum-signature-fields-0x5F-0xFF-0XFE.icc

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
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x5f5f5f5f (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:️ ColorSpace signature: 0x5f5f5f5f (Unknown)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x5f5f5f5f (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:️ ColorSpace signature: 0x5f5f5f5f (Unknown)
     [WARN]  HEURISTIC: Unknown/invalid colorSpace signature
     Risk: Parser may not handle unknown values safely
     Name: Unknown  Bytes: '____'

[H4] PCS ColorSpace: 0x5F5F5FFF (___.)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x5f5f5fff (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:️ ColorSpace signature: 0x5f5f5fff (Unknown)
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
ICC_WARN: [IccAnalyzerSecurity.cpp:477] NaN detected in biSpectralRange.start: value=NaN [bits=0xffc00000]
ICC_WARN: [IccAnalyzerSecurity.cpp:478] NaN detected in biSpectralRange.end: value=NaN [bits=0xffc00000]
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
Profile: /tmp/xsscx-poison-enum-signature-fields-0x5F-0xFF-0XFE.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /tmp/xsscx-poison-enum-signature-fields-0x5F-0xFF-0XFE.icc
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

File: /tmp/xsscx-poison-enum-signature-fields-0x5F-0xFF-0XFE.icc
Total Issues Detected: 13

[WARN] ANALYSIS COMPLETE - 13 issue(s) detected
  Review detailed output above for security concerns.
```

**Exit Code:** 1 (Finding detected)

---

### Ninja Inspection Mode (`-n`)

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

File: /tmp/xsscx-poison-enum-signature-fields-0x5F-0xFF-0XFE.icc

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

=== FULL FILE HEX DUMP (first 2048 bytes) ===
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

**Exit Code:** 0 (Ninja mode completed successfully)

---

### Roundtrip Validation

The profile **FAILED** roundtrip validation during Phase 2 of the comprehensive analysis:

```
Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /tmp/xsscx-poison-enum-signature-fields-0x5F-0xFF-0XFE.icc
Result: NOT round-trip capable
```

---

## ASAN/UBSAN Output

No AddressSanitizer or UndefinedBehaviorSanitizer errors were triggered during analysis. The iccanalyzer-lite tool was built with `-fsanitize=address,undefined` instrumentation and successfully handled the malformed input without crashing.

**Note:** Coverage profiling warnings were emitted because the binary was built in a different location (`/build/iccanalyzer-lite/`) than where it's currently running, but these are benign and do not affect the analysis results.

---

## Detailed Vulnerability Analysis

### 1. Memory Exhaustion (CRITICAL)

**Finding:** Profile header claims size of 4,294,967,295 bytes (0xFFFFFFFF = 4GB) but actual file is only 205 bytes.

**Attack Vector:** 
- Many ICC parsers allocate buffers based on the header-declared size without validating against actual file size
- This creates a **20,951,060x inflation ratio**
- Tag-internal allocations may use this inflated size for buffer allocation
- Even with the 16MB CLUT cap (patch 001), other allocation paths could still OOM

**Heuristics Triggered:**
- [H1] Profile size > 1 GiB (possible memory exhaustion)
- [H1] Header/file size mismatch (20951060x inflation)

**Risk:** High - Direct resource exhaustion attack

---

### 2. Enum Confusion Vulnerabilities (HIGH)

**Finding:** Multiple enum-type fields contain out-of-range or invalid values:

- **Rendering Intent:** 3,691,118,592 (0xDC020000) - valid range is 0-3
- **Platform:** 0xFFFE0000 - unknown signature
- **ColorSpace:** 0x5F5F5F5F ("____") - invalid/unknown
- **PCS:** 0x5F5F5FFF - must be Lab, XYZ, or spectral
- **Device Class:** 0x5F5F5F8D

**Attack Vector:**
- Switch statements on enum values without default cases can cause undefined behavior
- Array indexing using enum values can cause out-of-bounds access
- Type confusion if parser casts enum to different integer width

**Heuristics Triggered:**
- [H3] Unknown/invalid colorSpace signature
- [H4] Invalid PCS signature
- [H5] Unknown platform signature
- [H6] Invalid rendering intent (> 3)

**Risk:** High - Out-of-bounds access, undefined behavior

---

### 3. Repeat-Byte Pattern (Fuzzing Artifact)

**Finding:** ColorSpace field uses repeat-byte pattern 0x5F5F5F5F (ASCII "____")

**Attack Vector:**
- Indicates profile was likely generated by a fuzzer
- Repeat patterns can expose edge cases in parsers that assume variability
- May bypass signature validation that checks for "known good" patterns

**Heuristics Triggered:**
- [H16] 1 repeat-byte signature detected (fuzz artifact)

**Risk:** Medium - Indicates intentional crafting

---

### 4. Invalid Date/Time (MEDIUM)

**Finding:** All date/time fields set to maximum values (65535):
- Year: 65535 (expected 1900-2100)
- Month: 65535 (valid range 1-12)
- Day: 65535 (valid range 1-31)
- Hours: 65535 (valid range 0-23)
- Minutes: 63487 (valid range 0-59)
- Seconds: 65535 (valid range 0-59)

**Attack Vector:**
- Date parsing code may perform arithmetic without overflow checks
- Could trigger integer overflows in timestamp calculations
- Some parsers use date fields for cache keys or sorting

**Heuristics Triggered:**
- [H15] Invalid month, day, hours, minutes, seconds
- [H15] Suspicious year

**Risk:** Medium - Possible integer overflow in date handling

---

### 5. Non-Physical Illuminant Values (MEDIUM)

**Finding:** Illuminant XYZ contains negative values and extreme magnitude:
- X: -0.343765 (should be positive)
- Y: -0.316956 (should be positive)
- Z: 767.380432 (unusually large)

**Attack Vector:**
- Color transformation math may not handle negative illuminants
- Could trigger floating-point exceptions (division by zero, sqrt of negative)
- NaN propagation through color pipeline

**Heuristics Triggered:**
- [H8] Negative illuminant values (non-physical)

**Risk:** Medium - Undefined behavior in color calculations

---

### 6. NaN in Spectral Range (HIGH)

**Finding:** BiSpectral range fields contain NaN values:
```
ICC_WARN: NaN detected in biSpectralRange.start: value=NaN [bits=0xffc00000]
ICC_WARN: NaN detected in biSpectralRange.end: value=NaN [bits=0xffc00000]
```

**Attack Vector:**
- NaN propagates through arithmetic operations
- Comparisons with NaN always return false (including NaN == NaN)
- Can bypass validation checks that use comparisons
- May cause infinite loops in iteration code

**Heuristics Triggered:**
- [H17] Excessive spectral steps (65535)
- [H17] Excessive bispectral steps (65535)

**Risk:** High - NaN propagation, comparison bypass

---

### 7. Out-of-Bounds Tag (CRITICAL)

**Finding:** Single tag entry has out-of-bounds offset/size:
- Offset: 0x000000A9 (169 bytes)
- Size: 0xA9A9A9A9 (2,846,468,521 bytes = 2.65 GB)
- File size: 205 bytes

**Attack Vector:**
- Tag data extends far beyond file boundaries
- Parsers that mmap the file or use unchecked reads will fault
- Size-based allocations will OOM
- Combined with header inflation, creates multiple OOM vectors

**Risk:** Critical - Out-of-bounds read, memory exhaustion

---

### 8. Missing Critical Tags (LOW)

**Finding:** Required text tags are missing:
- Description
- Copyright
- Manufacturer
- Device Model

**Attack Vector:**
- Some parsers assume these tags exist
- NULL pointer dereferences when accessing missing tags
- Metadata-dependent code paths may fail

**Heuristics Triggered:**
- [H9] Multiple required text tags missing

**Risk:** Low - Incomplete profile, possible NULL deref

---

## Attack Classification

This profile targets the following vulnerability classes:

1. **Resource Exhaustion**: Header size inflation + OOB tag size
2. **Enum Confusion**: Out-of-range enum values
3. **Type Confusion**: Invalid signatures, repeat patterns
4. **Floating-Point Exploits**: NaN injection, negative illuminants
5. **Integer Overflow**: Date fields, spectral step counts
6. **Out-of-Bounds Access**: Tag offset/size beyond file boundaries

---

## iccanalyzer-lite Hardening Evidence

The iccanalyzer-lite tool successfully detected all issues without crashing:

1. **Size Validation**: Detected 20951060x inflation ratio
2. **Enum Validation**: Flagged invalid rendering intent, platform, colorspace, PCS
3. **NaN Detection**: Identified NaN values in spectral range
4. **Pattern Detection**: Recognized repeat-byte fuzzing artifact
5. **Bounds Checking**: Identified OOB tag offset/size
6. **Safe Parsing**: Ninja mode completed without memory errors

**Sanitizer Coverage**: Built with ASan + UBSan, no violations triggered.

---

## Recommendations

1. **DO NOT** use this profile in production ICC workflows
2. **DO** use as a fuzzing/testing corpus entry for ICC parser validation
3. **DO** validate that your ICC parser:
   - Checks header size against file size before allocation
   - Validates enum ranges before use in switch/array access
   - Handles NaN in floating-point fields
   - Bounds-checks tag offsets/sizes against file size
   - Rejects profiles with missing critical tags

4. **Testing Value**: This profile is an excellent test case for:
   - Memory exhaustion defenses
   - Enum validation completeness
   - NaN handling in color math
   - Parser robustness under malformed input

---

## References

- ICC Profile Format Specification: https://www.color.org/specification/ICC.1-2022-05.pdf
- iccanalyzer-lite Heuristic Documentation: See `IccAnalyzerSecurity.h`
- Exit Code Reference: `IccAnalyzerErrors.h` (0=clean, 1=finding, 2=error, 3=usage)

---

**Analysis Tool:** iccanalyzer-lite v2.9.1  
**Build Flags:** `-fsanitize=address,undefined -g3 -O0`  
**Analyst:** GitHub Copilot Coding Agent  
**Repository:** xsscx/research
