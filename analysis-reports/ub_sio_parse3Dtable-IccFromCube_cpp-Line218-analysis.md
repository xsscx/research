# ICC Profile Analysis Report

**Profile**: `test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc`
**File Size**: 258 bytes
**SHA-256**: `14ccb963a898d012280391849e3246641311afd6de2e6b7d3498bdb28cb8c09a`
**File Type**: data
**Date**: 2026-03-25T03:11:30Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 2 | Error |
| `-xt` (LUT text export) | 2 | Error |
| `-cube` (cube export) | 1 | No 3D CLUT |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 1**

```

=======================================================================
  ICC PROFILE CONFORMANCE AUDIT
=======================================================================

File: /home/h02332/po/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc


[CRITICAL] Profile TRUNCATED — header claims more bytes than file contains (CWE-125/CWE-131)
       Library-phase conformance skipped (unsafe on truncated data)
       Running raw-byte security heuristics (H1-H173)...


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/h02332/po/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc

=======================================================================
[PREFLIGHT] Tag count = 807415854 (>1000) — profile is severely malformed
            Library-API heuristics will be skipped to avoid crash/hang
=======================================================================

=======================================================================
[PREFLIGHT] Profile TRUNCATED — header claims 1414091852 bytes, file is 258 bytes
            Library-API heuristics skipped (tag data extends beyond EOF)
            CWE-125: Tags will read out-of-bounds on lazy load
=======================================================================

=======================================================================
[PREFLIGHT] Half-float values below 1.0 will trigger upstream icF16toF UB
            Library-API heuristics skipped to avoid unsafe parse/validate of user input
=======================================================================

=======================================================================
EXTERNAL FILE METADATA
=======================================================================

  [file]
      data

  [exiftool]
      ExifTool Version Number         : 12.76
      File Name                       : ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc
      Directory                       : /home/h02332/po/research/test-profiles
      File Size                       : 258 bytes
      File Modification Date/Time     : 2026:02:23 11:23:31-05:00
      File Access Date/Time           : 2026:03:24 12:27:17-04:00
      File Inode Change Date/Time     : 2026:03:13 10:54:17-04:00
      File Permissions                : -rw-r--r--
      Error                           : File format error

  [exiftool -b -icc_profile]
      No embedded ICC profile found (or extraction failed)

  [identify]
      Image:
        Filename: /home/h02332/po/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc
        Permissions: rw-r--r--
        Format: ICC (ICC Color Profile)
        Class: DirectClass
        Geometry: 1x1+0+0
        Units: Undefined
        Colorspace: sRGB
        Type: Bilevel
        Base type: Undefined
        Endianness: Undefined
        Depth: 16/1-bit
        Channel depth:
          red: 1-bit
          green: 1-bit
          blue: 1-bit
        Channel statistics:
          Pixels: 1
          Red:
            min: 65535  (1)
            max: 65535 (1)
            mean: 65535 (1)
            standard deviation: 0 (0)
            kurtosis: -3
            skewness: 0
            entropy: 0
          Green:
            min: 65535  (1)
            max: 65535 (1)
            mean: 65535 (1)
            standard deviation: 0 (0)
            kurtosis: -3
            skewness: 0
            entropy: 0
          Blue:
            min: 65535  (1)
            max: 65535 (1)
            mean: 65535 (1)
            standard deviation: 0 (0)
            kurtosis: -3

  [xxd -l 128]
      00000000: 5449 544c 4520 2249 6465 6e74 6974 7920  TITLE "Identity 
      00000010: 4c55 5422 0a4c 5554 5f33 445f 5349 5a45  LUT".LUT_3D_SIZE
      00000020: 2032 3030 3030 3030 3030 3030 3030 3030   200000000000000
      00000030: 3030 302e 3020 302e 300a 312e 3020 0a0a  000.0 0.0.1.0 ..
      00000040: 2a0a 0a0a 0a5f 5349 5a45 2032 302e 3020  *...._SIZE 20.0 
      00000050: 302e 302e 300a 312e 3020 0a0a 2a0a 0a0a  0.0.0.1.0 ..*...
      00000060: 0a0a 2e30 200a 2e3d 2030 2e30 0a30 0a31  ...0 ..= 0.0.0.1
      00000070: 2e30 200a 0a2a 0a0a 0a0a 0a2e 3020 0a2e  .0 ..*......0 ..

  [sha256sum]
      14ccb963a898d012280391849e3246641311afd6de2e6b7d3498bdb28cb8c09a  /home/h02332/po/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 1414091852 bytes (0x5449544C)  [actual file: 258 bytes]
      [WARN]  HEURISTIC: Profile size > 1 GiB (possible memory exhaustion)
      Risk: Resource exhaustion attack
      [WARN]  HEURISTIC: Profile TRUNCATED — header claims 1414091852 bytes but file is only 258 bytes
      Risk: Tags referencing past EOF will cause heap-buffer-overflow reads
      Truncation: 100.0% of declared data missing (1414091594 bytes absent)
      [WARN]  HEURISTIC: Extreme inflation — header claims 1414091852 bytes but file is 258 bytes (5480976x)
      Risk: OOM via tag-internal allocations sized from inflated header

[H2] Magic Bytes (offset 0x24): 30 30 30 30 (0000)
      [WARN]  HEURISTIC: Invalid magic bytes (expected "acsp" — ICC.1-2022-05 §7.2.9)
      Risk: Not a valid ICC profile, possible format confusion attack

[H3] Data ColorSpace: 0x4C555422 (LUT")
      [WARN]  HEURISTIC: Unknown/invalid colorSpace signature
      Risk: Parser may not handle unknown values safely
      Name: Unknown  Bytes: 'LUT"'

[H4] PCS ColorSpace: 0x0A4C5554 (.LUT)
      [WARN]  HEURISTIC: Invalid PCS signature — ICC.1-2022-05 §7.2.7 requires Lab or XYZ; ICC.2-2023 allows spectral
      Risk: Colorimetric transform failures
      Name: Unknown  Bytes: '
LUT'

[H5] Platform / CMM / Manufacturer / Creator Validation
      Platform: 0x30303030 (0000)
      [WARN]  HEURISTIC: Unknown platform signature — ICC.1-2022-05 §7.2.10 Table 18
      Risk: Platform-specific code path exploitation
      CMM: 0x45202249 (E "I)
      [WARN]  HEURISTIC: Unregistered CMM signature — ICC.1-2022-05 §7.2.3
      Manufacturer: 0x3030302E (000.)
      [OK] Manufacturer signature is printable ASCII
      Creator: 0x302E302E (0.0.)
      [OK] Creator signature is printable ASCII

[H6] Rendering Intent: 705301002 (0x2A0A0A0A)
      [WARN]  HEURISTIC: Upper 16 bits non-zero (0x2A0A) — spec requires 0
      Risk: CWE-20: non-conformant header, possible exploitation vector
      [WARN]  HEURISTIC: Invalid rendering intent value 2570 (> 3)
      Risk: Out-of-bounds enum access

[H7] Profile Class: 0x69747920 (ity)
      [OK] Known class: Unknown 'ity ' = 69747920

[H8] Illuminant XYZ: (2655.325439, 23109.125000, 12334.187500)
      [WARN]  HEURISTIC: PCS illuminant is NOT D50 (spec: 0.9642, 1.0000, 0.8249)
      Risk: Non-conformant header — ICC.1-2022-05 §7.2.16 requires D50

[H15] Date Validation (§4.2 dateTimeNumber): 24371-17503-21321 23109:8242:12336
      [WARN]  HEURISTIC: Invalid month: 17503
      [WARN]  HEURISTIC: Invalid day: 21321
      [WARN]  HEURISTIC: Invalid hours: 23109
      [WARN]  HEURISTIC: Invalid minutes: 8242
      [WARN]  HEURISTIC: Invalid seconds: 12336
      [WARN]  HEURISTIC: Suspicious year: 24371 (expected 1900-2100)
      Risk: Malformed date may indicate crafted/corrupted profile

[H16] Signature Pattern Analysis
      platform: 0x30303030 repeat-byte pattern (fuzz artifact?)
      [WARN]  HEURISTIC: 1 repeat-byte signature(s) — likely crafted/fuzzed profile

[H17] Spectral Range Validation (ICC.2-2023 §7.2.22-23)
      Spectral: start=0.01nm end=0.10nm steps=2608
      BiSpectral: start=0.00nm end=0.10nm steps=8202
      [WARN]  HEURISTIC: MCS field 0x0A2A0A0A: not a valid icMaterialColorSignature
       CWE-843: Invalid enum value — UB in AddXform() (iccDEV #323)
      DeviceSubClass: 0x0A0A0A2E

=======================================================================
[NOT RUN] Profile structurally unsafe for library loading (807415854 tags, 258 bytes)
       Library-API heuristics not run — raw analysis continues below
=======================================================================

RAW-FILE ANALYSIS ENGINE (library load failed)
=======================================================================

[H10] Tag Count (raw fallback)
      [WARN]  Excessive tag count: 807415854 (>256) — potential DoS

[H13] Per-Tag Size Check (raw fallback)
      [WARN]  Tag '0
1<': offset=0x30200A0A past EOF (0x102) — fully inaccessible
      [WARN]  Tag '0
1<': size 169881902 bytes (>16MB) — potential OOM
      [WARN]  Tag '0 0.': offset=0x300A302E past EOF (0x102) — fully inaccessible
      [WARN]  Tag '0 0.': size 807416110 bytes (>16MB) — potential OOM
      [WARN]  Tag '0 1
': offset=0xA0A2031 past EOF (0x102) — fully inaccessible
      [WARN]  Tag '0 1
': size 774900529 bytes (>16MB) — potential OOM
      [WARN]  Tag '.0 0': offset=0x2E302030 past EOF (0x102) — fully inaccessible
      [WARN]  Tag '.0 0': size 774900273 bytes (>16MB) — potential OOM
      [WARN]  Tag '.0 0': offset=0x2E302031 past EOF (0x102) — fully inaccessible
      [WARN]  Tag '.0 0': size 774900273 bytes (>16MB) — potential OOM
      [WARN]  Tag '.0 1': offset=0x2E300000 past EOF (0x102) — fully inaccessible
      [WARN]  Tag '#


': offset=0xA0A2320 past EOF (0x102) — fully inaccessible
      [WARN]  Tag '#


': size 1817512452 bytes (>16MB) — potential OOM
      [WARN]  Tag '

UT': offset=0x5F31445F past EOF (0x102) — fully inaccessible
      [WARN]  Tag '

UT': size 1597055026 bytes (>16MB) — potential OOM
      [WARN]  Tag '0.0 ': offset=0x302E300A past EOF (0x102) — fully inaccessible
      [WARN]  Tag '0.0 ': size 825110560 bytes (>16MB) — potential OOM
      [WARN]  Tag '

*
': offset=0xA0A0A0A past EOF (0x102) — fully inaccessible
      [WARN]  Tag '

*
': size 774905866 bytes (>16MB) — potential OOM
            Tag accessibility: 0/10 accessible (10 inaccessible due to truncation)

[H25] Tag Offset/Size Out-of-Bounds Detection (raw fallback)
      [WARN]  Tag '0
1<': offset 0x30200A0A past file end (0x102)
       CRITICAL: OOB read if parser follows this offset
      [WARN]  Tag '0 0.': offset 0x300A302E past file end (0x102)
       CRITICAL: OOB read if parser follows this offset
      [WARN]  Tag '0 0.': extends past declared profile size (1414091852)
      [WARN]  Tag '0 1
': offset 0x0A0A2031 past file end (0x102)
       CRITICAL: OOB read if parser follows this offset
      [WARN]  Tag '.0 0': offset 0x2E302030 past file end (0x102)
       CRITICAL: OOB read if parser follows this offset
      [WARN]  Tag '.0 0': extends past declared profile size (1414091852)
      [WARN]  Tag '.0 0': offset 0x2E302031 past file end (0x102)
       CRITICAL: OOB read if parser follows this offset
      [WARN]  Tag '.0 0': extends past declared profile size (1414091852)
      [WARN]  Tag '.0 1': offset 0x2E300000 past file end (0x102)
       CRITICAL: OOB read if parser follows this offset
      [WARN]  Tag '#


': offset 0x0A0A2320 past file end (0x102)
       CRITICAL: OOB read if parser follows this offset
      [WARN]  Tag '#


': extends past declared profile size (1414091852)
      [WARN]  Tag '

UT': offset 0x5F31445F past file end (0x102)
       CRITICAL: OOB read if parser follows this offset
      [WARN]  Tag '

UT': extends past declared profile size (1414091852)
      [WARN]  Tag '0.0 ': offset 0x302E300A past file end (0x102)
       CRITICAL: OOB read if parser follows this offset
      [WARN]  Tag '0.0 ': extends past declared profile size (1414091852)
      [WARN]  Tag '

*
': offset 0x0A0A0A0A past file end (0x102)
       CRITICAL: OOB read if parser follows this offset

[H28] LUT Dimension Validation (raw fallback)
      [OK] No LUT dimension issues

[H32] Tag Data Type Confusion Detection (raw fallback)
      [OK] All tag type signatures are printable ICC 4CC codes


[H33] mBA/mAB Sub-Element Offset Validation
      [OK] All mBA/mAB sub-element offsets within tag bounds

[H34] Integer Overflow in Sub-Element Bounds
      [OK] No integer overflow in sub-element bounds

[H35] Suspicious Fill Pattern in mBA/mAB Data
      [OK] No suspicious fill patterns in mBA/mAB data

[H36] LUT Tag Pair Completeness
      [OK] All LUT tags properly paired

[H37] Calculator Element Complexity Validation
      [OK] No calculator complexity issues

[H152] Curve Element OOM Size Validation
      [OK] Curve elements within bounded size limits

[H38] Curve Degenerate Value Detection
      [OK] No degenerate curve values detected

[H39] Shared Tag Data Aliasing Detection
      [WARN]  Tags '0
1<' [0x30200A0A+169881902] and '0 0.' [0x300A302E+807416110] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0
1<' [0x30200A0A+169881902] and '0 1
' [0xA0A2031+774900529] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0
1<' [0x30200A0A+169881902] and '.0 0' [0x2E302030+774900273] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0
1<' [0x30200A0A+169881902] and '.0 0' [0x2E302031+774900273] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0
1<' [0x30200A0A+169881902] and '#


' [0xA0A2320+1817512452] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0
1<' [0x30200A0A+169881902] and '0.0 ' [0x302E300A+825110560] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0
1<' [0x30200A0A+169881902] and '

*
' [0xA0A0A0A+774905866] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 0.' [0x300A302E+807416110] and '0 1
' [0xA0A2031+774900529] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 0.' [0x300A302E+807416110] and '.0 0' [0x2E302030+774900273] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 0.' [0x300A302E+807416110] and '.0 0' [0x2E302031+774900273] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 0.' [0x300A302E+807416110] and '#


' [0xA0A2320+1817512452] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 0.' [0x300A302E+807416110] and '

UT' [0x5F31445F+1597055026] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 0.' [0x300A302E+807416110] and '0.0 ' [0x302E300A+825110560] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 0.' [0x300A302E+807416110] and '

*
' [0xA0A0A0A+774905866] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 1
' [0xA0A2031+774900529] and '.0 0' [0x2E302030+774900273] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 1
' [0xA0A2031+774900529] and '.0 0' [0x2E302031+774900273] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 1
' [0xA0A2031+774900529] and '.0 1' [0x2E300000+657930] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 1
' [0xA0A2031+774900529] and '#


' [0xA0A2320+1817512452] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 1
' [0xA0A2031+774900529] and '0.0 ' [0x302E300A+825110560] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0 1
' [0xA0A2031+774900529] and '

*
' [0xA0A0A0A+774905866] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '.0 0' [0x2E302030+774900273] and '.0 0' [0x2E302031+774900273] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '.0 0' [0x2E302030+774900273] and '.0 1' [0x2E300000+657930] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '.0 0' [0x2E302030+774900273] and '#


' [0xA0A2320+1817512452] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '.0 0' [0x2E302030+774900273] and '0.0 ' [0x302E300A+825110560] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '.0 0' [0x2E302030+774900273] and '

*
' [0xA0A0A0A+774905866] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '.0 0' [0x2E302031+774900273] and '.0 1' [0x2E300000+657930] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '.0 0' [0x2E302031+774900273] and '#


' [0xA0A2320+1817512452] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '.0 0' [0x2E302031+774900273] and '0.0 ' [0x302E300A+825110560] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '.0 0' [0x2E302031+774900273] and '

*
' [0xA0A0A0A+774905866] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '.0 1' [0x2E300000+657930] and '#


' [0xA0A2320+1817512452] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '.0 1' [0x2E300000+657930] and '

*
' [0xA0A0A0A+774905866] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '#


' [0xA0A2320+1817512452] and '

UT' [0x5F31445F+1597055026] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '#


' [0xA0A2320+1817512452] and '0.0 ' [0x302E300A+825110560] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '#


' [0xA0A2320+1817512452] and '

*
' [0xA0A0A0A+774905866] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '

UT' [0x5F31445F+1597055026] and '0.0 ' [0x302E300A+825110560] partially overlap
       CWE-119: Partial tag data overlap — parser confusion
      [WARN]  Tags '0.0 ' [0x302E300A+825110560] and '

*
' [0xA0A0A0A+774905866] partially overlap
       CWE-119: Partial tag data overlap — parser confusion

[H40] Tag Alignment Padding
      [WARN]  Tag '0
1<': offset 0x30200A0A not 4-byte aligned
      [WARN]  Tag '0 0.': offset 0x300A302E not 4-byte aligned
      [WARN]  Tag '0 1
': offset 0xA0A2031 not 4-byte aligned
      [WARN]  Tag '.0 0': offset 0x2E302031 not 4-byte aligned
      [WARN]  Tag '

UT': offset 0x5F31445F not 4-byte aligned
      [WARN]  Tag '0.0 ': offset 0x302E300A not 4-byte aligned
      [WARN]  Tag '

*
': offset 0xA0A0A0A not 4-byte aligned

[H41] Version/Type Consistency
      [OK] Version/type consistency OK

[H42] Matrix Singularity
      [OK] No singular matrices detected

[H43] Spectral/BRDF Tag Structure
      [OK] No spectral/BRDF structure issues

[H44] Embedded Image Validation
      [OK] No embedded image issues

[H45] Sparse Matrix Bounds
      [OK] No sparse matrix bounds issues

[H46] TextDescription Unicode Length
      [OK] No text description length issues

[H47] NamedColor2 Size Overflow
      [OK] No NamedColor2 size overflow

[H48] CLUT Grid Dimension Product Overflow
      [OK] CLUT grid dimension products within bounds

[H49] Float/s15Fixed16 NaN/Inf Detection
      [OK] No NaN/Inf values in float tags

[H50] Zero-Size Profile Tag
      [OK] No zero-size tags

[H51] LUT Channel Count Consistency
      [OK] LUT channel counts consistent

[H52] Integer Underflow in Tag Size
      [OK] No integer underflow in tag sizes

[H53] Embedded Profile Recursion
      [OK] No embedded profile recursion detected

[H54] Division by Zero Trigger
      [OK] No division-by-zero triggers

[H55] UTF-16 Encoding Validation
      [OK] UTF-16 encoding OK

[H57] Embedded Profile Recursion Depth
      [OK] No excessive profile nesting

[H59] Spectral Wavelength Range
      [WARN]  Spectral start wavelength 8240 nm outside reasonable range (100-2000)

[H68] Gamut Boundary Description Overflow
      [OK] No gamut boundary overflow

[H69] Profile ID / MD5 Consistency
            Profile ID present: 300a312e...0a0a2e30
      [OK] Profile ID / MD5 consistency OK

[H153] Sampled Curve NaN-to-Unsigned Cast Detection (10.26 MPE)
      [OK] No sampled curve degenerate range entries

[H154] Uncontrolled Tag Allocation Size (CWE-789, §7.3 Tag Table)
      [WARN]  CRITICAL: Tag '0
1<': offset=807406090 size=169881902 exceeds file (258 bytes)
       CWE-789: Uncontrolled allocation — Read() allocates 169881902 bytes from file-controlled size before bounds check
      [WARN]  CRITICAL: Tag '0 0.': offset=805974062 size=807416110 exceeds file (258 bytes)
       CWE-789: Uncontrolled allocation — Read() allocates 807416110 bytes from file-controlled size before bounds check
      [WARN]  CRITICAL: Tag '0 1
': offset=168435761 size=774900529 exceeds file (258 bytes)
       CWE-789: Uncontrolled allocation — Read() allocates 774900529 bytes from file-controlled size before bounds check
      [WARN]  CRITICAL: Tag '.0 0': offset=774905904 size=774900273 exceeds file (258 bytes)
       CWE-789: Uncontrolled allocation — Read() allocates 774900273 bytes from file-controlled size before bounds check
      [WARN]  CRITICAL: Tag '.0 0': offset=774905905 size=774900273 exceeds file (258 bytes)
       CWE-789: Uncontrolled allocation — Read() allocates 774900273 bytes from file-controlled size before bounds check
      [WARN]  CRITICAL: Tag '.0 1': offset=774897664 size=657930 exceeds file (258 bytes)
       CWE-789: Uncontrolled allocation — Read() allocates 657930 bytes from file-controlled size before bounds check
      [WARN]  CRITICAL: Tag '#


': offset=168436512 size=1817512452 exceeds file (258 bytes)
       CWE-789: Uncontrolled allocation — Read() allocates 1817512452 bytes from file-controlled size before bounds check
      [WARN]  CRITICAL: Tag '

UT': offset=1597064287 size=1597055026 exceeds file (258 bytes)
       CWE-789: Uncontrolled allocation — Read() allocates 1597055026 bytes from file-controlled size before bounds check
      [WARN]  CRITICAL: Tag '0.0 ': offset=808333322 size=825110560 exceeds file (258 bytes)
       CWE-789: Uncontrolled allocation — Read() allocates 825110560 bytes from file-controlled size before bounds check
      [WARN]  CRITICAL: Tag '

*
': offset=168430090 size=774905866 exceeds file (258 bytes)
       CWE-789: Uncontrolled allocation — Read() allocates 774905866 bytes from file-controlled size before bounds check

[H155] Integer Overflow in Tag Dimensions (CWE-190, §10.6-10.14)
      [NOT RUN] Invalid tag count

[H156] Allocation Failure Path Profiles (CWE-252, §7.3)
      [WARN]  Aggregate tag allocation: 7931.9 MB across 256 tags
       CWE-252: iccDEV has 88 unchecked allocation sites — aggregate pressure increases OOM probability
      Risk: new/malloc returns NULL -> dereference at IccCmm.cpp, IccMpeSpectral.cpp, IccEncoding.cpp
      [WARN]  9 tags exceed 10MB — high concurrent allocation demand
       CWE-252: Multiple large allocations without error checking increase NULL-deref risk
      [WARN]  Tag sizes total 8317240921 bytes but profile is 1414091852 bytes
       CWE-252: Oversized tag declarations trigger allocation then fail on read — unchecked paths crash

[H157] Alloc-Dealloc Mismatch Tag Patterns (CWE-762, §10.14)
      [OK] No alloc-dealloc mismatch trigger patterns

[H158] Enum Range Validation Extended (CWE-681, §7.2 Header Fields)
      [OK] All enum values within valid ranges

[H159] UAF Tag Ownership Chain Detection (CWE-416, §7.3)
      [OK] No UAF-triggering ownership patterns detected

[H160] Format String Injection in Text Tags (CWE-134, §10.24/§10.22)
      [OK] No format string specifiers in text tags

[H161] Stack Address Escape via Deep Apply Chains (CWE-121, §10.6/§10.14)
      [OK] No deep Apply() chain stack-escape risk patterns

[H173] Signature Conversion Shift Overflow (IccUtil.cpp signature formatting helpers)
      [WARN]  HEURISTIC: 18/18 FourCC signatures trigger UBSAN shift overflow in icGetSig()/icGetSigStr()/icGetColorSig()/icGetColorSigStr() — IccUtil.cpp:1088,1130,1167,1187,1228,1253
       CWE-190: sig<<=8 on uint32 with first byte non-zero produces value > UINT32_MAX (upstream iccDEV library pattern)

[H174] Half-Float Conversion Unsigned Underflow (IccUtil.cpp icF16toF)
      [WARN]  HEURISTIC: 4 half-float value(s) would trigger UBSAN unsigned-wrap in icF16toF() — IccUtil.cpp:665,677 / IccIO.cpp:328
       CWE-190: exponent rebias uses unsigned subtraction for non-zero half-floats with exponent < 15 (values below 1.0)
      header spectralRange.start raw=0x2030 at file+0x68
      header spectralRange.end raw=0x2E30 at file+0x6A
      header biSpectralRange.start raw=0x0A31 at file+0x6E
      header biSpectralRange.end raw=0x2E30 at file+0x70

[H162] Partial Tag Data Overlap Detection
      [WARN]  CRITICAL: Tags '

*
' (off=168430090,sz=774905866) and '0 1
' (off=168435761,sz=774900529) overlap by 774900195 bytes
       CWE-119/CWE-787: Partial tag data overlap — write to one tag corrupts adjacent tag data
      [WARN]  CRITICAL: Tags '0 1
' (off=168435761,sz=774900529) and '#


' (off=168436512,sz=1817512452) overlap by 774899778 bytes
       CWE-119/CWE-787: Partial tag data overlap — write to one tag corrupts adjacent tag data
      [WARN]  CRITICAL: Tags '#


' (off=168436512,sz=1817512452) and '.0 1' (off=774897664,sz=657930) overlap by 1211051300 bytes
       CWE-119/CWE-787: Partial tag data overlap — write to one tag corrupts adjacent tag data
      [WARN]  CRITICAL: Tags '.0 1' (off=774897664,sz=657930) and '.0 0' (off=774905904,sz=774900273) overlap by 649690 bytes
       CWE-119/CWE-787: Partial tag data overlap — write to one tag corrupts adjacent tag data
      [WARN]  CRITICAL: Tags '.0 0' (off=774905904,sz=774900273) and '.0 0' (off=774905905,sz=774900273) overlap by 774900272 bytes
       CWE-119/CWE-787: Partial tag data overlap — write to one tag corrupts adjacent tag data
      [WARN]  CRITICAL: Tags '.0 0' (off=774905905,sz=774900273) and '0 0.' (off=805974062,sz=807416110) overlap by 743832116 bytes
       CWE-119/CWE-787: Partial tag data overlap — write to one tag corrupts adjacent tag data
      [WARN]  CRITICAL: Tags '0 0.' (off=805974062,sz=807416110) and '0
1<' (off=807406090,sz=169881902) overlap by 805984082 bytes
       CWE-119/CWE-787: Partial tag data overlap — write to one tag corrupts adjacent tag data
      [WARN]  CRITICAL: Tags '0
1<' (off=807406090,sz=169881902) and '0.0 ' (off=808333322,sz=825110560) overlap by 168954670 bytes
       CWE-119/CWE-787: Partial tag data overlap — write to one tag corrupts adjacent tag data

[H163] Executable Signature Scan in Tag Data
      [OK] No executable signatures detected in tag data

[H164] Raw LUT Channel Count vs ColorSpace/PCS
      [N/A] Unknown colorspace/PCS signature

[H165] LUT Data Sufficiency Validation
      [OK] All LUT tags have sufficient data for declared contents

[H166] Division-by-Zero in CAM/Array/MPE Detection
      [OK] No division-by-zero risk patterns detected

[H167] Null MPE CLUT/Curve Application Guard
      [OK] No null MPE CLUT/Curve application risks detected

[H168] Unchecked Allocation Size Overflow Detection
      [OK] No unchecked allocation overflow patterns detected

[H169] Dictionary Tag Element Bounds Validation
      [OK] No dictionary tag bounds issues detected

[H170] Copy Constructor UB via Null PCS (CWE-843, §7.2.7)
      [OK] PCS signature valid for copy-constructor safety

[H171] Curve Param Count vs FuncType Validation (CWE-125, §10.15/§10.23)
      [OK] Curve param counts consistent with function types

[H136] ResponseCurve Per-Channel Measurement Count (CWE-400)
      [N/A] Excessive tag count (%u)

HEURISTIC SUMMARY
=======================================================================

[WARN]  122 HEURISTIC WARNING(S) DETECTED

  This profile exhibits patterns associated with:
  - Malformed/corrupted data
  - Resource exhaustion attempts
  - Enum confusion vulnerabilities
  - Parser exploitation attempts
  - Type confusion / buffer overflow patterns

  - Sub-element offset OOB (mBA/mAB SIGBUS pattern)
  - 32-bit integer overflow in bounds checks
  - Suspicious fill patterns enabling OOB traversal

  CVE Coverage: 174 heuristics covering patterns from 87 CVEs + 95 GHSAs across 93 iccDEV security advisories (57 heuristics with CVE/GHSA cross-references)
  Spec conformance: ICC.1-2022-05, ICC.2-2023 — heuristics cite §section references
  Key CVE categories: HBO, OOB, OOM, UAF, SBO, type confusion, integer overflow
  H33-H36: mBA/mAB structural analysis (OOB offsets, integer overflow, fill patterns)
  H37-H45: CFL fuzzer dictionary analysis (calc, curves, v5, BRDF, sparse matrix)
  H46-H54: CWE-driven gap analysis (unicode HBO, ncl2 overflow, CLUT grid, NaN/Inf, recursion)
  H55-H60: UTF-16, calc depth, embedded profiles, spectral, dict
  H61-H70: Viewing conditions, mluc bombs, LUT channels, NamedColor2, chromaticity,
           NumArray NaN/Inf, ResponseCurveSet, GBD overflow, Profile ID, measurement
  H71-H78: ColorantTable null-term, SparseMatrix, nesting depth, type confusion,
           small tags, data flags, calculator sub-elements, CLUT grid overflow
  H79-H86: LoadTag overflow, UAF shared pointers, MPE channel consistency,
           I/O bit-shift overflow, float array SBO, 3D LUT OOB, memcpy overlap, mluc HBO
  H87-H94: TRC curve anomalies, chromatic adaptation matrix, profile sequence,
           preview channels, colorant order, spectral viewing, flags, matrix colorants
  H95-H102: Sparse matrix bounds, embedded profile recursion, profile sequence ID,
            spectral MPE elements, embedded images, sequence desc, MPE chain, tag sizes
  H103-H106: PCC viewing conditions, PRMG gamut evaluation, matrix-TRC validation,
             environment variable tags, spectral range validation
  H107-H115: LUT/colorspace channel cross-check, private tag scan, shellcode patterns,
             class-required tags, reserved bytes, wtpt validation, round-trip fidelity,
             TRC monotonicity, characterization data
  H116-H127: ICC Technical Secretary feedback — cprt/desc encoding, tag-type validation,
             computation cost, ΔE round-trip, curve invertibility, characterization RT,
             deep encoding, non-required tags, version-tag, smoothness, malware scan, registry
  H128-H132: ICC.1-2022-05 spec compliance — version BCD, PCS D50, tag alignment,
             Profile ID MD5, chromaticAdaptation matrix (§7.2.4, §7.2.16, §7.3.1, §7.2.18, Annex G)
  H133-H135: ICC.1-2022-05 additional — flags reserved bits (§7.2.11), tag type reserved
             bytes (§10.1), duplicate tag signatures (§7.3.1)
  H136-H138: CWE-400 systemic — ResponseCurve measurement counts, high-dimensional
             grid complexity, calculator branching depth (CFL-074/075/076 findings)
  H142-H145: XML serialization safety — fork-isolated ToXml(), array bounds precheck,
             string termination validation, curve type consistency (25 XML advisories)

  Recommendations:
  • Validate profile with official ICC tools
  • Use -n (ninja mode) for detailed byte-level analysis
  • Do NOT use in production color workflows
  • Consider as potential security test case


[NOT RUN] Library-phase conformance validation skipped — profile truncated
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

File: /home/h02332/po/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc
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
  Version:         0x64656E74  (100.6.5)
  Device Class:    0x69747920  'ity '
  Color Space:     0x4C555422  'LUT"'
  PCS:             0x0A4C5554  '.LUT'
  Date/Time:       24371-17503-21321 23109:8242:12336
  Magic:           0x30303030  [INVALID]
  Platform:        0x30303030  '0000'
  Flags:           0x30303030
  Manufacturer:    0x3030302E  '000.'
  Model:           0x3020302E  '0 0.'
  Dev Attributes:  0x300A312E30200A0A [Matte]
  Rendering Intent:0x2A0A0A0A  UNKNOWN
  PCS Illuminant:  X=2655.3254 Y=23109.1250 Z=12334.1875
  Creator:         0x302E302E  '0.0.'
  Profile ID:      300a312e30200a0a2a0a0a0a0a0a2e30
  Reserved 100-127: NON-ZERO [VIOLATION]

  --- V5/iccMAX Extended Header ---
  Spectral PCS:    0x0A4C5554  '.LUT'
  Spectral Range:  0.0 - 0.1 nm, 2608 steps
  BiSpectral:      0.0 - 0.1 nm, 8202 steps
  MCS:             0x0A2A0A0A  '.*..'

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
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/ub_sio_parse3Dtable-IccFromCube_cpp-Line218.icc

[NOT RUN] Profile TRUNCATED — round-trip validation not run
       Header claims more bytes than file contains (CWE-125)
```

---

## LUT Text Export (`-xt`)

**Exit Code: 2**

```
Error reading ICC profile
Exported 0 text file(s) to /tmp/tmp.qoXsDmXCBB/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
