# ICC Profile Analysis Report

**Profile**: `sbo-GetValues-FixedNum-crafted-cenc.icc`
**File Size**: 704 bytes
**SHA-256**: `4ed01d7cd294c0cac7102f8028e30c9c790b1ab84236770e0177d1c1d271678d`
**File Type**: color profile 5.0, RGB-cenc device, 704 bytes, PCS X=0 Y=0 Z=0, no copyright tag
**Date**: 2026-03-16T15:27:07Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 1 | Finding detected |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 1**

```
ICC_DEBUG: [../iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
ICC_DEBUG: [../iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x00000000 (Unknown)
ICC_WARN: [../iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h:️ ColorSpace signature: 0x00000000 (Unknown)

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/xss/research/sbo-GetValues-FixedNum-crafted-cenc.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/xss/research/sbo-GetValues-FixedNum-crafted-cenc.icc

=======================================================================
EXTERNAL FILE METADATA
=======================================================================

  [file]
      color profile 5.0, RGB-cenc device, 704 bytes, PCS X=0 Y=0 Z=0, no copyright tag

  [exiftool]
      timeout: failed to run command ‘exiftool’: No such file or directory

  [identify]
      timeout: failed to run command ‘identify’: No such file or directory

  [xxd -l 128]
      00000000: 0000 02c0 0000 0000 0500 0000 6365 6e63  ............cenc
      00000010: 5247 4220 0000 0000 0000 0000 0000 0000  RGB ............
      00000020: 0000 0000 6163 7370 0000 0000 0000 0000  ....acsp........
      00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
      00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
      00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
      00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
      00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................

  [sha256sum]
      4ed01d7cd294c0cac7102f8028e30c9c790b1ab84236770e0177d1c1d271678d  /home/xss/research/sbo-GetValues-FixedNum-crafted-cenc.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 704 bytes (0x000002C0)  [actual file: 704 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x52474220 (RGB)
     [OK] Valid colorSpace: RgbData

[H4] PCS ColorSpace: 0x00000000 (....)
     [WARN]  HEURISTIC: Invalid PCS signature — ICC.1-2022-05 §7.2.7 requires Lab or XYZ; ICC.2-2023 allows spectral
     Risk: Colorimetric transform failures
     Name: Unknown  Bytes: ''

[H5] Platform / CMM / Manufacturer / Creator Validation
      Platform: 0x00000000 (....)
      [OK] Known platform code
      CMM: 0x00000000 (....)
      [OK] CMM signature registered or zero
      Manufacturer: 0x00000000 (....)
      [OK] Manufacturer is zero (unspecified)
      Creator: 0x00000000 (....)
      [OK] Creator is zero (unspecified)

[H6] Rendering Intent: 0 (0x00000000)
     [OK] Valid intent: Perceptual

[H7] Profile Class: 0x63656E63 (cenc)
     [OK] Known class: ColorEncodingClass

[H8] Illuminant XYZ: (0.000000, 0.000000, 0.000000)
     [WARN]  HEURISTIC: PCS illuminant is NOT D50 (spec: 0.9642, 1.0000, 0.8249)
     Risk: Non-conformant header — ICC.1-2022-05 §7.2.16 requires D50

[H15] Date Validation (§4.2 dateTimeNumber): 0-00-00 00:00:00
      [WARN]  HEURISTIC: Invalid month: 0
      [WARN]  HEURISTIC: Invalid day: 0
      [WARN]  HEURISTIC: Suspicious year: 0 (expected 1900-2100)
      Risk: Malformed date may indicate crafted/corrupted profile

[H16] Signature Pattern Analysis
      [OK] No suspicious signature patterns detected

[H17] Spectral Range Validation (ICC.2-2023 §7.2.22-23)
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

[H20] Tag Type Signature Validation
      [OK] All tag type signatures are valid ASCII

[H21] tagStruct Member Inspection
      Tag 'cept' is tagStruct (type='cept', 16 members)
        Member 'bXYZ': type='fl32' size=16 values=2
        Member 'gXYZ': type='fl32' size=16 values=2
        Member 'rXYZ': type='fl32' size=16 values=2
        Member 'func': type='curf' size=72
        Member 'wlum': type='sf32' size=24 values=4
        Member 'wXYZ': type='fl32' size=16 values=2
        Member 'eRng': type='fl32' size=16 values=2
        Member 'bits': type='ui08' size=11 values=3
        Member 'imst': type='sig' size=12
        Member 'ibkg': type='fl32' size=12 values=1
        Member 'srnd': type='fl32' size=12 values=1
        Member 'ailm': type='fl32' size=12 values=1
        Member 'mwpl': type='fl32' size=12 values=1
        Member 'mwpc': type='fl32' size=16 values=2
        Member 'mbpl': type='fl32' size=12 values=1
        Member 'mbpc': type='fl32' size=16 values=2
      [OK] tagStruct members appear well-formed

[H22] NumArray Scalar Expectation (cept struct)
      [WARN]  wlum (WhitePointLuminance) has 4 values (expected 1 scalar)
       Risk: Stack buffer overflow in GetElemNumberValue → GetValues
       (SCARINESS: 51 — 4-byte-write-stack-buffer-overflow, CFL-030)
      [OK] srnd (ViewingSurround): 1 value (scalar)
      [OK] mwpl (MediumWPLuminance): 1 value (scalar)

[H23] NumArray Value Range Validation
      [OK] All NumArray values within normal ranges

[H24] tagStruct/tagArray Nesting Depth
      [OK] Max nesting depth: 1 (safe limit: 4)

[H25] Tag Offset/Size Out-of-Bounds Detection
      [OK] All tag offsets/sizes within bounds

[H26] NamedColor2 String Validation
      [OK] No NamedColor2 tags with risky strings

[H27] MPE Matrix Output Channel Validation
      [OK] All MPE matrix/calculator dimensions valid

[H28] LUT Dimension Validation (OOM Risk)
      [OK] All LUT dimensions within safe limits

[H29] ColorantTable String Validation
      [OK] No ColorantTable string issues detected

[H30] GamutBoundaryDesc Allocation Validation
      [OK] No GamutBoundaryDesc allocation issues

[H31] MPE Channel Count Validation
      [OK] All MPE channel counts within safe limits

[H32] Tag Data Type Confusion Detection
      [OK] All tag type signatures are known ICC types

[H56] Calculator Element Stack Depth Analysis
      [OK] Calculator element depths within safe bounds

[H58] Sparse Matrix Entry Bounds
      [OK] No oversized array/sparse matrix entries

[H60] Dictionary Tag Consistency
      [OK] Dictionary tags consistent

[H61] Viewing Conditions Validation
      [OK] Viewing conditions plausible (or tag absent)

[H62] Multi-Localized Unicode String Bombs
      [OK] MultiLocalizedUnicode tags within bounds

[H63] Curve/LUT I/O Channel Mismatch
      [OK] LUT I/O channel counts valid

[H64] NamedColor2 Device Coord Overflow
      [OK] NamedColor2 dimensions valid (or tag absent)

[H65] Chromaticity Physical Plausibility
      [OK] Chromaticity coordinates plausible (or tag absent)

[H66] Comprehensive NumArray NaN/Inf Scan
      [OK] All numeric arrays free of NaN/Inf

[H67] ResponseCurveSet Bounds
      [OK] ResponseCurveSet bounds valid (or tag absent)

[H70] Measurement Tag Validation
      [OK] Measurement tag valid (or absent)

[H71] ColorantTable Name Null-Termination
      [OK] ColorantTable names properly terminated (or absent)

[H72] SparseMatrixArray Allocation Bounds + Enum Validation
      [OK] SparseMatrixArray allocations and types valid (or absent)

[H73] TagArray/TagStruct Nesting Depth
      [OK] No suspicious TagArray/TagStruct nesting

[H74] Tag Type Signature Consistency
      [OK] Tag type signatures consistent

[H75] Tags with Very Small Size
      [OK] All tags have sufficient minimum size

[H76] CIccTagData Type Flag Validation
      [OK] CIccTagData types valid (or absent)

[H77] MPE Calculator Sub-Element Count
      [OK] MPE calculator element counts within bounds

[H78] CLUT Grid Dimension Product Overflow
      [OK] CLUT grid dimension products within bounds

[H79] LoadTag Allocation Overflow Detection
      [OK] Tag sizes within safe allocation limits

[H80] Shared Tag Pointer / Use-After-Free Pattern
      [OK] No excessive tag pointer sharing detected

[H81] MPE Calculator I/O Channel Consistency
      [OK] MPE calculator channel counts within bounds

[H82] I/O Read Size Overflow Pattern
      [OK] Tag sizes safe for I/O bit-shift operations

[H83] Float/Numeric Array Size Validation
      [OK] Float/numeric array sizes within bounds

[H84] 3D LUT Transform Channel/Grid Consistency
      [OK] 3D LUT channel/grid dimensions consistent

[H85] MPE Buffer Overlap Pattern Detection
      [OK] No excessive MPE buffer overlap patterns

[H86] Localized Unicode Text Bounds Validation
      [OK] Localized Unicode text within bounds

[H87] TRC Curve Anomaly Detection
      [OK] TRC curves within bounds (or absent)

[H88] Chromatic Adaptation Matrix Validation
      [OK] No chromatic adaptation tag (standard D50)

[H89] Profile Sequence Description Validation
      [OK] Profile sequence descriptions within bounds (or absent)

[H90] Preview Tag Channel Consistency
      [OK] Preview tag channels consistent (or absent)

[H91] Colorant Order Validation
      [OK] Colorant order indices valid (or absent)

[H92] Spectral Viewing Conditions Validation
      [OK] No spectral viewing conditions tag (standard PCC)

[H93] Embedded Profile Flag Consistency
      [OK] Profile flags and attributes consistent

[H94] Matrix/TRC Colorant Consistency
      [OK] Matrix/TRC colorant consistency valid (or non-RGB)

[H95] Sparse Matrix Array Bounds Validation
      [SKIP] No sparse matrix array tags present

[H96] Embedded Profile Validation
      [SKIP] No embedded profile tag present

[H97] Profile Sequence Identifier Validation
      [SKIP] No profile sequence ID tag present

[H98] Spectral MPE Element Validation
      [SKIP] No spectral MPE elements present

[H99] Embedded Image Tag Validation
      [SKIP] No embedded image tags present

[H100] Profile Sequence Description Validation
      [SKIP] No profile sequence description tag

[H101] MPE Sub-Element Channel Continuity
      [OK] MPE sub-element channel continuity valid

[H102] Tag Size vs Profile Size Cross-Check
      Profile size: 704 bytes, tag count: 3
      [OK] Tag size vs profile size consistent

[H146] Stack Buffer Overflow — GetValues() Size Mismatch (CWE-121)
      [OK] No stack buffer overflow patterns detected in numeric/LUT tags

[H147] Null Pointer Dereference — Post-Read() Tag State (CWE-476)
      [OK] No null pointer patterns detected in loaded tags

[H148] Memory Copy Bounds and Overlap Detection (CWE-119)
      [OK] No memory copy overlap or bounds issues detected

[H103] Profile Connection Conditions (PCC)
      [INFO] No spectral viewing conditions tag (svcn)
      Standard PCC: yes (D50/2deg)
      Illuminant: 0x00000000, CCT: 0.0, Observer: 0x00000000

[H104] PRMG Gamut Evaluation
      [INFO] No rendering intent gamut tags

[H105] Matrix-TRC Validation
      [INFO] Missing rXYZ/gXYZ/bXYZ colorant tags

[H106] Environment Variable Tags
      [INFO] No environment variable or PCC transform tags

[H107] LUT Channel vs Colorspace Cross-Check
      [WARN]  Cannot determine channel counts (data=3, PCS=0)

[H108] Private Tag Identification
      [INFO] Private/unknown tag: 'rfnm' (0x72666E6D) offset=168 size=20
      [INFO] Private/unknown tag: 'csnm' (0x63736E6D) offset=188 size=13
      [INFO] Private/unknown tag: 'cept' (0x63657074) offset=204 size=500
      [WARN]  3 private/unregistered tag(s) detected
       CWE-829: Private tags may contain unvalidated data

[H109] NOP Sled / Shellcode Pattern Scan
      [OK] No shellcode or executable patterns detected

[H110] Profile-Class Required Tag Validation
      [WARN]  Missing required tag 'desc' for non-DeviceLink class
      [WARN]  Missing required tag 'cprt' for non-DeviceLink class
      [WARN]  Missing required tag 'wtpt' for non-DeviceLink class
      [WARN]  Unknown profile class: 0x63656E63
      Profile class: unknown
      [WARN]  Non-DeviceLink PCS is not Lab/XYZ/spectral: 0x00000000
       CWE-20: Invalid PCS for profile class

[H111] Reserved Byte Validation
      [OK] All reserved header bytes are zero

[H112] Wtpt Profile-Class Validation
      [WARN]  Missing wtpt tag (required for non-DeviceLink)

[H113] Round-Trip Fidelity Assessment
      [OK] Round-trip tag geometry is consistent

[H114] TRC Curve Smoothness and Monotonicity
      [INFO] No TRC curve tags found

[H115] Characterization Data Presence
      [INFO] No characterization data (targ) tag present

[H116] cprt/desc Encoding vs Profile Version
      Profile version: 5.0.0
      cprt: not present
      desc: not present

[H117] Tag Type Allowed Per Signature
      [INFO] No applicable tags found

[H118] Calculator Computation Cost Estimate
      [INFO] No MPE calculator/CLUT elements found

[H119] Round-Trip ΔE Measurement
      [INFO] No AToB/BToA CLUT pairs available for ΔE measurement

[H120] Curve Invertibility Assessment
      [INFO] No TRC curves found for invertibility check

[H121] Characterization Data Round-Trip Capability
      [INFO] No characterization data (targ) tag — cannot assess

[H122] Tag Type Encoding Validation
      [INFO] No applicable tags for deep encoding validation

[H123] Non-Required Tag Classification
      [INFO] 'rfnm' (0x72666E6D): not required/optional for class 'cenc'
      [INFO] 'csnm' (0x63736E6D): not required/optional for class 'cenc'
      [INFO] 'cept' (0x63657074): not required/optional for class 'cenc'
      [WARN]  3 tag(s) not in required/optional set for this profile class
       CWE-20: Non-standard tags should be registered as private

[H124] Version-Tag Correspondence
      [OK] Tags correspond to profile version 5

[H125] Overall Transform Smoothness
      [INFO] No suitable LUT tags for smoothness measurement

[H126] Private Tag Malware Content Scan
      [OK] 3 private tag(s) scanned — no malware signatures found

[H127] Private Tag Registry Check
      [WARN]  'rfnm' (0x72666E6D): not found in private tag registry
       CWE-20: Undocumented private tag
      [WARN]  'csnm' (0x63736E6D): not found in private tag registry
       CWE-20: Undocumented private tag
      [WARN]  'cept' (0x63657074): not found in private tag registry
       CWE-20: Undocumented private tag
      Summary: 3 private tag(s) — 0 registered, 3 undocumented

[H128] Version BCD Encoding Validation
      Version bytes: 05 00 00 00 → v5.0.0
      [OK] Version BCD encoding is valid

[H129] PCS Illuminant Exact D50 Check
      Raw bytes: X=0x00000000 Y=0x00000000 Z=0x00000000
      Float:     X=0.000000   Y=0.000000   Z=0.000000
      D50 spec:  X=0x0000F6D6 Y=0x00010000 Z=0x0000D32D
      [INFO] PCS illuminant is not D50 (valid for ICC.2/v5 spectral profiles)

[H130] Tag Data 4-Byte Alignment
      [OK] All 3 tags are 4-byte aligned

[H131] Profile ID (MD5) Validation
      Profile ID: 00000000000000000000000000000000
      [INFO] Profile ID is all zeros (not computed)
       ICC.1-2022-05 §7.2.18: ID may be zero if not computed

[H132] chromaticAdaptation Matrix Validation
      [INFO] No chromaticAdaptation (chad) tag present

[H133] Profile Flags Reserved Bits (ICC.1-2022-05 §7.2.11)
      Flags: 0x00000000 (embedded=0, independent=0)
      [OK] Reserved flag bits are zero

[H134] Tag Type Reserved Bytes (ICC.1-2022-05 §10.1)
      [OK] All 3 tag types have zeroed reserved bytes

[H135] Duplicate Tag Signatures (ICC.1-2022-05 §7.3.1)
      [OK] All 3 tag signatures are unique

[H137] High-Dimensional Color Space Grid Complexity (CWE-400)
      [OK] Color space dimensionality within safe bounds

[H138] Calculator Element Branching Depth (CWE-400/CWE-674)
      [INFO] No calculator elements found

[H142] XML Serialization Safety (§10 Tag Type Definitions)
      [OK] XML serialization completed safely (ToXml succeeded)

[H143] XML Array Bounds Precheck (§10 Tag Types)
      [OK] All array tag element counts consistent with data sizes

[H144] XML String Termination Precheck (§10.4/§10.19)
      [OK] All string fields properly null-terminated for XML serialization

[H145] XML Curve Type Consistency (§10.14 MPE)
      [OK] All curve/MPE type signatures consistent for XML serialization

[H33] mBA/mAB Sub-Element Offset Validation
      [OK] All mBA/mAB sub-element offsets within tag bounds

[H34] 32-bit Integer Overflow in Sub-Element Bounds
      [OK] No 32-bit integer overflow in sub-element offsets

[H35] Suspicious Fill Pattern in mBA/mAB Data
      [OK] No suspicious fill patterns in mBA/mAB data

[H36] LUT Tag Pair Completeness
      [OK] All LUT tags properly paired

[H37] Calculator Element Complexity Validation
      [OK] No calculator complexity issues

[H38] Curve Degenerate Value Detection
      [OK] No degenerate curve values detected

[H39] Shared Tag Data Aliasing Detection
      [OK] No risky shared tag data aliasing

[H40] Tag Alignment & Padding Validation
      [OK] All tags properly aligned with zero padding

[H41] Version/Type Consistency Check
      Profile version: 5.0.0
      [OK] All tags/types consistent with declared version

[H42] Matrix Singularity Detection
      [INFO]  rXYZ/gXYZ/bXYZ tags not all present (0/3 found)
      [OK] Color matrix is well-conditioned

[H43] Spectral/BRDF Tag Structural Validation
      [WARN]  Illuminant ≠ D50 but 'chad' (chromaticAdaptation) tag missing
       CWE-20: ICC.1-2022-05 Annex G requires chad when adopted white ≠ D50

[H44] Embedded Image Validation
      [OK] Embedded images valid (or none present)

[H45] Sparse Matrix Bounds Validation
      [OK] Sparse matrix bounds valid (or none present)

[H46] TextDescription Unicode Length Validation
      [OK] TextDescription unicode lengths valid (or no desc tags)

[H47] NamedColor2 Size Overflow Detection
      [OK] NamedColor2 sizes valid (or no ncl2 tags)

[H48] CLUT Grid Dimension Product Overflow
      [OK] CLUT grid dimension products within bounds

[H49] Float/s15Fixed16 NaN/Inf Detection
      [OK] No NaN/Inf/extreme values in float/fixed-point tags

[H50] Zero-Size Profile/Tag Detection (Infinite Loop)
      [OK] No zero-size profile or tags detected

[H51] LUT I/O Channel Count Consistency
      [OK] LUT I/O channel counts within valid range

[H52] Integer Underflow in Tag Size Subtraction
      [OK] All tag sizes meet minimum requirements

[H53] Embedded Profile Recursion Detection
      [OK] No embedded profiles detected

[H54] Division-by-Zero Trigger Detection
      [OK] No division-by-zero triggers detected

[H55] UTF-16 Encoding Validation
      [OK] UTF-16 encoding appears valid

[H57] Embedded Profile Recursion Depth
      [OK] No embedded profiles detected

[H59] Spectral Wavelength Range Consistency
      [OK] Spectral range fields consistent

[H68] GamutBoundaryDesc Triangle/Vertex Overflow
      [OK] GamutBoundaryDesc bounds valid (or absent)

[H69] Profile ID / MD5 Consistency
      [INFO] Profile ID is all zeros (MD5 not computed)

[H153] Sampled Curve NaN-to-Unsigned Cast Detection (§10.26 MPE)
      [OK] No sampled curve degenerate range entries

[H154] Uncontrolled Tag Allocation Size (CWE-789, §7.3 Tag Table)
      [OK] All tag allocation sizes within bounds

[H155] Integer Overflow in Tag Dimensions (CWE-190, §10.6-10.14)
      [OK] No integer overflow in tag dimension calculations

[H156] Allocation Failure Path Profiles (CWE-252, §7.3)
      [OK] Allocation pressure within safe bounds

[H157] Alloc-Dealloc Mismatch Tag Patterns (CWE-762, §10.14)
      [OK] No alloc-dealloc mismatch trigger patterns

[H158] Enum Range Validation Extended (CWE-681, §7.2 Header Fields)
      [OK] All enum values within valid ranges

[H159] UAF Tag Ownership Chain Detection (CWE-416, §7.3)
      [OK] No UAF-triggering ownership patterns detected

[H136] ResponseCurve Per-Channel Measurement Count (CWE-400)
      [OK] ResponseCurve measurement counts within bounds (or tag absent)

HEURISTIC SUMMARY
=======================================================================

[WARN]  23 HEURISTIC WARNING(S) DETECTED

  This profile exhibits patterns associated with:
  - Malformed/corrupted data
  - Resource exhaustion attempts
  - Enum confusion vulnerabilities
  - Parser exploitation attempts
  - Type confusion / buffer overflow patterns

  - Sub-element offset OOB (mBA/mAB SIGBUS pattern)
  - 32-bit integer overflow in bounds checks
  - Suspicious fill patterns enabling OOB traversal

  CVE Coverage: 159 heuristics covering patterns from 87 CVEs + 95 GHSAs across 93 iccDEV security advisories (57 heuristics with CVE/GHSA cross-references)
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


=======================================================================
PHASE 2: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/xss/research/sbo-GetValues-FixedNum-crafted-cenc.icc

Device Class: 0x63656E63

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [ ] [ ]  
  AToB1/BToA1 (Rel. Colorimetric): [ ] [ ]  
  AToB2/BToA2 (Saturation):        [ ] [ ]  

  DToB0/BToD0 (Perceptual):        [ ] [ ]  
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]  
  DToB2/BToD2 (Saturation):        [ ] [ ]  

  Matrix/TRC Tags:                 [ ]  

[ERR] RESULT: Profile does NOT support round-trip validation
   (Missing symmetric AToB/BToA, DToB/BToD, or Matrix/TRC tag pairs)

Result: NOT round-trip capable

=======================================================================
PHASE 3: SIGNATURE ANALYSIS
=======================================================================


=== Signature Analysis ===

Header Signatures:
  Device Class:    0x63656E63  ''  ColorEncodingClass
  Color Space:     0x52474220  'RGB'  RgbData
  PCS:             0x00000000  '....'  NoData [WARN] non-printable
  Manufacturer:    0x00000000  '....'
  Model:           0x00000000  '....'

Tag Signatures:
Idx  Tag          FourCC     Type         Issues
---  ------------ ---------- ------------ ------
0    referenceNameTag 'rfnm    '  utf8Type    
1    colorSpaceNameTag 'csnm    '  utf8Type    
2    colorEncodingParamsTag 'cept    '  tagStructType

Summary: 1 signature issue(s) detected

=======================================================================
PHASE 4: PROFILE STRUCTURE DUMP
=======================================================================

=== ICC Profile Header ===

=== ICC Profile Header (0x0000-0x007F) ===
0x0000: 00 00 02 C0 00 00 00 00  05 00 00 00 63 65 6E 63  |............cenc|
0x0010: 52 47 42 20 00 00 00 00  00 00 00 00 00 00 00 00  |RGB ............|
0x0020: 00 00 00 00 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields:
  Size:              0x000002C0 (704 bytes)
  CMM Type:          '....' (0x00000000)
  Version:           5.0.0.0 (0x05000000)
  Device Class:      ColorEncodingClass
  Color Space:       RgbData (3 channels)
  PCS:               NoData
  Date/Time:         0000-00-00 00:00:00
  Magic:             0x61637370 [OK]
  Platform:          Unknown
  Profile Flags:     0x00000000
  Manufacturer:      '....' (0x00000000)
  Model:             '....' (0x00000000)
  Device Attribs:    0x0000000000000000
  Rendering Intent:  Perceptual (0)
  PCS Illuminant:    X=0.0000 Y=0.0000 Z=0.0000
  Creator:           '....' (0x00000000)
  Profile ID:        (not set)

  --- ICC v5/iccMAX Extended Header ---
  Spectral PCS:      NoSpectralData
  Spectral Range:    Not Defined
  BiSpectral Range:  Not Defined
  MCS Color Space:   Not Defined

=== Tag Table ===

=== Tag Table ===
Tag Count: 3

Tag Table Raw Data (0x0080-0x00A8):
0x0080: 00 00 00 03 72 66 6E 6D  00 00 00 A8 00 00 00 14  |....rfnm........|
0x0090: 63 73 6E 6D 00 00 00 BC  00 00 00 0D 63 65 70 74  |csnm........cept|
0x00A0: 00 00 00 CC 00 00 01 F4                           |........|

Tag Entries:
Idx  Signature    FourCC       Offset     Size
---  ------------ ------------ ---------- ----
0    referenceNameTag 'rfnm      '  0x000000A8  20
1    colorSpaceNameTag 'csnm      '  0x000000BC  13
2    colorEncodingParamsTag 'cept      '  0x000000CC  500

=======================================================================
PHASE 5: TAG CONTENT ANALYSIS
=======================================================================

--- 5A: LUT Tag Geometry ---

  No legacy LUT tags (A2B/B2A/D2B/B2D) found

--- 5B: MPE Element Chains ---

  No MPE tags found

--- 5C: TRC Curve Analysis ---

  No TRC curve tags found

--- 5D: NamedColor2 Validation ---

  No NamedColor2 tag

--- 5E: XYZ Tag Values ---

  No XYZ colorant/white-point tags

--- 5F: ICC v5 Spectral Data ---

  No ICC v5 spectral tags

--- 5G: Profile ID Verification ---

  Profile ID: not set (all zeros)
      INFO: Profile integrity cannot be verified without ID

--- 5H: Per-Tag Size Analysis ---

  Tag sizes (flagging >10MB):
      [OK] All tags within 10MB limit

--- 5I: V5/iccMAX Summary ---

  --- V5/iccMAX Profile Summary ---

  BRDF Tags:              0 of 16 present
  Gamut Boundary Desc:    gbd0=---  gbd1=---

  MPE Tags:               0 (multiProcessElementType)
  Total MPE Elements:     0
  Calculator Elements:    0
  Late-Binding Elements:  0 (spectral observer/emission)

--- 5J: Version Classification & Capabilities ---

  Version Classification:
    ICC Version:       5.0.0
    Specification:     ICC.2 (iccMAX)
    Features:          MPE, Spectral PCS, Calculator, BRDF, MCS, Named Colors
    Device Class:      ColorEncodingClass
    Color Space:       RgbData (3 channels)
    Connection Space:  NoData

  Transform Capabilities:
    AToB (device→PCS):   no
    BToA (PCS→device):   no
    DToB (device→PCS):   no
    BToD (PCS→device):   no
    TRC (matrix/gamma):  no
    Gamut check:         no
    Chromatic adapt:     no
    Preview:             no


=======================================================================
COMPREHENSIVE ANALYSIS SUMMARY
=======================================================================

File: /home/xss/research/sbo-GetValues-FixedNum-crafted-cenc.icc
Total Issues Detected: 24

[WARN] ANALYSIS COMPLETE - 24 issue(s) detected
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

File: /home/xss/research/sbo-GetValues-FixedNum-crafted-cenc.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 704 bytes (0x2C0)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 02 C0 00 00 00 00  05 00 00 00 63 65 6E 63  |............cenc|
0x0010: 52 47 42 20 00 00 00 00  00 00 00 00 00 00 00 00  |RGB ............|
0x0020: 00 00 00 00 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x000002C0 (704 bytes) OK
  CMM:             0x00000000  '....'
  Version:         0x05000000  (5.0.0)
  Device Class:    0x63656E63  'cenc'
  Color Space:     0x52474220  'RGB '
  PCS:             0x00000000  '....'
  Date/Time:       0000-00-00 00:00:00
  Magic:           0x61637370  [OK 'acsp']
  Platform:        0x00000000  '....'
  Flags:           0x00000000
  Manufacturer:    0x00000000  '....'
  Model:           0x00000000  '....'
  Dev Attributes:  0x0000000000000000
  Rendering Intent:0x00000000  Perceptual
  PCS Illuminant:  X=0.0000 Y=0.0000 Z=0.0000
  Creator:         0x00000000  '....'
  Profile ID:      00000000000000000000000000000000  (not set)
  Reserved 100-127: all zeros [OK]

  --- V5/iccMAX Extended Header ---
  Spectral PCS:    0x00000000  '....'
  Spectral Range:  Not defined

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 3 (0x00000003)

Tag Table Raw Data:
0x0080: 00 00 00 03 72 66 6E 6D  00 00 00 A8 00 00 00 14  |....rfnm........|
0x0090: 63 73 6E 6D 00 00 00 BC  00 00 00 0D 63 65 70 74  |csnm........cept|
0x00A0: 00 00 00 CC 00 00 01 F4                           |........|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x72666E6D   'rfnm'        0x000000A8   0x00000014   'utf8'        OK
1    0x63736E6D   'csnm'        0x000000BC   0x0000000D   'utf8'        OK
2    0x63657074   'cept'        0x000000CC   0x000001F4   'tstr'        OK

=== FULL FILE HEX DUMP (all 704 bytes) ===
0x0000: 00 00 02 C0 00 00 00 00  05 00 00 00 63 65 6E 63  |............cenc|
0x0010: 52 47 42 20 00 00 00 00  00 00 00 00 00 00 00 00  |RGB ............|
0x0020: 00 00 00 00 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0080: 00 00 00 03 72 66 6E 6D  00 00 00 A8 00 00 00 14  |....rfnm........|
0x0090: 63 73 6E 6D 00 00 00 BC  00 00 00 0D 63 65 70 74  |csnm........cept|
0x00A0: 00 00 00 CC 00 00 01 F4  75 74 66 38 00 00 00 00  |........utf8....|
0x00B0: 49 53 4F 20 32 32 30 32  38 2D 31 00 75 74 66 38  |ISO 22028-1.utf8|
0x00C0: 00 00 00 00 73 52 47 42  00 00 00 00 74 73 74 72  |....sRGB....tstr|
0x00D0: 00 00 00 00 63 65 70 74  00 00 00 10 62 58 59 5A  |....cept....bXYZ|
0x00E0: 00 00 00 D0 00 00 00 10  67 58 59 5A 00 00 00 E0  |........gXYZ....|
0x00F0: 00 00 00 10 72 58 59 5A  00 00 00 F0 00 00 00 10  |....rXYZ........|
0x0100: 66 75 6E 63 00 00 01 00  00 00 00 48 77 6C 75 6D  |func.......Hwlum|
0x0110: 00 00 01 48 00 00 00 18  77 58 59 5A 00 00 01 60  |...H....wXYZ...`|
0x0120: 00 00 00 10 65 52 6E 67  00 00 01 70 00 00 00 10  |....eRng...p....|
0x0130: 62 69 74 73 00 00 01 80  00 00 00 0B 69 6D 73 74  |bits........imst|
0x0140: 00 00 01 8C 00 00 00 0C  69 62 6B 67 00 00 01 98  |........ibkg....|
0x0150: 00 00 00 0C 73 72 6E 64  00 00 01 A4 00 00 00 0C  |....srnd........|
0x0160: 61 69 6C 6D 00 00 01 B0  00 00 00 0C 6D 77 70 6C  |ailm........mwpl|
0x0170: 00 00 01 BC 00 00 00 0C  6D 77 70 63 00 00 01 C8  |........mwpc....|
0x0180: 00 00 00 10 6D 62 70 6C  00 00 01 D8 00 00 00 0C  |....mbpl........|
0x0190: 6D 62 70 63 00 00 01 E4  00 00 00 10 66 6C 33 32  |mbpc........fl32|
0x01A0: 00 00 00 00 3E 19 99 9A  3D 75 C2 8F 66 6C 33 32  |....>...=u..fl32|
0x01B0: 00 00 00 00 3E 99 99 9A  3F 19 99 9A 66 6C 33 32  |....>...?...fl32|
0x01C0: 00 00 00 00 3F 23 D7 0A  3E A8 F5 C3 63 75 72 66  |....?#..>...curf|
0x01D0: 00 00 00 00 00 02 00 00  3B 4D 2E 1C 70 61 72 66  |........;M..parf|
0x01E0: 00 00 00 00 00 00 00 00  3F 80 00 00 41 4E B8 52  |........?...AN.R|
0x01F0: 00 00 00 00 00 00 00 00  70 61 72 66 00 00 00 00  |........parf....|
0x0200: 00 00 00 00 3E D5 55 55  3F 91 8D 1D 00 00 00 00  |....>.UU?.......|
0x0210: BD 61 47 AE 73 66 33 32  00 00 00 00 00 50 00 00  |.aG.sf32.....P..|
0x0220: 03 E7 00 00 04 D2 00 00  16 2E 00 00 66 6C 33 32  |............fl32|
0x0230: 00 00 00 00 3E A0 1A 37  3E A8 72 B0 66 6C 33 32  |....>..7>.r.fl32|
0x0240: 00 00 00 00 00 00 00 00  3F 80 00 00 75 69 30 38  |........?...ui08|
0x0250: 00 00 00 00 00 08 10 00  73 69 67 20 00 00 00 00  |........sig ....|
0x0260: 64 6F 72 63 66 6C 33 32  00 00 00 00 41 80 00 00  |dorcfl32....A...|
0x0270: 66 6C 33 32 00 00 00 00  40 83 33 33 66 6C 33 32  |fl32....@.33fl32|
0x0280: 00 00 00 00 42 80 00 00  66 6C 33 32 00 00 00 00  |....B...fl32....|
0x0290: 42 A0 00 00 66 6C 33 32  00 00 00 00 3E A0 1A 37  |B...fl32....>..7|
0x02A0: 3E A8 72 B0 66 6C 33 32  00 00 00 00 42 A0 00 00  |>.r.fl32....B...|
0x02B0: 66 6C 33 32 00 00 00 00  3E A0 1A 37 3E A8 72 B0  |fl32....>..7>.r.|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 1**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/xss/research/sbo-GetValues-FixedNum-crafted-cenc.icc

Device Class: 0x63656E63

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [ ] [ ]  
  AToB1/BToA1 (Rel. Colorimetric): [ ] [ ]  
  AToB2/BToA2 (Saturation):        [ ] [ ]  

  DToB0/BToD0 (Perceptual):        [ ] [ ]  
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]  
  DToB2/BToD2 (Saturation):        [ ] [ ]  

  Matrix/TRC Tags:                 [ ]  

[ERR] RESULT: Profile does NOT support round-trip validation
   (Missing symmetric AToB/BToA, DToB/BToD, or Matrix/TRC tag pairs)
```
