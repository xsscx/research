# ICC Profile Analysis Report

**Profile**: `test-profiles/BlacklightPoster_202143.icc`
**File Size**: 16680 bytes
**SHA-256**: `4227ce8eff19f3224c74a386116ed559a610cbfbf8a2278d9dccaf925d1bfb10`
**File Type**: ColorSync color profile 2.1, type ADBE, Lab/Lab-abst device by ADBE, 16680 bytes, 7-11-2011 2:49:01, relative colorimetric "Blacklight Poster"
**Date**: 2026-03-19T09:12:29Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 1 | Finding detected |
| `-xt` (LUT text export) | 0 | Exported |
| `-cube` (cube export) | 1 | No 3D CLUT |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 1**

```

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/xss/research/test-profiles/BlacklightPoster_202143.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/xss/research/test-profiles/BlacklightPoster_202143.icc

=======================================================================
EXTERNAL FILE METADATA
=======================================================================

  [file]
      ColorSync color profile 2.1, type ADBE, Lab/Lab-abst device by ADBE, 16680 bytes, 7-11-2011 2:49:01, relative colorimetric "Blacklight Poster"

  [exiftool]
      ExifTool Version Number         : 12.76
      File Name                       : BlacklightPoster_202143.icc
      Directory                       : /home/xss/research/test-profiles
      File Size                       : 17 kB
      File Modification Date/Time     : 2026:03:14 15:00:55+00:00
      File Access Date/Time           : 2026:03:19 04:36:19+00:00
      File Inode Change Date/Time     : 2026:03:14 15:00:55+00:00
      File Permissions                : -rw-rw-r--
      File Type                       : ICC
      File Type Extension             : icc
      MIME Type                       : application/vnd.iccprofile
      Profile CMM Type                : Adobe Systems Inc.
      Profile Version                 : 2.1.0
      Profile Class                   : Abstract Profile
      Color Space Data                : Lab
      Profile Connection Space        : Lab
      Profile Date Time               : 2011:11:07 02:49:01
      Profile File Signature          : acsp
      Primary Platform                : Apple Computer Inc.
      CMM Flags                       : Not Embedded, Independent
      Device Manufacturer             : none
      Device Model                    : 
      Device Attributes               : Reflective, Glossy, Positive, Color
      Rendering Intent                : Media-Relative Colorimetric
      Connection Space Illuminant     : 0.9642 1 0.82491
      Profile Creator                 : Adobe Systems Inc.
      Profile ID                      : 0
      Profile Description             : Blacklight Poster
      Profile Copyright               : Copyright 2011 Adobe Systems Inc.
      Media White Point               : 0.9642 1 0.82491

  [identify]
      Image:
        Filename: /home/xss/research/test-profiles/BlacklightPoster_202143.icc
        Permissions: rw-rw-r--
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
      00000000: 0000 4128 4144 4245 0210 0000 6162 7374  ..A(ADBE....abst
      00000010: 4c61 6220 4c61 6220 07db 000b 0007 0002  Lab Lab ........
      00000020: 0031 0001 6163 7370 4150 504c 0000 0000  .1..acspAPPL....
      00000030: 6e6f 6e65 0000 0000 0000 0000 0000 0000  none............
      00000040: 0000 0001 0000 f6d6 0001 0000 0000 d32d  ...............-
      00000050: 4144 4245 0000 0000 0000 0000 0000 0000  ADBE............
      00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
      00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................

  [sha256sum]
      4227ce8eff19f3224c74a386116ed559a610cbfbf8a2278d9dccaf925d1bfb10  /home/xss/research/test-profiles/BlacklightPoster_202143.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 16680 bytes (0x00004128)  [actual file: 16680 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x4C616220 (Lab)
     [OK] Valid colorSpace: LabData

[H4] PCS ColorSpace: 0x4C616220 (Lab)
     [OK] Valid PCS: LabData

[H5] Platform / CMM / Manufacturer / Creator Validation
      Platform: 0x4150504C (APPL)
      [OK] Known platform code
      CMM: 0x41444245 (ADBE)
      [OK] CMM signature registered or zero
      Manufacturer: 0x6E6F6E65 (none)
      [OK] Manufacturer signature is printable ASCII
      Creator: 0x41444245 (ADBE)
      [OK] Creator signature is printable ASCII

[H6] Rendering Intent: 1 (0x00000001)
     [OK] Valid intent: Relative Colorimetric

[H7] Profile Class: 0x61627374 (abst)
     [OK] Known class: AbstractClass

[H8] Illuminant XYZ: (0.964203, 1.000000, 0.824905)
     [OK] PCS illuminant matches D50 (within s15Fixed16 tolerance)

[H15] Date Validation (§4.2 dateTimeNumber): 2011-11-07 02:49:01
      [OK] Date values within valid ranges

[H16] Signature Pattern Analysis
      [OK] No suspicious signature patterns detected

[H17] Spectral Range Validation (ICC.2-2023 §7.2.22-23)
      [OK] No spectral data (standard profile)

=======================================================================
TAG-LEVEL HEURISTICS
=======================================================================

[H9] Critical Text Tags:
     Description: Present [OK]
     Copyright: Present [OK]
     Manufacturer: Missing
     Device Model: Missing

[H10] Tag Count: 4
      [OK] Tag count within normal range

[H11] CLUT Entry Limit Check
      Max safe CLUT entries per tag: 16777216 (16M)
      Inspected 1 CLUT tag(s)

[H12] MPE Chain Depth Check
      Max MPE elements per chain: 1024
      [OK] No MPE tags to check

[H13] Per-Tag Size Check
      Max tag size: 64 MB (67108864 bytes)
      [OK] All 4 tags within size limits

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
      [OK] No tagStruct tags present

[H22] NumArray Scalar Expectation (cept struct)
      [OK] No cept (ColorEncodingParams) tag — check not applicable

[H23] NumArray Value Range Validation
      [OK] All NumArray values within normal ranges

[H24] tagStruct/tagArray Nesting Depth
      [OK] Max nesting depth: 0 (safe limit: 4)

[H25] Tag Offset/Size Out-of-Bounds Detection
      [OK] All tag offsets/sizes within bounds

[H26] NamedColor2 String Validation
      [OK] No NamedColor2 tags with risky strings

[H27] MPE Matrix Output Channel Validation
      [OK] All MPE matrix/calculator dimensions valid

[H28] LUT Dimension Validation (OOM Risk)
      [OK] Tag 'A2B0' (LUT8): 2x3x17 → 867 points
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
      [WARN]  Tag 'AToB0Tag': CLUT input dim=2 != colorSpace channels=3
       CWE-125: 3D LUT dimension mismatch (CVE-2026-25585)

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
      Profile size: 16680 bytes, tag count: 4
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
      Illuminant: 0x00000001, CCT: 5000.0, Observer: 0x00000001

[H104] PRMG Gamut Evaluation
      [INFO] No rendering intent gamut tags

[H105] Matrix-TRC Validation
      [INFO] Not an RGB profile — matrix-TRC check skipped

[H106] Environment Variable Tags
      [INFO] No environment variable or PCC transform tags

[H107] LUT Channel vs Colorspace Cross-Check
      Declared data colorspace channels: 3
      Declared PCS channels: 3
      [WARN]  AToB0: input channels (2) != data colorspace (3)
       CWE-131: Channel/colorspace mismatch — buffer overflow risk

[H108] Private Tag Identification
      [OK] All tags are registered ICC signatures

[H109] NOP Sled / Shellcode Pattern Scan
      [OK] No shellcode or executable patterns detected

[H110] Profile-Class Required Tag Validation
      Profile class: Abstract (abst)
      [OK] Profile class and required tags are consistent

[H111] Reserved Byte Validation
      [OK] All reserved header bytes are zero

[H112] Wtpt Profile-Class Validation
      wtpt: X=0.964203 Y=1.000000 Z=0.824905
      [OK] wtpt is physically plausible
      (Matches D50 reference illuminant)

[H113] Round-Trip Fidelity Assessment
      Perceptual intent:
        AToB0 present (2in→3out) but BToA0 MISSING
        [INFO] One-way transform only — no round-trip possible
      [OK] Round-trip tag geometry is consistent

[H114] TRC Curve Smoothness and Monotonicity
      [INFO] No TRC curve tags found

[H115] Characterization Data Presence
      [INFO] No characterization data (targ) tag present

[H116] cprt/desc Encoding vs Profile Version
      Profile version: 2.1.0
      cprt: type='text' (0x74657874)
      [OK] cprt uses acceptable type for v2
      desc: type='desc' (0x64657363)
      [OK] desc uses acceptable type for v2

[H117] Tag Type Allowed Per Signature
      [OK] 3 tags checked — all use allowed types

[H118] Calculator Computation Cost Estimate
      [INFO] No MPE calculator/CLUT elements found

[H119] Round-Trip ΔE Measurement
      [INFO] No AToB/BToA CLUT pairs available for ΔE measurement

[H120] Curve Invertibility Assessment
      [INFO] No TRC curves found for invertibility check

[H121] Characterization Data Round-Trip Capability
      [INFO] No characterization data (targ) tag — cannot assess

[H122] Tag Type Encoding Validation
      [OK] 1 tag types validated — encoding correct

[H123] Non-Required Tag Classification
      [OK] All tags are required or optional for this profile class

[H124] Version-Tag Correspondence
      [OK] Tags correspond to profile version 2

[H125] Overall Transform Smoothness
      AToB0 (grid=17, 2in/3out): avg step=0.141526  max step=1.013230
      [WARN]  AToB0: large discontinuity (max step > 0.5) — poor smoothness

[H126] Private Tag Malware Content Scan
      [INFO] No private tags to scan

[H127] Private Tag Registry Check
      [OK] No private tags present

[H128] Version BCD Encoding Validation
      Version bytes: 02 10 00 00 → v2.1.0
      [OK] Version BCD encoding is valid

[H129] PCS Illuminant Exact D50 Check
      Raw bytes: X=0x0000F6D6 Y=0x00010000 Z=0x0000D32D
      Float:     X=0.964203   Y=1.000000   Z=0.824905
      D50 spec:  X=0x0000F6D6 Y=0x00010000 Z=0x0000D32D
      [OK] PCS illuminant is exact D50

[H130] Tag Data 4-Byte Alignment
      [OK] All 4 tags are 4-byte aligned

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
      [OK] All 4 tag types have zeroed reserved bytes

[H135] Duplicate Tag Signatures (ICC.1-2022-05 §7.3.1)
      [OK] All 4 tag signatures are unique

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
      [INFO]  A2B0 present but B2A0 missing — forward-only LUT
      1 unpaired LUT tag(s) — may indicate crafted profile

[H37] Calculator Element Complexity Validation
      [OK] No calculator complexity issues

[H38] Curve Degenerate Value Detection
      [OK] No degenerate curve values detected

[H39] Shared Tag Data Aliasing Detection
      [OK] No risky shared tag data aliasing

[H40] Tag Alignment & Padding Validation
      [OK] All tags properly aligned with zero padding

[H41] Version/Type Consistency Check
      Profile version: 2.1.0
      [OK] All tags/types consistent with declared version

[H42] Matrix Singularity Detection
      [INFO]  rXYZ/gXYZ/bXYZ tags not all present (0/3 found)
      [OK] Color matrix is well-conditioned

[H43] Spectral/BRDF Tag Structural Validation
      [OK] Spectral/BRDF tags structurally valid

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

[H160] Format String Injection in Text Tags (CWE-134, §10.24/§10.22)
      [OK] No format string specifiers in text tags

[H161] Stack Address Escape via Deep Apply Chains (CWE-121, §10.6/§10.14)
      [OK] No deep Apply() chain stack-escape risk patterns

[H162] Partial Tag Data Overlap Detection
      [OK] No partial tag data overlaps detected

[H163] Executable Signature Scan in Tag Data
      [OK] No executable signatures detected in tag data

[H164] Raw LUT Channel Count vs ColorSpace/PCS
      [CRITICAL] A2B0: raw n_in=2 but colorSpace expects 3 channels
       CWE-131: LUT input channel mismatch — heap-buffer-overflow in Apply() when indexing caller buffer

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
      [OK] ResponseCurve measurement counts within bounds (or tag absent)

HEURISTIC SUMMARY
=======================================================================

[WARN]  4 HEURISTIC WARNING(S) DETECTED

  This profile exhibits patterns associated with:
  - Malformed/corrupted data
  - Resource exhaustion attempts
  - Enum confusion vulnerabilities
  - Parser exploitation attempts
  - Type confusion / buffer overflow patterns

  - Sub-element offset OOB (mBA/mAB SIGBUS pattern)
  - 32-bit integer overflow in bounds checks
  - Suspicious fill patterns enabling OOB traversal

  CVE Coverage: 171 heuristics covering patterns from 87 CVEs + 95 GHSAs across 93 iccDEV security advisories (57 heuristics with CVE/GHSA cross-references)
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
Profile: /home/xss/research/test-profiles/BlacklightPoster_202143.icc

Device Class: 0x61627374

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [[X]] [ ]  
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
  Device Class:    0x61627374  ''  AbstractClass
  Color Space:     0x4C616220  'Lab'  LabData
  PCS:             0x4C616220  'Lab'  LabData
  Manufacturer:    0x6E6F6E65  'none'
  Model:           0x00000000  '....'

Tag Signatures:
Idx  Tag          FourCC     Type         Issues
---  ------------ ---------- ------------ ------
0    profileDescriptionTag 'desc    '  textDescriptionType
1    copyrightTag 'cprt    '  textType    
2    mediaWhitePointTag 'wtpt    '  XYZArrayType
3    AToB0Tag     'A2B0    '  lut8Type    

Summary: 0 signature issue(s) detected

=======================================================================
PHASE 4: PROFILE STRUCTURE DUMP
=======================================================================

=== ICC Profile Header ===

=== ICC Profile Header (0x0000-0x007F) ===
0x0000: 00 00 41 28 41 44 42 45  02 10 00 00 61 62 73 74  |..A(ADBE....abst|
0x0010: 4C 61 62 20 4C 61 62 20  07 DB 00 0B 00 07 00 02  |Lab Lab ........|
0x0020: 00 31 00 01 61 63 73 70  41 50 50 4C 00 00 00 00  |.1..acspAPPL....|
0x0030: 6E 6F 6E 65 00 00 00 00  00 00 00 00 00 00 00 00  |none............|
0x0040: 00 00 00 01 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 41 44 42 45 00 00 00 00  00 00 00 00 00 00 00 00  |ADBE............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields:
  Size:              0x00004128 (16680 bytes)
  CMM Type:          'ADBE' (0x41444245)
  Version:           2.1.0.0 (0x02100000)
  Device Class:      AbstractClass
  Color Space:       LabData (3 channels)
  PCS:               LabData
  Date/Time:         2011-11-07 02:49:01
  Magic:             0x61637370 [OK]
  Platform:          Macintosh
  Profile Flags:     0x00000000
  Manufacturer:      'none' (0x6E6F6E65)
  Model:             '....' (0x00000000)
  Device Attribs:    0x0000000000000000
  Rendering Intent:  Relative Colorimetric (1)
  PCS Illuminant:    X=0.9642 Y=1.0000 Z=0.8249
  Creator:           'ADBE' (0x41444245)
  Profile ID:        (not set)

=== Tag Table ===

=== Tag Table ===
Tag Count: 4

Tag Table Raw Data (0x0080-0x00B4):
0x0080: 00 00 00 04 64 65 73 63  00 00 00 B4 00 00 00 6D  |....desc.......m|
0x0090: 63 70 72 74 00 00 01 24  00 00 00 2A 77 74 70 74  |cprt...$...*wtpt|
0x00A0: 00 00 01 50 00 00 00 14  41 32 42 30 00 00 01 64  |...P....A2B0...d|
0x00B0: 00 00 3F C3                                       |..?.|

Tag Entries:
Idx  Signature    FourCC       Offset     Size
---  ------------ ------------ ---------- ----
0    profileDescriptionTag 'desc      '  0x000000B4  109
1    copyrightTag 'cprt      '  0x00000124  42
2    mediaWhitePointTag 'wtpt      '  0x00000150  20
3    AToB0Tag     'A2B0      '  0x00000164  16323

=======================================================================
PHASE 5: TAG CONTENT ANALYSIS
=======================================================================

--- 5A: LUT Tag Geometry ---

  [A2B0] LUT Tag 'A2B0'
      Input channels:  2
      Output channels: 3
      Matrix side:     input (B-side)
      CurvesB:         present
      CurvesM:         none
      CurvesA:         present
      CLUT:            present
        Grid points:   17 x 17
        Total entries: 867

--- 5B: MPE Element Chains ---

  No MPE tags found

--- 5C: TRC Curve Analysis ---

  No TRC curve tags found

--- 5D: NamedColor2 Validation ---

  No NamedColor2 tag

--- 5E: XYZ Tag Values ---

  [wtpt] X=0.9642 Y=1.0000 Z=0.8249

--- 5F: ICC v5 Spectral Data ---

  No ICC v5 spectral tags

--- 5G: Profile ID Verification ---

  Profile ID: not set (all zeros)
      INFO: Profile integrity cannot be verified without ID

--- 5H: Per-Tag Size Analysis ---

  Tag sizes (flagging >10MB):
      [OK] All tags within 10MB limit

--- 5I: V5/iccMAX Summary ---

  (Profile is v2/v4 — v5/iccMAX summary not applicable)

--- 5J: Version Classification & Capabilities ---

  Version Classification:
    ICC Version:       2.1.0
    Specification:     ICC.1 (v2.1+)
    Features:          lut8/lut16 only, no profileID
    Device Class:      AbstractClass
    Color Space:       LabData (3 channels)
    Connection Space:  LabData

  Transform Capabilities:
    AToB (device→PCS):   YES
    BToA (PCS→device):   no
    TRC (matrix/gamma):  no
    Gamut check:         no
    Chromatic adapt:     no
    Preview:             no


=======================================================================
COMPREHENSIVE ANALYSIS SUMMARY
=======================================================================

File: /home/xss/research/test-profiles/BlacklightPoster_202143.icc
Total Issues Detected: 5

[WARN] ANALYSIS COMPLETE - 5 issue(s) detected
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

File: /home/xss/research/test-profiles/BlacklightPoster_202143.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 16680 bytes (0x4128)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 41 28 41 44 42 45  02 10 00 00 61 62 73 74  |..A(ADBE....abst|
0x0010: 4C 61 62 20 4C 61 62 20  07 DB 00 0B 00 07 00 02  |Lab Lab ........|
0x0020: 00 31 00 01 61 63 73 70  41 50 50 4C 00 00 00 00  |.1..acspAPPL....|
0x0030: 6E 6F 6E 65 00 00 00 00  00 00 00 00 00 00 00 00  |none............|
0x0040: 00 00 00 01 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 41 44 42 45 00 00 00 00  00 00 00 00 00 00 00 00  |ADBE............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x00004128 (16680 bytes) OK
  CMM:             0x41444245  'ADBE'
  Version:         0x02100000  (2.1.0)
  Device Class:    0x61627374  'abst'
  Color Space:     0x4C616220  'Lab '
  PCS:             0x4C616220  'Lab '
  Date/Time:       2011-11-07 02:49:01
  Magic:           0x61637370  [OK 'acsp']
  Platform:        0x4150504C  'APPL'
  Flags:           0x00000000
  Manufacturer:    0x6E6F6E65  'none'
  Model:           0x00000000  '....'
  Dev Attributes:  0x0000000000000000
  Rendering Intent:0x00000001  Relative Colorimetric
  PCS Illuminant:  X=0.9642 Y=1.0000 Z=0.8249
  Creator:         0x41444245  'ADBE'
  Profile ID:      00000000000000000000000000000000  (not set)
  Reserved 100-127: all zeros [OK]

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 4 (0x00000004)

Tag Table Raw Data:
0x0080: 00 00 00 04 64 65 73 63  00 00 00 B4 00 00 00 6D  |....desc.......m|
0x0090: 63 70 72 74 00 00 01 24  00 00 00 2A 77 74 70 74  |cprt...$...*wtpt|
0x00A0: 00 00 01 50 00 00 00 14  41 32 42 30 00 00 01 64  |...P....A2B0...d|
0x00B0: 00 00 3F C3                                       |..?.|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x64657363   'desc'        0x000000B4   0x0000006D   'desc'        OK
1    0x63707274   'cprt'        0x00000124   0x0000002A   'text'        OK
2    0x77747074   'wtpt'        0x00000150   0x00000014   'XYZ '        OK
3    0x41324230   'A2B0'        0x00000164   0x00003FC3   'mft1'        OK

=== FULL FILE HEX DUMP (all 16680 bytes) ===
0x0000: 00 00 41 28 41 44 42 45  02 10 00 00 61 62 73 74  |..A(ADBE....abst|
0x0010: 4C 61 62 20 4C 61 62 20  07 DB 00 0B 00 07 00 02  |Lab Lab ........|
0x0020: 00 31 00 01 61 63 73 70  41 50 50 4C 00 00 00 00  |.1..acspAPPL....|
0x0030: 6E 6F 6E 65 00 00 00 00  00 00 00 00 00 00 00 00  |none............|
0x0040: 00 00 00 01 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 41 44 42 45 00 00 00 00  00 00 00 00 00 00 00 00  |ADBE............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0080: 00 00 00 04 64 65 73 63  00 00 00 B4 00 00 00 6D  |....desc.......m|
0x0090: 63 70 72 74 00 00 01 24  00 00 00 2A 77 74 70 74  |cprt...$...*wtpt|
0x00A0: 00 00 01 50 00 00 00 14  41 32 42 30 00 00 01 64  |...P....A2B0...d|
0x00B0: 00 00 3F C3 64 65 73 63  00 00 00 00 00 00 00 12  |..?.desc........|
0x00C0: 42 6C 61 63 6B 6C 69 67  68 74 20 50 6F 73 74 65  |Blacklight Poste|
0x00D0: 72 00 00 00 00 00 00 00  00 00 00 00 01 00 00 00  |r...............|
0x00E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x00F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0100: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0110: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0120: 00 00 00 00 74 65 78 74  00 00 00 00 43 6F 70 79  |....text....Copy|
0x0130: 72 69 67 68 74 20 32 30  31 31 20 41 64 6F 62 65  |right 2011 Adobe|
0x0140: 20 53 79 73 74 65 6D 73  20 49 6E 63 2E 00 00 00  | Systems Inc....|
0x0150: 58 59 5A 20 00 00 00 00  00 00 F6 D6 00 01 00 00  |XYZ ............|
0x0160: 00 00 D3 2D 6D 66 74 31  00 00 00 00 02 03 11 00  |...-mft1........|
0x0170: 00 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0180: 00 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0190: 00 01 00 00 00 01 02 03  04 05 06 07 08 09 0A 0B  |................|
0x01A0: 0C 0D 0E 0F 10 11 12 13  14 15 16 17 18 19 1A 1B  |................|
0x01B0: 1C 1D 1E 1F 20 21 22 23  24 25 26 27 28 29 2A 2B  |.... !"#$%&'()*+|
0x01C0: 2C 2D 2E 2F 30 31 32 33  34 35 36 37 38 39 3A 3B  |,-./0123456789:;|
0x01D0: 3C 3D 3E 3F 40 41 42 43  44 45 46 47 48 49 4A 4B  |<=>?@ABCDEFGHIJK|
0x01E0: 4C 4D 4E 4F 50 51 52 53  54 55 56 57 58 59 5A 5B  |LMNOPQRSTUVWXYZ[|
0x01F0: 5C 5D 5E 5F 60 61 62 63  64 65 66 67 68 69 6A 6B  |\]^_`abcdefghijk|
0x0200: 6C 6D 6E 6F 70 71 72 73  74 75 76 77 78 79 7A 7B  |lmnopqrstuvwxyz{|
0x0210: 7C 7D 7E 7F 80 81 82 83  84 85 86 87 88 89 8A 8B  ||}~.............|
0x0220: 8C 8D 8E 8F 90 91 92 93  94 95 96 97 98 99 9A 9B  |................|
0x0230: 9C 9D 9E 9F A0 A1 A2 A3  A4 A5 A6 A7 A8 A9 AA AB  |................|
0x0240: AC AD AE AF B0 B1 B2 B3  B4 B5 B6 B7 B8 B9 BA BB  |................|
0x0250: BC BD BE BF C0 C1 C2 C3  C4 C5 C6 C7 C8 C9 CA CB  |................|
0x0260: CC CD CE CF D0 D1 D2 D3  D4 D5 D6 D7 D8 D9 DA DB  |................|
0x0270: DC DD DE DF E0 E1 E2 E3  E4 E5 E6 E7 E8 E9 EA EB  |................|
0x0280: EC ED EE EF F0 F1 F2 F3  F4 F5 F6 F7 F8 F9 FA FB  |................|
0x0290: FC FD FE FF 00 01 02 03  04 05 06 07 08 09 0A 0B  |................|
0x02A0: 0C 0D 0E 0F 10 11 12 13  14 15 16 17 18 19 1A 1B  |................|
0x02B0: 1C 1D 1E 1F 20 21 22 23  24 25 26 27 28 29 2A 2B  |.... !"#$%&'()*+|
0x02C0: 2C 2D 2E 2F 30 31 32 33  34 35 36 37 38 39 3A 3B  |,-./0123456789:;|
0x02D0: 3C 3D 3E 3F 40 41 42 43  44 45 46 47 48 49 4A 4B  |<=>?@ABCDEFGHIJK|
0x02E0: 4C 4D 4E 4F 50 51 52 53  54 55 56 57 58 59 5A 5B  |LMNOPQRSTUVWXYZ[|
0x02F0: 5C 5D 5E 5F 60 61 62 63  64 65 66 67 68 69 6A 6B  |\]^_`abcdefghijk|
0x0300: 6C 6D 6E 6F 70 71 72 73  74 75 76 77 78 79 7A 7B  |lmnopqrstuvwxyz{|
0x0310: 7C 7D 7E 7F 80 81 82 83  84 85 86 87 88 89 8A 8B  ||}~.............|
0x0320: 8C 8D 8E 8F 90 91 92 93  94 95 96 97 98 99 9A 9B  |................|
0x0330: 9C 9D 9E 9F A0 A1 A2 A3  A4 A5 A6 A7 A8 A9 AA AB  |................|
0x0340: AC AD AE AF B0 B1 B2 B3  B4 B5 B6 B7 B8 B9 BA BB  |................|
0x0350: BC BD BE BF C0 C1 C2 C3  C4 C5 C6 C7 C8 C9 CA CB  |................|
0x0360: CC CD CE CF D0 D1 D2 D3  D4 D5 D6 D7 D8 D9 DA DB  |................|
0x0370: DC DD DE DF E0 E1 E2 E3  E4 E5 E6 E7 E8 E9 EA EB  |................|
0x0380: EC ED EE EF F0 F1 F2 F3  F4 F5 F6 F7 F8 F9 FA FB  |................|
0x0390: FC FD FE FF 00 01 02 03  04 05 06 07 08 09 0A 0B  |................|
0x03A0: 0C 0D 0E 0F 10 11 12 13  14 15 16 17 18 19 1A 1B  |................|
0x03B0: 1C 1D 1E 1F 20 21 22 23  24 25 26 27 28 29 2A 2B  |.... !"#$%&'()*+|
0x03C0: 2C 2D 2E 2F 30 31 32 33  34 35 36 37 38 39 3A 3B  |,-./0123456789:;|
0x03D0: 3C 3D 3E 3F 40 41 42 43  44 45 46 47 48 49 4A 4B  |<=>?@ABCDEFGHIJK|
0x03E0: 4C 4D 4E 4F 50 51 52 53  54 55 56 57 58 59 5A 5B  |LMNOPQRSTUVWXYZ[|
0x03F0: 5C 5D 5E 5F 60 61 62 63  64 65 66 67 68 69 6A 6B  |\]^_`abcdefghijk|
0x0400: 6C 6D 6E 6F 70 71 72 73  74 75 76 77 78 79 7A 7B  |lmnopqrstuvwxyz{|
0x0410: 7C 7D 7E 7F 80 81 82 83  84 85 86 87 88 89 8A 8B  ||}~.............|
0x0420: 8C 8D 8E 8F 90 91 92 93  94 95 96 97 98 99 9A 9B  |................|
0x0430: 9C 9D 9E 9F A0 A1 A2 A3  A4 A5 A6 A7 A8 A9 AA AB  |................|
0x0440: AC AD AE AF B0 B1 B2 B3  B4 B5 B6 B7 B8 B9 BA BB  |................|
0x0450: BC BD BE BF C0 C1 C2 C3  C4 C5 C6 C7 C8 C9 CA CB  |................|
0x0460: CC CD CE CF D0 D1 D2 D3  D4 D5 D6 D7 D8 D9 DA DB  |................|
0x0470: DC DD DE DF E0 E1 E2 E3  E4 E5 E6 E7 E8 E9 EA EB  |................|
0x0480: EC ED EE EF F0 F1 F2 F3  F4 F5 F6 F7 F8 F9 FA FB  |................|
0x0490: FC FD FE FF E2 58 36 E2  58 36 E2 58 36 E2 58 36  |.....X6.X6.X6.X6|
0x04A0: E2 58 36 E2 58 36 00 80  80 00 80 80 00 80 80 00  |.X6.X6..........|
0x04B0: 80 80 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |...1..1..1..1..1|
0x04C0: D9 F6 31 D9 F6 31 D9 E2  58 36 E2 58 36 E2 58 36  |..1..1..X6.X6.X6|
0x04D0: E2 58 36 E2 58 36 E2 58  36 00 80 80 00 80 80 00  |.X6.X6.X6.......|
0x04E0: 80 80 00 80 80 00 80 80  F6 31 D9 F6 31 D9 F6 31  |.........1..1..1|
0x04F0: D9 F6 31 D9 F6 31 D9 F6  31 D9 E2 58 36 E2 58 36  |..1..1..1..X6.X6|
0x0500: E2 58 36 E2 58 36 E2 58  36 00 80 80 00 80 80 00  |.X6.X6.X6.......|
0x0510: 80 80 00 80 80 00 80 80  00 80 80 F6 31 D9 F6 31  |............1..1|
0x0520: D9 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 E2 58 36  |..1..1..1..1..X6|
0x0530: E2 58 36 E2 58 36 E2 58  36 E2 58 36 00 80 80 00  |.X6.X6.X6.X6....|
0x0540: 80 80 00 80 80 00 80 80  00 80 80 00 80 80 00 80  |................|
0x0550: 80 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..1..1..1..1..1.|
0x0560: E2 58 36 E2 58 36 E2 58  36 E2 58 36 00 80 80 00  |.X6.X6.X6.X6....|
0x0570: 80 80 00 80 80 00 80 80  00 80 80 00 80 80 00 80  |................|
0x0580: 80 00 80 80 00 80 80 F6  31 D9 F6 31 D9 F6 31 D9  |........1..1..1.|
0x0590: F6 31 D9 E2 58 36 E2 58  36 E2 58 36 E2 58 36 00  |.1..X6.X6.X6.X6.|
0x05A0: 80 80 00 80 80 00 80 80  00 80 80 00 80 80 00 80  |................|
0x05B0: 80 00 80 80 00 80 80 00  80 80 00 80 80 FD 60 D0  |..............`.|
0x05C0: F6 31 D9 F6 31 D9 E2 58  36 E2 58 36 E2 58 36 00  |.1..1..X6.X6.X6.|
0x05D0: 80 80 00 80 80 00 80 80  00 80 80 00 80 80 00 80  |................|
0x05E0: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x05F0: FD 60 D0 FD 60 D0 FD 60  D0 E2 58 36 E2 58 36 E2  |.`..`..`..X6.X6.|
0x0600: 58 36 00 80 80 00 80 80  00 80 80 00 80 80 00 80  |X6..............|
0x0610: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0620: 00 80 80 00 80 80 FD 60  D0 FD 60 D0 E2 58 36 E2  |.......`..`..X6.|
0x0630: 58 36 00 80 80 00 80 80  00 80 80 00 80 80 00 80  |X6..............|
0x0640: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0650: 00 80 80 00 80 80 00 80  80 FD 60 D0 FD 60 D0 E2  |..........`..`..|
0x0660: 58 36 E2 58 36 00 80 80  00 80 80 00 80 80 00 80  |X6.X6...........|
0x0670: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0680: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 FD  |................|
0x0690: 60 D0 C4 A4 61 C4 A4 61  C4 A4 61 00 80 80 00 80  |`...a..a..a.....|
0x06A0: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x06B0: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x06C0: 80 80 FD 60 D0 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |...`...a..a..a..|
0x06D0: 61 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |a...............|
0x06E0: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x06F0: 80 80 00 80 80 DB D5 9F  C4 A4 61 C4 A4 61 C4 A4  |..........a..a..|
0x0700: 61 C4 A4 61 C4 A4 61 00  80 80 00 80 80 00 80 80  |a..a..a.........|
0x0710: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 DB  |................|
0x0720: D5 9F DB D5 9F DB D5 9F  DB D5 9F C4 A4 61 C4 A4  |.............a..|
0x0730: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 00 80 80  |a..a..a..a..a...|
0x0740: 00 80 80 00 80 80 00 80  80 00 80 80 DB D5 9F DB  |................|
0x0750: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F C4 A4  |................|
0x0760: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |a..a..a..a..a..a|
0x0770: C4 A4 61 00 80 80 DB D5  9F DB D5 9F DB D5 9F DB  |..a.............|
0x0780: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x0790: 9F C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |...a..a..a..a..a|
0x07A0: C4 A4 61 C4 A4 61 DB D5  9F DB D5 9F DB D5 9F DB  |..a..a..........|
0x07B0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x07C0: 9F DB D5 9F C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |......a..a..a..a|
0x07D0: C4 A4 61 C4 A4 61 DB D5  9F DB D5 9F DB D5 9F DB  |..a..a..........|
0x07E0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x07F0: 9F DB D5 9F DB D5 9F E2  58 36 E2 58 36 E2 58 36  |........X6.X6.X6|
0x0800: E2 58 36 E2 58 36 E2 58  36 E2 58 36 00 80 80 00  |.X6.X6.X6.X6....|
0x0810: 80 80 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |...1..1..1..1..1|
0x0820: D9 F6 31 D9 F6 31 D9 F6  31 D9 E2 58 36 E2 58 36  |..1..1..1..X6.X6|
0x0830: E2 58 36 E2 58 36 E2 58  36 E2 58 36 00 80 80 00  |.X6.X6.X6.X6....|
0x0840: 80 80 00 80 80 00 80 80  F6 31 D9 F6 31 D9 F6 31  |.........1..1..1|
0x0850: D9 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 E2 58 36  |..1..1..1..1..X6|
0x0860: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 00  |.X6.X6.X6.X6.X6.|
0x0870: 80 80 00 80 80 00 80 80  00 80 80 00 80 80 F6 31  |...............1|
0x0880: D9 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..1..1..1..1..1.|
0x0890: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 00  |.X6.X6.X6.X6.X6.|
0x08A0: 80 80 00 80 80 00 80 80  00 80 80 00 80 80 00 80  |................|
0x08B0: 80 00 80 80 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |.....1..1..1..1.|
0x08C0: F6 31 D9 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.1..X6.X6.X6.X6.|
0x08D0: 58 36 00 80 80 00 80 80  00 80 80 00 80 80 00 80  |X6..............|
0x08E0: 80 00 80 80 00 80 80 00  80 80 F6 31 D9 F6 31 D9  |...........1..1.|
0x08F0: F6 31 D9 F6 31 D9 E2 58  36 E2 58 36 E2 58 36 E2  |.1..1..X6.X6.X6.|
0x0900: 58 36 00 80 80 00 80 80  00 80 80 00 80 80 00 80  |X6..............|
0x0910: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0920: FD 60 D0 F6 31 D9 F6 31  D9 E2 58 36 E2 58 36 E2  |.`..1..1..X6.X6.|
0x0930: 58 36 E2 58 36 00 80 80  00 80 80 00 80 80 00 80  |X6.X6...........|
0x0940: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0950: 00 80 80 FD 60 D0 FD 60  D0 FD 60 D0 E2 58 36 E2  |....`..`..`..X6.|
0x0960: 58 36 E2 58 36 00 80 80  00 80 80 00 80 80 00 80  |X6.X6...........|
0x0970: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0980: 00 80 80 00 80 80 FD 60  D0 FD 60 D0 FD 60 D0 E2  |.......`..`..`..|
0x0990: 58 36 E2 58 36 E2 58 36  00 80 80 00 80 80 00 80  |X6.X6.X6........|
0x09A0: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x09B0: 00 80 80 00 80 80 00 80  80 00 80 80 FD 60 D0 FD  |.............`..|
0x09C0: 60 D0 E2 58 36 E2 58 36  00 80 80 00 80 80 00 80  |`..X6.X6........|
0x09D0: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x09E0: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 FD  |................|
0x09F0: 60 D0 FD 60 D0 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |`..`...a..a..a..|
0x0A00: 61 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |a...............|
0x0A10: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x0A20: 80 80 00 80 80 FD 60 D0  C4 A4 61 C4 A4 61 C4 A4  |......`...a..a..|
0x0A30: 61 C4 A4 61 C4 A4 61 00  80 80 00 80 80 00 80 80  |a..a..a.........|
0x0A40: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x0A50: 80 80 00 80 80 DB D5 9F  DB D5 9F C4 A4 61 C4 A4  |.............a..|
0x0A60: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 00 80 80  |a..a..a..a..a...|
0x0A70: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 DB  |................|
0x0A80: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F C4 A4  |................|
0x0A90: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |a..a..a..a..a..a|
0x0AA0: C4 A4 61 00 80 80 00 80  80 00 80 80 DB D5 9F DB  |..a.............|
0x0AB0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x0AC0: 9F C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |...a..a..a..a..a|
0x0AD0: C4 A4 61 C4 A4 61 DB D5  9F DB D5 9F DB D5 9F DB  |..a..a..........|
0x0AE0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x0AF0: 9F DB D5 9F C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |......a..a..a..a|
0x0B00: C4 A4 61 C4 A4 61 C4 A4  61 DB D5 9F DB D5 9F DB  |..a..a..a.......|
0x0B10: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x0B20: 9F DB D5 9F DB D5 9F C4  A4 61 C4 A4 61 C4 A4 61  |.........a..a..a|
0x0B30: C4 A4 61 C4 A4 61 C4 A4  61 DB D5 9F DB D5 9F DB  |..a..a..a.......|
0x0B40: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x0B50: 9F DB D5 9F DB D5 9F DB  D5 9F E2 58 36 E2 58 36  |...........X6.X6|
0x0B60: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 00  |.X6.X6.X6.X6.X6.|
0x0B70: 80 80 00 80 80 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |......1..1..1..1|
0x0B80: D9 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 E2 58 36  |..1..1..1..1..X6|
0x0B90: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.X6.X6.X6.X6.X6.|
0x0BA0: 58 36 00 80 80 00 80 80  00 80 80 F6 31 D9 F6 31  |X6..........1..1|
0x0BB0: D9 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..1..1..1..1..1.|
0x0BC0: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.X6.X6.X6.X6.X6.|
0x0BD0: 58 36 00 80 80 00 80 80  00 80 80 00 80 80 00 80  |X6..............|
0x0BE0: 80 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..1..1..1..1..1.|
0x0BF0: F6 31 D9 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.1..X6.X6.X6.X6.|
0x0C00: 58 36 E2 58 36 00 80 80  00 80 80 00 80 80 00 80  |X6.X6...........|
0x0C10: 80 00 80 80 F9 57 B1 F6  31 D9 F6 31 D9 F6 31 D9  |.....W..1..1..1.|
0x0C20: F6 31 D9 F6 31 D9 E2 58  36 E2 58 36 E2 58 36 E2  |.1..1..X6.X6.X6.|
0x0C30: 58 36 E2 58 36 00 80 80  00 80 80 00 80 80 00 80  |X6.X6...........|
0x0C40: 80 00 80 80 00 80 80 00  80 80 F6 31 D9 F6 31 D9  |...........1..1.|
0x0C50: F6 31 D9 F6 31 D9 F6 31  D9 E2 58 36 E2 58 36 E2  |.1..1..1..X6.X6.|
0x0C60: 58 36 E2 58 36 E2 58 36  00 80 80 00 80 80 00 80  |X6.X6.X6........|
0x0C70: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0C80: FD 60 D0 FD 60 D0 F6 31  D9 F6 31 D9 E2 58 36 E2  |.`..`..1..1..X6.|
0x0C90: 58 36 E2 58 36 E2 58 36  00 80 80 00 80 80 00 80  |X6.X6.X6........|
0x0CA0: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0CB0: 46 80 80 00 80 80 FD 60  D0 FD 60 D0 FD 60 D0 E2  |F......`..`..`..|
0x0CC0: 58 36 E2 58 36 E2 58 36  E2 58 36 00 80 80 00 80  |X6.X6.X6.X6.....|
0x0CD0: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0CE0: 00 80 80 00 80 80 00 80  80 FD 60 D0 FD 60 D0 FD  |..........`..`..|
0x0CF0: 60 D0 E2 58 36 E2 58 36  E2 58 36 00 80 80 00 80  |`..X6.X6.X6.....|
0x0D00: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0D10: 00 80 80 00 80 80 00 80  80 00 80 80 FD 60 D0 FD  |.............`..|
0x0D20: 60 D0 FD 60 D0 E2 58 36  E2 58 36 C4 A4 61 00 80  |`..`..X6.X6..a..|
0x0D30: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0D40: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x0D50: 80 80 FD 60 D0 FD 60 D0  C4 A4 61 C4 A4 61 C4 A4  |...`..`...a..a..|
0x0D60: 61 C4 A4 61 00 80 80 00  80 80 00 80 80 00 80 80  |a..a............|
0x0D70: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x0D80: 80 80 00 80 80 FD 60 D0  FD 60 D0 C4 A4 61 C4 A4  |......`..`...a..|
0x0D90: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 00 80 80  |a..a..a..a..a...|
0x0DA0: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x0DB0: 80 80 00 80 80 DB D5 9F  DB D5 9F DB D5 9F C4 A4  |................|
0x0DC0: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |a..a..a..a..a..a|
0x0DD0: C4 A4 61 00 80 80 00 80  80 00 80 80 00 80 80 DB  |..a.............|
0x0DE0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x0DF0: 9F C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |...a..a..a..a..a|
0x0E00: C4 A4 61 C4 A4 61 C4 A4  61 DB D5 9F DB D5 9F DB  |..a..a..a.......|
0x0E10: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x0E20: 9F DB D5 9F C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |......a..a..a..a|
0x0E30: C4 A4 61 C4 A4 61 C4 A4  61 DB D5 9F DB D5 9F DB  |..a..a..a.......|
0x0E40: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x0E50: 9F DB D5 9F DB D5 9F C4  A4 61 C4 A4 61 C4 A4 61  |.........a..a..a|
0x0E60: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 DB D5 9F DB  |..a..a..a..a....|
0x0E70: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x0E80: 9F DB D5 9F DB D5 9F DB  D5 9F C4 A4 61 C4 A4 61  |............a..a|
0x0E90: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 DB D5 9F DB  |..a..a..a..a....|
0x0EA0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x0EB0: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F E2 58 36  |..............X6|
0x0EC0: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.X6.X6.X6.X6.X6.|
0x0ED0: 58 36 E2 58 36 F9 57 B1  F6 31 D9 F6 31 D9 F6 31  |X6.X6.W..1..1..1|
0x0EE0: D9 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..1..1..1..1..1.|
0x0EF0: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.X6.X6.X6.X6.X6.|
0x0F00: 58 36 E2 58 36 00 80 80  00 80 80 F9 57 B1 F6 31  |X6.X6.......W..1|
0x0F10: D9 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..1..1..1..1..1.|
0x0F20: F6 31 D9 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.1..X6.X6.X6.X6.|
0x0F30: 58 36 E2 58 36 E2 58 36  00 80 80 00 80 80 00 80  |X6.X6.X6........|
0x0F40: 80 F9 57 B1 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..W..1..1..1..1.|
0x0F50: F6 31 D9 F6 31 D9 E2 58  36 E2 58 36 E2 58 36 E2  |.1..1..X6.X6.X6.|
0x0F60: 58 36 E2 58 36 E2 58 36  00 80 80 00 80 80 00 80  |X6.X6.X6........|
0x0F70: 80 00 80 80 00 80 80 F9  57 B1 F6 31 D9 F6 31 D9  |........W..1..1.|
0x0F80: F6 31 D9 F6 31 D9 F6 31  D9 E2 58 36 E2 58 36 E2  |.1..1..1..X6.X6.|
0x0F90: 58 36 E2 58 36 E2 58 36  E2 58 36 00 80 80 00 80  |X6.X6.X6.X6.....|
0x0FA0: 80 00 80 80 00 80 80 00  80 80 00 80 80 F6 31 D9  |..............1.|
0x0FB0: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 E2 58 36 E2  |.1..1..1..1..X6.|
0x0FC0: 58 36 E2 58 36 E2 58 36  E2 58 36 00 80 80 00 80  |X6.X6.X6.X6.....|
0x0FD0: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x0FE0: F9 57 B1 FD 60 D0 FD 60  D0 F6 31 D9 F6 31 D9 E2  |.W..`..`..1..1..|
0x0FF0: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 00 80  |X6.X6.X6.X6.X6..|
0x1000: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x1010: 00 80 80 00 80 80 FD 60  D0 FD 60 D0 FD 60 D0 FD  |.......`..`..`..|
0x1020: 60 D0 E2 58 36 E2 58 36  E2 58 36 E2 58 36 00 80  |`..X6.X6.X6.X6..|
0x1030: 80 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |................|
0x1040: 00 80 80 00 80 80 00 80  80 FD 60 D0 FD 60 D0 FD  |..........`..`..|
0x1050: 60 D0 FD 60 D0 E2 58 36  E2 58 36 E2 58 36 E2 58  |`..`..X6.X6.X6.X|
0x1060: 36 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |6...............|
0x1070: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 FD  |................|
0x1080: 60 D0 FD 60 D0 FD 60 D0  E2 58 36 E2 58 36 C4 A4  |`..`..`..X6.X6..|
0x1090: 61 C4 A4 61 00 80 80 00  80 80 00 80 80 00 80 80  |a..a............|
0x10A0: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x10B0: 80 80 FD 60 D0 FD 60 D0  FD 60 D0 C4 A4 61 C4 A4  |...`..`..`...a..|
0x10C0: 61 C4 A4 61 C4 A4 61 C4  A4 61 00 80 80 00 80 80  |a..a..a..a......|
0x10D0: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x10E0: 80 80 00 80 80 00 80 80  FD 60 D0 FD 60 D0 C4 A4  |.........`..`...|
0x10F0: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |a..a..a..a..a..a|
0x1100: C4 A4 61 00 80 80 00 80  80 00 80 80 00 80 80 00  |..a.............|
0x1110: 80 80 00 80 80 DB D5 9F  DB D5 9F DB D5 9F FD 60  |...............`|
0x1120: D0 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |...a..a..a..a..a|
0x1130: C4 A4 61 C4 A4 61 C4 A4  61 00 80 80 00 80 80 DB  |..a..a..a.......|
0x1140: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x1150: 9F DB D5 9F C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |......a..a..a..a|
0x1160: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 DB D5 9F DB  |..a..a..a..a....|
0x1170: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x1180: 9F DB D5 9F DB D5 9F C4  A4 61 C4 A4 61 C4 A4 61  |.........a..a..a|
0x1190: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 DB D5 9F DB  |..a..a..a..a....|
0x11A0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x11B0: 9F DB D5 9F DB D5 9F DB  D5 9F C4 A4 61 C4 A4 61  |............a..a|
0x11C0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 DB  |..a..a..a..a..a.|
0x11D0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x11E0: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F C4 A4 61  |...............a|
0x11F0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 DB  |..a..a..a..a..a.|
0x1200: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x1210: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1220: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.X6.X6.X6.X6.X6.|
0x1230: 58 36 E2 58 36 E2 58 36  F9 57 B1 F6 31 D9 F6 31  |X6.X6.X6.W..1..1|
0x1240: D9 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..1..1..1..1..1.|
0x1250: F6 31 D9 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.1..X6.X6.X6.X6.|
0x1260: 58 36 E2 58 36 E2 58 36  E2 58 36 F9 57 B1 F9 57  |X6.X6.X6.X6.W..W|
0x1270: B1 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..1..1..1..1..1.|
0x1280: F6 31 D9 F6 31 D9 E2 58  36 E2 58 36 E2 58 36 E2  |.1..1..X6.X6.X6.|
0x1290: 58 36 E2 58 36 E2 58 36  E2 58 36 00 80 80 00 80  |X6.X6.X6.X6.....|
0x12A0: 80 F9 57 B1 F9 57 B1 F6  31 D9 F6 31 D9 F6 31 D9  |..W..W..1..1..1.|
0x12B0: F6 31 D9 F6 31 D9 F6 31  D9 E2 58 36 E2 58 36 E2  |.1..1..1..X6.X6.|
0x12C0: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 00 80  |X6.X6.X6.X6.X6..|
0x12D0: 80 00 80 80 00 80 80 F9  57 B1 F9 57 B1 F6 31 D9  |........W..W..1.|
0x12E0: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 E2 58 36 E2  |.1..1..1..1..X6.|
0x12F0: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 00 80  |X6.X6.X6.X6.X6..|
0x1300: 80 00 80 80 00 80 80 00  80 80 00 80 80 F9 57 B1  |..............W.|
0x1310: F9 57 B1 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 E2  |.W..1..1..1..1..|
0x1320: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x1330: 36 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |6...............|
0x1340: 00 80 80 F9 57 B1 FD 60  D0 FD 60 D0 F6 EB D9 F6  |....W..`..`.....|
0x1350: 31 D9 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..X6.X6.X6.X6.X|
0x1360: 36 00 80 80 00 80 80 00  80 80 00 80 80 00 80 80  |6...............|
0x1370: 00 80 80 00 80 80 F9 57  B1 FD 60 D0 FD 60 D0 FD  |.......W..`..`..|
0x1380: 60 D0 FD 60 D0 E2 58 36  E2 58 36 E2 58 36 E2 58  |`..`..X6.X6.X6.X|
0x1390: 36 E2 58 36 00 80 80 00  80 80 00 80 80 00 80 80  |6.X6............|
0x13A0: 00 80 80 00 80 80 00 80  80 00 80 80 FD 60 D0 FD  |.............`..|
0x13B0: 60 D0 FD 60 D0 FD 60 D0  E2 58 36 E2 58 36 E2 58  |`..`..`..X6.X6.X|
0x13C0: 36 E2 58 36 00 80 80 00  80 80 00 80 80 00 80 80  |6.X6............|
0x13D0: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 FD  |................|
0x13E0: 60 D0 FD 60 D0 FD 60 D0  FD 60 D0 E2 58 36 E2 58  |`..`..`..`..X6.X|
0x13F0: 36 C4 A4 61 C4 A4 61 C4  A4 61 00 80 80 00 80 80  |6..a..a..a......|
0x1400: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x1410: 80 80 00 80 80 FD 60 D0  FD 60 D0 FD 60 D0 C4 A4  |......`..`..`...|
0x1420: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |a..a..a..a..a..a|
0x1430: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x1440: 80 80 00 80 80 00 80 80  FD 60 D0 FD 60 D0 FD 60  |.........`..`..`|
0x1450: D0 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |...a..a..a..a..a|
0x1460: C4 A4 61 C4 A4 61 C4 A4  61 00 80 80 00 80 80 00  |..a..a..a.......|
0x1470: 80 80 00 80 80 DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x1480: 9F FD 60 D0 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |..`...a..a..a..a|
0x1490: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 DB  |..a..a..a..a..a.|
0x14A0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x14B0: 9F DB D5 9F DB D5 9F C4  A4 61 C4 A4 61 C4 A4 61  |.........a..a..a|
0x14C0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 DB  |..a..a..a..a..a.|
0x14D0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x14E0: 9F DB D5 9F DB D5 9F DB  D5 9F C4 A4 61 C4 A4 61  |............a..a|
0x14F0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 DB  |..a..a..a..a..a.|
0x1500: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x1510: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F C4 A4 61  |...............a|
0x1520: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 DB  |..a..a..a..a..a.|
0x1530: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x1540: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1550: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1560: A4 61 DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |.a..............|
0x1570: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1580: DB D5 9F E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |....X6.X6.X6.X6.|
0x1590: 58 36 E2 58 36 E2 58 36  E2 58 36 F9 57 B1 F6 31  |X6.X6.X6.X6.W..1|
0x15A0: D9 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..1..1..1..1..1.|
0x15B0: F6 31 D9 F6 31 D9 E2 58  36 E2 58 36 E2 58 36 E2  |.1..1..X6.X6.X6.|
0x15C0: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 F9 57  |X6.X6.X6.X6.X6.W|
0x15D0: B1 F9 57 B1 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..W..1..1..1..1.|
0x15E0: F6 31 D9 F6 31 D9 F6 31  D9 E2 58 36 E2 58 36 E2  |.1..1..1..X6.X6.|
0x15F0: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 EB 6A  |X6.X6.X6.X6.X6.j|
0x1600: 57 F9 57 B1 F9 57 B1 F9  57 B1 F6 31 D9 F6 31 D9  |W.W..W..W..1..1.|
0x1610: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 E2 58 36 E2  |.1..1..1..1..X6.|
0x1620: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x1630: 36 00 80 80 00 80 80 F9  57 B1 F9 57 B1 F9 57 B1  |6.......W..W..W.|
0x1640: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 E2  |.1..1..1..1..1..|
0x1650: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x1660: 36 EB 6A 57 00 80 80 00  80 80 00 80 80 F9 57 B1  |6.jW..........W.|
0x1670: F9 57 B1 F9 57 B1 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.W..W..1..1..1..|
0x1680: 31 D9 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..X6.X6.X6.X6.X|
0x1690: 36 E2 58 36 00 80 80 00  80 80 00 80 80 00 80 80  |6.X6............|
0x16A0: 00 80 80 F9 57 B1 F9 57  B1 FD 60 D0 FD 60 D0 F6  |....W..W..`..`..|
0x16B0: 31 D9 F6 31 D9 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..1..X6.X6.X6.X|
0x16C0: 36 E2 58 36 EB 6A 57 00  80 80 00 80 80 00 80 80  |6.X6.jW.........|
0x16D0: 00 80 80 00 80 80 00 80  80 F9 57 B1 FD 60 D0 FD  |..........W..`..|
0x16E0: 60 D0 FD 60 D0 FD 60 D0  E2 58 36 E2 58 36 E2 58  |`..`..`..X6.X6.X|
0x16F0: 36 E2 58 36 E2 58 36 00  80 80 00 80 80 00 80 80  |6.X6.X6.........|
0x1700: 00 80 80 00 80 80 00 80  80 00 80 80 FD 70 AC FD  |.............p..|
0x1710: 60 D0 FD 60 D0 FD 60 D0  FD 60 D0 E2 58 36 E2 58  |`..`..`..`..X6.X|
0x1720: 36 E2 58 36 E2 58 36 C4  A4 61 00 80 80 00 80 80  |6.X6.X6..a......|
0x1730: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x1740: 80 80 FD 60 D0 FD 60 D0  FD 60 D0 FD 60 D0 E2 58  |...`..`..`..`..X|
0x1750: 36 E2 58 36 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |6.X6..a..a..a..a|
0x1760: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x1770: 80 80 00 80 80 FD 70 AC  FD 60 D0 FD 60 D0 FD 60  |......p..`..`..`|
0x1780: D0 E2 58 36 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |..X6..a..a..a..a|
0x1790: C4 A4 61 C4 A4 61 00 80  80 00 80 80 00 80 80 00  |..a..a..........|
0x17A0: 80 80 00 80 80 E6 B0 90  E6 B0 90 FD 60 D0 FD 60  |............`..`|
0x17B0: D0 FD 60 D0 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |..`...a..a..a..a|
0x17C0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 E6  |..a..a..a..a..a.|
0x17D0: B0 90 E6 B0 90 E6 B0 90  DB D5 9F DB D5 9F DB D5  |................|
0x17E0: 9F DB D5 9F FD 60 D0 C4  A4 61 C4 A4 61 C4 A4 61  |.....`...a..a..a|
0x17F0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1800: A4 61 DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |.a..............|
0x1810: 9F DB D5 9F DB D5 9F DB  D5 9F C4 A4 61 C4 A4 61  |............a..a|
0x1820: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1830: A4 61 DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |.a..............|
0x1840: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F C4 A4 61  |...............a|
0x1850: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1860: A4 61 DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |.a..............|
0x1870: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1880: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1890: A4 61 DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |.a..............|
0x18A0: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x18B0: DB D5 9F C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |.....a..a..a..a.|
0x18C0: A4 61 C4 A4 61 DB D5 9F  DB D5 9F DB D5 9F DB D5  |.a..a...........|
0x18D0: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x18E0: DB D5 9F DB D5 9F E2 58  36 E2 58 36 E2 58 36 E2  |.......X6.X6.X6.|
0x18F0: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 F9 57  |X6.X6.X6.X6.X6.W|
0x1900: B1 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..1..1..1..1..1.|
0x1910: F6 31 D9 F6 31 D9 F6 31  D9 E2 58 36 E2 58 36 E2  |.1..1..1..X6.X6.|
0x1920: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x1930: 36 F9 57 B1 F9 57 B1 F6  31 D9 F6 31 D9 F6 31 D9  |6.W..W..1..1..1.|
0x1940: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 E2 58 36 E2  |.1..1..1..1..X6.|
0x1950: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x1960: 36 EB 6A 57 F9 57 B1 F9  57 B1 F9 57 B1 F6 31 D9  |6.jW.W..W..W..1.|
0x1970: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 E2  |.1..1..1..1..1..|
0x1980: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x1990: 36 E2 58 36 EB 6A 57 F9  57 B1 F9 57 B1 F9 57 B1  |6.X6.jW.W..W..W.|
0x19A0: F9 57 B1 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.W..1..1..1..1..|
0x19B0: 31 D9 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..X6.X6.X6.X6.X|
0x19C0: 36 E2 58 36 EB 6A 57 EB  6A 57 00 80 80 F9 57 B1  |6.X6.jW.jW....W.|
0x19D0: F9 57 B1 F9 57 B1 F9 57  B1 F6 31 D9 F6 31 D9 F6  |.W..W..W..1..1..|
0x19E0: 31 D9 F6 31 D9 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..1..X6.X6.X6.X|
0x19F0: 36 E2 58 36 E2 58 36 EB  6A 57 00 80 80 00 80 80  |6.X6.X6.jW......|
0x1A00: 00 80 80 F9 57 B1 F9 57  B1 F9 57 B1 FD 60 D0 FD  |....W..W..W..`..|
0x1A10: 60 D0 F6 31 D9 F6 31 D9  E2 58 36 E2 58 36 E2 58  |`..1..1..X6.X6.X|
0x1A20: 36 E2 58 36 E2 58 36 EB  6A 57 EB 6A 57 00 80 80  |6.X6.X6.jW.jW...|
0x1A30: 00 80 80 00 80 80 00 80  80 F9 57 B1 F9 57 B1 FD  |..........W..W..|
0x1A40: 60 D0 FD 60 D0 FD 60 D0  FD 60 D0 E2 58 36 E2 58  |`..`..`..`..X6.X|
0x1A50: 36 E2 58 36 E2 58 36 E2  58 36 EB 6A 57 00 80 80  |6.X6.X6.X6.jW...|
0x1A60: 00 80 80 00 80 80 00 80  80 00 80 80 FD 70 AC FD  |.............p..|
0x1A70: 70 AC FD 60 D0 FD 60 D0  FD 60 D0 FD 60 D0 E2 58  |p..`..`..`..`..X|
0x1A80: 36 E2 58 36 E2 58 36 E2  58 36 C4 A4 61 C4 A4 61  |6.X6.X6.X6..a..a|
0x1A90: 00 80 80 00 80 80 00 80  80 00 80 80 00 80 80 00  |................|
0x1AA0: 80 80 FD 70 AC FD 60 D0  FD 60 D0 FD 60 D0 FD 60  |...p..`..`..`..`|
0x1AB0: D0 E2 58 36 E2 58 36 C4  A4 61 C4 A4 61 C4 A4 61  |..X6.X6..a..a..a|
0x1AC0: C4 A4 61 C4 A4 61 00 80  80 00 80 80 00 80 80 00  |..a..a..........|
0x1AD0: 80 80 00 80 80 FD 70 AC  FD 70 AC FD 60 D0 FD 60  |......p..p..`..`|
0x1AE0: D0 FD 60 D0 E2 58 36 C4  A4 61 C4 A4 61 C4 A4 61  |..`..X6..a..a..a|
0x1AF0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 00 80 80 00  |..a..a..a..a....|
0x1B00: 80 80 E6 B0 90 E6 B0 90  E6 B0 90 E6 B0 90 FD 60  |...............`|
0x1B10: D0 FD 60 D0 FD 60 D0 C4  A4 61 C4 A4 61 C4 A4 61  |..`..`...a..a..a|
0x1B20: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1B30: A4 61 E6 B0 90 E6 B0 90  E6 B0 90 DB D5 9F DB D5  |.a..............|
0x1B40: 9F DB D5 9F DB D5 9F FD  60 D0 C4 A4 61 C4 A4 61  |........`...a..a|
0x1B50: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1B60: A4 61 C4 A4 61 E6 B0 90  DB D5 9F DB D5 9F DB D5  |.a..a...........|
0x1B70: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F C4 A4 61  |...............a|
0x1B80: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1B90: A4 61 B8 A4 61 DB D5 9F  DB D5 9F DB D5 9F DB D5  |.a..a...........|
0x1BA0: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1BB0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1BC0: A4 61 C4 A4 61 DB D5 9F  DB D5 9F DB D5 9F DB D5  |.a..a...........|
0x1BD0: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1BE0: DB D5 9F C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |.....a..a..a..a.|
0x1BF0: A4 61 C4 A4 61 DB D5 9F  DB D5 9F DB D5 9F DB D5  |.a..a...........|
0x1C00: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1C10: DB D5 9F DB D5 9F C4 A4  61 C4 A4 61 C4 A4 61 C4  |........a..a..a.|
0x1C20: A4 61 C4 A4 61 C4 A4 61  DB D5 9F DB D5 9F DB D5  |.a..a..a........|
0x1C30: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1C40: DB D5 9F DB D5 9F DB D5  9F E2 58 36 E2 58 36 E2  |..........X6.X6.|
0x1C50: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x1C60: 36 F9 57 B1 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |6.W..1..1..1..1.|
0x1C70: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 E2 58 36 E2  |.1..1..1..1..X6.|
0x1C80: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x1C90: 36 E2 58 36 F9 57 B1 F9  57 B1 F6 31 D9 F6 31 D9  |6.X6.W..W..1..1.|
0x1CA0: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 E2  |.1..1..1..1..1..|
0x1CB0: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x1CC0: 36 E2 58 36 EB 6A 57 F9  57 B1 F9 57 B1 F9 57 B1  |6.X6.jW.W..W..W.|
0x1CD0: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.1..1..1..1..1..|
0x1CE0: 31 D9 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..X6.X6.X6.X6.X|
0x1CF0: 36 E2 58 36 E2 58 36 EB  6A 57 F9 57 B1 F9 57 B1  |6.X6.X6.jW.W..W.|
0x1D00: F9 57 B1 F9 57 B1 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.W..W..1..1..1..|
0x1D10: 31 D9 F6 31 D9 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..1..X6.X6.X6.X|
0x1D20: 36 E2 58 36 E2 58 36 EB  6A 57 EB 6A 57 EB 6A 57  |6.X6.X6.jW.jW.jW|
0x1D30: F9 57 B1 F9 57 B1 F9 57  B1 F9 57 B1 F6 31 D9 F6  |.W..W..W..W..1..|
0x1D40: 31 D9 F6 31 D9 F6 31 D9  E2 58 36 E2 58 36 E2 58  |1..1..1..X6.X6.X|
0x1D50: 36 E2 58 36 E2 58 36 E2  58 36 EB 6A 57 EB 6A 57  |6.X6.X6.X6.jW.jW|
0x1D60: 00 80 80 F9 57 B1 F9 57  B1 F9 57 B1 F9 57 B1 FD  |....W..W..W..W..|
0x1D70: 60 D0 FD 60 D0 F6 31 D9  F6 31 D9 E2 58 36 E2 58  |`..`..1..1..X6.X|
0x1D80: 36 E2 58 36 E2 58 36 E2  58 36 EB 6A 57 EB 6A 57  |6.X6.X6.X6.jW.jW|
0x1D90: EB 6A 57 00 80 80 00 80  80 F9 57 B1 F9 57 B1 F9  |.jW.......W..W..|
0x1DA0: 57 B1 FD 60 D0 FD 60 D0  FD 60 D0 FD 60 D0 E2 58  |W..`..`..`..`..X|
0x1DB0: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 EB 6A 57  |6.X6.X6.X6.X6.jW|
0x1DC0: EB 6A 57 00 80 80 00 80  80 00 80 80 00 80 80 FD  |.jW.............|
0x1DD0: 70 AC FD 70 AC FD 60 D0  FD 60 D0 FD 60 D0 FD 60  |p..p..`..`..`..`|
0x1DE0: D0 E2 58 36 E2 58 36 E2  58 36 E2 58 36 EB 6A 57  |..X6.X6.X6.X6.jW|
0x1DF0: C4 A4 61 C4 A4 61 00 80  80 00 80 80 00 80 80 00  |..a..a..........|
0x1E00: 80 80 FD 70 AC FD 70 AC  FD 60 D0 FD 60 D0 FD 60  |...p..p..`..`..`|
0x1E10: D0 FD 60 D0 E2 58 36 E2  58 36 E2 58 36 C4 A4 61  |..`..X6.X6.X6..a|
0x1E20: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 00 80 80 00  |..a..a..a..a....|
0x1E30: 80 80 00 80 80 FD 70 AC  FD 70 AC FD 70 AC FD 60  |......p..p..p..`|
0x1E40: D0 FD 60 D0 FD 60 D0 E2  58 36 C4 A4 61 C4 A4 61  |..`..`..X6..a..a|
0x1E50: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1E60: A4 61 E6 B0 90 E6 B0 90  E6 B0 90 E6 B0 90 E6 B0  |.a..............|
0x1E70: 90 FD 60 D0 FD 60 D0 FD  60 D0 C4 A4 61 C4 A4 61  |..`..`..`...a..a|
0x1E80: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1E90: A4 61 C4 A4 61 E6 B0 90  E6 B0 90 E6 B0 90 DB D5  |.a..a...........|
0x1EA0: 9F DB D5 9F DB D5 9F DB  D5 9F FD 60 D0 C4 A4 61  |...........`...a|
0x1EB0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1EC0: A4 61 C4 A4 61 E6 B0 90  E6 B0 90 DB D5 9F DB D5  |.a..a...........|
0x1ED0: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1EE0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x1EF0: A4 61 C4 A4 61 C4 A4 61  DB D5 9F DB D5 9F DB D5  |.a..a..a........|
0x1F00: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1F10: DB D5 9F C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |.....a..a..a..a.|
0x1F20: A4 61 C4 A4 61 C4 A4 61  DB D5 9F DB D5 9F DB D5  |.a..a..a........|
0x1F30: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1F40: DB D5 9F DB D5 9F C4 A4  61 C4 A4 61 C4 A4 61 C4  |........a..a..a.|
0x1F50: A4 61 C4 A4 61 C4 A4 61  DB D5 9F DB D5 9F DB D5  |.a..a..a........|
0x1F60: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1F70: DB D5 9F DB D5 9F DB D5  9F C4 A4 61 C4 A4 61 C4  |...........a..a.|
0x1F80: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 DB D5 9F DB D5  |.a..a..a..a.....|
0x1F90: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x1FA0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F E2 58 36 E2  |.............X6.|
0x1FB0: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x1FC0: 36 E2 58 36 F9 57 B1 F6  31 D9 F6 31 D9 F6 31 D9  |6.X6.W..1..1..1.|
0x1FD0: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 E2  |.1..1..1..1..1..|
0x1FE0: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x1FF0: 36 E2 58 36 E2 58 36 F9  57 B1 F9 57 B1 F6 31 D9  |6.X6.X6.W..W..1.|
0x2000: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.1..1..1..1..1..|
0x2010: 31 D9 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..X6.X6.X6.X6.X|
0x2020: 36 E2 58 36 E2 58 36 EB  6A 57 F9 57 B1 F9 57 B1  |6.X6.X6.jW.W..W.|
0x2030: F9 57 B1 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.W..1..1..1..1..|
0x2040: 31 D9 F6 31 D9 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..1..X6.X6.X6.X|
0x2050: 36 E2 58 36 E2 58 36 E2  58 36 EB 6A 57 F9 57 B1  |6.X6.X6.X6.jW.W.|
0x2060: F9 57 B1 F9 57 B1 F9 57  B1 F6 31 D9 F6 31 D9 F6  |.W..W..W..1..1..|
0x2070: 31 D9 F6 31 D9 F6 31 D9  E2 58 36 E2 58 36 E2 58  |1..1..1..X6.X6.X|
0x2080: 36 E2 58 36 E2 58 36 E2  58 36 EB 6A 57 EB 6A 57  |6.X6.X6.X6.jW.jW|
0x2090: F9 57 B1 F9 57 B1 F9 57  B1 F9 57 B1 F9 57 B1 F6  |.W..W..W..W..W..|
0x20A0: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 E2 58 36 E2 58  |1..1..1..1..X6.X|
0x20B0: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 EB 6A 57  |6.X6.X6.X6.X6.jW|
0x20C0: EB 6A 57 EB 6A 57 F9 57  B1 F9 57 B1 F9 57 B1 F9  |.jW.jW.W..W..W..|
0x20D0: 57 B1 FD 60 D0 FD 60 D0  F6 31 D9 F6 31 D9 E2 58  |W..`..`..1..1..X|
0x20E0: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 EB 6A 57  |6.X6.X6.X6.X6.jW|
0x20F0: EB 6A 57 EB 6A 57 00 80  80 F9 57 B1 F9 57 B1 F9  |.jW.jW....W..W..|
0x2100: 57 B1 F9 57 B1 FD 60 D0  FD 60 D0 FD 60 D0 FD 60  |W..W..`..`..`..`|
0x2110: D0 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..X6.X6.X6.X6.X6|
0x2120: EB 6A 57 EB 6A 57 EB 6A  57 00 80 80 00 80 80 FD  |.jW.jW.jW.......|
0x2130: 70 AC FD 70 AC FD 70 AC  FD 60 D0 FD 60 D0 FD 60  |p..p..p..`..`..`|
0x2140: D0 FD 60 D0 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..`..X6.X6.X6.X6|
0x2150: EB 6A 57 C4 A4 61 C4 A4  61 C4 A4 61 00 80 80 00  |.jW..a..a..a....|
0x2160: 80 80 FD 70 AC FD 70 AC  FD 70 AC FD 60 D0 FD 60  |...p..p..p..`..`|
0x2170: D0 FD 60 D0 FD 60 D0 E2  58 36 E2 58 36 E2 58 36  |..`..`..X6.X6.X6|
0x2180: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x2190: A4 61 E6 B0 90 E6 B0 90  FD 70 AC FD 70 AC FD 70  |.a.......p..p..p|
0x21A0: AC FD 60 D0 FD 60 D0 FD  60 D0 E2 58 36 C4 A4 61  |..`..`..`..X6..a|
0x21B0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x21C0: A4 61 C4 A4 61 E6 B0 90  E6 B0 90 E6 B0 90 E6 B0  |.a..a...........|
0x21D0: 90 E6 B0 90 FD 60 D0 FD  60 D0 FD 60 D0 C4 A4 61  |.....`..`..`...a|
0x21E0: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x21F0: A4 61 C4 A4 61 C4 A4 61  E6 B0 90 E6 B0 90 E6 B0  |.a..a..a........|
0x2200: 90 DB D5 9F DB D5 9F DB  D5 9F DB D5 9F FD 60 D0  |..............`.|
0x2210: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x2220: A4 61 C4 A4 61 C4 A4 61  E6 B0 90 E6 B0 90 DB D5  |.a..a..a........|
0x2230: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x2240: DB D5 9F C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |.....a..a..a..a.|
0x2250: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 DB D5 9F DB D5  |.a..a..a..a.....|
0x2260: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x2270: DB D5 9F DB D5 9F C4 A4  61 C4 A4 61 C4 A4 61 C4  |........a..a..a.|
0x2280: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 DB D5 9F DB D5  |.a..a..a..a.....|
0x2290: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x22A0: DB D5 9F DB D5 9F DB D5  9F C4 A4 61 C4 A4 61 C4  |...........a..a.|
0x22B0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 DB D5 9F DB D5  |.a..a..a..a.....|
0x22C0: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x22D0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F C4 A4 61 C4  |..............a.|
0x22E0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 DB D5 9F DB D5  |.a..a..a..a.....|
0x22F0: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x2300: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F E2  |................|
0x2310: 58 36 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |X6.X6.X6.X6.X6.X|
0x2320: 36 E2 58 36 E2 58 36 F9  57 B1 F6 31 D9 F6 31 D9  |6.X6.X6.W..1..1.|
0x2330: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.1..1..1..1..1..|
0x2340: 31 D9 E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..X6.X6.X6.X6.X|
0x2350: 36 E2 58 36 E2 58 36 E2  58 36 F9 57 B1 F9 57 B1  |6.X6.X6.X6.W..W.|
0x2360: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.1..1..1..1..1..|
0x2370: 31 D9 F6 31 D9 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..1..X6.X6.X6.X|
0x2380: 36 E2 58 36 E2 58 36 E2  58 36 EB 6A 57 F9 57 B1  |6.X6.X6.X6.jW.W.|
0x2390: F9 57 B1 F9 57 B1 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.W..W..1..1..1..|
0x23A0: 31 D9 F6 31 D9 F6 31 D9  E2 58 36 E2 58 36 E2 58  |1..1..1..X6.X6.X|
0x23B0: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 EB 6A 57  |6.X6.X6.X6.X6.jW|
0x23C0: F9 57 B1 F9 57 B1 F9 57  B1 F9 57 B1 F6 31 D9 F6  |.W..W..W..W..1..|
0x23D0: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 E2 58 36 E2 58  |1..1..1..1..X6.X|
0x23E0: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 EB 6A 57  |6.X6.X6.X6.X6.jW|
0x23F0: EB 6A 57 F9 57 B1 F9 57  B1 F9 57 B1 F9 57 B1 F9  |.jW.W..W..W..W..|
0x2400: 57 B1 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 E2 58  |W..1..1..1..1..X|
0x2410: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x2420: EB 6A 57 EB 6A 57 EB 6A  57 F9 57 B1 F9 57 B1 F9  |.jW.jW.jW.W..W..|
0x2430: 57 B1 F9 57 B1 FD 60 D0  FD 60 D0 FD 60 D0 F6 31  |W..W..`..`..`..1|
0x2440: D9 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..X6.X6.X6.X6.X6|
0x2450: EB 6A 57 EB 6A 57 EB 6A  57 EB 6A 57 FD 70 AC F9  |.jW.jW.jW.jW.p..|
0x2460: 57 B1 F9 57 B1 F9 57 B1  FD 60 D0 FD 60 D0 FD 60  |W..W..W..`..`..`|
0x2470: D0 FD 60 D0 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..`..X6.X6.X6.X6|
0x2480: E2 58 36 EB 6A 57 EB 6A  57 EB 6A 57 EB 6A 57 FD  |.X6.jW.jW.jW.jW.|
0x2490: 70 AC FD 70 AC FD 70 AC  FD 70 AC FD 60 D0 FD 60  |p..p..p..p..`..`|
0x24A0: D0 FD 60 D0 FD 60 D0 E2  58 36 E2 58 36 E2 58 36  |..`..`..X6.X6.X6|
0x24B0: E2 58 36 EB 6A 57 EB 6A  57 C4 A4 61 C4 A4 61 C4  |.X6.jW.jW..a..a.|
0x24C0: A4 61 FD 70 AC FD 70 AC  FD 70 AC FD 70 AC FD 60  |.a.p..p..p..p..`|
0x24D0: D0 FD 60 D0 FD 60 D0 FD  60 D0 E2 58 36 E2 58 36  |..`..`..`..X6.X6|
0x24E0: E2 58 36 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |.X6..a..a..a..a.|
0x24F0: A4 61 C4 A4 61 E6 B0 90  E6 B0 90 FD 70 AC FD 70  |.a..a.......p..p|
0x2500: AC FD 70 AC FD 60 D0 FD  60 D0 FD 60 D0 E2 58 36  |..p..`..`..`..X6|
0x2510: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x2520: A4 61 C4 A4 61 C4 A4 61  E6 B0 90 E6 B0 90 E6 B0  |.a..a..a........|
0x2530: 90 E6 B0 90 FD 70 AC FD  60 D0 FD 60 D0 FD 60 D0  |.....p..`..`..`.|
0x2540: C4 A4 61 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |..a..a..a..a..a.|
0x2550: A4 61 C4 A4 61 C4 A4 61  E6 B0 90 E6 B0 90 E6 B0  |.a..a..a........|
0x2560: 90 E6 B0 90 DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x2570: FD 60 D0 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |.`...a..a..a..a.|
0x2580: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 E6 B0 90 E6 B0  |.a..a..a..a.....|
0x2590: 90 DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x25A0: DB D5 9F DB D5 9F C4 A4  61 C4 A4 61 C4 A4 61 C4  |........a..a..a.|
0x25B0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 DB D5  |.a..a..a..a..a..|
0x25C0: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x25D0: DB D5 9F DB D5 9F DB D5  9F C4 A4 61 C4 A4 61 C4  |...........a..a.|
0x25E0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 DB D5  |.a..a..a..a..a..|
0x25F0: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x2600: DB D5 9F DB D5 9F DB D5  9F DB D5 9F C4 A4 61 C4  |..............a.|
0x2610: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 DB D5  |.a..a..a..a..a..|
0x2620: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x2630: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F C4  |................|
0x2640: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 DB D5  |.a..a..a..a..a..|
0x2650: 9F DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x2660: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x2670: D5 9F E2 58 36 E2 58 36  E2 58 36 E2 58 36 E2 58  |...X6.X6.X6.X6.X|
0x2680: 36 E2 58 36 E2 58 36 E2  58 36 F9 57 B1 F6 31 D9  |6.X6.X6.X6.W..1.|
0x2690: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.1..1..1..1..1..|
0x26A0: 31 D9 F6 31 D9 E2 58 36  E2 58 36 E2 58 36 E2 58  |1..1..X6.X6.X6.X|
0x26B0: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 F9 57 B1  |6.X6.X6.X6.X6.W.|
0x26C0: F9 57 B1 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.W..1..1..1..1..|
0x26D0: 31 D9 F6 31 D9 F6 31 D9  E2 58 36 E2 58 36 E2 58  |1..1..1..X6.X6.X|
0x26E0: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 EB 6A 57  |6.X6.X6.X6.X6.jW|
0x26F0: F9 57 B1 F9 57 B1 F9 57  B1 F6 31 D9 F6 31 D9 F6  |.W..W..W..1..1..|
0x2700: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 E2 58 36 E2 58  |1..1..1..1..X6.X|
0x2710: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x2720: EB 6A 57 F9 57 B1 F9 57  B1 F9 57 B1 F9 57 B1 F6  |.jW.W..W..W..W..|
0x2730: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 E2 58  |1..1..1..1..1..X|
0x2740: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x2750: EB 6A 57 EB 6A 57 F9 57  B1 F9 57 B1 F9 57 B1 F9  |.jW.jW.W..W..W..|
0x2760: 57 B1 F9 57 B1 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |W..W..1..1..1..1|
0x2770: D9 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..X6.X6.X6.X6.X6|
0x2780: E2 58 36 EB 6A 57 EB 6A  57 EB 6A 57 F9 57 B1 F9  |.X6.jW.jW.jW.W..|
0x2790: 57 B1 F9 57 B1 F9 57 B1  FD 60 D0 FD 60 D0 FD 60  |W..W..W..`..`..`|
0x27A0: D0 F6 31 D9 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..1..X6.X6.X6.X6|
0x27B0: E2 58 36 EB 6A 57 EB 6A  57 EB 6A 57 EB 6A 57 FD  |.X6.jW.jW.jW.jW.|
0x27C0: 70 AC F9 57 B1 F9 57 B1  F9 57 B1 FD 60 D0 FD 60  |p..W..W..W..`..`|
0x27D0: D0 FD 60 D0 FD 60 D0 E2  58 36 E2 58 36 E2 58 36  |..`..`..X6.X6.X6|
0x27E0: E2 58 36 E2 58 36 EB 6A  57 EB 6A 57 EB 6A 57 EB  |.X6.X6.jW.jW.jW.|
0x27F0: 6A 57 FD 70 AC FD 70 AC  FD 70 AC FD 70 AC FD 60  |jW.p..p..p..p..`|
0x2800: D0 FD 60 D0 FD 60 D0 FD  60 D0 E2 58 36 E2 58 36  |..`..`..`..X6.X6|
0x2810: E2 58 36 E2 58 36 EB 6A  57 EB 6A 57 EB 6A 57 C4  |.X6.X6.jW.jW.jW.|
0x2820: A4 61 C4 A4 61 FD 70 AC  FD 70 AC FD 70 AC FD 70  |.a..a.p..p..p..p|
0x2830: AC FD 60 D0 FD 60 D0 FD  60 D0 FD 60 D0 E2 58 36  |..`..`..`..`..X6|
0x2840: E2 58 36 E2 58 36 C4 A4  61 C4 A4 61 C4 A4 61 C4  |.X6.X6..a..a..a.|
0x2850: A4 61 C4 A4 61 C4 A4 61  E6 B0 90 E6 B0 90 FD 70  |.a..a..a.......p|
0x2860: AC FD 70 AC FD 70 AC FD  60 D0 FD 60 D0 FD 60 D0  |..p..p..`..`..`.|
0x2870: E2 58 36 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |.X6..a..a..a..a.|
0x2880: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 E6 B0 90 E6 B0  |.a..a..a..a.....|
0x2890: 90 E6 B0 90 E6 B0 90 FD  70 AC FD 60 D0 FD 60 D0  |........p..`..`.|
0x28A0: FD 60 D0 C4 A4 61 C4 A4  61 C4 A4 61 C4 A4 61 C4  |.`...a..a..a..a.|
0x28B0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 E6 B0 90 E6 B0  |.a..a..a..a.....|
0x28C0: 90 E6 B0 90 E6 B0 90 DB  D5 9F DB D5 9F DB D5 9F  |................|
0x28D0: DB D5 9F FD 60 D0 C4 A4  61 C4 A4 61 C4 A4 61 C4  |....`...a..a..a.|
0x28E0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 E6 B0  |.a..a..a..a..a..|
0x28F0: 90 E6 B0 90 DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |................|
0x2900: DB D5 9F DB D5 9F DB D5  9F C4 A4 61 C4 A4 61 C4  |...........a..a.|
0x2910: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x2920: 61 DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |a...............|
0x2930: DB D5 9F DB D5 9F DB D5  9F DB D5 9F C4 A4 61 C4  |..............a.|
0x2940: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x2950: 61 DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |a...............|
0x2960: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F C4  |................|
0x2970: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x2980: 61 DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |a...............|
0x2990: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x29A0: D5 9F C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |....a..a..a..a..|
0x29B0: 61 DB D5 9F DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |a...............|
0x29C0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x29D0: D5 9F DB D5 9F E2 58 36  E2 58 36 E2 58 36 E2 58  |......X6.X6.X6.X|
0x29E0: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 F9 57 B1  |6.X6.X6.X6.X6.W.|
0x29F0: F6 31 D9 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.1..1..1..1..1..|
0x2A00: 31 D9 F6 31 D9 F6 31 D9  E2 58 36 E2 58 36 E2 58  |1..1..1..X6.X6.X|
0x2A10: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x2A20: F9 57 B1 F9 57 B1 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.W..W..1..1..1..|
0x2A30: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 E2 58 36 E2 58  |1..1..1..1..X6.X|
0x2A40: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x2A50: EB 6A 57 F9 57 B1 F9 57  B1 F9 57 B1 F6 31 D9 F6  |.jW.W..W..W..1..|
0x2A60: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 E2 58  |1..1..1..1..1..X|
0x2A70: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x2A80: E2 58 36 EB 6A 57 F9 57  B1 F9 57 B1 F9 57 B1 F9  |.X6.jW.W..W..W..|
0x2A90: 57 B1 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |W..1..1..1..1..1|
0x2AA0: D9 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..X6.X6.X6.X6.X6|
0x2AB0: E2 58 36 EB 6A 57 EB 6A  57 F9 57 B1 F9 57 B1 F9  |.X6.jW.jW.W..W..|
0x2AC0: 57 B1 F9 57 B1 F9 57 B1  F6 31 D9 F6 31 D9 F6 31  |W..W..W..1..1..1|
0x2AD0: D9 F6 31 D9 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..1..X6.X6.X6.X6|
0x2AE0: E2 58 36 E2 58 36 EB 6A  57 EB 6A 57 EB 6A 57 F9  |.X6.X6.jW.jW.jW.|
0x2AF0: 57 B1 F9 57 B1 F9 57 B1  F9 57 B1 FD 60 D0 FD 60  |W..W..W..W..`..`|
0x2B00: D0 FD 60 D0 F6 31 D9 E2  58 36 E2 58 36 E2 58 36  |..`..1..X6.X6.X6|
0x2B10: E2 58 36 E2 58 36 EB 6A  57 EB 6A 57 EB 6A 57 EB  |.X6.X6.jW.jW.jW.|
0x2B20: 6A 57 FD 70 AC F9 57 B1  F9 57 B1 F9 57 B1 FD 60  |jW.p..W..W..W..`|
0x2B30: D0 FD 60 D0 FD 60 D0 FD  60 D0 E2 58 36 E2 58 36  |..`..`..`..X6.X6|
0x2B40: E2 58 36 E2 58 36 E2 58  36 EB 6A 57 EB 6A 57 EB  |.X6.X6.X6.jW.jW.|
0x2B50: 6A 57 EB 6A 57 FD 70 AC  FD 70 AC FD 70 AC FD 70  |jW.jW.p..p..p..p|
0x2B60: AC FD 60 D0 FD 60 D0 FD  60 D0 FD 60 D0 E2 58 36  |..`..`..`..`..X6|
0x2B70: E2 58 36 E2 58 36 E2 58  36 EB 6A 57 EB 6A 57 EB  |.X6.X6.X6.jW.jW.|
0x2B80: 6A 57 C4 A4 61 C4 A4 61  FD 70 AC FD 70 AC FD 70  |jW..a..a.p..p..p|
0x2B90: AC FD 70 AC FD 60 D0 FD  60 D0 FD 60 D0 FD 60 D0  |..p..`..`..`..`.|
0x2BA0: E2 58 36 E2 58 36 E2 58  36 C4 A4 61 C4 A4 61 C4  |.X6.X6.X6..a..a.|
0x2BB0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 E6 B0 90 E6 B0  |.a..a..a..a.....|
0x2BC0: 90 FD 70 AC FD 70 AC FD  70 AC FD 60 D0 FD 60 D0  |..p..p..p..`..`.|
0x2BD0: FD 60 D0 E2 58 36 C4 A4  61 C4 A4 61 C4 A4 61 C4  |.`..X6..a..a..a.|
0x2BE0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 E6 B0 90 E6 B0  |.a..a..a..a.....|
0x2BF0: 90 E6 B0 90 E6 B0 90 E6  B0 90 FD 70 AC FD 60 D0  |...........p..`.|
0x2C00: FD 60 D0 FD 60 D0 C4 A4  61 C4 A4 61 C4 A4 61 C4  |.`..`...a..a..a.|
0x2C10: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 E6 B0  |.a..a..a..a..a..|
0x2C20: 90 E6 B0 90 E6 B0 90 E6  B0 90 E6 B0 90 DB D5 9F  |................|
0x2C30: DB D5 9F DB D5 9F FD 60  D0 C4 A4 61 C4 A4 61 C4  |.......`...a..a.|
0x2C40: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x2C50: 61 E6 B0 90 E6 B0 90 DB  D5 9F DB D5 9F DB D5 9F  |a...............|
0x2C60: DB D5 9F DB D5 9F DB D5  9F DB D5 9F C4 A4 61 C4  |..............a.|
0x2C70: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x2C80: 61 C4 A4 61 DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |a..a............|
0x2C90: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F C4  |................|
0x2CA0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x2CB0: 61 C4 A4 61 DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |a..a............|
0x2CC0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x2CD0: D5 9F C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |....a..a..a..a..|
0x2CE0: 61 C4 A4 61 DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |a..a............|
0x2CF0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x2D00: D5 9F DB D5 9F C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.......a..a..a..|
0x2D10: 61 C4 A4 61 DB D5 9F DB  D5 9F DB D5 9F DB D5 9F  |a..a............|
0x2D20: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x2D30: D5 9F DB D5 9F DB D5 9F  E2 58 36 E2 58 36 E2 58  |.........X6.X6.X|
0x2D40: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x2D50: F9 57 B1 F6 31 D9 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.W..1..1..1..1..|
0x2D60: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 E2 58 36 E2 58  |1..1..1..1..X6.X|
0x2D70: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x2D80: E2 58 36 F9 57 B1 F9 57  B1 F6 31 D9 F6 31 D9 F6  |.X6.W..W..1..1..|
0x2D90: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 E2 58  |1..1..1..1..1..X|
0x2DA0: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x2DB0: E2 58 36 EB 6A 57 F9 57  B1 F9 57 B1 F9 57 B1 F6  |.X6.jW.W..W..W..|
0x2DC0: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |1..1..1..1..1..1|
0x2DD0: D9 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..X6.X6.X6.X6.X6|
0x2DE0: E2 58 36 E2 58 36 EB 6A  57 F9 57 B1 F9 57 B1 F9  |.X6.X6.jW.W..W..|
0x2DF0: 57 B1 F9 57 B1 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |W..W..1..1..1..1|
0x2E00: D9 F6 31 D9 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..1..X6.X6.X6.X6|
0x2E10: E2 58 36 E2 58 36 EB 6A  57 EB 6A 57 F9 57 B1 F9  |.X6.X6.jW.jW.W..|
0x2E20: 57 B1 F9 57 B1 F9 57 B1  F9 57 B1 F6 31 D9 F6 31  |W..W..W..W..1..1|
0x2E30: D9 F6 31 D9 F6 31 D9 E2  58 36 E2 58 36 E2 58 36  |..1..1..X6.X6.X6|
0x2E40: E2 58 36 E2 58 36 E2 58  36 EB 6A 57 EB 6A 57 EB  |.X6.X6.X6.jW.jW.|
0x2E50: 6A 57 F9 57 B1 F9 57 B1  F9 57 B1 F9 57 B1 FD 60  |jW.W..W..W..W..`|
0x2E60: D0 FD 60 D0 FD 60 D0 F6  31 D9 E2 58 36 E2 58 36  |..`..`..1..X6.X6|
0x2E70: E2 58 36 E2 58 36 E2 58  36 EB 6A 57 EB 6A 57 EB  |.X6.X6.X6.jW.jW.|
0x2E80: 6A 57 EB 6A 57 FD 70 AC  F9 57 B1 F9 57 B1 F9 57  |jW.jW.p..W..W..W|
0x2E90: B1 FD 60 D0 FD 60 D0 FD  60 D0 FD 60 D0 E2 58 36  |..`..`..`..`..X6|
0x2EA0: E2 58 36 E2 58 36 E2 58  36 EB 6A 57 EB 6A 57 EB  |.X6.X6.X6.jW.jW.|
0x2EB0: 6A 57 EB 6A 57 EB 6A 57  FD 70 AC FD 70 AC FD 70  |jW.jW.jW.p..p..p|
0x2EC0: AC FD 70 AC FD 60 D0 FD  60 D0 FD 60 D0 FD 60 D0  |..p..`..`..`..`.|
0x2ED0: E2 58 36 E2 58 36 E2 58  36 E2 58 36 EB 6A 57 EB  |.X6.X6.X6.X6.jW.|
0x2EE0: 6A 57 EB 6A 57 EB 6A 57  C4 A4 61 FD 70 AC FD 70  |jW.jW.jW..a.p..p|
0x2EF0: AC FD 70 AC FD 70 AC FD  60 D0 FD 60 D0 FD 60 D0  |..p..p..`..`..`.|
0x2F00: FD 60 D0 E2 58 36 E2 58  36 E2 58 36 C4 A4 61 C4  |.`..X6.X6.X6..a.|
0x2F10: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 E6 B0  |.a..a..a..a..a..|
0x2F20: 90 E6 B0 90 FD 70 AC FD  70 AC FD 70 AC FD 60 D0  |.....p..p..p..`.|
0x2F30: FD 60 D0 FD 60 D0 E2 58  36 C4 A4 61 C4 A4 61 C4  |.`..`..X6..a..a.|
0x2F40: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 E6 B0  |.a..a..a..a..a..|
0x2F50: 90 E6 B0 90 E6 B0 90 E6  B0 90 E6 B0 90 FD 70 AC  |..............p.|
0x2F60: FD 60 D0 FD 60 D0 FD 60  D0 C4 A4 61 C4 A4 61 C4  |.`..`..`...a..a.|
0x2F70: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x2F80: 61 E6 B0 90 E6 B0 90 E6  B0 90 E6 B0 90 E6 B0 90  |a...............|
0x2F90: DB D5 9F DB D5 9F FD 60  D0 FD 60 D0 C4 A4 61 C4  |.......`..`...a.|
0x2FA0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x2FB0: 61 C4 A4 61 E6 B0 90 E6  B0 90 DB D5 9F DB D5 9F  |a..a............|
0x2FC0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F C4  |................|
0x2FD0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x2FE0: 61 C4 A4 61 C4 A4 61 DB  D5 9F DB D5 9F DB D5 9F  |a..a..a.........|
0x2FF0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3000: D5 9F C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |....a..a..a..a..|
0x3010: 61 C4 A4 61 C4 A4 61 DB  D5 9F DB D5 9F DB D5 9F  |a..a..a.........|
0x3020: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3030: D5 9F DB D5 9F C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.......a..a..a..|
0x3040: 61 C4 A4 61 C4 A4 61 DB  D5 9F DB D5 9F DB D5 9F  |a..a..a.........|
0x3050: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3060: D5 9F DB D5 9F DB D5 9F  C4 A4 61 C4 A4 61 C4 A4  |..........a..a..|
0x3070: 61 C4 A4 61 C4 A4 61 DB  D5 9F DB D5 9F DB D5 9F  |a..a..a.........|
0x3080: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3090: D5 9F DB D5 9F DB D5 9F  DB D5 9F E2 58 36 E2 58  |............X6.X|
0x30A0: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x30B0: E2 58 36 F9 57 B1 F6 31  D9 F6 31 D9 F6 31 D9 F6  |.X6.W..1..1..1..|
0x30C0: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 E2 58  |1..1..1..1..1..X|
0x30D0: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x30E0: E2 58 36 E2 58 36 F9 57  B1 F9 57 B1 F6 31 D9 F6  |.X6.X6.W..W..1..|
0x30F0: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |1..1..1..1..1..1|
0x3100: D9 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..X6.X6.X6.X6.X6|
0x3110: E2 58 36 E2 58 36 EB 6A  57 F9 57 B1 F9 57 B1 F9  |.X6.X6.jW.W..W..|
0x3120: 57 B1 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |W..1..1..1..1..1|
0x3130: D9 F6 31 D9 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..1..X6.X6.X6.X6|
0x3140: E2 58 36 E2 58 36 E2 58  36 EB 6A 57 F9 57 B1 F9  |.X6.X6.X6.jW.W..|
0x3150: 57 B1 F9 57 B1 F9 57 B1  F6 31 D9 F6 31 D9 F6 31  |W..W..W..1..1..1|
0x3160: D9 F6 31 D9 F6 31 D9 E2  58 36 E2 58 36 E2 58 36  |..1..1..X6.X6.X6|
0x3170: E2 58 36 E2 58 36 E2 58  36 EB 6A 57 EB 6A 57 F9  |.X6.X6.X6.jW.jW.|
0x3180: 57 B1 F9 57 B1 F9 57 B1  F9 57 B1 F9 57 B1 F6 31  |W..W..W..W..W..1|
0x3190: D9 F6 31 D9 F6 31 D9 F6  31 D9 E2 58 36 E2 58 36  |..1..1..1..X6.X6|
0x31A0: E2 58 36 E2 58 36 E2 58  36 E2 58 36 EB 6A 57 EB  |.X6.X6.X6.X6.jW.|
0x31B0: 6A 57 EB 6A 57 F9 57 B1  F9 57 B1 F9 57 B1 F9 57  |jW.jW.W..W..W..W|
0x31C0: B1 FD 60 D0 FD 60 D0 FD  60 D0 F6 31 D9 E2 58 7D  |..`..`..`..1..X}|
0x31D0: E2 58 36 E2 58 36 E2 58  36 E2 58 36 EB 6A 57 EB  |.X6.X6.X6.X6.jW.|
0x31E0: 6A 57 EB 6A 57 EB 6A 57  FD 70 AC F9 57 B1 F9 57  |jW.jW.jW.p..W..W|
0x31F0: B1 F9 57 B1 FD 60 D0 FD  60 D0 FD 60 D0 FD 60 D0  |..W..`..`..`..`.|
0x3200: E2 58 36 E2 58 36 E2 58  36 E2 58 36 EB 6A 57 EB  |.X6.X6.X6.X6.jW.|
0x3210: 6A 57 EB 6A 57 EB 6A 57  EB 6A 57 FD 70 AC FD 70  |jW.jW.jW.jW.p..p|
0x3220: AC FD 70 AC FD 70 AC FD  60 D0 FD 60 D0 FD 60 D0  |..p..p..`..`..`.|
0x3230: FD 60 D0 E2 58 36 E2 58  36 E2 58 36 E2 58 36 EB  |.`..X6.X6.X6.X6.|
0x3240: 6A 57 EB 6A 57 EB 6A 57  EB 6A 57 C4 A4 61 FD 70  |jW.jW.jW.jW..a.p|
0x3250: AC FD 70 AC FD 70 AC FD  70 AC FD 60 D0 FD 60 D0  |..p..p..p..`..`.|
0x3260: FD 60 D0 FD 60 D0 E2 58  36 E2 58 36 E2 58 36 C4  |.`..`..X6.X6.X6.|
0x3270: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 E6 B0  |.a..a..a..a..a..|
0x3280: 90 E6 B0 90 E6 B0 90 FD  70 AC FD 70 AC FD 70 AC  |........p..p..p.|
0x3290: FD 60 D0 FD 60 D0 FD 60  D0 E2 58 36 C4 A4 61 C4  |.`..`..`..X6..a.|
0x32A0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x32B0: 61 E6 B0 90 E6 B0 90 E6  B0 90 E6 B0 90 E6 B0 90  |a...............|
0x32C0: FD 70 AC FD 60 D0 FD 60  D0 FD 60 D0 C4 A4 61 C4  |.p..`..`..`...a.|
0x32D0: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x32E0: 61 C4 A4 61 E6 B0 90 E6  B0 90 E6 B0 90 E6 B0 90  |a..a............|
0x32F0: E6 B0 90 DB D5 9F DB D5  9F FD 60 D0 FD 60 D0 C4  |..........`..`..|
0x3300: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x3310: 61 C4 A4 61 C4 A4 61 E6  B0 90 E6 B0 90 DB D5 9F  |a..a..a.........|
0x3320: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3330: D5 9F C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |....a..a..a..a..|
0x3340: 61 C4 A4 61 C4 A4 61 E6  B0 90 DB D5 9F DB D5 9F  |a..a..a.........|
0x3350: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3360: D5 9F DB D5 9F C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.......a..a..a..|
0x3370: 61 C4 A4 61 C4 A4 61 C4  A4 61 DB D5 9F DB D5 9F  |a..a..a..a......|
0x3380: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3390: D5 9F DB D5 9F DB D5 9F  C4 A4 61 C4 A4 61 C4 A4  |..........a..a..|
0x33A0: 61 C4 A4 61 C4 A4 61 C4  A4 61 DB D5 9F DB D5 9F  |a..a..a..a......|
0x33B0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x33C0: D5 9F DB D5 9F DB D5 9F  DB D5 9F C4 A4 61 C4 A4  |.............a..|
0x33D0: 61 C4 A4 61 C4 A4 61 C4  A4 61 DB D5 9F DB D5 9F  |a..a..a..a......|
0x33E0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x33F0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F E2 58  |...............X|
0x3400: 36 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |6.X6.X6.X6.X6.X6|
0x3410: E2 58 36 E2 58 36 F9 57  B1 F6 31 D9 F6 31 D9 F6  |.X6.X6.W..1..1..|
0x3420: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |1..1..1..1..1..1|
0x3430: D9 E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..X6.X6.X6.X6.X6|
0x3440: E2 58 36 E2 58 36 E2 58  36 F9 57 B1 F9 57 B1 F6  |.X6.X6.X6.W..W..|
0x3450: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |1..1..1..1..1..1|
0x3460: D9 F6 31 D9 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..1..X6.X6.X6.X6|
0x3470: E2 58 36 E2 58 36 E2 58  36 EB 6A 57 F9 57 B1 F9  |.X6.X6.X6.jW.W..|
0x3480: 57 B1 F9 57 B1 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |W..W..1..1..1..1|
0x3490: D9 F6 31 D9 F6 31 D9 E2  58 36 E2 58 36 E2 58 36  |..1..1..X6.X6.X6|
0x34A0: E2 58 36 E2 58 36 E2 58  36 E2 58 36 EB 6A 57 F9  |.X6.X6.X6.X6.jW.|
0x34B0: 57 B1 F9 57 B1 F9 57 B1  F9 57 B1 F6 31 D9 F6 31  |W..W..W..W..1..1|
0x34C0: D9 F6 31 D9 F6 31 D9 F6  31 D9 E2 58 36 E2 58 36  |..1..1..1..X6.X6|
0x34D0: E2 58 36 E2 58 36 E2 58  36 E2 58 36 EB 6A 57 EB  |.X6.X6.X6.X6.jW.|
0x34E0: 6A 57 F9 57 B1 F9 57 B1  F9 57 B1 F9 57 B1 F9 57  |jW.W..W..W..W..W|
0x34F0: B1 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 E2 58 36  |..1..1..1..1..X6|
0x3500: E2 58 36 E2 58 36 E2 58  36 E2 58 36 EB 6A 57 EB  |.X6.X6.X6.X6.jW.|
0x3510: 6A 57 EB 6A 57 EB 6A 57  F9 57 B1 F9 57 B1 F9 57  |jW.jW.jW.W..W..W|
0x3520: B1 F9 57 B1 FD 60 D0 FD  60 D0 FD 60 D0 F6 31 D9  |..W..`..`..`..1.|
0x3530: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 EB  |.X6.X6.X6.X6.X6.|
0x3540: 6A 57 EB 6A 57 EB 6A 57  EB 6A 57 FD 70 AC F9 57  |jW.jW.jW.jW.p..W|
0x3550: B1 F9 57 B1 F9 57 B1 FD  60 D0 FD 60 D0 FD 60 D0  |..W..W..`..`..`.|
0x3560: FD 60 D0 E2 58 36 E2 58  36 E2 58 36 E2 58 36 EB  |.`..X6.X6.X6.X6.|
0x3570: 6A 57 EB 6A 57 EB 6A 57  EB 6A 57 EB 6A 57 FD 70  |jW.jW.jW.jW.jW.p|
0x3580: AC FD 70 AC FD 70 AC FD  70 AC FD 60 D0 FD 60 D0  |..p..p..p..`..`.|
0x3590: FD 60 D0 FD 60 D0 E2 58  36 E2 58 36 E2 58 36 E2  |.`..`..X6.X6.X6.|
0x35A0: 58 36 EB 6A 57 EB 6A 57  EB 6A 57 EB 6A 57 EB 6A  |X6.jW.jW.jW.jW.j|
0x35B0: 57 FD 70 AC FD 70 AC FD  70 AC FD 70 AC FD 60 D0  |W.p..p..p..p..`.|
0x35C0: FD 60 D0 FD 60 D0 FD 60  D0 E2 58 36 E2 58 36 E2  |.`..`..`..X6.X6.|
0x35D0: 58 36 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |X6..a..a..a..a..|
0x35E0: 61 E6 B0 90 E6 B0 90 E6  B0 90 FD 70 AC FD 70 AC  |a..........p..p.|
0x35F0: FD 70 AC FD 60 D0 FD 60  D0 FD 60 D0 E2 58 36 E2  |.p..`..`..`..X6.|
0x3600: 58 36 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |X6..a..a..a..a..|
0x3610: 61 C4 A4 61 E6 B0 90 E6  B0 90 E6 B0 90 E6 B0 90  |a..a............|
0x3620: E6 B0 90 FD 70 AC FD 60  D0 FD 60 D0 FD 60 D0 C4  |....p..`..`..`..|
0x3630: A4 61 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.a..a..a..a..a..|
0x3640: 61 C4 A4 61 C4 A4 61 E6  B0 90 E6 B0 90 E6 B0 90  |a..a..a.........|
0x3650: E6 B0 90 E6 B0 90 DB D5  9F DB D5 9F FD 60 D0 FD  |.............`..|
0x3660: 60 D0 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |`...a..a..a..a..|
0x3670: 61 C4 A4 61 C4 A4 61 C4  A4 61 E6 B0 90 E6 B0 90  |a..a..a..a......|
0x3680: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3690: D5 9F DB D5 9F C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |.......a..a..a..|
0x36A0: 61 C4 A4 61 C4 A4 61 C4  A4 61 E6 B0 90 DB D5 9F  |a..a..a..a......|
0x36B0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x36C0: D5 9F DB D5 9F DB D5 9F  C4 A4 61 C4 A4 61 C4 A4  |..........a..a..|
0x36D0: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 DB D5 9F  |a..a..a..a..a...|
0x36E0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x36F0: D5 9F DB D5 9F DB D5 9F  DB D5 9F C4 A4 61 C4 A4  |.............a..|
0x3700: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 DB D5 9F  |a..a..a..a..a...|
0x3710: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3720: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F C4 A4  |................|
0x3730: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 DB D5 9F  |a..a..a..a..a...|
0x3740: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3750: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x3760: 9F E2 58 36 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..X6.X6.X6.X6.X6|
0x3770: E2 58 36 E2 58 36 E2 58  36 F9 57 B1 F6 31 D9 F6  |.X6.X6.X6.W..1..|
0x3780: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |1..1..1..1..1..1|
0x3790: D9 F6 31 D9 E2 58 36 E2  58 36 E2 58 36 E2 58 36  |..1..X6.X6.X6.X6|
0x37A0: E2 58 36 E2 58 36 E2 58  36 E2 58 36 F9 57 B1 F9  |.X6.X6.X6.X6.W..|
0x37B0: 57 B1 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |W..1..1..1..1..1|
0x37C0: D9 F6 31 D9 F6 31 D9 E2  58 36 E2 58 36 E2 58 36  |..1..1..X6.X6.X6|
0x37D0: E2 58 36 E2 58 36 E2 58  36 E2 58 36 EB 6A 57 F9  |.X6.X6.X6.X6.jW.|
0x37E0: 57 B1 F9 57 B1 F9 57 B1  F6 31 D9 F6 31 D9 F6 31  |W..W..W..1..1..1|
0x37F0: D9 F6 31 D9 F6 31 D9 F6  31 D9 E2 58 36 E2 58 36  |..1..1..1..X6.X6|
0x3800: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 EB  |.X6.X6.X6.X6.X6.|
0x3810: 6A 57 F9 57 B1 F9 57 B1  F9 57 B1 F9 57 B1 F6 31  |jW.W..W..W..W..1|
0x3820: D9 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 E2 58 36  |..1..1..1..1..X6|
0x3830: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 EB  |.X6.X6.X6.X6.X6.|
0x3840: 6A 57 EB 6A 57 F9 57 B1  F9 57 B1 F9 57 B1 F9 57  |jW.jW.W..W..W..W|
0x3850: B1 F9 57 B1 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..W..1..1..1..1.|
0x3860: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 EB  |.X6.X6.X6.X6.X6.|
0x3870: 6A 57 EB 6A 57 EB 6A 57  EB 6A 57 F9 57 B1 F9 57  |jW.jW.jW.jW.W..W|
0x3880: B1 F9 57 B1 F9 57 B1 FD  60 D0 FD 60 D0 FD 60 D0  |..W..W..`..`..`.|
0x3890: F6 31 D9 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.1..X6.X6.X6.X6.|
0x38A0: 58 36 EB 6A 57 EB 6A 57  EB 6A 57 EB 6A 57 FD 70  |X6.jW.jW.jW.jW.p|
0x38B0: AC F9 57 B1 F9 57 B1 FD  60 D0 FD 60 D0 FD 60 D0  |..W..W..`..`..`.|
0x38C0: FD 60 D0 FD 60 D0 E2 58  36 E2 58 36 E2 58 36 E2  |.`..`..X6.X6.X6.|
0x38D0: 58 36 EB 6A 57 EB 6A 57  EB 6A 57 EB 6A 57 EB 6A  |X6.jW.jW.jW.jW.j|
0x38E0: 57 FD 70 AC FD 70 AC FD  70 AC FD 70 AC FD 60 D0  |W.p..p..p..p..`.|
0x38F0: FD 60 D0 FD 60 D0 FD 60  D0 E2 58 36 E2 58 36 E2  |.`..`..`..X6.X6.|
0x3900: 58 36 E2 58 36 EB 6A 57  EB 6A 57 EB 6A 57 EB 6A  |X6.X6.jW.jW.jW.j|
0x3910: 57 EB 6A 57 FD 70 AC FD  70 AC FD 70 AC FD 70 AC  |W.jW.p..p..p..p.|
0x3920: FD 60 D0 FD 60 D0 FD 60  D0 FD 60 D0 E2 58 36 E2  |.`..`..`..`..X6.|
0x3930: 58 36 E2 58 36 EB 6A 57  C4 A4 61 C4 A4 61 C4 A4  |X6.X6.jW..a..a..|
0x3940: 61 C4 A4 61 E6 B0 90 E6  B0 90 FD 70 AC FD 70 AC  |a..a.......p..p.|
0x3950: FD 70 AC FD 70 AC FD 60  D0 FD 60 D0 FD 60 D0 E2  |.p..p..`..`..`..|
0x3960: 58 36 E2 58 36 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |X6.X6..a..a..a..|
0x3970: 61 C4 A4 61 C4 A4 61 E6  B0 90 E6 B0 90 E6 B0 90  |a..a..a.........|
0x3980: E6 B0 90 E6 B0 90 FD 70  AC FD 60 D0 FD 60 D0 FD  |.......p..`..`..|
0x3990: 60 D0 C4 A4 61 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |`...a..a..a..a..|
0x39A0: 61 C4 A4 61 C4 A4 61 C4  A4 61 E6 B0 90 E6 B0 90  |a..a..a..a......|
0x39B0: E6 B0 90 E6 B0 90 E6 B0  90 DB D5 9F DB D5 9F FD  |................|
0x39C0: 60 D0 FD 60 D0 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |`..`...a..a..a..|
0x39D0: 61 C4 A4 61 C4 A4 61 C4  A4 61 E6 B0 90 E6 B0 90  |a..a..a..a......|
0x39E0: E6 B0 90 E6 B0 90 DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x39F0: D5 9F DB D5 9F DB D5 9F  C4 A4 61 C4 A4 61 C4 A4  |..........a..a..|
0x3A00: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 E6 B0 90  |a..a..a..a..a...|
0x3A10: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3A20: D5 9F DB D5 9F DB D5 9F  DB D5 9F C4 A4 61 C4 A4  |.............a..|
0x3A30: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |a..a..a..a..a..a|
0x3A40: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3A50: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F C4 A4  |................|
0x3A60: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |a..a..a..a..a..a|
0x3A70: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3A80: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F B4 D5  |................|
0x3A90: 9F C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |...a..a..a..a..a|
0x3AA0: DB D5 9F DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3AB0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x3AC0: 9F DB D5 9F E2 58 36 E2  58 36 E2 58 36 E2 58 36  |.....X6.X6.X6.X6|
0x3AD0: E2 58 36 E2 58 36 E2 58  36 E2 58 36 F9 57 B1 F6  |.X6.X6.X6.X6.W..|
0x3AE0: 31 D9 F6 31 D9 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |1..1..1..1..1..1|
0x3AF0: D9 F6 31 D9 F6 31 D9 E2  58 36 E2 58 36 E2 58 36  |..1..1..X6.X6.X6|
0x3B00: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 F9  |.X6.X6.X6.X6.X6.|
0x3B10: 57 B1 F9 57 B1 F6 31 D9  F6 31 D9 F6 31 D9 F6 31  |W..W..1..1..1..1|
0x3B20: D9 F6 31 D9 F6 31 D9 F6  31 D9 E2 58 36 E2 58 36  |..1..1..1..X6.X6|
0x3B30: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 EB  |.X6.X6.X6.X6.X6.|
0x3B40: 6A 57 F9 57 B1 F9 57 B1  F9 57 B1 F6 31 D9 F6 31  |jW.W..W..W..1..1|
0x3B50: D9 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 E2 58 36  |..1..1..1..1..X6|
0x3B60: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 EB  |.X6.X6.X6.X6.X6.|
0x3B70: 6A 57 EB 6A 57 F9 57 B1  F9 57 B1 F9 57 B1 F9 57  |jW.jW.W..W..W..W|
0x3B80: B1 F6 31 D9 F6 31 D9 F6  31 D9 F6 31 D9 F6 31 D9  |..1..1..1..1..1.|
0x3B90: E2 58 36 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.X6.X6.X6.X6.X6.|
0x3BA0: 58 36 EB 6A 57 EB 6A 57  F9 57 B1 F9 57 B1 F9 57  |X6.jW.jW.W..W..W|
0x3BB0: B1 F9 57 B1 F9 57 B1 F6  31 D9 F6 31 D9 F6 31 D9  |..W..W..1..1..1.|
0x3BC0: F6 31 D9 E2 58 36 E2 58  36 E2 58 36 E2 58 36 E2  |.1..X6.X6.X6.X6.|
0x3BD0: 58 36 EB 6A 57 EB 6A 57  EB 6A 57 EB 6A 57 F9 57  |X6.jW.jW.jW.jW.W|
0x3BE0: B1 F9 57 B1 F9 57 B1 F9  57 B1 FD 60 D0 FD 60 D0  |..W..W..W..`..`.|
0x3BF0: FD 60 D0 F6 31 D9 E2 58  36 E2 58 36 E2 58 36 E2  |.`..1..X6.X6.X6.|
0x3C00: 58 36 E2 58 36 EB 6A 57  EB 6A 57 EB 6A 57 EB 6A  |X6.X6.jW.jW.jW.j|
0x3C10: 57 FD 70 AC F9 57 B1 F9  57 B1 FD 60 D0 FD 60 D0  |W.p..W..W..`..`.|
0x3C20: FD 60 D0 FD 60 D0 FD 60  D0 E2 58 36 E2 58 36 E2  |.`..`..`..X6.X6.|
0x3C30: 58 36 E2 58 36 EB 6A 57  EB 6A 57 EB 6A 57 EB 6A  |X6.X6.jW.jW.jW.j|
0x3C40: 57 EB 6A 57 FD 70 AC FD  70 AC FD 70 AC FD 70 AC  |W.jW.p..p..p..p.|
0x3C50: FD 60 D0 FD 60 D0 FD 60  D0 FD 60 D0 E2 58 36 E2  |.`..`..`..`..X6.|
0x3C60: 58 36 E2 58 36 E2 58 36  EB 6A 57 EB 6A 57 EB 6A  |X6.X6.X6.jW.jW.j|
0x3C70: 57 EB 6A 57 FD 70 AC FD  70 AC FD 70 AC FD 70 AC  |W.jW.p..p..p..p.|
0x3C80: FD 70 AC FD 60 D0 FD 60  D0 FD 60 D0 FD 60 D0 E2  |.p..`..`..`..`..|
0x3C90: 58 36 E2 58 36 E2 58 36  EB 6A 57 C4 A4 61 C4 A4  |X6.X6.X6.jW..a..|
0x3CA0: 61 C4 A4 61 C4 A4 61 E6  B0 90 E6 B0 90 FD 70 AC  |a..a..a.......p.|
0x3CB0: FD 70 AC FD 70 AC FD 70  AC FD 60 D0 FD 60 D0 FD  |.p..p..p..`..`..|
0x3CC0: 60 D0 E2 58 36 E2 58 36  C4 A4 61 C4 A4 61 C4 A4  |`..X6.X6..a..a..|
0x3CD0: 61 C4 A4 61 C4 A4 61 C4  A4 61 E6 B0 90 E6 B0 90  |a..a..a..a......|
0x3CE0: E6 B0 90 E6 B0 90 E6 B0  90 FD 70 AC FD 60 D0 FD  |..........p..`..|
0x3CF0: 60 D0 FD 60 D0 C4 A4 61  C4 A4 61 C4 A4 61 C4 A4  |`..`...a..a..a..|
0x3D00: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 E6 B0 90  |a..a..a..a..a...|
0x3D10: E6 B0 90 E6 B0 90 E6 B0  90 E6 B0 90 DB D5 9F DB  |................|
0x3D20: D5 5F FD 60 D0 FD 60 D0  C4 A4 61 C4 A4 61 C4 A4  |._.`..`...a..a..|
0x3D30: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 E6 B0 90  |a..a..a..a..a...|
0x3D40: E6 B0 90 E6 B0 90 E6 B0  90 DB D5 9F DB D5 9F DB  |................|
0x3D50: D5 9F DB D5 9F DB D5 9F  DB D5 9F C4 A4 61 C4 A4  |.............a..|
0x3D60: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |a..a..a..a..a..a|
0x3D70: E6 B0 90 DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |................|
0x3D80: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F C4 A4  |................|
0x3D90: 61 C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |a..a..a..a..a..a|
0x3DA0: C4 A4 61 DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |..a.............|
0x3DB0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x3DC0: 9F C4 A4 61 C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |...a..a..a..a..a|
0x3DD0: C4 A4 61 DB D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |..a.............|
0x3DE0: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x3DF0: 9F DB D5 9F C4 A4 61 C4  A4 61 C4 A4 61 C4 A4 61  |......a..a..a..a|
0x3E00: C4 A4 61 D1 D5 9F DB D5  9F DB D5 9F DB D5 9F DB  |..a.............|
0x3E10: D5 9F DB D5 9F DB D5 9F  DB D5 9F DB D5 9F DB D5  |................|
0x3E20: 9F DB D5 9F DB D5 9F 00  01 02 03 04 05 06 07 08  |................|
0x3E30: 09 0A 0B 0C 0D 0E 0F 10  11 12 13 14 15 16 17 18  |................|
0x3E40: 19 1A 1B 1C 1D 1E 1F 20  21 22 23 24 25 26 27 28  |....... !"#$%&'(|
0x3E50: 29 2A 2B 2C 2D 2E 2F 30  31 32 33 34 35 36 37 38  |)*+,-./012345678|
0x3E60: 39 3A 3B 3C 3D 3E 3F 40  41 42 43 44 45 46 47 48  |9:;<=>?@ABCDEFGH|
0x3E70: 49 4A 4B 4C 4D 4E 4F 50  51 52 53 54 55 56 57 58  |IJKLMNOPQRSTUVWX|
0x3E80: 59 5A 5B 5C 5D 5E 5F 60  61 62 63 64 65 66 67 68  |YZ[\]^_`abcdefgh|
0x3E90: 69 6A 6B 6C 6D 6E 6F 70  71 72 73 74 75 76 77 78  |ijklmnopqrstuvwx|
0x3EA0: 79 7A 7B 7C 7D 7E 7F 80  81 82 83 84 85 86 87 88  |yz{|}~..........|
0x3EB0: 89 8A 8B 8C 8D 8E 8F 90  91 92 93 94 95 96 97 98  |................|
0x3EC0: 99 9A 9B 9C 9D 9E 9F A0  A1 A2 A3 A4 A5 A6 A7 A8  |................|
0x3ED0: A9 AA AB AC AD AE AF B0  B1 B2 B3 B4 B5 B6 B7 B8  |................|
0x3EE0: B9 BA BB BC BD BE BF C0  C1 C2 C3 C4 C5 C6 C7 C8  |................|
0x3EF0: C9 CA CB CC CD CE CF D0  D1 D2 D3 D4 D5 D6 D7 D8  |................|
0x3F00: D9 DA DB DC DD DE DF E0  E1 E2 E3 E4 E5 E6 E7 E8  |................|
0x3F10: E9 EA EB EC ED EE EF F0  F1 F2 F3 F4 F5 F6 F7 F8  |................|
0x3F20: F9 FA FB FC FD FE FF 00  01 02 03 04 05 06 07 08  |................|
0x3F30: 09 0A 0B 0C 0D 0E 0F 10  11 12 13 14 15 16 17 18  |................|
0x3F40: 19 1A 1B 1C 1D 1E 1F 20  21 22 23 24 25 26 27 28  |....... !"#$%&'(|
0x3F50: 29 2A 2B 2C 2D 2E 2F 30  31 32 33 34 35 36 37 38  |)*+,-./012345678|
0x3F60: 39 3A 3B 3C 3D 3E 3F 40  41 42 43 44 45 46 47 48  |9:;<=>?@ABCDEFGH|
0x3F70: 49 4A 4B 4C 4D 4E 4F 50  51 52 53 54 55 56 57 58  |IJKLMNOPQRSTUVWX|
0x3F80: 59 5A 5B 5C 5D 5E 5F 60  61 62 63 64 65 66 67 68  |YZ[\]^_`abcdefgh|
0x3F90: 69 6A 6B 6C 6D 6E 6F 70  71 72 73 74 75 76 77 78  |ijklmnopqrstuvwx|
0x3FA0: 79 7A 7B 7C 7D 7E 7F 80  81 82 83 84 85 86 87 88  |yz{|}~..........|
0x3FB0: 89 8A 8B 8C 8D 8E 8F 90  91 92 93 94 95 96 97 98  |................|
0x3FC0: 99 9A 9B 9C 9D 9E 9F A0  A1 A2 A3 A4 A5 A6 A7 A8  |................|
0x3FD0: A9 AA AB AC AD AE AF B0  B1 B2 B3 B4 B5 B6 B7 B8  |................|
0x3FE0: B9 BA BB BC BD BE BF C0  C1 C2 C3 C4 C5 C6 C7 C8  |................|
0x3FF0: C9 CA CB CC CD CE CF D0  D1 D2 D3 D4 D5 D6 D7 D8  |................|
0x4000: D9 DA DB DC DD DE DF E0  E1 E2 E3 E4 E5 E6 E7 E8  |................|
0x4010: E9 EA EB EC ED EE EF F0  F1 F2 F3 F4 F5 F6 F7 F8  |................|
0x4020: F9 FA FB FC FD FE FF 00  01 02 03 04 05 06 07 08  |................|
0x4030: 09 0A 0B 0C 0D 0E 0F 10  11 12 13 14 15 16 17 18  |................|
0x4040: 19 1A 1B 1C 1D 1E 1F 20  21 22 23 24 25 26 27 28  |....... !"#$%&'(|
0x4050: 29 2A 2B 2C 2D 2E 2F 30  31 32 33 34 35 36 37 38  |)*+,-./012345678|
0x4060: 39 3A 3B 3C 3D 3E 3F 40  41 42 43 44 45 46 47 48  |9:;<=>?@ABCDEFGH|
0x4070: 49 4A 4B 4C 4D 4E 4F 50  51 52 53 54 55 56 57 58  |IJKLMNOPQRSTUVWX|
0x4080: 59 5A 5B 5C 5D 5E 5F 60  61 62 63 64 65 66 67 68  |YZ[\]^_`abcdefgh|
0x4090: 69 6A 6B 6C 6D 6E 6F 70  71 72 73 74 75 76 77 78  |ijklmnopqrstuvwx|
0x40A0: 79 7A 7B 7C 7D 7E 7F 80  81 82 83 84 85 86 87 88  |yz{|}~..........|
0x40B0: 89 8A 8B 8C 8D 8E 8F 90  91 92 93 94 95 96 97 98  |................|
0x40C0: 99 9A 9B 9C 9D 9E 9F A0  A1 A2 A3 A4 A5 A6 A7 A8  |................|
0x40D0: A9 AA AB AC AD AE AF B0  B1 B2 B3 B4 B5 B6 B7 B8  |................|
0x40E0: B9 BA BB BC BD BE BF C0  C1 C2 C3 C4 C5 C6 C7 C8  |................|
0x40F0: C9 CA CB CC CD CE CF D0  D1 D2 D3 D4 D5 D6 D7 D8  |................|
0x4100: D9 DA DB DC DD DE DF E0  E1 E2 E3 E4 E5 E6 E7 E8  |................|
0x4110: E9 EA EB EC ED EE EF F0  F1 F2 F3 F4 F5 F6 F7 F8  |................|
0x4120: F9 FA FB FC FD FE FF 00                           |........|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 1**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/xss/research/test-profiles/BlacklightPoster_202143.icc

Device Class: 0x61627374

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [[X]] [ ]  
  AToB1/BToA1 (Rel. Colorimetric): [ ] [ ]  
  AToB2/BToA2 (Saturation):        [ ] [ ]  

  DToB0/BToD0 (Perceptual):        [ ] [ ]  
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]  
  DToB2/BToD2 (Saturation):        [ ] [ ]  

  Matrix/TRC Tags:                 [ ]  

[ERR] RESULT: Profile does NOT support round-trip validation
   (Missing symmetric AToB/BToA, DToB/BToD, or Matrix/TRC tag pairs)
```

---

## LUT Text Export (`-xt`)

**Exit Code: 0**

```
=== Extracting LUT data as text from: /home/xss/research/test-profiles/BlacklightPoster_202143.icc ===

--- AToB0Tag (type: lut8Type) ---
  Channels: in=2 out=3
  Wrote curve A[0]: /tmp/tmp.vkDT0A5oy4/BlacklightPoster_202143__AToB0Tag_curveA_0.txt (256 samples)
  Wrote curve A[1]: /tmp/tmp.vkDT0A5oy4/BlacklightPoster_202143__AToB0Tag_curveA_1.txt (256 samples)
  Wrote curve A[2]: /tmp/tmp.vkDT0A5oy4/BlacklightPoster_202143__AToB0Tag_curveA_2.txt (256 samples)
  Wrote CLUT: /tmp/tmp.vkDT0A5oy4/BlacklightPoster_202143__AToB0Tag_clut.txt (289 entries × 3 outputs)
  Wrote curve B[0]: /tmp/tmp.vkDT0A5oy4/BlacklightPoster_202143__AToB0Tag_curveB_0.txt (256 samples)
  Wrote curve B[1]: /tmp/tmp.vkDT0A5oy4/BlacklightPoster_202143__AToB0Tag_curveB_1.txt (256 samples)

=== Exported 6 LUT component(s) ===
Exported 6 text file(s) to /tmp/tmp.vkDT0A5oy4/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
