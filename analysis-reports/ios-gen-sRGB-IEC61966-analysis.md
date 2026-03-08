# ICC Profile Analysis Report

**Profile**: `test-profiles/ios-gen-sRGB-IEC61966.icc`
**File Size**: 3144 bytes
**SHA-256**: `2b3aa1645779a9e634744faf9b01e9102b0c9b88fd6deced7934df86b949af7e`
**File Type**: Microsoft color profile 2.1, type Lino, RGB/XYZ-mntr device, IEC/sRGB model by HP, 3144 bytes, 9-2-1998 6:49:00 "sRGB IEC61966-2.1"
**Date**: 2026-03-08T19:58:07Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 0 | Clean |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 1**

```

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/h02332/po/research/test-profiles/ios-gen-sRGB-IEC61966.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/h02332/po/research/test-profiles/ios-gen-sRGB-IEC61966.icc

=======================================================================
EXTERNAL FILE METADATA
=======================================================================

  [file]
      Microsoft color profile 2.1, type Lino, RGB/XYZ-mntr device, IEC/sRGB model by HP, 3144 bytes, 9-2-1998 6:49:00 "sRGB IEC61966-2.1"

  [exiftool]
      ExifTool Version Number         : 12.76
      File Name                       : ios-gen-sRGB-IEC61966.icc
      Directory                       : /home/h02332/po/research/test-profiles
      File Size                       : 3.1 kB
      File Modification Date/Time     : 2026:03:08 15:58:00-04:00
      File Access Date/Time           : 2026:03:08 15:58:07-04:00
      File Inode Change Date/Time     : 2026:03:08 15:58:00-04:00
      File Permissions                : -rw-r--r--
      File Type                       : ICC
      File Type Extension             : icc
      MIME Type                       : application/vnd.iccprofile
      Profile CMM Type                : Linotronic
      Profile Version                 : 2.1.0
      Profile Class                   : Display Device Profile
      Color Space Data                : RGB
      Profile Connection Space        : XYZ
      Profile Date Time               : 1998:02:09 06:49:00
      Profile File Signature          : acsp
      Primary Platform                : Microsoft Corporation
      CMM Flags                       : Not Embedded, Independent
      Device Manufacturer             : Hewlett-Packard
      Device Model                    : sRGB
      Device Attributes               : Reflective, Glossy, Positive, Color
      Rendering Intent                : Perceptual
      Connection Space Illuminant     : 0.9642 1 0.82491
      Profile Creator                 : Hewlett-Packard
      Profile ID                      : 0
      Profile Copyright               : Copyright (c) 1998 Hewlett-Packard Company
      Profile Description             : sRGB IEC61966-2.1
      Media White Point               : 0.95045 1 1.08905

  [identify]
      Image:
        Filename: /home/h02332/po/research/test-profiles/ios-gen-sRGB-IEC61966.icc
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
      00000000: 0000 0c48 4c69 6e6f 0210 0000 6d6e 7472  ...HLino....mntr
      00000010: 5247 4220 5859 5a20 07ce 0002 0009 0006  RGB XYZ ........
     ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:344] IsValidTechnologySignature(): input = 0x43525420
 00000020: 0031 0000 6163 7370 4d53 4654 0000 0000  .1..acspMSFT....
      00000030: 4945 4320 7352 4742 0000 0000 0000 0000  IEC sRGB........
      00000040: 0000 0000 0000 f6d6 0001 0000 0000 d32d  ...............-
      00000050: 4850 2020 0000 0000 0000 0000 0000 0000  HP  ............
      00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
      00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................

  [sha256sum]
      2b3aa1645779a9e634744faf9b01e9102b0c9b88fd6deced7934df86b949af7e  /home/h02332/po/research/test-profiles/ios-gen-sRGB-IEC61966.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 3144 bytes (0x00000C48)  [actual file: 3144 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x52474220 (RGB)
     [OK] Valid colorSpace: RgbData

[H4] PCS ColorSpace: 0x58595A20 (XYZ)
     [OK] Valid PCS: XYZData

[H5] Platform: 0x4D534654 (MSFT)
     [OK] Known platform code

[H6] Rendering Intent: 0 (0x00000000)
     [OK] Valid intent: Perceptual

[H7] Profile Class: 0x6D6E7472 (mntr)
     [OK] Known class: DisplayClass

[H8] Illuminant XYZ: (0.964203, 1.000000, 0.824905)
     [OK] PCS illuminant matches D50 (within s15Fixed16 tolerance)

[H15] Date Validation (§4.2 dateTimeNumber): 1998-02-09 06:49:00
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
     Manufacturer: Present [OK]
     Device Model: Present [OK]

[H10] Tag Count: 17
      [OK] Tag count within normal range

[H11] CLUT Entry Limit Check
      Max safe CLUT entries per tag: 16777216 (16M)
      [OK] No CLUT tags to check

[H12] MPE Chain Depth Check
      Max MPE elements per chain: 1024
      [OK] No MPE tags to check

[H13] Per-Tag Size Check
      Max tag size: 64 MB (67108864 bytes)
      [OK] All 17 tags within size limits

[H14] TagArrayType Detection (UAF Risk)
      Checking for TagArrayType (0x74617279 = 'tary')
      Note: Tag signature ≠ tag type - must check tag DATA
      [OK] No TagArrayType tags detected

[H18] Technology Signature Validation
      [OK] Valid technology: CRTDisplay

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
      [WARN]  Matrix column sum (0.9643, 1.0000, 0.8251) deviates from D50
       Expected ≈ (0.9505, 1.0000, 1.0890), deviation (0.0138, 0.0000, 0.2639)

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
      Profile size: 3144 bytes, tag count: 17
      [OK] Tag size vs profile size consistent

[H103] Profile Connection Conditions (PCC)
      [INFO] No spectral viewing conditions tag (svcn)
      Standard PCC: yes (D50/2deg)
      Illuminant: 0x00000001, CCT: 5000.0, Observer: 0x00000001

[H104] PRMG Gamut Evaluation
      [INFO] No rendering intent gamut tags
      PRMG boundary: 12/12 test points in gamut

[H105] Matrix-TRC Validation
      Matrix:
        [ 0.43607   0.38515   0.14307]
        [ 0.22249   0.71687   0.06061]
        [ 0.01392   0.09708   0.71410]
      Determinant: 0.161460
      [OK] Matrix is invertible (det=0.161460)
      Row sums (≈D50 XYZ): [0.9643, 1.0000, 0.8251]
      [OK] Matrix × Inverse = Identity

[H106] Environment Variable Tags
      [INFO] No environment variable or PCC transform tags

[H107] LUT Channel vs Colorspace Cross-Check
      Declared data colorspace channels: 3
      Declared PCS channels: 3
      [OK] All LUT channel counts match declared colorspace/PCS

[H108] Private Tag Identification
      [OK] All tags are registered ICC signatures

[H109] NOP Sled / Shellcode Pattern Scan
      [OK] No shellcode or executable patterns detected

[H110] Profile-Class Required Tag Validation
      Profile class: Display (mntr)
      [OK] Using Matrix/TRC instead of AToB0
      [WARN]  wtpt ≠ D50 but 'chad' tag missing (ICC.1-2022-05 Annex G)
       CWE-20: chromaticAdaptationTag required when adopted white ≠ D50

[H111] Reserved Byte Validation
      [OK] All reserved header bytes are zero

[H112] Wtpt Profile-Class Validation
      wtpt: X=0.950455 Y=1.000000 Z=1.089050
      [OK] wtpt is physically plausible

[H113] Round-Trip Fidelity Assessment
      [OK] Round-trip tag geometry is consistent

[H114] TRC Curve Smoothness and Monotonicity
      rTRC: 1024 entries [OK]
      gTRC: 1024 entries [OK]
      bTRC: 1024 entries [OK]

[H115] Characterization Data Presence
      [INFO] No characterization data (targ) tag present

[H116] cprt/desc Encoding vs Profile Version
      Profile version: 2.1.0
      cprt: type='text' (0x74657874)
      [OK] cprt uses acceptable type for v2
      desc: type='desc' (0x64657363)
      [OK] desc uses acceptable type for v2

[H117] Tag Type Allowed Per Signature
      [OK] 16 tags checked — all use allowed types

[H118] Calculator Computation Cost Estimate
      [INFO] No MPE calculator/CLUT elements found

[H119] Round-Trip ΔE Measurement
      [INFO] No AToB/BToA CLUT pairs available for ΔE measurement

[H120] Curve Invertibility Assessment
      rTRC (1024 entries): inv avg err=0.188974  max err=0.287135
      [WARN]  rTRC: poor invertibility (max err > 1%)
      gTRC (1024 entries): inv avg err=0.188974  max err=0.287135
      [WARN]  gTRC: poor invertibility (max err > 1%)
      bTRC (1024 entries): inv avg err=0.188974  max err=0.287135
      [WARN]  bTRC: poor invertibility (max err > 1%)

[H121] Characterization Data Round-Trip Capability
      [INFO] No characterization data (targ) tag — cannot assess

[H122] Tag Type Encoding Validation
      [WARN]  'lumi': XYZ(76.0365, 80.0000, 87.1246) out of expected range [-5,10]
       CWE-20: Value out of specification range

[H123] Non-Required Tag Classification
      [OK] All tags are required or optional for this profile class

[H124] Version-Tag Correspondence
      [OK] Tags correspond to profile version 2

[H125] Overall Transform Smoothness
      [INFO] No suitable LUT tags for smoothness measurement

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
      [OK] All 17 tags are 4-byte aligned

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
      [OK] All 17 tag types have zeroed reserved bytes

[H135] Duplicate Tag Signatures (ICC.1-2022-05 §7.3.1)
      [OK] All 17 tag signatures are unique

[H137] High-Dimensional Color Space Grid Complexity (CWE-400)
      [OK] Color space dimensionality within safe bounds

[H138] Calculator Element Branching Depth (CWE-400/CWE-674)
      [INFO] No calculator elements found

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
      [INFO]  Tags 'rTRC' and 'gTRC' share data at offset 0x43C (2060 bytes)
      [INFO]  Tags 'rTRC' and 'bTRC' share data at offset 0x43C (2060 bytes)
      [INFO]  Tags 'gTRC' and 'bTRC' share data at offset 0x43C (2060 bytes)
      [OK] 3 shared tag pair(s) — all immutable types (safe)
      [OK] No risky shared tag data aliasing

[H40] Tag Alignment & Padding Validation
      [OK] All tags properly aligned with zero padding

[H41] Version/Type Consistency Check
      Profile version: 2.1.0
      [OK] All tags/types consistent with declared version

[H42] Matrix Singularity Detection
      Matrix determinant: 0.16145967
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

[H136] ResponseCurve Per-Channel Measurement Count (CWE-400)
      [OK] ResponseCurve measurement counts within bounds (or tag absent)

HEURISTIC SUMMARY
=======================================================================

[WARN]  6 HEURISTIC WARNING(S) DETECTED

  This profile exhibits patterns associated with:
  - Malformed/corrupted data
  - Resource exhaustion attempts
  - Enum confusion vulnerabilities
  - Parser exploitation attempts
  - Type confusion / buffer overflow patterns

  - Sub-element offset OOB (mBA/mAB SIGBUS pattern)
  - 32-bit integer overflow in bounds checks
  - Suspicious fill patterns enabling OOB traversal

  CVE Coverage: 141 heuristics (H1-H138 ICC profile + H139-H141 TIFF image) covering patterns from 48 CVEs across 77 iccDEV security advisories (39 heuristics with CVE cross-references)
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

  Recommendations:
  • Validate profile with official ICC tools
  • Use -n (ninja mode) for detailed byte-level analysis
  • Do NOT use in production color workflows
  • Consider as potential security test case


=======================================================================
PHASE 2: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/ios-gen-sRGB-IEC61966.icc

Device Class: 0x6D6E7472

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [ ] [ ]  
  AToB1/BToA1 (Rel. Colorimetric): [ ] [ ]  
  AToB2/BToA2 (Saturation):        [ ] [ ]  

  DToB0/BToD0 (Perceptual):        [ ] [ ]  
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]  
  DToB2/BToD2 (Saturation):        [ ] [ ]  

  Matrix/TRC Tags:                 [[X]]  [X] Round-trip capable

[OK] RESULT: Profile supports round-trip validation

Result: Round-trip capable [OK]

=======================================================================
PHASE 3: SIGNATURE ANALYSIS
=======================================================================


=== Signature Analysis ===

Header Signatures:
  Device Class:    0x6D6E7472  ''  DisplayClass
  Color Space:     0x52474220  'RGB'  RgbData
  PCS:             0x58595A20  'XYZ'  XYZData
  Manufacturer:    0x49454320  'IEC'
  Model:           0x73524742  'sRGB'

Tag Signatures:
Idx  Tag          FourCC     Type         Issues
---  ------------ ---------- ------------ ------
0    copyrightTag 'cprt    '  textType    
1    profileDescriptionTag 'desc    '  textDescriptionType
2    mediaWhitePointTag 'wtpt    '  XYZArrayType
3    mediaBlackPointTag 'bkpt    '  XYZArrayType
4    redColorantTag 'rXYZ    '  XYZArrayType
5    greenColorantTag 'gXYZ    '  XYZArrayType
6    blueColorantTag 'bXYZ    '  XYZArrayType
7    deviceMfgDescTag 'dmnd    '  textDescriptionType
8    deviceModelDescTag 'dmdd    '  textDescriptionType
9    viewingCondDescTag 'vued    '  textDescriptionType
10   viewingConditionsTag 'view    '  viewingConditionsType
11   luminanceTag 'lumi    '  XYZArrayType
12   measurementTag 'meas    '  measurementType
13   technologyTag 'tech    '  signatureType
14   redTRCTag    'rTRC    '  curveType   
15   greenTRCTag  'gTRC    '  curveType   
16   blueTRCTag   'bTRC    '  curveType   

Summary: 0 signature issue(s) detected

=======================================================================
PHASE 4: PROFILE STRUCTURE DUMP
=======================================================================

=== ICC Profile Header ===

=== ICC Profile Header (0x0000-0x007F) ===
0x0000: 00 00 0C 48 4C 69 6E 6F  02 10 00 00 6D 6E 74 72  |...HLino....mntr|
0x0010: 52 47 42 20 58 59 5A 20  07 CE 00 02 00 09 00 06  |RGB XYZ ........|
0x0020: 00 31 00 00 61 63 73 70  4D 53 46 54 00 00 00 00  |.1..acspMSFT....|
0x0030: 49 45 43 20 73 52 47 42  00 00 00 00 00 00 00 00  |IEC sRGB........|
0x0040: 00 00 00 00 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 48 50 20 20 00 00 00 00  00 00 00 00 00 00 00 00  |HP  ............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields:
  Size:            0x00000C48 (3144 bytes)
  CMM:             Lino
  Version:         0x02100000
  Device Class:    DisplayClass
  Color Space:     RgbData
  PCS:             XYZData

=== Tag Table ===

=== Tag Table ===
Tag Count: 17

Tag Table Raw Data (0x0080-0x0150):
0x0080: 00 00 00 11 63 70 72 74  00 00 01 50 00 00 00 33  |....cprt...P...3|
0x0090: 64 65 73 63 00 00 01 84  00 00 00 6C 77 74 70 74  |desc.......lwtpt|
0x00A0: 00 00 01 F0 00 00 00 14  62 6B 70 74 00 00 02 04  |........bkpt....|
0x00B0: 00 00 00 14 72 58 59 5A  00 00 02 18 00 00 00 14  |....rXYZ........|
0x00C0: 67 58 59 5A 00 00 02 2C  00 00 00 14 62 58 59 5A  |gXYZ...,....bXYZ|
0x00D0: 00 00 02 40 00 00 00 14  64 6D 6E 64 00 00 02 54  |...@....dmnd...T|
0x00E0: 00 00 00 70 64 6D 64 64  00 00 02 C4 00 00 00 88  |...pdmdd........|
0x00F0: 76 75 65 64 00 00 03 4C  00 00 00 86 76 69 65 77  |vued...L....view|
0x0100: 00 00 03 D4 00 00 00 24  6C 75 6D 69 00 00 03 F8  |.......$lumi....|
0x0110: 00 00 00 14 6D 65 61 73  00 00 04 0C 00 00 00 24  |....meas.......$|
0x0120: 74 65 63 68 00 00 04 30  00 00 00 0C 72 54 52 43  |tech...0....rTRC|
0x0130: 00 00 04 3C 00 00 08 0C  67 54 52 43 00 00 04 3C  |...<....gTRC...<|
0x0140: 00 00 08 0C 62 54 52 43  00 00 04 3C 00 00 08 0C  |....bTRC...<....|

Tag Entries:
Idx  Signature    FourCC       Offset     Size
---  ------------ ------------ ---------- ----
0    copyrightTag 'cprt      '  0x00000150  51
1    profileDescriptionTag 'desc      '  0x00000184  108
2    mediaWhitePointTag 'wtpt      '  0x000001F0  20
3    mediaBlackPointTag 'bkpt      '  0x00000204  20
4    redColorantTag 'rXYZ      '  0x00000218  20
5    greenColorantTag 'gXYZ      '  0x0000022C  20
6    blueColorantTag 'bXYZ      '  0x00000240  20
7    deviceMfgDescTag 'dmnd      '  0x00000254  112
8    deviceModelDescTag 'dmdd      '  0x000002C4  136
9    viewingCondDescTag 'vued      '  0x0000034C  134
10   viewingConditionsTag 'view      '  0x000003D4  36
11   luminanceTag 'lumi      '  0x000003F8  20
12   measurementTag 'meas      '  0x0000040C  36
13   technologyTag 'tech      '  0x00000430  12
14   redTRCTag    'rTRC      '  0x0000043C  2060
15   greenTRCTag  'gTRC      '  0x0000043C  2060
16   blueTRCTag   'bTRC      '  0x0000043C  2060

=======================================================================
PHASE 5: TAG CONTENT ANALYSIS
=======================================================================

--- 5A: LUT Tag Geometry ---

  No legacy LUT tags (A2B/B2A/D2B/B2D) found

--- 5B: MPE Element Chains ---

  No MPE tags found

--- 5C: TRC Curve Analysis ---

  [rTRC] Tabulated curve, 1024 entries
      Values: [0]=0.000000  [512]=0.214496  [1023]=1.000000
  [gTRC] Tabulated curve, 1024 entries
      Values: [0]=0.000000  [512]=0.214496  [1023]=1.000000
  [bTRC] Tabulated curve, 1024 entries
      Values: [0]=0.000000  [512]=0.214496  [1023]=1.000000

--- 5D: NamedColor2 Validation ---

  No NamedColor2 tag

--- 5E: XYZ Tag Values ---

  [rXYZ] X=0.4361 Y=0.2225 Z=0.0139
  [gXYZ] X=0.3851 Y=0.7169 Z=0.0971
  [bXYZ] X=0.1431 Y=0.0606 Z=0.7141
  [wtpt] X=0.9505 Y=1.0000 Z=1.0891

--- 5F: ICC v5 Spectral Data ---

  No ICC v5 spectral tags

--- 5G: Profile ID Verification ---

  Profile ID: not set (all zeros)
      INFO: Profile integrity cannot be verified without ID

--- 5H: Per-Tag Size Analysis ---

  Tag sizes (flagging >10MB):
      [OK] All tags within 10MB limit


=======================================================================
COMPREHENSIVE ANALYSIS SUMMARY
=======================================================================

File: /home/h02332/po/research/test-profiles/ios-gen-sRGB-IEC61966.icc
Total Issues Detected: 6

[WARN] ANALYSIS COMPLETE - 6 issue(s) detected
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

File: /home/h02332/po/research/test-profiles/ios-gen-sRGB-IEC61966.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 3144 bytes (0xC48)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 0C 48 4C 69 6E 6F  02 10 00 00 6D 6E 74 72  |...HLino....mntr|
0x0010: 52 47 42 20 58 59 5A 20  07 CE 00 02 00 09 00 06  |RGB XYZ ........|
0x0020: 00 31 00 00 61 63 73 70  4D 53 46 54 00 00 00 00  |.1..acspMSFT....|
0x0030: 49 45 43 20 73 52 47 42  00 00 00 00 00 00 00 00  |IEC sRGB........|
0x0040: 00 00 00 00 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 48 50 20 20 00 00 00 00  00 00 00 00 00 00 00 00  |HP  ............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x00000C48 (3144 bytes) OK
  CMM:             0x4C696E6F  'Lino'
  Version:         0x02100000
  Device Class:    0x6D6E7472  'mntr'
  Color Space:     0x52474220  'RGB '
  PCS:             0x58595A20  'XYZ '

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 17 (0x00000011)

Tag Table Raw Data:
0x0080: 00 00 00 11 63 70 72 74  00 00 01 50 00 00 00 33  |....cprt...P...3|
0x0090: 64 65 73 63 00 00 01 84  00 00 00 6C 77 74 70 74  |desc.......lwtpt|
0x00A0: 00 00 01 F0 00 00 00 14  62 6B 70 74 00 00 02 04  |........bkpt....|
0x00B0: 00 00 00 14 72 58 59 5A  00 00 02 18 00 00 00 14  |....rXYZ........|
0x00C0: 67 58 59 5A 00 00 02 2C  00 00 00 14 62 58 59 5A  |gXYZ...,....bXYZ|
0x00D0: 00 00 02 40 00 00 00 14  64 6D 6E 64 00 00 02 54  |...@....dmnd...T|
0x00E0: 00 00 00 70 64 6D 64 64  00 00 02 C4 00 00 00 88  |...pdmdd........|
0x00F0: 76 75 65 64 00 00 03 4C  00 00 00 86 76 69 65 77  |vued...L....view|
0x0100: 00 00 03 D4 00 00 00 24  6C 75 6D 69 00 00 03 F8  |.......$lumi....|
0x0110: 00 00 00 14 6D 65 61 73  00 00 04 0C 00 00 00 24  |....meas.......$|
0x0120: 74 65 63 68 00 00 04 30  00 00 00 0C 72 54 52 43  |tech...0....rTRC|
0x0130: 00 00 04 3C 00 00 08 0C  67 54 52 43 00 00 04 3C  |...<....gTRC...<|
0x0140: 00 00 08 0C 62 54 52 43  00 00 04 3C 00 00 08 0C  |....bTRC...<....|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x63707274   'cprt'        0x00000150   0x00000033   'text'        OK
1    0x64657363   'desc'        0x00000184   0x0000006C   'desc'        OK
2    0x77747074   'wtpt'        0x000001F0   0x00000014   'XYZ '        OK
3    0x626B7074   'bkpt'        0x00000204   0x00000014   'XYZ '        OK
4    0x7258595A   'rXYZ'        0x00000218   0x00000014   'XYZ '        OK
5    0x6758595A   'gXYZ'        0x0000022C   0x00000014   'XYZ '        OK
6    0x6258595A   'bXYZ'        0x00000240   0x00000014   'XYZ '        OK
7    0x646D6E64   'dmnd'        0x00000254   0x00000070   'desc'        OK
8    0x646D6464   'dmdd'        0x000002C4   0x00000088   'desc'        OK
9    0x76756564   'vued'        0x0000034C   0x00000086   'desc'        OK
10   0x76696577   'view'        0x000003D4   0x00000024   'view'        OK
11   0x6C756D69   'lumi'        0x000003F8   0x00000014   'XYZ '        OK
12   0x6D656173   'meas'        0x0000040C   0x00000024   'meas'        OK
13   0x74656368   'tech'        0x00000430   0x0000000C   'sig '        OK
14   0x72545243   'rTRC'        0x0000043C   0x0000080C   'curv'        OK
15   0x67545243   'gTRC'        0x0000043C   0x0000080C   'curv'        OK
16   0x62545243   'bTRC'        0x0000043C   0x0000080C   'curv'        OK

=== FULL FILE HEX DUMP (all 3144 bytes) ===
0x0000: 00 00 0C 48 4C 69 6E 6F  02 10 00 00 6D 6E 74 72  |...HLino....mntr|
0x0010: 52 47 42 20 58 59 5A 20  07 CE 00 02 00 09 00 06  |RGB XYZ ........|
0x0020: 00 31 00 00 61 63 73 70  4D 53 46 54 00 00 00 00  |.1..acspMSFT....|
0x0030: 49 45 43 20 73 52 47 42  00 00 00 00 00 00 00 00  |IEC sRGB........|
0x0040: 00 00 00 00 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 48 50 20 20 00 00 00 00  00 00 00 00 00 00 00 00  |HP  ............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0080: 00 00 00 11 63 70 72 74  00 00 01 50 00 00 00 33  |....cprt...P...3|
0x0090: 64 65 73 63 00 00 01 84  00 00 00 6C 77 74 70 74  |desc.......lwtpt|
0x00A0: 00 00 01 F0 00 00 00 14  62 6B 70 74 00 00 02 04  |........bkpt....|
0x00B0: 00 00 00 14 72 58 59 5A  00 00 02 18 00 00 00 14  |....rXYZ........|
0x00C0: 67 58 59 5A 00 00 02 2C  00 00 00 14 62 58 59 5A  |gXYZ...,....bXYZ|
0x00D0: 00 00 02 40 00 00 00 14  64 6D 6E 64 00 00 02 54  |...@....dmnd...T|
0x00E0: 00 00 00 70 64 6D 64 64  00 00 02 C4 00 00 00 88  |...pdmdd........|
0x00F0: 76 75 65 64 00 00 03 4C  00 00 00 86 76 69 65 77  |vued...L....view|
0x0100: 00 00 03 D4 00 00 00 24  6C 75 6D 69 00 00 03 F8  |.......$lumi....|
0x0110: 00 00 00 14 6D 65 61 73  00 00 04 0C 00 00 00 24  |....meas.......$|
0x0120: 74 65 63 68 00 00 04 30  00 00 00 0C 72 54 52 43  |tech...0....rTRC|
0x0130: 00 00 04 3C 00 00 08 0C  67 54 52 43 00 00 04 3C  |...<....gTRC...<|
0x0140: 00 00 08 0C 62 54 52 43  00 00 04 3C 00 00 08 0C  |....bTRC...<....|
0x0150: 74 65 78 74 00 00 00 00  43 6F 70 79 72 69 67 68  |text....Copyrigh|
0x0160: 74 20 28 63 29 20 31 39  39 38 20 48 65 77 6C 65  |t (c) 1998 Hewle|
0x0170: 74 74 2D 50 61 63 6B 61  72 64 20 43 6F 6D 70 61  |tt-Packard Compa|
0x0180: 6E 79 00 00 64 65 73 63  00 00 00 00 00 00 00 12  |ny..desc........|
0x0190: 73 52 47 42 20 49 45 43  36 31 39 36 36 2D 32 2E  |sRGB IEC61966-2.|
0x01A0: 31 00 00 00 00 00 00 00  00 00 00 00 12 73 52 47  |1............sRG|
0x01B0: 42 20 49 45 43 36 31 39  36 36 2D 32 2E 31 00 00  |B IEC61966-2.1..|
0x01C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x01D0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x01E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x01F0: 58 59 5A 20 00 00 00 00  00 00 F3 51 00 01 00 00  |XYZ .......Q....|
0x0200: 00 01 16 CC 58 59 5A 20  00 00 00 00 00 00 00 00  |....XYZ ........|
0x0210: 00 00 00 00 00 00 00 00  58 59 5A 20 00 00 00 00  |........XYZ ....|
0x0220: 00 00 6F A2 00 00 38 F5  00 00 03 90 58 59 5A 20  |..o...8.....XYZ |
0x0230: 00 00 00 00 00 00 62 99  00 00 B7 85 00 00 18 DA  |......b.........|
0x0240: 58 59 5A 20 00 00 00 00  00 00 24 A0 00 00 0F 84  |XYZ ......$.....|
0x0250: 00 00 B6 CF 64 65 73 63  00 00 00 00 00 00 00 16  |....desc........|
0x0260: 49 45 43 20 68 74 74 70  3A 2F 2F 77 77 77 2E 69  |IEC http://www.i|
0x0270: 65 63 2E 63 68 00 00 00  00 00 00 00 00 00 00 00  |ec.ch...........|
0x0280: 16 49 45 43 20 68 74 74  70 3A 2F 2F 77 77 77 2E  |.IEC http://www.|
0x0290: 69 65 63 2E 63 68 00 00  00 00 00 00 00 00 00 00  |iec.ch..........|
0x02A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x02B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x02C0: 00 00 00 00 64 65 73 63  00 00 00 00 00 00 00 2E  |....desc........|
0x02D0: 49 45 43 20 36 31 39 36  36 2D 32 2E 31 20 44 65  |IEC 61966-2.1 De|
0x02E0: 66 61 75 6C 74 20 52 47  42 20 63 6F 6C 6F 75 72  |fault RGB colour|
0x02F0: 20 73 70 61 63 65 20 2D  20 73 52 47 42 00 00 00  | space - sRGB...|
0x0300: 00 00 00 00 00 00 00 00  2E 49 45 43 20 36 31 39  |.........IEC 619|
0x0310: 36 36 2D 32 2E 31 20 44  65 66 61 75 6C 74 20 52  |66-2.1 Default R|
0x0320: 47 42 20 63 6F 6C 6F 75  72 20 73 70 61 63 65 20  |GB colour space |
0x0330: 2D 20 73 52 47 42 00 00  00 00 00 00 00 00 00 00  |- sRGB..........|
0x0340: 00 00 00 00 00 00 00 00  00 00 00 00 64 65 73 63  |............desc|
0x0350: 00 00 00 00 00 00 00 2C  52 65 66 65 72 65 6E 63  |.......,Referenc|
0x0360: 65 20 56 69 65 77 69 6E  67 20 43 6F 6E 64 69 74  |e Viewing Condit|
0x0370: 69 6F 6E 20 69 6E 20 49  45 43 36 31 39 36 36 2D  |ion in IEC61966-|
0x0380: 32 2E 31 00 00 00 00 00  00 00 00 00 00 00 2C 52  |2.1...........,R|
0x0390: 65 66 65 72 65 6E 63 65  20 56 69 65 77 69 6E 67  |eference Viewing|
0x03A0: 20 43 6F 6E 64 69 74 69  6F 6E 20 69 6E 20 49 45  | Condition in IE|
0x03B0: 43 36 31 39 36 36 2D 32  2E 31 00 00 00 00 00 00  |C61966-2.1......|
0x03C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x03D0: 00 00 00 00 76 69 65 77  00 00 00 00 00 13 A4 FE  |....view........|
0x03E0: 00 14 5F 2E 00 10 CF 14  00 03 ED CC 00 04 13 0B  |.._.............|
0x03F0: 00 03 5C 9E 00 00 00 01  58 59 5A 20 00 00 00 00  |..\.....XYZ ....|
0x0400: 00 4C 09 56 00 50 00 00  00 57 1F E7 6D 65 61 73  |.L.V.P...W..meas|
0x0410: 00 00 00 00 00 00 00 01  00 00 00 00 00 00 00 00  |................|
0x0420: 00 00 00 00 00 00 00 00  00 00 02 8F 00 00 00 02  |................|
0x0430: 73 69 67 20 00 00 00 00  43 52 54 20 63 75 72 76  |sig ....CRT curv|
0x0440: 00 00 00 00 00 00 04 00  00 00 00 05 00 0A 00 0F  |................|
0x0450: 00 14 00 19 00 1E 00 23  00 28 00 2D 00 32 00 37  |.......#.(.-.2.7|
0x0460: 00 3B 00 40 00 45 00 4A  00 4F 00 54 00 59 00 5E  |.;.@.E.J.O.T.Y.^|
0x0470: 00 63 00 68 00 6D 00 72  00 77 00 7C 00 81 00 86  |.c.h.m.r.w.|....|
0x0480: 00 8B 00 90 00 95 00 9A  00 9F 00 A4 00 A9 00 AE  |................|
0x0490: 00 B2 00 B7 00 BC 00 C1  00 C6 00 CB 00 D0 00 D5  |................|
0x04A0: 00 DB 00 E0 00 E5 00 EB  00 F0 00 F6 00 FB 01 01  |................|
0x04B0: 01 07 01 0D 01 13 01 19  01 1F 01 25 01 2B 01 32  |...........%.+.2|
0x04C0: 01 38 01 3E 01 45 01 4C  01 52 01 59 01 60 01 67  |.8.>.E.L.R.Y.`.g|
0x04D0: 01 6E 01 75 01 7C 01 83  01 8B 01 92 01 9A 01 A1  |.n.u.|..........|
0x04E0: 01 A9 01 B1 01 B9 01 C1  01 C9 01 D1 01 D9 01 E1  |................|
0x04F0: 01 E9 01 F2 01 FA 02 03  02 0C 02 14 02 1D 02 26  |...............&|
0x0500: 02 2F 02 38 02 41 02 4B  02 54 02 5D 02 67 02 71  |./.8.A.K.T.].g.q|
0x0510: 02 7A 02 84 02 8E 02 98  02 A2 02 AC 02 B6 02 C1  |.z..............|
0x0520: 02 CB 02 D5 02 E0 02 EB  02 F5 03 00 03 0B 03 16  |................|
0x0530: 03 21 03 2D 03 38 03 43  03 4F 03 5A 03 66 03 72  |.!.-.8.C.O.Z.f.r|
0x0540: 03 7E 03 8A 03 96 03 A2  03 AE 03 BA 03 C7 03 D3  |.~..............|
0x0550: 03 E0 03 EC 03 F9 04 06  04 13 04 20 04 2D 04 3B  |........... .-.;|
0x0560: 04 48 04 55 04 63 04 71  04 7E 04 8C 04 9A 04 A8  |.H.U.c.q.~......|
0x0570: 04 B6 04 C4 04 D3 04 E1  04 F0 04 FE 05 0D 05 1C  |................|
0x0580: 05 2B 05 3A 05 49 05 58  05 67 05 77 05 86 05 96  |.+.:.I.X.g.w....|
0x0590: 05 A6 05 B5 05 C5 05 D5  05 E5 05 F6 06 06 06 16  |................|
0x05A0: 06 27 06 37 06 48 06 59  06 6A 06 7B 06 8C 06 9D  |.'.7.H.Y.j.{....|
0x05B0: 06 AF 06 C0 06 D1 06 E3  06 F5 07 07 07 19 07 2B  |...............+|
0x05C0: 07 3D 07 4F 07 61 07 74  07 86 07 99 07 AC 07 BF  |.=.O.a.t........|
0x05D0: 07 D2 07 E5 07 F8 08 0B  08 1F 08 32 08 46 08 5A  |...........2.F.Z|
0x05E0: 08 6E 08 82 08 96 08 AA  08 BE 08 D2 08 E7 08 FB  |.n..............|
0x05F0: 09 10 09 25 09 3A 09 4F  09 64 09 79 09 8F 09 A4  |...%.:.O.d.y....|
0x0600: 09 BA 09 CF 09 E5 09 FB  0A 11 0A 27 0A 3D 0A 54  |...........'.=.T|
0x0610: 0A 6A 0A 81 0A 98 0A AE  0A C5 0A DC 0A F3 0B 0B  |.j..............|
0x0620: 0B 22 0B 39 0B 51 0B 69  0B 80 0B 98 0B B0 0B C8  |.".9.Q.i........|
0x0630: 0B E1 0B F9 0C 12 0C 2A  0C 43 0C 5C 0C 75 0C 8E  |.......*.C.\.u..|
0x0640: 0C A7 0C C0 0C D9 0C F3  0D 0D 0D 26 0D 40 0D 5A  |...........&.@.Z|
0x0650: 0D 74 0D 8E 0D A9 0D C3  0D DE 0D F8 0E 13 0E 2E  |.t..............|
0x0660: 0E 49 0E 64 0E 7F 0E 9B  0E B6 0E D2 0E EE 0F 09  |.I.d............|
0x0670: 0F 25 0F 41 0F 5E 0F 7A  0F 96 0F B3 0F CF 0F EC  |.%.A.^.z........|
0x0680: 10 09 10 26 10 43 10 61  10 7E 10 9B 10 B9 10 D7  |...&.C.a.~......|
0x0690: 10 F5 11 13 11 31 11 4F  11 6D 11 8C 11 AA 11 C9  |.....1.O.m......|
0x06A0: 11 E8 12 07 12 26 12 45  12 64 12 84 12 A3 12 C3  |.....&.E.d......|
0x06B0: 12 E3 13 03 13 23 13 43  13 63 13 83 13 A4 13 C5  |.....#.C.c......|
0x06C0: 13 E5 14 06 14 27 14 49  14 6A 14 8B 14 AD 14 CE  |.....'.I.j......|
0x06D0: 14 F0 15 12 15 34 15 56  15 78 15 9B 15 BD 15 E0  |.....4.V.x......|
0x06E0: 16 03 16 26 16 49 16 6C  16 8F 16 B2 16 D6 16 FA  |...&.I.l........|
0x06F0: 17 1D 17 41 17 65 17 89  17 AE 17 D2 17 F7 18 1B  |...A.e..........|
0x0700: 18 40 18 65 18 8A 18 AF  18 D5 18 FA 19 20 19 45  |.@.e......... .E|
0x0710: 19 6B 19 91 19 B7 19 DD  1A 04 1A 2A 1A 51 1A 77  |.k.........*.Q.w|
0x0720: 1A 9E 1A C5 1A EC 1B 14  1B 3B 1B 63 1B 8A 1B B2  |.........;.c....|
0x0730: 1B DA 1C 02 1C 2A 1C 52  1C 7B 1C A3 1C CC 1C F5  |.....*.R.{......|
0x0740: 1D 1E 1D 47 1D 70 1D 99  1D C3 1D EC 1E 16 1E 40  |...G.p.........@|
0x0750: 1E 6A 1E 94 1E BE 1E E9  1F 13 1F 3E 1F 69 1F 94  |.j.........>.i..|
0x0760: 1F BF 1F EA 20 15 20 41  20 6C 20 98 20 C4 20 F0  |.... . A l . . .|
0x0770: 21 1C 21 48 21 75 21 A1  21 CE 21 FB 22 27 22 55  |!.!H!u!.!.!."'"U|
0x0780: 22 82 22 AF 22 DD 23 0A  23 38 23 66 23 94 23 C2  |".".".#.#8#f#.#.|
0x0790: 23 F0 24 1F 24 4D 24 7C  24 AB 24 DA 25 09 25 38  |#.$.$M$|$.$.%.%8|
0x07A0: 25 68 25 97 25 C7 25 F7  26 27 26 57 26 87 26 B7  |%h%.%.%.&'&W&.&.|
0x07B0: 26 E8 27 18 27 49 27 7A  27 AB 27 DC 28 0D 28 3F  |&.'.'I'z'.'.(.(?|
0x07C0: 28 71 28 A2 28 D4 29 06  29 38 29 6B 29 9D 29 D0  |(q(.(.).)8)k).).|
0x07D0: 2A 02 2A 35 2A 68 2A 9B  2A CF 2B 02 2B 36 2B 69  |*.*5*h*.*.+.+6+i|
0x07E0: 2B 9D 2B D1 2C 05 2C 39  2C 6E 2C A2 2C D7 2D 0C  |+.+.,.,9,n,.,.-.|
0x07F0: 2D 41 2D 76 2D AB 2D E1  2E 16 2E 4C 2E 82 2E B7  |-A-v-.-....L....|
0x0800: 2E EE 2F 24 2F 5A 2F 91  2F C7 2F FE 30 35 30 6C  |../$/Z/././.050l|
0x0810: 30 A4 30 DB 31 12 31 4A  31 82 31 BA 31 F2 32 2A  |0.0.1.1J1.1.1.2*|
0x0820: 32 63 32 9B 32 D4 33 0D  33 46 33 7F 33 B8 33 F1  |2c2.2.3.3F3.3.3.|
0x0830: 34 2B 34 65 34 9E 34 D8  35 13 35 4D 35 87 35 C2  |4+4e4.4.5.5M5.5.|
0x0840: 35 FD 36 37 36 72 36 AE  36 E9 37 24 37 60 37 9C  |5.676r6.6.7$7`7.|
0x0850: 37 D7 38 14 38 50 38 8C  38 C8 39 05 39 42 39 7F  |7.8.8P8.8.9.9B9.|
0x0860: 39 BC 39 F9 3A 36 3A 74  3A B2 3A EF 3B 2D 3B 6B  |9.9.:6:t:.:.;-;k|
0x0870: 3B AA 3B E8 3C 27 3C 65  3C A4 3C E3 3D 22 3D 61  |;.;.<'<e<.<.="=a|
0x0880: 3D A1 3D E0 3E 20 3E 60  3E A0 3E E0 3F 21 3F 61  |=.=.> >`>.>.?!?a|
0x0890: 3F A2 3F E2 40 23 40 64  40 A6 40 E7 41 29 41 6A  |?.?.@#@d@.@.A)Aj|
0x08A0: 41 AC 41 EE 42 30 42 72  42 B5 42 F7 43 3A 43 7D  |A.A.B0BrB.B.C:C}|
0x08B0: 43 C0 44 03 44 47 44 8A  44 CE 45 12 45 55 45 9A  |C.D.DGD.D.E.EUE.|
0x08C0: 45 DE 46 22 46 67 46 AB  46 F0 47 35 47 7B 47 C0  |E.F"FgF.F.G5G{G.|
0x08D0: 48 05 48 4B 48 91 48 D7  49 1D 49 63 49 A9 49 F0  |H.HKH.H.I.IcI.I.|
0x08E0: 4A 37 4A 7D 4A C4 4B 0C  4B 53 4B 9A 4B E2 4C 2A  |J7J}J.K.KSK.K.L*|
0x08F0: 4C 72 4C BA 4D 02 4D 4A  4D 93 4D DC 4E 25 4E 6E  |LrL.M.MJM.M.N%Nn|
0x0900: 4E B7 4F 00 4F 49 4F 93  4F DD 50 27 50 71 50 BB  |N.O.OIO.O.P'PqP.|
0x0910: 51 06 51 50 51 9B 51 E6  52 31 52 7C 52 C7 53 13  |Q.QPQ.Q.R1R|R.S.|
0x0920: 53 5F 53 AA 53 F6 54 42  54 8F 54 DB 55 28 55 75  |S_S.S.TBT.T.U(Uu|
0x0930: 55 C2 56 0F 56 5C 56 A9  56 F7 57 44 57 92 57 E0  |U.V.V\V.V.WDW.W.|
0x0940: 58 2F 58 7D 58 CB 59 1A  59 69 59 B8 5A 07 5A 56  |X/X}X.Y.YiY.Z.ZV|
0x0950: 5A A6 5A F5 5B 45 5B 95  5B E5 5C 35 5C 86 5C D6  |Z.Z.[E[.[.\5\.\.|
0x0960: 5D 27 5D 78 5D C9 5E 1A  5E 6C 5E BD 5F 0F 5F 61  |]']x].^.^l^._._a|
0x0970: 5F B3 60 05 60 57 60 AA  60 FC 61 4F 61 A2 61 F5  |_.`.`W`.`.aOa.a.|
0x0980: 62 49 62 9C 62 F0 63 43  63 97 63 EB 64 40 64 94  |bIb.b.cCc.c.d@d.|
0x0990: 64 E9 65 3D 65 92 65 E7  66 3D 66 92 66 E8 67 3D  |d.e=e.e.f=f.f.g=|
0x09A0: 67 93 67 E9 68 3F 68 96  68 EC 69 43 69 9A 69 F1  |g.g.h?h.h.iCi.i.|
0x09B0: 6A 48 6A 9F 6A F7 6B 4F  6B A7 6B FF 6C 57 6C AF  |jHj.j.kOk.k.lWl.|
0x09C0: 6D 08 6D 60 6D B9 6E 12  6E 6B 6E C4 6F 1E 6F 78  |m.m`m.n.nkn.o.ox|
0x09D0: 6F D1 70 2B 70 86 70 E0  71 3A 71 95 71 F0 72 4B  |o.p+p.p.q:q.q.rK|
0x09E0: 72 A6 73 01 73 5D 73 B8  74 14 74 70 74 CC 75 28  |r.s.s]s.t.tpt.u(|
0x09F0: 75 85 75 E1 76 3E 76 9B  76 F8 77 56 77 B3 78 11  |u.u.v>v.v.wVw.x.|
0x0A00: 78 6E 78 CC 79 2A 79 89  79 E7 7A 46 7A A5 7B 04  |xnx.y*y.y.zFz.{.|
0x0A10: 7B 63 7B C2 7C 21 7C 81  7C E1 7D 41 7D A1 7E 01  |{c{.|!|.|.}A}.~.|
0x0A20: 7E 62 7E C2 7F 23 7F 84  7F E5 80 47 80 A8 81 0A  |~b~..#.....G....|
0x0A30: 81 6B 81 CD 82 30 82 92  82 F4 83 57 83 BA 84 1D  |.k...0.....W....|
0x0A40: 84 80 84 E3 85 47 85 AB  86 0E 86 72 86 D7 87 3B  |.....G.....r...;|
0x0A50: 87 9F 88 04 88 69 88 CE  89 33 89 99 89 FE 8A 64  |.....i...3.....d|
0x0A60: 8A CA 8B 30 8B 96 8B FC  8C 63 8C CA 8D 31 8D 98  |...0.....c...1..|
0x0A70: 8D FF 8E 66 8E CE 8F 36  8F 9E 90 06 90 6E 90 D6  |...f...6.....n..|
0x0A80: 91 3F 91 A8 92 11 92 7A  92 E3 93 4D 93 B6 94 20  |.?.....z...M... |
0x0A90: 94 8A 94 F4 95 5F 95 C9  96 34 96 9F 97 0A 97 75  |....._...4.....u|
0x0AA0: 97 E0 98 4C 98 B8 99 24  99 90 99 FC 9A 68 9A D5  |...L...$.....h..|
0x0AB0: 9B 42 9B AF 9C 1C 9C 89  9C F7 9D 64 9D D2 9E 40  |.B.........d...@|
0x0AC0: 9E AE 9F 1D 9F 8B 9F FA  A0 69 A0 D8 A1 47 A1 B6  |.........i...G..|
0x0AD0: A2 26 A2 96 A3 06 A3 76  A3 E6 A4 56 A4 C7 A5 38  |.&.....v...V...8|
0x0AE0: A5 A9 A6 1A A6 8B A6 FD  A7 6E A7 E0 A8 52 A8 C4  |.........n...R..|
0x0AF0: A9 37 A9 A9 AA 1C AA 8F  AB 02 AB 75 AB E9 AC 5C  |.7.........u...\|
0x0B00: AC D0 AD 44 AD B8 AE 2D  AE A1 AF 16 AF 8B B0 00  |...D...-........|
0x0B10: B0 75 B0 EA B1 60 B1 D6  B2 4B B2 C2 B3 38 B3 AE  |.u...`...K...8..|
0x0B20: B4 25 B4 9C B5 13 B5 8A  B6 01 B6 79 B6 F0 B7 68  |.%.........y...h|
0x0B30: B7 E0 B8 59 B8 D1 B9 4A  B9 C2 BA 3B BA B5 BB 2E  |...Y...J...;....|
0x0B40: BB A7 BC 21 BC 9B BD 15  BD 8F BE 0A BE 84 BE FF  |...!............|
0x0B50: BF 7A BF F5 C0 70 C0 EC  C1 67 C1 E3 C2 5F C2 DB  |.z...p...g..._..|
0x0B60: C3 58 C3 D4 C4 51 C4 CE  C5 4B C5 C8 C6 46 C6 C3  |.X...Q...K...F..|
0x0B70: C7 41 C7 BF C8 3D C8 BC  C9 3A C9 B9 CA 38 CA B7  |.A...=...:...8..|
0x0B80: CB 36 CB B6 CC 35 CC B5  CD 35 CD B5 CE 36 CE B6  |.6...5...5...6..|
0x0B90: CF 37 CF B8 D0 39 D0 BA  D1 3C D1 BE D2 3F D2 C1  |.7...9...<...?..|
0x0BA0: D3 44 D3 C6 D4 49 D4 CB  D5 4E D5 D1 D6 55 D6 D8  |.D...I...N...U..|
0x0BB0: D7 5C D7 E0 D8 64 D8 E8  D9 6C D9 F1 DA 76 DA FB  |.\...d...l...v..|
0x0BC0: DB 80 DC 05 DC 8A DD 10  DD 96 DE 1C DE A2 DF 29  |...............)|
0x0BD0: DF AF E0 36 E0 BD E1 44  E1 CC E2 53 E2 DB E3 63  |...6...D...S...c|
0x0BE0: E3 EB E4 73 E4 FC E5 84  E6 0D E6 96 E7 1F E7 A9  |...s............|
0x0BF0: E8 32 E8 BC E9 46 E9 D0  EA 5B EA E5 EB 70 EB FB  |.2...F...[...p..|
0x0C00: EC 86 ED 11 ED 9C EE 28  EE B4 EF 40 EF CC F0 58  |.......(...@...X|
0x0C10: F0 E5 F1 72 F1 FF F2 8C  F3 19 F3 A7 F4 34 F4 C2  |...r.........4..|
0x0C20: F5 50 F5 DE F6 6D F6 FB  F7 8A F8 19 F8 A8 F9 38  |.P...m.........8|
0x0C30: F9 C7 FA 57 FA E7 FB 77  FC 07 FC 98 FD 29 FD BA  |...W...w.....)..|
0x0C40: FE 4B FE DC FF 6D FF FF                           |.K...m..|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 0**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/ios-gen-sRGB-IEC61966.icc

Device Class: 0x6D6E7472

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [ ] [ ]  
  AToB1/BToA1 (Rel. Colorimetric): [ ] [ ]  
  AToB2/BToA2 (Saturation):        [ ] [ ]  

  DToB0/BToD0 (Perceptual):        [ ] [ ]  
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]  
  DToB2/BToD2 (Saturation):        [ ] [ ]  

  Matrix/TRC Tags:                 [[X]]  [X] Round-trip capable

[OK] RESULT: Profile supports round-trip validation
```
