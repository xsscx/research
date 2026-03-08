# ICC Profile Analysis Report

**Profile**: `test-profiles/ios-gen-AdobeRGB1998.icc`
**File Size**: 560 bytes
**SHA-256**: `304f569a83c1e5eddaddac54e99ed03339333db013738bb499ab64f049887e28`
**File Type**: ColorSync color profile 2.1, type ADBE, RGB/XYZ-mntr device by ADBE, 560 bytes, 11-8-2000 19:51:59 "Adobe RGB (1998)"
**Date**: 2026-03-08T19:58:00Z
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

File: /home/h02332/po/research/test-profiles/ios-gen-AdobeRGB1998.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/h02332/po/research/test-profiles/ios-gen-AdobeRGB1998.icc

=======================================================================
EXTERNAL FILE METADATA
=======================================================================

  [file]
      ColorSync color profile 2.1, type ADBE, RGB/XYZ-mntr device by ADBE, 560 bytes, 11-8-2000 19:51:59 "Adobe RGB (1998)"

  [exiftool]
      ExifTool Version Number         : 12.76
      File Name                       : ios-gen-AdobeRGB1998.icc
      Directory                       : /home/h02332/po/research/test-profiles
      File Size                       : 560 bytes
      File Modification Date/Time     : 2026:03:08 15:58:00-04:00
      File Access Date/Time           : 2026:03:08 15:58:00-04:00
      File Inode Change Date/Time     : 2026:03:08 15:58:00-04:00
      File Permissions                : -rw-r--r--
      File Type                       : ICC
      File Type Extension             : icc
      MIME Type                       : application/vnd.iccprofile
      Profile CMM Type                : Adobe Systems Inc.
      Profile Version                 : 2.1.0
      Profile Class                   : Display Device Profile
      Color Space Data                : RGB
      Profile Connection Space        : XYZ
      Profile Date Time               : 2000:08:11 19:51:59
      Profile File Signature          : acsp
      Primary Platform                : Apple Computer Inc.
      CMM Flags                       : Not Embedded, Independent
      Device Manufacturer             : none
      Device Model                    : 
      Device Attributes               : Reflective, Glossy, Positive, Color
      Rendering Intent                : Perceptual
      Connection Space Illuminant     : 0.9642 1 0.82491
      Profile Creator                 : Adobe Systems Inc.
      Profile ID                      : 0
      Profile Copyright               : Copyright 2000 Adobe Systems Incorporated
      Profile Description             : Adobe RGB (1998)
      Media White Point               : 0.95045 1 1.08905

  [identify]
      Image:
        Filename: /home/h02332/po/research/test-profiles/ios-gen-AdobeRGB1998.icc
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
      00000000: 0000 0230 4144 4245 0210 0000 6d6e 7472  ...0ADBE....mntr
      00000010: 5247 4220 5859 5a20 07d0 0008 000b 0013  RGB XYZ ........
      00000020: 0033 003b 61ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
63 7370 4150 504c 0000 0000  .3.;acspAPPL....
      00000030: 6e6f 6e65 0000 0000 0000 0000 0000 0000  none............
      00000040: 0000 0000 0000 f6d6 0001 0000 0000 d32d  ...............-
      00000050: 4144 4245 0000 0000 0000 0000 0000 0000  ADBE............
      00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
      00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................

  [sha256sum]
      304f569a83c1e5eddaddac54e99ed03339333db013738bb499ab64f049887e28  /home/h02332/po/research/test-profiles/ios-gen-AdobeRGB1998.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 560 bytes (0x00000230)  [actual file: 560 bytes]
     [OK] Size within normal range

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x52474220 (RGB)
     [OK] Valid colorSpace: RgbData

[H4] PCS ColorSpace: 0x58595A20 (XYZ)
     [OK] Valid PCS: XYZData

[H5] Platform: 0x4150504C (APPL)
     [OK] Known platform code

[H6] Rendering Intent: 0 (0x00000000)
     [OK] Valid intent: Perceptual

[H7] Profile Class: 0x6D6E7472 (mntr)
     [OK] Known class: DisplayClass

[H8] Illuminant XYZ: (0.964203, 1.000000, 0.824905)
     [OK] PCS illuminant matches D50 (within s15Fixed16 tolerance)

[H15] Date Validation (§4.2 dateTimeNumber): 2000-08-11 19:51:59
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

[H10] Tag Count: 10
      [OK] Tag count within normal range

[H11] CLUT Entry Limit Check
      Max safe CLUT entries per tag: 16777216 (16M)
      [OK] No CLUT tags to check

[H12] MPE Chain Depth Check
      Max MPE elements per chain: 1024
      [OK] No MPE tags to check

[H13] Per-Tag Size Check
      Max tag size: 64 MB (67108864 bytes)
      [OK] All 10 tags within size limits

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
      [WARN]  Matrix column sum (0.9642, 1.0000, 0.8249) deviates from D50
       Expected ≈ (0.9505, 1.0000, 1.0890), deviation (0.0137, 0.0000, 0.2641)

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
      Profile size: 560 bytes, tag count: 10
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
        [ 0.60974   0.20528   0.14919]
        [ 0.31111   0.62567   0.06322]
        [ 0.01947   0.06087   0.74457]
      Determinant: 0.235414
      [OK] Matrix is invertible (det=0.235414)
      Row sums (≈D50 XYZ): [0.9642, 1.0000, 0.8249]
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
      rTRC: gamma=0.0086 [WARN] extreme gamma
      gTRC: gamma=0.0086 [WARN] extreme gamma
      bTRC: gamma=0.0086 [WARN] extreme gamma

[H115] Characterization Data Presence
      [INFO] No characterization data (targ) tag present

[H116] cprt/desc Encoding vs Profile Version
      Profile version: 2.1.0
      cprt: type='text' (0x74657874)
      [OK] cprt uses acceptable type for v2
      desc: type='desc' (0x64657363)
      [OK] desc uses acceptable type for v2

[H117] Tag Type Allowed Per Signature
      [OK] 9 tags checked — all use allowed types

[H118] Calculator Computation Cost Estimate
      [INFO] No MPE calculator/CLUT elements found

[H119] Round-Trip ΔE Measurement
      [INFO] No AToB/BToA CLUT pairs available for ΔE measurement

[H120] Curve Invertibility Assessment
      [WARN]  rTRC: gamma=0.008591 ≈ 0 — NOT invertible
      [WARN]  gTRC: gamma=0.008591 ≈ 0 — NOT invertible
      [WARN]  bTRC: gamma=0.008591 ≈ 0 — NOT invertible

[H121] Characterization Data Round-Trip Capability
      [INFO] No characterization data (targ) tag — cannot assess

[H122] Tag Type Encoding Validation
      [OK] 4 tag types validated — encoding correct

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
      [OK] All 10 tags are 4-byte aligned

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
      [OK] All 10 tag types have zeroed reserved bytes

[H135] Duplicate Tag Signatures (ICC.1-2022-05 §7.3.1)
      [OK] All 10 tag signatures are unique

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
      [OK] No risky shared tag data aliasing

[H40] Tag Alignment & Padding Validation
      [OK] All tags properly aligned with zero padding

[H41] Version/Type Consistency Check
      Profile version: 2.1.0
      [OK] All tags/types consistent with declared version

[H42] Matrix Singularity Detection
      Matrix determinant: 0.23541404
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

[WARN]  8 HEURISTIC WARNING(S) DETECTED

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
Profile: /home/h02332/po/research/test-profiles/ios-gen-AdobeRGB1998.icc

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
  Manufacturer:    0x6E6F6E65  'none'
  Model:           0x00000000  '....'

Tag Signatures:
Idx  Tag          FourCC     Type         Issues
---  ------------ ---------- ------------ ------
0    copyrightTag 'cprt    '  textType    
1    profileDescriptionTag 'desc    '  textDescriptionType
2    mediaWhitePointTag 'wtpt    '  XYZArrayType
3    mediaBlackPointTag 'bkpt    '  XYZArrayType
4    redTRCTag    'rTRC    '  curveType   
5    greenTRCTag  'gTRC    '  curveType   
6    blueTRCTag   'bTRC    '  curveType   
7    redColorantTag 'rXYZ    '  XYZArrayType
8    greenColorantTag 'gXYZ    '  XYZArrayType
9    blueColorantTag 'bXYZ    '  XYZArrayType

Summary: 0 signature issue(s) detected

=======================================================================
PHASE 4: PROFILE STRUCTURE DUMP
=======================================================================

=== ICC Profile Header ===

=== ICC Profile Header (0x0000-0x007F) ===
0x0000: 00 00 02 30 41 44 42 45  02 10 00 00 6D 6E 74 72  |...0ADBE....mntr|
0x0010: 52 47 42 20 58 59 5A 20  07 D0 00 08 00 0B 00 13  |RGB XYZ ........|
0x0020: 00 33 00 3B 61 63 73 70  41 50 50 4C 00 00 00 00  |.3.;acspAPPL....|
0x0030: 6E 6F 6E 65 00 00 00 00  00 00 00 00 00 00 00 00  |none............|
0x0040: 00 00 00 00 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 41 44 42 45 00 00 00 00  00 00 00 00 00 00 00 00  |ADBE............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields:
  Size:            0x00000230 (560 bytes)
  CMM:             ADBE
  Version:         0x02100000
  Device Class:    DisplayClass
  Color Space:     RgbData
  PCS:             XYZData

=== Tag Table ===

=== Tag Table ===
Tag Count: 10

Tag Table Raw Data (0x0080-0x00FC):
0x0080: 00 00 00 0A 63 70 72 74  00 00 00 FC 00 00 00 32  |....cprt.......2|
0x0090: 64 65 73 63 00 00 01 30  00 00 00 6B 77 74 70 74  |desc...0...kwtpt|
0x00A0: 00 00 01 9C 00 00 00 14  62 6B 70 74 00 00 01 B0  |........bkpt....|
0x00B0: 00 00 00 14 72 54 52 43  00 00 01 C4 00 00 00 0E  |....rTRC........|
0x00C0: 67 54 52 43 00 00 01 D4  00 00 00 0E 62 54 52 43  |gTRC........bTRC|
0x00D0: 00 00 01 E4 00 00 00 0E  72 58 59 5A 00 00 01 F4  |........rXYZ....|
0x00E0: 00 00 00 14 67 58 59 5A  00 00 02 08 00 00 00 14  |....gXYZ........|
0x00F0: 62 58 59 5A 00 00 02 1C  00 00 00 14              |bXYZ........|

Tag Entries:
Idx  Signature    FourCC       Offset     Size
---  ------------ ------------ ---------- ----
0    copyrightTag 'cprt      '  0x000000FC  50
1    profileDescriptionTag 'desc      '  0x00000130  107
2    mediaWhitePointTag 'wtpt      '  0x0000019C  20
3    mediaBlackPointTag 'bkpt      '  0x000001B0  20
4    redTRCTag    'rTRC      '  0x000001C4  14
5    greenTRCTag  'gTRC      '  0x000001D4  14
6    blueTRCTag   'bTRC      '  0x000001E4  14
7    redColorantTag 'rXYZ      '  0x000001F4  20
8    greenColorantTag 'gXYZ      '  0x00000208  20
9    blueColorantTag 'bXYZ      '  0x0000021C  20

=======================================================================
PHASE 5: TAG CONTENT ANALYSIS
=======================================================================

--- 5A: LUT Tag Geometry ---

  No legacy LUT tags (A2B/B2A/D2B/B2D) found

--- 5B: MPE Element Chains ---

  No MPE tags found

--- 5C: TRC Curve Analysis ---

  [rTRC] Tabulated curve, 1 entries
      Gamma: 0.0086
  [gTRC] Tabulated curve, 1 entries
      Gamma: 0.0086
  [bTRC] Tabulated curve, 1 entries
      Gamma: 0.0086

--- 5D: NamedColor2 Validation ---

  No NamedColor2 tag

--- 5E: XYZ Tag Values ---

  [rXYZ] X=0.6097 Y=0.3111 Z=0.0195
  [gXYZ] X=0.2053 Y=0.6257 Z=0.0609
  [bXYZ] X=0.1492 Y=0.0632 Z=0.7446
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

File: /home/h02332/po/research/test-profiles/ios-gen-AdobeRGB1998.icc
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

File: /home/h02332/po/research/test-profiles/ios-gen-AdobeRGB1998.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 560 bytes (0x230)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 02 30 41 44 42 45  02 10 00 00 6D 6E 74 72  |...0ADBE....mntr|
0x0010: 52 47 42 20 58 59 5A 20  07 D0 00 08 00 0B 00 13  |RGB XYZ ........|
0x0020: 00 33 00 3B 61 63 73 70  41 50 50 4C 00 00 00 00  |.3.;acspAPPL....|
0x0030: 6E 6F 6E 65 00 00 00 00  00 00 00 00 00 00 00 00  |none............|
0x0040: 00 00 00 00 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 41 44 42 45 00 00 00 00  00 00 00 00 00 00 00 00  |ADBE............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x00000230 (560 bytes) OK
  CMM:             0x41444245  'ADBE'
  Version:         0x02100000
  Device Class:    0x6D6E7472  'mntr'
  Color Space:     0x52474220  'RGB '
  PCS:             0x58595A20  'XYZ '

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 10 (0x0000000A)

Tag Table Raw Data:
0x0080: 00 00 00 0A 63 70 72 74  00 00 00 FC 00 00 00 32  |....cprt.......2|
0x0090: 64 65 73 63 00 00 01 30  00 00 00 6B 77 74 70 74  |desc...0...kwtpt|
0x00A0: 00 00 01 9C 00 00 00 14  62 6B 70 74 00 00 01 B0  |........bkpt....|
0x00B0: 00 00 00 14 72 54 52 43  00 00 01 C4 00 00 00 0E  |....rTRC........|
0x00C0: 67 54 52 43 00 00 01 D4  00 00 00 0E 62 54 52 43  |gTRC........bTRC|
0x00D0: 00 00 01 E4 00 00 00 0E  72 58 59 5A 00 00 01 F4  |........rXYZ....|
0x00E0: 00 00 00 14 67 58 59 5A  00 00 02 08 00 00 00 14  |....gXYZ........|
0x00F0: 62 58 59 5A 00 00 02 1C  00 00 00 14              |bXYZ........|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x63707274   'cprt'        0x000000FC   0x00000032   'text'        OK
1    0x64657363   'desc'        0x00000130   0x0000006B   'desc'        OK
2    0x77747074   'wtpt'        0x0000019C   0x00000014   'XYZ '        OK
3    0x626B7074   'bkpt'        0x000001B0   0x00000014   'XYZ '        OK
4    0x72545243   'rTRC'        0x000001C4   0x0000000E   'curv'        OK
5    0x67545243   'gTRC'        0x000001D4   0x0000000E   'curv'        OK
6    0x62545243   'bTRC'        0x000001E4   0x0000000E   'curv'        OK
7    0x7258595A   'rXYZ'        0x000001F4   0x00000014   'XYZ '        OK
8    0x6758595A   'gXYZ'        0x00000208   0x00000014   'XYZ '        OK
9    0x6258595A   'bXYZ'        0x0000021C   0x00000014   'XYZ '        OK

=== FULL FILE HEX DUMP (all 560 bytes) ===
0x0000: 00 00 02 30 41 44 42 45  02 10 00 00 6D 6E 74 72  |...0ADBE....mntr|
0x0010: 52 47 42 20 58 59 5A 20  07 D0 00 08 00 0B 00 13  |RGB XYZ ........|
0x0020: 00 33 00 3B 61 63 73 70  41 50 50 4C 00 00 00 00  |.3.;acspAPPL....|
0x0030: 6E 6F 6E 65 00 00 00 00  00 00 00 00 00 00 00 00  |none............|
0x0040: 00 00 00 00 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 41 44 42 45 00 00 00 00  00 00 00 00 00 00 00 00  |ADBE............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0080: 00 00 00 0A 63 70 72 74  00 00 00 FC 00 00 00 32  |....cprt.......2|
0x0090: 64 65 73 63 00 00 01 30  00 00 00 6B 77 74 70 74  |desc...0...kwtpt|
0x00A0: 00 00 01 9C 00 00 00 14  62 6B 70 74 00 00 01 B0  |........bkpt....|
0x00B0: 00 00 00 14 72 54 52 43  00 00 01 C4 00 00 00 0E  |....rTRC........|
0x00C0: 67 54 52 43 00 00 01 D4  00 00 00 0E 62 54 52 43  |gTRC........bTRC|
0x00D0: 00 00 01 E4 00 00 00 0E  72 58 59 5A 00 00 01 F4  |........rXYZ....|
0x00E0: 00 00 00 14 67 58 59 5A  00 00 02 08 00 00 00 14  |....gXYZ........|
0x00F0: 62 58 59 5A 00 00 02 1C  00 00 00 14 74 65 78 74  |bXYZ........text|
0x0100: 00 00 00 00 43 6F 70 79  72 69 67 68 74 20 32 30  |....Copyright 20|
0x0110: 30 30 20 41 64 6F 62 65  20 53 79 73 74 65 6D 73  |00 Adobe Systems|
0x0120: 20 49 6E 63 6F 72 70 6F  72 61 74 65 64 00 00 00  | Incorporated...|
0x0130: 64 65 73 63 00 00 00 00  00 00 00 11 41 64 6F 62  |desc........Adob|
0x0140: 65 20 52 47 42 20 28 31  39 39 38 29 00 00 00 00  |e RGB (1998)....|
0x0150: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0160: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0170: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0180: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0190: 00 00 00 00 00 00 00 00  00 00 00 00 58 59 5A 20  |............XYZ |
0x01A0: 00 00 00 00 00 00 F3 51  00 01 00 00 00 01 16 CC  |.......Q........|
0x01B0: 58 59 5A 20 00 00 00 00  00 00 00 00 00 00 00 00  |XYZ ............|
0x01C0: 00 00 00 00 63 75 72 76  00 00 00 00 00 00 00 01  |....curv........|
0x01D0: 02 33 00 00 63 75 72 76  00 00 00 00 00 00 00 01  |.3..curv........|
0x01E0: 02 33 00 00 63 75 72 76  00 00 00 00 00 00 00 01  |.3..curv........|
0x01F0: 02 33 00 00 58 59 5A 20  00 00 00 00 00 00 9C 18  |.3..XYZ ........|
0x0200: 00 00 4F A5 00 00 04 FC  58 59 5A 20 00 00 00 00  |..O.....XYZ ....|
0x0210: 00 00 34 8D 00 00 A0 2C  00 00 0F 95 58 59 5A 20  |..4....,....XYZ |
0x0220: 00 00 00 00 00 00 26 31  00 00 10 2F 00 00 BE 9C  |......&1.../....|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 0**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/ios-gen-AdobeRGB1998.icc

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
