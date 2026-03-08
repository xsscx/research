# ICC Profile Analysis Report

**Profile**: `test-profiles/catalyst-16bit-mismatch.tiff`
**File Size**: 2830 bytes
**SHA-256**: `8bc9485f47c60269bea3f33337cf0f481604d0d739775be22c17ea0779afa354`
**File Type**: TIFF image data, big-endian, direntries=16, height=16, bps=0, compression=none, PhotometricInterpretation=RGB, orientation=upper-left, width=32
**Date**: 2026-03-08T20:03:08Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 2 | Error |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 1**

```
=======================================================================
IMAGE FILE ANALYSIS â€” TIFF
=======================================================================
File: /home/h02332/po/research/test-profiles/catalyst-16bit-mismatch.tiff

--- TIFF Metadata ---
  Dimensions:      32 Ã— 16 pixels
  Bits/Sample:     8
  Samples/Pixel:   4
  Compression:     None (Uncompressed) (1)
  Photometric:     RGB (2)
  Planar Config:   Contiguous (Chunky) (1)
  Sample Format:   Unsigned Integer (1)
  Orientation:     1
  Rows/Strip:      16
  Strip Count:     1

--- TIFF Security Heuristics ---
[H139] TIFF Strip Geometry Validation (CWE-122/CWE-190)
      [OK] Strip geometry valid (bytesPerLine=128, stripSize=2048, rowsPerStrip=16)

[H140] TIFF Dimension and Sample Validation (CWE-400/CWE-131)
      [OK] Dimensions 32Ã—16, BPS=8, SPP=4 (512 pixels)

[H141] TIFF IFD Offset Bounds Validation (CWE-125)
      [OK] All IFD offsets within file bounds (size=2830, pages=1)


--- Injection Signature Scan ---
      [INJECT] PixelData(strip0): 'BigTIFF magic in standard TIFF' at offset 1183
       CWE-843: Type Confusion
  [WARN] 1 injection signature(s) detected

--- Embedded ICC Profile ---
  [FOUND] ICC profile embedded (TIFFTAG_ICCPROFILE, tag 34675)
  Profile Size:    560 bytes (0.5 KB)
  ICC Magic:       [OK] 'acsp' at offset 36
  ICC Version:     2.1

  Extracted to: /tmp/iccanalyzer-extracted-68866.icc

=======================================================================
EXTRACTED ICC PROFILE â€” FULL HEURISTIC ANALYSIS
=======================================================================


=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /tmp/iccanalyzer-extracted-68866.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /tmp/iccanalyzer-extracted-68866.icc

=======================================================================
EXTERNAL FILE METADATA
=======================================================================

  [file]
      ColorSync color profile 2.1, type ADBE, RGB/XYZ-mntr device by ADBE, 560 bytes, 11-8-2000 19:51:59 "Adobe RGB (1998)"

  [exiftool]
      ExifTool Version Number         : 12.76
      File Name                       : iccanalyzer-extracted-68866.icc
      Directory                       : /tmp
      File Size                       : 560 bytes
      File Modification Date/Time     : 2026:03:08 16:03:08-04:00
      File Access Date/Time           : 2026:03:08 16:03:08-04:00
      File Inode Change Date/Time     : 2026:03:08 16:03:08-04:00
      File Permissions                : -rw-------
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
      ProfilICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
e Creator                 : Adobe Systems Inc.
      Profile ID                      : 0
      Profile Copyright               : Copyright 2000 Adobe Systems Incorporated
      Profile Description             : Adobe RGB (1998)
      Media White Point               : 0.95045 1 1.08905

  [identify]
      Image:
        Filename: /tmp/iccanalyzer-extracted-68866.icc
        Permissions: rw-------
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
      00000020: 0033 003b 6163 7370 4150 504c 0000 0000  .3.;acspAPPL....
      00000030: 6e6f 6e65 0000 0000 0000 0000 0000 0000  none............
      00000040: 0000 0000 0000 f6d6 0001 0000 0000 d32d  ...............-
      00000050: 4144 4245 0000 0000 0000 0000 0000 0000  ADBE............
      00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
      00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................

  [sha256sum]
      304f569a83c1e5eddaddac54e99ed03339333db013738bb499ab64f049887e28  /tmp/iccanalyzer-extracted-68866.icc

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

[H15] Date Validation (Â§4.2 dateTimeNumber): 2000-08-11 19:51:59
      [OK] Date values within valid ranges

[H16] Signature Pattern Analysis
      [OK] No suspicious signature patterns detected

[H17] Spectral Range Validation (ICC.2-2023 Â§7.2.22-23)
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
      Note: Tag signature â‰  tag type - must check tag DATA
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
      [OK] No cept (ColorEncodingParams) tag â€” check not applicable

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
       Expected â‰ˆ (0.9505, 1.0000, 1.0890), deviation (0.0137, 0.0000, 0.2641)

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
      Row sums (â‰ˆD50 XYZ): [0.9642, 1.0000, 0.8249]
      [OK] Matrix Ã— Inverse = Identity

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
      [WARN]  wtpt â‰  D50 but 'chad' tag missing (ICC.1-2022-05 Annex G)
       CWE-20: chromaticAdaptationTag required when adopted white â‰  D50

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
      [OK] 9 tags checked â€” all use allowed types

[H118] Calculator Computation Cost Estimate
      [INFO] No MPE calculator/CLUT elements found

[H119] Round-Trip Î”E Measurement
      [INFO] No AToB/BToA CLUT pairs available for Î”E measurement

[H120] Curve Invertibility Assessment
      [WARN]  rTRC: gamma=0.008591 â‰ˆ 0 â€” NOT invertible
      [WARN]  gTRC: gamma=0.008591 â‰ˆ 0 â€” NOT invertible
      [WARN]  bTRC: gamma=0.008591 â‰ˆ 0 â€” NOT invertible

[H121] Characterization Data Round-Trip Capability
      [INFO] No characterization data (targ) tag â€” cannot assess

[H122] Tag Type Encoding Validation
      [OK] 4 tag types validated â€” encoding correct

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
      Version bytes: 02 10 00 00 â†’ v2.1.0
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
       ICC.1-2022-05 Â§7.2.18: ID may be zero if not computed

[H132] chromaticAdaptation Matrix Validation
      [INFO] No chromaticAdaptation (chad) tag present

[H133] Profile Flags Reserved Bits (ICC.1-2022-05 Â§7.2.11)
      Flags: 0x00000000 (embedded=0, independent=0)
      [OK] Reserved flag bits are zero

[H134] Tag Type Reserved Bytes (ICC.1-2022-05 Â§10.1)
      [OK] All 10 tag types have zeroed reserved bytes

[H135] Duplicate Tag Signatures (ICC.1-2022-05 Â§7.3.1)
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
  Spec conformance: ICC.1-2022-05, ICC.2-2023 â€” heuristics cite Â§section references
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
  H116-H127: ICC Technical Secretary feedback â€” cprt/desc encoding, tag-type validation,
             computation cost, Î”E round-trip, curve invertibility, characterization RT,
             deep encoding, non-required tags, version-tag, smoothness, malware scan, registry
  H128-H132: ICC.1-2022-05 spec compliance â€” version BCD, PCS D50, tag alignment,
             Profile ID MD5, chromaticAdaptation matrix (Â§7.2.4, Â§7.2.16, Â§7.3.1, Â§7.2.18, Annex G)
  H133-H135: ICC.1-2022-05 additional â€” flags reserved bits (Â§7.2.11), tag type reserved
             bytes (Â§10.1), duplicate tag signatures (Â§7.3.1)
  H136-H138: CWE-400 systemic â€” ResponseCurve measurement counts, high-dimensional
             grid complexity, calculator branching depth (CFL-074/075/076 findings)

  Recommendations:
  â€¢ Validate profile with official ICC tools
  â€¢ Use -n (ninja mode) for detailed byte-level analysis
  â€¢ Do NOT use in production color workflows
  â€¢ Consider as potential security test case


=======================================================================
PHASE 2: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /tmp/iccanalyzer-extracted-68866.icc

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

File: /tmp/iccanalyzer-extracted-68866.icc
Total Issues Detected: 8

[WARN] ANALYSIS COMPLETE - 8 issue(s) detected
  Review detailed output above for security concerns.


=======================================================================
IMAGE ANALYSIS SUMMARY
=======================================================================
Format:     TIFF
Dimensions: 32 Ã— 16
Findings:   9
=======================================================================
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

File: /home/h02332/po/research/test-profiles/catalyst-16bit-mismatch.tiff
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 2830 bytes (0xB0E)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 4D 4D 00 2A 00 00 08 08  02 01 13 13 3C 26 86 89  |MM.*........<&..|
0x0010: 8D F5 4A F5 7D D5 B1 E4  3B 3B 3B 3B 00 00 00 00  |..J.}...;;;;....|
0x0020: C6 A9 83 D1 01 01 01 01  01 01 01 01 8E 62 15 FF  |.............b..|
0x0030: 5D 98 43 98 26 26 26 26  1D 1D 1D 1D C8 0A 30 E9  |].C.&&&&......0.|
0x0040: A2 75 CE D0 50 8E 61 93  4C 1A 30 57 3B 1F 42 43  |.u..P.a.L.0W;.BC|
0x0050: 45 3F 3D 48 57 57 21 57  85 85 85 85 A2 00 F0 F5  |E?=HWW!W........|
0x0060: 00 00 00 00 9D AD 6B AD  7D 7D 7D 7D 22 3D 3D 3D  |......k.}}}}"===|
0x0070: 94 B9 7E D8 1D 00 21 22  01 01 01 01 28 46 2A 46  |..~...!"....(F*F|

Header Fields (RAW - no validation):
  Profile Size:    0x4D4D002A (1296891946 bytes) MISMATCH
  CMM:             0x00000808  '....'
  Version:         0x02011313
  Device Class:    0x3C268689  '<&..'
  Color Space:     0x8DF54AF5  '..J.'
  PCS:             0x7DD5B1E4  '}...'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 623845679 (0x252F212F)
WARNING: Suspicious tag count (>1000) - possible corruption

Tag Table Raw Data:
0x0080: 25 2F 21 2F 44 00 77 B2  72 72 72 72 53 59 1E 74  |%/!/D.w.rrrrSY.t|
0x0090: 22 00 27 28 40 40 40 40  4D 26 89 8C 73 C9 D3 E8  |".'(@@@@M&..s...|
0x00A0: 5B 5B 3B 5B 00 00 00 00  AF 8E 41 BB A4 B1 6A B1  |[[;[......A...j.|
0x00B0: D6 69 A4 F2 2E 51 50 8C  69 69 4B 69 9A C2 AD C2  |.i...QP.iiKi....|
0x00C0: 00 00 00 00 D6 C4 DC DD  18 2A 67 D9 81 10 EA FF  |.........*g.....|
0x00D0: B5 C3 CA CA AC 40 17 C5  03 03 03 03 05 05 05 05  |.....@..........|
0x00E0: 51 01 5C 5E 6F 42 10 7C  41 20 62 81 B8 B8 AC B8  |Q.\^oB.|A b.....|
0x00F0: 68 87 89 89 00 00 00 00  52 52 52 52 23 02 53 55  |h.......RRRR#.SU|
0x0100: 23 23 23 23 49 49 49 49  6A 94 94 94 01 01 01 01  |####IIIIj.......|
0x0110: 1D 1D 1D 1D 29 48 4B 4B  03 03 03 03 6B 43 3E FF  |....)HKK....kC>.|
0x0120: 75 88 6B 88 6B 6B 6B 6B  AB C7 92 C7 41 38 B8 BB  |u.k.kkkk....A8..|
0x0130: 31 31 31 31 01 01 01 01  C3 02 2D E3 8E FB 75 FB  |1111......-...u.|
0x0140: 9D 9D 31 9D A1 E0 37 FA  98 B1 B1 B1 3F 70 35 70  |..1...7.....?p5p|
0x0150: 2B 44 14 44 03 03 03 03  6E 77 1C F8 4F 81 20 81  |+D.D....nw..O. .|
0x0160: 29 00 5E 60 C8 E0 E0 E0  5A 9F 51 9F 7B B6 B6 B6  |).^`....Z.Q.{...|
0x0170: 2F 53 71 8C 7E 44 B8 BB  38 52 61 CF 44 39 68 7F  |/Sq.~D..8Ra.D9h.|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x440077B2   'D   '        0x72727272   0x53591E74   '----'        OOB offset
1    0x22002728   '"   '        0x40404040   0x4D26898C   '----'        OOB offset
2    0x73C9D3E8   'sÉÓè'        0x5B5B3B5B   0x00000000   '----'        OOB offset
3    0xAF8E41BB   '¯ŽA»'        0xA4B16AB1   0xD669A4F2   '----'        OOB offset
4    0x2E51508C   '.QPŒ'        0x69694B69   0x9AC2ADC2   '----'        OOB offset
5    0x00000000   '    '        0xD6C4DCDD   0x182A67D9   '----'        OOB offset
6    0x8110EAFF   'êÿ'        0xB5C3CACA   0xAC4017C5   '----'        OOB offset
7    0x03030303   ''        0x05050505   0x51015C5E   '----'        OOB offset
8    0x6F42107C   'oB|'        0x41206281   0xB8B8ACB8   '----'        OOB offset
9    0x68878989   'h‡‰‰'        0x00000000   0x52525252   'MM  '        OOB size
10   0x23025355   '#SU'        0x23232323   0x49494949   '----'        OOB offset
11   0x6A949494   'j”””'        0x01010101   0x1D1D1D1D   '----'        OOB offset
12   0x29484B4B   ')HKK'        0x03030303   0x6B433EFF   '----'        OOB offset
13   0x75886B88   'uˆkˆ'        0x6B6B6B6B   0xABC792C7   '----'        OOB offset
14   0x4138B8BB   'A8¸»'        0x31313131   0x01010101   '----'        OOB offset
15   0xC3022DE3   'Ã-ã'        0x8EFB75FB   0x9D9D319D   '----'        OOB offset
16   0xA1E037FA   '¡à7ú'        0x98B1B1B1   0x3F703570   '----'        OOB offset
17   0x2B441444   '+DD'        0x03030303   0x6E771CF8   '----'        OOB offset
18   0x4F812081   'O '        0x29005E60   0xC8E0E0E0   '----'        OOB offset
19   0x5A9F519F   'ZŸQŸ'        0x7BB6B6B6   0x2F53718C   '----'        OOB offset
20   0x7E44B8BB   '~D¸»'        0x385261CF   0x4439687F   '----'        OOB offset
21   0x52525252   'RRRR'        0x5D2251D8   0x0A0A0A0A   '----'        OOB offset
22   0x2A39A3A6   '*9£¦'        0x3E3E1A8D   0x2B167779   '----'        OOB offset
23   0x01010101   ''        0x1A237D7F   0x84842084   '----'        OOB offset
24   0x2B0B3540   '+5@'        0xE4E3C1F2   0x12121212   '----'        OOB offset
25   0xAAA04EAE   'ª N®'        0x15252525   0x04050505   '----'        OOB offset
26   0xD4D4C5D4   'ÔÔÅÔ'        0x811B9295   0x3B644B64   '----'        OOB offset
27   0x0C0C030D   ''        0x676767DA   0x91917A91   '----'        OOB offset
28   0xE2E2ABE2   'ââ«â'        0x17016B6D   0x476F6F6F   '----'        OOB offset
29   0x0A0A0A0A   '



'        0x647F4B7F   0x6C517475   '----'        OOB offset
30   0x0D0D0D0D   ''        0x7C2ECFFF   0x1D1D1D1D   '----'        OOB offset
31   0x04040104   ''        0x01010101   0x06060206   '----'        OOB offset
32   0x14141414   ''        0x6661509F   0x8F00A3A6   '----'        OOB offset
33   0x15015E9F   '^Ÿ'        0x263E3E3E   0x01010101   '----'        OOB offset
34   0x0C161616   ''        0x36073E3F   0x00000000   '----'        OOB offset
35   0x33333333   '3333'        0x1600191A   0xD99EF2F5   '----'        OOB offset
36   0x579824FF   'W˜$ÿ'        0x00000000   0x80408E9F   'MM  '        OOB size
37   0x87851FF5   '‡…õ'        0x58939393   0x56563156   '----'        OOB offset
38   0x081B66FF   'fÿ'        0x5F666666   0x23232323   '----'        OOB offset
39   0xB1BFF8FA   '±¿øú'        0xE3E6C2E6   0x3F609BFF   '----'        OOB offset
40   0x2D2D2D2D   '----'        0x85EBEBEB   0x262604DD   '----'        OOB offset
41   0x0F1B1B1B   ''        0x02020202   0x34343434   '----'        OOB offset
42   0x4F01225C   'O"\'        0xB6734BFF   0x4D7F9BF2   '----'        OOB offset
43   0x58585858   'XXXX'        0x78A247C4   0x8700019D   '----'        OOB offset
44   0x993874B6   '™8t¶'        0x7B7A7B7B   0x44009DA0   '----'        OOB offset
45   0x64176874   'dht'        0xBFBFB5BF   0x22221522   '----'        OOB offset
46   0x7D8C8C8C   '}ŒŒŒ'        0x594036B6   0xB9D84BD8   '----'        OOB offset
47   0x2F2F2F2F   '////'        0x85959595   0x73B6ABB6   '----'        OOB offset
48   0x00000000   '    '        0x2F4A4A4A   0x42424242   '----'        OOB offset
49   0x9A695EE9   'ši^é'        0x01010101   0x40004A4B   '----'        OOB offset
50   0x4C82898A   'L‚‰Š'        0x355D5D5D   0x955D16A5   '----'        OOB offset
51   0x20202020   '    '        0x1E1E1E1E   0x7A7A8485   '----'        OOB offset
52   0x92829798   '’‚—˜'        0x10101010   0x68396B96   '----'        OOB offset
53   0x02020202   ''        0x5E2530DB   0x62626262   '----'        OOB offset
54   0x020200FE   '  '        0x15151515   0x783E8587   '----'        OOB offset
55   0xBED4BAD4   '¾ÔºÔ'        0x6BA8A8A8   0x5324095F   '----'        OOB offset
56   0x526E6E6E   'Rnnn'        0x3B3B6BFC   0x29484848   '----'        OOB offset
57   0x00000000   '    '        0x669842A4   0x5F8257A3   '----'        OOB offset
58   0x5601A9EC   'V©ì'        0x536A7979   0x58926092   '----'        OOB offset
59   0x825013AD   '‚P­'        0x56968BF0   0x8FB345B8   '----'        OOB offset
60   0x14191919   ''        0x0101979A   0x1C1C1C9D   '----'        OOB offset
61   0xB4C051DB   '´ÀQÛ'        0xBCA42AC4   0x85E8C6E8   '----'        OOB offset
62   0x61A35FA3   'a£_£'        0x07075B88   0x50505050   '----'        OOB offset
63   0x15090718   '	'        0x527B7B7B   0x4739424C   '----'        OOB offset
64   0x54545454   'TTTT'        0x373778CA   0x655454F7   '----'        OOB offset
65   0x8AAFAFAF   'Š¯¯¯'        0x916D1A9D   0xCACA91CA   '----'        OOB offset
66   0x1A1A1A1A   ''        0x30014849   0xB5B557B5   '----'        OOB offset
67   0x3E000B68   '>   '        0x72208083   0x576868EA   '----'        OOB offset
68   0x26262626   '&&&&'        0x2401A1D9   0x3A2E2E3E   '----'        OOB offset
69   0xC7C03AC9   'ÇÀ:É'        0x5A9E2F9E   0x3F007678   '----'        OOB offset
70   0xC2EC3BEC   'Âì;ì'        0x3B3B3B3B   0xA79F9EFF   '----'        OOB offset
71   0xBE3C58FF   '¾<Xÿ'        0x01010101   0x7E805680   '----'        OOB offset
72   0x33333333   '3333'        0x2A2A2A2A   0x05050505   '----'        OOB offset
73   0x01010101   ''        0x5F839697   0x426839FF   '----'        OOB offset
74   0x785A8082   'xZ€‚'        0x57585858   0x622C6D6F   '----'        OOB offset
75   0x2F000838   '/   '        0x8A609597   0x3C615A61   '----'        OOB offset
76   0x6E6E6E6E   'nnnn'        0x28282828   0x49494949   '----'        OOB offset
77   0x000227CC   '    '        0x75A0A0A0   0x25252525   '----'        OOB offset
78   0x9E0095B8   'ž   '        0x5A9CEDF4   0x6B244384   '----'        OOB offset
79   0x1722119D   '"'        0x70687373   0x7E71CEF2   '----'        OOB offset
80   0xB26B20F6   '²k ö'        0x26444444   0x4212294C   '----'        OOB offset
81   0x75B55BFE   'uµ[þ'        0x1D1D141D   0xB0B0B0B0   '----'        OOB offset
82   0x4E2D41C6   'N-AÆ'        0x5B97C7C9   0x21002526   '----'        OOB offset
83   0x494F4F4F   'IOOO'        0xCDC056F7   0x3B676767   '----'        OOB offset
84   0x05000606   '   '        0x73C46CDC   0x75118588   '----'        OOB offset
85   0x3A2E3D5D   ':.=]'        0xD0504EEE   0x4C4BA9AC   '----'        OOB offset
86   0x508E87F9   'PŽ‡ù'        0x79641881   0x8A0C55CC   '----'        OOB offset
87   0x00000000   '    '        0x0F1A1A1A   0x53472277   '----'        OOB offset
88   0x00000000   '    '        0x2B2B2B2B   0x18082F30   '----'        OOB offset
89   0x335BBCBF   '3[¼¿'        0x83E0DEE0   0xA041ACFF   '----'        OOB offset
90   0x6D7F6E7F   'mn'        0x73B280B2   0xADD533FC   '----'        OOB offset
91   0x60606060   '````'        0x6E6E676E   0x424242F0   '----'        OOB offset
92   0x6E6E6E6E   'nnnn'        0x5C5C5C5C   0x87AF29AF   '----'        OOB offset
93   0x03030303   ''        0x34343434   0x1E1EE3FB   '----'        OOB offset
94   0x6E40417B   'n@A{'        0x93FF78FF   0x8F14A3A6   '----'        OOB offset
95   0x26260926   '&&	&'        0x50207CDA   0x5A95D2D5   '----'        OOB offset
96   0x355C5C5C   '5\\\'        0x44330C73   0x37371037   '----'        OOB offset
97   0x8B679597   '‹g•—'        0x01010101   0x01010101   '----'        OOB offset
98   0x49493E49   'II>I'        0xEBB094FF   0x24404040   '----'        OOB offset
99   0x151C7779   'wy'        0x49494549   0x31313131   '----'        OOB offset
... (623845579 more tags not shown)

[WARN] SIZE INFLATION: Header claims 1296891946 bytes, file is 2830 bytes (458266x)
   Risk: OOM via tag-internal allocations based on inflated header size

[WARN] TAG OVERLAP: 2946 overlapping tag pair(s) detected
   Risk: Data corruption, possible exploit crafting

=== FULL FILE HEX DUMP (all 2830 bytes) ===
0x0000: 4D 4D 00 2A 00 00 08 08  02 01 13 13 3C 26 86 89  |MM.*........<&..|
0x0010: 8D F5 4A F5 7D D5 B1 E4  3B 3B 3B 3B 00 00 00 00  |..J.}...;;;;....|
0x0020: C6 A9 83 D1 01 01 01 01  01 01 01 01 8E 62 15 FF  |.............b..|
0x0030: 5D 98 43 98 26 26 26 26  1D 1D 1D 1D C8 0A 30 E9  |].C.&&&&......0.|
0x0040: A2 75 CE D0 50 8E 61 93  4C 1A 30 57 3B 1F 42 43  |.u..P.a.L.0W;.BC|
0x0050: 45 3F 3D 48 57 57 21 57  85 85 85 85 A2 00 F0 F5  |E?=HWW!W........|
0x0060: 00 00 00 00 9D AD 6B AD  7D 7D 7D 7D 22 3D 3D 3D  |......k.}}}}"===|
0x0070: 94 B9 7E D8 1D 00 21 22  01 01 01 01 28 46 2A 46  |..~...!"....(F*F|
0x0080: 25 2F 21 2F 44 00 77 B2  72 72 72 72 53 59 1E 74  |%/!/D.w.rrrrSY.t|
0x0090: 22 00 27 28 40 40 40 40  4D 26 89 8C 73 C9 D3 E8  |".'(@@@@M&..s...|
0x00A0: 5B 5B 3B 5B 00 00 00 00  AF 8E 41 BB A4 B1 6A B1  |[[;[......A...j.|
0x00B0: D6 69 A4 F2 2E 51 50 8C  69 69 4B 69 9A C2 AD C2  |.i...QP.iiKi....|
0x00C0: 00 00 00 00 D6 C4 DC DD  18 2A 67 D9 81 10 EA FF  |.........*g.....|
0x00D0: B5 C3 CA CA AC 40 17 C5  03 03 03 03 05 05 05 05  |.....@..........|
0x00E0: 51 01 5C 5E 6F 42 10 7C  41 20 62 81 B8 B8 AC B8  |Q.\^oB.|A b.....|
0x00F0: 68 87 89 89 00 00 00 00  52 52 52 52 23 02 53 55  |h.......RRRR#.SU|
0x0100: 23 23 23 23 49 49 49 49  6A 94 94 94 01 01 01 01  |####IIIIj.......|
0x0110: 1D 1D 1D 1D 29 48 4B 4B  03 03 03 03 6B 43 3E FF  |....)HKK....kC>.|
0x0120: 75 88 6B 88 6B 6B 6B 6B  AB C7 92 C7 41 38 B8 BB  |u.k.kkkk....A8..|
0x0130: 31 31 31 31 01 01 01 01  C3 02 2D E3 8E FB 75 FB  |1111......-...u.|
0x0140: 9D 9D 31 9D A1 E0 37 FA  98 B1 B1 B1 3F 70 35 70  |..1...7.....?p5p|
0x0150: 2B 44 14 44 03 03 03 03  6E 77 1C F8 4F 81 20 81  |+D.D....nw..O. .|
0x0160: 29 00 5E 60 C8 E0 E0 E0  5A 9F 51 9F 7B B6 B6 B6  |).^`....Z.Q.{...|
0x0170: 2F 53 71 8C 7E 44 B8 BB  38 52 61 CF 44 39 68 7F  |/Sq.~D..8Ra.D9h.|
0x0180: 52 52 52 52 5D 22 51 D8  0A 0A 0A 0A 2A 39 A3 A6  |RRRR]"Q.....*9..|
0x0190: 3E 3E 1A 8D 2B 16 77 79  01 01 01 01 1A 23 7D 7F  |>>..+.wy.....#}.|
0x01A0: 84 84 20 84 2B 0B 35 40  E4 E3 C1 F2 12 12 12 12  |.. .+.5@........|
0x01B0: AA A0 4E AE 15 25 25 25  04 05 05 05 D4 D4 C5 D4  |..N..%%%........|
0x01C0: 81 1B 92 95 3B 64 4B 64  0C 0C 03 0D 67 67 67 DA  |....;dKd....ggg.|
0x01D0: 91 91 7A 91 E2 E2 AB E2  17 01 6B 6D 47 6F 6F 6F  |..z.......kmGooo|
0x01E0: 0A 0A 0A 0A 64 7F 4B 7F  6C 51 74 75 0D 0D 0D 0D  |....d.K.lQtu....|
0x01F0: 7C 2E CF FF 1D 1D 1D 1D  04 04 01 04 01 01 01 01  ||...............|
0x0200: 06 06 02 06 14 14 14 14  66 61 50 9F 8F 00 A3 A6  |........faP.....|
0x0210: 15 01 5E 9F 26 3E 3E 3E  01 01 01 01 0C 16 16 16  |..^.&>>>........|
0x0220: 36 07 3E 3F 00 00 00 00  33 33 33 33 16 00 19 1A  |6.>?....3333....|
0x0230: D9 9E F2 F5 57 98 24 FF  00 00 00 00 80 40 8E 9F  |....W.$......@..|
0x0240: 87 85 1F F5 58 93 93 93  56 56 31 56 08 1B 66 FF  |....X...VV1V..f.|
0x0250: 5F 66 66 66 23 23 23 23  B1 BF F8 FA E3 E6 C2 E6  |_fff####........|
0x0260: 3F 60 9B FF 2D 2D 2D 2D  85 EB EB EB 26 26 04 DD  |?`..----....&&..|
0x0270: 0F 1B 1B 1B 02 02 02 02  34 34 34 34 4F 01 22 5C  |........4444O."\|
0x0280: B6 73 4B FF 4D 7F 9B F2  58 58 58 58 78 A2 47 C4  |.sK.M...XXXXx.G.|
0x0290: 87 00 01 9D 99 38 74 B6  7B 7A 7B 7B 44 00 9D A0  |.....8t.{z{{D...|
0x02A0: 64 17 68 74 BF BF B5 BF  22 22 15 22 7D 8C 8C 8C  |d.ht....""."}...|
0x02B0: 59 40 36 B6 B9 D8 4B D8  2F 2F 2F 2F 85 95 95 95  |Y@6...K.////....|
0x02C0: 73 B6 AB B6 00 00 00 00  2F 4A 4A 4A 42 42 42 42  |s......./JJJBBBB|
0x02D0: 9A 69 5E E9 01 01 01 01  40 00 4A 4B 4C 82 89 8A  |.i^.....@.JKL...|
0x02E0: 35 5D 5D 5D 95 5D 16 A5  20 20 20 20 1E 1E 1E 1E  |5]]].]..    ....|
0x02F0: 7A 7A 84 85 92 82 97 98  10 10 10 10 68 39 6B 96  |zz..........h9k.|
0x0300: 02 02 02 02 5E 25 30 DB  62 62 62 62 02 02 00 FE  |....^%0.bbbb....|
0x0310: 15 15 15 15 78 3E 85 87  BE D4 BA D4 6B A8 A8 A8  |....x>......k...|
0x0320: 53 24 09 5F 52 6E 6E 6E  3B 3B 6B FC 29 48 48 48  |S$._Rnnn;;k.)HHH|
0x0330: 00 00 00 00 66 98 42 A4  5F 82 57 A3 56 01 A9 EC  |....f.B._.W.V...|
0x0340: 53 6A 79 79 58 92 60 92  82 50 13 AD 56 96 8B F0  |SjyyX.`..P..V...|
0x0350: 8F B3 45 B8 14 19 19 19  01 01 97 9A 1C 1C 1C 9D  |..E.............|
0x0360: B4 C0 51 DB BC A4 2A C4  85 E8 C6 E8 61 A3 5F A3  |..Q...*.....a._.|
0x0370: 07 07 5B 88 50 50 50 50  15 09 07 18 52 7B 7B 7B  |..[.PPPP....R{{{|
0x0380: 47 39 42 4C 54 54 54 54  37 37 78 CA 65 54 54 F7  |G9BLTTTT77x.eTT.|
0x0390: 8A AF AF AF 91 6D 1A 9D  CA CA 91 CA 1A 1A 1A 1A  |.....m..........|
0x03A0: 30 01 48 49 B5 B5 57 B5  3E 00 0B 68 72 20 80 83  |0.HI..W.>..hr ..|
0x03B0: 57 68 68 EA 26 26 26 26  24 01 A1 D9 3A 2E 2E 3E  |Whh.&&&&$...:..>|
0x03C0: C7 C0 3A C9 5A 9E 2F 9E  3F 00 76 78 C2 EC 3B EC  |..:.Z./.?.vx..;.|
0x03D0: 3B 3B 3B 3B A7 9F 9E FF  BE 3C 58 FF 01 01 01 01  |;;;;.....<X.....|
0x03E0: 7E 80 56 80 33 33 33 33  2A 2A 2A 2A 05 05 05 05  |~.V.3333****....|
0x03F0: 01 01 01 01 5F 83 96 97  42 68 39 FF 78 5A 80 82  |...._...Bh9.xZ..|
0x0400: 57 58 58 58 62 2C 6D 6F  2F 00 08 38 8A 60 95 97  |WXXXb,mo/..8.`..|
0x0410: 3C 61 5A 61 6E 6E 6E 6E  28 28 28 28 49 49 49 49  |<aZannnn((((IIII|
0x0420: 00 02 27 CC 75 A0 A0 A0  25 25 25 25 9E 00 95 B8  |..'.u...%%%%....|
0x0430: 5A 9C ED F4 6B 24 43 84  17 22 11 9D 70 68 73 73  |Z...k$C.."..phss|
0x0440: 7E 71 CE F2 B2 6B 20 F6  26 44 44 44 42 12 29 4C  |~q...k .&DDDB.)L|
0x0450: 75 B5 5B FE 1D 1D 14 1D  B0 B0 B0 B0 4E 2D 41 C6  |u.[.........N-A.|
0x0460: 5B 97 C7 C9 21 00 25 26  49 4F 4F 4F CD C0 56 F7  |[...!.%&IOOO..V.|
0x0470: 3B 67 67 67 05 00 06 06  73 C4 6C DC 75 11 85 88  |;ggg....s.l.u...|
0x0480: 3A 2E 3D 5D D0 50 4E EE  4C 4B A9 AC 50 8E 87 F9  |:.=].PN.LK..P...|
0x0490: 79 64 18 81 8A 0C 55 CC  00 00 00 00 0F 1A 1A 1A  |yd....U.........|
0x04A0: 53 47 22 77 00 00 00 00  2B 2B 2B 2B 18 08 2F 30  |SG"w....++++../0|
0x04B0: 33 5B BC BF 83 E0 DE E0  A0 41 AC FF 6D 7F 6E 7F  |3[.......A..m.n.|
0x04C0: 73 B2 80 B2 AD D5 33 FC  60 60 60 60 6E 6E 67 6E  |s.....3.````nngn|
0x04D0: 42 42 42 F0 6E 6E 6E 6E  5C 5C 5C 5C 87 AF 29 AF  |BBB.nnnn\\\\..).|
0x04E0: 03 03 03 03 34 34 34 34  1E 1E E3 FB 6E 40 41 7B  |....4444....n@A{|
0x04F0: 93 FF 78 FF 8F 14 A3 A6  26 26 09 26 50 20 7C DA  |..x.....&&.&P |.|
0x0500: 5A 95 D2 D5 35 5C 5C 5C  44 33 0C 73 37 37 10 37  |Z...5\\\D3.s77.7|
0x0510: 8B 67 95 97 01 01 01 01  01 01 01 01 49 49 3E 49  |.g..........II>I|
0x0520: EB B0 94 FF 24 40 40 40  15 1C 77 79 49 49 45 49  |....$@@@..wyIIEI|
0x0530: 31 31 31 31 6D 7B 7B 7B  0A 0A 02 0A 1F 00 F8 FD  |1111m{{{........|
0x0540: B1 4A 0D DA B1 3A 15 CC  4A 27 09 53 5B 47 11 6A  |.J...:..J'.S[G.j|
0x0550: 3F 30 56 57 05 05 05 05  A2 A6 4F DB DB F0 48 FF  |?0VW......O...H.|
0x0560: 2B 1A 2F 30 1C 1C 1C 1C  2A 00 9C AE 1F 25 25 25  |+./0....*....%%%|
0x0570: 03 03 03 03 38 24 A8 AB  0C 0C 0C 0C 39 39 1D 39  |....8$......99.9|
0x0580: 62 14 97 9A 52 63 BA BD  2E 49 49 49 6B 6A 22 88  |b...Rc...IIIkj".|
0x0590: 41 30 46 47 A5 43 FA FF  81 7F 21 82 37 37 37 37  |A0FG.C....!.7777|
0x05A0: 18 18 18 18 15 15 0F 15  7A 7A 7A 7A 2E 00 49 B0  |........zzzz..I.|
0x05B0: 45 64 63 70 25 2E 08 8C  40 6B 1E 6B 7D 04 E8 ED  |Edcp%...@k.k}...|
0x05C0: 14 24 24 24 88 32 4D B7  D0 D0 9D D0 3B 15 1D 44  |.$$$.2M.....;..D|
0x05D0: 37 20 3C 3D 8F DC A5 DC  7D 38 55 C8 8A 5D 88 BA  |7 <=....}8U..]..|
0x05E0: 75 BC 9B C1 54 8A 8B 8B  97 8C 77 CA 35 35 35 35  |u...T.....w.5555|
0x05F0: 62 73 C7 C9 31 0D 1E 5F  5B 99 71 BE 94 06 51 AC  |bs..1.._[.q...Q.|
0x0600: 6D 6D 23 9B 2C 3A 06 FF  A0 53 C2 EC BD 96 5E CA  |mm#.,:...S....^.|
0x0610: 00 01 31 32 69 51 1A BC  A8 03 AC C4 3F 6C 7F DB  |..12iQ......?l..|
0x0620: 41 41 41 41 68 45 77 78  06 06 06 06 5A 5A 15 5A  |AAAAhEwx....ZZ.Z|
0x0630: 00 00 00 00 18 21 2E B7  AA D2 9F D2 7E 84 C8 ED  |.....!......~...|
0x0640: 09 09 02 09 3B 2A 57 58  CB 0C 0B F6 C2 44 45 F7  |....;*WX.....DE.|
0x0650: 08 0F 0F 0F 5E 09 01 6E  9B 94 6B 9E 9F 28 BB BF  |....^..n..k..(..|
0x0660: 01 01 01 01 4E 39 DB F3  29 39 39 39 37 1A 5B 5D  |....N9..)9997.[]|
0x0670: 40 6B 86 FF 69 B9 4F CA  8E 9F 9F 9F 94 EF E8 FF  |@k..i.O.........|
0x0680: 1A 1A 1A 1A C8 C8 52 C8  27 2E 16 83 B7 93 99 D4  |......R.'.......|
0x0690: 1E 1E 10 1E 4C 4C 36 4C  9E 92 22 A2 00 00 00 00  |....LL6L..".....|
0x06A0: 80 80 7D FF E4 B6 88 F3  7A 7A 7A 7A 0B 0B 0B 0B  |..}.....zzzz....|
0x06B0: 77 B0 B0 B0 21 21 0B 21  7D 7D 40 7D 31 34 4A 9B  |w...!!.!}}@}14J.|
0x06C0: 76 79 1C 83 68 B5 73 DE  34 34 34 34 4F 6F 3B 6F  |vy..h.s.4444Oo;o|
0x06D0: DC 96 FC FF 63 15 66 8B  2A 2A 0D 2A 1C 08 1F FF  |....c.f.**.*....|
0x06E0: 12 1F 05 79 71 9C 66 9C  36 5F 89 8B 7E 59 B5 B8  |...yq.f.6_..~Y..|
0x06F0: 4A 4A 13 4A 07 07 07 07  90 5F 2F 9F 41 15 10 4B  |JJ.J....._/.A..K|
0x0700: 4B 3F 15 C3 7E D1 31 D1  7B 96 EC EF 48 1D 39 52  |K?..~.1.{...H.9R|
0x0710: 3C 17 24 B5 2B 2B 2B 2B  2D 35 35 35 93 00 A8 AB  |<.$.++++-555....|
0x0720: 9E 5D B5 B8 58 99 71 DF  5B 4B 37 D9 02 02 01 02  |.]..X.q.[K7.....|
0x0730: 31 57 BC BF 28 01 2D 2E  82 C9 C3 EA 45 29 80 82  |1W..(.-.....E)..|
0x0740: 1B 1B 1B 1B 35 35 63 65  FF FF 5E FF 57 89 40 E9  |....55ce..^.W.@.|
0x0750: 99 AD 29 AD 70 70 70 A1  28 28 28 28 8D 01 5B A4  |..).ppp.((((..[.|
0x0760: 40 63 63 63 0E 0E 0E 0E  84 5D 8E 90 97 97 97 97  |@ccc.....]......|
0x0770: 16 12 2C 9F CC CC 45 CC  02 01 A9 FE 00 00 00 00  |..,...E.........|
0x0780: 4E 81 32 A4 93 48 57 A7  26 25 26 DD 58 58 15 58  |N.2..HW.&%&.XX.X|
0x0790: 32 01 08 3A 01 01 01 01  25 40 08 FF 00 00 00 00  |2..:....%@......|
0x07A0: 01 01 01 01 78 01 B2 B6  9A 61 54 E3 80 C6 88 F8  |....x....aT.....|
0x07B0: 69 69 1F 69 27 45 DF FF  11 11 11 11 AA 11 C2 C6  |ii.i'E..........|
0x07C0: 7F 68 B8 BA 42 01 E0 FF  7F A9 AF AF DB 9E 41 EF  |.h..B.........A.|
0x07D0: 81 6F 77 87 39 52 52 52  01 01 01 01 1F 35 35 35  |.ow.9RRR.....555|
0x07E0: 65 A9 32 A9 6A BB C3 FF  76 76 76 76 62 07 70 72  |e.2.j...vvvvb.pr|
0x07F0: 06 06 01 06 57 6F 35 85  0A 0A 0A 0A 2D 1A 31 32  |....Wo5.....-.12|
0x0800: 00 00 00 00 6C B9 D3 D4  00 10 01 00 00 03 00 00  |....l...........|
0x0810: 00 01 00 20 00 00 01 01  00 03 00 00 00 01 00 10  |... ............|
0x0820: 00 00 01 02 00 03 00 00  00 04 00 00 08 CE 01 03  |................|
0x0830: 00 03 00 00 00 01 00 01  00 00 01 06 00 03 00 00  |................|
0x0840: 00 01 00 02 00 00 01 0A  00 03 00 00 00 01 00 01  |................|
0x0850: 00 00 01 11 00 04 00 00  00 01 00 00 00 08 01 12  |................|
0x0860: 00 03 00 00 00 01 00 01  00 00 01 15 00 03 00 00  |................|
0x0870: 00 01 00 04 00 00 01 16  00 03 00 00 00 01 00 10  |................|
0x0880: 00 00 01 17 00 04 00 00  00 01 00 00 08 00 01 1C  |................|
0x0890: 00 03 00 00 00 01 00 01  00 00 01 28 00 03 00 00  |...........(....|
0x08A0: 00 01 00 02 00 00 01 52  00 03 00 00 00 01 00 01  |.......R........|
0x08B0: 00 00 01 53 00 03 00 00  00 04 00 00 08 D6 87 73  |...S...........s|
0x08C0: 00 07 00 00 02 30 00 00  08 DE 00 00 00 00 00 08  |.....0..........|
0x08D0: 00 08 00 08 00 08 00 01  00 01 00 01 00 01 00 00  |................|
0x08E0: 02 30 41 44 42 45 02 10  00 00 6D 6E 74 72 52 47  |.0ADBE....mntrRG|
0x08F0: 42 20 58 59 5A 20 07 D0  00 08 00 0B 00 13 00 33  |B XYZ .........3|
0x0900: 00 3B 61 63 73 70 41 50  50 4C 00 00 00 00 6E 6F  |.;acspAPPL....no|
0x0910: 6E 65 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |ne..............|
0x0920: 00 00 00 00 F6 D6 00 01  00 00 00 00 D3 2D 41 44  |.............-AD|
0x0930: 42 45 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |BE..............|
0x0940: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0950: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0960: 00 0A 63 70 72 74 00 00  00 FC 00 00 00 32 64 65  |..cprt.......2de|
0x0970: 73 63 00 00 01 30 00 00  00 6B 77 74 70 74 00 00  |sc...0...kwtpt..|
0x0980: 01 9C 00 00 00 14 62 6B  70 74 00 00 01 B0 00 00  |......bkpt......|
0x0990: 00 14 72 54 52 43 00 00  01 C4 00 00 00 0E 67 54  |..rTRC........gT|
0x09A0: 52 43 00 00 01 D4 00 00  00 0E 62 54 52 43 00 00  |RC........bTRC..|
0x09B0: 01 E4 00 00 00 0E 72 58  59 5A 00 00 01 F4 00 00  |......rXYZ......|
0x09C0: 00 14 67 58 59 5A 00 00  02 08 00 00 00 14 62 58  |..gXYZ........bX|
0x09D0: 59 5A 00 00 02 1C 00 00  00 14 74 65 78 74 00 00  |YZ........text..|
0x09E0: 00 00 43 6F 70 79 72 69  67 68 74 20 32 30 30 30  |..Copyright 2000|
0x09F0: 20 41 64 6F 62 65 20 53  79 73 74 65 6D 73 20 49  | Adobe Systems I|
0x0A00: 6E 63 6F 72 70 6F 72 61  74 65 64 00 00 00 64 65  |ncorporated...de|
0x0A10: 73 63 00 00 00 00 00 00  00 11 41 64 6F 62 65 20  |sc........Adobe |
0x0A20: 52 47 42 20 28 31 39 39  38 29 00 00 00 00 00 00  |RGB (1998)......|
0x0A30: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0A40: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0A50: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0A60: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0A70: 00 00 00 00 00 00 00 00  00 00 58 59 5A 20 00 00  |..........XYZ ..|
0x0A80: 00 00 00 00 F3 51 00 01  00 00 00 01 16 CC 58 59  |.....Q........XY|
0x0A90: 5A 20 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |Z ..............|
0x0AA0: 00 00 63 75 72 76 00 00  00 00 00 00 00 01 02 33  |..curv.........3|
0x0AB0: 00 00 63 75 72 76 00 00  00 00 00 00 00 01 02 33  |..curv.........3|
0x0AC0: 00 00 63 75 72 76 00 00  00 00 00 00 00 01 02 33  |..curv.........3|
0x0AD0: 00 00 58 59 5A 20 00 00  00 00 00 00 9C 18 00 00  |..XYZ ..........|
0x0AE0: 4F A5 00 00 04 FC 58 59  5A 20 00 00 00 00 00 00  |O.....XYZ ......|
0x0AF0: 34 8D 00 00 A0 2C 00 00  0F 95 58 59 5A 20 00 00  |4....,....XYZ ..|
0x0B00: 00 00 00 00 26 31 00 00  10 2F 00 00 BE 9C        |....&1.../....|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/catalyst-16bit-mismatch.tiff

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/h02332/po/research/test-profiles/catalyst-16bit-mismatch.tiff
```
