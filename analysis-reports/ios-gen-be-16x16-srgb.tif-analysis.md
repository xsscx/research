# ICC Profile Analysis Report

**Profile**: `test-profiles/ios-gen-be-16x16-srgb.tif`
**File Size**: 4118 bytes
**SHA-256**: `7bdc333070f956a1e11aec2430b27a975db3f2c0c405126c5630566e6a1ad8fa`
**File Type**: TIFF image data, big-endian, direntries=15, height=16, bps=0, compression=none, PhotometricInterpretation=RGB, orientation=upper-left, width=16
**Date**: 2026-03-08T19:58:22Z
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
File: /home/h02332/po/research/test-profiles/ios-gen-be-16x16-srgb.tif

--- TIFF Metadata ---
  Dimensions:      16 Ã— 16 pixels
  Bits/Sample:     8
  Samples/Pixel:   3
  Compression:     None (Uncompressed) (1)
  Photometric:     RGB (2)
  Planar Config:   Contiguous (Chunky) (1)
  Sample Format:   Unsigned Integer (1)
  Orientation:     1
  Rows/Strip:      16
  Strip Count:     1

--- TIFF Security Heuristics ---
[H139] TIFF Strip Geometry Validation (CWE-122/CWE-190)
      [OK] Strip geometry valid (bytesPerLine=48, stripSize=768, rowsPerStrip=16)

[H140] TIFF Dimension and Sample Validation (CWE-400/CWE-131)
      [OK] Dimensions 16Ã—16, BPS=8, SPP=3 (256 pixels)

[H141] TIFF IFD Offset Bounds Validation (CWE-125)
      [OK] All IFD offsets within file bounds (size=4118, pages=1)


--- Injection Signature Scan ---
  [OK] No injection signatures detected

--- Embedded ICC Profile ---
  [FOUND] ICC profile embedded (TIFFTAG_ICCPROFILE, tag 34675)
  Profile Size:    3144 bytes (3.1 KB)
  ICC Magic:       [OK] 'acsp' at offset 36
  ICC Version:     2.1

  Extracted to: /tmp/iccanalyzer-extracted-67332.icc

=======================================================================
EXTRACTED ICC PROFILE â€” FULL HEURISTIC ANALYSIS
=======================================================================


=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /tmp/iccanalyzer-extracted-67332.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /tmp/iccanalyzer-extracted-67332.icc

=======================================================================
EXTERNAL FILE METADATA
=======================================================================

  [file]
      Microsoft color profile 2.1, type Lino, RGB/XYZ-mntr device, IEC/sRGB model by HP, 3144 bytes, 9-2-1998 6:49:00 "sRGB IEC61966-2.1"

  [exiftool]
      ExifTool Version Number         : 12.76
      File Name                       : iccanalyzer-extracted-67332.icc
      Directory                       : /tmp
      File Size                       : 3.1 kB
      File Modification Date/Time     : 2026:03:08 15:58:22-04:00
      File Access Date/Time           : 2026:03:08 15:58:22-04:00
      File Inode Change Date/Time     : 2026:03:08 15:58:22-04:00
      File Permissions                : -rw-------
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
      Profile Copyright             ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
  : Copyright (c) 1998 Hewlett-Packard Company
      Profile Description             : sRGB IEC61966-2.1
      Media White Point               : 0.95045 1 1.08905

  [identify]
      Image:
        Filename: /tmp/iccanalyzer-extracted-67332.icc
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
      00000000: 0000 0c48 4c69 6e6f 0210 0000 6d6e 7472  ...HLino....mntr
      00000010: 5247 4220 5859 5a20 07ce 0002 0009 0006  RGB XYZ ........
      00000020: 0031 0000 6163 7370 4d53 4654 0000 0000  .1..acspMSFT....
      00000030: 4945 4320 7352 4742 0000 0000 0000 0000  IEC sRGB........
      00000040: 0000 0000 0000 f6d6 0001 0000 0000 d32d  ...............-
      00000050: 4850 2020 0000 0000 0000 0000 0000 0000  HP  ............
      00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
      00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................

  [sha256sum]
      2b3aa1645779a9e634744faf9b01e9102b0c9b88fd6deced7934df86b949af7e  /tmp/iccanalyzer-extracted-67332.icc

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

[H15] Date Validation (Â§4.2 dateTimeNumber): 1998-02-09 06:49:00
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
      Note: Tag signature â‰  tICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:344] IsValidTechnologySignature(): input = 0x43525420
ag type - must check tag DATA
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
      [WARN]  Matrix column sum (0.9643, 1.0000, 0.8251) deviates from D50
       Expected â‰ˆ (0.9505, 1.0000, 1.0890), deviation (0.0138, 0.0000, 0.2639)

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
      Row sums (â‰ˆD50 XYZ): [0.9643, 1.0000, 0.8251]
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
      [OK] 16 tags checked â€” all use allowed types

[H118] Calculator Computation Cost Estimate
      [INFO] No MPE calculator/CLUT elements found

[H119] Round-Trip Î”E Measurement
      [INFO] No AToB/BToA CLUT pairs available for Î”E measurement

[H120] Curve Invertibility Assessment
      rTRC (1024 entries): inv avg err=0.188974  max err=0.287135
      [WARN]  rTRC: poor invertibility (max err > 1%)
      gTRC (1024 entries): inv avg err=0.188974  max err=0.287135
      [WARN]  gTRC: poor invertibility (max err > 1%)
      bTRC (1024 entries): inv avg err=0.188974  max err=0.287135
      [WARN]  bTRC: poor invertibility (max err > 1%)

[H121] Characterization Data Round-Trip Capability
      [INFO] No characterization data (targ) tag â€” cannot assess

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
      Version bytes: 02 10 00 00 â†’ v2.1.0
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
       ICC.1-2022-05 Â§7.2.18: ID may be zero if not computed

[H132] chromaticAdaptation Matrix Validation
      [INFO] No chromaticAdaptation (chad) tag present

[H133] Profile Flags Reserved Bits (ICC.1-2022-05 Â§7.2.11)
      Flags: 0x00000000 (embedded=0, independent=0)
      [OK] Reserved flag bits are zero

[H134] Tag Type Reserved Bytes (ICC.1-2022-05 Â§10.1)
      [OK] All 17 tag types have zeroed reserved bytes

[H135] Duplicate Tag Signatures (ICC.1-2022-05 Â§7.3.1)
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
      [OK] 3 shared tag pair(s) â€” all immutable types (safe)
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
Profile: /tmp/iccanalyzer-extracted-67332.icc

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

File: /tmp/iccanalyzer-extracted-67332.icc
Total Issues Detected: 6

[WARN] ANALYSIS COMPLETE - 6 issue(s) detected
  Review detailed output above for security concerns.


=======================================================================
IMAGE ANALYSIS SUMMARY
=======================================================================
Format:     TIFF
Dimensions: 16 Ã— 16
Findings:   6
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

File: /home/h02332/po/research/test-profiles/ios-gen-be-16x16-srgb.tif
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 4118 bytes (0x1016)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 4D 4D 00 2A 00 00 03 08  2F 18 70 63 32 EA 63 32  |MM.*..../.pc2.c2|
0x0010: EA D3 B8 B5 AB AC BA 12  40 E7 12 40 E7 12 40 E7  |........@..@..@.|
0x0020: 12 40 E7 19 43 E7 B1 8E  FA B1 8E FA B1 8E FA B1  |.@..C...........|
0x0030: 84 EB B8 28 63 B8 28 63  12 09 2C 28 14 5F 94 53  |...(c.(c..,(._.S|
0x0040: C7 D9 C1 AF BC B8 B5 42  62 D8 42 62 D8 42 62 D8  |.......Bb.Bb.Bb.|
0x0050: 42 62 D8 47 64 D9 B1 8E  FA B1 8E FA B1 8E FA B1  |Bb.Gd...........|
0x0060: 84 EB B8 28 63 B8 28 63  00 00 00 00 00 00 B2 78  |...(c.(c.......x|
0x0070: AD DD CE A8 F9 E4 A4 F9  E4 A4 F9 E4 A4 F9 E4 A4  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x4D4D002A (1296891946 bytes) MISMATCH
  CMM:             0x00000308  '....'
  Version:         0x2F187063
  Device Class:    0x32EA6332  '2.c2'
  Color Space:     0xEAD3B8B5  '....'
  PCS:             0xABACBA12  '....'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 4192511221 (0xF9E4A4F5)
WARNING: Suspicious tag count (>1000) - possible corruption

Tag Table Raw Data:
0x0080: F9 E4 A4 F5 DF A8 B1 8E  FA B1 8E FA B1 8E FA B1  |................|
0x0090: 84 EB B8 28 63 B8 28 63  00 00 00 BF 71 AA 98 87  |...(c.(c....q...|
0x00A0: B4 D7 D2 AA F9 E4 A4 F9  E4 A4 F9 E4 A4 F9 E4 A4  |................|
0x00B0: F9 E4 A4 F5 DF A8 B1 8E  FA B1 8E FA B1 8E FA B1  |................|
0x00C0: 84 EB B8 28 63 B8 28 63  00 00 00 B2 78 AD 8B 8E  |...(c.(c....x...|
0x00D0: B7 A8 C2 B4 B0 D4 B3 A1  DC B7 99 8C 64 99 8C 64  |............d..d|
0x00E0: E9 98 78 E7 98 7F B1 8E  FA B1 8E FA B1 8E FA B1  |..x.............|
0x00F0: 84 EB B8 28 63 B8 28 63  BF 70 A9 98 87 B5 70 9D  |...(c.(c.p....p.|
0x0100: BE 4A B4 C9 23 CA D4 00  00 00 00 00 00 00 00 00  |.J..#...........|
0x0110: D0 20 34 D2 26 3E B1 8E  FA B1 8E FA B1 8E FA B1  |. 4.&>..........|
0x0120: 84 EB B8 28 63 B8 28 63  B2 78 AD 8B 8E B8 64 A5  |...(c.(c.x....d.|
0x0130: C2 3C BB CC 15 D1 D7 00  00 00 00 00 00 00 00 00  |.<..............|
0x0140: D1 20 35 D2 26 3E B1 8E  FA B1 8E FA B1 8E FA B1  |. 5.&>..........|
0x0150: 84 EB B8 28 63 B8 28 63  A4 7F B0 7E 96 BB 57 AC  |...(c.(c...~..W.|
0x0160: C5 2F C2 CF 00 00 00 00  00 00 00 00 00 4A 19 76  |./...........J.v|
0x0170: D2 21 37 D2 26 3E B1 8E  FA B1 8E FA B1 8E FA B1  |.!7.&>..........|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0xDFA8B18E   'ß¨±Ž'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
1    0x84EBB828   '„ë¸('        0x63B82863   0x000000BF   '----'        OOB offset
2    0x71AA9887   'qª˜‡'        0xB4D7D2AA   0xF9E4A4F9   '----'        OOB offset
3    0xE4A4F9E4   'ä¤ùä'        0xA4F9E4A4   0xF9E4A4F5   '----'        OOB offset
4    0xDFA8B18E   'ß¨±Ž'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
5    0x84EBB828   '„ë¸('        0x63B82863   0x000000B2   '----'        OOB offset
6    0x78AD8B8E   'x­‹Ž'        0xB7A8C2B4   0xB0D4B3A1   '----'        OOB offset
7    0xDCB7998C   'Ü·™Œ'        0x64998C64   0xE99878E7   '----'        OOB offset
8    0x987FB18E   '˜±Ž'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
9    0x84EBB828   '„ë¸('        0x63B82863   0xBF70A998   '----'        OOB offset
10   0x87B5709D   '‡µp'        0xBE4AB4C9   0x23CAD400   '----'        OOB offset
11   0x00000000   '    '        0x00000000   0xD02034D2   'MM  '        OOB size
12   0x263EB18E   '&>±Ž'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
13   0x84EBB828   '„ë¸('        0x63B82863   0xB278AD8B   '----'        OOB offset
14   0x8EB864A5   'Ž¸d¥'        0xC23CBBCC   0x15D1D700   '----'        OOB offset
15   0x00000000   '    '        0x00000000   0xD12035D2   'MM  '        OOB size
16   0x263EB18E   '&>±Ž'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
17   0x84EBB828   '„ë¸('        0x63B82863   0xA47FB07E   '----'        OOB offset
18   0x96BB57AC   '–»W¬'        0xC52FC2CF   0x00000000   '----'        OOB offset
19   0x00000000   '    '        0x004A1976   0xD22137D2   '----'        OOB offset
20   0x263EB18E   '&>±Ž'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
21   0x84EBB828   '„ë¸('        0x63B82863   0x8B8EB764   '----'        OOB offset
22   0xA5C23DBB   '¥Â=»'        0xCD16D2D7   0x00000004   '----'        OOB offset
23   0x01065B1F   '['        0x92882FDA   0xD22137D2   '----'        OOB offset
24   0x263EB18E   '&>±Ž'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
25   0x8BF6B272   '‹ö²r'        0xD1B272D1   0x7D95BB57   '----'        OOB offset
26   0xACC52FC2   '¬Å/Â'        0xD0000000   0x0A031069   '----'        OOB offset
27   0x24A8882F   '$¨ˆ/'        0xDA882FDA   0x942CBE95   '----'        OOB offset
28   0x30C0B18E   '0À±Ž'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
29   0x8EFAB18E   'Žú±Ž'        0xFAB18EFA   0x719DBE4A   '----'        OOB offset
30   0xB4C923CA   '´É#Ê'        0xD313061E   0x7428BA88   '----'        OOB offset
31   0x2FDA882F   '/Úˆ/'        0xDA882FDA   0x882FDA88   '----'        OOB offset
32   0x30DA8449   '0Ú„I'        0xC9463464   0x3D31573D   '----'        OOB offset
33   0x31573D31   '1W=1'        0x573D3157   0x57ACC62F   '----'        OOB offset
34   0xC2CF1E0A   'ÂÏ
'        0x307D2BC8   0x882FDA88   '----'        OOB offset
35   0x2FDA882F   '/Úˆ/'        0xDAA62CBA   0xAB2CB694   '----'        OOB offset
36   0x25985E14   '%˜^'        0x4A52113E   0x490F3740   '----'        OOB offset
37   0x0D30370B   '07'        0x290C0209   0x4AB4C943   '----'        OOB offset
38   0x97D5832D   '—Õƒ-'        0xD3882FDA   0x882FDA88   '----'        OOB offset
39   0x2FDA882F   '/Úˆ/'        0xDABD2AA3   0xC92A98C9   '----'        OOB offset
40   0x2A98C92A   '*˜É*'        0x98C92A98   0xC92A98C9   '----'        OOB offset
41   0x2A98C92A   '*˜É*'        0x982C0921   0x2FC2CF68   '----'        OOB offset
42   0x5BD9882F   '[Ùˆ/'        0xDA882FDA   0x882FDA88   '----'        OOB offset
43   0x2FDA872E   '/Ú‡.'        0xD93E1564   0x0200010B   '----'        OOB offset
44   0x02081404   ''        0x0F1D0616   0x26081D2F   '----'        OOB offset
45   0x0923380B   '	#8'        0x2A0B0208   0x22CAD307   '----'        OOB offset
46   0x020B7026   'p&'        0xB3882FDA   0x882FDA84   '----'        OOB offset
47   0x2DD42D0F   '-Ô-'        0x49000000   0x00000000   '----'        OOB offset
48   0x00000000   '    '        0x00000000   0x00000000   'MM  '        overlap
49   0x00000000   '    '        0x00000000   0x16D1D700   'MM  '        OOB size
50   0x00000E05   '    '        0x177A2AC3   0x7D2BC920   '----'        OOB offset
51   0x0B330000   '3  '        0x00000000   0x00000000   'MM  '        overlap
52   0x00000000   '    '        0x00000000   0x00000000   'MM  '        overlap
53   0x00000000   '    '        0x00000000   0x000F0100   'MM  '        OOB size
54   0x00030000   '    '        0x00010010   0x00000101   '----'        OOB offset
55   0x00030000   '    '        0x00010010   0x00000102   '----'        OOB offset
56   0x00030000   '    '        0x00030000   0x03C20103   '----'        OOB offset
57   0x00030000   '    '        0x00010001   0x00000106   '----'        OOB offset
58   0x00030000   '    '        0x00010002   0x0000010A   '----'        OOB offset
59   0x00030000   '    '        0x00010001   0x00000111   '----'        OOB offset
60   0x00040000   '    '        0x00010000   0x00080112   '----'        OOB offset
61   0x00030000   '    '        0x00010001   0x00000115   '----'        OOB offset
62   0x00030000   '    '        0x00010003   0x00000116   '----'        OOB offset
63   0x00030000   '    '        0x00010010   0x00000117   '----'        OOB offset
64   0x00040000   '    '        0x00010000   0x0300011C   '----'        OOB offset
65   0x00030000   '    '        0x00010001   0x00000128   '----'        OOB offset
66   0x00030000   '    '        0x00010002   0x00000153   '----'        OOB offset
67   0x00030000   '    '        0x00030000   0x03C88773   '----'        OOB offset
68   0x00070000   '    '        0x0C480000   0x03CE0000   '----'        OOB offset
69   0x00000008   '    '        0x00080008   0x00010001   '----'        OOB offset
70   0x00010000   '    '        0x0C484C69   0x6E6F0210   '----'        OOB offset
71   0x00006D6E   '    '        0x74725247   0x42205859   '----'        OOB offset
72   0x5A2007CE   'Z Î'        0x00020009   0x00060031   '----'        OOB offset
73   0x00006163   '    '        0x73704D53   0x46540000   '----'        OOB offset
74   0x00004945   '    '        0x43207352   0x47420000   '----'        OOB offset
75   0x00000000   '    '        0x00000000   0x00000000   'MM  '        overlap
76   0xF6D60001   'öÖ  '        0x00000000   0xD32D4850   'MM  '        OOB size
77   0x20200000   '    '        0x00000000   0x00000000   'MM  '        overlap
78   0x00000000   '    '        0x00000000   0x00000000   'MM  '        overlap
79   0x00000000   '    '        0x00000000   0x00000000   'MM  '        overlap
80   0x00000000   '    '        0x00000000   0x00000000   'MM  '        overlap
81   0x00116370   '    '        0x72740000   0x01500000   '----'        OOB offset
82   0x00336465   '    '        0x73630000   0x01840000   '----'        OOB offset
83   0x006C7774   '    '        0x70740000   0x01F00000   '----'        OOB offset
84   0x0014626B   '    '        0x70740000   0x02040000   '----'        OOB offset
85   0x00147258   '    '        0x595A0000   0x02180000   '----'        OOB offset
86   0x00146758   '    '        0x595A0000   0x022C0000   '----'        OOB offset
87   0x00146258   '    '        0x595A0000   0x02400000   '----'        OOB offset
88   0x0014646D   '    '        0x6E640000   0x02540000   '----'        OOB offset
89   0x0070646D   '    '        0x64640000   0x02C40000   '----'        OOB offset
90   0x00887675   '    '        0x65640000   0x034C0000   '----'        OOB offset
91   0x00867669   '    '        0x65770000   0x03D40000   '----'        OOB offset
92   0x00246C75   '    '        0x6D690000   0x03F80000   '----'        OOB offset
93   0x00146D65   '    '        0x61730000   0x040C0000   '----'        OOB offset
94   0x00247465   '    '        0x63680000   0x04300000   '----'        OOB offset
95   0x000C7254   '    '        0x52430000   0x043C0000   '----'        OOB offset
96   0x080C6754   'gT'        0x52430000   0x043C0000   '----'        OOB offset
97   0x080C6254   'bT'        0x52430000   0x043C0000   '----'        OOB offset
98   0x080C7465   'te'        0x78740000   0x0000436F   '----'        OOB offset
99   0x70797269   'pyri'        0x67687420   0x28632920   '----'        OOB offset
... (4192511121 more tags not shown)

[WARN] SIZE INFLATION: Header claims 1296891946 bytes, file is 4118 bytes (314932x)
   Risk: OOM via tag-internal allocations based on inflated header size

[WARN] TAG OVERLAP: 1208 overlapping tag pair(s) detected
   Risk: Data corruption, possible exploit crafting

=== FULL FILE HEX DUMP (all 4118 bytes) ===
0x0000: 4D 4D 00 2A 00 00 03 08  2F 18 70 63 32 EA 63 32  |MM.*..../.pc2.c2|
0x0010: EA D3 B8 B5 AB AC BA 12  40 E7 12 40 E7 12 40 E7  |........@..@..@.|
0x0020: 12 40 E7 19 43 E7 B1 8E  FA B1 8E FA B1 8E FA B1  |.@..C...........|
0x0030: 84 EB B8 28 63 B8 28 63  12 09 2C 28 14 5F 94 53  |...(c.(c..,(._.S|
0x0040: C7 D9 C1 AF BC B8 B5 42  62 D8 42 62 D8 42 62 D8  |.......Bb.Bb.Bb.|
0x0050: 42 62 D8 47 64 D9 B1 8E  FA B1 8E FA B1 8E FA B1  |Bb.Gd...........|
0x0060: 84 EB B8 28 63 B8 28 63  00 00 00 00 00 00 B2 78  |...(c.(c.......x|
0x0070: AD DD CE A8 F9 E4 A4 F9  E4 A4 F9 E4 A4 F9 E4 A4  |................|
0x0080: F9 E4 A4 F5 DF A8 B1 8E  FA B1 8E FA B1 8E FA B1  |................|
0x0090: 84 EB B8 28 63 B8 28 63  00 00 00 BF 71 AA 98 87  |...(c.(c....q...|
0x00A0: B4 D7 D2 AA F9 E4 A4 F9  E4 A4 F9 E4 A4 F9 E4 A4  |................|
0x00B0: F9 E4 A4 F5 DF A8 B1 8E  FA B1 8E FA B1 8E FA B1  |................|
0x00C0: 84 EB B8 28 63 B8 28 63  00 00 00 B2 78 AD 8B 8E  |...(c.(c....x...|
0x00D0: B7 A8 C2 B4 B0 D4 B3 A1  DC B7 99 8C 64 99 8C 64  |............d..d|
0x00E0: E9 98 78 E7 98 7F B1 8E  FA B1 8E FA B1 8E FA B1  |..x.............|
0x00F0: 84 EB B8 28 63 B8 28 63  BF 70 A9 98 87 B5 70 9D  |...(c.(c.p....p.|
0x0100: BE 4A B4 C9 23 CA D4 00  00 00 00 00 00 00 00 00  |.J..#...........|
0x0110: D0 20 34 D2 26 3E B1 8E  FA B1 8E FA B1 8E FA B1  |. 4.&>..........|
0x0120: 84 EB B8 28 63 B8 28 63  B2 78 AD 8B 8E B8 64 A5  |...(c.(c.x....d.|
0x0130: C2 3C BB CC 15 D1 D7 00  00 00 00 00 00 00 00 00  |.<..............|
0x0140: D1 20 35 D2 26 3E B1 8E  FA B1 8E FA B1 8E FA B1  |. 5.&>..........|
0x0150: 84 EB B8 28 63 B8 28 63  A4 7F B0 7E 96 BB 57 AC  |...(c.(c...~..W.|
0x0160: C5 2F C2 CF 00 00 00 00  00 00 00 00 00 4A 19 76  |./...........J.v|
0x0170: D2 21 37 D2 26 3E B1 8E  FA B1 8E FA B1 8E FA B1  |.!7.&>..........|
0x0180: 84 EB B8 28 63 B8 28 63  8B 8E B7 64 A5 C2 3D BB  |...(c.(c...d..=.|
0x0190: CD 16 D2 D7 00 00 00 04  01 06 5B 1F 92 88 2F DA  |..........[.../.|
0x01A0: D2 21 37 D2 26 3E B1 8E  FA B1 8E FA B1 8E FA B1  |.!7.&>..........|
0x01B0: 8B F6 B2 72 D1 B2 72 D1  7D 95 BB 57 AC C5 2F C2  |...r..r.}..W../.|
0x01C0: D0 00 00 00 0A 03 10 69  24 A8 88 2F DA 88 2F DA  |.......i$../../.|
0x01D0: 94 2C BE 95 30 C0 B1 8E  FA B1 8E FA B1 8E FA B1  |.,..0...........|
0x01E0: 8E FA B1 8E FA B1 8E FA  71 9D BE 4A B4 C9 23 CA  |........q..J..#.|
0x01F0: D3 13 06 1E 74 28 BA 88  2F DA 88 2F DA 88 2F DA  |....t(../../../.|
0x0200: 88 2F DA 88 30 DA 84 49  C9 46 34 64 3D 31 57 3D  |./..0..I.F4d=1W=|
0x0210: 31 57 3D 31 57 3D 31 57  57 AC C6 2F C2 CF 1E 0A  |1W=1W=1WW../....|
0x0220: 30 7D 2B C8 88 2F DA 88  2F DA 88 2F DA A6 2C BA  |0}+../../../..,.|
0x0230: AB 2C B6 94 25 98 5E 14  4A 52 11 3E 49 0F 37 40  |.,..%.^.JR.>I.7@|
0x0240: 0D 30 37 0B 29 0C 02 09  4A B4 C9 43 97 D5 83 2D  |.07.)...J..C...-|
0x0250: D3 88 2F DA 88 2F DA 88  2F DA 88 2F DA BD 2A A3  |../../../../..*.|
0x0260: C9 2A 98 C9 2A 98 C9 2A  98 C9 2A 98 C9 2A 98 C9  |.*..*..*..*..*..|
0x0270: 2A 98 C9 2A 98 2C 09 21  2F C2 CF 68 5B D9 88 2F  |*..*.,.!/..h[../|
0x0280: DA 88 2F DA 88 2F DA 88  2F DA 87 2E D9 3E 15 64  |../../../....>.d|
0x0290: 02 00 01 0B 02 08 14 04  0F 1D 06 16 26 08 1D 2F  |............&../|
0x02A0: 09 23 38 0B 2A 0B 02 08  22 CA D3 07 02 0B 70 26  |.#8.*...".....p&|
0x02B0: B3 88 2F DA 88 2F DA 84  2D D4 2D 0F 49 00 00 00  |../../..-.-.I...|
0x02C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x02D0: 00 00 00 00 00 00 00 00  16 D1 D7 00 00 00 0E 05  |................|
0x02E0: 17 7A 2A C3 7D 2B C9 20  0B 33 00 00 00 00 00 00  |.z*.}+. .3......|
0x02F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0300: 00 00 00 00 00 00 00 00  00 0F 01 00 00 03 00 00  |................|
0x0310: 00 01 00 10 00 00 01 01  00 03 00 00 00 01 00 10  |................|
0x0320: 00 00 01 02 00 03 00 00  00 03 00 00 03 C2 01 03  |................|
0x0330: 00 03 00 00 00 01 00 01  00 00 01 06 00 03 00 00  |................|
0x0340: 00 01 00 02 00 00 01 0A  00 03 00 00 00 01 00 01  |................|
0x0350: 00 00 01 11 00 04 00 00  00 01 00 00 00 08 01 12  |................|
0x0360: 00 03 00 00 00 01 00 01  00 00 01 15 00 03 00 00  |................|
0x0370: 00 01 00 03 00 00 01 16  00 03 00 00 00 01 00 10  |................|
0x0380: 00 00 01 17 00 04 00 00  00 01 00 00 03 00 01 1C  |................|
0x0390: 00 03 00 00 00 01 00 01  00 00 01 28 00 03 00 00  |...........(....|
0x03A0: 00 01 00 02 00 00 01 53  00 03 00 00 00 03 00 00  |.......S........|
0x03B0: 03 C8 87 73 00 07 00 00  0C 48 00 00 03 CE 00 00  |...s.....H......|
0x03C0: 00 00 00 08 00 08 00 08  00 01 00 01 00 01 00 00  |................|
0x03D0: 0C 48 4C 69 6E 6F 02 10  00 00 6D 6E 74 72 52 47  |.HLino....mntrRG|
0x03E0: 42 20 58 59 5A 20 07 CE  00 02 00 09 00 06 00 31  |B XYZ .........1|
0x03F0: 00 00 61 63 73 70 4D 53  46 54 00 00 00 00 49 45  |..acspMSFT....IE|
0x0400: 43 20 73 52 47 42 00 00  00 00 00 00 00 00 00 00  |C sRGB..........|
0x0410: 00 00 00 00 F6 D6 00 01  00 00 00 00 D3 2D 48 50  |.............-HP|
0x0420: 20 20 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ..............|
0x0430: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0440: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0450: 00 11 63 70 72 74 00 00  01 50 00 00 00 33 64 65  |..cprt...P...3de|
0x0460: 73 63 00 00 01 84 00 00  00 6C 77 74 70 74 00 00  |sc.......lwtpt..|
0x0470: 01 F0 00 00 00 14 62 6B  70 74 00 00 02 04 00 00  |......bkpt......|
0x0480: 00 14 72 58 59 5A 00 00  02 18 00 00 00 14 67 58  |..rXYZ........gX|
0x0490: 59 5A 00 00 02 2C 00 00  00 14 62 58 59 5A 00 00  |YZ...,....bXYZ..|
0x04A0: 02 40 00 00 00 14 64 6D  6E 64 00 00 02 54 00 00  |.@....dmnd...T..|
0x04B0: 00 70 64 6D 64 64 00 00  02 C4 00 00 00 88 76 75  |.pdmdd........vu|
0x04C0: 65 64 00 00 03 4C 00 00  00 86 76 69 65 77 00 00  |ed...L....view..|
0x04D0: 03 D4 00 00 00 24 6C 75  6D 69 00 00 03 F8 00 00  |.....$lumi......|
0x04E0: 00 14 6D 65 61 73 00 00  04 0C 00 00 00 24 74 65  |..meas.......$te|
0x04F0: 63 68 00 00 04 30 00 00  00 0C 72 54 52 43 00 00  |ch...0....rTRC..|
0x0500: 04 3C 00 00 08 0C 67 54  52 43 00 00 04 3C 00 00  |.<....gTRC...<..|
0x0510: 08 0C 62 54 52 43 00 00  04 3C 00 00 08 0C 74 65  |..bTRC...<....te|
0x0520: 78 74 00 00 00 00 43 6F  70 79 72 69 67 68 74 20  |xt....Copyright |
0x0530: 28 63 29 20 31 39 39 38  20 48 65 77 6C 65 74 74  |(c) 1998 Hewlett|
0x0540: 2D 50 61 63 6B 61 72 64  20 43 6F 6D 70 61 6E 79  |-Packard Company|
0x0550: 00 00 64 65 73 63 00 00  00 00 00 00 00 12 73 52  |..desc........sR|
0x0560: 47 42 20 49 45 43 36 31  39 36 36 2D 32 2E 31 00  |GB IEC61966-2.1.|
0x0570: 00 00 00 00 00 00 00 00  00 00 12 73 52 47 42 20  |...........sRGB |
0x0580: 49 45 43 36 31 39 36 36  2D 32 2E 31 00 00 00 00  |IEC61966-2.1....|
0x0590: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x05A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x05B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 58 59  |..............XY|
0x05C0: 5A 20 00 00 00 00 00 00  F3 51 00 01 00 00 00 01  |Z .......Q......|
0x05D0: 16 CC 58 59 5A 20 00 00  00 00 00 00 00 00 00 00  |..XYZ ..........|
0x05E0: 00 00 00 00 00 00 58 59  5A 20 00 00 00 00 00 00  |......XYZ ......|
0x05F0: 6F A2 00 00 38 F5 00 00  03 90 58 59 5A 20 00 00  |o...8.....XYZ ..|
0x0600: 00 00 00 00 62 99 00 00  B7 85 00 00 18 DA 58 59  |....b.........XY|
0x0610: 5A 20 00 00 00 00 00 00  24 A0 00 00 0F 84 00 00  |Z ......$.......|
0x0620: B6 CF 64 65 73 63 00 00  00 00 00 00 00 16 49 45  |..desc........IE|
0x0630: 43 20 68 74 74 70 3A 2F  2F 77 77 77 2E 69 65 63  |C http://www.iec|
0x0640: 2E 63 68 00 00 00 00 00  00 00 00 00 00 00 16 49  |.ch............I|
0x0650: 45 43 20 68 74 74 70 3A  2F 2F 77 77 77 2E 69 65  |EC http://www.ie|
0x0660: 63 2E 63 68 00 00 00 00  00 00 00 00 00 00 00 00  |c.ch............|
0x0670: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0680: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0690: 00 00 64 65 73 63 00 00  00 00 00 00 00 2E 49 45  |..desc........IE|
0x06A0: 43 20 36 31 39 36 36 2D  32 2E 31 20 44 65 66 61  |C 61966-2.1 Defa|
0x06B0: 75 6C 74 20 52 47 42 20  63 6F 6C 6F 75 72 20 73  |ult RGB colour s|
0x06C0: 70 61 63 65 20 2D 20 73  52 47 42 00 00 00 00 00  |pace - sRGB.....|
0x06D0: 00 00 00 00 00 00 2E 49  45 43 20 36 31 39 36 36  |.......IEC 61966|
0x06E0: 2D 32 2E 31 20 44 65 66  61 75 6C 74 20 52 47 42  |-2.1 Default RGB|
0x06F0: 20 63 6F 6C 6F 75 72 20  73 70 61 63 65 20 2D 20  | colour space - |
0x0700: 73 52 47 42 00 00 00 00  00 00 00 00 00 00 00 00  |sRGB............|
0x0710: 00 00 00 00 00 00 00 00  00 00 64 65 73 63 00 00  |..........desc..|
0x0720: 00 00 00 00 00 2C 52 65  66 65 72 65 6E 63 65 20  |.....,Reference |
0x0730: 56 69 65 77 69 6E 67 20  43 6F 6E 64 69 74 69 6F  |Viewing Conditio|
0x0740: 6E 20 69 6E 20 49 45 43  36 31 39 36 36 2D 32 2E  |n in IEC61966-2.|
0x0750: 31 00 00 00 00 00 00 00  00 00 00 00 2C 52 65 66  |1...........,Ref|
0x0760: 65 72 65 6E 63 65 20 56  69 65 77 69 6E 67 20 43  |erence Viewing C|
0x0770: 6F 6E 64 69 74 69 6F 6E  20 69 6E 20 49 45 43 36  |ondition in IEC6|
0x0780: 31 39 36 36 2D 32 2E 31  00 00 00 00 00 00 00 00  |1966-2.1........|
0x0790: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x07A0: 00 00 76 69 65 77 00 00  00 00 00 13 A4 FE 00 14  |..view..........|
0x07B0: 5F 2E 00 10 CF 14 00 03  ED CC 00 04 13 0B 00 03  |_...............|
0x07C0: 5C 9E 00 00 00 01 58 59  5A 20 00 00 00 00 00 4C  |\.....XYZ .....L|
0x07D0: 09 56 00 50 00 00 00 57  1F E7 6D 65 61 73 00 00  |.V.P...W..meas..|
0x07E0: 00 00 00 00 00 01 00 00  00 00 00 00 00 00 00 00  |................|
0x07F0: 00 00 00 00 00 00 00 00  02 8F 00 00 00 02 73 69  |..............si|
0x0800: 67 20 00 00 00 00 43 52  54 20 63 75 72 76 00 00  |g ....CRT curv..|
0x0810: 00 00 00 00 04 00 00 00  00 05 00 0A 00 0F 00 14  |................|
0x0820: 00 19 00 1E 00 23 00 28  00 2D 00 32 00 37 00 3B  |.....#.(.-.2.7.;|
0x0830: 00 40 00 45 00 4A 00 4F  00 54 00 59 00 5E 00 63  |.@.E.J.O.T.Y.^.c|
0x0840: 00 68 00 6D 00 72 00 77  00 7C 00 81 00 86 00 8B  |.h.m.r.w.|......|
0x0850: 00 90 00 95 00 9A 00 9F  00 A4 00 A9 00 AE 00 B2  |................|
0x0860: 00 B7 00 BC 00 C1 00 C6  00 CB 00 D0 00 D5 00 DB  |................|
0x0870: 00 E0 00 E5 00 EB 00 F0  00 F6 00 FB 01 01 01 07  |................|
0x0880: 01 0D 01 13 01 19 01 1F  01 25 01 2B 01 32 01 38  |.........%.+.2.8|
0x0890: 01 3E 01 45 01 4C 01 52  01 59 01 60 01 67 01 6E  |.>.E.L.R.Y.`.g.n|
0x08A0: 01 75 01 7C 01 83 01 8B  01 92 01 9A 01 A1 01 A9  |.u.|............|
0x08B0: 01 B1 01 B9 01 C1 01 C9  01 D1 01 D9 01 E1 01 E9  |................|
0x08C0: 01 F2 01 FA 02 03 02 0C  02 14 02 1D 02 26 02 2F  |.............&./|
0x08D0: 02 38 02 41 02 4B 02 54  02 5D 02 67 02 71 02 7A  |.8.A.K.T.].g.q.z|
0x08E0: 02 84 02 8E 02 98 02 A2  02 AC 02 B6 02 C1 02 CB  |................|
0x08F0: 02 D5 02 E0 02 EB 02 F5  03 00 03 0B 03 16 03 21  |...............!|
0x0900: 03 2D 03 38 03 43 03 4F  03 5A 03 66 03 72 03 7E  |.-.8.C.O.Z.f.r.~|
0x0910: 03 8A 03 96 03 A2 03 AE  03 BA 03 C7 03 D3 03 E0  |................|
0x0920: 03 EC 03 F9 04 06 04 13  04 20 04 2D 04 3B 04 48  |......... .-.;.H|
0x0930: 04 55 04 63 04 71 04 7E  04 8C 04 9A 04 A8 04 B6  |.U.c.q.~........|
0x0940: 04 C4 04 D3 04 E1 04 F0  04 FE 05 0D 05 1C 05 2B  |...............+|
0x0950: 05 3A 05 49 05 58 05 67  05 77 05 86 05 96 05 A6  |.:.I.X.g.w......|
0x0960: 05 B5 05 C5 05 D5 05 E5  05 F6 06 06 06 16 06 27  |...............'|
0x0970: 06 37 06 48 06 59 06 6A  06 7B 06 8C 06 9D 06 AF  |.7.H.Y.j.{......|
0x0980: 06 C0 06 D1 06 E3 06 F5  07 07 07 19 07 2B 07 3D  |.............+.=|
0x0990: 07 4F 07 61 07 74 07 86  07 99 07 AC 07 BF 07 D2  |.O.a.t..........|
0x09A0: 07 E5 07 F8 08 0B 08 1F  08 32 08 46 08 5A 08 6E  |.........2.F.Z.n|
0x09B0: 08 82 08 96 08 AA 08 BE  08 D2 08 E7 08 FB 09 10  |................|
0x09C0: 09 25 09 3A 09 4F 09 64  09 79 09 8F 09 A4 09 BA  |.%.:.O.d.y......|
0x09D0: 09 CF 09 E5 09 FB 0A 11  0A 27 0A 3D 0A 54 0A 6A  |.........'.=.T.j|
0x09E0: 0A 81 0A 98 0A AE 0A C5  0A DC 0A F3 0B 0B 0B 22  |..............."|
0x09F0: 0B 39 0B 51 0B 69 0B 80  0B 98 0B B0 0B C8 0B E1  |.9.Q.i..........|
0x0A00: 0B F9 0C 12 0C 2A 0C 43  0C 5C 0C 75 0C 8E 0C A7  |.....*.C.\.u....|
0x0A10: 0C C0 0C D9 0C F3 0D 0D  0D 26 0D 40 0D 5A 0D 74  |.........&.@.Z.t|
0x0A20: 0D 8E 0D A9 0D C3 0D DE  0D F8 0E 13 0E 2E 0E 49  |...............I|
0x0A30: 0E 64 0E 7F 0E 9B 0E B6  0E D2 0E EE 0F 09 0F 25  |.d.............%|
0x0A40: 0F 41 0F 5E 0F 7A 0F 96  0F B3 0F CF 0F EC 10 09  |.A.^.z..........|
0x0A50: 10 26 10 43 10 61 10 7E  10 9B 10 B9 10 D7 10 F5  |.&.C.a.~........|
0x0A60: 11 13 11 31 11 4F 11 6D  11 8C 11 AA 11 C9 11 E8  |...1.O.m........|
0x0A70: 12 07 12 26 12 45 12 64  12 84 12 A3 12 C3 12 E3  |...&.E.d........|
0x0A80: 13 03 13 23 13 43 13 63  13 83 13 A4 13 C5 13 E5  |...#.C.c........|
0x0A90: 14 06 14 27 14 49 14 6A  14 8B 14 AD 14 CE 14 F0  |...'.I.j........|
0x0AA0: 15 12 15 34 15 56 15 78  15 9B 15 BD 15 E0 16 03  |...4.V.x........|
0x0AB0: 16 26 16 49 16 6C 16 8F  16 B2 16 D6 16 FA 17 1D  |.&.I.l..........|
0x0AC0: 17 41 17 65 17 89 17 AE  17 D2 17 F7 18 1B 18 40  |.A.e...........@|
0x0AD0: 18 65 18 8A 18 AF 18 D5  18 FA 19 20 19 45 19 6B  |.e......... .E.k|
0x0AE0: 19 91 19 B7 19 DD 1A 04  1A 2A 1A 51 1A 77 1A 9E  |.........*.Q.w..|
0x0AF0: 1A C5 1A EC 1B 14 1B 3B  1B 63 1B 8A 1B B2 1B DA  |.......;.c......|
0x0B00: 1C 02 1C 2A 1C 52 1C 7B  1C A3 1C CC 1C F5 1D 1E  |...*.R.{........|
0x0B10: 1D 47 1D 70 1D 99 1D C3  1D EC 1E 16 1E 40 1E 6A  |.G.p.........@.j|
0x0B20: 1E 94 1E BE 1E E9 1F 13  1F 3E 1F 69 1F 94 1F BF  |.........>.i....|
0x0B30: 1F EA 20 15 20 41 20 6C  20 98 20 C4 20 F0 21 1C  |.. . A l . . .!.|
0x0B40: 21 48 21 75 21 A1 21 CE  21 FB 22 27 22 55 22 82  |!H!u!.!.!."'"U".|
0x0B50: 22 AF 22 DD 23 0A 23 38  23 66 23 94 23 C2 23 F0  |".".#.#8#f#.#.#.|
0x0B60: 24 1F 24 4D 24 7C 24 AB  24 DA 25 09 25 38 25 68  |$.$M$|$.$.%.%8%h|
0x0B70: 25 97 25 C7 25 F7 26 27  26 57 26 87 26 B7 26 E8  |%.%.%.&'&W&.&.&.|
0x0B80: 27 18 27 49 27 7A 27 AB  27 DC 28 0D 28 3F 28 71  |'.'I'z'.'.(.(?(q|
0x0B90: 28 A2 28 D4 29 06 29 38  29 6B 29 9D 29 D0 2A 02  |(.(.).)8)k).).*.|
0x0BA0: 2A 35 2A 68 2A 9B 2A CF  2B 02 2B 36 2B 69 2B 9D  |*5*h*.*.+.+6+i+.|
0x0BB0: 2B D1 2C 05 2C 39 2C 6E  2C A2 2C D7 2D 0C 2D 41  |+.,.,9,n,.,.-.-A|
0x0BC0: 2D 76 2D AB 2D E1 2E 16  2E 4C 2E 82 2E B7 2E EE  |-v-.-....L......|
0x0BD0: 2F 24 2F 5A 2F 91 2F C7  2F FE 30 35 30 6C 30 A4  |/$/Z/././.050l0.|
0x0BE0: 30 DB 31 12 31 4A 31 82  31 BA 31 F2 32 2A 32 63  |0.1.1J1.1.1.2*2c|
0x0BF0: 32 9B 32 D4 33 0D 33 46  33 7F 33 B8 33 F1 34 2B  |2.2.3.3F3.3.3.4+|
0x0C00: 34 65 34 9E 34 D8 35 13  35 4D 35 87 35 C2 35 FD  |4e4.4.5.5M5.5.5.|
0x0C10: 36 37 36 72 36 AE 36 E9  37 24 37 60 37 9C 37 D7  |676r6.6.7$7`7.7.|
0x0C20: 38 14 38 50 38 8C 38 C8  39 05 39 42 39 7F 39 BC  |8.8P8.8.9.9B9.9.|
0x0C30: 39 F9 3A 36 3A 74 3A B2  3A EF 3B 2D 3B 6B 3B AA  |9.:6:t:.:.;-;k;.|
0x0C40: 3B E8 3C 27 3C 65 3C A4  3C E3 3D 22 3D 61 3D A1  |;.<'<e<.<.="=a=.|
0x0C50: 3D E0 3E 20 3E 60 3E A0  3E E0 3F 21 3F 61 3F A2  |=.> >`>.>.?!?a?.|
0x0C60: 3F E2 40 23 40 64 40 A6  40 E7 41 29 41 6A 41 AC  |?.@#@d@.@.A)AjA.|
0x0C70: 41 EE 42 30 42 72 42 B5  42 F7 43 3A 43 7D 43 C0  |A.B0BrB.B.C:C}C.|
0x0C80: 44 03 44 47 44 8A 44 CE  45 12 45 55 45 9A 45 DE  |D.DGD.D.E.EUE.E.|
0x0C90: 46 22 46 67 46 AB 46 F0  47 35 47 7B 47 C0 48 05  |F"FgF.F.G5G{G.H.|
0x0CA0: 48 4B 48 91 48 D7 49 1D  49 63 49 A9 49 F0 4A 37  |HKH.H.I.IcI.I.J7|
0x0CB0: 4A 7D 4A C4 4B 0C 4B 53  4B 9A 4B E2 4C 2A 4C 72  |J}J.K.KSK.K.L*Lr|
0x0CC0: 4C BA 4D 02 4D 4A 4D 93  4D DC 4E 25 4E 6E 4E B7  |L.M.MJM.M.N%NnN.|
0x0CD0: 4F 00 4F 49 4F 93 4F DD  50 27 50 71 50 BB 51 06  |O.OIO.O.P'PqP.Q.|
0x0CE0: 51 50 51 9B 51 E6 52 31  52 7C 52 C7 53 13 53 5F  |QPQ.Q.R1R|R.S.S_|
0x0CF0: 53 AA 53 F6 54 42 54 8F  54 DB 55 28 55 75 55 C2  |S.S.TBT.T.U(UuU.|
0x0D00: 56 0F 56 5C 56 A9 56 F7  57 44 57 92 57 E0 58 2F  |V.V\V.V.WDW.W.X/|
0x0D10: 58 7D 58 CB 59 1A 59 69  59 B8 5A 07 5A 56 5A A6  |X}X.Y.YiY.Z.ZVZ.|
0x0D20: 5A F5 5B 45 5B 95 5B E5  5C 35 5C 86 5C D6 5D 27  |Z.[E[.[.\5\.\.]'|
0x0D30: 5D 78 5D C9 5E 1A 5E 6C  5E BD 5F 0F 5F 61 5F B3  |]x].^.^l^._._a_.|
0x0D40: 60 05 60 57 60 AA 60 FC  61 4F 61 A2 61 F5 62 49  |`.`W`.`.aOa.a.bI|
0x0D50: 62 9C 62 F0 63 43 63 97  63 EB 64 40 64 94 64 E9  |b.b.cCc.c.d@d.d.|
0x0D60: 65 3D 65 92 65 E7 66 3D  66 92 66 E8 67 3D 67 93  |e=e.e.f=f.f.g=g.|
0x0D70: 67 E9 68 3F 68 96 68 EC  69 43 69 9A 69 F1 6A 48  |g.h?h.h.iCi.i.jH|
0x0D80: 6A 9F 6A F7 6B 4F 6B A7  6B FF 6C 57 6C AF 6D 08  |j.j.kOk.k.lWl.m.|
0x0D90: 6D 60 6D B9 6E 12 6E 6B  6E C4 6F 1E 6F 78 6F D1  |m`m.n.nkn.o.oxo.|
0x0DA0: 70 2B 70 86 70 E0 71 3A  71 95 71 F0 72 4B 72 A6  |p+p.p.q:q.q.rKr.|
0x0DB0: 73 01 73 5D 73 B8 74 14  74 70 74 CC 75 28 75 85  |s.s]s.t.tpt.u(u.|
0x0DC0: 75 E1 76 3E 76 9B 76 F8  77 56 77 B3 78 11 78 6E  |u.v>v.v.wVw.x.xn|
0x0DD0: 78 CC 79 2A 79 89 79 E7  7A 46 7A A5 7B 04 7B 63  |x.y*y.y.zFz.{.{c|
0x0DE0: 7B C2 7C 21 7C 81 7C E1  7D 41 7D A1 7E 01 7E 62  |{.|!|.|.}A}.~.~b|
0x0DF0: 7E C2 7F 23 7F 84 7F E5  80 47 80 A8 81 0A 81 6B  |~..#.....G.....k|
0x0E00: 81 CD 82 30 82 92 82 F4  83 57 83 BA 84 1D 84 80  |...0.....W......|
0x0E10: 84 E3 85 47 85 AB 86 0E  86 72 86 D7 87 3B 87 9F  |...G.....r...;..|
0x0E20: 88 04 88 69 88 CE 89 33  89 99 89 FE 8A 64 8A CA  |...i...3.....d..|
0x0E30: 8B 30 8B 96 8B FC 8C 63  8C CA 8D 31 8D 98 8D FF  |.0.....c...1....|
0x0E40: 8E 66 8E CE 8F 36 8F 9E  90 06 90 6E 90 D6 91 3F  |.f...6.....n...?|
0x0E50: 91 A8 92 11 92 7A 92 E3  93 4D 93 B6 94 20 94 8A  |.....z...M... ..|
0x0E60: 94 F4 95 5F 95 C9 96 34  96 9F 97 0A 97 75 97 E0  |..._...4.....u..|
0x0E70: 98 4C 98 B8 99 24 99 90  99 FC 9A 68 9A D5 9B 42  |.L...$.....h...B|
0x0E80: 9B AF 9C 1C 9C 89 9C F7  9D 64 9D D2 9E 40 9E AE  |.........d...@..|
0x0E90: 9F 1D 9F 8B 9F FA A0 69  A0 D8 A1 47 A1 B6 A2 26  |.......i...G...&|
0x0EA0: A2 96 A3 06 A3 76 A3 E6  A4 56 A4 C7 A5 38 A5 A9  |.....v...V...8..|
0x0EB0: A6 1A A6 8B A6 FD A7 6E  A7 E0 A8 52 A8 C4 A9 37  |.......n...R...7|
0x0EC0: A9 A9 AA 1C AA 8F AB 02  AB 75 AB E9 AC 5C AC D0  |.........u...\..|
0x0ED0: AD 44 AD B8 AE 2D AE A1  AF 16 AF 8B B0 00 B0 75  |.D...-.........u|
0x0EE0: B0 EA B1 60 B1 D6 B2 4B  B2 C2 B3 38 B3 AE B4 25  |...`...K...8...%|
0x0EF0: B4 9C B5 13 B5 8A B6 01  B6 79 B6 F0 B7 68 B7 E0  |.........y...h..|
0x0F00: B8 59 B8 D1 B9 4A B9 C2  BA 3B BA B5 BB 2E BB A7  |.Y...J...;......|
0x0F10: BC 21 BC 9B BD 15 BD 8F  BE 0A BE 84 BE FF BF 7A  |.!.............z|
0x0F20: BF F5 C0 70 C0 EC C1 67  C1 E3 C2 5F C2 DB C3 58  |...p...g..._...X|
0x0F30: C3 D4 C4 51 C4 CE C5 4B  C5 C8 C6 46 C6 C3 C7 41  |...Q...K...F...A|
0x0F40: C7 BF C8 3D C8 BC C9 3A  C9 B9 CA 38 CA B7 CB 36  |...=...:...8...6|
0x0F50: CB B6 CC 35 CC B5 CD 35  CD B5 CE 36 CE B6 CF 37  |...5...5...6...7|
0x0F60: CF B8 D0 39 D0 BA D1 3C  D1 BE D2 3F D2 C1 D3 44  |...9...<...?...D|
0x0F70: D3 C6 D4 49 D4 CB D5 4E  D5 D1 D6 55 D6 D8 D7 5C  |...I...N...U...\|
0x0F80: D7 E0 D8 64 D8 E8 D9 6C  D9 F1 DA 76 DA FB DB 80  |...d...l...v....|
0x0F90: DC 05 DC 8A DD 10 DD 96  DE 1C DE A2 DF 29 DF AF  |.............)..|
0x0FA0: E0 36 E0 BD E1 44 E1 CC  E2 53 E2 DB E3 63 E3 EB  |.6...D...S...c..|
0x0FB0: E4 73 E4 FC E5 84 E6 0D  E6 96 E7 1F E7 A9 E8 32  |.s.............2|
0x0FC0: E8 BC E9 46 E9 D0 EA 5B  EA E5 EB 70 EB FB EC 86  |...F...[...p....|
0x0FD0: ED 11 ED 9C EE 28 EE B4  EF 40 EF CC F0 58 F0 E5  |.....(...@...X..|
0x0FE0: F1 72 F1 FF F2 8C F3 19  F3 A7 F4 34 F4 C2 F5 50  |.r.........4...P|
0x0FF0: F5 DE F6 6D F6 FB F7 8A  F8 19 F8 A8 F9 38 F9 C7  |...m.........8..|
0x1000: FA 57 FA E7 FB 77 FC 07  FC 98 FD 29 FD BA FE 4B  |.W...w.....)...K|
0x1010: FE DC FF 6D FF FF                                 |...m..|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/ios-gen-be-16x16-srgb.tif

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/h02332/po/research/test-profiles/ios-gen-be-16x16-srgb.tif
```
