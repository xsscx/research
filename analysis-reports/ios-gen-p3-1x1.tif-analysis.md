# ICC Profile Analysis Report

**Profile**: `test-profiles/ios-gen-p3-1x1.tif`
**File Size**: 762 bytes
**SHA-256**: `58522ce710ff327d4856f826aa4f12bdddcb89e7fe8523be690878f309db27db`
**File Type**: TIFF image data, big-endian, direntries=16, height=1, bps=0, compression=none, PhotometricInterpretation=RGB, orientation=upper-left, width=1
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
IMAGE FILE ANALYSIS — TIFF
=======================================================================
File: /home/h02332/po/research/test-profiles/ios-gen-p3-1x1.tif

--- TIFF Metadata ---
  Dimensions:      1 × 1 pixels
  Bits/Sample:     8
  Samples/Pixel:   4
  Compression:     None (Uncompressed) (1)
  Photometric:     RGB (2)
  Planar Config:   Contiguous (Chunky) (1)
  Sample Format:   Unsigned Integer (1)
  Orientation:     1
  Rows/Strip:      1
  Strip Count:     1

--- TIFF Security Heuristics ---
[H139] TIFF Strip Geometry Validation (CWE-122/CWE-190)
      [OK] Strip geometry valid (bytesPerLine=4, stripSize=4, rowsPerStrip=1)

[H140] TIFF Dimension and Sample Validation (CWE-400/CWE-131)
      [OK] Dimensions 1×1, BPS=8, SPP=4 (1 pixels)

[H141] TIFF IFD Offset Bounds Validation (CWE-125)
      [OK] All IFD offsets within file bounds (size=762, pages=1)


--- Injection Signature Scan ---
  [OK] No injection signatures detected

--- Embedded ICC Profile ---
  [FOUND] ICC profile embedded (TIFFTAG_ICCPROFILE, tag 34675)
  Profile Size:    536 bytes (0.5 KB)
  ICC Magic:       [OK] 'acsp' at offset 36
  ICC Version:     4.0

  Extracted to: /tmp/iccanalyzer-extracted-67273.icc

=======================================================================
EXTRACTED ICC PROFILE — FULL HEURISTIC ANALYSIS
=======================================================================


=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /tmp/iccanalyzer-extracted-67273.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /tmp/iccanalyzer-extracted-67273.icc

=======================================================================
EXTERNAL FILE METADATA
=======================================================================

  [file]
      ColorSync color profile 4.0, type appl, RGB/XYZ-mntr device by appl, 536 bytes, 1-1-2022 'Display P3lc'

  [exiftool]
      ExifTool Version Number         : 12.76
      File Name                       : iccanalyzer-extracted-67273.icc
      Directory                       : /tmp
      File Size                       : 536 bytes
      File Modification Date/Time     : 2026:03:08 15:58:22-04:00
      File Access Date/Time           : 2026:03:08 15:58:22-04:00
      File Inode Change Date/Time     : 2026:03:08 15:58:22-04:00
      File Permissions                : -rw-------
      File Type                       : ICC
      File Type Extension             : icc
      MIME Type                       : application/vnd.iccprofile
      Profile CMM Type                : Apple Computer Inc.
      Profile Version                 : 4.0.0
      Profile Class                   : Display Device Profile
      Color Space Data                : RGB
      Profile Connection Space        : XYZ
      Profile Date Time               : 2022:01:01 00:00:00
      Profile File Signature          : acsp
      Primary Platform                : Apple Computer Inc.
      CMM Flags                       : Not Embedded, Independent
      Device Manufacturer             : Apple Computer Inc.
      Device Model                    : 
      Device Attributes               : Reflective, Glossy, Positive, Color
      Rendering Intent                : Perceptual
      Connection Space Illuminant     : 0.9642 1 0.82491
      Profile Creator                 : Apple Computer Inc.
      Profile ID                      : 0
      Profile Description             : Display P3
      Profile CopyrICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x52474220 (RGB)
ight               : Copyright Apple Inc., 2022
      Media White Point               : 0.96419 1 0.82489

  [identify]
      Image:
        Filename: /tmp/iccanalyzer-extracted-67273.icc
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
      00000000: 0000 0218 6170 706c 0400 0000 6d6e 7472  ....appl....mntr
      00000010: 5247 4220 5859 5a20 07e6 0001 0001 0000  RGB XYZ ........
      00000020: 0000 0000 6163 7370 4150 504c 0000 0000  ....acspAPPL....
      00000030: 4150 504c 0000 0000 0000 0000 0000 0000  APPL............
      00000040: 0000 0000 0000 f6d6 0001 0000 0000 d32d  ...............-
      00000050: 6170 706c 0000 0000 0000 0000 0000 0000  appl............
      00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
      00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................

  [sha256sum]
      0ff6958f98684c61f6bbdce1368ddeaf3873baf84545baba482e920d92a914c0  /tmp/iccanalyzer-extracted-67273.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 536 bytes (0x00000218)  [actual file: 536 bytes]
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

[H15] Date Validation (§4.2 dateTimeNumber): 2022-01-01 00:00:00
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
      Profile size: 536 bytes, tag count: 10
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
        [ 0.51512   0.29198   0.15710]
        [ 0.24120   0.69225   0.06657]
        [-0.00105   0.04189   0.78407]
      Determinant: 0.224621
      [OK] Matrix is invertible (det=0.224621)
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
      [OK] Profile class and required tags are consistent

[H111] Reserved Byte Validation
      [OK] All reserved header bytes are zero

[H112] Wtpt Profile-Class Validation
      wtpt: X=0.964188 Y=1.000000 Z=0.824890
      [OK] v4 Display wtpt is D50

[H113] Round-Trip Fidelity Assessment
      [OK] Round-trip tag geometry is consistent

[H114] TRC Curve Smoothness and Monotonicity
      [INFO] No TRC curve tags found

[H115] Characterization Data Presence
      [INFO] No characterization data (targ) tag present

[H116] cprt/desc Encoding vs Profile Version
      Profile version: 4.0.0
      cprt: type='mluc' (0x6D6C7563)
      [OK] cprt uses correct type for v4
      desc: type='mluc' (0x6D6C7563)
      [OK] desc uses correct type for v4

[H117] Tag Type Allowed Per Signature
      [OK] 10 tags checked — all use allowed types

[H118] Calculator Computation Cost Estimate
      [INFO] No MPE calculator/CLUT elements found

[H119] Round-Trip ΔE Measurement
      [INFO] No AToB/BToA CLUT pairs available for ΔE measurement

[H120] Curve Invertibility Assessment
      [INFO] No TRC curves found for invertibility check

[H121] Characterization Data Round-Trip Capability
      [INFO] No characterization data (targ) tag — cannot assess

[H122] Tag Type Encoding Validation
      [OK] 4 tag types validated — encoding correct

[H123] Non-Required Tag Classification
      [OK] All tags are required or optional for this profile class

[H124] Version-Tag Correspondence
      [OK] Tags correspond to profile version 4

[H125] Overall Transform Smoothness
      [INFO] No suitable LUT tags for smoothness measurement

[H126] Private Tag Malware Content Scan
      [INFO] No private tags to scan

[H127] Private Tag Registry Check
      [OK] No private tags present

[H128] Version BCD Encoding Validation
      Version bytes: 04 00 00 00 → v4.0.0
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
      chad matrix:
        [68674.000000  1502.000000  -3290.000000]
        [1939.000000  64912.000000  -1118.000000]
        [-605.000000  988.000000  49262.000000]
      Determinant: 219396398309936.000000
      [OK] chad matrix is invertible (det > 0)
      [WARN]  chad matrix contains extreme values (|element| > 5.0)
       CWE-682: May cause float overflow in adaptation transforms

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
      [INFO]  Tags 'rTRC' and 'bTRC' share data at offset 0x1CC (32 bytes)
      [INFO]  Tags 'rTRC' and 'gTRC' share data at offset 0x1CC (32 bytes)
      [INFO]  Tags 'bTRC' and 'gTRC' share data at offset 0x1CC (32 bytes)
      [OK] 3 shared tag pair(s) — all immutable types (safe)
      [OK] No risky shared tag data aliasing

[H40] Tag Alignment & Padding Validation
      [OK] All tags properly aligned with zero padding

[H41] Version/Type Consistency Check
      Profile version: 4.0.0
      [OK] All tags/types consistent with declared version

[H42] Matrix Singularity Detection
      Matrix determinant: 0.22462052
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

[WARN]  2 HEURISTIC WARNING(S) DETECTED

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
Profile: /tmp/iccanalyzer-extracted-67273.icc

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
  Manufacturer:    0x4150504C  'APPL'
  Model:           0x00000000  '....'

Tag Signatures:
Idx  Tag          FourCC     Type         Issues
---  ------------ ---------- ------------ ------
0    profileDescriptionTag 'desc    '  multiLocalizedUnicodeType
1    copyrightTag 'cprt    '  multiLocalizedUnicodeType
2    mediaWhitePointTag 'wtpt    '  XYZArrayType
3    redColorantTag 'rXYZ    '  XYZArrayType
4    greenColorantTag 'gXYZ    '  XYZArrayType
5    blueColorantTag 'bXYZ    '  XYZArrayType
6    redTRCTag    'rTRC    '  parametricCurveType
7    chromaticAdaptationTag 'chad    '  s15Fixed16ArrayType
8    blueTRCTag   'bTRC    '  parametricCurveType
9    greenTRCTag  'gTRC    '  parametricCurveType

Summary: 0 signature issue(s) detected

=======================================================================
PHASE 4: PROFILE STRUCTURE DUMP
=======================================================================

=== ICC Profile Header ===

=== ICC Profile Header (0x0000-0x007F) ===
0x0000: 00 00 02 18 61 70 70 6C  04 00 00 00 6D 6E 74 72  |....appl....mntr|
0x0010: 52 47 42 20 58 59 5A 20  07 E6 00 01 00 01 00 00  |RGB XYZ ........|
0x0020: 00 00 00 00 61 63 73 70  41 50 50 4C 00 00 00 00  |....acspAPPL....|
0x0030: 41 50 50 4C 00 00 00 00  00 00 00 00 00 00 00 00  |APPL............|
0x0040: 00 00 00 00 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 61 70 70 6C 00 00 00 00  00 00 00 00 00 00 00 00  |appl............|
0x0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields:
  Size:            0x00000218 (536 bytes)
  CMM:             appl
  Version:         0x04000000
  Device Class:    DisplayClass
  Color Space:     RgbData
  PCS:             XYZData

=== Tag Table ===

=== Tag Table ===
Tag Count: 10

Tag Table Raw Data (0x0080-0x00FC):
0x0080: 00 00 00 0A 64 65 73 63  00 00 00 FC 00 00 00 30  |....desc.......0|
0x0090: 63 70 72 74 00 00 01 2C  00 00 00 50 77 74 70 74  |cprt...,...Pwtpt|
0x00A0: 00 00 01 7C 00 00 00 14  72 58 59 5A 00 00 01 90  |...|....rXYZ....|
0x00B0: 00 00 00 14 67 58 59 5A  00 00 01 A4 00 00 00 14  |....gXYZ........|
0x00C0: 62 58 59 5A 00 00 01 B8  00 00 00 14 72 54 52 43  |bXYZ........rTRC|
0x00D0: 00 00 01 CC 00 00 00 20  63 68 61 64 00 00 01 EC  |....... chad....|
0x00E0: 00 00 00 2C 62 54 52 43  00 00 01 CC 00 00 00 20  |...,bTRC....... |
0x00F0: 67 54 52 43 00 00 01 CC  00 00 00 20              |gTRC....... |

Tag Entries:
Idx  Signature    FourCC       Offset     Size
---  ------------ ------------ ---------- ----
0    profileDescriptionTag 'desc      '  0x000000FC  48
1    copyrightTag 'cprt      '  0x0000012C  80
2    mediaWhitePointTag 'wtpt      '  0x0000017C  20
3    redColorantTag 'rXYZ      '  0x00000190  20
4    greenColorantTag 'gXYZ      '  0x000001A4  20
5    blueColorantTag 'bXYZ      '  0x000001B8  20
6    redTRCTag    'rTRC      '  0x000001CC  32
7    chromaticAdaptationTag 'chad      '  0x000001EC  44
8    blueTRCTag   'bTRC      '  0x000001CC  32
9    greenTRCTag  'gTRC      '  0x000001CC  32

=======================================================================
PHASE 5: TAG CONTENT ANALYSIS
=======================================================================

--- 5A: LUT Tag Geometry ---

  No legacy LUT tags (A2B/B2A/D2B/B2D) found

--- 5B: MPE Element Chains ---

  No MPE tags found

--- 5C: TRC Curve Analysis ---

  [rTRC] Parametric curve, function type 3
      Parameters (5): 2.4000 0.9479 0.0521 0.0774 0.0405
  [gTRC] Parametric curve, function type 3
      Parameters (5): 2.4000 0.9479 0.0521 0.0774 0.0405
  [bTRC] Parametric curve, function type 3
      Parameters (5): 2.4000 0.9479 0.0521 0.0774 0.0405

--- 5D: NamedColor2 Validation ---

  No NamedColor2 tag

--- 5E: XYZ Tag Values ---

  [rXYZ] X=0.5151 Y=0.2412 Z=-0.0011
  [gXYZ] X=0.2920 Y=0.6922 Z=0.0419
  [bXYZ] X=0.1571 Y=0.0666 Z=0.7841
  [wtpt] X=0.9642 Y=1.0000 Z=0.8249

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

File: /tmp/iccanalyzer-extracted-67273.icc
Total Issues Detected: 2

[WARN] ANALYSIS COMPLETE - 2 issue(s) detected
  Review detailed output above for security concerns.


=======================================================================
IMAGE ANALYSIS SUMMARY
=======================================================================
Format:     TIFF
Dimensions: 1 × 1
Findings:   2
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

File: /home/h02332/po/research/test-profiles/ios-gen-p3-1x1.tif
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 762 bytes (0x2FA)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 4D 4D 00 2A 00 00 00 0C  C0 90 78 FF 00 10 01 00  |MM.*......x.....|
0x0010: 00 03 00 00 00 01 00 01  00 00 01 01 00 03 00 00  |................|
0x0020: 00 01 00 01 00 00 01 02  00 03 00 00 00 04 00 00  |................|
0x0030: 00 D2 01 03 00 03 00 00  00 01 00 01 00 00 01 06  |................|
0x0040: 00 03 00 00 00 01 00 02  00 00 01 0A 00 03 00 00  |................|
0x0050: 00 01 00 01 00 00 01 11  00 04 00 00 00 01 00 00  |................|
0x0060: 00 08 01 12 00 03 00 00  00 01 00 01 00 00 01 15  |................|
0x0070: 00 03 00 00 00 01 00 04  00 00 01 16 00 03 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x4D4D002A (1296891946 bytes) MISMATCH
  CMM:             0x0000000C  '....'
  Version:         0xC09078FF
  Device Class:    0x00100100  '....'
  Color Space:     0x00030000  '....'
  PCS:             0x00010001  '....'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 65537 (0x00010001)
WARNING: Suspicious tag count (>1000) - possible corruption

Tag Table Raw Data:
0x0080: 00 01 00 01 00 00 01 17  00 04 00 00 00 01 00 00  |................|
0x0090: 00 04 01 1C 00 03 00 00  00 01 00 01 00 00 01 28  |...............(|
0x00A0: 00 03 00 00 00 01 00 02  00 00 01 52 00 03 00 00  |...........R....|
0x00B0: 00 01 00 01 00 00 01 53  00 03 00 00 00 04 00 00  |.......S........|
0x00C0: 00 DA 87 73 00 07 00 00  02 18 00 00 00 E2 00 00  |...s............|
0x00D0: 00 00 00 08 00 08 00 08  00 08 00 01 00 01 00 01  |................|
0x00E0: 00 01 00 00 02 18 61 70  70 6C 04 00 00 00 6D 6E  |......appl....mn|
0x00F0: 74 72 52 47 42 20 58 59  5A 20 07 E6 00 01 00 01  |trRGB XYZ ......|
0x0100: 00 00 00 00 00 00 61 63  73 70 41 50 50 4C 00 00  |......acspAPPL..|
0x0110: 00 00 41 50 50 4C 00 00  00 00 00 00 00 00 00 00  |..APPL..........|
0x0120: 00 00 00 00 00 00 00 00  F6 D6 00 01 00 00 00 00  |................|
0x0130: D3 2D 61 70 70 6C 00 00  00 00 00 00 00 00 00 00  |.-appl..........|
0x0140: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0150: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0160: 00 00 00 00 00 0A 64 65  73 63 00 00 00 FC 00 00  |......desc......|
0x0170: 00 30 63 70 72 74 00 00  01 2C 00 00 00 50 77 74  |.0cprt...,...Pwt|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x00000117   '    '        0x00040000   0x00010000   '----'        OOB offset
1    0x0004011C   '    '        0x00030000   0x00010001   '----'        OOB offset
2    0x00000128   '    '        0x00030000   0x00010002   '----'        OOB offset
3    0x00000152   '    '        0x00030000   0x00010001   '----'        OOB offset
4    0x00000153   '    '        0x00030000   0x00040000   '----'        OOB offset
5    0x00DA8773   '    '        0x00070000   0x02180000   '----'        OOB offset
6    0x00E20000   '    '        0x00000008   0x00080008   '��x�'        OOB size
7    0x00080001   '    '        0x00010001   0x00010000   '----'        OOB offset
8    0x02186170   'ap'        0x706C0400   0x00006D6E   '----'        OOB offset
9    0x74725247   'trRG'        0x42205859   0x5A2007E6   '----'        OOB offset
10   0x00010001   '    '        0x00000000   0x00006163   'MM  '        OOB size
11   0x73704150   'spAP'        0x504C0000   0x00004150   '----'        OOB offset
12   0x504C0000   'PL  '        0x00000000   0x00000000   'MM  '        overlap
13   0x00000000   '    '        0x00000000   0xF6D60001   'MM  '        OOB size
14   0x00000000   '    '        0xD32D6170   0x706C0000   '----'        OOB offset
15   0x00000000   '    '        0x00000000   0x00000000   'MM  '        overlap
16   0x00000000   '    '        0x00000000   0x00000000   'MM  '        overlap
17   0x00000000   '    '        0x00000000   0x00000000   'MM  '        overlap
18   0x00000000   '    '        0x00000000   0x000A6465   'MM  '        OOB size
19   0x73630000   'sc  '        0x00FC0000   0x00306370   '----'        OOB offset
20   0x72740000   'rt  '        0x012C0000   0x00507774   '----'        OOB offset
21   0x70740000   'pt  '        0x017C0000   0x00147258   '----'        OOB offset
22   0x595A0000   'YZ  '        0x01900000   0x00146758   '----'        OOB offset
23   0x595A0000   'YZ  '        0x01A40000   0x00146258   '----'        OOB offset
24   0x595A0000   'YZ  '        0x01B80000   0x00147254   '----'        OOB offset
25   0x52430000   'RC  '        0x01CC0000   0x00206368   '----'        OOB offset
26   0x61640000   'ad  '        0x01EC0000   0x002C6254   '----'        OOB offset
27   0x52430000   'RC  '        0x01CC0000   0x00206754   '----'        OOB offset
28   0x52430000   'RC  '        0x01CC0000   0x00206D6C   '----'        OOB offset
29   0x75630000   'uc  '        0x00000000   0x00010000   'MM  '        OOB size
30   0x000C656E   '    '        0x55530000   0x00140000   '----'        OOB offset
31   0x001C0044   '    '        0x00690073   0x0070006C   '----'        OOB offset
32   0x00610079   '    '        0x00200050   0x00336D6C   '----'        OOB offset
33   0x75630000   'uc  '        0x00000000   0x00010000   'MM  '        OOB size
34   0x000C656E   '    '        0x55530000   0x00340000   '----'        OOB offset
35   0x001C0043   '    '        0x006F0070   0x00790072   '----'        OOB offset
36   0x00690067   '    '        0x00680074   0x00200041   '----'        OOB offset
37   0x00700070   '    '        0x006C0065   0x00200049   '----'        OOB offset
38   0x006E0063   '    '        0x002E002C   0x00200032   '----'        OOB offset
39   0x00300032   '    '        0x00325859   0x5A200000   '----'        OOB offset
40   0x00000000   '    '        0xF6D50001   0x00000000   '----'        OOB offset
41   0xD32C5859   '�,XY'        0x5A200000   0x00000000   '----'        OOB offset
42   0x83DF0000   '��  '        0x3DBFFFFF   0xFFBB5859   '----'        OOB offset
43   0x5A200000   'Z   '        0x00000000   0x4ABF0000   'MM  '        OOB size
44   0xB1370000   '�7  '        0x0AB95859   0x5A200000   '----'        OOB offset
45   0x00000000   '    '        0x28380000   0x110B0000   '----'        OOB offset
46   0xC8B97061   'ȹpa'        0x72610000   0x00000003   '----'        OOB offset
47   0x00000002   '    '        0x66660000   0xF2A70000   '----'        OOB offset
48   0x0D590000   'Y  '        0x13D00000   0x0A5B7366   '----'        OOB offset
49   0x33320000   '32  '        0x00000001   0x0C420000   'M   '        OOB size
50   0x05DEFFFF   '���'        0xF3260000   0x07930000   '----'        OOB offset
51   0xFD90FFFF   '����'        0xFBA2FFFF   0xFDA30000   '----'        OOB offset
... (65437 more tags not shown)

[WARN] SIZE INFLATION: Header claims 1296891946 bytes, file is 762 bytes (1701958x)
   Risk: OOM via tag-internal allocations based on inflated header size

[WARN] TAG OVERLAP: 221 overlapping tag pair(s) detected
   Risk: Data corruption, possible exploit crafting

=== FULL FILE HEX DUMP (all 762 bytes) ===
0x0000: 4D 4D 00 2A 00 00 00 0C  C0 90 78 FF 00 10 01 00  |MM.*......x.....|
0x0010: 00 03 00 00 00 01 00 01  00 00 01 01 00 03 00 00  |................|
0x0020: 00 01 00 01 00 00 01 02  00 03 00 00 00 04 00 00  |................|
0x0030: 00 D2 01 03 00 03 00 00  00 01 00 01 00 00 01 06  |................|
0x0040: 00 03 00 00 00 01 00 02  00 00 01 0A 00 03 00 00  |................|
0x0050: 00 01 00 01 00 00 01 11  00 04 00 00 00 01 00 00  |................|
0x0060: 00 08 01 12 00 03 00 00  00 01 00 01 00 00 01 15  |................|
0x0070: 00 03 00 00 00 01 00 04  00 00 01 16 00 03 00 00  |................|
0x0080: 00 01 00 01 00 00 01 17  00 04 00 00 00 01 00 00  |................|
0x0090: 00 04 01 1C 00 03 00 00  00 01 00 01 00 00 01 28  |...............(|
0x00A0: 00 03 00 00 00 01 00 02  00 00 01 52 00 03 00 00  |...........R....|
0x00B0: 00 01 00 01 00 00 01 53  00 03 00 00 00 04 00 00  |.......S........|
0x00C0: 00 DA 87 73 00 07 00 00  02 18 00 00 00 E2 00 00  |...s............|
0x00D0: 00 00 00 08 00 08 00 08  00 08 00 01 00 01 00 01  |................|
0x00E0: 00 01 00 00 02 18 61 70  70 6C 04 00 00 00 6D 6E  |......appl....mn|
0x00F0: 74 72 52 47 42 20 58 59  5A 20 07 E6 00 01 00 01  |trRGB XYZ ......|
0x0100: 00 00 00 00 00 00 61 63  73 70 41 50 50 4C 00 00  |......acspAPPL..|
0x0110: 00 00 41 50 50 4C 00 00  00 00 00 00 00 00 00 00  |..APPL..........|
0x0120: 00 00 00 00 00 00 00 00  F6 D6 00 01 00 00 00 00  |................|
0x0130: D3 2D 61 70 70 6C 00 00  00 00 00 00 00 00 00 00  |.-appl..........|
0x0140: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0150: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0160: 00 00 00 00 00 0A 64 65  73 63 00 00 00 FC 00 00  |......desc......|
0x0170: 00 30 63 70 72 74 00 00  01 2C 00 00 00 50 77 74  |.0cprt...,...Pwt|
0x0180: 70 74 00 00 01 7C 00 00  00 14 72 58 59 5A 00 00  |pt...|....rXYZ..|
0x0190: 01 90 00 00 00 14 67 58  59 5A 00 00 01 A4 00 00  |......gXYZ......|
0x01A0: 00 14 62 58 59 5A 00 00  01 B8 00 00 00 14 72 54  |..bXYZ........rT|
0x01B0: 52 43 00 00 01 CC 00 00  00 20 63 68 61 64 00 00  |RC....... chad..|
0x01C0: 01 EC 00 00 00 2C 62 54  52 43 00 00 01 CC 00 00  |.....,bTRC......|
0x01D0: 00 20 67 54 52 43 00 00  01 CC 00 00 00 20 6D 6C  |. gTRC....... ml|
0x01E0: 75 63 00 00 00 00 00 00  00 01 00 00 00 0C 65 6E  |uc............en|
0x01F0: 55 53 00 00 00 14 00 00  00 1C 00 44 00 69 00 73  |US.........D.i.s|
0x0200: 00 70 00 6C 00 61 00 79  00 20 00 50 00 33 6D 6C  |.p.l.a.y. .P.3ml|
0x0210: 75 63 00 00 00 00 00 00  00 01 00 00 00 0C 65 6E  |uc............en|
0x0220: 55 53 00 00 00 34 00 00  00 1C 00 43 00 6F 00 70  |US...4.....C.o.p|
0x0230: 00 79 00 72 00 69 00 67  00 68 00 74 00 20 00 41  |.y.r.i.g.h.t. .A|
0x0240: 00 70 00 70 00 6C 00 65  00 20 00 49 00 6E 00 63  |.p.p.l.e. .I.n.c|
0x0250: 00 2E 00 2C 00 20 00 32  00 30 00 32 00 32 58 59  |...,. .2.0.2.2XY|
0x0260: 5A 20 00 00 00 00 00 00  F6 D5 00 01 00 00 00 00  |Z ..............|
0x0270: D3 2C 58 59 5A 20 00 00  00 00 00 00 83 DF 00 00  |.,XYZ ..........|
0x0280: 3D BF FF FF FF BB 58 59  5A 20 00 00 00 00 00 00  |=.....XYZ ......|
0x0290: 4A BF 00 00 B1 37 00 00  0A B9 58 59 5A 20 00 00  |J....7....XYZ ..|
0x02A0: 00 00 00 00 28 38 00 00  11 0B 00 00 C8 B9 70 61  |....(8........pa|
0x02B0: 72 61 00 00 00 00 00 03  00 00 00 02 66 66 00 00  |ra..........ff..|
0x02C0: F2 A7 00 00 0D 59 00 00  13 D0 00 00 0A 5B 73 66  |.....Y.......[sf|
0x02D0: 33 32 00 00 00 00 00 01  0C 42 00 00 05 DE FF FF  |32.......B......|
0x02E0: F3 26 00 00 07 93 00 00  FD 90 FF FF FB A2 FF FF  |.&..............|
0x02F0: FD A3 00 00 03 DC 00 00  C0 6E                    |.........n|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/ios-gen-p3-1x1.tif

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/h02332/po/research/test-profiles/ios-gen-p3-1x1.tif
```
