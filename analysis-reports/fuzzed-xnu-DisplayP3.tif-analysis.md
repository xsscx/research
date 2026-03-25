# ICC Profile Analysis Report

**Profile**: `test-profiles/fuzzed-xnu-DisplayP3.tif`
**File Size**: 17142 bytes
**SHA-256**: `8993301d3aa2857ab9325accdfeb668e8348e1ec62f39caef9233cc52711d084`
**File Type**: TIFF image data, big-endian, direntries=16, height=1, bps=0, compression=none, PhotometricInterpretation=RGB, orientation=upper-left, width=4096
**Date**: 2026-03-25T02:25:05Z
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
IMAGE FILE ANALYSIS ‚Äî TIFF
=======================================================================
File: /home/h02332/po/research/test-profiles/fuzzed-xnu-DisplayP3.tif

--- TIFF Metadata ---
  Dimensions:      4096 √ó 1 pixels
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
      [OK] Strip geometry valid

[H140] TIFF Dimension and Sample Validation (CWE-400/CWE-131)
      [OK] Dimensions valid

[H141] TIFF IFD Offset Bounds Validation (CWE-125)
      [OK] All IFD offsets within file bounds

[H149] TIFF IFD Chain Cycle Detection (CWE-835)
      [OK] IFD chain is acyclic

[H150] TIFF Tile Geometry Validation (CWE-122/CWE-131)
      [OK] Strip-based image ‚Äî tile geometry N/A


--- Injection Signature Scan ---
      [INJECT] PixelData(strip0): 'ICC tag count corruption (0xFFFF)' at offset 9211
       CWE-787: Out-of-bounds Write
  [WARN] 1 injection signature(s) detected

--- Embedded ICC Profile ---
  [FOUND] ICC profile embedded (TIFFTAG_ICCPROFILE, tag 34675)
  Profile Size:    536 bytes (0.5 KB)
  ICC Magic:       [OK] 'acsp' at offset 36
  ICC Version:     4.0

  Extracted ICC from TIFF to: /tmp/iccanalyzer-FynhxB.icc

=======================================================================
EXTRACTED ICC PROFILE ‚Äî FULL HEURISTIC ANALYSIS
=======================================================================


=======================================================================
  ICC PROFILE CONFORMANCE AUDIT
=======================================================================

File: /tmp/iccanalyzer-FynhxB.icc

[H173] Signature Conversion Shift Overflow (IccUtil.cpp signature formatting helpers)
      [WARN]  HEURISTIC: 27/27 FourCC signatures trigger UBSAN shift overflow in icGetSig()/icGetSigStr()/icGetColorSig()/icGetColorSigStr() ‚Äî IccUtil.cpp:1088,1130,1167,1187,1228,1253
       CWE-190: sig<<=8 on uint32 with first byte non-zero produces value > UINT32_MAX (upstream iccDEV library pattern)

[H174] Half-Float Conversion Unsigned Underflow (IccUtil.cpp icF16toF)
      [N/A] No vulnerable half-float values detected

=======================================================================
PHASE 1: ICC SPECIFICATION CONFORMANCE
=======================================================================


=======================================================================
ICC LIBRARY CONFORMANCE VALIDATION
=======================================================================

  Running CIccProfile::ReadValidate() ‚Äî ICC.1-2022-05 conformance checks
  Checks: header, required tags, tag types, per-tag content validation

  Validation Status: NON-COMPLIANT ‚Äî Profile does not conform to ICC specification

  [NON-COMPLIANT] redColorantTag::XYZ - XYZNumber: Negative Z value!

  Validation Summary: 0 error(s), 1 non-compliant, 0 warning(s), 0 info
  [WARN] 1 ICC spec conformance issue(s) detected


=======================================================================
PHASE 2: DEEP CONFORMANCE CHECKS (ICC.1/ICC.2)
=======================================================================

--- Header Conformance (CF-001..CF-015, CF-184..CF-187, CF-199..CF-201, CF-203, CF-206, CF-210, CF-214..CF-219) ---

[H1001] CF-001: Date/Time Month-Day Validity
[CF-001] Date/Time Month-Day Validity (ICC.1-2022-05 ¬ß7.2.8)
         Month=1, Day=1 ‚Äî valid
         [OK] Date fields within range
      [OK] Conformant

[H1002] CF-002: Date/Time Leap Year Validation
[CF-002] Date/Time Leap Year Validation (ICC.1-2022-05 ¬ß7.2.8)
         Month=1 ‚Äî leap year check not applicable
         [OK] Not February, skip leap year validation
      [OK] Conformant

[H1003] CF-003: Profile Flags Reserved Bits
[CF-003] Profile Flags Reserved Bits (ICC.1-2022-05 ¬ß7.2.11 Table 21)
         flags=0x00000000 ‚Äî reserved bits 3-15 clear
         [OK] Profile flags conformant
      [OK] Conformant

[H1004] CF-004: Device Attributes Reserved Bits
[CF-004] Device Attributes Reserved Bits (ICC.1-2022-05 ¬ß7.2.14)
         attributes=0x0000000000000000 ‚Äî reserved bits clear
         [OK] Device attributes conformant
      [OK] Conformant

[H1005] CF-005: Rendering Intent Upper Bits Zero
[CF-005] Rendering Intent Upper Bits Zero (ICC.1-2022-05 ¬ß7.2.15)
         renderingIntent=0 (Perceptual)
         [OK] Rendering intent conformant
      [OK] Conformant

[H1006] CF-006: Version BCD Encoding
[CF-006] Profile Version BCD Encoding (ICC.1-2022-05 ¬ß7.2.4)
         version=0x04000000 ‚Üí v4.0.0.0
         [OK] Version BCD encoding conformant
      [OK] Conformant

[H1007] CF-007: Primary Platform Signature
[CF-007] Primary Platform Signature (ICC.1-2022-05 ¬ß7.2.10 Table 20)
         platform=Apple (APPL)
         [OK] Platform signature conformant
      [OK] Conformant

[H1008] CF-008: PCS Illuminant D50 Values
[CF-008] PCS Illuminant D50 Precision (ICC.1-2022-05 ¬ß7.2.16)
         illuminant X=0.9642, Y=1.0000, Z=0.8249
         expected   X=0.9642, Y=1.0000, Z=0.8249 (D50)
         [OK] PCS illuminant matches D50
      [OK] Conformant

[H1009] CF-009: Chromatic Adaptation Tag Requirement
[CF-009] Chromatic Adaptation Tag Requirement (ICC.1-2022-05 ¬ß8.2)
         chad tag present
         [OK] Chromatic adaptation tag conformant
      [OK] Conformant

[H1010] CF-010: Profile Size vs File Size
[CF-010] Profile Size vs File Size (ICC.1-2022-05 ¬ß7.2.2)
         Header size: 536 bytes, File size: 536 bytes
         [OK] Profile size matches file size
      [OK] Conformant

[H1011] CF-011: Profile ID MD5 Verification
[CF-011] Profile ID MD5 Verification (ICC.1-2022-05 ¬ß7.2.18)
         Profile ID is all zeros ‚Äî not computed
         [INFO] Profile ID not set ‚Äî ¬ß7.2.18
      [OK] Conformant

[H1012] CF-012: Profile Class Signature
[CF-012] Profile Class Signature (ICC.1-2022-05 ¬ß7.2.5 Table 18)
         deviceClass='mntr' (0x6D6E7472)
         [OK] Valid v4 profile class
      [OK] Conformant

[H1013] CF-013: Data Colour Space Signature
[CF-013] Data Colour Space Signature (ICC.1-2022-05 ¬ß7.2.6 Table 19)
         colorSpace='RGB ' (0x52474220) ‚Äî RGB
         [OK] Valid colour space signature
      [OK] Conformant

[H1014] CF-014: PCS Field for Non-DeviceLink
[CF-014] PCS Field for Non-DeviceLink (ICC.1-2022-05 ¬ß7.2.7)
         PCS='XYZ ' (0x58595A20)
         [OK] PCS conformant for non-DeviceLink profile
      [OK] Conformant

[H1015] CF-015: Reserved Bytes 100-127 Zero
[CF-015] Reserved Bytes 100-127 Zero (ICC.1-2022-05 ¬ß7.2.24)
         Bytes 100-127: all zero
         [OK] Reserved bytes conformant
      [OK] Conformant

[H1016] CF-016: Device Manufacturer Signature
[CF-016] Device Manufacturer Signature (ICC.1-2022-05 ¬ß7.2.12)
         manufacturer='APPL' (0x4150504C)
         [OK] Device manufacturer field conformant
      [OK] Conformant

[H1017] CF-017: Device Model Signature
[CF-017] Device Model Signature (ICC.1-2022-05 ¬ß7.2.13)
         model=0x00000000 ‚Äî not specified (permitted)
         [OK] Device model field conformant
      [OK] Conformant

[H1018] CF-018: Device Attributes Semantic Bits
[CF-018] Device Attributes Semantic Bits (ICC.1-2022-05 ¬ß7.2.14 Table 23)
         Bit 0 (Media): reflective
         Bit 1 (Finish): glossy
         Bit 2 (Polarity): positive
         Bit 3 (Colour): colour
         [OK] Device attributes conformant
      [OK] Conformant

[H1019] CF-019: Creator Signature
[CF-019] Creator Signature (ICC.1-2022-05 ¬ß7.2.17)
         creator='appl' (0x6170706C)
         [OK] Creator signature field conformant
      [OK] Conformant

[H1107] CF-107: Tag Table Ordering
  [CF-107] Tag Table Ordering (ICC.1-2022-05 ¬ß7.3.1)
         [OK] Tag table has no duplicate signatures
      [OK] Conformant

[H1121] CF-121: Illuminant Metadata Consistency
  [CF-121] Illuminant Metadata Consistency (ICC.1-2022-05 ¬ß7.2.16)
         [OK] Illuminant metadata consistent
      [OK] Conformant

[H1122] CF-122: Profile Date/Time Plausibility
  [CF-122] Profile Date/Time Plausibility (ICC.1-2022-05 ¬ß7.2.8)
         [OK] Profile date/time is plausible
      [OK] Conformant

[H1184] CF-184: Profile ID v4+ Presence
[CF-184] Profile ID v4+ Presence (ICC.1-2022-05 ¬ß7.2.18, RFC 1321)
         Profile version: 4.x
         Profile ID is all zeros (not computed)
         [WARN] v4+ profile SHOULD have computed Profile ID ‚Äî ¬ß7.2.18
      [WARN]  1 non-conformance(s)

[H1185] CF-185: Profile ID Size Consistency
[CF-185] Profile ID Size Consistency (ICC.1-2022-05 ¬ß7.2.18, RFC 1321 ¬ß3.1)
         Profile ID is zero ‚Äî size consistency check not applicable
         [OK] No Profile ID to validate
      [OK] Conformant

[H1186] CF-186: Profile ID Entropy Analysis
[CF-186] Profile ID Entropy Analysis (RFC 1321, ICC.1-2022-05 ¬ß7.2.18)
         Profile ID is zero ‚Äî entropy analysis not applicable
         [OK] No Profile ID to analyze
      [OK] Conformant

[H1187] CF-187: Embedded Profile ProfileID Chain
[CF-187] Embedded Profile ProfileID Chain (ICC TN Embedding + ¬ß7.2.18 + RFC 1321)
         No embedded profile tag (ICC5) present
         [OK] No embedding chain to validate
      [OK] Conformant

[H1199] CF-199: CMM Type Signature Registration
  [CF-199] CMM Type Signature Registration (ICC.1-2022-05 ¬ß7.2.3)
           cmmId='appl' (0x6170706C) ‚Äî registered ICC CMM
           [OK] CMM type conformant
      [OK] Conformant

[H1200] CF-200: Device Manufacturer/Model Signature
  [CF-200] Device Manufacturer/Model Signature (ICC.1-2022-05 ¬ß7.2.12-13)
           manufacturer='APPL' (0x4150504C)
           model=0x00000000 ‚Äî not specified (permitted)
           [OK] Device manufacturer/model conformant
      [OK] Conformant

[H1201] CF-201: Profile Creator Signature
  [CF-201] Profile Creator Signature (ICC.1-2022-05 ¬ß7.2.17)
           creator='appl' (0x6170706C)
           [OK] Profile creator conformant
      [OK] Conformant

[H1203] CF-203: Profile Flags Semantic Validation
  [CF-203] Profile Flags Semantic Validation (ICC.1-2022-05 ¬ß7.2.11 Table 21)
           Bit 0 (Embedded): not embedded
           Bit 1 (Independent): can be used independently
           [OK] Profile flags semantics conformant
      [OK] Conformant

[H1206] CF-206: Profile File Signature 'acsp'
[CF-206] Profile File Signature 'acsp' (ICC.1-2022-05 ¬ß7.2.9)
         magic=0x61637370 ('acsp')
         [OK] Profile file signature conformant
      [OK] Conformant

[H1210] CF-210: DeviceLink PCS Space Validation
[CF-210] DeviceLink PCS Space Validation (ICC.1-2022-05 ¬ß8.6)
         Not a DeviceLink profile ‚Äî skipping
         [OK] Not applicable
      [OK] Conformant

[H1214] CF-214: Embedded Profile Class Suitability
  [CF-214] Embedded Profile Class Suitability (ICC TN Embedding ¬ßTable 1)
         Embedded flag not set ‚Äî profile not marked for embedding
         [OK] Not applicable (not an embedded profile)
      [OK] Conformant

[H1215] CF-215: JPEG APP2 Embedding Size Limit
  [CF-215] JPEG APP2 Embedding Size Limit (ICC TN Embedding ¬ßJFIF)
         Profile size: 536 bytes (JPEG limit: 16707345 bytes)
         Would require 1 APP2 segment(s) for JPEG embedding
         [OK] Profile fits within JPEG APP2 embedding limit
      [OK] Conformant

[H1216] CF-216: JP2 Restricted ICC Compliance
  [CF-216] JP2 Restricted ICC Compliance (ISO 15444-1 Annex I)
         Class 'mntr' ‚Äî JP2 requires Input ('scnr') class
         Version 4.x ‚Äî JP2 requires ICC v2 (ICC.1:1998-09)
         [INFO] Profile not compatible with JP2 Restricted ICC method
      [OK] Conformant

[H1217] CF-217: JPX Any ICC Method Compliance
  [CF-217] JPX Any ICC Method Compliance (ISO 15444-2 Annex M)
         [OK] Profile compatible with JPX Any ICC method
      [OK] Conformant

[H1218] CF-218: HEIF Restricted ICC Compatibility
  [CF-218] HEIF Restricted ICC Compatibility (ISO/IEC 14496-12)
         HEIF 'colr' compatible (v4 profile, ‚â§ v4)
         HEIF 'ricc' compatible (3-component Matrix/TRC)
         [OK] Profile compatible with HEIF embedding
      [OK] Conformant

[H1219] CF-219: Container Format Version Matrix
  [CF-219] Container Format Version Matrix (ICC TN Embedding ¬ßTable 1)
         Profile version: 4.x, class: mntr
         JPX (ISO 15444-2): compatible (v4 Display)
         PNG: v4 widely supported in practice (spec says v2)
         Compatible with 16+ media formats (of 18 surveyed)
         [OK] Profile version has broad container format support
      [OK] Conformant

[H1243] CF-243: dateTimeNumber Field Range
      [OK] Conformant

[H1244] CF-244: Profile Creation Date Plausibility
      [OK] Conformant

[H1245] CF-245: Profile Size Multiple of 4
      [OK] Conformant

[H1246] CF-246: Rendering Intent Range
      [OK] Conformant


--- Tag Type Conformance (CF-020..CF-034, CF-169..CF-174, CF-188..CF-190, CF-208, CF-209, CF-212, CF-213, CF-220..CF-234, CF-247..CF-254, CF-263..CF-265, CF-273..CF-281) ---

[H1020] CF-020: Tag Signature ‚Üí Allowed Type
[CF-020] Tag Type Allowed for Signature (ICC.1-2022-05 ¬ß9.2, ¬ß10)
         [OK] 8/8 tags checked, all use permitted types
      [OK] Conformant

[H1021] CF-021: Tag Type Reserved Bytes Zero
[CF-021] Tag Type Reserved Bytes Zero (ICC.1-2022-05 ¬ß10)
         [OK] 8 tag(s) checked, all reserved bytes are zero
      [OK] Conformant

[H1022] CF-022: curveType Entry Count
[CF-022] curveType Entry Count Mode (ICC.1-2022-05 ¬ß10.6)
         No curveType tags found
         [OK] 0 curveType tag(s) checked, all consistent
      [OK] Conformant

[H1023] CF-023: parametricCurveType Function Type
[CF-023] parametricCurveType Function Type (ICC.1-2022-05 ¬ß10.18 Table 68)
         [OK] 3 parametricCurveType tag(s) checked, all function types valid
      [OK] Conformant

[H1024] CF-024: parametricCurveType Parameter Count
[CF-024] parametricCurveType Parameter Count (ICC.1-2022-05 ¬ß10.18 Table 68)
         [OK] 3 parametricCurveType tag(s) checked, all parameter counts correct
      [OK] Conformant

[H1025] CF-025: Chromaticity Phosphor Count
[CF-025] chromaticityType Phosphor Count (ICC.1-2022-05 ¬ß10.2)
         No chromaticityTag found
         [OK] Not applicable
      [OK] Conformant

[H1026] CF-026: Colorant Table Entry Count
[CF-026] colorantTableType Colorant Count (ICC.1-2022-05 ¬ß10.4)
         No colorantTableTag found
         [OK] Not applicable
      [OK] Conformant

[H1027] CF-027: Colorant Order Count
[CF-027] colorantOrderType Count Match (ICC.1-2022-05 ¬ß10.3)
         No colorantOrderTag found
         [OK] Not applicable
      [OK] Conformant

[H1028] CF-028: Named Color2 Device Coordinate Count
[CF-028] namedColor2Type Coordinate Count (ICC.1-2022-05 ¬ß10.14)
         No namedColor2Tag found
         [OK] Not applicable
      [OK] Conformant

[H1029] CF-029: dateTimeType Field Ranges
[CF-029] dateTimeType Field Ranges (ICC.1-2022-05 ¬ß10.7, ¬ß4.2)
         No dateTimeType tags found
         [OK] 0 dateTimeType tag(s) checked, all fields in range
      [OK] Conformant

[H1030] CF-030: multiLocalizedUnicodeType Structure
[CF-030] multiLocalizedUnicodeType Structure (ICC.1-2022-05 ¬ß10.13)
         [OK] 2 mluc tag(s) checked, all structurally valid
      [OK] Conformant

[H1031] CF-031: s15Fixed16ArrayType Element Count
[CF-031] s15Fixed16ArrayType Element Count (ICC.1-2022-05 ¬ß10.18)
         Tag 'chad': 9 s15Fixed16 element(s)
         [OK] 1 sf32 tag(s) checked, all element counts valid
      [OK] Conformant

[H1032] CF-032: XYZType Triplet Count
[CF-032] XYZType Triplet Count (ICC.1-2022-05 ¬ß10.23)
         [OK] 4 XYZ tag(s) checked, all contain exactly 1 triplet
      [OK] Conformant

[H1033] CF-033: Measurement Standard Observer
[CF-033] measurementType Standard Observer (ICC.1-2022-05 ¬ß10.12 Table 56)
         No measurementTag found
         [OK] Not applicable
      [OK] Conformant

[H1034] CF-034: Measurement Geometry
[CF-034] measurementType Measurement Geometry (ICC.1-2022-05 ¬ß10.12 Table 57)
         No measurementTag found
         [OK] Not applicable
      [OK] Conformant

[H1035] CF-035: responseCurveSet16Type Structure
[CF-035] responseCurveSet16Type Structure (ICC.1-2022-05 ¬ß10.19)
         No outputResponseTag ('resp') found
         [N/A] Not applicable
      [OK] Conformant

[H1036] CF-036: profileSequenceDescType Elements
[CF-036] profileSequenceDescType Elements (ICC.1-2022-05 ¬ß10.22)
         No profileSequenceDescTag found
         [N/A] Not applicable
      [OK] Conformant

[H1037] CF-037: profileSequenceIdentifierType Validation
[CF-037] profileSequenceIdentifierType Validation (ICC.1-2022-05 ¬ß10.23)
         No profileSequenceIdentifierTag ('psid') found
         [N/A] Not applicable
      [OK] Conformant

[H1038] CF-038: dateTimeType Tag Range Validation
[CF-038] dateTimeType Tag Range Validation (ICC.1-2022-05 ¬ß10.7)
         No calibrationDateTimeTag ('calt') found
         [N/A] Not applicable
      [OK] Conformant

[H1039] CF-039: signatureType Technology Validation
[CF-039] signatureType Technology Validation (ICC.1-2022-05 ¬ß10.24)
         No technologyTag ('tech') found
         [N/A] Not applicable
      [OK] Conformant

[H1112] CF-112: XYZ Triplet Normalization
  [CF-112] XYZ Triplet Value Normalization (ICC.1-2022-05 ¬ß10.31)
         [OK] All 4 XYZ triplets have valid values
      [OK] Conformant

[H1169] CF-169: Negative PCSXYZ Encoding Capability
  [CF-169] Negative PCSXYZ Encoding Capability (ICC TN Negative PCSXYZ ¬ß6.3.4.2)
         'rXYZ' has negative component(s): X=0.515121 Y=0.241196 Z=-0.001053
         [INFO] Negative value encoded via s15Fixed16Number ‚Äî conformant per ICC TN Negative PCSXYZ
         [OK] 1 negative value(s) properly encoded via s15Fixed16
      [OK] Conformant

[H1170] CF-170: Chromatic Adaptation Negative XYZ Consistency
  [CF-170] Chromatic Adaptation Negative XYZ Consistency (ICC TN Negative PCSXYZ, ¬ß9.2.10)
         'rXYZ' contains negative component(s)
         [OK] Negative XYZ values present with chad tag ‚Äî consistent with chromatic adaptation (BT.2020/DCI-P3 pattern)
      [OK] Conformant

[H1171] CF-171: White Point Non-Negative Luminance
  [CF-171] White Point Non-Negative Luminance (ICC TN Negative PCSXYZ, ¬ß3.1.24)
         [OK] White point luminance values are non-negative
      [OK] Conformant

[H1172] CF-172: Colorant XYZ Sum White Point Consistency
  [CF-172] Colorant XYZ Sum White Point Consistency (ICC TN Negative PCSXYZ, ¬ß9.2.7)
         Column sum: X=0.9642 Y=1.0000 Z=0.8249
         White point: X=0.9642 Y=1.0000 Z=0.8249
         [OK] Colorant sum matches white point within tolerance
      [OK] Conformant

[H1173] CF-173: PCS XYZ Absorber Encoding
  [CF-173] PCS XYZ Absorber Encoding (ICC TN Negative PCSXYZ, ¬ß6.4.3)
         [OK] White point and luminance properly distinguish from absorber encoding
      [OK] Conformant

[H1174] CF-174: Lab Conversion Clipping Awareness
  [CF-174] Lab Conversion Clipping Awareness (ICC TN Negative PCSXYZ, ¬ß6.4)
         1 matrix column(s) with negative components in XYZ PCS profile
         [INFO] Per ICC TN: CMMs should accept negative PCSXYZ without clipping; on Lab conversion clip per-component ‚Äî ¬ß6.4
      [OK] Conformant

[H1123] CF-123: ADGC Class Restriction
         No ADGC tag present ‚Äî check not applicable
      [OK] Conformant

[H1124] CF-124: ADGC Type Signature
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1125] CF-125: ADGC Function Type ID
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1126] CF-126: ADGC Reserved Bytes
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1127] CF-127: ADGC Float Field Finiteness
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1128] CF-128: ADGC Weight Coefficient Sum
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1129] CF-129: ADGC Curve Position Bounds
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1130] CF-130: ADGC Image-Specific GUID Flags
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1131] CF-131: ADGC Headroom Range Plausibility
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1132] CF-132: ADGC Curve Data Monotonicity
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1133] CF-133: ADGC H_baseline vs H_alternate Div-by-Zero
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1134] CF-134: ADGC Per-Channel GainMin ‚â§ GainMax
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1135] CF-135: ADGC Curve X-Value Domain Range
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1136] CF-136: ADGC Curve Adjacent-Point X-Equality
         No ADGC tag or read failed ‚Äî check skipped
      [OK] Conformant

[H1188] CF-188: Global Per-Tag Validate() Sweep
  [CF-188] Global Per-Tag Validate() Sweep (SampleICC ¬ß3 Compliance)
         Tag 'rXYZ': non-compliant per Validate()
           NonCompliant! - :XYZ - XYZNumber: Negative Z value!
         Swept 10 tags: 9 OK, 0 warnings, 1 errors
      [WARN]  1 non-conformance(s)

[H1189] CF-189: Tag Type Recognition Coverage
  [CF-189] Tag Type Recognition Coverage (SampleICC ¬ß3 CheckTagTypes)
         10/10 tags have recognized type signatures
         [OK] All 10 tag types are recognized by the factory
      [OK] Conformant

[H1190] CF-190: Profile Legibility Gate
  [CF-190] Profile Legibility Gate (SampleICC ¬ß3 ReadValidate)
         [OK] Profile is legible: 10 tags parsed, all non-NULL
      [OK] Conformant

[H1208] CF-208: Tag Type Version Compatibility
[CF-208] Tag Type Version Compatibility (ICC.1-2022-05 ¬ß7.2.4, ¬ß10)
         Profile version 4.x ‚Äî all standard tag types permitted
         [OK] Version 4.x tag types unrestricted
      [OK] Conformant

[H1209] CF-209: Colorspace Channel Count vs LUT Dimensions
[CF-209] Colorspace Channel Count vs LUT Dimensions (ICC.1-2022-05 ¬ß7.2.6, ¬ß10.8-10.11)
         colorSpace channels=3, PCS channels=3
         No AToB/BToA LUT tags present
         [OK] Colorspace/PCS channel counts match LUT dimensions
      [OK] Conformant

[H1212] CF-212: textType Null Termination
[CF-212] textType Null Termination (ICC.1-2022-05 ¬ß10.24)
         No textType tags found (profiles may use multiLocalizedUnicodeType)
         [OK] textType tag structure conformant
      [OK] Conformant

[H1213] CF-213: viewingConditionsType Completeness
[CF-213] viewingConditionsType Completeness (ICC.1-2022-05 ¬ß10.32)
         No viewingConditionsTag ('view') present
         [OK] viewingConditionsTag is optional
      [OK] Conformant

[H1220] CF-220: mluc Name Record Overlap Detection
[CF-220] mluc Name Record Overlap Detection (ICC TN PSD ¬ßmluc)
      [OK] Conformant

[H1221] CF-221: profileSequenceDescTag Structure
[CF-221] profileSequenceDescTag Structure (ICC.1-2022-05 ¬ß9.2.50)
         No profileSequenceDescTag ‚Äî not required for this class
      [OK] Conformant

[H1222] CF-222: profileSequenceIdentifierTag Validation
[CF-222] profileSequenceIdentifierTag Validation (ICC.1-2022-05 ¬ß9.2.51)
         No profileSequenceIdentifierTag ('psid') present
      [OK] Conformant

[H1223] CF-223: mluc Zero-Name Placeholder Encoding
[CF-223] mluc Zero-Name Placeholder Encoding (ICC TN PSD ¬ßplaceholder)
         No zero-name mluc tags found
      [OK] Conformant

[H1224] CF-224: mluc Reserved Field Zero
[CF-224] mluc Reserved Field Zero (ICC.1-2022-05 ¬ß10.13)
         [OK] 2 mluc tag(s) checked, all reserved fields zero
      [OK] Conformant

[H1225] CF-225: mluc Name Record String Alignment
[CF-225] mluc Name Record String Alignment (ICC.1-2022-05 ¬ß7.1, ¬ß10.13)
         [OK] 2 mluc tag(s) checked, all strings properly aligned
      [OK] Conformant

[H1226] CF-226: mluc Size Inference Safety
[CF-226] mluc Size Inference Safety (ICC TN PSD ¬ßsize)
         [OK] 2 mluc tag(s) checked, sizes consistent with records
      [OK] Conformant

[H1227] CF-227: v4 Text Tag Unicode Migration
[CF-227] v4 Text Tag Unicode Migration (ICC.1-2022-05 S9)
         [OK] All v4+ text tags use multiLocalizedUnicodeType
      [OK] Conformant

[H1228] CF-228: grayTRCTag Semantic Validation
[CF-228] grayTRCTag Semantic Validation (v2->v4 TN)
         Profile color space is not Gray -- grayTRC check N/A
      [OK] Conformant

[H1229] CF-229: Rendering Intent Dominance Per Class
[CF-229] Rendering Intent Dominance Per Class (v2->v4 TN)
         AToB tags: 0, BToA tags: 0, class: 0x6D6E7472
         [OK] Rendering intent dominance consistent with profile class
      [OK] Conformant

[H1230] CF-230: CIELAB Encoding Version Consistency
[CF-230] CIELAB Encoding Version Consistency (ICC.1-2022-05 S6.5.9)
         PCS is not Lab -- CIELAB encoding check N/A
      [OK] Conformant

[H1231] CF-231: LUT Processing Element Sequence
[CF-231] LUT Processing Element Sequence (ICC.1-2022-05 S10.10-10.11)
         No lutAtoB/lutBtoA type tags found
      [OK] Conformant

[H1232] CF-232: Date/Time UTC and Temporal Consistency
[CF-232] Date/Time UTC and Temporal Consistency (ICC.1-2022-05 S7.2.8)
         Profile creation: 2022-01-01 00:00:00 (UTC)
         [OK] Date/time fields consistent with UTC encoding
      [OK] Conformant

[H1233] CF-233: colorantOrderTag Index Validation
[CF-233] colorantOrderTag Index Validation (ICC.1-2022-05 S9.2.11, S10.3)
         No colorantOrderTag present
      [OK] Conformant

[H1234] CF-234: v4 Perceptual PCS Reference Medium
[CF-234] v4 Perceptual PCS Reference Medium (ICC.1-2022-05 Annex D)
         XYZ PCS with perceptual intent: encoding bounds per Annex A.3 apply
         [OK] XYZ PCS noted -- clipping at PCS encoding bounds
      [OK] Conformant

[H1247] CF-247: viewingConditionsType Illuminant Type Range
      [OK] Conformant

[H1248] CF-248: namedColor2Type Device Coords Limit
      [OK] Conformant

[H1249] CF-249: profileDescriptionTag Non-Empty
      [OK] Conformant

[H1250] CF-250: copyrightTag Non-Empty
      [OK] Conformant

[H1251] CF-251: chromaticityType Phosphor Type Range
      [OK] Conformant

[H1252] CF-252: curveType Gamma Positive/Finite
      [OK] Conformant

[H1253] CF-253: chromaticityType Channel Count
      [OK] Conformant

[H1254] CF-254: Technology Signature Registered
      [OK] Conformant

[H1263] CF-263: Perceptual PCS White Point D50
[CF-263] Perceptual PCS White Point D50 (ICC.1-2022-05 Annex D)
         [OK] Perceptual rendering intent PCS illuminant matches D50
      [OK] Conformant

[H1264] CF-264: parametricCurveType Function Type Range
[CF-264] parametricCurveType Function Type Range (ICC.1-2022-05 ¬ß10.18)
         No MBB tags with parametric curves found
         [OK] All parametricCurveType function types in range [0..4]
      [OK] Conformant

[H1265] CF-265: mluc Language/Country Code Validity
[CF-265] mluc Record Language/Country Code (ICC.1-2022-05 ¬ß10.15)
         [OK] mluc language/country codes valid
      [OK] Conformant

[H1273] CF-273: Primary Colorant XYZ Values Positive
[CF-273] Primary Colorant XYZ Values Positive (ICC.1-2022-05 ¬ß10.28)
         [OK] Primary colorant XYZ values plausible
      [OK] Conformant

[H1274] CF-274: Primary Colorant Chromaticity Sum
[CF-274] Primary Colorant Chromaticity Sum (TN v4-matrix-entries)
         [OK] Primary colorant chromaticity sums plausible
      [OK] Conformant

[H1275] CF-275: copyrightTag Must Be mluc for v4+
[CF-275] copyrightTag Must Be mluc for v4+ (ICC.1-2022-05 ¬ß9.2.14)
         [OK] copyrightTag is mluc for v4+
      [OK] Conformant

[H1276] CF-276: profileDescriptionTag Must Be mluc for v4+
[CF-276] profileDescriptionTag Must Be mluc for v4+ (ICC.1-2022-05 ¬ß9.2.44)
         [OK] profileDescriptionTag is mluc for v4+
      [OK] Conformant

[H1277] CF-277: mediaWhitePointTag Must Be XYZType
[CF-277] mediaWhitePointTag Must Be XYZType (ICC.1-2022-05 ¬ß9.2.35)
         [OK] mediaWhitePointTag is XYZType
      [OK] Conformant

[H1278] CF-278: chromaticAdaptationTag Type
[CF-278] chromaticAdaptationTag Type (ICC.1-2022-05 ¬ß9.2.2)
         [OK] chromaticAdaptationTag is s15Fixed16ArrayType
      [OK] Conformant

[H1279] CF-279: TRC Curve Values Non-Negative
[CF-279] TRC Curve Values Non-Negative (ICC.1-2022-05 ¬ß10.5)
         [OK] TRC curve values non-negative
      [OK] Conformant

[H1280] CF-280: XYZ Element Luminance (Y) Non-Negative
[CF-280] XYZ Element Luminance (Y) Non-Negative (ICC.1-2022-05 ¬ß10.28)
         [OK] XYZ luminance values non-negative
      [OK] Conformant

[H1281] CF-281: profileSequenceDescTag Structure
[CF-281] profileSequenceDescTag Structure (ICC.1-2022-05 ¬ß10.16)
      [OK] Conformant


--- Required Tag Conformance (CF-040..CF-053, CF-202, CF-204..CF-205, CF-207, CF-211, CF-258..CF-260, CF-266..CF-272, CF-282..CF-283) ---

[H1040] CF-040: Common Required Tags (cprt, desc, wtpt)
[CF-040] Common Required Tags (Non-DeviceLink) (ICC.1-2022-05 ¬ß8.2)
         'desc' (profileDescriptionTag): present
         'cprt' (copyrightTag): present
         'wtpt' (mediaWhitePointTag): present
         'chad' (chromaticAdaptationTag): present
         [OK] All common required tags present
      [OK] Conformant

[H1042] CF-042: Display Profile Required Tags
[CF-042] Display Profile Required Tags (ICC.1-2022-05 ¬ß8.4 Tables 25-27)
         Matrix/TRC model detected (redMatrixColumnTag present)
         'rXYZ' (redMatrixColumnTag): present
         'gXYZ' (greenMatrixColumnTag): present
         'bXYZ' (blueMatrixColumnTag): present
         'rTRC' (redTRCTag): present
         'gTRC' (greenTRCTag): present
         'bTRC' (blueTRCTag): present
         [OK] Display profile required tags present
      [OK] Conformant

[H1048] CF-048: Rendering Intent vs Transform Consistency
[CF-048] Rendering Intent Transform Consistency (ICC.1-2022-05 ¬ß7.2.15, ¬ß8)
         Declared rendering intent: 0 (Perceptual)
         [OK] Rendering intent consistent with transform tags
      [OK] Conformant

[H1049] CF-049: Matrix/TRC Profiles Must Use PCS XYZ
[CF-049] Matrix/TRC Profile PCS Must Be XYZ (ICC.1-2022-05 ¬ß8.3-8.4)
         PCS='XYZ ' ‚Äî correct for matrix/TRC
         [OK] PCS is XYZ as required
      [OK] Conformant

[H1050] CF-050: xCLR Spaces Require Colorant Table
[CF-050] xCLR Colorant Table Required (ICC.1-2022-05 ¬ß8.5-8.6)
         Colour space is not xCLR ‚Äî skipped
         [OK] Not an N-component colour space
      [OK] Conformant

[H1051] CF-051: DeviceLink Prohibited Tags
[CF-051] DeviceLink Prohibited Tags (ICC.1-2022-05 ¬ß8.6 Table 30)
         Not a DeviceLink profile ‚Äî skipped
         [OK] Not applicable
      [OK] Conformant

[H1052] CF-052: Transform Tag Pair Completeness
[CF-052] Transform Tag Pair Consistency (ICC.1-2022-05 ¬ß8.3-8.5)
         [OK] All transform tag pairs consistent
      [OK] Conformant

[H1053] CF-053: CICP Tag Class Restriction
[CF-053] cicpTag Class Restriction (ICC.1-2022-05 ¬ß9.2.11)
         'cicp' (cicpTag): not present ‚Äî no restriction check needed
         [OK] No cicpTag to validate
      [OK] Conformant

[H1054] CF-054: v5 Spectral Required Tags
[CF-054] v5 Spectral Required Tags (ICC.2-2023 ¬ß8)
         Profile version 4 ‚Äî not v5, skipped
         [OK] Not a v5 profile
      [OK] Conformant

[H1055] CF-055: D2B/B2D Tag Pair Completeness
[CF-055] D2B/B2D Tag Pair Completeness (ICC.1-2022-05 ¬ß8)
         No D2B/B2D tags found ‚Äî skipped
         [OK] No D2B/B2D tags to validate
      [OK] Conformant

[H1056] CF-056: Embedded Profile Structure
[CF-056] Embedded Profile Structure (ICC.2-2023 ¬ß9.2)
         No embedded profile tag ('ICC5') found ‚Äî skipped
         [OK] No embedded profile to validate
      [OK] Conformant

[H1057] CF-057: Dictionary Tag Structure v5
[CF-057] Dictionary Tag Structure v5 (ICC.2-2023 ¬ß9.2.25)
         Profile version 4 ‚Äî not v5, skipped
         [OK] Not a v5 profile
      [OK] Conformant

[H1058] CF-058: Profile Sequence Identifier v5
[CF-058] Profile Sequence Identifier v5 (ICC.2-2023 ¬ß8)
         Profile version 4 ‚Äî not v5, skipped
         [OK] Not a v5 profile
      [OK] Conformant

[H1059] CF-059: Colorimetric Intent Image State
[CF-059] Colorimetric Intent Image State (ICC.1-2022-05 ¬ß9.2.12)
         'ciis' (colorimetricIntentImageStateTag): not present ‚Äî skipped
         [OK] No colorimetricIntentImageState tag
      [OK] Conformant

[H1095] CF-095: Non-Required Tag Identification
  [CF-095] Non-Required Tag Identification (ICC.1-2022-05 ¬ß8)
           Additional tag: 'chad' (0x63686164)
           [INFO] 1 non-required tag(s) present
      [OK] Conformant

[H1096] CF-096: Private Tag Signature Range
  [CF-096] Private Tag Signature Range (ICC.1-2022-05 ¬ß9)
           [OK] No private tags
      [OK] Conformant

[H1097] CF-097: Private Tag Documentation
  [CF-097] Private Tag Documentation (ICC.1-2022-05 ¬ß9)
           [OK] No private tags
      [OK] Conformant

[H1098] CF-098: Undocumented Private Tags
  [CF-098] Undocumented Private Tag Identification (ICC.1-2022-05 ¬ß9)
           [OK] All tags are recognized ICC signatures
      [OK] Conformant

[H1103] CF-103: Tag Alignment & Offset Validity
  [CF-103] Tag Table Alignment & Offset Validity (ICC.1-2022-05 ¬ß7.3.1)
           [OK] All tag offsets aligned and within bounds
      [OK] Conformant

[H1104] CF-104: DeviceLink PCS Consistency
  [CF-104] DeviceLink PCS Consistency (ICC.1-2022-05 ¬ß8.6)
           Not a DeviceLink profile ‚Äî check not applicable
      [OK] Conformant

[H1111] CF-111: Required Tags per ICC Version
  [CF-111] Required Tags per ICC Version (ICC.1-2022-05 ¬ß8.2-8.9)
           [OK] Version-specific required tags present
      [OK] Conformant

[H1117] CF-117: Rendering Intent Tags per Class
  [CF-117] Rendering Intent Tags per Class (ICC.1-2022-05 ¬ß8.3-8.5)
           [OK] Rendering intent tags appropriate for profile class
      [OK] Conformant

[H1118] CF-118: Private Tag Creator Signature
  [CF-118] Private Tag Creator Signature (ICC.1-2022-05 ¬ß9)
           [OK] Creator signature present (0x6170706C)
      [OK] Conformant

[H1119] CF-119: Profile Sequence Identifier
  [CF-119] Profile Sequence Identifier (ICC.1-2022-05 ¬ß8.6)
           V4 profile without profileSequenceIdentifierTag
           [INFO] ¬ß10.15 recommends profileSequenceIdentifierTag
           [OK] Profile sequence identification validated
      [OK] Conformant

[H1120] CF-120: Named Color Space Dimensions
  [CF-120] Named Color Space Dimensions (ICC.1-2022-05 ¬ß10.14)
           Not a NamedColor profile ‚Äî check not applicable
      [OK] Conformant

[H1202] CF-202: Tag Data Padding Zero-Fill
  [CF-202] Tag Data Padding Zero-Fill (ICC.1-2022-05 ¬ß7.2.1c)
           [OK] All inter-tag padding bytes are zero
      [OK] Conformant

[H1204] CF-204: Device Attributes Semantic Validation
  [CF-204] Device Attributes Semantic Validation (ICC.1-2022-05 ¬ß7.2.14 Table 22)
           Bit 0: reflective
           Bit 1: glossy
           Bit 2: positive media
           Bit 3: colour
           [OK] Device attributes semantics conformant
      [OK] Conformant

[H1205] CF-205: Tag Data Region Gap Analysis
  [CF-205] Tag Data Region Gap Analysis (ICC.1-2022-05 ¬ß7.3)
           Distinct data regions: 8
           Data coverage: 284 / 536 bytes (53.0%)
           Inter-region gaps: 0 (largest: 0 bytes)
           [OK] Tag data region layout conformant
      [OK] Conformant

[H1207] CF-207: mediaWhitePointTag Value Range
[CF-207] mediaWhitePointTag Value Range (ICC.1-2022-05 ¬ß10.27)
         wtpt: X=0.9642, Y=1.0000, Z=0.8249
         [OK] mediaWhitePointTag values conformant
      [OK] Conformant

[H1211] CF-211: AToB/BToA Tag Pair Completeness
[CF-211] AToB/BToA Tag Pair Completeness (ICC.1-2022-05 ¬ß9.2.1-9.2.2)
         No AToB/BToA LUT pairs present (profile may use Matrix/TRC)
         [OK] AToB/BToA tag pair completeness conformant
      [OK] Conformant

[H1258] CF-258: Display v4+ mediaWhitePointTag D50
[CF-258] Display v4+ mediaWhitePointTag D50 (ICC.1-2022-05 ¬ß8.4)
         [OK] mediaWhitePointTag equals D50 (tolerance +/-0.005)
      [OK] Conformant

[H1259] CF-259: colorantOrderTag vs colorantTableTag Cross-Validation
[CF-259] colorantOrderTag vs colorantTableTag Cross-Validation (ICC.1-2022-05 ¬ß10.3)
         Neither colorantOrderTag nor colorantTableTag present
      [OK] Conformant

[H1260] CF-260: Output Profile gamutTag Rendering Intent
[CF-260] Output Profile gamutTag Rendering Intent (ICC.1-2022-05 ¬ß9.2.22)
         Not an Output profile ‚Äî gamutTag check not applicable
      [OK] Conformant

[H1266] CF-266: Input Profile Device Color Space
[CF-266] Input Profile Device Color Space (ICC.1-2022-05 ¬ß6.1)
      [OK] Conformant

[H1267] CF-267: Display Profile Color Space
[CF-267] Display Profile Color Space (ICC.1-2022-05 ¬ß6.2)
         [OK] Display profile device color space valid
      [OK] Conformant

[H1268] CF-268: Output Profile Color Space
[CF-268] Output Profile Color Space (ICC.1-2022-05 ¬ß6.3)
      [OK] Conformant

[H1269] CF-269: DeviceLink Data Color Space Matching
[CF-269] DeviceLink Data Color Space Matching (ICC.1-2022-05 ¬ß6.4)
      [OK] Conformant

[H1270] CF-270: Abstract Profile PCS
[CF-270] Abstract Profile PCS (ICC.1-2022-05 ¬ß6.6)
      [OK] Conformant

[H1271] CF-271: NamedColor Profile PCS
[CF-271] NamedColor Profile PCS (ICC.1-2022-05 ¬ß6.7)
      [OK] Conformant

[H1272] CF-272: Matrix/TRC RGB Required Colorant Tags
[CF-272] Matrix/TRC RGB Required Colorant Tags (ICC.1-2022-05 ¬ß9.2.47)
         [OK] All matrix/TRC colorant tags present
      [OK] Conformant

[H1282] CF-282: DeviceLink AToB0Tag Required
[CF-282] DeviceLink AToB0Tag Required (ICC.1-2022-05 ¬ß6.4)
      [OK] Conformant

[H1283] CF-283: DeviceLink profileSequenceDescTag
[CF-283] DeviceLink profileSequenceDescTag (ICC.1-2022-05 ¬ß6.4)
      [OK] Conformant


--- LUT/Matrix Conformance (CF-060..CF-070, CF-163..CF-168, CF-255..CF-256, CF-261..CF-262) ---

[H1060] CF-060: LUT Input Channel Count
[CF-060] LUT Input Channel Count (ICC.1-2022-05 ¬ß10.8-10.11)
         [OK] Matrix/TRC device-side channel tags valid
      [OK] Conformant

[H1061] CF-061: LUT Output Channel Count
[CF-061] LUT Output Channel Count (ICC.1-2022-05 ¬ß10.8-10.11)
         [OK] Matrix/TRC PCS-side channel tags valid
      [OK] Conformant

[H1062] CF-062: CLUT Grid Dimensionality
[CF-062] CLUT Grid Dimensionality (ICC.1-2022-05 ¬ß10.8-10.11)
         [N/A] No CLUT elements found
      N/A: No CLUT elements found
      [OK] Conformant

[H1063] CF-063: lut8Type Fixed 256-Entry Tables
[CF-063] lut8Type Fixed Table Size 256 (ICC.1-2022-05 ¬ß10.9)
         No lut8Type tags found ‚Äî check not applicable
         [OK] lut8Type table sizes conformant
      [OK] Conformant

[H1064] CF-064: lut16Type Table Size Range
[CF-064] lut16Type Table Size Range 2-4096 (ICC.1-2022-05 ¬ß10.10)
         No lut16Type tags found ‚Äî check not applicable
         [OK] lut16Type table sizes within range
      [OK] Conformant

[H1065] CF-065: lutAToBType Element Presence
[CF-065] lutAToBType Processing Element Present (ICC.1-2022-05 ¬ß10.11)
         No lutAToBType tags found ‚Äî check not applicable
         [OK] lutAToBType element presence valid
      [OK] Conformant

[H1066] CF-066: lutBToAType Element Presence
[CF-066] lutBToAType Processing Element Present (ICC.1-2022-05 ¬ß10.12)
         No lutBToAType tags found ‚Äî check not applicable
         [OK] lutBToAType element presence valid
      [OK] Conformant

[H1067] CF-067: LUT Matrix Identity for Non-XYZ PCS
[CF-067] lut8/16 Matrix Identity When Not PCSXYZ (ICC.1-2022-05 ¬ß10.8-10.10)
         PCS is XYZ ‚Äî matrix may be non-identity
         [OK] PCS=XYZ, identity check not applicable
      [OK] Conformant

[H1068] CF-068: Chad Matrix Invertible
[CF-068] Chromatic Adaptation Matrix Invertible (ICC.1-2022-05 ¬ß9.2.10)
         Determinant = 0.779453 ‚Äî matrix is invertible
         [OK] Chromatic adaptation matrix invertible
      [OK] Conformant

[H1069] CF-069: Matrix Column XYZ Count
[CF-069] Matrix Column Tag XYZ Count (ICC.1-2022-05 ¬ß9.2.7, ¬ß9.2.18, ¬ß9.2.31)
         [OK] Matrix column XYZ counts valid
      [OK] Conformant

[H1070] CF-070: Chad Array Count = 9
[CF-070] Chad s15Fixed16 Array Count 9 (ICC.1-2022-05 ¬ß9.2.10)
         [OK] Chad array count is 9
      [OK] Conformant

[H1071] CF-071: Curve Count vs Channel Match
[CF-071] Curve Count vs Channel Match (ICC.1-2022-05 ¬ß10.10-10.12)
         No LUT tags found ‚Äî check not applicable
         [OK] Curve counts match channel expectations
      [OK] Conformant

[H1072] CF-072: CLUT Output Value Range
[CF-072] CLUT Output Value Range (ICC.1-2022-05 ¬ß10.8-10.12)
         No CLUT elements found ‚Äî check not applicable
         [OK] CLUT output values are finite
      [OK] Conformant

[H1073] CF-073: MBB Matrix Determinant Non-Zero
[CF-073] MBB Matrix Determinant Non-Zero (ICC.1-2022-05 ¬ß10.10-10.12)
         No MBB tags with matrix found ‚Äî check not applicable
         [OK] MBB matrix determinants are non-zero
      [OK] Conformant

[H1074] CF-074: A2B/B2A Dimension Consistency
[CF-074] A2B/B2A Dimension Consistency (ICC.1-2022-05 ¬ß10.8-10.12)
         No matching A2B/B2A pairs found ‚Äî check not applicable
         [OK] A2B/B2A dimensions are consistent
      [OK] Conformant

[H1075] CF-075: Tag Data Size vs Dimensions
[CF-075] Tag Data Size vs Dimensions (ICC.1-2022-05 ¬ß10.8-10.12)
         No LUT tags found ‚Äî check not applicable
         [OK] LUT dimensions are plausible
      [OK] Conformant

[H1076] CF-076: Curve Response Direction
[CF-076] Curve Response Direction (ICC.1-2022-05 ¬ß10.5)
         No AToB tags with B curves found ‚Äî check not applicable
         [OK] B curves are non-decreasing
      [OK] Conformant

[H1077] CF-077: CLUT Grid Size Plausibility
[CF-077] CLUT Grid Size Plausibility (ICC.1-2022-05 ¬ß10.8-10.12)
         No CLUT elements found ‚Äî check not applicable
         [OK] CLUT grid sizes are plausible
      [OK] Conformant

[H1078] CF-078: MBB B-Curve Presence
[CF-078] MBB B-Curve Presence (ICC.1-2022-05 ¬ß10.10-10.12)
         No lutAToBType/lutBToAType tags found ‚Äî check not applicable
         [OK] B curves present in all MBB tags
      [OK] Conformant

[H1079] CF-079: LUT Bit Depth Consistency
[CF-079] LUT Bit Depth Consistency (ICC.1-2022-05 ¬ß10.9-10.10)
         No lut8/lut16 type tags found ‚Äî check not applicable
         [OK] Legacy LUT curve sizes are consistent
      [OK] Conformant

[H1105] CF-105: LUT Channel Symmetry
  [CF-105] LUT Channel Symmetry (ICC.1-2022-05 ¬ß10.8-10.11)
         No AToB/BToA tag pairs found ‚Äî check not applicable
         [OK] LUT channel symmetry validated
      [OK] Conformant

[H1106] CF-106: Curve Monotonicity
  [CF-106] Curve Monotonicity (ICC.1-2022-05 ¬ß10.5)
         [N/A] No tabulated TRC curves found
      N/A: No tabulated TRC curves found
         [OK] TRC curves are monotonically non-decreasing
      [OK] Conformant

[H1108] CF-108: CLUT Grid Point Range
  [CF-108] CLUT Grid Point Range (ICC.1-2022-05 ¬ß10.8-10.10)
         No CLUT elements found ‚Äî check not applicable
         [OK] CLUT grid points in valid range [2,255]
      [OK] Conformant

[H1109] CF-109: Matrix Column Normalization
  [CF-109] Matrix Column Normalization (ICC.1-2022-05 ¬ß9.2.7)
         [OK] Matrix columns properly normalized
      [OK] Conformant

[H1110] CF-110: B Curves vs CLUT Output
  [CF-110] B Curves vs CLUT Output Count (ICC.1-2022-05 ¬ß10.8-10.11)
         No lutAToB/lutBToA with CLUT found ‚Äî check not applicable
         [OK] B curves match CLUT output channels
      [OK] Conformant

[H1116] CF-116: Curve Segment Continuity
  [CF-116] Curve Segment Continuity (ICC.1-2022-05 ¬ß10.18)
         [OK] Curve segments continuous
      [OK] Conformant

[H1163] CF-163: LUT Matrix Coefficient Finite
[CF-163] LUT Matrix Coefficient Finite (ICC v4 Matrix Entries TN)
         No LUT tags with matrix found ‚Äî check not applicable
         [OK] All LUT matrix coefficients are finite
      [OK] Conformant

[H1164] CF-164: LUT Matrix s15Fixed16 Range
[CF-164] LUT Matrix s15Fixed16 Range (ICC v4 Matrix Entries TN)
         No LUT tags with matrix found ‚Äî check not applicable
         [OK] All LUT matrix coefficients within s15Fixed16 range
      [OK] Conformant

[H1165] CF-165: LUT Matrix Determinant Non-Singular
[CF-165] LUT Matrix Determinant Non-Singular (ICC v4 Matrix Entries TN)
         No LUT tags with matrix found ‚Äî check not applicable
         [OK] All LUT matrices are non-singular
      [OK] Conformant

[H1166] CF-166: LUT Matrix Row Non-Zero
[CF-166] LUT Matrix Row Non-Zero (ICC v4 Matrix Entries TN)
         No LUT tags with matrix found ‚Äî check not applicable
         [OK] All LUT matrix rows have non-zero elements
      [OK] Conformant

[H1167] CF-167: LUT Matrix Offset Bounds
[CF-167] LUT Matrix Offset Bounds (ICC v4 Matrix Entries TN)
         No LUT tags with matrix offset constants found ‚Äî check not applicable
         [OK] All LUT matrix offsets within reasonable bounds
      [OK] Conformant

[H1168] CF-168: LUT Matrix Input-Output Range
[CF-168] LUT Matrix Input-Output Range (ICC v4 Matrix Entries TN)
         No LUT tags with matrix found ‚Äî check not applicable
         [OK] LUT matrix outputs within expected range
      [OK] Conformant

[H1255] CF-255: CLUT Grid Point Values
      [OK] Conformant

[H1256] CF-256: LUT I/O Channels vs Profile Spaces
      [OK] Conformant

[H1261] CF-261: M-Curve Count = 3 When Matrix Present
[CF-261] lutAToBType M-Curve Count = 3 When Matrix Present (ICC.1-2022-05 ¬ß10.11)
         No lutAToB/BToA tags with matrix+M-curves found
         [OK] M-curve count consistent with matrix presence
      [OK] Conformant

[H1262] CF-262: B-Curve Count vs Output Channels
[CF-262] LUT B-Curve Count vs Output Channels (ICC.1-2022-05 ¬ß10.11)
         No lutAToBType tags found
         [OK] B-curve count matches output channel count
      [OK] Conformant


--- v5/iccMAX Conformance (CF-080..CF-090, CF-113..CF-115, CF-137..CF-162, CF-175..CF-198, CF-235..CF-242, CF-257, CF-284..CF-316) ---

[H1178] CF-178: Chad Diagonal Dominance
[CF-178] Chad Matrix Diagonal Dominance (ICC TN Partial Adaptation)
         All rows diagonally dominant ‚Äî valid adaptation structure
         [OK] Chad matrix diagonally dominant
      [OK] Conformant

[H1179] CF-179: Chad D50 Identity
[CF-179] Chad D50-to-D50 Identity Check (ICC TN Partial Adaptation)
         Illuminant is D50 but chad deviates from identity (max dev = 0.248322)
         [WARN] D50 illuminant with non-identity chad ‚Äî profile may have inconsistent adaptation
      [WARN]  1 non-conformance(s)

[H1183] CF-183: Chad Column Normalization
[CF-183] Chad Column Normalization (ICC TN Partial Adaptation)
         Column 0 norm = 1.0483
         Column 1 norm = 0.9909
         Column 2 norm = 0.7535
         All column norms within reasonable range
         [OK] Chad column normalization conformant
      [OK] Conformant

  [INFO] Profile version 4 ‚Äî v5/iccMAX checks skipped

--- Security Conformance (CF-091..CF-094) ---

[H1091] CF-091: Malware Signature Scan
  [CF-091] Malware Signature Scan (ICC.1-2022-05 ¬ß9)
           [OK] No malware signatures detected in tag data
      [OK] Conformant

[H1092] CF-092: Private Tag Identification
  [CF-092] Private/Unregistered Tag Identification (ICC.1-2022-05 ¬ß9)
           [OK] All tags are registered ICC signatures
      [OK] Conformant

[H1093] CF-093: Private Tag Content Scan
  [CF-093] Private Tag Content Security Scan (ICC.1-2022-05 ¬ß9)
           [OK] No private tags to scan
      [OK] Conformant

[H1094] CF-094: NOP/Shellcode Pattern Scan
  [CF-094] NOP/Shellcode Pattern Scan (CWE-506)
           [OK] No NOP sled or shellcode patterns detected
      [OK] Conformant


--- Private Tag Conformance (CF-095..CF-098) ---


--- Quality Conformance (CF-099..CF-102) ---

[H1099] CF-099: Round-Trip CIEDE2000
  [CF-099] Round-Trip Transform CIEDE2000 (ICC.1-2022-05 ¬ß8)
           Model: matrix/TRC, samples: 729
           First round trip:  avg DeltaE00=0.0000  max DeltaE00=0.0000
           Second round trip: avg DeltaE00=0.0000  max DeltaE00=0.0000
           [OK] Round-trip DeltaE00 metrics recorded
      [OK] Conformant

[H1100] CF-100: Curve Invertibility
  [CF-100] Curve Invertibility Check (ICC.1-2022-05 ¬ß10.6)
           rTRC: avg inv err=0.000000  max err=0.000000
           gTRC: avg inv err=0.000000  max err=0.000000
           bTRC: avg inv err=0.000000  max err=0.000000
           [OK] 3 curve(s) checked ‚Äî invertibility metrics recorded
      [OK] Conformant

[H1101] CF-101: Transform Smoothness
  [CF-101] Transform Smoothness (ICC.1-2022-05 ¬ß10.8)
           Model: matrix/TRC multi-axis, samples: 256
           Avg step DeltaE00=1.1718  max step DeltaE00=4.0637  max curvature=0.5800
           Large discontinuities (>6.0 DeltaE00): 0
           [OK] Transform smoothness metrics recorded
      [OK] Conformant

[H1102] CF-102: Characterization Round-Trip
  [CF-102] Characterization Data Round-Trip (ICC.1-2022-05 ¬ß9.2.26)
           [N/A] No characterization data (targ) tag present
      N/A: No characterization data (targ) tag present
      [OK] Conformant


Deep Conformance Summary: 3 issue(s)

=======================================================================
PHASE 3: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /tmp/iccanalyzer-FynhxB.icc

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
PHASE 4: SIGNATURE ANALYSIS
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
PHASE 5: PROFILE STRUCTURE DUMP
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
  Size:              0x00000218 (536 bytes)
  CMM Type:          'appl' (0x6170706C)
  Version:           4.0.0.0 (0x04000000)
  Device Class:      DisplayClass
  Color Space:       RgbData (3 channels)
  PCS:               XYZData
  Date/Time:         2022-01-01 00:00:00
  Magic:             0x61637370 [OK]
  Platform:          Macintosh
  Profile Flags:     0x00000000
  Manufacturer:      'APPL' (0x4150504C)
  Model:             '....' (0x00000000)
  Device Attribs:    0x0000000000000000
  Rendering Intent:  Perceptual (0)
  PCS Illuminant:    X=0.9642 Y=1.0000 Z=0.8249
  Creator:           'appl' (0x6170706C)
  Profile ID:        (not set)

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
PHASE 6: TAG CONTENT ANALYSIS
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

--- 5I: V5/iccMAX Summary ---

  (Profile is v2/v4 ‚Äî v5/iccMAX summary not applicable)

--- 5J: Version Classification & Capabilities ---

  Version Classification:
    ICC Version:       4.0.0
    Specification:     ICC.1-2022-05 (v4)
    Features:          chromaticAdaptationTag, lut16/lutAToB, profileID
    Device Class:      DisplayClass
    Color Space:       RgbData (3 channels)
    Connection Space:  XYZData

  Transform Capabilities:
    AToB (device‚ÜíPCS):   no
    BToA (PCS‚Üídevice):   no
    DToB (device‚ÜíPCS):   no
    BToD (PCS‚Üídevice):   no
    TRC (matrix/gamma):  YES
    Gamut check:         no
    Chromatic adapt:     YES
    Preview:             no


=======================================================================
CONFORMANCE AUDIT SUMMARY
=======================================================================

File: /tmp/iccanalyzer-FynhxB.icc
Mode: Conformance (ICC specification audit)
Total Issues Detected: 5

[WARN] ANALYSIS COMPLETE - 5 issue(s) detected
  Review conformance findings above. Use --legacy for vulnerability analysis.


=======================================================================
IMAGE ANALYSIS SUMMARY
=======================================================================
Format:     TIFF
Dimensions: 4096 √ó 1
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

File: /home/h02332/po/research/test-profiles/fuzzed-xnu-DisplayP3.tif
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 17142 bytes (0x42F6)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 4D 4D 00 2A 00 00 40 08  41 41 41 FF 32 32 32 FF  |MM.*..@.AAA.222.|
0x0010: 39 4F 35 FF BE BE BE FF  39 4F 50 FF 37 72 9C FF  |9O5.....9OP.7r..|
0x0020: 68 20 24 FF 32 32 4E FF  41 41 41 FF 70 64 27 FF  |h $.22N.AAA.pd'.|
0x0030: 4F 2A 21 FF 50 50 36 FF  39 4F 35 FF BE BE BE FF  |O*!.PP6.9O5.....|
0x0040: 47 72 3F FF 41 41 41 FF  41 41 41 FF 94 2B 42 FF  |Gr?.AAA.AAA..+B.|
0x0050: 00 00 00 FF 59 7B 2C FF  40 53 14 FF 0E 2A 5F FF  |....Y{,.@S...*_.|
0x0060: 48 71 1E FF CC 9E F8 FF  29 61 31 FF 48 71 24 FF  |Hq......)a1.Hq$.|
0x0070: 40 53 1C FF 3A 62 19 FF  0E 2A 5F FF 3A 62 19 FF  |@S..:b...*_.:b..|

Header Fields (RAW - no validation):
  Profile Size:    0x4D4D002A (1296891946 bytes) MISMATCH
  CMM:             0x00004008  '..@.'
  Version:         0x414141FF  (65.4.1)
  Device Class:    0x323232FF  '222.'
  Color Space:     0x394F35FF  '9O5.'
  PCS:             0xBEBEBEFF  '....'
  Date/Time:       14671-20735-14194 40191:26656:9471
  Magic:           0x32324EFF  [INVALID]
  Platform:        0x414141FF  'AAA.'
  Flags:           0x706427FF [Embedded] [EmbeddedOnly]
  Manufacturer:    0x4F2A21FF  'O*!.'
  Model:           0x505036FF  'PP6.'
  Dev Attributes:  0x394F35FFBEBEBEFF [Transparency] [Matte]
  Rendering Intent:0x47723FFF  UNKNOWN
  PCS Illuminant:  X=16705.2578 Y=16705.2578 Z=-27604.7383
  Creator:         0x000000FF  '....'
  Profile ID:      597b2cff405314ff0e2a5fff48711eff
  Reserved 100-127: NON-ZERO [VIOLATION]

  --- V5/iccMAX Extended Header ---
  Spectral PCS:    0xBEBEBEFF  '....'
  Spectral Range:  0.0 - 0.2 nm, 18545 steps
  BiSpectral:      0.0 - 2.2 nm, 7423 steps
  MCS:             0x3A6219FF  ':b..'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 237658111 (0x0E2A5FFF)
WARNING: Suspicious tag count (>1000) - possible corruption

Tag Table Raw Data:
0x0080: 0E 2A 5F FF 3D 77 20 FF  48 71 1E FF 29 61 31 FF  |.*_.=w .Hq..)a1.|
0x0090: 48 71 1E FF 58 54 31 FF  3C 76 3A FF 3A 62 19 FF  |Hq..XT1.<v:.:b..|
0x00A0: 27 03 5F FF CC 9E F8 FF  0E 2A 5F FF 0E 2A 5F FF  |'._......*_..*_.|
0x00B0: 5B 65 1B FF 4E 6C 1D FF  00 00 00 FF 00 00 00 FF  |[e..Nl..........|
0x00C0: 29 61 31 FF 4C 16 9A FF  29 61 31 FF 27 03 5F FF  |)a1.L...)a1.'._.|
0x00D0: 29 61 31 FF 38 70 23 FF  CF 9F F6 FF 41 41 41 FF  |)a1.8p#.....AAA.|
0x00E0: 41 41 41 FF DB 9B 97 FF  00 00 00 FF BE BE BE FF  |AAA.............|
0x00F0: BE BE BE FF 41 41 41 FF  40 40 40 FF C8 F6 FD FF  |....AAA.@@@.....|
0x0100: 41 41 41 FF 40 40 40 FF  4E 80 34 FF 5A 1F 59 FF  |AAA.@@@.N.4.Z.Y.|
0x0110: E3 CE CF FF 2E 58 42 FF  41 41 41 FF 94 54 9C FF  |.....XB.AAA..T..|
0x0120: 4F 4F 4F FF 41 41 41 FF  51 23 33 FF 4F 4F 4F FF  |OOO.AAA.Q#3.OOO.|
0x0130: 41 41 41 FF BF BF BF FF  41 41 41 FF 86 F4 A9 FF  |AAA.....AAA.....|
0x0140: 40 40 40 FF 00 00 00 FF  BF BF BF FF 40 40 40 FF  |@@@.........@@@.|
0x0150: 05 03 1B FF DF 35 C2 FF  38 4E 4F FF 41 41 41 FF  |.....5..8NO.AAA.|
0x0160: 40 40 40 FF 32 32 32 FF  41 41 41 FF 41 41 41 FF  |@@@.222.AAA.AAA.|
0x0170: 8F EB A1 FF 3C 1B 2C FF  31 31 31 FF 00 00 00 FF  |....<.,.111.....|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x3D7720FF   '=w ˇ'        0x48711EFF   0x296131FF   '----'        OOB offset
1    0x48711EFF   'Hqˇ'        0x585431FF   0x3C763AFF   '----'        OOB offset
2    0x3A6219FF   ':bˇ'        0x27035FFF   0xCC9EF8FF   '----'        OOB offset
3    0x0E2A5FFF   '*_ˇ'        0x0E2A5FFF   0x5B651BFF   '----'        OOB offset
4    0x4E6C1DFF   'Nlˇ'        0x000000FF   0x000000FF   'ˇAAA'        OK
5    0x296131FF   ')a1ˇ'        0x4C169AFF   0x296131FF   '----'        OOB offset
6    0x27035FFF   ''_ˇ'        0x296131FF   0x387023FF   '----'        OOB offset
7    0xCF9FF6FF   'œüˆˇ'        0x414141FF   0x414141FF   '----'        OOB offset
8    0xDB9B97FF   '€õóˇ'        0x000000FF   0xBEBEBEFF   'ˇAAA'        OOB size
9    0xBEBEBEFF   'æææˇ'        0x414141FF   0x404040FF   '----'        OOB offset
10   0xC8F6FDFF   '»ˆ˝ˇ'        0x414141FF   0x404040FF   '----'        OOB offset
11   0x4E8034FF   'NÄ4ˇ'        0x5A1F59FF   0xE3CECFFF   '----'        OOB offset
12   0x2E5842FF   '.XBˇ'        0x414141FF   0x94549CFF   '----'        OOB offset
13   0x4F4F4FFF   'OOOˇ'        0x414141FF   0x512333FF   '----'        OOB offset
14   0x4F4F4FFF   'OOOˇ'        0x414141FF   0xBFBFBFFF   '----'        OOB offset
15   0x414141FF   'AAAˇ'        0x86F4A9FF   0x404040FF   '----'        OOB offset
16   0x000000FF   '    '        0xBFBFBFFF   0x404040FF   '----'        OOB offset
17   0x05031BFF   'ˇ'        0xDF35C2FF   0x384E4FFF   '----'        OOB offset
18   0x414141FF   'AAAˇ'        0x404040FF   0x323232FF   '----'        OOB offset
19   0x414141FF   'AAAˇ'        0x414141FF   0x8FEBA1FF   '----'        OOB offset
20   0x3C1B2CFF   '<,ˇ'        0x313131FF   0x000000FF   '----'        OOB offset
21   0x506C28FF   'Pl(ˇ'        0x384E4FFF   0x404040FF   '----'        OOB offset
22   0x414141FF   'AAAˇ'        0x000000FF   0xC22DA7FF   'ˇAAA'        OOB size
23   0x414141FF   'AAAˇ'        0x505036FF   0x62406CFF   '----'        OOB offset
24   0x581B67FF   'Xgˇ'        0xBEBEBEFF   0x575A4BFF   '----'        OOB offset
25   0x404040FF   '@@@ˇ'        0x414141FF   0x404040FF   '----'        OOB offset
26   0x404040FF   '@@@ˇ'        0x404040FF   0x414141FF   '----'        OOB offset
27   0x384E34FF   '8N4ˇ'        0x414141FF   0x31314DFF   '----'        OOB offset
28   0x5E283EFF   '^(>ˇ'        0x4C334EFF   0x000000FF   '----'        OOB offset
29   0x414141FF   'AAAˇ'        0xBEBEBEFF   0x505050FF   '----'        OOB offset
30   0x313131FF   '111ˇ'        0x859070FF   0x464E44FF   '----'        OOB offset
31   0x5D1EA8FF   ']®ˇ'        0x404040FF   0x414141FF   '----'        OOB offset
32   0x6295B8FF   'bï∏ˇ'        0x465D1AFF   0x222639FF   '----'        OOB offset
33   0x1D47F1FF   'GÒˇ'        0xBFBFBFFF   0x639B2EFF   '----'        OOB offset
34   0xB28DD8FF   '≤çÿˇ'        0xD93BC1FF   0x414141FF   '----'        OOB offset
35   0x414141FF   'AAAˇ'        0x414141FF   0x000000FF   '----'        OOB offset
36   0x000000FF   '    '        0x404040FF   0x384E34FF   '----'        OOB offset
37   0x74DBB5FF   't€µˇ'        0x000000FF   0xBFBFBFFF   'ˇAAA'        OOB size
38   0xBEBEBEFF   'æææˇ'        0x000000FF   0x414141FF   'ˇAAA'        OOB size
39   0x5E9DE9FF   '^ùÈˇ'        0x414141FF   0x4F4F34FF   '----'        OOB offset
40   0x414141FF   'AAAˇ'        0x5A6D25FF   0x693660FF   '----'        OOB offset
41   0x404040FF   '@@@ˇ'        0x000000FF   0x000000FF   'ˇAAA'        OK
42   0x4C334EFF   'L3Nˇ'        0x404040FF   0x984CF1FF   '----'        OOB offset
43   0x38676FFF   '8goˇ'        0x000000FF   0x404040FF   'ˇAAA'        OOB size
44   0x404040FF   '@@@ˇ'        0x414141FF   0x4F4F34FF   '----'        OOB offset
45   0x414141FF   'AAAˇ'        0x414141FF   0x271455FF   '----'        OOB offset
46   0x404040FF   '@@@ˇ'        0x000000FF   0x414141FF   'ˇAAA'        OOB size
47   0x404040FF   '@@@ˇ'        0x414141FF   0x404040FF   '----'        OOB offset
48   0x414141FF   'AAAˇ'        0xBFBFBFFF   0xBFBFBFFF   '----'        OOB offset
49   0xBFBFBFFF   'øøøˇ'        0x000000FF   0x414141FF   'ˇAAA'        OOB size
50   0x344455FF   '4DUˇ'        0x000000FF   0xC8B97AFF   'ˇAAA'        OOB size
51   0x404040FF   '@@@ˇ'        0x404040FF   0xBEBEBEFF   '----'        OOB offset
52   0x414141FF   'AAAˇ'        0xEBBCDEFF   0x404040FF   '----'        OOB offset
53   0x9D505DFF   'ùP]ˇ'        0xE4509FFF   0x777249FF   '----'        OOB offset
54   0x4F4F34FF   'OO4ˇ'        0x6C6C39FF   0xBEBEBEFF   '----'        OOB offset
55   0x63513AFF   'cQ:ˇ'        0x414141FF   0x4F4F4FFF   '----'        OOB offset
56   0x414141FF   'AAAˇ'        0x404040FF   0xDC6C92FF   '----'        OOB offset
57   0x404040FF   '@@@ˇ'        0xDC82BDFF   0xAF8343FF   '----'        OOB offset
58   0x000000FF   '    '        0xA92AE9FF   0xBEBEBEFF   '----'        OOB offset
59   0x384E34FF   '8N4ˇ'        0x000000FF   0xBEBEBEFF   'ˇAAA'        OOB size
60   0x4C3333FF   'L33ˇ'        0x000000FF   0xBEBEBEFF   'ˇAAA'        OOB size
61   0x1F1D3FFF   '?ˇ'        0x394F35FF   0x5FBE89FF   '----'        OOB offset
62   0xBFBFBFFF   'øøøˇ'        0x404040FF   0xBEBEBEFF   '----'        OOB offset
63   0x404040FF   '@@@ˇ'        0x273917FF   0x394F50FF   '----'        OOB offset
64   0x4B3232FF   'K22ˇ'        0x3952D9FF   0x61CF81FF   '----'        OOB offset
65   0xBFBFBFFF   'øøøˇ'        0x777F62FF   0x404040FF   '----'        OOB offset
66   0x487255FF   'HrUˇ'        0x31314DFF   0x404040FF   '----'        OOB offset
67   0x591BE7FF   'YÁˇ'        0x404040FF   0x404040FF   '----'        OOB offset
68   0xA0885CFF   '†à\ˇ'        0x414141FF   0xDB39B1FF   '----'        OOB offset
69   0xBFBFBFFF   'øøøˇ'        0xBEBEBEFF   0x404040FF   '----'        OOB offset
70   0x551B1CFF   'Uˇ'        0x4F2216FF   0x5C373AFF   '----'        OOB offset
71   0x4B324DFF   'K2Mˇ'        0x414141FF   0x000000FF   '----'        OOB offset
72   0xBEBEBEFF   'æææˇ'        0x404040FF   0x000000FF   '----'        OOB offset
73   0x000000FF   '    '        0x5D5B45FF   0x65DB47FF   '----'        OOB offset
74   0x000000FF   '    '        0x404040FF   0x96DEEAFF   '----'        OOB offset
75   0x572B53FF   'W+Sˇ'        0x384E4FFF   0xBFBFBFFF   '----'        OOB offset
76   0x404040FF   '@@@ˇ'        0xBEBEBEFF   0x414141FF   '----'        OOB offset
77   0xBEBEBEFF   'æææˇ'        0xC7F1C6FF   0x69E146FF   '----'        OOB offset
78   0x414141FF   'AAAˇ'        0x404040FF   0xBEBEBEFF   '----'        OOB offset
79   0x4B3232FF   'K22ˇ'        0xBFBFBFFF   0x414141FF   '----'        OOB offset
80   0x585567FF   'XUgˇ'        0xBFBFBFFF   0xABFAF2FF   '----'        OOB offset
81   0x404040FF   '@@@ˇ'        0x414141FF   0x404040FF   '----'        OOB offset
82   0xBFBFBFFF   'øøøˇ'        0x000000FF   0x414141FF   'ˇAAA'        OOB size
83   0x31535DFF   '1S]ˇ'        0xBFBFBFFF   0x3B5235FF   '----'        OOB offset
84   0xBFBFBFFF   'øøøˇ'        0x313131FF   0xBEBEBEFF   '----'        OOB offset
85   0x2038E2FF   ' 8‚ˇ'        0x000000FF   0x404040FF   'ˇAAA'        OOB size
86   0x414141FF   'AAAˇ'        0x6F897EFF   0x505050FF   '----'        OOB offset
87   0x404040FF   '@@@ˇ'        0x000000FF   0xBEBEBEFF   'ˇAAA'        OOB size
88   0x414141FF   'AAAˇ'        0x414141FF   0x000000FF   '----'        OOB offset
89   0x5A543AFF   'ZT:ˇ'        0x9F9851FF   0x2A333BFF   '----'        OOB offset
90   0xBEBEBEFF   'æææˇ'        0x000000FF   0x414141FF   'ˇAAA'        OOB size
91   0x4C3333FF   'L33ˇ'        0x414141FF   0xBFBFBFFF   '----'        OOB offset
92   0x414141FF   'AAAˇ'        0x404040FF   0x313131FF   '----'        OOB offset
93   0x414141FF   'AAAˇ'        0x404040FF   0x404040FF   '----'        OOB offset
94   0x356F61FF   '5oaˇ'        0x414141FF   0x4F4F4FFF   '----'        OOB offset
95   0x000000FF   '    '        0x000000FF   0x404040FF   'ˇAAA'        OOB size
96   0x4F166EFF   'Onˇ'        0x1B1E33FF   0x000000FF   '----'        OOB offset
97   0x404040FF   '@@@ˇ'        0x404040FF   0x394F50FF   '----'        OOB offset
98   0x000000FF   '    '        0x000000FF   0x404040FF   'ˇAAA'        OOB size
99   0x414141FF   'AAAˇ'        0x404040FF   0x404040FF   '----'        OOB offset
... (237658011 more tags not shown)

[WARN] SIZE INFLATION: Header claims 1296891946 bytes, file is 17142 bytes (75656x)
   Risk: OOM via tag-internal allocations based on inflated header size

[WARN] TAG OVERLAP: 2730 overlapping tag pair(s) detected
   Risk: Data corruption, possible exploit crafting

=== FULL FILE HEX DUMP (all 17142 bytes) ===
0x0000: 4D 4D 00 2A 00 00 40 08  41 41 41 FF 32 32 32 FF  |MM.*..@.AAA.222.|
0x0010: 39 4F 35 FF BE BE BE FF  39 4F 50 FF 37 72 9C FF  |9O5.....9OP.7r..|
0x0020: 68 20 24 FF 32 32 4E FF  41 41 41 FF 70 64 27 FF  |h $.22N.AAA.pd'.|
0x0030: 4F 2A 21 FF 50 50 36 FF  39 4F 35 FF BE BE BE FF  |O*!.PP6.9O5.....|
0x0040: 47 72 3F FF 41 41 41 FF  41 41 41 FF 94 2B 42 FF  |Gr?.AAA.AAA..+B.|
0x0050: 00 00 00 FF 59 7B 2C FF  40 53 14 FF 0E 2A 5F FF  |....Y{,.@S...*_.|
0x0060: 48 71 1E FF CC 9E F8 FF  29 61 31 FF 48 71 24 FF  |Hq......)a1.Hq$.|
0x0070: 40 53 1C FF 3A 62 19 FF  0E 2A 5F FF 3A 62 19 FF  |@S..:b...*_.:b..|
0x0080: 0E 2A 5F FF 3D 77 20 FF  48 71 1E FF 29 61 31 FF  |.*_.=w .Hq..)a1.|
0x0090: 48 71 1E FF 58 54 31 FF  3C 76 3A FF 3A 62 19 FF  |Hq..XT1.<v:.:b..|
0x00A0: 27 03 5F FF CC 9E F8 FF  0E 2A 5F FF 0E 2A 5F FF  |'._......*_..*_.|
0x00B0: 5B 65 1B FF 4E 6C 1D FF  00 00 00 FF 00 00 00 FF  |[e..Nl..........|
0x00C0: 29 61 31 FF 4C 16 9A FF  29 61 31 FF 27 03 5F FF  |)a1.L...)a1.'._.|
0x00D0: 29 61 31 FF 38 70 23 FF  CF 9F F6 FF 41 41 41 FF  |)a1.8p#.....AAA.|
0x00E0: 41 41 41 FF DB 9B 97 FF  00 00 00 FF BE BE BE FF  |AAA.............|
0x00F0: BE BE BE FF 41 41 41 FF  40 40 40 FF C8 F6 FD FF  |....AAA.@@@.....|
0x0100: 41 41 41 FF 40 40 40 FF  4E 80 34 FF 5A 1F 59 FF  |AAA.@@@.N.4.Z.Y.|
0x0110: E3 CE CF FF 2E 58 42 FF  41 41 41 FF 94 54 9C FF  |.....XB.AAA..T..|
0x0120: 4F 4F 4F FF 41 41 41 FF  51 23 33 FF 4F 4F 4F FF  |OOO.AAA.Q#3.OOO.|
0x0130: 41 41 41 FF BF BF BF FF  41 41 41 FF 86 F4 A9 FF  |AAA.....AAA.....|
0x0140: 40 40 40 FF 00 00 00 FF  BF BF BF FF 40 40 40 FF  |@@@.........@@@.|
0x0150: 05 03 1B FF DF 35 C2 FF  38 4E 4F FF 41 41 41 FF  |.....5..8NO.AAA.|
0x0160: 40 40 40 FF 32 32 32 FF  41 41 41 FF 41 41 41 FF  |@@@.222.AAA.AAA.|
0x0170: 8F EB A1 FF 3C 1B 2C FF  31 31 31 FF 00 00 00 FF  |....<.,.111.....|
0x0180: 50 6C 28 FF 38 4E 4F FF  40 40 40 FF 41 41 41 FF  |Pl(.8NO.@@@.AAA.|
0x0190: 00 00 00 FF C2 2D A7 FF  41 41 41 FF 50 50 36 FF  |.....-..AAA.PP6.|
0x01A0: 62 40 6C FF 58 1B 67 FF  BE BE BE FF 57 5A 4B FF  |b@l.X.g.....WZK.|
0x01B0: 40 40 40 FF 41 41 41 FF  40 40 40 FF 40 40 40 FF  |@@@.AAA.@@@.@@@.|
0x01C0: 40 40 40 FF 41 41 41 FF  38 4E 34 FF 41 41 41 FF  |@@@.AAA.8N4.AAA.|
0x01D0: 31 31 4D FF 5E 28 3E FF  4C 33 4E FF 00 00 00 FF  |11M.^(>.L3N.....|
0x01E0: 41 41 41 FF BE BE BE FF  50 50 50 FF 31 31 31 FF  |AAA.....PPP.111.|
0x01F0: 85 90 70 FF 46 4E 44 FF  5D 1E A8 FF 40 40 40 FF  |..p.FND.]...@@@.|
0x0200: 41 41 41 FF 62 95 B8 FF  46 5D 1A FF 22 26 39 FF  |AAA.b...F].."&9.|
0x0210: 1D 47 F1 FF BF BF BF FF  63 9B 2E FF B2 8D D8 FF  |.G......c.......|
0x0220: D9 3B C1 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |.;..AAA.AAA.AAA.|
0x0230: 00 00 00 FF 00 00 00 FF  40 40 40 FF 38 4E 34 FF  |........@@@.8N4.|
0x0240: 74 DB B5 FF 00 00 00 FF  BF BF BF FF BE BE BE FF  |t...............|
0x0250: 00 00 00 FF 41 41 41 FF  5E 9D E9 FF 41 41 41 FF  |....AAA.^...AAA.|
0x0260: 4F 4F 34 FF 41 41 41 FF  5A 6D 25 FF 69 36 60 FF  |OO4.AAA.Zm%.i6`.|
0x0270: 40 40 40 FF 00 00 00 FF  00 00 00 FF 4C 33 4E FF  |@@@.........L3N.|
0x0280: 40 40 40 FF 98 4C F1 FF  38 67 6F FF 00 00 00 FF  |@@@..L..8go.....|
0x0290: 40 40 40 FF 40 40 40 FF  41 41 41 FF 4F 4F 34 FF  |@@@.@@@.AAA.OO4.|
0x02A0: 41 41 41 FF 41 41 41 FF  27 14 55 FF 40 40 40 FF  |AAA.AAA.'.U.@@@.|
0x02B0: 00 00 00 FF 41 41 41 FF  40 40 40 FF 41 41 41 FF  |....AAA.@@@.AAA.|
0x02C0: 40 40 40 FF 41 41 41 FF  BF BF BF FF BF BF BF FF  |@@@.AAA.........|
0x02D0: BF BF BF FF 00 00 00 FF  41 41 41 FF 34 44 55 FF  |........AAA.4DU.|
0x02E0: 00 00 00 FF C8 B9 7A FF  40 40 40 FF 40 40 40 FF  |......z.@@@.@@@.|
0x02F0: BE BE BE FF 41 41 41 FF  EB BC DE FF 40 40 40 FF  |....AAA.....@@@.|
0x0300: 9D 50 5D FF E4 50 9F FF  77 72 49 FF 4F 4F 34 FF  |.P]..P..wrI.OO4.|
0x0310: 6C 6C 39 FF BE BE BE FF  63 51 3A FF 41 41 41 FF  |ll9.....cQ:.AAA.|
0x0320: 4F 4F 4F FF 41 41 41 FF  40 40 40 FF DC 6C 92 FF  |OOO.AAA.@@@..l..|
0x0330: 40 40 40 FF DC 82 BD FF  AF 83 43 FF 00 00 00 FF  |@@@.......C.....|
0x0340: A9 2A E9 FF BE BE BE FF  38 4E 34 FF 00 00 00 FF  |.*......8N4.....|
0x0350: BE BE BE FF 4C 33 33 FF  00 00 00 FF BE BE BE FF  |....L33.........|
0x0360: 1F 1D 3F FF 39 4F 35 FF  5F BE 89 FF BF BF BF FF  |..?.9O5._.......|
0x0370: 40 40 40 FF BE BE BE FF  40 40 40 FF 27 39 17 FF  |@@@.....@@@.'9..|
0x0380: 39 4F 50 FF 4B 32 32 FF  39 52 D9 FF 61 CF 81 FF  |9OP.K22.9R..a...|
0x0390: BF BF BF FF 77 7F 62 FF  40 40 40 FF 48 72 55 FF  |....w.b.@@@.HrU.|
0x03A0: 31 31 4D FF 40 40 40 FF  59 1B E7 FF 40 40 40 FF  |11M.@@@.Y...@@@.|
0x03B0: 40 40 40 FF A0 88 5C FF  41 41 41 FF DB 39 B1 FF  |@@@...\.AAA..9..|
0x03C0: BF BF BF FF BE BE BE FF  40 40 40 FF 55 1B 1C FF  |........@@@.U...|
0x03D0: 4F 22 16 FF 5C 37 3A FF  4B 32 4D FF 41 41 41 FF  |O"..\7:.K2M.AAA.|
0x03E0: 00 00 00 FF BE BE BE FF  40 40 40 FF 00 00 00 FF  |........@@@.....|
0x03F0: 00 00 00 FF 5D 5B 45 FF  65 DB 47 FF 00 00 00 FF  |....][E.e.G.....|
0x0400: 40 40 40 FF 96 DE EA FF  57 2B 53 FF 38 4E 4F FF  |@@@.....W+S.8NO.|
0x0410: BF BF BF FF 40 40 40 FF  BE BE BE FF 41 41 41 FF  |....@@@.....AAA.|
0x0420: BE BE BE FF C7 F1 C6 FF  69 E1 46 FF 41 41 41 FF  |........i.F.AAA.|
0x0430: 40 40 40 FF BE BE BE FF  4B 32 32 FF BF BF BF FF  |@@@.....K22.....|
0x0440: 41 41 41 FF 58 55 67 FF  BF BF BF FF AB FA F2 FF  |AAA.XUg.........|
0x0450: 40 40 40 FF 41 41 41 FF  40 40 40 FF BF BF BF FF  |@@@.AAA.@@@.....|
0x0460: 00 00 00 FF 41 41 41 FF  31 53 5D FF BF BF BF FF  |....AAA.1S].....|
0x0470: 3B 52 35 FF BF BF BF FF  31 31 31 FF BE BE BE FF  |;R5.....111.....|
0x0480: 20 38 E2 FF 00 00 00 FF  40 40 40 FF 41 41 41 FF  | 8......@@@.AAA.|
0x0490: 6F 89 7E FF 50 50 50 FF  40 40 40 FF 00 00 00 FF  |o.~.PPP.@@@.....|
0x04A0: BE BE BE FF 41 41 41 FF  41 41 41 FF 00 00 00 FF  |....AAA.AAA.....|
0x04B0: 5A 54 3A FF 9F 98 51 FF  2A 33 3B FF BE BE BE FF  |ZT:...Q.*3;.....|
0x04C0: 00 00 00 FF 41 41 41 FF  4C 33 33 FF 41 41 41 FF  |....AAA.L33.AAA.|
0x04D0: BF BF BF FF 41 41 41 FF  40 40 40 FF 31 31 31 FF  |....AAA.@@@.111.|
0x04E0: 41 41 41 FF 40 40 40 FF  40 40 40 FF 35 6F 61 FF  |AAA.@@@.@@@.5oa.|
0x04F0: 41 41 41 FF 4F 4F 4F FF  00 00 00 FF 00 00 00 FF  |AAA.OOO.........|
0x0500: 40 40 40 FF 4F 16 6E FF  1B 1E 33 FF 00 00 00 FF  |@@@.O.n...3.....|
0x0510: 40 40 40 FF 40 40 40 FF  39 4F 50 FF 00 00 00 FF  |@@@.@@@.9OP.....|
0x0520: 00 00 00 FF 40 40 40 FF  41 41 41 FF 40 40 40 FF  |....@@@.AAA.@@@.|
0x0530: 40 40 40 FF 00 00 00 FF  32 32 32 FF 41 41 41 FF  |@@@.....222.AAA.|
0x0540: 40 40 40 FF 40 40 40 FF  BE BE BE FF BE BE BE FF  |@@@.@@@.........|
0x0550: BE BE BE FF 5C 6F 42 FF  BF BF BF FF 00 00 00 FF  |....\oB.........|
0x0560: 40 40 40 FF BF BF BF FF  41 41 41 FF 00 00 00 FF  |@@@.....AAA.....|
0x0570: 50 50 36 FF 00 00 00 FF  00 00 00 FF 00 00 00 FF  |PP6.............|
0x0580: 91 8A 34 FF 00 00 00 FF  37 4A 5A FF 39 4F 50 FF  |..4.....7JZ.9OP.|
0x0590: 4C 33 4E FF 00 00 00 FF  00 00 00 FF BE BE BE FF  |L3N.............|
0x05A0: BE BE BE FF BE BE BE FF  00 00 00 FF 41 41 41 FF  |............AAA.|
0x05B0: 41 41 41 FF 00 00 00 FF  41 41 41 FF BE BE BE FF  |AAA.....AAA.....|
0x05C0: 41 41 41 FF 50 50 36 FF  29 2F 63 FF 41 41 41 FF  |AAA.PP6.)/c.AAA.|
0x05D0: 00 00 00 FF BE BE BE FF  41 41 41 FF 39 4F 35 FF  |........AAA.9O5.|
0x05E0: BE BE BE FF 00 00 00 FF  F3 F2 5E FF 00 00 00 FF  |..........^.....|
0x05F0: 41 41 41 FF 41 41 41 FF  50 50 36 FF 48 21 52 FF  |AAA.AAA.PP6.H!R.|
0x0600: 41 41 41 FF 41 41 41 FF  BF 5C 54 FF 41 41 41 FF  |AAA.AAA..\T.AAA.|
0x0610: 4F A6 37 FF 41 41 41 FF  BE BE BE FF 00 00 00 FF  |O.7.AAA.........|
0x0620: 41 41 41 FF 41 41 41 FF  00 00 00 FF 4C 33 4E FF  |AAA.AAA.....L3N.|
0x0630: BE BE BE FF 41 41 41 FF  67 5E 23 FF 50 50 36 FF  |....AAA.g^#.PP6.|
0x0640: 00 00 00 FF 41 41 41 FF  BE BE BE FF 1B 33 2E FF  |....AAA......3..|
0x0650: 2B 17 59 FF 2C 5D 6E FF  39 4F 35 FF BE BE BE FF  |+.Y.,]n.9O5.....|
0x0660: 39 4F 35 FF 4C 33 4E FF  41 41 41 FF 41 47 40 FF  |9O5.L3N.AAA.AG@.|
0x0670: 6F E7 6B FF 4F A8 36 FF  15 15 A4 FF D9 5E E3 FF  |o.k.O.6......^..|
0x0680: 4F A8 36 FF 75 FB 4C FF  46 9A 2C FF 4F A8 36 FF  |O.6.u.L.F.,.O.6.|
0x0690: D9 5E E3 FF 15 15 A4 FF  9D 27 20 FF 75 FB 4C FF  |.^.......' .u.L.|
0x06A0: 4F A8 36 FF 15 15 A4 FF  83 D0 C2 FF 75 FB 4C FF  |O.6.........u.L.|
0x06B0: BB D1 E4 FF 4F A8 36 FF  CD BD 69 FF 32 69 C3 FF  |....O.6...i.2i..|
0x06C0: D9 5E E3 FF 15 15 A4 FF  5E 97 5E FF 75 FB 4C FF  |.^......^.^.u.L.|
0x06D0: 15 15 A4 FF 40 79 44 FF  D9 5E E3 FF 75 FB 4C FF  |....@yD..^..u.L.|
0x06E0: 75 FB 4C FF 62 D4 4A FF  46 76 AD FF 4F A8 36 FF  |u.L.b.J.Fv..O.6.|
0x06F0: 4F A8 36 FF 75 FB 4C FF  4F A8 36 FF E3 35 DD FF  |O.6.u.L.O.6..5..|
0x0700: 75 FB 4C FF D9 5E E3 FF  15 15 A4 FF 9D 27 20 FF  |u.L..^.......' .|
0x0710: D9 5E E3 FF 94 44 76 FF  46 9A 2C FF D9 5E E3 FF  |.^...Dv.F.,..^..|
0x0720: 5A B7 40 FF 15 15 A4 FF  75 FB 4C FF 40 91 32 FF  |Z.@.....u.L.@.2.|
0x0730: 4D 9A 39 FF 54 B7 40 FF  15 15 A4 FF D9 5E E3 FF  |M.9.T.@......^..|
0x0740: 54 B7 36 FF D9 5E E3 FF  75 FB 4C FF 75 FB 4C FF  |T.6..^..u.L.u.L.|
0x0750: D9 5E E3 FF 56 BC 3B FF  DF 6C 48 FF 75 FB 4C FF  |.^..V.;..lH.u.L.|
0x0760: 4F A8 36 FF 52 B2 33 FF  15 15 A4 FF 4F A8 36 FF  |O.6.R.3.....O.6.|
0x0770: 48 A0 4E FF 4F A8 36 FF  75 FB 4C FF 75 FB 4C FF  |H.N.O.6.u.L.u.L.|
0x0780: D9 5E E3 FF 75 FB 4C FF  84 CB 96 FF 61 D4 3F FF  |.^..u.L.....a.?.|
0x0790: 4E 82 24 FF 15 15 A4 FF  82 6F C5 FF 68 43 8D FF  |N.$......o..hC..|
0x07A0: 4D A9 49 FF 4D 9A 2D FF  15 15 A4 FF 54 B7 36 FF  |M.I.M.-.....T.6.|
0x07B0: 67 D8 40 FF 4F A8 36 FF  B3 88 5D FF 4F A8 36 FF  |g.@.O.6...].O.6.|
0x07C0: 15 15 A4 FF 65 D9 40 FF  3E 8D 3A FF 4F A8 36 FF  |....e.@.>.:.O.6.|
0x07D0: 75 FB 4C FF 75 FB 4C FF  41 41 41 FF 41 41 41 FF  |u.L.u.L.AAA.AAA.|
0x07E0: BE BE BE FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |....AAA.AAA.AAA.|
0x07F0: 45 26 67 FF BE BE BE FF  E6 F9 88 FF 41 41 41 FF  |E&g.........AAA.|
0x0800: BE BE BE FF BE BE BE FF  4C 44 24 FF 61 B7 A2 FF  |........LD$.a...|
0x0810: 41 41 41 FF 41 41 41 FF  00 00 00 FF A7 F2 9D FF  |AAA.AAA.........|
0x0820: 50 50 50 FF 41 41 41 FF  41 41 41 FF 12 19 59 FF  |PPP.AAA.AAA...Y.|
0x0830: 50 50 50 FF 44 99 8E FF  00 00 00 FF 00 00 00 FF  |PPP.D...........|
0x0840: BE BE BE FF 41 41 41 FF  41 41 41 FF 4C 33 33 FF  |....AAA.AAA.L33.|
0x0850: 00 00 00 FF 43 50 2C FF  6D 7F F6 FF 39 4F 50 FF  |....CP,.m...9OP.|
0x0860: 41 41 41 FF 41 41 41 FF  32 32 4E FF BE BE BE FF  |AAA.AAA.22N.....|
0x0870: 41 41 41 FF 4C 33 4E FF  41 41 41 FF 00 00 00 FF  |AAA.L3N.AAA.....|
0x0880: 57 64 66 FF BE BE BE FF  41 41 41 FF 32 32 32 FF  |Wdf.....AAA.222.|
0x0890: 41 41 41 FF 00 00 00 FF  00 00 00 FF B6 DD 78 FF  |AAA...........x.|
0x08A0: 65 D5 E7 FF BE BE BE FF  41 41 41 FF 41 41 41 FF  |e.......AAA.AAA.|
0x08B0: DD CF 4F FF BE BE BE FF  4C 33 33 FF 92 AE 3A FF  |..O.....L33...:.|
0x08C0: 41 41 41 FF 41 41 41 FF  BE BE BE FF 4C 33 4E FF  |AAA.AAA.....L3N.|
0x08D0: 74 38 C9 FF ED BE 7B FF  3F 13 5A FF BE BE BE FF  |t8....{.?.Z.....|
0x08E0: 41 41 41 FF 39 65 80 FF  E9 85 EF FF 5F 98 68 FF  |AAA.9e......_.h.|
0x08F0: 41 41 41 FF 41 41 41 FF  4D 24 81 FF BE BE BE FF  |AAA.AAA.M$......|
0x0900: 41 41 41 FF 50 50 50 FF  4C 33 33 FF 41 41 41 FF  |AAA.PPP.L33.AAA.|
0x0910: 41 41 41 FF BE BE BE FF  4A 1C 5D FF AC D4 7D FF  |AAA.....J.]...}.|
0x0920: 64 13 36 FF A9 A9 8D FF  00 00 00 FF BE BE BE FF  |d.6.............|
0x0930: 7C 46 21 FF 41 41 41 FF  50 50 36 FF 41 41 41 FF  ||F!.AAA.PP6.AAA.|
0x0940: 85 4D B8 FF 41 41 41 FF  D9 DB AB FF 30 19 41 FF  |.M..AAA.....0.A.|
0x0950: BE BE BE FF BE BE BE FF  29 44 52 FF 39 4F 35 FF  |........)DR.9O5.|
0x0960: BE BE BE FF 50 50 36 FF  BE BE BE FF D8 EB 56 FF  |....PP6.......V.|
0x0970: 00 00 00 FF BB 77 2E FF  F2 DC 71 FF 41 41 41 FF  |.....w....q.AAA.|
0x0980: BE BE BE FF 50 50 36 FF  00 00 00 FF 41 41 41 FF  |....PP6.....AAA.|
0x0990: BE BE BE FF BE BE BE FF  41 41 41 FF 41 41 41 FF  |........AAA.AAA.|
0x09A0: 41 41 41 FF 41 41 41 FF  00 00 00 FF EF C4 73 FF  |AAA.AAA.......s.|
0x09B0: 41 41 41 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |AAA.AAA.AAA.AAA.|
0x09C0: BE BE BE FF 00 00 00 FF  97 7C 6B FF 41 41 41 FF  |.........|k.AAA.|
0x09D0: BE BE BE FF 41 41 41 FF  50 50 50 FF 41 41 41 FF  |....AAA.PPP.AAA.|
0x09E0: 41 41 41 FF 41 41 41 FF  39 4F 35 FF 00 00 00 FF  |AAA.AAA.9O5.....|
0x09F0: 00 00 00 FF 00 00 00 FF  41 41 41 FF 00 00 00 FF  |........AAA.....|
0x0A00: 41 41 41 FF 32 32 32 FF  00 00 00 FF 41 41 41 FF  |AAA.222.....AAA.|
0x0A10: 41 41 41 FF 41 41 41 FF  47 3B 49 FF 41 41 41 FF  |AAA.AAA.G;I.AAA.|
0x0A20: 42 18 12 FF 8F 92 68 FF  41 41 41 FF E3 EA C2 FF  |B.....h.AAA.....|
0x0A30: 36 21 17 FF 4C 33 4E FF  41 41 41 FF 5D B9 59 FF  |6!..L3N.AAA.].Y.|
0x0A40: 69 42 26 FF BE BE BE FF  BE BE BE FF 41 41 41 FF  |iB&.........AAA.|
0x0A50: 36 1B 4B FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |6.K.AAA.AAA.AAA.|
0x0A60: 41 41 41 FF 99 F1 F4 FF  41 41 41 FF 00 00 00 FF  |AAA.....AAA.....|
0x0A70: 00 00 00 FF 41 41 41 FF  00 00 00 FF BE BE BE FF  |....AAA.........|
0x0A80: BE BE BE FF 41 41 41 FF  41 41 41 FF 50 50 36 FF  |....AAA.AAA.PP6.|
0x0A90: 4C 33 33 FF CB F4 B0 FF  2B 4F 3E FF 4D 4F 38 FF  |L33.....+O>.MO8.|
0x0AA0: 32 32 4E FF 32 32 4E FF  BE BE BE FF 41 41 41 FF  |22N.22N.....AAA.|
0x0AB0: 41 41 41 FF E4 EE 5B FF  00 00 00 FF 00 00 00 FF  |AAA...[.........|
0x0AC0: 68 E1 58 FF 00 00 00 FF  62 56 29 FF 40 63 57 FF  |h.X.....bV).@cW.|
0x0AD0: 39 4F 35 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |9O5.AAA.AAA.AAA.|
0x0AE0: 41 41 41 FF A9 79 BE FF  BE BE BE FF 50 50 36 FF  |AAA..y......PP6.|
0x0AF0: 00 00 00 FF 41 41 41 FF  41 41 41 FF B3 DA CE FF  |....AAA.AAA.....|
0x0B00: 41 41 41 FF 48 3C 38 FF  00 00 00 FF BE BE BE FF  |AAA.H<8.........|
0x0B10: 48 28 41 FF BE BE BE FF  D4 73 91 FF 46 14 69 FF  |H(A......s..F.i.|
0x0B20: 41 41 41 FF 41 41 41 FF  00 00 00 FF 52 6F 35 FF  |AAA.AAA.....Ro5.|
0x0B30: 41 41 41 FF 4C 33 33 FF  41 41 41 FF 4C 33 33 FF  |AAA.L33.AAA.L33.|
0x0B40: 00 00 00 FF 41 41 41 FF  4D 40 29 FF 41 41 41 FF  |....AAA.M@).AAA.|
0x0B50: 41 41 41 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |AAA.AAA.AAA.AAA.|
0x0B60: BE BE BE FF 57 35 6C FF  41 41 41 FF 50 50 36 FF  |....W5l.AAA.PP6.|
0x0B70: 41 41 41 FF 41 41 41 FF  23 2B 4F FF 41 41 41 FF  |AAA.AAA.#+O.AAA.|
0x0B80: 32 32 32 FF 32 32 4E FF  41 41 41 FF 64 5D 3C FF  |222.22N.AAA.d]<.|
0x0B90: 50 50 36 FF BE BE BE FF  3A 1E 73 FF 39 4F 35 FF  |PP6.....:.s.9O5.|
0x0BA0: 41 41 41 FF 00 00 00 FF  4C 33 33 FF 41 41 41 FF  |AAA.....L33.AAA.|
0x0BB0: 39 4F 35 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |9O5.AAA.AAA.AAA.|
0x0BC0: 39 65 50 FF 41 41 41 FF  00 00 00 FF BE BE BE FF  |9eP.AAA.........|
0x0BD0: 39 4F 50 FF 41 41 41 FF  40 7B 5B FF 67 9B 4E FF  |9OP.AAA.@{[.g.N.|
0x0BE0: 41 41 41 FF 41 41 41 FF  43 49 38 FF 5D 65 2E FF  |AAA.AAA.CI8.]e..|
0x0BF0: 41 41 41 FF 39 4F 35 FF  39 18 1B FF 39 51 5E FF  |AAA.9O5.9...9Q^.|
0x0C00: 43 29 ED FF 41 41 41 FF  41 41 41 FF BE BE BE FF  |C)..AAA.AAA.....|
0x0C10: 00 00 00 FF 5F AA 99 FF  39 4F 50 FF E9 CE 7E FF  |...._...9OP...~.|
0x0C20: 41 41 41 FF 40 6E 23 FF  BE BE BE FF 41 41 41 FF  |AAA.@n#.....AAA.|
0x0C30: 64 A9 ED FF 3F 61 23 FF  41 41 41 FF 00 00 00 FF  |d...?a#.AAA.....|
0x0C40: C3 E8 95 FF 50 50 36 FF  41 41 41 FF 00 00 00 FF  |....PP6.AAA.....|
0x0C50: 2B 3A 20 FF 32 32 4E FF  9D A7 68 FF 59 AC 54 FF  |+: .22N...h.Y.T.|
0x0C60: 41 41 41 FF 30 68 52 FF  00 00 00 FF 4C 33 33 FF  |AAA.0hR.....L33.|
0x0C70: 71 BB 4B FF 41 41 41 FF  BE BE BE FF 41 41 41 FF  |q.K.AAA.....AAA.|
0x0C80: 33 3F 40 FF 50 50 36 FF  00 00 00 FF 41 41 41 FF  |3?@.PP6.....AAA.|
0x0C90: 50 50 50 FF 42 41 42 FF  75 FB FD FF DE 7A 9E FF  |PPP.BAB.u....z..|
0x0CA0: 9E 55 7F FF A8 80 5C FF  A3 83 57 FF 63 71 97 FF  |.U....\...W.cq..|
0x0CB0: 26 38 27 FF 5B 80 A5 FF  75 FB FD FF A8 80 5C FF  |&8'.[...u.....\.|
0x0CC0: 9E 55 7F FF 75 FB FD FF  6D 7A A9 FF 5B 80 A5 FF  |.U..u...mz..[...|
0x0CD0: 6A 8F 99 FF A8 80 5C FF  5D 78 A5 FF 5B 80 A5 FF  |j.....\.]x..[...|
0x0CE0: 63 71 B3 FF A3 83 57 FF  9E 55 7F FF A8 80 5C FF  |cq....W..U....\.|
0x0CF0: D4 52 79 FF 6C 9F AF FF  67 A7 84 FF A8 80 5C FF  |.Ry.l...g.....\.|
0x0D00: 6A B2 66 FF 4E A9 61 FF  6A 8F B4 FF 9E 55 7F FF  |j.f.N.a.j....U..|
0x0D10: 7A 52 A4 FF 5B 80 A5 FF  75 68 B3 FF A8 80 5C FF  |zR..[...uh....\.|
0x0D20: 75 FB FD FF 75 FB FD FF  C3 B9 3C FF 75 FB FD FF  |u...u.....<.u...|
0x0D30: A3 83 57 FF A8 80 5C FF  4D 71 97 FF 7A 52 A4 FF  |..W...\.Mq..zR..|
0x0D40: 94 EE FC FF 9E 55 7F FF  9E 55 7F FF 3B 2E 6F FF  |.....U...U..;.o.|
0x0D50: 7A 52 A4 FF 9B A6 C9 FF  67 A7 84 FF 4D 71 B3 FF  |zR......g...Mq..|
0x0D60: A3 83 57 FF 5B 80 A5 FF  4D 71 B3 FF 75 FB FD FF  |..W.[...Mq..u...|
0x0D70: 9E 55 7F FF 4D 71 B3 FF  75 FB FD FF 67 A7 84 FF  |.U..Mq..u...g...|
0x0D80: BB 29 40 FF 5B 80 A5 FF  56 8E B4 FF 49 14 38 FF  |.)@.[...V...I.8.|
0x0D90: 6C 74 B1 FF 5B 80 A5 FF  75 FB FD FF 7A 52 A4 FF  |lt..[...u...zR..|
0x0DA0: 4D 71 97 FF 5B 80 A5 FF  56 8E B4 FF A8 80 5C FF  |Mq..[...V.....\.|
0x0DB0: 9E 55 7F FF 9E 55 7F FF  A8 80 5C FF 75 FB FD FF  |.U...U....\.u...|
0x0DC0: 75 FB FD FF 90 1F 12 FF  A3 83 57 FF 6C 9E B5 FF  |u.........W.l...|
0x0DD0: 73 7E 9E FF A8 80 5C FF  56 8E 98 FF A3 83 57 FF  |s~....\.V.....W.|
0x0DE0: 67 A7 84 FF 71 AB B2 FF  4D 71 B3 FF 5B 80 A5 FF  |g...q...Mq..[...|
0x0DF0: 70 85 78 FF 7D AB AE FF  A3 83 57 FF A8 80 5C FF  |p.x.}.....W...\.|
0x0E00: A3 83 57 FF A8 80 5C FF  6A 8F B4 FF 19 33 31 FF  |..W...\.j....31.|
0x0E10: A3 83 57 FF 75 FB FD FF  56 8E 98 FF 9E 55 7F FF  |..W.u...V....U..|
0x0E20: A8 80 5C FF 4D 71 97 FF  75 FB FD FF 5B 80 A5 FF  |..\.Mq..u...[...|
0x0E30: A3 83 57 FF 6A 8F 99 FF  A3 83 57 FF 63 71 B3 FF  |..W.j.....W.cq..|
0x0E40: 6C 8D B3 FF AE A3 DE FF  A8 80 5C FF 9E 55 7F FF  |l.........\..U..|
0x0E50: A8 80 5C FF 5F 88 84 FF  56 8E 98 FF A3 83 57 FF  |..\._...V.....W.|
0x0E60: 9E 55 7F FF 61 80 88 FF  A8 80 5C FF 20 33 97 FF  |.U..a.....\. 3..|
0x0E70: 71 F3 6D FF 9D 6A 72 FF  E9 43 29 FF A3 83 57 FF  |q.m..jr..C)...W.|
0x0E80: 9E 55 7F FF 75 FB FD FF  75 FB FD FF 56 8E 98 FF  |.U..u...u...V...|
0x0E90: 4D 71 B3 FF A3 83 57 FF  4D 71 97 FF 3F 72 B2 FF  |Mq....W.Mq..?r..|
0x0EA0: 56 4C 75 FF A8 80 5C FF  A3 83 57 FF 56 8E 98 FF  |VLu...\...W.V...|
0x0EB0: A8 80 5C FF 27 3E 3D FF  6A 91 BE FF 75 FB FD FF  |..\.'>=.j...u...|
0x0EC0: AF 36 2E FF 7A 52 A4 FF  6A 8F 99 FF 7A 52 A4 FF  |.6..zR..j...zR..|
0x0ED0: 7A 52 A4 FF 5B 80 A5 FF  9E 55 7F FF 9E 55 7F FF  |zR..[....U...U..|
0x0EE0: 75 FB FD FF 4D 71 97 FF  6A 8F 99 FF 75 FB FD FF  |u...Mq..j...u...|
0x0EF0: 75 FB FD FF 67 A7 84 FF  75 FB FD FF 7A 52 A4 FF  |u...g...u...zR..|
0x0F00: A3 83 57 FF 74 86 8A FF  75 FB FD FF A8 80 5C FF  |..W.t...u.....\.|
0x0F10: 49 A0 54 FF 5B 80 A5 FF  63 71 97 FF 6A 8F 99 FF  |I.T.[...cq..j...|
0x0F20: 67 A7 84 FF 75 FB FD FF  75 FB FD FF 69 63 20 FF  |g...u...u...ic .|
0x0F30: 68 90 CD FF 9E 55 7F FF  9E 55 7F FF 9E 55 7F FF  |h....U...U...U..|
0x0F40: 74 9E A3 FF 54 7E B2 FF  75 FB FD FF CE A7 52 FF  |t...T~..u.....R.|
0x0F50: A8 80 5C FF AB 27 1E FF  50 7E A7 FF 3B 65 5A FF  |..\..'..P~..;eZ.|
0x0F60: 53 24 78 FF 5B 80 A5 FF  9E 55 7F FF 75 FB FD FF  |S$x.[....U..u...|
0x0F70: A3 83 57 FF 5B 80 A5 FF  A3 83 57 FF 3A 69 C2 FF  |..W.[.....W.:i..|
0x0F80: A3 83 57 FF 3E 1F DA FF  A8 80 5C FF 7A 52 A4 FF  |..W.>.....\.zR..|
0x0F90: 9E 55 7F FF 9E 55 7F FF  75 FB FD FF 9E 55 7F FF  |.U...U..u....U..|
0x0FA0: 67 A7 84 FF 75 FB FD FF  A8 80 5C FF 39 7F 5A FF  |g...u.....\.9.Z.|
0x0FB0: 9E 55 7F FF 68 9A BB FF  A8 80 5C FF 9E 55 7F FF  |.U..h.....\..U..|
0x0FC0: A8 80 5C FF 9E 55 7F FF  75 FB FD FF 7A 52 A4 FF  |..\..U..u...zR..|
0x0FD0: 9E 55 7F FF 4D 71 97 FF  67 A7 84 FF 9E 55 7F FF  |.U..Mq..g....U..|
0x0FE0: E0 88 32 FF 5B 80 A5 FF  75 FB FD FF 5B 80 A5 FF  |..2.[...u...[...|
0x0FF0: A8 80 5C FF 56 57 C5 FF  B3 A2 91 FF 41 41 41 FF  |..\.VW......AAA.|
0x1000: 00 00 00 FF 41 41 41 FF  41 41 41 FF D8 73 88 FF  |....AAA.AAA..s..|
0x1010: 41 41 41 FF 00 00 00 FF  4C 33 33 FF 41 41 41 FF  |AAA.....L33.AAA.|
0x1020: 2B 2C 64 FF E1 81 97 FF  41 41 41 FF 00 00 00 FF  |+,d.....AAA.....|
0x1030: 41 41 41 FF 41 41 41 FF  BE BE BE FF 39 4F 50 FF  |AAA.AAA.....9OP.|
0x1040: 41 41 41 FF 00 00 00 FF  4C 33 33 FF 32 32 4E FF  |AAA.....L33.22N.|
0x1050: 66 64 3B FF BE BE BE FF  41 41 41 FF 4C 33 4E FF  |fd;.....AAA.L3N.|
0x1060: BE BE BE FF 00 00 00 FF  41 41 41 FF BE BE BE FF  |........AAA.....|
0x1070: BE BE BE FF 41 41 41 FF  4C 33 4E FF 21 3D 4D FF  |....AAA.L3N.!=M.|
0x1080: BE BE BE FF BE BE BE FF  00 00 00 FF 41 41 41 FF  |............AAA.|
0x1090: 00 00 00 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |....AAA.AAA.AAA.|
0x10A0: 00 00 00 FF 19 32 25 FF  52 4B 44 FF 41 41 41 FF  |.....2%.RKD.AAA.|
0x10B0: 37 67 5F FF 48 58 1E FF  41 41 41 FF 41 41 41 FF  |7g_.HX..AAA.AAA.|
0x10C0: 32 32 4E FF BE BE BE FF  19 1F 37 FF 41 41 41 FF  |22N.......7.AAA.|
0x10D0: 41 41 41 FF 26 35 41 FF  41 41 41 FF 41 41 41 FF  |AAA.&5A.AAA.AAA.|
0x10E0: BE BE BE FF 52 48 1B FF  51 37 6C FF 41 41 41 FF  |....RH..Q7l.AAA.|
0x10F0: 9B E2 48 FF BE BE BE FF  41 41 41 FF 39 4F 35 FF  |..H.....AAA.9O5.|
0x1100: 39 4F 50 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |9OP.AAA.AAA.AAA.|
0x1110: 45 2C 4B FF BE BE BE FF  00 00 00 FF 41 41 41 FF  |E,K.........AAA.|
0x1120: 50 50 50 FF 93 F0 4C FF  4C 64 57 FF 5F 9B 36 FF  |PPP...L.LdW._.6.|
0x1130: 41 41 41 FF 50 50 36 FF  41 41 41 FF 32 32 4E FF  |AAA.PP6.AAA.22N.|
0x1140: 41 41 41 FF 41 41 41 FF  00 00 00 FF D8 DE 64 FF  |AAA.AAA.......d.|
0x1150: 41 41 41 FF 00 00 00 FF  41 41 41 FF 00 00 00 FF  |AAA.....AAA.....|
0x1160: 32 32 4E FF 41 41 41 FF  62 38 65 FF 00 00 00 FF  |22N.AAA.b8e.....|
0x1170: 32 32 4E FF 4D 24 5B FF  41 41 41 FF 39 4F 35 FF  |22N.M$[.AAA.9O5.|
0x1180: 51 6B 25 FF 41 41 41 FF  1A 30 16 FF 41 41 41 FF  |Qk%.AAA..0..AAA.|
0x1190: 50 19 13 FF 50 50 36 FF  BE BE BE FF 4D 15 3B FF  |P...PP6.....M.;.|
0x11A0: 4F 25 36 FF 32 32 32 FF  B4 A4 37 FF 00 00 00 FF  |O%6.222...7.....|
0x11B0: 2F 2B 5E FF BE BE BE FF  56 A2 5E FF 38 55 21 FF  |/+^.....V.^.8U!.|
0x11C0: 00 00 00 FF A2 89 C5 FF  41 41 41 FF 00 00 00 FF  |........AAA.....|
0x11D0: 41 41 41 FF 41 41 41 FF  41 41 41 FF 53 17 84 FF  |AAA.AAA.AAA.S...|
0x11E0: 4C 33 33 FF 32 32 32 FF  59 56 46 FF BE BE BE FF  |L33.222.YVF.....|
0x11F0: 00 00 00 FF 32 32 32 FF  50 50 50 FF 41 41 41 FF  |....222.PPP.AAA.|
0x1200: 41 41 41 FF BE BE BE FF  00 00 00 FF 68 65 69 FF  |AAA.........hei.|
0x1210: 50 50 50 FF 38 54 2D FF  E6 33 47 FF 41 41 41 FF  |PPP.8T-..3G.AAA.|
0x1220: CD AF 90 FF 41 41 41 FF  41 41 41 FF BE BE BE FF  |....AAA.AAA.....|
0x1230: 4C 33 4E FF 39 4F 35 FF  41 41 41 FF 41 41 41 FF  |L3N.9O5.AAA.AAA.|
0x1240: DF D8 F3 FF 32 32 32 FF  BE BE BE FF 41 41 41 FF  |....222.....AAA.|
0x1250: BE BE BE FF 41 41 41 FF  89 51 6B FF 6A 9C 2D FF  |....AAA..Qk.j.-.|
0x1260: 6F 29 5C FF 6A 9C 2D FF  B5 6B F7 FF EA 33 F7 FF  |o)\.j.-..k...3..|
0x1270: 6A 9C 2D FF 89 73 F7 FF  6A 9C 2D FF A9 58 E8 FF  |j.-..s..j.-..X..|
0x1280: F2 AA 6D FF EA 33 F7 FF  6C D9 4F FF 6A 9C 2D FF  |..m..3..l.O.j.-.|
0x1290: C6 4B F6 FF 9D 64 F6 FF  8E 56 F6 FF F2 AA 6D FF  |.K...d...V....m.|
0x12A0: 70 3D F5 FF 9D 64 F6 FF  C6 4C F6 FF EA 33 F7 FF  |p=...d...L...3..|
0x12B0: A9 58 F6 FF 6A 9C 2D FF  ED 6C A4 FF A4 7C F7 FF  |.X..j.-..l...|..|
0x12C0: EA 33 F7 FF AB 73 F7 FF  B5 7D F0 FF 8E 56 E8 FF  |.3...s...}...V..|
0x12D0: EA 33 F7 FF F2 AA 6D FF  ED 6C A4 FF EA 33 F7 FF  |.3....m..l...3..|
0x12E0: 6F 6A C9 FF F2 AA 6D FF  ED 6C A4 FF EA 33 F7 FF  |oj....m..l...3..|
0x12F0: 91 72 E8 FF A0 4B 7D FF  ED 6C A4 FF 9D 64 F6 FF  |.r...K}..l...d..|
0x1300: 8C 36 17 FF ED 6C A4 FF  91 E0 57 FF 91 72 F7 FF  |.6...l....W..r..|
0x1310: F2 AA 6D FF 9D 64 F6 FF  6A 9C 2D FF BA FD 78 FF  |..m..d..j.-...x.|
0x1320: 84 3E F5 FF 9D 64 F6 FF  A9 58 F6 FF 8E 56 F6 FF  |.>...d...X...V..|
0x1330: 91 72 F7 FF 91 72 F7 FF  AA 47 F6 FF 91 72 E8 FF  |.r...r...G...r..|
0x1340: 6A 9C 2D FF 6A 9C 2D FF  F2 AA 6D FF 6A 9C 2D FF  |j.-.j.-...m.j.-.|
0x1350: F2 AA 6D FF 6A 9C 2D FF  ED 6C A4 FF 91 72 F7 FF  |..m.j.-..l...r..|
0x1360: 71 A4 F8 FF F2 AA 6D FF  8E 56 E8 FF AA 65 F7 FF  |q.....m..V...e..|
0x1370: F2 AA 6D FF 6A 9C 2D FF  CE 32 C3 FF 6A 9C 2D FF  |..m.j.-..2..j.-.|
0x1380: 8E 56 E8 FF 71 A4 F8 FF  6A 9C 2D FF EA 33 F7 FF  |.V..q...j.-..3..|
0x1390: C3 84 D5 FF 9D 64 F6 FF  ED 6C A4 FF AB 73 F7 FF  |.....d...l...s..|
0x13A0: F2 AA 6D FF EA 33 F7 FF  F2 AA 6D FF 71 A4 F8 FF  |..m..3....m.q...|
0x13B0: 6A 9C 2D FF BA FD 78 FF  F2 AA 6D FF 8E 6E F7 FF  |j.-...x...m..n..|
0x13C0: F2 AA 6D FF C2 6C F7 FF  ED 6C A4 FF B5 3D D3 FF  |..m..l...l...=..|
0x13D0: 91 72 E8 FF 86 73 F7 FF  ED 6C A4 FF F2 AA 6D FF  |.r...s...l....m.|
0x13E0: 71 A4 F8 FF DA 68 2D FF  74 4E D1 FF F2 AA 6D FF  |q....h-.tN....m.|
0x13F0: BA 8B F8 FF BA FD 78 FF  ED 6C A4 FF AB 73 E9 FF  |......x..l...s..|
0x1400: AC 42 F6 FF 9D 64 F6 FF  6E 3C C8 FF 8C 92 F8 FF  |.B...d..n<......|
0x1410: C6 8D F7 FF 9D 64 F6 FF  EA 33 F7 FF 9D 64 F6 FF  |.....d...3...d..|
0x1420: ED 6C A4 FF F2 AA 6D FF  EA 33 F7 FF EA 33 F7 FF  |.l....m..3...3..|
0x1430: 77 9A 4F FF 9D 64 F6 FF  EA 33 F7 FF 96 8A F5 FF  |w.O..d...3......|
0x1440: ED 6C A4 FF 71 A4 F8 FF  6A 9C 2D FF 3D 2E D7 FF  |.l..q...j.-.=...|
0x1450: 6A 9C 2D FF 9D 64 F6 FF  ED 6C A4 FF F2 AA 6D FF  |j.-..d...l....m.|
0x1460: F2 AA 6D FF 9D 64 F6 FF  EA 33 F7 FF A9 58 F6 FF  |..m..d...3...X..|
0x1470: A0 D1 5E FF 83 81 DB FF  AB 73 E9 FF 9D 64 F6 FF  |..^......s...d..|
0x1480: AB 63 E2 FF 91 72 E8 FF  ED 6C A4 FF 9D 64 F6 FF  |.c...r...l...d..|
0x1490: BC 7F B3 FF F2 AA 6D FF  A4 46 F6 FF 6A 9C 2D FF  |......m..F..j.-.|
0x14A0: 6A 9C 2D FF A7 41 5A FF  ED 6C A4 FF 71 A4 F8 FF  |j.-..AZ..l..q...|
0x14B0: AB 73 F7 FF EA 33 F7 FF  62 98 78 FF ED 6C A4 FF  |.s...3..b.x..l..|
0x14C0: 6A 9C 2D FF 6A 9C 2D FF  EA 33 F7 FF A9 58 F6 FF  |j.-.j.-..3...X..|
0x14D0: ED 6C A4 FF EA 33 F7 FF  ED 6C A4 FF 6A 9C 2D FF  |.l...3...l..j.-.|
0x14E0: 6A 9C 2D FF AA 7C CF FF  F2 AA 6D FF ED 6C A4 FF  |j.-..|....m..l..|
0x14F0: 65 77 9E FF CC 86 E0 FF  27 3C D7 FF F2 AA 6D FF  |ew......'<....m.|
0x1500: ED 6C A4 FF 71 A4 F8 FF  D0 6D 3C FF BA FD 78 FF  |.l..q....m<...x.|
0x1510: 8E 56 E8 FF 6A 9C 2D FF  91 72 F7 FF EA 33 F7 FF  |.V..j.-..r...3..|
0x1520: AB 6D 6B FF F2 AA 6D FF  EA 33 F7 FF A9 58 F6 FF  |.mk...m..3...X..|
0x1530: AB 73 F7 FF 91 72 F7 FF  8E 56 E8 FF 89 52 5D FF  |.s...r...V...R].|
0x1540: 73 E3 EB FF 9D 64 F6 FF  EA 33 F7 FF F2 AA 6D FF  |s....d...3....m.|
0x1550: 6A 9C 2D FF AB 73 F7 FF  6A 9C 2D FF BA FD 78 FF  |j.-..s..j.-...x.|
0x1560: ED 6C A4 FF ED 6C A4 FF  6A 9C 2D FF EA 33 F7 FF  |.l...l..j.-..3..|
0x1570: 91 72 E8 FF 7F 41 F6 FF  87 80 F7 FF 67 CE C4 FF  |.r...A......g...|
0x1580: 79 6B E3 FF 6A 9C 2D FF  F2 AA 6D FF 8E 56 F6 FF  |yk..j.-...m..V..|
0x1590: 8E 56 F6 FF ED 6C A4 FF  ED 6C A4 FF AB 73 E9 FF  |.V...l...l...s..|
0x15A0: 6A 9C 2D FF ED 6C A4 FF  9C 49 F6 FF 9D 64 F6 FF  |j.-..l...I...d..|
0x15B0: EA 33 F7 FF B8 90 F8 FF  EA 33 F7 FF 34 74 22 FF  |.3.......3..4t".|
0x15C0: 65 D9 C8 FF F2 AA 6D FF  EA 33 F7 FF ED 6C A4 FF  |e.....m..3...l..|
0x15D0: ED 6C A4 FF AB 73 F7 FF  8E 56 E8 FF 6A 9C 2D FF  |.l...s...V..j.-.|
0x15E0: ED 6C A4 FF 9D 64 F6 FF  ED 6C A4 FF 6A 9C 2D FF  |.l...d...l..j.-.|
0x15F0: B8 95 EE FF C2 2E B7 FF  6A 55 1A FF EA 33 F7 FF  |........jU...3..|
0x1600: 6A 9C 2D FF 5F C7 8B FF  EA 3B 9A FF EA 3B 99 FF  |j.-._....;...;..|
0x1610: 60 D1 7C FF 75 FB 4C FF  EA 3B 99 FF EA 3B 99 FF  |`.|.u.L..;...;..|
0x1620: 87 E0 44 FF EA 3B 98 FF  EA 3B 97 FF 68 E1 75 FF  |..D..;...;..h.u.|
0x1630: 2B 65 DC FF 5E 0E DB FF  70 EF 6E FF 68 E1 77 FF  |+e..^...p.n.h.w.|
0x1640: EA 3B 94 FF D1 2D 6A FF  EA 3B 93 FF EA 3B 92 FF  |.;...-j..;...;..|
0x1650: 56 BC 7D FF 68 E1 79 FF  55 B6 97 FF EA 3B 91 FF  |V.}.h.y.U....;..|
0x1660: 63 10 DC FF 75 FB 4C FF  56 BD 65 FF 64 10 DC FF  |c...u.L.V.e.d...|
0x1670: 8E E2 45 FF 53 B7 99 FF  63 D1 8D FF 75 FB 4C FF  |..E.S...c...u.L.|
0x1680: 45 99 2E FF 5B C6 78 FF  30 6F DD FF 7B EB 4B FF  |E...[.x.0o..{.K.|
0x1690: 68 11 DC FF EA 3A 8B FF  D3 2D 73 FF 6A 12 DD FF  |h....:...-s.j...|
0x16A0: 6A 12 DD FF 70 F1 8F FF  92 E3 45 FF EA 3A 88 FF  |j...p.....E..:..|
0x16B0: 70 F1 79 FF D3 2D 76 FF  EA 3A 87 FF 75 FB 4C FF  |p.y..-v..:..u.L.|
0x16C0: 94 E3 46 FF 75 FB 4C FF  EA 3A 85 FF 75 FB 4C FF  |..F.u.L..:..u.L.|
0x16D0: 6F 13 DE FF 34 78 DF FF  D4 2D 7A FF 35 79 E0 FF  |o...4x...-z.5y..|
0x16E0: 97 E4 46 FF 72 F2 95 FF  6D D2 8D FF EA 3A 81 FF  |..F.r...m....:..|
0x16F0: 62 D5 7A FF 69 E4 88 FF  EA 3A 80 FF 99 E5 46 FF  |b.z.i....:....F.|
0x1700: 99 E5 46 FF 62 D6 95 FF  75 14 DF FF 5C C9 7C FF  |..F.b...u...\.|.|
0x1710: 9A E5 47 FF D5 2E 80 FF  EA 39 7D FF 75 FB 9C FF  |..G......9}.u...|
0x1720: EB 62 BF FF 72 F3 83 FF  6F EE 81 FF A3 CD 69 FF  |.b..r...o.....i.|
0x1730: EA 39 7A FF 65 CF B3 FF  63 D7 81 FF 6A E6 8F FF  |.9z.e...c...j...|
0x1740: 9E E7 47 FF 6A E6 90 FF  EA 39 78 FF 6A E6 91 FF  |..G.j....9x.j...|
0x1750: 75 FB FD FF 0F 1C CF FF  73 F4 A1 FF 6A E6 93 FF  |u.......s...j...|
0x1760: 6D DB 92 FF 7F 17 E0 FF  A1 E8 48 FF D7 2E 8A FF  |m.........H.....|
0x1770: 80 17 E1 FF 6B E7 95 FF  A3 E8 48 FF 5C BA 86 FF  |....k.....H.\...|
0x1780: D7 2E 8C FF 82 18 E1 FF  75 FB FD FF A4 E8 48 FF  |........u.....H.|
0x1790: 84 18 E1 FF 75 FB FD FF  72 F5 8D FF E5 40 B6 FF  |....u...r....@..|
0x17A0: 85 19 E2 FF 40 90 E4 FF  65 D9 A6 FF 6B E8 9B FF  |....@...e...k...|
0x17B0: D8 2E 90 FF 87 19 E2 FF  72 F6 AA FF 88 19 E2 FF  |........r.......|
0x17C0: 5A C5 7E FF 75 FB FD FF  C1 6C 34 FF 91 22 1F FF  |Z.~.u....l4.."..|
0x17D0: D8 2E 94 FF 8F 9C 38 FF  B2 98 9C FF B3 2E C1 FF  |......8.........|
0x17E0: 5C 9E 41 FF A5 D4 76 FF  75 FB FD FF EA 38 67 FF  |\.A...v.u....8g.|
0x17F0: 75 FB FD FF 75 FB FD FF  75 FB FD FF AD EA 49 FF  |u...u...u.....I.|
0x1800: D8 2E 99 FF 75 FB FD FF  90 1B E4 FF 90 1B E4 FF  |....u...........|
0x1810: 90 1B E4 FF 90 1B E4 FF  75 FB 9B FF 70 EC 9E FF  |........u...p...|
0x1820: 47 9E E7 FF 75 FB FD FF  92 1C E4 FF 75 FB FD FF  |G...u.......u...|
0x1830: D8 DC 9B FF 70 EC A0 FF  75 FB FD FF 62 D5 7C FF  |....p...u...b.|.|
0x1840: 75 FB FD FF 75 F9 9E FF  49 A1 E8 FF 6D EA AA FF  |u...u...I...m...|
0x1850: 75 FB FD FF 63 D4 AD FF  75 FB D1 FF 75 FB FD FF  |u...c...u...u...|
0x1860: 72 E9 AB FF 51 3F 82 FF  9A 1E E5 FF 67 DC B9 FF  |r...Q?......g...|
0x1870: EA 37 5B FF 9B 1E E6 FF  B8 ED 4A FF 75 FB B6 FF  |.7[.......J.u...|
0x1880: 75 FB FD FF B9 ED 4A FF  74 FA BF FF 77 FB CE FF  |u.....J.t...w...|
0x1890: EA 37 57 FF 6A DE CF FF  EA 37 57 FF 68 E2 A5 FF  |.7W.j....7W.h...|
0x18A0: E8 B0 3C FF 75 FB FD FF  75 FB FD FF 4E AC EA FF  |..<.u...u...N...|
0x18B0: A1 B3 AD FF DD 87 8B FF  70 CC 52 FF 43 84 75 FF  |........p.R.C.u.|
0x18C0: 6B 80 2F FF DC 30 AD FF  4F AF EA FF 75 FB FD FF  |k./..0..O...u...|
0x18D0: EA 37 51 FF A4 21 E7 FF  A4 21 E8 FF 68 DF C4 FF  |.7Q..!...!..h...|
0x18E0: EA 36 51 FF EA 36 50 FF  EA 36 50 FF 6E ED BA FF  |.6Q..6P..6P.n...|
0x18F0: 9E D8 C6 FF 69 D3 D4 FF  BB 7D B6 FF 62 D5 C5 FF  |....i....}..b...|
0x1900: DD 30 B3 FF EA 36 4D FF  75 FB CA FF 1A 0F 4B FF  |.0...6M.u.....K.|
0x1910: 53 B7 ED FF 75 FB FD FF  C5 F0 4C FF 75 FB FD FF  |S...u.....L.u...|
0x1920: C6 F0 4C FF 6F EF E2 FF  C2 72 31 FF 71 F3 E6 FF  |..L.o....r1.q...|
0x1930: 65 DB C9 FF 6B B7 8F FF  67 E0 B2 FF 6F EE C1 FF  |e...k...g...o...|
0x1940: 5A C4 DE FF DF 30 BA FF  EA 36 48 FF CA F2 4D FF  |Z....0...6H...M.|
0x1950: CA F2 4D FF 68 E1 B5 FF  EA 36 46 FF B1 24 EA FF  |..M.h....6F..$..|
0x1960: 77 F6 C9 FF B0 9B 6E FF  58 C0 EE FF 75 FB FD FF  |w.....n.X...u...|
0x1970: 75 FB BA FF 68 E1 D3 FF  E0 74 72 FF B4 25 EB FF  |u...h....tr..%..|
0x1980: B4 25 EB FF 70 E8 CA FF  B5 25 EB FF 64 D9 BC FF  |.%..p....%..d...|
0x1990: EA 36 41 FF 7A FB F4 FF  EA 36 40 FF 70 F0 CA FF  |.6A.z....6@.p...|
0x19A0: B8 26 EB FF 72 F5 BC FF  5B C7 EF FF 75 FB FD FF  |.&..r...[...u...|
0x19B0: 70 ED E9 FF 77 54 1E FF  84 C5 60 FF EA 35 3E FF  |p...wT....`..5>.|
0x19C0: EA 35 3E FF 6D EB E3 FF  75 FB C2 FF 69 E3 DC FF  |.5>.m...u...i...|
0x19D0: EA 35 3C FF EA 35 3C FF  D6 F4 4E FF 75 FB C4 FF  |.5<..5<...N.u...|
0x19E0: 75 FB FD FF 43 64 70 FF  00 00 00 FF 41 41 41 FF  |u...Cdp.....AAA.|
0x19F0: 00 00 00 FF 00 00 00 FF  41 41 41 FF 41 41 41 FF  |........AAA.AAA.|
0x1A00: 52 68 62 FF 41 41 41 FF  7D CB 97 FF D2 89 3E FF  |Rhb.AAA.}.....>.|
0x1A10: 41 41 41 FF 4C 33 4E FF  41 41 41 FF 3B 2F 49 FF  |AAA.L3N.AAA.;/I.|
0x1A20: 41 41 41 FF BE BE BE FF  41 41 41 FF 41 41 41 FF  |AAA.....AAA.AAA.|
0x1A30: 41 41 41 FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x1A40: 20 2C 40 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  | ,@.AAA.AAA.AAA.|
0x1A50: 39 4F 35 FF BE BE BE FF  41 41 41 FF 41 41 41 FF  |9O5.....AAA.AAA.|
0x1A60: 41 41 41 FF BE BE BE FF  4C 33 4E FF 41 41 41 FF  |AAA.....L3N.AAA.|
0x1A70: 41 41 41 FF 32 32 4E FF  41 41 41 FF BE BE BE FF  |AAA.22N.AAA.....|
0x1A80: 4C 33 33 FF 41 41 41 FF  41 41 41 FF 4C 33 33 FF  |L33.AAA.AAA.L33.|
0x1A90: 4B 31 24 FF 6D 4D 2A FF  41 41 41 FF 27 15 3E FF  |K1$.mM*.AAA.'.>.|
0x1AA0: 41 41 41 FF DD F1 B4 FF  32 32 4E FF 00 00 00 FF  |AAA.....22N.....|
0x1AB0: BE BE BE FF BE BE BE FF  56 2D 69 FF 6C 3F 36 FF  |........V-i.l?6.|
0x1AC0: 50 50 50 FF BE BE BE FF  32 32 32 FF 41 41 41 FF  |PPP.....222.AAA.|
0x1AD0: 50 50 50 FF 41 41 41 FF  39 4F 50 FF 41 41 41 FF  |PPP.AAA.9OP.AAA.|
0x1AE0: 41 41 41 FF 91 E9 51 FF  39 4F 50 FF 41 41 41 FF  |AAA...Q.9OP.AAA.|
0x1AF0: 41 41 41 FF 39 4F 35 FF  41 41 41 FF 41 41 41 FF  |AAA.9O5.AAA.AAA.|
0x1B00: B2 D9 BF FF 4C 33 33 FF  3C 31 4B FF 41 41 41 FF  |....L33.<1K.AAA.|
0x1B10: 70 2B C7 FF 41 41 41 FF  50 50 36 FF 41 41 41 FF  |p+..AAA.PP6.AAA.|
0x1B20: 00 00 00 FF 60 35 22 FF  41 41 41 FF 32 32 32 FF  |....`5".AAA.222.|
0x1B30: BE BE BE FF 00 00 00 FF  41 41 41 FF BE BE BE FF  |........AAA.....|
0x1B40: 45 59 3A FF BE BE BE FF  BE BE BE FF 41 41 41 FF  |EY:.........AAA.|
0x1B50: 41 41 41 FF 41 41 41 FF  BE BE BE FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x1B60: 50 50 36 FF 41 41 41 FF  BE BE BE FF 30 2A 31 FF  |PP6.AAA.....0*1.|
0x1B70: 00 00 00 FF 41 41 41 FF  42 70 71 FF 41 41 41 FF  |....AAA.Bpq.AAA.|
0x1B80: 41 41 41 FF 40 53 33 FF  41 41 41 FF 55 30 57 FF  |AAA.@S3.AAA.U0W.|
0x1B90: 70 68 72 FF 79 4F A5 FF  41 41 41 FF 41 41 41 FF  |phr.yO..AAA.AAA.|
0x1BA0: 41 41 41 FF 34 44 40 FF  00 00 00 FF 41 41 41 FF  |AAA.4D@.....AAA.|
0x1BB0: 00 00 00 FF 41 41 41 FF  BE BE BE FF 41 41 41 FF  |....AAA.....AAA.|
0x1BC0: 41 41 41 FF 00 00 00 FF  BE BE BE FF 54 5C 63 FF  |AAA.........T\c.|
0x1BD0: 41 41 41 FF 00 00 00 FF  41 41 41 FF 00 00 00 FF  |AAA.....AAA.....|
0x1BE0: 41 41 41 FF BE BE BE FF  41 41 41 FF BE BE BE FF  |AAA.....AAA.....|
0x1BF0: BE BE BE FF BE BE BE FF  00 00 00 FF BE BE BE FF  |................|
0x1C00: 41 41 41 FF 71 ED ED FF  C3 3C 4A FF 32 32 32 FF  |AAA.q....<J.222.|
0x1C10: BE BE BE FF 28 49 3C FF  00 00 00 FF 3C 55 2D FF  |....(I<.....<U-.|
0x1C20: 4C 33 33 FF 41 41 41 FF  00 00 00 FF 26 1A 2A FF  |L33.AAA.....&.*.|
0x1C30: 41 41 41 FF 41 41 41 FF  17 26 17 FF 00 00 00 FF  |AAA.AAA..&......|
0x1C40: 00 00 00 FF 47 3F 3E FF  6F 72 2A FF 7F 48 9C FF  |....G?>.or*..H..|
0x1C50: 41 41 41 FF 32 32 32 FF  BE BE BE FF 40 15 3C FF  |AAA.222.....@.<.|
0x1C60: 41 41 41 FF 41 41 41 FF  C8 90 88 FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x1C70: 41 41 41 FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x1C80: BE BE BE FF 41 41 41 FF  5D 98 2F FF 32 32 32 FF  |....AAA.]./.222.|
0x1C90: 49 9D D6 FF 41 41 41 FF  4C 33 4E FF 66 A1 8B FF  |I...AAA.L3N.f...|
0x1CA0: 32 32 32 FF BE BE BE FF  36 48 6E FF BE BE BE FF  |222.....6Hn.....|
0x1CB0: 41 41 41 FF 00 00 00 FF  2E 27 1A FF 41 41 41 FF  |AAA......'..AAA.|
0x1CC0: 2B 36 30 FF BE BE BE FF  41 41 41 FF 39 4F 35 FF  |+60.....AAA.9O5.|
0x1CD0: 58 6D 25 FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |Xm%.AAA.....AAA.|
0x1CE0: 32 32 32 FF 4C 33 4E FF  59 1C 40 FF 41 41 41 FF  |222.L3N.Y.@.AAA.|
0x1CF0: 41 41 41 FF 41 41 41 FF  41 41 41 FF BE BE BE FF  |AAA.AAA.AAA.....|
0x1D00: 64 3A 5E FF 00 00 00 FF  30 1E 6D FF 41 41 41 FF  |d:^.....0.m.AAA.|
0x1D10: 5E 89 50 FF EB 57 B1 FF  69 B5 35 FF 52 A8 50 FF  |^.P..W..i.5.R.P.|
0x1D20: D1 71 F0 FF 42 95 38 FF  44 08 B0 FF 52 B4 58 FF  |.q..B.8.D...R.X.|
0x1D30: C0 6A 86 FF 75 FB 4C FF  75 FB 4C FF D4 49 4F FF  |.j..u.L.u.L..IO.|
0x1D40: 75 FB 4C FF EB 57 B1 FF  65 DB 4E FF 45 2A 10 FF  |u.L..W..e.N.E*..|
0x1D50: 69 B5 35 FF 75 FB 4C FF  6A E6 61 FF E3 50 27 FF  |i.5.u.L.j.a..P'.|
0x1D60: 75 FB 4C FF 47 9E 3E FF  57 BC 5A FF 44 08 B0 FF  |u.L.G.>.W.Z.D...|
0x1D70: EB 57 B1 FF 52 B4 58 FF  69 B5 35 FF 4B A5 62 FF  |.W..R.X.i.5.K.b.|
0x1D80: 69 B5 35 FF 52 B4 58 FF  4D 93 32 FF 1B 06 C8 FF  |i.5.R.X.M.2.....|
0x1D90: 1D 4A B0 FF 40 83 64 FF  75 FB 4C FF CD 94 B1 FF  |.J..@.d.u.L.....|
0x1DA0: 75 FB 4C FF 5B C3 66 FF  75 FB 4C FF 75 FB 4C FF  |u.L.[.f.u.L.u.L.|
0x1DB0: 3C 88 6C FF 75 FB 4C FF  44 08 B0 FF 52 B4 58 FF  |<.l.u.L.D...R.X.|
0x1DC0: 4D A5 62 FF 75 FB 4C FF  5F CE 6E FF 4B A5 4B FF  |M.b.u.L._.n.K.K.|
0x1DD0: 44 08 B0 FF 75 FB 4C FF  64 D9 84 FF 4A 92 56 FF  |D...u.L.d...J.V.|
0x1DE0: 4B A5 62 FF 52 B4 58 FF  35 43 5C FF 41 41 41 FF  |K.b.R.X.5C\.AAA.|
0x1DF0: 41 41 41 FF BE BE BE FF  41 41 41 FF 41 41 41 FF  |AAA.....AAA.AAA.|
0x1E00: 41 41 41 FF 41 41 41 FF  36 47 55 FF 44 53 8F FF  |AAA.AAA.6GU.DS..|
0x1E10: 00 00 00 FF BE BE BE FF  32 32 17 FF 00 00 00 FF  |........22......|
0x1E20: 41 41 41 FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x1E30: BE BE BE FF 44 3D 7D FF  27 52 1F FF 94 D3 6C FF  |....D=}.'R....l.|
0x1E40: 41 41 41 FF 41 41 41 FF  BE BE BE FF 4D 4A E1 FF  |AAA.AAA.....MJ..|
0x1E50: 41 41 41 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |AAA.AAA.AAA.AAA.|
0x1E60: 00 00 00 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |....AAA.AAA.AAA.|
0x1E70: 41 41 41 FF 4C 33 33 FF  41 41 41 FF 41 41 41 FF  |AAA.L33.AAA.AAA.|
0x1E80: 00 00 00 FF 41 41 41 FF  73 D5 40 FF 41 41 41 FF  |....AAA.s.@.AAA.|
0x1E90: 39 20 6A FF 54 74 47 FF  57 3F 3F FF 18 3F 78 FF  |9 j.TtG.W??..?x.|
0x1EA0: 40 58 3E FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |@X>.AAA.AAA.AAA.|
0x1EB0: 32 32 4E FF 41 41 41 FF  7E FB 56 FF 41 41 41 FF  |22N.AAA.~.V.AAA.|
0x1EC0: 41 41 41 FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x1ED0: 70 17 34 FF 41 41 41 FF  50 50 50 FF 66 86 DF FF  |p.4.AAA.PPP.f...|
0x1EE0: BE BE BE FF 3F 70 35 FF  5B 3E 26 FF 50 50 36 FF  |....?p5.[>&.PP6.|
0x1EF0: E1 97 3F FF 00 00 00 FF  39 4F 35 FF 00 00 00 FF  |..?.....9O5.....|
0x1F00: 20 42 42 FF 41 41 41 FF  00 00 00 FF BE BE BE FF  | BB.AAA.........|
0x1F10: 39 4F 35 FF 41 41 41 FF  41 41 41 FF BE BE BE FF  |9O5.AAA.AAA.....|
0x1F20: 5C C5 83 FF 3E 3F EB FF  41 41 41 FF 41 41 41 FF  |\...>?..AAA.AAA.|
0x1F30: 00 00 00 FF 41 41 41 FF  33 4D 4E FF 41 41 41 FF  |....AAA.3MN.AAA.|
0x1F40: 2C 15 72 FF 9F 39 C9 FF  39 4F 35 FF BE BE BE FF  |,.r..9..9O5.....|
0x1F50: 41 41 41 FF 41 41 41 FF  47 64 67 FF 37 71 71 FF  |AAA.AAA.Gdg.7qq.|
0x1F60: D7 78 3B FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |.x;.AAA.AAA.AAA.|
0x1F70: AD 50 F5 FF BE BE BE FF  41 41 41 FF 91 F7 E9 FF  |.P......AAA.....|
0x1F80: BE BE BE FF 41 41 41 FF  BE BE BE FF 00 00 00 FF  |....AAA.........|
0x1F90: 41 41 41 FF 41 41 41 FF  BE BE BE FF 2C 22 33 FF  |AAA.AAA.....,"3.|
0x1FA0: 71 E3 A0 FF 41 41 41 FF  BE BE BE FF 41 41 41 FF  |q...AAA.....AAA.|
0x1FB0: 00 00 00 FF 00 00 00 FF  00 00 00 FF 67 1B 68 FF  |............g.h.|
0x1FC0: 41 41 41 FF 41 41 41 FF  69 66 55 FF 00 00 00 FF  |AAA.AAA.ifU.....|
0x1FD0: 00 00 00 FF 39 4F 50 FF  41 41 41 FF BE BE BE FF  |....9OP.AAA.....|
0x1FE0: 41 41 41 FF 41 41 41 FF  72 E7 C7 FF 00 00 00 FF  |AAA.AAA.r.......|
0x1FF0: 41 41 41 FF 41 41 41 FF  1F 34 43 FF 41 41 41 FF  |AAA.AAA..4C.AAA.|
0x2000: 41 41 41 FF 41 41 41 FF  32 32 4E FF 41 41 41 FF  |AAA.AAA.22N.AAA.|
0x2010: 41 41 41 FF 21 25 6E FF  BE BE BE FF 50 50 36 FF  |AAA.!%n.....PP6.|
0x2020: 32 32 32 FF 41 41 41 FF  50 50 36 FF 41 41 41 FF  |222.AAA.PP6.AAA.|
0x2030: D3 E9 AC FF 00 00 00 FF  BE BE BE FF BE BE BE FF  |................|
0x2040: 41 41 41 FF 41 41 41 FF  6A 71 5C FF BE BE BE FF  |AAA.AAA.jq\.....|
0x2050: 41 41 41 FF BE BE BE FF  BE BE BE FF 39 4F 35 FF  |AAA.........9O5.|
0x2060: 41 41 41 FF 4A 4A 60 FF  00 00 00 FF 41 41 41 FF  |AAA.JJ`.....AAA.|
0x2070: 41 41 41 FF 41 41 41 FF  00 00 00 FF 32 32 4E FF  |AAA.AAA.....22N.|
0x2080: 41 41 41 FF 00 00 00 FF  A2 6A 7E FF 00 00 00 FF  |AAA......j~.....|
0x2090: 4A 57 41 FF 00 00 00 FF  41 41 41 FF 57 3A 59 FF  |JWA.....AAA.W:Y.|
0x20A0: BE BE BE FF 41 41 41 FF  41 41 41 FF 37 66 57 FF  |....AAA.AAA.7fW.|
0x20B0: BE BE BE FF BE BE BE FF  BE BE BE FF 48 5C 2D FF  |............H\-.|
0x20C0: BE BE BE FF 41 41 41 FF  4C 33 4E FF 41 41 41 FF  |....AAA.L3N.AAA.|
0x20D0: BE BE BE FF BE BE BE FF  A3 8D 30 FF B1 74 7C FF  |..........0..t|.|
0x20E0: 41 41 41 FF 26 32 5C FF  BE BE BE FF 00 00 00 FF  |AAA.&2\.........|
0x20F0: 4F 6E B5 FF 41 41 41 FF  64 45 52 FF 41 41 41 FF  |On..AAA.dER.AAA.|
0x2100: 41 41 41 FF 00 00 00 FF  61 42 4F FF 00 00 00 FF  |AAA.....aBO.....|
0x2110: 23 42 50 FF 00 00 00 FF  00 00 00 FF 41 41 41 FF  |#BP.........AAA.|
0x2120: BE BE BE FF 41 41 41 FF  39 4F 50 FF 00 00 00 FF  |....AAA.9OP.....|
0x2130: 00 00 00 FF 00 00 00 FF  41 41 41 FF 32 32 32 FF  |........AAA.222.|
0x2140: 41 41 41 FF 00 00 00 FF  41 41 41 FF 00 00 00 FF  |AAA.....AAA.....|
0x2150: 39 4F 35 FF 41 41 41 FF  41 41 41 FF BE BE BE FF  |9O5.AAA.AAA.....|
0x2160: 41 41 41 FF 41 41 41 FF  BE BE BE FF 7B A8 DB FF  |AAA.AAA.....{...|
0x2170: 2C 57 3A FF 41 41 41 FF  BE BE BE FF 41 41 41 FF  |,W:.AAA.....AAA.|
0x2180: 41 41 41 FF BE BE BE FF  41 41 41 FF 00 00 00 FF  |AAA.....AAA.....|
0x2190: 50 3D 10 FF 2E 0F 73 FF  BE BE BE FF 39 4F 50 FF  |P=....s.....9OP.|
0x21A0: BE BE BE FF 19 2B 16 FF  B3 C2 7C FF BE BE BE FF  |.....+....|.....|
0x21B0: BE BE BE FF 4A 65 4F FF  2A 36 60 FF 63 9E 7F FF  |....JeO.*6`.c...|
0x21C0: BE BE BE FF BE BE BE FF  39 4F 50 FF 00 00 00 FF  |........9OP.....|
0x21D0: 41 41 41 FF 41 41 41 FF  39 4F 35 FF 41 41 41 FF  |AAA.AAA.9O5.AAA.|
0x21E0: BE BE BE FF 4C 33 33 FF  00 00 00 FF BE BE BE FF  |....L33.........|
0x21F0: 41 41 41 FF 42 27 63 FF  C3 F4 75 FF 32 32 32 FF  |AAA.B'c...u.222.|
0x2200: 41 41 41 FF 50 50 50 FF  00 00 00 FF 41 41 41 FF  |AAA.PPP.....AAA.|
0x2210: 41 41 41 FF 41 41 41 FF  00 00 00 FF 00 00 00 FF  |AAA.AAA.........|
0x2220: 41 41 41 FF 41 41 41 FF  6D 6F 4E FF 41 41 41 FF  |AAA.AAA.moN.AAA.|
0x2230: 50 50 50 FF 7F D7 88 FF  32 32 4E FF BE BE BE FF  |PPP.....22N.....|
0x2240: 00 00 00 FF 5C 69 80 FF  41 41 41 FF 4C 33 33 FF  |....\i..AAA.L33.|
0x2250: 41 41 41 FF 41 41 41 FF  41 41 41 FF BE BE BE FF  |AAA.AAA.AAA.....|
0x2260: C2 B4 53 FF 41 41 41 FF  32 32 32 FF 41 41 41 FF  |..S.AAA.222.AAA.|
0x2270: 39 6F 58 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |9oX.AAA.AAA.AAA.|
0x2280: 6B 64 6D FF 00 00 00 FF  41 41 41 FF 32 32 4E FF  |kdm.....AAA.22N.|
0x2290: 00 00 00 FF 2B 64 D4 FF  41 41 41 FF 41 41 41 FF  |....+d..AAA.AAA.|
0x22A0: 00 00 00 FF 00 00 00 FF  4C 33 33 FF 41 41 41 FF  |........L33.AAA.|
0x22B0: 00 00 00 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |....AAA.AAA.AAA.|
0x22C0: 41 41 41 FF 41 41 41 FF  68 28 20 FF BE BE BE FF  |AAA.AAA.h( .....|
0x22D0: 41 41 41 FF 1C 30 6E FF  00 00 00 FF 6A 4C 44 FF  |AAA..0n.....jLD.|
0x22E0: 41 41 41 FF 41 41 41 FF  3A 6D 72 FF BE BE BE FF  |AAA.AAA.:mr.....|
0x22F0: 41 41 41 FF 54 5B B5 FF  57 2E 30 FF 41 41 41 FF  |AAA.T[..W.0.AAA.|
0x2300: 00 00 00 FF 41 41 41 FF  41 41 41 FF BE BE BE FF  |....AAA.AAA.....|
0x2310: BE BE BE FF 41 41 41 FF  22 35 2E FF 41 41 41 FF  |....AAA."5..AAA.|
0x2320: 41 41 41 FF BE BE BE FF  00 00 00 FF BE BE BE FF  |AAA.............|
0x2330: DE 3D 98 FF 41 41 41 FF  00 00 00 FF BE BE BE FF  |.=..AAA.........|
0x2340: BE BE BE FF 00 00 00 FF  AC 23 21 FF 41 41 41 FF  |.........#!.AAA.|
0x2350: 26 23 63 FF 41 41 41 FF  2A 43 4F FF BE BE BE FF  |&#c.AAA.*CO.....|
0x2360: 41 41 41 FF 41 41 41 FF  39 4F 50 FF 41 41 41 FF  |AAA.AAA.9OP.AAA.|
0x2370: 00 00 00 FF 41 41 41 FF  41 41 41 FF 39 4F 50 FF  |....AAA.AAA.9OP.|
0x2380: 41 41 41 FF F4 E4 CF FF  41 41 41 FF 41 41 41 FF  |AAA.....AAA.AAA.|
0x2390: 41 41 41 FF 3F 37 20 FF  BE BE BE FF 51 2B 68 FF  |AAA.?7 .....Q+h.|
0x23A0: 39 4F 50 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |9OP.AAA.AAA.AAA.|
0x23B0: 41 41 41 FF 41 41 41 FF  41 41 41 FF 37 24 1E FF  |AAA.AAA.AAA.7$..|
0x23C0: 41 41 41 FF 41 41 41 FF  00 00 00 FF 00 00 00 FF  |AAA.AAA.........|
0x23D0: 41 41 41 FF BE BE BE FF  BE BE BE FF 41 41 41 FF  |AAA.........AAA.|
0x23E0: 81 5D 3F FF 00 00 00 FF  38 7F 4D FF C0 BC 7F FF  |.]?.....8.M.....|
0x23F0: BE BE BE FF 65 35 77 FF  2F 1C CE FF A7 CB BF FF  |....e5w./.......|
0x2400: BA 9F C9 FF FF FF FF FF  BA 9F C9 FF 5B 35 40 FF  |............[5@.|
0x2410: C5 A0 BD FF FF FF FF FF  FF FF FF FF 5B 66 5E FF  |............[f^.|
0x2420: 1D 42 0E FF FF FF FF FF  C1 CC A2 FF 6C 3E 7B FF  |.B..........l>{.|
0x2430: FF FF FF FF B0 BD CC FF  FF FF FF FF C1 CC A2 FF  |................|
0x2440: BA 9F C9 FF 5B 35 40 FF  BF B8 C0 FF 5B 35 40 FF  |....[5@.....[5@.|
0x2450: 5B 35 40 FF B6 DA CE FF  9E D8 B7 FF A4 BE CA FF  |[5@.............|
0x2460: 5B 35 40 FF BA 9F C9 FF  B6 DA B3 FF BA 9F C9 FF  |[5@.............|
0x2470: 5B 35 40 FF BA 9F C9 FF  C4 B4 BF FF A7 CB BF FF  |[5@.............|
0x2480: B6 DA B3 FF 67 DF 43 FF  FF FF FF FF A7 CB BF FF  |....g.C.........|
0x2490: 21 28 A9 FF A7 CB BF FF  C1 CC A2 FF 1D 43 F4 FF  |!(...........C..|
0x24A0: C1 CC A2 FF C0 D0 A9 FF  86 AC E9 FF 98 BC B0 FF  |................|
0x24B0: FF FF FF FF FF FF FF FF  92 CD B8 FF A7 CB BF FF  |................|
0x24C0: C1 CC A2 FF BA 9F C9 FF  98 CA AA FF 7D 99 93 FF  |............}...|
0x24D0: FF FF FF FF BA 9F C9 FF  B6 DA CE FF C3 F2 D1 FF  |................|
0x24E0: 9F BD E4 FF 34 77 50 FF  BA 9F C9 FF BA 9F C9 FF  |....4wP.........|
0x24F0: B0 BD B1 FF 5B 35 40 FF  BA 9F C9 FF A4 BE CA FF  |....[5@.........|
0x2500: BA 9F C9 FF FF FF FF FF  9D 5E 6A FF 5B 35 40 FF  |.........^j.[5@.|
0x2510: EE C1 A4 FF C1 CC A2 FF  E0 33 B2 FF BA 9F C9 FF  |.........3......|
0x2520: BA 9F C9 FF 8D DE EA FF  79 99 A7 FF B6 DA B3 FF  |........y.......|
0x2530: BA 9F C9 FF BA 9F C9 FF  98 BC CC FF 5B 35 40 FF  |............[5@.|
0x2540: 98 BC B0 FF 6E EC 96 FF  BA 9F C9 FF 5B 35 40 FF  |....n.......[5@.|
0x2550: C1 CC A2 FF A7 CB BF FF  5B 35 40 FF 88 9A E8 FF  |........[5@.....|
0x2560: FF FF FF FF 5B 35 40 FF  AA D6 ED FF 95 52 CB FF  |....[5@......R..|
0x2570: 5B 35 40 FF A4 BE CA FF  5A 38 44 FF A7 CB BF FF  |[5@.....Z8D.....|
0x2580: BA 9F C9 FF BA 9F C9 FF  FF FF FF FF 5B 35 40 FF  |............[5@.|
0x2590: BA 9F C9 FF A7 CB BF FF  C1 CC A2 FF 91 B2 C3 FF  |................|
0x25A0: 5B 35 40 FF B0 BD CC FF  D3 9C 69 FF 5B 35 40 FF  |[5@.......i.[5@.|
0x25B0: C1 CC A2 FF BA 9F C9 FF  C1 CB BC FF C4 AE AF FF  |................|
0x25C0: C1 CC A2 FF FF FF FF FF  B6 DA B3 FF C5 A0 BD FF  |................|
0x25D0: 64 C3 4C FF 5B 35 40 FF  C5 A0 BD FF 5B 35 40 FF  |d.L.[5@.....[5@.|
0x25E0: 5B 35 40 FF A7 CB BF FF  FF FF FF FF A7 CB BF FF  |[5@.............|
0x25F0: C1 CC A2 FF 5B 35 40 FF  A4 BE CA FF C8 B1 D2 FF  |....[5@.........|
0x2600: B1 72 EB FF C1 CC A2 FF  C5 A0 BD FF BA 9F C9 FF  |.r..............|
0x2610: AA A5 8F FF A4 BE CA FF  FF FF FF FF FF FF FF FF  |................|
0x2620: C1 CC A2 FF A0 D9 CE FF  B3 D4 E4 FF DE 72 AD FF  |.............r..|
0x2630: 47 17 8F FF 5B 35 40 FF  B3 70 5C FF B0 BD B1 FF  |G...[5@..p\.....|
0x2640: 5B 35 40 FF 1D 46 51 FF  2E 17 A9 FF A0 D9 CE FF  |[5@..FQ.........|
0x2650: C1 CC A2 FF B0 BD CC FF  C1 CC A2 FF C5 9E 8A FF  |................|
0x2660: B6 DA B3 FF BA 9F C9 FF  76 5F 47 FF 7E D2 E4 FF  |........v_G.~...|
0x2670: 8D A5 DD FF FF FF FF FF  BA 9F C9 FF 5B 35 40 FF  |............[5@.|
0x2680: 80 9F 99 FF 97 ED C6 FF  FF FF FF FF BE 41 78 FF  |.............Ax.|
0x2690: C1 CC A2 FF 85 E4 4F FF  BA 9F C9 FF A7 CB BF FF  |......O.........|
0x26A0: B6 DA CE FF 5B 35 40 FF  BA 9F C9 FF 5B 35 40 FF  |....[5@.....[5@.|
0x26B0: BA 9F C9 FF BA 9F C9 FF  40 91 70 FF B0 BD CC FF  |........@.p.....|
0x26C0: B0 BD B1 FF A7 CB BF FF  FF FF FF FF FF FF FF FF  |................|
0x26D0: 5B 35 40 FF E9 BD B5 FF  A4 BE CA FF BA 9F C9 FF  |[5@.............|
0x26E0: 85 BD 9F FF BA 9F C9 FF  98 BC CC FF A7 CB BF FF  |................|
0x26F0: A4 BE CA FF FF FF FF FF  C1 CC A2 FF A4 BE CA FF  |................|
0x2700: BA 9F C9 FF 95 E7 C8 FF  5B 35 40 FF BA 9F C9 FF  |........[5@.....|
0x2710: 5B 35 40 FF FF FF FF FF  A0 D9 B3 FF FF FF FF FF  |[5@.............|
0x2720: 5B 35 40 FF FF FF FF FF  C1 CC A2 FF C1 CC A2 FF  |[5@.............|
0x2730: A0 D9 CE FF A0 D9 CE FF  A5 D8 D9 FF 96 7D 96 FF  |.............}..|
0x2740: BA 9F C9 FF FF FF FF FF  5B BA 6A FF A7 CB BF FF  |........[.j.....|
0x2750: 98 BC B0 FF B6 DA CE FF  5B 35 40 FF 5B 35 40 FF  |........[5@.[5@.|
0x2760: A0 D9 B3 FF BA 9F C9 FF  BA 9F C9 FF B2 EE E7 FF  |................|
0x2770: 86 CC 55 FF BA 9F C9 FF  E7 F7 AF FF 5B 35 40 FF  |..U.........[5@.|
0x2780: 98 BC CC FF 59 C3 D9 FF  A4 BE CA FF 5B 35 40 FF  |....Y.......[5@.|
0x2790: BA 9F C9 FF 5B 35 40 FF  FF FF FF FF 8D C8 D6 FF  |....[5@.........|
0x27A0: B6 DA CE FF 98 BC B0 FF  C1 CC A2 FF 5B 35 40 FF  |............[5@.|
0x27B0: C5 A0 BD FF B5 FC CC FF  C5 A0 BD FF BA 9F C9 FF  |................|
0x27C0: BA 9F C9 FF FF FF FF FF  FF FF FF FF A7 CB BF FF  |................|
0x27D0: 98 BC B0 FF B6 DA CE FF  FF FF FF FF 91 9B 90 FF  |................|
0x27E0: 94 DB D2 FF FF FF FF FF  F4 C8 C0 FF A7 CB BF FF  |................|
0x27F0: FF FF FF FF 9D CF EA FF  B4 E9 C5 FF C5 A0 BD FF  |................|
0x2800: C5 A0 BD FF A7 CB BF FF  BA 9F C9 FF A4 BE CA FF  |................|
0x2810: 5B 35 40 FF A7 CB BF FF  C1 CC A2 FF C3 F5 AE FF  |[5@.............|
0x2820: FF FF FF FF C5 A0 BD FF  BA 9F C9 FF A0 D9 B3 FF  |................|
0x2830: C1 CC A2 FF FF FF FF FF  DE D2 5D FF A7 CB BF FF  |..........].....|
0x2840: C1 CC A2 FF FF FF FF FF  C1 CC A2 FF CB B4 B7 FF  |................|
0x2850: BA AE 39 FF A2 EA A7 FF  C1 CC A2 FF B6 DA CE FF  |..9.............|
0x2860: C1 CC A2 FF A0 D9 CE FF  B6 DA CE FF A7 CB BF FF  |................|
0x2870: B6 DA B3 FF A7 CB BF FF  FF FF FF FF FF FF FF FF  |................|
0x2880: 84 A7 E3 FF 5B 35 40 FF  BA 9F C9 FF 5B 35 40 FF  |....[5@.....[5@.|
0x2890: C1 CC A2 FF 41 8E B8 FF  98 6A 33 FF B6 DA B3 FF  |....A....j3.....|
0x28A0: A0 D9 B3 FF 5B 35 40 FF  B4 E2 EA FF 5B 35 40 FF  |....[5@.....[5@.|
0x28B0: F4 BB 83 FF A7 CB BF FF  C5 A0 BD FF BA 9F C9 FF  |................|
0x28C0: 1A 09 2F FF FF FF FF FF  C1 CC A2 FF A4 BE CA FF  |../.............|
0x28D0: 5B 35 40 FF A4 BE CA FF  C1 CC A2 FF A7 CB BF FF  |[5@.............|
0x28E0: FF FF FF FF AB 31 6C FF  C1 CC A2 FF 8C AE E9 FF  |.....1l.........|
0x28F0: BA 9F C9 FF 5B 35 40 FF  BA 9F C9 FF BA 9F C9 FF  |....[5@.........|
0x2900: CB BE 97 FF A7 CB BF FF  A4 6A 38 FF A7 CB BF FF  |.........j8.....|
0x2910: 5B 35 40 FF 5B 35 40 FF  96 A1 C8 FF 5B 35 40 FF  |[5@.[5@.....[5@.|
0x2920: A0 D9 CE FF 5B 35 40 FF  C1 CC A2 FF 5B 35 40 FF  |....[5@.....[5@.|
0x2930: 4C 9F F7 FF C5 A0 BD FF  FF FF FF FF C5 A0 BD FF  |L...............|
0x2940: C5 A0 BD FF 5B 35 40 FF  C1 CC A2 FF 5B 35 40 FF  |....[5@.....[5@.|
0x2950: C1 CC A2 FF BA 9F C9 FF  C5 A0 BD FF A7 CB BF FF  |................|
0x2960: A0 D9 B3 FF C5 B2 A6 FF  98 BC B0 FF A0 D9 B3 FF  |................|
0x2970: 7C B0 59 FF 5B 35 40 FF  C5 A0 BD FF A0 D9 CE FF  ||.Y.[5@.........|
0x2980: A0 D9 CE FF A4 BE CA FF  C1 CC A2 FF 4F 76 7E FF  |............Ov~.|
0x2990: B6 DA B3 FF FF FF FF FF  A8 B3 E6 FF B6 DA B3 FF  |................|
0x29A0: 4E 57 BA FF A4 BE CA FF  FF FF FF FF BA 9F C9 FF  |NW..............|
0x29B0: A4 CB C0 FF A3 EB EB FF  B0 BD CC FF BA 9F C9 FF  |................|
0x29C0: BA 9F C9 FF FF FF FF FF  5B 35 40 FF A4 BE CA FF  |........[5@.....|
0x29D0: BA 9F C9 FF C5 A0 BD FF  98 BC B0 FF FF FF FF FF  |................|
0x29E0: B0 D8 CC FF 5B 35 40 FF  8F C2 D0 FF A7 CB BF FF  |....[5@.........|
0x29F0: FF FF FF FF 98 BC B0 FF  C1 CC A2 FF CA D1 A9 FF  |................|
0x2A00: 5B 35 40 FF A2 F9 E9 FF  B5 FB 99 FF A7 CB BF FF  |[5@.............|
0x2A10: C1 CC A2 FF B8 3C 6C FF  5B 35 40 FF A7 CB BF FF  |.....<l.[5@.....|
0x2A20: C5 A0 BD FF FF FF FF FF  B6 DA CE FF B0 BD B1 FF  |................|
0x2A30: C1 CC A2 FF 5B 35 40 FF  5B 35 40 FF BA 9F C9 FF  |....[5@.[5@.....|
0x2A40: 88 9A 90 FF 5C C3 A2 FF  FF FF FF FF BA 9F C9 FF  |....\...........|
0x2A50: B7 CF C8 FF C5 A0 BD FF  C1 CC A2 FF C1 CC A2 FF  |................|
0x2A60: BA 9F C9 FF C1 CC A2 FF  3E 8A 61 FF C5 A0 BD FF  |........>.a.....|
0x2A70: 98 BC CC FF FF FF FF FF  B0 BD CC FF AA E9 B0 FF  |................|
0x2A80: 5B 35 40 FF A7 CB BF FF  BA 9F C9 FF A7 CB BF FF  |[5@.............|
0x2A90: A4 BE CA FF BA 9F C9 FF  BA 9F C9 FF A4 BE CA FF  |................|
0x2AA0: B4 5D 26 FF FF FF FF FF  BC 9D 62 FF A7 CB BF FF  |.]&.......b.....|
0x2AB0: C1 CC A2 FF B0 BD B1 FF  BA 9F C9 FF 5B 35 40 FF  |............[5@.|
0x2AC0: B6 DA B3 FF BA 9F C9 FF  C1 CC A2 FF CF 34 29 FF  |.............4).|
0x2AD0: C1 CC A2 FF A7 CB BF FF  C1 CC A2 FF BA 9F C9 FF  |................|
0x2AE0: BB A5 D1 FF B0 BD B1 FF  B0 BD B1 FF DD 76 35 FF  |.............v5.|
0x2AF0: 5B 35 40 FF A4 BE CA FF  C1 CC A2 FF 5B 35 40 FF  |[5@.........[5@.|
0x2B00: C7 D1 A4 FF BA 9F C9 FF  FF FF FF FF 5B 35 40 FF  |............[5@.|
0x2B10: 5B 35 40 FF FF FF FF FF  FF FF FF FF BC BA C1 FF  |[5@.............|
0x2B20: C1 CC A2 FF AD D2 9D FF  A4 BE CA FF C1 CC A2 FF  |................|
0x2B30: FF FF FF FF A5 D8 9B FF  C1 CC A2 FF A2 EB DF FF  |................|
0x2B40: FF FF FF FF A4 BE CA FF  5B 35 40 FF 96 BC 9B FF  |........[5@.....|
0x2B50: FF FF FF FF C5 A0 BD FF  B5 BF D7 FF FF FF FF FF  |................|
0x2B60: A4 BE CA FF FF FF FF FF  8D DD CA FF A7 CB BF FF  |................|
0x2B70: 98 BC B0 FF 8E 60 E3 FF  9F D7 D7 FF BA 9F C9 FF  |.....`..........|
0x2B80: 7E 64 BA FF A4 BE CA FF  FF FF FF FF A7 CB BF FF  |~d..............|
0x2B90: C5 A0 BD FF A7 CB BF FF  C1 CC A2 FF 5B 35 40 FF  |............[5@.|
0x2BA0: C1 CC A2 FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x2BB0: FF FF FF FF C5 A0 BD FF  5B 35 40 FF B0 BD B1 FF  |........[5@.....|
0x2BC0: FF FF FF FF 5B 35 40 FF  C1 CC A2 FF A0 D9 B3 FF  |....[5@.........|
0x2BD0: C5 A0 BD FF 46 98 2B FF  C5 A0 BD FF 93 A0 CD FF  |....F.+.........|
0x2BE0: C5 A0 BD FF 40 5F E6 FF  39 4B 1F FF A7 CB BF FF  |....@_..9K......|
0x2BF0: C6 D0 C4 FF B6 DA CE FF  C1 CC A2 FF A7 CB BF FF  |................|
0x2C00: BF C2 D0 FF 5B 35 40 FF  AB D2 C9 FF 5E 6A C3 FF  |....[5@.....^j..|
0x2C10: BA 9F C9 FF BA 9F C9 FF  C1 CC A2 FF 3B 72 38 FF  |............;r8.|
0x2C20: DD 53 C0 FF A7 CB BF FF  FF FF FF FF BA 9F C9 FF  |.S..............|
0x2C30: 5B 35 40 FF A4 BE CA FF  C1 CC A2 FF FF FF FF FF  |[5@.............|
0x2C40: FF FF FF FF A7 CB BF FF  5B 35 40 FF F4 C8 6F FF  |........[5@...o.|
0x2C50: CF 6A C7 FF 8E AC B2 FF  A0 D9 B3 FF A7 CB BF FF  |.j..............|
0x2C60: A4 F8 C3 FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x2C70: 5B 35 40 FF 65 DB 7F FF  B6 DA B3 FF A8 9D CC FF  |[5@.e...........|
0x2C80: FF FF FF FF C5 A0 BD FF  C1 CC A2 FF FF FF FF FF  |................|
0x2C90: C1 CC A2 FF BA 9F C9 FF  C1 CC A2 FF 5B 35 40 FF  |............[5@.|
0x2CA0: FF FF FF FF A7 CB BF FF  5B 35 40 FF 5B 35 40 FF  |........[5@.[5@.|
0x2CB0: BA 9F C9 FF FF FF FF FF  B6 DA B3 FF FF FF FF FF  |................|
0x2CC0: FB E7 50 FF BA 9F C9 FF  86 A5 9C FF 9D ED D8 FF  |..P.............|
0x2CD0: C5 A0 BD FF FF FF FF FF  C1 CC A2 FF 6F 5C CA FF  |............o\..|
0x2CE0: FF FF FF FF FF FF FF FF  A4 BE CA FF 85 65 9F FF  |.............e..|
0x2CF0: 5E 45 8B FF C1 CC A2 FF  B0 BD CC FF A7 B2 DE FF  |^E..............|
0x2D00: 5C 87 88 FF 5B 35 40 FF  5B 35 40 FF 5B 35 40 FF  |\...[5@.[5@.[5@.|
0x2D10: C1 CC A2 FF B0 94 84 FF  C1 CC A2 FF BD 3D C9 FF  |.............=..|
0x2D20: BA 9F C9 FF FF FF FF FF  A7 E4 CC FF BA 9F C9 FF  |................|
0x2D30: 7D CC B5 FF 9D BD 88 FF  BA 9F C9 FF FF FF FF FF  |}...............|
0x2D40: 4C A2 B4 FF 98 BC CC FF  C1 CC A2 FF A4 BE CA FF  |L...............|
0x2D50: 98 BC CC FF B7 70 29 FF  B6 DA B3 FF FF FF FF FF  |.....p).........|
0x2D60: 5B 35 40 FF C5 A0 BD FF  C7 D9 87 FF 5B 35 40 FF  |[5@.........[5@.|
0x2D70: C1 CC A2 FF FF FF FF FF  FF FF FF FF A4 BE CA FF  |................|
0x2D80: A4 BE CA FF B0 BD CC FF  C1 CC A2 FF 5B 35 40 FF  |............[5@.|
0x2D90: A0 D9 CE FF A7 CB BF FF  A4 BE CA FF B0 BD B1 FF  |................|
0x2DA0: 98 BC B0 FF BA 9F C9 FF  A0 D9 B3 FF BA 9F C9 FF  |................|
0x2DB0: 93 5A CE FF BF A5 B7 FF  BA AF B9 FF F7 DB 4A FF  |.Z............J.|
0x2DC0: A3 DB E4 FF 5B 35 40 FF  DF C3 C9 FF 17 05 58 FF  |....[5@.......X.|
0x2DD0: C1 CC A2 FF C1 CC A2 FF  C5 A0 BD FF 4E 18 94 FF  |............N...|
0x2DE0: 5B 35 40 FF FF FF FF FF  C1 CC A2 FF A7 CB BF FF  |[5@.............|
0x2DF0: A0 D9 B3 FF A4 BE CA FF  FF FF FF FF A7 CB BF FF  |................|
0x2E00: C5 A0 BD FF 5B 35 40 FF  D9 FD CC FF 5B 35 40 FF  |....[5@.....[5@.|
0x2E10: FF FF FF FF BA 9F C9 FF  C1 CC A2 FF 95 D3 99 FF  |................|
0x2E20: C1 CC A2 FF 5B 35 40 FF  98 BC B0 FF BA 9F C9 FF  |....[5@.........|
0x2E30: 5B 35 40 FF 79 6E CE FF  C1 CC A2 FF A7 CB BF FF  |[5@.yn..........|
0x2E40: A4 BE CA FF A7 CB BF FF  C1 CC A2 FF A0 D9 B3 FF  |................|
0x2E50: 56 AD 8C FF BA 9F C9 FF  C5 A0 BD FF 98 BC CC FF  |V...............|
0x2E60: FF FF FF FF BA 9F C9 FF  C1 CC A2 FF 5B 35 40 FF  |............[5@.|
0x2E70: 5B 35 40 FF C5 BE 40 FF  A0 D9 CE FF 5B 35 40 FF  |[5@...@.....[5@.|
0x2E80: 98 BC B0 FF A7 CB BF FF  FF FF FF FF A7 CB BF FF  |................|
0x2E90: 5B 35 40 FF B0 BD CC FF  7E 1F 93 FF BA 9F C9 FF  |[5@.....~.......|
0x2EA0: C1 CC A2 FF A0 D9 CE FF  C1 CC A2 FF FF FF FF FF  |................|
0x2EB0: 99 BC E1 FF C5 A0 BD FF  8C A8 C1 FF 5B 35 40 FF  |............[5@.|
0x2EC0: 67 BA 5B FF FF FF FF FF  FF FF FF FF A7 CB BF FF  |g.[.............|
0x2ED0: 99 CC 96 FF 5B 35 40 FF  C1 CC A2 FF FF FF FF FF  |....[5@.........|
0x2EE0: 5B 35 40 FF A7 CB BF FF  C5 A0 BD FF 80 69 70 FF  |[5@..........ip.|
0x2EF0: 33 46 22 FF 41 41 41 FF  BE BE BE FF 41 41 41 FF  |3F".AAA.....AAA.|
0x2F00: 50 50 36 FF 00 00 00 FF  32 32 4E FF BE BE BE FF  |PP6.....22N.....|
0x2F10: 41 41 41 FF 45 60 33 FF  41 41 41 FF BE BE BE FF  |AAA.E`3.AAA.....|
0x2F20: 00 00 00 FF BE BE BE FF  41 41 41 FF 41 41 41 FF  |........AAA.AAA.|
0x2F30: 41 41 41 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |AAA.AAA.AAA.AAA.|
0x2F40: 41 41 41 FF 00 00 00 FF  41 41 41 FF 41 41 41 FF  |AAA.....AAA.AAA.|
0x2F50: BE BE BE FF 00 00 00 FF  BE BE BE FF EA 38 C4 FF  |.............8..|
0x2F60: C6 96 9B FF 7C A9 B5 FF  00 00 00 FF 4C 33 33 FF  |....|.......L33.|
0x2F70: 41 41 41 FF 5C 33 44 FF  4C 33 33 FF BE BE BE FF  |AAA.\3D.L33.....|
0x2F80: 50 50 36 FF BE BE BE FF  BE BE BE FF 40 21 2E FF  |PP6.........@!..|
0x2F90: 41 41 41 FF 41 41 41 FF  1A 34 17 FF B0 6B 3C FF  |AAA.AAA..4...k<.|
0x2FA0: BE BE BE FF 41 41 41 FF  74 AE EA FF BE BE BE FF  |....AAA.t.......|
0x2FB0: 75 6B A7 FF 75 DF 5A FF  41 41 41 FF 00 00 00 FF  |uk..u.Z.AAA.....|
0x2FC0: 41 41 41 FF 50 50 36 FF  00 00 00 FF 78 26 6C FF  |AAA.PP6.....x&l.|
0x2FD0: 00 00 00 FF 35 6C BB FF  BE BE BE FF CA A5 DA FF  |....5l..........|
0x2FE0: 84 24 1F FF 41 41 41 FF  32 32 32 FF 00 00 00 FF  |.$..AAA.222.....|
0x2FF0: 8E F3 73 FF 41 41 41 FF  53 74 30 FF 00 00 00 FF  |..s.AAA.St0.....|
0x3000: 41 41 41 FF BE BE BE FF  57 5D 27 FF 00 00 00 FF  |AAA.....W]'.....|
0x3010: 41 41 41 FF 41 2B 14 FF  41 41 41 FF 41 41 41 FF  |AAA.A+..AAA.AAA.|
0x3020: 62 5F 4C FF 39 4F 35 FF  33 1E 79 FF 0E 02 16 FF  |b_L.9O5.3.y.....|
0x3030: 00 00 00 FF 41 41 41 FF  41 41 41 FF BE BE BE FF  |....AAA.AAA.....|
0x3040: EC FB 72 FF 00 00 00 FF  41 41 41 FF 00 00 00 FF  |..r.....AAA.....|
0x3050: BE BE BE FF 32 32 32 FF  9B 62 32 FF BE BE BE FF  |....222..b2.....|
0x3060: 4C 33 4E FF 2E 40 21 FF  41 41 41 FF 00 00 00 FF  |L3N..@!.AAA.....|
0x3070: BE BE BE FF 00 00 00 FF  00 00 00 FF 50 4E 1C FF  |............PN..|
0x3080: 4C 33 4E FF 5A 56 AB FF  35 4B 3D FF 23 15 46 FF  |L3N.ZV..5K=.#.F.|
0x3090: 41 41 41 FF 41 41 41 FF  62 33 4F FF 41 41 41 FF  |AAA.AAA.b3O.AAA.|
0x30A0: BE BE BE FF 41 41 41 FF  50 50 50 FF 3F 3A 2F FF  |....AAA.PPP.?:/.|
0x30B0: BE BE BE FF 32 1E 45 FF  41 41 41 FF 41 41 41 FF  |....2.E.AAA.AAA.|
0x30C0: 41 41 41 FF 25 17 2E FF  BE BE BE FF 20 3A 58 FF  |AAA.%....... :X.|
0x30D0: C0 7E 5F FF 41 41 41 FF  00 00 00 FF 20 1F C5 FF  |.~_.AAA..... ...|
0x30E0: 4C 33 33 FF 41 41 41 FF  50 50 36 FF DA 74 DE FF  |L33.AAA.PP6..t..|
0x30F0: 37 5E 4D FF 9A F1 54 FF  47 22 18 FF 23 50 1A FF  |7^M...T.G"..#P..|
0x3100: BE BE BE FF E8 5F 98 FF  00 00 00 FF 00 00 00 FF  |....._..........|
0x3110: 41 41 41 FF 60 BF 4B FF  BE BE BE FF 00 00 00 FF  |AAA.`.K.........|
0x3120: DC E6 EB FF 41 41 41 FF  50 50 36 FF 41 41 41 FF  |....AAA.PP6.AAA.|
0x3130: 56 57 F2 FF BE BE BE FF  39 4F 50 FF 41 41 41 FF  |VW......9OP.AAA.|
0x3140: 00 00 00 FF BE BE BE FF  BE BE BE FF 5C 4B 27 FF  |............\K'.|
0x3150: 37 49 23 FF 41 41 41 FF  14 19 23 FF 32 32 32 FF  |7I#.AAA...#.222.|
0x3160: 41 41 41 FF 41 41 41 FF  BF 79 AE FF 2E 1F 67 FF  |AAA.AAA..y....g.|
0x3170: 67 72 55 FF 41 41 41 FF  36 77 AF FF 1D 3B 1C FF  |grU.AAA.6w...;..|
0x3180: 41 41 41 FF 00 00 00 FF  41 41 41 FF 00 00 00 FF  |AAA.....AAA.....|
0x3190: 41 41 41 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |AAA.AAA.AAA.AAA.|
0x31A0: 00 00 00 FF 32 32 4E FF  41 41 41 FF 12 17 14 FF  |....22N.AAA.....|
0x31B0: 00 00 00 FF 4C 33 33 FF  4C 33 33 FF BE BE BE FF  |....L33.L33.....|
0x31C0: 00 00 00 FF 41 41 41 FF  41 41 41 FF BE BE BE FF  |....AAA.AAA.....|
0x31D0: 00 00 00 FF 32 32 4E FF  41 41 41 FF 34 69 60 FF  |....22N.AAA.4i`.|
0x31E0: BE BE BE FF 41 41 41 FF  41 41 41 FF BE BE BE FF  |....AAA.AAA.....|
0x31F0: E7 95 44 FF 39 4F 35 FF  4C 33 4E FF 39 4F 50 FF  |..D.9O5.L3N.9OP.|
0x3200: 50 50 50 FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |PPP.AAA.....AAA.|
0x3210: 41 41 41 FF B8 FC B2 FF  43 37 6B FF 6B 5B 29 FF  |AAA.....C7k.k[).|
0x3220: 00 00 00 FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |....AAA.....AAA.|
0x3230: 50 50 36 FF 41 41 41 FF  32 32 4E FF 41 41 41 FF  |PP6.AAA.22N.AAA.|
0x3240: 65 67 D0 FF 35 24 19 FF  CE D3 48 FF BE BE BE FF  |eg..5$....H.....|
0x3250: 41 41 41 FF 7D EC 96 FF  41 41 41 FF 41 41 41 FF  |AAA.}...AAA.AAA.|
0x3260: 32 32 4E FF 5A 73 74 FF  46 92 2E FF 41 41 41 FF  |22N.Zst.F...AAA.|
0x3270: E6 FE F8 FF 00 00 00 FF  41 41 41 FF 50 50 50 FF  |........AAA.PPP.|
0x3280: 41 41 41 FF 00 00 00 FF  43 1B 6B FF 60 BA A2 FF  |AAA.....C.k.`...|
0x3290: 39 4F 35 FF 41 41 41 FF  41 41 41 FF 3F 4D 21 FF  |9O5.AAA.AAA.?M!.|
0x32A0: 00 00 00 FF 00 00 00 FF  39 4F 50 FF 3E 29 36 FF  |........9OP.>)6.|
0x32B0: 5F 4D 21 FF 00 00 00 FF  41 41 41 FF 28 4F 47 FF  |_M!.....AAA.(OG.|
0x32C0: 41 41 41 FF 41 41 41 FF  BE BE BE FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x32D0: 32 32 4E FF 41 41 41 FF  5C 1F 3C FF 41 41 41 FF  |22N.AAA.\.<.AAA.|
0x32E0: 41 41 41 FF 00 00 00 FF  41 41 41 FF 00 00 00 FF  |AAA.....AAA.....|
0x32F0: 41 41 41 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |AAA.AAA.AAA.AAA.|
0x3300: 41 41 41 FF 12 23 EE FF  30 2B 45 FF 50 50 36 FF  |AAA..#..0+E.PP6.|
0x3310: 39 4F 35 FF 41 41 41 FF  BE BE BE FF 41 41 41 FF  |9O5.AAA.....AAA.|
0x3320: 00 00 00 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |....AAA.AAA.AAA.|
0x3330: 56 27 39 FF 41 41 41 FF  41 41 41 FF 00 00 00 FF  |V'9.AAA.AAA.....|
0x3340: 41 41 41 FF 00 00 00 FF  BE BE BE FF 00 00 00 FF  |AAA.............|
0x3350: 2C 48 1B FF 41 41 41 FF  41 41 41 FF 32 32 4E FF  |,H..AAA.AAA.22N.|
0x3360: 48 62 60 FF 45 25 2A FF  32 32 4E FF 41 41 41 FF  |Hb`.E%*.22N.AAA.|
0x3370: 4C 33 4E FF 41 41 41 FF  5D 72 4F FF B4 E4 FA FF  |L3N.AAA.]rO.....|
0x3380: 41 41 41 FF 65 4D 5D FF  2C 60 B2 FF 26 4B 57 FF  |AAA.eM].,`..&KW.|
0x3390: 1F 28 AB FF 41 41 41 FF  00 00 00 FF A2 4B 24 FF  |.(..AAA......K$.|
0x33A0: 41 41 41 FF 00 00 00 FF  41 41 41 FF 41 41 41 FF  |AAA.....AAA.AAA.|
0x33B0: DF 37 E9 FF BE BE BE FF  41 41 41 FF 00 00 00 FF  |.7......AAA.....|
0x33C0: 41 41 41 FF 41 41 41 FF  4C 33 4E FF 00 00 00 FF  |AAA.AAA.L3N.....|
0x33D0: 5F 48 2D FF 41 41 41 FF  BE BE BE FF 39 4F 50 FF  |_H-.AAA.....9OP.|
0x33E0: 41 41 41 FF 00 00 00 FF  BE BE BE FF 00 00 00 FF  |AAA.............|
0x33F0: 00 00 00 FF 41 41 41 FF  1D 1B 5E FF 3D 88 B7 FF  |....AAA...^.=...|
0x3400: 00 00 00 FF 41 41 41 FF  41 41 41 FF 54 52 6A FF  |....AAA.AAA.TRj.|
0x3410: 41 41 41 FF 41 41 41 FF  50 50 36 FF BE BE BE FF  |AAA.AAA.PP6.....|
0x3420: 50 50 50 FF 50 50 50 FF  39 4F 35 FF 42 41 42 FF  |PPP.PPP.9O5.BAB.|
0x3430: BF BC BC FF 41 43 43 FF  42 40 43 FF 29 0A 9B FF  |....ACC.B@C.)...|
0x3440: 42 40 43 FF 61 B8 B4 FF  43 43 40 FF 00 00 00 FF  |B@C.a...CC@.....|
0x3450: 42 40 43 FF 50 52 37 FF  D0 3D 67 FF 00 00 00 FF  |B@C.PR7..=g.....|
0x3460: 43 43 40 FF 42 40 43 FF  42 40 43 FF 41 43 43 FF  |CC@.B@C.B@C.ACC.|
0x3470: 32 34 34 FF BF BC BC FF  43 43 40 FF 32 34 50 FF  |244.....CC@.24P.|
0x3480: 46 33 3E FF 54 5B 69 FF  3D 22 F3 FF 41 43 43 FF  |F3>.T[i.="..ACC.|
0x3490: 42 40 43 FF 37 06 4F FF  00 00 00 FF 00 00 00 FF  |B@C.7.O.........|
0x34A0: 4B 35 50 FF 42 40 43 FF  42 40 43 FF 4B 35 50 FF  |K5P.B@C.B@C.K5P.|
0x34B0: 42 40 43 FF 00 00 00 FF  38 6C 51 FF BF BC BC FF  |B@C.....8lQ.....|
0x34C0: 00 00 00 FF 1D 1E 52 FF  4B 35 35 FF 42 40 43 FF  |......R.K55.B@C.|
0x34D0: 42 40 43 FF 00 00 00 FF  32 34 34 FF 00 00 00 FF  |B@C.....244.....|
0x34E0: BF BC BC FF 42 40 43 FF  41 43 43 FF 32 34 34 FF  |....B@C.ACC.244.|
0x34F0: 43 43 40 FF 41 43 43 FF  43 43 40 FF 43 43 40 FF  |CC@.ACC.CC@.CC@.|
0x3500: 4B 35 50 FF 69 55 3B FF  BF BC BC FF 47 66 6F FF  |K5P.iU;.....Gfo.|
0x3510: 42 40 43 FF 3E 87 47 FF  BF BC BC FF BF BC BC FF  |B@C.>.G.........|
0x3520: 37 58 22 FF 41 43 43 FF  42 40 43 FF BF BC BC FF  |7X".ACC.B@C.....|
0x3530: BF BC BC FF 43 43 40 FF  43 43 40 FF 00 00 00 FF  |....CC@.CC@.....|
0x3540: 42 40 43 FF 41 43 43 FF  59 2A 49 FF 39 57 4E FF  |B@C.ACC.Y*I.9WN.|
0x3550: 4F 6F 31 FF 6A 44 2E FF  50 50 50 FF 41 41 41 FF  |Oo1.jD..PPP.AAA.|
0x3560: 3D 62 57 FF 32 32 32 FF  4C 33 33 FF 41 41 41 FF  |=bW.222.L33.AAA.|
0x3570: 00 00 00 FF 39 4F 50 FF  52 39 56 FF 41 41 41 FF  |....9OP.R9V.AAA.|
0x3580: 00 00 00 FF 00 00 00 FF  41 41 41 FF 4C 33 4E FF  |........AAA.L3N.|
0x3590: 41 41 41 FF 41 41 41 FF  41 41 41 FF 32 32 32 FF  |AAA.AAA.AAA.222.|
0x35A0: 41 41 41 FF 41 41 41 FF  45 75 97 FF 00 00 00 FF  |AAA.AAA.Eu......|
0x35B0: 76 E2 A1 FF 32 32 32 FF  CD C9 42 FF 28 28 17 FF  |v...222...B.((..|
0x35C0: 41 41 41 FF 59 61 63 FF  41 41 41 FF 50 4D 40 FF  |AAA.Yac.AAA.PM@.|
0x35D0: 62 6E 5C FF 41 41 41 FF  41 41 41 FF 00 00 00 FF  |bn\.AAA.AAA.....|
0x35E0: 41 41 41 FF 41 41 41 FF  BE BE BE FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x35F0: 41 41 41 FF 32 32 4E FF  BE BE BE FF BE BE BE FF  |AAA.22N.........|
0x3600: 41 41 41 FF 00 00 00 FF  41 41 41 FF 39 4F 35 FF  |AAA.....AAA.9O5.|
0x3610: 00 00 00 FF 42 2D 5B FF  00 00 00 FF 4C 33 4E FF  |....B-[.....L3N.|
0x3620: 41 41 41 FF 3F 23 2E FF  41 41 41 FF 60 34 35 FF  |AAA.?#..AAA.`45.|
0x3630: 30 26 44 FF BE BE BE FF  2E 48 47 FF C4 90 78 FF  |0&D......HG...x.|
0x3640: 41 41 41 FF 00 00 00 FF  41 41 41 FF BE BE BE FF  |AAA.....AAA.....|
0x3650: BE BE BE FF 00 00 00 FF  41 41 41 FF BE BE BE FF  |........AAA.....|
0x3660: 41 41 41 FF 00 00 00 FF  BE BE BE FF 41 41 41 FF  |AAA.........AAA.|
0x3670: 41 41 41 FF 41 41 41 FF  BE BE BE FF 4C 4F 8E FF  |AAA.AAA.....LO..|
0x3680: 71 37 F2 FF BE BE BE FF  9B E4 95 FF 41 41 41 FF  |q7..........AAA.|
0x3690: 41 41 41 FF 41 41 41 FF  BE BE BE FF 39 4F 50 FF  |AAA.AAA.....9OP.|
0x36A0: 41 41 41 FF 32 32 4E FF  4C 33 33 FF BE BE BE FF  |AAA.22N.L33.....|
0x36B0: 41 41 41 FF 1E 2C 70 FF  1B 26 3D FF 41 41 41 FF  |AAA..,p..&=.AAA.|
0x36C0: BE BE BE FF BE BE BE FF  A6 D3 D2 FF 5C 40 19 FF  |............\@..|
0x36D0: 41 41 41 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |AAA.AAA.AAA.AAA.|
0x36E0: 41 41 41 FF 41 41 41 FF  41 41 41 FF 39 4F 35 FF  |AAA.AAA.AAA.9O5.|
0x36F0: 00 00 00 FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |....AAA.....AAA.|
0x3700: 39 4F 50 FF 47 22 23 FF  41 41 41 FF 39 4F 35 FF  |9OP.G"#.AAA.9O5.|
0x3710: 41 41 41 FF 36 58 5E FF  41 41 41 FF 41 41 41 FF  |AAA.6X^.AAA.AAA.|
0x3720: 41 41 41 FF 00 00 00 FF  41 41 41 FF 40 42 46 FF  |AAA.....AAA.@BF.|
0x3730: 57 BF 58 FF 7E CB 4C FF  A9 46 F6 FF 6C BF 39 FF  |W.X.~.L..F..l.9.|
0x3740: AD 29 C0 FF 1C 47 BB FF  95 42 78 FF 6C BF 39 FF  |.)...G...Bx.l.9.|
0x3750: 57 BF 58 FF 41 07 BA FF  75 FB 4C FF 57 BF 58 FF  |W.X.A...u.L.W.X.|
0x3760: 79 CE 41 FF 5C B4 39 FF  B4 50 1F FF 6E A8 91 FF  |y.A.\.9..P..n...|
0x3770: 1C 47 BB FF A9 46 F6 FF  75 FB 4C FF 1C 47 BB FF  |.G...F..u.L..G..|
0x3780: 6F B1 34 FF 6F B1 37 FF  57 BF 58 FF 75 FB 4C FF  |o.4.o.7.W.X.u.L.|
0x3790: 5B 8E 28 FF 75 FB 4C FF  75 FB 4C FF 75 FB 4C FF  |[.(.u.L.u.L.u.L.|
0x37A0: F0 BE 59 FF 57 BF 58 FF  56 BC 58 FF 32 32 4E FF  |..Y.W.X.V.X.22N.|
0x37B0: 6C 5D 27 FF BE BE BE FF  3A 68 40 FF 39 4F 50 FF  |l]'.....:h@.9OP.|
0x37C0: 00 00 00 FF 4B 31 4A FF  BE BE BE FF 49 50 2A FF  |....K1J.....IP*.|
0x37D0: 00 00 00 FF 50 50 50 FF  2C 14 58 FF 00 00 00 FF  |....PPP.,.X.....|
0x37E0: 41 41 41 FF 41 41 41 FF  BE BE BE FF 4C 33 33 FF  |AAA.AAA.....L33.|
0x37F0: 1F 3D 3B FF 41 41 41 FF  39 4F 35 FF BE BE BE FF  |.=;.AAA.9O5.....|
0x3800: 00 00 00 FF C1 89 88 FF  32 32 32 FF 4C 33 4E FF  |........222.L3N.|
0x3810: 41 41 41 FF 41 41 41 FF  41 41 41 FF 24 1D 2C FF  |AAA.AAA.AAA.$.,.|
0x3820: 41 41 41 FF 41 41 41 FF  36 4C 22 FF 41 41 41 FF  |AAA.AAA.6L".AAA.|
0x3830: 3F 06 68 FF 68 70 58 FF  00 00 00 FF 41 41 41 FF  |?.h.hpX.....AAA.|
0x3840: 4E 9D 8D FF 80 23 5D FF  41 41 41 FF 41 41 41 FF  |N....#].AAA.AAA.|
0x3850: 41 41 41 FF 65 23 9D FF  34 47 1F FF 42 40 46 FF  |AAA.e#..4G..B@F.|
0x3860: 38 50 3A FF 68 54 4C FF  00 00 00 FF 00 00 00 FF  |8P:.hTL.........|
0x3870: 41 72 5B FF 3D 5D 70 FF  67 3B 22 FF 58 68 89 FF  |Ar[.=]p.g;".Xh..|
0x3880: 00 00 00 FF BF BD B8 FF  46 40 42 FF 46 40 42 FF  |........F@B.F@B.|
0x3890: 46 42 40 FF 46 40 42 FF  00 00 00 FF 46 42 40 FF  |FB@.F@B.....FB@.|
0x38A0: 46 42 40 FF 41 47 42 FF  41 40 42 FF 4E 30 45 FF  |FB@.AGB.A@B.N0E.|
0x38B0: 4C 33 4E FF 41 41 41 FF  39 4F 50 FF 42 34 21 FF  |L3N.AAA.9OP.B4!.|
0x38C0: 00 00 00 FF A6 7D 2D FF  46 41 57 FF 41 41 41 FF  |.....}-.FAW.AAA.|
0x38D0: 39 4F 35 FF EA 41 4D FF  32 32 4E FF 41 41 41 FF  |9O5..AM.22N.AAA.|
0x38E0: 32 32 4E FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |22N.AAA.AAA.AAA.|
0x38F0: 86 A2 3C FF 00 00 00 FF  31 47 58 FF 64 57 6C FF  |..<.....1GX.dWl.|
0x3900: 00 00 00 FF 41 41 41 FF  5B 70 42 FF 00 00 00 FF  |....AAA.[pB.....|
0x3910: BE BE BE FF 6B 3D 45 FF  00 00 00 FF 4C 33 33 FF  |....k=E.....L33.|
0x3920: 00 00 00 FF 41 41 41 FF  54 73 DD FF 70 72 6F FF  |....AAA.Ts..pro.|
0x3930: 70 94 E0 FF 41 41 41 FF  00 00 00 FF BE BE BE FF  |p...AAA.........|
0x3940: 50 50 36 FF 4C 33 33 FF  BE BE BE FF 00 00 00 FF  |PP6.L33.........|
0x3950: 00 00 00 FF 65 29 4E FF  BE BE BE FF 4E 6C 32 FF  |....e)N.....Nl2.|
0x3960: 00 00 00 FF 00 00 00 FF  00 00 00 FF BE BE BE FF  |................|
0x3970: 60 3C 4A FF 00 00 00 FF  BE BE BE FF 6A DB 65 FF  |`<J.........j.e.|
0x3980: 41 41 41 FF 41 41 41 FF  41 41 41 FF 68 53 69 FF  |AAA.AAA.AAA.hSi.|
0x3990: A0 B8 F7 FF 1B 30 58 FF  41 41 41 FF 32 32 4E FF  |.....0X.AAA.22N.|
0x39A0: BE BE BE FF 41 41 41 FF  41 41 41 FF 00 00 00 FF  |....AAA.AAA.....|
0x39B0: 41 41 41 FF 41 41 41 FF  BE BE BE FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x39C0: 00 00 00 FF BE BE BE FF  41 41 41 FF 41 41 41 FF  |........AAA.AAA.|
0x39D0: BE BE BE FF E1 4E 7F FF  4C 33 4E FF 41 41 41 FF  |.....N..L3N.AAA.|
0x39E0: 00 00 00 FF 4C 33 33 FF  5B C5 6F FF BE BE BE FF  |....L33.[.o.....|
0x39F0: 41 41 41 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |AAA.AAA.AAA.AAA.|
0x3A00: 41 41 41 FF BE BE BE FF  41 41 41 FF 5F 3A 47 FF  |AAA.....AAA._:G.|
0x3A10: 41 41 41 FF 41 41 41 FF  41 41 41 FF 50 50 50 FF  |AAA.AAA.AAA.PPP.|
0x3A20: 8D 50 6F FF BE BE BE FF  41 41 41 FF BE BE BE FF  |.Po.....AAA.....|
0x3A30: 50 50 36 FF 00 00 00 FF  41 41 41 FF 9B BD 81 FF  |PP6.....AAA.....|
0x3A40: 30 2D 58 FF BE BE BE FF  43 55 2D FF E9 69 C9 FF  |0-X.....CU-..i..|
0x3A50: 41 41 41 FF 41 41 41 FF  41 41 41 FF 4C 33 4E FF  |AAA.AAA.AAA.L3N.|
0x3A60: 41 41 41 FF 4C 33 4E FF  32 32 4E FF 00 00 00 FF  |AAA.L3N.22N.....|
0x3A70: 30 59 4A FF 22 40 43 FF  39 4F 35 FF 00 00 00 FF  |0YJ."@C.9O5.....|
0x3A80: 39 4F 50 FF 00 00 00 FF  BE BE BE FF 00 00 00 FF  |9OP.............|
0x3A90: 00 00 00 FF 41 41 41 FF  39 4F 50 FF 41 41 41 FF  |....AAA.9OP.AAA.|
0x3AA0: CD FA DB FF 00 00 00 FF  41 41 41 FF BE BE BE FF  |........AAA.....|
0x3AB0: 68 64 45 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |hdE.AAA.AAA.AAA.|
0x3AC0: BE BE BE FF 00 00 00 FF  BE BE BE FF BE BE BE FF  |................|
0x3AD0: 33 47 54 FF 59 21 6C FF  41 41 41 FF 50 50 50 FF  |3GT.Y!l.AAA.PPP.|
0x3AE0: 00 00 00 FF 41 41 41 FF  4C 33 33 FF 41 41 41 FF  |....AAA.L33.AAA.|
0x3AF0: 41 41 41 FF 8F 61 EB FF  00 00 00 FF 00 00 00 FF  |AAA..a..........|
0x3B00: B9 7E 39 FF 41 41 41 FF  32 32 32 FF BE BE BE FF  |.~9.AAA.222.....|
0x3B10: 41 41 41 FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x3B20: 41 41 41 FF 00 00 00 FF  24 31 63 FF 4C 33 33 FF  |AAA.....$1c.L33.|
0x3B30: 41 41 41 FF 41 41 41 FF  41 43 1E FF BE BE BE FF  |AAA.AAA.AC......|
0x3B40: A8 22 50 FF 41 41 41 FF  80 9B CB FF 2D 25 16 FF  |."P.AAA.....-%..|
0x3B50: 27 42 3D FF 41 41 41 FF  A7 8D 31 FF 4A 5B DA FF  |'B=.AAA...1.J[..|
0x3B60: 99 D3 60 FF 41 41 41 FF  59 71 5D FF 41 41 41 FF  |..`.AAA.Yq].AAA.|
0x3B70: 39 4F 50 FF 94 C6 8A FF  00 00 00 FF 00 00 00 FF  |9OP.............|
0x3B80: 4C 33 33 FF BE BE BE FF  8F 39 E2 FF 00 00 00 FF  |L33......9......|
0x3B90: 50 50 36 FF B3 30 67 FF  41 41 41 FF 41 41 41 FF  |PP6..0g.AAA.AAA.|
0x3BA0: 41 41 41 FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x3BB0: 87 B8 AB FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |....AAA.....AAA.|
0x3BC0: 4C 33 4E FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |L3N.AAA.AAA.AAA.|
0x3BD0: 41 41 41 FF 22 40 35 FF  41 41 41 FF 50 50 50 FF  |AAA."@5.AAA.PPP.|
0x3BE0: 96 C6 95 FF 39 4F 50 FF  41 41 41 FF 41 41 41 FF  |....9OP.AAA.AAA.|
0x3BF0: 41 41 41 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |AAA.AAA.AAA.AAA.|
0x3C00: 77 28 24 FF 52 3D 1C FF  50 50 36 FF 41 41 41 FF  |w($.R=..PP6.AAA.|
0x3C10: 00 00 00 FF 41 41 41 FF  41 41 41 FF 50 50 50 FF  |....AAA.AAA.PPP.|
0x3C20: 50 50 36 FF 41 41 41 FF  00 00 00 FF 00 00 00 FF  |PP6.AAA.........|
0x3C30: 62 55 45 FF 32 32 32 FF  41 41 41 FF 50 50 50 FF  |bUE.222.AAA.PPP.|
0x3C40: 00 00 00 FF 41 41 41 FF  41 41 41 FF 32 32 32 FF  |....AAA.AAA.222.|
0x3C50: BE BE BE FF 93 35 94 FF  41 41 41 FF CE CC 92 FF  |.....5..AAA.....|
0x3C60: 21 42 69 FF C4 34 70 FF  41 41 41 FF BE BE BE FF  |!Bi..4p.AAA.....|
0x3C70: 41 41 41 FF 41 41 41 FF  39 4F 50 FF 87 92 57 FF  |AAA.AAA.9OP...W.|
0x3C80: 41 41 41 FF 41 41 41 FF  00 00 00 FF 41 41 41 FF  |AAA.AAA.....AAA.|
0x3C90: 8E 41 20 FF 41 41 41 FF  50 50 50 FF 20 2E 1C FF  |.A .AAA.PPP. ...|
0x3CA0: 17 09 72 FF 41 41 41 FF  4C 33 4E FF 41 41 41 FF  |..r.AAA.L3N.AAA.|
0x3CB0: 4E 54 3D FF 4C 33 4E FF  41 41 41 FF 25 13 48 FF  |NT=.L3N.AAA.%.H.|
0x3CC0: 41 41 41 FF 41 41 41 FF  32 32 4E FF 39 4F 50 FF  |AAA.AAA.22N.9OP.|
0x3CD0: 5A 50 38 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |ZP8.AAA.AAA.AAA.|
0x3CE0: BE BE BE FF 9B 89 3C FF  41 41 41 FF 49 6F 6E FF  |......<.AAA.Ion.|
0x3CF0: 6E 60 A7 FF 41 41 41 FF  BE BE BE FF 4C 3F 1F FF  |n`..AAA.....L?..|
0x3D00: BE BE BE FF 39 4F 35 FF  2A 55 99 FF 50 50 36 FF  |....9O5.*U..PP6.|
0x3D10: 41 41 41 FF 41 41 41 FF  BE BE BE FF 97 43 4D FF  |AAA.AAA......CM.|
0x3D20: 00 00 00 FF 41 41 41 FF  25 1A 42 FF 41 41 41 FF  |....AAA.%.B.AAA.|
0x3D30: 4C 33 33 FF 41 41 41 FF  41 41 41 FF 50 50 36 FF  |L33.AAA.AAA.PP6.|
0x3D40: 00 00 00 FF 00 00 00 FF  5C 11 E5 FF 50 50 50 FF  |........\...PPP.|
0x3D50: 00 00 00 FF 2E 0E 40 FF  41 41 41 FF 00 00 00 FF  |......@.AAA.....|
0x3D60: BE BE BE FF BE BE BE FF  BE BE BE FF 41 41 41 FF  |............AAA.|
0x3D70: 41 41 41 FF 5D 14 D1 FF  41 41 41 FF 41 41 41 FF  |AAA.]...AAA.AAA.|
0x3D80: AF C1 3D FF 41 41 41 FF  41 41 41 FF 43 42 42 FF  |..=.AAA.AAA.CBB.|
0x3D90: 42 43 44 FF 44 43 42 FF  44 43 42 FF 00 00 00 FF  |BCD.DCB.DCB.....|
0x3DA0: 44 43 42 FF 7B A8 F6 FF  57 75 4B FF 44 43 42 FF  |DCB.{...WuK.DCB.|
0x3DB0: BC BD BB FF BB 66 B0 FF  44 43 42 FF 43 42 44 FF  |.....f..DCB.CBD.|
0x3DC0: 44 43 42 FF 3A 50 52 FF  44 42 43 FF 44 43 42 FF  |DCB.:PR.DBC.DCB.|
0x3DD0: 45 2C 58 FF 00 00 00 FF  44 42 43 FF BC BD BB FF  |E,X.....DBC.....|
0x3DE0: BC BD BB FF 42 43 44 FF  43 44 42 FF 43 42 44 FF  |....BCD.CDB.CBD.|
0x3DF0: 44 42 43 FF 44 43 42 FF  00 00 00 FF 34 33 35 FF  |DBC.DCB.....435.|
0x3E00: 44 43 42 FF 00 00 00 FF  44 43 42 FF 24 1E 32 FF  |DCB.....DCB.$.2.|
0x3E10: 00 00 00 FF 43 42 44 FF  A9 48 61 FF 71 6C BA FF  |....CBD..Ha.ql..|
0x3E20: 43 44 42 FF 48 6D 32 FF  BC BD BB FF 44 43 42 FF  |CDB.Hm2.....DCB.|
0x3E30: 34 3A 3A FF 34 26 3F FF  44 42 43 FF 24 48 50 FF  |4::.4&?.DBC.$HP.|
0x3E40: 00 00 00 FF 00 00 00 FF  BC BD BB FF BC BD BB FF  |................|
0x3E50: 44 42 43 FF 00 00 00 FF  44 43 42 FF 43 42 44 FF  |DBC.....DCB.CBD.|
0x3E60: 44 43 42 FF 00 00 00 FF  00 00 00 FF 43 42 44 FF  |DCB.........CBD.|
0x3E70: 44 42 43 FF 44 43 42 FF  43 44 42 FF 44 42 43 FF  |DBC.DCB.CDB.DBC.|
0x3E80: 23 2E 40 FF BC BD BB FF  42 41 41 FF BE BE BE FF  |#.@.....BAA.....|
0x3E90: 41 41 41 FF 42 29 2E FF  41 41 41 FF 41 41 41 FF  |AAA.B)..AAA.AAA.|
0x3EA0: 60 8F 6A FF 50 50 36 FF  BE BE BE FF 39 4F 50 FF  |`.j.PP6.....9OP.|
0x3EB0: 00 00 00 FF 50 50 50 FF  50 50 36 FF 64 39 3C FF  |....PPP.PP6.d9<.|
0x3EC0: 41 41 41 FF BE BE BE FF  3F 5B 49 FF 41 41 41 FF  |AAA.....?[I.AAA.|
0x3ED0: 41 41 41 FF E5 32 AE FF  41 41 41 FF F4 D5 B4 FF  |AAA..2..AAA.....|
0x3EE0: 7B 9E D2 FF 39 4F 50 FF  5F 5E 22 FF 58 BA 37 FF  |{...9OP._^".X.7.|
0x3EF0: 41 41 41 FF 41 41 41 FF  00 00 00 FF BE BE BE FF  |AAA.AAA.........|
0x3F00: A7 E2 4C FF 41 41 41 FF  41 41 41 FF BE BE BE FF  |..L.AAA.AAA.....|
0x3F10: BE BE BE FF 41 41 41 FF  41 41 41 FF DA 4A 48 FF  |....AAA.AAA..JH.|
0x3F20: BE BE BE FF 41 41 41 FF  CE 43 22 FF 21 30 18 FF  |....AAA..C".!0..|
0x3F30: 2A 26 4D FF 00 00 00 FF  41 41 41 FF 32 32 32 FF  |*&M.....AAA.222.|
0x3F40: 35 67 5A FF 41 41 41 FF  41 41 41 FF 4C 2E 33 FF  |5gZ.AAA.AAA.L.3.|
0x3F50: 00 00 00 FF 41 41 41 FF  00 00 00 FF 39 4F 50 FF  |....AAA.....9OP.|
0x3F60: 4C 33 4E FF 41 41 41 FF  41 41 41 FF 33 2B 84 FF  |L3N.AAA.AAA.3+..|
0x3F70: 41 41 41 FF 41 41 41 FF  41 41 41 FF 41 41 41 FF  |AAA.AAA.AAA.AAA.|
0x3F80: 41 41 41 FF 41 41 41 FF  6C 4E 6A FF 41 41 41 FF  |AAA.AAA.lNj.AAA.|
0x3F90: BE BE BE FF 6B 68 64 FF  E2 9A D1 FF E4 37 B6 FF  |....khd......7..|
0x3FA0: BE BE BE FF 00 00 00 FF  41 41 41 FF 81 CA 43 FF  |........AAA...C.|
0x3FB0: 41 41 41 FF 41 41 41 FF  33 3B B2 FF 7E 1B 45 FF  |AAA.AAA.3;..~.E.|
0x3FC0: 57 29 74 FF 50 50 36 FF  41 41 41 FF 3A 17 40 FF  |W)t.PP6.AAA.:.@.|
0x3FD0: 65 5B 24 FF 00 00 00 FF  00 00 00 FF 47 46 42 FF  |e[$.........GFB.|
0x3FE0: 50 50 36 FF 00 00 00 FF  39 4F 50 FF 41 41 41 FF  |PP6.....9OP.AAA.|
0x3FF0: 32 32 32 FF BE BE BE FF  41 41 41 FF BE BE BE FF  |222.....AAA.....|
0x4000: 41 41 41 FF 41 41 41 FF  00 10 01 00 00 03 00 00  |AAA.AAA.........|
0x4010: 00 01 10 00 00 00 01 01  00 03 00 00 00 01 00 01  |................|
0x4020: 00 00 01 02 00 03 00 00  00 04 00 00 40 CE 01 03  |............@...|
0x4030: 00 03 00 00 00 01 00 01  00 00 01 06 00 03 00 00  |................|
0x4040: 00 01 00 02 00 00 01 0A  00 03 00 00 00 01 00 01  |................|
0x4050: 00 00 01 11 00 04 00 00  00 01 00 00 00 08 01 12  |................|
0x4060: 00 03 00 00 00 01 00 01  00 00 01 15 00 03 00 00  |................|
0x4070: 00 01 00 04 00 00 01 16  00 03 00 00 00 01 00 01  |................|
0x4080: 00 00 01 17 00 04 00 00  00 01 00 00 40 00 01 1C  |............@...|
0x4090: 00 03 00 00 00 01 00 01  00 00 01 28 00 03 00 00  |...........(....|
0x40A0: 00 01 00 02 00 00 01 52  00 03 00 00 00 01 00 01  |.......R........|
0x40B0: 00 00 01 53 00 03 00 00  00 04 00 00 40 D6 87 73  |...S........@..s|
0x40C0: 00 07 00 00 02 18 00 00  40 DE 00 00 00 00 00 08  |........@.......|
0x40D0: 00 08 00 08 00 08 00 01  00 01 00 01 00 01 00 00  |................|
0x40E0: 02 18 61 70 70 6C 04 00  00 00 6D 6E 74 72 52 47  |..appl....mntrRG|
0x40F0: 42 20 58 59 5A 20 07 E6  00 01 00 01 00 00 00 00  |B XYZ ..........|
0x4100: 00 00 61 63 73 70 41 50  50 4C 00 00 00 00 41 50  |..acspAPPL....AP|
0x4110: 50 4C 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |PL..............|
0x4120: 00 00 00 00 F6 D6 00 01  00 00 00 00 D3 2D 61 70  |.............-ap|
0x4130: 70 6C 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |pl..............|
0x4140: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4150: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4160: 00 0A 64 65 73 63 00 00  00 FC 00 00 00 30 63 70  |..desc.......0cp|
0x4170: 72 74 00 00 01 2C 00 00  00 50 77 74 70 74 00 00  |rt...,...Pwtpt..|
0x4180: 01 7C 00 00 00 14 72 58  59 5A 00 00 01 90 00 00  |.|....rXYZ......|
0x4190: 00 14 67 58 59 5A 00 00  01 A4 00 00 00 14 62 58  |..gXYZ........bX|
0x41A0: 59 5A 00 00 01 B8 00 00  00 14 72 54 52 43 00 00  |YZ........rTRC..|
0x41B0: 01 CC 00 00 00 20 63 68  61 64 00 00 01 EC 00 00  |..... chad......|
0x41C0: 00 2C 62 54 52 43 00 00  01 CC 00 00 00 20 67 54  |.,bTRC....... gT|
0x41D0: 52 43 00 00 01 CC 00 00  00 20 6D 6C 75 63 00 00  |RC....... mluc..|
0x41E0: 00 00 00 00 00 01 00 00  00 0C 65 6E 55 53 00 00  |..........enUS..|
0x41F0: 00 14 00 00 00 1C 00 44  00 69 00 73 00 70 00 6C  |.......D.i.s.p.l|
0x4200: 00 61 00 79 00 20 00 50  00 33 6D 6C 75 63 00 00  |.a.y. .P.3mluc..|
0x4210: 00 00 00 00 00 01 00 00  00 0C 65 6E 55 53 00 00  |..........enUS..|
0x4220: 00 34 00 00 00 1C 00 43  00 6F 00 70 00 79 00 72  |.4.....C.o.p.y.r|
0x4230: 00 69 00 67 00 68 00 74  00 20 00 41 00 70 00 70  |.i.g.h.t. .A.p.p|
0x4240: 00 6C 00 65 00 20 00 49  00 6E 00 63 00 2E 00 2C  |.l.e. .I.n.c...,|
0x4250: 00 20 00 32 00 30 00 32  00 32 58 59 5A 20 00 00  |. .2.0.2.2XYZ ..|
0x4260: 00 00 00 00 F6 D5 00 01  00 00 00 00 D3 2C 58 59  |.............,XY|
0x4270: 5A 20 00 00 00 00 00 00  83 DF 00 00 3D BF FF FF  |Z ..........=...|
0x4280: FF BB 58 59 5A 20 00 00  00 00 00 00 4A BF 00 00  |..XYZ ......J...|
0x4290: B1 37 00 00 0A B9 58 59  5A 20 00 00 00 00 00 00  |.7....XYZ ......|
0x42A0: 28 38 00 00 11 0B 00 00  C8 B9 70 61 72 61 00 00  |(8........para..|
0x42B0: 00 00 00 03 00 00 00 02  66 66 00 00 F2 A7 00 00  |........ff......|
0x42C0: 0D 59 00 00 13 D0 00 00  0A 5B 73 66 33 32 00 00  |.Y.......[sf32..|
0x42D0: 00 00 00 01 0C 42 00 00  05 DE FF FF F3 26 00 00  |.....B.......&..|
0x42E0: 07 93 00 00 FD 90 FF FF  FB A2 FF FF FD A3 00 00  |................|
0x42F0: 03 DC 00 00 C0 6E                                 |.....n|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/fuzzed-xnu-DisplayP3.tif

[NOT RUN] Profile TRUNCATED ‚Äî round-trip validation not run
       Header claims more bytes than file contains (CWE-125)
```

---

## LUT Text Export (`-xt`)

**Exit Code: 2**

```
Error reading ICC profile
Exported 0 text file(s) to /tmp/tmp.EW1jiggfFK/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
