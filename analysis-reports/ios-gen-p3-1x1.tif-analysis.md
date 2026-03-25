# ICC Profile Analysis Report

**Profile**: `test-profiles/ios-gen-p3-1x1.tif`
**File Size**: 762 bytes
**SHA-256**: `58522ce710ff327d4856f826aa4f12bdddcb89e7fe8523be690878f309db27db`
**File Type**: TIFF image data, big-endian, direntries=16, height=1, bps=0, compression=none, PhotometricInterpretation=RGB, orientation=upper-left, width=1
**Date**: 2026-03-25T02:25:07Z
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
      [OK] Strip geometry valid

[H140] TIFF Dimension and Sample Validation (CWE-400/CWE-131)
      [OK] Dimensions valid

[H141] TIFF IFD Offset Bounds Validation (CWE-125)
      [OK] All IFD offsets within file bounds

[H149] TIFF IFD Chain Cycle Detection (CWE-835)
      [OK] IFD chain is acyclic

[H150] TIFF Tile Geometry Validation (CWE-122/CWE-131)
      [OK] Strip-based image — tile geometry N/A


--- Injection Signature Scan ---
  [OK] No injection signatures detected

--- Embedded ICC Profile ---
  [FOUND] ICC profile embedded (TIFFTAG_ICCPROFILE, tag 34675)
  Profile Size:    536 bytes (0.5 KB)
  ICC Magic:       [OK] 'acsp' at offset 36
  ICC Version:     4.0

  Extracted ICC from TIFF to: /tmp/iccanalyzer-dELDiY.icc

=======================================================================
EXTRACTED ICC PROFILE — FULL HEURISTIC ANALYSIS
=======================================================================


=======================================================================
  ICC PROFILE CONFORMANCE AUDIT
=======================================================================

File: /tmp/iccanalyzer-dELDiY.icc

[H173] Signature Conversion Shift Overflow (IccUtil.cpp signature formatting helpers)
      [WARN]  HEURISTIC: 27/27 FourCC signatures trigger UBSAN shift overflow in icGetSig()/icGetSigStr()/icGetColorSig()/icGetColorSigStr() — IccUtil.cpp:1088,1130,1167,1187,1228,1253
       CWE-190: sig<<=8 on uint32 with first byte non-zero produces value > UINT32_MAX (upstream iccDEV library pattern)

[H174] Half-Float Conversion Unsigned Underflow (IccUtil.cpp icF16toF)
      [N/A] No vulnerable half-float values detected

=======================================================================
PHASE 1: ICC SPECIFICATION CONFORMANCE
=======================================================================


=======================================================================
ICC LIBRARY CONFORMANCE VALIDATION
=======================================================================

  Running CIccProfile::ReadValidate() — ICC.1-2022-05 conformance checks
  Checks: header, required tags, tag types, per-tag content validation

  Validation Status: NON-COMPLIANT — Profile does not conform to ICC specification

  [NON-COMPLIANT] redColorantTag::XYZ - XYZNumber: Negative Z value!

  Validation Summary: 0 error(s), 1 non-compliant, 0 warning(s), 0 info
  [WARN] 1 ICC spec conformance issue(s) detected


=======================================================================
PHASE 2: DEEP CONFORMANCE CHECKS (ICC.1/ICC.2)
=======================================================================

--- Header Conformance (CF-001..CF-015, CF-184..CF-187, CF-199..CF-201, CF-203, CF-206, CF-210, CF-214..CF-219) ---

[H1001] CF-001: Date/Time Month-Day Validity
[CF-001] Date/Time Month-Day Validity (ICC.1-2022-05 §7.2.8)
         Month=1, Day=1 — valid
         [OK] Date fields within range
      [OK] Conformant

[H1002] CF-002: Date/Time Leap Year Validation
[CF-002] Date/Time Leap Year Validation (ICC.1-2022-05 §7.2.8)
         Month=1 — leap year check not applicable
         [OK] Not February, skip leap year validation
      [OK] Conformant

[H1003] CF-003: Profile Flags Reserved Bits
[CF-003] Profile Flags Reserved Bits (ICC.1-2022-05 §7.2.11 Table 21)
         flags=0x00000000 — reserved bits 3-15 clear
         [OK] Profile flags conformant
      [OK] Conformant

[H1004] CF-004: Device Attributes Reserved Bits
[CF-004] Device Attributes Reserved Bits (ICC.1-2022-05 §7.2.14)
         attributes=0x0000000000000000 — reserved bits clear
         [OK] Device attributes conformant
      [OK] Conformant

[H1005] CF-005: Rendering Intent Upper Bits Zero
[CF-005] Rendering Intent Upper Bits Zero (ICC.1-2022-05 §7.2.15)
         renderingIntent=0 (Perceptual)
         [OK] Rendering intent conformant
      [OK] Conformant

[H1006] CF-006: Version BCD Encoding
[CF-006] Profile Version BCD Encoding (ICC.1-2022-05 §7.2.4)
         version=0x04000000 → v4.0.0.0
         [OK] Version BCD encoding conformant
      [OK] Conformant

[H1007] CF-007: Primary Platform Signature
[CF-007] Primary Platform Signature (ICC.1-2022-05 §7.2.10 Table 20)
         platform=Apple (APPL)
         [OK] Platform signature conformant
      [OK] Conformant

[H1008] CF-008: PCS Illuminant D50 Values
[CF-008] PCS Illuminant D50 Precision (ICC.1-2022-05 §7.2.16)
         illuminant X=0.9642, Y=1.0000, Z=0.8249
         expected   X=0.9642, Y=1.0000, Z=0.8249 (D50)
         [OK] PCS illuminant matches D50
      [OK] Conformant

[H1009] CF-009: Chromatic Adaptation Tag Requirement
[CF-009] Chromatic Adaptation Tag Requirement (ICC.1-2022-05 §8.2)
         chad tag present
         [OK] Chromatic adaptation tag conformant
      [OK] Conformant

[H1010] CF-010: Profile Size vs File Size
[CF-010] Profile Size vs File Size (ICC.1-2022-05 §7.2.2)
         Header size: 536 bytes, File size: 536 bytes
         [OK] Profile size matches file size
      [OK] Conformant

[H1011] CF-011: Profile ID MD5 Verification
[CF-011] Profile ID MD5 Verification (ICC.1-2022-05 §7.2.18)
         Profile ID is all zeros — not computed
         [INFO] Profile ID not set — §7.2.18
      [OK] Conformant

[H1012] CF-012: Profile Class Signature
[CF-012] Profile Class Signature (ICC.1-2022-05 §7.2.5 Table 18)
         deviceClass='mntr' (0x6D6E7472)
         [OK] Valid v4 profile class
      [OK] Conformant

[H1013] CF-013: Data Colour Space Signature
[CF-013] Data Colour Space Signature (ICC.1-2022-05 §7.2.6 Table 19)
         colorSpace='RGB ' (0x52474220) — RGB
         [OK] Valid colour space signature
      [OK] Conformant

[H1014] CF-014: PCS Field for Non-DeviceLink
[CF-014] PCS Field for Non-DeviceLink (ICC.1-2022-05 §7.2.7)
         PCS='XYZ ' (0x58595A20)
         [OK] PCS conformant for non-DeviceLink profile
      [OK] Conformant

[H1015] CF-015: Reserved Bytes 100-127 Zero
[CF-015] Reserved Bytes 100-127 Zero (ICC.1-2022-05 §7.2.24)
         Bytes 100-127: all zero
         [OK] Reserved bytes conformant
      [OK] Conformant

[H1016] CF-016: Device Manufacturer Signature
[CF-016] Device Manufacturer Signature (ICC.1-2022-05 §7.2.12)
         manufacturer='APPL' (0x4150504C)
         [OK] Device manufacturer field conformant
      [OK] Conformant

[H1017] CF-017: Device Model Signature
[CF-017] Device Model Signature (ICC.1-2022-05 §7.2.13)
         model=0x00000000 — not specified (permitted)
         [OK] Device model field conformant
      [OK] Conformant

[H1018] CF-018: Device Attributes Semantic Bits
[CF-018] Device Attributes Semantic Bits (ICC.1-2022-05 §7.2.14 Table 23)
         Bit 0 (Media): reflective
         Bit 1 (Finish): glossy
         Bit 2 (Polarity): positive
         Bit 3 (Colour): colour
         [OK] Device attributes conformant
      [OK] Conformant

[H1019] CF-019: Creator Signature
[CF-019] Creator Signature (ICC.1-2022-05 §7.2.17)
         creator='appl' (0x6170706C)
         [OK] Creator signature field conformant
      [OK] Conformant

[H1107] CF-107: Tag Table Ordering
  [CF-107] Tag Table Ordering (ICC.1-2022-05 §7.3.1)
         [OK] Tag table has no duplicate signatures
      [OK] Conformant

[H1121] CF-121: Illuminant Metadata Consistency
  [CF-121] Illuminant Metadata Consistency (ICC.1-2022-05 §7.2.16)
         [OK] Illuminant metadata consistent
      [OK] Conformant

[H1122] CF-122: Profile Date/Time Plausibility
  [CF-122] Profile Date/Time Plausibility (ICC.1-2022-05 §7.2.8)
         [OK] Profile date/time is plausible
      [OK] Conformant

[H1184] CF-184: Profile ID v4+ Presence
[CF-184] Profile ID v4+ Presence (ICC.1-2022-05 §7.2.18, RFC 1321)
         Profile version: 4.x
         Profile ID is all zeros (not computed)
         [WARN] v4+ profile SHOULD have computed Profile ID — §7.2.18
      [WARN]  1 non-conformance(s)

[H1185] CF-185: Profile ID Size Consistency
[CF-185] Profile ID Size Consistency (ICC.1-2022-05 §7.2.18, RFC 1321 §3.1)
         Profile ID is zero — size consistency check not applicable
         [OK] No Profile ID to validate
      [OK] Conformant

[H1186] CF-186: Profile ID Entropy Analysis
[CF-186] Profile ID Entropy Analysis (RFC 1321, ICC.1-2022-05 §7.2.18)
         Profile ID is zero — entropy analysis not applicable
         [OK] No Profile ID to analyze
      [OK] Conformant

[H1187] CF-187: Embedded Profile ProfileID Chain
[CF-187] Embedded Profile ProfileID Chain (ICC TN Embedding + §7.2.18 + RFC 1321)
         No embedded profile tag (ICC5) present
         [OK] No embedding chain to validate
      [OK] Conformant

[H1199] CF-199: CMM Type Signature Registration
  [CF-199] CMM Type Signature Registration (ICC.1-2022-05 §7.2.3)
           cmmId='appl' (0x6170706C) — registered ICC CMM
           [OK] CMM type conformant
      [OK] Conformant

[H1200] CF-200: Device Manufacturer/Model Signature
  [CF-200] Device Manufacturer/Model Signature (ICC.1-2022-05 §7.2.12-13)
           manufacturer='APPL' (0x4150504C)
           model=0x00000000 — not specified (permitted)
           [OK] Device manufacturer/model conformant
      [OK] Conformant

[H1201] CF-201: Profile Creator Signature
  [CF-201] Profile Creator Signature (ICC.1-2022-05 §7.2.17)
           creator='appl' (0x6170706C)
           [OK] Profile creator conformant
      [OK] Conformant

[H1203] CF-203: Profile Flags Semantic Validation
  [CF-203] Profile Flags Semantic Validation (ICC.1-2022-05 §7.2.11 Table 21)
           Bit 0 (Embedded): not embedded
           Bit 1 (Independent): can be used independently
           [OK] Profile flags semantics conformant
      [OK] Conformant

[H1206] CF-206: Profile File Signature 'acsp'
[CF-206] Profile File Signature 'acsp' (ICC.1-2022-05 §7.2.9)
         magic=0x61637370 ('acsp')
         [OK] Profile file signature conformant
      [OK] Conformant

[H1210] CF-210: DeviceLink PCS Space Validation
[CF-210] DeviceLink PCS Space Validation (ICC.1-2022-05 §8.6)
         Not a DeviceLink profile — skipping
         [OK] Not applicable
      [OK] Conformant

[H1214] CF-214: Embedded Profile Class Suitability
  [CF-214] Embedded Profile Class Suitability (ICC TN Embedding §Table 1)
         Embedded flag not set — profile not marked for embedding
         [OK] Not applicable (not an embedded profile)
      [OK] Conformant

[H1215] CF-215: JPEG APP2 Embedding Size Limit
  [CF-215] JPEG APP2 Embedding Size Limit (ICC TN Embedding §JFIF)
         Profile size: 536 bytes (JPEG limit: 16707345 bytes)
         Would require 1 APP2 segment(s) for JPEG embedding
         [OK] Profile fits within JPEG APP2 embedding limit
      [OK] Conformant

[H1216] CF-216: JP2 Restricted ICC Compliance
  [CF-216] JP2 Restricted ICC Compliance (ISO 15444-1 Annex I)
         Class 'mntr' — JP2 requires Input ('scnr') class
         Version 4.x — JP2 requires ICC v2 (ICC.1:1998-09)
         [INFO] Profile not compatible with JP2 Restricted ICC method
      [OK] Conformant

[H1217] CF-217: JPX Any ICC Method Compliance
  [CF-217] JPX Any ICC Method Compliance (ISO 15444-2 Annex M)
         [OK] Profile compatible with JPX Any ICC method
      [OK] Conformant

[H1218] CF-218: HEIF Restricted ICC Compatibility
  [CF-218] HEIF Restricted ICC Compatibility (ISO/IEC 14496-12)
         HEIF 'colr' compatible (v4 profile, ≤ v4)
         HEIF 'ricc' compatible (3-component Matrix/TRC)
         [OK] Profile compatible with HEIF embedding
      [OK] Conformant

[H1219] CF-219: Container Format Version Matrix
  [CF-219] Container Format Version Matrix (ICC TN Embedding §Table 1)
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

[H1020] CF-020: Tag Signature → Allowed Type
[CF-020] Tag Type Allowed for Signature (ICC.1-2022-05 §9.2, §10)
         [OK] 8/8 tags checked, all use permitted types
      [OK] Conformant

[H1021] CF-021: Tag Type Reserved Bytes Zero
[CF-021] Tag Type Reserved Bytes Zero (ICC.1-2022-05 §10)
         [OK] 8 tag(s) checked, all reserved bytes are zero
      [OK] Conformant

[H1022] CF-022: curveType Entry Count
[CF-022] curveType Entry Count Mode (ICC.1-2022-05 §10.6)
         No curveType tags found
         [OK] 0 curveType tag(s) checked, all consistent
      [OK] Conformant

[H1023] CF-023: parametricCurveType Function Type
[CF-023] parametricCurveType Function Type (ICC.1-2022-05 §10.18 Table 68)
         [OK] 3 parametricCurveType tag(s) checked, all function types valid
      [OK] Conformant

[H1024] CF-024: parametricCurveType Parameter Count
[CF-024] parametricCurveType Parameter Count (ICC.1-2022-05 §10.18 Table 68)
         [OK] 3 parametricCurveType tag(s) checked, all parameter counts correct
      [OK] Conformant

[H1025] CF-025: Chromaticity Phosphor Count
[CF-025] chromaticityType Phosphor Count (ICC.1-2022-05 §10.2)
         No chromaticityTag found
         [OK] Not applicable
      [OK] Conformant

[H1026] CF-026: Colorant Table Entry Count
[CF-026] colorantTableType Colorant Count (ICC.1-2022-05 §10.4)
         No colorantTableTag found
         [OK] Not applicable
      [OK] Conformant

[H1027] CF-027: Colorant Order Count
[CF-027] colorantOrderType Count Match (ICC.1-2022-05 §10.3)
         No colorantOrderTag found
         [OK] Not applicable
      [OK] Conformant

[H1028] CF-028: Named Color2 Device Coordinate Count
[CF-028] namedColor2Type Coordinate Count (ICC.1-2022-05 §10.14)
         No namedColor2Tag found
         [OK] Not applicable
      [OK] Conformant

[H1029] CF-029: dateTimeType Field Ranges
[CF-029] dateTimeType Field Ranges (ICC.1-2022-05 §10.7, §4.2)
         No dateTimeType tags found
         [OK] 0 dateTimeType tag(s) checked, all fields in range
      [OK] Conformant

[H1030] CF-030: multiLocalizedUnicodeType Structure
[CF-030] multiLocalizedUnicodeType Structure (ICC.1-2022-05 §10.13)
         [OK] 2 mluc tag(s) checked, all structurally valid
      [OK] Conformant

[H1031] CF-031: s15Fixed16ArrayType Element Count
[CF-031] s15Fixed16ArrayType Element Count (ICC.1-2022-05 §10.18)
         Tag 'chad': 9 s15Fixed16 element(s)
         [OK] 1 sf32 tag(s) checked, all element counts valid
      [OK] Conformant

[H1032] CF-032: XYZType Triplet Count
[CF-032] XYZType Triplet Count (ICC.1-2022-05 §10.23)
         [OK] 4 XYZ tag(s) checked, all contain exactly 1 triplet
      [OK] Conformant

[H1033] CF-033: Measurement Standard Observer
[CF-033] measurementType Standard Observer (ICC.1-2022-05 §10.12 Table 56)
         No measurementTag found
         [OK] Not applicable
      [OK] Conformant

[H1034] CF-034: Measurement Geometry
[CF-034] measurementType Measurement Geometry (ICC.1-2022-05 §10.12 Table 57)
         No measurementTag found
         [OK] Not applicable
      [OK] Conformant

[H1035] CF-035: responseCurveSet16Type Structure
[CF-035] responseCurveSet16Type Structure (ICC.1-2022-05 §10.19)
         No outputResponseTag ('resp') found
         [N/A] Not applicable
      [OK] Conformant

[H1036] CF-036: profileSequenceDescType Elements
[CF-036] profileSequenceDescType Elements (ICC.1-2022-05 §10.22)
         No profileSequenceDescTag found
         [N/A] Not applicable
      [OK] Conformant

[H1037] CF-037: profileSequenceIdentifierType Validation
[CF-037] profileSequenceIdentifierType Validation (ICC.1-2022-05 §10.23)
         No profileSequenceIdentifierTag ('psid') found
         [N/A] Not applicable
      [OK] Conformant

[H1038] CF-038: dateTimeType Tag Range Validation
[CF-038] dateTimeType Tag Range Validation (ICC.1-2022-05 §10.7)
         No calibrationDateTimeTag ('calt') found
         [N/A] Not applicable
      [OK] Conformant

[H1039] CF-039: signatureType Technology Validation
[CF-039] signatureType Technology Validation (ICC.1-2022-05 §10.24)
         No technologyTag ('tech') found
         [N/A] Not applicable
      [OK] Conformant

[H1112] CF-112: XYZ Triplet Normalization
  [CF-112] XYZ Triplet Value Normalization (ICC.1-2022-05 §10.31)
         [OK] All 4 XYZ triplets have valid values
      [OK] Conformant

[H1169] CF-169: Negative PCSXYZ Encoding Capability
  [CF-169] Negative PCSXYZ Encoding Capability (ICC TN Negative PCSXYZ §6.3.4.2)
         'rXYZ' has negative component(s): X=0.515121 Y=0.241196 Z=-0.001053
         [INFO] Negative value encoded via s15Fixed16Number — conformant per ICC TN Negative PCSXYZ
         [OK] 1 negative value(s) properly encoded via s15Fixed16
      [OK] Conformant

[H1170] CF-170: Chromatic Adaptation Negative XYZ Consistency
  [CF-170] Chromatic Adaptation Negative XYZ Consistency (ICC TN Negative PCSXYZ, §9.2.10)
         'rXYZ' contains negative component(s)
         [OK] Negative XYZ values present with chad tag — consistent with chromatic adaptation (BT.2020/DCI-P3 pattern)
      [OK] Conformant

[H1171] CF-171: White Point Non-Negative Luminance
  [CF-171] White Point Non-Negative Luminance (ICC TN Negative PCSXYZ, §3.1.24)
         [OK] White point luminance values are non-negative
      [OK] Conformant

[H1172] CF-172: Colorant XYZ Sum White Point Consistency
  [CF-172] Colorant XYZ Sum White Point Consistency (ICC TN Negative PCSXYZ, §9.2.7)
         Column sum: X=0.9642 Y=1.0000 Z=0.8249
         White point: X=0.9642 Y=1.0000 Z=0.8249
         [OK] Colorant sum matches white point within tolerance
      [OK] Conformant

[H1173] CF-173: PCS XYZ Absorber Encoding
  [CF-173] PCS XYZ Absorber Encoding (ICC TN Negative PCSXYZ, §6.4.3)
         [OK] White point and luminance properly distinguish from absorber encoding
      [OK] Conformant

[H1174] CF-174: Lab Conversion Clipping Awareness
  [CF-174] Lab Conversion Clipping Awareness (ICC TN Negative PCSXYZ, §6.4)
         1 matrix column(s) with negative components in XYZ PCS profile
         [INFO] Per ICC TN: CMMs should accept negative PCSXYZ without clipping; on Lab conversion clip per-component — §6.4
      [OK] Conformant

[H1123] CF-123: ADGC Class Restriction
         No ADGC tag present — check not applicable
      [OK] Conformant

[H1124] CF-124: ADGC Type Signature
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1125] CF-125: ADGC Function Type ID
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1126] CF-126: ADGC Reserved Bytes
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1127] CF-127: ADGC Float Field Finiteness
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1128] CF-128: ADGC Weight Coefficient Sum
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1129] CF-129: ADGC Curve Position Bounds
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1130] CF-130: ADGC Image-Specific GUID Flags
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1131] CF-131: ADGC Headroom Range Plausibility
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1132] CF-132: ADGC Curve Data Monotonicity
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1133] CF-133: ADGC H_baseline vs H_alternate Div-by-Zero
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1134] CF-134: ADGC Per-Channel GainMin ≤ GainMax
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1135] CF-135: ADGC Curve X-Value Domain Range
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1136] CF-136: ADGC Curve Adjacent-Point X-Equality
         No ADGC tag or read failed — check skipped
      [OK] Conformant

[H1188] CF-188: Global Per-Tag Validate() Sweep
  [CF-188] Global Per-Tag Validate() Sweep (SampleICC §3 Compliance)
         Tag 'rXYZ': non-compliant per Validate()
           NonCompliant! - :XYZ - XYZNumber: Negative Z value!
         Swept 10 tags: 9 OK, 0 warnings, 1 errors
      [WARN]  1 non-conformance(s)

[H1189] CF-189: Tag Type Recognition Coverage
  [CF-189] Tag Type Recognition Coverage (SampleICC §3 CheckTagTypes)
         10/10 tags have recognized type signatures
         [OK] All 10 tag types are recognized by the factory
      [OK] Conformant

[H1190] CF-190: Profile Legibility Gate
  [CF-190] Profile Legibility Gate (SampleICC §3 ReadValidate)
         [OK] Profile is legible: 10 tags parsed, all non-NULL
      [OK] Conformant

[H1208] CF-208: Tag Type Version Compatibility
[CF-208] Tag Type Version Compatibility (ICC.1-2022-05 §7.2.4, §10)
         Profile version 4.x — all standard tag types permitted
         [OK] Version 4.x tag types unrestricted
      [OK] Conformant

[H1209] CF-209: Colorspace Channel Count vs LUT Dimensions
[CF-209] Colorspace Channel Count vs LUT Dimensions (ICC.1-2022-05 §7.2.6, §10.8-10.11)
         colorSpace channels=3, PCS channels=3
         No AToB/BToA LUT tags present
         [OK] Colorspace/PCS channel counts match LUT dimensions
      [OK] Conformant

[H1212] CF-212: textType Null Termination
[CF-212] textType Null Termination (ICC.1-2022-05 §10.24)
         No textType tags found (profiles may use multiLocalizedUnicodeType)
         [OK] textType tag structure conformant
      [OK] Conformant

[H1213] CF-213: viewingConditionsType Completeness
[CF-213] viewingConditionsType Completeness (ICC.1-2022-05 §10.32)
         No viewingConditionsTag ('view') present
         [OK] viewingConditionsTag is optional
      [OK] Conformant

[H1220] CF-220: mluc Name Record Overlap Detection
[CF-220] mluc Name Record Overlap Detection (ICC TN PSD §mluc)
      [OK] Conformant

[H1221] CF-221: profileSequenceDescTag Structure
[CF-221] profileSequenceDescTag Structure (ICC.1-2022-05 §9.2.50)
         No profileSequenceDescTag — not required for this class
      [OK] Conformant

[H1222] CF-222: profileSequenceIdentifierTag Validation
[CF-222] profileSequenceIdentifierTag Validation (ICC.1-2022-05 §9.2.51)
         No profileSequenceIdentifierTag ('psid') present
      [OK] Conformant

[H1223] CF-223: mluc Zero-Name Placeholder Encoding
[CF-223] mluc Zero-Name Placeholder Encoding (ICC TN PSD §placeholder)
         No zero-name mluc tags found
      [OK] Conformant

[H1224] CF-224: mluc Reserved Field Zero
[CF-224] mluc Reserved Field Zero (ICC.1-2022-05 §10.13)
         [OK] 2 mluc tag(s) checked, all reserved fields zero
      [OK] Conformant

[H1225] CF-225: mluc Name Record String Alignment
[CF-225] mluc Name Record String Alignment (ICC.1-2022-05 §7.1, §10.13)
         [OK] 2 mluc tag(s) checked, all strings properly aligned
      [OK] Conformant

[H1226] CF-226: mluc Size Inference Safety
[CF-226] mluc Size Inference Safety (ICC TN PSD §size)
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
[CF-264] parametricCurveType Function Type Range (ICC.1-2022-05 §10.18)
         No MBB tags with parametric curves found
         [OK] All parametricCurveType function types in range [0..4]
      [OK] Conformant

[H1265] CF-265: mluc Language/Country Code Validity
[CF-265] mluc Record Language/Country Code (ICC.1-2022-05 §10.15)
         [OK] mluc language/country codes valid
      [OK] Conformant

[H1273] CF-273: Primary Colorant XYZ Values Positive
[CF-273] Primary Colorant XYZ Values Positive (ICC.1-2022-05 §10.28)
         [OK] Primary colorant XYZ values plausible
      [OK] Conformant

[H1274] CF-274: Primary Colorant Chromaticity Sum
[CF-274] Primary Colorant Chromaticity Sum (TN v4-matrix-entries)
         [OK] Primary colorant chromaticity sums plausible
      [OK] Conformant

[H1275] CF-275: copyrightTag Must Be mluc for v4+
[CF-275] copyrightTag Must Be mluc for v4+ (ICC.1-2022-05 §9.2.14)
         [OK] copyrightTag is mluc for v4+
      [OK] Conformant

[H1276] CF-276: profileDescriptionTag Must Be mluc for v4+
[CF-276] profileDescriptionTag Must Be mluc for v4+ (ICC.1-2022-05 §9.2.44)
         [OK] profileDescriptionTag is mluc for v4+
      [OK] Conformant

[H1277] CF-277: mediaWhitePointTag Must Be XYZType
[CF-277] mediaWhitePointTag Must Be XYZType (ICC.1-2022-05 §9.2.35)
         [OK] mediaWhitePointTag is XYZType
      [OK] Conformant

[H1278] CF-278: chromaticAdaptationTag Type
[CF-278] chromaticAdaptationTag Type (ICC.1-2022-05 §9.2.2)
         [OK] chromaticAdaptationTag is s15Fixed16ArrayType
      [OK] Conformant

[H1279] CF-279: TRC Curve Values Non-Negative
[CF-279] TRC Curve Values Non-Negative (ICC.1-2022-05 §10.5)
         [OK] TRC curve values non-negative
      [OK] Conformant

[H1280] CF-280: XYZ Element Luminance (Y) Non-Negative
[CF-280] XYZ Element Luminance (Y) Non-Negative (ICC.1-2022-05 §10.28)
         [OK] XYZ luminance values non-negative
      [OK] Conformant

[H1281] CF-281: profileSequenceDescTag Structure
[CF-281] profileSequenceDescTag Structure (ICC.1-2022-05 §10.16)
      [OK] Conformant


--- Required Tag Conformance (CF-040..CF-053, CF-202, CF-204..CF-205, CF-207, CF-211, CF-258..CF-260, CF-266..CF-272, CF-282..CF-283) ---

[H1040] CF-040: Common Required Tags (cprt, desc, wtpt)
[CF-040] Common Required Tags (Non-DeviceLink) (ICC.1-2022-05 §8.2)
         'desc' (profileDescriptionTag): present
         'cprt' (copyrightTag): present
         'wtpt' (mediaWhitePointTag): present
         'chad' (chromaticAdaptationTag): present
         [OK] All common required tags present
      [OK] Conformant

[H1042] CF-042: Display Profile Required Tags
[CF-042] Display Profile Required Tags (ICC.1-2022-05 §8.4 Tables 25-27)
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
[CF-048] Rendering Intent Transform Consistency (ICC.1-2022-05 §7.2.15, §8)
         Declared rendering intent: 0 (Perceptual)
         [OK] Rendering intent consistent with transform tags
      [OK] Conformant

[H1049] CF-049: Matrix/TRC Profiles Must Use PCS XYZ
[CF-049] Matrix/TRC Profile PCS Must Be XYZ (ICC.1-2022-05 §8.3-8.4)
         PCS='XYZ ' — correct for matrix/TRC
         [OK] PCS is XYZ as required
      [OK] Conformant

[H1050] CF-050: xCLR Spaces Require Colorant Table
[CF-050] xCLR Colorant Table Required (ICC.1-2022-05 §8.5-8.6)
         Colour space is not xCLR — skipped
         [OK] Not an N-component colour space
      [OK] Conformant

[H1051] CF-051: DeviceLink Prohibited Tags
[CF-051] DeviceLink Prohibited Tags (ICC.1-2022-05 §8.6 Table 30)
         Not a DeviceLink profile — skipped
         [OK] Not applicable
      [OK] Conformant

[H1052] CF-052: Transform Tag Pair Completeness
[CF-052] Transform Tag Pair Consistency (ICC.1-2022-05 §8.3-8.5)
         [OK] All transform tag pairs consistent
      [OK] Conformant

[H1053] CF-053: CICP Tag Class Restriction
[CF-053] cicpTag Class Restriction (ICC.1-2022-05 §9.2.11)
         'cicp' (cicpTag): not present — no restriction check needed
         [OK] No cicpTag to validate
      [OK] Conformant

[H1054] CF-054: v5 Spectral Required Tags
[CF-054] v5 Spectral Required Tags (ICC.2-2023 §8)
         Profile version 4 — not v5, skipped
         [OK] Not a v5 profile
      [OK] Conformant

[H1055] CF-055: D2B/B2D Tag Pair Completeness
[CF-055] D2B/B2D Tag Pair Completeness (ICC.1-2022-05 §8)
         No D2B/B2D tags found — skipped
         [OK] No D2B/B2D tags to validate
      [OK] Conformant

[H1056] CF-056: Embedded Profile Structure
[CF-056] Embedded Profile Structure (ICC.2-2023 §9.2)
         No embedded profile tag ('ICC5') found — skipped
         [OK] No embedded profile to validate
      [OK] Conformant

[H1057] CF-057: Dictionary Tag Structure v5
[CF-057] Dictionary Tag Structure v5 (ICC.2-2023 §9.2.25)
         Profile version 4 — not v5, skipped
         [OK] Not a v5 profile
      [OK] Conformant

[H1058] CF-058: Profile Sequence Identifier v5
[CF-058] Profile Sequence Identifier v5 (ICC.2-2023 §8)
         Profile version 4 — not v5, skipped
         [OK] Not a v5 profile
      [OK] Conformant

[H1059] CF-059: Colorimetric Intent Image State
[CF-059] Colorimetric Intent Image State (ICC.1-2022-05 §9.2.12)
         'ciis' (colorimetricIntentImageStateTag): not present — skipped
         [OK] No colorimetricIntentImageState tag
      [OK] Conformant

[H1095] CF-095: Non-Required Tag Identification
  [CF-095] Non-Required Tag Identification (ICC.1-2022-05 §8)
           Additional tag: 'chad' (0x63686164)
           [INFO] 1 non-required tag(s) present
      [OK] Conformant

[H1096] CF-096: Private Tag Signature Range
  [CF-096] Private Tag Signature Range (ICC.1-2022-05 §9)
           [OK] No private tags
      [OK] Conformant

[H1097] CF-097: Private Tag Documentation
  [CF-097] Private Tag Documentation (ICC.1-2022-05 §9)
           [OK] No private tags
      [OK] Conformant

[H1098] CF-098: Undocumented Private Tags
  [CF-098] Undocumented Private Tag Identification (ICC.1-2022-05 §9)
           [OK] All tags are recognized ICC signatures
      [OK] Conformant

[H1103] CF-103: Tag Alignment & Offset Validity
  [CF-103] Tag Table Alignment & Offset Validity (ICC.1-2022-05 §7.3.1)
           [OK] All tag offsets aligned and within bounds
      [OK] Conformant

[H1104] CF-104: DeviceLink PCS Consistency
  [CF-104] DeviceLink PCS Consistency (ICC.1-2022-05 §8.6)
           Not a DeviceLink profile — check not applicable
      [OK] Conformant

[H1111] CF-111: Required Tags per ICC Version
  [CF-111] Required Tags per ICC Version (ICC.1-2022-05 §8.2-8.9)
           [OK] Version-specific required tags present
      [OK] Conformant

[H1117] CF-117: Rendering Intent Tags per Class
  [CF-117] Rendering Intent Tags per Class (ICC.1-2022-05 §8.3-8.5)
           [OK] Rendering intent tags appropriate for profile class
      [OK] Conformant

[H1118] CF-118: Private Tag Creator Signature
  [CF-118] Private Tag Creator Signature (ICC.1-2022-05 §9)
           [OK] Creator signature present (0x6170706C)
      [OK] Conformant

[H1119] CF-119: Profile Sequence Identifier
  [CF-119] Profile Sequence Identifier (ICC.1-2022-05 §8.6)
           V4 profile without profileSequenceIdentifierTag
           [INFO] §10.15 recommends profileSequenceIdentifierTag
           [OK] Profile sequence identification validated
      [OK] Conformant

[H1120] CF-120: Named Color Space Dimensions
  [CF-120] Named Color Space Dimensions (ICC.1-2022-05 §10.14)
           Not a NamedColor profile — check not applicable
      [OK] Conformant

[H1202] CF-202: Tag Data Padding Zero-Fill
  [CF-202] Tag Data Padding Zero-Fill (ICC.1-2022-05 §7.2.1c)
           [OK] All inter-tag padding bytes are zero
      [OK] Conformant

[H1204] CF-204: Device Attributes Semantic Validation
  [CF-204] Device Attributes Semantic Validation (ICC.1-2022-05 §7.2.14 Table 22)
           Bit 0: reflective
           Bit 1: glossy
           Bit 2: positive media
           Bit 3: colour
           [OK] Device attributes semantics conformant
      [OK] Conformant

[H1205] CF-205: Tag Data Region Gap Analysis
  [CF-205] Tag Data Region Gap Analysis (ICC.1-2022-05 §7.3)
           Distinct data regions: 8
           Data coverage: 284 / 536 bytes (53.0%)
           Inter-region gaps: 0 (largest: 0 bytes)
           [OK] Tag data region layout conformant
      [OK] Conformant

[H1207] CF-207: mediaWhitePointTag Value Range
[CF-207] mediaWhitePointTag Value Range (ICC.1-2022-05 §10.27)
         wtpt: X=0.9642, Y=1.0000, Z=0.8249
         [OK] mediaWhitePointTag values conformant
      [OK] Conformant

[H1211] CF-211: AToB/BToA Tag Pair Completeness
[CF-211] AToB/BToA Tag Pair Completeness (ICC.1-2022-05 §9.2.1-9.2.2)
         No AToB/BToA LUT pairs present (profile may use Matrix/TRC)
         [OK] AToB/BToA tag pair completeness conformant
      [OK] Conformant

[H1258] CF-258: Display v4+ mediaWhitePointTag D50
[CF-258] Display v4+ mediaWhitePointTag D50 (ICC.1-2022-05 §8.4)
         [OK] mediaWhitePointTag equals D50 (tolerance +/-0.005)
      [OK] Conformant

[H1259] CF-259: colorantOrderTag vs colorantTableTag Cross-Validation
[CF-259] colorantOrderTag vs colorantTableTag Cross-Validation (ICC.1-2022-05 §10.3)
         Neither colorantOrderTag nor colorantTableTag present
      [OK] Conformant

[H1260] CF-260: Output Profile gamutTag Rendering Intent
[CF-260] Output Profile gamutTag Rendering Intent (ICC.1-2022-05 §9.2.22)
         Not an Output profile — gamutTag check not applicable
      [OK] Conformant

[H1266] CF-266: Input Profile Device Color Space
[CF-266] Input Profile Device Color Space (ICC.1-2022-05 §6.1)
      [OK] Conformant

[H1267] CF-267: Display Profile Color Space
[CF-267] Display Profile Color Space (ICC.1-2022-05 §6.2)
         [OK] Display profile device color space valid
      [OK] Conformant

[H1268] CF-268: Output Profile Color Space
[CF-268] Output Profile Color Space (ICC.1-2022-05 §6.3)
      [OK] Conformant

[H1269] CF-269: DeviceLink Data Color Space Matching
[CF-269] DeviceLink Data Color Space Matching (ICC.1-2022-05 §6.4)
      [OK] Conformant

[H1270] CF-270: Abstract Profile PCS
[CF-270] Abstract Profile PCS (ICC.1-2022-05 §6.6)
      [OK] Conformant

[H1271] CF-271: NamedColor Profile PCS
[CF-271] NamedColor Profile PCS (ICC.1-2022-05 §6.7)
      [OK] Conformant

[H1272] CF-272: Matrix/TRC RGB Required Colorant Tags
[CF-272] Matrix/TRC RGB Required Colorant Tags (ICC.1-2022-05 §9.2.47)
         [OK] All matrix/TRC colorant tags present
      [OK] Conformant

[H1282] CF-282: DeviceLink AToB0Tag Required
[CF-282] DeviceLink AToB0Tag Required (ICC.1-2022-05 §6.4)
      [OK] Conformant

[H1283] CF-283: DeviceLink profileSequenceDescTag
[CF-283] DeviceLink profileSequenceDescTag (ICC.1-2022-05 §6.4)
      [OK] Conformant


--- LUT/Matrix Conformance (CF-060..CF-070, CF-163..CF-168, CF-255..CF-256, CF-261..CF-262) ---

[H1060] CF-060: LUT Input Channel Count
[CF-060] LUT Input Channel Count (ICC.1-2022-05 §10.8-10.11)
         [OK] Matrix/TRC device-side channel tags valid
      [OK] Conformant

[H1061] CF-061: LUT Output Channel Count
[CF-061] LUT Output Channel Count (ICC.1-2022-05 §10.8-10.11)
         [OK] Matrix/TRC PCS-side channel tags valid
      [OK] Conformant

[H1062] CF-062: CLUT Grid Dimensionality
[CF-062] CLUT Grid Dimensionality (ICC.1-2022-05 §10.8-10.11)
         [N/A] No CLUT elements found
      N/A: No CLUT elements found
      [OK] Conformant

[H1063] CF-063: lut8Type Fixed 256-Entry Tables
[CF-063] lut8Type Fixed Table Size 256 (ICC.1-2022-05 §10.9)
         No lut8Type tags found — check not applicable
         [OK] lut8Type table sizes conformant
      [OK] Conformant

[H1064] CF-064: lut16Type Table Size Range
[CF-064] lut16Type Table Size Range 2-4096 (ICC.1-2022-05 §10.10)
         No lut16Type tags found — check not applicable
         [OK] lut16Type table sizes within range
      [OK] Conformant

[H1065] CF-065: lutAToBType Element Presence
[CF-065] lutAToBType Processing Element Present (ICC.1-2022-05 §10.11)
         No lutAToBType tags found — check not applicable
         [OK] lutAToBType element presence valid
      [OK] Conformant

[H1066] CF-066: lutBToAType Element Presence
[CF-066] lutBToAType Processing Element Present (ICC.1-2022-05 §10.12)
         No lutBToAType tags found — check not applicable
         [OK] lutBToAType element presence valid
      [OK] Conformant

[H1067] CF-067: LUT Matrix Identity for Non-XYZ PCS
[CF-067] lut8/16 Matrix Identity When Not PCSXYZ (ICC.1-2022-05 §10.8-10.10)
         PCS is XYZ — matrix may be non-identity
         [OK] PCS=XYZ, identity check not applicable
      [OK] Conformant

[H1068] CF-068: Chad Matrix Invertible
[CF-068] Chromatic Adaptation Matrix Invertible (ICC.1-2022-05 §9.2.10)
         Determinant = 0.779453 — matrix is invertible
         [OK] Chromatic adaptation matrix invertible
      [OK] Conformant

[H1069] CF-069: Matrix Column XYZ Count
[CF-069] Matrix Column Tag XYZ Count (ICC.1-2022-05 §9.2.7, §9.2.18, §9.2.31)
         [OK] Matrix column XYZ counts valid
      [OK] Conformant

[H1070] CF-070: Chad Array Count = 9
[CF-070] Chad s15Fixed16 Array Count 9 (ICC.1-2022-05 §9.2.10)
         [OK] Chad array count is 9
      [OK] Conformant

[H1071] CF-071: Curve Count vs Channel Match
[CF-071] Curve Count vs Channel Match (ICC.1-2022-05 §10.10-10.12)
         No LUT tags found — check not applicable
         [OK] Curve counts match channel expectations
      [OK] Conformant

[H1072] CF-072: CLUT Output Value Range
[CF-072] CLUT Output Value Range (ICC.1-2022-05 §10.8-10.12)
         No CLUT elements found — check not applicable
         [OK] CLUT output values are finite
      [OK] Conformant

[H1073] CF-073: MBB Matrix Determinant Non-Zero
[CF-073] MBB Matrix Determinant Non-Zero (ICC.1-2022-05 §10.10-10.12)
         No MBB tags with matrix found — check not applicable
         [OK] MBB matrix determinants are non-zero
      [OK] Conformant

[H1074] CF-074: A2B/B2A Dimension Consistency
[CF-074] A2B/B2A Dimension Consistency (ICC.1-2022-05 §10.8-10.12)
         No matching A2B/B2A pairs found — check not applicable
         [OK] A2B/B2A dimensions are consistent
      [OK] Conformant

[H1075] CF-075: Tag Data Size vs Dimensions
[CF-075] Tag Data Size vs Dimensions (ICC.1-2022-05 §10.8-10.12)
         No LUT tags found — check not applicable
         [OK] LUT dimensions are plausible
      [OK] Conformant

[H1076] CF-076: Curve Response Direction
[CF-076] Curve Response Direction (ICC.1-2022-05 §10.5)
         No AToB tags with B curves found — check not applicable
         [OK] B curves are non-decreasing
      [OK] Conformant

[H1077] CF-077: CLUT Grid Size Plausibility
[CF-077] CLUT Grid Size Plausibility (ICC.1-2022-05 §10.8-10.12)
         No CLUT elements found — check not applicable
         [OK] CLUT grid sizes are plausible
      [OK] Conformant

[H1078] CF-078: MBB B-Curve Presence
[CF-078] MBB B-Curve Presence (ICC.1-2022-05 §10.10-10.12)
         No lutAToBType/lutBToAType tags found — check not applicable
         [OK] B curves present in all MBB tags
      [OK] Conformant

[H1079] CF-079: LUT Bit Depth Consistency
[CF-079] LUT Bit Depth Consistency (ICC.1-2022-05 §10.9-10.10)
         No lut8/lut16 type tags found — check not applicable
         [OK] Legacy LUT curve sizes are consistent
      [OK] Conformant

[H1105] CF-105: LUT Channel Symmetry
  [CF-105] LUT Channel Symmetry (ICC.1-2022-05 §10.8-10.11)
         No AToB/BToA tag pairs found — check not applicable
         [OK] LUT channel symmetry validated
      [OK] Conformant

[H1106] CF-106: Curve Monotonicity
  [CF-106] Curve Monotonicity (ICC.1-2022-05 §10.5)
         [N/A] No tabulated TRC curves found
      N/A: No tabulated TRC curves found
         [OK] TRC curves are monotonically non-decreasing
      [OK] Conformant

[H1108] CF-108: CLUT Grid Point Range
  [CF-108] CLUT Grid Point Range (ICC.1-2022-05 §10.8-10.10)
         No CLUT elements found — check not applicable
         [OK] CLUT grid points in valid range [2,255]
      [OK] Conformant

[H1109] CF-109: Matrix Column Normalization
  [CF-109] Matrix Column Normalization (ICC.1-2022-05 §9.2.7)
         [OK] Matrix columns properly normalized
      [OK] Conformant

[H1110] CF-110: B Curves vs CLUT Output
  [CF-110] B Curves vs CLUT Output Count (ICC.1-2022-05 §10.8-10.11)
         No lutAToB/lutBToA with CLUT found — check not applicable
         [OK] B curves match CLUT output channels
      [OK] Conformant

[H1116] CF-116: Curve Segment Continuity
  [CF-116] Curve Segment Continuity (ICC.1-2022-05 §10.18)
         [OK] Curve segments continuous
      [OK] Conformant

[H1163] CF-163: LUT Matrix Coefficient Finite
[CF-163] LUT Matrix Coefficient Finite (ICC v4 Matrix Entries TN)
         No LUT tags with matrix found — check not applicable
         [OK] All LUT matrix coefficients are finite
      [OK] Conformant

[H1164] CF-164: LUT Matrix s15Fixed16 Range
[CF-164] LUT Matrix s15Fixed16 Range (ICC v4 Matrix Entries TN)
         No LUT tags with matrix found — check not applicable
         [OK] All LUT matrix coefficients within s15Fixed16 range
      [OK] Conformant

[H1165] CF-165: LUT Matrix Determinant Non-Singular
[CF-165] LUT Matrix Determinant Non-Singular (ICC v4 Matrix Entries TN)
         No LUT tags with matrix found — check not applicable
         [OK] All LUT matrices are non-singular
      [OK] Conformant

[H1166] CF-166: LUT Matrix Row Non-Zero
[CF-166] LUT Matrix Row Non-Zero (ICC v4 Matrix Entries TN)
         No LUT tags with matrix found — check not applicable
         [OK] All LUT matrix rows have non-zero elements
      [OK] Conformant

[H1167] CF-167: LUT Matrix Offset Bounds
[CF-167] LUT Matrix Offset Bounds (ICC v4 Matrix Entries TN)
         No LUT tags with matrix offset constants found — check not applicable
         [OK] All LUT matrix offsets within reasonable bounds
      [OK] Conformant

[H1168] CF-168: LUT Matrix Input-Output Range
[CF-168] LUT Matrix Input-Output Range (ICC v4 Matrix Entries TN)
         No LUT tags with matrix found — check not applicable
         [OK] LUT matrix outputs within expected range
      [OK] Conformant

[H1255] CF-255: CLUT Grid Point Values
      [OK] Conformant

[H1256] CF-256: LUT I/O Channels vs Profile Spaces
      [OK] Conformant

[H1261] CF-261: M-Curve Count = 3 When Matrix Present
[CF-261] lutAToBType M-Curve Count = 3 When Matrix Present (ICC.1-2022-05 §10.11)
         No lutAToB/BToA tags with matrix+M-curves found
         [OK] M-curve count consistent with matrix presence
      [OK] Conformant

[H1262] CF-262: B-Curve Count vs Output Channels
[CF-262] LUT B-Curve Count vs Output Channels (ICC.1-2022-05 §10.11)
         No lutAToBType tags found
         [OK] B-curve count matches output channel count
      [OK] Conformant


--- v5/iccMAX Conformance (CF-080..CF-090, CF-113..CF-115, CF-137..CF-162, CF-175..CF-198, CF-235..CF-242, CF-257, CF-284..CF-316) ---

[H1178] CF-178: Chad Diagonal Dominance
[CF-178] Chad Matrix Diagonal Dominance (ICC TN Partial Adaptation)
         All rows diagonally dominant — valid adaptation structure
         [OK] Chad matrix diagonally dominant
      [OK] Conformant

[H1179] CF-179: Chad D50 Identity
[CF-179] Chad D50-to-D50 Identity Check (ICC TN Partial Adaptation)
         Illuminant is D50 but chad deviates from identity (max dev = 0.248322)
         [WARN] D50 illuminant with non-identity chad — profile may have inconsistent adaptation
      [WARN]  1 non-conformance(s)

[H1183] CF-183: Chad Column Normalization
[CF-183] Chad Column Normalization (ICC TN Partial Adaptation)
         Column 0 norm = 1.0483
         Column 1 norm = 0.9909
         Column 2 norm = 0.7535
         All column norms within reasonable range
         [OK] Chad column normalization conformant
      [OK] Conformant

  [INFO] Profile version 4 — v5/iccMAX checks skipped

--- Security Conformance (CF-091..CF-094) ---

[H1091] CF-091: Malware Signature Scan
  [CF-091] Malware Signature Scan (ICC.1-2022-05 §9)
           [OK] No malware signatures detected in tag data
      [OK] Conformant

[H1092] CF-092: Private Tag Identification
  [CF-092] Private/Unregistered Tag Identification (ICC.1-2022-05 §9)
           [OK] All tags are registered ICC signatures
      [OK] Conformant

[H1093] CF-093: Private Tag Content Scan
  [CF-093] Private Tag Content Security Scan (ICC.1-2022-05 §9)
           [OK] No private tags to scan
      [OK] Conformant

[H1094] CF-094: NOP/Shellcode Pattern Scan
  [CF-094] NOP/Shellcode Pattern Scan (CWE-506)
           [OK] No NOP sled or shellcode patterns detected
      [OK] Conformant


--- Private Tag Conformance (CF-095..CF-098) ---


--- Quality Conformance (CF-099..CF-102) ---

[H1099] CF-099: Round-Trip CIEDE2000
  [CF-099] Round-Trip Transform CIEDE2000 (ICC.1-2022-05 §8)
           Model: matrix/TRC, samples: 729
           First round trip:  avg DeltaE00=0.0000  max DeltaE00=0.0000
           Second round trip: avg DeltaE00=0.0000  max DeltaE00=0.0000
           [OK] Round-trip DeltaE00 metrics recorded
      [OK] Conformant

[H1100] CF-100: Curve Invertibility
  [CF-100] Curve Invertibility Check (ICC.1-2022-05 §10.6)
           rTRC: avg inv err=0.000000  max err=0.000000
           gTRC: avg inv err=0.000000  max err=0.000000
           bTRC: avg inv err=0.000000  max err=0.000000
           [OK] 3 curve(s) checked — invertibility metrics recorded
      [OK] Conformant

[H1101] CF-101: Transform Smoothness
  [CF-101] Transform Smoothness (ICC.1-2022-05 §10.8)
           Model: matrix/TRC multi-axis, samples: 256
           Avg step DeltaE00=1.1718  max step DeltaE00=4.0637  max curvature=0.5800
           Large discontinuities (>6.0 DeltaE00): 0
           [OK] Transform smoothness metrics recorded
      [OK] Conformant

[H1102] CF-102: Characterization Round-Trip
  [CF-102] Characterization Data Round-Trip (ICC.1-2022-05 §9.2.26)
           [N/A] No characterization data (targ) tag present
      N/A: No characterization data (targ) tag present
      [OK] Conformant


Deep Conformance Summary: 3 issue(s)

=======================================================================
PHASE 3: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /tmp/iccanalyzer-dELDiY.icc

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

  (Profile is v2/v4 — v5/iccMAX summary not applicable)

--- 5J: Version Classification & Capabilities ---

  Version Classification:
    ICC Version:       4.0.0
    Specification:     ICC.1-2022-05 (v4)
    Features:          chromaticAdaptationTag, lut16/lutAToB, profileID
    Device Class:      DisplayClass
    Color Space:       RgbData (3 channels)
    Connection Space:  XYZData

  Transform Capabilities:
    AToB (device→PCS):   no
    BToA (PCS→device):   no
    DToB (device→PCS):   no
    BToD (PCS→device):   no
    TRC (matrix/gamma):  YES
    Gamut check:         no
    Chromatic adapt:     YES
    Preview:             no


=======================================================================
CONFORMANCE AUDIT SUMMARY
=======================================================================

File: /tmp/iccanalyzer-dELDiY.icc
Mode: Conformance (ICC specification audit)
Total Issues Detected: 5

[WARN] ANALYSIS COMPLETE - 5 issue(s) detected
  Review conformance findings above. Use --legacy for vulnerability analysis.


=======================================================================
IMAGE ANALYSIS SUMMARY
=======================================================================
Format:     TIFF
Dimensions: 1 × 1
Findings:   5
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
  Version:         0xC09078FF  (192.9.0)
  Device Class:    0x00100100  '....'
  Color Space:     0x00030000  '....'
  PCS:             0x00010001  '....'
  Date/Time:       0000-257-03 00:01:01
  Magic:           0x00000102  [INVALID]
  Platform:        0x00030000  '....'
  Flags:           0x00040000
  Manufacturer:    0x00D20103  '....'
  Model:           0x00030000  '....'
  Dev Attributes:  0x0001000100000106 [Matte]
  Rendering Intent:0x00030000  UNKNOWN
  PCS Illuminant:  X=1.0000 Y=0.0041 Z=3.0000
  Creator:         0x00010001  '....'
  Profile ID:      00000111000400000001000000080112
  Reserved 100-127: NON-ZERO [VIOLATION]

  --- V5/iccMAX Extended Header ---
  Spectral PCS:    0x00010001  '....'
  Spectral Range:  Not defined
  MCS:             0x00010004  '....'

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

[NOT RUN] Profile TRUNCATED — round-trip validation not run
       Header claims more bytes than file contains (CWE-125)
```

---

## LUT Text Export (`-xt`)

**Exit Code: 2**

```
Error reading ICC profile
Exported 0 text file(s) to /tmp/tmp.DgotxZkphs/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
