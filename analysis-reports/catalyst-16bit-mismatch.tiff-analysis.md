# ICC Profile Analysis Report

**Profile**: `test-profiles/catalyst-16bit-mismatch.tiff`
**File Size**: 2830 bytes
**SHA-256**: `8bc9485f47c60269bea3f33337cf0f481604d0d739775be22c17ea0779afa354`
**File Type**: TIFF image data, big-endian, direntries=16, height=16, bps=0, compression=none, PhotometricInterpretation=RGB, orientation=upper-left, width=32
**Date**: 2026-03-25T02:25:01Z
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
File: /home/h02332/po/research/test-profiles/catalyst-16bit-mismatch.tiff

--- TIFF Metadata ---
  Dimensions:      32 × 16 pixels
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
      [INJECT] PixelData(strip0): 'BigTIFF magic in standard TIFF' at offset 1183
       CWE-843: Type Confusion
  [WARN] 1 injection signature(s) detected

--- Embedded ICC Profile ---
  [FOUND] ICC profile embedded (TIFFTAG_ICCPROFILE, tag 34675)
  Profile Size:    560 bytes (0.5 KB)
  ICC Magic:       [OK] 'acsp' at offset 36
  ICC Version:     2.1

  Extracted ICC from TIFF to: /tmp/iccanalyzer-lOy6C4.icc

=======================================================================
EXTRACTED ICC PROFILE — FULL HEURISTIC ANALYSIS
=======================================================================


=======================================================================
  ICC PROFILE CONFORMANCE AUDIT
=======================================================================

File: /tmp/iccanalyzer-lOy6C4.icc

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

  Validation Status: OK — Profile conforms to ICC specification

  [OK] No conformance findings — profile is spec-compliant


=======================================================================
PHASE 2: DEEP CONFORMANCE CHECKS (ICC.1/ICC.2)
=======================================================================

--- Header Conformance (CF-001..CF-015, CF-184..CF-187, CF-199..CF-201, CF-203, CF-206, CF-210, CF-214..CF-219) ---

[H1001] CF-001: Date/Time Month-Day Validity
[CF-001] Date/Time Month-Day Validity (ICC.1-2022-05 §7.2.8)
         Month=8, Day=11 — valid
         [OK] Date fields within range
      [OK] Conformant

[H1002] CF-002: Date/Time Leap Year Validation
[CF-002] Date/Time Leap Year Validation (ICC.1-2022-05 §7.2.8)
         Month=8 — leap year check not applicable
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
         version=0x02100000 → v2.1.0.0
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
         Version 2.x  — chad tag check not applicable
         [OK] Not required for this profile type
      [OK] Conformant

[H1010] CF-010: Profile Size vs File Size
[CF-010] Profile Size vs File Size (ICC.1-2022-05 §7.2.2)
         Header size: 560 bytes, File size: 560 bytes
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
         manufacturer='none' (0x6E6F6E65)
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
         creator='ADBE' (0x41444245)
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
         Profile version: 2.x
         v2 profile — Profile ID field not defined before v4
         [OK] v2 profiles exempt from Profile ID requirement
      [OK] Conformant

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
           cmmId='ADBE' (0x41444245) — registered ICC CMM
           [OK] CMM type conformant
      [OK] Conformant

[H1200] CF-200: Device Manufacturer/Model Signature
  [CF-200] Device Manufacturer/Model Signature (ICC.1-2022-05 §7.2.12-13)
           manufacturer='none' (0x6E6F6E65)
           model=0x00000000 — not specified (permitted)
           [OK] Device manufacturer/model conformant
      [OK] Conformant

[H1201] CF-201: Profile Creator Signature
  [CF-201] Profile Creator Signature (ICC.1-2022-05 §7.2.17)
           creator='ADBE' (0x41444245)
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
         Profile size: 560 bytes (JPEG limit: 16707345 bytes)
         Would require 1 APP2 segment(s) for JPEG embedding
         [OK] Profile fits within JPEG APP2 embedding limit
      [OK] Conformant

[H1216] CF-216: JP2 Restricted ICC Compliance
  [CF-216] JP2 Restricted ICC Compliance (ISO 15444-1 Annex I)
         Class 'mntr' — JP2 requires Input ('scnr') class
         [INFO] Profile not compatible with JP2 Restricted ICC method
      [OK] Conformant

[H1217] CF-217: JPX Any ICC Method Compliance
  [CF-217] JPX Any ICC Method Compliance (ISO 15444-2 Annex M)
         [OK] Profile compatible with JPX Any ICC method
      [OK] Conformant

[H1218] CF-218: HEIF Restricted ICC Compatibility
  [CF-218] HEIF Restricted ICC Compatibility (ISO/IEC 14496-12)
         HEIF 'colr' compatible (v2 profile, ≤ v4)
         HEIF 'ricc' compatible (3-component Matrix/TRC)
         [OK] Profile compatible with HEIF embedding
      [OK] Conformant

[H1219] CF-219: Container Format Version Matrix
  [CF-219] Container Format Version Matrix (ICC TN Embedding §Table 1)
         Profile version: 2.x, class: mntr
         JPX (ISO 15444-2): compatible (v2 Display)
         PNG (ISO 15948): compatible (v2, per specification)
         Compatible with 17+ media formats (of 18 surveyed)
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
         [OK] 9/9 tags checked, all use permitted types
      [OK] Conformant

[H1021] CF-021: Tag Type Reserved Bytes Zero
[CF-021] Tag Type Reserved Bytes Zero (ICC.1-2022-05 §10)
         [OK] 10 tag(s) checked, all reserved bytes are zero
      [OK] Conformant

[H1022] CF-022: curveType Entry Count
[CF-022] curveType Entry Count Mode (ICC.1-2022-05 §10.6)
         Tag 'rTRC': curveType count=1 (gamma=0.0086)
         Tag 'gTRC': curveType count=1 (gamma=0.0086)
         Tag 'bTRC': curveType count=1 (gamma=0.0086)
         [OK] 3 curveType tag(s) checked, all consistent
      [OK] Conformant

[H1023] CF-023: parametricCurveType Function Type
[CF-023] parametricCurveType Function Type (ICC.1-2022-05 §10.18 Table 68)
         No parametricCurveType tags found
         [OK] 0 parametricCurveType tag(s) checked, all function types valid
      [OK] Conformant

[H1024] CF-024: parametricCurveType Parameter Count
[CF-024] parametricCurveType Parameter Count (ICC.1-2022-05 §10.18 Table 68)
         No parametricCurveType tags found
         [OK] 0 parametricCurveType tag(s) checked, all parameter counts correct
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
         No multiLocalizedUnicodeType tags found
         [OK] 0 mluc tag(s) checked, all structurally valid
      [OK] Conformant

[H1031] CF-031: s15Fixed16ArrayType Element Count
[CF-031] s15Fixed16ArrayType Element Count (ICC.1-2022-05 §10.18)
         No s15Fixed16ArrayType tags found
         [OK] 0 sf32 tag(s) checked, all element counts valid
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
         [OK] All 4 XYZ tags have non-negative values
      [OK] Conformant

[H1170] CF-170: Chromatic Adaptation Negative XYZ Consistency
  [CF-170] Chromatic Adaptation Negative XYZ Consistency (ICC TN Negative PCSXYZ, §9.2.10)
         [OK] No negative matrix column values — no adaptation concern
      [OK] Conformant

[H1171] CF-171: White Point Non-Negative Luminance
  [CF-171] White Point Non-Negative Luminance (ICC TN Negative PCSXYZ, §3.1.24)
         [OK] White point luminance values are non-negative
      [OK] Conformant

[H1172] CF-172: Colorant XYZ Sum White Point Consistency
  [CF-172] Colorant XYZ Sum White Point Consistency (ICC TN Negative PCSXYZ, §9.2.7)
         Column sum: X=0.9642 Y=1.0000 Z=0.8249
         White point: X=0.9505 Y=1.0000 Z=1.0891
         Delta: dX=0.0137 dY=0.0000 dZ=0.2641 (tolerance=0.0500)
         [WARN] Colorant sum deviates from white point — round-trip accuracy affected — ICC TN §9.2.7
      [WARN]  1 non-conformance(s)

[H1173] CF-173: PCS XYZ Absorber Encoding
  [CF-173] PCS XYZ Absorber Encoding (ICC TN Negative PCSXYZ, §6.4.3)
         [OK] White point and luminance properly distinguish from absorber encoding
      [OK] Conformant

[H1174] CF-174: Lab Conversion Clipping Awareness
  [CF-174] Lab Conversion Clipping Awareness (ICC TN Negative PCSXYZ, §6.4)
         [OK] XYZ PCS profile with all non-negative matrix values
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
         Swept 10 tags: 9 OK, 1 warnings, 0 errors
         [OK] All 10 tags pass library Validate()
      [OK] Conformant

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
         Checked 10 tags for v2 compatibility
         [OK] All tag types compatible with profile version 2.x
      [OK] Conformant

[H1209] CF-209: Colorspace Channel Count vs LUT Dimensions
[CF-209] Colorspace Channel Count vs LUT Dimensions (ICC.1-2022-05 §7.2.6, §10.8-10.11)
         colorSpace channels=3, PCS channels=3
         No AToB/BToA LUT tags present
         [OK] Colorspace/PCS channel counts match LUT dimensions
      [OK] Conformant

[H1212] CF-212: textType Null Termination
[CF-212] textType Null Termination (ICC.1-2022-05 §10.24)
         cprt (copyright): "Copyright 2000 Adobe Systems Incorporated" (41 bytes)
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
         No mluc tags found
      [OK] Conformant

[H1225] CF-225: mluc Name Record String Alignment
[CF-225] mluc Name Record String Alignment (ICC.1-2022-05 §7.1, §10.13)
         No mluc tags with records found
      [OK] Conformant

[H1226] CF-226: mluc Size Inference Safety
[CF-226] mluc Size Inference Safety (ICC TN PSD §size)
         No mluc tags with records found
      [OK] Conformant

[H1227] CF-227: v4 Text Tag Unicode Migration
[CF-227] v4 Text Tag Unicode Migration (ICC.1-2022-05 S9)
         Profile is v2 -- mluc migration check not applicable
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
         Profile creation: 2000-08-11 19:51:59 (UTC)
         [OK] Date/time fields consistent with UTC encoding
      [OK] Conformant

[H1233] CF-233: colorantOrderTag Index Validation
[CF-233] colorantOrderTag Index Validation (ICC.1-2022-05 S9.2.11, S10.3)
         No colorantOrderTag present
      [OK] Conformant

[H1234] CF-234: v4 Perceptual PCS Reference Medium
[CF-234] v4 Perceptual PCS Reference Medium (ICC.1-2022-05 Annex D)
         v2 profile -- Perceptual PCS reference medium check N/A
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
         No multiLocalizedUnicodeType tags found
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
      [OK] Conformant

[H1276] CF-276: profileDescriptionTag Must Be mluc for v4+
[CF-276] profileDescriptionTag Must Be mluc for v4+ (ICC.1-2022-05 §9.2.44)
      [OK] Conformant

[H1277] CF-277: mediaWhitePointTag Must Be XYZType
[CF-277] mediaWhitePointTag Must Be XYZType (ICC.1-2022-05 §9.2.35)
         [OK] mediaWhitePointTag is XYZType
      [OK] Conformant

[H1278] CF-278: chromaticAdaptationTag Type
[CF-278] chromaticAdaptationTag Type (ICC.1-2022-05 §9.2.2)
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
         Profile version 2 — not v5, skipped
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
         Profile version 2 — not v5, skipped
         [OK] Not a v5 profile
      [OK] Conformant

[H1058] CF-058: Profile Sequence Identifier v5
[CF-058] Profile Sequence Identifier v5 (ICC.2-2023 §8)
         Profile version 2 — not v5, skipped
         [OK] Not a v5 profile
      [OK] Conformant

[H1059] CF-059: Colorimetric Intent Image State
[CF-059] Colorimetric Intent Image State (ICC.1-2022-05 §9.2.12)
         'ciis' (colorimetricIntentImageStateTag): not present — skipped
         [OK] No colorimetricIntentImageState tag
      [OK] Conformant

[H1095] CF-095: Non-Required Tag Identification
  [CF-095] Non-Required Tag Identification (ICC.1-2022-05 §8)
           Additional tag: 'bkpt' (0x626B7074)
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
           [OK] Creator signature present (0x41444245)
      [OK] Conformant

[H1119] CF-119: Profile Sequence Identifier
  [CF-119] Profile Sequence Identifier (ICC.1-2022-05 §8.6)
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
           Distinct data regions: 10
           Data coverage: 299 / 560 bytes (53.4%)
           Inter-region gaps: 0 (largest: 0 bytes)
           [OK] Tag data region layout conformant
      [OK] Conformant

[H1207] CF-207: mediaWhitePointTag Value Range
[CF-207] mediaWhitePointTag Value Range (ICC.1-2022-05 §10.27)
         wtpt: X=0.9505, Y=1.0000, Z=1.0891
         [OK] mediaWhitePointTag values conformant
      [OK] Conformant

[H1211] CF-211: AToB/BToA Tag Pair Completeness
[CF-211] AToB/BToA Tag Pair Completeness (ICC.1-2022-05 §9.2.1-9.2.2)
         No AToB/BToA LUT pairs present (profile may use Matrix/TRC)
         [OK] AToB/BToA tag pair completeness conformant
      [OK] Conformant

[H1258] CF-258: Display v4+ mediaWhitePointTag D50
[CF-258] Display v4+ mediaWhitePointTag D50 (ICC.1-2022-05 §8.4)
         Profile version < 4.0 — D50 mediaWhitePoint not mandated
         [OK] v2 profiles exempt from D50 requirement
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
         No chromaticAdaptationTag present — check not applicable
         [OK] No chad tag to validate
      [OK] Conformant

[H1069] CF-069: Matrix Column XYZ Count
[CF-069] Matrix Column Tag XYZ Count (ICC.1-2022-05 §9.2.7, §9.2.18, §9.2.31)
         [OK] Matrix column XYZ counts valid
      [OK] Conformant

[H1070] CF-070: Chad Array Count = 9
[CF-070] Chad s15Fixed16 Array Count 9 (ICC.1-2022-05 §9.2.10)
         No chromaticAdaptationTag present — check not applicable
         [OK] No chad tag to validate
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
         No parametricCurveType TRC tags found — check not applicable
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
         No chromaticAdaptationTag (or < 9 elements) — not applicable
         [OK] Skipped (no chad)
      [OK] Conformant

[H1179] CF-179: Chad D50 Identity
[CF-179] Chad D50-to-D50 Identity Check (ICC TN Partial Adaptation)
         No chad tag — not applicable
         [OK] Skipped (no chad)
      [OK] Conformant

[H1183] CF-183: Chad Column Normalization
[CF-183] Chad Column Normalization (ICC TN Partial Adaptation)
         No chromaticAdaptationTag (or < 9 elements) — not applicable
         [OK] Skipped (no chad)
      [OK] Conformant

  [INFO] Profile version 2 — v5/iccMAX checks skipped

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
           Avg step DeltaE00=1.1696  max step DeltaE00=4.2227  max curvature=0.6297
           Large discontinuities (>6.0 DeltaE00): 0
           [OK] Transform smoothness metrics recorded
      [OK] Conformant

[H1102] CF-102: Characterization Round-Trip
  [CF-102] Characterization Data Round-Trip (ICC.1-2022-05 §9.2.26)
           [N/A] No characterization data (targ) tag present
      N/A: No characterization data (targ) tag present
      [OK] Conformant


Deep Conformance Summary: 1 issue(s)

=======================================================================
PHASE 3: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /tmp/iccanalyzer-lOy6C4.icc

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
PHASE 5: PROFILE STRUCTURE DUMP
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
  Size:              0x00000230 (560 bytes)
  CMM Type:          'ADBE' (0x41444245)
  Version:           2.1.0.0 (0x02100000)
  Device Class:      DisplayClass
  Color Space:       RgbData (3 channels)
  PCS:               XYZData
  Date/Time:         2000-08-11 19:51:59
  Magic:             0x61637370 [OK]
  Platform:          Macintosh
  Profile Flags:     0x00000000
  Manufacturer:      'none' (0x6E6F6E65)
  Model:             '....' (0x00000000)
  Device Attribs:    0x0000000000000000
  Rendering Intent:  Perceptual (0)
  PCS Illuminant:    X=0.9642 Y=1.0000 Z=0.8249
  Creator:           'ADBE' (0x41444245)
  Profile ID:        (not set)

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
PHASE 6: TAG CONTENT ANALYSIS
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

--- 5I: V5/iccMAX Summary ---

  (Profile is v2/v4 — v5/iccMAX summary not applicable)

--- 5J: Version Classification & Capabilities ---

  Version Classification:
    ICC Version:       2.1.0
    Specification:     ICC.1 (v2.1+)
    Features:          lut8/lut16 only, no profileID
    Device Class:      DisplayClass
    Color Space:       RgbData (3 channels)
    Connection Space:  XYZData

  Transform Capabilities:
    AToB (device→PCS):   no
    BToA (PCS→device):   no
    TRC (matrix/gamma):  YES
    Gamut check:         no
    Chromatic adapt:     no
    Preview:             no


=======================================================================
CONFORMANCE AUDIT SUMMARY
=======================================================================

File: /tmp/iccanalyzer-lOy6C4.icc
Mode: Conformance (ICC specification audit)
Total Issues Detected: 2

[WARN] ANALYSIS COMPLETE - 2 issue(s) detected
  Review conformance findings above. Use --legacy for vulnerability analysis.


=======================================================================
IMAGE ANALYSIS SUMMARY
=======================================================================
Format:     TIFF
Dimensions: 32 × 16
Findings:   3
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
  Version:         0x02011313  (2.0.1)
  Device Class:    0x3C268689  '<&..'
  Color Space:     0x8DF54AF5  '..J.'
  PCS:             0x7DD5B1E4  '}...'
  Date/Time:       15163-15163-00 00:50857:33745
  Magic:           0x01010101  [INVALID]
  Platform:        0x01010101  '....'
  Flags:           0x8E6215FF [Embedded] [EmbeddedOnly]
  Manufacturer:    0x5D984398  '].C.'
  Model:           0x26262626  '&&&&'
  Dev Attributes:  0x1D1D1D1DC80A30E9 [Transparency]
  Rendering Intent:0xA275CED0  UNKNOWN
  PCS Illuminant:  X=20622.3809 Y=19482.1895 Z=15135.2588
  Creator:         0x453F3D48  'E?=H'
  Profile ID:      5757215785858585a200f0f500000000
  Reserved 100-127: NON-ZERO [VIOLATION]

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
2    0x73C9D3E8   's���'        0x5B5B3B5B   0x00000000   '----'        OOB offset
3    0xAF8E41BB   '��A�'        0xA4B16AB1   0xD669A4F2   '----'        OOB offset
4    0x2E51508C   '.QP�'        0x69694B69   0x9AC2ADC2   '----'        OOB offset
5    0x00000000   '    '        0xD6C4DCDD   0x182A67D9   '----'        OOB offset
6    0x8110EAFF   '���'        0xB5C3CACA   0xAC4017C5   '----'        OOB offset
7    0x03030303   ''        0x05050505   0x51015C5E   '----'        OOB offset
8    0x6F42107C   'oB|'        0x41206281   0xB8B8ACB8   '----'        OOB offset
9    0x68878989   'h���'        0x00000000   0x52525252   'MM  '        OOB size
10   0x23025355   '#SU'        0x23232323   0x49494949   '----'        OOB offset
11   0x6A949494   'j���'        0x01010101   0x1D1D1D1D   '----'        OOB offset
12   0x29484B4B   ')HKK'        0x03030303   0x6B433EFF   '----'        OOB offset
13   0x75886B88   'u�k�'        0x6B6B6B6B   0xABC792C7   '----'        OOB offset
14   0x4138B8BB   'A8��'        0x31313131   0x01010101   '----'        OOB offset
15   0xC3022DE3   '�-�'        0x8EFB75FB   0x9D9D319D   '----'        OOB offset
16   0xA1E037FA   '��7�'        0x98B1B1B1   0x3F703570   '----'        OOB offset
17   0x2B441444   '+DD'        0x03030303   0x6E771CF8   '----'        OOB offset
18   0x4F812081   'O� �'        0x29005E60   0xC8E0E0E0   '----'        OOB offset
19   0x5A9F519F   'Z�Q�'        0x7BB6B6B6   0x2F53718C   '----'        OOB offset
20   0x7E44B8BB   '~D��'        0x385261CF   0x4439687F   '----'        OOB offset
21   0x52525252   'RRRR'        0x5D2251D8   0x0A0A0A0A   '----'        OOB offset
22   0x2A39A3A6   '*9��'        0x3E3E1A8D   0x2B167779   '----'        OOB offset
23   0x01010101   ''        0x1A237D7F   0x84842084   '----'        OOB offset
24   0x2B0B3540   '+5@'        0xE4E3C1F2   0x12121212   '----'        OOB offset
25   0xAAA04EAE   '��N�'        0x15252525   0x04050505   '----'        OOB offset
26   0xD4D4C5D4   '����'        0x811B9295   0x3B644B64   '----'        OOB offset
27   0x0C0C030D   ''        0x676767DA   0x91917A91   '----'        OOB offset
28   0xE2E2ABE2   '���'        0x17016B6D   0x476F6F6F   '----'        OOB offset
29   0x0A0A0A0A   '



'        0x647F4B7F   0x6C517475   '----'        OOB offset
30   0x0D0D0D0D   ''        0x7C2ECFFF   0x1D1D1D1D   '----'        OOB offset
31   0x04040104   ''        0x01010101   0x06060206   '----'        OOB offset
32   0x14141414   ''        0x6661509F   0x8F00A3A6   '----'        OOB offset
33   0x15015E9F   '^�'        0x263E3E3E   0x01010101   '----'        OOB offset
34   0x0C161616   ''        0x36073E3F   0x00000000   '----'        OOB offset
35   0x33333333   '3333'        0x1600191A   0xD99EF2F5   '----'        OOB offset
36   0x579824FF   'W�$�'        0x00000000   0x80408E9F   'MM  '        OOB size
37   0x87851FF5   '���'        0x58939393   0x56563156   '----'        OOB offset
38   0x081B66FF   'f�'        0x5F666666   0x23232323   '----'        OOB offset
39   0xB1BFF8FA   '����'        0xE3E6C2E6   0x3F609BFF   '----'        OOB offset
40   0x2D2D2D2D   '----'        0x85EBEBEB   0x262604DD   '----'        OOB offset
41   0x0F1B1B1B   ''        0x02020202   0x34343434   '----'        OOB offset
42   0x4F01225C   'O"\'        0xB6734BFF   0x4D7F9BF2   '----'        OOB offset
43   0x58585858   'XXXX'        0x78A247C4   0x8700019D   '----'        OOB offset
44   0x993874B6   '�8t�'        0x7B7A7B7B   0x44009DA0   '----'        OOB offset
45   0x64176874   'dht'        0xBFBFB5BF   0x22221522   '----'        OOB offset
46   0x7D8C8C8C   '}���'        0x594036B6   0xB9D84BD8   '----'        OOB offset
47   0x2F2F2F2F   '////'        0x85959595   0x73B6ABB6   '----'        OOB offset
48   0x00000000   '    '        0x2F4A4A4A   0x42424242   '----'        OOB offset
49   0x9A695EE9   '�i^�'        0x01010101   0x40004A4B   '----'        OOB offset
50   0x4C82898A   'L���'        0x355D5D5D   0x955D16A5   '----'        OOB offset
51   0x20202020   '    '        0x1E1E1E1E   0x7A7A8485   '----'        OOB offset
52   0x92829798   '����'        0x10101010   0x68396B96   '----'        OOB offset
53   0x02020202   ''        0x5E2530DB   0x62626262   '----'        OOB offset
54   0x020200FE   '  '        0x15151515   0x783E8587   '----'        OOB offset
55   0xBED4BAD4   '�Ժ�'        0x6BA8A8A8   0x5324095F   '----'        OOB offset
56   0x526E6E6E   'Rnnn'        0x3B3B6BFC   0x29484848   '----'        OOB offset
57   0x00000000   '    '        0x669842A4   0x5F8257A3   '----'        OOB offset
58   0x5601A9EC   'V��'        0x536A7979   0x58926092   '----'        OOB offset
59   0x825013AD   '�P�'        0x56968BF0   0x8FB345B8   '----'        OOB offset
60   0x14191919   ''        0x0101979A   0x1C1C1C9D   '----'        OOB offset
61   0xB4C051DB   '��Q�'        0xBCA42AC4   0x85E8C6E8   '----'        OOB offset
62   0x61A35FA3   'a�_�'        0x07075B88   0x50505050   '----'        OOB offset
63   0x15090718   '	'        0x527B7B7B   0x4739424C   '----'        OOB offset
64   0x54545454   'TTTT'        0x373778CA   0x655454F7   '----'        OOB offset
65   0x8AAFAFAF   '����'        0x916D1A9D   0xCACA91CA   '----'        OOB offset
66   0x1A1A1A1A   ''        0x30014849   0xB5B557B5   '----'        OOB offset
67   0x3E000B68   '>   '        0x72208083   0x576868EA   '----'        OOB offset
68   0x26262626   '&&&&'        0x2401A1D9   0x3A2E2E3E   '----'        OOB offset
69   0xC7C03AC9   '��:�'        0x5A9E2F9E   0x3F007678   '----'        OOB offset
70   0xC2EC3BEC   '��;�'        0x3B3B3B3B   0xA79F9EFF   '----'        OOB offset
71   0xBE3C58FF   '�<X�'        0x01010101   0x7E805680   '----'        OOB offset
72   0x33333333   '3333'        0x2A2A2A2A   0x05050505   '----'        OOB offset
73   0x01010101   ''        0x5F839697   0x426839FF   '----'        OOB offset
74   0x785A8082   'xZ��'        0x57585858   0x622C6D6F   '----'        OOB offset
75   0x2F000838   '/   '        0x8A609597   0x3C615A61   '----'        OOB offset
76   0x6E6E6E6E   'nnnn'        0x28282828   0x49494949   '----'        OOB offset
77   0x000227CC   '    '        0x75A0A0A0   0x25252525   '----'        OOB offset
78   0x9E0095B8   '�   '        0x5A9CEDF4   0x6B244384   '----'        OOB offset
79   0x1722119D   '"�'        0x70687373   0x7E71CEF2   '----'        OOB offset
80   0xB26B20F6   '�k �'        0x26444444   0x4212294C   '----'        OOB offset
81   0x75B55BFE   'u�[�'        0x1D1D141D   0xB0B0B0B0   '----'        OOB offset
82   0x4E2D41C6   'N-A�'        0x5B97C7C9   0x21002526   '----'        OOB offset
83   0x494F4F4F   'IOOO'        0xCDC056F7   0x3B676767   '----'        OOB offset
84   0x05000606   '   '        0x73C46CDC   0x75118588   '----'        OOB offset
85   0x3A2E3D5D   ':.=]'        0xD0504EEE   0x4C4BA9AC   '----'        OOB offset
86   0x508E87F9   'P���'        0x79641881   0x8A0C55CC   '----'        OOB offset
87   0x00000000   '    '        0x0F1A1A1A   0x53472277   '----'        OOB offset
88   0x00000000   '    '        0x2B2B2B2B   0x18082F30   '----'        OOB offset
89   0x335BBCBF   '3[��'        0x83E0DEE0   0xA041ACFF   '----'        OOB offset
90   0x6D7F6E7F   'mn'        0x73B280B2   0xADD533FC   '----'        OOB offset
91   0x60606060   '````'        0x6E6E676E   0x424242F0   '----'        OOB offset
92   0x6E6E6E6E   'nnnn'        0x5C5C5C5C   0x87AF29AF   '----'        OOB offset
93   0x03030303   ''        0x34343434   0x1E1EE3FB   '----'        OOB offset
94   0x6E40417B   'n@A{'        0x93FF78FF   0x8F14A3A6   '----'        OOB offset
95   0x26260926   '&&	&'        0x50207CDA   0x5A95D2D5   '----'        OOB offset
96   0x355C5C5C   '5\\\'        0x44330C73   0x37371037   '----'        OOB offset
97   0x8B679597   '�g��'        0x01010101   0x01010101   '----'        OOB offset
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

[NOT RUN] Profile TRUNCATED — round-trip validation not run
       Header claims more bytes than file contains (CWE-125)
```

---

## LUT Text Export (`-xt`)

**Exit Code: 2**

```
Error reading ICC profile
Exported 0 text file(s) to /tmp/tmp.PrhicmAyou/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
