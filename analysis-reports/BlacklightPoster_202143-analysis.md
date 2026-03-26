# ICC Profile Analysis Report

**Profile**: `test-profiles/BlacklightPoster_202143.icc`
**File Size**: 16680 bytes
**SHA-256**: `4227ce8eff19f3224c74a386116ed559a610cbfbf8a2278d9dccaf925d1bfb10`
**File Type**: ColorSync color profile 2.1, type ADBE, Lab/Lab-abst device by ADBE, 16680 bytes, 7-11-2011 2:49:01, relative colorimetric "Blacklight Poster"
**Date**: 2026-03-26T16:57:44Z
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
  ICC PROFILE CONFORMANCE AUDIT
=======================================================================

File: /home/h02332/po/research/test-profiles/BlacklightPoster_202143.icc

[H173] Signature Conversion Shift Overflow (IccUtil.cpp signature formatting helpers)
      [WARN]  HEURISTIC: 15/15 FourCC signatures trigger UBSAN shift overflow in icGetSig()/icGetSigStr()/icGetColorSig()/icGetColorSigStr() — IccUtil.cpp:1088,1130,1167,1187,1228,1253
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

  Validation Status: CRITICAL ERROR — Profile is not usable

  [ERROR] AToB0Tag: - Incorrect number of input channels.

  Validation Summary: 1 error(s), 0 non-compliant, 0 warning(s), 0 info
  [WARN] 1 ICC spec conformance issue(s) detected


=======================================================================
PHASE 2: DEEP CONFORMANCE CHECKS (ICC.1/ICC.2)
=======================================================================

--- Header Conformance (CF-001..CF-015, CF-184..CF-187, CF-199..CF-201, CF-203, CF-206, CF-210, CF-214..CF-219) ---

[H1001] CF-001: Date/Time Month-Day Validity
[CF-001] Date/Time Month-Day Validity (ICC.1-2022-05 §7.2.8)
         Month=11, Day=7 — valid
         [OK] Date fields within range
      [OK] Conformant

[H1002] CF-002: Date/Time Leap Year Validation
[CF-002] Date/Time Leap Year Validation (ICC.1-2022-05 §7.2.8)
         Month=11 — leap year check not applicable
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
         renderingIntent=1 (Media-Relative Colorimetric)
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
         Header size: 16680 bytes, File size: 16680 bytes
         [OK] Profile size matches file size
      [OK] Conformant

[H1011] CF-011: Profile ID MD5 Verification
[CF-011] Profile ID MD5 Verification (ICC.1-2022-05 §7.2.18)
         Profile ID is all zeros — not computed
         [INFO] Profile ID not set — §7.2.18
      [OK] Conformant

[H1012] CF-012: Profile Class Signature
[CF-012] Profile Class Signature (ICC.1-2022-05 §7.2.5 Table 18)
         deviceClass='abst' (0x61627374)
         [OK] Valid v4 profile class
      [OK] Conformant

[H1013] CF-013: Data Colour Space Signature
[CF-013] Data Colour Space Signature (ICC.1-2022-05 §7.2.6 Table 19)
         colorSpace='Lab ' (0x4C616220) — Lab
         [OK] Valid colour space signature
      [OK] Conformant

[H1014] CF-014: PCS Field for Non-DeviceLink
[CF-014] PCS Field for Non-DeviceLink (ICC.1-2022-05 §7.2.7)
         PCS='Lab ' (0x4C616220)
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
         Profile size: 16680 bytes (JPEG limit: 16707345 bytes)
         Would require 1 APP2 segment(s) for JPEG embedding
         [OK] Profile fits within JPEG APP2 embedding limit
      [OK] Conformant

[H1216] CF-216: JP2 Restricted ICC Compliance
  [CF-216] JP2 Restricted ICC Compliance (ISO 15444-1 Annex I)
         Class 'abst' — JP2 requires Input ('scnr') class
         Color space 'Lab ' — JP2 supports only Gray/RGB
         [INFO] Profile not compatible with JP2 Restricted ICC method
      [OK] Conformant

[H1217] CF-217: JPX Any ICC Method Compliance
  [CF-217] JPX Any ICC Method Compliance (ISO 15444-2 Annex M)
         Class 'abst' — JPX Any ICC requires Input ('scnr') or Display ('mntr')
         LUT-based profile (AToB0Tag present, no Matrix/TRC tags)
         JPX Any ICC method requires Matrix/TRC profiles only
         [INFO] Profile not compatible with JPX Any ICC method
      [OK] Conformant

[H1218] CF-218: HEIF Restricted ICC Compatibility
  [CF-218] HEIF Restricted ICC Compatibility (ISO/IEC 14496-12)
         HEIF 'colr' compatible (v2 profile, ≤ v4)
         HEIF 'ricc' incompatible (color space 'Lab ')
         [OK] Profile compatible with HEIF embedding
      [OK] Conformant

[H1219] CF-219: Container Format Version Matrix
  [CF-219] Container Format Version Matrix (ICC TN Embedding §Table 1)
         Profile version: 2.x, class: abst
         PNG (ISO 15948): compatible (v2, per specification)
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
         [OK] 4/4 tags checked, all use permitted types
      [OK] Conformant

[H1021] CF-021: Tag Type Reserved Bytes Zero
[CF-021] Tag Type Reserved Bytes Zero (ICC.1-2022-05 §10)
         [OK] 4 tag(s) checked, all reserved bytes are zero
      [OK] Conformant

[H1022] CF-022: curveType Entry Count
[CF-022] curveType Entry Count Mode (ICC.1-2022-05 §10.6)
         No curveType tags found
         [OK] 0 curveType tag(s) checked, all consistent
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
         [OK] 1 XYZ tag(s) checked, all contain exactly 1 triplet
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
         [OK] All 1 XYZ triplets have valid values
      [OK] Conformant

[H1169] CF-169: Negative PCSXYZ Encoding Capability
  [CF-169] Negative PCSXYZ Encoding Capability (ICC TN Negative PCSXYZ §6.3.4.2)
         [OK] All 1 XYZ tags have non-negative values
      [OK] Conformant

[H1170] CF-170: Chromatic Adaptation Negative XYZ Consistency
  [CF-170] Chromatic Adaptation Negative XYZ Consistency (ICC TN Negative PCSXYZ, §9.2.10)
         Matrix column tags not all present — check not applicable
      [OK] Conformant

[H1171] CF-171: White Point Non-Negative Luminance
  [CF-171] White Point Non-Negative Luminance (ICC TN Negative PCSXYZ, §3.1.24)
         [OK] White point luminance values are non-negative
      [OK] Conformant

[H1172] CF-172: Colorant XYZ Sum White Point Consistency
  [CF-172] Colorant XYZ Sum White Point Consistency (ICC TN Negative PCSXYZ, §9.2.7)
         Not all matrix columns present — check not applicable
      [OK] Conformant

[H1173] CF-173: PCS XYZ Absorber Encoding
  [CF-173] PCS XYZ Absorber Encoding (ICC TN Negative PCSXYZ, §6.4.3)
         [OK] White point and luminance properly distinguish from absorber encoding
      [OK] Conformant

[H1174] CF-174: Lab Conversion Clipping Awareness
  [CF-174] Lab Conversion Clipping Awareness (ICC TN Negative PCSXYZ, §6.4)
         [OK] Lab PCS profile uses LUT model (no matrix columns)
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
         Swept 4 tags: 3 OK, 1 warnings, 0 errors
         [OK] All 4 tags pass library Validate()
      [OK] Conformant

[H1189] CF-189: Tag Type Recognition Coverage
  [CF-189] Tag Type Recognition Coverage (SampleICC §3 CheckTagTypes)
         4/4 tags have recognized type signatures
         [OK] All 4 tag types are recognized by the factory
      [OK] Conformant

[H1190] CF-190: Profile Legibility Gate
  [CF-190] Profile Legibility Gate (SampleICC §3 ReadValidate)
         [OK] Profile is legible: 4 tags parsed, all non-NULL
      [OK] Conformant

[H1208] CF-208: Tag Type Version Compatibility
[CF-208] Tag Type Version Compatibility (ICC.1-2022-05 §7.2.4, §10)
         Checked 4 tags for v2 compatibility
         [OK] All tag types compatible with profile version 2.x
      [OK] Conformant

[H1209] CF-209: Colorspace Channel Count vs LUT Dimensions
[CF-209] Colorspace Channel Count vs LUT Dimensions (ICC.1-2022-05 §7.2.6, §10.8-10.11)
         colorSpace channels=3, PCS channels=3
         AToB0 input channels=2, expected 3 (from colorSpace)
         [FAIL] AToB0 input channel mismatch — ICC.1-2022-05 §10.8-10.11
      [WARN]  1 non-conformance(s)

[H1212] CF-212: textType Null Termination
[CF-212] textType Null Termination (ICC.1-2022-05 §10.24)
         cprt (copyright): "Copyright 2011 Adobe Systems Inc." (33 bytes)
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
         AToB tags: 1, BToA tags: 0, class: 0x61627374
         [OK] Rendering intent dominance consistent with profile class
      [OK] Conformant

[H1230] CF-230: CIELAB Encoding Version Consistency
[CF-230] CIELAB Encoding Version Consistency (ICC.1-2022-05 S6.5.9)
         v2 profile with Lab PCS -- uses legacy encoding
      [OK] Conformant

[H1231] CF-231: LUT Processing Element Sequence
[CF-231] LUT Processing Element Sequence (ICC.1-2022-05 S10.10-10.11)
         [OK] All 1 LUT processing element sequences valid
      [OK] Conformant

[H1232] CF-232: Date/Time UTC and Temporal Consistency
[CF-232] Date/Time UTC and Temporal Consistency (ICC.1-2022-05 S7.2.8)
         Profile creation: 2011-11-07 02:49:01 (UTC)
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
         Rendering intent = 1 (not perceptual) — check not applicable
      [OK] Conformant

[H1264] CF-264: parametricCurveType Function Type Range
[CF-264] parametricCurveType Function Type Range (ICC.1-2022-05 §10.18)
         [OK] All parametricCurveType function types in range [0..4]
      [OK] Conformant

[H1265] CF-265: mluc Language/Country Code Validity
[CF-265] mluc Record Language/Country Code (ICC.1-2022-05 §10.15)
         No multiLocalizedUnicodeType tags found
         [OK] mluc language/country codes valid
      [OK] Conformant

[H1273] CF-273: Primary Colorant XYZ Values Positive
[CF-273] Primary Colorant XYZ Values Positive (ICC.1-2022-05 §10.28)
      [OK] Conformant

[H1274] CF-274: Primary Colorant Chromaticity Sum
[CF-274] Primary Colorant Chromaticity Sum (TN v4-matrix-entries)
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

[H1046] CF-046: Abstract Profile Required Tags
[CF-046] Abstract Profile Required Tags (ICC.1-2022-05 §8.8 Table 32)
         'A2B0' (AToB0Tag): present
         [OK] Abstract profile required tags present
      [OK] Conformant

[H1048] CF-048: Rendering Intent vs Transform Consistency
[CF-048] Rendering Intent Transform Consistency (ICC.1-2022-05 §7.2.15, §8)
         Declared rendering intent: 1 (Media-Relative Colorimetric)
         AToB1Tag: missing, BToA1Tag: missing
         [WARN] Intent 1 profile should have AToB1/BToA1 transforms — ICC.1-2022-05 §8
      [WARN]  1 non-conformance(s)

[H1049] CF-049: Matrix/TRC Profiles Must Use PCS XYZ
[CF-049] Matrix/TRC Profile PCS Must Be XYZ (ICC.1-2022-05 §8.3-8.4)
         No matrix/TRC tags detected — skipped
         [OK] Not a matrix/TRC profile
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
           Additional tag: 'A2B0' (0x41324230)
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
           Distinct data regions: 4
           Data coverage: 16494 / 16680 bytes (98.9%)
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
         Pair 0 (Perceptual): AToB ✓  BToA ✗ — missing inverse transform
         [FAIL] AToB0 (Perceptual) present without matching BToA0 (Perceptual) — ICC.1-2022-05 §9.2
      [WARN]  1 non-conformance(s)

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
      [OK] Conformant

[H1268] CF-268: Output Profile Color Space
[CF-268] Output Profile Color Space (ICC.1-2022-05 §6.3)
      [OK] Conformant

[H1269] CF-269: DeviceLink Data Color Space Matching
[CF-269] DeviceLink Data Color Space Matching (ICC.1-2022-05 §6.4)
      [OK] Conformant

[H1270] CF-270: Abstract Profile PCS
[CF-270] Abstract Profile PCS (ICC.1-2022-05 §6.6)
         [OK] Abstract profile PCS valid
      [OK] Conformant

[H1271] CF-271: NamedColor Profile PCS
[CF-271] NamedColor Profile PCS (ICC.1-2022-05 §6.7)
      [OK] Conformant

[H1272] CF-272: Matrix/TRC RGB Required Colorant Tags
[CF-272] Matrix/TRC RGB Required Colorant Tags (ICC.1-2022-05 §9.2.47)
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
         Tag 'AToB0' — input channels=2, expected=3
         [FAIL] Input channel count mismatch — ICC.1-2022-05 §10.8-10.11
      [WARN]  1 non-conformance(s)

[H1061] CF-061: LUT Output Channel Count
[CF-061] LUT Output Channel Count (ICC.1-2022-05 §10.8-10.11)
         [OK] LUT output channel counts valid
      [OK] Conformant

[H1062] CF-062: CLUT Grid Dimensionality
[CF-062] CLUT Grid Dimensionality (ICC.1-2022-05 §10.8-10.11)
         [OK] CLUT grid dimensions valid
      [OK] Conformant

[H1063] CF-063: lut8Type Fixed 256-Entry Tables
[CF-063] lut8Type Fixed Table Size 256 (ICC.1-2022-05 §10.9)
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
         No lut8/lut16 tags with matrix found — check not applicable
         [OK] lut8/16 matrix identity check passed
      [OK] Conformant

[H1068] CF-068: Chad Matrix Invertible
[CF-068] Chromatic Adaptation Matrix Invertible (ICC.1-2022-05 §9.2.10)
         No chromaticAdaptationTag present — check not applicable
         [OK] No chad tag to validate
      [OK] Conformant

[H1069] CF-069: Matrix Column XYZ Count
[CF-069] Matrix Column Tag XYZ Count (ICC.1-2022-05 §9.2.7, §9.2.18, §9.2.31)
         No matrix column tags present — check not applicable
         [OK] Matrix column XYZ counts valid
      [OK] Conformant

[H1070] CF-070: Chad Array Count = 9
[CF-070] Chad s15Fixed16 Array Count 9 (ICC.1-2022-05 §9.2.10)
         No chromaticAdaptationTag present — check not applicable
         [OK] No chad tag to validate
      [OK] Conformant

[H1071] CF-071: Curve Count vs Channel Match
[CF-071] Curve Count vs Channel Match (ICC.1-2022-05 §10.10-10.12)
         [OK] Curve counts match channel expectations
      [OK] Conformant

[H1072] CF-072: CLUT Output Value Range
[CF-072] CLUT Output Value Range (ICC.1-2022-05 §10.8-10.12)
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
         [OK] LUT dimensions are plausible
      [OK] Conformant

[H1076] CF-076: Curve Response Direction
[CF-076] Curve Response Direction (ICC.1-2022-05 §10.5)
         [OK] B curves are non-decreasing
      [OK] Conformant

[H1077] CF-077: CLUT Grid Size Plausibility
[CF-077] CLUT Grid Size Plausibility (ICC.1-2022-05 §10.8-10.12)
         [OK] CLUT grid sizes are plausible
      [OK] Conformant

[H1078] CF-078: MBB B-Curve Presence
[CF-078] MBB B-Curve Presence (ICC.1-2022-05 §10.10-10.12)
         No lutAToBType/lutBToAType tags found — check not applicable
         [OK] B curves present in all MBB tags
      [OK] Conformant

[H1079] CF-079: LUT Bit Depth Consistency
[CF-079] LUT Bit Depth Consistency (ICC.1-2022-05 §10.9-10.10)
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
         [OK] CLUT grid points in valid range [2,255]
      [OK] Conformant

[H1109] CF-109: Matrix Column Normalization
  [CF-109] Matrix Column Normalization (ICC.1-2022-05 §9.2.7)
         Not all matrix column tags present — check not applicable
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
    Non-conformance: AToB0 input channels (2) != colorSpace channels (3)
      [WARN]  1 non-conformance(s)

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
           [GAP] Matrix/TRC quality metrics require XYZ PCS
      GAP: Matrix/TRC quality metrics require XYZ PCS
      [OK] Conformant

[H1100] CF-100: Curve Invertibility
  [CF-100] Curve Invertibility Check (ICC.1-2022-05 §10.6)
           A2B0 A[0]: avg inv err=0.415005  max err=1.000000
           [WARN] A2B0 A[0] is non-monotonic — not reliably invertible
           A2B0 A[1]: avg inv err=0.511582  max err=1.000000
           [WARN] A2B0 A[1] is non-monotonic — not reliably invertible
           A2B0 A[2]: avg inv err=0.457964  max err=0.992188
           [WARN] A2B0 A[2] is non-monotonic — not reliably invertible
           A2B0 B[0]: avg inv err=0.000000  max err=0.000000
           A2B0 B[1]: avg inv err=0.000000  max err=0.000000
      [WARN]  3 non-conformance(s)

[H1101] CF-101: Transform Smoothness
  [CF-101] Transform Smoothness (ICC.1-2022-05 §10.8)
           Model: classic lut8/lut16 A2B0, samples: 192
           Avg step DeltaE00=16.3013  max step DeltaE00=115.6213  max curvature=77.0160
           Large discontinuities (>6.0 DeltaE00): 67
           [OK] Transform smoothness metrics recorded
      [OK] Conformant

[H1102] CF-102: Characterization Round-Trip
  [CF-102] Characterization Data Round-Trip (ICC.1-2022-05 §9.2.26)
           [N/A] No characterization data (targ) tag present
      N/A: No characterization data (targ) tag present
      [OK] Conformant


Deep Conformance Summary: 8 issue(s)

=======================================================================
PHASE 3: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/BlacklightPoster_202143.icc

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
PHASE 4: SIGNATURE ANALYSIS
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
PHASE 5: PROFILE STRUCTURE DUMP
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
PHASE 6: TAG CONTENT ANALYSIS
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
CONFORMANCE AUDIT SUMMARY
=======================================================================

File: /home/h02332/po/research/test-profiles/BlacklightPoster_202143.icc
Mode: Conformance (ICC specification audit)
Total Issues Detected: 11

[WARN] ANALYSIS COMPLETE - 11 issue(s) detected
  Review conformance findings above. Use --legacy for vulnerability analysis.
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

File: /home/h02332/po/research/test-profiles/BlacklightPoster_202143.icc
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
Profile: /home/h02332/po/research/test-profiles/BlacklightPoster_202143.icc

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
=== Extracting LUT data as text from: /home/h02332/po/research/test-profiles/BlacklightPoster_202143.icc ===

--- AToB0Tag (type: lut8Type) ---
  Channels: in=2 out=3
  Wrote curve A[0]: /tmp/tmp.Xg8EzdgwNy/BlacklightPoster_202143__AToB0Tag_curveA_0.txt (256 samples)
  Wrote curve A[1]: /tmp/tmp.Xg8EzdgwNy/BlacklightPoster_202143__AToB0Tag_curveA_1.txt (256 samples)
  Wrote curve A[2]: /tmp/tmp.Xg8EzdgwNy/BlacklightPoster_202143__AToB0Tag_curveA_2.txt (256 samples)
  Wrote CLUT: /tmp/tmp.Xg8EzdgwNy/BlacklightPoster_202143__AToB0Tag_clut.txt (289 entries × 3 outputs)
  Wrote curve B[0]: /tmp/tmp.Xg8EzdgwNy/BlacklightPoster_202143__AToB0Tag_curveB_0.txt (256 samples)
  Wrote curve B[1]: /tmp/tmp.Xg8EzdgwNy/BlacklightPoster_202143__AToB0Tag_curveB_1.txt (256 samples)

=== Exported 6 LUT component(s) ===
Exported 6 text file(s) to /tmp/tmp.Xg8EzdgwNy/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
