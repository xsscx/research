# ICC Profile Analysis Report

**Profile**: `test-profiles/calcUnderStack_asin.icc`
**File Size**: 3936 bytes
**SHA-256**: `75fc42038663df61ff0c4af64063b5e2235a70d8b3707bab51e24a34983f76be`
**File Type**: color profile 5.0, RGB/XYZ-spac device by ICC, 3936 bytes, 15-8-2018 10:22:18, relative colorimetric, PCS X=0xf354 Z=0x116cf, 0xadc26a85cda0de91 MD5 'calcUnderStack_asin'
**Date**: 2026-03-25T02:25:00Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 0 | Clean |
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

File: /home/h02332/po/research/test-profiles/calcUnderStack_asin.icc

[H173] Signature Conversion Shift Overflow (IccUtil.cpp signature formatting helpers)
      [WARN]  HEURISTIC: 20/20 FourCC signatures trigger UBSAN shift overflow in icGetSig()/icGetSigStr()/icGetColorSig()/icGetColorSigStr() — IccUtil.cpp:1088,1130,1167,1187,1228,1253
       CWE-190: sig<<=8 on uint32 with first byte non-zero produces value > UINT32_MAX (upstream iccDEV library pattern)

[H174] Half-Float Conversion Unsigned Underflow (IccUtil.cpp icF16toF)
      [WARN]  HEURISTIC: 2 half-float value(s) would trigger UBSAN unsigned-wrap in icF16toF() — IccUtil.cpp:665,677 / IccIO.cpp:328
       CWE-190: exponent rebias uses unsigned subtraction for non-zero half-floats with exponent < 15 (values below 1.0)
      tag 'svcn' svcn illuminantRange.start raw=0x3B8B
      tag 'svcn' svcn illuminantRange.end raw=0x08DD

[DEFENSE] H174 half-float fingerprint reaches upstream validation paths — skipping Validate() phase but continuing with safe deep conformance checks
=======================================================================
PHASE 1: ICC SPECIFICATION CONFORMANCE
=======================================================================

[NOT RUN] Library validation not run — half-float fields would hit upstream icF16toF UB during Validate()
       Deep conformance checks will continue using analyzer-owned safe conversions

=======================================================================
PHASE 2: DEEP CONFORMANCE CHECKS (ICC.1/ICC.2)
=======================================================================

--- Header Conformance (CF-001..CF-015, CF-184..CF-187, CF-199..CF-201, CF-203, CF-206, CF-210, CF-214..CF-219) ---

[H1001] CF-001: Date/Time Month-Day Validity
[CF-001] Date/Time Month-Day Validity (ICC.1-2022-05 §7.2.8)
         Month=8, Day=15 — valid
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
         renderingIntent=1 (Media-Relative Colorimetric)
         [OK] Rendering intent conformant
      [OK] Conformant

[H1006] CF-006: Version BCD Encoding
[CF-006] Profile Version BCD Encoding (ICC.1-2022-05 §7.2.4)
         version=0x05000000 → v5.0.0.0
         [OK] Version BCD encoding conformant
      [OK] Conformant

[H1007] CF-007: Primary Platform Signature
[CF-007] Primary Platform Signature (ICC.1-2022-05 §7.2.10 Table 20)
         platform=unspecified
         [OK] Platform signature conformant
      [OK] Conformant

[H1008] CF-008: PCS Illuminant D50 Values
[CF-008] PCS Illuminant D50 Precision (ICC.1-2022-05 §7.2.16)
         illuminant X=0.9505, Y=1.0000, Z=1.0891
         expected   X=0.9642, Y=1.0000, Z=0.8249 (D50)
         X deviation: 0.013700 (tolerance 0.0001)
         [FAIL] PCS illuminant X does not match D50 — ICC.1-2022-05 §7.2.16
         Z deviation: 0.264196 (tolerance 0.0001)
         [FAIL] PCS illuminant Z does not match D50 — ICC.1-2022-05 §7.2.16
      [WARN]  2 non-conformance(s)

[H1009] CF-009: Chromatic Adaptation Tag Requirement
[CF-009] Chromatic Adaptation Tag Requirement (ICC.1-2022-05 §8.2)
         Illuminant deviates from D50, chad tag: missing
         [FAIL] chad tag required when adopted white != D50 — ICC.1-2022-05 §8.2
      [WARN]  1 non-conformance(s)

[H1010] CF-010: Profile Size vs File Size
[CF-010] Profile Size vs File Size (ICC.1-2022-05 §7.2.2)
         Header size: 3936 bytes, File size: 3936 bytes
         [OK] Profile size matches file size
      [OK] Conformant

[H1011] CF-011: Profile ID MD5 Verification
[CF-011] Profile ID MD5 Verification (ICC.1-2022-05 §7.2.18)
         Profile ID: adc26a85cda0de91cdfd8d746ffc5c00 — MD5 verified
         [OK] Profile ID matches computed MD5
      [OK] Conformant

[H1012] CF-012: Profile Class Signature
[CF-012] Profile Class Signature (ICC.1-2022-05 §7.2.5 Table 18)
         deviceClass='spac' (0x73706163)
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
         manufacturer=0x00000000 — not specified (permitted)
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
         creator='ICC ' (0x49434320)
         [OK] Creator signature field conformant
      [OK] Conformant

[H1107] CF-107: Tag Table Ordering
  [CF-107] Tag Table Ordering (ICC.1-2022-05 §7.3.1)
         [OK] Tag table has no duplicate signatures
      [OK] Conformant

[H1121] CF-121: Illuminant Metadata Consistency
  [CF-121] Illuminant Metadata Consistency (ICC.1-2022-05 §7.2.16)
         V4 mediaWhitePointTag (0.9505, 1.0000, 1.0891) ≠ D50
         [FAIL] V4 wtpt must be D50 — §9.2.28
      [WARN]  1 non-conformance(s)

[H1122] CF-122: Profile Date/Time Plausibility
  [CF-122] Profile Date/Time Plausibility (ICC.1-2022-05 §7.2.8)
         [OK] Profile date/time is plausible
      [OK] Conformant

[H1184] CF-184: Profile ID v4+ Presence
[CF-184] Profile ID v4+ Presence (ICC.1-2022-05 §7.2.18, RFC 1321)
         Profile version: 5.x
         Profile ID: adc26a85cda0de91cdfd8d746ffc5c00
         [OK] v4+ profile has computed Profile ID
      [OK] Conformant

[H1185] CF-185: Profile ID Size Consistency
[CF-185] Profile ID Size Consistency (ICC.1-2022-05 §7.2.18, RFC 1321 §3.1)
         Header-declared size: 3936 bytes
         Actual file size: 3936 bytes
         [OK] Header size matches file size — MD5 input length consistent
      [OK] Conformant

[H1186] CF-186: Profile ID Entropy Analysis
[CF-186] Profile ID Entropy Analysis (RFC 1321, ICC.1-2022-05 §7.2.18)
         Profile ID: adc26a85cda0de91cdfd8d746ffc5c00
         Unique byte values: 15/16
         [OK] Profile ID entropy consistent with MD5 output
      [OK] Conformant

[H1187] CF-187: Embedded Profile ProfileID Chain
[CF-187] Embedded Profile ProfileID Chain (ICC TN Embedding + §7.2.18 + RFC 1321)
         No embedded profile tag (ICC5) present
         [OK] No embedding chain to validate
      [OK] Conformant

[H1199] CF-199: CMM Type Signature Registration
  [CF-199] CMM Type Signature Registration (ICC.1-2022-05 §7.2.3)
           cmmId=0x00000000 — no preferred CMM (permitted)
           [OK] CMM type conformant
      [OK] Conformant

[H1200] CF-200: Device Manufacturer/Model Signature
  [CF-200] Device Manufacturer/Model Signature (ICC.1-2022-05 §7.2.12-13)
           manufacturer=0x00000000 — not specified (permitted)
           model=0x00000000 — not specified (permitted)
           [OK] Device manufacturer/model conformant
      [OK] Conformant

[H1201] CF-201: Profile Creator Signature
  [CF-201] Profile Creator Signature (ICC.1-2022-05 §7.2.17)
           creator='ICC ' (0x49434320)
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
         Profile size: 3936 bytes (JPEG limit: 16707345 bytes)
         Would require 1 APP2 segment(s) for JPEG embedding
         [OK] Profile fits within JPEG APP2 embedding limit
      [OK] Conformant

[H1216] CF-216: JP2 Restricted ICC Compliance
  [CF-216] JP2 Restricted ICC Compliance (ISO 15444-1 Annex I)
         Class 'spac' — JP2 requires Input ('scnr') class
         Version 5.x — JP2 requires ICC v2 (ICC.1:1998-09)
         [INFO] Profile not compatible with JP2 Restricted ICC method
      [OK] Conformant

[H1217] CF-217: JPX Any ICC Method Compliance
  [CF-217] JPX Any ICC Method Compliance (ISO 15444-2 Annex M)
         Class 'spac' — JPX Any ICC requires Input ('scnr') or Display ('mntr')
         No Matrix/TRC tags found — JPX requires Matrix/TRC structure
         [INFO] Profile not compatible with JPX Any ICC method
      [OK] Conformant

[H1218] CF-218: HEIF Restricted ICC Compatibility
  [CF-218] HEIF Restricted ICC Compatibility (ISO/IEC 14496-12)
         HEIF 'colr' incompatible (v5 profile, requires ≤ v4)
         HEIF 'ricc' incompatible (color space 'RGB ', no Matrix/TRC)
         [INFO] Profile not compatible with any HEIF embedding method
      [OK] Conformant

[H1219] CF-219: Container Format Version Matrix
  [CF-219] Container Format Version Matrix (ICC TN Embedding §Table 1)
         Profile version: 5.x, class: spac
         No media formats currently support ICC v5 embedding
         Consider embedding v5 inside a v4 wrapper (ICC TN 04-2018)
         [INFO] v5 profile — no standard container format support
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
         Tag 'A2B1' (AToB1Tag): type 'mpet' — not in allowed set {'mAB ', 'mft1', 'mft2'}
         [FAIL] Type violation — ICC.1-2022-05 §9.2
         Tag 'B2A1' (BToA1Tag): type 'mpet' — not in allowed set {'mBA ', 'mft1', 'mft2'}
         [FAIL] Type violation — ICC.1-2022-05 §9.2
         Summary: 5/5 tags checked, 2 type violation(s)
      [WARN]  2 non-conformance(s)

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
         [OK] 2 mluc tag(s) checked, all structurally valid
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
         Tag 'A2B1': CRITICAL ERROR in Validate()
           Warning! -  - Unknown tag - Cannot validate input and output channels!
         Tag 'B2A1': CRITICAL ERROR in Validate()
           Warning! -  - Unknown tag - Cannot validate input and output channels!
         Swept 8 tags: 4 OK, 2 warnings, 2 errors
      [WARN]  2 non-conformance(s)

[H1189] CF-189: Tag Type Recognition Coverage
  [CF-189] Tag Type Recognition Coverage (SampleICC §3 CheckTagTypes)
         8/8 tags have recognized type signatures
         [OK] All 8 tag types are recognized by the factory
      [OK] Conformant

[H1190] CF-190: Profile Legibility Gate
  [CF-190] Profile Legibility Gate (SampleICC §3 ReadValidate)
         [OK] Profile is legible: 8 tags parsed, all non-NULL
      [OK] Conformant

[H1208] CF-208: Tag Type Version Compatibility
[CF-208] Tag Type Version Compatibility (ICC.1-2022-05 §7.2.4, §10)
         Profile version 5.x — all standard tag types permitted
         [OK] Version 5.x tag types unrestricted
      [OK] Conformant

[H1209] CF-209: Colorspace Channel Count vs LUT Dimensions
[CF-209] Colorspace Channel Count vs LUT Dimensions (ICC.1-2022-05 §7.2.6, §10.8-10.11)
         colorSpace channels=3, PCS channels=3
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
         AToB tags: 1, BToA tags: 1, class: 0x73706163
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
         Profile creation: 2018-08-15 10:22:18 (UTC)
         [OK] Date/time fields consistent with UTC encoding
      [OK] Conformant

[H1233] CF-233: colorantOrderTag Index Validation
[CF-233] colorantOrderTag Index Validation (ICC.1-2022-05 S9.2.11, S10.3)
         No colorantOrderTag present
      [OK] Conformant

[H1234] CF-234: v4 Perceptual PCS Reference Medium
[CF-234] v4 Perceptual PCS Reference Medium (ICC.1-2022-05 Annex D)
         No perceptual intent transforms -- reference medium check N/A
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
         Illuminant X=0.9505 Y=1.0000 Z=1.0891 — not D50, chad missing
         [FAIL] chromaticAdaptationTag required when adopted white ≠ D50 — ICC.1-2022-05 §8.2
      [WARN]  1 non-conformance(s)

[H1045] CF-045: ColorSpace Profile Required Tags
[CF-045] ColorSpace Profile Required Tags (ICC.1-2022-05 §8.7 Table 31)
         'A2B0' (AToB0Tag): missing
         [FAIL] AToB0Tag required — ICC.1-2022-05 §8.7 Table 31
         'B2A0' (BToA0Tag): missing
         [FAIL] BToA0Tag required — ICC.1-2022-05 §8.7 Table 31
      [WARN]  2 non-conformance(s)

[H1048] CF-048: Rendering Intent vs Transform Consistency
[CF-048] Rendering Intent Transform Consistency (ICC.1-2022-05 §7.2.15, §8)
         Declared rendering intent: 1 (Media-Relative Colorimetric)
         AToB1Tag: present
         BToA1Tag: present
         [OK] Rendering intent consistent with transform tags
      [OK] Conformant

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
         AToB1Tag + BToA1Tag: paired (intent 1)
         [OK] All transform tag pairs consistent
      [OK] Conformant

[H1053] CF-053: CICP Tag Class Restriction
[CF-053] cicpTag Class Restriction (ICC.1-2022-05 §9.2.11)
         'cicp' (cicpTag): not present — no restriction check needed
         [OK] No cicpTag to validate
      [OK] Conformant

[H1054] CF-054: v5 Spectral Required Tags
[CF-054] v5 Spectral Required Tags (ICC.2-2023 §8)
         v5 profile with non-spectral PCS — skipped
         [OK] PCS is not spectral
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
         'meta' (metaDataTag): not present — no dictionary to validate
         [OK] No metaDataTag found
      [OK] Conformant

[H1058] CF-058: Profile Sequence Identifier v5
[CF-058] Profile Sequence Identifier v5 (ICC.2-2023 §8)
         Profile class is not DeviceLink — skipped
         [OK] Not a DeviceLink profile
      [OK] Conformant

[H1059] CF-059: Colorimetric Intent Image State
[CF-059] Colorimetric Intent Image State (ICC.1-2022-05 §9.2.12)
         'ciis' (colorimetricIntentImageStateTag): not present — skipped
         [OK] No colorimetricIntentImageState tag
      [OK] Conformant

[H1095] CF-095: Non-Required Tag Identification
  [CF-095] Non-Required Tag Identification (ICC.1-2022-05 §8)
           Additional tag: 'A2B1' (0x41324231)
           Additional tag: 'B2A1' (0x42324131)
           Additional tag: 'c2sp' (0x63327370)
           Additional tag: 's2cp' (0x73326370)
           Additional tag: 'svcn' (0x7376636E)
           [INFO] 5 non-required tag(s) present
      [OK] Conformant

[H1096] CF-096: Private Tag Signature Range
  [CF-096] Private Tag Signature Range (ICC.1-2022-05 §9)
           Private tag 'c2sp' (0x63327370) — printable signature
           Private tag 's2cp' (0x73326370) — printable signature
           Private tag 'svcn' (0x7376636E) — printable signature
           [OK] 3 private tag(s) — all use printable 4-char signatures
      [OK] Conformant

[H1097] CF-097: Private Tag Documentation
  [CF-097] Private Tag Documentation (ICC.1-2022-05 §9)
           Undocumented private tag: 'c2sp' (0x63327370)
           Undocumented private tag: 's2cp' (0x73326370)
           Undocumented private tag: 'svcn' (0x7376636E)
           [INFO] 3 undocumented private tag(s)
      [WARN]  3 non-conformance(s)

[H1098] CF-098: Undocumented Private Tags
  [CF-098] Undocumented Private Tag Identification (ICC.1-2022-05 §9)
           Unrecognized: 'c2sp' (0x63327370) size=84
           Unrecognized: 's2cp' (0x73326370) size=84
           Unrecognized: 'svcn' (0x7376636E) size=1356
           [INFO] 3 unrecognized tag(s) — may require vendor documentation
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
           V5 profile with non-D50 white point missing chromaticAdaptationTag
           [FAIL] V4+ requires chad when adopted white ≠ D50 — §8
      [WARN]  1 non-conformance(s)

[H1117] CF-117: Rendering Intent Tags per Class
  [CF-117] Rendering Intent Tags per Class (ICC.1-2022-05 §8.3-8.5)
           [OK] Rendering intent tags appropriate for profile class
      [OK] Conformant

[H1118] CF-118: Private Tag Creator Signature
  [CF-118] Private Tag Creator Signature (ICC.1-2022-05 §9)
           [OK] Creator signature present (0x49434320)
      [OK] Conformant

[H1119] CF-119: Profile Sequence Identifier
  [CF-119] Profile Sequence Identifier (ICC.1-2022-05 §8.6)
           V5 profile without profileSequenceIdentifierTag
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
           Data coverage: 3704 / 3936 bytes (94.1%)
           Inter-region gaps: 0 (largest: 0 bytes)
           [OK] Tag data region layout conformant
      [OK] Conformant

[H1207] CF-207: mediaWhitePointTag Value Range
[CF-207] mediaWhitePointTag Value Range (ICC.1-2022-05 §10.27)
         wtpt: X=0.9505, Y=1.0000, Z=1.0891
         v4 non-DeviceLink: wtpt should be D50 (0.9642, 1.0, 0.8249)
         deviation: ΔX=0.0137, ΔY=0.0000, ΔZ=0.2642
         [FAIL] v4+ non-DeviceLink wtpt must be D50 — ICC.1-2022-05 §9.2.28
      [WARN]  1 non-conformance(s)

[H1211] CF-211: AToB/BToA Tag Pair Completeness
[CF-211] AToB/BToA Tag Pair Completeness (ICC.1-2022-05 §9.2.1-9.2.2)
         Pair 1 (Relative Colorimetric): AToB ✓  BToA ✓
         [OK] AToB/BToA tag pair completeness conformant
      [OK] Conformant

[H1258] CF-258: Display v4+ mediaWhitePointTag D50
[CF-258] Display v4+ mediaWhitePointTag D50 (ICC.1-2022-05 §8.4)
         Not a Display profile — D50 mediaWhitePoint applies only to mntr
         [OK] Non-display class exempt
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
         [OK] LUT input channel counts valid
      [OK] Conformant

[H1061] CF-061: LUT Output Channel Count
[CF-061] LUT Output Channel Count (ICC.1-2022-05 §10.8-10.11)
         [OK] LUT output channel counts valid
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

[H1080] CF-080: Spectral PCS Signature
[CF-080] Spectral PCS Signature (ICC.2-2023 §7.2.22)
         spectralPCS=0x00000000 (not set)
         [OK] No spectral PCS — field unused
      [OK] Conformant

[H1081] CF-081: Spectral PCS Range
[CF-081] Spectral PCS Range Validity (ICC.2-2023 §7.2.23)
         No spectral PCS set — range check not applicable
         [OK] Skipped (no spectral PCS)
      [OK] Conformant

[H1082] CF-082: PCC Tags Required
[CF-082] PCC Tags Required When Spectral (ICC.2-2023 §8)
         No spectral PCS — PCC tag requirement not applicable
         [OK] Skipped (no spectral PCS)
      [OK] Conformant

[H1083] CF-083: MCS Signature
[CF-083] MCS Signature Encoding (ICC.2-2023 §7.2.25)
         mcs=0x00000000 (not set — no MCS)
         [OK] MCS field unused
      [OK] Conformant

[H1084] CF-084: Profile Sub-Class
[CF-084] Profile Sub-Class Signature (ICC.2-2023 §7.2.26)
         deviceSubClass=0x00000000 (not set)
         [OK] No sub-class defined (default)
      [OK] Conformant

[H1085] CF-085: V5 Version BCD
[CF-085] Version Field 5.x BCD (ICC.2-2023 §7.2.4)
         version=0x05000000 → 5.0.0 (bytes 10-11: 0x0000)
         [OK] Version 5.0.0 — valid BCD encoding
      [OK] Conformant

[H1086] CF-086: Extended Attributes
[CF-086] Extended Attribute Bits (ICC.2-2023 §7.2.14)
         attributes=0x0000000000000000
         Bit 0 (Transparency): Reflective
         Bit 1 (Matte):        Glossy
         Bit 2 (Polarity):     Positive
         Bit 3 (Colour):       Colour
         [OK] Attribute bits reported (informational)
      [OK] Conformant

[H1087] CF-087: MPE Element Signature
[CF-087] MPE Element Signature Valid (ICC.2-2023 §10.x)
         Scanned 4 MPE tag(s), 4 element(s) total
         [OK] All 4 MPE element signatures recognized
      [OK] Conformant

[H1088] CF-088: Calculator Stack Structure
[CF-088] Calculator Element Stack Structure (ICC.2-2023 §10.x)
         Tag 'A2B1' element 0: Calculator in=3 out=3
         Tag 'B2A1' element 0: Calculator in=3 out=3
         Found 2 calculator element(s)
         [OK] Calculator element(s) structurally valid
      [OK] Conformant

[H1089] CF-089: Spectral Wavelength Range
[CF-089] Spectral Wavelength Range (ICC.2-2023 §7.2.23)
         No spectral PCS — wavelength range check not applicable
         [OK] Skipped (no spectral PCS)
      [OK] Conformant

[H1090] CF-090: Spectral Illuminant Consistency
[CF-090] Spectral Illuminant/Observer Consistency (ICC.2-2023 §7.2.17)
         [N/A] No spectral PCS — not applicable
      [OK] Conformant

[H1113] CF-113: Spectral Range Physical Bounds
  [CF-113] Spectral Range Physical Bounds (ICC.2-2023 §7.2.23)
         No spectral range defined — check not applicable
      [OK] Conformant

[H1114] CF-114: MCS Colour Space Consistency
  [CF-114] MCS Colour Space Consistency (ICC.2-2023 §7.2.19)
         No MCS data — check not applicable
      [OK] Conformant

[H1115] CF-115: Calculator Element Complexity
  [CF-115] Calculator Element Complexity (ICC.2-2023 §10.2.6)
         [OK] 2 calculator(s), 2 total sub-elements
      [OK] Conformant

[H1137] CF-137: MultiplexDefaultValues Type
  [CF-137] MultiplexDefaultValues Tag Type (ICC.2-2019 §9.2.84 Errata)
         No multiplexDefaultValuesTag ('mdv ') — check not applicable
      [OK] Conformant

[H1138] CF-138: Embedded Height Image Data Length
  [CF-138] Embedded Height Image Data Length (ICC.2-2019 §10.2.6 Errata)
         No embeddedHeightImageType tags — check not applicable
      [OK] Conformant

[H1139] CF-139: Embedded Normal Image Data Length
  [CF-139] Embedded Normal Image Data Length (ICC.2-2019 §10.2.7 Errata)
         No embeddedNormalImageType tags — check not applicable
      [OK] Conformant

[H1140] CF-140: GBD Vertex Count Field
  [CF-140] GBD Vertex Count Field (ICC.2-2019 §10.2.11 Errata)
         No gamutBoundaryDescType tags — check not applicable
      [OK] Conformant

[H1141] CF-141: Sparse Matrix Array Count
  [CF-141] Sparse Matrix Array Count Field (ICC.2-2019 §10.2.20 Errata)
         No sparseMatrixArrayType tags — check not applicable
      [OK] Conformant

[H1142] CF-142: Vector-Or Signature Alignment
  [CF-142] Calculator Vector-Or Signature (ICC.2-2019 §11.2.1.9 Errata)
         No calculator vector-or operations — check not applicable
      [OK] Conformant

[H1143] CF-143: Measurement Tag Struct Type
  [CF-143] Measurement Tag Structure Type (ICC.2-2019 §9.2.86/87 Errata)
         No measurement struct tags — check not applicable
      [OK] Conformant

[H1144] CF-144: Extended Range PCS Flag Consistency
[CF-144] Extended Range PCS Flag Consistency (ICC.2-2023 §7.2.13)
         flags=0x00000000 — Extended Range PCS bit (3) not set
         [OK] Check not applicable — no extended range PCS
      [OK] Conformant

[H1145] CF-145: Extended Range PCS + Spectral Co-existence
[CF-145] Extended Range PCS + Spectral Co-existence (ICS-ExtendedRange Part 1 §6.2)
         Extended Range PCS not set — check not applicable
      [OK] Conformant

[H1146] CF-146: Extended Range Class Restriction
[CF-146] Extended Range Class Restriction (ICS-ExtendedRange Table 1)
         Extended Range PCS not set — check not applicable
      [OK] Conformant

[H1147] CF-147: Extended Range Colorimetric Intent Required
[CF-147] Extended Range Colorimetric Intent Required (ICS-ExtendedRange Table 4)
         Extended Range PCS not set — check not applicable
      [OK] Conformant

[H1148] CF-148: Extended Range LUT multiProcessElementsType
[CF-148] Extended Range LUT multiProcessElementsType (ICS-ExtendedRange Table 4)
         Extended Range PCS not set — check not applicable
      [OK] Conformant

[H1149] CF-149: Extended Output Profile Class
[CF-149] Extended Output Profile Class (ICS-ExtendedOutput Table 11)
         No spectral PCS — extended output ICS check not applicable
      [OK] Conformant

[H1150] CF-150: Extended Output Gamut Boundary Tag
[CF-150] Extended Output Gamut Boundary Tag (ICS-ExtendedOutput Table 13)
         Not an output class profile — check not applicable
      [OK] Conformant

[H1151] CF-151: Extended Output mediaWhitePoint Range
[CF-151] Extended Output mediaWhitePoint Range (ICS-ExtendedOutput Table 12)
         Not an output class profile — check not applicable
      [OK] Conformant

[H1152] CF-152: Extended Output AToB/BToA/DToB Completeness
[CF-152] Extended Output AToB/BToA/DToB Completeness (ICS-ExtendedOutput Table 12)
         Not an output class with spectral PCS — check not applicable
      [OK] Conformant

[H1191] CF-191: ICS Sub-Class Signature Registry
[CF-191] ICS Sub-Class Signature Registry (ICC WP-57 §ICS Registration)
         deviceSubClass not set — no ICS sub-class declared
         [OK] No sub-class (standard ICC.2 profile)
      [OK] Conformant

[H1192] CF-192: Colorimetric ICS Required Tags
[CF-192] Colorimetric ICS Required Tags (ICS-Colorimetric-Part1 §6)
         Sub-class is not 'pcc ' — check not applicable
      [OK] Conformant

[H1193] CF-193: Colorimetric ICS PCC Matrix Restriction
[CF-193] Colorimetric ICS PCC Matrix Restriction (ICS-Colorimetric-Part1 §7)
         Sub-class is not 'pcc ' — check not applicable
      [OK] Conformant

[H1194] CF-194: Spectral Reflectance ICS Required Tags
[CF-194] Spectral Reflectance ICS Required Tags (ICS-SpectralReflectance-Part1 §6)
         Sub-class is not 'sref' — check not applicable
      [OK] Conformant

[H1195] CF-195: Extended Dynamic Range Radiance White Point
[CF-195] Extended Dynamic Range Radiance White Point (ICS-ExtendedRange §5.2)
         Extended Range PCS not set — check not applicable
      [OK] Conformant

[H1196] CF-196: ICS MPE Calculator Restriction
[CF-196] ICS MPE Calculator Restriction (ICC WP-57 Part 1 vs Part 2)
         No ICS sub-class — check not applicable
      [OK] Conformant

[H1197] CF-197: ICS PCC Transform Pair Completeness
[CF-197] ICS PCC Transform Pair Completeness (ICC WP-57 §PCC Transforms)
         [OK] Both c2sp and s2cp present — transform pair complete
      [OK] Conformant

[H1198] CF-198: Extended Range Sub-Class Validation
[CF-198] Extended Range Sub-Class Validation (ICS-ExtendedRange §4)
         Sub-class is not 'xrng' — check not applicable
      [OK] Conformant

[H1235] CF-235: xrng Data Colour Space Restriction
[CF-235] xrng Data Colour Space Restriction (ICS-ExtRange-Part1 Table 3)
         Profile sub-class is not 'xrng' -- check N/A
      [OK] Conformant

[H1236] CF-236: xrng Colorimetric PCS Constraint
[CF-236] xrng Colorimetric PCS Constraint (ICS-ExtRange-Part1 Table 3)
         Profile sub-class is not 'xrng' -- check N/A
      [OK] Conformant

[H1237] CF-237: xrng Required Tag Completeness
[CF-237] xrng Required Tag Completeness (ICS-ExtRange-Part1 Table 4)
         Profile sub-class is not 'xrng' -- check N/A
      [OK] Conformant

[H1238] CF-238: xrng Header Field Restrictions
[CF-238] xrng Header Field Restrictions (ICS-ExtRange-Part1 Table 3)
         Profile sub-class is not 'xrng' -- check N/A
      [OK] Conformant

[H1239] CF-239: xrng Optional Tag Type Validation
[CF-239] xrng Optional Tag Type Validation (ICS-ExtRange-Part1 Table 5)
         Profile sub-class is not 'xrng' -- check N/A
      [OK] Conformant

[H1240] CF-240: xrng Transform Channel Dimensions
[CF-240] xrng Transform Channel Dimensions (ICS-ExtRange-Part1 S5.2)
         Profile sub-class is not 'xrng' -- check N/A
      [OK] Conformant

[H1241] CF-241: xrng mediaWhitePointTag Absolute Radiance
[CF-241] xrng mediaWhitePointTag Absolute Radiance (ICS-ExtRange-Part1 Table 4)
         Profile sub-class is not 'xrng' -- check N/A
      [OK] Conformant

[H1242] CF-242: xrng Workflow Connection Consistency
[CF-242] xrng Workflow Connection Consistency (ICS-ExtRange-Part1 S5.2.3)
         Profile sub-class is not 'xrng' -- check N/A
      [OK] Conformant

[H1153] CF-153: Embedded Profile Tag Presence
[CF-153] Embedded Profile Tag Presence (ICC TN Embedding §Embedded profile tag)
         No 'ICC5' embedded profile tag found
         [OK] Check not applicable — no embedded ICC.2 profile
      [OK] Conformant

[H1154] CF-154: Embedded Profile Version Bridging
[CF-154] Embedded Profile Version Bridging (ICC TN Embedding §ICC.2 Profile header)
         No embedded profile — check not applicable
      [OK] Conformant

[H1155] CF-155: Embedded Profile Device Class Match
[CF-155] Embedded Profile Device Class Match (ICC TN Embedding §Processing)
         No embedded profile — check not applicable
      [OK] Conformant

[H1156] CF-156: Embedded Profile Header Flags
[CF-156] Embedded Profile Header Flags (ICC TN Embedding §ICC.2 Profile header)
         No embedded profile — check not applicable
      [OK] Conformant

[H1157] CF-157: Embedded Profile Recursive Depth
[CF-157] Embedded Profile Recursive Depth (Security: anti-bomb)
         No embedded profile — check not applicable
      [OK] Conformant

[H1158] CF-158: Embedded Profile Size Bounds
[CF-158] Embedded Profile Size Bounds (Security: size validation)
         No embedded profile — check not applicable
      [OK] Conformant

[H1175] CF-175: Embedded Profile PCS Compatibility
[CF-175] Embedded Profile PCS Compatibility (ICC TN Embedding §Processing)
         No embedded profile — check not applicable
      [OK] Conformant

[H1176] CF-176: Embedded Profile Tag Reserved Bytes
[CF-176] Embedded Profile Tag Reserved Bytes (ICC TN Embedding Table 1)
         No embedded profile — check not applicable
      [OK] Conformant

[H1177] CF-177: Embedded Profile Data Integrity
[CF-177] Embedded Profile Data Integrity (ICC TN Embedding §Embedding)
         No embedded profile — check not applicable
      [OK] Conformant

[H1180] CF-180: PCC Complete Adaptation
[CF-180] PCC Complete Adaptation Principle (ICC TN Partial Adaptation)
         Both c2sp and s2cp present — complete PCC transform pair
         Profile should perform complete adaptation (D=1.0) in these transforms
         CMM should apply partial adaptation factor externally per ICC TN
         [OK] PCC transform pair complete — adaptation architecture conformant
      [OK] Conformant

[H1181] CF-181: PCC Illuminant-Chad Consistency
[CF-181] PCC Illuminant-Chad Consistency (ICC TN Partial Adaptation)
         PCC illuminant type: 0x00000002
         PCC observer type: 0x00000001
         PCC illuminant is not D50 but no chad tag present
         [WARN] Non-D50 PCC illuminant without chad — adaptation may be incomplete
      [WARN]  1 non-conformance(s)

[H1182] CF-182: PCC Observer Standard
[CF-182] PCC Observer Standard Compliance (ICC TN Partial Adaptation)
         Observer: CIE 1931 2-degree (standard)
         [OK] PCC observer is a recognized standard
      [OK] Conformant

[H1159] CF-159: Dictionary Name Uniqueness
[CF-159] Dictionary Name Uniqueness (ICC.2-2023 §10.2.6)
         No dictType tags found — check not applicable
      [OK] Conformant

[H1160] CF-160: Dictionary Name Non-Zero
[CF-160] Dictionary Name Non-Zero (ICC.2-2023 §10.2.6)
         No dictType tags found — check not applicable
      [OK] Conformant

[H1161] CF-161: Dictionary Record Length Alignment
[CF-161] Dictionary Record Length Alignment (ICC.2-2023 §10.2.6 Table 40)
         No dictType tags found — check not applicable
      [OK] Conformant

[H1162] CF-162: Dictionary Entry Count Bounds
[CF-162] Dictionary Entry Count Bounds (ICC.2-2023 §10.2.6)
         No dictType tags found — check not applicable
      [OK] Conformant

[H1257] CF-257: Spectral Range Step Count
      [OK] Conformant

[H1284] CF-284: BRDF Spectral Parameter Tag Type
  [CF-284] BRDF Spectral Parameter Tag Type (ICC.2-2023 §9.2.10-13)
         No BRDF spectral parameter tags — not applicable
      [OK] Conformant

[H1285] CF-285: BRDF Tag Presence Consistency
  [CF-285] BRDF Tag Presence Consistency (ICC.2-2023 §9.2.10)
         No BRDF tags — not applicable
      [OK] Conformant

[H1286] CF-286: GBD Triangle-Vertex Consistency
  [CF-286] GBD Triangle-Vertex Consistency (ICC.2-2023 §10.2.11)
         No GBD tags — not applicable
      [OK] Conformant

[H1287] CF-287: GBD Channel Count Plausibility
  [CF-287] GBD Channel Count Plausibility (ICC.2-2023 §10.2.11)
         No GBD tags — not applicable
      [OK] Conformant

[H1288] CF-288: Spectral Data Info Bi-Spectral Consistency
  [CF-288] Spectral Data Info Bi-Spectral Consistency (ICC.2-2023 §9.2.84)
         No spectralDataInfoTag — not applicable
      [OK] Conformant

[H1289] CF-289: Spectral Viewing Conditions Illuminant Bounds
  [CF-289] Spectral Viewing Conditions Illuminant Bounds (ICC.2-2023 §10.2.30)
         Illuminant XYZ: (95.0500, 100.0000, 108.9100)
         [OK] Spectral viewing conditions illuminant values plausible
      [OK] Conformant

[H1290] CF-290: Material Default Values Tag Presence
  [CF-290] Material Default Values Tag Presence (ICC.2-2023 §9.2.47)
         Profile class is not material — not applicable
      [OK] Conformant

[H1291] CF-291: Spectral White Point XYZ Range
  [CF-291] Spectral White Point XYZ Range (ICC.2-2023 §9.2.85)
         No spectralWhitePointTag — not applicable
      [OK] Conformant

[H1292] CF-292: MPE Chain I/O Channel Consistency
  [CF-292] MPE Element Chain I/O Channel Consistency (ICC.2-2023 §10.2.17)
         No multi-element MPE tags — not applicable
      [OK] Conformant

[H1293] CF-293: MPE Container I/O vs First/Last Element
  [CF-293] MPE Container I/O vs First/Last Element (ICC.2-2023 §10.2.17)
         [OK] MPE container channels match first/last elements (4 tags)
      [OK] Conformant

[H1294] CF-294: MPE ACS Boundary Element Pairing
  [CF-294] MPE ACS Boundary Element Pairing (ICC.2-2023 §10.2.1-2)
         No MPE tags with ACS elements — not applicable
      [OK] Conformant

[H1295] CF-295: MPE Element Type Version Compatibility
  [CF-295] MPE Element Type Version Compatibility (ICC.2-2023 §10.2.17)
         [OK] All 4 MPE elements version-compatible with v5
      [OK] Conformant

[H1296] CF-296: MPE Empty Container Validation
  [CF-296] MPE Empty Container Validation (ICC.2-2023 §10.2.17)
         No empty MPE containers — not applicable
      [OK] Conformant

[H1297] CF-297: MPE CurveSet Element Channel Count
  [CF-297] MPE CurveSet Element Channel Count (ICC.2-2023 §10.2.5)
         No CurveSet elements — not applicable
      [OK] Conformant

[H1298] CF-298: MPE Matrix Element Dimension
  [CF-298] MPE Matrix Element Dimension Validation (ICC.2-2023 §10.2.9)
         [OK] All 2 Matrix elements have valid dimensions
      [OK] Conformant

[H1299] CF-299: MPE CLUT Element Grid Dimension
  [CF-299] MPE CLUT Element Grid Dimension (ICC.2-2023 §10.2.3)
         No CLUT/ExtCLUT elements — not applicable
      [OK] Conformant

[H1300] CF-300: MPE Tag vs Color Space Channels
  [CF-300] MPE Tag vs Color Space Channel Consistency (ICC.2-2023 §10.2.17)
         [OK] 2 MPE AToB/BToA tags have correct channel counts
      [OK] Conformant

[H1301] CF-301: Measurement Struct tagStructType Enforcement
  [CF-301] Measurement Struct tagStructType Enforcement (ICC.2-2019 Errata §9.2.86/87)
         No measurement-related tags — not applicable
      [OK] Conformant

[H1302] CF-302: Measurement Struct Member Completeness
  [CF-302] Measurement Struct Member Completeness (ICC.2-2019 Errata §9.2.86/87)
         No measurementInfoStruct tags — not applicable
      [OK] Conformant

[H1303] CF-303: Spectral Data Array Type Restriction
  [CF-303] Spectral Data Array Type Restriction (ICC.2-2019 Errata §9.2.84)
         No spectral data tags — not applicable
      [OK] Conformant

[H1304] CF-304: v5 Text Tag multiLocalizedUnicodeType
  [CF-304] v5 Text Tag multiLocalizedUnicodeType (ICC.2-2019 Errata §10.2.5)
         [OK] 2 text tag(s) use multiLocalizedUnicodeType per errata
      [OK] Conformant

[H1305] CF-305: multiProcessElementsType Nomenclature Audit
  [CF-305] multiProcessElementsType Nomenclature Audit (ICC.2-2019 Errata Tech.Err.#3)
         Found 4 tag(s) using multiProcessElementsType ('mpet')
         NOTE: iccDEV implementation uses singular name 'icSigMultiProcessElementType'
         and class 'CIccTagMultiProcessElement'. The ICC.2-2019 errata (March 2021)
         corrected 80 instances of 'multiProcessElementType' (singular) to
         'multiProcessElementsType' (plural). Binary signature 'mpet' is unchanged.
         [OK] All 4 tag(s) correctly typed
      [OK] Conformant

[H1306] CF-306: Embedded Image Data Length Cross-Validation
  [CF-306] Embedded Image Data Length Cross-Validation (ICC.2-2019 Errata §10.2.6/10.2.7)
         No embedded image tags — not applicable
      [OK] Conformant

[H1307] CF-307: Calculator Vector-Or Signature Validation
  [CF-307] Calculator Vector-Or Signature Validation (ICC.2-2019 Errata §11.2.1.9)
         Calculator element in tag 0x41324231 — vector-or must use 'vor ' (0x766F7220) per errata
         Calculator element in tag 0x42324131 — vector-or must use 'vor ' (0x766F7220) per errata
         NOTE: ICC.2-2019 §11.2.1.9 originally defined 'vor' (766f7200h).
         September 2021 errata corrects to 'vor ' (766f7220h) with trailing space.
         iccDEV implements 0x766F7220 (correct). Both implementations may exist
         in the wild — check binary profiles for stale encoding.
         [OK] 2 calculator element(s) audited for vector-or errata compliance
      [OK] Conformant

[H1308] CF-308: pcc AToB1/BToA1 Part 1 Element Restriction
[CF-308] pcc AToB1/BToA1 Part 1 Element Restriction (ICS-ColorimetricPCC-Part1 §6)
         Sub-class is not 'pcc ' — check not applicable
      [OK] Conformant

[H1309] CF-309: sref PCC Matrix Restriction
[CF-309] sref PCC Matrix Restriction (ICS-SpectralReflectance-Part1 §6.2)
         Sub-class is not 'sref' — check not applicable
      [OK] Conformant

[H1310] CF-310: sref DToB3/BToD3 Part 1 Element Restriction
[CF-310] sref DToB3/BToD3 Part 1 Element Restriction (ICS-SpectralReflectance-Part1 §6)
         Sub-class is not 'sref' — check not applicable
      [OK] Conformant

[H1311] CF-311: sref Spectral Range Mandatory
[CF-311] sref Spectral Range Mandatory (ICS-SpectralReflectance-Part1 §5.2)
         Sub-class is not 'sref' — check not applicable
      [OK] Conformant

[H1312] CF-312: ext Required Tag Completeness
[CF-312] ext Required Tag Completeness (ICS-ExtendedOutput-Part1 §6)
         Sub-class is not 'ext ' — check not applicable
      [OK] Conformant

[H1313] CF-313: ext Part 1 Element Type Restriction
[CF-313] ext Part 1 Element Type Restriction (ICS-ExtendedOutput-Part1 §6.3)
         Sub-class is not 'ext ' — check not applicable
      [OK] Conformant

[H1314] CF-314: xrng AToB1/BToA1 Part 1 Element Restriction
[CF-314] xrng AToB1/BToA1 Part 1 Element Restriction (ICS-ExtRange-Part1 §6.2)
         Sub-class is not 'xrng' — check not applicable
      [OK] Conformant

[H1315] CF-315: xrng Part 2 PCC Matrix Restriction
[CF-315] xrng Part 2 PCC Matrix Restriction (ICS-ExtRange-Part2 §6)
         Sub-class is not 'xrng' — check not applicable
      [OK] Conformant

[H1316] CF-316: ICS svcn Observer/Illuminant Plausibility
[CF-316] ICS svcn Observer/Illuminant Plausibility (ICC WP-57 §svcn)
         Not an ICS sub-class — check not applicable
      [OK] Conformant

[H1317] CF-317: HDR-to-SDR Flag-Tag Consistency
[CF-317] HDR-to-SDR Flag-Tag Consistency (K.2.9, ICC.2 §7.2.13)
         [OK] No Extended Range PCS flag, no HToS tags — consistent
      [OK] Conformant

[H1318] CF-318: HDR-to-SDR Tag Type Validation
[CF-318] HDR-to-SDR Tag Type Validation (K.2.9, ICC.2 §9.2)
         No HToS tags present — check not applicable
      [OK] Conformant

[H1319] CF-319: HDR-to-SDR Tag Channel Consistency
[CF-319] HDR-to-SDR Tag Channel Consistency (K.2.9)
         No HToS tags present — check not applicable
      [OK] Conformant

[H1320] CF-320: HDR-to-SDR Intent Coverage
[CF-320] HDR-to-SDR Intent Coverage (K.2.9)
         Extended Range PCS flag not set — check not applicable
      [OK] Conformant

[H1321] CF-321: Calculator 'solv' Operator Presence
  [CF-321] Calculator 'solv' Operator Presence (K.2.8, ICC.2 §11.2.1.7)
         No calculator elements — check not applicable
      [OK] Conformant

[H1322] CF-322: Calculator 'solv' Status Handling
  [CF-322] Calculator 'solv' Status Handling (K.2.8)
         No 'solv' operators — check not applicable
      [OK] Conformant

[H1323] CF-323: Calculator 'solv' Matrix Dimensions
  [CF-323] Calculator 'solv' Matrix Dimensions (K.2.8, §11.2.1.7)
         No 'solv' operators — check not applicable
      [OK] Conformant

[H1324] CF-324: Calculator 'env' Operator Usage
  [CF-324] Calculator 'env' Operator Usage (K.2.7, ICC.2 §11.2.1.4)
         No calculator elements — check not applicable
      [OK] Conformant

[H1325] CF-325: Calculator 'env' Status Handling
  [CF-325] Calculator 'env' Status Handling (K.2.7)
         No variable 'env' operators (excluding constants) — check not applicable
      [OK] Conformant

[H1326] CF-326: Calculator 'env' Reserved Signatures
  [CF-326] Calculator 'env' Reserved Signatures (K.2.7, §11.2.1.4)
         No calculator elements — check not applicable
      [OK] Conformant

[H1327] CF-327: PCC Alternate Override Readiness
  [CF-327] PCC Alternate Override Readiness (K.2.6, §6.3.2)
         PCC tag inventory:
           svcn (spectralViewingConditions): present
           c2sp (customToStandard):          present
           s2cp (standardToCustom):          present
           spectralPCS:                      not set
         PCC mode: non-standard (custom illuminant/observer)
         [INFO] Profile uses non-standard PCC — eligible for alternate PCC override per K.2.6
         Custom colorimetry transforms: complete (bidirectional)
      [OK] Conformant

[H1328] CF-328: PCC Non-Standard Colorimetry Indication
  [CF-328] PCC Non-Standard Colorimetry Indication (K.2.6, §6.3.2)
         Illuminant SPD: 81 steps (380.0–780.0 nm)
         Observer CMF: 81 steps (380.0–780.0 nm)
         [OK] PCC spectral data complete for alternate override support
      [OK] Conformant

[H1329] CF-329: PCC Override Source Profile Validation
  [CF-329] PCC Override Source Profile Validation (K.2.6, ICS-Colorimetric)
         deviceSubClass is not 'pcc ' — profile is not a PCC override source
      [OK] Conformant


--- Security Conformance (CF-091..CF-094) ---

[H1091] CF-091: Malware Signature Scan
  [CF-091] Malware Signature Scan (ICC.1-2022-05 §9)
           [OK] No malware signatures detected in tag data
      [OK] Conformant

[H1092] CF-092: Private Tag Identification
  [CF-092] Private/Unregistered Tag Identification (ICC.1-2022-05 §9)
           Private/unregistered: 'c2sp' (0x63327370) offset=2272 size=84
           Private/unregistered: 's2cp' (0x73326370) offset=2356 size=84
           Private/unregistered: 'svcn' (0x7376636E) offset=2440 size=1356
           [INFO] 3 private/unregistered tag(s) detected
      [WARN]  3 non-conformance(s)

[H1093] CF-093: Private Tag Content Scan
  [CF-093] Private Tag Content Security Scan (ICC.1-2022-05 §9)
           [OK] 3 private tag(s) scanned — no malware signatures
      [OK] Conformant

[H1094] CF-094: NOP/Shellcode Pattern Scan
  [CF-094] NOP/Shellcode Pattern Scan (CWE-506)
           [OK] No NOP sled or shellcode patterns detected
      [OK] Conformant


--- Private Tag Conformance (CF-095..CF-098) ---


--- Quality Conformance (CF-099..CF-102) ---

[H1099] CF-099: Round-Trip CIEDE2000
  [CF-099] Round-Trip Transform CIEDE2000 (ICC.1-2022-05 §8)
           [GAP] A2B1/B2A1 present but Only classic lut8/lut16 quality metrics are currently supported
      GAP: A2B1/B2A1 present but Only classic lut8/lut16 quality metrics are currently supported
      [OK] Conformant

[H1100] CF-100: Curve Invertibility
  [CF-100] Curve Invertibility Check (ICC.1-2022-05 §10.6)
           [N/A] No supported curves found
      N/A: No supported curves found
      [OK] Conformant

[H1101] CF-101: Transform Smoothness
  [CF-101] Transform Smoothness (ICC.1-2022-05 §10.8)
           [GAP] A2B1 present but Only classic lut8/lut16 quality metrics are currently supported
      GAP: A2B1 present but Only classic lut8/lut16 quality metrics are currently supported
      [OK] Conformant

[H1102] CF-102: Characterization Round-Trip
  [CF-102] Characterization Data Round-Trip (ICC.1-2022-05 §9.2.26)
           [N/A] No characterization data (targ) tag present
      N/A: No characterization data (targ) tag present
      [OK] Conformant


Deep Conformance Summary: 20 issue(s)

=======================================================================
PHASE 3: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/calcUnderStack_asin.icc

Device Class: 0x73706163

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [ ] [ ]  
  AToB1/BToA1 (Rel. Colorimetric): [[X]] [[X]]  [X] Round-trip capable
  AToB2/BToA2 (Saturation):        [ ] [ ]  

  DToB0/BToD0 (Perceptual):        [ ] [ ]  
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]  
  DToB2/BToD2 (Saturation):        [ ] [ ]  

  Matrix/TRC Tags:                 [ ]  

[OK] RESULT: Profile supports round-trip validation

Result: Round-trip capable [OK]

=======================================================================
PHASE 4: SIGNATURE ANALYSIS
=======================================================================


=== Signature Analysis ===

Header Signatures:
  Device Class:    0x73706163  ''  ColorSpaceClass
  Color Space:     0x52474220  'RGB'  RgbData
  PCS:             0x58595A20  'XYZ'  XYZData
  Manufacturer:    0x00000000  '....'
  Model:           0x00000000  '....'

Tag Signatures:
Idx  Tag          FourCC     Type         Issues
---  ------------ ---------- ------------ ------
0    profileDescriptionTag 'desc    '  multiLocalizedUnicodeType
1    AToB1Tag     'A2B1    '  multiProcessElementType
2    BToA1Tag     'B2A1    '  multiProcessElementType
3    customToStandardPccTag 'c2sp    '  multiProcessElementType
4    standardToCustomPccTag 's2cp    '  multiProcessElementType
5    spectralViewingConditionsTag 'svcn    '  spectralViewingConditionsType
6    mediaWhitePointTag 'wtpt    '  XYZArrayType
7    copyrightTag 'cprt    '  multiLocalizedUnicodeType

Summary: 0 signature issue(s) detected

=======================================================================
PHASE 5: PROFILE STRUCTURE DUMP
=======================================================================

=== ICC Profile Header ===

=== ICC Profile Header (0x0000-0x007F) ===
0x0000: 00 00 0F 60 00 00 00 00  05 00 00 00 73 70 61 63  |...`........spac|
0x0010: 52 47 42 20 58 59 5A 20  07 E2 00 08 00 0F 00 0A  |RGB XYZ ........|
0x0020: 00 16 00 12 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 54  00 01 00 00 00 01 16 CF  |.......T........|
0x0050: 49 43 43 20 AD C2 6A 85  CD A0 DE 91 CD FD 8D 74  |ICC ..j........t|
0x0060: 6F FC 5C 00 00 00 00 00  00 00 00 00 00 00 00 00  |o.\.............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields:
  Size:              0x00000F60 (3936 bytes)
  CMM Type:          '....' (0x00000000)
  Version:           5.0.0.0 (0x05000000)
  Device Class:      ColorSpaceClass
  Color Space:       RgbData (3 channels)
  PCS:               XYZData
  Date/Time:         2018-08-15 10:22:18
  Magic:             0x61637370 [OK]
  Platform:          Unknown
  Profile Flags:     0x00000000
  Manufacturer:      '....' (0x00000000)
  Model:             '....' (0x00000000)
  Device Attribs:    0x0000000000000000
  Rendering Intent:  Relative Colorimetric (1)
  PCS Illuminant:    X=0.9505 Y=1.0000 Z=1.0891
  Creator:           'ICC ' (0x49434320)
  Profile ID:        adc26a85cda0de91cdfd8d746ffc5c00

  --- ICC v5/iccMAX Extended Header ---
  Spectral PCS:      NoSpectralData
  Spectral Range:    Not Defined
  BiSpectral Range:  Not Defined
  MCS Color Space:   Not Defined

=== Tag Table ===

=== Tag Table ===
Tag Count: 8

Tag Table Raw Data (0x0080-0x00E4):
0x0080: 00 00 00 08 64 65 73 63  00 00 00 E4 00 00 00 42  |....desc.......B|
0x0090: 41 32 42 31 00 00 01 28  00 00 03 DC 42 32 41 31  |A2B1...(....B2A1|
0x00A0: 00 00 05 04 00 00 03 DC  63 32 73 70 00 00 08 E0  |........c2sp....|
0x00B0: 00 00 00 54 73 32 63 70  00 00 09 34 00 00 00 54  |...Ts2cp...4...T|
0x00C0: 73 76 63 6E 00 00 09 88  00 00 05 4C 77 74 70 74  |svcn.......Lwtpt|
0x00D0: 00 00 0E D4 00 00 00 14  63 70 72 74 00 00 0E E8  |........cprt....|
0x00E0: 00 00 00 76                                       |...v|

Tag Entries:
Idx  Signature    FourCC       Offset     Size
---  ------------ ------------ ---------- ----
0    profileDescriptionTag 'desc      '  0x000000E4  66
1    AToB1Tag     'A2B1      '  0x00000128  988
2    BToA1Tag     'B2A1      '  0x00000504  988
3    customToStandardPccTag 'c2sp      '  0x000008E0  84
4    standardToCustomPccTag 's2cp      '  0x00000934  84
5    spectralViewingConditionsTag 'svcn      '  0x00000988  1356
6    mediaWhitePointTag 'wtpt      '  0x00000ED4  20
7    copyrightTag 'cprt      '  0x00000EE8  118

=======================================================================
PHASE 6: TAG CONTENT ANALYSIS
=======================================================================

--- 5A: LUT Tag Geometry ---

  No legacy LUT tags (A2B/B2A/D2B/B2D) found

--- 5B: MPE Element Chains ---

  [A2B1] MPE Tag 'A2B1'
      Input channels:  3
      Output channels: 3
      Elements:        1

      === MPE Element Chain: 1 elements, 3→3 channels ===
      [1] Calculator Element ('calc') 3→3
      ===
      [INFO] Calculator element detected — #1 source of UBSAN findings

  [B2A1] MPE Tag 'B2A1'
      Input channels:  3
      Output channels: 3
      Elements:        1

      === MPE Element Chain: 1 elements, 3→3 channels ===
      [1] Calculator Element ('calc') 3→3
      ===
      [INFO] Calculator element detected — #1 source of UBSAN findings

--- 5C: TRC Curve Analysis ---

  No TRC curve tags found

--- 5D: NamedColor2 Validation ---

  No NamedColor2 tag

--- 5E: XYZ Tag Values ---

  [wtpt] X=0.9505 Y=1.0000 Z=1.0891

--- 5F: ICC v5 Spectral Data ---

  SpectralViewingConditions:
      Observer:    CIE 1931 (two degree) standard observer
      Illuminant:  Illuminant D65 (CCT=6500 K)
      Illuminant XYZ: (95.0500, 100.0000, 108.9100)
  PCC Transform Tags:  c2sp=PRESENT  s2cp=PRESENT

--- 5G: Profile ID Verification ---

  Profile ID (header):   adc26a85cda0de91cdfd8d746ffc5c00
  Profile ID (computed): adc26a85cda0de91cdfd8d746ffc5c00
  [OK] Profile ID matches — integrity verified

--- 5H: Per-Tag Size Analysis ---

  Tag sizes (flagging >10MB):
      [OK] All tags within 10MB limit

--- 5I: V5/iccMAX Summary ---

  --- V5/iccMAX Profile Summary ---

  BRDF Tags:              0 of 16 present
  Gamut Boundary Desc:    gbd0=---  gbd1=---

  MPE Tags:               4 (multiProcessElementsType)
  Total MPE Elements:     4
  Calculator Elements:    2
  Late-Binding Elements:  0 (spectral observer/emission)
    NOTE: Calculator elements are primary source of CWE-674/CWE-400 findings

--- 5J: Version Classification & Capabilities ---

  Version Classification:
    ICC Version:       5.0.0
    Specification:     ICC.2 (iccMAX)
    Features:          MPE, Spectral PCS, Calculator, BRDF, MCS, Named Colors
    Device Class:      ColorSpaceClass
    Color Space:       RgbData (3 channels)
    Connection Space:  XYZData

  Transform Capabilities:
    AToB (device→PCS):   no
    BToA (PCS→device):   no
    DToB (device→PCS):   no
    BToD (PCS→device):   no
    TRC (matrix/gamma):  no
    Gamut check:         no
    Chromatic adapt:     no
    Preview:             no


=======================================================================
CONFORMANCE AUDIT SUMMARY
=======================================================================

File: /home/h02332/po/research/test-profiles/calcUnderStack_asin.icc
Mode: Conformance (ICC specification audit)
Total Issues Detected: 23

[WARN] ANALYSIS COMPLETE - 23 issue(s) detected
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

File: /home/h02332/po/research/test-profiles/calcUnderStack_asin.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 3936 bytes (0xF60)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 0F 60 00 00 00 00  05 00 00 00 73 70 61 63  |...`........spac|
0x0010: 52 47 42 20 58 59 5A 20  07 E2 00 08 00 0F 00 0A  |RGB XYZ ........|
0x0020: 00 16 00 12 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 54  00 01 00 00 00 01 16 CF  |.......T........|
0x0050: 49 43 43 20 AD C2 6A 85  CD A0 DE 91 CD FD 8D 74  |ICC ..j........t|
0x0060: 6F FC 5C 00 00 00 00 00  00 00 00 00 00 00 00 00  |o.\.............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x00000F60 (3936 bytes) OK
  CMM:             0x00000000  '....'
  Version:         0x05000000  (5.0.0)
  Device Class:    0x73706163  'spac'
  Color Space:     0x52474220  'RGB '
  PCS:             0x58595A20  'XYZ '
  Date/Time:       2018-08-15 10:22:18
  Magic:           0x61637370  [OK 'acsp']
  Platform:        0x00000000  '....'
  Flags:           0x00000000
  Manufacturer:    0x00000000  '....'
  Model:           0x00000000  '....'
  Dev Attributes:  0x0000000000000000
  Rendering Intent:0x00000001  Relative Colorimetric
  PCS Illuminant:  X=0.9505 Y=1.0000 Z=1.0891
  Creator:         0x49434320  'ICC '
  Profile ID:      adc26a85cda0de91cdfd8d746ffc5c00
  Reserved 100-127: all zeros [OK]

  --- V5/iccMAX Extended Header ---
  Spectral PCS:    0x58595A20  'XYZ '
  Spectral Range:  Not defined

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 8 (0x00000008)

Tag Table Raw Data:
0x0080: 00 00 00 08 64 65 73 63  00 00 00 E4 00 00 00 42  |....desc.......B|
0x0090: 41 32 42 31 00 00 01 28  00 00 03 DC 42 32 41 31  |A2B1...(....B2A1|
0x00A0: 00 00 05 04 00 00 03 DC  63 32 73 70 00 00 08 E0  |........c2sp....|
0x00B0: 00 00 00 54 73 32 63 70  00 00 09 34 00 00 00 54  |...Ts2cp...4...T|
0x00C0: 73 76 63 6E 00 00 09 88  00 00 05 4C 77 74 70 74  |svcn.......Lwtpt|
0x00D0: 00 00 0E D4 00 00 00 14  63 70 72 74 00 00 0E E8  |........cprt....|
0x00E0: 00 00 00 76                                       |...v|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x64657363   'desc'        0x000000E4   0x00000042   'mluc'        OK
1    0x41324231   'A2B1'        0x00000128   0x000003DC   'mpet'        OK
2    0x42324131   'B2A1'        0x00000504   0x000003DC   'mpet'        OK
3    0x63327370   'c2sp'        0x000008E0   0x00000054   'mpet'        OK
4    0x73326370   's2cp'        0x00000934   0x00000054   'mpet'        OK
5    0x7376636E   'svcn'        0x00000988   0x0000054C   'svcn'        OK
6    0x77747074   'wtpt'        0x00000ED4   0x00000014   'XYZ '        OK
7    0x63707274   'cprt'        0x00000EE8   0x00000076   'mluc'        OK

=== FULL FILE HEX DUMP (all 3936 bytes) ===
0x0000: 00 00 0F 60 00 00 00 00  05 00 00 00 73 70 61 63  |...`........spac|
0x0010: 52 47 42 20 58 59 5A 20  07 E2 00 08 00 0F 00 0A  |RGB XYZ ........|
0x0020: 00 16 00 12 61 63 73 70  00 00 00 00 00 00 00 00  |....acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 54  00 01 00 00 00 01 16 CF  |.......T........|
0x0050: 49 43 43 20 AD C2 6A 85  CD A0 DE 91 CD FD 8D 74  |ICC ..j........t|
0x0060: 6F FC 5C 00 00 00 00 00  00 00 00 00 00 00 00 00  |o.\.............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0080: 00 00 00 08 64 65 73 63  00 00 00 E4 00 00 00 42  |....desc.......B|
0x0090: 41 32 42 31 00 00 01 28  00 00 03 DC 42 32 41 31  |A2B1...(....B2A1|
0x00A0: 00 00 05 04 00 00 03 DC  63 32 73 70 00 00 08 E0  |........c2sp....|
0x00B0: 00 00 00 54 73 32 63 70  00 00 09 34 00 00 00 54  |...Ts2cp...4...T|
0x00C0: 73 76 63 6E 00 00 09 88  00 00 05 4C 77 74 70 74  |svcn.......Lwtpt|
0x00D0: 00 00 0E D4 00 00 00 14  63 70 72 74 00 00 0E E8  |........cprt....|
0x00E0: 00 00 00 76 6D 6C 75 63  00 00 00 00 00 00 00 01  |...vmluc........|
0x00F0: 00 00 00 0C 65 6E 55 53  00 00 00 26 00 00 00 1C  |....enUS...&....|
0x0100: 00 63 00 61 00 6C 00 63  00 55 00 6E 00 64 00 65  |.c.a.l.c.U.n.d.e|
0x0110: 00 72 00 53 00 74 00 61  00 63 00 6B 00 5F 00 61  |.r.S.t.a.c.k._.a|
0x0120: 00 73 00 69 00 6E 00 00  6D 70 65 74 00 00 00 00  |.s.i.n..mpet....|
0x0130: 00 03 00 03 00 00 00 01  00 00 00 18 00 00 03 C4  |................|
0x0140: 63 61 6C 63 00 00 00 00  00 03 00 03 00 00 00 07  |calc............|
0x0150: 00 00 00 50 00 00 01 8C  00 00 01 8C 00 00 00 9C  |...P............|
0x0160: 00 00 02 28 00 00 00 3C  00 00 02 64 00 00 00 7C  |...(...<...d...||
0x0170: 00 00 02 E0 00 00 00 54  00 00 03 34 00 00 00 2C  |.......T...4...,|
0x0180: 00 00 03 60 00 00 00 2C  00 00 03 8C 00 00 00 38  |...`...,.......8|
0x0190: 66 75 6E 63 00 00 00 00  00 00 00 26 69 6E 20 20  |func.......&in  |
0x01A0: 00 00 00 02 64 61 74 61  40 0C C0 00 67 61 6D 61  |....data@...gama|
0x01B0: 00 02 00 00 74 73 61 76  00 00 00 02 64 61 74 61  |....tsav....data|
0x01C0: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x01D0: 00 00 00 00 65 71 20 20  00 02 00 00 73 75 6D 20  |....eq  ....sum |
0x01E0: 00 01 00 00 64 61 74 61  40 40 00 00 65 71 20 20  |....data@@..eq  |
0x01F0: 00 00 00 00 69 66 20 20  00 00 00 07 64 61 74 61  |....if  ....data|
0x0200: 3F 80 00 00 64 61 74 61  40 00 00 00 74 70 75 74  |?...data@...tput|
0x0210: 00 05 00 01 64 61 74 61  3F 80 00 00 74 70 75 74  |....data?...tput|
0x0220: 00 07 00 00 61 73 69 6E  00 00 00 00 70 6F 70 20  |....asin....pop |
0x0230: 00 00 00 00 74 67 65 74  00 00 00 02 64 61 74 61  |....tget....data|
0x0240: 3F 13 A0 8E 64 61 74 61  3E 3E 03 0D 64 61 74 61  |?...data>>..data|
0x0250: 3E 40 BE C7 6D 75 6C 20  00 02 00 00 73 75 6D 20  |>@..mul ....sum |
0x0260: 00 01 00 00 74 67 65 74  00 00 00 02 64 61 74 61  |....tget....data|
0x0270: 3E 98 3D 5C 64 61 74 61  3F 20 9A D1 64 61 74 61  |>.=\data? ..data|
0x0280: 3D 9A 30 7F 6D 75 6C 20  00 02 00 00 73 75 6D 20  |=.0.mul ....sum |
0x0290: 00 01 00 00 74 67 65 74  00 00 00 02 64 61 74 61  |....tget....data|
0x02A0: 3C DD 74 59 64 61 74 61  3D 90 C5 0F 64 61 74 61  |<.tYdata=...data|
0x02B0: 3F 7D C8 A1 6D 75 6C 20  00 02 00 00 73 75 6D 20  |?}..mul ....sum |
0x02C0: 00 01 00 00 6F 75 74 20  00 00 00 02 63 76 73 74  |....out ....cvst|
0x02D0: 00 00 00 00 00 03 00 03  00 00 00 24 00 00 00 28  |...........$...(|
0x02E0: 00 00 00 4C 00 00 00 28  00 00 00 74 00 00 00 28  |...L...(...t...(|
0x02F0: 63 75 72 66 00 00 00 00  00 01 00 00 70 61 72 66  |curf........parf|
0x0300: 00 00 00 00 00 00 00 00  3F 80 00 00 3F 00 00 00  |........?...?...|
0x0310: 00 00 00 00 00 00 00 00  63 75 72 66 00 00 00 00  |........curf....|
0x0320: 00 01 00 00 70 61 72 66  00 00 00 00 00 00 00 00  |....parf........|
0x0330: 3F 80 00 00 3F 80 00 00  00 00 00 00 00 00 00 00  |?...?...........|
0x0340: 63 75 72 66 00 00 00 00  00 01 00 00 70 61 72 66  |curf........parf|
0x0350: 00 00 00 00 00 00 00 00  3F 80 00 00 3F C0 00 00  |........?...?...|
0x0360: 00 00 00 00 00 00 00 00  6D 61 74 66 00 00 00 00  |........matf....|
0x0370: 00 03 00 03 3F 80 00 00  3F 80 00 00 BF 80 00 00  |....?...?.......|
0x0380: 40 00 00 00 3F 80 00 00  BF 80 00 00 3F 80 00 00  |@...?.......?...|
0x0390: BF 80 00 00 3F 80 00 00  00 00 00 00 00 00 00 00  |....?...........|
0x03A0: 00 00 00 00 63 6C 75 74  00 00 00 00 00 03 00 03  |....clut........|
0x03B0: 02 02 02 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x03C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x03D0: 00 00 00 00 3F 40 00 00  00 00 00 00 3F 00 00 00  |....?@......?...|
0x03E0: 00 00 00 00 00 00 00 00  3F 00 00 00 3F 40 00 00  |........?...?@..|
0x03F0: 3E 80 00 00 00 00 00 00  00 00 00 00 3E 80 00 00  |>...........>...|
0x0400: 00 00 00 00 3F 40 00 00  3E 80 00 00 3F 00 00 00  |....?@..>...?...|
0x0410: 00 00 00 00 3E 80 00 00  3F 00 00 00 3F 40 00 00  |....>...?...?@..|
0x0420: 63 61 6C 63 00 00 00 00  00 03 00 03 00 00 00 00  |calc............|
0x0430: 00 00 00 18 00 00 00 3C  66 75 6E 63 00 00 00 00  |.......<func....|
0x0440: 00 00 00 06 69 6E 20 20  00 00 00 02 64 61 74 61  |....in  ....data|
0x0450: 3F 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |?...data?...data|
0x0460: 3F 80 00 00 61 64 64 20  00 02 00 00 6F 75 74 20  |?...add ....out |
0x0470: 00 00 00 02 4A 74 6F 58  00 00 00 00 00 03 00 03  |....JtoX........|
0x0480: 3F 76 D5 D0 3F 80 00 00  3F 53 2C A5 43 FA 00 00  |?v..?...?S,.C...|
0x0490: 41 A0 00 00 3F 30 A3 D7  3F 80 00 00 3F 80 00 00  |A...?0..?...?...|
0x04A0: 58 74 6F 4A 00 00 00 00  00 03 00 03 3F 76 D5 D0  |XtoJ........?v..|
0x04B0: 3F 80 00 00 3F 53 2C A5  43 FA 00 00 41 A0 00 00  |?...?S,.C...A...|
0x04C0: 3F 30 A3 D7 3F 80 00 00  3F 80 00 00 74 69 6E 74  |?0..?...?...tint|
0x04D0: 00 00 00 00 00 01 00 03  66 6C 33 32 00 00 00 00  |........fl32....|
0x04E0: 3F 80 00 00 3F 80 00 00  BF 80 00 00 40 00 00 00  |?...?.......@...|
0x04F0: 3F 80 00 00 BF 80 00 00  3F 80 00 00 BF 80 00 00  |?.......?.......|
0x0500: 3F 80 00 00 6D 70 65 74  00 00 00 00 00 03 00 03  |?...mpet........|
0x0510: 00 00 00 01 00 00 00 18  00 00 03 C4 63 61 6C 63  |............calc|
0x0520: 00 00 00 00 00 03 00 03  00 00 00 07 00 00 00 50  |...............P|
0x0530: 00 00 01 8C 00 00 01 8C  00 00 00 9C 00 00 02 28  |...............(|
0x0540: 00 00 00 3C 00 00 02 64  00 00 00 7C 00 00 02 E0  |...<...d...|....|
0x0550: 00 00 00 54 00 00 03 34  00 00 00 2C 00 00 03 60  |...T...4...,...`|
0x0560: 00 00 00 2C 00 00 03 8C  00 00 00 38 66 75 6E 63  |...,.......8func|
0x0570: 00 00 00 00 00 00 00 26  69 6E 20 20 00 00 00 02  |.......&in  ....|
0x0580: 74 73 61 76 00 00 00 02  64 61 74 61 00 00 00 00  |tsav....data....|
0x0590: 64 61 74 61 00 00 00 00  64 61 74 61 00 00 00 00  |data....data....|
0x05A0: 65 71 20 20 00 02 00 00  73 75 6D 20 00 01 00 00  |eq  ....sum ....|
0x05B0: 64 61 74 61 40 40 00 00  65 71 20 20 00 00 00 00  |data@@..eq  ....|
0x05C0: 69 66 20 20 00 00 00 07  64 61 74 61 3F 80 00 00  |if  ....data?...|
0x05D0: 64 61 74 61 40 00 00 00  74 70 75 74 00 05 00 01  |data@...tput....|
0x05E0: 64 61 74 61 3F 80 00 00  74 70 75 74 00 07 00 00  |data?...tput....|
0x05F0: 61 73 69 6E 00 00 00 00  70 6F 70 20 00 00 00 00  |asin....pop ....|
0x0600: 74 67 65 74 00 00 00 02  64 61 74 61 40 02 A9 69  |tget....data@..i|
0x0610: 64 61 74 61 BF 10 A4 7F  64 61 74 61 BE B0 80 73  |data....data...s|
0x0620: 6D 75 6C 20 00 02 00 00  73 75 6D 20 00 01 00 00  |mul ....sum ....|
0x0630: 69 6E 20 20 00 00 00 02  64 61 74 61 BF 78 20 1D  |in  ....data.x .|
0x0640: 64 61 74 61 3F F0 1F C9  64 61 74 61 3D 2A 3A D2  |data?...data=*:.|
0x0650: 6D 75 6C 20 00 02 00 00  73 75 6D 20 00 01 00 00  |mul ....sum ....|
0x0660: 69 6E 20 20 00 00 00 02  64 61 74 61 3C 5C 33 72  |in  ....data<\3r|
0x0670: 64 61 74 61 BD F2 66 BA  64 61 74 61 3F 81 F1 17  |data..f.data?...|
0x0680: 6D 75 6C 20 00 02 00 00  73 75 6D 20 00 01 00 00  |mul ....sum ....|
0x0690: 64 61 74 61 3E E8 CF 59  67 61 6D 61 00 02 00 00  |data>..Ygama....|
0x06A0: 6F 75 74 20 00 00 00 02  63 76 73 74 00 00 00 00  |out ....cvst....|
0x06B0: 00 03 00 03 00 00 00 24  00 00 00 28 00 00 00 4C  |.......$...(...L|
0x06C0: 00 00 00 28 00 00 00 74  00 00 00 28 63 75 72 66  |...(...t...(curf|
0x06D0: 00 00 00 00 00 01 00 00  70 61 72 66 00 00 00 00  |........parf....|
0x06E0: 00 00 00 00 3F 80 00 00  3F 00 00 00 00 00 00 00  |....?...?.......|
0x06F0: 00 00 00 00 63 75 72 66  00 00 00 00 00 01 00 00  |....curf........|
0x0700: 70 61 72 66 00 00 00 00  00 00 00 00 3F 80 00 00  |parf........?...|
0x0710: 3F 80 00 00 00 00 00 00  00 00 00 00 63 75 72 66  |?...........curf|
0x0720: 00 00 00 00 00 01 00 00  70 61 72 66 00 00 00 00  |........parf....|
0x0730: 00 00 00 00 3F 80 00 00  3F C0 00 00 00 00 00 00  |....?...?.......|
0x0740: 00 00 00 00 6D 61 74 66  00 00 00 00 00 03 00 03  |....matf........|
0x0750: 3F 80 00 00 3F 80 00 00  BF 80 00 00 40 00 00 00  |?...?.......@...|
0x0760: 3F 80 00 00 BF 80 00 00  3F 80 00 00 BF 80 00 00  |?.......?.......|
0x0770: 3F 80 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |?...............|
0x0780: 63 6C 75 74 00 00 00 00  00 03 00 03 02 02 02 00  |clut............|
0x0790: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x07A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x07B0: 3F 40 00 00 00 00 00 00  3F 00 00 00 00 00 00 00  |?@......?.......|
0x07C0: 00 00 00 00 3F 00 00 00  3F 40 00 00 3E 80 00 00  |....?...?@..>...|
0x07D0: 00 00 00 00 00 00 00 00  3E 80 00 00 00 00 00 00  |........>.......|
0x07E0: 3F 40 00 00 3E 80 00 00  3F 00 00 00 00 00 00 00  |?@..>...?.......|
0x07F0: 3E 80 00 00 3F 00 00 00  3F 40 00 00 63 61 6C 63  |>...?...?@..calc|
0x0800: 00 00 00 00 00 03 00 03  00 00 00 00 00 00 00 18  |................|
0x0810: 00 00 00 3C 66 75 6E 63  00 00 00 00 00 00 00 06  |...<func........|
0x0820: 69 6E 20 20 00 00 00 02  64 61 74 61 3F 80 00 00  |in  ....data?...|
0x0830: 64 61 74 61 3F 80 00 00  64 61 74 61 3F 80 00 00  |data?...data?...|
0x0840: 61 64 64 20 00 02 00 00  6F 75 74 20 00 00 00 02  |add ....out ....|
0x0850: 4A 74 6F 58 00 00 00 00  00 03 00 03 3F 76 D5 D0  |JtoX........?v..|
0x0860: 3F 80 00 00 3F 53 2C A5  43 FA 00 00 41 A0 00 00  |?...?S,.C...A...|
0x0870: 3F 30 A3 D7 3F 80 00 00  3F 80 00 00 58 74 6F 4A  |?0..?...?...XtoJ|
0x0880: 00 00 00 00 00 03 00 03  3F 76 D5 D0 3F 80 00 00  |........?v..?...|
0x0890: 3F 53 2C A5 43 FA 00 00  41 A0 00 00 3F 30 A3 D7  |?S,.C...A...?0..|
0x08A0: 3F 80 00 00 3F 80 00 00  74 69 6E 74 00 00 00 00  |?...?...tint....|
0x08B0: 00 01 00 03 66 6C 33 32  00 00 00 00 3F 80 00 00  |....fl32....?...|
0x08C0: 3F 80 00 00 BF 80 00 00  40 00 00 00 3F 80 00 00  |?.......@...?...|
0x08D0: BF 80 00 00 3F 80 00 00  BF 80 00 00 3F 80 00 00  |....?.......?...|
0x08E0: 6D 70 65 74 00 00 00 00  00 03 00 03 00 00 00 01  |mpet............|
0x08F0: 00 00 00 18 00 00 00 3C  6D 61 74 66 00 00 00 00  |.......<matf....|
0x0900: 00 03 00 03 3F 93 79 27  BD 7F 06 97 BD 80 E0 11  |....?.y'........|
0x0910: 3D CA 96 ED 3F 6F 1F 3E  BC D3 53 DB BC E8 61 EF  |=...?o.>..S...a.|
0x0920: 3D 0E 18 47 3F 40 14 F8  00 00 00 00 00 00 00 00  |=..G?@..........|
0x0930: 00 00 00 00 6D 70 65 74  00 00 00 00 00 03 00 03  |....mpet........|
0x0940: 00 00 00 01 00 00 00 18  00 00 00 3C 6D 61 74 66  |...........<matf|
0x0950: 00 00 00 00 00 03 00 03  3F 5D 75 71 3D 60 DD 1E  |........?]uq=`..|
0x0960: 3D 98 73 6C BD B9 89 BF  3F 88 1F BD 3C ED 48 91  |=.sl....?...<.H.|
0x0970: 3D 17 1E 44 BD 40 E5 B3  3F AA C8 5F 00 00 00 00  |=..D.@..?.._....|
0x0980: 00 00 00 00 00 00 00 00  73 76 63 6E 00 00 00 00  |........svcn....|
0x0990: 00 00 00 01 5D F0 62 18  00 51 00 00 3A B3 4E 77  |....].b..Q..:.Nw|
0x09A0: 3B 12 89 DB 3B 8B 08 DD  3B FA AC DA 3C 6A 74 7E  |;...;...;...<jt~|
0x09B0: 3C BD F8 F4 3D 32 37 8B  3D 9E FC 7A 3E 09 9A E9  |<...=27.=..z>...|
0x09C0: 3E 5B EC AB 3E 91 5B 57  3E A8 31 27 3E B2 51 C2  |>[..>.[W>.1'>.Q.|
0x09D0: 3E B2 34 EC 3E AC 22 68  3E A3 2C A5 3E 94 E3 BD  |>.4.>."h>.,.>...|
0x09E0: 3E 80 90 2E 3E 48 0C 74  3E 11 82 AA 3D C3 DE E8  |>...>H.t>...=...|
0x09F0: 3D 6D 5C FB 3D 03 1C EB  3C 70 D8 45 3B A0 90 2E  |=m\.=...<p.E;...|
0x0A00: 3B 1D 49 52 3C 18 5F 07  3C EE 63 20 3D 81 93 B4  |;.IR<._.<.c =...|
0x0A10: 3D E0 75 F7 3E 29 78 D5  3E 67 2B 02 3E 94 AF 4F  |=.u.>)x.>g+.>..O|
0x0A20: 3E B8 2A 99 3E DD ED 29  3F 03 15 B5 3F 18 31 27  |>.*.>..)?...?.1'|
0x0A30: 3F 2D AB 9F 3F 43 18 FC  3F 57 AE 14 3F 6A 92 A3  |?-..?C..?W..?j..|
0x0A40: 3F 7A 85 88 3F 83 5D CC  3F 87 41 F2 3F 87 F6 2B  |?z..?.].?.A.?..+|
0x0A50: 3F 85 D6 39 3F 80 55 32  3F 70 3A FB 3F 5A BD 3C  |?..9?.U2?p:.?Z.<|
0x0A60: 3F 40 5B C0 3F 24 74 54  3F 0A B9 F5 3E E5 53 26  |?@[.?$tT?...>.S&|
0x0A70: 3E B8 BA C7 3E 91 26 E9  3E 5F F2 E5 3E 28 DB 8C  |>...>.&.>_..>(..|
0x0A80: 3D F8 37 B5 3D B2 FE C5  3D 82 40 B8 3D 3F 91 E6  |=.7.=...=.@.=?..|
0x0A90: 3D 06 C2 27 3C B9 F5 5A  3C 81 C2 E3 3C 3A 1B 19  |=..'<..Z<...<:..|
0x0AA0: 3C 04 E4 00 3B BD BA 0A  3B 86 A4 CA 3B 3D FD 26  |<...;...;...;=.&|
0x0AB0: 3B 06 48 84 3A BC BE 62  3A 83 12 6F 3A 34 E1 1E  |;.H.:..b:..o:4..|
0x0AC0: 39 F9 8F A3 39 AE 10 49  39 76 6A 55 39 2E 10 49  |9...9..I9vjU9..I|
0x0AD0: 38 F5 5D E6 38 AE 10 49  38 77 76 C5 38 30 29 28  |8.].8..I8wv.80)(|
0x0AE0: 38 23 93 EE 38 86 37 BD  38 FB A8 82 39 63 8A 7E  |8#..8.7.8...9c.~|
0x0AF0: 39 CF 9E 38 3A 27 C5 AC  3A 9E 98 DD 3B 0E DE 55  |9..8:'..:...;..U|
0x0B00: 3B 83 12 6F 3B EF 34 D7  3C 3E 0D ED 3C 89 F4 0A  |;..o;.4.<>..<...|
0x0B10: 3C BC 6A 7F 3C F4 1F 21  3D 1B A5 E3 3D 44 9B A6  |<.j.<..!=...=D..|
0x0B20: 3D 75 C2 8F 3D 97 58 E2  3D BA 53 B9 3D E6 9A D4  |=u..=.X.=.S.=...|
0x0B30: 3E 0E 5B 42 3E 2D 5C FB  3E 55 03 32 3E 84 67 38  |>.[B>-\.>U.2>.g8|
0x0B40: 3E A5 60 42 3E D0 89 A0  3F 00 C4 9C 3F 1B B2 FF  |>.`B>...?...?...|
0x0B50: 3F 35 C2 8F 3F 4B 0F 28  3F 5C AC 08 3F 6A 33 9C  |?5..?K.(?\..?j3.|
0x0B60: 3F 74 39 58 3F 7A F4 F1  3F 7E B5 0B 3F 80 00 00  |?t9X?z..?~..?...|
0x0B70: 3F 7E B8 52 3F 7A 85 88  3F 73 B6 46 3F 6A 57 A8  |?~.R?z..?s.F?jW.|
0x0B80: 3F 5E B8 52 3F 50 F9 09  3F 41 CA C1 3F 31 E4 F7  |?^.R?P..?A..?1..|
0x0B90: 3F 21 89 37 3F 11 19 CE  3F 00 C4 9C 3E E1 E4 F7  |?!.7?...?...>...|
0x0BA0: 3E C3 12 6F 3E A4 5A 1D  3E 87 AE 14 3E 5E 35 3F  |>..o>.Z.>...>^5?|
0x0BB0: 3E 33 33 33 3E 0D 84 4D  3D DB 22 D1 3D A7 1D E7  |>333>..M=.".=...|
0x0BC0: 3D 79 DB 23 3D 36 99 85  3D 03 12 6F 3C BE 0D ED  |=y.#=6..=..o<...|
0x0BD0: 3C 8B 43 96 3C 43 4C 1B  3C 06 83 3C 3B BB 88 01  |<.C.<CL.<..<;...|
0x0BE0: 3B 86 6A 12 3B 3F F4 77  3B 09 09 29 3A C2 82 C7  |;.j.;?.w;..):...|
0x0BF0: 3A 89 3B 7E 3A 41 FC 8F  3A 08 50 9C 39 BD 44 9A  |:.;~:A..:.P.9.D.|
0x0C00: 39 82 8C 37 39 34 5A E6  38 FB A8 82 38 B2 42 07  |9..794Z.8...8.B.|
0x0C10: 38 7B A8 82 38 30 29 28  37 FB A8 82 37 B0 29 28  |8{..80)(7...7.)(|
0x0C20: 37 7B A8 82 3B D3 5A 86  3C 2C D9 E8 3C A4 3F E6  |7{..;.Z.<,..<.?.|
0x0C30: 3D 14 50 F0 3D 8A F4 F1  3D E1 B0 8A 3E 54 60 AA  |=.P.=...=...>T`.|
0x0C40: 3E BE 1B 09 3F 25 46 0B  3F 84 FF 97 3F B1 5B 57  |>...?%F.?...?.[W|
0x0C50: 3F CF BD 27 3F DF 9F A9  3F E4 2C 3D 3F E2 D4 80  |?..'?...?.,=?...|
0x0C60: 3F DF 3E AB 3F D5 A8 58  3F C3 98 C8 3F A4 D1 63  |?.>.?..X?...?..c|
0x0C70: 3F 85 5C FB 3F 50 1D 7E  3F 1D BF 48 3E EE 2C 13  |?.\.?P.~?..H>.,.|
0x0C80: 3E B4 E3 BD 3E 8B 43 96  3E 59 65 2C 3E 21 FF 2E  |>...>.C.>Ye,>!..|
0x0C90: 3D E4 C2 F8 3D A0 41 89  3D 6A 7E FA 3D 2C AF F7  |=...=.A.=j~.=,..|
0x0CA0: 3C F4 73 04 3C A6 4C 30  3C 5B 8B AC 3C 0F 5C 29  |<.s.<.L0<[..<.\)|
0x0CB0: 3B BC 6A 7F 3B 7F 97 24  3B 34 39 58 3B 09 A0 27  |;.j.;..$;49X;..'|
0x0CC0: 3A EB ED FA 3A D8 44 D0  3A B7 80 34 3A 90 2D E0  |:...:.D.:..4:.-.|
0x0CD0: 3A 83 12 6F 3A 51 B7 17  3A 1D 49 52 39 B2 42 07  |:..o:Q..:.IR9.B.|
0x0CE0: 39 7B A8 82 39 47 3A BD  38 D1 B7 17 38 51 B7 17  |9{..9G:.8...8Q..|
0x0CF0: 37 FB A8 82 37 A7 C5 AC  37 27 C5 AC 00 00 00 00  |7...7...7'......|
0x0D00: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D10: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D20: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D30: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D40: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D50: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0D60: 00 00 00 00 00 00 00 00  00 00 00 02 45 CB 20 00  |............E. .|
0x0D70: 5D F0 62 18 00 51 00 00  42 47 E6 E9 42 51 3F 48  |].b..Q..BG..BQ?H|
0x0D80: 42 5A 97 C2 42 89 67 2B  42 A5 82 82 42 AE 3D A5  |BZ..B.g+B...B.=.|
0x0D90: 42 B6 F8 D5 42 B8 EA F5  42 BA DD 15 42 B4 1D 2F  |B...B...B...B../|
0x0DA0: 42 AD 5D 56 42 BF 8C 15  42 D1 BA E1 42 DD DF 3B  |B.]VB...B...B..;|
0x0DB0: 42 EA 04 19 42 EA D1 EC  42 EB 9F BE 42 E8 AC 08  |B...B...B...B...|
0x0DC0: 42 E5 B8 D5 42 E6 C8 B4  42 E7 D8 93 42 E0 BB E7  |B...B...B...B...|
0x0DD0: 42 D9 9F 3B 42 DA 29 FC  42 DA B5 3F 42 D9 27 F0  |B..;B.).B..?B.'.|
0x0DE0: 42 D7 9A A0 42 D4 97 8D  42 D1 94 7B 42 D4 7A 5E  |B...B...B..{B.z^|
0x0DF0: 42 D7 60 C5 42 D4 18 10  42 D0 CF 5C 42 D0 73 33  |B.`.B...B..\B.s3|
0x0E00: 42 D0 17 8D 42 CC 0B C7  42 C8 00 00 42 C4 55 8E  |B...B...B...B.U.|
0x0E10: 42 C0 AB 1C 42 C0 1F 48  42 BF 93 75 42 B8 79 3E  |B...B..HB..uB.y>|
0x0E20: 42 B1 5F 07 42 B2 B1 1A  42 B4 03 2D 42 B3 9A EE  |B._.B...B..-B...|
0x0E30: 42 B3 32 BD 42 B1 4C 3D  42 AF 65 BC 42 AA FC B9  |B.2.B.L=B.e.B...|
0x0E40: 42 A6 93 C3 42 A6 FC E0  42 A7 65 FE 42 A3 B9 DB  |B...B...B.e.B...|
0x0E50: 42 A0 0D B9 42 A0 3D CC  42 A0 6D E0 42 A2 7E 0E  |B...B.=.B.m.B.~.|
0x0E60: 42 A4 8E 3C 42 A0 8F DF  42 9C 91 83 42 94 01 62  |B..<B...B...B..b|
0x0E70: 42 8B 71 4E 42 8D 54 95  42 8F 37 DC 42 91 F5 3F  |B.qNB.T.B.7.B..?|
0x0E80: 42 94 B2 B0 42 87 F3 F8  42 76 6A 7F 42 83 7D 56  |B...B...Bvj.B.}V|
0x0E90: 42 8B C5 6D 42 90 F8 FC  42 96 2C 8B 42 8A AD FA  |B..mB...B.,.B...|
0x0EA0: 42 7E 5E ED 42 5C 05 88  42 39 AC 3D 42 62 72 7C  |B~^.B\..B9.=Bbr||
0x0EB0: 42 85 9C 5D 42 82 30 2E  42 7D 87 FD 42 BE 19 9A  |B..]B.0.B}..B...|
0x0EC0: 42 C8 00 00 42 D9 D1 EC  42 BE 19 9A 42 C8 00 00  |B...B...B...B...|
0x0ED0: 42 D9 D1 EC 58 59 5A 20  00 00 00 00 00 00 F3 54  |B...XYZ .......T|
0x0EE0: 00 01 00 00 00 01 16 CF  6D 6C 75 63 00 00 00 00  |........mluc....|
0x0EF0: 00 00 00 01 00 00 00 0C  65 6E 55 53 00 00 00 5A  |........enUS...Z|
0x0F00: 00 00 00 1C 00 43 00 6F  00 70 00 79 00 72 00 69  |.....C.o.p.y.r.i|
0x0F10: 00 67 00 68 00 74 00 20  00 32 00 30 00 31 00 38  |.g.h.t. .2.0.1.8|
0x0F20: 00 20 00 49 00 6E 00 74  00 65 00 72 00 6E 00 61  |. .I.n.t.e.r.n.a|
0x0F30: 00 74 00 69 00 6F 00 6E  00 61 00 6C 00 20 00 43  |.t.i.o.n.a.l. .C|
0x0F40: 00 6F 00 6C 00 6F 00 72  00 20 00 43 00 6F 00 6E  |.o.l.o.r. .C.o.n|
0x0F50: 00 73 00 6F 00 72 00 74  00 69 00 75 00 6D 00 00  |.s.o.r.t.i.u.m..|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 0**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/calcUnderStack_asin.icc

Device Class: 0x73706163

Tag Pair Analysis:
  AToB0/BToA0 (Perceptual):        [ ] [ ]  
  AToB1/BToA1 (Rel. Colorimetric): [[X]] [[X]]  [X] Round-trip capable
  AToB2/BToA2 (Saturation):        [ ] [ ]  

  DToB0/BToD0 (Perceptual):        [ ] [ ]  
  DToB1/BToD1 (Rel. Colorimetric): [ ] [ ]  
  DToB2/BToD2 (Saturation):        [ ] [ ]  

  Matrix/TRC Tags:                 [ ]  

[OK] RESULT: Profile supports round-trip validation
```

---

## LUT Text Export (`-xt`)

**Exit Code: 0**

```
=== Extracting LUT data as text from: /home/h02332/po/research/test-profiles/calcUnderStack_asin.icc ===

--- AToB1Tag (MPE: 1 elements) ---
  Channels: in=3 out=3
  Element[0]: CIccMpeCalculator (skipped)

--- BToA1Tag (MPE: 1 elements) ---
  Channels: in=3 out=3
  Element[0]: CIccMpeCalculator (skipped)

--- customToStandardPccTag (MPE: 1 elements) ---
  Channels: in=3 out=3
  Wrote MPE Matrix[0]: /tmp/tmp.cR334CKA1m/calcUnderStack_asin__customToStandardPccTag_mpe0_matrix.txt (3x3)

--- standardToCustomPccTag (MPE: 1 elements) ---
  Channels: in=3 out=3
  Wrote MPE Matrix[0]: /tmp/tmp.cR334CKA1m/calcUnderStack_asin__standardToCustomPccTag_mpe0_matrix.txt (3x3)

=== Exported 2 LUT component(s) ===
Exported 2 text file(s) to /tmp/tmp.cR334CKA1m/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
