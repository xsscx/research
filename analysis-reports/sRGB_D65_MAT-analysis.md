# ICC Profile Analysis Report

**Profile**: `test-profiles/sRGB_D65_MAT.icc`
**File Size**: 24712 bytes
**SHA-256**: `317a85b01c29550c5289e505079a549c12aaf92cfebc80d04b6626f717675fce`
**File Type**: color profile 5.0, RGB/XYZ-mntr device by ICC, 24712 bytes, 17-2-2026 8:38:13, embedded, relative colorimetric, PCS X=0xf34d Z=0x116c2, 0x33174f15abb4d791 MD5 'sRGB D65 MAT'
**Date**: 2026-03-25T02:25:08Z
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

File: /home/h02332/po/research/test-profiles/sRGB_D65_MAT.icc

[H173] Signature Conversion Shift Overflow (IccUtil.cpp signature formatting helpers)
      [WARN]  HEURISTIC: 22/22 FourCC signatures trigger UBSAN shift overflow in icGetSig()/icGetSigStr()/icGetColorSig()/icGetColorSigStr() — IccUtil.cpp:1088,1130,1167,1187,1228,1253
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
         Month=2, Day=17 — valid
         [OK] Date fields within range
      [OK] Conformant

[H1002] CF-002: Date/Time Leap Year Validation
[CF-002] Date/Time Leap Year Validation (ICC.1-2022-05 §7.2.8)
         Year=2026 (non-leap), Day=17 — valid
         [OK] February day valid for non-leap year
      [OK] Conformant

[H1003] CF-003: Profile Flags Reserved Bits
[CF-003] Profile Flags Reserved Bits (ICC.1-2022-05 §7.2.11 Table 21)
         flags=0x00000001 — reserved bits 3-15 clear
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
         illuminant X=0.9504, Y=1.0000, Z=1.0889
         expected   X=0.9642, Y=1.0000, Z=0.8249 (D50)
         X deviation: 0.013806 (tolerance 0.0001)
         [FAIL] PCS illuminant X does not match D50 — ICC.1-2022-05 §7.2.16
         Z deviation: 0.263998 (tolerance 0.0001)
         [FAIL] PCS illuminant Z does not match D50 — ICC.1-2022-05 §7.2.16
      [WARN]  2 non-conformance(s)

[H1009] CF-009: Chromatic Adaptation Tag Requirement
[CF-009] Chromatic Adaptation Tag Requirement (ICC.1-2022-05 §8.2)
         Illuminant deviates from D50, chad tag: missing
         [FAIL] chad tag required when adopted white != D50 — ICC.1-2022-05 §8.2
      [WARN]  1 non-conformance(s)

[H1010] CF-010: Profile Size vs File Size
[CF-010] Profile Size vs File Size (ICC.1-2022-05 §7.2.2)
         Header size: 24712 bytes, File size: 24712 bytes
         [OK] Profile size matches file size
      [OK] Conformant

[H1011] CF-011: Profile ID MD5 Verification
[CF-011] Profile ID MD5 Verification (ICC.1-2022-05 §7.2.18)
         Profile ID: 33174f15abb4d791a2ace1bf694996c1 — MD5 verified
         [OK] Profile ID matches computed MD5
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
         V4 mediaWhitePointTag (0.9504, 1.0000, 1.0889) ≠ D50
         [FAIL] V4 wtpt must be D50 — §9.2.28
      [WARN]  1 non-conformance(s)

[H1122] CF-122: Profile Date/Time Plausibility
  [CF-122] Profile Date/Time Plausibility (ICC.1-2022-05 §7.2.8)
         [OK] Profile date/time is plausible
      [OK] Conformant

[H1184] CF-184: Profile ID v4+ Presence
[CF-184] Profile ID v4+ Presence (ICC.1-2022-05 §7.2.18, RFC 1321)
         Profile version: 5.x
         Profile ID: 33174f15abb4d791a2ace1bf694996c1
         [OK] v4+ profile has computed Profile ID
      [OK] Conformant

[H1185] CF-185: Profile ID Size Consistency
[CF-185] Profile ID Size Consistency (ICC.1-2022-05 §7.2.18, RFC 1321 §3.1)
         Header-declared size: 24712 bytes
         Actual file size: 24712 bytes
         [OK] Header size matches file size — MD5 input length consistent
      [OK] Conformant

[H1186] CF-186: Profile ID Entropy Analysis
[CF-186] Profile ID Entropy Analysis (RFC 1321, ICC.1-2022-05 §7.2.18)
         Profile ID: 33174f15abb4d791a2ace1bf694996c1
         Unique byte values: 16/16
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
           Bit 0 (Embedded): embedded in file
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
         Embedded flag set on 'mntr' class profile — standard embedding use case
         [OK] Profile class 'mntr' is appropriate for embedding
      [OK] Conformant

[H1215] CF-215: JPEG APP2 Embedding Size Limit
  [CF-215] JPEG APP2 Embedding Size Limit (ICC TN Embedding §JFIF)
         Profile size: 24712 bytes (JPEG limit: 16707345 bytes)
         Would require 1 APP2 segment(s) for JPEG embedding
         [OK] Profile fits within JPEG APP2 embedding limit
      [OK] Conformant

[H1216] CF-216: JP2 Restricted ICC Compliance
  [CF-216] JP2 Restricted ICC Compliance (ISO 15444-1 Annex I)
         Class 'mntr' — JP2 requires Input ('scnr') class
         Version 5.x — JP2 requires ICC v2 (ICC.1:1998-09)
         [INFO] Profile not compatible with JP2 Restricted ICC method
      [OK] Conformant

[H1217] CF-217: JPX Any ICC Method Compliance
  [CF-217] JPX Any ICC Method Compliance (ISO 15444-2 Annex M)
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
         Profile version: 5.x, class: mntr
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
         [OK] 9 tag(s) checked, all reserved bytes are zero
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
         Swept 9 tags: 4 OK, 5 warnings, 0 errors
         [OK] All 9 tags pass library Validate()
      [OK] Conformant

[H1189] CF-189: Tag Type Recognition Coverage
  [CF-189] Tag Type Recognition Coverage (SampleICC §3 CheckTagTypes)
         9/9 tags have recognized type signatures
         [OK] All 9 tag types are recognized by the factory
      [OK] Conformant

[H1190] CF-190: Profile Legibility Gate
  [CF-190] Profile Legibility Gate (SampleICC §3 ReadValidate)
         [OK] Profile is legible: 9 tags parsed, all non-NULL
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
         AToB tags: 1, BToA tags: 1, class: 0x6D6E7472
         [WARN] Display profile has BToA tags but missing BToA0
      [WARN]  1 non-conformance(s)

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
         Profile creation: 2026-02-17 08:38:13 (UTC)
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
         Illuminant X=0.9504 Y=1.0000 Z=1.0889 — not D50, chad missing
         [FAIL] chromaticAdaptationTag required when adopted white ≠ D50 — ICC.1-2022-05 §8.2
      [WARN]  1 non-conformance(s)

[H1042] CF-042: Display Profile Required Tags
[CF-042] Display Profile Required Tags (ICC.1-2022-05 §8.4 Tables 25-27)
         Neither matrix/TRC tags nor AToB0Tag found
         [FAIL] Display profile must have matrix/TRC set OR AToB0+BToA0 — ICC.1-2022-05 §8.4
      [WARN]  1 non-conformance(s)

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
           Additional tag: 'gbd1' (0x67626431)
           [INFO] 6 non-required tag(s) present
      [OK] Conformant

[H1096] CF-096: Private Tag Signature Range
  [CF-096] Private Tag Signature Range (ICC.1-2022-05 §9)
           Private tag 'c2sp' (0x63327370) — printable signature
           Private tag 's2cp' (0x73326370) — printable signature
           Private tag 'svcn' (0x7376636E) — printable signature
           Private tag 'gbd1' (0x67626431) — printable signature
           [OK] 4 private tag(s) — all use printable 4-char signatures
      [OK] Conformant

[H1097] CF-097: Private Tag Documentation
  [CF-097] Private Tag Documentation (ICC.1-2022-05 §9)
           Undocumented private tag: 'c2sp' (0x63327370)
           Undocumented private tag: 's2cp' (0x73326370)
           Undocumented private tag: 'svcn' (0x7376636E)
           Undocumented private tag: 'gbd1' (0x67626431)
           [INFO] 4 undocumented private tag(s)
      [WARN]  4 non-conformance(s)

[H1098] CF-098: Undocumented Private Tags
  [CF-098] Undocumented Private Tag Identification (ICC.1-2022-05 §9)
           Unrecognized: 'c2sp' (0x63327370) size=84
           Unrecognized: 's2cp' (0x73326370) size=84
           Unrecognized: 'svcn' (0x7376636E) size=1356
           Unrecognized: 'gbd1' (0x67626431) size=22052
           [INFO] 4 unrecognized tag(s) — may require vendor documentation
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
           Distinct data regions: 9
           Data coverage: 24470 / 24712 bytes (99.0%)
           Inter-region gaps: 0 (largest: 0 bytes)
           [OK] Tag data region layout conformant
      [OK] Conformant

[H1207] CF-207: mediaWhitePointTag Value Range
[CF-207] mediaWhitePointTag Value Range (ICC.1-2022-05 §10.27)
         wtpt: X=0.9504, Y=1.0000, Z=1.0889
         v4 non-DeviceLink: wtpt should be D50 (0.9642, 1.0, 0.8249)
         deviation: ΔX=0.0138, ΔY=0.0000, ΔZ=0.2640
         [FAIL] v4+ non-DeviceLink wtpt must be D50 — ICC.1-2022-05 §9.2.28
      [WARN]  1 non-conformance(s)

[H1211] CF-211: AToB/BToA Tag Pair Completeness
[CF-211] AToB/BToA Tag Pair Completeness (ICC.1-2022-05 §9.2.1-9.2.2)
         Pair 1 (Relative Colorimetric): AToB ✓  BToA ✓
         [OK] AToB/BToA tag pair completeness conformant
      [OK] Conformant

[H1258] CF-258: Display v4+ mediaWhitePointTag D50
[CF-258] Display v4+ mediaWhitePointTag D50 (ICC.1-2022-05 §8.4)
         mediaWhitePoint = (0.9504, 1.0000, 1.0889)
         Expected D50    = (0.9642, 1.0000, 0.8249)
         [FAIL] Display v4+ mediaWhitePointTag must equal D50 — ICC.1-2022-05 §8.4
      [WARN]  1 non-conformance(s)

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
         Scanned 4 MPE tag(s), 6 element(s) total
         [OK] All 6 MPE element signatures recognized
      [OK] Conformant

[H1088] CF-088: Calculator Stack Structure
[CF-088] Calculator Element Stack Structure (ICC.2-2023 §10.x)
         Found 0 calculator element(s)
         [OK] No calculator elements present
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
         No calculator elements found — check not applicable
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
         [OK] GBD tag structure has room for vertex count field
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
         flags=0x00000001 — Extended Range PCS bit (3) not set
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
         [OK] 1 GBD tag(s) have consistent vertex/triangle counts
      [OK] Conformant

[H1287] CF-287: GBD Channel Count Plausibility
  [CF-287] GBD Channel Count Plausibility (ICC.2-2023 §10.2.11)
         [OK] 1 GBD tag(s) have plausible channel counts
      [OK] Conformant

[H1288] CF-288: Spectral Data Info Bi-Spectral Consistency
  [CF-288] Spectral Data Info Bi-Spectral Consistency (ICC.2-2023 §9.2.84)
         No spectralDataInfoTag — not applicable
      [OK] Conformant

[H1289] CF-289: Spectral Viewing Conditions Illuminant Bounds
  [CF-289] Spectral Viewing Conditions Illuminant Bounds (ICC.2-2023 §10.2.30)
         Illuminant XYZ: (0.9504, 1.0000, 1.0889)
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
         [OK] All MPE element chains have consistent I/O channels (2 tags)
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
         [OK] All 6 MPE elements version-compatible with v5
      [OK] Conformant

[H1296] CF-296: MPE Empty Container Validation
  [CF-296] MPE Empty Container Validation (ICC.2-2023 §10.2.17)
         No empty MPE containers — not applicable
      [OK] Conformant

[H1297] CF-297: MPE CurveSet Element Channel Count
  [CF-297] MPE CurveSet Element Channel Count (ICC.2-2023 §10.2.5)
         [OK] All 2 CurveSet elements have input==output channels
      [OK] Conformant

[H1298] CF-298: MPE Matrix Element Dimension
  [CF-298] MPE Matrix Element Dimension Validation (ICC.2-2023 §10.2.9)
         [OK] All 4 Matrix elements have valid dimensions
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
         No calculator elements — not applicable
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
           Private/unregistered: 'c2sp' (0x63327370) offset=1116 size=84
           Private/unregistered: 's2cp' (0x73326370) offset=1200 size=84
           Private/unregistered: 'svcn' (0x7376636E) offset=1284 size=1356
           Private/unregistered: 'gbd1' (0x67626431) offset=2660 size=22052
           [INFO] 4 private/unregistered tag(s) detected
      [WARN]  4 non-conformance(s)

[H1093] CF-093: Private Tag Content Scan
  [CF-093] Private Tag Content Security Scan (ICC.1-2022-05 §9)
           [OK] 4 private tag(s) scanned — no malware signatures
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


Deep Conformance Summary: 21 issue(s)

=======================================================================
PHASE 3: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/sRGB_D65_MAT.icc

Device Class: 0x6D6E7472

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
  Device Class:    0x6D6E7472  ''  DisplayClass
  Color Space:     0x52474220  'RGB'  RgbData
  PCS:             0x58595A20  'XYZ'  XYZData
  Manufacturer:    0x00000000  '....'
  Model:           0x00000000  '....'

Tag Signatures:
Idx  Tag          FourCC     Type         Issues
---  ------------ ---------- ------------ ------
0    profileDescriptionTag 'desc    '  multiLocalizedUnicodeType
1    copyrightTag 'cprt    '  multiLocalizedUnicodeType
2    AToB1Tag     'A2B1    '  multiProcessElementType
3    BToA1Tag     'B2A1    '  multiProcessElementType
4    customToStandardPccTag 'c2sp    '  multiProcessElementType
5    standardToCustomPccTag 's2cp    '  multiProcessElementType
6    spectralViewingConditionsTag 'svcn    '  spectralViewingConditionsType
7    mediaWhitePointTag 'wtpt    '  XYZArrayType
8    gamutBoundaryDescription1Tag 'gbd1    '  gamutBoundaryDescType

Summary: 0 signature issue(s) detected

=======================================================================
PHASE 5: PROFILE STRUCTURE DUMP
=======================================================================

=== ICC Profile Header ===

=== ICC Profile Header (0x0000-0x007F) ===
0x0000: 00 00 60 88 00 00 00 00  05 00 00 00 6D 6E 74 72  |..`.........mntr|
0x0010: 52 47 42 20 58 59 5A 20  07 EA 00 02 00 11 00 08  |RGB XYZ ........|
0x0020: 00 26 00 0D 61 63 73 70  00 00 00 00 00 00 00 01  |.&..acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 4D  00 01 00 00 00 01 16 C2  |.......M........|
0x0050: 49 43 43 20 33 17 4F 15  AB B4 D7 91 A2 AC E1 BF  |ICC 3.O.........|
0x0060: 69 49 96 C1 00 00 00 00  00 00 00 00 00 00 00 00  |iI..............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields:
  Size:              0x00006088 (24712 bytes)
  CMM Type:          '....' (0x00000000)
  Version:           5.0.0.0 (0x05000000)
  Device Class:      DisplayClass
  Color Space:       RgbData (3 channels)
  PCS:               XYZData
  Date/Time:         2026-02-17 08:38:13
  Magic:             0x61637370 [OK]
  Platform:          Unknown
  Profile Flags:     0x00000001 [Embedded]
  Manufacturer:      '....' (0x00000000)
  Model:             '....' (0x00000000)
  Device Attribs:    0x0000000000000000
  Rendering Intent:  Relative Colorimetric (1)
  PCS Illuminant:    X=0.9504 Y=1.0000 Z=1.0889
  Creator:           'ICC ' (0x49434320)
  Profile ID:        33174f15abb4d791a2ace1bf694996c1

  --- ICC v5/iccMAX Extended Header ---
  Spectral PCS:      NoSpectralData
  Spectral Range:    Not Defined
  BiSpectral Range:  Not Defined
  MCS Color Space:   Not Defined

=== Tag Table ===

=== Tag Table ===
Tag Count: 9

Tag Table Raw Data (0x0080-0x00F0):
0x0080: 00 00 00 09 64 65 73 63  00 00 00 F0 00 00 00 36  |....desc.......6|
0x0090: 63 70 72 74 00 00 01 28  00 00 00 78 41 32 42 31  |cprt...(...xA2B1|
0x00A0: 00 00 01 A0 00 00 01 58  42 32 41 31 00 00 02 F8  |.......XB2A1....|
0x00B0: 00 00 01 64 63 32 73 70  00 00 04 5C 00 00 00 54  |...dc2sp...\...T|
0x00C0: 73 32 63 70 00 00 04 B0  00 00 00 54 73 76 63 6E  |s2cp.......Tsvcn|
0x00D0: 00 00 05 04 00 00 05 4C  77 74 70 74 00 00 0A 50  |.......Lwtpt...P|
0x00E0: 00 00 00 14 67 62 64 31  00 00 0A 64 00 00 56 24  |....gbd1...d..V$|

Tag Entries:
Idx  Signature    FourCC       Offset     Size
---  ------------ ------------ ---------- ----
0    profileDescriptionTag 'desc      '  0x000000F0  54
1    copyrightTag 'cprt      '  0x00000128  120
2    AToB1Tag     'A2B1      '  0x000001A0  344
3    BToA1Tag     'B2A1      '  0x000002F8  356
4    customToStandardPccTag 'c2sp      '  0x0000045C  84
5    standardToCustomPccTag 's2cp      '  0x000004B0  84
6    spectralViewingConditionsTag 'svcn      '  0x00000504  1356
7    mediaWhitePointTag 'wtpt      '  0x00000A50  20
8    gamutBoundaryDescription1Tag 'gbd1      '  0x00000A64  22052

=======================================================================
PHASE 6: TAG CONTENT ANALYSIS
=======================================================================

--- 5A: LUT Tag Geometry ---

  No legacy LUT tags (A2B/B2A/D2B/B2D) found

--- 5B: MPE Element Chains ---

  [A2B1] MPE Tag 'A2B1'
      Input channels:  3
      Output channels: 3
      Elements:        2

      === MPE Element Chain: 2 elements, 3→3 channels ===
      [1] Curve Set Element ('cvst') 3→3
      [2] Matrix Element ('matf') 3→3
      ===

  [B2A1] MPE Tag 'B2A1'
      Input channels:  3
      Output channels: 3
      Elements:        2

      === MPE Element Chain: 2 elements, 3→3 channels ===
      [1] Matrix Element ('matf') 3→3
      [2] Curve Set Element ('cvst') 3→3
      ===

--- 5C: TRC Curve Analysis ---

  No TRC curve tags found

--- 5D: NamedColor2 Validation ---

  No NamedColor2 tag

--- 5E: XYZ Tag Values ---

  [wtpt] X=0.9504 Y=1.0000 Z=1.0889

--- 5F: ICC v5 Spectral Data ---

  SpectralViewingConditions:
      Observer:    CIE 1931 (two degree) standard observer
      Illuminant:  Illuminant D65 (CCT=6500 K)
      Illuminant XYZ: (0.9504, 1.0000, 1.0889)
  PCC Transform Tags:  c2sp=PRESENT  s2cp=PRESENT

--- 5G: Profile ID Verification ---

  Profile ID (header):   33174f15abb4d791a2ace1bf694996c1
  Profile ID (computed): 33174f15abb4d791a2ace1bf694996c1
  [OK] Profile ID matches — integrity verified

--- 5H: Per-Tag Size Analysis ---

  Tag sizes (flagging >10MB):
      [OK] All tags within 10MB limit

--- 5I: V5/iccMAX Summary ---

  --- V5/iccMAX Profile Summary ---

  BRDF Tags:              0 of 16 present
  Gamut Boundary Desc:    gbd0=---  gbd1=PRESENT

  MPE Tags:               4 (multiProcessElementsType)
  Total MPE Elements:     6
  Calculator Elements:    0
  Late-Binding Elements:  0 (spectral observer/emission)

--- 5J: Version Classification & Capabilities ---

  Version Classification:
    ICC Version:       5.0.0
    Specification:     ICC.2 (iccMAX)
    Features:          MPE, Spectral PCS, Calculator, BRDF, MCS, Named Colors
    Device Class:      DisplayClass
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

File: /home/h02332/po/research/test-profiles/sRGB_D65_MAT.icc
Mode: Conformance (ICC specification audit)
Total Issues Detected: 24

[WARN] ANALYSIS COMPLETE - 24 issue(s) detected
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

File: /home/h02332/po/research/test-profiles/sRGB_D65_MAT.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 24712 bytes (0x6088)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 60 88 00 00 00 00  05 00 00 00 6D 6E 74 72  |..`.........mntr|
0x0010: 52 47 42 20 58 59 5A 20  07 EA 00 02 00 11 00 08  |RGB XYZ ........|
0x0020: 00 26 00 0D 61 63 73 70  00 00 00 00 00 00 00 01  |.&..acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 4D  00 01 00 00 00 01 16 C2  |.......M........|
0x0050: 49 43 43 20 33 17 4F 15  AB B4 D7 91 A2 AC E1 BF  |ICC 3.O.........|
0x0060: 69 49 96 C1 00 00 00 00  00 00 00 00 00 00 00 00  |iI..............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x00006088 (24712 bytes) OK
  CMM:             0x00000000  '....'
  Version:         0x05000000  (5.0.0)
  Device Class:    0x6D6E7472  'mntr'
  Color Space:     0x52474220  'RGB '
  PCS:             0x58595A20  'XYZ '
  Date/Time:       2026-02-17 08:38:13
  Magic:           0x61637370  [OK 'acsp']
  Platform:        0x00000000  '....'
  Flags:           0x00000001 [Embedded]
  Manufacturer:    0x00000000  '....'
  Model:           0x00000000  '....'
  Dev Attributes:  0x0000000000000000
  Rendering Intent:0x00000001  Relative Colorimetric
  PCS Illuminant:  X=0.9504 Y=1.0000 Z=1.0889
  Creator:         0x49434320  'ICC '
  Profile ID:      33174f15abb4d791a2ace1bf694996c1
  Reserved 100-127: all zeros [OK]

  --- V5/iccMAX Extended Header ---
  Spectral PCS:    0x58595A20  'XYZ '
  Spectral Range:  Not defined

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 9 (0x00000009)

Tag Table Raw Data:
0x0080: 00 00 00 09 64 65 73 63  00 00 00 F0 00 00 00 36  |....desc.......6|
0x0090: 63 70 72 74 00 00 01 28  00 00 00 78 41 32 42 31  |cprt...(...xA2B1|
0x00A0: 00 00 01 A0 00 00 01 58  42 32 41 31 00 00 02 F8  |.......XB2A1....|
0x00B0: 00 00 01 64 63 32 73 70  00 00 04 5C 00 00 00 54  |...dc2sp...\...T|
0x00C0: 73 32 63 70 00 00 04 B0  00 00 00 54 73 76 63 6E  |s2cp.......Tsvcn|
0x00D0: 00 00 05 04 00 00 05 4C  77 74 70 74 00 00 0A 50  |.......Lwtpt...P|
0x00E0: 00 00 00 14 67 62 64 31  00 00 0A 64 00 00 56 24  |....gbd1...d..V$|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x64657363   'desc'        0x000000F0   0x00000036   'mluc'        OK
1    0x63707274   'cprt'        0x00000128   0x00000078   'mluc'        OK
2    0x41324231   'A2B1'        0x000001A0   0x00000158   'mpet'        OK
3    0x42324131   'B2A1'        0x000002F8   0x00000164   'mpet'        OK
4    0x63327370   'c2sp'        0x0000045C   0x00000054   'mpet'        OK
5    0x73326370   's2cp'        0x000004B0   0x00000054   'mpet'        OK
6    0x7376636E   'svcn'        0x00000504   0x0000054C   'svcn'        OK
7    0x77747074   'wtpt'        0x00000A50   0x00000014   'XYZ '        OK
8    0x67626431   'gbd1'        0x00000A64   0x00005624   'gbd '        OK

=== FULL FILE HEX DUMP (all 24712 bytes) ===
0x0000: 00 00 60 88 00 00 00 00  05 00 00 00 6D 6E 74 72  |..`.........mntr|
0x0010: 52 47 42 20 58 59 5A 20  07 EA 00 02 00 11 00 08  |RGB XYZ ........|
0x0020: 00 26 00 0D 61 63 73 70  00 00 00 00 00 00 00 01  |.&..acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F3 4D  00 01 00 00 00 01 16 C2  |.......M........|
0x0050: 49 43 43 20 33 17 4F 15  AB B4 D7 91 A2 AC E1 BF  |ICC 3.O.........|
0x0060: 69 49 96 C1 00 00 00 00  00 00 00 00 00 00 00 00  |iI..............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0080: 00 00 00 09 64 65 73 63  00 00 00 F0 00 00 00 36  |....desc.......6|
0x0090: 63 70 72 74 00 00 01 28  00 00 00 78 41 32 42 31  |cprt...(...xA2B1|
0x00A0: 00 00 01 A0 00 00 01 58  42 32 41 31 00 00 02 F8  |.......XB2A1....|
0x00B0: 00 00 01 64 63 32 73 70  00 00 04 5C 00 00 00 54  |...dc2sp...\...T|
0x00C0: 73 32 63 70 00 00 04 B0  00 00 00 54 73 76 63 6E  |s2cp.......Tsvcn|
0x00D0: 00 00 05 04 00 00 05 4C  77 74 70 74 00 00 0A 50  |.......Lwtpt...P|
0x00E0: 00 00 00 14 67 62 64 31  00 00 0A 64 00 00 56 24  |....gbd1...d..V$|
0x00F0: 6D 6C 75 63 00 00 00 00  00 00 00 01 00 00 00 0C  |mluc............|
0x0100: 65 6E 55 53 00 00 00 1A  00 00 00 1C 00 73 00 52  |enUS.........s.R|
0x0110: 00 47 00 42 00 20 00 44  00 36 00 35 00 20 00 4D  |.G.B. .D.6.5. .M|
0x0120: 00 41 00 54 00 00 00 00  6D 6C 75 63 00 00 00 00  |.A.T....mluc....|
0x0130: 00 00 00 01 00 00 00 0C  65 6E 55 53 00 00 00 5C  |........enUS...\|
0x0140: 00 00 00 1C 00 43 00 6F  00 70 00 79 00 72 00 69  |.....C.o.p.y.r.i|
0x0150: 00 67 00 68 00 74 00 20  00 32 00 30 00 31 00 37  |.g.h.t. .2.0.1.7|
0x0160: 00 20 00 49 00 6E 00 74  00 65 00 72 00 6E 00 61  |. .I.n.t.e.r.n.a|
0x0170: 00 74 00 69 00 6F 00 6E  00 61 00 6C 00 20 00 43  |.t.i.o.n.a.l. .C|
0x0180: 00 6F 00 6C 00 6F 00 72  00 20 00 43 00 6F 00 6E  |.o.l.o.r. .C.o.n|
0x0190: 00 73 00 6F 00 72 00 74  00 69 00 75 00 6D 00 00  |.s.o.r.t.i.u.m..|
0x01A0: 6D 70 65 74 00 00 00 00  00 03 00 03 00 00 00 02  |mpet............|
0x01B0: 00 00 00 20 00 00 00 FC  00 00 01 1C 00 00 00 3C  |... ...........<|
0x01C0: 63 76 73 74 00 00 00 00  00 03 00 03 00 00 00 24  |cvst...........$|
0x01D0: 00 00 00 48 00 00 00 6C  00 00 00 48 00 00 00 B4  |...H...l...H....|
0x01E0: 00 00 00 48 63 75 72 66  00 00 00 00 00 02 00 00  |...Hcurf........|
0x01F0: 3D 25 E3 54 70 61 72 66  00 00 00 00 00 00 00 00  |=%.Tparf........|
0x0200: 3F 80 00 00 3D 9E 83 91  00 00 00 00 00 00 00 00  |?...=...........|
0x0210: 70 61 72 66 00 00 00 00  00 00 00 00 40 19 99 9A  |parf........@...|
0x0220: 3F 72 A7 6E 3D 55 89 19  00 00 00 00 63 75 72 66  |?r.n=U......curf|
0x0230: 00 00 00 00 00 02 00 00  3D 25 E3 54 70 61 72 66  |........=%.Tparf|
0x0240: 00 00 00 00 00 00 00 00  3F 80 00 00 3D 9E 83 91  |........?...=...|
0x0250: 00 00 00 00 00 00 00 00  70 61 72 66 00 00 00 00  |........parf....|
0x0260: 00 00 00 00 40 19 99 9A  3F 72 A7 6E 3D 55 89 19  |....@...?r.n=U..|
0x0270: 00 00 00 00 63 75 72 66  00 00 00 00 00 02 00 00  |....curf........|
0x0280: 3D 25 E3 54 70 61 72 66  00 00 00 00 00 00 00 00  |=%.Tparf........|
0x0290: 3F 80 00 00 3D 9E 83 91  00 00 00 00 00 00 00 00  |?...=...........|
0x02A0: 70 61 72 66 00 00 00 00  00 00 00 00 40 19 99 9A  |parf........@...|
0x02B0: 3F 72 A7 6E 3D 55 89 19  00 00 00 00 6D 61 74 66  |?r.n=U......matf|
0x02C0: 00 00 00 00 00 03 00 03  3E D3 1F 57 3E B7 17 87  |........>..W>...|
0x02D0: 3E 38 C7 EB 3E 59 B8 52  3F 37 17 87 3D 93 D3 23  |>8..>Y.R?7..=..#|
0x02E0: 3C 9E 57 81 3D F4 1F 5F  3F 73 4B 7F 00 00 00 00  |<.W.=.._?sK.....|
0x02F0: 00 00 00 00 00 00 00 00  6D 70 65 74 00 00 00 00  |........mpet....|
0x0300: 00 03 00 03 00 00 00 02  00 00 00 20 00 00 00 3C  |........... ...<|
0x0310: 00 00 00 5C 00 00 01 08  6D 61 74 66 00 00 00 00  |...\....matf....|
0x0320: 00 03 00 03 40 4F 71 80  BF C4 CE 24 BE FF 50 9E  |....@Oq....$..P.|
0x0330: BF 78 1D 53 3F F0 1C C6  3D 2A 33 8F 3D 63 E6 47  |.x.S?...=*3.=c.G|
0x0340: BE 50 E8 6B 3F 87 50 BA  00 00 00 00 00 00 00 00  |.P.k?.P.........|
0x0350: 00 00 00 00 63 76 73 74  00 00 00 00 00 03 00 03  |....cvst........|
0x0360: 00 00 00 24 00 00 00 4C  00 00 00 70 00 00 00 4C  |...$...L...p...L|
0x0370: 00 00 00 BC 00 00 00 4C  63 75 72 66 00 00 00 00  |.......Lcurf....|
0x0380: 00 02 00 00 3B 4D 2E 1C  70 61 72 66 00 00 00 00  |....;M..parf....|
0x0390: 00 00 00 00 3F 80 00 00  41 4E B8 52 00 00 00 00  |....?...AN.R....|
0x03A0: 00 00 00 00 70 61 72 66  00 00 00 00 00 03 00 00  |....parf........|
0x03B0: 3E D5 55 55 3F 87 0A 3D  3F 80 00 00 00 00 00 00  |>.UU?..=?.......|
0x03C0: BD 61 47 AE 63 75 72 66  00 00 00 00 00 02 00 00  |.aG.curf........|
0x03D0: 3B 4D 2E 1C 70 61 72 66  00 00 00 00 00 00 00 00  |;M..parf........|
0x03E0: 3F 80 00 00 41 4E B8 52  00 00 00 00 00 00 00 00  |?...AN.R........|
0x03F0: 70 61 72 66 00 00 00 00  00 03 00 00 3E D5 55 55  |parf........>.UU|
0x0400: 3F 87 0A 3D 3F 80 00 00  00 00 00 00 BD 61 47 AE  |?..=?........aG.|
0x0410: 63 75 72 66 00 00 00 00  00 02 00 00 3B 4D 2E 1C  |curf........;M..|
0x0420: 70 61 72 66 00 00 00 00  00 00 00 00 3F 80 00 00  |parf........?...|
0x0430: 41 4E B8 52 00 00 00 00  00 00 00 00 70 61 72 66  |AN.R........parf|
0x0440: 00 00 00 00 00 03 00 00  3E D5 55 55 3F 87 0A 3D  |........>.UU?..=|
0x0450: 3F 80 00 00 00 00 00 00  BD 61 47 AE 6D 70 65 74  |?........aG.mpet|
0x0460: 00 00 00 00 00 03 00 03  00 00 00 01 00 00 00 18  |................|
0x0470: 00 00 00 3C 6D 61 74 66  00 00 00 00 00 03 00 03  |...<matf........|
0x0480: 3F 91 7D 76 BD 4D 95 09  BD 77 AB B3 3D C9 35 F2  |?.}v.M...w..=.5.|
0x0490: 3F 6F 45 3E BC D2 F0 06  BD 0C 66 EC 3D 1C DF E7  |?oE>......f.=...|
0x04A0: 3F 40 91 B7 00 00 00 00  00 00 00 00 00 00 00 00  |?@..............|
0x04B0: 6D 70 65 74 00 00 00 00  00 03 00 03 00 00 00 01  |mpet............|
0x04C0: 00 00 00 18 00 00 00 3C  6D 61 74 66 00 00 00 00  |.......<matf....|
0x04D0: 00 03 00 03 3F 60 CD B5  3D 35 0C EA 3D 93 A9 BB  |....?`..=5..=...|
0x04E0: BD BA 86 8D 3F 88 2B C5  3C EE 58 59 3D 36 E5 E1  |....?.+.<.XY=6..|
0x04F0: BD 55 9C 49 3F AA 64 A5  00 00 00 00 00 00 00 00  |.U.I?.d.........|
0x0500: 00 00 00 00 73 76 63 6E  00 00 00 00 00 00 00 01  |....svcn........|
0x0510: 5D F0 62 18 00 51 00 00  3A B3 4E 77 3B 12 89 DB  |].b..Q..:.Nw;...|
0x0520: 3B 8B 08 DD 3B FA AC DA  3C 6A 74 7E 3C BD F8 F4  |;...;...<jt~<...|
0x0530: 3D 32 37 8B 3D 9E FC 7A  3E 09 9A E9 3E 5B EC AB  |=27.=..z>...>[..|
0x0540: 3E 91 5B 57 3E A8 31 27  3E B2 51 C2 3E B2 34 EC  |>.[W>.1'>.Q.>.4.|
0x0550: 3E AC 22 68 3E A3 2C A5  3E 94 E3 BD 3E 80 90 2E  |>."h>.,.>...>...|
0x0560: 3E 48 0C 74 3E 11 82 AA  3D C3 DE E8 3D 6D 5C FB  |>H.t>...=...=m\.|
0x0570: 3D 03 1C EB 3C 70 D8 45  3B A0 90 2E 3B 1D 49 52  |=...<p.E;...;.IR|
0x0580: 3C 18 5F 07 3C EE 63 20  3D 81 93 B4 3D E0 75 F7  |<._.<.c =...=.u.|
0x0590: 3E 29 78 D5 3E 67 2B 02  3E 94 AF 4F 3E B8 2A 99  |>)x.>g+.>..O>.*.|
0x05A0: 3E DD ED 29 3F 03 15 B5  3F 18 31 27 3F 2D AB 9F  |>..)?...?.1'?-..|
0x05B0: 3F 43 18 FC 3F 57 AE 14  3F 6A 92 A3 3F 7A 85 88  |?C..?W..?j..?z..|
0x05C0: 3F 83 5D CC 3F 87 41 F2  3F 87 F6 2B 3F 85 D6 39  |?.].?.A.?..+?..9|
0x05D0: 3F 80 55 32 3F 70 3A FB  3F 5A BD 3C 3F 40 5B C0  |?.U2?p:.?Z.<?@[.|
0x05E0: 3F 24 74 54 3F 0A B9 F5  3E E5 53 26 3E B8 BA C7  |?$tT?...>.S&>...|
0x05F0: 3E 91 26 E9 3E 5F F2 E5  3E 28 DB 8C 3D F8 37 B5  |>.&.>_..>(..=.7.|
0x0600: 3D B2 FE C5 3D 82 40 B8  3D 3F 91 E6 3D 06 C2 27  |=...=.@.=?..=..'|
0x0610: 3C B9 F5 5A 3C 81 C2 E3  3C 3A 1B 19 3C 04 E4 00  |<..Z<...<:..<...|
0x0620: 3B BD BA 0A 3B 86 A4 CA  3B 3D FD 26 3B 06 48 84  |;...;...;=.&;.H.|
0x0630: 3A BC BE 62 3A 83 12 6F  3A 34 E1 1E 39 F9 8F A3  |:..b:..o:4..9...|
0x0640: 39 AE 10 49 39 76 6A 55  39 2E 10 49 38 F5 5D E6  |9..I9vjU9..I8.].|
0x0650: 38 AE 10 49 38 77 76 C5  38 30 29 28 38 23 93 EE  |8..I8wv.80)(8#..|
0x0660: 38 86 37 BD 38 FB A8 82  39 63 8A 7E 39 CF 9E 38  |8.7.8...9c.~9..8|
0x0670: 3A 27 C5 AC 3A 9E 98 DD  3B 0E DE 55 3B 83 12 6F  |:'..:...;..U;..o|
0x0680: 3B EF 34 D7 3C 3E 0D ED  3C 89 F4 0A 3C BC 6A 7F  |;.4.<>..<...<.j.|
0x0690: 3C F4 1F 21 3D 1B A5 E3  3D 44 9B A6 3D 75 C2 8F  |<..!=...=D..=u..|
0x06A0: 3D 97 58 E2 3D BA 53 B9  3D E6 9A D4 3E 0E 5B 42  |=.X.=.S.=...>.[B|
0x06B0: 3E 2D 5C FB 3E 55 03 32  3E 84 67 38 3E A5 60 42  |>-\.>U.2>.g8>.`B|
0x06C0: 3E D0 89 A0 3F 00 C4 9C  3F 1B B2 FF 3F 35 C2 8F  |>...?...?...?5..|
0x06D0: 3F 4B 0F 28 3F 5C AC 08  3F 6A 33 9C 3F 74 39 58  |?K.(?\..?j3.?t9X|
0x06E0: 3F 7A F4 F1 3F 7E B5 0B  3F 80 00 00 3F 7E B8 52  |?z..?~..?...?~.R|
0x06F0: 3F 7A 85 88 3F 73 B6 46  3F 6A 57 A8 3F 5E B8 52  |?z..?s.F?jW.?^.R|
0x0700: 3F 50 F9 09 3F 41 CA C1  3F 31 E4 F7 3F 21 89 37  |?P..?A..?1..?!.7|
0x0710: 3F 11 19 CE 3F 00 C4 9C  3E E1 E4 F7 3E C3 12 6F  |?...?...>...>..o|
0x0720: 3E A4 5A 1D 3E 87 AE 14  3E 5E 35 3F 3E 33 33 33  |>.Z.>...>^5?>333|
0x0730: 3E 0D 84 4D 3D DB 22 D1  3D A7 1D E7 3D 79 DB 23  |>..M=.".=...=y.#|
0x0740: 3D 36 99 85 3D 03 12 6F  3C BE 0D ED 3C 8B 43 96  |=6..=..o<...<.C.|
0x0750: 3C 43 4C 1B 3C 06 83 3C  3B BB 88 01 3B 86 6A 12  |<CL.<..<;...;.j.|
0x0760: 3B 3F F4 77 3B 09 09 29  3A C2 82 C7 3A 89 3B 7E  |;?.w;..):...:.;~|
0x0770: 3A 41 FC 8F 3A 08 50 9C  39 BD 44 9A 39 82 8C 37  |:A..:.P.9.D.9..7|
0x0780: 39 34 5A E6 38 FB A8 82  38 B2 42 07 38 7B A8 82  |94Z.8...8.B.8{..|
0x0790: 38 30 29 28 37 FB A8 82  37 B0 29 28 37 7B A8 82  |80)(7...7.)(7{..|
0x07A0: 3B D3 5A 86 3C 2C D9 E8  3C A4 3F E6 3D 14 50 F0  |;.Z.<,..<.?.=.P.|
0x07B0: 3D 8A F4 F1 3D E1 B0 8A  3E 54 60 AA 3E BE 1B 09  |=...=...>T`.>...|
0x07C0: 3F 25 46 0B 3F 84 FF 97  3F B1 5B 57 3F CF BD 27  |?%F.?...?.[W?..'|
0x07D0: 3F DF 9F A9 3F E4 2C 3D  3F E2 D4 80 3F DF 3E AB  |?...?.,=?...?.>.|
0x07E0: 3F D5 A8 58 3F C3 98 C8  3F A4 D1 63 3F 85 5C FB  |?..X?...?..c?.\.|
0x07F0: 3F 50 1D 7E 3F 1D BF 48  3E EE 2C 13 3E B4 E3 BD  |?P.~?..H>.,.>...|
0x0800: 3E 8B 43 96 3E 59 65 2C  3E 21 FF 2E 3D E4 C2 F8  |>.C.>Ye,>!..=...|
0x0810: 3D A0 41 89 3D 6A 7E FA  3D 2C AF F7 3C F4 73 04  |=.A.=j~.=,..<.s.|
0x0820: 3C A6 4C 30 3C 5B 8B AC  3C 0F 5C 29 3B BC 6A 7F  |<.L0<[..<.\);.j.|
0x0830: 3B 7F 97 24 3B 34 39 58  3B 09 A0 27 3A EB ED FA  |;..$;49X;..':...|
0x0840: 3A D8 44 D0 3A B7 80 34  3A 90 2D E0 3A 83 12 6F  |:.D.:..4:.-.:..o|
0x0850: 3A 51 B7 17 3A 1D 49 52  39 B2 42 07 39 7B A8 82  |:Q..:.IR9.B.9{..|
0x0860: 39 47 3A BD 38 D1 B7 17  38 51 B7 17 37 FB A8 82  |9G:.8...8Q..7...|
0x0870: 37 A7 C5 AC 37 27 C5 AC  00 00 00 00 00 00 00 00  |7...7'..........|
0x0880: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0890: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x08A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x08B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x08C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x08D0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x08E0: 00 00 00 00 00 00 00 02  45 CB 20 00 5D F0 62 18  |........E. .].b.|
0x08F0: 00 51 00 00 42 47 E6 E9  42 51 3F 48 42 5A 97 C2  |.Q..BG..BQ?HBZ..|
0x0900: 42 89 67 2B 42 A5 82 82  42 AE 3D A5 42 B6 F8 D5  |B.g+B...B.=.B...|
0x0910: 42 B8 EA F5 42 BA DD 15  42 B4 1D 2F 42 AD 5D 56  |B...B...B../B.]V|
0x0920: 42 BF 8C 15 42 D1 BA E1  42 DD DF 3B 42 EA 04 19  |B...B...B..;B...|
0x0930: 42 EA D1 EC 42 EB 9F BE  42 E8 AC 08 42 E5 B8 D5  |B...B...B...B...|
0x0940: 42 E6 C8 B4 42 E7 D8 93  42 E0 BB E7 42 D9 9F 3B  |B...B...B...B..;|
0x0950: 42 DA 29 FC 42 DA B5 3F  42 D9 27 F0 42 D7 9A A0  |B.).B..?B.'.B...|
0x0960: 42 D4 97 8D 42 D1 94 7B  42 D4 7A 5E 42 D7 60 C5  |B...B..{B.z^B.`.|
0x0970: 42 D4 18 10 42 D0 CF 5C  42 D0 73 33 42 D0 17 8D  |B...B..\B.s3B...|
0x0980: 42 CC 0B C7 42 C8 00 00  42 C4 55 8E 42 C0 AB 1C  |B...B...B.U.B...|
0x0990: 42 C0 1F 48 42 BF 93 75  42 B8 79 3E 42 B1 5F 07  |B..HB..uB.y>B._.|
0x09A0: 42 B2 B1 1A 42 B4 03 2D  42 B3 9A EE 42 B3 32 BD  |B...B..-B...B.2.|
0x09B0: 42 B1 4C 3D 42 AF 65 BC  42 AA FC B9 42 A6 93 C3  |B.L=B.e.B...B...|
0x09C0: 42 A6 FC E0 42 A7 65 FE  42 A3 B9 DB 42 A0 0D B9  |B...B.e.B...B...|
0x09D0: 42 A0 3D CC 42 A0 6D E0  42 A2 7E 0E 42 A4 8E 3C  |B.=.B.m.B.~.B..<|
0x09E0: 42 A0 8F DF 42 9C 91 83  42 94 01 62 42 8B 71 4E  |B...B...B..bB.qN|
0x09F0: 42 8D 54 95 42 8F 37 DC  42 91 F5 3F 42 94 B2 B0  |B.T.B.7.B..?B...|
0x0A00: 42 87 F3 F8 42 76 6A 7F  42 83 7D 56 42 8B C5 6D  |B...Bvj.B.}VB..m|
0x0A10: 42 90 F8 FC 42 96 2C 8B  42 8A AD FA 42 7E 5E ED  |B...B.,.B...B~^.|
0x0A20: 42 5C 05 88 42 39 AC 3D  42 62 72 7C 42 85 9C 5D  |B\..B9.=Bbr|B..]|
0x0A30: 42 82 30 2E 42 7D 87 FD  3F 73 4D 6A 3F 80 00 00  |B.0.B}..?sMj?...|
0x0A40: 3F 8B 61 13 3F 73 4D 6A  3F 80 00 00 3F 8B 61 13  |?.a.?sMj?...?.a.|
0x0A50: 58 59 5A 20 00 00 00 00  00 00 F3 4D 00 01 00 00  |XYZ .......M....|
0x0A60: 00 01 16 C2 67 62 64 20  00 00 00 00 00 03 00 03  |....gbd ........|
0x0A70: 00 00 01 D4 00 00 03 84  00 00 00 01 00 00 00 02  |................|
0x0A80: 00 00 00 13 00 00 00 02  00 00 00 03 00 00 00 14  |................|
0x0A90: 00 00 00 03 00 00 00 04  00 00 00 15 00 00 00 04  |................|
0x0AA0: 00 00 00 05 00 00 00 16  00 00 00 05 00 00 00 06  |................|
0x0AB0: 00 00 00 17 00 00 00 06  00 00 00 07 00 00 00 18  |................|
0x0AC0: 00 00 00 07 00 00 00 08  00 00 00 19 00 00 00 08  |................|
0x0AD0: 00 00 00 09 00 00 00 1A  00 00 00 09 00 00 00 0A  |................|
0x0AE0: 00 00 00 1B 00 00 00 0A  00 00 00 0B 00 00 00 1C  |................|
0x0AF0: 00 00 00 0B 00 00 00 0C  00 00 00 1D 00 00 00 0C  |................|
0x0B00: 00 00 00 0D 00 00 00 1E  00 00 00 0D 00 00 00 0E  |................|
0x0B10: 00 00 00 1F 00 00 00 0E  00 00 00 0F 00 00 00 20  |............... |
0x0B20: 00 00 00 0F 00 00 00 10  00 00 00 21 00 00 00 10  |...........!....|
0x0B30: 00 00 00 11 00 00 00 22  00 00 00 11 00 00 00 12  |......."........|
0x0B40: 00 00 00 23 00 00 00 12  00 00 00 01 00 00 00 24  |...#...........$|
0x0B50: 00 00 00 13 00 00 00 14  00 00 00 25 00 00 00 14  |...........%....|
0x0B60: 00 00 00 15 00 00 00 26  00 00 00 15 00 00 00 16  |.......&........|
0x0B70: 00 00 00 27 00 00 00 16  00 00 00 17 00 00 00 28  |...'...........(|
0x0B80: 00 00 00 17 00 00 00 18  00 00 00 29 00 00 00 18  |...........)....|
0x0B90: 00 00 00 19 00 00 00 2A  00 00 00 19 00 00 00 1A  |.......*........|
0x0BA0: 00 00 00 2B 00 00 00 1A  00 00 00 1B 00 00 00 2C  |...+...........,|
0x0BB0: 00 00 00 1B 00 00 00 1C  00 00 00 2D 00 00 00 1C  |...........-....|
0x0BC0: 00 00 00 1D 00 00 00 2E  00 00 00 1D 00 00 00 1E  |................|
0x0BD0: 00 00 00 2F 00 00 00 1E  00 00 00 1F 00 00 00 30  |.../...........0|
0x0BE0: 00 00 00 1F 00 00 00 20  00 00 00 31 00 00 00 20  |....... ...1... |
0x0BF0: 00 00 00 21 00 00 00 32  00 00 00 21 00 00 00 22  |...!...2...!..."|
0x0C00: 00 00 00 33 00 00 00 22  00 00 00 23 00 00 00 34  |...3..."...#...4|
0x0C10: 00 00 00 23 00 00 00 24  00 00 00 35 00 00 00 24  |...#...$...5...$|
0x0C20: 00 00 00 13 00 00 00 36  00 00 00 25 00 00 00 26  |.......6...%...&|
0x0C30: 00 00 00 37 00 00 00 26  00 00 00 27 00 00 00 38  |...7...&...'...8|
0x0C40: 00 00 00 27 00 00 00 28  00 00 00 39 00 00 00 28  |...'...(...9...(|
0x0C50: 00 00 00 29 00 00 00 3A  00 00 00 29 00 00 00 2A  |...)...:...)...*|
0x0C60: 00 00 00 3B 00 00 00 2A  00 00 00 2B 00 00 00 3C  |...;...*...+...<|
0x0C70: 00 00 00 2B 00 00 00 2C  00 00 00 3D 00 00 00 2C  |...+...,...=...,|
0x0C80: 00 00 00 2D 00 00 00 3E  00 00 00 2D 00 00 00 2E  |...-...>...-....|
0x0C90: 00 00 00 3F 00 00 00 2E  00 00 00 2F 00 00 00 40  |...?......./...@|
0x0CA0: 00 00 00 2F 00 00 00 30  00 00 00 41 00 00 00 30  |.../...0...A...0|
0x0CB0: 00 00 00 31 00 00 00 42  00 00 00 31 00 00 00 32  |...1...B...1...2|
0x0CC0: 00 00 00 43 00 00 00 32  00 00 00 33 00 00 00 44  |...C...2...3...D|
0x0CD0: 00 00 00 33 00 00 00 34  00 00 00 45 00 00 00 34  |...3...4...E...4|
0x0CE0: 00 00 00 35 00 00 00 46  00 00 00 35 00 00 00 36  |...5...F...5...6|
0x0CF0: 00 00 00 47 00 00 00 36  00 00 00 25 00 00 00 48  |...G...6...%...H|
0x0D00: 00 00 00 37 00 00 00 38  00 00 00 49 00 00 00 38  |...7...8...I...8|
0x0D10: 00 00 00 39 00 00 00 4A  00 00 00 39 00 00 00 3A  |...9...J...9...:|
0x0D20: 00 00 00 4B 00 00 00 3A  00 00 00 3B 00 00 00 4C  |...K...:...;...L|
0x0D30: 00 00 00 3B 00 00 00 3C  00 00 00 4D 00 00 00 3C  |...;...<...M...<|
0x0D40: 00 00 00 3D 00 00 00 4E  00 00 00 3D 00 00 00 3E  |...=...N...=...>|
0x0D50: 00 00 00 4F 00 00 00 3E  00 00 00 3F 00 00 00 50  |...O...>...?...P|
0x0D60: 00 00 00 3F 00 00 00 40  00 00 00 51 00 00 00 40  |...?...@...Q...@|
0x0D70: 00 00 00 41 00 00 00 52  00 00 00 41 00 00 00 42  |...A...R...A...B|
0x0D80: 00 00 00 53 00 00 00 42  00 00 00 43 00 00 00 54  |...S...B...C...T|
0x0D90: 00 00 00 43 00 00 00 44  00 00 00 55 00 00 00 44  |...C...D...U...D|
0x0DA0: 00 00 00 45 00 00 00 56  00 00 00 45 00 00 00 46  |...E...V...E...F|
0x0DB0: 00 00 00 57 00 00 00 46  00 00 00 47 00 00 00 58  |...W...F...G...X|
0x0DC0: 00 00 00 47 00 00 00 48  00 00 00 59 00 00 00 48  |...G...H...Y...H|
0x0DD0: 00 00 00 37 00 00 00 5A  00 00 00 49 00 00 00 4A  |...7...Z...I...J|
0x0DE0: 00 00 00 5B 00 00 00 4A  00 00 00 4B 00 00 00 5C  |...[...J...K...\|
0x0DF0: 00 00 00 4B 00 00 00 4C  00 00 00 5D 00 00 00 4C  |...K...L...]...L|
0x0E00: 00 00 00 4D 00 00 00 5E  00 00 00 4D 00 00 00 4E  |...M...^...M...N|
0x0E10: 00 00 00 5F 00 00 00 4E  00 00 00 4F 00 00 00 60  |..._...N...O...`|
0x0E20: 00 00 00 4F 00 00 00 50  00 00 00 61 00 00 00 50  |...O...P...a...P|
0x0E30: 00 00 00 51 00 00 00 62  00 00 00 51 00 00 00 52  |...Q...b...Q...R|
0x0E40: 00 00 00 63 00 00 00 52  00 00 00 53 00 00 00 64  |...c...R...S...d|
0x0E50: 00 00 00 53 00 00 00 54  00 00 00 65 00 00 00 54  |...S...T...e...T|
0x0E60: 00 00 00 55 00 00 00 66  00 00 00 55 00 00 00 56  |...U...f...U...V|
0x0E70: 00 00 00 67 00 00 00 56  00 00 00 57 00 00 00 68  |...g...V...W...h|
0x0E80: 00 00 00 57 00 00 00 58  00 00 00 69 00 00 00 58  |...W...X...i...X|
0x0E90: 00 00 00 59 00 00 00 6A  00 00 00 59 00 00 00 5A  |...Y...j...Y...Z|
0x0EA0: 00 00 00 6B 00 00 00 5A  00 00 00 49 00 00 00 6C  |...k...Z...I...l|
0x0EB0: 00 00 00 5B 00 00 00 5C  00 00 00 6D 00 00 00 5C  |...[...\...m...\|
0x0EC0: 00 00 00 5D 00 00 00 6E  00 00 00 5D 00 00 00 5E  |...]...n...]...^|
0x0ED0: 00 00 00 6F 00 00 00 5E  00 00 00 5F 00 00 00 70  |...o...^..._...p|
0x0EE0: 00 00 00 5F 00 00 00 60  00 00 00 71 00 00 00 60  |..._...`...q...`|
0x0EF0: 00 00 00 61 00 00 00 72  00 00 00 61 00 00 00 62  |...a...r...a...b|
0x0F00: 00 00 00 73 00 00 00 62  00 00 00 63 00 00 00 74  |...s...b...c...t|
0x0F10: 00 00 00 63 00 00 00 64  00 00 00 75 00 00 00 64  |...c...d...u...d|
0x0F20: 00 00 00 65 00 00 00 76  00 00 00 65 00 00 00 66  |...e...v...e...f|
0x0F30: 00 00 00 77 00 00 00 66  00 00 00 67 00 00 00 78  |...w...f...g...x|
0x0F40: 00 00 00 67 00 00 00 68  00 00 00 79 00 00 00 68  |...g...h...y...h|
0x0F50: 00 00 00 69 00 00 00 7A  00 00 00 69 00 00 00 6A  |...i...z...i...j|
0x0F60: 00 00 00 7B 00 00 00 6A  00 00 00 6B 00 00 00 7C  |...{...j...k...||
0x0F70: 00 00 00 6B 00 00 00 6C  00 00 00 7D 00 00 00 6C  |...k...l...}...l|
0x0F80: 00 00 00 5B 00 00 00 7E  00 00 00 6D 00 00 00 6E  |...[...~...m...n|
0x0F90: 00 00 00 7F 00 00 00 6E  00 00 00 6F 00 00 00 80  |.......n...o....|
0x0FA0: 00 00 00 6F 00 00 00 70  00 00 00 81 00 00 00 70  |...o...p.......p|
0x0FB0: 00 00 00 71 00 00 00 82  00 00 00 71 00 00 00 72  |...q.......q...r|
0x0FC0: 00 00 00 83 00 00 00 72  00 00 00 73 00 00 00 84  |.......r...s....|
0x0FD0: 00 00 00 73 00 00 00 74  00 00 00 85 00 00 00 74  |...s...t.......t|
0x0FE0: 00 00 00 75 00 00 00 86  00 00 00 75 00 00 00 76  |...u.......u...v|
0x0FF0: 00 00 00 87 00 00 00 76  00 00 00 77 00 00 00 88  |.......v...w....|
0x1000: 00 00 00 77 00 00 00 78  00 00 00 89 00 00 00 78  |...w...x.......x|
0x1010: 00 00 00 79 00 00 00 8A  00 00 00 79 00 00 00 7A  |...y.......y...z|
0x1020: 00 00 00 8B 00 00 00 7A  00 00 00 7B 00 00 00 8C  |.......z...{....|
0x1030: 00 00 00 7B 00 00 00 7C  00 00 00 8D 00 00 00 7C  |...{...|.......||
0x1040: 00 00 00 7D 00 00 00 8E  00 00 00 7D 00 00 00 7E  |...}.......}...~|
0x1050: 00 00 00 8F 00 00 00 7E  00 00 00 6D 00 00 00 90  |.......~...m....|
0x1060: 00 00 00 7F 00 00 00 80  00 00 00 91 00 00 00 80  |................|
0x1070: 00 00 00 81 00 00 00 92  00 00 00 81 00 00 00 82  |................|
0x1080: 00 00 00 93 00 00 00 82  00 00 00 83 00 00 00 94  |................|
0x1090: 00 00 00 83 00 00 00 84  00 00 00 95 00 00 00 84  |................|
0x10A0: 00 00 00 85 00 00 00 96  00 00 00 85 00 00 00 86  |................|
0x10B0: 00 00 00 97 00 00 00 86  00 00 00 87 00 00 00 98  |................|
0x10C0: 00 00 00 87 00 00 00 88  00 00 00 99 00 00 00 88  |................|
0x10D0: 00 00 00 89 00 00 00 9A  00 00 00 89 00 00 00 8A  |................|
0x10E0: 00 00 00 9B 00 00 00 8A  00 00 00 8B 00 00 00 9C  |................|
0x10F0: 00 00 00 8B 00 00 00 8C  00 00 00 9D 00 00 00 8C  |................|
0x1100: 00 00 00 8D 00 00 00 9E  00 00 00 8D 00 00 00 8E  |................|
0x1110: 00 00 00 9F 00 00 00 8E  00 00 00 8F 00 00 00 A0  |................|
0x1120: 00 00 00 8F 00 00 00 90  00 00 00 A1 00 00 00 90  |................|
0x1130: 00 00 00 7F 00 00 00 A2  00 00 00 91 00 00 00 92  |................|
0x1140: 00 00 00 A3 00 00 00 92  00 00 00 93 00 00 00 A4  |................|
0x1150: 00 00 00 93 00 00 00 94  00 00 00 A5 00 00 00 94  |................|
0x1160: 00 00 00 95 00 00 00 A6  00 00 00 95 00 00 00 96  |................|
0x1170: 00 00 00 A7 00 00 00 96  00 00 00 97 00 00 00 A8  |................|
0x1180: 00 00 00 97 00 00 00 98  00 00 00 A9 00 00 00 98  |................|
0x1190: 00 00 00 99 00 00 00 AA  00 00 00 99 00 00 00 9A  |................|
0x11A0: 00 00 00 AB 00 00 00 9A  00 00 00 9B 00 00 00 AC  |................|
0x11B0: 00 00 00 9B 00 00 00 9C  00 00 00 AD 00 00 00 9C  |................|
0x11C0: 00 00 00 9D 00 00 00 AE  00 00 00 9D 00 00 00 9E  |................|
0x11D0: 00 00 00 AF 00 00 00 9E  00 00 00 9F 00 00 00 B0  |................|
0x11E0: 00 00 00 9F 00 00 00 A0  00 00 00 B1 00 00 00 A0  |................|
0x11F0: 00 00 00 A1 00 00 00 B2  00 00 00 A1 00 00 00 A2  |................|
0x1200: 00 00 00 B3 00 00 00 A2  00 00 00 91 00 00 00 B4  |................|
0x1210: 00 00 00 A3 00 00 00 A4  00 00 00 B5 00 00 00 A4  |................|
0x1220: 00 00 00 A5 00 00 00 B6  00 00 00 A5 00 00 00 A6  |................|
0x1230: 00 00 00 B7 00 00 00 A6  00 00 00 A7 00 00 00 B8  |................|
0x1240: 00 00 00 A7 00 00 00 A8  00 00 00 B9 00 00 00 A8  |................|
0x1250: 00 00 00 A9 00 00 00 BA  00 00 00 A9 00 00 00 AA  |................|
0x1260: 00 00 00 BB 00 00 00 AA  00 00 00 AB 00 00 00 BC  |................|
0x1270: 00 00 00 AB 00 00 00 AC  00 00 00 BD 00 00 00 AC  |................|
0x1280: 00 00 00 AD 00 00 00 BE  00 00 00 AD 00 00 00 AE  |................|
0x1290: 00 00 00 BF 00 00 00 AE  00 00 00 AF 00 00 00 C0  |................|
0x12A0: 00 00 00 AF 00 00 00 B0  00 00 00 C1 00 00 00 B0  |................|
0x12B0: 00 00 00 B1 00 00 00 C2  00 00 00 B1 00 00 00 B2  |................|
0x12C0: 00 00 00 C3 00 00 00 B2  00 00 00 B3 00 00 00 C4  |................|
0x12D0: 00 00 00 B3 00 00 00 B4  00 00 00 C5 00 00 00 B4  |................|
0x12E0: 00 00 00 A3 00 00 00 C6  00 00 00 B5 00 00 00 B6  |................|
0x12F0: 00 00 00 C7 00 00 00 B6  00 00 00 B7 00 00 00 C8  |................|
0x1300: 00 00 00 B7 00 00 00 B8  00 00 00 C9 00 00 00 B8  |................|
0x1310: 00 00 00 B9 00 00 00 CA  00 00 00 B9 00 00 00 BA  |................|
0x1320: 00 00 00 CB 00 00 00 BA  00 00 00 BB 00 00 00 CC  |................|
0x1330: 00 00 00 BB 00 00 00 BC  00 00 00 CD 00 00 00 BC  |................|
0x1340: 00 00 00 BD 00 00 00 CE  00 00 00 BD 00 00 00 BE  |................|
0x1350: 00 00 00 CF 00 00 00 BE  00 00 00 BF 00 00 00 D0  |................|
0x1360: 00 00 00 BF 00 00 00 C0  00 00 00 D1 00 00 00 C0  |................|
0x1370: 00 00 00 C1 00 00 00 D2  00 00 00 C1 00 00 00 C2  |................|
0x1380: 00 00 00 D3 00 00 00 C2  00 00 00 C3 00 00 00 D4  |................|
0x1390: 00 00 00 C3 00 00 00 C4  00 00 00 D5 00 00 00 C4  |................|
0x13A0: 00 00 00 C5 00 00 00 D6  00 00 00 C5 00 00 00 C6  |................|
0x13B0: 00 00 00 D7 00 00 00 C6  00 00 00 B5 00 00 00 D8  |................|
0x13C0: 00 00 00 C7 00 00 00 C8  00 00 00 D9 00 00 00 C8  |................|
0x13D0: 00 00 00 C9 00 00 00 DA  00 00 00 C9 00 00 00 CA  |................|
0x13E0: 00 00 00 DB 00 00 00 CA  00 00 00 CB 00 00 00 DC  |................|
0x13F0: 00 00 00 CB 00 00 00 CC  00 00 00 DD 00 00 00 CC  |................|
0x1400: 00 00 00 CD 00 00 00 DE  00 00 00 CD 00 00 00 CE  |................|
0x1410: 00 00 00 DF 00 00 00 CE  00 00 00 CF 00 00 00 E0  |................|
0x1420: 00 00 00 CF 00 00 00 D0  00 00 00 E1 00 00 00 D0  |................|
0x1430: 00 00 00 D1 00 00 00 E2  00 00 00 D1 00 00 00 D2  |................|
0x1440: 00 00 00 E3 00 00 00 D2  00 00 00 D3 00 00 00 E4  |................|
0x1450: 00 00 00 D3 00 00 00 D4  00 00 00 E5 00 00 00 D4  |................|
0x1460: 00 00 00 D5 00 00 00 E6  00 00 00 D5 00 00 00 D6  |................|
0x1470: 00 00 00 E7 00 00 00 D6  00 00 00 D7 00 00 00 E8  |................|
0x1480: 00 00 00 D7 00 00 00 D8  00 00 00 E9 00 00 00 D8  |................|
0x1490: 00 00 00 D9 00 00 00 EA  00 00 00 D9 00 00 00 DA  |................|
0x14A0: 00 00 00 EB 00 00 00 DA  00 00 00 DB 00 00 00 EC  |................|
0x14B0: 00 00 00 DB 00 00 00 DC  00 00 00 ED 00 00 00 DC  |................|
0x14C0: 00 00 00 DD 00 00 00 EE  00 00 00 DD 00 00 00 DE  |................|
0x14D0: 00 00 00 EF 00 00 00 DE  00 00 00 DF 00 00 00 F0  |................|
0x14E0: 00 00 00 DF 00 00 00 E0  00 00 00 F1 00 00 00 E0  |................|
0x14F0: 00 00 00 E1 00 00 00 F2  00 00 00 E1 00 00 00 E2  |................|
0x1500: 00 00 00 F3 00 00 00 E2  00 00 00 E3 00 00 00 F4  |................|
0x1510: 00 00 00 E3 00 00 00 E4  00 00 00 F5 00 00 00 E4  |................|
0x1520: 00 00 00 E5 00 00 00 F6  00 00 00 E5 00 00 00 E6  |................|
0x1530: 00 00 00 F7 00 00 00 E6  00 00 00 E7 00 00 00 F8  |................|
0x1540: 00 00 00 E7 00 00 00 E8  00 00 00 F9 00 00 00 E8  |................|
0x1550: 00 00 00 E9 00 00 00 FA  00 00 00 E9 00 00 00 EA  |................|
0x1560: 00 00 00 FB 00 00 00 EA  00 00 00 D9 00 00 00 FC  |................|
0x1570: 00 00 00 EB 00 00 00 EC  00 00 00 FD 00 00 00 EC  |................|
0x1580: 00 00 00 ED 00 00 00 FE  00 00 00 ED 00 00 00 EE  |................|
0x1590: 00 00 00 FF 00 00 00 EE  00 00 00 EF 00 00 01 00  |................|
0x15A0: 00 00 00 EF 00 00 00 F0  00 00 01 01 00 00 00 F0  |................|
0x15B0: 00 00 00 F1 00 00 01 02  00 00 00 F1 00 00 00 F2  |................|
0x15C0: 00 00 01 03 00 00 00 F2  00 00 00 F3 00 00 01 04  |................|
0x15D0: 00 00 00 F3 00 00 00 F4  00 00 01 05 00 00 00 F4  |................|
0x15E0: 00 00 00 F5 00 00 01 06  00 00 00 F5 00 00 00 F6  |................|
0x15F0: 00 00 01 07 00 00 00 F6  00 00 00 F7 00 00 01 08  |................|
0x1600: 00 00 00 F7 00 00 00 F8  00 00 01 09 00 00 00 F8  |................|
0x1610: 00 00 00 F9 00 00 01 0A  00 00 00 F9 00 00 00 FA  |................|
0x1620: 00 00 01 0B 00 00 00 FA  00 00 00 FB 00 00 01 0C  |................|
0x1630: 00 00 00 FB 00 00 00 FC  00 00 01 0D 00 00 00 FC  |................|
0x1640: 00 00 00 EB 00 00 01 0E  00 00 00 FD 00 00 00 FE  |................|
0x1650: 00 00 01 0F 00 00 00 FE  00 00 00 FF 00 00 01 10  |................|
0x1660: 00 00 00 FF 00 00 01 00  00 00 01 11 00 00 01 00  |................|
0x1670: 00 00 01 01 00 00 01 12  00 00 01 01 00 00 01 02  |................|
0x1680: 00 00 01 13 00 00 01 02  00 00 01 03 00 00 01 14  |................|
0x1690: 00 00 01 03 00 00 01 04  00 00 01 15 00 00 01 04  |................|
0x16A0: 00 00 01 05 00 00 01 16  00 00 01 05 00 00 01 06  |................|
0x16B0: 00 00 01 17 00 00 01 06  00 00 01 07 00 00 01 18  |................|
0x16C0: 00 00 01 07 00 00 01 08  00 00 01 19 00 00 01 08  |................|
0x16D0: 00 00 01 09 00 00 01 1A  00 00 01 09 00 00 01 0A  |................|
0x16E0: 00 00 01 1B 00 00 01 0A  00 00 01 0B 00 00 01 1C  |................|
0x16F0: 00 00 01 0B 00 00 01 0C  00 00 01 1D 00 00 01 0C  |................|
0x1700: 00 00 01 0D 00 00 01 1E  00 00 01 0D 00 00 01 0E  |................|
0x1710: 00 00 01 1F 00 00 01 0E  00 00 00 FD 00 00 01 20  |............... |
0x1720: 00 00 01 0F 00 00 01 10  00 00 01 21 00 00 01 10  |...........!....|
0x1730: 00 00 01 11 00 00 01 22  00 00 01 11 00 00 01 12  |......."........|
0x1740: 00 00 01 23 00 00 01 12  00 00 01 13 00 00 01 24  |...#...........$|
0x1750: 00 00 01 13 00 00 01 14  00 00 01 25 00 00 01 14  |...........%....|
0x1760: 00 00 01 15 00 00 01 26  00 00 01 15 00 00 01 16  |.......&........|
0x1770: 00 00 01 27 00 00 01 16  00 00 01 17 00 00 01 28  |...'...........(|
0x1780: 00 00 01 17 00 00 01 18  00 00 01 29 00 00 01 18  |...........)....|
0x1790: 00 00 01 19 00 00 01 2A  00 00 01 19 00 00 01 1A  |.......*........|
0x17A0: 00 00 01 2B 00 00 01 1A  00 00 01 1B 00 00 01 2C  |...+...........,|
0x17B0: 00 00 01 1B 00 00 01 1C  00 00 01 2D 00 00 01 1C  |...........-....|
0x17C0: 00 00 01 1D 00 00 01 2E  00 00 01 1D 00 00 01 1E  |................|
0x17D0: 00 00 01 2F 00 00 01 1E  00 00 01 1F 00 00 01 30  |.../...........0|
0x17E0: 00 00 01 1F 00 00 01 20  00 00 01 31 00 00 01 20  |....... ...1... |
0x17F0: 00 00 01 0F 00 00 01 32  00 00 01 21 00 00 01 22  |.......2...!..."|
0x1800: 00 00 01 33 00 00 01 22  00 00 01 23 00 00 01 34  |...3..."...#...4|
0x1810: 00 00 01 23 00 00 01 24  00 00 01 35 00 00 01 24  |...#...$...5...$|
0x1820: 00 00 01 25 00 00 01 36  00 00 01 25 00 00 01 26  |...%...6...%...&|
0x1830: 00 00 01 37 00 00 01 26  00 00 01 27 00 00 01 38  |...7...&...'...8|
0x1840: 00 00 01 27 00 00 01 28  00 00 01 39 00 00 01 28  |...'...(...9...(|
0x1850: 00 00 01 29 00 00 01 3A  00 00 01 29 00 00 01 2A  |...)...:...)...*|
0x1860: 00 00 01 3B 00 00 01 2A  00 00 01 2B 00 00 01 3C  |...;...*...+...<|
0x1870: 00 00 01 2B 00 00 01 2C  00 00 01 3D 00 00 01 2C  |...+...,...=...,|
0x1880: 00 00 01 2D 00 00 01 3E  00 00 01 2D 00 00 01 2E  |...-...>...-....|
0x1890: 00 00 01 3F 00 00 01 2E  00 00 01 2F 00 00 01 40  |...?......./...@|
0x18A0: 00 00 01 2F 00 00 01 30  00 00 01 41 00 00 01 30  |.../...0...A...0|
0x18B0: 00 00 01 31 00 00 01 42  00 00 01 31 00 00 01 32  |...1...B...1...2|
0x18C0: 00 00 01 43 00 00 01 32  00 00 01 21 00 00 01 44  |...C...2...!...D|
0x18D0: 00 00 01 33 00 00 01 34  00 00 01 45 00 00 01 34  |...3...4...E...4|
0x18E0: 00 00 01 35 00 00 01 46  00 00 01 35 00 00 01 36  |...5...F...5...6|
0x18F0: 00 00 01 47 00 00 01 36  00 00 01 37 00 00 01 48  |...G...6...7...H|
0x1900: 00 00 01 37 00 00 01 38  00 00 01 49 00 00 01 38  |...7...8...I...8|
0x1910: 00 00 01 39 00 00 01 4A  00 00 01 39 00 00 01 3A  |...9...J...9...:|
0x1920: 00 00 01 4B 00 00 01 3A  00 00 01 3B 00 00 01 4C  |...K...:...;...L|
0x1930: 00 00 01 3B 00 00 01 3C  00 00 01 4D 00 00 01 3C  |...;...<...M...<|
0x1940: 00 00 01 3D 00 00 01 4E  00 00 01 3D 00 00 01 3E  |...=...N...=...>|
0x1950: 00 00 01 4F 00 00 01 3E  00 00 01 3F 00 00 01 50  |...O...>...?...P|
0x1960: 00 00 01 3F 00 00 01 40  00 00 01 51 00 00 01 40  |...?...@...Q...@|
0x1970: 00 00 01 41 00 00 01 52  00 00 01 41 00 00 01 42  |...A...R...A...B|
0x1980: 00 00 01 53 00 00 01 42  00 00 01 43 00 00 01 54  |...S...B...C...T|
0x1990: 00 00 01 43 00 00 01 44  00 00 01 55 00 00 01 44  |...C...D...U...D|
0x19A0: 00 00 01 33 00 00 01 56  00 00 01 45 00 00 01 46  |...3...V...E...F|
0x19B0: 00 00 01 57 00 00 01 46  00 00 01 47 00 00 01 58  |...W...F...G...X|
0x19C0: 00 00 01 47 00 00 01 48  00 00 01 59 00 00 01 48  |...G...H...Y...H|
0x19D0: 00 00 01 49 00 00 01 5A  00 00 01 49 00 00 01 4A  |...I...Z...I...J|
0x19E0: 00 00 01 5B 00 00 01 4A  00 00 01 4B 00 00 01 5C  |...[...J...K...\|
0x19F0: 00 00 01 4B 00 00 01 4C  00 00 01 5D 00 00 01 4C  |...K...L...]...L|
0x1A00: 00 00 01 4D 00 00 01 5E  00 00 01 4D 00 00 01 4E  |...M...^...M...N|
0x1A10: 00 00 01 5F 00 00 01 4E  00 00 01 4F 00 00 01 60  |..._...N...O...`|
0x1A20: 00 00 01 4F 00 00 01 50  00 00 01 61 00 00 01 50  |...O...P...a...P|
0x1A30: 00 00 01 51 00 00 01 62  00 00 01 51 00 00 01 52  |...Q...b...Q...R|
0x1A40: 00 00 01 63 00 00 01 52  00 00 01 53 00 00 01 64  |...c...R...S...d|
0x1A50: 00 00 01 53 00 00 01 54  00 00 01 65 00 00 01 54  |...S...T...e...T|
0x1A60: 00 00 01 55 00 00 01 66  00 00 01 55 00 00 01 56  |...U...f...U...V|
0x1A70: 00 00 01 67 00 00 01 56  00 00 01 45 00 00 01 68  |...g...V...E...h|
0x1A80: 00 00 01 57 00 00 01 58  00 00 01 69 00 00 01 58  |...W...X...i...X|
0x1A90: 00 00 01 59 00 00 01 6A  00 00 01 59 00 00 01 5A  |...Y...j...Y...Z|
0x1AA0: 00 00 01 6B 00 00 01 5A  00 00 01 5B 00 00 01 6C  |...k...Z...[...l|
0x1AB0: 00 00 01 5B 00 00 01 5C  00 00 01 6D 00 00 01 5C  |...[...\...m...\|
0x1AC0: 00 00 01 5D 00 00 01 6E  00 00 01 5D 00 00 01 5E  |...]...n...]...^|
0x1AD0: 00 00 01 6F 00 00 01 5E  00 00 01 5F 00 00 01 70  |...o...^..._...p|
0x1AE0: 00 00 01 5F 00 00 01 60  00 00 01 71 00 00 01 60  |..._...`...q...`|
0x1AF0: 00 00 01 61 00 00 01 72  00 00 01 61 00 00 01 62  |...a...r...a...b|
0x1B00: 00 00 01 73 00 00 01 62  00 00 01 63 00 00 01 74  |...s...b...c...t|
0x1B10: 00 00 01 63 00 00 01 64  00 00 01 75 00 00 01 64  |...c...d...u...d|
0x1B20: 00 00 01 65 00 00 01 76  00 00 01 65 00 00 01 66  |...e...v...e...f|
0x1B30: 00 00 01 77 00 00 01 66  00 00 01 67 00 00 01 78  |...w...f...g...x|
0x1B40: 00 00 01 67 00 00 01 68  00 00 01 79 00 00 01 68  |...g...h...y...h|
0x1B50: 00 00 01 57 00 00 01 7A  00 00 01 69 00 00 01 6A  |...W...z...i...j|
0x1B60: 00 00 01 7B 00 00 01 6A  00 00 01 6B 00 00 01 7C  |...{...j...k...||
0x1B70: 00 00 01 6B 00 00 01 6C  00 00 01 7D 00 00 01 6C  |...k...l...}...l|
0x1B80: 00 00 01 6D 00 00 01 7E  00 00 01 6D 00 00 01 6E  |...m...~...m...n|
0x1B90: 00 00 01 7F 00 00 01 6E  00 00 01 6F 00 00 01 80  |.......n...o....|
0x1BA0: 00 00 01 6F 00 00 01 70  00 00 01 81 00 00 01 70  |...o...p.......p|
0x1BB0: 00 00 01 71 00 00 01 82  00 00 01 71 00 00 01 72  |...q.......q...r|
0x1BC0: 00 00 01 83 00 00 01 72  00 00 01 73 00 00 01 84  |.......r...s....|
0x1BD0: 00 00 01 73 00 00 01 74  00 00 01 85 00 00 01 74  |...s...t.......t|
0x1BE0: 00 00 01 75 00 00 01 86  00 00 01 75 00 00 01 76  |...u.......u...v|
0x1BF0: 00 00 01 87 00 00 01 76  00 00 01 77 00 00 01 88  |.......v...w....|
0x1C00: 00 00 01 77 00 00 01 78  00 00 01 89 00 00 01 78  |...w...x.......x|
0x1C10: 00 00 01 79 00 00 01 8A  00 00 01 79 00 00 01 7A  |...y.......y...z|
0x1C20: 00 00 01 8B 00 00 01 7A  00 00 01 69 00 00 01 8C  |.......z...i....|
0x1C30: 00 00 01 7B 00 00 01 7C  00 00 01 8D 00 00 01 7C  |...{...|.......||
0x1C40: 00 00 01 7D 00 00 01 8E  00 00 01 7D 00 00 01 7E  |...}.......}...~|
0x1C50: 00 00 01 8F 00 00 01 7E  00 00 01 7F 00 00 01 90  |.......~........|
0x1C60: 00 00 01 7F 00 00 01 80  00 00 01 91 00 00 01 80  |................|
0x1C70: 00 00 01 81 00 00 01 92  00 00 01 81 00 00 01 82  |................|
0x1C80: 00 00 01 93 00 00 01 82  00 00 01 83 00 00 01 94  |................|
0x1C90: 00 00 01 83 00 00 01 84  00 00 01 95 00 00 01 84  |................|
0x1CA0: 00 00 01 85 00 00 01 96  00 00 01 85 00 00 01 86  |................|
0x1CB0: 00 00 01 97 00 00 01 86  00 00 01 87 00 00 01 98  |................|
0x1CC0: 00 00 01 87 00 00 01 88  00 00 01 99 00 00 01 88  |................|
0x1CD0: 00 00 01 89 00 00 01 9A  00 00 01 89 00 00 01 8A  |................|
0x1CE0: 00 00 01 9B 00 00 01 8A  00 00 01 8B 00 00 01 9C  |................|
0x1CF0: 00 00 01 8B 00 00 01 8C  00 00 01 9D 00 00 01 8C  |................|
0x1D00: 00 00 01 7B 00 00 01 9E  00 00 01 8D 00 00 01 8E  |...{............|
0x1D10: 00 00 01 9F 00 00 01 8E  00 00 01 8F 00 00 01 A0  |................|
0x1D20: 00 00 01 8F 00 00 01 90  00 00 01 A1 00 00 01 90  |................|
0x1D30: 00 00 01 91 00 00 01 A2  00 00 01 91 00 00 01 92  |................|
0x1D40: 00 00 01 A3 00 00 01 92  00 00 01 93 00 00 01 A4  |................|
0x1D50: 00 00 01 93 00 00 01 94  00 00 01 A5 00 00 01 94  |................|
0x1D60: 00 00 01 95 00 00 01 A6  00 00 01 95 00 00 01 96  |................|
0x1D70: 00 00 01 A7 00 00 01 96  00 00 01 97 00 00 01 A8  |................|
0x1D80: 00 00 01 97 00 00 01 98  00 00 01 A9 00 00 01 98  |................|
0x1D90: 00 00 01 99 00 00 01 AA  00 00 01 99 00 00 01 9A  |................|
0x1DA0: 00 00 01 AB 00 00 01 9A  00 00 01 9B 00 00 01 AC  |................|
0x1DB0: 00 00 01 9B 00 00 01 9C  00 00 01 AD 00 00 01 9C  |................|
0x1DC0: 00 00 01 9D 00 00 01 AE  00 00 01 9D 00 00 01 9E  |................|
0x1DD0: 00 00 01 AF 00 00 01 9E  00 00 01 8D 00 00 01 B0  |................|
0x1DE0: 00 00 01 9F 00 00 01 A0  00 00 01 B1 00 00 01 A0  |................|
0x1DF0: 00 00 01 A1 00 00 01 B2  00 00 01 A1 00 00 01 A2  |................|
0x1E00: 00 00 01 B3 00 00 01 A2  00 00 01 A3 00 00 01 B4  |................|
0x1E10: 00 00 01 A3 00 00 01 A4  00 00 01 B5 00 00 01 A4  |................|
0x1E20: 00 00 01 A5 00 00 01 B6  00 00 01 A5 00 00 01 A6  |................|
0x1E30: 00 00 01 B7 00 00 01 A6  00 00 01 A7 00 00 01 B8  |................|
0x1E40: 00 00 01 A7 00 00 01 A8  00 00 01 B9 00 00 01 A8  |................|
0x1E50: 00 00 01 A9 00 00 01 BA  00 00 01 A9 00 00 01 AA  |................|
0x1E60: 00 00 01 BB 00 00 01 AA  00 00 01 AB 00 00 01 BC  |................|
0x1E70: 00 00 01 AB 00 00 01 AC  00 00 01 BD 00 00 01 AC  |................|
0x1E80: 00 00 01 AD 00 00 01 BE  00 00 01 AD 00 00 01 AE  |................|
0x1E90: 00 00 01 BF 00 00 01 AE  00 00 01 AF 00 00 01 C0  |................|
0x1EA0: 00 00 01 AF 00 00 01 B0  00 00 01 C1 00 00 01 B0  |................|
0x1EB0: 00 00 01 9F 00 00 01 C2  00 00 01 B1 00 00 01 B2  |................|
0x1EC0: 00 00 01 C3 00 00 01 B2  00 00 01 B3 00 00 01 C4  |................|
0x1ED0: 00 00 01 B3 00 00 01 B4  00 00 01 C5 00 00 01 B4  |................|
0x1EE0: 00 00 01 B5 00 00 01 C6  00 00 01 B5 00 00 01 B6  |................|
0x1EF0: 00 00 01 C7 00 00 01 B6  00 00 01 B7 00 00 01 C8  |................|
0x1F00: 00 00 01 B7 00 00 01 B8  00 00 01 C9 00 00 01 B8  |................|
0x1F10: 00 00 01 B9 00 00 01 CA  00 00 01 B9 00 00 01 BA  |................|
0x1F20: 00 00 01 CB 00 00 01 BA  00 00 01 BB 00 00 01 CC  |................|
0x1F30: 00 00 01 BB 00 00 01 BC  00 00 01 CD 00 00 01 BC  |................|
0x1F40: 00 00 01 BD 00 00 01 CE  00 00 01 BD 00 00 01 BE  |................|
0x1F50: 00 00 01 CF 00 00 01 BE  00 00 01 BF 00 00 01 D0  |................|
0x1F60: 00 00 01 BF 00 00 01 C0  00 00 01 D1 00 00 01 C0  |................|
0x1F70: 00 00 01 C1 00 00 01 D2  00 00 01 C1 00 00 01 C2  |................|
0x1F80: 00 00 01 D3 00 00 01 C2  00 00 01 B1 00 00 01 D4  |................|
0x1F90: 00 00 00 01 00 00 00 13  00 00 00 24 00 00 00 02  |...........$....|
0x1FA0: 00 00 00 14 00 00 00 13  00 00 00 03 00 00 00 15  |................|
0x1FB0: 00 00 00 14 00 00 00 04  00 00 00 16 00 00 00 15  |................|
0x1FC0: 00 00 00 05 00 00 00 17  00 00 00 16 00 00 00 06  |................|
0x1FD0: 00 00 00 18 00 00 00 17  00 00 00 07 00 00 00 19  |................|
0x1FE0: 00 00 00 18 00 00 00 08  00 00 00 1A 00 00 00 19  |................|
0x1FF0: 00 00 00 09 00 00 00 1B  00 00 00 1A 00 00 00 0A  |................|
0x2000: 00 00 00 1C 00 00 00 1B  00 00 00 0B 00 00 00 1D  |................|
0x2010: 00 00 00 1C 00 00 00 0C  00 00 00 1E 00 00 00 1D  |................|
0x2020: 00 00 00 0D 00 00 00 1F  00 00 00 1E 00 00 00 0E  |................|
0x2030: 00 00 00 20 00 00 00 1F  00 00 00 0F 00 00 00 21  |... ...........!|
0x2040: 00 00 00 20 00 00 00 10  00 00 00 22 00 00 00 21  |... ......."...!|
0x2050: 00 00 00 11 00 00 00 23  00 00 00 22 00 00 00 12  |.......#..."....|
0x2060: 00 00 00 24 00 00 00 23  00 00 00 13 00 00 00 25  |...$...#.......%|
0x2070: 00 00 00 36 00 00 00 14  00 00 00 26 00 00 00 25  |...6.......&...%|
0x2080: 00 00 00 15 00 00 00 27  00 00 00 26 00 00 00 16  |.......'...&....|
0x2090: 00 00 00 28 00 00 00 27  00 00 00 17 00 00 00 29  |...(...'.......)|
0x20A0: 00 00 00 28 00 00 00 18  00 00 00 2A 00 00 00 29  |...(.......*...)|
0x20B0: 00 00 00 19 00 00 00 2B  00 00 00 2A 00 00 00 1A  |.......+...*....|
0x20C0: 00 00 00 2C 00 00 00 2B  00 00 00 1B 00 00 00 2D  |...,...+.......-|
0x20D0: 00 00 00 2C 00 00 00 1C  00 00 00 2E 00 00 00 2D  |...,...........-|
0x20E0: 00 00 00 1D 00 00 00 2F  00 00 00 2E 00 00 00 1E  |......./........|
0x20F0: 00 00 00 30 00 00 00 2F  00 00 00 1F 00 00 00 31  |...0.../.......1|
0x2100: 00 00 00 30 00 00 00 20  00 00 00 32 00 00 00 31  |...0... ...2...1|
0x2110: 00 00 00 21 00 00 00 33  00 00 00 32 00 00 00 22  |...!...3...2..."|
0x2120: 00 00 00 34 00 00 00 33  00 00 00 23 00 00 00 35  |...4...3...#...5|
0x2130: 00 00 00 34 00 00 00 24  00 00 00 36 00 00 00 35  |...4...$...6...5|
0x2140: 00 00 00 25 00 00 00 37  00 00 00 48 00 00 00 26  |...%...7...H...&|
0x2150: 00 00 00 38 00 00 00 37  00 00 00 27 00 00 00 39  |...8...7...'...9|
0x2160: 00 00 00 38 00 00 00 28  00 00 00 3A 00 00 00 39  |...8...(...:...9|
0x2170: 00 00 00 29 00 00 00 3B  00 00 00 3A 00 00 00 2A  |...)...;...:...*|
0x2180: 00 00 00 3C 00 00 00 3B  00 00 00 2B 00 00 00 3D  |...<...;...+...=|
0x2190: 00 00 00 3C 00 00 00 2C  00 00 00 3E 00 00 00 3D  |...<...,...>...=|
0x21A0: 00 00 00 2D 00 00 00 3F  00 00 00 3E 00 00 00 2E  |...-...?...>....|
0x21B0: 00 00 00 40 00 00 00 3F  00 00 00 2F 00 00 00 41  |...@...?.../...A|
0x21C0: 00 00 00 40 00 00 00 30  00 00 00 42 00 00 00 41  |...@...0...B...A|
0x21D0: 00 00 00 31 00 00 00 43  00 00 00 42 00 00 00 32  |...1...C...B...2|
0x21E0: 00 00 00 44 00 00 00 43  00 00 00 33 00 00 00 45  |...D...C...3...E|
0x21F0: 00 00 00 44 00 00 00 34  00 00 00 46 00 00 00 45  |...D...4...F...E|
0x2200: 00 00 00 35 00 00 00 47  00 00 00 46 00 00 00 36  |...5...G...F...6|
0x2210: 00 00 00 48 00 00 00 47  00 00 00 37 00 00 00 49  |...H...G...7...I|
0x2220: 00 00 00 5A 00 00 00 38  00 00 00 4A 00 00 00 49  |...Z...8...J...I|
0x2230: 00 00 00 39 00 00 00 4B  00 00 00 4A 00 00 00 3A  |...9...K...J...:|
0x2240: 00 00 00 4C 00 00 00 4B  00 00 00 3B 00 00 00 4D  |...L...K...;...M|
0x2250: 00 00 00 4C 00 00 00 3C  00 00 00 4E 00 00 00 4D  |...L...<...N...M|
0x2260: 00 00 00 3D 00 00 00 4F  00 00 00 4E 00 00 00 3E  |...=...O...N...>|
0x2270: 00 00 00 50 00 00 00 4F  00 00 00 3F 00 00 00 51  |...P...O...?...Q|
0x2280: 00 00 00 50 00 00 00 40  00 00 00 52 00 00 00 51  |...P...@...R...Q|
0x2290: 00 00 00 41 00 00 00 53  00 00 00 52 00 00 00 42  |...A...S...R...B|
0x22A0: 00 00 00 54 00 00 00 53  00 00 00 43 00 00 00 55  |...T...S...C...U|
0x22B0: 00 00 00 54 00 00 00 44  00 00 00 56 00 00 00 55  |...T...D...V...U|
0x22C0: 00 00 00 45 00 00 00 57  00 00 00 56 00 00 00 46  |...E...W...V...F|
0x22D0: 00 00 00 58 00 00 00 57  00 00 00 47 00 00 00 59  |...X...W...G...Y|
0x22E0: 00 00 00 58 00 00 00 48  00 00 00 5A 00 00 00 59  |...X...H...Z...Y|
0x22F0: 00 00 00 49 00 00 00 5B  00 00 00 6C 00 00 00 4A  |...I...[...l...J|
0x2300: 00 00 00 5C 00 00 00 5B  00 00 00 4B 00 00 00 5D  |...\...[...K...]|
0x2310: 00 00 00 5C 00 00 00 4C  00 00 00 5E 00 00 00 5D  |...\...L...^...]|
0x2320: 00 00 00 4D 00 00 00 5F  00 00 00 5E 00 00 00 4E  |...M..._...^...N|
0x2330: 00 00 00 60 00 00 00 5F  00 00 00 4F 00 00 00 61  |...`..._...O...a|
0x2340: 00 00 00 60 00 00 00 50  00 00 00 62 00 00 00 61  |...`...P...b...a|
0x2350: 00 00 00 51 00 00 00 63  00 00 00 62 00 00 00 52  |...Q...c...b...R|
0x2360: 00 00 00 64 00 00 00 63  00 00 00 53 00 00 00 65  |...d...c...S...e|
0x2370: 00 00 00 64 00 00 00 54  00 00 00 66 00 00 00 65  |...d...T...f...e|
0x2380: 00 00 00 55 00 00 00 67  00 00 00 66 00 00 00 56  |...U...g...f...V|
0x2390: 00 00 00 68 00 00 00 67  00 00 00 57 00 00 00 69  |...h...g...W...i|
0x23A0: 00 00 00 68 00 00 00 58  00 00 00 6A 00 00 00 69  |...h...X...j...i|
0x23B0: 00 00 00 59 00 00 00 6B  00 00 00 6A 00 00 00 5A  |...Y...k...j...Z|
0x23C0: 00 00 00 6C 00 00 00 6B  00 00 00 5B 00 00 00 6D  |...l...k...[...m|
0x23D0: 00 00 00 7E 00 00 00 5C  00 00 00 6E 00 00 00 6D  |...~...\...n...m|
0x23E0: 00 00 00 5D 00 00 00 6F  00 00 00 6E 00 00 00 5E  |...]...o...n...^|
0x23F0: 00 00 00 70 00 00 00 6F  00 00 00 5F 00 00 00 71  |...p...o..._...q|
0x2400: 00 00 00 70 00 00 00 60  00 00 00 72 00 00 00 71  |...p...`...r...q|
0x2410: 00 00 00 61 00 00 00 73  00 00 00 72 00 00 00 62  |...a...s...r...b|
0x2420: 00 00 00 74 00 00 00 73  00 00 00 63 00 00 00 75  |...t...s...c...u|
0x2430: 00 00 00 74 00 00 00 64  00 00 00 76 00 00 00 75  |...t...d...v...u|
0x2440: 00 00 00 65 00 00 00 77  00 00 00 76 00 00 00 66  |...e...w...v...f|
0x2450: 00 00 00 78 00 00 00 77  00 00 00 67 00 00 00 79  |...x...w...g...y|
0x2460: 00 00 00 78 00 00 00 68  00 00 00 7A 00 00 00 79  |...x...h...z...y|
0x2470: 00 00 00 69 00 00 00 7B  00 00 00 7A 00 00 00 6A  |...i...{...z...j|
0x2480: 00 00 00 7C 00 00 00 7B  00 00 00 6B 00 00 00 7D  |...|...{...k...}|
0x2490: 00 00 00 7C 00 00 00 6C  00 00 00 7E 00 00 00 7D  |...|...l...~...}|
0x24A0: 00 00 00 6D 00 00 00 7F  00 00 00 90 00 00 00 6E  |...m...........n|
0x24B0: 00 00 00 80 00 00 00 7F  00 00 00 6F 00 00 00 81  |...........o....|
0x24C0: 00 00 00 80 00 00 00 70  00 00 00 82 00 00 00 81  |.......p........|
0x24D0: 00 00 00 71 00 00 00 83  00 00 00 82 00 00 00 72  |...q...........r|
0x24E0: 00 00 00 84 00 00 00 83  00 00 00 73 00 00 00 85  |...........s....|
0x24F0: 00 00 00 84 00 00 00 74  00 00 00 86 00 00 00 85  |.......t........|
0x2500: 00 00 00 75 00 00 00 87  00 00 00 86 00 00 00 76  |...u...........v|
0x2510: 00 00 00 88 00 00 00 87  00 00 00 77 00 00 00 89  |...........w....|
0x2520: 00 00 00 88 00 00 00 78  00 00 00 8A 00 00 00 89  |.......x........|
0x2530: 00 00 00 79 00 00 00 8B  00 00 00 8A 00 00 00 7A  |...y...........z|
0x2540: 00 00 00 8C 00 00 00 8B  00 00 00 7B 00 00 00 8D  |...........{....|
0x2550: 00 00 00 8C 00 00 00 7C  00 00 00 8E 00 00 00 8D  |.......|........|
0x2560: 00 00 00 7D 00 00 00 8F  00 00 00 8E 00 00 00 7E  |...}...........~|
0x2570: 00 00 00 90 00 00 00 8F  00 00 00 7F 00 00 00 91  |................|
0x2580: 00 00 00 A2 00 00 00 80  00 00 00 92 00 00 00 91  |................|
0x2590: 00 00 00 81 00 00 00 93  00 00 00 92 00 00 00 82  |................|
0x25A0: 00 00 00 94 00 00 00 93  00 00 00 83 00 00 00 95  |................|
0x25B0: 00 00 00 94 00 00 00 84  00 00 00 96 00 00 00 95  |................|
0x25C0: 00 00 00 85 00 00 00 97  00 00 00 96 00 00 00 86  |................|
0x25D0: 00 00 00 98 00 00 00 97  00 00 00 87 00 00 00 99  |................|
0x25E0: 00 00 00 98 00 00 00 88  00 00 00 9A 00 00 00 99  |................|
0x25F0: 00 00 00 89 00 00 00 9B  00 00 00 9A 00 00 00 8A  |................|
0x2600: 00 00 00 9C 00 00 00 9B  00 00 00 8B 00 00 00 9D  |................|
0x2610: 00 00 00 9C 00 00 00 8C  00 00 00 9E 00 00 00 9D  |................|
0x2620: 00 00 00 8D 00 00 00 9F  00 00 00 9E 00 00 00 8E  |................|
0x2630: 00 00 00 A0 00 00 00 9F  00 00 00 8F 00 00 00 A1  |................|
0x2640: 00 00 00 A0 00 00 00 90  00 00 00 A2 00 00 00 A1  |................|
0x2650: 00 00 00 91 00 00 00 A3  00 00 00 B4 00 00 00 92  |................|
0x2660: 00 00 00 A4 00 00 00 A3  00 00 00 93 00 00 00 A5  |................|
0x2670: 00 00 00 A4 00 00 00 94  00 00 00 A6 00 00 00 A5  |................|
0x2680: 00 00 00 95 00 00 00 A7  00 00 00 A6 00 00 00 96  |................|
0x2690: 00 00 00 A8 00 00 00 A7  00 00 00 97 00 00 00 A9  |................|
0x26A0: 00 00 00 A8 00 00 00 98  00 00 00 AA 00 00 00 A9  |................|
0x26B0: 00 00 00 99 00 00 00 AB  00 00 00 AA 00 00 00 9A  |................|
0x26C0: 00 00 00 AC 00 00 00 AB  00 00 00 9B 00 00 00 AD  |................|
0x26D0: 00 00 00 AC 00 00 00 9C  00 00 00 AE 00 00 00 AD  |................|
0x26E0: 00 00 00 9D 00 00 00 AF  00 00 00 AE 00 00 00 9E  |................|
0x26F0: 00 00 00 B0 00 00 00 AF  00 00 00 9F 00 00 00 B1  |................|
0x2700: 00 00 00 B0 00 00 00 A0  00 00 00 B2 00 00 00 B1  |................|
0x2710: 00 00 00 A1 00 00 00 B3  00 00 00 B2 00 00 00 A2  |................|
0x2720: 00 00 00 B4 00 00 00 B3  00 00 00 A3 00 00 00 B5  |................|
0x2730: 00 00 00 C6 00 00 00 A4  00 00 00 B6 00 00 00 B5  |................|
0x2740: 00 00 00 A5 00 00 00 B7  00 00 00 B6 00 00 00 A6  |................|
0x2750: 00 00 00 B8 00 00 00 B7  00 00 00 A7 00 00 00 B9  |................|
0x2760: 00 00 00 B8 00 00 00 A8  00 00 00 BA 00 00 00 B9  |................|
0x2770: 00 00 00 A9 00 00 00 BB  00 00 00 BA 00 00 00 AA  |................|
0x2780: 00 00 00 BC 00 00 00 BB  00 00 00 AB 00 00 00 BD  |................|
0x2790: 00 00 00 BC 00 00 00 AC  00 00 00 BE 00 00 00 BD  |................|
0x27A0: 00 00 00 AD 00 00 00 BF  00 00 00 BE 00 00 00 AE  |................|
0x27B0: 00 00 00 C0 00 00 00 BF  00 00 00 AF 00 00 00 C1  |................|
0x27C0: 00 00 00 C0 00 00 00 B0  00 00 00 C2 00 00 00 C1  |................|
0x27D0: 00 00 00 B1 00 00 00 C3  00 00 00 C2 00 00 00 B2  |................|
0x27E0: 00 00 00 C4 00 00 00 C3  00 00 00 B3 00 00 00 C5  |................|
0x27F0: 00 00 00 C4 00 00 00 B4  00 00 00 C6 00 00 00 C5  |................|
0x2800: 00 00 00 B5 00 00 00 C7  00 00 00 D8 00 00 00 B6  |................|
0x2810: 00 00 00 C8 00 00 00 C7  00 00 00 B7 00 00 00 C9  |................|
0x2820: 00 00 00 C8 00 00 00 B8  00 00 00 CA 00 00 00 C9  |................|
0x2830: 00 00 00 B9 00 00 00 CB  00 00 00 CA 00 00 00 BA  |................|
0x2840: 00 00 00 CC 00 00 00 CB  00 00 00 BB 00 00 00 CD  |................|
0x2850: 00 00 00 CC 00 00 00 BC  00 00 00 CE 00 00 00 CD  |................|
0x2860: 00 00 00 BD 00 00 00 CF  00 00 00 CE 00 00 00 BE  |................|
0x2870: 00 00 00 D0 00 00 00 CF  00 00 00 BF 00 00 00 D1  |................|
0x2880: 00 00 00 D0 00 00 00 C0  00 00 00 D2 00 00 00 D1  |................|
0x2890: 00 00 00 C1 00 00 00 D3  00 00 00 D2 00 00 00 C2  |................|
0x28A0: 00 00 00 D4 00 00 00 D3  00 00 00 C3 00 00 00 D5  |................|
0x28B0: 00 00 00 D4 00 00 00 C4  00 00 00 D6 00 00 00 D5  |................|
0x28C0: 00 00 00 C5 00 00 00 D7  00 00 00 D6 00 00 00 C6  |................|
0x28D0: 00 00 00 D8 00 00 00 D7  00 00 00 C7 00 00 00 D9  |................|
0x28E0: 00 00 00 EA 00 00 00 C8  00 00 00 DA 00 00 00 D9  |................|
0x28F0: 00 00 00 C9 00 00 00 DB  00 00 00 DA 00 00 00 CA  |................|
0x2900: 00 00 00 DC 00 00 00 DB  00 00 00 CB 00 00 00 DD  |................|
0x2910: 00 00 00 DC 00 00 00 CC  00 00 00 DE 00 00 00 DD  |................|
0x2920: 00 00 00 CD 00 00 00 DF  00 00 00 DE 00 00 00 CE  |................|
0x2930: 00 00 00 E0 00 00 00 DF  00 00 00 CF 00 00 00 E1  |................|
0x2940: 00 00 00 E0 00 00 00 D0  00 00 00 E2 00 00 00 E1  |................|
0x2950: 00 00 00 D1 00 00 00 E3  00 00 00 E2 00 00 00 D2  |................|
0x2960: 00 00 00 E4 00 00 00 E3  00 00 00 D3 00 00 00 E5  |................|
0x2970: 00 00 00 E4 00 00 00 D4  00 00 00 E6 00 00 00 E5  |................|
0x2980: 00 00 00 D5 00 00 00 E7  00 00 00 E6 00 00 00 D6  |................|
0x2990: 00 00 00 E8 00 00 00 E7  00 00 00 D7 00 00 00 E9  |................|
0x29A0: 00 00 00 E8 00 00 00 D8  00 00 00 EA 00 00 00 E9  |................|
0x29B0: 00 00 00 D9 00 00 00 EB  00 00 00 FC 00 00 00 DA  |................|
0x29C0: 00 00 00 EC 00 00 00 EB  00 00 00 DB 00 00 00 ED  |................|
0x29D0: 00 00 00 EC 00 00 00 DC  00 00 00 EE 00 00 00 ED  |................|
0x29E0: 00 00 00 DD 00 00 00 EF  00 00 00 EE 00 00 00 DE  |................|
0x29F0: 00 00 00 F0 00 00 00 EF  00 00 00 DF 00 00 00 F1  |................|
0x2A00: 00 00 00 F0 00 00 00 E0  00 00 00 F2 00 00 00 F1  |................|
0x2A10: 00 00 00 E1 00 00 00 F3  00 00 00 F2 00 00 00 E2  |................|
0x2A20: 00 00 00 F4 00 00 00 F3  00 00 00 E3 00 00 00 F5  |................|
0x2A30: 00 00 00 F4 00 00 00 E4  00 00 00 F6 00 00 00 F5  |................|
0x2A40: 00 00 00 E5 00 00 00 F7  00 00 00 F6 00 00 00 E6  |................|
0x2A50: 00 00 00 F8 00 00 00 F7  00 00 00 E7 00 00 00 F9  |................|
0x2A60: 00 00 00 F8 00 00 00 E8  00 00 00 FA 00 00 00 F9  |................|
0x2A70: 00 00 00 E9 00 00 00 FB  00 00 00 FA 00 00 00 EA  |................|
0x2A80: 00 00 00 FC 00 00 00 FB  00 00 00 EB 00 00 00 FD  |................|
0x2A90: 00 00 01 0E 00 00 00 EC  00 00 00 FE 00 00 00 FD  |................|
0x2AA0: 00 00 00 ED 00 00 00 FF  00 00 00 FE 00 00 00 EE  |................|
0x2AB0: 00 00 01 00 00 00 00 FF  00 00 00 EF 00 00 01 01  |................|
0x2AC0: 00 00 01 00 00 00 00 F0  00 00 01 02 00 00 01 01  |................|
0x2AD0: 00 00 00 F1 00 00 01 03  00 00 01 02 00 00 00 F2  |................|
0x2AE0: 00 00 01 04 00 00 01 03  00 00 00 F3 00 00 01 05  |................|
0x2AF0: 00 00 01 04 00 00 00 F4  00 00 01 06 00 00 01 05  |................|
0x2B00: 00 00 00 F5 00 00 01 07  00 00 01 06 00 00 00 F6  |................|
0x2B10: 00 00 01 08 00 00 01 07  00 00 00 F7 00 00 01 09  |................|
0x2B20: 00 00 01 08 00 00 00 F8  00 00 01 0A 00 00 01 09  |................|
0x2B30: 00 00 00 F9 00 00 01 0B  00 00 01 0A 00 00 00 FA  |................|
0x2B40: 00 00 01 0C 00 00 01 0B  00 00 00 FB 00 00 01 0D  |................|
0x2B50: 00 00 01 0C 00 00 00 FC  00 00 01 0E 00 00 01 0D  |................|
0x2B60: 00 00 00 FD 00 00 01 0F  00 00 01 20 00 00 00 FE  |........... ....|
0x2B70: 00 00 01 10 00 00 01 0F  00 00 00 FF 00 00 01 11  |................|
0x2B80: 00 00 01 10 00 00 01 00  00 00 01 12 00 00 01 11  |................|
0x2B90: 00 00 01 01 00 00 01 13  00 00 01 12 00 00 01 02  |................|
0x2BA0: 00 00 01 14 00 00 01 13  00 00 01 03 00 00 01 15  |................|
0x2BB0: 00 00 01 14 00 00 01 04  00 00 01 16 00 00 01 15  |................|
0x2BC0: 00 00 01 05 00 00 01 17  00 00 01 16 00 00 01 06  |................|
0x2BD0: 00 00 01 18 00 00 01 17  00 00 01 07 00 00 01 19  |................|
0x2BE0: 00 00 01 18 00 00 01 08  00 00 01 1A 00 00 01 19  |................|
0x2BF0: 00 00 01 09 00 00 01 1B  00 00 01 1A 00 00 01 0A  |................|
0x2C00: 00 00 01 1C 00 00 01 1B  00 00 01 0B 00 00 01 1D  |................|
0x2C10: 00 00 01 1C 00 00 01 0C  00 00 01 1E 00 00 01 1D  |................|
0x2C20: 00 00 01 0D 00 00 01 1F  00 00 01 1E 00 00 01 0E  |................|
0x2C30: 00 00 01 20 00 00 01 1F  00 00 01 0F 00 00 01 21  |... ...........!|
0x2C40: 00 00 01 32 00 00 01 10  00 00 01 22 00 00 01 21  |...2......."...!|
0x2C50: 00 00 01 11 00 00 01 23  00 00 01 22 00 00 01 12  |.......#..."....|
0x2C60: 00 00 01 24 00 00 01 23  00 00 01 13 00 00 01 25  |...$...#.......%|
0x2C70: 00 00 01 24 00 00 01 14  00 00 01 26 00 00 01 25  |...$.......&...%|
0x2C80: 00 00 01 15 00 00 01 27  00 00 01 26 00 00 01 16  |.......'...&....|
0x2C90: 00 00 01 28 00 00 01 27  00 00 01 17 00 00 01 29  |...(...'.......)|
0x2CA0: 00 00 01 28 00 00 01 18  00 00 01 2A 00 00 01 29  |...(.......*...)|
0x2CB0: 00 00 01 19 00 00 01 2B  00 00 01 2A 00 00 01 1A  |.......+...*....|
0x2CC0: 00 00 01 2C 00 00 01 2B  00 00 01 1B 00 00 01 2D  |...,...+.......-|
0x2CD0: 00 00 01 2C 00 00 01 1C  00 00 01 2E 00 00 01 2D  |...,...........-|
0x2CE0: 00 00 01 1D 00 00 01 2F  00 00 01 2E 00 00 01 1E  |......./........|
0x2CF0: 00 00 01 30 00 00 01 2F  00 00 01 1F 00 00 01 31  |...0.../.......1|
0x2D00: 00 00 01 30 00 00 01 20  00 00 01 32 00 00 01 31  |...0... ...2...1|
0x2D10: 00 00 01 21 00 00 01 33  00 00 01 44 00 00 01 22  |...!...3...D..."|
0x2D20: 00 00 01 34 00 00 01 33  00 00 01 23 00 00 01 35  |...4...3...#...5|
0x2D30: 00 00 01 34 00 00 01 24  00 00 01 36 00 00 01 35  |...4...$...6...5|
0x2D40: 00 00 01 25 00 00 01 37  00 00 01 36 00 00 01 26  |...%...7...6...&|
0x2D50: 00 00 01 38 00 00 01 37  00 00 01 27 00 00 01 39  |...8...7...'...9|
0x2D60: 00 00 01 38 00 00 01 28  00 00 01 3A 00 00 01 39  |...8...(...:...9|
0x2D70: 00 00 01 29 00 00 01 3B  00 00 01 3A 00 00 01 2A  |...)...;...:...*|
0x2D80: 00 00 01 3C 00 00 01 3B  00 00 01 2B 00 00 01 3D  |...<...;...+...=|
0x2D90: 00 00 01 3C 00 00 01 2C  00 00 01 3E 00 00 01 3D  |...<...,...>...=|
0x2DA0: 00 00 01 2D 00 00 01 3F  00 00 01 3E 00 00 01 2E  |...-...?...>....|
0x2DB0: 00 00 01 40 00 00 01 3F  00 00 01 2F 00 00 01 41  |...@...?.../...A|
0x2DC0: 00 00 01 40 00 00 01 30  00 00 01 42 00 00 01 41  |...@...0...B...A|
0x2DD0: 00 00 01 31 00 00 01 43  00 00 01 42 00 00 01 32  |...1...C...B...2|
0x2DE0: 00 00 01 44 00 00 01 43  00 00 01 33 00 00 01 45  |...D...C...3...E|
0x2DF0: 00 00 01 56 00 00 01 34  00 00 01 46 00 00 01 45  |...V...4...F...E|
0x2E00: 00 00 01 35 00 00 01 47  00 00 01 46 00 00 01 36  |...5...G...F...6|
0x2E10: 00 00 01 48 00 00 01 47  00 00 01 37 00 00 01 49  |...H...G...7...I|
0x2E20: 00 00 01 48 00 00 01 38  00 00 01 4A 00 00 01 49  |...H...8...J...I|
0x2E30: 00 00 01 39 00 00 01 4B  00 00 01 4A 00 00 01 3A  |...9...K...J...:|
0x2E40: 00 00 01 4C 00 00 01 4B  00 00 01 3B 00 00 01 4D  |...L...K...;...M|
0x2E50: 00 00 01 4C 00 00 01 3C  00 00 01 4E 00 00 01 4D  |...L...<...N...M|
0x2E60: 00 00 01 3D 00 00 01 4F  00 00 01 4E 00 00 01 3E  |...=...O...N...>|
0x2E70: 00 00 01 50 00 00 01 4F  00 00 01 3F 00 00 01 51  |...P...O...?...Q|
0x2E80: 00 00 01 50 00 00 01 40  00 00 01 52 00 00 01 51  |...P...@...R...Q|
0x2E90: 00 00 01 41 00 00 01 53  00 00 01 52 00 00 01 42  |...A...S...R...B|
0x2EA0: 00 00 01 54 00 00 01 53  00 00 01 43 00 00 01 55  |...T...S...C...U|
0x2EB0: 00 00 01 54 00 00 01 44  00 00 01 56 00 00 01 55  |...T...D...V...U|
0x2EC0: 00 00 01 45 00 00 01 57  00 00 01 68 00 00 01 46  |...E...W...h...F|
0x2ED0: 00 00 01 58 00 00 01 57  00 00 01 47 00 00 01 59  |...X...W...G...Y|
0x2EE0: 00 00 01 58 00 00 01 48  00 00 01 5A 00 00 01 59  |...X...H...Z...Y|
0x2EF0: 00 00 01 49 00 00 01 5B  00 00 01 5A 00 00 01 4A  |...I...[...Z...J|
0x2F00: 00 00 01 5C 00 00 01 5B  00 00 01 4B 00 00 01 5D  |...\...[...K...]|
0x2F10: 00 00 01 5C 00 00 01 4C  00 00 01 5E 00 00 01 5D  |...\...L...^...]|
0x2F20: 00 00 01 4D 00 00 01 5F  00 00 01 5E 00 00 01 4E  |...M..._...^...N|
0x2F30: 00 00 01 60 00 00 01 5F  00 00 01 4F 00 00 01 61  |...`..._...O...a|
0x2F40: 00 00 01 60 00 00 01 50  00 00 01 62 00 00 01 61  |...`...P...b...a|
0x2F50: 00 00 01 51 00 00 01 63  00 00 01 62 00 00 01 52  |...Q...c...b...R|
0x2F60: 00 00 01 64 00 00 01 63  00 00 01 53 00 00 01 65  |...d...c...S...e|
0x2F70: 00 00 01 64 00 00 01 54  00 00 01 66 00 00 01 65  |...d...T...f...e|
0x2F80: 00 00 01 55 00 00 01 67  00 00 01 66 00 00 01 56  |...U...g...f...V|
0x2F90: 00 00 01 68 00 00 01 67  00 00 01 57 00 00 01 69  |...h...g...W...i|
0x2FA0: 00 00 01 7A 00 00 01 58  00 00 01 6A 00 00 01 69  |...z...X...j...i|
0x2FB0: 00 00 01 59 00 00 01 6B  00 00 01 6A 00 00 01 5A  |...Y...k...j...Z|
0x2FC0: 00 00 01 6C 00 00 01 6B  00 00 01 5B 00 00 01 6D  |...l...k...[...m|
0x2FD0: 00 00 01 6C 00 00 01 5C  00 00 01 6E 00 00 01 6D  |...l...\...n...m|
0x2FE0: 00 00 01 5D 00 00 01 6F  00 00 01 6E 00 00 01 5E  |...]...o...n...^|
0x2FF0: 00 00 01 70 00 00 01 6F  00 00 01 5F 00 00 01 71  |...p...o..._...q|
0x3000: 00 00 01 70 00 00 01 60  00 00 01 72 00 00 01 71  |...p...`...r...q|
0x3010: 00 00 01 61 00 00 01 73  00 00 01 72 00 00 01 62  |...a...s...r...b|
0x3020: 00 00 01 74 00 00 01 73  00 00 01 63 00 00 01 75  |...t...s...c...u|
0x3030: 00 00 01 74 00 00 01 64  00 00 01 76 00 00 01 75  |...t...d...v...u|
0x3040: 00 00 01 65 00 00 01 77  00 00 01 76 00 00 01 66  |...e...w...v...f|
0x3050: 00 00 01 78 00 00 01 77  00 00 01 67 00 00 01 79  |...x...w...g...y|
0x3060: 00 00 01 78 00 00 01 68  00 00 01 7A 00 00 01 79  |...x...h...z...y|
0x3070: 00 00 01 69 00 00 01 7B  00 00 01 8C 00 00 01 6A  |...i...{.......j|
0x3080: 00 00 01 7C 00 00 01 7B  00 00 01 6B 00 00 01 7D  |...|...{...k...}|
0x3090: 00 00 01 7C 00 00 01 6C  00 00 01 7E 00 00 01 7D  |...|...l...~...}|
0x30A0: 00 00 01 6D 00 00 01 7F  00 00 01 7E 00 00 01 6E  |...m.......~...n|
0x30B0: 00 00 01 80 00 00 01 7F  00 00 01 6F 00 00 01 81  |...........o....|
0x30C0: 00 00 01 80 00 00 01 70  00 00 01 82 00 00 01 81  |.......p........|
0x30D0: 00 00 01 71 00 00 01 83  00 00 01 82 00 00 01 72  |...q...........r|
0x30E0: 00 00 01 84 00 00 01 83  00 00 01 73 00 00 01 85  |...........s....|
0x30F0: 00 00 01 84 00 00 01 74  00 00 01 86 00 00 01 85  |.......t........|
0x3100: 00 00 01 75 00 00 01 87  00 00 01 86 00 00 01 76  |...u...........v|
0x3110: 00 00 01 88 00 00 01 87  00 00 01 77 00 00 01 89  |...........w....|
0x3120: 00 00 01 88 00 00 01 78  00 00 01 8A 00 00 01 89  |.......x........|
0x3130: 00 00 01 79 00 00 01 8B  00 00 01 8A 00 00 01 7A  |...y...........z|
0x3140: 00 00 01 8C 00 00 01 8B  00 00 01 7B 00 00 01 8D  |...........{....|
0x3150: 00 00 01 9E 00 00 01 7C  00 00 01 8E 00 00 01 8D  |.......|........|
0x3160: 00 00 01 7D 00 00 01 8F  00 00 01 8E 00 00 01 7E  |...}...........~|
0x3170: 00 00 01 90 00 00 01 8F  00 00 01 7F 00 00 01 91  |................|
0x3180: 00 00 01 90 00 00 01 80  00 00 01 92 00 00 01 91  |................|
0x3190: 00 00 01 81 00 00 01 93  00 00 01 92 00 00 01 82  |................|
0x31A0: 00 00 01 94 00 00 01 93  00 00 01 83 00 00 01 95  |................|
0x31B0: 00 00 01 94 00 00 01 84  00 00 01 96 00 00 01 95  |................|
0x31C0: 00 00 01 85 00 00 01 97  00 00 01 96 00 00 01 86  |................|
0x31D0: 00 00 01 98 00 00 01 97  00 00 01 87 00 00 01 99  |................|
0x31E0: 00 00 01 98 00 00 01 88  00 00 01 9A 00 00 01 99  |................|
0x31F0: 00 00 01 89 00 00 01 9B  00 00 01 9A 00 00 01 8A  |................|
0x3200: 00 00 01 9C 00 00 01 9B  00 00 01 8B 00 00 01 9D  |................|
0x3210: 00 00 01 9C 00 00 01 8C  00 00 01 9E 00 00 01 9D  |................|
0x3220: 00 00 01 8D 00 00 01 9F  00 00 01 B0 00 00 01 8E  |................|
0x3230: 00 00 01 A0 00 00 01 9F  00 00 01 8F 00 00 01 A1  |................|
0x3240: 00 00 01 A0 00 00 01 90  00 00 01 A2 00 00 01 A1  |................|
0x3250: 00 00 01 91 00 00 01 A3  00 00 01 A2 00 00 01 92  |................|
0x3260: 00 00 01 A4 00 00 01 A3  00 00 01 93 00 00 01 A5  |................|
0x3270: 00 00 01 A4 00 00 01 94  00 00 01 A6 00 00 01 A5  |................|
0x3280: 00 00 01 95 00 00 01 A7  00 00 01 A6 00 00 01 96  |................|
0x3290: 00 00 01 A8 00 00 01 A7  00 00 01 97 00 00 01 A9  |................|
0x32A0: 00 00 01 A8 00 00 01 98  00 00 01 AA 00 00 01 A9  |................|
0x32B0: 00 00 01 99 00 00 01 AB  00 00 01 AA 00 00 01 9A  |................|
0x32C0: 00 00 01 AC 00 00 01 AB  00 00 01 9B 00 00 01 AD  |................|
0x32D0: 00 00 01 AC 00 00 01 9C  00 00 01 AE 00 00 01 AD  |................|
0x32E0: 00 00 01 9D 00 00 01 AF  00 00 01 AE 00 00 01 9E  |................|
0x32F0: 00 00 01 B0 00 00 01 AF  00 00 01 9F 00 00 01 B1  |................|
0x3300: 00 00 01 C2 00 00 01 A0  00 00 01 B2 00 00 01 B1  |................|
0x3310: 00 00 01 A1 00 00 01 B3  00 00 01 B2 00 00 01 A2  |................|
0x3320: 00 00 01 B4 00 00 01 B3  00 00 01 A3 00 00 01 B5  |................|
0x3330: 00 00 01 B4 00 00 01 A4  00 00 01 B6 00 00 01 B5  |................|
0x3340: 00 00 01 A5 00 00 01 B7  00 00 01 B6 00 00 01 A6  |................|
0x3350: 00 00 01 B8 00 00 01 B7  00 00 01 A7 00 00 01 B9  |................|
0x3360: 00 00 01 B8 00 00 01 A8  00 00 01 BA 00 00 01 B9  |................|
0x3370: 00 00 01 A9 00 00 01 BB  00 00 01 BA 00 00 01 AA  |................|
0x3380: 00 00 01 BC 00 00 01 BB  00 00 01 AB 00 00 01 BD  |................|
0x3390: 00 00 01 BC 00 00 01 AC  00 00 01 BE 00 00 01 BD  |................|
0x33A0: 00 00 01 AD 00 00 01 BF  00 00 01 BE 00 00 01 AE  |................|
0x33B0: 00 00 01 C0 00 00 01 BF  00 00 01 AF 00 00 01 C1  |................|
0x33C0: 00 00 01 C0 00 00 01 B0  00 00 01 C2 00 00 01 C1  |................|
0x33D0: 00 00 01 B1 00 00 01 C3  00 00 01 D4 00 00 01 B2  |................|
0x33E0: 00 00 01 C4 00 00 01 C3  00 00 01 B3 00 00 01 C5  |................|
0x33F0: 00 00 01 C4 00 00 01 B4  00 00 01 C6 00 00 01 C5  |................|
0x3400: 00 00 01 B5 00 00 01 C7  00 00 01 C6 00 00 01 B6  |................|
0x3410: 00 00 01 C8 00 00 01 C7  00 00 01 B7 00 00 01 C9  |................|
0x3420: 00 00 01 C8 00 00 01 B8  00 00 01 CA 00 00 01 C9  |................|
0x3430: 00 00 01 B9 00 00 01 CB  00 00 01 CA 00 00 01 BA  |................|
0x3440: 00 00 01 CC 00 00 01 CB  00 00 01 BB 00 00 01 CD  |................|
0x3450: 00 00 01 CC 00 00 01 BC  00 00 01 CE 00 00 01 CD  |................|
0x3460: 00 00 01 BD 00 00 01 CF  00 00 01 CE 00 00 01 BE  |................|
0x3470: 00 00 01 D0 00 00 01 CF  00 00 01 BF 00 00 01 D1  |................|
0x3480: 00 00 01 D0 00 00 01 C0  00 00 01 D2 00 00 01 D1  |................|
0x3490: 00 00 01 C1 00 00 01 D3  00 00 01 D2 00 00 01 C2  |................|
0x34A0: 00 00 01 D4 00 00 01 D3  3F 73 4D 6A 3F 80 00 00  |........?sMj?...|
0x34B0: 3F 8B 61 13 3F 73 4D 6A  3F 80 00 00 3F 8B 61 13  |?.a.?sMj?...?.a.|
0x34C0: 3F 73 4D 6A 3F 80 00 00  3F 8B 61 13 3F 73 4D 6A  |?sMj?...?.a.?sMj|
0x34D0: 3F 80 00 00 3F 8B 61 13  3F 73 4D 6A 3F 80 00 00  |?...?.a.?sMj?...|
0x34E0: 3F 8B 61 13 3F 73 4D 6A  3F 80 00 00 3F 8B 61 13  |?.a.?sMj?...?.a.|
0x34F0: 3F 73 4D 6A 3F 80 00 00  3F 8B 61 13 3F 73 4D 6A  |?sMj?...?.a.?sMj|
0x3500: 3F 80 00 00 3F 8B 61 13  3F 73 4D 6A 3F 80 00 00  |?...?.a.?sMj?...|
0x3510: 3F 8B 61 13 3F 73 4D 6A  3F 80 00 00 3F 8B 61 13  |?.a.?sMj?...?.a.|
0x3520: 3F 73 4D 6A 3F 80 00 00  3F 8B 61 13 3F 73 4D 6A  |?sMj?...?.a.?sMj|
0x3530: 3F 80 00 00 3F 8B 61 13  3F 73 4D 6A 3F 80 00 00  |?...?.a.?sMj?...|
0x3540: 3F 8B 61 13 3F 73 4D 6A  3F 80 00 00 3F 8B 61 13  |?.a.?sMj?...?.a.|
0x3550: 3F 73 4D 6A 3F 80 00 00  3F 8B 61 13 3F 73 4D 6A  |?sMj?...?.a.?sMj|
0x3560: 3F 80 00 00 3F 8B 61 13  3F 73 4D 6A 3F 80 00 00  |?...?.a.?sMj?...|
0x3570: 3F 8B 61 13 3F 73 4D 6A  3F 80 00 00 3F 8B 61 13  |?.a.?sMj?...?.a.|
0x3580: 3F 6A DB 5E 3F 73 A4 11  3F 82 FC 27 3F 6A DB 5E  |?j.^?s..?..'?j.^|
0x3590: 3F 73 A4 11 3F 82 FC 27  3F 6C 70 84 3F 76 CE 5D  |?s..?..'?lp.?v.]|
0x35A0: 3F 83 3F AD 3F 6D 3C B5  3F 78 66 C0 3F 83 61 B5  |?.?.?m<.?xf.?.a.|
0x35B0: 3F 70 78 50 3F 7E DD F6  3F 83 EB A4 3F 6B D2 8D  |?pxP?~..?...?k..|
0x35C0: 3F 7C 78 7D 3F 83 CF C2  3F 6B D2 8D 3F 7C 78 7D  |?|x}?...?k..?|x}|
0x35D0: 3F 83 CF C2 3F 69 FF 60  3F 7B 87 9A 3F 83 C4 CF  |?...?i.`?{..?...|
0x35E0: 3F 6A CB D2 3F 7B D9 61  3F 85 DF 2D 3F 6B 32 DC  |?j..?{.a?..-?k2.|
0x35F0: 3F 7C 02 98 3F 86 EE 82  3F 6C D4 7A 3F 7C A9 A4  |?|..?...?l.z?|..|
0x3600: 3F 8B 3A 3E 3F 69 98 DF  3F 76 32 6F 3F 8A B0 4E  |?.:>?i..?v2o?..N|
0x3610: 3F 68 CC AE 3F 74 9A 0C  3F 8A 8E 46 3F 67 37 88  |?h..?t..?..F?g7.|
0x3620: 3F 71 6F C0 3F 8A 4A C0  3F 69 0A B5 3F 72 60 A3  |?qo.?.J.?i..?r`.|
0x3630: 3F 8A 55 B3 3F 69 F6 29  3F 72 DA 0B 3F 8A 5B 38  |?.U.?i.)?r..?.[8|
0x3640: 3F 6D B0 78 3F 74 C6 1B  3F 8A 71 96 3F 6C 0E D9  |?m.x?t..?.q.?l..|
0x3650: 3F 74 1F 0F 3F 86 25 DA  3F 5A F8 06 3F 58 D7 28  |?t..?.%.?Z..?X.(|
0x3660: 3F 71 55 0D 3F 57 A1 6D  3F 57 81 51 3F 5F C0 2C  |?qU.?W.m?W.Q?_.,|
0x3670: 3F 59 FB 41 3F 61 D3 E9  3F 4F 34 0D 3F 5B D8 DA  |?Y.A?a..?O4.?[..|
0x3680: 3F 6C 61 87 3F 3A CA 72  3F 5F C9 E4 3F 78 31 CA  |?la.?:.r?_..?x1.|
0x3690: 3F 2F FC 62 3F 5C 68 1A  3F 76 17 E4 3F 3F F5 6F  |?/.b?\h.?v..??.o|
0x36A0: 3F 5D 2B A9 3F 75 93 C5  3F 69 13 34 3F 54 D0 A0  |?]+.?u..?i.4?T..|
0x36B0: 3F 71 5A 5C 3F 64 E3 15  3F 57 C6 22 3F 72 89 5D  |?qZ\?d..?W."?r.]|
0x36C0: 3F 74 78 9F 3F 5A DD ED  3F 73 C6 14 3F 82 61 5D  |?tx.?Z..?s..?.a]|
0x36D0: 3F 5E 18 6F 3F 75 10 AE  3F 8A E1 D5 3F 5B D3 40  |?^.o?u..?...?[.@|
0x36E0: 3F 6B 90 0A 3F 8A 06 66  3F 58 06 91 3F 62 B4 99  |?k..?..f?X..?b..|
0x36F0: 3F 89 45 35 3F 51 F2 28  3F 57 CD DC 3F 88 60 E2  |?.E5?Q.(?W..?.`.|
0x3700: 3F 5A 7B 24 3F 5D 4B CE  3F 88 AF 0C 3F 5E 3F 68  |?Z{$?]K.?...?^?h|
0x3710: 3F 5E 25 B1 3F 88 AA B2  3F 60 E9 3C 3F 5B 37 A3  |?^%.?...?`.<?[7.|
0x3720: 3F 88 50 61 3F 5E 14 22  3F 5A 15 99 3F 80 DA F2  |?.Pa?^."?Z..?...|
0x3730: 3F 47 6A 61 3F 39 5C E0  3F 53 4A BB 3F 41 62 73  |?Gja?9\.?SJ.?Abs|
0x3740: 3F 36 F3 4E 3F 33 87 5A  3F 45 4E CF 3F 48 4F 86  |?6.N?3.Z?EN.?HO.|
0x3750: 3F 17 80 AE 3F 4A F2 61  3F 5D 04 36 3E F8 A0 34  |?...?J.a?].6>..4|
0x3760: 3F 53 32 35 3F 73 28 51  3E DB 54 AA 3F 4A F8 2C  |?S25?s(Q>.T.?J.,|
0x3770: 3F 6E 65 C5 3F 04 AA C0  3F 4B 5E E2 3F 6D 32 8D  |?ne.?...?K^.?m2.|
0x3780: 3F 44 33 9C 3F 3C 4E 2E  3F 65 93 F0 3F 3C CB 59  |?D3.?<N.?e..?<.Y|
0x3790: 3F 41 49 1B 3F 67 91 E8  3F 57 05 F7 3F 47 1A BE  |?AI.?g..?W..?G..|
0x37A0: 3F 69 E5 C3 3F 75 AB 60  3F 4D 0B F4 3F 6C 46 3F  |?i..?u.`?M..?lF?|
0x37B0: 3F 8A 7B 8A 3F 49 7D B3  3F 5C 58 5F 3F 89 0A 04  |?.{.?I}.?\X_?...|
0x37C0: 3F 43 9E 30 3F 4D 2E 02  3F 87 BA F8 3F 3B 43 78  |?C.0?M..?...?;Cx|
0x37D0: 3F 3C 78 92 3F 86 56 84  3F 46 91 7F 3F 42 4C CD  |?<x.?.V.?F..?BL.|
0x37E0: 3F 86 9A 58 3F 4E 1A AC  3F 43 38 69 3F 86 7E 4F  |?..X?N..?C8i?.~O|
0x37F0: 3F 52 20 38 3F 3D A5 9D  3F 85 D9 8B 3F 4C 90 A3  |?R 8?=..?...?L..|
0x3800: 3F 3B 6C 2E 3F 6E 69 8C  3F 33 00 C1 3F 19 2A A1  |?;l.?ni.?3..?.*.|
0x3810: 3F 31 E1 BF 3F 2A C9 38  3F 15 E1 37 3F 06 9B 1F  |?1..?*.8?..7?...|
0x3820: 3F 31 D2 F5 3F 2E BA 93  3E CF 78 75 3F 3C 85 17  |?1..?...>.xu?<..|
0x3830: 3F 4C A9 2E 3E A1 EF 79  3F 4A FE 83 3F 6F E0 70  |?L..>..y?J..?o.p|
0x3840: 3E 84 EF D7 3F 3B 88 AC  3F 67 6E C5 3E AE 21 53  |>...?;..?gn.>.!S|
0x3850: 3F 37 D1 28 3F 63 F3 79  3F 1D 8B FC 3F 23 68 4C  |?7.(?c.y?...?#hL|
0x3860: 3F 59 9D BE 3F 14 10 F5  3F 2A 5B 44 3F 5C 65 55  |?Y..?...?*[D?\eU|
0x3870: 3F 38 AA 32 3F 32 72 7F  3F 5F A1 D3 3F 63 46 AC  |?8.2?2r.?_..?cF.|
0x3880: 3F 3B BA 4E 3F 63 58 25  3F 8A 13 A1 3F 36 BC C2  |?;.N?cX%?...?6..|
0x3890: 3F 4D 10 F9 3F 88 0E F1  3F 2E B8 D4 3F 38 02 CC  |?M..?...?...?8..|
0x38A0: 3F 86 3C D6 3F 26 87 3E  3F 23 7B F2 3F 84 78 FD  |?.<.?&.>?#{.?.x.|
0x38B0: 3F 31 8F 5A 3F 25 95 25  3F 84 62 81 3F 3B D8 77  |?1.Z?%.%?.b.?;.w|
0x38C0: 3F 26 87 50 3F 84 34 94  3F 43 1B 39 3F 1F 9B 9E  |?&.P?.4.?C.9?...|
0x38D0: 3F 83 58 B6 3F 3A 8D 9A  3F 1C 2F C5 3F 59 A5 6B  |?.X.?:..?./.?Y.k|
0x38E0: 3F 21 A3 15 3E FC 7D E4  3F 14 02 42 3F 18 00 A6  |?!..>.}.?..B?...|
0x38F0: 3E F4 C8 BD 3E C2 88 B7  3F 21 88 4E 3F 18 3D 84  |>...>...?!.N?.=.|
0x3900: 3E 86 5B E1 3F 31 43 C5  3F 3E 1A C5 3E 52 C3 AB  |>.[.?1C.?>..>R..|
0x3910: 3F 46 94 A3 3F 6E 1C 7D  3E 2C E5 02 3F 2F 53 8A  |?F..?n.}>,..?/S.|
0x3920: 3F 61 CB 4A 3E 63 86 F2  3F 26 88 E9 3F 5B BF 90  |?a.J>c..?&..?[..|
0x3930: 3E F9 84 42 3F 0E B6 74  3F 4F AC 82 3E E4 6D 7E  |>..B?..t?O..>.m~|
0x3940: 3F 16 EC 92 3F 52 F5 5B  3F 1D 75 E4 3F 20 E1 94  |?...?R.[?.u.? ..|
0x3950: 3F 56 F0 F5 3F 51 E6 AA  3F 2D 55 24 3F 5B EB FC  |?V..?Q..?-U$?[..|
0x3960: 3F 89 BD 42 3F 26 0B 53  3F 3F 00 E7 3F 87 24 06  |?..B?&.S??..?.$.|
0x3970: 3F 1B D8 BB 3F 24 7B 90  3F 84 D9 9D 3F 13 B0 6F  |?...?${.?...?..o|
0x3980: 3F 0C C8 46 3F 82 C7 21  3F 1E 84 8E 3F 0B F5 FB  |?..F?..!?...?...|
0x3990: 3F 82 69 E3 3F 2B 74 D1  3F 0D 51 E8 3F 82 34 4B  |?.i.?+t.?.Q.?.4K|
0x39A0: 3F 36 9F 56 3F 06 A3 D9  3F 81 44 10 3F 2B 35 A3  |?6.V?...?.D.?+5.|
0x39B0: 3F 02 13 2A 3F 46 6C 81  3F 13 29 C6 3E D0 A1 6C  |?..*?Fl.?.).>..l|
0x39C0: 3E F3 18 93 3F 08 D2 E2  3E C8 5B E9 3E 86 30 01  |>...?...>.[.>.0.|
0x39D0: 3F 13 BB 07 3F 03 B9 6D  3E 22 E6 45 3F 29 13 43  |?...?..m>".E?).C|
0x39E0: 3F 32 54 AB 3E 0F 0C 71  3F 45 6E 29 3F 6D A6 B3  |?2T.>..q?En)?m..|
0x39F0: 3E 14 A9 6B 3F 25 F4 96  3F 5D 53 23 3E 20 4E 65  |>..k?%..?]S#> Ne|
0x3A00: 3F 17 6F 91 3F 54 8C C8  3E C3 19 03 3E FB FA 9E  |?.o.?T..>...>...|
0x3A10: 3F 47 A3 BA 3E AD B7 4F  3F 06 8F F0 3F 4B 11 94  |?G..>..O?...?K..|
0x3A20: 3F 04 02 06 3F 12 91 84  3F 4F DF 02 3F 43 3D 89  |?...?...?O..?C=.|
0x3A30: 3F 21 B3 32 3F 55 EC 7B  3F 89 77 76 3F 17 54 7B  |?!.2?U.{?.wv?.T{|
0x3A40: 3F 32 1D 11 3F 86 48 BF  3F 0A ED 13 3F 12 8C FE  |?2..?.H.?...?...|
0x3A50: 3F 83 90 A7 3F 02 B1 76  3E F0 9A 5B 3F 81 3F B7  |?...?..v>..[?.?.|
0x3A60: 3F 0C B1 BC 3E E9 F2 87  3F 80 AA 23 3F 1D AC A7  |?...>...?..#?...|
0x3A70: 3E EF BD F4 3F 80 7F 50  3F 2C 88 C5 3E E4 ED 6B  |>...?..P?,..>..k|
0x3A80: 3F 7F 2B 45 3F 1E 64 81  3E D9 9D 35 3F 34 B0 88  |?.+E?.d.>..5?4..|
0x3A90: 3F 07 E7 AE 3E AF 5B 67  3E C7 55 45 3E FA D3 C9  |?...>.[g>.UE>...|
0x3AA0: 3E A6 F6 C6 3E 31 A5 EB  3F 0A 7A 8E 3E E7 37 34  |>...>1..?.z.>.74|
0x3AB0: 3D F2 3E 5D 3F 20 C4 E0  3F 23 FC C5 3D CF FA 3C  |=.>]? ..?#..=..<|
0x3AC0: 3F 45 1B 6F 3F 6D 85 9C  3E 0D DA A0 3F 1E 30 3A  |?E.o?m..>...?.0:|
0x3AD0: 3F 59 5D 59 3E 16 C4 8B  3F 0A 93 B3 3F 4E 5F E6  |?Y]Y>...?...?N_.|
0x3AE0: 3E 98 CE D1 3E E2 D6 36  3F 41 99 9C 3E 84 96 A3  |>...>..6?A..>...|
0x3AF0: 3E F4 3C 6B 3F 45 14 74  3E E0 39 79 3F 06 F6 5A  |>.<k?E.t>.9y?..Z|
0x3B00: 3F 4A 37 B5 3F 33 C2 4B  3F 18 F4 A0 3F 51 6A 38  |?J7.?3.K?...?Qj8|
0x3B10: 3F 89 42 FF 3F 0A 81 E4  3F 26 59 A0 3F 85 7C 8E  |?.B.?...?&Y.?.|.|
0x3B20: 3E F8 AE 16 3F 02 66 80  3F 82 63 FA 3E E6 F8 3B  |>...?.f.?.c.>..;|
0x3B30: 3E CB F3 17 3F 7F C2 F0  3E FC F1 81 3E C4 B1 D2  |>...?...>...>...|
0x3B40: 3F 7E 7B B2 3F 10 C6 95  3E CA 5C DF 3F 7E 11 16  |?~{.?...>.\.?~..|
0x3B50: 3F 24 F3 69 3E C6 97 FD  3F 7C A4 26 3F 14 35 A4  |?$.i>...?|.&?.5.|
0x3B60: 3E B9 33 5F 3F 24 78 6B  3E FD 8C 4F 3E 95 EF 4B  |>.3_?$xk>..O>..K|
0x3B70: 3E 9F 04 18 3E E9 CA 34  3E 8E 08 0D 3D DB D3 00  |>...>..4>...=...|
0x3B80: 3F 00 BC CC 3E C4 1C A7  3D A8 A5 08 3F 16 9F D6  |?...>...=...?...|
0x3B90: 3F 10 60 77 3D A4 2E 4F  3F 3C 6D E0 3F 63 10 8A  |?.`w=..O?<m.?c..|
0x3BA0: 3E 07 9B D0 3F 12 68 58  3F 53 52 47 3E 0E EB 46  |>...?.hX?SRG>..F|
0x3BB0: 3E FB A7 BA 3F 48 28 3A  3E 6E DD 33 3E D0 10 D6  |>...?H(:>n.3>...|
0x3BC0: 3F 3D 17 4B 3E 4B C4 06  3E E0 51 38 3F 40 57 5E  |?=.K>K..>.Q8?@W^|
0x3BD0: 3E BB 79 5D 3E FC 0C 89  3F 45 E3 3B 3F 26 C3 8B  |>.y]>...?E.;?&..|
0x3BE0: 3F 12 6D 53 3F 4E 0C 74  3F 89 1B D3 3E FE F6 EF  |?.mS?N.t?...>...|
0x3BF0: 3F 1B A9 D7 3F 84 BE D9  3E DE D8 36 3E E7 5A BF  |?...?...>..6>.Z.|
0x3C00: 3F 81 4F 50 3E CC 03 03  3E AB 76 D9 3F 7D 56 1B  |?.OP>...>.v.?}V.|
0x3C10: 3E E2 6B 50 3E A3 BE 84  3F 7C 00 73 3F 06 46 39  |>.kP>...?|.s?.F9|
0x3C20: 3E AB D2 D8 3F 7B AC 35  3F 1F 4A 02 3E AF F2 60  |>...?{.5?.J.>..`|
0x3C30: 3F 7A C1 04 3F 0C 60 AD  3E A0 D1 4F 3F 17 27 53  |?z..?.`.>..O?.'S|
0x3C40: 3E EF 6F 7E 3E 83 60 89  3E 79 01 EC 3E DD A5 A5  |>.o~>.`.>y..>...|
0x3C50: 3E 78 85 FF 3D 76 8A F9  3E F1 EF A5 3E A7 C0 A9  |>x..=v..>...>...|
0x3C60: 3D 64 CC 85 3F 0A 9A DD  3E F9 5B 54 3D 86 20 3E  |=d..?...>.[T=. >|
0x3C70: 3F 1F 0E 5B 3F 3F AB 39  3D E4 F0 56 3F 05 3A 39  |?..[??.9=..V?.:9|
0x3C80: 3F 48 F9 B6 3D FE 2E 9F  3E E6 00 6A 3F 42 D9 69  |?H..=...>..j?B.i|
0x3C90: 3E 3B 3B BD 3E C2 AF FB  3F 39 E0 98 3E 1F FF 46  |>;;.>...?9..>..F|
0x3CA0: 3E D1 23 77 3F 3C C4 7D  3E 9C 1B 97 3E ED 9E 9F  |>.#w?<.}>...>...|
0x3CB0: 3F 42 76 B9 3F 19 0D D8  3F 0D C6 2B 3F 4B A6 43  |?Bv.?...?..+?K.C|
0x3CC0: 3F 88 FF E8 3E EC 4D EC  3F 11 FF D9 3F 84 0E FC  |?...>.M.?...?...|
0x3CD0: 3E C7 95 64 3E CC 58 E5  3F 80 50 1A 3E B4 63 DF  |>..d>.X.?.P.>.c.|
0x3CE0: 3E 8E FF CF 3F 7B 36 1B  3E CA 84 41 3E 86 7E E1  |>...?{6.>..A>.~.|
0x3CF0: 3F 79 CE FD 3E F9 12 3D  3E 92 2D 54 3F 79 B5 E9  |?y..>..=>.-T?y..|
0x3D00: 3F 1B 41 00 3E 9F CE 57  3F 79 68 AE 3F 05 FA E5  |?.A.>..W?yh.?...|
0x3D10: 3E 8E C9 74 3F 09 5D DA  3E E5 81 FB 3E 6F A0 78  |>..t?.].>...>o.x|
0x3D20: 3E 3F 41 77 3E D6 81 D4  3E 63 A0 59 3D 04 FF 61  |>?Aw>...>c.Y=..a|
0x3D30: 3E E6 03 C5 3E 91 AE 95  3D 19 4B B4 3E E7 3C 20  |>...>...=.K.>.< |
0x3D40: 3E CA 1E 79 3D 56 AE 6E  3F 04 8B 1A 3F 1F B8 51  |>..y=V.n?...?..Q|
0x3D50: 3D BE C7 0A 3E DE 4B 93  3F 2A 33 DC 3D D7 F8 4B  |=...>.K.?*3.=..K|
0x3D60: 3E D5 31 64 3F 3E B3 54  3E 18 4C F9 3E BA D2 2E  |>.1d?>.T>.L.>...|
0x3D70: 3F 37 FC D9 3E 06 42 EC  3E C6 79 C2 3F 3A 51 91  |?7..>.B.>.y.?:Q.|
0x3D80: 3E 80 82 FB 3E E3 DA 98  3F 40 31 BB 3F 0D 9E 5C  |>...>...?@1.?..\|
0x3D90: 3F 0B 09 C5 3F 4A 3D 1F  3F 88 EF 7D 3E DC CE B2  |?...?J=.?..}>...|
0x3DA0: 3F 09 4C 5A 3F 83 6C 40  3E B3 A2 39 3E B4 22 C8  |?.LZ?.l@>..9>.".|
0x3DB0: 3F 7E D0 8A 3E 9F F9 9A  3E 6C CB E4 3F 79 5F F3  |?~..>...>l..?y_.|
0x3DC0: 3E B4 DE 7D 3E 5B 74 D1  3F 77 FD 06 3E E9 E9 08  |>..}>[t.?w..>...|
0x3DD0: 3E 7D 25 2D 3F 78 37 C8  3F 18 E1 98 3E 96 50 B8  |>}%-?x7.?...>.P.|
0x3DE0: 3F 78 9E 36 3F 01 5E 6B  3E 83 81 60 3E F9 92 6C  |?x.6?.^k>..`>..l|
0x3DF0: 3E DF D7 C0 3E 65 51 A7  3E 15 64 D4 3E D3 CA 96  |>...>eQ.>.d.>...|
0x3E00: 3E 5B AD 86 3C B3 9E 20  3E D8 BA D3 3E 80 65 86  |>[..<.. >...>.e.|
0x3E10: 3C D5 F1 7A 3E BE F6 70  3E A2 35 E8 3D 2A 06 69  |<..z>..p>.5.=*.i|
0x3E20: 3E D9 9C 5E 3F 03 1D 64  3D 9C 9C 2C 3E B6 DF D0  |>..^?..d=..,>...|
0x3E30: 3F 0E 6B 42 3D B5 60 04  3E C4 0B 2E 3F 36 D2 93  |?.kB=.`.>...?6..|
0x3E40: 3D F0 FA E2 3E B7 D4 33  3F 37 44 D9 3D F8 F1 E1  |=...>..3?7D.=...|
0x3E50: 3E C1 0C FC 3F 39 1D 02  3E 5D 9B E1 3E DE 36 91  |>...?9..>]..>.6.|
0x3E60: 3F 3E F2 20 3F 04 32 57  3F 09 FF 5D 3F 49 B3 C1  |?>. ?.2W?..]?I..|
0x3E70: 3F 88 E9 3F 3E D0 B8 F2  3F 01 9F 70 3F 82 D7 5D  |?..?>...?..p?..]|
0x3E80: 3E A3 8F 89 3E 9E FC FE  3F 7D 32 70 3E 8E A0 D4  |>...>...?}2p>...|
0x3E90: 3E 42 FD 45 3F 77 D0 75  3E A4 F0 CD 3E 37 F4 2D  |>B.E?w.u>...>7.-|
0x3EA0: 3F 76 B1 D8 3E DD C3 84  3E 61 52 A2 3F 77 31 FB  |?v..>...>aR.?w1.|
0x3EB0: 3F 17 FA 8F 3E 92 B4 93  3F 78 51 33 3E FD 37 1F  |?...>...?xQ3>.7.|
0x3EC0: 3E 7C D1 27 3E E5 64 6F  3E DC 91 8F 3E 61 46 E5  |>|.'>.do>...>aF.|
0x3ED0: 3D EE 95 A8 3E D3 1F 57  3E 59 B8 52 3C 9E 57 81  |=...>..W>Y.R<.W.|
0x3EE0: 3E B4 4E 3D 3E 52 80 56  3C AD 25 EF 3E 9D B3 55  |>.N=>R.V<.%.>..U|
0x3EF0: 3E 84 5C 16 3D 09 F1 D1  3E B1 B4 CB 3E D6 24 9B  |>.\.=...>...>.$.|
0x3F00: 3D 7F C8 77 3E 94 C1 C5  3E EB 71 20 3D 96 6D 68  |=..w>...>.q =.mh|
0x3F10: 3E A0 5A 15 3F 18 11 AB  3D C9 03 D2 3E B7 17 87  |>.Z.?...=...>...|
0x3F20: 3F 37 17 87 3D F4 1F 5F  3E BF 7C 1D 3F 38 C5 3F  |?7..=.._>.|.?8.?|
0x3F30: 3E 52 77 71 3E DC 3B 17  3F 3E 85 0A 3F 00 50 81  |>Rwq>.;.?>..?.P.|
0x3F40: 3F 09 BD BE 3F 49 91 EB  3F 88 E7 B5 3E C7 55 3F  |?...?I..?...>.U?|
0x3F50: 3E F5 92 F5 3F 82 4E 22  3E 96 D9 6D 3E 8C 9D 37  |>...?.N">..m>..7|
0x3F60: 3F 7B C2 33 3E 80 33 9A  3E 20 38 4F 3F 76 84 37  |?{.3>.3.> 8O?v.7|
0x3F70: 3E 99 CB 68 3E 20 3B DF  3F 75 D7 F9 3E D4 02 7F  |>..h> ;.?u..>...|
0x3F80: 3E 4E 67 CD 3F 76 8A 0B  3F 17 C1 A7 3E 91 D0 F2  |>Ng.?v..?...>...|
0x3F90: 3F 78 3E 3B 3E F9 BB 24  3E 78 9B 5C 3E D5 3C 27  |?x>;>..$>x.\>.<'|
0x3FA0: 3E D7 90 E9 3E 5C 68 89  3D D3 70 3E 3E CF 60 08  |>...>\h.=.p>>.`.|
0x3FB0: 3E 55 DB 08 3C 9B 88 06  3E 94 F6 76 3E 2E 62 4C  |>U..<...>..v>.bL|
0x3FC0: 3C 8F C8 35 3E 81 BE 7E  3E 5A 8D 97 3C E4 28 37  |<..5>..~>Z..<.(7|
0x3FD0: 3E 8E 6E AC 3E AB A2 F5  3D 4D 02 E1 3E 71 5B C3  |>.n.>...=M..>q[.|
0x3FE0: 3E C0 7E 53 3D 76 5E DD  3E 83 2F 48 3E FA 65 90  |>.~S=v^.>./H>.e.|
0x3FF0: 3D A5 AB BE 3E B3 D7 96  3F 33 D7 96 3D EF CA 1D  |=...>...?3..=...|
0x4000: 3E BC 08 76 3F 35 7A F6  3E 4E 2C 2D 3E D8 7F 9F  |>..v?5z.>N,->...|
0x4010: 3F 3B 2C 64 3E FD 01 22  3F 07 4B DE 3F 45 FE 04  |?;,d>.."?.K.?E..|
0x4020: 3F 86 79 A1 3E BE B5 BC  3E E6 E8 F2 3F 81 B6 11  |?.y.>...>...?...|
0x4030: 3E 8B B6 D2 3E 76 15 48  3F 7A 5B 24 3E 69 11 AF  |>...>v.H?z[$>i..|
0x4040: 3E 04 19 FB 3F 75 77 87  3E 90 85 69 3E 0E 85 C3  |>...?uw.>..i>...|
0x4050: 3F 75 3B B2 3E CB F3 FD  3E 41 9E 59 3F 76 22 64  |?u;.>...>A.Y?v"d|
0x4060: 3F 15 10 17 3E 8F 3A 60  3F 73 D6 3F 3E F4 08 12  |?...>.:`?s.?>...|
0x4070: 3E 73 2E 43 3E CA C7 1B  3E BA 04 88 3E 3E 29 07  |>s.C>...>...>>).|
0x4080: 3D B9 B4 65 3E B2 CB 3F  3E 38 61 99 3C 86 18 6F  |=..e>..?>8a.<..o|
0x4090: 3E 72 1B F2 3E 0E 2C BD  3C 6B 1D 45 3E 51 D5 5D  |>r..>.,.<k.E>Q.]|
0x40A0: 3E 31 76 F3 3C B9 A1 2C  3E 5F 3E 1A 3E 86 82 10  |>1v.<..,>_>.>...|
0x40B0: 3D 20 A9 C2 3E 43 50 69  3E 9B 60 88 3D 46 C2 FA  |= ..>CPi>.`.=F..|
0x40C0: 3E 55 4D AC 3E CB 4E C3  3D 86 7C 7C 3E 9B 0E 3E  |>UM.>.N.=.||>..>|
0x40D0: 3F 1B 0E 3E 3D CE BD A8  3E A2 47 87 3F 1C 80 19  |?..>=...>.G.?...|
0x40E0: 3E 33 75 F9 3E BA A5 30  3F 21 5F A2 3E DA 0E AA  |>3u.>..0?!_.>...|
0x40F0: 3E E9 4C 74 3F 2A B4 49  3F 67 E1 EE 3E AC 75 0C  |>.Lt?*.I?g..>.u.|
0x4100: 3E C4 3B CD 3F 80 47 44  3E 7F 7D 04 3E 4D 4D 1B  |>.;.?.GD>.}.>MM.|
0x4110: 3F 78 B4 17 3E 56 E7 01  3D DC 6B 75 3F 74 A6 57  |?x..>V..=.ku?t.W|
0x4120: 3E 84 E0 20 3D F8 B6 FE  3F 74 A9 CB 3E B9 B6 4D  |>.. =...?t..>..M|
0x4130: 3E 2B A2 9B 3F 75 8D C3  3F 00 84 BB 3E 76 F9 C4  |>+..?u..?...>v..|
0x4140: 3F 52 3A FD 3E D2 62 31  3E 51 A7 28 3E AE C0 C7  |?R:.>.b1>Q.(>...|
0x4150: 3E 95 74 30 3E 18 BD 60  3D 99 07 CA 3E 8F 77 77  |>.t0>..`=...>.ww|
0x4160: 3E 13 F3 32 3C 57 33 32  3E 40 ED A2 3D E3 7B FB  |>..2<W32>@..=.{.|
0x4170: 3C 3C BC EA 3E 28 1C 66  3E 0E 41 90 3C 94 D7 05  |<<..>(.f>.A.<...|
0x4180: 3E 2A 30 CC 3E 4D 16 1E  3C F4 F7 24 3E 1C 7E 5A  |>*0.>M..<..$>.~Z|
0x4190: 3E 78 E7 B4 3D 1F 30 F6  3E 2A 0F 6D 3E A1 D6 2F  |>x..=.0.>*.m>../|
0x41A0: 3D 56 0D 09 3E 78 D6 63  3E F8 D6 63 3D A5 E4 42  |=V..>x.c>..c=..B|
0x41B0: 3E 82 67 EB 3E FB 3B 7A  3E 12 02 D3 3E 95 CB DA  |>.g.>.;z>...>...|
0x41C0: 3F 01 7E 86 3E AF 20 CA  3E BB 33 B5 3F 08 F9 B2  |?.~.>. .>.3.?...|
0x41D0: 3F 3A 10 D0 3E 85 69 17  3E 98 22 A2 3F 47 0A D1  |?:..>.i.>.".?G..|
0x41E0: 3E 68 E4 D9 3E 25 1C 13  3F 77 0F CC 3E 49 82 B8  |>h..>%..?w..>I..|
0x41F0: 3D BC 25 04 3F 74 0C 22  3E 73 D2 66 3D D9 6E CB  |=.%.?t.">s.f=.n.|
0x4200: 3F 74 32 7B 3E 90 E0 26  3E 04 D3 C8 3F 3E 78 1A  |?t2{>..&>...?>x.|
0x4210: 3E CE 3F FA 3E 46 2D 35  3F 28 B1 14 3E A8 D8 1F  |>.?.>F-5?(..>...|
0x4220: 3E 28 40 86 3E 8C 61 53  3E 65 76 19 3D EA 70 F3  |>(@.>.aS>ev.=.p.|
0x4230: 3D 70 D3 44 3E 5B FC DA  3D E2 DC C1 3C 24 FD A3  |=p.D>[..=...<$..|
0x4240: 3E 16 22 BB 3D B1 E5 0F  3C 14 36 EA 3E 03 AD 5A  |>.".=...<.6.>..Z|
0x4250: 3D DE FF EC 3C 69 64 EA  3D FF 7F 49 3E 19 F1 2E  |=...<id.=..I>...|
0x4260: 3C B7 E0 49 3D F5 2F 04  3E 42 E7 81 3C F9 49 8C  |<..I=./.>B..<.I.|
0x4270: 3E 04 6C 69 3E 7B 8C 2A  3D 26 4C 64 3E 3E C7 B8  |>.li>{.*=&Ld>>..|
0x4280: 3E BE C7 B8 3D 7E 5F 9F  3E 48 40 F7 3E C0 AC C4  |>...=~_.>H@.>...|
0x4290: 3D E2 F9 BD 3E 65 FF 10  3E C6 9F 96 3E 87 10 E6  |=...>e..>...>...|
0x42A0: 3E 8F 86 6D 3E D2 08 BE  3F 0E A7 67 3E 48 81 A6  |>..m>...?..g>H..|
0x42B0: 3E 60 73 53 3F 18 CF 1F  3E 57 70 11 3E 05 52 D8  |>`sS?...>Wp.>.R.|
0x42C0: 3F 75 C2 03 3E 40 72 07  3D A6 4B F9 3F 73 A3 C0  |?u..>@r.=.K.?s..|
0x42D0: 3E 62 22 B0 3D C1 C5 74  3F 73 DB EF 3E 66 AB E7  |>b".=..t?s..>f..|
0x42E0: 3D D1 BF 4B 3F 21 74 EF  3E 9E 20 FE 3E 17 F0 6E  |=..K?!t.>. .>..n|
0x42F0: 3F 01 55 63 3E 81 9A 19  3E 01 1E 1D 3E 58 D9 BF  |?.Uc>...>...>X..|
0x4300: 3E 28 12 88 3D AB B1 31  3D 32 E8 A6 3E 21 03 50  |>(..=..1=2..>!.P|
0x4310: 3D A6 0B 6B 3B F1 84 F9  3D E2 F0 21 3D 87 49 4E  |=..k;...=..!=.IN|
0x4320: 3B E2 9E DE 3D C8 A4 51  3D AA 09 7C 3C 32 08 55  |;...=..Q=..|<2.U|
0x4330: 3D B8 72 31 3D DE 43 C8  3C 84 BD F7 3D BA D3 3F  |=.r1=.C.<...=..?|
0x4340: 3E 14 70 21 3C BD D5 F9  3D C8 53 90 3E 3D CA C5  |>.p!<...=.S.>=..|
0x4350: 3C FA D6 9D 3E 0B A2 AA  3E 8B A2 AA 3D 3A 2E 39  |<...>...>...=:.9|
0x4360: 3E 12 B1 E2 3E 8D 0C 1C  3D A7 73 20 3E 29 02 23  |>...>...=.s >).#|
0x4370: 3E 91 82 8F 3E 49 3E 1A  3E 52 18 E1 3E 99 BA 4F  |>...>I>.>R..>..O|
0x4380: 3E D0 D2 69 3E 0F E1 D9  3E 1C 24 15 3E E2 E6 63  |>..i>...>.$.>..c|
0x4390: 3E 40 AF 16 3D D2 98 25  3F 67 F1 E0 3E 3B 2C 8D  |>@..=..%?g..>;,.|
0x43A0: 3D 99 97 A1 3F 73 67 0D  3E 49 A6 5C 3D A7 78 F1  |=...?sg.>I.\=.x.|
0x43B0: 3F 66 C9 61 3E 20 28 87  3D 92 23 B9 3E DA 74 BC  |?f.a> (.=.#.>.t.|
0x43C0: 3E 67 79 87 3D DE 69 FD  3E BD 52 B6 3E 3E 62 C9  |>gy.=.i.>.R.>>b.|
0x43D0: 3D BD 8A FE 3E 22 3E B3  3D EB 70 93 3D 70 5E 30  |=...>">.=.p.=p^0|
0x43E0: 3D 03 BE 00 3D E0 EF 40  3D 67 F6 BA 3B A8 B3 70  |=...=..@=g..;..p|
0x43F0: 3D A5 4B AC 3D 46 B0 62  3B A7 8D 38 3D 93 A2 45  |=.K.=F.b;..8=..E|
0x4400: 3D 7A 7D F4 3C 03 33 5C  3D 7C FD 8C 3D 98 6E 85  |=z}.<.3\=|..=.n.|
0x4410: 3C 36 12 71 3D 89 7E 24  3D DA 57 C2 3C 8B 99 77  |<6.q=.~$=.W.<..w|
0x4420: 3D 92 11 4B 3E 09 EE 20  3C B6 31 9B 3D C3 11 FA  |=..K>.. <.1.=...|
0x4430: 3E 43 11 FA 3D 02 0B FC  3D CD 93 4E 3E 45 2B D8  |>C..=...=..N>E+.|
0x4440: 3D 70 B3 8E 3D EC 6F A9  3E 4B 57 EA 3E 0D 71 2B  |=p..=.o.>KW.>.q+|
0x4450: 3E 12 C0 A7 3E 56 C1 D8  3E 91 DC 9D 3D C7 B2 CC  |>...>V..>...=...|
0x4460: 3D D3 0A 5C 3E A1 D5 3A  3E 07 F9 C4 3D 8E 16 FE  |=..\>..:>...=...|
0x4470: 3F 26 32 57 3E 38 C7 EB  3D 93 D3 23 3F 73 4B 7F  |?&2W>8..=..#?sK.|
0x4480: 3E 0E 43 C3 3D 6B 58 AF  3F 25 86 60 3D DC DE 20  |>.C.=kX.?%.`=.. |
0x4490: 3D 48 8B E2 3E 9C 35 D9  3E 21 AF 4A 3D 9B 5B 18  |=H..>.5.>!.J=.[.|
0x44A0: 3E 84 3D EB 3E 05 26 78  3D 84 87 3D 3D E4 67 8F  |>.=.>.&x=..==.g.|
0x44B0: 3D A0 7D 3D 3D 23 C5 47  3C BA A4 26 3D 98 FD C8  |=.}==#.G<..&=...|
0x44C0: 3D 1D C5 B7 3B 65 7C AD  3D 65 7A 87 3D 0B 76 01  |=...;e|.=ez.=.v.|
0x44D0: 3B 6D 5F 00 3D 4F B1 0C  3D 30 70 9A 3B B8 F3 04  |;m_.=O..=0p.;...|
0x44E0: 3D 21 B0 72 3D 42 D7 88  3B E8 BA 98 3D 41 78 D2  |=!.r=B..;...=Ax.|
0x44F0: 3D 99 7D 30 3C 44 3C 0C  3D 4B 14 D7 3D BE E5 3D  |=.}0<D<.=K..=..=|
0x4500: 3C 7B F6 3B 3D 84 AD C8  3E 04 AD C8 3C B0 E7 B5  |<{.;=...>...<...|
0x4510: 3D 8C 2D 3D 3E 06 2D AC  3D 27 6E 23 3D A1 92 EC  |=.-=>.-.='n#=...|
0x4520: 3E 0A 75 35 3D C4 68 37  3D C7 A1 56 3E 12 11 B1  |>.u5=.h7=..V>...|
0x4530: 3E 46 6B 22 3D 89 09 27  3D 92 6E F3 3E 5B 9D 5C  |>Fk"=..'=.n.>[.\|
0x4540: 3D B7 87 E2 3D 42 5F 58  3E DF 52 BB 3E 33 DF C7  |=...=B_X>.R.>3..|
0x4550: 3D 8F E6 39 3F 6C D5 93  3D B9 CE 3C 3D 18 9B 4A  |=..9?l..=..<=..J|
0x4560: 3E DE 49 26 3D 91 CD 62  3D 03 E9 31 3E 53 9E 5B  |>.I&=..b=..1>S.[|
0x4570: 3D DB F1 57 3D 53 55 5C  3E 33 E4 1E 3D B5 E2 ED  |=..W=SU\>3..=...|
0x4580: 3D 34 E3 6E 3D 9F 5A 2F  3D 47 2D DA 3C CB 0F BB  |=4.n=.Z/=G-.<...|
0x4590: 3C 78 CC F2 3D 3D 0D 33  3C C2 F5 9D 3B 0D C9 E7  |<x..==.3<...;...|
0x45A0: 3D 15 38 60 3C B8 4D 6C  3B 1E E0 C1 3D 09 80 BB  |=.8`<.Ml;...=...|
0x45B0: 3C EA 11 BB 3B 75 94 05  3C C1 B9 0E 3C E9 71 96  |<...;u..<...<.q.|
0x45C0: 3B 8B 6B 1C 3D 00 21 A8  3D 4B 10 B1 3C 01 C6 EC  |;.k.=.!.=K..<...|
0x45D0: 3D 04 56 65 3D 77 23 0E  3C 22 E9 6E 3D 23 F3 8D  |=.Ve=w#.<".n=#..|
0x45E0: 3D A3 F3 8D 3C 5A 9A 12  3D 2E 14 33 3D A5 FA 15  |=...<Z..=..3=...|
0x45F0: 3C D7 FA 45 3D 48 B0 D0  3D AB 4C 9B 3D 78 24 E5  |<..E=H..=.L.=x$.|
0x4600: 3D 76 AE EC 3D B4 7F 6D  3D F5 2F 9A 3D 2D 0E 89  |=v..=..m=./.=-..|
0x4610: 3D 39 B6 BF 3E 0A 10 16  3D 65 5A 15 3C F7 B4 8C  |=9..>...=eZ.<...|
0x4620: 3E 8A 9D 11 3D DA 45 2C  3D 2E 9D BD 3F 0F B1 CE  |>...=.E,=...?...|
0x4630: 3D 68 6C AC 3C BF 4A 93  3E 89 E9 B3 3D 38 34 04  |=hl.<.J.>...=84.|
0x4640: 3C A6 C6 DA 3E 04 FA BB  3D 87 E4 49 3D 02 92 8E  |<...>...=..I=...|
0x4650: 3D DE 4A A7 3D 61 CA 76  3C E0 59 D3 3D 4A 5A FF  |=.J.=a.v<.Y.=JZ.|
0x4660: 3C D5 B1 3C 3C 59 70 F5  3C 18 42 6A 3C C9 06 C9  |<..<<Yp.<.Bj<...|
0x4670: 3C 4F 4F 00 3A 96 C5 17  3C B0 B7 65 3C 5F C8 86  |<OO.:...<..e<_..|
0x4680: 3A C4 AD 1B 3C A9 31 51  3C 92 D2 92 3B 1B 6F 34  |:...<.1Q<...;.o4|
0x4690: 3C 54 05 CE 3C 7F 7E E5  3B 18 96 A0 3C 9E 34 23  |<T..<.~.;...<.4#|
0x46A0: 3C F7 B3 F1 3B 9D E7 3A  3C 9D 41 19 3D 11 47 31  |<...;..:<.A.=.G1|
0x46B0: 3B BF 2E CD 3C AE 56 1F  3D 2E 56 1F 3B E8 72 D5  |;...<.V.=.V.;.r.|
0x46C0: 3C BB 00 92 3D 30 DE 9D  3C 79 A3 32 3C D6 B9 34  |<...=0..<y.2<..4|
0x46D0: 3D 36 69 F0 3D 07 68 9A  3D 03 27 85 3D 3F EE 4E  |=6i.=.h.=.'.=?.N|
0x46E0: 3D 82 5B B8 3C C0 A8 17  3C CD 1E AD 3D 9A F4 2A  |=.[.<...<...=..*|
0x46F0: 3C FF 99 15 3C 8E 66 39  3E 18 CA 50 3D 68 13 96  |<...<.f9>..P=h..|
0x4700: 3C B9 A9 45 3E 98 C8 A1  3D 01 B8 68 3C 56 3E DD  |<..E>...=..h<V>.|
0x4710: 3E 17 E9 FF 3C CC E8 E2  3C 39 45 01 3D 95 5D 9A  |>...<...<9E.=.].|
0x4720: 3D 10 7F DA 3C 8A D7 DE  3D 6C 5F 3F 3C F1 69 DE  |=...<...=l_?<.i.|
0x4730: 3C 6F 9E 44 3C DE 20 D1  3C 38 48 8C 3B BA C6 BB  |<o.D<. .<8H.;...|
0x4740: 3B A4 B7 18 3C 2A 29 0D  3B AF 7A 55 39 FF 3D 93  |;...<*).;.zU9.=.|
0x4750: 3C 36 D0 6B 3B F6 BC 5E  3A 62 FA 0B 3C 35 01 16  |<6.k;..^:b..<5..|
0x4760: 3C 1E 8C 63 3A A8 90 6C  3B CA 6C 43 3B F3 ED 75  |<..c:..l;.lC;..u|
0x4770: 3A 91 AD FB 3C 29 88 47  3C 83 EE 57 3B 27 FD F0  |:...<).G<..W;'..|
0x4780: 3C 24 25 A6 3C 93 5D F4  3B 40 F4 EA 3C 13 91 7E  |<$%.<.].;@..<..~|
0x4790: 3C 93 91 7E 3B 44 C1 FD  3C 21 B0 FD 3C 96 64 97  |<..~;D..<!..<.d.|
0x47A0: 3B F7 24 3D 3C 37 E4 AD  3C 9A D5 54 3C 70 80 34  |;.$=<7..<..T<p.4|
0x47B0: 3C 5E 08 7C 3C A2 76 17  3C DC AF 78 3C 31 3D AD  |<^.|<.v.<..x<1=.|
0x47C0: 3C 3A 12 DC 3D 10 95 B0  3C 6C 01 D5 3C 0B 2E F9  |<:..=...<l..<...|
0x47D0: 3D 8A 1C B8 3C C4 69 8A  3C 1D 21 3B 3E 01 4E 03  |=...<.i.<.!;>.N.|
0x47E0: 3C 70 4A BF 3B C7 B2 57  3D 89 22 97 3C 3C 42 F9  |<pJ.;..W=.".<<B.|
0x47F0: 3B A9 CD F7 3D 0B 8F 02  3C 74 A0 0B 3B EB 0C BA  |;...=...<t..;...|
0x4800: 3C C8 14 2F 3C 4E 7C 3C  3B CC 89 AE 3C 47 49 A2  |<../<N|<;...<GI.|
0x4810: 3B 82 21 0E 3B 02 E0 18  3B 22 17 60 3B 67 8A CE  |;.!.;...;".`;g..|
0x4820: 3A EE C7 24 39 2D A8 1A  3B 90 C2 10 3B 54 A2 A6  |:..$9-..;...;T..|
0x4830: 39 CE 60 AB 3B 97 7D 2B  3B 8E 0F 46 3A 1B 89 0E  |9.`.;.}+;..F:...|
0x4840: 3B 19 28 73 3B 38 8F BA  39 DC 73 09 3B 8F B0 F2  |;.(s;8..9.s.;...|
0x4850: 3B D5 A4 DF 3A 86 AA DC  3B 83 A3 9A 3B E2 C0 73  |;...:...;...;..s|
0x4860: 3A 93 52 AD 3B 48 CC F2  3B C8 CC F2 3A 85 DD F7  |:.R.;H..;...:...|
0x4870: 3B 65 84 40 3B CE 8B 35  3B 5A 2B DA 3B 80 A5 78  |;e.@;..5;Z+.;..x|
0x4880: 3B D4 19 58 3B B6 3A BD  3B 97 10 43 3B DD 10 DD  |;..X;.:.;..C;...|
0x4890: 3C 16 25 86 3B 79 47 1A  3B 8B 6A B3 3C 3E 24 61  |<.%.;yG.;.j.<>$a|
0x48A0: 3B 99 EB DD 3B 56 30 3D  3C A7 92 05 3B B5 9B B9  |;...;V0=<...;...|
0x48B0: 3B 11 49 60 3C EF 1E 19  3B 6C 6E 92 3A CC 51 EB  |;.I`<...;ln.:.Q.|
0x48C0: 3C 61 AC 18 3B 85 35 60  3A F2 FC 61 3C 36 53 5A  |<a..;.5`:..a<6SZ|
0x48D0: 3B A6 6F 31 3B 1F EB 67  3C 08 20 68 3B 90 04 66  |;.o1;..g<. h;..f|
0x48E0: 3B 0D FC 5E 3B 9A 30 80  3A 40 C3 A9 39 C0 25 C9  |;..^;.0.:@..9.%.|
0x48F0: 3A 1E ED 73 3A 24 0C 5B  39 A9 2C BE 37 F6 12 89  |:..s:$.[9.,.7...|
0x4900: 3A 40 80 77 3A 0D 7E 96  38 89 64 EC 3A 58 99 69  |:@.w:.~.8.d.:X.i|
0x4910: 3A 6E 64 25 39 0A 6B E3  3A 99 28 73 3A B8 8F BA  |:nd%9.k.:.(s:...|
0x4920: 39 5C 73 09 3A 54 3E 3F  3A 8B 30 BE 39 2A 35 2B  |9\s.:T>?:.0.9*5+|
0x4930: 3A 2F 13 D0 3A 96 B9 FA  39 43 D7 95 3A 0E 44 8A  |:/..:...9C..:.D.|
0x4940: 3A 8E 44 8A 39 3D B0 B8  3A 2A FB D8 3A 94 02 CD  |:.D.9=..:*..:...|
0x4950: 3A 46 A9 0D 3A 39 57 7F  3A 96 E1 EE 3A 89 23 BE  |:F..:9W.:...:.#.|
0x4960: 3A 56 0E CD 3A 9C A0 31  3A D4 C2 2D 3A 1D 26 96  |:V..:..1:..-:.&.|
0x4970: 3A 47 6F F4 3A CB 46 24  3A 00 B2 7A 3A 0E 87 BD  |:Go.:.F$:..z:...|
0x4980: 3A C6 88 1F 39 8F 94 85  38 E5 BA 6F 3A BD 0C 16  |:...9...8..o:...|
0x4990: 3A 09 68 CE 39 7A 34 36  3A BE 95 CD 3A 2A 38 13  |:.h.9z46:...:*8.|
0x49A0: 39 9E EF DA 3A BF 5A A9  3A 6B D6 9E 39 E2 9B 5A  |9...:.Z.:k..9..Z|
0x49B0: 3A C0 E4 60 3A 4F 1F 50  39 CB A2 4F 3A 6A 8B E2  |:..`:O.P9..O:j..|
0x49C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x49D0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x49E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x49F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4A00: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4A10: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4A20: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4A30: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4A40: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4A50: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4A60: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4A70: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4A80: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x4A90: 00 00 00 00 00 00 00 00  43 7F 00 00 43 7F 00 00  |........C...C...|
0x4AA0: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4AB0: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4AC0: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4AD0: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4AE0: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4AF0: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4B00: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4B10: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4B20: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4B30: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4B40: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4B50: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4B60: 43 7F 00 00 43 7F 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4B70: 43 7F 00 00 43 78 00 00  43 78 00 00 43 7F 00 00  |C...Cx..Cx..C...|
0x4B80: 43 78 00 00 43 78 00 00  43 7F 00 00 43 7A 00 00  |Cx..Cx..C...Cz..|
0x4B90: 43 78 00 00 43 7F 00 00  43 7B 00 00 43 78 00 00  |Cx..C...C{..Cx..|
0x4BA0: 43 7F 00 00 43 7F 00 00  43 78 00 00 43 7A 00 00  |C...C...Cx..Cz..|
0x4BB0: 43 7F 00 00 43 78 00 00  43 7A 00 00 43 7F 00 00  |C...Cx..Cz..C...|
0x4BC0: 43 78 00 00 43 78 00 00  43 7F 00 00 43 78 00 00  |Cx..Cx..C...Cx..|
0x4BD0: 43 78 00 00 43 7F 00 00  43 7A 00 00 43 78 00 00  |Cx..C...Cz..Cx..|
0x4BE0: 43 7F 00 00 43 7B 00 00  43 78 00 00 43 7F 00 00  |C...C{..Cx..C...|
0x4BF0: 43 7F 00 00 43 78 00 00  43 7B 00 00 43 7F 00 00  |C...Cx..C{..C...|
0x4C00: 43 78 00 00 43 7A 00 00  43 7F 00 00 43 78 00 00  |Cx..Cz..C...Cx..|
0x4C10: 43 78 00 00 43 7F 00 00  43 7A 00 00 43 78 00 00  |Cx..C...Cz..Cx..|
0x4C20: 43 7F 00 00 43 7B 00 00  43 78 00 00 43 7F 00 00  |C...C{..Cx..C...|
0x4C30: 43 7F 00 00 43 78 00 00  43 7F 00 00 43 7F 00 00  |C...Cx..C...C...|
0x4C40: 43 78 00 00 43 7B 00 00  43 7F 00 00 43 67 00 00  |Cx..C{..C...Cg..|
0x4C50: 43 70 00 00 43 7F 00 00  43 67 00 00 43 67 00 00  |Cp..C...Cg..Cg..|
0x4C60: 43 7F 00 00 43 6F 00 00  43 5D 00 00 43 7F 00 00  |C...Co..C]..C...|
0x4C70: 43 77 00 00 43 50 00 00  43 7F 00 00 43 7F 00 00  |Cw..CP..C...C...|
0x4C80: 43 48 00 00 43 78 00 00  43 7F 00 00 43 52 00 00  |CH..Cx..C...CR..|
0x4C90: 43 70 00 00 43 7F 00 00  43 69 00 00 43 67 00 00  |Cp..C...Ci..Cg..|
0x4CA0: 43 7F 00 00 43 67 00 00  43 67 00 00 43 7F 00 00  |C...Cg..Cg..C...|
0x4CB0: 43 6F 00 00 43 67 00 00  43 7F 00 00 43 77 00 00  |Co..Cg..C...Cw..|
0x4CC0: 43 67 00 00 43 7F 00 00  43 7F 00 00 43 6B 00 00  |Cg..C...C...Ck..|
0x4CD0: 43 78 00 00 43 7F 00 00  43 6C 00 00 43 72 00 00  |Cx..C...Cl..Cr..|
0x4CE0: 43 7F 00 00 43 6B 00 00  43 6B 00 00 43 7F 00 00  |C...Ck..Ck..C...|
0x4CF0: 43 74 00 00 43 6C 00 00  43 7F 00 00 43 79 00 00  |Ct..Cl..C...Cy..|
0x4D00: 43 6B 00 00 43 7F 00 00  43 7F 00 00 43 67 00 00  |Ck..C...C...Cg..|
0x4D10: 43 7F 00 00 43 7F 00 00  43 67 00 00 43 78 00 00  |C...C...Cg..Cx..|
0x4D20: 43 7F 00 00 43 51 00 00  43 63 00 00 43 7F 00 00  |C...CQ..Cc..C...|
0x4D30: 43 51 00 00 43 51 00 00  43 7F 00 00 43 60 00 00  |CQ..CQ..C...C`..|
0x4D40: 43 3D 00 00 43 7F 00 00  43 70 00 00 43 26 00 00  |C=..C...Cp..C&..|
0x4D50: 43 7F 00 00 43 7F 00 00  43 16 00 00 43 71 00 00  |C...C...C...Cq..|
0x4D60: 43 7F 00 00 43 2A 00 00  43 63 00 00 43 7F 00 00  |C...C*..Cc..C...|
0x4D70: 43 55 00 00 43 51 00 00  43 7F 00 00 43 51 00 00  |CU..CQ..C...CQ..|
0x4D80: 43 51 00 00 43 7F 00 00  43 60 00 00 43 51 00 00  |CQ..C...C`..CQ..|
0x4D90: 43 7F 00 00 43 70 00 00  43 51 00 00 43 7F 00 00  |C...Cp..CQ..C...|
0x4DA0: 43 7F 00 00 43 59 00 00  43 73 00 00 43 7F 00 00  |C...CY..Cs..C...|
0x4DB0: 43 5C 00 00 43 68 00 00  43 7F 00 00 43 5C 00 00  |C\..Ch..C...C\..|
0x4DC0: 43 5C 00 00 43 7F 00 00  43 6A 00 00 43 5C 00 00  |C\..C...Cj..C\..|
0x4DD0: 43 7F 00 00 43 75 00 00  43 59 00 00 43 7F 00 00  |C...Cu..CY..C...|
0x4DE0: 43 7F 00 00 43 51 00 00  43 7F 00 00 43 7F 00 00  |C...CQ..C...C...|
0x4DF0: 43 51 00 00 43 71 00 00  43 7F 00 00 43 37 00 00  |CQ..Cq..C...C7..|
0x4E00: 43 53 00 00 43 7F 00 00  43 37 00 00 43 37 00 00  |CS..C...C7..C7..|
0x4E10: 43 7F 00 00 43 4F 00 00  43 1B 00 00 43 7F 00 00  |C...CO..C...C...|
0x4E20: 43 67 00 00 42 FE 00 00  43 7F 00 00 43 7F 00 00  |Cg..B...C...C...|
0x4E30: 42 C8 00 00 43 69 00 00  43 7F 00 00 43 00 00 00  |B...Ci..C...C...|
0x4E40: 43 53 00 00 43 7F 00 00  43 3D 00 00 43 37 00 00  |CS..C...C=..C7..|
0x4E50: 43 7F 00 00 43 37 00 00  43 37 00 00 43 7F 00 00  |C...C7..C7..C...|
0x4E60: 43 4F 00 00 43 37 00 00  43 7F 00 00 43 67 00 00  |CO..C7..C...Cg..|
0x4E70: 43 37 00 00 43 7F 00 00  43 7F 00 00 43 44 00 00  |C7..C...C...CD..|
0x4E80: 43 6E 00 00 43 7F 00 00  43 49 00 00 43 5E 00 00  |Cn..C...CI..C^..|
0x4E90: 43 7F 00 00 43 4D 00 00  43 4D 00 00 43 7F 00 00  |C...CM..CM..C...|
0x4EA0: 43 5F 00 00 43 49 00 00  43 7F 00 00 43 6F 00 00  |C_..CI..C...Co..|
0x4EB0: 43 44 00 00 43 7F 00 00  43 7F 00 00 43 37 00 00  |CD..C...C...C7..|
0x4EC0: 43 7F 00 00 43 7F 00 00  43 37 00 00 43 69 00 00  |C...C...C7..Ci..|
0x4ED0: 43 7F 00 00 43 1D 00 00  43 43 00 00 43 7F 00 00  |C...C...CC..C...|
0x4EE0: 43 1D 00 00 43 1D 00 00  43 7F 00 00 43 3E 00 00  |C...C...C...C>..|
0x4EF0: 42 F2 00 00 43 7F 00 00  43 5E 00 00 42 B6 00 00  |B...C...C^..B...|
0x4F00: 43 7F 00 00 43 7F 00 00  42 48 00 00 43 61 00 00  |C...C...BH..Ca..|
0x4F10: 43 7F 00 00 42 AC 00 00  43 43 00 00 43 7F 00 00  |C...B...CC..C...|
0x4F20: 43 25 00 00 43 1D 00 00  43 7F 00 00 43 1D 00 00  |C%..C...C...C...|
0x4F30: 43 1D 00 00 43 7F 00 00  43 3E 00 00 43 1D 00 00  |C...C...C>..C...|
0x4F40: 43 7F 00 00 43 5E 00 00  43 1D 00 00 43 7F 00 00  |C...C^..C...C...|
0x4F50: 43 7F 00 00 43 2F 00 00  43 69 00 00 43 7F 00 00  |C...C/..Ci..C...|
0x4F60: 43 36 00 00 43 54 00 00  43 7F 00 00 43 3E 00 00  |C6..CT..C...C>..|
0x4F70: 43 3E 00 00 43 7F 00 00  43 54 00 00 43 36 00 00  |C>..C...CT..C6..|
0x4F80: 43 7F 00 00 43 69 00 00  43 2F 00 00 43 7F 00 00  |C...Ci..C/..C...|
0x4F90: 43 7F 00 00 43 1D 00 00  43 7F 00 00 43 7F 00 00  |C...C...C...C...|
0x4FA0: 43 1D 00 00 43 61 00 00  43 7F 00 00 43 03 00 00  |C...Ca..C...C...|
0x4FB0: 43 33 00 00 43 7F 00 00  43 03 00 00 43 03 00 00  |C3..C...C...C...|
0x4FC0: 43 7F 00 00 43 2C 00 00  42 AE 00 00 43 7F 00 00  |C...C,..B...C...|
0x4FD0: 43 56 00 00 42 68 00 00  43 7F 00 00 43 7F 00 00  |CV..Bh..C...C...|
0x4FE0: 41 A0 00 00 43 59 00 00  43 7F 00 00 42 30 00 00  |A...CY..C...B0..|
0x4FF0: 43 33 00 00 43 7F 00 00  43 0D 00 00 43 03 00 00  |C3..C...C...C...|
0x5000: 43 7F 00 00 43 03 00 00  43 03 00 00 43 7F 00 00  |C...C...C...C...|
0x5010: 43 2C 00 00 43 03 00 00  43 7F 00 00 43 56 00 00  |C,..C...C...CV..|
0x5020: 43 03 00 00 43 7F 00 00  43 7F 00 00 43 1A 00 00  |C...C...C...C...|
0x5030: 43 64 00 00 43 7F 00 00  43 23 00 00 43 4A 00 00  |Cd..C...C#..CJ..|
0x5040: 43 7F 00 00 43 2F 00 00  43 2F 00 00 43 7F 00 00  |C...C/..C/..C...|
0x5050: 43 48 00 00 43 23 00 00  43 7F 00 00 43 64 00 00  |CH..C#..C...Cd..|
0x5060: 43 1A 00 00 43 7F 00 00  43 7F 00 00 43 03 00 00  |C...C...C...C...|
0x5070: 43 7F 00 00 43 7F 00 00  43 03 00 00 43 59 00 00  |C...C...C...CY..|
0x5080: 43 7F 00 00 42 D4 00 00  43 24 00 00 43 7F 00 00  |C...B...C$..C...|
0x5090: 42 D4 00 00 42 D4 00 00  43 7F 00 00 43 1B 00 00  |B...B...C...C...|
0x50A0: 42 8E 00 00 43 7F 00 00  43 4B 00 00 41 E0 00 00  |B...C...CK..A...|
0x50B0: 43 7F 00 00 43 7F 00 00  00 00 00 00 43 4F 00 00  |C...C.......CO..|
0x50C0: 43 7F 00 00 42 0C 00 00  43 23 00 00 43 7F 00 00  |C...B...C#..C...|
0x50D0: 42 EC 00 00 42 D4 00 00  43 7F 00 00 42 D4 00 00  |B...B...C...B...|
0x50E0: 42 D4 00 00 43 7F 00 00  43 1C 00 00 42 D4 00 00  |B...C...C...B...|
0x50F0: 43 7F 00 00 43 4D 00 00  42 D4 00 00 43 7F 00 00  |C...CM..B...C...|
0x5100: 43 7F 00 00 43 05 00 00  43 5F 00 00 43 7F 00 00  |C...C...C_..C...|
0x5110: 43 11 00 00 43 40 00 00  43 7F 00 00 43 20 00 00  |C...C@..C...C ..|
0x5120: 43 20 00 00 43 7F 00 00  43 3E 00 00 43 11 00 00  |C ..C...C>..C...|
0x5130: 43 7F 00 00 43 5E 00 00  43 05 00 00 43 7F 00 00  |C...C^..C...C...|
0x5140: 43 7F 00 00 42 D4 00 00  43 7F 00 00 43 7F 00 00  |C...B...C...C...|
0x5150: 42 D4 00 00 43 51 00 00  43 7F 00 00 42 A2 00 00  |B...CQ..C...B...|
0x5160: 43 14 00 00 43 7F 00 00  42 A2 00 00 42 A2 00 00  |C...C...B...B...|
0x5170: 43 7F 00 00 43 05 00 00  42 58 00 00 43 7F 00 00  |C...C...BX..C...|
0x5180: 43 3A 00 00 41 00 00 00  43 7A 00 00 43 7A 00 00  |C:..A...Cz..Cz..|
0x5190: 00 00 00 00 43 3E 00 00  43 7F 00 00 41 D8 00 00  |....C>..C...A...|
0x51A0: 43 0F 00 00 43 7F 00 00  42 BE 00 00 42 A2 00 00  |C...C...B...B...|
0x51B0: 43 7F 00 00 42 A2 00 00  42 A2 00 00 43 7F 00 00  |C...B...B...C...|
0x51C0: 43 0B 00 00 42 A2 00 00  43 7F 00 00 43 45 00 00  |C...B...C...CE..|
0x51D0: 42 A2 00 00 43 7F 00 00  43 7F 00 00 42 E0 00 00  |B...C...C...B...|
0x51E0: 43 5A 00 00 43 7F 00 00  42 FE 00 00 43 36 00 00  |CZ..C...B...C6..|
0x51F0: 43 7F 00 00 43 11 00 00  43 11 00 00 43 7F 00 00  |C...C...C...C...|
0x5200: 43 33 00 00 42 FE 00 00  43 7F 00 00 43 59 00 00  |C3..B...C...CY..|
0x5210: 42 E0 00 00 43 7F 00 00  43 7F 00 00 42 A2 00 00  |B...C...C...B...|
0x5220: 43 7F 00 00 43 7F 00 00  42 A2 00 00 43 4A 00 00  |C...C...B...CJ..|
0x5230: 43 7F 00 00 42 5C 00 00  43 04 00 00 43 7F 00 00  |C...B\..C...C...|
0x5240: 42 5C 00 00 42 5C 00 00  43 7F 00 00 42 DE 00 00  |B\..B\..C...B...|
0x5250: 42 14 00 00 43 7C 00 00  43 28 00 00 00 00 00 00  |B...C|..C(......|
0x5260: 43 68 00 00 43 68 00 00  00 00 00 00 43 2D 00 00  |Ch..Ch......C-..|
0x5270: 43 7C 00 00 00 00 00 00  42 F4 00 00 43 7F 00 00  |C|......B...C...|
0x5280: 42 8E 00 00 42 5C 00 00  43 7F 00 00 42 5C 00 00  |B...B\..C...B\..|
0x5290: 42 5C 00 00 43 7F 00 00  42 F4 00 00 42 5C 00 00  |B\..C...B...B\..|
0x52A0: 43 7F 00 00 43 3C 00 00  42 5C 00 00 43 7F 00 00  |C...C<..B\..C...|
0x52B0: 43 7F 00 00 42 B6 00 00  43 55 00 00 43 7F 00 00  |C...B...CU..C...|
0x52C0: 42 D8 00 00 43 2C 00 00  43 7F 00 00 43 02 00 00  |B...C,..C...C...|
0x52D0: 43 02 00 00 43 7F 00 00  43 28 00 00 42 D8 00 00  |C...C...C(..B...|
0x52E0: 43 7F 00 00 43 53 00 00  42 B6 00 00 43 7F 00 00  |C...CS..B...C...|
0x52F0: 43 7F 00 00 42 5C 00 00  43 7F 00 00 43 7F 00 00  |C...B\..C...C...|
0x5300: 42 5C 00 00 43 42 00 00  43 7F 00 00 41 E8 00 00  |B\..CB..C...A...|
0x5310: 42 E8 00 00 43 7F 00 00  41 E8 00 00 41 E8 00 00  |B...C...A...A...|
0x5320: 43 7F 00 00 42 B2 00 00  41 98 00 00 43 6B 00 00  |C...B...A...Ck..|
0x5330: 43 16 00 00 00 00 00 00  43 56 00 00 43 56 00 00  |C.......CV..CV..|
0x5340: 00 00 00 00 43 1C 00 00  43 6B 00 00 00 00 00 00  |....C...Ck......|
0x5350: 42 CA 00 00 43 7F 00 00  42 3C 00 00 41 E8 00 00  |B...C...B<..A...|
0x5360: 43 7F 00 00 41 E8 00 00  41 E8 00 00 43 7F 00 00  |C...A...A...C...|
0x5370: 42 D0 00 00 41 E8 00 00  43 7F 00 00 43 34 00 00  |B...A...C...C4..|
0x5380: 41 E8 00 00 43 7F 00 00  43 7F 00 00 42 8C 00 00  |A...C...C...B...|
0x5390: 43 50 00 00 43 7F 00 00  42 B2 00 00 43 22 00 00  |CP..C...B...C"..|
0x53A0: 43 7F 00 00 42 E6 00 00  42 E6 00 00 43 7F 00 00  |C...B...B...C...|
0x53B0: 43 1C 00 00 42 B2 00 00  43 7F 00 00 43 4E 00 00  |C...B...C...CN..|
0x53C0: 42 8C 00 00 43 7F 00 00  43 7F 00 00 41 E8 00 00  |B...C...C...A...|
0x53D0: 43 7F 00 00 43 7F 00 00  41 E8 00 00 43 3A 00 00  |C...C...A...C:..|
0x53E0: 43 7F 00 00 41 00 00 00  42 CC 00 00 43 7F 00 00  |C...A...B...C...|
0x53F0: 41 00 00 00 41 00 00 00  43 7C 00 00 42 8C 00 00  |A...A...C|..B...|
0x5400: 00 00 00 00 43 5A 00 00  43 05 00 00 00 00 00 00  |....CZ..C.......|
0x5410: 43 44 00 00 43 44 00 00  00 00 00 00 43 0B 00 00  |CD..CD......C...|
0x5420: 43 5A 00 00 00 00 00 00  42 A4 00 00 43 7C 00 00  |CZ......B...C|..|
0x5430: 00 00 00 00 41 00 00 00  43 7F 00 00 41 00 00 00  |....A...C...A...|
0x5440: 41 00 00 00 43 7F 00 00  42 B4 00 00 41 00 00 00  |A...C...B...A...|
0x5450: 43 7F 00 00 43 2D 00 00  41 00 00 00 43 7F 00 00  |C...C-..A...C...|
0x5460: 43 7F 00 00 42 4C 00 00  43 4B 00 00 43 7F 00 00  |C...BL..CK..C...|
0x5470: 42 90 00 00 43 18 00 00  43 7F 00 00 42 C8 00 00  |B...C...C...B...|
0x5480: 42 C8 00 00 43 7F 00 00  43 12 00 00 42 90 00 00  |B...C...C...B...|
0x5490: 43 7F 00 00 43 49 00 00  42 4C 00 00 43 7F 00 00  |C...CI..BL..C...|
0x54A0: 43 7F 00 00 41 00 00 00  43 7F 00 00 43 7F 00 00  |C...A...C...C...|
0x54B0: 41 00 00 00 43 33 00 00  43 7F 00 00 00 00 00 00  |A...C3..C.......|
0x54C0: 42 B4 00 00 43 7F 00 00  00 00 00 00 00 00 00 00  |B...C...........|
0x54D0: 43 69 00 00 42 70 00 00  00 00 00 00 43 49 00 00  |Ci..Bp......CI..|
0x54E0: 42 F0 00 00 00 00 00 00  43 33 00 00 43 33 00 00  |B.......C3..C3..|
0x54F0: 00 00 00 00 42 F6 00 00  43 49 00 00 00 00 00 00  |....B...CI......|
0x5500: 42 82 00 00 43 69 00 00  00 00 00 00 00 00 00 00  |B...Ci..........|
0x5510: 43 7F 00 00 00 00 00 00  00 00 00 00 43 7F 00 00  |C...........C...|
0x5520: 42 AA 00 00 00 00 00 00  43 7F 00 00 43 2A 00 00  |B.......C...C*..|
0x5530: 00 00 00 00 43 7F 00 00  43 7F 00 00 42 0C 00 00  |....C...C...B...|
0x5540: 43 46 00 00 43 7F 00 00  42 68 00 00 43 0E 00 00  |CF..C...Bh..C...|
0x5550: 43 7F 00 00 42 AA 00 00  42 AA 00 00 43 7F 00 00  |C...B...B...C...|
0x5560: 43 0A 00 00 42 68 00 00  43 7F 00 00 43 44 00 00  |C...Bh..C...CD..|
0x5570: 42 0C 00 00 43 7F 00 00  43 7F 00 00 00 00 00 00  |B...C...C.......|
0x5580: 43 7F 00 00 43 7F 00 00  00 00 00 00 43 2D 00 00  |C...C.......C-..|
0x5590: 43 7D 00 00 00 00 00 00  42 A8 00 00 43 7D 00 00  |C}......B...C}..|
0x55A0: 00 00 00 00 00 00 00 00  43 56 00 00 42 5C 00 00  |........CV..B\..|
0x55B0: 00 00 00 00 43 38 00 00  42 DC 00 00 00 00 00 00  |....C8..B.......|
0x55C0: 43 22 00 00 43 22 00 00  00 00 00 00 42 DC 00 00  |C"..C"......B...|
0x55D0: 43 38 00 00 00 00 00 00  42 5C 00 00 43 56 00 00  |C8......B\..CV..|
0x55E0: 00 00 00 00 00 00 00 00  43 7D 00 00 00 00 00 00  |........C}......|
0x55F0: 00 00 00 00 43 7D 00 00  42 A8 00 00 00 00 00 00  |....C}..B.......|
0x5600: 43 7D 00 00 43 29 00 00  00 00 00 00 43 7D 00 00  |C}..C)......C}..|
0x5610: 43 7D 00 00 41 B8 00 00  43 40 00 00 43 7F 00 00  |C}..A...C@..C...|
0x5620: 42 38 00 00 43 03 00 00  43 7F 00 00 42 8C 00 00  |B8..C...C...B...|
0x5630: 42 8C 00 00 43 7F 00 00  43 02 00 00 42 38 00 00  |B...C...C...B8..|
0x5640: 43 7F 00 00 43 3F 00 00  41 B8 00 00 43 7F 00 00  |C...C?..A...C...|
0x5650: 43 7D 00 00 00 00 00 00  43 7D 00 00 43 7D 00 00  |C}......C}..C}..|
0x5660: 00 00 00 00 43 29 00 00  43 6D 00 00 00 00 00 00  |....C)..Cm......|
0x5670: 42 9E 00 00 43 6D 00 00  00 00 00 00 00 00 00 00  |B...Cm..........|
0x5680: 43 43 00 00 42 48 00 00  00 00 00 00 43 27 00 00  |CC..BH......C'..|
0x5690: 42 C8 00 00 00 00 00 00  43 11 00 00 43 11 00 00  |B.......C...C...|
0x56A0: 00 00 00 00 42 C8 00 00  43 27 00 00 00 00 00 00  |....B...C'......|
0x56B0: 42 48 00 00 43 43 00 00  00 00 00 00 00 00 00 00  |BH..CC..........|
0x56C0: 43 6D 00 00 00 00 00 00  00 00 00 00 43 6D 00 00  |Cm..........Cm..|
0x56D0: 42 9E 00 00 00 00 00 00  43 6D 00 00 43 1E 00 00  |B.......Cm..C...|
0x56E0: 00 00 00 00 43 6D 00 00  43 6D 00 00 41 10 00 00  |....Cm..Cm..A...|
0x56F0: 43 30 00 00 43 7F 00 00  42 08 00 00 42 E8 00 00  |C0..C...B...B...|
0x5700: 43 7F 00 00 42 5C 00 00  42 5C 00 00 43 7F 00 00  |C...B\..B\..C...|
0x5710: 42 EA 00 00 42 08 00 00  43 7F 00 00 43 31 00 00  |B...B...C...C1..|
0x5720: 41 10 00 00 43 7F 00 00  43 6D 00 00 00 00 00 00  |A...C...Cm......|
0x5730: 43 6D 00 00 43 6D 00 00  00 00 00 00 43 1E 00 00  |Cm..Cm......C...|
0x5740: 43 57 00 00 00 00 00 00  42 90 00 00 43 57 00 00  |CW......B...CW..|
0x5750: 00 00 00 00 00 00 00 00  43 30 00 00 42 34 00 00  |........C0..B4..|
0x5760: 00 00 00 00 43 17 00 00  42 B4 00 00 00 00 00 00  |....C...B.......|
0x5770: 43 00 00 00 43 00 00 00  00 00 00 00 42 B4 00 00  |C...C.......B...|
0x5780: 43 17 00 00 00 00 00 00  42 34 00 00 43 30 00 00  |C.......B4..C0..|
0x5790: 00 00 00 00 00 00 00 00  43 57 00 00 00 00 00 00  |........CW......|
0x57A0: 00 00 00 00 43 57 00 00  42 90 00 00 00 00 00 00  |....CW..B.......|
0x57B0: 43 57 00 00 43 0F 00 00  00 00 00 00 43 57 00 00  |CW..C.......CW..|
0x57C0: 43 57 00 00 00 00 00 00  43 1D 00 00 43 64 00 00  |CW......C...Cd..|
0x57D0: 41 B0 00 00 42 C4 00 00  43 7F 00 00 42 20 00 00  |A...B...C...B ..|
0x57E0: 42 20 00 00 43 7F 00 00  42 CC 00 00 41 B0 00 00  |B ..C...B...A...|
0x57F0: 43 7F 00 00 43 1F 00 00  00 00 00 00 43 64 00 00  |C...C.......Cd..|
0x5800: 43 57 00 00 00 00 00 00  43 57 00 00 43 57 00 00  |CW......CW..CW..|
0x5810: 00 00 00 00 43 0F 00 00  43 3F 00 00 00 00 00 00  |....C...C?......|
0x5820: 42 80 00 00 43 3F 00 00  00 00 00 00 00 00 00 00  |B...C?..........|
0x5830: 43 1D 00 00 42 20 00 00  00 00 00 00 43 07 00 00  |C...B ......C...|
0x5840: 42 A0 00 00 00 00 00 00  42 E0 00 00 42 E0 00 00  |B.......B...B...|
0x5850: 00 00 00 00 42 A0 00 00  43 07 00 00 00 00 00 00  |....B...C.......|
0x5860: 42 20 00 00 43 1D 00 00  00 00 00 00 00 00 00 00  |B ..C...........|
0x5870: 43 3F 00 00 00 00 00 00  00 00 00 00 43 3F 00 00  |C?..........C?..|
0x5880: 42 80 00 00 00 00 00 00  43 3F 00 00 42 FE 00 00  |B.......C?..B...|
0x5890: 00 00 00 00 43 3F 00 00  43 3F 00 00 00 00 00 00  |....C?..C?......|
0x58A0: 43 08 00 00 43 4B 00 00  41 20 00 00 42 A0 00 00  |C...CK..A ..B...|
0x58B0: 43 7F 00 00 41 C8 00 00  41 C8 00 00 43 7F 00 00  |C...A...A...C...|
0x58C0: 42 AE 00 00 41 20 00 00  43 7F 00 00 43 0B 00 00  |B...A ..C...C...|
0x58D0: 00 00 00 00 43 54 00 00  43 3F 00 00 00 00 00 00  |....CT..C?......|
0x58E0: 43 3F 00 00 43 3F 00 00  00 00 00 00 42 FE 00 00  |C?..C?......B...|
0x58F0: 43 26 00 00 00 00 00 00  42 5C 00 00 43 26 00 00  |C&......B\..C&..|
0x5900: 00 00 00 00 00 00 00 00  43 0A 00 00 42 0C 00 00  |........C...B...|
0x5910: 00 00 00 00 42 EE 00 00  42 8C 00 00 00 00 00 00  |....B...B.......|
0x5920: 42 C0 00 00 42 C0 00 00  00 00 00 00 42 8C 00 00  |B...B.......B...|
0x5930: 42 EE 00 00 00 00 00 00  42 0C 00 00 43 0A 00 00  |B.......B...C...|
0x5940: 00 00 00 00 00 00 00 00  43 26 00 00 00 00 00 00  |........C&......|
0x5950: 00 00 00 00 43 26 00 00  42 5C 00 00 00 00 00 00  |....C&..B\......|
0x5960: 43 26 00 00 42 DE 00 00  00 00 00 00 43 26 00 00  |C&..B.......C&..|
0x5970: 43 26 00 00 00 00 00 00  42 E4 00 00 43 32 00 00  |C&......B...C2..|
0x5980: 00 00 00 00 42 78 00 00  43 79 00 00 41 20 00 00  |....Bx..Cy..A ..|
0x5990: 41 20 00 00 43 7F 00 00  42 8E 00 00 00 00 00 00  |A ..C...B.......|
0x59A0: 43 79 00 00 42 EE 00 00  00 00 00 00 43 32 00 00  |Cy..B.......C2..|
0x59B0: 43 26 00 00 00 00 00 00  43 26 00 00 43 26 00 00  |C&......C&..C&..|
0x59C0: 00 00 00 00 42 DE 00 00  43 0D 00 00 00 00 00 00  |....B...C.......|
0x59D0: 42 3C 00 00 43 0D 00 00  00 00 00 00 00 00 00 00  |B<..C...........|
0x59E0: 42 EE 00 00 41 F0 00 00  00 00 00 00 42 CE 00 00  |B...A.......B...|
0x59F0: 42 70 00 00 00 00 00 00  42 A0 00 00 42 A0 00 00  |Bp......B...B...|
0x5A00: 00 00 00 00 42 70 00 00  42 CE 00 00 00 00 00 00  |....Bp..B.......|
0x5A10: 41 F0 00 00 42 EE 00 00  00 00 00 00 00 00 00 00  |A...B...........|
0x5A20: 43 0D 00 00 00 00 00 00  00 00 00 00 43 0D 00 00  |C...........C...|
0x5A30: 42 3C 00 00 00 00 00 00  43 0D 00 00 42 BC 00 00  |B<......C...B...|
0x5A40: 00 00 00 00 43 0D 00 00  43 0D 00 00 00 00 00 00  |....C...C.......|
0x5A50: 42 BC 00 00 43 19 00 00  00 00 00 00 42 3C 00 00  |B...C.......B<..|
0x5A60: 43 57 00 00 00 00 00 00  00 00 00 00 43 7F 00 00  |CW..........C...|
0x5A70: 42 60 00 00 00 00 00 00  43 57 00 00 42 C4 00 00  |B`......CW..B...|
0x5A80: 00 00 00 00 43 19 00 00  43 0D 00 00 00 00 00 00  |....C...C.......|
0x5A90: 43 0D 00 00 43 0D 00 00  00 00 00 00 42 BC 00 00  |C...C.......B...|
0x5AA0: 42 EC 00 00 00 00 00 00  42 1C 00 00 42 EC 00 00  |B.......B...B...|
0x5AB0: 00 00 00 00 00 00 00 00  42 C8 00 00 41 C8 00 00  |........B...A...|
0x5AC0: 00 00 00 00 42 AE 00 00  42 48 00 00 00 00 00 00  |....B...BH......|
0x5AD0: 42 80 00 00 42 80 00 00  00 00 00 00 42 48 00 00  |B...B.......BH..|
0x5AE0: 42 AE 00 00 00 00 00 00  41 C8 00 00 42 C8 00 00  |B.......A...B...|
0x5AF0: 00 00 00 00 00 00 00 00  42 EC 00 00 00 00 00 00  |........B.......|
0x5B00: 00 00 00 00 42 EC 00 00  42 1C 00 00 00 00 00 00  |....B...B.......|
0x5B10: 42 EC 00 00 42 9E 00 00  00 00 00 00 42 EC 00 00  |B...B.......B...|
0x5B20: 42 EC 00 00 00 00 00 00  42 9E 00 00 43 00 00 00  |B.......B...C...|
0x5B30: 00 00 00 00 42 1C 00 00  43 34 00 00 00 00 00 00  |....B...C4......|
0x5B40: 00 00 00 00 43 7C 00 00  42 1C 00 00 00 00 00 00  |....C|..B.......|
0x5B50: 43 34 00 00 42 9E 00 00  00 00 00 00 43 00 00 00  |C4..B.......C...|
0x5B60: 42 EC 00 00 00 00 00 00  42 EC 00 00 42 EC 00 00  |B.......B...B...|
0x5B70: 00 00 00 00 42 9E 00 00  42 BC 00 00 00 00 00 00  |....B...B.......|
0x5B80: 41 F8 00 00 42 BC 00 00  00 00 00 00 00 00 00 00  |A...B...........|
0x5B90: 42 A2 00 00 41 A0 00 00  00 00 00 00 42 8E 00 00  |B...A.......B...|
0x5BA0: 42 20 00 00 00 00 00 00  42 44 00 00 42 44 00 00  |B ......BD..BD..|
0x5BB0: 00 00 00 00 42 20 00 00  42 8E 00 00 00 00 00 00  |....B ..B.......|
0x5BC0: 41 A0 00 00 42 A2 00 00  00 00 00 00 00 00 00 00  |A...B...........|
0x5BD0: 42 BC 00 00 00 00 00 00  00 00 00 00 42 BC 00 00  |B...........B...|
0x5BE0: 41 F8 00 00 00 00 00 00  42 BC 00 00 42 7C 00 00  |A.......B...B|..|
0x5BF0: 00 00 00 00 42 BC 00 00  42 BC 00 00 00 00 00 00  |....B...B.......|
0x5C00: 42 7C 00 00 42 CE 00 00  00 00 00 00 41 F8 00 00  |B|..B.......A...|
0x5C10: 43 11 00 00 00 00 00 00  00 00 00 00 43 4A 00 00  |C...........CJ..|
0x5C20: 41 F8 00 00 00 00 00 00  43 11 00 00 42 7C 00 00  |A.......C...B|..|
0x5C30: 00 00 00 00 42 CE 00 00  42 BC 00 00 00 00 00 00  |....B...B.......|
0x5C40: 42 BC 00 00 42 BC 00 00  00 00 00 00 42 7C 00 00  |B...B.......B|..|
0x5C50: 42 8A 00 00 00 00 00 00  41 B8 00 00 42 8A 00 00  |B.......A...B...|
0x5C60: 00 00 00 00 00 00 00 00  42 78 00 00 41 70 00 00  |........Bx..Ap..|
0x5C70: 00 00 00 00 42 5C 00 00  41 F8 00 00 00 00 00 00  |....B\..A.......|
0x5C80: 42 0C 00 00 42 0C 00 00  00 00 00 00 41 F8 00 00  |B...B.......A...|
0x5C90: 42 5C 00 00 00 00 00 00  41 70 00 00 42 78 00 00  |B\......Ap..Bx..|
0x5CA0: 00 00 00 00 00 00 00 00  42 8A 00 00 00 00 00 00  |........B.......|
0x5CB0: 00 00 00 00 42 8A 00 00  41 B8 00 00 00 00 00 00  |....B...A.......|
0x5CC0: 42 8A 00 00 42 38 00 00  00 00 00 00 42 8A 00 00  |B...B8......B...|
0x5CD0: 42 8A 00 00 00 00 00 00  42 38 00 00 42 9C 00 00  |B.......B8..B...|
0x5CE0: 00 00 00 00 41 B8 00 00  42 DC 00 00 00 00 00 00  |....A...B.......|
0x5CF0: 00 00 00 00 43 18 00 00  41 B8 00 00 00 00 00 00  |....C...A.......|
0x5D00: 42 DC 00 00 42 38 00 00  00 00 00 00 42 9C 00 00  |B...B8......B...|
0x5D10: 42 8A 00 00 00 00 00 00  42 8A 00 00 42 8A 00 00  |B.......B...B...|
0x5D20: 00 00 00 00 42 38 00 00  42 30 00 00 00 00 00 00  |....B8..B0......|
0x5D30: 41 70 00 00 42 30 00 00  00 00 00 00 00 00 00 00  |Ap..B0..........|
0x5D40: 42 2C 00 00 41 30 00 00  00 00 00 00 42 1C 00 00  |B,..A0......B...|
0x5D50: 41 A8 00 00 00 00 00 00  41 B0 00 00 41 B0 00 00  |A.......A...A...|
0x5D60: 00 00 00 00 41 A8 00 00  42 1C 00 00 00 00 00 00  |....A...B.......|
0x5D70: 41 30 00 00 42 2C 00 00  00 00 00 00 00 00 00 00  |A0..B,..........|
0x5D80: 42 30 00 00 00 00 00 00  00 00 00 00 42 30 00 00  |B0..........B0..|
0x5D90: 41 70 00 00 00 00 00 00  42 30 00 00 41 E8 00 00  |Ap......B0..A...|
0x5DA0: 00 00 00 00 42 30 00 00  42 30 00 00 00 00 00 00  |....B0..B0......|
0x5DB0: 41 E8 00 00 42 54 00 00  00 00 00 00 41 70 00 00  |A...BT......Ap..|
0x5DC0: 42 96 00 00 00 00 00 00  00 00 00 00 42 CC 00 00  |B...........B...|
0x5DD0: 41 70 00 00 00 00 00 00  42 96 00 00 41 E8 00 00  |Ap......B...A...|
0x5DE0: 00 00 00 00 42 54 00 00  42 30 00 00 00 00 00 00  |....BT..B0......|
0x5DF0: 42 30 00 00 42 30 00 00  00 00 00 00 41 E8 00 00  |B0..B0......A...|
0x5E00: 41 B8 00 00 00 00 00 00  41 00 00 00 41 B8 00 00  |A.......A...A...|
0x5E10: 00 00 00 00 00 00 00 00  41 C0 00 00 40 C0 00 00  |........A...@...|
0x5E20: 00 00 00 00 41 B0 00 00  41 40 00 00 00 00 00 00  |....A...A@......|
0x5E30: 41 20 00 00 41 20 00 00  00 00 00 00 41 40 00 00  |A ..A ......A@..|
0x5E40: 41 B0 00 00 00 00 00 00  40 C0 00 00 41 C0 00 00  |A.......@...A...|
0x5E50: 00 00 00 00 00 00 00 00  41 B8 00 00 00 00 00 00  |........A.......|
0x5E60: 00 00 00 00 41 B8 00 00  41 00 00 00 00 00 00 00  |....A...A.......|
0x5E70: 41 B8 00 00 41 70 00 00  00 00 00 00 41 B8 00 00  |A...Ap......A...|
0x5E80: 41 B8 00 00 00 00 00 00  41 70 00 00 41 E0 00 00  |A.......Ap..A...|
0x5E90: 00 00 00 00 41 00 00 00  42 20 00 00 00 00 00 00  |....A...B ......|
0x5EA0: 00 00 00 00 42 44 00 00  41 00 00 00 00 00 00 00  |....BD..A.......|
0x5EB0: 42 00 00 00 41 70 00 00  00 00 00 00 41 E0 00 00  |B...Ap......A...|
0x5EC0: 41 B8 00 00 00 00 00 00  41 B8 00 00 41 B8 00 00  |A.......A...A...|
0x5ED0: 00 00 00 00 41 70 00 00  40 A0 00 00 00 00 00 00  |....Ap..@.......|
0x5EE0: 40 00 00 00 40 A0 00 00  00 00 00 00 00 00 00 00  |@...@...........|
0x5EF0: 40 A0 00 00 3F 80 00 00  00 00 00 00 40 80 00 00  |@...?.......@...|
0x5F00: 40 40 00 00 00 00 00 00  40 A0 00 00 40 A0 00 00  |@@......@...@...|
0x5F10: 00 00 00 00 40 40 00 00  40 80 00 00 00 00 00 00  |....@@..@.......|
0x5F20: 3F 80 00 00 40 A0 00 00  00 00 00 00 00 00 00 00  |?...@...........|
0x5F30: 40 A0 00 00 00 00 00 00  00 00 00 00 40 A0 00 00  |@...........@...|
0x5F40: 40 00 00 00 00 00 00 00  40 A0 00 00 40 40 00 00  |@.......@...@@..|
0x5F50: 00 00 00 00 40 A0 00 00  40 A0 00 00 00 00 00 00  |....@...@.......|
0x5F60: 40 40 00 00 40 A0 00 00  00 00 00 00 40 00 00 00  |@@..@.......@...|
0x5F70: 40 A0 00 00 00 00 00 00  00 00 00 00 40 A0 00 00  |@...........@...|
0x5F80: 40 00 00 00 00 00 00 00  40 A0 00 00 40 40 00 00  |@.......@...@@..|
0x5F90: 00 00 00 00 40 A0 00 00  40 A0 00 00 00 00 00 00  |....@...@.......|
0x5FA0: 40 A0 00 00 40 A0 00 00  00 00 00 00 40 40 00 00  |@...@.......@@..|
0x5FB0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x5FC0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x5FD0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x5FE0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x5FF0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x6000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x6010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x6020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x6030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x6040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x6050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x6060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x6070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x6080: 00 00 00 00 00 00 00 00                           |........|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 0**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/sRGB_D65_MAT.icc

Device Class: 0x6D6E7472

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
=== Extracting LUT data as text from: /home/h02332/po/research/test-profiles/sRGB_D65_MAT.icc ===

--- AToB1Tag (MPE: 2 elements) ---
  Channels: in=3 out=3
  Wrote MPE CurveSet[0]: /tmp/tmp.LEnhTJYuUR/sRGB_D65_MAT__AToB1Tag_mpe0_curves.txt (3 ch × 4096 samples)
  Wrote MPE Matrix[1]: /tmp/tmp.LEnhTJYuUR/sRGB_D65_MAT__AToB1Tag_mpe1_matrix.txt (3x3)

--- BToA1Tag (MPE: 2 elements) ---
  Channels: in=3 out=3
  Wrote MPE Matrix[0]: /tmp/tmp.LEnhTJYuUR/sRGB_D65_MAT__BToA1Tag_mpe0_matrix.txt (3x3)
  Wrote MPE CurveSet[1]: /tmp/tmp.LEnhTJYuUR/sRGB_D65_MAT__BToA1Tag_mpe1_curves.txt (3 ch × 4096 samples)

--- customToStandardPccTag (MPE: 1 elements) ---
  Channels: in=3 out=3
  Wrote MPE Matrix[0]: /tmp/tmp.LEnhTJYuUR/sRGB_D65_MAT__customToStandardPccTag_mpe0_matrix.txt (3x3)

--- standardToCustomPccTag (MPE: 1 elements) ---
  Channels: in=3 out=3
  Wrote MPE Matrix[0]: /tmp/tmp.LEnhTJYuUR/sRGB_D65_MAT__standardToCustomPccTag_mpe0_matrix.txt (3x3)

=== Exported 6 LUT component(s) ===
Exported 6 text file(s) to /tmp/tmp.LEnhTJYuUR/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
