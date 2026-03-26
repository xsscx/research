# ICC Profile Analysis Report

**Profile**: `test-profiles/hbo-CIccCalculatorFunc-InitSelectOp-IccMpeCalc_cpp-Line3663.icc`
**File Size**: 11727 bytes
**SHA-256**: `4f736b7a7633d8383d510c03519842e01d59df0139974a11a1b022859f0bd1ff`
**File Type**: color profile 5.0, RGB/XYZ-spac device by ICC, 11236 bytes, 17-2-2026 8:38:12, relative colorimetric, 0x6ac2323e93276f5a MD5 'sRGB calc tester'
**Date**: 2026-03-26T16:57:50Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 0 | Clean |
| `-xt` (LUT text export) | 2 | Error |
| `-cube` (cube export) | 1 | No 3D CLUT |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 1**

```

=======================================================================
  ICC PROFILE CONFORMANCE AUDIT
=======================================================================

File: /home/h02332/po/research/test-profiles/hbo-CIccCalculatorFunc-InitSelectOp-IccMpeCalc_cpp-Line3663.icc

[H173] Signature Conversion Shift Overflow (IccUtil.cpp signature formatting helpers)
      [WARN]  HEURISTIC: 12/12 FourCC signatures trigger UBSAN shift overflow in icGetSig()/icGetSigStr()/icGetColorSig()/icGetColorSigStr() — IccUtil.cpp:1088,1130,1167,1187,1228,1253
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

  [NON-COMPLIANT] Bad Header File Size
  [NON-COMPLIANT] Bad Profile ID
  [NON-COMPLIANT] BToA1Tag Unknown NULL: Invalid tag type (Might be critical!).
  [NON-COMPLIANT] mediaWhitePointTag Unknown '????' = 3F800000: Invalid tag type (Might be critical!).
  [NON-COMPLIANT] copyrightTag Unknown NULL: Invalid tag type (Might be critical!).
  [ERROR] AToB1Tag>multiProcessElementType>Calculator Element: - Contains unknown processing element type ('case' = 63617365).
  [ERROR] AToB1Tag>multiProcessElementType>Calculator Element: - Contains unknown processing element type ('@???' = 40000000).
  [ERROR] AToB1Tag>multiProcessElementType>Calculator Element: - Contains unknown processing element type ('pop ' = 706F7020).
  [ERROR] AToB1Tag>multiProcessElementType>Calculator Element: - Contains unknown processing element type ('A???' = 41D80000).
  [ERROR] AToB1Tag>multiProcessElementType>Calculator Element: - Contains unknown processing element type ('sum ' = 73756D20).
  [ERROR] AToB1Tag>multiProcessElementType>Calculator Element: - Contains unknown processing element type ('B???' = 42B80000).
  [ERROR] AToB1Tag>multiProcessElementType>Calculator Element: - Contains unknown processing element type ('out ' = 6F757420).
  [ERROR] AToB1Tag>multiProcessElementType>Calculator Element: - Contains unknown processing element type (NULL).
  [ERROR] AToB1Tag>multiProcessElementType>Calculator Element: - Contains unknown processing element type ('parf' = 70617266).
  Invalid Operation (curv(0))
  [ERROR] AToB1Tag>multiProcessElementType>Calculator Element: function has invalid operations.

  Validation Summary: 10 error(s), 5 non-compliant, 0 warning(s), 0 info
  [WARN] 15 ICC spec conformance issue(s) detected


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
         illuminant X=0.9642, Y=1.0000, Z=0.8249
         expected   X=0.9642, Y=1.0000, Z=0.8249 (D50)
         [OK] PCS illuminant matches D50
      [OK] Conformant

[H1009] CF-009: Chromatic Adaptation Tag Requirement
[CF-009] Chromatic Adaptation Tag Requirement (ICC.1-2022-05 §8.2)
         Illuminant is D50, chad tag not required
         [OK] Chromatic adaptation tag conformant
      [OK] Conformant

[H1010] CF-010: Profile Size vs File Size
[CF-010] Profile Size vs File Size (ICC.1-2022-05 §7.2.2)
         Header size: 11236 bytes, File size: 11727 bytes
         Size mismatch: header=11236, file=11727
         [FAIL] Profile size must match file size — ICC.1-2022-05 §7.2.2
      [WARN]  1 non-conformance(s)

[H1011] CF-011: Profile ID MD5 Verification
[CF-011] Profile ID MD5 Verification (ICC.1-2022-05 §7.2.18)
         Stored:   6ac2323e93276f5ae1e3759c3a698f54
         Computed: 88deca4bb5bdc343f1a1c73028e54dcb
         [WARN] Profile ID MD5 mismatch — ICC.1-2022-05 §7.2.18
      [WARN]  1 non-conformance(s)

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
         mediaWhitePointTag is not valid XYZ type
      [OK] Conformant

[H1122] CF-122: Profile Date/Time Plausibility
  [CF-122] Profile Date/Time Plausibility (ICC.1-2022-05 §7.2.8)
         [OK] Profile date/time is plausible
      [OK] Conformant

[H1184] CF-184: Profile ID v4+ Presence
[CF-184] Profile ID v4+ Presence (ICC.1-2022-05 §7.2.18, RFC 1321)
         Profile version: 5.x
         Profile ID: 6ac2323e93276f5ae1e3759c3a698f54
         [OK] v4+ profile has computed Profile ID
      [OK] Conformant

[H1185] CF-185: Profile ID Size Consistency
[CF-185] Profile ID Size Consistency (ICC.1-2022-05 §7.2.18, RFC 1321 §3.1)
         Header-declared size: 11236 bytes
         Actual file size: 11727 bytes
         Size mismatch: MD5 computed over 11236 bytes, file is 11727 bytes
         [WARN] Profile ID MD5 input length inconsistent — §7.2.18 + RFC 1321 §3.1
      [WARN]  1 non-conformance(s)

[H1186] CF-186: Profile ID Entropy Analysis
[CF-186] Profile ID Entropy Analysis (RFC 1321, ICC.1-2022-05 §7.2.18)
         Profile ID: 6ac2323e93276f5ae1e3759c3a698f54
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
         Profile size: 11236 bytes (JPEG limit: 16707345 bytes)
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
         Tag 'B2A1' (BToA1Tag): type '' — not in allowed set {'mBA ', 'mft1', 'mft2'}
         [FAIL] Type violation — ICC.1-2022-05 §9.2
         Tag 'wtpt' (mediaWhitePointTag): type '?�' — not in allowed set {'XYZ '}
         [FAIL] Type violation — ICC.1-2022-05 §9.2
         Tag 'cprt' (copyrightTag): type '' — not in allowed set {'mluc', 'text'}
         [FAIL] Type violation — ICC.1-2022-05 §9.2
         Summary: 5/5 tags checked, 4 type violation(s)
      [WARN]  4 non-conformance(s)

[H1021] CF-021: Tag Type Reserved Bytes Zero
[CF-021] Tag Type Reserved Bytes Zero (ICC.1-2022-05 §10)
         Tag 'wtpt' at offset 11096: reserved bytes = BF 80 00 00 — must be zero
         [FAIL] Tag type reserved bytes non-zero — ICC.1-2022-05 §10
         Summary: 5/5 tags checked, 1 violation(s)
      [WARN]  1 non-conformance(s)

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
         [OK] 1 mluc tag(s) checked, all structurally valid
      [OK] Conformant

[H1031] CF-031: s15Fixed16ArrayType Element Count
[CF-031] s15Fixed16ArrayType Element Count (ICC.1-2022-05 §10.18)
         No s15Fixed16ArrayType tags found
         [OK] 0 sf32 tag(s) checked, all element counts valid
      [OK] Conformant

[H1032] CF-032: XYZType Triplet Count
[CF-032] XYZType Triplet Count (ICC.1-2022-05 §10.23)
         No single-value XYZ tags found
         [OK] 0 XYZ tag(s) checked, all contain exactly 1 triplet
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
         No XYZ tags to validate
      [OK] Conformant

[H1169] CF-169: Negative PCSXYZ Encoding Capability
  [CF-169] Negative PCSXYZ Encoding Capability (ICC TN Negative PCSXYZ §6.3.4.2)
         No XYZ tags to validate
      [OK] Conformant

[H1170] CF-170: Chromatic Adaptation Negative XYZ Consistency
  [CF-170] Chromatic Adaptation Negative XYZ Consistency (ICC TN Negative PCSXYZ, §9.2.10)
         Matrix column tags not all present — check not applicable
      [OK] Conformant

[H1171] CF-171: White Point Non-Negative Luminance
  [CF-171] White Point Non-Negative Luminance (ICC TN Negative PCSXYZ, §3.1.24)
         No white point tags present
      [OK] Conformant

[H1172] CF-172: Colorant XYZ Sum White Point Consistency
  [CF-172] Colorant XYZ Sum White Point Consistency (ICC TN Negative PCSXYZ, §9.2.7)
         Not all matrix columns present — check not applicable
      [OK] Conformant

[H1173] CF-173: PCS XYZ Absorber Encoding
  [CF-173] PCS XYZ Absorber Encoding (ICC TN Negative PCSXYZ, §6.4.3)
         No white point or luminance tags present
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
         Swept 5 tags: 4 OK, 0 warnings, 1 errors
      [WARN]  1 non-conformance(s)

[H1189] CF-189: Tag Type Recognition Coverage
  [CF-189] Tag Type Recognition Coverage (SampleICC §3 CheckTagTypes)
         Tag 'B2A1': unrecognized type '' → CIccTagUnknown
         Tag 'wtpt': unrecognized type '?�' → CIccTagUnknown
         Tag 'cprt': unrecognized type '' → CIccTagUnknown
         2/5 tags have recognized type signatures
      [WARN]  3 non-conformance(s)

[H1190] CF-190: Profile Legibility Gate
  [CF-190] Profile Legibility Gate (SampleICC §3 ReadValidate)
         File has 491 bytes trailing data beyond header size 11236
         [OK] Profile is legible: 5 tags parsed, all non-NULL
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
         [OK] 1 mluc tag(s) checked, all reserved fields zero
      [OK] Conformant

[H1225] CF-225: mluc Name Record String Alignment
[CF-225] mluc Name Record String Alignment (ICC.1-2022-05 §7.1, §10.13)
         [OK] 1 mluc tag(s) checked, all strings properly aligned
      [OK] Conformant

[H1226] CF-226: mluc Size Inference Safety
[CF-226] mluc Size Inference Safety (ICC TN PSD §size)
         [OK] 1 mluc tag(s) checked, sizes consistent with records
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
         Profile creation: 2026-02-17 08:38:12 (UTC)
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
         [WARN] v4+ copyrightTag type 0x00000000, expected multiLocalizedUnicodeType (0x6D6C7563) — ICC.1-2022-05 §9.2.14
      [WARN]  1 non-conformance(s)

[H1276] CF-276: profileDescriptionTag Must Be mluc for v4+
[CF-276] profileDescriptionTag Must Be mluc for v4+ (ICC.1-2022-05 §9.2.44)
         [OK] profileDescriptionTag is mluc for v4+
      [OK] Conformant

[H1277] CF-277: mediaWhitePointTag Must Be XYZType
[CF-277] mediaWhitePointTag Must Be XYZType (ICC.1-2022-05 §9.2.35)
         [WARN] mediaWhitePointTag type 0x3F800000, expected XYZType (0x58595A20) — ICC.1-2022-05 §9.2.35
      [WARN]  1 non-conformance(s)

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
         Illuminant is D50, chad not required
         [OK] All common required tags present
      [OK] Conformant

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
           [INFO] 2 non-required tag(s) present
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
           Distinct data regions: 5
           Data coverage: 11042 / 11236 bytes (98.3%)
           Inter-region gaps: 0 (largest: 0 bytes)
           [OK] Tag data region layout conformant
      [OK] Conformant

[H1207] CF-207: mediaWhitePointTag Value Range
[CF-207] mediaWhitePointTag Value Range (ICC.1-2022-05 §10.27)
         wtpt tag is not XYZType or has no entries
         [FAIL] mediaWhitePointTag must be XYZType — ICC.1-2022-05 §10.27
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
         Scanned 1 MPE tag(s), 1 element(s) total
         [OK] All 1 MPE element signatures recognized
      [OK] Conformant

[H1088] CF-088: Calculator Stack Structure
[CF-088] Calculator Element Stack Structure (ICC.2-2023 §10.x)
         Tag 'A2B1' element 0: Calculator in=3 out=3
         Found 1 calculator element(s)
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
         [OK] 1 calculator(s), 1 total sub-elements
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
         Neither c2sp nor s2cp present — check not applicable
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
         No PCC tags (c2sp/s2cp) — complete adaptation check not applicable
         [OK] Skipped (no PCC tags)
      [OK] Conformant

[H1181] CF-181: PCC Illuminant-Chad Consistency
[CF-181] PCC Illuminant-Chad Consistency (ICC TN Partial Adaptation)
         No spectralViewingConditionsTag — not applicable
         [OK] Skipped (no spectral viewing conditions)
      [OK] Conformant

[H1182] CF-182: PCC Observer Standard
[CF-182] PCC Observer Standard Compliance (ICC TN Partial Adaptation)
         No spectralViewingConditionsTag — not applicable
         [OK] Skipped (no spectral viewing conditions)
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
         No spectralViewingConditionsTag — not applicable
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
         [OK] MPE container channels match first/last elements (1 tags)
      [OK] Conformant

[H1294] CF-294: MPE ACS Boundary Element Pairing
  [CF-294] MPE ACS Boundary Element Pairing (ICC.2-2023 §10.2.1-2)
         No MPE tags with ACS elements — not applicable
      [OK] Conformant

[H1295] CF-295: MPE Element Type Version Compatibility
  [CF-295] MPE Element Type Version Compatibility (ICC.2-2023 §10.2.17)
         [OK] All 1 MPE elements version-compatible with v5
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
         No Matrix elements — not applicable
      [OK] Conformant

[H1299] CF-299: MPE CLUT Element Grid Dimension
  [CF-299] MPE CLUT Element Grid Dimension (ICC.2-2023 §10.2.3)
         No CLUT/ExtCLUT elements — not applicable
      [OK] Conformant

[H1300] CF-300: MPE Tag vs Color Space Channels
  [CF-300] MPE Tag vs Color Space Channel Consistency (ICC.2-2023 §10.2.17)
         [OK] 1 MPE AToB/BToA tags have correct channel counts
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
         [WARN] copyrightTag type 0x00000000 — errata §10.2.5 requires multiLocalizedUnicodeType ('mluc') in v5
         NOTE: ICC.2-2019 originally used 'multiLocalizedType' in Tables 40/41.
         The errata corrects this to 'multiLocalizedUnicodeType' (there is no distinct
         'multiLocalizedType' in the tag type registry).
      [WARN]  1 non-conformance(s)

[H1305] CF-305: multiProcessElementsType Nomenclature Audit
  [CF-305] multiProcessElementsType Nomenclature Audit (ICC.2-2019 Errata Tech.Err.#3)
         Found 1 tag(s) using multiProcessElementsType ('mpet')
         NOTE: iccDEV implementation uses singular name 'icSigMultiProcessElementType'
         and class 'CIccTagMultiProcessElement'. The ICC.2-2019 errata (March 2021)
         corrected 80 instances of 'multiProcessElementType' (singular) to
         'multiProcessElementsType' (plural). Binary signature 'mpet' is unchanged.
         [OK] All 1 tag(s) correctly typed
      [OK] Conformant

[H1306] CF-306: Embedded Image Data Length Cross-Validation
  [CF-306] Embedded Image Data Length Cross-Validation (ICC.2-2019 Errata §10.2.6/10.2.7)
         No embedded image tags — not applicable
      [OK] Conformant

[H1307] CF-307: Calculator Vector-Or Signature Validation
  [CF-307] Calculator Vector-Or Signature Validation (ICC.2-2019 Errata §11.2.1.9)
         Calculator element in tag 0x41324231 — vector-or must use 'vor ' (0x766F7220) per errata
         NOTE: ICC.2-2019 §11.2.1.9 originally defined 'vor' (766f7200h).
         September 2021 errata corrects to 'vor ' (766f7220h) with trailing space.
         iccDEV implements 0x766F7220 (correct). Both implementations may exist
         in the wild — check binary profiles for stale encoding.
         [OK] 1 calculator element(s) audited for vector-or errata compliance
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
         [INFO] 1 'solv' operator(s) found in 1 calculator element(s)
         Profile requires CMM with IIccMatrixSolver support (K.2.8)
      [OK] Conformant

[H1322] CF-322: Calculator 'solv' Status Handling
  [CF-322] Calculator 'solv' Status Handling (K.2.8)
         [OK] All 1 'solv' operator(s) have subsequent status check
      [OK] Conformant

[H1323] CF-323: Calculator 'solv' Matrix Dimensions
  [CF-323] Calculator 'solv' Matrix Dimensions (K.2.8, §11.2.1.7)
         [OK] 1 'solv' operator(s) with valid dimensions
      [OK] Conformant

[H1324] CF-324: Calculator 'env' Operator Usage
  [CF-324] Calculator 'env' Operator Usage (K.2.7, ICC.2 §11.2.1.4)
         [OK] 1 calculator element(s), no 'env' operators (no CMM environment variable dependency)
      [OK] Conformant

[H1325] CF-325: Calculator 'env' Status Handling
  [CF-325] Calculator 'env' Status Handling (K.2.7)
         No variable 'env' operators (excluding constants) — check not applicable
      [OK] Conformant

[H1326] CF-326: Calculator 'env' Reserved Signatures
  [CF-326] Calculator 'env' Reserved Signatures (K.2.7, §11.2.1.4)
         [OK] No reserved env signatures ('true'/'ndef') used
      [OK] Conformant

[H1327] CF-327: PCC Alternate Override Readiness
  [CF-327] PCC Alternate Override Readiness (K.2.6, §6.3.2)
         No PCC tags and no spectral PCS — standard D50/2° PCS
         Alternate PCC override not applicable (standard processing)
         [OK] Standard PCC (no override needed)
      [OK] Conformant

[H1328] CF-328: PCC Non-Standard Colorimetry Indication
  [CF-328] PCC Non-Standard Colorimetry Indication (K.2.6, §6.3.2)
         No custom colorimetry transforms (c2sp/s2cp) — check not applicable
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


Deep Conformance Summary: 18 issue(s)

=======================================================================
PHASE 3: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/hbo-CIccCalculatorFunc-InitSelectOp-IccMpeCalc_cpp-Line3663.icc

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
2    BToA1Tag     'B2A1    '  Unknown NULL bad-type
3    mediaWhitePointTag 'wtpt    '  Unknown '????' = 3F800000 bad-type
4    copyrightTag 'cprt    '  Unknown NULL bad-type

Summary: 3 signature issue(s) detected

=======================================================================
PHASE 5: PROFILE STRUCTURE DUMP
=======================================================================

=== ICC Profile Header ===

=== ICC Profile Header (0x0000-0x007F) ===
0x0000: 00 00 2B E4 00 00 00 00  05 00 00 00 73 70 61 63  |..+.........spac|
0x0010: 52 47 42 20 58 59 5A 20  07 EA 00 02 00 11 00 08  |RGB XYZ ........|
0x0020: 00 26 00 0C 61 63 73 70  00 00 00 00 00 00 00 00  |.&..acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 49 43 43 20 6A C2 32 3E  93 27 6F 5A E1 E3 75 9C  |ICC j.2>.'oZ..u.|
0x0060: 3A 69 8F 54 00 00 00 00  00 00 00 00 00 00 00 00  |:i.T............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields:
  Size:              0x00002BE4 (11236 bytes)
  CMM Type:          '....' (0x00000000)
  Version:           5.0.0.0 (0x05000000)
  Device Class:      ColorSpaceClass
  Color Space:       RgbData (3 channels)
  PCS:               XYZData
  Date/Time:         2026-02-17 08:38:12
  Magic:             0x61637370 [OK]
  Platform:          Unknown
  Profile Flags:     0x00000000
  Manufacturer:      '....' (0x00000000)
  Model:             '....' (0x00000000)
  Device Attribs:    0x0000000000000000
  Rendering Intent:  Relative Colorimetric (1)
  PCS Illuminant:    X=0.9642 Y=1.0000 Z=0.8249
  Creator:           'ICC ' (0x49434320)
  Profile ID:        6ac2323e93276f5ae1e3759c3a698f54

  --- ICC v5/iccMAX Extended Header ---
  Spectral PCS:      NoSpectralData
  Spectral Range:    Not Defined
  BiSpectral Range:  Not Defined
  MCS Color Space:   Not Defined

=== Tag Table ===

=== Tag Table ===
Tag Count: 5

Tag Table Raw Data (0x0080-0x00C0):
0x0080: 00 00 00 05 64 65 73 63  00 00 00 C0 00 00 00 3E  |....desc.......>|
0x0090: 41 32 42 31 00 00 01 00  00 00 29 00 42 32 41 31  |A2B1......).B2A1|
0x00A0: 00 00 2A 00 00 00 01 58  77 74 70 74 00 00 2B 58  |..*....Xwtpt..+X|
0x00B0: 00 00 00 14 63 70 72 74  00 00 2B 6C 00 00 00 78  |....cprt..+l...x|

Tag Entries:
Idx  Signature    FourCC       Offset     Size
---  ------------ ------------ ---------- ----
0    profileDescriptionTag 'desc      '  0x000000C0  62
1    AToB1Tag     'A2B1      '  0x00000100  10496
2    BToA1Tag     'B2A1      '  0x00002A00  344
3    mediaWhitePointTag 'wtpt      '  0x00002B58  20
4    copyrightTag 'cprt      '  0x00002B6C  120

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

--- 5C: TRC Curve Analysis ---

  No TRC curve tags found

--- 5D: NamedColor2 Validation ---

  No NamedColor2 tag

--- 5E: XYZ Tag Values ---

  No XYZ colorant/white-point tags

--- 5F: ICC v5 Spectral Data ---

  No ICC v5 spectral tags

--- 5G: Profile ID Verification ---

  Profile ID (header):   6ac2323e93276f5ae1e3759c3a698f54
  Profile ID (computed): 88deca4bb5bdc343f1a1c73028e54dcb
  [WARN] Profile ID MISMATCH — possible tampering or corruption

--- 5H: Per-Tag Size Analysis ---

  Tag sizes (flagging >10MB):
      [OK] All tags within 10MB limit

--- 5I: V5/iccMAX Summary ---

  --- V5/iccMAX Profile Summary ---

  BRDF Tags:              0 of 16 present
  Gamut Boundary Desc:    gbd0=---  gbd1=---

  MPE Tags:               1 (multiProcessElementsType)
  Total MPE Elements:     1
  Calculator Elements:    1
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

File: /home/h02332/po/research/test-profiles/hbo-CIccCalculatorFunc-InitSelectOp-IccMpeCalc_cpp-Line3663.icc
Mode: Conformance (ICC specification audit)
Total Issues Detected: 35

[WARN] ANALYSIS COMPLETE - 35 issue(s) detected
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

File: /home/h02332/po/research/test-profiles/hbo-CIccCalculatorFunc-InitSelectOp-IccMpeCalc_cpp-Line3663.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 11727 bytes (0x2DCF)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 2B E4 00 00 00 00  05 00 00 00 73 70 61 63  |..+.........spac|
0x0010: 52 47 42 20 58 59 5A 20  07 EA 00 02 00 11 00 08  |RGB XYZ ........|
0x0020: 00 26 00 0C 61 63 73 70  00 00 00 00 00 00 00 00  |.&..acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 49 43 43 20 6A C2 32 3E  93 27 6F 5A E1 E3 75 9C  |ICC j.2>.'oZ..u.|
0x0060: 3A 69 8F 54 00 00 00 00  00 00 00 00 00 00 00 00  |:i.T............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

Header Fields (RAW - no validation):
  Profile Size:    0x00002BE4 (11236 bytes) MISMATCH
  CMM:             0x00000000  '....'
  Version:         0x05000000  (5.0.0)
  Device Class:    0x73706163  'spac'
  Color Space:     0x52474220  'RGB '
  PCS:             0x58595A20  'XYZ '
  Date/Time:       2026-02-17 08:38:12
  Magic:           0x61637370  [OK 'acsp']
  Platform:        0x00000000  '....'
  Flags:           0x00000000
  Manufacturer:    0x00000000  '....'
  Model:           0x00000000  '....'
  Dev Attributes:  0x0000000000000000
  Rendering Intent:0x00000001  Relative Colorimetric
  PCS Illuminant:  X=0.9642 Y=1.0000 Z=0.8249
  Creator:         0x49434320  'ICC '
  Profile ID:      6ac2323e93276f5ae1e3759c3a698f54
  Reserved 100-127: all zeros [OK]

  --- V5/iccMAX Extended Header ---
  Spectral PCS:    0x58595A20  'XYZ '
  Spectral Range:  Not defined

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 5 (0x00000005)

Tag Table Raw Data:
0x0080: 00 00 00 05 64 65 73 63  00 00 00 C0 00 00 00 3E  |....desc.......>|
0x0090: 41 32 42 31 00 00 01 00  00 00 29 00 42 32 41 31  |A2B1......).B2A1|
0x00A0: 00 00 2A 00 00 00 01 58  77 74 70 74 00 00 2B 58  |..*....Xwtpt..+X|
0x00B0: 00 00 00 14 63 70 72 74  00 00 2B 6C 00 00 00 78  |....cprt..+l...x|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x64657363   'desc'        0x000000C0   0x0000003E   'mluc'        OK
1    0x41324231   'A2B1'        0x00000100   0x00002900   'mpet'        OK
2    0x42324131   'B2A1'        0x00002A00   0x00000158   '    '        OK
3    0x77747074   'wtpt'        0x00002B58   0x00000014   '?�  '        OK
4    0x63707274   'cprt'        0x00002B6C   0x00000078   '    '        OK

=== FULL FILE HEX DUMP (all 11727 bytes) ===
0x0000: 00 00 2B E4 00 00 00 00  05 00 00 00 73 70 61 63  |..+.........spac|
0x0010: 52 47 42 20 58 59 5A 20  07 EA 00 02 00 11 00 08  |RGB XYZ ........|
0x0020: 00 26 00 0C 61 63 73 70  00 00 00 00 00 00 00 00  |.&..acsp........|
0x0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0040: 00 00 00 01 00 00 F6 D6  00 01 00 00 00 00 D3 2D  |...............-|
0x0050: 49 43 43 20 6A C2 32 3E  93 27 6F 5A E1 E3 75 9C  |ICC j.2>.'oZ..u.|
0x0060: 3A 69 8F 54 00 00 00 00  00 00 00 00 00 00 00 00  |:i.T............|
0x0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0080: 00 00 00 05 64 65 73 63  00 00 00 C0 00 00 00 3E  |....desc.......>|
0x0090: 41 32 42 31 00 00 01 00  00 00 29 00 42 32 41 31  |A2B1......).B2A1|
0x00A0: 00 00 2A 00 00 00 01 58  77 74 70 74 00 00 2B 58  |..*....Xwtpt..+X|
0x00B0: 00 00 00 14 63 70 72 74  00 00 2B 6C 00 00 00 78  |....cprt..+l...x|
0x00C0: 6D 6C 75 63 00 00 00 00  00 00 00 01 00 00 00 0C  |mluc............|
0x00D0: 65 6E 55 53 00 00 00 22  00 00 00 1C 00 73 00 52  |enUS...".....s.R|
0x00E0: 00 47 00 42 00 20 00 63  00 61 00 6C 00 63 00 20  |.G.B. .c.a.l.c. |
0x00F0: 00 74 00 65 00 73 00 74  00 65 00 72 00 00 00 00  |.t.e.s.t.e.r....|
0x0100: 6D 70 65 74 00 00 00 00  00 03 00 03 00 00 00 01  |mpet............|
0x0110: 00 00 00 18 00 00 28 E8  63 61 6C 63 00 00 00 00  |......(.calc....|
0x0120: 00 03 00 03 00 00 00 09  00 00 00 60 00 00 25 84  |...........`..%.|
0x0130: 00 00 25 84 00 00 00 9C  00 00 26 20 00 00 00 FC  |..%.......& ....|
0x0140: 00 00 27 1C 00 00 00 3C  00 00 27 58 00 00 00 3C  |..'....<..'X...<|
0x0150: 00 00 27 94 00 00 00 7C  00 00 28 10 00 00 00 54  |..'....|..(....T|
0x0160: 00 00 28 64 00 00 00 2C  00 00 28 90 00 00 00 2C  |..(d...,..(....,|
0x0170: 00 00 28 BC 00 00 00 2C  66 75 6E 63 00 00 00 00  |..(....,func....|
0x0180: 00 00 04 A3 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x0190: 3F 80 00 00 64 61 74 61  3F 80 00 00 74 70 75 74  |?...data?...tput|
0x01A0: 00 00 00 02 74 67 65 74  00 00 00 02 73 75 6D 20  |....tget....sum |
0x01B0: 00 01 00 00 64 61 74 61  40 40 00 00 65 71 20 20  |....data@@..eq  |
0x01C0: 00 00 00 00 74 70 75 74  00 03 00 00 64 61 74 61  |....tput....data|
0x01D0: 3F 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |?...data?...data|
0x01E0: 3F 80 00 00 74 73 61 76  00 04 00 02 73 75 6D 20  |?...tsav....sum |
0x01F0: 00 01 00 00 64 61 74 61  40 40 00 00 65 71 20 20  |....data@@..eq  |
0x0200: 00 00 00 00 74 70 75 74  00 07 00 00 64 61 74 61  |....tput....data|
0x0210: 3F 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |?...data?...data|
0x0220: 3F 80 00 00 63 75 72 76  00 00 00 00 73 75 6D 20  |?...curv....sum |
0x0230: 00 01 00 00 64 61 74 61  40 40 00 00 65 71 20 20  |....data@@..eq  |
0x0240: 00 00 00 00 74 70 75 74  00 08 00 00 64 61 74 61  |....tput....data|
0x0250: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x0260: 40 40 00 00 6D 74 78 20  00 02 00 00 64 61 74 61  |@@..mtx ....data|
0x0270: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x0280: 40 00 00 00 73 75 62 20  00 02 00 00 73 75 6D 20  |@...sub ....sum |
0x0290: 00 01 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x02A0: 00 00 00 00 74 70 75 74  00 09 00 00 64 61 74 61  |....tput....data|
0x02B0: 3F 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |?...data?...data|
0x02C0: 3F 80 00 00 63 6C 75 74  00 04 00 00 64 61 74 61  |?...clut....data|
0x02D0: 3E 80 00 00 64 61 74 61  3F 00 00 00 64 61 74 61  |>...data?...data|
0x02E0: 3F 40 00 00 73 75 62 20  00 02 00 00 73 75 6D 20  |?@..sub ....sum |
0x02F0: 00 01 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x0300: 00 00 00 00 74 70 75 74  00 0A 00 00 64 61 74 61  |....tput....data|
0x0310: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x0320: 40 40 00 00 63 61 6C 63  00 05 00 00 64 61 74 61  |@@..calc....data|
0x0330: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x0340: 40 80 00 00 73 75 62 20  00 02 00 00 73 75 6D 20  |@...sub ....sum |
0x0350: 00 01 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x0360: 00 00 00 00 74 70 75 74  00 0B 00 00 64 61 74 61  |....tput....data|
0x0370: 3F 00 00 00 74 69 6E 74  00 08 00 00 64 61 74 61  |?...tint....data|
0x0380: 3F 80 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |?...data@@..data|
0x0390: 40 C0 00 00 73 75 62 20  00 02 00 00 73 75 6D 20  |@...sub ....sum |
0x03A0: 00 01 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x03B0: 00 00 00 00 74 70 75 74  00 0C 00 00 64 61 74 61  |....tput....data|
0x03C0: 42 C8 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |B...data....data|
0x03D0: 00 00 00 00 66 4A 61 62  00 06 00 00 64 61 74 61  |....fJab....data|
0x03E0: 3F 76 D5 D0 64 61 74 61  3F 80 00 00 64 61 74 4D  |?v..data?...datM|
0x03F0: 43 48 2C A5 73 75 62 20  00 02 00 00 61 62 73 20  |CH,.sub ....abs |
0x0400: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x0410: 3A 83 12 6F 6C 65 20 20  00 00 00 00 74 70 75 74  |:..ole  ....tput|
0x0420: 00 0D 00 00 64 61 74 61  3F 76 D5 D0 64 61 74 61  |....data?v..data|
0x0430: 3F 80 00 00 64 61 74 61  3F 53 2C A5 74 4A 61 62  |?...data?S,.tJab|
0x0440: 00 07 00 00 64 61 74 61  42 C8 00 00 64 61 74 61  |....dataB...data|
0x0450: 00 00 00 00 64 61 74 61  00 00 00 00 73 75 62 20  |....data....sub |
0x0460: 00 02 00 00 61 62 73 20  00 02 00 00 73 75 6D 20  |....abs ....sum |
0x0470: 00 01 00 00 64 61 74 61  3D CC CC CD 6C 65 20 20  |....data=...le  |
0x0480: 00 00 00 00 74 70 75 74  00 0E 00 00 64 61 74 61  |....tput....data|
0x0490: 3F 80 00 00 65 6C 65 6D  00 08 00 00 64 61 74 61  |?...elem....data|
0x04A0: 40 00 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@...data@...data|
0x04B0: 41 00 00 00 73 75 62 20  00 02 00 00 73 75 6D 20  |A...sub ....sum |
0x04C0: 00 01 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x04D0: 00 00 00 00 74 70 75 74  00 0F 00 00 64 61 74 61  |....tput....data|
0x04E0: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x04F0: 40 40 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@@..data@...data|
0x0500: 40 A0 00 00 64 61 74 61  40 C0 00 00 63 6F 70 79  |@...data@...copy|
0x0510: 00 02 00 01 73 75 6D 20  00 0A 00 00 64 61 74 61  |....sum ....data|
0x0520: 42 4C 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |BL..eq  ....tput|
0x0530: 00 10 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x0540: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x0550: 40 80 00 00 64 61 74 61  40 A0 00 00 72 6F 74 6C  |@...data@...rotl|
0x0560: 00 04 00 01 64 61 74 61  40 40 00 00 64 61 74 61  |....data@@..data|
0x0570: 40 80 00 00 64 61 74 61  40 A0 00 00 64 61 74 61  |@...data@...data|
0x0580: 3F 80 00 00 64 61 74 61  40 00 00 00 73 75 62 20  |?...data@...sub |
0x0590: 00 04 00 00 73 75 6D 20  00 03 00 00 64 61 74 61  |....sum ....data|
0x05A0: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x05B0: 00 11 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x05C0: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x05D0: 40 80 00 00 64 61 74 61  40 A0 00 00 72 6F 74 72  |@...data@...rotr|
0x05E0: 00 04 00 01 64 61 74 61  40 80 00 00 64 61 74 61  |....data@...data|
0x05F0: 40 A0 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |@...data?...data|
0x0600: 40 00 00 00 64 61 74 61  40 40 00 00 73 75 62 20  |@...data@@..sub |
0x0610: 00 04 00 00 73 75 6D 20  00 03 00 00 64 61 74 61  |....sum ....data|
0x0620: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x0630: 00 12 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x0640: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x0650: 40 80 00 00 64 61 74 61  40 A0 00 00 70 6F 73 64  |@...data@...posd|
0x0660: 00 03 00 01 73 75 6D 20  00 05 00 00 64 61 74 61  |....sum ....data|
0x0670: 41 98 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |A...eq  ....tput|
0x0680: 00 13 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x0690: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x06A0: 40 80 00 00 64 61 74 61  40 A0 00 00 66 6C 69 70  |@...data@...flip|
0x06B0: 00 03 00 00 64 61 74 61  40 A0 00 00 64 61 74 61  |....data@...data|
0x06C0: 40 80 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x06D0: 40 00 00 00 64 61 74 61  3F 80 00 00 73 75 62 20  |@...data?...sub |
0x06E0: 00 04 00 00 61 62 73 20  00 04 00 00 73 75 6D 20  |....abs ....sum |
0x06F0: 00 03 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x0700: 00 00 00 00 74 70 75 74  00 14 00 00 64 61 74 61  |....tput....data|
0x0710: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x0720: 40 40 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@@..data@...data|
0x0730: 40 A0 00 00 70 6F 70 20  00 01 00 00 73 75 6D 20  |@...pop ....sum |
0x0740: 00 01 00 00 64 61 74 61  40 C0 00 00 65 71 20 20  |....data@...eq  |
0x0750: 00 00 00 00 74 70 75 74  00 15 00 00 64 61 74 61  |....tput....data|
0x0760: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x0770: 40 40 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@@..data@...data|
0x0780: 40 A0 00 00 64 61 74 61  40 C0 00 00 64 61 74 61  |@...data@...data|
0x0790: 40 E0 00 00 64 61 74 61  41 00 00 00 64 61 74 61  |@...dataA...data|
0x07A0: 41 10 00 00 64 61 74 61  40 C0 00 00 64 61 74 61  |A...data@...data|
0x07B0: 41 70 00 00 64 61 74 61  41 C0 00 00 73 6F 6C 76  |Ap..dataA...solv|
0x07C0: 00 02 00 02 64 61 74 61  3F 80 00 00 65 71 20 20  |....data?...eq  |
0x07D0: 00 00 00 00 69 66 20 20  00 00 00 09 65 6C 73 65  |....if  ....else|
0x07E0: 00 00 00 04 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x07F0: 3F 80 00 00 64 61 74 61  3F 80 00 00 73 75 62 20  |?...data?...sub |
0x0800: 00 02 00 00 61 62 73 20  00 02 00 00 64 61 74 61  |....abs ....data|
0x0810: 37 27 C5 AC 64 61 74 61  37 27 C5 AC 64 61 74 61  |7'..data7'..data|
0x0820: 37 27 C5 AC 6C 74 20 20  00 02 00 00 64 61 74 61  |7'..lt  ....data|
0x0830: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x0840: 00 00 00 00 65 71 20 20  00 02 00 00 73 75 6D 20  |....eq  ....sum |
0x0850: 00 01 00 00 64 61 74 61  40 40 00 00 65 71 20 20  |....data@@..eq  |
0x0860: 00 00 00 00 74 70 75 74  00 16 00 00 64 61 74 61  |....tput....data|
0x0870: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x0880: 40 40 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@@..data@...data|
0x0890: 40 A0 00 00 64 61 74 61  40 C0 00 00 64 61 74 61  |@...data@...data|
0x08A0: 40 E0 00 00 64 61 74 61  41 00 00 00 74 72 61 6E  |@...dataA...tran|
0x08B0: 00 01 00 03 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x08C0: 40 A0 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |@...data@...data|
0x08D0: 40 C0 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x08E0: 40 E0 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@...data@...data|
0x08F0: 41 00 00 00 65 71 20 20  00 07 00 00 61 6E 64 20  |A...eq  ....and |
0x0900: 00 06 00 00 74 70 75 74  00 17 00 00 64 61 74 61  |....tput....data|
0x0910: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x0920: 40 80 00 00 64 61 74 61  40 A0 00 00 70 72 6F 64  |@...data@...prod|
0x0930: 00 02 00 00 64 61 74 61  42 F0 00 00 65 71 20 20  |....dataB...eq  |
0x0940: 00 00 00 00 74 70 75 74  00 18 00 00 64 61 74 61  |....tput....data|
0x0950: 40 A0 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x0960: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x0970: 40 80 00 00 6D 69 6E 20  00 03 00 00 64 61 74 61  |@...min ....data|
0x0980: 3F 80 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |?...eq  ....tput|
0x0990: 00 19 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x09A0: 40 40 00 00 64 61 74 61  40 A0 00 00 64 61 74 61  |@@..data@...data|
0x09B0: 40 80 00 00 64 61 74 61  40 00 00 00 6D 61 78 20  |@...data@...max |
0x09C0: 00 03 00 00 64 61 74 61  40 A0 00 00 65 71 20 20  |....data@...eq  |
0x09D0: 00 00 00 00 74 70 75 74  00 1A 00 00 64 61 74 61  |....tput....data|
0x09E0: 3F 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |?...data?...data|
0x09F0: 3F 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |?...data?...data|
0x0A00: 3F 80 00 00 61 6E 64 20  00 03 00 00 74 70 75 74  |?...and ....tput|
0x0A10: 00 1B 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x0A20: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x0A30: 00 00 00 00 64 61 74 61  00 00 00 00 6F 72 20 20  |....data....or  |
0x0A40: 00 03 00 00 74 70 75 74  00 1C 00 00 70 69 20 20  |....tput....pi  |
0x0A50: 00 00 00 00 64 61 74 61  40 49 0E 56 73 75 62 20  |....data@I.Vsub |
0x0A60: 00 00 00 00 61 62 73 20  00 00 00 00 64 61 74 61  |....abs ....data|
0x0A70: 3D CC CC CD 6C 74 20 20  00 00 00 00 74 70 75 74  |=...lt  ....tput|
0x0A80: 00 1D 00 00 2B 49 4E 46  00 00 00 00 64 61 74 61  |....+INF....data|
0x0A90: 79 9A 13 0C 67 74 20 20  00 00 00 00 74 70 75 74  |y...gt  ....tput|
0x0AA0: 00 1E 00 00 2D 49 4E 46  00 00 00 00 64 61 74 61  |....-INF....data|
0x0AB0: F9 9A 13 0C 6C 74 20 20  00 00 00 00 74 70 75 74  |....lt  ....tput|
0x0AC0: 00 1F 00 00 4E 61 4E 20  00 00 00 00 4E 61 4E 20  |....NaN ....NaN |
0x0AD0: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x0AE0: 00 20 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |. ..data?...data|
0x0AF0: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x0B00: 40 80 00 00 64 61 74 61  BF 80 00 00 64 61 74 61  |@...data....data|
0x0B10: C0 00 00 00 64 61 74 61  C0 40 00 00 64 61 74 61  |....data.@..data|
0x0B20: C0 80 00 00 61 64 64 20  00 03 00 00 73 75 6D 20  |....add ....sum |
0x0B30: 00 02 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x0B40: 00 00 00 00 74 70 75 74  00 21 00 00 64 61 74 61  |....tput.!..data|
0x0B50: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x0B60: 40 40 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@@..data@...data|
0x0B70: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x0B80: 40 40 00 00 64 61 74 61  40 80 00 00 73 75 62 20  |@@..data@...sub |
0x0B90: 00 03 00 00 73 75 6D 20  00 02 00 00 64 61 74 61  |....sum ....data|
0x0BA0: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x0BB0: 00 22 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |."..data@...data|
0x0BC0: 40 80 00 00 64 61 74 61  40 C0 00 00 64 61 74 61  |@...data@...data|
0x0BD0: 41 00 00 00 64 61 74 61  3F 00 00 00 64 61 74 61  |A...data?...data|
0x0BE0: 3F 00 00 00 64 61 74 61  3F 00 00 00 64 61 74 61  |?...data?...data|
0x0BF0: 3F 00 00 00 6D 75 6C 20  00 03 00 00 64 61 74 61  |?...mul ....data|
0x0C00: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x0C10: 40 40 00 00 64 61 74 61  40 80 00 00 73 75 62 20  |@@..data@...sub |
0x0C20: 00 03 00 00 73 75 6D 20  00 02 00 00 64 61 74 61  |....sum ....data|
0x0C30: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x0C40: 00 23 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |.#..data@...data|
0x0C50: 40 80 00 00 64 61 74 61  40 C0 00 00 64 61 74 61  |@...data@...data|
0x0C60: 41 00 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |A...data@...data|
0x0C70: 40 00 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |@...data@...data|
0x0C80: 40 00 00 00 64 69 76 20  00 03 00 00 64 61 74 61  |@...div ....data|
0x0C90: 3F 80 00 00 64 61 74 61  40 00 00 B3 64 61 74 61  |?...data@...data|
0x0CA0: 40 40 00 00 64 61 74 61  40 80 00 00 73 75 62 20  |@@..data@...sub |
0x0CB0: 00 03 00 00 73 75 6D 20  00 02 00 00 64 61 74 61  |....sum ....data|
0x0CC0: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x0CD0: 00 24 00 00 64 61 74 61  40 A0 00 00 64 61 74 61  |.$..data@...data|
0x0CE0: 41 30 00 00 64 61 74 61  40 50 00 00 64 61 74 61  |A0..data@P..data|
0x0CF0: 40 00 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@...data@...data|
0x0D00: 3F 80 00 00 6D 6F 64 20  00 02 00 00 64 61 74 61  |?...mod ....data|
0x0D10: 3F 80 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |?...data@@..data|
0x0D20: 3E 80 00 00 73 75 62 20  00 02 00 00 73 75 6D 20  |>...sub ....sum |
0x0D30: 00 01 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x0D40: 00 00 00 00 74 70 75 74  00 25 00 00 64 61 74 6C  |....tput.%..datl|
0x0D50: 14 00 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |....data@...data|
0x0D60: 40 00 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |@...data@...data|
0x0D70: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x0D80: 40 80 00 00 64 61 74 61  40 A0 00 00 70 6F 77 20  |@...data@...pow |
0x0D90: 00 03 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |....data@...data|
0x0DA0: 41 00 00 00 64 61 74 61  41 80 00 00 64 61 74 61  |A...dataA...data|
0x0DB0: 42 00 00 00 73 75 62 20  00 03 00 00 73 75 6D 20  |B...sub ....sum |
0x0DC0: 00 02 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x0DD0: 00 00 00 00 74 70 75 74  00 26 00 00 64 61 74 61  |....tput.&..data|
0x0DE0: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x0DF0: 40 80 00 00 64 61 74 61  40 00 00 00 67 61 6D 61  |@...data@...gama|
0x0E00: 00 02 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |....data@...data|
0x0E10: 41 10 00 00 64 61 74 61  41 80 00 00 73 75 62 20  |A...dataA...sub |
0x0E20: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x0E30: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x0E40: 00 27 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |.'..data@...data|
0x0E50: 40 40 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@@..data@...data|
0x0E60: 40 00 00 00 73 61 64 64  00 02 00 00 64 61 74 61  |@...sadd....data|
0x0E70: 40 80 00 00 64 61 74 61  40 A0 00 00 64 61 74 61  |@...data@...data|
0x0E80: 40 C0 00 00 73 75 62 20  00 02 00 00 73 75 6D 20  |@...sub ....sum |
0x0E90: 00 01 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x0EA0: 00 00 00 00 74 70 75 74  00 28 00 00 64 61 74 61  |....tput.(..data|
0x0EB0: 40 40 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@@..data@...data|
0x0EC0: 40 A0 00 00 64 61 74 61  40 00 00 00 73 73 75 62  |@...data@...ssub|
0x0ED0: 00 02 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x0EE0: 40 00 00 00 64 61 74 61  40 40 00 00 73 75 62 20  |@...data@@..sub |
0x0EF0: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x0F00: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x0F10: 00 29 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |.)..data@...data|
0x0F20: 40 40 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@@..data@...data|
0x0F30: 40 00 00 00 73 6D 75 6C  00 02 00 00 64 61 74 61  |@...smul....data|
0x0F40: 40 80 00 00 64 61 74 61  40 C0 00 00 64 61 74 61  |@...data@...data|
0x0F50: 41 00 00 00 73 75 62 20  00 02 00 00 73 75 6D 20  |A...sub ....sum |
0x0F60: 00 01 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x0F70: 00 00 00 00 74 70 75 74  00 2A 00 00 64 61 74 61  |....tput.*..data|
0x0F80: 40 00 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@...data@...data|
0x0F90: 41 00 00 00 64 61 74 61  40 00 00 00 73 64 69 76  |A...data@...sdiv|
0x0FA0: 00 02 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x0FB0: 40 00 00 00 64 61 74 61  40 80 00 00 73 75 62 20  |@...data@...sub |
0x0FC0: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x0FD0: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x0FE0: 00 2B 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |.+..data@...data|
0x0FF0: 40 40 00 00 64 61 74 61  40 80 00 00 73 71 20 20  |@@..data@...sq  |
0x1000: 00 02 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |....data@...data|
0x1010: 41 10 00 00 64 61 74 61  41 80 00 00 73 75 62 20  |A...dataA...sub |
0x1020: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x1030: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x1040: 00 2C 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |.,..data@...data|
0x1050: 41 10 00 00 64 61 74 61  41 80 00 00 73 71 72 74  |A...dataA...sqrt|
0x1060: 00 02 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |....data@...data|
0x1070: 40 40 00 00 64 61 74 61  40 80 00 00 73 75 62 20  |@@..data@...sub |
0x1080: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x1090: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x10A0: 00 2D 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |.-..data@...data|
0x10B0: 40 40 00 00 64 61 74 61  40 80 00 00 63 62 20 20  |@@..data@...cb  |
0x10C0: 00 02 00 00 64 61 74 61  41 00 00 00 64 61 74 61  |....dataA...data|
0x10D0: 41 D8 00 00 64 61 74 61  42 80 00 00 73 75 62 20  |A...dataB...sub |
0x10E0: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x10F0: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x1100: 00 2E 00 00 64 61 74 61  41 00 00 00 64 61 74 61  |....dataA...data|
0x1110: 41 D8 00 00 64 61 74 61  42 80 00 00 63 62 72 74  |A...dataB...cbrt|
0x1120: 00 02 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |....data@...data|
0x1130: 40 40 00 00 64 61 74 61  40 80 00 00 73 75 62 20  |@@..data@...sub |
0x1140: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x1150: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x1160: 00 2F 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |./..data@...data|
0x1170: 40 40 00 00 64 61 74 61  40 80 00 00 63 62 20 20  |@@..data@...cb  |
0x1180: 00 02 00 00 64 61 74 61  41 00 00 00 64 61 74 61  |....dataA...data|
0x1190: 41 D8 00 00 64 61 74 61  42 80 00 00 73 75 62 20  |A...dataB...sub |
0x11A0: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x11B0: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x11C0: 00 30 00 00 64 61 74 61  41 00 00 00 64 61 74 61  |.0..dataA...data|
0x11D0: 41 D8 00 00 64 61 74 61  42 80 00 00 63 62 72 74  |A...dataB...cbrt|
0x11E0: 00 02 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |....data@...data|
0x11F0: 40 40 00 00 64 61 74 61  40 80 00 00 73 75 62 20  |@@..data@...sub |
0x1200: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x1210: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x1220: 00 31 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |.1..data?...data|
0x1230: C0 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |....data@@..data|
0x1240: C0 80 00 00 64 61 74 61  40 A0 00 00 61 62 73 20  |....data@...abs |
0x1250: 00 04 00 00 73 75 6D 20  00 03 00 00 64 61 74 61  |....sum ....data|
0x1260: 41 70 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |Ap..eq  ....tput|
0x1270: 00 32 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |.2..data?...data|
0x1280: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x1290: 40 80 00 00 6E 65 67 20  00 03 00 00 64 61 74 61  |@...neg ....data|
0x12A0: BF 80 00 00 64 61 74 61  C0 00 00 00 64 61 74 61  |....data....data|
0x12B0: C0 40 00 00 64 61 74 61  C0 80 00 00 73 75 62 20  |.@..data....sub |
0x12C0: 00 03 00 00 73 75 6D 20  00 02 00 00 64 61 74 61  |....sum ....data|
0x12D0: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x12E0: 00 33 00 00 64 61 74 61  3F 8C CC CD 64 61 74 61  |.3..data?...data|
0x12F0: 40 20 00 00 64 61 74 61  40 6C CC CD 72 6F 6E 64  |@ ..data@l..rond|
0x1300: 00 02 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x1310: 40 40 00 00 64 61 74 61  40 80 00 00 73 75 62 20  |@@..data@...sub |
0x1320: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x1330: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x1340: 00 34 00 00 64 61 74 61  3F 8C CC CD 64 61 74 61  |.4..data?...data|
0x1350: 40 20 00 00 64 61 74 61  40 6C CC CD 66 6C 6F 72  |@ ..data@l..flor|
0x1360: 00 02 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x1370: 40 00 00 00 64 61 74 61  40 40 00 00 73 75 62 20  |@...data@@..sub |
0x1380: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x1390: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x13A0: 00 35 00 00 64 61 74 61  3F 8C CC CD 64 61 74 61  |.5..data?...data|
0x13B0: 40 20 00 00 64 61 74 61  40 6C CC CD 63 65 69 6C  |@ ..data@l..ceil|
0x13C0: 00 02 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |....data@...data|
0x13D0: 40 40 00 00 64 61 74 61  40 80 00 00 73 75 62 20  |@@..data@...sub |
0x13E0: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x13F0: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x1400: 00 36 00 00 64 61 74 61  3F 8C CC CD 64 61 74 61  |.6..data?...data|
0x1410: 40 20 00 00 64 61 74 61  40 6C CC CD 74 72 6E 63  |@ ..data@l..trnc|
0x1420: 00 02 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x1430: 40 00 00 00 64 61 74 61  40 40 00 00 73 75 62 20  |@...data@@..sub |
0x1440: 00 02 00 00 73 75 6D 20  00 01 00 20 00 02 00 00  |....sum ... ....|
0x1450: 64 61 74 61 00 00 00 00  65 71 20 20 00 00 00 00  |data....eq  ....|
0x1460: 74 70 75 74 00 33 00 00  64 61 74 61 3F 8C CC CD  |tput.3..data?...|
0x1470: 64 61 74 61 40 20 00 00  64 61 74 61 40 6C CC CD  |data@ ..data@l..|
0x1480: 72 6F 6E 64 00 02 00 00  64 61 74 61 3F 80 00 00  |rond....data?...|
0x1490: 64 61 74 61 40 40 00 00  64 61 74 61 40 80 00 00  |data@@..data@...|
0x14A0: 73 75 62 20 00 02 00 00  73 75 6D 20 00 01 00 00  |sub ....sum ....|
0x14B0: 64 61 74 61 00 00 00 00  65 71 20 20 00 00 00 00  |data....eq  ....|
0x14C0: 74 70 75 74 00 34 00 00  64 61 74 61 3F 8C CC CD  |tput.4..data?...|
0x14D0: 64 61 74 61 40 20 00 00  64 61 74 61 40 6C CC CD  |data@ ..data@l..|
0x14E0: 66 6C 6F 72 00 02 00 00  64 61 74 61 3F 80 00 00  |flor....data?...|
0x14F0: 64 61 74 61 40 00 00 00  64 61 74 61 40 40 00 00  |data@...data@@..|
0x1500: 73 75 62 20 00 02 00 00  73 75 6D 20 00 01 00 00  |sub ....sum ....|
0x1510: 64 61 74 61 00 00 00 00  65 71 20 20 00 00 00 00  |data....eq  ....|
0x1520: 74 70 75 74 00 35 00 00  64 61 74 61 3F 8C CC CD  |tput.5..data?...|
0x1530: 64 61 74 61 40 20 00 00  64 61 74 61 40 6C CC CD  |data@ ..data@l..|
0x1540: 63 65 69 6C 00 02 00 00  64 61 74 61 40 00 00 00  |ceil....data@...|
0x1550: 64 61 74 61 40 40 00 00  64 61 74 61 40 80 00 00  |data@@..data@...|
0x1560: 73 75 62 20 00 02 00 00  73 75 6D 20 00 01 00 00  |sub ....sum ....|
0x1570: 64 61 74 61 00 00 00 00  65 71 20 20 00 00 00 00  |data....eq  ....|
0x1580: 74 70 75 74 00 36 00 00  64 61 74 61 3F 8C CC CD  |tput.6..data?...|
0x1590: 64 61 74 61 40 20 00 00  64 61 74 61 40 6C CC CD  |data@ ..data@l..|
0x15A0: 74 72 6E 63 00 02 00 00  64 61 74 61 3F 80 00 00  |trnc....data?...|
0x15B0: 64 61 74 61 40 00 00 00  64 61 74 61 40 40 00 00  |data@...data@@..|
0x15C0: 73 75 62 20 00 02 00 00  73 75 6D 20 00 01 00 00  |sub ....sum ....|
0x15D0: 64 61 74 61 00 00 00 00  65 71 20 20 00 00 00 00  |data....eq  ....|
0x15E0: 74 70 75 74 00 37 00 00  64 61 74 61 3F 80 00 00  |tput.7..data?...|
0x15F0: 64 61 74 61 40 00 00 00  64 61 74 61 40 40 00 00  |data@...data@@..|
0x1600: 65 78 70 20 00 02 00 00  73 75 6D 20 00 01 00 00  |exp ....sum ....|
0x1610: 63 6F 70 79 00 00 00 00  64 61 74 61 41 F0 00 00  |copy....dataA...|
0x1620: 67 65 20 20 00 00 00 00  66 6C 69 70 00 00 00 00  |ge  ....flip....|
0x1630: 64 61 74 61 41 F8 00 00  6C 65 20 20 00 00 00 00  |dataA...le  ....|
0x1640: 61 6E 64 20 00 00 00 00  74 70 75 74 00 38 00 00  |and ....tput.8..|
0x1650: 64 61 74 61 41 20 00 00  64 61 74 61 42 C8 00 00  |dataA ..dataB...|
0x1660: 64 61 74 61 44 7A 00 00  6C 6F 67 20 00 02 00 00  |dataDz..log ....|
0x1670: 64 61 74 61 3F 80 00 00  64 61 74 61 40 00 00 00  |data?...data@...|
0x1680: 64 61 74 61 40 40 00 00  73 75 62 20 00 02 00 00  |data@@..sub ....|
0x1690: 73 75 6D 20 00 01 00 00  64 61 74 61 00 00 00 00  |sum ....data....|
0x16A0: 65 71 20 20 00 00 00 00  74 70 75 74 00 39 00 00  |eq  ....tput.9..|
0x16B0: 64 61 74 61 40 40 00 00  64 61 74 61 40 E0 00 00  |data@@..data@...|
0x16C0: 64 61 74 61 41 A0 00 00  6C 6E 20 20 00 02 00 00  |dataA...ln  ....|
0x16D0: 73 75 6D 20 00 01 00 00  63 6F 70 79 00 00 00 00  |sum ....copy....|
0x16E0: 64 61 74 61 40 C0 00 00  67 65 20 20 00 00 00 00  |data@...ge  ....|
0x16F0: 66 6C 69 70 00 00 00 00  64 61 74 61 40 E0 00 00  |flip....data@...|
0x1700: 6C 65 20 20 00 00 00 00  61 6E 64 20 00 00 00 00  |le  ....and ....|
0x1710: 74 70 75 74 00 3A 00 00  64 61 74 61 00 00 00 00  |tput.:..data....|
0x1720: 64 61 74 61 3F C9 0F F9  64 61 74 61 3F 49 0F F9  |data?...data?I..|
0x1730: 73 69 6E 20 00 02 00 00  64 61 74 61 00 00 00 00  |sin ....data....|
0x1740: 64 61 74 61 3F 80 00 00  64 61 74 61 3F 35 05 29  |data?...data?5.)|
0x1750: 73 75 62 00 64 61 74 61  00 00 00 00 65 71 20 20  |sub.data....eq  |
0x1760: 00 00 00 00 74 70 75 74  00 37 00 00 64 61 74 61  |....tput.7..data|
0x1770: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x1780: 40 40 00 00 65 78 70 20  00 02 00 00 73 75 6D 20  |@@..exp ....sum |
0x1790: 00 01 00 00 63 6F 70 79  00 00 00 00 64 61 74 61  |....copy....data|
0x17A0: 41 F0 00 00 67 65 20 20  00 00 00 00 66 6C 69 70  |A...ge  ....flip|
0x17B0: 00 00 00 00 64 61 74 61  41 F8 00 00 6C 65 20 20  |....dataA...le  |
0x17C0: 00 00 00 00 61 6E 64 20  00 00 00 00 74 70 75 74  |....and ....tput|
0x17D0: 00 38 00 00 64 61 74 61  41 20 00 00 64 61 74 61  |.8..dataA ..data|
0x17E0: 42 C8 00 00 64 61 74 61  44 7A 00 00 6C 6F 67 20  |B...dataDz..log |
0x17F0: 00 02 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x1800: 40 00 00 00 64 61 74 61  40 40 00 00 73 75 62 20  |@...data@@..sub |
0x1810: 00 02 00 00 73 75 6D 20  00 01 00 00 64 61 74 61  |....sum ....data|
0x1820: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x1830: 00 39 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |.9..data@@..data|
0x1840: 40 E0 00 00 64 61 74 61  41 A0 00 00 6C 6E 20 20  |@...dataA...ln  |
0x1850: 00 02 00 00 73 75 6D 20  00 01 00 00 63 6F 70 79  |....sum ....copy|
0x1860: 00 00 00 00 64 61 74 61  40 C0 00 00 67 65 20 20  |....data@...ge  |
0x1870: 00 00 00 00 66 6C 69 70  00 00 00 00 64 61 74 61  |....flip....data|
0x1880: 40 E0 00 00 6C 65 20 20  00 00 00 00 61 6E 64 20  |@...le  ....and |
0x1890: 00 00 00 00 74 70 75 74  00 3A 00 00 64 61 74 61  |....tput.:..data|
0x18A0: 00 00 00 00 64 61 74 61  3F C9 0F F9 64 61 74 61  |....data?...data|
0x18B0: 3F 49 0F F9 73 69 6E 20  00 02 00 00 64 61 74 61  |?I..sin ....data|
0x18C0: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x18D0: 3F 35 05 29 73 75 62 20  00 02 00 00 73 75 6D 20  |?5.)sub ....sum |
0x18E0: 00 01 00 00 61 62 73 20  00 00 00 00 64 61 74 61  |....abs ....data|
0x18F0: 3C 23 D7 0A 6C 65 20 20  00 00 00 00 74 70 75 74  |<#..le  ....tput|
0x1900: 00 3B 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |.;..data....data|
0x1910: 3F C9 0F F9 64 61 74 61  3F 49 0F F9 63 6F 73 20  |?...data?I..cos |
0x1920: 00 02 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x1930: 00 00 00 00 64 61 74 61  3F 35 05 29 73 75 62 20  |....data?5.)sub |
0x1940: 00 02 00 00 73 75 6D 20  00 01 00 00 61 62 73 20  |....sum ....abs |
0x1950: 00 00 00 00 64 61 74 61  3C 23 D7 0A 6C 65 20 20  |....data<#..le  |
0x1960: 00 00 00 00 74 70 75 74  00 3C 00 00 64 61 74 61  |....tput.<..data|
0x1970: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x1980: 3F 49 0F F9 74 61 6E 20  00 02 00 00 64 61 74 61  |?I..tan ....data|
0x1990: 00 00 00 00 64 61 74 61  3F C7 58 E2 64 61 74 61  |....data?.X.data|
0x19A0: 3F 80 00 00 73 75 62 20  00 02 00 00 73 75 6D 20  |?...sub ....sum |
0x19B0: 00 01 00 00 61 62 73 20  00 00 00 00 64 61 74 61  |....abs ....data|
0x19C0: 3C 23 D7 0A 6C 65 20 20  00 00 00 00 74 70 75 74  |<#..le  ....tput|
0x19D0: 00 3D 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |.=..data....data|
0x19E0: 3F 80 00 00 64 61 74 61  3F 35 05 29 61 73 69 6E  |?...data?5.)asin|
0x19F0: 00 02 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x1A00: 3F C9 0F F9 64 61 74 61  3F 49 0F F9 73 75 62 20  |?...data?I..sub |
0x1A10: 00 02 00 00 73 75 6D 20  00 01 00 00 61 62 73 20  |....sum ....abs |
0x1A20: 00 00 00 00 64 61 74 61  3C 23 D7 0A 6C 65 20 20  |....data<#..le  |
0x1A30: 00 00 00 00 74 70 75 74  00 3E 00 00 64 61 74 61  |....tput.>..data|
0x1A40: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x1A50: 3F 35 05 29 61 63 6F 73  00 02 00 00 64 61 74 61  |?5.)acos....data|
0x1A60: 3F C9 0F F9 64 61 74 61  00 00 00 00 64 61 74 61  |?...data....data|
0x1A70: 3F 49 0F 52 73 75 62 20  00 02 00 00 73 75 6D 20  |?I.Rsub ....sum |
0x1A80: 00 01 00 00 61 62 73 20  00 00 00 00 64 61 74 61  |....abs ....data|
0x1A90: 3C 23 D7 0A 6C 65 20 20  00 00 00 00 74 70 75 74  |<#..le  ....tput|
0x1AA0: 00 3F 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |.?..data....data|
0x1AB0: 3F 80 00 00 64 61 74 61  3F 35 05 29 61 74 61 6E  |?...data?5.)atan|
0x1AC0: 00 02 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x1AD0: 3F 49 0F F9 64 61 74 61  3F 1D 90 19 73 75 62 20  |?I..data?...sub |
0x1AE0: 00 02 00 00 73 75 6D 20  00 01 00 00 61 62 73 20  |....sum ....abs |
0x1AF0: 00 00 00 00 64 61 74 61  3C 23 D7 0A 6C 65 20 20  |....data<#..le  |
0x1B00: 00 00 00 00 74 70 75 74  00 40 00 00 64 61 74 61  |....tput.@..data|
0x1B10: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x1B20: 40 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |@...data....data|
0x1B30: 3F 80 00 00 64 61 74 61  40 00 00 00 61 74 6E 32  |?...data@...atn2|
0x1B40: 00 02 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x1B50: 3E ED 63 88 64 61 74 61  3F 49 0F F9 73 75 62 20  |>.c.data?I..sub |
0x1B60: 00 02 00 00 73 75 6D 20  00 01 00 00 61 62 73 20  |....sum ....abs |
0x1B70: 00 00 00 00 64 61 74 61  3C 23 D7 0A 6C 65 20 20  |....data<#..le  |
0x1B80: 00 00 00 00 74 70 75 74  00 41 00 00 64 61 74 61  |....tput.A..data|
0x1B90: 00 00 00 00 64 61 74 61  41 E2 46 3F 64 61 74 61  |....dataA.F?data|
0x1BA0: 42 20 00 00 64 61 74 61  42 20 00 00 64 61 74 61  |B ..dataB ..data|
0x1BB0: 41 E2 46 3F 64 61 74 61  00 00 00 00 63 74 6F 70  |A.F?data....ctop|
0x1BC0: 00 02 00 00 64 61 74 61  42 20 00 00 64 61 74 61  |....dataB ..data|
0x1BD0: 42 20 00 00 64 61 74 61  42 20 00 00 64 61 74 61  |B ..dataB ..data|
0x1BE0: 00 00 00 00 64 61 74 61  42 34 00 00 64 61 74 61  |....dataB4..data|
0x1BF0: 42 B4 00 00 73 75 62 20  00 05 00 00 73 75 6D 20  |B...sub ....sum |
0x1C00: 00 04 00 00 61 62 73 20  00 00 00 00 64 61 74 61  |....abs ....data|
0x1C10: 3C 23 D7 0A 6C 65 20 20  00 00 00 00 74 70 75 74  |<#..le  ....tput|
0x1C20: 00 42 00 00 64 61 74 61  42 20 00 00 64 61 74 61  |.B..dataB ..data|
0x1C30: 42 20 00 00 64 61 74 61  42 20 00 00 64 61 74 61  |B ..dataB ..data|
0x1C40: 00 00 00 00 64 61 74 61  42 34 00 00 64 61 74 61  |....dataB4..data|
0x1C50: 42 B4 00 00 70 74 6F 63  00 02 00 00 64 61 74 61  |B...ptoc....data|
0x1C60: 00 00 00 00 64 61 74 61  41 E2 46 3F 64 61 74 61  |....dataA.F?data|
0x1C70: 42 20 00 00 64 61 74 61  42 20 00 00 64 61 74 61  |B ..dataB ..data|
0x1C80: 41 E2 46 3F 64 61 74 61  00 00 00 00 73 75 62 20  |A.F?data....sub |
0x1C90: 00 05 00 00 73 75 6D 20  00 04 00 00 61 62 73 20  |....sum ....abs |
0x1CA0: 00 00 00 00 64 61 74 61  3C 23 D7 0A 6C 65 20 20  |....data<#..le  |
0x1CB0: 00 00 00 00 74 70 75 74  00 43 00 00 70 69 20 20  |....tput.C..pi  |
0x1CC0: 00 00 00 00 2B 49 4E 46  00 00 00 00 2D 49 4E 46  |....+INF....-INF|
0x1CD0: 00 00 00 00 4E 61 4E 20  00 00 00 00 64 61 74 61  |....NaN ....data|
0x1CE0: 40 80 00 00 72 6E 75 6D  00 04 00 00 64 61 74 61  |@...rnum....data|
0x1CF0: 3F 80 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |?...data....data|
0x1D00: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x1D10: 3F 80 00 00 65 71 20 20  00 04 00 00 73 75 6D 20  |?...eq  ....sum |
0x1D20: 00 03 00 00 64 61 74 61  40 A0 00 00 65 71 20 20  |....data@...eq  |
0x1D30: 00 00 00 00 74 70 75 74  00 44 00 00 64 61 74 61  |....tput.D..data|
0x1D40: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x1D50: 40 40 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@@..data@...data|
0x1D60: 40 A0 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x1D70: 40 40 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@@..data@@..data|
0x1D80: 40 40 00 00 64 61 74 61  40 40 00 00 6C 74 20 20  |@@..data@@..lt  |
0x1D90: 00 04 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x1DA0: 3F 80 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |?...data....data|
0x1DB0: 00 00 00 00 64 61 74 61  00 00 00 00 73 75 62 20  |....data....sub |
0x1DC0: 00 04 00 00 73 75 6D 20  00 03 00 00 64 61 74 61  |....sum ....data|
0x1DD0: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x1DE0: 00 45 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |.E..data?...data|
0x1DF0: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x1E00: 40 80 00 00 64 61 74 61  40 A0 00 00 64 61 74 61  |@...data@...data|
0x1E10: 40 40 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@@..data@@..data|
0x1E20: 40 40 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@@..data@@..data|
0x1E30: 40 40 00 00 6C 65 20 20  00 04 00 00 64 61 74 61  |@@..le  ....data|
0x1E40: 3F 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |?...data?...data|
0x1E50: 3F 80 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |?...data....data|
0x1E60: 00 00 00 00 73 75 62 20  00 04 00 00 73 75 6D 20  |....sub ....sum |
0x1E70: 00 03 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x1E80: 00 00 00 00 74 70 75 74  00 46 00 00 64 61 74 61  |....tput.F..data|
0x1E90: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x1EA0: 40 40 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@@..data@...data|
0x1EB0: 40 A0 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |@...data?...data|
0x1EC0: 00 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |....data@@..data|
0x1ED0: 00 00 00 00 64 61 74 61  40 A0 00 00 65 71 20 20  |....data@...eq  |
0x1EE0: 00 04 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x1EF0: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x1F00: 00 00 00 00 64 61 74 61  3F 80 00 00 73 75 62 20  |....data?...sub |
0x1F10: 00 04 00 00 73 75 6D 20  00 03 00 00 64 61 74 61  |....sum ....data|
0x1F20: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x1F30: 00 47 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |.G..data?...data|
0x1F40: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x1F50: 40 80 00 00 64 61 74 61  40 A0 00 00 64 61 74 61  |@...data@...data|
0x1F60: 3F 80 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |?...data....data|
0x1F70: 40 40 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |@@..data....data|
0x1F80: 40 A0 00 00 6E 65 61 72  00 04 00 00 64 61 74 61  |@...near....data|
0x1F90: 3F 80 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |?...data....data|
0x1FA0: 3F 80 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |?...data....data|
0x1FB0: 3F 80 00 00 73 75 62 20  00 04 00 00 73 75 6D 20  |?...sub ....sum |
0x1FC0: 00 03 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x1FD0: 00 00 00 00 74 70 75 74  00 48 00 00 64 61 74 61  |....tput.H..data|
0x1FE0: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x1FF0: 40 40 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@@..data@...data|
0x2000: 40 A0 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x2010: 40 40 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@@..data@@..data|
0x2020: 40 40 00 00 64 61 74 61  40 40 00 00 67 65 20 20  |@@..data@@..ge  |
0x2030: 00 04 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x2040: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x2050: 3F 80 00 00 64 61 74 61  3F 80 00 00 73 75 62 20  |?...data?...sub |
0x2060: 00 04 00 00 73 75 6D 20  00 03 00 00 64 61 74 61  |....sum ....data|
0x2070: 00 00 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |....eq  ....tput|
0x2080: 00 49 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |.I..data?...data|
0x2090: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x20A0: 40 80 00 00 64 61 74 61  40 A0 00 00 64 61 74 61  |@...data@...data|
0x20B0: 40 40 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@@..data@@..data|
0x20C0: 40 40 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@@..data@@..data|
0x20D0: 40 40 00 00 67 74 20 20  00 04 00 00 64 61 74 61  |@@..gt  ....data|
0x20E0: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x20F0: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x2100: 3F 80 00 00 73 75 62 20  00 04 00 00 73 75 6D 20  |?...sub ....sum |
0x2110: 00 03 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x2120: 00 00 00 00 74 70 75 74  00 4A 00 00 64 61 74 61  |....tput.J..data|
0x2130: 3F 80 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |?...data....data|
0x2140: 3F 80 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |?...data....data|
0x2150: 3F 80 00 00 6E 6F 74 20  00 04 00 00 64 61 74 61  |?...not ....data|
0x2160: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x2170: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x2180: 00 00 00 00 73 75 62 20  00 04 00 00 73 75 6D 20  |....sub ....sum |
0x2190: 00 03 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x21A0: 00 00 00 00 74 70 75 74  00 4B 00 00 64 61 74 61  |....tput.K..data|
0x21B0: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x21C0: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x21D0: 40 40 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |@@..data@...data|
0x21E0: 3F 80 00 00 64 61 74 61  00 00 00 00 76 6D 61 78  |?...data....vmax|
0x21F0: 00 03 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |....data@@..data|
0x2200: 40 00 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |@...data@...data|
0x2210: 40 40 00 00 73 75 62 20  00 03 00 00 73 75 6D 20  |@@..sub ....sum |
0x2220: 00 02 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x2230: 00 00 00 00 74 70 75 74  00 4C 00 00 64 61 74 61  |....tput.L..data|
0x2240: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x2250: 40 00 00 00 64 61 74 61  40 40 00 00 64 61 74 61  |@...data@@..data|
0x2260: 40 40 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |@@..data@...data|
0x2270: 3F 80 00 00 64 61 74 61  00 00 00 00 76 6D 69 6E  |?...data....vmin|
0x2280: 00 03 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x2290: 3F 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |?...data?...data|
0x22A0: 00 00 00 00 73 75 62 20  00 03 00 00 73 75 6D 20  |....sub ....sum |
0x22B0: 00 02 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x22C0: 00 00 00 00 74 70 75 74  00 4D 00 00 64 61 74 61  |....tput.M..data|
0x22D0: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x22E0: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x22F0: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x2300: 3F 80 00 00 64 61 74 61  3F 80 00 00 76 61 6E 64  |?...data?...vand|
0x2310: 00 03 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x2320: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x2330: 3F 80 00 00 73 75 62 20  00 03 00 00 73 75 6D 20  |?...sub ....sum |
0x2340: 00 02 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x2350: 00 00 00 00 74 70 75 74  00 4E 00 00 64 61 74 61  |....tput.N..data|
0x2360: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x2370: 00 00 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x2380: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x2390: 3F 80 00 00 64 61 74 61  3F 80 00 00 76 6F 72 20  |?...data?...vor |
0x23A0: 00 03 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x23B0: 3F 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |?...data?...data|
0x23C0: 3F 80 00 00 73 75 62 20  00 03 00 00 73 75 6D 20  |?...sub ....sum |
0x23D0: 00 02 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |....data....eq  |
0x23E0: 00 00 00 00 74 70 75 74  00 4F 00 00 64 61 74 61  |....tput.O..data|
0x23F0: 3F 80 00 00 64 61 74 61  3F 00 00 00 64 61 74 61  |?...data?...data|
0x2400: 3E 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |>...data?...data|
0x2410: 3F 00 00 00 64 61 74 61  3E 80 00 00 64 61 74 61  |?...data>...data|
0x2420: 3F 80 00 00 64 61 74 61  3F 00 00 00 64 61 74 61  |?...data?...data|
0x2430: 3E 80 00 00 74 4C 61 62  00 02 00 00 64 61 74 61  |>...tLab....data|
0x2440: 42 C8 00 00 64 61 74 61  42 98 23 76 64 61 74 61  |B...dataB.#vdata|
0x2450: 42 64 4D 3B 64 61 74 61  00 00 00 00 64 61 74 61  |BdM;data....data|
0x2460: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x2470: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x2480: 00 00 00 00 73 75 62 20  00 08 00 00 61 62 73 20  |....sub ....abs |
0x2490: 00 08 00 00 73 75 6D 20  00 07 00 00 64 61 74 61  |....sum ....data|
0x24A0: 3A 03 12 6F 6C 74 20 20  00 00 00 00 74 70 75 74  |:..olt  ....tput|
0x24B0: 00 50 00 00 64 61 74 61  42 C8 00 00 64 61 74 61  |.P..dataB...data|
0x24C0: 42 98 23 76 64 61 74 61  42 64 4D 3B 64 61 74 61  |B.#vdataBdM;data|
0x24D0: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x24E0: 00 00 00 00 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x24F0: 00 00 00 00 64 61 74 61  00 00 00 00 74 58 59 5A  |....data....tXYZ|
0x2500: 00 02 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x2510: 3F 00 00 00 64 61 74 61  3E 80 00 00 64 61 74 61  |?...data>...data|
0x2520: 3F 80 00 00 64 61 74 61  3F 00 00 00 64 61 74 61  |?...data?...data|
0x2530: 3E 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |>...data?...data|
0x2540: 3F 00 00 00 64 61 74 61  3E 80 00 00 73 75 62 20  |?...data>...sub |
0x2550: 00 08 00 00 61 62 73 20  00 08 00 00 73 75 6D 20  |....abs ....sum |
0x2560: 00 07 00 00 64 61 74 61  3A 03 12 6F 6C 74 20 20  |....data:..olt  |
0x2570: 00 00 00 00 74 70 75 74  00 51 00 00 64 61 74 61  |....tput.Q..data|
0x2580: 41 A0 00 00 64 61 74 61  00 00 00 00 69 66 20 20  |A...data....if  |
0x2590: 00 00 00 02 70 6F 70 20  00 00 00 00 64 61 74 61  |....pop ....data|
0x25A0: 41 20 00 00 64 61 74 61  41 A0 00 00 65 71 20 20  |A ..dataA...eq  |
0x25B0: 00 00 00 00 74 70 75 74  00 52 00 00 64 61 74 61  |....tput.R..data|
0x25C0: 41 A0 00 00 64 61 74 61  3F 80 00 00 69 66 20 20  |A...data?...if  |
0x25D0: 00 00 00 02 70 6F 70 20  00 00 00 00 64 61 74 61  |....pop ....data|
0x25E0: 41 20 00 00 64 61 74 61  41 20 00 00 65 71 20 20  |A ..dataA ..eq  |
0x25F0: 00 00 00 00 74 70 75 74  00 53 00 00 64 61 74 61  |....tput.S..data|
0x2600: 3F 80 00 00 69 66 20 20  00 00 00 01 65 6C 73 65  |?...if  ....else|
0x2610: 00 00 00 01 64 61 74 61  41 20 00 00 64 61 74 61  |....dataA ..data|
0x2620: 41 A0 00 00 64 61 74 61  41 20 00 00 65 71 20 20  |A...dataA ..eq  |
0x2630: 00 00 00 00 74 70 75 74  00 54 00 00 64 61 74 61  |....tput.T..data|
0x2640: 00 00 00 00 69 66 20 20  00 00 00 01 65 6C 73 65  |....if  ....else|
0x2650: 00 00 00 01 64 61 74 61  41 20 00 00 64 61 74 61  |....dataA ..data|
0x2660: 41 A0 00 00 64 61 74 61  41 A0 00 00 65 71 20 20  |A...dataA...eq  |
0x2670: 00 00 00 00 74 70 75 74  00 55 00 00 64 61 74 61  |....tput.U..data|
0x2680: 40 00 00 00 73 65 6C 20  00 00 00 00 63 61 73 65  |@...sel ....case|
0x2690: 00 00 00 01 63 61 73 65  00 00 00 01 63 61 73 65  |....case....case|
0x26A0: 00 00 00 01 63 61 73 65  00 00 00 01 64 66 6C 74  |....case....dflt|
0x26B0: 00 00 00 01 64 61 74 61  3F 80 00 00 64 61 74 61  |....data?...data|
0x26C0: 40 00 00 00 64 61 74 61  40 80 00 00 64 61 74 61  |@...data@...data|
0x26D0: 41 00 00 00 64 61 74 61  BF 80 00 00 64 61 74 61  |A...data....data|
0x26E0: 40 80 00 00 65 71 20 20  00 00 00 00 74 70 75 74  |@...eq  ....tput|
0x26F0: 00 56 00 00 64 61 74 61  41 00 00 00 73 65 6C 20  |.V..dataA...sel |
0x2700: 00 00 00 00 63 61 73 65  00 00 00 01 63 61 73 65  |....case....case|
0x2710: 00 00 00 01 63 61 73 65  00 00 00 01 63 61 73 65  |....case....case|
0x2720: 00 00 00 01 64 66 6C 74  00 00 00 01 64 61 74 61  |....dflt....data|
0x2730: 3F 80 00 00 64 61 74 61  40 00 00 00 64 61 74 61  |?...data@...data|
0x2740: 40 80 00 00 64 61 74 61  41 00 00 00 64 61 74 61  |@...dataA...data|
0x2750: BF 80 00 00 64 61 74 61  BF 80 00 00 65 71 20 20  |....data....eq  |
0x2760: 00 00 00 00 74 70 75 74  00 57 00 00 64 61 74 61  |....tput.W..data|
0x2770: 00 00 00 00 64 61 74 61  3F 80 00 00 73 65 6C 20  |....data?...sel |
0x2780: 00 00 00 00 63 61 73 65  00 00 00 02 63 61 73 65  |....case....case|
0x2790: 00 00 00 02 63 61 73 65  00 00 00 02 63 61 73 65  |....case....case|
0x27A0: 00 00 00 02 70 6F 70 20  00 00 00 00 64 61 74 61  |....pop ....data|
0x27B0: 3F 80 00 00 70 6F 70 20  00 00 00 00 64 61 74 61  |?...pop ....data|
0x27C0: 40 40 00 00 70 6F 70 20  00 00 00 00 64 61 74 61  |@@..pop ....data|
0x27D0: 41 10 00 00 70 6F 70 20  00 00 00 00 64 61 74 61  |A...pop ....data|
0x27E0: 41 D8 00 00 64 61 74 61  40 40 00 00 65 71 20 20  |A...data@@..eq  |
0x27F0: 00 00 00 00 74 70 75 74  00 58 00 00 64 61 74 61  |....tput.X..data|
0x2800: 00 00 00 00 64 61 74 61  BF 80 00 00 73 65 6C 20  |....data....sel |
0x2810: 00 00 00 00 63 61 73 65  00 00 00 02 63 61 73 65  |....case....case|
0x2820: 00 00 00 02 63 61 73 65  00 00 00 02 63 61 73 65  |....case....case|
0x2830: 00 00 00 02 70 6F 70 20  00 00 00 00 64 61 74 61  |....pop ....data|
0x2840: 3F 80 00 00 70 6F 70 20  00 00 00 00 64 61 74 61  |?...pop ....data|
0x2850: 40 40 00 00 70 6F 70 20  00 00 00 00 64 61 74 61  |@@..pop ....data|
0x2860: 41 10 00 00 70 6F 70 20  00 00 00 00 64 61 74 61  |A...pop ....data|
0x2870: 41 D8 00 00 64 61 74 61  00 00 00 00 65 71 20 20  |A...data....eq  |
0x2880: 00 00 00 00 74 70 75 74  00 59 00 00 65 6E 76 20  |....tput.Y..env |
0x2890: 74 72 75 65 64 61 74 61  3F 80 00 00 64 61 74 61  |truedata?...data|
0x28A0: 3F 80 00 00 65 71 20 20  00 01 00 00 73 75 6D 20  |?...eq  ....sum |
0x28B0: 00 00 00 00 64 61 74 61  40 00 00 00 65 71 20 20  |....data@...eq  |
0x28C0: 00 00 00 00 74 70 75 74  00 5A 00 00 65 6E 76 20  |....tput.Z..env |
0x28D0: 6E 64 65 66 64 61 74 61  00 00 00 00 64 61 74 61  |ndefdata....data|
0x28E0: 00 00 00 00 65 71 20 20  00 01 00 00 73 75 6D 20  |....eq  ....sum |
0x28F0: 00 00 00 00 64 61 74 61  40 00 00 00 65 71 20 20  |....data@...eq  |
0x2900: 00 00 00 00 74 70 75 74  00 5B 00 00 74 67 65 74  |....tput.[..tget|
0x2910: 00 00 00 2D 74 67 65 74  00 2E 00 2D 73 75 6D 20  |...-tget...-sum |
0x2920: 00 5A 00 00 64 61 74 61  42 B8 00 00 65 71 20 20  |.Z..dataB...eq  |
0x2930: 00 00 00 00 69 66 20 20  00 00 00 08 65 6C 73 65  |....if  ....else|
0x2940: 00 00 00 04 65 6E 76 20  01 02 03 04 69 66 20 20  |....env ....if  |
0x2950: 00 00 00 01 65 6C 73 65  00 00 00 03 63 6F 70 79  |....else....copy|
0x2960: 00 00 00 01 69 6E 20 20  00 00 00 02 63 75 72 76  |....in  ....curv|
0x2970: 00 01 00 00 6D 74 78 20  00 03 00 00 6F 75 74 20  |....mtx ....out |
0x2980: 00 00 00 02 64 61 74 61  00 00 00 00 64 61 74 61  |....data....data|
0x2990: 00 00 00 00 64 61 74 61  00 00 00 00 6F 75 74 20  |....data....out |
0x29A0: 00 00 00 02 63 76 73 74  00 00 00 00 00 03 00 03  |....cvst........|
0x29B0: 00 00 00 24 00 00 00 28  00 00 00 4C 00 00 00 28  |...$...(...L...(|
0x29C0: 00 00 00 74 00 00 00 28  63 75 72 66 00 00 00 00  |...t...(curf....|
0x29D0: 00 01 00 00 70 61 72 66  00 00 00 00 00 00 00 00  |....parf........|
0x29E0: 3F 80 00 00 3F 00 00 00  00 00 00 00 00 00 00 00  |?...?...........|
0x29F0: 63 75 72 66 00 00 00 00  00 01 00 00 70 61 72 66  |curf........parf|
0x2A00: 00 00 00 00 00 00 00 00  3F 80 00 00 3F 80 00 00  |........?...?...|
0x2A10: 00 00 00 00 00 00 00 00  63 75 72 66 00 00 00 00  |........curf....|
0x2A20: 00 01 00 00 70 61 72 66  00 00 00 00 00 00 00 00  |....parf........|
0x2A30: 3F 80 00 00 3F C0 00 00  00 00 00 00 00 00 00 00  |?...?...........|
0x2A40: 63 76 73 74 00 00 00 00  00 03 00 03 00 00 00 24  |cvst...........$|
0x2A50: 00 00 00 48 00 00 00 6C  00 00 00 48 00 00 00 B4  |...H...l...H....|
0x2A60: 00 00 00 48 63 75 72 66  00 00 00 00 00 02 00 00  |...Hcurf........|
0x2A70: 3D 25 AE E6 70 61 72 66  00 00 00 00 00 00 00 00  |=%..parf........|
0x2A80: 3F 80 00 00 3D 9C 88 54  3C 4C CC CD 00 00 00 00  |?...=..T<L......|
0x2A90: 70 61 72 66 00 00 00 00  00 00 00 00 40 19 99 9A  |parf........@...|
0x2AA0: 3F 71 62 B6 3D 54 6B 59  3C 4C CC CD 63 75 72 66  |?qb.=TkY<L..curf|
0x2AB0: 00 00 00 00 00 02 00 00  3D 25 AE E6 70 61 72 66  |........=%..parf|
0x2AC0: 00 00 00 00 00 00 00 00  3F 80 00 00 3D 9C 88 54  |........?...=..T|
0x2AD0: 3C 4C CC CD 00 00 00 00  70 61 72 66 00 00 00 00  |<L......parf....|
0x2AE0: 00 00 00 00 40 19 99 9A  3F 71 62 B6 3D 54 6B 59  |....@...?qb.=TkY|
0x2AF0: 3C 4C CC CD 63 75 72 66  00 00 00 00 00 02 00 00  |<L..curf........|
0x2B00: 3D 25 AE E6 70 61 72 66  00 00 00 00 00 00 00 00  |=%..parf........|
0x2B10: 3F 80 00 00 3D 9C 88 54  3C 4C CC CD 00 00 00 00  |?...=..T<L......|
0x2B20: 70 61 72 66 00 00 00 00  00 00 00 00 40 19 99 9A  |parf........@...|
0x2B30: 3F 71 62 B6 3D 54 6B 59  3C 4C CC CD 6D 61 74 66  |?qb.=TkY<L..matf|
0x2B40: 00 00 00 00 00 03 00 03  3F 80 00 00 3F 80 00 00  |........?...?...|
0x2B50: BF 80 00 00 40 00 00 00  3F 80 00 00 BF 80 00 00  |....@...?.......|
0x2B60: 3F 80 00 00 BF 80 00 00  3F 80 00 00 00 00 00 00  |?.......?.......|
0x2B70: 00 00 00 00 00 00 00 00  6D 61 74 66 00 00 00 00  |........matf....|
0x2B80: 00 03 00 03 3E EE 97 8D  3E C5 2B D4 3E 12 88 CE  |....>...>.+.>...|
0x2B90: 3E 63 D7 0A 3F 37 86 C2  3D 78 37 B5 3C 63 BC D3  |>c..?7..=x7.<c..|
0x2BA0: 3D C6 DC 5D 3F 36 C2 27  00 00 00 00 00 00 00 00  |=..]?6.'........|
0x2BB0: 00 00 00 00 63 6C 75 74  00 00 00 00 00 03 00 03  |....clut........|
0x2BC0: 02 02 02 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x2BD0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x2BE0: 00 00 00 00 3F 40 00 00  00 00 00 00 3F 00 00 00  |....?@......?...|
0x2BF0: 00 00 00 00 00 00 00 00  3F 00 00 00 3F 40 00 00  |........?...?@..|
0x2C00: 3E 80 00 00 00 00 00 00  00 00 00 00 3E 80 00 00  |>...........>...|
0x2C10: 00 00 00 00 3F 40 00 00  3E 80 00 00 3F 00 00 00  |....?@..>...?...|
0x2C20: 00 00 00 00 3E 80 00 00  3F 00 00 00 3F 40 00 00  |....>...?...?@..|
0x2C30: 63 61 6C 63 00 00 00 00  00 03 00 03 00 00 00 00  |calc............|
0x2C40: 00 00 00 18 00 00 00 3C  66 75 6E 63 00 00 00 00  |.......<func....|
0x2C50: 00 00 00 06 69 6E 20 20  00 00 00 02 64 61 74 61  |....in  ....data|
0x2C60: 3F 80 00 00 64 61 74 61  3F 80 00 00 64 61 74 61  |?...data?...data|
0x2C70: 3F 80 00 00 61 64 64 20  00 02 00 00 6F 75 74 20  |?...add ....out |
0x2C80: 00 00 00 02 4A 74 6F 58  00 00 00 00 00 03 00 03  |....JtoX........|
0x2C90: 3F 76 D5 D0 3F 80 00 00  3F 53 2C A5 43 FA 00 00  |?v..?...?S,.C...|
0x2CA0: 41 A0 00 00 3F 30 A3 D7  3F 80 00 00 3F 80 00 00  |A...?0..?...?...|
0x2CB0: 58 74 6F 4A 00 00 00 00  00 03 00 03 3F 76 D5 D0  |XtoJ........?v..|
0x2CC0: 3F 80 00 00 3F 53 2C A5  43 FA 00 00 41 A0 00 00  |?...?S,.C...A...|
0x2CD0: 3F 30 A3 D7 3F 80 00 00  3F 80 00 00 74 69 6E 74  |?0..?...?...tint|
0x2CE0: 00 00 00 00 00 01 00 03  66 6C 33 32 00 00 00 00  |........fl32....|
0x2CF0: 00 00 00 00 40 00 00 00  40 80 00 00 40 00 00 00  |....@...@...@...|
0x2D00: 40 80 00 00 41 00 00 00  6D 70 65 74 00 00 00 00  |@...A...mpet....|
0x2D10: 00 03 00 03 00 00 00 02  00 00 00 20 00 00 00 3C  |........... ...<|
0x2D20: 00 00 00 5C 00 00 00 FC  6D 61 74 66 00 00 00 00  |...\....matf....|
0x2D30: 00 03 00 03 40 48 9C ED  BF 7A 9C BC 6B D4 6F BD  |....@H...z..k.o.|
0x2D40: 61 47 AE 58 59 5A 20 00  00 00 00 00 00 F6 D6 00  |aG.XYZ .........|
0x2D50: 01 00 00 00 00 D3 2D 6D  6C 75 63 00 00 00 00 00  |......-mluc.....|
0x2D60: 00 00 01 00 00 00 0C 65  6E 55 53 00 00 00 5C 00  |.......enUS...\.|
0x2D70: 00 00 1C 00 43 00 6F 00  70 00 79 00 72 00 69 00  |....C.o.p.y.r.i.|
0x2D80: 67 00 68 00 74 00 20 00  32 00 30 00 31 00 35 00  |g.h.t. .2.0.1.5.|
0x2D90: 20 00 49 00 6E 00 74 00  65 00 72 00 6E 00 61 00  | .I.n.t.e.r.n.a.|
0x2DA0: 74 00 69 00 6F 00 6E 00  61 00 6C 00 20 00 43 00  |t.i.o.n.a.l. .C.|
0x2DB0: 6F 00 6C 00 6F 00 72 00  20 00 43 00 6F 00 6E 00  |o.l.o.r. .C.o.n.|
0x2DC0: 73 00 6F 00 72 00 74 00  69 00 75 00 6D 00 00     |s.o.r.t.i.u.m..|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 0**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/hbo-CIccCalculatorFunc-InitSelectOp-IccMpeCalc_cpp-Line3663.icc

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

**Exit Code: 2**

```
=== Extracting LUT data as text from: /home/h02332/po/research/test-profiles/hbo-CIccCalculatorFunc-InitSelectOp-IccMpeCalc_cpp-Line3663.icc ===

--- AToB1Tag (MPE: 1 elements) ---
  Channels: in=3 out=3
  Element[0]: CIccMpeCalculator (skipped)

=== Exported 0 LUT component(s) ===
Exported 0 text file(s) to /tmp/tmp.SZqZfFP0Pu/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
