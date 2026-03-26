# ICC Profile Analysis Report

**Profile**: `test-profiles/ios-gen-be-16x16-srgb.tif`
**File Size**: 4118 bytes
**SHA-256**: `7bdc333070f956a1e11aec2430b27a975db3f2c0c405126c5630566e6a1ad8fa`
**File Type**: TIFF image data, big-endian, direntries=15, height=16, bps=0, compression=none, PhotometricInterpretation=RGB, orientation=upper-left, width=16
**Date**: 2026-03-26T16:57:50Z
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
File: /home/h02332/po/research/test-profiles/ios-gen-be-16x16-srgb.tif

--- TIFF Metadata ---
  Dimensions:      16 × 16 pixels
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
  Profile Size:    3144 bytes (3.1 KB)
  ICC Magic:       [OK] 'acsp' at offset 36
  ICC Version:     2.1

  Extracted ICC from TIFF to: /tmp/iccanalyzer-K3atyt.icc

=======================================================================
EXTRACTED ICC PROFILE — FULL HEURISTIC ANALYSIS
=======================================================================


=======================================================================
  ICC PROFILE CONFORMANCE AUDIT
=======================================================================

File: /tmp/iccanalyzer-K3atyt.icc

[H173] Signature Conversion Shift Overflow (IccUtil.cpp signature formatting helpers)
      [WARN]  HEURISTIC: 42/42 FourCC signatures trigger UBSAN shift overflow in icGetSig()/icGetSigStr()/icGetColorSig()/icGetColorSigStr() — IccUtil.cpp:1088,1130,1167,1187,1228,1253
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
         Month=2, Day=9 — valid
         [OK] Date fields within range
      [OK] Conformant

[H1002] CF-002: Date/Time Leap Year Validation
[CF-002] Date/Time Leap Year Validation (ICC.1-2022-05 §7.2.8)
         Year=1998 (non-leap), Day=9 — valid
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
         platform=Microsoft (MSFT)
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
         Header size: 3144 bytes, File size: 3144 bytes
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
         manufacturer='IEC ' (0x49454320)
         [OK] Device manufacturer field conformant
      [OK] Conformant

[H1017] CF-017: Device Model Signature
[CF-017] Device Model Signature (ICC.1-2022-05 §7.2.13)
         model='sRGB' (0x73524742)
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
         creator='HP  ' (0x48502020)
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
           cmmId='Lino' (0x4C696E6F) — not in ICC registry
           [WARN] CMM signature not in ICC registered list — §7.2.3
      [WARN]  1 non-conformance(s)

[H1200] CF-200: Device Manufacturer/Model Signature
  [CF-200] Device Manufacturer/Model Signature (ICC.1-2022-05 §7.2.12-13)
           manufacturer='IEC ' (0x49454320)
           model='sRGB' (0x73524742)
           [OK] Device manufacturer/model conformant
      [OK] Conformant

[H1201] CF-201: Profile Creator Signature
  [CF-201] Profile Creator Signature (ICC.1-2022-05 §7.2.17)
           creator='HP  ' (0x48502020)
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
         Profile size: 3144 bytes (JPEG limit: 16707345 bytes)
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
         [OK] 14/14 tags checked, all use permitted types
      [OK] Conformant

[H1021] CF-021: Tag Type Reserved Bytes Zero
[CF-021] Tag Type Reserved Bytes Zero (ICC.1-2022-05 §10)
         [OK] 15 tag(s) checked, all reserved bytes are zero
      [OK] Conformant

[H1022] CF-022: curveType Entry Count
[CF-022] curveType Entry Count Mode (ICC.1-2022-05 §10.6)
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
         [OK] 5 XYZ tag(s) checked, all contain exactly 1 triplet
      [OK] Conformant

[H1033] CF-033: Measurement Standard Observer
[CF-033] measurementType Standard Observer (ICC.1-2022-05 §10.12 Table 56)
         Observer=1 (CIE 1931 2-degree)
         [OK] Valid standard observer
      [OK] Conformant

[H1034] CF-034: Measurement Geometry
[CF-034] measurementType Measurement Geometry (ICC.1-2022-05 §10.12 Table 57)
         Geometry=0 (Unknown)
         [OK] Valid measurement geometry
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
         Technology='CRT ' (0x43525420)
         [OK] Valid technology signature
      [OK] Conformant

[H1112] CF-112: XYZ Triplet Normalization
  [CF-112] XYZ Triplet Value Normalization (ICC.1-2022-05 §10.31)
         [OK] All 5 XYZ triplets have valid values
      [OK] Conformant

[H1169] CF-169: Negative PCSXYZ Encoding Capability
  [CF-169] Negative PCSXYZ Encoding Capability (ICC TN Negative PCSXYZ §6.3.4.2)
         [OK] All 5 XYZ tags have non-negative values
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
         Column sum: X=0.9643 Y=1.0000 Z=0.8251
         White point: X=0.9505 Y=1.0000 Z=1.0891
         Delta: dX=0.0138 dY=0.0000 dZ=0.2640 (tolerance=0.0500)
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
         Swept 17 tags: 16 OK, 1 warnings, 0 errors
         [OK] All 17 tags pass library Validate()
      [OK] Conformant

[H1189] CF-189: Tag Type Recognition Coverage
  [CF-189] Tag Type Recognition Coverage (SampleICC §3 CheckTagTypes)
         17/17 tags have recognized type signatures
         [OK] All 17 tag types are recognized by the factory
      [OK] Conformant

[H1190] CF-190: Profile Legibility Gate
  [CF-190] Profile Legibility Gate (SampleICC §3 ReadValidate)
         [OK] Profile is legible: 17 tags parsed, all non-NULL
      [OK] Conformant

[H1208] CF-208: Tag Type Version Compatibility
[CF-208] Tag Type Version Compatibility (ICC.1-2022-05 §7.2.4, §10)
         Checked 17 tags for v2 compatibility
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
         cprt (copyright): "Copyright (c) 1998 Hewlett-Packard Company" (42 bytes)
         [OK] textType tag structure conformant
      [OK] Conformant

[H1213] CF-213: viewingConditionsType Completeness
[CF-213] viewingConditionsType Completeness (ICC.1-2022-05 §10.32)
         Illuminant: X=19.6445, Y=20.3718, Z=16.8089
         Surround:   X=3.9289, Y=4.0744, Z=3.3618
         Illuminant type: 1
         [OK] viewingConditionsType structure conformant
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
         Profile creation: 1998-02-09 06:49:00 (UTC)
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
           Additional tag: 'dmnd' (0x646D6E64)
           Additional tag: 'dmdd' (0x646D6464)
           Additional tag: 'vued' (0x76756564)
           Additional tag: 'view' (0x76696577)
           Additional tag: 'lumi' (0x6C756D69)
           Additional tag: 'meas' (0x6D656173)
           Additional tag: 'tech' (0x74656368)
           [INFO] 8 non-required tag(s) present
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
           [OK] Creator signature present (0x48502020)
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
           Distinct data regions: 15
           Data coverage: 2805 / 3144 bytes (89.2%)
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
           Avg step DeltaE00=1.1053  max step DeltaE00=3.5063  max curvature=0.4341
           Large discontinuities (>6.0 DeltaE00): 0
           [OK] Transform smoothness metrics recorded
      [OK] Conformant

[H1102] CF-102: Characterization Round-Trip
  [CF-102] Characterization Data Round-Trip (ICC.1-2022-05 §9.2.26)
           [N/A] No characterization data (targ) tag present
      N/A: No characterization data (targ) tag present
      [OK] Conformant


Deep Conformance Summary: 2 issue(s)

=======================================================================
PHASE 3: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /tmp/iccanalyzer-K3atyt.icc

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
PHASE 5: PROFILE STRUCTURE DUMP
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
  Size:              0x00000C48 (3144 bytes)
  CMM Type:          'Lino' (0x4C696E6F)
  Version:           2.1.0.0 (0x02100000)
  Device Class:      DisplayClass
  Color Space:       RgbData (3 channels)
  PCS:               XYZData
  Date/Time:         1998-02-09 06:49:00
  Magic:             0x61637370 [OK]
  Platform:          Microsoft
  Profile Flags:     0x00000000
  Manufacturer:      'IEC ' (0x49454320)
  Model:             'sRGB' (0x73524742)
  Device Attribs:    0x0000000000000000
  Rendering Intent:  Perceptual (0)
  PCS Illuminant:    X=0.9642 Y=1.0000 Z=0.8249
  Creator:           'HP  ' (0x48502020)
  Profile ID:        (not set)

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
PHASE 6: TAG CONTENT ANALYSIS
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

File: /tmp/iccanalyzer-K3atyt.icc
Mode: Conformance (ICC specification audit)
Total Issues Detected: 3

[WARN] ANALYSIS COMPLETE - 3 issue(s) detected
  Review conformance findings above. Use --legacy for vulnerability analysis.


=======================================================================
IMAGE ANALYSIS SUMMARY
=======================================================================
Format:     TIFF
Dimensions: 16 × 16
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
  Version:         0x2F187063  (47.1.8)
  Device Class:    0x32EA6332  '2.c2'
  Color Space:     0xEAD3B8B5  '....'
  PCS:             0xABACBA12  '....'
  Date/Time:       16615-4672-59154 16615:4672:59161
  Magic:           0x43E7B18E  [INVALID]
  Platform:        0xFAB18EFA  '....'
  Flags:           0xB18EFAB1 [Embedded]
  Manufacturer:    0x84EBB828  '...('
  Model:           0x63B82863  'c.(c'
  Dev Attributes:  0x12092C28145F9453 [Transparency] [Matte]
  Rendering Intent:0xC7D9C1AF  UNKNOWN
  PCS Illuminant:  X=-17223.2910 Y=25304.2598 Z=-10173.6143
  Creator:         0x4262D847  'Bb.G'
  Profile ID:      64d9b18efab18efab18efab184ebb828
  Reserved 100-127: NON-ZERO [VIOLATION]

  --- V5/iccMAX Extended Header ---
  Spectral PCS:    0xABACBA12  '....'
  Spectral Range:  Not defined
  BiSpectral:      -0.2 - -0.1 nm, 52904 steps
  MCS:             0xF9E4A4F9  '....'

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
0    0xDFA8B18E   'ߨ��'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
1    0x84EBB828   '��('        0x63B82863   0x000000BF   '----'        OOB offset
2    0x71AA9887   'q���'        0xB4D7D2AA   0xF9E4A4F9   '----'        OOB offset
3    0xE4A4F9E4   '���'        0xA4F9E4A4   0xF9E4A4F5   '----'        OOB offset
4    0xDFA8B18E   'ߨ��'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
5    0x84EBB828   '��('        0x63B82863   0x000000B2   '----'        OOB offset
6    0x78AD8B8E   'x���'        0xB7A8C2B4   0xB0D4B3A1   '----'        OOB offset
7    0xDCB7998C   'ܷ��'        0x64998C64   0xE99878E7   '----'        OOB offset
8    0x987FB18E   '���'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
9    0x84EBB828   '��('        0x63B82863   0xBF70A998   '----'        OOB offset
10   0x87B5709D   '��p�'        0xBE4AB4C9   0x23CAD400   '----'        OOB offset
11   0x00000000   '    '        0x00000000   0xD02034D2   'MM  '        OOB size
12   0x263EB18E   '&>��'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
13   0x84EBB828   '��('        0x63B82863   0xB278AD8B   '----'        OOB offset
14   0x8EB864A5   '��d�'        0xC23CBBCC   0x15D1D700   '----'        OOB offset
15   0x00000000   '    '        0x00000000   0xD12035D2   'MM  '        OOB size
16   0x263EB18E   '&>��'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
17   0x84EBB828   '��('        0x63B82863   0xA47FB07E   '----'        OOB offset
18   0x96BB57AC   '��W�'        0xC52FC2CF   0x00000000   '----'        OOB offset
19   0x00000000   '    '        0x004A1976   0xD22137D2   '----'        OOB offset
20   0x263EB18E   '&>��'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
21   0x84EBB828   '��('        0x63B82863   0x8B8EB764   '----'        OOB offset
22   0xA5C23DBB   '��=�'        0xCD16D2D7   0x00000004   '----'        OOB offset
23   0x01065B1F   '['        0x92882FDA   0xD22137D2   '----'        OOB offset
24   0x263EB18E   '&>��'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
25   0x8BF6B272   '���r'        0xD1B272D1   0x7D95BB57   '----'        OOB offset
26   0xACC52FC2   '��/�'        0xD0000000   0x0A031069   '----'        OOB offset
27   0x24A8882F   '$��/'        0xDA882FDA   0x942CBE95   '----'        OOB offset
28   0x30C0B18E   '0���'        0xFAB18EFA   0xB18EFAB1   '----'        OOB offset
29   0x8EFAB18E   '����'        0xFAB18EFA   0x719DBE4A   '----'        OOB offset
30   0xB4C923CA   '��#�'        0xD313061E   0x7428BA88   '----'        OOB offset
31   0x2FDA882F   '/ڈ/'        0xDA882FDA   0x882FDA88   '----'        OOB offset
32   0x30DA8449   '0ڄI'        0xC9463464   0x3D31573D   '----'        OOB offset
33   0x31573D31   '1W=1'        0x573D3157   0x57ACC62F   '----'        OOB offset
34   0xC2CF1E0A   '��
'        0x307D2BC8   0x882FDA88   '----'        OOB offset
35   0x2FDA882F   '/ڈ/'        0xDAA62CBA   0xAB2CB694   '----'        OOB offset
36   0x25985E14   '%�^'        0x4A52113E   0x490F3740   '----'        OOB offset
37   0x0D30370B   '07'        0x290C0209   0x4AB4C943   '----'        OOB offset
38   0x97D5832D   '�Ճ-'        0xD3882FDA   0x882FDA88   '----'        OOB offset
39   0x2FDA882F   '/ڈ/'        0xDABD2AA3   0xC92A98C9   '----'        OOB offset
40   0x2A98C92A   '*��*'        0x98C92A98   0xC92A98C9   '----'        OOB offset
41   0x2A98C92A   '*��*'        0x982C0921   0x2FC2CF68   '----'        OOB offset
42   0x5BD9882F   '[و/'        0xDA882FDA   0x882FDA88   '----'        OOB offset
43   0x2FDA872E   '/ڇ.'        0xD93E1564   0x0200010B   '----'        OOB offset
44   0x02081404   ''        0x0F1D0616   0x26081D2F   '----'        OOB offset
45   0x0923380B   '	#8'        0x2A0B0208   0x22CAD307   '----'        OOB offset
46   0x020B7026   'p&'        0xB3882FDA   0x882FDA84   '----'        OOB offset
47   0x2DD42D0F   '-�-'        0x49000000   0x00000000   '----'        OOB offset
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
72   0x5A2007CE   'Z �'        0x00020009   0x00060031   '----'        OOB offset
73   0x00006163   '    '        0x73704D53   0x46540000   '----'        OOB offset
74   0x00004945   '    '        0x43207352   0x47420000   '----'        OOB offset
75   0x00000000   '    '        0x00000000   0x00000000   'MM  '        overlap
76   0xF6D60001   '��  '        0x00000000   0xD32D4850   'MM  '        OOB size
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

[NOT RUN] Profile TRUNCATED — round-trip validation not run
       Header claims more bytes than file contains (CWE-125)
```

---

## LUT Text Export (`-xt`)

**Exit Code: 2**

```
Error reading ICC profile
Exported 0 text file(s) to /tmp/tmp.ikPDnNRSBT/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
