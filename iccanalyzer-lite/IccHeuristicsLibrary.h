/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

#ifndef _ICCHEURISTICSLIBRARY_H
#define _ICCHEURISTICSLIBRARY_H

class CIccProfile;

/// Run library-API heuristics (H9-H32, H56-H102) using iccDEV profile API.
/// Dispatcher that calls individual RunHeuristic_H##_*() functions.
/// @param pIcc Loaded ICC profile (must not be null)
/// @param filename Path to the ICC profile (for raw-file fallback reads)
/// @return Number of heuristic warnings detected
int RunLibraryAPIHeuristics(CIccProfile *pIcc, const char *filename);

// H9-H32: Tag structure and content heuristics (extracted from mega-function)
int RunHeuristic_H9_CriticalTextTags(CIccProfile *pIcc);
int RunHeuristic_H10_TagCount(CIccProfile *pIcc);
int RunHeuristic_H11_CLUTEntryLimit(CIccProfile *pIcc);
int RunHeuristic_H12_MPEChainDepth(CIccProfile *pIcc);
int RunHeuristic_H13_PerTagSizeCheck(CIccProfile *pIcc);
int RunHeuristic_H14_TagArrayDetection(CIccProfile *pIcc, const char *filename);
int RunHeuristic_H18_TechnologySignature(CIccProfile *pIcc);
int RunHeuristic_H19_TagOffsetOverlap(CIccProfile *pIcc);
int RunHeuristic_H20_TagTypeSignature(CIccProfile *pIcc, const char *filename);
int RunHeuristic_H21_TagStructMemberInspection(CIccProfile *pIcc);
int RunHeuristic_H22_NumArrayScalarExpectation(CIccProfile *pIcc);
int RunHeuristic_H23_NumArrayValueRange(CIccProfile *pIcc);
int RunHeuristic_H24_TagStructNestingDepth(CIccProfile *pIcc);
int RunHeuristic_H25_TagOffsetOOB(CIccProfile *pIcc, const char *filename);
int RunHeuristic_H26_NamedColor2StringValidation(CIccProfile *pIcc, const char *filename);
int RunHeuristic_H27_MPEMatrixOutputChannel(CIccProfile *pIcc);
int RunHeuristic_H28_LUTDimensionValidation(CIccProfile *pIcc, const char *filename);
int RunHeuristic_H29_ColorantTableStringValidation(CIccProfile *pIcc, const char *filename);
int RunHeuristic_H30_GamutBoundaryDescAllocation(CIccProfile *pIcc, const char *filename);
int RunHeuristic_H31_MPEChannelCount(CIccProfile *pIcc);
int RunHeuristic_H32_TagDataTypeConfusion(CIccProfile *pIcc, const char *filename);

// H56-H102: Advanced validation heuristics (extracted from mega-function)
int RunHeuristic_H56_CalculatorStackDepth(CIccProfile *pIcc);
int RunHeuristic_H58_SparseMatrixEntryBounds(CIccProfile *pIcc);
int RunHeuristic_H60_DictionaryTagConsistency(CIccProfile *pIcc);
int RunHeuristic_H61_ViewingConditionsValidation(CIccProfile *pIcc);
int RunHeuristic_H62_MLUStringBombs(CIccProfile *pIcc);
int RunHeuristic_H63_CurveLUTChannelMismatch(CIccProfile *pIcc);
int RunHeuristic_H64_NamedColor2DeviceCoordOverflow(CIccProfile *pIcc);
int RunHeuristic_H65_ChromaticityPlausibility(CIccProfile *pIcc);
int RunHeuristic_H66_NumArrayNaNInfScan(CIccProfile *pIcc);
int RunHeuristic_H67_ResponseCurveSetBounds(CIccProfile *pIcc);
int RunHeuristic_H70_MeasurementTagValidation(CIccProfile *pIcc);
int RunHeuristic_H71_ColorantTableNullTermination(CIccProfile *pIcc);
int RunHeuristic_H72_SparseMatrixArrayBounds(CIccProfile *pIcc);
int RunHeuristic_H73_TagArrayNestingDepth(CIccProfile *pIcc);
int RunHeuristic_H74_TagTypeSignatureConsistency(CIccProfile *pIcc);
int RunHeuristic_H75_TagsVerySmallSize(CIccProfile *pIcc);
int RunHeuristic_H76_CIccTagDataTypeFlag(CIccProfile *pIcc);
int RunHeuristic_H77_MPECalculatorSubElementCount(CIccProfile *pIcc);
int RunHeuristic_H78_CLUTGridDimensionOverflow(CIccProfile *pIcc);
int RunHeuristic_H79_LoadTagAllocationOverflow(CIccProfile *pIcc);
int RunHeuristic_H80_SharedTagPointerUAF(CIccProfile *pIcc);
int RunHeuristic_H81_MPECalculatorIOConsistency(CIccProfile *pIcc);
int RunHeuristic_H82_IOReadSizeOverflow(CIccProfile *pIcc);
int RunHeuristic_H83_FloatNumericArraySize(CIccProfile *pIcc);
int RunHeuristic_H84_LUT3DTransformConsistency(CIccProfile *pIcc);
int RunHeuristic_H85_MPEBufferOverlap(CIccProfile *pIcc);
int RunHeuristic_H86_LocalizedUnicodeBounds(CIccProfile *pIcc);
int RunHeuristic_H87_TRCCurveAnomaly(CIccProfile *pIcc);
int RunHeuristic_H88_ChromaticAdaptationMatrix(CIccProfile *pIcc);
int RunHeuristic_H89_ProfileSequenceDescription(CIccProfile *pIcc);
int RunHeuristic_H90_PreviewTagChannelConsistency(CIccProfile *pIcc);
int RunHeuristic_H91_ColorantOrderValidation(CIccProfile *pIcc);
int RunHeuristic_H92_SpectralViewingConditions(CIccProfile *pIcc);
int RunHeuristic_H93_EmbeddedProfileFlag(CIccProfile *pIcc);
int RunHeuristic_H94_MatrixTRCColorantConsistency(CIccProfile *pIcc);
int RunHeuristic_H95_SparseMatrixArrayBoundsValidation(CIccProfile *pIcc);
int RunHeuristic_H96_EmbeddedProfileValidation(CIccProfile *pIcc);
int RunHeuristic_H97_ProfileSequenceIdValidation(CIccProfile *pIcc);
int RunHeuristic_H98_SpectralMPEElementValidation(CIccProfile *pIcc);
int RunHeuristic_H99_EmbeddedImageTagValidation(CIccProfile *pIcc);
int RunHeuristic_H100_ProfileSequenceDescValidation(CIccProfile *pIcc);
int RunHeuristic_H101_MPESubElementChannelContinuity(CIccProfile *pIcc);
int RunHeuristic_H102_TagSizeProfileSizeCrossCheck(CIccProfile *pIcc);

/// H103: PCC (Profile Connection Conditions) validation
int RunHeuristic_H103_PCC(CIccProfile *pIcc);

/// H104: PRMG (Perceptual Reference Medium Gamut) evaluation
int RunHeuristic_H104_PRMG(CIccProfile *pIcc, const char *profilePath);

/// H105: Matrix-TRC validation (determinant, inversion, chromaticity)
int RunHeuristic_H105_MatrixTRC(CIccProfile *pIcc);

/// H106: Environment variable and spectral viewing condition tags
int RunHeuristic_H106_EnvVar(CIccProfile *pIcc);

/// H107: LUT channel count vs colorspace cross-check (CWE-121/CWE-131)
int RunHeuristic_H107_ChannelCrossCheck(CIccProfile *pIcc);

/// H108: Private/unregistered tag identification (CWE-829)
int RunHeuristic_H108_PrivateTags(CIccProfile *pIcc);

/// H109: NOP sled / shellcode pattern scan (CWE-506)
int RunHeuristic_H109_ShellcodePatterns(const char *filename);

/// H110: Profile-class required tag validation (CWE-20)
int RunHeuristic_H110_ClassTagValidation(CIccProfile *pIcc);

/// H111: Reserved byte validation (CWE-20)
int RunHeuristic_H111_ReservedBytes(const char *filename);

/// H112: Wtpt profile-class validation (CWE-20)
int RunHeuristic_H112_WtptValidation(CIccProfile *pIcc);

/// H113: Round-trip fidelity assessment (CWE-682)
int RunHeuristic_H113_RoundTripFidelity(CIccProfile *pIcc);

/// H114: TRC curve smoothness and monotonicity (CWE-682)
int RunHeuristic_H114_CurveSmoothness(CIccProfile *pIcc);

/// H115: Characterization data presence (CWE-20)
int RunHeuristic_H115_CharacterizationData(CIccProfile *pIcc);

// H116-H127: ICC Technical Secretary feedback heuristics
int RunHeuristic_H116_CprtDescEncoding(CIccProfile *pIcc);
int RunHeuristic_H117_TagTypeAllowed(CIccProfile *pIcc);
int RunHeuristic_H118_CalcCostEstimate(CIccProfile *pIcc);
int RunHeuristic_H119_RoundTripDeltaE(CIccProfile *pIcc);
int RunHeuristic_H120_CurveInvertibility(CIccProfile *pIcc);
int RunHeuristic_H121_CharDataRoundTrip(CIccProfile *pIcc);
int RunHeuristic_H122_TagEncoding(CIccProfile *pIcc);
int RunHeuristic_H123_NonRequiredTags(CIccProfile *pIcc);
int RunHeuristic_H124_VersionTags(CIccProfile *pIcc);
int RunHeuristic_H125_TransformSmoothness(CIccProfile *pIcc);
int RunHeuristic_H126_PrivateTagMalware(CIccProfile *pIcc, const char *filename);
int RunHeuristic_H127_PrivateTagRegistry(CIccProfile *pIcc);

// H128-H132: ICC.1-2022-05 specification compliance heuristics
/// H128: Version BCD encoding validation (§7.2.4)
int RunHeuristic_H128_VersionBCD(const char *filename);
/// H129: PCS illuminant exact D50 validation (§7.2.16)
int RunHeuristic_H129_PCSIlluminantD50(const char *filename);
/// H130: Tag data 4-byte alignment check (§7.3.1)
int RunHeuristic_H130_TagAlignment(const char *filename);
/// H131: Profile ID MD5 validation (§7.2.18)
int RunHeuristic_H131_ProfileIdMD5(const char *filename);
/// H132: chromaticAdaptation matrix determinant check (Annex G)
int RunHeuristic_H132_ChadDeterminant(CIccProfile *pIcc);

// H133-H135: ICC.1-2022-05 additional spec compliance heuristics
/// H133: Profile flags reserved bits (§7.2.11) — bits 2-15 must be zero
int RunHeuristic_H133_FlagsReservedBits(const char *filename);
/// H134: Tag type reserved bytes (§10.1) — bytes 4-7 of all tag types must be zero
int RunHeuristic_H134_TagTypeReservedBytes(CIccProfile *pIcc, const char *filename);
/// H135: Duplicate tag signatures (§7.3.1) — no duplicates in tag table
int RunHeuristic_H135_DuplicateTagSignatures(const char *filename);
/// H136: ResponseCurveStruct per-channel measurement count (CWE-400)
int RunHeuristic_H136_ResponseCurveMeasurementCount(const char *filename);
/// H137: High-dimensional color space grid complexity (CWE-400)
int RunHeuristic_H137_HighDimensionalGridComplexity(CIccProfile *pIcc);
/// H138: Calculator element branching depth (CWE-400/CWE-674)
int RunHeuristic_H138_CalculatorBranchingDepth(CIccProfile *pIcc);

#endif // _ICCHEURISTICSLIBRARY_H
