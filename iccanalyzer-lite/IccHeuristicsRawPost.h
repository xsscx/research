/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

#ifndef ICCHEURISTICSRAWPOST_H
#define ICCHEURISTICSRAWPOST_H

/// Run raw-file post-library heuristics (H33-H55, H57, H59, H68-H69).
/// Dispatches to individual RunHeuristic_H##_*() functions below.
/// @param filename Path to the ICC profile to analyze
/// @return Number of heuristic warnings detected
int RunRawPostLibraryHeuristics(const char *filename);

/// Run raw-file fallback heuristics (H10, H13, H25, H28, H32) when
/// the library failed to load the profile.
/// @param filename Path to the ICC profile to analyze
/// @param libraryAnalyzed true if CIccProfile loaded successfully
/// @return Number of heuristic warnings detected
int RunRawFallbackHeuristics(const char *filename, bool libraryAnalyzed);

// Individual raw-file heuristic functions (H33-H55, H57, H59, H68-H69).
// Each opens its own FILE*, returns number of findings (0 = OK).
int RunHeuristic_H33_mBAmABSubElementOffset(const char *filename);
int RunHeuristic_H34_IntegerOverflowSubElement(const char *filename);
int RunHeuristic_H35_SuspiciousFillPattern(const char *filename);
int RunHeuristic_H36_LUTTagPairCompleteness(const char *filename);
int RunHeuristic_H37_CalculatorElementComplexity(const char *filename);
int RunHeuristic_H38_CurveDegenerateValue(const char *filename);
int RunHeuristic_H39_SharedTagDataAliasing(const char *filename);
int RunHeuristic_H40_TagAlignmentPadding(const char *filename);
int RunHeuristic_H41_VersionTypeConsistency(const char *filename);
int RunHeuristic_H42_MatrixSingularity(const char *filename);
int RunHeuristic_H43_SpectralBRDFTagStructure(const char *filename);
int RunHeuristic_H44_EmbeddedImageValidation(const char *filename);
int RunHeuristic_H45_SparseMatrixBounds(const char *filename);
int RunHeuristic_H46_TextDescUnicodeLength(const char *filename);
int RunHeuristic_H47_NamedColor2SizeOverflow(const char *filename);
int RunHeuristic_H48_CLUTGridDimensionOverflow(const char *filename);
int RunHeuristic_H49_FloatNaNInfDetection(const char *filename);
int RunHeuristic_H50_ZeroSizeProfileTag(const char *filename);
int RunHeuristic_H51_LUTChannelCountConsistency(const char *filename);
int RunHeuristic_H52_IntegerUnderflowTagSize(const char *filename);
int RunHeuristic_H53_EmbeddedProfileRecursion(const char *filename);
int RunHeuristic_H54_DivisionByZeroTrigger(const char *filename);
int RunHeuristic_H55_UTF16EncodingValidation(const char *filename);
int RunHeuristic_H57_EmbeddedProfileRecursionDepth(const char *filename);
int RunHeuristic_H59_SpectralWavelengthRange(const char *filename);
int RunHeuristic_H68_GamutBoundaryDescOverflow(const char *filename);
int RunHeuristic_H69_ProfileIDMD5Consistency(const char *filename);
int RunHeuristic_H153_SampledCurveNaNCast(const char *filename);

// ── CodeQL-Driven Heuristics (H154-H161) ──
// Derived from CodeQL analysis of iccDEV IccProfLib+IccXML (1,114 findings).
// Each targets a CWE category with ≥9 library sites not covered by H1-H153.
int RunHeuristic_H154_UncontrolledTagAllocationSize(const char *filename);
int RunHeuristic_H155_IntegerOverflowTagDimensions(const char *filename);
int RunHeuristic_H156_AllocationFailurePathProfiles(const char *filename);
int RunHeuristic_H157_AllocDeallocMismatchTagPatterns(const char *filename);
int RunHeuristic_H158_EnumRangeValidationExtended(const char *filename);
int RunHeuristic_H159_UAFTagOwnershipChains(const char *filename);
int RunHeuristic_H160_FormatStringInjectionTextTags(const char *filename);
int RunHeuristic_H161_StackAddressEscapeDeepApply(const char *filename);

// ── Exploit-Gap Heuristics (H162-H165) ──
int RunHeuristic_H162_PartialTagDataOverlap(const char *filename);
int RunHeuristic_H163_ExecutableSignatureInTagData(const char *filename);
int RunHeuristic_H164_RawLUTChannelCrossCheck(const char *filename);
int RunHeuristic_H165_LUTDataSufficiency(const char *filename);

#endif // ICCHEURISTICSRAWPOST_H
