/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

#ifndef ICCHEURISTICSRAWPOST_H
#define ICCHEURISTICSRAWPOST_H

// Sub-module headers (split from this file for maintainability)
#include "IccHeuristicsCodeQLPatterns.h"
#include "IccHeuristicsExploitGap.h"
#include "IccHeuristicsHelpers.h"

/// Run raw-file post-library heuristics (H33-H55, H57, H59, H68-H69, H153, H175-H178)
/// plus CodeQL-driven (H154-H161) and exploit-gap (H162-H171) via sub-dispatchers.
/// @param filename Path to the ICC profile to analyze
/// @return Number of heuristic warnings detected
int RunRawPostLibraryHeuristics(const char *filename);

/// Run raw-file fallback heuristics (H10, H13, H25, H28, H32) when
/// the library failed to load the profile.
/// @param filename Path to the ICC profile to analyze
/// @param libraryAnalyzed true if CIccProfile loaded successfully
/// @return Number of heuristic warnings detected
int RunRawFallbackHeuristics(const char *filename, bool libraryAnalyzed);

// Individual raw-file heuristic functions (H33-H55, H57, H59, H68-H69, H153).
// All use shared RawProfileContext (single file open per analysis run).
// Returns number of findings (0 = OK).
int RunHeuristic_H33_mBAmABSubElementOffset(RawProfileContext &ctx);
int RunHeuristic_H34_IntegerOverflowSubElement(RawProfileContext &ctx);
int RunHeuristic_H35_SuspiciousFillPattern(RawProfileContext &ctx);
int RunHeuristic_H36_LUTTagPairCompleteness(RawProfileContext &ctx);
int RunHeuristic_H37_CalculatorElementComplexity(RawProfileContext &ctx);
int RunHeuristic_H152_CurveElementOOMSizeValidation(RawProfileContext &ctx);
bool DetectH152CurveElementOOMSize(const char *filename);
int RunHeuristic_H38_CurveDegenerateValue(RawProfileContext &ctx);
int RunHeuristic_H39_SharedTagDataAliasing(RawProfileContext &ctx);
int RunHeuristic_H40_TagAlignmentPadding(RawProfileContext &ctx);
int RunHeuristic_H41_VersionTypeConsistency(RawProfileContext &ctx);
int RunHeuristic_H42_MatrixSingularity(RawProfileContext &ctx);
int RunHeuristic_H43_SpectralBRDFTagStructure(RawProfileContext &ctx);
int RunHeuristic_H44_EmbeddedImageValidation(RawProfileContext &ctx);
int RunHeuristic_H45_SparseMatrixBounds(RawProfileContext &ctx);
int RunHeuristic_H46_TextDescUnicodeLength(RawProfileContext &ctx);
int RunHeuristic_H47_NamedColor2SizeOverflow(RawProfileContext &ctx);
int RunHeuristic_H48_CLUTGridDimensionOverflow(RawProfileContext &ctx);
int RunHeuristic_H49_FloatNaNInfDetection(RawProfileContext &ctx);
int RunHeuristic_H50_ZeroSizeProfileTag(RawProfileContext &ctx);
int RunHeuristic_H51_LUTChannelCountConsistency(RawProfileContext &ctx);
int RunHeuristic_H52_IntegerUnderflowTagSize(RawProfileContext &ctx);
int RunHeuristic_H53_EmbeddedProfileRecursion(RawProfileContext &ctx);
int RunHeuristic_H54_DivisionByZeroTrigger(RawProfileContext &ctx);
int RunHeuristic_H55_UTF16EncodingValidation(RawProfileContext &ctx);
int RunHeuristic_H57_EmbeddedProfileRecursionDepth(RawProfileContext &ctx);
int RunHeuristic_H59_SpectralWavelengthRange(RawProfileContext &ctx);
int RunHeuristic_H68_GamutBoundaryDescOverflow(RawProfileContext &ctx);
int RunHeuristic_H69_ProfileIDMD5Consistency(RawProfileContext &ctx);
int RunHeuristic_H153_SampledCurveNaNCast(RawProfileContext &ctx);
int RunHeuristic_H175_DeviceSpectralColourSpaceRange(RawProfileContext &ctx);
int RunHeuristic_H176_DsrnTagValidation(RawProfileContext &ctx);
int RunHeuristic_H177_DpccTagValidation(RawProfileContext &ctx);
int RunHeuristic_H178_SrngEncodingValidation(RawProfileContext &ctx);

#endif // ICCHEURISTICSRAWPOST_H
