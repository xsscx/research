/*
 * IccHeuristicsIntegrity.h — Profile integrity heuristics (H121-H138)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * Extracted from IccHeuristicsLibrary.cpp as part of codebase modernization.
 */

#ifndef ICC_HEURISTICS_INTEGRITY_H
#define ICC_HEURISTICS_INTEGRITY_H

#include "IccDefs.h"
#include "IccProfile.h"

int RunHeuristic_H121_CharDataRoundTrip(CIccProfile *pIcc);
int RunHeuristic_H122_TagEncoding(CIccProfile *pIcc);
int RunHeuristic_H123_NonRequiredTags(CIccProfile *pIcc);
int RunHeuristic_H124_VersionTags(CIccProfile *pIcc);
int RunHeuristic_H125_TransformSmoothness(CIccProfile *pIcc);
int RunHeuristic_H126_PrivateTagMalware(CIccProfile *pIcc, const char *filename);
int RunHeuristic_H127_PrivateTagRegistry(CIccProfile *pIcc);
int RunHeuristic_H128_VersionBCD(const char *filename);
int RunHeuristic_H129_PCSIlluminantD50(const char *filename);
int RunHeuristic_H130_TagAlignment(const char *filename);
int RunHeuristic_H131_ProfileIdMD5(const char *filename);
int RunHeuristic_H132_ChadDeterminant(CIccProfile *pIcc);
int RunHeuristic_H133_FlagsReservedBits(const char *filename);
int RunHeuristic_H134_TagTypeReservedBytes(CIccProfile *pIcc, const char *filename);
int RunHeuristic_H135_DuplicateTagSignatures(const char *filename);
int RunHeuristic_H136_ResponseCurveMeasurementCount(const char *filename);
int RunHeuristic_H137_HighDimensionalGridComplexity(CIccProfile *pIcc);
int RunHeuristic_H138_CalculatorBranchingDepth(CIccProfile *pIcc);

/// Sub-dispatcher for profile integrity heuristics (H121-H135, H137-H138).
/// NOTE: H136 (ResponseCurveMeasurementCount) is excluded — it is a raw-file
/// scan that must always run regardless of library load success.
/// It is called separately in IccAnalyzerSecurity.cpp.
/// @param pIcc Profile loaded via CIccProfile (must not be NULL)
/// @param filename Path for heuristics needing raw file access
/// @return Number of heuristic warnings detected
int RunIntegrityHeuristics(CIccProfile *pIcc, const char *filename);

#endif
