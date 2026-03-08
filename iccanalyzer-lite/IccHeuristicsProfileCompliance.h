/*
 * IccHeuristicsProfileCompliance.h — Profile compliance heuristics (H103-H120)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * Extracted from IccHeuristicsLibrary.cpp as part of codebase modernization.
 */

#ifndef ICC_HEURISTICS_PROFILE_COMPLIANCE_H
#define ICC_HEURISTICS_PROFILE_COMPLIANCE_H

#include "IccDefs.h"
#include "IccProfile.h"

int RunHeuristic_H103_PCC(CIccProfile *pIcc);
int RunHeuristic_H104_PRMG(CIccProfile *pIcc, const char *profilePath);
int RunHeuristic_H105_MatrixTRC(CIccProfile *pIcc);
int RunHeuristic_H106_EnvVar(CIccProfile *pIcc);
int RunHeuristic_H107_ChannelCrossCheck(CIccProfile *pIcc);
int RunHeuristic_H108_PrivateTags(CIccProfile *pIcc);
int RunHeuristic_H109_ShellcodePatterns(const char *filename);
int RunHeuristic_H110_ClassTagValidation(CIccProfile *pIcc);
int RunHeuristic_H111_ReservedBytes(const char *filename);
int RunHeuristic_H112_WtptValidation(CIccProfile *pIcc);
int RunHeuristic_H113_RoundTripFidelity(CIccProfile *pIcc);
int RunHeuristic_H114_CurveSmoothness(CIccProfile *pIcc);
int RunHeuristic_H115_CharacterizationData(CIccProfile *pIcc);
int RunHeuristic_H116_CprtDescEncoding(CIccProfile *pIcc);
int RunHeuristic_H117_TagTypeAllowed(CIccProfile *pIcc);
int RunHeuristic_H118_CalcCostEstimate(CIccProfile *pIcc);
int RunHeuristic_H119_RoundTripDeltaE(CIccProfile *pIcc);
int RunHeuristic_H120_CurveInvertibility(CIccProfile *pIcc);

#endif
