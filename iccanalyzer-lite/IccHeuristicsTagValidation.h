/*
 * IccHeuristicsTagValidation.h — Tag structure validation heuristics (H9-H32)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * Extracted from IccHeuristicsLibrary.cpp as part of codebase modernization.
 */

#ifndef ICC_HEURISTICS_TAG_VALIDATION_H
#define ICC_HEURISTICS_TAG_VALIDATION_H

#include "IccDefs.h"
#include "IccProfile.h"

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

#endif
