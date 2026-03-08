/*
 * IccHeuristicsLibrary.cpp — Dispatcher for library API heuristics (H9-H138)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * This file dispatches to heuristic functions split across 4 category files:
 * - IccHeuristicsTagValidation.cpp     (H9-H32)
 * - IccHeuristicsDataValidation.cpp    (H56-H102)
 * - IccHeuristicsProfileCompliance.cpp (H103-H120)
 * - IccHeuristicsIntegrity.cpp         (H121-H138)
 */

#include "IccHeuristicsLibrary.h"
#include "IccHeuristicsTagValidation.h"
#include "IccHeuristicsDataValidation.h"
#include "IccHeuristicsProfileCompliance.h"
#include "IccHeuristicsIntegrity.h"
#include "IccAnalyzerSecurity.h"
#include "IccProfile.h"
#include <cstdio>

int RunLibraryAPIHeuristics(CIccProfile *pIcc, const char *filename)
{
  int heuristicCount = 0;

  heuristicCount += RunHeuristic_H9_CriticalTextTags(pIcc);
  heuristicCount += RunHeuristic_H10_TagCount(pIcc);
  heuristicCount += RunHeuristic_H11_CLUTEntryLimit(pIcc);
  heuristicCount += RunHeuristic_H12_MPEChainDepth(pIcc);
  heuristicCount += RunHeuristic_H13_PerTagSizeCheck(pIcc);
  heuristicCount += RunHeuristic_H14_TagArrayDetection(pIcc, filename);
  heuristicCount += RunHeuristic_H18_TechnologySignature(pIcc);
  heuristicCount += RunHeuristic_H19_TagOffsetOverlap(pIcc);
  heuristicCount += RunHeuristic_H20_TagTypeSignature(pIcc, filename);
  heuristicCount += RunHeuristic_H21_TagStructMemberInspection(pIcc);
  heuristicCount += RunHeuristic_H22_NumArrayScalarExpectation(pIcc);
  heuristicCount += RunHeuristic_H23_NumArrayValueRange(pIcc);
  heuristicCount += RunHeuristic_H24_TagStructNestingDepth(pIcc);
  heuristicCount += RunHeuristic_H25_TagOffsetOOB(pIcc, filename);
  heuristicCount += RunHeuristic_H26_NamedColor2StringValidation(pIcc, filename);
  heuristicCount += RunHeuristic_H27_MPEMatrixOutputChannel(pIcc);
  heuristicCount += RunHeuristic_H28_LUTDimensionValidation(pIcc, filename);
  heuristicCount += RunHeuristic_H29_ColorantTableStringValidation(pIcc, filename);
  heuristicCount += RunHeuristic_H30_GamutBoundaryDescAllocation(pIcc, filename);
  heuristicCount += RunHeuristic_H31_MPEChannelCount(pIcc);
  heuristicCount += RunHeuristic_H32_TagDataTypeConfusion(pIcc, filename);
  heuristicCount += RunHeuristic_H56_CalculatorStackDepth(pIcc);
  heuristicCount += RunHeuristic_H58_SparseMatrixEntryBounds(pIcc);
  heuristicCount += RunHeuristic_H60_DictionaryTagConsistency(pIcc);
  heuristicCount += RunHeuristic_H61_ViewingConditionsValidation(pIcc);
  heuristicCount += RunHeuristic_H62_MLUStringBombs(pIcc);
  heuristicCount += RunHeuristic_H63_CurveLUTChannelMismatch(pIcc);
  heuristicCount += RunHeuristic_H64_NamedColor2DeviceCoordOverflow(pIcc);
  heuristicCount += RunHeuristic_H65_ChromaticityPlausibility(pIcc);
  heuristicCount += RunHeuristic_H66_NumArrayNaNInfScan(pIcc);
  heuristicCount += RunHeuristic_H67_ResponseCurveSetBounds(pIcc);
  heuristicCount += RunHeuristic_H70_MeasurementTagValidation(pIcc);
  heuristicCount += RunHeuristic_H71_ColorantTableNullTermination(pIcc);
  heuristicCount += RunHeuristic_H72_SparseMatrixArrayBounds(pIcc);
  heuristicCount += RunHeuristic_H73_TagArrayNestingDepth(pIcc);
  heuristicCount += RunHeuristic_H74_TagTypeSignatureConsistency(pIcc);
  heuristicCount += RunHeuristic_H75_TagsVerySmallSize(pIcc);
  heuristicCount += RunHeuristic_H76_CIccTagDataTypeFlag(pIcc);
  heuristicCount += RunHeuristic_H77_MPECalculatorSubElementCount(pIcc);
  heuristicCount += RunHeuristic_H78_CLUTGridDimensionOverflow(pIcc);
  heuristicCount += RunHeuristic_H79_LoadTagAllocationOverflow(pIcc);
  heuristicCount += RunHeuristic_H80_SharedTagPointerUAF(pIcc);
  heuristicCount += RunHeuristic_H81_MPECalculatorIOConsistency(pIcc);
  heuristicCount += RunHeuristic_H82_IOReadSizeOverflow(pIcc);
  heuristicCount += RunHeuristic_H83_FloatNumericArraySize(pIcc);
  heuristicCount += RunHeuristic_H84_LUT3DTransformConsistency(pIcc);
  heuristicCount += RunHeuristic_H85_MPEBufferOverlap(pIcc);
  heuristicCount += RunHeuristic_H86_LocalizedUnicodeBounds(pIcc);
  heuristicCount += RunHeuristic_H87_TRCCurveAnomaly(pIcc);
  heuristicCount += RunHeuristic_H88_ChromaticAdaptationMatrix(pIcc);
  heuristicCount += RunHeuristic_H89_ProfileSequenceDescription(pIcc);
  heuristicCount += RunHeuristic_H90_PreviewTagChannelConsistency(pIcc);
  heuristicCount += RunHeuristic_H91_ColorantOrderValidation(pIcc);
  heuristicCount += RunHeuristic_H92_SpectralViewingConditions(pIcc);
  heuristicCount += RunHeuristic_H93_EmbeddedProfileFlag(pIcc);
  heuristicCount += RunHeuristic_H94_MatrixTRCColorantConsistency(pIcc);
  heuristicCount += RunHeuristic_H95_SparseMatrixArrayBoundsValidation(pIcc);
  heuristicCount += RunHeuristic_H96_EmbeddedProfileValidation(pIcc);
  heuristicCount += RunHeuristic_H97_ProfileSequenceIdValidation(pIcc);
  heuristicCount += RunHeuristic_H98_SpectralMPEElementValidation(pIcc);
  heuristicCount += RunHeuristic_H99_EmbeddedImageTagValidation(pIcc);
  heuristicCount += RunHeuristic_H100_ProfileSequenceDescValidation(pIcc);
  heuristicCount += RunHeuristic_H101_MPESubElementChannelContinuity(pIcc);
  heuristicCount += RunHeuristic_H102_TagSizeProfileSizeCrossCheck(pIcc);

  return heuristicCount;
}


// =====================================================================
// H103: Profile Connection Conditions (PCC) Validation
// Exercises IccPcc.cpp — viewing conditions, illuminant, observer
// =====================================================================
