/*
 * IccHeuristicsLibrary.cpp — Dispatcher for library API heuristics (H9-H138)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * Table-driven dispatch: two arrays of function pointers (profile-only and
 * profile+filename signatures) replace 67 sequential calls.
 */

#include "IccHeuristicsLibrary.h"
#include "IccHeuristicsTagValidation.h"
#include "IccHeuristicsDataValidation.h"
#include "IccHeuristicsProfileCompliance.h"
#include "IccHeuristicsIntegrity.h"
#include "IccAnalyzerSecurity.h"
#include "IccProfile.h"
#include <cstdio>

// Heuristics taking only (CIccProfile*)
using HeuristicFn = int (*)(CIccProfile *);

// Heuristics taking (CIccProfile*, const char* filename)
using HeuristicFnFile = int (*)(CIccProfile *, const char *);

static const HeuristicFn kProfileOnlyHeuristics[] = {
  RunHeuristic_H9_CriticalTextTags,
  RunHeuristic_H10_TagCount,
  RunHeuristic_H11_CLUTEntryLimit,
  RunHeuristic_H12_MPEChainDepth,
  RunHeuristic_H13_PerTagSizeCheck,
  RunHeuristic_H18_TechnologySignature,
  RunHeuristic_H19_TagOffsetOverlap,
  RunHeuristic_H21_TagStructMemberInspection,
  RunHeuristic_H22_NumArrayScalarExpectation,
  RunHeuristic_H23_NumArrayValueRange,
  RunHeuristic_H24_TagStructNestingDepth,
  RunHeuristic_H27_MPEMatrixOutputChannel,
  RunHeuristic_H31_MPEChannelCount,
  RunHeuristic_H56_CalculatorStackDepth,
  RunHeuristic_H58_SparseMatrixEntryBounds,
  RunHeuristic_H60_DictionaryTagConsistency,
  RunHeuristic_H61_ViewingConditionsValidation,
  RunHeuristic_H62_MLUStringBombs,
  RunHeuristic_H63_CurveLUTChannelMismatch,
  RunHeuristic_H64_NamedColor2DeviceCoordOverflow,
  RunHeuristic_H65_ChromaticityPlausibility,
  RunHeuristic_H66_NumArrayNaNInfScan,
  RunHeuristic_H67_ResponseCurveSetBounds,
  RunHeuristic_H70_MeasurementTagValidation,
  RunHeuristic_H71_ColorantTableNullTermination,
  RunHeuristic_H72_SparseMatrixArrayBounds,
  RunHeuristic_H73_TagArrayNestingDepth,
  RunHeuristic_H74_TagTypeSignatureConsistency,
  RunHeuristic_H75_TagsVerySmallSize,
  RunHeuristic_H76_CIccTagDataTypeFlag,
  RunHeuristic_H77_MPECalculatorSubElementCount,
  RunHeuristic_H78_CLUTGridDimensionOverflow,
  RunHeuristic_H79_LoadTagAllocationOverflow,
  RunHeuristic_H80_SharedTagPointerUAF,
  RunHeuristic_H81_MPECalculatorIOConsistency,
  RunHeuristic_H82_IOReadSizeOverflow,
  RunHeuristic_H83_FloatNumericArraySize,
  RunHeuristic_H84_LUT3DTransformConsistency,
  RunHeuristic_H85_MPEBufferOverlap,
  RunHeuristic_H86_LocalizedUnicodeBounds,
  RunHeuristic_H87_TRCCurveAnomaly,
  RunHeuristic_H88_ChromaticAdaptationMatrix,
  RunHeuristic_H89_ProfileSequenceDescription,
  RunHeuristic_H90_PreviewTagChannelConsistency,
  RunHeuristic_H91_ColorantOrderValidation,
  RunHeuristic_H92_SpectralViewingConditions,
  RunHeuristic_H93_EmbeddedProfileFlag,
  RunHeuristic_H94_MatrixTRCColorantConsistency,
  RunHeuristic_H95_SparseMatrixArrayBoundsValidation,
  RunHeuristic_H96_EmbeddedProfileValidation,
  RunHeuristic_H97_ProfileSequenceIdValidation,
  RunHeuristic_H98_SpectralMPEElementValidation,
  RunHeuristic_H99_EmbeddedImageTagValidation,
  RunHeuristic_H100_ProfileSequenceDescValidation,
  RunHeuristic_H101_MPESubElementChannelContinuity,
  RunHeuristic_H102_TagSizeProfileSizeCrossCheck,
  RunHeuristic_H146_StackBufferOverflowGetValues,
  RunHeuristic_H147_NullPointerAfterTagRead,
  RunHeuristic_H148_MemcpyBoundsOverlap,
};

static const HeuristicFnFile kFileHeuristics[] = {
  RunHeuristic_H14_TagArrayDetection,
  RunHeuristic_H20_TagTypeSignature,
  RunHeuristic_H25_TagOffsetOOB,
  RunHeuristic_H26_NamedColor2StringValidation,
  RunHeuristic_H28_LUTDimensionValidation,
  RunHeuristic_H29_ColorantTableStringValidation,
  RunHeuristic_H30_GamutBoundaryDescAllocation,
  RunHeuristic_H32_TagDataTypeConfusion,
};

int RunLibraryAPIHeuristics(CIccProfile *pIcc, const char *filename)
{
  int heuristicCount = 0;

  for (auto fn : kProfileOnlyHeuristics)
    heuristicCount += fn(pIcc);

  for (auto fn : kFileHeuristics)
    heuristicCount += fn(pIcc, filename);

  return heuristicCount;
}
