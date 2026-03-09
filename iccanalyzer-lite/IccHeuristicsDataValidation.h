/*
 * IccHeuristicsDataValidation.h — Data content validation heuristics (H56-H102)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * Extracted from IccHeuristicsLibrary.cpp as part of codebase modernization.
 */

#ifndef ICC_HEURISTICS_DATA_VALIDATION_H
#define ICC_HEURISTICS_DATA_VALIDATION_H

#include "IccDefs.h"
#include "IccProfile.h"

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
int RunHeuristic_H146_StackBufferOverflowGetValues(CIccProfile *pIcc);
int RunHeuristic_H147_NullPointerAfterTagRead(CIccProfile *pIcc);
int RunHeuristic_H148_MemcpyBoundsOverlap(CIccProfile *pIcc);

#endif
