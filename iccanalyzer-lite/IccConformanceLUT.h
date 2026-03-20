/*
 * IccConformanceLUT.h — ICC specification LUT/curve structure conformance checks
 *
 * Implements CF-060 through CF-070 from the conformance registry.
 * Validates lut8Type, lut16Type, lutAToBType, lutBToAType tags and
 * matrix tags against ICC.1-2022-05 §9-10 requirements.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ICC_CONFORMANCE_LUT_H
#define ICC_CONFORMANCE_LUT_H

class CIccProfile;

int RunLUTConformance(CIccProfile *pIcc);

#endif // ICC_CONFORMANCE_LUT_H
