/*
 * IccConformanceTagTypes.h — ICC specification tag type conformance checks
 *
 * Implements CF-020 through CF-034 from the conformance registry.
 * Validates that tag signatures use only ICC-permitted tag types.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ICC_CONFORMANCE_TAG_TYPES_H
#define ICC_CONFORMANCE_TAG_TYPES_H

class CIccProfile;

int RunTagTypeConformance(CIccProfile *pIcc, const char *filename);

#endif // ICC_CONFORMANCE_TAG_TYPES_H
