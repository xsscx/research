/*
 * IccConformanceRequired.h — ICC specification required tag conformance checks
 *
 * Implements CF-040 through CF-053 from the conformance registry.
 * Validates required tags per profile class per ICC.1-2022-05 §8.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ICC_CONFORMANCE_REQUIRED_H
#define ICC_CONFORMANCE_REQUIRED_H

class CIccProfile;

int RunRequiredTagConformance(CIccProfile *pIcc, const char *filename = nullptr);

#endif // ICC_CONFORMANCE_REQUIRED_H
