/*
 * IccConformanceHeader.h — ICC specification header conformance checks
 *
 * Implements CF-001 through CF-015 from the conformance registry.
 * Validates ICC profile header fields against ICC.1-2022-05 requirements.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ICC_CONFORMANCE_HEADER_H
#define ICC_CONFORMANCE_HEADER_H

class CIccProfile;

int RunHeaderConformance(CIccProfile *pIcc, const char *filename);

#endif // ICC_CONFORMANCE_HEADER_H
