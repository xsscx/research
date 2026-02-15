/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * This software and associated documentation files (the "Software") are the
 * exclusive intellectual property of David H Hoyt LLC.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "David H Hoyt LLC" must not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID H HOYT LLC "AS IS" AND ANY EXPRESSED
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL DAVID H HOYT LLC BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Contact: https://hoyt.net
 */

#ifndef _ICCANALYZERCOMMON_H
#define _ICCANALYZERCOMMON_H

#include <cstdio>

// Lite version: Disable fingerprint database and metrics
// Define ICCANALYZER_LITE at compile time to create distribution binary
#ifndef ICCANALYZER_LITE
  #define ICCANALYZER_ENABLE_FINGERPRINT 1
#else
  #define ICCANALYZER_ENABLE_FINGERPRINT 0
#endif

#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <dirent.h>
#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagLut.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"
#include "IccUtil.h"
#include "IccIO.h"
#include "IccProfLibVer.h"
#include "IccSignatureUtils.h"

// Override upstream diagnostic macros to be non-fatal for the analyzer.
// The originals call __builtin_trap() / assert(false) which crash the tool.
#undef ICC_TRACE_NAN
#ifdef ICC_TRACE_NAN_ENABLED
#include <cmath>
#define ICC_TRACE_NAN(val, label) \
  do { \
    if (std::isnan(static_cast<float>(val))) { \
      union { float f; uint32_t u; } raw; \
      raw.f = static_cast<float>(val); \
      ICC_LOG_WARNING("NaN detected in %s: value=NaN [bits=0x%08x]", label, raw.u); \
    } \
  } while(0)
#else
#define ICC_TRACE_NAN(val, label) ((void)0)
#endif

#undef ICC_SANITY_CHECK_SIGNATURE
#define ICC_SANITY_CHECK_SIGNATURE(sig, label) \
  do { \
    if (((sig) & 0xFF000000) == 0x3F000000) { \
      ICC_LOG_WARNING("%s: suspicious signature 0x%08x", \
                      label, (uint32_t)(sig)); \
    } \
  } while(0)

#endif // _ICCANALYZERCOMMON_H
