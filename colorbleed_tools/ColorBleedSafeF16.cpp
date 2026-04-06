/*!
 *  @file ColorBleedSafeF16.cpp
 *  @brief Safe icF16toF override for colorbleed tools
 *
 *  Upstream icF16toF() (IccUtil.cpp) uses unsigned arithmetic for the
 *  exponent bias computation: (icUInt32Number)(exp) - 15 + 127.
 *  When the half-float exponent is less than 15, the subtraction wraps
 *  around producing a huge unsigned value instead of a small negative.
 *  This is undefined behavior under UBSAN and produces wrong float values.
 *
 *  This file provides a safe reimplementation using signed arithmetic
 *  (icInt32Number) for the exponent bias. It is linked BEFORE
 *  libIccProfLib2-static.a so the linker picks our definition.
 *
 *  Bug: CFL-061 (latent since initial commit 1f0a9dd, 2015)
 *  CWE: CWE-191 (unsigned integer underflow)
 *
 *  Copyright (c) 2021-2026 David H Hoyt LLC
 *  License: GPL-3.0-or-later
 */

#include <cstring>
#include "IccUtil.h"

#ifdef USEICCDEVNAMESPACE
namespace iccDEV {
#endif

icFloat32Number ICCPROFLIB_API icF16toF(icFloat16Number num)
{
  const icUInt32Number sign = (static_cast<icUInt32Number>(num & 0x8000u) << 16);
  const icUInt32Number exp  = (num >> 10) & 0x1Fu;
  icUInt32Number mant       = num & 0x03FFu;
  icUInt32Number bits       = 0;

  if ((num & 0x7FFFu) == 0) {
    /* Signed zero */
    bits = static_cast<icUInt32Number>(num) << 16;
  } else if (exp == 0) {
    /* Subnormal: normalize mantissa, compute biased exponent with signed math */
    int shift = -1;
    do {
      shift++;
      mant <<= 1;
    } while ((mant & 0x0400u) == 0);

    const icInt32Number exp32 = 127 - 15 - shift;
    bits = sign |
           (static_cast<icUInt32Number>(exp32) << 23) |
           ((mant & 0x03FFu) << 13);
  } else if (exp == 0x1Fu) {
    /* Inf / NaN */
    if (mant == 0) {
      bits = sign | 0x7F800000u;
    } else {
      bits = 0xFFC00000u;  /* Quiet NaN */
    }
  } else {
    /* Normal: signed exponent bias avoids unsigned underflow */
    const icInt32Number exp32 = static_cast<icInt32Number>(exp) - 15 + 127;
    bits = sign |
           (static_cast<icUInt32Number>(exp32) << 23) |
           (mant << 13);
  }

  icFloat32Number rv;
  std::memcpy(&rv, &bits, sizeof(rv));
  return rv;
}

#ifdef USEICCDEVNAMESPACE
}
#endif
