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

#ifndef _ICCANALYZERSAFEARITHMETIC_H
#define _ICCANALYZERSAFEARITHMETIC_H

#include "IccDefs.h"
#include <stdint.h>
#include <limits.h>

/**
 * Checked arithmetic operations for preventing integer overflow vulnerabilities.
 * 
 * NOTE: These are iccAnalyzer-specific utilities and do NOT modify IccProfLib.
 *       They are used for validating ICC profile data during security analysis.
 * 
 * All functions return true if the operation succeeded without overflow,
 * false if overflow would occur. The result pointer is only written on success.
 */

/**
 * Safe 64-bit unsigned addition with overflow detection.
 * 
 * @param result Pointer to store result (only written if no overflow)
 * @param a First operand
 * @param b Second operand
 * @return true if succeeded, false if overflow detected
 */
inline bool SafeAdd64(uint64_t *result, uint64_t a, uint64_t b)
{
  if (a > UINT64_MAX - b) {
    return false;
  }
  *result = a + b;
  return true;
}

/**
 * Safe 64-bit unsigned multiplication with overflow detection.
 * 
 * @param result Pointer to store result (only written if no overflow)
 * @param a First operand
 * @param b Second operand
 * @return true if succeeded, false if overflow detected
 */
inline bool SafeMul64(uint64_t *result, uint64_t a, uint64_t b)
{
  if (a == 0 || b == 0) {
    *result = 0;
    return true;
  }
  
  if (a > UINT64_MAX / b) {
    return false;
  }
  
  *result = a * b;
  return true;
}

/**
 * Safe 32-bit unsigned addition with overflow detection.
 * 
 * @param result Pointer to store result (only written if no overflow)
 * @param a First operand
 * @param b Second operand
 * @return true if succeeded, false if overflow detected
 */
inline bool SafeAdd32(uint32_t *result, uint32_t a, uint32_t b)
{
  if (a > UINT32_MAX - b) {
    return false;
  }
  *result = a + b;
  return true;
}

/**
 * Safe 32-bit unsigned multiplication with overflow detection.
 * 
 * @param result Pointer to store result (only written if no overflow)
 * @param a First operand
 * @param b Second operand
 * @return true if succeeded, false if overflow detected
 */
inline bool SafeMul32(uint32_t *result, uint32_t a, uint32_t b)
{
  if (a == 0 || b == 0) {
    *result = 0;
    return true;
  }
  
  if (a > UINT32_MAX / b) {
    return false;
  }
  
  *result = a * b;
  return true;
}

/**
 * Safe cast from 64-bit to 32-bit with overflow detection.
 * 
 * @param result Pointer to store result (only written if cast is safe)
 * @param value 64-bit value to cast
 * @return true if cast succeeded, false if value > UINT32_MAX
 */
inline bool SafeCast64to32(uint32_t *result, uint64_t value)
{
  if (value > UINT32_MAX) {
    return false;
  }
  *result = (uint32_t)value;
  return true;
}

/**
 * Hard limits for ICC profile resource constraints.
 * These prevent resource exhaustion attacks.
 */
#define ICCANALYZER_MAX_PROFILE_SIZE    (1ULL << 30)  // 1 GiB
#define ICCANALYZER_MAX_TAG_SIZE        (64ULL << 20) // 64 MiB
#define ICCANALYZER_MAX_TAG_COUNT       200
#define ICCANALYZER_MAX_CLUT_ENTRIES    (16ULL << 20) // 16M entries
#define ICCANALYZER_MAX_MPE_ELEMENTS    1024

#endif // _ICCANALYZERSAFEARITHMETIC_H
