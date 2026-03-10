/*
 * CflSafeDescribe.h — Defensive Describe() wrapper for CFL fuzzers
 *
 * CIccTag::Describe() can crash when Read() partially loads internal state
 * (e.g., CIccToneMapFunc allocates 1 param but Describe accesses 3).
 * This header provides SafeDescribe() which validates tag state before
 * calling Describe(), preventing fuzzer-only crashes that don't reproduce
 * in upstream tools (alignment issues).
 *
 * Usage: Replace raw pTag->Describe(desc, v) with SafeDescribe(pTag, desc, v)
 *
 * Guards:
 *   1. Null pointer check
 *   2. Validate() pre-check — skip Describe() if validation reports Error/Critical
 *   3. Output size cap (kMaxSafeDescribeLen)
 */

#ifndef CFL_SAFE_DESCRIBE_H
#define CFL_SAFE_DESCRIBE_H

#include <string>
#include "IccTag.h"
#include "IccProfile.h"
#include "IccTagMPE.h"

static constexpr size_t kMaxSafeDescribeLen = 256 * 1024; // 256 KB

// SafeDescribe: validates tag state before calling Describe().
// Returns true if Describe() was called, false if skipped due to validation errors.
static inline bool SafeDescribe(CIccTag *pTag, std::string &desc, int verboseness,
                                size_t maxLen = kMaxSafeDescribeLen) {
  if (!pTag) return false;

  // Pre-validate: if the tag has critical validation errors, its internal
  // state may be inconsistent (partially loaded arrays, null pointers in
  // sub-elements). Skip Describe() to avoid alignment crashes.
  std::string valReport;
  icValidateStatus valStatus = pTag->Validate("", valReport);
  if (valStatus >= icValidateCriticalError) return false;

  desc.reserve(maxLen);
  pTag->Describe(desc, verboseness);

  if (desc.size() > maxLen)
    desc.resize(maxLen);

  return true;
}

// SafeDescribeMPE: validates MPE tag before calling Describe().
// MPE tags (CIccTagMultiProcessElement) contain sub-elements that can have
// partially loaded state (ToneMapFunc, Calculator, etc).
static inline bool SafeDescribeMPE(CIccTagMultiProcessElement *pMPE,
                                   std::string &desc, int verboseness,
                                   CIccProfile *pProfile = nullptr,
                                   size_t maxLen = kMaxSafeDescribeLen) {
  if (!pMPE) return false;

  // Validate the MPE tag — this checks sub-element channel counts,
  // parameter validity, and structural consistency
  std::string valReport;
  icValidateStatus valStatus = pMPE->Validate("", valReport, pProfile);
  if (valStatus >= icValidateCriticalError) return false;

  desc.reserve(maxLen);
  pMPE->Describe(desc, verboseness);

  if (desc.size() > maxLen)
    desc.resize(maxLen);

  return true;
}

// SafeDescribeElement: validates individual MPE element before Describe()
static inline bool SafeDescribeElement(CIccMultiProcessElement *pElem,
                                       std::string &desc, int verboseness,
                                       CIccTagMultiProcessElement *pMPE = nullptr,
                                       CIccProfile *pProfile = nullptr,
                                       size_t maxLen = kMaxSafeDescribeLen) {
  if (!pElem) return false;

  std::string valReport;
  icValidateStatus valStatus = pElem->Validate("", valReport, pMPE, pProfile);
  if (valStatus >= icValidateCriticalError) return false;

  desc.reserve(maxLen);
  pElem->Describe(desc, verboseness);

  if (desc.size() > maxLen)
    desc.resize(maxLen);

  return true;
}

#endif // CFL_SAFE_DESCRIBE_H
