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
 *   4. CIccTagUnknown skip — Describe() calls icMemDump() which allocates ~5×m_nSize
 *      for hex representation. Corrupted tags with size < 8 cause uint32 underflow
 *      in m_nSize (e.g., cprt size=5 → m_nSize=0xFFFFFFFD → 21GB alloc, CWE-789).
 *      Raw hex dumps don't exercise interesting code paths for fuzzer coverage.
 */

#ifndef CFL_SAFE_DESCRIBE_H
#define CFL_SAFE_DESCRIBE_H

#include <string>
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagComposite.h"
#include "IccProfile.h"
#include "IccTagMPE.h"

static constexpr size_t kMaxSafeDescribeLen = 256 * 1024; // 256 KB

// SafeDescribe: validates tag state before calling Describe().
// Returns true if Describe() was called, false if skipped due to validation errors.
static inline bool SafeDescribe(CIccTag *pTag, std::string &desc, int verboseness,
                                size_t maxLen = kMaxSafeDescribeLen) {
  if (!pTag) return false;

  // Skip CIccTagUnknown — Describe() calls icMemDump() which allocates ~5×m_nSize
  // bytes for hex output. When tag size < 8 bytes (e.g., cprt with size=5),
  // CIccTagUnknown::Read() underflows: m_nSize = uint32(5-8) = 0xFFFFFFFD,
  // causing icMemDump to reserve ~21GB (CWE-789). Raw hex dumps don't exercise
  // useful code paths — all interesting coverage is in typed tag Describe().
  if (dynamic_cast<CIccTagUnknown*>(pTag)) return false;

  // Skip CIccTagStruct/CIccTagArray containing CIccTagUnknown sub-tags.
  // CIccTagStruct::Describe() → CIccStructUnknown::Describe() iterates sub-tags
  // and calls pTag->Describe() directly, bypassing SafeDescribe. If any sub-tag
  // is CIccTagUnknown with underflowed m_nSize, it triggers the same 21GB OOM.
  if (auto *pStruct = dynamic_cast<CIccTagStruct*>(pTag)) {
    TagEntryList *entries = pStruct->GetElemList();
    if (entries) {
      for (auto it = entries->begin(); it != entries->end(); ++it) {
        if (it->pTag && dynamic_cast<CIccTagUnknown*>(it->pTag))
          return false;
      }
    }
  }

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

  // CFL-006: Guard spectral matrix elements against Describe() HBO.
  // Use element type signature — avoids including IccMpeSpectral.h which
  // has broken CLUT subclass constructors in upstream v2.3.1.5.
  icElemTypeSignature elemType = pElem->GetType();
  if (elemType == icSigEmissionMatrixElemType ||
      elemType == icSigInvEmissionMatrixElemType) {
    icUInt16Number numIn = pElem->NumInputChannels();
    icUInt16Number numOut = pElem->NumOutputChannels();
    if (numIn == 0 || numOut == 0)
      return false;
    // EmissionMatrix: numVectors()=numIn, Describe() iterates numOut rows
    if (elemType == icSigEmissionMatrixElemType && numOut > numIn)
      return false;
  }

  desc.reserve(maxLen);
  pElem->Describe(desc, verboseness);

  if (desc.size() > maxLen)
    desc.resize(maxLen);

  return true;
}

#endif // CFL_SAFE_DESCRIBE_H
