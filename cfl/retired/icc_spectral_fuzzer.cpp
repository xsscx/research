/** @file
    File:       icc_spectral_fuzzer.cpp
    Contains:   LibFuzzer harness for ICC v5 spectral profile processing
    Version:    V2
    Copyright:  (c) see Software License

    Fuzzer for: iccDEV spectral processing paths
    Tool Alignment:
      - IccDumpProfile (Describe of spectral tags + header spectral fields)
      - IccV5DspObsToV4Dsp (MPE Begin/Apply on spectral emission/observer elements)
      - IccApplyNamedCmm (CMM spectral intent 100+)

    TOOL FIDELITY (V2 improvements over V1):
      V1 only called FindTag() + Validate() - missed all deep spectral paths.
      V2 exercises the full spectral MPE pipeline:
        1. Profile Read + tag loading (all spectral tag types)
        2. Describe() on spectral tags (IccDumpProfile alignment)
        3. MPE element extraction + type-checked Begin()/Apply() cycle
        4. SpectralViewingConditions Read/Write/Describe round-trip
        5. SpectralDataInfo validation paths
        6. Profile-level Validate() with spectral-specific checks

    Target API Surface (IccMpeSpectral.cpp - 2145 LOC):
      - CIccMpeSpectralMatrix::Read/Describe/Validate
      - CIccMpeEmissionMatrix::Begin/Apply
      - CIccMpeInvEmissionMatrix::Begin/Apply/Validate
      - CIccMpeSpectralCLUT::Read/Describe/Apply/Validate
      - CIccMpeEmissionCLUT::Begin
      - CIccMpeReflectanceCLUT::Begin
      - CIccMpeSpectralObserver::Read/Describe/Apply/Validate
      - CIccMpeEmissionObserver::Begin
      - CIccMpeReflectanceObserver::Begin

    Target API Surface (IccTagBasic.cpp spectral tags):
      - CIccTagSpectralViewingConditions::Read/Write/Describe/Validate
      - CIccTagSpectralDataInfo::Read/Write/Describe/Validate
*/

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

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"
#include "IccMpeSpectral.h"
#include "IccUtil.h"
#include "IccCmm.h"
#include "CflSafeDescribe.h"
#include <stdint.h>
#include <stddef.h>
#include <new>
#include <cstring>
#include <string>
#include <memory>

// Spectral tag signatures to probe
static const icTagSignature kSpectralTags[] = {
  icSigSpectralViewingConditionsTag,
  icSigSpectralWhitePointTag,
  icSigSpectralDataInfoTag,
  icSigCustomToStandardPccTag,
  icSigStandardToCustomPccTag,
  icSigColorEncodingParamsTag,
  icSigColorSpaceNameTag,
};
static const int kNumSpectralTags = sizeof(kSpectralTags) / sizeof(kSpectralTags[0]);

// MPE tag signatures that may contain spectral elements
static const icTagSignature kMpeTags[] = {
  icSigAToB0Tag,
  icSigAToB1Tag,
  icSigAToB2Tag,
  icSigAToB3Tag,
  icSigBToA0Tag,
  icSigBToA1Tag,
  icSigBToA2Tag,
  icSigBToA3Tag,
  icSigDToB0Tag,
  icSigDToB1Tag,
  icSigDToB2Tag,
  icSigDToB3Tag,
  icSigBToD0Tag,
  icSigBToD1Tag,
  icSigBToD2Tag,
  icSigBToD3Tag,
  icSigCustomToStandardPccTag,
  icSigStandardToCustomPccTag,
  icSigGamutBoundaryDescription0Tag,
  icSigGamutBoundaryDescription1Tag,
  icSigGamutBoundaryDescription2Tag,
  icSigGamutBoundaryDescription3Tag,
};
static const int kNumMpeTags = sizeof(kMpeTags) / sizeof(kMpeTags[0]);

// Spectral MPE element types we want to exercise
static bool IsSpectralElement(icElemTypeSignature sig) {
  switch (sig) {
    case icSigEmissionMatrixElemType:
    case icSigInvEmissionMatrixElemType:
    case icSigEmissionCLUTElemType:
    case icSigReflectanceCLUTElemType:
    case icSigEmissionObserverElemType:
    case icSigReflectanceObserverElemType:
      return true;
    default:
      return false;
  }
}

// OOM guard: check spectral matrix allocation would not blow up
static bool SpectralMatrixSafe(CIccMpeSpectralMatrix *pMtx) {
  const icSpectralRange &r = pMtx->GetRange();
  if (r.steps == 0 || r.steps > 4096) return false;
  icUInt16Number nIn = pMtx->NumInputChannels();
  icUInt16Number nOut = pMtx->NumOutputChannels();
  uint64_t allocEst = (uint64_t)r.steps * (nIn > nOut ? nIn : nOut) * sizeof(icFloatNumber);
  return allocEst < 64 * 1024 * 1024; // 64MB cap
}

// OOM guard: check spectral CLUT allocation
static bool SpectralCLUTSafe(CIccMpeSpectralCLUT *pClut) {
  CIccCLUT *pCLUT = pClut->GetCLUT();
  if (!pCLUT) return false;
  icUInt16Number nIn = pClut->NumInputChannels();
  if (nIn > 8) return false; // grid^8 already huge
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 128 || size > 5 * 1024 * 1024) return 0;

  // Phase 1: In-memory profile parse
  CIccMemIO memIO;
  if (!memIO.Attach((icUInt8Number *)data, (icUInt32Number)size))
    return 0;

  CIccProfile profile;
  if (!profile.Read(&memIO))
    return 0;

  // Phase 2: Exercise spectral tags - Describe + Write round-trip
  // Aligned with IccDumpProfile which calls Describe() on every tag
  for (int i = 0; i < kNumSpectralTags; i++) {
    CIccTag *pTag = profile.FindTag(kSpectralTags[i]);
    if (!pTag) continue;

    // Describe (IccDumpProfile alignment — SafeDescribe validates first)
    std::string desc;
    SafeDescribe(pTag, desc, 100);

    // Write round-trip
    CIccMemIO outIO;
    if (outIO.Alloc((icUInt32Number)(size + 4096), true))
      pTag->Write(&outIO);
  }

  // Phase 3: SpectralViewingConditions deep exercise
  // This is the key PCC tag used by IccV5DspObsToV4Dsp
  CIccTagSpectralViewingConditions *pSvcn =
    dynamic_cast<CIccTagSpectralViewingConditions *>(
      profile.FindTagOfType(icSigSpectralViewingConditionsTag,
                            icSigSpectralViewingConditionsType));
  if (pSvcn) {
    // Describe exercises illuminant/observer name resolution
    std::string svcnDesc;
    SafeDescribe(pSvcn, svcnDesc, 100);

    // Access illuminant data (used by ReflectanceObserver::Begin)
    icSpectralRange illumRange;
    pSvcn->getIlluminant(illumRange);

    // Validation catches bad spectral ranges, missing illuminants
    std::string svcnReport;
    pSvcn->Validate("svcn", svcnReport, &profile);
  }

  // Phase 4: SpectralDataInfo exercise
  CIccTagSpectralDataInfo *pSdi =
    dynamic_cast<CIccTagSpectralDataInfo *>(
      profile.FindTagOfType(icSigSpectralDataInfoTag,
                            icSigSpectralDataInfoType));
  if (pSdi) {
    std::string sdiDesc;
    SafeDescribe(pSdi, sdiDesc, 100);
    std::string sdiReport;
    pSdi->Validate("sdi", sdiReport, &profile);
  }

  // Phase 5: MPE spectral element exercise
  // IccV5DspObsToV4Dsp extracts MPE elements and calls Begin/Apply directly
  for (int t = 0; t < kNumMpeTags; t++) {
    CIccTagMultiProcessElement *pMpe =
      dynamic_cast<CIccTagMultiProcessElement *>(
        profile.FindTagOfType(kMpeTags[t], icSigMultiProcessElementType));
    if (!pMpe) continue;

    // Describe the MPE tag (IccDumpProfile alignment — SafeDescribe validates first)
    std::string mpeDesc;
    SafeDescribeMPE(pMpe, mpeDesc, 100, &profile);

    // Validate (catches channel mismatches, range errors)
    std::string mpeReport;
    pMpe->Validate("mpe", mpeReport, &profile);

    // Enumerate elements looking for spectral types
    int nElem = pMpe->NumElements();
    if (nElem > 32) continue; // sanity cap

    for (int e = 0; e < nElem; e++) {
      CIccMultiProcessElement *pElem = pMpe->GetElement(e);
      if (!pElem) continue;

      icElemTypeSignature elemType = pElem->GetType();
      if (!IsSpectralElement(elemType)) continue;

      // Describe the element
      std::string elemDesc;
      SafeDescribeElement(pElem, elemDesc, 100, pMpe, &profile);

      // Validate the element
      std::string elemReport;
      pElem->Validate("elem", elemReport, pMpe, &profile);

      // Try Begin/Apply on spectral matrix elements
      // This is what IccV5DspObsToV4Dsp does with CurveSet + EmissionMatrix
      if (elemType == icSigEmissionMatrixElemType ||
          elemType == icSigInvEmissionMatrixElemType) {
        CIccMpeSpectralMatrix *pMtx = dynamic_cast<CIccMpeSpectralMatrix *>(pElem);
        if (pMtx && SpectralMatrixSafe(pMtx)) {
          // Begin needs PCC - try with the profile itself as PCC source
          if (pMpe->Begin(icElemInterpLinear, &profile, &profile)) {
            // Apply with test pixel data
            icUInt16Number nIn = pMtx->NumInputChannels();
            icUInt16Number nOut = pMtx->NumOutputChannels();
            if (nIn <= 256 && nOut <= 256) {
              icFloatNumber srcPixel[256] = {};
              icFloatNumber dstPixel[256] = {};
              for (int c = 0; c < nIn && c < 256; c++)
                srcPixel[c] = 0.5f;
              pMtx->Apply(nullptr, dstPixel, srcPixel);
            }
          }
        }
      }

      // Try Begin/Apply on spectral CLUT elements
      if (elemType == icSigEmissionCLUTElemType ||
          elemType == icSigReflectanceCLUTElemType) {
        CIccMpeSpectralCLUT *pClut = dynamic_cast<CIccMpeSpectralCLUT *>(pElem);
        if (pClut && SpectralCLUTSafe(pClut)) {
          if (pMpe->Begin(icElemInterpLinear, &profile, &profile)) {
            icUInt16Number nIn = pClut->NumInputChannels();
            icUInt16Number nOut = pClut->NumOutputChannels();
            if (nIn <= 16 && nOut <= 256) {
              icFloatNumber srcPixel[16] = {};
              icFloatNumber dstPixel[256] = {};
              for (int c = 0; c < nIn; c++)
                srcPixel[c] = 0.5f;
              CIccApplyMpe *pApply = pClut->GetNewApply(nullptr);
              if (pApply) {
                pClut->Apply(pApply, dstPixel, srcPixel);
                delete pApply;
              }
            }
          }
        }
      }

      // Try Begin/Apply on spectral observer elements
      if (elemType == icSigEmissionObserverElemType ||
          elemType == icSigReflectanceObserverElemType) {
        CIccMpeSpectralObserver *pObs = dynamic_cast<CIccMpeSpectralObserver *>(pElem);
        if (pObs) {
          icUInt16Number nIn = pObs->NumInputChannels();
          if (nIn <= 256 && nIn > 0) {
            if (pMpe->Begin(icElemInterpLinear, &profile, &profile)) {
              icFloatNumber srcPixel[256] = {};
              icFloatNumber dstPixel[3] = {};
              for (int c = 0; c < nIn && c < 256; c++)
                srcPixel[c] = 1.0f / (float)(nIn);
              pObs->Apply(nullptr, dstPixel, srcPixel);
            }
          }
        }
      }
    }
  }

  // Phase 6: Profile-level validation (spectral header fields, tag requirements)
  std::string fullReport;
  profile.Validate(fullReport);

  // Phase 7: Header spectral field coverage
  // IccDumpProfile prints these - exercise the field access paths
  icHeader &hdr = profile.m_Header;
  (void)hdr.spectralPCS;
  (void)hdr.spectralRange.start;
  (void)hdr.spectralRange.end;
  (void)hdr.spectralRange.steps;
  (void)hdr.biSpectralRange.start;
  (void)hdr.biSpectralRange.end;
  (void)hdr.biSpectralRange.steps;

  // Phase 8: Tag iteration with SafeDescribe() - IccDumpProfile alignment
  // IccDumpProfile iterates all tags and calls Describe on each
  TagEntryList::iterator it;
  for (it = profile.m_Tags.begin(); it != profile.m_Tags.end(); it++) {
    CIccTag *pTag = profile.FindTag(it->TagInfo.sig);
    if (!pTag) continue;
    std::string tagDesc;
    SafeDescribe(pTag, tagDesc, 100);
  }

  return 0;
}
