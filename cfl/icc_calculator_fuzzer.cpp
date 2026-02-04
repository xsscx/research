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
#include "IccTagLut.h"
#include "IccUtil.h"
#include "IccMpeFactory.h"
#include <stdint.h>
#include <stddef.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 128) return 0;
  if (size > 5 * 1024 * 1024) return 0;  // Max 5MB

  CIccProfile *pProfile = nullptr;
  CIccMemIO *pIO = nullptr;

  try {
    pIO = new CIccMemIO;
    if (!pIO) return 0;

    if (!pIO->Attach((icUInt8Number*)data, size)) {
      delete pIO;
      return 0;
    }

    pProfile = new CIccProfile;
    if (!pProfile) {
      delete pIO;
      return 0;
    }

    if (!pProfile->Attach(pIO)) {
      delete pProfile;
      delete pIO;
      return 0;
    }

    // Find and exercise calculator-containing tags
    // Process only first matching tag to avoid CMM lifecycle issues
    for (icSignature sig : {
      icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, icSigAToB3Tag,
      icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, icSigBToA3Tag,
      icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag, icSigDToB3Tag,
      icSigGamutTag, icSigPreview0Tag, icSigPreview1Tag, icSigPreview2Tag
    }) {
      CIccTag *pTag = pProfile->FindTag(sig);
      if (!pTag) continue;

      // Validate tag (triggers calculator validation)
      std::string sigPath = "";
      std::string report;
      pTag->Validate(sigPath, report, pProfile);

      // Attempt to write (exercises serialization) - BEFORE CMM ops
      CIccMemIO *pOutIO = new CIccMemIO;
      if (pOutIO) {
        pOutIO->Alloc(size + 4096);
        pTag->Write(pOutIO);
        delete pOutIO;
      }

      // Exercise LUT/MPE type-specific paths
      icTagTypeSignature tagType = pTag->GetType();
      if (tagType == icSigLutAtoBType || tagType == icSigLutBtoAType) {
        // Exercise MPE chain traversal and calculator elements
        CIccTagLutAtoB *pLut = (CIccTagLutAtoB*)pTag;
        if (pLut) {
          // Trigger MPE chain validation and channel info
          icUInt16Number nInputChannels = pLut->InputChannels();
          icUInt16Number nOutputChannels = pLut->OutputChannels();
          
          // Exercise tag description
          std::string desc;
          pTag->Describe(desc, 100);
        }
      }

      // Only process first matching tag
      break;
    }

    // Overall profile validation
    std::string validationReport;
    pProfile->Validate(validationReport);

    delete pProfile;

  } catch (...) {
    if (pProfile) delete pProfile;
  }

  return 0;
}
