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
#include "IccUtil.h"
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 128) return 0;
  if (size > 10 * 1024 * 1024) return 0;

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

    // Deep validation (exercises tag consistency checks)
    std::string validationReport;
    icValidateStatus status = pProfile->Validate(validationReport);

    // Exercise tag lookup by signature (exercises tag retrieval and validation)
    for (icSignature sig : {
      icSigProfileDescriptionTag,
      icSigCopyrightTag,
      icSigMediaWhitePointTag,
      icSigChromaticAdaptationTag,
      icSigRedColorantTag,
      icSigGreenColorantTag,
      icSigBlueColorantTag,
      icSigRedTRCTag,
      icSigGreenTRCTag,
      icSigBlueTRCTag,
      icSigAToB0Tag,
      icSigBToA0Tag,
      icSigPreview0Tag,
      icSigGamutTag,
      icSigColorantTableTag
    }) {
      CIccTag *pTag = pProfile->FindTag(sig);
      if (pTag) {
        icTagTypeSignature type = pTag->GetType();
        
        // Validate individual tag
        std::string sigPath = "";
        std::string tagReport;
        pTag->Validate(sigPath, tagReport, pProfile);
      }
    }

    delete pProfile;

  } catch (...) {
    if (pProfile) delete pProfile;
  }

  return 0;
}
