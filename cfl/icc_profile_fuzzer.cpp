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

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <cmath>
#include "IccProfile.h"
#include "IccUtil.h"
#include "IccIO.h"
#include "IccTag.h"
#include "IccTagLut.h"
#include "IccMpeBasic.h"
#include "IccCmm.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 128) return 0;
  
  CIccProfile *pIcc = OpenIccProfile(data, size);
  if (pIcc) {
    std::string report;
    pIcc->Validate(report);
    
    // Exercise header fields
    volatile icUInt32Number tmp;
    tmp = pIcc->m_Header.size;
    tmp = pIcc->m_Header.version;
    tmp = pIcc->m_Header.deviceClass;
    tmp = pIcc->m_Header.colorSpace;
    tmp = pIcc->m_Header.pcs;
    tmp = pIcc->m_Header.renderingIntent;
    tmp = pIcc->m_Header.manufacturer;
    tmp = pIcc->m_Header.model;
    tmp = pIcc->m_Header.attributes;
    tmp = pIcc->m_Header.flags;
    (void)tmp;
    
    // Exercise all tag iteration with deeper testing
    TagEntryList::iterator i;
    for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
      if (i->pTag) {
        std::string desc;
        i->pTag->Describe(desc, 100);
        i->pTag->GetType();
        i->pTag->IsArrayType();
        i->pTag->IsSupported();
        i->pTag->GetTagArrayType();
        i->pTag->GetTagStructType();
      }
    }
    
    // Exercise expanded tag lookups for maximum coverage
    icSignature tags[] = {icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
                           icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
                           icSigRedColorantTag, icSigGreenColorantTag, icSigBlueColorantTag,
                           icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag,
                           icSigGrayTRCTag, icSigMediaWhitePointTag, icSigMediaBlackPointTag,
                           icSigCopyrightTag, icSigProfileDescriptionTag, icSigChromaticAdaptationTag,
                           icSigNamedColor2Tag, icSigColorantTableTag, icSigColorantOrderTag,
                           icSigMeasurementTag, icSigLuminanceTag, icSigViewingCondDescTag,
                           icSigTechnologyTag, icSigDeviceMfgDescTag, icSigDeviceModelDescTag,
                           icSigProfileSequenceDescTag, icSigDToB0Tag, icSigDToB1Tag, icSigDToB2Tag,
                           icSigDToB3Tag, icSigBToD0Tag, icSigBToD1Tag, icSigBToD2Tag, icSigBToD3Tag,
                           icSigGamutTag, icSigPreview0Tag, icSigPreview1Tag, icSigPreview2Tag,
                           icSigCicpTag, icSigMetaDataTag, icSigSpectralWhitePointTag};
    for (int j = 0; j < 41; j++) {
      CIccTag *tag = pIcc->FindTag(tags[j]);
      if (tag) {
        std::string desc, rpt;
        tag->Describe(desc, 50);
        tag->Validate("", rpt);
        tag->GetType();
        tag->IsSupported();
      }
    }
    
    // Test device class specific methods
    pIcc->GetSpaceSamples();
    pIcc->AreTagsUnique();
    pIcc->GetParentSpaceSamples();
    pIcc->GetParentColorSpace();
    
    // Test serialization if profile is valid (before CMM ownership transfer)
    if (report.find("Error") == std::string::npos && size < 100000) {
      CIccMemIO io;
      if (pIcc->Write(&io)) {
        icUInt32Number len = io.GetLength();
        if (len > 0 && len < 200000) {
          io.Seek(0, icSeekSet);
          icUInt8Number *buf = new icUInt8Number[len];
          io.Read8(buf, len);
          delete[] buf;
        }
      }
    }
    
    // DEEP EXECUTION: Apply actual color transformations via CMM
    CIccCmm *pCmm = new CIccCmm();
    if (pCmm) {
      if (pCmm->AddXform(pIcc, icPerceptual) == icCmmStatOk) {
        // CMM now owns pIcc and will delete it in destructor
        // Must call Begin() before Apply() to initialize m_pApply
        if (pCmm->Begin() == icCmmStatOk) {
          // Test with edge case pixel values
          icFloatNumber test_pixels[][4] = {
            {0.0f, 0.0f, 0.0f, 1.0f},     // Black
            {1.0f, 1.0f, 1.0f, 1.0f},     // White
            {0.5f, 0.5f, 0.5f, 1.0f},     // Gray
            {1.0f, 0.0f, 0.0f, 1.0f},     // Red
            {-0.1f, 0.5f, 1.1f, 1.0f},    // Out of range
            {NAN, 0.5f, 0.5f, 1.0f},      // NaN input
            {0.5f, INFINITY, 0.5f, 1.0f}, // Infinity input
          };
          
          for (size_t k = 0; k < 7; k++) {
            icFloatNumber out[4];
            pCmm->Apply(out, test_pixels[k]);
            volatile icFloatNumber check = out[0] + out[1] + out[2];
            (void)check;
          }
        }
        // CMM destructor will delete pIcc
        delete pCmm;
      } else {
        // AddXform failed, CMM doesn't own profile
        delete pCmm;
        delete pIcc;
      }
    } else {
      // CMM allocation failed
      delete pIcc;
    }
  }
  
  return 0;
}
