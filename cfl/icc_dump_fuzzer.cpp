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
#include <map>
#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagLut.h"
#include "IccUtil.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 128 || size > 1024 * 1024) return 0;
  
  // Extract verboseness parameter from first byte (matches tool's 1-100 range)
  int verboseness = 1;
  if (size > 128) {
    verboseness = (data[0] % 100) + 1;  // 1-100
    data++;
    size--;
  }
  
  // Use ValidateIccProfile() like tool does with -v flag (line 193)
  std::string report;
  icValidateStatus nStatus;
  CIccProfile *pIcc = ValidateIccProfile(data, size, report, nStatus);
  
  if (pIcc) {
    // Note: ValidateIccProfile already called Validate(), no separate call needed
    
    // Exercise CIccInfo formatting methods (IccDumpProfile coverage)
    CIccInfo Fmt;
    icHeader *pHdr = &pIcc->m_Header;
    
    Fmt.GetDeviceAttrName(pHdr->attributes);
    Fmt.GetProfileFlagsName(pHdr->flags);
    Fmt.GetPlatformSigName(pHdr->platform);
    Fmt.GetCmmSigName((icCmmSignature)pHdr->cmmId);
    Fmt.GetRenderingIntentName((icRenderingIntent)pHdr->renderingIntent);
    Fmt.GetProfileClassSigName(pHdr->deviceClass);
    Fmt.GetColorSpaceSigName(pHdr->colorSpace);
    Fmt.GetColorSpaceSigName(pHdr->pcs);
    Fmt.GetVersionName(pHdr->version);
    Fmt.GetSpectralColorSigName(pHdr->spectralPCS);
    Fmt.IsProfileIDCalculated(&pHdr->profileID);
    Fmt.GetProfileID(&pHdr->profileID);
    
    if (pHdr->version >= icVersionNumberV5 && pHdr->deviceSubClass) {
      Fmt.GetSubClassVersionName(pHdr->version);
    }
    
    // Tag duplication detection (IccDumpProfile lines 303-308)
    std::map<icTagSignature, int> tagCounts;
    TagEntryList::iterator i, j;
    for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
      tagCounts[i->TagInfo.sig]++;
    }
    
    // Tag overlap and padding validation (IccDumpProfile lines 337-380)
    size_t n = pIcc->m_Tags.size();
    icUInt32Number smallest_offset = pHdr->size;
    
    for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
      // Track smallest offset for first tag validation
      if (i->TagInfo.offset < smallest_offset) {
        smallest_offset = i->TagInfo.offset;
      }
      
      // Check if offset+size exceeds file size (check for overflow first)
      icUInt32Number tag_end = i->TagInfo.offset + i->TagInfo.size;
      if ((tag_end > i->TagInfo.offset) && (tag_end > pHdr->size)) {
        // Non-compliant tag bounds
      }
      
      // Find closest following tag for overlap detection
      icUInt32Number closest = pHdr->size;
      for (j = pIcc->m_Tags.begin(); j != pIcc->m_Tags.end(); j++) {
        if ((i != j) && (j->TagInfo.offset > i->TagInfo.offset) && 
            (j->TagInfo.offset <= closest)) {
          closest = j->TagInfo.offset;
        }
      }
      
      // Check for tag overlap (tag_end already computed above)
      if ((tag_end > i->TagInfo.offset) &&  // Check for overflow
          (closest < tag_end) && 
          (closest < pHdr->size)) {
        // Overlapping tags detected
      }
      
      // Check for padding gaps (4-byte alignment)
      icUInt32Number rndup = 4 * ((i->TagInfo.size + 3) / 4);
      icUInt32Number aligned_end = i->TagInfo.offset + rndup;
      if ((aligned_end > i->TagInfo.offset) &&  // Check for overflow
          (closest > aligned_end)) {
        // Unnecessary gap between tags
      }
    }
    
    // First tag offset validation (IccDumpProfile lines 384-390)
    if (n > 0) {
      icUInt32Number expected_first_offset = 128 + 4 + (n * 12);
      if (smallest_offset > expected_first_offset) {
        // Non-compliant: gap after tag table
      }
    }
    
    // File size multiple-of-4 check (IccDumpProfile lines 331-335)
    if ((pHdr->version >= icVersionNumberV4_2) && (pHdr->size % 4 != 0)) {
      // Non-compliant file size
    }
    
    // Exercise all tags with Describe() - matches tool DumpTagCore() at line 108
    for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
      if (i->pTag) {
        std::string desc;
        desc.reserve(100000);  // Pre-allocate 100KB max for safety
        
        // Match tool behavior: call Describe() with verboseness parameter
        // Tool calls this on EVERY tag (iccDumpProfile.cpp line 108)
        i->pTag->Describe(desc, verboseness);
        
        // For small tags, also try higher verbosity levels
        if (i->TagInfo.size < 10000 && verboseness < 50) {
          desc.clear();
          i->pTag->Describe(desc, 50);
        }
        
        // For tiny tags, try maximum verbosity
        if (i->TagInfo.size < 1000 && verboseness < 100) {
          desc.clear();
          i->pTag->Describe(desc, 100);
        }
        
        i->pTag->GetType();
        
        // Array type detection
        if (i->pTag->IsArrayType()) {
          // Exercise array-specific paths
        }
        i->pTag->IsSupported();
        
        // Get tag signature name for formatting
        Fmt.GetTagSigName(i->TagInfo.sig);
        Fmt.GetTagTypeSigName(i->pTag->GetType());
      }
    }
    
    // Exercise comprehensive tag lookup with Describe() - matches tool DumpTagSig()
    icSignature tags[] = {icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
                           icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
                           icSigRedColorantTag, icSigGreenColorantTag, icSigBlueColorantTag,
                           icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag,
                           icSigGrayTRCTag, icSigMediaWhitePointTag,
                           icSigLuminanceTag, icSigMeasurementTag,
                           icSigNamedColor2Tag, icSigColorantTableTag,
                           icSigChromaticAdaptationTag, icSigCopyrightTag,
                           icSigProfileDescriptionTag, icSigViewingCondDescTag,
                           icSigColorantOrderTag, icSigColorimetricIntentImageStateTag,
                           icSigPerceptualRenderingIntentGamutTag,
                           icSigSaturationRenderingIntentGamutTag,
                           icSigTechnologyTag, icSigDeviceMfgDescTag,
                           icSigDeviceModelDescTag, icSigProfileSequenceDescTag,
                           icSigCicpTag, icSigMetaDataTag};
    for (int j = 0; j < 32; j++) {
      CIccTag *tag = pIcc->FindTag(tags[j]);
      if (tag) {
        // Match tool DumpTagCore() behavior (line 108)
        std::string desc;
        desc.reserve(100000);
        tag->Describe(desc, verboseness);
        
        // Also validate
        std::string validation_report;
        tag->Validate("", validation_report);
      }
    }
    
    // Exercise profile methods
    pIcc->GetSpaceSamples();
    pIcc->AreTagsUnique();
    
    delete pIcc;
  }
  
  return 0;
}
