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
#include <cstring>
#include <stdio.h>

// AST Gate logging macros
#define AST_LOG(gate, msg, ...) fprintf(stderr, "[AST-GATE-%d] " msg "\n", gate, ##__VA_ARGS__)
#define AST_LOG_VERBOSE(msg, ...) fprintf(stderr, "[AST-DEBUG] " msg "\n", ##__VA_ARGS__)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  AST_LOG(0, "=== SPECTRAL FUZZER ENTRY ===");
  AST_LOG(0, "Untrusted input: %zu bytes", size);
  
  if (size < 128) {
    AST_LOG_VERBOSE("Input too small: %zu < 128", size);
    return 0;
  }
  if (size > 10 * 1024 * 1024) {
    AST_LOG_VERBOSE("Input too large: %zu > 10MB", size);
    return 0;
  }

  CIccProfile *pProfile = nullptr;
  CIccMemIO *pIO = nullptr;

  try {
    AST_LOG(1, "GATE 1: Creating CIccMemIO wrapper");
    // Create memory I/O wrapper
    pIO = new CIccMemIO;
    if (!pIO) {
      AST_LOG(1, "CIccMemIO allocation failed");
      return 0;
    }

    AST_LOG(1, "Calling pIO->Attach(data=%p, size=%zu)", (void*)data, size);
    if (!pIO->Attach((icUInt8Number*)data, size)) {
      AST_LOG(1, "pIO->Attach() failed");
      delete pIO;
      return 0;
    }

    AST_LOG(2, "GATE 2: Creating CIccProfile object");
    // Parse ICC profile
    pProfile = new CIccProfile;
    if (!pProfile) {
      AST_LOG(2, "CIccProfile allocation failed");
      delete pIO;
      return 0;
    }

    AST_LOG(2, "Calling pProfile->Attach(pIO)");
    if (!pProfile->Attach(pIO)) {
      AST_LOG(2, "pProfile->Attach() failed - invalid profile format");
      delete pProfile;
      delete pIO;
      return 0;
    }

    AST_LOG(3, "GATE 3: Profile loaded successfully");
    AST_LOG_VERBOSE("Header: colorSpace=0x%08X, PCS=0x%08X, class=0x%08X",
                    pProfile->m_Header.colorSpace,
                    pProfile->m_Header.pcs,
                    pProfile->m_Header.deviceClass);

    AST_LOG(4, "GATE 4: Searching for spectral tags");
    // Exercise spectral viewing conditions tag
    CIccTag *pTag = pProfile->FindTag(icSigSpectralViewingConditionsTag);
    if (pTag) {
      AST_LOG_VERBOSE("Found icSigSpectralViewingConditionsTag");
      // Trigger spectral processing paths
      icTagTypeSignature tagType = pTag->GetType();
      AST_LOG_VERBOSE("  Tag type: 0x%08X", tagType);
      
      // Attempt to write (triggers NULL deref if not fixed)
      AST_LOG_VERBOSE("  Writing tag to test output");
      CIccMemIO *pOutIO = new CIccMemIO;
      if (pOutIO) {
        pOutIO->Alloc(size + 1024);
        pTag->Write(pOutIO);
        delete pOutIO;
        AST_LOG_VERBOSE("  Tag write successful");
      }
    }

    // Exercise spectral white point
    pTag = pProfile->FindTag(icSigSpectralWhitePointTag);
    if (pTag) {
      AST_LOG_VERBOSE("Found icSigSpectralWhitePointTag");
      icTagTypeSignature tagType = pTag->GetType();
      AST_LOG_VERBOSE("  Tag type: 0x%08X", tagType);
    }

    // Exercise spectral data info
    pTag = pProfile->FindTag(icSigSpectralDataInfoTag);
    if (pTag) {
      AST_LOG_VERBOSE("Found icSigSpectralDataInfoTag");
      icTagTypeSignature tagType = pTag->GetType();
      AST_LOG_VERBOSE("  Tag type: 0x%08X", tagType);
    }

    AST_LOG(5, "GATE 5: Validating profile");
    // Validate profile (triggers spectral validation paths) before CMM takes ownership
    std::string validationReport;
    pProfile->Validate(validationReport);
    if (!validationReport.empty()) {
      AST_LOG_VERBOSE("Validation report: %zu bytes", validationReport.size());
    }

    AST_LOG(6, "GATE 6: Checking for spectral color space");
    // Note: CMM transforms (AddXform/Begin/Apply) are out of scope for
    // IccV5DspObsToV4Dsp — that tool uses MPE tag-level operations, not CMM.
    // CMM spectral paths are covered by icc_apply_fuzzer.
    if (pProfile->m_Header.colorSpace == icSigReflectanceSpectralData ||
        pProfile->m_Header.colorSpace == icSigTransmisionSpectralData ||
        pProfile->m_Header.pcs == icSigReflectanceSpectralPcsData) {
      AST_LOG(6, "Spectral profile detected");
    } else {
      AST_LOG_VERBOSE("Non-spectral profile");
    }
    AST_LOG(7, "GATE 7: Cleanup - deleting profile");
    delete pProfile;

  } catch (...) {
    AST_LOG_VERBOSE("Exception caught during processing");
    // Profile destructor handles pIO cleanup if attached
    if (pProfile) delete pProfile;
  }

  AST_LOG(0, "=== SPECTRAL FUZZER EXIT ===");
  return 0;
}
