/*
 * Copyright (c) International Color Consortium.
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
 * 3. In the absence of prior written permission, the names "ICC" and "The
 *    International Color Consortium" must not be used to imply that the
 *    ICC organization endorses or promotes products derived from this
 *    software.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNATIONAL COLOR CONSORTIUM OR
 * ITS CONTRIBUTING MEMBERS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/** @file
    File:       icc_toxml_fuzzer.cpp
    Contains:   LibFuzzer harness for IccToXml - 100% tool fidelity
    Version:    V2 - Refactored 2026-02-01 for tool alignment
*/

#include "IccProfile.h"
#include "IccTag.h"
#include "IccUtil.h"
#include <stdint.h>
#include <stddef.h>

#ifdef HAVE_ICCXML
#include "IccProfileXml.h"
#include "IccUtilXml.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 128) return 0;
  if (size > 5 * 1024 * 1024) return 0;

  CIccMemIO *pIO = nullptr;

  try {
    pIO = new CIccMemIO;
    if (!pIO) return 0;

    if (!pIO->Attach((icUInt8Number*)data, size)) {
      delete pIO;
      return 0;
    }

    // Convert to XML
    CIccProfileXml xmlProfile;
    if (xmlProfile.Attach(pIO)) {
      // Convert to XML string
      std::string xmlString;
      if (xmlProfile.ToXml(xmlString)) {
        // Successfully serialized to XML
        // This exercises XML generation and tag serialization
      }
    }
    // xmlProfile owns pIO now, it will be freed when xmlProfile goes out of scope

  } catch (...) {
    // If exception before Attach, we need to clean up
    // Otherwise xmlProfile destructor handles it
  }

  return 0;
}

#else
// Stub when IccXML not available
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return 0;
}
#endif
