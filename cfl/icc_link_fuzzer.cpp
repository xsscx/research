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
#include <unistd.h>
#include <fcntl.h>
#include "IccCmm.h"
#include "IccUtil.h"
#include "IccProfile.h"
#include "IccDefs.h"
#include "IccApplyBPC.h"
#include <climits>
#include <new>
#include "fuzz_utils.h"

// Aligned with iccDEV/Tools/CmdLine/IccApplyToLink/iccApplyToLink.cpp:
// Uses ReadIccProfile() + AddXform(CIccProfile*, ...) with full parameter set
// including icXformLutType, bUseD2BxB2DxTags, BPC hints, and bUseSubProfile.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 258 || size > 2 * 1024 * 1024) return 0;
  
  // Derive parameters from trailing bytes to preserve ICC header structure
  // Matches iccApplyToLink parameter derivation from command-line args
  icRenderingIntent intent = (icRenderingIntent)(data[size - 1] % 4);
  icXformInterp interp = (data[size - 2] & 1) ? icInterpLinear : icInterpTetrahedral;
  uint8_t ctrl = data[size - 3];
  bool bFirstTransform = (ctrl & 0x01);        // iccApplyToLink: first_transform arg
  bool bUseD2BxB2DxTags = !(ctrl & 0x02);      // iccApplyToLink: nType==1 disables
  bool bUseBPC = (ctrl & 0x04);                 // iccApplyToLink: nType==4 enables BPC
  bool bUseLuminance = (ctrl & 0x08);           // iccApplyToLink: +100 intent modifier
  bool bUseSubProfile = (ctrl & 0x10);          // iccApplyToLink: +1000 intent modifier
  icXformLutType nLutType = (ctrl & 0x20) ? icXformLutPreview : icXformLutColor;
  
  // Split input into two profiles (no leading byte skip)
  size_t mid = size / 2;
  
  const char *tmpdir = fuzz_tmpdir();
  char tmp1[PATH_MAX];
  char tmp2[PATH_MAX];
  if (!fuzz_build_path(tmp1, sizeof(tmp1), tmpdir, "/fuzz_link1_XXXXXX")) return 0;
  if (!fuzz_build_path(tmp2, sizeof(tmp2), tmpdir, "/fuzz_link2_XXXXXX")) return 0;
  
  int fd1 = mkstemp(tmp1);
  int fd2 = mkstemp(tmp2);
  
  if (fd1 == -1 || fd2 == -1) {
    if (fd1 != -1) { close(fd1); unlink(tmp1); }
    if (fd2 != -1) { close(fd2); unlink(tmp2); }
    return 0;
  }
  
  write(fd1, data, mid);
  write(fd2, data + mid, size - mid);
  close(fd1);
  close(fd2);
  
  // Use ReadIccProfile + AddXform(CIccProfile*,...) matching iccApplyToLink
  CIccProfile *pProf1 = ReadIccProfile(tmp1, bUseSubProfile);
  CIccProfile *pProf2 = ReadIccProfile(tmp2, bUseSubProfile);
  
  if (!pProf1 || !pProf2) {
    delete pProf1;
    delete pProf2;
    unlink(tmp1);
    unlink(tmp2);
    return 0;
  }
  
  // Matches iccApplyToLink: CIccCmm(icSigUnknownData, icSigUnknownData, bFirstTransform)
  CIccCmm cmm(icSigUnknownData, icSigUnknownData, bFirstTransform);
  
  // Build hints matching iccApplyToLink hint construction
  CIccCreateXformHintManager hint1, hint2;
  if (bUseBPC) {
    auto* h1 = new (std::nothrow) CIccApplyBPCHint();
    auto* h2 = new (std::nothrow) CIccApplyBPCHint();
    if (!h1 || !h2) { delete h1; delete h2; delete pProf1; delete pProf2; unlink(tmp1); unlink(tmp2); return 0; }
    hint1.AddHint(h1);
    hint2.AddHint(h2);
  }
  if (bUseLuminance) {
    auto* h1 = new (std::nothrow) CIccLuminanceMatchingHint();
    auto* h2 = new (std::nothrow) CIccLuminanceMatchingHint();
    if (!h1 || !h2) { delete h1; delete h2; delete pProf1; delete pProf2; unlink(tmp1); unlink(tmp2); return 0; }
    hint1.AddHint(h1);
    hint2.AddHint(h2);
  }
  
  // Note: AddXform(CIccProfile*,...) takes ownership of profile on success
  icStatusCMM stat1 = cmm.AddXform(pProf1, intent, interp, NULL,
                                    nLutType, bUseD2BxB2DxTags, &hint1);
  if (stat1 != icCmmStatOk) {
    delete pProf1;
    delete pProf2;
    unlink(tmp1);
    unlink(tmp2);
    return 0;
  }
  // pProf1 now owned by cmm
  
  icStatusCMM stat2 = cmm.AddXform(pProf2, intent, interp, NULL,
                                    nLutType, bUseD2BxB2DxTags, &hint2);
  if (stat2 != icCmmStatOk) {
    delete pProf2;
    unlink(tmp1);
    unlink(tmp2);
    return 0;
  }
  // pProf2 now owned by cmm
  
  if (cmm.Begin() == icCmmStatOk) {
    int nSrc = icGetSpaceSamples(cmm.GetSourceSpace());
    int nDst = icGetSpaceSamples(cmm.GetDestSpace());
    if (nSrc <= 0 || nSrc > 16 || nDst <= 0 || nDst > 16) {
      unlink(tmp1);
      unlink(tmp2);
      return 0;
    }

    // Test varied color values through chain
    icFloatNumber in[16], out[16];
    for (int i = 0; i < nSrc; i++)
      in[i] = (icFloatNumber)i / (nSrc > 1 ? (nSrc - 1) : 1);
    cmm.Apply(out, in);

    // Test boundary values
    for (int i = 0; i < nSrc; i++) in[i] = 0.0f;
    cmm.Apply(out, in);
    for (int i = 0; i < nSrc; i++) in[i] = 1.0f;
    cmm.Apply(out, in);

    // Test mid-range
    for (int i = 0; i < nSrc; i++) in[i] = 0.5f;
    cmm.Apply(out, in);

    // Test out-of-gamut values
    for (int i = 0; i < nSrc; i++) in[i] = (i % 2) ? -0.1f : 1.1f;
    cmm.Apply(out, in);

    // Exercise CMM chain info matching iccApplyToLink post-Begin usage
    (void)cmm.GetNumXforms();
    (void)cmm.GetSourceSpace();
    (void)cmm.GetDestSpace();
    (void)cmm.Valid();
  }
  
  unlink(tmp1);
  unlink(tmp2);
  return 0;
}
