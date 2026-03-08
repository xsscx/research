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
#include <string>
#include "IccCmm.h"
#include "IccUtil.h"
#include "IccProfile.h"
#include "IccDefs.h"
#include "IccApplyBPC.h"
#include "IccEnvVar.h"
#include "IccTagBasic.h"
#include <climits>
#include <new>
#include "fuzz_utils.h"

// Aligned with iccDEV/Tools/CmdLine/IccApplyToLink/iccApplyToLink.cpp:
// Uses ReadIccProfile() + AddXform(CIccProfile*, ...) with full parameter set
// including icXformLutType, bUseD2BxB2DxTags, BPC/Luminance/EnvVar hints,
// IterateXforms callback, SaveIccProfile output, and grid sweep Apply.

// IXformIterator for IterateXforms — mirrors CCubeWriter::iterate() and
// CDevLinkWriter::iterate() in iccApplyToLink.cpp (lines 204-524)
class CFuzzLinkIterator : public IXformIterator {
public:
  int m_count = 0;
  void iterate(const CIccXform* pXform) override {
    m_count++;
    if (pXform) {
      const CIccProfile* pProf = pXform->GetProfile();
      if (pProf) {
        const CIccTag* pDesc = pProf->FindTagConst(icSigProfileDescriptionTag);
        if (pDesc) {
          std::string text;
          (void)icGetTagText(pDesc, text);
        }
      }
    }
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 258 || size > 2 * 1024 * 1024) return 0;
  
  // Derive parameters from trailing bytes to preserve ICC header structure
  // Matches iccApplyToLink intent modifier parsing (lines 726-746)
  icRenderingIntent intent = (icRenderingIntent)(data[size - 1] % 4);
  icXformInterp interp = (data[size - 2] & 1) ? icInterpLinear : icInterpTetrahedral;
  uint8_t ctrl = data[size - 3];
  uint8_t ctrl2 = data[size - 4];

  bool bFirstTransform = (ctrl & 0x01);        // iccApplyToLink: first_transform arg
  bool bUseD2BxB2DxTags = !(ctrl & 0x02);      // iccApplyToLink: nType==1 disables
  bool bUseBPC = (ctrl & 0x04);                 // iccApplyToLink: nType==4 enables BPC
  bool bUseLuminance = (ctrl & 0x08);           // iccApplyToLink: +100 intent modifier
  bool bUseSubProfile = (ctrl & 0x10);          // iccApplyToLink: +1000 intent modifier

  // Expand nLutType to exercise all xform types (was: binary Color/Preview)
  // Matches iccApplyToLink nType values 0-8 (lines 737-746)
  static const icXformLutType lutTypes[] = {
    icXformLutColor, icXformLutNamedColor, icXformLutPreview, icXformLutGamut,
    icXformLutBRDFParam, icXformLutBRDFDirect, icXformLutBRDFMcsParam, icXformLutMCS
  };
  icXformLutType nLutType = lutTypes[(ctrl >> 5) & 0x07];

  bool bSaveLink = (ctrl2 & 0x01);             // Exercise SaveIccProfile path
  bool bUseEnvVars = (ctrl2 & 0x02);           // Exercise CIccCmmEnvVarHint
  
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
  
  // Build hints matching iccApplyToLink hint construction (lines 736-766)
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
  // CIccCmmEnvVarHint — exercises iccApplyToLink -ENV: handling (lines 715-723)
  if (bUseEnvVars) {
    icCmmEnvSigMap envVars;
    envVars[0x656E7631] = 1.0f;  // 'env1' = 1.0
    envVars[0x656E7632] = 0.5f;  // 'env2' = 0.5
    auto* e1 = new (std::nothrow) CIccCmmEnvVarHint(envVars);
    auto* e2 = new (std::nothrow) CIccCmmEnvVarHint(envVars);
    if (e1) hint1.AddHint(e1);
    if (e2) hint2.AddHint(e2);
  }
  
  // Note: AddXform → CIccXform::Create takes ownership of the profile pointer.
  // On icCmmStatBadXform, Create already freed it; on other errors, it did not.
  // To avoid double-free (heap-use-after-free), only delete on non-BadXform errors.
  icStatusCMM stat1 = cmm.AddXform(pProf1, intent, interp, NULL,
                                    nLutType, bUseD2BxB2DxTags, &hint1);
  if (stat1 != icCmmStatOk) {
    if (stat1 != icCmmStatBadXform)
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
    if (stat2 != icCmmStatBadXform)
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

    // IterateXforms — exercises IXformIterator callback matching
    // iccApplyToLink CCubeWriter::iterate() and CDevLinkWriter::iterate()
    CFuzzLinkIterator iter;
    cmm.IterateXforms(&iter);

    icFloatNumber in[16], out[16];

    // Grid sweep — exercises CMM.Apply with parameterized color samples
    // matching iccApplyToLink grid sweep (lines 820-854)
    if (nSrc <= 4) {
      int nGridSize = 3 + ((ctrl2 >> 2) & 0x03); // 3-6 grid
      for (int i = 0; i < nSrc; i++) in[i] = 0.0f;

      // Nested loop for up to 4 dimensions
      int idx[4] = {0, 0, 0, 0};
      int dims = (nSrc < 4) ? nSrc : 4;
      for (;;) {
        for (int d = 0; d < dims; d++)
          in[d] = (icFloatNumber)idx[d] / (nGridSize - 1);
        for (int d = dims; d < nSrc; d++)
          in[d] = 0.5f;
        cmm.Apply(out, in);

        // Increment multi-dimensional index
        int carry = dims - 1;
        while (carry >= 0) {
          idx[carry]++;
          if (idx[carry] >= nGridSize) {
            idx[carry] = 0;
            carry--;
          } else {
            break;
          }
        }
        if (carry < 0) break;
      }
    } else {
      // High-dimensional: test varied color values through chain
      for (int i = 0; i < nSrc; i++)
        in[i] = (icFloatNumber)i / (nSrc - 1);
      cmm.Apply(out, in);
    }

    // Test boundary values
    for (int i = 0; i < nSrc; i++) in[i] = 0.0f;
    cmm.Apply(out, in);
    for (int i = 0; i < nSrc; i++) in[i] = 1.0f;
    cmm.Apply(out, in);

    // Test out-of-gamut values
    for (int i = 0; i < nSrc; i++) in[i] = (i % 2) ? -0.1f : 1.1f;
    cmm.Apply(out, in);

    // Exercise CMM chain info matching iccApplyToLink post-Begin usage
    (void)cmm.GetNumXforms();
    (void)cmm.GetSourceSpace();
    (void)cmm.GetDestSpace();
    (void)cmm.Valid();

    // SaveIccProfile — exercises device link serialization matching
    // iccApplyToLink CDevLinkWriter::finish() (line 540)
    if (bSaveLink) {
      CIccProfile linkProfile;
      linkProfile.InitHeader();
      linkProfile.m_Header.deviceClass = icSigLinkClass;
      linkProfile.m_Header.colorSpace = cmm.GetSourceSpace();
      linkProfile.m_Header.pcs = cmm.GetDestSpace();

      auto* pDesc = new (std::nothrow) CIccTagMultiLocalizedUnicode();
      if (pDesc) {
        pDesc->SetText("Fuzz Device Link");
        linkProfile.AttachTag(icSigProfileDescriptionTag, pDesc);
      }
      auto* pCopy = new (std::nothrow) CIccTagMultiLocalizedUnicode();
      if (pCopy) {
        pCopy->SetText("Copyright Fuzz");
        linkProfile.AttachTag(icSigCopyrightTag, pCopy);
      }

      char tmpout[PATH_MAX];
      if (fuzz_build_path(tmpout, sizeof(tmpout), tmpdir, "/fuzz_linkout_XXXXXX")) {
        int fdout = mkstemp(tmpout);
        if (fdout != -1) {
          close(fdout);
          SaveIccProfile(tmpout, &linkProfile);
          unlink(tmpout);
        }
      }
    }
  }
  
  unlink(tmp1);
  unlink(tmp2);
  return 0;
}
