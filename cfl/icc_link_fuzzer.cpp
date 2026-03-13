/** @file
    File:       icc_link_fuzzer.cpp
    Contains:   LibFuzzer harness for IccApplyToLink — tool-faithful rewrite
    Version:    V4

    Tool:       iccDEV/Tools/CmdLine/IccApplyToLink/iccApplyToLink.cpp
    Usage:      iccApplyToLink dst_link lut_type lut_size option title
                range_min range_max first_transform interp
                {profile_path rendering_intent}...

    FIDELITY RULE: This fuzzer reproduces the tool's core pipeline:
      ReadIccProfile → AddXform (×N) → Begin → grid Apply → IterateXforms
    NO pre-validation beyond what the tool performs.

    Input format: Two ICC profiles concatenated. The first profile's declared
    size (bytes 0-3) determines the split point. Fuzz parameters derived from
    trailing bytes to preserve ICC header structure.

    Ownership: AddXform → CIccXform::Create takes ownership of the profile.
    On icCmmStatBadXform, Create already freed it. On other errors, it did not.
*/

/*
 * Copyright (c) International Color Consortium.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice.
 * 2. Redistributions in binary form must reproduce the above copyright notice.
 * 3. The names "ICC" and "The International Color Consortium" must not be used
 *    to imply endorsement without prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
 */

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <new>
#include <cstring>
#include <unistd.h>
#include <climits>

#include "IccCmm.h"
#include "IccUtil.h"
#include "IccProfile.h"
#include "IccDefs.h"
#include "IccApplyBPC.h"
#include "IccEnvVar.h"
#include "IccTagBasic.h"
#include "IccTagLut.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"

#include "fuzz_utils.h"

// IXformIterator — mirrors CCubeWriter::iterate() and CDevLinkWriter::iterate()
class CFuzzLinkIterator : public IXformIterator {
public:
  void iterate(const CIccXform *pXform) override {
    if (pXform) {
      const CIccProfile *pProf = pXform->GetProfile();
      if (pProf) {
        const CIccTag *pDesc = pProf->FindTagConst(icSigProfileDescriptionTag);
        if (pDesc) {
          std::string text;
          (void)icGetTagText(pDesc, text);
        }
      }
    }
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum: two 128-byte ICC headers + 4 control bytes
  if (size < 260 || size > 2 * 1024 * 1024)
    return 0;

  // Derive fuzz parameters from trailing 4 bytes (preserve ICC header structure)
  // Matches iccApplyToLink intent/type/interp parsing (lines 726-746)
  uint8_t ctrl0 = data[size - 4];
  uint8_t ctrl1 = data[size - 3];
  uint8_t ctrl2 = data[size - 2];
  uint8_t ctrl3 = data[size - 1];
  size_t profileData = size - 4;

  icRenderingIntent intent = (icRenderingIntent)(ctrl3 % 4);
  icXformInterp interp = (ctrl2 & 1) ? icInterpLinear : icInterpTetrahedral;
  bool bFirstTransform = (ctrl0 & 0x01);
  bool bUseD2BxB2DxTags = !(ctrl0 & 0x02);
  bool bUseBPC = (ctrl0 & 0x04);
  bool bUseLuminance = (ctrl0 & 0x08);
  bool bUseSubProfile = (ctrl0 & 0x10);

  // LUT type from tool's nType values (lines 737-746)
  static const icXformLutType lutTypes[] = {
      icXformLutColor,     icXformLutNamedColor,
      icXformLutPreview,   icXformLutGamut,
      icXformLutBRDFParam, icXformLutBRDFDirect,
      icXformLutBRDFMcsParam, icXformLutMCS};
  icXformLutType nLutType = lutTypes[(ctrl1 >> 5) & 0x07];

  bool bSaveLink = (ctrl1 & 0x01);

  // Split input using first profile's declared size (bytes 0-3)
  uint32_t prof1Size = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                       ((uint32_t)data[2] << 8) | data[3];

  if (prof1Size < 128 || prof1Size >= profileData - 127)
    return 0;

  // Write both profiles to temp files
  const char *tmpdir = fuzz_tmpdir();
  char path1[PATH_MAX], path2[PATH_MAX];
  if (!fuzz_build_path(path1, sizeof(path1), tmpdir, "/fuzz_lnk1_XXXXXX"))
    return 0;
  if (!fuzz_build_path(path2, sizeof(path2), tmpdir, "/fuzz_lnk2_XXXXXX"))
    return 0;

  int fd1 = mkstemp(path1);
  if (fd1 < 0) return 0;
  int fd2 = mkstemp(path2);
  if (fd2 < 0) { close(fd1); unlink(path1); return 0; }

  bool ok = (write(fd1, data, prof1Size) == (ssize_t)prof1Size) &&
            (write(fd2, data + prof1Size, profileData - prof1Size) ==
             (ssize_t)(profileData - prof1Size));
  close(fd1);
  close(fd2);
  if (!ok) { unlink(path1); unlink(path2); return 0; }

  // === TOOL LINE 770: ReadIccProfile ===
  CIccProfile *pProf1 = ReadIccProfile(path1, bUseSubProfile);
  CIccProfile *pProf2 = ReadIccProfile(path2, bUseSubProfile);

  if (!pProf1 || !pProf2) {
    delete pProf1;
    delete pProf2;
    unlink(path1); unlink(path2);
    return 0;
  }

  // === TOOL LINE 699: CIccCmm(icSigUnknownData, icSigUnknownData, bFirstTransform) ===
  CIccCmm cmm(icSigUnknownData, icSigUnknownData, bFirstTransform);

  // === TOOL LINES 736-766: Build hints ===
  CIccCreateXformHintManager hint1, hint2;
  if (bUseBPC) {
    auto *h1 = new (std::nothrow) CIccApplyBPCHint();
    auto *h2 = new (std::nothrow) CIccApplyBPCHint();
    if (h1) hint1.AddHint(h1); else delete h1;
    if (h2) hint2.AddHint(h2); else delete h2;
  }
  if (bUseLuminance) {
    auto *h1 = new (std::nothrow) CIccLuminanceMatchingHint();
    auto *h2 = new (std::nothrow) CIccLuminanceMatchingHint();
    if (h1) hint1.AddHint(h1); else delete h1;
    if (h2) hint2.AddHint(h2); else delete h2;
  }

  // === TOOL LINE 771: AddXform (profile 1) ===
  // Ownership: AddXform → CIccXform::Create takes ownership.
  // On icCmmStatBadXform, profile already freed by Create.
  icStatusCMM stat1 = cmm.AddXform(pProf1, intent, interp, NULL,
                                    nLutType, bUseD2BxB2DxTags, &hint1);
  if (stat1 != icCmmStatOk) {
    if (stat1 != icCmmStatBadXform)
      delete pProf1;
    delete pProf2;
    unlink(path1); unlink(path2);
    return 0;
  }

  // === AddXform (profile 2) ===
  icStatusCMM stat2 = cmm.AddXform(pProf2, intent, interp, NULL,
                                    nLutType, bUseD2BxB2DxTags, &hint2);
  if (stat2 != icCmmStatOk) {
    if (stat2 != icCmmStatBadXform)
      delete pProf2;
    unlink(path1); unlink(path2);
    return 0;
  }

  // === TOOL LINE 783: Begin() ===
  if (cmm.Begin() != icCmmStatOk) {
    unlink(path1); unlink(path2);
    return 0;
  }

  // === TOOL LINES 804-809: Get source/dest dimensions ===
  int nSrc = icGetSpaceSamples(cmm.GetSourceSpace());
  int nDst = icGetSpaceSamples(cmm.GetDestSpace());
  if (nSrc <= 0 || nSrc > 16 || nDst <= 0 || nDst > 16) {
    unlink(path1); unlink(path2);
    return 0;
  }

  // === TOOL LINES 788, 860: IterateXforms ===
  CFuzzLinkIterator iter;
  cmm.IterateXforms(&iter);

  // === TOOL LINES 820-854: Grid sweep Apply ===
  icFloatNumber srcPixel[16], dstPixel[16];

  if (nSrc <= 4) {
    int nGridSize = 3 + ((ctrl2 >> 2) & 0x03); // 3-6 grid
    int idx[4] = {0, 0, 0, 0};
    int dims = (nSrc < 4) ? nSrc : 4;

    for (;;) {
      for (int d = 0; d < dims; d++)
        srcPixel[d] = (icFloatNumber)idx[d] / (nGridSize - 1);
      for (int d = dims; d < nSrc; d++)
        srcPixel[d] = 0.5f;

      cmm.Apply(dstPixel, srcPixel);

      int carry = dims - 1;
      while (carry >= 0) {
        idx[carry]++;
        if (idx[carry] >= nGridSize) {
          idx[carry] = 0;
          carry--;
        } else
          break;
      }
      if (carry < 0) break;
    }
  } else {
    for (int i = 0; i < nSrc; i++)
      srcPixel[i] = (icFloatNumber)i / (nSrc - 1);
    cmm.Apply(dstPixel, srcPixel);
  }

  // Boundary values
  for (int i = 0; i < nSrc; i++) srcPixel[i] = 0.0f;
  cmm.Apply(dstPixel, srcPixel);
  for (int i = 0; i < nSrc; i++) srcPixel[i] = 1.0f;
  cmm.Apply(dstPixel, srcPixel);

  // === TOOL: SaveIccProfile (device link output) ===
  if (bSaveLink) {
    CIccProfile linkProfile;
    linkProfile.InitHeader();
    linkProfile.m_Header.deviceClass = icSigLinkClass;
    linkProfile.m_Header.colorSpace = cmm.GetSourceSpace();
    linkProfile.m_Header.pcs = cmm.GetDestSpace();

    auto *pDesc = new (std::nothrow) CIccTagMultiLocalizedUnicode();
    if (pDesc) {
      pDesc->SetText("Fuzz Device Link");
      linkProfile.AttachTag(icSigProfileDescriptionTag, pDesc);
    }
    auto *pCopy = new (std::nothrow) CIccTagMultiLocalizedUnicode();
    if (pCopy) {
      pCopy->SetText("Copyright Fuzz");
      linkProfile.AttachTag(icSigCopyrightTag, pCopy);
    }

    char outPath[PATH_MAX];
    if (fuzz_build_path(outPath, sizeof(outPath), tmpdir, "/fuzz_lnkout_XXXXXX")) {
      int outFd = mkstemp(outPath);
      if (outFd >= 0) {
        close(outFd);
        SaveIccProfile(outPath, &linkProfile);
        unlink(outPath);
      }
    }
  }

  unlink(path1);
  unlink(path2);
  return 0;
}
