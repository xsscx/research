/** @file
    File:       icc_v5dspobs_fuzzer.cpp
    Contains:   LibFuzzer harness for IccV5DspObsToV4Dsp — tool-faithful rewrite
    Version:    V4

    Tool:       iccDEV/Tools/CmdLine/IccV5DspObsToV4Dsp/iccV5DspObsToV4Dsp.cpp
    Usage:      iccV5DspObsToV4Dsp inputV5.icc inputObserverV5.icc outputV4.icc

    FIDELITY RULE: This fuzzer does EXACTLY what the tool does, in the same order,
    with the same API calls. NO pre-validation beyond what the tool performs.
    The library is the system under test — let it see every input.

    Input format: Two ICC profiles concatenated. The split point is determined by
    the first profile's own size field (bytes 0-3, big-endian uint32), which is how
    CIccFileIO::Read() determines profile boundaries. No artificial size prefix.
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
#include <memory>
#include <new>
#include <cstring>
#include <unistd.h>
#include <climits>

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagMPE.h"
#include "IccTagLut.h"
#include "IccMpeBasic.h"
#include "IccMpeSpectral.h"
#include "IccUtil.h"

#include "fuzz_utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum: two 128-byte ICC headers
  if (size < 256 || size > 5 * 1024 * 1024)
    return 0;

  // Split using the first profile's declared size (bytes 0-3).
  // This is how the ICC library itself determines profile length.
  uint32_t dspSize = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                     ((uint32_t)data[2] << 8) | data[3];

  if (dspSize < 128 || dspSize >= size - 127)
    return 0;

  // OOM guard: reject declared sizes that would cause icRealloc bombs.
  // The tool itself doesn't check this, but LibFuzzer -rss_limit_mb only
  // catches OOM AFTER allocation — we avoid the cost of fork+write+read.
  if (dspSize > 2 * 1024 * 1024)
    return 0;
  size_t obsSize = size - dspSize;
  if (obsSize > 2 * 1024 * 1024)
    return 0;

  const uint8_t *dspData = data;
  const uint8_t *obsData = data + dspSize;

  // Write both halves to temp files — tool uses file-based ReadIccProfile()
  const char *tmpdir = fuzz_tmpdir();
  char dspPath[PATH_MAX], obsPath[PATH_MAX], outPath[PATH_MAX];
  if (!fuzz_build_path(dspPath, sizeof(dspPath), tmpdir, "/fuzz_v5dsp_XXXXXX"))
    return 0;
  if (!fuzz_build_path(obsPath, sizeof(obsPath), tmpdir, "/fuzz_v5obs_XXXXXX"))
    return 0;

  int fd1 = mkstemp(dspPath);
  if (fd1 < 0) return 0;
  int fd2 = mkstemp(obsPath);
  if (fd2 < 0) { close(fd1); unlink(dspPath); return 0; }

  bool ok = (write(fd1, dspData, dspSize) == (ssize_t)dspSize) &&
            (write(fd2, obsData, obsSize) == (ssize_t)obsSize);
  close(fd1);
  close(fd2);
  if (!ok) { unlink(dspPath); unlink(obsPath); return 0; }

  // === TOOL LINE 108: ReadIccProfile(argv[1], true) ===
  CIccProfile *dspRaw = ReadIccProfile(dspPath, true);
  if (!dspRaw) {
    unlink(dspPath); unlink(obsPath);
    return 0;
  }
  std::shared_ptr<CIccProfile> dspIcc(dspRaw);

  // === TOOL LINES 115-119: Version and class check ===
  if (dspIcc->m_Header.version < icVersionNumberV5 ||
      dspIcc->m_Header.deviceClass != icSigDisplayClass) {
    unlink(dspPath); unlink(obsPath);
    return 0;
  }

  // === TOOL LINE 121: FindTagOfType(AToB1, MPE) ===
  CIccTagMultiProcessElement *pTagIn =
      static_cast<CIccTagMultiProcessElement *>(dspIcc->FindTagOfType(
          icSigAToB1Tag, icSigMultiProcessElementType));
  if (!pTagIn) {
    unlink(dspPath); unlink(obsPath);
    return 0;
  }

  // === TOOL LINES 130-136: MPE structure validation ===
  CIccMultiProcessElement *curveMpe, *matrixMpe;
  if (pTagIn->NumElements() != 2 ||
      pTagIn->NumInputChannels() != 3 ||
      pTagIn->NumOutputChannels() != 3 ||
      ((curveMpe = pTagIn->GetElement(0)) == nullptr) ||
      curveMpe->GetType() != icSigCurveSetElemType ||
      ((matrixMpe = pTagIn->GetElement(1)) == nullptr) ||
      matrixMpe->GetType() != icSigEmissionMatrixElemType) {
    unlink(dspPath); unlink(obsPath);
    return 0;
  }

  // === TOOL LINE 141: ReadIccProfile(argv[2]) ===
  CIccProfile *pccRaw = ReadIccProfile(obsPath, false);
  if (!pccRaw) {
    unlink(dspPath); unlink(obsPath);
    return 0;
  }
  std::shared_ptr<CIccProfile> pccIcc(pccRaw);

  // === TOOL LINES 148-150: Version check ===
  if (pccIcc->m_Header.version < icVersionNumberV5) {
    unlink(dspPath); unlink(obsPath);
    return 0;
  }

  // === TOOL LINES 153-161: PCC tag search ===
  CIccTagSpectralViewingConditions *pTagSvcn =
      static_cast<CIccTagSpectralViewingConditions *>(pccIcc->FindTagOfType(
          icSigSpectralViewingConditionsTag, icSigSpectralViewingConditionsType));
  CIccTagMultiProcessElement *pTagC2S =
      static_cast<CIccTagMultiProcessElement *>(pccIcc->FindTagOfType(
          icSigCustomToStandardPccTag, icSigMultiProcessElementType));

  if (!pTagSvcn || !pTagC2S ||
      pTagC2S->NumInputChannels() != 3 ||
      pTagC2S->NumOutputChannels() != 3) {
    unlink(dspPath); unlink(obsPath);
    return 0;
  }

  // === TOOL LINE 164: pTagIn->Begin() ===
  if (!pTagIn->Begin(icElemInterpLinear, dspIcc.get(), pccIcc.get())) {
    unlink(dspPath); unlink(obsPath);
    return 0;
  }

  // === TOOL LINES 169-175: GetNewApply + iterator ===
  CIccApplyTagMpe *pApplyMpe = pTagIn->GetNewApply();
  if (!pApplyMpe) {
    unlink(dspPath); unlink(obsPath);
    return 0;
  }

  auto applyList = pApplyMpe->GetList();
  if (!applyList || applyList->size() < 2) {
    delete pApplyMpe;
    unlink(dspPath); unlink(obsPath);
    return 0;
  }
  auto applyIter = applyList->begin();
  auto curveApply = applyIter->ptr;
  applyIter++;
  auto mtxApply = applyIter->ptr;

  // === TOOL LINE 177: pTagC2S->Begin() ===
  if (!pTagC2S->Begin(icElemInterpLinear, pccIcc.get())) {
    delete pApplyMpe;
    unlink(dspPath); unlink(obsPath);
    return 0;
  }

  CIccApplyTagMpe *pApplyC2S = pTagC2S->GetNewApply();
  if (!pApplyC2S) {
    delete pApplyMpe;
    unlink(dspPath); unlink(obsPath);
    return 0;
  }

  // === TOOL LINES 188-209: Create output V4 profile ===
  CIccProfile *pIcc = new (std::nothrow) CIccProfile();
  if (!pIcc) {
    delete pApplyC2S; delete pApplyMpe;
    unlink(dspPath); unlink(obsPath);
    return 0;
  }
  pIcc->InitHeader();
  pIcc->m_Header.deviceClass = icSigDisplayClass;
  pIcc->m_Header.version = icVersionNumberV4_3;

  CIccTag *pDesc = dspIcc->FindTag(icSigProfileDescriptionTag);
  CIccTagMultiLocalizedUnicode *pDspText = new(std::nothrow) CIccTagMultiLocalizedUnicode();
  if (!pDspText) { delete pApplyC2S; delete pApplyMpe; unlink(dspPath); unlink(obsPath); return 0; }
  std::string text;
  if (!icGetTagText(pDesc, text))
    text = "Fuzzed V5 to V4 display conversion";
  pDspText->SetText(text.c_str());
  pIcc->AttachTag(icSigProfileDescriptionTag, pDspText);

  pDspText = new(std::nothrow) CIccTagMultiLocalizedUnicode();
  if (!pDspText) { delete pApplyC2S; delete pApplyMpe; delete pIcc; unlink(dspPath); unlink(obsPath); return 0; }
  pDspText->SetText("Copyright (C) 2026 International Color Consortium");
  pIcc->AttachTag(icSigCopyrightTag, pDspText);

  // === TOOL LINES 211-226: TRC curves (2048 samples) ===
  CIccTagCurve *pTrcR = new(std::nothrow) CIccTagCurve(2048);
  CIccTagCurve *pTrcG = new(std::nothrow) CIccTagCurve(2048);
  CIccTagCurve *pTrcB = new(std::nothrow) CIccTagCurve(2048);
  if (!pTrcR || !pTrcG || !pTrcB) {
    delete pTrcR; delete pTrcG; delete pTrcB;
    delete pApplyC2S; delete pApplyMpe; delete pIcc;
    unlink(dspPath); unlink(obsPath); return 0;
  }

  icFloatNumber in[3], out[3];
  for (icUInt16Number i = 0; i < 2048; i++) {
    in[0] = in[1] = in[2] = (icFloatNumber)i / 2047.0f;
    curveMpe->Apply(curveApply, out, in);
    (*pTrcR)[i] = out[0];
    (*pTrcG)[i] = out[1];
    (*pTrcB)[i] = out[2];
  }
  pIcc->AttachTag(icSigRedTRCTag, pTrcR);
  pIcc->AttachTag(icSigGreenTRCTag, pTrcG);
  pIcc->AttachTag(icSigBlueTRCTag, pTrcB);

  // === TOOL LINES 228-251: Colorant XYZ computation ===
  const icFloatNumber rRGB[3] = {1.0f, 0.0f, 0.0f};
  const icFloatNumber gRGB[3] = {0.0f, 1.0f, 0.0f};
  const icFloatNumber bRGB[3] = {0.0f, 0.0f, 1.0f};

  matrixMpe->Apply(mtxApply, in, rRGB);
  pTagC2S->Apply(pApplyC2S, out, in);
  CIccTagS15Fixed16 *primaryXYZ = new(std::nothrow) CIccTagS15Fixed16(3);
  if (!primaryXYZ) { delete pApplyC2S; delete pApplyMpe; delete pIcc; unlink(dspPath); unlink(obsPath); return 0; }
  (*primaryXYZ)[0] = icDtoF(out[0]);
  (*primaryXYZ)[1] = icDtoF(out[1]);
  (*primaryXYZ)[2] = icDtoF(out[2]);
  pIcc->AttachTag(icSigRedColorantTag, primaryXYZ);

  matrixMpe->Apply(mtxApply, in, gRGB);
  pTagC2S->Apply(pApplyC2S, out, in);
  primaryXYZ = new(std::nothrow) CIccTagS15Fixed16(3);
  if (!primaryXYZ) { delete pApplyC2S; delete pApplyMpe; delete pIcc; unlink(dspPath); unlink(obsPath); return 0; }
  (*primaryXYZ)[0] = icDtoF(out[0]);
  (*primaryXYZ)[1] = icDtoF(out[1]);
  (*primaryXYZ)[2] = icDtoF(out[2]);
  pIcc->AttachTag(icSigGreenColorantTag, primaryXYZ);

  matrixMpe->Apply(mtxApply, in, bRGB);
  pTagC2S->Apply(pApplyC2S, out, in);
  primaryXYZ = new(std::nothrow) CIccTagS15Fixed16(3);
  if (!primaryXYZ) { delete pApplyC2S; delete pApplyMpe; delete pIcc; unlink(dspPath); unlink(obsPath); return 0; }
  (*primaryXYZ)[0] = icDtoF(out[0]);
  (*primaryXYZ)[1] = icDtoF(out[1]);
  (*primaryXYZ)[2] = icDtoF(out[2]);
  pIcc->AttachTag(icSigBlueColorantTag, primaryXYZ);

  // === TOOL LINE 253: SaveIccProfile ===
  if (fuzz_build_path(outPath, sizeof(outPath), tmpdir, "/fuzz_v4out_XXXXXX")) {
    int outFd = mkstemp(outPath);
    if (outFd >= 0) {
      close(outFd);
      SaveIccProfile(outPath, pIcc);
      unlink(outPath);
    }
  }

  // Cleanup
  delete pIcc;
  delete pApplyC2S;
  delete pApplyMpe;
  // dspIcc and pccIcc freed by shared_ptr

  unlink(dspPath);
  unlink(obsPath);
  return 0;
}
