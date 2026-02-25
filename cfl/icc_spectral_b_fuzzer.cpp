/** @file
    File:       icc_spectral_b_fuzzer.cpp
    Contains:   LibFuzzer harness for IccSpecSepToTiff (Variant B)
    Version:    V1
    Copyright:  (c) see Software License

    Fuzzer for: Build/Tools/IccSpecSepToTiff/iccSpecSepToTiff
    Tool Usage: iccSpecSepToTiff output compress sep infile_fmt start end incr {profile}

    TOOL FIDELITY: This fuzzer maintains strict fidelity with iccSpecSepToTiff by:
      1. Using CTiffImg::Open/ReadLine for input (same file-based I/O as tool)
      2. Interleaving separated spectral channels into output (same pixel loop)
      3. Embedding an ICC profile via SetIccProfile (same optional argv[8] path)
      4. Using CTiffImg::Create/WriteLine for output (same output path)

    The existing icc_specsep_fuzzer (Variant A) synthesizes TIFF pixel data
    from fuzzer bytes. This variant (B) focuses on profile embedding: it
    treats the fuzzer input as an ICC profile and generates minimal valid
    TIFF structure, exercising the profile-embed path more deeply.

    Input Format: Raw ICC profile bytes for embedding into output TIFF
*/

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
#include <cstdlib>
#include <cstring>
#include <vector>
#include <memory>
#include <unistd.h>
#include <climits>
#include <tiffio.h>
#include "fuzz_utils.h"

#include "IccProfile.h"
#include "IccUtil.h"
#include "IccIO.h"
#include "IccTagBasic.h"
#include "TiffImg.h"

static void SilentTIFFErrorHandler(const char*, const char*, va_list) {}
static void SilentTIFFWarningHandler(const char*, const char*, va_list) {}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  TIFFSetErrorHandler(SilentTIFFErrorHandler);
  TIFFSetWarningHandler(SilentTIFFWarningHandler);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4 || size > 1024 * 1024) return 0;

  const char *tmpdir = fuzz_tmpdir();

  // Parse control byte from end to preserve ICC header at start
  uint8_t ctrl = data[size - 1];
  uint8_t nSamples = (ctrl & 0x07) + 1;       // 1-8 channels
  bool bCompress = (ctrl >> 3) & 1;
  bool bSep = (ctrl >> 4) & 1;
  uint8_t bitsFlag = (ctrl >> 5) & 1;
  uint8_t bitsPerSample = bitsFlag ? 16 : 8;
  uint8_t dimBits = (ctrl >> 6) & 0x03;

  // Small fixed dimensions for speed
  uint32_t width = 4 + dimBits * 4;            // 4, 8, 12, 16
  uint32_t height = 4 + dimBits * 4;

  size_t bytesPerSample = bitsPerSample / 8;
  size_t profileSize = size - 1;               // rest is ICC profile data

  // Create nSamples input TIFFs with single-channel spectral data
  // Tool: for (int i=0; i<nSamples; i++) { infile[i].Open(filename); }
  std::vector<char*> infiles;
  for (uint8_t i = 0; i < nSamples; i++) {
    char *tf = (char*)malloc(PATH_MAX);
    if (!tf) break;
    char suffix[64];
    snprintf(suffix, sizeof(suffix), "/fuzz_specb_%d_XXXXXX", i);
    if (!fuzz_build_path(tf, PATH_MAX, tmpdir, suffix)) { free(tf); break; }
    int fd = mkstemp(tf);
    if (fd < 0) { free(tf); break; }

    CTiffImg tiff;
    if (!tiff.Create(tf, width, height, bitsPerSample,
                     PHOTO_MINISBLACK, 1, 0, 72, 72, false, false)) {
      close(fd);
      unlink(tf);
      free(tf);
      break;
    }

    // Fill with deterministic pattern derived from fuzzer input + channel
    std::vector<icUInt8Number> row(width * bytesPerSample);
    for (uint32_t r = 0; r < height; r++) {
      for (uint32_t c = 0; c < width * bytesPerSample; c++) {
        size_t idx = (i * height * width + r * width + c) % profileSize;
        row[c] = data[idx] ^ (uint8_t)i;
      }
      tiff.WriteLine(row.data());
    }
    tiff.Close();
    close(fd);
    infiles.push_back(tf);
  }

  if ((int)infiles.size() < nSamples) {
    for (auto tf : infiles) { unlink(tf); free(tf); }
    return 0;
  }

  // Open all input files — matches tool: for (int i=0; i<nSamples; i++) infile[i].Open()
  std::vector<CTiffImg> inputs(nSamples);
  bool allOk = true;
  for (uint8_t i = 0; i < nSamples; i++) {
    if (!inputs[i].Open(infiles[i])) { allOk = false; break; }
    // Tool checks: GetSamples()==1, not PALETTE, matching dimensions
    if (inputs[i].GetSamples() != 1) { allOk = false; break; }
    if (inputs[i].GetPhoto() == PHOTOMETRIC_PALETTE) { allOk = false; break; }
  }

  if (!allOk) {
    for (auto tf : infiles) { unlink(tf); free(tf); }
    return 0;
  }

  CTiffImg *f = &inputs[0];
  long bytePerLine = f->GetBytesPerLine();
  long bps_img = f->GetBitsPerSample() / 8;

  // Tool: unique_ptr<icUInt8Number> inbufffer(new icUInt8Number[bytePerLine*nSamples]);
  std::unique_ptr<icUInt8Number[]> inbuf(new icUInt8Number[bytePerLine * nSamples]);
  std::unique_ptr<icUInt8Number[]> outbuf(new icUInt8Number[f->GetWidth() * bps_img * nSamples]);

  float xRes = f->GetXRes() > 1 ? f->GetXRes() : 72;
  float yRes = f->GetYRes() > 1 ? f->GetYRes() : 72;

  // Create output TIFF — tool: outfile.Create(argv[1], ...)
  char outpath[PATH_MAX];
  if (!fuzz_build_path(outpath, sizeof(outpath), tmpdir, "/fuzz_specb_out_XXXXXX")) {
    for (auto tf : infiles) { unlink(tf); free(tf); }
    return 0;
  }
  int outfd = mkstemp(outpath);
  if (outfd < 0) {
    for (auto tf : infiles) { unlink(tf); free(tf); }
    return 0;
  }
  close(outfd);

  CTiffImg outimg;
  if (!outimg.Create(outpath, f->GetWidth(), f->GetHeight(), f->GetBitsPerSample(),
                     PHOTO_MINISBLACK, nSamples, 0, xRes, yRes, bCompress, bSep)) {
    unlink(outpath);
    for (auto tf : infiles) { unlink(tf); free(tf); }
    return 0;
  }

  // Embed ICC profile — tool: io.Open(argv[8]); io.Read8(); outfile.SetIccProfile()
  if (profileSize >= 128) {
    outimg.SetIccProfile((unsigned char*)data, (unsigned int)profileSize);

    // Parse profile through IccProfLib for coverage of tag/MPE/validation paths
    CIccMemIO memIO;
    if (memIO.Attach((icUInt8Number*)data, (icUInt32Number)profileSize)) {
      CIccProfile profile;
      if (profile.Read(&memIO)) {
        std::string report;
        profile.Validate(report);

        // Exercise spectral-relevant tag lookups
        profile.FindTag(icSigSpectralViewingConditionsTag);
        profile.FindTag(icSigSpectralDataInfoTag);
        profile.FindTag(icSigSpectralWhitePointTag);
        profile.FindTag(icSigProfileDescriptionTag);
        profile.FindTag(icSigAToB0Tag);
        profile.FindTag(icSigDToB0Tag);
      }
    }
  }

  // Interleave scanlines — exact match of tool's pixel loop
  for (uint32_t i = 0; i < f->GetHeight(); i++) {
    bool readOk = true;
    for (uint8_t j = 0; j < nSamples; j++) {
      icUInt8Number *sptr = inbuf.get() + j * bytePerLine;
      if (!inputs[j].ReadLine(sptr)) { readOk = false; break; }
    }
    if (!readOk) break;

    icUInt8Number *tptr = outbuf.get();
    for (uint32_t k = 0; k < f->GetWidth(); k++) {
      for (uint8_t j = 0; j < nSamples; j++) {
        icUInt8Number *sptr = inbuf.get() + j * bytePerLine + k * bps_img;
        memcpy(tptr, sptr, bps_img);
        tptr += bps_img;
      }
    }
    outimg.WriteLine(outbuf.get());
  }

  // Tool: outfile.Close()
  outimg.Close();

  // Cleanup temp files
  unlink(outpath);
  for (auto tf : infiles) { unlink(tf); free(tf); }
  return 0;
}
