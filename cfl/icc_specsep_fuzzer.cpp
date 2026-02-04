/** @file
    File:       icc_specsep_fuzzer.cpp
    Contains:   LibFuzzer harness for IccSpecSepToTiff spectral separation
    Version:    V1
    Copyright:  (c) see Software License
*/

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

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <cstring>
#include <vector>
#include <memory>
#include <unistd.h>
#include <sys/stat.h>
#include <tiffio.h>

#include "IccProfile.h"
#include "IccUtil.h"
#include "TiffImg.h"

static void SilentTIFFErrorHandler(const char*, const char*, va_list) {}
static void SilentTIFFWarningHandler(const char*, const char*, va_list) {}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  TIFFSetErrorHandler(SilentTIFFErrorHandler);
  TIFFSetWarningHandler(SilentTIFFWarningHandler);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 16 || size > 10 * 1024 * 1024) return 0;

  // Parse fuzzer input:
  // [0-3]: number of input files (1-8)
  // [4-7]: width (1-1024)
  // [8-11]: height (1-1024)
  // [12]: bits per sample (8 or 16)
  // [13]: compress flag
  // [14]: separate flag
  // [15-]: TIFF data + optional ICC profile

  uint8_t nFiles = (data[0] % 8) + 1;
  uint32_t width = ((data[1] % 64) + 1);
  uint32_t height = ((data[2] % 64) + 1);
  uint8_t bitsPerSample = (data[12] & 1) ? 16 : 8;
  bool compress = data[13] & 1;
  bool separate = data[14] & 1;

  size_t bytesPerSample = bitsPerSample / 8;
  size_t minDataSize = width * height * bytesPerSample * nFiles;

  if (size < 15 + minDataSize) return 0;

  // Create temporary input TIFF files
  std::vector<char*> tmpfiles;
  
  for (uint8_t i = 0; i < nFiles; i++) {
    char *tmpfile = (char*)malloc(32);
    snprintf(tmpfile, 32, "/tmp/fuzz_sep_%d_XXXXXX", i);
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
      for (auto tf : tmpfiles) {
        unlink(tf);
        free(tf);
      }
      free(tmpfile);
      return 0;
    }

    tmpfiles.push_back(tmpfile);

    // Create simple single-channel TIFF
    CTiffImg tiff;
    if (!tiff.Create(tmpfile, width, height, bitsPerSample, PHOTO_MINISBLACK, 1, 0, 72, 72, false, false)) {
      close(fd);
      for (auto tf : tmpfiles) {
        unlink(tf);
        free(tf);
      }
      return 0;
    }

    // Write pixel data from fuzzer input
    size_t offset = 15 + (i * width * height * bytesPerSample);
    const uint8_t *pixelData = data + offset;
    
    for (uint32_t row = 0; row < height; row++) {
      size_t rowOffset = row * width * bytesPerSample;
      if (offset + rowOffset + width * bytesPerSample > size) {
        tiff.Close();
        close(fd);
        for (auto tf : tmpfiles) {
          unlink(tf);
          free(tf);
        }
        return 0;
      }
      tiff.WriteLine((icUInt8Number*)(pixelData + rowOffset));
    }

    tiff.Close();
    close(fd);
  }

  // Create output file
  char outfile[] = "/tmp/fuzz_out_XXXXXX";
  int outfd = mkstemp(outfile);
  if (outfd < 0) {
    for (auto tf : tmpfiles) {
      unlink(tf);
      free(tf);
    }
    return 0;
  }
  close(outfd);

  // Open all input files - pre-allocate vector to avoid moves
  std::vector<CTiffImg> infiles(nFiles);
  bool allOpened = true;
  
  for (uint8_t i = 0; i < nFiles; i++) {
    if (!infiles[i].Open(tmpfiles[i])) {
      allOpened = false;
      break;
    }
    
    if (infiles[i].GetSamples() != 1 || infiles[i].GetPhoto() == PHOTOMETRIC_PALETTE) {
      allOpened = false;
      break;
    }
  }

  if (allOpened && nFiles > 0) {
    CTiffImg *f = &infiles[0];
    long bytePerLine = f->GetBytesPerLine();
    long bytesPerSample_img = f->GetBitsPerSample() / 8;

    std::unique_ptr<icUInt8Number[]> inbuffer(new icUInt8Number[bytePerLine * nFiles]);
    std::unique_ptr<icUInt8Number[]> outbuffer(new icUInt8Number[f->GetWidth() * bytesPerSample_img * nFiles]);
    
    icUInt8Number *inbuf = inbuffer.get();
    icUInt8Number *outbuf = outbuffer.get();

    float xRes = f->GetXRes() > 1 ? f->GetXRes() : 72;
    float yRes = f->GetYRes() > 1 ? f->GetYRes() : 72;

    CTiffImg outimg;
    if (outimg.Create(outfile, f->GetWidth(), f->GetHeight(), f->GetBitsPerSample(),
                      PHOTO_MINISBLACK, nFiles, 0, xRes, yRes, compress, separate)) {
      
      // Optional ICC profile embedding
      size_t profileOffset = 15 + minDataSize;
      if (size > profileOffset + 128) {
        size_t profileSize = std::min(size - profileOffset, (size_t)1024 * 1024);
        std::unique_ptr<unsigned char[]> profile(new unsigned char[profileSize]);
        memcpy(profile.get(), data + profileOffset, profileSize);
        outimg.SetIccProfile(profile.get(), (unsigned int)profileSize);
      }

      // Process scanlines
      for (uint32_t i = 0; i < f->GetHeight(); i++) {
        bool readOk = true;
        for (uint8_t j = 0; j < nFiles; j++) {
          icUInt8Number *sptr = inbuf + j * bytePerLine;
          if (!infiles[j].ReadLine(sptr)) {
            readOk = false;
            break;
          }
        }

        if (!readOk) break;

        icUInt8Number *tptr = outbuf;
        for (uint32_t k = 0; k < f->GetWidth(); k++) {
          for (uint8_t j = 0; j < nFiles; j++) {
            icUInt8Number *sptr = inbuf + j * bytePerLine + k * bytesPerSample_img;
            memcpy(tptr, sptr, bytesPerSample_img);
            tptr += bytesPerSample_img;
          }
        }
        outimg.WriteLine(outbuf);
      }
      
      outimg.Close();
    }
  }

  // Cleanup
  unlink(outfile);
  for (auto tf : tmpfiles) {
    unlink(tf);
    free(tf);
  }

  return 0;
}
