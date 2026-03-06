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

//
// icc_applyprofiles_fuzzer.cpp — Full-pipeline fuzzer matching iccApplyProfiles.cpp
//
// Exercises: CTiffImg Open/Create/ReadLine/WriteLine, embedded ICC profile
// extraction, CIccCmm with BPC/Luminance/D2Bx hints, pixel encoding
// (8/16/32-bit, Lab/XYZ/RGB), CIccPixelBuf, CIccFileIO profile embedding,
// and the complete source→CMM→destination pixel loop.
//
// Input format (backward compatible):
//   [0..profile_end]:  ICC profile data (75% of input)
//   [profile_end+0]:   intent (0-3)
//   [profile_end+1]:   interp (bit 0)
//   [profile_end+2]:   flags: bit0=BPC, bit1=luminance, bit2=useV5SubProfile,
//                              bit3=embed_icc, bit4..5=bps_select, bit6..7=photo_select
//   [profile_end+3]:   bit0=use_d2bx, bit1..2=width(1-4), bit3..4=height(1-4)
//   [profile_end+4..]: pixel seed data
//

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <tiffio.h>
#include "IccCmm.h"
#include "IccUtil.h"
#include "IccDefs.h"
#include "IccApplyBPC.h"
#include "IccIO.h"
#include "TiffImg.h"
#include <climits>
#include "fuzz_utils.h"

static icFloatNumber UnitClip(icFloatNumber v) {
  if (v != v) return 0.0;  // NaN guard
  if (v < 0.0) return 0.0;
  if (v > 1.0) return 1.0;
  return v;
}

static void SilentTIFFErrorHandler(const char*, const char*, va_list) {}
static void SilentTIFFWarningHandler(const char*, const char*, va_list) {}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  TIFFSetErrorHandler(SilentTIFFErrorHandler);
  TIFFSetWarningHandler(SilentTIFFWarningHandler);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 200 || size > 5 * 1024 * 1024) return 0;

  // Split input: first part is profile data, rest is control data
  size_t profile_size = (size * 3) / 4;
  if (profile_size < 130) return 0;

  const uint8_t *profile_data = data;
  const uint8_t *control_data = data + profile_size;
  size_t control_size = size - profile_size;

  if (control_size < 4) return 0;

  // Extract fuzzing parameters from control data (backward compatible layout)
  icRenderingIntent intent = (icRenderingIntent)(control_data[0] % 4);
  icXformInterp interp = (control_data[1] & 1) ? icInterpLinear : icInterpTetrahedral;

  uint8_t flags  = control_data[2];
  bool use_bpc         = (flags & 0x01) != 0;
  bool use_luminance   = (flags & 0x02) != 0;
  bool use_v5sub       = (flags & 0x04) != 0;
  bool embed_icc       = (flags & 0x08) != 0;
  unsigned int bps_sel = (flags >> 4) & 0x03;  // 0=8, 1=16, 2=32, 3=8
  unsigned int photo_sel = (flags >> 6) & 0x03; // 0=RGB, 1=CIELAB, 2=MINISBLACK, 3=MINISWHITE

  bool use_d2bx  = (control_data[3] & 0x01) != 0;
  unsigned int img_w = ((control_data[3] >> 1) & 0x03) + 1;  // 1-4 pixels wide
  unsigned int img_h = ((control_data[3] >> 3) & 0x03) + 1;  // 1-4 pixels tall

  // Map bps and photo selections
  unsigned int bps;
  switch (bps_sel) {
    case 1:  bps = 16; break;
    case 2:  bps = 32; break;
    default: bps = 8;  break;
  }

  static const unsigned int photoModes[] = { PHOTO_RGB, PHOTO_CIELAB, PHOTO_MINISBLACK, PHOTO_MINISWHITE };
  unsigned int sphoto = photoModes[photo_sel];
  unsigned int sn = (sphoto == PHOTO_RGB || sphoto == PHOTO_CIELAB) ? 3 : 1;

  const char *tmpdir = fuzz_tmpdir();

  // --- Phase 1: Write ICC profile to temp file ---
  char tmp_profile[PATH_MAX];
  if (!fuzz_build_path(tmp_profile, sizeof(tmp_profile), tmpdir, "/fuzz_ap_prof_XXXXXX.icc")) return 0;
  int fd = mkstemps(tmp_profile, 4);
  if (fd == -1) return 0;
  write(fd, profile_data, profile_size);
  close(fd);

  // --- Phase 2: Create source TIFF with embedded ICC profile ---
  char tmp_src_tiff[PATH_MAX];
  if (!fuzz_build_path(tmp_src_tiff, sizeof(tmp_src_tiff), tmpdir, "/fuzz_ap_src_XXXXXX.tif")) {
    unlink(tmp_profile);
    return 0;
  }
  fd = mkstemps(tmp_src_tiff, 4);
  if (fd == -1) { unlink(tmp_profile); return 0; }
  close(fd);

  {
    CTiffImg srcCreate;
    if (!srcCreate.Create(tmp_src_tiff, img_w, img_h, bps, sphoto, sn, 0, 72.0f, 72.0f, false, false)) {
      unlink(tmp_profile);
      unlink(tmp_src_tiff);
      return 0;
    }

    // Embed ICC profile into source TIFF (tool line 251: GetIccProfile)
    srcCreate.SetIccProfile((unsigned char*)profile_data, (unsigned int)std::min(profile_size, (size_t)UINT_MAX));

    // Write pixel rows from control_data seed
    unsigned int bytesPerLine = srcCreate.GetBytesPerLine();
    unsigned char *rowBuf = (unsigned char *)calloc(1, bytesPerLine);
    if (rowBuf) {
      for (unsigned int row = 0; row < img_h; row++) {
        size_t seed_off = 4 + row * bytesPerLine;
        size_t avail = (seed_off < control_size) ? std::min((size_t)bytesPerLine, control_size - seed_off) : 0;
        if (avail > 0)
          memcpy(rowBuf, control_data + seed_off, avail);
        srcCreate.WriteLine(rowBuf);
      }
      free(rowBuf);
    }
    srcCreate.Close();
  }

  // --- Phase 3: Open source TIFF and extract info (tool lines 206-251) ---
  CTiffImg SrcImg;
  if (!SrcImg.Open(tmp_src_tiff)) {
    unlink(tmp_profile);
    unlink(tmp_src_tiff);
    return 0;
  }

  unsigned int read_sn = SrcImg.GetSamples();
  unsigned int read_sen = SrcImg.GetExtraSamples();
  unsigned int read_sphoto = SrcImg.GetPhoto();
  unsigned int read_bps = SrcImg.GetBitsPerSample();
  (void)SrcImg.GetCompress();
  (void)SrcImg.GetPlanar();
  (void)SrcImg.GetWidth();
  (void)SrcImg.GetHeight();
  (void)SrcImg.GetXRes();
  (void)SrcImg.GetYRes();

  unsigned char *pSrcProfile = nullptr;
  unsigned int nSrcProfileLen = 0;
  bool bHasSrcProfile = SrcImg.GetIccProfile(pSrcProfile, nSrcProfileLen);

  // --- Phase 4: Build CMM with hints (tool lines 262-346) ---
  CIccCmm theCmm(icSigUnknownData, icSigUnknownData, true);

  CIccCreateXformHintManager Hint;
  if (use_bpc)
    Hint.AddHint(new CIccApplyBPCHint());
  if (use_luminance)
    Hint.AddHint(new CIccLuminanceMatchingHint());

  icStatusCMM stat;

  // Try embedded profile path first (tool line 314), then file path (tool line 334)
  if (bHasSrcProfile && pSrcProfile && nSrcProfileLen > 128) {
    stat = theCmm.AddXform(pSrcProfile, (icUInt32Number)nSrcProfileLen,
                           intent, interp, nullptr, icXformLutColor,
                           use_d2bx, &Hint, use_v5sub);
  } else {
    stat = theCmm.AddXform(tmp_profile, intent, interp, nullptr,
                           icXformLutColor, use_d2bx, &Hint, use_v5sub);
  }

  if (stat != icCmmStatOk) {
    SrcImg.Close();
    unlink(tmp_profile);
    unlink(tmp_src_tiff);
    return 0;
  }

  // --- Phase 5: Begin CMM (tool line 350) ---
  stat = theCmm.Begin();
  if (stat != icCmmStatOk) {
    SrcImg.Close();
    unlink(tmp_profile);
    unlink(tmp_src_tiff);
    return 0;
  }

  // --- Phase 6: Validate color spaces (tool lines 364-397) ---
  icColorSpaceSignature SrcspaceSig = theCmm.GetSourceSpace();
  int nSrcColorSamples = icGetSpaceSamples(SrcspaceSig);

  icColorSpaceSignature DestSpaceSig = theCmm.GetDestSpace();
  int nDestSamples = icGetSpaceSamples(DestSpaceSig);

  icColorSpaceSignature DestParentSpaceSig = theCmm.GetLastParentSpace();
  int nDestParentSamples = icGetSpaceSamples(DestParentSpaceSig);

  int nExtraSamples = 0;
  icColorSpaceSignature DestColorSpaceSig = DestSpaceSig;
  if (nDestParentSamples && nDestSamples != nDestParentSamples) {
    DestColorSpaceSig = DestParentSpaceSig;
    nExtraSamples = nDestSamples - nDestParentSamples;
  }

  // Determine destination photo (tool lines 399-424)
  unsigned int dphoto;
  switch (DestColorSpaceSig) {
    case icSigRgbData:     dphoto = PHOTO_RGB; break;
    case icSigCmyData:
    case icSigCmykData:
    case icSig4colorData:
    case icSig5colorData:
    case icSig6colorData:
    case icSig7colorData:
    case icSig8colorData:  dphoto = PHOTO_MINISWHITE; break;
    case icSigXYZData:
    case icSigLabData:     dphoto = PHOTO_CIELAB; break;
    default:               dphoto = PHOTO_MINISBLACK; break;
  }

  unsigned int dbps = bps;
  if (nSrcColorSamples <= 0 || nSrcColorSamples > 16 ||
      nDestSamples <= 0 || nDestSamples > 16) {
    SrcImg.Close();
    unlink(tmp_profile);
    unlink(tmp_src_tiff);
    return 0;
  }

  // Source space validation (tool lines 368-382)
  int nSrcSamples = nSrcColorSamples;
  if (nSrcSamples != (int)read_sn) {
    if (read_sen != 0 && nSrcSamples == (int)(read_sn - read_sen)) {
      nSrcSamples = read_sn;
    } else {
      SrcImg.Close();
      unlink(tmp_profile);
      unlink(tmp_src_tiff);
      return 0;
    }
  }

  // --- Phase 7: Create destination TIFF (tool line 430) ---
  char tmp_dst_tiff[PATH_MAX];
  if (!fuzz_build_path(tmp_dst_tiff, sizeof(tmp_dst_tiff), tmpdir, "/fuzz_ap_dst_XXXXXX.tif")) {
    SrcImg.Close();
    unlink(tmp_profile);
    unlink(tmp_src_tiff);
    return 0;
  }
  fd = mkstemps(tmp_dst_tiff, 4);
  if (fd == -1) {
    SrcImg.Close();
    unlink(tmp_profile);
    unlink(tmp_src_tiff);
    return 0;
  }
  close(fd);

  CTiffImg DstImg;
  if (!DstImg.Create(tmp_dst_tiff, SrcImg.GetWidth(), SrcImg.GetHeight(),
                     dbps, dphoto, nDestSamples, nExtraSamples,
                     SrcImg.GetXRes(), SrcImg.GetYRes(), false, false)) {
    SrcImg.Close();
    unlink(tmp_profile);
    unlink(tmp_src_tiff);
    unlink(tmp_dst_tiff);
    return 0;
  }

  // Embed destination profile (tool lines 436-451)
  if (embed_icc) {
    CIccFileIO io;
    if (io.Open(tmp_profile, "r")) {
      icUInt32Number length = io.GetLength();
      if (length > 0 && length < 10 * 1024 * 1024) {
        icUInt8Number *pDestProfile = (icUInt8Number *)malloc(length);
        if (pDestProfile) {
          io.Read8(pDestProfile, (icInt32Number)length);
          DstImg.SetIccProfile(pDestProfile, length);
          free(pDestProfile);
        }
      }
      io.Close();
    }
  }

  // --- Phase 8: Pixel loop — read, encode, apply, decode, write (tool lines 454-617) ---
  unsigned int read_width = SrcImg.GetWidth();
  unsigned int read_height = SrcImg.GetHeight();

  unsigned long sbpp = (nSrcSamples * read_bps + 7) / 8;
  unsigned long dbpp = (nDestSamples * dbps + 7) / 8;

  unsigned char *pSBuf = (unsigned char *)malloc(SrcImg.GetBytesPerLine());
  unsigned char *pDBuf = (unsigned char *)malloc(DstImg.GetBytesPerLine());

  if (pSBuf && pDBuf) {
    CIccPixelBuf SrcPixelBuf(nSrcColorSamples + 16);
    CIccPixelBuf DestPixelBuf(nDestSamples + 16);

    for (unsigned int i = 0; i < read_height; i++) {
      if (!SrcImg.ReadLine(pSBuf))
        break;

      unsigned char *sptr = pSBuf;
      unsigned char *dptr = pDBuf;

      for (unsigned int j = 0; j < read_width; j++, sptr += sbpp, dptr += dbpp) {
        icFloatNumber *pSrcPix = SrcPixelBuf;
        icFloatNumber *pDstPix = DestPixelBuf;

        // Source pixel encoding (tool lines 481-538)
        switch (read_bps) {
          case 8:
            if (read_sphoto == PHOTO_CIELAB) {
              pSrcPix[0] = (icFloatNumber)sptr[0] / 255.0f;
              pSrcPix[1] = (icFloatNumber)((int)sptr[1] - 128) / 255.0f;
              pSrcPix[2] = (icFloatNumber)((int)sptr[2] - 128) / 255.0f;
            } else {
              for (int k = 0; k < nSrcColorSamples; k++)
                pSrcPix[k] = (icFloatNumber)sptr[k] / 255.0f;
            }
            break;
          case 16:
            if (read_sphoto == PHOTO_CIELAB) {
              unsigned short *pS16 = (unsigned short*)sptr;
              pSrcPix[0] = (icFloatNumber)pS16[0] / 65535.0f;
              pSrcPix[1] = (icFloatNumber)((int)pS16[1] - 0x8000) / 65535.0f;
              pSrcPix[2] = (icFloatNumber)((int)pS16[2] - 0x8000) / 65535.0f;
            } else {
              unsigned short *pS16 = (unsigned short*)sptr;
              for (int k = 0; k < nSrcColorSamples; k++)
                pSrcPix[k] = (icFloatNumber)pS16[k] / 65535.0f;
            }
            break;
          case 32:
            if (sizeof(icFloatNumber) == sizeof(icFloat32Number)) {
              memcpy(pSrcPix, sptr, sbpp);
            } else {
              icFloat32Number *pS32 = (icFloat32Number*)sptr;
              for (int k = 0; k < nSrcColorSamples; k++)
                pSrcPix[k] = (icFloatNumber)pS32[k];
            }
            if (read_sphoto == PHOTO_CIELAB || read_sphoto == PHOTO_ICCLAB)
              icLabToPcs(pSrcPix);
            break;
          default:
            break;
        }

        // Lab→XYZ PCS conversion (tool lines 539-543)
        if (read_sphoto == PHOTO_CIELAB && SrcspaceSig == icSigXYZData) {
          icLabFromPcs(pSrcPix);
          icLabtoXYZ(pSrcPix);
          icXyzToPcs(pSrcPix);
        }

        // CMM Apply (tool line 546)
        theCmm.Apply(pDstPix, pSrcPix);

        // XYZ→Lab PCS conversion (tool lines 549-553)
        if (dphoto == PHOTO_CIELAB && DestSpaceSig == icSigXYZData) {
          icXyzFromPcs(pDstPix);
          icXYZtoLab(pDstPix);
          icLabToPcs(pDstPix);
        }

        // Destination pixel encoding (tool lines 554-611)
        switch (dbps) {
          case 8:
            if (dphoto == PHOTO_CIELAB) {
              dptr[0] = (icUInt8Number)(UnitClip(pDstPix[0]) * 255.0f + 0.5f);
              dptr[1] = (icUInt8Number)(UnitClip(pDstPix[1]) * 255.0f + 0.5f) + 128;
              dptr[2] = (icUInt8Number)(UnitClip(pDstPix[2]) * 255.0f + 0.5f) + 128;
            } else {
              for (int k = 0; k < nDestSamples; k++)
                dptr[k] = (icUInt8Number)(UnitClip(pDstPix[k]) * 255.0f + 0.5f);
            }
            break;
          case 16:
            if (dphoto == PHOTO_CIELAB) {
              icUInt16Number *pD16 = (icUInt16Number*)dptr;
              pD16[0] = (icUInt16Number)(UnitClip(pDstPix[0]) * 65535.0f + 0.5f);
              pD16[1] = (icUInt16Number)(UnitClip(pDstPix[1]) * 65535.0f + 0.5f) + 0x8000;
              pD16[2] = (icUInt16Number)(UnitClip(pDstPix[2]) * 65535.0f + 0.5f) + 0x8000;
            } else {
              icUInt16Number *pD16 = (icUInt16Number*)dptr;
              for (int k = 0; k < nDestSamples; k++)
                pD16[k] = (icUInt16Number)(UnitClip(pDstPix[k]) * 65535.0f + 0.5f);
            }
            break;
          case 32:
            if (dphoto == PHOTO_CIELAB || dphoto == PHOTO_ICCLAB)
              icLabFromPcs(pDstPix);
            if (sizeof(icFloatNumber) == sizeof(icFloat32Number)) {
              memcpy(dptr, pDstPix, dbpp);
            } else {
              icFloat32Number *pD32 = (icFloat32Number*)dptr;
              for (int k = 0; k < nDestSamples; k++)
                pD32[k] = (icFloat32Number)pDstPix[k];
            }
            break;
          default:
            break;
        }
      }

      // Write converted line to destination (tool line 615)
      DstImg.WriteLine(pDBuf);
    }
  }

  free(pSBuf);
  free(pDBuf);

  SrcImg.Close();
  DstImg.Close();

  // --- Phase 9: CMM query methods ---
  (void)theCmm.GetNumXforms();
  (void)theCmm.Valid();
  (void)theCmm.GetLastParentSpace();
  (void)theCmm.GetLastSpace();

  unlink(tmp_profile);
  unlink(tmp_src_tiff);
  unlink(tmp_dst_tiff);
  return 0;
}
