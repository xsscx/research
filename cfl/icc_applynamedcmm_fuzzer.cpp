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
#include <cstring>
#include "IccCmm.h"
#include "IccUtil.h"
#include "IccDefs.h"
#include "IccApplyBPC.h"
#include "IccEnvVar.h"
#include <climits>

// Fuzzer input structure (packed):
// [0-3]: Profile data (remaining bytes)
// Profile header: [0]: flags byte
//   bit 0: use BPC
//   bit 1: use D2Bx/B2Dx tags
//   bit 2: adjust PCS luminance
//   bit 3: use V5 sub-profile
//   bit 4-5: interpolation (0=linear, 1=tetrahedral)
//   bit 6-7: reserved
// [1]: rendering intent (0-3 base, +modifiers)
// [2-3]: source color space signature (16-bit index)
// [4-5]: dest color space signature (16-bit index)
// [6]: interface type hint (0=pixel2pixel, 1=named2pixel, 2=pixel2named, 3=named2named)
// [7-9]: reserved for future use
// [10+]: ICC profile data

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum: 4 byte control + 128 byte minimal ICC profile
  if (size < 132 || size > 2 * 1024 * 1024) return 0;

  // Parse fuzzing configuration from first 4 bytes
  uint8_t flags = data[0];
  bool useBPC = (flags & 0x01) != 0;
  bool useD2BxB2Dx = (flags & 0x02) != 0;
  bool adjustPcsLuminance = (flags & 0x04) != 0;
  bool useV5SubProfile = (flags & 0x08) != 0;
  icXformInterp interp = ((flags >> 4) & 0x01) ? icInterpTetrahedral : icInterpLinear;
  icRenderingIntent intent = (icRenderingIntent)(data[1] & 0x03);
  icFloatColorEncoding srcEncoding = (icFloatColorEncoding)(data[2] % 7);
  icFloatColorEncoding dstEncoding = (icFloatColorEncoding)(data[3] % 7);

  // Profile data starts at offset 4
  const uint8_t *profile_data = data + 4;
  size_t profile_size = size - 4;

  // Write profile to temporary file
  const char *tmpdir = getenv("FUZZ_TMPDIR");
  if (!tmpdir) tmpdir = "/tmp";
  char tmp_profile[PATH_MAX];
  snprintf(tmp_profile, sizeof(tmp_profile), "%s/fuzz_namedcmm_XXXXXX", tmpdir);
  int fd = mkstemp(tmp_profile);
  if (fd == -1) return 0;
  
  ssize_t written = write(fd, profile_data, profile_size);
  close(fd);
  if (written != (ssize_t)profile_size) {
    unlink(tmp_profile);
    return 0;
  }

  // Read profile to determine source color space from its header
  // (mirrors iccApplyNamedCmm.cpp: SrcspaceSig comes from profile)
  CIccProfile *pProf = OpenIccProfile(tmp_profile);
  if (!pProf) {
    unlink(tmp_profile);
    return 0;
  }
  
  icColorSpaceSignature srcSpace = pProf->m_Header.colorSpace;
  bool srcIsPCS = (srcSpace == icSigXYZData || srcSpace == icSigLabData);
  bool bInputProfile = !srcIsPCS;
  if (!bInputProfile) {
    if (pProf->m_Header.deviceClass != icSigAbstractClass && srcIsPCS)
      bInputProfile = true;
  }
  delete pProf;

  // Tool uses icSigUnknownData for dst — CMM determines it from profile chain
  CIccNamedColorCmm namedCmm(srcSpace, icSigUnknownData, bInputProfile);

  // Build hint manager for profile attachment (mirrors lines 354-389)
  CIccCreateXformHintManager Hint;
  
  if (useBPC) {
    Hint.AddHint(new CIccApplyBPCHint());
  }
  
  if (adjustPcsLuminance) {
    Hint.AddHint(new CIccLuminanceMatchingHint());
  }

  // Add environment variable hints (exercise IccEnvVar.h)
  // icCmmEnvSigMap maps icSignature -> icFloatNumber
  if ((flags & 0x80) != 0) {
    icCmmEnvSigMap envVars;
    envVars[0x656E7631] = 1.0; // 'env1' -> 1.0
    Hint.AddHint(new CIccCmmEnvVarHint(envVars));
  }

  // Add profile to CMM (mirrors lines 382-392)
  icStatusCMM stat = namedCmm.AddXform(
    tmp_profile,
    intent,
    interp,
    nullptr,  // No PCC profile for fuzzing simplicity
    icXformLutColor,
    useD2BxB2Dx,
    &Hint,
    useV5SubProfile
  );

  if (stat != icCmmStatOk) {
    unlink(tmp_profile);
    return 0;
  }

  // Initialize CMM (mirrors line 398)
  stat = namedCmm.Begin();
  
  if (stat != icCmmStatOk) {
    unlink(tmp_profile);
    return 0;
  }

  // Get actual CMM interface type (determined by profiles)
  icApplyInterface interface = namedCmm.GetInterface();
  
  // Get source and destination color spaces
  icColorSpaceSignature actualSrcSpace = namedCmm.GetSourceSpace();
  icColorSpaceSignature actualDstSpace = namedCmm.GetDestSpace();
  
  int nSrcSamples = icGetSpaceSamples(actualSrcSpace);
  int nDstSamples = icGetSpaceSamples(actualDstSpace);
  
  // Validate sample counts
  if (nSrcSamples <= 0 || nSrcSamples > 16 || 
      nDstSamples <= 0 || nDstSamples > 16) {
    unlink(tmp_profile);
    return 0;
  }

  // Apply transformations based on interface type
  // (mirrors iccApplyNamedCmm.cpp lines 470-560)
  
  switch (interface) {
    case icApplyNamed2Pixel: {
      // Named color to pixel transformation
      icFloatNumber dstPixel[16];
      const char *testNames[] = {
        "White", "Black", "Red", "Green", "Blue",
        "Cyan", "Magenta", "Yellow", "Gray"
      };
      
      for (size_t i = 0; i < sizeof(testNames) / sizeof(testNames[0]); i++) {
        icFloatNumber tint = 1.0;
        namedCmm.Apply(dstPixel, testNames[i], tint);
        
        // Test tint variations
        tint = 0.5;
        namedCmm.Apply(dstPixel, testNames[i], tint);
        
        tint = 0.0;
        namedCmm.Apply(dstPixel, testNames[i], tint);
      }
      break;
    }
    
    case icApplyPixel2Pixel: {
      // Pixel to pixel transformation (most common case)
      icFloatNumber srcPixel[16];
      icFloatNumber dstPixel[16];
      
      // Test 1: Black (all zeros)
      memset(srcPixel, 0, sizeof(icFloatNumber) * nSrcSamples);
      namedCmm.Apply(dstPixel, srcPixel);
      
      // Test 2: White (all ones)
      for (int i = 0; i < nSrcSamples; i++) {
        srcPixel[i] = 1.0;
      }
      namedCmm.Apply(dstPixel, srcPixel);
      
      // Test 3: Gray (all 0.5)
      for (int i = 0; i < nSrcSamples; i++) {
        srcPixel[i] = 0.5;
      }
      namedCmm.Apply(dstPixel, srcPixel);
      
      // Test 4: Primary colors
      for (int j = 0; j < nSrcSamples && j < 8; j++) {
        memset(srcPixel, 0, sizeof(icFloatNumber) * nSrcSamples);
        srcPixel[j] = 1.0;
        namedCmm.Apply(dstPixel, srcPixel);
      }
      
      // Test 5: Edge cases - negative values
      for (int i = 0; i < nSrcSamples; i++) {
        srcPixel[i] = -0.1;
      }
      namedCmm.Apply(dstPixel, srcPixel);
      
      // Test 6: Edge cases - values > 1.0
      for (int i = 0; i < nSrcSamples; i++) {
        srcPixel[i] = 1.5;
      }
      namedCmm.Apply(dstPixel, srcPixel);
      
      // Test 7: NaN/Inf handling (critical for fuzzing)
      for (int i = 0; i < nSrcSamples; i++) {
        srcPixel[i] = 0.0 / 0.0; // NaN
      }
      namedCmm.Apply(dstPixel, srcPixel);
      
      for (int i = 0; i < nSrcSamples; i++) {
        srcPixel[i] = 1.0 / 0.0; // +Inf
      }
      namedCmm.Apply(dstPixel, srcPixel);
      
      // Test 8: Random values from remaining fuzz data
      if (size > 132) {
        size_t remaining = size - 132;
        for (int i = 0; i < nSrcSamples && i < (int)remaining; i++) {
          srcPixel[i] = ((icFloatNumber)data[132 + i] / 127.5) - 1.0;
        }
        namedCmm.Apply(dstPixel, srcPixel);
      }
      
      // Test 9: Batch apply (tests multi-pixel path)
      icFloatNumber batchSrc[48]; // 3 pixels * 16 channels max
      icFloatNumber batchDst[48];
      
      for (int i = 0; i < nSrcSamples * 3; i++) {
        batchSrc[i] = ((icFloatNumber)(i % 256)) / 255.0;
      }
      namedCmm.Apply(batchDst, batchSrc, 3);
      
      break;
    }
    
    case icApplyNamed2Named: {
      // Named color to named color transformation
      icChar srcName[256];
      icChar dstName[256];
      const char *testNames[] = {"White", "Black", "Red"};
      
      for (size_t i = 0; i < sizeof(testNames) / sizeof(testNames[0]); i++) {
        strncpy(srcName, testNames[i], sizeof(srcName) - 1);
        srcName[sizeof(srcName) - 1] = '\0';
        
        icFloatNumber tint = 1.0;
        namedCmm.Apply(dstName, srcName, tint);
      }
      break;
    }
    
    case icApplyPixel2Named: {
      // Pixel to named color transformation
      icFloatNumber srcPixel[16];
      icChar dstName[256];
      
      // Test white point
      for (int i = 0; i < nSrcSamples; i++) {
        srcPixel[i] = 1.0;
      }
      namedCmm.Apply(dstName, srcPixel);
      
      // Test black point
      memset(srcPixel, 0, sizeof(icFloatNumber) * nSrcSamples);
      namedCmm.Apply(dstName, srcPixel);
      
      break;
    }
    
    default:
      // Unknown interface - should not occur if CMM is valid
      break;
  }

  // Exercise CMM query methods (mirrors IccApplyNamedCmm usage)
  (void)namedCmm.GetNumXforms();
  (void)namedCmm.Valid();
  (void)namedCmm.GetSourceSpace();
  (void)namedCmm.GetDestSpace();
  (void)namedCmm.GetLastSpace();
  (void)namedCmm.GetLastParentSpace();
  
  // Test encoding conversion functions (mirrors lines 489, 523, 541)
  // These are critical paths that handle different encoding formats
  icFloatNumber testPixel[16];
  icFloatNumber convertedPixel[16];
  
  for (int i = 0; i < nDstSamples; i++) {
    testPixel[i] = 0.5;
  }
  
  // Test various encoding conversions
  icFloatColorEncoding encodings[] = {
    icEncodeValue,
    icEncodePercent, 
    icEncodeUnitFloat,
    icEncodeFloat,
    icEncode16Bit,
    icEncode16BitV2
  };
  
  for (size_t i = 0; i < sizeof(encodings) / sizeof(encodings[0]); i++) {
    // ToInternalEncoding test (source encoding)
    CIccCmm::ToInternalEncoding(actualSrcSpace, encodings[i], 
                                 convertedPixel, testPixel, true);
    
    // FromInternalEncoding test (destination encoding)
    CIccCmm::FromInternalEncoding(actualDstSpace, encodings[i],
                                   convertedPixel, testPixel, false);
  }

  unlink(tmp_profile);
  return 0;
}
