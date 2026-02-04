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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 200 || size > 5 * 1024 * 1024) return 0;

  // Split input: first part is profile data, rest is control data
  size_t profile_size = (size * 3) / 4;
  if (profile_size < 130) return 0;
  
  const uint8_t *profile_data = data;
  const uint8_t *control_data = data + profile_size;
  size_t control_size = size - profile_size;
  
  if (control_size < 4) return 0;

  // Extract fuzzing parameters from control data
  icRenderingIntent intent = (icRenderingIntent)(control_data[0] % 4);
  icXformInterp interp = (control_data[1] & 1) ? icInterpLinear : icInterpTetrahedral;
  bool use_bpc = (control_data[2] & 1) != 0;
  bool use_d2bx = (control_data[3] & 1) != 0;

  // Write profile to temporary file
  char tmp_profile[] = "/tmp/fuzz_applyprofiles_XXXXXX.icc";
  int fd = mkstemp(tmp_profile);
  if (fd == -1) return 0;
  write(fd, profile_data, profile_size);
  close(fd);

  // Create CMM and add profile
  CIccCmm cmm(icSigUnknownData, icSigUnknownData, true);
  
  CIccCreateXformHintManager hint;
  if (use_bpc) {
    // BPC hint would be added here if available
  }

  icStatusCMM stat = cmm.AddXform(tmp_profile, intent, interp, nullptr, 
                                   icXformLutColor, use_d2bx, &hint);
  
  if (stat == icCmmStatOk) {
    stat = cmm.Begin();
    
    if (stat == icCmmStatOk) {
      // Get color space information
      icColorSpaceSignature srcSpace = cmm.GetSourceSpace();
      icColorSpaceSignature dstSpace = cmm.GetDestSpace();
      
      int nSrcSamples = icGetSpaceSamples(srcSpace);
      int nDstSamples = icGetSpaceSamples(dstSpace);
      
      // Validate sample counts
      if (nSrcSamples > 0 && nSrcSamples <= 16 && 
          nDstSamples > 0 && nDstSamples <= 16) {
        
        // Test various pixel values
        icFloatNumber srcPixel[16];
        icFloatNumber dstPixel[16];
        
        // Test 1: Black (all zeros)
        memset(srcPixel, 0, sizeof(icFloatNumber) * nSrcSamples);
        cmm.Apply(dstPixel, srcPixel);
        
        // Test 2: White (all ones)
        for (int i = 0; i < nSrcSamples; i++) {
          srcPixel[i] = 1.0f;
        }
        cmm.Apply(dstPixel, srcPixel);
        
        // Test 3: Gray (all 0.5)
        for (int i = 0; i < nSrcSamples; i++) {
          srcPixel[i] = 0.5f;
        }
        cmm.Apply(dstPixel, srcPixel);
        
        // Test 4: Primary colors (varied)
        for (int j = 0; j < nSrcSamples && j < 8; j++) {
          memset(srcPixel, 0, sizeof(icFloatNumber) * nSrcSamples);
          srcPixel[j] = 1.0f;
          cmm.Apply(dstPixel, srcPixel);
        }
        
        // Test 5: Edge cases from control data
        if (control_size >= 4 + nSrcSamples) {
          for (int i = 0; i < nSrcSamples; i++) {
            // Normalize byte values to 0.0-1.0 range
            srcPixel[i] = (icFloatNumber)control_data[4 + i] / 255.0f;
          }
          cmm.Apply(dstPixel, srcPixel);
        }
        
        // Test 6: Out of range values (negative and >1.0)
        for (int i = 0; i < nSrcSamples; i++) {
          srcPixel[i] = -0.1f;
        }
        cmm.Apply(dstPixel, srcPixel);
        
        for (int i = 0; i < nSrcSamples; i++) {
          srcPixel[i] = 1.1f;
        }
        cmm.Apply(dstPixel, srcPixel);
        
        // Test 7: NaN and infinity (if supported)
        for (int i = 0; i < nSrcSamples; i++) {
          srcPixel[i] = 0.0f / 0.0f; // NaN
        }
        cmm.Apply(dstPixel, srcPixel);
        
        // Exercise CMM query methods
        cmm.GetNumXforms();
        cmm.Valid();
        cmm.GetLastParentSpace();
        cmm.GetLastSpace();
      }
    }
  }

  unlink(tmp_profile);
  return 0;
}
