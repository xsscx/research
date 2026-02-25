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
#include <climits>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 130 || size > 1024 * 1024) return 0;
  
  // Use fixed parameters that match real tool usage
  // Tools typically use Perceptual intent and Linear interpolation
  icRenderingIntent intent = icPerceptual;
  icXformInterp interp = icInterpLinear;
  
  // Write the COMPLETE profile without modification
  const char *tmpdir = getenv("FUZZ_TMPDIR");
  if (!tmpdir) tmpdir = "/tmp";
  char tmp_file[PATH_MAX];
  snprintf(tmp_file, sizeof(tmp_file), "%s/fuzz_apply_XXXXXX", tmpdir);
  int fd = mkstemp(tmp_file);
  if (fd == -1) return 0;
  write(fd, data, size);
  close(fd);
  
  CIccCmm cmm;
  if (cmm.AddXform(tmp_file, intent, interp) == icCmmStatOk) {
    icStatusCMM beginStatus = cmm.Begin();
    if (beginStatus == icCmmStatOk) {
      // Verify CMM is valid and has apply object before use
      // GetApply() can return non-null but with invalid internal state
      // so we need to try a test apply to verify it's actually usable
      if (!cmm.Valid()) {
        unlink(tmp_file);
        return 0;
      }
      
      CIccApplyCmm *pApply = cmm.GetApply();
      if (!pApply) {
        unlink(tmp_file);
        return 0;
      }
      
      // Get actual channel counts
      icUInt16Number nSrcChannels = cmm.GetSourceSamples();
      icUInt16Number nDstChannels = cmm.GetDestSamples();
      
      // Validate channel counts
      if (nSrcChannels == 0 || nDstChannels == 0 ||
          nSrcChannels > 16 || nDstChannels > 16) {
        unlink(tmp_file);
        return 0;
      }
      
      // Allocate buffers based on actual channel counts
      icFloatNumber in[128] = {0};
      icFloatNumber out[128] = {0};
      
      // Initialize test values - ensure we don't exceed array bounds
      int maxInit = (8 * nSrcChannels < 128) ? 8 * nSrcChannels : 127;
      for (int i = 0; i < maxInit; i++) {
        in[i] = (i % 10) * 0.1f;
      }
      
      // Apply transforms with bounds checking
      for (int i = 0; i < 8 && (i + 1) * nDstChannels <= 128 && 
                              (i + 1) * nSrcChannels <= 128; i++) {
        if (cmm.Apply(out + i * nDstChannels, in + i * nSrcChannels) != icCmmStatOk) {
          unlink(tmp_file);
          return 0;
        }
      }
      
      // Test edge cases
      icFloatNumber edge_in[64] = {0};
      icFloatNumber edge_out[64] = {0};
      for (int i = 0; i < 4 && (i + 1) * nDstChannels <= 64 &&
                              (i + 1) * nSrcChannels <= 64; i++) {
        if (cmm.Apply(edge_out + i * nDstChannels, edge_in + i * nSrcChannels) != icCmmStatOk) {
          unlink(tmp_file);
          return 0;
        }
      }
      
      // Exercise CMM info methods
      (void)cmm.GetNumXforms();
      (void)cmm.GetSourceSpace();
      (void)cmm.GetDestSpace();
    }
  }
  
  unlink(tmp_file);
  return 0;
}
