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
  if (size < 258 || size > 2 * 1024 * 1024) return 0;
  
  // Derive parameters from trailing bytes to preserve ICC header structure
  icRenderingIntent intent = (icRenderingIntent)(data[size - 1] % 4);
  icXformInterp interp = (data[size - 2] & 1) ? icInterpLinear : icInterpTetrahedral;
  bool useAbsPCS = (data[size - 3] & 0x01);
  
  // Split input into two profiles (no leading byte skip)
  size_t mid = size / 2;
  
  const char *tmpdir = getenv("FUZZ_TMPDIR");
  if (!tmpdir) tmpdir = "/tmp";
  char tmp1[PATH_MAX];
  char tmp2[PATH_MAX];
  snprintf(tmp1, sizeof(tmp1), "%s/fuzz_link1_XXXXXX", tmpdir);
  snprintf(tmp2, sizeof(tmp2), "%s/fuzz_link2_XXXXXX", tmpdir);
  
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
  
  // Test profile linking with varied parameters
  CIccCmm cmm(icSigUnknownData, icSigUnknownData, useAbsPCS);
  if (cmm.AddXform(tmp1, intent, interp) == icCmmStatOk) {
    if (cmm.AddXform(tmp2, intent, interp) == icCmmStatOk) {
      if (cmm.Begin() == icCmmStatOk) {
        // Test varied color values through chain
        icFloatNumber in[16] = {0.0, 0.25, 0.5, 0.75, 1.0, 0.0, 0.5, 1.0, 
                                 0.5, 0.5, 0.5, 0.1, 0.9, 0.3, 0.7, 0.6};
        icFloatNumber out[16];
        for (int i = 0; i < 5; i++) {
          cmm.Apply(out + i * 3, in + i * 3);
        }
        
        // Test boundary values
        icFloatNumber bounds[] = {-0.1f, 0.0f, 1.0f, 1.1f, 0.5f, 0.5f};
        icFloatNumber bounds_out[6];
        cmm.Apply(bounds_out, bounds);
        cmm.Apply(bounds_out + 3, bounds + 3);
        
        // Exercise CMM chain info
        cmm.GetNumXforms();
        cmm.GetSourceSpace();
        cmm.GetDestSpace();
        cmm.Valid();
      }
    }
  }
  
  unlink(tmp1);
  unlink(tmp2);
  return 0;
}
