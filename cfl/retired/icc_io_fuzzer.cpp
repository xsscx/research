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
#include "IccProfile.h"
#include "IccUtil.h"
#include "IccIO.h"
#include <climits>
#include "fuzz_utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 128 || size > 2 * 1024 * 1024) return 0;
  
  const char *tmpdir = fuzz_tmpdir();
  char icc_file[PATH_MAX];
  if (!fuzz_build_path(icc_file, sizeof(icc_file), tmpdir, "/fuzz_icc_XXXXXX")) return 0;
  int fd = mkstemp(icc_file);
  if (fd == -1) return 0;
  
  write(fd, data, size);
  close(fd);
  
  // Test ICC profile I/O operations
  CIccFileIO io;
  if (io.Open(icc_file, "r")) {
    unsigned long length = io.GetLength();
    
    if (length > 0 && length < 10 * 1024 * 1024) {
      icUInt8Number *profile_data = (icUInt8Number *)malloc(length);
      if (profile_data) {
        io.Read8(profile_data, (icInt32Number)length);
        
        // Validate profile
        CIccProfile *pIcc = OpenIccProfile(profile_data, length);
        if (pIcc) {
          std::string report;
          pIcc->Validate(report);
          
          // Test write operations
          char out_file[PATH_MAX];
          if (!fuzz_build_path(out_file, sizeof(out_file), tmpdir, "/fuzz_out_XXXXXX")) {
            delete pIcc;
            free(profile_data);
            io.Close();
            unlink(icc_file);
            return 0;
          }
          int fd_out = mkstemp(out_file);
          if (fd_out != -1) {
            close(fd_out);
            CIccFileIO io_out;
            if (io_out.Open(out_file, "w")) {
              pIcc->Write(&io_out);
              io_out.Close();
            }
            unlink(out_file);
          }
          
          delete pIcc;
        }
        
        free(profile_data);
      }
    }
    io.Close();
  }
  
  unlink(icc_file);
  return 0;
}
