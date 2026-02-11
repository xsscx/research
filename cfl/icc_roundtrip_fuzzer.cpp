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
#include <string>
#include <cstring>
#include <cmath>
#include <unistd.h>
#include <fcntl.h>
#include "IccEval.h"
#include "IccPrmg.h"
#include "IccUtil.h"

// Full implementation matching the tool (iccRoundTrip.cpp lines 79-146)
class CIccMinMaxEval : public CIccEvalCompare {
public:
  CIccMinMaxEval() {
    minDE1 = minDE2 = 10000;
    maxDE1 = maxDE2 = -1;
    sum1 = sum2 = 0;
    num1 = num2 = 0.0;
    num3 = m_nTotal = 0;
    memset(&maxLab1[0], 0, sizeof(maxLab1));
    memset(&maxLab2[0], 0, sizeof(maxLab2));
  }

  virtual void Compare(icFloatNumber * /*pixel*/, icFloatNumber *deviceLab, 
                      icFloatNumber *lab1, icFloatNumber *lab2) override {
    icFloatNumber DE1 = icDeltaE(deviceLab, lab1);
    icFloatNumber DE2 = icDeltaE(lab1, lab2);

    if (DE1 < minDE1) {
      minDE1 = DE1;
    }

    if (DE1 > maxDE1) {
      maxDE1 = DE1;
      memcpy(&maxLab1[0], deviceLab, sizeof(maxLab1));
    }

    if (DE2 < minDE2) {
      minDE2 = DE2;
    }

    if (DE2 > maxDE2) {
      maxDE2 = DE2;
      memcpy(&maxLab2[0], deviceLab, sizeof(maxLab2));
    }

    if (DE2 <= 1.0)
      num3 += 1;

    sum1 += DE1;
    num1 += 1.0;

    sum2 += DE2;
    num2 += 1.0;

    m_nTotal += 1;
  }

  icFloatNumber GetMean1() { return sum1 / num1; }
  icFloatNumber GetMean2() { return sum2 / num2; }

  icFloatNumber minDE1, minDE2;
  icFloatNumber maxDE1, maxDE2;
  icUInt32Number num3, m_nTotal;
  icFloatNumber maxLab1[3], maxLab2[3];

protected:
  icFloatNumber sum1, sum2;
  icFloatNumber num1, num2;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 130 || size > 1024 * 1024) return 0;
  
  // Derive parameters from trailing bytes to preserve ICC header structure
  // (consuming leading bytes shifts the profile header, breaking fidelity)
  icRenderingIntent nIntent = (icRenderingIntent)(data[size - 1] % 4);
  bool nUseMPE = (data[size - 2] % 2) == 1;
  
  // Create temp file (TOOL FIDELITY - matches tool's file-based I/O)
  char tmp_file[] = "/tmp/fuzz_roundtrip_XXXXXX";
  int fd = mkstemp(tmp_file);
  if (fd == -1) return 0;
  
  // Write with error checking (TOOL FIDELITY FIX - ensure valid file)
  // Tool only processes valid files, fuzzer must not process corrupted temp files
  if (write(fd, data, size) != (ssize_t)size) {
    close(fd);
    unlink(tmp_file);
    return 0;
  }
  close(fd);
  
  CIccMinMaxEval eval;
  
  // Tool: line 170: stat = eval.EvaluateProfile(argv[1], 0, nIntent, icInterpLinear, (nUseMPE!=0));
  icStatusCMM stat = eval.EvaluateProfile(tmp_file, 0, nIntent, icInterpLinear, nUseMPE);
  
  // TOOL FIDELITY: Exit on first error (tool lines 172-174)
  if (stat != icCmmStatOk) {
    // Tool: printf("Unable to perform round trip on '%s'\n", argv[1]);
    // Tool: return -1;
    unlink(tmp_file);
    return 0;  // Fuzzer equivalent of tool's early exit
  }
  
  // TOOL FIDELITY: Run PRMG analysis (tool lines 177-184)
  CIccPRMG prmg;
  stat = prmg.EvaluateProfile(tmp_file, nIntent, icInterpLinear, nUseMPE);
  
  // TOOL FIDELITY: Check PRMG status (tool exits on PRMG failure)
  if (stat != icCmmStatOk) {
    // Tool: printf("Unable to perform PRMG analysis on '%s'\n", argv[1]);
    // Tool: return -1;
    unlink(tmp_file);
    return 0;  // Fuzzer equivalent of tool's early exit
  }
  
  // TOOL FIDELITY: Access eval members (tool lines 194-206)
  // Tool accesses these to print results - fuzzer must access to exercise same code paths
  (void)eval.minDE1;
  (void)eval.maxDE1;
  (void)eval.GetMean1();
  (void)eval.maxLab1[0];
  (void)eval.maxLab1[1];
  (void)eval.maxLab1[2];
  
  (void)eval.minDE2;
  (void)eval.maxDE2;
  (void)eval.GetMean2();
  (void)eval.maxLab2[0];
  (void)eval.maxLab2[1];
  (void)eval.maxLab2[2];
  
  // TOOL FIDELITY: Access PRMG members (tool lines 190, 208-217)
  // Tool accesses these to print PRMG interoperability results
  if (prmg.m_nTotal) {
    (void)prmg.m_bPrmgImplied;
    (void)prmg.m_nDE1;
    (void)prmg.m_nDE2;
    (void)prmg.m_nDE3;
    (void)prmg.m_nDE5;
    (void)prmg.m_nDE10;
    (void)prmg.m_nTotal;
  }
  
  unlink(tmp_file);
  return 0;
}
